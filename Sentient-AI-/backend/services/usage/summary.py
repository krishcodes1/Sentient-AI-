"""Aggregate one account's token usage across time windows and models.

Everything is summed in SQL: a transcript is unbounded, and loading every
assistant row a user has ever produced to add up four integers would make
the dashboard's cost grow with the account's age. One GROUP BY over
(provider, model) with conditional sums per window returns a handful of
rows however long the history is; pricing is applied to those rows.
"""

from __future__ import annotations

import uuid
from datetime import datetime, time, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

from sqlalchemy import case, func, literal_column, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.conversation import Conversation, Message, MessageRole
from services.usage.pricing import PRICING_AS_OF, estimate_cost_usd

WINDOWS = ("today", "last_7_days", "last_30_days", "all_time")

PRICING_NOTE = (
    f"Estimated from list prices as of {PRICING_AS_OF}, with prompt-cache "
    "discounts where the provider reported them. Excludes long-context tiers, "
    "off-peak and batch pricing and free tiers, so your provider's bill is "
    "the source of truth. Turns on a model without a known price, or recorded "
    "before the model was tracked, count toward tokens but not cost."
)

UTC = ZoneInfo("UTC")


def _window_starts(
    now: datetime, tz: ZoneInfo = UTC
) -> dict[str, Optional[datetime]]:
    """Window lower bounds, in UTC.

    "today" starts at midnight in ``tz`` — the viewer's zone, not the
    server's: a container runs in UTC, so a server-local midnight put
    "today" hours off for anyone else. Built from the calendar date in
    ``tz`` rather than by zeroing the clock on ``now``: on a daylight-saving
    change day the offset at midnight differs from the one in effect now,
    and replace() would keep the wrong one.
    """
    local_now = now.astimezone(tz)
    local_midnight = datetime.combine(local_now.date(), time.min, tzinfo=tz)
    utc_now = now.astimezone(timezone.utc)
    return {
        "today": local_midnight.astimezone(timezone.utc),
        "last_7_days": utc_now - timedelta(days=7),
        "last_30_days": utc_now - timedelta(days=30),
        "all_time": None,
    }


def _empty_window() -> dict[str, Any]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "total_tokens": 0,
        "turns": 0,
        "estimated_cost_usd": 0.0,
        "unpriced_turns": 0,
    }


async def usage_summary(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    now: Optional[datetime] = None,
    tz: ZoneInfo = UTC,
) -> dict[str, Any]:
    """Token totals and estimated cost for one user.

    A "turn" is an assistant message that recorded usage. Rows without
    counts (approval-outcome messages, replay-cache hits) are not LLM calls
    that were billed and are left out rather than counted as zero-token
    turns. ``tz`` decides where "today" begins.
    """
    now = now or datetime.now(timezone.utc)
    starts = _window_starts(now, tz)

    zero = literal_column("0")
    sums = {
        "in": Message.input_tokens,
        "out": Message.output_tokens,
        "cread": Message.cache_read_tokens,
        "cwrite": Message.cache_write_tokens,
    }
    columns = []
    for window in WINDOWS:
        since = starts[window]
        if since is None:
            columns += [
                func.sum(func.coalesce(col, zero)).label(f"{window}_{key}")
                for key, col in sums.items()
            ]
            columns.append(func.count(Message.id).label(f"{window}_turns"))
            continue
        # Literal zero rather than a bound 0: Postgres cannot always infer
        # the type of an untyped parameter inside CASE in a select list.
        in_window = Message.created_at >= since
        columns += [
            func.sum(
                case((in_window, func.coalesce(col, zero)), else_=zero)
            ).label(f"{window}_{key}")
            for key, col in sums.items()
        ]
        # COUNT skips the NULL the CASE yields outside the window.
        columns.append(func.count(case((in_window, Message.id))).label(f"{window}_turns"))

    stmt = (
        select(Message.llm_provider, Message.llm_model, *columns)
        .join(Conversation, Conversation.id == Message.conversation_id)
        .where(
            Conversation.user_id == user_id,
            Message.role == MessageRole.assistant,
            or_(
                Message.input_tokens.is_not(None),
                Message.output_tokens.is_not(None),
            ),
        )
        .group_by(Message.llm_provider, Message.llm_model)
    )
    rows = (await db.execute(stmt)).mappings().all()

    windows = {window: _empty_window() for window in WINDOWS}
    priced_turns = dict.fromkeys(WINDOWS, 0)
    by_model: list[dict[str, Any]] = []

    for row in rows:
        provider, model = row["llm_provider"], row["llm_model"]
        for window in WINDOWS:
            in_tokens, out_tokens, read, written = _counts(row, window)
            turns = int(row[f"{window}_turns"])
            if turns == 0:
                continue
            bucket = windows[window]
            bucket["input_tokens"] += in_tokens
            bucket["output_tokens"] += out_tokens
            bucket["cache_read_tokens"] += read
            bucket["cache_write_tokens"] += written
            bucket["total_tokens"] += in_tokens + out_tokens
            bucket["turns"] += turns
            cost = estimate_cost_usd(
                provider, model, in_tokens, out_tokens, read, written
            )
            if cost is None:
                bucket["unpriced_turns"] += turns
            else:
                bucket["estimated_cost_usd"] += cost
                priced_turns[window] += turns

        all_in, all_out, all_read, all_written = _counts(row, "all_time")
        by_model.append(
            {
                "provider": provider,
                "model": model,
                "input_tokens": all_in,
                "output_tokens": all_out,
                "cache_read_tokens": all_read,
                "cache_write_tokens": all_written,
                "total_tokens": all_in + all_out,
                "turns": int(row["all_time_turns"]),
                "estimated_cost_usd": estimate_cost_usd(
                    provider, model, all_in, all_out, all_read, all_written
                ),
            }
        )

    for window in WINDOWS:
        bucket = windows[window]
        if bucket["turns"] and not priced_turns[window]:
            # Every turn in the window is on an unpriced model: the cost is
            # unknown, and 0.0 would claim it was free.
            bucket["estimated_cost_usd"] = None
        else:
            bucket["estimated_cost_usd"] = round(bucket["estimated_cost_usd"], 8)

    by_model.sort(key=lambda m: (-m["total_tokens"], m["provider"] or "", m["model"] or ""))

    return {
        "windows": windows,
        "by_model": by_model,
        "currency": "USD",
        "pricing_note": PRICING_NOTE,
    }


def _counts(row: Any, window: str) -> tuple[int, int, int, int]:
    """(input, output, cache read, cache write) for one window of a row."""
    return tuple(  # type: ignore[return-value]
        int(row[f"{window}_{key}"] or 0) for key in ("in", "out", "cread", "cwrite")
    )


def _format_cost(cost: Optional[float]) -> str:
    if cost is None:
        return "cost unknown"
    if cost == 0:
        return "~$0.00"
    if cost < 0.01:
        return "<$0.01"
    return f"~${cost:,.2f}"


def _format_window(label: str, window: dict[str, Any]) -> str:
    line = (
        f"{label}: {window['total_tokens']:,} tokens "
        f"({window['input_tokens']:,} in · {window['output_tokens']:,} out) "
        f"· {_format_cost(window['estimated_cost_usd'])}"
    )
    if window["unpriced_turns"] and window["estimated_cost_usd"] is not None:
        line += f" (excludes {window['unpriced_turns']} unpriced turn(s))"
    return line


def format_usage_text(summary: dict[str, Any]) -> str:
    """Plain-text rendering for chat channels (Telegram).

    A chat channel has no way to learn the reader's timezone and accounts
    store none, so the summary behind this is computed in UTC and the label
    says so rather than letting "today" silently mean someone else's day.
    """
    windows = summary["windows"]
    return (
        "Token usage (costs are estimates)\n\n"
        + _format_window("Today (UTC)", windows["today"])
        + "\n"
        + _format_window("Last 30 days", windows["last_30_days"])
    )
