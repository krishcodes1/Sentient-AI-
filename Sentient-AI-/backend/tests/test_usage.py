"""Tests for token usage accounting: every assistant-persistence path (blocking,
streaming, Telegram, and resumed-after-approval) records tokens and model, that
pricing handles cached, uncached, and unpriced models correctly, and that the
summary aggregates per account, window, and model without crossing accounts.

Why it exists: Guards the billing data the platform's cost reporting depends
on, including that summary queries stay a single query and that timezone-
bucketed "today" windows are correct across a daylight-saving change.

Connects to: services/usage, the agent routes and the Telegram bot, with
the model and the Bot API faked.
Used by: pytest (CI backend jobs).

Token usage: every assistant persistence path records what a turn used
and which model produced it, and the summary adds those rows up per
account, per window and per model without leaking across accounts.

No provider is ever called: runtimes are stubs or the real runtime driven
by a scripted provider, as elsewhere in the suite.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from tests.conftest import auth_headers, make_user, telegram_dm

BACKEND_DIR = Path(__file__).resolve().parents[1]

# A fixed "now" at UTC noon. "today" defaults to the UTC day, so its
# boundary sits twelve hours back whatever timezone the suite runs in.
NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
UTC_MIDNIGHT = datetime(2026, 9, 23, tzinfo=timezone.utc)


async def _conversation_for(session_factory, user_id) -> uuid.UUID:
    from models.conversation import Conversation

    async with session_factory() as session:
        conversation = Conversation(user_id=user_id, title="usage")
        session.add(conversation)
        await session.commit()
        return conversation.id


async def _add_turn(
    session_factory,
    conversation_id,
    *,
    at: datetime,
    input_tokens,
    output_tokens,
    provider="anthropic",
    model="claude-sonnet-4-20250514",
    role="assistant",
    cache_read_tokens=None,
    cache_write_tokens=None,
):
    from models.conversation import Message, MessageRole

    async with session_factory() as session:
        session.add(
            Message(
                conversation_id=conversation_id,
                role=MessageRole(role),
                content="x",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=cache_read_tokens,
                cache_write_tokens=cache_write_tokens,
                llm_provider=provider,
                llm_model=model,
                created_at=at.astimezone(timezone.utc),
            )
        )
        await session.commit()


async def _summary(session_factory, user_id, *, now=NOW, tz=None):
    from services.usage import usage_summary

    kwargs = {"tz": tz} if tz is not None else {}
    async with session_factory() as session:
        return await usage_summary(session, user_id, now=now, **kwargs)


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------


def test_listed_models_have_prices_and_unknown_ones_do_not():
    from services.usage import estimate_cost_usd, price_for

    sonnet = price_for("anthropic", "claude-sonnet-5")
    assert (sonnet.input, sonnet.cached_input, sonnet.output) == (2.00, 0.20, 10.00)
    # The -latest alias is priced as the release it pointed at.
    assert price_for("gemini", "gemini-flash-lite-latest") == price_for(
        "gemini", "gemini-3.5-flash-lite"
    )
    assert price_for("groq", "openai/gpt-oss-120b").cached_input == 0.075
    # No published cached rate: cached tokens bill at the input rate.
    assert price_for("mistral", "mistral-large-latest").cached_input is None
    # A local model costs nothing to run per token: a real zero.
    assert estimate_cost_usd("ollama", "llama3.2", 10_000, 10_000) == 0.0
    # Retired, but turns recorded while it ran still have a cost:
    # 1M in at $3 + 1M out at $15.
    retired = price_for("anthropic", "claude-sonnet-4-20250514")
    assert retired.retired == "2026-06-15"
    assert estimate_cost_usd(
        "anthropic", "claude-sonnet-4-20250514", 1_000_000, 1_000_000
    ) == 18.0


def test_cached_input_is_priced_at_the_cached_rate():
    from services.usage import estimate_cost_usd

    # gpt-5-mini: 1M prompt of which 800k cached, 100k out.
    # 200k x $0.25 + 800k x $0.025 + 100k x $2.00 = 0.05 + 0.02 + 0.20
    assert estimate_cost_usd(
        "openai", "gpt-5-mini", 1_000_000, 100_000, cache_read_tokens=800_000
    ) == pytest.approx(0.27)
    # Without the split the same turn would be priced at the full rate.
    assert estimate_cost_usd("openai", "gpt-5-mini", 1_000_000, 100_000) == pytest.approx(
        0.45
    )


def test_anthropic_cache_writes_bill_at_a_premium():
    from services.usage import estimate_cost_usd

    # claude-sonnet-5: 1M prompt = 100k fresh + 300k read + 600k written.
    # 100k x $2 + 300k x $0.20 + 600k x $2 x 1.25 + 10k out x $10
    expected = (100_000 * 2 + 300_000 * 0.20 + 600_000 * 2.5 + 10_000 * 10) / 1_000_000
    assert estimate_cost_usd(
        "anthropic",
        "claude-sonnet-5",
        1_000_000,
        10_000,
        cache_read_tokens=300_000,
        cache_write_tokens=600_000,
    ) == pytest.approx(expected)


def test_openai_cache_writes_bill_at_a_premium():
    from services.usage import estimate_cost_usd

    # gpt-6-luna reports its cache writes (GPT-5.6 and later bill them at
    # 1.25x input): 1M prompt = 100k fresh + 300k read + 600k written.
    # 100k x $0.10 + 300k x $0.01 + 600k x $0.10 x 1.25 + 10k out x $0.50
    expected = (100_000 * 0.10 + 300_000 * 0.01 + 600_000 * 0.125 + 10_000 * 0.50) / 1_000_000
    assert estimate_cost_usd(
        "openai",
        "gpt-6-luna",
        1_000_000,
        10_000,
        cache_read_tokens=300_000,
        cache_write_tokens=600_000,
    ) == pytest.approx(expected)
    # No other provider here charges for a write: it bills as plain input.
    assert estimate_cost_usd(
        "grok", "grok-4.3", 1_000_000, 0, cache_write_tokens=600_000
    ) == pytest.approx(1.25)


def test_a_model_without_a_cached_rate_bills_cached_tokens_in_full():
    from services.usage import estimate_cost_usd

    assert estimate_cost_usd(
        "mistral", "mistral-large-latest", 1_000_000, 0, cache_read_tokens=900_000
    ) == pytest.approx(0.50)


@pytest.mark.parametrize(
    "provider, model",
    [
        # Near-misses are not priced as their neighbour.
        ("anthropic", "claude-opus-4-7"),
        ("openai", "gpt-4o-2024-05-13"),
        ("gemini", "gemini-3.9-flash"),
        # A moving alias whose current target was not verified.
        ("gemini", "gemini-flash-latest"),
        # Right model id, wrong provider: a different host, a different bill.
        ("openai", "llama-3.3-70b-versatile"),
        (None, "gpt-4o"),
        ("openai", None),
    ],
)
def test_unknown_models_are_unpriced_rather_than_guessed(provider, model):
    from services.usage import estimate_cost_usd, price_for

    assert price_for(provider, model) is None
    assert estimate_cost_usd(provider, model, 1000, 1000) is None
    assert estimate_cost_usd(provider, model, 1000, 1000, 500, 100) is None


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_windows_bucket_turns_by_age(session_factory):
    user, _ = await make_user(session_factory, "windows@example.com")
    conv = await _conversation_for(session_factory, user.id)

    await _add_turn(session_factory, conv, at=NOW - timedelta(hours=1),
                    input_tokens=100, output_tokens=10)
    # One minute before UTC midnight: yesterday, not today.
    await _add_turn(session_factory, conv, at=UTC_MIDNIGHT - timedelta(minutes=1),
                    input_tokens=200, output_tokens=20)
    await _add_turn(session_factory, conv, at=NOW - timedelta(days=10),
                    input_tokens=400, output_tokens=40)
    await _add_turn(session_factory, conv, at=NOW - timedelta(days=90),
                    input_tokens=800, output_tokens=80)

    windows = (await _summary(session_factory, user.id))["windows"]

    def tokens(name):
        w = windows[name]
        return (w["input_tokens"], w["output_tokens"], w["total_tokens"], w["turns"])

    assert tokens("today") == (100, 10, 110, 1)
    assert tokens("last_7_days") == (300, 30, 330, 2)
    assert tokens("last_30_days") == (700, 70, 770, 3)
    assert tokens("all_time") == (1500, 150, 1650, 4)
    # Sonnet: $3/M in, $15/M out.
    assert windows["today"]["estimated_cost_usd"] == pytest.approx(
        (100 * 3 + 10 * 15) / 1_000_000
    )


@pytest.mark.asyncio
async def test_today_starts_at_midnight_in_the_requested_zone(session_factory):
    user, _ = await make_user(session_factory, "tz-window@example.com")
    conv = await _conversation_for(session_factory, user.id)
    tokyo = ZoneInfo("Asia/Tokyo")  # UTC+9, no DST
    # 12:00 UTC is 21:00 in Tokyo; Tokyo's day began at 15:00 UTC yesterday.
    tokyo_midnight = datetime(2026, 9, 23, tzinfo=tokyo)
    await _add_turn(session_factory, conv, at=tokyo_midnight + timedelta(minutes=1),
                    input_tokens=100, output_tokens=10)
    await _add_turn(session_factory, conv, at=tokyo_midnight - timedelta(minutes=1),
                    input_tokens=200, output_tokens=20)

    in_tokyo = (await _summary(session_factory, user.id, tz=tokyo))["windows"]["today"]
    in_utc = (await _summary(session_factory, user.id))["windows"]["today"]

    assert (in_tokyo["input_tokens"], in_tokyo["turns"]) == (100, 1)
    # Both turns fall on the UTC calendar day of 2026-09-22 → neither is
    # "today" in UTC.
    assert in_utc["turns"] == 0


@pytest.mark.asyncio
async def test_today_is_right_on_a_daylight_saving_change_day(session_factory):
    """New York falls back on 2026-11-01: midnight that day was EDT
    (UTC-4) while noon is EST (UTC-5). "today" must start at 04:00 UTC —
    reusing noon's offset would start it an hour late, at 05:00."""
    user, _ = await make_user(session_factory, "tz-dst@example.com")
    conv = await _conversation_for(session_factory, user.id)
    new_york = ZoneInfo("America/New_York")
    now = datetime(2026, 11, 1, 12, 0, tzinfo=new_york)
    midnight_utc = datetime(2026, 11, 1, 4, 0, tzinfo=timezone.utc)
    await _add_turn(session_factory, conv, at=midnight_utc + timedelta(minutes=30),
                    input_tokens=100, output_tokens=10)
    await _add_turn(session_factory, conv, at=midnight_utc - timedelta(minutes=1),
                    input_tokens=200, output_tokens=20)

    today = (await _summary(session_factory, user.id, now=now, tz=new_york))["windows"][
        "today"
    ]

    assert (today["input_tokens"], today["turns"]) == (100, 1)


@pytest.mark.asyncio
async def test_cache_counts_are_summed_and_priced(session_factory):
    user, _ = await make_user(session_factory, "cache-sum@example.com")
    conv = await _conversation_for(session_factory, user.id)
    await _add_turn(session_factory, conv, at=NOW, input_tokens=1_000_000,
                    output_tokens=10_000, provider="anthropic", model="claude-sonnet-5",
                    cache_read_tokens=300_000, cache_write_tokens=600_000)
    # A row from before the cache split was recorded: priced as uncached.
    await _add_turn(session_factory, conv, at=NOW, input_tokens=100_000,
                    output_tokens=0, provider="anthropic", model="claude-sonnet-5")

    summary = await _summary(session_factory, user.id)
    today = summary["windows"]["today"]

    assert (today["cache_read_tokens"], today["cache_write_tokens"]) == (300_000, 600_000)
    expected = (
        (100_000 * 2 + 300_000 * 0.20 + 600_000 * 2.5 + 10_000 * 10) + 100_000 * 2
    ) / 1_000_000
    assert today["estimated_cost_usd"] == pytest.approx(expected)
    [row] = summary["by_model"]
    assert row["cache_read_tokens"] == 300_000
    assert row["estimated_cost_usd"] == pytest.approx(expected)


@pytest.mark.asyncio
async def test_another_accounts_usage_never_appears(session_factory):
    alice, _ = await make_user(session_factory, "alice-usage@example.com")
    bob, _ = await make_user(session_factory, "bob-usage@example.com")
    alice_conv = await _conversation_for(session_factory, alice.id)
    bob_conv = await _conversation_for(session_factory, bob.id)

    await _add_turn(session_factory, alice_conv, at=NOW, input_tokens=5, output_tokens=1)
    await _add_turn(session_factory, bob_conv, at=NOW, input_tokens=5000,
                    output_tokens=900, provider="openai", model="gpt-4o")

    alice_summary = await _summary(session_factory, alice.id)
    assert alice_summary["windows"]["all_time"]["total_tokens"] == 6
    assert [m["model"] for m in alice_summary["by_model"]] == ["claude-sonnet-4-20250514"]

    bob_summary = await _summary(session_factory, bob.id)
    assert bob_summary["windows"]["all_time"]["total_tokens"] == 5900
    assert [m["model"] for m in bob_summary["by_model"]] == ["gpt-4o"]


@pytest.mark.asyncio
async def test_rows_without_usage_are_not_turns(session_factory):
    """User rows, approval-outcome rows and replay-cache hits carry no
    counts; counting them as zero-token turns would dilute every average."""
    user, _ = await make_user(session_factory, "nocount@example.com")
    conv = await _conversation_for(session_factory, user.id)
    await _add_turn(session_factory, conv, at=NOW, input_tokens=None,
                    output_tokens=None)
    await _add_turn(session_factory, conv, at=NOW, input_tokens=None,
                    output_tokens=None, role="user", provider=None, model=None)
    await _add_turn(session_factory, conv, at=NOW, input_tokens=7, output_tokens=3)

    summary = await _summary(session_factory, user.id)
    assert summary["windows"]["all_time"]["turns"] == 1
    assert summary["windows"]["all_time"]["total_tokens"] == 10


@pytest.mark.asyncio
async def test_unpriced_models_count_tokens_but_not_cost(session_factory):
    user, _ = await make_user(session_factory, "unpriced@example.com")
    conv = await _conversation_for(session_factory, user.id)
    # Recorded before the model was tracked.
    await _add_turn(session_factory, conv, at=NOW - timedelta(days=20),
                    input_tokens=1000, output_tokens=100, provider=None, model=None)
    await _add_turn(session_factory, conv, at=NOW - timedelta(days=3),
                    input_tokens=50, output_tokens=5, provider="openai",
                    model="gpt-9-imaginary")
    await _add_turn(session_factory, conv, at=NOW, input_tokens=1_000_000,
                    output_tokens=0, provider="openai", model="gpt-4o-mini")

    summary = await _summary(session_factory, user.id)
    windows = summary["windows"]

    # Today is fully priced.
    assert windows["today"]["estimated_cost_usd"] == pytest.approx(0.15)
    assert windows["today"]["unpriced_turns"] == 0
    # The 30-day window prices what it can and says how much it left out.
    assert windows["last_30_days"]["total_tokens"] == 1_001_155
    assert windows["last_30_days"]["estimated_cost_usd"] == pytest.approx(0.15)
    assert windows["last_30_days"]["unpriced_turns"] == 2

    by_model = {(m["provider"], m["model"]): m for m in summary["by_model"]}
    assert by_model[(None, None)]["estimated_cost_usd"] is None
    assert by_model[("openai", "gpt-9-imaginary")]["estimated_cost_usd"] is None
    assert by_model[("openai", "gpt-4o-mini")]["estimated_cost_usd"] == pytest.approx(0.15)
    # Heaviest model first.
    assert summary["by_model"][0]["model"] == "gpt-4o-mini"


@pytest.mark.asyncio
async def test_a_window_with_only_unpriced_turns_has_unknown_cost(session_factory):
    """Zero would claim the turns were free; the honest answer is unknown."""
    user, _ = await make_user(session_factory, "allunpriced@example.com")
    conv = await _conversation_for(session_factory, user.id)
    await _add_turn(session_factory, conv, at=NOW, input_tokens=10, output_tokens=1,
                    provider="mistral", model="some-new-model")

    windows = (await _summary(session_factory, user.id))["windows"]
    assert windows["today"]["estimated_cost_usd"] is None
    assert windows["today"]["unpriced_turns"] == 1


@pytest.mark.asyncio
async def test_an_account_with_no_turns_reports_zeros(session_factory):
    user, _ = await make_user(session_factory, "fresh-usage@example.com")
    summary = await _summary(session_factory, user.id)
    assert summary["by_model"] == []
    for window in summary["windows"].values():
        assert window["total_tokens"] == 0 and window["turns"] == 0
        assert window["estimated_cost_usd"] == 0.0


@pytest.mark.asyncio
async def test_summary_is_one_query(session_factory):
    """The aggregation is a single GROUP BY, however long the history."""
    user, _ = await make_user(session_factory, "onequery@example.com")
    conv = await _conversation_for(session_factory, user.id)
    for i in range(30):
        await _add_turn(session_factory, conv, at=NOW - timedelta(days=i),
                        input_tokens=1, output_tokens=1,
                        model="claude-sonnet-4-20250514" if i % 2 else "claude-haiku-4-5")

    from sqlalchemy import event

    from services.usage import usage_summary

    statements = []
    async with session_factory() as session:
        engine = session.bind.sync_engine

        def _count(conn, cursor, statement, *args):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        event.listen(engine, "before_cursor_execute", _count)
        try:
            summary = await usage_summary(session, user.id, now=NOW)
        finally:
            event.remove(engine, "before_cursor_execute", _count)

    assert len(statements) == 1
    assert "GROUP BY" in statements[0].upper()
    assert summary["windows"]["all_time"]["turns"] == 30


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_endpoint_requires_auth(client):
    resp = await client.get("/api/usage/summary")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_summary_endpoint_shape_and_scope(client, session_factory):
    alice, alice_token = await make_user(session_factory, "alice-http@example.com")
    bob, _ = await make_user(session_factory, "bob-http@example.com")
    now = datetime.now(timezone.utc)
    await _add_turn(session_factory, await _conversation_for(session_factory, alice.id),
                    at=now, input_tokens=1234, output_tokens=56,
                    provider="gemini", model="gemini-2.5-flash")
    await _add_turn(session_factory, await _conversation_for(session_factory, bob.id),
                    at=now, input_tokens=99999, output_tokens=9999)

    resp = await client.get("/api/usage/summary", headers=auth_headers(alice_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["currency"] == "USD"
    assert "estimate" in body["pricing_note"].lower()
    assert set(body["windows"]) == {"today", "last_7_days", "last_30_days", "all_time"}
    today = body["windows"]["today"]
    assert today == {
        "input_tokens": 1234,
        "output_tokens": 56,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "total_tokens": 1290,
        "turns": 1,
        "estimated_cost_usd": pytest.approx((1234 * 0.30 + 56 * 2.50) / 1_000_000),
        "unpriced_turns": 0,
    }
    assert body["by_model"] == [
        {
            "provider": "gemini",
            "model": "gemini-2.5-flash",
            "input_tokens": 1234,
            "output_tokens": 56,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "total_tokens": 1290,
            "turns": 1,
            "estimated_cost_usd": pytest.approx((1234 * 0.30 + 56 * 2.50) / 1_000_000),
        }
    ]


@pytest.mark.asyncio
async def test_summary_endpoint_counts_today_in_the_callers_zone(
    client, session_factory, monkeypatch
):
    from api.routes import usage as usage_routes

    seen_zones = []
    real_summary = usage_routes.usage_summary

    async def recording_summary(db, user_id, **kwargs):
        seen_zones.append(kwargs.get("tz"))
        return await real_summary(db, user_id, **kwargs)

    monkeypatch.setattr(usage_routes, "usage_summary", recording_summary)
    user, token = await make_user(session_factory, "tz-http@example.com")
    conv = await _conversation_for(session_factory, user.id)
    # Just after midnight in Kiritimati (UTC+14), the earliest "today" on
    # Earth: 10:01 UTC the previous UTC day.
    kiritimati = ZoneInfo("Pacific/Kiritimati")
    local_now = datetime.now(kiritimati)
    local_midnight = datetime.combine(local_now.date(), datetime.min.time(), tzinfo=kiritimati)
    await _add_turn(session_factory, conv, at=local_midnight - timedelta(minutes=1),
                    input_tokens=5, output_tokens=1)

    here = await client.get(
        "/api/usage/summary",
        params={"tz": "Pacific/Kiritimati"},
        headers=auth_headers(token),
    )
    assert here.status_code == 200
    # One minute before the caller's midnight is yesterday for them.
    assert here.json()["windows"]["today"]["turns"] == 0
    assert here.json()["windows"]["all_time"]["turns"] == 1

    default = await client.get("/api/usage/summary", headers=auth_headers(token))
    assert default.status_code == 200
    assert [str(z) for z in seen_zones] == ["Pacific/Kiritimati", "UTC"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tz", ["Mars/Olympus", "../../etc/passwd", "/etc/localtime", "America", "zone.tab", ""]
)
async def test_summary_endpoint_rejects_an_unknown_zone(client, session_factory, tz):
    _, token = await make_user(session_factory, f"tz-bad-{abs(hash(tz))}@example.com")
    resp = await client.get(
        "/api/usage/summary", params={"tz": tz}, headers=auth_headers(token)
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Every persistence path records usage and the model
# ---------------------------------------------------------------------------


def _server_default_pair():
    """What the real runtime's environment source resolves a turn to when
    the account follows the install (NULL provider)."""
    from core.config import settings

    return settings.LLM_PROVIDER.strip().lower(), settings.LLM_MODEL.strip()


class UsageRuntime:
    """Reports, like the real runtime, the pair it ran on: the account's
    pinned provider/model, else the install default. The routes persist
    that report — never the account row."""

    def __init__(self, usage=None, content="ok"):
        self.calls = []
        self._usage = usage or {"input_tokens": 321, "output_tokens": 12}
        self._content = content

    @staticmethod
    def _ran_on(kwargs):
        if kwargs.get("llm_provider"):
            return kwargs["llm_provider"], kwargs.get("llm_model") or ""
        return _server_default_pair()

    async def chat(self, messages, tools, user_id, conversation_id=None, **kwargs):
        from services.agent.runtime import AgentResponse

        self.calls.append(kwargs)
        provider, model = self._ran_on(kwargs)
        return AgentResponse(
            content=self._content, usage=dict(self._usage), provider=provider, model=model
        )

    async def stream_chat(self, messages, tools, user_id, conversation_id=None, **kwargs):
        self.calls.append(kwargs)
        provider, model = self._ran_on(kwargs)
        yield {"type": "start", "data": {}}
        yield {
            "type": "done",
            "data": {
                "content": self._content,
                "usage": dict(self._usage),
                "provider": provider,
                "model": model,
                "tool_calls": [],
                "pending_approvals": [],
                "blocked_actions": [],
            },
        }


async def _set_model(session_factory, user_id, provider, model):
    from models.user import User

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.id == user_id))).scalar_one()
        user.llm_provider = provider
        user.llm_model = model
        await session.commit()


async def _assistant_rows(session_factory, conversation_id=None, content=None):
    from models.conversation import Message, MessageRole

    stmt = select(Message).where(Message.role == MessageRole.assistant)
    if conversation_id is not None:
        stmt = stmt.where(Message.conversation_id == uuid.UUID(str(conversation_id)))
    if content is not None:
        stmt = stmt.where(Message.content == content)
    async with session_factory() as session:
        return list((await session.execute(stmt.order_by(Message.created_at))).scalars())


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["messages", "messages/stream"])
async def test_http_send_paths_record_usage_and_model(client, session_factory, path):
    from api.routes import agent as agent_routes
    from main import app

    user, token = await make_user(session_factory, f"path-{path.count('/')}@example.com")
    await _set_model(session_factory, user.id, "gemini", "gemini-2.5-flash")
    runtime = UsageRuntime(
        usage={
            "input_tokens": 1234,
            "output_tokens": 56,
            "cache_read_tokens": 1024,
            "cache_write_tokens": 0,
        }
    )
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        conv_id = (
            await client.post(
                "/api/agent/conversations", json={"title": "t"}, headers=auth_headers(token)
            )
        ).json()["id"]
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/{path}",
            json={"content": "hello"},
            headers=auth_headers(token),
        )
        assert resp.status_code in (200, 201)
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    assert runtime.calls[0]["llm_model"] == "gemini-2.5-flash"
    [row] = await _assistant_rows(session_factory, conv_id)
    assert (row.input_tokens, row.output_tokens) == (1234, 56)
    assert (row.cache_read_tokens, row.cache_write_tokens) == (1024, 0)
    assert (row.llm_provider, row.llm_model) == ("gemini", "gemini-2.5-flash")

    thread = await client.get(
        f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
    )
    assert thread.json()["messages"][-1]["llm_model"] == "gemini-2.5-flash"


@pytest.mark.asyncio
async def test_detached_persistence_records_usage_and_model(session_factory, monkeypatch):
    """The fallback write for a client that vanished before the saved frame
    carries the same accounting as the in-request write."""
    from api.routes import agent as agent_routes

    monkeypatch.setattr(agent_routes, "_detached_session_factory", session_factory)
    user, _ = await make_user(session_factory, "detached-usage@example.com")
    conv = await _conversation_for(session_factory, user.id)

    await agent_routes._persist_assistant_detached(
        conv,
        "late reply",
        None,
        {"input_tokens": 77, "output_tokens": 8, "cache_read_tokens": 64,
         "cache_write_tokens": 0},
        "groq",
        "llama-3.3-70b-versatile",
    )

    [row] = await _assistant_rows(session_factory, conv)
    assert (row.input_tokens, row.output_tokens) == (77, 8)
    assert (row.cache_read_tokens, row.cache_write_tokens) == (64, 0)
    assert (row.llm_provider, row.llm_model) == ("groq", "llama-3.3-70b-versatile")


@pytest.mark.asyncio
async def test_orphaned_stream_turn_records_usage_and_model(
    client, session_factory, monkeypatch
):
    """End to end: the client drops the SSE stream mid-turn, the runtime's
    on_orphaned hook persists the turn, and the row is still counted."""
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.providers import LLMResponse
    from tests.test_stream_resilience import SlowProvider, _runtime

    monkeypatch.setattr(agent_routes, "_detached_session_factory", session_factory)
    runtime = _runtime(
        SlowProvider(
            [LLMResponse(content="Orphan.", usage={"input_tokens": 40, "output_tokens": 4})],
            0.4,
        )
    )
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    user, token = await make_user(session_factory, "orphan-usage@example.com")
    try:
        conv_id = (
            await client.post(
                "/api/agent/conversations", json={"title": "o"}, headers=auth_headers(token)
            )
        ).json()["id"]
        try:
            async with client.stream(
                "POST",
                f"/api/agent/conversations/{conv_id}/messages/stream",
                json={"content": "hello"},
                headers=auth_headers(token),
            ) as resp:
                async for _chunk in resp.aiter_text():
                    break
        except Exception:
            pass

        rows = []
        for _ in range(60):
            await asyncio.sleep(0.1)
            rows = await _assistant_rows(session_factory, conv_id, content="Orphan.")
            if rows:
                break
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    assert rows, "the orphaned turn was not persisted"
    assert (rows[0].input_tokens, rows[0].output_tokens) == (40, 4)
    assert (rows[0].llm_provider, rows[0].llm_model) == _server_default_pair()


@pytest.mark.asyncio
async def test_telegram_chat_applier_records_usage_and_model(session_factory):
    from api.routes.agent import build_chat_applier
    from main import app

    user, _ = await make_user(session_factory, "tg-usage@example.com")
    await _set_model(session_factory, user.id, "deepseek", "deepseek-chat")
    runtime = UsageRuntime(usage={"input_tokens": 12, "output_tokens": 3})
    saved = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = runtime
    try:
        result = await build_chat_applier(app, session_factory=session_factory)(
            str(user.id), "hi"
        )
    finally:
        app.state.agent_runtime = saved

    assert result["usage"] == {"input_tokens": 12, "output_tokens": 3}
    [row] = await _assistant_rows(session_factory, result["conversation_id"])
    assert (row.input_tokens, row.output_tokens) == (12, 3)
    assert (row.llm_provider, row.llm_model) == ("deepseek", "deepseek-chat")


@pytest.mark.asyncio
async def test_resumed_turn_after_approval_is_counted(client, session_factory):
    """The turn that runs after an approval is a real, billed LLM call; it
    used to be saved without usage and vanished from every total."""
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.providers import LLMResponse
    from tests.test_resume_after_approval import (
        RecordingExecutor,
        ScriptedProvider,
        _park_action,
        _runtime,
    )

    provider = ScriptedProvider(
        [LLMResponse(content="Done, email sent.", usage={"input_tokens": 900, "output_tokens": 9})]
    )
    runtime, _ = _runtime(session_factory, provider, RecordingExecutor())
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        user, token = await make_user(session_factory, "resume-usage@example.com")
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        action = await _park_action(session_factory, user, conv["id"])
        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}",
            headers=auth_headers(token),
            json={"approved": True},
        )
        assert decided.status_code == 200
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    outcome, resumed = await _assistant_rows(session_factory, conv["id"])
    # The recorded decision is not an LLM call and carries no usage.
    assert outcome.input_tokens is None and outcome.llm_model is None
    assert resumed.content == "Done, email sent."
    assert (resumed.input_tokens, resumed.output_tokens) == (900, 9)
    assert (resumed.llm_provider, resumed.llm_model) == _server_default_pair()

    body = (await client.get("/api/usage/summary", headers=auth_headers(token))).json()
    assert body["windows"]["today"]["turns"] == 1
    assert body["windows"]["today"]["total_tokens"] == 909


def test_turn_model_falls_back_to_the_server_default():
    """A blank Settings choice runs on the server default, so that is the
    model the row must name."""
    from api.routes.agent import _usage_columns
    from core.config import settings

    columns = _usage_columns({"input_tokens": 1}, "", None)
    # A provider that never reported cache counts stores NULL, not 0.
    assert columns["cache_read_tokens"] is None
    assert columns["llm_provider"] == settings.LLM_PROVIDER
    assert columns["llm_model"] == settings.LLM_MODEL
    assert _usage_columns({}, " Gemini ", "gemini-2.5-pro")["llm_provider"] == "gemini"


# ---------------------------------------------------------------------------
# Telegram /usage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_telegram_usage_command(session_factory, monkeypatch):
    import httpx

    from models.user import User
    from services.notifications.telegram import TelegramService
    from tests.test_telegram import FakeTelegramAPI

    api = FakeTelegramAPI()
    real_client_cls = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client_cls(**{**kw, "transport": httpx.MockTransport(api.handler)}),
    )

    user, _ = await make_user(session_factory, "tg-usage-cmd@example.com")
    async with session_factory() as session:
        row = (await session.execute(select(User).where(User.id == user.id))).scalar_one()
        row.telegram_chat_id = 5150
        await session.commit()
    conv = await _conversation_for(session_factory, user.id)
    await _add_turn(session_factory, conv, at=datetime.now(timezone.utc),
                    input_tokens=1200, output_tokens=34,
                    provider="gemini", model="gemini-2.5-flash")
    await _add_turn(session_factory, conv,
                    at=datetime.now(timezone.utc) - timedelta(days=12),
                    input_tokens=100_000, output_tokens=2_000,
                    provider="gemini", model="gemini-2.5-flash")

    service = TelegramService(token="123:fake", session_factory=session_factory)
    try:
        await service._handle_message(telegram_dm(5150, "/usage"))
        text = api.sent_messages()[-1]["text"]
        assert "estimate" in text.lower()
        # Telegram cannot learn the reader's zone, so it says whose day it is.
        assert "Today (UTC): 1,234 tokens (1,200 in · 34 out)" in text
        assert "Last 30 days: 103,234 tokens" in text
        assert "$" in text

        await service._handle_message(telegram_dm(5150, "/help"))
        assert "/usage" in api.sent_messages()[-1]["text"]

        # An unlinked chat learns nothing about anyone's usage: it is
        # ignored outright, so nothing new is sent.
        sent_before = len(api.sent_messages())
        await service._handle_message(telegram_dm(6160, "/usage"))
        assert len(api.sent_messages()) == sent_before
    finally:
        await service._client.aclose()


# ---------------------------------------------------------------------------
# Migration 0007
# ---------------------------------------------------------------------------


MODEL_COLUMNS = {"llm_provider", "llm_model", "cache_read_tokens", "cache_write_tokens"}


def _alembic_config(db_path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _message_columns(db_path) -> set[str]:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        return {c["name"] for c in sa.inspect(engine).get_columns("messages")}
    finally:
        engine.dispose()


def test_migration_0007_adds_and_removes_the_model_columns(tmp_path):
    db_path = tmp_path / "model.db"
    config = _alembic_config(db_path)

    command.upgrade(config, "0006_message_usage")
    assert MODEL_COLUMNS & _message_columns(db_path) == set()

    command.upgrade(config, "0007_message_model")
    assert MODEL_COLUMNS <= _message_columns(db_path)

    command.downgrade(config, "0006_message_usage")
    assert MODEL_COLUMNS & _message_columns(db_path) == set()


def test_migration_0007_tolerates_columns_that_already_exist(tmp_path):
    import models  # noqa: F401 — registers every model on Base.metadata
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()

    config = _alembic_config(db_path)
    command.stamp(config, "0006_message_usage")
    command.upgrade(config, "head")
    assert MODEL_COLUMNS <= _message_columns(db_path)
