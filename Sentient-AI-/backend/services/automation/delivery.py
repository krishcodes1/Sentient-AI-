"""Turns an unattended run's outcome into the chat messages the owner gets
(``compose``) and sends them to the owner's own linked chats (``deliver``).

Why it exists: a scheduled result, a briefing and (wave 2) a trigger alert
all reach Telegram and Slack the same way: plain text with a header that
names the task and its local time, notes for what the owner must do (a card
waits) or should know (a tool was not available, the budget ran out), the
usage line and how to pause, every URL without its query string, and at most
four parts before a pointer to the web app, where the whole result is kept.
Nothing here chooses a recipient: a sender only ever reaches the linked chat
of the user it is given.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence, Union

import structlog

from services.automation.runner import UnattendedOutcome
from services.notifications import cards

logger = structlog.get_logger(__name__)

PART_CHARS = 3400
MAX_PARTS = 4
PART_PAUSE_S = 0.3
_CALENDAR = "\U0001f5d3"

Sender = Callable[[str, str], Awaitable[Any]]

# How each channel's owner pauses a task, and lists waiting cards.
_PAUSE_HINTS = {"telegram": "/schedules to pause", "slack": 'reply "schedules" to pause'}
_PENDING_HINTS = {"telegram": "/pending", "slack": "send pending"}


def _strip_queries(text: str) -> str:
    # The same rule the chat channels use for a turn that read a logged-in
    # site (spec §9); every scheduled delivery gets it.
    from api.routes.agent import strip_url_queries

    return strip_url_queries(text)


def outcome_notes(outcome: UnattendedOutcome, channel: str) -> list[str]:
    """The lines a delivery adds after the reply, from the outcome's facts."""
    notes: list[str] = []
    pending = _PENDING_HINTS.get(channel, "/pending")
    if outcome.cards == 1:
        notes.append(f"1 action is waiting for your approval ({pending}).")
    elif outcome.cards > 1:
        notes.append(f"{outcome.cards} actions are waiting for your approval ({pending}).")
    if outcome.unavailable:
        notes.append("Not available this run: " + ", ".join(outcome.unavailable) + ".")
    if outcome.blocked:
        notes.append("Not run (outside this task's tools): " + ", ".join(outcome.blocked) + ".")
    if outcome.status == "over_budget":
        budget = f"${outcome.budget_usd:.2f} " if outcome.budget_usd is not None else ""
        notes.append(f"Stopped at this task's {budget}budget.")
    elif outcome.status == "timed_out":
        notes.append("Stopped: this run took longer than it is allowed to.")
    elif outcome.status == "stopped":
        notes.append("Stopped because you asked Crawler to stop.")
    elif outcome.status == "not_configured":
        notes.append("No AI provider is set up, so this task could not run.")
    return notes


def compose(
    label: str, when_local: str, outcome: UnattendedOutcome, channel: str
) -> list[str]:
    """The messages for *channel* ("telegram" or "slack"): header
    ("🗓 <label> · Tue 08:00"), the reply, the notes, then the usage line
    and how to pause. URL queries are stripped from all of it. Split into
    parts of at most PART_CHARS (Telegram counts UTF-16 units); past
    MAX_PARTS the rest is replaced by a pointer to the web app."""
    from services.notifications.page_watch import defang

    # The label is shown as text, never as a link or a /command.
    header = f"{_CALENDAR} {defang(label)} · {when_local}"
    body = (outcome.reply or "").strip() or "(No reply this run.)"
    notes = outcome_notes(outcome, channel)
    text = _strip_queries("\n\n".join([header, body, *notes]))
    length = cards.utf16_len if channel == "telegram" else len
    parts = cards.split_text(text, max_chars=PART_CHARS, length=length)
    if len(parts) > MAX_PARTS:
        parts = parts[:MAX_PARTS] + [
            f'The rest is in the web app, in the conversation "Scheduled: {label}".'
        ]
    footer_lines = []
    usage = cards.usage_line(
        {"usage": dict(outcome.usage), "provider": outcome.provider, "model": outcome.model}
    ) if outcome.usage else None
    if usage:
        footer_lines.append(usage)
    footer_lines.append(_PAUSE_HINTS.get(channel, "/schedules to pause"))
    footer = "\n".join(footer_lines)
    if parts and length(parts[-1]) + 2 + length(footer) <= PART_CHARS:
        parts[-1] = f"{parts[-1]}\n\n{footer}"
    else:
        parts.append(footer)
    return parts


async def deliver(
    user_id: str,
    texts: Union[Sequence[str], Mapping[str, Sequence[str]]],
    channels: Sequence[str],
    senders: Mapping[str, Sender],
    *,
    pause_s: float = PART_PAUSE_S,
    sleep: Optional[Callable[[float], Awaitable[None]]] = None,
) -> tuple[str, ...]:
    """Send *texts* to each of *channels* the owner asked for and return the
    ones that took it. *texts* is one list for every channel, or a list per
    channel. A sender answers True when the part reached the user's linked
    chat (False: no chat linked, the channel is not running). A channel
    counts as delivered once its first part went out; a failing sender is
    logged by type and never retried (a broken channel must not turn into
    a storm)."""
    wait = sleep or asyncio.sleep
    delivered: list[str] = []
    for channel in dict.fromkeys(channels):
        send = senders.get(channel)
        parts = texts.get(channel, ()) if isinstance(texts, Mapping) else texts
        if send is None or not parts:
            continue
        reached = False
        for index, part in enumerate(parts):
            if index and pause_s:
                await wait(pause_s)
            try:
                ok = (await send(user_id, part)) is True
            except Exception as exc:
                logger.warning(
                    "unattended_delivery_failed", channel=channel, error_type=type(exc).__name__
                )
                ok = False
            if not ok:
                break
            reached = True
        if reached:
            delivered.append(channel)
    return tuple(delivered)
