"""Turns an unattended run's outcome into the chat messages the owner gets
(``compose``) and sends them to the owner's own linked chats (``deliver``).

Why it exists: a scheduled result, a briefing and (wave 2) a trigger alert
all reach Telegram and Slack the same way: text (the reply's Markdown is
shown formatted on Telegram) with a header that names the task and its local
time, notes for what the owner must do (a card waits) or should know (a step
could not be used, the budget ran out), written in plain words with each step
named by its phrase from services/action_text.py (never a tool id), the usage
line and how to pause,
every URL without its query string, and at most four parts before a pointer
to the web app, where the whole result is kept.
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

# How each channel's owner pauses a task, and lists waiting cards (Slack
# keeps "/..." for its own slash commands, so it gets a word to reply).
_PAUSE_HINTS = {"telegram": "Send /schedules to pause this.", "slack": 'Reply "schedules" to pause this.'}
_PENDING_HINTS = {"telegram": "Send /pending to see", "slack": 'Reply "pending" to see'}
# The words for a step when its tool has no plain phrase (or the phrase
# table cannot be read): a tool id never reaches the chat.
_SOME_STEP = "do one of the steps"


def _strip_queries(text: str) -> str:
    # The same rule the chat channels use for a turn that read a logged-in
    # site (spec §9); every scheduled delivery gets it.
    from api.routes.agent import strip_url_queries

    return strip_url_queries(text)


def _short_phrase(name: Any) -> str:
    """One tool as a lower-case verb phrase ("send an email"), from
    services.action_text; the generic _SOME_STEP when that has nothing
    usable. Never raises."""
    try:
        from services.action_text import short_phrase

        phrase = short_phrase(str(name))
    except Exception as exc:  # a missing table or an odd name: still a sentence
        logger.warning("delivery_step_phrase_failed", error_type=type(exc).__name__)
        phrase = None
    if not isinstance(phrase, str) or not phrase.strip():
        return _SOME_STEP
    return phrase.strip()


def plain_steps(names: Any) -> str:
    """Tool names (``outcome.blocked``, ``outcome.unavailable``) as one
    phrase for a sentence: "send an email", "check your Canvas deadlines
    or read your email", "a, b or c". Duplicates are dropped; anything that
    is not a list of names gives the generic _SOME_STEP, and an entry that
    is not a name (None, a number, "") is left out rather than read as
    one."""
    if isinstance(names, (str, bytes)) or not isinstance(names, (list, tuple, set, frozenset)):
        names = [names] if isinstance(names, str) and names else []
    usable = [name for name in names if isinstance(name, str) and name.strip()]
    phrases = list(dict.fromkeys(_short_phrase(name) for name in usable))
    if not phrases:
        return _SOME_STEP
    if len(phrases) == 1:
        return phrases[0]
    return f"{', '.join(phrases[:-1])} or {phrases[-1]}"


def pending_note(count: int, hint: str) -> str:
    """'1 action is waiting for your approval. Send /pending to see it.'"""
    if count == 1:
        return f"1 action is waiting for your approval. {hint} it."
    return f"{count} actions are waiting for your approval. {hint} them."


def outcome_notes(outcome: UnattendedOutcome, channel: str) -> list[str]:
    """The lines a delivery adds after the reply, from the outcome's facts,
    in the owner's words: steps are named by their plain phrase (never a
    tool id) and each chat names only its own command."""
    notes: list[str] = []
    if outcome.cards >= 1:
        notes.append(pending_note(outcome.cards, _PENDING_HINTS.get(channel, _PENDING_HINTS["telegram"])))
    if outcome.unavailable:
        notes.append(f"This time I couldn't {plain_steps(outcome.unavailable)} (not connected or turned off).")
    if outcome.blocked:
        notes.append(f"I didn't {plain_steps(outcome.blocked)} because this task isn't set up to do that.")
    if outcome.status == "over_budget":
        budget = f"${outcome.budget_usd:.2f} " if outcome.budget_usd is not None else ""
        notes.append(f"I stopped because this task reached its {budget}spending limit.")
    elif outcome.status == "timed_out":
        notes.append("I stopped because this was taking too long.")
    elif outcome.status == "stopped":
        notes.append("I stopped because you asked me to.")
    elif outcome.status == "not_configured":
        notes.append("Add an AI service in Settings and this task will run next time.")
    return notes


def compose(
    label: str, when_local: str, outcome: UnattendedOutcome, channel: str
) -> list[str]:
    """The messages for *channel* ("telegram" or "slack"): header
    ("🗓 <label> · Tue 08:00"), the reply, the notes, then the usage line
    and how to pause. URL queries are stripped from all of it. Split into
    parts of at most PART_CHARS (Telegram counts UTF-16 units); past
    MAX_PARTS the rest is replaced by a pointer to the web app.

    Telegram's parts are TelegramMarkdown, so the reply shows formatted
    there: split where a code block can close and reopen, with a block the
    reply leaves open closed before the notes. Slack's are plain text."""
    from services.notifications import telegram_format
    from services.notifications.page_watch import defang

    # The label is shown as text, never as a link or a /command.
    header = f"{_CALENDAR} {defang(label)} · {when_local}"
    body = (outcome.reply or "").strip() or "(Nothing to report this time.)"
    notes = outcome_notes(outcome, channel)
    telegram = channel == "telegram"
    if telegram:
        body = telegram_format.close_fence(body)
    text = _strip_queries("\n\n".join([header, body, *notes]))
    length = cards.utf16_len if telegram else len
    if telegram:
        parts = telegram_format.split_markdown(text, PART_CHARS)
    else:
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
    footer_lines.append(_PAUSE_HINTS.get(channel, _PAUSE_HINTS["telegram"]))
    footer = "\n".join(footer_lines)
    if parts and length(parts[-1]) + 2 + length(footer) <= PART_CHARS:
        parts[-1] = f"{parts[-1]}\n\n{footer}"
    else:
        parts.append(footer)
    if telegram:
        return [telegram_format.TelegramMarkdown(part) for part in parts]
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
