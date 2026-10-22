"""Lays out an approval card for a chat channel: every detail of the action
as plain labelled lines with nothing cut, split into labelled message-sized
parts when it is long, ending with the question and a short check code of
the exact arguments; and paces the sending of the parts. Also holds the
channel-neutral texts that go with a card (the decision line, the reply
notes for requests waiting on an OK and steps the safety settings skipped,
the 7-day grant offer, the requests still waiting after a stop) that each
chat channel finishes with its own commands.

Why it exists: an approval card must never hide or cut what the owner is
approving (spec F3), and it must read like a person wrote it, not like a
developer log (docs/bot-message-style.md): no tool ids, no JSON, no
"arguments". Chat channels cap message length, so a long card is sent as
several messages, each naming the request it belongs to, and the check code
lets the owner see that two cards (for example the web app's and
Telegram's) describe the same call.

A card that fits in one message reads:

    🔐 Send an email to priya@acme.com from your Gmail

    To: priya@acme.com
    Subject: Friday lunch
    Message:
       Hi Priya, are we still on for noon?

    Okay to go ahead? This expires in 14 minutes.
    Check code 6d3b dfca 7bf8 cfc5

The channel writes the first line(s) (the head); this module writes the
details, the question and the check code.

Connects to: the Telegram approval card in services/notifications/telegram.py,
the Slack approval card in services/notifications/slack.py and the web API's
card (``detail_pairs``, ``check_code``). The words for each action (labels,
plain values, phrases) come from services/action_text.py. No network and no
channel imports: sending goes through a callback the channel passes in.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from services.action_text import (
    GUARD_PHRASES,
    exact_moment,
    field_label,
    field_value,
    short_phrase,
)
from services.security.call_checks import has_warnings, notes_from
from services.security.policies import CHANNEL
from services.security.redact import redact_obj

# Hex characters of the sha256 behind a card's check code: 64 bits, enough
# to tell two calls apart at a glance while staying readable. The code shows
# them in four groups of four ("6d3b dfca 7bf8 cfc5").
DIGEST_HEX_CHARS = 16

# Smallest limit the chunkers accept: any one character (two UTF-16 units at
# most) always fits, so splitting always makes progress, and the check code
# line always fits whole on the last message.
_MIN_CHUNK = 64

# Most messages one card may take, buttons included. A longer card is
# replaced by a short notice pointing at the web app: dozens of messages are
# no way to review an action, and would trip the channel's limits.
MAX_CARD_PARTS = 8

# Put before every line of a value that goes under its label (a message on
# several lines, a list, nested details), so no line inside a value can pass
# for another line of the card (a fake "To: someone@else.com").
DETAIL_INDENT = "   "

# Characters a chat app may show as a line break. A value is split on every
# one of them, so each piece of it goes on its own indented line.
_LINE_BREAKS = re.compile(r"\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]")

# How deep nested details are laid out line by line. Anything deeper (no
# real action nests this far; a value that contains itself would) is shown
# as one line of text instead of recursing forever.
_MAX_DETAIL_DEPTH = 12

# Pause before each details part of a split card and after the last one.
# Channels rate limit per chat (Telegram asks for about one message per
# second), so an unpaced burst of parts is refused part way through.
PART_INTERVAL_S = 1.0

# Pause before the "part was not delivered" notice: the usual cause is a
# rate limit, which a notice sent at once would hit as well.
FAILED_PART_NOTICE_DELAY_S = 5.0

# Measures a string in a channel's unit (``len`` or ``utf16_len``). It must
# be additive: length(a + b) == length(a) + length(b).
LengthFn = Callable[[str], int]

# Sends one message to the chat; True when it was delivered.
SendFn = Callable[[str], Awaitable[bool]]


def utf16_len(text: str) -> int:
    """Length of *text* in UTF-16 code units, the unit Telegram counts its
    4096 message limit in (a character outside the BMP counts as two)."""
    return len(text) + sum(1 for ch in text if ord(ch) > 0xFFFF)


def _canonical_json(arguments: Any) -> str:
    return json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def arguments_digest(arguments: Any) -> str:
    """Short hex sha256 of *arguments* as canonical JSON (sorted keys, no
    whitespace, unicode kept). Key order never changes it; any change to a
    key or value does."""
    canonical = _canonical_json(arguments)
    digest = hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()
    return digest[:DIGEST_HEX_CHARS]


def check_code(arguments: Any) -> str:
    """``arguments_digest`` in groups of four ("6d3b dfca 7bf8 cfc5"), easy
    to read out and compare. The web app's card shows the same code for the
    same call, whichever channel the owner decides in."""
    digest = arguments_digest(arguments)
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


def check_code_line(arguments: Any) -> str:
    """The quiet last line of an approval card: ``Check code 6d3b dfca 7bf8
    cfc5``, the code of the real arguments (before any masking)."""
    return f"Check code {check_code(arguments)}"


def _short_code(digest: str) -> str:
    """The first eight hex of a digest in two groups ("6d3b dfca"): what a
    request's label and its part headers name it by."""
    return f"{digest[:4]} {digest[4:8]}"


# ── the details on a card ────────────────────────────────────────────────
# Every argument as a plain "Label: value" line, in the arguments' own
# order, with nothing dropped or cut (spec F3). Labels and the plain words
# for known fixed values come from services/action_text.py.


def _safe_str(value: Any) -> str:
    """``str(value)``, then ``repr(value)``, and a plain placeholder only
    when both fail (an object whose own text raises). Never raises."""
    for show in (str, repr):
        try:
            text = show(value)
        except Exception:
            continue
        if isinstance(text, str):
            return text
    return "(a value I can't show)"


def _scalar_text(tool_name: Any, path: str, value: Any) -> str:
    """One plain value as text: "Yes"/"No" for a flag, "(none)" for no
    value, "(empty)" for empty text, the everyday words for a known fixed
    value (action_text.field_value: "speech_to_text" is "Voice notes"),
    an exact ISO date or time in words that keep the same moment
    (action_text.exact_moment), else the value itself, whole."""
    if value is None:
        return "(none)"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str):
        if value == "":
            return "(empty)"
        return field_value(tool_name, path, value) or exact_moment(value) or value
    return _safe_str(value)


def _join_path(path: str, key: Any) -> str:
    """A dotted key path ("event.start", "attendees.0.email"), which
    action_text.field_label reads whole first, then by its last part."""
    key_text = key if isinstance(key, str) else _safe_str(key)
    return f"{path}.{key_text}" if path else key_text


def _indented(lines: list[str]) -> list[str]:
    """*lines* moved under a label: each indented, blank ones left empty."""
    return [DETAIL_INDENT + line if line else "" for line in lines]


def _value_lines(tool_name: Any, path: str, value: Any, depth: int) -> tuple[list[str], bool]:
    """The lines one value shows as, and whether they go under the label
    (True for nested details, numbered lists and anything on more than one
    line; False for a value that reads well after "Label: ").

    A list of plain values gives one item per line; a list holding nested
    values gives numbered items ("1. Email: a@b.com"); a mapping gives its
    own "Sub label: value" lines. Empty ones are "(none)"."""
    if isinstance(value, Mapping) and depth < _MAX_DETAIL_DEPTH:
        if not value:
            return ["(none)"], False
        lines: list[str] = []
        for key, item in value.items():
            lines += _labelled(tool_name, _join_path(path, key), item, depth + 1)
        return lines, True
    if isinstance(value, (list, tuple)) and depth < _MAX_DETAIL_DEPTH:
        if not value:
            return ["(none)"], False
        numbered = any(isinstance(item, (Mapping, list, tuple)) for item in value)
        lines = []
        for index, item in enumerate(value):
            item_lines, _ = _value_lines(tool_name, _join_path(path, index), item, depth + 1)
            prefix = f"{index + 1}. " if numbered else ""
            pad = " " * len(prefix) if numbered else DETAIL_INDENT
            lines.append(prefix + item_lines[0])
            lines += [pad + line if line else "" for line in item_lines[1:]]
        return lines, numbered or len(lines) > 1
    lines = _LINE_BREAKS.split(_scalar_text(tool_name, path, value))
    return lines, len(lines) > 1


def _label_block(label: str, lines: list[str], under: bool) -> list[str]:
    """``Label: value`` for a value on one line, else ``Label:`` with every
    line of the value indented under it."""
    if not under:
        return [f"{label}: {lines[0]}"]
    return [f"{label}:", *_indented(lines)]


def _labelled(tool_name: Any, path: str, value: Any, depth: int) -> list[str]:
    """One labelled value as card lines (``_label_block``)."""
    lines, under = _value_lines(tool_name, path, value, depth)
    return _label_block(field_label(tool_name, path), lines, under)


def _details(tool_name: Any, arguments: Any) -> list[tuple[str, list[str], bool]]:
    """``(label, value lines, under)`` for every argument, in order. None or
    an empty mapping gives none; anything that is not a mapping gives one
    "Details" entry. Never raises: should a strange mapping fail part way,
    the whole value is shown as text under "Details" instead."""
    try:
        if arguments is None:
            return []
        if not isinstance(arguments, Mapping):
            lines, under = _value_lines(tool_name, "", arguments, 0)
            return [("Details", lines, under)]
        out = []
        for key, value in arguments.items():
            path = _join_path("", key)
            lines, under = _value_lines(tool_name, path, value, 0)
            out.append((field_label(tool_name, path), lines, under))
        return out
    except Exception:
        lines = _LINE_BREAKS.split(_safe_str(arguments))
        return [("Details", lines, len(lines) > 1)]


def detail_pairs(tool_name: str, arguments: Any) -> list[tuple[str, str]]:
    """Every argument as ``(label, value)`` in everyday words, in the
    arguments' own order, nothing dropped and nothing cut (spec F3).

    Labels come from action_text.field_label ("to" is "To", "message_id"
    is "Email ID"). Values: text as it is ("(empty)" when empty), known
    fixed values in plain words (action_text.field_value), None as
    "(none)", flags as "Yes"/"No", numbers as written, a list one item per
    line ("(none)" when empty), nested details as "Sub label: value" lines
    (indented further when they nest), a list of nested details as
    numbered items. A value on several lines keeps every line, joined with
    "\\n". Anything that is not a mapping gives one ("Details", value)
    pair. Never raises. The web API's card shows these; a chat card shows
    them through ``render_details``.
    """
    return [(label, "\n".join(lines)) for label, lines, _ in _details(tool_name, arguments)]


def render_details(tool_name: str, arguments: Any) -> str:
    """The details of a card as text: ``Label: value`` for a value that
    fits on one line, else ``Label:`` with every line of the value under
    it, indented by ``DETAIL_INDENT``, so text inside a value (say a
    message holding "To: attacker@x.com") can never pass for another line
    of the card. "" when there are no arguments. Never raises.

    Callers that send it to a chat mask secrets first:
    ``render_details(tool, redact_obj(arguments, CHANNEL))``.
    """
    lines: list[str] = []
    for label, value_lines, under in _details(tool_name, arguments):
        lines += _label_block(label, value_lines, under)
    return "\n".join(lines)


# ── helpers every chat channel's card and reply share ────────────────────
# Public so a channel never imports another channel's private names (the
# Slack channel used to import these from telegram.py).


def card_arguments(tool_name: Any, arguments: Any) -> dict[str, Any]:
    """A call's arguments as its approval card shows them: whole, except
    that a desktop.act card leaves out the reserved keys starting with "_"
    (the screen the runtime stored, ``services.tools.computer.CARD_KEY``),
    and a VirusTotal upload card its ``_upload`` (the file the runtime
    holds, security S10), which the model can never set. Nothing the owner
    approves is hidden."""
    if not isinstance(arguments, dict):
        return {}
    if tool_name not in {"desktop.act", "security.upload_to_virustotal"}:
        return arguments
    return {k: v for k, v in arguments.items() if not str(k).startswith("_")}


# ── security notes on cards (security wave, services/security/call_checks.py)
# The mark each note's line starts with, by severity.
SEVERITY_MARKS: Mapping[str, str] = {"high": "🚨", "warn": "⚠️", "info": "ℹ️"}


def security_notes_of(action: Any) -> list[dict[str, str]]:
    """The card's validated notes (``StoredAction.security_notes``); none
    for a card without them or with anything that is not a note."""
    return notes_from(list(getattr(action, "security_notes", None) or ()))


def security_note_lines(notes: Sequence[Mapping[str, str]]) -> list[str]:
    """One "<mark> <text>" line per note, in stored order. The text is the
    note's own one line (no message text, no markup)."""
    return [
        f"{SEVERITY_MARKS.get(note['severity'], SEVERITY_MARKS['warn'])} {note['text']}"
        for note in notes_from(list(notes))
    ]


def offers_standing_consent(action: Any) -> bool:
    """False when the card carries a high or warn note: it then offers
    neither "Allow for 7 days" nor "Allow low-risk changes" (A18)."""
    return not has_warnings(security_notes_of(action))


def more_notes_line(count: int) -> str:
    """The line that stands for *count* notes a caption had no room for."""
    return f"{SEVERITY_MARKS['info']} and {count} more security notes"


def fit_note_lines(
    render: Callable[[list[str]], str],
    note_lines: Sequence[str],
    *,
    max_chars: int,
    length: LengthFn = len,
) -> str:
    """``render(lines)`` with as many of *note_lines* as fit in *max_chars*
    (a photo caption's limit): whole lines are dropped from the end and
    replaced by one "and N more security notes" line. With no room even for
    that, the text with the "more" line alone (the channel cuts it)."""
    lines = list(note_lines)
    text = render(lines)
    if length(text) <= max_chars or not lines:
        return text
    for keep in range(len(lines) - 1, -1, -1):
        text = render([*lines[:keep], more_notes_line(len(lines) - keep)])
        if length(text) <= max_chars:
            return text
    return text


def usage_line(outcome: dict[str, Any]) -> str | None:
    """The per-reply usage footer for an outcome that reports its turn's
    usage, else None (see services.usage.format_turn_usage_line)."""
    if not isinstance(outcome.get("usage"), dict):
        return None
    from services.usage import format_turn_usage_line

    return format_turn_usage_line(
        outcome["usage"],
        outcome.get("provider"),
        outcome.get("model"),
        outcome.get("served_model"),
    )


def expires_in_text(expires_at_iso: str) -> str:
    """How long until *expires_at_iso*, in words: "14 minutes", "1 minute",
    "less than a minute" (also once it has passed), "about 2 hours" or
    "about 3 days" for a long wait, and "a few minutes" when the timestamp
    cannot be read. A naive timestamp counts as UTC. Never raises."""
    try:
        expires = (
            expires_at_iso
            if isinstance(expires_at_iso, datetime)
            else datetime.fromisoformat(str(expires_at_iso))
        )
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        minutes = max(0, int((expires - datetime.now(timezone.utc)).total_seconds() // 60))
    except (ValueError, TypeError, OverflowError):
        return "a few minutes"
    if minutes == 0:
        return "less than a minute"
    if minutes == 1:
        return "1 minute"
    if minutes < 90:
        return f"{minutes} minutes"
    hours = round(minutes / 60)
    if hours < 48:
        return f"about {hours} hours"
    return f"about {round(hours / 24):,} days"


def ask_line(expires_at_iso: str) -> str:
    """The question that closes an approval card, just above its check
    code: "Okay to go ahead? This expires in 14 minutes." Never raises."""
    return f"Okay to go ahead? This expires in {expires_in_text(expires_at_iso)}."


def decided_at_text(now: datetime | None = None) -> str:
    """A clock time as a decided card shows it ("5:25 PM"), in this
    computer's local time zone like the chat's dates (telegram._day). *now*
    defaults to the current time; a naive one counts as UTC. Never raises
    (a time that cannot be converted gives the current local time)."""
    try:
        moment = now if isinstance(now, datetime) else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        local = moment.astimezone()
    except (ValueError, TypeError, OverflowError, OSError):
        local = datetime.now()
    # Built by hand: strftime's "%-I" (no leading zero) fails on Windows.
    hour = local.hour % 12 or 12
    return f"{hour}:{local.minute:02d} {'AM' if local.hour < 12 else 'PM'}"


def decision_line(approved: bool, *, at: str) -> str:
    """The line a card gets once the owner has decided (its buttons go):
    "✅ Approved at 5:25 PM." or "❌ Denied at 5:25 PM. I didn't do it."
    *at* is ``decided_at_text()``; when it is empty the time is left out."""
    when = f" at {at.strip()}" if isinstance(at, str) and at.strip() else ""
    if approved:
        return f"✅ Approved{when}."
    return f"❌ Denied{when}. I didn't do it."


# The reply to a "pending" request when no approval waits on the account.
NOTHING_PENDING_TEXT = "Nothing is waiting for your approval right now."


def _phrases(names: Any) -> tuple[int, list[str]]:
    """How many steps *names* (tool names, as an outcome lists them) holds,
    and each step's plain phrase (action_text.short_phrase, never the tool
    name) once, in order, with "(2 times)" after one that comes up more
    than once."""
    items = list(names) if isinstance(names, (list, tuple)) else [names]
    counts = Counter(short_phrase(item) for item in items)
    return len(items), [
        phrase if count == 1 else f"{phrase} ({count} times)" for phrase, count in counts.items()
    ]


def turn_notes(outcome: dict[str, Any], *, pending_hint: str) -> str:
    """What a chat reply adds for what the turn left the person, in plain
    words and never by tool name: the requests waiting on their OK (the
    cards are already in the chat, just above the reply) and the steps
    their safety settings did not allow. Each note starts with a blank
    line; empty when there is neither. *pending_hint* says how to list the
    cards again ("send pending", "send /pending").

        🔐 I need your OK first to send an email. The request is just
        above, or send pending to see it again.

        ⛔ I skipped one step because your safety settings don't allow
        it: click or type in an app on your computer.
    """
    notes = ""
    again = pending_hint.strip() if isinstance(pending_hint, str) else ""
    try:
        pending = outcome.get("pending_approvals")
        blocked = outcome.get("blocked")
    except Exception:
        return ""
    if pending:
        count, phrases = _phrases(pending)
        if count == 1:
            notes += f"\n\n🔐 I need your OK first to {phrases[0]}. The request is just above"
            notes += f", or {again} to see it again." if again else "."
        else:
            notes += (
                f"\n\n🔐 I need your OK on {count} things first: {'; '.join(phrases)}. "
                "The requests are just above"
            )
            notes += f", or {again} to see them again." if again else "."
    # What the prompt guard stopped (the person's message, or my reply) is
    # no skipped step: the reply it wrote already says why
    # (action_text.GUARD_PHRASES), so it gets no note here.
    if isinstance(blocked, (list, tuple)):
        blocked = [name for name in blocked if not (isinstance(name, str) and name in GUARD_PHRASES)]
    elif isinstance(blocked, str) and blocked in GUARD_PHRASES:
        blocked = None
    if blocked:
        count, phrases = _phrases(blocked)
        if count == 1:
            notes += (
                "\n\n⛔ I skipped one step because your safety settings don't allow it: "
                f"{phrases[0]}."
            )
        else:
            notes += (
                f"\n\n⛔ I skipped {count} steps because your safety settings don't allow "
                f"them: {'; '.join(phrases)}."
            )
    return notes


# Most low-risk notes a grant line lists (permission tiers).
_GRANT_LINE_NOTES = 4


def low_risk_account(action: Any) -> str | None:
    """The account a card's grant offer names (StoredAction.grant_offer,
    written by the runtime), or None when the card offers no grant."""
    offer = getattr(action, "grant_offer", None)
    if not isinstance(offer, dict) or offer.get("kind") != "low_risk":
        return None
    account = offer.get("account")
    return account if isinstance(account, str) and account.strip() else None


def low_risk_line(account: str, notes: list[str], *, how: str) -> str:
    """What a card that offers the 7-day grant for small (low-risk) changes
    says about it: the account, up to four of its connector's low-risk notes
    (verb phrases such as "save email drafts (nothing is sent)"), what still
    asks, and *how* to list and revoke grants in this chat:

        Or let me make small changes on School Gmail for 7 days without
        asking: save email drafts (nothing is sent); star, mark important
        or apply your own labels to emails. I'll still ask before I send,
        delete or share anything, and before anything other people can
        see. /grants lists and revokes.
    """
    head = f"Or let me make small changes on {account} for 7 days without asking"
    shown = [str(note).strip().rstrip(".") for note in (notes or [])][:_GRANT_LINE_NOTES]
    shown = [note for note in shown if note]
    extra = len(notes or []) - _GRANT_LINE_NOTES
    if shown:
        head += ": " + "; ".join(shown) + (f"; and {extra} more." if extra > 0 else ".")
    else:
        head += "."
    return (
        f"{head} I'll still ask before I send, delete or share anything, and before "
        f"anything other people can see. {how}"
    ).rstrip()


def waiting_cards_note(waiting: int, *, pending_hint: str) -> str:
    """What a "stop" reply adds when *waiting* approval cards still wait on
    the account: approving one does just that one thing, and its task stays
    stopped. Empty when none wait. *pending_hint* says how to list them
    ("send pending")."""
    if waiting <= 0:
        return ""
    if waiting == 1:
        return (
            f"\n\nOne request is still waiting for your OK ({pending_hint} to see it). "
            "If you approve it, I'll do just that one thing and the task stays stopped."
        )
    return (
        f"\n\n{waiting} requests are still waiting for your OK ({pending_hint} to see them). "
        "If you approve one, I'll do just that one thing and the task stays stopped."
    )


def _check_limit(max_chars: int) -> None:
    if max_chars < _MIN_CHUNK:
        raise ValueError(f"max_chars must be at least {_MIN_CHUNK}, got {max_chars}")


def _longest_prefix(text: str, max_chars: int, length: LengthFn) -> int:
    """Largest k >= 1 with ``length(text[:k]) <= max_chars``. Every character
    measures at least one unit, so k never exceeds *max_chars* and the
    search only ever measures short prefixes."""
    upper = min(len(text), max_chars)
    if length(text[:upper]) <= max_chars:
        return upper
    low, high = 1, upper - 1
    while low < high:
        mid = (low + high + 1) // 2
        if length(text[:mid]) <= max_chars:
            low = mid
        else:
            high = mid - 1
    return low


def _fitting_prefix(text: str, room: int, length: LengthFn) -> int:
    """Largest k >= 0 with ``length(text[:k]) <= room`` (0 when not even
    the first character fits, such as a two-unit character in one unit)."""
    if room <= 0 or not text:
        return 0
    k = _longest_prefix(text, room, length)
    return k if length(text[:k]) <= room else 0


def _hard_split(line: str, max_chars: int, length: LengthFn, parts: list[str]) -> tuple[str, int]:
    """Append full-size pieces of an over-long *line* to *parts*; return the
    remainder (which fits) and its length. Walks an offset instead of
    re-slicing and re-measuring the rest, so a huge line stays linear."""
    pos = 0
    remaining = length(line)
    while remaining > max_chars:
        window = line[pos : pos + max_chars]
        cut = _longest_prefix(window, max_chars, length)
        piece = window[:cut]
        parts.append(piece)
        pos += cut
        remaining -= length(piece)
    return line[pos:], remaining


def split_text(text: str, *, max_chars: int, length: LengthFn = len) -> list[str]:
    """Split *text* into parts that each measure at most *max_chars* under
    *length*, breaking on line boundaries where possible and hard-splitting
    a line longer than the limit. ``"".join(parts) == text`` always holds:
    nothing is dropped or rewritten. An empty text gives no parts."""
    _check_limit(max_chars)
    if not text:
        return []
    if length(text) <= max_chars:
        return [text]
    parts: list[str] = []
    current = ""
    current_len = 0
    for line in text.splitlines(keepends=True):
        line_len = length(line)
        if current and current_len + line_len > max_chars:
            if line_len > max_chars:
                # This line is hard-split anyway: top up the current part
                # first instead of sending it half empty.
                take = _fitting_prefix(line, max_chars - current_len, length)
                current += line[:take]
                line_len -= length(line[:take])
                line = line[take:]
            parts.append(current)
            current, current_len = "", 0
        if line_len > max_chars:
            line, line_len = _hard_split(line, max_chars, length, parts)
        current += line
        current_len += line_len
    if current:
        parts.append(current)
    return parts


@dataclass(frozen=True)
class CardLayout:
    """An approval card laid out for a channel's message limit.

    *leading* are the messages to send first, in order (empty when the card
    fits in one message). *final_lines* is the last message as lines, the
    one that carries the buttons, ending with the question (when the
    caller gave one) and the check code line; the caller may append a
    short footer (a 7-day grant offer). *label* ("Request 6d3b dfca", the
    first eight hex of the check code) heads every leading part and is
    named again on the last message, so a part is never read as part of
    another card. *notice* is set instead of both when the card would need
    more than the part cap: send it alone, with no buttons. *parts* counts
    the messages the card takes (or would take), buttons included.
    """

    label: str
    parts: int
    final_lines: tuple[str, ...] = ()
    leading: tuple[str, ...] = ()
    notice: str | None = None


def _in_sentence(label: str) -> str:
    """A card label inside a sentence ("request 6d3b dfca")."""
    return label[:1].lower() + label[1:]


def _part_header(label: str, index: int, total: int) -> str:
    return f"{label}, part {index} of {total}"


def _blank_tail_marker(count: int) -> str:
    noun = "blank space" if count == 1 else "blank spaces"
    return f"(This part ends with {count} {noun}.)"


def _leading_part(label: str, index: int, total: int, chunk: str) -> str:
    """One labelled details part. The header line comes first, so a chunk
    that starts with blanks keeps them (channels trim each message's ends),
    and blanks at the end of a chunk are followed by a marker line naming
    how many there are: they are kept and the owner can see they exist."""
    text = f"{_part_header(label, index, total)}\n{chunk}"
    body = chunk.rstrip("\n")
    blank = len(body) - len(body.rstrip())
    if blank:
        text += "\n" + _blank_tail_marker(blank)
    return text


def _closing_line(label: str, total: int) -> str:
    """What the last message of a split card says about the parts above."""
    return (
        f"That's all of {_in_sentence(label)} (part {total} of {total}). "
        "The details are in the messages above."
    )


def _blocks(*blocks: list[str]) -> list[str]:
    """The non-empty *blocks* of lines, in order, a blank line between two."""
    lines: list[str] = []
    for block in blocks:
        if not block:
            continue
        if lines:
            lines.append("")
        lines += block
    return lines


def _head_reminder(head_lines: list[str], room: int, length: LengthFn) -> list[str]:
    """What the last message of a split card repeats of a head too long to
    repeat whole: its first line (the card's plain sentence), clipped with
    "…" when even that is longer than *room*. The whole head is in the
    first part, so nothing is lost; [] when there is no room at all."""
    first = next((line for line in head_lines if line.strip()), "")
    if not first or room <= 0:
        return []
    if length(first) <= room:
        return [first]
    keep = _fitting_prefix(first, room - length("…"), length)
    return [first[:keep].rstrip() + "…"] if keep > 0 else []


def layout_card(
    head_lines: list[str],
    arguments: Any,
    *,
    tool_name: str,
    max_chars: int,
    length: LengthFn = len,
    max_parts: int = MAX_CARD_PARTS,
    ask: str = "",
) -> CardLayout:
    """Lay out a whole approval card for a channel with a message limit.

    A card that fits is one message: *head_lines* (the channel's plain
    sentence and any note), a blank line, every detail in full
    (``render_details``, left out when there are none), a blank line, then
    *ask* (``ask_line``, when given) and the check code line last. A longer
    card becomes labelled details parts followed by a last message that
    repeats *head_lines* (or just their first line, the sentence, when they
    are too long to repeat), says it closes the request and ends the same
    way, so the message with the buttons always says what it approves.
    Every message measures at most *max_chars*; joining the leading parts
    without their header and marker lines gives back the head (when it
    moved) and the rendered details exactly. More than *max_parts* messages
    gives a notice instead. Raises ValueError when *max_chars* leaves no
    room for content.
    """
    _check_limit(max_chars)
    if max_parts < 2:
        raise ValueError(f"max_parts must be at least 2, got {max_parts}")
    # The check code is of the real arguments, so it matches the web card's;
    # the chat shows them with any key, card, bank or ID number masked
    # (policy CHANNEL): the chat app keeps its own copy of every message.
    digest = arguments_digest(arguments)
    label = f"Request {_short_code(digest)}"
    rendered = render_details(tool_name, redact_obj(arguments, CHANNEL))
    head = list(head_lines)
    details = rendered.split("\n") if rendered else []
    tail = [ask, check_code_line(arguments)] if ask else [check_code_line(arguments)]
    single = _blocks(head, details, tail)
    if length("\n".join(single)) <= max_chars:
        return CardLayout(label=label, parts=1, final_lines=tuple(single))

    def last_message(final_head: list[str], total: int) -> list[str]:
        return _blocks(final_head, [_closing_line(label, total)], tail)

    final_head = head
    body_lines = details
    if length("\n".join(last_message(head, max_parts))) > max_chars:
        # A head too long to repeat on the last message goes first, whole;
        # the last message repeats its first line (the sentence) instead.
        room = max_chars - length("\n".join(last_message([], max_parts))) - length("\n\n")
        final_head = _head_reminder(head, room, length)
        body_lines = _blocks(head, details)
    reserve = length(_part_header(label, max_parts, max_parts) + "\n")
    reserve += length("\n" + _blank_tail_marker(max_chars))
    budget = max_chars - reserve
    if budget < _MIN_CHUNK or length("\n".join(last_message(final_head, max_parts))) > max_chars:
        raise ValueError(f"max_chars {max_chars} leaves no room for the card labels")

    chunks = split_text("\n".join(body_lines), max_chars=budget, length=length)
    total = len(chunks) + 1
    if total > max_parts:
        notice = (
            f"{label} is too long to show here (it would take {total} messages). "
            "Open the Crawler web app to read it and decide there."
        )
        if length(notice) > max_chars:
            raise ValueError(f"max_chars {max_chars} leaves no room for the card notice")
        return CardLayout(label=label, parts=total, notice=notice)
    return CardLayout(
        label=label,
        parts=total,
        final_lines=tuple(last_message(final_head, total)),
        leading=tuple(
            _leading_part(label, index, total, chunk) for index, chunk in enumerate(chunks, start=1)
        ),
    )


async def send_card_parts(card: CardLayout, send: SendFn, *, retry_hint: str) -> bool:
    """Send everything that goes before a card's button message through
    *send* (one message per call, True when it was delivered), paced by
    ``PART_INTERVAL_S``. Returns True when the caller should now send the
    button message, False when it must not: the card is over the part cap
    (its notice was sent instead), or a part was lost (a notice naming the
    lost part and *retry_hint* is sent, best effort), since buttons under
    an incomplete card would approve something the owner could not read:
    "Part 2 of 3 of request 6d3b dfca didn't come through, so I left the
    buttons off to be safe. Send /pending to get it again, or decide in the
    web app."
    """
    if card.notice is not None:
        await send(card.notice)
        return False
    for index, part in enumerate(card.leading, start=1):
        await asyncio.sleep(PART_INTERVAL_S)
        if not await send(part):
            await asyncio.sleep(FAILED_PART_NOTICE_DELAY_S)
            await send(
                (
                    f"Part {index} of {card.parts} of {_in_sentence(card.label)} didn't come "
                    f"through, so I left the buttons off to be safe. {retry_hint}"
                ).rstrip()
            )
            return False
    if card.leading:
        await asyncio.sleep(PART_INTERVAL_S)
    return True
