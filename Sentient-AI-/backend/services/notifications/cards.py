"""Renders the arguments of an approval card in full, lays a card out as
labelled message-sized parts without dropping anything, computes a short
digest of the exact arguments shown, and paces the sending of the parts.
Also holds the channel-neutral reply texts (parked approvals, blocked calls,
cards still waiting) that each chat channel words with its own commands.

Why it exists: an approval card must never hide or cut what the owner is
approving (spec F3). Chat channels cap message length, so a long card is
sent as several messages, each naming the card it belongs to, and the
digest line lets the owner check that two cards (for example web and
Telegram) describe the same call.

Connects to: the Telegram approval card in services/notifications/telegram.py
and the Slack approval card. No network and no channel imports: sending
goes through a callback the channel passes in.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

# Hex characters of the sha256 shown on a card: 64 bits, enough to tell two
# calls apart at a glance while staying readable.
DIGEST_HEX_CHARS = 16

# Smallest limit the chunkers accept: any one character (two UTF-16 units at
# most) always fits, so splitting always makes progress, and the digest line
# always fits whole on the last message.
_MIN_CHUNK = 64

# Most messages one card may take, buttons included. A longer card is
# replaced by a short notice pointing at the web app: dozens of messages of
# JSON are no way to review an action, and would trip the channel's limits.
MAX_CARD_PARTS = 8

# Pause before each argument part of a split card and after the last one.
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


def digest_line(arguments: Any) -> str:
    """The last line of an approval card: ``Arguments digest: <hex>``."""
    return f"Arguments digest: {arguments_digest(arguments)}"


def render_arguments(arguments: Any) -> str:
    """Every argument in full as indented JSON; "" when there are none.
    Values JSON cannot encode are shown through ``str``."""
    if arguments is None or arguments == {}:
        return ""
    return json.dumps(arguments, indent=2, ensure_ascii=False, default=str)


# ── helpers every chat channel's card and reply share ────────────────────
# Public so a channel never imports another channel's private names (the
# Slack channel used to import these from telegram.py).


def card_arguments(tool_name: Any, arguments: Any) -> dict[str, Any]:
    """A call's arguments as its approval card shows them: whole, except
    that a desktop.act card leaves out the reserved keys starting with "_"
    (the screen the runtime stored, ``services.tools.computer.CARD_KEY``),
    which the model can never set. Nothing the owner approves is hidden."""
    if not isinstance(arguments, dict):
        return {}
    if tool_name != "desktop.act":
        return arguments
    return {k: v for k, v in arguments.items() if not str(k).startswith("_")}


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
    """Whole minutes until *expires_at_iso* ("12 min"), or "a few minutes"
    when the timestamp cannot be read. A naive timestamp counts as UTC."""
    try:
        expires = datetime.fromisoformat(expires_at_iso)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        minutes = max(0, int((expires - datetime.now(timezone.utc)).total_seconds() // 60))
        return f"{minutes} min"
    except (ValueError, TypeError):
        return "a few minutes"


# The reply to a "pending" request when no approval waits on the account.
NOTHING_PENDING_TEXT = "Nothing is waiting for your approval right now."


def turn_notes(outcome: dict[str, Any], *, where: str, pending_hint: str) -> str:
    """What a chat reply adds for what the turn left the person: the
    approvals it parked (their cards are already in the chat) and the calls
    security policy blocked. Empty when there is neither. *where* names the
    chat ("DM"), *pending_hint* how to list the cards again ("send pending")."""
    notes = ""
    if outcome.get("pending_approvals"):
        names = ", ".join(str(name) for name in outcome["pending_approvals"])
        notes += (
            f"\n\n\U0001f510 Waiting on your approval for: {names}. "
            f"The request is in this {where}, or {pending_hint}."
        )
    if outcome.get("blocked"):
        notes += "\n\n⛔ Blocked by security policy: " + ", ".join(
            str(name) for name in outcome["blocked"]
        )
    return notes


def waiting_cards_note(waiting: int, *, pending_hint: str) -> str:
    """What a "stop" reply adds when *waiting* approval cards still wait on
    the account: approving one runs that action, but its task stays stopped.
    Empty when none wait. *pending_hint* names how to list them ("send
    pending")."""
    if waiting <= 0:
        return ""
    if waiting == 1:
        return (
            f"\n\n1 action is still waiting for your approval ({pending_hint}). "
            "Approving it runs that one action; its task stays stopped."
        )
    return (
        f"\n\n{waiting} actions are still waiting for your approval ({pending_hint}). "
        "Approving one runs that one action; its task stays stopped."
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


def card_argument_chunks(arguments: Any, *, max_chars: int, length: LengthFn = len) -> list[str]:
    """*arguments* rendered in full (``render_arguments``) and split into
    parts of at most *max_chars* each (see ``split_text``). Joining the
    parts gives the full rendering back; no arguments give no parts."""
    return split_text(render_arguments(arguments), max_chars=max_chars, length=length)


@dataclass(frozen=True)
class CardLayout:
    """An approval card laid out for a channel's message limit.

    *leading* are the messages to send first, in order (empty when the card
    fits in one message). *final_lines* is the last message as lines, the
    one that carries the buttons, so the caller can append a short footer.
    *label* ("Approval <digest> (Tool: <name>)") heads every leading part
    and is repeated on the last message, so a part is never read as part of
    another card. *notice* is set instead of both when the card would need
    more than the part cap: send it alone, with no buttons. *parts* counts
    the messages the card takes (or would take), buttons included.
    """

    label: str
    parts: int
    final_lines: tuple[str, ...] = ()
    leading: tuple[str, ...] = ()
    notice: str | None = None


def _part_header(label: str, index: int, total: int) -> str:
    return f"{label}, part {index} of {total}"


def _blank_tail_marker(count: int) -> str:
    return f"[this part ends with {count} blank characters]"


def _leading_part(label: str, index: int, total: int, chunk: str) -> str:
    """One labelled argument part. The header line comes first, so a chunk
    that starts with blanks keeps them (channels trim each message's ends),
    and blanks at the end of a chunk are followed by a marker line naming
    how many there are: they are kept and the owner can see they exist."""
    text = f"{_part_header(label, index, total)}\n{chunk}"
    body = chunk.rstrip("\n")
    blank = len(body) - len(body.rstrip())
    if blank:
        text += "\n" + _blank_tail_marker(blank)
    return text


def _closing_lines(label: str, digest: str, total: int) -> list[str]:
    return [
        "",
        f"Part {total} of {total} of {label}. The arguments are in the parts above.",
        f"Arguments digest: {digest}",
    ]


def layout_card(
    head_lines: list[str],
    arguments: Any,
    *,
    tool_name: str,
    max_chars: int,
    length: LengthFn = len,
    max_parts: int = MAX_CARD_PARTS,
) -> CardLayout:
    """Lay out a whole approval card for a channel with a message limit.

    A card that fits is one message: *head_lines*, then "Arguments:" and
    every argument in full (left out when there are none), then the digest
    line. A longer card becomes labelled argument parts followed by a last
    message that repeats *head_lines* (or just the tool, if they are too
    long to repeat), names its part number and ends with the digest line,
    so the message with the buttons always says what it approves. Every
    message measures at most *max_chars*; joining the leading parts without
    their header and marker lines gives back the head (when it moved) and
    the arguments exactly. More than *max_parts* messages gives a notice
    instead. Raises ValueError when *max_chars* leaves no room for content.
    """
    _check_limit(max_chars)
    if max_parts < 2:
        raise ValueError(f"max_parts must be at least 2, got {max_parts}")
    digest = arguments_digest(arguments)
    label = f"Approval {digest} (Tool: {tool_name})"
    rendered = render_arguments(arguments)
    args_block = ["Arguments:", rendered] if rendered else []
    single = [*head_lines, *([""] + args_block if args_block else []), "", digest_line(arguments)]
    if length("\n".join(single)) <= max_chars:
        return CardLayout(label=label, parts=1, final_lines=tuple(single))

    final_head = list(head_lines)
    body_lines = args_block
    if length("\n".join([*final_head, *_closing_lines(label, digest, max_parts)])) > max_chars:
        # A head too long to repeat on the last message goes first instead.
        final_head = [f"Tool: {tool_name}"]
        body_lines = [*head_lines, "", *args_block] if args_block else list(head_lines)
    reserve = length(_part_header(label, max_parts, max_parts) + "\n")
    reserve += length("\n" + _blank_tail_marker(max_chars))
    budget = max_chars - reserve
    last = [*final_head, *_closing_lines(label, digest, max_parts)]
    if budget < _MIN_CHUNK or length("\n".join(last)) > max_chars:
        raise ValueError(f"max_chars {max_chars} leaves no room for the card labels")

    chunks = split_text("\n".join(body_lines), max_chars=budget, length=length)
    total = len(chunks) + 1
    if total > max_parts:
        notice = (
            f"{label}: the arguments are too long to show here "
            f"({len(rendered)} characters, {total} messages, the limit is {max_parts}). "
            "Review and decide in the web app."
        )
        if length(notice) > max_chars:
            raise ValueError(f"max_chars {max_chars} leaves no room for the card notice")
        return CardLayout(label=label, parts=total, notice=notice)
    return CardLayout(
        label=label,
        parts=total,
        final_lines=(*final_head, *_closing_lines(label, digest, total)),
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
    an incomplete card would approve something the owner could not read.
    """
    if card.notice is not None:
        await send(card.notice)
        return False
    for index, part in enumerate(card.leading, start=1):
        await asyncio.sleep(PART_INTERVAL_S)
        if not await send(part):
            await asyncio.sleep(FAILED_PART_NOTICE_DELAY_S)
            await send(
                f"{card.label}: part {index} of {card.parts} was not delivered, "
                f"so this card has no buttons. {retry_hint}"
            )
            return False
    if card.leading:
        await asyncio.sleep(PART_INTERVAL_S)
    return True
