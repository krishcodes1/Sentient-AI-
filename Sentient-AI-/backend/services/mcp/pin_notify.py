"""The words MCP tool pinning sends and shows: the Telegram/Slack message when
tools of a server are held for review, the per-server message throttle, the
note the owner's Test appends to its result line, and the card note for an
approved definition that carried hidden characters. Pure: no I/O, no clock.

Why it exists: these messages leave Crawler (a linked chat) or sit on an
approval card, so they must never quote anything an MCP server wrote. They are
built only from the owner's own connector name, provider-safe exposed tool
names and counts, in one place a test can pin. services/mcp/pin_store.py sends
them through the same ``fan_out_send`` the reminders use, after its notify
claim; no approve buttons go to the channels on purpose (the review needs the
diff, which only the web Security page shows).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

# At most one message per server per this window. Every change is still held
# and listed on the Security page; the throttle only limits the chat noise a
# server with dynamic descriptions could cause.
NOTIFY_EVERY = timedelta(hours=6)
MAX_NAMES_PER_LINE = 5
MAX_SERVER_NAME_CHARS = 80
REVIEW_PLACE = "Security > MCP reviews"

HIDDEN_TEXT_NOTE_KIND = "mcp_hidden_text"
HIDDEN_TEXT_NOTE_SEVERITY = "warn"  # scaffold A3: "warning" became "warn"

_SAFE_TOOL_CHARS = re.compile(r"[^A-Za-z0-9_-]+")
_WHITESPACE_RUN = re.compile(r"\s+")


@dataclass(frozen=True)
class HeldTool:
    """One tool a message is about: its exposed name and why it is held."""

    tool: str  # the provider-safe exposed name, never the server's raw name
    kind: str  # "changed" or "new"


def _tool_name(name: str) -> str:
    # Exposed names are already [A-Za-z0-9_-]{1,64}; this keeps a message
    # safe even if a caller hands in something else by mistake.
    cleaned = _SAFE_TOOL_CHARS.sub("_", name).strip("_")[:64]
    return cleaned or "unnamed_tool"


def _server_name(name: str) -> str:
    """The owner's own connector name, on one line, without control or format
    characters, with straight double quotes swapped so the quoting holds."""
    kept = "".join(
        " " if unicodedata.category(ch) in ("Cc", "Zl", "Zp") else ch
        for ch in name
        if unicodedata.category(ch) not in ("Cf", "Cs", "Co")
    )
    one_line = _WHITESPACE_RUN.sub(" ", kept).strip().replace('"', "'")
    if len(one_line) > MAX_SERVER_NAME_CHARS:
        one_line = one_line[: MAX_SERVER_NAME_CHARS - 3].rstrip() + "..."
    return one_line or "MCP server"


def _names_line(names: Sequence[str]) -> str:
    shown = ", ".join(names[:MAX_NAMES_PER_LINE])
    extra = len(names) - MAX_NAMES_PER_LINE
    return f"{shown} and {extra} more" if extra > 0 else shown


def held_message(server_name: str, held: Sequence[HeldTool]) -> str:
    """The fact-only channel message for the tools of one server that were just held
    for review ("" when *held* is empty). One message per server per discovery; at
    most five names per line, then "and N more"."""
    changed: list[str] = []
    new: list[str] = []
    seen: set[str] = set()
    for item in held:
        name = _tool_name(item.tool)
        if name in seen:
            continue
        seen.add(name)
        # Anything not plainly "new" reads as a change: the wording that asks
        # the owner to look is the safe one.
        (new if item.kind == "new" else changed).append(name)
    total = len(changed) + len(new)
    if total == 0:
        return ""
    server = _server_name(server_name)
    if total == 1 and changed:
        return (
            f'Crawler security: a tool on your MCP server "{server}" changed.\n\n'
            f"{changed[0]} changed its description or inputs since it was approved. "
            "Crawler has stopped offering it to the AI until you review the change.\n\n"
            f"Review it in the Crawler web app: {REVIEW_PLACE}."
        )
    if total == 1:
        return (
            f'Crawler security: a new tool appeared on your MCP server "{server}".\n\n'
            f"{new[0]} is new on that server. Crawler will not offer it to the AI until "
            "you review it.\n\n"
            f"Review it in the Crawler web app: {REVIEW_PLACE}."
        )
    lines = [
        f'Crawler security: {total} tools on your MCP server "{server}" need your review.',
        "",
    ]
    if changed:
        lines.append(f"Changed: {_names_line(changed)}")
    if new:
        lines.append(f"New: {_names_line(new)}")
    lines += [
        "",
        "Crawler will not offer them to the AI until you review them in the Crawler web "
        f"app: {REVIEW_PLACE}.",
    ]
    return "\n".join(lines)


def _utc(moment: datetime) -> datetime:
    # SQLite returns these columns without a zone; both mean UTC.
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def may_notify(
    last_notified: Iterable[Optional[datetime]],
    *,
    now: datetime,
    every: timedelta = NOTIFY_EVERY,
) -> bool:
    """The per-server throttle: False when any pin of the server had a message sent
    within *every* before *now* (pass every pin's ``notified_at``). The caller still
    claims the change, so it is never sent later; it stays held and listed."""
    current = _utc(now)
    for moment in last_notified:
        if moment is not None and current - _utc(moment) < every:
            return False
    return True


def owner_test_note(*, first_use: bool, waiting: int, tools: int = 1) -> str:
    """The sentence the owner's Test appends to ``Connected. Server advertises N
    tool(s).`` (it starts with a space; "" when there is nothing to say).

    *first_use*: this Test pinned a server Crawler had never seen. *waiting*: how
    many of the server's tools now wait for review. *tools*: how many it advertises.
    """
    if first_use:
        if tools <= 0:
            return " Crawler will hold any tool this server adds later for your review."
        return (
            " Crawler remembered what each one does and will hold any that change for your review."
        )
    if waiting <= 0:
        return ""
    if waiting == 1:
        return " 1 tool changed or is new and waits for your review on the Security page."
    return f" {waiting} tools changed or are new and wait for your review on the Security page."


def hidden_text_note(hidden_chars: int) -> Optional[dict[str, str]]:
    """The typed ``security_notes`` entry for a card whose MCP tool's approved
    definition contained hidden characters (None when it had none). A plain dict in
    the shape ``SecurityNote.from_value`` accepts."""
    if hidden_chars <= 0:
        return None
    noun = "character" if hidden_chars == 1 else "characters"
    return {
        "kind": HIDDEN_TEXT_NOTE_KIND,
        "severity": HIDDEN_TEXT_NOTE_SEVERITY,
        "text": (
            f"This tool's description from the server contained {hidden_chars} hidden "
            f"{noun}. Crawler removed them before the AI read it."
        ),
    }
