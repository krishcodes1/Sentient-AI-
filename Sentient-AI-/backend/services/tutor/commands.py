"""The ``/tutor on|off|status`` command grammar and the fixed replies every
channel sends for it.

Why it exists: only the conversation's own person switches tutor mode, with
a whole-message command parsed on the server, never by the model. The web
and Telegram take the slash forms; Slack's client swallows an unknown
``/tutor`` itself, so a Slack DM takes the bare words (``tutor on``).
Anything else, like "tutor me in calc" or "/tutoring", is an ordinary
message for the assistant. The replies are fixed text plus a sanitised
lock label, so they are the same on every channel apart from the off
command they name.

Connects to: services/tutor/service.py (apply_command), api/routes/agent.py
(the web intercept), services/notifications/telegram.py and slack.py.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

COMMAND_ON = "on"
COMMAND_OFF = "off"
COMMAND_STATUS = "status"
COMMANDS: frozenset[str] = frozenset({COMMAND_ON, COMMAND_OFF, COMMAND_STATUS})

# Where a command came from, as the audit row's "via" says (command:<channel>).
CHANNEL_WEB = "web"
CHANNEL_TELEGRAM = "telegram"
CHANNEL_SLACK = "slack"
CHANNELS: frozenset[str] = frozenset({CHANNEL_WEB, CHANNEL_TELEGRAM, CHANNEL_SLACK})

_SLASH = re.compile(r"/tutor(?:@[A-Za-z0-9_]{1,64})?(?:\s+(on|off|status))?", re.IGNORECASE)
_BARE = re.compile(r"tutor(?:\s+(on|off|status))?", re.IGNORECASE)
_ARGUMENT = re.compile(r"(on|off|status)?", re.IGNORECASE)


def parse_tutor_command(text: Any, *, slash_required: bool) -> Optional[str]:
    """``"on"``, ``"off"`` or ``"status"`` when *text* is, as a whole message,
    a tutor command; None when it is an ordinary message.

    With ``slash_required`` (web, Telegram) only ``/tutor``, ``/tutor on``,
    ``/tutor off`` and ``/tutor status`` count, a Telegram ``@bot`` suffix
    allowed; without it (Slack) only the bare ``tutor ...`` forms do. Case
    and surrounding whitespace do not matter; a bare ``/tutor`` is status."""
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped or len(stripped) > 100:
        return None
    match = (_SLASH if slash_required else _BARE).fullmatch(stripped)
    if match is None:
        return None
    return (match.group(1) or COMMAND_STATUS).lower()


def parse_tutor_argument(argument: Any) -> Optional[str]:
    """The command a Telegram ``/tutor <argument>`` asks for (the command
    word already matched): "" is status; anything but on/off/status is None."""
    if not isinstance(argument, str):
        return None
    match = _ARGUMENT.fullmatch(argument.strip())
    if match is None:
        return None
    return (match.group(1) or COMMAND_STATUS).lower()


def off_command(channel: str) -> str:
    """How the person switches tutor mode off on *channel*."""
    return "tutor off" if channel == CHANNEL_SLACK else "/tutor off"


def on_command(channel: str) -> str:
    return "tutor on" if channel == CHANNEL_SLACK else "/tutor on"


def usage_line(channel: str) -> str:
    """The reply to a malformed ``/tutor ...`` on Telegram."""
    word = "tutor" if channel == CHANNEL_SLACK else "/tutor"
    return f"Use {word} on, {word} off or {word} status."


REPLY_ON = (
    "Tutor mode is on for this chat. I'll guide you with questions and hints instead "
    "of giving final answers, and check your steps as you go. {off} switches it off."
)
REPLY_ON_LOCKED_COURSE = (
    "Tutor mode is on for this chat: the owner locked it for {label}. I'll guide you "
    "with questions and hints instead of giving final answers."
)
REPLY_ON_LOCKED_ACCOUNT = (
    "Tutor mode is on for this chat: the owner locked it for this account. I'll guide "
    "you with questions and hints instead of giving final answers."
)
REPLY_OFF = "Tutor mode is off for this chat."
REPLY_STAYS_LOCKED_COURSE = (
    "This chat stays in tutor mode: the owner locked it for {label}. Only the owner "
    "can change that, in Settings → Permissions."
)
REPLY_STAYS_LOCKED_ACCOUNT = (
    "This chat stays in tutor mode: the owner locked it for this account. Only the "
    "owner can change that, in Settings → Permissions."
)
STATUS_USER_ON = "Tutor mode: on in this chat (you turned it on). {off} switches it off."
STATUS_OFF = "Tutor mode: off in this chat. {on} turns it on."
STATUS_LOCKED_COURSE = "Tutor mode: on in this chat (the owner locked it for {label})."
STATUS_LOCKED_ACCOUNT = "Tutor mode: on in this chat (the owner locked it for this account)."
STATUS_LOCKS = "Owner locks that apply to you: {labels}."
STATUS_NO_LOCKS = "No owner locks apply to you."


def reply_for(
    command: str,
    *,
    source: str,
    label: str,
    channel: str,
    lock_labels: Iterable[str] = (),
) -> str:
    """The fixed reply to *command* once it was applied, for the effective
    state it left (*source*: "off", "user", "course" or "account"; *label*
    the course lock's sanitised label). ``lock_labels`` are the labels of
    the locks that apply to this person, for status."""
    off, on = off_command(channel), on_command(channel)
    if command == COMMAND_ON:
        if source == "course":
            return REPLY_ON_LOCKED_COURSE.format(label=label)
        if source == "account":
            return REPLY_ON_LOCKED_ACCOUNT
        return REPLY_ON.format(off=off)
    if command == COMMAND_OFF:
        if source == "course":
            return REPLY_STAYS_LOCKED_COURSE.format(label=label)
        if source == "account":
            return REPLY_STAYS_LOCKED_ACCOUNT
        return REPLY_OFF
    if source == "course":
        head = STATUS_LOCKED_COURSE.format(label=label)
    elif source == "account":
        head = STATUS_LOCKED_ACCOUNT
    elif source == "user":
        head = STATUS_USER_ON.format(off=off)
    else:
        head = STATUS_OFF.format(on=on)
    labels = sorted({text for text in lock_labels if text})
    tail = STATUS_LOCKS.format(labels=", ".join(labels)) if labels else STATUS_NO_LOCKS
    return f"{head}\n{tail}"
