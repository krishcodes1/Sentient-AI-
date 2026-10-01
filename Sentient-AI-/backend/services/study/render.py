"""Turns study items into what Telegram and Slack show: plain-text screens with
buttons (Telegram) or keyword hints (Slack), card text made channel-safe, and
the full text an item can ever show at once (for the save-time length rule).

Why it exists: the review and quiz engine is written once and speaks in
``Screen`` values, so the two channels differ only in how they draw buttons.
Card text comes from documents the user did not write, so before it reaches a
chat every link, bare domain, e-mail address, @mention and /command in it is
defanged (page_watch.defang, applied to those spans only: "3.14" and "e.g."
stay as written). Nothing here reads the database or calls a network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional, Sequence

from services.notifications.page_watch import defang
from services.study.srs import RATINGS, long_interval, short_interval

LETTERS = "ABCDEF"
# Telegram caps a message at 4096 characters; an item must render within
# this many, so one card is always one message (Slack has room too).
RENDER_MAX_CHARS = 3500
# Telegram's callback_data limit, in bytes.
CALLBACK_MAX_BYTES = 64

# Spans a chat app would turn into a link, a mention or a command.
_LINKABLE = re.compile(
    r"(?:"
    r"(?i:\b(?:https?|ftp)://[^\s<>\"']+)"  # a URL
    r"|(?i:\bwww\.[^\s<>\"']+)"  # www.example
    r"|[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}"  # e-mail
    r"|(?<![\w@])@[A-Za-z0-9_]{1,64}"  # @mention
    r"|(?<![\w/])/[A-Za-z][A-Za-z0-9_]{0,63}"  # /command
    r"|\b(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b"  # a bare domain (letters after the last dot)
    r")"
)

_RATING_LABELS = {"again": "Again", "hard": "Hard", "good": "Good", "easy": "Easy"}


def channel_safe(text: str) -> str:
    """*text* with every URL, bare domain, e-mail, @mention and /command
    defanged, and nothing else changed."""
    return _LINKABLE.sub(lambda m: defang(m.group(0)), text or "")


@dataclass(frozen=True)
class Button:
    """One button: its label, its Telegram callback_data (at most 64 bytes)
    and the Slack keyword that does the same."""

    label: str
    data: str
    word: str = ""


@dataclass(frozen=True)
class Screen:
    """What a channel shows: the text, rows of buttons, a short answer for
    a Telegram button press, and whether the press changed nothing."""

    text: str
    buttons: tuple[tuple[Button, ...], ...] = ()
    notice: str = ""
    stale: bool = False

    def slack_text(self) -> str:
        """The text with a hint line naming the keywords (Slack has no
        buttons here)."""
        words = [b.word for row in self.buttons for b in row if b.word]
        if not words:
            return self.text
        return f"{self.text}\n\nReply {' / '.join(dict.fromkeys(words))}"


def choices_block(choices: Sequence[str]) -> str:
    return "\n".join(f"{LETTERS[i]}) {channel_safe(c)}" for i, c in enumerate(choices[: len(LETTERS)]))


def front_text(front: str, choices: Optional[Sequence[str]], header: str = "") -> str:
    parts = [header] if header else []
    parts.append(channel_safe(front))
    if choices:
        parts.append(choices_block(choices))
    return "\n\n".join(parts)


def answer_text(
    front: str,
    back: str,
    choices: Optional[Sequence[str]],
    answer_index: Optional[int],
    explanation: Optional[str],
    header: str = "",
) -> str:
    """The card with its answer (and the right choice, for a choice item)."""
    parts = [front_text(front, choices, header)]
    if choices and answer_index is not None and 0 <= answer_index < len(choices):
        parts.append(f"Answer: {LETTERS[answer_index]}) {channel_safe(choices[answer_index])}")
    else:
        parts.append(f"Answer: {channel_safe(back)}")
    if explanation:
        parts.append(f"Why: {channel_safe(explanation)}")
    return "\n\n".join(parts)


def full_text(
    front: str,
    back: str,
    choices: Optional[Sequence[str]],
    answer_index: Optional[int],
    explanation: Optional[str],
    choice_notes: Optional[Sequence[Optional[str]]],
    source_note: Optional[str] = None,
) -> str:
    """Everything an item can show at once (the answer, the explanation and
    every wrong choice's note, plus a header's worth of room): the text the
    3500-character rule measures."""
    header = "Quiz · a deck title of the longest allowed length · question 30 of 30" + " " * 60
    parts = [answer_text(front, back, choices, answer_index, explanation, header)]
    if choices and answer_index is not None and choice_notes:
        for index, note in enumerate(choice_notes[: len(choices)]):
            if note and index != answer_index:
                parts.append(f"{LETTERS[index]}) is wrong: {channel_safe(note)}")
    if choices:
        # A choice item's back is shown in chat reviews next to the choices.
        parts.append(channel_safe(back))
    if source_note:
        parts.append(f"Source: {channel_safe(source_note)}")
    return "\n\n".join(parts)


def grade_buttons(item_id: str, intervals: dict[str, timedelta]) -> tuple[Button, ...]:
    """"Again · 10m", "Hard · 1d", "Good · 6d", "Easy · 8d"."""
    return tuple(
        Button(
            f"{_RATING_LABELS[name]} · {short_interval(intervals[name])}",
            f"srg:{item_id}:{index + 1}",
            name,
        )
        for index, name in enumerate(RATINGS)
    )


def frozen_line(rating: str, interval: timedelta) -> str:
    """"✅ Good · next in 6 days"."""
    return f"✅ {_RATING_LABELS.get(rating, rating.title())} · next in {long_interval(interval)}"


def title_line(title: str) -> str:
    return channel_safe(title)
