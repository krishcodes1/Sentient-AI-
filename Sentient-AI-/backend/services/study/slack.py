"""Flashcard reviews and practice quizzes in a Slack DM, with no model involved:
the keywords "decks", "review", "review <n>" and "quiz <n> [count]", and,
while a card or question is waiting in that DM (30 minutes), "show", "again",
"hard", "good", "easy", "skip", "end" and "a" to "f".

Why it exists: the StudyChannel flow (services/study/channel.py) is drawn here
for Slack as plain text posts ending with a hint line, and registered in the
SlackChannel's keyword table, so the channel's own code does not change. It
runs only for the Slack user linked to the channel's account (checked by the
channel before any keyword handler). Any other text, and every keyword while
the owner's study switch is off, goes to the chat as it would without this
feature (the agent then explains the switch).
"""

from __future__ import annotations

from typing import Any, Awaitable, Optional

import structlog

from services.notifications import cards
from services.study import channel as study_channel
from services.study.channel import CURSOR_WORDS, StudyChannel
from services.study.render import Screen

logger = structlog.get_logger(__name__)

_PART_CHARS = 3900


def _key(channel: Any, dm: str) -> str:
    return f"slack:{channel.user_id}:{dm}"


def _start_words(words: list[str]) -> bool:
    """decks | review | review <n> | quiz <n> | quiz <n> <count>."""
    if not words:
        return False
    first, rest = words[0], words[1:]
    if first == "decks":
        return not rest
    if first == "review":
        return not rest or (len(rest) == 1 and rest[0].isdecimal())
    if first == "quiz":
        return 1 <= len(rest) <= 2 and all(w.isdecimal() and len(w) <= 6 for w in rest)
    return False


async def _post(channel: Any, dm: str, screen: Screen) -> None:
    for part in cards.split_text(screen.slack_text(), max_chars=_PART_CHARS):
        await channel._post_text(dm, part)


async def _answer(channel: Any, study: StudyChannel, dm: str, words: list[str]) -> list[Screen]:
    key = _key(channel, dm)
    user_id = channel.user_id
    first, rest = words[0], words[1:]
    if first == "decks" and not rest:
        return [await study.decks(user_id, slack=True)]
    if first == "review" and len(rest) <= 1:
        number = int(rest[0]) if rest else None
        return [await study.review_start(key, user_id, "slack", number)]
    if first == "quiz" and rest:
        count = int(rest[1]) if len(rest) == 2 else None
        return [await study.quiz_start(key, user_id, "slack", int(rest[0]), count)]
    return await study.word(key, user_id, "slack", first)


def register_slack(channel: Any) -> None:
    """Add the study keywords to a SlackChannel (tried after the built-in and
    earlier keywords; anything else goes to the chat)."""

    def _keyword_study(message: Any) -> Optional[Awaitable[None]]:
        study = study_channel.current()
        if study is None:
            return None
        words = message.text.strip().lower().split()
        if not _start_words(words):
            cursor_word = len(words) == 1 and words[0] in CURSOR_WORDS
            if not (cursor_word and study.has_cursor(_key(channel, message.channel), channel.user_id)):
                return None

        async def run() -> None:
            if not await study.is_enabled():
                # Off: the message goes to the chat as if this did not exist.
                channel._handle_chat(message.channel, message.text)
                return
            try:
                screens = await _answer(channel, study, message.channel, words)
            except Exception as exc:
                logger.error("slack_study_failed", error_type=type(exc).__name__)
                await channel._post_text(message.channel, "That did not work; try again.")
                return
            for screen in screens:
                await _post(channel, message.channel, screen)

        return run()

    channel._text_handlers.append(_keyword_study)
