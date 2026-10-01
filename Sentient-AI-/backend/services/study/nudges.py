"""The "cards are due" nudge: the text the schedule sweeper sends a user on
their study reminder's schedule, or nothing when nothing is due.

Why it exists: the daily reminder is a scheduled_tasks row of kind "nudge"
(services/scheduler/renderers.py), not a second scheduler; this module is its
renderer, registered at import (main.py imports it). It never calls a model:
one query for what is due by the end of the user's local day (decks in
reviews only, new cards counted up to what is left of today's allowance) and
one sentence with counts and at most three defanged deck titles, never card
text, at most 500 characters. It answers None, so the occurrence is skipped
silently, when the owner's "Flashcards and practice quizzes" switch is off
(read from the installation row in the sweeper's own session) or when
nothing is due.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

import structlog

from services.scheduler.renderers import register_nudge_renderer
from services.study import engine
from services.study.render import channel_safe

logger = structlog.get_logger(__name__)

RENDERER = "study_due"
CAPABILITY = "study"
LABEL = "Flashcards due"
NUDGE_MAX_CHARS = 500
MAX_TITLES = 3
TITLE_CHARS = 60
_BOOKS = "\U0001F4DA"
_HOW = 'Send /review on Telegram or "review" in Slack.'


async def _switch_on(session: Any) -> bool:
    """The owner's study switch as stored (a missing key reads as the
    capability's default, off). Unreadable counts as off."""
    from models.installation import INSTALLATION_ROW_ID, Installation
    from services import capabilities as registry

    default = bool(registry.default_switches().get(CAPABILITY, False))
    row = await session.get(Installation, INSTALLATION_ROW_ID)
    stored = dict(row.capabilities or {}) if row is not None else {}
    return bool(stored.get(CAPABILITY, default))


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def nudge_text(total: int, decks: list[tuple[str, int]]) -> str:
    """"📚 18 flashcards are due: Bio 101 – Lecture 3 (12), Chem 201 (6). ..."
    Counts and titles only."""
    noun = "flashcard is" if total == 1 else "flashcards are"
    shown = [f"{_cut(channel_safe(title), TITLE_CHARS)} ({count})" for title, count in decks[:MAX_TITLES]]
    more = len(decks) - len(shown)
    listing = ", ".join(shown) + (f" and {more} more deck{'s' if more != 1 else ''}" if more > 0 else "")
    text = f"{_BOOKS} {total} {noun} due: {listing}. {_HOW}"
    if len(text) > NUDGE_MAX_CHARS:
        text = f"{_BOOKS} {total} {noun} due. {_HOW}"
    return text[:NUDGE_MAX_CHARS]


async def render_due_nudge(session: Any, user_id: str, now: datetime) -> Optional[str]:
    """The nudge for *user_id* at *now*, or None to skip this occurrence."""
    owner = engine.as_uuid(str(user_id))
    if owner is None:
        return None
    try:
        if not await _switch_on(session):
            return None
        tz = await engine.user_zone(session, owner, engine.default_timezone())
        settings = await engine.load_settings(session, owner)
        new_left = await engine.new_left_today(session, owner, now, tz, settings.new_per_day)
        rows = await engine.due_counts_by_deck(
            session, owner, until=engine.day_end(now, tz), new_left=new_left
        )
    except Exception as exc:  # a nudge that cannot be read is skipped, never guessed
        logger.warning("study_nudge_unreadable", error_type=type(exc).__name__)
        return None
    total = sum(count for _deck, _title, count in rows)
    if total <= 0:
        return None
    return nudge_text(total, [(title, count) for _deck, title, count in rows])


register_nudge_renderer(RENDERER, CAPABILITY, render_due_nudge)
