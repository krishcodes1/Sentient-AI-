"""Deterministic SM-2 spaced repetition: given a card's state and a rating
(again, hard, good or easy), the card's next state and when it is due.

Why it exists: one pure function decides every review, whether it came from
chat, Telegram or Slack, so a card is scheduled the same way everywhere and
the rules are testable with fixed vectors (no clock, no randomness, no
dependency). The rules:

- good: a new card gets 1 day, then 6 days, then round(previous × ease);
- easy: a new card gets 4 days; later, the good interval × 1.3;
- hard: max(1, round(previous × 1.2)) days;
- again: repetitions back to 0, one more lapse, due again in 10 minutes;
- the ease moves by −0.54 (again), −0.14 (hard), 0 (good) or +0.10 (easy),
  never below 1.3; no interval is longer than 365 days.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

RATINGS: tuple[str, ...] = ("again", "hard", "good", "easy")
# The stored rating number (study_reviews.rating): 1 again ... 4 easy.
RATING_NUMBERS: dict[str, int] = {name: index + 1 for index, name in enumerate(RATINGS)}

START_EASE = 2.5
MIN_EASE = 1.3
MAX_INTERVAL_DAYS = 365
AGAIN_MINUTES = 10
EASE_CHANGE: dict[str, float] = {"again": -0.54, "hard": -0.14, "good": 0.0, "easy": 0.10}
FIRST_GOOD_DAYS = 1
SECOND_GOOD_DAYS = 6
FIRST_EASY_DAYS = 4
EASY_BONUS = 1.3
HARD_FACTOR = 1.2


@dataclass(frozen=True)
class CardState:
    """What SM-2 keeps per card."""

    ease: float = START_EASE
    interval_days: float = 0.0
    repetitions: int = 0
    lapses: int = 0


@dataclass(frozen=True)
class Scheduled:
    """A review's result: the new state and when the card is next due."""

    state: CardState
    due_at: datetime

    @property
    def interval_days(self) -> float:
        return self.state.interval_days


def _round_half_up(value: float) -> int:
    # round() rounds halves to even (round(2.5) == 2); intervals round up.
    return int(math.floor(value + 0.5))


def _cap(days: float) -> float:
    return float(min(MAX_INTERVAL_DAYS, max(0.0, days)))


def rating_name(rating: Any) -> Optional[str]:
    """The rating's name for a name ("Good") or a number (1-4); None for
    anything else."""
    if isinstance(rating, bool):
        return None
    if isinstance(rating, int):
        return RATINGS[rating - 1] if 1 <= rating <= len(RATINGS) else None
    if isinstance(rating, str):
        name = rating.strip().lower()
        return name if name in RATING_NUMBERS else None
    return None


def _good_days(state: CardState) -> int:
    if state.repetitions <= 0:
        return FIRST_GOOD_DAYS
    if state.repetitions == 1:
        return SECOND_GOOD_DAYS
    return max(1, _round_half_up(max(state.interval_days, 1.0) * state.ease))


def schedule(state: CardState, rating: Any, now: datetime) -> Scheduled:
    """The card's next state after *rating* at *now*. Raises ValueError for
    a rating that is not again, hard, good or easy (or 1-4)."""
    name = rating_name(rating)
    if name is None:
        raise ValueError("rating must be again, hard, good or easy")
    ease = max(MIN_EASE, round(state.ease + EASE_CHANGE[name], 2))
    if name == "again":
        return Scheduled(
            CardState(ease=ease, interval_days=0.0, repetitions=0, lapses=state.lapses + 1),
            now + timedelta(minutes=AGAIN_MINUTES),
        )
    if name == "hard":
        days = float(max(1, _round_half_up(state.interval_days * HARD_FACTOR)))
    elif name == "good":
        days = float(_good_days(state))
    else:
        days = float(
            FIRST_EASY_DAYS
            if state.repetitions <= 0
            else max(1, _round_half_up(_good_days(state) * EASY_BONUS))
        )
    days = _cap(days)
    return Scheduled(
        CardState(ease=ease, interval_days=days, repetitions=state.repetitions + 1, lapses=state.lapses),
        now + timedelta(days=days),
    )


def previews(state: CardState, now: datetime) -> dict[str, timedelta]:
    """How long each rating would put the card away, for the grade buttons."""
    return {name: schedule(state, name, now).due_at - now for name in RATINGS}


def short_interval(delta: timedelta) -> str:
    """"10m", "1d", "6d", "3mo", "1y": a grade button's interval."""
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60 * 24:
        return f"{max(1, minutes)}m" if minutes < 60 else f"{minutes // 60}h"
    days = _round_half_up(delta.total_seconds() / 86400)
    if days < 60:
        return f"{days}d"
    if days < MAX_INTERVAL_DAYS:
        return f"{_round_half_up(days / 30)}mo"
    return "1y"


def long_interval(delta: timedelta) -> str:
    """"10 minutes", "1 day", "6 days": the frozen card's "next in" line."""
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return "1 minute" if minutes <= 1 else f"{minutes} minutes"
    if minutes < 60 * 24:
        hours = minutes // 60
        return "1 hour" if hours == 1 else f"{hours} hours"
    days = _round_half_up(delta.total_seconds() / 86400)
    return "1 day" if days == 1 else f"{days} days"
