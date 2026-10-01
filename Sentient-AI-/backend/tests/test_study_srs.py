"""Tests for the SM-2 scheduler behind flashcard reviews: good gives 1 day, then
6, then round(previous × ease); easy on a new card gives 4 days and later the
good interval × 1.3; hard gives max(1, round(previous × 1.2)); again resets the
repetitions, adds a lapse and brings the card back in 10 minutes; the ease moves
by −0.54/−0.14/0/+0.10 with a floor of 1.3; no interval passes 365 days; and the
button previews and interval words match what grading does.

Why it exists: every review in chat, Telegram and Slack goes through
``srs.schedule``, so these fixed vectors are the contract. No clock, no
randomness, no database.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from services.study import srs
from services.study.srs import CardState, long_interval, previews, schedule, short_interval

NOW = datetime(2026, 9, 30, 9, 0, tzinfo=timezone.utc)


def days(result) -> float:
    return (result.due_at - NOW) / timedelta(days=1)


def test_good_goes_one_day_then_six_then_times_ease():
    first = schedule(CardState(), "good", NOW)
    assert days(first) == 1 and first.state.repetitions == 1 and first.state.ease == 2.5
    second = schedule(first.state, "good", NOW)
    assert days(second) == 6 and second.state.repetitions == 2
    third = schedule(second.state, "good", NOW)
    assert days(third) == 15  # round(6 × 2.5)
    fourth = schedule(third.state, "good", NOW)
    assert days(fourth) == 38  # round(15 × 2.5) = 37.5 rounds up


def test_easy_on_a_new_card_is_four_days_and_later_the_good_interval_times_1_3():
    new = schedule(CardState(), "easy", NOW)
    assert days(new) == 4 and new.state.ease == pytest.approx(2.6)
    after_good = schedule(CardState(), "good", NOW).state
    easy = schedule(after_good, "easy", NOW)
    assert days(easy) == 8  # round(6 × 1.3)


def test_hard_is_at_least_a_day_and_otherwise_previous_times_1_2():
    assert days(schedule(CardState(), "hard", NOW)) == 1
    state = CardState(ease=2.5, interval_days=10, repetitions=3)
    hard = schedule(state, "hard", NOW)
    assert days(hard) == 12 and hard.state.ease == pytest.approx(2.36)


def test_again_resets_repetitions_adds_a_lapse_and_is_due_in_ten_minutes():
    state = CardState(ease=2.5, interval_days=15, repetitions=3, lapses=1)
    again = schedule(state, "again", NOW)
    assert again.due_at == NOW + timedelta(minutes=10)
    assert (again.state.repetitions, again.state.lapses, again.state.interval_days) == (0, 2, 0.0)
    assert again.state.ease == pytest.approx(1.96)
    # After a lapse the card relearns from the first step.
    assert days(schedule(again.state, "good", NOW)) == 1


@pytest.mark.parametrize(
    ("rating", "change"), [("again", -0.54), ("hard", -0.14), ("good", 0.0), ("easy", 0.10)]
)
def test_ease_changes_by_the_classic_amounts(rating, change):
    state = CardState(ease=2.0, interval_days=6, repetitions=2)
    assert schedule(state, rating, NOW).state.ease == pytest.approx(2.0 + change)


def test_ease_never_drops_below_1_3():
    state = CardState(ease=1.35, interval_days=6, repetitions=2)
    for _ in range(5):
        state = schedule(state, "again", NOW).state
    assert state.ease == pytest.approx(1.3)


def test_intervals_are_capped_at_365_days():
    state = CardState(ease=2.5, interval_days=300, repetitions=8)
    assert days(schedule(state, "good", NOW)) == 365
    assert days(schedule(state, "easy", NOW)) == 365
    assert days(schedule(state, "hard", NOW)) == 360


def test_previews_match_what_grading_does():
    state = CardState(ease=2.5, interval_days=1, repetitions=1)
    shown = previews(state, NOW)
    assert {k: short_interval(v) for k, v in shown.items()} == {
        "again": "10m",
        "hard": "1d",
        "good": "6d",
        "easy": "8d",
    }
    for rating, delta in shown.items():
        assert schedule(state, rating, NOW).due_at - NOW == delta


def test_interval_words():
    assert short_interval(timedelta(minutes=10)) == "10m"
    assert short_interval(timedelta(hours=3)) == "3h"
    assert short_interval(timedelta(days=45)) == "45d"
    assert short_interval(timedelta(days=90)) == "3mo"
    assert short_interval(timedelta(days=365)) == "1y"
    assert long_interval(timedelta(minutes=10)) == "10 minutes"
    assert long_interval(timedelta(days=1)) == "1 day"
    assert long_interval(timedelta(days=6)) == "6 days"


def test_the_same_inputs_always_give_the_same_schedule():
    state = CardState(ease=2.18, interval_days=7, repetitions=4, lapses=2)
    assert all(schedule(state, "good", NOW) == schedule(state, "good", NOW) for _ in range(5))


@pytest.mark.parametrize("rating", ["meh", "", None, 0, 5, True, 2.5])
def test_a_bad_rating_is_refused(rating):
    with pytest.raises(ValueError):
        schedule(CardState(), rating, NOW)


def test_ratings_by_name_or_number():
    assert srs.rating_name("Good") == "good"
    assert srs.rating_name(1) == "again" and srs.rating_name(4) == "easy"
    assert srs.RATING_NUMBERS == {"again": 1, "hard": 2, "good": 3, "easy": 4}
