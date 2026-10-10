"""Tests for scheduled-task recurrence and time zones: parsing and its errors
for each frequency, the next occurrence across weekends, month ends and
daylight-saving changes in New York and London, the one-year horizon of a
once task, the plain-words descriptions, and the zone checks that refuse a
path or a directory of zones.

Why it exists: a daily 08:00 that silently drifts by an hour twice a year, or
runs twice in an autumn fold, is exactly what an owner would never notice
until a briefing arrived at the wrong time. Pure functions, no database.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from services.scheduler.recurrence import (
    describe,
    local_label,
    next_after,
    parse_recurrence,
    phrase,
    recurrence_from_stored,
    short_when,
)
from services.scheduler.timezones import parse_zone, remember_zone, resolve_zone

NY = ZoneInfo("America/New_York")
LONDON = ZoneInfo("Europe/London")


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def rule(**params):
    parsed, error = parse_recurrence(params, today=date(2026, 9, 1))
    assert error is None, error
    return parsed


# ── parsing ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "params, message",
    [
        ({"freq": "hourly", "time": "08:00"}, "'freq' must be one of"),
        ({"freq": "daily"}, "'time' must be"),
        ({"freq": "daily", "time": "25:00"}, "'time' must be"),
        ({"freq": "daily", "time": "8am"}, "'time' must be"),
        ({"freq": "weekly", "time": "08:00"}, "needs 'days'"),
        ({"freq": "weekly", "time": "08:00", "days": ["funday"]}, "'days' must list"),
        ({"freq": "daily", "time": "08:00", "days": ["mon"]}, "only for a weekly"),
        ({"freq": "monthly", "time": "08:00"}, "needs 'day_of_month'"),
        ({"freq": "monthly", "time": "08:00", "day_of_month": 32}, "1 to 31"),
        ({"freq": "monthly", "time": "08:00", "day_of_month": 0}, "1 to 31"),
        ({"freq": "monthly", "time": "08:00", "day_of_month": True}, "1 to 31"),
        ({"freq": "daily", "time": "08:00", "day_of_month": 3}, "only for a monthly"),
        ({"freq": "once", "time": "08:00"}, "needs 'date'"),
        ({"freq": "once", "time": "08:00", "date": "2026-02-30"}, "real date"),
        ({"freq": "once", "time": "08:00", "date": "next week"}, "YYYY-MM-DD"),
        ({"freq": "once", "time": "08:00", "date": "2026-08-31"}, "already passed"),
        ({"freq": "once", "time": "08:00", "date": "2027-09-02"}, "within 365 days"),
        ({"freq": "daily", "time": "08:00", "date": "2026-10-01"}, "only for a one-time"),
    ],
)
def test_bad_recurrences_are_refused_with_a_plain_reason(params, message):
    parsed, error = parse_recurrence(params, today=date(2026, 9, 1))
    assert parsed is None and message in error


def test_each_frequency_parses_and_stores_only_its_own_keys():
    assert rule(freq="daily", time="8:05").to_dict() == {"freq": "daily", "time": "08:05"}
    assert rule(freq="weekdays", time="07:30").to_dict() == {"freq": "weekdays", "time": "07:30"}
    assert rule(freq="weekly", time="18:00", days=["wed", "Monday", "mon"]).to_dict() == {
        "freq": "weekly",
        "time": "18:00",
        "days": ["mon", "wed"],
    }
    assert rule(freq="monthly", time="09:00", day_of_month=-1).to_dict()["day_of_month"] == -1
    assert rule(freq="once", time="06:00", date="2027-08-31").to_dict()["date"] == "2027-08-31"


def test_a_stored_rule_is_read_back_without_the_date_checks():
    stored = {"freq": "once", "time": "06:00", "date": "2020-01-01", "junk": 1}
    assert recurrence_from_stored(stored).on_date == date(2020, 1, 1)
    assert recurrence_from_stored({"freq": "never"}) is None
    assert recurrence_from_stored("daily") is None


# ── next occurrence ───────────────────────────────────────────────────────


def test_daily_runs_today_if_the_time_is_ahead_else_tomorrow():
    daily = rule(freq="daily", time="08:00")
    assert next_after(daily, NY, utc(2026, 9, 29, 11, 0)) == utc(2026, 9, 29, 12, 0)
    assert next_after(daily, NY, utc(2026, 9, 29, 12, 0)) == utc(2026, 9, 30, 12, 0)


def test_weekdays_skip_the_weekend():
    weekdays = rule(freq="weekdays", time="08:00")
    # Friday 2 October 2026, after 08:00 in New York: Monday is next.
    assert next_after(weekdays, NY, utc(2026, 10, 2, 13, 0)) == utc(2026, 10, 5, 12, 0)


def test_weekly_on_several_days():
    weekly = rule(freq="weekly", time="18:00", days=["tue", "thu"])
    start = utc(2026, 9, 29, 23, 0)  # Tuesday 19:00 in New York
    first = next_after(weekly, NY, start)
    assert first == utc(2026, 10, 1, 22, 0)  # Thursday 18:00 EDT
    assert next_after(weekly, NY, first) == utc(2026, 10, 6, 22, 0)


def test_monthly_31st_runs_on_the_last_day_of_shorter_months():
    monthly = rule(freq="monthly", time="09:00", day_of_month=31)
    feb = next_after(monthly, LONDON, utc(2026, 2, 1, 0, 0))
    assert feb.astimezone(LONDON).date() == date(2026, 2, 28)
    leap = next_after(monthly, LONDON, utc(2028, 2, 1, 0, 0))
    assert leap.astimezone(LONDON).date() == date(2028, 2, 29)
    april = next_after(rule(freq="monthly", time="09:00", day_of_month=30), LONDON, utc(2026, 4, 1))
    assert april.astimezone(LONDON).date() == date(2026, 4, 30)


def test_monthly_last_day():
    last = rule(freq="monthly", time="09:00", day_of_month=-1)
    assert next_after(last, NY, utc(2026, 9, 1)).astimezone(NY).date() == date(2026, 9, 30)
    assert next_after(last, NY, utc(2026, 10, 1)).astimezone(NY).date() == date(2026, 10, 31)


def test_once_runs_once_then_never():
    once = rule(freq="once", time="06:00", date="2026-10-02")
    first = next_after(once, NY, utc(2026, 9, 30))
    assert first == utc(2026, 10, 2, 10, 0)
    assert next_after(once, NY, first) is None


def test_new_york_spring_gap_runs_after_the_gap():
    # 2026-03-08: clocks jump from 02:00 to 03:00; 02:30 does not exist.
    daily = rule(freq="daily", time="02:30")
    run = next_after(daily, NY, utc(2026, 3, 7, 12, 0))
    assert run == utc(2026, 3, 8, 7, 30)
    assert run.astimezone(NY).strftime("%H:%M %Z") == "03:30 EDT"
    assert next_after(daily, NY, run) == utc(2026, 3, 9, 6, 30)  # 02:30 EDT


def test_new_york_autumn_fold_runs_once_at_the_first_occurrence():
    # 2026-11-01: 01:00-02:00 happens twice.
    daily = rule(freq="daily", time="01:30")
    run = next_after(daily, NY, utc(2026, 10, 31, 12, 0))
    assert run == utc(2026, 11, 1, 5, 30)  # 01:30 EDT, the first one
    # The second 01:30 (06:30 UTC) is not scheduled: next is the next day.
    assert next_after(daily, NY, run) == utc(2026, 11, 2, 6, 30)


def test_london_gap_and_fold():
    daily = rule(freq="daily", time="01:30")
    # 2026-03-29: 01:00 GMT jumps to 02:00 BST.
    spring = next_after(daily, LONDON, utc(2026, 3, 28, 12, 0))
    assert spring == utc(2026, 3, 29, 1, 30)
    assert spring.astimezone(LONDON).strftime("%H:%M") == "02:30"
    # 2026-10-25: 01:00-02:00 happens twice; the first is BST.
    autumn = next_after(daily, LONDON, utc(2026, 10, 24, 12, 0))
    assert autumn == utc(2026, 10, 25, 0, 30)
    assert next_after(daily, LONDON, autumn) == utc(2026, 10, 26, 1, 30)


def test_a_naive_after_counts_as_utc():
    daily = rule(freq="daily", time="08:00")
    assert next_after(daily, NY, datetime(2026, 9, 29, 11, 0)) == utc(2026, 9, 29, 12, 0)


# ── words ─────────────────────────────────────────────────────────────────


def test_describe_and_phrase():
    assert describe(rule(freq="weekdays", time="08:00")) == "Weekdays at 08:00"
    assert describe(rule(freq="daily", time="07:30")) == "Every day at 07:30"
    assert describe(rule(freq="weekly", time="18:00", days=["mon", "wed"])) == "Mon, Wed at 18:00"
    assert describe(rule(freq="monthly", time="09:00", day_of_month=-1)) == "Last day of the month at 09:00"
    assert describe(rule(freq="monthly", time="09:00", day_of_month=15)) == "Day 15 of the month at 09:00"
    assert describe(rule(freq="once", time="06:00", date="2026-10-02")) == "Once on 2026-10-02 at 06:00"
    assert phrase(rule(freq="weekdays", time="08:00")) == "every weekday at 08:00"
    assert phrase(rule(freq="weekly", time="18:00", days=["mon", "wed", "fri"])) == (
        "every Monday, Wednesday and Friday at 18:00"
    )


def test_local_labels():
    instant = utc(2026, 9, 29, 12, 0)
    assert local_label(instant, NY) == "Tue 2026-09-29 08:00"
    assert short_when(instant, NY) == "Tue 08:00"
    assert local_label(None, NY) is None


# ── zones ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name", ["../etc", "America", "", "   ", "Mars/Olympus", "America/New_York/../x", 42, None, "zone.tab"]
)
def test_invalid_zones_are_refused(name):
    zone, error = parse_zone(name)
    assert zone is None and error


@pytest.mark.parametrize("name", ["America/New_York", "Europe/London", "UTC", "Asia/Kolkata"])
def test_real_zones_parse(name):
    zone, error = parse_zone(name)
    assert error is None and str(zone) == name


def test_resolve_zone_prefers_the_argument_then_the_user_then_the_install():
    assert str(resolve_zone("Europe/London", "America/Chicago", "UTC")) == "Europe/London"
    assert str(resolve_zone(None, "America/Chicago", "UTC")) == "America/Chicago"
    assert str(resolve_zone(None, None, "UTC")) == "UTC"
    assert str(resolve_zone(None, "../etc", "UTC")) == "UTC"
    assert resolve_zone(None, None, None) is None
    # An invalid argument resolves to nothing, never to a guess.
    assert resolve_zone("America", "America/Chicago", "UTC") is None


def test_remember_zone_stores_a_valid_changed_zone_only():
    class User:
        timezone = None

    user = User()
    assert remember_zone(user, "America/Chicago") is True and user.timezone == "America/Chicago"
    assert remember_zone(user, "America/Chicago") is False
    assert remember_zone(user, "../etc") is False and user.timezone == "America/Chicago"
    assert remember_zone(user, None) is False
