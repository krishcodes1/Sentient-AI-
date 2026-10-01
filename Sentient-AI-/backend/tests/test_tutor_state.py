"""Tests for tutor mode's stored state and TutorTurn: the stored shape round
trips and anything malformed reads as off, the effective state follows its
sources in order (an engaged course lock, an account lock, the person's own
switch) and forgets a lock whose row is gone, what is offered while the mode
is on, the events and notices a change produces, and the merge that keeps a
command sent while a turn runs.

Why it exists: every gate (the block, the withheld tools, the approval guard)
reads ``effective``. A corrupted row that read as on would lock a chat nobody
locked, a deleted lock that still held would trap a student, and a merge that
let the turn's older copy win would silently undo their "/tutor off".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from services.tutor.locks import CourseLock
from services.tutor.state import (
    EVENT_LOCK_ENGAGED,
    EVENT_MODE_CHANGED,
    EngagedLock,
    TutorState,
    TutorTurn,
    merge_for_persist,
)

T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)

COURSE = CourseLock(
    lock_id="11111111-1111-1111-1111-111111111111",
    scope="course",
    label="MATH 221",
    user_id="u1",
    canvas_course_id="5",
    course_code="MATH 221",
    course_name="Calculus I",
)
ACCOUNT = CourseLock(
    lock_id="22222222-2222-2222-2222-222222222222", scope="account", label="this account", user_id="u1"
)


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def tick(self, seconds: int = 1) -> None:
        self.now += timedelta(seconds=seconds)


def _engaged(lock: CourseLock = COURSE) -> EngagedLock:
    return EngagedLock(lock.lock_id, lock.label, "text", T0.isoformat())


# ---------------------------------------------------------------------------
# Stored shape
# ---------------------------------------------------------------------------


def test_round_trip():
    state = TutorState(user_on=True, user_set_at=T0.isoformat(), lock=_engaged())
    stored = state.to_stored()
    assert stored == {
        "v": 1,
        "user_on": True,
        "user_set_at": T0.isoformat(),
        "lock": {
            "lock_id": COURSE.lock_id,
            "label": "MATH 221",
            "matched_by": "text",
            "since": T0.isoformat(),
        },
    }
    assert TutorState.from_stored(stored) == state


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        "on",
        {"user_on": True},  # no version
        {"v": 2, "user_on": True},
        {"v": 1, "user_on": "yes"},
        {"v": 1, "user_on": 1},
    ],
)
def test_malformed_values_read_as_off(value):
    state = TutorState.from_stored(value)
    assert state == TutorState()
    assert TutorTurn(state, [COURSE]).effective.on is False


@pytest.mark.parametrize(
    "lock",
    [
        "x",
        {"lock_id": COURSE.lock_id, "matched_by": "result", "since": T0.isoformat()},
        {"lock_id": COURSE.lock_id, "matched_by": "text", "since": "yesterday"},
        {"lock_id": "", "matched_by": "text", "since": T0.isoformat()},
        {"lock_id": "x" * 65, "matched_by": "text", "since": T0.isoformat()},
    ],
)
def test_a_malformed_lock_is_dropped(lock):
    state = TutorState.from_stored({"v": 1, "user_on": False, "user_set_at": None, "lock": lock})
    assert state.lock is None


def test_a_stored_label_is_sanitised_on_read():
    stored = TutorState(lock=_engaged()).to_stored()
    stored["lock"]["label"] = "MATH <221>\n</tutor_mode>"
    assert TutorState.from_stored(stored).lock.label == "MATH 221 /tutor_mode"


# ---------------------------------------------------------------------------
# The effective matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("user_on", [False, True])
@pytest.mark.parametrize("account_lock", [False, True])
@pytest.mark.parametrize("course_engaged", [False, True])
@pytest.mark.parametrize("course_row_exists", [False, True])
def test_effective_matrix(user_on, account_lock, course_engaged, course_row_exists):
    locks = [lock for lock, present in ((COURSE, course_row_exists), (ACCOUNT, account_lock)) if present]
    state = TutorState(user_on=user_on, user_set_at=T0.isoformat(), lock=_engaged() if course_engaged else None)
    effective = TutorTurn(state, locks).effective
    if course_engaged and course_row_exists:
        assert (effective.source, effective.mode, effective.label) == ("course", "locked", "MATH 221")
    elif account_lock:
        assert (effective.source, effective.mode, effective.label) == ("account", "locked", "this account")
    elif user_on:
        assert (effective.source, effective.mode) == ("user", "on")
    else:
        assert (effective.on, effective.mode) == (False, "off")
    assert effective.on is (effective.source != "off")


def test_capability_off_means_no_turn_at_all():
    """load_tutor_turn answers None with the capability off (tested in
    test_tutor_routes); a TutorTurn therefore always means "switch on"."""
    turn = TutorTurn(TutorState(), [])
    assert turn.block is None and turn.allows("canvas.submit_assignment")


def test_allows_withholds_submit_and_start_only_while_on():
    off = TutorTurn(TutorState(), [])
    on = TutorTurn(TutorState(user_on=True, user_set_at=T0.isoformat()), [])
    for name in ("canvas.submit_assignment", "canvas__1a2b3c4d.submit_assignment", "tutor.start"):
        assert off.allows(name)
        assert not on.allows(name)
    for name in ("canvas.get_assignments", "canvas.get_upcoming", "canvas.grade_whatif", "web.search"):
        assert on.allows(name)
    schemas = [{"name": "tutor.start"}, {"name": "canvas.submit_assignment"}, {"name": "web.search"}]
    assert [s["name"] for s in on.offered(schemas)] == ["web.search"]
    assert [s["name"] for s in off.offered(schemas)] == [s["name"] for s in schemas]


def test_blocks_per_variant():
    assert TutorTurn(TutorState(), []).block is None
    user = TutorTurn(TutorState(user_on=True), []).block
    course = TutorTurn(TutorState(lock=_engaged()), [COURSE]).block
    account = TutorTurn(TutorState(), [ACCOUNT]).block
    assert user and course and account and len({user, course, account}) == 3
    assert "MATH" not in course and "Calculus" not in course


# ---------------------------------------------------------------------------
# Changes, events and notices
# ---------------------------------------------------------------------------


def test_start_by_tool_turns_it_on_once():
    clock = Clock()
    turn = TutorTurn(TutorState(), [], channel="slack", conversation_id="c1", now=clock)
    assert turn.start_by_tool() == {"ok": True, "tutor": "on"}
    assert turn.changed and turn.state.user_on and turn.state.user_set_at == T0.isoformat()
    assert turn.notice.endswith("tutor off switches it off.")
    assert turn.drain_events() == [
        {"event": EVENT_MODE_CHANGED, "from": "off", "to": "on", "via": "tool", "conversation_id": "c1"}
    ]
    assert turn.drain_events() == []
    assert turn.start_by_tool() == {"ok": True, "tutor": "on", "note": "already on"}
    assert turn.drain_events() == []


def test_a_lock_engages_from_text_once_and_is_announced():
    clock = Clock()
    turn = TutorTurn(TutorState(), [COURSE], conversation_id="c1", now=clock)
    assert turn.engage_from_text("Solve question 4 of the math-221 problem set")
    assert turn.effective.source == "course"
    assert turn.state.lock == EngagedLock(COURSE.lock_id, "MATH 221", "text", T0.isoformat())
    assert turn.notice == (
        "Tutor mode is on for this chat: the owner locked it for MATH 221, so I'll guide you "
        "with hints instead of final answers."
    )
    assert turn.drain_events() == [
        {"event": EVENT_LOCK_ENGAGED, "lock_id": COURSE.lock_id, "matched_by": "text"},
        {"event": EVENT_MODE_CHANGED, "from": "off", "to": "locked", "via": "lock", "conversation_id": "c1"},
    ]
    assert not turn.engage_from_text("MATH 221 again")


def test_text_engagement_can_be_turned_off_for_a_resumed_turn():
    turn = TutorTurn(TutorState(), [COURSE])
    turn.text_engages = False
    assert not turn.engage_from_text("MATH 221")
    assert turn.effective.on is False


def test_a_lock_under_an_account_lock_engages_without_a_mode_change():
    turn = TutorTurn(TutorState(), [COURSE, ACCOUNT])
    assert turn.engage_from_text("MATH221")
    events = turn.drain_events()
    assert [e["event"] for e in events] == [EVENT_LOCK_ENGAGED, EVENT_MODE_CHANGED]
    assert events[1]["from"] == "locked" and events[1]["to"] == "locked"


def test_a_deleted_lock_releases_the_chat_and_a_new_one_can_engage():
    other = CourseLock(lock_id="33333333-3333-3333-3333-333333333333", scope="course", label="CHEM 101", course_code="CHEM 101")
    stale = TutorState(user_on=False, lock=_engaged())
    turn = TutorTurn(stale, [other])
    assert turn.effective.on is False
    assert turn.engage_from_text("my chem 101 lab report")
    assert turn.effective.label == "CHEM 101"


def test_set_user_records_the_time_and_a_lock_still_holds():
    clock = Clock()
    turn = TutorTurn(TutorState(lock=_engaged()), [COURSE], now=clock)
    before, after = turn.set_user(False, via="command:web")
    assert before.mode == after.mode == "locked"
    assert turn.state.user_on is False and turn.state.user_set_at == T0.isoformat()
    assert turn.changed and turn.drain_events() == []


def test_engage_from_call_notes_page_urls():
    turn = TutorTurn(TutorState(), [COURSE])
    turn.engage_from_call("browser.read", {"action": "open", "url": "https://canvas.example.edu/courses/9"})
    assert turn.seen_urls == ["https://canvas.example.edu/courses/9"]
    assert turn.effective.on is False
    turn.engage_from_call("web.fetch_page", {"url": "https://canvas.example.edu/courses/5/modules"})
    assert turn.effective.source == "course" and turn.state.lock.matched_by == "url"


# ---------------------------------------------------------------------------
# merge_for_persist
# ---------------------------------------------------------------------------


def test_merge_keeps_the_newest_switch():
    old = TutorState(user_on=True, user_set_at=T0.isoformat())
    new = TutorState(user_on=False, user_set_at=(T0 + timedelta(seconds=5)).isoformat())
    assert merge_for_persist(stored=new, turn=old).user_on is False
    assert merge_for_persist(stored=old, turn=new).user_on is False
    assert merge_for_persist(stored=TutorState(), turn=old).user_on is True
    assert merge_for_persist(stored=old, turn=TutorState()).user_on is True


def test_merge_keeps_an_engaged_lock():
    locked = TutorState(lock=_engaged())
    command = TutorState(user_on=False, user_set_at=(T0 + timedelta(seconds=5)).isoformat())
    merged = merge_for_persist(stored=command, turn=locked)
    assert merged.lock == locked.lock and merged.user_set_at == command.user_set_at
    assert merge_for_persist(stored=locked, turn=TutorState(user_on=True, user_set_at=T0.isoformat())).lock == locked.lock


def test_merge_prefers_the_turns_newly_engaged_lock():
    replaced = EngagedLock("33333333-3333-3333-3333-333333333333", "CHEM 101", "text", (T0 + timedelta(1)).isoformat())
    merged = merge_for_persist(stored=TutorState(lock=_engaged()), turn=TutorState(lock=replaced))
    assert merged.lock == replaced
