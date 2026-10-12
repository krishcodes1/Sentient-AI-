"""Tests for what the audit log keeps of a goals.* call's arguments
(services/audit.redact_tool_arguments): an id only when it is a UUID; a
status, category, check-in choice, source, target date or clear flag only
when it is one the goals take; every other value (a title given as an id, a
key goals.* does not take, a milestone list, a delete card's facts) as its
length or item count, and a key name goals.* does not take as its length,
even one shaped like a field name; a misspelt or dotted action and a Goals
page row meet the same rule; and a row written through the runtime's audit
logger stores the reduced arguments.

Why it exists: the runtime writes a call's arguments to the append-only
audit log before the toolkit checks them, so a model that puts a goal's or a
milestone's title where its id belongs would otherwise leave the user's own
words there for good. In-memory SQLite; no model.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from models.audit import AuditLog
from services.audit import RuntimeAuditLogger, redact_tool_arguments
from tests.conftest import make_user

GOAL_ID = str(uuid.uuid4())
MILESTONE_ID = str(uuid.uuid4())
ENTRY_ID = str(uuid.uuid4())


def _chars(text: str) -> str:
    return f"<{len(text)} characters>"


def test_a_title_given_as_an_id_is_kept_as_its_length():
    goal_title = "Get an A in Calc 2"
    milestone_title = "Finish problem set 4 on integrals"
    assert redact_tool_arguments(
        "goals.update",
        {
            "goal_id": goal_title,
            "complete_milestones": [MILESTONE_ID, milestone_title],
            "reopen_milestones": "Week 3",
            "drop_milestones": [],
            "status": "paused",
        },
    ) == {
        "goal_id": _chars(goal_title),
        "complete_milestones": [MILESTONE_ID, _chars(milestone_title)],
        "reopen_milestones": _chars("Week 3"),
        "drop_milestones": [],
        "status": "paused",
    }
    assert redact_tool_arguments(
        "goals.log_progress",
        {
            "goal_id": GOAL_ID,
            "milestone_id": "Week 3 of couch to 5k",
            "note": "Ran 3k",
            "notes": "Ran 3k again",
        },
    ) == {
        "goal_id": GOAL_ID,
        "milestone_id": _chars("Week 3 of couch to 5k"),
        "note": _chars("Ran 3k"),
        _chars("notes"): _chars("Ran 3k again"),
    }
    assert redact_tool_arguments("goals.get", {"goal_id": uuid.UUID(GOAL_ID)}) == {
        "goal_id": uuid.UUID(GOAL_ID)
    }


def test_choices_dates_and_flags_are_kept_only_when_the_goals_take_them():
    assert redact_tool_arguments(
        "goals.update",
        {
            "goal_id": GOAL_ID,
            "title": "Run",
            "description": None,
            "category": "health",
            "check_in": "weekly",
            "target_date": "2027-05-01",
            "clear_target_date": False,
            "add_milestones": [{"title": "Run 3k"}],
        },
    ) == {
        "goal_id": GOAL_ID,
        "title": "<3 characters>",
        "description": None,
        "category": "health",
        "check_in": "weekly",
        "target_date": "2027-05-01",
        "clear_target_date": False,
        "add_milestones": "<1 item>",
    }
    assert redact_tool_arguments(
        "goals.update",
        {
            "goal_id": GOAL_ID,
            "status": "Run a 5k",
            "category": ["health"],
            "check_in": "Every morning at 6",
            "target_date": "next May",
            "clear_target_date": "yes",
        },
    ) == {
        "goal_id": GOAL_ID,
        "status": _chars("Run a 5k"),
        "category": "<1 item>",
        "check_in": _chars("Every morning at 6"),
        "target_date": _chars("next May"),
        "clear_target_date": _chars("yes"),
    }
    assert redact_tool_arguments("goals.list", {"status": "all", "category": "Marathon"}) == {
        "status": "all",
        "category": _chars("Marathon"),
    }


def test_every_goals_action_and_shape_meets_the_same_rule():
    for tool in ("goals.add", "goals__1a2b3c4d.create", " Goals.Update "):
        assert redact_tool_arguments(
            tool, {"title": "Run a 5k", "milestones": ["Run 3k", "Run 4k"], "Run a 5k": True}
        ) == {
            "title": "<8 characters>",
            "milestones": "<2 items>",
            "<8 characters>": "***REDACTED***",
        }, tool
    # A delete card's facts hold the goal's title: hidden outright.
    assert redact_tool_arguments(
        "goals.delete", {"goal_id": GOAL_ID, "_goal": {"title": "Run a 5k", "entries": 2}}
    ) == {"goal_id": GOAL_ID, "_goal": "***REDACTED***"}
    assert redact_tool_arguments("goals.create", "Run a 5k") == "<8 characters>"
    assert redact_tool_arguments("goals.create", None) is None
    # A Goals page row (api/routes/goals.py) is ids and its source only, kept.
    page = {"goal_id": GOAL_ID, "entry_id": ENTRY_ID, "source": "web"}
    assert redact_tool_arguments("goals.goal_progress_logged", page) == page
    arguments = {"goal_id": "Run a 5k"}
    redact_tool_arguments("goals.get", arguments)
    assert arguments == {"goal_id": "Run a 5k"}  # the caller's copy is untouched


def test_a_key_name_is_kept_only_when_the_goals_take_it():
    # A milestone's or goal's title written as an identifier is still the
    # user's words: only the names goals.* takes are kept, every other key
    # as its length (numbered when two share one).
    assert redact_tool_arguments(
        "goals.update",
        {
            "goal_id": GOAL_ID,
            "Finish_problem_set_4": True,
            "Get_an_A_in_Calc_2": "x",
            "Run_a_5k": 1,
            "Swim_10k": 2,
            "<8 characters>": 3,
            "check_in": "daily",
        },
    ) == {
        "goal_id": GOAL_ID,
        "<20 characters>": "***REDACTED***",
        "<18 characters>": "<1 character>",
        "<8 characters>": "***REDACTED***",
        "<8 characters> (2)": "***REDACTED***",
        "<14 characters>": "***REDACTED***",
        "check_in": "daily",
    }
    # Every field a goals.* call or a Goals page row takes keeps its name.
    taken = (
        "title description category status current_state target_date clear_target_date "
        "check_in milestones add_milestones complete_milestones reopen_milestones "
        "drop_milestones note milestone_id goal_id entry_id source _goal"
    ).split()
    kept = redact_tool_arguments("goals.update", dict.fromkeys(taken))
    assert kept == dict.fromkeys(taken)


def test_a_dotted_goals_action_meets_the_same_rule():
    # RuntimeAuditLogger files "goals.milestones.add" under connector goals
    # (its first dot), so its arguments are reduced like any goals.* call's.
    title = "Finish problem set 4 on integrals"
    for tool in ("goals.milestones.add", "goals__1a2b3c4d.update.extra", " Goals.list.all "):
        assert redact_tool_arguments(tool, {"goal_id": GOAL_ID, "title": title}) == {
            "goal_id": GOAL_ID,
            "title": _chars(title),
        }, tool
    # Another connector's dotted name is not a goals call.
    assert redact_tool_arguments("canvas.goals.add", {"title": title}) == {"title": title}


@pytest.mark.asyncio
async def test_the_stored_row_keeps_no_title(session_factory):
    user, _ = await make_user(session_factory, "goals-audit@example.com")
    await RuntimeAuditLogger(session_factory).log(
        {
            "event": "tool_executing",
            "user_id": str(user.id),
            "tool": "goals.update",
            "arguments": {
                "goal_id": "Get an A in Calc 2",
                "complete_milestones": ["Finish problem set 4"],
                "notes": "Integrals done",
            },
        }
    )
    async with session_factory() as session:
        [row] = (
            (await session.execute(select(AuditLog).where(AuditLog.user_id == user.id)))
            .scalars()
            .all()
        )
    assert (row.connector_name, row.action) == ("goals", "update")
    assert row.request_data == {
        "goal_id": _chars("Get an A in Calc 2"),
        "complete_milestones": [_chars("Finish problem set 4")],
        _chars("notes"): _chars("Integrals done"),
    }
    stored = json.dumps([row.request_data, row.reasoning_chain, row.response_summary])
    for word in ("Calc", "problem set", "Integrals"):
        assert word not in stored


@pytest.mark.asyncio
async def test_a_dotted_goals_row_keeps_no_title(session_factory):
    user, _ = await make_user(session_factory, "goals-dotted@example.com")
    await RuntimeAuditLogger(session_factory).log(
        {
            "event": "tool_unknown",
            "user_id": str(user.id),
            "tool": "goals.milestones.add",
            "arguments": {"goal_id": GOAL_ID, "title": "Finish problem set 4 on integrals"},
        }
    )
    async with session_factory() as session:
        [row] = (
            (await session.execute(select(AuditLog).where(AuditLog.user_id == user.id)))
            .scalars()
            .all()
        )
    assert (row.connector_name, row.action) == ("goals", "milestones.add")
    assert row.request_data == {
        "goal_id": GOAL_ID,
        "title": _chars("Finish problem set 4 on integrals"),
    }
