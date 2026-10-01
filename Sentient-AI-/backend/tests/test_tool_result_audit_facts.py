"""Tests for what an audit row keeps of a schedule.*, study.* or triggers.*
result (runtime.result_for_audit with services/agent/audit_facts.py and each
skill's rules): ids, status, counts, grades and scores stay; a scheduled
task's prompt, a briefing's topic, a label, card text, a deck title, an export
link, a trigger's filters and what a fire saw never reach the row.

Why it exists: the runtime stores the first 500 characters of every tool
result in the append-only audit log. The e2e run found a schedule.list row
holding the task prompt and a study.review row holding the card text; this
pins the allowlist on the real toolkits' results (in-memory SQLite, a fixed
clock, fake reminders and gate; no network, no model).
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest

from services.agent.audit_facts import ERROR_CHARS, FactRules, keep_facts
from services.agent.runtime import AgentRuntime, result_for_audit
from services.study.export import ExportTokens
from services.tools.schedule import ScheduleToolkit
from services.tools.study import StudyToolkit
from tests.conftest import make_user
from tests.test_schedule_toolkit import NOW as SCHEDULE_NOW
from tests.test_study_toolkit import Clock, FakeNudges, choice_item
from tests.test_trigger_toolkit import EMAIL, NOW as TRIGGER_NOW, approved_create, connector
from tests.test_trigger_toolkit import toolkit as trigger_toolkit

PROMPT = "Summarise the quokkavine lab notes and email Dr Pemberton."
TOPIC = "quokkavine enzyme research"
FRONT = "What does the quokkavine enzyme regulate?"
BACK = "Photosynthesis in marsupial gardens"
EXPLANATION = "Lecture 3, page 2 of the zarblot handout."
DECK_TITLE = "Zarblot Biology 101"


def row_text(tool: str, result: object) -> str:
    """The result_summary the runtime would write for *result*."""
    return AgentRuntime._summarize_result(result_for_audit(tool, result))


# -- the allowlist ------------------------------------------------------------------------


def test_keep_facts_keeps_numbers_named_text_and_names_and_counts_the_rest():
    rules = FactRules(
        text=frozenset({"id", "status"}),
        names=frozenset({"tools"}),
        rows={"rows": FactRules(text=frozenset({"id"}))},
    )
    value = {
        "ok": True,
        "id": "t1",
        "status": "active",
        "count": 3,
        "ratio": 0.5,
        "missing": None,
        "label": "private label",
        "tools": ["web.search", "canvas.get_upcoming"],
        "secrets": ["a private line", "another"],
        "forecast": [1, 2, 3],
        "rows": [{"id": "r1", "text": "private row"}, "not a row"],
        "blob": {"text": "private nested"},
        "error": "e" * 300,
        7: "a non-string key",
    }
    facts = keep_facts(value, rules)
    assert facts == {
        "ok": True,
        "id": "t1",
        "status": "active",
        "count": 3,
        "ratio": 0.5,
        "missing": None,
        "tools": ["web.search", "canvas.get_upcoming"],
        "secrets": 2,
        "forecast": [1, 2, 3],
        "rows": [{"id": "r1"}],
        "error": "e" * ERROR_CHARS,
    }
    assert keep_facts("a whole string result", rules) == "<str>"
    assert keep_facts(["a", "list"], rules) == "<list>"
    assert keep_facts(None, rules) is None


def test_other_tools_are_not_routed_through_these_rules():
    assert result_for_audit("reminders.list", {"ok": True, "items": [{"text": "x"}]}) == {
        "ok": True,
        "items": [{"text": "x"}],
    }
    # A slugged spelling still reaches the rules.
    assert "prompt" not in result_for_audit(
        "schedule__1a2b3c4d.list", {"ok": True, "prompt": PROMPT}
    )


# -- schedule.* ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_schedule_rows_keep_ids_and_status_never_the_prompt_or_topic(session_factory):
    user, _ = await make_user(session_factory, "audit-schedule@example.com")
    uid = str(user.id)
    kit = ScheduleToolkit(
        session_factory, clock=lambda: SCHEDULE_NOW, default_timezone=lambda: None
    )
    args = {
        # A label is the owner's short name for the task: the create row's
        # arguments keep it (only the prompt and topic are length-only).
        "label": "Lab digest",
        "prompt": PROMPT,
        "freq": "weekdays",
        "time": "08:00",
        "tools": ["canvas.get_upcoming"],
        "timezone": "America/New_York",
    }
    created = await kit.execute("create", args, uid)
    assert created["ok"] is True
    briefing = await kit.execute(
        "briefing",
        {"freq": "daily", "time": "07:30", "topic": TOPIC, "timezone": "America/New_York"},
        uid,
    )
    assert briefing["ok"] is True
    listing = await kit.execute("list", {}, uid)
    assert PROMPT[:40] in json.dumps(listing) and TOPIC in json.dumps(
        listing
    )  # the model sees them
    paused = await kit.execute("pause", {"task_id": created["task_id"], "paused": True}, uid)
    duplicate = await kit.execute("create", args, uid)
    deleted = await kit.execute("delete", {"task_id": created["task_id"]}, uid)

    for result in (created, briefing, listing, paused, duplicate, deleted):
        text = row_text("schedule.list", result)
        for private in ("quokkavine", "Quokkavine", "Pemberton"):
            assert private not in text, (private, text)

    facts = result_for_audit("schedule.list", listing)
    assert facts["ok"] is True and facts["count"] == 2
    tasks = {t["kind"]: t for t in facts["tasks"]}
    task = tasks["prompt"]
    assert task["id"] == created["task_id"] and task["status"] == "active"
    assert task["schedule"] == "Weekdays at 08:00" and task["tools"] == ["canvas.get_upcoming"]
    assert (
        "prompt" not in task
        and "label" not in task
        and "Lab digest" not in row_text("schedule.list", listing)
    )
    assert tasks["briefing"]["id"] == briefing["task_id"] and "topic" not in tasks["briefing"]
    assert result_for_audit("schedule.pause", paused) == {
        "ok": True,
        "task_id": created["task_id"],
        "status": "paused",
    }
    assert result_for_audit("schedule.create", duplicate)["duplicate"] is True


# -- study.* ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_study_rows_keep_ids_grades_and_scores_never_card_text(session_factory):
    user, _ = await make_user(session_factory, "audit-study@example.com")
    uid = str(user.id)
    clock = Clock()
    kit = StudyToolkit(
        session_factory,
        clock=clock,
        exports=ExportTokens(clock=clock),
        nudges=FakeNudges(session_factory),
        default_timezone=lambda: "UTC",
    )
    card = {"front": FRONT, "back": BACK, "explanation": EXPLANATION, "tags": ["zarblot"]}
    choice = {**choice_item("Which zarblot organelle makes ATP?"), "explanation": EXPLANATION}
    saved = await kit.execute(
        "save",
        {"title": DECK_TITLE, "course": "ZARB 101", "items": [card, choice, {"front": ""}]},
        uid,
    )
    assert saved["ok"] is True
    deck_id = saved["deck_id"]
    results = {
        "save": saved,
        "decks": await kit.execute("decks", {}, uid),
        "deck_items": await kit.execute("decks", {"deck_id": deck_id, "full": True}, uid),
        "review_next": await kit.execute("review", {"action": "next", "count": 2}, uid),
    }
    first = results["review_next"]["items"][0]["item_id"]
    results["review_grade"] = await kit.execute(
        "review", {"action": "grade", "item_id": first, "rating": "good"}, uid
    )
    started = await kit.execute("quiz", {"action": "start", "deck_id": deck_id}, uid)
    results["quiz_start"] = started
    by_kind = {q["kind"]: q for q in started["questions"]}
    results["quiz_reveal"] = await kit.execute(
        "quiz",
        {
            "action": "reveal",
            "attempt_id": started["attempt_id"],
            "item_id": by_kind["card"]["item_id"],
        },
        uid,
    )
    results["quiz_submit"] = await kit.execute(
        "quiz",
        {
            "action": "submit",
            "attempt_id": started["attempt_id"],
            "answers": [
                {"item_id": by_kind["choice"]["item_id"], "choice": 0},
                {"item_id": by_kind["card"]["item_id"], "correct": True},
            ],
        },
        uid,
    )
    results["quiz_finish"] = await kit.execute(
        "quiz", {"action": "finish", "attempt_id": started["attempt_id"]}, uid
    )
    clock.advance(days=1)
    results["progress"] = await kit.execute("progress", {}, uid)
    results["settings"] = await kit.execute("settings", {"reminder": True, "hour": 18}, uid)
    results["export"] = await kit.execute("export", {"deck_id": deck_id}, uid)
    token = results["export"]["url"].split("t=", 1)[1]

    shown = json.dumps(results)
    assert FRONT in shown and BACK in shown and EXPLANATION in shown  # the model sees them
    for name, result in results.items():
        text = row_text("study.review", result)
        for private in (
            "quokkavine",
            "Photosynthesis",
            "zarblot",
            "Zarblot",
            "ZARB",
            "Mitochondrion",
            "Golgi",
            "Oxidative",
            "Ribosomes",
            token,
        ):
            assert private not in text, (name, private, text)

    assert result_for_audit("study.save", saved) == {
        "ok": True,
        "deck_id": deck_id,
        "created": True,
        "added": 2,
        "skipped_duplicates": 0,
        "rejected": 1,
        "deck_items": 2,
        "added_ids": 2,
    }
    graded = result_for_audit("study.review", results["review_grade"])
    assert (
        graded["item_id"] == first
        and graded["rating"] == "good"
        and isinstance(graded["next"], int)
    )
    submitted = result_for_audit("study.quiz", results["quiz_submit"])
    assert submitted["correct"] == results["quiz_submit"]["correct"] and submitted["answered"] == 2
    assert all(set(r) <= {"item_id", "correct", "already_answered"} for r in submitted["results"])
    finished = result_for_audit("study.quiz", results["quiz_finish"])
    assert finished["score"] == results["quiz_finish"]["score"] and "deck" not in finished
    exported = result_for_audit("study.export", results["export"])
    assert exported["format"] == "anki" and exported["items"] == 2 and "url" not in exported
    assert (
        result_for_audit("study.settings", results["settings"])["reminder"]["recurrence"]["time"]
        == "18:00"
    )


# -- triggers.* ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trigger_rows_keep_ids_and_counts_never_filters_prompts_or_what_fired(
    session_factory,
):
    from models.event_trigger import TriggerEvent

    user, _ = await make_user(session_factory, "audit-triggers@example.com")
    uid = str(user.id)
    await connector(session_factory, user, name="pemberton@univ.edu")
    kit = trigger_toolkit(session_factory, "trigger_runs")
    created, _bound = await approved_create(
        kit,
        user,
        {
            **EMAIL,
            "label": "Quokkavine lab mail",
            "senders": ["smith@univ.edu"],
            "subject_contains": "zarblot",
            "mode": "run_task",
            "prompt": PROMPT,
        },
    )
    assert created["ok"] is True
    trigger_id = created["trigger_id"]
    async with session_factory() as session:
        session.add(
            TriggerEvent(
                trigger_id=uuid.UUID(trigger_id),
                user_id=user.id,
                external_key="0" * 64,
                status="notified",
                batch_id=uuid.uuid4(),
                facts={
                    "kind": "email",
                    "subject": "Zarblot exam moved",
                    "from_address": "smith@univ.edu",
                },
                detected_at=TRIGGER_NOW - timedelta(minutes=1),
                note="and 2 more from smith@univ.edu",
            )
        )
        await session.commit()
    listing = await kit.execute("list", {}, uid)
    history = await kit.execute("history", {"trigger_id": trigger_id}, uid)
    assert "smith@univ.edu" in json.dumps(listing) and "Zarblot exam" in json.dumps(
        history
    )  # the model sees them

    for result in (created, listing, history):
        text = row_text("triggers.list", result)
        for private in (
            "quokkavine",
            "Quokkavine",
            "Pemberton",
            "pemberton",
            "smith@",
            "zarblot",
            "Zarblot",
        ):
            assert private not in text, (private, text)

    row = result_for_audit("triggers.list", listing)["triggers"][0]
    assert row["id"] == trigger_id and row["source"] == "email.new" and row["mode"] == "run_task"
    assert row["status"] == "active" and row["prompt_truncated"] is False
    assert not {"label", "account", "filters", "prompt"} & set(row)
    # A refusal may quote what the call sent; the row keeps its rule only.
    from services.tools.triggers import validate_create

    _spec, refused = validate_create({**EMAIL, "senders": ["Dr Pemberton"]})
    assert refused is not None and refused["ok"] is False and "pemberton" in refused["error"]
    assert result_for_audit("triggers.create", refused) == {"ok": False, "rule": refused["rule"]}
    fire = result_for_audit("triggers.history", history)["fires"][0]
    assert fire == {
        "detected_at": fire["detected_at"],
        "items": 1,
        "outcome": "notified",
        "facts": 1,
    }
