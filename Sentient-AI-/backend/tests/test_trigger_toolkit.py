"""Tests for the triggers.* toolkit (services/tools/triggers.py): argument rules
per source (intervals, lead minutes, sender formats, prompt length, a mail task
without senders, unknown arguments, the reserved bound keys), the card hooks
(precheck, the async bind that pins the account, the card sentence), account
resolution (a plain type, a slugged namespace, omission with one or several
rows, another user's row, a missing scope), the switches (trigger_runs off, no
runner, page_watch off or a foreign watch), an approved create whose account
changed, the 10-trigger cap, duplicates, list and history shapes within their
budgets, update before and after, delete, and foreign ids.

Why it exists: a trigger reads an app and messages the owner, or runs a task,
for as long as it exists, and the card is the owner's only look at the rule;
each check here is what keeps that card truthful and the rule the owner's own.
In-memory SQLite, a fake capability gate; no network.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from services.agent.tool_registry import ConnectorToolExecutor, connector_slug
from services.triggers import TRIGGER_RULE_POLICY
from services.tools.triggers import (
    HISTORY_ROWS_CHARS,
    LIST_ROWS_CHARS,
    MAX_TRIGGERS_PER_USER,
    TriggerToolkit,
    validate_create,
)
from tests.conftest import make_user

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
EMAIL = {"label": "Prof emails", "source": "email.new", "senders": ["smith@univ.edu"]}


def gate(*keys: str):
    async def statuses():
        return {k: SimpleNamespace(effective="on") for k in keys}

    return statuses


def toolkit(session_factory, *keys: str, runner: bool = True) -> TriggerToolkit:
    return TriggerToolkit(
        session_factory,
        capability_gate=gate("event_triggers", *keys),
        runner_available=lambda: runner,
        clock=lambda: NOW,
    )


async def connector(session_factory, user, kind="google_workspace", name="School", scopes=("gmail.read",), active=True):
    from models.connector import AuthMethod, ConnectorConfig

    row_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                id=row_id,
                user_id=user.id,
                connector_type=kind,
                display_name=name,
                is_active=active,
                auth_method=AuthMethod.bearer_token,
                encrypted_credentials=b"x",
                granted_scopes=list(scopes),
            )
        )
        await session.commit()
    return str(row_id)


async def approved_create(kit, user, params):
    """What the card does: precheck, bind, then the approved call with the
    bound arguments."""
    uid = str(user.id)
    assert await kit.precheck("create", params, uid) is None
    bound = await kit.bind("create", params, uid)
    assert bound.get("refused") is not True, bound
    return await kit.execute("create", bound, uid, approved=True), bound


# -- argument rules -----------------------------------------------------------------


@pytest.mark.parametrize(
    "extra, message",
    [
        ({"interval_minutes": 4}, "from 5 to 1440"),
        ({"interval_minutes": 1441}, "from 5 to 1440"),
        ({"interval_minutes": True}, "from 5 to 1440"),
        ({"senders": ["not-an-address"]}, "not an email address"),
        ({"senders": [f"a{i}@x.org" for i in range(11)]}, "at most 10"),
        ({"subject_contains": 'x" OR from:evil'}, "without quotes"),
        ({"subject_contains": "x" * 101}, "too long"),
        ({"mode": "run_task", "prompt": "p" * 601}, "too long"),
        ({"mode": "run_task", "senders": None, "prompt": "Summarise it"}, "needs 'senders'"),
        ({"prompt": "Summarise it"}, "only for mode run_task"),
        ({"allow_writes": True}, "only for mode run_task"),
        ({"lead_minutes": 10}, "cannot be used with source email.new"),
        ({"color": "red"}, "Unknown argument"),
        ({"folder": "drafts"}, "cannot watch"),
        ({"max_runs_per_day": 25}, "from 1 to 24"),
        ({"source": "email.old"}, "'source' must be one of"),
        ({"label": "two\nlines"}, "one line"),
    ],
)
def test_bad_arguments_are_refused_with_a_plain_reason(extra, message):
    params = {**EMAIL, **extra}
    spec, refusal = validate_create({k: v for k, v in params.items() if v is not None})
    assert spec is None and refusal is not None and message in refusal["error"]
    assert refusal["ok"] is False


def test_intervals_per_source_and_the_fixed_calendar_one():
    def spec(**params):
        return validate_create({"label": "x", **params})

    assert spec(source="email.new")[0].interval_minutes == 15
    assert spec(source="canvas.grade")[0].interval_minutes == 60
    assert spec(source="canvas.grade", interval_minutes=29)[0] is None
    assert spec(source="files.new_in_folder", folder="root")[0].interval_minutes == 60
    assert spec(source="files.new_in_folder", folder="root", interval_minutes=14)[0] is None
    assert spec(source="files.new_in_folder")[1]["error"].startswith("'folder' is required")
    assert spec(source="calendar.starting_soon")[0].interval_minutes == 5
    assert spec(source="calendar.starting_soon", interval_minutes=10)[0] is None
    assert spec(source="calendar.starting_soon", lead_minutes=4)[0] is None
    assert spec(source="calendar.starting_soon", lead_minutes=121)[0] is None
    assert spec(source="calendar.starting_soon", lead_minutes=30)[0].filters == {"lead_minutes": 30}
    assert spec(source="canvas.grade")[0].filters == {"show_score": False}
    assert spec(source="page.changed", watch_id=str(uuid.uuid4()), interval_minutes=60)[0] is None
    assert spec(source="page.changed", watch_id="x")[0] is None
    run = spec(source="page.changed", watch_id=str(uuid.uuid4()), mode="run_task", prompt="p")
    assert run[0] is None and "can only notify" in run[1]["error"]


def test_senders_are_lowercased_and_deduplicated():
    spec, _ = validate_create({**EMAIL, "senders": ["Smith@Univ.edu", "smith@univ.edu", "@CS.univ.edu"]})
    assert spec.filters["senders"] == ["smith@univ.edu", "@cs.univ.edu"]


def test_a_prompt_holding_a_secret_is_refused_as_a_rule():
    _spec, refusal = validate_create(
        {**EMAIL, "mode": "run_task", "prompt": "Use my key sk-ant-api03-" + "a" * 40 + " to reply"}
    )
    assert refusal["rule"] == "secret" and refusal["refused"] is True


@pytest.mark.asyncio
async def test_the_user_id_argument_is_dropped_and_changes_need_approval(session_factory):
    user, _ = await make_user(session_factory, "tk-uid@example.com")
    kit = toolkit(session_factory)
    unapproved = await kit.execute("create", {**EMAIL, "user_id": "someone-else"}, str(user.id))
    assert unapproved["ok"] is False and unapproved["requires_approval"] is True
    listing = await kit.execute("list", {"user_id": "someone-else"}, str(user.id))
    assert listing["ok"] is True and listing["triggers"] == []


# -- account resolution and the switches ------------------------------------------------


@pytest.mark.asyncio
async def test_bind_pins_the_only_account_and_the_card_states_the_rule(session_factory):
    user, _ = await make_user(session_factory, "tk-bind@example.com")
    row = await connector(session_factory, user)
    kit = toolkit(session_factory, "trigger_runs")
    params = {**EMAIL, "mode": "run_task", "prompt": "Summarise it"}
    bound = await kit.bind("create", params, str(user.id))
    assert bound["_account"] == {"connector_id": row, "type": "google_workspace", "label": "School"}
    assert kit.describe("create", bound, str(user.id)) == (
        'When a new email from smith@univ.edu arrives in Gmail (School), run "Summarise it" and '
        "message you the result. Checks every 15 min, at most 6 runs a day, read-only."
    )
    notify = await kit.bind("create", EMAIL, str(user.id))
    assert kit.describe("create", notify, str(user.id)) == (
        "When a new email from smith@univ.edu arrives in Gmail (School), message you on Telegram "
        "or Slack. Checks every 15 min."
    )


@pytest.mark.asyncio
async def test_accounts_by_plain_type_slug_or_omission(session_factory):
    user, _ = await make_user(session_factory, "tk-accounts@example.com")
    school = await connector(session_factory, user, name="School")
    outlook = await connector(session_factory, user, kind="microsoft", name="Work", scopes=("mail.read",))
    kit = toolkit(session_factory)
    uid = str(user.id)
    # Two accounts fit an email trigger: omission is ambiguous and lists both.
    refusal = await kit.precheck("create", EMAIL, uid)
    assert refusal["rule"] == "ambiguous_account"
    assert "google_workspace (School)" in refusal["error"] and "microsoft (Work)" in refusal["error"]
    assert (await kit.bind("create", {**EMAIL, "account": "google_workspace"}, uid))["_account"]["connector_id"] == school
    assert (await kit.bind("create", {**EMAIL, "account": "microsoft"}, uid))["_account"]["connector_id"] == outlook
    # A second Google row: the plain type is ambiguous, each slug is exact.
    other = await connector(session_factory, user, name="Personal")
    refusal = await kit.precheck("create", {**EMAIL, "account": "google_workspace"}, uid)
    assert refusal["rule"] == "ambiguous_account" and f"google_workspace__{connector_slug(other)}" in refusal["error"]
    slugged = {**EMAIL, "account": f"google_workspace__{connector_slug(other)}"}
    assert (await kit.bind("create", slugged, uid))["_account"]["label"] == "Personal"
    # Canvas is not a mail account.
    refusal = await kit.precheck("create", {**EMAIL, "account": "canvas"}, uid)
    assert refusal["rule"] == "unknown_account"


@pytest.mark.asyncio
async def test_another_users_account_a_missing_scope_and_no_account(session_factory):
    owner, _ = await make_user(session_factory, "tk-owner@example.com")
    stranger, _ = await make_user(session_factory, "tk-stranger@example.com")
    foreign = await connector(session_factory, stranger)
    kit = toolkit(session_factory)
    refusal = await kit.precheck("create", {**EMAIL, "account": f"google_workspace__{connector_slug(foreign)}"}, str(owner.id))
    assert refusal["rule"] == "unknown_account"
    refusal = await kit.precheck("create", EMAIL, str(owner.id))
    assert refusal["rule"] == "no_account" and "connect Gmail or Outlook" in refusal["error"]
    await connector(session_factory, owner, scopes=("drive.read",))
    refusal = await kit.precheck("create", EMAIL, str(owner.id))
    assert refusal["rule"] == "account_scope" and refusal["refused"] is True and "gmail.read" in refusal["error"]


@pytest.mark.asyncio
async def test_an_inactive_row_is_not_an_account(session_factory):
    user, _ = await make_user(session_factory, "tk-inactive@example.com")
    await connector(session_factory, user, active=False)
    refusal = await toolkit(session_factory).precheck("create", EMAIL, str(user.id))
    assert refusal["rule"] == "no_account"


@pytest.mark.asyncio
async def test_run_task_needs_trigger_runs_on_and_the_runner(session_factory):
    user, _ = await make_user(session_factory, "tk-runs@example.com")
    await connector(session_factory, user)
    params = {**EMAIL, "mode": "run_task", "prompt": "Summarise it"}
    off = await toolkit(session_factory).precheck("create", params, str(user.id))
    assert off["rule"] == "runs_off" and off["refused"] is True and "Run a task when" in off["error"]
    no_runner = await toolkit(session_factory, "trigger_runs", runner=False).precheck("create", params, str(user.id))
    assert no_runner["rule"] == "runner_unavailable"
    # No gate at all: the registry defaults, so trigger_runs is off.
    bare = TriggerToolkit(session_factory, runner_available=lambda: True)
    assert (await bare.precheck("create", params, str(user.id)))["rule"] == "runs_off"
    assert await toolkit(session_factory, "trigger_runs").precheck("create", params, str(user.id)) is None


@pytest.mark.asyncio
async def test_page_changed_needs_page_watch_and_the_callers_own_watch(session_factory):
    from models.page_watch import PageWatch

    user, _ = await make_user(session_factory, "tk-page@example.com")
    stranger, _ = await make_user(session_factory, "tk-page-other@example.com")
    mine, theirs = uuid.uuid4(), uuid.uuid4()
    async with session_factory() as session:
        for watch_id, owner in ((mine, user), (theirs, stranger)):
            session.add(
                PageWatch(
                    id=watch_id,
                    user_id=owner.id,
                    url=f"https://example.com/{watch_id.hex}",
                    label="Course page",
                    interval_minutes=60,
                    next_check_at=NOW,
                )
            )
        await session.commit()
    params = {"label": "Course page", "source": "page.changed", "watch_id": str(mine)}
    off = await toolkit(session_factory).precheck("create", params, str(user.id))
    assert off["rule"] == "page_watch_off"
    kit = toolkit(session_factory, "page_watch")
    foreign = await kit.precheck("create", {**params, "watch_id": str(theirs)}, str(user.id))
    assert foreign["rule"] == "watch_not_found"
    result, bound = await approved_create(kit, user, params)
    assert result["ok"] is True and bound["_account"] is None
    assert kit.describe("create", bound, str(user.id)) == (
        'When your page watch "Course page" sees a change, message you on Telegram or Slack.'
    )
    refused = await kit.precheck("create", {**params, "account": "google_workspace"}, str(user.id))
    assert "leave 'account' out" in refused["error"]


@pytest.mark.asyncio
async def test_the_model_may_not_supply_the_bound_keys(session_factory):
    user, _ = await make_user(session_factory, "tk-reserved@example.com")
    await connector(session_factory, user)
    kit = toolkit(session_factory)
    forged = {**EMAIL, "_account": {"connector_id": str(uuid.uuid4()), "type": "google_workspace", "label": "x"}}
    refusal = await kit.precheck("create", forged, str(user.id))
    assert refusal["rule"] == "reserved_argument" and refusal["refused"] is True
    # The bind overwrites whatever came in with the resolved row.
    bound = await kit.bind("create", forged, str(user.id))
    assert bound["_account"]["label"] == "School"


@pytest.mark.asyncio
async def test_an_approved_create_must_resolve_to_the_bound_account(session_factory):
    user, _ = await make_user(session_factory, "tk-changed@example.com")
    await connector(session_factory, user)
    kit = toolkit(session_factory)
    bound = await kit.bind("create", EMAIL, str(user.id))
    tampered = {**bound, "_account": {**bound["_account"], "connector_id": str(uuid.uuid4())}}
    result = await kit.execute("create", tampered, str(user.id), approved=True)
    assert result["rule"] == "account_changed" and result["refused"] is True
    missing = await kit.execute("create", dict(EMAIL), str(user.id), approved=True)
    assert missing["rule"] == "account_changed"
    assert (await kit.execute("list", {}, str(user.id)))["triggers"] == []
    saved = await kit.execute("create", bound, str(user.id), approved=True)
    assert saved["ok"] is True and saved["account"] == "School"
    assert "only newer items fire" in saved["note"]


# -- limits, list, history, update, delete -------------------------------------------


@pytest.mark.asyncio
async def test_ten_triggers_at_most_and_no_duplicates(session_factory):
    user, _ = await make_user(session_factory, "tk-cap@example.com")
    await connector(session_factory, user)
    kit = toolkit(session_factory)
    result, _ = await approved_create(kit, user, EMAIL)
    dup = await kit.precheck("create", {**EMAIL, "label": "Same rule, other name"}, str(user.id))
    assert dup["rule"] == "duplicate" and dup["duplicate"] is True
    for i in range(MAX_TRIGGERS_PER_USER - 1):
        await approved_create(kit, user, {**EMAIL, "senders": [f"p{i}@univ.edu"]})
    over = await kit.precheck("create", {**EMAIL, "senders": ["late@univ.edu"]}, str(user.id))
    assert over["rule"] == "trigger_limit" and over["refused"] is True


@pytest.mark.asyncio
async def test_list_shows_rules_never_content_and_fits_its_budget(session_factory):
    user, _ = await make_user(session_factory, "tk-list@example.com")
    await connector(session_factory, user)
    kit = toolkit(session_factory, "trigger_runs")
    long_prompt = "Summarise it and say whether a deadline moved. " * 12
    for i in range(MAX_TRIGGERS_PER_USER):
        await approved_create(
            kit,
            user,
            {
                **EMAIL,
                "label": f"Trigger number {i} " + "x" * 50,
                "senders": [f"prof{i}@univ.edu", "@cs.univ.edu"],
                "subject_contains": "deadline " * 10,
                "mode": "run_task",
                "prompt": long_prompt[:600],
            },
        )
    listing = await kit.execute("list", {}, str(user.id))
    assert listing["count"] == MAX_TRIGGERS_PER_USER
    shown = json.dumps(listing["triggers"], ensure_ascii=False, separators=(",", ":"))
    assert len(shown) <= LIST_ROWS_CHARS + 20
    row = listing["triggers"][0]
    assert row["source"] == "email.new" and row["account"] == "School" and row["mode"] == "run_task"
    assert row["prompt_truncated"] is True and len(row["prompt"]) == 200
    assert "cursor" not in row and "facts" not in shown


@pytest.mark.asyncio
async def test_history_groups_fires_caps_facts_and_hides_bodies(session_factory):
    from models.event_trigger import TriggerEvent

    user, _ = await make_user(session_factory, "tk-history@example.com")
    await connector(session_factory, user)
    kit = toolkit(session_factory)
    created, _ = await approved_create(kit, user, EMAIL)
    trigger_id = uuid.UUID(created["trigger_id"])
    batch = uuid.uuid4()
    async with session_factory() as session:
        for i in range(3):
            session.add(
                TriggerEvent(
                    trigger_id=trigger_id,
                    user_id=user.id,
                    external_key=f"{i:064d}",
                    status="notified",
                    batch_id=batch,
                    facts={
                        "kind": "email",
                        "subject": "S" * 300,
                        "domain": "univ.edu",
                        "from_address": "smith@univ.edu",
                        "body": "SECRET BODY TEXT",
                    },
                    detected_at=NOW - timedelta(minutes=i),
                    note="and 4 more" if i == 2 else None,
                )
            )
        await session.commit()
    history = await kit.execute("history", {"trigger_id": str(trigger_id), "limit": 5}, str(user.id))
    [fire] = history["fires"]
    assert fire["items"] == 3 and fire["outcome"] == "notified" and fire["note"] == "and 4 more"
    assert all(len(f["subject"]) <= 120 for f in fire["facts"])
    text = json.dumps(history)
    assert "SECRET BODY TEXT" not in text and "smith@univ.edu" not in text
    assert len(json.dumps(history["fires"])) <= HISTORY_ROWS_CHARS + 50
    bad = await kit.execute("history", {"trigger_id": str(trigger_id), "limit": 11}, str(user.id))
    assert "from 1 to 10" in bad["error"]


@pytest.mark.asyncio
async def test_update_shows_before_and_after_and_resuming_clears_errors(session_factory):
    from models.event_trigger import EventTrigger

    user, _ = await make_user(session_factory, "tk-update@example.com")
    await connector(session_factory, user)
    kit = toolkit(session_factory)
    created, _ = await approved_create(kit, user, EMAIL)
    uid, tid = str(user.id), created["trigger_id"]
    change = {"trigger_id": tid, "label": "Smith mail", "senders": ["smith@univ.edu", "ta@univ.edu"], "interval_minutes": 30}
    assert await kit.precheck("update", change, uid) is None
    bound = await kit.bind("update", change, uid)
    assert bound["_trigger"]["label"] == "Prof emails"
    sentence = kit.describe("update", bound, uid)
    assert sentence == (
        'Change the trigger "Prof emails": label: Prof emails → Smith mail; interval minutes: 15 → 30; '
        "senders: smith@univ.edu → smith@univ.edu, ta@univ.edu."
    )
    result = await kit.execute("update", bound, uid, approved=True)
    assert result["ok"] is True and result["label"] == "Smith mail"
    assert set(result["changed"]) == {"label", "filters", "interval_minutes"}
    # Immutable fields and a pause.
    immutable = await kit.precheck("update", {"trigger_id": tid, "mode": "run_task"}, uid)
    assert "cannot be changed" in immutable["error"]
    nothing = await kit.precheck("update", {"trigger_id": tid}, uid)
    assert "Nothing to change" in nothing["error"]
    pause = await kit.bind("update", {"trigger_id": tid, "paused": True}, uid)
    assert kit.describe("update", pause, uid) == (
        'Pause the trigger "Smith mail"; nothing is checked or sent until you resume it.'
    )
    assert (await kit.execute("update", pause, uid, approved=True))["status"] == "paused"
    async with session_factory() as session:
        row = await session.get(EventTrigger, uuid.UUID(tid))
        row.status, row.consecutive_errors, row.last_error = "error", 5, "The app did not answer in time."
        await session.commit()
    resume = await kit.bind("update", {"trigger_id": tid, "paused": False}, uid)
    assert kit.describe("update", resume, uid).startswith('Resume the trigger "Smith mail"')
    assert (await kit.execute("update", resume, uid, approved=True))["status"] == "active"
    async with session_factory() as session:
        row = await session.get(EventTrigger, uuid.UUID(tid))
        assert row.consecutive_errors == 0 and row.last_error is None
        # A new baseline: what arrived while it was stopped is not sent.
        assert row.baseline_at is None and row.cursor is None
    # A notify trigger takes no prompt.
    prompt = await kit.precheck("update", {"trigger_id": tid, "prompt": "x"}, uid)
    assert "only for a trigger that runs a task" in prompt["error"]


@pytest.mark.asyncio
async def test_delete_and_foreign_ids_read_as_not_found(session_factory):
    owner, _ = await make_user(session_factory, "tk-del@example.com")
    intruder, _ = await make_user(session_factory, "tk-del-other@example.com")
    await connector(session_factory, owner)
    kit = toolkit(session_factory)
    created, _ = await approved_create(kit, owner, EMAIL)
    tid = created["trigger_id"]
    for action, params in (
        ("history", {"trigger_id": tid}),
        ("update", {"trigger_id": tid, "paused": True}),
        ("delete", {"trigger_id": tid}),
    ):
        if action == "history":
            result = await kit.execute(action, params, str(intruder.id))
        else:
            result = await kit.precheck(action, params, str(intruder.id))
        assert result["not_found"] is True, action
    assert (await kit.set_paused(str(intruder.id), tid, True))["not_found"] is True
    assert (await kit.delete_trigger(str(intruder.id), tid))["not_found"] is True
    bound = await kit.bind("delete", {"trigger_id": tid}, str(owner.id))
    assert kit.describe("delete", bound, str(owner.id)) == (
        'Delete the trigger "Prof emails" (a new email) and its queued events. Its conversation is kept.'
    )
    assert (await kit.execute("delete", bound, str(owner.id), approved=True))["deleted"] is True
    assert (await kit.execute("list", {}, str(owner.id)))["count"] == 0


@pytest.mark.asyncio
async def test_without_a_database_everything_is_refused():
    kit = TriggerToolkit(None)
    assert (await kit.execute("list", {}, str(uuid.uuid4())))["rule"] == "storage"


# -- through the executor ---------------------------------------------------------


@pytest.mark.asyncio
async def test_the_executor_routes_the_card_hooks_and_files_refusals_under_trigger_rule(session_factory):
    user, _ = await make_user(session_factory, "tk-exec@example.com")
    await connector(session_factory, user)
    kit = toolkit(session_factory)
    executor = ConnectorToolExecutor(
        session_factory, capability_gate=gate("event_triggers"), triggers_toolkit=kit
    )
    assert executor.triggers_toolkit is kit
    uid = str(user.id)
    refusal = await executor.precheck_approval("triggers.create", {**EMAIL, "mode": "run_task", "prompt": "p"}, uid)
    assert refusal.policy == TRIGGER_RULE_POLICY and refusal.rule == "runs_off"
    assert await executor.precheck_approval("triggers.create", EMAIL, uid) is None
    bound = await executor.approval_arguments_async("triggers.create", dict(EMAIL), uid, task_id=None)
    assert bound["_account"]["label"] == "School"
    assert executor.describe_approval("triggers.create", bound, uid).startswith("When a new email from smith@univ.edu")
    unapproved = await executor.execute("triggers.create", bound, uid)
    assert unapproved["requires_approval"] is True
    saved = await executor.execute("triggers.create", bound, uid, approved=True)
    assert saved["ok"] is True
    listing = await executor.execute("triggers.list", {}, uid)
    assert listing["ok"] is True and listing["count"] == 1


@pytest.mark.asyncio
async def test_the_executor_refuses_triggers_while_the_switch_is_off(session_factory):
    user, _ = await make_user(session_factory, "tk-off@example.com")
    executor = ConnectorToolExecutor(session_factory, capability_gate=gate())
    result = await executor.execute("triggers.list", {}, str(user.id))
    assert result["ok"] is False and result["capability"] == "event_triggers"


def test_the_catalog_has_no_argument_named_action_or_url():
    from services.agent.tool_registry import CONNECTOR_CATALOG

    for spec in CONNECTOR_CATALOG["triggers"]:
        assert not {"action", "url", "user_id"} & set(spec.parameters.get("properties", {}))


def test_registry_wiring():
    from services import capabilities
    from services.agent.context_manager import UNDO_COMPANIONS
    from services.agent.permissions import _DEFAULT_POLICIES, ActionCategory, PermissionTier
    from services.agent.runtime import _BIND_REFUSAL_POLICIES, RESULT_CHAR_BUDGETS, SECURITY_SYSTEM_PROMPT
    from services.agent.tool_registry import _BUILTIN_STANCE, _BUILTIN_STARTER_TOOLS, BUILTIN_CONNECTOR_TYPES
    from services.connectors.registry import RESERVED_KEYS
    from services.notifications.progress import _TOOL_PHRASES

    assert "triggers" in BUILTIN_CONNECTOR_TYPES and _BUILTIN_STANCE["triggers"] == "user_confirm"
    assert "triggers.create" in _BUILTIN_STARTER_TOOLS
    assert UNDO_COMPANIONS["triggers.create"] == ("triggers.list", "triggers.delete")
    assert {cat: _DEFAULT_POLICIES[("triggers", cat)] for cat in ActionCategory} == {
        ActionCategory.READ: PermissionTier.AUTO_APPROVE,
        ActionCategory.WRITE: PermissionTier.USER_CONFIRM,
        ActionCategory.DELETE: PermissionTier.USER_CONFIRM,
        ActionCategory.EXECUTE: PermissionTier.HARD_BLOCKED,
        ActionCategory.FINANCIAL: PermissionTier.HARD_BLOCKED,
    }
    assert _BIND_REFUSAL_POLICIES["triggers.create"] == TRIGGER_RULE_POLICY
    assert RESULT_CHAR_BUDGETS["triggers.list"] == 6000 and RESULT_CHAR_BUDGETS["triggers.history"] == 5000
    assert "(only when triggers.create is\n  offered): triggers.create." in SECURITY_SYSTEM_PROMPT
    assert {"triggers", "watch"} <= RESERVED_KEYS
    assert _TOOL_PHRASES["triggers.create"] == "Setting up your trigger…"
    assert _TOOL_PHRASES["triggers.list"] == _TOOL_PHRASES["triggers.history"] == "Checking your triggers…"
    assert capabilities.capability_for_tool("triggers.create").key == "event_triggers"


def test_the_column_sizes_match_the_toolkit():
    from models import event_trigger as model
    from services.tools import triggers

    assert model.LABEL_MAX_CHARS == triggers.LABEL_MAX_CHARS
    assert model.PROMPT_MAX_CHARS == triggers.PROMPT_MAX_CHARS


def test_audit_rows_keep_only_the_length_of_the_owners_text():
    from services.audit import redact_tool_arguments

    stored = redact_tool_arguments(
        "triggers.create",
        {"label": "x", "prompt": "Summarise it", "senders": ["smith@univ.edu"], "subject_contains": "exam"},
    )
    assert stored["prompt"] == "<12 characters>" and "smith" not in json.dumps(stored)
    change = redact_tool_arguments("triggers.update", {"trigger_id": "t", "_trigger": {"filters": {"senders": ["a@b.c"]}}})
    assert "a@b.c" not in json.dumps(change)
