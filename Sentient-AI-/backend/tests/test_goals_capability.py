"""Tests for the "goals" capability and its wiring: it is registered on by
default, low risk and always available, claims the goals.* family, and is
enforced at the offer, the permission adapter and the executor; the catalog
(six tools, their categories and schemas, only delete carded) is neither core
nor a starter nor a lead; the policy rows, the stance (the delete card stays
under an auto_approve account default) and the executor entry; the card
hooks (a model-supplied "_goal" refused under goals_rule, the sentence built
from the bound facts, an unapproved delete refused); the reserved connector
key; the result budgets, the bind-refusal policy, the audit reduction and
argument redaction; the progress lines; how unattended runs classify each
tool; and, end to end through a real runtime turn, a goal created and listed
with no card and a delete parked on a card that deletes only once approved.

Why it exists: goals are on for every install and every write but delete
runs with no card, so each lock that keeps delete on its card, and keeps the
user's words out of the append-only audit log, is pinned here. No model: a
scripted provider. The database is in-memory SQLite.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select

from core.config import settings
from models.audit import AuditLog
from models.goal import Goal, GoalEntry, GoalMilestone
from services.agent.approvals import InMemoryApprovalStore
from services.agent.context_manager import UNDO_COMPANIONS, core_tool_names
from services.agent.permissions import _DEFAULT_POLICIES, ActionCategory, PermissionTier
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    CAPABILITY_OFF_POLICY,
    RESULT_CHAR_BUDGETS,
    AgentRuntime,
    result_char_budget,
    result_for_audit,
)
from services.agent.tool_registry import (
    _BUILTIN_STANCE,
    _BUILTIN_STARTER_TOOLS,
    BUILTIN_CONNECTOR_TYPES,
    CONNECTOR_CATALOG,
    LEAD_STARTER_TOOLS,
    RUNTIME_BUILTIN_TYPES,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.audit import RuntimeAuditLogger, redact_tool_arguments
from services.automation.fence import NEVER_TYPES, classify_tool
from services.capabilities import REGISTRY, capability_for_tool, get
from services.capabilities import report as capability_report
from services.capabilities import statuses_by_key
from services.capabilities.base import ReportContext
from services.connectors import registry as connector_registry
from services.notifications.progress import phrase_for
from services.tools import goals as goals_tools
from services.tools.goals import GOAL_CARD_KEY, GOALS_RULE_POLICY, GoalsToolkit
from tests.conftest import make_user, use_provider

_CTX = ReportContext(
    in_container=False, platform="win32", telegram_configured=False, browser_installed=False
)
ACTIONS = ("create", "list", "get", "update", "log_progress", "delete")
NAMES = {f"goals.{action}" for action in ACTIONS}


def _gate(*keys: str):
    switches = {c.key: c.key in keys for c in REGISTRY}
    statuses = statuses_by_key(capability_report(switches, _CTX, use_cache=False))

    async def gate():
        return statuses

    return gate


def _specs() -> dict[str, Any]:
    return {spec.action: spec for spec in CONNECTOR_CATALOG["goals"]}


async def _count(session_factory, model) -> int:
    async with session_factory() as session:
        return int((await session.execute(select(func.count()).select_from(model))).scalar_one())


# --------------------------------------------------------------------------- #
# Registration, catalog, gates
# --------------------------------------------------------------------------- #


def test_goals_is_registered_on_by_default_low_risk_and_claims_the_family():
    cap = get("goals")
    assert cap.label == "Goals and plans"
    assert cap.tools == ("goals.",) and cap.default_enabled is True and cap.risk == "low"
    assert cap.when_denied == (
        "Goals are turned off. The owner can turn them on in Settings → Permissions."
    )
    assert cap.availability(_CTX).available and cap.install is None and not cap.requires
    for spec in CONNECTOR_CATALOG["goals"]:
        assert capability_for_tool(f"goals.{spec.action}") is cap
    [status] = [s for s in capability_report({}, _CTX, use_cache=False) if s.key == "goals"]
    assert status.effective == "on" and status.enabled is True and status.available is True


def test_the_catalog_is_the_six_tools_of_the_spec():
    specs = _specs()
    assert list(specs) == list(ACTIONS)
    assert {action: spec.category for action, spec in specs.items()} == {
        "create": ActionCategory.WRITE,
        "list": ActionCategory.READ,
        "get": ActionCategory.READ,
        "update": ActionCategory.WRITE,
        "log_progress": ActionCategory.WRITE,
        "delete": ActionCategory.DELETE,
    }
    assert {action for action, spec in specs.items() if spec.always_confirm} == {"delete"}
    assert not any(spec.starter or spec.required_scope or spec.risk for spec in specs.values())
    required = {action: spec.parameters["required"] for action, spec in specs.items()}
    assert required == {
        "create": ["title"],
        "list": [],
        "get": ["goal_id"],
        "update": ["goal_id"],
        "log_progress": ["goal_id", "note"],
        "delete": ["goal_id"],
    }


def test_the_schemas_name_every_field_the_toolkit_takes_with_their_enums():
    from services.goals.store import CREATE_KEYS, PROGRESS_KEYS, UPDATE_KEYS

    specs = _specs()
    props = {action: spec.parameters["properties"] for action, spec in specs.items()}
    assert set(props["create"]) == CREATE_KEYS
    assert set(props["update"]) == UPDATE_KEYS | {"goal_id"}
    assert set(props["log_progress"]) == PROGRESS_KEYS | {"goal_id"}
    assert set(props["list"]) == {"status", "category"}
    assert set(props["get"]) == set(props["delete"]) == {"goal_id"}
    categories = ["school", "career", "health", "money", "personal", "other"]
    for action in ("create", "update", "list"):
        assert props[action]["category"]["enum"] == categories
    assert props["list"]["status"]["enum"] == ["active", "paused", "completed", "archived", "all"]
    assert props["update"]["status"]["enum"] == ["active", "paused", "completed", "archived"]
    for action in ("create", "update"):
        assert props[action]["check_in"]["enum"] == ["none", "daily", "weekly"]
    for action, field in (("create", "milestones"), ("update", "add_milestones")):
        milestone = props[action][field]
        assert milestone["type"] == "array"
        assert milestone["items"]["type"] == "object"
        assert set(milestone["items"]["properties"]) == {"title", "due_date"}
        assert milestone["items"]["required"] == ["title"]
    for field in ("complete_milestones", "reopen_milestones", "drop_milestones"):
        assert props["update"][field]["items"] == {"type": "string"}
    assert props["update"]["clear_target_date"]["type"] == "boolean"
    # The words users say, for tools.find and the model.
    words = " ".join(spec.description.lower() for spec in specs.values())
    for word in ("goal", "plan", "milestone", "progress", "check-in"):
        assert word in words, word
    assert "approves it first" in specs["delete"].description


def test_goals_tools_are_offered_only_with_the_switch_on():
    assert not NAMES & {t.name for t in build_tools([], enabled_capabilities=frozenset())}
    assert NAMES <= {t.name for t in build_tools([], enabled_capabilities=frozenset({"goals"}))}
    # On by default: an install that never touched the switch offers them.
    assert NAMES <= {t.name for t in build_tools([])}


@pytest.mark.parametrize("default_tier", ["user_confirm", "auto_approve"])
def test_only_delete_is_carded_whatever_the_account_default(default_tier):
    tools = {
        t.name: t
        for t in build_tools(
            [], enabled_capabilities=frozenset({"goals"}), user_default_tier=default_tier
        )
    }
    assert tools["goals.delete"].permission_tier == "approval"
    for name in NAMES - {"goals.delete"}:
        assert tools[name].permission_tier == "auto", name


def test_not_core_not_a_starter_and_not_a_lead():
    assert not NAMES & core_tool_names()
    assert not NAMES & _BUILTIN_STARTER_TOOLS
    assert not NAMES & LEAD_STARTER_TOOLS
    assert not any(key.startswith("goals.") for key in UNDO_COMPANIONS)
    tools = build_tools([], enabled_capabilities=frozenset({"goals"}))
    assert not any(t.starter or t.lead for t in tools if t.name in NAMES)


@pytest.mark.asyncio
async def test_the_adapter_and_the_executor_refuse_while_it_is_off():
    adapter = RuntimePermissionAdapter(capability_gate=_gate())
    assert await adapter.check("u1", "goals.create", {"title": "Run"}) == "blocked"
    assert await adapter.get_policy_name("u1", "goals.create") == CAPABILITY_OFF_POLICY
    assert await adapter.get_block_reason("u1", "goals.list", {}) == get("goals").when_denied
    on = RuntimePermissionAdapter(capability_gate=_gate("goals"))
    for name in NAMES - {"goals.delete"}:
        assert await on.check("u1", name, {"goal_id": "x", "title": "Run"}) == "approved", name
    assert await on.check("u1", "goals.delete", {"goal_id": "x"}) == "requires_approval"
    executor = ConnectorToolExecutor(capability_gate=_gate())
    for name in NAMES:
        refused = await executor.execute(name, {}, user_id="u1")
        assert refused["ok"] is False and refused["capability"] == "goals", name
        assert refused["state"] == "off"


def test_the_policy_rows():
    assert {cat: _DEFAULT_POLICIES[("goals", cat)] for cat in ActionCategory} == {
        ActionCategory.READ: PermissionTier.AUTO_APPROVE,
        ActionCategory.WRITE: PermissionTier.AUTO_APPROVE,
        ActionCategory.DELETE: PermissionTier.USER_CONFIRM,
        ActionCategory.EXECUTE: PermissionTier.HARD_BLOCKED,
        ActionCategory.FINANCIAL: PermissionTier.HARD_BLOCKED,
    }


def test_the_stance_and_the_executor_entry():
    assert "goals" in BUILTIN_CONNECTOR_TYPES and "goals" not in RUNTIME_BUILTIN_TYPES
    assert _BUILTIN_STANCE["goals"] == "user_confirm"
    entry = ConnectorToolExecutor()._builtins["goals"]
    assert entry.label == "Goal"
    assert entry.allowed == frozenset(
        {ActionCategory.READ, ActionCategory.WRITE, ActionCategory.DELETE}
    )
    assert entry.confirm == frozenset({ActionCategory.DELETE})
    assert not entry.task_scoped


def test_the_default_toolkit_shares_the_executor_session_factory():
    def factory() -> Any:
        raise AssertionError("never opened while building")

    executor = ConnectorToolExecutor(session_factory=factory)
    assert isinstance(executor.goals_toolkit, GoalsToolkit)
    assert executor.goals_toolkit._session_factory is factory


class _Recording:
    """A goals toolkit that records what the executor hands it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    async def execute(self, action, params, user_id):
        self.calls.append((action, dict(params), user_id))
        return {"ok": True}


@pytest.mark.asyncio
async def test_the_executor_hands_its_own_user_and_refuses_an_unapproved_delete():
    kit = _Recording()
    executor = ConnectorToolExecutor(goals_toolkit=kit)  # type: ignore[arg-type]
    assert executor.goals_toolkit is kit
    await executor.execute("goals.list", {"status": "all", "user_confirmed": True}, user_id="u1")
    assert kit.calls == [("list", {"status": "all"}, "u1")]
    unapproved = await executor.execute("goals.delete", {"goal_id": "g1"}, user_id="u1")
    assert unapproved["ok"] is False and unapproved["requires_approval"] is True
    assert "deletes a goal" in unapproved["error"]
    assert len(kit.calls) == 1  # never reached the toolkit
    await executor.execute("goals.delete", {"goal_id": "g1"}, user_id="u1", approved=True)
    assert kit.calls[-1] == ("delete", {"goal_id": "g1"}, "u1")


def test_goals_is_a_reserved_connector_key():
    from tests.test_connector_registry import GOOD

    assert "goals" in connector_registry.RESERVED_KEYS
    [problem] = connector_registry.validate_registry([dataclasses.replace(GOOD, key="goals")])
    assert "reserved" in problem


# --------------------------------------------------------------------------- #
# Card hooks
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_card_hooks_bind_the_facts_and_refuse_a_forged_card(session_factory):
    owner, _ = await make_user(session_factory, "goals-hooks@example.com")
    other, _ = await make_user(session_factory, "goals-hooks-other@example.com")
    uid = str(owner.id)
    executor = ConnectorToolExecutor(session_factory=session_factory)
    kit = executor.goals_toolkit
    made = await kit.execute(
        "create", {"title": "Learn the cello", "milestones": ["Buy a cello", "First lesson"]}, uid
    )
    goal_id = made["goal"]["id"]
    await kit.execute("log_progress", {"goal_id": goal_id, "note": "Rented one"}, uid)

    assert await executor.precheck_approval("goals.delete", {"goal_id": goal_id}, uid) is None
    forged = await executor.precheck_approval(
        "goals.delete", {"goal_id": goal_id, GOAL_CARD_KEY: {"title": "Old"}}, uid
    )
    assert forged is not None and forged.policy == GOALS_RULE_POLICY
    assert forged.rule == "reserved_argument" and forged.result["refused"] is True
    malformed = await executor.precheck_approval("goals.delete", {"goal_id": "nope"}, uid)
    assert malformed is not None and malformed.rule == "invalid_arguments"

    bound = await executor.approval_arguments_async(
        "goals.delete", {"goal_id": goal_id, "user_confirmed": True}, uid, task_id=None
    )
    assert bound == {
        "goal_id": goal_id,
        GOAL_CARD_KEY: {
            "goal_id": goal_id,
            "title": "Learn the cello",
            "milestones": 2,
            "entries": 1,
        },
    }
    assert executor.describe_approval("goals.delete", bound, uid) == (
        'Delete the goal "Learn the cello" with 2 milestones and 1 progress note.'
    )
    # Without the bound facts there is no sentence (the runtime's generic one).
    assert executor.describe_approval("goals.delete", {"goal_id": goal_id}, uid) is None
    foreign = await executor.approval_arguments_async(
        "goals.delete", {"goal_id": goal_id}, str(other.id), task_id=None
    )
    assert foreign["refused"] is True and foreign.get("not_found") is True
    assert foreign["rule"] == "invalid_arguments"

    unbound = await executor.execute(
        "goals.delete", {"goal_id": goal_id}, user_id=uid, approved=True
    )
    assert unbound["ok"] is False and unbound["rule"] == "unbound"
    stolen = await executor.execute("goals.delete", bound, user_id=str(other.id), approved=True)
    assert stolen["ok"] is False and stolen.get("not_found")
    assert await _count(session_factory, Goal) == 1
    done = await executor.execute("goals.delete", bound, user_id=uid, approved=True)
    assert done["ok"] is True and await _count(session_factory, Goal) == 0


# --------------------------------------------------------------------------- #
# Runtime: budgets, bind policy, audit
# --------------------------------------------------------------------------- #


def test_the_result_budgets():
    assert result_char_budget("goals.list", 0) == goals_tools.MAX_LIST_RESULT_CHARS + 2000
    assert result_char_budget("goals.get", 0) == goals_tools.MAX_GET_RESULT_CHARS + 2000
    assert result_char_budget("goals.create", 0) == goals_tools.MAX_WRITE_RESULT_CHARS + 2000
    assert result_char_budget("goals.update", 0) == goals_tools.MAX_WRITE_RESULT_CHARS + 2000
    assert result_char_budget("goals.log_progress", 2000) == 2000
    assert result_char_budget("goals.delete", 2000) == 2000
    assert {k for k in RESULT_CHAR_BUDGETS if k.startswith("goals.")} == {
        "goals.list",
        "goals.get",
        "goals.create",
        "goals.update",
    }


def test_the_bind_refusal_policy_names_the_toolkits():
    from services.agent import runtime as runtime_mod

    assert runtime_mod._BIND_REFUSAL_POLICIES["goals.delete"] == GOALS_RULE_POLICY


def test_an_audit_row_keeps_a_goals_result_as_facts_only():
    result = {
        "ok": True,
        "goal": {
            "id": "g1",
            "title": "Visit Zanzibar",
            "description": "See the Quokka",
            "status": "active",
            "progress": {"done": 0, "total": 1},
            "milestones": [{"id": "m1", "title": "Book Pelican", "state": "open", "position": 0}],
            "entries": [{"id": "e1", "note": "Bought Tangerine", "source": "agent"}],
        },
    }
    for name in ("goals.get", "goals__1a2b3c4d.get"):
        facts = result_for_audit(name, result)
        text = json.dumps(facts)
        for word in ("Zanzibar", "Quokka", "Pelican", "Tangerine"):
            assert word not in text
        assert facts["goal"]["id"] == "g1" and facts["goal"]["status"] == "active"


def test_tool_arguments_are_kept_as_lengths_and_counts():
    goal_id = str(uuid.uuid4())
    assert redact_tool_arguments(
        "goals.create",
        {
            "title": "Run a 5k",
            "description": "No walking",
            "current_state": "2k",
            "category": "health",
            "milestones": [{"title": "Run 3k"}, "Run 4k"],
        },
    ) == {
        "title": "<8 characters>",
        "description": "<10 characters>",
        "current_state": "<2 characters>",
        "category": "health",
        "milestones": "<2 items>",
    }
    assert redact_tool_arguments(
        "goals.update",
        {"goal_id": goal_id, "title": "Run", "add_milestones": [{"title": "x"}], "status": "paused"},
    ) == {
        "goal_id": goal_id,
        "title": "<3 characters>",
        "add_milestones": "<1 item>",
        "status": "paused",
    }
    assert redact_tool_arguments("goals.log_progress", {"goal_id": goal_id, "note": "Ran 3k"}) == {
        "goal_id": goal_id,
        "note": "<6 characters>",
    }
    assert redact_tool_arguments(
        "goals.delete", {"goal_id": goal_id, GOAL_CARD_KEY: {"title": "Run"}}
    ) == {"goal_id": goal_id, GOAL_CARD_KEY: "***REDACTED***"}
    # An id that is not an id (a title the model put there) keeps its length only.
    assert redact_tool_arguments("goals.get", {"goal_id": "Run a 5k"}) == {
        "goal_id": "<8 characters>"
    }


def test_progress_lines_name_the_goals_tools():
    for tool, line in (
        ("goals.list", "Checking your goals…"),
        ("goals.get", "Checking your goal…"),
        ("goals.create", "Saving your goal…"),
        ("goals.update", "Updating your goal…"),
        ("goals.log_progress", "Logging your progress…"),
        ("goals.delete", "Deleting a goal…"),
        ("goals.archive_all", "Working on your goals…"),
    ):
        assert phrase_for({"type": "tool_call", "data": {"name": tool}}) == line


def test_unattended_runs_may_read_goals_and_card_their_writes_never_delete():
    assert "goals" not in NEVER_TYPES
    assert classify_tool("goals.list") == "read"
    assert classify_tool("goals.get") == "read"
    for name in ("goals.create", "goals.update", "goals.log_progress"):
        assert classify_tool(name) == "write", name
    assert classify_tool("goals.delete") is None


# --------------------------------------------------------------------------- #
# End to end through the runtime
# --------------------------------------------------------------------------- #


class _Script:
    """A scripted model that records what it was shown."""

    def __init__(self, *steps: LLMResponse) -> None:
        self.steps = list(steps)
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(list(messages))
        return self.steps.pop(0) if self.steps else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"


def _call(name: str, call_id: str = "t1", **arguments: Any) -> LLMResponse:
    return LLMResponse(
        content="", tool_calls=[ToolCall(id=call_id, name=name, arguments=arguments)]
    )


def _runtime(session_factory) -> tuple[AgentRuntime, ConnectorToolExecutor, InMemoryApprovalStore]:
    gate = _gate("goals")
    executor = ConnectorToolExecutor(session_factory=session_factory, capability_gate=gate)
    store = InMemoryApprovalStore()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate),
        tool_executor=executor,
        audit_service=RuntimeAuditLogger(session_factory=session_factory),
        approval_store=store,
    )
    return runtime, executor, store


async def _turn(runtime, user_id: str, text: str, *steps: LLMResponse, default_tier: str):
    model = _Script(*steps)
    use_provider(runtime, model)
    tools = build_tools(
        [], enabled_capabilities=frozenset({"goals"}), user_default_tier=default_tier
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": text}], tools=tools, user_id=user_id
    )
    return response, model


@pytest.mark.asyncio
@pytest.mark.parametrize("default_tier", ["user_confirm", "auto_approve"])
async def test_a_goal_is_made_without_a_card_and_deleted_only_after_one(
    session_factory, default_tier
):
    user, _ = await make_user(session_factory, f"goals-e2e-{default_tier}@example.com")
    uid = str(user.id)
    runtime, _executor, store = _runtime(session_factory)

    response, model = await _turn(
        runtime,
        uid,
        "I want to run a 5k by May.",
        _call(
            "goals.create",
            title="Run a 5k",
            category="health",
            target_date="2027-05-01",
            milestones=[{"title": "Run 3k"}],
        ),
        _call("goals.list", "t2"),
        LLMResponse(content="Saved your goal."),
        default_tier=default_tier,
    )
    assert response.pending_approvals == [] and response.content == "Saved your goal."
    async with session_factory() as session:
        [goal] = (await session.execute(select(Goal))).scalars().all()
    assert (goal.user_id, goal.title, goal.category) == (user.id, "Run a 5k", "health")
    assert await _count(session_factory, GoalMilestone) == 1
    # The list the model was shown has the new goal (as a tool result).
    assert str(goal.id) in json.dumps(model.calls[-1], default=str)

    response, _ = await _turn(
        runtime,
        uid,
        "Delete my 5k goal.",
        _call("goals.delete", goal_id=str(goal.id)),
        default_tier=default_tier,
    )
    [card] = response.pending_approvals
    assert card.tool_name == "goals.delete"
    assert card.reason == 'Delete the goal "Run a 5k" with 1 milestone and 0 progress notes.'
    assert card.arguments == {
        "goal_id": str(goal.id),
        GOAL_CARD_KEY: {
            "goal_id": str(goal.id),
            "title": "Run a 5k",
            "milestones": 1,
            "entries": 0,
        },
    }
    assert await _count(session_factory, Goal) == 1  # nothing until approved

    outcome = await runtime.approve_action(card.action_id, uid)
    assert outcome["result"]["ok"] is True, outcome
    for model_class in (Goal, GoalMilestone, GoalEntry):
        assert await _count(session_factory, model_class) == 0
    assert await store.list_pending(uid) == []

    # The audit log kept facts: never the goal's title or a milestone's.
    async with session_factory() as session:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.user_id == user.id)))
            .scalars()
            .all()
        )
    assert {"create", "list", "delete"} <= {r.action for r in rows}
    for row in rows:
        stored = json.dumps([row.request_data, row.response_summary], default=str)
        assert "Run a 5k" not in stored and "Run 3k" not in stored, row.action
    assert any((r.request_data or {}).get("title") == "<8 characters>" for r in rows)


@pytest.mark.asyncio
async def test_a_forged_card_or_a_foreign_goal_gets_no_card(session_factory):
    owner, _ = await make_user(session_factory, "goals-e2e-owner@example.com")
    other, _ = await make_user(session_factory, "goals-e2e-other@example.com")
    runtime, executor, _store = _runtime(session_factory)
    made = await executor.goals_toolkit.execute("create", {"title": "Run a 5k"}, str(owner.id))
    goal_id = made["goal"]["id"]

    forged, _ = await _turn(
        runtime,
        str(owner.id),
        "Delete it.",
        _call("goals.delete", goal_id=goal_id, **{GOAL_CARD_KEY: {"title": "Old scratch goal"}}),
        default_tier="user_confirm",
    )
    assert forged.pending_approvals == []
    assert [b.policy for b in forged.blocked_actions] == [GOALS_RULE_POLICY]

    for target in (goal_id, str(uuid.uuid4())):
        foreign, _ = await _turn(
            runtime,
            str(other.id),
            "Delete it.",
            _call("goals.delete", goal_id=target),
            default_tier="user_confirm",
        )
        # The call's own error (not found), not a security block.
        assert foreign.pending_approvals == [] and foreign.blocked_actions == []
    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.user_id == other.id, AuditLog.action == "delete"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 2
    assert {(r.reasoning_chain or {}).get("policy") for r in rows} == {GOALS_RULE_POLICY}
    assert await _count(session_factory, Goal) == 1
