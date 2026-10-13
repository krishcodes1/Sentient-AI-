"""Tests for the secret guard on tool arguments (services/security/guard.py at the
runtime's call_after_argument_scan point, and again in approve_action): a key in
an auto-tier write, an approval write, a web.search query, a URL carrying
X-Amz-Signature, an MCP tool and a weekly-approved desktop.act is refused with
no card and no executor call, filed as a secret_guard block whose audit row
shows ***REDACTED***; contact details pass; and an approval whose stored
arguments were swapped to hold a key is refused before tool_approved.

Why it exists: a prompt injection that reads a token from one place and asks a
tool to send it somewhere is the exfiltration the model floor cannot stop on
its own (a value the model saw before the floor, or one a tool call built).
Everything is faked: a scripted model, a recording executor and audit log.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime, Tool
from services.agent.tool_registry import ConnectorSpec, RuntimePermissionAdapter, build_tools
from services.security.guard import CREDENTIAL_RULE, SECRET_GUARD_POLICY, check_stored
from tests.conftest import use_provider
from tests.test_weekly_app_approvals_runtime import (
    ACT,
    OBSERVE,
    TG,
    U1,
    Turn,
    calendar_desktop,
    refs_of,
)
from tests.test_weekly_app_approvals_runtime import (
    _computer_control_on as _computer_control_on,  # noqa: F401 - autouse fixture
)
from tests.test_weekly_app_approvals_runtime import (
    _no_stale_stop as _no_stale_stop,  # noqa: F401 - autouse fixture
)

TOKEN = "ghp_" + "FAKE" * 9
REDACTED = "***REDACTED***"
USER = "guard-user"

GOOGLE_TOOLS = build_tools([ConnectorSpec("google_workspace")], include_builtins=False)
AUTO_GOOGLE_TOOLS = build_tools(
    [ConnectorSpec("google_workspace", permission_tier="auto_approve")],
    user_default_tier="auto_approve",
    include_builtins=False,
)
WEB_TOOLS = build_tools([], enabled_capabilities=frozenset({"web_browsing"}))
MCP_TOOLS = [
    Tool(
        name="mcp.notes.save",
        description="Save a note",
        parameters={"type": "object", "properties": {"text": {"type": "string"}}},
        connector_type="mcp",
        permission_tier="approval",
    )
]


class ScriptedProvider:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(list(messages))
        return self._responses.pop(0) if self._responses else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append({"tool": tool_name, "arguments": arguments})
        return {"ok": True}


class RecordingAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def log(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)


def _runtime(responses: list[LLMResponse], audit: Any = None):
    provider = ScriptedProvider(responses)
    executor = RecordingExecutor()
    audit = audit if audit is not None else RecordingAudit()
    store = InMemoryApprovalStore()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor,
        audit_service=audit,
        approval_store=store,
    )
    use_provider(runtime, provider)
    return runtime, provider, executor, audit, store


def _call(name: str, **arguments: Any) -> LLMResponse:
    return LLMResponse(content="", tool_calls=[ToolCall(id="c1", name=name, arguments=arguments)])


CASES = [
    ("auto-tier write", AUTO_GOOGLE_TOOLS, "google_workspace.create_draft",
     {"to": "prof.lee@uni.edu", "subject": "key", "body": f"here it is: {TOKEN}"}, "body"),
    ("approval write", GOOGLE_TOOLS, "google_workspace.send_email",
     {"to": "prof.lee@uni.edu", "subject": "key", "body": f"token {TOKEN}"}, "body"),
    ("web.search", WEB_TOOLS, "web.search", {"query": f"is {TOKEN} valid"}, "query"),
    ("pre-signed URL", WEB_TOOLS, "web.fetch_page",
     {"url": "https://files.example.com/r.pdf?X-Amz-Date=20260930&X-Amz-Signature=" + "ab12" * 16},
     "url"),
    ("MCP tool", MCP_TOOLS, "mcp.notes.save", {"text": f"remember {TOKEN}"}, "text"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("_label", "tools", "name", "arguments", "field"), CASES, ids=[c[0] for c in CASES])
async def test_a_key_in_the_arguments_is_refused_before_any_card(_label, tools, name, arguments, field):
    runtime, provider, executor, audit, store = _runtime(
        [_call(name, **arguments), LLMResponse(content="I cannot send that.")]
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "do the thing"}], tools=tools, user_id=USER
    )
    assert executor.calls == []
    assert response.pending_approvals == [] and await store.list_pending(USER) == []
    [blocked] = response.blocked_actions
    assert blocked.tool_name == name and blocked.policy == SECRET_GUARD_POLICY
    [row] = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert row["policy"] == SECRET_GUARD_POLICY and row["rule"] == CREDENTIAL_RULE
    assert row["arguments"][field] == REDACTED
    assert TOKEN not in json.dumps(audit.entries, default=str)
    # The model is told the field and the kind of value, never the value.
    [record] = response.tool_calls
    result = record["result"]
    assert result["ok"] is False and result["rule"] == CREDENTIAL_RULE
    assert f"'{field}'" in result["error"] and "YOUR_API_KEY" in result["error"]
    assert TOKEN not in json.dumps(result)
    # The refusal reached the model as the call's result, and the turn went on.
    assert len(provider.calls) == 2 and response.content == "I cannot send that."


@pytest.mark.asyncio
async def test_the_blocked_event_names_the_policy_and_rule():
    runtime, _provider, _executor, _audit, _store = _runtime(
        [_call("web.search", query=f"{TOKEN}"), LLMResponse(content="ok")]
    )
    events: list[dict[str, Any]] = []

    async def sink(event: dict[str, Any]) -> None:
        events.append(event)

    await runtime.chat(
        messages=[{"role": "user", "content": "search"}], tools=WEB_TOOLS, user_id=USER, event_sink=sink
    )
    [blocked] = [e for e in events if e["type"] == "blocked"]
    assert blocked["data"]["policy"] == SECRET_GUARD_POLICY
    assert blocked["data"]["rule"] == CREDENTIAL_RULE
    assert TOKEN not in json.dumps(events)


@pytest.mark.asyncio
async def test_contact_details_and_placeholders_for_examples_pass():
    runtime, _provider, executor, _audit, _store = _runtime(
        [
            _call(
                "google_workspace.create_draft",
                to="prof.lee@uni.edu",
                subject="Setup",
                body="Call me at (212) 555-0100. Set api_key = YOUR_API_KEY in the config.",
            ),
            LLMResponse(content="Drafted."),
        ]
    )
    await runtime.chat(
        messages=[{"role": "user", "content": "draft it"}], tools=AUTO_GOOGLE_TOOLS, user_id=USER
    )
    assert len(executor.calls) == 1


@pytest.mark.asyncio
async def test_a_key_in_a_weekly_approved_desktop_act_is_refused():
    refs = await refs_of()
    turn = Turn(calendar_desktop())
    await turn.app_store.allow(user_id=U1, app="Calendar", channel=TG)
    response = await turn.run(
        OBSERVE,
        LLMResponse(
            content="",
            tool_calls=[
                ToolCall(id="a1", name=ACT, arguments={"action": "type", "ref": refs["search"], "text": TOKEN})
            ],
        ),
        LLMResponse(content="I will not type that."),
    )
    assert turn.fake.events == []
    assert response.pending_approvals == []
    assert [b.policy for b in response.blocked_actions] == [SECRET_GUARD_POLICY]
    [row] = turn.act_rows("tool_blocked")
    assert row["arguments"]["text"] == REDACTED


@pytest.mark.asyncio
async def test_the_stored_audit_row_holds_no_key(session_factory):
    from services.audit import RuntimeAuditLogger
    from tests.conftest import make_user

    user, _ = await make_user(session_factory, email="guard-audit@example.com")
    runtime, *_ = _runtime(
        [_call("web.search", query=f"check {TOKEN}"), LLMResponse(content="ok")],
        audit=RuntimeAuditLogger(session_factory=session_factory),
    )
    await runtime.chat(
        messages=[{"role": "user", "content": "search"}], tools=WEB_TOOLS, user_id=str(user.id)
    )
    from sqlalchemy import select

    from models.audit import AuditLog

    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog))).scalars().all()
    blocked = [r for r in rows if r.reasoning_chain and r.reasoning_chain.get("policy") == SECRET_GUARD_POLICY]
    assert len(blocked) == 1 and blocked[0].request_data == {"query": REDACTED}
    stored = json.dumps([[r.request_data, r.reasoning_chain, r.response_summary] for r in rows], default=str)
    assert TOKEN not in stored


# ── approve_action ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_approval_whose_stored_arguments_were_swapped_is_refused():
    runtime, _provider, executor, audit, store = _runtime([])
    stored = await store.create(
        user_id=USER,
        tool_name="google_workspace.send_email",
        arguments={"to": "prof.lee@uni.edu", "subject": "s", "body": "clean"},
        reason="needs approval",
    )
    record = store._records[stored.action_id]
    record.action = type(record.action)(
        **{**record.action.__dict__, "arguments": {"to": "prof.lee@uni.edu", "subject": "s", "body": TOKEN}}
    )
    result = await runtime.approve_action(stored.action_id, USER)
    assert "error" in result and "security policy" in result["error"]
    assert executor.calls == []
    events = [e["event"] for e in audit.entries]
    assert "tool_approved" not in events
    [row] = [e for e in audit.entries if e["event"] == "tool_blocked"]
    assert row["policy"] == SECRET_GUARD_POLICY and row["arguments"]["body"] == REDACTED
    assert TOKEN not in json.dumps(audit.entries, default=str)


@pytest.mark.asyncio
async def test_an_untouched_approval_still_runs():
    runtime, _provider, executor, _audit, store = _runtime([])
    stored = await store.create(
        user_id=USER,
        tool_name="google_workspace.send_email",
        arguments={"to": "prof.lee@uni.edu", "subject": "s", "body": "See you Monday."},
        reason="needs approval",
    )
    result = await runtime.approve_action(stored.action_id, USER)
    assert "error" not in result and len(executor.calls) == 1


def test_a_cards_reserved_screen_is_not_read_at_approval():
    screen = {"outline": [f"text field 'Card' value {TOKEN}"]}
    assert check_stored("desktop.act", {"action": "click", "ref": "d1", "_screen": screen}) is None
    assert check_stored("google_workspace.send_email", {"_screen": screen}) is not None
