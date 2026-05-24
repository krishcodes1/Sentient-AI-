"""Tests for the connector tool registry, permission adapter, and executor.

Pure-Python: builds tools from plain ConnectorSpec inputs and exercises
the adapter/executor directly. No database required.
"""

from __future__ import annotations

import pytest

from services.agent.permissions import (
    ActionCategory,
    PermissionEngine,
    PermissionTier,
)
from services.agent.tool_registry import (
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    resolve_tool,
)


# ---------------------------------------------------------------------------
# build_tools
# ---------------------------------------------------------------------------


def test_build_tools_canvas_and_gmail_emit_expected_tools():
    tools = build_tools([ConnectorSpec("canvas"), ConnectorSpec("google_workspace")])
    names = {t.name for t in tools}
    assert "canvas.get_assignments" in names
    assert "canvas.get_courses" in names
    assert "google_workspace.send_email" in names
    assert "google_workspace.get_events" in names


def test_build_tools_canvas_read_is_auto_approve():
    tools = build_tools([ConnectorSpec("canvas")])
    courses = next(t for t in tools if t.name == "canvas.get_courses")
    assert courses.permission_tier == "auto"


def test_build_tools_gmail_write_requires_approval():
    tools = build_tools([ConnectorSpec("google_workspace")])
    send = next(t for t in tools if t.name == "google_workspace.send_email")
    assert send.permission_tier == "approval"


def test_build_tools_omits_hard_blocked_trade():
    tools = build_tools([ConnectorSpec("robinhood")])
    names = {t.name for t in tools}
    assert "robinhood.execute_trade" not in names
    # Read tools are still present
    assert "robinhood.get_crypto_holdings" in names


def test_build_tools_robinhood_reads_require_approval():
    # Robinhood READ policy is USER_CONFIRM, not auto-approve.
    tools = build_tools([ConnectorSpec("robinhood")])
    holdings = next(t for t in tools if t.name == "robinhood.get_crypto_holdings")
    assert holdings.permission_tier == "approval"


def test_build_tools_inactive_connector_emits_nothing():
    assert build_tools([ConnectorSpec("canvas", is_active=False)]) == []


def test_build_tools_unknown_connector_skipped_safely():
    assert build_tools([ConnectorSpec("dropbox")]) == []


def test_build_tools_empty_list():
    assert build_tools([]) == []


def test_build_tools_tool_has_parameters_schema():
    tools = build_tools([ConnectorSpec("canvas")])
    assignments = next(t for t in tools if t.name == "canvas.get_assignments")
    assert assignments.parameters["type"] == "object"
    assert "course_id" in assignments.parameters["properties"]
    assert "course_id" in assignments.parameters["required"]


# ---------------------------------------------------------------------------
# resolve_tool
# ---------------------------------------------------------------------------


def test_resolve_tool_valid_canvas():
    r = resolve_tool("canvas.get_assignments")
    assert r is not None
    assert r.connector_type == "canvas"
    assert r.action == "get_assignments"
    assert r.policy_key == "canvas"


def test_resolve_tool_gmail_policy_key():
    r = resolve_tool("google_workspace.send_email")
    assert r is not None
    assert r.policy_key == "gmail"


def test_resolve_tool_calendar_policy_key():
    r = resolve_tool("google_workspace.create_event")
    assert r is not None
    assert r.policy_key == "google_calendar"


def test_resolve_tool_malformed_and_unknown():
    assert resolve_tool("nodot") is None
    assert resolve_tool("canvas.nonexistent_action") is None
    assert resolve_tool("unknown_connector.action") is None


# ---------------------------------------------------------------------------
# RuntimePermissionAdapter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adapter_auto_approves_read():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u", "canvas.get_courses", {}) == "approved"


@pytest.mark.asyncio
async def test_adapter_requires_approval_for_write():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u", "google_workspace.send_email", {}) == "requires_approval"


@pytest.mark.asyncio
async def test_adapter_blocks_financial():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u", "robinhood.execute_trade", {}) == "blocked"


@pytest.mark.asyncio
async def test_adapter_default_denies_unknown_tools():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u", "unknown.tool", {}) == "blocked"
    assert await adapter.check("u", "malformed", {}) == "blocked"


@pytest.mark.asyncio
async def test_adapter_block_reason_and_policy_name():
    adapter = RuntimePermissionAdapter()
    reason = await adapter.get_block_reason("u", "robinhood.execute_trade", {})
    assert "block" in reason.lower()
    assert await adapter.get_policy_name("u", "canvas.get_courses") == "canvas:read"
    assert await adapter.get_policy_name("u", "malformed") == "default-deny"


# ---------------------------------------------------------------------------
# ConnectorToolExecutor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_executor_dispatches_known_tool():
    executor = ConnectorToolExecutor()
    res = await executor.execute("canvas.get_assignments", {"course_id": "1"}, "u")
    assert res["ok"] is True
    assert res["connector"] == "canvas"
    assert res["action"] == "get_assignments"
    assert res["arguments"] == {"course_id": "1"}


@pytest.mark.asyncio
async def test_executor_unknown_tool_returns_structured_error():
    executor = ConnectorToolExecutor()
    res = await executor.execute("unknown.tool", {}, "u")
    assert res["ok"] is False
    assert "error" in res


@pytest.mark.asyncio
async def test_executor_never_runs_financial_action():
    executor = ConnectorToolExecutor()
    res = await executor.execute(
        "robinhood.execute_trade", {"symbol": "BTC", "side": "buy"}, "u"
    )
    assert res["ok"] is False
    assert "block" in res["error"].lower()


# ---------------------------------------------------------------------------
# Permission mapping sanity (real engine)
# ---------------------------------------------------------------------------


def test_permission_mapping_documented_tiers():
    eng = PermissionEngine()
    assert (
        eng.check_permission("canvas", "get_courses", ActionCategory.READ).tier
        == PermissionTier.AUTO_APPROVE
    )
    assert (
        eng.check_permission("gmail", "send_email", ActionCategory.WRITE).tier
        == PermissionTier.USER_CONFIRM
    )
    assert (
        eng.check_permission("robinhood", "execute_trade", ActionCategory.FINANCIAL).tier
        == PermissionTier.HARD_BLOCKED
    )


def test_permission_default_deny_unknown_connector():
    eng = PermissionEngine()
    # Unknown connector falls back to USER_CONFIRM for reads, never auto-approve.
    decision = eng.check_permission("dropbox", "list_files", ActionCategory.READ)
    assert decision.tier != PermissionTier.AUTO_APPROVE


# ---------------------------------------------------------------------------
# Admin-tier behavior (regression for the build_tools / adapter consistency fix)
# ---------------------------------------------------------------------------


def test_build_tools_omits_admin_only_tools_for_standard_user():
    from services.agent.permissions import UserTier

    # Force Canvas reads to ADMIN_ONLY via a policy override.
    eng = PermissionEngine(
        policy_overrides={("canvas", ActionCategory.READ): PermissionTier.ADMIN_ONLY}
    )
    tools = build_tools([ConnectorSpec("canvas")], engine=eng, user_tier=UserTier.STANDARD)
    names = {t.name for t in tools}
    # Read tools are admin-only -> blocked for a standard user -> omitted.
    assert "canvas.get_courses" not in names
    # A non-overridden write tool is still offered (requires approval).
    assert "canvas.submit_assignment" in names


def test_build_tools_admin_user_gets_admin_only_tools_as_approval():
    from services.agent.permissions import UserTier

    eng = PermissionEngine(
        policy_overrides={("canvas", ActionCategory.READ): PermissionTier.ADMIN_ONLY}
    )
    tools = build_tools([ConnectorSpec("canvas")], engine=eng, user_tier=UserTier.ADMIN)
    courses = next((t for t in tools if t.name == "canvas.get_courses"), None)
    assert courses is not None
    # ADMIN_ONLY for an admin resolves to requires_approval -> "approval".
    assert courses.permission_tier == "approval"
