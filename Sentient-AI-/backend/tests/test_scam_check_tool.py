"""Tests for security.check_scam, the scam check's in-turn tool, through the
pieces a chat turn uses: the capability that claims it (offered, allowed and
dispatched only while scam_check is on), the executor running it as a READ
with no approval card and no model call, the audit row keeping only the
lengths of the text and sender and the number of links, the progress line,
the capability report row (on, low risk, its daily setting the service
reads), and main.py registering the handler of the process's one service.

Why it exists: the model calls this tool in an ordinary turn when someone asks
"is this legit?". It must never need a card (it only reads), never run when
the owner switched scam checks off, and never put the message, its sender or
its links in the append-only audit log.
"""

from __future__ import annotations

import pytest

from services import capabilities as registry
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    security_toolkit_of,
)
from services.audit import append_audit_log, redact_tool_arguments
from services.notifications.progress import phrase_for
from services.scam_check.service import ScamCheckService
from tests.conftest import make_user
from tests.test_scam_check_service import FakeLinks, FakeRuntime, FakeSettings, gate_for, scam_rows

ARGUMENTS = {
    "text": "Your refund is ready. Confirm your password to claim it.",
    "urls": ["https://amazon-refunds.shop/claim", "bit.ly/abc"],
    "sender": "Amazon Refunds <refunds@amazon-refunds.shop>",
    "reply_to": "help@amazon-refunds.example",
}


def _service(session_factory, runtime=None, links=None) -> ScamCheckService:
    return ScamCheckService(
        session_factory,
        capability_gate=gate_for({"scam_check": True}),
        settings=FakeSettings(),
        runtime_getter=lambda: runtime,
        links_getter=lambda: links,
    )


@pytest.mark.asyncio
async def test_security_check_scam_is_claimed_by_scam_check_and_offered_only_when_it_is_on():
    assert registry.capability_for_tool("security.check_scam").key == "scam_check"
    on = {t.name for t in build_tools([], enabled_capabilities=frozenset({"scam_check"}))}
    off = {t.name for t in build_tools([], enabled_capabilities=frozenset())}
    assert "security.check_scam" in on and "security.check_scam" not in off
    # On by default: a caller that passes no enabled set still offers it.
    assert "security.check_scam" in {t.name for t in build_tools([])}
    # The permission adapter blocks it with the capability's own sentence when off.
    adapter = RuntimePermissionAdapter(capability_gate=gate_for({"scam_check": False}))
    assert await adapter.check("u1", "security.check_scam", {}) == "blocked"
    assert await adapter.get_block_reason("u1", "security.check_scam", {}) == registry.get("scam_check").when_denied


@pytest.mark.asyncio
async def test_the_executor_runs_security_check_scam_as_a_read_without_a_card(session_factory):
    user, _ = await make_user(session_factory, "scam-tool-exec@example.com")
    runtime, links = FakeRuntime(), FakeLinks()
    service = _service(session_factory, runtime=runtime, links=links)
    executor = ConnectorToolExecutor(session_factory=None, capability_gate=gate_for({"scam_check": True}))
    security_toolkit_of(executor).register("check_scam", service.check_for_tool)

    # The offer marks it "auto" even under the default user_confirm account tier, and the
    # permission adapter lets it run: no approval card.
    (tool,) = [
        t
        for t in build_tools([], user_default_tier="user_confirm", enabled_capabilities=frozenset({"scam_check"}))
        if t.name == "security.check_scam"
    ]
    assert tool.permission_tier == "auto"
    adapter = RuntimePermissionAdapter(capability_gate=gate_for({"scam_check": True}))
    assert await adapter.check(str(user.id), "security.check_scam", ARGUMENTS) == "approved"

    result = await executor.execute("security.check_scam", dict(ARGUMENTS), str(user.id))
    assert result["ok"] is True and result["verdict"] == "likely_scam"
    assert "requires_approval" not in result and "pending" not in result
    assert runtime.calls == [] and runtime.resolved == []  # no model call inside a turn
    assert [call["purpose"] for call in links.calls] == ["scam_check", "scam_check"]
    assert service.quota.used_today(str(user.id)) == 0
    assert await scam_rows(session_factory, user.id) == []

    # Switched off, the executor refuses before the handler runs.
    off = ConnectorToolExecutor(session_factory=None, capability_gate=gate_for({"scam_check": False}))
    security_toolkit_of(off).register("check_scam", service.check_for_tool)
    refused = await off.execute("security.check_scam", dict(ARGUMENTS), str(user.id))
    assert refused["ok"] is False and refused["error"] == registry.get("scam_check").when_denied
    assert len(links.calls) == 2


@pytest.mark.asyncio
async def test_the_audit_row_keeps_the_lengths_of_the_text_sender_and_links(session_factory):
    from sqlalchemy import select

    from models.audit import AuditLog, AuditStatus

    user, _ = await make_user(session_factory, "scam-tool-audit@example.com")
    assert redact_tool_arguments("security.check_scam", ARGUMENTS) == {
        "text": f"<{len(ARGUMENTS['text'])} characters>",
        "urls": "<2 items>",
        "sender": f"<{len(ARGUMENTS['sender'])} characters>",
        "reply_to": f"<{len(ARGUMENTS['reply_to'])} characters>",
    }
    # The row the runtime writes for the call (tool_executed) stores exactly that.
    async with session_factory() as session:
        await append_audit_log(
            session,
            user_id=user.id,
            connector_name="security",
            action="check_scam",
            endpoint="tool",
            scope_used="READ",
            status=AuditStatus.approved,
            request_data=dict(ARGUMENTS),
        )
        await session.commit()
        row = (await session.execute(select(AuditLog).where(AuditLog.user_id == user.id))).scalars().one()
    stored = str(row.request_data)
    for leaked in ("refund", "password", "amazon-refunds", "bit.ly", "help@"):
        assert leaked not in stored, leaked
    assert row.request_data["urls"] == "<2 items>"


def test_the_progress_line_names_the_scam_check():
    for name in ("security.check_scam", "security__1a2b3c4d.check_scam"):
        assert phrase_for({"type": "tool_call", "data": {"name": name}}) == "Checking for signs of a scam\u2026"
    assert phrase_for({"type": "tool_result", "data": {"name": "security.check_scam"}}) is None


@pytest.mark.asyncio
async def test_the_capability_report_shows_scam_check_on_low_risk_with_its_daily_setting(session_factory):
    from services.installation import InstallationService

    owner, _ = await make_user(session_factory, "scam-tool-owner@example.com")
    installation = InstallationService(session_factory)
    status = (await installation.capability_statuses())["scam_check"]
    assert (status.effective, status.risk, status.default_enabled) == ("on", "low", True)
    assert status.label == "Check messages for scams when asked"
    assert status.tools == ("security.check_scam",)
    assert await installation.capability_settings("scam_check") == {"checks_per_day": 30}
    # The owner's setting is what the service counts against (validated 1..10000).
    await installation.set_capability_settings("scam_check", {"checks_per_day": 12}, actor_id=owner.id)
    with pytest.raises(ValueError):
        await installation.set_capability_settings("scam_check", {"checks_per_day": 0}, actor_id=owner.id)
    service = ScamCheckService(
        session_factory,
        capability_gate=installation.capability_statuses,
        settings=installation,
        runtime_getter=lambda: FakeRuntime(),
        links_getter=lambda: FakeLinks(),
    )
    answer = await service.status(str(owner.id))
    assert (answer["effective"], answer["checks_per_day"], answer["checks_used_today"]) == ("on", 12, 0)


@pytest.mark.asyncio
async def test_wire_services_registers_the_handler_of_the_one_scam_check_service(session_factory, monkeypatch):
    from core.config import settings
    from main import app, wire_services
    from tests.test_telegram_manager import FakeService

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        service = app.state.scam_check
        assert isinstance(service, ScamCheckService)
        assert service.installation is app.state.installation
        toolkit = security_toolkit_of(app.state.tool_executor)
        assert toolkit._handlers["check_scam"] == service.check_for_tool
        user, _ = await make_user(session_factory, "scam-tool-wired@example.com")
        answer = await app.state.tool_executor.execute(
            "security.check_scam", {"text": "Send me the code we just sent you."}, str(user.id)
        )
        assert answer["ok"] is True and answer["verdict"] in ("suspicious", "likely_scam")
    finally:
        await app.state.telegram_manager.stop()
        await app.state.slack_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)
