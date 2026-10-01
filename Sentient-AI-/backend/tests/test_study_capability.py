"""Tests for the "study" capability: it is registered off by default, low risk and
always available, claims the study.* family, and is enforced at the offer, the
permission adapter and the executor; the <study> prompt block is added only
when a study tool is offered, and with the switch off the system prompt is
byte-identical to one without the feature; study.save and study.review are
starters, and study.settings is offered with study.progress.

Why it exists: with the switch off, every request must look exactly as it did
before this feature (apart from its <permissions> line), and with it on the
model gets the card-writing rules exactly when it can act on them. No model
and no database.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.context_manager import UNDO_COMPANIONS, select_offered_tools
from services.agent.runtime import (
    CAPABILITY_OFF_POLICY,
    RESULT_CHAR_BUDGETS,
    SECURITY_SYSTEM_PROMPT,
    AgentRuntime,
    PermissionEngine,
    result_char_budget,
)
from services.agent.tool_registry import (
    CONNECTOR_CATALOG,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.capabilities import REGISTRY, capability_for_tool, get
from services.capabilities import report as capability_report
from services.capabilities import statuses_by_key
from services.capabilities.base import ReportContext
from services.notifications.progress import phrase_for
from services.study.prompt import STUDY_SYSTEM_PROMPT
from services.tools import study as study_tools
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider

_CTX = ReportContext(in_container=False, platform="win32", telegram_configured=False, browser_installed=False)


def _gate(*keys: str):
    switches = {c.key: c.key in keys for c in REGISTRY}
    statuses = statuses_by_key(capability_report(switches, _CTX, use_cache=False))

    async def gate():
        return statuses

    return gate


def test_study_is_registered_off_by_default_low_risk_and_claims_the_family():
    cap = get("study")
    assert cap.label == "Flashcards and practice quizzes"
    assert cap.description.startswith("Make flashcard decks and practice quizzes")
    assert cap.tools == ("study.",) and cap.default_enabled is False and cap.risk == "low"
    assert cap.when_denied == (
        "Flashcards and quizzes are turned off. The owner can turn them on in Settings → Permissions."
    )
    assert cap.availability(_CTX).available
    for spec in CONNECTOR_CATALOG["study"]:
        assert capability_for_tool(f"study.{spec.action}") is cap
    [status] = [s for s in capability_report({}, _CTX, use_cache=False) if s.key == "study"]
    assert status.effective == "off" and status.enabled is False and status.available is True


def test_the_catalog_matches_the_brief():
    categories = {s.action: s.category.value for s in CONNECTOR_CATALOG["study"]}
    assert categories == {
        "save": "write",
        "decks": "read",
        "edit": "write",
        "delete": "delete",
        "review": "write",
        "quiz": "write",
        "progress": "read",
        "settings": "write",
        "export": "read",
    }
    confirm = {s.action for s in CONNECTOR_CATALOG["study"] if s.always_confirm}
    assert confirm == {"delete"}
    assert RESULT_CHAR_BUDGETS["study.decks"] == 14000 == study_tools.DECKS_ROWS_CHARS + 2000
    assert RESULT_CHAR_BUDGETS["study.review"] == 12000 == study_tools.REVIEW_ROWS_CHARS + 2000
    assert RESULT_CHAR_BUDGETS["study.quiz"] == 16000 == study_tools.QUIZ_ROWS_CHARS + 2000
    assert result_char_budget("study.progress", 2000) == 6000


def test_study_tools_are_offered_only_with_the_switch_on():
    assert not any(t.name.startswith("study.") for t in build_tools([]))
    offered = {t.name for t in build_tools([], enabled_capabilities=frozenset({"study"}))}
    assert {f"study.{s.action}" for s in CONNECTOR_CATALOG["study"]} <= offered


@pytest.mark.asyncio
async def test_the_adapter_and_the_executor_refuse_while_it_is_off():
    adapter = RuntimePermissionAdapter(capability_gate=_gate())
    assert await adapter.check("u1", "study.save", {}) == "blocked"
    assert await adapter.get_policy_name("u1", "study.save") == CAPABILITY_OFF_POLICY
    assert await adapter.get_block_reason("u1", "study.decks", {}) == get("study").when_denied
    on = RuntimePermissionAdapter(capability_gate=_gate("study"))
    assert await on.check("u1", "study.save", {}) == "approved"
    assert await on.check("u1", "study.delete", {"deck_id": "x"}) == "requires_approval"
    executor = ConnectorToolExecutor(capability_gate=_gate())
    refused = await executor.execute("study.decks", {}, user_id="u1")
    assert refused["ok"] is False and refused["capability"] == "study" and refused["state"] == "off"


async def _system_prompt(tools) -> str:
    provider = RecordingProvider()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(runtime, provider)
    await runtime.chat(messages=[{"role": "user", "content": "hi"}], tools=tools, user_id="u1")
    return provider.calls[0]["messages"][0]["content"]


@pytest.mark.asyncio
async def test_the_study_block_is_there_only_when_a_study_tool_is_offered():
    with_study = await _system_prompt(build_tools([], enabled_capabilities=frozenset({"study"})))
    without = await _system_prompt(build_tools([]))
    assert STUDY_SYSTEM_PROMPT in with_study and "<study>" not in without
    assert with_study.index(STUDY_SYSTEM_PROMPT) < with_study.index("<today>")
    assert with_study.replace(f"\n\n{STUDY_SYSTEM_PROMPT}", "") == without


def test_off_the_system_prompt_is_byte_identical_to_the_one_without_the_feature():
    messages: list[dict[str, Any]] = [{"role": "user", "content": "x"}]
    assert AgentRuntime._with_system_prompt(messages) == AgentRuntime._with_system_prompt(messages, study=False)
    head = AgentRuntime._with_system_prompt(messages, study=True)[0]["content"]
    assert head.startswith(SECURITY_SYSTEM_PROMPT) and "<study>" in head
    assert "graded Canvas quiz" in STUDY_SYSTEM_PROMPT and "3 sample items" in STUDY_SYSTEM_PROMPT


def test_starters_and_the_reminder_is_offered_with_its_progress():
    tools = {t.name: t for t in build_tools([], enabled_capabilities=frozenset({"study"}))}
    starters = {name for name, t in tools.items() if name.startswith("study.") and t.starter}
    assert starters == {"study.save", "study.review"}
    assert UNDO_COMPANIONS["study.settings"] == ("study.progress",)
    catalog = [
        {"name": name, "description": "", "starter": False, "connector_type": "study"}
        for name in sorted(tools)
        if name.startswith("study.")
    ]
    fillers = [{"name": f"acme.a{i}", "description": "", "starter": False, "connector_type": "acme"} for i in range(40)]
    offered = {t["name"] for t in select_offered_tools([*fillers, *catalog], [], max_tools=5, loaded=["study.settings"])}
    assert {"study.settings", "study.progress"} <= offered


def test_progress_lines_name_the_study_tools():
    for tool, line in (
        ("study.save", "Saving flashcards…"),
        ("study.review", "Getting your next card…"),
        ("study.quiz", "Preparing your quiz…"),
        ("study.progress", "Checking your study progress…"),
        ("study.export", "Preparing your export…"),
    ):
        event = {"type": "tool_call", "data": {"name": tool, "action": "next"}}
        assert phrase_for(event) == line
