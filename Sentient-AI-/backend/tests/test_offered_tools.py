"""Tests for what the bounded tool array keeps for the assistant tools: a
reminder or page-watch create is never offered without the tools that list and
undo what it makes, and the new everyday tools (memory.remember, the page-watch
tools, canvas.get_upcoming) are starters, so a large connector cannot push them
out.

Why it exists: Nothing errors when a tool is missing from the array; the
assistant just claims it cannot do the thing, or starts a reminder or a watch
it cannot find and stop again (chat is the only place the owner can). The cap,
the core tools, tools.find and the loaded list are tested in
tests/test_tool_offering.py.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.context_manager import (
    CORE_TOOL_NAMES,
    MAX_OFFERED_TOOLS,
    UNDO_COMPANIONS,
    select_offered_tools,
)
from services.agent.runtime import AgentRuntime, PermissionEngine, Tool
from services.agent.tool_registry import (
    CONNECTOR_CATALOG,
    LEAD_STARTER_TOOLS,
    ConnectorSpec,
    build_tools,
    connector_scopes,
    resolve_tool,
)
from services.capabilities import REGISTRY as CAPABILITY_REGISTRY
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider

_EVERY_CAPABILITY = frozenset(c.key for c in CAPABILITY_REGISTRY)
_DEFAULT_SWITCHES = frozenset(c.key for c in CAPABILITY_REGISTRY if c.default_enabled)
_NEW_STARTERS = ("memory.remember", "watch.create", "watch.list", "watch.delete")


def _connected(connector_types: tuple[str, ...], write_scopes: bool) -> list[ConnectorSpec]:
    """Connectors as the Connectors page adds them: the read scopes by
    default, the write scopes when the user ticks them too."""
    specs = []
    for row, connector_type in enumerate(connector_types):
        scopes = connector_scopes(connector_type)
        granted = scopes["read"] + (scopes["write"] if write_scopes else [])
        specs.append(
            ConnectorSpec(connector_type, granted_scopes=tuple(granted), connector_id=f"row-{row}")
        )
    return specs


async def _offered_in_a_turn(tools: list[Tool]) -> set[str]:
    """The names of the tool array the provider is actually handed."""
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
    return {t["name"] for t in provider.calls[0]["tools"] or []}


# ---------------------------------------------------------------------------
# The real tool list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("connector_types", "switches", "starters_fit"),
    [
        (("canvas", "google_workspace"), _DEFAULT_SWITCHES, True),
        (("canvas", "google_workspace"), _DEFAULT_SWITCHES | {"page_watch"}, True),
        (("github",), _EVERY_CAPABILITY, True),
        # More starters than slots: they are cut in build order (connectors
        # first), and tools.find reaches the rest. The undo promise holds.
        (("canvas", "google_workspace", "github"), _EVERY_CAPABILITY, False),
        (("github", "notion", "slack", "microsoft"), _EVERY_CAPABILITY, False),
    ],
    ids=[
        "canvas-google",
        "canvas-google+page_watch",
        "github-all-on",
        "three-connectors-all-on",
        "large-all-on",
    ],
)
async def test_the_assistant_tools_survive_a_trim(
    connector_types: tuple[str, ...], switches: frozenset[str], starters_fit: bool
):
    tools = build_tools(_connected(connector_types, write_scopes=True), enabled_capabilities=switches)
    built = {t.name for t in tools}
    assert len(built) > MAX_OFFERED_TOOLS  # precondition: this is a trim

    offered = await _offered_in_a_turn(tools)

    assert len(offered) == MAX_OFFERED_TOOLS
    assert CORE_TOOL_NAMES <= offered
    if starters_fit:
        for name in (*_NEW_STARTERS, "canvas.get_upcoming", "reminders.create"):
            if name in built:
                assert name in offered, name
    # Whatever the trim, a reminder or a page watch the assistant can start
    # is one it can list and stop.
    for create, companions in UNDO_COMPANIONS.items():
        if create in offered:
            assert set(companions) <= offered, create


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("connector_types", "switches"),
    [
        (("canvas", "google_workspace"), _DEFAULT_SWITCHES | {"scheduled_tasks"}),
        (("canvas", "google_workspace"), _DEFAULT_SWITCHES | {"scheduled_tasks", "study", "event_triggers"}),
        ((), _EVERY_CAPABILITY),
        (("canvas",), _DEFAULT_SWITCHES | {"scheduled_tasks", "study", "event_triggers", "page_watch"}),
        (("github",), _EVERY_CAPABILITY - {"page_watch"}),
    ],
    ids=["student-scheduled", "student-study-triggers", "no-connectors-all-on", "canvas-opt-ins", "github-most-on"],
)
async def test_every_skill_and_account_keeps_its_entry_point_through_a_trim(
    connector_types: tuple[str, ...], switches: frozenset[str]
):
    """An opt-in switch must not push out a default-on skill's entry point
    (knowledge.search, video.transcript) or another opt-in's: a trim drops
    second tools (schedule.briefing, study.review, extra reads) first."""
    tools = build_tools(_connected(connector_types, write_scopes=True), enabled_capabilities=switches)
    assert len(tools) > MAX_OFFERED_TOOLS  # precondition: this is a trim
    offered = await _offered_in_a_turn(tools)
    leads = [t.name for t in tools if t.lead]
    for name in leads:
        assert name in offered, name
    built = {t.name for t in tools}
    assert LEAD_STARTER_TOOLS & built <= set(leads)
    # Each connected account leads with one everyday read.
    for connector_type in connector_types:
        assert any(n.startswith(f"{connector_type}.") for n in leads), connector_type
    if "scheduled_tasks" in switches:
        assert {"knowledge.search", "video.transcript", "schedule.create"} <= offered


def test_every_lead_is_a_real_starter():
    tools = {
        t.name: t
        for t in build_tools(
            _connected(("canvas",), write_scopes=False), enabled_capabilities=_EVERY_CAPABILITY
        )
    }
    for name in LEAD_STARTER_TOOLS:
        assert resolve_tool(name) is not None, name
        assert tools[name].starter and tools[name].lead, name
    assert not tools["schedule.briefing"].lead and tools["schedule.briefing"].starter


def test_leads_go_before_the_other_starters():
    tools = [
        *_core(),
        _tool("alpha.one", starter=True),
        _tool("alpha.two", starter=True),
        {**_tool("beta.entry", starter=True), "lead": True},
        *[_tool(f"gamma.t{i}") for i in range(30)],
    ]
    offered = [t["name"] for t in select_offered_tools(tools, [], max_tools=len(CORE_TOOL_NAMES) + 2)]
    assert "beta.entry" in offered and "alpha.one" in offered and "alpha.two" not in offered
    # The result keeps build order.
    assert offered.index("alpha.one") < offered.index("beta.entry")


def test_the_new_builtins_and_get_upcoming_are_starters():
    tools = {
        t.name: t
        for t in build_tools(
            _connected(("canvas",), write_scopes=False), enabled_capabilities=_EVERY_CAPABILITY
        )
    }
    for name in (*_NEW_STARTERS, "canvas.get_upcoming"):
        assert tools[name].starter, name
    # web.research repeats web.search plus web.fetch_page (both core), and the
    # grade what-if is one tools.find away: neither takes a starter slot.
    assert not tools["web.research"].starter
    assert not tools["canvas.grade_whatif"].starter
    canvas_starters = [s.action for s in CONNECTOR_CATALOG["canvas"] if s.starter]
    assert "get_upcoming" in canvas_starters and len(canvas_starters) <= 4


def test_the_undo_companions_name_real_tools_of_their_own_family():
    """A typo would silently keep nothing."""
    for create, companions in UNDO_COMPANIONS.items():
        for name in (create, *companions):
            assert resolve_tool(name) is not None, name
            assert name.partition(".")[0] == create.partition(".")[0], name


# ---------------------------------------------------------------------------
# select_offered_tools: undo companions
# ---------------------------------------------------------------------------


def _tool(name: str, *, starter: bool = False) -> dict[str, Any]:
    """A tool dict as ``AgentRuntime._tools_to_schema`` makes it."""
    namespace = name.rpartition(".")[0]
    return {
        "name": name,
        "description": "d",
        "parameters": {},
        "connector_type": namespace.partition("__")[0],
        "starter": starter,
    }


def _core() -> list[dict[str, Any]]:
    return [_tool(n) for n in sorted(CORE_TOOL_NAMES)]


def _names(offered: list[dict[str, Any]]) -> set[str]:
    return {t["name"] for t in offered} - CORE_TOOL_NAMES


def test_a_create_is_chosen_together_with_its_undo_or_not_at_all():
    # Build order puts the create first and its undo tools after the rest.
    tools = [
        *_core(),
        _tool("watch.create"),
        _tool("alpha.one"),
        _tool("alpha.two"),
        _tool("alpha.three"),
        _tool("watch.list"),
        _tool("watch.delete"),
    ]
    active = ["watch", "alpha"]

    # Three slots: the create and its two companions take them all.
    assert _names(select_offered_tools(tools, active, max_tools=len(_core()) + 3)) == {
        "watch.create",
        "watch.list",
        "watch.delete",
    }
    # Two slots cannot hold all three, so the create is passed over rather
    # than offered alone.
    assert _names(select_offered_tools(tools, active, max_tools=len(_core()) + 2)) == {
        "alpha.one",
        "alpha.two",
    }


def test_a_starter_create_brings_its_undo_ahead_of_other_starters():
    tools = [
        *_core(),
        _tool("reminders.create", starter=True),
        _tool("acme.read", starter=True),
        _tool("acme.write"),
        _tool("reminders.list"),
        _tool("reminders.cancel"),
    ]
    offered = _names(select_offered_tools(tools, ["reminders", "acme"], max_tools=len(_core()) + 4))
    assert offered == {"reminders.create", "reminders.list", "reminders.cancel", "acme.read"}


def test_a_loaded_create_takes_its_undo_first_when_slots_run_short():
    tools = [
        *_core(),
        _tool("watch.create"),
        _tool("watch.list"),
        _tool("watch.delete"),
        _tool("alpha.one"),
    ]
    # One free slot: the undo's first companion takes it, never the create.
    one = _names(
        select_offered_tools(tools, ["watch", "alpha"], max_tools=len(_core()) + 1, loaded=["watch.create"])
    )
    assert "watch.create" not in one and len(one) == 1
    three = _names(
        select_offered_tools(tools, ["watch", "alpha"], max_tools=len(_core()) + 3, loaded=["watch.create"])
    )
    assert three == {"watch.create", "watch.list", "watch.delete"}


def test_a_second_accounts_create_brings_its_own_undo():
    tools = [
        *_core(),
        _tool("reminders__1f2e3d4c.create"),
        _tool("reminders.list"),
        _tool("reminders.cancel"),
        _tool("reminders__1f2e3d4c.list"),
        _tool("reminders__1f2e3d4c.cancel"),
        _tool("alpha.one"),
    ]
    offered = _names(select_offered_tools(tools, ["reminders", "alpha"], max_tools=len(_core()) + 3))
    assert offered == {
        "reminders__1f2e3d4c.create",
        "reminders__1f2e3d4c.list",
        "reminders__1f2e3d4c.cancel",
    }


# top10:knowledge_base
def test_knowledge_search_is_a_starter_but_not_core_and_writes_are_never_auto():
    tools = {t.name: t for t in build_tools([], enabled_capabilities=_DEFAULT_SWITCHES)}
    assert tools["knowledge.search"].starter and "knowledge.search" not in CORE_TOOL_NAMES
    assert not tools["knowledge.add"].starter and not tools["knowledge.remove"].starter
    assert tools["knowledge.search"].permission_tier == "auto"
    assert tools["knowledge.add"].permission_tier == "approval"
    assert tools["knowledge.remove"].permission_tier == "approval"
    auto_account = {t.name: t for t in build_tools([], user_default_tier="auto_approve")}
    assert auto_account["knowledge.add"].permission_tier == "approval"
    off = {t.name for t in build_tools([], enabled_capabilities=_DEFAULT_SWITCHES - {"knowledge_base"})}
    assert not any(name.startswith("knowledge.") for name in off)


# top10:flashcards_quizzes
def test_the_study_starters_and_the_reminder_undo():
    tools = {
        t.name: t
        for t in build_tools(
            _connected(("canvas",), write_scopes=False), enabled_capabilities=_EVERY_CAPABILITY
        )
    }
    assert tools["study.save"].starter and tools["study.review"].starter
    assert not tools["study.delete"].starter and not tools["study.settings"].starter
    assert UNDO_COMPANIONS["study.settings"] == ("study.progress",)
