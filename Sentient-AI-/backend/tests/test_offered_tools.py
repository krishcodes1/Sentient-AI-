"""Tests for which tools a request offers once there are more than the cap: the
core tools always, every active family at least its most useful tool (by the
tool priority list), the rest shared round-robin, and the same array for the
same tool set whatever order it was built in.

Why it exists: One global alphabetical cut used to fill the array with Canvas
and Gmail tools, so with the default switches plus Canvas and Google connected
reminders.create and web.screenshot were silently never offered. Nothing
errors when a tool is missing from the array; the assistant just claims it
cannot do the thing, so the cut needs tests of its own.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.context_manager import (
    CORE_TOOL_NAMES,
    COVERED_TOOLS,
    OFFERED_TOOL_CAP,
    TOOL_PRIORITY,
    UNDO_COMPANIONS,
    select_offered_tools,
)
from services.agent.permissions import ActionCategory
from services.agent.runtime import AgentRuntime, PermissionEngine, Tool
from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    CONNECTOR_CATALOG,
    ConnectorSpec,
    build_tools,
    connector_scopes,
    resolve_tool,
)
from services.capabilities import REGISTRY as CAPABILITY_REGISTRY
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider


def _canvas_and_google(write_scopes: bool) -> list[ConnectorSpec]:
    """Canvas and Google as the Connectors page adds them: the read scopes
    by default, the write scopes when the user ticks them too."""
    specs = []
    for row, connector_type in enumerate(("canvas", "google_workspace")):
        scopes = connector_scopes(connector_type)
        granted = scopes["read"] + (scopes["write"] if write_scopes else [])
        specs.append(
            ConnectorSpec(connector_type, granted_scopes=tuple(granted), connector_id=f"row-{row}")
        )
    return specs


def _future_tools() -> list[Tool]:
    """Stand-ins for the families still being added: three new families and
    one more tool each for two existing ones. Named so they cannot collide
    with the real tools when those land."""
    names = {
        "future_a": ("alpha", "beta", "gamma"),
        "future_b": ("alpha",),
        "future_c": ("alpha", "beta", "gamma"),
        "web": ("zz_future",),
        "canvas": ("zz_future",),
    }
    return [
        Tool(
            name=f"{family}.{action}",
            description="A tool still to come, with a description of ordinary length.",
            parameters={"type": "object", "properties": {"q": {"type": "string"}}},
            connector_type=family,
        )
        for family, actions in names.items()
        for action in actions
    ]


def _family(name: str) -> str:
    return name.rpartition(".")[0]


async def _offered_in_a_turn(tools: list[Tool]) -> list[dict[str, Any]]:
    """The tool array the provider is actually handed on a chat turn."""
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
    return provider.calls[0]["tools"] or []


def _schema(tools: list[Tool]) -> list[dict[str, Any]]:
    return AgentRuntime._tools_to_schema(tools)


# ---------------------------------------------------------------------------
# The real tool list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("write_scopes", [False, True], ids=["read-scopes", "write-scopes"])
@pytest.mark.parametrize("with_future", [False, True], ids=["today", "grown"])
async def test_defaults_with_canvas_and_google_still_offer_reminders_and_screenshots(
    write_scopes: bool, with_future: bool
):
    tools = build_tools(_canvas_and_google(write_scopes))  # registry default switches
    if with_future:
        tools += _future_tools()
    built = {t.name for t in tools}
    assert {"reminders.create", "web.screenshot"} <= built  # precondition

    offered = {t["name"] for t in await _offered_in_a_turn(tools)}

    assert {"reminders.create", "web.screenshot"} <= offered
    assert CORE_TOOL_NAMES <= offered
    assert len(offered) == min(len(built), OFFERED_TOOL_CAP)
    # Every family that was built is offered at least one tool.
    assert {_family(n) for n in built} == {_family(n) for n in offered}


# What the default switches plus Canvas and Google with every scope built
# when the cap was set. Pinned so the next test stays about the selection
# policy as more default-on tools join the catalog.
_EVERYDAY_TOOLS = frozenset(
    {
        "web.search",
        "web.fetch_page",
        "web.screenshot",
        "reminders.now",
        "reminders.create",
        "reminders.list",
        "reminders.cancel",
        "system.capabilities",
        "system.install_capability",
        "canvas.get_courses",
        "canvas.get_assignments",
        "canvas.get_grades",
        "canvas.get_calendar_events",
        "canvas.get_submissions",
        "canvas.submit_assignment",
        "google_workspace.get_messages",
        "google_workspace.get_message",
        "google_workspace.search_emails",
        "google_workspace.send_email",
        "google_workspace.get_events",
        "google_workspace.check_availability",
        "google_workspace.create_event",
    }
)


@pytest.mark.asyncio
async def test_the_everyday_trim_drops_only_what_another_tool_already_does():
    """Those 22 tools, so two go: Gmail's get_message and search_emails,
    which repeat what get_messages returns (full messages, any query), not
    a Canvas read or anything from the small families."""
    tools = [
        t for t in build_tools(_canvas_and_google(write_scopes=True)) if t.name in _EVERYDAY_TOOLS
    ]
    assert {t.name for t in tools} == _EVERYDAY_TOOLS  # precondition

    offered = {t["name"] for t in await _offered_in_a_turn(tools)}

    assert _EVERYDAY_TOOLS - offered == {
        "google_workspace.get_message",
        "google_workspace.search_emails",
    }


# The tools added once the cap was set (web.research, canvas.get_upcoming,
# canvas.grade_whatif, memory.remember, the watch family) against the real
# catalog: from the default switches alone up to every capability switched on
# with Canvas and Google on every scope.
_EVERY_CAPABILITY = frozenset(c.key for c in CAPABILITY_REGISTRY)

# The tool each family's priority list ranks first, where the family is built.
_FAMILY_LEADS = (
    "web.screenshot",
    "reminders.create",
    "canvas.get_upcoming",
    "google_workspace.get_messages",
    "memory.remember",
    "watch.create",
    "desktop.observe",
    "browser.read",
)


def _connected(connector_types: tuple[str, ...], write_scopes: bool) -> list[ConnectorSpec]:
    specs = []
    for row, connector_type in enumerate(connector_types):
        scopes = connector_scopes(connector_type)
        granted = scopes["read"] + (scopes["write"] if write_scopes else [])
        specs.append(
            ConnectorSpec(connector_type, granted_scopes=tuple(granted), connector_id=f"row-{row}")
        )
    return specs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("connector_types", "write_scopes", "every_capability"),
    [
        ((), False, False),
        (("canvas",), False, False),
        (("canvas",), True, False),
        (("canvas", "google_workspace"), False, False),
        (("canvas", "google_workspace"), True, False),
        (("canvas", "google_workspace"), True, True),
    ],
    ids=[
        "defaults",
        "canvas-read",
        "canvas-write",
        "canvas-google-read",
        "canvas-google-write",
        "everything-on",
    ],
)
async def test_every_built_family_keeps_its_lead_tool(
    connector_types: tuple[str, ...], write_scopes: bool, every_capability: bool
):
    tools = build_tools(
        _connected(connector_types, write_scopes),
        enabled_capabilities=_EVERY_CAPABILITY if every_capability else None,
    )
    built = {t.name for t in tools}
    if every_capability:
        assert {"watch.create", "desktop.observe", "browser.read"} <= built  # precondition
        assert len(built) > OFFERED_TOOL_CAP

    offered = {t["name"] for t in await _offered_in_a_turn(tools)}

    assert CORE_TOOL_NAMES <= offered
    assert len(offered) == min(len(built), OFFERED_TOOL_CAP)
    assert {_family(n) for n in built} == {_family(n) for n in offered}
    for lead in _FAMILY_LEADS:
        if lead in built:
            assert lead in offered, lead
    # Whatever the trim, a reminder or a page watch the assistant can start
    # is one it can list and stop: chat is the only place the owner can.
    for create, companions in UNDO_COMPANIONS.items():
        if create in offered:
            assert set(companions) <= offered, (create, sorted(built - offered))


@pytest.mark.asyncio
@pytest.mark.parametrize("write_scopes", [False, True], ids=["read-scopes", "write-scopes"])
async def test_the_new_tools_are_offered_with_canvas_and_google_connected(write_scopes: bool):
    """With the default switches the new tools push the everyday set past
    the cap again; the trim takes the tools they cover, not them."""
    tools = build_tools(_canvas_and_google(write_scopes))
    new_tools = {"web.research", "canvas.get_upcoming", "canvas.grade_whatif", "memory.remember"}
    assert new_tools <= {t.name for t in tools}  # precondition

    offered = {t["name"] for t in await _offered_in_a_turn(tools)}

    assert new_tools | {"web.screenshot", "reminders.create", "canvas.get_courses"} <= offered
    assert not {"canvas.get_submissions", "google_workspace.search_emails"} & offered


_DEFAULT_SWITCHES = frozenset(c.key for c in CAPABILITY_REGISTRY if c.default_enabled)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "switches",
    [_DEFAULT_SWITCHES, _DEFAULT_SWITCHES | {"page_watch"}],
    ids=["defaults", "defaults+page_watch"],
)
@pytest.mark.parametrize(
    "connector_types",
    [("canvas",), ("google_workspace",), ("canvas", "google_workspace")],
    ids=["canvas", "google", "canvas+google"],
)
async def test_every_write_the_owner_granted_is_offered(
    switches: frozenset[str], connector_types: tuple[str, ...]
):
    """A write tool is built only once the owner granted its scope, and
    nothing else does what it does: the trim takes a tool that repeats
    another offered one instead (the assistant would otherwise just say it
    cannot submit, send or book)."""
    tools = build_tools(
        _connected(connector_types, write_scopes=True), enabled_capabilities=switches
    )
    built = {t.name for t in tools}
    granted = {t.name for t in tools if t.connector_write}
    assert granted  # precondition

    offered = {t["name"] for t in await _offered_in_a_turn(tools)}

    assert granted <= offered, sorted(granted - offered)
    assert len(offered) == min(len(built), OFFERED_TOOL_CAP)
    for create, companions in UNDO_COMPANIONS.items():
        if create in offered:
            assert set(companions) <= offered, create
    for lead in _FAMILY_LEADS:
        if lead in built:
            assert lead in offered, lead


# Pinned so any change to what these two configurations lose is deliberate.
_DROPPED = {
    # Nothing dropped does something no offered tool does, except
    # grade_whatif's what-if answers and the course calendar.
    "canvas-google-write+page_watch": (
        (("canvas", "google_workspace"), _DEFAULT_SWITCHES | {"page_watch"}),
        {
            "canvas.get_assignments",
            "canvas.get_calendar_events",
            "canvas.get_grades",
            "canvas.get_submissions",
            "canvas.grade_whatif",
            "google_workspace.check_availability",
            "google_workspace.get_message",
            "google_workspace.search_emails",
            "web.research",
        },
    ),
    # 33 tools for 20 slots across nine families. The undo companions take
    # the slots of web.research and system.install_capability; Gmail's
    # send_email and Calendar's create_event stay out, since the only
    # other picks left are families' second tools (canvas.get_courses,
    # desktop.act, google_workspace.get_events), which are not repeats.
    "everything-on": (
        (("canvas", "google_workspace"), _EVERY_CAPABILITY),
        {
            "canvas.get_assignments",
            "canvas.get_calendar_events",
            "canvas.get_grades",
            "canvas.get_submissions",
            "canvas.grade_whatif",
            "desktop.screenshot",
            "google_workspace.check_availability",
            "google_workspace.create_event",
            "google_workspace.get_message",
            "google_workspace.search_emails",
            "google_workspace.send_email",
            "system.install_capability",
            "web.research",
        },
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("config", sorted(_DROPPED))
async def test_what_the_largest_configurations_leave_out_is_pinned(config: str):
    (connector_types, switches), dropped = _DROPPED[config]
    tools = build_tools(
        _connected(connector_types, write_scopes=True), enabled_capabilities=switches
    )

    offered = {t["name"] for t in await _offered_in_a_turn(tools)}

    assert {t.name for t in tools} - offered == dropped


def test_the_keep_lists_name_real_tools():
    """A typo would silently keep or cover nothing. A covered tool is a
    read: a write is never a repeat of another tool."""
    for create, companions in UNDO_COMPANIONS.items():
        for name in (create, *companions):
            assert resolve_tool(name) is not None, name
            assert _family(name) == _family(create), name
    for name, coverers in COVERED_TOOLS.items():
        resolved = resolve_tool(name)
        assert resolved is not None, name
        for coverer in coverers:
            assert resolve_tool(coverer) is not None, coverer
            assert _family(coverer) == _family(name), coverer
        assert resolved.spec.category == ActionCategory.READ, name
        assert name not in CORE_TOOL_NAMES


def test_every_connector_write_is_marked_from_the_catalog_and_nothing_else():
    """The trim keeps a granted write by its ``connector_write`` mark, which
    build_tools takes from the catalog entry: a new connector's writes are
    kept with no list to update. Built-in writes (a reminder, a memory, a
    page watch, a desktop act) are not connector writes; a FINANCIAL action
    is hard-blocked and never built."""
    connectors = [c for c in CONNECTOR_CATALOG if c not in BUILTIN_CONNECTOR_TYPES]
    tools = build_tools(
        _connected(tuple(connectors), write_scopes=True), enabled_capabilities=_EVERY_CAPABILITY
    )
    marked = {t.name for t in tools if t.connector_write}
    assert {
        "canvas.submit_assignment",
        "google_workspace.send_email",
        "google_workspace.create_event",
    } <= marked  # precondition: the writes were built
    assert {"reminders.create", "memory.remember", "watch.create", "watch.delete"} <= {
        t.name for t in tools
    }  # precondition: so were built-in writes

    writes = (ActionCategory.WRITE, ActionCategory.DELETE)
    for tool in tools:
        resolved = resolve_tool(tool.name)
        assert resolved is not None, tool.name
        is_connector = resolved.connector_type not in BUILTIN_CONNECTOR_TYPES
        expected = is_connector and resolved.spec.category in writes
        assert tool.connector_write is expected, tool.name
    # And the mark reaches the dicts the context manager selects from.
    assert {t["name"] for t in _schema(tools) if t["connector_write"]} == marked


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_the_offer_does_not_depend_on_the_order_the_tools_were_built_in():
    """The array sits in the cached prompt prefix, so the same tool set and
    connectors must give byte-identical output however they were listed."""
    schema = _schema(build_tools(_canvas_and_google(write_scopes=True)) + _future_tools())
    active = sorted({t["connector_type"] for t in schema})
    assert len(schema) > OFFERED_TOOL_CAP  # precondition: this is a trim
    first = select_offered_tools(schema, active)

    rng = random.Random(1234)
    for _ in range(25):
        shuffled_tools, shuffled_active = list(schema), list(active)
        rng.shuffle(shuffled_tools)
        rng.shuffle(shuffled_active)
        again = select_offered_tools(shuffled_tools, shuffled_active)
        assert again == first
        assert [t["name"] for t in again] == [t["name"] for t in first]


# ---------------------------------------------------------------------------
# Fairness and the priority list
# ---------------------------------------------------------------------------


def _tool(name: str, connector_type: str | None = None, *, write: bool = False) -> dict[str, Any]:
    """A tool dict as ``AgentRuntime._tools_to_schema`` makes it; ``write``
    is the ``connector_write`` mark build_tools gives a connector write."""
    family = connector_type or name.partition(".")[0]
    return {
        "name": name,
        "description": "d",
        "parameters": {},
        "connector_type": family,
        "connector_write": write,
    }


def test_every_active_family_is_represented_and_the_rest_is_shared_evenly():
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    sizes = {"alpha": 1, "bravo": 2, "charlie": 3, "delta": 5, "echo": 8, "foxtrot": 13}
    tools = core + [_tool(f"{f}.t{i:02d}") for f, n in sizes.items() for i in range(n)]
    # Two MCP servers are two families, however many tools the first has.
    tools += [_tool(f"mcp.big.t{i:02d}", "mcp") for i in range(12)] + [
        _tool("mcp.small.t00", "mcp")
    ]
    active = [*sizes, "web", "reminders", "mcp"]

    offered = select_offered_tools(tools, active)

    assert len(offered) == OFFERED_TOOL_CAP
    assert CORE_TOOL_NAMES <= {t["name"] for t in offered}
    totals = {**sizes, "mcp.big": 12, "mcp.small": 1}
    counts = dict.fromkeys(totals, 0)
    for t in offered:
        if t["name"] not in CORE_TOOL_NAMES:
            counts[_family(t["name"])] += 1
    assert all(counts.values()), counts
    # Round-robin: a family that lost tools holds at most one fewer than
    # any other family.
    for family, count in counts.items():
        if count < totals[family]:
            assert all(other <= count + 1 for other in counts.values()), counts


def test_the_priority_list_picks_each_familys_tool_before_its_name_order_does():
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    rest = [
        _tool("reminders.cancel"),
        _tool("reminders.create"),
        _tool("reminders.list"),
        _tool("web.a_sorts_before_screenshot", "web"),
        _tool("web.screenshot"),
        _tool("canvas.get_assignments"),
        _tool("canvas.get_calendar_events"),
        _tool("canvas.get_courses"),
        # A second Canvas account is its own family and follows the same list.
        _tool("canvas__1f2e3d4c.get_assignments", "canvas"),
        _tool("canvas__1f2e3d4c.get_courses", "canvas"),
    ]
    tools = core + rest
    active = ["reminders", "web", "canvas"]

    one_each = select_offered_tools(tools, active, max_tools=len(core) + 4)
    assert {t["name"] for t in one_each} - CORE_TOOL_NAMES == {
        "reminders.create",
        "web.screenshot",
        "canvas.get_courses",
        "canvas__1f2e3d4c.get_courses",
    }

    # A second round gives each family its second tool, except that
    # reminders.create brings its undo (reminders.cancel), which takes the
    # latest pick's slot (web's second tool) rather than go missing.
    two_each = select_offered_tools(tools, active, max_tools=len(core) + 8)
    assert {t["name"] for t in two_each} - {t["name"] for t in one_each} == {
        "reminders.list",
        "reminders.cancel",
        "canvas.get_assignments",
        "canvas__1f2e3d4c.get_assignments",
    }


@pytest.mark.parametrize(
    ("family", "ranked"),
    [
        ("web", ["web.screenshot", "web.research"]),
        (
            "canvas",
            [
                "canvas.get_upcoming",
                "canvas.get_courses",
                "canvas.submit_assignment",
                "canvas.grade_whatif",
                "canvas.get_assignments",
                "canvas.get_grades",
            ],
        ),
        ("watch", ["watch.create", "watch.list", "watch.delete"]),
    ],
)
def test_the_new_tools_take_their_place_in_the_family_order(family: str, ranked: list[str]):
    """One slot more at a time, each family gives up its tools in the
    priority list's order, ahead of any unlisted tool of the same family."""
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    unlisted = [_tool(f"{family}.a_unlisted", family)]
    tools = core + unlisted + [_tool(n) for n in reversed(ranked)]

    for count in range(1, len(ranked) + 1):
        offered = select_offered_tools(
            tools, [family, "web", "reminders"], max_tools=len(core) + count
        )
        assert {t["name"] for t in offered} - CORE_TOOL_NAMES == set(ranked[:count])


def test_the_priority_list_names_real_tools_once_each():
    """Other families extend the list; a typo there would silently rank
    nothing, so every entry must resolve to a catalog tool."""
    assert len(TOOL_PRIORITY) == len(set(TOOL_PRIORITY))
    for name in TOOL_PRIORITY:
        assert resolve_tool(name) is not None, name
        # A core tool is always offered; ranking it would do nothing.
        assert name not in CORE_TOOL_NAMES, name


def test_core_tools_survive_even_when_families_outnumber_the_slots():
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    families = [f"family_{i:02d}" for i in range(30)]
    tools = core + [_tool(f"{f}.only") for f in families]

    offered = select_offered_tools(tools, [*families, "web", "reminders"])

    assert len(offered) == OFFERED_TOOL_CAP
    assert CORE_TOOL_NAMES <= {t["name"] for t in offered}
    # With more families than slots the cut is still deterministic: the
    # families that sort first by name keep their tool.
    kept = sorted(_family(t["name"]) for t in offered if t["name"] not in CORE_TOOL_NAMES)
    assert kept == families[: OFFERED_TOOL_CAP - len(CORE_TOOL_NAMES)]


def _names(offered: list[dict[str, Any]]) -> set[str]:
    return {t["name"] for t in offered} - CORE_TOOL_NAMES


def test_an_undo_companion_takes_a_repeat_first_then_the_latest_pick():
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    tools = core + [
        _tool("reminders.create"),
        _tool("reminders.list"),
        _tool("reminders.cancel"),
        _tool("web.screenshot"),
        _tool("web.research"),
        _tool("alpha.one"),
        _tool("alpha.two"),
        _tool("bravo.one"),
        _tool("bravo.two"),
    ]
    active = ["reminders", "web", "alpha", "bravo"]

    # Eight slots: four leads, then alpha.two, bravo.two, reminders.list
    # and web.research. reminders.cancel takes web.research's slot: search
    # plus fetch_page, both offered, do what it does.
    assert _names(select_offered_tools(tools, active, max_tools=len(core) + 8)) == {
        "alpha.one",
        "alpha.two",
        "bravo.one",
        "bravo.two",
        "reminders.create",
        "reminders.list",
        "reminders.cancel",
        "web.screenshot",
    }
    # Seven: no repeat is offered, so the latest pick that is neither a
    # family's first nor a companion (bravo.two) makes room.
    assert _names(select_offered_tools(tools, active, max_tools=len(core) + 7)) == {
        "alpha.one",
        "alpha.two",
        "bravo.one",
        "reminders.create",
        "reminders.list",
        "reminders.cancel",
        "web.screenshot",
    }
    # Four: only leads, which are never taken, so the undo cannot be added.
    assert _names(select_offered_tools(tools, active, max_tools=len(core) + 4)) == {
        "alpha.one",
        "bravo.one",
        "reminders.create",
        "web.screenshot",
    }


def test_a_granted_write_takes_only_a_repeat_and_follows_a_second_account():
    """A second Google account's create_event is still a granted write. It
    takes web.research's slot (web.search plus web.fetch_page do what it
    does), but never a tool nothing else repeats."""
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    google = [
        _tool(f"google_workspace__9a8b.{action}", "google_workspace", write=write)
        for action, write in (
            ("get_messages", False),
            ("get_events", False),
            ("send_email", True),
            ("create_event", True),
        )
    ]
    alpha = [_tool("alpha.one"), _tool("alpha.two"), _tool("alpha.three")]
    web = [_tool("web.screenshot"), _tool("web.research")]
    active = ["google_workspace", "web", "alpha"]
    create = "google_workspace__9a8b.create_event"

    # Eight slots. Rounds: alpha.one, get_messages, web.screenshot; then
    # alpha.two, get_events, web.research; then alpha.three, send_email.
    offered = _names(
        select_offered_tools(core + google + alpha + web, active, max_tools=len(core) + 8)
    )
    assert create in offered and "web.research" not in offered
    assert {"alpha.two", "alpha.three", "google_workspace__9a8b.send_email"} <= offered

    # Without web.research nothing offered is a repeat, so create_event
    # stays out rather than take another family's tool.
    offered = _names(
        select_offered_tools(core + google + alpha + web[:1], active, max_tools=len(core) + 7)
    )
    assert create not in offered and {"alpha.two", "alpha.three"} <= offered


@pytest.mark.parametrize("marked", [True, False], ids=["marked", "unmarked"])
def test_a_new_connectors_write_is_kept_by_its_mark_alone(marked: bool):
    """A connector nobody listed anywhere (the connectors spec's next ones:
    one file plus one registry line). Six slots: alpha.one, get_page,
    web.screenshot, then alpha.two, notion.search, web.research, which
    leaves update_page out by rank. Marked as a connector write, it takes
    web.research's slot (a repeat); unmarked, it is just a third tool."""
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    notion = [
        _tool("notion.get_page"),
        _tool("notion.search"),
        _tool("notion.update_page", write=marked),
    ]
    rest = [_tool("alpha.one"), _tool("alpha.two"), _tool("web.screenshot"), _tool("web.research")]

    offered = _names(
        select_offered_tools(
            core + notion + rest, ["notion", "alpha", "web"], max_tools=len(core) + 6
        )
    )

    assert {
        "alpha.one",
        "alpha.two",
        "notion.get_page",
        "notion.search",
        "web.screenshot",
    } <= offered
    if marked:
        assert "notion.update_page" in offered and "web.research" not in offered
    else:
        assert "notion.update_page" not in offered and "web.research" in offered


def test_browser_read_leads_its_family_ahead_of_tools_that_sort_first():
    """browser.read returns the refs and the pages every other browser tool
    acts on. feat/purchases adds browser.act and browser.checkout, which sort
    ahead of it by name: with one slot, or two, the family must still be
    usable."""
    core = [_tool(n) for n in sorted(CORE_TOOL_NAMES)]
    browser = [_tool("browser.act"), _tool("browser.checkout"), _tool("browser.read")]

    one = select_offered_tools(
        core + browser, ["browser", "web", "reminders"], max_tools=len(core) + 1
    )
    assert _names(one) == {"browser.read"}
    two = select_offered_tools(
        core + browser, ["browser", "web", "reminders"], max_tools=len(core) + 2
    )
    assert "browser.read" in _names(two)
