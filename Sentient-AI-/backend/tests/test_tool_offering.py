"""Tests for offering tools at scale (connectors spec 4.5): the bounded, stable
selection of offered tools (core, loaded, starters, the rest; cap 24), the
tools.find built-in the runtime answers from the turn's full tool list, the
conversation's persisted loaded list, and the result budgets for long
connector reads.

Why it exists: once several services are connected, most tools cannot be
offered at once. The model must still reach every tool the user can use, and
nothing else, while the offered array stays byte-identical between turns so
the provider's prompt cache keeps matching.

Covers services/agent/context_manager.py (select_offered_tools, find_tools,
merge_loaded), services/agent/runtime.py (tools.find in the tool loop,
LoadedTools, result_char_budget), services/agent/tool_registry.py (the tools
family, starters, the executor refusal), services/capabilities, the agent
routes' persistence of Conversation.loaded_tools, and migration 0013.
"""

from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import event, select

from core.config import settings
from services import capabilities as capability_registry
from services.agent import context_manager
from services.agent.approvals import InMemoryApprovalStore
from services.agent.context_manager import (
    MAX_FIND_RESULTS,
    MAX_LOADED_TOOLS,
    MAX_OFFERED_TOOLS,
    find_tools,
    merge_loaded,
    select_offered_tools,
)
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    SECURITY_SYSTEM_PROMPT,
    AgentRuntime,
    LoadedTools,
    Tool,
    canonical_tool_name,
    result_char_budget,
)
from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    RUNTIME_BUILTIN_TYPES,
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from tests.conftest import auth_headers, make_user, use_provider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool(name: str, *, starter: bool = False, description: str = "", connector: str = "") -> dict:
    return {
        "name": name,
        "description": description or f"Does {name}",
        "parameters": {"type": "object", "properties": {}},
        "connector_type": connector or name.partition(".")[0],
        "starter": starter,
    }


def _names(tools: list[dict]) -> list[str]:
    return [t["name"] for t in tools]


CORE = ["web.search", "web.fetch_page", "reminders.now", "tools.find"]


def _big_set(rest: int = 30) -> list[dict]:
    """Core tools, two starters and *rest* plain connector tools, in a
    build order that interleaves them."""
    tools = [_tool("web.search"), _tool("web.fetch_page")]
    tools += [_tool(f"acme.op_{i:02d}") for i in range(rest)]
    tools += [
        _tool("reminders.now"),
        _tool("acme.list_things", starter=True),
        _tool("acme.get_thing", starter=True),
        _tool("tools.find"),
    ]
    return tools


class AllowAll:
    """Permission engine that approves every call (runtime mechanics only)."""

    async def check(self, user_id, tool_name, arguments):
        return "approved"

    async def get_block_reason(self, user_id, tool_name, arguments):
        return ""

    async def get_policy_name(self, user_id, tool_name):
        return ""


class RecordingExecutor:
    def __init__(self):
        self.calls: list[str] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append(tool_name)
        return {"ok": True, "items": [f"ran {tool_name}"]}


class RecordingAudit:
    def __init__(self):
        self.entries: list[dict] = []

    async def log(self, entry):
        self.entries.append(entry)


class ScriptedProvider:
    """Replays scripted responses; records the tool names offered per call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.offered: list[list[str]] = []
        self.raw_tools: list[Any] = []

    async def complete(self, messages, tools=None, **kwargs):
        self.offered.append([t["name"] for t in tools or []])
        self.raw_tools.append(tools)
        if self._responses:
            return self._responses.pop(0)
        return LLMResponse(content="done")

    async def stream(self, messages, tools=None):  # pragma: no cover - unused
        yield "done"


def _call(name: str, **arguments) -> LLMResponse:
    return LLMResponse(
        content="",
        tool_calls=[ToolCall(id=f"tc-{uuid.uuid4().hex[:6]}", name=name, arguments=arguments)],
    )


def _runtime(provider, *, permissions=None, executor=None, audit=None) -> AgentRuntime:
    runtime = AgentRuntime(
        config=settings,
        permission_engine=permissions or AllowAll(),
        tool_executor=executor or RecordingExecutor(),
        audit_service=audit or RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(runtime, provider)
    return runtime


def _runtime_tools(rest: int = 30) -> list[Tool]:
    """Runtime Tool objects: the core built-ins, two starters, *rest*
    connector tools with distinct descriptions."""
    tools = [
        Tool("web.search", "Search the public web", {}, "web"),
        Tool("web.fetch_page", "Fetch a public web page", {}, "web"),
        Tool("reminders.now", "Current date and time", {}, "reminders"),
        Tool("tools.find", "Find tools", {}, "tools"),
        Tool("acme.list_things", "List things", {}, "acme", starter=True),
    ]
    tools += [
        Tool(f"acme.widget_{i:02d}", f"Operate acme widget number {i}", {}, "acme")
        for i in range(rest)
    ]
    return tools


# ---------------------------------------------------------------------------
# Selection: core, loaded, starters, the rest
# ---------------------------------------------------------------------------


def test_a_set_within_the_cap_is_offered_as_built():
    tools = _big_set(rest=5)
    assert select_offered_tools(tools, ["acme"]) is tools
    # Loading changes nothing while everything fits: no cache churn.
    assert select_offered_tools(tools, ["acme"], loaded=["acme.op_03"]) is tools


def test_over_the_cap_core_then_starters_then_the_rest_in_build_order():
    tools = _big_set(rest=30)
    offered = select_offered_tools(tools, ["acme"])
    names = _names(offered)
    assert len(offered) == MAX_OFFERED_TOOLS
    assert set(CORE) <= set(names)
    assert {"acme.list_things", "acme.get_thing"} <= set(names)
    # The remaining 18 slots go to the rest in build order.
    rest = [n for n in names if n.startswith("acme.op_")]
    assert rest == [f"acme.op_{i:02d}" for i in range(18)]
    # The result keeps the build order of the chosen tools.
    positions = [_names(tools).index(n) for n in names]
    assert positions == sorted(positions)


def test_loaded_tools_outrank_starters_and_the_rest():
    tools = _big_set(rest=30)
    offered = _names(select_offered_tools(tools, ["acme"], loaded=["acme.op_29", "acme.op_25"]))
    assert {"acme.op_29", "acme.op_25"} <= set(offered)
    assert "acme.op_17" not in offered  # pushed out by the two loaded tools
    assert "acme.op_15" in offered


def test_over_the_cap_the_most_recently_loaded_are_kept():
    tools = _big_set(rest=30)
    loaded = [f"acme.op_{i:02d}" for i in range(30)]  # oldest first
    offered = _names(select_offered_tools(tools, ["acme"], max_tools=10, loaded=loaded))
    assert set(CORE) <= set(offered)
    # 10 slots: 4 core, then the 6 newest loaded names; no starters left.
    assert [n for n in offered if n.startswith("acme.op_")] == [
        f"acme.op_{i:02d}" for i in range(24, 30)
    ]
    assert "acme.list_things" not in offered


def test_loaded_names_that_are_no_longer_available_are_skipped():
    tools = _big_set(rest=30)
    with_stale = select_offered_tools(
        tools, ["acme"], loaded=["gone.tool", "acme.op_29", "github__0badf00d.list_issues"]
    )
    without_stale = select_offered_tools(tools, ["acme"], loaded=["acme.op_29"])
    assert with_stale == without_stale
    assert "gone.tool" not in _names(with_stale)


def test_selection_is_byte_identical_across_calls():
    tools = _big_set(rest=40)
    loaded = ["acme.op_33", "acme.op_07"]
    first = select_offered_tools(tools, ["acme"], loaded=loaded)
    second = select_offered_tools(list(tools), ["acme"], loaded=list(loaded))
    assert json.dumps(first) == json.dumps(second)


def test_starters_and_the_rest_prefer_active_connectors():
    tools = [_tool(f"dormant.op_{i}", starter=True) for i in range(5)]
    tools += [_tool(f"live.op_{i}", starter=True) for i in range(5)]
    offered = _names(select_offered_tools(tools, ["live"], max_tools=5))
    assert offered == [f"live.op_{i}" for i in range(5)]


def test_the_core_set_is_extensible(monkeypatch):
    tools = _big_set(rest=30) + [_tool("skills.read")]
    assert "skills.read" not in _names(select_offered_tools(tools, ["acme"]))
    assert "skills.read" in _names(
        select_offered_tools(tools, ["acme"], core=[*CORE, "skills.read"])
    )
    monkeypatch.setattr(context_manager, "_core_tool_names", set(context_manager.CORE_TOOL_NAMES))
    context_manager.register_core_tools("skills.read")
    assert "skills.read" in context_manager.core_tool_names()
    assert "skills.read" in _names(select_offered_tools(tools, ["acme"]))


def test_prepare_context_offers_loaded_tools():
    manager = context_manager.ContextManager(model="claude-sonnet-4-20250514")
    tools = _big_set(rest=30)
    _, offered = manager.prepare_context(
        [{"role": "user", "content": "hi"}],
        tools,
        active_connectors=["acme"],
        loaded=["acme.op_29"],
    )
    assert "acme.op_29" in _names(offered)


# ---------------------------------------------------------------------------
# build_tools: starters and the tools family
# ---------------------------------------------------------------------------


ALL_CAPABILITIES = frozenset(cap.key for cap in capability_registry.REGISTRY)

# Built-ins a prompt playbook relies on: starters whenever they are offered.
PLAYBOOK_BUILTINS = (
    "web.screenshot",
    "reminders.create",
    "reminders.list",
    "reminders.cancel",
    "system.capabilities",
    "system.install_capability",
    "browser.read",
    "desktop.screenshot",
    "desktop.observe",
    "desktop.act",
)


def test_build_tools_marks_starters():
    from services.agent.tool_registry import CONNECTOR_CATALOG

    tools = {
        t.name: t
        for t in build_tools([ConnectorSpec("canvas")], enabled_capabilities=ALL_CAPABILITIES)
    }
    missing = [name for name in PLAYBOOK_BUILTINS if name not in tools]
    assert not missing, missing
    for name in PLAYBOOK_BUILTINS:
        assert tools[name].starter, name
    assert not tools["web.search"].starter  # core, not a starter
    assert not tools["tools.find"].starter

    connector_starters = 0
    for spec in CONNECTOR_CATALOG["canvas"]:
        name = f"canvas.{spec.action}"
        assert name in tools, name  # an unscoped spec offers every canvas action
        assert tools[name].starter is spec.starter, name
        connector_starters += spec.starter
    assert connector_starters >= 1


@pytest.mark.asyncio
async def test_a_large_connector_does_not_push_out_enabled_builtins():
    """GitHub alone is over the cap: the browser, desktop and installer
    tools the owner switched on must still be offered."""
    from services.agent.tool_registry import CONNECTOR_CATALOG

    tools = build_tools([ConnectorSpec("github")], enabled_capabilities=ALL_CAPABILITIES)
    assert len(tools) > MAX_OFFERED_TOOLS
    provider = ScriptedProvider([LLMResponse(content="ok")])
    await _runtime(provider).chat(
        messages=[{"role": "user", "content": "hi"}], tools=tools, user_id="u1"
    )
    offered = provider.offered[0]
    assert len(offered) == MAX_OFFERED_TOOLS
    assert set(CORE) <= set(offered)
    assert set(PLAYBOOK_BUILTINS) <= set(offered)
    github_starters = {f"github.{s.action}" for s in CONNECTOR_CATALOG["github"] if s.starter}
    assert github_starters and github_starters <= set(offered)


def test_disabled_builtins_leave_their_slots_to_connectors():
    tools = build_tools([ConnectorSpec("github")], enabled_capabilities=frozenset())
    names = {t.name for t in tools}
    assert not names & {"browser.read", "desktop.act", "desktop.observe", "desktop.screenshot"}


def test_tools_find_is_offered_to_everyone_as_an_automatic_read():
    for enabled in (None, frozenset()):
        tools = {t.name: t for t in build_tools([], enabled_capabilities=enabled)}
        assert tools["tools.find"].permission_tier == "auto"
        assert tools["tools.find"].connector_type == "tools"
        assert tools["tools.find"].parameters["required"] == ["query"]


def test_the_tools_family_is_a_runtime_builtin():
    assert "tools" in BUILTIN_CONNECTOR_TYPES
    assert "tools" in RUNTIME_BUILTIN_TYPES
    assert "tools" not in ConnectorToolExecutor()._builtins


def test_tools_find_is_always_on():
    assert "tools.find" in capability_registry.ALWAYS_ON_TOOLS
    assert capability_registry.capability_for_tool("tools.find") is None


def test_only_read_is_allowed_for_the_tools_family():
    engine = PermissionEngine()
    read = engine.check_permission("tools", "find", ActionCategory.READ)
    assert read.allowed and not read.requires_approval
    for category in (ActionCategory.WRITE, ActionCategory.DELETE, ActionCategory.EXECUTE):
        assert engine.check_permission("tools", "x", category).tier == PermissionTier.HARD_BLOCKED


@pytest.mark.asyncio
async def test_the_adapter_approves_tools_find_even_with_every_capability_off():
    async def everything_off():
        return {}

    for gate in (None, everything_off):
        adapter = RuntimePermissionAdapter(capability_gate=gate)
        assert await adapter.check("u1", "tools.find", {"query": "x"}) == "approved"
    # A slugged spelling of a built-in never resolves.
    assert await RuntimePermissionAdapter().check("u1", "tools__0badf00d.find", {}) == "blocked"


@pytest.mark.asyncio
async def test_the_executor_refuses_tools_find():
    result = await ConnectorToolExecutor().execute("tools.find", {"query": "email"}, "u1")
    assert result["ok"] is False
    assert "agent runtime" in result["error"]


def test_the_prompt_points_at_tools_find():
    assert "tools.find" in SECURITY_SYSTEM_PROMPT
    tool_use = SECURITY_SYSTEM_PROMPT.split("<tool_use>")[1].split("</tool_use>")[0]
    bullet = next(b for b in tool_use.split("\n- ") if "tools.find" in b)
    assert "connected service" in bullet
    assert chr(0x2014) not in bullet and chr(0x2013) not in bullet


# ---------------------------------------------------------------------------
# find_tools and merge_loaded
# ---------------------------------------------------------------------------


def test_find_ranks_name_matches_above_description_matches_and_ties_by_name():
    tools = [
        _tool("acme.archive", description="Store an email for later"),
        _tool("acme.send_email", description="Send a message"),
        _tool("acme.read_email", description="Read one message"),
        _tool("acme.unrelated", description="Nothing to see"),
    ]
    found = _names(find_tools(tools, "email"))
    assert found == ["acme.read_email", "acme.send_email", "acme.archive"]


def test_find_matches_word_forms_and_ignores_filler_words():
    tools = [_tool("gmail.search_emails", description="Search the inbox")]
    assert _names(find_tools(tools, "find my email")) == ["gmail.search_emails"]
    assert find_tools(tools, "the of to") == []


def test_find_filters_by_connector_type_or_namespace():
    tools = [
        _tool("github.list_issues", description="List issues"),
        _tool("github__1a2b3c4d.list_issues", description="List issues", connector="github"),
        _tool("notion.list_issues", description="List issues"),
    ]
    assert _names(find_tools(tools, "issues", "github")) == [
        "github.list_issues",
        "github__1a2b3c4d.list_issues",
    ]
    assert _names(find_tools(tools, "issues", "github__1a2b3c4d")) == [
        "github__1a2b3c4d.list_issues"
    ]
    assert _names(find_tools(tools, "issues", "NOTION")) == ["notion.list_issues"]
    assert find_tools(tools, "issues", "slack") == []


def test_find_returns_at_most_eight():
    tools = [_tool(f"acme.widget_{i:02d}", description="widget") for i in range(20)]
    found = find_tools(tools, "widget")
    assert len(found) == MAX_FIND_RESULTS == 8
    assert _names(found) == [f"acme.widget_{i:02d}" for i in range(8)]


def test_find_with_only_a_connector_lists_that_connector():
    tools = [_tool("acme.b"), _tool("acme.a"), _tool("other.c")]
    assert _names(find_tools(tools, "", "acme")) == ["acme.a", "acme.b"]
    assert find_tools(tools, "") == []


def test_find_never_returns_itself():
    tools = [_tool("tools.find", description="Find tools"), _tool("acme.find_things")]
    assert _names(find_tools(tools, "find")) == ["acme.find_things"]


def test_merge_loaded_dedupes_refreshes_and_caps():
    available = [f"t.{i}" for i in range(40)]
    merged = merge_loaded(["t.1", "t.2", "t.3"], ["t.2", "t.9"], available)
    # Found names move to the newest end, the best match newest of all.
    assert merged == ["t.1", "t.3", "t.9", "t.2"]
    old = [f"t.{i}" for i in range(MAX_LOADED_TOOLS)]
    capped = merge_loaded(old, ["t.30", "t.31"], available)
    assert len(capped) == MAX_LOADED_TOOLS
    assert capped[-2:] == ["t.31", "t.30"]
    assert "t.0" not in capped and "t.1" not in capped  # the oldest dropped


def test_merge_loaded_drops_names_no_longer_available():
    assert merge_loaded(["gone.x", "t.1"], ["t.2"], ["t.1", "t.2"]) == ["t.1", "t.2"]
    assert merge_loaded(["t.1"], ["not.usable"], ["t.1"]) == ["t.1"]


def test_loaded_tools_reads_only_lists_of_names():
    assert LoadedTools.from_stored(None).names == []
    assert LoadedTools.from_stored({"a": 1}).names == []
    assert LoadedTools.from_stored(["a.b", 3, "", None, "c.d"]).names == ["a.b", "c.d"]


# ---------------------------------------------------------------------------
# tools.find inside a runtime turn
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_found_tool_is_offered_in_the_next_round_of_the_same_turn():
    provider = ScriptedProvider(
        [
            _call("tools.find", query="widget 27", connector="acme"),
            _call("acme.widget_27"),
            LLMResponse(content="All done."),
        ]
    )
    executor = RecordingExecutor()
    audit = RecordingAudit()
    runtime = _runtime(provider, executor=executor, audit=audit)
    loaded = LoadedTools()

    response = await runtime.chat(
        messages=[{"role": "user", "content": "use widget 27"}],
        tools=_runtime_tools(),
        user_id="u1",
        loaded_tools=loaded,
    )

    assert response.content == "All done."
    assert "acme.widget_27" not in provider.offered[0]
    assert "acme.widget_27" in provider.offered[1]
    assert len(provider.offered[1]) == MAX_OFFERED_TOOLS
    # The runtime answered tools.find; only the found tool reached the executor.
    assert executor.calls == ["acme.widget_27"]
    assert loaded.changed is True
    assert loaded.names[-1] == "acme.widget_27"  # the best match is the newest
    assert len(loaded.names) == MAX_FIND_RESULTS
    find_record = response.tool_calls[0]
    assert find_record["name"] == "tools.find"
    assert find_record["result"]["tools"][0] == {
        "name": "acme.widget_27",
        "description": "Operate acme widget number 27",
    }
    assert find_record["result"]["loaded"][0] == "acme.widget_27"
    # Audited like any other call: intent row, then outcome row.
    events = [(e["event"], e.get("tool")) for e in audit.entries]
    assert ("tool_executing", "tools.find") in events
    assert ("tool_executed", "tools.find") in events


@pytest.mark.asyncio
async def test_tools_find_only_returns_tools_of_this_turn():
    provider = ScriptedProvider(
        [_call("tools.find", query="merge pull request"), LLMResponse(content="ok")]
    )
    runtime = _runtime(provider)
    loaded = LoadedTools(["acme.widget_01"])
    response = await runtime.chat(
        messages=[{"role": "user", "content": "merge it"}],
        tools=_runtime_tools(),
        user_id="u1",
        loaded_tools=loaded,
    )
    result = response.tool_calls[0]["result"]
    assert result["tools"] == [] and result["loaded"] == []
    assert "hint" in result
    assert loaded.changed is False and loaded.names == ["acme.widget_01"]
    # Nothing changed, so the second round offers the same array.
    assert provider.raw_tools[0] == provider.raw_tools[1]


@pytest.mark.asyncio
async def test_tools_find_rejects_a_missing_query_without_loading():
    provider = ScriptedProvider([_call("tools.find"), LLMResponse(content="ok")])
    runtime = _runtime(provider)
    loaded = LoadedTools()
    response = await runtime.chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=_runtime_tools(),
        user_id="u1",
        loaded_tools=loaded,
    )
    assert response.tool_calls[0]["result"]["ok"] is False
    assert loaded.changed is False and loaded.names == []


@pytest.mark.asyncio
async def test_real_permissions_let_tools_find_run_and_find_real_tools():
    tools = build_tools([ConnectorSpec("canvas")])
    provider = ScriptedProvider(
        [_call("tools.find", query="reminder list"), LLMResponse(content="ok")]
    )
    executor = RecordingExecutor()
    runtime = _runtime(provider, permissions=RuntimePermissionAdapter(), executor=executor)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "what reminders do I have"}],
        tools=tools,
        user_id="u1",
    )
    assert not response.blocked_actions
    found = [t["name"] for t in response.tool_calls[0]["result"]["tools"]]
    assert found[0] == "reminders.list"
    assert set(found) <= {t.name for t in tools}
    assert executor.calls == []


@pytest.mark.asyncio
async def test_a_turn_without_tools_find_leaves_the_loaded_list_alone():
    provider = ScriptedProvider([LLMResponse(content="hello")])
    runtime = _runtime(provider)
    loaded = LoadedTools(["acme.widget_29"])
    await runtime.chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=_runtime_tools(),
        user_id="u1",
        loaded_tools=loaded,
    )
    assert loaded.changed is False
    assert "acme.widget_29" in provider.offered[0]


# ---------------------------------------------------------------------------
# Result budgets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "github.get_pr_diff",
        "github.get_failed_logs",
        "notion.get_page",
        "google_workspace.get_file_text",
        "microsoft.get_file_text",
    ],
)
def test_long_reads_have_a_budget_under_either_spelling(name):
    budget = result_char_budget(name, 2000)
    assert budget > 2000
    namespace, _, action = name.partition(".")
    assert result_char_budget(f"{namespace}__1a2b3c4d.{action}", 2000) == budget


# Text as escape-heavy as real files get: each 11-character line holds two
# quotes and a newline, so its JSON is about 27% longer than the text.
_ESCAPE_HEAVY_LINE = 'print("x")\n'


def _escape_heavy(chars: int) -> str:
    return (_ESCAPE_HEAVY_LINE * (chars // len(_ESCAPE_HEAVY_LINE) + 1))[:chars]


def _envelope(connector: str, action: str, result: dict) -> dict:
    """The executor's success envelope around an action result."""
    return {
        "ok": True,
        "connector": connector,
        "action": action,
        "result": result,
        "sanitized": False,
        "execution_time_ms": 1234,
    }


def _largest_long_reads() -> dict[str, dict]:
    """The largest result each long-read action returns, built with the
    connectors' own caps and shaping helpers."""
    from services.connectors.github_api.common import fit_head, json_len
    from services.connectors.github_api.pulls import _DIFF_HINT, MAX_DIFF_CHARS
    from services.connectors.google_api.client import text_window
    from services.connectors.google_api.drive import FILE_TEXT_CHARS
    from services.connectors.microsoft_api.common import capped_text
    from services.connectors.microsoft_api.drive import MAX_FILE_CHARS
    from services.connectors.notion_api import reads as notion_reads

    hint = _DIFF_HINT.format(lines=99999)
    overhead = json_len({"number": 123456, "diff": "", "truncated": True, "hint": hint})
    diff, _ = fit_head(_escape_heavy(4 * MAX_DIFF_CHARS), MAX_DIFF_CHARS - overhead)
    github = {"number": 123456, "diff": diff, "truncated": True, "hint": hint}

    google = {
        "id": "1" * 44,
        "name": "n" * 300,
        "mime_type": "text/plain",
        **text_window(_escape_heavy(3 * FILE_TEXT_CHARS), 0, FILE_TEXT_CHARS, action="get_file_text"),
    }

    microsoft = {
        "id": "01ABCDEF" * 5,
        "name": "n" * 255,
        "mime_type": "text/plain",
        "size": 999999,
        "web_url": "https://contoso-my.sharepoint.com/" + "p" * 200,
        **capped_text(_escape_heavy(2 * MAX_FILE_CHARS), MAX_FILE_CHARS, hint="x" * 80),
    }

    content_chars = notion_reads._PAGE_MARKDOWN_CHARS
    block = _escape_heavy(1000)
    notion = {
        "id": str(uuid.uuid4()),
        "title": "t" * 300,
        "url": "https://www.notion.so/" + "p" * 60,
        "last_edited": "2026-09-25T10:00:00.000Z",
        "parent": {"type": "page_id", "id": str(uuid.uuid4())},
        # A page with a handful of filled properties, each at its cap.
        "properties": {
            f"Property {i}": _escape_heavy(notion_reads._PAGE_PROPERTY_CHARS // 4)
            for i in range(4)
        },
        "content": [block] * (content_chars // len(block)),
        "truncated": True,
        "hint": "h" * 200,
        "more": [
            {"block_id": str(uuid.uuid4()), "start_cursor": str(uuid.uuid4())}
            for _ in range(notion_reads._MAX_MORE_ENTRIES)
        ],
    }
    return {
        "github.get_pr_diff": _envelope("github", "get_pr_diff", github),
        "google_workspace.get_file_text": _envelope("google_workspace", "get_file_text", google),
        "microsoft.get_file_text": _envelope("microsoft", "get_file_text", microsoft),
        "notion.get_page": _envelope("notion", "get_page", notion),
    }


@pytest.mark.parametrize("slugged", [False, True])
def test_the_largest_long_reads_reach_the_model_whole(slugged):
    provider = ScriptedProvider([])
    runtime = _runtime(provider)
    for name, result in _largest_long_reads().items():
        if slugged:
            namespace, _, action = name.partition(".")
            name = f"{namespace}__1a2b3c4d.{action}"
        messages = runtime._follow_up_messages(
            [{"role": "user", "content": "read it"}],
            LLMResponse(content=""),
            [{"name": name, "tool_call_id": "tc-1", "result": result}],
            provider,
        )
        shown = messages[-1]["content"]
        assert "chars truncated" not in shown, name
        # The connector's own paging fields arrive intact.
        body = result["result"]
        text = body.get("diff") or body.get("text") or body["content"][-1]
        assert json.dumps(text, ensure_ascii=False)[1:-1][-200:] in shown, name


def test_canonical_tool_name_strips_only_a_well_formed_slug():
    assert canonical_tool_name("google_workspace__0badf00d.get_file_text") == (
        "google_workspace.get_file_text"
    )
    for name in (
        "github__1A2B3C4D.get_pr_diff",
        "github__1a2b3c4.get_pr_diff",
        "github.get_pr_diff",
    ):
        assert canonical_tool_name(name) == name
    assert result_char_budget("github__1A2B3C4D.get_pr_diff", 2000) == 2000
    assert result_char_budget("tools.find", 2000) > 2000
    assert result_char_budget("canvas__1a2b3c4d.get_courses", 2000) == 2000


# ---------------------------------------------------------------------------
# Persistence through the real routes
# ---------------------------------------------------------------------------


@contextmanager
def _count_statements(session_factory):
    engine = session_factory.kw["bind"]
    statements: list[str] = []

    def _record(_conn, _cursor, statement, *_args):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _record)
    try:
        yield statements
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _record)


def _conversation_updates(statements: list[str]) -> list[str]:
    return [s for s in statements if s.lstrip().upper().startswith("UPDATE CONVERSATIONS")]


@pytest.fixture
def wide_tool_set(monkeypatch):
    """The real route tool list plus 30 synthetic acme tools, so the offered
    array is over its cap and loading visibly changes it."""
    from api.routes import agent as agent_routes

    real = agent_routes._build_tools_and_memory

    async def wider(*args, **kwargs):
        tools, memory, permissions = await real(*args, **kwargs)
        extra = [
            Tool(f"acme.widget_{i:02d}", f"Operate acme widget number {i}", {}, "acme")
            for i in range(30)
        ]
        return tools + extra, memory, permissions

    monkeypatch.setattr(agent_routes, "_build_tools_and_memory", wider)


@pytest.fixture
def route_runtime():
    from main import app

    saved = getattr(app.state, "agent_runtime", None)

    def install(provider):
        runtime = _runtime(provider)
        app.state.agent_runtime = runtime
        return runtime

    yield install
    app.state.agent_runtime = saved


async def _stored_loaded(session_factory, conversation_id: str):
    from models.conversation import Conversation

    async with session_factory() as session:
        return (
            await session.execute(
                select(Conversation.loaded_tools).where(
                    Conversation.id == uuid.UUID(conversation_id)
                )
            )
        ).scalar_one()


@pytest.mark.asyncio
async def test_loaded_tools_persist_across_turns_with_one_update(
    client, session_factory, wide_tool_set, route_runtime
):
    _, token = await make_user(session_factory, "offering-route@example.com")
    provider = ScriptedProvider(
        [
            _call("tools.find", query="widget 27", connector="acme"),
            LLMResponse(content="Found it."),
            LLMResponse(content="Second turn."),
        ]
    )
    route_runtime(provider)
    conv = await client.post(
        "/api/agent/conversations", headers=auth_headers(token), json={"title": "t"}
    )
    conv_id = conv.json()["id"]
    url = f"/api/agent/conversations/{conv_id}/messages"

    with _count_statements(session_factory) as first:
        resp = await client.post(url, headers=auth_headers(token), json={"content": "widget 27"})
    assert resp.status_code == 201
    stored = await _stored_loaded(session_factory, conv_id)
    assert stored[-1] == "acme.widget_27" and len(stored) == MAX_FIND_RESULTS
    # The loaded list rides the updated_at UPDATE the route already issues.
    updates = _conversation_updates(first)
    assert len(updates) == 1 and "loaded_tools" in updates[0]

    with _count_statements(session_factory) as second:
        resp = await client.post(url, headers=auth_headers(token), json={"content": "again"})
    assert resp.status_code == 201
    # The next turn offers the loaded tool from its first call...
    assert "acme.widget_27" not in provider.offered[0]
    assert "acme.widget_27" in provider.offered[1]
    assert "acme.widget_27" in provider.offered[2]
    # ...and, loading nothing, writes nothing for it: same statements.
    updates = _conversation_updates(second)
    assert len(updates) == 1 and "loaded_tools" not in updates[0]
    assert len(second) == len(first)
    assert await _stored_loaded(session_factory, conv_id) == stored


@pytest.mark.asyncio
async def test_the_streaming_route_persists_loaded_tools(
    client, session_factory, wide_tool_set, route_runtime
):
    _, token = await make_user(session_factory, "offering-stream@example.com")
    provider = ScriptedProvider(
        [_call("tools.find", query="widget 11"), LLMResponse(content="Streamed.")]
    )
    route_runtime(provider)
    conv = await client.post(
        "/api/agent/conversations", headers=auth_headers(token), json={"title": "s"}
    )
    conv_id = conv.json()["id"]
    resp = await client.post(
        f"/api/agent/conversations/{conv_id}/messages/stream",
        headers=auth_headers(token),
        json={"content": "widget 11"},
    )
    assert resp.status_code == 200
    assert "event: saved" in resp.text
    stored = await _stored_loaded(session_factory, conv_id)
    assert stored[-1] == "acme.widget_11"


@pytest.mark.asyncio
async def test_a_stale_stored_name_is_ignored_by_the_route(
    client, session_factory, wide_tool_set, route_runtime
):
    from models.conversation import Conversation

    _, token = await make_user(session_factory, "offering-stale@example.com")
    provider = ScriptedProvider([LLMResponse(content="fine")])
    route_runtime(provider)
    conv = await client.post(
        "/api/agent/conversations", headers=auth_headers(token), json={"title": "x"}
    )
    conv_id = conv.json()["id"]
    async with session_factory() as session:
        row = await session.get(Conversation, uuid.UUID(conv_id))
        row.loaded_tools = ["github.merge_pr", "acme.widget_29"]
        await session.commit()
    resp = await client.post(
        f"/api/agent/conversations/{conv_id}/messages",
        headers=auth_headers(token),
        json={"content": "hi"},
    )
    assert resp.status_code == 201
    assert "github.merge_pr" not in provider.offered[0]
    assert "acme.widget_29" in provider.offered[0]


# ---------------------------------------------------------------------------
# Migration 0013
# ---------------------------------------------------------------------------


def test_0013_adds_a_nullable_column_and_downgrades_cleanly(tmp_path):
    from alembic import command

    from tests.test_migrations import _alembic_config

    db_path = tmp_path / "loaded.db"
    config = _alembic_config(f"sqlite+aiosqlite:///{db_path}")
    sync_url = f"sqlite:///{db_path}"
    command.upgrade(config, "0012_oauth_states")
    engine = sa.create_engine(sync_url)
    try:
        user_id, conversation_id = uuid.uuid4().hex, uuid.uuid4().hex
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "INSERT INTO users (id, email, hashed_password, is_active, created_at, "
                    "updated_at) VALUES (:id, 'l@example.com', 'x', 1, '2026-01-01 00:00:00', "
                    "'2026-01-01 00:00:00')"
                ),
                {"id": user_id},
            )
            conn.execute(
                sa.text(
                    "INSERT INTO conversations (id, user_id, title, created_at, updated_at) "
                    "VALUES (:id, :user, 'Old', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"id": conversation_id, "user": user_id},
            )
        command.upgrade(config, "0013_conversation_loaded_tools")
        columns = {c["name"]: c for c in sa.inspect(engine).get_columns("conversations")}
        assert columns["loaded_tools"]["nullable"] is True
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT loaded_tools FROM conversations")).scalar() is None
        command.downgrade(config, "0012_oauth_states")
        engine.dispose()
        columns = {c["name"] for c in sa.inspect(engine).get_columns("conversations")}
        assert "loaded_tools" not in columns
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT title FROM conversations")).scalar() == "Old"
    finally:
        engine.dispose()
