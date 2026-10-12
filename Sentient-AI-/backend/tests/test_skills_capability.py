"""Tests for the "skills" capability and its wiring: it is registered on by
default, low risk and always available, claims the skills.* family, and is
enforced at the offer, the permission adapter and the executor; the policy
rows, the stance, the executor entry (reads only, no user) and the core tool;
the result budgets; the progress line; the <available_skills> block (right
after <permissions>, before <unattended> and <user_memory>, only while
skills.read is offered, byte-identical when absent) and how the routes build
it (the switches read on a connection of its own, so a failed read never
aborts the request's transaction); and reading a skill loads the tools it
names into the conversation, every account's copy of each, in a real
runtime turn.

Why it exists: skills are on for every install, so with the switch off every
request must look exactly as it did before the feature (apart from its
<permissions> line), and with it on a skill can only ever guide tools the
turn already had: loading never grants, and no write is ever possible
through the family. No model: a scripted provider. Skills are written to a
temporary folder and pinned there.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import event, select
from sqlalchemy import text as sa_text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core.config import settings
from models.skill_state import SkillState
from models.user import User
from services.agent import context_manager
from services.agent.approvals import InMemoryApprovalStore
from services.agent.context_manager import MAX_OFFERED_TOOLS, core_tool_names
from services.agent.permissions import _DEFAULT_POLICIES, ActionCategory, PermissionTier
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    CAPABILITY_OFF_POLICY,
    MAX_SKILL_TOOL_LOADS,
    RESULT_CHAR_BUDGETS,
    SECURITY_SYSTEM_PROMPT,
    AgentRuntime,
    LoadedTools,
    Tool,
    canonical_tool_name,
    result_char_budget,
)
from services.agent.tool_registry import (
    _BUILTIN_STANCE,
    BUILTIN_CONNECTOR_TYPES,
    CONNECTOR_CATALOG,
    RUNTIME_BUILTIN_TYPES,
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.automation.fence import classify_tool
from services.capabilities import REGISTRY, capability_for_tool, get
from services.capabilities import report as capability_report
from services.capabilities import statuses_by_key
from services.capabilities.base import ReportContext
from services.notifications.progress import phrase_for
from services.skills import loader
from services.skills.loader import SkillCatalog, load_skills
from services.skills.prompt import SKILLS_BLOCK_HEADER
from services.tools import skills as skills_tools
from services.tools.skills import SkillsToolkit
from tests.conftest import make_user, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider
from tests.test_skills_loader import pin, write_skill

BACKEND_DIR = Path(__file__).resolve().parents[1]
_CTX = ReportContext(
    in_container=False, platform="win32", telegram_configured=False, browser_installed=False
)

BLOCK = f"{SKILLS_BLOCK_HEADER}\n- week-planner: Plans a school week.\n</available_skills>"
PERMISSIONS = "<permissions>\n- Skills (built-in playbooks): on\n</permissions>"
MEMORY = "<user_memory>\n- likes tea\n</user_memory>"
HISTORY = [{"role": "user", "content": "hello"}]


def _gate(*keys: str):
    switches = {c.key: c.key in keys for c in REGISTRY}
    statuses = statuses_by_key(capability_report(switches, _CTX, use_cache=False))

    async def gate():
        return statuses

    return gate


def _catalog(root: Path) -> SkillCatalog:
    write_skill(
        root,
        extra=(
            "metadata:\n  crawler:\n    tools: [acme.widget_27, web.search, gone.tool, "
            "acme.widget_28]\n"
        ),
    )
    write_skill(
        root,
        "study-coach",
        extra="metadata:\n  crawler:\n    requires:\n      capabilities: [study]\n",
    )
    write_skill(
        root,
        "canvas-helper",
        extra="metadata:\n  crawler:\n    requires:\n      connectors: [canvas]\n",
    )
    pin(root)
    catalog = load_skills(root)
    assert all(record.status == "ok" for record in catalog)
    return catalog


# --------------------------------------------------------------------------- #
# Registration, catalog, gates
# --------------------------------------------------------------------------- #


def test_skills_is_registered_on_by_default_low_risk_and_claims_the_family():
    cap = get("skills")
    assert cap.label == "Skills (built-in playbooks)"
    assert cap.tools == ("skills.",) and cap.default_enabled is True and cap.risk == "low"
    assert cap.when_denied == (
        "Skills are turned off. The owner can turn them on in Settings → Permissions."
    )
    assert cap.availability(_CTX).available and cap.install is None and not cap.requires
    for spec in CONNECTOR_CATALOG["skills"]:
        assert capability_for_tool(f"skills.{spec.action}") is cap
    [status] = [s for s in capability_report({}, _CTX, use_cache=False) if s.key == "skills"]
    assert status.effective == "on" and status.enabled is True and status.available is True


def test_the_catalog_is_three_reads_with_their_arguments_required():
    specs = {s.action: s for s in CONNECTOR_CATALOG["skills"]}
    assert list(specs) == ["read", "read_reference", "scan_report"]
    assert {s.category for s in specs.values()} == {ActionCategory.READ}
    assert not any(s.always_confirm for s in specs.values())
    assert specs["read"].parameters["required"] == ["name"]
    assert specs["read_reference"].parameters["required"] == ["name", "file"]
    assert specs["scan_report"].parameters["required"] == ["name"]
    assert "<available_skills>" in specs["read"].description
    assert "never grants" in specs["read"].description


def test_skills_tools_are_offered_only_with_the_switch_on():
    names = {f"skills.{s.action}" for s in CONNECTOR_CATALOG["skills"]}
    assert not names & {t.name for t in build_tools([], enabled_capabilities=frozenset())}
    on = {t.name: t for t in build_tools([], enabled_capabilities=frozenset({"skills"}))}
    assert names <= set(on)
    assert all(on[name].permission_tier == "auto" for name in names)
    # On by default: an install that never touched the switch offers them.
    assert names <= {t.name for t in build_tools([])}


@pytest.mark.asyncio
async def test_the_adapter_and_the_executor_refuse_while_it_is_off():
    adapter = RuntimePermissionAdapter(capability_gate=_gate())
    assert await adapter.check("u1", "skills.read", {"name": "goals"}) == "blocked"
    assert await adapter.get_policy_name("u1", "skills.read") == CAPABILITY_OFF_POLICY
    assert (
        await adapter.get_block_reason("u1", "skills.scan_report", {}) == get("skills").when_denied
    )
    on = RuntimePermissionAdapter(capability_gate=_gate("skills"))
    for action in ("read", "read_reference", "scan_report"):
        assert await on.check("u1", f"skills.{action}", {"name": "goals"}) == "approved"
    executor = ConnectorToolExecutor(capability_gate=_gate())
    refused = await executor.execute("skills.read", {"name": "goals"}, user_id="u1")
    assert (
        refused["ok"] is False and refused["capability"] == "skills" and refused["state"] == "off"
    )


def test_the_policy_rows_allow_reads_only():
    assert {cat: _DEFAULT_POLICIES[("skills", cat)] for cat in ActionCategory} == {
        ActionCategory.READ: PermissionTier.AUTO_APPROVE,
        ActionCategory.WRITE: PermissionTier.HARD_BLOCKED,
        ActionCategory.DELETE: PermissionTier.HARD_BLOCKED,
        ActionCategory.EXECUTE: PermissionTier.HARD_BLOCKED,
        ActionCategory.FINANCIAL: PermissionTier.HARD_BLOCKED,
    }


def test_the_stance_and_the_executor_entry():
    assert "skills" in BUILTIN_CONNECTOR_TYPES and "skills" not in RUNTIME_BUILTIN_TYPES
    assert _BUILTIN_STANCE["skills"] == "user_confirm"
    entry = ConnectorToolExecutor()._builtins["skills"]
    assert entry.allowed == frozenset({ActionCategory.READ}) and entry.confirm == frozenset()
    assert not entry.task_scoped


def test_the_default_toolkit_shares_the_executor_session_factory():
    def factory() -> Any:
        raise AssertionError("never opened while building")

    executor = ConnectorToolExecutor(session_factory=factory)
    assert isinstance(executor.skills_toolkit, SkillsToolkit)
    assert executor.skills_toolkit._session_factory is factory


@pytest.mark.asyncio
async def test_the_executor_hands_the_toolkit_no_user_and_no_confirmation():
    class Recording:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any]]] = []

        async def execute(self, action, params):
            self.calls.append((action, dict(params)))
            return {"ok": True}

    kit = Recording()
    executor = ConnectorToolExecutor(skills_toolkit=kit)  # type: ignore[arg-type]
    assert executor.skills_toolkit is kit
    await executor.execute("skills.read", {"name": "goals", "user_confirmed": True}, user_id="u1")
    assert kit.calls == [("read", {"name": "goals"})]


def test_skills_read_is_core_and_the_offer_has_room_for_it():
    assert "skills.read" in core_tool_names()
    assert MAX_OFFERED_TOOLS == 25
    # Core only while the turn has it: the capability off means not offered.
    assert "skills.read" not in {t.name for t in build_tools([], enabled_capabilities=frozenset())}
    every = frozenset(cap.key for cap in REGISTRY)
    tools = build_tools([], enabled_capabilities=every)
    assert len(tools) > MAX_OFFERED_TOOLS  # precondition: this is a trim
    schemas = AgentRuntime._tools_to_schema(tools)
    offered = {
        t["name"]
        for t in context_manager.select_offered_tools(
            schemas, sorted({t.connector_type for t in tools})
        )
    }
    assert "skills.read" in offered and "tools.find" in offered


def test_unattended_runs_never_get_a_skill():
    for action in ("read", "read_reference", "scan_report"):
        assert classify_tool(f"skills.{action}") is None
    source = (BACKEND_DIR / "services" / "automation" / "turns.py").read_text(encoding="utf-8")
    assert "skills_text" not in source


def test_the_result_budgets():
    assert result_char_budget("skills.read", 0) == 34000 == skills_tools.READ_RESULT_CHARS
    assert result_char_budget("skills.read_reference", 0) == 34000
    assert result_char_budget("skills.scan_report", 0) == 8000 == skills_tools.SCAN_REPORT_CHARS
    keys = list(RESULT_CHAR_BUDGETS)
    # A prefix match in order: the longer name must come first.
    assert keys.index("skills.read_reference") < keys.index("skills.read")


def test_progress_lines_name_the_skill_tools():
    for tool, line in (
        ("skills.read", "Reading a skill…"),
        ("skills.read_reference", "Reading a skill…"),
        ("skills.scan_report", "Checking a skill…"),
    ):
        assert phrase_for({"type": "tool_call", "data": {"name": tool}}) == line


# --------------------------------------------------------------------------- #
# The <available_skills> block
# --------------------------------------------------------------------------- #


def test_the_block_goes_after_permissions_and_before_unattended_and_memory():
    content = AgentRuntime._with_system_prompt(
        HISTORY,
        MEMORY,
        PERMISSIONS,
        skills_block=BLOCK,
        unattended="<unattended>\nrun\n</unattended>",
        tutor_block="<tutor_mode>\non\n</tutor_mode>",
    )[0]["content"]
    assert content.startswith(SECURITY_SYSTEM_PROMPT)
    order = [
        content.index("<today>"),
        content.index(PERMISSIONS),
        content.index(BLOCK),
        content.index("<unattended>"),
        content.index(MEMORY),
        content.index("<tutor_mode>"),
    ]
    assert order == sorted(order)
    assert f"{PERMISSIONS}\n\n{BLOCK}\n\n<unattended>" in content
    assert content.endswith("<tutor_mode>\non\n</tutor_mode>")  # tutor still last


def test_without_a_block_the_system_message_is_byte_identical():
    plain = AgentRuntime._with_system_prompt(HISTORY, MEMORY, PERMISSIONS)
    assert (
        AgentRuntime._with_system_prompt(HISTORY, MEMORY, PERMISSIONS, skills_block=None) == plain
    )
    assert AgentRuntime._with_system_prompt(HISTORY, MEMORY, PERMISSIONS, skills_block="") == plain
    with_block = AgentRuntime._with_system_prompt(HISTORY, MEMORY, PERMISSIONS, skills_block=BLOCK)
    assert with_block[0]["content"].replace(f"\n\n{BLOCK}", "") == plain[0]["content"]


def _runtime(provider, executor=None) -> AgentRuntime:
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor or ConnectorToolExecutor(),
        prompt_guard=RecordingGuard(),
        audit_service=RecordingAudit(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(runtime, provider)
    return runtime


async def _system(tools, **kwargs) -> str:
    provider = RecordingProvider()
    await _runtime(provider).chat(
        messages=list(HISTORY),
        tools=tools,
        user_id="u1",
        memory_block=MEMORY,
        permissions_text=PERMISSIONS,
        **kwargs,
    )
    return provider.calls[0]["messages"][0]["content"]


@pytest.mark.asyncio
async def test_chat_adds_the_block_only_while_skills_read_is_offered():
    on = build_tools([], enabled_capabilities=frozenset({"skills"}))
    with_block = await _system(on, skills_text=BLOCK)
    assert with_block.index(PERMISSIONS) < with_block.index(BLOCK) < with_block.index(MEMORY)
    assert with_block.replace(f"\n\n{BLOCK}", "") == await _system(on)
    assert await _system(on, skills_text=None) == await _system(on)
    # The capability off (or a fence that removed skills.read): no block,
    # whatever the route built, and the bytes of a turn without the feature.
    off = build_tools([], enabled_capabilities=frozenset())
    without = await _system(off, skills_text=BLOCK)
    assert "<available_skills>" not in without
    assert without == await _system(off)


@pytest.mark.asyncio
async def test_stream_chat_forwards_the_block():
    provider = RecordingProvider()
    runtime = _runtime(provider)
    runtime._CONTENT_CHUNK_DELAY = 0
    tools = build_tools([], enabled_capabilities=frozenset({"skills"}))
    async for _event in runtime.stream_chat(
        messages=list(HISTORY), tools=tools, user_id="u1", skills_text=BLOCK
    ):
        pass
    assert BLOCK in provider.calls[0]["messages"][0]["content"]


@pytest.mark.asyncio
async def test_the_routes_build_the_block_from_the_owner_switches(
    tmp_path, session_factory, monkeypatch
):
    from api.routes.agent import _build_tools_and_memory, _skills_text

    monkeypatch.setattr(loader, "_bundled", _catalog(tmp_path))
    user, _ = await make_user(session_factory, "skills-block@example.com")
    on = build_tools([], enabled_capabilities=frozenset({"skills"}))
    async with session_factory() as db:
        text = await _skills_text(db, on, frozenset({"skills"}))
        assert text is not None and text.startswith(SKILLS_BLOCK_HEADER)
        # Requirements: study-coach needs the study switch, canvas-helper a
        # canvas tool in the turn.
        assert "- week-planner:" in text
        assert "study-coach" not in text and "canvas-helper" not in text
        more = await _skills_text(
            db, [*on, Tool("canvas.get_upcoming", "", {}, "canvas")], frozenset({"skills", "study"})
        )
        assert more is not None and "- study-coach:" in more and "- canvas-helper:" in more
        # Not offered: no block at all.
        assert (
            await _skills_text(db, build_tools([], enabled_capabilities=frozenset()), frozenset())
            is None
        )
        # Committed, as the Settings route does: on an engine with a pool
        # the switches are read on a connection of their own.
        db.add(SkillState(name="week-planner", enabled=False, sha256="a" * 64))
        await db.commit()
        assert await _skills_text(db, on, frozenset({"skills"})) is None  # nothing left
        built = await _build_tools_and_memory(None, user, db)
        assert built.skills_text is None
        db.add(SkillState(name="study-coach", enabled=True, sha256="a" * 64))
        await db.commit()
        assert "study-coach" in (await _skills_text(db, on, frozenset({"skills", "study"})) or "")

    class Broken:
        async def execute(self, *args, **kwargs):
            raise OperationalError("SELECT", {}, Exception("database is down"))

    # The switches cannot be read: the block is left out (fail closed).
    assert await _skills_text(Broken(), on, frozenset({"skills"})) is None  # type: ignore[arg-type]


def _like_postgres(engine: Any) -> None:
    """Give a SQLite engine Postgres's rule for a failed statement: the
    transaction is aborted, every later statement on its connection fails,
    and COMMIT quietly rolls back (until a rollback ends it)."""
    sync = engine.sync_engine

    @event.listens_for(sync, "handle_error")
    def _abort(context: Any) -> None:
        if context.connection is not None:
            context.connection.info["aborted"] = True

    @event.listens_for(sync, "before_cursor_execute")
    def _refuse(conn: Any, *args: Any) -> None:
        if conn.info.get("aborted"):
            raise RuntimeError("current transaction is aborted")

    @event.listens_for(sync, "commit")
    def _commit(conn: Any) -> None:
        if conn.info.pop("aborted", False):
            conn.connection.dbapi_connection.rollback()

    @event.listens_for(sync, "rollback")
    def _rollback(conn: Any) -> None:
        conn.info.pop("aborted", None)


@pytest_asyncio.fixture
async def pooled_factory(tmp_path):
    """A file-backed database whose pool gives each session its own
    connection (as Postgres's does), with Postgres's aborted-transaction rule."""
    import models  # noqa: F401 - registers every model on Base.metadata
    from core.database import Base

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'pooled.db'}")
    _like_postgres(engine)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(bind=engine, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_a_failed_switches_read_leaves_the_request_session_usable(
    tmp_path, pooled_factory, monkeypatch
):
    from api.routes.agent import _skills_text

    monkeypatch.setattr(loader, "_bundled", _catalog(tmp_path / "skills"))
    on = build_tools([], enabled_capabilities=frozenset({"skills"}))
    # Read on a connection of its own: a switch the owner committed counts.
    async with pooled_factory() as db:
        db.add(SkillState(name="study-coach", enabled=False, sha256="a" * 64))
        await db.commit()
        text = await _skills_text(db, on, frozenset({"skills", "study"}))
        assert text is not None and "- week-planner:" in text and "study-coach" not in text
    # A database without skill_states (migration 0025 never ran): the read fails.
    async with pooled_factory() as db:
        await db.execute(sa_text("DROP TABLE skill_states"))
        await db.commit()
    async with pooled_factory() as db:
        db.add(User(email="flushed@example.com", hashed_password="x"))
        await db.flush()  # the turn's user message, flushed before the context is built
        assert await _skills_text(db, on, frozenset({"skills"})) is None  # block left out
        assert (await db.execute(select(User.email))).scalars().all() == ["flushed@example.com"]
        await db.commit()
    async with pooled_factory() as check:
        rows = (await check.execute(select(User.email))).scalars().all()
    assert rows == ["flushed@example.com"]


@pytest.mark.asyncio
async def test_a_turn_context_carries_the_block(tmp_path, session_factory, monkeypatch):
    from api.routes.agent import TurnContext, _build_tools_and_memory

    assert TurnContext._field_defaults["skills_text"] is None
    monkeypatch.setattr(loader, "_bundled", _catalog(tmp_path))
    user, _ = await make_user(session_factory, "skills-turn@example.com")
    async with session_factory() as db:
        built = await _build_tools_and_memory(None, user, db)
    assert built.skills_text is not None and "- week-planner:" in built.skills_text


def test_every_chat_call_site_passes_the_block():
    tree = ast.parse((BACKEND_DIR / "api" / "routes" / "agent.py").read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("chat", "stream_chat")
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "runtime"
    ]
    # send, stream, the approval resume and the channel applier.
    assert len(calls) == 4
    for call in calls:
        [keyword] = [k for k in call.keywords if k.arg == "skills_text"]
        assert ast.unparse(keyword.value) == "turn_context.skills_text"


# --------------------------------------------------------------------------- #
# Reading a skill loads the tools it names
# --------------------------------------------------------------------------- #


def _turn_tools(rest: int = 30) -> list[Tool]:
    tools = [
        Tool("web.search", "Search the public web", {}, "web"),
        Tool("web.fetch_page", "Fetch a public web page", {}, "web"),
        Tool("reminders.now", "Current date and time", {}, "reminders"),
        Tool("tools.find", "Find tools", {}, "tools"),
        Tool(
            "skills.read",
            "Read a skill",
            {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
            "skills",
        ),
    ]
    tools += [
        Tool(f"acme.widget_{i:02d}", f"Operate acme widget number {i}", {}, "acme")
        for i in range(rest)
    ]
    return tools


def _offered(call: dict[str, Any]) -> list[str]:
    return [t["name"] for t in call["tools"] or []]


@pytest.mark.asyncio
async def test_reading_a_skill_loads_the_tools_it_names(tmp_path):
    catalog = _catalog(tmp_path)
    provider = RecordingProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[
                    ToolCall(id="tc-1", name="skills.read", arguments={"name": "week-planner"})
                ],
            ),
            LLMResponse(content="Following the playbook."),
        ]
    )
    executor = ConnectorToolExecutor(skills_toolkit=SkillsToolkit(catalog=catalog))
    loaded = LoadedTools(["acme.widget_01"])
    runtime = _runtime(provider, executor)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "plan my week"}],
        tools=_turn_tools(),
        user_id="u1",
        loaded_tools=loaded,
    )
    assert response.content == "Following the playbook."
    assert not response.blocked_actions and not response.pending_approvals
    first, second = (_offered(call) for call in provider.calls)
    assert "skills.read" in first  # core
    assert "acme.widget_27" not in first and "acme.widget_28" not in first
    assert {"acme.widget_27", "acme.widget_28"} <= set(second)
    assert len(second) == MAX_OFFERED_TOOLS
    # Loaded like a tools.find match: in the conversation's list, to persist.
    assert loaded.changed is True
    assert loaded.names == ["acme.widget_01", "acme.widget_28", "acme.widget_27"]
    # The result says which were loaded: not the core one, not one the turn
    # does not have.
    result = response.tool_calls[0]["result"]
    assert result["ok"] is True and result["name"] == "week-planner"
    assert result["tools"] == ["acme.widget_27", "acme.widget_28"]
    # Audited like any read, as facts: the loaded names, never the playbook.
    [row] = [e for e in runtime._audit.entries if e["event"] == "tool_executed"]
    assert row["tool"] == "skills.read" and "acme.widget_27" in row["result_summary"]
    assert "Show the week" not in row["result_summary"]


@pytest.mark.asyncio
async def test_a_refused_read_loads_nothing(tmp_path):
    catalog = _catalog(tmp_path)
    provider = RecordingProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[ToolCall(id="tc-1", name="skills.read", arguments={"name": "nope"})],
            ),
            LLMResponse(content="ok"),
        ]
    )
    executor = ConnectorToolExecutor(skills_toolkit=SkillsToolkit(catalog=catalog))
    loaded = LoadedTools()
    response = await _runtime(provider, executor).chat(
        messages=[{"role": "user", "content": "plan"}],
        tools=_turn_tools(),
        user_id="u1",
        loaded_tools=loaded,
    )
    assert response.tool_calls[0]["result"]["rule"] == "unknown_skill"
    assert loaded.changed is False and loaded.names == []
    assert provider.calls[0]["tools"] == provider.calls[1]["tools"]


def test_loading_skips_withheld_names_and_stops_at_the_cap():
    schemas = [{"name": f"acme.op_{i:02d}"} for i in range(20)] + [{"name": "web.search"}]
    named = [f"acme.op_{i:02d}" for i in range(12)] + ["web.search", "acme.op_01", 7]
    loaded = LoadedTools()
    result = AgentRuntime._load_skill_tools(
        {"ok": True, "tools": named},
        schemas,
        loaded,
        allows=lambda name: name != "acme.op_00",
    )
    assert result["tools"] == [f"acme.op_{i:02d}" for i in range(1, 1 + MAX_SKILL_TOOL_LOADS)]
    assert MAX_SKILL_TOOL_LOADS == 8 and len(loaded.names) == 8
    # Anything but a successful read is left as it was.
    for other in ({"ok": False, "tools": named}, {"redacted": True}, "text", {"ok": True}):
        untouched = LoadedTools()
        assert AgentRuntime._load_skill_tools(other, schemas, untouched) == other
        assert untouched.changed is False


def _github(n: int) -> ConnectorSpec:
    return ConnectorSpec(
        connector_type="github",
        is_active=True,
        granted_scopes=None,
        permission_tier="user_confirm",
        connector_id=f"00000000-0000-4000-8000-{n:012d}",
        display_name=f"GitHub account {n}",
    )


def test_a_skill_loads_every_account_of_the_tools_it_names():
    # Two GitHub rows: build_tools names each account's tools
    # github__<slug>.<action>, and a skill names them github.<action>.
    tools = build_tools([_github(1), _github(2)], enabled_capabilities=frozenset({"skills"}))
    schemas = [{"name": t.name} for t in tools]
    names = [t.name for t in tools]
    assert "github.get_pr" not in names

    def accounts(canonical: str) -> list[str]:
        return [name for name in names if canonical_tool_name(name) == canonical]

    assert len(accounts("github.get_pr")) == 2
    loaded = LoadedTools()
    result = AgentRuntime._load_skill_tools(
        {"ok": True, "tools": ["github.get_pr", "web.search", "github.list_prs", "gone.tool"]},
        schemas,
        loaded,
    )
    # The real names the model can call, both accounts of each named tool;
    # never a core tool or one the turn does not have.
    expected = accounts("github.get_pr") + accounts("github.list_prs")
    assert result["tools"] == expected and len(expected) == 4
    assert loaded.changed is True and sorted(loaded.names) == sorted(expected)
    # The cap counts the skill's names, not each account's copy.
    actions = sorted({canonical_tool_name(n) for n in names if n.startswith("github__")})
    assert len(actions) > MAX_SKILL_TOOL_LOADS
    capped = AgentRuntime._load_skill_tools({"ok": True, "tools": actions}, schemas, LoadedTools())
    assert {canonical_tool_name(n) for n in capped["tools"]} == set(actions[:MAX_SKILL_TOOL_LOADS])
    assert len(capped["tools"]) == 2 * MAX_SKILL_TOOL_LOADS
    # A withheld name is skipped for every account, and the next name counts.
    skipped = AgentRuntime._load_skill_tools(
        {"ok": True, "tools": actions},
        schemas,
        LoadedTools(),
        allows=lambda name: canonical_tool_name(name) != actions[0],
    )
    assert {canonical_tool_name(n) for n in skipped["tools"]} == set(
        actions[1 : 1 + MAX_SKILL_TOOL_LOADS]
    )
