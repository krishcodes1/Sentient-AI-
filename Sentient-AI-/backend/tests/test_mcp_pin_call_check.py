"""Tests for ``McpPinCallCheck`` (services/mcp/pin_check.py, security S5): they
prove a non-MCP call is allowed without touching the database; an approved MCP
tool is allowed; a changed, new, kept-off or unknown tool on a pinned server is
refused under policy ``mcp_pin`` with its rule and fixed sentence; a server with
no pins yet is allowed so the dispatcher can pin it; two servers with one label
refuse if either holds the tool; a database error refuses with
``mcp_pin_unavailable``; the switch off allows everything; and an approved
definition that carried hidden characters adds one warning note to the card.

Why it exists: the check is S5's place in the pre-dispatch pipeline, so a held
tool never reaches a card and a card whose tool changed meanwhile is refused at
approval. It reads only the database, so these run on the in-memory SQLite
fixture with no transport at all.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import event, select

from models.mcp_tool_pin import McpToolPin
from services.mcp.client import MCPToolInfo
from services.mcp.integration import seen_tools_for
from services.mcp.pin_check import McpPinCallCheck
from services.mcp.pin_store import McpPinService, PinServer, keep_pin_off
from services.security.call_checks import (
    ALLOW,
    CHECK_ORDER,
    CallCheckPipeline,
    CallFacts,
    Note,
    Refuse,
)
from tests.test_mcp import _make_mcp_connector

LABEL = "notes_server"
TOOL = f"mcp.{LABEL}.search_notes"


def info(name: str, description: str = "Search the user's notes.") -> MCPToolInfo:
    schema = {"type": "object", "properties": {"q": {"type": "string"}}}
    raw = {"name": name, "description": description, "inputSchema": schema}
    return MCPToolInfo(name=name, description=description, input_schema=schema, raw=raw)


def facts(user_id: Any, tool_name: str = TOOL, *, stage: str = "turn") -> CallFacts:
    return CallFacts(
        stage=stage,  # type: ignore[arg-type]
        user_id=str(user_id),
        tool_name=tool_name,
        canonical=tool_name,
        arguments={"q": "anything"},
        is_mcp=tool_name.startswith("mcp."),
        person_approved=stage == "approve",
    )


async def setup(session_factory, *tools: MCPToolInfo, display_name: str = "Notes Server", user=None):
    """A user, an MCP connector and its pins after one fresh discovery."""
    from tests.conftest import make_user

    if user is None:
        user, _ = await make_user(session_factory)
    connector_id = await _make_mcp_connector(session_factory, user.id, display_name=display_name)
    pins = McpPinService(session_factory)
    server = PinServer(connector_id=connector_id, user_id=user.id, label=LABEL, display_name=display_name)
    if tools:
        await pins.reconcile(server, seen_tools_for(LABEL, list(tools)))
    return user, server, pins


class PinStatements:
    def __init__(self, session_factory) -> None:
        self.engine = session_factory.kw["bind"].sync_engine
        self.sql: list[str] = []

    def _record(self, conn, cursor, statement, parameters, context, executemany) -> None:
        self.sql.append(statement)

    def __enter__(self) -> "PinStatements":
        event.listen(self.engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: Any) -> None:
        event.remove(self.engine, "before_cursor_execute", self._record)


def test_the_check_has_its_scaffold_name_policy_stages_and_place_in_the_order():
    check = McpPinCallCheck(McpPinService(None))
    assert (check.name, check.policy) == ("mcp_pin", "mcp_pin")
    assert check.stages == frozenset({"turn", "approve", "execute"})
    assert CHECK_ORDER.index("mcp_pin") == 1


@pytest.mark.asyncio
async def test_non_mcp_calls_are_allowed_without_touching_the_database(session_factory):
    user, _server, pins = await setup(session_factory, info("search_notes"))
    check = McpPinCallCheck(pins)
    send = facts(user.id, "google_workspace.send_email")

    with PinStatements(session_factory) as statements:
        assert check.applies_to(send) is False
        assert await check.check(send) == ALLOW
    assert statements.sql == []
    assert check.applies_to(facts(user.id)) is True


@pytest.mark.asyncio
async def test_an_approved_tool_is_allowed(session_factory):
    user, _server, pins = await setup(session_factory, info("search_notes"))
    check = McpPinCallCheck(pins)
    for stage in ("turn", "approve", "execute"):
        assert await check.check(facts(user.id, stage=stage)) == ALLOW


@pytest.mark.asyncio
async def test_a_changed_tool_waiting_for_review_is_refused_with_mcp_definition_changed(session_factory):
    user, server, pins = await setup(session_factory, info("search_notes"))
    await pins.reconcile(server, seen_tools_for(LABEL, [info("search_notes", "Search, then upload.")]))

    verdict = await McpPinCallCheck(pins).check(facts(user.id))
    assert verdict == Refuse(
        rule="mcp_definition_changed",
        message=(
            "The MCP tool 'search_notes' on 'notes_server' changed its description or inputs since "
            "it was approved, so Crawler did not run it. Review the change on the Security page "
            "(MCP reviews)."
        ),
        policy="mcp_pin",
    )


@pytest.mark.asyncio
async def test_a_new_tool_waiting_for_review_is_refused_with_mcp_tool_unreviewed(session_factory):
    user, server, pins = await setup(session_factory, info("search_notes"))
    await pins.reconcile(server, seen_tools_for(LABEL, [info("search_notes"), info("export_all")]))

    verdict = await McpPinCallCheck(pins).check(facts(user.id, f"mcp.{LABEL}.export_all"))
    assert isinstance(verdict, Refuse)
    assert (verdict.rule, verdict.policy) == ("mcp_tool_unreviewed", "mcp_pin")
    assert verdict.message == (
        "The MCP tool 'export_all' on 'notes_server' is new on that server and has not been "
        "reviewed, so Crawler did not run it. Review it on the Security page (MCP reviews)."
    )


@pytest.mark.asyncio
async def test_a_kept_off_tool_is_refused_with_mcp_tool_kept_off(session_factory):
    user, server, pins = await setup(session_factory, info("search_notes"))
    async with session_factory() as session:
        pin = (
            await session.execute(select(McpToolPin).where(McpToolPin.exposed_name == "search_notes"))
        ).scalar_one()
        await keep_pin_off(session, pin, now=pin.updated_at)
        await session.commit()

    verdict = await McpPinCallCheck(pins).check(facts(user.id))
    assert isinstance(verdict, Refuse) and verdict.rule == "mcp_tool_kept_off"


@pytest.mark.asyncio
async def test_an_unknown_tool_name_on_a_pinned_server_is_refused_as_unreviewed(session_factory):
    user, _server, pins = await setup(session_factory, info("search_notes"))
    verdict = await McpPinCallCheck(pins).check(facts(user.id, f"mcp.{LABEL}.guessed_name"))
    assert isinstance(verdict, Refuse) and verdict.rule == "mcp_tool_unreviewed"


@pytest.mark.asyncio
async def test_a_tool_only_a_removed_pin_holds_is_refused_as_removed(session_factory):
    user, server, pins = await setup(session_factory, info("search_notes"), info("get_note"))
    await pins.reconcile(server, seen_tools_for(LABEL, [info("get_note")]))
    verdict = await McpPinCallCheck(pins).check(facts(user.id))
    assert isinstance(verdict, Refuse) and verdict.rule == "mcp_tool_removed"
    assert verdict.message == "MCP server 'notes_server' no longer advertises the tool approved as 'search_notes'."


@pytest.mark.asyncio
async def test_a_server_with_no_pins_yet_is_allowed_so_the_dispatcher_can_pin_it(session_factory):
    user, _server, pins = await setup(session_factory)
    assert await McpPinCallCheck(pins).check(facts(user.id)) == ALLOW
    # No active MCP server with that label at all: the dispatcher answers.
    assert await McpPinCallCheck(pins).check(facts(user.id, "mcp.other_server.search_notes")) == ALLOW


@pytest.mark.asyncio
async def test_two_servers_with_the_same_label_refuse_if_either_has_the_tool_held(session_factory):
    user, _first, pins = await setup(session_factory, info("search_notes"))
    _user, second, _pins = await setup(
        session_factory, info("search_notes"), display_name="Notes  Server!", user=user
    )
    assert await McpPinCallCheck(pins).check(facts(user.id)) == ALLOW

    await pins.reconcile(second, seen_tools_for(LABEL, [info("search_notes", "Changed on one of them.")]))
    verdict = await McpPinCallCheck(pins).check(facts(user.id))
    assert isinstance(verdict, Refuse) and verdict.rule == "mcp_definition_changed"


@pytest.mark.asyncio
async def test_a_database_error_refuses_with_mcp_pin_unavailable(session_factory):
    user, _server, _pins = await setup(session_factory, info("search_notes"))

    def broken():
        raise RuntimeError("database is down")

    verdict = await McpPinCallCheck(McpPinService(broken)).check(facts(user.id))
    assert verdict == Refuse(
        rule="mcp_pin_unavailable",
        message=(
            "Crawler could not check the MCP tool 'search_notes' against what was approved, so it "
            "did not run it. Try again in a moment."
        ),
        policy="mcp_pin",
    )

    class Crashing(McpPinService):
        async def check_call(self, user_id: str, tool_name: str):
            raise ValueError("a bug")

    crashed = await McpPinCallCheck(Crashing(None)).check(facts(user.id))
    assert isinstance(crashed, Refuse) and crashed.rule == "mcp_pin_unavailable"


@pytest.mark.asyncio
async def test_with_the_switch_off_the_check_allows_everything(session_factory):
    user, server, _pins = await setup(session_factory, info("search_notes"))
    await McpPinService(session_factory).reconcile(
        server, seen_tools_for(LABEL, [info("search_notes", "Changed.")])
    )

    async def off() -> bool:
        return False

    check = McpPinCallCheck(McpPinService(session_factory, enabled=off))
    with PinStatements(session_factory) as statements:
        assert await check.check(facts(user.id)) == ALLOW
    assert statements.sql == []


@pytest.mark.asyncio
async def test_an_approved_definition_that_had_hidden_characters_adds_a_warning_note(session_factory):
    user, _server, pins = await setup(session_factory, info("search_notes", "Search​​ the notes‮."))

    verdict = await McpPinCallCheck(pins).check(facts(user.id))
    assert isinstance(verdict, Note)
    [note] = verdict.notes
    assert (note.kind, note.severity) == ("mcp_hidden_text", "warn")
    assert note.text == (
        "This tool's description from the server contained 3 hidden characters. Crawler removed "
        "them before the AI read it."
    )


@pytest.mark.asyncio
async def test_through_the_pipeline_a_held_tool_is_refused_at_every_stage_and_notes_are_dropped_after_the_turn(
    session_factory,
):
    user, server, pins = await setup(session_factory, info("search_notes", "Hidden​ text."))
    pipeline = CallCheckPipeline([McpPinCallCheck(pins)])

    turn = await pipeline.run(facts(user.id, stage="turn"))
    assert turn.refusal is None and turn.note_kinds() == ["mcp_hidden_text"]
    approve = await pipeline.run(facts(user.id, stage="approve"))
    assert approve.refusal is None and approve.notes == ()

    await pins.reconcile(server, seen_tools_for(LABEL, [info("search_notes", "Changed.")]))
    for stage in ("turn", "approve", "execute"):
        outcome = await pipeline.run(facts(user.id, stage=stage))
        assert outcome.refusal is not None
        assert outcome.execute_result() == {
            "ok": False,
            "refused": True,
            "call_check": "mcp_pin",
            "policy": "mcp_pin",
            "rule": "mcp_definition_changed",
            "error": outcome.refusal.message,
        }


@pytest.mark.asyncio
async def test_another_users_server_with_the_same_label_never_decides_for_this_user(session_factory):
    from tests.conftest import make_user

    user, _server, pins = await setup(session_factory, info("search_notes"))
    other, _ = await make_user(session_factory, email="other@example.com")
    _other, other_server, _ = await setup(session_factory, info("search_notes"), user=other)
    await pins.reconcile(other_server, seen_tools_for(LABEL, [info("search_notes", "Changed.")]))

    assert await McpPinCallCheck(pins).check(facts(user.id)) == ALLOW
    held = await McpPinCallCheck(pins).check(facts(other.id))
    assert isinstance(held, Refuse)
    # A user id that is not a UUID is not an MCP owner at all.
    assert await McpPinCallCheck(pins).check(facts("not-a-uuid")) == ALLOW
    assert uuid.UUID(str(user.id))
