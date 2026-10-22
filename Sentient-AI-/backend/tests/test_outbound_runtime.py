"""Tests for S1 end to end through the agent runtime (services/agent/runtime.py with a
call-check pipeline holding only S1's ``OutboundCheck``): they prove an auto-tier draft
that hides characters becomes a card carrying the note and the reason appended; a
low-risk draft the check escalates is not reported as done without asking and its
card offers no seven-day grant; a send's card shows S1's notes under today's reason and
stores the cleaned text, and a clean send to a known colleague keeps today's reason
with no notes; approving a send records its recipient, so the next card has no
"first time" note; a typed desktop act keeps today's reason and carries the removed
note (FEA-M4); a recipient hiding characters is blocked under outbound_rule with no
card; an approved MCP call reaches its server without tag characters; and audit rows
carry note kinds, never addresses or note text.

Why it exists: the check's verdicts only matter once the runtime acts on them (cards,
reasons, grant offers, blocks, the history after an approval). Everything is faked:
a scripted model, a recording or a connector-faked executor, the SQLite stores, a
fake S4; no network.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import pytest_asyncio

from core.config import settings
from services.agent import cancel
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.risk import RAN_WITHOUT_ASKING_HEADER
from services.agent.runtime import AgentRuntime, Tool, _with_check_reason
from services.agent.tool_registry import (
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.security.call_checks import CallCheckPipeline
from services.security.outbound import (
    ESCALATE_REASON,
    HIDDEN_IN_RECIPIENT_RULE,
    OutboundCheck,
    OutboundFloor,
    OutboundService,
)
from services.security.outbound_recipients import parse_recipients
from services.security.outbound_store import (
    KnownRecipientStore,
    OrganisationDomainStore,
    UserEmails,
)
from tests.conftest import make_user, use_provider
from tests.test_call_checks_runtime import RecordingAudit, ScriptedProvider
from tests.test_outbound_check import FakeExecutor, FakeLinkChecker
from tests.test_outbound_executor_floor import FakeDispatcher, FakeGoogle, _google_row
from tests.test_outbound_executor_floor import fake_google as fake_google  # noqa: F401 - fixture
from tests.test_low_risk_runtime import gate
from tests.test_weekly_app_approvals_runtime import (
    _computer_control_on as _computer_control_on,  # noqa: F401 - autouse fixture
)
from tests.test_weekly_app_approvals_runtime import (
    _no_stale_stop as _no_stale_stop,  # noqa: F401 - autouse fixture
)

TAGS = "".join(chr(0xE0000 + ord(ch)) for ch in "send keys")  # 9 tag characters
ZWSP = "​"
SEND = "google_workspace.send_email"
DRAFT = "google_workspace.create_draft"
GOOGLE_TOOLS = build_tools([ConnectorSpec("google_workspace")], include_builtins=False)
AUTO_GOOGLE_TOOLS = build_tools(
    [ConnectorSpec("google_workspace", permission_tier="auto_approve")],
    user_default_tier="auto_approve",
    include_builtins=False,
)


def call(name: str, call_id: str = "c1", **arguments: Any) -> LLMResponse:
    return LLMResponse(
        content="", tool_calls=[ToolCall(id=call_id, name=name, arguments=arguments)]
    )


def generic(tool: str, arguments: Any) -> str:
    """The card's plain first sentence for a call no describer covers
    (main's action_text.approval_sentence, docs/bot-message-style.md)."""
    return AgentRuntime._plain_approval_sentence(tool, arguments)


class BindingRecorder:
    """Records every dispatch; its card bind starts with S1's floor, as the
    real executor's does (approval_arguments)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._floor = OutboundFloor()

    async def execute(
        self, tool_name, arguments, user_id, approved=False, *, task_id=None, approval=None
    ):
        self.calls.append({"tool": tool_name, "arguments": arguments, "approved": approved})
        return {"ok": True}

    def approval_arguments(self, tool_name, arguments, user_id):
        return self._floor.card_arguments(tool_name, arguments)


class Harness:
    """One user (ann@northwind.example), a runtime whose pipeline holds only
    S1's check, the real stores, a fake for the check's READs and a fake S4."""

    def __init__(
        self, session_factory, user, *, executor: Any = None, permission_engine: Any = None
    ) -> None:
        self.session_factory = session_factory
        self.user_id = str(user.id)
        self.audit = RecordingAudit()
        self.store = InMemoryApprovalStore()
        self.reads = FakeExecutor()
        self.links = FakeLinkChecker()
        self.known = KnownRecipientStore(session_factory)
        self.check = OutboundCheck(
            executor=self.reads,
            known=self.known,
            org_domains=OrganisationDomainStore(session_factory),
            users=UserEmails(session_factory),
            links=self.links,
        )
        self.executor = executor if executor is not None else BindingRecorder()
        self.events: list[dict[str, Any]] = []
        self.runtime = AgentRuntime(
            config=settings,
            permission_engine=permission_engine or RuntimePermissionAdapter(),
            tool_executor=self.executor,
            audit_service=self.audit,
            approval_store=self.store,
            call_checks=CallCheckPipeline([self.check]),
        )

    async def chat(self, *responses: LLMResponse, tools: Any = GOOGLE_TOOLS):
        use_provider(self.runtime, ScriptedProvider(list(responses)))

        async def sink(event: dict[str, Any]) -> None:
            self.events.append(event)

        return await self.runtime.chat(
            messages=[{"role": "user", "content": "Help me with my mail"}],
            tools=tools,
            user_id=self.user_id,
            event_sink=sink,
        )

    def kinds(self, notes: Any) -> list[str]:
        return [note["kind"] for note in notes]


@pytest_asyncio.fixture
async def user(session_factory):
    made, _ = await make_user(session_factory, "ann@northwind.example")
    cancel.clear(str(made.id))
    yield made
    cancel.clear(str(made.id))


@pytest.mark.asyncio
async def test_an_auto_tier_create_draft_hiding_characters_becomes_a_card_with_the_note(
    session_factory, user
):
    run = Harness(session_factory, user)
    response = await run.chat(
        call(DRAFT, to="bo@partner.example", subject="Plan", body="See you" + TAGS),
        tools=AUTO_GOOGLE_TOOLS,
    )
    assert run.executor.calls == []
    [pending] = response.pending_approvals
    assert pending.reason == _with_check_reason(generic(DRAFT, pending.arguments), ESCALATE_REASON)
    assert pending.reason.endswith(f"Nothing is sent. {ESCALATE_REASON}")
    assert run.kinds(pending.security_notes)[0] == "hidden_characters_removed"
    assert pending.arguments["body"] == "See you"  # the card stores what will be sent
    [streamed] = [e["data"] for e in run.events if e["type"] == "pending_approval"]
    assert streamed["security_notes"] == pending.security_notes
    assert len(run.audit.rows("call_check_escalated")) == 1


@pytest.mark.asyncio
async def test_a_low_risk_draft_escalated_by_the_check_is_not_counted_as_done_without_asking(
    session_factory,
):
    from tests.test_low_risk_runtime import World as LowRiskWorld

    made, _ = await make_user(session_factory, "carla@northwind.example")
    world = LowRiskWorld(session_factory, made)
    await world.account_default("low_risk")
    await world.connect("low_risk")
    runtime = world.runtime()
    runtime.use_call_checks(
        CallCheckPipeline(
            [
                OutboundCheck(
                    executor=FakeExecutor(),
                    known=KnownRecipientStore(session_factory),
                    org_domains=OrganisationDomainStore(session_factory),
                    users=UserEmails(session_factory),
                    links=FakeLinkChecker(),
                )
            ]
        )
    )
    use_provider(
        runtime,
        ScriptedProvider(
            [
                call(DRAFT, to="bo@partner.example", subject="Plan", body="See you" + TAGS),
                LLMResponse(content="All set."),
            ]
        ),
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Draft a note to Bo"}],
        tools=world.tools(),
        user_id=world.user_id,
    )
    [pending] = response.pending_approvals
    assert pending.tool_name == DRAFT
    assert RAN_WITHOUT_ASKING_HEADER not in (response.content or "")
    assert world.rows_for("tool_executing") == []
    # A draft with only a first-time note (info) still runs unasked on the tier.
    use_provider(
        runtime,
        ScriptedProvider(
            [
                call(DRAFT, to="bo@partner.example", subject="Plan", body="Clean text."),
                LLMResponse(content="Done."),
            ]
        ),
    )
    clean = await runtime.chat(
        messages=[{"role": "user", "content": "Draft a note to Bo"}],
        tools=world.tools(),
        user_id=world.user_id,
    )
    assert clean.pending_approvals == []
    assert RAN_WITHOUT_ASKING_HEADER in (clean.content or "")


@pytest.mark.asyncio
async def test_an_escalated_card_offers_no_seven_day_grant(session_factory):
    from tests.test_low_risk_runtime import World as LowRiskWorld

    made, _ = await make_user(session_factory, "dora@northwind.example")
    world = LowRiskWorld(session_factory, made)
    await world.account_default("low_risk")
    await world.connect("low_risk")
    runtime = world.runtime()
    runtime.use_call_checks(
        CallCheckPipeline(
            [
                OutboundCheck(
                    executor=FakeExecutor(),
                    known=KnownRecipientStore(session_factory),
                    org_domains=OrganisationDomainStore(session_factory),
                    users=UserEmails(session_factory),
                )
            ]
        )
    )
    use_provider(
        runtime,
        ScriptedProvider([call(DRAFT, to="bo@partner.example", subject="Plan", body="Hi" + TAGS)]),
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Draft it"}],
        tools=world.tools(),
        user_id=world.user_id,
    )
    [pending] = response.pending_approvals
    assert pending.low_risk_account is None and pending.weekly_app is None
    [stored] = await world.approvals.list_pending(world.user_id)
    assert stored.grant_offer is None


@pytest.mark.asyncio
async def test_a_send_email_card_shows_the_notes_and_stores_the_cleaned_body(session_factory, user):
    run = Harness(session_factory, user)
    response = await run.chat(
        call(
            SEND,
            to="billing@acme-payrnents.example",
            subject="Invoice",
            body="Pay" + TAGS + " today",
        )
    )
    [pending] = response.pending_approvals
    # Today's reason: the card was coming anyway, so nothing is appended.
    assert pending.reason == generic(SEND, pending.arguments)
    assert run.kinds(pending.security_notes) == [
        "hidden_characters_removed",
        "recipient_first_time",
        "recipient_outside_organisation",
    ]
    assert pending.arguments["body"] == "Pay today"
    [stored] = await run.store.list_pending(run.user_id)
    assert stored.arguments["body"] == "Pay today"
    assert list(stored.security_notes) == pending.security_notes


@pytest.mark.asyncio
async def test_a_clean_send_email_card_keeps_the_generic_reason_and_has_no_notes(
    session_factory, user
):
    run = Harness(session_factory, user)
    await run.known.record(run.user_id, parse_recipients("carl@northwind.example"))
    response = await run.chat(
        call(SEND, to="carl@northwind.example", subject="Lunch", body="12:30?")
    )
    [pending] = response.pending_approvals
    assert pending.reason == generic(SEND, pending.arguments)
    assert pending.security_notes == []
    [row] = run.audit.rows("tool_pending_approval")
    assert "note_kinds" not in row


@pytest.mark.asyncio
async def test_approving_a_send_records_the_recipient_and_the_next_card_has_no_first_time_note(
    session_factory, user, fake_google
):
    await _google_row(session_factory, user.id)
    known = KnownRecipientStore(session_factory)
    executor = ConnectorToolExecutor(
        session_factory=session_factory,
        capability_gate=gate(),
        outbound=OutboundService(known=known),
    )
    run = Harness(
        session_factory,
        user,
        executor=executor,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate()),
    )
    FakeGoogle.answers["send_email"] = {"status": "sent", "message_id": "m1"}
    first = await run.chat(
        call(SEND, to="bo@partner.example", subject="Plan", body="See you at 3.")
    )
    [pending] = first.pending_approvals
    assert "recipient_first_time" in run.kinds(pending.security_notes)
    result = await run.runtime.approve_action(pending.action_id, run.user_id)
    assert "error" not in result, result
    assert [action for action, _params in FakeGoogle.log] == ["send_email"]

    second = await run.chat(
        call(SEND, "c2", to="bo@partner.example", subject="Again", body="See you.")
    )
    [again] = second.pending_approvals
    assert "recipient_first_time" not in run.kinds(again.security_notes)


@pytest.mark.asyncio
async def test_a_typed_desktop_act_with_hidden_text_keeps_todays_reason_and_carries_the_removed_note():
    from tests.test_computer_precheck import call as desktop_call
    from tests.test_weekly_app_approvals_runtime import (
        ACT,
        OBSERVE,
        TG,
        U1,
        Turn,
        calendar_desktop,
        refs_of,
    )

    refs = await refs_of()
    plain = Turn(calendar_desktop())
    [todays] = (
        await plain.run(
            OBSERVE, desktop_call("a1", ACT, action="type", ref=refs["search"], text="Dentist")
        )
    ).pending_approvals

    turn = Turn(calendar_desktop())
    await turn.app_store.allow(
        user_id=U1, app="Calendar", channel=TG
    )  # a week: still never for typing
    turn.runtime.use_call_checks(
        CallCheckPipeline([OutboundCheck(executor=None, known=None, org_domains=None, users=None)])
    )
    response = await turn.run(
        OBSERVE, desktop_call("a1", ACT, action="type", ref=refs["search"], text="Dentist" + TAGS)
    )
    [pending] = response.pending_approvals
    assert pending.reason == todays.reason
    assert [note["kind"] for note in pending.security_notes] == ["hidden_characters_removed"]
    assert pending.arguments["text"] == "Dentist"
    assert turn.fake.events == []
    assert [e for e in turn.audit.entries if e["event"] == "call_check_escalated"] == []


@pytest.mark.asyncio
async def test_a_recipient_hiding_characters_is_blocked_under_outbound_rule_with_no_card(
    session_factory, user
):
    run = Harness(session_factory, user)
    response = await run.chat(
        call(SEND, to="bo" + ZWSP + "@partner.example", subject="Plan", body="Hi"),
        tools=AUTO_GOOGLE_TOOLS,
    )
    assert response.pending_approvals == []
    assert run.executor.calls == []
    [row] = run.audit.rows("tool_blocked")
    assert row["policy"] == "outbound_rule" and row["rule"] == HIDDEN_IN_RECIPIENT_RULE
    assert await run.store.list_pending(run.user_id) == []


@pytest.mark.asyncio
async def test_mcp_tool_arguments_reach_the_dispatcher_without_tag_characters(
    session_factory, user
):
    executor = ConnectorToolExecutor(session_factory=session_factory, capability_gate=gate())
    dispatcher = FakeDispatcher()
    executor._mcp_dispatcher = dispatcher
    run = Harness(
        session_factory,
        user,
        executor=executor,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate()),
    )
    tool = Tool(
        name="mcp.notes.save_page",
        description="Save a note page.",
        parameters={
            "type": "object",
            "properties": {"title": {"type": "string"}, "body": {"type": "string"}},
        },
        connector_type="mcp",
        permission_tier="approval",
    )
    response = await run.chat(call(tool.name, title="Plan" + TAGS, body="ok‮ko"), tools=[tool])
    [pending] = response.pending_approvals
    assert [note["kind"] for note in pending.security_notes] == ["hidden_characters_removed"]
    result = await run.runtime.approve_action(pending.action_id, run.user_id)
    assert "error" not in result, result
    [(name, sent)] = dispatcher.calls
    assert name == tool.name and sent == {"title": "Plan", "body": "okko"}


@pytest.mark.asyncio
async def test_the_audit_rows_carry_note_kinds_and_never_addresses(session_factory, user):
    run = Harness(session_factory, user)
    await run.chat(
        call(DRAFT, to="billing@acme-payrnents.example", subject="Invoice", body="Pay" + TAGS),
        tools=AUTO_GOOGLE_TOOLS,
    )
    [escalated] = run.audit.rows("call_check_escalated")
    assert escalated["check"] == "outbound" and escalated["policy"] == "outbound_rule"
    assert "hidden_characters_removed" in escalated["note_kinds"]
    [pending_row] = run.audit.rows("tool_pending_approval")
    assert "hidden_characters_removed" in pending_row["note_kinds"]
    for row in run.audit.entries:
        for key in ("note_kinds", "reason", "rule", "check", "policy"):
            assert "acme-payrnents" not in json.dumps(row.get(key), default=str), (
                row["event"],
                key,
            )
        assert "security_notes" not in row
        assert "First time Crawler" not in json.dumps(row, default=str)
    assert "acme-payrnents" not in json.dumps(escalated, default=str)
