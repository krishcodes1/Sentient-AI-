"""Tests for the file tools inside a real turn (AgentRuntime with a scripted model, the real
ConnectorToolExecutor, its security family wired to FileReputationToolkit, and the capability
gate on with a key): they prove the model checks an attachment and the turn goes on without a
card; asking to upload parks a card and sends nothing; approving sends the file once and
denying sends nothing; the card's file facts stay out of the audit log and the card's shown
arguments; an unattended run is never given the upload tool; and a card parked from the
Security page runs once and resumes no turn.

Why it exists: the upload's safety comes from the runtime and the executor as much as from the
toolkit (the precheck, the bind under ``_upload``, the card, the single-use approval). These
tests hold the pieces together end to end, so a change in any one of them that lets a file
leave without exactly one approval fails here.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from core.config import settings
from services import capabilities as registry
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime, PrecheckRefusal
from services.agent.tool_registry import ConnectorToolExecutor, RuntimePermissionAdapter, build_tools
from services.agent.unattended import UnattendedRun
from services.audit import redact_tool_arguments
from services.automation.fence import build_fence
from services.capabilities.base import ReportContext
from services.file_reputation.service import FileReputationService
from services.file_reputation.toolkit import UPLOAD_CARD_KEY, FileReputationToolkit
from services.file_reputation.virustotal import VirusTotalClient
from services.files.intake import InboundFile
from services.files.sandbox import InProcessSandbox
from services.files.store import UserFileStore
from services.notifications.cards import card_arguments
from services.tools.security_checks import SecurityToolkit
from tests.conftest import make_user, use_provider
from tests.file_reputation.fakevt import (
    FakeExecutor,
    FakeSettings,
    FakeTelegram,
    FakeVirusTotal,
    Outbox,
    RecordingAudit,
    SerializedSessions,
    sha_of,
)
from tests.files import builders as b

EXE = b"MZ\x90\x00\x03 \"Payroll Q3\" program"
UPLOAD = "security.upload_to_virustotal"


class ScriptedProvider:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(list(messages))
        return self._responses.pop(0) if self._responses else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"


class RuntimeAudit:
    """The runtime's audit service (``log``), recording rows."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def log(self, entry: dict[str, Any]) -> None:
        self.entries.append(dict(entry))


def _gate():
    """The owner's report with file_reputation on and a VirusTotal key saved."""
    ctx = ReportContext(
        in_container=False,
        platform="linux",
        telegram_configured=False,
        browser_installed=False,
        service_keys=frozenset({"virustotal"}),
    )
    statuses = registry.statuses_by_key(registry.report(registry.default_switches(), ctx, use_cache=False))

    async def gate():
        return statuses

    return gate


class World:
    """A runtime, the real executor and the file service on fakes, for one user."""

    def __init__(self, session_factory: Any, user_id: str) -> None:
        self.user_id = user_id
        self.vt = FakeVirusTotal()
        self.outbox = Outbox()
        self.service_audit = RecordingAudit()
        self.audit = RuntimeAudit()
        self.store = InMemoryApprovalStore()
        self.service = FileReputationService(
            SerializedSessions(session_factory),
            settings=FakeSettings(),
            audit=self.service_audit,
            send=self.outbox,
            telegram_fetch=FakeTelegram(),
            connector_read=FakeExecutor().execute,
            park_card=self._park,
            pending_ids=self._pending,
            client=VirusTotalClient(transport=self.vt.transport),
        )
        family = SecurityToolkit()
        family.use_file_reputation(FileReputationToolkit(self.service))
        gate = _gate()
        self.executor = ConnectorToolExecutor(session_factory=None, capability_gate=gate, security_toolkit=family)
        self.runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(capability_gate=gate),
            tool_executor=self.executor,
            audit_service=self.audit,
            approval_store=self.store,
        )
        self.tools = build_tools([], enabled_capabilities=frozenset({"file_reputation"}))
        self.provider = ScriptedProvider([])

    async def _park(self, **kwargs: Any) -> Any:
        return await self.runtime.park_card(**kwargs)

    async def _pending(self, user_id: str) -> set[str]:
        return {p.action_id for p in await self.runtime.list_pending_approvals(user_id)}

    async def chat(self, *responses: LLMResponse) -> Any:
        self.provider = ScriptedProvider(list(responses))
        use_provider(self.runtime, self.provider)
        return await self.runtime.chat(
            messages=[{"role": "user", "content": "Is this file OK?"}], tools=self.tools, user_id=self.user_id
        )

    def events(self, name: str) -> list[dict[str, Any]]:
        return [e for e in self.audit.entries if e.get("event") == name]


def call(name: str, **arguments: Any) -> LLMResponse:
    return LLMResponse(content="", tool_calls=[ToolCall(id="c1", name=name, arguments=arguments)])


def _tool_results(messages: list[dict[str, Any]]) -> str:
    return json.dumps([m.get("content") for m in messages if m.get("role") in ("tool", "user")], default=str)


@pytest.mark.asyncio
async def test_the_model_checks_an_attachment_and_the_turn_continues_without_a_card(session_factory):
    user, _ = await make_user(session_factory, "rt-check@example.com")
    world = World(session_factory, str(user.id))
    pdf = b.make_pdf(["Invoice attached"])
    store = UserFileStore(session_factory, sandbox=InProcessSandbox())
    info = await store.ingest(str(user.id), data=pdf, name="invoice.pdf", declared_mime="application/pdf", source="web")
    world.vt.add_file(sha_of(pdf), malicious=41, undetected=31, label="trojan.pdfka")

    response = await world.chat(
        call("security.check_file", file_id=str(info.id)),
        LLMResponse(content="VirusTotal flags it; don't open it."),
    )

    assert response.pending_approvals == [] and await world.store.list_pending(str(user.id)) == []
    assert len(world.provider.calls) == 2
    seen = _tool_results(world.provider.calls[1]).replace("\\", "").replace(" ", "")
    assert '"verdict":"malicious"' in seen and '"flagged_by":41' in seen
    assert [r.url.path for r in world.vt.requests] == [f"/api/v3/files/{sha_of(pdf)}"]
    assert world.events("tool_pending_approval") == []
    # The model tells the user in the turn; the service does not send a second alert.
    assert world.outbox.sent == []


@pytest.mark.asyncio
async def test_asking_to_upload_parks_a_card_and_sends_nothing(session_factory):
    user, _ = await make_user(session_factory, "rt-ask@example.com")
    world = World(session_factory, str(user.id))
    uid = str(user.id)
    await world.service.screen(uid, InboundFile("Payroll Q3.exe", "application/x-msdownload", EXE, "web"))
    await world.service.drain()

    response = await world.chat(call(UPLOAD, sha256=sha_of(EXE)), LLMResponse(content="Approve the card."))

    assert len(response.pending_approvals) == 1
    [card] = await world.store.list_pending(uid)
    assert card.tool_name == UPLOAD
    assert card.arguments["sha256"] == sha_of(EXE)
    facts = card.arguments[UPLOAD_CARD_KEY]
    assert facts["name"] == "Payroll Q3․exe" and facts["size_bytes"] == len(EXE)
    assert card.reason.startswith('Send "Payroll Q3․exe" (')
    assert "VirusTotal shares files it receives with security companies" in card.reason
    assert world.vt.uploads == [] and not [r for r in world.vt.requests if r.method == "POST"]


@pytest.mark.asyncio
async def test_approving_the_card_sends_the_file_once_and_denying_sends_nothing(session_factory):
    user, _ = await make_user(session_factory, "rt-approve@example.com")
    world = World(session_factory, str(user.id))
    uid = str(user.id)
    other = EXE + b" another"
    for name, data in (("setup.exe", EXE), ("other.exe", other)):
        await world.service.screen(uid, InboundFile(name, "application/x-msdownload", data, "web"))
    await world.service.drain()
    await world.chat(call(UPLOAD, sha256=sha_of(EXE)), LLMResponse(content="ok"))
    await world.chat(call(UPLOAD, sha256=sha_of(other)), LLMResponse(content="ok"))
    cards = {c.arguments["sha256"]: c for c in await world.store.list_pending(uid)}

    approved = await world.runtime.approve_action(cards[sha_of(EXE)].action_id, uid)
    again = await world.runtime.approve_action(cards[sha_of(EXE)].action_id, uid)
    denied = await world.runtime.deny_action(cards[sha_of(other)].action_id, uid)

    assert "error" not in approved and "error" in again and denied.get("denied") is True
    assert len(world.vt.uploads) == 1 and EXE in world.vt.uploads[0]
    assert other not in world.vt.uploads[0]
    row = await world.service.store.check_for(uid, sha_of(EXE))
    assert row is not None and row.state == "analysing"
    untouched = await world.service.store.check_for(uid, sha_of(other))
    assert untouched is not None and untouched.state == "checked"
    assert len(world.service_audit.events("file_reputation_uploaded")) == 1


@pytest.mark.asyncio
async def test_the_upload_card_hides_its_file_facts_from_the_audit_log_and_the_cards_shown_arguments(
    session_factory,
):
    user, _ = await make_user(session_factory, "rt-hide@example.com")
    world = World(session_factory, str(user.id))
    uid = str(user.id)
    name = "Jane-Doe-medical-records.exe"
    await world.service.screen(uid, InboundFile(name, "application/x-msdownload", EXE, "web"))
    await world.service.drain()
    await world.chat(call(UPLOAD, sha256=sha_of(EXE)), LLMResponse(content="ok"))
    [card] = await world.store.list_pending(uid)
    await world.runtime.approve_action(card.action_id, uid)

    shown = card_arguments(UPLOAD, card.arguments)
    assert shown == {"sha256": sha_of(EXE)}
    rows = [e for e in world.audit.entries if e.get("tool") == UPLOAD and isinstance(e.get("arguments"), dict)]
    assert {e["event"] for e in rows} >= {"tool_pending_approval", "tool_approved"}
    for entry in rows:
        stored = redact_tool_arguments(UPLOAD, entry["arguments"])
        assert "Jane-Doe" not in str(stored) and "medical" not in str(stored)
        if UPLOAD_CARD_KEY in entry["arguments"]:
            # A marker, never the facts ("<n characters>", or the runtime's own redaction).
            assert isinstance(stored[UPLOAD_CARD_KEY], str) and "exe" not in stored[UPLOAD_CARD_KEY]
    assert "Jane-Doe" not in str(world.service_audit.rows)


@pytest.mark.asyncio
async def test_an_unattended_run_is_never_given_the_upload_tool(session_factory):
    tools = build_tools([], enabled_capabilities=frozenset({"file_reputation"}))
    run = UnattendedRun(
        label="Daily file check",
        origin="schedule:1",
        reads=frozenset({"security.check_file"}),
        writes=frozenset({UPLOAD}),
    )

    kept, missing = build_fence(tools, run)

    assert [t.name for t in kept if t.name.startswith("security.")] == ["security.check_file"]
    assert UPLOAD in missing
    assert run.verdict(UPLOAD) == "refuse" and run.verdict("security.check_file") == "read"


@pytest.mark.asyncio
async def test_a_card_parked_from_the_security_page_runs_once_and_resumes_no_turn(session_factory):
    user, _ = await make_user(session_factory, "rt-page@example.com")
    world = World(session_factory, str(user.id))
    uid = str(user.id)
    pdf = b"%PDF-1.7 a document the owner chose"
    checked = await world.service.check_hash(uid, sha_of(pdf), name="chosen.pdf", source="page", alert="caller")
    assert checked.check_id is not None

    outcome = await world.service.request_upload(uid, checked.check_id, pdf)
    assert outcome.status == "parked" and outcome.action_id
    [card] = await world.store.list_pending(uid)
    assert card.origin == f"file_check:{checked.check_id}" and card.conversation_id is None
    assert [e["origin"] for e in world.events("tool_pending_approval")] == [card.origin]

    result = await world.runtime.approve_action(card.action_id, uid)
    again = await world.runtime.approve_action(card.action_id, uid)

    assert result.get("origin") == card.origin and "error" in again
    assert len(world.vt.uploads) == 1 and pdf in world.vt.uploads[0]
    assert world.provider.calls == []  # no turn was resumed
    # A request for a file the server cannot send is refused by park_card's precheck.
    personal = await world.service.check_hash(uid, sha_of(b"%PDF other"), name="other.pdf", alert="caller")
    refused = await world.runtime.park_card(
        user_id=uid, tool_name=UPLOAD, arguments={"sha256": sha_of(b"%PDF other")}, origin=f"file_check:{personal.check_id}"
    )
    assert isinstance(refused, PrecheckRefusal) and refused.rule == "personal_document"
    assert refused.policy == "file_reputation_rule"
