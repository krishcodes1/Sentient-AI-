"""Tests for S1's floor and send hooks in ConnectorToolExecutor
(services/agent/tool_registry.py with services/security/outbound.py): they prove the
executor dispatches the cleaned text to a connector, an MCP server and the browser's
act toolkit; writes one ``outbound_cleaned`` row of counts only when it removed
something (marked when it happened after an approval) and none for a clean call;
refuses a recipient that hides characters without dispatching anything; that both
card binds store cleaned arguments (the same dict when nothing changed), memory and
schedule cards included (SEC-F3), while a READ is untouched; that a successful,
approved send records its recipients (a Gmail reply from its result, a sent draft
from a READ made just before), and a failed send or a draft records nothing; that a
recording failure never changes the send's result; and that an executor with no
service wired still cleans.

Why it exists: the floor is the guarantee that holds on every path (approved cards,
standing consent, unattended runs, MCP), whatever the call check said. Connectors are
faked through ``create_connector`` (the test_executor_security.py way); no network.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import pytest
import pytest_asyncio

from services.agent.tool_registry import ConnectorToolExecutor
from services.connectors.base import (
    BaseConnector,
    ConnectorError,
    UserConfirmationRequired,
)
from services.tools.memory import MemoryToolkit
from services.security.outbound import (
    CLEANED_EVENT,
    HIDDEN_IN_RECIPIENT_RULE,
    OutboundFloor,
    OutboundService,
)
from services.security.outbound_recipients import parse_recipients
from services.security.outbound_store import KnownRecipientStore
from services.agent.tool_registry import resolve_tool
from tests.conftest import make_user
from tests.test_browser_act_card import gate as act_gate
from tests.test_low_risk_runtime import gate

TAGS = "".join(chr(0xE0000 + ord(ch)) for ch in "send keys")  # 9 tag characters
RLO = "‮"
ZWSP = "​"
SEND = "google_workspace.send_email"
WRITES = {"send_email", "reply", "send_draft", "create_draft", "forward"}


class FakeGoogle(BaseConnector):
    """A Google Workspace connector that records every action and answers
    from ``answers`` (a dict, or an exception to raise)."""

    log: list[tuple[str, dict[str, Any]]] = []
    answers: dict[str, Any] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()

    @property
    def name(self) -> str:
        return "Google Workspace"

    @property
    def connector_type(self) -> str:
        return "google_workspace"

    @property
    def required_scopes(self) -> list[str]:
        return []

    async def authenticate(self, credentials: Any) -> bool:
        self._authenticated = True
        return True

    async def _execute_action(self, action: str, params: dict[str, Any]) -> Any:
        if action in WRITES and not params.get("user_confirmed"):
            raise UserConfirmationRequired(action=action, details="confirm first")
        FakeGoogle.log.append((action, {k: v for k, v in params.items() if k != "user_confirmed"}))
        answer = FakeGoogle.answers.get(action, {"status": "done"})
        if isinstance(answer, BaseException):
            raise answer
        return answer

    async def health_check(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def fake_google(monkeypatch):
    import services.connectors.factory as factory_module

    FakeGoogle.log = []
    FakeGoogle.answers = {}

    def create(
        connector_type: str, credentials: Any, *, rate_limit: Any = None, timeout_s: Any = None
    ):
        connector = FakeGoogle()
        connector.set_network_policy(
            factory_module.NETWORK_POLICY_KEYS.get(connector_type, connector_type)
        )
        return connector

    monkeypatch.setattr(factory_module, "create_connector", create)
    return FakeGoogle


class Recording:
    """A built-in toolkit stand-in that records what it is asked to run."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(
        self, action: str, params: dict[str, Any], *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        self.calls.append((action, dict(params)))
        return {"ok": True, "action": action}


class FakeSchedule(Recording):
    async def bind(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        return {**params, "timezone": "Europe/London"}

    def describe(self, action: str, params: dict[str, Any], user_id: str) -> Optional[str]:
        return None


class RecordingAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def log(self, row: dict[str, Any]) -> None:
        self.rows.append(row)

    def of(self, event: str) -> list[dict[str, Any]]:
        return [row for row in self.rows if row.get("event") == event]


class FakeDispatcher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(
        self, tool_name: str, arguments: dict[str, Any], user_id: str
    ) -> dict[str, Any]:
        self.calls.append((tool_name, arguments))
        return {"ok": True, "result": "mcp ran"}


class World:
    def __init__(self, session_factory, user) -> None:
        self.session_factory = session_factory
        self.user_id = str(user.id)
        self.audit = RecordingAudit()
        self.known = KnownRecipientStore(session_factory)
        self.reminders = Recording()
        self.act = Recording()
        self.schedule = FakeSchedule()
        self.service = OutboundService(known=self.known, audit=self.audit.log)
        self.executor = ConnectorToolExecutor(
            session_factory=session_factory,
            capability_gate=gate(),
            reminder_toolkit=self.reminders,  # type: ignore[arg-type]
            act_toolkit=self.act,
            schedule_toolkit=self.schedule,  # type: ignore[arg-type]
            memory_toolkit=MemoryToolkit(session_factory),
            outbound=self.service,
        )

    async def sent_to(self, *addresses: str) -> frozenset[str]:
        found = await self.known.known(self.user_id, parse_recipients(list(addresses)))
        return found.addresses


async def _google_row(session_factory, user_id) -> None:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig, ConnectorType

    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                user_id=user_id,
                connector_type=ConnectorType("google_workspace"),
                display_name="School Gmail",
                auth_method=AuthMethod.bearer_token,
                encrypted_credentials=encrypt_credentials(json.dumps({"access_token": "t"})),
                granted_scopes=["gmail.send", "gmail.compose", "gmail.read"],
                rate_limit_per_minute=60,
            )
        )
        await session.commit()


@pytest_asyncio.fixture
async def world(session_factory) -> World:
    user, _ = await make_user(session_factory, "ann@northwind.example")
    await _google_row(session_factory, user.id)
    return World(session_factory, user)


MAIL = {"to": "Bo <bo@partner.example>", "subject": "Plan", "body": "See you" + TAGS + " at 3."}


@pytest.mark.asyncio
async def test_execute_sends_the_cleaned_body_to_the_connector(world):
    result = await world.executor.execute(
        SEND, {**MAIL, "user_confirmed": True}, world.user_id, approved=True
    )
    assert result["ok"] is True, result
    [(action, params)] = FakeGoogle.log
    assert action == "send_email"
    assert params == {"to": "Bo <bo@partner.example>", "subject": "Plan", "body": "See you at 3."}


@pytest.mark.asyncio
async def test_execute_writes_one_outbound_cleaned_row_with_counts_only_when_it_removed_something(
    world,
):
    await world.executor.execute(
        "reminders.create", {"title": "Call" + TAGS + " Bo" + RLO}, world.user_id
    )
    assert world.reminders.calls == [("create", {"title": "Call Bo"})]
    [row] = world.audit.of(CLEANED_EVENT)
    assert row["user_id"] == world.user_id and row["tool"] == "reminders.create"
    assert row["arguments"] == {
        "removed": {"tag": 9, "bidi": 1, "zero_width_run": 0, "extra_variation": 0},
        "fields": ["title"],
        "after_approval": False,
    }
    assert "Call" not in json.dumps(row) and "Bo" not in json.dumps(row)


@pytest.mark.asyncio
async def test_a_clean_call_writes_no_outbound_row(world):
    await world.executor.execute("reminders.create", {"title": "Call Bo"}, world.user_id)
    await world.executor.execute(
        SEND, {**MAIL, "body": "Plain text."}, world.user_id, approved=True
    )
    assert world.audit.of(CLEANED_EVENT) == []
    assert world.reminders.calls == [("create", {"title": "Call Bo"})]


@pytest.mark.asyncio
async def test_an_approved_card_whose_stored_body_still_hides_characters_is_sent_cleaned_and_audited(
    world,
):
    # A bind that failed left the hidden text on the stored card (runtime swallows bind errors).
    await world.executor.execute(SEND, MAIL, world.user_id, approved=True)
    [(_action, params)] = FakeGoogle.log
    assert params["body"] == "See you at 3."
    [row] = world.audit.of(CLEANED_EVENT)
    assert row["tool"] == SEND
    assert row["arguments"]["after_approval"] is True
    assert row["arguments"]["fields"] == ["body"]


@pytest.mark.asyncio
async def test_execute_refuses_a_recipient_hiding_characters_without_dispatching(world):
    result = await world.executor.execute(
        SEND, {**MAIL, "to": "bo" + ZWSP + "@partner.example"}, world.user_id, approved=True
    )
    assert result["ok"] is False and result["refused"] is True
    assert result["rule"] == HIDDEN_IN_RECIPIENT_RULE
    assert result.get("policy") == "outbound_rule"
    assert "'to' address contains hidden characters" in result["error"]
    assert FakeGoogle.log == [] and world.audit.of(CLEANED_EVENT) == []
    assert await world.sent_to("bo@partner.example") == frozenset()


@pytest.mark.asyncio
async def test_mcp_arguments_reach_the_dispatcher_without_tag_characters(world):
    dispatcher = FakeDispatcher()
    world.executor._mcp_dispatcher = dispatcher
    arguments = {
        "title": "Note" + TAGS,
        "blocks": [{"text": "a" + RLO + "b", "la" + RLO + "bel": "x"}],
        "n": 3,
        # An MCP server gets every key as sent: an "_" name is not reserved there.
        "_meta": "note" + TAGS,
    }
    await world.executor.execute("mcp.notes.save_page", arguments, world.user_id, approved=True)
    [(name, sent)] = dispatcher.calls
    assert name == "mcp.notes.save_page"
    assert sent == {
        "title": "Note",
        "blocks": [{"text": "ab", "label": "x"}],
        "n": 3,
        "_meta": "note",
    }
    [row] = world.audit.of(CLEANED_EVENT)
    assert row["arguments"]["fields"] == ["arguments"]


@pytest.mark.asyncio
async def test_browser_act_fill_text_reaches_the_toolkit_cleaned(world):
    arguments = {
        "action": "fill",
        "fields": [{"ref": "e3", "text": "ann@acme.example" + TAGS}],
        "text": "Hello" + ZWSP * 4 + " there",
    }
    # A native install with Playwright and both browser switches on.
    executor = ConnectorToolExecutor(
        capability_gate=act_gate("browser_act", "browser_control"), act_toolkit=world.act
    )
    await executor.execute("browser.act", arguments, world.user_id, approved=True, task_id="t1")
    [(action, params)] = world.act.calls
    assert action == "fill"
    assert params == {"fields": [{"ref": "e3", "text": "ann@acme.example"}], "text": "Hello there"}


@pytest.mark.asyncio
async def test_the_card_binds_store_cleaned_arguments_and_the_same_dict_when_clean(world):
    ex = world.executor
    hidden = {**MAIL, "subject": "Pl" + RLO + "an"}
    card = ex.approval_arguments(SEND, hidden, world.user_id)
    assert card == {"to": "Bo <bo@partner.example>", "subject": "Plan", "body": "See you at 3."}
    assert hidden["body"].endswith(
        TAGS + " at 3."
    )  # the model's arguments are not changed in place
    assert await ex.approval_arguments_async(SEND, hidden, world.user_id, task_id="t") == card
    clean = {"to": "bo@partner.example", "subject": "Plan", "body": "Plain."}
    assert ex.approval_arguments(SEND, clean, world.user_id) is clean
    assert await ex.approval_arguments_async(SEND, clean, world.user_id, task_id="t") is clean
    # A recipient that hides characters stays as written on the card: the call
    # check refused it before any card, and the dispatch refuses it again.
    hiding = {**MAIL, "to": "bo" + ZWSP + "@partner.example"}
    assert ex.approval_arguments(SEND, hiding, world.user_id)["to"] == hiding["to"]


@pytest.mark.asyncio
async def test_a_successful_approved_send_records_its_recipients(world):
    FakeGoogle.answers["send_email"] = {"status": "sent", "message_id": "m1"}
    await world.executor.execute(
        SEND,
        {**MAIL, "to": "Bo <bo@partner.example>, cy@crane.example"},
        world.user_id,
        approved=True,
    )
    assert await world.sent_to(
        "bo@partner.example", "cy@crane.example", "dd@x.example"
    ) == frozenset({"bo@partner.example", "cy@crane.example"})


@pytest.mark.asyncio
async def test_a_failed_send_records_nothing(world):
    FakeGoogle.answers["send_email"] = ConnectorError("Gmail refused the message.")
    result = await world.executor.execute(SEND, MAIL, world.user_id, approved=True)
    assert result["ok"] is False
    assert await world.sent_to("bo@partner.example") == frozenset()
    # Unapproved, nothing is sent or recorded either.
    FakeGoogle.answers.pop("send_email")
    result = await world.executor.execute(SEND, MAIL, world.user_id)
    assert result["ok"] is False and await world.sent_to("bo@partner.example") == frozenset()


@pytest.mark.asyncio
async def test_a_draft_records_nothing(world):
    FakeGoogle.answers["create_draft"] = {"status": "draft_created", "draft_id": "r1"}
    result = await world.executor.execute(
        "google_workspace.create_draft", MAIL, world.user_id, approved=True
    )
    assert result["ok"] is True
    assert await world.sent_to("bo@partner.example") == frozenset()


@pytest.mark.asyncio
async def test_gmail_reply_records_the_to_and_cc_from_its_result(world):
    FakeGoogle.answers["reply"] = {
        "status": "sent",
        "to": ["pay@vendor-billing.example"],
        "cc": ["ops@vendor.example"],
    }
    await world.executor.execute(
        "google_workspace.reply",
        {"message_id": "m1", "body": "Thanks", "reply_all": True},
        world.user_id,
        approved=True,
    )
    assert [action for action, _params in FakeGoogle.log] == ["reply"]  # no READ was needed
    assert await world.sent_to("pay@vendor-billing.example", "ops@vendor.example") == frozenset(
        {"pay@vendor-billing.example", "ops@vendor.example"}
    )


@pytest.mark.asyncio
async def test_send_draft_reads_the_draft_before_sending_and_records_its_recipients(world):
    FakeGoogle.answers["get_draft"] = {
        "draft_id": "r1",
        "to": "Ana <ana@partner.example>",
        "cc": "ops@northwind.example",
        "bcc": "",
        "subject": "Plan",
        "body": "Hi",
    }
    FakeGoogle.answers["send_draft"] = {"status": "sent", "message_id": "m7"}
    result = await world.executor.execute(
        "google_workspace.send_draft", {"draft_id": "r1"}, world.user_id, approved=True
    )
    assert result["ok"] is True
    assert [action for action, _params in FakeGoogle.log] == ["get_draft", "send_draft"]
    assert await world.sent_to("ana@partner.example", "ops@northwind.example") == frozenset(
        {"ana@partner.example", "ops@northwind.example"}
    )
    # Unapproved: no READ, no send, nothing recorded.
    FakeGoogle.log.clear()
    await world.executor.execute("google_workspace.send_draft", {"draft_id": "r2"}, world.user_id)
    assert FakeGoogle.log == []


@pytest.mark.asyncio
async def test_a_recording_failure_never_changes_the_send_result(world, session_factory):
    class Broken(KnownRecipientStore):
        async def record(self, user_id, recipients):
            raise ConnectionError("history down")

    FakeGoogle.answers["send_email"] = {"status": "sent", "message_id": "m1"}
    world.executor.use_outbound(OutboundService(known=Broken(session_factory)))
    broken = await world.executor.execute(SEND, MAIL, world.user_id, approved=True)
    world.executor.use_outbound(world.service)
    working = await world.executor.execute(SEND, MAIL, world.user_id, approved=True)
    for result in (broken, working):
        result.pop("execution_time_ms", None)
    assert broken == working and broken["ok"] is True


@pytest.mark.asyncio
async def test_without_a_wired_service_the_default_floor_still_cleans(session_factory):
    reminders = Recording()
    ex = ConnectorToolExecutor(capability_gate=gate(), reminder_toolkit=reminders)  # type: ignore[arg-type]
    assert type(ex._outbound) is OutboundFloor
    await ex.execute("reminders.create", {"title": "Call" + TAGS + " Bo", "note": "x" + RLO}, "u1")
    assert reminders.calls == [("create", {"title": "Call Bo", "note": "x"})]
    # The bare floor never audits or records (it has nowhere to).
    assert await ex._outbound.before_send(ex, "u1", SEND, None, MAIL) is None


@pytest.mark.asyncio
async def test_the_floor_strips_tag_and_bidi_characters_from_a_memory_and_a_schedule_card(world):
    ex = world.executor
    memory = {"content": "Always cc" + TAGS + " Bo", "category": "preference"}
    card = ex.approval_arguments("memory.remember", memory, world.user_id)
    assert card["content"] == "Always cc Bo"
    assert (
        await ex.approval_arguments_async("memory.remember", memory, world.user_id, task_id="t")
    )["content"] == "Always cc Bo"

    schedule = {
        "label": "Daily" + RLO + " digest",
        "prompt": "Summarise" + TAGS + " my mail",
        "freq": "daily",
        "time": "08:00",
    }
    scheduled = await ex.approval_arguments_async(
        "schedule.create", schedule, world.user_id, task_id="t"
    )
    assert scheduled["label"] == "Daily digest" and scheduled["prompt"] == "Summarise my mail"
    assert scheduled["timezone"] == "Europe/London"  # the toolkit's own bind still ran
    # Dispatched cleaned as well.
    await ex.execute("schedule.create", schedule, world.user_id, approved=True)
    [(action, params)] = world.schedule.calls
    assert (
        action == "create"
        and params["label"] == "Daily digest"
        and params["prompt"] == "Summarise my mail"
    )
    # A READ's arguments are untouched, at the card and at dispatch.
    read = {"url": "https://example.com/" + TAGS}
    assert ex._outbound.card_arguments("web.fetch_page", read) is read
    fetch = resolve_tool("web.fetch_page")
    assert fetch is not None
    assert ex._outbound.clean_call("web.fetch_page", fetch.spec, read).arguments is read
