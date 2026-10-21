"""Tests for the tool-rules call check inside the real agent runtime and executor
(services/security/tool_rules/check.py through services/security/call_checks.py): they prove a
low-risk draft to an address Crawler only read becomes a card naming the rule (also when the
address came from Crawler's own earlier reply, which the turn's taint tracker never sees), and
that card offers no low-risk grant and frees its low-risk slot; an auto-approved reminder an
owner rule matches becomes a card with exactly one escalation row; a send that already asks gets
the rule on its card and no extra row; a call no rule matches keeps its reason and audit rows
byte for byte; approving an escalated card runs the call once; an owner rule on a read parks
that read; the switch off means no rule applies and an unreadable switch counts as on; an
unreadable store asks before writes and lets reads run; MCP cards carry the owner rule's note;
an unattended run's own prompt counts as the owner's words; the executor backstop refuses an
unapproved write a rule matches (and a rule added mid-turn), never touches the internal reads,
and runs a person-approved call; a "*" rule never parks tools.find; a weekly app approval does
not run a desktop act a rule matches; a later check's refusal wins over a rule's escalation; an
address from a forwarded Telegram message breaks rule B1; and a card parked outside a turn gets
the owner rule's note.

Why it exists: decisions.md item 3. These are the places where a tool rule decides whether a
call runs without anyone looking; the pure tests prove which rules a call breaks, these prove
the break really turns into a card (or a refusal) and nothing else changes. Everything is faked:
a scripted model, recording executors and audit logs, in-memory approval and rule stores, and
the real Google connector behind an httpx MockTransport where a real executor runs.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import pytest

from core.config import settings
from services.agent import cancel
from services.agent.approvals import InMemoryApprovalStore
from services.agent.permission_grants import StandingConsent
from services.agent.providers import LLMResponse, ToolCall
from services.agent.risk import LOW_RISK_MAX_PER_TURN, RAN_WITHOUT_ASKING_HEADER
from services.agent.runtime import (
    PARKED_ROUND_POLICY,
    PARKED_ROUND_REASON,
    AgentRuntime,
    PrecheckRefusal,
    ran_beside_card_line,
)
from services.agent.shared_content import fence_forwarded
from services.agent.taint import TaintTracker
from services.agent.tool_registry import (
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    resolve_tool,
)
from services.agent.unattended import SeedResult, UnattendedRun
from services.security.call_checks import CallCheckPipeline, CallFacts, Escalate, Refuse, TurnFacts
from services.security.tool_rules import InMemoryToolRuleStore, ToolRulesCheck, texts
from services.security.tool_rules.engine import OwnerRule
from services.security.tool_rules.grammar import validate_rule
from tests.conftest import use_provider
from tests.test_call_checks import FakeCheck
from tests.test_call_checks_runtime import (
    AUTO_GOOGLE_TOOLS,
    DRAFT,
    DRAFT_ARGS,
    GOOGLE_TOOLS,
    READ,
    SEND,
    SEND_ARGS,
    BindingExecutor,
    Executor,
    generic,
    shape,
)
from tests.test_call_checks_runtime import RecordingAudit as CallAudit
from tests.test_computer_precheck import RecordingAudit, Script, call, calls
from tests.test_low_risk_runtime import FINAL, STAR, World, gate
from tests.test_low_risk_runtime import google as google  # noqa: F401 - fixture
from tests.test_low_risk_runtime import world as world  # noqa: F401 - fixture
from tests.test_weekly_app_approvals_runtime import (
    ACT,
    ANSWER,
    OBSERVE,
    TG,
    U1,
    Turn,
    calendar_desktop,
    refs_of,
)
from tests.test_weekly_app_approvals_runtime import (
    _computer_control_on as _computer_control_on,  # noqa: F401 - autouse fixture
)
from tests.test_weekly_app_approvals_runtime import (
    _no_stale_stop as _no_stale_stop,  # noqa: F401 - autouse fixture
)

USER = "rules-user"
B1 = texts.UNTRUSTED_RECIPIENT.name
B2 = texts.MANY_RECIPIENTS.name
PAYEE = "billing@paypa1-help.com"
DRAFTS_POST = "POST /gmail/v1/users/me/drafts"


@pytest.fixture(autouse=True)
def _no_stale_stop_for_user():
    cancel.clear(USER)
    yield
    cancel.clear(USER)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def owner_rule(name: str, tool: str, *conditions: dict[str, Any]) -> OwnerRule:
    """An owner rule exactly as the store would hold it after the validator."""
    draft = validate_rule(name, tool, list(conditions), existing=[])
    return OwnerRule(
        id=str(uuid.uuid4()),
        name=draft.name,
        tool=draft.tool,
        conditions=draft.conditions,
        created_at=datetime.now(timezone.utc),
    )


class LiveStore(InMemoryToolRuleStore):
    """The in-memory store, plus a way to add a rule from a synchronous model step (the owner
    saving a rule on the web while a turn runs)."""

    def add_now(self, rule: OwnerRule) -> None:
        self._rules.append(rule)


def rules_check(
    *rules: OwnerRule,
    store: Optional[InMemoryToolRuleStore] = None,
    enabled: Any = None,
    org_domains: Any = None,
) -> ToolRulesCheck:
    return ToolRulesCheck(
        store if store is not None else InMemoryToolRuleStore(rules), enabled=enabled, org_domains=org_domains
    )


class Harness:
    """One runtime with a scripted model, a recording executor (or the one given), a recording
    audit log, an in-memory approval store and the given call checks."""

    def __init__(self, *checks: Any, executor: Any = None) -> None:
        self.executor = executor if executor is not None else Executor()
        self.audit = CallAudit()
        self.approvals = InMemoryApprovalStore()
        self.events: list[dict[str, Any]] = []
        self.model = Script()
        self.runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(),
            tool_executor=self.executor,
            audit_service=self.audit,
            approval_store=self.approvals,
            call_checks=CallCheckPipeline(list(checks)) if checks else None,
        )

    async def chat(
        self,
        *steps: Any,
        messages: Optional[list[dict[str, Any]]] = None,
        tools: Any = GOOGLE_TOOLS,
        unattended: Optional[UnattendedRun] = None,
    ):
        self.model = Script(*steps)
        use_provider(self.runtime, self.model)

        async def sink(event: dict[str, Any]) -> None:
            self.events.append(event)

        extra = {"unattended": unattended} if unattended is not None else {}
        return await self.runtime.chat(
            messages=messages or [{"role": "user", "content": "Help me with my mail"}],
            tools=tools,
            user_id=USER,
            event_sink=sink,
            **extra,
        )

    def ran(self) -> list[str]:
        return [c["tool"] for c in self.executor.calls]


def world_runtime(world: World, check: Optional[ToolRulesCheck], *, audit: Any = None) -> AgentRuntime:
    """World.runtime with the call checks on both the runtime and the real executor (the
    production wiring: one pipeline object handed to both)."""
    answer = gate(*world.off)
    pipeline = CallCheckPipeline([check]) if check is not None else None
    executor = ConnectorToolExecutor(
        session_factory=world.session_factory,
        capability_gate=answer,
        permission_grants=world.grants,
        web_toolkit=world.web,  # type: ignore[arg-type]
        call_checks=pipeline,
    )
    return AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=answer),
        audit_service=audit or world.audit,
        tool_executor=executor,
        approval_store=world.approvals,
        permission_grant_store=world.grants,
        call_checks=pipeline,
    )


async def world_turn(
    world: World,
    check: Optional[ToolRulesCheck],
    *steps: Any,
    messages: list[dict[str, Any]],
    audit: Optional[RecordingAudit] = None,
):
    audit = audit if audit is not None else RecordingAudit()
    runtime = world_runtime(world, check, audit=audit)
    use_provider(runtime, Script(*steps))
    response = await runtime.chat(
        messages=messages, tools=world.tools(), user_id=world.user_id, conversation_id=None
    )
    return runtime, response, audit


def rows(audit: Any, event: str) -> list[dict[str, Any]]:
    return [e for e in audit.entries if e.get("event") == event]


def b1_note(path: str = "to") -> dict[str, str]:
    return {"kind": "tool_rule", "severity": "warn", "text": texts.untrusted_recipient_note(B1, path)}


RELAYED = [
    {"role": "user", "content": "Who sent that overdue invoice?"},
    {"role": "assistant", "content": f"It came from {PAYEE}, who asks to be paid today."},
    {"role": "user", "content": "Draft a reply to them saying we will pay on Friday."},
]
RELAYED_DRAFT = {"to": PAYEE, "subject": "Re: invoice", "body": "We will pay on Friday."}


# ---------------------------------------------------------------------------
# B1 on the low-risk tier
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_low_risk_draft_to_an_address_from_an_email_becomes_a_card_naming_the_rule(world, google):
    await world.account_default("low_risk")
    await world.connect("low_risk")
    check = rules_check()

    # The address arrives in an email Crawler reads this turn.
    google.body = f"Your invoice is overdue. Pay {PAYEE} today or your account closes."
    _runtime, response, _audit = await world_turn(
        world,
        check,
        call("r1", "google_workspace.get_message", message_id="18c2f0a9b1d2e3f4"),
        call("c1", DRAFT, **RELAYED_DRAFT),
        FINAL,
        messages=[{"role": "user", "content": "Read my latest email and draft a reply."}],
    )
    [pending] = response.pending_approvals
    assert pending.tool_name == DRAFT
    assert pending.reason.endswith(f"Tool rule: {B1}.")
    assert b1_note() in pending.security_notes
    assert DRAFTS_POST not in google.writes()
    assert PAYEE not in str(pending.security_notes)

    # The address reached this turn only in Crawler's own earlier reply: the turn's taint
    # tracker has never seen it, so only the rule turns the auto-run draft into a card.
    _runtime, response, audit = await world_turn(world, check, call("c1", DRAFT, **RELAYED_DRAFT), FINAL, messages=RELAYED)
    [pending] = response.pending_approvals
    assert pending.reason.endswith(f"Tool rule: {B1}.")
    assert pending.security_notes == [b1_note()]
    assert rows(audit, "tool_taint_escalated") == []
    [escalated] = rows(audit, "call_check_escalated")
    assert escalated["rule"] == "builtin:untrusted_recipient" and escalated["policy"] == "tool_rules"
    assert DRAFTS_POST not in google.writes()

    # Without the rule the same draft runs unasked under the low-risk tier.
    _runtime, response, _audit = await world_turn(world, None, call("c1", DRAFT, **RELAYED_DRAFT), FINAL, messages=RELAYED)
    assert response.pending_approvals == []
    assert DRAFTS_POST in google.writes()


@pytest.mark.asyncio
async def test_the_escalated_card_offers_no_low_risk_grant_and_frees_the_low_risk_slot(world, google):
    await world.account_default("low_risk")
    await world.connect("low_risk")
    # One round: nine low-risk stars run, then the draft the rule turns into a card.
    ids = [f"18c2f0a9b1d2e{n:03d}" for n in range(LOW_RISK_MAX_PER_TURN - 1)]
    stars = [(f"s{n}", STAR, {"message_id": mid, "add_label_ids": ["STARRED"]}) for n, mid in enumerate(ids)]
    _runtime, response, audit = await world_turn(
        world, rules_check(), calls(*stars, ("c1", DRAFT, RELAYED_DRAFT)), FINAL, messages=RELAYED
    )
    [pending] = response.pending_approvals
    assert pending.tool_name == DRAFT
    assert pending.low_risk_account is None and pending.weekly_app is None
    [stored] = await world.approvals.list_pending(world.user_id)
    assert stored.grant_offer is None
    assert DRAFTS_POST not in google.writes()
    assert [w for w in google.writes() if w.endswith("/modify")] == [
        f"POST /gmail/v1/users/me/messages/{mid}/modify" for mid in ids
    ]
    # The draft is not counted as a change made without asking (main's plain-language
    # summary under services/agent/risk.py RAN_WITHOUT_ASKING_HEADER).
    assert response.content.endswith(f"- Change labels on an email (School Gmail), {len(ids)} times")
    assert "draft" not in response.content.split(RAN_WITHOUT_ASKING_HEADER)[1]
    [escalated] = rows(audit, "call_check_escalated")
    assert escalated["tool"] == DRAFT
    executing = [r["tool"] for r in rows(audit, "tool_executing")]
    assert DRAFT not in executing and executing.count(STAR) == len(ids)

    # The slot itself: the low-risk run the tier counted for the draft is handed back once the
    # rule's verdict escalates it, and its card offers no grant.
    consent = StandingConsent(user_id=world.user_id, grants=None)
    tc = ToolCall(id="c1", name=DRAFT, arguments=dict(RELAYED_DRAFT))

    class Offered:
        permission_tier = "low_risk"
        connector_id = "conn-1"
        account = "School Gmail"

    permission, via_tier = await consent.decide(tc, Offered(), "requires_approval", False, unattended=False, results=[])
    assert (permission, via_tier, consent.count) == ("approved", True, 1)
    verdict = await rules_check().check(
        CallFacts(
            stage="turn", user_id=world.user_id, tool_name=DRAFT, canonical=DRAFT, arguments=tc.arguments,
            spec=resolve_tool(DRAFT).spec, runs_without_card=True,  # type: ignore[union-attr]
            turn=TurnFacts(messages=RELAYED, taint=TaintTracker()),
        )
    )
    assert isinstance(verdict, Escalate) and verdict.rule == "builtin:untrusted_recipient"
    consent.withdraw(tc)
    assert consent.count == 0 and consent.audit_fields(tc) == {}
    _note, extra = await consent.card_fields(tc, None, None, {}, accepts_offer=True)
    assert "grant_offer" not in extra


# ---------------------------------------------------------------------------
# Auto-run calls, carded calls, untouched calls
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_auto_approved_reminder_matching_an_owner_rule_becomes_a_card_with_one_escalation_row():
    rule = owner_rule("Wire reminders", "reminders.create", {"arg": "title", "op": "contains", "value": "wire"})
    harness = Harness(rules_check(rule))
    tools = build_tools([], include_builtins=True)
    title = "Wire the deposit to the new account"
    response = await harness.chat(call("c1", "reminders.create", title=title, delay_minutes=30), FINAL, tools=tools)
    assert harness.ran() == []
    [pending] = response.pending_approvals
    assert pending.tool_name == "reminders.create"
    assert pending.reason.endswith(". Tool rule: Wire reminders.")
    assert pending.security_notes == [
        {"kind": "tool_rule", "severity": "warn", "text": 'Your tool rule "Wire reminders": "title" contains "wire".'}
    ]
    [row] = harness.audit.rows("call_check_escalated")
    assert row["tool"] == "reminders.create" and row["policy"] == "tool_rules" and row["check"] == "tool_rules"
    assert row["rule"] == f"owner:{rule.id}" and row["reason"] == "Tool rule: Wire reminders."
    assert row["arguments"] == {"checks": ["tool_rules"], "rules": [f"owner:{rule.id}"], "notes": 1}
    assert row["note_kinds"] == ["tool_rule"]
    assert title not in str(row) and "deposit" not in str(row)
    [pending_row] = harness.audit.rows("tool_pending_approval")
    assert pending_row["rule"] == f"owner:{rule.id}"

    # A reminder the rule does not match still runs without a card.
    response = await harness.chat(call("c2", "reminders.create", title="Dentist", delay_minutes=30), FINAL, tools=tools)
    assert response.pending_approvals == [] and harness.ran() == ["reminders.create"]
    assert len(harness.audit.rows("call_check_escalated")) == 1


@pytest.mark.asyncio
async def test_a_send_that_already_asks_gets_the_rule_on_its_card_and_no_extra_audit_row():
    harness = Harness(rules_check())
    to = ", ".join(f"guest{n}@example.com" for n in range(11))
    args = {"to": to, "subject": "Party", "body": "Saturday at 8"}
    response = await harness.chat(call("c1", SEND, **args))
    [pending] = response.pending_approvals
    assert pending.reason == f"{generic(SEND, args)}. Tool rule: {B2}."
    assert pending.security_notes == [
        {"kind": "tool_rule", "severity": "warn", "text": texts.many_recipients_note(B2, 11)}
    ]
    assert harness.audit.rows("call_check_escalated") == []
    [row] = harness.audit.rows("tool_pending_approval")
    assert row["rule"] == "builtin:many_recipients" and row["note_kinds"] == ["tool_rule"]
    [streamed] = [e["data"] for e in harness.events if e["type"] == "pending_approval"]
    assert streamed["reason"] == pending.reason and streamed["security_notes"] == pending.security_notes
    # Ten people is not more than ten.
    ten = {"to": ", ".join(to.split(", ")[:10]), "subject": "Party", "body": "Sat"}
    response = await harness.chat(call("c2", SEND, **ten))
    [pending] = response.pending_approvals
    assert pending.reason == generic(SEND, ten) and pending.security_notes == []


@pytest.mark.asyncio
async def test_a_call_no_rule_matches_keeps_its_card_reason_and_audit_events_exactly_as_before():
    elsewhere = owner_rule("Large refunds", "mcp.stripe.*", {"arg": "amount", "op": "number_gt", "value": 500})
    outcomes = []
    for checks in ((), (rules_check(elsewhere),)):
        harness = Harness(*checks)
        response = await harness.chat(
            call("r1", READ, message_id="m1"),
            call("c1", DRAFT, **DRAFT_ARGS),
            call("c2", SEND, **SEND_ARGS),
            tools=AUTO_GOOGLE_TOOLS,
        )
        [pending] = response.pending_approvals
        [stored] = await harness.approvals.list_pending(USER)
        outcomes.append(
            (
                shape(harness.audit.entries),
                harness.ran(),
                pending.reason,
                pending.security_notes,
                stored.grant_offer,
                [e["type"] for e in harness.events],
            )
        )
    assert outcomes[0] == outcomes[1]
    audit_shape, ran, reason, notes, _offer, _events = outcomes[0]
    assert ran == [READ, DRAFT] and reason == generic(SEND) and notes == []
    assert "call_check_escalated" not in str(audit_shape) and "'rule'" not in str(audit_shape)


@pytest.mark.asyncio
async def test_approving_an_escalated_card_runs_the_call_once_and_the_rule_does_not_ask_again(world, google):
    await world.account_default("auto_approve")
    await world.connect("auto_approve")
    rule = owner_rule("Drafts to example", DRAFT, {"arg": "to", "op": "domain_in", "value": ["example.com"]})
    check = rules_check(rule)
    runtime, response, audit = await world_turn(
        world, check, call("c1", DRAFT, **DRAFT_ARGS), FINAL,
        messages=[{"role": "user", "content": "Draft a note to my colleague."}],
    )
    [pending] = response.pending_approvals
    assert pending.reason.endswith("Tool rule: Drafts to example.")
    assert google.writes() == []

    result = await runtime.approve_action(pending.action_id, world.user_id)
    assert "error" not in result and result["result"].get("requires_approval") is None
    assert google.writes() == [DRAFTS_POST]
    assert rows(audit, "tool_blocked") == []
    # The card is single-use: the call never runs a second time.
    again = await runtime.approve_action(pending.action_id, world.user_id)
    assert "error" in again
    assert google.writes() == [DRAFTS_POST]


@pytest.mark.asyncio
async def test_an_owner_rule_on_a_read_parks_the_read_and_records_the_rest_of_the_round_as_not_run():
    rule = owner_rule("Ask before opening mail", READ)
    harness = Harness(rules_check(rule))
    response = await harness.chat(
        calls(
            ("r1", "google_workspace.get_messages", {}),
            ("r2", READ, {"message_id": "m1"}),
            ("r3", "google_workspace.get_thread", {"thread_id": "t1"}),
        ),
        LLMResponse(content="never reached"),
    )
    [pending] = response.pending_approvals
    assert pending.tool_name == READ and pending.reason.endswith("Tool rule: Ask before opening mail.")
    # The read before it ran; the parked read did not; the read after it is recorded as not run
    # (the turn ends on the card, so the model would never see what it returned).
    assert harness.ran() == ["google_workspace.get_messages"]
    assert len(harness.model.calls) == 1
    assert ran_beside_card_line(["google_workspace.get_messages"]) in response.content
    [not_run] = harness.audit.rows("tool_blocked")
    assert not_run["tool"] == "google_workspace.get_thread"
    assert (not_run["policy"], not_run["reason"]) == (PARKED_ROUND_POLICY, PARKED_ROUND_REASON)
    assert response.blocked_actions == []
    [row] = harness.audit.rows("call_check_escalated")
    assert row["tool"] == READ and row["rule"] == f"owner:{rule.id}"


# ---------------------------------------------------------------------------
# The switch and the store
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_with_the_tool_rules_switch_off_no_rule_applies():
    async def off() -> bool:
        return False

    store = InMemoryToolRuleStore([owner_rule("Every draft", DRAFT)])
    harness = Harness(rules_check(store=store, enabled=off))
    response = await harness.chat(call("c1", DRAFT, **DRAFT_ARGS), FINAL, tools=AUTO_GOOGLE_TOOLS)
    assert response.pending_approvals == [] and harness.ran() == [DRAFT]
    to = ", ".join(f"guest{n}@example.com" for n in range(11))
    args = {"to": to, "subject": "Hi", "body": "Hi"}
    [pending] = (await harness.chat(call("c2", SEND, **args))).pending_approvals
    assert pending.reason == generic(SEND, args) and pending.security_notes == []
    assert store.snapshot_reads == 0
    assert harness.audit.rows("call_check_escalated") == []


@pytest.mark.asyncio
async def test_an_unreadable_switch_counts_as_on():
    async def broken() -> bool:
        raise RuntimeError("installation unreadable")

    harness = Harness(rules_check(owner_rule("Every draft", DRAFT), enabled=broken))
    response = await harness.chat(call("c1", DRAFT, **DRAFT_ARGS), FINAL, tools=AUTO_GOOGLE_TOOLS)
    [pending] = response.pending_approvals
    assert pending.reason.endswith("Tool rule: Every draft.") and harness.ran() == []


@pytest.mark.asyncio
async def test_an_unreadable_rule_store_asks_before_every_write_and_lets_reads_run():
    store = InMemoryToolRuleStore(error=True)
    harness = Harness(rules_check(store=store))
    response = await harness.chat(
        call("r1", READ, message_id="m1"), call("c1", DRAFT, **DRAFT_ARGS), FINAL, tools=AUTO_GOOGLE_TOOLS
    )
    assert harness.ran() == [READ]
    [pending] = response.pending_approvals
    assert pending.tool_name == DRAFT
    assert pending.reason.endswith(f"Tool rule: {texts.UNAVAILABLE_NAME}.")
    assert pending.security_notes == [{"kind": "tool_rule", "severity": "warn", "text": texts.UNAVAILABLE_NOTE}]
    [row] = harness.audit.rows("call_check_escalated")
    assert row["rule"] == "tool_rules:unavailable"
    # The snapshot is read once for the whole turn.
    assert store.snapshot_reads == 1


@pytest.mark.asyncio
async def test_an_mcp_tool_card_carries_the_owner_rule_note():
    rule = owner_rule("Issues about payroll", "mcp.github.*", {"arg": "title", "op": "contains", "value": "payroll"})
    harness = Harness(rules_check(rule))
    tool = "mcp.github.create_issue"
    response = await harness.chat(call("c1", tool, title="Payroll export broken", body="See attached"), FINAL)
    [pending] = response.pending_approvals
    assert pending.tool_name == tool
    assert pending.reason == f"{generic(tool)}. Tool rule: Issues about payroll."
    assert pending.security_notes == [
        {"kind": "tool_rule", "severity": "warn", "text": 'Your tool rule "Issues about payroll": "title" contains "payroll".'}
    ]
    # MCP tools always ask, so this only adds the reason and the note: no escalation row.
    assert harness.audit.rows("call_check_escalated") == [] and harness.ran() == []
    other = await harness.chat(call("c2", tool, title="Docs typo", body="x"), FINAL)
    [pending] = other.pending_approvals
    assert pending.reason == generic(tool) and pending.security_notes == []


@pytest.mark.asyncio
async def test_an_unattended_run_turns_a_rule_hit_into_an_origin_card_and_its_prompt_counts_as_the_owners_words():
    harness = Harness(rules_check())
    run = UnattendedRun(
        label="Weekly report",
        origin="schedule:77",
        reads=frozenset(),
        writes=frozenset({DRAFT}),
        trusted_text="Draft the weekly report to ann@client.example",
        seed_results=(SeedResult("contacts", "Report contacts: ann@client.example, eve@evil.example"),),
    )
    cards = []
    for to in ("ann@client.example", "eve@evil.example"):
        response = await harness.chat(
            call("c1", DRAFT, to=to, subject="Weekly report", body="Attached."), FINAL, unattended=run
        )
        cards.extend(response.pending_approvals)
    to_ann, to_eve = cards
    stored = {s.arguments["to"]: s for s in await harness.approvals.list_pending(USER)}
    assert set(stored) == {"ann@client.example", "eve@evil.example"}
    assert {s.origin for s in stored.values()} == {"schedule:77"}
    # The run's own approved prompt named ann: her draft carries no tool-rule note.
    assert "Tool rule" not in to_ann.reason and to_ann.security_notes == []
    # eve came only from the trigger's data: rule B1 names itself on her card.
    assert to_eve.reason.endswith(f"Tool rule: {B1}.") and to_eve.security_notes == [b1_note()]
    assert harness.audit.rows("call_check_escalated") == [] and harness.ran() == []


# ---------------------------------------------------------------------------
# The executor backstop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_executor_refuses_an_unapproved_write_an_owner_rule_matches_and_runs_an_approved_one(world, google):
    await world.connect("user_confirm")
    rule = owner_rule("Drafts to example", DRAFT, {"arg": "to", "op": "domain_in", "value": ["example.com"]})
    executor = world_runtime(world, rules_check(rule))._executor  # the one main.py would share
    refusal = {
        "ok": False,
        "requires_approval": True,
        "call_check": "tool_rules",
        "policy": "tool_rules",
        "rule": f"owner:{rule.id}",
        "error": texts.EXECUTE_REFUSAL,
    }
    assert await executor.execute(DRAFT, dict(DRAFT_ARGS), world.user_id, approved=False) == refusal
    # Standing consent is not a person: a tier or low-risk run is refused the same way.
    for kind in ("tier", "low_risk"):
        result = await executor.execute(DRAFT, dict(DRAFT_ARGS), world.user_id, approved=True, approval=kind)
        assert result == refusal
    assert "Drafts to example" not in str(refusal)  # the model never learns the rule's name
    assert google.writes() == []
    # A call the owner approved on a card runs.
    result = await executor.execute(DRAFT, dict(DRAFT_ARGS), world.user_id, approved=True)
    assert result.get("requires_approval") is None
    assert google.writes() == [DRAFTS_POST]


@pytest.mark.asyncio
async def test_the_executor_backstop_never_touches_the_briefing_and_trigger_reads(world, google):
    await world.connect("user_confirm")
    # A rule that asks before every call, and a store that cannot be read: neither may break the
    # reads the briefing, the triggers, the knowledge base and the tutor routes make directly.
    for store in (InMemoryToolRuleStore([owner_rule("Everything", "*")]), InMemoryToolRuleStore(error=True)):
        check = rules_check(store=store)
        executor = world_runtime(world, check)._executor
        listed = await executor.execute(
            "google_workspace.get_messages", {}, world.user_id, task_id="unattended:briefing-1"
        )
        assert listed.get("requires_approval") is None and listed.get("ok") is not False
        one = await executor.execute(
            "google_workspace.get_message", {"message_id": "18c2f0a9b1d2e3f4"}, world.user_id, approved=False
        )
        assert one.get("requires_approval") is None and one.get("ok") is not False
        assert store.snapshot_reads == 0
        for tool in ("canvas.get_courses", "knowledge.search", "google_workspace.get_messages"):
            resolved = resolve_tool(tool)
            assert resolved is not None
            facts = CallFacts(
                stage="execute", user_id=world.user_id, tool_name=tool, canonical=tool, arguments={},
                spec=resolved.spec, runs_without_card=True,
            )
            assert check.applies_to(facts) is False
    assert google.writes() == []


@pytest.mark.asyncio
async def test_a_rule_added_mid_turn_is_seen_by_the_executor_backstop(world, google):
    await world.account_default("auto_approve")
    await world.connect("auto_approve")
    store = LiveStore()
    rule = owner_rule("Drafts to example", DRAFT, {"arg": "to", "op": "domain_in", "value": ["example.com"]})

    def owner_saves_a_rule() -> LLMResponse:
        store.add_now(rule)  # saved on the web after this turn's first check read the snapshot
        return call("c1", DRAFT, **DRAFT_ARGS)

    _runtime, response, audit = await world_turn(
        world,
        rules_check(store=store),
        call("r1", "google_workspace.get_messages"),
        owner_saves_a_rule,
        FINAL,
        messages=[{"role": "user", "content": "Check my mail and draft a note."}],
    )
    # The turn's check still used the snapshot it read first; the backstop read the new rule.
    assert response.pending_approvals == []
    assert DRAFTS_POST not in google.writes()
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [(DRAFT, "tool_rules")]
    [blocked] = rows(audit, "tool_blocked")
    assert blocked["rule"] == f"owner:{rule.id}" and blocked["policy"] == "tool_rules"
    assert blocked["reason"] == texts.EXECUTE_REFUSAL


# ---------------------------------------------------------------------------
# Runtime-answered tools, weekly approvals and other checks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_star_rule_never_parks_tools_find():
    check = rules_check(owner_rule("Everything", "*"))
    harness = Harness(check)
    tools = build_tools([ConnectorSpec("google_workspace")])
    response = await harness.chat(call("f1", "tools.find", query="calendar"), LLMResponse(content="ok"), tools=tools)
    assert response.pending_approvals == [] and response.blocked_actions == []
    assert [tc["name"] for tc in response.tool_calls] == ["tools.find"]
    for name in ("tools.find", "tutor.start", "tutor.stop"):
        for stage in ("turn", "execute"):
            facts = CallFacts(stage=stage, user_id=USER, tool_name=name, canonical=name, arguments={})
            assert check.applies_to(facts) is False
    # The same rule does ask before an ordinary call.
    [pending] = (await harness.chat(call("r1", READ, message_id="m1"), FINAL)).pending_approvals
    assert pending.reason.endswith("Tool rule: Everything.")


@pytest.mark.asyncio
async def test_a_weekly_app_approval_does_not_run_a_desktop_act_a_rule_matches():
    refs = await refs_of()
    turn = Turn(calendar_desktop())
    await turn.app_store.allow(user_id=U1, app="Calendar", channel=TG)
    rule = owner_rule("Clicks in apps", ACT, {"arg": "action", "op": "equals", "value": "click"})
    turn.runtime.use_call_checks(CallCheckPipeline([rules_check(rule)]))
    response = await turn.run(OBSERVE, call("a1", ACT, action="click", ref=refs["next"]), ANSWER)
    [pending] = response.pending_approvals
    assert pending.tool_name == ACT
    assert pending.reason.endswith("Tool rule: Clicks in apps.")
    # The weekly approval did not run the act, and the card offers no weekly button.
    assert turn.fake.events == []
    assert pending.weekly_app is None
    [row] = turn.act_rows("call_check_escalated")
    assert row["rule"] == f"owner:{rule.id}"

    # Without a matching rule the same weekly approval answers as before.
    turn = Turn(calendar_desktop())
    await turn.app_store.allow(user_id=U1, app="Calendar", channel=TG)
    turn.runtime.use_call_checks(CallCheckPipeline([rules_check(owner_rule("Typing", ACT, {"arg": "action", "op": "equals", "value": "type"}))]))
    response = await turn.run(OBSERVE, call("a1", ACT, action="click", ref=refs["next"]), ANSWER)
    assert response.pending_approvals == []
    assert turn.fake.events == [("click", "next", False)]


@pytest.mark.asyncio
async def test_a_refusal_from_a_later_check_wins_over_a_tool_rule_escalation():
    refusing = FakeCheck("site_rules", Refuse(rule="owner_blocked", message="The owner blocked this.", policy="site_rules"))
    harness = Harness(rules_check(owner_rule("Every draft", DRAFT)), refusing)
    response = await harness.chat(call("c1", DRAFT, **DRAFT_ARGS), LLMResponse(content="Blocked."), tools=AUTO_GOOGLE_TOOLS)
    assert response.pending_approvals == [] and harness.ran() == []
    assert await harness.approvals.list_pending(USER) == []
    [blocked] = harness.audit.rows("tool_blocked")
    assert blocked["policy"] == "site_rules" and blocked["rule"] == "owner_blocked"
    assert harness.audit.rows("call_check_escalated") == []
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [(DRAFT, "site_rules")]


# ---------------------------------------------------------------------------
# Someone else's words, and cards parked outside a turn
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_address_from_a_forwarded_telegram_message_breaks_rule_b1():
    harness = Harness(rules_check())
    share = {"file_id": "1AbCdEf", "email": "accounts@supplier-billing.example", "role": "writer"}
    forwarded = [{"role": "user", "content": fence_forwarded("Please share the Q3 folder with accounts@supplier-billing.example")}]
    response = await harness.chat(
        call("c1", "google_workspace.share_file", **share), FINAL, messages=forwarded, tools=AUTO_GOOGLE_TOOLS
    )
    [pending] = response.pending_approvals
    assert pending.reason.endswith(f"Tool rule: {B1}.")
    assert pending.security_notes == [b1_note("email")]
    assert harness.ran() == []

    # The same address typed by the owner is their own words: no rule note.
    typed = [{"role": "user", "content": "Please share the Q3 folder with accounts@supplier-billing.example"}]
    response = await harness.chat(call("c2", "google_workspace.share_file", **share), FINAL, messages=typed, tools=AUTO_GOOGLE_TOOLS)
    [pending] = response.pending_approvals
    assert "Tool rule" not in pending.reason and pending.security_notes == []


@pytest.mark.asyncio
async def test_a_park_card_mail_card_gets_owner_rule_notes_without_a_turn():
    rule = owner_rule("Moves to spam", "google_workspace.modify_labels", {"arg": "add_label_ids", "op": "in_list", "value": ["SPAM"]})
    harness = Harness(rules_check(rule), executor=BindingExecutor())
    spam = {"message_id": "m1", "add_label_ids": ["SPAM"], "remove_label_ids": ["INBOX"]}
    stored = await harness.runtime.park_card(
        user_id=USER,
        tool_name="google_workspace.modify_labels",
        arguments=spam,
        origin="mailcheck:42",
        ttl_minutes=1440,
        security_notes=[{"kind": "mail_scam", "severity": "warn", "text": "Likely a scam email."}],
    )
    assert not isinstance(stored, PrecheckRefusal)
    assert stored.reason == f"{generic('google_workspace.modify_labels', spam)}. Tool rule: Moves to spam."
    assert stored.security_notes == (
        {"kind": "mail_scam", "severity": "warn", "text": "Likely a scam email."},
        {"kind": "tool_rule", "severity": "warn", "text": 'Your tool rule "Moves to spam": "add_label_ids" is one of "SPAM".'},
    )
    assert "check_failed" not in str(stored.security_notes)
    [row] = harness.audit.rows("tool_pending_approval")
    assert row["rule"] == f"owner:{rule.id}" and row["origin"] == "mailcheck:42"
    assert harness.audit.rows("call_check_escalated") == []
