"""Tests for the call checks' executor backstop and S1's outbound floor in
ConnectorToolExecutor (services/agent/tool_registry.py): they prove the backstop runs
before the MCP branch and answers in the call-check shape; a call no person approved
that a check escalates is answered requires_approval and never dispatched; a
person-approved call is stopped only by a refusal; internal reads keep working when a
check breaks; an executor without a pipeline builds nothing and dispatches as before;
the floor runs on the MCP and connector paths and at both card binds, refuses
(fail closed, in the call-check shape so it is filed as a block) when it says so or
breaks, and the WAVE 0 stub changes nothing; a non-object argument for an MCP or known
tool is refused before the checks, the floor and the dispatch, while an unknown name
still gets today's answer; and a weekly act is never person-approved to the backstop.

Why it exists: the backstop is the last word before anything runs for every caller
(approved cards, standing consent, unattended runs, weekly acts, internal reads), so
its order and its fail-closed rules are pinned here with recording toolkits; nothing
reaches a network.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

import pytest

from services.agent.tool_registry import (
    OUTBOUND_CLEAN_FAILED,
    OUTBOUND_CLEAN_FAILED_RULE,
    OUTBOUND_FLOOR_CHECK,
    OUTBOUND_FLOOR_POLICY,
    ConnectorToolExecutor,
    resolve_tool,
)
from services.security.call_checks import (
    ARGUMENTS_NOT_OBJECT_REFUSAL,
    ARGUMENTS_NOT_OBJECT_RULE,
    CHECK_FAILED_REFUSAL,
    CHECK_FAILED_RULE,
    PIPELINE_CHECK,
    CallCheckPipeline,
    CallFacts,
    Escalate,
    Refuse,
    call_check_refusal,
)
from services.security.outbound import (
    CHECK_NAME,
    OUTBOUND_RULE_POLICY,
    CleanedCall,
    OutboundCheck,
    OutboundFloor,
    OutboundService,
)
from tests.test_call_checks import FakeCheck, facts, note
from tests.test_low_risk_runtime import gate

USER = "exec-user"
# Always on, and a write the executor runs unapproved: without the
# backstop it would be dispatched.
REMIND = "reminders.create"
REMIND_ARGS = {"text": "Call the dentist", "when": "2026-10-15T09:00:00"}
PAGE = "web.fetch_page"


class Recording:
    """A built-in toolkit stand-in that records what it is asked to run."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, action: str, params: dict[str, Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((action, dict(params)))
        return {"ok": True, "action": action}


class FakeDispatcher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, tool_name: str, arguments: dict[str, Any], user_id: str) -> dict[str, Any]:
        self.calls.append((tool_name, arguments))
        return {"ok": True, "result": "mcp ran"}


class RecordingFloor(OutboundFloor):
    """The bare floor, recording every hook; *refuse* or *explode* make
    clean_call refuse or raise."""

    def __init__(self, *, refuse: bool = False, explode: bool = False, rewrite: bool = False) -> None:
        self.cleaned: list[tuple[str, Any, dict[str, Any]]] = []
        self.noted: list[tuple[str, bool]] = []
        self.carded: list[str] = []
        self.sent: list[tuple[str, Any]] = []
        self.refuse, self.explode, self.rewrite = refuse, explode, rewrite

    def clean_call(self, tool_name, spec, arguments):
        self.cleaned.append((tool_name, spec, dict(arguments)))
        if self.explode:
            raise RuntimeError("floor broke")
        if self.refuse:
            return CleanedCall(arguments, {}, (), {"ok": False, "refused": True, "rule": "hidden", "error": "No."})
        if self.rewrite:
            return CleanedCall({**arguments, "description": "cleaned"}, {"tag": 2}, ("description",), None)
        return super().clean_call(tool_name, spec, arguments)

    def card_arguments(self, tool_name, arguments):
        self.carded.append(tool_name)
        return super().card_arguments(tool_name, arguments)

    async def note_cleaned(self, user_id, tool_name, cleaned, *, approved):
        self.noted.append((tool_name, approved))

    async def after_send(self, user_id, tool_name, spec, arguments, result, ticket):
        self.sent.append((tool_name, ticket))


def executor(*checks: FakeCheck, floor: Optional[OutboundFloor] = None, pipeline: Any = None, **kw: Any):
    reminders, web = Recording(), Recording()
    ex = ConnectorToolExecutor(
        session_factory=kw.pop("session_factory", None),
        capability_gate=gate(),
        reminder_toolkit=reminders,  # type: ignore[arg-type]
        web_toolkit=web,  # type: ignore[arg-type]
        call_checks=pipeline if pipeline is not None else (CallCheckPipeline(list(checks)) if checks else None),
        outbound=floor,
    )
    return ex, reminders, web


def with_fake_mcp(ex: ConnectorToolExecutor) -> FakeDispatcher:
    dispatcher = FakeDispatcher()
    ex._session_factory = object()  # never opened: the dispatcher is faked
    ex._mcp_dispatcher = dispatcher
    return dispatcher


# ── the backstop ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_backstop_runs_before_the_mcp_branch_and_refuses_in_the_call_check_shape():
    refusing = FakeCheck("mcp_pin", Refuse(rule="tool_changed", message="This MCP tool changed.", policy="mcp_pin"))
    ex, _reminders, _web = executor(refusing)
    dispatcher = with_fake_mcp(ex)
    result = await ex.execute("mcp.notes.save", {"text": "hi", "user_confirmed": True}, USER, approved=True)
    assert result == {
        "ok": False,
        "refused": True,
        "call_check": "mcp_pin",
        "policy": "mcp_pin",
        "rule": "tool_changed",
        "error": "This MCP tool changed.",
    }
    assert dispatcher.calls == []
    [seen] = refusing.calls
    assert seen.stage == "execute" and seen.is_mcp and seen.spec is None
    # MCP arguments reach the check as sent (nothing of theirs is stripped).
    assert dict(seen.arguments) == {"text": "hi", "user_confirmed": True}
    assert seen.person_approved and not seen.runs_without_card and seen.approval is None
    # Even before the "not configured" answer an executor without a database gives.
    bare, _w, _b = executor(refusing)
    assert (await bare.execute("mcp.notes.save", {}, USER))["call_check"] == "mcp_pin"


@pytest.mark.asyncio
async def test_an_unapproved_write_a_check_escalates_answers_requires_approval_and_is_not_dispatched():
    escalating = FakeCheck(
        "tool_rules",
        Escalate((note("tool_rule", "warn"),), "A rule asks.", rule="owner:1", refusal_text="Ask the owner first."),
    )
    ex, reminders, _web = executor(escalating)
    result = await ex.execute(REMIND, {**REMIND_ARGS, "user_confirmed": True}, USER)
    assert result == {
        "ok": False,
        "requires_approval": True,
        "call_check": "tool_rules",
        "policy": "tool_rules_policy",
        "rule": "owner:1",
        "error": "Ask the owner first.",
    }
    assert reminders.calls == []
    [seen] = escalating.calls
    # The model's user_confirmed never reaches a check, and no person approved.
    assert dict(seen.arguments) == REMIND_ARGS
    assert seen.runs_without_card and not seen.person_approved
    assert seen.canonical == REMIND and seen.spec is resolve_tool(REMIND).spec  # type: ignore[union-attr]
    # Standing consent is not a person's approval either.
    result = await ex.execute(REMIND, REMIND_ARGS, USER, approved=True, approval="tier")
    assert result["requires_approval"] is True and result["call_check"] == "tool_rules"
    assert escalating.calls[-1].approval == "tier" and escalating.calls[-1].runs_without_card


@pytest.mark.asyncio
async def test_a_person_approved_call_is_refused_only_by_a_refuse():
    escalating = FakeCheck("tool_rules", Escalate((), "A rule asks.", rule="owner:1"))
    ex, reminders, _web = executor(escalating)
    result = await ex.execute(REMIND, REMIND_ARGS, USER, approved=True)
    assert result["ok"] is True and reminders.calls == [("create", REMIND_ARGS)]

    refusing = FakeCheck("site_rules", Refuse(rule="owner_blocked", message="Blocked."))
    ex, reminders, _web = executor(refusing)
    result = await ex.execute(REMIND, REMIND_ARGS, USER, approved=True)
    assert result["refused"] is True and result["call_check"] == "site_rules"
    assert reminders.calls == []


@pytest.mark.asyncio
async def test_internal_reads_keep_working_when_a_check_raises():
    ex, reminders, web = executor(FakeCheck("tool_rules", RuntimeError("rules store down")))
    read = await ex.execute(PAGE, {"url": "https://example.com/"}, USER)
    assert read["ok"] is True and [c[0] for c in web.calls] == ["fetch_page"]
    write = await ex.execute(REMIND, REMIND_ARGS, USER, approved=True)
    assert write == {
        "ok": False,
        "refused": True,
        "call_check": "tool_rules",
        "policy": PIPELINE_CHECK,
        "rule": CHECK_FAILED_RULE,
        "error": CHECK_FAILED_REFUSAL,
    }
    assert reminders.calls == []


@pytest.mark.asyncio
async def test_an_executor_without_a_pipeline_dispatches_exactly_as_before():
    answers = []
    for pipeline in (None, CallCheckPipeline(), CallCheckPipeline([FakeCheck("outbound", applies=False)])):
        ex, reminders, web = executor(pipeline=pipeline)
        answers.append(
            (
                await ex.execute(REMIND, REMIND_ARGS, USER),
                await ex.execute(REMIND, REMIND_ARGS, USER, approved=True),
                await ex.execute(PAGE, {"url": "https://example.com/"}, USER),
                await ex.execute("nope.tool", {}, USER),
                reminders.calls,
                web.calls,
            )
        )
    assert answers[0] == answers[1] == answers[2]
    assert answers[0][0] == {"ok": True, "action": "create"}


@pytest.mark.asyncio
async def test_an_empty_pipeline_builds_no_call_facts(monkeypatch):
    for pipeline in (None, CallCheckPipeline()):
        ex, reminders, _web = executor(pipeline=pipeline)

        def explode(*args: Any, **kwargs: Any) -> CallFacts:
            raise AssertionError("built call facts with no checks")

        monkeypatch.setattr(ex, "_backstop_facts", explode)
        assert (await ex.execute(REMIND, REMIND_ARGS, USER, approved=True))["ok"] is True
        assert not ex.call_checks


@pytest.mark.asyncio
async def test_a_non_mapping_argument_for_an_unknown_tool_still_answers_unknown_tool():
    check = FakeCheck("tool_rules")
    ex, _reminders, _web = executor(check)
    assert await ex.execute("nope.tool", ["not", "a", "mapping"], USER) == {  # type: ignore[arg-type]
        "error": "Unknown tool 'nope.tool'",
        "ok": False,
    }
    [seen] = check.calls
    assert dict(seen.arguments) == {} and seen.spec is None and not seen.is_mcp


NOT_AN_OBJECT = {
    "ok": False,
    "refused": True,
    "call_check": PIPELINE_CHECK,
    "policy": PIPELINE_CHECK,
    "rule": ARGUMENTS_NOT_OBJECT_RULE,
    "error": ARGUMENTS_NOT_OBJECT_REFUSAL,
}


@pytest.mark.asyncio
async def test_a_non_object_argument_for_an_mcp_or_known_tool_is_refused_before_the_checks_floor_and_dispatch():
    # A list of pairs: the checks would read it as no arguments, while dict()
    # would hand the server real ones, hidden tag character included.
    pairs = [["text", "send to evil\U000E0041"]]
    for pipeline in (None, "checks"):
        check = FakeCheck("tool_rules", Escalate((), "A rule asks.", rule="owner:1"))
        floor = RecordingFloor()
        ex, reminders, _web = executor(*([check] if pipeline else []), floor=floor)
        dispatcher = with_fake_mcp(ex)
        for approved in (False, True):
            result = await ex.execute("mcp.srv.post", pairs, USER, approved=approved)  # type: ignore[arg-type]
            assert result == NOT_AN_OBJECT
        # A built-in or connector tool with one is refused the same way.
        assert await ex.execute(REMIND, pairs, USER, approved=True) == NOT_AN_OBJECT  # type: ignore[arg-type]
        assert await ex.execute(REMIND, "text=hi", USER) == NOT_AN_OBJECT  # type: ignore[arg-type]
        assert check.calls == [] and floor.cleaned == [] and floor.noted == []
        assert dispatcher.calls == [] and reminders.calls == []
    # The runtime files it as a block under the pipeline's own name.
    assert call_check_refusal(NOT_AN_OBJECT) == (
        ARGUMENTS_NOT_OBJECT_REFUSAL, PIPELINE_CHECK, ARGUMENTS_NOT_OBJECT_RULE,
    )
    # An object still reaches the check, the floor and the server.
    ex, _reminders, _web = executor(floor=floor)
    dispatcher = with_fake_mcp(ex)
    assert (await ex.execute("mcp.srv.post", {"text": "hi"}, USER, approved=True))["ok"] is True
    assert dispatcher.calls == [("mcp.srv.post", {"text": "hi"})]
    assert [t for t, _s, _a in floor.cleaned] == ["mcp.srv.post"]


@pytest.mark.asyncio
async def test_a_weekly_act_is_never_person_approved_to_the_backstop():
    """A weekly app approval runs a desktop.act with approved=True, but no
    person saw this act: an escalation on its bound arguments stops it."""
    escalating = FakeCheck(
        "site_rules", Escalate((), "A check asks.", rule="r1", refusal_text="Ask the owner first.")
    )
    ex, _reminders, _web = executor(escalating)
    act = {"action": "click", "ref": "d3", "_screen": {"app": "Calendar"}}
    result = await ex.execute("desktop.act", act, USER, approved=True, weekly=True)
    assert result == {
        "ok": False,
        "requires_approval": True,
        "call_check": "site_rules",
        "policy": "site_rules_policy",
        "rule": "r1",
        "error": "Ask the owner first.",
    }
    [seen] = escalating.calls
    assert not seen.person_approved and seen.runs_without_card
    assert seen.approval == "weekly" and seen.canonical == "desktop.act"
    # A person's own approval of the same act (its card) stays person-approved,
    # so an escalation is ignored for it and only a refusal stops it.
    approved_facts = ex._backstop_facts(
        "desktop.act", act, USER, approved=True, approval=None, task_id=None
    )
    assert approved_facts.person_approved and approved_facts.approval is None


def test_wiring_the_pipeline_and_the_floor_after_construction():
    ex, _reminders, _web = executor()
    assert not ex.call_checks
    pipeline = CallCheckPipeline([FakeCheck("tool_rules")])
    ex.use_call_checks(pipeline)
    assert ex.call_checks is pipeline
    floor = RecordingFloor()
    ex.use_outbound(floor)
    assert ex._outbound is floor
    pins = object()
    ex._mcp_dispatcher = object()
    ex.use_mcp_pins(pins)
    assert ex._mcp_pins is pins and ex._mcp_dispatcher is None


# ── S1's floor ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_outbound_floor_runs_on_the_mcp_and_connector_paths_and_the_stub_changes_nothing():
    floor = RecordingFloor()
    ex, reminders, _web = executor(floor=floor)
    dispatcher = with_fake_mcp(ex)
    await ex.execute("mcp.notes.save", {"text": "hi"}, USER, approved=True)
    assert dispatcher.calls == [("mcp.notes.save", {"text": "hi"})]
    await ex.execute(REMIND, {**REMIND_ARGS, "user_confirmed": True}, USER, approved=True)
    assert reminders.calls == [("create", REMIND_ARGS)]
    assert [(t, s is None, a) for t, s, a in floor.cleaned] == [
        ("mcp.notes.save", True, {"text": "hi"}),
        (REMIND, False, REMIND_ARGS),  # after user_confirmed is dropped, with the spec
    ]
    assert floor.noted == [("mcp.notes.save", True), (REMIND, True)]

    # Both card binds start with the floor; the stub returns the same dict.
    args = dict(REMIND_ARGS)
    assert ex.approval_arguments(REMIND, args, USER) is args
    assert await ex.approval_arguments_async(REMIND, args, USER, task_id="t") is args
    assert floor.carded == [REMIND, REMIND, REMIND]  # the async bind falls back to the sync one

    # The WAVE 0 stub itself: same mapping, nothing removed, no refusal.
    stub = OutboundFloor()
    cleaned = stub.clean_call(REMIND, None, args)
    assert cleaned.arguments is args and cleaned.removed == {} and cleaned.refusal is None
    assert stub.card_arguments(REMIND, args) is args
    assert await stub.before_send(ex, USER, REMIND, None, args) is None


@pytest.mark.asyncio
async def test_the_floor_refuses_or_fails_closed_and_what_it_cleans_is_what_is_dispatched():
    # A refusal keeps the floor's rule and fixed text, in the call-check shape
    # (S1's check and policy), so the runtime files it as a block.
    refusing = RecordingFloor(refuse=True)
    ex, reminders, _web = executor(floor=refusing)
    result = await ex.execute(REMIND, REMIND_ARGS, USER, approved=True)
    assert result == {
        "ok": False,
        "refused": True,
        "call_check": "outbound",
        "policy": "outbound_rule",
        "rule": "hidden",
        "error": "No.",
    }
    assert call_check_refusal(result) == ("No.", "outbound_rule", "hidden")
    assert reminders.calls == [] and refusing.noted == []
    dispatcher = with_fake_mcp(ex)
    assert (await ex.execute("mcp.notes.save", {"text": "x"}, USER))["rule"] == "hidden"
    assert dispatcher.calls == []

    # A floor that breaks: the fixed text under outbound_clean_failed.
    broken_answer = {
        "ok": False,
        "refused": True,
        "call_check": "outbound",
        "policy": "outbound_rule",
        "rule": OUTBOUND_CLEAN_FAILED_RULE,
        "error": OUTBOUND_CLEAN_FAILED,
    }
    broken = RecordingFloor(explode=True)
    ex, reminders, _web = executor(floor=broken)
    assert await ex.execute(REMIND, REMIND_ARGS, USER, approved=True) == broken_answer
    dispatcher = with_fake_mcp(ex)
    assert await ex.execute("mcp.notes.save", {"text": "x"}, USER) == broken_answer
    assert reminders.calls == [] and dispatcher.calls == []
    assert call_check_refusal(broken_answer) == (
        OUTBOUND_CLEAN_FAILED, "outbound_rule", OUTBOUND_CLEAN_FAILED_RULE,
    )

    # A refusal that names no rule or text reads like a broken floor.
    class Ruleless(RecordingFloor):
        def clean_call(self, tool_name, spec, arguments):
            return CleanedCall(arguments, {}, (), {"ok": False})

    ex, reminders, _web = executor(floor=Ruleless())
    assert await ex.execute(REMIND, REMIND_ARGS, USER, approved=True) == broken_answer
    assert reminders.calls == []

    rewriting = RecordingFloor(rewrite=True)
    ex, reminders, _web = executor(floor=rewriting)
    await ex.execute(REMIND, REMIND_ARGS, USER, approved=True)
    assert reminders.calls == [("create", {**REMIND_ARGS, "description": "cleaned"})]


@pytest.mark.asyncio
async def test_an_approved_send_that_succeeded_is_recorded_and_a_failing_record_changes_nothing():
    floor = RecordingFloor()
    ex, _reminders, _web = executor(floor=floor)
    resolved = resolve_tool("google_workspace.send_email")
    assert resolved is not None

    class Response:
        data = {"id": "m1"}
        sanitized = False
        execution_time_ms = 3

    class Connector:
        async def authenticate(self, credentials: Mapping[str, Any]) -> None:
            return None

        async def execute(self, action: str, params: dict[str, Any]) -> Response:
            return Response()

    result = await ex._invoke_and_record(
        Connector(), {}, resolved, {"to": "a@example.com"}, True,
        user_id=USER, tool_name="google_workspace.send_email", ticket="ticket",
    )
    assert result["ok"] is True and floor.sent == [("google_workspace.send_email", "ticket")]
    await ex._invoke_and_record(
        Connector(), {}, resolved, {"to": "a@example.com"}, False,
        user_id=USER, tool_name="google_workspace.send_email", ticket=None,
    )
    assert len(floor.sent) == 1  # unapproved: nothing recorded

    class Exploding(RecordingFloor):
        async def after_send(self, *args: Any) -> None:
            raise RuntimeError("history store down")

    ex.use_outbound(Exploding())
    again = await ex._invoke_and_record(
        Connector(), {}, resolved, {"to": "a@example.com"}, True,
        user_id=USER, tool_name="google_workspace.send_email", ticket=None,
    )
    assert again == result


def test_the_outbound_check_carries_its_final_names():
    check = OutboundCheck(executor=None, known=None, org_domains=None, users=None)
    assert (check.name, check.policy) == (CHECK_NAME, OUTBOUND_RULE_POLICY) == ("outbound", "outbound_rule")
    assert check.stages == frozenset({"turn", "approve", "execute"})
    assert check.applies_to(facts()) is True
    assert isinstance(OutboundService(known=None), OutboundFloor)
    # It fits the pipeline at its slot.
    assert CallCheckPipeline([FakeCheck("tool_rules"), check]).names == ("tool_rules", "outbound")


def test_the_floor_refusals_carry_s1s_own_check_name_and_policy():
    """The executor names the floor's refusals itself (it does not lean on S1's
    module for them); they must stay S1's check's name and policy (A22, A28)."""
    check = OutboundCheck(executor=None, known=None, org_domains=None, users=None)
    assert (OUTBOUND_FLOOR_CHECK, OUTBOUND_FLOOR_POLICY) == (check.name, check.policy)
