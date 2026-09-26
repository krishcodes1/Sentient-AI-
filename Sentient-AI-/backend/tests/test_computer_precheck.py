"""Tests for refusing a blocked desktop.act before its approval card: the runtime
asks the executor's precheck_approval before it parks a call, and an act the
computer toolkit's own hard rules refuse (a blocked app or key combo, a password
field, a stale ref) gets no approval row, a blocked event and an audit row
under computer_rule, and the refusal as its result for the model to explain.
Stop, even when the toolkit is first to see it, skips the act as a stop, never
as a block. An allowed act is parked exactly as before, a precheck that fails
refuses the call, and an approved act still meets every rule again when it
runs. A round that parks a call ends the turn (so the model never asks for the
same card twice) and runs nothing after the card, and Stop ends it before the
next model round. Each card stores the screen it was made from, and the
approved act runs only on that screen; the text an act types is kept for the
approval but stored in the audit log as its length only, and no audit row
stores it read back off the screen either (desktop results are audited as
facts only).

Why it exists: A card that can only end in a refusal looks broken and teaches
the owner to tap Approve. Each test drives the real runtime, permission adapter,
executor and toolkit over the in-memory fake desktop: nothing clicks, types or
reads the real screen, and no model or Telegram call is made.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Optional, Union

import pytest

from core.config import settings
from services.agent import cancel
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    PARKED_ROUND_POLICY,
    PARKED_ROUND_REASON,
    PRECHECK_ERROR_POLICY,
    PRECHECK_ERROR_REASON,
    USER_STOPPED_POLICY,
    AgentRuntime,
    BlockedAction,
    PrecheckRefusal,
    Tool,
    ToolExecutor,
    stopped_reply,
)
from services.agent.tool_registry import (
    COMPUTER_RULE_POLICY,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.tools.computer import backend as computer_backend
from services.tools.computer.backend import BlockedTargetError
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.toolkit import CARD_KEY, ComputerToolkit
from tests.conftest import use_provider
from tests.test_computer_control_wiring import _gate, mail_desktop, ref_of, toolkit

U1 = "user-1"
U2 = "user-2"
ACT = "desktop.act"
TOOLS = build_tools([], enabled_capabilities=frozenset({"computer_control"}))
EXPLAINED = "I could not do that on your computer."

Step = Union[LLMResponse, Callable[[], LLMResponse]]


@pytest.fixture(autouse=True)
def _computer_control_on(monkeypatch):
    """The owner's report sees an available backend (a fake), so
    computer_control is on; conftest's guard would report it blocked."""
    monkeypatch.setattr(
        computer_backend, "select_backend", lambda name: FakeBackend(available=(True, ""))
    )


@pytest.fixture(autouse=True)
def _no_stale_stop():
    for user in (U1, U2):
        cancel.clear(user)
    yield
    for user in (U1, U2):
        cancel.clear(user)


# ── helpers ──────────────────────────────────────────────────────────────────


class RecordingAudit:
    """Keeps every audit entry. An entry whose event is *fail_on* raises
    instead, as a store that is down would."""

    def __init__(self, fail_on: str = "") -> None:
        self.entries: list[dict[str, Any]] = []
        self.fail_on = fail_on

    async def log(self, entry: dict[str, Any]) -> None:
        if entry.get("event") == self.fail_on:
            raise RuntimeError("audit store is down")
        self.entries.append(entry)

    def events_for(self, tool: str) -> list[str]:
        return [e["event"] for e in self.entries if e.get("tool") == tool]


class Script:
    """A scripted model. A step is an LLMResponse, or a callable returning one
    (to change something mid-turn, as /stop does). Records every call's
    messages, so a test can read what the model was shown."""

    def __init__(self, *steps: Step) -> None:
        self.steps = list(steps)
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(list(messages))
        step = self.steps.pop(0) if self.steps else LLMResponse(content="done")
        return step() if callable(step) else step

    async def stream(self, messages, tools=None):
        yield "done"


def call(tool_id: str, name: str, **arguments: Any) -> LLMResponse:
    return LLMResponse(
        content="", tool_calls=[ToolCall(id=tool_id, name=name, arguments=arguments)]
    )


def calls(*items: tuple[str, str, dict[str, Any]]) -> LLMResponse:
    """One model round asking for several tool calls at once, each an
    (id, name, arguments) triple."""
    return LLMResponse(
        content="",
        tool_calls=[ToolCall(id=i, name=name, arguments=args) for i, name, args in items],
    )


OBSERVE = call("t1", "desktop.observe", action="outline")


class Turn:
    """One runtime over one fake desktop, with everything it records. A
    second Turn can share the first's toolkit and approval store, as two
    users' turns on one install do."""

    def __init__(
        self,
        fake: FakeBackend,
        *,
        audit: Any = None,
        kit: Optional[ComputerToolkit] = None,
        store: Optional[InMemoryApprovalStore] = None,
    ) -> None:
        gate = _gate("computer_control")
        self.fake = fake
        self.kit: ComputerToolkit = kit if kit is not None else toolkit(fake)
        self.store = store if store is not None else InMemoryApprovalStore()
        self.audit = audit if audit is not None else RecordingAudit()
        self.events: list[dict[str, Any]] = []
        self.runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(capability_gate=gate),
            tool_executor=ConnectorToolExecutor(
                session_factory=None, capability_gate=gate, computer_toolkit=self.kit
            ),
            audit_service=self.audit,
            approval_store=self.store,
        )
        self.model: Script = Script()

    async def run(self, *steps: Step, user_id: str = U1):
        self.model = Script(*steps)
        use_provider(self.runtime, self.model)

        async def sink(event: dict[str, Any]) -> None:
            self.events.append(event)

        return await self.runtime.chat(
            messages=[{"role": "user", "content": "Do this on my computer."}],
            tools=TOOLS,
            user_id=user_id,
            event_sink=sink,
        )

    def of_type(self, kind: str) -> list[dict[str, Any]]:
        return [e["data"] for e in self.events if e["type"] == kind]

    def shown_to_model(self) -> str:
        """Everything in the model's last request."""
        return "\n".join(str(m.get("content")) for m in self.model.calls[-1])


async def mail_refs() -> dict[str, str]:
    """The refs the runtime's first outline of the Mail desktop hands out
    (numbered per user from d1, so a twin desktop shows them)."""
    twin = await toolkit(mail_desktop()).execute("observe", {"action": "outline"}, user_id=U1)
    return {
        "send": ref_of(twin, 'button "Send"'),
        "password": ref_of(twin, '"Password"'),
    }


def terminal_in_front() -> FakeBackend:
    fake = mail_desktop()
    fake.front = "Terminal"
    return fake


def request_stop_then(response: LLMResponse) -> Callable[[], LLMResponse]:
    """The owner taps Stop while the model is still choosing its action."""

    def step() -> LLMResponse:
        cancel.request_cancel(U1)
        return response

    return step


async def assert_refused_before_the_card(
    turn: Turn, response, rule: str, says: str, *, explained: bool = True
) -> None:
    # No approval row, no card, nothing sent to the desktop.
    assert response.pending_approvals == []
    assert await turn.store.list_pending(U1) == []
    assert turn.of_type("pending_approval") == []
    assert turn.fake.events == []
    # One blocked event, under computer_rule, naming the toolkit's rule.
    [blocked] = turn.of_type("blocked")
    assert blocked["tool"] == ACT and blocked["policy"] == COMPUTER_RULE_POLICY
    assert blocked["rule"] == rule and says in blocked["reason"]
    assert response.blocked_actions == [
        BlockedAction(tool_name=ACT, reason=blocked["reason"], policy=COMPUTER_RULE_POLICY)
    ]
    # One audit row: refused, never parked, never executed.
    assert turn.audit.events_for(ACT) == ["tool_blocked"]
    [row] = [e for e in turn.audit.entries if e.get("tool") == ACT]
    assert row["policy"] == COMPUTER_RULE_POLICY and row["rule"] == rule
    assert row["reason"] == blocked["reason"]
    # The refusal is the call's result; unless the turn ended (Stop), the
    # model was shown it and answered from it.
    [acted] = [tr for tr in response.tool_calls if tr["name"] == ACT]
    assert acted["result"]["ok"] is False and says in acted["result"]["error"]
    if explained:
        assert says in turn.shown_to_model()
        assert response.content == EXPLAINED


# ── refused before the card ──────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("app", "says"),
    [
        ("Terminal", "Crawler never acts in Terminal"),
        ("Windows Terminal", "Crawler never acts in Windows Terminal"),
        # A full-width lookalike folds to the same name.
        ("\uff34\uff45\uff52\uff4d\uff49\uff4e\uff41\uff4c", "Crawler never acts in Terminal"),
        # The bundle id and the executable name, as the OS reports them.
        ("com.apple.Terminal", "Crawler never acts in Terminal"),
        ("WindowsTerminal.exe", "Crawler never acts in Windows Terminal"),
    ],
)
async def test_opening_a_blocked_app_never_reaches_a_card(app, says):
    turn = Turn(mail_desktop())
    response = await turn.run(
        call("t2", ACT, action="open_app", app=app), LLMResponse(content=EXPLAINED)
    )
    await assert_refused_before_the_card(turn, response, "blocked_app", says)
    assert turn.fake.reads == []  # a static rule: the desktop was not even read


@pytest.mark.asyncio
async def test_switching_to_a_blocked_app_never_reaches_a_card():
    turn = Turn(mail_desktop())
    response = await turn.run(
        call("t2", ACT, action="focus_window", app="Command Prompt"),
        LLMResponse(content=EXPLAINED),
    )
    await assert_refused_before_the_card(
        turn, response, "blocked_app", "Crawler never acts in Command Prompt"
    )


@pytest.mark.asyncio
async def test_input_to_a_blocked_front_app_never_reaches_a_card():
    turn = Turn(terminal_in_front())
    response = await turn.run(
        OBSERVE, call("t2", ACT, action="key", keys="enter"), LLMResponse(content=EXPLAINED)
    )
    await assert_refused_before_the_card(
        turn, response, "blocked_app", "Crawler never acts in Terminal"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("keys", ["cmd+shift+q", "ctrl+alt+del", "win+r", "fn+q"])
async def test_a_blocked_key_combo_never_reaches_a_card(keys):
    turn = Turn(mail_desktop())
    response = await turn.run(
        OBSERVE, call("t2", ACT, action="key", keys=keys), LLMResponse(content=EXPLAINED)
    )
    await assert_refused_before_the_card(turn, response, "blocked_key", "The owner can do this")


@pytest.mark.asyncio
async def test_typing_into_a_password_field_never_reaches_a_card():
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(
        OBSERVE,
        call("t2", ACT, action="type", ref=refs["password"], text="hunter2"),
        LLMResponse(content=EXPLAINED),
    )
    await assert_refused_before_the_card(
        turn, response, "secure_field", "Crawler never types into one"
    )
    # The would-be password is in no event and no reason. The audit service
    # is handed the call's arguments, as for every tool_blocked row; the row
    # it stores keeps only the text's length (see the audit tests below).
    assert "hunter2" not in str(turn.events)


@pytest.mark.asyncio
async def test_a_stale_ref_never_reaches_a_card():
    turn = Turn(mail_desktop())
    response = await turn.run(
        OBSERVE, call("t2", ACT, action="click", ref="d999"), LLMResponse(content=EXPLAINED)
    )
    await assert_refused_before_the_card(
        turn, response, "stale_ref", "d999 is not in the latest outline"
    )
    [acted] = [tr for tr in response.tool_calls if tr["name"] == ACT]
    assert acted["result"]["stale_ref"] is True  # the toolkit's own hint to observe again


@pytest.mark.asyncio
async def test_acting_before_any_outline_never_reaches_a_card():
    turn = Turn(mail_desktop())
    response = await turn.run(
        call("t2", ACT, action="click", ref="d1"), LLMResponse(content=EXPLAINED)
    )
    await assert_refused_before_the_card(turn, response, "needs_observe", "Look first")


@pytest.mark.asyncio
async def test_invalid_arguments_never_reach_a_card():
    turn = Turn(mail_desktop())
    response = await turn.run(
        call("t2", ACT, action="drag", ref="d1"), LLMResponse(content=EXPLAINED)
    )
    await assert_refused_before_the_card(
        turn, response, "invalid_arguments", "action must be one of"
    )


@pytest.mark.asyncio
async def test_an_act_after_stop_never_reaches_a_card_and_ends_the_turn():
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(
        OBSERVE,
        request_stop_then(call("t2", ACT, action="click", ref=refs["send"])),
        call("t3", "desktop.observe", action="outline"),
        LLMResponse(content="never asked: Stop ends the turn"),
    )
    # The runtime's stop boundary comes before the precheck: the act is
    # skipped, so it is neither parked, refused as a rule, nor sent.
    assert response.pending_approvals == []
    assert await turn.store.list_pending(U1) == []
    assert turn.of_type("pending_approval") == []
    assert turn.fake.events == []
    assert response.blocked_actions == []
    [row] = [e for e in turn.audit.entries if e.get("tool") == ACT]
    assert row["event"] == "tool_blocked" and row["policy"] == USER_STOPPED_POLICY
    # No model round after the stop, so the model cannot go on to another
    # tool: the second outline was never asked for, and the reply is fixed.
    assert len(turn.model.calls) == 2
    assert [tr["name"] for tr in response.tool_calls] == ["desktop.observe"]
    one_outline = mail_desktop()
    await toolkit(one_outline).execute("observe", {"action": "outline"}, user_id=U2)
    assert turn.fake.reads == one_outline.reads
    assert response.stopped is True
    assert response.content == stopped_reply(ran=1, skipped=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("stops_in", ["permission check", "precheck"])
async def test_a_stop_after_the_acts_first_check_is_still_a_stop(stops_in):
    # The stop lands after the per-call boundary: while the act's permission
    # is checked (the gate can read the database), or, as a backstop, first
    # seen by the toolkit's own cancel check in the precheck. Either way the
    # act is skipped under user_stopped: no card, and no security block.
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    if stops_in == "permission check":
        real_check = turn.runtime._permissions.check

        async def check_then_stop(user_id, tool_name, arguments):
            decision = await real_check(user_id, tool_name, arguments)
            if tool_name == ACT:
                cancel.request_cancel(user_id)
            return decision

        turn.runtime._permissions.check = check_then_stop  # type: ignore[method-assign]
    else:
        real_precheck = turn.kit.precheck

        def stop_then_precheck(params, *, user_id):
            cancel.request_cancel(user_id)
            return real_precheck(params, user_id=user_id)

        turn.kit.precheck = stop_then_precheck  # type: ignore[method-assign]
    response = await turn.run(
        OBSERVE,
        call("t2", ACT, action="click", ref=refs["send"]),
        LLMResponse(content="never asked"),
    )
    assert response.stopped is True
    assert response.blocked_actions == [] and turn.of_type("blocked") == []
    assert response.pending_approvals == [] and await turn.store.list_pending(U1) == []
    assert turn.fake.events == []
    [row] = [e for e in turn.audit.entries if e.get("tool") == ACT]
    assert row["event"] == "tool_blocked" and row["policy"] == USER_STOPPED_POLICY
    assert [tr["name"] for tr in response.tool_calls] == ["desktop.observe"]
    assert response.content == stopped_reply(ran=1, skipped=1)


@pytest.mark.asyncio
async def test_an_act_refused_before_its_card_is_not_a_step_that_ran():
    # The refusal is the act's result for the model, but nothing touched the
    # desktop, so the stop reply and its audit row count no step as run.
    turn = Turn(mail_desktop())
    response = await turn.run(
        call("t1", ACT, action="open_app", app="Terminal"),
        request_stop_then(call("t2", "desktop.observe", action="outline")),
        LLMResponse(content="never asked"),
    )
    assert turn.fake.events == [] and turn.fake.reads == []
    assert [b.policy for b in response.blocked_actions] == [COMPUTER_RULE_POLICY]
    assert response.stopped is True
    assert response.content == stopped_reply(ran=0, skipped=1)
    assert turn.of_type("stopped") == [
        {"policy": USER_STOPPED_POLICY, "steps_ran": 0, "steps_skipped": 1}
    ]
    [row] = [e for e in turn.audit.entries if e.get("event") == "turn_stopped"]
    assert row["arguments"] == {"steps_ran": 0, "steps_skipped": 1}


@pytest.mark.asyncio
async def test_the_stream_carries_the_rule_and_finishes_without_a_card():
    turn = Turn(mail_desktop())
    use_provider(
        turn.runtime,
        Script(call("t1", ACT, action="open_app", app="Terminal"), LLMResponse(content=EXPLAINED)),
    )
    events = [
        event
        async for event in turn.runtime.stream_chat(
            messages=[{"role": "user", "content": "Open Terminal."}], tools=TOOLS, user_id=U1
        )
    ]
    kinds = [event["type"] for event in events]
    assert "pending_approval" not in kinds and kinds[-1] == "done"
    [blocked] = [event["data"] for event in events if event["type"] == "blocked"]
    assert blocked["policy"] == COMPUTER_RULE_POLICY and blocked["rule"] == "blocked_app"
    assert await turn.store.list_pending(U1) == []


@pytest.mark.asyncio
async def test_each_user_is_checked_against_their_own_outline():
    # Two users' turns at once on one toolkit: U1's latest outline has
    # Terminal in front, U2's has Mail, so the same scroll is refused for
    # U1 and parked for U2.
    fake = mail_desktop()
    first = Turn(fake)
    second = Turn(fake, kit=first.kit, store=first.store)
    fake.front = "Terminal"
    await first.kit.execute("observe", {"action": "outline"}, user_id=U1)
    fake.front = "Mail"
    await first.kit.execute("observe", {"action": "outline"}, user_id=U2)

    r1, r2 = await asyncio.gather(
        first.run(call("a", ACT, action="scroll", direction="down"), LLMResponse(content="x")),
        second.run(call("b", ACT, action="scroll", direction="down"), user_id=U2),
    )
    assert r1.pending_approvals == []
    assert [b.policy for b in r1.blocked_actions] == [COMPUTER_RULE_POLICY]
    assert len(r2.pending_approvals) == 1 and r2.blocked_actions == []
    assert await first.store.list_pending(U1) == []
    assert [p.tool_name for p in await first.store.list_pending(U2)] == [ACT]


@pytest.mark.asyncio
async def test_a_refusal_stands_when_the_audit_write_fails():
    turn = Turn(mail_desktop(), audit=RecordingAudit(fail_on="tool_blocked"))
    response = await turn.run(
        call("t2", ACT, action="open_app", app="Terminal"), LLMResponse(content=EXPLAINED)
    )
    assert response.pending_approvals == [] and await turn.store.list_pending(U1) == []
    assert [b.policy for b in response.blocked_actions] == [COMPUTER_RULE_POLICY]
    assert "Crawler never acts in Terminal" in turn.shown_to_model()
    assert turn.fake.events == []


@pytest.mark.asyncio
async def test_the_audit_row_keeps_the_rule(session_factory):
    from sqlalchemy import select

    from models.audit import AuditLog, AuditStatus
    from services.audit import RuntimeAuditLogger
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    turn = Turn(mail_desktop(), audit=RuntimeAuditLogger(session_factory=session_factory))
    response = await turn.run(
        call("t2", ACT, action="open_app", app="Terminal"),
        LLMResponse(content=EXPLAINED),
        user_id=str(user.id),
    )
    assert response.pending_approvals == []
    async with session_factory() as session:
        rows = list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.user_id == user.id, AuditLog.action == "act")
                )
            ).scalars()
        )
    [row] = rows
    assert row.status == AuditStatus.blocked
    assert row.reasoning_chain["policy"] == COMPUTER_RULE_POLICY
    assert row.reasoning_chain["rule"] == "blocked_app"


# ── allowed acts are parked exactly as before ────────────────────────────────


@pytest.mark.asyncio
async def test_an_allowed_act_still_gets_its_card_and_runs_once_approved():
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(
        OBSERVE,
        call("t2", ACT, action="click", ref=refs["send"]),
        LLMResponse(content="never asked: the turn ends on the card"),
    )
    [pending] = response.pending_approvals
    assert pending.tool_name == ACT and pending.reason == 'Click "Send" in Mail'
    assert [p.action_id for p in await turn.store.list_pending(U1)] == [pending.action_id]
    [card] = turn.of_type("pending_approval")
    assert card["action_id"] == pending.action_id and card["reason"] == 'Click "Send" in Mail'
    assert turn.of_type("blocked") == [] and response.blocked_actions == []
    assert turn.audit.events_for(ACT) == ["tool_pending_approval"]
    assert len(turn.model.calls) == 2  # parked: nothing to feed back
    assert turn.fake.events == []

    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True, outcome
    assert turn.fake.events == [("click", "send", False)]


@pytest.mark.asyncio
async def test_an_app_action_needs_no_outline_to_get_its_card():
    turn = Turn(mail_desktop())
    response = await turn.run(call("t1", ACT, action="open_app", app="Calculator"))
    [pending] = response.pending_approvals
    assert pending.reason == "Open Calculator"
    assert turn.of_type("blocked") == [] and turn.fake.events == []


@pytest.mark.asyncio
async def test_a_smuggled_user_confirmed_is_ignored_not_refused():
    # Dispatch drops it, so the precheck and the card do too: the act is
    # parked with its real sentence and runs only once approved.
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(
        OBSERVE, call("t2", ACT, action="click", ref=refs["send"], user_confirmed=True)
    )
    [pending] = response.pending_approvals
    assert pending.reason == 'Click "Send" in Mail'
    assert turn.of_type("blocked") == [] and turn.fake.events == []
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True, outcome


# ── a round that parks a call ends the turn ─────────────────────────────────
#
# The next model round would see the round's other results (a refusal, an
# outline) but nothing of the parked call, and could ask for it again: a
# second card for the same action, run twice once both are approved.


@pytest.mark.asyncio
async def test_a_refusal_beside_a_card_ends_the_turn_on_the_card():
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    click = {"action": "click", "ref": refs["send"]}
    response = await turn.run(
        OBSERVE,
        calls(("t2", ACT, {"action": "open_app", "app": "Terminal"}), ("t3", ACT, click)),
        call("t4", ACT, **click),  # never asked: the card ends the turn
        LLMResponse(content="never asked"),
    )
    [pending] = response.pending_approvals
    assert pending.reason == 'Click "Send" in Mail'
    assert [p.action_id for p in await turn.store.list_pending(U1)] == [pending.action_id]
    assert len(turn.model.calls) == 2
    # The refused act still got no card, its blocked event and its result.
    [blocked] = turn.of_type("blocked")
    assert blocked["rule"] == "blocked_app"
    [refused] = [tr for tr in response.tool_calls if tr["tool_call_id"] == "t2"]
    assert refused["result"]["rule"] == "blocked_app"
    assert response.content.startswith("I need your approval")
    assert turn.fake.events == []


@pytest.mark.asyncio
async def test_an_app_opened_beside_a_refusal_opens_once():
    # An act with no ref (open_app, keys into whatever has focus) would run
    # once per card.
    turn = Turn(mail_desktop())
    response = await turn.run(
        calls(
            ("t1", ACT, {"action": "open_app", "app": "Terminal"}),
            ("t2", ACT, {"action": "open_app", "app": "Calculator"}),
        ),
        call("t3", ACT, action="open_app", app="Calculator"),
    )
    [pending] = response.pending_approvals
    assert pending.reason == "Open Calculator"
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True, outcome
    assert turn.fake.events == [("open_app", "Calculator")]


@pytest.mark.asyncio
async def test_a_card_beside_an_outline_ends_the_turn():
    # The same with no refusal at all: an outline and a parked act.
    turn = Turn(mail_desktop())
    response = await turn.run(
        calls(
            ("t1", "desktop.observe", {"action": "outline"}),
            ("t2", ACT, {"action": "open_app", "app": "Calculator"}),
        ),
        call("t3", ACT, action="open_app", app="Calculator"),
    )
    [pending] = response.pending_approvals
    assert [p.action_id for p in await turn.store.list_pending(U1)] == [pending.action_id]
    assert len(turn.model.calls) == 1
    # The outline that ran is kept with the turn's results.
    assert [tr["name"] for tr in response.tool_calls] == ["desktop.observe"]


@pytest.mark.asyncio
async def test_an_outline_after_a_card_in_the_same_round_is_not_read():
    # The turn ends on the card, so the model would never see that outline,
    # and reading it would replace the refs the parked click was checked
    # against: the card could then only fail with a stale ref once approved.
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(
        OBSERVE,
        calls(
            ("t2", ACT, {"action": "click", "ref": refs["send"]}),
            ("t3", "desktop.observe", {"action": "outline"}),
        ),
        LLMResponse(content="never asked"),
    )
    [pending] = response.pending_approvals
    assert pending.reason == 'Click "Send" in Mail'
    assert [tr["tool_call_id"] for tr in response.tool_calls] == ["t1"]
    one_outline = mail_desktop()
    await toolkit(one_outline).execute("observe", {"action": "outline"}, user_id=U2)
    assert turn.fake.reads == one_outline.reads
    # Recorded as not run, and not as a security block.
    assert response.blocked_actions == [] and turn.of_type("blocked") == []
    rows = [e for e in turn.audit.entries if e.get("policy") == PARKED_ROUND_POLICY]
    assert [(r["event"], r["tool"], r["reason"]) for r in rows] == [
        ("tool_blocked", "desktop.observe", PARKED_ROUND_REASON)
    ]
    assert len(turn.model.calls) == 2

    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True, outcome
    assert turn.fake.events == [("click", "send", False)]


@pytest.mark.asyncio
async def test_calls_after_a_parked_call_are_not_run_and_earlier_ones_are():
    # Any tool, not only the desktop: the call before the card runs, the
    # card is raised, and nothing after it runs or is parked this turn.
    class ReadsRunWritesPark:
        async def check(self, user_id, tool_name, arguments):
            return "approved" if tool_name == "mail.read" else "requires_approval"

    executor = _Answering(None)
    audit = RecordingAudit()
    store = InMemoryApprovalStore()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=ReadsRunWritesPark(),  # type: ignore[arg-type]
        tool_executor=executor,
        audit_service=audit,  # type: ignore[arg-type]
        approval_store=store,
    )
    use_provider(
        runtime,
        Script(
            calls(
                ("t1", "mail.read", {"box": "inbox"}),
                ("t2", "mail.send", {"to": "a@b.c"}),
                ("t3", "mail.read", {"box": "sent"}),
                ("t4", "mail.send", {"to": "d@e.f"}),
            )
        ),
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Reply to Ann and Dan."}],
        tools=[
            Tool(name="mail.read", description="read", parameters={}),
            Tool(name="mail.send", description="send", parameters={}, permission_tier="approval"),
        ],
        user_id=U1,
    )
    assert executor.dispatched == ["mail.read"]
    assert [tr["tool_call_id"] for tr in response.tool_calls] == ["t1"]
    [pending] = response.pending_approvals
    assert pending.arguments == {"to": "a@b.c"}
    assert [p.action_id for p in await store.list_pending(U1)] == [pending.action_id]
    assert response.blocked_actions == [] and response.stopped is False
    rows = [e for e in audit.entries if e.get("policy") == PARKED_ROUND_POLICY]
    assert [(r["event"], r["tool"], r["arguments"], r["reason"]) for r in rows] == [
        ("tool_blocked", "mail.read", {"box": "sent"}, PARKED_ROUND_REASON),
        ("tool_blocked", "mail.send", {"to": "d@e.f"}, PARKED_ROUND_REASON),
    ]
    assert all(r["user_id"] == U1 for r in rows)


# ── the rules still run when an approved act executes ───────────────────────


@pytest.mark.asyncio
async def test_approve_after_stop_sends_the_one_approved_act_and_no_more():
    # The Approve tap is newer than the Stop, so the approved click is sent
    # (services.agent.cancel: every piece of work answers only to stops
    # after its own mark); the turn that would resume the task answers to
    # the Stop and ends. A stop after the tap is covered in
    # test_runtime_stop.py.
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(OBSERVE, call("t2", ACT, action="click", ref=refs["send"]))
    [pending] = response.pending_approvals
    cancel.request_cancel(U1)
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True
    assert [e[0] for e in turn.fake.events] == ["click"]
    assert cancel.stopped_since(U1, outcome["resume_stop_mark"]) is True


@pytest.mark.asyncio
async def test_a_blocked_app_in_front_by_approval_time_is_still_refused():
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(OBSERVE, call("t2", ACT, action="click", ref=refs["send"]))
    [pending] = response.pending_approvals
    turn.fake.front = "Terminal"
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["refused"] is True and outcome["result"]["rule"] == "blocked_app"
    assert turn.fake.events == []


@pytest.mark.asyncio
async def test_a_name_only_the_os_can_resolve_is_refused_by_the_backend():
    # A localized display name the static rules cannot know gets its card;
    # once approved, the backend resolves it to Terminal and refuses.
    turn = Turn(mail_desktop())
    turn.fake.failures["open_app"] = BlockedTargetError("resolved to Terminal", app="Terminal")
    response = await turn.run(call("t1", ACT, action="open_app", app="Terminal-DE"))
    [pending] = response.pending_approvals
    assert pending.reason == "Open Terminal-DE"
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["refused"] is True and outcome["result"]["rule"] == "blocked_app"
    assert "Crawler never acts in Terminal" in outcome["result"]["error"]


# ── an approved act runs only on the screen its card was made from ──────────


def mail_and_messages() -> FakeBackend:
    fake = mail_desktop()
    fake.apps["Messages"] = FakeApp(
        "Messages", 104, [FakeWindow("Ann", (make_node("text field", "iMessage", handle="imsg"),))]
    )
    return fake


def assert_screen_changed(outcome: dict[str, Any]) -> None:
    result = outcome["result"]
    assert result["refused"] is True and result["rule"] == "screen_changed", outcome
    assert result["error"] == "The screen changed since this was approved. Look again first."


@pytest.mark.asyncio
async def test_a_look_at_another_app_later_in_the_round_cannot_move_the_card():
    # A round ends on its card: an outline asked for after the parked call
    # is never taken (parked_round), so it cannot replace the screen the
    # card was made from. If the owner brings Messages to the front while
    # the card waits, the live rules still keep the typing out of it.
    turn = Turn(mail_and_messages())
    response = await turn.run(
        OBSERVE,
        calls(
            ("t2", ACT, {"action": "type", "text": "I quit\n"}),
            ("t3", "desktop.observe", {"action": "outline", "app": "Messages"}),
        ),
    )
    [pending] = response.pending_approvals
    assert pending.reason == (
        "Type 7 characters (including 1 line break) into the focused field in Mail"
    )
    rows = [e for e in turn.audit.entries if e.get("policy") == PARKED_ROUND_POLICY]
    assert [(r["tool"], r["arguments"]) for r in rows] == [
        ("desktop.observe", {"action": "outline", "app": "Messages"})
    ]
    turn.fake.front, turn.fake.focused_handle = "Messages", "imsg"
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert turn.fake.events == []  # nothing typed into the Messages chat box
    result = outcome["result"]
    assert result["refused"] is True and result["rule"] == "frontmost_changed", outcome


@pytest.mark.asyncio
async def test_a_card_is_refused_once_a_later_turn_looked_at_another_app():
    turn = Turn(mail_and_messages())
    response = await turn.run(OBSERVE, call("t2", ACT, action="key", keys="cmd+a"))
    [pending] = response.pending_approvals
    assert pending.reason == "Press cmd+a in Mail"
    turn.fake.front = "Messages"
    await turn.run(OBSERVE, LLMResponse(content="Messages is open."))
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert turn.fake.events == []
    assert_screen_changed(outcome)
    # The audit row records the refusal as the approved call's result.
    [row] = [e for e in turn.audit.entries if e["event"] == "tool_approved_and_executed"]
    assert "screen_changed" in row["result_summary"]


@pytest.mark.asyncio
async def test_a_card_runs_when_a_later_turn_looked_at_the_same_app_again():
    turn = Turn(mail_and_messages())
    response = await turn.run(OBSERVE, call("t2", ACT, action="type", text="Thanks"))
    [pending] = response.pending_approvals
    await turn.run(OBSERVE, LLMResponse(content="Still in Mail."))
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True, outcome
    assert turn.fake.events == [("type", "Thanks", "subject")]


@pytest.mark.asyncio
async def test_the_card_stores_its_screen_with_the_call():
    refs = await mail_refs()
    turn = Turn(mail_desktop())
    response = await turn.run(OBSERVE, call("t2", ACT, action="click", ref=refs["send"]))
    [pending] = response.pending_approvals
    [stored] = await turn.store.list_pending(U1)
    arguments = dict(stored.arguments)
    screen = arguments.pop(CARD_KEY)
    assert arguments == {"action": "click", "ref": refs["send"]}
    assert screen["app"] == "Mail" and screen["outline"]
    assert pending.arguments == stored.arguments
    # The call as the model sent it is what the intent row records.
    [row] = [e for e in turn.audit.entries if e["event"] == "tool_pending_approval"]
    assert row["arguments"] == {"action": "click", "ref": refs["send"]}


@pytest.mark.asyncio
async def test_the_cards_screen_survives_the_database_store(session_factory):
    # Production parks cards in the pending_actions table (a JSON column).
    from services.agent.approvals import DbApprovalStore
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    uid = str(user.id)
    refs = await mail_refs()
    turn = Turn(mail_and_messages(), store=DbApprovalStore(session_factory))
    first = await turn.run(OBSERVE, call("t2", ACT, action="click", ref=refs["send"]), user_id=uid)
    second = await turn.run(OBSERVE, call("t3", ACT, action="key", keys="cmd+a"), user_id=uid)
    [click], [press] = first.pending_approvals, second.pending_approvals
    [stored_click, stored_press] = await turn.store.list_pending(uid)
    assert stored_click.arguments[CARD_KEY] == click.arguments[CARD_KEY]
    # The click's outline was replaced by the second turn's; the key press
    # was made from the latest one.
    assert_screen_changed(await turn.runtime.approve_action(click.action_id, uid))
    done = await turn.runtime.approve_action(press.action_id, uid)
    assert done["result"]["ok"] is True, done
    assert turn.fake.events == [("key", "cmd+a")]
    assert stored_press.arguments[CARD_KEY]["app"] == "Mail"


@pytest.mark.asyncio
async def test_a_screen_sent_by_the_model_never_reaches_a_card():
    turn = Turn(mail_desktop())
    forged = {"app": "Mail", "outline": "whatever"}
    response = await turn.run(
        OBSERVE,
        calls(("t2", ACT, {"action": "key", "keys": "enter", CARD_KEY: forged})),
        LLMResponse(content=EXPLAINED),
    )
    await assert_refused_before_the_card(
        turn, response, "invalid_arguments", f"does not take {CARD_KEY}"
    )


@pytest.mark.asyncio
async def test_a_card_stored_without_its_screen_is_refused_once_approved():
    # A row parked before cards were tied to a screen, or written by anyone
    # else: approving it sends nothing.
    turn = Turn(mail_desktop())
    await turn.run(OBSERVE, LLMResponse(content="Mail is open."))
    for arguments in (
        {"action": "key", "keys": "enter"},
        {"action": "open_app", "app": "Calculator"},
    ):
        parked = await turn.store.create(
            user_id=U1, tool_name=ACT, arguments=arguments, reason="Press enter in Mail"
        )
        outcome = await turn.runtime.approve_action(parked.action_id, U1)
        result = outcome["result"]
        assert result["refused"] is True and result["rule"] == "unbound_approval", outcome
    assert turn.fake.events == []


# ── what desktop.act types never reaches the audit log ──────────────────────


async def _stored_rows(session_factory, user_id) -> list[Any]:
    from sqlalchemy import select

    from models.audit import AuditLog

    async with session_factory() as session:
        return list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.user_id == user_id).order_by(AuditLog.seq)
                )
            ).scalars()
        )


@pytest.mark.asyncio
async def test_text_refused_for_a_password_field_is_stored_as_its_length(session_factory):
    from services.audit import RuntimeAuditLogger
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    refs = await mail_refs()
    turn = Turn(mail_desktop(), audit=RuntimeAuditLogger(session_factory=session_factory))
    response = await turn.run(
        OBSERVE,
        call("t2", ACT, action="type", ref=refs["password"], text="hunter2-S3cret"),
        LLMResponse(content=EXPLAINED),
        user_id=str(user.id),
    )
    assert response.pending_approvals == []
    rows = await _stored_rows(session_factory, user.id)
    [row] = [r for r in rows if (r.reasoning_chain or {}).get("rule") == "secure_field"]
    assert row.request_data == {
        "action": "type",
        "ref": refs["password"],
        "text": "<14 characters>",
    }
    assert all("hunter2" not in str(r.request_data) for r in rows)
    assert all("hunter2" not in str(r.response_summary) for r in rows)


@pytest.mark.asyncio
async def test_typed_text_is_kept_for_the_approval_but_not_in_the_audit_log(session_factory):
    from services.audit import RuntimeAuditLogger
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    uid = str(user.id)
    turn = Turn(mail_desktop(), audit=RuntimeAuditLogger(session_factory=session_factory))
    response = await turn.run(
        OBSERVE, call("t2", ACT, action="type", text="See you at 5"), user_id=uid
    )
    [pending] = response.pending_approvals
    # The approval store is not the audit log: it keeps the text to type.
    [stored] = await turn.store.list_pending(uid)
    assert stored.arguments["text"] == "See you at 5"
    outcome = await turn.runtime.approve_action(pending.action_id, uid)
    assert outcome["result"]["ok"] is True, outcome
    assert turn.fake.events == [("type", "See you at 5", "subject")]
    rows = [r for r in await _stored_rows(session_factory, user.id) if r.action == "act"]
    assert [r.reasoning_chain["event"] for r in rows] == [
        "tool_pending_approval",
        "tool_approved",
        "tool_approved_and_executed",
    ]
    for row in rows:
        assert row.request_data["text"] == "<12 characters>", row.request_data
        assert "See you at 5" not in str(row.request_data)


def _columns_holding(rows: list[Any], text: str) -> list[tuple[Any, str]]:
    """(event, column) for every stored audit column that contains *text*."""
    return [
        ((row.reasoning_chain or {}).get("event"), column)
        for row in rows
        for column, value in (
            ("request_data", row.request_data),
            ("response_summary", row.response_summary),
            ("reasoning_chain", row.reasoning_chain),
        )
        if text in str(value)
    ]


@pytest.mark.asyncio
async def test_no_audit_column_holds_the_text_an_approved_act_typed(session_factory):
    # The approved act's result carries its fresh outline (its ``then``),
    # where the field now shows what was typed; the row keeps facts only.
    from services.audit import RuntimeAuditLogger
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    uid = str(user.id)
    turn = Turn(mail_desktop(), audit=RuntimeAuditLogger(session_factory=session_factory))
    response = await turn.run(
        OBSERVE, call("t2", ACT, action="type", text="See you at 5"), user_id=uid
    )
    [pending] = response.pending_approvals
    outcome = await turn.runtime.approve_action(pending.action_id, uid)
    assert outcome["result"]["ok"] is True, outcome
    assert turn.fake.events == [("type", "See you at 5", "subject")]
    # The model still gets the whole outline, typed text included.
    assert "See you at 5" in str(outcome["result"]["then"]["outline"])

    rows = await _stored_rows(session_factory, user.id)
    assert _columns_holding(rows, "See you at 5") == []
    [executed] = [r for r in rows if r.reasoning_chain["event"] == "tool_approved_and_executed"]
    summary = json.loads(executed.response_summary)
    then = outcome["result"]["then"]
    assert summary == {
        "ok": True,
        "did": outcome["result"]["did"],
        "then": {
            "ok": True,
            "app": "Mail",
            "lines": len(then["outline"]),
            "refs": then["refs"],
        },
    }


@pytest.mark.asyncio
async def test_no_audit_column_holds_typed_text_read_back_by_the_next_observe(session_factory):
    # One step later: the model looks again after typing, as the act's own
    # reply tells it to, and that outline shows the text too.
    from services.audit import RuntimeAuditLogger
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    uid = str(user.id)
    turn = Turn(mail_desktop(), audit=RuntimeAuditLogger(session_factory=session_factory))
    first = await turn.run(
        OBSERVE, call("t2", ACT, action="type", text="See you at 5"), user_id=uid
    )
    [pending] = first.pending_approvals
    await turn.runtime.approve_action(pending.action_id, uid)
    second = await turn.run(OBSERVE, LLMResponse(content="Typed it."), user_id=uid)
    [observed] = second.tool_calls
    assert "See you at 5" in str(observed["result"]["outline"])

    rows = await _stored_rows(session_factory, user.id)
    assert _columns_holding(rows, "See you at 5") == []
    observes = [r for r in rows if r.reasoning_chain["event"] == "tool_executed"]
    assert [json.loads(r.response_summary)["app"] for r in observes] == ["Mail", "Mail"]


def test_a_desktop_result_is_audited_as_facts_only():
    from services.agent.runtime import desktop_result_for_audit

    outline = {
        "ok": True,
        "frontmost_app": "Mail",
        "app": "Mail",
        "window_title": "See you at 5",
        "outline": ['text field "Subject" [ref=d6] value="See you at 5"'],
        "refs": 1,
        "truncated": False,
        "secure_fields_redacted": 0,
        "image": "data:image/png;base64,AAAA",
    }
    assert desktop_result_for_audit("desktop.observe", outline) == {
        "ok": True,
        "app": "Mail",
        "lines": 1,
        "refs": 1,
    }
    windows = {
        "ok": True,
        "frontmost_app": "Mail",
        "window_title": "See you at 5",
        "windows": [{"app": "Mail", "title": "See you at 5", "index": 1}],
    }
    assert desktop_result_for_audit("desktop.observe", windows) == {
        "ok": True,
        "app": "Mail",
        "windows": 1,
    }
    refused = {"ok": False, "refused": True, "rule": "screen_changed", "error": "Look again first."}
    assert desktop_result_for_audit(ACT, refused) == refused
    # An act whose fresh outline could not be read keeps that error.
    withheld = {"ok": True, "did": "press cmd+s in Mail", "then": {"ok": False, "error": "gone"}}
    assert desktop_result_for_audit(ACT, withheld) == withheld
    # Every other tool's result is audited as it is.
    page = {"ok": True, "outline": ["heading 'See you at 5'"]}
    assert desktop_result_for_audit("browser.read", page) is page


# ── the precheck fails closed ────────────────────────────────────────────────


async def assert_refused_as_unchecked(turn: Turn, response) -> None:
    assert response.pending_approvals == [] and await turn.store.list_pending(U1) == []
    assert turn.of_type("pending_approval") == []
    [blocked] = turn.of_type("blocked")
    assert blocked == {
        "tool": ACT,
        "reason": PRECHECK_ERROR_REASON,
        "policy": PRECHECK_ERROR_POLICY,
    }
    assert response.blocked_actions == [
        BlockedAction(tool_name=ACT, reason=PRECHECK_ERROR_REASON, policy=PRECHECK_ERROR_POLICY)
    ]
    assert turn.audit.events_for(ACT) == ["tool_blocked"]
    assert PRECHECK_ERROR_REASON in turn.shown_to_model()


@pytest.mark.asyncio
async def test_a_precheck_that_raises_refuses_the_act():
    turn = Turn(mail_desktop())

    def broken(params, *, user_id):
        raise RuntimeError("boom at /Users/owner/secret")

    turn.kit.precheck = broken  # type: ignore[method-assign]
    response = await turn.run(
        call("t1", ACT, action="open_app", app="Calculator"), LLMResponse(content=EXPLAINED)
    )
    await assert_refused_as_unchecked(turn, response)
    assert "secret" not in str(turn.events) and "secret" not in str(turn.audit.entries)
    assert turn.fake.events == [] and turn.fake.reads == []


class _Answering(ToolExecutor):
    """An executor whose precheck gives a fixed answer; records dispatches."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.dispatched: list[str] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.dispatched.append(tool_name)
        return {"ok": True}

    def precheck_approval(self, tool_name, arguments, user_id):
        return self.answer


class _Park:
    async def check(self, user_id, tool_name, arguments):
        return "requires_approval"


def _parking_runtime(executor: ToolExecutor, audit: RecordingAudit) -> tuple[AgentRuntime, Any]:
    store = InMemoryApprovalStore()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=_Park(),  # type: ignore[arg-type]
        tool_executor=executor,
        audit_service=audit,  # type: ignore[arg-type]
        approval_store=store,
    )
    return runtime, store


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [{"ok": False, "error": "no"}, "refused", True])
async def test_an_unusable_precheck_answer_refuses_the_act(answer):
    executor = _Answering(answer)
    audit = RecordingAudit()
    runtime, store = _parking_runtime(executor, audit)
    model = Script(call("t1", ACT, action="scroll", direction="down"), LLMResponse(content="ok"))
    use_provider(runtime, model)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "scroll"}],
        tools=[Tool(name=ACT, description="act", parameters={}, permission_tier="approval")],
        user_id=U1,
    )
    assert response.pending_approvals == [] and await store.list_pending(U1) == []
    assert response.blocked_actions == [
        BlockedAction(tool_name=ACT, reason=PRECHECK_ERROR_REASON, policy=PRECHECK_ERROR_POLICY)
    ]
    assert executor.dispatched == []


class _AnsweringLater(_Answering):
    """The same, answering through an awaitable, as a check that must read
    storage does (memory.remember: is memory on, is it full)."""

    def __init__(self, answer: Any) -> None:
        super().__init__(answer)
        self.awaited = False

    def precheck_approval(self, tool_name, arguments, user_id):
        async def later():
            self.awaited = True
            if isinstance(self.answer, BaseException):
                raise self.answer
            return self.answer

        return later()


async def _scroll_turn(executor: ToolExecutor, audit: RecordingAudit):
    runtime, store = _parking_runtime(executor, audit)
    use_provider(
        runtime,
        Script(call("t1", ACT, action="scroll", direction="down"), LLMResponse(content="ok")),
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "scroll"}],
        tools=[Tool(name=ACT, description="act", parameters={}, permission_tier="approval")],
        user_id=U1,
    )
    return response, store


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        RuntimeError("database is locked at /Users/owner/secret"),
        {"ok": False, "error": "no"},
        "refused",
    ],
    ids=["raises", "a-result-dict", "a-string"],
)
async def test_an_awaited_precheck_that_raises_or_answers_unusably_refuses_the_act(answer):
    """The awaitable is awaited inside the same fail-closed rule: no card
    for a call whose check could not answer, and nothing dispatched."""
    executor = _AnsweringLater(answer)
    audit = RecordingAudit()
    response, store = await _scroll_turn(executor, audit)

    assert executor.awaited
    assert response.pending_approvals == [] and await store.list_pending(U1) == []
    assert response.blocked_actions == [
        BlockedAction(tool_name=ACT, reason=PRECHECK_ERROR_REASON, policy=PRECHECK_ERROR_POLICY)
    ]
    assert executor.dispatched == []
    assert "secret" not in str(audit.entries)


@pytest.mark.asyncio
async def test_an_awaited_precheck_answer_is_honoured():
    """None parks the call for its card; a PrecheckRefusal refuses it with
    that refusal's own policy."""
    parked = _AnsweringLater(None)
    response, store = await _scroll_turn(parked, RecordingAudit())
    assert parked.awaited and [p.tool_name for p in response.pending_approvals] == [ACT]
    assert len(await store.list_pending(U1)) == 1 and parked.dispatched == []

    refusal = PrecheckRefusal(
        reason="Memory is off.",
        policy="memory_rule",
        result={"ok": False, "refused": True, "error": "Memory is off."},
        rule="memory_off",
    )
    refused = _AnsweringLater(refusal)
    response, store = await _scroll_turn(refused, RecordingAudit())
    assert response.pending_approvals == [] and await store.list_pending(U1) == []
    assert response.blocked_actions == [
        BlockedAction(tool_name=ACT, reason="Memory is off.", policy="memory_rule")
    ]
    assert refused.dispatched == []


@pytest.mark.asyncio
async def test_an_executor_refusal_is_filed_under_its_own_policy():
    # The hook is generic: whatever policy and rule the executor names are
    # what the event and the audit row carry.
    refusal = PrecheckRefusal(
        reason="Not today.", policy="some_rule", result={"ok": False, "error": "Not today."}
    )
    executor = _Answering(refusal)
    audit = RecordingAudit()
    runtime, store = _parking_runtime(executor, audit)
    use_provider(runtime, Script(call("t1", "x.y"), LLMResponse(content="ok")))
    response = await runtime.chat(
        messages=[{"role": "user", "content": "go"}],
        tools=[Tool(name="x.y", description="x", parameters={}, permission_tier="approval")],
        user_id=U1,
    )
    assert response.pending_approvals == [] and await store.list_pending(U1) == []
    assert response.blocked_actions == [
        BlockedAction(tool_name="x.y", reason="Not today.", policy="some_rule")
    ]
    [row] = audit.entries
    assert row["event"] == "tool_blocked" and "rule" not in row
    assert executor.dispatched == []


@pytest.mark.asyncio
async def test_an_executor_without_a_precheck_parks_as_before():
    class Plain:
        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            return {"ok": True}

    runtime, store = _parking_runtime(Plain(), RecordingAudit())  # type: ignore[arg-type]
    use_provider(runtime, Script(call("t1", ACT, action="scroll", direction="down")))
    response = await runtime.chat(
        messages=[{"role": "user", "content": "scroll"}],
        tools=[Tool(name=ACT, description="act", parameters={}, permission_tier="approval")],
        user_id=U1,
    )
    [pending] = response.pending_approvals
    assert [p.action_id for p in await store.list_pending(U1)] == [pending.action_id]


@pytest.mark.asyncio
async def test_a_stop_during_any_tool_ends_the_turn_before_the_next_model_round():
    # Not only a desktop act: Stop pressed while any tool runs ends the turn
    # before the model can ask for another tool.
    class StoppedMidCall:
        def __init__(self) -> None:
            self.dispatched: list[str] = []

        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            self.dispatched.append(tool_name)
            cancel.request_cancel(user_id)
            return {"ok": True}

    class Allow:
        async def check(self, user_id, tool_name, arguments):
            return "approved"

    executor = StoppedMidCall()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=Allow(),  # type: ignore[arg-type]
        tool_executor=executor,  # type: ignore[arg-type]
        audit_service=RecordingAudit(),  # type: ignore[arg-type]
        approval_store=InMemoryApprovalStore(),
    )
    model = Script(
        call("t1", "web.search", query="flights"),
        call("t2", "web.search", query="hotels"),
        LLMResponse(content="never asked"),
    )
    use_provider(runtime, model)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Plan my trip."}],
        tools=[Tool(name="web.search", description="search", parameters={})],
        user_id=U1,
    )
    assert len(model.calls) == 1 and executor.dispatched == ["web.search"]
    assert response.content == stopped_reply(ran=1, skipped=0)
    assert [tr["name"] for tr in response.tool_calls] == ["web.search"]


@pytest.mark.asyncio
async def test_any_round_that_parks_a_call_ends_the_turn():
    # Not only desktop.act: a read that ran beside a parked write stays in
    # the turn's results, and the model is not asked again this turn.
    class ReadsRunWritesPark:
        async def check(self, user_id, tool_name, arguments):
            return "approved" if tool_name == "mail.read" else "requires_approval"

    executor = _Answering(None)
    runtime = AgentRuntime(
        config=settings,
        permission_engine=ReadsRunWritesPark(),  # type: ignore[arg-type]
        tool_executor=executor,
        audit_service=RecordingAudit(),  # type: ignore[arg-type]
        approval_store=InMemoryApprovalStore(),
    )
    model = Script(
        calls(("t1", "mail.read", {}), ("t2", "mail.send", {"to": "a@b.c"})),
        call("t3", "mail.send", to="a@b.c"),
    )
    use_provider(runtime, model)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "Reply to Ann."}],
        tools=[
            Tool(name="mail.read", description="read", parameters={}),
            Tool(name="mail.send", description="send", parameters={}, permission_tier="approval"),
        ],
        user_id=U1,
    )
    assert len(model.calls) == 1 and executor.dispatched == ["mail.read"]
    assert [p.tool_name for p in response.pending_approvals] == ["mail.send"]
    assert [tr["name"] for tr in response.tool_calls] == ["mail.read"]


# ── the executor's hook ──────────────────────────────────────────────────────


def test_precheck_approval_is_only_for_desktop_act():
    ex = ConnectorToolExecutor(session_factory=None, computer_toolkit=toolkit(mail_desktop()))
    for tool, args in (
        ("desktop.observe", {"action": "outline"}),
        ("system.install_capability", {"name": "browser"}),
        ("gmail.send_email", {"to": "a@b.c"}),
        ("desktop__deadbeef.act", {"action": "open_app", "app": "Terminal"}),
        ("nope", {}),
    ):
        assert ex.precheck_approval(tool, args, U1) is None, tool


def test_approval_arguments_tie_only_desktop_act_to_its_screen():
    fake = mail_desktop()
    ex = ConnectorToolExecutor(session_factory=None, computer_toolkit=toolkit(fake))
    for tool, args in (
        ("desktop.observe", {"action": "outline"}),
        ("system.install_capability", {"name": "browser"}),
        ("gmail.send_email", {"to": "a@b.c", CARD_KEY: "kept as sent"}),
        ("desktop__deadbeef.act", {"action": "open_app", "app": "Calculator"}),
        ("nope", {}),
    ):
        assert ex.approval_arguments(tool, args, U1) is args, tool
    # desktop.act gets the toolkit's screen, never one the call brought.
    card = ex.approval_arguments(
        ACT, {"action": "open_app", "app": "Calculator", CARD_KEY: "forged"}, U1
    )
    assert card == {
        "action": "open_app",
        "app": "Calculator",
        CARD_KEY: {"app": "", "outline": ""},
    }
    assert fake.reads == [] and fake.events == []


class _Binding(ToolExecutor):
    """An executor whose card arguments are a fixed answer (or raise it);
    records the arguments each card sentence was built from."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.described: list[dict[str, Any]] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        return {"ok": True}

    def describe_approval(self, tool_name, arguments, user_id):
        self.described.append(dict(arguments))
        return "Scroll down in Mail"

    def approval_arguments(self, tool_name, arguments, user_id):
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "stored"),
    [
        ({"direction": "down", "tie": "screen"}, {"direction": "down", "tie": "screen"}),
        # A hook that fails or answers nothing usable stores the call as sent;
        # an executor that needs the tie then refuses it once approved.
        (RuntimeError("boom"), {"direction": "down"}),
        ("not arguments", {"direction": "down"}),
    ],
)
async def test_the_card_stores_the_executors_arguments_and_its_sentence_reads_them(answer, stored):
    executor = _Binding(answer)
    runtime, store = _parking_runtime(executor, RecordingAudit())
    use_provider(runtime, Script(call("t1", ACT, direction="down")))
    response = await runtime.chat(
        messages=[{"role": "user", "content": "scroll"}],
        tools=[Tool(name=ACT, description="act", parameters={}, permission_tier="approval")],
        user_id=U1,
    )
    [pending] = response.pending_approvals
    [row] = await store.list_pending(U1)
    assert row.arguments == stored and pending.arguments == stored
    assert executor.described == [stored]
    assert pending.reason == "Scroll down in Mail"


def test_precheck_approval_reads_nothing_on_the_desktop():
    fake = mail_desktop()
    ex = ConnectorToolExecutor(session_factory=None, computer_toolkit=toolkit(fake))
    refusal = ex.precheck_approval(ACT, {"action": "open_app", "app": "Terminal"}, U1)
    assert refusal is not None and refusal.rule == "blocked_app"
    assert refusal.policy == COMPUTER_RULE_POLICY
    assert refusal.result["refused"] is True and refusal.reason == refusal.result["error"]
    assert ex.precheck_approval(ACT, {"action": "open_app", "app": "Calculator"}, U1) is None
    assert fake.reads == [] and fake.events == []
