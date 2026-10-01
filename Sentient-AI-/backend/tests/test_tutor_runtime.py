"""Tests for tutor mode inside an agent turn: tutor.start in one round puts the
<tutor_mode> block into the next request, takes itself off the tool array,
ends the reply with the notice and writes the audit row; with the capability
off tutor.start is refused as capability_off; a Canvas call naming a locked
course engages the lock and a submit in the same round is refused (policy
tutor_mode) while reads still run; tools.find never returns a withheld tool;
and a browser.act bound to a Canvas quiz page is refused before any card
while one on a shop page still gets its card.

Why it exists: these are the deterministic parts of tutor mode, the ones that
must hold whatever the model does. Every test drives the real AgentRuntime
with a scripted provider and fake executor: no network, no browser, no model.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from core.config import settings
from services import capabilities as capability_registry
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime, Tool
from services.agent.tool_registry import CAPABILITY_OFF_POLICY, RuntimePermissionAdapter
from services.capabilities.base import ReportContext
from services.tools.browser.pagememory import page_address
from services.tutor import hooks as tutor_hooks
from services.tutor.locks import CourseLock
from services.tutor.prompt import (
    NOTICE_LOCKED_COURSE,
    NOTICE_ON,
    TUTOR_SYSTEM_PROMPT,
    VARIANT_LOCKED_COURSE,
    VARIANT_ON,
)
from services.tutor.state import TutorState, TutorTurn
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider

USER = "u1"
LOCK = CourseLock(
    lock_id="11111111-1111-1111-1111-111111111111",
    scope="course",
    label="MATH 221",
    canvas_course_id="5",
    course_code="MATH 221",
)
QUIZ = "https://canvas.example.edu/courses/5/quizzes/9/take"
SHOP = "https://shop.example.com/cart"
_EMPTY = {"type": "object", "properties": {}, "required": []}


def _tool(name: str, tier: str = "auto", description: str = "") -> Tool:
    return Tool(
        name=name,
        description=description or name,
        parameters=_EMPTY,
        connector_type=name.partition(".")[0],
        permission_tier=tier,
    )


TOOLS = [
    _tool("web.search"),
    _tool("tutor.start", description="Turn on tutor mode"),
    _tool("tools.find"),
    _tool("canvas.get_assignments"),
    _tool("canvas.submit_assignment", "approval", "Submit an assignment to Canvas"),
    _tool("browser.read"),
    _tool("browser.act", "approval"),
]


def _gate(*off: str):
    """Every capability on (and available) except *off*."""
    ctx = ReportContext(
        in_container=False,
        platform="win32",
        telegram_configured=True,
        browser_installed=True,
        playwright_installed=True,
    )
    switches = {key: key not in off for key in capability_registry.keys()}
    statuses = capability_registry.statuses_by_key(
        capability_registry.report(switches, ctx, use_cache=False)
    )

    async def gate():
        return statuses

    return gate


class FakeExecutor:
    """Records dispatches; binds a browser.act card to *page_url*, and
    remembers it as the real executor's page memory does when
    ``remembers`` is set."""

    def __init__(self, page_url: Optional[str] = None, *, remembers: bool = True) -> None:
        self.calls: list[str] = []
        self.page_url = page_url
        if remembers and page_url:
            memory = SimpleNamespace(get=lambda _uid: SimpleNamespace(url=page_url))
            self._act = SimpleNamespace(_memory=memory)

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append(tool_name)
        return {"ok": True, "result": [{"id": 9, "name": "Problem set 4"}]}

    def approval_arguments(self, tool_name, arguments, user_id):
        if tool_name != "browser.act":
            return arguments
        address = page_address(self.page_url) if self.page_url else ""
        return {**arguments, "_page": {"origin": "", "address": address, "outline": "", "scheme": "https"}}

    def precheck_approval(self, tool_name, arguments, user_id):
        return None


def _runtime(provider, executor=None, gate=None):
    audit = RecordingAudit()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate or _gate()),
        prompt_guard=RecordingGuard(),
        audit_service=audit,
        tool_executor=executor or FakeExecutor(),
        approval_store=InMemoryApprovalStore(),
    )
    use_provider(runtime, provider)
    return runtime, audit


def _call(name: str, arguments: Optional[dict[str, Any]] = None, call_id: str = "t1") -> ToolCall:
    return ToolCall(id=call_id, name=name, arguments=arguments or {})


def _round(*calls: ToolCall) -> LLMResponse:
    return LLMResponse(content="", tool_calls=list(calls))


def _system(call: dict[str, Any]) -> str:
    return call["messages"][0]["content"]


def _offered(call: dict[str, Any]) -> set[str]:
    return {t["name"] for t in call["tools"] or []}


def _events(audit: RecordingAudit, name: str) -> list[dict[str, Any]]:
    return [entry for entry in audit.entries if entry.get("event") == name]


@pytest.mark.asyncio
async def test_tutor_start_puts_the_block_in_the_next_round_with_a_notice_and_an_audit_row():
    provider = RecordingProvider(
        [_round(_call("tutor.start")), LLMResponse(content="Which rule handles a product?")]
    )
    runtime, audit = _runtime(provider)
    tutor = TutorTurn(TutorState(), [], channel="web", conversation_id="c1")

    response = await runtime.chat(
        messages=[{"role": "user", "content": "Be my tutor for calculus"}],
        tools=TOOLS,
        user_id=USER,
        conversation_id="c1",
        tutor=tutor,
    )

    first, second = provider.calls
    assert "<tutor_mode>" not in _system(first)
    assert "tutor.start" in _offered(first)
    assert _system(second).endswith("\n\n" + TUTOR_SYSTEM_PROMPT[VARIANT_ON])
    assert "tutor.start" not in _offered(second)
    assert "canvas.submit_assignment" not in _offered(second)
    assert response.content == "Which rule handles a product?\n\n" + NOTICE_ON.format(off="/tutor off")
    assert response.tool_calls[0]["result"] == {"ok": True, "tutor": "on"}
    assert response.blocked_actions == []
    assert tutor.changed and tutor.state.user_on
    assert _events(audit, "tutor_mode_changed") == [
        {
            "event": "tutor_mode_changed",
            "user_id": USER,
            "arguments": {"from": "off", "to": "on", "via": "tool", "conversation_id": "c1"},
            "timestamp": _events(audit, "tutor_mode_changed")[0]["timestamp"],
        }
    ]
    executed = _events(audit, "tool_executed")
    assert [e["tool"] for e in executed] == ["tutor.start"]


@pytest.mark.asyncio
async def test_with_the_capability_off_tutor_start_is_refused_as_capability_off():
    provider = RecordingProvider([_round(_call("tutor.start")), LLMResponse(content="ok")])
    executor = FakeExecutor()
    runtime, audit = _runtime(provider, executor, gate=_gate("tutor_mode"))

    response = await runtime.chat(
        messages=[{"role": "user", "content": "tutor me"}],
        tools=[t for t in TOOLS if t.name != "tutor.start"],
        user_id=USER,
        tutor=None,  # load_tutor_turn answers None with the switch off
    )

    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [
        ("tutor.start", CAPABILITY_OFF_POLICY)
    ]
    assert response.blocked_actions[0].reason == capability_registry.get("tutor_mode").when_denied
    assert executor.calls == []
    assert "<tutor_mode>" not in _system(provider.calls[-1])
    assert _events(audit, "tutor_mode_changed") == []


@pytest.mark.asyncio
async def test_a_course_id_engages_the_lock_and_submit_is_refused_in_the_same_round():
    provider = RecordingProvider(
        [
            _round(
                _call("canvas.get_assignments", {"course_id": "5"}, "t1"),
                _call(
                    "canvas.submit_assignment",
                    {"course_id": "5", "assignment_id": "9", "body": "my essay"},
                    "t2",
                ),
            ),
            LLMResponse(content="Let's look at the problem together."),
        ]
    )
    executor = FakeExecutor()
    runtime, audit = _runtime(provider, executor)
    tutor = TutorTurn(TutorState(), [LOCK], conversation_id="c1")

    response = await runtime.chat(
        messages=[{"role": "user", "content": "do my homework"}],
        tools=TOOLS,
        user_id=USER,
        conversation_id="c1",
        tutor=tutor,
    )

    assert executor.calls == ["canvas.get_assignments"]
    assert response.pending_approvals == []
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [
        ("canvas.submit_assignment", "tutor_mode")
    ]
    refusal = response.tool_calls[1]["result"]
    # Locked: the refusal does not suggest /tutor off, which could not help.
    assert refusal["ok"] is False and "graded work can't be submitted" in refusal["error"]
    assert "/tutor off" not in refusal["error"]
    blocked = _events(audit, "tool_blocked")
    assert [(e["tool"], e["policy"]) for e in blocked] == [("canvas.submit_assignment", "tutor_mode")]
    second = provider.calls[1]
    assert _system(second).endswith("\n\n" + TUTOR_SYSTEM_PROMPT[VARIANT_LOCKED_COURSE])
    assert "canvas.submit_assignment" not in _offered(second)
    assert "canvas.get_assignments" in _offered(second)  # reads are never restricted
    assert response.content.endswith(NOTICE_LOCKED_COURSE.format(label="MATH 221"))
    assert [e["arguments"] for e in _events(audit, "tutor_lock_engaged")] == [
        {"lock_id": LOCK.lock_id, "matched_by": "tool_args"}
    ]
    assert tutor.state.lock is not None and tutor.changed


@pytest.mark.asyncio
async def test_the_message_naming_a_locked_course_locks_the_first_request():
    provider = RecordingProvider([LLMResponse(content="What have you tried so far?")])
    runtime, _audit = _runtime(provider)
    tutor = TutorTurn(TutorState(), [LOCK], conversation_id="c1")

    response = await runtime.chat(
        messages=[{"role": "user", "content": "solve question 4 of the MATH 221 problem set"}],
        tools=TOOLS,
        user_id=USER,
        conversation_id="c1",
        tutor=tutor,
    )

    assert _system(provider.calls[0]).endswith(TUTOR_SYSTEM_PROMPT[VARIANT_LOCKED_COURSE])
    assert {"canvas.submit_assignment", "tutor.start"}.isdisjoint(_offered(provider.calls[0]))
    assert response.content.endswith(NOTICE_LOCKED_COURSE.format(label="MATH 221"))


@pytest.mark.asyncio
async def test_a_submit_naming_the_locked_course_is_refused_by_its_own_arguments():
    provider = RecordingProvider(
        [
            _round(_call("canvas__1a2b3c4d.submit_assignment", {"course_id": 5, "assignment_id": "9"})),
            LLMResponse(content="Submit it yourself in Canvas."),
        ]
    )
    executor = FakeExecutor()
    runtime, _audit = _runtime(provider, executor)

    response = await runtime.chat(
        messages=[{"role": "user", "content": "hand it in"}],
        tools=TOOLS,
        user_id=USER,
        tutor=TutorTurn(TutorState(), [LOCK]),
    )

    assert executor.calls == []
    assert response.pending_approvals == []
    assert [b.policy for b in response.blocked_actions] == ["tutor_mode"]


@pytest.mark.asyncio
@pytest.mark.parametrize("tutor_on", [False, True])
async def test_tools_find_never_returns_a_withheld_tool(tutor_on):
    provider = RecordingProvider(
        [_round(_call("tools.find", {"query": "submit assignment", "connector": "canvas"})), LLMResponse(content="ok")]
    )
    runtime, _audit = _runtime(provider)
    tutor = TutorTurn(TutorState(user_on=tutor_on), [])

    response = await runtime.chat(
        messages=[{"role": "user", "content": "find the submit tool"}], tools=TOOLS, user_id=USER, tutor=tutor
    )

    found = {t["name"] for t in response.tool_calls[0]["result"]["tools"]}
    if tutor_on:
        assert "canvas.submit_assignment" not in found
        for call in provider.calls:
            assert "canvas.submit_assignment" not in _offered(call)
    else:
        assert "canvas.submit_assignment" in found  # the query does find it when allowed


@pytest.mark.asyncio
@pytest.mark.parametrize("remembers", [True, False])
async def test_browser_act_on_a_canvas_quiz_page_is_refused_before_any_card(remembers):
    """``remembers``: the page is known from the browser's page memory (the
    real executor), or only from this turn's own browser.read call."""
    provider = RecordingProvider(
        [
            _round(_call("browser.read", {"action": "open", "url": QUIZ}, "t1")),
            _round(_call("browser.act", {"action": "click", "ref": "e3"}, "t2")),
            LLMResponse(content="Take the quiz yourself."),
        ]
    )
    runtime, audit = _runtime(provider, FakeExecutor(QUIZ, remembers=remembers))

    response = await runtime.chat(
        messages=[{"role": "user", "content": "start my quiz"}],
        tools=TOOLS,
        user_id=USER,
        tutor=TutorTurn(TutorState(user_on=True), []),
    )

    assert response.pending_approvals == []
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [("browser.act", "tutor_rule")]
    rows = [e for e in _events(audit, "tool_blocked") if e["tool"] == "browser.act"]
    assert rows and rows[0]["rule"] == "graded_work_page" and rows[0]["policy"] == "tutor_rule"
    assert _events(audit, "tool_pending_approval") == []


@pytest.mark.asyncio
async def test_browser_act_on_a_shop_page_still_gets_its_card():
    provider = RecordingProvider([_round(_call("browser.act", {"action": "click", "ref": "e3"}))])
    runtime, _audit = _runtime(provider, FakeExecutor(SHOP))

    response = await runtime.chat(
        messages=[{"role": "user", "content": "click add to cart"}],
        tools=TOOLS,
        user_id=USER,
        tutor=TutorTurn(TutorState(user_on=True), []),
    )

    assert [p.tool_name for p in response.pending_approvals] == ["browser.act"]
    assert response.blocked_actions == []


@pytest.mark.asyncio
async def test_browser_act_on_a_quiz_page_gets_its_card_when_tutor_mode_is_off():
    provider = RecordingProvider([_round(_call("browser.act", {"action": "click", "ref": "e3"}))])
    runtime, _audit = _runtime(provider, FakeExecutor(QUIZ))

    response = await runtime.chat(
        messages=[{"role": "user", "content": "click"}],
        tools=TOOLS,
        user_id=USER,
        tutor=TutorTurn(TutorState(), []),
    )

    assert [p.tool_name for p in response.pending_approvals] == ["browser.act"]


def test_the_hooks_page_address_is_the_browsers():
    for url in (QUIZ, SHOP + "#frag", "https://x.test/a?b=c#d"):
        assert tutor_hooks._page_address(url) == page_address(url)
        assert page_address(url) == hashlib.sha1(url.partition("#")[0].encode()).hexdigest()


@pytest.mark.parametrize(
    ("url", "graded"),
    [
        ("https://c.edu/courses/5/quizzes/9", True),
        ("https://c.edu/courses/5/quizzes/9/take", True),
        ("https://c.edu/courses/5/quizzes/9/take/questions/2", True),
        ("https://c.edu/courses/5/quizzes/9/submissions/3", True),
        ("https://c.edu/courses/5/assignments/12", True),
        ("https://c.edu/courses/5/assignments/12/submissions/7?x=1", True),
        ("https://c.edu/courses/5/discussion_topics/4", True),
        ("https://c.edu/courses/5/grades", False),
        ("https://c.edu/courses/5/assignments", False),
        ("https://c.edu/courses/5/quizzes/9/history", False),
        ("https://c.edu/courses/5/modules", False),
        ("https://shop.example.com/assignments/12", False),
    ],
)
def test_graded_work_pages(url, graded):
    from services.tutor.policy import graded_work_page

    assert graded_work_page(url) is graded


@pytest.mark.asyncio
async def test_in_a_chat_the_person_switched_on_the_refusal_names_the_off_command():
    provider = RecordingProvider(
        [_round(_call("canvas.submit_assignment", {"course_id": "7"})), LLMResponse(content="ok")]
    )
    executor = FakeExecutor()
    runtime, _audit = _runtime(provider, executor)

    response = await runtime.chat(
        messages=[{"role": "user", "content": "hand it in"}],
        tools=TOOLS,
        user_id=USER,
        tutor=TutorTurn(TutorState(user_on=True), [LOCK], channel="slack"),
    )

    assert executor.calls == []
    error = response.tool_calls[0]["result"]["error"]
    assert "won't submit graded work" in error and "send tutor off first" in error
    assert response.content == "ok"  # no notice: the mode did not change this turn
