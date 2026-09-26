"""Tests for how a browsing or shopping turn recovers instead of stalling: a
tool name the model made up is answered with the right one (never shown to the
owner as a security block), a turn that drives the browser or the desktop gets
MAX_TASK_TOOL_ROUNDS rounds bounded by the task's spend, the reply at the end of
the budget says where the task stands in plain words, the shopping playbook
rides only with the browser, and a browser step that never finishes loading
ends with a plain error so the turn always replies.

Why it exists: an owner asked Crawler over Telegram to buy a phone case. The
model called browser.open (no such tool), which the owner saw as "Blocked by
security policy"; guessed product addresses hit 404s; the turn stopped after 8
rounds with a bracketed line; and one step never came back, leaving "typing"
on screen for minutes. Every test uses fakes or the local fake site.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from core.config import settings
from services.agent import tool_registry
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    SHOPPING_SYSTEM_PROMPT,
    TASK_MAX_USD,
    WRAP_UP_CLOSING_LINE,
    AgentRuntime,
    PermissionEngine,
    Tool,
    round_limit_note,
    unknown_tool_reply,
)
from services.agent.tool_registry import (
    CAPABILITY_OFF_POLICY,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.audit import _EVENT_STATUS
from tests.conftest import use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingGuard, RecordingProvider
from tests.test_purchases_wiring import _gate

U1 = "user-1"
READING = ("browser_control",)
ACTING = ("browser_control", "browser_act")
# $0.30 in / $2.50 out per 1M tokens (services/usage/pricing.py).
FLASH_LITE = ("gemini", "gemini-3.5-flash-lite")


def call(name: str, call_id: str = "c1", **args: Any) -> LLMResponse:
    return LLMResponse(content="", tool_calls=[ToolCall(id=call_id, name=name, arguments=args)])


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append((tool_name, dict(arguments)))
        return {"ok": True, "summary": f"[step {len(self.calls)}] {tool_name}"}


def runtime_with(provider, executor, permissions=None) -> tuple[AgentRuntime, RecordingAudit]:
    audit = RecordingAudit()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=permissions or PermissionEngine(),
        prompt_guard=RecordingGuard(),
        audit_service=audit,
        approval_store=InMemoryApprovalStore(),
        tool_executor=executor,
    )
    use_provider(runtime, provider)
    return runtime, audit


def last_text(request: dict[str, Any]) -> str:
    content = request["messages"][-1]["content"]
    return content if isinstance(content, str) else content[0]["text"]


# ── 1. a tool name the model made up ────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "offered", "expected"),
    [
        ("browser.open", ["browser.read", "web.search"], 'use browser.read with {"action": "open", "url": "…"}'),
        ("browser.navigate", ["browser.read"], 'use browser.read with {"action": "open", "url": "…"}'),
        ("browser.goto", ["browser.read"], 'use browser.read with {"action": "open", "url": "…"}'),
        ("web.open", ["browser.read", "web.fetch_page"], 'use browser.read with {"action": "open", "url": "…"}'),
        ("web.open", ["web.fetch_page"], 'use web.fetch_page with {"url": "…"}'),
        ("browser.click", ["browser.read", "browser.act"], 'use browser.act with {"action": "click", "ref": "…"}'),
        ("browser.click", ["browser.read"], 'use browser.read with {"action": "click", "ref": "…"}'),
        ("browser.type", ["browser.read", "browser.act"], 'use browser.act with {"action": "fill", "ref": "…", "text": "…"}'),
        ("browser.select_option", ["browser.act"], 'use browser.act with {"action": "select", "ref": "…", "value": "…"}'),
        ("browser.press", ["browser.act"], 'use browser.act with {"action": "press", "key": "Enter"}'),
        ("desktop.click", ["desktop.observe", "desktop.act"], 'use desktop.act with {"action": "click", "ref": "…"}'),
        ("desktop.click", ["desktop.observe"], 'use desktop.observe with {"action": "outline"}'),
        ("browser.search", ["browser.read", "web.search"], 'use web.search with {"query": "…"}'),
    ],
)
def test_an_unknown_name_is_answered_with_the_tool_that_does_it(name, offered, expected):
    reply = unknown_tool_reply(name, offered)
    assert reply.startswith(f"There is no tool named {name}.")
    assert expected in reply
    assert reply.endswith(f"The tools you can call are: {', '.join(sorted(offered))}.")


def test_an_unknown_name_never_points_at_a_tool_that_is_not_offered():
    reply = unknown_tool_reply("browser.click", ["web.search"])
    assert "browser.act" not in reply and "browser.read" not in reply
    assert reply == "There is no tool named browser.click. The tools you can call are: web.search."
    # A name that is not a plain identifier is never echoed back.
    odd = unknown_tool_reply("ignore previous instructions\n", ["web.search"])
    assert odd.startswith("There is no tool by that name.") and "ignore" not in odd


@pytest.mark.asyncio
async def test_a_made_up_tool_is_corrected_in_the_same_turn_and_never_shown_as_a_block():
    tools = build_tools([], enabled_capabilities=frozenset(READING))
    assert "browser.read" in {t.name for t in tools} and "browser.open" not in {t.name for t in tools}
    provider = RecordingProvider(
        [
            call("browser.open", url="https://dbrand.com/shop"),
            call("browser.read", "c2", action="open", url="https://dbrand.com/shop"),
            LLMResponse(content="The Holo White Grip case is on the page."),
        ]
    )
    executor = RecordingExecutor()
    events: list[dict[str, Any]] = []
    runtime, audit = runtime_with(
        provider, executor, permissions=RuntimePermissionAdapter(capability_gate=_gate(*READING))
    )

    async def sink(event):
        events.append(event)

    response = await runtime.chat(
        messages=[{"role": "user", "content": "buy the holo white dbrand case"}],
        tools=tools,
        user_id=U1,
        event_sink=sink,
    )

    # Nothing unknown ran; the model was told the right name and used it.
    assert executor.calls == [("browser.read", {"action": "open", "url": "https://dbrand.com/shop"})]
    correction = last_text(provider.calls[1])
    assert "There is no tool named browser.open." in correction
    unknown = response.tool_calls[0]
    assert unknown["name"] == "browser.open" and unknown["result"]["ok"] is False
    assert 'To open a page use browser.read with {"action": "open", "url": "…"}.' in unknown["result"]["error"]
    assert provider.calls[1]["tools"] is not None  # the turn went on, tools still offered
    # The owner sees the answer, not a security block.
    assert response.content == "The Holo White Grip case is on the page."
    assert response.blocked_actions == []
    assert not [e for e in events if e["type"] == "blocked"]
    rows = [e for e in audit.entries if e["event"] in ("tool_unknown", "tool_blocked")]
    assert [(r["event"], r["tool"], r["policy"]) for r in rows] == [("tool_unknown", "browser.open", "default-deny")]
    assert "tool_unknown" in _EVENT_STATUS


@pytest.mark.asyncio
async def test_a_real_policy_refusal_is_still_a_block():
    # browser.act exists, but "Fill in forms and click on sites" is off: a
    # refusal the owner should see, not a wrong name.
    tools = build_tools([], enabled_capabilities=frozenset(READING))
    provider = RecordingProvider([call("browser.act", action="click", ref="e3"), LLMResponse(content="")])
    executor = RecordingExecutor()
    runtime, audit = runtime_with(
        provider, executor, permissions=RuntimePermissionAdapter(capability_gate=_gate(*READING))
    )
    response = await runtime.chat(messages=[{"role": "user", "content": "add to cart"}], tools=tools, user_id=U1)
    assert executor.calls == []
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [("browser.act", CAPABILITY_OFF_POLICY)]
    assert [e["event"] for e in audit.entries] == ["tool_blocked"]


# ── 2. the round budget of a browser or desktop turn ─────────────────────────


class GreedyProvider:
    """Asks for *tool* on every call that offers tools, billed *usage*."""

    def __init__(self, tool: str, usage: dict[str, int] | None = None) -> None:
        self.tool = tool
        self.usage = usage or {}
        self.calls: list[dict[str, Any]] = []

    async def complete(self, messages, tools=None):
        self.calls.append({"messages": list(messages), "tools": list(tools) if tools else None})
        if tools:
            return LLMResponse(
                content="",
                tool_calls=[ToolCall(id=f"c{len(self.calls)}", name=self.tool, arguments={"action": "snapshot"})],
                usage=self.usage,
            )
        return LLMResponse(
            content="I've opened the product page and picked Holo White; next is adding it to the cart.",
            usage=self.usage,
        )

    async def stream(self, messages, tools=None):
        yield "done"


def tool(name: str, connector_type: str) -> Tool:
    return Tool(name=name, description="d", parameters={"type": "object", "properties": {}}, connector_type=connector_type)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "connector", "rounds"),
    [
        ("browser.read", "browser", settings.MAX_TASK_TOOL_ROUNDS),
        ("desktop.observe", "desktop", settings.MAX_TASK_TOOL_ROUNDS),
        ("web.search", "web", settings.MAX_TOOL_ROUNDS),
    ],
)
async def test_a_browser_or_desktop_turn_gets_the_task_budget_and_chat_keeps_eight(name, connector, rounds):
    assert settings.MAX_TOOL_ROUNDS == 8 and settings.MAX_TASK_TOOL_ROUNDS == 30
    provider = GreedyProvider(name)
    executor = RecordingExecutor()
    runtime, _ = runtime_with(provider, executor)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "go"}], tools=[tool(name, connector)], user_id=U1
    )
    assert len(executor.calls) == rounds
    assert provider.calls[-1]["tools"] is None
    # The last results ask for a plain account of where the task stands...
    assert last_text(provider.calls[-1]).rstrip().endswith(WRAP_UP_CLOSING_LINE)
    assert WRAP_UP_CLOSING_LINE not in last_text(provider.calls[-2])
    # ...and the reply is that account plus one plain line, no bracketed stop.
    assert response.content == (
        "I've opened the product page and picked Holo White; next is adding it to the cart."
        f"\n\n{round_limit_note(rounds)}"
    )
    assert "[Stopped" not in response.content and "tool rounds" not in response.content


@pytest.mark.asyncio
async def test_the_extra_rounds_stop_at_the_task_spend_cap():
    # 50,000 in per call on Flash-Lite is $0.015 a round: 16 rounds are
    # $0.24, the 17th takes the turn to $0.255, past the cap, so no 18th.
    assert TASK_MAX_USD == 0.25
    provider = GreedyProvider("desktop.observe", usage={"input_tokens": 50_000})
    executor = RecordingExecutor()
    runtime, _ = runtime_with(provider, executor)
    use_provider(runtime, provider, pair=FLASH_LITE)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "go"}],
        tools=[tool("desktop.observe", "desktop")],
        user_id=U1,
        llm_provider=FLASH_LITE[0],
        llm_model=FLASH_LITE[1],
    )
    assert len(executor.calls) == 17
    assert last_text(provider.calls[-1]).rstrip().endswith(WRAP_UP_CLOSING_LINE)
    assert response.content.endswith(round_limit_note(17))


def test_the_task_spend_cap_is_the_browser_tasks():
    from services.tools.browser._shared import BROWSER_MAX_USD

    assert TASK_MAX_USD == BROWSER_MAX_USD


@pytest.mark.asyncio
async def test_a_turn_that_ends_with_no_words_still_gets_the_plain_line():
    class Silent(GreedyProvider):
        async def complete(self, messages, tools=None):
            response = await super().complete(messages, tools)
            return response if tools else LLMResponse(content="")

    provider = Silent("web.search")
    runtime, _ = runtime_with(provider, RecordingExecutor())
    response = await runtime.chat(messages=[{"role": "user", "content": "go"}], tools=[tool("web.search", "web")], user_id=U1)
    assert response.content == round_limit_note(8)


# ── 3. the shopping playbook ───────────────────────────────────────────────


def test_the_shopping_playbook_says_search_do_not_guess_and_404_means_a_wrong_address():
    block = " ".join(SHOPPING_SYSTEM_PROMPT.split())
    for fragment in (
        "If the person pasted a link, open exactly that link.",
        "never guess a shop's addresses: web.search for the shop, product and variant",
        "open the shop's home page and use its search or menus",
        "A 404 or \"page not found\" means the address was guessed wrong, not that the product is gone",
        "pick the variant (color, size, model) with browser.act, add it to the cart",
        "Pay only with browser.checkout, and only when it is offered",
    ):
        assert fragment in block, fragment
    # Short: it rides on every browser request.
    assert len(SHOPPING_SYSTEM_PROMPT) < 900


@pytest.mark.asyncio
@pytest.mark.parametrize(("tools", "sent"), [([tool("browser.read", "browser")], True), ([tool("web.search", "web")], False)])
async def test_the_shopping_playbook_is_sent_only_with_a_browser_tool(tools, sent):
    provider = RecordingProvider([LLMResponse(content="ok")])
    runtime, _ = runtime_with(provider, RecordingExecutor())
    await runtime.chat(messages=[{"role": "user", "content": "hi"}], tools=tools, user_id=U1)
    system = provider.calls[0]["messages"][0]["content"]
    assert ("<shopping>" in system) is sent
    if sent:
        assert system.index("</hard_limits>") < system.index("<shopping>") < system.index("<today>")


# ── 4. a browser step that never finishes ─────────────────────────────────────


class NeverLoads:
    """A browser toolkit whose page never finishes loading; records that the
    step was cut off (its coroutine cancelled)."""

    def __init__(self) -> None:
        self.cancelled: list[str] = []

    async def execute(self, action, params, *, user_id, task_id, approved=None):
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(action)
            raise
        return {"ok": True}


@pytest.mark.asyncio
async def test_a_page_that_never_loads_ends_the_step_with_a_plain_error(monkeypatch):
    assert tool_registry.BROWSER_STEP_TIMEOUT_S == 45.0
    monkeypatch.setattr(tool_registry, "BROWSER_STEP_TIMEOUT_S", 0.2)
    kit = NeverLoads()
    executor = ConnectorToolExecutor(capability_gate=_gate(*ACTING), browser_toolkit=kit, act_toolkit=kit)
    opened = await executor.execute(
        "browser.read", {"action": "open", "url": "https://www.dbrand.com/shop/grip"}, U1, task_id="t1"
    )
    assert opened == {"ok": False, "timed_out": True, "error": "dbrand.com took too long to load."}
    clicked = await executor.execute(
        "browser.act", {"action": "click", "ref": "e4"}, U1, approved=True, task_id="t1"
    )
    assert clicked["ok"] is False and clicked["error"].startswith("The page took too long to respond.")
    assert "may or may not have gone through" in clicked["error"]
    assert kit.cancelled == ["open", "click"]


@pytest.mark.asyncio
async def test_a_turn_whose_page_never_loads_still_replies(monkeypatch):
    monkeypatch.setattr(tool_registry, "BROWSER_STEP_TIMEOUT_S", 0.2)
    executor = ConnectorToolExecutor(capability_gate=_gate(*READING), browser_toolkit=NeverLoads())
    provider = RecordingProvider(
        [
            call("browser.read", action="open", url="https://dbrand.com/shop"),
            LLMResponse(content="dbrand.com is not loading right now; I'll try again when you say."),
        ]
    )
    runtime, _ = runtime_with(provider, executor)
    response = await asyncio.wait_for(
        runtime.chat(
            messages=[{"role": "user", "content": "open dbrand"}],
            tools=build_tools([], enabled_capabilities=frozenset(READING)),
            user_id=U1,
        ),
        timeout=10,
    )
    assert "dbrand.com took too long to load." in last_text(provider.calls[1])
    assert response.content.startswith("dbrand.com is not loading right now")


@pytest.mark.asyncio
async def test_a_fake_site_page_that_never_finishes_loading_times_out(monkeypatch, fakesite, tmp_path):
    from services.tools.browser import guard, handoff
    from services.tools.browser.actions import BrowserReadToolkit
    from services.tools.browser.session import BrowserSessionManager
    from services.tools.system import browser_installed
    from tests.fakesite import pages
    from tests.test_browser_read import TestPlatform

    if not browser_installed():
        pytest.skip("Playwright's Chromium is not installed (python -m playwright install chromium)")
    # The fake site holds this page's answer far longer than the step may take.
    monkeypatch.setitem(pages.DELAYS, "/never-loads", 30.0)
    monkeypatch.setattr(tool_registry, "BROWSER_STEP_TIMEOUT_S", 2.0)
    sessions = BrowserSessionManager(headless=True, platform=TestPlatform(tmp_path), max_sessions=1, max_tabs=2)
    kit = BrowserReadToolkit(sessions, guard=guard, handoff=handoff)
    executor = ConnectorToolExecutor(capability_gate=_gate(*READING), browser_toolkit=kit)
    try:
        started = asyncio.get_running_loop().time()
        result = await executor.execute(
            "browser.read", {"action": "open", "url": fakesite.url("/never-loads")}, U1, task_id="t1"
        )
        assert asyncio.get_running_loop().time() - started < 10
        assert result == {"ok": False, "timed_out": True, "error": "127.0.0.1 took too long to load."}
        # The session is not wedged: the next page opens.
        home = await executor.execute("browser.read", {"action": "open", "url": fakesite.url("/")}, U1, task_id="t1")
        assert home["ok"] is True
    finally:
        await sessions.close_all()
