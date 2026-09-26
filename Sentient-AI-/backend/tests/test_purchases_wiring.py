"""Tests for wiring browser.act and browser.checkout into the platform: the
policy (browser FINANCIAL asks, every connector's stays blocked), the catalog
(act WRITE and checkout FINANCIAL with their schemas), the offer (checkout only
with both capabilities on, always as approval), the permission adapter and the
executor (refusals by capability, unapproved calls, dispatch to the toolkits),
the approval hooks (describe, precheck, bind, the async bind that builds the
purchase card from the page, the card's picture), the runtime (a bind refusal
is filed under purchase_rule with no card; a card carries its picture; an
approved checkout reaches the toolkit's run), the audit redaction of what
browser.act types, the prompt lines, and main.wire_services.

Why it exists: browser.checkout is the only tool that ever moves money. Each
seam here is one place a mistake would let it run unattended, run with a
switch off, skip the page checks, or show the owner the model's words instead
of the page's facts. Every test uses fake toolkits; nothing opens a browser,
reads a card or touches the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Optional

import pytest

from services import capabilities as capability_registry
from services.agent import cancel
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.runtime import (
    BROWSER_RULE_POLICY,
    CHECKOUT_TOOL,
    PRECHECK_ERROR_POLICY,
    PURCHASE_RULE_POLICY,
    SECURITY_SYSTEM_PROMPT,
    AgentRuntime,
    PendingApproval,
    PrecheckRefusal,
    Tool,
    _capability_refusal,
)
from services.agent.tool_registry import (
    _BUILTIN_STANCE,
    _REQUIRED_CAPABILITIES,
    CAPABILITY_OFF_POLICY,
    CHECKOUT_CARD_KEY,
    CONNECTOR_CATALOG,
    FINANCIAL_BUILTINS,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    capabilities_of_tool,
    capability_of_tool,
    resolve_tool,
)
from services.audit import redact_tool_arguments
from services.capabilities.base import ReportContext

U1 = "user-1"
ACT = "browser.act"
CHECKOUT = "browser.checkout"
IMAGE = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsL"
CONFIRMATION = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAs="
CARD = {
    "checkout_id": "chk-1",
    "origin": "https://shop.example.com",
    "host": "shop.example.com",
    "amount_usd": "23.40",
    "currency": "USD",
    "items": ["Concert ticket — $19.00", "Service fee — $4.40"],
    "card_label": "Visa ····4242",
    "outline": "9f2c1a",
    "notice": "Crawler can make mistakes. Check the amount and the site before you approve.",
}
BOTH = ("browser_control", "purchases")
# Reading and acting: what browser.act needs on.
ACTING = ("browser_control", "browser_act")
# Every browser switch on.
ALL = ("browser_control", "browser_act", "purchases")


# ── fakes ────────────────────────────────────────────────────────────────


class FakeActToolkit:
    """The act toolkit's five methods, recording calls; ``precheck`` answers
    what it was built with."""

    def __init__(self, precheck: Optional[dict[str, Any]] = None) -> None:
        self.calls: list[tuple] = []
        self._precheck = precheck

    def precheck(self, params, *, user_id):
        self.calls.append(("precheck", dict(params), user_id))
        return self._precheck

    def bind(self, params, *, user_id):
        self.calls.append(("bind", dict(params), user_id))
        return {**params, "_page": {"origin": "https://shop.example.com", "outline": "9f2c1a", "scheme": "https"}}

    def describe(self, params, *, user_id):
        self.calls.append(("describe", dict(params), user_id))
        return 'Click "Continue to payment" on shop.example.com'

    async def execute(self, action, params, *, user_id, task_id, approved):
        self.calls.append(("execute", action, dict(params), user_id, task_id, approved))
        return {"ok": True, "did": f"{action} done", "url": "https://shop.example.com/checkout"}


class FakeCheckoutToolkit:
    """The checkout toolkit's five methods, recording calls. ``precheck``
    and ``begin`` answer what they were built with (None: no refusal;
    begin then answers the card arguments with ``_checkout``)."""

    def __init__(
        self,
        precheck: Optional[dict[str, Any]] = None,
        begin: Optional[dict[str, Any]] = None,
        image: Optional[str] = IMAGE,
    ) -> None:
        self.calls: list[tuple] = []
        self._precheck = precheck
        self._begin = begin
        self._image = image

    async def precheck(self, params, *, user_id):
        self.calls.append(("precheck", dict(params), user_id))
        return self._precheck

    async def begin(self, params, *, user_id, task_id):
        self.calls.append(("begin", dict(params), user_id, task_id))
        if self._begin is not None:
            return dict(self._begin)
        return {**params, CHECKOUT_CARD_KEY: dict(CARD)}

    def describe(self, arguments, *, user_id):
        self.calls.append(("describe", dict(arguments), user_id))
        return "Pay $23.40 to shop.example.com (2 items) with Visa ····4242"

    def approval_image(self, arguments, *, user_id):
        self.calls.append(("approval_image", dict(arguments), user_id))
        card = arguments.get(CHECKOUT_CARD_KEY) or {}
        return self._image if card.get("checkout_id") == CARD["checkout_id"] else None

    async def run(self, arguments, *, user_id, task_id, approved):
        self.calls.append(("run", dict(arguments), user_id, task_id, approved))
        return {
            "ok": True,
            "merchant": "shop.example.com",
            "amount": "23.40",
            "currency": "USD",
            "confirmation_text_summary": "Thank you. Order number 8841",
            "user_image": CONFIRMATION,
            "summary": "[step 3] checkout → shop.example.com/order-confirmed",
            "mode": "browser",
        }


class RecordingBrowserToolkit:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def execute(self, action, params, *, user_id, task_id):
        self.calls.append((action, params, user_id, task_id))
        return {"ok": True}


def _gate(*keys: str, **ctx_overrides: Any):
    """The owner's report with exactly *keys* switched on (Windows: no OS
    permission is asked, the vault is available, a browser is installed)."""
    ctx = ReportContext(
        **{
            "in_container": False,
            "platform": "win32",
            "telegram_configured": True,
            "browser_installed": True,
            "playwright_installed": True,
            "browser_channel": "chrome",
            "host_platform": "windows",
            **ctx_overrides,
        }
    )
    switches = {k: k in keys for k in capability_registry.keys()}
    statuses = capability_registry.statuses_by_key(
        capability_registry.report(switches, ctx, use_cache=False)
    )

    async def gate():
        return statuses

    return gate


def executor(
    *keys: str,
    act: Optional[FakeActToolkit] = None,
    checkout: Optional[FakeCheckoutToolkit] = None,
    browser: Optional[RecordingBrowserToolkit] = None,
) -> ConnectorToolExecutor:
    return ConnectorToolExecutor(
        session_factory=None,
        capability_gate=_gate(*keys),
        browser_toolkit=browser or RecordingBrowserToolkit(),
        act_toolkit=act,
        checkout_toolkit=checkout,
    )


def names(tools):
    return {t.name for t in tools}


@pytest.fixture(autouse=True)
def _no_stale_stop():
    cancel.clear(U1)
    yield
    cancel.clear(U1)


# ── 1. policy ────────────────────────────────────────────────────────────


def test_browser_financial_asks_and_every_connector_financial_stays_blocked():
    engine = PermissionEngine()
    checkout = engine.check_permission("browser", "checkout", ActionCategory.FINANCIAL)
    assert checkout.tier == PermissionTier.USER_CONFIRM and checkout.requires_approval
    for key in ("robinhood", "gmail", "google_calendar", "canvas", "github", "todoist", "web"):
        decision = engine.check_permission(key, "checkout", ActionCategory.FINANCIAL)
        assert decision.tier == PermissionTier.HARD_BLOCKED, key
    assert engine.check_permission("browser", "buy", ActionCategory.FINANCIAL).tier == (
        PermissionTier.HARD_BLOCKED
    )


def test_financial_builtins_and_required_capabilities_name_checkout_only():
    assert FINANCIAL_BUILTINS == frozenset({("browser", "checkout")})
    assert _REQUIRED_CAPABILITIES == {
        ("browser", "act"): ("browser_control",),
        ("browser", "checkout"): ("browser_control", "purchases"),
    }
    assert _BUILTIN_STANCE["browser"] == "user_confirm"


# ── 2. catalog ───────────────────────────────────────────────────────────


def _spec(action: str):
    return next(s for s in CONNECTOR_CATALOG["browser"] if s.action == action)


def test_browser_catalog_has_read_act_and_checkout():
    assert [s.action for s in CONNECTOR_CATALOG["browser"]] == ["read", "act", "checkout"]
    assert _spec("act").category == ActionCategory.WRITE
    assert _spec("checkout").category == ActionCategory.FINANCIAL
    assert resolve_tool(ACT).spec.category == ActionCategory.WRITE
    assert resolve_tool(CHECKOUT).spec.category == ActionCategory.FINANCIAL
    assert resolve_tool("browser__deadbeef.checkout") is None


def test_act_schema_matches_the_toolkit_contract():
    params = _spec("act").parameters
    assert params["required"] == ["action"]
    assert params["properties"]["action"]["enum"] == [
        "fill", "fill_form", "select", "check", "click", "press", "submit",
    ]
    assert set(params["properties"]) == {"action", "ref", "text", "fields", "value", "key"}
    assert params["properties"]["key"]["enum"] == ["Enter", "Tab", "Escape", "ArrowDown", "ArrowUp"]
    assert params["properties"]["fields"]["items"]["required"] == ["ref", "text"]
    assert "2000" in params["properties"]["text"]["description"]
    assert "12" in params["properties"]["fields"]["description"]
    description = _spec("act").description.lower()
    assert "approve" in description and "password" in description and "card" in description


def test_checkout_schema_is_merchant_amount_note():
    params = _spec("checkout").parameters
    assert params["required"] == ["merchant"]
    assert set(params["properties"]) == {"merchant", "amount", "note"}
    assert params["properties"]["amount"]["type"] == "number"
    description = _spec("checkout").description.lower()
    for fragment in ("approve", "https", "merchant", "screenshot", "filled from the vault, never"):
        assert fragment in description, fragment
    # An install with buying off is offered browser.act but never
    # browser.checkout, so act's own text must not send the model to it.
    assert "checkout" not in _spec("act").description.lower()


def test_capabilities_of_tool_lists_the_claiming_then_the_required():
    assert [c.key for c in capabilities_of_tool(CHECKOUT)] == ["purchases", "browser_control"]
    assert [c.key for c in capabilities_of_tool(ACT)] == ["browser_act", "browser_control"]
    assert [c.key for c in capabilities_of_tool("browser.read")] == ["browser_control"]
    assert capabilities_of_tool("system.capabilities") == ()
    assert capabilities_of_tool("nope") == () and capabilities_of_tool("browser__1234abcd.checkout") == ()
    assert capability_of_tool(CHECKOUT).key == "purchases"


# ── 3. offer ─────────────────────────────────────────────────────────────


def test_act_is_offered_with_both_browser_switches_on_and_always_as_approval():
    assert ACT not in names(build_tools([]))
    assert ACT not in names(build_tools([], enabled_capabilities=frozenset({"browser_control"})))
    assert ACT not in names(build_tools([], enabled_capabilities=frozenset({"browser_act"})))
    tools = build_tools([], enabled_capabilities=frozenset(ACTING))
    act = next(t for t in tools if t.name == ACT)
    assert act.permission_tier == "approval"
    auto = build_tools([], user_default_tier="auto_approve", enabled_capabilities=frozenset(ACTING))
    assert next(t for t in auto if t.name == ACT).permission_tier == "approval"


def test_checkout_is_offered_only_with_both_capabilities_on_and_never_auto():
    assert CHECKOUT not in names(build_tools([]))
    assert CHECKOUT not in names(build_tools([], enabled_capabilities=frozenset({"purchases"})))
    assert CHECKOUT not in names(build_tools([], enabled_capabilities=frozenset({"browser_control"})))
    tools = build_tools([], enabled_capabilities=frozenset(BOTH))
    checkout = next(t for t in tools if t.name == CHECKOUT)
    assert checkout.permission_tier == "approval"
    assert checkout.connector_type == "browser"
    auto = build_tools([], user_default_tier="auto_approve", enabled_capabilities=frozenset(BOTH))
    assert next(t for t in auto if t.name == CHECKOUT).permission_tier == "approval"
    assert next(t for t in auto if t.name == "browser.read").permission_tier == "auto"


# ── 4. permission adapter ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adapter_blocks_checkout_until_both_capabilities_are_on():
    purchases_off = RuntimePermissionAdapter(capability_gate=_gate("browser_control"))
    assert await purchases_off.check(U1, CHECKOUT, {}) == "blocked"
    assert await purchases_off.get_policy_name(U1, CHECKOUT) == CAPABILITY_OFF_POLICY
    assert await purchases_off.get_block_reason(U1, CHECKOUT, {}) == (
        "Buying things is off. Turn on 'Buy things for me' in Permissions."
    )
    browser_off = RuntimePermissionAdapter(capability_gate=_gate("purchases"))
    assert await browser_off.check(U1, CHECKOUT, {}) == "blocked"
    assert "Browser control" in await browser_off.get_block_reason(U1, CHECKOUT, {})
    both = RuntimePermissionAdapter(capability_gate=_gate(*BOTH))
    assert await both.check(U1, CHECKOUT, {}) == "requires_approval"
    assert await both.get_policy_name(U1, CHECKOUT) == "browser:financial"
    # Buying on does not switch acting on: browser.act is its own switch.
    assert await both.check(U1, ACT, {}) == "blocked"
    assert await RuntimePermissionAdapter(capability_gate=_gate(*ALL)).check(U1, ACT, {}) == (
        "requires_approval"
    )


@pytest.mark.asyncio
async def test_adapter_blocks_checkout_in_a_container_as_blocked():
    from services.agent.runtime import CAPABILITY_BLOCKED_POLICY

    adapter = RuntimePermissionAdapter(
        capability_gate=_gate(*BOTH, in_container=True, host_platform="container")
    )
    assert await adapter.check(U1, CHECKOUT, {}) == "blocked"
    assert await adapter.get_policy_name(U1, CHECKOUT) == CAPABILITY_BLOCKED_POLICY
    assert "card vault" in await adapter.get_block_reason(U1, CHECKOUT, {})


# ── 5. executor ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_executor_refuses_checkout_with_purchases_off_with_the_plain_reason():
    kit = FakeCheckoutToolkit()
    ex = executor("browser_control", checkout=kit)
    result = await ex.execute(CHECKOUT, {"merchant": "shop.example.com"}, user_id=U1, approved=True)
    assert result == {
        "ok": False,
        "capability": "purchases",
        "state": "off",
        "error": "Buying things is off. Turn on 'Buy things for me' in Permissions.",
    }
    assert kit.calls == []


@pytest.mark.asyncio
async def test_executor_refuses_checkout_with_browser_control_off():
    kit = FakeCheckoutToolkit()
    ex = executor("purchases", checkout=kit)
    result = await ex.execute(CHECKOUT, {"merchant": "shop.example.com"}, user_id=U1, approved=True)
    assert result["ok"] is False and result["capability"] == "browser_control"
    assert result["state"] == "off"
    assert kit.calls == []


@pytest.mark.asyncio
async def test_executor_refuses_unapproved_act_and_checkout():
    act, checkout = FakeActToolkit(), FakeCheckoutToolkit()
    ex = executor(*ALL, act=act, checkout=checkout)
    for tool, args in ((ACT, {"action": "click", "ref": "e7"}), (CHECKOUT, {"merchant": "x"})):
        result = await ex.execute(tool, {**args, "user_confirmed": True}, user_id=U1)
        assert result["ok"] is False and result["requires_approval"] is True
        assert "acts in the browser or pays" in result["error"]
    assert act.calls == [] and checkout.calls == []


@pytest.mark.asyncio
async def test_executor_dispatches_an_approved_checkout_with_the_card_and_task():
    kit = FakeCheckoutToolkit()
    ex = executor(*BOTH, checkout=kit)
    card = {"merchant": "shop.example.com", "amount": 23.4, CHECKOUT_CARD_KEY: dict(CARD)}
    result = await ex.execute(
        CHECKOUT, {**card, "user_confirmed": True}, user_id=U1, approved=True, task_id="conv-9"
    )
    assert result["ok"] is True and result["amount"] == "23.40"
    assert kit.calls == [("run", card, U1, "conv-9", True)]


@pytest.mark.asyncio
async def test_executor_dispatches_an_approved_act_without_its_action_key():
    kit = FakeActToolkit()
    ex = executor(*ACTING, act=kit)
    result = await ex.execute(
        ACT,
        {"action": "fill", "ref": "e3", "text": "hi", "_page": {"origin": "o"}},
        user_id=U1,
        approved=True,
        task_id="conv-9",
    )
    assert result["ok"] is True
    assert kit.calls == [
        ("execute", "fill", {"ref": "e3", "text": "hi", "_page": {"origin": "o"}}, U1, "conv-9", True)
    ]


@pytest.mark.asyncio
async def test_executor_keeps_read_on_the_read_toolkit():
    browser = RecordingBrowserToolkit()
    ex = executor("browser_control", browser=browser, act=FakeActToolkit())
    await ex.execute("browser.read", {"action": "tabs"}, user_id=U1)
    assert browser.calls == [("tabs", {}, U1, U1)]


@pytest.mark.asyncio
async def test_unwired_act_and_checkout_are_refused_not_run():
    ex = executor(*ALL)
    for tool, args in ((ACT, {"action": "click", "ref": "e7"}), (CHECKOUT, {"merchant": "x"})):
        result = await ex.execute(tool, args, user_id=U1, approved=True)
        assert result["ok"] is False and result["rule"] == "unavailable"
        assert "not set up in this process" in result["error"]
        refusal = ex.precheck_approval(tool, args, U1)
        assert isinstance(refusal, PrecheckRefusal) and refusal.rule == "unavailable"
    assert ex.describe_approval(ACT, {"action": "click"}, U1) is None
    assert ex.approval_image(CHECKOUT, {CHECKOUT_CARD_KEY: CARD}, U1) is None
    bound = await ex.approval_arguments_async(CHECKOUT, {"merchant": "x"}, U1, task_id="t")
    assert bound["refused"] is True and bound["rule"] == "unavailable"


@pytest.mark.asyncio
async def test_connector_financial_actions_are_still_never_executed():
    ex = executor(*BOTH, checkout=FakeCheckoutToolkit())
    result = await ex.execute("robinhood.execute_trade", {"symbol": "BTC", "side": "buy"}, U1, approved=True)
    assert result["ok"] is False and "permanently blocked" in result["error"]


def test_every_builtin_type_still_has_a_stance_and_an_executor_entry():
    from services.agent.tool_registry import BUILTIN_CONNECTOR_TYPES

    assert set(_BUILTIN_STANCE) == set(BUILTIN_CONNECTOR_TYPES)
    assert set(ConnectorToolExecutor()._builtins) == set(BUILTIN_CONNECTOR_TYPES)


# ── 6. approval hooks ────────────────────────────────────────────────────


def test_describe_routes_act_and_checkout_to_their_toolkits():
    act, checkout = FakeActToolkit(), FakeCheckoutToolkit()
    ex = executor(*ALL, act=act, checkout=checkout)
    assert ex.describe_approval(ACT, {"action": "click", "ref": "e7", "user_confirmed": True}, U1) == (
        'Click "Continue to payment" on shop.example.com'
    )
    assert act.calls == [("describe", {"action": "click", "ref": "e7"}, U1)]
    assert ex.describe_approval(CHECKOUT, {"merchant": "x", CHECKOUT_CARD_KEY: CARD}, U1) == (
        "Pay $23.40 to shop.example.com (2 items) with Visa ····4242"
    )
    assert ex.describe_approval("browser.read", {"action": "open"}, U1) is None
    assert ex.describe_approval("gmail.send_email", {"to": "a@b.c"}, U1) is None


def test_precheck_routes_act_to_the_toolkit_under_browser_rule():
    refused = {"ok": False, "refused": True, "rule": "secure_field", "error": "That is a password field."}
    ex = executor("browser_control", act=FakeActToolkit(precheck=refused))
    refusal = ex.precheck_approval(ACT, {"action": "fill", "ref": "e9", "text": "x", "user_confirmed": True}, U1)
    assert isinstance(refusal, PrecheckRefusal)
    assert refusal.policy == BROWSER_RULE_POLICY and refusal.rule == "secure_field"
    assert refusal.reason == "That is a password field." and refusal.result == refused
    ok = executor("browser_control", act=FakeActToolkit())
    assert ok.precheck_approval(ACT, {"action": "click", "ref": "e7"}, U1) is None
    stale = executor("browser_control", act=FakeActToolkit(precheck={"ok": False, "stale_ref": True, "error": "gone"}))
    assert stale.precheck_approval(ACT, {"action": "click", "ref": "e7"}, U1).rule == "stale_ref"


def test_checkout_precheck_refuses_a_forged_card_and_a_stopped_user():
    ex = executor(*BOTH, checkout=FakeCheckoutToolkit())
    assert ex.precheck_approval(CHECKOUT, {"merchant": "shop.example.com"}, U1) is None
    forged = ex.precheck_approval(CHECKOUT, {"merchant": "x", CHECKOUT_CARD_KEY: {"amount_usd": "1"}}, U1)
    assert forged.policy == PURCHASE_RULE_POLICY and forged.rule == "invalid_arguments"
    assert forged.result["refused"] is True
    cancel.request_cancel(U1)
    stopped = ex.precheck_approval(CHECKOUT, {"merchant": "x"}, U1)
    assert stopped.rule == "cancelled" and stopped.policy == PURCHASE_RULE_POLICY


def test_bind_ties_act_to_its_page_and_leaves_checkout_to_the_async_hook():
    act, checkout = FakeActToolkit(), FakeCheckoutToolkit()
    ex = executor(*ALL, act=act, checkout=checkout)
    bound = ex.approval_arguments(ACT, {"action": "click", "ref": "e7"}, U1)
    assert bound["_page"]["origin"] == "https://shop.example.com"
    args = {"merchant": "shop.example.com"}
    assert ex.approval_arguments(CHECKOUT, args, U1) is args
    assert checkout.calls == []


@pytest.mark.asyncio
async def test_async_bind_runs_checkout_precheck_then_begin():
    checkout = FakeCheckoutToolkit()
    ex = executor(*BOTH, checkout=checkout)
    bound = await ex.approval_arguments_async(
        CHECKOUT, {"merchant": "shop.example.com", "amount": 23.4, "user_confirmed": True}, U1, task_id="conv-9"
    )
    assert bound[CHECKOUT_CARD_KEY] == CARD
    assert bound["merchant"] == "shop.example.com" and "user_confirmed" not in bound
    params = {"merchant": "shop.example.com", "amount": 23.4}
    assert checkout.calls == [("precheck", params, U1), ("begin", params, U1, "conv-9")]
    # No task id: the user-keyed task the dispatch would use.
    await ex.approval_arguments_async(CHECKOUT, params, U1, task_id=None)
    assert checkout.calls[-1] == ("begin", params, U1, U1)


@pytest.mark.asyncio
async def test_async_bind_answers_the_toolkit_refusal_with_refused_true():
    no_card = {"ok": False, "rule": "no_card", "error": "No payment card is stored."}
    ex = executor(*BOTH, checkout=FakeCheckoutToolkit(precheck=no_card))
    bound = await ex.approval_arguments_async(CHECKOUT, {"merchant": "x"}, U1, task_id="t")
    assert bound == {**no_card, "refused": True}
    over = {"ok": False, "refused": True, "rule": "over_cap", "error": "That is over your per-purchase cap."}
    ex = executor(*BOTH, checkout=FakeCheckoutToolkit(begin=over))
    assert await ex.approval_arguments_async(CHECKOUT, {"merchant": "x"}, U1, task_id="t") == over


@pytest.mark.asyncio
async def test_async_bind_falls_back_to_the_sync_hook_for_other_tools():
    act = FakeActToolkit()
    ex = executor(*BOTH, act=act, checkout=FakeCheckoutToolkit())
    bound = await ex.approval_arguments_async(ACT, {"action": "click", "ref": "e7"}, U1, task_id="t")
    assert "_page" in bound
    args = {"to": "a@b.c"}
    assert await ex.approval_arguments_async("gmail.send_email", args, U1, task_id="t") is args


def test_approval_image_answers_for_checkout_only():
    checkout = FakeCheckoutToolkit()
    ex = executor(*BOTH, act=FakeActToolkit(), checkout=checkout)
    assert ex.approval_image(CHECKOUT, {"merchant": "x", CHECKOUT_CARD_KEY: CARD}, U1) == IMAGE
    assert ex.approval_image(CHECKOUT, {"merchant": "x"}, U1) is None
    assert ex.approval_image(ACT, {"action": "click", CHECKOUT_CARD_KEY: CARD}, U1) is None
    assert ex.approval_image("desktop.act", {"action": "click"}, U1) is None


# ── 7. runtime ───────────────────────────────────────────────────────────


class ScriptedProvider:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list = []

    async def complete(self, messages, tools=None):
        from services.agent.providers import LLMResponse

        self.calls.append(messages)
        return self._responses.pop(0) if self._responses else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"


class RecordingAudit:
    def __init__(self):
        self.entries = []

    async def log(self, entry):
        self.entries.append(entry)

    def events_for(self, tool):
        return [e["event"] for e in self.entries if e.get("tool") == tool]


class Turn:
    """One runtime turn on fake toolkits, capturing its events."""

    def __init__(self, ex: ConnectorToolExecutor, gate) -> None:
        from core.config import settings
        from services.agent.approvals import InMemoryApprovalStore
        from services.agent.runtime import AgentRuntime

        self.executor = ex
        self.audit = RecordingAudit()
        self.store = InMemoryApprovalStore()
        self.events: list[dict] = []
        self.runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(capability_gate=gate),
            tool_executor=ex,
            audit_service=self.audit,
            approval_store=self.store,
        )

    async def run(self, *responses, tools=None, task_id="conv-9"):
        from tests.conftest import use_provider

        self.model = ScriptedProvider(responses)
        use_provider(self.runtime, self.model)

        async def sink(event):
            self.events.append(event)

        return await self.runtime.chat(
            messages=[{"role": "user", "content": "Buy the ticket on shop.example.com"}],
            tools=tools or build_tools([], enabled_capabilities=frozenset(BOTH)),
            user_id=U1,
            event_sink=sink,
            task_id=task_id,
        )

    def of_type(self, kind):
        return [e["data"] for e in self.events if e["type"] == kind]


def call(call_id, name, **arguments):
    from services.agent.providers import LLMResponse, ToolCall

    return LLMResponse(content="", tool_calls=[ToolCall(id=call_id, name=name, arguments=arguments)])


@pytest.mark.asyncio
async def test_a_checkout_gets_one_card_built_from_the_page_with_its_picture():
    checkout = FakeCheckoutToolkit()
    ex = executor(*BOTH, checkout=checkout)
    turn = Turn(ex, _gate(*BOTH))
    response = await turn.run(call("t1", CHECKOUT, merchant="shop.example.com", amount=23.4))
    [pending] = response.pending_approvals
    assert isinstance(pending, PendingApproval) and pending.tool_name == CHECKOUT
    assert pending.arguments[CHECKOUT_CARD_KEY] == CARD
    assert pending.reason == "Pay $23.40 to shop.example.com (2 items) with Visa ····4242"
    assert pending.image == IMAGE
    [card] = turn.of_type("pending_approval")
    assert card["image"] == IMAGE and card["arguments"][CHECKOUT_CARD_KEY]["amount_usd"] == "23.40"
    assert turn.audit.events_for(CHECKOUT) == ["tool_pending_approval"]
    assert response.blocked_actions == [] and turn.of_type("blocked") == []
    # begin ran once, with the runtime's task id; nothing was paid.
    assert [c[0] for c in checkout.calls if c[0] in ("begin", "run")] == ["begin"]
    assert next(c for c in checkout.calls if c[0] == "begin")[3] == "conv-9"
    # The stored card carries the facts, never the picture.
    [stored] = await turn.store.list_pending(U1)
    assert IMAGE not in str(stored.arguments)
    # list_pending_approvals serves the picture again while the toolkit has it.
    [listed] = await turn.runtime.list_pending_approvals(U1)
    assert listed.image == IMAGE and listed.action_id == pending.action_id
    done = turn.runtime._done_event(response)
    assert done["data"]["pending_approvals"][0]["image"] == IMAGE


@pytest.mark.asyncio
async def test_the_rest_approvals_list_carries_the_picture(client, session_factory):
    """GET /agent/approvals is what the Gateway page and a reloaded chat
    read; without ``image`` there, the purchase card would show its
    screenshot only on the live stream."""
    from api.routes import agent as agent_routes
    from main import app
    from tests.conftest import auth_headers, make_user

    user, token = await make_user(session_factory, "buyer@example.com")
    checkout = FakeCheckoutToolkit()
    ex = executor(*BOTH, checkout=checkout)
    turn = Turn(ex, _gate(*BOTH))
    app.dependency_overrides[agent_routes.get_runtime] = lambda: turn.runtime
    try:
        from tests.conftest import use_provider

        turn.model = ScriptedProvider([call("t1", CHECKOUT, merchant="shop.example.com", amount=23.4)])
        use_provider(turn.runtime, turn.model)
        response = await turn.runtime.chat(
            messages=[{"role": "user", "content": "Buy the ticket on shop.example.com"}],
            tools=build_tools([], enabled_capabilities=frozenset(BOTH)),
            user_id=str(user.id),
            task_id="conv-9",
        )
        [pending] = response.pending_approvals
        listed = await client.get("/api/agent/approvals", headers=auth_headers(token))
        assert listed.status_code == 200, listed.text
        [row] = listed.json()
        assert row["action_id"] == pending.action_id and row["tool_name"] == CHECKOUT
        assert row["image"] == IMAGE and row["arguments"][CHECKOUT_CARD_KEY] == CARD
        # Once the toolkit no longer holds it (approved, expired, restarted),
        # the same row lists with no picture rather than a stale one.
        checkout._image = None
        [row] = (await client.get("/api/agent/approvals", headers=auth_headers(token))).json()
        assert row["image"] is None
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_a_refused_bind_is_filed_under_purchase_rule_with_no_card():
    over = {"ok": False, "refused": True, "rule": "over_cap", "error": "$99.00 is over your $25 per-purchase cap."}
    checkout = FakeCheckoutToolkit(begin=over)
    ex = executor(*BOTH, checkout=checkout)
    turn = Turn(ex, _gate(*BOTH))
    from services.agent.providers import LLMResponse

    response = await turn.run(
        call("t1", CHECKOUT, merchant="shop.example.com", amount=99),
        LLMResponse(content="That is over your cap."),
    )
    assert response.pending_approvals == [] and await turn.store.list_pending(U1) == []
    assert [(b.tool_name, b.policy, b.reason) for b in response.blocked_actions] == [
        (CHECKOUT, PURCHASE_RULE_POLICY, over["error"])
    ]
    [blocked] = turn.of_type("blocked")
    assert blocked["rule"] == "over_cap" and blocked["policy"] == PURCHASE_RULE_POLICY
    [entry] = [e for e in turn.audit.entries if e["event"] == "tool_blocked"]
    assert entry["policy"] == PURCHASE_RULE_POLICY and entry["rule"] == "over_cap"
    assert "tool_executing" not in turn.audit.events_for(CHECKOUT)
    # The model saw the refusal as the call's result and answered.
    assert response.tool_calls and response.tool_calls[0]["result"]["rule"] == "over_cap"
    assert response.content == "That is over your cap."
    assert all(c[0] != "run" for c in checkout.calls)


@pytest.mark.asyncio
async def test_a_refused_toolkit_precheck_is_filed_the_same_way():
    no_card = {"ok": False, "rule": "no_card", "error": "No payment card is stored. Add one in Settings → Payment card."}
    ex = executor(*BOTH, checkout=FakeCheckoutToolkit(precheck=no_card))
    turn = Turn(ex, _gate(*BOTH))
    response = await turn.run(call("t1", CHECKOUT, merchant="shop.example.com"))
    assert response.pending_approvals == []
    assert [(b.policy, b.reason) for b in response.blocked_actions] == [(PURCHASE_RULE_POLICY, no_card["error"])]
    assert turn.of_type("blocked")[0]["rule"] == "no_card"


@pytest.mark.asyncio
async def test_a_forged_card_key_never_reaches_the_toolkit():
    checkout = FakeCheckoutToolkit()
    ex = executor(*BOTH, checkout=checkout)
    turn = Turn(ex, _gate(*BOTH))
    response = await turn.run(
        call("t1", CHECKOUT, merchant="shop.example.com", _checkout={"amount_usd": "0.01"})
    )
    assert response.pending_approvals == []
    assert response.blocked_actions[0].policy == PURCHASE_RULE_POLICY
    assert turn.of_type("blocked")[0]["rule"] == "invalid_arguments"
    assert checkout.calls == []


@pytest.mark.asyncio
async def test_an_approved_checkout_runs_the_toolkit_with_the_card_it_showed():
    checkout = FakeCheckoutToolkit()
    ex = executor(*BOTH, checkout=checkout)
    turn = Turn(ex, _gate(*BOTH))
    response = await turn.run(call("t1", CHECKOUT, merchant="shop.example.com", amount=23.4))
    [pending] = response.pending_approvals
    outcome = await turn.runtime.approve_action(pending.action_id, U1)
    assert outcome["result"]["ok"] is True and outcome["result"]["amount"] == "23.40"
    assert outcome["result"]["user_image"] == CONFIRMATION
    run = next(c for c in checkout.calls if c[0] == "run")
    assert run[1][CHECKOUT_CARD_KEY] == CARD and run[2] == U1 and run[4] is True
    assert "tool_approved_and_executed" in turn.audit.events_for(CHECKOUT)


@pytest.mark.asyncio
async def test_a_checkout_with_purchases_off_is_blocked_before_any_bind():
    checkout = FakeCheckoutToolkit()
    ex = executor("browser_control", checkout=checkout)
    turn = Turn(ex, _gate("browser_control"))
    response = await turn.run(
        call("t1", CHECKOUT, merchant="shop.example.com"),
        tools=build_tools([], enabled_capabilities=frozenset(BOTH)),
    )
    assert response.pending_approvals == []
    assert [(b.policy, b.reason) for b in response.blocked_actions] == [
        (CAPABILITY_OFF_POLICY, "Buying things is off. Turn on 'Buy things for me' in Permissions.")
    ]
    assert checkout.calls == []


def test_the_backstop_honours_a_browser_control_refusal_of_checkout():
    assert _capability_refusal(
        CHECKOUT, {"ok": False, "capability": "browser_control", "state": "off", "error": "off"}
    ) == ("off", CAPABILITY_OFF_POLICY)
    assert _capability_refusal(
        CHECKOUT, {"ok": False, "capability": "purchases", "state": "off", "error": "Buying things is off."}
    ) == ("Buying things is off.", CAPABILITY_OFF_POLICY)
    assert _capability_refusal(CHECKOUT, {"ok": False, "capability": "screen", "state": "off"}) is None
    assert _capability_refusal("browser.read", {"ok": False, "capability": "purchases", "state": "off"}) is None


@pytest.mark.asyncio
async def test_a_sync_only_executor_still_parks_its_cards():
    """An executor without the async hook (a third-party one, or the
    Protocol's default) binds through the sync hook as before."""
    from services.agent.runtime import ToolExecutor

    class Sync(ToolExecutor):
        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            return {"ok": True}

        def approval_arguments(self, tool_name, arguments, user_id):
            return {**arguments, "tie": "screen"}

    turn = Turn(Sync(), _gate(*ACTING))
    response = await turn.run(
        call("t1", ACT, action="click", ref="e7"),
        tools=build_tools([], enabled_capabilities=frozenset(ACTING)),
    )
    [pending] = response.pending_approvals
    assert pending.arguments == {"action": "click", "ref": "e7", "tie": "screen"}
    assert pending.image is None


def test_a_checkout_card_names_no_risk_when_the_merchant_is_the_page_it_read():
    """The normal purchase: the model read the shop's page, then named that
    shop, so the taint tracker sees the host in an untrusted result. The
    toolkit checked the merchant against the page's own origin, so the card
    carries no warning. A merchant the page does not match, or a note copied
    from the page, gets one plain sentence; other tools keep their heads-up."""
    from services.agent.taint import TaintTracker

    taint = TaintTracker()
    taint.add_result({"url": "https://tickets.example.com/checkout", "title": "Checkout"})
    args = {"merchant": "tickets.example.com", "amount": 5}
    reason = taint.taint_reason(args)
    assert reason and "tickets.example.com" in reason
    note = AgentRuntime._card_risk_note

    facts = {"_checkout": {"checkout_id": "c1", "host": "tickets.example.com"}}
    assert note("browser.checkout", args, {**args, **facts}, reason, taint) is None
    # The registrable domain, or a scheme and path around it, still match.
    for merchant in ("example.com", "https://tickets.example.com/checkout", "www.tickets.example.com"):
        named = {**args, "merchant": merchant}
        assert note("browser.checkout", named, {**named, **facts}, reason, taint) is None
    # Not the page's host: a plain sentence, no jargon.
    elsewhere = {"_checkout": {"checkout_id": "c1", "host": "other.example.net"}}
    assert (
        note("browser.checkout", args, {**args, **elsewhere}, reason, taint)
        == "The site name came from a web page; check it matches where you meant to buy."
    )
    # A note copied word for word from the page.
    taint.add_result({"text": "limited time offer ends tonight at midnight sharp"})
    copied = {**args, "note": "limited time offer ends tonight at midnight sharp"}
    assert note("browser.checkout", copied, {**copied, **facts}, taint.taint_reason(copied), taint) == (
        "Part of this request came from a web page. Check the site and the amount on the card before approving."
    )
    # No card facts at all (the bind failed): still a plain sentence.
    assert "web page" in str(note("browser.checkout", args, args, reason, taint))
    # Nothing tainted: nothing to say. Other tools: the heads-up as before.
    assert note("browser.checkout", args, {**args, **facts}, None, taint) is None
    mail = {"to": "someone@tickets.example.com"}
    heads_up = note("google_workspace.send_email", mail, mail, taint.taint_reason(mail), taint)
    assert str(heads_up).startswith("Heads up: this request was shaped by external content")


def test_bind_refusal_policies():
    from services.agent.runtime import AgentRuntime

    refusal = AgentRuntime._bind_refusal(CHECKOUT, {"refused": True, "rule": "no_total", "error": "No total."})
    assert refusal.policy == PURCHASE_RULE_POLICY and refusal.rule == "no_total"
    assert AgentRuntime._bind_refusal(ACT, {"refused": True}).policy == BROWSER_RULE_POLICY
    other = AgentRuntime._bind_refusal("gmail.send_email", {"refused": True})
    assert other.policy == PRECHECK_ERROR_POLICY and other.reason == "gmail.send_email was refused."
    assert AgentRuntime._bind_refusal(CHECKOUT, {"merchant": "x", CHECKOUT_CARD_KEY: CARD}) is None
    assert AgentRuntime._bind_refusal(CHECKOUT, {"refused": "yes"}) is None


# ── 8. audit redaction and prompt ────────────────────────────────────────


def test_audit_keeps_only_the_length_of_what_browser_act_types():
    redacted = redact_tool_arguments(
        ACT, {"action": "fill", "ref": "e3", "text": "my private note", "fields": [{"ref": "e1", "text": "x"}]}
    )
    assert redacted == {"action": "fill", "ref": "e3", "text": "<15 characters>", "fields": "***REDACTED***"}
    # A checkout's arguments carry nothing to hide.
    args = {"merchant": "shop.example.com", "amount": 23.4, CHECKOUT_CARD_KEY: CARD}
    assert redact_tool_arguments(CHECKOUT, args) == args


def _system_text(tools: list[Tool]) -> str:
    """The system message the runtime sends for a turn offered *tools*
    (AgentRuntime.chat keys the purchases block on the checkout tool)."""
    purchases = any(t.name == CHECKOUT_TOOL for t in tools)
    [head] = AgentRuntime._with_system_prompt([], purchases=purchases)
    return str(head["content"])


def test_prompt_offers_checkout_and_a_reminder_only_when_checkout_is_offered():
    """The purchases block rides only with the checkout tool. With buying
    off the system message is the pre-purchases one to the byte: its hard
    limit still forbids purchases outright, and no request grows (the
    desktop outline budget in test_desktop_observation_policy holds)."""
    with_checkout = _system_text(build_tools([], enabled_capabilities=frozenset(BOTH)))
    without = _system_text(build_tools([], enabled_capabilities=frozenset({"browser_control"})))
    assert "browser.checkout" in with_checkout and "browser.checkout" not in without
    block = " ".join(with_checkout.split("<purchases>")[1].split("</purchases>")[0].split())
    for fragment in (
        "After a completed checkout, tell the person what was bought and the amount",
        "offer a reminder (reminders.create) for the event or delivery date",
        "filled from the owner's vault, never typed by you",
        "the only exception to the hard limit above",
    ):
        assert fragment in block, fragment
    # The block sits inside the one system message, before the date, so
    # the policy it qualifies is the same message it is part of.
    assert with_checkout.index("<hard_limits>") < with_checkout.index("<purchases>") < with_checkout.index("<today>")
    # Buying off: exactly the policy plus the date, nothing about purchases
    # beyond the standing hard limit, and no "purchases" section at all.
    assert without.startswith(SECURITY_SYSTEM_PROMPT + "\n\n<today>")
    assert "<purchases>" not in without
    limits = " ".join(SECURITY_SYSTEM_PROMPT.split("<hard_limits>")[1].split("</hard_limits>")[0].split())
    assert "Money never moves: no trades, transfers, purchases, or withdrawals, ever." in limits
    # The catalog says nothing about checkout either when it is not offered.
    assert not any("checkout" in t.description.lower() for t in build_tools([], enabled_capabilities=frozenset({"browser_control"})))


# ── 9. main.wire_services ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wire_services_hands_the_executor_the_browser_toolkits_and_telegram_the_picture(
    session_factory, monkeypatch
):
    """wire_services builds the three browser toolkits on one session
    manager and one page memory, hands act and checkout to the executor
    (with the vault it hung on app.state), and wires the executor's
    approval_image into the Telegram poller."""
    import main as main_module
    from core.config import settings
    from main import app, wire_services
    from services.tools.browser.act import BrowserActToolkit
    from services.tools.browser.checkout.toolkit import BrowserCheckoutToolkit
    from tests.test_telegram_manager import FakeService

    class Sessions:
        def __init__(self, **kwargs: Any) -> None:
            pass

        async def close_all(self) -> None:
            pass

    monkeypatch.setattr(
        main_module,
        "current_platform",
        lambda: SimpleNamespace(name="mac", browser_channel=lambda: "chrome", data_dir=lambda: None),
    )
    monkeypatch.setattr(main_module, "BrowserSessionManager", Sessions)
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    FakeService.instances.clear()
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        ex = app.state.tool_executor
        assert ex is app.state.agent_runtime._executor
        assert isinstance(ex._act, BrowserActToolkit)
        assert isinstance(ex._checkout, BrowserCheckoutToolkit)
        assert ex._act._memory is ex._checkout._memory
        assert ex._checkout._vault is app.state.vault
        assert ex._checkout._cancel_flag is cancel.is_cancelled
        # The poller reads a card's picture through the executor.
        service = SimpleNamespace()
        main_module._wire_telegram(app, service, session_factory)
        assert callable(service.approval_image)
        action = SimpleNamespace(tool_name=CHECKOUT, arguments={CHECKOUT_CARD_KEY: CARD}, user_id=U1)
        assert service.approval_image(action) is None  # nothing pending: no picture
    finally:
        await app.state.telegram_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)
