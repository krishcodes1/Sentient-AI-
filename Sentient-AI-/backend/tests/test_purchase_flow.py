"""Purchases end to end through the agent runtime (purchases spec §1, §6,
§11): a scripted model on the real ConnectorToolExecutor, the real
browser toolkits (read, act, checkout) sharing one headless Chromium
session against the fake site over TLS, the real vault on a fixed test
key, the real purchase ledger and the real audit logger on the test
database.

Why it exists: the package tests prove each seam on fakes; this file is
the one place the whole chain runs as it does in the app, so the promises
the owner reads on the card are checked where they are made: one card per
checkout with the amount, the merchant, the notice and a screenshot;
Approve fills the card from the vault and lands on the confirmation while
the number never reaches the model, an event, an audit row or the
transcript, and the picture the decision path hands the person is the
toolkit's own masked one; a submit the page stops leaves no card on
screen for the model's next look, nor in that picture; an order form that turns on the card at submit time is
stopped by the network guard; Deny fills nothing; a cap, an http page, a
wrong or look-alike merchant and a page that changed after the card are
refused; and the purchases switch off refuses before any of that. Skipped
where Playwright's Chromium is not installed. Never a real site, never a
real card, never a headed window.
"""

from __future__ import annotations

import dataclasses
import json
import re
import uuid
from decimal import Decimal
from typing import Any, Optional

import pytest
import pytest_asyncio
from sqlalchemy import select

from api.routes.agent import _channel_photos, _render_decision_message
from core.config import settings
from models.audit import AuditLog, AuditStatus
from services.agent import cancel
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import (
    PURCHASE_RULE_POLICY,
    AgentRuntime,
    PendingApproval,
    redact_binary_for_model,
)
from services.agent.tool_registry import (
    CAPABILITY_OFF_POLICY,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.audit import RuntimeAuditLogger
from services.installation import InstallationService
from services.tools.browser import handoff
from services.tools.browser.act import BrowserActToolkit
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.checkout import NOTICE
from services.tools.browser.checkout.ledger import PurchaseLedger
from services.tools.browser.checkout.toolkit import CARD_KEY, BrowserCheckoutToolkit
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.session import BrowserSessionManager
from services.tools.system import browser_installed
from services.vault.service import VaultService
from tests.conftest import make_user, tls_launcher, use_provider
from tests.fakesite.pages import PAGES
from tests.test_browser_act import SpyGuard
from tests.test_browser_read import TestPlatform
from tests.test_purchases_wiring import _gate

CHECKOUT = "browser.checkout"
BOTH = ("browser_control", "purchases")
HOST = "127.0.0.1"
NUMBER = "4242424242424242"
CVC = "987"
NAME = "Krish Q"
TASK = "msg-1"
CONV = "conv-1"
ASK = {"role": "user", "content": "Buy the concert ticket on the fake shop, it is about $23."}
# The columns an audit row's content lives in; ids and hashes are random
# hex, where a short digit run (a CVC) can occur by chance.
CONTENT_COLUMNS = (
    "connector_name", "action", "endpoint", "scope_used", "status", "reasoning_chain",
    "detection_method", "request_data", "response_summary",
)
# Values a turn carries that are known not to be card data and where any
# three digits occur by chance: UUIDs (an action id), hashes with at least
# one letter (an integrity hash, never a digit run that could be a card
# number), clock times, ports and decimals. Nothing else is stripped.
_INCIDENTAL_VALUES = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
    r"|\b(?=[0-9a-f]{16,}\b)(?=[0-9]*[a-f])[0-9a-f]+\b"
    r"|\d{2}:\d{2}:\d{2}(?:\.\d+)?|:\d{2,5}\b|\d+\.\d+"
)
SPACED = " ".join(NUMBER[i : i + 4] for i in range(0, 16, 4))
_NUMBER_ANY_GROUPING = re.compile(r"(?<!\d)" + r"[\s\-.]*".join(NUMBER) + r"(?!\d)")
_CVC_ALONE = re.compile(r"(?<![0-9a-f])" + CVC + r"(?![0-9a-f])")


def card_secret_in(text: str) -> Optional[str]:
    """The first card value found in *text*, or None: the number in any
    grouping (checked on the raw text, so nothing stripped can hide it),
    then the CVC as a digit run of its own once the incidental values are
    set aside."""
    if _NUMBER_ANY_GROUPING.search(text):
        return NUMBER
    if _CVC_ALONE.search(_INCIDENTAL_VALUES.sub("", text)):
        return CVC
    return None


class FixedKey:
    """A vault key that never leaves the test: 32 fixed bytes."""

    def get(self) -> bytes:
        return bytes(range(32))


class ScriptedProvider:
    """Answers with scripted responses and records every request, so a test
    can check what the model was shown."""

    def __init__(self, responses) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def complete(self, messages, tools=None):
        self.calls.append({"messages": list(messages), "tools": list(tools or [])})
        if self._responses:
            return self._responses.pop(0)
        return LLMResponse(content="done", usage={"input_tokens": 10, "output_tokens": 2})

    async def stream(self, messages, tools=None):
        yield "done"


_call_ids = iter(range(1, 1000))


def open_call(url: str) -> LLMResponse:
    return LLMResponse(
        content="",
        tool_calls=[ToolCall(id=f"c{next(_call_ids)}", name="browser.read", arguments={"action": "open", "url": url})],
    )


def checkout_call(merchant: str = HOST, **arguments: Any) -> LLMResponse:
    return LLMResponse(
        content="",
        tool_calls=[
            ToolCall(id=f"c{next(_call_ids)}", name=CHECKOUT, arguments={"merchant": merchant, **arguments})
        ],
    )


def _no_images(value: Any) -> Any:
    """*value* with every data URL replaced, so a JPEG's base64 text never
    stands in for (or hides) what a text check is about."""
    if isinstance(value, str):
        return "<image>" if value.startswith("data:image/") else value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _no_images(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {k: _no_images(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_no_images(v) for v in value]
    return value


def _text(value: Any) -> str:
    return json.dumps(_no_images(value), default=str)


def row_text(row: AuditLog) -> str:
    return _text({name: getattr(row, name) for name in CONTENT_COLUMNS})


def region_mean(data_url: str, box: dict[str, float]) -> float:
    """Mean luminance of the inner part of *box* (CSS px, which the
    headless viewport paints at scale 1) in the JPEG *data_url*: a masked
    field is painted #000000 and reads near 0; a white box with text well
    above 100."""
    import base64
    import io

    from PIL import Image

    image = Image.open(io.BytesIO(base64.b64decode(data_url.partition(",")[2]))).convert("L")
    x0, y0 = int(box["x"]) + 3, int(box["y"]) + 3
    x1, y1 = int(box["x"] + box["width"]) - 3, int(box["y"] + box["height"]) - 3
    pixels = list(image.crop((x0, y0, x1, y1)).getdata())
    return sum(pixels) / max(1, len(pixels))


def delivered_photo(result: dict[str, Any]) -> dict[str, str]:
    """The one photo the decision path hands the person for the approved
    checkout (api.routes.agent._apply_decision: Telegram as a photo, the
    web chat under the decision row)."""
    [photo] = _channel_photos([{"name": CHECKOUT, "result": result}], False)
    return photo


class Flow:
    """Everything one purchase runs through, on one user and one browser."""

    def __init__(self, *, user_id, session_factory, tls, http, sessions, memory, read, act, checkout, vault, ledger):
        self.user_id = user_id
        self.session_factory = session_factory
        self.tls = tls
        self.http = http
        self.sessions = sessions
        self.memory = memory
        self.read = read
        self.act = act
        self.checkout = checkout
        self.vault = vault
        self.ledger = ledger
        self.providers: list[ScriptedProvider] = []
        self.responses: list[Any] = []
        self.events: list[dict[str, Any]] = []
        self.outcomes: list[dict[str, Any]] = []
        self.store = InMemoryApprovalStore()
        self.executor: Optional[ConnectorToolExecutor] = None

    def runtime(self, *keys: str) -> AgentRuntime:
        """The runtime as main.wire_services builds it, with the owner's
        switches *keys* on (the report is a Windows install so the vault
        and a browser are available)."""
        gate = _gate(*keys)
        self.executor = ConnectorToolExecutor(
            session_factory=self.session_factory,
            capability_gate=gate,
            browser_toolkit=self.read,
            act_toolkit=self.act,
            checkout_toolkit=self.checkout,
        )
        return AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(capability_gate=gate),
            tool_executor=self.executor,
            audit_service=RuntimeAuditLogger(session_factory=self.session_factory),
            approval_store=self.store,
        )

    async def chat(self, runtime: AgentRuntime, *responses: LLMResponse, messages=None):
        provider = ScriptedProvider(responses)
        use_provider(runtime, provider)
        self.providers.append(provider)

        async def sink(event: dict[str, Any]) -> None:
            self.events.append(event)

        response = await runtime.chat(
            messages=messages or [ASK],
            tools=build_tools([], enabled_capabilities=frozenset(BOTH)),
            user_id=self.user_id,
            event_sink=sink,
            task_id=TASK,
            conversation_id=CONV,
        )
        self.responses.append(response)
        return response

    async def approve(self, runtime: AgentRuntime, pending: PendingApproval) -> dict[str, Any]:
        outcome = await runtime.approve_action(pending.action_id, self.user_id)
        self.outcomes.append(outcome)
        return outcome

    def of_type(self, kind: str) -> list[dict[str, Any]]:
        return [e["data"] for e in self.events if e["type"] == kind]

    def session(self):
        return self.sessions.sessions[self.user_id]

    async def page(self):
        return await self.session().page()

    async def card_last_used(self) -> Optional[str]:
        view = await self.vault.get_card_view(self.user_id)
        assert view is not None
        return view.last_used_at

    async def audit_rows(self) -> list[AuditLog]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(AuditLog).where(AuditLog.user_id == uuid.UUID(self.user_id)).order_by(AuditLog.seq)
            )
            return list(result.scalars().all())

    async def purchase_events(self) -> list[tuple[str, Optional[str]]]:
        return [
            (r.action, (r.reasoning_chain or {}).get("reason"))
            for r in await self.audit_rows()
            if r.connector_name == "purchases"
        ]

    async def checkout_events(self) -> list[tuple[str, Optional[str], Optional[str]]]:
        """(runtime event, policy, rule) of every browser.checkout audit row."""
        return [
            (r.reasoning_chain.get("event"), r.reasoning_chain.get("policy"), r.reasoning_chain.get("rule"))
            for r in await self.audit_rows()
            if r.connector_name == "browser" and r.action == "checkout"
        ]

    async def assert_card_secret_nowhere(self) -> None:
        """The number is in none of what the model saw, the turn emitted,
        the audit log kept or the approval returned; the CVC neither, once
        random hex, times, ports and decimals (where any three digits can
        occur by chance) are set aside."""
        texts = [_text(p.calls) for p in self.providers]
        texts += [_text(r) for r in self.responses]
        texts += [_text(self.events), _text(self.outcomes)]
        texts += [row_text(r) for r in await self.audit_rows()]
        for text in texts:
            assert card_secret_in(text) is None


@pytest_asyncio.fixture
async def flow(session_factory, fakesite_tls, fakesite, tmp_path):
    if not browser_installed():
        pytest.skip("Playwright's Chromium is not installed (python -m playwright install chromium)")
    user, _ = await make_user(session_factory)
    user_id = str(user.id)
    cancel.clear(user_id)
    vault = VaultService(session_factory, FixedKey())
    await vault.put_card(
        user_id, label="Visa", number=NUMBER, exp_month=12, exp_year=2028, cvc=CVC, name=NAME
    )
    sessions = BrowserSessionManager(
        headless=True, platform=TestPlatform(tmp_path), max_sessions=1, max_tabs=2, launcher=tls_launcher
    )
    memory, guard = PageMemory(), SpyGuard()
    read = BrowserReadToolkit(sessions, guard=guard, handoff=handoff, page_memory=memory)
    act = BrowserActToolkit(
        sessions, guard=guard, handoff=handoff, memory=memory, cancel_flag=cancel.is_cancelled
    )
    ledger = PurchaseLedger(session_factory)
    checkout = BrowserCheckoutToolkit(
        sessions,
        guard=guard,
        handoff=handoff,
        memory=memory,
        vault=vault,
        ledger=ledger,
        settings=InstallationService(session_factory),
        cancel_flag=cancel.is_cancelled,
    )
    f = Flow(
        user_id=user_id, session_factory=session_factory, tls=fakesite_tls, http=fakesite, sessions=sessions,
        memory=memory, read=read, act=act, checkout=checkout, vault=vault, ledger=ledger,
    )
    try:
        yield f
    finally:
        await sessions.close_all()
        cancel.clear(user_id)


def test_the_secret_check_strips_only_known_incidental_values():
    """A UUID segment or a hash can hold the CVC by chance and must not
    fail a test; a card number, however grouped, must never pass one."""
    assert card_secret_in('{"action_id": "1f0c2b7e-a987-4c3d-8e21-5f00b1c2d3e4"}') is None
    assert card_secret_in('"integrity_hash": "987f00d1c2b3a4e5d6c7b8a9f0e1d2c3"') is None
    assert card_secret_in("at 12:59:87 on port :987 for 9.87") is None
    assert card_secret_in("code 987 sent") == CVC
    assert card_secret_in(f"a{CVC}b") is None and card_secret_in(f"x {CVC}") == CVC
    for shown in (NUMBER, SPACED, "-".join(NUMBER[i : i + 4] for i in range(0, 16, 4)), "4242.4242.4242.4242"):
        assert card_secret_in(f"paid with {shown}.") == NUMBER, shown
    assert card_secret_in("0" + NUMBER) is None  # a longer number is a different number
    assert card_secret_in("order 8841, Visa ····4242") is None


def _blocked(response, rule: str):
    """The one blocked action of a turn that made no card, with its event."""
    assert response.pending_approvals == []
    [blocked] = response.blocked_actions
    assert blocked.tool_name == CHECKOUT and blocked.policy == PURCHASE_RULE_POLICY
    return blocked


@pytest.mark.asyncio
async def test_a_checkout_is_one_card_then_a_purchase_from_the_vault(flow):
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(
        runtime, open_call(flow.tls.url("/checkout")), checkout_call(amount=23.4, note="two tickets")
    )
    # One card, built from the page: the amount, the merchant, the items,
    # the card's masked label, the notice and a picture.
    assert response.blocked_actions == []
    [pending] = response.pending_approvals
    assert pending.tool_name == CHECKOUT
    card = pending.arguments[CARD_KEY]
    assert card["amount_usd"] == "23.40" and card["currency"] == "USD"
    assert card["host"] == HOST and card["origin"] == flow.tls.base
    assert card["items"] == ["Concert ticket — $19.00", "Service fee — $4.40"]
    assert card["card_label"] == "Visa ····4242" and card["notice"] == NOTICE
    assert pending.arguments["merchant"] == HOST and pending.arguments["amount"] == "23.40"
    assert pending.reason == "Pay $23.40 to 127.0.0.1 (2 items) with Visa ····4242"
    assert pending.image is not None and pending.image.startswith("data:image/jpeg;base64,")
    [event] = flow.of_type("pending_approval")
    assert event["image"] == pending.image and event["arguments"][CARD_KEY] == card
    assert len(await flow.store.list_pending(flow.user_id)) == 1
    [listed] = await runtime.list_pending_approvals(flow.user_id)
    assert listed.action_id == pending.action_id and listed.image == pending.image
    # Nothing paid, nothing typed, the vault untouched.
    assert await flow.card_last_used() is None
    assert await flow.ledger.spent_last_24h(flow.user_id) == Decimal("0")
    page = await flow.page()
    assert await page.locator("input[name=cc-number]").input_value() == ""

    outcome = await flow.approve(runtime, pending)
    result = outcome["result"]
    assert result["ok"] is True, result
    assert result["merchant"] == HOST and result["amount"] == "23.40" and result["currency"] == "USD"
    assert "Order number 8841" in result["confirmation_text_summary"]
    assert result["user_image"].startswith("data:image/jpeg;base64,")
    # The person gets that confirmation picture, captioned from the facts.
    assert delivered_photo(result) == {
        "data_url": result["user_image"], "caption": f"Order confirmation on {HOST}: $23.40"
    }
    # The fake site only confirms a Luhn-valid card: the vault's number
    # reached the merchant's form and nowhere else.
    assert (await flow.page()).url.endswith("/order-confirmed")
    assert NUMBER in flow.session().typed_secrets
    # The name on the card is the delivery name too: never a secret.
    assert NAME not in flow.session().typed_secrets
    assert await flow.card_last_used() is not None
    assert await flow.ledger.spent_last_24h(flow.user_id) == Decimal("23.40")
    # The card was used up.
    assert flow.executor.approval_image(CHECKOUT, pending.arguments, flow.user_id) is None
    assert "error" in await runtime.approve_action(pending.action_id, flow.user_id)

    # The turn the route resumes sees the decision the way it is recorded
    # in the transcript, and the model answers from it.
    content, _payload = _render_decision_message(True, CHECKOUT, redact_binary_for_model(result))
    resumed = await flow.chat(
        runtime,
        LLMResponse(content="Bought it: $23.40, order number 8841."),
        messages=[ASK, {"role": "assistant", "content": content}],
    )
    assert resumed.content.startswith("Bought it")
    assert "Order number 8841" in _text(flow.providers[-1].calls)

    assert await flow.purchase_events() == [
        ("purchase_requested", None), ("purchase_approved", None), ("purchase_completed", None),
    ]
    rows = await flow.audit_rows()
    assert [r.status for r in rows if r.connector_name == "purchases"] == [
        AuditStatus.pending, AuditStatus.approved, AuditStatus.approved,
    ]
    assert [e[0] for e in await flow.checkout_events()] == [
        "tool_pending_approval", "tool_approved", "tool_approved_and_executed",
    ]
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_deny_fills_nothing(flow):
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(runtime, open_call(flow.tls.url("/checkout")), checkout_call())
    [pending] = response.pending_approvals
    denied = await runtime.deny_action(pending.action_id, flow.user_id)
    assert denied["denied"] is True and denied["tool"] == CHECKOUT
    page = await flow.page()
    assert page.url.endswith("/checkout")
    for field in ("cc-number", "cc-csc", "cc-exp", "cc-name"):
        assert await page.locator(f"input[name={field}]").input_value() == ""
    assert flow.session().typed_secrets == []
    assert await flow.card_last_used() is None
    assert await flow.purchase_events() == [("purchase_requested", None)]
    assert [e[0] for e in await flow.checkout_events()] == ["tool_pending_approval", "tool_denied"]
    # The card is settled: it cannot be approved afterwards.
    assert "error" in await runtime.approve_action(pending.action_id, flow.user_id)
    assert await flow.store.list_pending(flow.user_id) == []
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_over_the_cap_is_refused_before_any_card(flow):
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(
        runtime,
        open_call(flow.tls.url("/checkout-big")),
        checkout_call(amount=99),
        LLMResponse(content="That is over your cap."),
    )
    blocked = _blocked(response, "over_cap")
    assert "$99.00" in blocked.reason and "$25.00" in blocked.reason
    assert response.content == "That is over your cap."
    [event] = flow.of_type("blocked")
    assert event["rule"] == "over_cap" and event["policy"] == PURCHASE_RULE_POLICY
    assert flow.of_type("pending_approval") == [] and await flow.store.list_pending(flow.user_id) == []
    # The model was told, as the call's result.
    assert response.tool_calls[-1]["result"]["rule"] == "over_cap"
    assert await flow.purchase_events() == [("purchase_refused", "over_cap")]
    assert await flow.checkout_events() == [("tool_blocked", PURCHASE_RULE_POLICY, "over_cap")]
    page = await flow.page()
    assert page.url.endswith("/checkout-big")
    assert await page.locator("input[name=cc-number]").input_value() == ""
    assert await flow.card_last_used() is None
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_a_plain_http_page_is_refused(flow):
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(
        runtime,
        open_call(flow.http.url("/checkout")),
        checkout_call(),
        LLMResponse(content="Not over a secure connection."),
    )
    blocked = _blocked(response, "insecure_page")
    assert "http://127.0.0.1" in blocked.reason
    assert flow.of_type("blocked")[0]["rule"] == "insecure_page"
    assert await flow.purchase_events() == [("purchase_refused", "insecure_page")]
    assert await flow.checkout_events() == [("tool_blocked", PURCHASE_RULE_POLICY, "insecure_page")]
    assert await flow.card_last_used() is None
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_a_page_that_changed_after_the_card_is_refused_on_approve(flow):
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(runtime, open_call(flow.tls.url("/checkout")), checkout_call())
    [pending] = response.pending_approvals
    page = await flow.page()
    await page.goto(flow.tls.url("/grades"), wait_until="domcontentloaded")
    outcome = await flow.approve(runtime, pending)
    result = outcome["result"]
    assert result == {"ok": False, "refused": True, "rule": "screen_changed", "error": result["error"]}
    assert "changed since you approved" in result["error"]
    assert flow.session().typed_secrets == [] and await flow.card_last_used() is None
    assert await flow.ledger.spent_last_24h(flow.user_id) == Decimal("0")
    assert await flow.purchase_events() == [("purchase_requested", None)]
    events = await flow.checkout_events()
    assert [e[0] for e in events] == ["tool_pending_approval", "tool_approved", "tool_approved_and_executed"]
    rows = [r for r in await flow.audit_rows() if r.connector_name == "browser" and r.action == "checkout"]
    assert "screen_changed" in (rows[-1].response_summary or "")
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_purchases_off_refuses_before_the_page_is_read(flow):
    runtime = flow.runtime("browser_control")
    response = await flow.chat(
        runtime,
        open_call(flow.tls.url("/checkout")),
        checkout_call(),
        LLMResponse(content="Buying is off."),
    )
    assert response.pending_approvals == []
    assert [(b.tool_name, b.policy, b.reason) for b in response.blocked_actions] == [
        (CHECKOUT, CAPABILITY_OFF_POLICY, "Buying things is off. Turn on 'Buy things for me' in Permissions.")
    ]
    assert flow.of_type("blocked")[0]["policy"] == CAPABILITY_OFF_POLICY
    # The checkout toolkit never ran: no purchase row, no picture, no card.
    assert await flow.purchase_events() == []
    assert await flow.checkout_events() == [("tool_blocked", CAPABILITY_OFF_POLICY, None)]
    assert flow.executor.approval_image(CHECKOUT, {}, flow.user_id) is None
    assert await flow.card_last_used() is None
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_the_wrong_merchant_and_a_look_alike_host_are_refused(flow):
    runtime = flow.runtime(*BOTH)
    # The site the person named is not the one on screen.
    response = await flow.chat(
        runtime,
        open_call(flow.tls.url("/checkout")),
        checkout_call(merchant="ticketmaster.com"),
        LLMResponse(content="Wrong site."),
    )
    blocked = _blocked(response, "merchant_mismatch")
    assert "not ticketmaster.com as asked" in blocked.reason
    assert flow.of_type("blocked")[0]["rule"] == "merchant_mismatch"

    # A look-alike of a well-known merchant, served into the session by
    # route interception (registered after the egress guard's route, so it
    # answers first and nothing leaves the machine).
    body = PAGES["/checkout"][2]

    async def serve(route, request):
        await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body)

    await flow.session().context.route("https://ticketmaster-tickets.co/**", serve)
    response = await flow.chat(
        runtime,
        open_call("https://ticketmaster-tickets.co/checkout"),
        checkout_call(merchant="ticketmaster-tickets.co"),
        LLMResponse(content="That is not ticketmaster."),
    )
    blocked = _blocked(response, "merchant_mismatch")
    assert "ticketmaster-tickets.co looks like ticketmaster.com" in blocked.reason
    assert [e["rule"] for e in flow.of_type("blocked")] == ["merchant_mismatch", "merchant_mismatch"]
    assert await flow.purchase_events() == [
        ("purchase_refused", "merchant_mismatch"), ("purchase_refused", "merchant_mismatch"),
    ]
    assert await flow.store.list_pending(flow.user_id) == []
    assert await flow.card_last_used() is None
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_a_submit_the_page_stops_leaves_no_card_for_the_models_next_look(flow):
    """The fake shop's /checkout-hint names its card fields by label,
    groups the number as typed and stops the submit for a missing ZIP.
    After Approve the card was filled, the page stayed, and the model
    does what the error says: it looks again. It sees no card value; the
    fields are empty; the picture the person got masks them."""
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(
        runtime, open_call(flow.tls.url("/checkout-hint")), checkout_call(amount=23.4)
    )
    assert response.blocked_actions == [], [b.reason for b in response.blocked_actions]
    [pending] = response.pending_approvals
    outcome = await flow.approve(runtime, pending)
    result = outcome["result"]
    assert result["ok"] is False and result["filled"] is True and "no confirmation" in result["error"]
    assert result["user_image"].startswith("data:image/jpeg;base64,")
    page = await flow.page()
    assert page.url.endswith("/checkout-hint")
    for field in ("pan", "expdate", "csc"):
        assert await page.locator(f"input[name={field}]").input_value() == "", field
    # The picture the person gets after Approve is this one, taken after
    # the fields were cleared and with them blacked out.
    assert delivered_photo(result) == {
        "data_url": result["user_image"], "caption": "The page after the order was sent"
    }
    for field in ("pan", "csc"):
        box = await page.locator(f"input[name={field}]").bounding_box()
        assert box is not None and region_mean(result["user_image"], box) < 40, field
    look = LLMResponse(
        content="", tool_calls=[ToolCall(id="look1", name="browser.read", arguments={"action": "snapshot"})]
    )
    await flow.chat(runtime, look, LLMResponse(content="The page asks for a ZIP code."))
    seen = _text(flow.providers[-1].calls)
    assert "Please enter your ZIP code." in seen and "Card no." in seen
    assert card_secret_in(seen) is None and SPACED not in seen and "12/28" not in seen
    assert await flow.purchase_events() == [
        ("purchase_requested", None), ("purchase_approved", None), ("purchase_refused", "no_confirmation"),
    ]
    # The card went out as far as Crawler can tell: it counts as spent.
    assert await flow.ledger.spent_last_24h(flow.user_id) == Decimal("23.40")
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_an_order_form_that_turns_on_the_card_at_submit_is_stopped_by_the_guard(flow):
    """/checkout-hijack posts to /pay until its submit handler points the
    form at another origin. The facts read the honest target, the card
    binds to it, and the guard's write window admits a POST there only:
    the card never leaves, and the person is told why."""
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(runtime, open_call(flow.tls.url("/checkout-hijack")), checkout_call())
    [pending] = response.pending_approvals
    assert pending.arguments[CARD_KEY]["submit_to"] == flow.tls.url("/pay")
    outcome = await flow.approve(runtime, pending)
    result = outcome["result"]
    assert result["ok"] is False and result["filled"] is True, result
    assert "could not be sent" in result["error"] and "collector.example.test" in result["error"]
    assert "not by POST to " + flow.tls.base in result["error"]
    seen = flow.read._guard.seen  # the spy guard: (method, last path segment, write window open)
    assert ("POST", "steal", True) in seen and not any(m == "POST" and p == "pay" for m, p, _a in seen)
    assert (await flow.purchase_events())[-1] == ("purchase_refused", "submit_blocked")
    # A submit the guard stopped counts toward the day (spec §6): the
    # guard cannot always tell whether the merchant read the card first.
    assert await flow.ledger.spent_last_24h(flow.user_id) == Decimal("23.40")
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_an_order_form_aimed_at_a_frame_cannot_send_the_card_elsewhere(flow):
    """/checkout-hijack's twin: the submit handler points the form at
    another origin AND at a hidden iframe, so the POST carrying the card
    is a frame's navigation. The bound window judges every frame: the
    POST is aborted, the card never leaves, the person is told."""
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(runtime, open_call(flow.tls.url("/checkout-hijack-frame")), checkout_call())
    [pending] = response.pending_approvals
    assert pending.arguments[CARD_KEY]["submit_to"] == flow.tls.url("/pay")
    page = await flow.page()
    finished: list[str] = []

    def on_finished(request):
        if "/steal" in request.url:
            finished.append(request.url)

    page.on("requestfinished", on_finished)
    outcome = await flow.approve(runtime, pending)
    result = outcome["result"]
    assert result["ok"] is False and result["filled"] is True, result
    assert "could not be sent" in result["error"] and "collector.example.test" in result["error"]
    assert "from a frame" in result["error"]
    seen = flow.read._guard.seen
    assert ("POST", "steal", True) in seen and not any(m == "POST" and p == "pay" for m, p, _a in seen)
    assert finished == []
    assert await page.locator("input[name=cc-number]").input_value() == ""
    assert (await flow.purchase_events())[-1] == ("purchase_refused", "submit_blocked")
    assert await flow.ledger.spent_last_24h(flow.user_id) == Decimal("23.40")
    await flow.assert_card_secret_nowhere()


@pytest.mark.asyncio
async def test_a_redirect_of_the_order_post_cannot_re_send_the_card_elsewhere(flow):
    """The merchant takes the card at /pay-redirect and answers 307 to
    another origin. A browser would send the same POST there, card
    included; the guard fetches the order POST itself, reads the answer
    and stops that. The card reached the merchant once, so the day's
    total counts it and the person is told to check the site."""
    runtime = flow.runtime(*BOTH)
    response = await flow.chat(runtime, open_call(flow.tls.url("/checkout-redirect")), checkout_call())
    [pending] = response.pending_approvals
    assert pending.arguments[CARD_KEY]["submit_to"] == flow.tls.url("/pay-redirect")
    page = await flow.page()
    posts: list[tuple[str, bool]] = []  # (last path segment, carried the card) of every POST the page issued

    def on_request(request):
        if request.method == "POST":
            posts.append((request.url.split("?")[0].rsplit("/", 1)[-1], NUMBER in (request.post_data or "")))

    page.on("request", on_request)
    outcome = await flow.approve(runtime, pending)
    result = outcome["result"]
    assert result["ok"] is False and result["filled"] is True, result
    assert result["error"].startswith("The order was sent, but the site's answer led to https://collector.example.test/confirm")
    assert "307" in result["error"] and "check the site" in result["error"]
    assert posts == [("pay-redirect", True)], posts  # once, and never again to the other origin
    state = guard_state(flow)
    assert state.blocked[-1]["url"] == "https://collector.example.test/confirm"
    assert state.blocked[-1]["via"] == flow.tls.url("/pay-redirect")
    assert (await flow.purchase_events())[-1] == ("purchase_refused", "submit_blocked")
    assert await flow.ledger.spent_last_24h(flow.user_id) == Decimal("23.40")
    await flow.assert_card_secret_nowhere()


def guard_state(flow):
    from services.tools.browser import guard as guard_module

    state = guard_module.egress_state(flow.session().context)
    assert state is not None
    return state
