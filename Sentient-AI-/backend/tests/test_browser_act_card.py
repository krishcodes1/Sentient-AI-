"""Tests for "no money moves without the owner seeing the page on an approval
card first": the "Fill in forms and click on sites" switch (browser_act) that
browser.act now needs, the picture every browser.act card carries (the page
with the target outlined in red, secret fields masked, kept in memory and
served to the web card and the Telegram photo), the money warning a card adds
from the page's own facts, and browser.read's click, which has no card and so
may only follow a plain link or click a control outside any form on a page
with nothing to pay.

Why it exists: Four review rounds showed that word lists and page patterns
cannot be proven to catch every way a click on an arbitrary shop page places
an order. What can be proven is that every act waits for a card that shows
the page, and that a read never makes a click that could order. The fake site
is served over TLS to headless Chromium; no real website, no real card.
"""

from __future__ import annotations

import base64
import io
from typing import Any, Optional

import pytest
from PIL import Image

from services import capabilities as capability_registry
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.capabilities.base import ReportContext
from services.capabilities.prompt import render_permissions_block
from services.tools.browser import _shared
from core.config import settings
from services.tools.browser.act import CARD_KEY, MAY_ORDER_NOTE, NO_PICTURE_NOTE, PICTURE_GONE_NOTE, _money_warning
from services.tools.browser.checkout import markers
from services.tools.browser.checkout.markers import READ_CLICK_MESSAGE
from tests.fakesite.pages import SAVED_CARD_LEAD
from tests import test_browser_act as _act_tests
from tests.test_browser_act import (
    USER,
    fake_kit,
    live_page,
    posted,
    read,
    ref_of,
    remember,
    sent,
    settled,
)

# test_browser_act's fake-site fixtures, shared rather than copied: one
# headless session on the TLS fake site, and a page served for one test.
kits = _act_tests.kits
page_at = _act_tests.page_at

ACT = "browser.act"
ACT_LABEL = "Fill in forms and click on sites"
NEEDS_BROWSER = "Needs 'Control a browser' on in Permissions."
WARNING = (
    "This page shows $499.00 and a saved payment method. This step may place an order. "
    "Crawler normally pays only through its checkout step."
)


def ctx(**over: Any) -> ReportContext:
    """A native Mac with Playwright and Chrome: every browser switch is
    available, so what decides is the owner's switches."""
    values: dict[str, Any] = {
        "in_container": False,
        "platform": "darwin",
        "telegram_configured": False,
        "browser_installed": True,
        "playwright_installed": True,
        "browser_channel": "chrome",
        "host_platform": "mac",
        **over,
    }
    return ReportContext(**values)


def statuses(*keys: str, **over: Any):
    switches = {k: k in keys for k in capability_registry.keys()}
    return capability_registry.statuses_by_key(capability_registry.report(switches, ctx(**over), use_cache=False))


def gate(*keys: str, **over: Any):
    report = statuses(*keys, **over)

    async def answer():
        return report

    return answer


# ── 1. the switch ─────────────────────────────────────────────────────────


def test_acting_is_its_own_switch_off_by_default():
    status = statuses()["browser_act"]
    assert status.label == ACT_LABEL and status.risk == "high"
    assert status.enabled is False and status.default_enabled is False and status.effective == "off"
    assert status.tools == ("browser.act",)
    assert capability_registry.capability_for_tool(ACT).key == "browser_act"
    assert "browser.act" not in capability_registry.get("browser_control").tools


def test_acting_without_browser_control_is_blocked_with_a_plain_reason():
    alone = statuses("browser_act")["browser_act"]
    assert alone.effective == "blocked" and alone.reason == NEEDS_BROWSER
    assert statuses("browser_act", "browser_control")["browser_act"].effective == "on"
    # Control a browser switched on but not usable here: acting says why.
    broken = statuses("browser_act", "browser_control", playwright_installed=False)["browser_act"]
    assert broken.effective == "blocked"
    assert broken.reason.startswith("Needs 'Control a browser', which is blocked here: Playwright")
    assert "browser_act" not in capability_registry.enabled_keys(
        {"browser_act": True}, ctx()
    )


@pytest.mark.parametrize(
    "over, reason",
    [
        ({"in_container": True, "host_platform": "container"}, "container"),
        ({"platform": "linux", "host_platform": "linux"}, "macOS and Windows only"),
    ],
)
def test_acting_is_native_only(over, reason):
    status = statuses("browser_act", "browser_control", **over)["browser_act"]
    assert status.available is False and status.effective == "blocked" and reason in status.reason
    assert statuses("browser_act", "browser_control", host_platform="windows")["browser_act"].effective == "on"


def test_the_permissions_block_names_the_switch_in_each_state():
    off = render_permissions_block(statuses("browser_control").values())
    assert f"- {ACT_LABEL}: off — Filling in forms and clicking is off." in off
    blocked = render_permissions_block(statuses("browser_act").values())
    assert f"- {ACT_LABEL}: blocked — {NEEDS_BROWSER}" in blocked
    on = render_permissions_block(statuses("browser_act", "browser_control").values())
    assert f"- {ACT_LABEL}: on" in on


def test_the_offer_needs_both_browser_switches():
    names = lambda keys: {t.name for t in build_tools([], enabled_capabilities=frozenset(keys))}  # noqa: E731
    assert ACT not in names({"browser_control"}) and "browser.read" in names({"browser_control"})
    assert ACT not in names({"browser_act"})
    assert ACT in names({"browser_act", "browser_control"})
    assert ACT not in names({"browser_control", "purchases"})


@pytest.mark.asyncio
async def test_the_permission_check_and_the_dispatch_refuse_acting_while_it_is_not_on():
    act = RecordingAct()
    off = ConnectorToolExecutor(session_factory=None, capability_gate=gate("browser_control"), act_toolkit=act)
    result = await off.execute(ACT, {"action": "click", "ref": "e1"}, user_id=USER, approved=True)
    assert result == {
        "ok": False,
        "capability": "browser_act",
        "state": "off",
        "error": capability_registry.get("browser_act").when_denied,
    }
    alone = ConnectorToolExecutor(session_factory=None, capability_gate=gate("browser_act"), act_toolkit=act)
    result = await alone.execute(ACT, {"action": "click", "ref": "e1"}, user_id=USER, approved=True)
    assert result["ok"] is False and result["capability"] == "browser_act" and result["state"] == "blocked"
    assert NEEDS_BROWSER in result["error"]
    assert act.calls == []

    assert await RuntimePermissionAdapter(capability_gate=gate("browser_control")).check(USER, ACT, {}) == "blocked"
    assert await RuntimePermissionAdapter(capability_gate=gate("browser_act")).check(USER, ACT, {}) == "blocked"
    both = RuntimePermissionAdapter(capability_gate=gate("browser_act", "browser_control"))
    assert await both.check(USER, ACT, {}) == "requires_approval"


@pytest.mark.asyncio
async def test_an_install_that_had_control_a_browser_on_does_not_gain_acting_on_upgrade(
    session_factory, monkeypatch
):
    """The row an install wrote before the switch existed: Control a browser
    on, nothing about acting. After the upgrade it reads and follows links,
    and browser.act stays off until the owner turns it on."""
    from models.installation import INSTALLATION_ROW_ID, Installation
    from services.installation import InstallationService

    async with session_factory() as s:
        s.add(Installation(id=INSTALLATION_ROW_ID, capabilities={"browser_control": True}))
        await s.commit()
    monkeypatch.setattr(capability_registry, "default_context", lambda **_kw: ctx())
    svc = InstallationService(session_factory)

    assert (await svc.capabilities())["browser_act"] is False
    by_key = await svc.capability_statuses()
    assert by_key["browser_control"].effective == "on" and by_key["browser_act"].effective == "off"
    enabled = await svc.enabled_keys()
    offered = {t.name for t in build_tools([], enabled_capabilities=enabled)}
    assert "browser.read" in offered and ACT not in offered
    act = RecordingAct()
    ex = ConnectorToolExecutor(session_factory=None, capability_gate=svc.capability_statuses, act_toolkit=act)
    result = await ex.execute(ACT, {"action": "click", "ref": "e1"}, user_id=USER, approved=True)
    assert result["ok"] is False and result["capability"] == "browser_act" and result["state"] == "off"
    assert act.calls == []


# ── 2. the card's picture, through the executor, the runtime and Telegram ──

IMAGE = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsL"


class RecordingAct:
    """The act toolkit's card hooks, with ``bind_async`` adding a picture
    the way the real one does."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def precheck(self, params, *, user_id):
        return None

    def bind(self, params, *, user_id):
        return {**params, CARD_KEY: {"origin": "https://shop.example.com", "outline": "d1", "scheme": "https"}}

    async def bind_async(self, params, *, user_id, task_id):
        self.calls.append(("bind_async", dict(params), user_id, task_id))
        self.owner = user_id
        card = self.bind(params, user_id=user_id)
        return {**card, CARD_KEY: {**card[CARD_KEY], "picture": "p1"}}

    def describe(self, params, *, user_id):
        return 'Click "Continue" on shop.example.com'

    def approval_image(self, arguments, *, user_id):
        card = arguments.get(CARD_KEY) or {}
        return IMAGE if card.get("picture") == "p1" and user_id == getattr(self, "owner", None) else None

    async def execute(self, action, params, *, user_id, task_id, approved):
        self.calls.append(("execute", action, dict(params), user_id, task_id, approved))
        return {"ok": True}


@pytest.mark.asyncio
async def test_the_executor_binds_an_act_card_with_its_picture_and_serves_it():
    act = RecordingAct()
    ex = ConnectorToolExecutor(
        session_factory=None, capability_gate=gate("browser_act", "browser_control"), act_toolkit=act
    )
    card = await ex.approval_arguments_async(
        ACT, {"action": "click", "ref": "e1", "user_confirmed": True}, USER, task_id="conv-1"
    )
    assert card[CARD_KEY]["picture"] == "p1" and "user_confirmed" not in card
    assert act.calls == [("bind_async", {"action": "click", "ref": "e1"}, USER, "conv-1")]
    assert ex.approval_image(ACT, card, USER) == IMAGE
    assert ex.approval_image(ACT, card, "someone-else") is None


@pytest.mark.asyncio
async def test_a_parked_act_card_carries_its_picture_to_the_web():
    from tests.test_purchases_wiring import Turn, call

    ex = ConnectorToolExecutor(
        session_factory=None, capability_gate=gate("browser_act", "browser_control"), act_toolkit=RecordingAct()
    )
    turn = Turn(ex, gate("browser_act", "browser_control"))
    response = await turn.run(
        call("t1", ACT, action="click", ref="e1"),
        tools=build_tools([], enabled_capabilities=frozenset({"browser_act", "browser_control"})),
    )
    [pending] = response.pending_approvals
    assert pending.image == IMAGE and pending.reason == 'Click "Continue" on shop.example.com'
    [event] = turn.of_type("pending_approval")
    assert event["image"] == IMAGE and CARD_KEY in event["arguments"]
    # The picture is served from memory, never stored with the card.
    assert "image" not in str(pending.arguments) and IMAGE not in str(pending.arguments)


def _telegram(session_factory, image: Optional[str]):
    from services.notifications.telegram import TelegramService

    return TelegramService(
        token="123:fake-token", session_factory=session_factory, approval_image=lambda action: image
    )


@pytest.mark.asyncio
async def test_telegram_sends_an_act_card_as_a_photo_with_its_sentence(session_factory, fake_api):
    from tests.test_telegram import _link
    from tests.test_telegram_purchase_card import _action, _caption_of, _keyboard_of

    user = await _link(session_factory, "tg-act@example.com", 902)
    sentence = f'Click "Continue" on shop.example.com. {WARNING}'
    action = _action(
        str(user.id),
        tool_name=ACT,
        arguments={"action": "click", "ref": "e1", CARD_KEY: {"origin": "o", "picture": "p1"}},
        reason=sentence,
    )
    await _telegram(session_factory, IMAGE).notify_pending(action)
    assert fake_api.sent_messages() == []  # the photo is the card
    [photo] = fake_api.photos
    caption = _caption_of(photo)
    assert caption.startswith(f"🔐 Approval required\n\n{sentence}\n\nExpires in ")
    assert "e1" not in caption and "_page" not in caption
    buttons = [b["text"] for b in _keyboard_of(photo)["inline_keyboard"][0]]
    assert buttons == ["✅ Approve", "❌ Deny"]


@pytest.mark.asyncio
async def test_telegram_sends_an_act_card_without_a_picture_as_text(session_factory, fake_api):
    from tests.test_telegram import _link
    from tests.test_telegram_purchase_card import _action

    user = await _link(session_factory, "tg-act2@example.com", 903)
    sentence = f'Click "Continue" on shop.example.com. {NO_PICTURE_NOTE}'
    action = _action(str(user.id), tool_name=ACT, arguments={"action": "click", "ref": "e1"}, reason=sentence)
    await _telegram(session_factory, None).notify_pending(action)
    assert fake_api.photos == []
    [message] = fake_api.sent_messages()
    assert sentence in message["text"]


@pytest.fixture
def fake_api(monkeypatch):
    import httpx

    from tests.test_telegram_purchase_card import PhotoAwareAPI

    api = PhotoAwareAPI()
    real_client_cls = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(api.handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return api


# ── 2. the picture itself (no browser, then the fake site) ────────────────


@pytest.mark.asyncio
async def test_a_card_whose_picture_cannot_be_taken_is_still_made_and_says_so():
    kit, _sessions, memory = fake_kit()  # its session's page() refuses to be touched
    remember(memory)
    card = await kit.bind_async({"action": "click", "ref": "e11"}, user_id=USER, task_id="t1")
    assert card[CARD_KEY]["origin"] == "https://shop.example.com" and card[CARD_KEY]["picture"] == ""
    assert kit.describe(card, user_id=USER) == f'Click "Continue" on shop.example.com. {NO_PICTURE_NOTE}'
    assert kit.approval_image(card, user_id=USER) is None


def _pixel(image: Image.Image, x: float, y: float) -> tuple[int, int, int]:
    return image.getpixel((int(x), int(y)))[:3]


def _decode(data_url: str) -> Image.Image:
    assert data_url.startswith("data:image/jpeg;base64,")
    return Image.open(io.BytesIO(base64.b64decode(data_url.split(",", 1)[1]))).convert("RGB")


@pytest.mark.asyncio
async def test_the_card_shows_the_page_with_the_target_outlined_and_secrets_masked(kits, fakesite_tls):
    _read, act_kit, _sessions, _memory, _spy = kits
    await read(kits, "open", url=fakesite_tls.url("/login"))
    page = await live_page(kits)
    await page.fill("input[name=password]", "hunter2hunter2")
    before = await read(kits, "snapshot")
    call = {"action": "click", "ref": ref_of(before, '- button "Log in"')}
    card = await act_kit.bind_async(call, user_id=USER, task_id="t1")

    image = act_kit.approval_image(card, user_id=USER)
    assert image is not None and card[CARD_KEY]["picture"]
    picture = _decode(image)
    button = await page.locator("button").bounding_box()
    red = _pixel(picture, button["x"] - 1.5, button["y"] + button["height"] / 2)
    assert red[0] > 180 and red[1] < 90 and red[2] < 90, red  # the 3px box left of the button
    field = await page.locator("input[name=password]").bounding_box()
    masked = _pixel(picture, field["x"] + field["width"] / 2, field["y"] + field["height"] / 2)
    assert max(masked) < 50, masked  # the password field is blacked out
    # The box was an overlay: gone again, and the page the card was made
    # from is still the page, so the approved act runs.
    assert await page.locator("[data-crawler-outline]").count() == 0
    assert act_kit.approval_image(card, user_id="someone-else") is None
    arguments = {k: v for k, v in card.items() if k != "action"}
    result = await act_kit.execute("click", arguments, user_id=USER, task_id="t1", approved=True)
    assert result["ok"] is True, result
    assert act_kit.approval_image(card, user_id=USER) is None  # decided: dropped


@pytest.mark.asyncio
async def test_a_failed_screenshot_leaves_a_card_that_says_no_picture_was_taken(kits, fakesite_tls, monkeypatch):
    _read, act_kit, *_ = kits
    before = await read(kits, "open", url=fakesite_tls.url("/login"))

    async def broken(page, ref, *, mask_refs=()):
        raise RuntimeError("screenshot failed")

    monkeypatch.setattr(_shared, "jpeg", broken)
    call = {"action": "click", "ref": ref_of(before, '- button "Log in"')}
    card = await act_kit.bind_async(call, user_id=USER, task_id="t1")
    assert card[CARD_KEY]["picture"] == ""
    assert act_kit.describe(card, user_id=USER).endswith(f'"Log in" on {fakesite_tls.base.split("://")[1]}. {NO_PICTURE_NOTE}')
    assert act_kit.approval_image(card, user_id=USER) is None
    assert await (await live_page(kits)).locator("[data-crawler-outline]").count() == 0


# ── 3. the money warning ──────────────────────────────────────────────────


def test_the_money_warning_is_built_from_facts_and_leaves_out_what_it_does_not_know():
    assert _money_warning({"amount": "$499.00", "order_total": True, "saved_payment": True}) == WARNING
    assert _money_warning({"amount": "", "saved_payment": True}) == (
        f"This page shows a saved payment method. {MAY_ORDER_NOTE}"
    )
    assert _money_warning({"order_total": True, "wallet": True}) == (
        f"This page shows an order total and a wallet payment button. {MAY_ORDER_NOTE}"
    )
    assert _money_warning({"unread": True}) == f"Part of this page could not be read. {MAY_ORDER_NOTE}"
    assert _money_warning({}) == MAY_ORDER_NOTE


async def _card_sentence(kits, fakesite_tls, page_at, body: str, call: dict[str, Any], prefix: str) -> str:
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-card", body)))
    call = {**call, "ref": ref_of(before, prefix)}
    card = await kits[1].bind_async(call, user_id=USER, task_id="t1")
    assert card[CARD_KEY]["picture"], card  # a picture came with it
    return kits[1].describe(card, user_id=USER)


@pytest.mark.asyncio
async def test_a_fill_on_a_page_with_a_total_and_a_card_on_file_warns(kits, fakesite_tls, page_at):
    host = fakesite_tls.base.split("://")[1]
    sentence = await _card_sentence(
        kits, fakesite_tls, page_at, SAVED_CARD_LEAD + '<label>Gift note <input name="gift"></label>',
        {"action": "fill", "text": "thanks"}, '- textbox "Gift note"',
    )
    assert sentence == f'Type 6 characters into "Gift note" on {host}. {WARNING}'


@pytest.mark.asyncio
async def test_a_review_page_in_a_language_the_lists_do_not_read_still_warns(kits, fakesite_tls, page_at):
    """Finnish: the total label is not one the patterns know, so the amount
    is left out; the masked card still reads as a payment method on file."""
    sentence = await _card_sentence(
        kits, fakesite_tls, page_at,
        "<h1>Tarkista tilaus</h1><p>Maksutapa: Visa •••• 4242</p><p>Yhteensä 499,00 €</p>"
        '<button type="button">Jatka</button>',
        {"action": "click"}, '- button "Jatka"',
    )
    assert sentence.endswith(f". This page shows a saved payment method. {MAY_ORDER_NOTE}"), sentence


@pytest.mark.asyncio
async def test_a_click_the_act_rules_allow_on_a_page_with_a_total_warns(kits, fakesite_tls, page_at):
    """A total and no payment method the patterns read: browser.act lets the
    click run, and the card says what the page shows."""
    sentence = await _card_sentence(
        kits, fakesite_tls, page_at,
        '<h1>Review your order</h1><p>Order total: $499.00</p><button type="button">Continue</button>',
        {"action": "click"}, '- button "Continue"',
    )
    assert sentence.endswith(f'"Continue" on {fakesite_tls.base.split("://")[1]}. This page shows $499.00. {MAY_ORDER_NOTE}')


@pytest.mark.asyncio
async def test_a_page_with_nothing_to_pay_gets_no_warning(kits, fakesite_tls, page_at):
    host = fakesite_tls.base.split("://")[1]
    sentence = await _card_sentence(
        kits, fakesite_tls, page_at,
        '<h1>Newsletter</h1><p>Socks from $5.00</p><label>Email <input name="email"></label>',
        {"action": "fill", "text": "a@b.co"}, '- textbox "Email"',
    )
    assert sentence == f'Type 6 characters into "Email" on {host}'


# ── 4. browser.read's click never orders ──────────────────────────────────

# A 1x1 picture: a total whose amount is an image.
_PIXEL = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)
_FETCH_BUTTON = (
    '<button type="button" onclick="fetch(\'/next-step\', {method: \'POST\', body: \'saved=1\'})">Continue</button>'
)


@pytest.mark.parametrize(
    "body",
    [
        # A total whose amount is a picture (no price in text), a script
        # button that orders by fetch().
        f'<h1>Review your order</h1><p>Order total: <img src="{_PIXEL}" width="60" height="16" alt=""></p>'
        + _FETCH_BUTTON,
        # A script button inside a form, on a page with nothing to pay.
        f"<h1>Almost done</h1><form>{_FETCH_BUTTON}</form>",
    ],
)
@pytest.mark.asyncio
async def test_a_read_refuses_a_script_button_that_could_order(kits, fakesite_tls, page_at, body):
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-read-order", body)))
    result = await read(kits, "click", ref=ref_of(before, '- button "Continue"'))
    await settled(kits)
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert "/next-step" not in posted(fakesite_tls), fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_read_refuses_an_order_step_link_with_the_plain_sentence(kits, fakesite_tls, page_at):
    path = page_at("/r-read-link", '<h1>Your cart</h1><a href="/place-order-now?token=abc">Continue</a>')
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "click", ref=ref_of(before, '- link "Continue"'))
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert not sent(fakesite_tls, "GET", "/place-order-now"), fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_read_still_shows_more_flights_and_follows_a_result_link(kits, fakesite_tls, page_at):
    path = page_at(
        "/r-read-flights",
        "<h1>Best departing flights</h1><ul>"
        '<li><a href="/flights">10:40 AM – 2:05 PM United Nonstop $612 round trip</a></li>'
        "<li>1:15 PM – 4:30 PM ANA Nonstop $688 round trip</li></ul>"
        '<button type="button" onclick="document.getElementById(\'more\').hidden = false">Show more flights</button>'
        '<ul id="more" hidden><li>6:00 AM – 1:10 PM Air Canada 1 stop $455 round trip</li></ul>',
        "Flights",
    )
    before = await read(kits, "open", url=fakesite_tls.url(path))
    more = await read(kits, "click", ref=ref_of(before, '- button "Show more flights"'))
    assert more["ok"] is True and any("Air Canada" in line for line in more["outline"]), more
    followed = await read(kits, "click", ref=ref_of(more, '- link "10:40 AM'))
    assert followed["ok"] is True and followed["url"].endswith("/flights"), followed


@pytest.mark.parametrize(
    "target, allowed",
    [
        ({"name": "Show more", "buttonish": True, "money": True}, True),
        ({"name": "Next", "link": True, "plain_link": True, "href": "/results?page=2"}, True),
        ({"name": "Next", "link": True, "plain_link": True, "href": "/checkout/complete"}, False),
        ({"name": "Continue", "buttonish": True, "in_form": True}, False),
        ({"name": "Continue", "buttonish": True, "order_total": True}, False),
        ({"name": "Continue", "buttonish": True, "wallet": True}, False),
        ({"name": "Continue", "link": True, "href": "#more", "saved_payment": True}, False),
        ({"name": "Jetzt kaufen", "buttonish": True}, False),
        ({"name": "$3.99", "buttonish": True}, False),
        (None, False),
        ({"frame": True}, False),
    ],
)
def test_read_click_allowed_lets_through_only_plain_links_and_harmless_controls(target, allowed):
    assert markers.read_click_allowed(target) is allowed


# ── a card whose picture is gone ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_card_whose_picture_is_no_longer_kept_says_so_and_does_not_run(kits, fakesite_tls):
    """A card's picture lives in memory as long as the approval can be
    decided (``APPROVAL_TTL_MINUTES``). Once it is gone (evicted by other
    pending cards, or a restart), the card says so and its act is refused:
    the owner could not have seen the page on it."""
    _read, act_kit, *_ = kits
    assert act_kit._picture_ttl == settings.APPROVAL_TTL_MINUTES * 60
    before = await read(kits, "open", url=fakesite_tls.url("/login"))
    call = {"action": "click", "ref": ref_of(before, '- button "Log in"')}
    card = await act_kit.bind_async(call, user_id=USER, task_id="t1")
    assert act_kit.approval_image(card, user_id=USER) is not None
    assert PICTURE_GONE_NOTE not in act_kit.describe(card, user_id=USER)
    act_kit._pictures.clear()  # what an eviction or a restart leaves
    assert act_kit.approval_image(card, user_id=USER) is None
    assert act_kit.describe(card, user_id=USER).endswith(PICTURE_GONE_NOTE)
    arguments = {k: v for k, v in card.items() if k != "action"}
    result = await act_kit.execute("click", arguments, user_id=USER, task_id="t1", approved=True)
    assert result["ok"] is False and result["rule"] == "picture_gone", result
    assert not sent(fakesite_tls, "POST", "/login"), fakesite_tls.handled
