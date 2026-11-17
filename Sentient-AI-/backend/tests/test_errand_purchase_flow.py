"""An errand end to end on the fake TLS shop: the errand sweeper runs it as an
unattended turn whose website steps need no card, it opens the real checkout
page in headless Chromium and parks the one purchase card, read off that page
by the real checkout toolkit; the browser session is parked for the card and
the idle reaper leaves it alone for hours; Approve pays once with the vault's
card through the real decision path, and the owner's one message names the
item, the amount and the site and carries the confirmation and its picture.
A checkout page that is gone by the time of the OK pays nothing and plans
the errand again.

Why it exists: tests/test_errand_runs.py proves each promise on a fake
checkout; this file is the one place the errand's single approval runs the
real purchase toolkit (the same page, the caps, the merchant and the total
re-checked at approval) on the fake site, never a real one. The steps before
checkout use the act toolkit's bind fake: the real act toolkit never judges a
step on 127.0.0.1 with a port an errand step (app_approvals.site_for wants
one public host on https's own port), so on the fake site every real step
would be refused. Skipped where Playwright's Chromium is not installed.

Connects to: services/automation/errands.py, services/tools/browser/checkout/
toolkit.py (``hold``), services/tools/browser/session.py
(``park_for_purchase``), api/routes/agent.py (_apply_decision).
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio

from services.agent import cancel
from services.automation import errands
from services.installation import InstallationService
from services.tools.browser import guard as browser_guard
from services.tools.browser import handoff as browser_handoff
from services.tools.browser.actions import BrowserReadToolkit
from services.tools.browser.checkout.ledger import PurchaseLedger
from services.tools.browser.checkout.toolkit import BrowserCheckoutToolkit
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.session import PENDING_IDLE_SECONDS, BrowserSessionManager
from services.tools.system import browser_installed
from services.vault.service import VaultService
from tests.conftest import make_user, tls_launcher
from tests.fakesite.pages import PAGES
from tests.test_errand_runs import READ, STEPS, Errands, call

HOST = "127.0.0.1"
ITEM = "Concert ticket"
NUMBER = "4242424242424242"


class FixedKey:
    """A vault key that never leaves the test: 32 fixed bytes."""

    def get(self) -> bytes:
        return bytes(range(32))


class Plat:
    """The container platform: headless Chromium, no channel, profiles
    under the test's tmp dir."""

    name = "container"

    def __init__(self, root) -> None:
        self._root = root

    def browser_channel(self):
        return None

    def profile_dir(self, user_id: str):
        path = self._root / user_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def data_dir(self):
        return self._root


@pytest_asyncio.fixture
async def shop(session_factory, fakesite_tls, tmp_path):
    if not browser_installed():
        pytest.skip(
            "Playwright's Chromium is not installed (python -m playwright install chromium)"
        )
    user, _ = await make_user(session_factory)
    user_id = str(user.id)
    cancel.clear(user_id)
    errands.configure(None)
    vault = VaultService(session_factory, FixedKey())
    await vault.put_card(
        user_id, label="Visa", number=NUMBER, exp_month=12, exp_year=2028, cvc="987", name="K Q"
    )
    now = [1000.0]
    sessions = BrowserSessionManager(
        headless=True,
        platform=Plat(tmp_path),
        max_sessions=1,
        max_tabs=2,
        launcher=tls_launcher,
        clock=lambda: now[0],
    )
    memory = PageMemory()
    read = BrowserReadToolkit(
        sessions, guard=browser_guard, handoff=browser_handoff, page_memory=memory
    )
    checkout = BrowserCheckoutToolkit(
        sessions,
        guard=browser_guard,
        handoff=browser_handoff,
        memory=memory,
        vault=vault,
        ledger=PurchaseLedger(session_factory),
        settings=InstallationService(session_factory),
        cancel_flag=cancel.is_cancelled,
    )
    harness = Errands(session_factory, user_id, read=read, checkout=checkout)
    harness.sessions, harness.now, harness.site = sessions, now, fakesite_tls
    try:
        yield harness
    finally:
        await sessions.close_all()
        errands.configure(None)
        cancel.clear(user_id)


async def _to_the_card(shop) -> tuple[object, str]:
    """Plan the errand and run it: steps, the real checkout page (the
    owner's own link, which an errand's page read may open), the card."""
    link = shop.site.url("/checkout")
    shop.script(
        *STEPS,
        call("r1", READ, action="open", url=link),
        call("k1", "browser.checkout", merchant=HOST, amount="23.40"),
    )
    errand = await shop.service.create(
        shop.user_id,
        source="calendar",
        title="Ticket for Anna",
        item=ITEM,
        link=link,
        source_ref="evt-9",
    )
    assert await shop.run_due() == 1
    [card] = await shop.store.list_pending(shop.user_id)
    return errand, card.action_id


@pytest.mark.asyncio
async def test_an_errand_parks_one_real_purchase_card_and_approving_it_buys_once(shop):
    errand, action_id = await _to_the_card(shop)
    [card] = await shop.store.list_pending(shop.user_id)
    assert card.tool_name == "browser.checkout" and card.arguments["_checkout"]["host"] == HOST
    assert card.arguments["_checkout"]["amount_usd"] == "23.40"
    assert card.risk_note.startswith("Errand: Ticket for Anna. Nothing has been paid yet.")
    assert ("POST", "/pay") not in shop.site.handled

    # The session is parked for the card: the reaper leaves it for hours.
    session = shop.sessions.sessions[shop.user_id]
    assert session.pending == "purchase"
    shop.now[0] += PENDING_IDLE_SECONDS + 3600
    assert await shop.sessions.reap_idle() == 0 and not session.closed

    result = await shop.decide(action_id, True)

    assert shop.site.handled.count(("POST", "/pay")) == 1
    reply = result["assistant_reply"]
    assert reply.startswith(f"✅ Done: I bought {ITEM} for $23.40 on {HOST}.")
    assert "Order number 8841" in reply
    [photo] = result["assistant_notes"]["images"]
    assert photo["data_url"].startswith("data:image/jpeg;base64,")
    assert (await shop.errand(errand.id)).status == "done"
    # Single use: a second tap pays nothing.
    assert "error" in await shop.decide(action_id, True)
    assert shop.site.handled.count(("POST", "/pay")) == 1


@pytest.mark.asyncio
async def test_a_checkout_page_gone_by_the_ok_pays_nothing_and_plans_the_errand_again(shop):
    errand, action_id = await _to_the_card(shop)
    page = await shop.sessions.sessions[shop.user_id].page()
    await page.goto("about:blank")

    result = await shop.decide(action_id, True)

    assert ("POST", "/pay") not in shop.site.handled
    assert "Nothing was paid" in result["assistant_reply"]
    assert (await shop.errand(errand.id)).status == "planned"


def _held_for(shop, minutes: float) -> None:
    """Let the checkout toolkit's clock run *minutes* past now."""
    real = time.monotonic
    shop.checkout._clock = lambda: real() + minutes * 60


@pytest.mark.asyncio
async def test_a_card_held_past_a_chat_cards_wait_loads_its_page_again_and_still_pays_once(shop):
    errand, action_id = await _to_the_card(shop)
    _held_for(shop, 60)

    result = await shop.decide(action_id, True)

    assert shop.site.handled.count(("GET", "/checkout")) == 2
    assert shop.site.handled.count(("POST", "/pay")) == 1
    assert result["assistant_reply"].startswith(f"✅ Done: I bought {ITEM} for $23.40")
    assert (await shop.errand(errand.id)).status == "done"


@pytest.mark.asyncio
async def test_a_shop_session_that_ran_out_while_the_card_waited_pays_nothing_and_plans_again(
    shop, monkeypatch
):
    errand, action_id = await _to_the_card(shop)
    # The live page still shows the checkout; the shop now answers a sign-in.
    monkeypatch.setitem(PAGES, "/checkout", PAGES["/login"])
    _held_for(shop, 60)

    result = await shop.decide(action_id, True)

    assert ("POST", "/pay") not in shop.site.handled
    assert "Nothing was paid" in result["assistant_reply"]
    assert (await shop.errand(errand.id)).status == "planned"


@pytest.mark.asyncio
async def test_a_card_younger_than_a_chat_cards_wait_is_not_loaded_again(shop):
    _errand, action_id = await _to_the_card(shop)

    await shop.decide(action_id, True)

    assert shop.site.handled.count(("GET", "/checkout")) == 1
    assert shop.site.handled.count(("POST", "/pay")) == 1
