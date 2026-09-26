"""What the owner reads on a purchase card made on a real-looking shop host:
no security jargon in the normal case (purchases spec §6, review 2026-09-25).

Why it exists: test_purchase_flow runs the fake shop on 127.0.0.1, which the
taint tracker's host pattern never matches, so it could not catch the card
every real purchase got: a red "Heads up: this request was shaped by
external content" warning, because the model read the shop's page and then
named that shop as the merchant. The checkout toolkit already checks the
merchant against the page's own origin, so a matching card carries no
warning at all. Headless Chromium against the fake site served under a
route on https://tickets.example.com; skipped where Chromium is missing.
"""

from __future__ import annotations

import pytest

from services.agent.providers import LLMResponse
from tests.fakesite.pages import PAGES
from tests.test_purchase_flow import BOTH, checkout_call, flow, open_call  # noqa: F401

HOST = "tickets.example.com"


@pytest.mark.asyncio
async def test_a_purchase_card_on_a_real_host_carries_no_untrusted_content_warning(flow):  # noqa: F811
    runtime = flow.runtime(*BOTH)
    # The first turn only starts the browser session, so a route can be added.
    await flow.chat(runtime, open_call(flow.tls.url("/checkout")), LLMResponse(content="ok"))
    body = PAGES["/checkout"][2]

    async def serve(route, request):
        await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body)

    await flow.session().context.route(f"https://{HOST}/**", serve)
    response = await flow.chat(
        runtime,
        open_call(f"https://{HOST}/checkout"),
        checkout_call(merchant=HOST, amount=23.4, note="one ticket"),
    )
    assert response.blocked_actions == []
    [pending] = response.pending_approvals
    assert pending.arguments["_checkout"]["host"] == HOST
    assert pending.reason.startswith(f"Pay $23.40 to {HOST}")
    # The merchant the model named is the host the toolkit read off the
    # page, so there is nothing to warn about: no risk note on the web
    # card, in the event, or in the Telegram caption built from it.
    assert pending.risk_note is None
    [event] = flow.of_type("pending_approval")
    assert event["risk_note"] is None
