"""The markers every browser toolkit shares (checkout/markers.py): the
card-field classifier as Python and as the page-side script built from
the same patterns, the purchase rules browser.act and browser.read judge
a click by (a plain link is navigation; words refuse an act only where
money can move), and the log sanitiser that keeps a typed value out of
an exception's text.
Pure, except one headless Chromium check that the script and the Python
rule agree on real elements."""

from __future__ import annotations

import json

import pytest

from services.tools.browser import _shared
from services.tools.browser.checkout import markers


@pytest.mark.parametrize(
    "field, kind",
    [
        ({"autocomplete": "cc-number", "hint": "x"}, "number"),
        ({"autocomplete": "cc-csc", "hint": "x"}, "cvc"),
        ({"autocomplete": "cc-exp-month", "hint": "x"}, "exp_month"),
        ({"hint": "card no"}, "number"),
        ({"hint": "ccnum"}, "number"),
        ({"hint": "pan"}, "number"),
        ({"hint": "csc"}, "cvc"),
        ({"hint": "cid"}, "cvc"),
        ({"hint": "security code"}, "cvc"),
        ({"hint": "name on card"}, "name"),
        ({"hint": "cardholder"}, "name"),
        ({"hint": "expiry (mm/yy)"}, "exp"),
        ({"hint": "valid thru"}, "exp"),
        ({"hint": "expmonth"}, "exp_month"),
        ({"hint": "year"}, "exp_year"),
        ({"hint": "email"}, None),
        ({"hint": "company"}, None),
        ({"hint": "card no", "type": "hidden"}, None),
        ({"hint": "card no", "type": "checkbox"}, None),
    ],
)
def test_field_kind_by_token_then_by_hint(field, kind):
    assert markers.field_kind({"type": "text", **field}) == kind


def test_the_page_side_classifier_is_built_from_the_same_patterns():
    """The script embeds each Python pattern verbatim, so a hint added
    to one side is on the other by construction."""
    for pattern in (markers.NUMBER_RE, markers.CVC_RE, markers.NAME_RE, markers.EXP_RE):
        assert f"new RegExp({json.dumps(pattern.pattern)}, 'i')" in markers.FIELD_KIND_FN
    assert markers.FIELD_KIND_JS.startswith("el => ") and "MARK" not in markers.FIELD_KIND_JS
    assert markers.MASK_ATTRIBUTE in markers.MASK_SELECTOR
    assert _shared.MASK_SELECTOR == markers.MASK_SELECTOR and _shared.FIELD_KIND_JS == markers.FIELD_KIND_JS


@pytest.mark.parametrize(
    "name",
    ["Password", "passcode", "One-time code", "Verification code", "Card number", "Card no",
     "CVC", "CVV", "CSC", "Security code", "Name on card", "Cardholder", "Expiry", "Expiration date",
     "Valid thru", "PAN"],
)
def test_the_name_rule_covers_every_card_field_name(name):
    assert markers.SECRET_NAME_RE.search(name), name


@pytest.mark.parametrize("name", ["Email", "Company", "Export", "Expected delivery", "Japan", "Month"])
def test_the_name_rule_leaves_ordinary_fields_alone(name):
    assert markers.SECRET_NAME_RE.search(name) is None, name


@pytest.mark.parametrize(
    "words, pays",
    [
        ("Place order", True), ("Place your order", True), ("PLACE ORDER", True), ("Pay now", True),
        ("Pay", True), ("Buy", True), ("Buy now with 1-Click", True), ("Purchase", True),
        ("Complete order", True), ("Complete purchase", True), ("Confirm payment", True),
        ("Confirm and pay", True), ("Submit order", True), ("Order now", True), ("Book now", True),
        ("Subscribe", True), ("Start free trial", True), ("Pay securely", True),
        ("Checkout", False), ("Proceed to checkout", False), ("Continue to payment", False),
        ("Payment methods", False), ("PayPal", False),
        # Other languages: German, French, Spanish, Italian, Portuguese,
        # Dutch, and the scripts written without spaces.
        ("Jetzt kaufen", True), ("Zahlungspflichtig bestellen", True), ("Bezahlen", True),
        ("Acheter", True), ("Passer la commande", True), ("Payer", True),
        ("Comprar ahora", True), ("Realizar pedido", True), ("Pagar", True),
        ("Acquista ora", True), ("Paga", True), ("Ordina", True),
        ("Finalizar compra", True), ("Nu kopen", True), ("Betalen", True), ("Bestelling plaatsen", True),
        ("今すぐ購入", True), ("注文を確定する", True), ("立即购买", True), ("提交订单并支付", True),
        ("구매하기", True), ("결제하기", True), ("अभी खरीदें", True), ("भुगतान करें", True),
        # Russian, Arabic and Hebrew (right to left), Turkish, Polish,
        # Swedish, a Japanese confirm, and the one-click words of English.
        ("Оплатить", True), ("Оформить заказ", True), ("ادفع الآن", True), ("تأكيد الطلب", True),
        ("לתשלום", True), ("קנה עכשיו", True), ("Satın al", True), ("Siparişi tamamla", True),
        ("Kup teraz", True), ("Złóż zamówienie", True), ("Köp nu", True), ("Slutför köp", True),
        ("確定する", True), ("提交订单", True),
        ("Rent HD", True), ("Donate now", True), ("Pre-order", True), ("Preorder", True), ("Reserve", True),
        ("Request to book", True), ("Place bid", True), ("Upgrade now", True), ("Renew", True),
        ("Böden", False), ("Rentals", False), ("Parent", False), ("Reserved seating", False),
        ("Weiter einkaufen", False), ("Bestellung ansehen", False), ("Métodos de pago", False),
        ("Pagamento sicuro", False), ("In den Warenkorb", False),
        ("Buyer protection", False), ("Add to cart", False), ("Sort order", False), ("Apply", False),
    ],
)
def test_the_purchase_words(words, pays):
    """One list, no allowlist: what a button that moves money says.
    Buttons that lead to the checkout page are not on it (no money moves
    there), and a word inside another word does not count. A bare word
    from the list ("Purchase") counts wherever it stands."""
    assert bool(markers.PURCHASE_RE.search(words)) is pays, words
    assert all(word == word.lower() for word in markers.PURCHASE_WORDS)


def _target(**over):
    base = {
        "name": "Continue", "card_in_form": False, "sends": True, "buttonish": True,
        "action": "/next", "order_total": False, "saved_payment": False,
    }
    return {**base, **over}


@pytest.mark.parametrize(
    "target, pays",
    [
        # The control's words when money can move from the act: it sends a
        # POST form, or the page shows an order total or a payment method
        # on file. Words alone are left to the approval card.
        (_target(name="Place order"), True),
        (_target(name="Gift note | Place order"), True),
        (_target(name="Place order", sends=False, order_total=True), True),
        (_target(name="Buy now", sends=False, buttonish=False, saved_payment=True), True),
        (_target(name="Place order", sends=False), False),
        # A typed card in the form it sends.
        (_target(card_in_form=True, sends=False, buttonish=False), True),
        # A POST form to an order path, whatever the button says.
        (_target(name="Confirm", action="/place-order"), True),
        (_target(name="Continue", action="/checkout/complete"), True),
        (_target(name="", action="/orders"), True),
        (_target(name="Confirm", action="/pay"), True),
        # The same path by GET is an order too (a GET can place one).
        (_target(name="Confirm", action="/place-order", sends=False), True),
        # A link aimed at an order path, whatever it says; a plain link
        # elsewhere is a read.
        (_target(name="Continue", sends=False, buttonish=False, action="", link=True, href="/place-order-now?t=1"), True),
        (_target(name="Your cart", sends=False, buttonish=False, action="", link=True, href="/cart"), False),
        # A page (any frame of it) that holds a payment method in words
        # next to a price: anything but a plain link is refused, in any
        # language. A wallet button somewhere on a page refuses nothing
        # (every shop shows one): only the wallet control itself is refused.
        (_target(name="Weiter", saved_payment=True, money=True), True),
        (_target(name="Weiter", sends=False, buttonish=False, action="", wallet=True, money=True), False),
        (_target(name="Add to cart", action="/cart/add", wallet=True, money=True), False),
        (_target(name="Buy with Google Pay", sends=False, action=""), True),
        (_target(name="PayPal", sends=False, buttonish=False, action=""), True),
        (_target(name="Edit cart", sends=False, buttonish=False, action="", link=True, href="/cart",
                 plain_link=True, saved_payment=True, money=True), False),
        (_target(name="Edit cart", sends=False, buttonish=False, action="", link=True, href="/cart",
                 plain_link=False, saved_payment=True, money=True), True),
        (_target(name="Save", saved_payment=True, money=False), False),
        # A focus in a frame nobody followed: fail closed.
        ({"frame": True}, True),
        # A total on screen next to a payment method on file: any button,
        # any form.
        (_target(name="Confirm", order_total=True, saved_payment=True), True),
        (_target(name="Confirm", sends=False, order_total=True, saved_payment=True), True),
        # Neither fact alone: a cart page shows a total; a profile page
        # shows a saved card.
        (_target(name="Update cart", order_total=True), False),
        (_target(name="Save", saved_payment=True), False),
        # A link (not a button, sends nothing) on an order page is a read.
        (_target(name="Terms", sends=False, buttonish=False, order_total=True, saved_payment=True), False),
        # Ordinary forms.
        (_target(name="Sign up", action="/post"), False),
        (_target(name="Log in", action="/login"), False),
        (_target(name="Search", action="/search", sends=False), False),
        # A button that is little more than a price is a one-click order;
        # a link that shows a price, or "Add to cart" with one, is not.
        (_target(name="HD $3.99", sends=False), True),
        (_target(name="$0.99", sends=False, action=""), True),
        (_target(name="Add to cart - $19.00", action="/cart/add"), False),
        (_target(name="Nonstop $612 round trip", sends=False, buttonish=False, action="", link=True, href="/book?f=0",
                 plain_link=True), False),
        # Not the scripts' answer (a click whose landing cannot be known
        # answers null): fail closed.
        (None, True),
        ("Place order", True),
    ],
)
def test_pays_judges_the_control_that_sends_the_form_and_the_page(target, pays):
    """The rule table behind ``use_checkout``: a typed card, an order
    path, a bare price, the wallet control, a review page with a saved
    payment method, or purchase words where money can move."""
    assert markers.pays(target) is pays, target


# What the judge answers for a plain link: an http(s) <a href> to another
# page, opened by GET, with no script or role of its own.
PLAIN_LINK = {"link": True, "plain_link": True, "sends": False, "buttonish": False, "action": ""}
# Everything a page and a form can show around a control.
BUSY_PAGE = {
    "order_total": True, "saved_payment": True, "wallet": True, "money": True,
    "in_form": True, "card_in_form": True,
}


@pytest.mark.parametrize(
    "name, href",
    [
        # A film poster whose anchor hides "Buy Tickets" for screen readers,
        # and a showtime: both open the next page, neither pays.
        ("Paper Tiger (2026) | Paper Tiger (2026) Buy Tickets", "/paper-tiger-2026-246826/movie-overview"),
        ("Buy tickets for 7:15 PM showtime", "/transaction/ticketing/mobile/jump.aspx?tid=AAQQP"),
        ("Subscribe and save $5.00", "/plans"),
        ("PayPal", "/help/paying-with-paypal"),
    ],
)
def test_a_plain_link_that_is_no_order_path_is_navigation_whatever_it_says(name, href):
    """Following a link by GET moves no money, so neither tier refuses it
    for its words: browser.read follows it, and browser.act's card is made
    for it. The one exception is a link worded like the order itself on a
    page that already shows a total or a payment method on file: a link a
    script handles ("Place order" in a cart) looks plain too."""
    link = _target(name=name, href=href, **PLAIN_LINK)
    assert markers.pays(link) is False, link
    assert markers.read_click_pays(link) is False, link
    assert markers.read_click_allowed(link) is True, link
    busy = _target(name=name, href=href, **PLAIN_LINK, **BUSY_PAGE)
    worded = bool(markers.PURCHASE_RE.search(name))
    assert markers.pays(busy) is worded, busy
    assert markers.pay_rule(busy) == ("purchase_words" if worded else None), busy


@pytest.mark.parametrize("href", ["/buy", "/pay", "/checkout/complete", "/buy?id=1", "/place-order-now?t=1"])
def test_a_plain_link_aimed_at_an_order_path_still_pays(href):
    """Opening an order path can be the order itself: the address is
    judged before anything else about a link."""
    link = _target(name="Tickets", href=href, **PLAIN_LINK)
    assert markers.pays(link) is True
    assert markers.read_click_pays(link) is True and markers.read_click_allowed(link) is False


def test_purchase_words_alone_go_to_the_approval_card_but_never_to_a_read():
    """A script button "Buy tickets" on a page with no order total and no
    payment method on file opens the ticketing page. browser.act no longer
    refuses it (its card shows the page and warns); browser.read, which
    has no card, still leaves it alone."""
    button = _target(name="Buy tickets", sends=False, action="", money=True)
    assert markers.pays(button) is False
    assert markers.read_click_pays(button) is True and markers.read_click_allowed(button) is False


@pytest.mark.parametrize("fact", ["sends", "order_total", "saved_payment"])
def test_purchase_words_refuse_an_act_when_money_can_move(fact):
    """The same button in a POST form, or on a page that shows an order
    total or a payment method on file, is the order button."""
    button = _target(name="Buy tickets", sends=False, action="")
    assert markers.pays(button) is False and markers.pays({**button, fact: True}) is True


@pytest.mark.parametrize("name", ["Buy with Google Pay", "PayPal", "Apple Pay", "G Pay", "Check out with Shop Pay"])
def test_a_wallet_control_is_refused_by_its_own_words(name):
    assert markers.pays(_target(name=name, sends=False, action="")) is True
    assert markers.change_pays({"name": f"Payment | {name}"}) is True


def test_a_wallet_button_elsewhere_on_the_page_refuses_no_act_but_every_read():
    """Most shops show an Apple Pay or PayPal button on every product
    page. That no longer makes "Add to cart" and the size picker
    unclickable through browser.act; a read still leaves the page's
    buttons alone."""
    shop = {"wallet": True, "money": True}
    add = _target(name="Add to cart", action="/cart/add", **shop)
    assert markers.pays(add) is False
    assert markers.change_pays({"name": "Size | M", **shop}) is False
    assert markers.read_click_pays(add) is True and markers.read_click_allowed(add) is False
    # A payment method on file in words, next to a price, still refuses both.
    assert markers.pays({**add, "saved_payment": True}) is True
    assert markers.change_pays({"name": "Size | M", "saved_payment": True, "money": True}) is True


@pytest.mark.parametrize(
    "target, rule",
    [
        (None, "unjudged"),
        ({"frame": True}, "unjudged"),
        (_target(name="Tickets", href="/buy", **PLAIN_LINK), "order_path"),
        (_target(name="Confirm", action="/place-order"), "order_path"),
        (_target(card_in_form=True), "card_in_form"),
        (_target(name="$0.99", sends=False, action=""), "priced_control"),
        (_target(name="PayPal", sends=False, action=""), "wallet_control"),
        (_target(name="Weiter", saved_payment=True, money=True), "saved_payment"),
        (_target(name="Place order"), "purchase_words"),
        (_target(name="Confirm", order_total=True, saved_payment=True), "order_review"),
        (_target(name="Sign up", action="/post"), None),
    ],
)
def test_pay_rule_names_the_rule_that_refuses(target, rule):
    """browser.act logs the rule's name with a refusal (never the
    control's words), so a refusal can be traced to the rule behind it."""
    assert markers.pay_rule(target) == rule
    assert markers.pays(target) is (rule is not None)


@pytest.mark.parametrize(
    "path, is_order",
    [
        ("/place-order", True), ("/placeOrder", True), ("/submit_order", True), ("/confirm-order", True),
        ("/orders", True), ("/order/", True), ("/pay", True), ("/payment", True), ("/purchase/confirm", True),
        ("/buy", True), ("/checkout/complete", True), ("/checkout/pay", True), ("/subscribe", True),
        ("/post", False), ("/login", False), ("/next", False), ("/search", False), ("/coupon", False),
        ("/checkout", False), ("/checkout/shipping", False), ("/payment-methods", False), ("/orders-help", False),
    ],
)
def test_order_paths(path, is_order):
    assert bool(markers.ORDER_ACTION_RE.search(path)) is is_order, path


@pytest.mark.parametrize(
    "path, is_step",
    [
        ("/place-order-now?token=abc", True), ("/placeOrder", True), ("/confirm_order", True),
        ("/checkout/complete", True), ("/checkout/confirm/", True), ("/go?next=/submit-order", True),
        ("/checkout/complete?sku=1", True), ("/checkout/finish#done", True), ("/checkout/completed", False),
        # An order history, a payment page, a product's buy page: opened to be read.
        ("/orders", False), ("/orders/8841", False), ("/pay", False), ("/payment", False),
        ("/checkout/pay", False), ("/purchase-history", False), ("/buy/", False), ("/order-confirmed", False),
    ],
)
def test_order_steps_are_the_addresses_that_order_when_opened(path, is_step):
    """What browser.read never opens (the guard) nor clicks a link to: an
    address whose opening may be the order itself. Every step is an order
    path for browser.act too."""
    assert bool(markers.ORDER_STEP_RE.search(path)) is is_step, path
    if is_step:
        assert markers.ORDER_ACTION_RE.search(path), path


@pytest.mark.parametrize(
    "text, saved",
    [
        ("Paying with the card on file (Visa ending 4242).", True),
        ("Card ending in 1234", True), ("Visa •••• 4242", True), ("**** 4242", True), ("xxxx-4242", True),
        ("Payment method: PayPal", True), ("Payment: Visa", True), ("Your saved card", True),
        ("Last 4 digits: 4242", True),
        ("We accept Visa, Mastercard and PayPal.", False),
        ("Pay with PayPal", False), ("Order #4242", False), ("Total: $499.00", False),
        # Masked numbers read the same in every language; "ending in" and
        # "Payment method:" in the main ones.
        ("Visa ····4242", True), ("●●●● 4242", True), ("Karte endet auf 4242", True),
        ("Carte se terminant par 4242", True), ("Tarjeta terminada en 4242", True),
        ("Zahlungsart: Visa", True), ("Método de pago: Mastercard", True), ("カード末尾 4242", True),
        ("**2024 sale", False), ("Artikel 4242", False),
        # A card written with ASCII dots or an ellipsis, a default card.
        ("Card: Visa ...4242 (default)", True), ("Visa ....4242", True), ("Mastercard …4444", True),
        ("Charged to your default card.", True), ("Your primary payment method", True),
        ("Loading... 2024", False), ("Default shipping address", False),
        # A card network and its last four right after "paying with" or
        # "pay with" (Amazon's review page); a network alone pays nothing.
        ("Paying with Visa 1234", True), ("Pay with Mastercard 5555", True),
        ("Pay with Visa", False), ("Visa 1234 Main St", False),
    ],
)
def test_saved_payment_words(text, saved):
    """A page that already holds a way to pay, as it says so; the brands a
    cart page merely accepts do not count."""
    assert bool(markers.SAVED_PAYMENT_RE.search(text)) is saved, text


def test_the_total_label_and_the_money_pattern_are_the_checkout_facts_own():
    """browser.act asks "is a total on screen" with the checkout's own
    label and price patterns, so the two cannot drift apart."""
    from services.tools.browser.checkout import facts

    assert facts._TOTAL_LABEL_RE is markers.TOTAL_LABEL_RE
    assert json.dumps(markers.MONEY_PATTERN) in facts._PAGE_JS
    assert markers.MONEY_RE.search("Order total: $499.00") and not markers.MONEY_RE.search("Order 499")
    assert markers.TOTAL_LABEL_RE.search("Order total: $499.00") and not markers.TOTAL_LABEL_RE.search("Subtotal $19")


@pytest.mark.parametrize(
    "text", ["Gesamtsumme: 23,40 €", "Total TTC 23,40 €", "Importe total: 23,40 €", "Totale 23,40 €",
             "合計 ¥2,300", "总计 ¥230", "총액 ₩23,000", "कुल ₹2,300",
             "Итого: 1 234 ₽", "الإجمالي: 499 ر.س", 'סה"כ לתשלום: ₪499', "合計 1,234円", "Razem: 99,00 zł"],
)
def test_total_labels_in_other_languages(text):
    assert markers.TOTAL_LABEL_RE.search(text) and markers.MONEY_RE.search(text), text


@pytest.mark.parametrize(
    "target, pays",
    [
        ({"name": "Pay with the card on file"}, True),
        ({"name": "Payment | Card on file"}, False),
        ({"name": "Payment | Card on file", "saved_payment": True, "money": True}, True),
        ({"name": "Country | Canada", "order_total": True}, False),
        ({"name": "Gift wrap", "wallet": True, "money": True}, False),
        ({"name": "Payment | PayPal"}, True),
        (None, True),
    ],
)
def test_change_pays_judges_the_choice_and_the_page(target, pays):
    """A check or a select: its own words (a purchase, or a wallet), or a
    page that holds a payment method in words next to a price. The form's
    button is not asked (a checkout's Country select sits in the form
    whose button says "Place order"), and a wallet button elsewhere on the
    page refuses no choice."""
    assert markers.change_pays(target) is pays, target


@pytest.mark.parametrize(
    "text, money",
    [
        ("1 234 ₽", True), ("₪499", True), ("1,234円", True), ("499 ر.س", True), ("25 د.إ", True),
        ("99,00 zł", True), ("149 kr", True), ("Rs. 499", True), ("฿350", True), ("99¢", True),
        ("UAH 250", True), ("250 CZK", True), ("US$5", True),
        ("ALL 3", False), ("TOP 10 deals", False), ("PEN 2", False), ("Order 499", False), ("6 ft tall", False),
    ],
)
def test_money_is_any_currency_sign_or_code(text, money):
    """Every currency sign Unicode knows, the ISO codes (less the ones
    that are English words), and the words shops write a price with."""
    assert bool(markers.MONEY_RE.search(text)) is money, text


@pytest.mark.parametrize(
    "name, priced",
    [
        ("Rent HD $3.99", True), ("$0.99", True), ("Get | 4,99 €", True), ("USD 5", True),
        ("Add to cart - $19.00", False), ("In den Warenkorb 19,00 €", False),
        ("Main cabin $612 Select", False), ("Continue", False), ("", False),
    ],
)
def test_a_control_that_is_little_more_than_a_price(name, priced):
    assert markers.priced_control(name) is priced, name


@pytest.mark.parametrize(
    "target, refused",
    [
        # Everything browser.act refuses.
        (_target(name="Complete purchase", sends=False), True),
        (_target(name="Jetzt kaufen", sends=False, saved_payment=True, money=True), True),
        (None, True),
        # A link: only one aimed at an order step; an order history is read.
        (_target(name="Continue", sends=False, buttonish=False, action="", link=True, href="/place-order-now?t=1",
                 plain_link=True), True),
        (_target(name="Your orders", sends=False, buttonish=False, action="", link=True, href="/orders",
                 plain_link=True), False),
        # A button, any words, on a page that shows a price next to a total
        # or a payment method: a script behind it may place the order.
        (_target(name="Continue", sends=False, action="", order_total=True, money=True), True),
        (_target(name="Show details", sends=False, action="", wallet=True, money=True), True),
        # A button on a page that only shows prices, a link anywhere.
        (_target(name="Show more", sends=False, action="", money=True), False),
        (_target(name="Terms", sends=False, buttonish=False, action="", link=True, href="/terms", plain_link=True,
                 order_total=True, saved_payment=True, money=True), False),
    ],
)
def test_read_click_pays_leaves_every_click_that_may_order_to_browser_act(target, refused):
    """browser.read clicks with no approval card: it refuses whatever
    browser.act would, any control whose words are a purchase, and any
    button on a page that looks like a cart or a review page."""
    assert markers.read_click_pays(target) is refused, target


def test_join_page_adds_every_frames_facts_and_fails_closed():
    inner = {"name": "Confirm", "order_total": False, "saved_payment": False, "wallet": False, "money": False}
    top = {"order_total": True, "saved_payment": True, "wallet": False, "money": True}
    joined = markers.join_page(inner, [top, {"order_total": False}])
    assert joined == {**inner, "order_total": True, "saved_payment": True, "wallet": True, "money": True}
    # a frame that could not be asked (None) counts as showing everything
    assert all(markers.join_page(inner, [None])[key] for key in markers.PAGE_FACT_KEYS)  # type: ignore[index]
    assert markers.join_page(inner, [])["money"] is False  # type: ignore[index]
    assert markers.join_page("junk", [top]) == "junk"


def test_the_refusals_name_the_next_tool_and_hold_with_the_switch_on_or_off():
    """Both are results the model reads. The old sentences named only the
    owner's switch, so a refusal with every switch on was passed on as
    "permissions are turned off". Each now says which tool to call next,
    and treats the switch as off only when that tool is not offered."""
    assert markers.USE_CHECKOUT_MESSAGE == (
        "This step pays or places an order, so browser.act does not do it. On the payment page "
        "call browser.checkout with the site's domain: the person approves the amount first. "
        "Only if you have no browser.checkout tool is 'Buy things for me' off: then stop here "
        "and tell the person the page is ready for them, and that they can turn it on in "
        "Settings, under Permissions."
    )
    assert markers.READ_CLICK_MESSAGE == (
        'browser.read does not make this click. Call browser.act with action "click" and the '
        "same ref: the person approves it on a request that shows the page, then it runs. Only "
        "if you have no browser.act tool is 'Fill in forms and click on sites' off: then tell "
        "the person they can turn it on in Settings, under Permissions."
    )


@pytest.mark.parametrize(
    "text, kept, dropped",
    [
        (
            'Locator.fill: Timeout 3000ms exceeded.\nCall log:\n  - waiting for locator("aria-ref=e12")\n'
            '    - locator resolved to <input readonly name="pan"/>\n    - fill("4242424242424242")\n',
            "Locator.fill: Timeout 3000ms exceeded.",
            "4242",
        ),
        ('Error: fill("4242 4242 4242 4242") failed on https://shop.example/pay?session=abc',
         'fill(…) failed on https://shop.example/pay', "4242"),
        ("selectOption('12') did not match", "selectOption(…) did not match", "12"),
        ("plain message", "plain message", "Call log"),
    ],
)
def test_log_detail_drops_the_call_log_typed_values_and_query_strings(text, kept, dropped):
    detail = _shared.log_detail(RuntimeError(text))
    assert kept in detail and dropped not in detail


@pytest.mark.asyncio
async def test_the_script_and_the_python_rule_agree_on_a_live_form(page):
    """The same elements, classified by the page-side script and by the
    Python rule over the hints the checkout collects."""
    await page.set_content(
        "<form><label>Card no <input id='a' name='ccnum'></label>"
        "<label>CSC <input id='b' name='csc'></label>"
        "<input id='c' placeholder='MM / YY'>"
        "<span id='nm'>Name on card</span><input id='d' aria-labelledby='nm'>"
        "<label>Month <select id='e' name='month'><option>1</option></select></label>"
        "<label>Exp month <select id='f' name='expmonth'><option>1</option></select></label>"
        "<label>Email <input id='g' name='email'></label>"
        "<input id='h' type='password' name='pw'><input id='i' autocomplete='one-time-code'>"
        "<input id='j' type='hidden' name='cardnumber'></form>"
    )
    kinds = {}
    for id_ in "abcdefghij":
        kinds[id_] = await page.locator(f"#{id_}").evaluate(markers.FIELD_KIND_JS)
    assert kinds == {
        "a": "cc-number", "b": "cc-csc", "c": "cc-exp", "d": "cc-name", "e": None, "f": "cc-exp-month",
        "g": None, "h": "password", "i": "one-time-code", "j": None,
    }
    marked = await page.evaluate(markers.MARK_SECRET_FIELDS_JS)
    assert marked == 7, await page.evaluate(f"() => [...document.querySelectorAll('[{markers.MASK_ATTRIBUTE}]')].map(e => e.id)")
    # The selector also matches the hidden cardnumber input by attribute:
    # a mask over nothing visible costs nothing.
    assert await page.locator(markers.MASK_SELECTOR).count() == 8
    assert await page.locator(f"#g[{markers.MASK_ATTRIBUTE}]").count() == 0
    # Filled, then cleared and counted.
    await page.fill("#a", "4242 4242 4242 4242")
    await page.fill("#b", "987")
    await page.fill("#h", "hunter2")
    assert await page.evaluate(markers.FILLED_CARD_FIELDS_JS) == 3  # the exp-month select has a value
    assert await page.evaluate(markers.CLEAR_CARD_FIELDS_JS) == 0
    assert await page.evaluate(markers.FILLED_CARD_FIELDS_JS) == 0
    assert await page.input_value("#a") == "" and await page.input_value("#h") == "hunter2"


@pytest.mark.asyncio
async def test_the_judge_says_whether_a_click_sends_its_form_by_any_method(page):
    """``sends`` is a POST form; ``submits`` is a form's own submit
    control whatever the method (a search box's "Go" sends by GET). A
    plain button or a field in the same form, a button outside any form
    and a link send nothing by themselves. browser.act reads ``submits``
    to tell an act that only clicks around from one that sends a form."""
    await page.set_content(
        "<form action='/search'><input id='q' name='q'><button id='go'>Go</button>"
        "<button id='plain' type='button'>Filters</button></form>"
        "<form method='post' action='/next'><button id='post'>Continue</button></form>"
        "<button id='out' type='button'>Next</button><a id='link' href='https://shop.example/about'>About</a>"
    )
    judged = {}
    for id_ in ("go", "plain", "q", "post", "out", "link"):
        target = await page.locator(f"#{id_}").evaluate(markers.PURCHASE_TARGET_JS)
        judged[id_] = (target["sends"], target["submits"])
    assert judged == {
        "go": (False, True), "plain": (False, False), "q": (False, False),
        "post": (True, True), "out": (False, False), "link": (False, False),
    }
    # A submit through a field goes out by the form's default button.
    assert (await page.locator("#q").evaluate(markers.SUBMIT_TARGET_JS))["submits"] is True


@pytest.mark.parametrize(
    "href, refused",
    [
        # Every order path: a GET to /buy/1 can be the order itself.
        ("/buy/1?qty=1", True), ("https://shop.example/buy?id=1", True), ("/pay?x=1", True),
        ("/purchase/7", True), ("/orders/8841/reorder", True), ("/orders/new", True), ("/order/5", True),
        ("/place-order-now?t=1", True), ("/orders?next=/pay", True),
        # An order history, and one past order by its number, are read.
        ("/orders", False), ("/orders/", False), ("https://shop.example/account/orders?page=2", False),
        ("/orders/8841", False), ("/orders/A-1234/", False),
        ("/orders-help", False), ("/payment-methods", False), ("/terms", False),
    ],
)
def test_a_read_click_follows_no_link_to_an_order_path(href, refused):
    """browser.read clicks with no approval card: a plain link to any
    order path (``READ_LINK_RE``) is left to browser.act, the order
    history aside."""
    target = _target(name="Get it now", sends=False, buttonish=False, action="", link=True, href=href,
                     plain_link=True)
    assert bool(markers.READ_LINK_RE.search(href)) is refused, href
    assert markers.read_click_allowed(target) is not refused, href


def test_an_order_path_may_carry_a_query_or_a_fragment():
    for path in ("/buy?id=1", "/pay#now", "/orders?page=2", "/subscribe?plan=pro", "/checkout/pay?x"):
        assert markers.ORDER_ACTION_RE.search(path), path
