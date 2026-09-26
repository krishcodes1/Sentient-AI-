"""What marks a card field, what marks a button that pays, and what marks
a page where an order is about to be placed: the one place every browser
toolkit reads them from (purchases spec §5, §6).

Why one place: the checkout fills the fields this classifier finds, the
outline redacts the values of the fields it finds, the screenshot mask
blacks out the fields it finds, and browser.act refuses to type into
them. Four copies of "what is a card field" drifted apart once (the
outline knew ``cc-*`` and a few names; the checkout knew "ccnum", "csc"
and "pan"), and a card typed into a field only the checkout recognised
reached the model. The hint patterns live here as Python regexes and
the page-side classifier is built from the same sources, so the two
cannot disagree.

Only ``re`` is imported: ``snapshot.py`` reads this module and must stay
free of Playwright and of the rest of the checkout package.

The purchase rules browser.act applies to a click, a submit or an Enter
(``pays``) judge the control that would send the form, never only the
element the model named: a submit through a plain field sends the form
through its default button, and Enter activates whatever has the focus.
Words alone are not enough either. A review page with a payment method
on file has no card field to protect and its button may say "Confirm",
so an order form's target path (``ORDER_ACTION_RE``) and a page that
shows an order total next to a saved payment method (``TOTAL_LABEL_RE``,
``SAVED_PAYMENT_RE``) refuse the act too. A page (or any frame of it) that
shows a payment method on file (a masked card, "ending in 4242", a wallet
button) next to any price refuses every sending act and every choice
(check, select) except a plain link; a link or a form aimed at an order
path is refused wherever it is (``pays``, ``change_pays``). The word lists
cover the main languages a shop is read in, not English alone.

A click is judged by the element it lands on, not only the one named: the
point Playwright clicks (the centre of the element's first box), followed
into open shadow roots, a <label> mapped to the control it activates. A
shadow tree nobody can read (a closed root) makes the page's facts unknown,
which counts as every fact shown. browser.read's click has no approval
card at all, so it follows only a plain link that is no order path (an
order history aside: ``READ_LINK_RE``), or clicks a control outside any
form, with no purchase words, on a page with no order total, payment
method on file or wallet (``read_click_allowed``); ``read_click_pays``
refuses first, as before.

These lists are defence in depth, not the guarantee: no word list or page
pattern can be shown to catch every way a click on an arbitrary shop page
places an order. What holds is that browser.act never runs without an
approval card that shows the owner a picture of the page, and that card
data is entered only by browser.checkout.
"""

from __future__ import annotations

import json
import re

# Field hints (name, id, placeholder, aria-label, aria-labelledby text,
# label text, the outline's accessible name), one pattern per card field.
NUMBER_RE = re.compile(r"card.?number|cardnumber|ccnumber|cc.?num|\bpan\b|number on card|card no\b", re.I)
CVC_RE = re.compile(
    r"\bcvc\b|\bcvv\b|\bcsc\b|\bcid\b|\bcvn\b|security.?code|card.?code|verification.?(?:value|code)|cc.?csc",
    re.I,
)
NAME_RE = re.compile(r"name.?on.?card|cardholder|card.?holder|holder.?name|cc.?name|name on the card", re.I)
MONTH_RE = re.compile(r"month|\bmm\b|exp.?m\b", re.I)
YEAR_RE = re.compile(r"year|\byy(?:yy)?\b|exp.?y\b", re.I)
EXP_RE = re.compile(r"\bexp(?:iry|iration|ires|[-_ ]?date)?\b|valid (?:thru|until|to)", re.I)
# A bare "Month" or "Year" field is a card field only next to a card:
# the checkout decides that from the form it found the number in, but
# the outline and the mask see one field at a time, so for them the hint
# must also say so ("MM / YY" in one field is an expiry on its own).
CARD_CONTEXT_RE = re.compile(r"card|\bcc\b|cc[-_]|exp|valid|pay", re.I)
# Inputs that never hold a card value.
SKIP_TYPES: frozenset[str] = frozenset(
    {"hidden", "checkbox", "radio", "submit", "button", "reset", "file", "image"}
)
# What a card field is called, in the autocomplete vocabulary: the same
# token a site would put on the field, so a field found by its label and
# a field found by its token read the same everywhere.
KIND_BY_TOKEN: dict[str, str] = {
    "cc-number": "number",
    "cc-csc": "cvc",
    "cc-exp": "exp",
    "cc-exp-month": "exp_month",
    "cc-exp-year": "exp_year",
    "cc-name": "name",
}
TOKEN_BY_KIND: dict[str, str] = {kind: token for token, kind in KIND_BY_TOKEN.items()}

# The name rule the outline, the page memory and browser.act apply to a
# field's accessible name alone (when the live facts are unknown, or a
# site labels a field without any attribute a script could read).
SECRET_NAME_RE = re.compile(
    r"(password|passcode|one[- ]time|verification code)"
    f"|{NUMBER_RE.pattern}|{CVC_RE.pattern}|{NAME_RE.pattern}|{EXP_RE.pattern}",
    re.I,
)

# The attribute the screenshot mask marks a classified field with, so one
# CSS selector covers fields found by label as well as by attribute.
MASK_ATTRIBUTE = "data-crawler-masked"
# Fields whose pixels never leave the machine: by attribute (cheap, and
# the fallback when a frame will not run the classifier) and by the mark
# the classifier leaves.
MASK_SELECTOR = (
    "input[type=password], input[autocomplete='one-time-code'], "
    "input[autocomplete^='cc-'], input[name*='card' i], input[name*='cvv' i], "
    f"input[name*='cvc' i], [{MASK_ATTRIBUTE}]"
)


def _js_regex(pattern: re.Pattern[str]) -> str:
    return f"new RegExp({json.dumps(pattern.pattern)}, 'i')"


# The page-side classifier: a function of one element returning
# ``password``, ``one-time-code``, a ``cc-*`` token, or null. Built from
# the Python patterns above (JavaScript reads the same syntax), so the
# checkout's ``field_kind`` and the outline's secret-field facts are one
# rule. Used as an evaluate script on one element, and inlined into the
# page-wide scripts below.
FIELD_KIND_FN = (
    r"""(el => {
  const tag = el.tagName ? el.tagName.toLowerCase() : '';
  if (!['input', 'select', 'textarea'].includes(tag) && !el.isContentEditable) return null;
  const type = (el.type || '').toLowerCase();
  if (type === 'password') return 'password';
  const ac = (el.getAttribute('autocomplete') || '').toLowerCase().trim();
  if (ac === 'one-time-code') return 'one-time-code';
  if (ac.startsWith('cc-')) return ac;
  if (SKIP.includes(type)) return null;
  const a = n => (el.getAttribute(n) || '');
  let label = '';
  try { label = el.labels && el.labels.length ? el.labels[0].innerText : ''; } catch (e) {}
  let byId = '';
  try {
    byId = a('aria-labelledby').split(/\s+/).filter(Boolean)
      .map(id => { const n = document.getElementById(id); return n ? n.textContent : ''; }).join(' ');
  } catch (e) {}
  const hint = [a('name'), a('id'), a('placeholder'), a('aria-label'), byId,
                a('data-elements-stable-field-name'), label]
    .join(' ').replace(/\s+/g, ' ').toLowerCase().slice(0, 300);
  if (NUMBER.test(hint)) return 'cc-number';
  if (CVC.test(hint)) return 'cc-csc';
  if (NAME.test(hint)) return 'cc-name';
  const month = MONTH.test(hint), year = YEAR.test(hint);
  if (month && year) return 'cc-exp';
  if (CONTEXT.test(hint)) {
    if (month) return 'cc-exp-month';
    if (year) return 'cc-exp-year';
  }
  if (EXP.test(hint)) return 'cc-exp';
  return null;
})"""
    .replace("SKIP", json.dumps(sorted(SKIP_TYPES)))
    .replace("NUMBER", _js_regex(NUMBER_RE))
    .replace("CVC", _js_regex(CVC_RE))
    .replace("NAME", _js_regex(NAME_RE))
    .replace("EXP", _js_regex(EXP_RE))
    .replace("CONTEXT", _js_regex(CARD_CONTEXT_RE))
    .replace("MONTH", _js_regex(MONTH_RE))
    .replace("YEAR", _js_regex(YEAR_RE))
)
# ``locator.evaluate(FIELD_KIND_JS)``: the classifier applied to one element.
FIELD_KIND_JS = f"el => {FIELD_KIND_FN}(el)"

# The control a form is sent through when no button is clicked (a submit
# from a field, Enter in a field): its first submit control in tree order,
# the browser's default button. ``form.elements`` is that order and holds a
# button tied to the form from outside it (``form=``), which
# ``form.querySelector`` would miss; browser.act sends a submit through the
# same button (``DEFAULT_BUTTON_FN``), so what is judged is what is sent.
_DEFAULT_BUTTON_SELECTOR = "button:not([type]), button[type=submit], input[type=submit], input[type=image]"
DEFAULT_BUTTON_FN = f"""(form => {{
  try {{ return [...form.elements].find(e => e.matches({json.dumps(_DEFAULT_BUTTON_SELECTOR)})) || null; }}
  catch (e) {{ return null; }}
}})"""
# The words a person or a screen reader reads on a control (its label
# too: a radio or a checkbox says what it does in its <label>).
_WORDS_FN = r"""(node => {
  if (!node) return '';
  const clean = s => (s || '').replace(/\s+/g, ' ').trim();
  let byId = '', labels = '';
  try {
    const root = node.getRootNode && node.getRootNode().getElementById ? node.getRootNode() : document;
    byId = (node.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
      .map(id => { const n = root.getElementById(id); return n ? n.textContent : ''; }).join(' ');
  } catch (e) {}
  try { labels = [...(node.labels || [])].map(l => l.innerText).join(' '); } catch (e) {}
  return [node.getAttribute('aria-label'), byId, labels, node.innerText, node.textContent, node.value,
          node.getAttribute('title'), node.getAttribute('alt'), node.getAttribute('name')]
    .map(clean).filter((v, i, all) => v && all.indexOf(v) === i).join(' | ').slice(0, 400);
})"""

# ``locator.evaluate(FIELD_FACTS_JS)``: what the page memory keeps about a
# field: its kind (the classifier) and the words on the default button of
# its form, so a submit through the field can be refused before the card.
FIELD_FACTS_JS = f"""
el => {{
  const form = el.form || el.closest('form');
  const button = form ? {DEFAULT_BUTTON_FN}(form) : null;
  return {{ kind: {FIELD_KIND_FN}(el), button: {_WORDS_FN}(button) }};
}}
"""

_FIELDS = "input, select, textarea, [contenteditable]"

# ``frame.evaluate(MARK_SECRET_FIELDS_JS)``: mark every classified field
# (and unmark anything that no longer is one) so ``MASK_SELECTOR`` finds
# it. Returns how many fields carry the mark.
MARK_SECRET_FIELDS_JS = f"""
() => {{
  const classify = {FIELD_KIND_FN};
  let marked = 0;
  for (const el of document.querySelectorAll({json.dumps(_FIELDS)})) {{
    if (classify(el)) {{ el.setAttribute({json.dumps(MASK_ATTRIBUTE)}, ''); marked++; }}
    else el.removeAttribute({json.dumps(MASK_ATTRIBUTE)});
  }}
  return marked;
}}
"""

# ``frame.evaluate(CLEAR_CARD_FIELDS_JS)``: empty every card field (the
# ``cc-*`` kinds; a password box is not the checkout's to clear) and tell
# the page so (input + change events, for a framework that mirrors the
# field into its own state). Returns how many card fields still hold a
# value afterwards, so the caller can verify the form is empty.
CLEAR_CARD_FIELDS_JS = f"""
() => {{
  const classify = {FIELD_KIND_FN};
  let left = 0;
  for (const el of document.querySelectorAll({json.dumps(_FIELDS)})) {{
    const kind = classify(el);
    if (!kind || !kind.startsWith('cc-')) continue;
    const filled = () => el.tagName.toLowerCase() === 'select'
      ? !!(el.value) : (el.isContentEditable ? !!el.textContent : !!el.value);
    if (!filled()) continue;
    try {{
      if (el.tagName.toLowerCase() === 'select') el.selectedIndex = -1;
      else if (el.isContentEditable) el.textContent = '';
      else el.value = '';
      el.dispatchEvent(new Event('input', {{ bubbles: true }}));
      el.dispatchEvent(new Event('change', {{ bubbles: true }}));
    }} catch (e) {{}}
    if (filled()) left++;
  }}
  return left;
}}
"""

# ``frame.evaluate(FILLED_CARD_FIELDS_JS)``: how many card fields hold a
# value right now (the verification after a clear, and browser.act's
# "is there a card in this form" check).
FILLED_CARD_FIELDS_JS = f"""
() => {{
  const classify = {FIELD_KIND_FN};
  let filled = 0;
  for (const el of document.querySelectorAll({json.dumps(_FIELDS)})) {{
    const kind = classify(el);
    if (kind && kind.startsWith('cc-') && (el.isContentEditable ? el.textContent : el.value)) filled++;
  }}
  return filled;
}}
"""


def field_kind(field: dict[str, str]) -> str | None:
    """Which card field an element is (``number``, ``cvc``, ``exp``,
    ``exp_month``, ``exp_year``, ``name``), by its autocomplete token
    first and its hints second; None for anything else. The checkout
    applies this to a field it already knows sits in a card form, so a
    bare "Month" or "Year" counts here where the page-side classifier
    (one field at a time) asks for card context too."""
    if field.get("type") in SKIP_TYPES:
        return None
    token = str(field.get("autocomplete") or "")
    if token in KIND_BY_TOKEN:
        return KIND_BY_TOKEN[token]
    hint = str(field.get("hint") or "")
    if NUMBER_RE.search(hint):
        return "number"
    if CVC_RE.search(hint):
        return "cvc"
    if NAME_RE.search(hint):
        return "name"
    month, year = bool(MONTH_RE.search(hint)), bool(YEAR_RE.search(hint))
    if month and year:
        return "exp"
    if month:
        return "exp_month"
    if year:
        return "exp_year"
    if EXP_RE.search(hint):
        return "exp"
    return None


# -- buttons that pay ---------------------------------------------------------

# What a control that moves money says. browser.act refuses to click,
# submit or press Enter on one of these whatever the purchases switch
# says: paying goes through browser.checkout and its card, or not at all.
# "Checkout" and "Proceed to checkout" are left out on purpose: on a cart
# page they lead to the checkout page (no money moves there), and the
# button that does move it is one of these. A shop is not always read in
# English: the main words of the other languages follow, and the words of
# scripts written without spaces (Japanese, Chinese, Korean, Hindi) match
# anywhere in a control's words, not only as a whole word.
PURCHASE_WORDS: tuple[str, ...] = (
    "place order", "place your order", "place my order", "place the order",
    "pay", "pay now", "pay securely",
    "buy", "buy now",
    "purchase", "purchase now",
    "complete order", "complete my order", "complete your order", "complete the order",
    "complete purchase", "complete payment", "complete booking", "complete checkout",
    "confirm order", "confirm purchase", "confirm payment", "confirm and pay", "confirm booking",
    "submit order", "submit payment",
    "order now", "book now",
    "subscribe", "subscribe now", "start subscription", "start membership",
    "start trial", "start free trial",
    "rent", "rent now", "donate", "donate now", "pre-order", "preorder", "reserve", "reserve now",
    "request to book", "place bid", "place a bid", "confirm bid", "upgrade", "upgrade now", "renew", "renew now",
    # German
    "kaufen", "jetzt kaufen", "bezahlen", "jetzt bezahlen", "bestellen", "jetzt bestellen",
    "zahlungspflichtig bestellen", "kostenpflichtig bestellen",
    # French
    "acheter", "payer", "commander", "passer la commande", "valider la commande",
    # Spanish and Portuguese
    "comprar", "pagar", "realizar pedido", "confirmar pedido", "finalizar compra", "finalizar pedido",
    # Italian
    "acquista", "paga", "ordina", "conferma ordine",
    # Dutch
    "kopen", "betalen", "bestelling plaatsen",
    # Russian
    "оплатить", "купить", "заказать", "оформить заказ", "подтвердить заказ", "подтвердить оплату",
    # Arabic
    "ادفع", "ادفع الآن", "اشتر", "اشتري", "اشتر الآن", "اشتري الآن", "شراء", "تأكيد الطلب", "إتمام الطلب",
    "إتمام الشراء",
    # Hebrew
    "לתשלום", "שלם", "שלם עכשיו", "קנה", "קנה עכשיו", "לרכישה", "בצע הזמנה", "אישור הזמנה", "אשר ושלם",
    # Turkish
    "satın al", "hemen al", "öde", "ödeme yap", "siparişi tamamla", "siparişi onayla", "sipariş ver",
    # Polish
    "kup", "kup teraz", "kupuję", "zapłać", "płacę", "zamawiam", "zamów", "złóż zamówienie",
    "potwierdzam zakup",
    # Swedish
    "köp", "köp nu", "betala", "slutför köp", "slutför köpet", "bekräfta köp", "slutför beställning",
    "lägg order",
    # Japanese, Chinese, Korean, Hindi
    "購入", "注文", "支払", "確定", "购买", "購買", "支付", "付款", "下单", "提交订单", "确认订单",
    "구매", "결제", "주문하기", "खरीदें", "भुगतान",
)


def _spaceless(word: str) -> bool:
    """A word of a script written without spaces between words (Devanagari
    and every script after it: Japanese, Chinese, Korean), which matches
    inside a longer phrase; every other word matches as a whole word."""
    return any(ord(ch) >= 0x0900 for ch in word)


PURCHASE_RE = re.compile(
    r"\b(?:"
    + "|".join(re.escape(w).replace(r"\ ", r"[\s-]*") for w in PURCHASE_WORDS if not _spaceless(w))
    + r")\b|"
    + "|".join(re.escape(w) for w in PURCHASE_WORDS if _spaceless(w)),
    re.I,
)
USE_CHECKOUT_MESSAGE = (
    "Crawler only pays through its own checkout step, which needs 'Buy things for me' on "
    "in Permissions."
)

# The label of the amount to pay ("Total", "Order total", "Amount due";
# never a subtotal, nor a total of something that is not money to pay).
# The checkout's facts pick the amount by it; browser.act asks whether
# such a line is on screen at all. "Total TTC", "Importe total" and
# "Totale" are read by the first branch.
TOTAL_LABEL_RE = re.compile(
    r"(?<!sub)(?<!sub )(?<!sub-)(?:(?:order|grand|cart|basket)\s+)?total"
    r"(?!\s*(?:savings?|discount|tax|shipping|items?|qty|quantity|weight|before))"
    r"|amount\s+due|you\s+pay|to\s+pay|balance\s+due|due\s+today"
    r"|gesamt(?:summe|betrag|preis)|zu\s+zahlen|totaal|razem|toplam|итого|к\s+оплате|الإجمالي|المجموع"
    r"|סה\"כ|סך\s+הכל|合計|合计|总计|總計|총액|합계|कुल",
    re.IGNORECASE,
)
# A price: a currency sign or code next to a digit. One pattern, read by
# Python and by the page scripts alike (both regex dialects accept it).
# The signs are every currency sign Unicode knows (its "Sc" category: $, €,
# ₽, ₪, ₹, ฿...); the codes are ISO 4217's, less the ones that are English
# words ("ALL 3", "TOP 10", "PEN 2"); the rest are the words shops write a
# price with (円, 元, 원, kr, zł, руб, ر.س...).
_CURRENCY_SIGNS = (
    r"[$¢-¥֏؋߾߿৲৳৻૱௹฿៛"
    r"₠-⃀꠸﷼﹩＄￠￡￥￦]"
)
_CURRENCY_CODES = (
    "AED|AFN|ANG|AOA|ARS|AUD|AWG|AZN|BBD|BDT|BGN|BHD|BIF|BMD|BND|BRL|BSD|BTN|BWP|BYN|BZD|CAD|CDF|CHF"
    "|CLP|CNY|COP|CRC|CVE|CZK|DJF|DKK|DOP|DZD|EGP|ERN|ETB|EUR|FJD|FKP|GBP|GHS|GIP|GMD|GNF|GTQ|GYD|HKD"
    "|HNL|HTG|HUF|IDR|ILS|INR|IQD|IRR|ISK|JMD|JOD|JPY|KES|KGS|KHR|KMF|KPW|KRW|KWD|KYD|KZT|LAK|LBP|LKR"
    "|LRD|LSL|LYD|MDL|MGA|MKD|MMK|MNT|MRU|MUR|MVR|MWK|MXN|MYR|MZN|NAD|NGN|NIO|NOK|NPR|NZD|OMR|PAB|PGK"
    "|PHP|PKR|PLN|PYG|QAR|RON|RSD|RUB|RWF|SAR|SBD|SCR|SDG|SEK|SGD|SHP|SLE|SLL|SRD|SSP|STN|SVC|SYP|SZL"
    "|THB|TJS|TMT|TND|TRY|TTD|TWD|TZS|UAH|UGX|USD|UYU|UZS|VES|VND|VUV|WST|XAF|XCD|XOF|XPF|YER|ZAR|ZMW"
    "|ZWL"
)
MONEY_PATTERN = (
    rf"(?:US\$|CA\$|AU\$|NZ\$|MX\$|HK\$|R\$|C\$|A\$|S\$|{_CURRENCY_SIGNS}"
    rf"|(?<![A-Za-z])(?:{_CURRENCY_CODES}|RM|Rs\.?|Rp|kr)(?![A-Za-z]))\s?\d"
    rf"|\d\s?(?:{_CURRENCY_SIGNS}|(?<![A-Za-z])(?:{_CURRENCY_CODES}|kr|zł|Kč|lei)(?![A-Za-z])"
    r"|円|元|원|руб|грн|ر\.س|د\.إ|ريال|درهم)"
)
MONEY_RE = re.compile(MONEY_PATTERN, re.IGNORECASE)
# The path of a step that places an order when it is merely opened
# (/place-order, /confirm_order, /checkout/complete): a GET to one can be
# the order itself. browser.read never opens one, by any route, outside
# an approved act; a page's own request to one is stopped there too. A
# query or fragment may follow (/checkout/complete?sku=1).
ORDER_STEP_RE = re.compile(
    r"(?:place|submit|confirm|complete|finish)[-_]?order"
    r"|/checkout/(?:complete|confirm|submit|place|finish)(?=[/?#;]|$)",
    re.IGNORECASE,
)
# The path an order form posts to says what it does whatever its button
# says: the steps above, and /orders, /pay, /purchase, /checkout/pay...
# (a query or a fragment may follow: /buy?id=1). A link or a form aimed
# at one is refused by browser.act whatever its words or method, and a
# page's own request to one is stopped outside an approved order (the
# guard).
_END = r"(?=[/?#;]|$)"
_ORDER_PATHS = (
    rf"|/pay(?:ment)?{_END}|/purchase|/buy{_END}|/checkout/pay{_END}|/subscribe{_END}"
)
ORDER_ACTION_RE = re.compile(
    ORDER_STEP_RE.pattern + rf"|/orders?{_END}" + _ORDER_PATHS,
    re.IGNORECASE,
)
# What browser.read, which clicks with no approval card, never follows a
# link to: every order path above except an order history (/orders, or
# one past order by its number, /orders/8841), which is opened by GET to
# be read. /buy/1 and /orders/8841/reorder are not read.
READ_LINK_RE = re.compile(
    ORDER_STEP_RE.pattern
    + rf"|/order{_END}"
    + rf"|/orders(?!/?(?:[?#;]|$)|/[a-z0-9-]*\d[a-z0-9-]*/?(?:[?#;]|$)){_END}"
    + _ORDER_PATHS,
    re.IGNORECASE,
)
# Words that put a thing in a cart, where a price on the button is the
# price of the thing and nothing is paid yet ("Add to cart - $19.00").
_ADD_TO_CART_RE = re.compile(
    r"\badd(?:\s+it)?\s+to\s+(?:cart|bag|basket|trolley)\b|in\s+den\s+warenkorb|ajouter\s+au\s+panier"
    r"|añadir\s+al\s+carrito|aggiungi\s+al\s+carrello|カートに入れる|加入购物车",
    re.IGNORECASE,
)
_LETTERS_RE = re.compile(r"[^\W\d_]+")
# How a page says it already holds a way to pay: "the card on file",
# "your default card", "ending in 4242", "•••• 4242", "Visa ...4242",
# "Payment method: Visa". Brand names on
# their own do not count (a cart page lists the cards it accepts). A
# masked number reads the same in every language; "ending in" and
# "Payment method:" are listed in the main ones.
SAVED_PAYMENT_RE = re.compile(
    r"(?:card|payment(?: method)?|paying|pay|charged?|billed?)\s+(?:on file|saved|stored)"
    r"|(?:saved|stored|default|primary|preferred)\s+(?:card|payment)"
    r"|(?<!\d)(?:\.{2,}|…)\d{4}(?!\d)"
    r"|(?:ending(?: in)?|ends in|last\s+(?:four|4)(?:\s+digits)?|endet auf|endend (?:auf|mit)"
    r"|se terminant par|finissant par|terminad[ao] en|que termina en|che termina con|terminante (?:in|con)"
    r"|terminado em|eindigend op|末尾|尾号|尾號|끝자리)\s*:?\s*[*•xX]*\s?\d{4}"
    r"|(?:\*{3,}|[•·●∙]{3,}|[xX]{4})[\s-]?\d{4}"
    r"|(?:payment(?: method)?|zahlungsart|zahlungsmethode|moyen de paiement|m[ée]todo de pago"
    r"|metodo di pagamento|forma de pagamento|betaalmethode)\s*:\s*(?:visa|mastercard|master card|amex"
    r"|american express|discover|paypal|apple pay|google pay|shop pay)",
    re.IGNORECASE,
)
# A wallet button (Apple Pay, Google Pay, PayPal, Shop Pay) pays with what
# the wallet holds: on a button, a wallet's own element or a wallet's
# frame, it counts as a payment method on file.
WALLET_RE = re.compile(r"apple\s*pay|google\s*pay|\bg\s?pay\b|paypal|shop\s*pay|amazon\s*pay", re.IGNORECASE)

# A form "holds a card" when a number or a security code has been typed
# into it: an expiry dropdown always has a selected option and says
# nothing on its own.
_CARD_IN_FORM_FN = f"""(form => {{
  const classify = {FIELD_KIND_FN};
  try {{
    return !!(form && [...form.elements].some(f => {{
      const k = classify(f);
      return (k === 'cc-number' || k === 'cc-csc') && f.tagName.toLowerCase() !== 'select' && !!f.value;
    }}));
  }} catch (e) {{ return false; }}
}})"""

# A shadow host whose tree cannot be read (a closed root: ``shadowRoot``
# is null, and neither the text nor the focus inside it can be seen): a
# custom element with no children or text of its own that still takes up
# room on screen. What it shows is unknown.
_CLOSED_HOST_FN = r"""(node => {
  try {
    if (!node || node.nodeType !== 1 || node.shadowRoot || !node.tagName.includes('-')) return false;
    if (node.childElementCount || (node.textContent || '').trim()) return false;
    const r = node.getBoundingClientRect();
    return r.width > 1 && r.height > 1;
  } catch (e) { return true; }
})"""

# What one document shows (its open shadow roots included): an order
# total on screen (``order_total``; a total whose amount is a picture
# counts), a payment method it already holds in words (``saved_payment``)
# or as a wallet button (``wallet``), and any price at all (``money``). A
# fact that cannot be read counts as shown, and so does every fact of a
# document holding a shadow tree nobody can read (``unread`` says so).
# ``total_line`` is the on-screen total's own text ("Order total: $499.00"),
# which browser.act's approval card quotes the amount from.
_PAGE_FACTS_FN = (
    r"""(() => {
  const clean = s => (s || '').replace(/\s+/g, ' ').trim();
  const TOTAL = __TOTAL__, MONEY = __MONEY__, SAVED = __SAVED__, WALLET = __WALLET__;
  const closed = __CLOSED__;
  const unknown = { order_total: true, saved_payment: true, wallet: true, money: true, unread: true };
  const roots = [document];
  let text = '';
  try {
    for (let i = 0; i < roots.length && roots.length < 200; i++) {
      for (const el of roots[i].querySelectorAll('*')) {
        if (el.shadowRoot) roots.push(el.shadowRoot);
        else if (closed(el)) return unknown;
      }
    }
    text = document.body ? document.body.innerText : '';
    for (const root of roots.slice(1)) for (const child of root.children) text += ' ' + (child.innerText || '');
    text = clean(text);
  } catch (e) { return unknown; }
  let orderTotal = false, totalLine = '';
  try {
    const vw = window.innerWidth, vh = window.innerHeight;
    search: for (const root of roots) {
      for (const el of root.querySelectorAll(
          'p, div, span, td, th, li, dt, dd, strong, b, em, h1, h2, h3, h4, h5, h6, label, tr, output, summary, section')) {
        const line = clean(el.innerText);
        if (!line || line.length > 160 || !TOTAL.test(line)) continue;
        if (!MONEY.test(line) && (/\d/.test(line) || !el.querySelector('img, svg, canvas, picture, object, embed'))) {
          continue;
        }
        const r = el.getBoundingClientRect();
        if (r.width > 1 && r.height > 1 && r.bottom > 0 && r.right > 0 && r.top < vh && r.left < vw) {
          orderTotal = true; totalLine = line; break search;
        }
      }
    }
  } catch (e) { orderTotal = true; }
  let wallet = false;
  try {
    search: for (const root of roots) {
      for (const el of root.querySelectorAll(
          'button, [role=button], input[type=button], input[type=submit], input[type=image], '
          + 'apple-pay-button, gpay-button, iframe')) {
        const tag = el.tagName.toLowerCase();
        if (tag === 'apple-pay-button' || tag === 'gpay-button') { wallet = true; break search; }
        const words = [el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('alt'),
                       el.getAttribute('name'), tag === 'iframe' ? el.getAttribute('src') : (el.innerText || el.value)]
          .map(clean).join(' ');
        if (WALLET.test(words)) { wallet = true; break search; }
      }
    }
  } catch (e) { wallet = true; }
  return { order_total: orderTotal, saved_payment: SAVED.test(text), wallet, money: MONEY.test(text),
           total_line: totalLine };
})"""
    .replace("__TOTAL__", _js_regex(TOTAL_LABEL_RE))
    .replace("__MONEY__", f"new RegExp({json.dumps(MONEY_PATTERN)}, 'i')")
    .replace("__SAVED__", _js_regex(SAVED_PAYMENT_RE))
    .replace("__WALLET__", _js_regex(WALLET_RE))
    .replace("__CLOSED__", _CLOSED_HOST_FN)
)
# ``frame.evaluate(PAGE_FACTS_JS)``: those facts for one frame; browser.act
# asks every frame of the page and joins the answers (``join_page``).
PAGE_FACTS_JS = f"() => {_PAGE_FACTS_FN}()"
PAGE_FACT_KEYS: tuple[str, ...] = ("order_total", "saved_payment", "wallet", "money")

# What a click, a submit or an Enter would do, as ``pays`` judges it: the
# words on the control that sends the form (``name``), whether that form
# holds a card right now, whether the act sends a POST form (``sends``)
# and where to (``action``: the path of the button's ``formaction`` or
# the form's ``action``), whether the target is a button of any kind
# (``buttonish``: a script may send an order from one, and an element
# with a click handler or a pointer cursor is one whatever its tag),
# whether it is a link (``link``, its ``href`` path and query, and
# ``plain_link``: an http(s) link to another page with no script of its
# own), whether it sits in a form at all (``in_form``), and what the page
# shows (the facts above). ``control`` is the
# element whose activation sends the form, or null when the form is sent
# with no button (a submit through a field, an implicit submission).
_JUDGE_FN = f"""((control, form) => {{
  const cardIn = {_CARD_IN_FORM_FN};
  const words = {_WORDS_FN};
  const tag = control ? control.tagName.toLowerCase() : '';
  const type = control ? (control.getAttribute('type') || '').toLowerCase() : '';
  const role = control ? (control.getAttribute('role') || '').toLowerCase() : '';
  const submitControl = (tag === 'button' && (type === '' || type === 'submit'))
    || (tag === 'input' && (type === 'submit' || type === 'image'));
  const link = !!control && (tag === 'a' || tag === 'area') && control.hasAttribute('href');
  let clickable = false;
  if (control && !link && !submitControl) {{
    try {{
      clickable = control.hasAttribute('onclick') || control.hasAttribute('tabindex')
        || window.getComputedStyle(control).cursor === 'pointer';
    }} catch (e) {{ clickable = true; }}
  }}
  const buttonish = submitControl || tag === 'button' || role === 'button' || clickable
    || (tag === 'input' && (type === 'button' || type === 'reset'));
  const sentForm = control ? (submitControl ? control.form : null) : form;
  const method = ((submitControl && control.getAttribute('formmethod'))
    || (sentForm && sentForm.getAttribute('method')) || 'get').toLowerCase();
  let action = '';
  if (sentForm) {{
    const raw = submitControl && control.hasAttribute('formaction')
      ? control.getAttribute('formaction') : sentForm.getAttribute('action');
    try {{ action = new URL(raw || '', document.baseURI).pathname; }} catch (e) {{ action = ''; }}
  }}
  let href = '', plainLink = false;
  if (link) {{
    try {{
      const to = new URL(control.getAttribute('href') || '', document.baseURI);
      const here = new URL(document.location.href);
      href = to.pathname + to.search;
      const samePage = to.origin === here.origin && to.pathname === here.pathname && to.search === here.search;
      plainLink = (to.protocol === 'https:' || to.protocol === 'http:') && !samePage && !role
        && !control.hasAttribute('onclick') && !control.hasAttribute('download');
    }} catch (e) {{ href = '?'; plainLink = false; }}
  }}
  const page = {_PAGE_FACTS_FN}();
  const holder = sentForm || form || (control ? (control.form || control.closest('form')) : null);
  return {{
    name: words(control),
    card_in_form: cardIn(holder),
    in_form: !!holder,
    sends: !!(sentForm && method === 'post'),
    buttonish,
    action,
    link,
    href,
    plain_link: plainLink,
    order_total: page.order_total,
    saved_payment: page.saved_payment,
    wallet: page.wallet,
    money: page.money,
  }};
}})"""

# The element a click lands on acts through the button or link around it
# (a <span> inside <a href="/place-order">), and a <label> through the
# control it is for: that is what is judged.
_ACTIVATED_FN = """(el => {
  let node = el;
  try {
    const label = node.closest ? node.closest('label') : null;
    if (label && label.control) node = label.control;
  } catch (e) {}
  return (node.closest && node.closest(
    "a[href], area[href], button, input[type=submit], input[type=image], input[type=button], [role=button]"
  )) || node;
})"""
# Where a click on the element lands: the point Playwright clicks (the
# centre of the element's first box on screen, scrolled into view first
# when none is), followed into open shadow roots. Playwright clicks only
# when that point is on the element or inside it; anything else answers
# the element itself, or null when the element holds a control of its own
# (the click may reach that control later). A shadow host that cannot be
# read answers null too: the caller refuses.
_HIT_FN = f"""(el => {{
  const closed = {_CLOSED_HOST_FN};
  const within = node => {{
    for (let n = node; n; n = n.parentNode || n.host) if (n === el) return true;
    return false;
  }};
  const boxes = () => [...el.getClientRects()].map(r => ({{
      left: Math.max(r.left, 0), top: Math.max(r.top, 0),
      right: Math.min(r.right, window.innerWidth), bottom: Math.min(r.bottom, window.innerHeight) }}))
    .filter(r => (r.right - r.left) * (r.bottom - r.top) > 0.99);
  let hit = null;
  try {{
    let shown = boxes();
    if (!shown.length) {{ el.scrollIntoView({{ block: 'center', inline: 'center' }}); shown = boxes(); }}
    if (shown.length) {{
      const x = (shown[0].left + shown[0].right) / 2, y = (shown[0].top + shown[0].bottom) / 2;
      hit = document.elementFromPoint(x, y);
      while (hit && hit.shadowRoot) {{
        const inner = hit.shadowRoot.elementFromPoint(x, y);
        if (!inner || inner === hit) break;
        hit = inner;
      }}
    }}
  }} catch (e) {{ hit = null; }}
  if (hit && within(hit)) return closed(hit) ? null : hit;
  const inside = el.querySelector && el.querySelector(
    'a[href], area[href], button, input, select, textarea, label, [role=button], [onclick], [tabindex]');
  return inside || closed(el) ? null : el;
}})"""
# ``locator.evaluate(PURCHASE_TARGET_JS)``: what a click on the element
# does, judged by the control the click reaches; null when that cannot be
# known.
PURCHASE_TARGET_JS = f"""
el => {{
  const hit = {_HIT_FN}(el);
  if (!hit) return null;
  const control = {_ACTIVATED_FN}(hit);
  return {_JUDGE_FN}(control, control.form || control.closest('form'));
}}
"""
# ``locator.evaluate(SUBMIT_TARGET_JS)``: what ``browser.act submit`` on
# the element does. A submit control sends its form as itself; anything
# else (a field) sends its form through the form's default button, or
# with no button at all when the form has none.
SUBMIT_TARGET_JS = f"""
el => {{
  const judge = {_JUDGE_FN};
  const form = el.form || el.closest('form');
  if (!form) return judge(el, null);
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const submitControl = ((tag === 'button' && (type === '' || type === 'submit'))
    || (tag === 'input' && (type === 'submit' || type === 'image'))) && el.form === form;
  if (submitControl) return judge(el, form);
  return judge({DEFAULT_BUTTON_FN}(form), form);
}}
"""
# The element that has the keyboard focus, through open shadow roots
# (``document.activeElement`` stops at the shadow host).
_FOCUSED_FN = """(() => {
  let el = document.activeElement;
  while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
  return el;
})"""
# ``frame.evaluate_handle(FOCUSED_JS)``: that element, so a focused frame
# can be entered (``content_frame``) and asked again.
FOCUSED_JS = f"() => {_FOCUSED_FN}()"
# ``frame.evaluate(ENTER_TARGET_JS)``: what pressing Enter does. In a field
# (an input, a text area, a select, an editable element) Enter sends the
# field's form through its default button (or with none: an implicit
# submission); on anything else that holds the focus (a button, a link, a
# <div tabindex> with a key handler) it activates that element, which is
# judged by its own words, its form and its link. When the focus is in a
# frame the answer is ``{frame: true}``: the caller asks that frame the
# same question. A focus nobody can see (inside a shadow tree that cannot
# be read: the element holding it cannot hold a focus itself) answers
# null, and the caller refuses.
ENTER_TARGET_JS = f"""
() => {{
  const judge = {_JUDGE_FN};
  const closed = {_CLOSED_HOST_FN};
  const el = {_FOCUSED_FN}();
  if (!el || el === document.body || el === document.documentElement) return judge(null, null);
  const tag = el.tagName.toLowerCase();
  if (tag === 'iframe' || tag === 'frame') return {{ frame: true }};
  let focusable = false;
  try {{
    focusable = el.tabIndex >= 0 || el.isContentEditable
      || el.matches('a[href], area[href], button, input, select, textarea, summary, [tabindex]');
  }} catch (e) {{ focusable = false; }}
  if (!focusable || closed(el)) return null;
  const type = (el.getAttribute('type') || '').toLowerCase();
  const form = el.form || el.closest('form');
  const field = (tag === 'input' && !['submit', 'image', 'button', 'reset'].includes(type))
    || tag === 'textarea' || tag === 'select' || el.isContentEditable;
  if (!field) return judge(el, form);
  if (!form) return judge(null, null);
  return judge({DEFAULT_BUTTON_FN}(form), form);
}}
"""
# ``locator.evaluate(CHANGE_TARGET_JS, value)``: what a check or a select
# chooses, as ``change_pays`` judges it: the control's own words (its
# label, never the options it does not choose) with the chosen option's
# (for a select) or the box's value, and what the page shows.
CHANGE_TARGET_JS = f"""
(el, value) => {{
  const clean = s => (s || '').replace(/\\s+/g, ' ').trim();
  const labelText = label => {{
    const copy = label.cloneNode(true);
    copy.querySelectorAll('input, select, textarea, button').forEach(n => n.remove());
    return copy.textContent || '';
  }};
  const parts = [el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('name')];
  try {{ for (const label of el.labels || []) parts.push(labelText(label)); }} catch (e) {{}}
  try {{
    const root = el.getRootNode && el.getRootNode().getElementById ? el.getRootNode() : document;
    for (const id of (el.getAttribute('aria-labelledby') || '').split(/\\s+/).filter(Boolean)) {{
      const n = root.getElementById(id);
      if (n) parts.push(n.textContent);
    }}
  }} catch (e) {{}}
  if (el.tagName.toLowerCase() === 'select') {{
    const want = clean(String(value || ''));
    const chosen = [...el.options].find(o => o.value === String(value || '') || clean(o.label) === want
      || clean(o.text) === want);
    if (chosen) parts.push(chosen.text, chosen.value);
  }} else {{
    parts.push(el.getAttribute('value'));
  }}
  return {{ name: parts.map(clean).filter(Boolean).join(' | ').slice(0, 400), ...{_PAGE_FACTS_FN}() }};
}}
"""


def join_page(target: object, pages: list[object]) -> object:
    """*target* (a script's answer about one element, in its own frame)
    with the facts every frame of the page shows (``PAGE_FACTS_JS``
    answers) joined in: a review page's total and saved card count for a
    button inside its frame, and a frame's for the page around it. An
    answer that is not the scripts' shape counts as every fact shown."""
    if not isinstance(target, dict):
        return target
    joined = dict(target)
    for page in pages:
        facts = page if isinstance(page, dict) else {}
        for key in PAGE_FACT_KEYS:
            joined[key] = bool(joined.get(key)) or bool(facts.get(key, True))
    return joined


def holds_payment(target: dict[str, object]) -> bool:
    """The page shows a payment method on file (in words, masked, or as a
    wallet button) and a price: whatever is clicked or chosen there may
    be the order being placed, in any language."""
    return bool((target.get("saved_payment") or target.get("wallet")) and target.get("money"))


def priced_control(name: str) -> bool:
    """A control that is little more than a price ("$0.99", "Rent HD
    $3.99", "Get - 4,99 €"): the one-click purchase of an app store or a
    video shop. A price on a button that puts a thing in a cart ("Add to
    cart - $19.00") is the thing's price, and a longer caption ("Main cabin
    $612 Select") is read by its words instead."""
    for part in name.split(" | "):
        if MONEY_RE.search(part) and not _ADD_TO_CART_RE.search(part):
            words = [w for w in _LETTERS_RE.findall(part) if not MONEY_RE.search(f"{w} 1")]
            if len(words) <= 2:
                return True
    return False


def pays(target: object, *, order_links: re.Pattern[str] = ORDER_ACTION_RE) -> bool:
    """Whether the act the scripts above described would place an order:
    the sending control's words are a purchase, or little more than a
    price; its form holds a typed card; it sends a form, or is a link,
    aimed at an order path (*order_links* for a link); it is anything but a
    plain link on a page that holds a payment method next to a price; or
    it is a button, or sends a form, on a page that shows an order total
    and a payment method on file. Anything that is not the scripts' answer
    (a focus in a frame nobody asked, a click whose landing cannot be
    known) fails closed."""
    if not isinstance(target, dict) or target.get("frame"):
        return True
    name = str(target.get("name") or "")
    if PURCHASE_RE.search(name):
        return True
    if target.get("card_in_form"):
        return True
    if ORDER_ACTION_RE.search(str(target.get("action") or "")):
        return True
    if target.get("link") and order_links.search(str(target.get("href") or "")):
        return True
    sends = bool(target.get("sends"))
    if (sends or target.get("buttonish")) and not target.get("link") and priced_control(name):
        return True
    if holds_payment(target) and not target.get("plain_link"):
        return True
    return bool(
        (sends or target.get("buttonish")) and target.get("order_total") and target.get("saved_payment")
    )


def read_click_pays(target: object) -> bool:
    """Whether browser.read, which clicks with no approval card, must leave
    this click to browser.act: whatever ``pays`` refuses (a link when it
    is aimed at an order path other than an order history,
    ``READ_LINK_RE``: /orders is read, /buy/1 is not), and any button (not
    a link) on a page that shows a price next to an order total or a
    payment method, where a script behind a button with any words may
    place the order."""
    if pays(target, order_links=READ_LINK_RE) or not isinstance(target, dict):
        return True
    return bool(
        target.get("buttonish")
        and not target.get("link")
        and target.get("money")
        and (target.get("order_total") or target.get("saved_payment") or target.get("wallet"))
    )


# What browser.read answers a click it will not make: acting is the
# owner's other switch, and every act shows the owner the page first.
READ_CLICK_MESSAGE = (
    "Reading can't click that. Ask to fill in forms and click (needs 'Fill in forms and "
    "click on sites' in Permissions)."
)


def read_click_allowed(target: object) -> bool:
    """Whether browser.read, which clicks with no approval card and so with
    no picture of the page in front of the owner, may make this click. Only
    two kinds are, whatever the heuristics would say of the rest:

    - following a plain link (``plain_link``: an http(s) ``<a href>`` to
      another page, opened by GET, with no script or role of its own) whose
      address is no order path but an order history (``READ_LINK_RE``);
    - a control outside any form, whose words are no purchase and not a
      bare price, on a page (every frame of it) that shows no order total,
      no payment method on file and no wallet button: "Show more", a tab,
      a menu.

    Everything else is left to browser.act, whose approval card shows the
    owner the page. ``read_click_pays`` is asked first all the same, as
    defence in depth; an answer that is not the scripts' shape is refused."""
    if not isinstance(target, dict) or target.get("frame"):
        return False
    if read_click_pays(target):
        return False
    if target.get("link") and READ_LINK_RE.search(str(target.get("href") or "")):
        return False
    if target.get("plain_link"):
        return True
    if target.get("in_form") or target.get("sends") or target.get("card_in_form"):
        return False
    name = str(target.get("name") or "")
    if PURCHASE_RE.search(name) or priced_control(name):
        return False
    return not (target.get("order_total") or target.get("saved_payment") or target.get("wallet"))


def change_pays(target: object) -> bool:
    """Whether a check or a select (``CHANGE_TARGET_JS``) may be the order
    being placed: the choice's words are a purchase ("Pay with the card on
    file"), or the page holds a payment method next to a price. What the
    form's own button would do is not asked: a choice sends nothing, and
    the network guard stops a page that sends its form on a change."""
    if not isinstance(target, dict):
        return True
    return bool(PURCHASE_RE.search(str(target.get("name") or ""))) or holds_payment(target)
