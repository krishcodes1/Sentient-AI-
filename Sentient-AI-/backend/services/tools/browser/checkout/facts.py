"""What a checkout page says, read by the toolkit and never by the model
(purchases spec §6): the origin and scheme, the order total, the item
lines, the card fields, the order button and where it would send the
form, plus a digest of the page outline that ties the approval card to
this page (the page memory's structure digest, the one browser.act's
card is tied to). A page with no card fields may pay with what the shop
keeps on file (Amazon's "Place your order" page): then the facts say
whether the page names a saved payment method, the one card it names in
a strict shape within one line of text ("Visa ending in 4242" or
"Paying with Visa 4242" read as "Visa ····4242"; no other page text is
kept), and its order button, which must be the only button in the page
itself (the page script says which frame is the main one, never a ref's
prefix) whose words place the order, with no other control that may
place one: no button or link in any frame named like one ("Pay $23.40",
"Buy now", "Complete payment", a "Place your order" link; never "Change
payment method", "Pay with a gift card" or an "Order details" link), and
no other submit button of a POST form in the page that sends it
somewhere else, whatever it says ("Continue"). Those are counted, never
pressed; the same button repeated in one form, to one target, counts
once, and every control named like one is read, however many buttons
come first. The method and the card are read only from text painted on
screen, outside links, buttons and form controls' labels, near the order
total or the order button, and never from words that say there is none
(before it, or right after it: "Card on file: none", "has expired") or
offer to keep one, so a sign-in link, a promo line, "no saved cards" or
"Keep this card on file" does not make a page pay on file. Text whose
look Crawler cannot judge (a colour not in rgb(), a background image, a
filter, a blend mode, an inset shadow, a mask, a transform, scale or
rotate that does more than move it) does not count either, and every box around it fades its ink by
its opacity before the contrast is judged. The limit: anything painted
over the text that hit testing does not see (an overlay that lets clicks
through, a sibling's box, the element's own ``::before`` or ``::after``,
an outline, a text decoration) is not seen, and only the person's look
at the screenshot on the card catches it. A card number or code field
Crawler does not fill, in the page or any frame, or more fields than
Crawler reads (``stray_card_fields``), means the page may ask for a
card, and it is refused instead.

Why the toolkit reads these itself: the amount on the card and the fields
the vault fills into must come from the page as it is, not from the
model's description of it (which page content can shape). ``collect_
checkout_facts`` is the only function that touches the browser;
``classify_facts`` is pure, so every refusal rule is tested with a
dataclass. Refs are the aria refs of the latest snapshot, the same
tokens ``browser.read`` shows, and are valid until the next snapshot of
any kind.

A total counts only where the owner can see it on the approval
screenshot: inside the viewport, not clipped, not covered. Text a page
hides off-screen, or a seller's note further down, cannot set the
amount; when the visible totals disagree the checkout is refused rather
than guessed at, and the caps are checked against the largest. The
order button is taken from the card fields' own ``<form>`` (never one
attached from outside through ``form=``), and its effective target
(``formaction`` or the form's ``action``) must be an https POST to the
page's own origin, or to the payment frame's, before a card is filled
or the order button is pressed.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Optional, Sequence
from urllib.parse import urlsplit

import structlog

from services.tools.browser import snapshot as snap
from services.tools.browser.checkout import markers
from services.tools.browser.checkout.amounts import Money, fmt_usd, parse_money, usd
from services.tools.browser.checkout.merchant import merchant_refusal
from services.tools.browser.pagememory import outline_digest

logger = structlog.get_logger(__name__)

# Payment providers whose hosted card frames are trusted to carry the card
# fields; any other cross-origin frame with card fields is not filled.
PAYMENT_FRAME_HOSTS: tuple[str, ...] = (
    "js.stripe.com",
    "checkout.stripe.com",
    "pay.google.com",
    "www.paypal.com",
    "assets.braintreegateway.com",
    "checkoutshopper-live.adyen.com",
)
FACTS_TIMEOUT_S = 8.0
REF_TIMEOUT_MS = 3_000
MAX_ITEMS = 10
MAX_TOTALS_SEEN = 10
# How many fields and buttons are asked about. A page with more fields
# than this and no card fields is never paid with the card on file (the
# rest could ask for a card); every button or link named like one that
# may place an order is asked about on top of the first ``_MAX_BUTTONS``,
# up to ``_MAX_ORDER_BUTTONS``, and more of them than that is ambiguous.
_MAX_FIELDS = 40
_MAX_BUTTONS = 40
_MAX_ORDER_BUTTONS = 10
_ITEM_CHARS = 120
_TOTAL_CHARS = 160

# The label of the amount to pay; "subtotal" never, nor a total of
# something that is not money to pay (items, savings, tax lines, a total
# "before" something). Held by ``markers`` so browser.act asks the same
# question of a page.
_TOTAL_LABEL_RE = markers.TOTAL_LABEL_RE
# Rows that are a total line or an order summary row (Amazon's "Items:",
# "Shipping & handling:", "Estimated tax"), not an item. The summary words
# count only at the start of the row: an item row that ends in "FREE
# Shipping" is still an item.
_ITEM_EXCLUDE_RE = re.compile(
    r"sub\s*-?\s*total|\btotal\b|amount\s+due|you\s+pay|to\s+pay|balance\s+due"
    r"|^\s*(?:items?\s*(?:\(\d+\)\s*)?:|shipping|handling|(?:estimated\s+)?tax\b"
    r"|promotion|discount)",
    re.IGNORECASE,
)
_PAY_BUTTON_RE = re.compile(
    r"\b(?:place (?:your |the |my )?order|pay(?:ment)?(?: now| securely)?|buy(?: now)?"
    r"|purchase(?: now)?|complete (?:my |your |the )?(?:order|purchase|payment|booking)"
    r"|confirm (?:and pay|order|purchase|payment|booking)|submit (?:order|payment)"
    r"|order now|book now|check ?out)\b",
    re.IGNORECASE,
)
# On a page with no card fields, the words of a button that places the
# order. Narrower than ``_PAY_BUTTON_RE`` because it counts buttons: a
# "Change payment method" or "Checkout" button must not make a second one.
_ORDER_BUTTON_RE = re.compile(
    r"\b(?:place (?:your |the |my )?order|complete (?:my |your |the )?(?:order|purchase)"
    r"|confirm (?:and pay|(?:your |the |my )?(?:order|purchase))|submit (?:your |the )?order"
    r"|(?:buy|pay|order) now)\b",
    re.IGNORECASE,
)
# On a page with no card fields, the words of a link or button that might
# place an order without being named like an order button: only the verb,
# optionally "now" and an amount ("Pay $23.40", "Buy", "Checkout"; never
# "Order summary" or "Pay in 4 interest-free payments"). A button in pay
# words (``_PAY_BUTTON_RE``: "Complete payment", "Confirm & pay") is one
# too, unless it changes, adds or picks a way to pay (``_PAY_CHOICE_RE``).
# Such a control is never pressed, only counted, so the one order button
# is not an upsell's while the real one is named in other words or is a
# link; the real one in plain words in a POST form is counted by its
# form's target instead (``_order_button``).
_RIVAL_RE = re.compile(
    r"^\s*(?:pay|buy|purchase|order|check\s?out)(?:\s+now)?(?:\s+(?:US)?\$?[\d.,]+)?\s*$",
    re.IGNORECASE,
)
_PAY_CHOICE_RE = re.compile(
    r"^\s*(?:change|edit|add|use|select|manage|update|remove|pay\s+(?:with|using)\s+an?)\b",
    re.IGNORECASE,
)
_NETWORK = r"visa|mastercard|american\s+express|amex|discover|jcb|diners(?:\s+club)?|unionpay"
_PAYING_WITH = rf"\b(?:paying|pay)\s+with\s+({_NETWORK})\s+(\d{{4}})(?!\d)"
_ENDING_IN = rf"\b({_NETWORK})\s*(?:ending\s+in|[·•]{{2,}})\s*(\d{{4}})(?!\d)"
# The one card a page says it will charge, in a strict shape: a card
# network, then "ending in" or a dotted mask, then exactly four digits;
# or, only right after "paying with" or "pay with", a network then four
# digits that end the phrase ("Paying with Visa 1234", never "Pay with
# Visa 2026 rewards"). Read within one text node, so a street number on
# the next line never joins it. Only the network (spelled as below) and
# the digits reach the approval card, so no other page text can.
_SAVED_CARD_RE = re.compile(
    _PAYING_WITH + r"(?=\s*(?:$|[.,;:·|)]))|" + _ENDING_IN, re.IGNORECASE
)
# What makes a page a card-on-file page: a card in the strict shape (here
# "paying with" a network and any four digits), a card the page says it
# keeps ("the card on file"), or a card by its last four ("card ending in
# 5555"). Never a bare "saved card" or "default payment": a heading over
# "none saved" says that too. Narrower than ``markers.SAVED_PAYMENT_RE``,
# which browser.act may over-read (it only refuses more): here a match
# lets the order button be pressed, so a bare "ending in 2026" (a sale) or
# a mask with no card named never counts.
_SAVED_METHOD_RE = re.compile(
    _PAYING_WITH + "|" + _ENDING_IN
    + r"|\b(?:card|payment(?:\s+method)?)\s+(?:on\s+file|saved|stored)\b"
    + r"|\bcard\s*(?:ending\s+in|[·•*]{2,}|\.{2,}|…)\s*\d{4}(?!\d)",
    re.IGNORECASE,
)
# What, right before a ``_SAVED_METHOD_RE`` match, says the method is
# missing or not this order's ("You have no saved cards", "No payment
# method on file", "Keep this card on file"): a negation or an offer to
# keep the card, then at most two words.
_NOT_SAVED_RE = re.compile(
    r"\b(?:no|not|never|none|without|don['’]?t|doesn['’]?t|add|keep|save|remember)\b"
    r"(?:\s+\S+){0,2}\s*$",
    re.IGNORECASE,
)
# What, in the ``_NONE_AFTER_CHARS`` right after such a match, says there
# is none or it cannot pay ("Card on file: none", "Payment method on file:
# N/A", "Your card on file has expired").
_NONE_AFTER_RE = re.compile(
    r"^\s*[:(\-\u2013\u2014]?\s*\(?\s*(?:none|no|n/?a|0|not|(?:has|is)\s+expired|expired|was\s+removed)\b",
    re.IGNORECASE,
)
_NONE_AFTER_CHARS = 30
# How near (CSS pixels, the gap between the two boxes) a saved method must
# sit to the order total or the order button to count: the next block or
# the next column, not a footer or a side panel.
# ponytail: one fixed reach; tune it if a real review page lays out wider.
_SAVED_REACH_PX = 300
# The least contrast (WCAG ratio: 1 is the same colour, 21 black on white)
# between a text's ink and the background colours behind it for the text
# to count as legible: #eee on white (1.16) is not, #ddd (1.36) is.
# ponytail: judged against ancestors' background colours only; text over a
# picture does not count, and anything painted over it that hit testing
# does not see (a click-through overlay, a sibling's box, its own ::before
# or ::after, an outline, a text decoration) is not seen either: the
# screenshot on the card is the check.
_LEGIBLE_CONTRAST = 1.25
_NETWORKS: dict[str, str] = {
    "visa": "Visa", "mastercard": "Mastercard", "american express": "American Express",
    "amex": "American Express", "discover": "Discover", "jcb": "JCB", "diners": "Diners Club",
    "diners club": "Diners Club", "unionpay": "UnionPay",
}
_MAX_SAVED_CARDS = 5
# The card-field hints live in ``markers`` (shared with the outline, the
# screenshot mask and browser.act); ``field_kind`` applies them here.
_FIELD_ROLES = frozenset({"textbox", "spinbutton", "combobox"})

_SNAPSHOT_LINE_RE = re.compile(
    r"^\s*-\s*'?(?P<role>[a-z][a-z-]*)(?:\s+(?P<name>\"(?:[^\"\\]|\\.)*\"))?.*?\[ref=(?P<ref>(?:f\d+)?e\d+)\]"
)

# Where a submit control would send its form: its own ``formaction`` or
# else the form's ``action`` (read as attributes, so a field named
# "action" cannot stand in for it), resolved against the document, and
# the method the same way. Shared by the page script and ``_BUTTON_JS``,
# so the order button's target and every other one are read alike.
_TARGET_JS = r"""(el, form) => {
  const raw = el.hasAttribute('formaction') ? el.getAttribute('formaction') : form.getAttribute('action');
  let action = 'invalid:';
  try { action = new URL(raw || '', document.baseURI).href; } catch (e) {}
  return [action, (el.getAttribute('formmethod') || form.getAttribute('method') || 'get').toLowerCase()];
}"""
# One evaluate on the main frame: the page origin, every short text
# block that mentions money and is on screen (total candidates, each with
# its distance to the card form or the order button), every leaf row
# that mentions money (item lines), whether the page names a payment
# method on file, the short matches of the strict card shape (never the
# text around them), each within one text node, and where every enabled
# submit button of a POST form in the page would send it (``posts``, read
# as ``_BUTTON_JS`` reads the order button's). Text is collapsed to one
# line. The saved method and the card are read only from words the owner
# sees as this order's: text painted on screen, not in a link, a button
# or a form control's label, in a block within ``_SAVED_REACH_PX`` of an
# order total or an order button, and not said to be missing ("no saved
# cards", "Card on file: none", "has expired") or offered to keep ("Keep
# this card on file"). A text node is painted when one of its own boxes,
# not shrunk under 0.6 of its font size, has its centre in the viewport
# on its own element (not pushed away by text-indent, clipped or
# covered), no ancestor has a transform that does more than move it or is
# drawn over by a background image, a filter, a blend mode or an inset
# shadow, and its ink, faded by every ancestor's opacity, and the colours
# behind it read as rgb() and differ enough. The limit: anything painted
# over the text that hit testing does not see (a click-through overlay, a
# sibling's box, its own ::before or ::after, an outline, a text
# decoration) is not seen, and the screenshot on the card is the check.
# Each card is kept once before the cap, so repeats cannot crowd out a
# second card. Reading never scrolls: the page is read, and photographed
# for the card, as the model left it.
_PAGE_JS = r"""
() => {
  const target = __TARGET__;
  const MONEY = __MONEY__;
  const classify = __FIELD_KIND__;
  const PAY = __PAY_RE__;
  const ORDER = __ORDER_RE__;
  const TOTAL = __TOTAL__;
  const SAVED = __SAVED__;
  const SAVED_ALL = __SAVED_ALL__;
  const NOT_SAVED = __NOT_SAVED__;
  const NONE_AFTER = __NONE_AFTER__;
  const CARD_ON_FILE = __CARD_ON_FILE__;
  const REACH = __REACH__;
  const LEGIBLE = __LEGIBLE__;
  // Links, buttons and form controls' labels: their words are a choice
  // the page offers ("Use a saved card", "Keep this card on file"), not
  // what pays this order.
  const CONTROLS = 'a, button, [role=button], [role=link], label';
  const vw = window.innerWidth, vh = window.innerHeight;
  const visible = el => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1;
  };
  // On screen and actually painted there: inside the viewport, and the
  // middle of its visible part lands on the element itself (not on an
  // overlay covering it, nor on whatever shows through a clipped box).
  const onScreen = el => {
    if (!visible(el)) return false;
    const r = el.getBoundingClientRect();
    if (r.bottom <= 0 || r.right <= 0 || r.top >= vh || r.left >= vw) return false;
    const cx = (Math.max(r.left, 0) + Math.min(r.right, vw)) / 2;
    const cy = (Math.max(r.top, 0) + Math.min(r.bottom, vh)) / 2;
    const hit = document.elementFromPoint(cx, cy);
    return !!hit && (hit === el || el.contains(hit));
  };
  const clean = s => (s || '').replace(/\s+/g, ' ').trim();
  const words = el => [el.getAttribute('aria-label'), el.innerText, el.value, el.getAttribute('title')]
    .map(clean).find(s => s) || '';
  let anchor = null;
  for (const el of document.querySelectorAll('input, select, textarea')) {
    const kind = classify(el);
    if (kind && kind.startsWith('cc-')) { anchor = el.closest('form') || el; break; }
  }
  if (!anchor) {
    for (const el of document.querySelectorAll('button, input[type=submit], input[type=image], [role=button]')) {
      if (PAY.test(words(el))) { anchor = el; break; }
    }
  }
  // The gap between a box and an element, in CSS pixels (0 when they touch).
  const gap = (ar, el) => {
    const r = el.getBoundingClientRect();
    const dy = Math.max(0, ar.top - r.bottom, r.top - ar.bottom);
    const dx = Math.max(0, ar.left - r.right, r.left - ar.right);
    return Math.round(Math.hypot(dx, dy));
  };
  const ar = anchor ? anchor.getBoundingClientRect() : null;
  const distance = el => (ar ? gap(ar, el) : 0);
  const totals = [];
  // Where this order is placed: its total lines on screen and its order buttons.
  const places = [];
  const blocks = document.querySelectorAll(
    'p, div, span, td, th, li, dt, dd, strong, b, em, h1, h2, h3, h4, h5, h6, label, tr, output, summary, section, output');
  for (const el of blocks) {
    if (totals.length >= 200) break;
    const text = clean(el.innerText);
    if (!text || text.length > 160 || !MONEY.test(text) || !onScreen(el)) continue;
    totals.push({ text, distance: distance(el) });
    if (TOTAL.test(text)) places.push(el.getBoundingClientRect());
  }
  for (const el of document.querySelectorAll('button, input[type=submit], input[type=image], [role=button]')) {
    if (!el.disabled && visible(el) && ORDER.test(words(el))) places.push(el.getBoundingClientRect());
  }
  // [r, g, b, alpha] of a computed rgb()/rgba() colour; null for any
  // other notation (oklch(), lab()), which cannot be judged.
  const rgba = s => {
    const n = /^rgba?\(/.test(s || '') ? s.match(/[\d.]+/g) : null;
    return n && n.length >= 3 ? [+n[0], +n[1], +n[2], n.length > 3 ? +n[3] : 1] : null;
  };
  // What shows behind an element: its own and its ancestors' background
  // colours laid over white; null when one cannot be read.
  const backdrop = el => {
    const layers = [];
    for (let a = el; a; a = a.parentElement) {
      const c = rgba(getComputedStyle(a).backgroundColor);
      if (!c) return null;
      if (c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
    }
    let base = [255, 255, 255];
    for (const c of layers.reverse()) base = base.map((v, i) => v + (c[i] - v) * c[3]);
    return base;
  };
  const luminance = c => 0.05 + c.slice(0, 3).map(v => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  }).reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
  // A transform that only moves a box (a centring translate, an
  // animation's resting state) draws its text as laid out.
  const MOVED = /^(?:none|matrix\(1, 0, 0, 1, [^,]+, [^,]+\))$/;
  // Is this text node painted where the owner can read it? Text that
  // cannot be judged does not count: no ancestor may have a transform
  // that does more than move it, a background image, a filter, a blend
  // mode or an inset shadow; its ink, faded by the opacity of every box
  // around it, and the colours behind it must read as rgb() and differ
  // enough; and one of its boxes, at least 0.6 of its font size tall, must
  // be on its own element at its centre, in the viewport.
  const painted = n => {
    const p = n.parentElement;
    if (!p || !n.data.trim() || p.closest(CONTROLS) || !visible(p)) return false;
    let alpha = 1;
    for (let a = p; a; a = a.parentElement) {
      const s = getComputedStyle(a);
      alpha *= +s.opacity;
      if (!MOVED.test(s.transform) || s.backgroundImage !== 'none' || s.filter !== 'none'
        || s.mixBlendMode !== 'normal' || /inset/.test(s.boxShadow)
        || !['none', '', undefined].includes(s.scale) || !['none', '', undefined].includes(s.rotate)
        || ![s.maskImage, s.webkitMaskImage].every(m => !m || m === 'none')) return false;
    }
    const cs = getComputedStyle(p);
    const ink = rgba(cs.webkitTextFillColor || cs.color);
    const back = backdrop(p);
    if (!ink || !back) return false;
    const seen = back.map((v, i) => v + (ink[i] - v) * ink[3] * alpha);
    const [hi, lo] = [luminance(seen), luminance(back)].sort((x, y) => y - x);
    if (hi / lo < LEGIBLE) return false;
    const least = Math.max(1, 0.6 * parseFloat(cs.fontSize) || 0);
    const range = document.createRange();
    range.selectNodeContents(n);
    for (const r of range.getClientRects()) {
      const cx = (r.left + r.right) / 2, cy = (r.top + r.bottom) / 2;
      if (r.width < 1 || r.height < least || cx < 0 || cy < 0 || cx >= vw || cy >= vh) continue;
      const hit = document.elementFromPoint(cx, cy);
      if (hit && (hit === p || p.contains(hit))) return true;
    }
    return false;
  };
  // The text nodes of a block the owner can read, each collapsed to one
  // line: its painted text, outside controls.
  const shown = el => {
    const parts = [];
    const walk = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) if (painted(n)) parts.push(clean(n.data));
    return parts;
  };
  // Words that name a saved method, not ones that say it is missing,
  // before it ("no saved cards") or right after it ("Card on file: none").
  const names = text => [...text.matchAll(SAVED_ALL)].some(m => {
    const end = m.index + m[0].length;
    return !NOT_SAVED.test(text.slice(Math.max(0, m.index - 40), m.index))
      && !NONE_AFTER.test(text.slice(end, end + __NONE_AFTER_CHARS__));
  });
  let saved = false;
  const cards = [], kept = new Set();
  for (const el of blocks) {
    const raw = clean(el.innerText);
    if (!raw || raw.length > 160 || !SAVED.test(raw) || el.closest(CONTROLS)) continue;
    if (!places.some(r => gap(r, el) <= REACH)) continue;
    const parts = shown(el);
    if (!names(parts.join(' '))) continue;
    saved = true;
    // The strict card within one text node, so no digits join it from
    // the next line.
    for (const part of parts) for (const m of part.matchAll(CARD_ON_FILE)) {
      const key = m[0].replace(/\s+/g, ' ').toLowerCase();
      if (kept.has(key) || cards.length >= __MAX_CARDS__) continue;
      kept.add(key);
      cards.push(m[0].slice(0, 60));
    }
  }
  const rows = [...document.querySelectorAll('[class*="item" i], li, tr')].filter(el => {
    const t = clean(el.innerText);
    return t && t.length <= 200 && MONEY.test(t) && visible(el);
  });
  const leaves = rows.filter(el => !rows.some(other => other !== el && el.contains(other)));
  const items = [];
  for (const el of leaves) { items.push(clean(el.innerText)); if (items.length >= 40) break; }
  // Every enabled submit button of a POST form in the page, by where it
  // sends the form (``el.form``, so one attached through form= counts by
  // the form it submits) and what it says, named as ``_BUTTON_JS`` names
  // one: an upsell posting to the order's own address is another button.
  const posts = new Set();
  for (const el of document.querySelectorAll('button, input')) {
    if (!el.form || el.disabled || !['submit', 'image'].includes(el.type) || !visible(el)) continue;
    const [action, method] = target(el, el.form);
    const name = [el.getAttribute('aria-label'), el.innerText, el.value, el.getAttribute('title')]
      .map(s => (s || '').replace(/\s+/g, ' ').trim()).find(s => s) || '';
    if (method === 'post') posts.add(JSON.stringify([action, name.slice(0, 80).toLowerCase()]));
  }
  let origin = '';
  try { origin = self.origin || location.origin || ''; } catch (e) {}
  return { origin, totals, items, saved, cards, posts: [...posts].map(p => JSON.parse(p)) };
}
""".replace("__TARGET__", _TARGET_JS).replace("__FIELD_KIND__", markers.FIELD_KIND_FN).replace(
    "__PAY_RE__", f"new RegExp({json.dumps(_PAY_BUTTON_RE.pattern)}, 'i')"
).replace("__ORDER_RE__", f"new RegExp({json.dumps(_ORDER_BUTTON_RE.pattern)}, 'i')").replace(
    "__TOTAL__", f"new RegExp({json.dumps(markers.TOTAL_LABEL_RE.pattern)}, 'i')"
).replace("__MONEY__", f"new RegExp({json.dumps(markers.MONEY_PATTERN)}, 'i')").replace(
    "__SAVED_ALL__", f"new RegExp({json.dumps(_SAVED_METHOD_RE.pattern)}, 'gi')"
).replace(
    "__SAVED__", f"new RegExp({json.dumps(_SAVED_METHOD_RE.pattern)}, 'i')"
).replace(
    "__NOT_SAVED__", f"new RegExp({json.dumps(_NOT_SAVED_RE.pattern)}, 'i')"
).replace(
    "__NONE_AFTER__", f"new RegExp({json.dumps(_NONE_AFTER_RE.pattern)}, 'i')"
).replace("__NONE_AFTER_CHARS__", str(_NONE_AFTER_CHARS)).replace(
    "__CARD_ON_FILE__", f"new RegExp({json.dumps(_SAVED_CARD_RE.pattern)}, 'gi')"
).replace("__MAX_CARDS__", str(_MAX_SAVED_CARDS)).replace(
    "__REACH__", str(_SAVED_REACH_PX)
).replace("__LEGIBLE__", str(_LEGIBLE_CONTRAST))
# Per field ref: what the element is, its autocomplete token, every hint
# a site uses to name a card field, which ``<form>`` of its document
# encloses it (-1 for none), and whether it is in the page itself rather
# than a frame (``main``). ``self.origin`` is the frame's security origin
# (a srcdoc frame inherits its parent's; location.origin says "null"
# there). ``main`` is asked of the page because a ref's ``fN`` prefix
# cannot say it: the main frame's refs carry one too once the tab has
# navigated; ``window`` and ``window.top`` are ones a page cannot redefine.
_FIELD_JS = r"""
el => {
  const a = n => (el.getAttribute(n) || '');
  let label = '';
  try { label = el.labels && el.labels.length ? el.labels[0].innerText : ''; } catch (e) {}
  let origin = '';
  try { origin = self.origin || location.origin || ''; } catch (e) {}
  const own = el.closest('form');
  return {
    tag: el.tagName.toLowerCase(),
    type: (el.type || '').toLowerCase(),
    autocomplete: a('autocomplete').toLowerCase().trim(),
    hint: [a('name'), a('id'), a('placeholder'), a('aria-label'), a('data-elements-stable-field-name'), label]
      .join(' ').replace(/\s+/g, ' ').toLowerCase().slice(0, 300),
    origin,
    form: own ? [...document.forms].indexOf(own) : -1,
    main: window === window.top,
  };
}
"""
# Per button ref: is it a submit control, which form encloses it (and
# whether ``form=`` attaches it to a different one), what it says, where
# a click would send the enclosing form and by which method
# (``_TARGET_JS``), and whether it is in the page itself (``main``, as
# for a field).
_BUTTON_JS = r"""
el => {
  const target = __TARGET__;
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const own = el.closest('form');
  const attached = el.form || null;
  const submit = (tag === 'button' && (type === '' || type === 'submit'))
    || (tag === 'input' && (type === 'submit' || type === 'image'));
  const name = [el.getAttribute('aria-label'), el.innerText, el.value, el.getAttribute('title')]
    .map(s => (s || '').replace(/\s+/g, ' ').trim()).find(s => s) || '';
  const [action, method] = own ? target(el, own) : ['', ''];
  return {
    submit,
    name: name.slice(0, 80),
    disabled: !!el.disabled,
    form: own ? [...document.forms].indexOf(own) : -1,
    reattached: !!(attached && attached !== own),
    action,
    method,
    main: window === window.top,
  };
}
""".replace("__TARGET__", _TARGET_JS)


@dataclass(frozen=True)
class CardFields:
    """Where the vault's card goes, as aria refs. ``exp_ref`` is one
    MM/YY field; sites that split it have ``exp_month_ref`` and
    ``exp_year_ref`` instead. ``frame_origin`` is the number field's."""

    number_ref: str
    cvc_ref: str
    exp_ref: Optional[str]
    exp_month_ref: Optional[str]
    exp_year_ref: Optional[str]
    name_ref: Optional[str]
    frame_origin: str
    # The index of the number field's ``<form>`` in its document; -1 when
    # the fields sit in no form.
    form: int = -1

    @property
    def refs(self) -> tuple[str, ...]:
        """Every ref the card is typed into, number first."""
        return tuple(
            ref
            for ref in (
                self.number_ref, self.cvc_ref, self.exp_ref, self.exp_month_ref,
                self.exp_year_ref, self.name_ref,
            )
            if ref
        )


@dataclass(frozen=True)
class SubmitTarget:
    """Where the order button sends the form: the URL (query and fragment
    dropped) and the method, both empty when the button is in no form
    (a script submits then)."""

    action: str
    method: str


@dataclass(frozen=True)
class CheckoutFacts:
    url: str
    origin: str
    host: str
    scheme: str
    title: str
    total: Optional[Money]
    totals_seen: tuple[str, ...]
    items: tuple[str, ...]
    card_fields: Optional[CardFields]
    submit_ref: Optional[str]
    outline_digest: str
    # Every distinct amount a visible total line carries (``total`` is the
    # one nearest the card form); more than one is refused.
    totals: tuple[Money, ...] = ()
    submit_target: Optional[SubmitTarget] = None
    # The page names a payment method on file (``_SAVED_METHOD_RE``, in
    # words the owner sees near the order total or button), and the one
    # card it names in the strict shape ("Visa ····4242", "" when none or
    # several). With no card fields, ``order_buttons`` counts the distinct
    # order buttons, or every control that may place an order when there
    # is more than one (``_order_button``); ``submit_ref`` is set only when
    # there is exactly one.
    saved_payment: bool = False
    saved_card: str = ""
    order_buttons: int = 0
    # No card fields Crawler fills, yet the page may ask for a card, so it
    # is never paid with the card on file: a card number or security code
    # field in the page itself ("page", a saved card asking for its code)
    # or in a frame, trusted or not ("frame"), or more fields than
    # ``_MAX_FIELDS`` so the rest went unread ("unchecked"). "" for none.
    stray_card_fields: str = ""


@dataclass(frozen=True)
class _Ref:
    role: str
    name: str
    ref: str


def _plain_name(token: Optional[str]) -> str:
    if not token:
        return ""
    try:
        return str(json.loads(token))
    except ValueError:
        return token.strip('"')


def _snapshot_refs(raw: str) -> list[_Ref]:
    """Every (role, name, ref) the raw snapshot shows, in document order,
    frames included (their refs are prefixed ``fN``)."""
    refs: list[_Ref] = []
    for line in raw.splitlines():
        match = _SNAPSHOT_LINE_RE.match(line)
        if match is not None:
            refs.append(_Ref(match.group("role"), _plain_name(match.group("name")), match.group("ref")))
    return refs


async def _evaluate(page: Any, ref: str, script: str) -> Optional[dict[str, Any]]:
    try:
        result = await page.locator(f"aria-ref={ref}").evaluate(script, timeout=REF_TIMEOUT_MS)
    except Exception:  # noqa: BLE001 - a ref that no longer resolves is simply not a candidate
        return None
    return result if isinstance(result, dict) else None


async def _ask_page(
    page: Any, fields: Sequence[_Ref], buttons: Sequence[_Ref]
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """The page script's answer, and each field's and button's (a link is
    asked like a button). A button keeps its snapshot name as ``label``
    beside the name the page gives it, and its snapshot ``role``."""
    page_data, field_data, button_data = await asyncio.gather(
        page.evaluate(_PAGE_JS),
        asyncio.gather(*(_evaluate(page, r.ref, _FIELD_JS) for r in fields)),
        asyncio.gather(*(_evaluate(page, r.ref, _BUTTON_JS) for r in buttons)),
    )
    found_fields = [
        {**data, "ref": r.ref, "hint": f"{data.get('hint', '')} {r.name}".lower()}
        for r, data in zip(fields, field_data, strict=True)
        if data is not None
    ]
    found_buttons = [
        {
            **data, "ref": r.ref, "name": data.get("name") or r.name, "label": r.name, "role": r.role,
            # The name as the page script reads it, for ``posts`` (an
            # aria-labelledby button reads "" there, "Place your order" here).
            "own_name": data.get("name") or "",
        }
        for r, data in zip(buttons, button_data, strict=True)
        if data is not None
    ]
    return (page_data if isinstance(page_data, dict) else {}), found_fields, found_buttons


def _pick_total(candidates: Any) -> tuple[Optional[Money], tuple[str, ...], tuple[Money, ...]]:
    """The on-screen price whose label is a total (never a subtotal)
    nearest the card form, every candidate text that carried such a
    label, and every distinct amount those candidates named."""
    picks: list[tuple[int, int, Money]] = []  # (distance, order, money)
    seen: list[str] = []
    amounts: list[Money] = []
    for order, item in enumerate(candidates if isinstance(candidates, list) else []):
        text, distance = (item.get("text"), item.get("distance", 0)) if isinstance(item, dict) else (item, 0)
        if not isinstance(text, str):
            continue
        text = " ".join(text.split())[:_TOTAL_CHARS]
        for match in _TOTAL_LABEL_RE.finditer(text):
            money = parse_money(text[match.end() :])
            if money is None:
                continue
            picks.append((int(distance) if isinstance(distance, (int, float)) else 0, order, money))
            if money not in amounts:
                amounts.append(money)
            if text not in seen and len(seen) < MAX_TOTALS_SEEN:
                seen.append(text)
            break
    if not picks:
        return None, (), ()
    # Nearest the card form; among equals the last one on the page, the
    # way a summary lists its grand total below the rest.
    _distance, _order, total = min(picks, key=lambda pick: (pick[0], -pick[1]))
    return total, tuple(seen), tuple(amounts)


def _pick_items(rows: Any) -> tuple[str, ...]:
    items: list[str] = []
    for text in rows if isinstance(rows, list) else []:
        if not isinstance(text, str):
            continue
        text = " ".join(text.split())
        if not text or _ITEM_EXCLUDE_RE.search(text) or text in items:
            continue
        items.append(text[:_ITEM_CHARS])
        if len(items) >= MAX_ITEMS:
            break
    return tuple(items)


def _field_kind(field: dict[str, Any]) -> Optional[str]:
    """Which card field this is (``markers.field_kind``): by its
    autocomplete token first and the site's own naming second; None for
    anything else on the page."""
    return markers.field_kind(field)


def _frame_allowed(field_origin: str, page_origin: str) -> bool:
    if not field_origin or field_origin == "null":
        return False
    if field_origin == page_origin:
        return True
    host = (urlsplit(field_origin).hostname or "").lower()
    return host in PAYMENT_FRAME_HOSTS


def _card_fields(fields: Sequence[dict[str, Any]], page_origin: str) -> Optional[CardFields]:
    found: dict[str, dict[str, Any]] = {}
    for field in fields:
        kind = _field_kind(field)
        if kind is None or kind in found:
            continue
        if not _frame_allowed(str(field.get("origin") or ""), page_origin):
            continue
        found[kind] = field
    number, cvc = found.get("number"), found.get("cvc")
    if number is None or cvc is None:
        return None

    def ref_of(kind: str) -> Optional[str]:
        field = found.get(kind)
        return str(field["ref"]) if field is not None else None

    form = number.get("form")
    return CardFields(
        number_ref=str(number["ref"]),
        cvc_ref=str(cvc["ref"]),
        exp_ref=ref_of("exp"),
        exp_month_ref=ref_of("exp_month"),
        exp_year_ref=ref_of("exp_year"),
        name_ref=ref_of("name"),
        frame_origin=str(number.get("origin") or ""),
        form=form if isinstance(form, int) and not isinstance(form, bool) else -1,
    )


def _frame_of(ref: str) -> str:
    """The frame address an aria ref carries (``f2`` of ``f2e8``; ``""``
    for the tab's first main frame). Playwright resolves a ref in the frame
    this names, so two refs of one snapshot share it exactly when they sit
    in the same frame. It never says which frame is the page itself: once
    the tab has navigated, the main frame's refs carry one too. That is
    asked of the page (``main``)."""
    return ref.partition("e")[0]


def _submit_button(
    buttons: Sequence[dict[str, Any]], card: Optional[CardFields]
) -> Optional[dict[str, Any]]:
    """The order button. Only a button that sits inside the card fields'
    own ``<form>`` element counts (one attached from elsewhere through
    ``form=`` never does, whatever it says): named like one first, else
    that form's last submit control. When the card fields are in no form
    (a script submits them), a button named like one, itself in no form or
    in its own, in the page itself or in the card number's frame, is taken
    instead (never one in another frame). A link is never the order button."""
    if card is None:
        return None
    usable = [
        b for b in buttons
        if not b.get("disabled") and not b.get("reattached") and isinstance(b.get("form"), int)
        and b.get("role") != "link"
    ]
    frame = _frame_of(card.number_ref)
    if card.form >= 0:
        in_form = [b for b in usable if _frame_of(str(b["ref"])) == frame and b["form"] == card.form]
        for button in in_form:
            if _PAY_BUTTON_RE.search(str(button.get("name") or "")):
                return button
        submits = [b for b in in_form if b.get("submit")]
        return submits[-1] if submits else None
    for button in usable:
        here = button.get("main") is True or _frame_of(str(button["ref"])) == frame
        if here and _PAY_BUTTON_RE.search(str(button.get("name") or "")):
            return button
    return None


def _rival(role: str, *names: str) -> bool:
    """Do these words (the page's or the snapshot's name for a control
    with this *role*) read as a control that may place an order
    (``_ORDER_BUTTON_RE`` or ``_RIVAL_RE``, or for a button pay words
    that do not pick a way to pay)?"""
    return any(
        _ORDER_BUTTON_RE.search(n) or _RIVAL_RE.match(n)
        or (role != "link" and _PAY_BUTTON_RE.search(n) and not _PAY_CHOICE_RE.match(n))
        for n in names
    )


def _order_button(
    buttons: Sequence[dict[str, Any]], named: int = 0, posts: Sequence[tuple[str, str]] = ()
) -> tuple[Optional[dict[str, Any]], int]:
    """On a page with no card fields: the one button in the page itself
    (``main``, never a frame) whose words, as the page or the snapshot
    names it, place the order, and how many distinct ones there are. Every
    button or link in any frame whose words may place an order (``_rival``:
    "Pay $23.40", "Complete payment", a "Place your order" link) is counted
    too, and so is every other target in *posts* (where each submit button
    of a POST form in the page sends it, whatever it says): those are never
    pressed, and two or more of them is ambiguous, so none is picked and
    that many are counted. Submit buttons of the same form with the same
    words and target are one (a shop repeats its order button at the foot
    of the form); a disabled button and one attached to another form
    through ``form=`` are not candidates. *named* is how many controls the
    snapshot names like a rival: more than ``_MAX_ORDER_BUTTONS`` were not
    all asked about, so none is picked and that many are counted."""
    if named > _MAX_ORDER_BUTTONS:
        return None, named
    rivals: dict[tuple[Any, ...], dict[str, Any]] = {}
    for button in buttons:
        name = str(button.get("name") or "")
        label = str(button.get("label") or "")
        if button.get("disabled") or button.get("reattached"):
            continue
        if not _rival(str(button.get("role") or ""), name, label):
            continue
        ref, form = str(button["ref"]), button.get("form")
        key: tuple[Any, ...] = (ref,)
        if isinstance(form, int) and form >= 0 and button.get("submit"):
            key = (_frame_of(ref), form, button.get("action"), button.get("method"), name.lower())
        rivals.setdefault(key, button)
    if len(rivals) > 1:
        return None, len(rivals)
    picks = [
        b for b in rivals.values()
        if b.get("main") is True and b.get("role") != "link"
        and (_ORDER_BUTTON_RE.search(str(b.get("name") or ""))
             or _ORDER_BUTTON_RE.search(str(b.get("label") or "")))
    ]
    if not picks:
        return None, 0
    pick = picks[0]
    own = None
    if pick.get("method") == "post":
        own_words = pick.get("own_name", pick.get("name"))
        own = (str(pick.get("action") or ""), str(own_words or "")[:80].lower())
    others = {post for post in posts if post != own}
    if others:
        return None, 1 + len(others)
    return pick, 1


def _stray(fields: Sequence[dict[str, Any]], cut: bool) -> str:
    """On a page with no card fields Crawler fills: where a card number or
    security code field sits anyway ("page" or "frame", by the page's own
    ``main``), else "unchecked" when *cut* left fields unread, else ""."""
    asks = [field for field in fields if _field_kind(field) in ("number", "cvc")]
    if any(field.get("main") is True for field in asks):
        return "page"
    if asks:
        return "frame"
    return "unchecked" if cut else ""


def _saved_card(found: Any) -> str:
    """``"Visa ····4242"`` when the page's strict matches (``_SAVED_CARD_RE``)
    name exactly one card, else ``""``: with two, which one pays is not said."""
    labels: set[str] = set()
    for text in found if isinstance(found, list) else []:
        match = _SAVED_CARD_RE.search(text) if isinstance(text, str) else None
        if match is None:
            continue
        name, digits = match.group(1) or match.group(3), match.group(2) or match.group(4)
        network = _NETWORKS.get(" ".join(name.lower().split()))
        if network is not None:
            labels.add(f"{network} ····{digits}")
    return labels.pop() if len(labels) == 1 else ""


def _submit_target(button: Optional[dict[str, Any]]) -> Optional[SubmitTarget]:
    if button is None:
        return None
    action = str(button.get("action") or "")
    return SubmitTarget(
        action=snap.strip_url(action, True) if action else "",
        method=str(button.get("method") or "").lower(),
    )


async def collect_checkout_facts(page: Any) -> CheckoutFacts:
    """Read the page. Takes a fresh snapshot (which retires every earlier
    ref) and asks the page about its first ``_MAX_FIELDS`` fields, its
    first ``_MAX_BUTTONS`` buttons and every button or link the snapshot
    names like one that may place an order (``_rival``, up to
    ``_MAX_ORDER_BUTTONS``), and the page script reads where every submit
    button of a POST form in the page sends it; a page that will not
    answer in time reports no total, no card fields and no button, so the
    toolkit refuses rather than guesses."""
    url = str(page.url)
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    python_origin = f"{scheme}://{parts.netloc.rpartition('@')[2].lower()}"
    title = str(await page.title())[:200]
    raw = await snap.snapshot_raw(page)
    outline = snap.filter_yaml(raw, full=True, account_mode=True, limit_chars=snap.FULL_LIMIT_CHARS)
    digest = outline_digest(outline.lines, states=True)
    refs = _snapshot_refs(raw)
    all_fields = [r for r in refs if r.role in _FIELD_ROLES]
    all_buttons = [r for r in refs if r.role == "button"]
    named = [r for r in refs if r.role in ("button", "link") and _rival(r.role, r.name)]
    asked = all_buttons[:_MAX_BUTTONS]
    asked += [r for r in named[:_MAX_ORDER_BUTTONS] if r not in asked]
    try:
        page_data, fields, buttons = await asyncio.wait_for(
            _ask_page(page, all_fields[:_MAX_FIELDS], asked), FACTS_TIMEOUT_S
        )
    except Exception as exc:  # noqa: BLE001 - unknown facts fail closed
        logger.warning("checkout_facts_failed", error_type=type(exc).__name__, host=host)
        page_data, fields, buttons = {}, [], []
    origin = str(page_data.get("origin") or "") or python_origin
    total, totals_seen, totals = _pick_total(page_data.get("totals"))
    card_fields = _card_fields(fields, origin)
    button, order_buttons = _submit_button(buttons, card_fields), 0
    stray = ""
    if card_fields is None:
        found = page_data.get("posts")
        posts = [
            (str(p[0]), str(p[1])) for p in (found if isinstance(found, list) else [])
            if isinstance(p, list) and len(p) == 2
        ]
        button, order_buttons = _order_button(buttons, len(named), posts)
        stray = _stray(fields, len(all_fields) > _MAX_FIELDS)
    return CheckoutFacts(
        url=snap.strip_url(url, True),
        origin=origin,
        host=host,
        scheme=scheme,
        title=title,
        total=total,
        totals_seen=totals_seen,
        items=_pick_items(page_data.get("items")),
        card_fields=card_fields,
        submit_ref=str(button["ref"]) if button is not None else None,
        outline_digest=digest,
        totals=totals,
        submit_target=_submit_target(button),
        saved_payment=page_data.get("saved") is True,
        saved_card=_saved_card(page_data.get("cards")),
        order_buttons=order_buttons,
        stray_card_fields=stray,
    )


def _list_amounts(totals: Sequence[Money]) -> str:
    shown = [f"${fmt_usd(t.amount)}" if t.currency == "USD" else f"{t.amount} {t.currency}" for t in totals]
    return " and ".join(shown[:4])


def _submit_target_refusal(facts: CheckoutFacts) -> Optional[str]:
    """Why the order button may not be clicked: its form would send the
    card (or, paying with the card on file, the order) somewhere other
    than this site (or the payment frame it sits in) over https by POST.
    A button in no form has no target to check."""
    target = facts.submit_target
    if target is None or not target.action:
        return None
    what = "the card" if facts.card_fields is not None else "the order"
    parts = urlsplit(target.action)
    origin = f"{parts.scheme.lower()}://{parts.netloc.rpartition('@')[2].lower()}"
    allowed = {facts.origin}
    if facts.card_fields is not None and facts.card_fields.frame_origin:
        allowed.add(facts.card_fields.frame_origin)
    if parts.scheme.lower() != "https" or origin not in allowed:
        return (
            f"The order button on this page would send {what} to {snap.host_path(target.action)} "
            f"over {parts.scheme or 'no scheme'}, not to {facts.host} over https, so Crawler will "
            "not pay here."
        )
    if target.method != "post":
        return (
            f"The order form on {facts.host} would send {what} in the page address "
            f"({target.method or 'no'} method instead of POST), so Crawler will not pay here."
        )
    return None


# Why a page with no card fields Crawler fills may still ask for a card,
# by ``CheckoutFacts.stray_card_fields``.
_STRAY_REFUSALS = {
    "page": (
        "This page asks for a card number or security code that Crawler cannot fill here, so "
        "Crawler will not pay here."
    ),
    "frame": (
        "The card fields on this page are in a part of the page Crawler cannot fill, so "
        "Crawler will not pay here."
    ),
    "unchecked": (
        "This page has more fields than Crawler checks, so Crawler cannot tell whether it asks "
        "for a card and will not pay here."
    ),
}


def _payment_step_refusal(facts: CheckoutFacts) -> Optional[str]:
    """Why this page is not a payment step Crawler can finish: it may ask
    for a card Crawler cannot fill (never paid with the card on file
    instead), an order button with no saved method on screen (scrolled
    away, so the person is told to bring it back beside the total, since
    reading never scrolls), no card fields and no payment method saved at
    the site, a saved method with no single order button, or card fields
    with no order button."""
    if facts.card_fields is None and facts.stray_card_fields:
        return _STRAY_REFUSALS[facts.stray_card_fields]
    if facts.card_fields is None and not facts.saved_payment and facts.order_buttons:
        return (
            "This page has an order button but no payment method saved at the site on screen "
            "beside the order total. If the page shows one elsewhere, scroll so the payment "
            "method and the order total show together and try again; if not, open the payment "
            "step with the card fields."
        )
    if facts.card_fields is None and not facts.saved_payment:
        return (
            "Could not find the card number and security code fields, or a payment method "
            "saved at the site, on this page. Open the payment step of the checkout (the page "
            "with the card fields, or the review page that shows the saved card and the order "
            "button) and try again."
        )
    if facts.submit_ref is not None:
        return None
    if facts.card_fields is not None:
        return (
            "Could not find the order button on this page. Open the payment step of the "
            "checkout and try again."
        )
    if facts.order_buttons > 1:
        return (
            "This page shows a payment method saved at the site and more than one order button, "
            "so Crawler cannot tell which one places the order. Open the final review step and "
            "try again."
        )
    return (
        "This page shows a payment method saved at the site but no button that places the "
        "order. Open the final review step, where the order is placed, and try again."
    )


def classify_facts(
    facts: CheckoutFacts,
    *,
    expected_merchant: str,
    model_amount: Optional[Decimal],
    per_purchase_cap: Decimal,
    per_day_cap: Decimal,
    spent_today: Decimal,
) -> Optional[tuple[str, str]]:
    """``(rule, message)`` for the first safeguard the page fails, or None
    when Crawler may ask the owner to approve. Pure; the rules run in the
    order the spec lists them, so the owner is told the most basic problem
    first (a plain http page before a missing total)."""
    if facts.scheme != "https":
        act = "enter a card" if facts.card_fields is not None else "pay"
        return (
            "insecure_page",
            f"This page is not served over HTTPS ({facts.scheme or 'no scheme'}://{facts.host}), "
            f"so Crawler will not {act} here.",
        )
    reason = merchant_refusal(facts.host, expected_merchant)
    if reason is not None:
        return "merchant_mismatch", reason
    if facts.total is None:
        return (
            "no_total",
            "Could not find the order total on this page, so Crawler cannot say what it would "
            "pay. Open the final checkout step (the page that shows the total next to the card "
            "fields or the saved card) and try again.",
        )
    totals = facts.totals or (facts.total,)
    if len(set(totals)) > 1:
        return (
            "ambiguous_total",
            f"This page shows more than one total ({_list_amounts(totals)}), so Crawler cannot "
            "tell what it would pay. Open the final checkout step and try again.",
        )
    charge = usd(facts.total)
    if charge is None:
        return (
            "currency",
            f"The total on this page is in {facts.total.currency}, and Crawler only pays in US "
            "dollars for now.",
        )
    reason = _payment_step_refusal(facts)
    if reason is not None:
        return "no_card_fields", reason
    reason = _submit_target_refusal(facts)
    if reason is not None:
        return "submit_target", reason
    # The caps see the largest visible total; with one distinct total
    # (checked above) that is the charge itself.
    charge = max([charge, *(amount for amount in map(usd, totals) if amount is not None)])
    amount = max(charge, model_amount) if model_amount is not None else charge
    if amount > per_purchase_cap:
        stated = (
            f" (the page shows ${fmt_usd(charge)}; you expected ${fmt_usd(model_amount)})"
            if model_amount is not None and model_amount > charge
            else ""
        )
        return (
            "over_cap",
            f"This purchase is ${fmt_usd(amount)}{stated}, over the per-purchase cap of "
            f"${fmt_usd(per_purchase_cap)}. The owner can change the cap in Permissions → "
            "Buy things for me.",
        )
    if amount + spent_today > per_day_cap:
        return (
            "over_daily_cap",
            f"This purchase would bring today's spending to ${fmt_usd(amount + spent_today)} "
            f"(${fmt_usd(spent_today)} already spent in the last 24 hours), over the daily cap "
            f"of ${fmt_usd(per_day_cap)}. The owner can change the cap in Permissions → "
            "Buy things for me.",
        )
    return None
