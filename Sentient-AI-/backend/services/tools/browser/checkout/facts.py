"""What a checkout page says, read by the toolkit and never by the model
(purchases spec §6): the origin and scheme, the order total, the item
lines, the card fields, the order button and where it would send the
form, plus a digest of the page outline that ties the approval card to
this page.

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
page's own origin, or to the payment frame's, before a card is filled.
"""

from __future__ import annotations

import asyncio
import hashlib
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
_MAX_FIELDS = 40
_MAX_BUTTONS = 40
_ITEM_CHARS = 120
_TOTAL_CHARS = 160

# The label of the amount to pay; "subtotal" never, nor a total of
# something that is not money to pay (items, savings, tax lines, a total
# "before" something). Held by ``markers`` so browser.act asks the same
# question of a page.
_TOTAL_LABEL_RE = markers.TOTAL_LABEL_RE
# Rows that are a total line, not an item.
_ITEM_EXCLUDE_RE = re.compile(
    r"sub\s*-?\s*total|\btotal\b|amount\s+due|you\s+pay|to\s+pay|balance\s+due",
    re.IGNORECASE,
)
_PAY_BUTTON_RE = re.compile(
    r"\b(?:place (?:your |the |my )?order|pay(?:ment)?(?: now| securely)?|buy(?: now)?"
    r"|purchase(?: now)?|complete (?:my |your |the )?(?:order|purchase|payment|booking)"
    r"|confirm (?:and pay|order|purchase|payment|booking)|submit (?:order|payment)"
    r"|order now|book now|check ?out)\b",
    re.IGNORECASE,
)
# The card-field hints live in ``markers`` (shared with the outline, the
# screenshot mask and browser.act); ``field_kind`` applies them here.
_FIELD_ROLES = frozenset({"textbox", "spinbutton", "combobox"})

_SNAPSHOT_LINE_RE = re.compile(
    r"^\s*-\s*'?(?P<role>[a-z][a-z-]*)(?:\s+(?P<name>\"(?:[^\"\\]|\\.)*\"))?.*?\[ref=(?P<ref>(?:f\d+)?e\d+)\]"
)
_ACTIVE_MARKER = " [active]"

# One evaluate on the main frame: the page origin, every short text
# block that mentions money and is on screen (total candidates, each with
# its distance to the card form or the order button) and every leaf row
# that mentions money (item lines). Text is collapsed to one line.
_PAGE_JS = r"""
() => {
  const MONEY = __MONEY__;
  const classify = __FIELD_KIND__;
  const PAY = __PAY_RE__;
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
  const ar = anchor ? anchor.getBoundingClientRect() : null;
  const distance = el => {
    if (!ar) return 0;
    const r = el.getBoundingClientRect();
    const dy = Math.max(0, ar.top - r.bottom, r.top - ar.bottom);
    const dx = Math.max(0, ar.left - r.right, r.left - ar.right);
    return Math.round(Math.hypot(dx, dy));
  };
  const totals = [];
  const blocks = document.querySelectorAll(
    'p, div, span, td, th, li, dt, dd, strong, b, em, h1, h2, h3, h4, h5, h6, label, tr, output, summary, section, output');
  for (const el of blocks) {
    if (totals.length >= 200) break;
    const text = clean(el.innerText);
    if (!text || text.length > 160 || !MONEY.test(text) || !onScreen(el)) continue;
    totals.push({ text, distance: distance(el) });
  }
  const rows = [...document.querySelectorAll('[class*="item" i], li, tr')].filter(el => {
    const t = clean(el.innerText);
    return t && t.length <= 200 && MONEY.test(t) && visible(el);
  });
  const leaves = rows.filter(el => !rows.some(other => other !== el && el.contains(other)));
  const items = [];
  for (const el of leaves) { items.push(clean(el.innerText)); if (items.length >= 40) break; }
  let origin = '';
  try { origin = self.origin || location.origin || ''; } catch (e) {}
  return { origin, totals, items };
}
""".replace("__FIELD_KIND__", markers.FIELD_KIND_FN).replace(
    "__PAY_RE__", f"new RegExp({json.dumps(_PAY_BUTTON_RE.pattern)}, 'i')"
).replace("__MONEY__", f"new RegExp({json.dumps(markers.MONEY_PATTERN)}, 'i')")
# Per field ref: what the element is, its autocomplete token, every hint
# a site uses to name a card field, and which ``<form>`` of its document
# encloses it (-1 for none). ``self.origin`` is the frame's security
# origin (a srcdoc frame inherits its parent's; location.origin says
# "null" there).
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
  };
}
"""
# Per button ref: is it a submit control, which form encloses it (and
# whether ``form=`` attaches it to a different one), what it says, and
# where a click would send the form: the button's own ``formaction`` or
# else the form's ``action`` (read as attributes, so a field named
# "action" cannot stand in for it), resolved against the document, and
# the method the same way.
_BUTTON_JS = r"""
el => {
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const own = el.closest('form');
  const attached = el.form || null;
  const submit = (tag === 'button' && (type === '' || type === 'submit'))
    || (tag === 'input' && (type === 'submit' || type === 'image'));
  const name = [el.getAttribute('aria-label'), el.innerText, el.value, el.getAttribute('title')]
    .map(s => (s || '').replace(/\s+/g, ' ').trim()).find(s => s) || '';
  let action = '', method = '';
  if (own) {
    const raw = el.hasAttribute('formaction') ? el.getAttribute('formaction') : own.getAttribute('action');
    try { action = new URL(raw || '', document.baseURI).href; } catch (e) { action = 'invalid:'; }
    method = (el.getAttribute('formmethod') || own.getAttribute('method') || 'get').toLowerCase();
  }
  return {
    submit,
    name: name.slice(0, 80),
    disabled: !!el.disabled,
    form: own ? [...document.forms].indexOf(own) : -1,
    reattached: !!(attached && attached !== own),
    action,
    method,
  };
}
"""


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


@dataclass(frozen=True)
class _Ref:
    role: str
    name: str
    ref: str


def outline_digest(lines: Sequence[str]) -> str:
    """sha1 of the page's interactive structure: the outline lines that
    carry a ref, minus their inline value and the focus marker. Text-only
    lines are left out so a ticking cart timer or a focus change does not
    void an approval; a changed total or item is caught by the explicit
    comparisons the toolkit makes."""
    kept: list[str] = []
    for line in lines:
        if "[ref=" not in line:
            continue
        line = line.replace(_ACTIVE_MARKER, "")
        head, sep, _value = line.partition("]: ")
        kept.append(head + ("]" if sep else ""))
    return hashlib.sha1("\n".join(kept).encode("utf-8")).hexdigest()


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
    page: Any, refs: Sequence[_Ref]
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    fields = [r for r in refs if r.role in _FIELD_ROLES][:_MAX_FIELDS]
    buttons = [r for r in refs if r.role == "button"][:_MAX_BUTTONS]
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
        {**data, "ref": r.ref, "name": data.get("name") or r.name}
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
    """The frame prefix of an aria ref: ``""`` for the main frame, ``f1``
    for the first child frame, so two refs in the same frame share it."""
    return ref.partition("e")[0]


def _submit_button(
    buttons: Sequence[dict[str, Any]], card: Optional[CardFields]
) -> Optional[dict[str, Any]]:
    """The order button. Only a button that sits inside the card fields'
    own ``<form>`` element counts (one attached from elsewhere through
    ``form=`` never does, whatever it says): named like one first, else
    that form's last submit control. When the card fields are in no form
    (a script submits them), a button named like one anywhere, itself in
    no form or in its own, is taken instead."""
    if card is None:
        return None
    usable = [
        b for b in buttons
        if not b.get("disabled") and not b.get("reattached") and isinstance(b.get("form"), int)
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
        if _PAY_BUTTON_RE.search(str(button.get("name") or "")):
            return button
    return None


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
    ref) and asks the page about its fields and buttons; a page that will
    not answer in time reports no total, no card fields and no button, so
    the toolkit refuses rather than guesses."""
    url = str(page.url)
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    python_origin = f"{scheme}://{parts.netloc.rpartition('@')[2].lower()}"
    title = str(await page.title())[:200]
    raw = await snap.snapshot_raw(page)
    outline = snap.filter_yaml(raw, full=True, account_mode=True, limit_chars=snap.FULL_LIMIT_CHARS)
    digest = outline_digest(outline.lines)
    try:
        page_data, fields, buttons = await asyncio.wait_for(
            _ask_page(page, _snapshot_refs(raw)), FACTS_TIMEOUT_S
        )
    except Exception as exc:  # noqa: BLE001 - unknown facts fail closed
        logger.warning("checkout_facts_failed", error_type=type(exc).__name__, host=host)
        page_data, fields, buttons = {}, [], []
    origin = str(page_data.get("origin") or "") or python_origin
    total, totals_seen, totals = _pick_total(page_data.get("totals"))
    card_fields = _card_fields(fields, origin)
    button = _submit_button(buttons, card_fields)
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
    )


def _list_amounts(totals: Sequence[Money]) -> str:
    shown = [f"${fmt_usd(t.amount)}" if t.currency == "USD" else f"{t.amount} {t.currency}" for t in totals]
    return " and ".join(shown[:4])


def _submit_target_refusal(facts: CheckoutFacts) -> Optional[str]:
    """Why the order button may not be clicked: its form would send the
    card somewhere other than this site (or the payment frame it sits
    in) over https by POST. A button in no form has no target to check."""
    target = facts.submit_target
    if target is None or not target.action:
        return None
    parts = urlsplit(target.action)
    origin = f"{parts.scheme.lower()}://{parts.netloc.rpartition('@')[2].lower()}"
    allowed = {facts.origin}
    if facts.card_fields is not None and facts.card_fields.frame_origin:
        allowed.add(facts.card_fields.frame_origin)
    if parts.scheme.lower() != "https" or origin not in allowed:
        return (
            f"The order button on this page would send the card to {snap.host_path(target.action)} "
            f"over {parts.scheme or 'no scheme'}, not to {facts.host} over https, so Crawler will "
            "not pay here."
        )
    if target.method != "post":
        return (
            f"The order form on {facts.host} would send the card in the page address "
            f"({target.method or 'no'} method instead of POST), so Crawler will not pay here."
        )
    return None


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
        return (
            "insecure_page",
            f"This page is not served over HTTPS ({facts.scheme or 'no scheme'}://{facts.host}), "
            "so Crawler will not enter a card here.",
        )
    reason = merchant_refusal(facts.host, expected_merchant)
    if reason is not None:
        return "merchant_mismatch", reason
    if facts.total is None:
        return (
            "no_total",
            "Could not find the order total on this page, so Crawler cannot say what it would "
            "pay. Open the final checkout step (the page with the card fields and the total) "
            "and try again.",
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
    if facts.card_fields is None or facts.submit_ref is None:
        missing = "the card number and security code fields" if facts.card_fields is None else "the order button"
        return (
            "no_card_fields",
            f"Could not find {missing} on this page. Open the payment step of the checkout and "
            "try again.",
        )
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
