"""browser.act: the agent types, chooses, clicks and submits in Crawler's
own browser (purchases spec §5).

WRITE tier, an approval card per call unless the act is an errand step
(below): the model may fill a field, fill a form, pick an option, tick a
box, click anything (a "Sign up" button included: that is what the card
is for), press a key or submit a form. The same session, egress guard, handoff detector, caps and loop
detector as browser.read; every act ends with the fresh outline the way
browser.read's actions do, plus ``did`` ("Typed 12 characters into
"Email"") so the model knows what happened without re-reading. An act
that opens a new tab (a ``target=_blank`` link, a script's
``window.open``) goes on in that tab, as a read's click does
(``BrowserSession.adopt_new_tab``): the outline is the new tab's and the
result says ``new_tab``; a new tab that shows no page is closed and the
result says so.

Hard rules, checked before the card (``precheck`` on the page memory,
with no browser call, then ``bind_async`` on the live page when the card
would be made) and again when the approved act runs:

- never into a password, one-time-code or card field (number, security
  code, expiry, name on card: ``checkout.markers`` decides). Those are
  filled by the checkout toolkit from the vault, never from model text;
  a fill/select into one is refused as ``secure_field`` from the page
  memory's facts and names, then from the live element's attributes.
- never a click, submit or Enter that pays. What is judged is the control
  that would send the form (a click, the element under the point it
  lands on, a <label> as the control it is for; a submit through a field
  goes through the form's default button, and is sent through that same
  button; Enter activates the focused element itself, whatever it is,
  followed into open shadow roots and into a focused frame, which is
  asked the same question or, when it cannot be, refuses, as a focus
  hidden in a shadow tree nobody can read does), and it is refused as
  ``use_checkout`` whatever the purchases switch says when money can
  move from it (``markers.pays``, with every frame's facts joined in):
  when it or a link is aimed at an order path (/place-order, /pay), when
  its form holds a card right now, when it is little more than a price,
  when it is a wallet button (Apple Pay, PayPal...), when its words are a
  purchase ("Place order", "Pay now", "Jetzt kaufen"...: the lists in
  ``checkout.markers``) and it sends a POST form or the page (any frame
  of it) shows an order total or a payment method on file, when it is
  anything but a plain link on a page that names a payment method on
  file next to a price, or when it is a button (a clickable <div>
  included) on a page that shows an order total next to a payment method
  on file: money moves through browser.checkout and its own card, or not
  at all. What cannot move money is not refused: a plain link that is not
  aimed at an order path is navigation whatever it says (a film poster
  that hides "Buy Tickets" in its anchor), and a control whose words are
  a purchase with none of the above (a script button "Buy tickets" that
  opens the ticketing page) gets its card, with the money warning. Words
  are judged on the live page; before that, from the outline's names
  alone, only a submit is refused (a submit sends a form; its own name
  and its form's default button's). A check or a select is refused the
  same way when its own words are a purchase (before the card too) or a
  wallet's, or the page names a payment method on file next to a price
  (``markers.change_pays``). A wallet button elsewhere on the page
  refuses nothing: most shops show one next to "Add to cart".
- never on an ``http://`` page (``insecure_page``): what the model types
  can be the person's address or a message, and it must not cross the
  network in clear.
- only on the page the card was made from. ``bind`` ties the card to the
  page's origin, address (a digest of the URL) and outline digest under
  ``_page`` (a key no action takes: a call carrying its own is refused);
  the approved act refuses when the origin differs (``page_changed``) or
  when the address or the outline digest differs (``outline_changed``),
  whatever the act: a ref is only meaningful against the outline it came
  from, and Enter activates whatever has the focus on the page open now,
  which must be the page the card showed. The digest is of the page's
  structure (which refs there are and what each is called:
  ``pagememory.outline_digest``), so a countdown, a typed value or a
  ticked box between the card and the owner's tap does not void the
  approval. A moved focus does not void an act on a ref either; it does
  void a key press, whose digest keeps the focus marker.

No card for a step that can only be refused. ``bind_async`` (the
executor's card-time bind) first runs the live checks the approved act
will run (``_live_rules``: the field, purchase and choice rules above)
and, when one refuses, answers that refusal instead of card arguments;
the runtime files it like a precheck refusal and makes no card, so the
owner is never asked to approve a step that is then refused. A ref that
no longer resolves, and a page that is no longer the one the model
looked at (judging a click scrolls its target into view, as the click
will), are answered the same way, as ``stale_ref``: the model looks
again and asks again. A ``use_checkout`` refusal logs one line,
``browser_act_use_checkout``: the rule that refused and what was
judged, as booleans, never the page's words.

Two sentences on every refusal. ``error`` is for the model and may name
the tool to call next; ``reason`` is for the person (``_REASONS``, and
``markers.USE_CHECKOUT_REASON``): why the step was not done and what
happens next, with no tool named, since the chat quotes it to the owner.

What may run with no card. The owner can allow clicks on a site for an
hour (``services/agent/app_approvals``); nobody looks at the acts that
then run, so which ones count is decided here from the live page, never
by the model. ``bind_async`` stores ``_page.quiet``: True only for a
click, a select or a check by ref, or a press of Tab, Escape, ArrowDown
or ArrowUp, that passed the live rules, on an https page of which every
frame was read and none shows an order total, a payment method on file
or a wallet, whose card carries no money warning, and whose target sends
no form by any method (``markers``' ``sends`` and ``submits``), is aimed
at no order path and has words that read as no purchase, wallet or price
(``_quiet``). A control with no words is not quiet, a plain link aside.
Typing, a submit and Enter never are. Anything that could not be judged
is not quiet, ``bind`` (no browser) never says it, and a ``_page`` the
call brings itself is refused by ``precheck`` and replaced by the bind.

The owner can also leave "Ask before every website step" off (its
default): an errand step then runs with no card at all, and only outcomes
get one. ``bind_async`` stores ``_page.errand`` beside ``quiet``, from the
same live page (``_errand``): on an https page that shows no order total
and no payment method on file (a wallet button elsewhere on it does not
count), a key that only moves; typing into search boxes, quantities, zip
or promo fields only (``_page.fields``, their kinds); a site search sent
by GET; a plain link; and, on a page that declares English, a choice or a
click whose words, as a person reads them (never a name or id attribute),
read as no outcome and no purchase (services/agent/app_approvals
``errand_outcome``), a POST button or a script button in a form only when
its words are cart words or "Check out" sent to a cart, and a cookie
banner's own Agree, Accept, Yes or OK in a region that says cookies (its
POST form only to a cookie or consent address). ``target`` then carries
the control's words (``words``, and ``consent``) for the runtime's own
check (``app_approvals.errand_covers``). Pays, sends, posts, deletes,
cancels, signs, agrees, consents or types a person's details: a card, as
before. A plain link worded like a purchase ("Place order", "Buy
tickets") gets its card too: a page's script can take it over. The words
only choose which steps are tried unasked; the guard is what holds. A
step the runtime runs with no card (an errand step, a site approval's
click) comes marked unasked (``app_approvals.UNASKED_MARK``) and runs
with the guard's ``no_orders`` until its page has gone quiet
(``UNASKED_QUIET_S``; a plain link until its page commits a new
document): no order address or order step opens for it, its write window
included, no socket message goes out, and nothing of any frame or script
is sent but a GET, a request to a cart (a page script's only on a cart
step), or its own form when the card judged that form by cart words or
as a cookie choice (``_unasked_sends``, from the form address the card
pinned; a live form that goes elsewhere is refused as
``outline_changed``); every redirect hop of what it sends or loads is
judged, and a beacon is held back. One stopped so is refused as
``auto_submit`` and asks with a card the next time it comes on that page
(by the page's path and the control's name), so a word missing from the
lists costs one card; one whose own send already went out is done, with
a note, so it is never taken twice.

Every card shows the owner the page. ``bind_async`` then takes a
screenshot of the page as it is when the card is made, with the target
outlined in a 3px red box (an overlay added and removed around the
capture) and secret fields masked by the shared mask (an errand step
that runs unasked drops its picture when it runs),
keeps it in memory only (``approval_image`` serves it to the web card and
the Telegram photo; it is never stored with the card) and adds to the
card's sentence, from the page's own facts, the line "This page shows
$499.00 and a saved payment method. This step may place an order. Crawler
normally pays only through its checkout step." whenever any frame shows
an order total, a payment method on file or a wallet button, or the
target matches a purchase pattern that did not refuse it. A capture that
fails leaves the card with "No picture of the page could be taken." So
no act that could move money runs without the owner having seen the page
on its card (an errand step needs a page with nothing to pay); the rules
above are defence in depth. A card whose
picture is no longer kept (its approval outlived it, more cards were
pending than are kept, Crawler restarted) says so and its act is refused
(``picture_gone``).

The egress guard's ``write_allowed`` is raised only around an approved
act meant to send (a click, a submit or an Enter that passed the rules
above, a plain link excepted), so the POST navigation it starts passes the
route guard, and lowered again in ``finally``; it opens for the card's
page only (``write_page``), never for another tab. Every other act (a fill, a
check, a select, another key, a plain link) runs with the window shut and
the guard's ``changing`` set: a page whose script sends its form on that
change, from any frame, or opens an order address or sends a request
to one (a ``fetch()``), is stopped, and the act is refused as
``auto_submit`` with one plain sentence (an unasked step: see above). An
act is the agent's next action on the
session, so it shuts a pending handoff's window first
(``_shared.take_back``); a challenge after an act hands the window to
the person the way browser.read's handoff does. Model text is not a secret:
``typed_secrets`` is untouched, and neither the text nor a field's value
ever appears in a summary, a log line or ``did``.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import urljoin

import structlog

from core.config import settings
from services.agent.app_approvals import (
    CHECKOUT_WORDS_RE,
    ERRAND_FIELD_KINDS,
    UNASKED_MARK,
    cart_words,
    consent_words,
    errand_money_ok,
    errand_outcome,
)
from services.tools.browser import _shared
from services.tools.browser import snapshot as snap
from services.tools.browser._shared import (
    REF_TIMEOUT_MS,
    HandoffDetector,
    PlaywrightError,
    PlaywrightTimeoutError,
)
from services.tools.browser.actions import (
    LOAD_QUIET_CAP_S,
    LOOP_REPEATS,
    NEW_TAB_WAIT_MS,
    BrowserReadToolkit,
    Guard,
    mode_for,
)
from services.tools.browser.checkout import markers
from services.tools.browser.checkout.amounts import fmt_usd, parse_money
from services.tools.browser.guard import (
    CART_ORDER_RE,
    CART_PATH_RE,
    SENDING_REASONS,
    UNASKED_HELD,
    UNASKED_REASONS,
    EgressHooks,
    page_place,
    wait_for_quiet,
)
from services.tools.browser.pagememory import (
    LastPage,
    PageMemory,
    _ref_names,
    outline_digest,
    page_address,
    page_origin,
)
from services.tools.browser.session import BrowserSession, BrowserSessionManager

logger = structlog.get_logger(__name__)

# The ``action`` enum of the flat browser.act schema (tool_registry).
ACT_ACTIONS: tuple[str, ...] = ("fill", "fill_form", "select", "check", "click", "press", "submit")
PRESS_KEYS: tuple[str, ...] = ("Enter", "Tab", "Escape", "ArrowDown", "ArrowUp")
MAX_FIELD_CHARS = 2000
MAX_FORM_FIELDS = 12
# The reserved argument an approval card stores the page under (bind); a
# call that carries it is refused before any card; only an approved act
# reads it.
CARD_KEY = "_page"
# How long an act waits for a navigation it may have started before the
# write window closes: a form POST is issued at the click, and the route
# guard reads ``write_allowed`` when the request is issued, not answered.
NAVIGATION_GRACE_MS = 300
# How long a step with no card keeps the guard's send stop on after it
# starts: until no request has been in flight for UNASKED_QUIET_S, at most
# UNASKED_QUIET_CAP_S, so a save the page debounces (450 ms, 700 ms) is
# still stopped. ponytail: a send delayed past the window goes out
# unstopped (SECURITY.md residuals); holding the stop for the page's life
# would break the pages that load their own data by POST.
UNASKED_QUIET_S = 1.0
UNASKED_QUIET_CAP_S = 2.0
_SUMMARY_LABEL_CHARS = 40
_NAMED_FIELDS_SHOWN = 3
# How many card pictures are kept at most across users; each is kept for
# the approval's own lifetime (``APPROVAL_TTL_MINUTES``).
_MAX_PICTURES = 32
# What a card says when its picture could not be taken: the owner then
# knows to look at the browser window before approving.
NO_PICTURE_NOTE = "No picture of the page could be taken."
# What a card says once its picture is no longer kept; its act is then
# refused, since the owner could not have seen the page on it.
PICTURE_GONE_NOTE = "The picture of the page is no longer kept, so this step will not run."
_PICTURE_GONE = (
    "The picture of the page on this approval is no longer kept, so the action was not run. "
    "Look at the page and ask again."
)
# The end of the money warning an act card carries (``_money_warning``).
MAY_ORDER_NOTE = (
    "This step may place an order. Crawler normally pays only through its checkout step."
)
# The red box drawn around the target for the card's picture: an overlay
# on top of the page (never a change to the element itself), removed
# again right after the capture.
_OUTLINE_ATTRIBUTE = "data-crawler-outline"
_OUTLINE_FN = f"""(el => {{
  const r = el.getBoundingClientRect();
  const doc = el.ownerDocument || document;
  const box = doc.createElement('div');
  box.setAttribute('{_OUTLINE_ATTRIBUTE}', '');
  box.setAttribute('aria-hidden', 'true');
  const style = {{
    position: 'fixed', left: (r.left - 3) + 'px', top: (r.top - 3) + 'px',
    width: r.width + 'px', height: r.height + 'px', border: '3px solid #ff0000',
    'box-sizing': 'content-box', margin: '0', padding: '0', background: 'transparent',
    'pointer-events': 'none', 'z-index': '2147483647', display: 'block',
  }};
  for (const [name, value] of Object.entries(style)) box.style.setProperty(name, value, 'important');
  (doc.body || doc.documentElement).appendChild(box);
  return true;
}})"""
_OUTLINE_JS = f"el => {_OUTLINE_FN}(el)"
# Enter has no ref: the box goes around what has the focus.
_OUTLINE_FOCUS_JS = f"""() => {{
  const el = ({markers.FOCUSED_JS})();
  if (!el || el === document.body || el === document.documentElement) return false;
  return {_OUTLINE_FN}(el);
}}"""
_REMOVE_OUTLINE_JS = (
    f"() => {{ for (const n of document.querySelectorAll('[{_OUTLINE_ATTRIBUTE}]')) n.remove(); }}"
)

_ACT_PARAMS: dict[str, frozenset[str]] = {
    "fill": frozenset({"ref", "text"}),
    "fill_form": frozenset({"fields"}),
    "select": frozenset({"ref", "value"}),
    "check": frozenset({"ref"}),
    "click": frozenset({"ref"}),
    "press": frozenset({"key"}),
    "submit": frozenset({"ref"}),
}
# Acts that write a value into a field: the secure-field rules apply.
_TYPING_ACTIONS = frozenset({"fill", "fill_form", "select"})
# Acts that can send a form: the purchase rules apply to their target.
_SENDING_ACTIONS = frozenset({"click", "submit", "press"})
# Acts that choose something on the page: the purchase rules apply to
# what they choose and to the page around it.
_CHOICE_ACTIONS = frozenset({"check", "select"})
# Acts made on one control by ref, whose card stays good while that control
# is still on the page under its name (``_check_outline``).
_SAME_TARGET_ACTIONS = frozenset({"click", "check", "select"})
# How many frames deep Enter's focus is followed before it is refused.
_MAX_FRAME_DEPTH = 4

_SECURE_MESSAGE = (
    "That is a password or card field, and Crawler never types into one from chat. "
    "Card details are filled from the vault during checkout."
)
_INSECURE_MESSAGE = (
    "This page is not encrypted (http://), so Crawler will not type or click on it. "
    "Use the https:// address of the site."
)
_NEEDS_OBSERVE = (
    "Look at the page first (browser.read open or snapshot) so this action can be tied "
    "to what is on it."
)
_CANCELLED = "The person stopped this task; nothing was done."
_UNBOUND = (
    "This action was approved without the page it was made for, so it was not run. "
    "Look at the page and ask again."
)
_PAGE_CHANGED = (
    "The page changed since this was approved (a different site is open now). Look again first."
)
_OUTLINE_CHANGED = (
    "The page changed since this was approved, so its refs may point elsewhere. Look again first."
)
_PAGE_MOVED = (
    "The page changed since this was approved (it is not the page the card showed). Look again first."
)
_AUTO_SUBMIT = "That change tried to send the page. Crawler didn't let it."
# A step that ran with no card and tried to reach an order address, or to
# send what a choice changed: it asks with a card when it comes again.
# What an "Add to cart" click's result says comes next.
CART_NEXT_STEP = (
    "It is in the cart. If the person asked you to order or buy it, keep going without asking in "
    "chat: open the cart, go to checkout, and on the final review page (the total, how it is paid "
    "and the order button) call browser.checkout. The person approves the purchase there, once. "
    "If they only asked you to add it or to look, tell them it is in the cart."
)
_UNASKED_STOPPED = (
    "That step tried to send something or reach an order address, so it was not taken "
    "without asking. Call browser.act again with the same arguments: the person is then "
    "asked on a request that shows the page."
)
_UNASKED_REASON = (
    "That step tried to send something, so I didn't take it on my own. I'll ask you first."
)
# What an unasked step that went through says when the guard held back
# something else its page sent meanwhile (a beacon, a request the step
# does not need): the step is done, and must not be taken again.
_HELD_NOTE = (
    "The step went through. Something else the page sent while it ran was held back; "
    "do not repeat the step for that."
)
# How many such steps are remembered per person (``_ask_first``).
_ASK_FIRST_KEPT = 16
_NEW_TAB_DEAD = "The page that step opened in a new tab did not load."
# What the PERSON reads when a rule refuses a step (``reason`` on every
# refusal; the chat's "I didn't click on the page." line quotes it). The
# texts above are for the model and may name the tool to call next; these
# say why the step wasn't done and what happens next, in the owner's
# words (docs/bot-message-style.md), and never hold anything of the page.
_REASONS: dict[str, str] = {
    "invalid_arguments": "I didn't set that step up right, so nothing happened.",
    "check_failed": "I couldn't check that step first, so I left it.",
    "cancelled": "You asked me to stop, so I left the page as it is.",
    "needs_observe": "I need to look at the page before I can do that. I'll look first.",
    "stale_ref": "The page changed before I could do that. I'll look at it again.",
    "secure_field": (
        "That's a password or card field, and I never type into those. "
        "Card details only go in during my payment step, after you approve."
    ),
    "use_checkout": markers.USE_CHECKOUT_REASON,
    "insecure_page": "That page isn't encrypted, so I don't type or click on it.",
    "unbound_approval": (
        "I couldn't match that approval to a page, so I left it. "
        "I'll look at the page and ask you again."
    ),
    "picture_gone": (
        "The picture of the page on that request is gone, so I left it. "
        "I'll look at the page and ask you again."
    ),
    "page_changed": "A different site is open now, so I left it. I'll look at the page again.",
    "outline_changed": "The page changed before I could do that. I'll look at it again.",
    "auto_submit": "That change tried to send the page, and I didn't let it.",
}
_REASON_FALLBACK = "I couldn't do that step, so nothing happened."
# What a site approval may run with no card when the live page agrees
# (``_quiet``): a click or a choice by ref, and the keys that only move
# the focus or close something. Typing, a submit and Enter keep their card.
_QUIET_ACTIONS = frozenset({"click", "select", "check"})
_QUIET_KEYS = frozenset({"Tab", "Escape", "ArrowDown", "ArrowUp"})
# What an errand step may type into (``_errand``), judged by the field's own
# name, id, placeholder, labels and autocomplete token on the live page: a
# site's search box, a quantity, a zip or postal code, a promo code. Words
# that ask for the person's own details win over all of them, and so does
# the card-field classifier; an autocomplete token other than a postal code
# names a detail too ("email", "street-address", "bday").
_DETAILS_WORDS = re.compile(
    r"name|e ?mail|phone|mobile|\btel\b|address|street|\bcity\b|birth|\bdob\b|card|account"
    r"|\biban\b|routing|\bssn\b|social security|passport|licen[cs]e|login|password|passcode|\bpin\b"
)
_SEARCH_WORDS = re.compile(r"search|query|keyword|\bfind\b")
_QUANTITY_WORDS = re.compile(r"quantity|\bqty\b")
_ZIP_WORDS = re.compile(r"zip|postal|post ?code")
_PROMO_WORDS = re.compile(r"promo|coupon|voucher|discount")


def _js(pattern: re.Pattern[str]) -> str:
    return f"new RegExp({json.dumps(pattern.pattern)}, 'i')"


_ERRAND_FIELD_FN = (
    r"""(el => {
  const secret = __SECRET__;
  try {
    if (!el || !el.tagName) return '';
    const tag = el.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'textarea') return '';
    const type = (el.getAttribute('type') || 'text').toLowerCase();
    if (tag === 'input' && !['text', 'search', 'number', 'tel'].includes(type)) return '';
    if (secret(el)) return '';
    const a = n => el.getAttribute(n) || '';
    let labels = '', byId = '';
    try { labels = [...(el.labels || [])].map(l => l.innerText).join(' '); } catch (e) {}
    try {
      const root = el.getRootNode && el.getRootNode().getElementById ? el.getRootNode() : document;
      byId = a('aria-labelledby').split(/\s+/).filter(Boolean)
        .map(id => { const n = root.getElementById(id); return n ? n.textContent : ''; }).join(' ');
    } catch (e) {}
    const words = [a('name'), a('id'), a('placeholder'), a('aria-label'), a('title'), byId, labels]
      .join(' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_.-]+/g, ' ').toLowerCase();
    const auto = (a('autocomplete').trim().toLowerCase().split(/\s+/).pop()) || '';
    if (!['', 'on', 'off', 'postal-code'].includes(auto) || __DETAILS__.test(words)) return '';
    if (a('role').toLowerCase() === 'searchbox' || type === 'search' || __SEARCH__.test(words)) return 'search';
    if (tag === 'textarea') return '';
    if (__QUANTITY__.test(words)) return 'quantity';
    if (auto === 'postal-code' || __ZIP__.test(words)) return 'zip';
    if (__PROMO__.test(words)) return 'promo';
    return '';
  } catch (e) { return ''; }
})"""
    .replace("__SECRET__", markers.FIELD_KIND_FN)
    .replace("__DETAILS__", _js(_DETAILS_WORDS))
    .replace("__SEARCH__", _js(_SEARCH_WORDS))
    .replace("__QUANTITY__", _js(_QUANTITY_WORDS))
    .replace("__ZIP__", _js(_ZIP_WORDS))
    .replace("__PROMO__", _js(_PROMO_WORDS))
)
# ``locator.evaluate(ERRAND_FIELD_JS)``: that kind for one field, or "".
_ERRAND_FIELD_JS = f"el => {_ERRAND_FIELD_FN}(el)"
# A site search: a form whose every field a person types into is one of
# those (a department <select>, ticks, radios and hidden fields aside).
# Whether it is sent by GET is the judge's ``sends``, not asked here.
_ERRAND_FORM_FN = f"""(form => {{
  const field = {_ERRAND_FIELD_FN};
  if (!form) return false;
  try {{
    for (const f of form.elements) {{
      const tag = f.tagName.toLowerCase();
      const type = (f.getAttribute('type') || '').toLowerCase();
      if (['button', 'fieldset', 'output', 'object', 'select'].includes(tag)) continue;
      if (tag === 'input' && ['hidden', 'submit', 'button', 'reset', 'image', 'checkbox', 'radio']
          .includes(type)) continue;
      if (!field(f)) return false;
    }}
    return true;
  }} catch (e) {{ return false; }}
}})"""
# ``locator.evaluate``: the form a submit or a click on the element sends.
_ERRAND_FORM_JS = f"""el => {{
  const control = (el.closest && el.closest('button, input')) || el;
  return {_ERRAND_FORM_FN}(control.form || el.form || (el.closest ? el.closest('form') : null));
}}"""
# ``frame.evaluate``: the form Enter sends from the focus in the top page;
# a focus inside a frame is no site search here.
_ERRAND_ENTER_JS = f"""() => {{
  const el = ({markers.FOCUSED_JS})();
  if (!el || !el.tagName || ['iframe', 'frame'].includes(el.tagName.toLowerCase())) return false;
  return {_ERRAND_FORM_FN}(el.form || el.closest('form'));
}}"""
# The page's own language, for the English word lists (``_lang_is_english``).
_PAGE_LANG_JS = "() => (document.documentElement.getAttribute('lang') || '').trim().toLowerCase()"
# The words a person reads on a control: its aria-label, the text it is
# labelled by, its <label> (without the fields inside it), its own text, a
# button input's value, its title, and the option a select chooses. Never
# its name or id attributes, which nobody reads (Amazon's "Add to Cart" is
# name="submit.add-to-cart").
_HUMAN_WORDS_FN = r"""((node, choice) => {
  if (!node || !node.getAttribute) return '';
  const clean = s => (s || '').replace(/\s+/g, ' ').trim();
  const a = n => node.getAttribute(n) || '';
  const tag = node.tagName.toLowerCase(), type = a('type').toLowerCase();
  let byId = '', labels = '';
  try {
    const root = node.getRootNode && node.getRootNode().getElementById ? node.getRootNode() : document;
    byId = a('aria-labelledby').split(/\s+/).filter(Boolean)
      .map(id => { const n = root.getElementById(id); return n ? n.textContent : ''; }).join(' ');
  } catch (e) {}
  try {
    labels = [...(node.labels || [])].map(label => {
      const copy = label.cloneNode(true);
      copy.querySelectorAll('input, select, textarea, button').forEach(n => n.remove());
      return copy.textContent;
    }).join(' ');
  } catch (e) {}
  const parts = [a('aria-label'), byId, labels, tag === 'select' ? '' : node.innerText, a('title')];
  if (tag === 'input' && ['submit', 'button', 'reset', 'image'].includes(type)) parts.push(node.value, a('alt'));
  parts.push(choice || '');
  return parts.map(clean).filter((v, i, all) => v && all.indexOf(v) === i).join(' | ').slice(0, 400);
})"""
# Whether a control sits in a cookie banner: the nearest dialog, region,
# aside, element named for cookies or consent, or form sent to a cookie or
# consent address, whose label, name, address or text says cookies. One
# that says consent alone (an OAuth screen, a terms dialog) is no banner.
_CONSENT_REGION_FN = r"""(node => {
  try {
    const box = node.closest('dialog, [role=dialog], [role=alertdialog], [aria-modal=true], [role=region], '
      + 'aside, [id*=cookie i], [class*=cookie i], [id*=consent i], [class*=consent i], '
      + 'form[action*=cookie i], form[action*=consent i]');
    if (!box) return false;
    const said = [box.getAttribute('aria-label'), box.id, box.getAttribute('class'),
                  box.getAttribute('action'), (box.innerText || '').slice(0, 3000)].join(' ');
    return /cookie/i.test(said);
  } catch (e) { return false; }
})"""
# The address a cookie banner's own POST form may be sent to and still be
# a cookie choice: a cookie or consent preferences address (/cookieprefs).
_COOKIE_ADDRESS_RE = re.compile(r"cookie|consent", re.IGNORECASE)
# ``locator.evaluate(_ERRAND_WORDS_JS, [action, value])``: the words and the
# region of the control the act is judged by, as the live rules find it (a
# click: the control the click lands on; a submit: the button that sends
# the form; a choice: the field itself, with the option it chooses).
_ERRAND_WORDS_JS = f"""(el, [action, value]) => {{
  const words = {_HUMAN_WORDS_FN};
  const consent = {_CONSENT_REGION_FN};
  try {{
    let control = el, choice = '';
    if (action === 'click') {{
      const hit = {markers._HIT_FN}(el);
      if (!hit) return null;
      control = {markers._ACTIVATED_FN}(hit);
    }} else if (action === 'submit') {{
      const form = el.form || el.closest('form');
      const tag = el.tagName.toLowerCase(), type = (el.getAttribute('type') || '').toLowerCase();
      const own = ((tag === 'button' && (type === '' || type === 'submit'))
        || (tag === 'input' && (type === 'submit' || type === 'image'))) && el.form === form;
      control = form && !own ? {markers.DEFAULT_BUTTON_FN}(form) : el;
    }} else if (action === 'select') {{
      const want = String(value || '').replace(/\\s+/g, ' ').trim();
      const chosen = [...el.options].find(o => o.value === String(value || '')
        || o.label.replace(/\\s+/g, ' ').trim() === want || o.text.replace(/\\s+/g, ' ').trim() === want);
      choice = chosen ? chosen.text : '';
    }}
    return {{ words: words(control, choice), consent: !!control && consent(control) }};
  }} catch (e) {{ return null; }}
}}"""


def _lang_is_english(lang: str) -> bool:
    """Whether a page's declared language is English, which the word lists
    are in. A page that names none is in a language nobody knows."""
    lang = lang.strip().lower()
    return lang == "en" or lang.startswith("en-")
# A submit through an element: a submit control sends its form as itself;
# anything else sends it through the form's default button, the one
# ``markers.SUBMIT_TARGET_JS`` judged (so the formaction and the words
# sent are the ones judged), or with none when the form has no button.
_SUBMIT_JS = f"""
el => {{
  const form = el.form || el.closest('form');
  if (!form) return false;
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const own = ((tag === 'button' && (type === '' || type === 'submit'))
    || (tag === 'input' && (type === 'submit' || type === 'image'))) && el.form === form;
  const submitter = own ? el : {markers.DEFAULT_BUTTON_FN}(form);
  if (typeof form.requestSubmit === 'function') {{
    submitter ? form.requestSubmit(submitter) : form.requestSubmit();
  }} else {{
    form.submit();
  }}
  return true;
}}
"""


class _Refused(Exception):
    """A rule refused the act: the result is ``{ok, refused, rule, error,
    reason}``: ``error`` for the model, ``reason`` for the person."""

    def __init__(self, rule: str, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.rule = rule
        self.message = message
        self.extra = extra

    def result(self) -> dict[str, Any]:
        return {
            "ok": False,
            "refused": True,
            "rule": self.rule,
            "error": self.message,
            "reason": _REASONS.get(self.rule, _REASON_FALLBACK),
            **self.extra,
        }


class _Done(Exception):
    """An act that ended early with a browser.read-shaped result (a stale
    ref, a network-policy refusal), raised out of the perform step."""

    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__(result.get("error"))
        self.result = result


@dataclass(frozen=True)
class _Request:
    action: str
    ref: Optional[str] = None
    text: Optional[str] = None
    fields: tuple[tuple[str, str], ...] = ()
    value: Optional[str] = None
    key: Optional[str] = None

    @property
    def refs(self) -> tuple[str, ...]:
        if self.action == "fill_form":
            return tuple(ref for ref, _text in self.fields)
        return (self.ref,) if self.ref is not None else ()


@dataclass(frozen=True)
class _Bound:
    origin: str
    outline: str
    scheme: str
    # page_address of the page's URL; None on a card bound before the
    # address was kept (the outline and origin checks still apply).
    address: Optional[str] = None
    # The outline name of the one control a click, a choice or a tick is
    # made on, as the card's page had it; None for every other act.
    ref_name: Optional[str] = None


def _invalid(message: str) -> _Refused:
    return _Refused("invalid_arguments", message)


# What a ``use_checkout`` refusal's log line says of the judged target:
# these facts as booleans, never its words, its address or the page's text.
_JUDGED_FACTS: tuple[str, ...] = (
    "link", "plain_link", "buttonish", "sends", "in_form", "card_in_form",
    "order_total", "saved_payment", "wallet", "money",
)


def _use_checkout(action: str, why: str, target: object = None) -> _Refused:
    """The refusal of a step that would pay, logged once on the way: the
    rule that refused (*why*: a ``markers.pay_rule`` name, or ``choice``
    for a check or a select) and what was judged (*target*, when the live
    page was asked), so a refusal the owner asks about can be traced to
    its rule. Rule names and booleans only."""
    judged = isinstance(target, dict)
    facts: Mapping[str, Any] = target if isinstance(target, dict) else {}
    # Before the card only the outline's names were read: no target then.
    words = why == "purchase_words" or markers.PURCHASE_RE.search(str(facts.get("name") or ""))
    logger.info(
        "browser_act_use_checkout",
        action=action,
        rule="use_checkout",
        why=why,
        judged=judged,
        purchase_words=bool(words),
        **{key: bool(facts.get(key)) for key in _JUDGED_FACTS},
    )
    return _Refused("use_checkout", markers.USE_CHECKOUT_MESSAGE)


def _text_arg(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise _invalid(f"{what} must be text (up to {MAX_FIELD_CHARS} characters).")
    if len(value) > MAX_FIELD_CHARS:
        raise _invalid(f"{what} is too long ({len(value)} characters; at most {MAX_FIELD_CHARS}).")
    if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t" for ch in value):
        raise _invalid(f"{what} may not contain control characters other than newlines and tabs.")
    return value


def _ref_arg(value: Any) -> str:
    if not _shared.valid_ref(value):
        raise _invalid("ref must be a ref from the latest outline, e.g. e7.")
    return str(value)


def _parse(params: Mapping[str, Any]) -> _Request:
    """Validate a browser.act call's arguments. Touches nothing; refuses
    an argument the action does not take, the reserved card key included."""
    action = params.get("action")
    if not isinstance(action, str) or action not in ACT_ACTIONS:
        raise _invalid(f"action must be one of: {', '.join(ACT_ACTIONS)}.")
    allowed = _ACT_PARAMS[action]
    extra = sorted(str(k) for k in params if k not in allowed and k != "action")
    if extra:
        raise _invalid(f"browser.act {action} does not take: {', '.join(extra)}.")
    if action == "fill":
        return _Request(
            action, ref=_ref_arg(params.get("ref")), text=_text_arg(params.get("text"), "text")
        )
    if action == "fill_form":
        fields = params.get("fields")
        if not isinstance(fields, (list, tuple)) or not fields:
            raise _invalid("fill_form needs fields: a list of {ref, text}.")
        if len(fields) > MAX_FORM_FIELDS:
            raise _invalid(
                f"fill_form takes at most {MAX_FORM_FIELDS} fields ({len(fields)} given)."
            )
        parsed: list[tuple[str, str]] = []
        for item in fields:
            if not isinstance(item, Mapping) or set(item) - {"ref", "text"}:
                raise _invalid("each field must be {ref, text}.")
            parsed.append(
                (_ref_arg(item.get("ref")), _text_arg(item.get("text"), "a field's text"))
            )
        if len({ref for ref, _ in parsed}) != len(parsed):
            raise _invalid("fill_form lists the same ref twice.")
        return _Request(action, fields=tuple(parsed))
    if action == "select":
        value = params.get("value")
        if not isinstance(value, str) or not value.strip():
            raise _invalid("select needs value: the option's label or value.")
        return _Request(action, ref=_ref_arg(params.get("ref")), value=_text_arg(value, "value"))
    if action == "press":
        key = params.get("key")
        if key not in PRESS_KEYS:
            raise _invalid(f"key must be one of: {', '.join(PRESS_KEYS)}.")
        return _Request(action, key=str(key))
    return _Request(action, ref=_ref_arg(params.get("ref")))


def _bound_page(card: Any) -> Optional[_Bound]:
    """The page an approval card was made from, as ``bind`` stored it,
    or None when *card* is not that."""
    if not isinstance(card, Mapping):
        return None
    origin, outline, scheme = card.get("origin"), card.get("outline"), card.get("scheme")
    if not all(isinstance(v, str) for v in (origin, outline, scheme)):
        return None
    address = card.get("address")
    if address is not None and not isinstance(address, str):
        return None
    ref_name = card.get("ref_name")
    return _Bound(
        str(origin), str(outline), str(scheme), address, ref_name if isinstance(ref_name, str) else None
    )


def _host(origin: str) -> str:
    return origin.partition("://")[2] if "://" in origin else ""


def _short(value: str) -> str:
    """Page- or model-supplied text as a sentence may quote it: one line,
    short (cards and summaries stay in context)."""
    value = " ".join(value.split())
    if len(value) > _SUMMARY_LABEL_CHARS:
        value = value[: _SUMMARY_LABEL_CHARS - 1] + "…"
    return value


def _characters(count: int) -> str:
    return "1 character" if count == 1 else f"{count} characters"


def _target(ref: str, names: Mapping[str, str]) -> str:
    """The control as the card names it: its own words in quotes, or
    "an unnamed control" (a seat on a seat map, an icon with no label).
    Never its ref: that is an internal id, and the card's picture shows
    which control is meant."""
    name = _short(names.get(ref) or "")
    return f'"{name}"' if name else "an unnamed control"


# A button's own words that say nothing of what it acts on ("Add to cart"
# under each of four products): its card also names the item it sits with.
_ITEM_WORDS = re.compile(r"\b(?:add|cart|basket|bag|buy|select|choose|pick|order|book|reserve|get|view)\b", re.I)
# The nearest heading around a control that is not inside it: a product's
# name in a search result, the title of a product page.
_ITEM_NAME_JS = """el => {
  for (let node = el.parentElement, depth = 0; node && depth < 12; node = node.parentElement, depth++) {
    const heading = node.querySelector('h1, h2, h3, h4, [role=heading]');
    if (heading && !heading.contains(el) && !el.contains(heading)) {
      const text = (heading.innerText || heading.textContent || '').replace(/\\s+/g, ' ').trim();
      if (text.length >= 3) return text.slice(0, 300);
    }
  }
  return '';
}"""


def _sentence(
    request: _Request, names: Mapping[str, str], on_host: str, item: str = ""
) -> str:
    """The approval-card sentence, built from facts the page memory holds,
    never from the model's words: the element's name, the count of
    characters (not the text), the key, the host, and for a click whose
    button names no item, the item it sits with (*item*, read off the page
    by ``bind_async``)."""
    action = request.action
    if action == "fill":
        count = len(request.text or "")
        target = _target(request.ref or "", names)
        return (
            f"Clear {target}{on_host}"
            if count == 0
            else f"Type {_characters(count)} into {target}{on_host}"
        )
    if action == "fill_form":
        shown = [_short(names.get(ref) or "") or ref for ref in request.refs[:_NAMED_FIELDS_SHOWN]]
        more = "…" if len(request.refs) > _NAMED_FIELDS_SHOWN else ""
        return f"Fill {len(request.refs)} fields{on_host}: {', '.join(shown)}{more}"
    target = _target(request.ref or "", names)
    if action == "select":
        return f'Select "{_short(request.value or "")}" in {target}{on_host}'
    if action == "check":
        return f"Check {target}{on_host}"
    if action == "click":
        about = f' for "{_short(item)}"' if item else ""
        return f"Click {target}{about}{on_host}"
    if action == "press":
        return f"Press {request.key}{on_host}"
    return f"Submit the form with {target}{on_host}"


def _and_list(parts: Sequence[str]) -> str:
    return parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])} and {parts[-1]}"


def _money_warning(money: Mapping[str, Any]) -> str:
    """The money line of an act card, from the facts ``bind_async`` read
    off the page: what the page shows (the total's amount when it could be
    read, a payment method on file, a wallet button), then that the step
    may place an order. Nothing in it comes from the model."""
    shown: list[str] = []
    amount = money.get("amount")
    if isinstance(amount, str) and amount:
        shown.append(amount)
    elif money.get("order_total"):
        shown.append("an order total")
    if money.get("saved_payment"):
        shown.append("a saved payment method")
    if money.get("wallet"):
        shown.append("a wallet payment button")
    if shown:
        lead = f"This page shows {_and_list(shown)}. "
    elif money.get("unread"):
        lead = "Part of this page could not be read. "
    else:
        lead = ""
    return lead + MAY_ORDER_NOTE


def _card_notes(card: Any) -> str:
    """What an act card adds after its sentence, from the page facts
    ``bind_async`` stored with it: the money warning, and the note that no
    picture could be taken. "" for a card bound without them."""
    if not isinstance(card, Mapping):
        return ""
    notes: list[str] = []
    money = card.get("money")
    if isinstance(money, Mapping):
        notes.append(_money_warning(money))
    if "picture" in card and not card.get("picture"):
        notes.append(NO_PICTURE_NOTE)
    return "".join(f" {note}" for note in notes)


def _amount_text(frames: Sequence[Mapping[str, Any]]) -> str:
    """The order total's amount as the page writes it, parsed ("$499.00",
    "23.40 EUR"), from the first frame that shows one; "" when none can
    be read."""
    for facts in frames:
        line = facts.get("total_line")
        money = parse_money(line) if isinstance(line, str) and line else None
        if money is not None:
            amount = fmt_usd(money.amount)
            return f"${amount}" if money.currency == "USD" else f"{amount} {money.currency}"
    return ""


def _nothing_to_pay(scheme: str, answers: Sequence[Any], money: Optional[Mapping[str, Any]]) -> bool:
    """The page half of what may run with no card: https, a card that would
    warn of no money (*money*), and every frame read (*answers*) with none
    showing an order total, a payment method on file or a wallet. A fact
    that is missing counts as shown."""
    if money is not None or scheme != "https" or not answers:
        return False
    for facts in answers:
        if not isinstance(facts, Mapping) or facts.get("unread"):
            return False
        if any(facts.get(key, True) for key in ("order_total", "saved_payment", "wallet")):
            return False
    return True


def _quiet(
    request: _Request,
    scheme: str,
    judged: Optional[Mapping[str, Any]],
    answers: Sequence[Any],
    money: Optional[Mapping[str, Any]],
) -> bool:
    """Whether a site approval may run this act with no card: it only
    clicks around. Decided here, from the live page as ``bind_async`` read
    it, never from the call: the act is a click or a choice by ref, or a
    key that only moves; the page is https; the card warns of no money
    (*money*); every frame was read (*answers*) and none shows an order
    total, a payment method on file or a wallet; and the target (*judged*:
    what the live rules judged for a click, or what a check or a select
    chooses; a key has none) sends no form by any method, is aimed at no
    order path, sits next to no typed card, and has words that read as no
    purchase, wallet or price. A control with no words at all is not
    quiet either, a plain link aside (it is followed by GET whatever it
    says), and neither is a button inside a form (a script can send the
    form; only a native submit says so). Anything missing counts against
    it: nobody looks at a quiet act."""
    if not _nothing_to_pay(scheme, answers, money):
        return False
    if request.action == "press":
        return request.key in _QUIET_KEYS
    if request.action not in _QUIET_ACTIONS or not isinstance(judged, Mapping):
        return False
    name = judged.get("name")
    if not isinstance(name, str) or markers.PURCHASE_RE.search(name):
        return False
    if markers.WALLET_RE.search(name) or markers.priced_control(name):
        return False
    if request.action != "click":
        return bool(name)
    if judged.get("sends") is not False or judged.get("submits") is not False:
        return False
    if judged.get("in_form", True) and judged.get("plain_link") is not True:
        # A script button inside a form can send it; only a native submit
        # says so (``sends``), so such a click keeps its card.
        return False
    if judged.get("card_in_form", True) or any(
        markers.ORDER_ACTION_RE.search(str(judged.get(key) or "")) for key in ("href", "action")
    ):
        return False
    return bool(name) or judged.get("plain_link") is True


def _errand_page(scheme: str, answers: Sequence[Any], money: Any) -> bool:
    """The page half of an errand step: https, every frame read (*answers*)
    and none showing an order total or a payment method on file, and a card
    whose money facts (*money*) show nothing to pay
    (``app_approvals.errand_money_ok``). A wallet button elsewhere on the
    page is no reason to ask: most shops show one next to "Add to cart",
    the wallet button itself is refused, and an unasked step reaches no
    order address. A fact that is missing counts as shown."""
    if scheme != "https" or not answers or not errand_money_ok(money):
        return False
    return all(
        isinstance(facts, Mapping) and not facts.get("unread")
        and not facts.get("order_total", True) and not facts.get("saved_payment", True)
        for facts in answers
    )


def _errand(
    request: _Request,
    scheme: str,
    judged: Optional[Mapping[str, Any]],
    answers: Sequence[Any],
    money: Optional[Mapping[str, Any]],
    *,
    fields: Sequence[str] = (),
    form_ok: bool = False,
    english: bool = False,
    words: Optional[str] = None,
    consent: bool = False,
) -> bool:
    """Whether this act is an errand step, one that commits the person to
    nothing and so may run with no card while "Ask before every website
    step" is off. Decided here from the live page as ``bind_async`` read it,
    never from the call, and checked again from what it wrote by
    ``app_approvals.errand_covers``. On an https page with nothing to pay
    (``_errand_page``; the purchase rules already refused what pays):

    - a key that only moves (Tab, Escape, ArrowDown, ArrowUp);
    - typing into fields that are each a search box, a quantity, a zip or
      postal code or a promo code (*fields*, one kind per field typed into;
      "" for any other);
    - a submit or Enter that sends a GET form whose fields are all those
      (*form_ok*: a site search), its button not worded as an outcome;
    - a plain link, unless its words are what a one-click link does by
      itself (unsubscribe, sign out, delete, cancel, accept, decline...)
      or a purchase (``markers.link_orders``: "Place order", "Book now";
      a ticket funnel's "Buy tickets" is none), which a page's script can
      make it do;
    - on a page that declares English (*english*: the word lists are
      English; a page that names no language is not), a choice or a click
      whose words read as no outcome (``app_approvals.errand_outcome``)
      and as no purchase or price: a button that sends a POST form, or a
      script button inside a form, only when its words are cart words
      (``cart_words``) or "Check out" sent to a cart; a form's own GET
      button only for a site search; a cookie banner's own Agree, Accept,
      Allow, Yes or OK in a region that says cookies (*consent*), a POST
      form's only when it is sent to a cookie or consent address; a
      control with no words never.

    The words judged are the ones a person reads on the control (*words*,
    never its name or id attributes), else the live rules' name. Anything
    missing counts against it. The words only choose which steps are tried
    unasked: one that runs sends nothing but to a cart or its own judged
    form and reaches no order address (the guard's ``no_orders``; a cart
    whose address names an order, ``CART_ORDER_RE``, is none)."""
    if not _errand_page(scheme, answers, money):
        return False
    action = request.action
    if action == "press" and request.key != "Enter":
        return request.key in _QUIET_KEYS
    if action in ("fill", "fill_form"):
        return len(fields) == len(request.refs) and all(k in ERRAND_FIELD_KINDS for k in fields)
    if not isinstance(judged, Mapping):
        return False
    if action in _SENDING_ACTIONS and markers.pay_rule(dict(judged)) is not None:
        return False  # the live rules refused it already; never unasked
    name = judged.get("name")
    if not isinstance(name, str):
        return False
    said = words if isinstance(words, str) else name
    if action == "click" and judged.get("plain_link") is True:
        # Worded like a purchase, a link gets its card: a page's script can
        # take it over and send the order (a single-page app's handler).
        return not errand_outcome(said, link=True) and not markers.link_orders(f"{name} | {said}")
    if action in _SENDING_ACTIONS and (
        markers.PURCHASE_RE.search(name) or markers.priced_control(name)
    ):
        return False  # worded like a purchase or a price: a person looks at it
    sends, submits, in_form = judged.get("sends"), judged.get("submits"), judged.get("in_form")
    if action in ("submit", "press"):
        return form_ok and submits is True and sends is False and not errand_outcome(said)
    if not said.strip() or not english:
        return False
    # A cookie choice: its words only agree, in a cookie banner, and a POST
    # form it sends goes to a cookie or consent address.
    consented = consent and consent_words(said) and (
        sends is False or bool(_COOKIE_ADDRESS_RE.search(str(judged.get("action") or "")))
    )
    if not consented and errand_outcome(said):
        return False
    if action in _CHOICE_ACTIONS:
        return True
    if not all(isinstance(fact, bool) for fact in (sends, submits, in_form)):
        return False
    if consented:
        return True
    if sends:
        path = str(judged.get("action") or "")
        to_cart = bool(CART_PATH_RE.search(path)) and not CART_ORDER_RE.search(path)
        return cart_words(said) or (to_cart and bool(CHECKOUT_WORDS_RE.search(said)))
    if submits:
        return form_ok
    # A script button inside a form can send it; outside one it only moves.
    return not in_form or cart_words(said)


def _unasked_sends(said: Any) -> frozenset[str]:
    """Where an unasked step's own form may send besides a cart (the
    guard's ``unasked_sends``): the path of the POST form the card was
    judged by, as the card pinned it (*said*, the card's ``target``, its
    ``action``), when the card's words for it are cart words or "Check
    out" sent to a cart, or a cookie
    choice and that path is a cookie or consent address. Nothing for
    anything else. ``_run`` refuses a step whose live form now goes
    elsewhere, so this is also where it goes."""
    if not isinstance(said, Mapping):
        return frozenset()
    path, words = said.get("action"), said.get("words", said.get("name"))
    if not isinstance(path, str) or not path or not isinstance(words, str):
        return frozenset()
    cookie = said.get("consent") is True and consent_words(words) and _COOKIE_ADDRESS_RE.search(path)
    # "Check out" sent to a cart (Shopify's cart form), as ``_errand`` judged it.
    to_cart = bool(CART_PATH_RE.search(path)) and not CART_ORDER_RE.search(path)
    checkout = to_cart and bool(CHECKOUT_WORDS_RE.search(words))
    return frozenset({path}) if cookie or cart_words(words) or checkout else frozenset()


def _cart_step(said: Any, fields: Any) -> bool:
    """Whether an unasked step is a cart step, whose page script may send
    to a cart (the guard's ``unasked_cart``): the card's words for its
    control (*said*, the card's ``target``) are cart words, a quantity
    select's among them, or it types only into quantity fields (*fields*,
    the card's kinds)."""
    if isinstance(fields, list) and fields and all(kind == "quantity" for kind in fields):
        return True
    words = said.get("words", said.get("name")) if isinstance(said, Mapping) else None
    return isinstance(words, str) and cart_words(words)


def _live_action(target: Optional[Mapping[str, Any]]) -> str:
    """The path the live control's form is sent to, "" when it sends none:
    what the card pins (``target.action``) and the unasked run compares."""
    if not isinstance(target, Mapping) or target.get("sends") is not True:
        return ""
    action = target.get("action")
    return action if isinstance(action, str) else ""


class BrowserActToolkit:
    """browser.act over the shared browser session.

    ``memory`` is the page memory browser.read writes and this toolkit
    both reads (precheck, bind, describe) and writes (after every act).
    ``cancel_flag(user_id)`` is True once the user's turn was stopped; it
    is checked before the card and again just before the act runs, and a
    flag that raises counts as set."""

    def __init__(
        self,
        sessions: BrowserSessionManager,
        *,
        guard: Guard,
        handoff: HandoffDetector,
        memory: PageMemory,
        cancel_flag: Callable[[str], bool],
        clock: Callable[[], float] = time.monotonic,
        picture_ttl_s: Optional[float] = None,
        egress_hooks: Optional[EgressHooks] = None,
    ) -> None:
        self._sessions = sessions
        self._guard = guard
        # Security wave (S4, S7): the owner's site rules and the link
        # lookup, bound to each context this toolkit guards (None: neither).
        self._egress_hooks = egress_hooks
        self._handoff = handoff
        self._memory = memory
        self._cancel_flag = cancel_flag
        self._clock = clock
        # A card's picture lives as long as the card can be approved.
        self._picture_ttl = (
            float(settings.APPROVAL_TTL_MINUTES) * 60.0 if picture_ttl_s is None else picture_ttl_s
        )
        # picture id -> (user_id, JPEG data URL, taken at): the pictures
        # the pending cards show, in memory only (never stored with a card).
        self._pictures: dict[str, tuple[str, str, float]] = {}
        # task_id -> keys of the last LOOP_REPEATS calls, newest last.
        self._recent: dict[str, list[str]] = {}
        # user_id -> the context the egress guard is installed on, by
        # identity (see BrowserReadToolkit._guarded).
        self._guarded: dict[str, Any] = {}
        # user_id -> the steps (``_step_key``: page path and control name,
        # never the ref) that, run with no card, tried to send or to reach
        # an order address: each asks with a card when it comes again on
        # that page (newest last, bounded).
        self._ask_first: dict[str, list[tuple[str, ...]]] = {}

    # -- the card's three hooks (no browser call) ------------------------------

    def precheck(self, params: Mapping[str, Any], *, user_id: str) -> Optional[dict[str, Any]]:
        """The refusal a browser.act call would get from the checks that
        need no browser (arguments, the stop flag, no page looked at yet,
        a ref the latest outline does not have, a secure field, a submit
        or a choice named like a purchase, an http:// page), or None. The
        runtime asks it before making an approval card, so a call it
        refuses never gets one, then asks the live page (``bind_async``);
        ``execute`` runs the same checks again. A check that fails refuses
        the call (rule ``check_failed``)."""
        try:
            if params is not None and not isinstance(params, Mapping):
                raise _invalid("browser.act arguments must be an object.")
            request = _parse(dict(params or {}))
            self._check_cancel(user_id)
            self._static_rules(request, self._memory.get(user_id))
        except _Refused as refusal:
            return refusal.result()
        except Exception as exc:  # fail closed: an unchecked act gets no card
            _shared.log_failure("browser_act_precheck_failed", exc)
            return _Refused(
                "check_failed",
                "Could not check this action before asking for approval, so nothing was done.",
            ).result()
        return None

    def bind(self, params: Mapping[str, Any], *, user_id: str) -> dict[str, Any]:
        """*params* as a browser.act approval card stores them: with the
        page the card is made from under ``CARD_KEY`` (origin, address,
        outline digest and scheme of *user_id*'s latest observation, all
        empty when there is none), replacing anything the call itself put
        there. The approved act then runs only on that page. A key press
        acts on whatever has the focus, so its digest keeps the focus
        marker; any other act names its target by ref. No ``quiet`` here:
        only ``bind_async``, which asks the live page, may say it."""
        last = self._memory.get(user_id)
        call = dict(params or {})
        press = call.get("action") == "press"
        page = {
            "origin": last.origin if last else "",
            "address": page_address(last.url) if last else "",
            "outline": (last.focus_digest if press else last.outline_digest) if last else "",
            "scheme": last.scheme if last else "",
        }
        ref = call.get("ref")
        if last and call.get("action") in _SAME_TARGET_ACTIONS and isinstance(ref, str) and last.names.get(ref):
            page["ref_name"] = last.names[ref]
        return {**call, CARD_KEY: page}

    def describe(self, params: Mapping[str, Any], *, user_id: str) -> str:
        """The approval-card sentence: ``Type 12 characters into "Email" on
        shop.example.com``, ``Fill 3 fields on shop.example.com: Email,
        Name, Address``, ``Click "Sign up" on shop.example.com``, ``Press
        Enter on shop.example.com``. With the page ``bind`` added, the
        sentence names that page's host and resolves refs only while that
        outline is still the latest, so the card says what the approved
        act would run on."""
        try:
            params = dict(params or {})
            card = params.pop(CARD_KEY, None)
            request = _parse(params)
        except _Refused as refusal:
            return f"Blocked browser action: {refusal.message}"
        except Exception:  # noqa: BLE001 - a card sentence must never raise
            return "Invalid browser action."
        last = self._memory.get(user_id)
        host = _host(last.origin) if last else ""
        if card is not None:
            bound = _bound_page(card)
            host = _host(bound.origin) if bound else ""
            if bound is None or last is None or last.outline_digest != bound.outline:
                last = None
        names: Mapping[str, str] = last.names if last else {}
        item = card.get("item") if isinstance(card, Mapping) else None
        sentence = _sentence(
            request, names, f" on {host}" if host else "", item if isinstance(item, str) else ""
        )
        notes = _card_notes(card)
        if self._picture_gone(card, user_id):
            notes += f" {PICTURE_GONE_NOTE}"
        return f"{sentence}.{notes}" if notes else sentence

    # -- the card's picture (the one bind that touches the browser) -----------

    async def bind_async(
        self, params: Mapping[str, Any], *, user_id: str, task_id: str
    ) -> dict[str, Any]:
        """``bind``, after the live page was asked what the approved act
        will be asked again (``_live_rules``, then the page binding).

        A step the page refuses gets no card: the refusal is the answer,
        in a precheck refusal's shape (``{"ok": False, "refused": True,
        "rule": ..., "error": ..., "reason": ...}``), which the runtime
        files under ``browser_rule``. A ref that no longer resolves, and a page that
        is no longer the one the model looked at, are answered the same
        way as ``stale_ref``, so the model looks again.

        Otherwise the card's arguments, plus what the owner sees on the
        card: a picture of the page as it is now, with the target outlined
        in red and secret fields masked (kept in memory under
        ``_page.picture``; "" when it could not be taken, which the card
        then says), and, under ``_page.money``, the page's own facts when
        it shows an order total, a payment method on file or a wallet
        button, or the target matches a purchase pattern (the card then
        warns that the step may place an order), and, under
        ``_page.quiet``, whether the act only clicks around (``_quiet``:
        what a site approval may run with no card), and under
        ``_page.errand`` whether it is an errand step (``_errand``: what may
        run with no card while "Ask before every website step" is off).
        Never raises: a page that cannot be looked at gives a card without
        a picture, neither quiet nor an errand, and the approved act then
        judges it."""
        card = self.bind(params, user_id=user_id)
        page_card = dict(card[CARD_KEY])
        picture, money, quiet, errand, item = "", None, False, False, ""
        errand_facts: dict[str, Any] = {}
        judged: Optional[Mapping[str, Any]] = None
        try:
            call = {k: v for k, v in dict(params or {}).items() if k != CARD_KEY}
            request = _parse(call)
            session = await self._sessions.get(user_id, mode=mode_for(user_id), task_id=task_id)
            async with session.lock:
                page = await session.page()
                target, answers, choice = await self._live_rules(page, request)
                try:
                    # After the rules: judging a click scrolls its target
                    # into view, which can change what the outline shows.
                    await self._check_outline(
                        session, page, None, press=request.action == "press",
                        target=self._same_target(request, page_card.get("ref_name")),
                    )
                except _Refused:
                    raise _Done(_shared.stale_result()) from None
                if answers is None:  # a fill or a key: no rule asked the frames
                    answers = await _shared.page_facts(page)
                money = self._money_facts(answers, target)
                judged = target if target is not None else choice
                scheme = page_origin(page.url)[0]
                quiet = _quiet(request, scheme, judged, answers, money)
                errand_facts = await self._errand_facts(page, request, judged)
                errand = _errand(request, scheme, judged, answers, money, **errand_facts)
                step = self._step_key(user_id, page.url, request, judged)
                if (quiet or errand) and self._asks_first(user_id, step):
                    # The same step, run unasked here, tried to send or to
                    # reach an order address: this time the owner is asked.
                    quiet = errand = False
                item = await self._item_of(session, page, request, judged)
                image = await self._picture(page, request)
            if image is not None:
                picture = self._keep_picture(user_id, image)
        except _Refused as refusal:
            return refusal.result()
        except _Done as done:
            # A ref that no longer resolves, or a page that is no longer
            # the one the model looked at, is the call's own error: told
            # now, in the precheck's shape, so the model looks again.
            return {
                **done.result,
                "refused": True,
                "rule": "stale_ref",
                "reason": _REASONS["stale_ref"],
            }
        except Exception as exc:  # noqa: BLE001 - the card is still made, and says so
            quiet = errand = False  # what could not be looked at runs nowhere unasked
            _shared.log_failure("browser_act_card_picture_failed", exc)
        page_card["picture"] = picture
        page_card["quiet"] = quiet
        page_card["errand"] = errand
        if errand and errand_facts.get("fields"):
            page_card["fields"] = errand_facts["fields"]  # each field's kind, for errand_covers
        if item:
            page_card["item"] = item
        name = judged.get("name") if isinstance(judged, Mapping) else None
        if (quiet or errand) and isinstance(name, str):
            # The words of the control as the page had them, for the
            # approvals' own check of what they run unasked
            # (services/agent/app_approvals.site_covers, errand_covers):
            # its name as the live rules read it and, for an errand step,
            # the words a person reads on it and whether it sits in a
            # region about cookies or consent. Longer than its limit on
            # purpose when the name is: a cut name could lose the word
            # that matters.
            named: dict[str, Any] = {"name": name[:400]}
            if errand:
                words = errand_facts.get("words")
                named["words"] = (words if isinstance(words, str) else name)[:400]
                if errand_facts.get("consent") is True:
                    named["consent"] = True
            if request.action == "click" and judged is not None and judged.get("plain_link") is True:
                named["plain_link"] = True
            if _live_action(judged):
                # The form it was judged by: the unasked run sends there
                # only, and is refused when the live form goes elsewhere.
                named["action"] = _live_action(judged)
            page_card["target"] = named
        if money is not None:
            page_card["money"] = money
        return {**card, CARD_KEY: page_card}

    async def _item_of(
        self, session: BrowserSession, page: Any, request: _Request, judged: Optional[Mapping[str, Any]]
    ) -> str:
        """The item a click's button sits with, for a button whose own words
        name none ("Add to cart"): the nearest heading around it, as the
        page has it, typed secrets redacted. "" for anything else, and when
        the page cannot say."""
        name = judged.get("name") if isinstance(judged, Mapping) else None
        if request.action != "click" or not request.ref or not isinstance(name, str):
            return ""
        if len(name) > 40 or not _ITEM_WORDS.search(name):
            return ""
        try:
            text = await page.locator(f"aria-ref={request.ref}").evaluate(
                _ITEM_NAME_JS, timeout=REF_TIMEOUT_MS
            )
        except Exception as exc:  # noqa: BLE001 - the card is made without it
            _shared.log_failure("browser_act_item_name_failed", exc)
            return ""
        item = self._label(session, str(text or ""))
        return item if item and item.lower() != name.strip().lower() else ""

    @staticmethod
    async def _errand_facts(
        page: Any, request: _Request, judged: Optional[Mapping[str, Any]]
    ) -> dict[str, Any]:
        """What ``_errand`` needs beyond the live rules' answers, as its
        keyword arguments: the kind of each field a fill types into
        (``fields``), whether the form a submit, a GET form's own button or
        Enter would send is a site search (``form_ok``), whether the page
        declares English (``english``; none declared is not), and for an
        act on one control the words a person reads on it and whether it
        sits in a region about cookies or consent (``words``, ``consent``).
        Asked only of the acts that need it; one that fails reads as no
        errand."""
        facts: dict[str, Any] = {
            "fields": [], "form_ok": False, "english": False, "words": None, "consent": False,
        }
        try:
            lang = str(await _shared.frame_evaluate(page.main_frame, _PAGE_LANG_JS) or "")
            facts["english"] = _lang_is_english(lang)
            if request.action in ("fill", "fill_form"):
                for ref in request.refs:
                    kind = await page.locator(f"aria-ref={ref}").evaluate(
                        _ERRAND_FIELD_JS, timeout=REF_TIMEOUT_MS
                    )
                    facts["fields"].append(str(kind or ""))
                return facts
            if request.ref:
                said = await page.locator(f"aria-ref={request.ref}").evaluate(
                    _ERRAND_WORDS_JS, [request.action, request.value or ""], timeout=REF_TIMEOUT_MS
                )
                if isinstance(said, dict) and isinstance(said.get("words"), str):
                    facts["words"], facts["consent"] = said["words"], said.get("consent") is True
            search = request.action == "submit" or (
                request.action == "click" and isinstance(judged, Mapping)
                and judged.get("submits") is True and judged.get("sends") is False
            )
            if search and request.ref:
                form_ok = await page.locator(f"aria-ref={request.ref}").evaluate(
                    _ERRAND_FORM_JS, timeout=REF_TIMEOUT_MS
                )
                facts["form_ok"] = form_ok is True
            elif request.action == "press" and request.key == "Enter":
                form_ok = await _shared.frame_evaluate(page.main_frame, _ERRAND_ENTER_JS)
                facts["form_ok"] = form_ok is True
            return facts
        except Exception as exc:  # noqa: BLE001 - not judged: not an errand step
            _shared.log_failure("browser_act_errand_facts_failed", exc, action=request.action)
            return {
                "fields": [], "form_ok": False, "english": False, "words": None, "consent": False,
            }

    def _step_key(
        self, user_id: str, url: str, request: _Request, judged: Optional[Mapping[str, Any]]
    ) -> tuple[str, ...]:
        """What ask-first remembers a step by: its page's host and path
        (``guard.page_place``), the act, the control's name as the live
        page judged it (else the outline's names of the refs it types
        into), and the key or the option chosen. Never the ref, which a new
        look at the page numbers afresh, nor the text typed."""
        name = judged.get("name") if isinstance(judged, Mapping) else None
        if not isinstance(name, str):
            last = self._memory.get(user_id)
            name = " | ".join(last.names.get(ref, "") for ref in request.refs) if last else ""
        return (page_place(url), request.action, name, request.key or "", request.value or "")

    def _asks_first(self, user_id: str, step: tuple[str, ...]) -> bool:
        """Whether this step (``_step_key``) was stopped when it ran with
        no card (``_run``): it then gets its card, never an unasked run."""
        return step in self._ask_first.get(user_id, ())

    def _ask_first_next_time(self, user_id: str, step: tuple[str, ...]) -> None:
        kept = self._ask_first.setdefault(user_id, [])
        kept.append(step)
        del kept[:-_ASK_FIRST_KEPT]

    def approval_image(self, arguments: Mapping[str, Any], *, user_id: str) -> Optional[str]:
        """The picture ``bind_async`` took for this card, while the card is
        pending (``APPROVAL_TTL_MINUTES``); None afterwards, for another
        user's card, and for a card bound without one. A card whose
        picture is gone says so (``describe``) and its act is refused."""
        card = arguments.get(CARD_KEY) if isinstance(arguments, Mapping) else None
        picture = card.get("picture") if isinstance(card, Mapping) else None
        if not isinstance(picture, str) or not picture:
            return None
        self._purge_pictures()
        kept = self._pictures.get(picture)
        if kept is None or kept[0] != user_id:
            return None
        return kept[1]

    def _picture_gone(self, card: Any, user_id: str) -> bool:
        """Whether *card* was bound with a picture that is no longer kept
        for *user_id* (expired, evicted, or taken before a restart)."""
        picture = card.get("picture") if isinstance(card, Mapping) else None
        if not isinstance(picture, str) or not picture:
            return False
        self._purge_pictures()
        kept = self._pictures.get(picture)
        return kept is None or kept[0] != user_id

    def _keep_picture(self, user_id: str, image: str) -> str:
        self._purge_pictures()
        picture = secrets.token_hex(8)
        self._pictures[picture] = (user_id, image, self._clock())
        while len(self._pictures) > _MAX_PICTURES:
            oldest = min(self._pictures, key=lambda p: self._pictures[p][2])
            del self._pictures[oldest]
        return picture

    def _purge_pictures(self) -> None:
        now = self._clock()
        for picture, (_user, _image, taken) in list(self._pictures.items()):
            if now - taken > self._picture_ttl:
                del self._pictures[picture]

    async def _picture(self, page: Any, request: _Request) -> Optional[str]:
        """The page as the card shows it: a masked JPEG of the viewport
        (``_shared.jpeg``) with a red box around the target, drawn by an
        overlay that is removed again before this returns. None when the
        capture failed; a box that could not be drawn only costs the box."""
        try:
            for ref in request.refs:
                try:
                    await page.locator(f"aria-ref={ref}").evaluate(_OUTLINE_JS, timeout=REF_TIMEOUT_MS)
                except Exception as exc:  # noqa: BLE001 - the picture without the box
                    _shared.log_failure("browser_act_outline_failed", exc, ref=ref)
            if request.action == "press" and request.key == "Enter":
                try:
                    await _shared.frame_evaluate(page.main_frame, _OUTLINE_FOCUS_JS)
                except Exception as exc:  # noqa: BLE001 - the picture without the box
                    _shared.log_failure("browser_act_outline_failed", exc, action="press")
            return await _shared.jpeg(page, None)
        except Exception as exc:  # noqa: BLE001 - the card says no picture was taken
            _shared.log_failure("browser_act_picture_failed", exc)
            return None
        finally:
            # Bounded and at once (``_shared.frame_evaluate``): a frame that
            # never answers (it has no document, so no box either) must not
            # hold the card, nor a cancelled card build, forever.
            await asyncio.gather(
                *(_shared.frame_evaluate(frame, _REMOVE_OUTLINE_JS, quick=True) for frame in list(page.frames)),
                return_exceptions=True,  # a frame that went away took its box along
            )

    @staticmethod
    def _money_facts(
        answers: Sequence[Any], target: Optional[Mapping[str, Any]]
    ) -> Optional[dict[str, Any]]:
        """What the card's money warning is built from, or None when there
        is nothing to warn about: every frame's facts (*answers*: an order
        total and its amount, a payment method on file, a wallet button, a
        frame or shadow tree that could not be read), and whether the
        target of a click, a submit or Enter (*target*, as the live rules
        judged it and let it through) still matches a purchase pattern: a
        control browser.read would leave alone (``markers.read_click_pays``),
        or one whose words are a purchase, a plain link among them ("Buy
        tickets" opens the next page; the owner is told what it says all
        the same). A check or a select that may order was refused before
        this."""
        frames = [a for a in answers if isinstance(a, dict)]
        unread = len(frames) < len(answers) or any(f.get("unread") for f in frames)
        read = [f for f in frames if not f.get("unread")]
        facts: dict[str, Any] = {
            "amount": _amount_text(read),
            "order_total": any(f.get("order_total") for f in read),
            "saved_payment": any(f.get("saved_payment") for f in read),
            "wallet": any(f.get("wallet") for f in read),
            "unread": unread,
        }
        may_order = target is not None and (
            markers.read_click_pays(target)
            or bool(markers.PURCHASE_RE.search(str(target.get("name") or "")))
        )
        if may_order or any(facts[k] for k in ("order_total", "saved_payment", "wallet", "unread")):
            return facts
        return None

    # -- execution -----------------------------------------------------------

    async def execute(
        self,
        action: str,
        params: dict[str, Any],
        *,
        user_id: str,
        task_id: str,
        approved: bool,
    ) -> dict[str, Any]:
        """Run one browser.act action for *user_id*'s task. ``approved``
        means the call comes from an approval card the owner accepted
        (the executor's own flag, never the model's): it then runs only
        with the page that card was made from under ``CARD_KEY`` and only
        while that page holds. Never raises."""
        if not isinstance(action, str) or action not in ACT_ACTIONS:
            return _shared.error_result(
                f"Unknown browser.act action '{_short(str(action))[:40]}'. "
                f"Actions: {', '.join(ACT_ACTIONS)}."
            )
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            return _shared.error_result(
                f"Invalid arguments for browser.act {action}: expected an object."
            )
        # The flat schema carries every field; Gemini sends null for the
        # ones an action does not use, and null means "not given".
        params = {k: v for k, v in params.items() if v is not None}
        if params.get("action", action) != action:
            return _shared.error_result("browser.act was given two different actions.")
        params.pop("action", None)
        # Only an approved act reads a card's page; anywhere else the
        # reserved key is an argument no action takes, and is refused.
        card = params.pop(CARD_KEY, None) if approved else None
        # A step the runtime runs with no card (an errand step, a site
        # approval's click) says so on its page: it reaches no order address.
        unasked = isinstance(card, Mapping) and card.get(UNASKED_MARK) is True
        # A card bound with a picture runs only while that picture is kept:
        # the owner saw the page on it, or approved without it.
        picture_gone = self._picture_gone(card, user_id)
        if isinstance(card, Mapping) and isinstance(card.get("picture"), str):
            self._pictures.pop(card["picture"], None)  # the card was decided
        try:
            request = _parse({"action": action, **params})
            self._check_cancel(user_id)
            self._static_rules(request, self._memory.get(user_id))
            bound = _bound_page(card) if approved else None
            if approved and bound is None:
                raise _Refused("unbound_approval", _UNBOUND)
            if picture_gone:
                raise _Refused("picture_gone", _PICTURE_GONE)
        except _Refused as refusal:
            self._log_refusal(action, refusal, user_id)
            return refusal.result()
        loop = self._loop_refusal(task_id, action, params)
        if loop is not None:
            return loop
        try:
            session = await self._sessions.get(user_id, mode=mode_for(user_id), task_id=task_id)
        except Exception as exc:  # launch errors quote paths; keep them in the log
            _shared.log_failure("browser_session_failed", exc, action=f"act {action}")
            return _shared.error_result(
                "Could not start the browser. The owner can check Settings → "
                "Permissions → Control a browser."
            )
        async with session.lock:
            cap = _shared.cap_refusal(session.task)
            if cap is not None:
                return cap
            try:
                await self._ensure_guard(session)
            except Exception as exc:  # fail closed: never act on an unguarded context
                _shared.log_failure("browser_guard_failed", exc, action=f"act {action}")
                return _shared.error_result(
                    "The browser's network guard could not be set up, so nothing was "
                    "done. Try again; if it keeps failing, the owner can restart Crawler."
                )
            session.task.actions += 1
            try:
                pinned = card if unasked and isinstance(card, Mapping) else None
                return await self._run(session, request, bound, unasked=unasked, card=pinned)
            except _Refused as refusal:
                self._log_refusal(action, refusal, user_id)
                self._record(session, f"act {action} refused: {refusal.rule}")
                return refusal.result()
            except _Done as done:
                return done.result
            except Exception as exc:  # last resort: never raise into the agent loop
                _shared.log_failure("browser_act_failed", exc, action=f"act {action}")
                return _shared.error_result(f"browser.act {action} failed.")

    # -- gates ----------------------------------------------------------------

    def _check_cancel(self, user_id: str) -> None:
        try:
            cancelled = bool(self._cancel_flag(user_id))
        except Exception:  # noqa: BLE001 - a flag that cannot be read counts as set
            cancelled = True
        if cancelled:
            raise _Refused("cancelled", _CANCELLED)

    @staticmethod
    def _static_rules(request: _Request, last: Optional[LastPage]) -> None:
        """The rules the page memory can answer without a browser call,
        in the order the spec lists them."""
        if last is None:
            raise _Refused("needs_observe", _NEEDS_OBSERVE, needs_observe=True)
        for ref in request.refs:
            if ref not in last.names:
                raise _Refused("stale_ref", "stale ref: re-snapshot", stale_ref=True)
        if request.action in _TYPING_ACTIONS:
            for ref in request.refs:
                if ref in last.secret_refs or snap._SECRET_NAME_RE.search(last.names.get(ref, "")):
                    raise _Refused("secure_field", _SECURE_MESSAGE)
        # Names alone refuse a submit (it sends a form) and a choice (its
        # words say what it chooses). A click is left to the live page: a
        # name cannot say whether money moves ("Buy tickets" may only open
        # the next page), and the page is judged when the card would be made.
        if request.action == "submit" or request.action in _CHOICE_ACTIONS:
            for ref in request.refs:
                if markers.PURCHASE_RE.search(f"{last.names.get(ref, '')} | {request.value or ''}"):
                    raise _use_checkout(request.action, "purchase_words")
                # A submit through a field sends the form by its default
                # button, whose words the page memory kept for the field.
                if request.action == "submit" and markers.PURCHASE_RE.search(
                    last.form_buttons.get(ref, "")
                ):
                    raise _use_checkout(request.action, "purchase_words")
        if last.scheme != "https":
            raise _Refused("insecure_page", _INSECURE_MESSAGE)

    def _loop_refusal(
        self, task_id: str, action: str, params: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """The same act with the same arguments LOOP_REPEATS times in a
        row is a loop: refuse the last one. History is per task and bounded."""
        if len(self._recent) > 64:
            for stale in [t for t in self._recent if t != task_id][:32]:
                del self._recent[stale]
        key = _shared.call_key(action, params)
        recent = self._recent.setdefault(task_id, [])
        streak = LOOP_REPEATS - 1
        if len(recent) >= streak and all(k == key for k in recent[-streak:]):
            recent.clear()
            return _shared.error_result(
                f"Loop detected: browser.act {action} was called {LOOP_REPEATS} times in a "
                "row with the same arguments. Change approach, or answer with what you have."
            )
        recent.append(key)
        del recent[:-LOOP_REPEATS]
        return None

    async def _ensure_guard(self, session: BrowserSession) -> None:
        context = session.context
        if self._guarded.get(session.user_id) is context:
            return
        await self._guard.install_egress_guard(context, account_mode=session.mode == "account")
        _shared.attach_egress_hooks(self._guard, session, self._egress_hooks)
        self._guarded[session.user_id] = context

    @staticmethod
    def _log_refusal(action: str, refusal: _Refused, user_id: str) -> None:
        logger.info("browser_act_refused", action=action, rule=refusal.rule, user_id=user_id)

    @staticmethod
    def _record(session: BrowserSession, line: str) -> str:
        summary = f"[step {session.task.actions}] {line}"
        session.task.summaries.append(summary)
        return summary

    def _blocked_count(self, session: BrowserSession) -> int:
        state = self._guard.egress_state(session.context)
        return 0 if state is None else len(state.blocked)

    def _blocked_reason(self, session: BrowserSession, *, since: int) -> Optional[str]:
        state = self._guard.egress_state(session.context)
        if state is None or len(state.blocked) <= since:
            return None
        last = state.blocked[-1]
        return f"{last['url']}: {last['reason']}"

    def _sent_anyway(self, session: BrowserSession, *, since: int) -> bool:
        """Whether the guard stopped the page sending itself (a form POST
        of any frame, an order address) during an act not meant to send,
        or stopped a step run with no card reaching an order address or
        sending what it changed (``UNASKED_REASONS``)."""
        state = self._guard.egress_state(session.context)
        return state is not None and any(
            entry.get("reason") in SENDING_REASONS or entry.get("reason") in UNASKED_REASONS
            for entry in state.blocked[since:]
        )

    def _held_back(self, session: BrowserSession, *, since: int) -> bool:
        """Whether the guard held back a beacon while a step ran with no
        card (``UNASKED_HELD``): no reason to say the step tried to send."""
        state = self._guard.egress_state(session.context)
        return state is not None and any(entry.get("reason") == UNASKED_HELD for entry in state.blocked[since:])

    @staticmethod
    def _lift_at_commit(page: Any, state: Any) -> Callable[[], None]:
        """For a plain link run with no card: lift the guard's send stop once
        the page's main frame commits a new document, so the page the link
        opens loads as it would for the person, while every request of the
        clicked document is still judged. Playwright tells a new document
        (``newDocument``) only on its frame's own "navigated" event, which
        a same-document change (pushState) lacks; it is read through the
        frame's implementation object, and a page whose frame cannot be
        listened to keeps the stop for the whole window. Returns what
        removes the listener."""

        def committed(event: Any) -> None:
            if isinstance(event, Mapping) and "newDocument" in event and not event.get("error"):
                state.no_orders = False

        try:
            emitter = page.main_frame._impl_obj._event_emitter
            emitter.on("navigated", committed)
        except Exception:  # noqa: BLE001 - not a Playwright page: the stop holds the whole window
            return lambda: None
        return lambda: emitter.remove_listener("navigated", committed)

    @staticmethod
    def _label(session: BrowserSession, value: str) -> str:
        return _short(snap.redact(value, session.typed_secrets, "•••"))

    # -- the approved act -------------------------------------------------------

    async def _run(
        self,
        session: BrowserSession,
        request: _Request,
        bound: Optional[_Bound],
        *,
        unasked: bool = False,
        card: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """The act on the live page, in its window. *unasked*: no person
        approved this step (it runs as an errand step or on a site
        approval), so the guard keeps every order address shut for it,
        inside its write window too, and lets it send nothing but to a
        cart (a page script only on a cart step, ``_cart_step``) or to its
        own form when the card judged that form by cart words or as a
        cookie choice (*card*'s ``target``, whose pinned ``action`` the live
        form must still have: else ``outline_changed``;
        ``_unasked_sends``), until the page has gone quiet after it, so a
        save the page makes a moment later is stopped too
        (``EgressState.no_orders``). A plain link has the same stop until
        its page commits a new document (``_lift_at_commit``): one a
        script takes over instead of opening it is judged as a script
        button. A step stopped so answers ``auto_submit`` and gets its card
        the next time it comes on that page (``_asks_first``), unless what
        the step itself sent went out (``EgressState.unasked_went``): it
        is then done, with a note, so it is not taken twice. A beacon held
        back meanwhile only adds the note. An approved act's window is as
        it was."""
        await _shared.take_back(self._guard, session)
        page = await session.page()
        challenge = await self._handoff.detect_challenge(page)
        if challenge is not None:
            return await _shared.needs_human(
                session, page, challenge.kind, challenge.detail, guard=self._guard
            )
        self._check_cancel(session.user_id)
        scheme, origin = page_origin(page.url)
        if bound is not None and origin != bound.origin:
            raise _Refused("page_changed", _PAGE_CHANGED)
        if scheme != "https":
            raise _Refused("insecure_page", _INSECURE_MESSAGE)
        # Every act, a key press included, runs only on the page the card
        # showed: Enter activates whatever has the focus there.
        await self._check_outline(
            session, page, bound, press=request.action == "press",
            target=self._same_target(request, bound.ref_name if bound is not None else None),
        )
        target, _facts, choice = await self._live_rules(page, request)
        said = card.get("target") if card is not None else None
        if unasked:
            pinned = said.get("action", "") if isinstance(said, Mapping) else ""
            if pinned != _live_action(target):
                # The form now goes elsewhere than the card judged it by.
                raise _Refused("outline_changed", _OUTLINE_CHANGED)
        # Only a click, a submit or an Enter is meant to send, and a plain
        # link among them is followed with the write window shut.
        sends = target is not None and not target.get("plain_link")
        state = self._guard.egress_state(session.context)
        blocked_before = self._blocked_count(session)
        went_before = getattr(state, "unasked_went", 0)
        step = self._step_key(session.user_id, page.url, request, target if target is not None else choice)
        # What tells afterwards whether the act opened a tab of its own.
        tabs_before = list(session.context.pages)
        in_flight_before = set(getattr(state, "in_flight", ()))
        address_before = page_address(page.url)
        url_before = page.url
        link = str(target.get("href") or "") if target is not None and target.get("plain_link") else ""
        lift: Callable[[], None] = lambda: None  # noqa: E731 - nothing to remove
        try:
            if state is not None:
                state.write_allowed = sends
                state.write_page = page  # the card's page: no other tab sends
                state.changing = not sends
                state.no_orders = unasked
                state.unasked_cart = unasked and _cart_step(said, card.get("fields") if card is not None else None)
                state.unasked_sends = _unasked_sends(said) if unasked else frozenset()
                if unasked and link:
                    lift = self._lift_at_commit(page, state)
            started = time.monotonic()
            did, args = await self._perform(session, page, request)
            if state is not None and state.no_orders:
                # A page may save the step a moment later (a debounced
                # autosave): the send stop holds until it has gone quiet.
                await wait_for_quiet(
                    state, since=started, quiet_s=UNASKED_QUIET_S, cap_s=UNASKED_QUIET_CAP_S
                )
        finally:
            lift()
            if state is not None:
                state.write_allowed = False
                state.write_page = None
                state.changing = False
                state.no_orders = False
                state.unasked_cart = False
                state.unasked_sends = frozenset()
        # Where the act landed, as after a read's click: the newest tab
        # it opened (target=_blank, window.open), else the card's page.
        new_tabs = await self._new_tabs(session, state, tabs_before, in_flight_before)
        sent_anyway = (not sends or unasked) and self._sent_anyway(session, since=blocked_before)
        if sent_anyway and unasked:
            self._ask_first_next_time(session.user_id, step)
        # What the step itself sent went out: it is done, never "not taken".
        stopped = sent_anyway and not (unasked and getattr(state, "unasked_went", 0) > went_before)
        if (
            request.action == "click" and link and not new_tabs and not sent_anyway
            and not page.url.startswith("chrome-error://")
            and page_address(page.url) == address_before
        ):
            # The approved click was on a plain link and the page is where
            # it was (a carousel slide that moved under the click, a link a
            # banner covers). Following that link is what was approved: its
            # address is opened, with the write window shut, and the guard
            # judges it like any navigation. The owner used to be asked for
            # the same click again and again.
            try:
                await page.goto(urljoin(page.url, link), wait_until="domcontentloaded", timeout=30_000)
            except PlaywrightError as exc:
                _shared.log_failure("browser_act_follow_link_failed", exc)
        landed = new_tabs[-1] if new_tabs else page
        blocked = self._blocked_reason(session, since=blocked_before)
        # Its navigation was stopped, or failed: nothing to go on in.
        dead = landed.url.startswith("chrome-error://") and (blocked is not None or bool(new_tabs))
        if stopped or dead:
            for tab in new_tabs:
                await tab.close()  # the session stays on the page the card showed
            if stopped and unasked:
                raise _Refused("auto_submit", _UNASKED_STOPPED, reason=_UNASKED_REASON, unasked_stopped=True)
            if stopped:
                raise _Refused("auto_submit", _AUTO_SUBMIT)
            if blocked is not None:
                return _shared.error_result(
                    f"That action was refused by the network policy: {blocked}"
                )
            return _shared.error_result(_NEW_TAB_DEAD)
        extra: dict[str, Any] = {"did": did}
        if unasked and (sent_anyway or self._held_back(session, since=blocked_before)):
            extra["note"] = _HELD_NOTE
        if request.action == "click" and markers.adds_to_cart(did):
            # A small model stopped at the cart though the person said
            # "order me": the result says what comes next.
            extra["next_step"] = CART_NEXT_STEP
        opened = await session.adopt_new_tab(tabs_before) if new_tabs else None
        if opened is not None:
            await _shared.settle(opened)
            extra["new_tab"] = True
        if opened is not None or page_address(page.url) != address_before:
            # The act opened a page: described once what it fetches as it
            # loads has gone quiet, as after an open. A ticket site's seat
            # page came back with no line of outline, and the resumed turn
            # started from an empty page.
            await wait_for_quiet(state, since=time.monotonic(), cap_s=LOAD_QUIET_CAP_S)
            if link:
                # The link it followed: what a person opens to get to the
                # same step (a showtime's seat map) on their own device.
                followed = urljoin(url_before, link)
                _shared.note_entry_link(opened or page, followed)
                try:
                    extra["opened_link"] = (
                        snap.strip_url_secrets(followed) if session.mode == "account" else followed
                    )
                except ValueError:
                    pass
        return await _shared.observe(
            session,
            self._handoff,
            f"act {request.action}",
            args,
            extra=extra,
            memory=self._memory,
            guard=self._guard,
        )

    @staticmethod
    async def _new_tabs(
        session: BrowserSession, state: Any, before: Sequence[Any], in_flight_before: set[Any]
    ) -> list[Any]:
        """The tabs the act opened, found the way browser.read's click
        finds them: Playwright lists a new tab only once its first page
        has answered, so one that is still on its way (a slow site, a
        chain of redirects) is waited for, NEW_TAB_WAIT_MS at most."""
        opened = [tab for tab in session.context.pages if tab not in before]
        if not opened and BrowserReadToolkit._tab_on_its_way(state, in_flight_before):
            try:
                await session.context.wait_for_event("page", timeout=NEW_TAB_WAIT_MS)
            except PlaywrightError:
                pass  # it never answered: the tab the act was made in is described
            opened = [tab for tab in session.context.pages if tab not in before]
        return opened

    async def _live_rules(
        self, page: Any, request: _Request
    ) -> tuple[Optional[dict[str, Any]], Optional[list[Any]], Optional[dict[str, Any]]]:
        """The rules only the live page can answer, asked when the card
        would be made (``bind_async``) and again when the approved act
        runs, through this one place so the two cannot disagree: the field
        rule for an act that types, the purchase rule for a click, a submit
        or Enter, the choice rule for a check or a select. Returns the
        judged target of a click, a submit or Enter (None for any other
        act: the approved run opens its write window by it), the frame
        facts a rule read (None when none asked), and what a check or a
        select chooses, as judged (None for any other act)."""
        if request.refs and request.action in _TYPING_ACTIONS:
            await self._check_fields(page, request.refs)
        if request.action in _SENDING_ACTIONS and (request.refs or request.key == "Enter"):
            target, answers = await self._check_purchase(page, request)
            return target, answers, None
        if request.action in _CHOICE_ACTIONS:
            choice, answers = await self._check_choice(page, request)
            return None, answers, choice
        return None, None, None

    @staticmethod
    def _same_target(request: _Request, name: Optional[str]) -> Optional[tuple[str, str]]:
        """``(ref, name)`` of the one control a click, a choice or a tick is
        made on, when its name on the card's page is known; None for every
        other act (typing, a submit and a key keep the whole-page check)."""
        if request.action in _SAME_TARGET_ACTIONS and request.ref and name:
            return request.ref, name
        return None

    async def _check_outline(
        self,
        session: BrowserSession,
        page: Any,
        bound: Optional[_Bound],
        *,
        press: bool,
        target: Optional[tuple[str, str]] = None,
    ) -> None:
        """The page's address, and its outline taken the way the remembered
        one was, must still be what the card (or, unapproved, the latest
        observation) was made from: a ref means nothing otherwise, and a
        key goes to whatever page is open. The outline is compared by its
        structure, so text and state that change by themselves do not
        void an approval; for a key press (*press*) the focus must be
        where it was too, since a key acts on whatever has it. This
        snapshot also makes the refs resolvable for the act itself.

        A page that moves by itself (a carousel, an advert that loads, a
        banner that leaves) changed its structure between two looks, and a
        card a person takes ten seconds to answer was void before the tap.
        So for a click, a choice or a tick (*target*: the control's ref and
        its name on the card's page) a changed structure is accepted when
        the whole page still has that ref under that name: the same
        control, on the same address. What the control would do is judged
        on the live page either way."""
        last = self._memory.get(session.user_id)
        if bound is not None:
            address = bound.address
        else:
            address = page_address(last.url) if last else ""
        if address is not None and page_address(page.url) != address:
            raise _Refused("outline_changed", _PAGE_MOVED)
        out = await snap.outline(
            page,
            query=last.query if last else None,
            full=last.full if last else False,
            account_mode=session.mode == "account",
            secrets=session.typed_secrets,
            limit_chars=_shared.FULL_OUTLINE_CHARS if last and last.full else _shared.OUTLINE_CHARS,
        )
        remembered = (last.focus_digest if press else last.outline_digest) if last else ""
        expected = bound.outline if bound is not None else remembered
        if outline_digest(out.lines, focus=press) != expected:
            if target is None:
                raise _Refused("outline_changed", _OUTLINE_CHANGED)
            whole = await snap.outline(
                page,
                full=True,
                account_mode=session.mode == "account",
                secrets=session.typed_secrets,
                limit_chars=_shared.FULL_OUTLINE_CHARS,
            )
            if _ref_names(whole.lines).get(target[0]) != target[1]:
                raise _Refused("outline_changed", _OUTLINE_CHANGED)

    @staticmethod
    async def _check_fields(page: Any, refs: Sequence[str]) -> None:
        """The live element's own attributes decide, whatever the outline
        said: a field turned into a password box after the card was made
        is still a password box."""
        for ref in refs:
            try:
                kind = await page.locator(f"aria-ref={ref}").evaluate(
                    _shared.FIELD_KIND_JS, timeout=REF_TIMEOUT_MS
                )
            except PlaywrightTimeoutError:
                raise _Done(_shared.stale_result())
            except PlaywrightError as exc:  # e.g. a frame that is not there
                _shared.log_failure("browser_act_field_check_failed", exc, ref=ref)
                raise _Done(_shared.stale_result())
            if kind:
                raise _Refused("secure_field", _SECURE_MESSAGE)

    async def _check_purchase(
        self, page: Any, request: _Request
    ) -> tuple[dict[str, Any], list[Any]]:
        """The live page decides, whatever the outline said: the control
        that would send the form (the element the click lands on, or the
        button, link or label target around it; for a submit through a
        field, that form's default button; for Enter, the focused element
        or the focused field's default button, in whatever shadow root or
        frame the focus is),
        its words, its form and the page around it, every frame of it
        (``markers.pay_rule``). A target that would place an order is
        refused: that is browser.checkout's job. Returns the target judged
        and the frame facts it was judged with, read after the target (a
        click's target is scrolled into view first, and an order total
        counts only on screen)."""
        if request.refs:
            ref = request.refs[0]
            locator = page.locator(f"aria-ref={ref}")
            script = markers.SUBMIT_TARGET_JS if request.action == "submit" else markers.PURCHASE_TARGET_JS
            try:
                target = await locator.evaluate(script, timeout=REF_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                raise _Done(_shared.stale_result())
            except PlaywrightError as exc:  # e.g. a frame that is not there
                _shared.log_failure("browser_act_purchase_check_failed", exc, ref=ref)
                raise _Done(_shared.stale_result())
        else:
            try:
                target = await self._enter_target(page)
            except Exception as exc:  # noqa: BLE001 - a focus that cannot be judged refuses
                _shared.log_failure("browser_act_purchase_check_failed", exc, action="press")
                raise _use_checkout(request.action, "unjudged")
        answers = await _shared.page_facts(page)
        target = markers.join_page(target, answers)
        rule = markers.pay_rule(target)
        if rule is not None or not isinstance(target, dict):
            raise _use_checkout(request.action, rule or "unjudged", target)
        return target, answers

    async def _check_choice(
        self, page: Any, request: _Request
    ) -> tuple[dict[str, Any], list[Any]]:
        """A check or a select, judged on the live page by what it chooses
        and by every frame of the page around it (``markers.change_pays``):
        choosing the card on file on a review page is the order's first
        half, and a page may send its form on the change. Returns what it
        chooses, as judged, and the frame facts it read."""
        ref = request.refs[0]
        try:
            target = await page.locator(f"aria-ref={ref}").evaluate(
                markers.CHANGE_TARGET_JS, request.value or "", timeout=REF_TIMEOUT_MS
            )
        except PlaywrightTimeoutError:
            raise _Done(_shared.stale_result())
        except PlaywrightError as exc:  # e.g. a frame that is not there
            _shared.log_failure("browser_act_purchase_check_failed", exc, ref=ref)
            raise _Done(_shared.stale_result())
        answers = await _shared.page_facts(page)
        target = markers.join_page(target, answers)
        if not isinstance(target, dict) or markers.change_pays(target):
            raise _use_checkout(request.action, "choice", target)
        return target, answers

    @staticmethod
    async def _enter_target(page: Any) -> Any:
        """What Enter would activate, followed from the top page into the
        focused frame (and a frame in it), each asked ``ENTER_TARGET_JS``.
        None when the focused frame cannot be entered, or is too deep:
        the caller refuses."""
        frame = page.main_frame
        for _ in range(_MAX_FRAME_DEPTH):
            target = await asyncio.wait_for(frame.evaluate(markers.ENTER_TARGET_JS), REF_TIMEOUT_MS / 1000)
            if not (isinstance(target, dict) and target.get("frame")):
                return target
            handle = await frame.evaluate_handle(markers.FOCUSED_JS)
            try:
                element = handle.as_element()
                inner = await element.content_frame() if element is not None else None
            finally:
                await handle.dispose()
            if inner is None:
                return None
            frame = inner
        return None

    async def _perform(
        self, session: BrowserSession, page: Any, request: _Request
    ) -> tuple[str, dict[str, Any]]:
        """Do the one act inside the write window and say what was done
        (``did``) with the summary's arguments. A navigation the act
        starts is given NAVIGATION_GRACE_MS after the act to commit (the
        listener is on before the act, so a fast commit is not missed),
        then a moment to land, all before the window closes."""
        navigated = asyncio.Event()

        def on_navigated(frame: Any) -> None:
            if frame is page.main_frame:
                navigated.set()

        page.on("framenavigated", on_navigated)
        try:
            did, args = await self._act(session, page, request)
            try:
                await asyncio.wait_for(navigated.wait(), NAVIGATION_GRACE_MS / 1000)
            except asyncio.TimeoutError:
                pass  # the act stayed on the page
        finally:
            page.remove_listener("framenavigated", on_navigated)
        await _shared.settle(page)
        return did, args

    async def _act(
        self, session: BrowserSession, page: Any, request: _Request
    ) -> tuple[str, dict[str, Any]]:
        action = request.action
        if action == "press":
            await page.keyboard.press(request.key)
            return f"Pressed {request.key}", {"name": request.key}
        if action == "fill_form":
            names: list[str] = []
            for ref, text in request.fields:
                names.append(await self._fill(session, page, ref, text))
            return f"Filled {len(names)} fields: {', '.join(names)}", {
                "name": f"{len(names)} fields"
            }
        ref = request.ref or ""
        locator = page.locator(f"aria-ref={ref}")
        try:
            name = self._label(
                session,
                str(await locator.evaluate(_shared.ELEMENT_NAME_JS, timeout=REF_TIMEOUT_MS) or ""),
            )
            target = f'"{name}"' if name else ref
            if action == "fill":
                text = request.text or ""
                await locator.fill(text, timeout=REF_TIMEOUT_MS)
                did = (
                    f"Cleared {target}"
                    if not text
                    else f"Typed {_characters(len(text))} into {target}"
                )
            elif action == "select":
                value = request.value or ""
                try:
                    await locator.select_option(value, timeout=REF_TIMEOUT_MS)
                except PlaywrightTimeoutError:
                    raise _Done(
                        _shared.error_result(
                            f'No option matches "{_short(value)}" in {target}; use the option\'s label or value.'
                        )
                    )
                did = f'Selected "{_short(value)}" in {target}'
            elif action == "check":
                await locator.check(timeout=REF_TIMEOUT_MS)
                did = f"Checked {target}"
            elif action == "click":
                await locator.click(timeout=REF_TIMEOUT_MS)
                did = f"Clicked {target}"
            else:
                if not await locator.evaluate(_SUBMIT_JS, timeout=REF_TIMEOUT_MS):
                    raise _Done(
                        _shared.error_result(
                            f"{target} is not inside a form, so there is nothing to submit."
                        )
                    )
                did = f"Submitted the form with {target}"
        except PlaywrightTimeoutError:
            raise _Done(_shared.stale_result())
        except PlaywrightError as exc:
            _shared.log_failure("browser_act_element_failed", exc, action=action, ref=ref)
            raise _Done(
                _shared.error_result(
                    f"The {action} failed (the element may be covered, gone or not the kind "
                    "that takes it); re-snapshot and try again."
                )
            )
        return did, {"name": name or ref}

    async def _fill(self, session: BrowserSession, page: Any, ref: str, text: str) -> str:
        locator = page.locator(f"aria-ref={ref}")
        try:
            name = self._label(
                session,
                str(await locator.evaluate(_shared.ELEMENT_NAME_JS, timeout=REF_TIMEOUT_MS) or ""),
            )
            await locator.fill(text, timeout=REF_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            raise _Done(_shared.stale_result())
        except PlaywrightError as exc:
            _shared.log_failure("browser_act_element_failed", exc, action="fill_form", ref=ref)
            raise _Done(
                _shared.error_result(
                    f"Filling {ref} failed (the element may be gone or not a field); "
                    "re-snapshot and try again."
                )
            )
        return name or ref
