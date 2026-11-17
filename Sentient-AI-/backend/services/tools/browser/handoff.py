"""Challenge detection for the human handoff (spec §8).

What: the detector runs before every action and answers one question: is
this page asking a *person* to do something the agent must never do, such
as solve a CAPTCHA, approve an MFA push, type a one-time code or sign in?
It looks at what is on the page (visible challenge frames, OTP inputs,
sign-in forms, the words) and where the page is (IdP hosts, bot-wall
URLs). It never looks at HTTP status codes: Canvas answers locked content
with 403 and throttles with 429, and neither is a challenge.

An ordinary checkout page is not a challenge either. A card's security
code is named like a one-time code, so a field the page marks as a card
field, or one called "security code" in a document that also holds a
card-number field, is left to the checkout; which field is a card
number and what a card's code is called come from ``checkout.markers``,
the classifier the outline and the checkout share. "Complete the
checkout" is not "complete the check" of a traffic wall.

A sign-in step is the person's too (kind ``signin``), judged by the
form a field sits in, not by the whole page, and handed over only on a
page named for signing in: its path names it (/ap/signin, /login), or
its title's name does, a part of the title (split at | - : ·) that
starts or ends with the words ("Amazon Sign-In", "Sign In | Hotel
Rewards", "Login"); "Can't log in after password reset - Forum" is a
thread to read. There, a form whose one rendered password box (not a new one,
not a card's code) sits beside a box for the account (username, ID,
email, phone, or a card number on a form that takes no card), or one box
alone (an email first, then the password on the next step), is a sign-in
step; an account box alone only under a sign-in, "Continue" or "Next"
button (or marked username or webauthn). The button judged is the first
submit after the box (a page-wide ASP.NET form puts its search button
first). A form whose button signs up, subscribes, sends or searches, a
change-password form, a form that takes a card (its number with its code
or expiry), a "Sign in" link and a newsletter or contact box are not a
sign-in step. An identity provider's frame counts as its own page. A
child frame whose address names signing in (a bank's logon box, a
wallet's login) is judged by the name of the page it is on, as an inline
form is, and only while its element is drawn in the viewport; the
``Challenge`` says which frame (``frame``).

Two kinds are notes, never a handoff (``NOTE_KINDS``): a password box
beside an account box on a page not named for signing in (a bank's home
page, a forum's header, a checkout's optional login) is ``signin_form``
(``SIGNIN_FORM_NOTE``), and a sign-in step that shows a real guest path
("Continue as guest", "Pay as guest", "Book as a guest", "Guest
checkout", "without an account", "without signing in", on a link with an
href or not, a clickable element, a button, or a radio's or checkbox's
label, drawn anywhere on the page; "Guest Services" is none) is
``guest`` (``GUEST_PATH_NOTE``). ``detect`` answers with them,
``detect_challenge`` never does. The detail is a fixed sentence, never
page text.

Why: the agent can never finish a sign-in (browser.act refuses a
password field), and the guard lets the person's own submit through only
while the page is handed to them, so an ordinary observation of one was a
dead end: the model told the person in prose to sign in and the guard
blocked their form (ERR_BLOCKED_BY_CLIENT). Handing over too much is a
dead end too: a blog post about passkeys is no sign-in, a forum thread
under a header login is to be read (its title about login trouble too),
and a shop's guest checkout or optional wallet login needs no account (a
scheduled order stalled on a handoff nobody was there to take). The note
lets the model hand the page over itself when the task needs it.

Connects: ``_shared.observe`` calls ``detect`` and describes a page of a
note kind with its note (``signin_note``); browser.read's other actions,
browser.act's approved run and browser.checkout call ``detect_challenge``,
so a note never reaches ``_shared.needs_human``; ``_shared.hand_over``
then opens the guard's ``human_driving`` window, and browser.checkout's
order handoff judges by ``Challenge.frame`` whose origin a sign-in is
on (the shop's, or the bank's 3-D Secure frame). ``collect_facts`` is the
only part that touches the browser; ``classify`` is a pure function over
its result so every rule is tested with a dict. Phase 2 parks the turn on
the returned ``Challenge`` and types ``/code`` into ``otp_ref`` (a
Playwright selector, IdP origin only).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Optional
from urllib.parse import urlparse

import structlog

from services.tools.browser.checkout import markers

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = structlog.get_logger(__name__)

Kind = Literal["captcha", "mfa", "otp", "unusual_traffic", "signin", "signin_form", "guest", "bank"]
# The kinds a page is described with, never handed over (``detect``).
NOTE_KINDS = frozenset({"signin_form", "guest"})


@dataclass(frozen=True)
class Challenge:
    kind: Kind
    detail: str
    otp_ref: Optional[str] = None  # Playwright selector for the code field, e.g. 'css=[id="otp"]'
    # The address of the child frame a sign-in step was found in, None for
    # the page's own: where it is, not what it asks, so never compared.
    frame: Optional[str] = dataclasses.field(default=None, compare=False)


CAPTCHA_HOSTS = (
    "google.com/recaptcha", "recaptcha.net", "hcaptcha.com", "challenges.cloudflare.com",
    "arkoselabs.com", "funcaptcha.com", "captcha-delivery.com",
)
_CAPTCHA_TITLE = re.compile(
    r"recaptcha|hcaptcha|captcha|security challenge|turnstile|arkose|funcaptcha|verification challenge",
    re.IGNORECASE,
)
MFA_HOSTS = ("duosecurity.com", "login.microsoftonline.com", "okta.com", "oktapreview.com", "accounts.google.com")
_MFA_TEXT = re.compile(
    r"duo push|approve (the )?(sign[- ]?in|request|notification)|push notification|enter the number|"
    r"number (shown|displayed)|two[- ]step verification|2-step verification|verify your identity|"
    r"authenticator app|okta verify|security key|check your phone",
    re.IGNORECASE,
)
# "complete the check" ends at the word: a shop's "Complete the checkout"
# and an airline's "complete the check-in" are not a traffic wall.
_HUMAN_TEXT = re.compile(
    r"verify (that )?you('re| are) (a )?human|confirm (that )?you('re| are) (a )?human|"
    r"prove you('re| are) (not a robot|human)|are you a robot|unusual traffic|checking your browser|"
    r"verify you are not a bot|automated (queries|traffic)|complete the (security )?check(?![\w-])(?!\s+(?:out|in)\b)",
    re.IGNORECASE,
)
_WALL_URLS = ("/bots.html", "/sorry/", "/cdn-cgi/challenge-platform/", "_incapsula_resource", "/distil_r_", "__cf_chl")
# How a page's title or path names its sign-in step. No letter may touch
# either end: "Designing", "Signing up" and "our blog in" are not one.
_SIGNIN_NAME = re.compile(
    r"(?<![a-z])(?:sign[\s_-]?(?:in|on)|log[\s_-]?(?:in|on)|authenticat(?:e|ion))(?![a-z])",
    re.IGNORECASE,
)
# Where a title's parts meet: "Sign In | Hotel Rewards", "Steam : r/Steam",
# "Thread - Forum". A hyphen inside a word ("Sign-In") parts nothing.
_NOT_A_NAME = re.compile(
    r"[!?'\u2019]|\b(?:can|cannot|unable|problems?|issues?|trouble|help|how|why|with|to|after|when|not)\b",
    re.IGNORECASE,
)
_TITLE_PARTS = re.compile(r"\s[-\u2013\u2014|:\u00b7]\s|[|\u00b7]|:\s")
SIGNIN_DETAIL = "the site wants you to sign in"
# What a page with a sign-in form, not named for signing in, is described with.
SIGNIN_FORM_NOTE = (
    "This page has a sign-in form. If the task needs the person's account, hand the page over "
    "with browser.read handoff; otherwise go on."
)
# What a sign-in step that also offers a guest path is described with, in
# place of handing it over.
GUEST_PATH_NOTE = (
    "This page asks for a sign-in but also offers a way on without an account. Take that guest "
    "path. Only if the task needs the person's own account, hand the page over with "
    "browser.read handoff so they can sign in."
)

# ``visible(el, min)``: rendered and at least min×min px inside the viewport.
# Challenge frames need 32 px (a real widget, not a 1-px tracker); inputs
# need 8 px, because a stock text field is ~21 px tall and would never pass
# the frame threshold.
_VISIBLE_FN = r"""(el, min) => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const w = Math.min(r.right, innerWidth) - Math.max(r.left, 0);
    const h = Math.min(r.bottom, innerHeight) - Math.max(r.top, 0);
    return w >= min && h >= min;
  }"""
# Whether a child frame's element is drawn as a challenge frame must be,
# asked of the element in its parent's document.
_SHOWN_JS = f"el => ({_VISIBLE_FN})(el, 32)"
_FACTS_JS = r"""
() => {
  const visible = __VISIBLE__;
  const frames = [...document.querySelectorAll('iframe')].map(f => ({
    title: f.title || '', src: f.src || '', visible: visible(f, 32), badge: !!f.closest('.grecaptcha-badge'),
  }));
  const otpish = /(^|[^a-z])(otp|otc|totp|passcode|one[-_ ]?time|verification[-_ ]?code|mfa[-_ ]?code|security[-_ ]?code)([^a-z]|$)/i;
  const skip = ['hidden', 'password', 'checkbox', 'radio', 'submit', 'button', 'file'];
  // A card's security code is called what a one-time code is called
  // ("security code", "verification code"). A field the page marks as a
  // card field (autocomplete cc-*) is never a one-time code. In a
  // document that holds a card-number field, the card's own words for
  // its code are taken out of a field's hints before the rule reads them
  // again, so "otp" or "one-time passcode" there still counts. The page
  // is only asked for a card-number field when a field looks one-time.
  const classify = __FIELD_KIND__;
  const CARD_CODE = __CARD_CODE__;
  const words = i => [i.name, i.id, i.placeholder, i.getAttribute('aria-label')].join(' ');
  const cardToken = i =>
    (i.getAttribute('autocomplete') || '').trim().toLowerCase().startsWith('cc-');
  const inputs = [...document.querySelectorAll('input')];
  const named = inputs.filter(i =>
      visible(i, 8) && !skip.includes((i.type || '').toLowerCase()) &&
      (i.autocomplete === 'one-time-code' || (!cardToken(i) && otpish.test(words(i)))));
  // A card field must be rendered (it may be scrolled off, so not
  // visible()): a hidden one says nothing about what the page asks for.
  const rendered = i => i.getClientRects().length > 0 && getComputedStyle(i).visibility !== 'hidden';
  const byCard = named.length > 0 && inputs.some(i => rendered(i) && classify(i) === 'cc-number');
  const otp = named.filter(i =>
      !byCard || i.autocomplete === 'one-time-code' ||
      otpish.test(words(i).replace(CARD_CODE, ' ')))
    .map(i => ({id: i.id || '', name: i.name || '', autocomplete: i.autocomplete || ''}));
  // A sign-in form, judged form by form (a box outside any form counts
  // only as a password box). "pair": its one rendered password box (not a
  // new one, not a card's code) beside a box for the account, a bank's
  // home page included; "field": one of them alone (an email first, then
  // the password). classify() hands either over only on a page named for
  // signing in, and notes a pair anywhere else. A form whose button (the
  // first submit after the box) signs up, subscribes, sends or searches,
  // and one that takes a card (its number with its code or expiry), is
  // not one. Cheap tests first: a label is read only for the few visible
  // boxes left.
  const TEXT = ['text', 'email', 'tel', 'number'];
  const ACCOUNT = /e-?mail|user|log[\s_-]?in|mobile|phone/i;
  const ID_WORD = /(^|[^a-z])id([^a-z]|$)/i;
  const GO = /sign[\s_-]?(in|on)|log[\s_-]?(in|on)|continue|next/i;
  const NOT_GO = /subscribe|send|search|sign[\s_-]?up|register|create\s+(an\s+)?account/i;
  // A way on without an account. The bare word is none: "Guest Services"
  // and "Guest reviews" sit on sign-in pages that need the account.
  const GUEST = /(continue|check\s*-?\s*out|proceed|shop|buy|pay|book|order|purchase)\s+as\s+(a\s+)?guest|guest\s+check\s*-?\s*out|without\s+(an?\s+)?account|without\s+(signing|logging)\s+in/i;
  const CODE_WORD = new RegExp(CARD_CODE.source, 'i');
  const token = (i, re) => re.test(i.getAttribute('autocomplete') || '');
  const labelText = i => {
    try { return [...(i.labels || [])].map(l => l.textContent).join(' '); } catch (e) { return ''; }
  };
  const said = el => {
    if (!el) return '';
    let byId = '';
    try {
      byId = (el.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean)
        .map(id => { const n = document.getElementById(id); return n ? n.textContent : ''; }).join(' ');
    } catch (e) {}
    return [el.value, el.textContent, el.getAttribute('aria-label'), byId].join(' ');
  };
  const accountField = i => {
    if (i.type === 'email' || i.type === 'tel') return true;
    if (token(i, /(^|\s)(username|webauthn|email|tel)(\s|$)/i) || ACCOUNT.test(words(i))) return true;
    const shown = [i.placeholder, i.getAttribute('aria-label'), labelText(i)].join(' ');
    return ACCOUNT.test(shown) || ID_WORD.test(shown);
  };
  // ponytail: a form's first 60 fields only; a page-wide form (ASP.NET)
  // whose card fields come later is not read for them.
  const takesPayment = form => {
    const kinds = new Set();
    let seen = 0;
    for (const el of form.elements) {
      if (seen++ >= 60) break;
      if (rendered(el)) kinds.add(classify(el) || '');
    }
    return kinds.has('cc-number') && [...kinds].some(k => k === 'cc-csc' || k.startsWith('cc-exp'));
  };
  const defaultButton = __DEFAULT_BUTTON__;
  const SUBMIT = 'button:not([type]), button[type=submit], input[type=submit], input[type=image]';
  // The words on the button that sends *box*: the first submit after it in
  // its form (a page-wide ASP.NET form puts the header's search first),
  // else the form's default button or first button of any kind.
  const buttonFor = (form, box) => {
    if (!form) return '';
    let after = null;
    try {
      for (const el of form.elements) {
        if (el.matches(SUBMIT) && (box.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING)) {
          after = el;
          break;
        }
      }
    } catch (e) {}
    return said(after || defaultButton(form) ||
      form.querySelector('button, input[type=button], [role=button]'));
  };
  // ponytail: a form's first 20 visible text boxes only. Each label read
  // walks the document, so asking every box of a page-wide form was
  // quadratic (2 s at 8000); an account box further down is missed. One
  // label-to-box map per evaluate if that ever bites.
  const shownBoxes = (list, max) => {
    const out = [];
    for (const t of list) {
      if (out.length >= max) break;
      if (visible(t, 8)) out.push(t);
    }
    return out;
  };
  const groups = new Map();
  for (const i of inputs) {
    const type = (i.type || '').toLowerCase();
    const password = type === 'password';
    if (!password && !(i.form && TEXT.includes(type))) continue;
    // A password box that is not drawn (a hidden register panel's) is none.
    if (password && !rendered(i)) continue;
    if (!groups.has(i.form)) groups.set(i.form, {passwords: [], texts: []});
    groups.get(i.form)[password ? 'passwords' : 'texts'].push(i);
  }
  const signinOf = (form, {passwords, texts}) => {
    const pw = passwords.length === 1 && visible(passwords[0], 8) &&
      !token(passwords[0], /new-password/i) ? passwords[0] : null;
    if (pw) {
      if (NOT_GO.test(buttonFor(form, pw))) return '';
      if (CODE_WORD.test(words(pw) + ' ' + labelText(pw)) || (form && takesPayment(form))) return '';
      // A card number here is the account's (a bank that signs on with its card).
      return shownBoxes(texts, 20).some(t => accountField(t) || classify(t) === 'cc-number')
        ? 'pair' : 'field';
    }
    if (!form || passwords.some(p => visible(p, 8))) return '';
    const shown = shownBoxes(texts, 2);
    if (shown.length !== 1 || !accountField(shown[0])) return '';
    const button = buttonFor(form, shown[0]);
    if (NOT_GO.test(button)) return '';
    return token(shown[0], /(^|\s)(username|webauthn)(\s|$)/i) || GO.test(button) ? 'field' : '';
  };
  let signin = '';
  for (const [form, group] of groups) {
    const found = signinOf(form, group);
    if (found === 'pair') { signin = found; break; }
    signin = signin || found;
  }
  // A way past the sign-in without an account, drawn anywhere on the page
  // (below the fold too): a link (with an href or not), a clickable
  // element, a button, or a radio's or checkbox's label ("Checkout as
  // Guest"). The agent takes it.
  const choice = l => !!l.control && ['radio', 'checkbox'].includes(l.control.type);
  // A control's own short words, never a question or a "not available"
  // (a help link, a wrapper's whole text).
  const offers = w => {
    w = (w || '').replace(/\s+/g, ' ').trim();
    return w.length <= 60 && GUEST.test(w) && !/[?]|\b(?:not|no|cannot|unavailable)\b|n['\u2019]t\b/i.test(w);
  };
  const guest = !!signin && ([...document.querySelectorAll(
    'a, [onclick], button, input[type=submit], input[type=button], [role=button], [role=link]'
  )].some(el => offers(said(el)) && rendered(el)) || [...document.querySelectorAll('label')]
    .some(l => offers(l.textContent) && choice(l) && rendered(l)));
  return {
    url: location.href, title: document.title || '',
    text: (document.body ? document.body.innerText : '').slice(0, 4000),
    frames, otp, signin, guest,
  };
}
""".replace("__VISIBLE__", _VISIBLE_FN).replace("__FIELD_KIND__", markers.FIELD_KIND_FN).replace(
    "__CARD_CODE__", f"new RegExp({json.dumps(markers.CVC_RE.pattern)}, 'gi')"
).replace("__DEFAULT_BUTTON__", markers.DEFAULT_BUTTON_FN)


def _is_mfa_host(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    for known in MFA_HOSTS:
        if host == known or host.endswith("." + known):
            if known == "accounts.google.com":
                return "challenge" in parsed.path.lower()
            return True
    return False


def _css_string(value: str) -> str:
    """*value* as the body of a double-quoted CSS string. The id/name come
    from the page: escaping only the quote would let a trailing backslash
    un-escape it and splice a second selector into ``otp_ref``."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return escaped.replace("\n", "\\a ").replace("\r", "\\d ").replace("\f", "\\c ")


def _selector_for(field: dict[str, str]) -> str:
    if field.get("id"):
        return 'css=[id="' + _css_string(field["id"]) + '"]'
    if field.get("name"):
        return 'css=input[name="' + _css_string(field["name"]) + '"]'
    return 'css=input[autocomplete="one-time-code"]'


def _log_url(url: str) -> str:
    """scheme://host/path only: IdP and bot-wall URLs carry session ids and
    SAML/OAuth state in the query, and log lines are persistent."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else parsed.path


def classify(facts: dict[str, Any]) -> Optional[Challenge]:
    """Spec §8 rules over the facts ``collect_facts`` gathered; first match wins."""
    url = facts.get("url") or ""
    lowered = url.lower()
    if any(marker in lowered for marker in _WALL_URLS):
        return Challenge("unusual_traffic", f"bot-wall URL: {urlparse(url).path}")
    for frame in facts.get("frames", []):
        if frame.get("badge") or not frame.get("visible"):
            continue
        title = frame.get("title") or ""
        src = (frame.get("src") or "").lower()
        if _CAPTCHA_TITLE.search(title) or any(host in src for host in CAPTCHA_HOSTS):
            return Challenge("captcha", f"visible challenge frame: {title or src}")
    idp_frames = facts.get("idp_frames", [])
    for scope in (facts, *idp_frames):
        for field in scope.get("otp", []):
            return Challenge("otp", "one-time code field on the page", otp_ref=_selector_for(field))
    text = f"{facts.get('title', '')}\n{facts.get('text', '')}"
    idp_text = "\n".join(f.get("text", "") for f in idp_frames)
    if (_is_mfa_host(url) or idp_frames) and _MFA_TEXT.search(text + "\n" + idp_text):
        return Challenge("mfa", "the identity provider is asking for a second factor")
    match = _HUMAN_TEXT.search(text)
    if match:
        return Challenge("unusual_traffic", f"page says: {match.group(0)}")
    # The page and its frames: a sign-in frame is judged by the page's name,
    # as an inline form is, an identity provider's by its own. A handoff in
    # any wins over a note.
    named = _named(facts)
    scopes = [(facts, named, None)]
    scopes += [(idp, _named(idp), idp.get("url")) for idp in idp_frames]
    scopes += [(logon, named, logon.get("url")) for logon in facts.get("signin_frames", [])]
    found = [
        step for scope, by, frame in scopes if (step := _signin_step(scope, by, frame)) is not None
    ]
    return min(found, key=lambda step: _SIGNIN_ORDER.index(step.kind), default=None)


_SIGNIN_ORDER = ("signin", "guest", "signin_form")


def _named(scope: dict[str, Any]) -> bool:
    """The document is named for signing in: its path names it (/ap/signin,
    /login), or its title's name does, a part of the title that starts or
    ends with the words ("Sign In | Hotel Rewards", "Amazon Sign-In",
    "Login"). A title that only mentions them in a sentence ("Can't log in
    after password reset - Fragrance Forum") names a thread to read."""
    if _SIGNIN_NAME.search(urlparse(scope.get("url") or "").path):
        return True
    for part in _TITLE_PARTS.split(scope.get("title") or ""):
        part = part.strip()
        for m in _SIGNIN_NAME.finditer(part):
            if m.start() == 0:
                return True
            # Ending with the words names the page only after a name of a
            # word or two ("Amazon Sign-In"), never a complaint ("Can't
            # log in", "Problem with login").
            before = part[: m.start()]
            if m.end() == len(part) and len(before.split()) <= 2 and not _NOT_A_NAME.search(before):
                return True
    return False


def _signin_step(scope: dict[str, Any], named: bool, frame: Optional[str]) -> Optional[Challenge]:
    """What one document's sign-in form makes it on a page *named* for
    signing in or not: a sign-in step there, a note elsewhere (a pair
    only), or None. *frame* is the child frame's address it is in."""
    signin = scope.get("signin")
    if not signin or not (named or signin == "pair"):
        return None
    if scope.get("guest"):
        return Challenge("guest", GUEST_PATH_NOTE, frame=frame)
    if named:
        return Challenge("signin", SIGNIN_DETAIL, frame=frame)
    return Challenge("signin_form", SIGNIN_FORM_NOTE, frame=frame)


# How long one IdP frame may take to answer (``_shared.REF_TIMEOUT_MS``).
_FRAME_TIMEOUT_S = 3.0


async def collect_facts(page: "Page") -> dict[str, Any]:
    """One evaluate on the main frame, plus one per IdP-hosted child frame
    (Duo's prompt lives in an iframe on the school's IdP page) and one per
    child frame whose address names signing in and whose element the
    person can see (a bank's logon box at /login on its home page), read
    for its sign-in form only."""
    facts = await page.evaluate(_FACTS_JS)
    facts["idp_frames"], facts["signin_frames"] = [], []
    for frame in page.frames:
        if frame is page.main_frame:
            continue
        if _is_mfa_host(frame.url):
            into, read = facts["idp_frames"], frame.evaluate(_FACTS_JS)
        elif _SIGNIN_NAME.search(urlparse(frame.url).path):
            into, read = facts["signin_frames"], _shown_frame_facts(frame)
        else:
            continue
        try:
            # Bounded: Playwright's frame.evaluate has none, and a frame
            # still without a document never answers.
            found = await asyncio.wait_for(read, _FRAME_TIMEOUT_S)
        except Exception:  # noqa: BLE001 - detached mid-read or no document; nothing to hand off in it
            continue
        if found is not None:
            into.append(found)
    return facts


# A bank's own payment check, as its frame words it (3-D Secure 2).
_BANK_CHECK_RE = re.compile(
    r"\b(?:3-?D\s*Secure|Verified\s+by\s+Visa|Visa\s+Secure|Mastercard\s+(?:ID|Identity)\s+Check"
    r"|SecureCode|SafeKey|ProtectBuy|authenticat\w*|verif(?:y|ication)\b|one[-\s]time\s+(?:code|pass)"
    r"|passcode|OTP|approve\s+(?:this|the|your)\s+(?:payment|purchase))",
    re.IGNORECASE,
)
BANK_DETAIL = "the bank is asking you to approve this payment"
_BANK_FRAME_JS = (
    "() => { const kind = " + markers.FIELD_KIND_FN + ";"
    " return { text: (document.body ? document.body.innerText : '').slice(0, 2000),"
    " card: [...document.querySelectorAll('input')].some(el => ['cc-number', 'cc-csc'].includes(kind(el))) }; }"
)


async def detect_bank_check(page: "Page", shop: "set[str]") -> Optional[Challenge]:
    """Right after an order is sent: a child frame on another origin than
    the shop's (*shop*, origins), drawn in the viewport, in a bank's check
    words and with no card field (a hosted card form left on the page is
    the shop's). 3-D Secure 2 shows its PIN or app approval in such a
    frame on the shop's own page, at any address, so the sign-in rules
    (an address or a page named for it) never see it."""
    for frame in page.frames:
        if frame is page.main_frame:
            continue
        parsed = urlparse(frame.url)
        if parsed.scheme not in ("http", "https") or f"{parsed.scheme}://{parsed.netloc}" in shop:
            continue
        try:
            element = await asyncio.wait_for(frame.frame_element(), _FRAME_TIMEOUT_S)
            if not await asyncio.wait_for(element.evaluate(_SHOWN_JS), _FRAME_TIMEOUT_S):
                continue
            found = await asyncio.wait_for(frame.evaluate(_BANK_FRAME_JS), _FRAME_TIMEOUT_S)
        except Exception:  # noqa: BLE001 - detached mid-read or no document: nothing to hand off in it
            continue
        if not found["card"] and _BANK_CHECK_RE.search(found["text"]):
            logger.info("browser_bank_check_detected", url=_log_url(frame.url))
            return Challenge("bank", BANK_DETAIL, frame=frame.url)
    return None


async def _shown_frame_facts(frame: Any) -> Optional[dict[str, Any]]:
    """*frame*'s facts, or None when its element is not drawn in the
    viewport (off screen, hidden, transparent, below the fold): a sign-in
    the person cannot see asks nothing of them."""
    element = await frame.frame_element()
    if not await element.evaluate(_SHOWN_JS):
        return None
    facts: dict[str, Any] = await frame.evaluate(_FACTS_JS)
    return facts


async def detect(page: "Page") -> Optional[Challenge]:
    """What the page asks of a person, the note kinds included: what
    ``_shared.observe`` describes a page with."""
    try:
        facts = await collect_facts(page)
    except Exception as exc:  # noqa: BLE001 - page mid-navigation or closed: nothing to hand off yet
        logger.debug("browser_handoff_facts_failed", error=str(exc)[:200])
        return None
    challenge = classify(facts)
    if challenge is not None:
        logger.info("browser_challenge_detected", kind=challenge.kind, url=_log_url(facts.get("url") or ""))
    return challenge


async def detect_challenge(page: "Page") -> Optional[Challenge]:
    """What to hand the person, or None: a note kind (a sign-in form on a
    page not named for it, a guest path) is never one, so no caller passes
    it to ``_shared.needs_human``."""
    challenge = await detect(page)
    return None if challenge is None or challenge.kind in NOTE_KINDS else challenge
