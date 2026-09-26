"""browser.act: the agent types, chooses, clicks and submits in Crawler's
own browser (purchases spec §5).

WRITE tier, one approval card per call: the model may fill a field,
fill a form, pick an option, tick a box, click anything (a "Sign up"
button included: that is what the card is for), press a key or submit a
form. The same session, egress guard, handoff detector, caps and loop
detector as browser.read; every act ends with the fresh outline the way
browser.read's actions do, plus ``did`` ("Typed 12 characters into
"Email"") so the model knows what happened without re-reading.

Hard rules, checked before the card (``precheck``, no browser call) and
again when the approved act runs:

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
  hidden in a shadow tree nobody can read does), and it is
  refused as ``use_checkout`` whatever the purchases switch says when its
  words are a purchase ("Place order", "Pay now", "Jetzt kaufen"...: the
  lists in ``checkout.markers``), when its form holds a card right now,
  when it or a link is aimed at an order path (/place-order, /pay), when
  it is anything but a plain link on a page (any frame of it) that shows
  a payment method on file next to a price, or when it is a button (a
  clickable <div> included) on a page that shows an order total next to
  a payment method on file (``markers.pays``, with every frame's facts
  joined in): money moves through browser.checkout and its own card, or
  not at all. A check or a select is refused the same way when its own
  words are a purchase or the page shows a payment method on file next
  to a price (``markers.change_pays``).
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
  which must be the page the card showed.

Every card shows the owner the page. ``bind_async`` (the executor's
card-time bind) takes a screenshot of the page as it is when the card is
made, with the target outlined in a 3px red box (an overlay added and
removed around the capture) and secret fields masked by the shared mask,
keeps it in memory only (``approval_image`` serves it to the web card and
the Telegram photo; it is never stored with the card) and adds to the
card's sentence, from the page's own facts, the line "This page shows
$499.00 and a saved payment method. This step may place an order. Crawler
normally pays only through its checkout step." whenever any frame shows
an order total, a payment method on file or a wallet button, or the
target matches a purchase pattern that did not refuse it. A capture that
fails leaves the card with "No picture of the page could be taken." So
no act, and no money it could move, runs without the owner having seen
the page on its card; the rules above are defence in depth. A card whose
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
``auto_submit`` with one plain sentence. An act is the agent's next action on the
session, so it shuts a pending handoff's window first
(``_shared.take_back``); a challenge after an act hands the window to
the person the way browser.read's handoff does. Model text is not a secret:
``typed_secrets`` is untouched, and neither the text nor a field's value
ever appears in a summary, a log line or ``did``.
"""

from __future__ import annotations

import asyncio
import secrets
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence

import structlog

from core.config import settings
from services.tools.browser import _shared
from services.tools.browser import snapshot as snap
from services.tools.browser._shared import (
    REF_TIMEOUT_MS,
    HandoffDetector,
    PlaywrightError,
    PlaywrightTimeoutError,
)
from services.tools.browser.actions import LOOP_REPEATS, Guard, mode_for
from services.tools.browser.checkout import markers
from services.tools.browser.checkout.amounts import fmt_usd, parse_money
from services.tools.browser.guard import SENDING_REASONS
from services.tools.browser.pagememory import (
    LastPage,
    PageMemory,
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
    """A rule refused the act: the result is ``{ok, refused, rule, error}``."""

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


def _invalid(message: str) -> _Refused:
    return _Refused("invalid_arguments", message)


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
    return _Bound(str(origin), str(outline), str(scheme), address)


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
    name = _short(names.get(ref) or "")
    return f'"{name}"' if name else ref


def _sentence(request: _Request, names: Mapping[str, str], on_host: str) -> str:
    """The approval-card sentence, built from facts the page memory holds,
    never from the model's words: the element's name, the count of
    characters (not the text), the key, the host."""
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
        return f"Click {target}{on_host}"
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
    ) -> None:
        self._sessions = sessions
        self._guard = guard
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

    # -- the card's three hooks (no browser call) ------------------------------

    def precheck(self, params: Mapping[str, Any], *, user_id: str) -> Optional[dict[str, Any]]:
        """The refusal a browser.act call would get from the checks that
        need no browser (arguments, the stop flag, no page looked at yet,
        a ref the latest outline does not have, a secure field, an
        http:// page), or None. The runtime asks it before making an
        approval card, so a call it refuses never gets one; ``execute``
        runs the same checks again. A check that fails refuses the call
        (rule ``check_failed``)."""
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
            return {
                "ok": False,
                "refused": True,
                "rule": "check_failed",
                "error": "Could not check this action before asking for approval, so nothing was done.",
            }
        return None

    def bind(self, params: Mapping[str, Any], *, user_id: str) -> dict[str, Any]:
        """*params* as a browser.act approval card stores them: with the
        page the card is made from under ``CARD_KEY`` (origin, address,
        outline digest and scheme of *user_id*'s latest observation, all
        empty when there is none), replacing anything the call itself put
        there. The approved act then runs only on that page."""
        last = self._memory.get(user_id)
        page = {
            "origin": last.origin if last else "",
            "address": page_address(last.url) if last else "",
            "outline": last.outline_digest if last else "",
            "scheme": last.scheme if last else "",
        }
        return {**dict(params or {}), CARD_KEY: page}

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
        sentence = _sentence(request, names, f" on {host}" if host else "")
        notes = _card_notes(card)
        if self._picture_gone(card, user_id):
            notes += f" {PICTURE_GONE_NOTE}"
        return f"{sentence}.{notes}" if notes else sentence

    # -- the card's picture (the one bind that touches the browser) -----------

    async def bind_async(
        self, params: Mapping[str, Any], *, user_id: str, task_id: str
    ) -> dict[str, Any]:
        """``bind``, plus what the owner sees on the card: a picture of the
        page as it is now, with the target outlined in red and secret
        fields masked (kept in memory under ``_page.picture``; "" when it
        could not be taken, which the card then says), and, under
        ``_page.money``, the page's own facts when it shows an order total,
        a payment method on file or a wallet button, or the target matches
        a purchase pattern (the card then warns that the step may place an
        order). Never raises: a page that cannot be looked at gives a card
        without a picture, never no card."""
        card = self.bind(params, user_id=user_id)
        page_card = dict(card[CARD_KEY])
        picture, money = "", None
        try:
            call = {k: v for k, v in dict(params or {}).items() if k != CARD_KEY}
            request = _parse(call)
            session = await self._sessions.get(user_id, mode=mode_for(user_id), task_id=task_id)
            async with session.lock:
                page = await session.page()
                money = await self._money_facts(page, request)
                image = await self._picture(page, request)
            if image is not None:
                picture = self._keep_picture(user_id, image)
        except Exception as exc:  # noqa: BLE001 - the card is still made, and says so
            _shared.log_failure("browser_act_card_picture_failed", exc)
        page_card["picture"] = picture
        if money is not None:
            page_card["money"] = money
        return {**card, CARD_KEY: page_card}

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
                    await page.main_frame.evaluate(_OUTLINE_FOCUS_JS)
                except Exception as exc:  # noqa: BLE001 - the picture without the box
                    _shared.log_failure("browser_act_outline_failed", exc, action="press")
            return await _shared.jpeg(page, None)
        except Exception as exc:  # noqa: BLE001 - the card says no picture was taken
            _shared.log_failure("browser_act_picture_failed", exc)
            return None
        finally:
            for frame in list(page.frames):
                try:
                    await frame.evaluate(_REMOVE_OUTLINE_JS)
                except Exception:  # noqa: BLE001 - a frame that went away took its box along
                    pass

    async def _money_facts(self, page: Any, request: _Request) -> Optional[dict[str, Any]]:
        """What the card's money warning is built from, or None when there
        is nothing to warn about: every frame's facts (an order total and
        its amount, a payment method on file, a wallet button, a frame or
        shadow tree that could not be read), and whether the target itself
        matches a purchase pattern (``markers.read_click_pays`` for a click,
        a submit or Enter; ``markers.change_pays`` for a check or a select).
        A target that cannot be judged counts as one that may order."""
        answers = await _shared.page_facts(page)
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
        try:
            may_order = await self._target_may_order(page, request, answers)
        except Exception as exc:  # noqa: BLE001 - not judged counts as may order
            _shared.log_failure("browser_act_card_judge_failed", exc)
            may_order = True
        if may_order or any(facts[k] for k in ("order_total", "saved_payment", "wallet", "unread")):
            return facts
        return None

    async def _target_may_order(self, page: Any, request: _Request, answers: list[Any]) -> bool:
        """Whether the act's target matches a purchase pattern, judged as the
        approved act will judge it (the control the click reaches, the
        form's default button, the focus; what a choice chooses)."""
        if request.action in _SENDING_ACTIONS and (request.refs or request.key == "Enter"):
            if request.refs:
                script = (
                    markers.SUBMIT_TARGET_JS if request.action == "submit" else markers.PURCHASE_TARGET_JS
                )
                target = await page.locator(f"aria-ref={request.refs[0]}").evaluate(
                    script, timeout=REF_TIMEOUT_MS
                )
            else:
                target = await self._enter_target(page)
            return markers.read_click_pays(markers.join_page(target, answers))
        if request.action in _CHOICE_ACTIONS:
            target = await page.locator(f"aria-ref={request.refs[0]}").evaluate(
                markers.CHANGE_TARGET_JS, request.value or "", timeout=REF_TIMEOUT_MS
            )
            return markers.change_pays(markers.join_page(target, answers))
        return False

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
                return await self._run(session, request, bound)
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
        if request.action in _SENDING_ACTIONS or request.action in _CHOICE_ACTIONS:
            for ref in request.refs:
                if markers.PURCHASE_RE.search(f"{last.names.get(ref, '')} | {request.value or ''}"):
                    raise _Refused("use_checkout", markers.USE_CHECKOUT_MESSAGE)
                # A submit through a field sends the form by its default
                # button, whose words the page memory kept for the field.
                if request.action == "submit" and markers.PURCHASE_RE.search(
                    last.form_buttons.get(ref, "")
                ):
                    raise _Refused("use_checkout", markers.USE_CHECKOUT_MESSAGE)
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
        of any frame, an order address) during an act not meant to send."""
        state = self._guard.egress_state(session.context)
        return state is not None and any(
            entry.get("reason") in SENDING_REASONS for entry in state.blocked[since:]
        )

    @staticmethod
    def _label(session: BrowserSession, value: str) -> str:
        return _short(snap.redact(value, session.typed_secrets, "•••"))

    # -- the approved act -------------------------------------------------------

    async def _run(
        self, session: BrowserSession, request: _Request, bound: Optional[_Bound]
    ) -> dict[str, Any]:
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
        await self._check_outline(session, page, bound)
        if request.refs and request.action in _TYPING_ACTIONS:
            await self._check_fields(page, request.refs)
        sends = False
        if request.action in _SENDING_ACTIONS and (request.refs or request.key == "Enter"):
            target = await self._check_purchase(page, request)
            sends = not target.get("plain_link")
        elif request.action in _CHOICE_ACTIONS:
            await self._check_choice(page, request)
        state = self._guard.egress_state(session.context)
        blocked_before = self._blocked_count(session)
        try:
            if state is not None:
                state.write_allowed = sends
                state.write_page = page  # the card's page: no other tab sends
                state.changing = not sends
            did, args = await self._perform(session, page, request)
        finally:
            if state is not None:
                state.write_allowed = False
                state.write_page = None
                state.changing = False
        if not sends and self._sent_anyway(session, since=blocked_before):
            raise _Refused("auto_submit", _AUTO_SUBMIT)
        blocked = self._blocked_reason(session, since=blocked_before)
        if blocked is not None and page.url.startswith("chrome-error://"):
            return _shared.error_result(f"That action was refused by the network policy: {blocked}")
        return await _shared.observe(
            session,
            self._handoff,
            f"act {request.action}",
            args,
            extra={"did": did},
            memory=self._memory,
            guard=self._guard,
        )

    async def _check_outline(
        self, session: BrowserSession, page: Any, bound: Optional[_Bound]
    ) -> None:
        """The page's address, and its outline taken the way the remembered
        one was, must still be what the card (or, unapproved, the latest
        observation) was made from: a ref means nothing otherwise, and a
        key goes to whatever page is open. This snapshot also makes the
        refs resolvable for the act itself."""
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
        expected = bound.outline if bound is not None else (last.outline_digest if last else "")
        if outline_digest(out.lines) != expected:
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

    async def _check_purchase(self, page: Any, request: _Request) -> dict[str, Any]:
        """The live page decides, whatever the outline said: the control
        that would send the form (the element the click lands on, or the
        button, link or label target around it; for a submit through a
        field, that form's default button; for Enter, the focused element
        or the focused field's default button, in whatever shadow root or
        frame the focus is),
        its words, its form and the page around it, every frame of it
        (``markers.pays``). A target that would place an order is refused:
        that is browser.checkout's job. Returns the target judged."""
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
                raise _Refused("use_checkout", markers.USE_CHECKOUT_MESSAGE)
        target = markers.join_page(target, await _shared.page_facts(page))
        if markers.pays(target) or not isinstance(target, dict):
            raise _Refused("use_checkout", markers.USE_CHECKOUT_MESSAGE)
        return target

    async def _check_choice(self, page: Any, request: _Request) -> None:
        """A check or a select, judged on the live page by what it chooses
        and by every frame of the page around it (``markers.change_pays``):
        choosing the card on file on a review page is the order's first
        half, and a page may send its form on the change."""
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
        if markers.change_pays(markers.join_page(target, await _shared.page_facts(page))):
            raise _Refused("use_checkout", markers.USE_CHECKOUT_MESSAGE)

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
