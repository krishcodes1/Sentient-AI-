"""Weekly app approvals: the owner allows Crawler to operate one app on this
computer for 7 days, from one desktop.act approval card, and only for
requests from the Telegram chat or the browser that allowed it.

Why it exists: every desktop.act had its own approval card, and every card
ends the turn; the task resumes after the tap as a new turn that sends the
whole conversation to the model again. Reading one day in Calendar took six
taps and about 129k tokens (spec 2026-09-25-weekly-app-approvals). With an
app allowed, its acts that only look around in it (``weekly_covers``) run at
once, in the same turn, under every toolkit rule and the taint gate, until the
week is up; then the next act raises a normal card that offers the week again.
Typing, and any click or key that could change or send something, keeps its
card: nobody looks at an act a weekly approval runs.

Tied to a channel (``Channel``): a Telegram approval holds only for turns from
the same Telegram chat (the linked private chat, which is all the bot
serves), and a web approval only for the same browser, named by a random
device id it sends as ``X-Crawler-Device`` and stored here only as a SHA-256.
A turn with no channel (a missing header, an automation) never uses one.

Only apps on ``rules.WEEKLY_APPS`` can be allowed: browsers, mail and chat
apps and anything with a store keep a card for every desktop act.

Site approvals are the same idea for Crawler's own browser, asked for by the
owner ("allow the assistant to get on with it"): from one browser.act card
the owner allows clicks on that card's website, by its exact host on https's
own port, for one hour and for the same chat or browser. During the hour a
browser.act there runs without a card only when it is a click, a choice or
a key that just moves (``may_run_site``), the act toolkit judged the live
target quiet (it sends no form, is not worded like a purchase or a price,
and the page shows no payment method, total or wallet), the target's own
name is not worded like something that changes, sends, ends or agrees
(``_SITE_CONSEQUENTIAL``), and the card would carry no money warning
(``site_covers``). Typing, sending a form and Enter always keep their card.
The runtime adds what holds for every unasked act: never on tainted
arguments, never after a tool result was flagged this turn, never past a
call check that asks for a card, never in an unattended run, and never on a
page tutor mode keeps for the student.

Website errands need no approval at all while the owner's "Ask before
every website step" switch is off (its default; the owner's words: "in one
approval, not 1000 approvals"). A browser.act that commits the person to
nothing then runs with no card in any turn, from any channel
(``errand_covers``): a step on an https page of one public host that shows
nothing to pay (a wallet button elsewhere on it does not count) and that
the act toolkit judged an errand step on the live page (``_page.errand``:
a plain link not worded like a purchase, a click that only moves a shop or
booking flow along, adding
to the cart, a choice, a search, a quantity, a zip or promo code, a site
search sent by GET, a key that only moves, a cookie banner's own Agree).
The toolkit's word is re-checked here from the facts it wrote: the words a
person reads on the control must not read as an outcome
(``errand_outcome``: pays, sends, posts, deletes, cancels, signs, agrees,
consents...), and every field typed into must be one of
``ERRAND_FIELD_KINDS``. A step that runs is marked unasked
(``unasked_arguments``): the act toolkit then lets it reach no order
address whatever the page says, and lets it send nothing but to a cart
or its own judged form (a choice the page would save at once is
stopped), so the step asks with a card instead. Outcomes keep exactly
one card. The runtime's rules above hold for errand steps too.

Connects to: the runtime (``AgentRuntime`` finds an approval before parking a
desktop.act or a browser.act and makes one when a card is approved with
``remember="week"`` or ``remember="site"``),
api/routes/agent.py (the channel of each web turn, the card's ``weekly_app``),
api/routes/app_approvals.py (list, revoke), the Telegram bot (the card's
third button, /apps), and the ``app_approvals`` table.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Mapping, Optional, Protocol
from urllib.parse import urlsplit

import structlog

# The purchase words (Playwright-free, like the rest of this module's imports).
from services.tools.browser.checkout.markers import link_orders
from services.tools.computer import keys as keymod
from services.tools.computer import rules
from services.tools.computer.toolkit import CARD_KEY, WEEKLY_MARK

logger = structlog.get_logger(__name__)

# How long one "Allow for 7 days" lasts; allowing again renews it.
WEEK = timedelta(days=7)
# The tool an app approval covers.
TOOL = "desktop.act"
# The decision option that allows the card's app for a week.
REMEMBER_WEEK = "week"
# A site approval: the tool it covers (browser.act on one website), how long
# one lasts (allowing again renews it) and the decision option that makes it.
# An hour is one errand: a booking or an order from start to finish, without
# leaving a site open to unseen clicks for days.
SITE_TOOL = "browser.act"
SITE_TTL = timedelta(hours=1)
REMEMBER_SITE = "site"
# A public site's host as a site approval is keyed by it: lower-case labels
# joined by dots (at least one dot, no port, no trailing dot), within the
# width of the app_key column.
_SITE_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_SITE_HOST_CHARS = 100
# The request header a browser names itself by (the web app's device id).
DEVICE_HEADER = "X-Crawler-Device"
# A device id as the web app makes it (crypto.randomUUID()), or any id of
# that alphabet and length.
_DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{16,100}")
# desktop.act actions that name their app themselves.
_APP_ACTIONS = frozenset({"open_app", "focus_window"})
# What a weekly approval covers (``weekly_covers``): looking around in the
# app. Keys that move through a view, bare or with cmd (Calendar's next and
# previous period).
_NAV_KEYS = frozenset({"up", "down", "left", "right", "pageup", "pagedown", "home", "end"})
_NAV_KEY_MODIFIERS = frozenset({"cmd"})
# Elements a click only selects or shows: a day, a row, a tab, a view.
_NAV_ROLES = frozenset(
    {"cell", "row", "list", "table", "tab", "radio button", "text", "static text", "image"}
)
# Buttons that only move through a view ("Next month", "Today", "Week").
_NAV_BUTTON = re.compile(
    r"(?:go\s+)?(?:next|previous|prev|back|today)(?:\s+(?:day|week|month|year|page))?"
    r"|day|week|month|year|zoom\s+(?:in|out)",
    re.IGNORECASE,
)
# Names of controls that change or send something, whatever their role: a
# weekly approval never clicks one ("Decline" on an invitation mails the
# organizer).
_CONSEQUENTIAL = re.compile(
    r"\b(?:send|share|invit\w*|accept|decline|maybe|tentative|reply|forward|delete|remove"
    r"|trash|erase|save|export|print|publish|post|submit|confirm|buy|pay|purchase|order"
    r"|subscribe|sign|call|facetime|message|e-?mail|upload|attach|install|allow)\b",
    re.IGNORECASE,
)

ChannelKind = Literal["telegram", "web"]
CHANNEL_KINDS: tuple[str, ...] = ("telegram", "web")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Naive timestamps (the SQLite backend) as UTC-aware."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


@dataclass(frozen=True)
class Channel:
    """Where a turn's request came from, as an approval is tied to it:
    ``("telegram", <chat id>)`` or ``("web", <sha256 of the device id>)``."""

    kind: ChannelKind
    key: str

    @classmethod
    def telegram(cls, chat_id: int) -> "Channel":
        return cls("telegram", str(int(chat_id)))

    @classmethod
    def web(cls, device_id: Any) -> Optional["Channel"]:
        """The browser a device id names, or None when it is missing or not
        one (the turn then uses no weekly approval)."""
        if not isinstance(device_id, str) or not _DEVICE_ID.fullmatch(device_id):
            return None
        return cls("web", hashlib.sha256(device_id.encode("ascii")).hexdigest())


@dataclass(frozen=True)
class WeeklyApproval:
    """Store-agnostic view of one approval."""

    id: str
    user_id: str
    app: str
    channel_kind: str
    channel_key: str
    granted_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime] = None
    # What it covers: desktop.act in ``app`` (an app on this computer), or
    # browser.act on ``app`` (a website's host).
    tool: str = TOOL

    def holds_for(self, channel: Optional[Channel]) -> bool:
        return (
            channel is not None
            and channel.kind == self.channel_kind
            and channel.key == self.channel_key
        )


def target_app(tool_name: str, arguments: Any) -> Optional[str]:
    """The app a desktop.act call acts in: the ``app`` it names for
    open_app and focus_window, else the app of the screen it is bound to
    (``CARD_KEY``, set by ``ComputerToolkit.bind``). None for any other
    tool, or when the call names none."""
    if tool_name != TOOL or not isinstance(arguments, Mapping):
        return None
    if arguments.get("action") in _APP_ACTIONS:
        app = arguments.get("app")
    else:
        screen = arguments.get(CARD_KEY)
        app = screen.get("app") if isinstance(screen, Mapping) else None
    return app.strip() if isinstance(app, str) and app.strip() else None


def weekly_app_for(tool_name: str, arguments: Any) -> Optional[str]:
    """The app (its weekly-list display name, e.g. "Calendar") a card for
    this call may be allowed for a week, or None: desktop.act only, and only
    in an app on ``rules.WEEKLY_APPS``. *arguments* are the card's (bound)."""
    app = target_app(tool_name, arguments)
    return rules.weekly_app(app) if app else None


def weekly_covers(arguments: Any) -> bool:
    """True when a weekly app approval may run this (bound) desktop.act with
    no card: it only looks around in the app. Scrolling; opening or
    switching to the app (the toolkit then leaves alone a front app that may
    be taking a password); navigation keys; and a click by ref on an element
    that only selects or shows something (a day cell, a row, a tab, a
    "Next month" button), as ``bind`` recorded it (``target``). Never
    ``type``, a click by coordinates, or a click on anything named like a
    control that changes or sends something (Send, Decline, Delete, Save).
    Nobody looks at these acts, and a click by ref carries no text the
    taint gate could match, so everything else keeps its card."""
    if not isinstance(arguments, Mapping):
        return False
    action = arguments.get("action")
    if action == "scroll" or action in _APP_ACTIONS:
        return True
    if action == "key":
        try:
            combo = keymod.parse_combo(arguments.get("keys"))
        except keymod.KeyComboError:
            return False
        return combo.key in _NAV_KEYS and combo.modifiers <= _NAV_KEY_MODIFIERS
    if action not in ("click", "double_click") or not isinstance(arguments.get("ref"), str):
        return False
    screen = arguments.get(CARD_KEY)
    target = screen.get("target") if isinstance(screen, Mapping) else None
    if not isinstance(target, Mapping):
        return False
    role, name = target.get("role"), target.get("name")
    if not isinstance(role, str) or not isinstance(name, str):
        return False
    role, name = role.strip().lower(), name.strip()
    if _CONSEQUENTIAL.search(name):
        return False
    return role in _NAV_ROLES or (role == "button" and bool(_NAV_BUTTON.fullmatch(name)))


def may_run_weekly(arguments: Any) -> bool:
    """True when a weekly app approval could run this desktop.act once it is bound: scrolling,
    open_app or focus_window, a navigation key (the same _NAV_KEYS test weekly_covers makes),
    or a click/double_click by ref. Never type and never a click by coordinates. A cheap
    superset of weekly_covers that needs no bind, for the call checks' runs_without_card (A29).

    Unbound arguments have no target yet, so a click by ref counts whatever it names: the
    weekly branch then binds it and ``weekly_covers`` decides. Every shape this refuses,
    ``weekly_covers`` refuses too, so a call it calls carded can never run unasked."""
    if not isinstance(arguments, Mapping):
        return False
    action = arguments.get("action")
    if action == "scroll" or action in _APP_ACTIONS:
        return True
    if action == "key":
        try:
            combo = keymod.parse_combo(arguments.get("keys"))
        except keymod.KeyComboError:
            return False
        return combo.key in _NAV_KEYS and combo.modifiers <= _NAV_KEY_MODIFIERS
    return action in ("click", "double_click") and isinstance(arguments.get("ref"), str)


def weekly_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """*arguments* (bound, as a card's) marked as run by a weekly approval
    (``WEEKLY_MARK`` on the screen): the toolkit then never brings the app
    forward, since no tap came just before the act."""
    screen = arguments.get(CARD_KEY)
    marked = {**(screen if isinstance(screen, Mapping) else {}), WEEKLY_MARK: True}
    return {**arguments, CARD_KEY: marked}


def _key(app: str) -> str:
    return rules.squash(app)


def site_key(host: Any) -> Optional[str]:
    """The key a site approval is stored and found by: the host itself, lower
    case, or None for anything that is not one public host name. Never
    ``rules.squash``: that drops the dots, and "a.bc.example" and
    "ab.c.example" are different sites."""
    if not isinstance(host, str):
        return None
    key = host.strip().lower()
    if len(key) > _SITE_HOST_CHARS or not _SITE_HOST.fullmatch(key):
        return None
    # A name, never an address: a router's or a NAS's admin page is no site
    # to allow for an hour, and "10.1" or "0x7f.1" is an address too (a
    # host name's last label is never all digits).
    if key.rpartition(".")[2].isdigit():
        return None
    try:
        ipaddress.ip_address(key)
    except ValueError:
        return key
    return None


# browser.act acts a site approval can run: a click, a choice, and the keys
# that only move the focus or close something. Never typing (fill,
# fill_form), never a submit and never Enter, which can send a form.
_SITE_ACTIONS = frozenset({"click", "select", "check"})
_SITE_KEYS = frozenset({"Tab", "Escape", "ArrowDown", "ArrowUp"})
# The reserved key a browser.act card stores its page under
# (services/tools/browser/act.CARD_KEY; not imported: that module needs
# Playwright, and this one is read by routes and channels).
_PAGE_KEY = "_page"
# Names of controls on a website that change, send, end or agree to
# something, whatever kind of control they are: a site approval never
# presses one ("Cancel booking", "Delete account", "Post", "I agree"). The
# desktop list above, and what a signed-in website adds to it. A script
# button sends no form, so its name is all that tells it from "Next".
# English only: a site in another language keeps its cards wherever the
# toolkit's own purchase rules do not already hold the act.
_SITE_CONSEQUENTIAL = re.compile(
    _CONSEQUENTIAL.pattern[:-3]
    + r"|cancel\w*|unsubscribe|transfer|log\s?out|sign\s?out|book\w*|reserv\w*|rsvp"
    r"|agree|apply|register|join|follow|unfollow|block|report|deactivate|revoke"
    r"|donate|tip|bid|check\s?out|place|renew|upgrade|downgrade|withdraw|vote"
    r"|comment|tweet|like|leave|close\s+account|empty|clear|reset|archive|merge"
    r"|approve|reject|refund|redeem|claim|enrol+|drop|unenrol+)\b",
    re.IGNORECASE,
)
# The longest name a card's target carries (page text: it is only matched).
_TARGET_NAME_CHARS = 200

# Website errands (the "Ask before every website step" switch off). Words
# on a control that commit the person to something: an errand step never
# presses one, whatever kind of control it is. The union of the site list
# above and the owner's list (pays, sends, posts, deletes, cancels, signs
# up, agrees), matched by stem: cancelling in any form ("Finish
# Cancellation"), signing (never "Sign in"), enrolling, authorising,
# granting, connecting, adding a friend, opting in or out, ending, stopping
# or pausing a membership, the social sends (repost, retweet, upvote),
# installing, activating, disabling, removing, declining, leaving,
# accepting; restarting, resuming or switching a plan, premium, selling,
# requesting, turning something on or off, making something public or
# private, a return, a last "Finish" (never the Finish Line brand), "End
# my", a bare "Yes"; every stem also with re, un, dis or down before it
# (unsend, unblock, downvote, disconnect, reactivate, resubscribe); and,
# for ticks, consent and assent (consent, acknowledge, "I have read", "I
# confirm"). "Apply filters", "Apply coupon", "Order summary", "Clear
# filters", "Save for later", "More like this" and "Maybe later" only move
# along. Short names a person presses to move on are steps by their whole
# name only (``_STEP_NAMES``); a cookie banner's own Agree, Accept, Allow,
# Yes or OK is a step only in a region that says cookies, as the toolkit
# read it (``consent_words``). Never "check out": going to the checkout
# commits nothing, and money only moves through browser.checkout. These
# lists only choose which steps are tried unasked: the act toolkit's
# network guard is what stops an unasked step that sends anything but to
# a cart, so a word missing here costs one card, not an outcome. English
# only: the act toolkit holds a page in any other language, or one that
# names none, to plain links, keys and search fields (act._errand).
_OUTCOME_PREFIX = r"\b(?:(?:re|un|dis|down)-?)?"
ERRAND_OUTCOME_RE = re.compile(
    _OUTCOME_PREFIX
    + r"(?:send|share|invit\w*|accept\w*|declin\w*|maybe(?!\s+later)|tentative|repl(?:y|ies)"
    r"|forward|delet\w*|remov\w*|trash|erase|save(?!\s+for\s+later)|export|print|publish\w*|post"
    r"|re-?post|submit\w*|confirm\w*|buy|pay|purchase\w*|re-?order"
    r"|order(?!\s+(?:list|history|details|status|summary))|subscri\w*|unsubscri\w*"
    r"|sign(?![\s-]*in\b)\w*|call|facetime|message|e-?mail|upload\w*|attach\w*|install\w*|allow\w*"
    r"|cancel\w*|transfer\w*|log[\s-]?out|book\w*|reserv\w*|rsvp|agree\w*"
    r"|apply(?!\s+(?:\S+\s+)?(?:filters?|coupon|promo|code|discount|voucher))|register\w*|join\w*"
    r"|follow\w*|unfollow\w*|block\w*|report\w*|deactivat\w*|revok\w*|donat\w*|tip|bid|place"
    r"|renew\w*|upgrad\w*|downgrad\w*|withdraw\w*|vote|comment|tweet|re-?tweet|like(?!\s+this)"
    r"|leave|close\s+(?:my\s+|your\s+|the\s+)?account|empty"
    r"|clear(?!\s+(?:all\s+)?(?:filters?|search))|reset(?!\s+(?:all\s+)?filters?)|archive|merge"
    r"|approv\w*|reject\w*|refund\w*|redeem\w*|claim\w*|enrol\w*|unenrol\w*|drop|review|rate"
    r"|create\s+(?:an?\s+|my\s+|your\s+)?account|authori[sz]\w*|grant\w*|connect"
    r"|add\s+(?:as\s+)?(?:a\s+)?friend|opt[\s-]?(?:out|in)|up-?vote|activat\w*|disabl\w*"
    r"|(?:end|stop|pause|turn\s+off)\s+(?:(?:my|your|the|this)\s+)?"
    r"(?:membership|subscription|plan|auto-?renew\w*)"
    r"|consent\w*|acknowledg\w*|i\s+have\s+read|i\s+confirm"
    r"|restart\w*|resum\w*|switch\s+(?:to|plans?|billing)|premium|sell|request|turn\s+(?:on|off)"
    r"|make\s+(?:\S+\s+){0,3}?(?:public|private)|return(?!\s+to\b)\w*|finish(?!\s+line\b)\w*"
    r"|end\s+my|yes)\b",
    re.IGNORECASE,
)
# A plain link is followed by GET, so its words are navigation ("Order
# online", "All showtimes" open the next page), except what a one-click
# link does on its own: an unsubscribe, sign-out, delete or confirm link,
# and the same stems as above where a GET can do them (cancelling,
# signing, accepting or declining an invitation, leaving a group,
# removing, authorising, granting, connecting..., with the same prefixes:
# disconnect, reactivate, uninstall). Those keep the card, and so does a
# link worded like a purchase ("Buy tickets", "Place order": the purchase
# words, ``errand_covers``), which a page's script can take over.
ERRAND_LINK_OUTCOME_RE = re.compile(
    _OUTCOME_PREFIX
    + r"(?:unsubscri\w*|log[\s-]?out|sign(?![\s-]*in\b)\w*|delet\w*|deactivat\w*|revok\w*"
    r"|confirm\w*|agree\w*|close\s+(?:my\s+|your\s+|the\s+)?account|remov\w*"
    r"|cancel\w*\b(?!\s+polic)|enrol\w*|unenrol\w*|authori[sz]\w*|grant\w*|connect"
    r"|add\s+(?:as\s+)?(?:a\s+)?friend|opt[\s-]?(?:out|in)"
    r"|(?:end|stop|pause|turn\s+off)\s+(?:(?:my|your|the|this)\s+)?"
    r"(?:membership|subscription|plan|auto-?renew\w*)"
    r"|re-?post|re-?tweet|up-?vote|install\w*|activat\w*|disabl\w*|declin\w*|leave|accept\w*)\b",
    re.IGNORECASE,
)
# Short names a person presses to move on (a pop-up's Cancel, a banner's
# Accept all): a step by its whole name only, never inside a longer one
# ("Cancel subscription", "Continue to cancel").
_STEP_NAMES = re.compile(
    r"\W*(?:cancel|close|dismiss|ok(?:ay)?|continue|next|back|got\s+it"
    r"|accept\s+(?:all\s+)?cookies|accept\s+all(?:\s+cookies)?|reject\s+all(?:\s+cookies)?)\W*",
    re.IGNORECASE,
)
# What a cookie banner's own button says: agreeing to the cookies, and
# nothing else ("Agree and close", "I agree", "Accept our cookie policy").
# A step only in a region that says cookies (the toolkit's ``consent``).
_CONSENT_WORDS = re.compile(
    r"\W*(?:(?:i|accept|agree|allow|ok(?:ay)?|all|cookies?|and|close|continue|got|it|yes|to|the"
    r"|use|of|our|policy)\b\W*)+",
    re.IGNORECASE,
)
# What a button that sends a form, or sits in one, may say and still be a
# step: the cart words (add to cart, update cart, go to checkout) and a
# quantity stepper's, which only change the cart: "increase" or
# "decrease" with the quantity in the same phrase, or as a stepper's whole
# name (``cart_words``), never inside a longer name ("Increase credit limit").
ERRAND_FORM_STEP_RE = re.compile(
    r"\badd(?:\s+it)?\s+to\s+(?:the\s+|my\s+|your\s+)?(?:shopping\s+)?"
    r"(?:cart|bag|basket|trolley|order\s+list)\b"
    r"|\bupdate\s+(?:the\s+|my\s+|your\s+)?(?:cart|bag|basket|quantity|qty)\b"
    r"|\b(?:proceed|continue|go)\s+to\s+(?:the\s+)?(?:checkout|check\s+out|cart|bag|basket)\b"
    r"|\b(?:increase|decrease|reduce|change)\s+(?:the\s+|item\s+)?(?:quantity|qty)\b",
    re.IGNORECASE,
)
_STEPPER_NAME = re.compile(
    r"\W*(?:increase|decrease|quantity|qty|plus|minus|\+|-|−)\W*", re.IGNORECASE
)
# "Check out" on a button that sends its form to a cart (Shopify's cart page).
CHECKOUT_WORDS_RE = re.compile(r"\bcheck[\s-]?out\b", re.IGNORECASE)
# The fields an errand step may type into, as the act toolkit classed them
# on the live page (``_page.fields``, one per field typed into).
ERRAND_FIELD_KINDS = frozenset({"search", "quantity", "zip", "promo"})
# The browser.act shapes an errand step can be; Enter only for a site search.
_ERRAND_KEYS = _SITE_KEYS | {"Enter"}
# The mark on the page of a browser.act that runs with no card (an errand
# step, a site approval's click): the act toolkit then lets it reach no
# order address, inside its write window too (``unasked_arguments``).
UNASKED_MARK = "unasked"
# What a card's money facts may show for an errand step to run unasked: a
# wallet button elsewhere on the page, or the control's own words, but no
# order total, amount, payment method on file or unread frame.
_MONEY_SHOWN = ("order_total", "saved_payment", "unread", "amount")


def _parts(words: str) -> list[str]:
    return [part.strip() for part in words.split("|") if part.strip()]


def errand_outcome(words: str, *, link: bool = False) -> bool:
    """Whether a control's words (the parts a person reads, joined by " | ")
    commit the person to something: a part matches the outcome list (a
    plain link's own, for *link*) and is not a short name a person presses
    to move on (``_STEP_NAMES``, by its whole name)."""
    outcome = ERRAND_LINK_OUTCOME_RE if link else ERRAND_OUTCOME_RE
    return any(outcome.search(part) and not _STEP_NAMES.fullmatch(part) for part in _parts(words))


def consent_words(words: str) -> bool:
    """Whether every part of a control's words only agrees to cookies
    ("Agree and close", "OK", "Yes", "Accept all cookies"): a step only in
    a region that says cookies (the act toolkit's ``consent`` fact; a
    region that says consent alone, an OAuth screen or a terms dialog, is
    not one)."""
    parts = _parts(words)
    return bool(parts) and all(_CONSENT_WORDS.fullmatch(part) for part in parts)


def cart_words(words: str) -> bool:
    """Whether a button that sends a form may: some part of its words is
    cart words (``ERRAND_FORM_STEP_RE``) or a quantity stepper's whole name."""
    return any(
        ERRAND_FORM_STEP_RE.search(part) or _STEPPER_NAME.fullmatch(part) for part in _parts(words)
    )


def errand_money_ok(money: Any) -> bool:
    """Whether a card's money facts let an errand step run unasked: none at
    all, or ones that show no order total, amount, payment method on file
    or unread frame (a wallet button elsewhere, a link worded like a
    purchase). A fact that is missing counts as shown."""
    if not money:
        return True
    return isinstance(money, Mapping) and not any(money.get(key, True) for key in _MONEY_SHOWN)


def unasked_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """*arguments* (a bound browser.act, as a card's) marked as run with no
    card (``UNASKED_MARK`` on the page): the act toolkit then keeps every
    order address shut for it, whatever the page said of itself."""
    page = arguments.get(_PAGE_KEY)
    marked = {**(page if isinstance(page, Mapping) else {}), UNASKED_MARK: True}
    return {**arguments, _PAGE_KEY: marked}


def carries_page(arguments: Any) -> bool:
    """Whether a browser.act call's own arguments hold the reserved page
    key. Only the act toolkit writes it (when it binds a card); in a call
    as the model sent it, it is forged."""
    return isinstance(arguments, Mapping) and _PAGE_KEY in arguments


def may_run_site(arguments: Any) -> bool:
    """True when a site approval could run this browser.act once it is bound:
    a click, select or check by ref, or one of the keys that only move. A
    cheap superset of ``site_covers`` that needs no bind, for the call
    checks' runs_without_card. Every shape this refuses, ``site_covers``
    refuses too, so a call it calls carded can never run unasked."""
    if not isinstance(arguments, Mapping):
        return False
    action = arguments.get("action")
    if action in _SITE_ACTIONS:
        return isinstance(arguments.get("ref"), str)
    return action == "press" and arguments.get("key") in _SITE_KEYS


def site_for(tool_name: str, arguments: Any) -> Optional[str]:
    """The website (its host) a browser.act card acts on, as a site approval
    names it: the host of the page the card is bound to, on https only. None
    for any other tool, an unbound call, an http page, or an origin that is
    not one plain public host (credentials in it, an IP literal, localhost)."""
    if tool_name != SITE_TOOL or not isinstance(arguments, Mapping):
        return None
    page = arguments.get(_PAGE_KEY)
    if not isinstance(page, Mapping) or page.get("scheme") != "https":
        return None
    origin = page.get("origin")
    if not isinstance(origin, str):
        return None
    try:
        parts = urlsplit(origin)
        port = parts.port  # raises ValueError for a port that is no number
    except ValueError:
        return None
    if parts.scheme != "https" or parts.username is not None or parts.password is not None:
        return None
    # Another port is another origin (another server, as likely as not): it
    # is never covered by, and never offers, the hour of the site itself.
    if port not in (None, 443):
        return None
    return site_key(parts.hostname)


def site_covers(arguments: Any) -> bool:
    """True when a site approval may run this (bound) browser.act with no
    card: it only clicks around on the site. The shape must be one
    ``may_run_site`` accepts, the page an https page of one host, and the
    toolkit itself must have judged the live target quiet when it bound the
    call (``_page.quiet`` is True: not a control that sends a form, not one
    worded like a purchase or a price, on a page with no payment method on
    file and no wallet; services/tools/browser/act.py). A card that carries
    a money warning is never covered: a person looks at that one. And the
    target's own name, as the toolkit read it (``_page.target.name``), must
    not be worded like something that changes, sends, ends or agrees
    (``_SITE_CONSEQUENTIAL``). Nobody looks at these acts, so everything
    else keeps its card."""
    if not may_run_site(arguments) or site_for(SITE_TOOL, arguments) is None:
        return False
    page = arguments[_PAGE_KEY]
    if page.get("quiet") is not True or page.get("money"):
        return False
    if arguments.get("action") == "press":
        return True  # a key that only moves has no target
    # A click or a choice is judged once more here by its target's own name
    # as the toolkit read it off the live page (``target``): a script button
    # sends no form and reads as quiet whatever it is called. No name to
    # read, or a name of the wrong shape, keeps the card.
    target = page.get("target")
    name = target.get("name") if isinstance(target, Mapping) else None
    if not isinstance(name, str) or not name.strip() or len(name) > _TARGET_NAME_CHARS:
        return False
    return _SITE_CONSEQUENTIAL.search(name) is None


def may_run_errand(arguments: Any) -> bool:
    """True when an errand step could be this browser.act once it is bound:
    a click, choice, tick, fill or submit by ref, a fill_form with fields, or
    a key that only moves or Enter. A cheap superset of ``errand_covers``
    that needs no bind, for the call checks' runs_without_card."""
    if not isinstance(arguments, Mapping):
        return False
    action = arguments.get("action")
    if action in _SITE_ACTIONS or action in ("fill", "submit"):
        return isinstance(arguments.get("ref"), str)
    if action == "fill_form":
        fields = arguments.get("fields")
        return isinstance(fields, (list, tuple)) and bool(fields)
    return action == "press" and arguments.get("key") in _ERRAND_KEYS


# What a page may have put in typed text that matters: a link, an email, a
# host name, or a long number (an account, a card, a phone).
_NOT_PLAIN_RE = re.compile(r"://|www\.|@|\d{6,}|\b[a-z0-9-]+\.[a-z]{2,}\b", re.IGNORECASE)
_PLAIN_TEXT_CHARS = 100


def plain_errand_text(arguments: Any) -> bool:
    """True when this browser.act types only short plain words (a product
    name, a quantity, a zip or promo code): such text read on a page may
    still be typed unasked into errand fields (``errand_covers`` judges the
    fields), since a site search sends nothing a page could want. A link,
    an email, a host name or a long number keeps the card."""
    if not isinstance(arguments, Mapping):
        return False
    action = arguments.get("action")
    if action == "fill":
        texts = [arguments.get("text")]
    elif action == "fill_form" and isinstance(arguments.get("fields"), (list, tuple)):
        texts = [f.get("text") if isinstance(f, Mapping) else None for f in arguments["fields"]]
    else:
        return False
    return bool(texts) and all(
        isinstance(t, str) and 0 < len(t) <= _PLAIN_TEXT_CHARS and not _NOT_PLAIN_RE.search(t) for t in texts
    )


def errand_covers(arguments: Any) -> bool:
    """True when this (bound) browser.act is an errand step that may run with
    no card while "Ask before every website step" is off. The shape must be
    one ``may_run_errand`` accepts, the page an https page of one public host
    (``site_for``), the toolkit must have judged the step an errand on the
    live page (``_page.errand`` is True, services/tools/browser/act.py), and
    the card's money facts must show nothing to pay (``errand_money_ok``: a
    wallet button elsewhere on the page is no reason to ask). Then, from what
    the toolkit wrote: every field typed into is an errand field
    (``_page.fields``), and the control's words as a person reads them
    (``_page.target.words``, else its ``name``) read as no outcome, a plain
    link's as nothing a one-click link does by itself and as no purchase
    (``markers.link_orders``: a page's script can take a "Place order"
    link over and send the order; a ticket funnel's "Buy tickets" is none), a cookie banner's
    own Agree or OK aside when the toolkit found it in a region about
    cookies or consent (``target.consent``). Anything missing or of the
    wrong shape keeps the card. The runtime runs a covered step marked
    unasked (``unasked_arguments``), so no order address opens for it."""
    if not may_run_errand(arguments) or site_for(SITE_TOOL, arguments) is None:
        return False
    page = arguments[_PAGE_KEY]
    if page.get("errand") is not True or not errand_money_ok(page.get("money")):
        return False
    action = arguments.get("action")
    if action in ("fill", "fill_form"):
        kinds = page.get("fields")
        typed = 1 if action == "fill" else len(arguments["fields"])
        return (
            isinstance(kinds, list)
            and len(kinds) == typed
            and all(isinstance(k, str) and k in ERRAND_FIELD_KINDS for k in kinds)
        )
    if action == "press" and arguments.get("key") != "Enter":
        return True  # a key that only moves has no target
    target = page.get("target")
    if not isinstance(target, Mapping):
        return False
    name = target.get("words", target.get("name"))
    if not isinstance(name, str) or len(name) > _TARGET_NAME_CHARS:
        return False
    link = action == "click" and target.get("plain_link") is True
    consented = not link and target.get("consent") is True and consent_words(name)
    if not consented and errand_outcome(name, link=link):
        return False
    if link and link_orders(f"{target.get('name')} | {name}"):
        return False  # a page's script can make a "Place order" link place it
    # A site search may have no button to name; any other control needs words.
    return link or action in ("submit", "press") or bool(name.strip())


def site_offer(tool_name: str, arguments: Any) -> Optional[str]:
    """The website a card for this call may be allowed for an hour (its
    "Allow clicks on <site> for 1 hour" button), or None: a browser.act card
    bound to an https page of one host, unless the card carries a money
    warning (a card that says the step may place an order asks about that
    step and nothing else). *arguments* are the card's (bound)."""
    site = site_for(tool_name, arguments)
    if site is None or arguments[_PAGE_KEY].get("money"):
        return None
    return site


def _stored_key(tool: str, app: str) -> Optional[str]:
    """The ``app_key`` of an approval of *tool* for *app*; None when *app*
    cannot be one (a site approval for something that is not a host)."""
    return site_key(app) if tool == SITE_TOOL else _key(app)


def _ttl(tool: str) -> timedelta:
    return SITE_TTL if tool == SITE_TOOL else WEEK


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


class AppApprovalStore(Protocol):
    """Approvals of both kinds: an app for a week (``tool`` = desktop.act,
    the default) and a website for an hour (``tool`` = browser.act, ``app``
    its host, matched exactly). ``allow`` raises ValueError for a site
    approval whose *app* is not a host; ``find`` answers None for one."""

    async def allow(
        self,
        *,
        user_id: str,
        app: str,
        channel: Channel,
        source_action_id: Optional[str] = None,
        tool: str = TOOL,
    ) -> WeeklyApproval: ...

    async def find(
        self, *, user_id: str, app: str, channel: Channel, tool: str = TOOL
    ) -> Optional[WeeklyApproval]: ...

    async def record_use(self, approval_id: str) -> None: ...

    async def list_active(self, user_id: str) -> list[WeeklyApproval]: ...

    async def revoke(self, *, user_id: str, approval_id: str) -> Optional[WeeklyApproval]: ...

    async def revoke_channel(self, *, user_id: str, kind: str) -> int: ...


@dataclass
class _MemRecord:
    approval: WeeklyApproval
    app_key: str
    revoked: bool = False
    uses: int = 0


class InMemoryAppApprovalStore:
    """Single-process store for tests and a runtime with no database; main.py
    injects ``DbAppApprovalStore``."""

    def __init__(self, now: Callable[[], datetime] = _utcnow) -> None:
        self._now = now
        self._records: dict[str, _MemRecord] = {}

    def _live(self, record: _MemRecord, now: datetime) -> bool:
        return not record.revoked and record.approval.expires_at > now

    def _matching(
        self, user_id: str, app: str, channel: Channel, tool: str = TOOL
    ) -> Optional[_MemRecord]:
        now, key = self._now(), _stored_key(tool, app)
        if key is None:
            return None
        for record in self._records.values():
            a = record.approval
            if (
                a.user_id == user_id
                and a.tool == tool
                and record.app_key == key
                and a.holds_for(channel)
                and self._live(record, now)
            ):
                return record
        return None

    async def allow(
        self,
        *,
        user_id: str,
        app: str,
        channel: Channel,
        source_action_id: Optional[str] = None,
        tool: str = TOOL,
    ) -> WeeklyApproval:
        key = _stored_key(tool, app)
        if key is None:
            raise ValueError("a site approval needs a host name")
        now = self._now()
        record = self._matching(user_id, app, channel, tool)
        if record is not None:
            record.approval = replace(record.approval, granted_at=now, expires_at=now + _ttl(tool))
            return record.approval
        approval = WeeklyApproval(
            id=str(uuid.uuid4()),
            user_id=user_id,
            app=key if tool == SITE_TOOL else app,
            channel_kind=channel.kind,
            channel_key=channel.key,
            granted_at=now,
            expires_at=now + _ttl(tool),
            tool=tool,
        )
        self._records[approval.id] = _MemRecord(approval=approval, app_key=key)
        return approval

    async def find(
        self, *, user_id: str, app: str, channel: Channel, tool: str = TOOL
    ) -> Optional[WeeklyApproval]:
        record = self._matching(user_id, app, channel, tool)
        return record.approval if record is not None else None

    async def record_use(self, approval_id: str) -> None:
        record = self._records.get(approval_id)
        if record is not None:
            record.uses += 1
            record.approval = replace(record.approval, last_used_at=self._now())

    async def list_active(self, user_id: str) -> list[WeeklyApproval]:
        now = self._now()
        live = [
            r.approval
            for r in self._records.values()
            if r.approval.user_id == user_id and self._live(r, now)
        ]
        return sorted(live, key=lambda a: a.expires_at)

    async def revoke(self, *, user_id: str, approval_id: str) -> Optional[WeeklyApproval]:
        record = self._records.get(approval_id)
        if record is None or record.revoked or record.approval.user_id != user_id:
            return None
        record.revoked = True
        return record.approval

    async def revoke_channel(self, *, user_id: str, kind: str) -> int:
        count = 0
        for record in self._records.values():
            a = record.approval
            if a.user_id == user_id and a.channel_kind == kind and not record.revoked:
                record.revoked = True
                count += 1
        return count


class DbAppApprovalStore:
    """Persists approvals in the ``app_approvals`` table, with its own
    short-lived sessions (the runtime that calls it has no request scope).
    Expiry is compared in Python, as the approval store does, so a naive
    SQLite timestamp and an aware Postgres one read the same."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        if session_factory is None:
            from core.database import async_session

            session_factory = async_session
        self._session_factory = session_factory
        self._now = now

    @staticmethod
    def _view(row: Any) -> WeeklyApproval:
        return WeeklyApproval(
            id=str(row.id),
            user_id=str(row.user_id),
            app=row.app_name,
            channel_kind=row.channel_kind,
            channel_key=row.channel_key,
            granted_at=_as_utc(row.granted_at),
            expires_at=_as_utc(row.expires_at),
            last_used_at=_as_utc(row.last_used_at) if row.last_used_at else None,
            tool=row.tool,
        )

    @staticmethod
    def _uuid(value: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(value))
        except ValueError:
            return None

    async def _live_rows(self, session: Any, user_uuid: uuid.UUID, **where: Any) -> list[Any]:
        from sqlalchemy import select

        from models.app_approval import AppApproval

        # Both kinds unless ``tool`` is among *where*: the owner's list shows
        # the apps and the sites together.
        query = select(AppApproval).where(
            AppApproval.user_id == user_uuid,
            AppApproval.tool.in_((TOOL, SITE_TOOL)),
            AppApproval.revoked_at.is_(None),
        )
        for column, value in where.items():
            query = query.where(getattr(AppApproval, column) == value)
        now = self._now()
        rows = (await session.execute(query)).scalars().all()
        return [row for row in rows if _as_utc(row.expires_at) > now]

    async def allow(
        self,
        *,
        user_id: str,
        app: str,
        channel: Channel,
        source_action_id: Optional[str] = None,
        tool: str = TOOL,
    ) -> WeeklyApproval:
        from models.app_approval import AppApproval

        key = _stored_key(tool, app)
        if key is None:
            raise ValueError("a site approval needs a host name")
        user_uuid = uuid.UUID(user_id)
        source = self._uuid(source_action_id) if source_action_id else None
        now = self._now()
        async with self._session_factory() as session:
            live = await self._live_rows(
                session,
                user_uuid,
                tool=tool,
                app_key=key,
                channel_kind=channel.kind,
                channel_key=channel.key,
            )
            if live:
                row = live[0]
                row.granted_at, row.expires_at = now, now + _ttl(tool)
                row.source_action_id = source
            else:
                row = AppApproval(
                    user_id=user_uuid,
                    tool=tool,
                    app_key=key,
                    app_name=key if tool == SITE_TOOL else app,
                    channel_kind=channel.kind,
                    channel_key=channel.key,
                    granted_at=now,
                    expires_at=now + _ttl(tool),
                    source_action_id=source,
                )
                session.add(row)
            await session.flush()
            view = self._view(row)
            await session.commit()
        return view

    async def find(
        self, *, user_id: str, app: str, channel: Channel, tool: str = TOOL
    ) -> Optional[WeeklyApproval]:
        user_uuid, key = self._uuid(user_id), _stored_key(tool, app)
        if user_uuid is None or key is None:
            return None
        async with self._session_factory() as session:
            live = await self._live_rows(
                session,
                user_uuid,
                tool=tool,
                app_key=key,
                channel_kind=channel.kind,
                channel_key=channel.key,
            )
            return self._view(live[0]) if live else None

    async def record_use(self, approval_id: str) -> None:
        from sqlalchemy import update

        from models.app_approval import AppApproval

        approval_uuid = self._uuid(approval_id)
        if approval_uuid is None:
            return
        async with self._session_factory() as session:
            await session.execute(
                update(AppApproval)
                .where(AppApproval.id == approval_uuid)
                .values(uses=AppApproval.uses + 1, last_used_at=self._now())
            )
            await session.commit()

    async def list_active(self, user_id: str) -> list[WeeklyApproval]:
        user_uuid = self._uuid(user_id)
        if user_uuid is None:
            return []
        async with self._session_factory() as session:
            live = await self._live_rows(session, user_uuid)
            return sorted((self._view(row) for row in live), key=lambda a: a.expires_at)

    async def revoke(self, *, user_id: str, approval_id: str) -> Optional[WeeklyApproval]:
        from sqlalchemy import select

        from models.app_approval import AppApproval

        user_uuid, approval_uuid = self._uuid(user_id), self._uuid(approval_id)
        if user_uuid is None or approval_uuid is None:
            return None
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AppApproval).where(
                        AppApproval.id == approval_uuid,
                        AppApproval.user_id == user_uuid,
                        AppApproval.revoked_at.is_(None),
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            row.revoked_at = self._now()
            view = self._view(row)
            await session.commit()
        return view

    async def revoke_channel(self, *, user_id: str, kind: str) -> int:
        from sqlalchemy import update

        from models.app_approval import AppApproval

        user_uuid = self._uuid(user_id)
        if user_uuid is None:
            return 0
        async with self._session_factory() as session:
            result = await session.execute(
                update(AppApproval)
                .where(
                    AppApproval.user_id == user_uuid,
                    AppApproval.channel_kind == kind,
                    AppApproval.revoked_at.is_(None),
                )
                .values(revoked_at=self._now())
            )
            await session.commit()
        # An UPDATE's result is a CursorResult, which counts the rows.
        return int(getattr(result, "rowcount", 0) or 0)
