"""browser.checkout: the toolkit behind the one purchase approval card
(purchases spec §6). ``precheck`` (no browser) -> ``begin`` (reads the
page, makes the card's arguments and keeps its screenshot in memory) ->
``describe`` / ``approval_image`` (what the card shows) -> ``run`` (after
the owner approved: fills the card from the vault, submits, reads the
confirmation).

Why every step is a safeguard and not a block: buying is on only when the
owner turned it on, and then Crawler still (1) reads the amount and the
merchant off the page itself, (2) refuses http, a look-alike host, a
missing or foreign total, a missing card form and anything over the caps
before the card exists, (3) shows one card with the amount, the host, the
items, a screenshot and the notice, and (4) after Approve, runs only
while the page the card was made from is still the page on screen, then
fills the card fields from the vault at that moment and never earlier.
The card is decrypted inside ``run`` only. Before it is typed, every
value (the number as digits and as a page groups them, the security
code, the expiry in every form a site writes it) goes on the session's
redaction list, so nothing the page echoes reaches the model, a result
or a summary; a page that keeps the form on screen (a validation stop,
a click that did nothing, a cancel between the fill and the submit) has
its card fields cleared and checked empty before anything is looked at
or photographed. No card value reaches a log line either: an exception
raised while the card is in play is logged by its type alone. The order
form's target is bound at ``begin`` and checked again at ``run``, and
while the order is sent the network guard admits, from any frame, only a
POST to that origin and stops an answer that would re-send the card
elsewhere (a 307/308 to another origin). What a page's own script sends
(an XHR, a beacon) is not judged: a hostile page could copy what it
holds that way, as it could at any moment before the submit.

Failures are results, never exceptions: a refusal is ``{"ok": False,
"refused": True, "rule", "error"}`` (the runtime files it under
``purchase_rule``), anything else ``{"ok": False, "error"}``. A checkout
that failed after the card was filled says ``"filled": True`` so the
owner is told to check the site, and the ledger counts it as spent
unless the merchant declined it (a submit the guard stopped counts too:
the guard cannot always tell whether the merchant read the card first).

The executor's pre-approval hook is synchronous; ``precheck_sync`` is the
part of ``precheck`` it can run (arguments, the stop flag, the vault's
availability). ``precheck`` adds the checks that need the database.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, Callable, Mapping, Optional, Protocol
from urllib.parse import urlsplit

import structlog

from services.tools.browser import _shared
from services.tools.browser import snapshot as snap
from services.tools.browser.actions import mode_for
from services.tools.browser.checkout import NOTICE, markers
from services.tools.browser.checkout.amounts import fmt_usd, usd
from services.tools.browser.checkout.facts import (
    REF_TIMEOUT_MS,
    CardFields,
    CheckoutFacts,
    classify_facts,
    collect_checkout_facts,
)
from services.tools.browser.checkout.ledger import PurchaseLedger
from services.tools.browser.handoff import Challenge
from services.tools.browser.session import BrowserSession, BrowserSessionManager

if TYPE_CHECKING:
    # Annotations only: the toolkit duck-types both (the vault: available,
    # get_card_view, open_card; the memory: forget), so importing this
    # module never loads the vault or the act toolkit.
    from services.tools.browser.pagememory import PageMemory
    from services.vault.service import VaultService

logger = structlog.get_logger(__name__)

# The reserved argument the card's binding travels under. No checkout
# call takes it; only ``begin`` sets it and only ``run`` reads it.
CARD_KEY = "_checkout"
CancelFlag = Callable[[str], bool]

MAX_MERCHANT_CHARS = 200
MAX_NOTE_CHARS = 500
MAX_AMOUNT = Decimal("100000")
NAVIGATION_TIMEOUT_MS = 20_000
# Fields whose pixels never leave the machine, in every frame (the one
# classifier every toolkit shares); the card fields found on the page are
# masked by ref on top of this.
MASK_SELECTOR = _shared.MASK_SELECTOR
_CONFIRMATION_RE = re.compile(
    r"order (?:number|no\.?|#|id|confirmed|complete|placed|received)|thank you|thanks for your "
    r"(?:order|purchase)|confirmation|receipt|payment (?:received|successful|complete)"
    r"|purchase complete|your order is",
    re.IGNORECASE,
)
_DECLINED_RE = re.compile(
    r"declined|payment failed|could not be processed|couldn't be processed|try another card"
    r"|insufficient funds|invalid card|card was not accepted|transaction failed",
    re.IGNORECASE,
)
_CONFIRMATION_CHARS = 600
_CONFIRMATION_LEAD = 150
_MAX_PENDING = 64
_ALLOWED_PARAMS = frozenset({"merchant", "amount", "note"})

_NO_CARD = "No payment card is stored. Add one in Settings → Payment card."
_UNBOUND = (
    "This approval is not tied to a checkout Crawler prepared (it may have expired), so "
    "nothing was paid. Ask me to check out again."
)
_SCREEN_CHANGED = (
    "The page changed since you approved this. Look again and ask me to check out once more."
)
_CANCELLED = "Stopped: this task was cancelled, so nothing was paid."
_UNAPPROVED = "browser.checkout runs only from an approval card the owner accepted."
_CARD_LEFT = (
    " Crawler could not clear the card details from the page; the person should close "
    "that tab."
)


class PurchaseSettings(Protocol):
    """What the toolkit needs from the installation service."""

    async def purchase_caps(self) -> tuple[Decimal, Decimal]: ...  # (per purchase, per day)


class _Guard(Protocol):
    async def install_egress_guard(self, context: Any, *, account_mode: bool) -> None: ...
    async def settle_blocked_navigation(self, page: Any, *, timeout_ms: int = 1500) -> None: ...
    def egress_state(self, context: Any) -> Any: ...


class _HandoffDetector(Protocol):
    async def detect_challenge(self, page: Any) -> Optional[Challenge]: ...


class _Refused(Exception):
    """A safeguard said no. Filed with its rule name."""

    def __init__(self, rule: str, message: str) -> None:
        super().__init__(message)
        self.rule = rule
        self.message = message


class _Failed(Exception):
    """An ordinary failure whose message is safe to show the model."""

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.message = message
        self.extra = extra


@dataclass(frozen=True)
class _Request:
    merchant: str
    amount: Optional[Decimal]
    note: str


@dataclass
class _Pending:
    """One checkout waiting for the owner: the facts its card was made
    from and the screenshot the card shows. In memory only, at most one
    per user, dropped after the approval TTL."""

    checkout_id: str
    user_id: str
    facts: CheckoutFacts
    charge: Decimal  # the page total: what the merchant will take and the ledger records
    amount: Decimal  # what the caps are checked against: max(page total, model amount)
    card_label: str
    user_image: Optional[str]
    created: float


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _refusal(rule: str, message: str) -> dict[str, Any]:
    return {"ok": False, "refused": True, "rule": rule, "error": message}


def _log_failure(event: str, exc: BaseException, *, detail: bool = True, **fields: Any) -> None:
    """A warning with the exception's type and, unless *detail* is off,
    its text with Playwright's call log, any quoted fill value and every
    URL's query string removed (``_shared.log_detail``). While a card is
    in play the text is left out altogether: the type says enough."""
    if detail:
        fields["error"] = _shared.log_detail(exc)
    logger.warning(event, error_type=type(exc).__name__, **fields)


# A value read back from a card field shorter than this is not put on the
# redaction list on its own (a bare month, a short code): the forms
# remembered before the fill cover it, and redacting "12" everywhere
# would blank the page.
_MIN_TYPED_CHARS = 4


def _origin_of(url: str) -> str:
    """``scheme://host[:port]`` of *url*, as the guard compares origins."""
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.rpartition('@')[2].lower()}"


def _expiry_forms(month: int, year: int) -> list[str]:
    """Every way a site renders an expiry (``12/28``, ``12/2028``,
    ``12-28``, ``2028-12``, ``12 / 28``, ``1228``...): all of them are
    redacted once the card is typed."""
    mm, yy, yyyy = f"{month:02d}", f"{year % 100:02d}", f"{year:04d}"
    forms: list[str] = []
    for sep in ("/", "-", ".", " / ", " "):
        forms += [f"{mm}{sep}{yy}", f"{mm}{sep}{yyyy}", f"{yyyy}{sep}{mm}"]
    forms += [f"{mm}{yy}", f"{mm}{yyyy}", f"{yyyy}{mm}"]
    return forms


def _number_forms(number: str) -> list[str]:
    """The digits, then the groupings a card is printed in (4-4-4-4, or
    4-6-5 for a 15-digit number) with spaces and with dashes. The outline
    and ``snap.redact`` find any grouping from the digits alone; the
    printed forms are for the one redaction that still does a plain
    replace (browser.read's page text)."""
    if len(number) == 15:
        parts = [number[:4], number[4:10], number[10:]]
    else:
        parts = [number[i : i + 4] for i in range(0, len(number), 4)]
    return [number, " ".join(parts), "-".join(parts)]


def _card_secrets(secret: Any) -> list[str]:
    """What the redaction list must hold before the card is typed: the
    number as digits and as printed, the security code, and the expiry
    in every form. Never the name: a person's name is not a secret, and
    redacting it would hide the delivery address."""
    values: list[str] = []
    number = "".join(ch for ch in str(getattr(secret, "number", "") or "") if ch.isdigit())
    if number:
        values += _number_forms(number)
    cvc = str(getattr(secret, "cvc", "") or "").strip()
    if cvc:
        values.append(cvc)
    month, year = int(getattr(secret, "exp_month", 0) or 0), int(getattr(secret, "exp_year", 0) or 0)
    if month and year:
        values += _expiry_forms(month, year)
    return values


def _decimal(value: Any) -> Optional[Decimal]:
    """A model-supplied amount as a Decimal, or None when it is not a
    plain positive number (booleans and NaN included)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return None
    try:
        amount = Decimal(value.strip().lstrip("$"))
    except InvalidOperation:
        return None
    if not amount.is_finite() or amount <= 0 or amount > MAX_AMOUNT:
        return None
    return amount


def _parse(params: Any) -> _Request:
    if params is None:
        params = {}
    if not isinstance(params, Mapping):
        raise _Refused("invalid_arguments", "browser.checkout takes an object of arguments.")
    given = {k: v for k, v in params.items() if v is not None}
    unknown = sorted(str(k)[:30] for k in given if k not in _ALLOWED_PARAMS)
    if unknown:
        # CARD_KEY among them: only begin sets it, so a call carrying it is
        # refused like any argument the tool does not take.
        raise _Refused(
            "invalid_arguments",
            f"browser.checkout does not take {', '.join(unknown)} (it takes: merchant, amount, note).",
        )
    merchant = given.get("merchant")
    if not isinstance(merchant, str) or not merchant.strip():
        raise _Refused(
            "invalid_arguments",
            "checkout needs 'merchant': the site the person asked to buy from, e.g. ticketmaster.com.",
        )
    merchant = " ".join(merchant.split())[:MAX_MERCHANT_CHARS]
    amount: Optional[Decimal] = None
    if "amount" in given:
        amount = _decimal(given["amount"])
        if amount is None:
            raise _Refused(
                "invalid_arguments",
                "amount must be the number of US dollars you expect to pay, e.g. 23.40.",
            )
    note = given.get("note", "")
    if not isinstance(note, str):
        raise _Refused("invalid_arguments", "note must be text.")
    return _Request(merchant=merchant, amount=amount, note=" ".join(note.split())[:MAX_NOTE_CHARS])


def _card(arguments: Any) -> Optional[dict[str, Any]]:
    """The ``_checkout`` binding on a card's arguments, or None."""
    if not isinstance(arguments, Mapping):
        return None
    card = arguments.get(CARD_KEY)
    if not isinstance(card, Mapping) or not isinstance(card.get("checkout_id"), str):
        return None
    return dict(card)


def _items_phrase(count: int) -> str:
    if count <= 0:
        return ""
    return " (1 item)" if count == 1 else f" ({count} items)"


class BrowserCheckoutToolkit:
    def __init__(
        self,
        sessions: BrowserSessionManager,
        *,
        guard: _Guard,
        handoff: _HandoffDetector,
        memory: "PageMemory",
        vault: "VaultService",
        ledger: PurchaseLedger,
        settings: PurchaseSettings,
        cancel_flag: CancelFlag,
        clock: Callable[[], float] = time.monotonic,
        pending_ttl_s: float = 900,
    ) -> None:
        self._sessions = sessions
        self._guard = guard
        self._handoff = handoff
        self._memory = memory
        self._vault = vault
        self._ledger = ledger
        self._settings = settings
        self._cancel_flag = cancel_flag
        self._clock = clock
        self._ttl = pending_ttl_s
        self._pending: dict[str, _Pending] = {}

    # -- precheck (no browser) -------------------------------------------------

    def precheck_sync(self, params: Mapping[str, Any], *, user_id: str) -> Optional[dict[str, Any]]:
        """The checks that need neither a browser nor a database: the
        arguments, the stop flag, the vault's availability. The executor's
        synchronous pre-approval hook runs exactly these."""
        try:
            _parse(params)
            self._check_cancel(user_id)
            self._check_vault()
        except _Refused as refusal:
            return _refusal(refusal.rule, refusal.message)
        except Exception as exc:  # fail closed: an unchecked call gets no card
            _log_failure("checkout_precheck_failed", exc)
            return _refusal(
                "check_failed",
                "Could not check this purchase before asking for approval, so nothing was done.",
            )
        return None

    async def precheck(self, params: Mapping[str, Any], *, user_id: str) -> Optional[dict[str, Any]]:
        """``precheck_sync`` plus the database checks: the caps can be read
        and a card is stored (rule ``no_card``)."""
        refusal = self.precheck_sync(params, user_id=user_id)
        if refusal is not None:
            return refusal
        try:
            await self._settings.purchase_caps()
            await self._card_label(user_id)
        except _Refused as refused:
            return _refusal(refused.rule, refused.message)
        except Exception as exc:
            _log_failure("checkout_precheck_failed", exc)
            return _refusal(
                "check_failed",
                "Could not read the purchase settings or the stored card, so nothing was done.",
            )
        return None

    def _check_cancel(self, user_id: str) -> None:
        try:
            cancelled = bool(self._cancel_flag(user_id))
        except Exception as exc:  # no answer is not a "carry on"
            _log_failure("checkout_cancel_flag_failed", exc)
            cancelled = True
        if cancelled:
            raise _Refused("cancelled", _CANCELLED)

    def _check_vault(self) -> None:
        try:
            ok, reason = self._vault.available()
        except Exception as exc:
            _log_failure("checkout_vault_unavailable", exc)
            ok, reason = False, ""
        if not ok:
            # The provider's reason is the sentence the owner reads in
            # Settings too ("Crawler could not open this Mac's Keychain.
            # Unlock the Mac and try again.", "...not available in this
            # environment (container)."): the same words here, with no
            # second "not available" in front of them.
            reason = " ".join(str(reason or "").split())
            raise _Refused("vault_unavailable", reason or "The card vault is not available.")

    async def _card_label(self, user_id: str) -> str:
        """The stored card's masked label ("Visa ····4242"); refuses with
        ``no_card`` when none is stored."""
        view = await self._vault.get_card_view(user_id)
        if view is None:
            raise _Refused("no_card", _NO_CARD)
        label = str(getattr(view, "masked", "") or "").strip()
        return label or "the stored card"

    # -- begin: the card's arguments -------------------------------------------

    async def begin(self, params: Mapping[str, Any], *, user_id: str, task_id: str) -> dict[str, Any]:
        """The arguments the approval card stores: the model's own plus
        ``_checkout`` with the facts read off the page, or a refusal dict.
        The one binding that may touch the browser, because the card must
        show what the page says now. Every failure is a refusal dict, so
        the runtime never mistakes an error for card arguments."""
        try:
            request = _parse(params)
            self._check_cancel(user_id)
            self._check_vault()
            caps = await self._settings.purchase_caps()
            card_label = await self._card_label(user_id)
            session = await self._session(user_id, task_id)
            async with session.lock:
                await self._ensure_guard(session)
                await _shared.take_back(self._guard, session)
                page = await session.page()
                await self._no_challenge(session, page)
                facts = await collect_checkout_facts(page)
                self._check_cancel(user_id)
                spent = await self._ledger.spent_last_24h(user_id)
                verdict = classify_facts(
                    facts,
                    expected_merchant=request.merchant,
                    model_amount=request.amount,
                    per_purchase_cap=caps[0],
                    per_day_cap=caps[1],
                    spent_today=spent,
                )
                if verdict is not None:
                    await self._record_refusal(user_id, task_id, facts, request, verdict)
                    raise _Refused(*verdict)
                charge = usd(facts.total)
                assert charge is not None and facts.card_fields is not None  # classify_facts checked
                amount = max(charge, request.amount) if request.amount is not None else charge
                image = await self._screenshot(page, facts.card_fields)
                session.task.actions += 1
                session.task.summaries.append(
                    f"[step {session.task.actions}] checkout {facts.host} · ${fmt_usd(charge)} · "
                    "waiting for approval"
                )
        except _Refused as refusal:
            logger.info("checkout_refused", rule=refusal.rule, user_id=user_id)
            return _refusal(refusal.rule, refusal.message)
        except _Failed as failure:
            return _refusal("check_failed", failure.message)
        except Exception as exc:  # last resort: never raise into the agent loop
            _log_failure("checkout_begin_failed", exc)
            return _refusal(
                "check_failed", "Could not read the checkout page, so nothing was done. Try again."
            )
        checkout_id = secrets.token_hex(8)
        self._purge_expired()
        self._pending[user_id] = _Pending(
            checkout_id=checkout_id,
            user_id=user_id,
            facts=facts,
            charge=charge,
            amount=amount,
            card_label=card_label,
            user_image=image,
            created=self._clock(),
        )
        try:
            await self._ledger.record(
                user_id,
                "purchase_requested",
                merchant=facts.host,
                amount_usd=charge,
                currency="USD",
                items=len(facts.items),
                task_id=task_id,
                checkout_id=checkout_id,
            )
        except Exception as exc:  # the card cannot exist unrecorded
            _log_failure("checkout_audit_failed", exc, purchase_event="purchase_requested")
            self._pending.pop(user_id, None)
            return _refusal(
                "check_failed", "Could not record this purchase request, so nothing was done."
            )
        arguments: dict[str, Any] = {"merchant": request.merchant}
        if request.amount is not None:
            arguments["amount"] = fmt_usd(request.amount)
        if request.note:
            arguments["note"] = request.note
        arguments[CARD_KEY] = {
            "checkout_id": checkout_id,
            "origin": facts.origin,
            "host": facts.host,
            "amount_usd": fmt_usd(charge),
            "currency": "USD",
            "items": list(facts.items),
            "card_label": card_label,
            "outline": facts.outline_digest,
            "submit_to": facts.submit_target.action if facts.submit_target is not None else "",
            "notice": NOTICE,
        }
        logger.info(
            "checkout_prepared",
            host=facts.host,
            amount_usd=fmt_usd(charge),
            items=len(facts.items),
            user_id=user_id,
        )
        return arguments

    async def _record_refusal(
        self,
        user_id: str,
        task_id: str,
        facts: CheckoutFacts,
        request: _Request,
        verdict: tuple[str, str],
    ) -> None:
        """A refused purchase is on the record with the amount it was
        about, so the owner's ledger tells the whole story; a ledger that
        will not write does not hide the refusal itself."""
        rule, _message = verdict
        try:
            await self._ledger.record(
                user_id,
                "purchase_refused",
                merchant=facts.host,
                amount_usd=usd(facts.total) if facts.total is not None else request.amount,
                currency=facts.total.currency if facts.total is not None else "USD",
                items=len(facts.items),
                task_id=task_id,
                reason=rule,
            )
        except Exception as exc:
            _log_failure("checkout_audit_failed", exc, purchase_event="purchase_refused")

    # -- what the card shows ------------------------------------------------------

    def describe(self, arguments: Mapping[str, Any], *, user_id: str) -> str:
        """``Pay $23.40 to shop.example.com (2 items) with Visa ····4242``,
        from the card's own ``_checkout`` facts, never the model's words."""
        card = _card(arguments)
        if card is None:
            merchant = arguments.get("merchant") if isinstance(arguments, Mapping) else None
            where = f" at {merchant}" if isinstance(merchant, str) and merchant.strip() else ""
            return f"Pay{where} (the checkout facts are missing, so this will be refused)"
        items = card.get("items")
        count = len(items) if isinstance(items, list) else 0
        return (
            f"Pay ${card.get('amount_usd', '?')} to {card.get('host', '?')}{_items_phrase(count)} "
            f"with {card.get('card_label', 'the stored card')}"
        )

    def approval_image(self, arguments: Mapping[str, Any], *, user_id: str) -> Optional[str]:
        """The screenshot taken when the card was made, while the checkout
        is pending; None afterwards (a restart drops it too)."""
        card = _card(arguments)
        pending = self._pending_for(user_id, card["checkout_id"] if card else "")
        return pending.user_image if pending is not None else None

    def _pending_for(self, user_id: str, checkout_id: str) -> Optional[_Pending]:
        pending = self._pending.get(user_id)
        if pending is None or not checkout_id or pending.checkout_id != checkout_id:
            return None
        if self._clock() - pending.created > self._ttl:
            self._pending.pop(user_id, None)
            return None
        return pending

    def _purge_expired(self) -> None:
        now = self._clock()
        for user, pending in list(self._pending.items()):
            if now - pending.created > self._ttl:
                del self._pending[user]
        while len(self._pending) > _MAX_PENDING:
            oldest = min(self._pending, key=lambda u: self._pending[u].created)
            del self._pending[oldest]

    # -- run: after Approve -------------------------------------------------------

    async def run(
        self, arguments: dict[str, Any], *, user_id: str, task_id: str, approved: bool
    ) -> dict[str, Any]:
        """Pay. Only from an approved card whose checkout is still pending
        (``unbound_approval``), only while the page is the one the card
        was made from (``screen_changed``), with the caps checked again,
        and only once the approval is on the ledger (``check_failed``)."""
        if not approved:
            return _refusal("unbound_approval", _UNAPPROVED)
        card = _card(arguments)
        pending = self._pending_for(user_id, card["checkout_id"] if card else "")
        if card is None or pending is None:
            return _refusal("unbound_approval", _UNBOUND)
        try:
            self._check_cancel(user_id)
            session = await self._session(user_id, task_id)
            async with session.lock:
                await self._ensure_guard(session)
                await _shared.take_back(self._guard, session)
                page = await session.page()
                await self._no_challenge(session, page)
                facts = await collect_checkout_facts(page)
                self._same_page(pending, card, facts)
                caps = await self._settings.purchase_caps()
                spent = await self._ledger.spent_last_24h(user_id)
                verdict = classify_facts(
                    facts,
                    expected_merchant=str(arguments.get("merchant") or pending.facts.host),
                    model_amount=pending.amount,
                    per_purchase_cap=caps[0],
                    per_day_cap=caps[1],
                    spent_today=spent,
                )
                if verdict is not None:
                    raise _Refused(*verdict)
                assert facts.card_fields is not None and facts.submit_ref is not None
                self._check_cancel(user_id)
                self._pending.pop(user_id, None)
                try:
                    await self._ledger.record(
                        user_id,
                        "purchase_approved",
                        merchant=facts.host,
                        amount_usd=pending.charge,
                        currency="USD",
                        items=len(facts.items),
                        task_id=task_id,
                        checkout_id=pending.checkout_id,
                    )
                except Exception as exc:
                    # This row counts the purchase against the daily cap
                    # until its outcome is on the record: without it the
                    # card stays in the vault.
                    _log_failure("checkout_audit_failed", exc, purchase_event="purchase_approved")
                    raise _Refused(
                        "check_failed",
                        "Could not write this purchase to Crawler's record before paying, so "
                        "nothing was paid. Ask me to check out again.",
                    ) from exc
                return await self._pay(session, page, facts, pending, task_id)
        except _Refused as refusal:
            logger.info("checkout_refused", rule=refusal.rule, user_id=user_id)
            return _refusal(refusal.rule, refusal.message)
        except _Failed as failure:
            return _error(failure.message, **failure.extra)
        except Exception as exc:
            _log_failure("checkout_run_failed", exc)
            return _error("browser.checkout failed before anything was paid.")

    @staticmethod
    def _same_page(pending: _Pending, card: Mapping[str, Any], facts: CheckoutFacts) -> None:
        """The page the owner approved is the page on screen: same origin,
        same URL, same interactive outline, same total."""
        before = pending.facts
        submit_to = facts.submit_target.action if facts.submit_target is not None else ""
        same = (
            facts.origin == card.get("origin") == before.origin
            and facts.outline_digest == card.get("outline") == before.outline_digest
            and facts.url == before.url
            and facts.total == before.total
            and facts.totals == before.totals
            and facts.submit_target == before.submit_target
            and submit_to == card.get("submit_to", "")
        )
        if not same:
            raise _Refused("screen_changed", _SCREEN_CHANGED)

    async def _pay(
        self,
        session: BrowserSession,
        page: Any,
        facts: CheckoutFacts,
        pending: _Pending,
        task_id: str,
    ) -> dict[str, Any]:
        """Decrypt, fill, submit, read the confirmation. Every card value
        goes on the session's redaction list before it is typed, so a page
        that echoes it is redacted for the rest of the task; every way out
        that leaves the form on screen clears the card fields first."""
        user_id = session.user_id
        assert facts.card_fields is not None and facts.submit_ref is not None
        fields = facts.card_fields
        filled = False
        blocked: list[dict[str, str]] = []  # what the guard stopped while the order was sent
        try:
            secret = await self._vault.open_card(user_id, purpose=f"checkout {facts.host}")
        except Exception as exc:
            _log_failure("checkout_vault_open_failed", exc)
            await self._refused(user_id, task_id, facts, pending, "vault_open_failed")
            return _error(
                "The stored card could not be opened, so nothing was paid. The owner can check "
                "Settings → Payment card."
            )
        try:
            try:
                self._remember(session, _card_secrets(secret))
                await self._fill(page, fields, secret)
                filled = True
                self._remember(session, await self._typed_values(page, fields))
                self._check_cancel(user_id)
                blocked = await self._submit(session, page, facts)
            finally:
                wipe = getattr(secret, "wipe", None)
                if callable(wipe):
                    wipe()
                del secret
        except _Refused as refusal:
            left = await self._clear_card(page, fields)
            await self._refused(user_id, task_id, facts, pending, refusal.rule)
            return _refusal(refusal.rule, refusal.message + (_CARD_LEFT if left else "")) | (
                {"filled": True} if filled else {}
            )
        except Exception as exc:
            # The card is in play: the type of the failure is logged, never
            # its text (Playwright quotes the value a fill was given). A
            # fill that failed half-way left some of the card behind, so
            # the clear runs whether or not the fill completed.
            _log_failure("checkout_pay_failed", exc, detail=False, filled=filled)
            left = await self._clear_card(page, fields)
            await self._refused(user_id, task_id, facts, pending, "fill_failed" if not filled else "submit_failed")
            if filled:
                return _error(
                    "The order button did not work after the card was entered, so the purchase "
                    "may or may not have gone through. Ask the person to check the site."
                    + (_CARD_LEFT if left else ""),
                    filled=True,
                )
            return _error(
                "Could not enter the card on this page, so nothing was paid. Re-read the page and "
                "try the checkout again." + (_CARD_LEFT if left else "")
            )
        return await self._after_submit(session, page, facts, pending, task_id, blocked)

    async def _after_submit(
        self,
        session: BrowserSession,
        page: Any,
        facts: CheckoutFacts,
        pending: _Pending,
        task_id: str,
        blocked: list[dict[str, str]],
    ) -> dict[str, Any]:
        self._forget_page(session.user_id)
        assert facts.card_fields is not None
        # Whatever page is on screen now, a card form still on it is
        # emptied before anything is read or photographed.
        left = await self._clear_card(page, facts.card_fields)
        challenge = await self._handoff.detect_challenge(page)
        if challenge is not None:
            # The person finishes the code in Crawler's window: their
            # submit, and the bank's return to the shop's payment
            # address, must pass the guard until the agent acts again.
            _shared.hand_over(self._guard, session, page, checkout=True)
            await self._event(session.user_id, task_id, facts, pending, "purchase_pending_human", challenge.kind)
            payload: dict[str, Any] = {
                "kind": challenge.kind,
                "detail": challenge.detail + (_CARD_LEFT if left else ""),
                "url": self._where(session, page),
            }
            image = await self._screenshot(page, facts.card_fields)
            if image is not None:
                payload["user_image"] = image
            return {"ok": False, "needs_human": payload, "mode": session.mode, "filled": True}
        try:
            text = await page.locator("body").inner_text(timeout=REF_TIMEOUT_MS)
        except Exception as exc:  # noqa: BLE001 - a page mid-navigation has no text yet
            _log_failure("checkout_confirmation_read_failed", exc, detail=False)
            text = ""
        text = self._redact(session, " ".join(str(text).split()))
        image = await self._screenshot(page, facts.card_fields)
        where = self._where(session, page)
        stopped = self._blocked_submit(page, blocked)
        if stopped is not None:
            reason, message = stopped
            await self._refused(session.user_id, task_id, facts, pending, reason)
            return _error(message + (_CARD_LEFT if left else ""), filled=True)
        declined = _DECLINED_RE.search(text)
        confirmation = _CONFIRMATION_RE.search(text)
        if declined is not None and (confirmation is None or declined.start() < confirmation.start()):
            await self._refused(session.user_id, task_id, facts, pending, "declined")
            return _error(
                "The site did not accept the payment: " + _window(text, declined.start(), 200)
                + (_CARD_LEFT if left else ""),
                filled=True,
                user_image=image,
            )
        if confirmation is None:
            await self._refused(session.user_id, task_id, facts, pending, "no_confirmation")
            return _error(
                "The order was sent but no confirmation was found on the page that followed, so "
                "the purchase may or may not have gone through. Ask the person to check the site. "
                + (f"The page says: {text[:300]}" if text else "")
                + (_CARD_LEFT if left else ""),
                filled=True,
                user_image=image,
            )
        summary_text = _window(text, confirmation.start(), _CONFIRMATION_CHARS)
        await self._event(session.user_id, task_id, facts, pending, "purchase_completed", None)
        session.task.actions += 1
        summary = f"[step {session.task.actions}] checkout → {snap.host_path(where)}"
        session.task.summaries.append(summary)
        logger.info(
            "checkout_completed", host=facts.host, amount_usd=fmt_usd(pending.charge), user_id=session.user_id
        )
        return {
            "ok": True,
            "merchant": facts.host,
            "amount": fmt_usd(pending.charge),
            "currency": "USD",
            "confirmation_text_summary": summary_text,
            "user_image": image,
            "summary": summary,
            "mode": session.mode,
        }

    # -- helpers ------------------------------------------------------------------

    async def _session(self, user_id: str, task_id: str) -> BrowserSession:
        try:
            return await self._sessions.get(user_id, mode=mode_for(user_id), task_id=task_id)
        except Exception as exc:  # launch errors quote paths; keep them in the log
            _log_failure("checkout_session_failed", exc)
            raise _Failed(
                "Could not start the browser. The owner can check Settings → Permissions → "
                "Control a browser."
            )

    async def _ensure_guard(self, session: BrowserSession) -> None:
        """The egress guard is idempotent per context; installing it here
        means a checkout never runs on a context the read toolkit has not
        seen yet."""
        try:
            await self._guard.install_egress_guard(session.context, account_mode=session.mode == "account")
        except Exception as exc:  # fail closed: never act on an unguarded context
            _log_failure("checkout_guard_failed", exc)
            raise _Failed("The browser's network guard could not be set up, so nothing was done.")

    async def _no_challenge(self, session: BrowserSession, page: Any) -> None:
        """A page asking a person for something (a sign-in, a code) is
        theirs until the agent's next action: the refusal tells the model
        to ask them, and the guard lets their own submit through."""
        challenge = await self._handoff.detect_challenge(page)
        if challenge is not None:
            _shared.hand_over(self._guard, session, page)
            raise _Refused(
                "needs_human",
                f"The page is asking a person to do something first ({challenge.detail}). "
                "Ask the person to take over in the browser, then check out again.",
            )

    @staticmethod
    def _where(session: BrowserSession, page: Any) -> str:
        return snap.strip_url(str(page.url), session.mode == "account")

    @staticmethod
    def _redact(session: BrowserSession, content: str) -> str:
        """Page text with every typed secret replaced, the way the outline
        does it (a card number in any grouping, a code as a whole run)."""
        return snap.redact(content, session.typed_secrets, "•••")

    @staticmethod
    def _remember(session: BrowserSession, values: list[str]) -> None:
        for value in values:
            if value and value not in session.typed_secrets:
                session.typed_secrets.append(value)

    def _forget_page(self, user_id: str) -> None:
        """The act toolkit's page memory no longer describes the page on
        screen; dropping it makes the next act ask for a fresh read."""
        try:
            self._memory.forget(user_id)
        except Exception as exc:  # noqa: BLE001 - the act toolkit's own checks still hold
            _log_failure("checkout_memory_forget_failed", exc)

    async def _screenshot(self, page: Any, card_fields: Optional[CardFields]) -> Optional[str]:
        """Masked JPEG data URL of the viewport, for the person only
        (``_shared.jpeg``: every frame's secret fields by the shared
        classifier, plus the card fields by ref while those still
        resolve, so a site that names them oddly is covered too)."""
        refs = card_fields.refs if card_fields is not None else ()
        try:
            return await _shared.jpeg(page, None, mask_refs=refs)
        except Exception as exc:  # noqa: BLE001 - a card without a picture still works
            _log_failure("checkout_screenshot_failed", exc, detail=False)
            return None

    async def _fill(self, page: Any, fields: CardFields, secret: Any) -> None:
        """Type the card into the detected fields by ref, frame-aware
        (``aria-ref`` resolves ``fNeN`` inside frames). A ``<select>`` for
        the month or year is chosen, not typed."""
        month = int(getattr(secret, "exp_month", 0) or 0)
        year = int(getattr(secret, "exp_year", 0) or 0)
        yy = f"{year % 100:02d}"
        await self._enter(page, fields.number_ref, [str(secret.number)])
        if fields.name_ref and getattr(secret, "name", ""):
            await self._enter(page, fields.name_ref, [str(secret.name)])
        if fields.exp_ref:
            await self._enter(page, fields.exp_ref, [f"{month:02d}/{yy}", f"{year:04d}-{month:02d}"])
        if fields.exp_month_ref:
            await self._enter(page, fields.exp_month_ref, [f"{month:02d}", str(month)])
        if fields.exp_year_ref:
            await self._enter(page, fields.exp_year_ref, [f"{year:04d}", yy])
        await self._enter(page, fields.cvc_ref, [str(secret.cvc)])

    @staticmethod
    async def _enter(page: Any, ref: str, values: list[str]) -> None:
        """Put *values[0]* into the field at *ref*: chosen for a select (any
        of *values* that is an option), typed otherwise (``type=month``
        inputs take the second, ISO form)."""
        locator = page.locator(f"aria-ref={ref}")
        kind = await locator.evaluate(
            "el => el.tagName.toLowerCase() === 'select' ? 'select' : (el.type || '').toLowerCase()",
            timeout=REF_TIMEOUT_MS,
        )
        if kind == "select":
            for value in values:
                try:
                    await locator.select_option(value, timeout=REF_TIMEOUT_MS)
                    return
                except Exception:  # noqa: BLE001 - not an option; try the next form
                    continue
            raise _Failed("A card field on this page could not be filled.")
        value = values[1] if kind == "month" and len(values) > 1 else values[0]
        await locator.fill(value, timeout=REF_TIMEOUT_MS)

    @staticmethod
    async def _typed_values(page: Any, fields: CardFields) -> list[str]:
        """What the number, security-code and expiry fields hold after the
        fill, as the page shows them (a site's input mask groups the
        digits, or writes the expiry its own way): each goes on the
        redaction list too. Never the name field (a person's name is not
        a secret: ``_card_secrets``), never a ``<select>`` (a year chosen
        from a dropdown would blank every "2028" the page shows) and
        nothing shorter than ``_MIN_TYPED_CHARS`` (a bare month would
        blank every "12"); the digit and expiry forms already remembered
        cover those. Best effort: a field that will not answer is covered
        the same way."""
        values: list[str] = []
        for ref in (fields.number_ref, fields.cvc_ref, fields.exp_ref, fields.exp_month_ref, fields.exp_year_ref):
            if not ref:
                continue
            try:
                value = await page.locator(f"aria-ref={ref}").evaluate(
                    "el => el.tagName.toLowerCase() === 'select' ? '' : String(el.value || '')",
                    timeout=REF_TIMEOUT_MS,
                )
            except Exception:  # noqa: BLE001 - a field that changed shape
                continue
            if isinstance(value, str) and len(value.strip()) >= _MIN_TYPED_CHARS:
                values.append(value)
        return values

    @staticmethod
    async def _clear_card(page: Any, fields: CardFields) -> int:
        """Empty every card field still on screen and say how many were
        left holding a value (0 when the form is empty or gone).

        By ref first (``fill("")`` / a deselect, frame-aware, only for
        refs that still resolve: a page that navigated has none), then a
        sweep of every frame for any card field the classifier finds
        (a page that re-rendered its form has new elements under the old
        refs), which also counts what is left."""
        for ref in fields.refs:
            locator = page.locator(f"aria-ref={ref}")
            try:
                # A ref whose frame navigated away is reported as an
                # invalid frame (the main frame's prefix changes after a
                # navigation): gone with the page, like a count of zero.
                gone = await locator.count() == 0
            except Exception:  # noqa: BLE001
                gone = True
            if gone:
                continue
            try:
                kind = await locator.evaluate(
                    "el => el.tagName.toLowerCase() === 'select' ? 'select' : 'field'",
                    timeout=REF_TIMEOUT_MS,
                )
                if kind == "select":
                    await locator.select_option([], timeout=REF_TIMEOUT_MS)
                else:
                    await locator.fill("", timeout=REF_TIMEOUT_MS)
            except Exception as exc:  # noqa: BLE001 - the sweep below still runs
                _log_failure("checkout_card_clear_failed", exc, detail=False)
        left = 0
        for frame in page.frames:
            try:
                left += int(await _shared.frame_evaluate(frame, markers.CLEAR_CARD_FIELDS_JS) or 0)
            except Exception as exc:  # noqa: BLE001 - a frame mid-navigation or without a document holds no form
                _log_failure("checkout_card_sweep_failed", exc, detail=False)
        if left:
            logger.warning("checkout_card_left_in_form", fields=left)
        return left

    async def _submit(self, session: BrowserSession, page: Any, facts: CheckoutFacts) -> list[dict[str, str]]:
        """Click the order button with the egress guard's write gate open
        for exactly that navigation (a POST to the origin the order form
        was bound to, from any frame of this page and no other tab, and no
        other navigation), then let
        the next page land. Returns what the guard stopped meanwhile."""
        assert facts.submit_ref is not None
        target = facts.submit_target
        bound = _origin_of(target.action) if target is not None and target.action else facts.origin
        state = self._guard.egress_state(session.context)
        before = len(getattr(state, "blocked", None) or [])
        if state is not None:
            state.write_allowed = True
            state.write_origin = bound
            state.write_page = page  # the approved page: no other tab sends
        try:
            await page.locator(f"aria-ref={facts.submit_ref}").click(timeout=REF_TIMEOUT_MS)
            await self._guard.settle_blocked_navigation(page, timeout_ms=300)
            for state_name, timeout in (("domcontentloaded", 5_000), ("networkidle", 3_000)):
                try:
                    await page.wait_for_load_state(state_name, timeout=timeout)
                except Exception:  # noqa: BLE001 - a page that never settles is read as it is
                    pass
        finally:
            if state is not None:
                state.write_allowed = False
                state.write_origin = None
                state.write_page = None
        return list((getattr(state, "blocked", None) or [])[before:])

    @staticmethod
    def _blocked_submit(page: Any, blocked: list[dict[str, str]]) -> Optional[tuple[str, str]]:
        """(reason, sentence) when the order did not get through as sent:
        the guard stopped something while it went out (the POST itself,
        or, with ``via``, where the site's answer led once the card had
        reached it), or the page after it never loaded and nothing was
        stopped. None when the next page is there to be read."""
        if blocked:
            last = blocked[-1]
            url, reason = last.get("url", ""), last.get("reason", "blocked by the network policy")
            if last.get("via"):
                return "submit_blocked", (
                    f"The order was sent, but the site's answer led to {url}, which Crawler stopped "
                    f"({reason}). The purchase may or may not have gone through. Ask the person to "
                    "check the site."
                )
            return "submit_blocked", f"The order could not be sent: {url}: {reason}"
        if str(page.url).startswith("chrome-error://"):
            return "no_confirmation", (
                "The order was sent but the page after it could not be loaded, so the purchase may "
                "or may not have gone through. Ask the person to check the site."
            )
        return None

    async def _refused(
        self, user_id: str, task_id: str, facts: CheckoutFacts, pending: _Pending, reason: str
    ) -> None:
        await self._event(user_id, task_id, facts, pending, "purchase_refused", reason)

    async def _event(
        self,
        user_id: str,
        task_id: str,
        facts: CheckoutFacts,
        pending: _Pending,
        event: str,
        reason: Optional[str],
    ) -> None:
        """The outcome row of an approved checkout, under the checkout id
        its approval row carries. It is written after the card was in
        play, so a failed write cannot stop anything: it is logged as an
        error (by type only), and the approval row already on the record
        keeps counting the purchase against the daily cap, so a lost
        outcome can only over-count, never read as nothing spent."""
        try:
            await self._ledger.record(
                user_id,
                event,
                merchant=facts.host,
                amount_usd=pending.charge,
                currency="USD",
                items=len(facts.items),
                task_id=task_id,
                reason=reason,
                checkout_id=pending.checkout_id,
            )
        except Exception as exc:
            logger.error(
                "checkout_audit_failed",
                error_type=type(exc).__name__,
                purchase_event=event,
                checkout_id=pending.checkout_id,
            )


def _window(text: str, start: int, chars: int) -> str:
    """Up to *chars* characters of *text* around *start*: a short lead-in
    so the sentence the match sits in is readable, the rest after."""
    lead = min(_CONFIRMATION_LEAD, start)
    return text[start - lead : start - lead + chars].strip()
