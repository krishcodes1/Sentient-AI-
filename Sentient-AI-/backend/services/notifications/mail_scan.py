"""The mail scam scan's sweeper and the methods its routes call (security
S2): ``MailScanService`` checks each connected Gmail and Outlook inbox for
new mail, flags what looks like a scam, reviews it once with the AI and
alerts the person on their own channels.

Why it exists: new mail must be checked without anyone asking, on the same
gated SweepLoop every background job uses (services/notifications/
sweeper.py), reading mail only through the executor (scopes, rate limits,
the call checks' backstop and the network policy apply) and making cards
only through ``AgentRuntime.park_card``. The Security page's Mail alerts tab
reads and changes the same rows through the methods at the end.

Phase 0, reconcile (at most every 5 minutes, while the switch is on): one
``mail_scan_cursors`` row per active Gmail or Outlook connector row of an
active user that may read mail; a row stopped by errors starts again when
its connector was reconnected since.

Phase A, detect (only while "mail_scam_scan" is on, re-read before every
account): up to 20 due cursors are claimed with a conditional UPDATE of
``next_check_at``. The first check of an account (or one left for a day, or
one the provider reset) only records where the inbox is, so there is never
a backlog flood. Otherwise ``list_new_message_ids`` gives new ids; they wait
in ``pending_ids`` (newest 200 kept, review SEC-F7) and the new cursor is
saved with them at once. Up to a third of the row's rate limit (at most 10)
of them are read with ``get_message_security``; a message the provider says
is gone is dropped (FEA-SF3), one that fails twice is skipped (SEC-F7), mail
older than a day is skipped. Each read message gets S4's link verdicts (at
most 5 URLs, one per host, query-stripped, ``purpose="mail"``) and
``mail_checks.evaluate``; it leaves only a 16-hex hash in the ``seen`` ring
unless it is flagged, when one finding row is written (the unique index is
the "never twice" guard). Failures back off; the fifth in a row stops the
account with one message.

Phase B, review and alert (background tasks, at most 2 at a time): pending
findings are claimed under a 5-minute lease. S10 fingerprints up to two
risky attachments. One AI review runs under the person's own daily cap
(counted from ``reviewed_at``, never the shared unattended budget), on a
local Ollama when configured or the person's own provider with contact
details pseudonymised. The review can only make a finding stricter
(``review.combine``); a weak finding from an authenticated sender goes quiet
only after a "no signs" review (``mail_checks.goes_quiet``, SEC-M1); with no
review, a finding whose signs are all noisy is listed on the tab and summed
up once a day (FEA-SF2). More than 10 pushed suspicious alerts in an hour
become one summary line; a likely scam is always pushed (SEC-F7). The alert
goes out first, then (likely scams only) the Move-to-Spam/Junk card.

Housekeeping (hourly, even while the switch is off): findings older than
``keep_alerts_days`` are deleted, review excerpts older than a day are
cleared, and findings that waited over a day without an alert expire.

Audit rows hold ids, counts and codes only; logs hold ids and exception
types (an exception's text can quote a URL with a token in it).

Connects to: main.py (built in wire_services, started in the lifespan),
api/routes/security_mail.py, services/mail_scan (texts, review, cards),
services/security/mail_facts.py and mail_checks.py, S4's LinkChecker
(``links``), S10's FileReputationService (``files``).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence

import structlog
from sqlalchemy import delete, func, null, select, update
from sqlalchemy.exc import IntegrityError

from services.mail_scan import AUDIT_CONNECTOR, CAPABILITY, PROVIDER_OF, READ_SCOPE
from services.mail_scan import actions as cards
from services.mail_scan import messages as text
from services.mail_scan import review as ai
from services.notifications.sweeper import Gate, SweepLoop, backoff_minutes, gate_open
from services.security import mail_checks as checks
from services.security import mail_facts
from services.triggers import facts as shape

logger = structlog.get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 60
CHECK_INTERVAL_MINUTES = 5
BACKLOG_INTERVAL_MINUTES = 1  # next check while pending_ids remain
MAX_CHECKS_PER_SWEEP = 20
CHECK_DEADLINE_SECONDS = 60.0
MESSAGES_PER_CHECK = 10  # also never more than a third of the row's rate_limit_per_minute
PENDING_MAX = 200
SEEN_RING = 500
STALE_AFTER = timedelta(hours=24)  # a cursor not checked for a day starts over (no old-mail flood)
MAX_MESSAGE_AGE = timedelta(hours=24)
LINK_DEADLINE_SECONDS = 10.0
FILE_DEADLINE_SECONDS = 30.0
MAX_CONCURRENT_REVIEWS = 2
REVIEW_LEASE_MINUTES = 5
REVIEW_ATTEMPTS = 2
MAX_ALERTS_PER_HOUR = 10
ERROR_LIMIT = 5
MAX_BACKOFF_MINUTES = 24 * 60
RECONCILE_EVERY = timedelta(minutes=5)
HOUSEKEEPING_EVERY = timedelta(hours=1)
# The S4 and S10 protocols are theirs (scaffold A8, A9): S2 calls
#   await links.check(urls, purpose="mail", network=True, timeout_s=LINK_DEADLINE_SECONDS)
# and S10's FileReputationService.check_mail_attachment(user_id, *, hash_tool, message_id,
#   attachment_id, priority="automatic", wait_s=FILE_DEADLINE_SECONDS, alert="caller").
# purpose "mail" is the background share of S4's limiter (scaffold A36).
SUMMARY_HOUR_LOCAL = 18  # the daily summary of unreviewed weak findings
FAILED_READ_TRIES = 2  # an id whose read fails twice (not a 404) is skipped
# One message read may take this long before it counts as a failed read.
MESSAGE_READ_SECONDS = 25.0
# Risky attachments of one finding sent to S10 (VirusTotal: 4/min, 500/day).
MAX_FILE_CHECKS = 2
REVIEW_EXCERPT_TTL = timedelta(hours=24)
PENDING_EXPIRY = timedelta(hours=24)
DEFAULT_REVIEWS_PER_DAY = 20
DEFAULT_KEEP_DAYS = 30
_STOP_WAIT_S = 10.0
_LIST_IDS_MAX = 300
_CURSOR_CHARS = 8000

SWEEPER_ENDPOINT = "mail_scan_sweeper"
ROUTE_DISMISS = "/api/security/mail/alerts/{id}/dismiss"
ROUTE_ACTIONS = "/api/security/mail/alerts/{id}/actions"
ROUTE_ACCOUNT = "/api/security/mail/accounts/{id}"

# alert_note values the tab turns into sentences (mailAlertFormat.ts).
NOT_DELIVERED = "not delivered"
HELD_NOTE = "held: too many alerts this hour"
LISTED_NOTE = "listed: weak signs and no AI review"
CARD_NOT_MADE = "card not made"
EXPIRED_NOTE = "expired"

FLOOD_NOTE = "Some messages arrived faster than they could be checked and were skipped."
OFFLINE = "The account this check reads was turned off or removed."
TIMEOUT_REASON = "{app} did not answer in time."
NOT_FOUND = "Not found."
NO_CARD_WAITING = "A card for this is already waiting."
STARTING = "The server is still starting. Try again shortly."
CARD_FAILED = "The card could not be made. Try again shortly."
ACCOUNT_GONE = "The account this alert came from was turned off or removed."
DISMISSED_NO_ACTION = "This alert was marked as not a scam."

_APP = {"google_workspace": "Gmail", "microsoft": "Outlook"}
_SEEN_RE = re.compile(r"[0-9a-f]{16}")
_DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z0-9-]{2,63}")
_OPEN_STATUSES = ("alerted",)
_ALL_STATUSES = ("alerted", "quiet", "dismissed", "expired")
_ACTIONABLE = ("alerted", "quiet", "expired")

# main.fan_out_send(...): (user_id, text) -> delivered on at least one channel.
Send = Callable[[str, str], Awaitable[bool]]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    moment = _utc(value)
    return moment.isoformat() if moment is not None else None


def _moment(value: Any) -> Optional[datetime]:
    """A stored card's expiry (a datetime, or the ISO text StoredAction
    carries) as an aware datetime, or None."""
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, str) and len(value) <= 64:
        try:
            return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def seen_key(connector_id: Any, message_id: str) -> str:
    """The 16-hex hash a checked message leaves in its cursor's ``seen``
    ring: the only trace of mail that was not flagged."""
    return hashlib.sha256(f"mail:{connector_id}:{message_id}".encode("utf-8")).hexdigest()[:16]


def external_key(message_id: str) -> str:
    """sha256 hex of "mail:<provider message id>": the finding's dedupe key."""
    return hashlib.sha256(f"mail:{message_id}".encode("utf-8")).hexdigest()


def _pending_of(value: Any) -> list[dict[str, Any]]:
    """A stored ``pending_ids`` list read back: valid ids once each, tries
    as a small whole number, the newest PENDING_MAX kept."""
    entries: list[dict[str, Any]] = []
    known: set[str] = set()
    for item in value if isinstance(value, list) else []:
        ident: Any = item.get("id") if isinstance(item, Mapping) else item
        tries: Any = item.get("tries") if isinstance(item, Mapping) else 0
        if not cards.valid_message_ref(ident) or ident in known:
            continue
        known.add(ident)
        ok = isinstance(tries, int) and not isinstance(tries, bool) and tries >= 0
        entries.append({"id": ident, "tries": min(tries, 99) if ok else 0})
    return entries[-PENDING_MAX:]


def _seen_of(value: Any) -> list[str]:
    keys = [k for k in (value if isinstance(value, list) else []) if isinstance(k, str) and _SEEN_RE.fullmatch(k)]
    return keys[-SEEN_RING:]


def _account_domain(value: Any) -> Optional[str]:
    """The mailbox's own domain as the provider said it, only when it is a
    plain lower-case domain (consumer domains never reach here: the Gmail
    action answers null for them)."""
    if not isinstance(value, str) or len(value) > 253:
        return None
    domain = value.strip().lower().rstrip(".")
    return domain if _DOMAIN_RE.fullmatch(domain) else None


def _app_error(result: Any, app: str) -> tuple[str, bool]:
    """(a fixed sentence for a failed read, whether the account itself is
    the problem): sources._app_error's set with "this trigger" replaced by
    "the mail check", plus the call checks' backstop (S2.md 4.5). Never the
    connector's or the vendor's text. A failure that is not the account's
    may be the one message's (counted against it, SEC-F7)."""
    data = result if isinstance(result, Mapping) else {}
    error = str(data.get("error") or "")
    if data.get("call_check") or data.get("requires_approval"):
        return f"A rule you set needs your OK for this read, so the mail check could not read {app}.", True
    if data.get("capability"):
        return f"A setting the mail check needs is turned off, so {app} could not be read.", True
    if error.startswith("No active"):
        return f"The {app} account the mail check reads was turned off or removed.", True
    if "Scope '" in error or "granted" in error:
        return f"The {app} account no longer allows what the mail check reads.", True
    lowered = error.lower()
    if "reconnect" in lowered or "sign-in" in lowered or "HTTP 401" in error:
        return f"The {app} sign-in needs to be renewed in Connectors.", True
    if "rate limit" in lowered:
        return f"{app} asked Crawler to slow down.", True
    return f"Crawler could not read {app}.", False


class _ReadFailed(Exception):
    """A connector read that did not answer; the message is the sweeper's
    own sentence."""

    def __init__(self, sentence: str, account_level: bool) -> None:
        super().__init__(sentence)
        self.sentence = sentence
        self.account_level = account_level


@dataclass(frozen=True)
class _Claim:
    """What a check needs from its cursor row, read when it was claimed."""

    id: uuid.UUID
    user_id: uuid.UUID
    connector_id: uuid.UUID
    provider: str
    cursor: Optional[str]
    pending: list[dict[str, Any]]
    seen: list[str]
    account_domain: Optional[str]
    baseline_at: Optional[datetime]
    last_checked_at: Optional[datetime]
    consecutive_errors: int
    checked_count: int
    flagged_count: int
    skipped_count: int


@dataclass(frozen=True)
class _Account:
    """The connector row a check reads through."""

    connector_type: str
    connector_id: str
    label: str
    rate_limit: int
    user_email: Optional[str]


@dataclass(frozen=True)
class _Job:
    """What one review needs: the finding, its user and its connector."""

    id: uuid.UUID
    user_id: uuid.UUID
    connector_id: uuid.UUID
    provider: str
    message_ref: str
    local_level: str
    score: int
    signals: list[Any]
    facts: dict[str, Any]
    review_input: dict[str, Any]
    check_notes: list[str]
    attempts: int
    reserved: bool
    user_active: bool
    llm_provider: Optional[str]
    llm_model: Optional[str]
    timezone: Optional[str]
    connector_type: Optional[str]
    display_name: str
    granted_scopes: list[str]


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _refusal(status: int, error: str) -> dict[str, Any]:
    return {"ok": False, "status": status, "error": error}


def _uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


class MailScanService:
    """Checks each connected Gmail and Outlook inbox for new mail, flags what
    looks like a scam, reviews it once with the AI and alerts the person (see
    the module docstring).

    ``executor`` is the tool executor (``execute(name, args, user_id,
    approved=False)``); ``send(user_id, text)`` reaches only that user's own
    linked Telegram and Slack chats; ``enabled`` is the "mail_scam_scan"
    switch, re-read before every check and review (a gate that fails is
    off); ``settings`` answers ``capability_settings("mail_scam_scan")``;
    ``runtime`` gives ``resolve_turn_provider``, ``untrusted_data_message``,
    ``complete_once`` and ``park_card``; ``links`` and ``files`` are S4's
    LinkChecker and S10's FileReputationService (optional, fail open with a
    note). ``approvals`` is kept for wiring; card statuses are read from the
    ``pending_actions`` rows by id. ``clock``, ``scan``, ``audit`` and the
    timings are test seams."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        executor: Any = None,  # ConnectorToolExecutor: execute(name, args, user_id, approved=False)
        send: Optional[Send] = None,  # main.fan_out_send(...)
        enabled: Optional[Gate] = None,  # capability_gate(installation, "mail_scam_scan")
        settings: Any = None,  # InstallationService: capability_settings("mail_scam_scan")
        approvals: Any = None,  # the NotifyingApprovalStore: reads only (card status)
        runtime: Any = None,  # AgentRuntime: complete_once, untrusted_data_message, park_card
        links: Optional[Any] = None,  # S4 LinkChecker (None: no link verdicts, a note)
        files: Optional[Any] = None,  # S10 FileReputationService (None: no file verdicts, a note)
        local_model: str = "",  # settings.MAIL_REVIEW_OLLAMA_MODEL
        ollama_base_url: str = "",  # settings.OLLAMA_BASE_URL
        clock: Callable[[], datetime] = _utcnow,
        scan: Optional[Callable[[str], bool]] = None,  # triggers.facts.default_scan()
        audit: bool = True,
        interval_seconds: float = SWEEP_INTERVAL_SECONDS,
        check_deadline_s: float = CHECK_DEADLINE_SECONDS,
        review_deadline_s: float = 60.0,
        max_reviews: int = MAX_CONCURRENT_REVIEWS,
    ) -> None:
        self._session_factory = session_factory
        self._executor = executor
        self._send = send
        self._enabled = enabled
        self._settings = settings
        self._approvals = approvals
        self._runtime = runtime
        self._links = links
        self._files = files
        self._local_model = local_model
        self._ollama_base_url = ollama_base_url
        self._clock = clock
        self._scan = scan
        self._audit_enabled = audit
        self._interval_seconds = interval_seconds
        self._check_deadline_s = check_deadline_s
        self._review_deadline_s = review_deadline_s
        self._max_reviews = max(1, int(max_reviews))
        self._running: set[asyncio.Task[None]] = set()
        self._last_housekeeping: Optional[datetime] = None
        self._last_reconcile: Optional[datetime] = None
        # Per user, in memory (after a restart one of each may repeat once):
        # when the last "too many alerts" line went out, and the local day
        # and time of the last daily summary.
        self._overflow_at: dict[str, datetime] = {}
        self._stopped_at: dict[str, tuple[str, datetime]] = {}
        self._summary_day: dict[str, Any] = {}
        self._summary_at: dict[str, datetime] = {}
        self._cap_lock = asyncio.Lock()
        self._action_lock = asyncio.Lock()
        self._guard: Optional[Callable[[str], bool]] = None
        # A microsecond apart: findings keep a strict order, so paging by
        # detected time never skips one.
        self._sequence = 0
        self._sweeper = SweepLoop(name="mail_scan", interval_seconds=interval_seconds, sweep=self.sweep_once)

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        await self._sweeper.start()

    async def stop(self) -> None:
        """Stop sweeping, cancel reviews in flight (bounded wait); their
        leases expire and they are retried once, then alerted without AI."""
        await self._sweeper.stop()
        running = [task for task in self._running if not task.done()]
        for task in running:
            task.cancel()
        if running:
            await asyncio.wait(running, timeout=_STOP_WAIT_S)

    async def wait_idle(self) -> None:
        """Wait for reviews in flight (tests, shutdown)."""
        while True:
            tasks = [task for task in self._running if not task.done()]
            if not tasks:
                return
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _on(self) -> bool:
        return await gate_open(self._enabled, CAPABILITY)

    def _scanner(self) -> Callable[[str], bool]:
        if self._scan is not None:
            return self._scan
        if self._guard is None:
            self._guard = shape.default_scan()
        return self._guard

    def _next_detected(self, now: datetime) -> datetime:
        self._sequence = (self._sequence + 1) % 1_000_000
        return now + timedelta(microseconds=self._sequence)

    # -- the sweep -----------------------------------------------------------

    async def sweep_once(self) -> int:
        """Housekeep (hourly), then reconcile, detect and start reviews while
        the switch is on. Returns how many accounts were checked."""
        now = self._clock()
        await self._maybe_housekeep(now)
        if not await self._on():
            return 0
        await self._maybe_reconcile(now)
        checked = await self._detect(now)
        try:
            await self._daily_summaries(self._clock())
        except Exception as exc:
            logger.warning("mail_scan_summary_failed", error_type=type(exc).__name__)
        try:
            # Last: the reviews run as background tasks after this returns.
            await self.review_pending()
        except Exception as exc:
            logger.warning("mail_scan_review_start_failed", error_type=type(exc).__name__)
        return checked

    # -- Phase 0: reconcile ----------------------------------------------------

    async def _maybe_reconcile(self, now: datetime) -> None:
        if self._last_reconcile is not None and now - self._last_reconcile < RECONCILE_EVERY:
            return
        self._last_reconcile = now
        try:
            await self.reconcile(now)
        except Exception as exc:
            logger.warning("mail_scan_reconcile_failed", error_type=type(exc).__name__)

    async def reconcile(self, now: datetime) -> int:
        """Add cursor rows for new mail accounts; reactivate reconnected ones.
        Returns how many rows were added."""
        from models.connector import ConnectorConfig, PermissionTier, connector_type_key
        from models.mail_security import MailScanCursor
        from models.user import User

        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        ConnectorConfig.id,
                        ConnectorConfig.user_id,
                        ConnectorConfig.connector_type,
                        ConnectorConfig.granted_scopes,
                        ConnectorConfig.permission_tier,
                    )
                    .join(User, User.id == ConnectorConfig.user_id)
                    .where(
                        ConnectorConfig.is_active.is_(True),
                        ConnectorConfig.connector_type.in_(list(PROVIDER_OF)),
                        User.is_active.is_(True),
                    )
                )
            ).all()
            have = set(
                (await session.execute(select(MailScanCursor.connector_id))).scalars().all()
            )
        added = 0
        for row in rows:
            kind = connector_type_key(row.connector_type)
            tier = row.permission_tier
            if row.id in have or kind not in PROVIDER_OF:
                continue
            if tier == PermissionTier.hard_blocked:
                continue
            scopes = list(row.granted_scopes or [])
            if scopes and READ_SCOPE[kind] not in scopes:
                continue
            async with self._session_factory() as session:
                session.add(
                    MailScanCursor(
                        id=uuid.uuid4(),
                        user_id=row.user_id,
                        connector_id=row.id,
                        provider=PROVIDER_OF[kind],
                        status="active",
                        next_check_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                )
                try:
                    await session.commit()
                    added += 1
                except IntegrityError:
                    # Another worker added it first (the unique connector index).
                    await session.rollback()
        await self._reactivate_reconnected(now)
        return added

    async def _reactivate_reconnected(self, now: datetime) -> None:
        """A row stopped by errors starts again once its connector changed
        after it stopped (the person reconnected it) and may read mail again.
        A token refresh also touches the connector row, so the read access
        is checked too, and the "stopped" message is not repeated for the
        same reason within a day (``_record_failure``)."""
        from models.connector import ConnectorConfig, PermissionTier, connector_type_key
        from models.mail_security import MailScanCursor

        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        MailScanCursor.id,
                        ConnectorConfig.connector_type,
                        ConnectorConfig.granted_scopes,
                        ConnectorConfig.permission_tier,
                    )
                    .join(ConnectorConfig, ConnectorConfig.id == MailScanCursor.connector_id)
                    .where(
                        MailScanCursor.status == "error",
                        ConnectorConfig.is_active.is_(True),
                        ConnectorConfig.updated_at > MailScanCursor.updated_at,
                    )
                )
            ).all()
            ids = []
            for cursor_id, kind, scopes, tier in rows:
                scope = READ_SCOPE.get(connector_type_key(kind), "")
                if tier == PermissionTier.hard_blocked or (scopes and scope not in scopes):
                    continue
                ids.append(cursor_id)
            for cursor_id in ids:
                await session.execute(
                    update(MailScanCursor)
                    .where(MailScanCursor.id == cursor_id, MailScanCursor.status == "error")
                    .values(
                        status="active",
                        consecutive_errors=0,
                        last_error=None,
                        next_check_at=now,
                        updated_at=now,
                    )
                    .execution_options(synchronize_session=False)
                )
            await session.commit()

    # -- Phase A: detect -----------------------------------------------------------

    async def _detect(self, now: datetime) -> int:
        claims = await self._claim_due(now)
        checked = 0
        for claim in claims:
            # Re-read before each account: a sweep can run for minutes, and
            # nothing is read once the owner turns the check off. A claim left
            # unchecked is retried at its next time.
            if checked and not await self._on():
                break
            try:
                await self._check(claim)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("mail_scan_check_failed", cursor_id=str(claim.id), error_type=type(exc).__name__)
            checked += 1
        return checked

    async def _claim_due(self, now: datetime) -> list[_Claim]:
        from models.mail_security import MailScanCursor
        from models.user import User

        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(MailScanCursor)
                        .join(User, User.id == MailScanCursor.user_id)
                        .where(
                            MailScanCursor.status == "active",
                            MailScanCursor.next_check_at <= now,
                            User.is_active.is_(True),
                        )
                        .order_by(MailScanCursor.next_check_at)
                        .limit(MAX_CHECKS_PER_SWEEP)
                    )
                )
                .scalars()
                .all()
            )
            claims: list[_Claim] = []
            for row in rows:
                # Whoever moves the row past "due" owns this check; the new
                # time is also the retry after a crash.
                result = await session.execute(
                    update(MailScanCursor)
                    .where(
                        MailScanCursor.id == row.id,
                        MailScanCursor.status == "active",
                        MailScanCursor.next_check_at <= now,
                    )
                    .values(next_check_at=now + timedelta(minutes=CHECK_INTERVAL_MINUTES))
                    .execution_options(synchronize_session=False)
                )
                if getattr(result, "rowcount", 0) != 1:
                    continue
                claims.append(
                    _Claim(
                        id=row.id,
                        user_id=row.user_id,
                        connector_id=row.connector_id,
                        provider=row.provider,
                        cursor=row.cursor if isinstance(row.cursor, str) and row.cursor else None,
                        pending=_pending_of(row.pending_ids),
                        seen=_seen_of(row.seen),
                        account_domain=_account_domain(row.account_domain),
                        baseline_at=_utc(row.baseline_at),
                        last_checked_at=_utc(row.last_checked_at),
                        consecutive_errors=int(row.consecutive_errors or 0),
                        checked_count=int(row.checked_count or 0),
                        flagged_count=int(row.flagged_count or 0),
                        skipped_count=int(row.skipped_count or 0),
                    )
                )
            await session.commit()
        return claims

    async def _account(self, claim: _Claim) -> Optional[_Account]:
        """The pinned connector row while it is the cursor's user's, active,
        a mail type and not hard-blocked; None otherwise."""
        from models.connector import ConnectorConfig, PermissionTier, connector_type_key
        from models.user import User

        async with self._session_factory() as session:
            row = await session.get(ConnectorConfig, claim.connector_id)
            if row is None or row.user_id != claim.user_id or not row.is_active:
                return None
            if row.permission_tier == PermissionTier.hard_blocked:
                return None
            kind = connector_type_key(row.connector_type)
            if kind not in PROVIDER_OF:
                return None
            email = (await session.execute(select(User.email).where(User.id == claim.user_id))).scalar_one_or_none()
            rate = row.rate_limit_per_minute
            return _Account(
                connector_type=kind,
                connector_id=str(row.id),
                label=text.account_label(row.display_name, PROVIDER_OF[kind]),
                rate_limit=rate if isinstance(rate, int) and rate > 0 else 30,
                user_email=email,
            )

    def _call(self, account: _Account, user_id: uuid.UUID) -> Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]:
        """One executor call on the pinned row, as the row's user, never
        approved; a failed result raises _ReadFailed with a fixed sentence."""
        from services.triggers.sources import tool_name

        app = _APP.get(account.connector_type, "the mailbox")

        async def call(action: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if self._executor is None:
                raise _ReadFailed(f"Crawler could not read {app}.", True)
            result = await self._executor.execute(
                tool_name(account.connector_type, account.connector_id, action),
                dict(arguments),
                str(user_id),
                approved=False,
            )
            if not isinstance(result, Mapping) or result.get("ok") is not True:
                sentence, account_level = _app_error(result, app)
                raise _ReadFailed(sentence, account_level)
            data = result.get("result")
            return dict(data) if isinstance(data, Mapping) else {}

        return call

    async def _check(self, claim: _Claim) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._check_deadline_s
        now = self._clock()
        try:
            account = await self._account(claim)
        except Exception as exc:
            logger.warning("mail_scan_check_lookup_failed", cursor_id=str(claim.id), error_type=type(exc).__name__)
            return
        if account is None:
            await self._record_failure(claim, OFFLINE, text.provider_name(claim.provider))
            return
        app = _APP[account.connector_type]
        call = self._call(account, claim.user_id)
        stale = claim.cursor is not None and (
            claim.last_checked_at is None or now - claim.last_checked_at > STALE_AFTER
        )
        cursor = "" if stale or claim.cursor is None else claim.cursor
        try:
            listing = await asyncio.wait_for(
                call("list_new_message_ids", {"cursor": cursor}), max(0.1, deadline - loop.time())
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            await self._record_failure(claim, TIMEOUT_REASON.format(app=app), account.label)
            return
        except _ReadFailed as exc:
            await self._record_failure(claim, exc.sentence, account.label)
            return
        except Exception as exc:
            await self._record_failure(claim, f"The check failed ({type(exc).__name__}).", account.label)
            return
        new_cursor = listing.get("cursor")
        if not isinstance(new_cursor, str) or not new_cursor or len(new_cursor) > _CURSOR_CHARS:
            await self._record_failure(claim, f"Crawler could not read {app}.", account.label)
            return
        if listing.get("baseline") is True:
            reason = "stale" if stale else "provider" if claim.cursor is not None else ""
            await self._record_baseline(claim, account, new_cursor, listing, now, reason)
            return
        await self._check_messages(claim, account, call, new_cursor, listing, now, deadline)

    async def _record_baseline(
        self,
        claim: _Claim,
        account: _Account,
        cursor: str,
        listing: Mapping[str, Any],
        now: datetime,
        reason: str,
    ) -> None:
        """The first check of an account, or a fresh start: only where the
        inbox is now is recorded; nothing is checked."""
        from models.mail_security import MailScanCursor

        values: dict[str, Any] = {
            "cursor": cursor,
            "pending_ids": [],
            "last_checked_at": now,
            "next_check_at": now + timedelta(minutes=CHECK_INTERVAL_MINUTES),
            "consecutive_errors": 0,
            "last_error": None,
            "updated_at": now,
        }
        domain = _account_domain(listing.get("account_domain"))
        if domain is not None or "account_domain" in listing:
            values["account_domain"] = domain
        if claim.baseline_at is None:
            values["baseline_at"] = now
        if reason:
            day = now.strftime("%b %d").replace(" 0", " ")
            values["note"] = (
                f"Restarted on {day}: mail that arrived while checks were off was not checked."
                if reason == "stale"
                else f"Restarted on {day}: the mail provider asked for a fresh start, so earlier mail was not checked."
            )
            if claim.pending:
                values["skipped_count"] = claim.skipped_count + len(claim.pending)
        async with self._session_factory() as session:
            result = await session.execute(
                update(MailScanCursor)
                .where(MailScanCursor.id == claim.id, MailScanCursor.status == "active")
                .values(**values)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        if reason and getattr(result, "rowcount", 0) == 1:
            await self._audit(
                claim.user_id,
                "mail_scan_reset",
                {"cursor_id": str(claim.id), "connector_type": account.connector_type, "reason": reason},
            )
        logger.info("mail_scan_baseline", cursor_id=str(claim.id), reset=bool(reason))

    async def _check_messages(
        self,
        claim: _Claim,
        account: _Account,
        call: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
        cursor: str,
        listing: Mapping[str, Any],
        now: datetime,
        deadline: float,
    ) -> None:
        from models.mail_security import MailScanCursor

        loop = asyncio.get_running_loop()
        app = _APP[account.connector_type]
        pending = [dict(entry) for entry in claim.pending]
        seen = list(claim.seen)
        skipped = claim.skipped_count
        note: Optional[str] = None
        known_ids = {entry["id"] for entry in pending}
        seen_set = set(seen)
        listed = listing.get("message_ids")
        for ident in (listed if isinstance(listed, list) else [])[:_LIST_IDS_MAX]:
            if not cards.valid_message_ref(ident):
                skipped += 1
                continue
            if ident in known_ids or seen_key(claim.connector_id, ident) in seen_set:
                continue
            known_ids.add(ident)
            pending.append({"id": ident, "tries": 0})
        overflow = len(pending) - PENDING_MAX
        if overflow > 0:
            # Keep the newest (review SEC-F7): a flood of harmless mail must
            # not push the real phish out; the oldest are counted as skipped.
            pending = pending[overflow:]
            skipped += overflow
            note = FLOOD_NOTE
        # The cursor and the queue are saved together before any message is
        # read: a crash later re-lists nothing and loses nothing.
        saved: dict[str, Any] = {"cursor": cursor, "pending_ids": pending, "skipped_count": skipped, "updated_at": now}
        if note:
            saved["note"] = note
        async with self._session_factory() as session:
            await session.execute(
                update(MailScanCursor)
                .where(MailScanCursor.id == claim.id)
                .values(**saved)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

        ctx = checks.CheckContext(owner_domains=checks.owner_domains(account.user_email, claim.account_domain))
        limit = min(MESSAGES_PER_CHECK, max(1, account.rate_limit // 3))
        checked, flagged, unreadable = 0, 0, 0
        failure: Optional[str] = None
        for entry in list(pending[:limit]):
            remaining = deadline - loop.time()
            if remaining <= 0.5:
                break
            ident = entry["id"]
            per_read = min(remaining, MESSAGE_READ_SECONDS)
            try:
                answer = await asyncio.wait_for(call("get_message_security", {"message_id": ident}), per_read)
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                if per_read < MESSAGE_READ_SECONDS:
                    break  # the check's own time ran out: the rest waits
                sentence, account_level = TIMEOUT_REASON.format(app=app), False
            except _ReadFailed as exc:
                sentence, account_level = exc.sentence, exc.account_level
            except Exception as exc:
                sentence, account_level = f"The check failed ({type(exc).__name__}).", False
            else:
                sentence, account_level = "", False
            if sentence:
                if account_level:
                    failure = sentence
                    break
                entry["tries"] = int(entry.get("tries", 0)) + 1
                if entry["tries"] >= FAILED_READ_TRIES:
                    # One "poison" message never stops the account (SEC-F7).
                    pending = [e for e in pending if e["id"] != ident]
                    skipped += 1
                    unreadable += 1
                    continue
                pending = [entry if e["id"] == ident else e for e in pending]
                failure = sentence
                break
            pending = [e for e in pending if e["id"] != ident]
            key = seen_key(claim.connector_id, ident)
            if mail_facts.is_gone(answer):
                # The provider says it no longer exists (FEA-SF3): not a
                # failure, and not read again if it is listed again.
                seen.append(key)
                skipped += 1
                continue
            if answer.get("sent_by_me") is True:
                seen.append(key)
                continue
            received = shape.parse_time(answer.get("received"))
            if received is not None and now - received > MAX_MESSAGE_AGE:
                # Old mail moved into the inbox: counted, not checked.
                seen.append(key)
                skipped += 1
                continue
            links, link_notes = await self._link_signals(answer, deadline)
            assessment = checks.evaluate(answer, ctx, links=links, notes=link_notes)
            seen.append(key)
            checked += 1
            if assessment.level != "none":
                if await self._store_finding(claim, ident, answer, assessment, received, now):
                    flagged += 1
        if unreadable:
            note = (
                "1 message could not be read and was skipped."
                if unreadable == 1
                else f"{unreadable} messages could not be read and were skipped."
            )
        values: dict[str, Any] = {
            "pending_ids": pending[-PENDING_MAX:],
            "seen": seen[-SEEN_RING:],
            "checked_count": claim.checked_count + checked,
            "flagged_count": claim.flagged_count + flagged,
            "skipped_count": skipped,
            "updated_at": now,
        }
        if note:
            values["note"] = note
        if failure is not None:
            await self._record_failure(claim, failure, account.label, extra=values)
            return
        values.update(
            last_checked_at=now,
            consecutive_errors=0,
            last_error=None,
            next_check_at=now
            + timedelta(minutes=BACKLOG_INTERVAL_MINUTES if pending else CHECK_INTERVAL_MINUTES),
        )
        async with self._session_factory() as session:
            await session.execute(
                update(MailScanCursor)
                .where(MailScanCursor.id == claim.id)
                .values(**values)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        logger.info("mail_scan_checked", cursor_id=str(claim.id), checked=checked, flagged=flagged, waiting=len(pending))

    async def _link_signals(
        self, facts: Mapping[str, Any], deadline: Optional[float] = None
    ) -> tuple[list[checks.LinkSignal], tuple[str, ...]]:
        """S4's verdicts for at most 5 of the message's link URLs (scaffold
        A8), as LinkSignals, plus the "not checked" note when S4 could not
        answer. Fail open: an error or a timeout gives no verdict and the
        note; the mail is still scored on everything else."""
        urls = checks.urls_for_reputation(facts)
        if not urls:
            return [], ()
        if self._links is None:
            return [], (checks.LINKS_NOT_CHECKED_NOTE,)
        timeout = LINK_DEADLINE_SECONDS
        if deadline is not None:
            timeout = min(timeout, max(0.1, deadline - asyncio.get_running_loop().time()))
        try:
            reports = await asyncio.wait_for(
                self._links.check(urls, purpose="mail", network=True, timeout_s=LINK_DEADLINE_SECONDS),
                timeout=timeout + 0.5,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("mail_scan_link_check_failed", error_type=type(exc).__name__)
            return [], (checks.LINKS_NOT_CHECKED_NOTE,)
        return self._adapt_links(reports)

    @staticmethod
    def _adapt_links(reports: Any) -> tuple[list[checks.LinkSignal], tuple[str, ...]]:
        """S4's LinkReports as S2's LinkSignals (scaffold A8: level dangerous
        is a listed site, suspicious a strong local sign; signal codes pass
        through LINK_CODE_MAP in mail_checks)."""
        from services.security.link_checks import NOT_CHECKED_STATUSES

        signals: list[checks.LinkSignal] = []
        notes: list[str] = []
        for report in reports if isinstance(reports, (list, tuple)) else []:
            url = getattr(report, "url", "")
            if not isinstance(url, str) or not url:
                continue
            level = getattr(report, "level", "unknown")
            verdict = "malicious" if level == "dangerous" else "suspicious" if level == "suspicious" else "unknown"
            codes = tuple(
                code
                for code in (getattr(s, "code", "") for s in (getattr(report, "signals", ()) or ()))
                if isinstance(code, str) and code
            )
            status = getattr(report, "service_status", "")
            note = checks.LINKS_NOT_CHECKED_NOTE if status in NOT_CHECKED_STATUSES else ""
            if note:
                notes.append(note)
            signals.append(
                checks.LinkSignal(
                    url=url,
                    verdict=verdict,
                    codes=codes,
                    checked_remote=status in ("listed", "not_listed"),
                    note=note,
                )
            )
        return signals, tuple(dict.fromkeys(notes))

    async def _store_finding(
        self,
        claim: _Claim,
        message_id: str,
        answer: Mapping[str, Any],
        assessment: checks.Assessment,
        received: Optional[datetime],
        now: datetime,
    ) -> bool:
        """One finding row for a flagged message; False when it was already
        flagged once (the unique index)."""
        from models.mail_security import MailScamFinding

        display = checks.display_facts(answer)
        refs = [
            shape.clean_line(a.get("ref"), 255)
            for a in checks.risky_attachments(answer, limit=MAX_FILE_CHECKS)
            if isinstance(a.get("ref"), str)
        ]
        if refs:
            display["check_files"] = [r for r in refs if r]
        async with self._session_factory() as session:
            session.add(
                MailScamFinding(
                    id=uuid.uuid4(),
                    user_id=claim.user_id,
                    connector_id=claim.connector_id,
                    provider=claim.provider,
                    external_key=external_key(message_id),
                    message_ref=message_id,
                    status="pending",
                    verdict="unknown",
                    local_level=assessment.level,
                    score=assessment.score,
                    signals=checks.hit_rows(assessment.hits),
                    facts=display,
                    review_input=checks.review_excerpt(answer),
                    check_notes=list(assessment.notes),
                    received_at=received,
                    detected_at=self._next_detected(now),
                )
            )
            try:
                await session.commit()
                return True
            except IntegrityError:
                # Already flagged once (the unique index): never twice.
                await session.rollback()
                return False

    async def _record_failure(
        self, claim: _Claim, reason: str, label: str, *, extra: Optional[dict[str, Any]] = None
    ) -> None:
        from models.mail_security import ERROR_MAX_CHARS, MailScanCursor

        now = self._clock()
        failures = claim.consecutive_errors + 1
        reason = reason[:ERROR_MAX_CHARS]
        values: dict[str, Any] = dict(extra or {})
        values.update(consecutive_errors=failures, last_error=reason, updated_at=now)
        stopped = failures >= ERROR_LIMIT
        if stopped:
            values["status"] = "error"
        else:
            wait = backoff_minutes(CHECK_INTERVAL_MINUTES, failures, MAX_BACKOFF_MINUTES)
            values["next_check_at"] = now + timedelta(minutes=wait)
        logger.info("mail_scan_check_failed", cursor_id=str(claim.id), failures=failures, stopped=stopped)
        try:
            async with self._session_factory() as session:
                result = await session.execute(
                    update(MailScanCursor)
                    .where(MailScanCursor.id == claim.id, MailScanCursor.status == "active")
                    .values(**values)
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
        except Exception as exc:
            logger.warning("mail_scan_record_failed", cursor_id=str(claim.id), error_type=type(exc).__name__)
            return
        if getattr(result, "rowcount", 0) == 1 and stopped:
            # Once per account and reason a day: an account that keeps
            # failing after a token refresh woke it must not repeat itself.
            key, last = str(claim.id), self._stopped_at.get(str(claim.id))
            delivered = False
            if last is None or last[0] != reason or now - last[1] >= timedelta(hours=24):
                self._stopped_at[key] = (reason, now)
                delivered = await self._deliver(claim.user_id, text.stopped_text(label, reason))
            await self._audit(
                claim.user_id,
                "mail_scan_stopped",
                {
                    "cursor_id": str(claim.id),
                    "connector_type": {"gmail": "google_workspace", "outlook": "microsoft"}.get(claim.provider),
                    "failures": failures,
                    "delivered": delivered,
                },
            )

    # -- Phase B: review and alert ----------------------------------------------------

    async def review_pending(self) -> int:
        """Claim pending findings and start up to max_reviews reviews (after
        expiring leases and day-old pending findings). Returns how many were
        started."""
        from models.mail_security import MailScamFinding

        now = self._clock()
        await self._expire_leases(now)
        await self._expire_pending(now)
        free = self._max_reviews - sum(1 for task in self._running if not task.done())
        if free <= 0:
            return 0
        async with self._session_factory() as session:
            ids = (
                (
                    await session.execute(
                        select(MailScamFinding.id)
                        .where(MailScamFinding.status == "pending")
                        .order_by(MailScamFinding.detected_at, MailScamFinding.id)
                        .limit(free)
                    )
                )
                .scalars()
                .all()
            )
            claimed: list[uuid.UUID] = []
            for finding_id in ids:
                result = await session.execute(
                    update(MailScamFinding)
                    .where(MailScamFinding.id == finding_id, MailScamFinding.status == "pending")
                    .values(status="reviewing", claimed_until=now + timedelta(minutes=REVIEW_LEASE_MINUTES))
                    .execution_options(synchronize_session=False)
                )
                if getattr(result, "rowcount", 0) == 1:
                    claimed.append(finding_id)
            await session.commit()
        for finding_id in claimed:
            task = asyncio.create_task(self._review_one(finding_id), name=f"mail-review-{str(finding_id)[:8]}")
            self._running.add(task)
            task.add_done_callback(self._running.discard)
        return len(claimed)

    async def _expire_leases(self, now: datetime) -> None:
        """A review still running past its lease (a crash, a stop): one more
        try; after REVIEW_ATTEMPTS it goes on to alert without AI."""
        from models.mail_security import MailScamFinding

        async with self._session_factory() as session:
            await session.execute(
                update(MailScamFinding)
                .where(MailScamFinding.status == "reviewing", MailScamFinding.claimed_until < now)
                .values(status="pending", claimed_until=None, attempts=MailScamFinding.attempts + 1)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def _expire_pending(self, now: datetime) -> int:
        """Findings that waited over a day (the switch was off) expire with
        no alert."""
        from models.mail_security import MailScamFinding

        async with self._session_factory() as session:
            result = await session.execute(
                update(MailScamFinding)
                .where(
                    MailScamFinding.status.in_(["pending", "reviewing"]),
                    MailScamFinding.detected_at < now - PENDING_EXPIRY,
                )
                .values(status="expired", alert_note=EXPIRED_NOTE, claimed_until=None, review_input=null())
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)

    async def _release(self, finding_id: uuid.UUID) -> None:
        from models.mail_security import MailScamFinding

        async with self._session_factory() as session:
            await session.execute(
                update(MailScamFinding)
                .where(MailScamFinding.id == finding_id, MailScamFinding.status == "reviewing")
                .values(status="pending", claimed_until=None)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def _review_one(self, finding_id: uuid.UUID) -> None:
        try:
            await self._review_inner(finding_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The lease expires and the review is tried once more.
            logger.error("mail_scan_review_failed", finding_id=str(finding_id), error_type=type(exc).__name__)

    async def _load_job(self, finding_id: uuid.UUID) -> Optional[_Job]:
        from models.connector import ConnectorConfig, connector_type_key
        from models.mail_security import MailScamFinding
        from models.user import User

        async with self._session_factory() as session:
            row = await session.get(MailScamFinding, finding_id)
            if row is None or row.status != "reviewing":
                return None
            user = await session.get(User, row.user_id)
            connector = await session.get(ConnectorConfig, row.connector_id)
            return _Job(
                id=row.id,
                user_id=row.user_id,
                connector_id=row.connector_id,
                provider=row.provider,
                message_ref=row.message_ref,
                local_level=row.local_level if row.local_level in ("likely_scam", "suspicious") else "suspicious",
                score=int(row.score or 0),
                signals=list(row.signals or []),
                facts=dict(row.facts) if isinstance(row.facts, Mapping) else {},
                review_input=dict(row.review_input) if isinstance(row.review_input, Mapping) else {},
                check_notes=[n for n in (row.check_notes or []) if isinstance(n, str)],
                attempts=int(row.attempts or 0),
                reserved=row.reviewed_at is not None,
                user_active=bool(user is not None and user.is_active),
                llm_provider=user.llm_provider if user is not None else None,
                llm_model=user.llm_model if user is not None else None,
                timezone=user.timezone if user is not None else None,
                connector_type=connector_type_key(connector.connector_type) if connector is not None else None,
                display_name=connector.display_name if connector is not None else "",
                granted_scopes=list(connector.granted_scopes or []) if connector is not None else [],
            )

    async def _review_inner(self, finding_id: uuid.UUID) -> None:
        from services.mail_scan.review import Review, ReviewSkipped

        if not await self._on():
            await self._release(finding_id)
            return
        job = await self._load_job(finding_id)
        if job is None:
            return
        if not job.user_active:
            await self._finish(job, status="expired", alert_note=EXPIRED_NOTE)
            return
        hits = checks.hits_from_rows(job.signals)
        assessment = checks.Assessment(
            hits=hits, score=job.score, level=job.local_level, notes=tuple(job.check_notes)
        )
        # c. Attachments: S10 fingerprints up to two risky ones (VirusTotal's
        # public limits), only for flagged mail.
        files, file_notes = await self._file_signals(job)
        assessment = checks.with_files(assessment, files)
        if file_notes:
            assessment = checks.Assessment(
                hits=assessment.hits,
                score=assessment.score,
                level=assessment.level,
                notes=tuple(dict.fromkeys([*assessment.notes, *file_notes])),
            )
        level, hits = assessment.level, assessment.hits
        if level not in ("likely_scam", "suspicious"):
            level = job.local_level
        # d, e. The AI review, under the person's own daily cap.
        if job.attempts >= REVIEW_ATTEMPTS:
            review: Any = ReviewSkipped(ai.INTERRUPTED_NOTE, True)
        else:
            review = await self._run_review(job, hits)
        verdict = ai.combine(level, review)
        auth = _map(job.facts.get("auth"))
        base: dict[str, Any] = {
            "local_level": level,
            "score": assessment.score,
            "signals": checks.hit_rows(hits),
            "check_notes": list(assessment.notes),
        }
        if isinstance(review, Review):
            base["review"] = ai.review_record(review)
            base["review_note"] = None
        else:
            base["review_note"] = review.note
        # f. A no-signs review quiets only a weak finding from an
        # authenticated sender (review SEC-M1); any other one still alerts.
        if isinstance(review, Review) and checks.goes_quiet(level, review.verdict, hits, auth):
            await self._finish(job, status="quiet", verdict="no_signs", **base)
            await self._flagged_audit(job, "no_signs", level, assessment.score, hits, review, alerted=False)
            return
        # f2. No review: a finding whose signs are all noisy is listed on the
        # tab and summed up once a day (review FEA-SF2).
        if isinstance(review, ReviewSkipped) and not checks.pushes_without_review(verdict, hits):
            await self._finish(
                job, status="alerted", verdict=verdict, alert_note=LISTED_NOTE, alerted_at=self._clock(), **base
            )
            await self._flagged_audit(job, verdict, level, assessment.score, hits, review, alerted=False)
            return
        # g. The hourly cap holds suspicious alerts only (review SEC-F7).
        if verdict != "likely_scam" and not checks.has_hard_hit(hits):
            if await self._alerts_last_hour(job.user_id) >= MAX_ALERTS_PER_HOUR:
                await self._finish(
                    job, status="alerted", verdict=verdict, alert_note=HELD_NOTE, alerted_at=self._clock(), **base
                )
                await self._overflow(job.user_id)
                await self._flagged_audit(job, verdict, level, assessment.score, hits, review, alerted=False)
                return
        # h. Only a likely scam gets an automatic card (review FEA-SF2).
        connector_type = job.connector_type or ""
        kinds, hint = cards.offered(job.facts, connector_type=connector_type, granted_scopes=job.granted_scopes)
        plan: Any = None
        if verdict == "likely_scam" and kinds:
            plan = cards.plan_card(
                cards.MOVE_TO_SPAM,
                connector_type=connector_type,
                connector_id=str(job.connector_id),
                granted_scopes=job.granted_scopes,
                message_ref=job.message_ref,
                display=job.facts,
            )
            if isinstance(plan, str):
                hint, plan = plan, None
        # i. The alert first.
        tz = self._zone(job.timezone)
        alert = text.alert_text(
            account=text.account_label(job.display_name, job.provider),
            provider=job.provider,
            verdict=verdict,
            display=job.facts,
            hits=hits,
            review=review if isinstance(review, Review) else None,
            review_note=review.note if isinstance(review, ReviewSkipped) else None,
            check_notes=list(assessment.notes),
            card="spam" if plan is not None else None,
            card_hint=hint if not kinds or (verdict == "likely_scam" and plan is None) else None,
            tz=tz,
            scan=self._scanner(),
        )
        delivered = await self._deliver(job.user_id, alert)
        # j. Then the card.
        card_ids: list[dict[str, Any]] = []
        notes: list[str] = [] if delivered else [NOT_DELIVERED]
        if plan is not None:
            action_id = await self._park(job, plan, verdict, hits)
            if action_id:
                card_ids.append({"action_id": action_id, "kind": plan.kind})
            else:
                notes.append(CARD_NOT_MADE)
        # k, l.
        await self._finish(
            job,
            status="alerted",
            verdict=verdict,
            alert_delivered=delivered,
            alert_note="; ".join(notes) or None,
            alerted_at=self._clock(),
            card_ids=card_ids or None,
            **base,
        )
        await self._flagged_audit(
            job, verdict, level, assessment.score, hits, review, alerted=True, delivered=delivered, card=bool(card_ids)
        )

    async def _park(self, job: _Job, plan: Any, verdict: str, hits: Sequence[checks.Hit]) -> Optional[str]:
        """Park the card; its action id, or None when no card was made (a
        refusal or an error is logged by type; the tab offers it again)."""
        if self._runtime is None:
            return None
        try:
            stored = await cards.create_card(
                self._runtime,
                user_id=str(job.user_id),
                finding_id=str(job.id),
                plan=plan,
                security_note=text.security_note(verdict, hits),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("mail_scan_card_failed", finding_id=str(job.id), error_type=type(exc).__name__)
            return None
        action_id = getattr(stored, "action_id", None)
        if not isinstance(action_id, str) or not action_id:
            logger.info("mail_scan_card_refused", finding_id=str(job.id), refusal=type(stored).__name__)
            return None
        return action_id

    async def _file_signals(self, job: _Job) -> tuple[list[checks.FileSignal], tuple[str, ...]]:
        """S10's verdicts for up to two risky attachments (scaffold A9). No
        key or the switch off: no lookup and no note (attachments are scored
        on type and name). An error, a limit or a timeout: the "not checked"
        note; the alert still goes out."""
        refs = [r for r in (job.facts.get("check_files") or []) if isinstance(r, str) and r][:MAX_FILE_CHECKS]
        if not refs or not job.connector_type:
            return [], ()
        if self._files is None:
            return [], (checks.FILES_NOT_CHECKED_NOTE,)
        try:
            if not await self._files.remote_configured():
                return [], ()
        except Exception as exc:
            logger.warning("mail_scan_file_service_unreadable", error_type=type(exc).__name__)
            return [], (checks.FILES_NOT_CHECKED_NOTE,)
        from services.triggers.sources import tool_name

        hash_tool = tool_name(job.connector_type, str(job.connector_id), "get_attachment_hash")
        signals: list[checks.FileSignal] = []
        notes: list[str] = []
        for ref in refs:
            try:
                verdict = await asyncio.wait_for(
                    self._files.check_mail_attachment(
                        str(job.user_id),
                        hash_tool=hash_tool,
                        message_id=job.message_ref,
                        attachment_id=ref,
                        priority="automatic",
                        wait_s=FILE_DEADLINE_SECONDS,
                        alert="caller",
                    ),
                    timeout=FILE_DEADLINE_SECONDS + 5.0,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("mail_scan_file_check_failed", finding_id=str(job.id), error_type=type(exc).__name__)
                notes.append(checks.FILES_NOT_CHECKED_NOTE)
                continue
            signal = self._adapt_file(ref, verdict)
            if signal.note:
                notes.append(signal.note)
            signals.append(signal)
        return signals, tuple(dict.fromkeys(notes))

    @staticmethod
    def _adapt_file(ref: str, verdict: Any) -> checks.FileSignal:
        """S10's FileVerdict as S2's FileSignal: malicious and suspicious pass
        through with the malicious engine count; a lookup that did not
        happen for any reason but a missing key or the switch gets the note."""
        value = getattr(verdict, "verdict", "")
        reason = getattr(verdict, "reason", None)
        malicious = getattr(verdict, "malicious", 0)
        engines = malicious if isinstance(malicious, int) and not isinstance(malicious, bool) and malicious > 0 else 0
        note = ""
        if value in ("not_checked", "pending") and reason not in ("no_key", "switched_off"):
            note = checks.FILES_NOT_CHECKED_NOTE
        return checks.FileSignal(
            ref=ref,
            verdict=value if value in ("malicious", "suspicious") else "unknown",
            codes=(),
            checked_remote=value in ("malicious", "suspicious", "no_detections", "unknown"),
            engines_malicious=engines,
            note=note,
        )

    async def _run_review(self, job: _Job, hits: Sequence[checks.Hit]) -> Any:
        """The review under the person's daily cap (counted from
        ``reviewed_at``; a slot is reserved before the call and given back
        when no provider was called). Never raises."""
        from services.agent.providers import ProviderNotConfigured
        from services.mail_scan.review import ReviewSkipped

        async with self._cap_lock:
            try:
                limit = await self._reviews_per_day()
            except Exception as exc:
                logger.warning("mail_scan_settings_unreadable", error_type=type(exc).__name__)
                return ReviewSkipped(ai.SETTINGS_NOTE, False)
            if not job.reserved:
                if await self._reviews_today(job.user_id) >= limit:
                    return ReviewSkipped(ai.daily_cap_note(limit), False)
                await self._set_reviewed(job.id, self._clock())
        result: Any
        if self._runtime is None:
            result = ReviewSkipped(ai.NO_PROVIDER_NOTE, False)
        else:
            try:
                provider, model, local = await ai.choose_provider(
                    self._runtime,
                    user_provider=job.llm_provider,
                    user_model=job.llm_model,
                    local_model=self._local_model,
                    ollama_base_url=self._ollama_base_url,
                )
            except ProviderNotConfigured:
                result = ReviewSkipped(ai.NO_PROVIDER_NOTE, False)
            except Exception as exc:
                logger.warning("mail_scan_provider_unreadable", error_type=type(exc).__name__)
                result = ReviewSkipped(ai.PROVIDER_ERROR_NOTE, False)
            else:
                data = ai.model_input({**job.facts, "provider": job.provider}, job.review_input, hits)
                result = await ai.review_mail(
                    self._runtime,
                    data,
                    provider=provider,
                    model=model,
                    is_local=local,
                    scan=self._scanner(),
                    deadline_s=self._review_deadline_s,
                )
        if isinstance(result, ReviewSkipped) and not result.called_provider and not job.reserved:
            await self._set_reviewed(job.id, None)
        return result

    async def _set_reviewed(self, finding_id: uuid.UUID, moment: Optional[datetime]) -> None:
        from models.mail_security import MailScamFinding

        async with self._session_factory() as session:
            await session.execute(
                update(MailScamFinding)
                .where(MailScamFinding.id == finding_id)
                .values(reviewed_at=moment if moment is not None else null())
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def _reviews_per_day(self) -> int:
        if self._settings is None:
            return DEFAULT_REVIEWS_PER_DAY
        values = await self._settings.capability_settings(CAPABILITY)
        limit = values.get("ai_reviews_per_day") if isinstance(values, Mapping) else None
        return limit if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0 else DEFAULT_REVIEWS_PER_DAY

    async def _keep_days(self) -> int:
        if self._settings is None:
            return DEFAULT_KEEP_DAYS
        try:
            values = await self._settings.capability_settings(CAPABILITY)
        except Exception as exc:
            logger.warning("mail_scan_settings_unreadable", error_type=type(exc).__name__)
            return DEFAULT_KEEP_DAYS
        days = values.get("keep_alerts_days") if isinstance(values, Mapping) else None
        return days if isinstance(days, int) and not isinstance(days, bool) and days >= 1 else DEFAULT_KEEP_DAYS

    def _day_start(self) -> datetime:
        return self._clock().astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    async def _reviews_today(self, user_id: uuid.UUID) -> int:
        from models.mail_security import MailScamFinding

        async with self._session_factory() as session:
            count = (
                await session.execute(
                    select(func.count(MailScamFinding.id)).where(
                        MailScamFinding.user_id == user_id, MailScamFinding.reviewed_at >= self._day_start()
                    )
                )
            ).scalar_one()
        return int(count or 0)

    async def _alerts_last_hour(self, user_id: uuid.UUID) -> int:
        from models.mail_security import MailScamFinding

        since = self._clock() - timedelta(hours=1)
        async with self._session_factory() as session:
            count = (
                await session.execute(
                    select(func.count(MailScamFinding.id)).where(
                        MailScamFinding.user_id == user_id,
                        MailScamFinding.alerted_at >= since,
                        MailScamFinding.alert_delivered.is_(True),
                    )
                )
            ).scalar_one()
        return int(count or 0)

    async def _overflow(self, user_id: uuid.UUID) -> None:
        """The "too many alerts" line, at most once per person per hour."""
        from models.mail_security import MailScamFinding

        now = self._clock()
        key = str(user_id)
        last = self._overflow_at.get(key)
        if last is not None and now - last < timedelta(hours=1):
            return
        async with self._session_factory() as session:
            held = (
                await session.execute(
                    select(func.count(MailScamFinding.id)).where(
                        MailScamFinding.user_id == user_id,
                        MailScamFinding.alert_note == HELD_NOTE,
                        MailScamFinding.alerted_at >= now - timedelta(hours=1),
                    )
                )
            ).scalar_one()
        self._overflow_at[key] = now
        await self._deliver(user_id, text.overflow_text(max(1, int(held or 0))))

    async def _finish(self, job: _Job, **values: Any) -> None:
        """Write the decision: the lease is released and the excerpt the AI
        read is cleared in the same UPDATE."""
        from models.mail_security import NOTE_MAX_CHARS, MailScamFinding

        values["claimed_until"] = None
        values["review_input"] = null()
        if isinstance(values.get("alert_note"), str):
            values["alert_note"] = values["alert_note"][:NOTE_MAX_CHARS]
        if isinstance(values.get("review_note"), str):
            values["review_note"] = values["review_note"][:NOTE_MAX_CHARS]
        async with self._session_factory() as session:
            await session.execute(
                update(MailScamFinding)
                .where(MailScamFinding.id == job.id, MailScamFinding.status == "reviewing")
                .values(**values)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def _flagged_audit(
        self,
        job: _Job,
        verdict: str,
        level: str,
        score: int,
        hits: Sequence[checks.Hit],
        review: Any,
        *,
        alerted: bool,
        delivered: bool = False,
        card: bool = False,
    ) -> None:
        from services.mail_scan.review import Review

        reviewed = isinstance(review, Review)
        await self._audit(
            job.user_id,
            "mail_scam_flagged",
            {
                "finding_id": str(job.id),
                "connector_type": job.connector_type,
                "verdict": verdict,
                "local_level": level,
                "score": score,
                "codes": [hit.code for hit in hits],
                "reviewed": reviewed,
                "provider": review.provider if reviewed else None,
                "input_tokens": review.input_tokens if reviewed else 0,
                "output_tokens": review.output_tokens if reviewed else 0,
                "cost_usd": round(float(review.cost_usd), 6) if reviewed and review.cost_usd is not None else None,
                "alerted": alerted,
                "delivered": delivered,
                "card": card,
            },
        )

    def _zone(self, name: Optional[str]) -> Any:
        from services.scheduler.timezones import parse_zone

        if not name:
            return None
        try:
            zone, _error = parse_zone(name)
        except Exception:
            return None
        return zone

    # -- the daily summary of unreviewed weak findings (FEA-SF2) ------------------------

    async def _daily_summaries(self, now: datetime) -> None:
        from models.mail_security import MailScamFinding
        from models.user import User

        since_floor = now - timedelta(hours=24)
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(MailScamFinding.user_id, User.timezone)
                    .join(User, User.id == MailScamFinding.user_id)
                    .where(
                        MailScamFinding.alert_note == LISTED_NOTE,
                        MailScamFinding.detected_at >= since_floor,
                        User.is_active.is_(True),
                    )
                    .group_by(MailScamFinding.user_id, User.timezone)
                )
            ).all()
        for user_id, zone_name in rows:
            key = str(user_id)
            zone = self._zone(zone_name) or timezone.utc
            local = now.astimezone(zone)
            if local.hour < SUMMARY_HOUR_LOCAL or self._summary_day.get(key) == local.date():
                continue
            since = max(self._summary_at.get(key, since_floor), since_floor)
            async with self._session_factory() as session:
                count = (
                    await session.execute(
                        select(func.count(MailScamFinding.id)).where(
                            MailScamFinding.user_id == user_id,
                            MailScamFinding.alert_note == LISTED_NOTE,
                            MailScamFinding.detected_at >= since,
                        )
                    )
                ).scalar_one()
            if not count:
                continue
            self._summary_day[key] = local.date()
            self._summary_at[key] = now
            await self._deliver(user_id, text.summary_text(int(count)))

    # -- delivery and audit -----------------------------------------------------------

    async def _deliver(self, user_id: uuid.UUID, message: str) -> bool:
        if self._send is None:
            return False
        try:
            # The person's own linked chats only; False while none is linked.
            return (await self._send(str(user_id), message)) is True
        except Exception as exc:
            # Not retried: a broken channel must not turn into a storm.
            logger.warning("mail_scan_delivery_failed", error_type=type(exc).__name__)
            return False

    async def _audit(
        self, user_id: Any, action: str, data: dict[str, Any], *, endpoint: str = SWEEPER_ENDPOINT
    ) -> None:
        """One row in the person's audit log: ids, counts and codes, never an
        address, a subject, a host or a message id."""
        if not self._audit_enabled:
            return
        from models.audit import AuditStatus
        from services.audit import append_audit_log

        status = AuditStatus.blocked if action == "mail_scan_stopped" else AuditStatus.approved
        try:
            async with self._session_factory() as session:
                await append_audit_log(
                    session,
                    user_id=user_id,
                    connector_name=AUDIT_CONNECTOR,
                    action=action,
                    endpoint=endpoint,
                    scope_used=CAPABILITY,
                    status=status,
                    request_data=data,
                )
                await session.commit()
        except Exception as exc:
            logger.warning("mail_scan_audit_failed", error_type=type(exc).__name__)

    # -- housekeeping (hourly, even while the switch is off) ---------------------------

    async def _maybe_housekeep(self, now: datetime) -> None:
        if self._last_housekeeping is not None and now - self._last_housekeeping < HOUSEKEEPING_EVERY:
            return
        self._last_housekeeping = now
        try:
            await self.housekeep(now)
        except Exception as exc:
            logger.warning("mail_scan_housekeeping_failed", error_type=type(exc).__name__)

    async def housekeep(self, now: datetime) -> None:
        """Delete findings older than keep_alerts_days, clear review excerpts
        older than a day, and expire findings that waited over a day."""
        from models.mail_security import MailScamFinding

        keep = await self._keep_days()
        async with self._session_factory() as session:
            await session.execute(
                delete(MailScamFinding)
                .where(MailScamFinding.detected_at < now - timedelta(days=keep))
                .execution_options(synchronize_session=False)
            )
            await session.execute(
                update(MailScamFinding)
                .where(
                    MailScamFinding.detected_at < now - REVIEW_EXCERPT_TTL,
                    MailScamFinding.review_input.is_not(None),
                )
                # SQL NULL, not a JSON null, so the next pass skips them.
                .values(review_input=null())
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        await self._expire_pending(now)

    # -- called by the routes (each re-checks ownership; ids only in audit rows) --------

    async def status(self, user_id: str, *, is_admin: bool) -> dict[str, Any]:
        """The Mail alerts tab's header and the caller's mailboxes; the
        owner also gets install-wide counts (numbers only)."""
        from models.mail_security import MailScamFinding, MailScanCursor
        from services.capabilities.mail_scam_scan import CAPABILITY as SWITCH

        owner = _uuid(user_id)
        if owner is None:
            return _refusal(404, NOT_FOUND)
        enabled = await self._on()
        try:
            per_day = await self._reviews_per_day()
        except Exception:
            per_day = DEFAULT_REVIEWS_PER_DAY
        link_checks = "local"
        if self._links is not None:
            try:
                link_checks = "local_and_remote" if await self._links.remote_configured() else "local"
            except Exception as exc:
                logger.warning("mail_scan_link_service_unreadable", error_type=type(exc).__name__)
        file_checks = "off"
        if self._files is not None:
            try:
                file_checks = "remote" if await self._files.remote_configured() else "off"
            except Exception as exc:
                logger.warning("mail_scan_file_service_unreadable", error_type=type(exc).__name__)
        accounts = await self._accounts(owner)
        install: Optional[dict[str, int]] = None
        if is_admin:
            week = self._clock() - timedelta(days=7)
            async with self._session_factory() as session:
                install = {
                    "accounts": int(
                        (await session.execute(select(func.count(MailScanCursor.id)))).scalar_one() or 0
                    ),
                    "alerts_7d": int(
                        (
                            await session.execute(
                                select(func.count(MailScamFinding.id)).where(MailScamFinding.alerted_at >= week)
                            )
                        ).scalar_one()
                        or 0
                    ),
                    "reviews_today": int(
                        (
                            await session.execute(
                                select(func.count(MailScamFinding.id)).where(
                                    MailScamFinding.reviewed_at >= self._day_start()
                                )
                            )
                        ).scalar_one()
                        or 0
                    ),
                }
        return {
            "ok": True,
            "enabled": enabled,
            "when_off": None if enabled else SWITCH.when_denied,
            "ai_reviews_today": await self._reviews_today(owner),
            "ai_reviews_per_day": per_day,
            "link_checks": link_checks,
            "file_checks": file_checks,
            "accounts": accounts,
            "install": install,
        }

    async def _accounts(self, owner: uuid.UUID) -> list[dict[str, Any]]:
        from models.connector import ConnectorConfig
        from models.mail_security import MailScanCursor

        async with self._session_factory() as session:
            connectors = (
                (
                    await session.execute(
                        select(ConnectorConfig)
                        .where(
                            ConnectorConfig.user_id == owner,
                            ConnectorConfig.is_active.is_(True),
                            ConnectorConfig.connector_type.in_(list(PROVIDER_OF)),
                        )
                        .order_by(ConnectorConfig.created_at, ConnectorConfig.id)
                    )
                )
                .scalars()
                .all()
            )
            cursors = {
                row.connector_id: row
                for row in (
                    await session.execute(select(MailScanCursor).where(MailScanCursor.user_id == owner))
                )
                .scalars()
                .all()
            }
        return [self._account_view(connector, cursors.get(connector.id)) for connector in connectors]

    @staticmethod
    def _account_view(connector: Any, cursor: Any) -> dict[str, Any]:
        from models.connector import PermissionTier, connector_type_key

        kind = connector_type_key(connector.connector_type)
        provider = PROVIDER_OF.get(kind, "gmail")
        scopes = list(connector.granted_scopes or [])
        readable = (not scopes or READ_SCOPE.get(kind, "") in scopes) and (
            connector.permission_tier != PermissionTier.hard_blocked
        )
        if not readable:
            status = "no_access"
        elif cursor is None:
            status = "starting"
        elif cursor.status in ("paused", "error"):
            status = cursor.status
        elif not cursor.cursor:
            status = "starting"
        else:
            status = "active"
        return {
            "connector_id": str(connector.id),
            "account": text.account_label(connector.display_name, provider),
            "provider": provider,
            "status": status,
            "last_checked_at": _iso(cursor.last_checked_at) if cursor is not None else None,
            "checked_count": int(cursor.checked_count or 0) if cursor is not None else 0,
            "flagged_count": int(cursor.flagged_count or 0) if cursor is not None else 0,
            "skipped_count": int(cursor.skipped_count or 0) if cursor is not None else 0,
            "last_error": cursor.last_error if cursor is not None and cursor.status == "error" else None,
            "note": cursor.note if cursor is not None else None,
        }

    async def list_alerts(
        self, user_id: str, *, view: str, before: Optional[datetime], limit: int
    ) -> dict[str, Any]:
        """The caller's alerts, newest detected first; ``open`` is alerted
        and not dismissed, ``all`` adds quiet, dismissed and expired."""
        from models.connector import ConnectorConfig
        from models.mail_security import MailScamFinding

        owner = _uuid(user_id)
        if owner is None:
            return _refusal(404, NOT_FOUND)
        if view not in ("open", "all"):
            return _refusal(422, "view must be open or all.")
        size = max(1, min(int(limit), 50))
        statuses = _OPEN_STATUSES if view == "open" else _ALL_STATUSES
        query = select(MailScamFinding).where(
            MailScamFinding.user_id == owner, MailScamFinding.status.in_(list(statuses))
        )
        if before is not None:
            query = query.where(MailScamFinding.detected_at < before)
        query = query.order_by(MailScamFinding.detected_at.desc(), MailScamFinding.id.desc()).limit(size + 1)
        async with self._session_factory() as session:
            rows = list((await session.execute(query)).scalars().all())
            more = len(rows) > size
            rows = rows[:size]
            connector_ids = list({row.connector_id for row in rows})
            connectors: dict[Any, Any] = {}
            if connector_ids:
                found = (
                    (await session.execute(select(ConnectorConfig).where(ConnectorConfig.id.in_(connector_ids))))
                    .scalars()
                    .all()
                )
                connectors = {connector.id: connector for connector in found}
        statuses_by_id = await self._card_statuses(owner, [c for row in rows for c in (row.card_ids or [])])
        alerts = [self._alert_view(row, connectors.get(row.connector_id), statuses_by_id) for row in rows]
        next_before = _iso(rows[-1].detected_at) if more and rows else None
        return {"ok": True, "alerts": alerts, "next_before": next_before}

    async def _card_statuses(self, owner: uuid.UUID, card_refs: Sequence[Any]) -> dict[str, dict[str, Any]]:
        """Each card's status read from its pending_actions row (this user's
        only): a pending one past its expiry reads as expired, a missing row
        as missing."""
        from models.pending_action import PendingAction

        ids: list[uuid.UUID] = []
        for ref in card_refs:
            parsed = _uuid(ref.get("action_id")) if isinstance(ref, Mapping) else None
            if parsed is not None:
                ids.append(parsed)
        if not ids:
            return {}
        now = self._clock()
        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(PendingAction).where(PendingAction.id.in_(ids), PendingAction.user_id == owner)
                    )
                )
                .scalars()
                .all()
            )
        found: dict[str, dict[str, Any]] = {}
        for row in rows:
            status = getattr(row.status, "value", row.status)
            expires = _utc(row.expires_at)
            if status == "pending" and expires is not None and expires <= now:
                status = "expired"
            found[str(row.id)] = {"status": str(status), "expires_at": _iso(expires)}
        return found

    @staticmethod
    def _cards_of(row: Any, statuses: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
        cards_out: list[dict[str, Any]] = []
        for ref in row.card_ids or []:
            if not isinstance(ref, Mapping):
                continue
            action_id = _uuid(ref.get("action_id"))
            kind = ref.get("kind")
            if action_id is None or kind not in cards.ACTION_KINDS:
                continue
            state = statuses.get(str(action_id))
            cards_out.append(
                {
                    "action_id": str(action_id),
                    "kind": kind,
                    "status": state["status"] if state else "missing",
                    "expires_at": state["expires_at"] if state else None,
                }
            )
        return cards_out

    def _alert_view(self, row: Any, connector: Any, statuses: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        """One MailAlert (S2.md 4.8): the sender, address and subject through
        the alert's rules (withheld or defanged), Crawler's fixed reasons, the
        review's sanitised lines (none for a "no signs" review), the cards and
        what may be asked for now."""
        from models.connector import connector_type_key

        scan = self._scanner()
        facts = _map(row.facts)
        sender = _map(facts.get("from"))
        hits = checks.hits_from_rows(row.signals)
        stored = ai.review_from_record(row.review)
        review: Optional[dict[str, Any]] = None
        if stored is not None:
            strict = stored.verdict in ("likely_scam", "suspicious")
            review = {
                "reasons": list(stored.reasons) if strict else [],
                "advice": stored.advice if strict else "",
                "provider": stored.provider,
                "model": stored.model,
            }
        actions: list[str] = []
        hint: Optional[str] = None
        if connector is not None and connector.is_active and row.status in _ACTIONABLE:
            actions, hint = cards.offered(
                facts,
                connector_type=connector_type_key(connector.connector_type),
                granted_scopes=list(connector.granted_scopes or []),
            )
        elif row.status in _ACTIONABLE:
            hint = ACCOUNT_GONE
        verdict = row.verdict if row.verdict in ("likely_scam", "suspicious", "no_signs") else "unknown"
        if verdict == "unknown" and row.status != "expired":
            verdict = row.local_level if row.local_level in ("likely_scam", "suspicious") else "unknown"
        return {
            "id": str(row.id),
            "connector_id": str(row.connector_id),
            "account": text.account_label(connector.display_name if connector is not None else "", row.provider),
            "provider": row.provider,
            "verdict": verdict,
            "status": row.status,
            "from_name": text.shown(sender.get("name"), "sender name", scan, limit=text.NAME_CHARS),
            "from_address": shape.defang(shape.clean_line(sender.get("address"), 254)),
            "subject": text.shown(facts.get("subject"), "subject", scan) or "(no subject)",
            "received_at": _iso(row.received_at),
            "detected_at": _iso(row.detected_at),
            "reasons": checks.reason_lines(hits),
            "check_notes": [shape.clean_line(n, 200) for n in (row.check_notes or []) if isinstance(n, str)][:5],
            "review": review,
            "review_note": row.review_note,
            "delivered": bool(row.alert_delivered),
            "alert_note": row.alert_note,
            "cards": self._cards_of(row, statuses),
            "actions": actions,
            "action_hint": hint,
        }

    async def _owned_finding(self, owner: uuid.UUID, finding_id: str) -> Any:
        from models.mail_security import MailScamFinding

        parsed = _uuid(finding_id)
        if parsed is None:
            return None
        async with self._session_factory() as session:
            row = await session.get(MailScamFinding, parsed)
        return row if row is not None and row.user_id == owner else None

    async def request_action(self, user_id: str, finding_id: str, kind: str) -> dict[str, Any]:
        """Park the Move-to-Spam/Junk card for one alert: 409 while one is
        still waiting, 422 with the reason it is not offered."""
        from models.connector import ConnectorConfig, connector_type_key
        from models.mail_security import MailScamFinding

        owner = _uuid(user_id)
        if owner is None:
            return _refusal(404, NOT_FOUND)
        async with self._action_lock:
            row = await self._owned_finding(owner, finding_id)
            if row is None or row.status in ("pending", "reviewing"):
                return _refusal(404, NOT_FOUND)
            if kind not in cards.ACTION_KINDS:
                return _refusal(422, cards.NOT_OFFERED)
            if row.status == "dismissed":
                return _refusal(422, DISMISSED_NO_ACTION)
            async with self._session_factory() as session:
                connector = await session.get(ConnectorConfig, row.connector_id)
            if connector is None or connector.user_id != owner or not connector.is_active:
                return _refusal(422, ACCOUNT_GONE)
            statuses = await self._card_statuses(owner, list(row.card_ids or []))
            for card in self._cards_of(row, statuses):
                if card["kind"] == kind and card["status"] == "pending":
                    return _refusal(409, NO_CARD_WAITING)
            facts = row.facts if isinstance(row.facts, Mapping) else {}
            plan = cards.plan_card(
                kind,
                connector_type=connector_type_key(connector.connector_type),
                connector_id=str(connector.id),
                granted_scopes=list(connector.granted_scopes or []),
                message_ref=row.message_ref,
                display=facts,
            )
            if isinstance(plan, str):
                return _refusal(422, plan)
            if self._runtime is None:
                return _refusal(503, STARTING)
            verdict = row.verdict if row.verdict in ("likely_scam", "suspicious") else row.local_level
            try:
                stored = await cards.create_card(
                    self._runtime,
                    user_id=str(owner),
                    finding_id=str(row.id),
                    plan=plan,
                    security_note=text.security_note(verdict, checks.hits_from_rows(row.signals)),
                )
            except Exception as exc:
                logger.warning("mail_scan_card_failed", finding_id=str(row.id), error_type=type(exc).__name__)
                return _refusal(503, CARD_FAILED)
            action_id = getattr(stored, "action_id", None)
            if not isinstance(action_id, str) or not action_id:
                reason = shape.clean_line(getattr(stored, "reason", ""), 200)
                return _refusal(422, f"The card was not made: {reason}" if reason else "The card was not made.")
            refs = [dict(r) for r in (row.card_ids or []) if isinstance(r, Mapping)]
            refs.append({"action_id": action_id, "kind": kind})
            async with self._session_factory() as session:
                await session.execute(
                    update(MailScamFinding)
                    .where(MailScamFinding.id == row.id)
                    .values(card_ids=refs)
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
        await self._audit(
            owner,
            "mail_scam_action_requested",
            {"finding_id": str(row.id), "kind": kind, "action_id": action_id, "source": "web"},
            endpoint=ROUTE_ACTIONS,
        )
        return {
            "ok": True,
            "card": {
                "action_id": action_id,
                "kind": kind,
                "status": "pending",
                "expires_at": _iso(_moment(getattr(stored, "expires_at", None))),
            },
        }

    async def dismiss(self, user_id: str, finding_id: str) -> dict[str, Any]:
        """"Not a scam": the alert leaves the open view (idempotent)."""
        from models.mail_security import MailScamFinding

        owner = _uuid(user_id)
        if owner is None:
            return _refusal(404, NOT_FOUND)
        row = await self._owned_finding(owner, finding_id)
        if row is None or row.status in ("pending", "reviewing"):
            return _refusal(404, NOT_FOUND)
        if row.status != "dismissed":
            async with self._session_factory() as session:
                await session.execute(
                    update(MailScamFinding)
                    .where(MailScamFinding.id == row.id, MailScamFinding.user_id == owner)
                    .values(status="dismissed", dismissed_at=self._clock())
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
            await self._audit(
                owner, "mail_scam_dismissed", {"finding_id": str(row.id), "source": "web"}, endpoint=ROUTE_DISMISS
            )
        return {"ok": True, "status": "dismissed"}

    async def set_paused(self, user_id: str, connector_id: str, paused: bool) -> dict[str, Any]:
        """Pause or resume one of the caller's mailboxes; Resume also clears
        a stop after errors and checks soon."""
        from models.connector import ConnectorConfig, connector_type_key
        from models.mail_security import MailScanCursor

        owner = _uuid(user_id)
        target = _uuid(connector_id)
        if owner is None or target is None:
            return _refusal(404, NOT_FOUND)
        now = self._clock()
        async with self._session_factory() as session:
            connector = await session.get(ConnectorConfig, target)
            if (
                connector is None
                or connector.user_id != owner
                or not connector.is_active
                or connector_type_key(connector.connector_type) not in PROVIDER_OF
            ):
                return _refusal(404, NOT_FOUND)
            cursor = (
                await session.execute(select(MailScanCursor).where(MailScanCursor.connector_id == target))
            ).scalar_one_or_none()
            values: dict[str, Any] = {"status": "paused" if paused else "active", "updated_at": now}
            if not paused:
                values.update(consecutive_errors=0, last_error=None, next_check_at=now)
            if cursor is None:
                session.add(
                    MailScanCursor(
                        id=uuid.uuid4(),
                        user_id=owner,
                        connector_id=target,
                        provider=PROVIDER_OF[connector_type_key(connector.connector_type)],
                        status=values["status"],
                        next_check_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                await session.execute(
                    update(MailScanCursor)
                    .where(MailScanCursor.id == cursor.id)
                    .values(**values)
                    .execution_options(synchronize_session=False)
                )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return _refusal(409, "This mailbox changed meanwhile. Try again.")
        # Read back in a fresh session: the one above may still hold the row
        # as it was before the UPDATE.
        async with self._session_factory() as session:
            cursor = (
                await session.execute(select(MailScanCursor).where(MailScanCursor.connector_id == target))
            ).scalar_one_or_none()
        await self._audit(
            owner,
            "mail_scan_paused" if paused else "mail_scan_resumed",
            {"connector_id": str(target), "source": "web"},
            endpoint=ROUTE_ACCOUNT,
        )
        return {"ok": True, "account": self._account_view(connector, cursor)}
