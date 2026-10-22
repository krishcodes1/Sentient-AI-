"""Every read and write of the breach monitor's two tables: the owners' watched
addresses (sealed, with each one's schedule and health) and the breaches already
seen for each address, which is the seen list that decides what is new.

Why it exists: the weekly sweeper, the owner's Check now and the Security page
routes all touch the same rows, and each rule here is what keeps the monitor
from alerting a breach twice, checking an address two workers both claimed, or
holding an address in plain text. Due rows are claimed with a conditional
UPDATE (``sweeper.claim``'s rule: whoever moves a row past "due" first owns it;
the new time is the lease). New breaches are found by diffing HIBP's answer
against the address's seen list (``unseen``), and each new finding is inserted
and committed on its own, so the unique (address_id, breach_name) index, not
the diff, has the last word: a concurrent check that inserted it first wins and
this call does not report it. Addresses are sealed with AES-GCM and looked up by
an HMAC digest (``services/breach/addresses.py``); nothing here logs an address,
and failures are stored as fixed codes, never vendor text.

The sign-in ("account") row follows ``User.email``: when its digest no longer
matches (the email changed, or ENCRYPTION_KEY did), it is resealed, its
findings are dropped and the next answer is a fresh baseline. Only admin
accounts have rows; housekeeping deletes the rows of an account that is no
longer an admin.
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import case, delete, func, select, update
from sqlalchemy.exc import IntegrityError

from models.breach_watch import ERROR_CODE_MAX_CHARS, BreachWatchAddress, BreachWatchFinding
from models.user import User
from services.breach.addresses import (
    MAX_ADDED_PER_OWNER,
    AddressRejected,
    address_digest,
    address_hint,
    normalize_address,
    open_address,
    seal_address,
)
from services.breach.hibp import Breach
from services.breach.messages import FAILURE_SENTENCES, failure_sentence
from services.connectors.base import clean_display_text

logger = structlog.get_logger(__name__)

# How often each address is looked up (the sweeper re-exports it).
CHECK_EVERY = timedelta(days=7)
# The seen list's cap per address: answers past it are neither stored nor alerted.
MAX_FINDINGS_PER_ADDRESS = 1000
# The overview lists at most this many findings (unacknowledged first, newest first).
MAX_OVERVIEW_FINDINGS = 500

SOURCE_ACCOUNT = "account"
SOURCE_ADDED = "added"
STATUS_ACTIVE = "active"
STATUS_PAUSED = "paused"
STATUS_ERROR = "error"
KEY_REFUSED = "key_refused"

ALREADY_WATCHED = "That address is already watched."
SIGN_IN_WATCHED = "That is your sign-in address; it is already watched."
LIMIT_MESSAGE = f"You can watch at most {MAX_ADDED_PER_OWNER} addresses."
SIGN_IN_NOT_REMOVABLE = (
    "Your sign-in address is always watched while breach monitoring is on. Pause it instead."
)
PAUSED_MESSAGE = "This address is paused. Resume it first."
NOT_FOUND_MESSAGE = "No such address."
FINDING_NOT_FOUND_MESSAGE = "No such breach."


class NotFound(LookupError):
    """Not this owner's row (also for another owner's id)."""


class Conflict(ValueError):
    """The request cannot be done in the row's current state; the message is for the owner."""


class LimitReached(ValueError):
    """The owner already watches the most typed addresses; the message is for the owner."""


class CheckTooSoon(Exception):
    """The address was checked moments ago, or the pacer is busy. ``retry_after_s`` is the
    wait in whole seconds; the message is for the owner. (The sweeper module re-exports it.)"""

    def __init__(self, retry_after_s: int, message: Optional[str] = None) -> None:
        self.retry_after_s = max(1, int(retry_after_s))
        super().__init__(
            message or f"Checked moments ago. Try again in {self.retry_after_s} seconds."
        )


@dataclass(frozen=True)
class Claim:
    id: uuid.UUID
    user_id: uuid.UUID
    source: str
    sealed: bytes
    baseline_at: Optional[datetime]
    consecutive_errors: int
    last_error_code: Optional[str]


@dataclass(frozen=True)
class Recorded:
    new: tuple[Breach, ...]  # inserted by this call only (unique index won)
    new_ids: tuple[uuid.UUID, ...]
    baseline: bool  # this was the address's first answer
    total: int  # breaches known for the address after this answer


@dataclass(frozen=True)
class Failed:
    failures: int
    stopped: bool  # this call moved the address to "error"
    # The row's status after this call ("active", "paused", "error"), or None when nothing
    # was recorded (the row was removed or resealed meanwhile). Only an "active" row is
    # looked up again on its own, so only then may the owner be told when Crawler retries.
    status: Optional[str] = None


def unseen(breaches: Sequence[Breach], seen: Collection[str]) -> list[Breach]:
    """The new-breach diff: the breaches of *breaches* whose Name is not in the seen list
    *seen*, in answer order, each Name once."""
    fresh: list[Breach] = []
    names = set(seen)
    for breach in breaches:
        if breach.name in names:
            continue
        names.add(breach.name)
        fresh.append(breach)
    return fresh


def _aware(moment: Optional[datetime]) -> Optional[datetime]:
    """*moment* as an aware UTC datetime (SQLite hands timestamps back naive)."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _iso(moment: Optional[datetime]) -> Optional[str]:
    aware = _aware(moment)
    return aware.isoformat().replace("+00:00", "Z") if aware is not None else None


def _iso_date(day: Optional[date]) -> Optional[str]:
    return day.isoformat() if day is not None else None


def _address_dict(row: BreachWatchAddress, new_count: int) -> dict[str, Any]:
    """The Address JSON shape (S6 4.6). The address is opened here, for the owner only."""
    opened = open_address(row.address_sealed)
    readable = opened is not None
    code = row.last_error_code
    # A stopped or paused row is not looked up on its own: no "tries again" promise.
    last_error = failure_sentence(code, retrying=row.status == STATUS_ACTIVE)
    if not readable:
        code = code or "unreadable"
        last_error = FAILURE_SENTENCES["unreadable"]
    return {
        "id": str(row.id),
        "address": opened,
        "hint": address_hint(opened) if opened is not None else "",
        "source": row.source,
        "status": row.status,
        "readable": readable,
        "last_checked_at": _iso(row.last_checked_at),
        "next_check_at": _iso(row.next_check_at),
        "baseline_at": _iso(row.baseline_at),
        "breach_count": int(row.breach_count or 0),
        "new_count": int(new_count),
        "last_error_code": code,
        "last_error": last_error,
    }


def _finding_dict(row: BreachWatchFinding) -> dict[str, Any]:
    """The Finding JSON shape (S6 4.6)."""
    return {
        "id": str(row.id),
        "address_id": str(row.address_id),
        "name": row.breach_name,
        "title": row.title,
        "domain": row.domain,
        "breach_date": _iso_date(row.breach_date),
        "added_at": _iso(row.added_at),
        "pwn_count": row.pwn_count,
        "data_classes": [str(item) for item in (row.data_classes or [])],
        "verified": bool(row.verified),
        "sensitive": bool(row.sensitive),
        "fabricated": bool(row.fabricated),
        "spam_list": bool(row.spam_list),
        "baseline": bool(row.baseline),
        "first_seen_at": _iso(row.first_seen_at),
        "alerted_at": _iso(row.alerted_at),
        "acknowledged_at": _iso(row.acknowledged_at),
    }


def _claim_of(row: Any) -> Claim:
    return Claim(
        id=row.id,
        user_id=row.user_id,
        source=row.source,
        sealed=row.address_sealed,
        baseline_at=_aware(row.baseline_at),
        consecutive_errors=int(row.consecutive_errors or 0),
        last_error_code=row.last_error_code,
    )


def _sign_in_note(email: str) -> str:
    shown = clean_display_text(email, 120) or "your sign-in address"
    return (
        f"Your sign-in address ({shown}) is not a mailbox address Have I Been Pwned can look "
        "up. Add the addresses you use below."
    )


class BreachStore:
    """The only reader and writer of ``breach_watch_addresses`` and ``breach_watch_findings``.
    *clock* is a test seam."""

    def __init__(
        self,
        session_factory: Any,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    # -- the sign-in row and housekeeping ------------------------------------

    async def ensure_account_row(self, user_id: uuid.UUID) -> Optional[str]:
        """Create or reseal this admin's sign-in row from User.email (reset baseline and drop its
        findings when the digest changed). Returns None when fine, or the owner-facing note
        when User.email cannot be watched (e.g. 'admin@localhost'). Does nothing for an
        account that is not an admin."""
        now = self._clock()
        async with self._session_factory() as session:
            user = await session.get(User, user_id)
            if user is None or not user.is_admin:
                return None
            rows = list(
                (
                    await session.execute(
                        select(BreachWatchAddress).where(BreachWatchAddress.user_id == user_id)
                    )
                ).scalars()
            )
            account = next((row for row in rows if row.source == SOURCE_ACCOUNT), None)
            try:
                normalized = normalize_address(user.email)
            except AddressRejected:
                if account is not None:
                    # The sign-in address changed to one HIBP cannot look up: stop watching it.
                    await self._delete_row(session, account)
                    await session.commit()
                return _sign_in_note(user.email)
            digest = address_digest(normalized)
            if account is not None and account.address_digest == digest:
                return None
            same = next((row for row in rows if row.address_digest == digest), None)
            if same is not None:
                # The owner had typed in what is now their sign-in address: that row (and its
                # seen list) becomes the sign-in row, and the old sign-in row goes.
                if account is not None:
                    await self._delete_row(session, account)
                    await session.flush()
                same.source = SOURCE_ACCOUNT
                same.updated_at = now
            elif account is not None:
                # The email (or ENCRYPTION_KEY) changed: a new address, a fresh baseline.
                await session.execute(
                    delete(BreachWatchFinding)
                    .where(BreachWatchFinding.address_id == account.id)
                    .execution_options(synchronize_session=False)
                )
                account.address_digest = digest
                account.address_sealed = seal_address(normalized)
                account.baseline_at = None
                account.last_checked_at = None
                account.breach_count = 0
                account.consecutive_errors = 0
                account.last_error_code = None
                if account.status != STATUS_PAUSED:
                    account.status = STATUS_ACTIVE
                account.next_check_at = now
                account.updated_at = now
            else:
                session.add(
                    BreachWatchAddress(
                        id=uuid.uuid4(),
                        user_id=user_id,
                        source=SOURCE_ACCOUNT,
                        address_digest=digest,
                        address_sealed=seal_address(normalized),
                        status=STATUS_ACTIVE,
                        next_check_at=now,
                        breach_count=0,
                        consecutive_errors=0,
                        created_at=now,
                        updated_at=now,
                    )
                )
            try:
                await session.commit()
            except IntegrityError:
                # A concurrent call made the row first; it is there either way.
                await session.rollback()
        return None

    @staticmethod
    async def _delete_row(session: Any, row: BreachWatchAddress) -> int:
        """Delete an address row and its findings; returns findings removed. The findings go
        first and explicitly, not only through the foreign key's cascade."""
        result = await session.execute(
            delete(BreachWatchFinding)
            .where(BreachWatchFinding.address_id == row.id)
            .execution_options(synchronize_session=False)
        )
        await session.delete(row)
        return int(getattr(result, "rowcount", 0) or 0)

    async def housekeep(self) -> int:
        """ensure_account_row for every active admin; delete every row whose user is not an
        admin. Returns rows deleted. An inactive admin is skipped, not deleted."""
        async with self._session_factory() as session:
            admins = list(
                (
                    await session.execute(
                        select(User.id).where(User.is_admin.is_(True), User.is_active.is_(True))
                    )
                ).scalars()
            )
            not_admins = select(User.id).where(User.is_admin.is_(False))
            await session.execute(
                delete(BreachWatchFinding)
                .where(BreachWatchFinding.user_id.in_(not_admins))
                .execution_options(synchronize_session=False)
            )
            result = await session.execute(
                delete(BreachWatchAddress)
                .where(BreachWatchAddress.user_id.in_(not_admins))
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        deleted = int(getattr(result, "rowcount", 0) or 0)
        for admin_id in admins:
            await self.ensure_account_row(admin_id)
        if deleted:
            logger.info("breach_watch_rows_pruned", rows=deleted)
        return deleted

    # -- the owner's view and edits -----------------------------------------

    async def _new_counts(self, session: Any, user_id: uuid.UUID) -> dict[uuid.UUID, int]:
        rows = await session.execute(
            select(BreachWatchFinding.address_id, func.count())
            .where(
                BreachWatchFinding.user_id == user_id,
                BreachWatchFinding.acknowledged_at.is_(None),
            )
            .group_by(BreachWatchFinding.address_id)
        )
        return {address_id: int(count) for address_id, count in rows.all()}

    async def overview(self, user_id: uuid.UUID) -> dict[str, Any]:
        """{'addresses': [...], 'findings': [...]} as the JSON shapes in 4.6 (addresses: the
        sign-in row first, then by when they were added; findings unacknowledged first,
        newest first, at most 500)."""
        async with self._session_factory() as session:
            addresses = list(
                (
                    await session.execute(
                        select(BreachWatchAddress)
                        .where(BreachWatchAddress.user_id == user_id)
                        .order_by(
                            case((BreachWatchAddress.source == SOURCE_ACCOUNT, 0), else_=1),
                            BreachWatchAddress.created_at,
                            BreachWatchAddress.id,
                        )
                    )
                ).scalars()
            )
            counts = await self._new_counts(session, user_id)
            findings = list(
                (
                    await session.execute(
                        select(BreachWatchFinding)
                        .where(BreachWatchFinding.user_id == user_id)
                        .order_by(
                            case((BreachWatchFinding.acknowledged_at.is_(None), 0), else_=1),
                            BreachWatchFinding.first_seen_at.desc(),
                            BreachWatchFinding.breach_date.desc(),
                            BreachWatchFinding.breach_name,
                        )
                        .limit(MAX_OVERVIEW_FINDINGS)
                    )
                ).scalars()
            )
        return {
            "addresses": [_address_dict(row, counts.get(row.id, 0)) for row in addresses],
            "findings": [_finding_dict(row) for row in findings],
        }

    async def _owned(
        self, session: Any, user_id: uuid.UUID, address_id: uuid.UUID
    ) -> BreachWatchAddress:
        row = await session.get(BreachWatchAddress, address_id)
        if row is None or row.user_id != user_id:
            raise NotFound(NOT_FOUND_MESSAGE)
        return row

    async def add(self, user_id: uuid.UUID, address: str) -> dict[str, Any]:
        """Normalise (AddressRejected), refuse the sign-in address and duplicates (Conflict) and the
        11th typed address (LimitReached), insert with next_check_at=now. Returns the row dict."""
        normalized = normalize_address(address)
        digest = address_digest(normalized)
        now = self._clock()
        async with self._session_factory() as session:
            rows = list(
                (
                    await session.execute(
                        select(BreachWatchAddress).where(BreachWatchAddress.user_id == user_id)
                    )
                ).scalars()
            )
            existing = next((row for row in rows if row.address_digest == digest), None)
            if existing is not None:
                raise Conflict(
                    SIGN_IN_WATCHED if existing.source == SOURCE_ACCOUNT else ALREADY_WATCHED
                )
            user = await session.get(User, user_id)
            if user is not None:
                try:
                    if normalize_address(user.email) == normalized:
                        raise Conflict(SIGN_IN_WATCHED)
                except AddressRejected:
                    pass
            if await self._added_count(session, user_id) >= MAX_ADDED_PER_OWNER:
                raise LimitReached(LIMIT_MESSAGE)
            row = BreachWatchAddress(
                id=uuid.uuid4(),
                user_id=user_id,
                source=SOURCE_ADDED,
                address_digest=digest,
                address_sealed=seal_address(normalized),
                status=STATUS_ACTIVE,
                next_check_at=now,
                breach_count=0,
                consecutive_errors=0,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                raise Conflict(ALREADY_WATCHED)
            # Two adds racing past the count above could both insert. Counting again after
            # the commit takes this one back when the owner is now over the cap, so the
            # limit holds whatever the interleaving (each racer only ever removes itself).
            if await self._added_count(session, user_id) > MAX_ADDED_PER_OWNER:
                await session.execute(
                    delete(BreachWatchAddress)
                    .where(BreachWatchAddress.id == row.id)
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
                raise LimitReached(LIMIT_MESSAGE)
            return _address_dict(row, 0)

    @staticmethod
    async def _added_count(session: Any, user_id: uuid.UUID) -> int:
        """How many typed ("added") addresses this owner watches now."""
        return int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(BreachWatchAddress)
                    .where(
                        BreachWatchAddress.user_id == user_id,
                        BreachWatchAddress.source == SOURCE_ADDED,
                    )
                )
            ).scalar_one()
        )

    async def remove(self, user_id: uuid.UUID, address_id: uuid.UUID) -> int:
        """Delete a typed address and its findings (returns findings removed); Conflict for the
        sign-in row ('Pause it instead')."""
        async with self._session_factory() as session:
            row = await self._owned(session, user_id, address_id)
            if row.source == SOURCE_ACCOUNT:
                raise Conflict(SIGN_IN_NOT_REMOVABLE)
            removed = await self._delete_row(session, row)
            await session.commit()
        return removed

    async def set_paused(
        self, user_id: uuid.UUID, address_id: uuid.UUID, paused: bool
    ) -> dict[str, Any]:
        """Pause (no lookups) or resume (status active, consecutive_errors 0, next_check_at now).
        Resuming an address that is already active changes nothing (no extra lookup)."""
        now = self._clock()
        async with self._session_factory() as session:
            row = await self._owned(session, user_id, address_id)
            if paused and row.status != STATUS_PAUSED:
                row.status = STATUS_PAUSED
                row.updated_at = now
            elif not paused and row.status != STATUS_ACTIVE:
                row.status = STATUS_ACTIVE
                row.consecutive_errors = 0
                row.next_check_at = now
                row.updated_at = now
            await session.commit()
            counts = await self._new_counts(session, user_id)
            return _address_dict(row, counts.get(row.id, 0))

    async def acknowledge(self, user_id: uuid.UUID, finding_id: uuid.UUID) -> dict[str, Any]:
        """Mark one of this owner's findings as handled (UI state only); NotFound otherwise."""
        now = self._clock()
        async with self._session_factory() as session:
            row = await session.get(BreachWatchFinding, finding_id)
            if row is None or row.user_id != user_id:
                raise NotFound(FINDING_NOT_FOUND_MESSAGE)
            if row.acknowledged_at is None:
                row.acknowledged_at = now
                await session.commit()
            return _finding_dict(row)

    async def acknowledge_all(self, user_id: uuid.UUID) -> int:
        """Mark every unhandled finding of this owner as handled. Returns how many."""
        now = self._clock()
        async with self._session_factory() as session:
            result = await session.execute(
                update(BreachWatchFinding)
                .where(
                    BreachWatchFinding.user_id == user_id,
                    BreachWatchFinding.acknowledged_at.is_(None),
                )
                .values(acknowledged_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)

    # -- claims ---------------------------------------------------------------

    async def claim_due(self, now: datetime, limit: int, lease: timedelta) -> list[Claim]:
        """Active rows of active admins with next_check_at <= now, soonest first; each won by a
        conditional UPDATE that moves next_check_at to now + lease (a crash mid-check is
        retried after the lease)."""
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        BreachWatchAddress.id,
                        BreachWatchAddress.user_id,
                        BreachWatchAddress.source,
                        BreachWatchAddress.address_sealed,
                        BreachWatchAddress.baseline_at,
                        BreachWatchAddress.consecutive_errors,
                        BreachWatchAddress.last_error_code,
                    )
                    .join(User, User.id == BreachWatchAddress.user_id)
                    .where(
                        BreachWatchAddress.status == STATUS_ACTIVE,
                        BreachWatchAddress.next_check_at <= now,
                        User.is_active.is_(True),
                        User.is_admin.is_(True),
                    )
                    .order_by(BreachWatchAddress.next_check_at, BreachWatchAddress.id)
                    .limit(limit)
                )
            ).all()
            claims: list[Claim] = []
            for row in rows:
                result = await session.execute(
                    update(BreachWatchAddress)
                    .where(
                        BreachWatchAddress.id == row.id,
                        BreachWatchAddress.status == STATUS_ACTIVE,
                        BreachWatchAddress.next_check_at <= now,
                    )
                    .values(next_check_at=now + lease)
                    .execution_options(synchronize_session=False)
                )
                if getattr(result, "rowcount", 0) == 1:
                    claims.append(_claim_of(row))
            await session.commit()
        return claims

    async def claim_one(
        self,
        user_id: uuid.UUID,
        address_id: uuid.UUID,
        now: datetime,
        cooldown: timedelta,
        lease: timedelta,
    ) -> Claim:
        """For Check now: NotFound, Conflict('This address is paused. Resume it first.'), or
        CheckTooSoon when last_checked_at is within *cooldown*. A row in "error" may be checked
        (a successful answer makes it active again)."""
        async with self._session_factory() as session:
            row = await self._owned(session, user_id, address_id)
            if row.status == STATUS_PAUSED:
                raise Conflict(PAUSED_MESSAGE)
            last = _aware(row.last_checked_at)
            if last is not None and now - last < cooldown:
                raise CheckTooSoon(math.ceil((cooldown - (now - last)).total_seconds()))
            claim = _claim_of(row)
            result = await session.execute(
                update(BreachWatchAddress)
                .where(
                    BreachWatchAddress.id == address_id,
                    BreachWatchAddress.user_id == user_id,
                    BreachWatchAddress.status != STATUS_PAUSED,
                )
                .values(next_check_at=now + lease)
                .execution_options(synchronize_session=False)
            )
            if getattr(result, "rowcount", 0) != 1:
                raise Conflict(PAUSED_MESSAGE)
            await session.commit()
        return claim

    # -- results --------------------------------------------------------------

    async def record_result(self, claim: Claim, breaches: list[Breach], now: datetime) -> Recorded:
        """Insert each unseen breach on its own (the unique index is the dedupe guard: an
        IntegrityError means a concurrent check saw it first). Set baseline_at (if NULL),
        last_checked_at, next_check_at = now + CHECK_EVERY, consecutive_errors 0,
        last_error_code NULL, status active (a paused row stays paused), breach_count,
        updated_at. An answer for a row that was removed or resealed meanwhile records
        nothing."""
        async with self._session_factory() as session:
            row = await session.get(BreachWatchAddress, claim.id)
            if row is None or row.address_sealed != claim.sealed:
                return Recorded(new=(), new_ids=(), baseline=False, total=0)
            baseline = row.baseline_at is None
            seen = set(
                (
                    await session.execute(
                        select(BreachWatchFinding.breach_name).where(
                            BreachWatchFinding.address_id == claim.id
                        )
                    )
                ).scalars()
            )
            fresh = unseen(breaches, seen)
            room = max(0, MAX_FINDINGS_PER_ADDRESS - len(seen))
            if len(fresh) > room:
                logger.warning(
                    "breach_findings_capped",
                    address_id=str(claim.id),
                    dropped=len(fresh) - room,
                )
                fresh = fresh[:room]
            inserted: list[Breach] = []
            ids: list[uuid.UUID] = []
            for breach in fresh:
                finding_id = uuid.uuid4()
                session.add(
                    BreachWatchFinding(
                        id=finding_id,
                        address_id=claim.id,
                        user_id=claim.user_id,
                        breach_name=breach.name,
                        title=breach.title,
                        domain=breach.domain,
                        breach_date=breach.breach_date,
                        added_at=breach.added_at,
                        pwn_count=breach.pwn_count,
                        data_classes=list(breach.data_classes),
                        verified=breach.verified,
                        sensitive=breach.sensitive,
                        fabricated=breach.fabricated,
                        spam_list=breach.spam_list,
                        baseline=baseline,
                        first_seen_at=now,
                    )
                )
                try:
                    await session.commit()
                except IntegrityError:
                    # Already seen (a concurrent check won), or the address was removed.
                    await session.rollback()
                    continue
                inserted.append(breach)
                ids.append(finding_id)
            total = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(BreachWatchFinding)
                        .where(BreachWatchFinding.address_id == claim.id)
                    )
                ).scalar_one()
            )
            await session.execute(
                update(BreachWatchAddress)
                .where(BreachWatchAddress.id == claim.id)
                .values(
                    baseline_at=func.coalesce(BreachWatchAddress.baseline_at, now),
                    last_checked_at=now,
                    next_check_at=now + CHECK_EVERY,
                    consecutive_errors=0,
                    last_error_code=None,
                    status=case(
                        (BreachWatchAddress.status == STATUS_PAUSED, STATUS_PAUSED),
                        else_=STATUS_ACTIVE,
                    ),
                    breach_count=total,
                    updated_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        return Recorded(new=tuple(inserted), new_ids=tuple(ids), baseline=baseline, total=total)

    async def mark_alerted(self, finding_ids: Sequence[uuid.UUID], now: datetime) -> None:
        """The owner was told about these findings (a channel delivered the alert, or a Check
        now answer showed them)."""
        if not finding_ids:
            return
        async with self._session_factory() as session:
            await session.execute(
                update(BreachWatchFinding)
                .where(
                    BreachWatchFinding.id.in_(list(finding_ids)),
                    BreachWatchFinding.alerted_at.is_(None),
                )
                .values(alerted_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def record_failure(
        self,
        claim: Claim,
        code: str,
        now: datetime,
        *,
        counts: bool,
        retry_at: datetime,
        limit: int,
    ) -> Failed:
        """Store the code; when *counts*, add one to consecutive_errors and set status error at
        *limit*; next_check_at = retry_at. ``stopped`` is True only for the call that moved the
        row to "error", so the owner hears about it once; ``status`` is the row's status
        afterwards (a row already in "error", or paused mid-check, stays so and is not
        retried on its own). Nothing is ever recorded as "no breaches"."""
        async with self._session_factory() as session:
            row = await session.get(BreachWatchAddress, claim.id)
            if row is None or row.address_sealed != claim.sealed:
                return Failed(failures=0, stopped=False, status=None)
            failures = int(row.consecutive_errors or 0) + (1 if counts else 0)
            stopped = (
                counts and failures >= limit and row.status not in (STATUS_ERROR, STATUS_PAUSED)
            )
            row.last_error_code = code[:ERROR_CODE_MAX_CHARS]
            row.next_check_at = retry_at
            row.updated_at = now
            if counts:
                row.consecutive_errors = failures
            if stopped:
                row.status = STATUS_ERROR
            status = str(row.status)
            await session.commit()
        return Failed(failures=failures, stopped=stopped, status=status)

    async def defer_for_key(self, now: datetime, retry_at: datetime) -> list[uuid.UUID]:
        """Every active row of an active admin (the rows claim_due would look up):
        last_error_code='key_refused', next_check_at=retry_at. Returns the admins for whom none
        of their rows had that code before (they get the one message). The rows of a
        deactivated admin (kept on purpose) or of an account no longer an admin (kept until
        the next housekeeping) are neither held nor returned: nothing is looked up for them,
        and the message is for the owners only."""
        owners_now = select(User.id).where(User.is_admin.is_(True), User.is_active.is_(True))
        watched = (
            BreachWatchAddress.status == STATUS_ACTIVE,
            BreachWatchAddress.user_id.in_(owners_now),
        )
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(BreachWatchAddress.user_id, BreachWatchAddress.last_error_code).where(
                        *watched
                    )
                )
            ).all()
            told: set[uuid.UUID] = {user for user, code in rows if code == KEY_REFUSED}
            owners = {user for user, _ in rows}
            await session.execute(
                update(BreachWatchAddress)
                .where(*watched)
                .values(last_error_code=KEY_REFUSED, next_check_at=retry_at, updated_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        return sorted(owners - told, key=str)

    async def release_claim(self, claim: Claim, now: datetime) -> None:
        """The claimed row is due again now, with nothing recorded: its lookup was refused for
        a key that was replaced while the lookup was out, so the answer says nothing about the
        key now saved. Only a row still leased (next_check_at after *now*) moves."""
        async with self._session_factory() as session:
            await session.execute(
                update(BreachWatchAddress)
                .where(
                    BreachWatchAddress.id == claim.id,
                    BreachWatchAddress.next_check_at > now,
                )
                .values(next_check_at=now, updated_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()

    async def release_key_hold(self, now: datetime) -> int:
        """Rows held by key_refused become due now (after the key or a switch changed). The code
        stays, so a still-bad key does not message again."""
        async with self._session_factory() as session:
            result = await session.execute(
                update(BreachWatchAddress)
                .where(
                    BreachWatchAddress.status == STATUS_ACTIVE,
                    BreachWatchAddress.last_error_code == KEY_REFUSED,
                    BreachWatchAddress.next_check_at > now,
                )
                .values(next_check_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)


async def export_for_user(session: Any, user_id: uuid.UUID) -> list[dict[str, Any]]:
    """The account export's 'breach_watch' section: each watched address (opened; null when it
    no longer decrypts), its source, status, created_at and last_checked_at, with its findings
    (name, title, domain, breach_date, data_classes, first_seen_at, acknowledged_at)."""
    addresses = list(
        (
            await session.execute(
                select(BreachWatchAddress)
                .where(BreachWatchAddress.user_id == user_id)
                .order_by(
                    case((BreachWatchAddress.source == SOURCE_ACCOUNT, 0), else_=1),
                    BreachWatchAddress.created_at,
                    BreachWatchAddress.id,
                )
            )
        ).scalars()
    )
    if not addresses:
        return []
    findings = list(
        (
            await session.execute(
                select(BreachWatchFinding)
                .where(BreachWatchFinding.user_id == user_id)
                .order_by(BreachWatchFinding.first_seen_at, BreachWatchFinding.breach_name)
            )
        ).scalars()
    )
    by_address: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for finding in findings:
        by_address.setdefault(finding.address_id, []).append(
            {
                "name": finding.breach_name,
                "title": finding.title,
                "domain": finding.domain,
                "breach_date": _iso_date(finding.breach_date),
                "data_classes": [str(item) for item in (finding.data_classes or [])],
                "first_seen_at": _iso(finding.first_seen_at),
                "acknowledged_at": _iso(finding.acknowledged_at),
            }
        )
    return [
        {
            "address": open_address(row.address_sealed),
            "source": row.source,
            "status": row.status,
            "created_at": _iso(row.created_at),
            "last_checked_at": _iso(row.last_checked_at),
            "findings": by_address.get(row.id, []),
        }
        for row in addresses
    ]
