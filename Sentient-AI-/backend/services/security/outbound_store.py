"""The stores behind the outbound message checks (security S1): who Crawler
has sent to (``KnownRecipientStore``, keyed HMACs only), the owner's list of
the organisation's own domains (``OrganisationDomainStore``), a user's
sign-in address (``UserEmails``), one user's organisation domains for the
tool rules' sharing rule (``OrgDomains``), and the account export section.

Why it exists: "first time Crawler sends to ..." and "outside your
organisation" need facts only the database holds. Keeping every read and
write of S1's two tables in one module lets the call check, the executor's
post-send hook, the Security tab's routes and S9's rule B3 share one cache
and one invalidation hook, and keeps addresses themselves out of the
database: a recipient is stored as an HMAC of the user, the kind and the
normalised value under a key derived from ENCRYPTION_KEY
(services/security/outbound_recipients.py), so the database alone can
neither list the owner's correspondents nor test a guess. Rows made under
another key stop matching (every recipient is "first time" again, the
cautious direction) and are pruned.

What is held, and for how long: per user at most 5,000 address rows and
2,000 domain rows, least recently sent pruned first, rows unused for 730
days pruned, at most one pruning pass per user per hour (in process), so a
send costs one SELECT and one write. Forget-all from the Security tab; the
rows go with the user (ON DELETE CASCADE). The organisation's domains are
install policy every user may read, plaintext, at most 50.

Logs carry counts and exception type names only, never an address, a
domain or a fingerprint.

Connects to: models/known_recipient.py (the two tables),
services/security/outbound.py (the check and the service), S9's tool rules
(``OrgDomains.for_user``), api/routes/security_outbound.py,
api/routes/auth.py (the export), main.py.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Sequence

import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from models.known_recipient import KnownRecipient, OrganisationDomain
from models.user import User
from services.security.outbound_recipients import (
    Recipient,
    RecipientKind,
    hmac_key_id,
    normalize_address,
    organisation_domain_of,
    recipient_hmac,
    validate_organisation_domain,
)

logger = structlog.get_logger(__name__)

# What the Security tab says when the list is full (the route answers it as a 422).
DOMAIN_LIMIT_SENTENCE = "You can list at most {limit} domains."
NO_SUCH_DOMAIN = "No such domain."

# Users whose cached values are kept at most (each cache drops its least recently used).
_CACHE_USERS = 1000
# How many fingerprints one SELECT asks about (an IN list stays well inside every database's
# limit; 50 recipients give 100).
_HMACS_PER_QUERY = 500


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_uuid(value: Any) -> uuid.UUID:
    """*value* as a UUID (a user id from a call, a route or a test); ValueError otherwise."""
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value).strip())


def _affected(result: Any) -> int:
    """Rows a DELETE removed (a CursorResult's rowcount; 0 when the driver
    cannot say)."""
    return int(getattr(result, "rowcount", 0) or 0)


def _aware(moment: Optional[datetime]) -> Optional[datetime]:
    """SQLite hands back naive datetimes; they were written in UTC."""
    if moment is None or moment.tzinfo is not None:
        return moment
    return moment.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class KnownSet:
    """Of the recipients asked about, the normalised addresses and the
    domains Crawler has sent to before."""

    addresses: frozenset[str]
    domains: frozenset[str]


@dataclass(frozen=True)
class KnownSummary:
    """What the Security tab shows about a user's sent-to history: counts
    and the first time, never an address."""

    addresses: int
    domains: int
    since: Optional[datetime]


class KnownRecipientStore:
    """The sent-to history, one HMAC row per address and per domain.

    ``known`` is one SELECT of the fingerprints asked about under the current
    key; ``record`` upserts after a successful approved send (one retry when
    a concurrent first send to the same address inserted the row first), then
    prunes at most once an hour per user; ``summary`` and ``forget`` serve the
    Security tab."""

    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        *,
        clock: Callable[[], datetime] = _utcnow,
        address_cap: int = 5000,
        domain_cap: int = 2000,
        max_age_days: int = 730,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._address_cap = address_cap
        self._domain_cap = domain_cap
        self._max_age_days = max_age_days
        # When each user's rows were last pruned (this process only: pruning is housekeeping).
        self._pruned_at: OrderedDict[uuid.UUID, datetime] = OrderedDict()

    @staticmethod
    def _fingerprints(user_id: str, recipients: Sequence[Recipient]) -> dict[str, tuple[str, str]]:
        """hmac -> (kind, value) for every recipient's address and its domain."""
        wanted: dict[str, tuple[str, str]] = {}
        for recipient in recipients:
            pairs: tuple[tuple[RecipientKind, str], ...] = (
                ("address", recipient.address),
                ("domain", recipient.domain),
            )
            for kind, value in pairs:
                if value:
                    wanted[recipient_hmac(user_id, kind, value)] = (kind, value)
        return wanted

    async def known(self, user_id: str, recipients: Sequence[Recipient]) -> KnownSet:
        """Which of *recipients* (and their domains) Crawler has sent to, under
        the current key (rows made under another key never match)."""
        if not recipients:
            return KnownSet(addresses=frozenset(), domains=frozenset())
        uid = _as_uuid(user_id)
        key_id = hmac_key_id()
        wanted = self._fingerprints(str(uid), recipients)
        found: set[str] = set()
        hmacs = list(wanted)
        async with self._session_factory() as session:
            for start in range(0, len(hmacs), _HMACS_PER_QUERY):
                rows = await session.execute(
                    select(KnownRecipient.value_hmac).where(
                        KnownRecipient.user_id == uid,
                        KnownRecipient.key_id == key_id,
                        KnownRecipient.value_hmac.in_(hmacs[start : start + _HMACS_PER_QUERY]),
                    )
                )
                found.update(rows.scalars().all())
        addresses = frozenset(
            value for h, (kind, value) in wanted.items() if h in found and kind == "address"
        )
        domains = frozenset(
            value for h, (kind, value) in wanted.items() if h in found and kind == "domain"
        )
        return KnownSet(addresses=addresses, domains=domains)

    async def record(self, user_id: str, recipients: Sequence[Recipient]) -> None:
        """Remember a successful send's recipients: each normalised address and
        its domain, the user's own sign-in address skipped. Upsert: the rows
        that exist get a later last_sent_at and one more send, the rest are
        inserted; a concurrent first send that inserted a row first is retried
        once. Then the user's rows are pruned, at most once an hour."""
        uid = _as_uuid(user_id)
        if not recipients:
            return
        for attempt in range(2):
            try:
                await self._upsert(uid, recipients)
                break
            except IntegrityError:
                if attempt:
                    raise
                logger.info("known_recipients_upsert_retried")
        await self._maybe_prune(uid)

    async def _upsert(self, uid: uuid.UUID, recipients: Sequence[Recipient]) -> None:
        now = self._clock()
        key_id = hmac_key_id()
        async with self._session_factory() as session:
            own = await session.scalar(select(User.email).where(User.id == uid))
            own_address = normalize_address(own) if isinstance(own, str) else None
            others = [r for r in recipients if r.address != own_address]
            wanted = self._fingerprints(str(uid), others)
            if not wanted:
                return
            rows = await session.execute(
                select(KnownRecipient).where(
                    KnownRecipient.user_id == uid,
                    KnownRecipient.value_hmac.in_(list(wanted)),
                )
            )
            existing = {(row.kind, row.value_hmac): row for row in rows.scalars().all()}
            for value_hmac, (kind, _value) in wanted.items():
                row = existing.get((kind, value_hmac))
                if row is not None:
                    row.last_sent_at = now
                    row.send_count = (row.send_count or 0) + 1
                    row.key_id = key_id
                    continue
                session.add(
                    KnownRecipient(
                        id=uuid.uuid4(),
                        user_id=uid,
                        kind=kind,
                        value_hmac=value_hmac,
                        key_id=key_id,
                        first_sent_at=now,
                        last_sent_at=now,
                        send_count=1,
                    )
                )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                raise

    async def _maybe_prune(self, uid: uuid.UUID) -> None:
        now = self._clock()
        last = self._pruned_at.get(uid)
        if last is not None and now - last < timedelta(hours=1):
            return
        self._pruned_at[uid] = now
        self._pruned_at.move_to_end(uid)
        while len(self._pruned_at) > _CACHE_USERS:
            self._pruned_at.popitem(last=False)
        try:
            await self.prune(uid)
        except Exception as exc:  # housekeeping: the send is recorded either way
            logger.warning("known_recipients_prune_failed", error_type=type(exc).__name__)

    async def prune(self, user_id: Any) -> int:
        """Delete this user's rows made under another key, rows unused for
        max_age_days, and the least recently sent rows beyond each kind's cap.
        Returns how many went."""
        uid = _as_uuid(user_id)
        now = self._clock()
        key_id = hmac_key_id()
        removed = 0
        async with self._session_factory() as session:
            stale = await session.execute(
                delete(KnownRecipient).where(
                    KnownRecipient.user_id == uid,
                    (KnownRecipient.key_id != key_id)
                    | (KnownRecipient.last_sent_at < now - timedelta(days=self._max_age_days)),
                )
            )
            removed += _affected(stale)
            for kind, cap in (("address", self._address_cap), ("domain", self._domain_cap)):
                beyond = await session.execute(
                    select(KnownRecipient.id)
                    .where(KnownRecipient.user_id == uid, KnownRecipient.kind == kind)
                    .order_by(KnownRecipient.last_sent_at.desc(), KnownRecipient.id)
                    .offset(cap)
                )
                ids = list(beyond.scalars().all())
                for start in range(0, len(ids), _HMACS_PER_QUERY):
                    gone = await session.execute(
                        delete(KnownRecipient).where(
                            KnownRecipient.id.in_(ids[start : start + _HMACS_PER_QUERY])
                        )
                    )
                    removed += _affected(gone)
            await session.commit()
        if removed:
            logger.info("known_recipients_pruned", rows=removed)
        return removed

    async def summary(self, user_id: str) -> KnownSummary:
        """Counts for the Security tab (under the current key) and the first
        send they cover."""
        uid = _as_uuid(user_id)
        key_id = hmac_key_id()
        async with self._session_factory() as session:
            rows = await session.execute(
                select(
                    KnownRecipient.kind,
                    func.count(KnownRecipient.id),
                    func.min(KnownRecipient.first_sent_at),
                )
                .where(KnownRecipient.user_id == uid, KnownRecipient.key_id == key_id)
                .group_by(KnownRecipient.kind)
            )
            counts: dict[str, int] = {}
            since: Optional[datetime] = None
            for kind, count, earliest in rows.all():
                counts[kind] = int(count or 0)
                first = _aware(earliest)
                if first is not None and (since is None or first < since):
                    since = first
        return KnownSummary(
            addresses=counts.get("address", 0), domains=counts.get("domain", 0), since=since
        )

    async def forget(self, user_id: str) -> int:
        """Delete every one of this user's rows (any key); the rows removed."""
        uid = _as_uuid(user_id)
        async with self._session_factory() as session:
            result = await session.execute(
                delete(KnownRecipient).where(KnownRecipient.user_id == uid)
            )
            await session.commit()
        self._pruned_at.pop(uid, None)
        return _affected(result)


@dataclass(frozen=True)
class OrganisationDomainRow:
    """One domain the owner listed as the organisation's own."""

    id: str
    domain: str
    added_at: datetime


class DomainRefused(Exception):
    """A domain the owner may not add: *status* is 409 or 422 and the message
    is one plain sentence the page shows as it is."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class OrganisationDomainStore:
    """The install-wide list of the organisation's own domains (owner-edited).

    ``domains`` is cached for *ttl_s* and raises on a database error (each
    caller decides what "could not read" means for it). An add or a remove
    clears the cache here and in every ``OrgDomains`` built on this store."""

    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        *,
        ttl_s: float = 60.0,
        limit: int = 50,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._ttl_s = ttl_s
        self._limit = limit
        self._clock = clock
        self._cached: Optional[tuple[float, tuple[OrganisationDomainRow, ...]]] = None
        self._listeners: list[Callable[[], None]] = []
        self._lock = asyncio.Lock()

    @property
    def limit(self) -> int:
        return self._limit

    def on_change(self, listener: Callable[[], None]) -> None:
        """Call *listener* after every add or remove (OrgDomains' cache)."""
        self._listeners.append(listener)

    def invalidate(self) -> None:
        self._cached = None
        for listener in list(self._listeners):
            try:
                listener()
            except Exception as exc:  # a listener's bug must not undo the owner's edit
                logger.warning(
                    "organisation_domains_listener_failed", error_type=type(exc).__name__
                )

    async def domains(self) -> tuple[OrganisationDomainRow, ...]:
        """Every listed domain, oldest first (cached ttl_s)."""
        cached = self._cached
        if cached is not None and self._clock() < cached[0]:
            return cached[1]
        async with self._session_factory() as session:
            rows = await session.execute(
                select(OrganisationDomain).order_by(
                    OrganisationDomain.created_at, OrganisationDomain.domain
                )
            )
            found = tuple(
                OrganisationDomainRow(
                    id=str(row.id), domain=row.domain, added_at=_aware(row.created_at) or _utcnow()
                )
                for row in rows.scalars().all()
            )
        self._cached = (self._clock() + self._ttl_s, found)
        return found

    async def add(self, domain: str, *, added_by: str) -> OrganisationDomainRow:
        """Add one domain, validated and stored as a lower-case A-label.
        DomainRefused(422) for a bad one or a full list, DomainRefused(409)
        for one already listed."""
        try:
            stored = validate_organisation_domain(domain)
        except ValueError as refused:
            raise DomainRefused(422, str(refused)) from None
        async with self._lock:
            async with self._session_factory() as session:
                count = await session.scalar(select(func.count(OrganisationDomain.id)))
                listed = await session.scalar(
                    select(OrganisationDomain.id).where(OrganisationDomain.domain == stored)
                )
                if listed is not None:
                    raise DomainRefused(409, f"{stored} is already listed.")
                if int(count or 0) >= self._limit:
                    raise DomainRefused(422, DOMAIN_LIMIT_SENTENCE.format(limit=self._limit))
                row = OrganisationDomain(
                    id=uuid.uuid4(),
                    domain=stored,
                    added_by=_optional_uuid(added_by),
                    created_at=_utcnow(),
                )
                session.add(row)
                try:
                    await session.commit()
                except IntegrityError:
                    await session.rollback()
                    raise DomainRefused(409, f"{stored} is already listed.") from None
        self.invalidate()
        return OrganisationDomainRow(
            id=str(row.id), domain=stored, added_at=_aware(row.created_at) or _utcnow()
        )

    async def remove(self, domain_id: str) -> bool:
        """Remove one domain; False when there is no such row (an id that is
        not a UUID included)."""
        try:
            row_id = _as_uuid(domain_id)
        except ValueError:
            return False
        async with self._session_factory() as session:
            row = await session.get(OrganisationDomain, row_id)
            if row is None:
                return False
            await session.delete(row)
            await session.commit()
        self.invalidate()
        return True


def _optional_uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return _as_uuid(value)
    except (ValueError, TypeError, AttributeError):
        return None


class UserEmails:
    """User.email by id, cached (the sign-in address rarely changes). A
    database error raises (the check notes it and goes on); an unknown user
    or an id that is not a UUID answers None."""

    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        *,
        ttl_s: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._ttl_s = ttl_s
        self._clock = clock
        self._cache: OrderedDict[str, tuple[float, Optional[str]]] = OrderedDict()

    async def email(self, user_id: str) -> Optional[str]:
        """The user's sign-in address."""
        key = str(user_id)
        cached = self._cache.get(key)
        if cached is not None and self._clock() < cached[0]:
            self._cache.move_to_end(key)
            return cached[1]
        try:
            uid = _as_uuid(user_id)
        except ValueError:
            return None
        async with self._session_factory() as session:
            found = await session.scalar(select(User.email).where(User.id == uid))
        address = found if isinstance(found, str) and found else None
        self._cache[key] = (self._clock() + self._ttl_s, address)
        self._cache.move_to_end(key)
        while len(self._cache) > _CACHE_USERS:
            self._cache.popitem(last=False)
        return address


class OrgDomains:
    """The organisation domains of one user, for S9's rule B3 (scaffold A24,
    review INT-S2): the registrable domain of User.email when it is not a
    consumer mail domain, union every owner-listed domain (lower-case
    A-labels). Cached per user for ttl_s; an owner edit through the
    ``OrganisationDomainStore`` given as *domains* clears this cache too.

    An empty set means "no organisation known". A database error RAISES,
    never an empty set: S9 treats a raise as "could not read" and fails
    closed (review FEA-SF5)."""

    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        *,
        ttl_s: float = 60.0,
        domains: Optional[OrganisationDomainStore] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._ttl_s = ttl_s
        self._domains = domains
        self._clock = clock
        self._cache: OrderedDict[str, tuple[float, frozenset[str]]] = OrderedDict()
        if domains is not None:
            domains.on_change(self.invalidate)

    async def for_user(self, user_id: str) -> frozenset[str]:
        """Lower-case A-label domains of *user_id*'s organisation."""
        key = str(user_id)
        cached = self._cache.get(key)
        if cached is not None and self._clock() < cached[0]:
            self._cache.move_to_end(key)
            return cached[1]
        found: set[str] = set()
        try:
            uid: Optional[uuid.UUID] = _as_uuid(user_id)
        except ValueError:
            uid = None
        async with self._session_factory() as session:
            email = (
                await session.scalar(select(User.email).where(User.id == uid))
                if uid is not None
                else None
            )
            if self._domains is None:
                rows = await session.execute(select(OrganisationDomain.domain))
                found.update(domain for domain in rows.scalars().all() if domain)
        if self._domains is not None:
            found.update(row.domain for row in await self._domains.domains())
        own = organisation_domain_of(email) if isinstance(email, str) else None
        if own:
            found.add(own)
        value = frozenset(found)
        self._cache[key] = (self._clock() + self._ttl_s, value)
        self._cache.move_to_end(key)
        while len(self._cache) > _CACHE_USERS:
            self._cache.popitem(last=False)
        return value

    def invalidate(self) -> None:
        """Forget the cache (an owner edit of the domain list)."""
        self._cache.clear()


async def export_for_user(db: AsyncSession, user_id: uuid.UUID) -> list[dict[str, Any]]:
    """The account export's "known_recipients" section: everything held per
    row (kind, the keyed fingerprint, the key it was made under, first and
    last sent, count). Never an address: none is stored."""
    rows = await db.execute(
        select(KnownRecipient)
        .where(KnownRecipient.user_id == _as_uuid(user_id))
        .order_by(KnownRecipient.kind, KnownRecipient.first_sent_at, KnownRecipient.id)
    )
    return [
        {
            "kind": row.kind,
            "value_hmac": row.value_hmac,
            "key_id": row.key_id,
            "first_sent_at": (_aware(row.first_sent_at) or _utcnow()).isoformat(),
            "last_sent_at": (_aware(row.last_sent_at) or _utcnow()).isoformat(),
            "send_count": int(row.send_count or 0),
        }
        for row in rows.scalars().all()
    ]
