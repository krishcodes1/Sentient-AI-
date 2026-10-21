"""Reads and writes the file-reputation tables: the install-wide VirusTotal verdict cache with
its lifetimes, the request log the quota counts, retention, and the encryption of a check's
source reference and the keyed hash of its mail message.

Why it exists: one module owns every query against ``file_reputation_verdicts``,
``file_reputation_checks`` and ``file_reputation_calls`` (models/file_reputation.py), so the rules
that make the tables safe are written once:

- The cache keeps an answer for as long as it is likely to hold: a flagged file (malicious or
  suspicious) 7 days, a file with no detections 24 hours (a new detection is more likely to
  appear), a file VirusTotal does not know 1 hour (someone may upload it). Failures, timeouts and
  refusals are never cached; only VirusTotal's four answers are.
- The request log is written before each request (``record_call``) and counted over sliding
  windows (``call_counts``), so the limits hold across restarts. It keeps 48 hours of rows.
- A check's ``source_ref`` (a Telegram ``file_id``, or a mail tool, message id and attachment id)
  lets anyone holding the bot token or the connector credentials pull the file, so it is
  encrypted with the connector credentials' AES-GCM key. A mail row's ``source_key`` is an HMAC
  of ``"<family>:<message_id>"`` under a key derived from ``ENCRYPTION_KEY``, enough for "is this
  the message with the flagged attachment?" without storing the message id.

- A person's check row (one per user and file) is theirs alone: every read and write of it is
  keyed by the user id as well as the row id or fingerprint, so one user never sees, changes or
  forgets another's. Its verdict columns are a snapshot (the cache expires; the history must
  not), and a later attempt that could not ask VirusTotal never erases a verdict already there.
  The sweep claims due rows with a conditional UPDATE (``claimed_until``), so two sweeps never
  work on one row.

Connects to: models/file_reputation.py, models/user_file.py (an upload's fingerprint and the
call check's join), core.security (``encrypt_credentials``),
services/file_reputation/virustotal.py (``VtFileReport``, ``verdict_of``).

Used by: services/file_reputation/quota.py (as its ``CallLog``), service.py, call_check.py and
sweeper.py.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import structlog
from sqlalchemy import and_, case, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from core.config import settings
from core.security import decrypt_credentials, encrypt_credentials
from models.file_reputation import FileReputationCall, FileReputationCheck, FileReputationVerdict
from models.user_file import UserFile
from services.file_reputation.byte_sink import is_sha256
from services.file_reputation.quota import DAY, MINUTE, CallCounts, CallKind, Priority
from services.file_reputation.verdicts import FLAGGED_VERDICTS, LOOKUP_VERDICTS, FileVerdict
from services.file_reputation.virustotal import VtFileReport, verdict_from_report, verdict_of

logger = structlog.get_logger(__name__)

# How long each VirusTotal answer is reused (S10 3.1, 4.4).
VERDICT_TTL: Mapping[str, timedelta] = {
    "malicious": timedelta(days=7),
    "suspicious": timedelta(days=7),
    "no_detections": timedelta(hours=24),
    "unknown": timedelta(hours=1),
}
# A person's check row lasts 30 days after its last sighting, like an upload.
CHECK_RETENTION = timedelta(days=30)
# The request log only needs the last day; two days leave room for a slow sweep.
CALL_RETENTION = timedelta(hours=48)

ORIGINS: frozenset[str] = frozenset({"lookup", "analysis"})

# Where a check's file came from (S10 3.2): the Security page, web chat, Telegram, Slack, a
# Gmail or Outlook attachment, a bare fingerprint from the model, or S3's scam check.
SOURCES: frozenset[str] = frozenset(
    {"page", "web", "telegram", "slack", "gmail", "outlook", "hash", "scam"}
)
# A check's states: waiting for a lookup slot, answered, not looked up (with a reason), waiting
# for the owner to approve an upload card, or being scanned after an upload.
STATES: frozenset[str] = frozenset(
    {"queued", "checked", "not_checked", "upload_pending", "analysing"}
)
# States a lookup answer must not end: a pending card or a running scan keeps its row's state
# while VirusTotal still does not know the file.
_UPLOAD_STATES: frozenset[str] = frozenset({"upload_pending", "analysing"})
# The display name a row gets when nobody named the file (a bare fingerprint).
DEFAULT_NAME = "file"

_SOURCE_KEY_DOMAIN = b"sentientai.file_reputation.source.v1:"
# The longest connector id (a message, attachment or Telegram file id) the file checks keep.
MAX_ID_CHARS = 512
_SOURCE_REF_MAX_ITEMS = 8
_SOURCE_REF_MAX_CHARS = 1024
_NAME_CHARS = 255
_MEDIA_TYPE_CHARS = 100
_REASON_CHARS = 32
_ACTION_ID_CHARS = 36
_ANALYSIS_ID_CHARS = 128
# The most rows one listing, claim or join reads.
_MAX_LIST = 100
_MAX_FILE_IDS = 20


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    # SQLite hands timestamps back without a zone; every stored time is UTC.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _as_uuid(value: Optional[str]) -> Optional[uuid.UUID]:
    if not value:
        return None
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


def verdict_ttl(verdict: str) -> timedelta:
    """How long a cached *verdict* is reused: 7 days flagged, 24 h no detections, 1 h unknown.
    ``ValueError`` for anything else (not_checked and pending are never cached)."""
    try:
        return VERDICT_TTL[verdict]
    except KeyError:
        raise ValueError("only VirusTotal's four answers are cached") from None


def verdict_expires_at(verdict: str, fetched_at: datetime) -> datetime:
    """When a *verdict* fetched at *fetched_at* stops being reused."""
    return _as_utc(fetched_at) + verdict_ttl(verdict)


def check_expires_at(last_seen: datetime) -> datetime:
    """When a person's check row is purged: 30 days after its last sighting."""
    return _as_utc(last_seen) + CHECK_RETENTION


# -- source references ----------------------------------------------------------------------


def _source_hmac_key() -> bytes:
    return hashlib.sha256(_SOURCE_KEY_DOMAIN + settings.ENCRYPTION_KEY.encode("utf-8")).digest()


def source_key(family: str, message_id: str) -> str:
    """HMAC-SHA256 hex of ``"<family>:<message_id>"`` (family ``google_workspace`` or
    ``microsoft``): the only form of a mail message id a check row keeps."""
    if not family or not message_id:
        raise ValueError("source_key needs a connector family and a message id")
    message = f"{family}:{message_id}".encode("utf-8")
    return hmac.new(_source_hmac_key(), message, hashlib.sha256).hexdigest()


def clean_message_id(value: Any) -> Optional[str]:
    """A connector id as the file checks key it: stripped, 1 to 512 characters; None for
    anything else. The mail check (which writes ``source_key``) and the call check (which
    looks a forward's message up by it) both go through this, so one message always hashes
    the same way."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if 0 < len(text) <= MAX_ID_CHARS else None


def message_source_key(family: str, message_id: Any) -> Optional[str]:
    """``source_key`` of a mail message id after ``clean_message_id``; None for an id that is
    not one."""
    cleaned = clean_message_id(message_id)
    if not family or cleaned is None:
        return None
    return source_key(family, cleaned)


def encrypt_source_ref(ref: Mapping[str, str]) -> bytes:
    """*ref* (``{"telegram_file_id": ...}`` or ``{"tool", "message_id", "attachment_id"}``)
    encrypted for the ``source_ref`` column. ``ValueError`` for anything but a small mapping of
    strings to strings."""
    if not isinstance(ref, Mapping) or not ref or len(ref) > _SOURCE_REF_MAX_ITEMS:
        raise ValueError("a source reference is a small mapping of strings")
    clean: dict[str, str] = {}
    for key, value in ref.items():
        if not isinstance(key, str) or not isinstance(value, str) or not key or not value:
            raise ValueError("a source reference is a small mapping of strings")
        if len(key) > _SOURCE_REF_MAX_CHARS or len(value) > _SOURCE_REF_MAX_CHARS:
            raise ValueError("a source reference is a small mapping of strings")
        clean[key] = value
    return encrypt_credentials(json.dumps(clean, sort_keys=True))


def decrypt_source_ref(blob: Optional[bytes]) -> Optional[dict[str, str]]:
    """The reference ``encrypt_source_ref`` stored, or None when there is none or it cannot be
    read (a changed ``ENCRYPTION_KEY``, a damaged row): the upload then has no bytes and refuses,
    which is the safe outcome."""
    if not blob:
        return None
    try:
        value = json.loads(decrypt_credentials(bytes(blob)))
    except Exception as exc:
        logger.warning("file_reputation_source_ref_unreadable", error_type=type(exc).__name__)
        return None
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        logger.warning("file_reputation_source_ref_unreadable", error_type="shape")
        return None
    return value


# -- cached answers -------------------------------------------------------------------------


@dataclass(frozen=True)
class CachedVerdict:
    """One reusable VirusTotal answer about a fingerprint."""

    sha256: str
    verdict: str
    report: Optional[VtFileReport]  # None for a file VirusTotal does not know
    origin: str  # lookup | analysis
    fetched_at: datetime
    expires_at: datetime

    def file_verdict(
        self, *, check_id: Optional[str] = None, can_upload: bool = False
    ) -> FileVerdict:
        return verdict_from_report(
            self.sha256, self.report, cached=True, check_id=check_id, can_upload=can_upload
        )


def _cached_from_row(row: FileReputationVerdict) -> Optional[CachedVerdict]:
    if row.verdict not in LOOKUP_VERDICTS:
        return None
    report: Optional[VtFileReport] = None
    if row.verdict != "unknown":
        report = VtFileReport(
            malicious=row.malicious,
            suspicious=row.suspicious,
            harmless=row.harmless,
            undetected=row.undetected,
            engines=row.engines,
            threat_label=row.threat_label,
            file_type=row.file_type,
            first_seen_at=_as_utc(row.first_seen_at) if row.first_seen_at else None,
            analysed_at=_as_utc(row.analysed_at) if row.analysed_at else None,
        )
        if verdict_of(report) != row.verdict:
            # A row that disagrees with today's mapping is asked again rather than trusted.
            return None
    return CachedVerdict(
        sha256=row.sha256,
        verdict=row.verdict,
        report=report,
        origin=row.origin,
        fetched_at=_as_utc(row.fetched_at),
        expires_at=_as_utc(row.expires_at),
    )


def _fill_row(
    row: FileReputationVerdict,
    report: Optional[VtFileReport],
    *,
    verdict: str,
    origin: str,
    now: datetime,
    expires_at: datetime,
) -> None:
    row.verdict = verdict
    row.malicious = report.malicious if report else 0
    row.suspicious = report.suspicious if report else 0
    row.harmless = report.harmless if report else 0
    row.undetected = report.undetected if report else 0
    row.engines = report.engines if report else 0
    row.threat_label = report.threat_label if report else None
    row.file_type = report.file_type if report else None
    row.first_seen_at = report.first_seen_at if report else None
    row.analysed_at = report.analysed_at if report else None
    row.origin = origin
    row.fetched_at = now
    row.expires_at = expires_at


@dataclass(frozen=True)
class PurgeCounts:
    checks: int
    verdicts: int
    calls: int

    @property
    def total(self) -> int:
        return self.checks + self.verdicts + self.calls


# -- check rows -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckRow:
    """One person's check of one file, as the service reads it. ``has_source_ref`` says whether
    an encrypted re-fetch reference exists; the reference itself is read only for an approved
    upload (``source_ref_of``)."""

    id: str
    user_id: str
    sha256: str
    name: str
    media_type: Optional[str]
    size_bytes: Optional[int]
    source: str
    has_source_ref: bool
    source_key: Optional[str]
    state: str
    priority: str
    verdict: Optional[str]
    malicious: Optional[int]
    suspicious: Optional[int]
    engines: Optional[int]
    threat_label: Optional[str]
    reason: Optional[str]
    alerted_verdict: Optional[str]
    action_id: Optional[str]
    analysis_id: Optional[str]
    polls: int
    next_poll_at: Optional[datetime]
    uploaded_at: Optional[datetime]
    checked_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    expires_at: datetime

    @property
    def flagged(self) -> bool:
        return self.verdict in FLAGGED_VERDICTS

    def file_verdict(self, *, can_upload: bool = False, limit: Optional[int] = None) -> FileVerdict:
        """The row's answer as a ``FileVerdict``: its verdict snapshot when VirusTotal answered,
        else not checked (or pending, for a queued row) with its reason."""
        if self.verdict in LOOKUP_VERDICTS and self.state not in ("queued", "not_checked"):
            return FileVerdict(
                sha256=self.sha256,
                verdict=self.verdict,  # type: ignore[arg-type]
                malicious=max(self.malicious or 0, 0),
                suspicious=max(self.suspicious or 0, 0),
                engines=max(self.engines or 0, 0),
                threat_label=self.threat_label,
                check_id=self.id,
                can_upload=can_upload and self.verdict == "unknown",
            )
        if self.state == "queued":
            return FileVerdict(
                sha256=self.sha256,
                verdict="pending",
                reason=self.reason or "minute_limit",
                check_id=self.id,
                limit=limit,
            )
        return FileVerdict(
            sha256=self.sha256,
            verdict="not_checked",
            reason=self.reason or "service_error",
            check_id=self.id,
            limit=limit,
        )


@dataclass(frozen=True)
class UploadedFile:
    """The facts of one of a person's uploads (``user_files``) a file check needs."""

    id: str
    sha256: str
    name: str
    media_type: Optional[str]
    size_bytes: Optional[int]
    source: str


@dataclass(frozen=True)
class FlaggedFile:
    """A flagged verdict snapshot: an attachment entry's file check, or what the call check
    found for a forward or a knowledge-base save."""

    verdict: str
    malicious: int
    suspicious: int
    engines: int
    threat_label: Optional[str] = None


def _clip(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return text[:limit] if text else None


def _row_of(row: FileReputationCheck, has_ref: Any) -> CheckRow:
    return CheckRow(
        id=str(row.id),
        user_id=str(row.user_id),
        sha256=row.sha256,
        name=row.name,
        media_type=row.media_type,
        size_bytes=row.size_bytes,
        source=row.source,
        has_source_ref=bool(has_ref),
        source_key=row.source_key,
        state=row.state,
        priority=row.priority,
        verdict=row.verdict,
        malicious=row.malicious,
        suspicious=row.suspicious,
        engines=row.engines,
        threat_label=row.threat_label,
        reason=row.reason,
        alerted_verdict=row.alerted_verdict,
        action_id=row.action_id,
        analysis_id=row.analysis_id,
        polls=int(row.polls or 0),
        next_poll_at=_as_utc(row.next_poll_at) if row.next_poll_at else None,
        uploaded_at=_as_utc(row.uploaded_at) if row.uploaded_at else None,
        checked_at=_as_utc(row.checked_at) if row.checked_at else None,
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
        expires_at=_as_utc(row.expires_at),
    )


def _with_ref() -> Any:
    """The check row and whether it holds a source reference, without loading the (deferred,
    encrypted) reference itself."""
    return select(FileReputationCheck, FileReputationCheck.source_ref.is_not(None))


class FileReputationStore:
    """Every read and write of the three file-reputation tables."""

    def __init__(
        self, session_factory: Callable[[], Any], *, clock: Callable[[], datetime] = _utcnow
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    # -- verdict cache --------------------------------------------------------------------

    async def cached_verdict(
        self, sha256: str, *, now: Optional[datetime] = None
    ) -> Optional[CachedVerdict]:
        """The cached answer about *sha256* while it is still fresh; None otherwise."""
        if not is_sha256(sha256):
            return None
        moment = now or self._clock()
        async with self._session_factory() as session:
            row = await session.get(FileReputationVerdict, sha256)
            if row is None or _as_utc(row.expires_at) <= moment:
                return None
            return _cached_from_row(row)

    async def cache_verdict(
        self,
        sha256: str,
        report: Optional[VtFileReport],
        *,
        origin: str = "lookup",
        now: Optional[datetime] = None,
    ) -> CachedVerdict:
        """Store VirusTotal's answer about *sha256* (*report* None: VirusTotal does not know it)
        with the lifetime of its verdict, replacing any older answer."""
        if not is_sha256(sha256):
            raise ValueError("not a SHA-256 fingerprint")
        if origin not in ORIGINS:
            raise ValueError("origin is lookup or analysis")
        moment = now or self._clock()
        verdict = verdict_of(report)
        expires_at = verdict_expires_at(verdict, moment)
        for attempt in (1, 2):
            try:
                async with self._session_factory() as session:
                    row = await session.get(FileReputationVerdict, sha256)
                    if row is None:
                        row = FileReputationVerdict(sha256=sha256)
                        session.add(row)
                    _fill_row(
                        row,
                        report,
                        verdict=verdict,
                        origin=origin,
                        now=moment,
                        expires_at=expires_at,
                    )
                    await session.commit()
                break
            except IntegrityError:
                # Another request cached the same fingerprint between our read and our insert;
                # the second attempt finds its row and updates it.
                if attempt == 2:
                    raise
        return CachedVerdict(
            sha256=sha256,
            verdict=verdict,
            report=report if verdict != "unknown" else None,
            origin=origin,
            fetched_at=moment,
            expires_at=expires_at,
        )

    async def forget_verdict(self, sha256: str) -> None:
        """Drop the cached answer (a successful upload: the finished scan writes a new one)."""
        if not is_sha256(sha256):
            return
        async with self._session_factory() as session:
            await session.execute(
                delete(FileReputationVerdict).where(FileReputationVerdict.sha256 == sha256)
            )
            await session.commit()

    # -- request log (quota.CallLog) ------------------------------------------------------

    async def call_counts(self, *, now: datetime, user_id: Optional[str]) -> CallCounts:
        """The sliding-window counts the quota decides on: reservation times in the last
        minute, all and automatic reservations in the last 24 h, and this person's explicit
        lookups in the last 24 h."""
        minute_from = now - MINUTE
        day_from = now - DAY
        user_uuid = _as_uuid(user_id)
        calls = FileReputationCall
        async with self._session_factory() as session:
            minute_times = (
                await session.execute(
                    select(calls.at).where(calls.at > minute_from).order_by(calls.at)
                )
            ).scalars().all()
            last_24h = await session.scalar(
                select(func.count()).select_from(calls).where(calls.at > day_from)
            )
            automatic = await session.scalar(
                select(func.count())
                .select_from(calls)
                .where(calls.at > day_from, calls.priority == "automatic")
            )
            user_count = 0
            if user_uuid is not None:
                user_count = (
                    await session.scalar(
                        select(func.count())
                        .select_from(calls)
                        .where(
                            calls.at > day_from,
                            calls.user_id == user_uuid,
                            calls.kind == "lookup",
                            calls.priority == "explicit",
                        )
                    )
                    or 0
                )
        return CallCounts(
            minute_times=tuple(_as_utc(at) for at in minute_times),
            last_24h=int(last_24h or 0),
            automatic_last_24h=int(automatic or 0),
            user_last_24h=int(user_count),
        )

    async def record_call(
        self, *, at: datetime, kind: CallKind, priority: Priority, user_id: Optional[str]
    ) -> None:
        """Reserve one request (written before the request is made)."""
        async with self._session_factory() as session:
            session.add(
                FileReputationCall(
                    at=at, kind=kind, priority=priority, user_id=_as_uuid(user_id)
                )
            )
            await session.commit()

    # -- check rows -----------------------------------------------------------------------

    async def upsert_check(
        self,
        user_id: str,
        sha256: str,
        *,
        name: Optional[str],
        media_type: Optional[str],
        size_bytes: Optional[int],
        source: str,
        priority: Priority,
        source_ref: Optional[Mapping[str, str]] = None,
        source_key: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> CheckRow:
        """Record one sighting of a file for *user_id*: a new row (state ``queued``) or the
        existing one refreshed (last sighting, 30 more days). A sighting without a real name
        or a byte source keeps what the row already had, so a bare fingerprint from the model
        never erases the name or the re-fetch reference of an earlier upload. ``ValueError``
        for a user id, fingerprint or source that is not one."""
        user_uuid = _as_uuid(user_id)
        if user_uuid is None:
            raise ValueError("not a user id")
        if not is_sha256(sha256):
            raise ValueError("not a SHA-256 fingerprint")
        if source not in SOURCES:
            raise ValueError("unknown file source")
        moment = now or self._clock()
        named = _clip(name, _NAME_CHARS)
        real_name = named if named and named != DEFAULT_NAME else None
        media = _clip(media_type, _MEDIA_TYPE_CHARS)
        size = size_bytes if isinstance(size_bytes, int) and not isinstance(size_bytes, bool) else None
        if size is not None and size < 0:
            size = None
        ref_blob = encrypt_source_ref(source_ref) if source_ref else None
        for attempt in (1, 2):
            try:
                async with self._session_factory() as session:
                    row = (
                        await session.execute(
                            select(FileReputationCheck).where(
                                FileReputationCheck.user_id == user_uuid,
                                FileReputationCheck.sha256 == sha256,
                            )
                        )
                    ).scalar_one_or_none()
                    if row is None:
                        row = FileReputationCheck(
                            id=uuid.uuid4(),
                            user_id=user_uuid,
                            sha256=sha256,
                            name=real_name or DEFAULT_NAME,
                            media_type=media,
                            size_bytes=size,
                            source=source,
                            source_ref=ref_blob,
                            source_key=source_key,
                            state="queued",
                            priority=priority,
                            polls=0,
                            created_at=moment,
                            updated_at=moment,
                            expires_at=check_expires_at(moment),
                        )
                        session.add(row)
                    else:
                        if real_name is not None:
                            row.name = real_name
                        if media is not None:
                            row.media_type = media
                        if size is not None:
                            row.size_bytes = size
                        if source != "hash":
                            row.source = source
                        if ref_blob is not None:
                            row.source_ref = ref_blob
                        if source_key is not None:
                            row.source_key = source_key
                        # A queued explicit check keeps its place at the front of the queue.
                        if not (row.state == "queued" and row.priority == "explicit"):
                            row.priority = priority
                        row.updated_at = moment
                        row.expires_at = check_expires_at(moment)
                    check_id = row.id
                    await session.commit()
                break
            except IntegrityError:
                # The same person's same file arrived twice at once; the second attempt finds
                # the row the first one inserted and refreshes it.
                if attempt == 2:
                    raise
        found = await self.get_check(str(user_uuid), str(check_id))
        if found is None:  # pragma: no cover - deleted between the write and the read
            raise LookupError("the check row went away")
        return found

    async def get_check(self, user_id: str, check_id: str) -> Optional[CheckRow]:
        """*user_id*'s check *check_id*, or None (unknown, another person's, or not an id)."""
        user_uuid, row_uuid = _as_uuid(user_id), _as_uuid(check_id)
        if user_uuid is None or row_uuid is None:
            return None
        async with self._session_factory() as session:
            found = (
                await session.execute(
                    _with_ref().where(
                        FileReputationCheck.id == row_uuid,
                        FileReputationCheck.user_id == user_uuid,
                    )
                )
            ).first()
        return _row_of(found[0], found[1]) if found is not None else None

    async def check_for(self, user_id: str, sha256: str) -> Optional[CheckRow]:
        """*user_id*'s check of the file with this fingerprint, or None."""
        user_uuid = _as_uuid(user_id)
        if user_uuid is None or not is_sha256(sha256):
            return None
        async with self._session_factory() as session:
            found = (
                await session.execute(
                    _with_ref().where(
                        FileReputationCheck.user_id == user_uuid,
                        FileReputationCheck.sha256 == sha256,
                    )
                )
            ).first()
        return _row_of(found[0], found[1]) if found is not None else None

    async def source_ref_of(self, user_id: str, sha256: str) -> Optional[dict[str, str]]:
        """The decrypted re-fetch reference of *user_id*'s check of this file (an approved
        upload only), or None."""
        user_uuid = _as_uuid(user_id)
        if user_uuid is None or not is_sha256(sha256):
            return None
        async with self._session_factory() as session:
            blob = await session.scalar(
                select(FileReputationCheck.source_ref).where(
                    FileReputationCheck.user_id == user_uuid,
                    FileReputationCheck.sha256 == sha256,
                )
            )
        return decrypt_source_ref(blob)

    async def _update(self, user_id: str, check_id: str, values: Mapping[str, Any]) -> bool:
        user_uuid, row_uuid = _as_uuid(user_id), _as_uuid(check_id)
        if user_uuid is None or row_uuid is None:
            return False
        async with self._session_factory() as session:
            result = await session.execute(
                update(FileReputationCheck)
                .where(
                    FileReputationCheck.id == row_uuid,
                    FileReputationCheck.user_id == user_uuid,
                )
                .values(**values)
            )
            await session.commit()
        return int(getattr(result, "rowcount", 0) or 0) == 1

    async def settle_check(
        self,
        user_id: str,
        check_id: str,
        verdict: FileVerdict,
        *,
        now: Optional[datetime] = None,
        end_upload: bool = False,
    ) -> Optional[CheckRow]:
        """Write one attempt's outcome to the row and release its claim:

        - VirusTotal answered: the verdict snapshot, state ``checked``. A pending card or a
          running scan keeps its state while the file is still unknown (``end_upload`` ends
          a scan whatever its answer).
        - A pending reason (a limit that only delays): state ``queued`` with the reason, so
          the sweep finishes it.
        - Not checked: state ``not_checked`` with the reason, unless the row already holds a
          verdict, which stands (a failed re-check never erases a flagged history).
        """
        current = await self.get_check(user_id, check_id)
        if current is None:
            return None
        moment = now or self._clock()
        values: dict[str, Any] = {"claimed_until": None}
        if verdict.checked:
            keep = current.state in _UPLOAD_STATES and verdict.verdict == "unknown" and not end_upload
            values.update(
                {
                    "state": current.state if keep else "checked",
                    "verdict": verdict.verdict,
                    "malicious": verdict.malicious,
                    "suspicious": verdict.suspicious,
                    "engines": verdict.engines,
                    "threat_label": verdict.threat_label,
                    "reason": None,
                    "checked_at": moment,
                }
            )
            if not keep and current.state == "analysing":
                values.update({"next_poll_at": None})
        elif verdict.verdict == "pending":
            if current.state not in _UPLOAD_STATES:
                values.update({"state": "queued", "reason": _clip(verdict.reason, _REASON_CHARS)})
        else:
            if end_upload or current.state not in _UPLOAD_STATES:
                if end_upload or current.verdict not in LOOKUP_VERDICTS:
                    values.update(
                        {
                            "state": "not_checked",
                            "reason": _clip(verdict.reason, _REASON_CHARS),
                            "next_poll_at": None,
                        }
                    )
                elif current.state == "queued":
                    # The verdict already there stands; the row stops waiting.
                    values.update({"state": "checked", "reason": None})
        await self._update(user_id, check_id, values)
        return await self.get_check(user_id, check_id)

    async def claim_alert(self, user_id: str, check_id: str, verdict: str) -> bool:
        """Record that *verdict* is being told for this row; True only for the one caller that
        changed it (a conditional UPDATE), so each verdict is told once per person and file even
        when two answers land together."""
        user_uuid, row_uuid = _as_uuid(user_id), _as_uuid(check_id)
        if user_uuid is None or row_uuid is None or not verdict:
            return False
        told = verdict[:16]
        async with self._session_factory() as session:
            result = await session.execute(
                update(FileReputationCheck)
                .where(
                    FileReputationCheck.id == row_uuid,
                    FileReputationCheck.user_id == user_uuid,
                    or_(
                        FileReputationCheck.alerted_verdict.is_(None),
                        FileReputationCheck.alerted_verdict != told,
                    ),
                )
                .values(alerted_verdict=told)
            )
            await session.commit()
        return int(getattr(result, "rowcount", 0) or 0) == 1

    async def mark_upload_pending(self, user_id: str, check_id: str, action_id: str) -> None:
        """An upload card was parked for this row (the Security page)."""
        await self._update(
            user_id,
            check_id,
            {"state": "upload_pending", "action_id": str(action_id)[:_ACTION_ID_CHARS]},
        )

    async def clear_upload_pending(self, user_id: str, *, keep: frozenset[str]) -> int:
        """Rows of *user_id* waiting for a card that is no longer pending (denied, expired or
        used) go back to ``checked``; *keep* holds the action ids still pending."""
        user_uuid = _as_uuid(user_id)
        if user_uuid is None:
            return 0
        stale = and_(
            FileReputationCheck.user_id == user_uuid,
            FileReputationCheck.state == "upload_pending",
        )
        if keep:
            stale = and_(
                stale,
                or_(
                    FileReputationCheck.action_id.is_(None),
                    FileReputationCheck.action_id.not_in(sorted(keep)),
                ),
            )
        async with self._session_factory() as session:
            result = await session.execute(
                update(FileReputationCheck).where(stale).values(state="checked", action_id=None)
            )
            await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)

    async def mark_uploaded(
        self,
        user_id: str,
        check_id: str,
        *,
        analysis_id: str,
        now: datetime,
        next_poll_at: datetime,
    ) -> None:
        """The file was sent: the row waits for its scan."""
        await self._update(
            user_id,
            check_id,
            {
                "state": "analysing",
                "analysis_id": analysis_id[:_ANALYSIS_ID_CHARS],
                "uploaded_at": now,
                "polls": 0,
                "next_poll_at": next_poll_at,
                "reason": None,
                "action_id": None,
                "claimed_until": None,
            },
        )

    async def end_upload_wait(self, user_id: str, check_id: str) -> None:
        """An approved upload sent nothing: a row waiting for that card goes back to
        ``checked``."""
        user_uuid, row_uuid = _as_uuid(user_id), _as_uuid(check_id)
        if user_uuid is None or row_uuid is None:
            return
        async with self._session_factory() as session:
            await session.execute(
                update(FileReputationCheck)
                .where(
                    FileReputationCheck.id == row_uuid,
                    FileReputationCheck.user_id == user_uuid,
                    FileReputationCheck.state == "upload_pending",
                )
                .values(state="checked", action_id=None)
            )
            await session.commit()

    async def record_poll(
        self, user_id: str, check_id: str, *, polls: int, next_poll_at: Optional[datetime]
    ) -> None:
        """One analysis poll that did not finish the scan."""
        await self._update(
            user_id,
            check_id,
            {"polls": polls, "next_poll_at": next_poll_at, "claimed_until": None},
        )

    async def release_claim(self, user_id: str, check_id: str) -> None:
        await self._update(user_id, check_id, {"claimed_until": None})

    async def _claim(
        self, due: Any, order: tuple[Any, ...], *, now: datetime, limit: int, claim_s: float
    ) -> list[CheckRow]:
        if limit <= 0:
            return []
        free = or_(
            FileReputationCheck.claimed_until.is_(None),
            FileReputationCheck.claimed_until <= now,
        )
        until = now + timedelta(seconds=claim_s)
        claimed: list[CheckRow] = []
        async with self._session_factory() as session:
            candidates = (
                await session.execute(
                    select(FileReputationCheck.id).where(due, free).order_by(*order).limit(
                        min(limit, _MAX_LIST)
                    )
                )
            ).scalars().all()
            for row_id in candidates:
                result = await session.execute(
                    update(FileReputationCheck)
                    .where(FileReputationCheck.id == row_id, due, free)
                    .values(claimed_until=until)
                )
                if getattr(result, "rowcount", 0) == 1:
                    claimed.append(row_id)
            await session.commit()
            if not claimed:
                return []
            rows = (
                await session.execute(_with_ref().where(FileReputationCheck.id.in_(claimed)))
            ).all()
        by_id = {row[0].id: _row_of(row[0], row[1]) for row in rows}
        return [by_id[row_id] for row_id in claimed if row_id in by_id]

    async def claim_queued(
        self, *, now: Optional[datetime] = None, limit: int, claim_s: float = 120.0
    ) -> list[CheckRow]:
        """Queued rows the sweep may look up now, explicit ones first, then oldest first; each
        is claimed (``claimed_until``) so no other sweep takes it."""
        moment = now or self._clock()
        explicit_first = case((FileReputationCheck.priority == "explicit", 0), else_=1)
        return await self._claim(
            FileReputationCheck.state == "queued",
            (explicit_first, FileReputationCheck.created_at),
            now=moment,
            limit=limit,
            claim_s=claim_s,
        )

    async def claim_due_polls(
        self, *, now: Optional[datetime] = None, limit: int, claim_s: float = 120.0
    ) -> list[CheckRow]:
        """Rows whose scan is due for a poll, oldest due first, each claimed."""
        moment = now or self._clock()
        due = and_(
            FileReputationCheck.state == "analysing",
            FileReputationCheck.next_poll_at.is_not(None),
            FileReputationCheck.next_poll_at <= moment,
        )
        return await self._claim(
            due, (FileReputationCheck.next_poll_at,), now=moment, limit=limit, claim_s=claim_s
        )

    async def list_checks(self, user_id: str, limit: int) -> list[CheckRow]:
        """*user_id*'s checks, last sighting first (at most 100)."""
        user_uuid = _as_uuid(user_id)
        if user_uuid is None:
            return []
        count = max(1, min(int(limit), _MAX_LIST))
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    _with_ref()
                    .where(FileReputationCheck.user_id == user_uuid)
                    .order_by(FileReputationCheck.updated_at.desc(), FileReputationCheck.id)
                    .limit(count)
                )
            ).all()
        return [_row_of(row[0], row[1]) for row in rows]

    async def delete_check(self, user_id: str, check_id: str) -> Optional[str]:
        """Forget *user_id*'s check *check_id*; its fingerprint, or None when there was no
        such row of theirs."""
        user_uuid, row_uuid = _as_uuid(user_id), _as_uuid(check_id)
        if user_uuid is None or row_uuid is None:
            return None
        async with self._session_factory() as session:
            sha256 = await session.scalar(
                select(FileReputationCheck.sha256).where(
                    FileReputationCheck.id == row_uuid,
                    FileReputationCheck.user_id == user_uuid,
                )
            )
            if sha256 is None:
                return None
            await session.execute(
                delete(FileReputationCheck).where(
                    FileReputationCheck.id == row_uuid,
                    FileReputationCheck.user_id == user_uuid,
                )
            )
            await session.commit()
        return str(sha256)

    async def uploaded_file(
        self, user_id: str, file_id: str, *, now: Optional[datetime] = None
    ) -> Optional[UploadedFile]:
        """One of *user_id*'s own uploads (``user_files``) that has not expired, or None (an
        unknown id, another person's, or not an id)."""
        user_uuid, file_uuid = _as_uuid(user_id), _as_uuid(file_id)
        if user_uuid is None or file_uuid is None:
            return None
        moment = now or self._clock()
        async with self._session_factory() as session:
            found = (
                await session.execute(
                    select(
                        UserFile.id,
                        UserFile.sha256,
                        UserFile.name,
                        UserFile.media_type,
                        UserFile.size_bytes,
                        UserFile.source,
                        UserFile.expires_at,
                    ).where(UserFile.id == file_uuid, UserFile.user_id == user_uuid)
                )
            ).first()
        if found is None or _as_utc(found.expires_at) <= moment:
            return None
        sha256 = str(found.sha256 or "").lower()
        if not is_sha256(sha256):
            return None
        return UploadedFile(
            id=str(found.id),
            sha256=sha256,
            name=found.name,
            media_type=found.media_type,
            size_bytes=found.size_bytes,
            source=found.source,
        )

    async def flagged_uploads(
        self, user_id: str, file_ids: list[str]
    ) -> dict[str, FlaggedFile]:
        """For each of *user_id*'s uploads among *file_ids* whose file a check flagged: the
        verdict snapshot, keyed by the file id. One query (``user_files`` joined to the checks
        on user and fingerprint)."""
        user_uuid = _as_uuid(user_id)
        wanted = [u for u in (_as_uuid(f) for f in file_ids[:_MAX_FILE_IDS]) if u is not None]
        if user_uuid is None or not wanted:
            return {}
        checks = FileReputationCheck
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        UserFile.id,
                        checks.verdict,
                        checks.malicious,
                        checks.suspicious,
                        checks.engines,
                        checks.threat_label,
                    )
                    .join(
                        checks,
                        and_(checks.user_id == UserFile.user_id, checks.sha256 == UserFile.sha256),
                    )
                    .where(
                        UserFile.user_id == user_uuid,
                        UserFile.id.in_(wanted),
                        checks.verdict.in_(sorted(FLAGGED_VERDICTS)),
                    )
                )
            ).all()
        return {
            str(row[0]): FlaggedFile(
                verdict=row[1],
                malicious=int(row[2] or 0),
                suspicious=int(row[3] or 0),
                engines=int(row[4] or 0),
                threat_label=row[5],
            )
            for row in rows
        }

    async def flagged_by_source_key(self, user_id: str, key: str) -> Optional[FlaggedFile]:
        """The worst flagged verdict among *user_id*'s checks of attachments of the mail message
        whose keyed hash is *key* (the call check's one indexed query), or None."""
        user_uuid = _as_uuid(user_id)
        if user_uuid is None or not key:
            return None
        checks = FileReputationCheck
        worst_first = case((checks.verdict == "malicious", 0), else_=1)
        async with self._session_factory() as session:
            found = (
                await session.execute(
                    select(checks.verdict, checks.malicious, checks.suspicious, checks.engines)
                    .where(
                        checks.user_id == user_uuid,
                        checks.source_key == key,
                        checks.verdict.in_(sorted(FLAGGED_VERDICTS)),
                    )
                    .order_by(worst_first, checks.malicious.desc())
                    .limit(1)
                )
            ).first()
        if found is None:
            return None
        return FlaggedFile(
            verdict=found[0],
            malicious=int(found[1] or 0),
            suspicious=int(found[2] or 0),
            engines=int(found[3] or 0),
        )

    # -- retention ------------------------------------------------------------------------

    async def purge(self, *, now: Optional[datetime] = None) -> PurgeCounts:
        """Delete expired check rows and cached answers, and request-log rows older than 48 h.
        Runs whether or not the switch is on and a key exists."""
        moment = now or self._clock()
        async with self._session_factory() as session:
            checks = await session.execute(
                delete(FileReputationCheck).where(FileReputationCheck.expires_at < moment)
            )
            verdicts = await session.execute(
                delete(FileReputationVerdict).where(FileReputationVerdict.expires_at < moment)
            )
            calls = await session.execute(
                delete(FileReputationCall).where(FileReputationCall.at < moment - CALL_RETENTION)
            )
            await session.commit()
        return PurgeCounts(
            checks=int(getattr(checks, "rowcount", 0) or 0),
            verdicts=int(getattr(verdicts, "rowcount", 0) or 0),
            calls=int(getattr(calls, "rowcount", 0) or 0),
        )
