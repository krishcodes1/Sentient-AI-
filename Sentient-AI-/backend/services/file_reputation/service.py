"""The file reputation service (security S10): one ``FileReputationService`` per process that
looks files up in VirusTotal by fingerprint with the owner's key, screens every file people send,
annotates attachment entries with a flagged file's check, checks email attachments for the mail
scan, and sends a file VirusTotal does not know only after its approval card.

Why it exists: the intake, the security.* tools, the Security page, S2's mail scan and S3's scam
check must give the same answer for the same file, under one switch, one key, one quota
(VirusTotal's public key allows 4 lookups a minute and 500 a day) and one failure rule: never
"safe", always ``not_checked`` (or ``pending``) with a reason when anything fails. So:

- The switch and the key are read per request. A report that cannot be read counts as off, and
  without a key nothing is hashed, stored or sent (decisions 2).
- A lookup tries the install-wide cache first, then reserves a slot in the persisted quota, then
  asks VirusTotal. Concurrent lookups of one fingerprint share one request (``_inflight``); each
  caller then writes only its own row, so two people with the same file never see each other's
  history.
- A flagged verdict is told to the person once per verdict (``alerted_verdict``), through their
  own linked chats, with fixed text built from counts (``alerts.py``). A caller that tells the
  person itself (``alert="caller"``: S2's mail alert, the model in a turn, the Security page)
  marks the verdict told instead; a verdict that arrives later (the queue, a scan) is always told
  by the service.
- An upload is the one thing that sends a file's bytes, and only after a person approved its own
  card. The bytes are fetched again at that moment (the in-memory holder, Telegram by file id, or
  the mail connector through the executor and the byte sink), hashed again and compared with the
  card, under the quota; anything missing or different sends nothing and writes one refusal row.
- Audit rows hold fingerprints, counts and codes only, never a file name, a message id or a key.

The single-process assumption of services/installation.py holds here too: the holder, the
cool-downs and the in-flight lookups are in memory, and losing them is safe (a card refuses, a
lookup is asked again).

Connects to: services/file_reputation/store.py (every table read and write), quota.py,
virustotal.py, holder.py, byte_sink.py, kinds.py, verdicts.py and alerts.py; main.py (built in
wire_services with the owner's sender, Telegram's download, the executor and park_card),
services/files/intake.py (the file screen), toolkit.py (the security.* file tools), sweeper.py,
api/routes/security_files.py, S2 (``check_mail_attachment``), S3 (``check_hash``).
"""

from __future__ import annotations

import asyncio
import inspect
import re
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Protocol

import structlog
from sqlalchemy import select

from models.user import User
from services.file_reputation import alerts, byte_sink, kinds
from services.file_reputation.holder import ByteHolder
from services.file_reputation.quota import (
    DEFAULT_LIMITS,
    KeyRejection,
    QuotaLimits,
    VirusTotalQuota,
    limits_from_settings,
)
from services.file_reputation.store import (
    SOURCES,
    CheckRow,
    FileReputationStore,
    clean_message_id,
    message_source_key,
)
from services.file_reputation.verdicts import (
    LOOKUP_VERDICTS,
    FileVerdict,
    card_name,
    reason_sentence,
)
from services.file_reputation.virustotal import (
    VT_MAX_UPLOAD_BYTES,
    VirusTotalClient,
    VirusTotalError,
    VtFileReport,
    verdict_from_report,
)
from services.files.prompting import sanitize_display_name

logger = structlog.get_logger(__name__)

Priority = Literal["explicit", "automatic"]
AlertMode = Literal["service", "caller"]

CAPABILITY_KEY = "file_reputation"
SERVICE_KEY_NAME = "virustotal"
TOOL_CHECK = "security.check_file"
TOOL_UPLOAD = "security.upload_to_virustotal"

MB = 1024 * 1024
# The largest file the Security page may send (the route reads at most this much) and the largest
# Telegram hands a bot: the bytes an approved upload can work with.
PAGE_UPLOAD_MAX_BYTES = 20 * MB
TELEGRAM_FETCH_MAX_BYTES = 20 * MB
# How long bytes wait in memory: a risky chat upload 30 minutes, a file the owner picked on the
# Security page 60 minutes, and a file a card was made for at least the card's 60 minutes.
SCREEN_HOLD_S = 30 * 60.0
PAGE_HOLD_S = 60 * 60.0
CARD_PIN_S = 60 * 60.0
UPLOAD_CARD_TTL_MINUTES = 60
# How long an approved upload waits for room in VirusTotal's minute window.
UPLOAD_WAIT_S = 20.0
# Analysis polls: the first after 90 s, then every 120 s, at most 8 (about 15 minutes).
FIRST_POLL_S = 90.0
NEXT_POLL_S = 120.0
MAX_POLLS = 8
# The sweep: purge once an hour; a claimed row is the sweep's for 2 minutes.
PURGE_EVERY = timedelta(hours=1)
CLAIM_S = 120.0
POLLS_PER_SWEEP = 4
# Upload requests from the Security page: 5 an hour per person.
UPLOAD_REQUESTS_PER_HOUR = 5
_UPLOAD_REQUEST_WINDOW = timedelta(hours=1)
# A lookup another caller started gets this much longer than the joiner's own wait to reserve
# its slot (a database write), so a joiner with no wait of its own is not told "the minute
# limit" just because the first caller had not reached VirusTotal yet.
_JOIN_SLACK_S = 2.0
# Quota refusals that depend on who asked (their share, an automatic check's share, the
# minute window they waited for): a caller who joined someone else's lookup asks again for
# themselves instead of taking that answer.
_PER_CALLER_REASONS = frozenset({"user_limit", "automatic_limit", "minute_limit"})

_MAIL_HASH_TOOL_RE = re.compile(
    r"(google_workspace|microsoft)(?:__[0-9a-f]{8})?\.get_attachment_hash"
)
_MAIL_SOURCE = {"google_workspace": "gmail", "microsoft": "outlook"}
_MAIL_ID_PARAM = {"google_workspace": "part_id", "microsoft": "attachment_id"}
_CHANNEL_SOURCES = frozenset({"web", "telegram", "slack"})

# What the Security tab says about the service (S10 6.2, 6.3).
OFF_SENTENCE = "Checking files with VirusTotal is turned off in Settings → Permissions."
NO_KEY_SENTENCE = "Add a VirusTotal key in the Service keys tab to check files."
NOT_SET_UP_SENTENCE = "File checks are not set up on this install."

# Upload refusals (S10 4.3 E and G): fixed sentences, never the model's words.
UPLOAD_INVALID = (
    "security.upload_to_virustotal needs the sha256 (64 hex characters) that "
    "security.check_file answered."
)
UPLOAD_UNKNOWN_FILE = (
    "Crawler has no check of that file for you. Look it up with security.check_file first; only "
    "a file someone sent Crawler can be sent to VirusTotal."
)
UPLOAD_NOT_CHECKED_YET = (
    "VirusTotal has not answered about that file yet. Check it with security.check_file first."
)
UPLOAD_ALREADY_KNOWN = (
    "VirusTotal already knows that file, so there is nothing to send. Its verdict is in "
    "security.check_file."
)
UPLOAD_ALREADY_SENT = (
    "That file was already sent to VirusTotal and is being scanned; Crawler will tell the user "
    "the result."
)
UPLOAD_PERSONAL_DOCUMENT = (
    "This looks like a personal document (PDF, Office, picture or text). Crawler does not send "
    "those to VirusTotal from a chat. If you are sure, use Send to VirusTotal on the Security "
    "page and pick the file there."
)
UPLOAD_BYTES_UNAVAILABLE = (
    "Crawler no longer has this file (it was kept in memory only, and the server restarted or "
    "60 minutes passed). Nothing was sent. The user can send it from Security → File checks by "
    "picking the file there."
)
UPLOAD_FILE_CHANGED = (
    "The file Crawler got back is not the one on the card (its fingerprint changed), so nothing "
    "was sent."
)
UPLOAD_TOO_LARGE = "The file is larger than VirusTotal accepts (32 MB), so nothing was sent."
UPLOAD_SENT = (
    "Sent to VirusTotal. The scan usually takes a few minutes; Crawler will tell you the result."
)


class FileReputationSettings(Protocol):
    """What the service reads from InstallationService."""

    async def capability_statuses(self) -> Mapping[str, Any]: ...

    async def service_key(self, name: str) -> Optional[str]: ...


SendText = Callable[[str, str], Awaitable[bool]]  # app.state.owner_send / main.fan_out_send(...)
TelegramFetch = Callable[[str, int], Awaitable[Optional[bytes]]]  # TelegramManager.download_file
ConnectorRead = Callable[..., Awaitable[dict[str, Any]]]  # ConnectorToolExecutor.execute
ParkCard = Callable[..., Awaitable[Any]]  # AgentRuntime.park_card
PendingIds = Callable[[str], Awaitable[set[str]]]  # pending action ids of a user


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class _Access:
    """The switch, the key and the limits, read once per request."""

    state: Literal["on", "off", "blocked"]
    key: Optional[str]
    limits: QuotaLimits

    @property
    def on(self) -> bool:
        return self.state == "on" and bool(self.key)

    @property
    def reason(self) -> str:
        """Why nothing may be sent (``switched_off`` or ``no_key``)."""
        return "switched_off" if self.state == "off" else "no_key"


@dataclass
class _Lookup:
    """One VirusTotal lookup of a fingerprint that every concurrent caller shares: ``sent`` is
    resolved once the request has its quota slot (or the lookup ended without one), ``done``
    with the answer. Both are always resolved, never failed."""

    sent: asyncio.Future[None]
    done: asyncio.Future[FileVerdict]


@dataclass(frozen=True)
class UploadRequestOutcome:
    """What ``request_upload`` answers the Security page's route.

    ``status`` is ``parked`` (a new card), ``pending`` (the card already waiting) or ``refused``
    with a ``code``: not_found, service_off, already_known, not_checked_yet, needs_file,
    too_large, file_changed, rate_limited, not_wired or refused."""

    status: Literal["parked", "pending", "refused"]
    message: str
    code: Optional[str] = None
    action_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    retry_after: Optional[int] = None


def _limit_for(reason: Optional[str], limits: QuotaLimits) -> Optional[int]:
    return {
        "minute_limit": limits.per_minute,
        "daily_limit": limits.per_day,
        "automatic_limit": limits.automatic_per_day,
        "user_limit": limits.per_user_per_day,
    }.get(reason or "")


def mail_family(hash_tool: Any) -> Optional[str]:
    """``google_workspace`` or ``microsoft`` for a mail connector's ``get_attachment_hash`` tool
    name (with or without its per-account slug); None for anything else."""
    if not isinstance(hash_tool, str):
        return None
    match = _MAIL_HASH_TOOL_RE.fullmatch(hash_tool)
    return match.group(1) if match else None


# One cleaning rule for every connector id the service keeps (store.clean_message_id).
_clean_id = clean_message_id


def _refusal(rule: str, message: str) -> dict[str, Any]:
    return {"ok": False, "rule": rule, "error": message}


def _hash_result(answer: Any) -> Optional[Mapping[str, Any]]:
    """The facts of a ``get_attachment_hash`` answer: the executor's ``{"ok": True, "result":
    {...}}`` or the action's own dict; None for a refusal or anything else."""
    if not isinstance(answer, Mapping):
        return None
    if answer.get("ok") is False or answer.get("error"):
        return None
    inner = answer.get("result")
    if isinstance(inner, Mapping):
        return inner
    if "sha256" in answer or "too_large" in answer:
        return answer
    return None


class FileReputationService:
    """File lookups, the intake screen and uploads (see the module docstring)."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        settings: FileReputationSettings,
        audit: Callable[[dict[str, Any]], Awaitable[None]],
        send: SendText,
        telegram_fetch: Optional[TelegramFetch] = None,
        connector_read: Optional[ConnectorRead] = None,
        park_card: Optional[ParkCard] = None,
        pending_ids: Optional[PendingIds] = None,
        client: Optional[VirusTotalClient] = None,
        holder: Optional[ByteHolder] = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._audit = audit
        self._send = send
        self._telegram_fetch = telegram_fetch
        self._connector_read = connector_read
        self._park_card = park_card
        self._pending_ids = pending_ids
        self._client = client if client is not None else VirusTotalClient()
        self.holder = holder if holder is not None else ByteHolder()
        self._clock = clock
        self.store = FileReputationStore(session_factory, clock=clock)
        self.quota = VirusTotalQuota(self.store, self._limits, clock=clock)
        self._key_rejection = KeyRejection()
        self._inflight: dict[str, _Lookup] = {}
        self._tasks: set[asyncio.Future[Any]] = set()
        # Background lookups the intake started, per user, so annotate can wait for them.
        self._screening: dict[str, set[asyncio.Future[Any]]] = {}
        self._sweep_lock = asyncio.Lock()
        self._last_purge: Optional[datetime] = None
        self._upload_requests: dict[str, deque[datetime]] = {}
        self._kick: Optional[Callable[[], Any]] = None

    # -- wiring -------------------------------------------------------------------------------

    def use_kick(self, kick: Callable[[], Any]) -> None:
        """The sweeper's ``kick`` (it hands it in): run one sweep at once after an upload, so the
        first analysis poll is not a whole interval late."""
        self._kick = kick

    def _spawn(self, coro: Awaitable[Any]) -> asyncio.Future[Any]:
        task: asyncio.Future[Any] = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def drain(self, timeout: float = 30.0) -> None:
        """Wait until the background lookups and late answers this service started are done (at
        most *timeout* seconds in all): tests and an orderly shutdown."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while self._tasks:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            await asyncio.wait(set(self._tasks), timeout=remaining)

    # -- the switch, the key, the audit -------------------------------------------------------

    async def _read_access(self) -> _Access:
        """The switch (fail closed: a report that cannot be read counts as off), the key and the
        owner's limits."""
        try:
            statuses = await self._settings.capability_statuses()
            status = statuses.get(CAPABILITY_KEY) if isinstance(statuses, Mapping) else None
        except Exception as exc:
            logger.warning("file_reputation_switch_unreadable", error_type=type(exc).__name__)
            return _Access("off", None, DEFAULT_LIMITS)
        if status is None:
            return _Access("off", None, DEFAULT_LIMITS)
        limits = limits_from_settings(getattr(status, "settings", None))
        effective = getattr(status, "effective", None)
        if effective == "blocked":
            return _Access("blocked", None, limits)
        if effective != "on":
            return _Access("off", None, limits)
        try:
            key = await self._settings.service_key(SERVICE_KEY_NAME)
        except Exception as exc:
            logger.warning("file_reputation_key_unreadable", error_type=type(exc).__name__)
            return _Access("blocked", None, limits)
        key = key.strip() if isinstance(key, str) else ""
        if not key:
            return _Access("blocked", None, limits)
        return _Access("on", key, limits)

    async def _limits(self) -> QuotaLimits:
        return (await self._read_access()).limits

    async def _write_audit(self, entry: dict[str, Any]) -> None:
        entry.setdefault("timestamp", self._clock().isoformat())
        try:
            result = self._audit(entry)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:  # the work stands; the log says the row is missing
            logger.error(
                "file_reputation_audit_failed",
                event=entry.get("event"),
                error_type=type(exc).__name__,
            )

    async def _audit_checked(
        self,
        user_id: Optional[str],
        sha256: str,
        *,
        source: str,
        priority: str,
        origin: str,
        verdict: Optional[FileVerdict] = None,
        reason: Optional[str] = None,
    ) -> None:
        if not user_id:
            return
        facts: dict[str, Any] = {
            "sha256": sha256,
            "source": source,
            "priority": priority,
            "origin": origin,
        }
        if verdict is not None and verdict.checked:
            facts.update(
                {
                    "verdict": verdict.verdict,
                    "flagged_by": verdict.flagged_by,
                    "engines": verdict.engines,
                }
            )
        else:
            facts["reason"] = reason or (verdict.reason if verdict else None) or "service_error"
        await self._write_audit(
            {
                "event": "file_reputation_checked",
                "user_id": user_id,
                "tool": TOOL_CHECK,
                "arguments": facts,
            }
        )

    async def _deliver(self, user_id: str, text: str) -> bool:
        try:
            return (await self._send(user_id, text)) is True
        except Exception as exc:
            logger.warning("file_reputation_alert_failed", error_type=type(exc).__name__)
            return False

    # -- state --------------------------------------------------------------------------------

    async def status(self, user_id: str, *, is_owner: bool) -> dict[str, Any]:
        """The File checks tab's service line: {'state','reason','lookups_last_24h',
        'lookups_per_day','your_lookups_last_24h','your_lookups_per_day','upload_max_bytes'}.
        The reason is the owner's sentence for an admin and "not set up" for everyone else."""
        access = await self._read_access()
        reason: Optional[str] = None
        if not access.on:
            if not is_owner:
                reason = NOT_SET_UP_SENTENCE
            else:
                reason = OFF_SENTENCE if access.state == "off" else NO_KEY_SENTENCE
        last_24h = mine = 0
        limits = access.limits
        try:
            usage = await self.quota.usage(user_id)
            last_24h, mine, limits = usage.last_24h, usage.user_last_24h, usage.limits
        except Exception as exc:
            logger.warning("file_reputation_usage_unreadable", error_type=type(exc).__name__)
        return {
            "state": "on" if access.on else access.state,
            "reason": reason,
            "lookups_last_24h": last_24h,
            "lookups_per_day": limits.per_day,
            "your_lookups_last_24h": mine,
            "your_lookups_per_day": limits.per_user_per_day,
            "upload_max_bytes": PAGE_UPLOAD_MAX_BYTES,
        }

    async def remote_configured(self) -> bool:
        """A VirusTotal key exists and file_reputation is on (S2, S3)."""
        return (await self._read_access()).on

    # -- the shared lookup --------------------------------------------------------------------

    async def _lookup(
        self,
        digest: str,
        access: _Access,
        *,
        priority: Priority,
        user_id: Optional[str],
        source: str,
        wait_s: float,
    ) -> tuple[FileVerdict, Optional[_Lookup]]:
        """VirusTotal's answer about *digest* for one caller: the cache, else the lookup already
        on its way (shared), else a new one under the quota (waiting up to *wait_s* for the
        minute window). The second value is the lookup still running when this caller stopped
        waiting for it, so its answer can be written to the caller's row when it lands."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, wait_s)
        for _attempt in range(3):
            cached = await self.store.cached_verdict(digest)
            if cached is not None:
                return cached.file_verdict(), None
            lookup = self._inflight.get(digest)
            started = lookup is None
            if lookup is None:
                lookup = _Lookup(loop.create_future(), loop.create_future())
                self._inflight[digest] = lookup
                self._spawn(
                    self._run_lookup(
                        digest,
                        lookup,
                        access,
                        priority=priority,
                        user_id=user_id,
                        source=source,
                        wait_s=max(0.0, deadline - loop.time()),
                    )
                )
            if not lookup.sent.done():
                if started:
                    # This caller's own reservation is bounded by its wait already.
                    await asyncio.shield(lookup.sent)
                else:
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(lookup.sent),
                            timeout=max(0.0, deadline - loop.time()) + _JOIN_SLACK_S,
                        )
                    except asyncio.TimeoutError:
                        pending = FileVerdict.not_checked(
                            digest, "minute_limit", limit=access.limits.per_minute
                        )
                        return pending, lookup
            verdict = await asyncio.shield(lookup.done)
            if not started and verdict.reason in _PER_CALLER_REASONS:
                # Someone else's share or wait decided that; ask again for this caller.
                continue
            return verdict, None
        return FileVerdict.not_checked(digest, "minute_limit", limit=access.limits.per_minute), None

    async def _run_lookup(
        self,
        digest: str,
        lookup: _Lookup,
        access: _Access,
        *,
        priority: Priority,
        user_id: Optional[str],
        source: str,
        wait_s: float,
    ) -> None:
        result = FileVerdict.not_checked(digest, "service_error")
        try:
            result = await self._fetch(
                digest,
                lookup,
                access,
                priority=priority,
                user_id=user_id,
                source=source,
                wait_s=wait_s,
            )
        except Exception as exc:
            logger.warning("file_reputation_lookup_failed", error_type=type(exc).__name__)
        finally:
            if self._inflight.get(digest) is lookup:
                del self._inflight[digest]
            if not lookup.sent.done():
                lookup.sent.set_result(None)
            if not lookup.done.done():
                lookup.done.set_result(result)

    async def _fetch(
        self,
        digest: str,
        lookup: _Lookup,
        access: _Access,
        *,
        priority: Priority,
        user_id: Optional[str],
        source: str,
        wait_s: float,
    ) -> FileVerdict:
        key = access.key or ""
        if self._key_rejection.blocks(key, self._clock()):
            # VirusTotal refused this key a few minutes ago: no request until the pause ends.
            return FileVerdict.not_checked(digest, "key_rejected")
        cached = await self.store.cached_verdict(digest)
        if cached is not None:
            return cached.file_verdict()
        refusal = await self.quota.acquire(
            kind="lookup", priority=priority, user_id=user_id, wait_s=wait_s
        )
        if refusal is not None:
            return FileVerdict.not_checked(
                digest, refusal, limit=_limit_for(refusal, access.limits)
            )
        if not lookup.sent.done():
            lookup.sent.set_result(None)
        try:
            report = await self._client.lookup(key, digest)
        except VirusTotalError as exc:
            reason = self._vt_failure(exc, key)
            await self._audit_checked(
                user_id, digest, source=source, priority=priority, origin="lookup", reason=reason
            )
            return FileVerdict.not_checked(digest, reason)
        self.quota.recovered()
        self._key_rejection.clear()
        await self.store.cache_verdict(digest, report, origin="lookup")
        verdict = verdict_from_report(digest, report)
        await self._audit_checked(
            user_id, digest, source=source, priority=priority, origin="lookup", verdict=verdict
        )
        return verdict

    def _vt_failure(self, exc: VirusTotalError, key: str) -> str:
        """The reason code for a request VirusTotal did not answer, after the side effects it
        calls for: a 429 starts the cool-down; a refused key pauses that key and, at most once a
        day, tells the owners."""
        if exc.code == "virustotal_limit":
            self.quota.cool_down()
            return "virustotal_limit"
        if exc.code == "key_rejected":
            if self._key_rejection.trip(key, self._clock()):
                self._spawn(self._alert_key_rejected(exc.status_code))
            return "key_rejected"
        if exc.code in ("too_large", "empty"):
            return exc.code
        return "service_error"

    async def _alert_key_rejected(self, status_code: Optional[int]) -> None:
        """Tell every owner (admin) that VirusTotal refused the saved key, through their own
        chats, with one file_reputation_key_rejected row each (review FEA-SF8)."""
        try:
            async with self._session_factory() as session:
                owners = (
                    (await session.execute(select(User.id).where(User.is_admin.is_(True))))
                    .scalars()
                    .all()
                )
        except Exception as exc:
            logger.warning("file_reputation_owner_lookup_failed", error_type=type(exc).__name__)
            return
        for owner in owners:
            delivered = await self._deliver(str(owner), alerts.KEY_REJECTED_ALERT)
            await self._write_audit(
                {
                    "event": "file_reputation_key_rejected",
                    "user_id": str(owner),
                    "tool": TOOL_CHECK,
                    "arguments": {"status_code": status_code, "delivered": delivered},
                }
            )

    # -- one person's row ---------------------------------------------------------------------

    async def _check(
        self,
        user_id: str,
        digest: str,
        access: _Access,
        *,
        name: Optional[str],
        size_bytes: Optional[int],
        media_type: Optional[str],
        source: str,
        source_ref: Optional[Mapping[str, str]],
        source_key_value: Optional[str],
        priority: Priority,
        wait_s: float,
        alert: AlertMode,
    ) -> FileVerdict:
        row = await self.store.upsert_check(
            user_id,
            digest,
            name=name,
            media_type=media_type,
            size_bytes=size_bytes,
            source=source,
            priority=priority,
            source_ref=source_ref,
            source_key=source_key_value,
        )
        verdict, pending = await self._lookup(
            digest, access, priority=priority, user_id=user_id, source=row.source, wait_s=wait_s
        )
        return await self._settle(row, verdict, alert=alert, pending=pending, access=access)

    async def _settle(
        self,
        row: CheckRow,
        verdict: FileVerdict,
        *,
        alert: AlertMode,
        pending: Optional[_Lookup] = None,
        access: Optional[_Access] = None,
    ) -> FileVerdict:
        """Write *verdict* to *row*, tell the person about a flagged verdict once, and answer the
        verdict with the row's id and whether an upload could be offered."""
        settled = await self.store.settle_check(row.user_id, row.id, verdict)
        if settled is None:  # forgotten meanwhile: nothing to write, nobody to tell
            return replace(verdict, check_id=None, can_upload=False)
        if pending is not None:
            self._finish_late(settled, pending)
        if verdict.flagged:
            await self._tell_flagged(settled, verdict, mode=alert)
        if access is None:
            access = await self._read_access()
        can_upload = (
            verdict.verdict == "unknown" and access.on and self._can_offer_upload(settled)
        )
        return replace(verdict, check_id=settled.id, can_upload=can_upload)

    def _finish_late(self, row: CheckRow, lookup: _Lookup) -> None:
        """When the lookup this row stopped waiting for lands, write its answer to the row (a
        late answer: a flagged one is told by the service)."""

        def landed(future: asyncio.Future[FileVerdict]) -> None:
            if future.cancelled():
                return
            self._spawn(self._settle(row, future.result(), alert="service"))

        lookup.done.add_done_callback(landed)

    async def _tell_flagged(self, row: CheckRow, verdict: FileVerdict, *, mode: AlertMode) -> None:
        if not await self.store.claim_alert(row.user_id, row.id, verdict.verdict):
            return  # this verdict was already told for this row
        if mode == "caller":
            return  # the caller tells the person (and the claim keeps the service quiet)
        text = alerts.flagged_alert(row.name, verdict)
        if text is None:
            return
        delivered = await self._deliver(row.user_id, text)
        await self._write_audit(
            {
                "event": "file_reputation_alerted",
                "user_id": row.user_id,
                "tool": TOOL_CHECK,
                "arguments": {
                    "sha256": row.sha256,
                    "verdict": verdict.verdict,
                    "delivered": delivered,
                },
            }
        )

    def _server_has_bytes(self, row: CheckRow) -> bool:
        return self.holder.has(row.user_id, row.sha256) or row.has_source_ref

    def _may_send(self, row: CheckRow) -> bool:
        """The personal-document rule (review SEC-F2): a file may be sent from a chat card only
        when it is a risky kind (by its name and declared type) or the owner picked it on the
        Security page."""
        return kinds.is_risky(row.name, row.media_type, None) or self.holder.has_explicit(
            row.user_id, row.sha256
        )

    def _can_offer_upload(self, row: CheckRow) -> bool:
        return self._server_has_bytes(row) and self._may_send(row)

    # -- lookups (used by the toolkit, routes, S2, S3) ----------------------------------------

    async def check_hash(
        self,
        user_id: str,
        sha256: str,
        *,
        name: str = "file",
        size_bytes: Optional[int] = None,
        media_type: Optional[str] = None,
        source: str = "hash",
        source_ref: Optional[dict[str, str]] = None,
        priority: Priority = "explicit",
        wait_s: float = 0.0,
        alert: Literal["service", "caller"] = "service",
    ) -> FileVerdict:
        """Look one fingerprint up for *user_id*: the cache, then VirusTotal under the quota.
        Never raises; never answers 'safe'. With alert='caller' the caller promises to tell the
        user about a flagged verdict it receives here (S2's mail alert), so the service does
        not; a verdict that arrives later from the queue is alerted by the service."""
        digest = byte_sink.normalise_sha256(sha256)
        if digest is None:
            shown = sha256[:64] if isinstance(sha256, str) else ""
            return FileVerdict(sha256=shown, verdict="not_checked", reason="invalid_fingerprint")
        try:
            access = await self._read_access()
            if not access.on:
                return FileVerdict.not_checked(digest, access.reason)
            return await self._check(
                user_id,
                digest,
                access,
                name=sanitize_display_name(name) if name else None,
                size_bytes=size_bytes,
                media_type=media_type,
                source=source if source in SOURCES else "hash",
                source_ref=source_ref,
                source_key_value=None,
                priority=priority,
                wait_s=wait_s,
                alert=alert,
            )
        except Exception as exc:
            logger.warning("file_reputation_check_failed", error_type=type(exc).__name__)
            return FileVerdict.not_checked(digest, "service_error")

    async def check_bytes(
        self,
        user_id: str,
        data: bytes,
        *,
        name: str,
        media_type: Optional[str],
        source: str,
        priority: Priority = "explicit",
        wait_s: float = 0.0,
        alert: Literal["service", "caller"] = "service",
        hold: bool = False,
    ) -> FileVerdict:
        """Hash (in a thread above 1 MB) and check_hash. hold=True keeps the bytes in the holder
        when the answer is unknown (for an upload card), and only for a risky kind: a personal
        document is never held."""
        if not isinstance(data, (bytes, bytearray)) or not data:
            return FileVerdict.not_checked(byte_sink.sha256_hex(b""), "empty")
        try:
            raw = bytes(data)
            digest = await byte_sink.sha256_hex_async(raw)
            access = await self._read_access()
            if not access.on:
                return FileVerdict.not_checked(digest, access.reason)
            shown = sanitize_display_name(name)
            held = hold and kinds.is_risky(shown, media_type, raw[: kinds.HEAD_BYTES])
            if held:
                # Provisional: dropped below as soon as VirusTotal turns out to know the file.
                self.holder.put(user_id, digest, raw, ttl_s=SCREEN_HOLD_S)
            verdict = await self._check(
                user_id,
                digest,
                access,
                name=shown,
                size_bytes=len(raw),
                media_type=media_type,
                source=source if source in SOURCES else "hash",
                source_ref=None,
                source_key_value=None,
                priority=priority,
                wait_s=wait_s,
                alert=alert,
            )
            if held and verdict.checked and verdict.verdict != "unknown":
                self._drop_unless_picked(user_id, digest)
            return verdict
        except Exception as exc:
            logger.warning("file_reputation_check_failed", error_type=type(exc).__name__)
            return FileVerdict.not_checked("", "service_error")

    def _drop_unless_picked(self, user_id: str, digest: str) -> None:
        if not self.holder.has_explicit(user_id, digest):
            self.holder.drop(user_id, digest)

    async def check_mail_attachment(
        self,
        user_id: str,
        *,
        hash_tool: str,
        message_id: str,
        attachment_id: str,
        priority: Priority = "automatic",
        wait_s: float = 0.0,
        alert: Literal["service", "caller"] = "caller",
    ) -> FileVerdict:
        """For S2 (and nothing stops a model turn): run <hash_tool> ('google_workspace[__slug].
        get_attachment_hash' or 'microsoft[__slug].get_attachment_hash') through the executor
        (scopes, rate limits, network policy apply), record the encrypted source (risky kinds
        only, like a Telegram file id) and the HMAC source_key, then check_hash.
        too_large -> not_checked('too_large')."""
        try:
            access = await self._read_access()
            if not access.on:
                return FileVerdict.not_checked("", access.reason)
            family = mail_family(hash_tool)
            message, part = _clean_id(message_id), _clean_id(attachment_id)
            if family is None or message is None or part is None or self._connector_read is None:
                return FileVerdict.not_checked("", "service_error")
            answer = await self._connector_read(
                hash_tool, {"message_id": message, _MAIL_ID_PARAM[family]: part}, user_id
            )
            facts = _hash_result(answer)
            if facts is None:
                return FileVerdict.not_checked("", "service_error")
            if facts.get("too_large") is True:
                return FileVerdict.not_checked("", "too_large")
            digest = byte_sink.normalise_sha256(facts.get("sha256"))
            if digest is None:
                return FileVerdict.not_checked("", "service_error")
            filename = facts.get("filename")
            mime = facts.get("mime_type")
            size = facts.get("size")
            shown = sanitize_display_name(filename) if isinstance(filename, str) and filename else None
            media = mime if isinstance(mime, str) and mime else None
            # Like a Telegram file id, a re-fetch reference is kept only for a risky kind: a
            # personal document is never sent from a chat card, so nothing needs to fetch it.
            ref = (
                {"tool": hash_tool, "message_id": message, "attachment_id": part}
                if kinds.is_risky_attachment(shown, media)
                else None
            )
            return await self._check(
                user_id,
                digest,
                access,
                name=shown,
                size_bytes=size if isinstance(size, int) and not isinstance(size, bool) else None,
                media_type=media,
                source=_MAIL_SOURCE[family],
                source_ref=ref,
                source_key_value=message_source_key(family, message),
                priority=priority,
                wait_s=wait_s,
                alert=alert,
            )
        except Exception as exc:
            logger.warning("file_reputation_mail_check_failed", error_type=type(exc).__name__)
            return FileVerdict.not_checked("", "service_error")

    # -- intake (services.files.intake.FileScreen) --------------------------------------------

    async def screen(self, user_id: str, inbound: Any) -> None:
        """Every file a person sends: when the switch is on with a key, hash it, upsert the row
        (source web|telegram|slack; Telegram keeps its file_id encrypted, risky kinds only),
        hold risky web/Slack bytes, and start an automatic lookup in the background. Returns at
        once; never raises."""
        try:
            data = getattr(inbound, "data", b"")
            if not isinstance(data, (bytes, bytearray)) or not data:
                return
            access = await self._read_access()
            if not access.on:
                return
            raw = bytes(data)
            source = getattr(inbound, "source", "web")
            source = source if source in _CHANNEL_SOURCES else "web"
            digest = await byte_sink.sha256_hex_async(raw)
            name = sanitize_display_name(getattr(inbound, "name", None))
            declared = getattr(inbound, "media_type", None)
            media = declared[:100] if isinstance(declared, str) and declared else None
            risky = kinds.is_risky(name, media, raw[: kinds.HEAD_BYTES])
            ref: Optional[dict[str, str]] = None
            file_id = _clean_id(getattr(inbound, "source_ref", None))
            if source == "telegram" and risky and file_id is not None and file_id != "None":
                ref = {"telegram_file_id": file_id}
            if risky and source in ("web", "slack"):
                self.holder.put(user_id, digest, raw, ttl_s=SCREEN_HOLD_S)
            row = await self.store.upsert_check(
                user_id,
                digest,
                name=name,
                media_type=media,
                size_bytes=len(raw),
                source=source,
                priority="automatic",
                source_ref=ref,
            )
            task = self._spawn(self._screen_lookup(row, access, risky=risky))
            self._screening.setdefault(user_id, set()).add(task)

            def forget(done: asyncio.Future[Any], user: str = user_id) -> None:
                tasks = self._screening.get(user)
                if tasks is not None:
                    tasks.discard(done)
                    if not tasks:
                        self._screening.pop(user, None)

            task.add_done_callback(forget)
        except Exception as exc:
            logger.warning("file_reputation_screen_failed", error_type=type(exc).__name__)

    async def _screen_lookup(self, row: CheckRow, access: _Access, *, risky: bool) -> None:
        try:
            verdict, pending = await self._lookup(
                row.sha256,
                access,
                priority="automatic",
                user_id=row.user_id,
                source=row.source,
                wait_s=0.0,
            )
            result = await self._settle(
                row, verdict, alert="service", pending=pending, access=access
            )
            if risky and result.checked and result.verdict != "unknown":
                self._drop_unless_picked(row.user_id, row.sha256)
        except Exception as exc:
            logger.warning("file_reputation_screen_failed", error_type=type(exc).__name__)

    async def annotate(
        self, user_id: str, entries: list[dict[str, Any]], *, wait_s: float = 3.0
    ) -> list[dict[str, Any]]:
        """Attachment entries (kind 'file') with 'file_check' added for flagged uploads, waiting at
        most wait_s in all for lookups still running. One query; never raises."""
        try:
            file_ids = [
                str(entry["file_id"])
                for entry in entries
                if isinstance(entry, dict)
                and entry.get("kind") == "file"
                and isinstance(entry.get("file_id"), str)
            ]
            if not file_ids:
                return entries
            running = set(self._screening.get(user_id, ()))
            if running and wait_s > 0:
                await asyncio.wait(running, timeout=wait_s)
            flagged = await self.store.flagged_uploads(user_id, file_ids)
            if not flagged:
                return entries
            annotated: list[dict[str, Any]] = []
            for entry in entries:
                hit = None
                if isinstance(entry, dict) and entry.get("kind") == "file":
                    hit = flagged.get(str(entry.get("file_id")))
                if hit is None:
                    annotated.append(entry)
                    continue
                check = FileVerdict(
                    sha256="",
                    verdict=hit.verdict,  # type: ignore[arg-type]
                    malicious=hit.malicious,
                    suspicious=hit.suspicious,
                    engines=hit.engines,
                    threat_label=hit.threat_label,
                )
                annotated.append({**entry, "file_check": check.as_entry()})
            return annotated
        except Exception as exc:
            logger.warning("file_reputation_annotate_failed", error_type=type(exc).__name__)
            return entries

    # -- uploads ------------------------------------------------------------------------------

    async def _known_verdict(self, row: CheckRow) -> Optional[str]:
        """VirusTotal's freshest answer about the row's file: the cache, else the row's own."""
        cached = await self.store.cached_verdict(row.sha256)
        if cached is not None:
            return cached.verdict
        return row.verdict if row.verdict in LOOKUP_VERDICTS else None

    async def upload_precheck(self, user_id: str, sha256: str) -> Optional[dict[str, Any]]:
        """The refusal before an upload card ({'ok': False, 'rule', 'error'}), or None: no row of
        this person's for the file, a file VirusTotal has not answered about or already knows,
        a personal document nobody picked on the Security page, or bytes that can no longer be
        had."""
        digest = byte_sink.normalise_sha256(sha256)
        if digest is None:
            return _refusal("invalid_arguments", UPLOAD_INVALID)
        row = await self.store.check_for(user_id, digest)
        if row is None:
            return _refusal("unknown_file", UPLOAD_UNKNOWN_FILE)
        if row.state == "analysing":
            return _refusal("already_known", UPLOAD_ALREADY_SENT)
        known = await self._known_verdict(row)
        if known is None:
            return _refusal("not_checked_yet", UPLOAD_NOT_CHECKED_YET)
        if known != "unknown":
            return _refusal("already_known", UPLOAD_ALREADY_KNOWN)
        if not self._may_send(row):
            return _refusal("personal_document", UPLOAD_PERSONAL_DOCUMENT)
        if not self._server_has_bytes(row):
            return _refusal("bytes_unavailable", UPLOAD_BYTES_UNAVAILABLE)
        return None

    async def upload_facts(self, user_id: str, sha256: str) -> dict[str, Any]:
        """The file facts an upload card stores under ``_upload`` ({'sha256', 'name',
        'size_bytes', 'source', 'check_id'}), keeping held bytes for the card's life. The name
        is ``card_name`` output (ASCII, look-alike letters escaped, defanged), so the stored
        arguments' re-scan at approval never meets a mixed-script word in it and cannot make
        the card unapprovable. ``LookupError`` when the person has no check of this file."""
        digest = byte_sink.normalise_sha256(sha256)
        row = await self.store.check_for(user_id, digest) if digest else None
        if row is None or digest is None:
            raise LookupError("no check of this file")
        self.holder.pin(user_id, digest, ttl_s=CARD_PIN_S)
        return {
            "sha256": digest,
            "name": card_name(row.name),
            "size_bytes": row.size_bytes,
            "source": row.source,
            "check_id": row.id,
        }

    async def _refuse_upload(
        self, user_id: str, digest: str, rule: str, message: str, *, row: Optional[CheckRow]
    ) -> dict[str, Any]:
        """One approved upload that sent nothing: a refusal row, the row back to ``checked``."""
        await self._write_audit(
            {
                "event": "file_reputation_upload_refused",
                "user_id": user_id,
                "tool": TOOL_UPLOAD,
                "rule": rule,
                "arguments": {
                    "sha256": digest,
                    "rule": rule,
                    "source": row.source if row is not None else None,
                },
            }
        )
        if row is not None:
            await self.store.end_upload_wait(user_id, row.id)
        return {"ok": False, "rule": rule, "error": message}

    async def upload(self, user_id: str, sha256: str, facts: Mapping[str, Any]) -> dict[str, Any]:
        """Send one approved file (S10 4.3 G): the switch and key again, the person's row, the
        bytes fetched again (holder, Telegram, the mail connector), hashed again and compared
        with the card, the quota, then VirusTotal. Fails closed: anything missing or different
        sends nothing and writes one refusal row."""
        digest = byte_sink.normalise_sha256(sha256)
        card_sha = (
            byte_sink.normalise_sha256(facts.get("sha256")) if isinstance(facts, Mapping) else None
        )
        if digest is None or card_sha != digest:
            return _refusal("invalid_arguments", UPLOAD_INVALID)
        access = await self._read_access()
        if not access.on:
            message = f"Not sent: {reason_sentence(access.reason)}."
            return await self._refuse_upload(user_id, digest, access.reason, message, row=None)
        row = await self.store.check_for(user_id, digest)
        if row is None:
            return await self._refuse_upload(
                user_id, digest, "unknown_file", UPLOAD_UNKNOWN_FILE, row=None
            )
        if row.state == "analysing":
            return await self._refuse_upload(
                user_id, digest, "already_known", UPLOAD_ALREADY_SENT, row=None
            )
        known = await self._known_verdict(row)
        if known is not None and known != "unknown":
            return await self._refuse_upload(
                user_id, digest, "already_known", UPLOAD_ALREADY_KNOWN, row=row
            )
        data = await self._bytes_for(user_id, row)
        if data is None:
            return await self._refuse_upload(
                user_id, digest, "bytes_unavailable", UPLOAD_BYTES_UNAVAILABLE, row=row
            )
        if await byte_sink.sha256_hex_async(data) != digest:
            return await self._refuse_upload(
                user_id, digest, "file_changed", UPLOAD_FILE_CHANGED, row=row
            )
        if len(data) > VT_MAX_UPLOAD_BYTES:
            return await self._refuse_upload(user_id, digest, "too_large", UPLOAD_TOO_LARGE, row=row)
        key = access.key or ""
        if self._key_rejection.blocks(key, self._clock()):
            message = f"Not sent: {reason_sentence('key_rejected')}."
            return await self._refuse_upload(user_id, digest, "key_rejected", message, row=row)
        refusal = await self.quota.acquire(
            kind="upload", priority="explicit", user_id=user_id, wait_s=UPLOAD_WAIT_S
        )
        if refusal is not None:
            sentence = reason_sentence(refusal, limit=_limit_for(refusal, access.limits))
            return await self._refuse_upload(
                user_id, digest, refusal, f"Not sent: {sentence}.", row=row
            )
        try:
            analysis_id = await self._client.upload(key, data)
        except VirusTotalError as exc:
            rule = self._vt_failure(exc, key)
            message = f"VirusTotal did not confirm it received the file ({exc})."
            if exc.maybe_received:
                # An approval is single-use, so this is never retried on its own.
                message += " It may have been received."
            refused = await self._refuse_upload(user_id, digest, rule, message, row=row)
            refused["maybe_received"] = exc.maybe_received
            return refused
        self.quota.recovered()
        self._key_rejection.clear()
        now = self._clock()
        await self.store.mark_uploaded(
            user_id,
            row.id,
            analysis_id=analysis_id,
            now=now,
            next_poll_at=now + timedelta(seconds=FIRST_POLL_S),
        )
        await self.store.forget_verdict(digest)
        self.holder.drop(user_id, digest)
        await self._write_audit(
            {
                "event": "file_reputation_uploaded",
                "user_id": user_id,
                "tool": TOOL_UPLOAD,
                "arguments": {"sha256": digest, "size_bytes": len(data), "source": row.source},
            }
        )
        if self._kick is not None:
            try:
                self._kick()
            except Exception as exc:
                logger.warning("file_reputation_kick_failed", error_type=type(exc).__name__)
        return {"ok": True, "status": "analysing", "sha256": digest, "message": UPLOAD_SENT}

    async def _bytes_for(self, user_id: str, row: CheckRow) -> Optional[bytes]:
        """The file's bytes for an approved upload, in this order: the holder, Telegram by its
        file id, the mail connector (through the executor, handing its bytes to the byte sink).
        None when none of them has them."""
        held = self.holder.get(user_id, row.sha256)
        if held is not None:
            return held
        if not row.has_source_ref:
            return None
        ref = await self.store.source_ref_of(user_id, row.sha256)
        if not ref:
            return None
        file_id = _clean_id(ref.get("telegram_file_id"))
        if file_id is not None:
            if self._telegram_fetch is None:
                return None
            try:
                fetched = await self._telegram_fetch(file_id, TELEGRAM_FETCH_MAX_BYTES)
            except Exception as exc:
                logger.warning(
                    "file_reputation_telegram_fetch_failed", error_type=type(exc).__name__
                )
                return None
            if isinstance(fetched, (bytes, bytearray)) and fetched:
                return bytes(fetched)
            return None
        tool = ref.get("tool")
        family = mail_family(tool)
        message, part = _clean_id(ref.get("message_id")), _clean_id(ref.get("attachment_id"))
        if family is None or message is None or part is None or self._connector_read is None:
            return None
        with byte_sink.expect(row.sha256) as sink:
            try:
                await self._connector_read(
                    tool, {"message_id": message, _MAIL_ID_PARAM[family]: part}, user_id
                )
            except Exception as exc:
                logger.warning("file_reputation_mail_fetch_failed", error_type=type(exc).__name__)
        return sink.data

    def take_upload_request_slot(self, user_id: str) -> Optional[int]:
        """One Security-page upload request of *user_id* (at most 5 an hour, in memory): None
        when it may go ahead, else the seconds until the next one may."""
        now = self._clock()
        bucket = self._upload_requests.setdefault(str(user_id), deque())
        while bucket and now - bucket[0] >= _UPLOAD_REQUEST_WINDOW:
            bucket.popleft()
        if len(bucket) >= UPLOAD_REQUESTS_PER_HOUR:
            wait = _UPLOAD_REQUEST_WINDOW - (now - bucket[0])
            return max(1, int(wait.total_seconds()) + 1)
        bucket.append(now)
        return None

    async def _pending_set(self, user_id: str) -> Optional[frozenset[str]]:
        if self._pending_ids is None:
            return None
        try:
            return frozenset(str(i) for i in await self._pending_ids(user_id))
        except Exception as exc:
            logger.warning("file_reputation_pending_unreadable", error_type=type(exc).__name__)
            return None

    async def request_upload(
        self, user_id: str, check_id: str, data: Optional[bytes]
    ) -> UploadRequestOutcome:
        """Park an upload card for one of the person's checks (S10 4.3 F). With *data* (the file
        the owner picked on the Security page) the bytes must hash to the row's fingerprint and
        are held as an explicit pick; without, the server needs its own copy or source and the
        file must not be a personal document. A card already pending is answered again."""
        row = await self.store.get_check(user_id, check_id)
        if row is None:
            return UploadRequestOutcome("refused", "No such file check.", code="not_found")
        access = await self._read_access()
        if not access.on:
            sentence = OFF_SENTENCE if access.state == "off" else NO_KEY_SENTENCE
            return UploadRequestOutcome("refused", sentence, code="service_off")
        if row.state == "upload_pending" and row.action_id:
            pending = await self._pending_set(user_id)
            if pending is None or row.action_id in pending:
                return UploadRequestOutcome(
                    "pending",
                    "An approval card to send this file is already waiting.",
                    action_id=row.action_id,
                )
            await self.store.clear_upload_pending(user_id, keep=pending)
            refreshed = await self.store.get_check(user_id, check_id)
            if refreshed is None:
                return UploadRequestOutcome("refused", "No such file check.", code="not_found")
            row = refreshed
        if row.state == "analysing":
            return UploadRequestOutcome("refused", UPLOAD_ALREADY_SENT, code="already_known")
        known = await self._known_verdict(row)
        if known is not None and known != "unknown":
            return UploadRequestOutcome("refused", UPLOAD_ALREADY_KNOWN, code="already_known")
        if known is None or row.state in ("queued", "not_checked"):
            return UploadRequestOutcome("refused", UPLOAD_NOT_CHECKED_YET, code="not_checked_yet")
        if data is not None:
            if len(data) > PAGE_UPLOAD_MAX_BYTES:
                return UploadRequestOutcome(
                    "refused",
                    "The file is larger than 20 MB, too large to send from here.",
                    code="too_large",
                )
            if await byte_sink.sha256_hex_async(bytes(data)) != row.sha256:
                return UploadRequestOutcome(
                    "refused",
                    "That is a different file: its fingerprint does not match this check.",
                    code="file_changed",
                )
            # The owner chose this file on the page: the one way a personal document may go.
            self.holder.put(user_id, row.sha256, bytes(data), ttl_s=PAGE_HOLD_S, explicit=True)
        elif not self._can_offer_upload(row):
            return UploadRequestOutcome("refused", "Pick the file again to send it.", code="needs_file")
        outcome = await self._park_upload_card(user_id, row)
        if outcome.status != "parked" and data is not None:
            # No card holds the file the owner just picked: it is not kept in memory for one.
            self.holder.drop(user_id, row.sha256)
        return outcome

    async def _park_upload_card(self, user_id: str, row: CheckRow) -> UploadRequestOutcome:
        if self._park_card is None:
            return UploadRequestOutcome(
                "refused", "Uploads to VirusTotal are not set up in this process.", code="not_wired"
            )
        try:
            parked = await self._park_card(
                user_id=user_id,
                tool_name=TOOL_UPLOAD,
                arguments={"sha256": row.sha256},
                origin=f"file_check:{row.id}",
                ttl_minutes=UPLOAD_CARD_TTL_MINUTES,
            )
        except Exception as exc:
            logger.warning("file_reputation_park_failed", error_type=type(exc).__name__)
            return UploadRequestOutcome(
                "refused",
                "The approval card could not be made. Try again in a moment.",
                code="refused",
            )
        action_id = getattr(parked, "action_id", None)
        if isinstance(action_id, str) and action_id:
            await self.store.mark_upload_pending(user_id, row.id, action_id)
            expires = getattr(parked, "expires_at", None)
            return UploadRequestOutcome(
                "parked",
                f'Approve the card to send "{row.name}" to VirusTotal.',
                action_id=action_id,
                expires_at=expires if isinstance(expires, datetime) else None,
            )
        rule = str(getattr(parked, "rule", "") or "")
        reason = str(getattr(parked, "reason", "") or "The upload was refused.")
        code = {
            "personal_document": "needs_file",
            "bytes_unavailable": "needs_file",
            "already_known": "already_known",
            "not_checked_yet": "not_checked_yet",
        }.get(rule, "refused")
        return UploadRequestOutcome("refused", reason, code=code)

    # -- rows ---------------------------------------------------------------------------------

    def _row_out(self, row: CheckRow, access: _Access) -> dict[str, Any]:
        """One row as the Security tab reads it. Never the source reference, the source key,
        the analysis id or anything key-shaped."""
        verdict = row.verdict if row.verdict in LOOKUP_VERDICTS else None
        answer = row.file_verdict(limit=_limit_for(row.reason, access.limits))
        if row.state == "upload_pending":
            summary = "Waiting for your approval to send it to VirusTotal."
        elif row.state == "analysing":
            summary = "Sent to VirusTotal; the scan is running."
        else:
            summary = answer.summary()
        can_upload = access.on and row.state == "checked" and verdict == "unknown"
        flagged_by: Optional[int] = None
        if verdict is not None:
            flagged_by = FileVerdict(
                sha256=row.sha256,
                verdict=verdict,  # type: ignore[arg-type]
                malicious=row.malicious or 0,
                suspicious=row.suspicious or 0,
            ).flagged_by
        return {
            "id": row.id,
            "sha256": row.sha256,
            "name": row.name,
            "source": row.source,
            "size_bytes": row.size_bytes,
            "state": row.state,
            "verdict": verdict,
            "flagged_by": flagged_by,
            "engines": row.engines if verdict is not None else None,
            "threat_label": row.threat_label if verdict is not None else None,
            "summary": summary,
            "reason": row.reason if row.state in ("queued", "not_checked") else None,
            "can_upload": can_upload,
            "upload_needs_file": can_upload and not self._can_offer_upload(row),
            "action_id": row.action_id if row.state == "upload_pending" else None,
            "checked_at": row.checked_at.isoformat() if row.checked_at else None,
            "updated_at": row.updated_at.isoformat(),
        }

    async def list_checks(self, user_id: str, limit: int) -> list[dict[str, Any]]:
        """*user_id*'s checks, last sighting first. A row waiting for a card that is no longer
        pending (denied, expired) goes back to ``checked`` first."""
        pending = await self._pending_set(user_id)
        if pending is not None:
            await self.store.clear_upload_pending(user_id, keep=pending)
        access = await self._read_access()
        rows = await self.store.list_checks(user_id, limit)
        return [self._row_out(row, access) for row in rows]

    async def get_check(self, user_id: str, check_id: str) -> Optional[dict[str, Any]]:
        """One of *user_id*'s checks as the Security tab reads it, or None."""
        row = await self.store.get_check(user_id, check_id)
        if row is None:
            return None
        return self._row_out(row, await self._read_access())

    async def forget(self, user_id: str, check_id: str) -> bool:
        """Forget one of *user_id*'s checks and any bytes held for it; False when it is not
        theirs (or does not exist)."""
        sha256 = await self.store.delete_check(user_id, check_id)
        if sha256 is None:
            return False
        self.holder.drop(user_id, sha256)
        return True

    # -- background ---------------------------------------------------------------------------

    async def sweep(self) -> int:
        """Purge (hourly), then, when on with a key: queued lookups (explicit first) while the
        minute window has room, then due analysis polls. Returns the work done."""
        async with self._sweep_lock:
            work = 0
            now = self._clock()
            if self._last_purge is None or now - self._last_purge >= PURGE_EVERY:
                purged = await self.store.purge(now=now)
                self._last_purge = now
                work += purged.total
                self._forget_old_requests(now)
            access = await self._read_access()
            if not access.on:
                return work
            work += await self._sweep_queued(access)
            work += await self._sweep_polls(access)
            return work

    def _forget_old_requests(self, now: datetime) -> None:
        for user, bucket in list(self._upload_requests.items()):
            while bucket and now - bucket[0] >= _UPLOAD_REQUEST_WINDOW:
                bucket.popleft()
            if not bucket:
                self._upload_requests.pop(user, None)

    def _paused(self, key: str) -> bool:
        return self.quota.cooling_down_for() > 0 or self._key_rejection.blocks(key, self._clock())

    async def _sweep_queued(self, access: _Access) -> int:
        if self._paused(access.key or ""):
            return 0
        usage = await self.quota.usage(None)
        room = usage.limits.per_minute - usage.last_minute
        if room <= 0:
            return 0
        rows = await self.store.claim_queued(limit=room, claim_s=CLAIM_S)
        done = 0
        for index, row in enumerate(rows):
            verdict, pending = await self._lookup(
                row.sha256,
                access,
                priority="explicit" if row.priority == "explicit" else "automatic",
                user_id=row.user_id,
                source=row.source,
                wait_s=0.0,
            )
            await self._settle(row, verdict, alert="service", pending=pending, access=access)
            done += 1
            if verdict.verdict == "pending" and verdict.reason in (
                "minute_limit",
                "virustotal_limit",
            ):
                for rest in rows[index + 1 :]:
                    await self.store.release_claim(rest.user_id, rest.id)
                break
        return done

    async def _sweep_polls(self, access: _Access) -> int:
        key = access.key or ""
        if self._paused(key):
            return 0
        rows = await self.store.claim_due_polls(limit=POLLS_PER_SWEEP, claim_s=CLAIM_S)
        done = 0
        for index, row in enumerate(rows):
            refusal = await self.quota.acquire(
                kind="analysis", priority="explicit", user_id=row.user_id, wait_s=0.0
            )
            if refusal is not None:
                # No room now: this poll and the rest wait for the next sweep.
                for rest in rows[index:]:
                    await self.store.release_claim(rest.user_id, rest.id)
                break
            done += 1
            if await self._poll(row, key):
                for rest in rows[index + 1 :]:
                    await self.store.release_claim(rest.user_id, rest.id)
                break
        return done

    async def _poll(self, row: CheckRow, key: str) -> bool:
        """One analysis poll of an uploaded file; True when the sweep should stop polling now
        (VirusTotal asked to slow down or refused the key)."""
        report: Optional[VtFileReport] = None
        try:
            analysis = await self._client.analysis(key, row.analysis_id or "")
            if analysis.status == "completed" and analysis.report is not None:
                if analysis.sha256 is not None and analysis.sha256 != row.sha256:
                    # A finished scan of some other file says nothing about this one.
                    raise VirusTotalError("service_error", error_type="other_file")
                report = analysis.report
        except ValueError:
            await self._end_scan(row, FileVerdict.not_checked(row.sha256, "service_error"))
            return False
        except VirusTotalError as exc:
            reason = self._vt_failure(exc, key)
            await self._audit_checked(
                row.user_id,
                row.sha256,
                source=row.source,
                priority="explicit",
                origin="analysis",
                reason=reason,
            )
            if reason in ("virustotal_limit", "key_rejected"):
                await self.store.release_claim(row.user_id, row.id)
                return True
            await self._count_poll(row)
            return False
        if report is None:
            await self._audit_checked(
                row.user_id,
                row.sha256,
                source=row.source,
                priority="explicit",
                origin="analysis",
                reason="analysis_in_progress",
            )
            await self._count_poll(row)
            return False
        self.quota.recovered()
        self._key_rejection.clear()
        await self.store.cache_verdict(row.sha256, report, origin="analysis")
        verdict = verdict_from_report(row.sha256, report)
        await self._audit_checked(
            row.user_id,
            row.sha256,
            source=row.source,
            priority="explicit",
            origin="analysis",
            verdict=verdict,
        )
        await self._end_scan(row, verdict)
        return False

    async def _count_poll(self, row: CheckRow) -> None:
        polls = row.polls + 1
        if polls >= MAX_POLLS:
            await self._end_scan(row, FileVerdict.not_checked(row.sha256, "analysis_timeout"))
            return
        await self.store.record_poll(
            row.user_id,
            row.id,
            polls=polls,
            next_poll_at=self._clock() + timedelta(seconds=NEXT_POLL_S),
        )

    async def _end_scan(self, row: CheckRow, verdict: FileVerdict) -> None:
        """A scan that finished (or never will): the row's answer, and one message to its person
        (the finished wording, the flagged wording, or the timeout)."""
        settled = await self.store.settle_check(row.user_id, row.id, verdict, end_upload=True)
        if settled is None:
            return
        told = verdict.verdict if verdict.checked else (verdict.reason or "not_checked")
        if verdict.checked:
            text = alerts.analysis_done_alert(row.name, verdict)
        elif verdict.reason == "analysis_timeout":
            text = alerts.analysis_timeout_alert(row.name)
        else:
            return
        if not await self.store.claim_alert(row.user_id, row.id, told):
            return
        delivered = await self._deliver(row.user_id, text)
        await self._write_audit(
            {
                "event": "file_reputation_alerted",
                "user_id": row.user_id,
                "tool": TOOL_CHECK,
                "arguments": {
                    "sha256": row.sha256,
                    "verdict": verdict.verdict,
                    "delivered": delivered,
                },
            }
        )
