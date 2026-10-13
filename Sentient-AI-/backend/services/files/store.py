"""Stores the text Crawler extracted from a user's uploaded files, encrypted,
with a per-user quota, an hourly rate and a 30-day expiry.

Why it exists: an upload is read once, in the sandbox, and kept as its
sections so files.read can page through it later. Only that text is kept,
as ``core.security.encrypt_credentials(json.dumps({"v": 1, "sections":
[...]}))`` (AES-GCM under ENCRYPTION_KEY); the original bytes never are.
Secrets in the text are not masked here: the text is encrypted at rest, and
the F6 floors (model egress, channels, audit) cover every place it goes.

Every query filters on the owner, so another user's id reads as unknown.
A re-upload of the same bytes (same sha256) returns the existing row and
refreshes its expiry; ``expires_at`` is 30 days after the last read and
moves forward with every read. Expired rows are purged at startup and
lazily for the caller on every upload, list and read.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import undefer

from core.security import decrypt_credentials, encrypt_credentials
from models.user_file import UserFile
from services.files import messages
from services.files.documents import extract
from services.files.limits import (
    MAX_FILES_PER_USER,
    MAX_STORED_BYTES_PER_USER,
    MAX_UPLOADS_PER_HOUR,
    RETENTION_DAYS,
    UPLOAD,
    Preset,
)
from services.files.prompting import prompt_name, sanitize_display_name
from services.files.sections import Extraction, ExtractionRefused, Section

logger = structlog.get_logger(__name__)

CONTENT_VERSION = 1
SOURCES = frozenset({"web", "telegram", "slack"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class UserFileInfo:
    """One upload's facts (never its text)."""

    id: str
    name: str
    prompt_name: str
    media_type: str
    kind: str
    size_bytes: int
    pages: Optional[int]
    sections_count: int
    chars: int
    ocr_pages: int
    scanned_pages_unread: tuple[int, ...]
    warnings: tuple[str, ...]
    truncated: bool
    source: str
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    deduped: bool = field(default=False, compare=False)

    def attachment(self) -> dict[str, Any]:
        """The entry a chat message's ``attachments`` keeps for this file."""
        return {
            "kind": "file",
            "file_id": self.id,
            "name": self.name,
            "media_type": self.media_type,
            "doc_kind": self.kind,
            "pages": self.pages,
            "chars": self.chars,
            "size_bytes": self.size_bytes,
            **({"scanned_pages_unread": list(self.scanned_pages_unread)} if self.scanned_pages_unread else {}),
        }

    def public(self) -> dict[str, Any]:
        """The API and files.list shape."""
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "pages": self.pages,
            "sections": self.sections_count,
            "chars": self.chars,
            "scanned_pages_unread": list(self.scanned_pages_unread),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "source": self.source,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


def _info(row: UserFile, *, deduped: bool = False) -> UserFileInfo:
    return UserFileInfo(
        id=str(row.id),
        name=row.name,
        prompt_name=row.prompt_name,
        media_type=row.media_type,
        kind=row.kind,
        size_bytes=row.size_bytes,
        pages=row.pages,
        sections_count=row.sections_count,
        chars=row.chars,
        ocr_pages=row.ocr_pages,
        scanned_pages_unread=tuple(int(p) for p in (row.scanned_pages_unread or []) if isinstance(p, int)),
        warnings=tuple(str(w) for w in (row.warnings or [])),
        truncated=bool(row.truncated),
        source=row.source,
        created_at=_aware(row.created_at) or _now(),
        last_used_at=_aware(row.last_used_at) or _now(),
        expires_at=_aware(row.expires_at) or _now(),
        deduped=deduped,
    )


def encode_content(extraction: Extraction) -> bytes:
    payload = {
        "v": CONTENT_VERSION,
        "sections": [
            {"label": s.label, "page": s.page, "text": s.text, "src": s.src} for s in extraction.sections
        ],
    }
    return encrypt_credentials(json.dumps(payload, ensure_ascii=False))


def decode_sections(content: bytes) -> tuple[Section, ...]:
    payload = json.loads(decrypt_credentials(content))
    if not isinstance(payload, dict) or payload.get("v") != CONTENT_VERSION:
        raise ValueError("unknown content version")
    sections: list[Section] = []
    for item in payload.get("sections") or []:
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            continue
        page = item.get("page")
        sections.append(
            Section(
                label=str(item.get("label") or ""),
                page=page if isinstance(page, int) else None,
                text=item["text"],
                src=str(item.get("src") or "text"),
            )
        )
    return tuple(sections)


def parse_file_id(file_id: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(file_id))
    except (ValueError, TypeError, AttributeError):
        return None


class UserFileStore:
    """Uploads' extracted text for every user (see the module doc).
    ``sandbox`` is the parser sandbox (the process's SubprocessSandbox by
    default); ``clock`` a test seam."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]],
        *,
        sandbox: Any = None,
        clock: Callable[[], datetime] = _now,
        preset: Preset = UPLOAD,
    ) -> None:
        self._session_factory = session_factory
        self._sandbox = sandbox
        self._clock = clock
        self._preset = preset

    def _session(self) -> Any:
        if self._session_factory is None:
            raise RuntimeError("the file store has no database session factory")
        return self._session_factory()

    def _expiry(self, now: datetime) -> datetime:
        return now + timedelta(days=RETENTION_DAYS)

    async def purge_expired(self, user_id: Optional[str] = None) -> int:
        """Delete expired rows (all users', or one user's). Returns how many."""
        now = self._clock()
        stmt = delete(UserFile).where(UserFile.expires_at < now)
        if user_id is not None:
            owner = parse_file_id(user_id)
            if owner is None:
                return 0
            stmt = stmt.where(UserFile.user_id == owner)
        async with self._session() as session:
            result = await session.execute(stmt)
            await session.commit()
        count = int(getattr(result, "rowcount", 0) or 0)
        if count:
            logger.info("user_files_purged", count=count)
        return count

    async def ingest(
        self,
        user_id: str,
        *,
        data: bytes,
        name: Optional[str],
        declared_mime: Optional[str],
        source: str,
    ) -> UserFileInfo:
        """Read and store one upload. A file already stored for this user
        (same bytes) comes back as it is (``deduped``) with its expiry
        refreshed. Raises ExtractionRefused: quota_full, rate_limited, or
        any extraction refusal."""
        owner = parse_file_id(user_id)
        if owner is None:
            raise ExtractionRefused("corrupt", messages.CORRUPT)
        source = source if source in SOURCES else "web"
        digest = hashlib.sha256(data).hexdigest()
        await self.purge_expired(user_id)
        now = self._clock()
        async with self._session() as session:
            existing = (
                await session.execute(
                    select(UserFile).where(UserFile.user_id == owner, UserFile.sha256 == digest)
                )
            ).scalar_one_or_none()
            if existing is not None:
                existing.last_used_at = now
                existing.expires_at = self._expiry(now)
                await session.commit()
                return _info(existing, deduped=True)
            recent = (
                await session.execute(
                    select(func.count())
                    .select_from(UserFile)
                    .where(UserFile.user_id == owner, UserFile.created_at >= now - timedelta(hours=1))
                )
            ).scalar_one()
            if int(recent) >= MAX_UPLOADS_PER_HOUR:
                raise ExtractionRefused("rate_limited", messages.RATE_LIMITED)
            count, stored = (
                await session.execute(
                    select(func.count(), func.coalesce(func.sum(UserFile.stored_bytes), 0))
                    .select_from(UserFile)
                    .where(UserFile.user_id == owner)
                )
            ).one()
            if int(count) >= MAX_FILES_PER_USER or int(stored) >= MAX_STORED_BYTES_PER_USER:
                raise ExtractionRefused("quota_full", messages.QUOTA_FULL)

        extraction = await extract(
            data, name=name, declared_mime=declared_mime, preset=self._preset, sandbox=self._sandbox
        )
        content = encode_content(extraction)
        if int(stored) + len(content) > MAX_STORED_BYTES_PER_USER:
            raise ExtractionRefused("quota_full", messages.QUOTA_FULL)
        display = sanitize_display_name(name)
        row = UserFile(
            id=uuid.uuid4(),
            user_id=owner,
            source=source,
            name=display,
            prompt_name=prompt_name(display, extraction.kind),
            media_type=extraction.media_type,
            kind=extraction.kind,
            size_bytes=len(data),
            sha256=digest,
            pages=extraction.pages_total,
            sections_count=len(extraction.sections),
            chars=extraction.chars,
            ocr_pages=extraction.ocr_pages,
            ocr_engine=None,
            scanned_pages_unread=list(extraction.scanned_pages_unread[:500]) or None,
            warnings=list(extraction.warnings) or None,
            truncated=extraction.truncated,
            content=content,
            stored_bytes=len(content),
            created_at=now,
            last_used_at=now,
            expires_at=self._expiry(now),
        )
        async with self._session() as session:
            session.add(row)
            try:
                await session.commit()
            except IntegrityError:
                # The same file finished uploading in another request first.
                await session.rollback()
                existing = (
                    await session.execute(
                        select(UserFile).where(UserFile.user_id == owner, UserFile.sha256 == digest)
                    )
                ).scalar_one_or_none()
                if existing is None:
                    raise
                return _info(existing, deduped=True)
        logger.info(
            "user_file_stored",
            kind=row.kind,
            size=row.size_bytes,
            pages=row.pages,
            sections=row.sections_count,
            source=source,
        )
        return _info(row)

    async def get_info(self, user_id: str, file_id: Any) -> Optional[UserFileInfo]:
        """One upload's facts, or None (unknown, another user's or expired).
        Does not count as a read."""
        owner, fid = parse_file_id(user_id), parse_file_id(file_id)
        if owner is None or fid is None:
            return None
        async with self._session() as session:
            row = (
                await session.execute(select(UserFile).where(UserFile.id == fid, UserFile.user_id == owner))
            ).scalar_one_or_none()
            if row is None or (_aware(row.expires_at) or self._clock()) < self._clock():
                return None
            return _info(row)

    async def get_extraction(self, user_id: str, file_id: Any) -> Optional[tuple[UserFileInfo, Extraction]]:
        """An upload and its sections, or None. A read moves ``last_used_at``
        and ``expires_at`` forward."""
        owner, fid = parse_file_id(user_id), parse_file_id(file_id)
        if owner is None or fid is None:
            return None
        await self.purge_expired(user_id)
        now = self._clock()
        async with self._session() as session:
            row = (
                await session.execute(
                    select(UserFile)
                    .where(UserFile.id == fid, UserFile.user_id == owner)
                    .options(undefer(UserFile.content))
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            content = row.content
            row.last_used_at = now
            row.expires_at = self._expiry(now)
            await session.commit()
            info = _info(row)
        try:
            sections = decode_sections(content)
        except Exception as exc:  # a key change or a damaged row reads as gone
            logger.warning("user_file_decrypt_failed", error_type=type(exc).__name__)
            return None
        extraction = Extraction(
            kind=info.kind,
            media_type=info.media_type,
            title="",
            pages_total=info.pages,
            sections=sections,
            truncated=info.truncated,
            scanned_pages_unread=info.scanned_pages_unread,
            ocr_pages=info.ocr_pages,
            warnings=info.warnings,
        )
        return info, extraction

    async def list(self, user_id: str, limit: int = 10) -> list[UserFileInfo]:
        """The user's uploads, newest first (expired ones purged first)."""
        owner = parse_file_id(user_id)
        if owner is None:
            return []
        await self.purge_expired(user_id)
        async with self._session() as session:
            rows = (
                await session.execute(
                    select(UserFile)
                    .where(UserFile.user_id == owner)
                    .order_by(UserFile.created_at.desc())
                    .limit(max(1, min(int(limit), 100)))
                )
            ).scalars().all()
            return [_info(row) for row in rows]

    async def delete(self, user_id: str, file_id: Any) -> bool:
        """Forget one upload. False when it is unknown or another user's."""
        owner, fid = parse_file_id(user_id), parse_file_id(file_id)
        if owner is None or fid is None:
            return False
        async with self._session() as session:
            result = await session.execute(
                delete(UserFile).where(UserFile.id == fid, UserFile.user_id == owner)
            )
            await session.commit()
        return bool(getattr(result, "rowcount", 0))
