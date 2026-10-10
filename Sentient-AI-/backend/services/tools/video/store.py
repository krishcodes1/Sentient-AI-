"""Keeps each user's transcripts (``media_transcripts``): read one back, save
or merge a newly read window into it, list them, count the provider video
seconds a user used today, purge expired rows and trim each user to 200.

Why it exists: a YouTube read costs provider tokens and a feed or caption
file costs a round trip, so the whole transcript is cached per user for 14
days after its last use and follow-ups are answered from here. Every query is
filtered by the executor's user id (another user's rows read as absent), the
least recently used row goes when a user passes 200, and the per-day minute
cap is counted from the provider seconds stored on the rows (``billed``),
never from anything the model says. The text is untrusted publisher content
and is only ever returned as a tool result.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional

import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from models.media_transcript import MediaTranscript

logger = structlog.get_logger(__name__)

KEEP_DAYS_DEFAULT = 14
MAX_ROWS_PER_USER = 200
MAX_ROW_CHARS = 400_000
MAX_BILLED_ENTRIES = 64
PROVIDER_METHOD = "provider_video"

Segment = tuple[Optional[float], Optional[float], str]
Window = tuple[float, float]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _owner(user_id: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(user_id))
    except (ValueError, TypeError, AttributeError):
        return None


def _cut(value: Optional[str], limit: int) -> Optional[str]:
    return value[:limit] if value else None


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _segments(raw: Any) -> tuple[Segment, ...]:
    out: list[Segment] = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, (list, tuple)) and len(item) == 3 and isinstance(item[2], str):
            out.append((_number(item[0]), _number(item[1]), item[2]))
    return tuple(out)


def _windows(raw: Any) -> tuple[Window, ...]:
    out: list[Window] = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            a, b = _number(item[0]), _number(item[1])
            if a is not None and b is not None and b >= a:
                out.append((a, b))
    return tuple(out)


def merge_windows(windows: Iterable[Window]) -> tuple[Window, ...]:
    """*windows* sorted and merged where they touch or overlap."""
    merged: list[list[float]] = []
    for a, b in sorted(windows):
        if merged and a <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return tuple((a, b) for a, b in merged)


def covers(windows: Iterable[Window], a: float, b: float) -> bool:
    """Whether one of *windows* holds all of [a, b]."""
    return any(start <= a + 1 and end >= b - 1 for start, end in windows)


@dataclass(frozen=True)
class TranscriptRecord:
    id: str
    source_key: str
    kind: str
    method: str
    detail: str
    display_url: str
    title: Optional[str]
    author: Optional[str]
    language: Optional[str]
    duration_s: Optional[int]
    engine: str
    segments: tuple[Segment, ...]
    covered: tuple[Window, ...]
    chars: int
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime


def _record(row: MediaTranscript, *, with_segments: bool = True) -> TranscriptRecord:
    return TranscriptRecord(
        id=str(row.id),
        source_key=row.source_key,
        kind=row.kind,
        method=row.method,
        detail=row.detail,
        display_url=row.display_url,
        title=row.title,
        author=row.author,
        language=row.language,
        duration_s=row.duration_s,
        engine=row.engine,
        segments=_segments(row.segments) if with_segments else (),
        covered=_windows(row.covered),
        chars=int(row.chars or 0),
        created_at=_aware(row.created_at) or _now(),
        last_used_at=_aware(row.last_used_at) or _now(),
        expires_at=_aware(row.expires_at) or _now(),
    )


def _capped(segments: list[Segment], covered: tuple[Window, ...]) -> tuple[list[Segment], tuple[Window, ...], int]:
    """At most MAX_ROW_CHARS of text, the earliest kept; the covered windows
    end where the kept text does."""
    kept: list[Segment] = []
    total = 0
    for segment in segments:
        if total + len(segment[2]) > MAX_ROW_CHARS:
            last = kept[-1][1] if kept and kept[-1][1] is not None else None
            if last is not None:
                covered = tuple((a, min(b, last)) for a, b in covered if a < last)
            break
        kept.append(segment)
        total += len(segment[2])
    return kept, covered, total


class TranscriptStore:
    """The ``media_transcripts`` rows. ``clock`` is a test seam."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]],
        *,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock

    def _session(self) -> Any:
        if self._session_factory is None:
            raise RuntimeError("the transcript store has no database session factory")
        return self._session_factory()

    async def get(
        self,
        user_id: str,
        source_key: str,
        method: str,
        detail: str,
        *,
        keep_days: int = KEEP_DAYS_DEFAULT,
    ) -> Optional[TranscriptRecord]:
        """This user's row for (source, method, detail), marked used (its
        expiry moves to *keep_days* from now); None when absent, expired or
        another user's."""
        owner = _owner(user_id)
        if owner is None:
            return None
        now = self._clock()
        async with self._session() as session:
            row = (
                await session.execute(
                    select(MediaTranscript).where(
                        MediaTranscript.user_id == owner,
                        MediaTranscript.source_key == source_key,
                        MediaTranscript.method == method,
                        MediaTranscript.detail == detail,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            if (_aware(row.expires_at) or now) <= now:
                await session.delete(row)
                await session.commit()
                return None
            row.last_used_at = now
            row.expires_at = now + timedelta(days=max(1, keep_days))
            await session.commit()
            return _record(row)

    async def save_merge(
        self,
        user_id: str,
        *,
        source_key: str,
        kind: str,
        method: str,
        detail: str,
        display_url: str,
        engine: str,
        segments: Iterable[Segment],
        title: Optional[str] = None,
        author: Optional[str] = None,
        language: Optional[str] = None,
        duration_s: Optional[int] = None,
        window: Optional[Window] = None,
        billed_seconds: int = 0,
        keep_days: int = KEEP_DAYS_DEFAULT,
    ) -> TranscriptRecord:
        """Store what was read. With *window* (a provider read of [a, b]),
        the row's passages in that window are replaced by *segments* and the
        window joins ``covered``; without one, *segments* is the whole
        transcript. *billed_seconds* joins ``billed`` (the per-day cap).
        The user's least recently used rows past 200 are removed."""
        owner = _owner(user_id)
        if owner is None:
            raise ValueError("unknown user")
        now = self._clock()
        new = sorted(
            (s for s in segments if s[2]),
            key=lambda s: (s[0] is None, s[0] or 0.0),
        )
        for attempt in range(2):
            try:
                async with self._session() as session:
                    row = (
                        await session.execute(
                            select(MediaTranscript).where(
                                MediaTranscript.user_id == owner,
                                MediaTranscript.source_key == source_key,
                                MediaTranscript.method == method,
                                MediaTranscript.detail == detail,
                            )
                        )
                    ).scalar_one_or_none()
                    if row is None:
                        row = MediaTranscript(
                            user_id=owner,
                            source_key=source_key,
                            method=method,
                            detail=detail,
                            created_at=now,
                            status="ready",
                            attempts=0,
                            billed=[],
                        )
                        session.add(row)
                        old_segments: tuple[Segment, ...] = ()
                        old_covered: tuple[Window, ...] = ()
                        old_billed: list[Any] = []
                    else:
                        old_segments = _segments(row.segments)
                        old_covered = _windows(row.covered)
                        old_billed = list(row.billed or [])
                    if window is not None:
                        a, b = window
                        kept = [s for s in old_segments if s[0] is None or not (a <= s[0] < b)]
                        # Only what lies inside the window read replaces it.
                        inside = [s for s in new if s[0] is not None and a <= s[0] <= b]
                        merged = sorted(kept + inside, key=lambda s: (s[0] is None, s[0] or 0.0))
                        covered = merge_windows([*old_covered, (a, b)])
                    else:
                        merged = new
                        timed_ends = [s[1] if s[1] is not None else s[0] for s in new if s[0] is not None]
                        last_end = max((e for e in timed_ends if e is not None), default=None)
                        covered = ((0.0, float(last_end)),) if last_end is not None else ()
                    merged, covered, chars = _capped(merged, covered)
                    billed = old_billed
                    if billed_seconds > 0:
                        billed = [*billed, [int(now.timestamp()), int(billed_seconds)]]
                    horizon = int((now - timedelta(days=2)).timestamp())
                    billed = [e for e in billed if isinstance(e, list) and len(e) == 2 and e[0] >= horizon]
                    row.billed = billed[-MAX_BILLED_ENTRIES:]
                    row.kind = kind[:12]
                    row.display_url = display_url[:500]
                    row.engine = (engine or "publisher")[:80]
                    row.title = _cut(title or row.title, 200)
                    row.author = _cut(author or row.author, 120)
                    row.language = _cut(language or row.language, 16)
                    if duration_s is not None:
                        row.duration_s = int(duration_s)
                    row.segments = [
                        [None if s[0] is None else round(s[0], 2), None if s[1] is None else round(s[1], 2), s[2]]
                        for s in merged
                    ]
                    row.covered = [[round(a, 2), round(b, 2)] for a, b in covered]
                    row.chars = chars
                    row.status = "ready"
                    row.error = None
                    row.updated_at = now
                    row.last_used_at = now
                    row.expires_at = now + timedelta(days=max(1, keep_days))
                    await session.commit()
                    record = _record(row)
                break
            except IntegrityError:
                # Another save of the same row won the insert: merge into it.
                if attempt:
                    raise
        await self._evict(owner)
        return record

    async def _evict(self, owner: uuid.UUID, max_rows: int = MAX_ROWS_PER_USER) -> int:
        async with self._session() as session:
            stale = (
                await session.execute(
                    select(MediaTranscript.id)
                    .where(MediaTranscript.user_id == owner)
                    .order_by(MediaTranscript.last_used_at.desc(), MediaTranscript.id)
                    .offset(max_rows)
                )
            ).scalars().all()
            if not stale:
                return 0
            await session.execute(
                delete(MediaTranscript).where(
                    MediaTranscript.user_id == owner, MediaTranscript.id.in_(list(stale))
                )
            )
            await session.commit()
        logger.info("media_transcripts_evicted", count=len(stale))
        return len(stale)

    async def list(self, user_id: str, limit: int = 10) -> list[TranscriptRecord]:
        """This user's transcripts, most recently used first, without their
        text (expired ones purged first)."""
        owner = _owner(user_id)
        if owner is None:
            return []
        await self.purge_expired(user_id)
        async with self._session() as session:
            rows = (
                await session.execute(
                    select(MediaTranscript)
                    .where(MediaTranscript.user_id == owner)
                    .order_by(MediaTranscript.last_used_at.desc())
                    .limit(max(1, min(int(limit), MAX_ROWS_PER_USER)))
                )
            ).scalars().all()
            return [_record(row, with_segments=False) for row in rows]

    async def provider_seconds_today(self, user_id: str) -> int:
        """Provider video seconds this user was billed since 00:00 UTC."""
        owner = _owner(user_id)
        if owner is None:
            return 0
        now = self._clock()
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        since = int(midnight.timestamp())
        async with self._session() as session:
            rows = (
                await session.execute(
                    select(MediaTranscript.billed).where(
                        MediaTranscript.user_id == owner,
                        MediaTranscript.method == PROVIDER_METHOD,
                        MediaTranscript.updated_at >= midnight,
                    )
                )
            ).scalars().all()
        total = 0
        for billed in rows:
            for entry in billed if isinstance(billed, list) else []:
                if isinstance(entry, list) and len(entry) == 2 and entry[0] >= since:
                    total += int(entry[1] or 0)
        return total

    async def purge_expired(self, user_id: Optional[str] = None, *, keep_days: Optional[int] = None) -> int:
        """Delete rows past their expiry (all users', or one user's), and,
        given *keep_days*, rows unused for longer than that (the owner may
        have shortened it). Returns how many."""
        now = self._clock()
        condition = MediaTranscript.expires_at <= now
        if keep_days is not None:
            condition = condition | (MediaTranscript.last_used_at <= now - timedelta(days=max(1, keep_days)))
        stmt = delete(MediaTranscript).where(condition)
        if user_id is not None:
            owner = _owner(user_id)
            if owner is None:
                return 0
            stmt = stmt.where(MediaTranscript.user_id == owner)
        async with self._session() as session:
            result = await session.execute(stmt)
            await session.commit()
        count = int(getattr(result, "rowcount", 0) or 0)
        if count:
            logger.info("media_transcripts_purged", count=count)
        return count

    async def trim(self, max_rows: int = MAX_ROWS_PER_USER) -> int:
        """Every user's least recently used rows past *max_rows*."""
        async with self._session() as session:
            owners = (
                await session.execute(
                    select(MediaTranscript.user_id)
                    .group_by(MediaTranscript.user_id)
                    .having(func.count() > max_rows)
                )
            ).scalars().all()
        removed = 0
        for owner in owners:
            removed += await self._evict(owner, max_rows)
        return removed
