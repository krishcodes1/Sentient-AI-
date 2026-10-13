"""KnowledgeEmbedService: the background sweeper that builds the meaning index
(vectors) for saved passages while "Smarter knowledge search" is on.

Why it exists: embedding a document can take many provider calls, so it runs
in the background on the shared SweepLoop design, never inside a chat turn:
- every 30 s it re-reads the knowledge_semantic switch and sends nothing
  anywhere while it is off, blocked or unreadable;
- it claims up to 4 pending documents with a conditional UPDATE (lease now +
  5 minutes, attempts + 1), so two workers or a restart never embed one
  twice;
- at most 256 passages a sweep, 64 per provider call, 60 s a sweep; a
  withheld passage is never embedded, and every text is redacted first
  (redact_for_embedding);
- the owner's daily cap (embed_ktokens_per_day, about 4 characters a token)
  is checked before each call; over it, the document waits for the next
  UTC midnight;
- a failure backs off from 1 to 60 minutes; after 5 attempts the document
  is marked 'error' with a fixed sentence, never the provider's text;
- when the backend or model changes, up to 20 ready documents a sweep are
  queued again and their old vectors deleted (a search ignores vectors of
  another model meanwhile);
- a vector for a passage deleted mid-sweep fails its foreign key and is
  dropped;
- the provider is built for each sweep and closed at its end.
Logs carry exception types only.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from models.knowledge import KbChunk, KbDocument, KbEmbedding
from services.knowledge.embeddings import Backend, close_provider, embed_documents
from services.knowledge.limits import (
    EMBED_BACKOFF_MAX_MINUTES,
    EMBED_BACKOFF_MIN_MINUTES,
    EMBED_CLAIM_DOCUMENTS,
    EMBED_INTERVAL_S,
    EMBED_LEASE_MINUTES,
    EMBED_MAX_ATTEMPTS,
    EMBED_PASSAGES_PER_CALL,
    EMBED_PASSAGES_PER_SWEEP,
    EMBED_REQUEUE_PER_SWEEP,
    EMBED_SWEEP_DEADLINE_S,
)
from services.knowledge.store import Limits
from services.knowledge.vectors import VectorCache, pack
from services.notifications.sweeper import SweepLoop, backoff_minutes, claim

logger = structlog.get_logger(__name__)

EMBED_ERROR_SENTENCE = (
    "The meaning index could not be built for this document; keyword search still finds it."
)
Gate = Callable[[], Awaitable[bool]]
SettingsSource = Callable[[], Awaitable[Mapping[str, Any]]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def next_midnight(now: datetime) -> datetime:
    start = now.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return start + timedelta(days=1)


@dataclass(frozen=True)
class _Claim:
    id: uuid.UUID
    user_id: uuid.UUID
    collection_id: uuid.UUID
    attempts: int


class KnowledgeEmbedService:
    """The meaning-index sweeper (see the module doc). ``source`` is an
    EmbeddingSource (or a fake with ``backend()``, ``provider(backend)``
    and ``hide_personal()``); ``enabled`` the knowledge_semantic gate;
    ``settings`` the knowledge_base settings (for the daily cap)."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        source: Any,
        enabled: Optional[Gate] = None,
        settings: Optional[SettingsSource] = None,
        clock: Callable[[], datetime] = _now,
        interval_seconds: float = EMBED_INTERVAL_S,
        sweep_deadline_s: float = EMBED_SWEEP_DEADLINE_S,
        vector_cache: Optional[VectorCache] = None,
    ) -> None:
        self._session_factory = session_factory
        self._source = source
        self._settings = settings
        self._clock = clock
        self._deadline_s = sweep_deadline_s
        self._vector_cache = vector_cache
        self.loop = SweepLoop(
            name="knowledge_embed",
            interval_seconds=interval_seconds,
            sweep=self.sweep_once,
            enabled=enabled,
        )

    async def start(self) -> None:
        await self.loop.start()

    async def stop(self) -> None:
        await self.loop.stop()

    async def run_once(self) -> int:
        """One gated sweep: the number of passages embedded."""
        return await self.loop.run_once()

    async def _limits(self) -> Limits:
        if self._settings is None:
            return Limits.from_settings(None)
        try:
            return Limits.from_settings(await self._settings())
        except Exception as exc:  # noqa: BLE001 - the defaults are the cap
            logger.warning("knowledge_embed_settings_unreadable", error_type=type(exc).__name__)
            return Limits.from_settings(None)

    # -- The sweep -------------------------------------------------------------------

    async def sweep_once(self) -> int:
        backend: Optional[Backend] = await self._source.backend()
        if backend is None:
            return 0
        now = self._clock()
        await self._requeue_other_models(backend)
        claims = await self._claim(now)
        if not claims:
            return 0
        try:
            provider = await self._source.provider(backend)
        except Exception as exc:  # noqa: BLE001 - a missing key is a failure
            logger.warning("knowledge_embed_provider_failed", error_type=type(exc).__name__)
            for item in claims:
                await self._failed(item, now)
            return 0
        embedded = 0
        started = time.monotonic()
        try:
            hide = await self._source.hide_personal()
            limits = await self._limits()
            budget = EMBED_PASSAGES_PER_SWEEP
            for item in claims:
                left = self._deadline_s - (time.monotonic() - started)
                if budget <= 0 or left <= 0:
                    await self._release(item)
                    continue
                done = await self._embed_document(provider, backend, item, hide, limits, budget, started, now)
                embedded += done
                budget -= done
        finally:
            await close_provider(provider)
        return embedded

    async def _requeue_other_models(self, backend: Backend) -> None:
        """Ready documents whose vectors are another model's go back to
        pending, their old vectors deleted (at most 20 a sweep)."""
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(KbDocument.id, KbDocument.user_id)
                    .where(
                        KbDocument.embed_state == "ready",
                        or_(KbDocument.embed_model.is_(None), KbDocument.embed_model != backend.id),
                    )
                    .limit(EMBED_REQUEUE_PER_SWEEP)
                )
            ).all()
            if not rows:
                return
            for doc_id, user_id in rows:
                chunk_ids = select(KbChunk.id).where(KbChunk.user_id == user_id, KbChunk.document_id == doc_id)
                await session.execute(
                    delete(KbEmbedding)
                    .where(
                        KbEmbedding.user_id == user_id,
                        KbEmbedding.chunk_id.in_(chunk_ids),
                        KbEmbedding.model != backend.id,
                    )
                    .execution_options(synchronize_session=False)
                )
                await session.execute(
                    update(KbDocument)
                    .where(KbDocument.id == doc_id, KbDocument.embed_state == "ready")
                    .values(embed_state="pending", embed_model=None, embed_attempts=0, embed_lease_until=None)
                )
                if self._vector_cache is not None:
                    self._vector_cache.invalidate(user_id)
            await session.commit()
        logger.info("knowledge_embed_requeued", documents=len(rows))

    async def _claim(self, now: datetime) -> list[_Claim]:
        """Up to EMBED_CLAIM_DOCUMENTS pending documents whose lease is free,
        each won by a conditional UPDATE."""
        due = or_(KbDocument.embed_lease_until.is_(None), KbDocument.embed_lease_until < now)
        claims: list[_Claim] = []
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(KbDocument.id, KbDocument.user_id, KbDocument.collection_id, KbDocument.embed_attempts)
                    .where(KbDocument.embed_state == "pending", due)
                    .order_by(KbDocument.created_at, KbDocument.id)
                    .limit(EMBED_CLAIM_DOCUMENTS)
                )
            ).all()
            for doc_id, user_id, collection_id, attempts in rows:
                won = await claim(
                    session,
                    update(KbDocument)
                    .where(KbDocument.id == doc_id, KbDocument.embed_state == "pending", due)
                    .values(
                        embed_lease_until=now + timedelta(minutes=EMBED_LEASE_MINUTES),
                        embed_attempts=KbDocument.embed_attempts + 1,
                    ),
                )
                if won:
                    claims.append(_Claim(doc_id, user_id, collection_id, int(attempts or 0) + 1))
            await session.commit()
        return claims

    async def _set(self, doc_id: uuid.UUID, **values: Any) -> None:
        async with self._session_factory() as session:
            await session.execute(update(KbDocument).where(KbDocument.id == doc_id).values(**values))
            await session.commit()

    async def _release(self, item: _Claim) -> None:
        """Give a claimed document back untouched (no attempt counted)."""
        await self._set(item.id, embed_lease_until=None, embed_attempts=max(0, item.attempts - 1))

    async def _failed(self, item: _Claim, now: datetime) -> None:
        if item.attempts >= EMBED_MAX_ATTEMPTS:
            await self._set(
                item.id, embed_state="error", embed_error=EMBED_ERROR_SENTENCE, embed_lease_until=None
            )
            logger.warning("knowledge_embed_gave_up", attempts=item.attempts)
            return
        wait = backoff_minutes(EMBED_BACKOFF_MIN_MINUTES, item.attempts - 1, EMBED_BACKOFF_MAX_MINUTES)
        await self._set(item.id, embed_lease_until=now + timedelta(minutes=wait))

    async def _spent_today(self, user_id: uuid.UUID, now: datetime) -> int:
        """Estimated tokens embedded for *user_id* since UTC midnight."""
        midnight = next_midnight(now) - timedelta(days=1)
        async with self._session_factory() as session:
            chars = await session.scalar(
                select(func.coalesce(func.sum(KbChunk.char_count), 0))
                .join(KbEmbedding, KbEmbedding.chunk_id == KbChunk.id)
                .where(KbEmbedding.user_id == user_id, KbEmbedding.created_at >= midnight)
            )
        return int(chars or 0) // 4

    async def _todo(self, item: _Claim, backend: Backend, limit: int) -> list[tuple[int, str, int]]:
        """(passage id, text, chars) still without a vector of this model."""
        async with self._session_factory() as session:
            rows = await session.execute(
                select(KbChunk.id, KbChunk.text, KbChunk.char_count)
                .outerjoin(
                    KbEmbedding,
                    (KbEmbedding.chunk_id == KbChunk.id) & (KbEmbedding.model == backend.id),
                )
                .where(
                    KbChunk.user_id == item.user_id,
                    KbChunk.document_id == item.id,
                    KbChunk.withheld.is_(False),
                    KbEmbedding.chunk_id.is_(None),
                )
                .order_by(KbChunk.ordinal)
                .limit(limit)
            )
            return [(int(c), str(t), int(n or len(t))) for c, t, n in rows.all()]

    async def _embed_document(
        self,
        provider: Any,
        backend: Backend,
        item: _Claim,
        hide: bool,
        limits: Limits,
        budget: int,
        started: float,
        now: datetime,
    ) -> int:
        from services.security.egress import redact_for_embedding

        todo = await self._todo(item, backend, budget)
        if not todo:
            await self._finish(item, backend)
            return 0
        spent = await self._spent_today(item.user_id, now)
        done = 0
        capped = False
        position = 0
        while position < len(todo):
            # The next call: up to EMBED_PASSAGES_PER_CALL passages that fit
            # what is left of the user's daily cap.
            batch: list[tuple[int, str, int]] = []
            cost = 0
            for entry in todo[position : position + EMBED_PASSAGES_PER_CALL]:
                price = entry[2] // 4
                if spent + cost + price > limits.embed_tokens_per_day:
                    capped = True
                    break
                batch.append(entry)
                cost += price
            if not batch:
                capped = True
                break
            position += len(batch)
            left = self._deadline_s - (time.monotonic() - started)
            if left <= 0:
                break
            texts = [redact_for_embedding(text, cloud=backend.cloud, hide_personal=hide) for _id, text, _n in batch]
            try:
                vectors = await asyncio.wait_for(embed_documents(provider, texts, backend), timeout=left)
            except Exception as exc:  # noqa: BLE001 - the provider's text is never kept
                logger.warning("knowledge_embed_failed", error_type=type(exc).__name__, attempts=item.attempts)
                await self._failed(item, now)
                return done
            await self._store(item, backend, [chunk_id for chunk_id, _t, _n in batch], vectors)
            spent += cost
            done += len(batch)
        if not await self._todo(item, backend, 1):
            await self._finish(item, backend)
        elif capped:
            logger.info("knowledge_embed_daily_cap_reached")
            await self._set(
                item.id, embed_lease_until=next_midnight(now), embed_attempts=max(0, item.attempts - 1)
            )
        else:
            # Progress was made (or the sweep ran out of time or budget):
            # the rest waits for the next sweep, and no attempt is counted.
            await self._set(item.id, embed_lease_until=None, embed_attempts=0)
        return done

    async def _finish(self, item: _Claim, backend: Backend) -> None:
        await self._set(
            item.id,
            embed_state="ready",
            embed_model=backend.id,
            embed_lease_until=None,
            embed_attempts=0,
            embed_error=None,
        )

    async def _store(
        self, item: _Claim, backend: Backend, chunk_ids: list[int], vectors: list[list[float]]
    ) -> None:
        """Write one batch's vectors, replacing another model's. A passage
        deleted meanwhile fails its foreign key and is dropped."""
        now = self._clock()
        rows = [
            {
                "chunk_id": chunk_id,
                "user_id": item.user_id,
                "collection_id": item.collection_id,
                "model": backend.id,
                "dims": len(vector),
                "vector": pack(vector),
                "created_at": now,
            }
            for chunk_id, vector in zip(chunk_ids, vectors, strict=True)
        ]
        async with self._session_factory() as session:
            await session.execute(
                delete(KbEmbedding)
                .where(KbEmbedding.user_id == item.user_id, KbEmbedding.chunk_id.in_(chunk_ids))
                .execution_options(synchronize_session=False)
            )
            try:
                session.add_all([KbEmbedding(**row) for row in rows])
                await session.commit()
            except IntegrityError:
                await session.rollback()
                kept = 0
                for row in rows:
                    try:
                        await session.execute(
                            delete(KbEmbedding)
                            .where(KbEmbedding.user_id == item.user_id, KbEmbedding.chunk_id == row["chunk_id"])
                            .execution_options(synchronize_session=False)
                        )
                        session.add(KbEmbedding(**row))
                        await session.commit()
                        kept += 1
                    except IntegrityError:
                        await session.rollback()
                logger.info("knowledge_embed_dropped_deleted_passages", dropped=len(rows) - kept)
        if self._vector_cache is not None:
            self._vector_cache.invalidate(item.user_id)
