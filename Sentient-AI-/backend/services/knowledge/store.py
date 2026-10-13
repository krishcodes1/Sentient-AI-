"""KnowledgeService: every read and write of the knowledge base tables, always
scoped to one user.

Why it exists: the toolkit, the Telegram caption, the embed sweeper and the
account export all touch the same five tables; keeping the SQL here means
every statement filters on the caller's user_id (a foreign id reads as "not
found"), a document and its keyword index are written in one transaction,
and a delete removes postings, vectors, passages and the document together,
explicitly, whatever the database's foreign-key settings.

Adding a document:
1. off the event loop (asyncio.to_thread): cut to MAX_DOCUMENT_CHARS, split
   into passages (chunking), screen each (redaction and PromptGuard), count
   its terms (text);
2. in one transaction: find or create the collection (at most 50), refuse a
   duplicate (same text in the same collection) or a document over the
   owner's limits, then insert the document, its passages and its postings
   in batches of INSERT_BATCH rows.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

import structlog
from sqlalchemy import delete, func, insert, select
from sqlalchemy.exc import IntegrityError

from models.knowledge import KbChunk, KbCollection, KbDocument, KbEmbedding, KbPosting
from services.files.sections import Section
from services.knowledge import chunking, ranking
from services.knowledge import text as kb_text
from services.knowledge.limits import (
    COLLECTION_NAME_MAX,
    INSERT_BATCH,
    KNOWLEDGE_SETTINGS_DEFAULTS,
    LOCATOR_MAX,
    MAX_COLLECTIONS_PER_USER,
    MAX_DOCUMENT_CHARS,
    MB,
)
from services.knowledge.screen import screen_passage
from services.knowledge.sources import SourceDocument
from services.knowledge.vectors import VectorCache, VectorRow, unpack

logger = structlog.get_logger(__name__)

_SMALLINT_MAX = 32767


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse_id(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return None


def clean_collection_name(value: Any) -> Optional[str]:
    """A collection name as stored (whitespace collapsed), or None when it
    is empty, too long or holds control characters."""
    if not isinstance(value, str):
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    name = " ".join(value.split())
    if not name or len(name) > COLLECTION_NAME_MAX:
        return None
    return name


class KnowledgeError(Exception):
    """A refusal the user can act on; ``message`` is safe to show and
    ``code`` names the rule (a limit, not_found, empty ...)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Limits:
    """The owner's limits, in units the store compares against."""

    documents: int
    text_chars: int
    file_bytes: int
    embed_tokens_per_day: int

    @classmethod
    def from_settings(cls, settings: Optional[Mapping[str, Any]]) -> "Limits":
        merged: dict[str, Any] = dict(KNOWLEDGE_SETTINGS_DEFAULTS)
        for key, value in (settings or {}).items():
            if key in merged and isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                merged[key] = value
        return cls(
            documents=int(merged["documents_per_user"]),
            text_chars=int(merged["text_mb_per_user"]) * MB,
            file_bytes=int(merged["file_mb"]) * MB,
            embed_tokens_per_day=int(merged["embed_ktokens_per_day"]) * 1000,
        )


DEFAULT_LIMITS = Limits.from_settings(None)


# -- Preparing a document (off the event loop) ------------------------------------


@dataclass(frozen=True)
class PreparedPassage:
    ordinal: int
    locator: str
    heading: Optional[str]
    text: str
    withheld: bool
    redacted: int
    counts: Mapping[str, int]
    term_count: int


@dataclass(frozen=True)
class Prepared:
    passages: tuple[PreparedPassage, ...]
    text_sha256: str
    char_count: int
    truncated: bool

    @property
    def withheld(self) -> int:
        return sum(1 for p in self.passages if p.withheld)

    @property
    def redacted(self) -> int:
        return sum(p.redacted for p in self.passages)


def _capped(sections: Sequence[Section]) -> tuple[list[Section], bool]:
    kept: list[Section] = []
    used = 0
    for section in sections:
        room = MAX_DOCUMENT_CHARS - used
        if room <= 0:
            return kept, True
        if len(section.text) > room:
            kept.append(Section(section.label, section.page, section.text[:room], section.src))
            return kept, True
        kept.append(section)
        used += len(section.text)
    return kept, False


def _screened_label(value: Optional[str]) -> Optional[str]:
    """A heading or locator as stored: None when PromptGuard flags it, with
    secrets masked otherwise."""
    if not value:
        return None
    screened = screen_passage(value)
    return None if screened.withheld else screened.text


def prepare(source: SourceDocument) -> Prepared:
    """Passages, screening and term counts for *source* (CPU only)."""
    sections, cut = _capped(source.sections)
    digest = hashlib.sha256(
        "\n\n".join(s.text for s in sections).encode("utf-8", "surrogatepass")
    ).hexdigest()
    passages: list[PreparedPassage] = []
    for passage in chunking.chunk_sections(source.doc_kind, sections):
        screened = screen_passage(passage.text)
        heading = _screened_label(passage.heading)
        locator = _screened_label(passage.locator) or f"part {passage.ordinal + 1}"
        counts = kb_text.term_counts(screened.text, heading)
        passages.append(
            PreparedPassage(
                ordinal=passage.ordinal,
                locator=locator[:LOCATOR_MAX],
                heading=heading,
                text=screened.text,
                withheld=screened.withheld,
                redacted=screened.redacted,
                counts=dict(counts),
                term_count=sum(counts.values()),
            )
        )
    return Prepared(
        passages=tuple(passages),
        text_sha256=digest,
        char_count=sum(len(s.text) for s in sections),
        truncated=source.truncated or cut,
    )


# -- Results -------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectionInfo:
    id: str
    name: str
    course_ref: Optional[str] = None


@dataclass(frozen=True)
class AddOutcome:
    """One saved item: ``status`` is ready, duplicate or error."""

    status: str
    title: str
    document_id: Optional[str] = None
    pages: Optional[int] = None
    passages: int = 0
    withheld: int = 0
    redacted: int = 0
    error: Optional[str] = None
    code: Optional[str] = None
    collection: Optional[CollectionInfo] = None
    collection_created: bool = False

    def item(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "document_id": self.document_id,
            "status": self.status,
            "pages": self.pages,
            "passages": self.passages,
            "withheld": self.withheld,
            "redacted": self.redacted,
            "error": self.error,
        }


@dataclass(frozen=True)
class PassageView:
    chunk_id: int
    document_id: str
    collection_id: str
    ordinal: int
    locator: str
    heading: Optional[str]
    text: str
    withheld: bool
    title: str
    source_kind: str
    source_ref: Optional[str]
    collection: str


@dataclass(frozen=True)
class DocumentFacts:
    id: str
    title: str
    passages: int
    collection: str
    collection_id: str
    source_kind: str
    source_ref: Optional[str]
    pages: Optional[int]
    withheld: int
    embed_state: str
    created_at: datetime
    truncated: bool = False


@dataclass(frozen=True)
class CollectionRow:
    id: str
    name: str
    course_ref: Optional[str]
    documents: int
    chars: int
    passages: int
    created_at: datetime


@dataclass(frozen=True)
class Usage:
    documents: int
    chars: int
    collections: int


@dataclass(frozen=True)
class Deleted:
    name: str
    documents: int
    passages: int


@dataclass
class ReadWindow:
    document: DocumentFacts
    passages: list[PassageView] = field(default_factory=list)
    more: bool = False


# -- The service ---------------------------------------------------------------------


class KnowledgeService:
    """The knowledge base tables for every user (see the module doc).
    ``vector_cache`` is shared with the search path; any write drops the
    user's cached vectors."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]],
        *,
        clock: Callable[[], datetime] = _now,
        vector_cache: Optional[VectorCache] = None,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self.vector_cache = vector_cache if vector_cache is not None else VectorCache()
        self._user_locks: dict[str, asyncio.Lock] = {}

    @property
    def configured(self) -> bool:
        return self._session_factory is not None

    def _session(self) -> Any:
        if self._session_factory is None:
            raise KnowledgeError("storage", "The knowledge base is not configured (no database).")
        return self._session_factory()

    def _owner(self, user_id: Any) -> uuid.UUID:
        owner = parse_id(user_id)
        if owner is None:
            raise KnowledgeError("storage", "The knowledge base needs a signed-in user.")
        return owner

    def _lock(self, owner: uuid.UUID) -> asyncio.Lock:
        key = str(owner)
        lock = self._user_locks.get(key)
        if lock is None:
            if len(self._user_locks) > 4096:
                self._user_locks = {k: v for k, v in self._user_locks.items() if v.locked()}
            lock = self._user_locks[key] = asyncio.Lock()
        return lock

    # -- Collections -------------------------------------------------------------

    @staticmethod
    async def _collections_of(session: Any, owner: uuid.UUID) -> list[KbCollection]:
        rows = await session.execute(
            select(KbCollection).where(KbCollection.user_id == owner).order_by(KbCollection.created_at, KbCollection.id)
        )
        return list(rows.scalars().all())

    @staticmethod
    def _match(rows: Iterable[KbCollection], ref: str) -> Optional[KbCollection]:
        rows = list(rows)
        wanted = parse_id(ref)
        if wanted is not None:
            for row in rows:
                if row.id == wanted:
                    return row
        name = clean_collection_name(ref)
        if name is None:
            return None
        for row in rows:
            if row.name == name:
                return row
        folded = name.casefold()
        for row in rows:
            if row.name.casefold() == folded:
                return row
        return None

    async def find_collection(self, user_id: Any, ref: Any) -> Optional[CollectionInfo]:
        """The user's collection named (case-insensitively) or identified by
        *ref*, or None."""
        owner = self._owner(user_id)
        if not isinstance(ref, str) or not ref.strip():
            return None
        async with self._session() as session:
            row = self._match(await self._collections_of(session, owner), ref)
        return None if row is None else CollectionInfo(str(row.id), row.name, row.course_ref)

    async def collection_count(self, user_id: Any) -> int:
        owner = self._owner(user_id)
        async with self._session() as session:
            count = await session.scalar(
                select(func.count()).select_from(KbCollection).where(KbCollection.user_id == owner)
            )
        return int(count or 0)

    # -- Usage and limits ------------------------------------------------------------

    async def usage(self, user_id: Any) -> Usage:
        owner = self._owner(user_id)
        async with self._session() as session:
            documents, chars = (
                await session.execute(
                    select(func.count(KbDocument.id), func.coalesce(func.sum(KbDocument.char_count), 0)).where(
                        KbDocument.user_id == owner
                    )
                )
            ).one()
            collections = await session.scalar(
                select(func.count()).select_from(KbCollection).where(KbCollection.user_id == owner)
            )
        return Usage(int(documents or 0), int(chars or 0), int(collections or 0))

    async def room_for(
        self, user_id: Any, collection: str, limits: Limits, *, documents: int = 1, chars: int = 0
    ) -> Optional[KnowledgeError]:
        """Why *documents* more documents (of *chars* characters) would not
        fit, or None. Checked before any card and again when they are
        saved."""
        usage = await self.usage(user_id)
        if usage.documents + documents > limits.documents:
            return KnowledgeError(
                "document_limit",
                f"The knowledge base holds at most {limits.documents} documents and has "
                f"{usage.documents}. Remove some first (knowledge.list, knowledge.remove).",
            )
        if usage.chars + chars > limits.text_chars or usage.chars >= limits.text_chars:
            return KnowledgeError(
                "storage_limit",
                f"The knowledge base holds at most {limits.text_chars // MB} MB of text and is "
                "full. Remove some documents first.",
            )
        if await self.find_collection(user_id, collection) is None and usage.collections >= MAX_COLLECTIONS_PER_USER:
            return KnowledgeError(
                "collection_limit",
                f"You already have {MAX_COLLECTIONS_PER_USER} collections, the most allowed. Save "
                "to an existing one or remove one first.",
            )
        return None

    # -- Adding ------------------------------------------------------------------------

    async def add_document(
        self, user_id: Any, collection: str, source: SourceDocument, *, limits: Limits = DEFAULT_LIMITS
    ) -> AddOutcome:
        """Save *source* into the user's collection *collection* (created
        when missing). Never raises for a bad document: the outcome says
        error, with the reason."""
        owner = self._owner(user_id)
        name = clean_collection_name(collection)
        if name is None:
            return AddOutcome("error", source.title, error="The collection name must be 1-80 characters.", code="invalid")
        try:
            prepared = await asyncio.to_thread(prepare, source)
        except Exception as exc:  # noqa: BLE001 - a bad document is one item's error
            logger.warning("knowledge_prepare_failed", error_type=type(exc).__name__)
            return AddOutcome("error", source.title, error="The document could not be indexed.", code="index_failed")
        if not prepared.passages:
            return AddOutcome("error", source.title, error="No text could be read from this document.", code="empty")
        async with self._lock(owner):
            try:
                return await self._insert(owner, name, source, prepared, limits)
            except KnowledgeError as refusal:
                return AddOutcome("error", source.title, error=refusal.message, code=refusal.code)
            except IntegrityError:
                # The same text (or collection) was saved at the same moment.
                duplicate = await self._duplicate_of(owner, name, prepared.text_sha256)
                if duplicate is not None:
                    return duplicate
                return AddOutcome("error", source.title, error="The document could not be saved; try again.", code="conflict")
            finally:
                self.vector_cache.invalidate(owner)

    async def _duplicate_of(self, owner: uuid.UUID, name: str, digest: str) -> Optional[AddOutcome]:
        async with self._session() as session:
            row = self._match(await self._collections_of(session, owner), name)
            if row is None:
                return None
            doc = (
                await session.execute(
                    select(KbDocument).where(
                        KbDocument.user_id == owner,
                        KbDocument.collection_id == row.id,
                        KbDocument.text_sha256 == digest,
                    )
                )
            ).scalar_one_or_none()
            if doc is None:
                return None
            return AddOutcome(
                "duplicate",
                doc.title,
                document_id=str(doc.id),
                pages=doc.page_count,
                passages=doc.chunk_count,
                withheld=doc.withheld_count,
                redacted=doc.redacted_count,
                error="Already saved in this collection.",
                collection=CollectionInfo(str(row.id), row.name, row.course_ref),
            )

    async def _insert(
        self, owner: uuid.UUID, name: str, source: SourceDocument, prepared: Prepared, limits: Limits
    ) -> AddOutcome:
        now = self._clock()
        async with self._session() as session:
            collections = await self._collections_of(session, owner)
            row = self._match(collections, name)
            created = False
            if row is not None:
                duplicate = (
                    await session.execute(
                        select(KbDocument).where(
                            KbDocument.user_id == owner,
                            KbDocument.collection_id == row.id,
                            KbDocument.text_sha256 == prepared.text_sha256,
                        )
                    )
                ).scalar_one_or_none()
                if duplicate is not None:
                    return AddOutcome(
                        "duplicate",
                        duplicate.title,
                        document_id=str(duplicate.id),
                        pages=duplicate.page_count,
                        passages=duplicate.chunk_count,
                        withheld=duplicate.withheld_count,
                        redacted=duplicate.redacted_count,
                        error="Already saved in this collection.",
                        collection=CollectionInfo(str(row.id), row.name, row.course_ref),
                    )
            documents, chars = (
                await session.execute(
                    select(func.count(KbDocument.id), func.coalesce(func.sum(KbDocument.char_count), 0)).where(
                        KbDocument.user_id == owner
                    )
                )
            ).one()
            if int(documents or 0) >= limits.documents:
                raise KnowledgeError(
                    "document_limit",
                    f"The knowledge base holds at most {limits.documents} documents. Remove some first.",
                )
            if int(chars or 0) + prepared.char_count > limits.text_chars:
                raise KnowledgeError(
                    "storage_limit",
                    f"This would pass the {limits.text_chars // MB} MB of text the knowledge base "
                    "holds. Remove some documents first.",
                )
            if row is None:
                if len(collections) >= MAX_COLLECTIONS_PER_USER:
                    raise KnowledgeError(
                        "collection_limit",
                        f"You already have {MAX_COLLECTIONS_PER_USER} collections, the most allowed.",
                    )
                row = KbCollection(id=uuid.uuid4(), user_id=owner, name=name, created_at=now, updated_at=now)
                session.add(row)
                created = True
            else:
                row.updated_at = now
            searchable = any(not p.withheld for p in prepared.passages)
            doc = KbDocument(
                id=uuid.uuid4(),
                user_id=owner,
                collection_id=row.id,
                title=source.title[:200],
                source_kind=source.source_kind,
                source_ref=source.source_ref,
                media_type=(source.media_type or "text/plain")[:100],
                original_name=(source.original_name or None) and source.original_name[:255],
                byte_size=int(source.byte_size or 0),
                text_sha256=prepared.text_sha256,
                char_count=prepared.char_count,
                chunk_count=len(prepared.passages),
                page_count=source.pages_total,
                withheld_count=prepared.withheld,
                redacted_count=prepared.redacted,
                truncated=prepared.truncated,
                status="ready",
                embed_state="pending" if searchable else "skipped",
                embed_attempts=0,
                created_at=now,
                indexed_at=now,
            )
            session.add(doc)
            await session.flush()
            chunk_ids: list[int] = []
            for start in range(0, len(prepared.passages), INSERT_BATCH):
                batch = prepared.passages[start : start + INSERT_BATCH]
                rows = [
                    KbChunk(
                        document_id=doc.id,
                        user_id=owner,
                        collection_id=row.id,
                        ordinal=p.ordinal,
                        locator=p.locator,
                        heading=p.heading[:200] if p.heading else None,
                        text=p.text,
                        char_count=len(p.text),
                        term_count=p.term_count,
                        withheld=p.withheld,
                    )
                    for p in batch
                ]
                session.add_all(rows)
                await session.flush()
                chunk_ids.extend(int(r.id) for r in rows)
            postings: list[dict[str, Any]] = []
            for passage, chunk_id in zip(prepared.passages, chunk_ids, strict=True):
                dl = min(passage.term_count, _SMALLINT_MAX)
                for term, tf in passage.counts.items():
                    postings.append(
                        {
                            "user_id": owner,
                            "term": term[:64],
                            "chunk_id": chunk_id,
                            "collection_id": row.id,
                            "tf": min(int(tf), _SMALLINT_MAX),
                            "dl": dl,
                        }
                    )
                    if len(postings) >= INSERT_BATCH:
                        await session.execute(insert(KbPosting), postings)
                        postings = []
            if postings:
                await session.execute(insert(KbPosting), postings)
            await session.commit()
            logger.info(
                "knowledge_document_indexed",
                source_kind=source.source_kind,
                passages=len(prepared.passages),
                withheld=prepared.withheld,
                redacted=prepared.redacted,
            )
            return AddOutcome(
                "ready",
                doc.title,
                document_id=str(doc.id),
                pages=source.pages_total,
                passages=len(prepared.passages),
                withheld=prepared.withheld,
                redacted=prepared.redacted,
                collection=CollectionInfo(str(row.id), row.name, row.course_ref),
                collection_created=created,
            )

    # -- Searching ----------------------------------------------------------------------

    async def keyword_ranking(
        self,
        user_id: Any,
        terms: Sequence[str],
        *,
        collection_id: Optional[str] = None,
        document_id: Optional[str] = None,
        limit: int = 200,
    ) -> tuple[list[tuple[int, float]], dict[int, list[str]]]:
        """BM25 over the user's passages in scope: (best first, the query
        terms each passage matched)."""
        owner = self._owner(user_id)
        collection = parse_id(collection_id) if collection_id else None
        document = parse_id(document_id) if document_id else None
        if not terms:
            return [], {}
        async with self._session() as session:
            stats = select(func.count(KbChunk.id), func.coalesce(func.avg(KbChunk.term_count), 0)).where(
                KbChunk.user_id == owner
            )
            if collection is not None:
                stats = stats.where(KbChunk.collection_id == collection)
            if document is not None:
                stats = stats.where(KbChunk.document_id == document)
            n, avgdl = (await session.execute(stats)).one()
            n = int(n or 0)
            if n == 0:
                return [], {}

            def scoped(stmt: Any) -> Any:
                stmt = stmt.where(KbPosting.user_id == owner)
                if collection is not None:
                    stmt = stmt.where(KbPosting.collection_id == collection)
                if document is not None:
                    stmt = stmt.join(KbChunk, KbChunk.id == KbPosting.chunk_id).where(
                        KbChunk.user_id == owner, KbChunk.document_id == document
                    )
                return stmt

            df_rows = await session.execute(
                scoped(select(KbPosting.term, func.count()).where(KbPosting.term.in_(list(terms)))).group_by(
                    KbPosting.term
                )
            )
            df = {str(term): int(count) for term, count in df_rows.all()}
            useful = ranking.useful_terms(list(terms), df, n)
            if not useful:
                return [], {}
            rows = await session.execute(
                scoped(
                    select(KbPosting.chunk_id, KbPosting.term, KbPosting.tf, KbPosting.dl).where(
                        KbPosting.term.in_(useful)
                    )
                )
            )
            postings = [ranking.Posting(int(c), str(t), int(tf), int(dl)) for c, t, tf, dl in rows.all()]
        scores = await asyncio.to_thread(ranking.bm25, postings, list(terms), df, n, float(avgdl or 0))
        matched: dict[int, list[str]] = defaultdict(list)
        for posting in postings:
            if posting.chunk_id in scores:
                matched[posting.chunk_id].append(posting.term)
        return ranking.ranked(scores)[:limit], dict(matched)

    async def search(
        self,
        user_id: Any,
        query: str,
        *,
        collection_id: Optional[str] = None,
        document_id: Optional[str] = None,
        limit: int = 6,
        include_withheld: bool = False,
    ) -> list[PassageView]:
        """The user's best passages for *query* by keywords (BM25), at most
        PER_DOCUMENT_CAP per document, best first; withheld passages are left
        out unless asked for. The internal entry point for other features
        (knowledge.search adds the meaning index and the model-facing shape)."""
        terms = kb_text.query_terms(query)
        ranked, _matched = await self.keyword_ranking(
            user_id, terms, collection_id=collection_id, document_id=document_id
        )
        views = await self.passages(user_id, [c for c, _ in ranked])
        if not include_withheld:
            views = {c: v for c, v in views.items() if not v.withheld}
        picked = ranking.cap_per_document(
            [(c, s) for c, s in ranked if c in views],
            {c: v.document_id for c, v in views.items()},
            limit=max(1, limit),
        )
        return [views[c] for c, _ in picked]

    async def passages(self, user_id: Any, chunk_ids: Iterable[int]) -> dict[int, PassageView]:
        """The user's passages with these ids, with their document facts."""
        owner = self._owner(user_id)
        ids = sorted({int(c) for c in chunk_ids})
        if not ids:
            return {}
        views: dict[int, PassageView] = {}
        async with self._session() as session:
            for start in range(0, len(ids), INSERT_BATCH):
                rows = await session.execute(
                    select(KbChunk, KbDocument.title, KbDocument.source_kind, KbDocument.source_ref, KbCollection.name)
                    .join(KbDocument, KbDocument.id == KbChunk.document_id)
                    .join(KbCollection, KbCollection.id == KbChunk.collection_id)
                    .where(
                        KbChunk.user_id == owner,
                        KbDocument.user_id == owner,
                        KbChunk.id.in_(ids[start : start + INSERT_BATCH]),
                    )
                )
                for chunk, title, kind, ref, collection in rows.all():
                    views[int(chunk.id)] = _view(chunk, title, kind, ref, collection)
        return views

    async def has_vectors(self, user_id: Any, model: str, *, collection_id: Optional[str] = None) -> bool:
        owner = self._owner(user_id)
        stmt = select(KbEmbedding.chunk_id).where(KbEmbedding.user_id == owner, KbEmbedding.model == model)
        collection = parse_id(collection_id) if collection_id else None
        if collection is not None:
            stmt = stmt.where(KbEmbedding.collection_id == collection)
        async with self._session() as session:
            return (await session.execute(stmt.limit(1))).first() is not None

    async def vector_rows(self, user_id: Any, model: str) -> list[VectorRow]:
        """Every vector of the user's for *model* (never a withheld
        passage's), from the cache when it has them."""
        owner = self._owner(user_id)
        cached = self.vector_cache.get(str(owner), model)
        if cached is not None:
            return cached
        rows: list[VectorRow] = []
        async with self._session() as session:
            result = await session.execute(
                select(KbEmbedding.chunk_id, KbChunk.document_id, KbEmbedding.collection_id, KbEmbedding.vector)
                .join(KbChunk, KbChunk.id == KbEmbedding.chunk_id)
                .where(
                    KbEmbedding.user_id == owner,
                    KbChunk.user_id == owner,
                    KbEmbedding.model == model,
                    KbChunk.withheld.is_(False),
                )
            )
            for chunk_id, document_id, collection_id, blob in result.all():
                rows.append(VectorRow(int(chunk_id), str(document_id), str(collection_id), unpack(blob)))
        self.vector_cache.put(str(owner), model, rows)
        return rows

    # -- Reading and listing ------------------------------------------------------------

    async def document_facts(self, user_id: Any, document_id: Any) -> Optional[DocumentFacts]:
        owner = self._owner(user_id)
        wanted = parse_id(document_id)
        if wanted is None:
            return None
        async with self._session() as session:
            row = (
                await session.execute(
                    select(KbDocument, KbCollection.name)
                    .join(KbCollection, KbCollection.id == KbDocument.collection_id)
                    .where(KbDocument.id == wanted, KbDocument.user_id == owner)
                )
            ).first()
        return None if row is None else _facts(row[0], row[1])

    async def read(self, user_id: Any, document_id: Any, start: int, count: int) -> Optional[ReadWindow]:
        """Passages *start* to *start + count - 1* of one of the user's
        documents (by ordinal), and whether more follow."""
        facts = await self.document_facts(user_id, document_id)
        if facts is None:
            return None
        owner = self._owner(user_id)
        async with self._session() as session:
            rows = await session.execute(
                select(KbChunk)
                .where(
                    KbChunk.user_id == owner,
                    KbChunk.document_id == uuid.UUID(facts.id),
                    KbChunk.ordinal >= start,
                )
                .order_by(KbChunk.ordinal)
                .limit(count + 1)
            )
            chunks = list(rows.scalars().all())
        views = [_view(c, facts.title, facts.source_kind, facts.source_ref, facts.collection) for c in chunks[:count]]
        return ReadWindow(facts, views, more=len(chunks) > count)

    async def collections(self, user_id: Any) -> list[CollectionRow]:
        owner = self._owner(user_id)
        async with self._session() as session:
            rows = await session.execute(
                select(
                    KbCollection,
                    func.count(KbDocument.id),
                    func.coalesce(func.sum(KbDocument.char_count), 0),
                    func.coalesce(func.sum(KbDocument.chunk_count), 0),
                )
                .outerjoin(
                    KbDocument,
                    (KbDocument.collection_id == KbCollection.id) & (KbDocument.user_id == owner),
                )
                .where(KbCollection.user_id == owner)
                .group_by(KbCollection.id)
                .order_by(KbCollection.name)
            )
            return [
                CollectionRow(
                    id=str(c.id),
                    name=c.name,
                    course_ref=c.course_ref,
                    documents=int(docs or 0),
                    chars=int(chars or 0),
                    passages=int(passages or 0),
                    created_at=c.created_at,
                )
                for c, docs, chars, passages in rows.all()
            ]

    async def documents(self, user_id: Any, collection_id: str, limit: int) -> list[DocumentFacts]:
        owner = self._owner(user_id)
        collection = parse_id(collection_id)
        if collection is None:
            return []
        async with self._session() as session:
            rows = await session.execute(
                select(KbDocument, KbCollection.name)
                .join(KbCollection, KbCollection.id == KbDocument.collection_id)
                .where(KbDocument.user_id == owner, KbDocument.collection_id == collection)
                .order_by(KbDocument.created_at.desc(), KbDocument.id)
                .limit(limit)
            )
            return [_facts(doc, name) for doc, name in rows.all()]

    # -- Deleting ------------------------------------------------------------------------

    async def _delete_chunks(self, session: Any, owner: uuid.UUID, chunk_filter: Any) -> int:
        chunk_ids = select(KbChunk.id).where(KbChunk.user_id == owner, chunk_filter)
        passages = int(
            await session.scalar(select(func.count()).select_from(KbChunk).where(KbChunk.user_id == owner, chunk_filter))
            or 0
        )
        await session.execute(
            delete(KbPosting).where(KbPosting.user_id == owner, KbPosting.chunk_id.in_(chunk_ids)).execution_options(
                synchronize_session=False
            )
        )
        await session.execute(
            delete(KbEmbedding)
            .where(KbEmbedding.user_id == owner, KbEmbedding.chunk_id.in_(chunk_ids))
            .execution_options(synchronize_session=False)
        )
        await session.execute(
            delete(KbChunk).where(KbChunk.user_id == owner, chunk_filter).execution_options(synchronize_session=False)
        )
        return passages

    async def delete_document(self, user_id: Any, document_id: Any) -> Optional[Deleted]:
        """Delete one of the user's documents with its postings, vectors and
        passages, in one transaction. None when it is not theirs."""
        owner = self._owner(user_id)
        wanted = parse_id(document_id)
        if wanted is None:
            return None
        async with self._lock(owner):
            async with self._session() as session:
                doc = (
                    await session.execute(
                        select(KbDocument).where(KbDocument.id == wanted, KbDocument.user_id == owner)
                    )
                ).scalar_one_or_none()
                if doc is None:
                    return None
                title = doc.title
                passages = await self._delete_chunks(session, owner, KbChunk.document_id == wanted)
                await session.execute(
                    delete(KbDocument)
                    .where(KbDocument.id == wanted, KbDocument.user_id == owner)
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
            self.vector_cache.invalidate(owner)
        return Deleted(title, 1, passages)

    async def delete_collection(self, user_id: Any, collection_id: Any) -> Optional[Deleted]:
        """Delete one of the user's collections and everything in it, in one
        transaction. None when it is not theirs."""
        owner = self._owner(user_id)
        wanted = parse_id(collection_id)
        if wanted is None:
            return None
        async with self._lock(owner):
            async with self._session() as session:
                row = (
                    await session.execute(
                        select(KbCollection).where(KbCollection.id == wanted, KbCollection.user_id == owner)
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                name = row.name
                documents = int(
                    await session.scalar(
                        select(func.count())
                        .select_from(KbDocument)
                        .where(KbDocument.user_id == owner, KbDocument.collection_id == wanted)
                    )
                    or 0
                )
                passages = await self._delete_chunks(session, owner, KbChunk.collection_id == wanted)
                await session.execute(
                    delete(KbDocument)
                    .where(KbDocument.user_id == owner, KbDocument.collection_id == wanted)
                    .execution_options(synchronize_session=False)
                )
                await session.execute(
                    delete(KbCollection)
                    .where(KbCollection.id == wanted, KbCollection.user_id == owner)
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
            self.vector_cache.invalidate(owner)
        return Deleted(name, documents, passages)


def _view(chunk: KbChunk, title: str, kind: str, ref: Optional[str], collection: str) -> PassageView:
    return PassageView(
        chunk_id=int(chunk.id),
        document_id=str(chunk.document_id),
        collection_id=str(chunk.collection_id),
        ordinal=int(chunk.ordinal),
        locator=chunk.locator,
        heading=chunk.heading,
        text=chunk.text,
        withheld=bool(chunk.withheld),
        title=title,
        source_kind=kind,
        source_ref=ref,
        collection=collection,
    )


def _facts(doc: KbDocument, collection: str) -> DocumentFacts:
    return DocumentFacts(
        id=str(doc.id),
        title=doc.title,
        passages=int(doc.chunk_count or 0),
        collection=collection,
        collection_id=str(doc.collection_id),
        source_kind=doc.source_kind,
        source_ref=doc.source_ref,
        pages=doc.page_count,
        withheld=int(doc.withheld_count or 0),
        embed_state=doc.embed_state,
        created_at=doc.created_at,
        truncated=bool(doc.truncated),
    )
