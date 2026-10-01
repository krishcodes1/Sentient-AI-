"""Streams a user's knowledge base into their account export: collections, then
documents with their passages' text.

Why it exists: the account export must hold everything the user saved, and a
knowledge base can be large, so documents are read in batches and each is
written as soon as its passages are loaded. The keyword postings and the
vectors are derived data and are left out.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, AsyncIterator

from sqlalchemy import select

from models.knowledge import KbChunk, KbCollection, KbDocument

_BATCH = 50


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)


def _json(value: Any) -> str:
    return json.dumps(value, default=_default)


async def export_sections(db: Any, user_id: uuid.UUID) -> AsyncIterator[str]:
    """Yield ``"knowledge_collections":[...],"knowledge_documents":[...]``
    (no trailing comma) for *user_id*, from the route's session *db*."""
    yield '"knowledge_collections":['
    rows = (
        await db.execute(
            select(KbCollection)
            .where(KbCollection.user_id == user_id)
            .order_by(KbCollection.created_at, KbCollection.id)
        )
    ).scalars().all()
    names = {row.id: row.name for row in rows}
    for index, row in enumerate(rows):
        yield ("," if index else "") + _json(
            {
                "id": row.id,
                "name": row.name,
                "description": row.description,
                "course_ref": row.course_ref,
                "created_at": row.created_at,
            }
        )
    yield '],"knowledge_documents":['
    offset = 0
    first = True
    while True:
        documents = (
            await db.execute(
                select(KbDocument)
                .where(KbDocument.user_id == user_id)
                .order_by(KbDocument.created_at, KbDocument.id)
                .offset(offset)
                .limit(_BATCH)
            )
        ).scalars().all()
        if not documents:
            break
        for doc in documents:
            chunks = (
                await db.execute(
                    select(KbChunk)
                    .where(KbChunk.user_id == user_id, KbChunk.document_id == doc.id)
                    .order_by(KbChunk.ordinal)
                )
            ).scalars().all()
            yield ("" if first else ",") + _json(
                {
                    "id": doc.id,
                    "collection": names.get(doc.collection_id),
                    "title": doc.title,
                    "source_kind": doc.source_kind,
                    "source_ref": doc.source_ref,
                    "media_type": doc.media_type,
                    "original_name": doc.original_name,
                    "pages": doc.page_count,
                    "withheld": doc.withheld_count,
                    "redacted": doc.redacted_count,
                    "truncated": doc.truncated,
                    "created_at": doc.created_at,
                    "passages": [
                        {
                            "passage": chunk.ordinal,
                            "locator": chunk.locator,
                            "heading": chunk.heading,
                            "text": chunk.text,
                            "withheld": chunk.withheld,
                        }
                        for chunk in chunks
                    ],
                }
            )
            first = False
        offset += len(documents)
        if len(documents) < _BATCH:
            break
    yield "]"
