"""Serves flashcard deck downloads: GET /api/study/export?t=<one-time token>
(the link study.export gives the web chat) and GET
/api/study/decks/{deck_id}/export?format= (signed in).

Why it exists: a deck is the user's own data and must leave as a file other
tools read (an Anki import file, or a CSV). A link in the chat cannot carry the
web app's bearer token, so study.export mints a one-time token instead
(services/study/export.py): valid once, for 10 minutes, bound to one user,
deck and format. An unknown, expired or used token and a deck that is gone
all answer the same 404, so the route is no oracle. The token's query string
is kept out of uvicorn's access log (core/logging_config.py) and nginx's
(docker/Dockerfile.frontend), and hidden in audit rows by its cse_ format.
Every download is an attachment, never cached or sniffed, and writes one
study_export audit row (deck id, format, item count; never card text) before
the file is sent: a download that cannot be recorded is refused.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.user import User
from services.auth import get_current_user
from services.study import export as study_export
from services.study.engine import StudyEngine

router = APIRouter(prefix="/study", tags=["study"])

_NOT_FOUND = "Not found."
_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


class _Borrowed:
    """The request's session, lent to code that opens its own (``async with
    factory() as session``); the request still owns and closes it."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def __aenter__(self) -> AsyncSession:
        return self._db

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


def _tokens(request: Request) -> study_export.ExportTokens:
    found = getattr(request.app.state, "study_exports", None)
    return found if isinstance(found, study_export.ExportTokens) else study_export.EXPORT_TOKENS


async def _download(db: AsyncSession, user_id: uuid.UUID, deck_id: Any, fmt: str, *, endpoint: str) -> Response:
    def factory() -> _Borrowed:
        return _Borrowed(db)

    found = await StudyEngine(factory).deck_items(user_id, deck_id)
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
    deck, items = found
    if not await study_export.record_export(factory, str(user_id), str(deck.id), fmt, len(items), endpoint=endpoint):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The download could not be recorded; try again shortly.",
        )
    filename = study_export.safe_filename(deck.title, fmt)
    return Response(
        content=study_export.render_file(fmt, deck.title, items),
        media_type=f"{study_export.MEDIA_TYPES[fmt]}; charset=utf-8",
        headers={**_HEADERS, "Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export")
async def download_by_token(
    request: Request,
    t: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """The one-time link: the deck the token was minted for, once."""
    grant = _tokens(request).redeem(t)
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
    return await _download(db, uuid.UUID(grant.user_id), grant.deck_id, grant.fmt, endpoint="/api/study/export")


@router.get("/decks/{deck_id}/export")
async def download_deck(
    deck_id: uuid.UUID,
    format: str = Query(default="anki", pattern="^(anki|csv)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """The signed-in user's own deck; another user's deck is a 404."""
    return await _download(db, current_user.id, deck_id, format, endpoint="/api/study/decks/export")
