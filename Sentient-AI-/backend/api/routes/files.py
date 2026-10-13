"""Serves /api/files: upload a document from the web chat (a raw streamed
body), list the signed-in user's uploads, read one's facts, and forget one.

Why it exists: the web chat attaches a file by uploading it as soon as it is
picked; the message then carries only its id (SendMessageRequest.file_ids).
The body is streamed and refused from Content-Length and again while
streaming, so a file over 20 MB is never held whole. Everything else is the
shared intake (services/files/intake.py): the "Read files and documents"
switch (403 when off), the sandboxed read, the encrypted store with its
quota (100 files / 200 MB) and rate (30 an hour, 429), and the audit row.
A re-upload of the same file answers 200 with the stored one; a new file
201. A refused file answers 413 (too large), 415 (not a readable type) or
422 (damaged, encrypted, empty, the quota), with the sentence to show.

Nothing here logs a file name or text; responses carry the sanitised name.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional
from urllib.parse import unquote

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from models.user import User
from services.auth import get_current_user
from services.files import messages
from services.files.intake import FileIntake, InboundFile
from services.files.limits import UPLOAD

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/files", tags=["files"])

NAME_HEADER = "X-File-Name"
_MAX_NAME_HEADER_CHARS = 2048

# Refusal code -> HTTP status for an upload.
_STATUS_BY_CODE: dict[str, int] = {
    "too_large": 413,
    "unsupported": 415,
    "legacy_office": 415,
    "encrypted": 422,
    "corrupt": 422,
    "empty": 422,
    "timeout": 422,
    "quota_full": 422,
    "rate_limited": status.HTTP_429_TOO_MANY_REQUESTS,
    "busy": status.HTTP_503_SERVICE_UNAVAILABLE,
    "switched_off": status.HTTP_403_FORBIDDEN,
}


def _refused(code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=_STATUS_BY_CODE.get(code, 422),
        content={"detail": message, "code": code},
    )


def _intake(request: Request) -> FileIntake:
    intake: Optional[FileIntake] = getattr(request.app.state, "file_intake", None)
    if intake is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="File uploads are not set up in this process.",
        )
    return intake


def _file_name(request: Request) -> Optional[str]:
    raw = request.headers.get(NAME_HEADER)
    if not raw or len(raw) > _MAX_NAME_HEADER_CHARS:
        return None
    try:
        name = unquote(raw, errors="strict")
    except UnicodeDecodeError:
        return None
    name = name.strip()
    return name or None


@router.post("", status_code=status.HTTP_201_CREATED)
async def upload_file(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Read one uploaded file (the raw request body) and keep its text.
    Headers: ``Content-Type`` (declared; the bytes decide) and
    ``X-File-Name`` (URL-encoded)."""
    intake = _intake(request)
    refusal = await intake.refusal()
    if refusal is not None:
        return _refused("switched_off", refusal)
    name = _file_name(request)
    if name is None:
        return JSONResponse(
            status_code=422,
            content={"detail": f"Send the file's name, URL-encoded, in the {NAME_HEADER} header."},
        )
    limit = UPLOAD.max_bytes
    declared = request.headers.get("content-length")
    if declared is not None and declared.strip().isdigit() and int(declared) > limit:
        return _refused("too_large", messages.too_large(int(declared), limit))
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return _refused("too_large", messages.too_large(None, limit))
    if not body:
        return _refused("empty", messages.EMPTY)
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip()[:100]
    result = await intake.ingest(
        str(current_user.id),
        [InboundFile(name=name, media_type=content_type, data=bytes(body), source="web")],
    )
    if result.errors:
        error = result.errors[0]
        return _refused(error.code, error.message)
    info = result.files[0]
    if info.deduped:
        response.status_code = status.HTTP_200_OK
    return {**info.public(), "deduped": info.deduped}


@router.get("")
async def list_files(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """The signed-in user's uploads, newest first (facts only, no text)."""
    rows = await _intake(request).store.list(str(current_user.id), limit)
    return [info.public() for info in rows]


@router.get("/{file_id}")
async def get_file(
    file_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    info = await _intake(request).store.get_info(str(current_user.id), file_id)
    if info is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return info.public()


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(
    file_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Forget one upload: its stored text is deleted (the original was
    never kept). 404 for an id that is not one of the user's."""
    deleted = await _intake(request).store.delete(str(current_user.id), file_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
