"""Serves Security -> File checks (/api/security/files): the caller's file
checks and the service's state, a lookup of a fingerprint the browser
computed (the file itself never leaves the browser for it), a request to
send one file VirusTotal does not know (which parks an approval card), and
forgetting a check.

Why it exists: a person should be able to check a file before opening it,
and see what Crawler concluded about files they sent it, with only the
fingerprint leaving the machine unless they approve an upload card. Rules
kept here:

- Every route is the signed-in person's own: rows are read, changed and
  forgotten by user id and row id together, so another person's id is a 404.
- No response ever carries the encrypted source reference, the source key,
  an analysis id or anything key-shaped (the service's row shape leaves them
  out, and a test pins it).
- An upload request's body (the file the owner picked, optional) is at most
  20 MB, refused from its Content-Length and again while streaming, and must
  hash to the check's fingerprint. Requests are limited to 5 an hour per
  person (in memory, like the setup routes), because each one can park a card
  that is pushed to Telegram and Slack.
- Errors answer ``{"detail": <sentence>, "code": <code>}`` (the files route's
  shape), so the page shows the sentence and can tell the cases apart.

Connects to: services/file_reputation/service.py (``app.state.file_reputation``).
Used by: the Security page's File checks tab (frontend/src/services/api.ts, S10
section); main.py mounts the router.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from models.user import User
from services.auth import get_current_user
from services.file_reputation.byte_sink import normalise_sha256
from services.file_reputation.service import (
    NOT_SET_UP_SENTENCE,
    PAGE_UPLOAD_MAX_BYTES,
    FileReputationService,
    UploadRequestOutcome,
)

router = APIRouter(prefix="/security/files", tags=["security"])

# Plain numbers: Starlette renamed these two constants (and warns on the old names).
_TOO_LARGE = 413
_UNPROCESSABLE = 422

# Each refusal code of an upload request and the status it answers with (S10 6.2).
_UPLOAD_STATUS: dict[str, int] = {
    "not_found": status.HTTP_404_NOT_FOUND,
    "service_off": status.HTTP_409_CONFLICT,
    "already_known": status.HTTP_409_CONFLICT,
    "not_checked_yet": status.HTTP_409_CONFLICT,
    "needs_file": status.HTTP_409_CONFLICT,
    "refused": status.HTTP_409_CONFLICT,
    "too_large": _TOO_LARGE,
    "file_changed": _UNPROCESSABLE,
    "rate_limited": status.HTTP_429_TOO_MANY_REQUESTS,
    "not_wired": status.HTTP_503_SERVICE_UNAVAILABLE,
}
BAD_HASH = "Send the file's SHA-256 fingerprint: 64 hex characters."
NOT_FOUND = "No such file check."
TOO_LARGE = "The file is larger than 20 MB, too large to send from here."
RATE_LIMITED = "Too many upload requests in the last hour. Try again later."
LOOKUP_FAILED = "VirusTotal could not be asked just now. Try again in a moment."


def _refused(status_code: int, code: str, message: str, **headers: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content={"detail": message, "code": code}, headers=headers or None
    )


def _service(request: Request) -> FileReputationService:
    service: Optional[FileReputationService] = getattr(
        request.app.state, "file_reputation", None
    )
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="File checks are not set up in this process.",
        )
    return service


def _is_owner(user: User) -> bool:
    return getattr(user, "is_admin", False) is True


class CheckBody(BaseModel):
    """A fingerprint the browser computed, with the facts the person's row shows."""

    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(max_length=200)
    name: Optional[str] = Field(default=None, max_length=255)
    size_bytes: Optional[int] = Field(default=None, ge=0)
    media_type: Optional[str] = Field(default=None, max_length=100)


@router.get("")
async def list_file_checks(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """The caller's checks, newest first, and the service's state (?limit=1..100)."""
    service = _service(request)
    user_id = str(current_user.id)
    return {
        "service": await service.status(user_id, is_owner=_is_owner(current_user)),
        "checks": await service.list_checks(user_id, limit),
    }


@router.post("/check", response_model=None)
async def check_file_hash(
    body: CheckBody,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Look up a fingerprint the browser computed (the file stays in the browser)."""
    service = _service(request)
    user_id = str(current_user.id)
    digest = normalise_sha256(body.sha256)
    if digest is None:
        return _refused(_UNPROCESSABLE, "bad_hash", BAD_HASH)
    if not await service.remote_configured():
        # The switch's sentence: the owner's (off, or add a key) or "not set up" for others.
        state = await service.status(user_id, is_owner=_is_owner(current_user))
        sentence = state.get("reason") or NOT_SET_UP_SENTENCE
        return _refused(status.HTTP_409_CONFLICT, "service_off", sentence)
    verdict = await service.check_hash(
        user_id,
        digest,
        name=body.name or "file",
        size_bytes=body.size_bytes,
        media_type=body.media_type,
        source="page",
        priority="explicit",
        wait_s=10.0,
        alert="caller",
    )
    row = await service.get_check(user_id, verdict.check_id) if verdict.check_id else None
    if row is None:
        return _refused(status.HTTP_503_SERVICE_UNAVAILABLE, "service_error", LOOKUP_FAILED)
    return row


async def _read_body(request: Request) -> tuple[Optional[bytes], Optional[JSONResponse]]:
    """The optional raw body (the picked file): None when there is none, or the refusal for a
    body over 20 MB (from its Content-Length before reading, else while streaming)."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.strip().isdigit() and int(declared) > PAGE_UPLOAD_MAX_BYTES:
        return None, _refused(_TOO_LARGE, "too_large", TOO_LARGE)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > PAGE_UPLOAD_MAX_BYTES:
            return None, _refused(_TOO_LARGE, "too_large", TOO_LARGE)
    return (bytes(body) if body else None), None


def _upload_answer(outcome: UploadRequestOutcome, response: Response) -> Any:
    if outcome.status == "refused":
        code = outcome.code or "refused"
        headers = {"Retry-After": str(outcome.retry_after)} if outcome.retry_after else {}
        return _refused(_UPLOAD_STATUS.get(code, status.HTTP_409_CONFLICT), code, outcome.message, **headers)
    if outcome.status == "pending":
        response.status_code = status.HTTP_200_OK
    return {
        "action_id": outcome.action_id,
        "expires_at": outcome.expires_at.isoformat() if outcome.expires_at else None,
        "state": "upload_pending",
        "reason": outcome.message,
    }


@router.post("/{check_id}/upload", status_code=status.HTTP_202_ACCEPTED, response_model=None)
async def request_file_upload(
    check_id: str,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Ask to send one file VirusTotal does not know: parks an approval card (nothing is sent
    before it is approved). The optional raw body is the file the owner picked on the page."""
    service = _service(request)
    user_id = str(current_user.id)
    wait = service.take_upload_request_slot(user_id)
    if wait is not None:
        return _refused(
            status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited", RATE_LIMITED, **{"Retry-After": str(wait)}
        )
    data, refusal = await _read_body(request)
    if refusal is not None:
        return refusal
    outcome = await service.request_upload(user_id, check_id, data)
    return _upload_answer(outcome, response)


@router.delete("/{check_id}", status_code=status.HTTP_204_NO_CONTENT)
async def forget_file_check(
    check_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Forget one check (and any copy held for an upload)."""
    if not await _service(request).forget(str(current_user.id), check_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
