"""Serves Security -> Check for scams (/api/security/scam-check): one
out-of-turn "is this a scam?" check of pasted text or screenshots, and what
the tab shows before a check (the switch, the provider, the person's checks
left today).

Why it exists: a person who received a suspicious message should be able to
ask about it without starting a chat turn that would treat the pasted text
as their own words. The check runs through the one ``ScamCheckService``, so
the page, web chat's /scam, Telegram and Slack give the same answer. The
check and its verdict are saved in the person's own "Scam checks" chat (the
pasted text fenced as someone else's words), which is also how its provider
spend reaches /usage.

Any signed-in user may check; the owner's scam_check switch is read per
check (403 when off), a capability report that cannot be read answers 503
(fail closed), and the per-person quota answers 429. The answer is never
"safe", and no host in it is ever a link (the tab shows them as code text).

Connects to: services/scam_check/service.py (``app.state.scam_check``),
services/scam_check/records.py (the "Scam checks" chat), api/routes/agent.py
(``ImageAttachment``: the chat's own picture validation).
Used by: the Security page's Check for scams tab; main.py mounts the router.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

# The chat's picture model (data URLs split, 5 MB cap, the four image types). The
# api.routes package imports agent first, so this import adds no cycle.
from api.routes.agent import MAX_IMAGES_PER_MESSAGE, ImageAttachment
from core.database import get_db
from core.validation import SafeStr
from models.user import User
from services.auth import get_current_user
from services.scam_check.records import add_check_rows, scam_checks_conversation
from services.scam_check.review import MAX_NOTE_CHARS
from services.scam_check.service import (
    ScamCheckRequest,
    ScamCheckResult,
    ScamGateUnavailable,
    ScamImage,
)
from services.scam_check.verdict import ADVICE_NOT_CHECKED, notes_for, render_markdown, to_json
from services.security.scam_signals import MAX_TEXT_CHARS

router = APIRouter(prefix="/security", tags=["security"])

NOT_READY = "The server is still starting. Try again shortly."
GATE_UNREADABLE = "Crawler couldn't check whether scam checks are on. Try again in a minute."
NOTHING_TO_CHECK = "Paste a message or link, or add a screenshot."

# A refusal's HTTP status (the sentence is the detail). provider_blind is not here:
# the check reached the service, so it answers 200 with "couldn't check".
_REFUSAL_STATUS: dict[str, int] = {
    "gate_error": status.HTTP_503_SERVICE_UNAVAILABLE,
    "capability_off": status.HTTP_403_FORBIDDEN,
    "capability_blocked": status.HTTP_403_FORBIDDEN,
    "quota_burst": status.HTTP_429_TOO_MANY_REQUESTS,
    "quota_daily": status.HTTP_429_TOO_MANY_REQUESTS,
    "empty": 422,
}


class ScamCheckIn(BaseModel):
    """What the tab sends: the pasted text, the person's own note, and up to
    four screenshots (base64 or data URLs; agent.ImageAttachment validates
    them exactly as the chat does)."""

    text: SafeStr = Field("", max_length=MAX_TEXT_CHARS)
    note: SafeStr = Field("", max_length=MAX_NOTE_CHARS)
    images: list[ImageAttachment] = Field(default_factory=list, max_length=MAX_IMAGES_PER_MESSAGE)


def _service(request: Request) -> Any:
    service = getattr(request.app.state, "scam_check", None)
    if service is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=NOT_READY)
    return service


def _blind_answer(result: ScamCheckResult, pictures: int) -> ScamCheckResult:
    """A picture-only check the provider cannot see, as the tab shows it:
    "couldn't check", why, and what to try instead (not an HTTP error)."""
    return ScamCheckResult(
        ok=True,
        verdict="not_checked",
        rule_verdict="not_checked",
        advice=(ADVICE_NOT_CHECKED,),
        notes=notes_for(("no_vision",), provider=result.provider),
        note_codes=("no_vision",),
        provider=result.provider,
        images=pictures,
    )


@router.post("/scam-check")
async def run_scam_check(
    body: ScamCheckIn,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Check one message (text, screenshots) out of turn and save it, with its
    verdict, in the person's "Scam checks" chat."""
    if not body.text.strip() and not body.images:
        raise HTTPException(status_code=422, detail=NOTHING_TO_CHECK)
    service = _service(request)
    check = ScamCheckRequest(
        user_id=str(current_user.id),
        channel="web_box",
        text=body.text,
        note=body.note,
        images=tuple(ScamImage(media_type=image.media_type, data=image.data, source="upload") for image in body.images),
    )
    result: ScamCheckResult = await service.check(check)
    if not result.ok:
        if result.reason != "provider_blind":
            code = _REFUSAL_STATUS.get(result.reason, status.HTTP_503_SERVICE_UNAVAILABLE)
            detail = GATE_UNREADABLE if result.reason == "gate_error" else result.refusal
            if result.reason == "empty":
                detail = NOTHING_TO_CHECK
            raise HTTPException(status_code=code, detail=detail)
        result = _blind_answer(result, len(check.images))
    conversation = await scam_checks_conversation(db, current_user.id)
    await add_check_rows(db, conversation, check, result, render_markdown(result))
    return {
        **to_json(result),
        "conversation_id": str(conversation.id),
        "usage": dict(result.usage),
        "provider": result.provider,
        "model": result.model,
    }


@router.get("/scam-check/status")
async def scam_check_status(request: Request, current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    """What the tab shows before a check: whether checks are on (and why not),
    the person's AI provider and whether it sees pictures, whether Google's
    list and file checks are set up, and today's checks used of the cap."""
    service = _service(request)
    try:
        answer: dict[str, Any] = await service.status(str(current_user.id))
    except ScamGateUnavailable:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=GATE_UNREADABLE) from None
    return answer
