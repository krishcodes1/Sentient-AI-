"""Web chat /scam (security S3): recognises "/scam ..." in a web chat message
and answers it with a scam check instead of a chat turn.

Why it exists: a pasted scam often carries look-alike letters or hidden
characters that PromptGuard blocks in a normal turn, and it is someone else's
words, so a web chat's /scam (with any screenshots or attached files) is
checked out of turn and stored fenced as untrusted (review SEC-F11: with files
it is still someone else's message). No chat turn runs and no PromptGuard
input scan blocks the pasted message; the check's own AI step is one
tool-less call through the runtime (services/scam_check/service.py).

Import rule: never import api.routes.agent at module level here (agent.py
imports this module).

Connects to: api/routes/agent.py (send_message and stream_message),
services/scam_check/service.py, services/scam_check/records.py.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy import select

from services.scam_check.records import add_check_rows
from services.scam_check.service import (
    ScamCheckRequest,
    ScamCheckResult,
    ScamFile,
    ScamImage,
)
from services.scam_check.verdict import render_markdown

# "/scam" at the very start, then whitespace or the end ("/scammers" is not the command).
SCAM_RE = re.compile(r"^/scam(?=\s|$)\s*(?P<rest>.*)$", re.IGNORECASE | re.DOTALL)
# The most files one web message carries (agent.MAX_FILES_PER_MESSAGE).
MAX_FILES = 5

NO_SERVICE = "Scam checks aren't set up in this process."
FILE_NOT_FOUND = "An attached file was not found: it expired, was forgotten or is not yours."
EMPTY_COMMAND = "Paste the message or link after /scam, or attach a screenshot."


def parse_scam_command(content: str) -> Optional[str]:
    """The text after a leading /scam (may be ""), or None when the message is
    not a /scam command. Hidden characters in the text are kept: they are
    part of what is checked."""
    if not isinstance(content, str):
        return None
    match = SCAM_RE.match(content.strip())
    return match.group("rest") if match else None


def _file_uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


def _aware(moment: Any) -> Optional[datetime]:
    if not isinstance(moment, datetime):
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


async def _files_for(db: Any, user_id: Any, file_ids: Sequence[Any]) -> tuple[tuple[ScamFile, ...], bool]:
    """(the files' fingerprints, whether any id was missing): one SELECT of
    UserFile.sha256 and size_bytes for this user's own, unexpired uploads. An
    id that is not the user's, has expired or does not parse counts as
    missing; nothing about another user's file is read."""
    from models.user_file import UserFile

    wanted = [_file_uuid(value) for value in list(dict.fromkeys(file_ids))[:MAX_FILES]]
    if not wanted:
        return (), False
    if any(fid is None for fid in wanted):
        return (), True
    owner = _file_uuid(user_id)
    if owner is None:
        return (), True
    rows = (
        await db.execute(
            select(UserFile.id, UserFile.sha256, UserFile.size_bytes, UserFile.expires_at).where(
                UserFile.user_id == owner, UserFile.id.in_(wanted)
            )
        )
    ).all()
    now = datetime.now(timezone.utc)
    found = {
        row[0]: ScamFile(sha256=str(row[1]), size_bytes=int(row[2] or 0))
        for row in rows
        if (_aware(row[3]) or now) >= now
    }
    files = tuple(found[fid] for fid in wanted if fid in found)
    return files, len(files) < len(wanted)


async def answer_web_scam_command(
    db: Any,
    app: Any,
    user: Any,
    conversation: Any,
    text: str,
    images: Sequence[Any],
    *,
    file_ids: Sequence[uuid.UUID] = (),
) -> tuple[Any, Any]:
    """Run the check for a web chat /scam and add both rows to *conversation*
    (the caller commits); a refusal is the reply row's text. No chat turn and
    no PromptGuard input scan. Each of *file_ids* becomes a ScamFile from one
    SELECT of UserFile.sha256 and size_bytes for this user (an id that is not
    the user's, or expired, gives the reply row "An attached file was not
    found: it expired, was forgotten or is not yours." and no check); review
    SEC-F11. *images* are the route's already-validated ImageAttachments."""
    scam_images = tuple(
        ScamImage(media_type=str(getattr(image, "media_type", "") or ""), data=str(getattr(image, "data", "") or ""), source="upload")
        for image in images or ()
    )
    files, missing = await _files_for(db, user.id, file_ids)
    request = ScamCheckRequest(
        user_id=str(user.id),
        channel="web_chat",
        text=text if isinstance(text, str) else "",
        images=scam_images,
        files=files,
    )
    service = getattr(app.state, "scam_check", None)
    result: ScamCheckResult
    if service is None:
        result = ScamCheckResult(ok=False, refusal=NO_SERVICE, reason="not_set_up")
    elif missing:
        result = ScamCheckResult(ok=False, refusal=FILE_NOT_FOUND, reason="not_found")
    elif not request.text.strip() and not scam_images and not files:
        # Nothing to check: no quota, no model, no audit row.
        result = ScamCheckResult(ok=False, refusal=EMPTY_COMMAND, reason="empty")
    else:
        result = await service.check(request)
    rendered = render_markdown(result) if result.ok else result.refusal
    return await add_check_rows(db, conversation, request, result, rendered)
