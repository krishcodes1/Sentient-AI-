"""Serves /api/skills (owner only): every bundled skill with its status, hash,
scan findings and on/off switch; one skill with the text of each of its
files; and the switch itself.

Why it exists: the owner decides which of the reviewed playbooks Crawler may
follow on this install (Settings → Skills), and can read exactly what each
one says before leaving it on. The switch is install-wide, so every route
is owner only (require_admin: 403 for anyone else). A skill that is not
usable (blocked, invalid, not pinned, or changed on disk, which is checked
again before it is switched on) cannot be switched on (409); switching any
skill off always works. Every change is audited with the skill's name and
hash only. Files are served as plain text for the page to show in a <pre>,
never rendered, and are hashed again first, so one edited since startup
shows as changed; files that merely could not be read just now are a 503
for that request and mark nothing. An unknown name is a 404.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes._deps import require_admin
from core.database import get_db
from models.audit import AuditStatus
from models.skill_state import SkillState
from models.user import User
from services.audit import append_audit_log
from services.skills import manifest as skills_manifest
from services.skills.loader import (
    MAX_REFERENCE_BYTES,
    MAX_SKILL_BYTES,
    STATUS_CHANGED,
    SkillReadError,
    SkillRecord,
    bundled_catalog,
    current_hash,
    mark_changed,
    normalise_newlines,
)
from services.skills.scanner import SKILL_FILE
from services.tools.skills import valid_skill_name

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/skills", tags=["skills"])

EVENT_ENABLED = "skill_enabled"
EVENT_DISABLED = "skill_disabled"


class SkillPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


async def _switches(db: AsyncSession) -> dict[str, bool]:
    """The owner's stored switches by skill name; a skill with no row is on."""
    rows = await db.execute(select(SkillState.name, SkillState.enabled))
    return {name: bool(enabled) for name, enabled in rows.all()}


def _info(record: SkillRecord, switches: dict[str, bool]) -> dict[str, Any]:
    return {**record.to_info(), "enabled": switches.get(record.name, True)}


def _record(name: str) -> SkillRecord:
    record = bundled_catalog().get(name) if valid_skill_name(name) else None
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such skill.")
    return record


async def _rechecked(record: SkillRecord) -> SkillRecord:
    """*record*, or, when a usable skill's files no longer hash to what was
    loaded, the same skill marked changed (for every later view too). A
    503 when they could not be read just now: no evidence of a change, so
    nothing is marked."""
    if not record.usable:
        return record
    try:
        now = await asyncio.to_thread(current_hash, record)
    except SkillReadError:
        logger.warning("skill_files_unreadable", skill=record.name)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The skill's files could not be read just now; try again shortly.",
        ) from None
    if now == record.sha256:
        return record
    return mark_changed(record.name) or dataclasses.replace(
        record, status=STATUS_CHANGED, status_reason=skills_manifest.CHANGED_REASON
    )


def _file_text(skill_dir: Path, relpath: str) -> Optional[str]:
    """One of the skill's files as text (LF line endings, undecodable bytes
    replaced), or None when it is gone, oversized or reached through a
    symlink. *relpath* is one the loader listed (SKILL.md or
    references/<file>), never a caller's path."""
    path = skill_dir / relpath
    cap = MAX_SKILL_BYTES if relpath == SKILL_FILE else MAX_REFERENCE_BYTES
    try:
        if any(p.is_symlink() for p in (skill_dir, path.parent, path)):
            return None
        if not path.is_file() or path.stat().st_size > 2 * cap:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return normalise_newlines(data).decode("utf-8", errors="replace")


def _files(record: SkillRecord) -> list[dict[str, str]]:
    """Every file the loader read, SKILL.md first, with its text."""
    files: list[dict[str, str]] = []
    for relpath in sorted(record.files, key=lambda p: (p != SKILL_FILE, p)):
        text = _file_text(Path(record.path), relpath)
        if text is not None:
            files.append({"path": relpath, "text": text})
    return files


@router.get("")
async def list_skills(
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Every bundled skill, sorted by name, with its status, hash, findings
    and switch."""
    switches = await _switches(db)
    return [_info(record, switches) for record in bundled_catalog()]


@router.get("/{name}")
async def get_skill(
    name: str,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """One skill, plus the text of each of its files."""
    record = await _rechecked(_record(name))
    files = await asyncio.to_thread(_files, record)
    return {**_info(record, await _switches(db)), "files": files}


@router.patch("/{name}")
async def set_skill(
    name: str,
    body: SkillPatch,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Switch one skill on or off for the whole install (audited). 409 when
    switching on a skill that cannot be used."""
    record = _record(name)
    if body.enabled:
        record = await _rechecked(record)
        if not record.usable:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"This skill cannot be switched on: its status is {record.status}. "
                    "Its scan report says why."
                ),
            )
    row = await db.get(SkillState, record.name)
    if row is None:
        row = SkillState(name=record.name, enabled=body.enabled)
        db.add(row)
    row.enabled = body.enabled
    row.sha256 = record.sha256
    row.updated_by = owner.id
    row.updated_at = datetime.now(timezone.utc)
    await db.flush()
    event = EVENT_ENABLED if body.enabled else EVENT_DISABLED
    await append_audit_log(
        db,
        user_id=owner.id,
        connector_name="skills",
        action=event,
        endpoint="/api/skills/{name}",
        scope_used="skills",
        status=AuditStatus.approved,
        reasoning_chain={"event": event},
        request_data={"name": record.name, "sha256": record.sha256},
    )
    logger.info(event, skill=record.name)
    return {**record.to_info(), "enabled": body.enabled}
