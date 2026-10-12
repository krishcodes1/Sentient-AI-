"""Tests for /api/skills (api/routes/skills.py): every route is the owner's
only (403 for a member); the list and detail shapes (SkillInfo, sorted by
name; the files as plain text, SKILL.md first); switching a skill off or on
is persisted, audited with its name and hash only, and honoured by
skills.read; switching on a skill that is not usable, or one changed on
disk, is a 409; files that cannot be read just now are a 503 that marks
nothing; a strict body; an unknown or malformed name is a 404.

Why it exists: the switch is install-wide, so a member must never reach it,
and the owner must only be able to switch on text that is still the pinned,
scanner-clean version they can read here. Skills are written to a temporary
folder and pinned there, standing in for the bundled catalog.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select, update

from models.audit import AuditLog
from models.skill_state import SkillState
from models.user import User
from services.skills import loader
from services.skills.loader import SkillCatalog, load_skills
from services.tools.skills import SkillsToolkit
from tests.conftest import auth_headers, make_user
from tests.test_skills_loader import BODY, failing_reads, pin, write_skill

INFO_KEYS = {
    "name",
    "title",
    "description",
    "category",
    "version",
    "license",
    "source",
    "sha256",
    "status",
    "status_reason",
    "enabled",
    "tools",
    "requires",
    "findings",
}
REFERENCE = "# Checklist\n\nOne.\n"


@pytest.fixture
def catalog(tmp_path: Path, monkeypatch) -> SkillCatalog:
    write_skill(
        tmp_path,
        extra="title: Week planner\nmetadata:\n  crawler:\n    tools: [canvas.get_upcoming]\n",
        files={"references/checklist.md": REFERENCE},
    )
    write_skill(tmp_path, "another-skill")
    pin(tmp_path)
    write_skill(tmp_path, "unpinned-skill")
    loaded = load_skills(tmp_path)
    monkeypatch.setattr(loader, "_bundled", loaded)
    return loaded


async def _account(session_factory, email: str, *, owner: bool):
    user, token = await make_user(session_factory, email)
    if owner:
        async with session_factory() as session:
            await session.execute(update(User).where(User.id == user.id).values(is_admin=True))
            await session.commit()
    return user, auth_headers(token)


@pytest.mark.asyncio
async def test_a_member_is_refused_every_route(client, session_factory, catalog):
    _, headers = await _account(session_factory, "member@example.com", owner=False)
    assert (await client.get("/api/skills", headers=headers)).status_code == 403
    assert (await client.get("/api/skills/week-planner", headers=headers)).status_code == 403
    resp = await client.patch("/api/skills/week-planner", json={"enabled": False}, headers=headers)
    assert resp.status_code == 403
    async with session_factory() as session:
        assert (await session.execute(select(SkillState))).scalars().all() == []


@pytest.mark.asyncio
async def test_the_list_is_every_skill_sorted_with_its_switch(client, session_factory, catalog):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    resp = await client.get("/api/skills", headers=headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert [row["name"] for row in rows] == ["another-skill", "unpinned-skill", "week-planner"]
    assert all(set(row) == INFO_KEYS for row in rows)
    week = rows[2]
    assert week["title"] == "Week planner" and week["source"] == "bundled"
    assert week["status"] == "ok" and week["status_reason"] is None and week["enabled"] is True
    assert week["sha256"] == catalog.get("week-planner").sha256
    assert week["tools"] == ["canvas.get_upcoming"]
    assert week["requires"] == {"connectors": [], "capabilities": []}
    assert rows[1]["status"] == "unpinned" and rows[1]["status_reason"]


@pytest.mark.asyncio
async def test_the_detail_shows_every_file_as_text(client, session_factory, catalog, tmp_path):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    resp = await client.get("/api/skills/week-planner", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == INFO_KEYS | {"files"}
    assert [f["path"] for f in body["files"]] == ["SKILL.md", "references/checklist.md"]
    skill_md = (tmp_path / "week-planner" / "SKILL.md").read_text(encoding="utf-8")
    assert body["files"][0]["text"] == skill_md and skill_md.startswith("---\nname: week-planner")
    assert body["files"][0]["text"].endswith(BODY)
    assert body["files"][1]["text"] == REFERENCE
    for name in ("no-such-skill", "Week-Planner", "week_planner"):
        assert (await client.get(f"/api/skills/{name}", headers=headers)).status_code == 404


@pytest.mark.asyncio
async def test_switching_off_and_on_is_persisted_audited_and_honoured(
    client, session_factory, catalog
):
    owner, headers = await _account(session_factory, "owner@example.com", owner=True)
    sha = catalog.get("week-planner").sha256
    off = await client.patch("/api/skills/week-planner", json={"enabled": False}, headers=headers)
    assert off.status_code == 200
    assert off.json()["enabled"] is False and set(off.json()) == INFO_KEYS
    async with session_factory() as session:
        row = await session.get(SkillState, "week-planner")
        assert row is not None and row.enabled is False
        assert row.sha256 == sha and row.updated_by == owner.id
    listed = (await client.get("/api/skills", headers=headers)).json()
    assert {r["name"]: r["enabled"] for r in listed}["week-planner"] is False
    # The model can no longer read it.
    refused = await SkillsToolkit(session_factory).execute("read", {"name": "week-planner"})
    assert refused["rule"] == "skill_off"

    on = await client.patch("/api/skills/week-planner", json={"enabled": True}, headers=headers)
    assert on.status_code == 200 and on.json()["enabled"] is True
    assert (await SkillsToolkit(session_factory).execute("read", {"name": "week-planner"}))["ok"]

    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.user_id == owner.id, AuditLog.connector_name == "skills")
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    assert [r.action for r in rows] == ["skill_disabled", "skill_enabled"]
    for r in rows:
        assert r.request_data == {"name": "week-planner", "sha256": sha}
        assert r.status.value == "approved"
    # Facts only: none of the skill's own text reaches the audit log.
    assert "Show the week" not in json.dumps([r.request_data for r in rows])


@pytest.mark.asyncio
async def test_a_skill_that_is_not_usable_cannot_be_switched_on(client, session_factory, catalog):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    resp = await client.patch("/api/skills/unpinned-skill", json={"enabled": True}, headers=headers)
    assert resp.status_code == 409 and "unpinned" in resp.json()["detail"]
    async with session_factory() as session:
        assert await session.get(SkillState, "unpinned-skill") is None
    # Switching it off always works.
    off = await client.patch("/api/skills/unpinned-skill", json={"enabled": False}, headers=headers)
    assert off.status_code == 200 and off.json()["enabled"] is False


@pytest.mark.asyncio
async def test_a_skill_changed_on_disk_cannot_be_switched_on(
    client, session_factory, catalog, tmp_path
):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    (tmp_path / "another-skill" / "SKILL.md").write_text("changed\n", encoding="utf-8")
    resp = await client.patch("/api/skills/another-skill", json={"enabled": True}, headers=headers)
    assert resp.status_code == 409 and "changed" in resp.json()["detail"]
    listed = (await client.get("/api/skills", headers=headers)).json()
    assert {r["name"]: r["status"] for r in listed}["another-skill"] == "changed"


@pytest.mark.asyncio
async def test_the_detail_rechecks_the_hash(client, session_factory, catalog, tmp_path):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    (tmp_path / "week-planner" / "references" / "checklist.md").write_text("Edited.\n")
    body = (await client.get("/api/skills/week-planner", headers=headers)).json()
    assert body["status"] == "changed"
    assert body["files"][1]["text"] == "Edited.\n"  # what is on disk now, for review


@pytest.mark.asyncio
async def test_files_unreadable_just_now_are_a_503_and_mark_nothing(
    client, session_factory, catalog, monkeypatch
):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    with failing_reads(monkeypatch):
        detail = await client.get("/api/skills/week-planner", headers=headers)
        assert detail.status_code == 503 and "try again" in detail.json()["detail"]
        on = await client.patch("/api/skills/week-planner", json={"enabled": True}, headers=headers)
        assert on.status_code == 503
    async with session_factory() as session:
        assert await session.get(SkillState, "week-planner") is None
    # Readable again: still ok, and it can be switched on.
    assert loader.bundled_catalog().get("week-planner").status == "ok"
    detail = await client.get("/api/skills/week-planner", headers=headers)
    assert detail.status_code == 200 and detail.json()["status"] == "ok"
    on = await client.patch("/api/skills/week-planner", json={"enabled": True}, headers=headers)
    assert on.status_code == 200 and on.json()["status"] == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [{"enabled": "yes"}, {"enabled": 1}, {}, {"enabled": True, "sha256": "x"}, None]
)
async def test_the_body_is_strict(client, session_factory, catalog, payload):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    resp = await client.patch("/api/skills/week-planner", json=payload, headers=headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_an_unknown_skill_is_a_404(client, session_factory, catalog):
    _, headers = await _account(session_factory, "owner@example.com", owner=True)
    for name in ("no-such-skill", "Bad_Name"):
        resp = await client.patch(f"/api/skills/{name}", json={"enabled": False}, headers=headers)
        assert resp.status_code == 404
    async with session_factory() as session:
        assert (await session.execute(select(SkillState))).scalars().all() == []
