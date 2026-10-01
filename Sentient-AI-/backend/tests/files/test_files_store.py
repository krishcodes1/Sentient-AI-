"""Tests for services/files/store.py (the encrypted upload store) on the test
database: ingest, dedupe, the quota and hourly rate, expiry and its
extension on read, isolation between users, no plaintext at rest, the cascade
on account deletion, and the export's metadata.

Why it exists: uploads hold a user's documents for 30 days; these tests hold
that only the owner can read them, only encrypted text is stored, and they
go away when they should.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from models.user import User
from models.user_file import UserFile
from services.files import store as store_module
from services.files.sandbox import InProcessSandbox
from services.files.sections import ExtractionRefused
from services.files.store import UserFileStore
from tests.conftest import auth_headers, make_user
from tests.files import builders as b

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


def make_store(session_factory, clock=None) -> UserFileStore:
    return UserFileStore(session_factory, sandbox=InProcessSandbox(), clock=clock or Clock())


async def ingest(store, user, data=None, name="syllabus.pdf"):
    return await store.ingest(
        str(user.id), data=data or b.make_pdf(["Midterm: Oct 12", "Late work: -10%"]), name=name,
        declared_mime="application/pdf", source="web",
    )


@pytest.mark.asyncio
async def test_ingest_stores_facts_and_encrypted_sections(session_factory):
    user, _ = await make_user(session_factory, "store@example.com")
    store = make_store(session_factory)
    info = await ingest(store, user)
    assert (info.kind, info.pages, info.sections_count, info.source) == ("pdf", 2, 2, "web")
    assert info.expires_at == T0 + timedelta(days=30)
    found = await store.get_extraction(str(user.id), info.id)
    assert found is not None
    assert [s.text for s in found[1].sections] == ["Midterm: Oct 12", "Late work: -10%"]


@pytest.mark.asyncio
async def test_no_plaintext_in_the_content_column(session_factory):
    user, _ = await make_user(session_factory, "plain@example.com")
    info = await ingest(make_store(session_factory), user)
    async with session_factory() as session:
        raw = (
            await session.execute(select(UserFile.content).where(UserFile.id == uuid.UUID(info.id)))
        ).scalar_one()
    assert b"Midterm" not in raw and b"Late work" not in raw
    assert b"sections" not in raw


@pytest.mark.asyncio
async def test_a_reupload_is_deduplicated_and_refreshes_the_expiry(session_factory):
    user, _ = await make_user(session_factory, "dedupe@example.com")
    clock = Clock()
    store = make_store(session_factory, clock)
    first = await ingest(store, user)
    clock.now = T0 + timedelta(days=5)
    second = await ingest(store, user)
    assert second.id == first.id and second.deduped is True
    assert second.expires_at == T0 + timedelta(days=35)
    assert len(await store.list(str(user.id))) == 1


@pytest.mark.asyncio
async def test_the_quota_is_enforced(session_factory, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_FILES_PER_USER", 2)
    user, _ = await make_user(session_factory, "quota@example.com")
    store = make_store(session_factory)
    await ingest(store, user, b.make_pdf(["one"]))
    await ingest(store, user, b.make_pdf(["two"]))
    with pytest.raises(ExtractionRefused) as caught:
        await ingest(store, user, b.make_pdf(["three"]))
    assert caught.value.code == "quota_full" and "100 files" in caught.value.message


@pytest.mark.asyncio
async def test_the_stored_bytes_quota_is_enforced(session_factory, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_STORED_BYTES_PER_USER", 10)
    user, _ = await make_user(session_factory, "bytes@example.com")
    with pytest.raises(ExtractionRefused) as caught:
        await ingest(make_store(session_factory), user)
    assert caught.value.code == "quota_full"


@pytest.mark.asyncio
async def test_the_hourly_rate_is_enforced(session_factory, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_UPLOADS_PER_HOUR", 2)
    user, _ = await make_user(session_factory, "rate@example.com")
    clock = Clock()
    store = make_store(session_factory, clock)
    await ingest(store, user, b.make_pdf(["one"]))
    await ingest(store, user, b.make_pdf(["two"]))
    with pytest.raises(ExtractionRefused) as caught:
        await ingest(store, user, b.make_pdf(["three"]))
    assert caught.value.code == "rate_limited"
    clock.now = T0 + timedelta(hours=2)
    assert (await ingest(store, user, b.make_pdf(["three"]))).kind == "pdf"


@pytest.mark.asyncio
async def test_expired_files_are_purged_and_reads_move_the_expiry(session_factory):
    user, _ = await make_user(session_factory, "expiry@example.com")
    clock = Clock()
    store = make_store(session_factory, clock)
    info = await ingest(store, user)
    clock.now = T0 + timedelta(days=20)
    read = await store.get_extraction(str(user.id), info.id)
    assert read is not None and read[0].expires_at == T0 + timedelta(days=50)
    clock.now = T0 + timedelta(days=51)
    assert await store.get_extraction(str(user.id), info.id) is None
    async with session_factory() as session:
        assert (await session.execute(select(UserFile))).scalars().all() == []


@pytest.mark.asyncio
async def test_purge_at_startup_removes_every_expired_row(session_factory):
    alice, _ = await make_user(session_factory, "p1@example.com")
    bob, _ = await make_user(session_factory, "p2@example.com")
    clock = Clock()
    store = make_store(session_factory, clock)
    await ingest(store, alice)
    await ingest(store, bob)
    clock.now = T0 + timedelta(days=31)
    assert await store.purge_expired() == 2


@pytest.mark.asyncio
async def test_another_users_file_reads_as_unknown(session_factory):
    alice, _ = await make_user(session_factory, "alice-files@example.com")
    bob, _ = await make_user(session_factory, "bob-files@example.com")
    store = make_store(session_factory)
    info = await ingest(store, alice)
    assert await store.get_extraction(str(bob.id), info.id) is None
    assert await store.get_info(str(bob.id), info.id) is None
    assert await store.list(str(bob.id)) == []
    assert await store.delete(str(bob.id), info.id) is False
    assert await store.delete(str(alice.id), info.id) is True
    assert await store.get_info(str(alice.id), info.id) is None


@pytest.mark.asyncio
async def test_a_bad_id_is_unknown(session_factory):
    user, _ = await make_user(session_factory, "badid@example.com")
    store = make_store(session_factory)
    assert await store.get_extraction(str(user.id), "not-a-uuid") is None
    assert await store.delete(str(user.id), "../etc") is False


@pytest.mark.asyncio
async def test_rows_cascade_when_the_account_is_deleted(session_factory):
    user, _ = await make_user(session_factory, "cascade-files@example.com")
    await ingest(make_store(session_factory), user)
    async with session_factory() as session:
        await session.execute(delete(User).where(User.id == user.id))
        await session.commit()
        assert (await session.execute(select(UserFile))).scalars().all() == []


@pytest.mark.asyncio
async def test_the_export_lists_files_as_metadata_only(client, session_factory):
    user, token = await make_user(session_factory, "export-files@example.com")
    store = UserFileStore(session_factory, sandbox=InProcessSandbox())
    await ingest(store, user)
    response = await client.get("/api/auth/export", headers=auth_headers(token))
    assert response.status_code == 200
    data = json.loads(response.text)
    assert [f["name"] for f in data["files"]] == ["syllabus.pdf"]
    assert data["files"][0]["kind"] == "pdf" and data["files"][0]["pages"] == 2
    assert "Midterm" not in response.text
