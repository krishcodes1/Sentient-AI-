"""Tests for the transcript cache (media_transcripts): saving and merging
provider windows, a cache hit marking the row used, one user never reading
another's rows, the 200-row least-recently-used cap, expiry (and a shortened
keep_transcripts_days) purged lazily and by the janitor, the per-day billed
seconds, the account export and the cascade on account deletion, and
migration 0024_media_transcripts upgrading and downgrading on SQLite.

Why it exists: the cache is what keeps follow-up questions free, and it
holds publisher text per user: isolation, retention and the daily cap all
live here. In-memory SQLite through the shared session_factory fixture
(Postgres in CI with TEST_DATABASE_URL).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import select

from models.media_transcript import MediaTranscript
from services.notifications.transcripts import TranscriptJanitor
from services.tools.video.store import TranscriptStore, covers, merge_windows
from tests.conftest import auth_headers, make_user
from tests.test_page_watch_migration import _config, _inspect

REVISION = "0024_media_transcripts"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


async def save(store: TranscriptStore, user_id: str, key: str = "yt:abcdefghijk", **fields):
    defaults = {
        "source_key": key,
        "kind": "youtube",
        "method": "provider_video",
        "detail": "notes",
        "display_url": "https://www.youtube.com/watch?v=abcdefghijk",
        "engine": "gemini-3.5-flash-lite",
        "segments": [(10.0, 20.0, "first"), (1000.0, 1010.0, "second")],
        "window": (0.0, 2700.0),
        "billed_seconds": 2700,
    }
    defaults.update(fields)
    return await store.save_merge(user_id, **defaults)


def test_window_helpers():
    assert merge_windows([(2700, 5400), (0, 2700), (6000, 7000)]) == ((0, 5400), (6000, 7000))
    assert covers([(0, 2700)], 60, 2700) and not covers([(0, 2700)], 60, 2800)


@pytest.mark.asyncio
async def test_save_merge_and_a_cache_hit(session_factory):
    user, _ = await make_user(session_factory, "store-1@example.com")
    clock = Clock()
    store = TranscriptStore(session_factory, clock=clock)
    uid = str(user.id)
    await save(store, uid)
    merged = await save(
        store,
        uid,
        segments=[(2710.0, 2800.0, "third"), (1000.0, 1005.0, "never: outside its window")],
        window=(2700.0, 5400.0),
        title="Lecture 5",
    )
    assert [s[2] for s in merged.segments] == ["first", "second", "third"]
    assert merged.covered == ((0.0, 5400.0),) and merged.title == "Lecture 5"
    replaced = await save(store, uid, segments=[(15.0, 30.0, "first, read again")], window=(0.0, 900.0))
    assert [s[2] for s in replaced.segments] == ["first, read again", "second", "third"]

    clock.now += timedelta(days=10)
    hit = await store.get(uid, "yt:abcdefghijk", "provider_video", "notes", keep_days=14)
    assert hit is not None and hit.expires_at == clock.now + timedelta(days=14)
    assert await store.get(uid, "yt:abcdefghijk", "provider_video", "verbatim") is None


@pytest.mark.asyncio
async def test_one_user_never_reads_anothers_rows(session_factory):
    alice, _ = await make_user(session_factory, "alice-video@example.com")
    bob, _ = await make_user(session_factory, "bob-video@example.com")
    store = TranscriptStore(session_factory)
    await save(store, str(alice.id))
    assert await store.get(str(bob.id), "yt:abcdefghijk", "provider_video", "notes") is None
    assert await store.list(str(bob.id)) == []
    assert await store.provider_seconds_today(str(bob.id)) == 0
    assert await store.purge_expired(str(bob.id), keep_days=1) == 0
    assert [r.source_key for r in await store.list(str(alice.id))] == ["yt:abcdefghijk"]
    # A saved row for bob under the same key is his own.
    await save(store, str(bob.id), segments=[(1.0, 2.0, "bob's")])
    alice_row = await store.get(str(alice.id), "yt:abcdefghijk", "provider_video", "notes")
    assert alice_row is not None and alice_row.segments[0][2] == "first"
    assert await store.get("not-a-uuid", "yt:abcdefghijk", "provider_video", "notes") is None


@pytest.mark.asyncio
async def test_the_least_recently_used_row_goes_past_the_cap(session_factory, monkeypatch):
    from services.tools.video import store as store_module

    user, _ = await make_user(session_factory, "lru@example.com")
    clock = Clock()
    store = TranscriptStore(session_factory, clock=clock)
    uid = str(user.id)
    monkeypatch.setattr(store_module, "MAX_ROWS_PER_USER", 3)
    monkeypatch.setattr(TranscriptStore._evict, "__defaults__", (3,))
    for i in range(3):
        clock.now += timedelta(minutes=1)
        await save(store, uid, key=f"url:{i}", kind="captions", method="publisher_captions", detail="verbatim", window=None)
    clock.now += timedelta(minutes=1)
    assert await store.get(uid, "url:0", "publisher_captions", "verbatim") is not None  # used: now newest
    clock.now += timedelta(minutes=1)
    await save(store, uid, key="url:3", kind="captions", method="publisher_captions", detail="verbatim", window=None)
    keys = sorted(r.source_key for r in await store.list(uid, 20))
    assert keys == ["url:0", "url:2", "url:3"]


@pytest.mark.asyncio
async def test_expiry_the_janitor_and_a_shortened_retention(session_factory):
    user, _ = await make_user(session_factory, "expiry@example.com")
    clock = Clock()
    store = TranscriptStore(session_factory, clock=clock)
    uid = str(user.id)
    await save(store, uid, key="yt:aaaaaaaaaaa")
    clock.now += timedelta(days=5)
    await save(store, uid, key="yt:bbbbbbbbbbb")
    clock.now += timedelta(days=10)  # the first is 15 days old, the second 10
    assert await store.get(uid, "yt:aaaaaaaaaaa", "provider_video", "notes") is None

    async def keep_days() -> int:
        return 7

    janitor = TranscriptJanitor(store, keep_days=keep_days)
    assert await janitor.sweep() == 1  # the owner now keeps 7 days
    assert await store.list(uid) == []
    assert janitor.loop.interval_seconds == 6 * 3600


@pytest.mark.asyncio
async def test_the_janitor_trims_every_user_to_the_cap(session_factory):
    user, _ = await make_user(session_factory, "trim@example.com")
    clock = Clock()
    store = TranscriptStore(session_factory, clock=clock)
    uid = str(user.id)
    for i in range(5):
        clock.now += timedelta(minutes=1)
        await save(store, uid, key=f"url:{i}", method="publisher_captions", detail="verbatim", window=None)
    assert await store.trim(2) == 3
    assert sorted(r.source_key for r in await store.list(uid, 20)) == ["url:3", "url:4"]


@pytest.mark.asyncio
async def test_billed_seconds_count_today_only(session_factory):
    user, _ = await make_user(session_factory, "billed@example.com")
    clock = Clock()
    store = TranscriptStore(session_factory, clock=clock)
    uid = str(user.id)
    clock.now = clock.now.replace(hour=23, minute=30)
    await save(store, uid, billed_seconds=600)
    assert await store.provider_seconds_today(uid) == 600
    clock.now += timedelta(hours=1)  # past midnight UTC
    await save(store, uid, window=(2700.0, 3600.0), billed_seconds=900)
    assert await store.provider_seconds_today(uid) == 900
    await save(store, uid, key="url:x", method="publisher_captions", detail="verbatim", window=None, billed_seconds=0)
    assert await store.provider_seconds_today(uid) == 900


@pytest.mark.asyncio
async def test_the_row_text_cap(session_factory, monkeypatch):
    from services.tools.video import store as store_module

    monkeypatch.setattr(store_module, "MAX_ROW_CHARS", 10)
    user, _ = await make_user(session_factory, "cap@example.com")
    store = TranscriptStore(session_factory)
    record = await save(store, str(user.id), segments=[(0.0, 5.0, "12345"), (5.0, 9.0, "67890"), (9.0, 12.0, "x")])
    assert [s[2] for s in record.segments] == ["12345", "67890"] and record.chars == 10
    assert record.covered == ((0.0, 9.0),)


@pytest.mark.asyncio
async def test_the_export_holds_the_rows_and_deleting_the_account_removes_them(client, session_factory):
    user, token = await make_user(session_factory, "export-video@example.com")
    await save(TranscriptStore(session_factory), str(user.id), title="Lecture 5")
    resp = await client.get("/api/auth/export", headers=auth_headers(token))
    assert resp.status_code == 200
    rows = json.loads(resp.text)["media_transcripts"]
    assert len(rows) == 1 and rows[0]["title"] == "Lecture 5"
    assert rows[0]["segments"][0] == [10.0, 20.0, "first"] and "billed" not in rows[0]

    # Deleting the account cascades in the database (no per-table delete).
    from sqlalchemy import delete

    from models.user import User

    async with session_factory() as session:
        await session.execute(delete(User).where(User.id == user.id))
        await session.commit()
    async with session_factory() as session:
        left = (await session.execute(select(MediaTranscript))).scalars().all()
    assert left == []


def test_the_revision_keeps_its_reserved_parent():
    script = ScriptDirectory.from_config(_config(Path("unused.db")))
    assert script.get_revision(REVISION).down_revision == "0023_permission_grants"


def test_upgrade_creates_the_table_and_downgrade_removes_only_it(tmp_path):
    db_path = tmp_path / "video.db"
    config = _config(db_path)
    command.upgrade(config, REVISION)
    engine, inspector = _inspect(db_path)
    try:
        assert "media_transcripts" in inspector.get_table_names()
        indexes = {
            i["name"]: (tuple(i["column_names"]), bool(i["unique"]))
            for i in inspector.get_indexes("media_transcripts")
        }
        assert indexes["uq_media_transcripts_user_source"] == (
            ("user_id", "source_key", "method", "detail"),
            True,
        )
        assert indexes["ix_media_transcripts_user_last_used"] == (("user_id", "last_used_at"), False)
        assert indexes["ix_media_transcripts_expires_at"] == (("expires_at",), False)
        assert indexes["ix_media_transcripts_status_claimed"] == (("status", "claimed_until"), False)
        (fk,) = inspector.get_foreign_keys("media_transcripts")
        assert fk["referred_table"] == "users" and fk["options"].get("ondelete") == "CASCADE"
    finally:
        engine.dispose()
    command.downgrade(config, "0023_permission_grants")
    engine, inspector = _inspect(db_path)
    try:
        tables = set(inspector.get_table_names())
        assert "media_transcripts" not in tables and "users" in tables
    finally:
        engine.dispose()
    command.upgrade(config, "head")


@pytest.mark.asyncio
async def test_an_unknown_user_id_is_refused_by_save():
    store = TranscriptStore(None)
    with pytest.raises(ValueError):
        await save(store, "not-a-uuid")
    assert await store.provider_seconds_today("not-a-uuid") == 0
    assert await store.purge_expired("not-a-uuid") == 0
