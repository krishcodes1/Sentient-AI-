"""Tests for services/file_reputation/store.py on the test database: the install-wide VirusTotal
verdict cache and its lifetimes, retention of the three tables, and the protection of a check's
source reference. They prove a flagged answer is reused for 7 days, a clean one for 24 hours and
an unknown one for an hour; only VirusTotal's four answers are ever cached; a cached answer reads
back with the same counts and says it was cached; expired rows are purged; and a Telegram file id
or mail message id is never stored readable.

Why it exists: the cache decides when Crawler asks VirusTotal again, and a wrong lifetime either
wastes the owner's 500 daily lookups or keeps a stale "no detections" answer too long. The
source reference lets anyone with the bot token or connector credentials pull the file.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from core.config import settings
from models.file_reputation import FileReputationCheck, FileReputationVerdict
from services.file_reputation import store as store_module
from services.file_reputation.store import (
    CHECK_RETENTION,
    FileReputationStore,
    check_expires_at,
    decrypt_source_ref,
    encrypt_source_ref,
    source_key,
    verdict_expires_at,
    verdict_ttl,
)
from services.file_reputation.virustotal import VtFileReport
from tests.conftest import make_user
from tests.file_reputation.fakevt import T0, Clock, sha_of

SHA = sha_of(b"MZ a cached program")


def vt_report(malicious: int = 0, suspicious: int = 0, harmless: int = 0, undetected: int = 0,
              **facts) -> VtFileReport:
    return VtFileReport(
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        engines=malicious + suspicious + harmless + undetected,
        threat_label=facts.get("threat_label"),
        file_type=facts.get("file_type"),
        first_seen_at=facts.get("first_seen_at"),
        analysed_at=facts.get("analysed_at"),
    )


async def count(session_factory, model) -> int:
    async with session_factory() as session:
        return int(await session.scalar(select(func.count()).select_from(model)))


def test_cache_lifetimes_are_seven_days_flagged_one_day_clean_and_one_hour_unknown():
    assert verdict_ttl("malicious") == timedelta(days=7)
    assert verdict_ttl("suspicious") == timedelta(days=7)
    assert verdict_ttl("no_detections") == timedelta(hours=24)
    assert verdict_ttl("unknown") == timedelta(hours=1)
    assert verdict_expires_at("unknown", T0) == T0 + timedelta(hours=1)
    # A naive time from SQLite is read as UTC.
    assert verdict_expires_at("malicious", T0.replace(tzinfo=None)) == T0 + timedelta(days=7)
    assert check_expires_at(T0) == T0 + CHECK_RETENTION == T0 + timedelta(days=30)


def test_failures_and_unchecked_answers_are_never_cached():
    for verdict in ("not_checked", "pending", "safe", "", "MALICIOUS"):
        with pytest.raises(ValueError):
            verdict_ttl(verdict)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "verdict", "lifetime"),
    [
        (vt_report(malicious=41, undetected=31), "malicious", timedelta(days=7)),
        (vt_report(malicious=1, undetected=60), "suspicious", timedelta(days=7)),
        (vt_report(harmless=3, undetected=60), "no_detections", timedelta(hours=24)),
        (None, "unknown", timedelta(hours=1)),
    ],
)
async def test_each_cached_answer_is_reused_exactly_for_its_lifetime(
    session_factory, answer, verdict, lifetime
):
    clock = Clock()
    store = FileReputationStore(session_factory, clock=clock)

    cached = await store.cache_verdict(SHA, answer)

    assert (cached.verdict, cached.expires_at) == (verdict, T0 + lifetime)
    hit = await store.cached_verdict(SHA, now=T0 + lifetime - timedelta(seconds=1))
    assert hit is not None and hit.verdict == verdict
    assert await store.cached_verdict(SHA, now=T0 + lifetime) is None


@pytest.mark.asyncio
async def test_a_cached_answer_reads_back_with_the_same_counts_and_says_it_was_cached(
    session_factory,
):
    store = FileReputationStore(session_factory, clock=Clock())
    first_seen = datetime(2024, 3, 1, tzinfo=timezone.utc)
    analysed = datetime(2026, 10, 10, 8, 30, tzinfo=timezone.utc)
    answer = vt_report(
        malicious=41, suspicious=2, harmless=1, undetected=28, threat_label="trojan.emotet",
        file_type="Win32 EXE", first_seen_at=first_seen, analysed_at=analysed,
    )

    await store.cache_verdict(SHA, answer)
    hit = await store.cached_verdict(SHA.upper())  # not a stored-form fingerprint
    assert hit is None
    hit = await store.cached_verdict(SHA)

    assert hit is not None
    assert hit.report == answer
    assert (hit.origin, hit.fetched_at) == ("lookup", T0)
    verdict = hit.file_verdict(check_id="row-1", can_upload=True)
    assert verdict.cached is True and verdict.check_id == "row-1"
    assert (verdict.verdict, verdict.flagged_by, verdict.engines) == ("malicious", 41, 72)
    assert verdict.threat_label == "trojan.emotet" and verdict.file_type == "Win32 EXE"
    assert (verdict.first_seen, verdict.last_scanned) == (first_seen.date(), analysed.date())
    # Only an unknown file can be offered for upload.
    assert verdict.can_upload is False


@pytest.mark.asyncio
async def test_an_unknown_file_is_cached_without_counts_and_can_be_offered_for_upload(
    session_factory,
):
    store = FileReputationStore(session_factory, clock=Clock())

    await store.cache_verdict(SHA, None)
    hit = await store.cached_verdict(SHA)

    assert hit is not None and hit.report is None
    verdict = hit.file_verdict(can_upload=True)
    assert (verdict.verdict, verdict.engines, verdict.can_upload) == ("unknown", 0, True)


@pytest.mark.asyncio
async def test_caching_again_replaces_the_older_answer_and_forgetting_drops_it(session_factory):
    clock = Clock()
    store = FileReputationStore(session_factory, clock=clock)

    await store.cache_verdict(SHA, None)
    clock.advance(600)
    replaced = await store.cache_verdict(
        SHA, vt_report(malicious=5, undetected=60), origin="analysis"
    )

    assert replaced.expires_at == clock.now + timedelta(days=7)
    assert await count(session_factory, FileReputationVerdict) == 1
    hit = await store.cached_verdict(SHA)
    assert hit is not None and (hit.verdict, hit.origin) == ("malicious", "analysis")

    await store.forget_verdict(SHA)
    assert await store.cached_verdict(SHA) is None
    with pytest.raises(ValueError):
        await store.cache_verdict("not-a-fingerprint", None)
    with pytest.raises(ValueError):
        await store.cache_verdict(SHA, None, origin="guess")


@pytest.mark.asyncio
async def test_a_stored_answer_that_disagrees_with_the_verdict_mapping_is_asked_again(
    session_factory,
):
    store = FileReputationStore(session_factory, clock=Clock())
    async with session_factory() as session:
        session.add(
            FileReputationVerdict(
                sha256=SHA, verdict="no_detections", malicious=9, suspicious=0, harmless=0,
                undetected=50, engines=59, origin="lookup", fetched_at=T0,
                expires_at=T0 + timedelta(hours=24),
            )
        )
        session.add(
            FileReputationVerdict(
                sha256=sha_of(b"other"), verdict="safe", malicious=0, suspicious=0, harmless=0,
                undetected=0, engines=0, origin="lookup", fetched_at=T0,
                expires_at=T0 + timedelta(hours=24),
            )
        )
        await session.commit()

    assert await store.cached_verdict(SHA) is None
    assert await store.cached_verdict(sha_of(b"other")) is None


@pytest.mark.asyncio
async def test_rows_expire_thirty_days_after_their_last_sighting_and_the_cache_after_its_ttl(
    session_factory,
):
    user, _ = await make_user(session_factory, "store-purge@example.com")
    clock = Clock()
    store = FileReputationStore(session_factory, clock=clock)
    old, fresh = sha_of(b"old"), sha_of(b"fresh")
    async with session_factory() as session:
        for sha, seen in ((old, T0 - timedelta(days=31)), (fresh, T0 - timedelta(days=29))):
            session.add(
                FileReputationCheck(
                    id=uuid.uuid4(), user_id=user.id, sha256=sha, name="file", source="hash",
                    state="checked", priority="explicit", polls=0, created_at=seen,
                    updated_at=seen, expires_at=check_expires_at(seen),
                )
            )
        await session.commit()
    clock.advance(-3 * 3600)
    await store.cache_verdict(old, None)  # unknown: expired an hour later
    await store.cache_verdict(fresh, vt_report(malicious=4, undetected=60))
    clock.advance(3 * 3600)

    purged = await store.purge()

    assert (purged.checks, purged.verdicts, purged.calls) == (1, 1, 0)
    assert purged.total == 2
    async with session_factory() as session:
        left = (await session.execute(select(FileReputationCheck.sha256))).scalars().all()
    assert left == [fresh]
    assert await store.cached_verdict(fresh) is not None


def test_source_references_are_encrypted_at_rest_and_message_ids_are_only_hmacs(monkeypatch):
    file_id = "BQACAgQAAxkBAAIBc2X-telegram-file-id"
    blob = encrypt_source_ref({"telegram_file_id": file_id})

    assert isinstance(blob, bytes) and file_id.encode() not in blob
    assert decrypt_source_ref(blob) == {"telegram_file_id": file_id}
    mail = {"tool": "google_workspace.get_attachment_hash", "message_id": "18c2f",
            "attachment_id": "0.1"}
    assert decrypt_source_ref(encrypt_source_ref(mail)) == mail
    # Unreadable or damaged rows read as "no source", so an upload refuses.
    assert decrypt_source_ref(None) is None
    assert decrypt_source_ref(b"") is None
    assert decrypt_source_ref(b"\x00" * 40) is None
    for bad in ({}, {"k": 1}, {"": "v"}, {"k": ""}, ["k", "v"], {"k": "v" * 2000}):
        with pytest.raises(ValueError):
            encrypt_source_ref(bad)  # type: ignore[arg-type]

    key = source_key("google_workspace", "18c2f9a0b1")
    assert len(key) == 64 and all(ch in "0123456789abcdef" for ch in key)
    assert "18c2f9a0b1" not in key
    assert key == source_key("google_workspace", "18c2f9a0b1")
    assert key != source_key("microsoft", "18c2f9a0b1")
    assert key != source_key("google_workspace", "18c2f9a0b2")
    with pytest.raises(ValueError):
        source_key("", "18c2f9a0b1")
    # Keyed by the install's ENCRYPTION_KEY: another install cannot recompute it.
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", settings.ENCRYPTION_KEY[::-1])
    assert source_key("google_workspace", "18c2f9a0b1") != key
    assert store_module._SOURCE_KEY_DOMAIN == b"sentientai.file_reputation.source.v1:"
