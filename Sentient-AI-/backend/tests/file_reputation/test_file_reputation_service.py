"""Tests for FileReputationService's lookups (services/file_reputation/service.py): they prove
nothing is hashed, stored or sent without a key and the switch, a cached answer is reused for
its lifetime and failures never are, a rejected key pauses every lookup and tells the owner at
most once a day, concurrent lookups of one file share one request while each person keeps their
own row, the queue survives a restart, mail attachments are fingerprinted through the executor
with their source encrypted and their message id kept only as an HMAC, rows and cached answers
expire on time, and audit rows hold fingerprints, counts and codes only.

Why it exists: the service is the one place the owner's VirusTotal key and quota are spent and
the one place a person's file history is written. A lookup that leaked a name or a key, ran
with the switch off, cached a failure or alerted twice would break decisions 2 and 6 for every
caller at once (the intake, the tools, the Security tab, S2 and S3).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import httpx
import pytest

from services.file_reputation import alerts
from services.file_reputation.store import decrypt_source_ref, message_source_key
from services.files.intake import InboundFile
from tests.conftest import make_user
from tests.file_reputation.fakevt import (
    KEY,
    OTHER_KEY,
    T0,
    Clock,
    FakeSettings,
    FakeVirusTotal,
    build_service,
    sha_of,
)
from tests.file_reputation.helpers import call_rows, check_rows, make_owner, verdict_rows

EXE = b"MZ\x90\x00 a small program"
GMAIL_HASH = "google_workspace__0123abcd.get_attachment_hash"


@pytest.mark.asyncio
async def test_without_a_key_nothing_is_sent_and_the_result_says_not_checked(session_factory):
    user, _ = await make_user(session_factory, "nokey@example.com")
    service, parts = build_service(session_factory, settings=FakeSettings(key=None))
    uid = str(user.id)

    by_hash = await service.check_hash(uid, sha_of(EXE))
    by_bytes = await service.check_bytes(uid, EXE, name="tool.exe", media_type=None, source="web")
    await service.screen(uid, InboundFile(name="tool.exe", media_type="", data=EXE, source="web"))
    await service.drain()

    for verdict in (by_hash, by_bytes):
        assert verdict.verdict == "not_checked" and verdict.reason == "no_key"
        assert verdict.summary().startswith("Not checked: no VirusTotal key is set")
        assert "safe" not in verdict.summary().lower()
    assert parts.vt.requests == []
    assert await check_rows(session_factory) == [] and await call_rows(session_factory) == []
    assert len(service.holder) == 0
    assert (await service.status(uid, is_owner=True))["state"] == "blocked"
    assert await service.remote_configured() is False


@pytest.mark.asyncio
async def test_with_the_switch_off_nothing_is_sent_even_with_a_key(session_factory):
    user, _ = await make_user(session_factory, "switchoff@example.com")
    service, parts = build_service(session_factory, settings=FakeSettings(switched_on=False))
    parts.vt.add_file(sha_of(EXE), malicious=40, undetected=30)

    verdict = await service.check_hash(str(user.id), sha_of(EXE))
    await service.screen(str(user.id), InboundFile(name="a.exe", media_type="", data=EXE, source="web"))
    await service.drain()

    assert verdict.verdict == "not_checked" and verdict.reason == "switched_off"
    assert parts.vt.requests == [] and parts.settings.key_reads == 0
    assert await check_rows(session_factory) == []
    assert (await service.status(str(user.id), is_owner=True))["state"] == "off"


@pytest.mark.asyncio
async def test_an_unreadable_switch_counts_as_off(session_factory):
    user, _ = await make_user(session_factory, "unreadable@example.com")
    settings = FakeSettings()
    settings.report_fails = True
    service, parts = build_service(session_factory, settings=settings)

    verdict = await service.check_hash(str(user.id), sha_of(EXE))

    assert verdict.verdict == "not_checked" and verdict.reason == "switched_off"
    assert parts.vt.requests == [] and await service.remote_configured() is False


@pytest.mark.asyncio
async def test_a_cached_verdict_is_answered_without_asking_virustotal_again(session_factory):
    ann, _ = await make_user(session_factory, "ann@example.com")
    bob, _ = await make_user(session_factory, "bob@example.com")
    service, parts = build_service(session_factory)
    digest = sha_of(EXE)
    parts.vt.add_file(digest, malicious=41, undetected=31, label="trojan.emotet")

    first = await service.check_hash(str(ann.id), digest, alert="caller")
    again = await service.check_hash(str(ann.id), digest, alert="caller")
    other = await service.check_hash(str(bob.id), digest, alert="caller")

    assert first.verdict == again.verdict == other.verdict == "malicious"
    assert (first.flagged_by, first.engines, first.threat_label) == (41, 72, "trojan.emotet")
    assert first.cached is False and again.cached is True and other.cached is True
    assert len(parts.vt.requests) == 1
    # Only the lookup actually sent is audited; cache hits write nothing.
    assert len(parts.audit.events("file_reputation_checked")) == 1
    assert len(await call_rows(session_factory)) == 1


@pytest.mark.asyncio
async def test_cache_lifetimes_are_seven_days_flagged_one_day_clean_and_one_hour_unknown(
    session_factory,
):
    user, _ = await make_user(session_factory, "ttl@example.com")
    clock = Clock(T0)
    service, parts = build_service(session_factory, clock=clock)
    flagged, clean, unknown = sha_of(b"bad"), sha_of(b"clean"), sha_of(b"new")
    parts.vt.add_file(flagged, malicious=5, undetected=60)
    parts.vt.add_file(clean, harmless=10, undetected=60)
    uid = str(user.id)

    for digest in (flagged, clean, unknown):
        await service.check_hash(uid, digest, alert="caller")
    assert len(parts.vt.requests) == 3
    lifetimes = {flagged: 7 * 24 * 3600, clean: 24 * 3600, unknown: 3600}
    for digest, seconds in lifetimes.items():
        just_before = T0 + timedelta(seconds=seconds - 1)
        just_after = T0 + timedelta(seconds=seconds + 1)
        assert await service.store.cached_verdict(digest, now=just_before) is not None
        assert await service.store.cached_verdict(digest, now=just_after) is None

    # An hour on, the unknown file is asked about again; the other two are not.
    clock.advance(3601)
    for digest in (flagged, clean, unknown):
        await service.check_hash(uid, digest, alert="caller")
    asked = [r.url.path.rsplit("/", 1)[-1] for r in parts.vt.requests[3:]]
    assert asked == [unknown]


@pytest.mark.asyncio
async def test_failures_are_never_cached_and_read_as_not_checked(session_factory):
    user, _ = await make_user(session_factory, "failures@example.com")
    service, parts = build_service(session_factory)
    digest = sha_of(EXE)
    uid = str(user.id)

    parts.vt.fail_with = 500
    server_error = await service.check_hash(uid, digest, alert="caller")
    parts.vt.fail_with = httpx.ConnectError("down")
    unreachable = await service.check_hash(uid, digest, alert="caller")
    parts.vt.fail_with = None
    parts.vt.add_file(digest, harmless=3, undetected=60)
    answered = await service.check_hash(uid, digest, alert="caller")

    for verdict in (server_error, unreachable):
        assert verdict.verdict == "not_checked" and verdict.reason == "service_error"
        assert verdict.summary() == "Not checked: VirusTotal could not be reached."
    assert answered.verdict == "no_detections" and answered.cached is False
    assert len(parts.vt.requests) == 3
    assert [row.verdict for row in await verdict_rows(session_factory)] == ["no_detections"]
    reasons = [row["arguments"].get("reason") for row in parts.audit.events("file_reputation_checked")]
    assert reasons == ["service_error", "service_error", None]


@pytest.mark.asyncio
async def test_a_rejected_key_cools_down_and_alerts_the_owner_once_a_day(session_factory):
    owner, _ = await make_owner(session_factory)
    member, _ = await make_user(session_factory, "member@example.com")
    clock = Clock(T0)
    service, parts = build_service(session_factory, settings=FakeSettings(key=OTHER_KEY), clock=clock)
    uid = str(member.id)

    first = await service.check_hash(uid, sha_of(b"one"), alert="caller")
    await service.drain()
    assert first.verdict == "not_checked" and first.reason == "key_rejected"
    assert len(parts.vt.requests) == 1
    assert parts.outbox.to(owner.id) == [alerts.KEY_REJECTED_ALERT]
    assert parts.outbox.to(member.id) == []
    rejected = parts.audit.events("file_reputation_key_rejected")
    assert len(rejected) == 1 and rejected[0]["user_id"] == str(owner.id)
    assert rejected[0]["arguments"] == {"status_code": 401, "delivered": True}

    # Within the 600 s pause: no request at all, the same answer.
    clock.advance(599)
    paused = await service.check_hash(uid, sha_of(b"two"), alert="caller")
    assert paused.reason == "key_rejected" and len(parts.vt.requests) == 1

    # After the pause VirusTotal is asked again; it still refuses, but the owner was told today.
    clock.advance(2)
    await service.check_hash(uid, sha_of(b"three"), alert="caller")
    await service.drain()
    assert len(parts.vt.requests) == 2
    assert len(parts.outbox.to(owner.id)) == 1 and len(parts.audit.events("file_reputation_key_rejected")) == 1

    # A day later the next refusal tells the owner again.
    clock.advance(24 * 3600)
    await service.check_hash(uid, sha_of(b"four"), alert="caller")
    await service.drain()
    assert len(parts.outbox.to(owner.id)) == 2 and len(parts.audit.events("file_reputation_key_rejected")) == 2

    # A new key lifts the pause at once.
    parts.settings.key = KEY
    clock.advance(1)
    works = await service.check_hash(uid, sha_of(b"five"), alert="caller")
    assert works.verdict == "unknown"
    assert all(KEY not in str(row) and OTHER_KEY not in str(row) for row in parts.audit.rows)


@pytest.mark.asyncio
async def test_two_people_with_the_same_file_share_one_request_but_see_only_their_own_rows(
    session_factory,
):
    ann, _ = await make_user(session_factory, "share-ann@example.com")
    bob, _ = await make_user(session_factory, "share-bob@example.com")
    gate = asyncio.Event()
    vt = FakeVirusTotal()
    digest = sha_of(EXE)
    vt.add_file(digest, malicious=3, undetected=60)
    answer_of = vt._handle

    async def slow(request: httpx.Request) -> httpx.Response:
        await gate.wait()
        return answer_of(request)

    vt.transport = httpx.MockTransport(slow)
    service, parts = build_service(session_factory, vt=vt)

    async def release() -> None:
        await asyncio.sleep(0.2)
        gate.set()

    ann_verdict, bob_verdict, _ = await asyncio.gather(
        service.check_hash(str(ann.id), digest, name="from-ann.exe", wait_s=5.0, alert="caller"),
        service.check_hash(str(bob.id), digest, name="from-bob.exe", wait_s=5.0, alert="caller"),
        release(),
    )

    assert ann_verdict.verdict == bob_verdict.verdict == "malicious"
    assert len(parts.vt.requests) == 1 and len(await call_rows(session_factory)) == 1
    ann_rows = await service.list_checks(str(ann.id), 50)
    bob_rows = await service.list_checks(str(bob.id), 50)
    assert [row["name"] for row in ann_rows] == ["from-ann.exe"]
    assert [row["name"] for row in bob_rows] == ["from-bob.exe"]
    assert ann_rows[0]["id"] != bob_rows[0]["id"]
    assert await service.get_check(str(bob.id), ann_rows[0]["id"]) is None


@pytest.mark.asyncio
async def test_queued_lookups_are_finished_by_the_sweep_after_a_restart(session_factory):
    user, _ = await make_user(session_factory, "queue@example.com")
    clock = Clock(T0)
    settings = FakeSettings(settings={"lookups_per_minute": 1})
    vt = FakeVirusTotal()
    first_file, queued_file = sha_of(b"first"), sha_of(b"queued")
    vt.add_file(queued_file, malicious=9, undetected=60)
    service, parts = build_service(session_factory, vt=vt, settings=settings, clock=clock)
    uid = str(user.id)

    await service.check_hash(uid, first_file, alert="caller")
    waiting = await service.check_hash(uid, queued_file, name="later.exe", alert="caller")
    assert waiting.verdict == "pending" and waiting.reason == "minute_limit"
    assert "limit of 1 lookups a minute" in waiting.summary()
    assert len(vt.requests) == 1

    # A new process (the holder and in-flight lookups are gone) a minute later.
    clock.advance(61)
    restarted, after = build_service(session_factory, vt=vt, settings=settings, clock=clock)
    assert await restarted.sweep() >= 1
    await restarted.drain()

    assert len(vt.requests) == 2
    row = await restarted.store.check_for(uid, queued_file)
    assert row is not None and row.state == "checked" and row.verdict == "malicious"
    # A verdict that arrived later from the queue is told by the service, once.
    told = after.outbox.to(user.id)
    assert len(told) == 1 and "later․exe" in told[0]
    assert await restarted.sweep() == 0 and len(after.outbox.sent) == 1


@pytest.mark.asyncio
async def test_an_empty_file_is_never_looked_up(session_factory):
    user, _ = await make_user(session_factory, "empty@example.com")
    service, parts = build_service(session_factory)

    verdict = await service.check_bytes(str(user.id), b"", name="empty.exe", media_type=None, source="web")
    await service.screen(str(user.id), InboundFile(name="empty.exe", media_type="", data=b"", source="web"))
    await service.drain()

    assert verdict.verdict == "not_checked" and verdict.reason == "empty"
    assert parts.vt.requests == [] and await check_rows(session_factory) == []


@pytest.mark.asyncio
async def test_mail_attachment_checks_run_the_hash_action_through_the_executor_and_keep_the_source_encrypted(
    session_factory,
):
    user, _ = await make_user(session_factory, "mail@example.com")
    service, parts = build_service(session_factory)
    message_id = "18c2f0a9d3e4b5c6-message"
    digest = parts.executor.add(message_id, "part-2", EXE, "invoice.exe", "application/x-msdownload")
    pdf = parts.executor.add(message_id, "part-3", b"%PDF-1.7 statement", "statement.pdf", "application/pdf")
    uid = str(user.id)

    risky = await service.check_mail_attachment(
        uid, hash_tool=GMAIL_HASH, message_id=message_id, attachment_id="part-2"
    )
    personal = await service.check_mail_attachment(
        uid, hash_tool=GMAIL_HASH, message_id=message_id, attachment_id="part-3"
    )

    assert risky.verdict == personal.verdict == "unknown"
    assert parts.executor.calls == [
        (GMAIL_HASH, {"message_id": message_id, "part_id": "part-2"}, uid),
        (GMAIL_HASH, {"message_id": message_id, "part_id": "part-3"}, uid),
    ]
    rows = {row.sha256: row for row in await check_rows(session_factory, uid)}
    assert rows[digest].source == rows[pdf].source == "gmail"
    assert rows[digest].source_key == message_source_key("google_workspace", message_id)
    assert message_id not in rows[digest].source_key
    assert message_id.encode() not in (rows[digest].source_ref or b"")
    assert decrypt_source_ref(rows[digest].source_ref) == {
        "tool": GMAIL_HASH,
        "message_id": message_id,
        "attachment_id": "part-2",
    }
    # A personal document keeps no re-fetch reference (review SEC-F2).
    assert rows[pdf].source_ref is None
    # A tool name that is not a mail connector's hash action is never run.
    odd = await service.check_mail_attachment(
        uid, hash_tool="files.read", message_id=message_id, attachment_id="part-2"
    )
    assert odd.verdict == "not_checked" and len(parts.executor.calls) == 2


@pytest.mark.asyncio
async def test_a_mail_check_answered_at_once_is_left_to_the_caller_but_a_late_flagged_answer_is_alerted(
    session_factory,
):
    user, _ = await make_user(session_factory, "late@example.com")
    clock = Clock(T0)
    settings = FakeSettings(settings={"lookups_per_minute": 1})
    service, parts = build_service(session_factory, settings=settings, clock=clock)
    uid = str(user.id)
    now_bad = parts.executor.add("m-1", "p-1", EXE, "now.exe", "application/x-msdownload")
    late_bad = parts.executor.add("m-2", "p-1", EXE + b"2", "late.exe", "application/x-msdownload")
    parts.vt.add_file(now_bad, malicious=30, undetected=40)
    parts.vt.add_file(late_bad, malicious=12, undetected=40)

    at_once = await service.check_mail_attachment(
        uid, hash_tool=GMAIL_HASH, message_id="m-1", attachment_id="p-1"
    )
    queued = await service.check_mail_attachment(
        uid, hash_tool=GMAIL_HASH, message_id="m-2", attachment_id="p-1"
    )
    await service.drain()
    assert at_once.verdict == "malicious" and queued.verdict == "pending"
    assert parts.outbox.sent == [] and parts.audit.events("file_reputation_alerted") == []

    clock.advance(61)
    await service.sweep()
    await service.drain()
    told = parts.outbox.to(user.id)
    assert len(told) == 1 and "late․exe" in told[0] and "12 of 52" in told[0]
    alerted = parts.audit.events("file_reputation_alerted")
    assert [row["arguments"]["sha256"] for row in alerted] == [late_bad]


@pytest.mark.asyncio
async def test_an_oversized_attachment_reads_as_not_checked_too_large(session_factory):
    user, _ = await make_user(session_factory, "big@example.com")
    service, parts = build_service(session_factory)
    parts.executor.too_large.add(("m-big", "p-1"))

    verdict = await service.check_mail_attachment(
        str(user.id), hash_tool=GMAIL_HASH, message_id="m-big", attachment_id="p-1"
    )

    assert verdict.verdict == "not_checked" and verdict.reason == "too_large"
    assert verdict.summary() == "Not checked: it is larger than 25 MB, too large to fingerprint."
    assert parts.vt.requests == []


@pytest.mark.asyncio
async def test_rows_expire_thirty_days_after_their_last_sighting_and_the_cache_after_its_ttl(
    session_factory,
):
    user, _ = await make_user(session_factory, "expire@example.com")
    clock = Clock(T0)
    service, parts = build_service(session_factory, clock=clock)
    digest = sha_of(EXE)
    parts.vt.add_file(digest, malicious=4, undetected=60)
    uid = str(user.id)

    await service.check_hash(uid, digest, alert="caller")
    clock.advance(10 * 24 * 3600)  # seen again ten days later: thirty more days from now
    await service.check_hash(uid, digest, alert="caller")
    assert [row.verdict for row in await verdict_rows(session_factory)] == ["malicious"]

    # Retention runs with the switch off too.
    parts.settings.switched_on = False
    clock.advance(29 * 24 * 3600)
    await service.sweep()
    assert len(await check_rows(session_factory, uid)) == 1
    assert await verdict_rows(session_factory) == []  # 7 days for a flagged answer

    clock.advance(2 * 24 * 3600)
    service._last_purge = None  # the hourly purge, now
    await service.sweep()
    assert await check_rows(session_factory, uid) == []
    assert await call_rows(session_factory) == []  # 48 h of request log


@pytest.mark.asyncio
async def test_audit_rows_hold_fingerprints_counts_and_codes_never_names_or_keys(session_factory):
    user, _ = await make_user(session_factory, "audit@example.com")
    service, parts = build_service(session_factory)
    uid = str(user.id)
    name = "Tax-Return-2026-Jane-Doe.exe"
    message_id = "mail-id-that-must-never-be-logged"
    digest = sha_of(EXE)
    parts.vt.add_file(digest, malicious=20, undetected=50)
    parts.executor.add(message_id, "p-1", EXE + b"x", "attached-secret.exe", "application/x-msdownload")

    await service.screen(uid, InboundFile(name=name, media_type="", data=EXE, source="web"))
    await service.drain()
    await service.check_mail_attachment(uid, hash_tool=GMAIL_HASH, message_id=message_id, attachment_id="p-1")
    parts.vt.fail_with = 503
    await service.check_hash(uid, sha_of(b"other"), name="other-private.exe", alert="caller")

    events = {row["event"] for row in parts.audit.rows}
    assert {"file_reputation_checked", "file_reputation_alerted"} <= events
    allowed = {"sha256", "verdict", "flagged_by", "engines", "source", "priority", "origin", "reason", "delivered"}
    for row in parts.audit.rows:
        text = str(row)
        for secret in (name, "Tax-Return", message_id, "attached-secret", "other-private", KEY):
            assert secret not in text
        assert set(row["arguments"]) <= allowed
        assert row["user_id"] == uid


@pytest.mark.asyncio
async def test_source_references_are_encrypted_at_rest_and_message_ids_are_only_hmacs(
    session_factory,
):
    user, _ = await make_user(session_factory, "encrypted@example.com")
    service, parts = build_service(session_factory)
    uid = str(user.id)
    file_id = "BQACAgQAAxkBAAIBZ2Unique-Telegram-File-Id"

    await service.screen(
        uid,
        InboundFile(name="setup.exe", media_type="application/x-msdownload", data=EXE, source="telegram", source_ref=file_id),
    )
    await service.drain()
    message_id = "<CAJ+unique-outlook-message-id@mail.example>"
    parts.executor.add(message_id, "AAMkAD-attachment", EXE + b"o", "tool.exe", "application/octet-stream")
    await service.check_mail_attachment(
        uid, hash_tool="microsoft.get_attachment_hash", message_id=message_id, attachment_id="AAMkAD-attachment"
    )

    rows = {row.source: row for row in await check_rows(session_factory, uid)}
    telegram, outlook = rows["telegram"], rows["outlook"]
    assert file_id.encode() not in telegram.source_ref
    assert decrypt_source_ref(telegram.source_ref) == {"telegram_file_id": file_id}
    assert telegram.source_key is None
    assert message_id.encode() not in outlook.source_ref
    assert len(outlook.source_key) == 64 and int(outlook.source_key, 16) >= 0
    assert outlook.source_key == message_source_key("microsoft", message_id)
    assert outlook.source_key != message_source_key("google_workspace", message_id)
    # The Security tab's rows never carry either.
    for row in await service.list_checks(uid, 50):
        assert "source_ref" not in row and "source_key" not in row and "analysis_id" not in row
    assert uuid.UUID(str(telegram.id))
