"""Tests for FileReputationToolkit (services/file_reputation/toolkit.py) and the upload path of
FileReputationService: they prove security.check_file takes exactly one of an upload's file_id
(the caller's own) or a sha256 and never says a file is safe; security.upload_to_virustotal is
refused before any card for a file VirusTotal knows, bytes that are gone, a personal document
nobody picked on the Security page, or a call that brings its own _upload; the card names the
file, its size and who VirusTotal shares it with; an approved upload fetches the bytes again
(Telegram, the mail connector through the executor and the byte sink, the in-memory holder),
hashes them again, and sends nothing when they differ, are gone after a restart, or were never
approved; and a finished scan is told once, an endless one stops after eight polls.

Why it exists: the upload is the one call that hands a person's file to a third party that
shares it with security companies. Every rule between "the model asked" and "the bytes left"
is here, and each one failing open would send a file nobody approved (decisions 2, review
SEC-F2).
"""

from __future__ import annotations

import pytest

from services.file_reputation.holder import ByteHolder
from services.file_reputation.service import UPLOAD_BYTES_UNAVAILABLE, UPLOAD_PERSONAL_DOCUMENT
from services.file_reputation.toolkit import (
    CHECK_BAD_SHA,
    CHECK_DOCUMENT_ID,
    CHECK_NOT_YOURS,
    CHECK_ONE_OF,
    UPLOAD_CARD_KEY,
    FileReputationToolkit,
)
from services.files.intake import InboundFile
from services.files.sandbox import InProcessSandbox
from services.files.store import UserFileStore
from services.tools.security_checks import SecurityToolkit
from tests.conftest import make_user
from tests.file_reputation.fakevt import (
    ANALYSIS_ID,
    T0,
    Clock,
    MonotonicClock,
    analysis_body,
    build_service,
    sha_of,
)
from tests.files import builders as b

EXE = b"MZ\x90\x00\x03 setup program"
GMAIL_HASH = "google_workspace__0123abcd.get_attachment_hash"


async def _upload_of(session_factory, user_id: str, name: str, data: bytes, media_type: str) -> str:
    """One of *user_id*'s own uploads (user_files), as the intake stores it; its file_id."""
    store = UserFileStore(session_factory, sandbox=InProcessSandbox())
    info = await store.ingest(user_id, data=data, name=name, declared_mime=media_type, source="web")
    return str(info.id)


async def _screened(service, user_id: str, name: str, data: bytes, source: str = "web", **extra):
    await service.screen(user_id, InboundFile(name, "application/octet-stream", data, source, **extra))
    await service.drain()


@pytest.mark.asyncio
async def test_check_file_takes_a_file_id_or_a_sha256_and_refuses_both_or_neither(session_factory):
    user, _ = await make_user(session_factory, "tk-args@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    pdf = b.make_pdf(["a lease"])
    file_id = await _upload_of(session_factory, uid, "lease.pdf", pdf, "application/pdf")

    assert await toolkit.execute("check_file", {}, uid) == {"ok": False, "error": CHECK_ONE_OF}
    assert (await toolkit.execute("check_file", {"file_id": " ", "sha256": ""}, uid))["error"] == CHECK_ONE_OF
    both = await toolkit.execute("check_file", {"file_id": file_id, "sha256": sha_of(pdf)}, uid)
    assert both == {"ok": False, "error": CHECK_ONE_OF}
    assert (await toolkit.execute("check_file", {"sha256": "abc"}, uid))["error"] == CHECK_BAD_SHA
    assert (await toolkit.execute("check_file", {"file_id": "tmp_9f3a"}, uid))["error"] == CHECK_DOCUMENT_ID
    assert parts.vt.requests == []

    by_id = await toolkit.execute("check_file", {"file_id": file_id}, uid)
    by_sha = await toolkit.execute("check_file", {"sha256": sha_of(pdf).upper()}, uid)
    assert by_id["ok"] is True and by_id["sha256"] == sha_of(pdf) and by_id["verdict"] == "unknown"
    assert by_sha["ok"] is True and by_sha["sha256"] == sha_of(pdf)
    rows = await service.list_checks(uid, 10)
    assert [(r["name"], r["source"]) for r in rows] == [("lease.pdf", "web")]


@pytest.mark.asyncio
async def test_check_file_of_another_users_file_id_reads_as_not_one_of_yours(session_factory):
    ann, _ = await make_user(session_factory, "tk-ann@example.com")
    bob, _ = await make_user(session_factory, "tk-bob@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    anns = await _upload_of(session_factory, str(ann.id), "private.pdf", b.make_pdf(["ann"]), "application/pdf")

    for file_id in (anns, "4e1f0c6a-0000-4000-8000-000000000000", "not-an-id", 12):
        answer = await toolkit.execute("check_file", {"file_id": file_id}, str(bob.id))
        assert answer == {"ok": False, "error": CHECK_NOT_YOURS}
    assert parts.vt.requests == [] and await service.list_checks(str(bob.id), 10) == []


@pytest.mark.asyncio
async def test_check_file_never_says_safe_and_offers_upload_only_for_unknown_files_with_a_source(
    session_factory,
):
    user, _ = await make_user(session_factory, "tk-safe@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    clean, held_exe, pdf = sha_of(b"clean"), EXE, b.make_pdf(["my letter"])
    parts.vt.add_file(clean, harmless=9, undetected=62)
    await _screened(service, uid, "setup.exe", held_exe)
    await _screened(service, uid, "letter.pdf", pdf)

    no_detections = await toolkit.execute("check_file", {"sha256": clean}, uid)
    unknown_bare = await toolkit.execute("check_file", {"sha256": sha_of(b"never seen")}, uid)
    unknown_held = await toolkit.execute("check_file", {"sha256": sha_of(held_exe)}, uid)
    unknown_personal = await toolkit.execute("check_file", {"sha256": sha_of(pdf)}, uid)

    assert no_detections["verdict"] == "no_detections" and no_detections["engines"] == 71
    assert no_detections["summary"].endswith("That is not a guarantee it is safe.")
    for answer in (no_detections, unknown_bare, unknown_held, unknown_personal):
        assert "safe" not in answer["verdict"]
        assert "is safe" not in answer["summary"].replace("not a guarantee it is safe", "")
    assert unknown_held["verdict"] == "unknown" and unknown_held["can_upload"] is True
    assert "never suggest it for personal documents" in unknown_held["upload_hint"]
    for answer in (no_detections, unknown_bare, unknown_personal):
        assert answer["can_upload"] is False and "upload_hint" not in answer


@pytest.mark.asyncio
async def test_upload_is_refused_before_a_card_when_virustotal_already_knows_the_file(session_factory):
    user, _ = await make_user(session_factory, "tk-known@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    parts.vt.add_file(sha_of(EXE), malicious=30, undetected=40)
    await _screened(service, uid, "setup.exe", EXE)

    refusal = await toolkit.precheck("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)
    parked = await parts.runtime.park_card(
        user_id=uid, tool_name="security.upload_to_virustotal", arguments={"sha256": sha_of(EXE)}, origin="t"
    )

    assert refusal is not None and refusal["ok"] is False and refusal["rule"] == "already_known"
    assert getattr(parked, "rule", None) == "already_known" and parts.runtime.cards == []
    assert await toolkit.precheck("check_file", {"sha256": sha_of(EXE)}, uid) is None


@pytest.mark.asyncio
async def test_upload_is_refused_before_a_card_when_the_bytes_are_gone(session_factory):
    user, _ = await make_user(session_factory, "tk-gone@example.com")
    service, _parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE)
    assert await toolkit.precheck("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid) is None

    service.holder.drop(uid, sha_of(EXE))
    refusal = await toolkit.precheck("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)

    assert refusal == {"ok": False, "rule": "bytes_unavailable", "error": UPLOAD_BYTES_UNAVAILABLE}
    unknown = await toolkit.precheck("upload_to_virustotal", {"sha256": sha_of(b"no row")}, uid)
    assert unknown is not None and unknown["rule"] == "unknown_file"


@pytest.mark.asyncio
async def test_upload_is_refused_before_a_card_for_a_personal_document_type(session_factory):
    user, _ = await make_user(session_factory, "tk-personal@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    pdf = b.make_pdf(["2026 tax return"])
    await service.screen(uid, InboundFile("tax-return.pdf", "application/pdf", pdf, "web"))
    await service.drain()

    refusal = await toolkit.precheck("upload_to_virustotal", {"sha256": sha_of(pdf)}, uid)
    assert refusal == {"ok": False, "rule": "personal_document", "error": UPLOAD_PERSONAL_DOCUMENT}

    # The owner picks the very file on the Security page: the card is parked after all.
    row = await service.store.check_for(uid, sha_of(pdf))
    assert row is not None
    outcome = await service.request_upload(uid, row.id, pdf)
    assert outcome.status == "parked" and outcome.action_id == parts.runtime.cards[0].action_id
    card = parts.runtime.cards[0]
    assert card.origin == f"file_check:{row.id}" and card.ttl_minutes == 60
    assert card.arguments["sha256"] == sha_of(pdf) and card.arguments[UPLOAD_CARD_KEY]["check_id"] == row.id
    assert parts.vt.uploads == []


@pytest.mark.asyncio
async def test_a_call_that_brings_its_own_upload_facts_is_refused_before_a_card(session_factory):
    user, _ = await make_user(session_factory, "tk-forged@example.com")
    service, _parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE)
    forged = {
        "sha256": sha_of(EXE),
        UPLOAD_CARD_KEY: {"sha256": sha_of(EXE), "name": "harmless.txt", "size_bytes": 1, "check_id": "x"},
    }

    refusal = await toolkit.precheck("upload_to_virustotal", forged, uid)
    bound = await toolkit.bind("upload_to_virustotal", forged, uid)
    extra = await toolkit.precheck("upload_to_virustotal", {"sha256": sha_of(EXE), "note": "x"}, uid)
    bad = await toolkit.precheck("upload_to_virustotal", {"sha256": "../../etc"}, uid)

    assert refusal is not None and refusal["rule"] == "invalid_arguments"
    assert bound["refused"] is True and bound["rule"] == "invalid_arguments"
    assert extra is not None and extra["rule"] == "invalid_arguments"
    assert bad is not None and bad["rule"] == "invalid_arguments"


@pytest.mark.asyncio
async def test_the_card_names_the_file_its_size_and_that_virustotal_shares_uploads(session_factory):
    user, _ = await make_user(session_factory, "tk-card@example.com")
    mono = MonotonicClock()
    holder = ByteHolder(clock=mono)
    service, _parts = build_service(session_factory, holder=holder)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    data = EXE + b"\x00" * (2_400_000 - len(EXE))
    look_alike = "\u0441etup.exe"  # a Cyrillic first letter
    await _screened(service, uid, look_alike, data)
    digest = sha_of(data)

    bound = await toolkit.bind("upload_to_virustotal", {"sha256": digest}, uid)
    sentence = toolkit.describe("upload_to_virustotal", bound, uid)

    facts = bound[UPLOAD_CARD_KEY]
    assert bound["sha256"] == digest and set(facts) == {"sha256", "name", "size_bytes", "source", "check_id"}
    assert facts["name"] == "\\u0441etup\u2024exe" and facts["name"].isascii() is False
    assert sentence == (
        f'Send "\\u0441etup\u2024exe" (2.3 MB, SHA-256 {digest[:8]}\u2026{digest[-4:]}) to VirusTotal '
        "to be scanned. VirusTotal shares files it receives with security companies, and its "
        "paying users can download them: never send private documents."
    )
    # The held bytes are kept for the card's 60 minutes, past the screen's 30.
    mono.now += 45 * 60
    assert holder.get(uid, digest) == data
    assert toolkit.describe("upload_to_virustotal", {"sha256": digest}, uid) is None
    assert toolkit.describe("check_file", bound, uid) is None


@pytest.mark.asyncio
async def test_an_approved_upload_refetches_from_telegram_and_checks_the_hash_before_sending(
    session_factory,
):
    user, _ = await make_user(session_factory, "tk-telegram@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    await _screened(service, uid, "Payroll Q3.exe", EXE, "telegram", source_ref="BQAC-tg-file")
    parts.telegram.files["BQAC-tg-file"] = EXE
    bound = await toolkit.bind("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)

    result = await toolkit.execute("upload_to_virustotal", bound, uid, approved=True)

    assert result == {
        "ok": True,
        "status": "analysing",
        "sha256": sha_of(EXE),
        "message": "Sent to VirusTotal. The scan usually takes a few minutes; Crawler will tell you the result.",
    }
    assert parts.telegram.calls == [("BQAC-tg-file", 20 * 1024 * 1024)]
    assert len(parts.vt.uploads) == 1
    body = parts.vt.uploads[0]
    assert EXE in body and b'filename="file"' in body and b"Payroll" not in body
    upload_request = [r for r in parts.vt.requests if r.method == "POST"][0]
    assert upload_request.url.path == "/api/v3/files"
    row = await service.store.check_for(uid, sha_of(EXE))
    assert row is not None and row.state == "analysing" and row.analysis_id == ANALYSIS_ID
    uploaded = parts.audit.events("file_reputation_uploaded")
    assert uploaded[0]["arguments"] == {"sha256": sha_of(EXE), "size_bytes": len(EXE), "source": "telegram"}
    assert await service.store.cached_verdict(sha_of(EXE)) is None


@pytest.mark.asyncio
async def test_an_approved_upload_refetches_a_mail_attachment_through_the_executor_and_the_byte_sink(
    session_factory,
):
    user, _ = await make_user(session_factory, "tk-mail@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    digest = parts.executor.add("msg-77", "part-4", EXE, "setup.exe", "application/x-msdownload")
    await service.check_mail_attachment(uid, hash_tool=GMAIL_HASH, message_id="msg-77", attachment_id="part-4")
    bound = await toolkit.bind("upload_to_virustotal", {"sha256": digest}, uid)

    result = await toolkit.execute("upload_to_virustotal", bound, uid, approved=True)

    assert result["ok"] is True and result["status"] == "analysing"
    assert parts.executor.calls == [
        (GMAIL_HASH, {"message_id": "msg-77", "part_id": "part-4"}, uid),
        (GMAIL_HASH, {"message_id": "msg-77", "part_id": "part-4"}, uid),
    ]
    assert len(parts.vt.uploads) == 1 and EXE in parts.vt.uploads[0]


@pytest.mark.asyncio
async def test_an_approved_upload_whose_bytes_hash_differently_is_refused_and_audited(session_factory):
    user, _ = await make_user(session_factory, "tk-changed@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE, "telegram", source_ref="tg-changed")
    parts.telegram.files["tg-changed"] = EXE + b" but changed"
    bound = await toolkit.bind("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)

    result = await toolkit.execute("upload_to_virustotal", bound, uid, approved=True)

    assert result["ok"] is False and result["rule"] == "file_changed"
    assert "nothing was sent" in result["error"]
    assert parts.vt.uploads == []
    refused = parts.audit.events("file_reputation_upload_refused")
    assert [row["arguments"] for row in refused] == [
        {"sha256": sha_of(EXE), "rule": "file_changed", "source": "telegram"}
    ]
    assert "setup" not in str(refused)


@pytest.mark.asyncio
async def test_after_a_restart_an_approved_web_upload_card_refuses_instead_of_sending_anything(
    session_factory,
):
    user, _ = await make_user(session_factory, "tk-restart@example.com")
    service, parts = build_service(session_factory)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE, "web")
    bound = await FileReputationToolkit(service).bind("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)
    assert service.holder.get(uid, sha_of(EXE)) == EXE

    restarted, after = build_service(session_factory, vt=parts.vt)
    result = await FileReputationToolkit(restarted).execute("upload_to_virustotal", bound, uid, approved=True)

    assert result == {"ok": False, "rule": "bytes_unavailable", "error": UPLOAD_BYTES_UNAVAILABLE}
    assert parts.vt.uploads == []
    assert [row["arguments"]["rule"] for row in after.audit.events("file_reputation_upload_refused")] == [
        "bytes_unavailable"
    ]


@pytest.mark.asyncio
async def test_an_unapproved_upload_never_reaches_virustotal(session_factory):
    user, _ = await make_user(session_factory, "tk-unapproved@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    family = SecurityToolkit()
    family.use_file_reputation(toolkit)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE)
    bound = await toolkit.bind("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)

    direct = await toolkit.execute("upload_to_virustotal", bound, uid)
    through_family = await family.execute("upload_to_virustotal", bound, uid, approved=False)
    # Approved but without the facts only the card's bind writes, or for another check.
    bare = await toolkit.execute("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid, approved=True)
    forged = {**bound, UPLOAD_CARD_KEY: {**bound[UPLOAD_CARD_KEY], "check_id": "guessed"}}
    wrong_check = await toolkit.execute("upload_to_virustotal", forged, uid, approved=True)

    for answer in (direct, through_family):
        assert answer["ok"] is False and answer["requires_approval"] is True
    assert bare["ok"] is False and bare["rule"] == "invalid_arguments"
    assert wrong_check["ok"] is False and wrong_check["rule"] == "invalid_arguments"
    assert parts.vt.uploads == [] and [r for r in parts.vt.requests if r.method == "POST"] == []


@pytest.mark.asyncio
async def test_a_finished_scan_becomes_a_verdict_and_the_user_is_told_once(session_factory):
    user, _ = await make_user(session_factory, "tk-finished@example.com")
    clock = Clock(T0)
    service, parts = build_service(session_factory, clock=clock)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE)
    bound = await toolkit.bind("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)
    assert (await toolkit.execute("upload_to_virustotal", bound, uid, approved=True))["ok"] is True
    parts.vt.analyses[ANALYSIS_ID] = analysis_body("completed", sha256=sha_of(EXE), harmless=7, undetected=64)

    await service.sweep()  # the first poll is not due yet (90 s)
    assert not any("/analyses/" in r.url.path for r in parts.vt.requests)
    clock.advance(91)
    await service.sweep()
    await service.sweep()

    polls = [r for r in parts.vt.requests if "/analyses/" in r.url.path]
    assert len(polls) == 1
    row = await service.store.check_for(uid, sha_of(EXE))
    assert row is not None and row.state == "checked" and row.verdict == "no_detections"
    assert parts.outbox.to(user.id) == [
        'File check: VirusTotal finished scanning "setup\u2024exe": none of 71 security vendors '
        "flag it. That is not a guarantee it is safe."
    ]
    checked = [r for r in parts.audit.events("file_reputation_checked") if r["arguments"]["origin"] == "analysis"]
    assert checked[-1]["arguments"]["verdict"] == "no_detections"
    assert (await service.store.cached_verdict(sha_of(EXE))) is not None


@pytest.mark.asyncio
async def test_a_scan_that_never_finishes_stops_after_eight_polls_with_one_message(session_factory):
    user, _ = await make_user(session_factory, "tk-timeout@example.com")
    clock = Clock(T0)
    service, parts = build_service(session_factory, clock=clock)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE)
    bound = await toolkit.bind("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)
    await toolkit.execute("upload_to_virustotal", bound, uid, approved=True)
    parts.vt.analyses[ANALYSIS_ID] = analysis_body("queued")

    clock.advance(91)
    for _ in range(12):
        await service.sweep()
        clock.advance(121)

    polls = [r for r in parts.vt.requests if "/analyses/" in r.url.path]
    assert len(polls) == 8
    row = await service.store.check_for(uid, sha_of(EXE))
    assert row is not None and row.state == "not_checked" and row.reason == "analysis_timeout"
    assert parts.outbox.to(user.id) == [
        'File check: VirusTotal had not finished scanning "setup\u2024exe" after 15 minutes. '
        "Check it again later in Security \u2192 File checks."
    ]


@pytest.mark.asyncio
async def test_an_upload_virustotal_may_have_taken_says_so_and_is_never_retried(session_factory):
    user, _ = await make_user(session_factory, "tk-maybe@example.com")
    service, parts = build_service(session_factory)
    toolkit = FileReputationToolkit(service)
    uid = str(user.id)
    await _screened(service, uid, "setup.exe", EXE)
    bound = await toolkit.bind("upload_to_virustotal", {"sha256": sha_of(EXE)}, uid)
    parts.vt.fail_with = 502

    result = await toolkit.execute("upload_to_virustotal", bound, uid, approved=True)

    assert result["ok"] is False and result["maybe_received"] is True
    assert result["error"] == (
        "VirusTotal did not confirm it received the file (VirusTotal could not be reached). "
        "It may have been received."
    )
    posts = [r for r in parts.vt.requests if r.method == "POST"]
    assert len(posts) == 1  # an approval is single-use: no automatic retry
    row = await service.store.check_for(uid, sha_of(EXE))
    assert row is not None and row.state == "checked"
    refused = parts.audit.events("file_reputation_upload_refused")
    assert [r["arguments"]["rule"] for r in refused] == ["service_error"]
