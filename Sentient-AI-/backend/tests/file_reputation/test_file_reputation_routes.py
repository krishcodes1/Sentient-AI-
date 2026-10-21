"""Tests for the Security -> File checks routes (api/routes/security_files.py) on the real app,
with ``app.state.file_reputation`` built on FakeVirusTotal: they prove each person lists only
their own checks with the service's state in the right words for owners and others, a
browser-computed fingerprint is looked up (bad ones are a 422, and nothing is asked while the
service is off or has no key), an upload request parks exactly one card (the same card on a
repeat), refuses a known file, a different body and a body over 20 MB before reading it whole,
is limited per person, another person's check is a 404, forgetting drops the held bytes, a
denied card puts the row back, and no response ever carries a key, a source reference or an
analysis id.

Why it exists: these routes are how a person checks a file before opening it and asks to share
one with VirusTotal. A route that leaked another person's history or an encrypted reference,
or parked a card for a file VirusTotal already knows, would break S10 6.2 and decisions 2.
"""

from __future__ import annotations

from typing import Any, AsyncIterator

import pytest
import pytest_asyncio

from services.file_reputation.service import NO_KEY_SENTENCE, NOT_SET_UP_SENTENCE, OFF_SENTENCE
from services.file_reputation.toolkit import FileReputationToolkit
from services.files.intake import InboundFile
from tests.conftest import auth_headers, make_user
from tests.file_reputation.fakevt import ANALYSIS_ID, KEY, build_service, sha_of
from tests.file_reputation.helpers import check_rows, make_owner

EXE = b"MZ\x90\x00\x03 the program"
MB = 1024 * 1024


@pytest_asyncio.fixture
async def wired(session_factory) -> AsyncIterator[tuple[Any, Any]]:
    """The app's file service, built on the fakes, restored afterwards."""
    from main import app

    service, parts = build_service(session_factory)
    saved = dict(app.state._state)
    app.state.file_reputation = service
    try:
        yield service, parts
    finally:
        await service.drain()
        app.state._state.clear()
        app.state._state.update(saved)


async def _check(client, token: str, data: bytes, name: str = "file.bin") -> Any:
    return await client.post(
        "/api/security/files/check",
        json={"sha256": sha_of(data), "name": name, "size_bytes": len(data), "media_type": "application/octet-stream"},
        headers=auth_headers(token),
    )


@pytest.mark.asyncio
async def test_listing_shows_only_the_callers_own_checks_and_the_service_state(client, session_factory, wired):
    service, parts = wired
    owner, owner_token = await make_owner(session_factory)
    member, member_token = await make_user(session_factory, "routes-member@example.com")
    assert (await _check(client, owner_token, b"owner's file", "mine.pdf")).status_code == 200
    assert (await _check(client, member_token, b"member's file", "theirs.pdf")).status_code == 200

    listed = await client.get("/api/security/files?limit=10", headers=auth_headers(member_token))
    assert listed.status_code == 200
    body = listed.json()
    assert [c["name"] for c in body["checks"]] == ["theirs.pdf"]
    assert body["service"] == {
        "state": "on",
        "reason": None,
        "lookups_last_24h": 2,
        "lookups_per_day": 500,
        "your_lookups_last_24h": 1,
        "your_lookups_per_day": 100,
        "upload_max_bytes": 20 * MB,
    }

    # Without a key the history stays listed, in each person's own words.
    parts.settings.key = None
    as_owner = (await client.get("/api/security/files", headers=auth_headers(owner_token))).json()
    as_member = (await client.get("/api/security/files", headers=auth_headers(member_token))).json()
    assert as_owner["service"]["state"] == "blocked" and as_owner["service"]["reason"] == NO_KEY_SENTENCE
    assert as_member["service"]["reason"] == NOT_SET_UP_SENTENCE
    assert [c["name"] for c in as_owner["checks"]] == ["mine.pdf"]
    assert (await client.get("/api/security/files?limit=0", headers=auth_headers(owner_token))).status_code == 422


@pytest.mark.asyncio
async def test_checking_a_browser_computed_fingerprint_creates_a_row_and_answers_the_verdict(
    client, session_factory, wired
):
    service, parts = wired
    user, token = await make_user(session_factory, "routes-check@example.com")
    parts.vt.add_file(sha_of(EXE), malicious=41, undetected=31, label="trojan.emotet")

    answer = await client.post(
        "/api/security/files/check",
        json={"sha256": sha_of(EXE).upper(), "name": "invoice.pdf.exe", "size_bytes": len(EXE)},
        headers=auth_headers(token),
    )

    assert answer.status_code == 200
    row = answer.json()
    assert row["sha256"] == sha_of(EXE) and row["source"] == "page" and row["state"] == "checked"
    assert (row["verdict"], row["flagged_by"], row["engines"], row["threat_label"]) == (
        "malicious",
        41,
        72,
        "trojan.emotet",
    )
    assert row["name"] == "invoice.pdf.exe" and row["can_upload"] is False
    # Only the fingerprint went to VirusTotal; the page shows the verdict, so no alert is sent.
    assert [r.url.path for r in parts.vt.requests] == [f"/api/v3/files/{sha_of(EXE)}"]
    assert parts.outbox.sent == []


@pytest.mark.asyncio
async def test_a_fingerprint_that_is_not_64_hex_is_a_422(client, session_factory, wired):
    _service, parts = wired
    _user, token = await make_user(session_factory, "routes-badhash@example.com")

    for value in ("xyz", "g" * 64, "a" * 63, "a" * 65):
        answer = await client.post("/api/security/files/check", json={"sha256": value}, headers=auth_headers(token))
        assert answer.status_code == 422
        assert answer.json()["code"] == "bad_hash"
    assert parts.vt.requests == []


@pytest.mark.asyncio
async def test_checks_are_refused_with_409_while_the_service_is_off_or_has_no_key(client, session_factory, wired):
    _service, parts = wired
    _owner, owner_token = await make_owner(session_factory)
    _member, member_token = await make_user(session_factory, "routes-off@example.com")

    parts.settings.key = None
    no_key = await _check(client, owner_token, EXE)
    member = await _check(client, member_token, EXE)
    parts.settings.key = KEY
    parts.settings.switched_on = False
    off = await _check(client, owner_token, EXE)

    assert [r.status_code for r in (no_key, member, off)] == [409, 409, 409]
    assert {r.json()["code"] for r in (no_key, member, off)} == {"service_off"}
    assert no_key.json()["detail"] == NO_KEY_SENTENCE
    assert member.json()["detail"] == NOT_SET_UP_SENTENCE
    assert off.json()["detail"] == OFF_SENTENCE
    assert parts.vt.requests == [] and await check_rows(session_factory) == []


@pytest.mark.asyncio
async def test_an_upload_body_that_hashes_differently_is_a_422(client, session_factory, wired):
    _service, parts = wired
    _user, token = await make_user(session_factory, "routes-changed@example.com")
    check_id = (await _check(client, token, EXE, "setup.exe")).json()["id"]

    answer = await client.post(
        f"/api/security/files/{check_id}/upload", content=EXE + b"!", headers=auth_headers(token)
    )

    assert answer.status_code == 422 and answer.json()["code"] == "file_changed"
    assert parts.runtime.cards == [] and parts.vt.uploads == []


@pytest.mark.asyncio
async def test_requesting_an_upload_parks_one_card_and_a_second_request_returns_the_same_card(
    client, session_factory, wired
):
    service, parts = wired
    user, token = await make_user(session_factory, "routes-park@example.com")
    pdf = b"%PDF-1.7 a private letter"
    check_id = (await _check(client, token, pdf, "letter.pdf")).json()["id"]
    listed = (await client.get("/api/security/files", headers=auth_headers(token))).json()["checks"][0]
    # The server holds no copy of a file checked from the page: the page must send it.
    assert listed["can_upload"] is True and listed["upload_needs_file"] is True
    without = await client.post(f"/api/security/files/{check_id}/upload", headers=auth_headers(token))
    assert without.status_code == 409 and without.json()["code"] == "needs_file"

    first = await client.post(
        f"/api/security/files/{check_id}/upload",
        content=pdf,
        headers={**auth_headers(token), "Content-Type": "application/pdf"},
    )
    again = await client.post(f"/api/security/files/{check_id}/upload", headers=auth_headers(token))

    assert first.status_code == 202 and again.status_code == 200
    assert first.json()["action_id"] == again.json()["action_id"] == parts.runtime.cards[0].action_id
    assert first.json()["state"] == "upload_pending" and first.json()["expires_at"]
    assert len(parts.runtime.cards) == 1 and parts.vt.uploads == []
    card = parts.runtime.cards[0]
    assert card.tool_name == "security.upload_to_virustotal" and card.origin == f"file_check:{check_id}"
    row = (await client.get("/api/security/files", headers=auth_headers(token))).json()["checks"][0]
    assert row["state"] == "upload_pending" and row["action_id"] == card.action_id
    assert service.holder.has_explicit(str(user.id), sha_of(pdf))


@pytest.mark.asyncio
async def test_an_upload_request_for_a_file_virustotal_knows_is_a_409(client, session_factory, wired):
    _service, parts = wired
    _user, token = await make_user(session_factory, "routes-known@example.com")
    parts.vt.add_file(sha_of(EXE), malicious=3, undetected=60)
    check_id = (await _check(client, token, EXE)).json()["id"]

    answer = await client.post(f"/api/security/files/{check_id}/upload", content=EXE, headers=auth_headers(token))

    assert answer.status_code == 409 and answer.json()["code"] == "already_known"
    assert parts.runtime.cards == []


@pytest.mark.asyncio
async def test_an_upload_body_over_20_mb_is_a_413_before_it_is_read_whole(client, session_factory, wired):
    _service, parts = wired
    _user, token = await make_user(session_factory, "routes-big@example.com")
    check_id = (await _check(client, token, EXE)).json()["id"]
    pulled: list[int] = []

    async def chunks() -> AsyncIterator[bytes]:
        for n in range(30):
            pulled.append(n)
            yield b"\x00" * MB

    declared = await client.post(
        f"/api/security/files/{check_id}/upload",
        content=chunks(),
        headers={**auth_headers(token), "Content-Length": str(30 * MB)},
    )
    assert declared.status_code == 413 and declared.json()["code"] == "too_large"
    assert len(pulled) <= 1  # refused from its Content-Length

    pulled.clear()
    streamed = await client.post(
        f"/api/security/files/{check_id}/upload", content=chunks(), headers=auth_headers(token)
    )
    assert streamed.status_code == 413 and streamed.json()["code"] == "too_large"
    assert len(pulled) <= 22  # stopped while streaming, not read to the end
    assert parts.runtime.cards == []


@pytest.mark.asyncio
async def test_another_users_check_id_is_a_404(client, session_factory, wired):
    _service, parts = wired
    _ann, ann_token = await make_user(session_factory, "routes-ann@example.com")
    _bob, bob_token = await make_user(session_factory, "routes-bob@example.com")
    anns = (await _check(client, ann_token, EXE)).json()["id"]

    for check_id in (anns, "not-an-id", "4e1f0c6a-0000-4000-8000-000000000000"):
        upload = await client.post(f"/api/security/files/{check_id}/upload", content=EXE, headers=auth_headers(bob_token))
        forget = await client.delete(f"/api/security/files/{check_id}", headers=auth_headers(bob_token))
        assert upload.status_code == 404 and upload.json()["code"] == "not_found"
        assert forget.status_code == 404
    assert len((await client.get("/api/security/files", headers=auth_headers(ann_token))).json()["checks"]) == 1
    assert parts.runtime.cards == []


@pytest.mark.asyncio
async def test_forgetting_a_check_deletes_the_row_and_drops_held_bytes(client, session_factory, wired):
    service, _parts = wired
    user, token = await make_user(session_factory, "routes-forget@example.com")
    uid = str(user.id)
    await service.screen(uid, InboundFile("setup.exe", "application/x-msdownload", EXE, "web"))
    await service.drain()
    assert service.holder.get(uid, sha_of(EXE)) == EXE
    check_id = (await client.get("/api/security/files", headers=auth_headers(token))).json()["checks"][0]["id"]

    forgotten = await client.delete(f"/api/security/files/{check_id}", headers=auth_headers(token))

    assert forgotten.status_code == 204 and forgotten.content == b""
    assert service.holder.get(uid, sha_of(EXE)) is None
    assert (await client.get("/api/security/files", headers=auth_headers(token))).json()["checks"] == []
    assert (await client.delete(f"/api/security/files/{check_id}", headers=auth_headers(token))).status_code == 404


@pytest.mark.asyncio
async def test_no_response_ever_carries_a_key_a_source_reference_or_an_analysis_id(client, session_factory, wired):
    service, parts = wired
    user, token = await make_user(session_factory, "routes-leak@example.com")
    uid = str(user.id)
    file_id = "BQACAgQ-telegram-file-id-never-shown"
    await service.screen(uid, InboundFile("setup.exe", "application/x-msdownload", EXE, "telegram", source_ref=file_id))
    await service.drain()
    parts.telegram.files[file_id] = EXE
    responses = [await client.get("/api/security/files", headers=auth_headers(token))]
    check_id = responses[0].json()["checks"][0]["id"]
    responses.append(await client.post(f"/api/security/files/{check_id}/upload", headers=auth_headers(token)))
    card = parts.runtime.cards[0]
    sent = await FileReputationToolkit(service).execute(
        "upload_to_virustotal", card.arguments, uid, approved=True
    )
    assert sent["ok"] is True
    responses.append(await client.get("/api/security/files", headers=auth_headers(token)))
    responses.append(await _check(client, token, EXE))
    rows = await check_rows(session_factory, uid)
    assert rows[0].analysis_id == ANALYSIS_ID and rows[0].source_ref

    for response in responses:
        text = response.text
        assert response.status_code in (200, 202)
        for secret in (KEY, file_id, ANALYSIS_ID, "source_ref", "source_key", "analysis_id"):
            assert secret not in text
    assert responses[2].json()["checks"][0]["state"] == "analysing"


@pytest.mark.asyncio
async def test_a_denied_or_expired_card_puts_the_row_back_to_checked(client, session_factory, wired):
    _service, parts = wired
    _user, token = await make_user(session_factory, "routes-denied@example.com")
    check_id = (await _check(client, token, EXE)).json()["id"]
    parked = await client.post(f"/api/security/files/{check_id}/upload", content=EXE, headers=auth_headers(token))
    assert parked.status_code == 202

    parts.runtime.decided.add(parked.json()["action_id"])  # denied (or expired)
    row = (await client.get("/api/security/files", headers=auth_headers(token))).json()["checks"][0]

    assert row["state"] == "checked" and row["action_id"] is None and row["can_upload"] is True
    again = await client.post(f"/api/security/files/{check_id}/upload", content=EXE, headers=auth_headers(token))
    assert again.status_code == 202 and again.json()["action_id"] != parked.json()["action_id"]


@pytest.mark.asyncio
async def test_upload_requests_are_limited_to_five_an_hour_per_person(client, session_factory, wired):
    _service, parts = wired
    _ann, ann_token = await make_user(session_factory, "routes-limit@example.com")
    _bob, bob_token = await make_user(session_factory, "routes-limit-bob@example.com")
    check_id = (await _check(client, ann_token, EXE)).json()["id"]

    answers = [
        await client.post(f"/api/security/files/{check_id}/upload", content=EXE, headers=auth_headers(ann_token))
        for _ in range(6)
    ]

    assert [a.status_code for a in answers[:5]] == [202, 200, 200, 200, 200]
    assert answers[5].status_code == 429 and answers[5].json()["code"] == "rate_limited"
    assert int(answers[5].headers["Retry-After"]) > 0
    # Another person has their own five.
    bob_check = (await _check(client, bob_token, EXE + b"b")).json()["id"]
    bob = await client.post(f"/api/security/files/{bob_check}/upload", content=EXE + b"b", headers=auth_headers(bob_token))
    assert bob.status_code == 202 and len(parts.runtime.cards) == 2


@pytest.mark.asyncio
async def test_an_upload_request_without_the_runtime_wired_is_a_503(client, session_factory):
    from main import app

    service, _parts = build_service(session_factory, with_runtime=False)
    saved = dict(app.state._state)
    app.state.file_reputation = service
    try:
        user, token = await make_user(session_factory, "routes-unwired@example.com")
        check_id = (await _check(client, token, EXE)).json()["id"]
        answer = await client.post(f"/api/security/files/{check_id}/upload", content=EXE, headers=auth_headers(token))
        assert answer.status_code == 503 and answer.json()["code"] == "not_wired"
        # No card holds the picked file, so it is not kept in memory for one.
        assert service.holder.get(str(user.id), sha_of(EXE)) is None
    finally:
        await service.drain()
        app.state._state.clear()
        app.state._state.update(saved)
