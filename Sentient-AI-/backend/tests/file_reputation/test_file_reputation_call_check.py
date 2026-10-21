"""Tests for FileReputationCallCheck (services/file_reputation/call_check.py): they prove a
forward of an email whose attachment VirusTotal flags gets a high note (malicious) or a warn note
(suspicious) worded for what each mail service really forwards, a knowledge-base save of a
flagged upload gets a note, every other call is allowed without touching the database, a
database error or a stall allows the call and adds nothing, and the check never escalates or
refuses and is inert as a backstop, alone and inside the production pipeline.

Why it exists: the check sits last in the call-check pipeline, on calls that already have a
card, and may only ever add a note (S10 4.9, scaffold D2, A3). A check that refused, escalated,
or failed closed on a database error would change what every forward and save does; one that
read the database for every call would cost every turn.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from services.file_reputation.call_check import NOTE_KIND, FileReputationCallCheck
from services.files.sandbox import InProcessSandbox
from services.files.store import UserFileStore
from services.security.call_checks import (
    ALLOW,
    CallFacts,
    Escalate,
    Note,
    Refuse,
    standard_pipeline,
)
from tests.conftest import make_user
from tests.file_reputation.fakevt import build_service, sha_of
from tests.files import builders as b

EXE = b"MZ\x90\x00 attached program"
GMAIL_HASH = "google_workspace__0123abcd.get_attachment_hash"
OUTLOOK_HASH = "microsoft.get_attachment_hash"


def _call(user_id: str, canonical: str, arguments: dict[str, Any], *, stage: str = "turn") -> CallFacts:
    family, action = canonical.split(".", 1)
    return CallFacts(
        stage=stage,  # type: ignore[arg-type]
        user_id=user_id,
        tool_name=f"{family}__0123abcd.{action}" if family != "knowledge" else canonical,
        canonical=canonical,
        arguments=arguments,
        will_card=True,
    )


class CountingSessions:
    """A session factory that counts the sessions opened."""

    def __init__(self, factory: Any) -> None:
        self.factory = factory
        self.opened = 0

    def __call__(self) -> Any:
        self.opened += 1
        return self.factory()


async def _flag_mail(service, parts, uid: str, message_id: str, *, malicious: int, suspicious: int = 0) -> None:
    data = EXE + message_id.encode()
    digest = parts.executor.add(message_id, "p-1", data, "invoice.exe", "application/x-msdownload")
    parts.vt.add_file(digest, malicious=malicious, suspicious=suspicious, undetected=60)
    for hash_tool in (GMAIL_HASH, OUTLOOK_HASH):
        await service.check_mail_attachment(uid, hash_tool=hash_tool, message_id=message_id, attachment_id="p-1")


@pytest.mark.asyncio
async def test_forwarding_an_email_with_a_flagged_attachment_gets_a_high_note(session_factory):
    user, _ = await make_user(session_factory, "cc-forward@example.com")
    other, _ = await make_user(session_factory, "cc-other@example.com")
    service, parts = build_service(session_factory)
    uid = str(user.id)
    await _flag_mail(service, parts, uid, "m-bad", malicious=41)
    check = FileReputationCallCheck(session_factory)

    outlook = await check.check(_call(uid, "microsoft.forward", {"message_id": " m-bad ", "to": ["x@example.com"]}))

    assert isinstance(outlook, Note) and len(outlook.notes) == 1
    note = outlook.notes[0]
    assert (note.kind, note.severity) == (NOTE_KIND, "high")
    assert note.text == (
        "This email has an attachment that 41 of 101 security vendors on VirusTotal flag as "
        "malicious. Forwarding it passes the file on."
    )
    # The row the Gmail check wrote last is the one the Gmail forward finds.
    await service.check_mail_attachment(uid, hash_tool=GMAIL_HASH, message_id="m-bad", attachment_id="p-1")
    gmail = await check.check(_call(uid, "google_workspace.forward", {"message_id": "m-bad", "to": "x@example.com"}))
    assert isinstance(gmail, Note)
    assert gmail.notes[0].text.endswith(
        "Gmail forwards only its text, but that text may be part of the same attack."
    )
    # A suspicious attachment is a warn note; another person's flagged mail is nobody else's.
    await _flag_mail(service, parts, uid, "m-iffy", malicious=1, suspicious=1)
    iffy = await check.check(_call(uid, "microsoft.forward", {"message_id": "m-iffy"}))
    assert isinstance(iffy, Note) and iffy.notes[0].severity == "warn"
    assert "2 of 62 security vendors on VirusTotal flag." in iffy.notes[0].text
    assert await check.check(_call(str(other.id), "microsoft.forward", {"message_id": "m-bad"})) == ALLOW
    assert await check.check(_call(uid, "microsoft.forward", {"message_id": "m-clean"})) == ALLOW
    for found in (outlook, gmail, iffy):
        assert "m-bad" not in found.notes[0].text and "invoice" not in found.notes[0].text


@pytest.mark.asyncio
async def test_saving_a_flagged_upload_to_the_knowledge_base_gets_a_note(session_factory):
    user, _ = await make_user(session_factory, "cc-save@example.com")
    service, parts = build_service(session_factory)
    uid = str(user.id)
    store = UserFileStore(session_factory, sandbox=InProcessSandbox())
    bad = b.make_pdf(["bad"])
    clean = b.make_pdf(["clean"])
    bad_id = str((await store.ingest(uid, data=bad, name="a.pdf", declared_mime="application/pdf", source="web")).id)
    clean_id = str((await store.ingest(uid, data=clean, name="b.pdf", declared_mime="application/pdf", source="web")).id)
    parts.vt.add_file(sha_of(bad), malicious=0, suspicious=2, undetected=68)
    await service.check_hash(uid, sha_of(bad), alert="caller")
    await service.check_hash(uid, sha_of(clean), alert="caller")
    check = FileReputationCallCheck(session_factory)

    one = await check.check(_call(uid, "knowledge.add", {"file_ids": [clean_id, bad_id], "collection": "c"}))
    none = await check.check(_call(uid, "knowledge.add", {"file_ids": [clean_id]}))

    assert isinstance(one, Note)
    assert (one.notes[0].kind, one.notes[0].severity) == (NOTE_KIND, "warn")
    assert one.notes[0].text == "A file being saved is flagged by 2 of 70 security vendors on VirusTotal."
    assert none == ALLOW


@pytest.mark.asyncio
async def test_calls_that_touch_no_flagged_file_are_allowed_without_a_database_read(session_factory):
    user, _ = await make_user(session_factory, "cc-cheap@example.com")
    sessions = CountingSessions(session_factory)
    check = FileReputationCallCheck(sessions)
    uid = str(user.id)

    calls = [
        _call(uid, "google_workspace.send_email", {"to": "x@example.com", "body": "hi"}),
        _call(uid, "microsoft.reply", {"message_id": "m-1", "comment": "ok"}),
        _call(uid, "knowledge.add", {"url": "https://example.com"}),
        _call(uid, "knowledge.add", {"file_ids": []}),
        _call(uid, "google_workspace.forward", {"to": "x@example.com"}),
        _call(uid, "google_workspace.forward", {"message_id": "  "}),
    ]
    for call in calls:
        assert check.applies_to(call) is False
        assert await check.check(call) == ALLOW
    assert sessions.opened == 0

    assert check.applies_to(_call(uid, "google_workspace.forward", {"message_id": "m-1"})) is True
    assert await check.check(_call(uid, "google_workspace.forward", {"message_id": "m-1"})) == ALLOW
    assert sessions.opened == 1


@pytest.mark.asyncio
async def test_a_database_error_allows_the_call_and_adds_nothing(session_factory):
    user, _ = await make_user(session_factory, "cc-error@example.com")
    uid = str(user.id)

    def broken() -> Any:
        raise RuntimeError("database down")

    failing = FileReputationCallCheck(broken)
    assert await failing.check(_call(uid, "microsoft.forward", {"message_id": "m-1"})) == ALLOW
    assert await failing.check(_call(uid, "knowledge.add", {"file_ids": ["4e1f0c6a-0000-4000-8000-000000000000"]})) == ALLOW

    class Stalled:
        async def flagged_by_source_key(self, *args: Any) -> Any:
            await asyncio.sleep(30)

    stalled = FileReputationCallCheck(session_factory, store=Stalled(), query_timeout_s=0.05)  # type: ignore[arg-type]
    assert await stalled.check(_call(uid, "microsoft.forward", {"message_id": "m-1"})) == ALLOW


@pytest.mark.asyncio
async def test_the_check_never_escalates_or_refuses_and_is_inert_as_a_backstop(session_factory):
    user, _ = await make_user(session_factory, "cc-backstop@example.com")
    service, parts = build_service(session_factory)
    uid = str(user.id)
    await _flag_mail(service, parts, uid, "m-bad", malicious=50)
    check = FileReputationCallCheck(session_factory)
    assert check.name == "file_reputation" and check.policy == "file_reputation"
    assert check.stages == frozenset({"turn"})

    arguments = {"message_id": "m-bad", "to": ["x@example.com"]}
    for stage in ("approve", "execute"):
        call = _call(uid, "microsoft.forward", arguments, stage=stage)
        assert check.applies_to(call) is False and await check.check(call) == ALLOW
    verdict = await check.check(_call(uid, "microsoft.forward", arguments))
    assert isinstance(verdict, Note) and not isinstance(verdict, (Escalate, Refuse))

    # In the production order it is last, and its note reaches the card as a note only.
    pipeline = standard_pipeline(file_reputation=check)
    assert pipeline.names == ("file_reputation",)
    turn = await pipeline.run(_call(uid, "microsoft.forward", arguments))
    assert turn.refusal is None and turn.escalations == () and turn.failed == ()
    assert [(n.kind, n.severity) for n in turn.notes] == [(NOTE_KIND, "high")]
    for stage in ("approve", "execute"):
        backstop = await pipeline.run(_call(uid, "microsoft.forward", arguments, stage=stage))
        assert backstop.notes == () and backstop.refusal is None and backstop.escalations == ()
