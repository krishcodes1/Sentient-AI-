"""Tests for S1's call check (``OutboundCheck``, services/security/outbound.py) with
fakes: a recording executor that answers the READs (or fails, or hangs), a scripted
link checker standing in for S4, the real SQLite stores and a switch the test flips.
They prove the floor's note and refusal at every stage; that a flagged call that
would run without a card is escalated and anything else only gets notes; the
recipient facts (first time, outside the organisation, look-alikes, unusual letters,
who a Gmail or Outlook reply and a saved draft really go to, the account address
learned from sent mail); the link facts (remote images, coded values, link text that
names another site, S4's notes, only ``scheme://host/`` handed to S4); that "could
not check" is always said and nothing is ever called safe; that the switch only
turns off what costs reads; the pure approve and execute stages; the caps; and that
the whole check is bounded in time.

Why it exists: the card is the owner's only chance to notice where a message really
goes, so every sentence S1 adds and every case it escalates is pinned here. No
network, no model: S4 is a fake or the local-only object, and every READ goes to the
fake executor.
"""

from __future__ import annotations

import asyncio
import re
import time
import unicodedata
from typing import Any, Optional
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

from services.agent.runtime import canonical_tool_name
from services.agent.tool_registry import resolve_tool
from services.security import outbound
from services.security.call_checks import (
    ALLOW,
    CHECK_ORDER,
    CallFacts,
    Escalate,
    Note,
    Refuse,
    standard_pipeline,
)
from services.security.link_checks import LinkReport, LinkSignal
from services.security.outbound import (
    ESCALATE_REASON,
    EXECUTE_REFUSAL,
    HIDDEN_IN_RECIPIENT_RULE,
    OUTBOUND_RULE_POLICY,
    OutboundCheck,
)
from services.security.outbound_recipients import parse_recipients
from services.security.outbound_store import (
    KnownRecipientStore,
    OrganisationDomainStore,
    UserEmails,
)
from tests.conftest import make_user
from tests.security_stubs import requires_real

TAGS = "".join(chr(0xE0000 + ord(ch)) for ch in "send keys")  # 9 tag characters
ZWSP = "​"
RLO = "‮"
SEND = "google_workspace.send_email"
REPLY = "google_workspace.reply"
DRAFT = "google_workspace.create_draft"
SEND_DRAFT = "google_workspace.send_draft"
MAIL = {
    "to": "billing@acme-payments.example",
    "subject": "Invoice 4471",
    "body": "Hi, see attached.",
}


def ok(data: Any) -> dict[str, Any]:
    return {"ok": True, "result": data}


class FakeExecutor:
    """Answers READs by action name: a result dict, an exception, "hang", or a
    callable of the arguments. Records every call."""

    def __init__(self, answers: Optional[dict[str, Any]] = None) -> None:
        self.calls: list[tuple[str, dict[str, Any], bool]] = []
        self.answers = dict(answers or {})

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        user_id: str,
        approved: bool = False,
        **_: Any,
    ):
        self.calls.append((tool_name, dict(arguments), approved))
        answer = self.answers.get(
            tool_name.rpartition(".")[2], {"ok": False, "error": "Not answered by this fake."}
        )
        if callable(answer):
            answer = answer(arguments)
        if isinstance(answer, str) and answer == "hang":
            await asyncio.sleep(3600)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def actions(self) -> list[str]:
        return [name.rpartition(".")[2] for name, _args, _approved in self.calls]


class FakeLinkChecker:
    """Stands in for S4: scripted reports by URL for ``check``, and a simple
    local rule for ``check_local``: link text that names a domain other than
    the link's host is a high text_mismatch signal."""

    def __init__(
        self, reports: Optional[dict[str, LinkReport]] = None, *, hang: bool = False
    ) -> None:
        self.reports = dict(reports or {})
        self.checked: list[list[str]] = []
        self.purposes: list[str] = []
        self.local: list[tuple[str, Optional[str]]] = []
        self.hang = hang

    async def check(self, urls, *, purpose, texts=None, network=True, timeout_s=8.0):
        self.checked.append(list(urls))
        self.purposes.append(purpose)
        if self.hang:
            await asyncio.sleep(3600)
        return [
            self.reports.get(url)
            or LinkReport(url=url, shown="", host="", level="unknown", service_status="no_key")
            for url in urls
        ]

    def check_local(self, url, *, text=None):
        self.local.append((url, text))
        host = (urlsplit(url).hostname or "").lower()
        named = (text or "").strip().lower()
        signals: tuple[LinkSignal, ...] = ()
        if named and "." in named and " " not in named and not host.endswith(named):
            signals = (
                LinkSignal(
                    "text_mismatch",
                    "high",
                    f"The link text says {named} but the link goes to {host}.",
                ),
            )
        return LinkReport(
            url=url,
            shown="",
            host=host,
            level="suspicious" if signals else "unknown",
            signals=signals,
        )

    def cached_report(self, url, *, purpose):
        return None

    async def remote_configured(self):
        return False


class World:
    """One user (ann@northwind.example by default) with the real stores, a
    fake executor, a fake S4 and the owner's switch."""

    def __init__(self, session_factory, user) -> None:
        self.session_factory = session_factory
        self.user = user
        self.user_id = str(user.id)
        self.known = KnownRecipientStore(session_factory)
        self.domains = OrganisationDomainStore(session_factory)
        self.users = UserEmails(session_factory)
        self.executor = FakeExecutor()
        self.links: Any = FakeLinkChecker()
        self.switch: Any = True

    async def enabled(self) -> bool:
        if isinstance(self.switch, BaseException):
            raise self.switch
        return bool(self.switch)

    def check(self, **overrides: Any) -> OutboundCheck:
        kwargs: dict[str, Any] = {
            "executor": self.executor,
            "known": self.known,
            "org_domains": self.domains,
            "users": self.users,
            "links": self.links,
            "enabled": self.enabled,
        }
        kwargs.update(overrides)
        return OutboundCheck(**kwargs)

    def call(
        self, tool: str, arguments: dict[str, Any], *, stage: str = "turn", **fields: Any
    ) -> CallFacts:
        is_mcp = tool.startswith("mcp.")
        resolved = None if is_mcp else resolve_tool(tool)
        return CallFacts(
            stage=stage,  # type: ignore[arg-type]
            user_id=self.user_id,
            tool_name=tool,
            canonical=canonical_tool_name(tool),
            arguments=arguments,
            spec=resolved.spec if resolved is not None else None,
            is_mcp=is_mcp,
            **fields,
        )

    async def run(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        check: Optional[OutboundCheck] = None,
        **fields: Any,
    ):
        return await (check or self.check()).check(self.call(tool, arguments, **fields))

    async def sent_before(self, *addresses: str) -> None:
        await self.known.record(self.user_id, parse_recipients(list(addresses)))


@pytest_asyncio.fixture
async def world(session_factory) -> World:
    user, _ = await make_user(session_factory, "ann@northwind.example")
    return World(session_factory, user)


def notes(verdict: Any) -> list[tuple[str, str, str]]:
    return [(n.kind, n.severity, n.text) for n in getattr(verdict, "notes", ())]


def kinds(verdict: Any) -> list[str]:
    return [kind for kind, _sev, _text in notes(verdict)]


def note_of(verdict: Any, kind: str) -> tuple[str, str]:
    found = [(sev, text) for k, sev, text in notes(verdict) if k == kind]
    assert found, (kind, notes(verdict))
    return found[0]


def facts_answer(**facts: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "m1",
        "from": {"name": "Vendor", "address": "billing@vendor.example", "domain": "vendor.example"},
        "reply_to": [],
        "to": ["ann@northwind.example"],
        "cc": [],
        "sent_by_me": False,
        "mailbox": "",
    }
    base.update(facts)
    return ok(base)


# -- what the check applies to, and the floor ----------------------------------------


@pytest.mark.asyncio
async def test_a_tool_with_no_outbound_fields_is_allowed_without_any_read(world):
    check = world.check()
    read = world.call("google_workspace.get_message", {"message_id": "m1"})
    assert check.applies_to(read) is False
    assert await check.check(read) is ALLOW
    assert (
        await world.run("memory.remember", {"content": "Ann likes tea", "category": "preference"})
        is ALLOW
    )
    assert (
        await world.run("reminders.create", {"title": "Call Bo", "due_at": "2026-10-15T09:00:00"})
        is ALLOW
    )
    assert world.executor.calls == [] and world.links.checked == []
    # SEC-F3: a write with no declaration still gets the always-safe subset's note.
    verdict = await world.run("memory.remember", {"content": "Ann" + TAGS + " likes tea"})
    assert isinstance(verdict, Note)
    assert notes(verdict) == [
        (
            "hidden_characters_removed",
            "warn",
            "Removed 9 hidden characters from content (9 tag characters): text a reader would not see.",
        )
    ]
    assert world.executor.calls == []


@pytest.mark.asyncio
async def test_tag_characters_in_a_send_give_the_removed_note_with_the_breakdown(world):
    body = "Hi" + TAGS + " there" + ZWSP * 5 + "!"
    verdict = await world.run(SEND, {**MAIL, "body": body})
    assert isinstance(verdict, Note)
    assert note_of(verdict, "hidden_characters_removed") == (
        "warn",
        "Removed 14 hidden characters from body (9 tag characters, 5 zero-width characters): "
        "text a reader would not see.",
    )
    # Two fields, and a direction control.
    both = await world.run(SEND, {**MAIL, "subject": "Re" + RLO + "ply", "body": body})
    assert note_of(both, "hidden_characters_removed")[1].startswith(
        "Removed 15 hidden characters from subject and body (9 tag characters, "
        "1 text-direction control, 5 zero-width characters)"
    )


@pytest.mark.asyncio
async def test_a_draft_hiding_characters_that_would_run_without_a_card_is_escalated(world):
    verdict = await world.run(DRAFT, {**MAIL, "body": "Draft" + TAGS}, runs_without_card=True)
    assert isinstance(verdict, Escalate)
    assert verdict.reason == ESCALATE_REASON and verdict.names_rule is False
    assert verdict.refusal_text == EXECUTE_REFUSAL
    assert kinds(verdict)[0] == "hidden_characters_removed"
    # The same draft going to a card anyway only carries the notes.
    carded = await world.run(DRAFT, {**MAIL, "body": "Draft" + TAGS}, will_card=True)
    assert isinstance(carded, Note)


@pytest.mark.asyncio
async def test_a_draft_to_a_first_time_recipient_is_an_info_note_and_not_escalated(world):
    verdict = await world.run(DRAFT, MAIL, runs_without_card=True)
    assert isinstance(verdict, Note)
    assert note_of(verdict, "recipient_first_time") == (
        "info",
        "First time Crawler sends to anyone at acme-payments.example (billing@acme-payments.example).",
    )
    assert all(severity == "info" for _kind, severity, _text in notes(verdict))


@pytest.mark.asyncio
async def test_an_auto_approved_github_issue_with_a_remote_image_is_escalated(world):
    body = "Status update ![chart](https://img.collect.example/p.png?u=1) thanks"
    verdict = await world.run(
        "github.create_issue",
        {"owner": "o", "repo": "r", "title": "Weekly", "body": body},
        runs_without_card=True,
    )
    assert isinstance(verdict, Escalate)
    assert note_of(verdict, "remote_image") == (
        "warn",
        "The message shows an image from img.collect.example. Opening the message loads it, which "
        "tells that site the message was read and can carry data in the image address.",
    )
    # An image on GitHub's own upload host is not one.
    own = "![s](https://user-images.githubusercontent.com/1/2-abc.png)"
    quiet = await world.run(
        "github.create_issue",
        {"owner": "o", "repo": "r", "title": "W", "body": own},
        runs_without_card=True,
    )
    assert quiet is ALLOW


@pytest.mark.asyncio
async def test_a_long_coded_value_in_a_link_is_a_warning(world):
    coded = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" * 4
    verdict = await world.run(
        "slack.post_message",
        {"channel": "C0123ABCD", "text": f"see https://collect.example/x?d={coded}"},
    )
    severity, text = note_of(verdict, "encoded_link")
    assert severity == "warn"
    assert text.startswith("A link to collect.example carries a long coded value (")
    assert text.endswith("characters). Links like this can carry your data to that site.")


@pytest.mark.asyncio
async def test_a_slack_status_with_a_mismatched_link_text_is_escalated_on_the_auto_tier(world):
    verdict = await world.run(
        "slack.set_status",
        {"text": "Pay here: [paypal.com](https://paypa1-verify.example/login)"},
        runs_without_card=True,
    )
    assert isinstance(verdict, Escalate)
    assert note_of(verdict, "link_text_mismatch") == (
        "high",
        "The link text says paypal.com but the link goes to paypa1-verify.example.",
    )
    # The local check saw the host only, with the link's text.
    assert ("https://paypa1-verify.example/", "paypal.com") in world.links.local


# -- recipients ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_send_to_a_new_domain_outside_the_organisation_is_a_warn_first_time_note(world):
    verdict = await world.run(SEND, MAIL)
    assert isinstance(verdict, Note)
    assert note_of(verdict, "recipient_first_time") == (
        "warn",
        "First time Crawler sends to anyone at acme-payments.example (billing@acme-payments.example).",
    )
    assert note_of(verdict, "recipient_outside_organisation") == (
        "info",
        "Outside your organisation (northwind.example): billing@acme-payments.example.",
    )
    # Would it have run unasked, the warning makes it a card.
    assert isinstance(await world.run(SEND, MAIL, runs_without_card=True), Escalate)


@pytest.mark.asyncio
async def test_a_send_to_a_new_colleague_inside_the_organisation_is_only_info(world):
    verdict = await world.run(
        SEND, {**MAIL, "to": "carl@eu.northwind.example"}, runs_without_card=True
    )
    assert isinstance(verdict, Note)
    assert note_of(verdict, "recipient_first_time") == (
        "info",
        "First time Crawler sends to anyone at eu.northwind.example (carl@eu.northwind.example).",
    )
    assert "recipient_outside_organisation" not in kinds(verdict)


@pytest.mark.asyncio
async def test_a_send_to_a_known_address_has_no_first_time_note(world):
    await world.sent_before("billing@acme-payments.example")
    verdict = await world.run(SEND, MAIL)
    assert "recipient_first_time" not in kinds(verdict)
    # A new address at a domain already written to is new, but only info.
    other = await world.run(SEND, {**MAIL, "to": "ops@acme-payments.example"})
    assert note_of(other, "recipient_first_time") == (
        "info",
        "First time Crawler sends to ops@acme-payments.example.",
    )


@pytest.mark.asyncio
async def test_outside_notes_name_the_organisation_domains_and_never_appear_without_any(
    session_factory,
):
    bob, _ = await make_user(session_factory, "bob@gmail.com")
    world = World(session_factory, bob)
    verdict = await world.run(SEND, MAIL)
    assert "recipient_outside_organisation" not in kinds(verdict)
    # Nobody is outside an organisation that is not known: a new domain is still a warning.
    assert note_of(verdict, "recipient_first_time")[0] == "warn"
    await world.domains.add("acme.co.uk", added_by=world.user_id)
    listed = await world.run(SEND, MAIL)
    assert note_of(listed, "recipient_outside_organisation") == (
        "info",
        "Outside your organisation (acme.co.uk): billing@acme-payments.example.",
    )


@pytest.mark.asyncio
async def test_a_lookalike_of_the_organisation_domain_is_a_high_note(world):
    verdict = await world.run(SEND, {**MAIL, "to": "Payroll <payroll@northwnd.example>"})
    assert note_of(verdict, "recipient_lookalike") == (
        "high",
        "payroll@northwnd.example looks like northwind.example but is a different address.",
    )
    assert kinds(verdict)[0] == "recipient_lookalike"  # high comes first
    # A brand on another domain is a warning.
    brand = await world.run(SEND, {**MAIL, "to": "desk@northwind-billing.example"})
    assert note_of(brand, "recipient_lookalike")[0] == "warn"
    # Look-alike letters, shown in their ASCII form.
    cyrillic = await world.run(SEND, {**MAIL, "to": "pay@nоrthwind.example"})
    assert note_of(cyrillic, "recipient_unusual_characters") == (
        "high",
        "pay@xn--nrthwind-nbh.example uses look-alike letters: it reads as northwind.example.",
    )


@pytest.mark.asyncio
async def test_a_hidden_character_inside_a_recipient_address_is_refused_with_the_outbound_rule(
    world,
):
    for to in (
        "ann" + ZWSP + "@acme.example",
        ["ok@acme.example", "Bo <bo" + RLO + "@acme.example>"],
    ):
        verdict = await world.run(SEND, {**MAIL, "to": to})
        assert isinstance(verdict, Refuse)
        assert verdict.rule == HIDDEN_IN_RECIPIENT_RULE and verdict.policy == OUTBOUND_RULE_POLICY
        assert verdict.message == (
            "Refused: the 'to' address contains hidden characters, which can make an address look "
            "like a different one. Write the address again in plain text; nothing was sent."
        )
    attendees = {
        "event_data": {"summary": "Sync", "attendees": [{"email": "x" + ZWSP + "@acme.example"}]}
    }
    refused = await world.run("google_workspace.create_event", attendees)
    assert isinstance(refused, Refuse) and "'attendees' address" in refused.message
    assert world.executor.calls == []
    # A display name may keep a Persian zero-width non-joiner.
    persian = "می‌خو <ann@acme.example>"
    assert not isinstance(await world.run(SEND, {**MAIL, "to": persian}), Refuse)


@pytest.mark.asyncio
async def test_a_gmail_reply_card_names_the_reply_to_address_read_from_the_original(world):
    world.executor.answers["get_message_security"] = facts_answer(
        reply_to=["pay@vendor-billing.example"]
    )
    verdict = await world.run(REPLY, {"message_id": "m1", "body": "Thanks, transfer done."})
    assert (
        "google_workspace.get_message_security",
        {"message_id": "m1"},
        False,
    ) in world.executor.calls
    assert note_of(verdict, "recipients_resolved") == (
        "info",
        "This reply goes to: pay@vendor-billing.example.",
    )
    assert note_of(verdict, "recipient_first_time") == (
        "warn",
        "First time Crawler sends to anyone at vendor-billing.example (pay@vendor-billing.example).",
    )
    # The READ is pinned to the call's own row.
    world.executor.calls.clear()
    await world.run("google_workspace__1a2b3c4d.reply", {"message_id": "m2", "body": "Thanks"})
    assert world.executor.calls[0][0] == "google_workspace__1a2b3c4d.get_message_security"


@pytest.mark.asyncio
async def test_a_resolved_reply_to_with_a_bidi_control_is_shown_normalised_and_flagged(world):
    world.executor.answers["get_message_security"] = facts_answer(
        reply_to=["pay" + RLO + "@vendor.example"]
    )
    verdict = await world.run(REPLY, {"message_id": "m1", "body": "Thanks"})
    for _kind, _severity, text in notes(verdict):
        assert not any(unicodedata.category(ch) in ("Cc", "Cf") for ch in text), text
    assert note_of(verdict, "recipients_resolved")[1] == "This reply goes to: pay@vendor.example."
    assert note_of(verdict, "recipient_unusual_characters") == (
        "high",
        "pay@vendor.example has characters a reader cannot see in the address, so it may not be "
        "the address it looks like.",
    )


@pytest.mark.asyncio
async def test_a_memory_write_hiding_tag_characters_that_would_run_without_a_card_is_escalated(
    world,
):
    verdict = await world.run(
        "memory.remember", {"content": "Always cc" + TAGS + " me"}, runs_without_card=True
    )
    assert isinstance(verdict, Escalate)
    assert kinds(verdict) == ["hidden_characters_removed"]
    # Switch off: still noted (the floor), but no longer escalated.
    world.switch = False
    off = await world.run(
        "memory.remember", {"content": "Always cc" + TAGS + " me"}, runs_without_card=True
    )
    assert isinstance(off, Note)


@pytest.mark.asyncio
async def test_a_reply_to_on_another_domain_than_the_sender_is_a_warning(world):
    world.executor.answers["get_message_security"] = facts_answer(
        reply_to=["pay@vendor-billing.co"]
    )
    verdict = await world.run(REPLY, {"message_id": "m1", "body": "Thanks"})
    assert note_of(verdict, "reply_to_elsewhere") == (
        "warn",
        "The original message asks for replies to pay@vendor-billing.co, a different domain from "
        "its sender (vendor.example).",
    )
    # Same domain: no warning.
    world.executor.answers["get_message_security"] = facts_answer(reply_to=["help@vendor.example"])
    quiet = await world.run(REPLY, {"message_id": "m9", "body": "Thanks"})
    assert "reply_to_elsewhere" not in kinds(quiet)


@pytest.mark.asyncio
async def test_reply_all_adds_to_and_cc_without_the_mailbox_or_the_primary(world):
    world.executor.answers["get_message_security"] = facts_answer(
        to=["me@northwind.example", "bob@x.example"],
        cc=["carl@y.example", "billing@vendor.example"],
        mailbox="me@northwind.example",
    )
    verdict = await world.run(REPLY, {"message_id": "m1", "body": "Thanks all", "reply_all": True})
    assert note_of(verdict, "recipients_resolved")[1] == (
        "This reply goes to: billing@vendor.example (cc: bob@x.example, carl@y.example)."
    )
    # The mailbox counted as the user's own: no sent-folder probe was needed.
    assert "get_messages" not in world.executor.actions()


@pytest.mark.asyncio
async def test_a_reply_to_mail_you_sent_goes_to_its_original_recipients(world):
    world.executor.answers["get_message_security"] = facts_answer(
        sent_by_me=True,
        to=["dora@zeta.example"],
        reply_to=["elsewhere@other.example"],
        **{
            "from": {
                "name": "Ann",
                "address": "ann@northwind.example",
                "domain": "northwind.example",
            }
        },
    )
    verdict = await world.run(REPLY, {"message_id": "m1", "body": "Following up"})
    assert note_of(verdict, "recipients_resolved")[1] == "This reply goes to: dora@zeta.example."
    assert "reply_to_elsewhere" not in kinds(verdict)


@pytest.mark.asyncio
async def test_an_outlook_reply_says_outlook_picks_and_names_the_expected_recipients(world):
    world.executor.answers["get_message_security"] = facts_answer(reply_to=["desk@vendor.example"])
    verdict = await world.run("microsoft.reply", {"message_id": "AAMk1", "comment": "Thanks"})
    assert world.executor.calls[0][0] == "microsoft.get_message_security"
    assert note_of(verdict, "recipients_resolved")[1] == (
        "Outlook picks who this reply goes to; from the original it should be: desk@vendor.example."
    )


@pytest.mark.asyncio
async def test_without_the_read_scope_the_card_says_the_recipients_could_not_be_checked(world):
    world.executor.answers["get_message_security"] = {
        "ok": False,
        "error": "Scope 'gmail.read' was not granted for this connector.",
    }
    verdict = await world.run(REPLY, {"message_id": "m1", "body": "Thanks"})
    assert note_of(verdict, "recipients_not_checked") == (
        "warn",
        "Crawler could not read the original message, so it cannot say who this reply goes to "
        "(this account does not allow reading mail). Gmail will send it to the original's "
        "Reply-To address, or its From address if it has none (for mail you sent, to its "
        "original To recipients).",
    )
    # A warning: a reply that would have run unasked gets a card.
    assert isinstance(
        await world.run(REPLY, {"message_id": "m1", "body": "x"}, runs_without_card=True), Escalate
    )
    # A message that is gone says so.
    world.executor.answers["get_message_security"] = ok({"id": "m3", "gone": True})
    gone = await world.run(REPLY, {"message_id": "m3", "body": "Thanks"})
    assert "(the original message is no longer there)" in note_of(gone, "recipients_not_checked")[1]


@pytest.mark.asyncio
async def test_a_read_that_times_out_says_the_recipients_could_not_be_checked(world, monkeypatch):
    monkeypatch.setattr(outbound, "READ_TIMEOUT_S", 0.05)
    world.executor.answers["get_message_security"] = "hang"
    verdict = await world.run(REPLY, {"message_id": "m1", "body": "Thanks", "reply_all": True})
    severity, text = note_of(verdict, "recipients_not_checked")
    assert severity == "warn"
    assert "(reading it took too long)" in text and text.endswith("plus everyone else on it.")


@pytest.mark.asyncio
async def test_a_send_draft_card_lists_the_drafts_recipients_and_counts_its_hidden_characters(
    world,
):
    world.executor.answers["get_draft"] = ok(
        {
            "draft_id": "r1",
            "to": "Ana <ana@partner.example>",
            "cc": "ops@northwind.example",
            "bcc": "",
            "subject": "Plan",
            "body": "See"
            + ZWSP
            + " you"
            + TAGS[:2]
            + " at 3. ![x](https://pixel.collect.example/t.gif)",
        }
    )
    verdict = await world.run(SEND_DRAFT, {"draft_id": "r1"})
    assert ("google_workspace.get_draft", {"draft_id": "r1"}, False) in world.executor.calls
    assert note_of(verdict, "recipients_resolved") == (
        "info",
        "This draft goes to: ana@partner.example (cc: ops@northwind.example).",
    )
    assert note_of(verdict, "hidden_characters_in_draft") == (
        "warn",
        "The draft contains 3 hidden characters. Crawler cannot clean a saved draft; open it in "
        "Gmail if you are unsure.",
    )
    # The draft's own links are checked too.
    assert note_of(verdict, "remote_image")[0] == "warn"
    assert world.links.checked == [["https://pixel.collect.example/"]]
    # A draft that cannot be read is said.
    world.executor.answers["get_draft"] = {
        "ok": False,
        "error": "Gmail answered HTTP 404 Not Found.",
    }
    missing = await world.run(SEND_DRAFT, {"draft_id": "r404"})
    assert note_of(missing, "recipients_not_checked")[1].startswith(
        "Crawler could not read the draft, so it cannot say who it goes to (it is no longer there)."
    )


@pytest.mark.asyncio
async def test_the_account_address_from_sent_mail_counts_as_self_and_is_cached(session_factory):
    student, _ = await make_user(session_factory, "ann.home@gmail.com")
    world = World(session_factory, student)
    world.executor.answers["get_messages"] = ok(
        [{"from": "Ann <ann@school.example>", "subject": "x"}]
    )
    check = world.check()
    to_self = await world.run(SEND, {**MAIL, "to": "ann@school.example"}, check=check)
    assert to_self is ALLOW
    colleague = await world.run(SEND, {**MAIL, "to": "bo@school.example"}, check=check)
    # The account's domain is the organisation's: a colleague is only info, and inside.
    assert note_of(colleague, "recipient_first_time")[0] == "info"
    assert "recipient_outside_organisation" not in kinds(colleague)
    assert world.executor.actions().count("get_messages") == 1  # cached
    assert world.executor.calls[0] == (
        "google_workspace.get_messages",
        {"query": "in:sent", "max_results": 1},
        False,
    )


@pytest.mark.asyncio
async def test_a_failed_history_lookup_is_noted_and_gives_no_first_time_notes(world):
    class Broken:
        async def known(self, user_id, recipients):
            raise ConnectionError("history down")

    verdict = await world.run(SEND, MAIL, check=world.check(known=Broken()))
    assert note_of(verdict, "recipient_history_not_checked") == (
        "info",
        "Crawler could not read its sent-to history, so it cannot say whether these recipients are new.",
    )
    assert "recipient_first_time" not in kinds(verdict)
    # Other recipient facts still appear.
    assert "recipient_outside_organisation" in kinds(verdict)


# -- links and S4 --------------------------------------------------------------------


@requires_real("services.security.link_checks")
@pytest.mark.asyncio
async def test_a_dangerous_link_report_becomes_a_high_note_in_s4s_wording(world):
    origin = "https://paypa1-verify.xyz/"
    world.links = FakeLinkChecker(
        {
            origin: LinkReport(
                url=origin,
                shown=origin,
                host="paypa1-verify.xyz",
                level="dangerous",
                threats=("SOCIAL_ENGINEERING",),
                service="safe_browsing",
                service_status="listed",
            )
        }
    )
    verdict = await world.run(
        "slack.post_message", {"channel": "C0123ABCD", "text": f"Log in at {origin}login"}
    )
    assert note_of(verdict, "link_dangerous") == (
        "high",
        "Link check: paypa1-verify.xyz - Google Safe Browsing says this site may be phishing or a "
        "scam (advisory provided by Google).",
    )


@requires_real("services.security.link_checks")
@pytest.mark.asyncio
async def test_a_not_checked_link_report_is_said_and_nothing_is_called_safe(world):
    origin = "https://shop.example/"
    world.links = FakeLinkChecker(
        {
            origin: LinkReport(
                url=origin,
                shown=origin,
                host="shop.example",
                level="unknown",
                service="safe_browsing",
                service_status="timeout",
            )
        }
    )
    verdict = await world.run(
        "slack.post_message", {"channel": "C0123ABCD", "text": f"Order at {origin}cart"}
    )
    severity, text = note_of(verdict, "link_not_checked")
    assert severity == "info" and "not checked" in text
    # "Google Safe Browsing" may be named; a link is never called safe.
    for _kind, _severity, line in notes(verdict):
        assert not re.search(
            r"\b(is|are|looks|seems|was|were) safe\b|no known threats", line, re.I
        ), line


@pytest.mark.asyncio
async def test_s4s_link_notes_reach_the_card_as_they_come(world, monkeypatch):
    seen: list[list[LinkReport]] = []

    def fake_notes(reports, *, limit=3):
        seen.append(list(reports))
        return [
            {
                "kind": "link_dangerous",
                "severity": "high",
                "text": "Link check: bad.example - listed.",
            }
        ]

    monkeypatch.setattr(outbound.link_checks, "security_notes", fake_notes)
    verdict = await world.run(
        "slack.post_message",
        {"channel": "C0123ABCD", "text": "go to https://bad.example/x"},
        runs_without_card=True,
    )
    assert isinstance(verdict, Escalate)
    assert note_of(verdict, "link_dangerous") == ("high", "Link check: bad.example - listed.")
    assert [report.url for report in seen[0]] == ["https://bad.example/"]
    assert world.links.purposes == ["outbound"]


@pytest.mark.asyncio
async def test_s4_is_given_only_scheme_and_host_of_each_link(world):
    text = (
        "Plan: https://docs.example:8443/d/secret-plan?token=abc#p2 and "
        "[the form](https://forms.example/f/123?prefill=me%40northwind.example) and "
        "https://docs.example/another/path"
    )
    await world.run("notion.add_comment", {"page_id": "0" * 32, "text": text})
    [handed] = world.links.checked
    assert handed == [
        "https://docs.example:8443/",
        "https://forms.example/",
        "https://docs.example/",
    ]
    for url in handed + [url for url, _text in world.links.local]:
        parts = urlsplit(url)
        assert parts.path == "/" and not parts.query and not parts.fragment, url


@pytest.mark.asyncio
async def test_with_only_local_link_checks_the_local_findings_still_appear(world):
    world.links = None  # the local-only checker
    check = world.check(links=None)
    coded = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" * 4
    verdict = await world.run(
        "github.comment",
        {
            "owner": "o",
            "repo": "r",
            "number": 1,
            "body": f"![p](https://t.example/p.png) https://c.example/?d={coded}",
        },
        check=check,
    )
    assert {"remote_image", "encoded_link"} <= set(kinds(verdict))
    assert "link_not_checked" not in kinds(verdict)


# -- the switch and the stages ---------------------------------------------------------


@pytest.mark.asyncio
async def test_with_the_switch_off_only_the_floor_applies_and_nothing_is_read(world):
    world.switch = False
    world.executor.answers["get_message_security"] = facts_answer(
        reply_to=["pay@vendor-billing.example"]
    )
    body = "Hi" + TAGS + " ![x](https://img.collect.example/p.png)"
    verdict = await world.run(SEND, {**MAIL, "body": body}, runs_without_card=True)
    assert isinstance(verdict, Note)
    assert kinds(verdict) == ["hidden_characters_removed"]
    reply = await world.run(REPLY, {"message_id": "m1", "body": "Thanks"}, runs_without_card=True)
    assert reply is ALLOW
    assert world.executor.calls == [] and world.links.checked == [] and world.links.local == []
    # The refusal is the floor: it stays.
    assert isinstance(await world.run(SEND, {**MAIL, "to": "a" + ZWSP + "@b.example"}), Refuse)


@pytest.mark.asyncio
async def test_a_switch_read_error_counts_as_on(world):
    world.switch = RuntimeError("settings unreadable")
    verdict = await world.run(SEND, MAIL, runs_without_card=True)
    assert isinstance(verdict, Escalate)
    assert "recipient_first_time" in kinds(verdict)


@pytest.mark.asyncio
async def test_the_execute_stage_reads_nothing_and_calls_no_network(world):
    class Spy(KnownRecipientStore):
        asked = 0

        async def known(self, user_id, recipients):
            Spy.asked += 1
            return await super().known(user_id, recipients)

    check = world.check(known=Spy(world.session_factory))
    body = "Hi ![x](https://img.collect.example/p.png) " + TAGS
    approved = await check.check(
        world.call(SEND, {**MAIL, "body": body}, stage="execute", person_approved=True)
    )
    assert approved is ALLOW
    clean = await check.check(
        world.call(SEND, MAIL, stage="execute", runs_without_card=True, approval="tier")
    )
    assert clean is ALLOW
    reply = await check.check(
        world.call(
            REPLY,
            {"message_id": "m1", "body": "x"},
            stage="execute",
            runs_without_card=True,
            approval="tier",
        )
    )
    assert reply is ALLOW
    assert world.executor.calls == [] and world.links.checked == [] and Spy.asked == 0


@pytest.mark.asyncio
async def test_the_execute_stage_escalates_standing_consent_on_a_pure_finding(world):
    check = world.check()
    for arguments in (
        {**MAIL, "body": "Hi" + TAGS},
        {**MAIL, "body": "Hi ![x](https://img.collect.example/p.png)"},
        {**MAIL, "body": "Pay at [paypal.com](https://paypa1-verify.example/)"},
    ):
        verdict = await check.check(
            world.call(
                DRAFT, arguments, stage="execute", runs_without_card=True, approval="low_risk"
            )
        )
        assert isinstance(verdict, Escalate), arguments
        assert verdict.refusal_text == EXECUTE_REFUSAL and verdict.notes == ()
    assert world.executor.calls == [] and world.links.checked == []
    world.switch = False
    off = await check.check(
        world.call(
            DRAFT,
            {**MAIL, "body": "Hi" + TAGS},
            stage="execute",
            runs_without_card=True,
            approval="tier",
        )
    )
    assert off is ALLOW


@pytest.mark.asyncio
async def test_the_approve_stage_refuses_a_stored_address_hiding_characters_and_otherwise_allows(
    world,
):
    check = world.check()
    hiding = await check.check(
        world.call(
            SEND,
            {**MAIL, "to": "ann" + ZWSP + "@acme.example", "_bind": "x"},
            stage="approve",
            person_approved=True,
        )
    )
    assert isinstance(hiding, Refuse) and hiding.rule == HIDDEN_IN_RECIPIENT_RULE
    noted = await check.check(
        world.call(SEND, {**MAIL, "body": "Hi" + TAGS}, stage="approve", person_approved=True)
    )
    assert noted is ALLOW
    assert world.executor.calls == [] and world.links.checked == []


@pytest.mark.asyncio
async def test_mcp_string_leaves_get_the_floor_note_only(world):
    arguments = {
        "title": "Note",
        "blocks": [{"text": "see https://img.collect.example/p.png" + TAGS}, {"n": 3}],
        "meta": {"author": "Ann" + RLO},
    }
    check = world.check()
    call = world.call("mcp.notes.save_page", arguments)
    assert check.applies_to(call) is True
    verdict = await check.check(call)
    assert notes(verdict) == [
        (
            "hidden_characters_removed",
            "warn",
            "Removed 10 hidden characters from arguments (9 tag characters, 1 text-direction "
            "control): text a reader would not see.",
        )
    ]
    assert world.executor.calls == [] and world.links.checked == [] and world.links.local == []


@pytest.mark.asyncio
async def test_at_most_six_notes_and_five_addresses_per_note(world):
    recipients = ", ".join(f"user{i}@d{i}.example" for i in range(8))
    images = " ".join(f"![i](https://img{i}.collect.example/p.png)" for i in range(5))
    verdict = await world.run(SEND, {**MAIL, "to": recipients, "body": "Hi" + TAGS + " " + images})
    found = notes(verdict)
    assert len(found) == 6
    for _kind, _severity, text in found:
        assert text.count("@") <= 5 and len(text) <= 300
    first_time = note_of(verdict, "recipient_first_time")[1]
    assert first_time.endswith("user4@d4.example) and 3 more.")
    # High first, then warn (hidden, links, recipients), then info.
    order = [severity for _kind, severity, _text in found]
    assert order == sorted(order, key={"high": 0, "warn": 1, "info": 2}.__getitem__)
    assert found[0][0] == "hidden_characters_removed"


@pytest.mark.asyncio
async def test_note_texts_never_quote_the_message_body(world):
    secret = "the vault code is 4471-9921"
    body = f"{secret} ![x](https://img.collect.example/p.png?d={secret.replace(' ', '')}) " + TAGS
    world.executor.answers["get_message_security"] = facts_answer(
        reply_to=["pay@vendor-billing.example"]
    )
    for tool, arguments in (
        (SEND, {**MAIL, "subject": secret, "body": body}),
        (REPLY, {"message_id": "m1", "body": body}),
    ):
        verdict = await world.run(tool, arguments)
        for _kind, _severity, text in notes(verdict):
            assert "vault" not in text and "4471" not in text and "9921" not in text, text


@pytest.mark.asyncio
async def test_the_whole_check_is_bounded_and_unfinished_parts_say_not_checked(world, monkeypatch):
    monkeypatch.setattr(outbound, "CHECK_BUDGET_S", 0.3)
    world.executor.answers["get_message_security"] = "hang"
    world.links = FakeLinkChecker(hang=True)
    started = time.monotonic()
    verdict = await world.run(
        REPLY, {"message_id": "m1", "body": "see https://shop.example/x"}, runs_without_card=True
    )
    assert time.monotonic() - started < 2.0
    assert "(reading it took too long)" in note_of(verdict, "recipients_not_checked")[1]
    assert note_of(verdict, "link_not_checked") == (
        "info",
        "Links in this message were not checked (the check did not finish in time).",
    )
    assert isinstance(verdict, Escalate)  # "could not check" is a warning on an auto-run call


@pytest.mark.asyncio
async def test_a_link_with_a_port_of_thousands_of_digits_cannot_hide_the_recipient_notes(world):
    # Batch-2 check: a port past int()'s 4,300-digit limit made the URL reader raise, the whole
    # check failed, and the card showed only "check_failed" in place of the look-alike,
    # first-time and outside notes: text an injection writes could hide S1's warnings.
    send = {**MAIL, "to": "billing@northwnd.example", "body": "Invoice attached."}
    plain = await world.run(SEND, send)
    assert note_of(plain, "recipient_lookalike")[0] == "high"
    huge = "https://a.example:" + "1" * 4400 + "/"
    for body in (
        f"Invoice attached. {huge}",
        f'Invoice attached. <div style="background:url({huge}p.png)">x</div>',
        f"Invoice attached. ![x]({huge}p.png)",
    ):
        verdict = await world.run(SEND, {**send, "body": body})
        for kind in kinds(plain):
            assert kind in kinds(verdict), (kind, body[:40])
        outcome = await standard_pipeline(outbound=world.check()).run(
            world.call(SEND, {**send, "body": body})
        )
        assert outcome.failed == ()
        shown = [note.kind for note in outcome.notes]
        assert "check_failed" not in shown
        assert {"recipient_lookalike", "recipient_first_time"} <= set(shown), shown


@pytest.mark.asyncio
async def test_a_body_full_of_long_international_hosts_is_checked_without_stalling(world):
    # Batch-2 check: punycode work on a 4,000-character host of distinct ideographs took 8.35 s
    # of synchronous CPU inside _link_facts (12 KB of body), stalling the whole backend before
    # any asyncio bound could act. Such a host can never be looked up and is refused unencoded.
    ideographs = "".join(chr(0x4E00 + index) for index in range(4000))
    started = time.monotonic()
    verdict = await world.run(SEND, {**MAIL, "body": "see https://" + ideographs})
    assert time.monotonic() - started < 2.0
    assert note_of(verdict, "recipient_first_time")[0] == "warn"
    check = world.check()
    started = time.monotonic()
    check._link_facts([("body", "see https://" + ideographs * 15)])
    assert time.monotonic() - started < 1.0


@pytest.mark.asyncio
async def test_a_recipient_nested_hundreds_deep_still_gets_its_look_alike_and_first_time_notes(
    world,
):
    # Batch-2 check: email.utils recursed once per nested comment or ":" group, so such a
    # recipient raised RecursionError: a send lost its look-alike and first-time notes for
    # "could not read its sent-to history in time", and a reply said "reading it took too long".
    nested = "(" * 1200 + ")" * 1200
    for to in ("payroll@northwnd.example " + nested, ":" * 1500 + "payroll@northwnd.example"):
        verdict = await world.run(SEND, {**MAIL, "to": to})
        assert note_of(verdict, "recipient_lookalike") == (
            "high",
            "payroll@northwnd.example looks like northwind.example but is a different address.",
        )
        assert note_of(verdict, "recipient_first_time")[0] == "warn"
        assert "recipient_history_not_checked" not in kinds(verdict)
    world.executor.answers["get_message_security"] = facts_answer(
        reply_to=["pay@vendor-billing.example " + nested]
    )
    replied = await world.run(REPLY, {"message_id": "m1", "body": "Thanks"})
    assert note_of(replied, "recipients_resolved") == (
        "info",
        "This reply goes to: pay@vendor-billing.example.",
    )
    assert note_of(replied, "recipient_first_time")[0] == "warn"
    assert "recipients_not_checked" not in kinds(replied)


# -- the contract -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_check_has_its_final_names_fits_slot_four_and_never_raises_on_odd_arguments(
    world,
):
    check = world.check()
    assert (check.name, check.policy) == ("outbound", "outbound_rule")
    assert check.stages == frozenset({"turn", "approve", "execute"})
    assert check.timeout_s == 9.0
    assert standard_pipeline(outbound=check).names == ("outbound",)
    assert CHECK_ORDER.index("outbound") == 3
    # An unknown tool: nothing to check.
    assert check.applies_to(world.call("nope.tool", {})) is False
    # Odd shapes: never a crash.
    for arguments in ({"to": None, "body": 7}, {"to": {"x": 1}, "body": ["a", {"b": "c"}]}, {}):
        verdict = await world.run(SEND, arguments)
        assert isinstance(verdict, (Note, type(ALLOW)))
    # Arguments nested past any real tool's shape are refused (the floor cannot clean them).
    deep: Any = "x"
    for _ in range(100):
        deep = {"k": deep}
    refused = await world.run("memory.remember", {"content": deep})
    assert isinstance(refused, Refuse) and refused.policy == OUTBOUND_RULE_POLICY


@pytest.mark.asyncio
async def test_argument_names_that_hide_characters_are_cleaned_and_a_clash_is_refused(world):
    floor = outbound.OutboundFloor()
    spec = resolve_tool("google_workspace.create_event")
    assert spec is not None
    # A hidden name cannot dodge a declared path: the summary gets the full rules.
    event = {"event_data": {"sum" + TAGS + "mary": "Sync" + ZWSP * 4 + "!", "loca‮tion": "Room 1"}}
    cleaned = floor.clean_call("google_workspace.create_event", spec.spec, event)
    assert cleaned.arguments == {"event_data": {"summary": "Sync!", "location": "Room 1"}}
    assert cleaned.removed == {"tag": 9, "zero_width_run": 4, "bidi": 1}
    # Two names that are the same once cleaned: the floor cannot tell which was meant.
    clash = {"event_data": {"summary": "a", "summary" + TAGS: "b"}}
    with pytest.raises(ValueError):
        floor.clean_call("google_workspace.create_event", spec.spec, clash)
    refused = await world.run("google_workspace.create_event", clash)
    assert isinstance(refused, Refuse) and refused.rule == outbound.UNCHECKABLE_RULE
    # Reserved "_" names of a connector call are left alone (binds set them);
    # an MCP call has none, so its "_" names are cleaned like any other.
    bound = floor.clean_call(SEND, resolve_tool(SEND).spec, {**MAIL, "_bind": "x" + TAGS})  # type: ignore[union-attr]
    assert bound.arguments["_bind"] == "x" + TAGS
    mcp = floor.clean_call("mcp.notes.save", None, {"_meta": "x" + TAGS})
    assert mcp.arguments == {"_meta": "x"}
    # A recipient argument whose own name hides characters is still a recipient:
    # its value is refused when it hides characters, and noted when it does not.
    send_spec = resolve_tool(SEND).spec  # type: ignore[union-attr]
    renamed = {**MAIL, "to" + TAGS: "ann" + ZWSP + "@acme.example"}
    del renamed["to"]
    assert floor.clean_call(SEND, send_spec, renamed).refusal is not None
    assert isinstance(await world.run(SEND, renamed), Refuse)
    plain = {"to" + TAGS: "evil@exfil.example", "subject": "Hi", "body": "Hello"}
    noted = await world.run(SEND, plain)
    assert note_of(noted, "recipient_first_time")[1] == (
        "First time Crawler sends to anyone at exfil.example (evil@exfil.example)."
    )
    assert "hidden_characters_removed" in kinds(noted)


@pytest.mark.asyncio
async def test_a_stub_less_wiring_with_no_collaborators_still_answers(world):
    """main.py could lose a collaborator; the check says what it could not check."""
    bare = OutboundCheck(executor=None, known=None, org_domains=None, users=None)
    verdict = await bare.check(world.call(SEND, MAIL))
    assert "recipient_history_not_checked" in kinds(verdict)
    replied = await bare.check(world.call(REPLY, {"message_id": "m1", "body": "x"}))
    assert "recipients_not_checked" in kinds(replied)
