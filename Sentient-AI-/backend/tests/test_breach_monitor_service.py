"""Tests for the breach monitor's sweeper (services/notifications/breach_monitor.py),
its store (services/breach/store.py, the seen list) and its texts
(services/breach/messages.py): they prove that nothing is looked up while the
switch is off or unreadable or no key is configured; that every active admin
gets a sign-in row and nobody else does; that the first answer is a baseline
with one summary and later answers alert only breaches never seen before, once;
that an alert names at most five breaches, never a sensitive one, and is
defanged; that an undelivered alert keeps the finding new for the web tab; that
the unique index, not the diff, decides what is new when checks race; that a
refused key holds every address for a day and tells each owner once, a rate
limit retries in an hour without counting, and failures back off hourly
doubling until the fifth stops the address with one message; that unreadable
and paused addresses are never sent; that a changed sign-in email is resealed
and baselined again and demoted accounts lose their rows; that the gate is
re-read before every lookup; that Check now answers inline without a channel
message and refuses paused, just-checked and paced cases; that kick is single
flight; that the owner's edits keep their limits; and that audit rows and logs
carry ids, counts and codes only. Also (checker findings): that a 429's
retry-after hold never turns into a counted "timeout"; that a stopped or paused
address's note never promises a retry nothing will make; that a refused key
holds and tells only active owners, and on a Check now tells the other owners;
and that a kick releases key holds after the running sweep, never loses a
change that arrives meanwhile, and ignores a refusal of a key already replaced.

Why it exists: the sweeper sends the owners' email addresses to a third party
and messages them with nobody watching; each rule here is what keeps it from
sending without consent, alerting twice, spamming, or leaking an address or
the key. In-memory SQLite, a scripted HIBP, a fake clock and an outbox; no
network, no model, no Telegram.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

import httpx
import pytest
from sqlalchemy import select, update
from structlog.testing import capture_logs

import core.network_security as netsec
from core.config import settings
from models.audit import AuditLog
from models.breach_watch import BreachWatchAddress, BreachWatchFinding
from models.user import User
from services.breach import store as store_module
from services.breach.addresses import AddressRejected, address_digest
from services.breach.hibp import (
    AddressRefused,
    BadAnswer,
    Breach,
    HibpClient,
    KeyRefused,
    Pacer,
    PolicyRefused,
    RateLimited,
    Unavailable,
)
from services.breach.messages import (
    ATTRIBUTION,
    FAILURE_SENTENCES,
    MAX_LISTED,
    baseline_message,
    checked_note,
    failure_sentence,
    key_refused_message,
    new_breaches_message,
    not_checked_note,
    retry_sentence,
    stopped_message,
)
from services.breach.store import (
    CHECK_EVERY,
    MAX_FINDINGS_PER_ADDRESS,
    BreachStore,
    CheckTooSoon,
    Conflict,
    LimitReached,
    NotFound,
    export_for_user,
    unseen,
)
from services.notifications import breach_monitor as monitor
from services.notifications.breach_monitor import (
    CHECK_NOW_COOLDOWN,
    ERROR_LIMIT,
    HOUSEKEEP_EVERY,
    KEY_REFUSED_RETRY,
    LEASE,
    RATE_LIMITED_RETRY,
    BreachMonitorService,
    BreachUnavailable,
)
from tests.conftest import make_user

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
KEY = "0123456789abcdef" * 2  # built, never a literal key (scaffold C6)
NEW_KEY = "fedcba9876543210" * 2  # the key the owner saves instead
OWNER = "kash@example.com"
PUBLIC_IP = "203.0.113.10"  # TEST-NET-3; check_ssrf is stubbed where the real client runs


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class Outbox:
    def __init__(self, answer: Any = True) -> None:
        self.sent: list[tuple[str, str]] = []
        self.answer = answer

    async def send(self, user_id: str, text: str) -> bool:
        self.sent.append((user_id, text))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def texts(self, user_id: Optional[uuid.UUID] = None) -> list[str]:
        return [text for uid, text in self.sent if user_id is None or uid == str(user_id)]


class FakePacer:
    def __init__(self) -> None:
        self.estimate = 0.0

    def wait_estimate(self) -> float:
        return self.estimate


class FakeHibp:
    """breaches_for scripted per address: a list of Breach, an exception, or a queue of them
    (the last one repeats). Every call is recorded with the key it carried."""

    def __init__(self) -> None:
        self.answers: dict[str, list[Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self.deadlines: list[Optional[float]] = []
        self.pacer = FakePacer()
        self.before: Optional[Any] = None

    def script(self, address: str, *answers: Any) -> None:
        self.answers[address] = list(answers)

    async def breaches_for(
        self, address: str, api_key: str, *, deadline_s: Optional[float] = None
    ) -> list[Breach]:
        self.calls.append((address, api_key))
        self.deadlines.append(deadline_s)
        if self.before is not None:
            # The hook stands for HIBP's own time to answer, so the deadline covers it (as the
            # real client's answer budget does).
            if deadline_s is None:
                await self.before(address)
            else:
                await asyncio.wait_for(self.before(address), deadline_s)
        queue = self.answers.get(address, [[]])
        answer = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(answer, BaseException):
            raise answer
        return list(answer)

    def addresses(self) -> list[str]:
        return [address for address, _ in self.calls]


def breach(
    name: str,
    *,
    title: Optional[str] = None,
    domain: Optional[str] = None,
    when: Optional[date] = date(2026, 8, 30),
    sensitive: bool = False,
    classes: tuple[str, ...] = ("Email addresses", "Passwords"),
) -> Breach:
    return Breach(
        name=name,
        title=title or name,
        domain=domain if domain is not None else f"{name.lower()}.com",
        breach_date=when,
        added_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
        pwn_count=1000,
        data_classes=classes,
        verified=True,
        sensitive=sensitive,
        fabricated=False,
        spam_list=False,
    )


class Harness:
    """A service over the test database with switchable gate and key."""

    def __init__(
        self, session_factory, *, clock: Optional[Clock] = None, outbox: Optional[Outbox] = None
    ):
        self.session_factory = session_factory
        self.clock = clock or Clock()
        self.outbox = outbox or Outbox()
        self.hibp = FakeHibp()
        self.gate: Any = True
        self.gate_reads = 0
        self.key: Any = KEY
        self.service = self.make_service()

    def make_service(self) -> BreachMonitorService:
        return BreachMonitorService(
            self.session_factory,
            api_key=self.api_key,
            send=self.outbox.send,
            enabled=self.enabled,
            client=self.hibp,  # type: ignore[arg-type]
            clock=self.clock,
        )

    async def enabled(self) -> bool:
        self.gate_reads += 1
        if isinstance(self.gate, Exception):
            raise self.gate
        return self.gate

    async def api_key(self) -> Optional[str]:
        if isinstance(self.key, Exception):
            raise self.key
        return self.key

    @property
    def store(self) -> BreachStore:
        return self.service.store


async def make_owner(
    session_factory, email: str = OWNER, *, admin: bool = True, active: bool = True
) -> User:
    user, _ = await make_user(session_factory, email=email)
    async with session_factory() as session:
        await session.execute(
            update(User).where(User.id == user.id).values(is_admin=admin, is_active=active)
        )
        await session.commit()
    return user


async def address_rows(
    session_factory, user_id: Optional[uuid.UUID] = None
) -> list[BreachWatchAddress]:
    async with session_factory() as session:
        stmt = select(BreachWatchAddress).order_by(BreachWatchAddress.created_at)
        if user_id is not None:
            stmt = stmt.where(BreachWatchAddress.user_id == user_id)
        return list((await session.execute(stmt)).scalars())


async def finding_rows(
    session_factory, user_id: Optional[uuid.UUID] = None
) -> list[BreachWatchFinding]:
    async with session_factory() as session:
        stmt = select(BreachWatchFinding).order_by(BreachWatchFinding.breach_name)
        if user_id is not None:
            stmt = stmt.where(BreachWatchFinding.user_id == user_id)
        return list((await session.execute(stmt)).scalars())


async def audit_rows(session_factory, user_id: Optional[uuid.UUID] = None) -> list[AuditLog]:
    async with session_factory() as session:
        stmt = (
            select(AuditLog)
            .where(AuditLog.connector_name == "breach_monitor")
            .order_by(AuditLog.timestamp, AuditLog.seq)
        )
        if user_id is not None:
            stmt = stmt.where(AuditLog.user_id == user_id)
        return list((await session.execute(stmt)).scalars())


def aware(moment: Optional[datetime]) -> Optional[datetime]:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def new_encryption_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")


class ScaledTime:
    """A pacer clock whose sleeps also take real loop time, scaled down: the pacer believes it
    waited *seconds*, the event loop sees seconds / scale go by (so a 60 s hold lands on the
    clock asyncio.wait_for measures without a real minute-long wait)."""

    def __init__(self, scale: float) -> None:
        self.now = 1000.0
        self.scale = scale
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 6))
        self.now += seconds
        await asyncio.sleep(seconds / self.scale)


def hold_first_lookup(h: Harness) -> tuple[asyncio.Event, asyncio.Event]:
    """The first lookup waits (``entered`` set) until ``release`` is set; later ones go."""
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hold(address: str) -> None:
        if not release.is_set():
            entered.set()
            await release.wait()

    h.hibp.before = hold
    return entered, release


async def stop_row(session_factory, address_id: uuid.UUID) -> None:
    """The row as five failed checks in a row left it: status "error"."""
    async with session_factory() as session:
        await session.execute(
            update(BreachWatchAddress)
            .where(BreachWatchAddress.id == address_id)
            .values(status="error", consecutive_errors=ERROR_LIMIT, last_error_code="unavailable")
        )
        await session.commit()


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nothing_is_looked_up_while_the_switch_is_off_or_unreadable(session_factory):
    await make_owner(session_factory)
    h = Harness(session_factory)
    for gate in (False, None, "yes", RuntimeError("report unreadable")):
        h.gate = gate
        assert await h.service.sweep_once() == 0
    assert h.hibp.calls == []
    assert h.outbox.sent == []
    # Not even housekeeping ran: no rows were made while off.
    assert await address_rows(session_factory) == []


@pytest.mark.asyncio
async def test_nothing_is_sent_without_a_key_even_when_the_gate_is_open(session_factory):
    await make_owner(session_factory)
    h = Harness(session_factory)
    for key in (None, "", RuntimeError("key store unreadable")):
        h.key = key
        assert await h.service.sweep_once() == 0
    assert h.hibp.calls == []
    assert h.outbox.sent == []


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_active_admin_gets_a_sign_in_row_and_standard_users_never_do(session_factory):
    first = await make_owner(session_factory, "kash@example.com")
    second = await make_owner(session_factory, "second.owner@example.org")
    await make_owner(session_factory, "standard@example.com", admin=False)
    await make_owner(session_factory, "asleep@example.com", active=False)
    h = Harness(session_factory)

    assert await h.service.sweep_once() == 2

    rows = await address_rows(session_factory)
    assert sorted((row.user_id, row.source) for row in rows) == sorted(
        [(first.id, "account"), (second.id, "account")]
    )
    assert sorted(h.hibp.addresses()) == ["kash@example.com", "second.owner@example.org"]
    assert all(key == KEY for _, key in h.hibp.calls)
    # Stored sealed and by digest, never in plain text.
    for row in rows:
        assert b"example" not in row.address_sealed
        assert len(row.address_digest) == 64


@pytest.mark.asyncio
async def test_a_sign_in_address_that_is_not_a_mailbox_is_not_watched_and_the_overview_says_why(
    session_factory,
):
    owner = await make_owner(session_factory, "admin@localhost")
    h = Harness(session_factory)

    note = await h.store.ensure_account_row(owner.id)

    assert note == (
        "Your sign-in address (admin@localhost) is not a mailbox address Have I Been Pwned can "
        "look up. Add the addresses you use below."
    )
    assert await address_rows(session_factory) == []
    assert await h.service.sweep_once() == 0
    assert h.hibp.calls == []
    # A standard user never gets a row, and the call says nothing.
    standard = await make_owner(session_factory, "standard@example.com", admin=False)
    assert await h.store.ensure_account_row(standard.id) is None
    assert await address_rows(session_factory, standard.id) == []


# ---------------------------------------------------------------------------
# Baseline, new breaches, messages
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_first_answer_records_every_breach_as_baseline_and_sends_one_summary(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(
        OWNER,
        [
            breach("Adobe", when=date(2013, 10, 4)),
            breach(
                "ExampleShop",
                title="Example Shop",
                domain="example-shop.com",
                when=date(2026, 8, 30),
            ),
            breach("Linked", when=date(2016, 5, 17)),
        ],
    )

    assert await h.service.sweep_once() == 1

    findings = await finding_rows(session_factory, owner.id)
    assert [f.breach_name for f in findings] == ["Adobe", "ExampleShop", "Linked"]
    assert all(f.baseline for f in findings)
    assert all(aware(f.alerted_at) == T0 for f in findings)
    (text,) = h.outbox.texts(owner.id)
    assert text.startswith("\U0001f6e1️ Breach monitoring is on for k•••＠example․com.")
    assert "It appears in 3 known breaches (the newest: Example Shop, 2026-08-30)." in text
    assert text.endswith(ATTRIBUTION)
    (row,) = await address_rows(session_factory, owner.id)
    assert aware(row.baseline_at) == T0 and aware(row.last_checked_at) == T0
    assert aware(row.next_check_at) == T0 + CHECK_EVERY
    assert row.breach_count == 3 and row.consecutive_errors == 0

    # An address in no breach gets the "not in any breach" summary.
    other = await make_owner(session_factory, "clean@example.org")
    h.hibp.script("clean@example.org", [])
    await h.store.ensure_account_row(other.id)
    assert await h.service.sweep_once() == 1
    (clean,) = h.outbox.texts(other.id)
    assert "It is not in any breach Have I Been Pwned knows of." in clean


@pytest.mark.asyncio
async def test_a_later_answer_alerts_only_the_new_breach_once_and_never_again(session_factory):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    old = [breach("Adobe", when=date(2013, 10, 4))]
    h.hibp.script(
        OWNER, old, old + [breach("ExampleShop", title="Example Shop", domain="example-shop.com")]
    )
    await h.service.sweep_once()
    h.outbox.sent.clear()

    # Not due yet: nothing is asked.
    h.clock.advance(timedelta(days=6))
    assert await h.service.sweep_once() == 0
    h.clock.advance(timedelta(days=1))
    assert await h.service.sweep_once() == 1
    (text,) = h.outbox.texts(owner.id)
    assert text.splitlines()[0] == "\U0001f513 New data breach: k•••＠example․com"
    assert "in 1 new breach:" in text
    assert "Example Shop (example-shop․com), breached 2026-08-30." in text
    assert "Adobe" not in text

    h.outbox.sent.clear()
    h.clock.advance(CHECK_EVERY)
    assert await h.service.sweep_once() == 1
    assert h.outbox.sent == []
    findings = await finding_rows(session_factory, owner.id)
    assert [(f.breach_name, f.baseline) for f in findings] == [
        ("Adobe", True),
        ("ExampleShop", False),
    ]


def test_an_alert_lists_at_most_five_breaches_and_never_names_a_sensitive_one():
    breaches = [breach(f"Shop{i}", title=f"Shop {i}") for i in range(7)]
    breaches.insert(
        1, breach("SecretSite", title="Secret Site", domain="secret.example", sensitive=True)
    )
    text = new_breaches_message("k•••@example.com", breaches)
    lines = text.splitlines()
    assert lines[1] == "Have I Been Pwned lists this address in 8 new breaches:"
    listed = [line for line in lines if line.startswith("• ")]
    assert len(listed) == MAX_LISTED == 5
    assert "• A breach marked sensitive (see the Security page)" in listed
    assert "Secret" not in text and "secret" not in text
    assert "…and 3 more on the Security page." in lines
    assert lines[-1] == (
        "Details: Crawler → Security → Breach monitor. Source: Have I Been Pwned "
        "(haveibeenpwned.com)."
    )
    # The baseline summary never names a sensitive breach as the newest either.
    summary = baseline_message(
        "k•••@example.com",
        [
            breach("Old", when=date(2010, 1, 1)),
            breach("Hidden", when=date(2026, 9, 1), sensitive=True),
        ],
    )
    assert "(the newest: Old, 2010-01-01)" in summary and "Hidden" not in summary
    only_sensitive = baseline_message("k•••@example.com", [breach("Hidden", sensitive=True)])
    assert "It appears in 1 known breach." in only_sensitive and "Hidden" not in only_sensitive


def test_alert_text_is_defanged_cleaned_and_capped_so_the_attribution_is_the_only_link():
    hostile = breach(
        "Evil",
        title="Visit https://evil.example/login now\nor @evilbot /start",
        domain="evil.example",
        classes=tuple(f"Class {i}/x" for i in range(9)) + ("E" * 60,),
    )
    text = new_breaches_message("k•••@example.com", [hostile])
    body = text.replace(ATTRIBUTION, "")
    assert "https://" not in body and "evil.example" not in body
    assert "@" not in body and "/" not in body
    assert "\n or" not in text  # the title stayed one line
    line = next(line for line in text.splitlines() if line.startswith("• "))
    assert line.count(",") <= 6 + 1  # at most 6 data classes (plus the date's comma)
    assert "class 6" not in line and "e" * 41 not in line


@pytest.mark.asyncio
async def test_an_undelivered_alert_keeps_the_finding_new_for_the_web_tab(session_factory):
    owner = await make_owner(session_factory)
    for answer in (False, RuntimeError("chat down")):
        h = Harness(session_factory, outbox=Outbox(answer=answer))
        h.hibp.script(OWNER, [breach("Adobe")])
        await h.service.sweep_once()
        findings = await finding_rows(session_factory, owner.id)
        assert findings and all(f.alerted_at is None for f in findings)
        view = await h.store.overview(owner.id)
        assert view["addresses"][0]["new_count"] == len(findings)
        assert all(f["acknowledged_at"] is None for f in view["findings"])
        # Not retried on the next sweep (a broken channel must not become a storm).
        sent_before = len(h.outbox.sent)
        await h.service.sweep_once()
        assert len(h.outbox.sent) == sent_before
        # Start the next round from a fresh, due address.
        async with session_factory() as session:
            await session.execute(BreachWatchFinding.__table__.delete())
            await session.execute(
                update(BreachWatchAddress).values(
                    baseline_at=None, last_checked_at=None, next_check_at=T0
                )
            )
            await session.commit()


@pytest.mark.asyncio
async def test_a_concurrent_check_of_the_same_address_alerts_each_breach_once(
    session_factory, monkeypatch
):
    owner = await make_owner(session_factory)
    store = BreachStore(session_factory, clock=Clock())
    await store.ensure_account_row(owner.id)
    (claim,) = await store.claim_due(T0, 10, LEASE)
    # A second worker racing the claim gets nothing.
    assert await store.claim_due(T0, 10, LEASE) == []

    answer = [breach("Adobe"), breach("ExampleShop")]
    first = await store.record_result(claim, answer, T0)
    assert [b.name for b in first.new] == ["Adobe", "ExampleShop"] and first.baseline

    # A check that read the seen list before the first one inserted (the diff sees nothing):
    # the unique index refuses both, so this call reports nothing new.
    monkeypatch.setattr(store_module, "unseen", lambda breaches, seen: list(breaches))
    second = await store.record_result(
        claim, answer + [breach("Linked")], T0 + timedelta(seconds=1)
    )
    assert [b.name for b in second.new] == ["Linked"]
    assert set(first.new_ids).isdisjoint(second.new_ids)
    assert second.total == 3
    assert [f.breach_name for f in await finding_rows(session_factory, owner.id)] == [
        "Adobe",
        "ExampleShop",
        "Linked",
    ]


def test_unseen_is_the_diff_against_the_seen_list_in_answer_order():
    answer = [breach("C"), breach("A"), breach("B"), breach("A")]
    assert [b.name for b in unseen(answer, {"B"})] == ["C", "A"]
    assert unseen(answer, {"A", "B", "C"}) == []
    assert [b.name for b in unseen(answer, [])] == ["C", "A", "B"]


@pytest.mark.asyncio
async def test_the_seen_list_is_capped_per_address_and_answers_past_it_are_not_stored(
    session_factory, monkeypatch
):
    owner = await make_owner(session_factory)
    monkeypatch.setattr(store_module, "MAX_FINDINGS_PER_ADDRESS", 3)
    store = BreachStore(session_factory, clock=Clock())
    await store.ensure_account_row(owner.id)
    (claim,) = await store.claim_due(T0, 10, LEASE)
    with capture_logs() as logs:
        recorded = await store.record_result(claim, [breach(f"B{i}") for i in range(5)], T0)
    assert len(recorded.new) == 3 and recorded.total == 3
    capped = [entry for entry in logs if entry["event"] == "breach_findings_capped"]
    assert capped and capped[0]["dropped"] == 2
    assert MAX_FINDINGS_PER_ADDRESS == 1000


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_refused_key_holds_every_address_for_a_day_messages_each_owner_once_and_stops_the_sweep(
    session_factory,
):
    first = await make_owner(session_factory, "kash@example.com")
    second = await make_owner(session_factory, "second.owner@example.org")
    h = Harness(session_factory)
    h.hibp.script("kash@example.com", KeyRefused("refused"))
    h.hibp.script("second.owner@example.org", KeyRefused("refused"))

    assert await h.service.sweep_once() == 1
    assert len(h.hibp.calls) == 1  # stopped at the first refusal

    assert h.outbox.texts(first.id) == [key_refused_message()]
    assert h.outbox.texts(second.id) == [key_refused_message()]
    assert key_refused_message() == (
        "⚠️ Breach checks paused: Have I Been Pwned refused the API key. Update it in "
        "Crawler → Security → Service keys; checks start again on their own after that."
    )
    for row in await address_rows(session_factory):
        assert row.last_error_code == "key_refused"
        assert aware(row.next_check_at) == T0 + KEY_REFUSED_RETRY
        assert row.consecutive_errors == 0 and row.status == "active"
    # Nothing is due for a day.
    h.clock.advance(timedelta(hours=23))
    assert await h.service.sweep_once() == 0


@pytest.mark.asyncio
async def test_saving_a_key_releases_the_hold_and_a_still_bad_key_does_not_message_again(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(OWNER, KeyRefused("refused"))
    await h.service.sweep_once()
    assert len(h.outbox.texts(owner.id)) == 1

    # The key "changed" but is still bad: the hold is released, the lookup refused, no message.
    task = h.service.kick()
    assert task is not None
    assert await task == 1
    assert len(h.hibp.calls) == 2
    assert len(h.outbox.texts(owner.id)) == 1

    # A good key: released again, answered, the code cleared, one baseline summary.
    h.hibp.script(OWNER, [breach("Adobe")])
    task = h.service.kick()
    assert task is not None and await task == 1
    (row,) = await address_rows(session_factory, owner.id)
    assert row.last_error_code is None and aware(row.next_check_at) == T0 + CHECK_EVERY
    assert "Breach monitoring is on" in h.outbox.texts(owner.id)[-1]


@pytest.mark.asyncio
async def test_a_refused_key_holds_and_tells_only_active_owners_never_a_deactivated_admin_or_a_demoted_account(
    session_factory,
):
    owner = await make_owner(session_factory, "kash@example.com")
    asleep = await make_owner(session_factory, "asleep@example.org")
    demoted = await make_owner(session_factory, "demoted@example.net")
    store = BreachStore(session_factory, clock=Clock())
    for user in (owner, asleep, demoted):
        await store.ensure_account_row(user.id)
    async with session_factory() as session:
        # Housekeeping keeps a deactivated admin's rows on purpose, and a demoted account's
        # rows survive until the next daily housekeeping.
        await session.execute(update(User).where(User.id == asleep.id).values(is_active=False))
        await session.execute(update(User).where(User.id == demoted.id).values(is_admin=False))
        await session.commit()

    # The store holds and returns only the rows claim_due would look up.
    assert await store.defer_for_key(T0, T0 + KEY_REFUSED_RETRY) == [owner.id]
    rows = {row.user_id: row for row in await address_rows(session_factory)}
    assert rows[owner.id].last_error_code == "key_refused"
    for other in (asleep, demoted):
        assert rows[other.id].last_error_code is None
        assert aware(rows[other.id].next_check_at) == T0

    # The sweeper's refusal messages the active owner only.
    async with session_factory() as session:
        await session.execute(
            update(BreachWatchAddress).values(last_error_code=None, next_check_at=T0)
        )
        await session.commit()
    h = Harness(session_factory)
    h.hibp.script(OWNER, KeyRefused("refused"))
    assert await h.service.sweep_once() == 1
    assert h.outbox.texts(owner.id) == [key_refused_message()]
    assert h.outbox.texts(asleep.id) == [] and h.outbox.texts(demoted.id) == []
    assert len(h.outbox.sent) == 1


@pytest.mark.asyncio
async def test_a_key_refused_on_an_owners_check_now_tells_every_other_owner_once_and_not_the_one_who_pressed_it(
    session_factory,
):
    first = await make_owner(session_factory, "kash@example.com")
    second = await make_owner(session_factory, "second.owner@example.org")
    h = Harness(session_factory)
    for user in (first, second):
        await h.store.ensure_account_row(user.id)
    h.hibp.script("kash@example.com", KeyRefused("refused"))
    h.hibp.script("second.owner@example.org", KeyRefused("refused"))
    (pressed,) = await address_rows(session_factory, first.id)

    report = await h.service.check_now(first.id, pressed.id)

    # The owner who pressed Check now reads it in the answer; the other owner, whose rows are
    # held too, gets the one message (it used to get none, and later sweeps took it as told).
    assert report.outcome == "not_checked"
    assert report.note == f"Not checked: {FAILURE_SENTENCES['key_refused']}"
    assert h.outbox.texts(first.id) == []
    assert h.outbox.texts(second.id) == [key_refused_message()]
    for row in await address_rows(session_factory):
        assert row.last_error_code == "key_refused"
        assert aware(row.next_check_at) == T0 + KEY_REFUSED_RETRY

    # Both now count as told: a sweep with the still-bad key messages nobody again.
    task = h.service.kick()
    assert task is not None and await task == 1
    assert h.outbox.texts(first.id) == []
    assert h.outbox.texts(second.id) == [key_refused_message()]


@pytest.mark.asyncio
async def test_a_rate_limited_lookup_is_retried_in_an_hour_without_counting_as_a_failure(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    await h.store.add(owner.id, "me.alt@example.org")
    h.hibp.script(OWNER, RateLimited(retry_after_s=120))
    h.hibp.script("me.alt@example.org", RateLimited(retry_after_s=120))

    assert await h.service.sweep_once() == 1
    (asked,) = h.hibp.addresses()  # the sweep stopped after the first
    rows = await address_rows(session_factory, owner.id)
    (limited,) = [row for row in rows if row.last_error_code == "rate_limited"]
    (other,) = [row for row in rows if row.id != limited.id]
    assert limited.consecutive_errors == 0 and limited.status == "active"
    assert aware(limited.next_check_at) == T0 + RATE_LIMITED_RETRY
    # The other leased row comes back after the lease, untouched.
    assert aware(other.next_check_at) == T0 + LEASE
    assert other.last_error_code is None and other.status == "active"
    assert h.outbox.sent == []
    view = await h.store.overview(owner.id)
    shown = next(a for a in view["addresses"] if a["address"] == asked)
    assert shown["last_error"] == (
        "Have I Been Pwned asked Crawler to slow down. Crawler tries again in an hour."
    )


@pytest.mark.asyncio
async def test_failures_back_off_hourly_doubling_and_the_fifth_stops_the_address_with_one_message(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(
        OWNER,
        Unavailable("down"),
        BadAnswer("bad"),
        PolicyRefused("no"),
        Unavailable("down"),
        Unavailable("down"),
    )
    expected = [timedelta(hours=1), timedelta(hours=2), timedelta(hours=4), timedelta(hours=8)]
    for failures, delay in enumerate(expected, start=1):
        assert await h.service.sweep_once() == 1
        (row,) = await address_rows(session_factory, owner.id)
        assert row.consecutive_errors == failures
        assert aware(row.next_check_at) == h.clock.now + delay
        assert row.status == "active"
        assert row.baseline_at is None and row.breach_count == 0  # never "no breaches"
        h.clock.now = aware(row.next_check_at)
    assert h.outbox.sent == []

    assert await h.service.sweep_once() == 1
    (row,) = await address_rows(session_factory, owner.id)
    assert row.status == "error" and row.consecutive_errors == ERROR_LIMIT
    assert row.last_error_code == "unavailable"
    (text,) = h.outbox.texts(owner.id)
    assert text == (
        "⚠️ Stopped checking k•••＠example․com for breaches: the last 5 "
        "checks failed (Have I Been Pwned could not be reached). Open Crawler → Security "
        "→ Breach monitor and press Check now to try again."
    )
    # A stopped address is not looked up again on its own.
    h.clock.advance(timedelta(days=30))
    assert await h.service.sweep_once() == 0
    assert len(h.hibp.calls) == 5


@pytest.mark.asyncio
async def test_a_timeout_counts_as_a_failure_and_stops_the_sweep(session_factory, monkeypatch):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    monkeypatch.setattr(monitor, "CHECK_DEADLINE_SECONDS", 0.01)

    async def slow(address: str) -> None:
        await asyncio.sleep(1)

    h.hibp.before = slow
    assert await h.service.sweep_once() == 1
    (row,) = await address_rows(session_factory, owner.id)
    assert row.last_error_code == "timeout" and row.consecutive_errors == 1
    # The service hands the client its deadline (the client measures it, see below).
    assert h.hibp.deadlines == [0.01]


@pytest.mark.asyncio
async def test_a_429_hold_longer_than_the_lookup_deadline_is_waited_out_and_never_recorded_as_a_counted_timeout(
    session_factory, monkeypatch
):
    # HIBP answers 429 with retry-after 59 (it may say up to 60), then the answer. The pacer's
    # hold (60 s; here 1.5 s of loop time) is longer than the lookup deadline (45 s; here 1 s).
    # It used to sit inside the deadline: the lookup ended as a counted "timeout" with an
    # hourly back-off, and five of those stopped the address as "did not answer in time".
    monkeypatch.setattr(
        netsec,
        "check_ssrf",
        lambda url: netsec.SSRFCheckResult(
            safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,)
        ),
    )
    monkeypatch.setattr(monitor, "CHECK_DEADLINE_SECONDS", 1.0)
    answers = [
        httpx.Response(429, headers={"retry-after": "59"}),
        httpx.Response(200, json=[{"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com"}]),
    ]
    requests: list[httpx.Request] = []

    def hibp_api(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return answers.pop(0)

    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    clock = ScaledTime(scale=40)
    h.service.client = HibpClient(
        transport=httpx.MockTransport(hibp_api), pacer=Pacer(clock=clock.clock, sleep=clock.sleep)
    )
    await h.store.ensure_account_row(owner.id)
    added = await h.store.add(owner.id, "me.alt@example.org")

    report = await h.service.check_now(owner.id, uuid.UUID(added["id"]))

    assert report.outcome == "checked", report.note
    assert report.note == "Found in 1 new breach."
    assert len(requests) == 2 and clock.sleeps == [60.0]
    row = next(r for r in await address_rows(session_factory, owner.id) if r.source == "added")
    assert row.consecutive_errors == 0 and row.last_error_code is None
    assert [a.request_data.get("error_code") for a in await audit_rows(session_factory)] == [
        None,
        None,
    ]  # breach_checked and breach_found; no breach_check_failed at all


@pytest.mark.asyncio
async def test_check_now_on_a_stopped_address_that_fails_again_promises_no_retry_because_none_will_come(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    added = await h.store.add(owner.id, "me.alt@example.org")
    address_id = uuid.UUID(added["id"])
    await stop_row(session_factory, address_id)
    h.hibp.script("me.alt@example.org", Unavailable("down"), RateLimited(retry_after_s=30))

    failed = await h.service.check_now(owner.id, address_id)

    # It used to read "... Crawler tries again in 24 hours." for a row nothing picks up.
    assert failed.outcome == "not_checked"
    assert failed.note == "Not checked: Have I Been Pwned could not be reached."
    assert failed.address["status"] == "error"
    assert failed.address["last_error"] == "Have I Been Pwned could not be reached."

    # A rate limit on a stopped row drops the fixed sentence's own "tries again in an hour",
    # on the note and on the tab.
    limited = await h.service.check_now(owner.id, address_id)
    assert limited.note == "Not checked: Have I Been Pwned asked Crawler to slow down."
    assert limited.address["status"] == "error"
    assert limited.address["last_error"] == "Have I Been Pwned asked Crawler to slow down."

    # Indeed nothing looks it up on its own, even a month later; only Check now does.
    later = await h.store.claim_due(h.clock.now + timedelta(days=30), 20, LEASE)
    assert address_id not in [claim.id for claim in later]
    assert h.outbox.sent == []


@pytest.mark.asyncio
async def test_check_now_on_an_address_paused_while_its_lookup_was_out_promises_no_retry(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    added = await h.store.add(owner.id, "me.alt@example.org")
    address_id = uuid.UUID(added["id"])

    async def paused_meanwhile(address: str) -> None:
        await h.store.set_paused(owner.id, address_id, True)

    h.hibp.before = paused_meanwhile
    h.hibp.script("me.alt@example.org", Unavailable("down"))

    report = await h.service.check_now(owner.id, address_id)

    assert report.note == "Not checked: Have I Been Pwned could not be reached."
    assert report.address["status"] == "paused"
    (row,) = [r for r in await address_rows(session_factory, owner.id) if r.id == address_id]
    assert row.status == "paused"


def test_a_failure_sentence_for_an_address_not_retried_on_its_own_drops_every_retry_promise():
    for code in FAILURE_SENTENCES:
        sentence = failure_sentence(code, retrying=False)
        assert sentence is not None and "tries again" not in sentence
        note = not_checked_note(code, timedelta(hours=4), retrying=False)
        assert "tries again" not in note and note.startswith("Not checked: ")
    assert failure_sentence("rate_limited", retrying=False) == (
        "Have I Been Pwned asked Crawler to slow down."
    )
    # An active address keeps them.
    assert failure_sentence("rate_limited") == FAILURE_SENTENCES["rate_limited"]
    assert not_checked_note("timeout", timedelta(hours=2)) == (
        "Not checked: Have I Been Pwned did not answer in time. Crawler tries again in 2 hours."
    )


@pytest.mark.asyncio
async def test_an_address_refusal_stops_only_that_address_and_the_sweep_goes_on(session_factory):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    await h.store.add(owner.id, "me.alt@example.org")
    h.hibp.script(OWNER, AddressRefused("no"))
    h.hibp.script("me.alt@example.org", [])

    assert await h.service.sweep_once() == 2
    rows = {row.source: row for row in await address_rows(session_factory, owner.id)}
    assert (
        rows["account"].status == "error" and rows["account"].last_error_code == "address_refused"
    )
    assert rows["added"].status == "active" and rows["added"].baseline_at is not None
    # No "stopped" message for a refusal; only the added address's summary went out.
    assert [text for text in h.outbox.texts(owner.id) if "Stopped" in text] == []


@pytest.mark.asyncio
async def test_an_address_that_no_longer_decrypts_is_never_sent_and_is_marked_unreadable(
    session_factory, monkeypatch
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    await h.store.add(owner.id, "me.alt@example.org")

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", new_encryption_key())
    h.hibp.script(OWNER, [])
    await h.service.sweep_once()

    # The sign-in row resealed itself under the new key; the typed one cannot be read.
    assert "me.alt@example.org" not in h.hibp.addresses()
    rows = {row.source: row for row in await address_rows(session_factory, owner.id)}
    assert rows["added"].status == "error" and rows["added"].last_error_code == "unreadable"
    view = await h.store.overview(owner.id)
    unreadable = next(a for a in view["addresses"] if a["source"] == "added")
    assert unreadable["address"] is None and unreadable["readable"] is False
    assert unreadable["last_error"] == FAILURE_SENTENCES["unreadable"]
    assert [text for text in h.outbox.texts(owner.id) if "Stopped" in text] == []


@pytest.mark.asyncio
async def test_paused_addresses_are_not_looked_up(session_factory):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    added = await h.store.add(owner.id, "me.alt@example.org")
    (account,) = [
        row for row in await address_rows(session_factory, owner.id) if row.source == "account"
    ]
    await h.store.set_paused(owner.id, account.id, True)
    await h.store.set_paused(owner.id, uuid.UUID(added["id"]), True)

    assert await h.service.sweep_once() == 0
    assert h.hibp.calls == []

    resumed = await h.store.set_paused(owner.id, uuid.UUID(added["id"]), False)
    assert resumed["status"] == "active"
    assert await h.service.sweep_once() == 1
    assert h.hibp.addresses() == ["me.alt@example.org"]


@pytest.mark.asyncio
async def test_a_changed_sign_in_email_is_resealed_and_baselined_again(session_factory):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(OWNER, [breach("Adobe")])
    h.hibp.script("new.me@example.net", [breach("Linked")])
    await h.service.sweep_once()
    (before,) = await address_rows(session_factory, owner.id)

    async with session_factory() as session:
        await session.execute(
            update(User).where(User.id == owner.id).values(email="new.me@example.net")
        )
        await session.commit()
    h.clock.advance(HOUSEKEEP_EVERY)
    h.outbox.sent.clear()
    assert await h.service.sweep_once() == 1

    (after,) = await address_rows(session_factory, owner.id)
    assert after.id == before.id and after.source == "account"
    assert after.address_digest == address_digest("new.me@example.net") != before.address_digest
    assert [f.breach_name for f in await finding_rows(session_factory, owner.id)] == ["Linked"]
    (text,) = h.outbox.texts(owner.id)
    assert "Breach monitoring is on for n•••＠example․net." in text


@pytest.mark.asyncio
async def test_rows_of_an_account_that_is_no_longer_an_owner_are_deleted(session_factory):
    owner = await make_owner(session_factory)
    asleep = await make_owner(session_factory, "asleep@example.org")
    h = Harness(session_factory)
    h.hibp.script(OWNER, [breach("Adobe")])
    await h.service.sweep_once()
    await h.store.add(owner.id, "me.alt@example.org")
    async with session_factory() as session:
        await session.execute(update(User).where(User.id == owner.id).values(is_admin=False))
        await session.execute(update(User).where(User.id == asleep.id).values(is_active=False))
        await session.commit()

    assert await h.store.housekeep() == 2
    assert await address_rows(session_factory, owner.id) == []
    assert await finding_rows(session_factory, owner.id) == []
    # An inactive admin is skipped, not deleted.
    assert len(await address_rows(session_factory, asleep.id)) == 1


@pytest.mark.asyncio
async def test_the_gate_is_re_read_before_every_lookup_and_a_switch_turned_off_mid_sweep_stops_it(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    await h.store.add(owner.id, "me.alt@example.org")

    async def turn_off(address: str) -> None:
        h.gate = False

    h.hibp.before = turn_off
    assert await h.service.sweep_once() == 1
    assert len(h.hibp.calls) == 1
    assert h.gate_reads == 2  # before the claim, then before the second lookup

    # A key removed mid-sweep stops it too.
    h.gate = True
    h.clock.advance(LEASE)

    async def remove_key(address: str) -> None:
        h.key = None

    h.hibp.before = remove_key
    calls = len(h.hibp.calls)
    assert await h.service.sweep_once() == 1
    assert len(h.hibp.calls) == calls + 1


# ---------------------------------------------------------------------------
# Check now and kick
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_now_answers_inline_without_a_channel_message_and_marks_the_findings_seen(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    added = await h.store.add(owner.id, "me.alt@example.org")
    h.hibp.script("me.alt@example.org", [breach("Adobe"), breach("ExampleShop")])

    report = await h.service.check_now(owner.id, uuid.UUID(added["id"]))

    assert report.outcome == "checked"
    assert report.note == "Found in 2 new breaches."
    assert report.address["id"] == added["id"] and report.address["breach_count"] == 2
    assert sorted(f["name"] for f in report.new_findings) == ["Adobe", "ExampleShop"]
    assert all(f["alerted_at"] is not None for f in report.new_findings)
    assert h.outbox.sent == []
    assert h.hibp.calls == [("me.alt@example.org", KEY)]

    # A failed Check now is "not checked" with its reason and when Crawler tries again.
    h.hibp.script(OWNER, Unavailable("down"))
    (account,) = [
        row for row in await address_rows(session_factory, owner.id) if row.source == "account"
    ]
    failed = await h.service.check_now(owner.id, account.id)
    assert failed.outcome == "not_checked" and failed.new_findings == []
    assert (
        failed.note
        == "Not checked: Have I Been Pwned could not be reached. Crawler tries again in 1 hour."
    )
    assert failed.address["last_error"] == "Have I Been Pwned could not be reached."
    assert h.outbox.sent == []


@pytest.mark.asyncio
async def test_check_now_refuses_a_paused_address_one_checked_moments_ago_and_when_the_pacer_is_busy(
    session_factory,
):
    owner = await make_owner(session_factory)
    other = await make_owner(session_factory, "other.owner@example.org")
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    added = await h.store.add(owner.id, "me.alt@example.org")
    address_id = uuid.UUID(added["id"])

    await h.service.check_now(owner.id, address_id)
    h.clock.advance(timedelta(minutes=2))
    with pytest.raises(CheckTooSoon) as soon:
        await h.service.check_now(owner.id, address_id)
    assert soon.value.retry_after_s == 180
    assert str(soon.value) == "Checked moments ago. Try again in 180 seconds."

    h.clock.advance(CHECK_NOW_COOLDOWN)
    h.hibp.pacer.estimate = 40.2
    with pytest.raises(CheckTooSoon) as paced:
        await h.service.check_now(owner.id, address_id)
    assert paced.value.retry_after_s == 41
    assert (
        str(paced.value)
        == "Crawler is pacing lookups to your key's limit. Try again in 41 seconds."
    )
    h.hibp.pacer.estimate = 0.0

    await h.store.set_paused(owner.id, address_id, True)
    with pytest.raises(Conflict) as paused:
        await h.service.check_now(owner.id, address_id)
    assert str(paused.value) == "This address is paused. Resume it first."

    # Another owner's address, or a made-up id, is not found.
    with pytest.raises(NotFound):
        await h.service.check_now(other.id, address_id)
    with pytest.raises(NotFound):
        await h.service.check_now(owner.id, uuid.uuid4())
    assert len(h.hibp.calls) == 1


@pytest.mark.asyncio
async def test_check_now_is_unavailable_while_the_switch_is_off_or_no_key_is_saved(session_factory):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    await h.store.ensure_account_row(owner.id)
    (row,) = await address_rows(session_factory, owner.id)
    h.gate = False
    with pytest.raises(BreachUnavailable) as off:
        await h.service.check_now(owner.id, row.id)
    assert "turned off" in off.value.reason
    h.gate = True
    h.key = None
    with pytest.raises(BreachUnavailable) as no_key:
        await h.service.check_now(owner.id, row.id)
    assert "none is saved yet" in no_key.value.reason
    assert h.hibp.calls == []


@pytest.mark.asyncio
async def test_kick_runs_one_sweep_at_a_time(session_factory):
    await make_owner(session_factory)
    h = Harness(session_factory)
    release = asyncio.Event()

    async def hold(address: str) -> None:
        await release.wait()

    h.hibp.before = hold
    first = h.service.kick()
    assert first is not None
    await asyncio.sleep(0)
    assert h.service.kick() is None  # one already running
    release.set()
    assert await first == 1
    assert len(h.hibp.calls) == 1
    # Done: the next kick runs again (nothing due now).
    again = h.service.kick()
    assert again is not None and await again == 0
    await h.service.stop()


@pytest.mark.asyncio
async def test_a_key_saved_while_a_sweep_is_mid_lookup_is_used_at_once_and_the_old_keys_refusal_holds_and_tells_nothing(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(OWNER, KeyRefused("the old key"), [breach("Adobe")])
    entered, release = hold_first_lookup(h)

    sweep = asyncio.create_task(h.service.sweep_once())
    await asyncio.wait_for(entered.wait(), 10)
    # The owner saves a new key while the loop's lookup with the old one is out; main.py
    # kicks on the capabilities change.
    h.key = NEW_KEY
    kick = h.service.kick()
    assert kick is not None
    release.set()
    assert await asyncio.wait_for(sweep, 10) == 1
    assert await asyncio.wait_for(kick, 10) == 1

    # The old key's 401 held nothing and told nobody (it used to hold every row for a day and
    # send "refused the API key"); the kick's sweep looked the address up with the new key.
    assert h.hibp.calls == [(OWNER, KEY), (OWNER, NEW_KEY)]
    assert key_refused_message() not in h.outbox.texts(owner.id)
    (row,) = await address_rows(session_factory, owner.id)
    assert row.last_error_code is None and row.baseline_at is not None
    assert aware(row.next_check_at) == T0 + CHECK_EVERY
    (text,) = h.outbox.texts(owner.id)
    assert "Breach monitoring is on" in text


@pytest.mark.asyncio
async def test_a_kick_releases_holds_made_by_the_sweep_that_was_running_when_it_was_called(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(OWNER, KeyRefused("refused"), [])
    entered, release = hold_first_lookup(h)

    sweep = asyncio.create_task(h.service.sweep_once())
    await asyncio.wait_for(entered.wait(), 10)
    kick = h.service.kick()  # a capabilities change while the loop's lookup is out
    assert kick is not None
    for _ in range(20):
        await asyncio.sleep(0)  # the kick is now waiting for the sweep lock
    release.set()
    assert await asyncio.wait_for(sweep, 10) == 1
    assert await asyncio.wait_for(kick, 10) == 1

    # The running sweep's refusal held the row and told the owner once; the kick released
    # that hold after the sweep (not before it), so its own sweep looked the address up again.
    assert len(h.hibp.calls) == 2
    texts = h.outbox.texts(owner.id)
    assert texts[0] == key_refused_message() and "Breach monitoring is on" in texts[1]
    (row,) = await address_rows(session_factory, owner.id)
    assert row.last_error_code is None and aware(row.next_check_at) == T0 + CHECK_EVERY


@pytest.mark.asyncio
async def test_a_kick_that_arrives_while_another_kick_runs_is_not_lost_and_releases_the_holds_again(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(OWNER, KeyRefused("refused"), [])
    entered, release = hold_first_lookup(h)

    first = h.service.kick()
    assert first is not None
    await asyncio.wait_for(entered.wait(), 10)
    # A second capabilities change while the first kick's lookup is out: single flight, so no
    # second task, but the running kick goes round once more (it used to drop this one).
    assert h.service.kick() is None
    release.set()
    assert await asyncio.wait_for(first, 10) == 2

    assert len(h.hibp.calls) == 2
    (row,) = await address_rows(session_factory, owner.id)
    assert row.last_error_code is None and row.baseline_at is not None
    await h.service.stop()


@pytest.mark.asyncio
async def test_start_and_stop_run_the_loop_and_cancel_a_running_kick(session_factory):
    await make_owner(session_factory)
    h = Harness(session_factory)
    h.service = BreachMonitorService(
        session_factory,
        api_key=h.api_key,
        send=h.outbox.send,
        enabled=h.enabled,
        client=h.hibp,
        clock=h.clock,
        interval_seconds=3600,  # type: ignore[arg-type]
    )
    blocked = asyncio.Event()

    async def hold(address: str) -> None:
        await blocked.wait()

    h.hibp.before = hold
    await h.service.start()
    kick = h.service.kick()
    await asyncio.sleep(0.05)
    await h.service.stop()
    assert kick is None or kick.done()


# ---------------------------------------------------------------------------
# The owner's edits (store)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adding_refuses_bad_input_duplicates_the_sign_in_address_and_the_eleventh(
    session_factory,
):
    owner = await make_owner(session_factory)
    store = BreachStore(session_factory, clock=Clock())
    await store.ensure_account_row(owner.id)

    added = await store.add(owner.id, "  Me.Alt@Example.org ")
    assert added["address"] == "me.alt@example.org" and added["source"] == "added"
    assert added["hint"] == "m•••@example.org"
    assert added["status"] == "active" and added["next_check_at"] == "2026-10-14T09:00:00Z"
    with pytest.raises(AddressRejected):
        await store.add(owner.id, "two@example.org, three@example.org")
    with pytest.raises(Conflict) as duplicate:
        await store.add(owner.id, "ME.ALT@example.org")
    assert str(duplicate.value) == "That address is already watched."
    with pytest.raises(Conflict) as sign_in:
        await store.add(owner.id, OWNER)
    assert str(sign_in.value) == "That is your sign-in address; it is already watched."
    for i in range(9):
        await store.add(owner.id, f"extra{i}@example.org")
    with pytest.raises(LimitReached) as limit:
        await store.add(owner.id, "eleventh@example.org")
    assert str(limit.value) == "You can watch at most 10 addresses."
    # The sign-in row does not count toward the ten.
    assert len(await address_rows(session_factory, owner.id)) == 11


@pytest.mark.asyncio
async def test_an_add_that_raced_past_the_limit_is_taken_back_so_the_cap_of_ten_holds(
    session_factory, monkeypatch
):
    # Ten typed addresses exist. The first count this add makes is stale (it reads nine, as
    # a second add racing the same owner would have seen before either committed), so the
    # row is inserted; the count after the commit sees eleven and takes it back.
    owner = await make_owner(session_factory)
    store = BreachStore(session_factory, clock=Clock())
    for i in range(10):
        await store.add(owner.id, f"extra{i}@example.org")
    real_count = BreachStore._added_count
    counts: list[int] = []

    async def stale_first(session, user_id):
        counted = await real_count(session, user_id)
        counts.append(counted)
        return counted - 1 if len(counts) == 1 else counted

    monkeypatch.setattr(BreachStore, "_added_count", staticmethod(stale_first))
    with pytest.raises(LimitReached) as limit:
        await store.add(owner.id, "raced@example.org")
    assert str(limit.value) == "You can watch at most 10 addresses."
    assert counts == [10, 11]
    rows = await address_rows(session_factory, owner.id)
    assert len([row for row in rows if row.source == "added"]) == 10
    assert address_digest("raced@example.org") not in {row.address_digest for row in rows}


@pytest.mark.asyncio
async def test_the_sign_in_address_cannot_be_removed_and_another_owners_rows_are_not_found(
    session_factory,
):
    owner = await make_owner(session_factory)
    other = await make_owner(session_factory, "other.owner@example.org")
    store = BreachStore(session_factory, clock=Clock())
    await store.ensure_account_row(owner.id)
    added = await store.add(owner.id, "me.alt@example.org")
    (account,) = [
        row for row in await address_rows(session_factory, owner.id) if row.source == "account"
    ]

    with pytest.raises(Conflict) as kept:
        await store.remove(owner.id, account.id)
    assert "Pause it instead." in str(kept.value)
    for call in (
        store.remove(other.id, uuid.UUID(added["id"])),
        store.set_paused(other.id, uuid.UUID(added["id"]), True),
        store.claim_one(other.id, uuid.UUID(added["id"]), T0, CHECK_NOW_COOLDOWN, LEASE),
    ):
        with pytest.raises(NotFound):
            await call

    (claim,) = [c for c in await store.claim_due(T0, 10, LEASE) if c.source == "added"]
    await store.record_result(claim, [breach("Adobe"), breach("Linked")], T0)
    assert await store.remove(owner.id, uuid.UUID(added["id"])) == 2
    assert [row.source for row in await address_rows(session_factory, owner.id)] == ["account"]
    assert await finding_rows(session_factory, owner.id) == []


@pytest.mark.asyncio
async def test_acknowledging_one_and_all_findings_and_the_overview_order(session_factory):
    owner = await make_owner(session_factory)
    other = await make_owner(session_factory, "other.owner@example.org")
    clock = Clock()
    store = BreachStore(session_factory, clock=clock)
    await store.ensure_account_row(owner.id)
    (claim,) = await store.claim_due(T0, 10, LEASE)
    await store.record_result(claim, [breach("Adobe", when=date(2013, 10, 4))], T0)
    later = T0 + CHECK_EVERY
    await store.record_result(
        claim, [breach("Adobe"), breach("ExampleShop", title="Example Shop")], later
    )

    view = await store.overview(owner.id)
    assert [f["name"] for f in view["findings"]] == ["ExampleShop", "Adobe"]
    shop, adobe = view["findings"]
    assert shop == {
        "id": shop["id"],
        "address_id": str(claim.id),
        "name": "ExampleShop",
        "title": "Example Shop",
        "domain": "exampleshop.com",
        "breach_date": "2026-08-30",
        "added_at": "2026-10-01T00:00:00Z",
        "pwn_count": 1000,
        "data_classes": ["Email addresses", "Passwords"],
        "verified": True,
        "sensitive": False,
        "fabricated": False,
        "spam_list": False,
        "baseline": False,
        "first_seen_at": "2026-10-21T09:00:00Z",
        "alerted_at": None,
        "acknowledged_at": None,
    }
    assert adobe["baseline"] is True
    (address,) = view["addresses"]
    assert address["new_count"] == 2 and address["breach_count"] == 2
    assert address["address"] == OWNER and address["readable"] is True
    assert address["last_error_code"] is None and address["last_error"] is None
    assert set(address) == {
        "id",
        "address",
        "hint",
        "source",
        "status",
        "readable",
        "last_checked_at",
        "next_check_at",
        "baseline_at",
        "breach_count",
        "new_count",
        "last_error_code",
        "last_error",
    }

    clock.advance(timedelta(hours=1))
    handled = await store.acknowledge(owner.id, uuid.UUID(adobe["id"]))
    assert handled["acknowledged_at"] == "2026-10-14T10:00:00Z"
    with pytest.raises(NotFound):
        await store.acknowledge(other.id, uuid.UUID(shop["id"]))
    view = await store.overview(owner.id)
    # Handled ones go after the new ones.
    assert [f["name"] for f in view["findings"]] == ["ExampleShop", "Adobe"]
    assert view["addresses"][0]["new_count"] == 1
    assert await store.acknowledge_all(owner.id) == 1
    assert await store.acknowledge_all(owner.id) == 0
    assert (await store.overview(owner.id))["addresses"][0]["new_count"] == 0


@pytest.mark.asyncio
async def test_a_typed_address_that_becomes_the_sign_in_address_keeps_its_seen_list(
    session_factory,
):
    owner = await make_owner(session_factory)
    store = BreachStore(session_factory, clock=Clock())
    await store.ensure_account_row(owner.id)
    added = await store.add(owner.id, "me.alt@example.org")
    (claim,) = [c for c in await store.claim_due(T0, 10, LEASE) if c.source == "added"]
    await store.record_result(claim, [breach("Adobe")], T0)

    async with session_factory() as session:
        await session.execute(
            update(User).where(User.id == owner.id).values(email="me.alt@example.org")
        )
        await session.commit()
    assert await store.ensure_account_row(owner.id) is None

    (row,) = await address_rows(session_factory, owner.id)
    assert str(row.id) == added["id"] and row.source == "account"
    assert [f.breach_name for f in await finding_rows(session_factory, owner.id)] == ["Adobe"]


@pytest.mark.asyncio
async def test_the_account_export_holds_the_addresses_and_their_breaches(session_factory):
    owner = await make_owner(session_factory)
    store = BreachStore(session_factory, clock=Clock())
    await store.ensure_account_row(owner.id)
    await store.add(owner.id, "me.alt@example.org")
    (claim,) = [c for c in await store.claim_due(T0, 10, LEASE) if c.source == "account"]
    await store.record_result(claim, [breach("Adobe", when=date(2013, 10, 4))], T0)

    async with session_factory() as session:
        exported = await export_for_user(session, owner.id)
        stranger = await export_for_user(session, uuid.uuid4())
    assert stranger == []
    account, added = exported
    assert account == {
        "address": OWNER,
        "source": "account",
        "status": "active",
        "created_at": "2026-10-14T09:00:00Z",
        "last_checked_at": "2026-10-14T09:00:00Z",
        "findings": [
            {
                "name": "Adobe",
                "title": "Adobe",
                "domain": "adobe.com",
                "breach_date": "2013-10-04",
                "data_classes": ["Email addresses", "Passwords"],
                "first_seen_at": "2026-10-14T09:00:00Z",
                "acknowledged_at": None,
            }
        ],
    }
    assert added["address"] == "me.alt@example.org" and added["findings"] == []
    json.dumps(exported)  # JSON-ready


# ---------------------------------------------------------------------------
# Texts
# ---------------------------------------------------------------------------


def test_failure_sentences_and_check_now_notes_read_as_not_checked_never_as_no_breaches():
    assert failure_sentence(None) is None
    assert failure_sentence("timeout") == "Have I Been Pwned did not answer in time."
    assert failure_sentence("something new") == "Have I Been Pwned could not be reached."
    assert checked_note(0) == "No new breaches."
    assert checked_note(1) == "Found in 1 new breach."
    assert checked_note(3) == "Found in 3 new breaches."
    assert retry_sentence(timedelta(hours=1)) == "Crawler tries again in 1 hour."
    assert retry_sentence(timedelta(hours=2)) == "Crawler tries again in 2 hours."
    assert retry_sentence(timedelta(minutes=30)) == "Crawler tries again in 30 minutes."
    assert not_checked_note("rate_limited") == (
        "Not checked: Have I Been Pwned asked Crawler to slow down. Crawler tries again in an hour."
    )
    for code in FAILURE_SENTENCES:
        note = not_checked_note(code, timedelta(hours=4))
        assert note.startswith("Not checked: ") and "no breaches" not in note.lower()
    assert stopped_message("k•••@example.com", 1, "address_refused").startswith(
        "⚠️ Stopped checking k•••＠example․com for breaches: the last check failed "
        "(Have I Been Pwned would not look this address up)."
    )


# ---------------------------------------------------------------------------
# Audit and logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_rows_carry_ids_counts_and_codes_and_never_the_address_or_the_key(
    session_factory,
):
    owner = await make_owner(session_factory)
    h = Harness(session_factory)
    h.hibp.script(
        OWNER, [breach("Adobe")], [breach("Adobe"), breach("Linked")], Unavailable("down")
    )
    await h.service.sweep_once()
    h.clock.advance(CHECK_EVERY)
    await h.service.sweep_once()
    h.clock.advance(CHECK_EVERY)
    await h.service.sweep_once()

    rows = await audit_rows(session_factory, owner.id)
    actions = [
        (row.action, row.status.value if hasattr(row.status, "value") else row.status)
        for row in rows
    ]
    assert actions == [
        ("breach_checked", "approved"),
        ("breach_found", "approved"),
        ("breach_checked", "approved"),
        ("breach_found", "approved"),
        ("breach_check_failed", "blocked"),
    ]
    (address,) = await address_rows(session_factory, owner.id)
    first_checked, first_found, _, second_found, failed = (row.request_data for row in rows)
    assert first_checked == {
        "address_id": str(address.id),
        "source": "account",
        "trigger": "schedule",
        "breaches": 1,
        "new": 1,
        "baseline": True,
    }
    assert first_found == {
        "address_id": str(address.id),
        "trigger": "schedule",
        "new": 1,
        "baseline": True,
        "delivered": True,
    }
    assert second_found["baseline"] is False and second_found["new"] == 1
    # "error_code", not "code": the audit sanitizer masks a key named exactly "code".
    assert failed == {
        "address_id": str(address.id),
        "source": "account",
        "trigger": "schedule",
        "error_code": "unavailable",
        "failures": 1,
        "stopped": False,
    }
    assert all(
        row.endpoint == "breach_monitor_sweeper" and row.scope_used == "breach_monitor"
        for row in rows
    )
    for row in rows:
        text = json.dumps(
            [row.request_data, row.response_summary, row.reasoning_chain], default=str
        )
        assert "kash" not in text and "example.com" not in text and KEY not in text


@pytest.mark.asyncio
async def test_logs_carry_ids_codes_and_exception_types_only(session_factory, monkeypatch):
    owner = await make_owner(session_factory)
    h = Harness(
        session_factory, outbox=Outbox(answer=RuntimeError(f"LEAKMARK chat said no to {OWNER}"))
    )
    await h.store.ensure_account_row(owner.id)
    await h.store.add(owner.id, "me.alt@example.org")
    # Neither failure stops the sweep, so both are tried whatever the claim order.
    h.hibp.script(OWNER, ValueError(f"LEAKMARK boom for {OWNER} with {KEY}"))
    h.hibp.script("me.alt@example.org", AddressRefused("refused"))

    async def broken_audit(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(f"LEAKMARK audit down for {OWNER}")

    with capture_logs() as logs:
        await h.service.sweep_once()
        monkeypatch.setattr("services.audit.append_audit_log", broken_audit)
        h.clock.advance(timedelta(hours=3))
        h.hibp.script(OWNER, [breach("Adobe")])
        await h.service.sweep_once()

    events = {entry["event"] for entry in logs}
    assert {
        "breach_check_crashed",
        "breach_check_failed",
        "breach_monitor_delivery_failed",
        "breach_monitor_audit_failed",
    } <= events
    crashed = next(entry for entry in logs if entry["event"] == "breach_check_crashed")
    assert crashed["error_type"] == "ValueError"
    for entry in logs:
        text = json.dumps(entry, default=str)
        assert "kash" not in text and "me.alt" not in text and KEY not in text, entry
        # No exception text reaches a log line: types only.
        assert "LEAKMARK" not in text
