"""Tests for S1's stores (services/security/outbound_store.py) on the SQLite test
database: they prove the sent-to history finds an address and its domain after a
send, counts repeat sends and keeps the first date, never stores an address or a
domain in any column, ignores and prunes rows made under another key, keeps at most
its cap of the most recently used rows and nothing unused for two years, prunes at
most once an hour, forgets only the caller's rows, survives a concurrent first send,
and goes with a deleted user; that the organisation's domain list refuses a duplicate
and the fifty-first, caches and clears its cache on a change (OrgDomains' too); that
``OrgDomains.for_user`` unions the sign-in domain and the owner's list without public
mail services and raises on a read error (scaffold A24); and that the account export
holds fingerprints, dates and counts only.

Why it exists: the history is the one place S1 keeps anything about who the owner
writes to, so its privacy promise (keyed fingerprints only, per user, gone on request)
and its bounds are pinned here; S9's rule B3 relies on OrgDomains failing loudly.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from core.config import settings
from models.known_recipient import KnownRecipient, OrganisationDomain
from models.user import User
from services.security.outbound_recipients import hmac_key_id, parse_recipients, recipient_hmac
from services.security.outbound_store import (
    DomainRefused,
    KnownRecipientStore,
    OrganisationDomainStore,
    OrgDomains,
    UserEmails,
    export_for_user,
)
from tests.conftest import make_user

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class Ticks:
    """A monotonic clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def people(*addresses: str):
    return parse_recipients(list(addresses))


async def rows_of(session_factory, user_id=None) -> list[KnownRecipient]:
    async with session_factory() as session:
        query = select(KnownRecipient)
        if user_id is not None:
            query = query.where(KnownRecipient.user_id == user_id)
        return list((await session.execute(query)).scalars().all())


# -- the sent-to history ----------------------------------------------------------


@pytest.mark.asyncio
async def test_record_then_known_finds_the_address_and_its_domain(session_factory):
    user, _ = await make_user(session_factory, "owner@northwind.example")
    store = KnownRecipientStore(session_factory, clock=Clock())
    uid = str(user.id)
    before = await store.known(uid, people("ann@acme.example", "bob@beta.example"))
    assert before.addresses == frozenset() and before.domains == frozenset()

    await store.record(uid, people("Ann <Ann+invoices@ACME.example>"))
    found = await store.known(
        uid, people("ann@acme.example", "carl@acme.example", "bob@beta.example")
    )
    assert found.addresses == frozenset({"ann@acme.example"})
    assert found.domains == frozenset({"acme.example"})
    # Nothing to ask about: no query, nothing known.
    empty = await store.known(uid, [])
    assert empty.addresses == frozenset()


@pytest.mark.asyncio
async def test_recording_twice_counts_the_sends_and_keeps_the_first_date(session_factory):
    user, _ = await make_user(session_factory)
    clock = Clock()
    store = KnownRecipientStore(session_factory, clock=clock)
    await store.record(str(user.id), people("ann@acme.example"))
    clock.now = T0 + timedelta(days=3)
    await store.record(str(user.id), people("ann@acme.example"))
    rows = {row.kind: row for row in await rows_of(session_factory)}
    assert set(rows) == {"address", "domain"}
    for row in rows.values():
        assert row.send_count == 2
        assert row.first_sent_at.replace(tzinfo=timezone.utc) == T0
        assert row.last_sent_at.replace(tzinfo=timezone.utc) == T0 + timedelta(days=3)
    summary = await store.summary(str(user.id))
    assert (summary.addresses, summary.domains, summary.since) == (1, 1, T0)


@pytest.mark.asyncio
async def test_no_column_holds_a_plain_address_or_domain(session_factory):
    user, _ = await make_user(session_factory)
    store = KnownRecipientStore(session_factory, clock=Clock())
    await store.record(str(user.id), people("Ann.Lee+news@Northwind-Partners.example"))
    rows = await rows_of(session_factory)
    assert len(rows) == 2
    for row in rows:
        values = " ".join(
            str(getattr(row, column.key)) for column in KnownRecipient.__table__.columns
        ).lower()
        for fragment in ("ann", "lee", "northwind", "partners", "example", "@"):
            assert fragment not in values
        assert row.key_id == hmac_key_id()
    expected = {
        recipient_hmac(str(user.id), "address", "ann.lee@northwind-partners.example"),
        recipient_hmac(str(user.id), "domain", "northwind-partners.example"),
    }
    assert {row.value_hmac for row in rows} == expected


@pytest.mark.asyncio
async def test_the_users_own_sign_in_address_is_never_recorded(session_factory):
    user, _ = await make_user(session_factory, "owner@northwind.example")
    store = KnownRecipientStore(session_factory, clock=Clock())
    await store.record(str(user.id), people("Owner@Northwind.example"))
    assert await rows_of(session_factory) == []
    await store.record(str(user.id), people("owner@northwind.example", "ann@acme.example"))
    assert len(await rows_of(session_factory)) == 2


@pytest.mark.asyncio
async def test_rows_made_under_another_key_are_ignored_and_pruned(session_factory, monkeypatch):
    user, _ = await make_user(session_factory)
    uid = str(user.id)
    await KnownRecipientStore(session_factory, clock=Clock()).record(
        uid, people("ann@acme.example")
    )
    old_key_id = hmac_key_id()

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", "another-key-entirely-" + "x" * 24)
    assert hmac_key_id() != old_key_id
    store = KnownRecipientStore(session_factory, clock=Clock(T0 + timedelta(minutes=5)))
    # Ignored: every recipient is "first time" again (the cautious direction).
    found = await store.known(uid, people("ann@acme.example"))
    assert found.addresses == frozenset() and found.domains == frozenset()
    assert (await store.summary(uid)).addresses == 0
    # Pruned on the next send.
    await store.record(uid, people("bob@beta.example"))
    rows = await rows_of(session_factory)
    assert {row.key_id for row in rows} == {hmac_key_id()} and len(rows) == 2


@pytest.mark.asyncio
async def test_the_address_cap_prunes_the_least_recently_sent_rows(session_factory):
    user, _ = await make_user(session_factory)
    uid = str(user.id)
    clock = Clock()
    store = KnownRecipientStore(session_factory, clock=clock, address_cap=3, domain_cap=2)
    for index in range(5):
        clock.now = T0 + timedelta(hours=2 * index)  # each send may prune (over an hour apart)
        await store.record(uid, people(f"user{index}@d{index}.example"))
    found = await store.known(uid, people(*(f"user{i}@d{i}.example" for i in range(5))))
    assert found.addresses == frozenset(
        {"user2@d2.example", "user3@d3.example", "user4@d4.example"}
    )
    assert found.domains == frozenset({"d3.example", "d4.example"})


@pytest.mark.asyncio
async def test_rows_unused_for_two_years_are_pruned(session_factory):
    user, _ = await make_user(session_factory)
    uid = str(user.id)
    clock = Clock()
    store = KnownRecipientStore(session_factory, clock=clock)
    await store.record(uid, people("old@past.example"))
    clock.now = T0 + timedelta(days=700)
    await store.record(uid, people("recent@now.example"))
    clock.now = T0 + timedelta(days=731)
    await store.record(uid, people("today@now.example"))
    found = await store.known(
        uid, people("old@past.example", "recent@now.example", "today@now.example")
    )
    assert found.addresses == frozenset({"recent@now.example", "today@now.example"})
    assert found.domains == frozenset({"now.example"})


@pytest.mark.asyncio
async def test_pruning_runs_at_most_once_an_hour_per_user(session_factory):
    user, _ = await make_user(session_factory)
    uid = str(user.id)
    clock = Clock()
    store = KnownRecipientStore(session_factory, clock=clock, address_cap=1, domain_cap=10)
    calls: list[str] = []
    real_prune = store.prune

    async def counting(user_id):
        calls.append(str(user_id))
        return await real_prune(user_id)

    store.prune = counting  # type: ignore[method-assign]
    await store.record(uid, people("a@one.example"))
    clock.now = T0 + timedelta(minutes=30)
    await store.record(uid, people("b@two.example"))
    assert len(calls) == 1
    assert (
        len([r for r in await rows_of(session_factory) if r.kind == "address"]) == 2
    )  # over the cap for now
    clock.now = T0 + timedelta(minutes=61)
    await store.record(uid, people("c@three.example"))
    assert len(calls) == 2
    assert len([r for r in await rows_of(session_factory) if r.kind == "address"]) == 1
    # Another user is pruned on their own schedule.
    other, _ = await make_user(session_factory, "other@example.com")
    await store.record(str(other.id), people("x@four.example"))
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_forget_removes_only_that_users_rows_and_says_how_many(session_factory):
    ann, _ = await make_user(session_factory, "ann@example.com")
    bob, _ = await make_user(session_factory, "bob@example.com")
    store = KnownRecipientStore(session_factory, clock=Clock())
    await store.record(str(ann.id), people("x@one.example", "y@two.example"))
    await store.record(str(bob.id), people("x@one.example"))
    assert await store.forget(str(ann.id)) == 4
    assert await rows_of(session_factory, ann.id) == []
    assert len(await rows_of(session_factory, bob.id)) == 2
    assert await store.forget(str(ann.id)) == 0


@pytest.mark.asyncio
async def test_a_concurrent_first_send_to_one_address_does_not_raise(session_factory, monkeypatch):
    user, _ = await make_user(session_factory)
    uid = str(user.id)
    store = KnownRecipientStore(session_factory, clock=Clock())
    await asyncio.gather(
        store.record(uid, people("ann@acme.example")),
        store.record(uid, people("ann@acme.example")),
    )
    rows = await rows_of(session_factory)
    assert len(rows) == 2 and {row.send_count for row in rows} == {2}

    # The race itself: another send inserts the same rows between this send's
    # read and its insert. The unique index refuses the second insert once; the
    # retry finds the rows and counts the send.
    from sqlalchemy.exc import IntegrityError

    racing = KnownRecipientStore(session_factory, clock=Clock())
    real_upsert = racing._upsert
    attempts: list[int] = []

    async def first_attempt_loses(uid_value, recipients):
        attempts.append(1)
        if len(attempts) == 1:
            await KnownRecipientStore(session_factory, clock=Clock())._upsert(uid_value, recipients)
            raise IntegrityError("INSERT", {}, Exception("unique"))
        await real_upsert(uid_value, recipients)

    monkeypatch.setattr(racing, "_upsert", first_attempt_loses)
    await racing.record(uid, people("carl@crane.example"))
    assert len(attempts) == 2
    found = await store.known(uid, people("carl@crane.example"))
    assert found.addresses == frozenset({"carl@crane.example"})


@pytest.mark.asyncio
async def test_deleting_a_user_deletes_their_known_recipients(session_factory):
    user, _ = await make_user(session_factory)
    await KnownRecipientStore(session_factory, clock=Clock()).record(
        str(user.id), people("ann@acme.example")
    )
    assert len(await rows_of(session_factory)) == 2
    async with session_factory() as session:
        await session.execute(delete(User).where(User.id == user.id))
        await session.commit()
    assert await rows_of(session_factory) == []


@pytest.mark.asyncio
async def test_summary_counts_only_this_user_and_says_since_when(session_factory):
    ann, _ = await make_user(session_factory, "ann@example.com")
    bob, _ = await make_user(session_factory, "bob@example.com")
    clock = Clock()
    store = KnownRecipientStore(session_factory, clock=clock)
    assert (await store.summary(str(ann.id))).since is None
    await store.record(str(ann.id), people("a@one.example", "b@one.example"))
    clock.now = T0 + timedelta(days=1)
    await store.record(str(ann.id), people("c@two.example"))
    await store.record(str(bob.id), people("z@three.example"))
    summary = await store.summary(str(ann.id))
    assert (summary.addresses, summary.domains, summary.since) == (3, 2, T0)


# -- organisation domains, sign-in addresses, OrgDomains --------------------------------


@pytest.mark.asyncio
async def test_organisation_domains_refuse_a_duplicate_and_the_fifty_first(session_factory):
    owner, _ = await make_user(session_factory, "owner@northwind.example")
    store = OrganisationDomainStore(session_factory, limit=50)
    first = await store.add(" WWW.Acme.CO.UK. ", added_by=str(owner.id))
    assert first.domain == "acme.co.uk"
    with pytest.raises(DomainRefused) as duplicate:
        await store.add("acme.co.uk", added_by=str(owner.id))
    assert (duplicate.value.status, duplicate.value.message) == (
        409,
        "acme.co.uk is already listed.",
    )
    with pytest.raises(DomainRefused) as consumer:
        await store.add("gmail.com", added_by=str(owner.id))
    assert consumer.value.status == 422 and "public mail service" in consumer.value.message
    for index in range(49):
        await store.add(f"branch{index}.example", added_by=str(owner.id))
    with pytest.raises(DomainRefused) as full:
        await store.add("one-too-many.example", added_by=str(owner.id))
    assert (full.value.status, full.value.message) == (422, "You can list at most 50 domains.")
    assert len(await store.domains()) == 50
    # An unknown id, or one that is not an id at all, removes nothing.
    assert await store.remove(str(uuid.uuid4())) is False
    assert await store.remove("not-an-id") is False
    assert await store.remove(first.id) is True
    assert "acme.co.uk" not in {row.domain for row in await store.domains()}


@pytest.mark.asyncio
async def test_organisation_domains_are_cached_and_a_change_clears_the_cache(session_factory):
    owner, _ = await make_user(session_factory, "owner@northwind.example")
    ticks = Ticks()
    store = OrganisationDomainStore(session_factory, ttl_s=60.0, clock=ticks)
    org = OrgDomains(session_factory, ttl_s=60.0, domains=store, clock=ticks)
    assert await store.domains() == ()
    assert await org.for_user(str(owner.id)) == frozenset({"northwind.example"})

    # A row written behind the store's back is not seen until the cache expires...
    async with session_factory() as session:
        session.add(OrganisationDomain(domain="sideways.example", created_at=T0))
        await session.commit()
    assert await store.domains() == ()
    assert await org.for_user(str(owner.id)) == frozenset({"northwind.example"})
    ticks.now += 61
    assert {row.domain for row in await store.domains()} == {"sideways.example"}

    # ...but an owner edit through the store clears both caches at once.
    await org.for_user(str(owner.id))
    await store.add("acme.co.uk", added_by=str(owner.id))
    assert await org.for_user(str(owner.id)) == frozenset(
        {"northwind.example", "sideways.example", "acme.co.uk"}
    )
    [acme] = [row for row in await store.domains() if row.domain == "acme.co.uk"]
    await store.remove(acme.id)
    assert await org.for_user(str(owner.id)) == frozenset({"northwind.example", "sideways.example"})


@pytest.mark.asyncio
async def test_org_domains_for_user_unions_the_sign_in_domain_and_the_owner_list_and_drops_consumer_domains(
    session_factory,
):
    ann, _ = await make_user(session_factory, "ann@eu.northwind.com")
    bob, _ = await make_user(session_factory, "bob@gmail.com")
    org = OrgDomains(session_factory)
    assert await org.for_user(str(bob.id)) == frozenset()  # no organisation known
    store = OrganisationDomainStore(session_factory)
    await store.add("acme.co.uk", added_by=str(ann.id))
    fresh = OrgDomains(session_factory, domains=store)
    assert await fresh.for_user(str(ann.id)) == frozenset({"northwind.com", "acme.co.uk"})
    assert await fresh.for_user(str(bob.id)) == frozenset({"acme.co.uk"})
    # Without the shared store it reads the rows itself, the same answer.
    assert await OrgDomains(session_factory).for_user(str(ann.id)) == frozenset(
        {"northwind.com", "acme.co.uk"}
    )
    # An id that is not a user: only the owner's list.
    assert await OrgDomains(session_factory).for_user("not-a-user") == frozenset({"acme.co.uk"})


@pytest.mark.asyncio
async def test_org_domains_raises_on_a_read_error_instead_of_answering_empty(session_factory):
    ann, _ = await make_user(session_factory, "ann@northwind.com")

    def broken():
        raise ConnectionError("database is down")

    with pytest.raises(ConnectionError):
        await OrgDomains(broken).for_user(str(ann.id))  # type: ignore[arg-type]
    with pytest.raises(ConnectionError):
        await OrgDomains(session_factory, domains=OrganisationDomainStore(broken)).for_user(  # type: ignore[arg-type]
            str(ann.id)
        )
    # A raise is never cached as an answer.
    org = OrgDomains(session_factory)
    assert await org.for_user(str(ann.id)) == frozenset({"northwind.com"})


@pytest.mark.asyncio
async def test_user_emails_are_cached_and_an_unknown_user_is_none(session_factory):
    ann, _ = await make_user(session_factory, "ann@northwind.com")
    ticks = Ticks()
    users = UserEmails(session_factory, ttl_s=300.0, clock=ticks)
    assert await users.email(str(ann.id)) == "ann@northwind.com"
    async with session_factory() as session:
        row = await session.get(User, ann.id)
        assert row is not None
        row.email = "ann@acme.example"
        await session.commit()
    assert await users.email(str(ann.id)) == "ann@northwind.com"  # cached
    ticks.now += 301
    assert await users.email(str(ann.id)) == "ann@acme.example"
    assert await users.email(str(uuid.uuid4())) is None
    assert await users.email("not-a-uuid") is None


@pytest.mark.asyncio
async def test_the_account_export_lists_fingerprints_dates_and_counts_only(session_factory):
    ann, _ = await make_user(session_factory, "ann@example.com")
    bob, _ = await make_user(session_factory, "bob@example.com")
    store = KnownRecipientStore(session_factory, clock=Clock())
    await store.record(str(ann.id), people("carl@crane.example"))
    await store.record(str(bob.id), people("dora@dune.example"))
    async with session_factory() as session:
        exported = await export_for_user(session, ann.id)
    assert [item["kind"] for item in exported] == ["address", "domain"]
    for item in exported:
        assert set(item) == {
            "kind",
            "value_hmac",
            "key_id",
            "first_sent_at",
            "last_sent_at",
            "send_count",
        }
        assert item["send_count"] == 1 and item["first_sent_at"].startswith("2026-10-14T09:00:00")
    text = str(exported)
    for fragment in ("carl", "crane", "dora", "dune", "@"):
        assert fragment not in text
