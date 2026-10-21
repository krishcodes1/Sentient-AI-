"""Tests for the site-rules store and service (services/site_rules/store.py
and service.py): they prove a new rule is stored and audited in the same
transaction and applies to the next snapshot and, once the service is
refreshed, to the next lookup; a duplicate is a 409 that writes nothing,
the 500th rule is the last one accepted, changes and deletions are audited
with the previous kind, a failed audit write rolls the change back, setting
a category back to Always ask removes its override row, every refusal
reaches the caller before anything is written, and audit rows carry ids,
kinds and keyed host hashes but never a host or a URL. For the service:
the snapshot is reloaded after its TTL and the last good one is kept when
the database fails (retried after five seconds), concurrent callers share
one read, a service that never loaded fails closed in its hooks, a switch
that cannot be read counts as on, a capabilities change marks the snapshot
stale, navigation blocks and read notices are audited once per user, site
and ten minutes (also from a worker thread, and a failed write is only
logged), and the recent hits keep the twenty latest sites with counts and
no user.

Why it exists: rules are owner policy written from the Security tab; a
change without its audit row, a duplicate row the unique index trips over
later, or a host name in the append-only audit log would each be a defect
the owner cannot undo; and a service that answered "no rules" when it had
never read them would open every Blocked site. Runs on in-memory SQLite
(or Postgres via TEST_DATABASE_URL), offline.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import select

from core.config import settings
from models.audit import AuditLog, AuditStatus
from models.browser_site_rule import BrowserSiteRule
from services.site_rules import messages, store
from services.site_rules.patterns import MAX_HOST_RULES, SiteRuleError, host_hash
from services.site_rules.service import SiteRulesService
from services.site_rules.snapshot import SiteVerdict
from tests.conftest import make_user


async def _rows(session_factory) -> list[BrowserSiteRule]:
    async with session_factory() as db:
        return await store.list_rows(db)


async def _audit_rows(session_factory) -> list[AuditLog]:
    async with session_factory() as db:
        result = await db.execute(
            select(AuditLog).where(AuditLog.connector_name == "site_rules").order_by(AuditLog.seq)
        )
        return list(result.scalars().all())


def _dumped(row: AuditLog) -> str:
    return json.dumps(
        {c.name: getattr(row, c.name) for c in AuditLog.__table__.columns}, default=str
    ).lower()


async def _create(session_factory, owner, site, kind="blocked", *, include_subdomains=True):
    async with session_factory() as db:
        row = await store.create_rule(
            db, owner, site=site, include_subdomains=include_subdomains, kind=kind
        )
        await db.commit()
        return row


@pytest.mark.asyncio
async def test_a_new_rule_is_stored_and_audited_in_one_transaction_and_applies_to_the_next_snapshot(
    session_factory,
):
    owner, _ = await make_user(session_factory, "owner@example.com")
    row = await _create(session_factory, owner, "https://www.Example-Casino.com/x?y=1")
    assert (row.target_type, row.target, row.kind) == ("host", "*.example-casino.com", "blocked")
    assert row.created_by == owner.id and row.updated_by == owner.id

    rows = await _rows(session_factory)
    assert [r.target for r in rows] == ["*.example-casino.com"]
    snapshot = store.snapshot_from_rows(rows, enabled=True, loaded_at=1.0)
    verdict = snapshot.verdict("https://login.example-casino.com/")
    assert (verdict.kind, verdict.source, verdict.rule_id) == ("blocked", "owner", str(row.id))

    (audit,) = await _audit_rows(session_factory)
    assert audit.action == "site_rule_created"
    assert audit.status == AuditStatus.approved
    assert audit.user_id == owner.id
    assert audit.endpoint == "/api/security/site-rules"
    assert audit.reasoning_chain == {"event": "site_rule_created"}
    assert audit.request_data == {
        "rule_id": str(row.id),
        "target_type": "host",
        "kind": "blocked",
        "include_subdomains": True,
        "host_hash": host_hash("example-casino.com", settings.ENCRYPTION_KEY),
    }


@pytest.mark.asyncio
async def test_a_duplicate_rule_is_a_conflict_and_nothing_is_written(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    await _create(session_factory, owner, "example-casino.com")
    async with session_factory() as db:
        with pytest.raises(SiteRuleError) as caught:
            # The same pattern however it is typed.
            await store.create_rule(
                db, owner, site="*.EXAMPLE-CASINO.com.", include_subdomains=False, kind="trusted"
            )
        await db.rollback()
    assert caught.value.status == 409
    assert str(caught.value) == (
        "There is already a rule for example-casino.com. Change that one instead."
    )
    assert len(await _rows(session_factory)) == 1
    assert len(await _audit_rows(session_factory)) == 1
    # The exact host is a different rule from the site with its subdomains.
    exact = await _create(session_factory, owner, "example-casino.com", "trusted", include_subdomains=False)
    assert exact.target == "example-casino.com"


@pytest.mark.asyncio
async def test_the_five_hundredth_rule_is_the_last_one_accepted(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    async with session_factory() as db:
        db.add_all(
            BrowserSiteRule(target_type="host", target=f"site{n}.example", kind="blocked")
            for n in range(MAX_HOST_RULES - 1)
        )
        # Category overrides do not count toward the limit.
        db.add(BrowserSiteRule(target_type="category", target="banks", kind="blocked"))
        await db.commit()
    last = await _create(session_factory, owner, "last.example", include_subdomains=False)
    assert last.target == "last.example"
    async with session_factory() as db:
        assert await store.count_host_rules(db) == MAX_HOST_RULES
        with pytest.raises(SiteRuleError) as caught:
            await store.create_rule(db, owner, site="one-more.example", include_subdomains=False, kind="blocked")
    assert caught.value.status == 422
    assert str(caught.value) == "You have 500 site rules, the most Crawler keeps. Remove some first."


@pytest.mark.asyncio
async def test_changing_and_deleting_a_rule_are_audited_with_the_previous_kind(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    editor, _ = await make_user(session_factory, "editor@example.com")
    row = await _create(session_factory, owner, "mybank.example", "always_ask")
    async with session_factory() as db:
        changed = await store.update_rule(db, editor, str(row.id), kind="trusted")
        await db.commit()
    assert changed is not None and changed.kind == "trusted"
    assert changed.updated_by == editor.id and changed.created_by == owner.id
    async with session_factory() as db:
        # The same kind again changes nothing and writes no row.
        same = await store.update_rule(db, editor, str(row.id), kind="trusted")
        assert same is not None
        assert await store.delete_rule(db, editor, str(row.id)) is True
        await db.commit()
    assert await _rows(session_factory) == []

    audits = await _audit_rows(session_factory)
    assert [a.action for a in audits] == ["site_rule_created", "site_rule_updated", "site_rule_deleted"]
    digest = host_hash("mybank.example", settings.ENCRYPTION_KEY)
    assert audits[1].request_data == {
        "rule_id": str(row.id),
        "kind": "trusted",
        "previous_kind": "always_ask",
        "host_hash": digest,
    }
    assert audits[2].request_data == {
        "rule_id": str(row.id),
        "previous_kind": "trusted",
        "host_hash": digest,
    }
    assert audits[1].user_id == editor.id


@pytest.mark.asyncio
async def test_an_unknown_or_malformed_rule_id_is_not_found(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    async with session_factory() as db:
        db.add(BrowserSiteRule(target_type="category", target="banks", kind="blocked"))
        await db.commit()
    category_row = (await _rows(session_factory))[0]
    async with session_factory() as db:
        for rule_id in ("not-a-uuid", "00000000-0000-0000-0000-000000000000", "", str(category_row.id)):
            assert await store.update_rule(db, owner, rule_id, kind="trusted") is None, rule_id
            assert await store.delete_rule(db, owner, rule_id) is False, rule_id
    assert messages.NO_SUCH_RULE == "No such site rule."


@pytest.mark.asyncio
async def test_a_failed_audit_write_leaves_the_rules_unchanged(session_factory, monkeypatch):
    owner, _ = await make_user(session_factory, "owner@example.com")
    row = await _create(session_factory, owner, "mybank.example", "always_ask")

    async def broken_audit(*_args, **_kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(store, "append_audit_log", broken_audit)
    for change in (
        lambda db: store.create_rule(db, owner, site="new.example", include_subdomains=True, kind="blocked"),
        lambda db: store.update_rule(db, owner, str(row.id), kind="blocked"),
        lambda db: store.delete_rule(db, owner, str(row.id)),
        lambda db: store.set_category(db, owner, "crypto", kind="blocked"),
    ):
        async with session_factory() as db:
            with pytest.raises(RuntimeError):
                await change(db)
            await db.rollback()
    rows = await _rows(session_factory)
    assert [(r.target_type, r.target, r.kind) for r in rows] == [("host", "*.mybank.example", "always_ask")]
    assert messages.SAVE_FAILED == "The rule could not be saved. Try again."


@pytest.mark.asyncio
async def test_setting_a_category_back_to_always_ask_removes_its_override_row(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    async with session_factory() as db:
        assert await store.set_category(db, owner, "brokers", kind="blocked") == "blocked"
        await db.commit()
    rows = await _rows(session_factory)
    assert [(r.target_type, r.target, r.kind) for r in rows] == [("category", "brokers", "blocked")]
    snapshot = store.snapshot_from_rows(rows, enabled=True, loaded_at=0.0)
    assert snapshot.verdict("www.fidelity.com").kind == "blocked"

    async with session_factory() as db:
        assert await store.set_category(db, owner, "brokers", kind="trusted") == "trusted"
        # Setting the same kind again writes nothing.
        assert await store.set_category(db, owner, "brokers", kind="trusted") == "trusted"
        assert await store.set_category(db, owner, "brokers", kind="always_ask") == "always_ask"
        # The default on a category with no override writes nothing either.
        assert await store.set_category(db, owner, "banks", kind="always_ask") == "always_ask"
        await db.commit()
    assert await _rows(session_factory) == []

    audits = await _audit_rows(session_factory)
    assert [a.request_data for a in audits] == [
        {"category": "brokers", "kind": "blocked", "previous_kind": "always_ask"},
        {"category": "brokers", "kind": "trusted", "previous_kind": "blocked"},
        {"category": "brokers", "kind": "always_ask", "previous_kind": "trusted"},
    ]
    assert {a.action for a in audits} == {"site_category_changed"}


@pytest.mark.asyncio
async def test_an_unknown_category_is_404_and_an_unknown_kind_422(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    async with session_factory() as db:
        with pytest.raises(SiteRuleError) as unknown:
            await store.set_category(db, owner, "payments", kind="blocked")
        with pytest.raises(SiteRuleError) as bad_kind:
            await store.set_category(db, owner, "banks", kind="block")
    assert (unknown.value.status, str(unknown.value)) == (404, "No such category.")
    assert (bad_kind.value.status, str(bad_kind.value)) == (422, messages.BAD_KIND)
    assert await _rows(session_factory) == []


@pytest.mark.asyncio
async def test_validation_refusals_reach_the_caller_before_anything_is_written(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    row = await _create(session_factory, owner, "аpple.com", "blocked")  # a look-alike: Block is fine
    cases = [
        ("*.co.uk", True, "blocked", messages.too_broad("*.co.uk")),
        ("", False, "blocked", messages.EMPTY_SITE),
        ("*.google.com", True, "blocked", messages.protected_block("accounts.google.com")),
        ("example.com", False, "allow", messages.BAD_KIND),
    ]
    async with session_factory() as db:
        for site, include_subdomains, kind, reason in cases:
            with pytest.raises(SiteRuleError) as caught:
                await store.create_rule(
                    db, owner, site=site, include_subdomains=include_subdomains, kind=kind
                )
            assert (caught.value.status, str(caught.value)) == (422, reason)
        with pytest.raises(SiteRuleError) as lookalike:
            await store.update_rule(db, owner, str(row.id), kind="trusted")
        assert "look-alike characters" in str(lookalike.value)
    assert [r.kind for r in await _rows(session_factory)] == ["blocked"]
    assert len(await _audit_rows(session_factory)) == 1


@pytest.mark.asyncio
async def test_audit_rows_carry_kinds_and_keyed_host_hashes_never_hosts_or_urls(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    row = await _create(session_factory, owner, "https://secure.mybank.example/login?user=alice", "always_ask")
    async with session_factory() as db:
        await store.update_rule(db, owner, str(row.id), kind="blocked")
        await store.delete_rule(db, owner, str(row.id))
        await store.set_category(db, owner, "crypto", kind="trusted")
        await db.commit()
    audits = await _audit_rows(session_factory)
    assert len(audits) == 4
    for audit in audits:
        dumped = _dumped(audit)
        for leak in ("mybank", "secure.", "login", "alice", "https"):
            assert leak not in dumped, (audit.action, leak)
    hashes = {a.request_data.get("host_hash") for a in audits[:3]}
    assert hashes == {host_hash("secure.mybank.example", settings.ENCRYPTION_KEY)}


@pytest.mark.asyncio
async def test_snapshot_from_rows_reads_host_rules_and_category_overrides_and_skips_bad_rows(session_factory):
    async with session_factory() as db:
        db.add_all(
            [
                BrowserSiteRule(target_type="host", target="*.example-casino.com", kind="blocked"),
                BrowserSiteRule(target_type="host", target="docs.example-casino.com", kind="trusted"),
                BrowserSiteRule(target_type="host", target="bad*.example", kind="blocked"),
                BrowserSiteRule(target_type="host", target="odd.example", kind="sometimes"),
                BrowserSiteRule(target_type="category", target="crypto", kind="blocked"),
                BrowserSiteRule(target_type="category", target="unknown", kind="blocked"),
                BrowserSiteRule(target_type="other", target="x.example", kind="blocked"),
            ]
        )
        await db.commit()
    rows = await _rows(session_factory)
    assert [r.target_type for r in rows][:4] == ["host"] * 4
    snapshot = store.snapshot_from_rows(rows, enabled=True, loaded_at=5.0)
    assert snapshot.skipped == 2
    assert snapshot.verdict("www.example-casino.com").kind == "blocked"
    assert snapshot.verdict("docs.example-casino.com").kind == "trusted"
    assert snapshot.verdict("www.coinbase.com").kind == "blocked"
    assert snapshot.verdict("x.example").kind is None
    off = store.snapshot_from_rows(rows, enabled=False, loaded_at=5.0)
    assert off.verdict("www.example-casino.com").kind is None
    assert off.would_apply("www.example-casino.com").kind == "blocked"


# -- the service: snapshot, freshness, hooks, hits ------------------------------


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Switch:
    """The owner's switch as main reads it: on, off, or unreadable."""

    def __init__(self, on: bool = True) -> None:
        self.on = on
        self.raises = False
        self.reads = 0

    async def __call__(self) -> bool:
        self.reads += 1
        if self.raises:
            raise RuntimeError("installation store unavailable")
        return self.on


class FlakyFactory:
    """The session factory, failing on demand and counting what it opened."""

    def __init__(self, session_factory) -> None:
        self._inner = session_factory
        self.fail = False
        self.opened = 0

    def __call__(self):
        self.opened += 1
        if self.fail:
            raise RuntimeError("database unavailable")
        return self._inner()


def _service(factory, *, switch=None, clock=None) -> SiteRulesService:
    return SiteRulesService(factory, enabled=switch or Switch(), clock=clock or FakeClock())


@pytest.mark.asyncio
async def test_a_new_rule_is_stored_audited_in_the_same_transaction_and_applies_after_refresh(
    session_factory,
):
    owner, _ = await make_user(session_factory, "owner@example.com")
    service = _service(session_factory)
    first = await service.refresh()
    assert first is not None and first.verdict("www.example-casino.com").kind is None
    row = await _create(session_factory, owner, "example-casino.com")
    # Not yet: the snapshot is the one read before the rule existed.
    assert service.snapshot is first
    assert first.verdict("www.example-casino.com").kind is None
    fresh = await service.refresh()
    assert fresh is not None and fresh is service.snapshot
    verdict = fresh.verdict("https://www.example-casino.com/")
    assert (verdict.kind, verdict.rule_id) == ("blocked", str(row.id))
    assert [a.action for a in await _audit_rows(session_factory)] == ["site_rule_created"]


@pytest.mark.asyncio
async def test_the_snapshot_reloads_after_its_ttl_and_keeps_the_last_good_one_when_the_database_fails(
    session_factory,
):
    owner, _ = await make_user(session_factory, "owner@example.com")
    clock = FakeClock()
    factory = FlakyFactory(session_factory)
    service = _service(factory, clock=clock)
    first = await service.ensure_fresh()
    assert first is not None and factory.opened == 1
    # Within the TTL nothing is read again.
    clock.now += SiteRulesService.REFRESH_TTL_S - 1
    assert await service.ensure_fresh() is first and factory.opened == 1
    await _create(session_factory, owner, "example-casino.com")
    # Past the TTL the rows are read again and the new rule applies.
    clock.now += 2
    second = await service.ensure_fresh()
    assert second is not first and factory.opened == 2
    assert second is not None and second.verdict("example-casino.com").kind == "blocked"
    # The database fails: the last good snapshot stays, and the read is
    # retried only after five seconds (an explicit refresh always tries).
    factory.fail = True
    clock.now += SiteRulesService.REFRESH_TTL_S + 1
    assert await service.ensure_fresh() is second and factory.opened == 3
    clock.now += 1
    assert await service.ensure_fresh() is second and factory.opened == 3
    assert await service.refresh() is second and factory.opened == 4
    clock.now += SiteRulesService.RETRY_AFTER_FAILURE_S
    factory.fail = False
    third = await service.ensure_fresh()
    assert third is not second and factory.opened == 5
    assert third is not None and third.verdict("example-casino.com").kind == "blocked"


@pytest.mark.asyncio
async def test_concurrent_callers_share_one_refresh(session_factory):
    factory = FlakyFactory(session_factory)
    service = _service(factory)
    snapshots = await asyncio.gather(*(service.ensure_fresh() for _ in range(10)))
    assert factory.opened == 1
    assert snapshots[0] is not None
    assert all(snapshot is snapshots[0] for snapshot in snapshots)


@pytest.mark.asyncio
async def test_a_service_that_never_loaded_has_no_snapshot_and_its_hooks_fail_closed(session_factory):
    factory = FlakyFactory(session_factory)
    factory.fail = True
    service = _service(factory)
    assert await service.refresh() is None and service.snapshot is None
    assert await service.ensure_fresh() is None
    hook = service.guard_hook_for("ann")
    assert hook.navigation_reason("https://example.org/", exempt=False) == messages.NAVIGATION_UNAVAILABLE
    assert hook.navigation_reason("https://example.org/", exempt=True) == messages.NAVIGATION_UNAVAILABLE
    notice = hook.page_notice("https://example.org/", exempt=False)
    assert notice is not None
    assert (notice.kind, notice.rule, notice.text) == (
        "blocked",
        "site_rules_unavailable",
        messages.UNAVAILABLE_PAGE,
    )
    # A page with no web host has nothing to judge.
    assert hook.page_notice("about:blank", exempt=False) is None
    # The resolver lets the hop through: the call check already refused the call.
    seen: list[str] = []

    def inner(url: str) -> tuple[str, ...]:
        seen.append(url)
        return ("93.184.216.34",)

    assert service.wrap_resolver(inner)("https://example.org/") == ("93.184.216.34",)
    assert seen == ["https://example.org/"]


@pytest.mark.asyncio
async def test_a_switch_that_cannot_be_read_counts_as_on(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    await _create(session_factory, owner, "example-casino.com")
    switch = Switch(on=False)
    service = _service(session_factory, switch=switch)
    off = await service.ensure_fresh()
    assert off is not None and off.enabled is False
    assert off.verdict("example-casino.com").kind is None
    switch.raises = True
    on = await service.ensure_fresh()
    assert on is not None and on.enabled is True
    assert on.verdict("example-casino.com").kind == "blocked"
    # The switch is read on every call, the rows only when stale.
    switch.raises, switch.on = False, False
    reads = switch.reads
    again = await service.ensure_fresh()
    assert again is not None and again.enabled is False
    assert switch.reads == reads + 1
    assert service.snapshot is again


@pytest.mark.asyncio
async def test_a_capabilities_change_marks_the_snapshot_stale(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    factory = FlakyFactory(session_factory)
    service = _service(factory)
    first = await service.ensure_fresh()
    await _create(session_factory, owner, "example-casino.com")
    await service.on_installation_change("connectors")
    assert await service.ensure_fresh() is first and factory.opened == 1
    await service.on_installation_change("capabilities")
    fresh = await service.ensure_fresh()
    assert fresh is not first and factory.opened == 2
    assert fresh is not None and fresh.verdict("example-casino.com").kind == "blocked"


async def _hit_rows(session_factory, event: str) -> list[AuditLog]:
    async with session_factory() as db:
        result = await db.execute(
            select(AuditLog).where(AuditLog.action == event).order_by(AuditLog.seq)
        )
        return list(result.scalars().all())


@pytest.mark.asyncio
async def test_navigation_blocks_and_read_notices_are_audited_once_per_user_site_and_ten_minutes(
    session_factory,
):
    owner, _ = await make_user(session_factory, "owner@example.com")
    other, _ = await make_user(session_factory, "other@example.com")
    await _create(session_factory, owner, "example-casino.com")
    clock = FakeClock()
    service = _service(session_factory, clock=clock)
    await service.refresh()
    ann, bob = service.guard_hook_for(str(owner.id)), service.guard_hook_for(str(other.id))
    for _ in range(3):
        assert ann.navigation_reason("https://example-casino.com/?a=1", exempt=False) == (
            messages.NAVIGATION_BLOCKED
        )
        notice = ann.page_notice("https://secure.chase.com/accounts?id=7", exempt=False)
        assert notice is not None and notice.kind == "always_ask"
    assert bob.navigation_reason("https://www.example-casino.com/", exempt=False) == (
        messages.NAVIGATION_BLOCKED
    )
    await service.drain()
    blocked = await _hit_rows(session_factory, "site_rule_blocked")
    noted = await _hit_rows(session_factory, "site_rule_noted")
    # One row per user and site within the window (each user has a chain of
    # their own, so the rows are compared without an order).
    assert sorted(str(row.user_id) for row in blocked) == sorted([str(owner.id), str(other.id)])
    assert [row.user_id for row in noted] == [owner.id]
    blocked = [row for row in blocked if row.user_id == owner.id]
    assert blocked[0].status == AuditStatus.blocked and noted[0].status == AuditStatus.approved
    assert blocked[0].connector_name == "site_rules"
    assert blocked[0].request_data == {
        "where": "navigation",
        "source": "owner",
        "category": None,
        "host_hash": host_hash("example-casino.com", settings.ENCRYPTION_KEY),
        "kind": "blocked",
    }
    assert noted[0].request_data == {
        "where": "read",
        "source": "builtin",
        "category": "banks",
        "host_hash": host_hash("secure.chase.com", settings.ENCRYPTION_KEY),
        "kind": "always_ask",
    }
    for row in [*blocked, *noted]:
        dumped = _dumped(row)
        for leak in ("casino", "chase", "accounts", "id=7", "https"):
            assert leak not in dumped, (row.action, leak)
    # Ten minutes later the same site writes again.
    clock.now += SiteRulesService.AUDIT_WINDOW_S
    ann.navigation_reason("https://example-casino.com/", exempt=False)
    await service.drain()
    assert len(await _hit_rows(session_factory, "site_rule_blocked")) == 3


@pytest.mark.asyncio
async def test_a_hit_recorded_from_a_worker_thread_is_audited_on_the_services_loop(session_factory):
    owner, _ = await make_user(session_factory, "owner@example.com")
    service = _service(session_factory)
    await service.refresh()

    def from_thread() -> None:
        service.record_hit(
            user_id=str(owner.id),
            host="example-casino.com",
            kind="blocked",
            where="navigation",
            verdict=SiteVerdict("blocked", source="owner", pattern="*.example-casino.com"),
            audit=True,
        )

    await asyncio.to_thread(from_thread)
    await service.drain()
    assert len(await _hit_rows(session_factory, "site_rule_blocked")) == 1


@pytest.mark.asyncio
async def test_a_failed_hit_audit_write_is_logged_and_never_raises(session_factory, monkeypatch):
    import structlog
    from structlog.testing import capture_logs

    from services.site_rules import service as service_module

    async def broken(*_args, **_kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(service_module, "append_audit_log", broken)
    owner, _ = await make_user(session_factory, "owner@example.com")
    service = _service(session_factory)
    await service.refresh()
    with capture_logs() as logs:
        # A logger bound inside the capture (structlog caches the module's).
        monkeypatch.setattr(service_module, "logger", structlog.get_logger(service_module.__name__))
        notice = service.guard_hook_for(str(owner.id)).page_notice(
            "https://www.coinbase.com/", exempt=False
        )
        await service.drain()
    assert notice is not None and notice.kind == "always_ask"
    failed = [entry for entry in logs if entry["event"] == "site_rules_audit_failed"]
    assert failed and failed[0]["error_type"] == "RuntimeError"
    assert "coinbase" not in repr(logs)


@pytest.mark.asyncio
async def test_recent_hits_keep_the_twenty_latest_sites_with_counts_and_no_user(session_factory):
    service = _service(session_factory)
    verdict = SiteVerdict("blocked", source="owner", pattern="*.example")
    for number in range(25):
        service.record_hit(
            user_id="user-secret-id",
            host=f"site{number}.example",
            kind="blocked",
            where="navigation",
            verdict=verdict,
            audit=False,
        )
    for _ in range(2):
        service.record_hit(
            user_id="user-secret-id",
            host="site10.example",
            kind="blocked",
            where="call",
            verdict=verdict,
            audit=False,
        )
    recent = service.recent()
    assert len(recent) == SiteRulesService.RECENT_LIMIT == 20
    assert recent[0]["host"] == "site10.example"
    assert (recent[0]["count"], recent[0]["where"], recent[0]["kind"]) == (3, "call", "blocked")
    assert [hit["host"] for hit in recent[1:]] == [f"site{n}.example" for n in range(24, 10, -1)] + [
        f"site{n}.example" for n in range(9, 4, -1)
    ]
    assert set(recent[0]) == {"host", "kind", "where", "count", "last_at"}
    assert "user-secret-id" not in repr(recent)
    # The same site under another kind is its own entry; a huge host is cut.
    service.record_hit(
        user_id=None,
        host="x" * 5000 + ".example",
        kind="always_ask",
        where="read",
        verdict=SiteVerdict("always_ask", source="owner"),
        audit=True,
    )
    assert len(service.recent()[0]["host"]) <= 253
    await service.drain()
