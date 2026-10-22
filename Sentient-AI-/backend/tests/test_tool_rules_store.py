"""Tests for where the tool rules live (services/security/tool_rules/store.py): they prove a
rule the owner adds is stored, listed oldest first and read back by a fresh store; that adding
and removing a rule each write one audit row carrying ids, names, argument and operator names
and a digest but never a condition value; that a built-in rule's row is written only when the
owner changes it (no row reads as on) and unknown keys in the table are ignored; that the
snapshot is cached and every write through the store drops the cache at once; that a database
that cannot be read answers an error snapshot (so every write asks) instead of raising; that a
stored row today's validator refuses still asks before every write its glob covers; that two
requests racing for the last of the 50 places store only one rule; and that removing the
account that made a rule keeps the rule with ``created_by`` cleared.

Why it exists: the call check reads this snapshot before every tool call, and a store that
lost a rule, raised, or served a stale cache after the owner's change would let a call run
unasked. The audit rows are what the owner reads after a suspicious change, and they must not
leak a third party's address from an ``in_list`` or ``domain_in`` value. SQLite through the
shared ``session_factory`` fixture (Postgres when TEST_DATABASE_URL is set).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import pytest
from sqlalchemy import delete, select

from models.audit import AuditLog
from models.tool_rule import ToolRule, ToolRuleBuiltin
from models.user import User
from services.agent.permissions import ActionCategory
from services.security.tool_rules import DbToolRuleStore, InMemoryToolRuleStore, texts
from services.security.tool_rules.builtins import BUILTIN_KEYS, MANY_RECIPIENTS, UNTRUSTED_LINK
from services.security.tool_rules.engine import CallView, Condition, evaluate
from services.security.tool_rules.grammar import (
    MAX_RULES,
    RuleDraft,
    RuleValidationError,
    rule_digest,
    validate_rule,
)
from services.security.tool_rules.store import (
    AUDIT_ENDPOINT,
    EVENT_BUILTIN_CHANGED,
    EVENT_CREATED,
    EVENT_DELETED,
)
from tests.conftest import make_user

# Condition values that must never reach an audit row: a third party's address and domains, and
# the owner's pattern.
SECRET_ADDRESS = "partner.person@vendor-billing.example"
SECRET_DOMAIN = "rival-supplier.example"
SECRET_PATTERN = r"wire\s?transfer"


class Clock:
    """A monotonic clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def draft(name: str = "Big mailings", tool: str = "google_workspace.send_email", conditions: Any = None) -> RuleDraft:
    """A draft the validator accepts (the routes validate before the store re-checks it)."""
    if conditions is None:
        conditions = [
            {"arg": "to", "op": "in_list", "value": [SECRET_ADDRESS]},
            {"arg": "to", "op": "domain_in", "value": [SECRET_DOMAIN]},
            {"arg": "body", "op": "regex", "value": SECRET_PATTERN},
        ]
    return validate_rule(name, tool, conditions, existing=[])


async def owner(session_factory) -> User:
    user, _token = await make_user(session_factory, f"owner-{uuid.uuid4().hex[:8]}@example.com")
    return user


async def audit_rows(session_factory, action: Optional[str] = None) -> list[AuditLog]:
    async with session_factory() as session:
        stmt = select(AuditLog).order_by(AuditLog.seq)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        return list((await session.execute(stmt)).scalars())


def write_call(arguments: dict[str, Any], canonical: str = "google_workspace.send_email") -> CallView:
    return CallView(canonical, arguments, ActionCategory.WRITE, False, ("to",), False)


# ---------------------------------------------------------------------------
# Rules: create, list, read back
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_created_rule_is_listed_oldest_first_and_read_back_by_a_new_store(session_factory):
    user = await owner(session_factory)
    store = DbToolRuleStore(session_factory)
    first = await store.create(str(user.id), draft("Big mailings"))
    second = await store.create(
        str(user.id),
        draft("Large refunds", "mcp.stripe.*", [{"arg": "amount", "op": "number_gt", "value": 500}]),
    )
    assert uuid.UUID(first.id) and first.created_by == str(user.id)
    assert [r.name for r in await store.list_rules()] == ["Big mailings", "Large refunds"]

    # Another process (a fresh store) reads the same rules back, validated again and in order.
    fresh = DbToolRuleStore(session_factory)
    listed = await fresh.list_rules()
    assert [(r.id, r.name, r.tool) for r in listed] == [
        (first.id, "Big mailings", "google_workspace.send_email"),
        (second.id, "Large refunds", "mcp.stripe.*"),
    ]
    assert listed[0].conditions == first.conditions
    assert listed[1].conditions == (Condition("amount", "number_gt", 500.0),)
    assert all(not r.unreadable for r in listed)
    snapshot = await fresh.snapshot()
    assert not snapshot.error and snapshot.builtins_off == frozenset()
    assert [r.id for r in snapshot.owner_rules] == [first.id, second.id]

    # The stored JSON keeps lists as lists and whole numbers as numbers.
    async with session_factory() as session:
        row = await session.get(ToolRule, uuid.UUID(second.id))
        assert row is not None and row.conditions == [{"arg": "amount", "op": "number_gt", "value": 500}]


@pytest.mark.asyncio
async def test_rules_made_in_the_same_clock_instant_still_list_in_the_order_they_were_made(session_factory, monkeypatch):
    # The Windows clock can answer the same instant twice; rules are evaluated (and their notes
    # shown) oldest first, so the order must not fall back to the random ids.
    import services.security.tool_rules.store as store_module

    frozen = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(store_module, "_now", lambda: frozen)
    user = await owner(session_factory)
    store = DbToolRuleStore(session_factory)
    made = [
        await store.create(str(user.id), draft(f"Rule {index}", f"mcp.server{index}.*", []))
        for index in range(6)
    ]
    assert [r.id for r in await DbToolRuleStore(session_factory).list_rules()] == [r.id for r in made]
    memory = InMemoryToolRuleStore()
    kept = [await memory.create("o", draft(f"Rule {index}", f"mcp.s{index}.*", [])) for index in range(3)]
    assert [r.created_at for r in kept] == sorted({r.created_at for r in kept})


@pytest.mark.asyncio
async def test_the_store_checks_a_draft_again_so_a_duplicate_or_a_taken_name_is_refused(session_factory):
    user = await owner(session_factory)
    store = DbToolRuleStore(session_factory)
    await store.create(str(user.id), draft("Big mailings"))
    with pytest.raises(RuleValidationError) as caught:
        await store.create(str(user.id), draft("Big mailings"))
    assert str(caught.value) == texts.NAME_TAKEN
    with pytest.raises(RuleValidationError) as caught:
        await store.create(str(user.id), draft("Another name"))
    assert str(caught.value) == texts.identical_rule("Big mailings")
    assert len(await store.list_rules()) == 1
    assert len(await audit_rows(session_factory, EVENT_CREATED)) == 1


@pytest.mark.asyncio
async def test_two_requests_racing_for_the_last_place_store_only_one_rule(session_factory):
    user = await owner(session_factory)
    store = DbToolRuleStore(session_factory)
    async with session_factory() as session:
        for index in range(MAX_RULES - 1):
            session.add(
                ToolRule(
                    name=f"Rule {index}",
                    tool_pattern=f"mcp.server{index}.*",
                    conditions=[],
                    created_by=user.id,
                    created_at=datetime.now(timezone.utc),
                )
            )
        await session.commit()
    # Both drafts were validated against 49 rules (as two routes would have); only one fits.
    results = await asyncio.gather(
        store.create(str(user.id), draft("Last one A", "mcp.a.*", [])),
        store.create(str(user.id), draft("Last one B", "mcp.b.*", [])),
        return_exceptions=True,
    )
    refused = [r for r in results if isinstance(r, RuleValidationError)]
    assert len(refused) == 1 and str(refused[0]) == texts.TOO_MANY_RULES
    assert len(await store.list_rules()) == MAX_RULES


# ---------------------------------------------------------------------------
# Audit rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_creating_and_deleting_a_rule_write_audit_rows_with_a_digest_and_no_condition_values(session_factory):
    user = await owner(session_factory)
    store = DbToolRuleStore(session_factory)
    created = await store.create(str(user.id), draft("Big mailings"))
    removed = await store.delete(str(user.id), created.id)
    assert removed is not None and removed.id == created.id
    assert await store.list_rules() == []
    assert await store.delete(str(user.id), created.id) is None  # already gone: nothing written
    assert await store.delete(str(user.id), "not-a-uuid") is None

    rows = await audit_rows(session_factory)
    assert [r.action for r in rows] == [EVENT_CREATED, EVENT_DELETED]
    expected = {
        "rule_id": created.id,
        "name": "Big mailings",
        "tool": "google_workspace.send_email",
        "args": ["to", "to", "body"],
        "ops": ["in_list", "domain_in", "regex"],
        "digest": rule_digest(created),
    }
    for row in rows:
        assert row.request_data == expected
        assert row.user_id == user.id
        assert row.connector_name == "agent" and row.endpoint == AUDIT_ENDPOINT
        assert row.status.value == "approved"
        stored = f"{row.request_data} {row.reasoning_chain} {row.response_summary}"
        for value in (SECRET_ADDRESS, SECRET_DOMAIN, "vendor-billing", "wire", "transfer"):
            assert value not in stored
    assert len(expected["digest"]) == 16


@pytest.mark.asyncio
async def test_a_builtin_row_is_written_only_when_the_owner_changes_it_and_no_row_reads_as_on(session_factory):
    user = await owner(session_factory)
    store = DbToolRuleStore(session_factory)
    states = await store.builtin_states()
    assert list(states) == list(BUILTIN_KEYS)
    assert all(on and changed_at is None for on, changed_at in states.values())

    # Turning on a rule that is already on changes nothing and writes nothing.
    assert await store.set_builtin(str(user.id), MANY_RECIPIENTS, True) is False
    async with session_factory() as session:
        assert (await session.execute(select(ToolRuleBuiltin))).scalars().all() == []
    assert await audit_rows(session_factory) == []

    assert await store.set_builtin(str(user.id), MANY_RECIPIENTS, False) is True
    assert await store.set_builtin(str(user.id), MANY_RECIPIENTS, False) is False
    on, changed_at = (await store.builtin_states())[MANY_RECIPIENTS]
    assert on is False and changed_at is not None
    assert (await store.snapshot()).builtins_off == frozenset({MANY_RECIPIENTS})

    assert await store.set_builtin(str(user.id), MANY_RECIPIENTS, True) is True
    async with session_factory() as session:
        [row] = (await session.execute(select(ToolRuleBuiltin))).scalars().all()
        assert (row.key, row.enabled, row.changed_by) == (MANY_RECIPIENTS, True, user.id)
    rows = await audit_rows(session_factory, EVENT_BUILTIN_CHANGED)
    assert [r.request_data for r in rows] == [
        {"key": MANY_RECIPIENTS, "enabled": False},
        {"key": MANY_RECIPIENTS, "enabled": True},
    ]
    with pytest.raises(KeyError):
        await store.set_builtin(str(user.id), "no_such_rule", False)


@pytest.mark.asyncio
async def test_unknown_builtin_keys_in_the_table_are_ignored(session_factory):
    async with session_factory() as session:
        session.add(ToolRuleBuiltin(key="retired_rule", enabled=False, changed_at=datetime.now(timezone.utc)))
        session.add(ToolRuleBuiltin(key=UNTRUSTED_LINK, enabled=False, changed_at=datetime.now(timezone.utc)))
        await session.commit()
    store = DbToolRuleStore(session_factory)
    states = await store.builtin_states()
    assert "retired_rule" not in states and states[UNTRUSTED_LINK][0] is False
    assert (await store.snapshot()).builtins_off == frozenset({UNTRUSTED_LINK})


# ---------------------------------------------------------------------------
# Snapshot cache and failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_snapshot_is_cached_and_a_write_through_the_store_refreshes_it_at_once(session_factory):
    user = await owner(session_factory)
    clock = Clock()
    store = DbToolRuleStore(session_factory, clock=clock)
    other_process = DbToolRuleStore(session_factory)
    assert (await store.snapshot()).owner_rules == ()

    # A rule written by another process is not seen until the 30 s cache runs out...
    await other_process.create(str(user.id), draft("From elsewhere", "mcp.a.*", []))
    clock.now += 29.0
    assert (await store.snapshot()).owner_rules == ()
    clock.now += 1.5
    assert [r.name for r in (await store.snapshot()).owner_rules] == ["From elsewhere"]

    # ...but every write through this store drops the cache at once.
    await store.create(str(user.id), draft("Mine", "mcp.b.*", []))
    assert [r.name for r in (await store.snapshot()).owner_rules] == ["From elsewhere", "Mine"]
    await store.set_builtin(str(user.id), MANY_RECIPIENTS, False)
    assert (await store.snapshot()).builtins_off == frozenset({MANY_RECIPIENTS})
    [mine] = [r for r in await store.list_rules() if r.name == "Mine"]
    await store.delete(str(user.id), mine.id)
    assert [r.name for r in (await store.snapshot()).owner_rules] == ["From elsewhere"]
    store.invalidate()
    assert [r.name for r in (await store.snapshot()).owner_rules] == ["From elsewhere"]


class _BrokenSession:
    async def __aenter__(self) -> Any:
        raise ConnectionError("database unreachable")

    async def __aexit__(self, *exc: Any) -> None:
        return None


@pytest.mark.asyncio
async def test_a_database_error_answers_an_error_snapshot_rather_than_raising(session_factory):
    broken = {"on": True}

    def factory() -> Any:
        return _BrokenSession() if broken["on"] else session_factory()

    store = DbToolRuleStore(factory)  # type: ignore[arg-type]
    snapshot = await store.snapshot()
    assert snapshot.error is True and snapshot.owner_rules == ()

    # The error snapshot makes every write ask, with every built-in counted as on.
    hits = evaluate(write_call({"to": "ann@example.com"}), snapshot, turn=None, org_domains=frozenset())
    assert [h.rule_id for h in hits] == ["tool_rules:unavailable"]
    assert hits[0].note == texts.UNAVAILABLE_NOTE

    # The routes' reads raise instead (they answer store_ok false), and nothing is written.
    with pytest.raises(ConnectionError):
        await store.list_rules()
    with pytest.raises(ConnectionError):
        await store.builtin_states()

    # An error is never cached: once the database is back, the next read sees it.
    broken["on"] = False
    assert (await store.snapshot()).error is False


@pytest.mark.asyncio
async def test_a_stored_row_todays_validator_refuses_asks_before_every_write_its_glob_covers(session_factory):
    async with session_factory() as session:
        session.add(
            ToolRule(
                name="Old pattern",
                tool_pattern="mcp.stripe.*",
                conditions=[{"arg": "memo", "op": "regex", "value": r".*(?:a{50}){50}b"}],
                created_at=datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc),
            )
        )
        session.add(
            ToolRule(
                name="pay bob@evil.example",  # a hand-edited name: never shown as written
                tool_pattern="google_workspace.send_email",
                conditions=[{"arg": "to", "op": "bogus", "value": 1}],
                created_at=datetime(2026, 10, 14, 12, 5, tzinfo=timezone.utc),
            )
        )
        await session.commit()
    store = DbToolRuleStore(session_factory)
    snapshot = await store.snapshot()
    assert not snapshot.error
    old, hand_edited = snapshot.owner_rules
    assert old.unreadable and old.tool == "mcp.stripe.*" and old.conditions == ()
    assert hand_edited.unreadable and hand_edited.name == texts.UNREADABLE_RULE_NAME

    refund = CallView("mcp.stripe.refund", {"memo": "a" * 4000}, None, True)
    [hit] = evaluate(refund, snapshot, turn=None, org_domains=frozenset())
    assert hit.rule_id == f"owner:{old.id}"
    assert hit.note == texts.rule_failed_note("Old pattern", owner=True)
    # A read the glob covers goes on, as with an unreadable store.
    lookup = CallView("mcp.stripe.refund", {}, ActionCategory.READ, False)
    assert evaluate(lookup, snapshot, turn=None, org_domains=frozenset()) == ()
    # The page lists it (with the placeholder name) so the owner can remove it.
    assert [r.name for r in await store.list_rules()] == ["Old pattern", texts.UNREADABLE_RULE_NAME]


@pytest.mark.asyncio
async def test_deleting_the_creating_account_keeps_the_rule_with_created_by_cleared(session_factory):
    user = await owner(session_factory)
    store = DbToolRuleStore(session_factory)
    rule = await store.create(str(user.id), draft("Big mailings"))
    await store.set_builtin(str(user.id), MANY_RECIPIENTS, False)
    async with session_factory() as session:
        await session.execute(delete(AuditLog).where(AuditLog.user_id == user.id))
        await session.execute(delete(User).where(User.id == user.id))
        await session.commit()
    fresh = DbToolRuleStore(session_factory)
    [kept] = await fresh.list_rules()
    assert (kept.id, kept.name, kept.created_by) == (rule.id, "Big mailings", None)
    async with session_factory() as session:
        builtin_row = await session.get(ToolRuleBuiltin, MANY_RECIPIENTS)
        assert builtin_row is not None and builtin_row.changed_by is None and builtin_row.enabled is False
    assert (await fresh.snapshot()).builtins_off == frozenset({MANY_RECIPIENTS})


# ---------------------------------------------------------------------------
# The in-memory store keeps the same contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_in_memory_store_keeps_the_same_contract_for_tests_and_an_unwired_runtime():
    store = InMemoryToolRuleStore()
    created = await store.create("owner-1", draft("Big mailings"))
    assert [r.id for r in (await store.snapshot()).owner_rules] == [created.id]
    with pytest.raises(RuleValidationError):
        await store.create("owner-1", draft("Big mailings"))
    assert await store.set_builtin("owner-1", MANY_RECIPIENTS, True) is False
    assert await store.set_builtin("owner-1", MANY_RECIPIENTS, False) is True
    assert (await store.snapshot()).builtins_off == frozenset({MANY_RECIPIENTS})
    assert (await store.delete("owner-1", created.id)) == created
    assert await store.delete("owner-1", created.id) is None
    assert [entry["event"] for entry in store.audit] == [EVENT_CREATED, EVENT_BUILTIN_CHANGED, EVENT_DELETED]
    assert SECRET_ADDRESS not in str(store.audit)

    down = InMemoryToolRuleStore(error=True)
    assert (await down.snapshot()).error is True
    with pytest.raises(RuntimeError):
        await down.list_rules()
