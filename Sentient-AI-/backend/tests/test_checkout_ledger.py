"""The purchase ledger: audit rows per purchase event with their statuses
and never any card data, and the rolling 24-hour sum over every purchase
on which the card was sent (completed, pending a person, refused after
the submit with no readable outcome, or approved with no outcome on the
record), each checkout once, never over a declined one or a rule that
stopped the checkout first. Against the in-memory test database."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select, update

from models.audit import AuditLog, AuditStatus
from services.audit import append_audit_log
from services.tools.browser.checkout.ledger import PURCHASE_EVENTS, PurchaseLedger
from tests.conftest import make_user

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


async def rows_for(session_factory, user_id):
    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog).where(AuditLog.user_id == user_id).order_by(AuditLog.seq)
        )
        return list(result.scalars().all())


def row_text(row: AuditLog) -> str:
    return json.dumps(
        {
            c.name: getattr(row, c.name)
            for c in AuditLog.__table__.columns  # type: ignore[attr-defined]
        },
        default=str,
    )


@pytest.mark.asyncio
async def test_record_writes_one_row_per_event_with_its_status(session_factory):
    user, _ = await make_user(session_factory)
    ledger = PurchaseLedger(session_factory, now=lambda: NOW)
    for event in PURCHASE_EVENTS:
        await ledger.record(
            str(user.id),
            event,
            merchant="shop.example.com",
            amount_usd=Decimal("23.4"),
            currency="USD",
            items=2,
            task_id="msg-1",
            action_id="act-1" if event == "purchase_approved" else None,
            reason="over_cap" if event == "purchase_refused" else None,
            checkout_id="9f2c1a",
        )
    rows = await rows_for(session_factory, user.id)
    assert [r.action for r in rows] == list(PURCHASE_EVENTS)
    assert all(r.connector_name == "purchases" and r.scope_used == "purchases" for r in rows)
    assert [r.status for r in rows] == [
        AuditStatus.pending,
        AuditStatus.approved,
        AuditStatus.approved,
        AuditStatus.blocked,
        AuditStatus.pending,
    ]
    for row in rows:
        assert row.request_data["merchant"] == "shop.example.com"
        assert row.request_data["amount_usd"] == "23.40"
        assert row.request_data["currency"] == "USD"
        assert row.request_data["items"] == 2
        assert row.request_data["task_id"] == "msg-1"
        assert row.request_data["checkout_id"] == "9f2c1a"
        assert row.reasoning_chain["event"] == row.action
        assert set(row.request_data) <= {
            "merchant", "amount_usd", "currency", "items", "task_id", "action_id", "checkout_id",
        }
    approved, refused = rows[1], rows[3]
    assert approved.request_data["action_id"] == "act-1"
    assert refused.reasoning_chain["reason"] == "over_cap" and refused.response_summary == "over_cap"
    # Rows chain like any other audit write.
    assert rows[1].previous_hash == rows[0].integrity_hash


@pytest.mark.asyncio
async def test_rows_never_carry_card_data_however_the_caller_slips(session_factory):
    """The ledger's row shape has no field for a number, brand, last4 or
    label; a merchant or reason that smuggles a number is still
    sanitised by the audit service."""
    user, _ = await make_user(session_factory)
    ledger = PurchaseLedger(session_factory)
    await ledger.record(
        str(user.id),
        "purchase_completed",
        merchant="shop.example.com",
        amount_usd=Decimal("5"),
        currency="USD",
        items=1,
        task_id="t",
        reason="paid with 4242424242424242",
    )
    (row,) = await rows_for(session_factory, user.id)
    text = row_text(row)
    assert "4242424242424242" not in text
    assert "Visa" not in text and "last4" not in text and "label" not in text


@pytest.mark.asyncio
async def test_record_rejects_unknown_events(session_factory):
    user, _ = await make_user(session_factory)
    ledger = PurchaseLedger(session_factory)
    with pytest.raises(ValueError):
        await ledger.record(
            str(user.id), "purchase_refunded", merchant="m", amount_usd=None, currency="USD",
            items=0, task_id="t",
        )
    assert await rows_for(session_factory, user.id) == []


@pytest.mark.asyncio
async def test_spent_last_24h_sums_completed_purchases_of_the_last_day_only(session_factory):
    user, _ = await make_user(session_factory)
    other, _ = await make_user(session_factory, email="other@example.com")
    ledger = PurchaseLedger(session_factory, now=lambda: NOW)
    assert await ledger.spent_last_24h(str(user.id)) == Decimal("0")

    async def completed(user_id, amount, *, age: timedelta = timedelta(0)):
        await ledger.record(
            user_id, "purchase_completed", merchant="shop.example.com", amount_usd=amount,
            currency="USD", items=1, task_id="t",
        )
        async with session_factory() as session:
            newest = (
                await session.execute(
                    select(AuditLog.id)
                    .where(AuditLog.user_id == uuid.UUID(user_id))
                    .order_by(AuditLog.seq.desc())
                    .limit(1)
                )
            ).scalar_one()
            await session.execute(
                update(AuditLog).where(AuditLog.id == newest).values(timestamp=NOW - age)
            )
            await session.commit()

    await completed(str(user.id), Decimal("23.40"), age=timedelta(hours=2))
    await completed(str(user.id), Decimal("10.00"), age=timedelta(hours=23, minutes=59))
    await completed(str(user.id), Decimal("40.00"), age=timedelta(hours=25))  # too old
    await completed(str(other.id), Decimal("99.00"))  # someone else
    # A requested row never counts (the card has not been sent), nor an
    # approval an outcome settled (the refusal after it in the same task),
    # nor a refusal for a rule that stopped the checkout first, nor a card
    # the merchant declined.
    for event, reason in (
        ("purchase_requested", None), ("purchase_approved", None), ("purchase_refused", "over_cap"),
        ("purchase_refused", "screen_changed"), ("purchase_refused", "declined"),
        ("purchase_refused", "fill_failed"), ("purchase_refused", "cancelled"), ("purchase_refused", None),
    ):
        await ledger.record(
            str(user.id), event, merchant="shop.example.com", amount_usd=Decimal("100"),
            currency="USD", items=1, task_id="t", reason=reason,
        )
    assert await ledger.spent_last_24h(str(user.id)) == Decimal("33.40")
    assert await ledger.spent_last_24h(str(other.id)) == Decimal("99.00")


@pytest.mark.asyncio
async def test_spent_last_24h_counts_every_purchase_the_card_was_sent_on(session_factory):
    """A submit whose outcome Crawler could not read (no confirmation it
    recognised, a button that failed after the fill, a submit the network
    guard stopped: spec §6 lists all three) and a 3-D Secure step handed
    to the person may each have moved money: they count, so the daily cap
    can never fail open across repeated attempts. Only a decline, and a
    rule that stopped the checkout before the fill, are left out."""
    user, _ = await make_user(session_factory)
    ledger = PurchaseLedger(session_factory, now=lambda: NOW)
    for event, reason, amount in (
        ("purchase_refused", "no_confirmation", "23.40"),
        ("purchase_refused", "submit_failed", "5.00"),
        ("purchase_refused", "submit_blocked", "10.00"),
        ("purchase_pending_human", "otp", "1.50"),
        ("purchase_completed", None, "0.10"),
        ("purchase_refused", "declined", "70.00"),
        ("purchase_refused", "over_cap", "80.00"),
    ):
        await ledger.record(
            str(user.id), event, merchant="shop.example.com", amount_usd=Decimal(amount),
            currency="USD", items=1, task_id="t", reason=reason,
        )
    assert await ledger.spent_last_24h(str(user.id)) == Decimal("40.00")


async def backdate_newest(session_factory, user_id: str, age: timedelta) -> None:
    async with session_factory() as session:
        newest = (
            await session.execute(
                select(AuditLog.id)
                .where(AuditLog.user_id == uuid.UUID(user_id))
                .order_by(AuditLog.seq.desc())
                .limit(1)
            )
        ).scalar_one()
        await session.execute(update(AuditLog).where(AuditLog.id == newest).values(timestamp=NOW - age))
        await session.commit()


@pytest.mark.asyncio
async def test_an_approved_purchase_with_no_outcome_on_the_record_counts(session_factory):
    """The process died, or the outcome's write failed, after the card was
    submitted: the approval row is all the log has, and it counts, so the
    daily cap can never read $0 for money that may have moved."""
    user, _ = await make_user(session_factory, "ledger@example.com")
    ledger = PurchaseLedger(session_factory)
    for event in ("purchase_requested", "purchase_approved"):
        await ledger.record(
            str(user.id), event, merchant="shop", amount_usd=Decimal("23.40"), currency="USD",
            items=2, task_id="t",
        )
    assert await ledger.spent_last_24h(str(user.id)) == Decimal("23.40")


@pytest.mark.asyncio
async def test_an_approval_counts_until_its_own_outcome_settles_it_and_a_checkout_counts_once(
    session_factory,
):
    """Checkouts of one task, paired by their checkout id: an approval
    and its outcome are one purchase, counted by the outcome (declined or
    stopped before the card: nothing), and an outcome never settles
    another checkout's approval."""
    user, _ = await make_user(session_factory)
    ledger = PurchaseLedger(session_factory, now=lambda: NOW)
    for checkout_id, amount, outcome, reason in (
        ("c1", "10.00", "purchase_completed", None),
        ("c2", "70.00", "purchase_refused", "declined"),
        ("c3", "5.00", "purchase_pending_human", "otp"),
        ("c4", "2.00", "purchase_refused", "no_confirmation"),
        ("c5", "1.00", None, None),  # no outcome on the record
        ("c6", "80.00", "purchase_refused", "vault_open_failed"),
        ("c7", "90.00", "purchase_refused", "fill_failed"),
    ):
        for event, why in (("purchase_requested", None), ("purchase_approved", None), (outcome, reason)):
            if event is None:
                continue
            await ledger.record(
                str(user.id), event, merchant="shop.example.com", amount_usd=Decimal(amount),
                currency="USD", items=1, task_id="t", reason=why, checkout_id=checkout_id,
            )
    assert await ledger.spent_last_24h(str(user.id)) == Decimal("18.00")


@pytest.mark.asyncio
async def test_rows_without_a_checkout_id_are_paired_by_task_in_order(session_factory):
    user, _ = await make_user(session_factory)
    ledger = PurchaseLedger(session_factory, now=lambda: NOW)
    for task, event, amount, reason in (
        ("a", "purchase_approved", "7.00", None),
        ("a", "purchase_completed", "7.00", None),  # one purchase: 7
        ("b", "purchase_approved", "3.00", None),  # no outcome followed: 3
        ("b", "purchase_approved", "4.00", None),
        ("b", "purchase_completed", "4.00", None),  # 4
        ("c", "purchase_approved", "50.00", None),
        ("c", "purchase_refused", "50.00", "declined"),  # nothing
    ):
        await ledger.record(
            str(user.id), event, merchant="shop.example.com", amount_usd=Decimal(amount),
            currency="USD", items=1, task_id=task, reason=reason,
        )
    assert await ledger.spent_last_24h(str(user.id)) == Decimal("14.00")


@pytest.mark.asyncio
async def test_an_unsettled_approval_leaves_the_window_after_24_hours(session_factory):
    user, _ = await make_user(session_factory)
    user_id = str(user.id)
    ledger = PurchaseLedger(session_factory, now=lambda: NOW)

    async def row(event, amount, checkout_id, age):
        await ledger.record(
            user_id, event, merchant="shop.example.com", amount_usd=Decimal(amount), currency="USD",
            items=1, task_id="t", checkout_id=checkout_id,
        )
        await backdate_newest(session_factory, user_id, age)

    await row("purchase_approved", "11.00", "old", timedelta(hours=25))  # too old, no outcome
    await row("purchase_approved", "6.00", "edge", timedelta(hours=24, minutes=1))
    await row("purchase_completed", "6.00", "edge", timedelta(hours=23, minutes=59))  # counts once
    assert await ledger.spent_last_24h(user_id) == Decimal("6.00")


@pytest.mark.asyncio
async def test_spent_last_24h_skips_rows_without_a_readable_amount(session_factory):
    user, _ = await make_user(session_factory)
    async with session_factory() as session:
        for data in ({"amount_usd": "abc"}, {"amount_usd": None}, {}, {"amount_usd": "-5"}, {"amount_usd": "7.25"}):
            await append_audit_log(
                session, user_id=user.id, connector_name="purchases", action="purchase_completed",
                endpoint="agent.purchase_completed", scope_used="purchases",
                status=AuditStatus.approved, request_data=data,
            )
        await session.commit()
    ledger = PurchaseLedger(session_factory)
    assert await ledger.spent_last_24h(str(user.id)) == Decimal("7.25")


@pytest.mark.asyncio
async def test_spent_last_24h_refuses_an_unreadable_user_id(session_factory):
    ledger = PurchaseLedger(session_factory)
    with pytest.raises(ValueError):
        await ledger.spent_last_24h("not-a-uuid")
