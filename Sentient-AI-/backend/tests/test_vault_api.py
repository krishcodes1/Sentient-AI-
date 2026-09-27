"""The card Settings API (/api/vault): owner-only, store only from the
machine Crawler runs on, 422 for a bad number or an expired card, 409 with
the reason where there is no key store, masked views only, and audit rows
that name the item by its masked label and nothing else. The key is a dev
file in tmp_path; no OS store is touched."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

from models.audit import AuditLog
from models.user import User
from services.vault.keys import DevFileKeyProvider, DisabledKeyProvider
from services.vault.service import VaultService
from tests.conftest import auth_headers, make_user

NUMBER = "4242 4242 4242 4242"
DIGITS = "4242424242424242"
CVC = "123"
CARD = {"label": "Blue Visa", "number": NUMBER, "exp_month": 12, "exp_year": 2099, "cvc": CVC, "name": "Krish Q"}


@pytest_asyncio.fixture
async def vault(session_factory, tmp_path):
    from main import app

    service = VaultService(session_factory, DevFileKeyProvider(tmp_path / "dev.key"))
    app.state.vault = service
    yield service
    try:
        del app.state.vault
    except AttributeError:
        pass


@pytest_asyncio.fixture
async def local_client(session_factory):
    """The conftest client, but with a loopback peer: the card form is only
    served on the owner's machine, and the store route checks the peer.
    A distinct 127.x address per client keeps rate-limit buckets apart."""
    from core.database import get_db
    from main import app

    async def _override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db
    peer = f"127.0.0.{uuid.uuid4().int % 254 + 1}"
    transport = httpx.ASGITransport(app=app, client=(peer, 54321))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client
    app.dependency_overrides.clear()


async def _make_owner(session_factory):
    user, token = await make_user(session_factory, "owner@example.com")
    async with session_factory() as session:
        row = await session.get(User, user.id)
        row.is_admin = True
        await session.commit()
    return str(user.id), auth_headers(token)


@pytest_asyncio.fixture
async def owner(session_factory):
    return await _make_owner(session_factory)


@pytest_asyncio.fixture
async def guest(session_factory):
    _user, token = await make_user(session_factory, "guest@example.com")
    return auth_headers(token)


async def _audit_rows(session_factory, user_id: str) -> list[AuditLog]:
    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == uuid.UUID(user_id))
            .where(AuditLog.connector_name == "vault")
            .order_by(AuditLog.seq)
        )
        return list(result.scalars())


def _row_text(row: AuditLog) -> str:
    return json.dumps(
        {
            "request_data": row.request_data,
            "response_summary": row.response_summary,
            "reasoning_chain": row.reasoning_chain,
            "action": row.action,
            "endpoint": row.endpoint,
        },
        default=str,
    )


# -- GET ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_is_empty_and_available_at_first(local_client, vault, owner):
    _uid, headers = owner
    resp = await local_client.get("/api/vault/items", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"items": [], "available": True, "reason": ""}


@pytest.mark.asyncio
async def test_list_is_owner_only(local_client, vault, guest):
    assert (await local_client.get("/api/vault/items", headers=guest)).status_code == 403
    assert (await local_client.get("/api/vault/items")).status_code in (401, 403)


@pytest.mark.asyncio
async def test_missing_vault_service_is_503(local_client, owner):
    _uid, headers = owner
    resp = await local_client.get("/api/vault/items", headers=headers)
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_list_reports_why_the_vault_is_unavailable(local_client, session_factory, owner):
    from main import app

    _uid, headers = owner
    app.state.vault = VaultService(
        session_factory, DisabledKeyProvider("The card vault is not available in this environment (container).")
    )
    try:
        resp = await local_client.get("/api/vault/items", headers=headers)
    finally:
        del app.state.vault
    assert resp.status_code == 200
    assert resp.json()["available"] is False and "(container)" in resp.json()["reason"]


# -- PUT ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_card_returns_the_masked_view_only(local_client, vault, owner, session_factory):
    uid, headers = owner
    resp = await local_client.put("/api/vault/card", json=CARD, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kind"] == "card" and body["label"] == "Blue Visa"
    assert body["masked"] == "Visa ····4242" and body["brand"] == "Visa" and body["last4"] == "4242"
    assert body["last_used_at"] is None and body["origins"] == []
    assert DIGITS not in resp.text and NUMBER not in resp.text and CVC not in resp.text
    assert "Krish" not in resp.text

    listed = await local_client.get("/api/vault/items", headers=headers)
    assert [item["id"] for item in listed.json()["items"]] == [body["id"]]
    assert DIGITS not in listed.text

    rows = await _audit_rows(session_factory, uid)
    assert [r.action for r in rows] == ["vault_card_stored"]
    assert rows[0].request_data == {"kind": "card", "label": "Blue Visa", "masked": "Visa ····4242"}
    assert rows[0].scope_used == "admin" and rows[0].status.value == "approved"
    assert DIGITS not in _row_text(rows[0]) and CVC not in _row_text(rows[0])


@pytest.mark.asyncio
async def test_store_replaces_the_previous_card(local_client, vault, owner):
    _uid, headers = owner
    first = (await local_client.put("/api/vault/card", json=CARD, headers=headers)).json()
    second = (
        await local_client.put(
            "/api/vault/card", json={**CARD, "number": "5555555555554444"}, headers=headers
        )
    ).json()
    items = (await local_client.get("/api/vault/items", headers=headers)).json()["items"]
    assert [i["id"] for i in items] == [second["id"]] and second["id"] != first["id"]
    assert items[0]["masked"] == "Mastercard ····4444"


@pytest.mark.asyncio
async def test_store_is_owner_only(local_client, vault, guest):
    resp = await local_client.put("/api/vault/card", json=CARD, headers=guest)
    assert resp.status_code == 403
    assert DIGITS not in resp.text


@pytest.mark.asyncio
async def test_store_is_refused_from_any_peer_but_this_machine(client, vault, owner):
    # The conftest client's peer is 198.51.100.x: another machine on the LAN.
    _uid, headers = owner
    resp = await client.put("/api/vault/card", json=CARD, headers=headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["code"] == "localhost_only"
    assert DIGITS not in resp.text
    listed = await client.get("/api/vault/items", headers=headers)
    assert listed.json()["items"] == []  # reads still work from anywhere the owner signs in


@pytest.mark.parametrize(
    "patch, fragment",
    [
        ({"number": "4242424242424241"}, "valid card number"),
        ({"number": "4242 abcd 4242 4242"}, "only contain digits"),
        ({"number": "4" * 40}, "valid card number"),
        ({"exp_year": 2020}, "expired"),
        ({"exp_month": 13}, "between 1 and 12"),
        ({"cvc": "1"}, "3 or 4 digits"),
        ({"name": ""}, "name as it appears"),
    ],
)
@pytest.mark.asyncio
async def test_store_rejects_a_bad_card_without_echoing_it(
    local_client, vault, owner, patch, fragment
):
    _uid, headers = owner
    body = {**CARD, **patch}
    resp = await local_client.put("/api/vault/card", json=body, headers=headers)
    assert resp.status_code == 422, resp.text
    assert fragment in resp.json()["detail"]
    assert body["number"] not in resp.text and body["cvc"] not in resp.text
    assert (await local_client.get("/api/vault/items", headers=headers)).json()["items"] == []


@pytest.mark.asyncio
async def test_store_with_a_missing_or_mistyped_field_never_echoes_the_body(
    local_client, vault, owner
):
    _uid, headers = owner
    body = {"number": NUMBER, "cvc": CVC, "exp_month": "12", "exp_year": 2099, "name": "K"}
    resp = await local_client.put("/api/vault/card", json=body, headers=headers)
    assert resp.status_code == 422
    assert NUMBER not in resp.text and DIGITS not in resp.text and CVC not in resp.text
    assert any(err["loc"][-1] == "exp_month" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_store_is_409_where_there_is_no_key_store(local_client, session_factory, owner):
    from main import app

    uid, headers = owner
    reason = "The card vault is not available in this environment (container)."
    app.state.vault = VaultService(session_factory, DisabledKeyProvider(reason))
    try:
        resp = await local_client.put("/api/vault/card", json=CARD, headers=headers)
    finally:
        del app.state.vault
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"] == {"message": reason, "code": "vault_unavailable"}
    assert DIGITS not in resp.text
    assert await _audit_rows(session_factory, uid) == []


# -- DELETE --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_item(local_client, vault, owner, session_factory):
    uid, headers = owner
    stored = (await local_client.put("/api/vault/card", json=CARD, headers=headers)).json()
    resp = await local_client.delete(f"/api/vault/items/{stored['id']}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert (await local_client.get("/api/vault/items", headers=headers)).json()["items"] == []
    assert (await local_client.delete(f"/api/vault/items/{stored['id']}", headers=headers)).status_code == 404
    assert (await local_client.delete("/api/vault/items/not-an-id", headers=headers)).status_code == 404

    rows = await _audit_rows(session_factory, uid)
    assert [r.action for r in rows] == ["vault_card_stored", "vault_item_deleted"]
    assert rows[1].request_data == {"kind": "card", "label": "Blue Visa", "masked": "Visa ····4242"}
    assert all(DIGITS not in _row_text(r) and CVC not in _row_text(r) for r in rows)


@pytest.mark.asyncio
async def test_delete_is_owner_only_and_per_owner(local_client, vault, owner, guest, session_factory):
    _uid, headers = owner
    stored = (await local_client.put("/api/vault/card", json=CARD, headers=headers)).json()
    assert (await local_client.delete(f"/api/vault/items/{stored['id']}", headers=guest)).status_code == 403
    # A second owner cannot remove the first owner's card by id either.
    other_user, other_token = await make_user(session_factory, "second-owner@example.com")
    async with session_factory() as session:
        row = await session.get(User, other_user.id)
        row.is_admin = True
        await session.commit()
    resp = await local_client.delete(
        f"/api/vault/items/{stored['id']}", headers=auth_headers(other_token)
    )
    assert resp.status_code == 404
    assert len((await local_client.get("/api/vault/items", headers=headers)).json()["items"]) == 1
