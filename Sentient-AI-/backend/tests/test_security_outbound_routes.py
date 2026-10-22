"""Tests for Security -> Outgoing messages' routes (/api/security/outbound, security
S1): they prove the GET answers the caller's counts, own domain and the
organisation's list with no address anywhere; that a public mail service sign-in
gives no own domain; that only the owner may add or remove organisation domains;
that a public mail service, a domain ending or something that is not a domain is
refused with one plain sentence, a listed one with 409 and an unknown id with 404;
that forgetting the history removes only the caller's rows and audits a count; that
domain changes audit counts and never the domain; and that the outbound_checks switch
is an always-available policy switch, on by default, whose state the GET reports.

Why it exists: these routes are how a person sees and resets what S1 remembers about
them and how the owner says which domains are "inside". Their privacy promise
(counts only, never an address in a response or an audit row) and their owner gate
are pinned here. Everything runs against the app with the SQLite test database; no
network.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import select

from models.audit import AuditLog
from models.user import User
from services.capabilities import REGISTRY
from services.capabilities.outbound_checks import CAPABILITY
from services.installation import InstallationService
from services.security.outbound import OutboundService
from services.security.outbound_recipients import parse_recipients
from services.security.outbound_store import KnownRecipientStore, OrganisationDomainStore
from tests.conftest import auth_headers, make_user

_MISSING = object()
BASE = "/api/security/outbound"


@pytest_asyncio.fixture
async def env(client, session_factory):
    """The services main.py hangs on app.state, built on the test database."""
    from main import app

    known = KnownRecipientStore(session_factory)
    names = ("outbound", "organisation_domains", "installation")
    previous = {name: getattr(app.state, name, _MISSING) for name in names}
    app.state.outbound = OutboundService(known=known)
    app.state.organisation_domains = OrganisationDomainStore(session_factory)
    app.state.installation = InstallationService(session_factory)
    try:
        yield SimpleNamespace(app=app, known=known, client=client)
    finally:
        for name, value in previous.items():
            if value is _MISSING:
                if hasattr(app.state, name):
                    delattr(app.state, name)
            else:
                setattr(app.state, name, value)


async def owner_and_member(session_factory):
    owner, owner_token = await make_user(session_factory, "owner@northwind.example")
    async with session_factory() as session:
        row = await session.get(User, owner.id)
        assert row is not None
        row.is_admin = True
        await session.commit()
    member, member_token = await make_user(session_factory, "member@gmail.com")
    return owner, auth_headers(owner_token), member, auth_headers(member_token)


async def audit_rows(session_factory, action: str) -> list[AuditLog]:
    async with session_factory() as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars().all())


@pytest.mark.asyncio
async def test_get_returns_counts_own_domains_and_organisation_domains_without_any_address(
    env, session_factory
):
    owner, owner_headers, _member, _ = await owner_and_member(session_factory)
    await env.known.record(
        str(owner.id),
        parse_recipients(["ann@acme.example", "bob@acme.example", "carl@beta.example"]),
    )
    added = await env.client.post(
        f"{BASE}/domains", json={"domain": "Acme.CO.UK"}, headers=owner_headers
    )
    assert added.status_code == 201

    response = await env.client.get(BASE, headers=owner_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["known"]["addresses"] == 3 and body["known"]["domains"] == 2
    assert body["known"]["since"]
    assert body["own_domains"] == ["northwind.example"]
    assert [row["domain"] for row in body["organisation_domains"]] == ["acme.co.uk"]
    assert set(body["organisation_domains"][0]) == {"id", "domain", "added_at"}
    assert body["can_edit_domains"] is True and body["domain_limit"] == 50
    for fragment in ("ann", "bob", "carl", "@"):
        assert fragment not in response.text


@pytest.mark.asyncio
async def test_a_consumer_sign_in_domain_is_not_listed_as_an_own_domain(env, session_factory):
    _owner, _, _member, member_headers = await owner_and_member(session_factory)
    body = (await env.client.get(BASE, headers=member_headers)).json()
    assert body["own_domains"] == []
    assert body["can_edit_domains"] is False
    assert body["known"] == {"addresses": 0, "domains": 0, "since": None}


@pytest.mark.asyncio
async def test_only_the_owner_can_add_or_remove_organisation_domains(env, session_factory):
    _owner, owner_headers, _member, member_headers = await owner_and_member(session_factory)
    refused = await env.client.post(
        f"{BASE}/domains", json={"domain": "acme.example"}, headers=member_headers
    )
    assert refused.status_code == 403
    added = await env.client.post(
        f"{BASE}/domains", json={"domain": "acme.example"}, headers=owner_headers
    )
    assert added.status_code == 201
    domain_id = added.json()["id"]
    assert (
        await env.client.delete(f"{BASE}/domains/{domain_id}", headers=member_headers)
    ).status_code == 403
    assert (
        await env.client.delete(f"{BASE}/domains/{domain_id}", headers=owner_headers)
    ).status_code == 204
    # Anonymous callers get nothing at all.
    assert (await env.client.get(BASE)).status_code == 401
    assert (await env.client.delete(f"{BASE}/known-recipients")).status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("domain", "sentence"),
    [
        (
            "gmail.com",
            "gmail.com is a public mail service, so it cannot be your organisation's domain.",
        ),
        (
            "co.uk",
            "co.uk is a domain ending, not a domain. Enter your organisation's own, such as acme.co.uk.",
        ),
        ("acme", "Enter a domain such as acme.com."),
        ("10.0.0.1", "Enter a domain such as acme.com."),
        ("https://acme.com/x", "Enter a domain such as acme.com."),
        ("a" * 5000 + ".example", "Enter a domain such as acme.com."),
    ],
    ids=["public_mail", "ending", "one_label", "ip_address", "url", "too_long"],
)
async def test_a_consumer_or_malformed_domain_is_refused_with_a_plain_reason(
    env, session_factory, domain, sentence
):
    _owner, owner_headers, _member, _ = await owner_and_member(session_factory)
    response = await env.client.post(
        f"{BASE}/domains", json={"domain": domain}, headers=owner_headers
    )
    assert response.status_code == 422
    assert response.json() == {"detail": sentence}


@pytest.mark.asyncio
async def test_a_listed_domain_is_refused_as_a_conflict(env, session_factory):
    _owner, owner_headers, _member, _ = await owner_and_member(session_factory)
    first = await env.client.post(
        f"{BASE}/domains", json={"domain": "@acme.co.uk"}, headers=owner_headers
    )
    assert first.status_code == 201 and first.json()["domain"] == "acme.co.uk"
    again = await env.client.post(
        f"{BASE}/domains", json={"domain": "ACME.co.uk"}, headers=owner_headers
    )
    assert again.status_code == 409
    assert again.json() == {"detail": "acme.co.uk is already listed."}


@pytest.mark.asyncio
async def test_removing_an_unknown_domain_is_a_404(env, session_factory):
    _owner, owner_headers, _member, _ = await owner_and_member(session_factory)
    for missing in (str(uuid.uuid4()), "not-an-id"):
        response = await env.client.delete(f"{BASE}/domains/{missing}", headers=owner_headers)
        assert response.status_code == 404
        assert response.json() == {"detail": "No such domain."}


@pytest.mark.asyncio
async def test_forgetting_the_history_removes_only_the_callers_rows_and_audits_a_count(
    env, session_factory
):
    owner, owner_headers, member, _member_headers = await owner_and_member(session_factory)
    await env.known.record(
        str(owner.id), parse_recipients(["ann@acme.example", "bob@beta.example"])
    )
    await env.known.record(str(member.id), parse_recipients(["carl@crane.example"]))
    response = await env.client.delete(f"{BASE}/known-recipients", headers=owner_headers)
    assert response.status_code == 200 and response.json() == {"removed": 4}
    assert (await env.known.summary(str(owner.id))).addresses == 0
    assert (await env.known.summary(str(member.id))).addresses == 1

    [row] = await audit_rows(session_factory, "known_recipients_cleared")
    assert row.user_id == owner.id
    assert row.request_data == {"rows": 4}
    assert row.reasoning_chain == {"event": "known_recipients_cleared"}
    assert row.status.value == "approved"
    for fragment in ("ann", "acme", "bob", "@"):
        assert fragment not in str(row.request_data) + str(row.reasoning_chain)


@pytest.mark.asyncio
async def test_domain_changes_audit_counts_and_never_the_domain(env, session_factory):
    owner, owner_headers, _member, _ = await owner_and_member(session_factory)
    one = await env.client.post(
        f"{BASE}/domains", json={"domain": "acme.co.uk"}, headers=owner_headers
    )
    await env.client.post(f"{BASE}/domains", json={"domain": "beta.example"}, headers=owner_headers)
    await env.client.delete(f"{BASE}/domains/{one.json()['id']}", headers=owner_headers)
    # A refused add writes nothing.
    await env.client.post(f"{BASE}/domains", json={"domain": "gmail.com"}, headers=owner_headers)

    rows = await audit_rows(session_factory, "outbound_domains_changed")
    assert [row.request_data for row in rows] == [
        {"added": 1, "removed": 0, "total": 1},
        {"added": 1, "removed": 0, "total": 2},
        {"added": 0, "removed": 1, "total": 1},
    ]
    for row in rows:
        assert row.user_id == owner.id
        text = str(row.request_data) + str(row.reasoning_chain) + str(row.response_summary)
        assert "acme" not in text and "beta" not in text


@pytest.mark.asyncio
async def test_the_outbound_checks_switch_is_an_always_available_policy_switch_on_by_default(
    env, session_factory
):
    assert CAPABILITY.key == "outbound_checks"
    assert CAPABILITY.tools == ()
    assert CAPABILITY.default_enabled is True and CAPABILITY.risk == "low"
    assert "hidden characters are still removed" in CAPABILITY.when_denied
    assert CAPABILITY in REGISTRY
    installation = env.app.state.installation
    assert "outbound_checks" in await installation.enabled_keys()

    owner, owner_headers, _member, member_headers = await owner_and_member(session_factory)
    await installation.set_capabilities({"outbound_checks": False}, actor_id=owner.id)
    assert (await env.client.get(BASE, headers=member_headers)).json()["enabled"] is False
    await installation.set_capabilities({"outbound_checks": True}, actor_id=owner.id)
    assert (await env.client.get(BASE, headers=owner_headers)).json()["enabled"] is True


@pytest.mark.asyncio
async def test_the_routes_answer_503_until_the_services_are_wired(client, session_factory):
    from main import app

    _owner, owner_headers, _member, _ = await owner_and_member(session_factory)
    saved = {
        name: getattr(app.state, name, _MISSING) for name in ("outbound", "organisation_domains")
    }
    for name in saved:
        if hasattr(app.state, name):
            delattr(app.state, name)
    try:
        response = await client.get(BASE, headers=owner_headers)
        assert response.status_code == 503
        assert response.json() == {"detail": "The server is still starting. Try again shortly."}
    finally:
        for name, value in saved.items():
            if value is not _MISSING:
                setattr(app.state, name, value)
