"""Tests for the two connector routes the guided connect flow relies on:
``GET /api/connectors/canvas/schools`` ("find your school") and the identity
``POST /api/connectors/{id}/test`` reports after a save ("Connected to
<account> as <user>").

Why it exists: the school search calls a third party for any signed-in user,
so it must be rate limited per user, validate its query and fail with one
plain message; the test route must report an identity only when the health
check really learned one.

Connects to: ``api/routes/connectors.py``, ``services/connectors/canvas_schools.py``
and the Slack connector's health check. No external service is contacted:
the school search is replaced, and the connector's HTTP goes to a mock.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest

from api.routes import connectors as connector_routes
from api.routes.agent import UserRateLimiter
from core.security import encrypt_credentials
from models.connector import AuthMethod, ConnectorConfig
from services.connectors import canvas_schools
from services.connectors.canvas_schools import CanvasSchool, SchoolSearchError
from tests.conftest import auth_headers, make_user

SCHOOLS = "/api/connectors/canvas/schools"
SEARCH_FAILED = (
    "School search is not working right now. Type your school's Canvas address instead."
)


@pytest.fixture(autouse=True)
def fresh_limiter(monkeypatch):
    monkeypatch.setattr(connector_routes, "_school_search_limiter", UserRateLimiter())


@pytest.fixture
def searches(monkeypatch) -> list[str]:
    """Replace the directory search; records the queries it was given."""
    queries: list[str] = []

    async def fake_search(query: str, *, transport: Any = None) -> list[CanvasSchool]:
        queries.append(query)
        return [
            CanvasSchool(name="NYIT", domain="nyit.instructure.com"),
            CanvasSchool(name="NYU", domain="nyu.instructure.com"),
        ]

    monkeypatch.setattr(canvas_schools, "search_schools", fake_search)
    return queries


# ---------------------------------------------------------------------------
# GET /api/connectors/canvas/schools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_school_search_returns_names_and_domains(client, session_factory, searches):
    _, token = await make_user(session_factory, "schools@example.com")

    response = await client.get(SCHOOLS, params={"q": "  ny  "}, headers=auth_headers(token))

    assert response.status_code == 200
    assert response.json() == [
        {"name": "NYIT", "domain": "nyit.instructure.com"},
        {"name": "NYU", "domain": "nyu.instructure.com"},
    ]
    assert searches == ["ny"]  # stripped before the search


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [{"q": "a"}, {"q": "   a   "}, {"q": "x" * 101}, {}])
async def test_school_search_rejects_a_query_out_of_bounds(
    client, session_factory, searches, params
):
    _, token = await make_user(session_factory, "schools-422@example.com")

    response = await client.get(SCHOOLS, params=params, headers=auth_headers(token))

    assert response.status_code == 422
    assert searches == []


@pytest.mark.asyncio
async def test_school_search_is_rate_limited_per_user(client, session_factory, searches):
    _, token = await make_user(session_factory, "schools-429@example.com")
    _, other = await make_user(session_factory, "schools-other@example.com")

    for _ in range(connector_routes.SCHOOL_SEARCHES_PER_MINUTE):
        ok = await client.get(SCHOOLS, params={"q": "nyit"}, headers=auth_headers(token))
        assert ok.status_code == 200
    refused = await client.get(SCHOOLS, params={"q": "nyit"}, headers=auth_headers(token))

    assert refused.status_code == 429
    assert refused.json() == {"detail": "Too many school searches. Wait a minute and try again."}
    assert len(searches) == connector_routes.SCHOOL_SEARCHES_PER_MINUTE
    assert (
        await client.get(SCHOOLS, params={"q": "nyit"}, headers=auth_headers(other))
    ).status_code == 200


@pytest.mark.asyncio
async def test_school_search_failure_is_a_502_with_one_plain_message(
    client, session_factory, monkeypatch
):
    async def broken(query: str, *, transport: Any = None) -> list[CanvasSchool]:
        raise SchoolSearchError("the directory answered HTTP 500")

    monkeypatch.setattr(canvas_schools, "search_schools", broken)
    _, token = await make_user(session_factory, "schools-502@example.com")

    response = await client.get(SCHOOLS, params={"q": "nyit"}, headers=auth_headers(token))

    assert response.status_code == 502
    assert response.json() == {"detail": SEARCH_FAILED}


@pytest.mark.asyncio
async def test_school_search_refused_by_the_policy_is_a_502(client, session_factory, monkeypatch):
    # The real search, pointed off its allowlist: refused before any DNS
    # lookup or connection, and reported like any other upstream failure.
    canvas_schools.clear_cache()
    monkeypatch.setattr(
        canvas_schools, "SEARCH_URL", "https://evil.example/api/v1/accounts/search"
    )
    _, token = await make_user(session_factory, "schools-policy@example.com")

    response = await client.get(SCHOOLS, params={"q": "nyit"}, headers=auth_headers(token))

    assert response.status_code == 502
    assert response.json() == {"detail": SEARCH_FAILED}
    assert canvas_schools._cache == {}


@pytest.mark.asyncio
async def test_school_search_needs_a_signed_in_user(client, searches):
    response = await client.get(SCHOOLS, params={"q": "nyit"})
    assert response.status_code in (401, 403)
    assert searches == []


# ---------------------------------------------------------------------------
# POST /api/connectors/{id}/test: account and user
# ---------------------------------------------------------------------------


async def add_slack_row(session_factory: Any, user_id: uuid.UUID) -> uuid.UUID:
    credentials = {"bot_token": "xoxb-test-identity", "app_token": "xapp-test-identity"}
    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type="slack",
            display_name="Slack",
            auth_method=AuthMethod.bearer_token,
            encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
            granted_scopes=[],
        )
        session.add(row)
        await session.commit()
        return row.id


def slack_answers(monkeypatch, payload: dict[str, Any]) -> list[httpx.Request]:
    """Connectors the route builds send their HTTP to a mock answering *payload*."""
    import services.connectors.factory as factory_module

    real_create = factory_module.create_connector
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=payload)

    def create(*args: Any, **kwargs: Any):
        connector = real_create(*args, **kwargs)
        connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return connector

    monkeypatch.setattr(factory_module, "create_connector", create)
    return seen


@pytest.mark.asyncio
async def test_connection_test_reports_the_account_and_user(client, session_factory, monkeypatch):
    user, token = await make_user(session_factory, "identity@example.com")
    connector_id = await add_slack_row(session_factory, user.id)
    seen = slack_answers(monkeypatch, {"ok": True, "team": "Acme Corp", "user": "crawler"})

    response = await client.post(f"/api/connectors/{connector_id}/test", headers=auth_headers(token))

    assert response.json() == {
        "ok": True,
        "detail": "Connection verified.",
        "account": "Acme Corp",
        "user": "crawler",
    }
    assert [r.url.path for r in seen] == ["/api/auth.test"]  # no extra request


@pytest.mark.asyncio
async def test_connection_test_without_an_identity_reports_none(
    client, session_factory, monkeypatch
):
    user, token = await make_user(session_factory, "no-identity@example.com")
    connector_id = await add_slack_row(session_factory, user.id)
    slack_answers(monkeypatch, {"ok": True, "team": "", "user": None})

    response = await client.post(f"/api/connectors/{connector_id}/test", headers=auth_headers(token))

    assert response.json() == {
        "ok": True,
        "detail": "Connection verified.",
        "account": None,
        "user": None,
    }


@pytest.mark.asyncio
async def test_a_failed_connection_test_reports_no_identity(client, session_factory, monkeypatch):
    user, token = await make_user(session_factory, "failed-identity@example.com")
    connector_id = await add_slack_row(session_factory, user.id)
    slack_answers(monkeypatch, {"ok": False, "error": "invalid_auth", "team": "Acme Corp"})

    response = await client.post(f"/api/connectors/{connector_id}/test", headers=auth_headers(token))

    body = response.json()
    assert body["ok"] is False
    assert (body["account"], body["user"]) == (None, None)
    assert body["detail"] == (
        "Service health check failed. The stored credentials may be invalid or "
        "expired. Re-enter them to fix."
    )


# ---------------------------------------------------------------------------
# POST /api/connectors/{id}/test: an address or network problem is not a bad code
# ---------------------------------------------------------------------------


async def add_canvas_row(session_factory: Any, user_id: uuid.UUID) -> uuid.UUID:
    credentials = {"base_url": "https://school.instructure.com", "access_token": "canvas-test-code"}
    async with session_factory() as session:
        row = ConnectorConfig(
            user_id=user_id,
            connector_type="canvas",
            display_name="Canvas",
            auth_method=AuthMethod.bearer_token,
            encrypted_credentials=encrypt_credentials(json.dumps(credentials)),
            granted_scopes=[],
        )
        session.add(row)
        await session.commit()
        return row.id


def answer_with(monkeypatch, handler: Any) -> None:
    """Connectors the route builds send their HTTP to *handler*, and never wait to retry."""
    import services.connectors.factory as factory_module

    real_create = factory_module.create_connector

    async def no_wait(_seconds: float) -> None:
        return None

    def create(*args: Any, **kwargs: Any):
        connector = real_create(*args, **kwargs)
        connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        connector._sleep = no_wait
        return connector

    monkeypatch.setattr(factory_module, "create_connector", create)


def no_answer(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("no route to host", request=request)


UNREACHABLE = "Could not reach the service. Check the address and the internet connection, then try again."
GENERIC = "Service health check failed. The stored credentials may be invalid or expired. Re-enter them to fix."


@pytest.mark.asyncio
@pytest.mark.parametrize("add_row", [add_canvas_row, add_slack_row])
async def test_a_service_that_does_not_answer_is_reported_as_unreachable(
    client, session_factory, monkeypatch, add_row
):
    user, token = await make_user(session_factory, f"unreachable-{add_row.__name__}@example.com")
    connector_id = await add_row(session_factory, user.id)
    answer_with(monkeypatch, no_answer)

    response = await client.post(f"/api/connectors/{connector_id}/test", headers=auth_headers(token))

    assert response.json() == {"ok": False, "detail": UNREACHABLE, "account": None, "user": None}


WRONG_ADDRESS = "The address answered, but not like this service. Check the address."
HTML_PAGE = {"text": "<html>not canvas</html>", "headers": {"content-type": "text/html; charset=utf-8"}}
CANVAS_REFUSAL = {"json": {"errors": [{"message": "Invalid access token."}]}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body", "detail"),
    [
        (404, HTML_PAGE, WRONG_ADDRESS),
        (302, HTML_PAGE, WRONG_ADDRESS),
        # A school's main site behind a firewall (seen live: www.nyit.edu answers 403 HTML).
        (403, HTML_PAGE, WRONG_ADDRESS),
        (503, HTML_PAGE, UNREACHABLE),
        # Canvas itself refuses a bad code with a JSON error (seen live on nyit.instructure.com).
        (401, CANVAS_REFUSAL, GENERIC),
        (403, CANVAS_REFUSAL, GENERIC),
    ],
)
async def test_canvas_tells_a_wrong_address_from_a_refused_code(
    client, session_factory, monkeypatch, status, body, detail
):
    user, token = await make_user(session_factory, f"canvas-{status}-{len(str(body))}@example.com")
    connector_id = await add_canvas_row(session_factory, user.id)
    answer_with(monkeypatch, lambda request: httpx.Response(status, **body))

    response = await client.post(f"/api/connectors/{connector_id}/test", headers=auth_headers(token))

    assert response.json()["detail"] == detail
    assert response.json()["ok"] is False


@pytest.mark.asyncio
async def test_canvas_reports_the_school_address_and_the_person(client, session_factory, monkeypatch):
    user, token = await make_user(session_factory, "canvas-ok@example.com")
    connector_id = await add_canvas_row(session_factory, user.id)
    answer_with(monkeypatch, lambda request: httpx.Response(200, json={"id": 1, "name": "Rafi Hossain"}))

    response = await client.post(f"/api/connectors/{connector_id}/test", headers=auth_headers(token))

    assert response.json() == {
        "ok": True,
        "detail": "Connection verified.",
        "account": "school.instructure.com",
        "user": "Rafi Hossain",
    }
