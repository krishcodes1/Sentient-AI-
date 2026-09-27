"""Shared helpers for the Google Workspace connector tests (no tests of its own).

Why it exists: every ``test_google_workspace*.py`` module builds the same
authenticated connector whose HTTP goes to an ``httpx.MockTransport`` while the
connector's real network-policy hook still runs, so every URL a test makes the
connector request is also proven to be inside the "google" allowlist.
Connects to services/connectors/google_workspace.py and the registry (which
arms the "google" network policy at import). No real network or DNS:
``core.network_security.check_ssrf`` is replaced by the ``no_dns`` fixture.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

import httpx
import pytest

import core.network_security as netsec
import services.connectors.registry  # noqa: F401 - arms the "google" policy
from services.connectors.google_workspace import GoogleWorkspaceConnector

# Obviously fake credentials; none of them is a real Google token format.
TOKEN = "google-test-access-token"
REFRESH = "google-test-refresh-token"
CLIENT_ID = "test-client-id.apps.example"
CLIENT_SECRET = "test-client-secret"

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def no_dns(monkeypatch):
    """Policy checks without DNS: SSRF resolution passes, the allowlist decides."""
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True))


async def _no_sleep(_seconds: float) -> None:
    return None


def make(
    handler: Handler,
    *,
    token: Optional[str] = TOKEN,
    refresh: Optional[str] = None,
    client_id: str = CLIENT_ID,
    expires_at: Optional[int] = None,
) -> tuple[GoogleWorkspaceConnector, list[httpx.Request]]:
    """An authenticated connector whose requests go to *handler*.

    The policy hook stays armed, so an off-list URL fails the test.
    """
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    connector = GoogleWorkspaceConnector(client_id=client_id, client_secret=CLIENT_SECRET)
    connector.set_network_policy("google")
    connector._access_token = token
    connector._refresh_token = refresh
    connector._expires_at = expires_at
    connector._authenticated = True
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(recording),
        event_hooks={"request": [connector._enforce_network_policy]},
    )
    connector._sleep = _no_sleep
    return connector, seen


def ok(payload: Any = None, status: int = 200) -> Handler:
    return lambda _request: httpx.Response(status, json={} if payload is None else payload)


def body(request: httpx.Request) -> Any:
    return json.loads(request.content)


def form(request: httpx.Request) -> dict[str, str]:
    return dict(httpx.QueryParams(request.content.decode()))


def query(request: httpx.Request) -> dict[str, str]:
    return dict(request.url.params)


def no_secret_in(value: Any) -> bool:
    text = json.dumps(value, default=str) if not isinstance(value, str) else value
    return all(secret not in text for secret in (TOKEN, REFRESH, CLIENT_SECRET))
