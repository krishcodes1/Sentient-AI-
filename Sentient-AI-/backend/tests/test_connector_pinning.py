"""Tests for DNS pinning on connector HTTP clients: the socket a connector
opens lands on the address its network-policy check validated, a later
request to the same origin never lands on a rebind, a missing pin or pinning primitive is
a refusal rather than a fallback, and every pinned transport shares one TLS
context built off the event loop.

Why it exists: checking a hostname and letting httpcore resolve it again at
connect time leaves a DNS rebinding window. BaseConnector._get_client now
dials through core.http_pinning.PinnedHTTPTransport, fed by the resolved_ips
of check_network_policy; these tests assert on the address actually dialled,
the only place a rebind would show up.
Connects to: services/connectors/base.py, core/http_pinning.py,
core/network_security.py. Nothing leaves the process: socket.getaddrinfo is
scripted and the httpcore socket layer is an in-memory recorder (the harness
from tests/test_mcp_dns_pinning.py).
"""

from __future__ import annotations

from typing import Any

import pytest

import core.network_security as netsec
import services.connectors.base as base_module
from core.http_pinning import PinningUnavailable
from core.network_security import NetworkPolicy
from services.connectors.base import BaseConnector, ConnectorError
from tests.test_mcp_dns_pinning import (
    OTHER_PUBLIC_IP,
    PRIVATE_IP,
    PUBLIC_IP,
    FakeResolver,
    RecordingBackend,
    _http_response,
)

URL = "https://api.acme.test/v1/things"
OK = _http_response(b'{"ok": true}')


class _Acme(BaseConnector):
    def __init__(self) -> None:
        super().__init__(timeout_s=5)

        async def _no_sleep(_seconds: float) -> None:
            return None

        self._sleep = _no_sleep

    @property
    def name(self) -> str:
        return "Acme"

    @property
    def connector_type(self) -> str:
        return "test"

    @property
    def required_scopes(self) -> list[str]:
        return []

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        self._authenticated = True
        return True

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer acme-test-token"}

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._request_json("GET", URL)

    async def health_check(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def acme_policy(monkeypatch):
    monkeypatch.setitem(
        netsec.DEFAULT_POLICIES,
        "acme",
        NetworkPolicy(
            connector_type="acme",
            allowed_hosts=["api.acme.test"],
            allowed_paths={"api.acme.test": ["/v1/"]},
            https_only=True,
        ),
    )


@pytest.fixture
def resolver(monkeypatch):
    import socket

    def install(*answers: list[str]) -> FakeResolver:
        fake = FakeResolver(list(answers))
        monkeypatch.setattr(socket, "getaddrinfo", fake)
        return fake

    return install


def _connector(backend: RecordingBackend | None) -> _Acme:
    connector = _Acme()
    connector.set_network_policy("acme")
    connector._network_backend = backend
    return connector


@pytest.mark.asyncio
async def test_socket_dials_exactly_the_validated_address(resolver):
    # A second lookup would rebind to loopback; there must not be one.
    fake = resolver([PUBLIC_IP], [PRIVATE_IP])
    backend = RecordingBackend(OK)
    connector = _connector(backend)
    try:
        assert await connector._request_json("GET", URL) == {"ok": True}
    finally:
        await connector.close()

    assert backend.dialled == [(PUBLIC_IP, 443)]
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_execute_goes_through_the_pinned_client(resolver):
    resolver([PUBLIC_IP])
    backend = RecordingBackend(OK)
    connector = _connector(backend)
    await connector.authenticate({})
    try:
        response = await connector.execute("read", {})
    finally:
        await connector.close()

    assert response.data == {"ok": True}
    assert backend.dialled == [(PUBLIC_IP, 443)]


@pytest.mark.asyncio
async def test_a_later_request_to_a_pinned_origin_never_lands_on_a_rebind(resolver):
    """The second request reuses the pin: DNS is not asked again (so its
    rebinding answer is never seen) and the socket dials the validated
    address, not the private one."""
    fake = resolver([PUBLIC_IP], [PRIVATE_IP])
    backend = RecordingBackend(OK)
    connector = _connector(backend)
    try:
        await connector._request_json("GET", URL)
        await connector._request_json("GET", URL)
    finally:
        await connector.close()

    assert set(backend.dialled) == {(PUBLIC_IP, 443)}
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_a_pinned_origin_still_gets_the_path_and_host_rules(resolver):
    """Skipping DNS for a pinned origin skips nothing else: an off-list path
    on the same host is still refused, before any socket."""
    fake = resolver([PUBLIC_IP])
    backend = RecordingBackend(OK)
    connector = _connector(backend)
    try:
        await connector._request_json("GET", URL)
        with pytest.raises(ConnectorError, match="network policy"):
            await connector._request_json("GET", "https://api.acme.test/admin/users")
        with pytest.raises(ConnectorError, match="network policy"):
            await connector._request_json("GET", "http://api.acme.test/v1/things")
    finally:
        await connector.close()

    assert fake.calls == 1


@pytest.mark.asyncio
async def test_each_connector_instance_resolves_afresh(resolver):
    """Pins live only as long as one connector (one tool call): the next
    call resolves again, so a changed DNS answer is re-validated."""
    fake = resolver([PUBLIC_IP], [PRIVATE_IP])
    first = _connector(RecordingBackend(OK))
    try:
        await first._request_json("GET", URL)
    finally:
        await first.close()
    second_backend = RecordingBackend(OK)
    second = _connector(second_backend)
    try:
        with pytest.raises(ConnectorError, match="network policy"):
            await second._request_json("GET", URL)
    finally:
        await second.close()

    assert second_backend.dialled == []
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_partly_private_resolution_is_refused_before_dialling(resolver):
    resolver([PUBLIC_IP, PRIVATE_IP])
    backend = RecordingBackend(OK)
    connector = _connector(backend)
    try:
        with pytest.raises(ConnectorError, match="private or internal"):
            await connector._request_json("GET", URL)
    finally:
        await connector.close()
    assert backend.dialled == []


@pytest.mark.asyncio
async def test_network_backend_can_be_passed_to_get_client(resolver):
    resolver([OTHER_PUBLIC_IP])
    backend = RecordingBackend(OK)
    connector = _connector(None)
    connector._get_client(network_backend=backend)
    try:
        await connector._request_json("GET", URL)
    finally:
        await connector.close()
    assert backend.dialled == [(OTHER_PUBLIC_IP, 443)]


@pytest.mark.asyncio
async def test_origin_without_a_validated_pin_is_never_resolved(monkeypatch):
    """A check that validates nothing leaves no pin; the transport refuses
    the origin instead of falling back to DNS at connect time."""
    monkeypatch.setattr(
        netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True)
    )
    backend = RecordingBackend(OK)
    connector = _connector(backend)
    try:
        with pytest.raises(ConnectorError, match="Could not connect to Acme"):
            await connector._request_json("GET", URL)
    finally:
        await connector.close()
    assert backend.dialled == []


@pytest.mark.asyncio
async def test_pinning_unavailable_is_a_refusal(monkeypatch, resolver):
    fake = resolver([PUBLIC_IP])

    def broken_transport(*args: Any, **kwargs: Any) -> Any:
        raise PinningUnavailable("no network backend to replace")

    monkeypatch.setattr(base_module, "PinnedHTTPTransport", broken_transport)
    connector = _connector(RecordingBackend(OK))

    with pytest.raises(ConnectorError, match="Outbound request refused"):
        await connector._request_json("GET", URL)
    assert connector._http_client is None
    assert fake.calls == 0


# ---------------------------------------------------------------------------
# One shared TLS context (the CA bundle is loaded once, off the event loop)
# ---------------------------------------------------------------------------


def test_pinned_transports_share_one_tls_context():
    from core.http_pinning import PinnedHTTPTransport, shared_ssl_context

    first, second = PinnedHTTPTransport({}), PinnedHTTPTransport({})
    assert first._pool._ssl_context is shared_ssl_context()
    assert second._pool._ssl_context is shared_ssl_context()


def test_an_explicit_verify_still_wins():
    import ssl

    from core.http_pinning import PinnedHTTPTransport

    own = ssl.create_default_context()
    assert PinnedHTTPTransport({}, verify=own)._pool._ssl_context is own


def test_connector_clients_use_the_shared_tls_context():
    from core.http_pinning import shared_ssl_context

    connector = _connector(None)
    client = connector._get_client()
    assert client._transport._pool._ssl_context is shared_ssl_context()


@pytest.mark.asyncio
async def test_warm_builds_the_context_once_in_a_worker_thread(monkeypatch):
    import ssl
    import threading

    import httpx

    import core.http_pinning as pinning

    built: list[int] = []

    def fake_create() -> ssl.SSLContext:
        built.append(threading.get_ident())
        return ssl.create_default_context()

    monkeypatch.setattr(pinning, "_shared_ssl_context", None)
    monkeypatch.setattr(httpx, "create_ssl_context", fake_create)

    await pinning.warm_ssl_context()
    context = pinning.shared_ssl_context()
    pinning.PinnedHTTPTransport({})

    assert len(built) == 1 and built[0] != threading.get_ident()
    assert pinning.PinnedHTTPTransport({})._pool._ssl_context is context
