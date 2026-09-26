"""Copyable test skeleton for a new connector (skipped: it tests the template).

Why it exists: every connector needs the same behavioural, failure and
security tests (connectors design spec section 4.7). Copy this file to
``tests/connectors/test_<key>.py``, point the import at your module, delete the
``pytest.skip`` line below and replace the recorded responses with real
shapes from the provider's docs.

It exercises ``services/connectors/_template.py`` through ``httpx.MockTransport``
only (no network, no real credentials) and depends on the registry validator.
"""

from __future__ import annotations

import json

import httpx
import pytest

pytest.skip(
    "Template for new connector tests; copy it to test_<key>.py and remove this line.",
    allow_module_level=True,
)

from services.connectors._template import DEFINITION, ExampleConnector  # noqa: E402
from services.connectors.base import (  # noqa: E402
    AuthenticationError,
    ConnectorError,
    RateLimitExceededError,
    UserConfirmationRequired,
)
from services.connectors.registry import validate_registry  # noqa: E402

TOKEN = "example-test-token"  # obviously fake


def _connector(handler) -> tuple[ExampleConnector, list[httpx.Request]]:
    """An authenticated connector whose HTTP goes to *handler*; records requests."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    connector = ExampleConnector()
    connector._authenticated = True
    connector._token = TOKEN
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(recording))

    async def no_sleep(_seconds: float) -> None:
        return None

    connector._sleep = no_sleep
    return connector, seen


def test_definition_passes_registry_validation():
    assert validate_registry([DEFINITION]) == []


# -- Behaviour: method, host, path, query, body -------------------------------


@pytest.mark.asyncio
async def test_list_notes_sends_one_get_with_clamped_limit():
    connector, seen = _connector(
        lambda r: httpx.Response(200, json={"notes": [{"id": "n1", "title": "A", "secret": "x"}]})
    )
    result = await connector.list_notes(limit=500)

    assert result == [{"id": "n1", "title": "A"}]
    (request,) = seen
    assert request.method == "GET"
    assert request.url.host == "api.example.com"
    assert request.url.raw_path == b"/v1/notes?limit=50"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.asyncio
async def test_get_note_escapes_the_id_into_one_path_segment():
    connector, seen = _connector(lambda r: httpx.Response(200, json={"id": "a/b", "body": "hi"}))
    await connector.get_note("a/b")
    assert seen[0].url.raw_path == b"/v1/notes/a%2Fb"


@pytest.mark.asyncio
async def test_long_body_is_truncated_and_flagged():
    connector, _ = _connector(lambda r: httpx.Response(200, json={"id": "n", "body": "x" * 10_000}))
    result = await connector.get_note("n")
    assert result["truncated"] is True
    assert len(result["body"]) <= 4000
    assert "hint" in result


@pytest.mark.asyncio
async def test_create_note_posts_the_body_once_confirmed():
    connector, seen = _connector(lambda r: httpx.Response(201, json={"id": "n9", "title": "T"}))
    await connector.create_note("T", "B", user_confirmed=True)
    assert seen[0].method == "POST"
    assert json.loads(seen[0].content) == {"title": "T", "body": "B"}


# -- Security: confirmation before any request, no token leaks ----------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.create_note("T", "B"),
        lambda c: c.delete_note("n1"),
    ],
)
async def test_writes_require_confirmation_before_any_request(call):
    connector, seen = _connector(lambda r: httpx.Response(200, json={}))
    with pytest.raises(UserConfirmationRequired):
        await call(connector)
    assert seen == []


@pytest.mark.asyncio
async def test_401_is_an_authentication_error_without_the_token():
    connector, _ = _connector(lambda r: httpx.Response(401, json={"error": "bad_token"}))
    with pytest.raises(AuthenticationError) as exc:
        await connector.list_notes()
    assert TOKEN not in str(exc.value)


# -- Failure cases ------------------------------------------------------------


@pytest.mark.asyncio
async def test_404_and_500_are_connector_errors():
    for status in (404, 500):
        connector, _ = _connector(lambda r, s=status: httpx.Response(s, json={}))
        with pytest.raises(ConnectorError):
            await connector.get_note("missing")


@pytest.mark.asyncio
async def test_429_with_short_retry_after_retries_once():
    responses = [
        httpx.Response(429, headers={"Retry-After": "1"}),
        httpx.Response(200, json={"notes": []}),
    ]
    connector, seen = _connector(lambda r: responses.pop(0))
    assert await connector.list_notes() == []
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_429_with_long_retry_after_raises_rate_limit():
    connector, seen = _connector(lambda r: httpx.Response(429, headers={"Retry-After": "120"}))
    with pytest.raises(RateLimitExceededError):
        await connector.list_notes()
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_malformed_json_is_a_connector_error():
    connector, _ = _connector(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(ConnectorError):
        await connector.get_note("n1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [[{"id": "n1"}], "notes", 7, {"notes": {"id": "n1"}}],
)
async def test_unexpected_json_shape_is_a_clean_connector_error(payload):
    connector, _ = _connector(lambda r: httpx.Response(200, json=payload))
    with pytest.raises(ConnectorError, match="Malformed response from Example"):
        await connector.list_notes()


@pytest.mark.asyncio
async def test_get_note_rejects_a_non_object_body():
    connector, _ = _connector(lambda r: httpx.Response(200, json=["not", "an", "object"]))
    with pytest.raises(ConnectorError, match="Malformed response from Example"):
        await connector.get_note("n1")
