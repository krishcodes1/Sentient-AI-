"""Tests for BaseConnector's shared HTTP helpers: _request, _request_json, the
status-to-error mapping, and the single-retry rules.

Why it exists: every new connector sends its requests through these helpers,
so the error text (which reaches the model, the audit log and the chat) must
never echo a vendor body or a token, and the retry rules must never repeat a
non-idempotent write or loop on a rate limit.
Connects to: services/connectors/base.py. No real network: requests go to an
httpx.MockTransport injected through connector._http_client.
"""

from __future__ import annotations

from typing import Any, Callable

import httpx
import pytest

from services.connectors.base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    RateLimitExceededError,
    http_error_for,
    parse_retry_after,
)

FAKE_TOKEN = "ghp_test_fake_token_0123456789"
URL = "https://api.acme.test/v1/things"
# An error body quoting our own token back, the way some vendors echo the
# request. None of it may reach an error string.
LEAKY_BODY = {
    "message": f"Bad credentials for Authorization: Bearer {FAKE_TOKEN}",
    "documentation_url": "https://docs.acme.test/errors",
}


class _Acme(BaseConnector):
    """Minimal connector exercising the base helpers."""

    def __init__(self) -> None:
        super().__init__(timeout_s=5)
        self.slept: list[float] = []

        async def _fake_sleep(seconds: float) -> None:
            self.slept.append(seconds)

        self._sleep = _fake_sleep
        self._token = FAKE_TOKEN

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
        return {"Authorization": f"Bearer {self._token}"}

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        if action == "legacy":
            response = await self._get_client().get(URL)
            response.raise_for_status()
            return {"ok": True}
        return await self._request_json("GET", URL)

    async def health_check(self) -> bool:
        return True


class _Script:
    """MockTransport handler replaying a list of responses (or exceptions)."""

    def __init__(self, *steps: httpx.Response | Exception | Callable[[httpx.Request], httpx.Response]):
        self._steps = list(steps)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        step = self._steps[min(len(self.requests), len(self._steps)) - 1]
        if isinstance(step, Exception):
            raise step
        if callable(step) and not isinstance(step, httpx.Response):
            return step(request)
        return step


def _wire(script: _Script) -> _Acme:
    connector = _Acme()
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(script))
    return connector


def _assert_clean(message: str) -> None:
    assert FAKE_TOKEN not in message
    assert "Bad credentials" not in message
    assert "documentation_url" not in message


# ---------------------------------------------------------------------------
# Success paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_sends_auth_headers_params_and_body():
    script = _Script(httpx.Response(201, json={"id": 7}))
    connector = _wire(script)

    result = await connector._request_json(
        "post", URL, params={"q": "a b"}, json={"title": "x"}, headers={"X-Extra": "1"}
    )

    assert result == {"id": 7}
    request = script.requests[0]
    assert request.method == "POST"
    assert request.url.host == "api.acme.test"
    assert request.url.raw_path == b"/v1/things?q=a+b"
    assert request.headers["Authorization"] == f"Bearer {FAKE_TOKEN}"
    assert request.headers["X-Extra"] == "1"
    assert request.content == b'{"title":"x"}'


@pytest.mark.asyncio
async def test_unauthorized_request_omits_auth_headers():
    script = _Script(httpx.Response(200, json={}))
    connector = _wire(script)

    await connector._request("GET", URL, authorized=False)

    assert "authorization" not in script.requests[0].headers


class _Versioned(_Acme):
    """A GitHub-style connector: versioning headers next to the token."""

    def _static_headers(self) -> dict[str, str]:
        return {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


@pytest.mark.asyncio
@pytest.mark.parametrize("authorized", [True, False])
async def test_static_headers_are_sent_with_and_without_credentials(authorized):
    script = _Script(httpx.Response(200, json={}))
    connector = _Versioned()
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(script))

    await connector._request("GET", URL, authorized=authorized)

    sent = script.requests[0].headers
    assert sent["accept"] == "application/vnd.github+json"
    assert sent["x-github-api-version"] == "2022-11-28"
    assert ("authorization" in sent) is authorized


@pytest.mark.asyncio
async def test_header_layers_merge_case_insensitively_caller_last():
    script = _Script(httpx.Response(200, json={}))
    connector = _Versioned()
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(script))

    await connector._request("GET", URL, headers={"accept": "application/vnd.github.raw"})

    sent = script.requests[0].headers
    assert sent.get_list("accept") == ["application/vnd.github.raw"]
    assert sent["authorization"] == f"Bearer {FAKE_TOKEN}"


def test_static_and_generic_header_values_are_not_secrets():
    class _Misplaced(_Versioned):
        def _auth_headers(self) -> dict[str, str]:
            return {"Authorization": f"Bearer {FAKE_TOKEN}", "Accept": "application/json"}

    connector = _Misplaced()
    assert connector._secret_values() == (f"Bearer {FAKE_TOKEN}",)
    assert "accept" not in connector._credential_header_names()
    assert "x-github-api-version" not in connector._credential_header_names()
    assert "authorization" in connector._credential_header_names()


@pytest.mark.asyncio
async def test_204_and_empty_body_decode_to_empty_dict():
    connector = _wire(_Script(httpx.Response(204), httpx.Response(200, content=b"  ")))
    assert await connector._request_json("DELETE", URL) == {}
    assert await connector._request_json("GET", URL) == {}


@pytest.mark.asyncio
async def test_malformed_json_is_a_connector_error_without_the_body():
    connector = _wire(_Script(httpx.Response(200, content=f"<html>{FAKE_TOKEN}".encode())))

    with pytest.raises(ConnectorError) as info:
        await connector._request_json("GET", URL)

    assert str(info.value) == "Malformed response from Acme."
    _assert_clean(str(info.value))


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error_type", "fragment"),
    [
        (401, AuthenticationError, "Reconnect Acme in Connectors."),
        (403, AuthenticationError, "missing permission or scope"),
        (404, ConnectorError, "not found"),
        (409, ConnectorError, "conflict"),
        (500, ConnectorError, "provider error"),
        (400, ConnectorError, "rejected"),
    ],
)
async def test_status_mapping_never_echoes_the_body(status, error_type, fragment):
    script = _Script(httpx.Response(status, json=LEAKY_BODY))
    connector = _wire(script)

    with pytest.raises(error_type) as info:
        await connector._request("GET", URL)

    message = str(info.value)
    assert message.startswith(f"HTTP {status} from Acme")
    assert fragment in message
    _assert_clean(message)
    # 500 and the 4xx family are never retried.
    assert len(script.requests) == 1
    assert connector.slept == []


@pytest.mark.asyncio
async def test_404_is_not_an_authentication_error():
    connector = _wire(_Script(httpx.Response(404)))
    with pytest.raises(ConnectorError) as info:
        await connector._request("GET", URL)
    assert not isinstance(info.value, AuthenticationError)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"error": "channel_not_found"}, "channel_not_found"),
        ({"error": {"code": 403, "status": "PERMISSION_DENIED"}}, "PERMISSION_DENIED"),
        ({"error": {"code": "object_not_found"}}, "object_not_found"),
        ({"code": "validation_error"}, "validation_error"),
        ({"errors": [{"code": "already_exists"}]}, "already_exists"),
    ],
)
def test_vendor_code_is_included_when_short_and_token_free(body, code):
    error = http_error_for("Acme", httpx.Response(409, json=body))
    assert f"HTTP 409 from Acme ({code})" in str(error)


@pytest.mark.parametrize(
    "body",
    [
        {"error": "free text with spaces explaining the failure"},
        {"error": "x" * 65},
        {"error": "xoxb-test-token"},
        {"code": "ghp_abcdef"},
        {"error": {"code": "ya29.fake"}},
        {"errors": ["not-a-dict"]},
        ["not", "a", "dict"],
    ],
)
def test_vendor_code_is_dropped_when_it_is_prose_or_token_shaped(body):
    message = str(http_error_for("Acme", httpx.Response(400, json=body)))
    assert "(" not in message
    assert message == "HTTP 400 from Acme: the request was rejected."


def test_vendor_code_matching_our_own_secret_is_dropped():
    secret = "Bearer customtoken42"
    response = httpx.Response(400, json={"error": "customtoken42"})
    error = http_error_for("Acme", response, secrets=(secret,))
    assert "customtoken42" not in str(error)
    assert error.vendor_code is None


@pytest.mark.parametrize(
    ("response", "error_type", "code"),
    [
        (httpx.Response(401, json={"error": "invalid_token"}), AuthenticationError, "invalid_token"),
        (httpx.Response(403, json={"error": {"code": "ErrorAccessDenied"}}), AuthenticationError, "ErrorAccessDenied"),
        (httpx.Response(403, headers={"Retry-After": "5"}), RateLimitExceededError, None),
        (httpx.Response(429, json={"code": "ratelimited"}), RateLimitExceededError, "ratelimited"),
        (httpx.Response(404, json=LEAKY_BODY), ConnectorError, None),
        (httpx.Response(409, json={"errors": [{"code": "already_exists"}]}), ConnectorError, "already_exists"),
        (httpx.Response(302), ConnectorError, None),
        (httpx.Response(400, json={"error": "free text with spaces"}), ConnectorError, None),
        (httpx.Response(503, json={"error": {"status": "UNAVAILABLE"}}), ConnectorError, "UNAVAILABLE"),
    ],
)
def test_mapped_errors_carry_status_and_vendor_code_attributes(response, error_type, code):
    error = http_error_for("Acme (odd) name", response)
    assert type(error) is error_type
    assert error.status_code == response.status_code
    assert error.vendor_code == code


def test_errors_not_built_from_a_response_have_no_status():
    from services.connectors.base import HardBlockError, UserConfirmationRequired

    for error in (
        ConnectorError("HTTP 403 from Acme: missing permission or scope."),
        AuthenticationError("Reconnect Acme."),
        RateLimitExceededError("Rate limit of 1 calls/min exceeded."),
        UserConfirmationRequired("act", "details"),
        HardBlockError("act"),
    ):
        assert error.status_code is None and error.vendor_code is None
    explicit = ConnectorError("x", status_code=418, vendor_code="teapot")
    assert (str(explicit), explicit.status_code, explicit.vendor_code) == ("x", 418, "teapot")


@pytest.mark.asyncio
async def test_request_raises_errors_with_structured_status():
    connector = _wire(_Script(httpx.Response(403, json={"error": {"code": "ErrorAccessDenied"}})))
    with pytest.raises(AuthenticationError) as info:
        await connector._request("GET", URL)
    assert (info.value.status_code, info.value.vendor_code) == (403, "ErrorAccessDenied")


@pytest.mark.asyncio
async def test_execute_hides_unexpected_error_text_and_keeps_the_cause():
    class _Broken(_Acme):
        async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
            raise ValueError(f"https://api.acme.test/v1?token={FAKE_TOKEN}")

    connector = _Broken()
    await connector.authenticate({})
    with pytest.raises(ConnectorError) as info:
        await connector.execute("anything", {})
    assert str(info.value) == "Acme failed (ValueError)."
    assert type(info.value) is ConnectorError and info.value.status_code is None
    # The original stays chained for debugging in-process, never in the text.
    assert isinstance(info.value.__cause__, ValueError)


@pytest.mark.asyncio
async def test_execute_maps_legacy_raise_for_status_without_the_body():
    connector = _wire(_Script(httpx.Response(403, json=LEAKY_BODY)))
    await connector.authenticate({})

    with pytest.raises(AuthenticationError) as info:
        await connector.execute("legacy", {})

    assert "HTTP 403 from Acme" in str(info.value)
    assert info.value.status_code == 403
    _assert_clean(str(info.value))
    # No chained httpx error carrying the URL or the response.
    assert info.value.__cause__ is None


@pytest.mark.asyncio
async def test_execute_keeps_rate_limit_error_type():
    connector = _wire(_Script(httpx.Response(429, headers={"Retry-After": "120"})))
    await connector.authenticate({})

    with pytest.raises(RateLimitExceededError, match="Retry after 120 s"):
        await connector.execute("read", {})


# ---------------------------------------------------------------------------
# Retry rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_429_with_short_retry_after_is_retried_once_after_that_wait():
    script = _Script(
        httpx.Response(429, headers={"Retry-After": "2"}),
        httpx.Response(200, json={"ok": True}),
    )
    connector = _wire(script)

    assert await connector._request_json("POST", URL, json={}) == {"ok": True}
    assert len(script.requests) == 2
    assert connector.slept == [2.0]


@pytest.mark.asyncio
async def test_429_without_retry_after_retries_once_then_reports():
    script = _Script(httpx.Response(429, json=LEAKY_BODY))
    connector = _wire(script)

    with pytest.raises(RateLimitExceededError) as info:
        await connector._request("GET", URL)

    assert len(script.requests) == 2  # one retry, then give up (no loop)
    assert len(connector.slept) == 1
    assert "HTTP 429 from Acme" in str(info.value)
    _assert_clean(str(info.value))


@pytest.mark.asyncio
async def test_retry_after_over_ten_seconds_is_reported_not_waited():
    script = _Script(httpx.Response(429, headers={"Retry-After": "11"}))
    connector = _wire(script)

    with pytest.raises(RateLimitExceededError, match="Retry after 11 s"):
        await connector._request("GET", URL)

    assert len(script.requests) == 1
    assert connector.slept == []


@pytest.mark.asyncio
async def test_github_secondary_rate_limit_403_is_honoured():
    script = _Script(
        httpx.Response(403, headers={"Retry-After": "3"}, json={"message": "secondary"}),
        httpx.Response(200, json={"ok": 1}),
    )
    connector = _wire(script)

    assert await connector._request_json("GET", URL) == {"ok": 1}
    assert connector.slept == [3.0]


@pytest.mark.asyncio
async def test_github_primary_limit_exhausted_reports_the_reset_wait():
    import time

    reset = str(int(time.time()) + 600)
    script = _Script(
        httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset})
    )
    connector = _wire(script)

    with pytest.raises(RateLimitExceededError, match="Retry after"):
        await connector._request("GET", URL)
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_plain_403_is_not_retried():
    script = _Script(httpx.Response(403, json={"message": "forbidden"}))
    connector = _wire(script)

    with pytest.raises(AuthenticationError):
        await connector._request("GET", URL)
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_502_is_retried_once_for_get():
    script = _Script(httpx.Response(502), httpx.Response(200, json={"n": 1}))
    connector = _wire(script)

    assert await connector._request_json("GET", URL) == {"n": 1}
    assert len(script.requests) == 2
    assert connector.slept == [0.5]


@pytest.mark.asyncio
async def test_502_is_not_retried_for_post():
    script = _Script(httpx.Response(502), httpx.Response(200, json={"n": 1}))
    connector = _wire(script)

    with pytest.raises(ConnectorError, match="HTTP 502 from Acme: provider error"):
        await connector._request("POST", URL, json={"a": 1})
    assert len(script.requests) == 1
    assert connector.slept == []


@pytest.mark.asyncio
async def test_503_twice_fails_after_a_single_retry():
    script = _Script(httpx.Response(503, text=f"down {FAKE_TOKEN}"))
    connector = _wire(script)

    with pytest.raises(ConnectorError) as info:
        await connector._request("GET", URL)

    assert len(script.requests) == 2
    assert "HTTP 503 from Acme" in str(info.value)
    _assert_clean(str(info.value))


@pytest.mark.asyncio
async def test_503_short_retry_after_is_used_as_the_backoff():
    script = _Script(
        httpx.Response(503, headers={"Retry-After": "4"}), httpx.Response(200, json={})
    )
    connector = _wire(script)

    await connector._request("PUT", URL, json={})
    assert connector.slept == [4.0]


@pytest.mark.asyncio
async def test_connect_error_retried_once_for_idempotent_methods_only():
    get_script = _Script(httpx.ConnectError("boom"), httpx.Response(200, json={"ok": 1}))
    connector = _wire(get_script)
    assert await connector._request_json("GET", URL) == {"ok": 1}
    assert len(get_script.requests) == 2

    post_script = _Script(httpx.ConnectError("boom"), httpx.Response(200, json={}))
    connector = _wire(post_script)
    with pytest.raises(ConnectorError, match="Could not connect to Acme"):
        await connector._request("POST", URL)
    assert len(post_script.requests) == 1


@pytest.mark.asyncio
async def test_connect_error_twice_gives_a_clean_error():
    script = _Script(httpx.ConnectError(f"cannot reach {URL}?token={FAKE_TOKEN}"))
    connector = _wire(script)

    with pytest.raises(ConnectorError) as info:
        await connector._request("GET", URL)
    assert str(info.value) == "Could not connect to Acme."


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT", "DELETE"])
async def test_connect_timeout_retried_once_for_idempotent_methods(method):
    script = _Script(httpx.ConnectTimeout("slow dial"), httpx.Response(200, json={}))
    connector = _wire(script)

    response = await connector._request(method, URL)

    assert response.status_code == 200
    assert len(script.requests) == 2
    assert connector.slept == [0.5]


@pytest.mark.asyncio
async def test_connect_timeout_is_not_retried_for_post():
    script = _Script(
        httpx.ConnectTimeout(f"dial {URL}?token={FAKE_TOKEN}"), httpx.Response(200, json={})
    )
    connector = _wire(script)

    with pytest.raises(ConnectorError) as info:
        await connector._request("POST", URL, json={})

    assert str(info.value) == "Could not connect to Acme: connection timed out."
    assert len(script.requests) == 1
    assert connector.slept == []


@pytest.mark.asyncio
async def test_connect_timeout_twice_gives_a_clean_error():
    script = _Script(httpx.ConnectTimeout(f"dial {URL}?token={FAKE_TOKEN}"))
    connector = _wire(script)

    with pytest.raises(ConnectorError) as info:
        await connector._request("GET", URL)

    assert str(info.value) == "Could not connect to Acme: connection timed out."
    assert len(script.requests) == 2
    assert info.value.__cause__ is None


@pytest.mark.asyncio
async def test_gateway_error_with_long_retry_after_is_a_provider_error_not_a_rate_limit():
    script = _Script(
        httpx.Response(503, headers={"Retry-After": "30"}, json=LEAKY_BODY),
        httpx.Response(200, json={}),
    )
    connector = _wire(script)

    with pytest.raises(ConnectorError) as info:
        await connector._request("GET", URL)

    assert not isinstance(info.value, RateLimitExceededError)
    assert str(info.value) == (
        "HTTP 503 from Acme: provider error, try again later. Retry after 30 s."
    )
    # Too long to wait in-line, so no retry at all.
    assert len(script.requests) == 1
    assert connector.slept == []
    _assert_clean(str(info.value))


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_after", ["2", "30"])
async def test_post_gateway_error_is_the_same_provider_error_whatever_its_retry_after(
    retry_after,
):
    script = _Script(
        httpx.Response(503, headers={"Retry-After": retry_after}), httpx.Response(200, json={})
    )
    connector = _wire(script)

    with pytest.raises(ConnectorError) as info:
        await connector._request("POST", URL, json={})

    assert not isinstance(info.value, RateLimitExceededError)
    assert str(info.value).startswith("HTTP 503 from Acme: provider error")
    assert len(script.requests) == 1
    assert connector.slept == []


@pytest.mark.asyncio
async def test_long_retry_after_on_a_real_rate_limit_keeps_the_vendor_code():
    script = _Script(
        httpx.Response(429, headers={"Retry-After": "90"}, json={"error": "ratelimited"})
    )
    connector = _wire(script)

    with pytest.raises(RateLimitExceededError) as info:
        await connector._request("POST", URL, json={})

    assert str(info.value) == (
        "HTTP 429 from Acme (ratelimited): rate limited by the provider. Retry after 90 s."
    )
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_read_timeout_is_not_retried():
    script = _Script(httpx.ReadTimeout("slow"))
    connector = _wire(script)

    with pytest.raises(ConnectorError, match="timed out after 5"):
        await connector._request("GET", URL)
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_unfollowed_redirect_is_an_error():
    script = _Script(httpx.Response(302, headers={"Location": "https://elsewhere.test/"}))
    connector = _wire(script)

    with pytest.raises(ConnectorError, match="HTTP 302 from Acme: unexpected redirect"):
        await connector._request("GET", URL)
    assert len(script.requests) == 1


# ---------------------------------------------------------------------------
# Retry-After parsing
# ---------------------------------------------------------------------------


def test_parse_retry_after_forms():
    assert parse_retry_after("5") == 5.0
    assert parse_retry_after(" 0 ") == 0.0
    assert parse_retry_after("-3") == 0.0
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None
    assert parse_retry_after("soon") is None
    assert parse_retry_after("nan") is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now=1445412470.0) == 10.0
    # A date in the past means retry now.
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now=1445412490.0) == 0.0
