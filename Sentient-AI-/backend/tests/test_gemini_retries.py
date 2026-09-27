"""Tests for Gemini's retries: a rate limit, a server error, a dropped
connection or a blank completion is asked again after a short pause, and an
error that would come back the same is not.

Why it exists: Gemini is called over plain HTTP, so unlike the SDK providers
(which retry twice on their own) one hiccup ended the whole task, and on
Telegram the owner was told to "send 'continue' to try again". Google is
faked at the httpx transport; the pauses are recorded, never slept.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from services.agent.providers import GeminiProvider, ProviderError

OK = {"candidates": [{"content": {"parts": [{"text": "On the 15th: Dentist."}]}}]}
HI = [{"role": "user", "content": "what am I doing on the 15th"}]


class Google:
    """Answers each request with the next scripted response."""

    def __init__(self) -> None:
        self.script: list[Callable[[httpx.Request], httpx.Response]] = []
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.script.pop(0)(request)


def answer(status: int, body: Any = None, headers: dict[str, str] | None = None):
    def respond(request: httpx.Request) -> httpx.Response:
        if isinstance(body, (dict, list)):
            return httpx.Response(status, json=body, headers=headers)
        return httpx.Response(status, text=body or "", headers=headers)

    return respond


def drop(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("read timed out")


@pytest.fixture
def google(monkeypatch):
    fake = Google()
    real_client_cls = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(fake.handle)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return fake


@pytest.fixture
def pauses(monkeypatch) -> list[float]:
    slept: list[float] = []

    async def record(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(GeminiProvider, "_retry_sleep", staticmethod(record))
    return slept


async def complete(google: Google) -> Any:
    provider = GeminiProvider(api_key="AIza-secret")
    try:
        return await provider.complete(HI)
    finally:
        await provider.aclose()


# ── asked again, and it works ────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "first",
    [
        answer(429, "Resource has been exhausted (e.g. check quota)."),
        answer(500, "Internal error"),
        answer(503, "The model is overloaded. Please try again later."),
        drop,
        answer(200, {"candidates": [{"content": {"parts": []}, "finishReason": "STOP"}]}),
        answer(200, {"candidates": [{"content": {}, "finishReason": "MALFORMED_FUNCTION_CALL"}]}),
    ],
    ids=["429", "500", "503", "dropped", "blank-stop", "malformed-call"],
)
async def test_one_hiccup_is_retried_and_the_answer_comes_back(google, pauses, first):
    google.script = [first, answer(200, OK)]
    response = await complete(google)
    assert response.content == "On the 15th: Dentist."
    assert len(google.requests) == 2
    assert pauses == [1.0]
    # The retry is the same request.
    assert google.requests[0].content == google.requests[1].content


@pytest.mark.asyncio
async def test_two_hiccups_are_retried_with_a_longer_pause(google, pauses):
    google.script = [answer(503), answer(502), answer(200, OK)]
    response = await complete(google)
    assert response.content
    assert pauses == [1.0, 2.0]


@pytest.mark.asyncio
async def test_after_three_tries_the_last_error_is_raised(google, pauses):
    google.script = [answer(503, "overloaded")] * 3
    with pytest.raises(ProviderError) as excinfo:
        await complete(google)
    assert excinfo.value.status_code == 503
    assert len(google.requests) == 3
    assert pauses == [1.0, 2.0]


@pytest.mark.asyncio
async def test_the_wait_google_asks_for_is_honoured_up_to_a_cap(google, pauses):
    retry_info = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "3.5s"}
            ],
        }
    }
    google.script = [
        answer(429, retry_info),
        answer(429, "slow down", headers={"Retry-After": "30"}),
        answer(200, OK),
    ]
    await complete(google)
    assert pauses == [3.5, 8.0]  # 30 s is capped: the task should not stall


# ── not asked again: it would come back the same ─────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "only",
    [
        answer(400, "API key not valid"),
        answer(403, "permission denied"),
        answer(404, "model not found"),
        answer(200, {"promptFeedback": {"blockReason": "SAFETY"}}),
        answer(200, {"candidates": [{"content": {"parts": []}, "finishReason": "SAFETY"}]}),
        answer(200, {"candidates": [{"content": {"parts": []}, "finishReason": "RECITATION"}]}),
    ],
    ids=["400", "403", "404", "blocked-prompt", "safety", "recitation"],
)
async def test_errors_that_would_repeat_are_not_retried(google, pauses, only):
    google.script = [only]
    with pytest.raises(ProviderError):
        await complete(google)
    assert len(google.requests) == 1
    assert pauses == []


@pytest.mark.asyncio
async def test_a_retried_error_never_carries_the_key_or_url(google, pauses):
    google.script = [answer(503)] * 3
    with pytest.raises(ProviderError) as excinfo:
        await complete(google)
    text = str(excinfo.value)
    assert "AIza-secret" not in text and "generativelanguage" not in text
    assert json.loads(google.requests[0].content)["contents"]
