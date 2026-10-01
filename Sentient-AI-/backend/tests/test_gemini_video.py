"""Tests for GeminiProvider.read_video_url, the one provider call that reads a
YouTube video: the request's wire format (one fileData part with the
canonical watch URL and its start/end offsets and fps, then the prompt; the
fixed system instruction; no tools; low media resolution; a JSON schema; the
output ceiling; the key in a header, never the URL), a refusal of any other
URL before a request, and the same retries as complete() on a 429 or 5xx.

Why it exists: video.transcript sends only the canonical URL rebuilt from a
parsed id, and a video read is long and billed, so its wire shape and retry
behaviour are pinned. Google is faked at the httpx transport; pauses are
recorded, never slept.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from services.agent.providers import GeminiProvider, ProviderError
from services.tools.video.provider_video import READER_INSTRUCTION, RESPONSE_SCHEMA

URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
OK = {
    "candidates": [{"content": {"parts": [{"text": '{"passages": []}'}]}}],
    "usageMetadata": {"promptTokenCount": 5000, "candidatesTokenCount": 300},
    "modelVersion": "gemini-3.5-flash-lite-001",
}


class Google:
    def __init__(self, script: list[httpx.Response]):
        self.script = script
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.script.pop(0)


@pytest.fixture
def google(monkeypatch):
    holder: dict[str, Google] = {}
    real = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(lambda r: holder["g"].handle(r))
        return real(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return holder


@pytest.fixture
def pauses(monkeypatch) -> list[float]:
    slept: list[float] = []

    async def record(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(GeminiProvider, "_retry_sleep", staticmethod(record))
    return slept


async def read(provider: GeminiProvider, url: str = URL) -> Any:
    return await provider.read_video_url(
        url=url,
        start_s=0,
        end_s=2700,
        fps=0.25,
        instruction=READER_INSTRUCTION,
        prompt="Write notes from 0:00 to 45:00.",
        response_schema=RESPONSE_SCHEMA,
        max_output_tokens=8192,
    )


@pytest.mark.asyncio
async def test_the_wire_format(google):
    google["g"] = Google([httpx.Response(200, json=OK)])
    provider = GeminiProvider(api_key="AIza-secret", model="gemini-3.5-flash-lite")
    try:
        response = await read(provider)
    finally:
        await provider.aclose()
    [request] = google["g"].requests
    assert request.url.path.endswith("/models/gemini-3.5-flash-lite:generateContent")
    assert "AIza-secret" not in str(request.url)
    assert request.headers["x-goog-api-key"] == "AIza-secret"
    body = json.loads(request.content)
    assert set(body) == {"contents", "systemInstruction", "generationConfig"}
    [content] = body["contents"]
    video, prompt = content["parts"]
    assert video == {
        "fileData": {"fileUri": URL},
        "videoMetadata": {"startOffset": "0s", "endOffset": "2700s", "fps": 0.25},
    }
    assert prompt == {"text": "Write notes from 0:00 to 45:00."}
    assert body["systemInstruction"] == {"parts": [{"text": READER_INSTRUCTION}]}
    config = body["generationConfig"]
    assert config["mediaResolution"] == "MEDIA_RESOLUTION_LOW"
    assert config["responseMimeType"] == "application/json"
    assert config["responseSchema"]["properties"]["passages"]["type"] == "array"
    assert config["maxOutputTokens"] == 8192
    assert config["thinkingConfig"] == {"thinkingLevel": "minimal"}
    assert "tools" not in body
    assert response.content == '{"passages": []}'
    assert response.usage["input_tokens"] == 5000 and response.usage["output_tokens"] == 300
    assert response.served_model == "gemini-3.5-flash-lite-001"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=x",
        "https://evil.test/watch?v=dQw4w9WgXcQ",
        "https://youtu.be/dQw4w9WgXcQ",
        "file:///etc/passwd",
    ],
)
async def test_any_other_url_is_refused_before_a_request(google, url):
    google["g"] = Google([])
    provider = GeminiProvider(api_key="k")
    try:
        with pytest.raises(ValueError):
            await read(provider, url)
    finally:
        await provider.aclose()
    assert google["g"].requests == []


@pytest.mark.asyncio
async def test_a_rate_limit_and_a_server_error_are_asked_again(google, pauses):
    google["g"] = Google(
        [
            httpx.Response(429, json={"error": {"message": "quota"}}, headers={"retry-after": "3"}),
            httpx.Response(503, text="busy"),
            httpx.Response(200, json=OK),
        ]
    )
    provider = GeminiProvider(api_key="k")
    try:
        response = await read(provider)
    finally:
        await provider.aclose()
    assert response.usage["input_tokens"] == 5000
    assert len(google["g"].requests) == 3
    assert pauses == [3.0, 2.0]


@pytest.mark.asyncio
async def test_a_private_video_is_not_asked_again(google, pauses):
    google["g"] = Google([httpx.Response(400, json={"error": {"message": "video is private"}})])
    provider = GeminiProvider(api_key="k")
    try:
        with pytest.raises(ProviderError) as caught:
            await read(provider)
    finally:
        await provider.aclose()
    assert caught.value.status_code == 400
    assert pauses == [] and len(google["g"].requests) == 1
