"""Ollama streaming error path.

Companion to the Gemini regressions in test_providers.py: both providers
hand-roll their streaming HTTP, and both read the error body only after
raise_for_status. On a streamed response the body has not been read yet,
so touching ``.text`` raises httpx.ResponseNotRead and the caller sees
that instead of the ProviderError the route maps to a clean 502.
"""

from __future__ import annotations

import httpx
import pytest

from services.agent.providers import OllamaProvider, ProviderError


class _UnreadStream(httpx.AsyncByteStream):
    """A response body that must be explicitly read, like a real network
    stream — a plain text= response is pre-read and would hide the bug."""

    def __init__(self, payload: bytes):
        self._payload = payload

    async def __aiter__(self):
        yield self._payload


@pytest.mark.asyncio
async def test_ollama_stream_http_error_becomes_provider_error():
    def _responder(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, stream=_UnreadStream(b"model not loaded"))

    provider = OllamaProvider(base_url="http://ollama.test")
    provider._client = httpx.AsyncClient(
        base_url="http://ollama.test",
        transport=httpx.MockTransport(_responder),
    )

    with pytest.raises(ProviderError) as excinfo:
        async for _chunk in provider.stream([{"role": "user", "content": "hi"}]):
            pass

    assert excinfo.value.status_code == 500
    await provider.aclose()


@pytest.mark.asyncio
async def test_ollama_stream_yields_content_chunks():
    body = (
        '{"message": {"content": "Hel"}}\n'
        '{"message": {"content": "lo"}}\n'
        '{"message": {"content": ""}, "done": true}\n'
    )

    def _responder(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    provider = OllamaProvider(base_url="http://ollama.test")
    provider._client = httpx.AsyncClient(
        base_url="http://ollama.test",
        transport=httpx.MockTransport(_responder),
    )

    chunks = [c async for c in provider.stream([{"role": "user", "content": "hi"}])]

    assert chunks == ["Hel", "lo"]
    await provider.aclose()
