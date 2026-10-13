"""Tests for LLMProvider.embed: Gemini's batchEmbedContents body (taskType,
outputDimensionality, batches of 100, retries on 429), OpenAI's dimensions,
Ollama's /api/embed with its prefixes and truncation, normalised output, the
key only in a header, and errors that never carry the key.

Why it exists: the meaning index sends passage text to the owner's provider;
the request must be exactly what the design says and a failure must not
leak the credential into a log, an audit row or a stored error.
"""

from __future__ import annotations

import json
import math
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from services.agent.providers import (
    AnthropicProvider,
    GeminiProvider,
    GrokProvider,
    OllamaProvider,
    OpenAIProvider,
    ProviderError,
)

KEY = "AIzaFAKEKEY-not-real-0123456789abcdefgh"


def _norm(vector: list[float]) -> float:
    return math.sqrt(sum(v * v for v in vector))


class Google:
    def __init__(self, answers: list[tuple[int, Any]]) -> None:
        self.answers = list(answers)
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self.answers.pop(0) if self.answers else (200, None)
        if body is None:
            count = len(json.loads(request.content)["requests"])
            body = {"embeddings": [{"values": [3.0, 4.0] + [0.0] * 254} for _ in range(count)]}
        return httpx.Response(status, json=body)


def _gemini(google: Google) -> GeminiProvider:
    provider = GeminiProvider(api_key=KEY)
    provider._client = httpx.AsyncClient(headers={"x-goog-api-key": KEY}, transport=httpx.MockTransport(google.handle))
    return provider


@pytest.mark.asyncio
async def test_gemini_sends_batch_embed_contents_with_task_type_and_dimensions():
    google = Google([])
    provider = _gemini(google)
    vectors = await provider.embed(["passage one", "passage two"], kind="document", dims=256)
    (request,) = google.requests
    assert request.url.path == "/v1beta/models/gemini-embedding-001:batchEmbedContents"
    assert request.headers["x-goog-api-key"] == KEY and KEY not in str(request.url)
    body = json.loads(request.content)
    assert [r["taskType"] for r in body["requests"]] == ["RETRIEVAL_DOCUMENT", "RETRIEVAL_DOCUMENT"]
    assert {r["outputDimensionality"] for r in body["requests"]} == {256}
    assert body["requests"][0]["model"] == "models/gemini-embedding-001"
    assert body["requests"][1]["content"] == {"parts": [{"text": "passage two"}]}
    assert len(vectors) == 2 and len(vectors[0]) == 256
    assert _norm(vectors[0]) == pytest.approx(1.0) and vectors[0][:2] == pytest.approx([0.6, 0.8])
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_query_task_and_batches_of_a_hundred():
    google = Google([])
    provider = _gemini(google)
    await provider.embed(["q"], kind="query", dims=256)
    assert json.loads(google.requests[0].content)["requests"][0]["taskType"] == "RETRIEVAL_QUERY"
    vectors = await provider.embed([f"t{n}" for n in range(150)], kind="document", dims=256)
    assert len(vectors) == 150
    assert [len(json.loads(r.content)["requests"]) for r in google.requests[1:]] == [100, 50]
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_retries_a_rate_limit_then_succeeds():
    google = Google([(429, {"error": {"message": "slow down"}}), (200, None)])
    provider = _gemini(google)
    vectors = await provider.embed(["x"], kind="document", dims=256)
    assert len(google.requests) == 2 and len(vectors) == 1
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_errors_never_carry_the_key_or_the_body():
    google = Google([(400, {"error": {"message": f"API key {KEY} not valid"}})])
    provider = _gemini(google)
    with pytest.raises(ProviderError) as caught:
        await provider.embed(["x"], kind="document", dims=256)
    assert KEY not in str(caught.value) and "not valid" not in str(caught.value)
    assert caught.value.status_code == 400
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_malformed_answers_are_provider_errors():
    google = Google([(200, {"embeddings": [{"values": []}]})])
    provider = _gemini(google)
    with pytest.raises(ProviderError):
        await provider.embed(["x"], kind="document", dims=256)
    await provider.aclose()


class FakeOpenAIEmbeddings:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail = fail

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.fail:
            error = RuntimeError(f"Incorrect API key provided: {KEY}")
            error.status_code = 401  # type: ignore[attr-defined]
            raise error
        rows = [SimpleNamespace(index=i, embedding=[1.0, 1.0, 1.0, 1.0]) for i in range(len(kwargs["input"]))]
        return SimpleNamespace(data=list(reversed(rows)))


def _openai(fake: FakeOpenAIEmbeddings) -> OpenAIProvider:
    provider = OpenAIProvider(api_key=KEY)
    provider._client = SimpleNamespace(embeddings=fake)  # type: ignore[assignment]
    return provider


@pytest.mark.asyncio
async def test_openai_asks_for_the_dimensions_and_keeps_the_order():
    fake = FakeOpenAIEmbeddings()
    vectors = await _openai(fake).embed(["a", "b"], kind="document", dims=256)
    (call,) = fake.calls
    assert call == {"model": "text-embedding-3-small", "input": ["a", "b"], "dimensions": 256}
    assert len(vectors) == 2 and _norm(vectors[0]) == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_openai_errors_name_the_status_but_never_the_key():
    with pytest.raises(ProviderError) as caught:
        await _openai(FakeOpenAIEmbeddings(fail=True)).embed(["a"], kind="query", dims=256)
    assert KEY not in str(caught.value) and caught.value.status_code == 401


@pytest.mark.asyncio
async def test_only_openai_itself_embeds_not_the_compatible_vendors():
    assert OpenAIProvider.supports_embeddings is True
    assert GrokProvider.supports_embeddings is False
    assert AnthropicProvider.supports_embeddings is False
    grok = GrokProvider(api_key="k")
    with pytest.raises(ProviderError, match="no embedding model"):
        await grok.embed(["a"], kind="document", dims=256)
    await grok.aclose()


class Ollama:
    def __init__(self, width: int = 768, status: int = 200) -> None:
        self.width = width
        self.status = status
        self.bodies: list[dict[str, Any]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.bodies.append({"path": request.url.path, **body})
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "model not found"})
        return httpx.Response(200, json={"embeddings": [[1.0] * self.width for _ in body["input"]]})


def _ollama(fake: Ollama) -> OllamaProvider:
    provider = OllamaProvider(base_url="http://localhost:11434")
    provider._client = httpx.AsyncClient(base_url="http://localhost:11434", transport=httpx.MockTransport(fake.handle))
    return provider


@pytest.mark.asyncio
async def test_ollama_prefixes_truncates_and_normalises():
    fake = Ollama()
    provider = _ollama(fake)
    docs = await provider.embed(["alpha", "beta"], kind="document", dims=256)
    query = await provider.embed(["gamma"], kind="query", dims=256)
    assert fake.bodies[0] == {"path": "/api/embed", "model": "nomic-embed-text", "input": ["search_document: alpha", "search_document: beta"]}
    assert fake.bodies[1]["input"] == ["search_query: gamma"]
    assert len(docs[0]) == 256 and _norm(docs[0]) == pytest.approx(1.0) and len(query) == 1
    await provider.aclose()


@pytest.mark.asyncio
async def test_ollama_keeps_an_unknown_models_own_size_and_maps_errors():
    fake = Ollama(width=384)
    provider = _ollama(fake)
    (vector,) = await provider.embed(["x"], kind="document", dims=256, model="all-minilm")
    assert len(vector) == 384 and fake.bodies[0]["input"] == ["x"]
    broken = _ollama(Ollama(status=404))
    with pytest.raises(ProviderError) as caught:
        await broken.embed(["x"], kind="document", dims=256)
    assert caught.value.status_code == 404
    await provider.aclose()
    await broken.aclose()
