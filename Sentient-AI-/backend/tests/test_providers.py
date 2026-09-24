"""Tests for the LLM provider layer: request construction, response normalization,
streaming, vision and image handling, and cache-token accounting are all
correct for the Anthropic, OpenAI-compatible, Gemini, and Ollama provider
families, and that every upstream error becomes a clean ProviderError without
leaking a credential.

Why it exists: Every chat turn crosses this module, so each provider is
exercised end to end with its SDK or socket replaced by a stub or mock rather
than trusting each vendor's client library to fail safely.

The LLM provider layer: request construction, response normalisation,
and the error contract.

Every chat turn crosses this module, so each provider family is exercised
end to end with the SDK entry point replaced by a stub (Anthropic/OpenAI)
or the socket replaced by an ``httpx.MockTransport`` (Gemini/Ollama).
Nothing here opens a connection or needs a credential.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from services.agent import providers
from services.agent.providers import (
    AnthropicProvider,
    DeepseekProvider,
    GeminiProvider,
    GrokProvider,
    GroqProvider,
    LLMProvider,
    MistralProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
    ProviderError,
    ToolCall,
    create_provider,
)

TOOLS = [
    {
        "name": "search",
        "description": "Search the web",
        "parameters": {"type": "object", "properties": {"q": {"type": "string"}}},
    },
    # No "parameters" key: every converter must substitute an empty schema
    # rather than emit a tool the provider will reject.
    {"name": "ping"},
]


# ---------------------------------------------------------------------------
# Anthropic SDK stub
# ---------------------------------------------------------------------------


@dataclass
class _TextBlock:
    text: str
    type: str = "text"


@dataclass
class _ToolUseBlock:
    id: str
    name: str
    input: dict[str, Any] | None = None
    type: str = "tool_use"


@dataclass
class _AnthropicUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class _AnthropicResponse:
    content: list[Any] = field(default_factory=list)
    model: str = "claude-sonnet-4-20250514"
    usage: _AnthropicUsage = field(default_factory=_AnthropicUsage)


class _FakeAnthropicMessages:
    def __init__(self, client: "FakeAnthropicClient"):
        self._client = client

    async def create(self, **kwargs: Any) -> Any:
        self._client.create_calls.append(kwargs)
        if self._client.error is not None:
            raise self._client.error
        return self._client.response


class FakeAnthropicClient:
    """Stands in for ``anthropic.AsyncAnthropic``.

    Records the constructor kwargs so the shared timeout/retry budget can
    be asserted, and the ``messages.create`` kwargs so the request the
    provider actually builds can be inspected.
    """

    def __init__(self, **init_kwargs: Any):
        self.init_kwargs = init_kwargs
        self.create_calls: list[dict[str, Any]] = []
        self.response: Any = _AnthropicResponse()
        self.error: Exception | None = None
        self.closed = False
        self.messages = _FakeAnthropicMessages(self)

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_anthropic(monkeypatch):
    """Swap the SDK client class so no provider ever opens a socket."""
    import anthropic

    created: list[FakeAnthropicClient] = []

    def _factory(**kwargs: Any) -> FakeAnthropicClient:
        client = FakeAnthropicClient(**kwargs)
        created.append(client)
        return client

    monkeypatch.setattr(anthropic, "AsyncAnthropic", _factory)
    return created


def _anthropic_error(status: int, message: str) -> Exception:
    import anthropic

    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx.Response(status, request=request, text=message)
    return anthropic.APIStatusError(message, response=response, body=None)


# ---------------------------------------------------------------------------
# OpenAI SDK stub
# ---------------------------------------------------------------------------


@dataclass
class _OAIFunction:
    name: str
    arguments: Any


@dataclass
class _OAIToolCall:
    id: str
    function: _OAIFunction
    type: str = "function"


@dataclass
class _OAIMessage:
    content: str | None = None
    tool_calls: list[_OAIToolCall] | None = None


@dataclass
class _OAIChoice:
    message: _OAIMessage


@dataclass
class _OAIUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class _OAIResponse:
    choices: list[_OAIChoice] = field(default_factory=list)
    model: str = "gpt-4o-2024-08-06"
    usage: _OAIUsage | None = field(default_factory=_OAIUsage)


class _AsyncChunks:
    """Minimal async iterable standing in for an SDK stream object."""

    def __init__(self, chunks: list[Any]):
        self._chunks = list(chunks)

    def __aiter__(self) -> "_AsyncChunks":
        return self

    async def __anext__(self) -> Any:
        if not self._chunks:
            raise StopAsyncIteration
        return self._chunks.pop(0)


class _FakeCompletions:
    def __init__(self, client: "FakeOpenAIClient"):
        self._client = client

    async def create(self, **kwargs: Any) -> Any:
        self._client.create_calls.append(kwargs)
        if self._client.error is not None:
            raise self._client.error
        return self._client.response


class FakeOpenAIClient:
    """Stands in for ``openai.AsyncOpenAI`` (and every compatible vendor)."""

    def __init__(self, **init_kwargs: Any):
        self.init_kwargs = init_kwargs
        self.create_calls: list[dict[str, Any]] = []
        self.response: Any = _OAIResponse(choices=[_OAIChoice(_OAIMessage(content=""))])
        self.error: Exception | None = None
        self.closed = False
        self.chat = SimpleNamespace(completions=_FakeCompletions(self))

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_openai(monkeypatch):
    import openai

    created: list[FakeOpenAIClient] = []

    def _factory(**kwargs: Any) -> FakeOpenAIClient:
        client = FakeOpenAIClient(**kwargs)
        created.append(client)
        return client

    monkeypatch.setattr(openai, "AsyncOpenAI", _factory)
    return created


def _openai_error(status: int, message: str) -> Exception:
    import openai

    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = httpx.Response(status, request=request, text=message)
    return openai.APIStatusError(message, response=response, body=None)


# ---------------------------------------------------------------------------
# httpx transport stub for the hand-rolled REST providers
# ---------------------------------------------------------------------------


class TransportRecorder:
    """Captures the requests a provider makes and scripts the replies.

    The provider's own client kwargs (headers, timeout, base_url) are left
    alone — only the transport is swapped — so assertions about the wire
    format are assertions about production behaviour.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responder = lambda request: httpx.Response(200, json={})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responder(request)

    @property
    def last_request(self) -> httpx.Request:
        return self.requests[-1]

    @property
    def last_payload(self) -> dict[str, Any]:
        return json.loads(self.requests[-1].content)


@pytest.fixture
def transport(monkeypatch):
    real_client_cls = httpx.AsyncClient
    recorder = TransportRecorder()

    def _factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(recorder.handle)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return recorder


class _UnreadStream(httpx.AsyncByteStream):
    """An error body that has not been read yet, as a real streamed HTTP
    error response would be."""

    def __init__(self, body: bytes):
        self._body = body

    async def __aiter__(self):
        yield self._body


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anthropic_complete_parses_text_and_tool_use(fake_anthropic):
    provider = AnthropicProvider(api_key="sk-ant-secret")
    provider._client.response = _AnthropicResponse(
        content=[
            _TextBlock(text="Let me look. "),
            _ToolUseBlock(id="toolu_1", name="search", input={"q": "cats"}),
            # A block type this layer does not model (e.g. thinking) must be
            # ignored, not crash the parse.
            SimpleNamespace(type="thinking", thinking="hmm"),
            _TextBlock(text="One moment."),
            # Anthropic sends input=None for a zero-argument tool.
            _ToolUseBlock(id="toolu_2", name="ping", input=None),
        ],
        model="claude-sonnet-4-20250514",
        usage=_AnthropicUsage(input_tokens=31, output_tokens=7),
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.content == "Let me look. One moment."
    assert resp.tool_calls == [
        ToolCall(id="toolu_1", name="search", arguments={"q": "cats"}),
        ToolCall(id="toolu_2", name="ping", arguments={}),
    ]
    assert resp.model == "claude-sonnet-4-20250514"
    assert resp.usage == {"input_tokens": 31, "output_tokens": 7}


@pytest.mark.asyncio
async def test_anthropic_sends_every_system_message_to_the_model(fake_anthropic):
    """Security property: the first system message is the injection-defense
    policy. A later system message must be appended, never replace it."""
    provider = AnthropicProvider(api_key="sk-ant-secret")

    await provider.complete(
        [
            {"role": "system", "content": "POLICY: money never moves"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
            {"role": "system", "content": "stray late instruction"},
            {"role": "user", "content": "go"},
        ]
    )

    kwargs = provider._client.create_calls[0]
    assert kwargs["system"] == [
        {
            "type": "text",
            "text": "POLICY: money never moves\n\nstray late instruction",
            "cache_control": {"type": "ephemeral"},
        }
    ]
    assert kwargs["messages"] == [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
        {"role": "user", "content": "go"},
    ]


@pytest.mark.asyncio
async def test_anthropic_omits_system_and_tools_when_absent(fake_anthropic):
    provider = AnthropicProvider(api_key="sk-ant-secret")

    await provider.complete([{"role": "user", "content": "hi"}], tools=[])

    kwargs = provider._client.create_calls[0]
    assert "system" not in kwargs
    assert "tools" not in kwargs
    assert kwargs["model"] == "claude-sonnet-4-20250514"


def test_anthropic_tool_schema_conversion():
    assert AnthropicProvider._convert_tools(None) is None
    assert AnthropicProvider._convert_tools([]) is None
    assert AnthropicProvider._convert_tools(TOOLS) == [
        {
            "name": "search",
            "description": "Search the web",
            "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
        },
        {
            "name": "ping",
            "description": "",
            "input_schema": {"type": "object", "properties": {}},
            # Cache breakpoint on the last tool only — it covers the whole
            # tool prefix, and Anthropic allows a handful of markers, not
            # one per tool.
            "cache_control": {"type": "ephemeral"},
        },
    ]


@pytest.mark.asyncio
async def test_anthropic_api_error_becomes_provider_error_without_leaking_key(
    fake_anthropic,
):
    api_key = "sk-ant-api03-DO-NOT-LEAK-ME"
    provider = AnthropicProvider(api_key=api_key)
    provider._client.error = _anthropic_error(429, "x" * 500)

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    err = excinfo.value
    assert err.provider == "anthropic"
    assert err.status_code == 429
    assert "HTTP 429" in str(err)
    # The upstream body is truncated, never echoed wholesale.
    assert len(err.detail) <= 300
    # Nothing client-side (the credential) is ever interpolated into the
    # message that reaches logs and users.
    assert api_key not in str(err)


@pytest.mark.asyncio
async def test_anthropic_client_uses_module_request_budget(fake_anthropic):
    provider = AnthropicProvider(api_key="sk-ant-secret")

    init_kwargs = provider._client.init_kwargs
    assert init_kwargs["timeout"] == providers._REQUEST_TIMEOUT_SECONDS
    assert init_kwargs["max_retries"] == providers._MAX_RETRIES
    # The whole point of overriding the SDK is a budget far below its
    # ~10-minute default; a regression to the default would pin server
    # resources for the duration.
    assert providers._REQUEST_TIMEOUT_SECONDS <= 180.0


@pytest.mark.asyncio
async def test_anthropic_aclose_closes_the_sdk_client(fake_anthropic):
    provider = AnthropicProvider(api_key="sk-ant-secret")

    await provider.aclose()

    assert provider._client.closed is True


# ---------------------------------------------------------------------------
# OpenAI-compatible family
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openai_complete_normalises_content_model_and_usage(fake_openai):
    provider = OpenAIProvider(api_key="sk-secret")
    provider._client.response = _OAIResponse(
        choices=[_OAIChoice(_OAIMessage(content="hello there"))],
        model="gpt-4o-2024-08-06",
        usage=_OAIUsage(prompt_tokens=12, completion_tokens=4),
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}], tools=TOOLS)

    assert resp.content == "hello there"
    assert resp.tool_calls == []
    assert resp.model == "gpt-4o-2024-08-06"
    assert resp.usage == {"input_tokens": 12, "output_tokens": 4, "cache_write_tokens": 0}
    # Messages are passed through untouched (the OpenAI schema already
    # carries the system role).
    assert provider._client.create_calls[0]["messages"] == [
        {"role": "user", "content": "hi"}
    ]


@pytest.mark.asyncio
async def test_openai_tool_calls_survive_malformed_arguments(fake_openai):
    """A vendor that emits truncated or null JSON arguments must still
    produce a ToolCall — with empty arguments — instead of blowing up the
    whole turn."""
    provider = OpenAIProvider(api_key="sk-secret")
    provider._client.response = _OAIResponse(
        choices=[
            _OAIChoice(
                _OAIMessage(
                    content=None,
                    tool_calls=[
                        _OAIToolCall("call_1", _OAIFunction("search", '{"q": "cats"}')),
                        _OAIToolCall("call_2", _OAIFunction("search", '{"q": "tru')),
                        _OAIToolCall("call_3", _OAIFunction("ping", None)),
                    ],
                )
            )
        ]
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.content == ""
    assert resp.tool_calls == [
        ToolCall(id="call_1", name="search", arguments={"q": "cats"}),
        ToolCall(id="call_2", name="search", arguments={}),
        ToolCall(id="call_3", name="ping", arguments={}),
    ]


@pytest.mark.asyncio
async def test_openai_empty_choices_raises_provider_error(fake_openai):
    """Regression: an empty choices array (outage/content filtering) used
    to surface as IndexError -> generic 500 instead of the designed 502."""
    provider = OpenAIProvider(api_key="sk-secret")
    provider._client.response = _OAIResponse(choices=[])

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    err = excinfo.value
    assert err.provider == "openai"
    assert err.status_code is None
    assert "no choices" in err.detail


@pytest.mark.asyncio
async def test_openai_missing_usage_and_model_fall_back(fake_openai):
    provider = OpenAIProvider(api_key="sk-secret", model="gpt-4o")
    provider._client.response = _OAIResponse(
        choices=[_OAIChoice(_OAIMessage(content="ok"))],
        model="",
        usage=None,
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.usage == {"input_tokens": 0, "output_tokens": 0, "cache_write_tokens": 0}
    assert resp.model == "gpt-4o"


@pytest.mark.asyncio
async def test_openai_api_error_becomes_provider_error_with_vendor_name(fake_openai):
    api_key = "xai-DO-NOT-LEAK-ME"
    provider = GrokProvider(api_key=api_key)
    provider._client.error = _openai_error(503, "Error code: 503 - upstream is down")

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    err = excinfo.value
    # The subclass's own name must reach the user, not the base "openai".
    assert err.provider == "grok"
    assert err.status_code == 503
    assert "upstream is down" in err.detail
    assert api_key not in str(err)


@pytest.mark.parametrize(
    "provider_cls,expected_base_url,expected_model,expected_name",
    [
        (OpenAIProvider, None, "gpt-4o", "openai"),
        (GrokProvider, "https://api.x.ai/v1", "grok-3", "grok"),
        (DeepseekProvider, "https://api.deepseek.com", "deepseek-chat", "deepseek"),
        (
            GroqProvider,
            "https://api.groq.com/openai/v1",
            "llama-3.3-70b-versatile",
            "groq",
        ),
        (MistralProvider, "https://api.mistral.ai/v1", "mistral-large-latest", "mistral"),
    ],
)
def test_openai_compatible_subclasses_are_wired_to_their_vendor(
    fake_openai, provider_cls, expected_base_url, expected_model, expected_name
):
    provider = provider_cls(api_key="secret")

    # OpenAI itself must NOT pass base_url — the SDK default is correct and
    # hardcoding it would break Azure/proxy deployments.
    assert provider._client.init_kwargs.get("base_url") == expected_base_url
    assert provider._model == expected_model
    assert provider._provider_name == expected_name


def test_openai_tool_schema_conversion():
    assert OpenAICompatibleProvider._convert_tools(None) is None
    assert OpenAICompatibleProvider._convert_tools([]) is None
    assert OpenAICompatibleProvider._convert_tools(TOOLS) == [
        {
            "type": "function",
            "function": {
                "name": "search",
                "description": "Search the web",
                "parameters": {
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "ping",
                "description": "",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    ]


def test_openai_client_uses_module_request_budget(fake_openai):
    provider = OpenAIProvider(api_key="sk-secret")

    init_kwargs = provider._client.init_kwargs
    assert init_kwargs["timeout"] == providers._REQUEST_TIMEOUT_SECONDS
    assert init_kwargs["max_retries"] == providers._MAX_RETRIES


@pytest.mark.asyncio
async def test_openai_aclose_closes_the_sdk_client(fake_openai):
    provider = OpenAIProvider(api_key="sk-secret")

    await provider.aclose()

    assert provider._client.closed is True


@pytest.mark.asyncio
async def test_openai_stream_yields_deltas_and_tolerates_choiceless_chunks(fake_openai):
    provider = OpenAIProvider(api_key="sk-secret")
    provider._client.response = _AsyncChunks(
        [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Hel"))]),
            # Azure/OpenAI emit a leading content-filter chunk with no choices.
            SimpleNamespace(choices=[]),
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=None))]),
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="lo"))]),
        ]
    )

    chunks = [c async for c in provider.stream([{"role": "user", "content": "hi"}])]

    assert chunks == ["Hel", "lo"]
    assert provider._client.create_calls[0]["stream"] is True


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gemini_parses_candidates_parts_and_function_calls(transport):
    transport.responder = lambda request: httpx.Response(
        200,
        json={
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Let me look. "},
                            {"functionCall": {"name": "search", "args": {"q": "cats"}}},
                            {"text": "One moment."},
                            {"functionCall": {"name": "ping"}},
                        ]
                    }
                }
            ],
            "usageMetadata": {"promptTokenCount": 20, "candidatesTokenCount": 6},
        },
    )
    # A misconfigured mixed-case model id must still resolve.
    provider = GeminiProvider(api_key="AIza-secret", model="Gemini-2.5-Flash")

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.content == "Let me look. One moment."
    assert resp.tool_calls == [
        ToolCall(id="gemini_1", name="search", arguments={"q": "cats"}),
        ToolCall(id="gemini_3", name="ping", arguments={}),
    ]
    assert resp.model == "gemini-2.5-flash"
    assert resp.usage == {"input_tokens": 20, "output_tokens": 6, "cache_write_tokens": 0}
    assert str(transport.last_request.url).endswith(
        "/v1beta/models/gemini-2.5-flash:generateContent"
    )
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_api_key_travels_in_header_never_in_url(transport):
    """Regression: the key must not reach request URLs, which land in
    access logs, proxies, and tracebacks."""
    api_key = "AIzaSy-DO-NOT-LEAK-ME"
    transport.responder = lambda request: httpx.Response(
        200, json={"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
    )
    provider = GeminiProvider(api_key=api_key)

    await provider.complete([{"role": "user", "content": "hi"}])

    request = transport.last_request
    assert request.headers["x-goog-api-key"] == api_key
    assert api_key not in str(request.url)
    assert request.url.query == b""
    assert "authorization" not in request.headers
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_empty_candidates_raises_provider_error(transport):
    """A safety-blocked prompt comes back with no candidates. Returning
    blank content here used to be persisted as a permanent empty assistant
    message (and cached); it must surface as a ProviderError that names
    the block reason instead."""
    transport.responder = lambda request: httpx.Response(
        200, json={"promptFeedback": {"blockReason": "SAFETY"}}
    )
    provider = GeminiProvider(api_key="AIza-secret")

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    assert "SAFETY" in str(excinfo.value)
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_textless_candidate_raises_provider_error(transport):
    """A candidate with neither text nor tool calls (e.g. finishReason
    RECITATION) is a failed completion, not a silent blank."""
    transport.responder = lambda request: httpx.Response(
        200,
        json={"candidates": [{"content": {"parts": []}, "finishReason": "RECITATION"}]},
    )
    provider = GeminiProvider(api_key="AIza-secret")

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    assert "RECITATION" in str(excinfo.value)
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_transport_error_becomes_provider_error(transport):
    """Connect/read failures escape the request call itself, not
    raise_for_status; they must still surface as ProviderError (the
    blocking route's designed 502), never a raw 500."""
    def _refuse(request):
        raise httpx.ConnectError("connection refused")

    transport.responder = _refuse
    provider = GeminiProvider(api_key="AIza-secret")

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    assert "could not reach the provider" in str(excinfo.value)
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_http_error_becomes_provider_error_without_url_or_key(transport):
    api_key = "AIzaSy-DO-NOT-LEAK-ME"
    transport.responder = lambda request: httpx.Response(
        429, text="Quota exceeded for quota metric 'Generate requests'"
    )
    provider = GeminiProvider(api_key=api_key)

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    err = excinfo.value
    assert err.provider == "gemini"
    assert err.status_code == 429
    assert "Quota exceeded" in err.detail
    assert api_key not in str(err)
    assert "generativelanguage" not in str(err)
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_payload_carries_all_system_messages_roles_and_tools(transport):
    transport.responder = lambda request: httpx.Response(
        200, json={"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
    )
    provider = GeminiProvider(api_key="AIza-secret")

    await provider.complete(
        [
            {"role": "system", "content": "POLICY: money never moves"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
            {"role": "system", "content": "stray late instruction"},
        ],
        tools=TOOLS,
    )

    payload = transport.last_payload
    assert payload["systemInstruction"] == {
        "parts": [{"text": "POLICY: money never moves\n\nstray late instruction"}]
    }
    assert payload["contents"] == [
        {"role": "user", "parts": [{"text": "hello"}]},
        {"role": "model", "parts": [{"text": "hi"}]},
    ]
    assert [d["name"] for d in payload["tools"][0]["functionDeclarations"]] == [
        "search",
        "ping",
    ]
    assert payload["tools"][0]["functionDeclarations"][1]["parameters"] == {
        "type": "object",
        "properties": {},
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_stream_yields_text_and_skips_unparseable_lines(transport):
    body = "\n".join(
        [
            '[{"candidates": [{"content": {"parts": [{"text": "Hel"}]}}]}',
            "",
            "not json at all",
            ',{"candidates": [{"content": {"parts": [{"text": "lo"}]}}]}',
            "]",
        ]
    )
    transport.responder = lambda request: httpx.Response(200, text=body)
    provider = GeminiProvider(api_key="AIza-secret")

    chunks = [c async for c in provider.stream([{"role": "user", "content": "hi"}])]

    assert chunks == ["Hel", "lo"]
    assert str(transport.last_request.url).endswith(":streamGenerateContent")
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_client_uses_module_timeout_and_aclose_closes_it(transport):
    provider = GeminiProvider(api_key="AIza-secret")

    assert provider._client.timeout == httpx.Timeout(providers._REQUEST_TIMEOUT_SECONDS)

    await provider.aclose()

    assert provider._client.is_closed is True


# Regression: Gemini emits trailing chunks carrying only usageMetadata with
# an empty candidates list. A dict .get default does not apply to a
# present-but-empty value, so indexing [0] raised IndexError and killed the
# stream mid-answer.
@pytest.mark.asyncio
async def test_gemini_stream_tolerates_chunks_with_no_candidates(transport):
    body = "\n".join(
        [
            '[{"candidates": [{"content": {"parts": [{"text": "Hel"}]}}]}',
            ',{"candidates": [], "usageMetadata": {"promptTokenCount": 3}}',
            ',{"candidates": [{"content": {"parts": [{"text": "lo"}]}}]}',
            "]",
        ]
    )
    transport.responder = lambda request: httpx.Response(200, text=body)
    provider = GeminiProvider(api_key="AIza-secret")

    chunks = [c async for c in provider.stream([{"role": "user", "content": "hi"}])]

    assert chunks == ["Hel", "lo"]
    await provider.aclose()


# Regression: the error path read exc.response.text on a streamed response
# whose body had not been read, so httpx.ResponseNotRead escaped instead of
# the ProviderError the route maps to a 502.
@pytest.mark.asyncio
async def test_gemini_stream_http_error_becomes_provider_error(transport):
    transport.responder = lambda request: httpx.Response(
        503, stream=_UnreadStream(b"backend unavailable")
    )
    provider = GeminiProvider(api_key="AIza-secret")

    with pytest.raises(ProviderError):
        async for _ in provider.stream([{"role": "user", "content": "hi"}]):
            pass

    await provider.aclose()


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ollama_complete_parses_message_and_tool_calls(transport):
    transport.responder = lambda request: httpx.Response(
        200,
        json={
            "model": "llama3.2:latest",
            "message": {
                "content": "on it",
                "tool_calls": [
                    {"function": {"name": "search", "arguments": {"q": "cats"}}},
                    {"function": {"name": "ping"}},
                ],
            },
            "prompt_eval_count": 9,
            "eval_count": 3,
        },
    )
    provider = OllamaProvider()

    resp = await provider.complete([{"role": "user", "content": "hi"}], tools=TOOLS)

    assert resp.content == "on it"
    assert resp.tool_calls == [
        ToolCall(id="ollama_0", name="search", arguments={"q": "cats"}),
        ToolCall(id="ollama_1", name="ping", arguments={}),
    ]
    assert resp.model == "llama3.2:latest"
    assert resp.usage == {"input_tokens": 9, "output_tokens": 3, "cache_write_tokens": 0}
    await provider.aclose()


@pytest.mark.asyncio
async def test_ollama_posts_to_chat_endpoint_with_normalised_base_url(transport):
    provider = OllamaProvider(base_url="http://ollama.internal:11434/", model="qwen2.5")

    await provider.complete([{"role": "user", "content": "hi"}], tools=TOOLS)

    assert str(transport.last_request.url) == "http://ollama.internal:11434/api/chat"
    payload = transport.last_payload
    assert payload["model"] == "qwen2.5"
    assert payload["stream"] is False
    assert payload["tools"][0]["function"]["name"] == "search"
    await provider.aclose()


@pytest.mark.asyncio
async def test_ollama_missing_message_fields_default_safely(transport):
    transport.responder = lambda request: httpx.Response(200, json={})
    provider = OllamaProvider(model="llama3.2")

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.content == ""
    assert resp.tool_calls == []
    assert resp.model == "llama3.2"
    assert resp.usage == {"input_tokens": 0, "output_tokens": 0, "cache_write_tokens": 0}
    await provider.aclose()


@pytest.mark.asyncio
async def test_ollama_http_error_becomes_provider_error(transport):
    transport.responder = lambda request: httpx.Response(
        404, text='{"error":"model \'llama3.2\' not found"}'
    )
    provider = OllamaProvider()

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "hi"}])

    err = excinfo.value
    assert err.provider == "ollama"
    assert err.status_code == 404
    assert "not found" in err.detail
    assert "localhost:11434" not in str(err)
    await provider.aclose()


@pytest.mark.asyncio
async def test_ollama_stream_yields_content_and_skips_malformed_lines(transport):
    body = "\n".join(
        [
            json.dumps({"message": {"content": "Hel"}}),
            "",
            "{ truncated json",
            json.dumps({"message": {"content": ""}}),
            json.dumps({"message": {"content": "lo"}}),
            json.dumps({"done": True}),
        ]
    )
    transport.responder = lambda request: httpx.Response(200, text=body)
    provider = OllamaProvider()

    chunks = [c async for c in provider.stream([{"role": "user", "content": "hi"}])]

    assert chunks == ["Hel", "lo"]
    assert transport.last_payload["stream"] is True
    await provider.aclose()


@pytest.mark.asyncio
async def test_ollama_client_uses_module_timeout_and_aclose_closes_it(transport):
    provider = OllamaProvider()

    assert provider._client.timeout == httpx.Timeout(providers._REQUEST_TIMEOUT_SECONDS)

    await provider.aclose()

    assert provider._client.is_closed is True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected_cls",
    [
        ("anthropic", AnthropicProvider),
        ("openai", OpenAIProvider),
        ("gemini", GeminiProvider),
        ("grok", GrokProvider),
        ("deepseek", DeepseekProvider),
        ("groq", GroqProvider),
        ("mistral", MistralProvider),
        ("ollama", OllamaProvider),
    ],
)
@pytest.mark.asyncio
async def test_create_provider_resolves_every_registered_name(
    name, expected_cls, fake_anthropic, fake_openai, transport
):
    provider = create_provider(name, "some-model", api_key="secret")

    assert type(provider) is expected_cls
    assert isinstance(provider, LLMProvider)
    assert provider._model == "some-model"
    await provider.aclose()


def test_create_provider_registry_matches_the_documented_names():
    assert set(providers.PROVIDER_REGISTRY) == {
        "anthropic",
        "openai",
        "gemini",
        "grok",
        "deepseek",
        "groq",
        "mistral",
        "ollama",
    }


def test_create_provider_rejects_unknown_name():
    with pytest.raises(ValueError) as excinfo:
        create_provider("skynet", "some-model", api_key="secret")

    message = str(excinfo.value)
    assert "skynet" in message
    # The error has to be actionable: it lists what *is* supported.
    assert "anthropic" in message and "ollama" in message


@pytest.mark.parametrize(
    "name", ["anthropic", "openai", "gemini", "grok", "deepseek", "groq", "mistral"]
)
def test_create_provider_requires_an_api_key_for_hosted_providers(name):
    with pytest.raises(ValueError) as excinfo:
        create_provider(name, "some-model", api_key=None)

    assert f"{name.upper()}_API_KEY" in str(excinfo.value)


@pytest.mark.asyncio
async def test_create_provider_builds_ollama_without_a_key(transport):
    """Ollama is local: it must stay usable with no credential configured,
    and must honour the configured base_url."""
    provider = create_provider(
        "ollama", "llama3.2", api_key=None, base_url="http://ollama.internal:11434"
    )

    assert isinstance(provider, OllamaProvider)
    assert provider._base_url == "http://ollama.internal:11434"
    await provider.aclose()


# ---------------------------------------------------------------------------
# Vision: multimodal content blocks
# ---------------------------------------------------------------------------

# One base64 pixel. Its content never matters to this layer — what matters
# is that the bytes reach each vendor in the shape that vendor expects.
PIXEL = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAE"

VISION_MESSAGES = [
    {"role": "system", "content": "POLICY: money never moves"},
    {
        "role": "user",
        "content": [
            {"type": "text", "text": "which shelf is this?"},
            {"type": "image", "media_type": "image/jpeg", "data": PIXEL},
        ],
    },
]


@pytest.mark.asyncio
async def test_anthropic_sends_images_as_base64_source_blocks(fake_anthropic):
    provider = AnthropicProvider(api_key="sk-ant-secret")

    await provider.complete(VISION_MESSAGES)

    kwargs = provider._client.create_calls[0]
    assert kwargs["messages"] == [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "which shelf is this?"},
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": PIXEL,
                    },
                },
            ],
        }
    ]
    # The policy slot stays text: an image can never carry instruction
    # authority.
    assert kwargs["system"][0]["text"] == "POLICY: money never moves"


@pytest.mark.asyncio
async def test_openai_sends_images_as_image_url_parts(fake_openai):
    provider = OpenAIProvider(api_key="sk-secret")

    await provider.complete(VISION_MESSAGES)

    sent = provider._client.create_calls[0]["messages"]
    assert sent[1]["content"] == [
        {"type": "text", "text": "which shelf is this?"},
        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{PIXEL}"}},
    ]
    # A text-only message keeps the bare-string shape it always had;
    # rewriting every message into parts would churn the prefix the
    # automatic prompt cache matches on.
    assert sent[0]["content"] == "POLICY: money never moves"


@pytest.mark.asyncio
async def test_gemini_sends_images_as_inline_data(transport):
    provider = GeminiProvider(api_key="g-secret")
    transport.responder = lambda request: httpx.Response(
        200,
        json={"candidates": [{"content": {"parts": [{"text": "A KALLAX."}]}}]},
    )

    resp = await provider.complete(VISION_MESSAGES)

    assert resp.content == "A KALLAX."
    payload = transport.last_payload
    assert payload["contents"] == [
        {
            "role": "user",
            "parts": [
                {"text": "which shelf is this?"},
                {"inlineData": {"mimeType": "image/jpeg", "data": PIXEL}},
            ],
        }
    ]
    assert payload["systemInstruction"] == {
        "parts": [{"text": "POLICY: money never moves"}]
    }
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory",
    [
        lambda: DeepseekProvider(api_key="k"),
        lambda: GroqProvider(api_key="k"),
        lambda: OllamaProvider(),
    ],
)
async def test_providers_without_vision_refuse_rather_than_drop_the_image(
    factory, fake_openai, transport
):
    """Silently stripping the image would leave the model answering a
    question about a picture it never saw, with nothing in the reply to
    say so."""
    provider = factory()

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete(VISION_MESSAGES)

    message = str(excinfo.value)
    assert provider._provider_name in message
    assert "image attachments" in message
    # Actionable: it names what to switch to.
    assert "Anthropic" in message
    await provider.aclose()


@pytest.mark.asyncio
async def test_a_non_vision_provider_still_serves_a_text_only_turn(fake_openai):
    provider = DeepseekProvider(api_key="k")
    provider._client.response = _OAIResponse(
        choices=[_OAIChoice(_OAIMessage(content="fine"))]
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.content == "fine"


@pytest.mark.asyncio
async def test_non_vision_refusal_also_covers_the_streaming_path(transport):
    provider = OllamaProvider()

    with pytest.raises(ProviderError):
        async for _ in provider.stream(VISION_MESSAGES):
            pass

    # Nothing was put on the wire.
    assert transport.requests == []
    await provider.aclose()


def test_vision_support_is_declared_per_provider():
    """The runtime has to answer "can I send this photo?" before spending a
    request, so the flag lives on the class."""
    assert AnthropicProvider.supports_vision is True
    assert OpenAIProvider.supports_vision is True
    assert GeminiProvider.supports_vision is True
    assert OpenAICompatibleProvider.supports_vision is False
    assert DeepseekProvider.supports_vision is False
    assert OllamaProvider.supports_vision is False


# ---------------------------------------------------------------------------
# Prompt caching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anthropic_marks_one_cache_breakpoint_on_system_and_on_tools(
    fake_anthropic,
):
    """Cached input bills at roughly a tenth of fresh input, and the system
    prompt plus tool schemas are re-sent verbatim on every turn."""
    provider = AnthropicProvider(api_key="sk-ant-secret")

    await provider.complete(
        [{"role": "system", "content": "policy"}, {"role": "user", "content": "hi"}],
        tools=TOOLS,
    )

    kwargs = provider._client.create_calls[0]
    assert kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}
    # Exactly one marker on the tool array: Anthropic allows a handful of
    # breakpoints, not one per tool, and the last one covers the prefix.
    marked = [t for t in kwargs["tools"] if "cache_control" in t]
    assert len(marked) == 1
    assert marked[0] is kwargs["tools"][-1]


@pytest.mark.asyncio
async def test_anthropic_input_count_includes_the_cached_prefix(fake_anthropic):
    """Anthropic's own input_tokens is only the part after the last cache
    breakpoint. The normalised count is the whole prompt, so it compares
    with every other provider's and a warm cache does not hide the prompt."""
    provider = AnthropicProvider(api_key="sk-ant-secret")
    usage = _AnthropicUsage(input_tokens=40, output_tokens=9)
    usage.cache_read_input_tokens = 610
    usage.cache_creation_input_tokens = 150
    provider._client.response = _AnthropicResponse(
        content=[_TextBlock(text="hi")], usage=usage
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.usage == {
        "input_tokens": 800,
        "output_tokens": 9,
        "cache_read_tokens": 610,
        "cache_write_tokens": 150,
    }


@pytest.mark.asyncio
async def test_anthropic_omits_cache_counters_the_api_did_not_send(fake_anthropic):
    """Reporting a zero the provider never sent would read as "nothing was
    cached" when the truth is "this model does not tell us"."""
    provider = AnthropicProvider(api_key="sk-ant-secret")

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert "cache_read_tokens" not in resp.usage
    assert "cache_write_tokens" not in resp.usage


@pytest.mark.asyncio
async def test_openai_surfaces_its_automatic_cache_counter(fake_openai):
    provider = OpenAIProvider(api_key="sk-secret")
    usage = _OAIUsage(prompt_tokens=1200, completion_tokens=8)
    usage.prompt_tokens_details = SimpleNamespace(cached_tokens=1024)
    provider._client.response = _OAIResponse(
        choices=[_OAIChoice(_OAIMessage(content="hi"))], usage=usage
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    # prompt_tokens already includes the cached share: taken as-is.
    assert resp.usage == {
        "input_tokens": 1200,
        "output_tokens": 8,
        "cache_read_tokens": 1024,
        "cache_write_tokens": 0,
    }


@pytest.mark.asyncio
async def test_deepseek_cache_hit_counter_is_read_as_cache_reads(fake_openai):
    """DeepSeek reports cache hits in its own field, not prompt_tokens_details."""
    provider = OpenAIProvider(api_key="sk-secret")
    usage = _OAIUsage(prompt_tokens=5000, completion_tokens=20)
    usage.prompt_cache_hit_tokens = 4608
    provider._client.response = _OAIResponse(
        choices=[_OAIChoice(_OAIMessage(content="hi"))], usage=usage
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.usage["input_tokens"] == 5000
    assert resp.usage["cache_read_tokens"] == 4608


@pytest.mark.asyncio
async def test_gemini_surfaces_its_implicit_cache_counter(transport):
    provider = GeminiProvider(api_key="g-secret")
    transport.responder = lambda request: httpx.Response(
        200,
        json={
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
            "usageMetadata": {
                "promptTokenCount": 900,
                "candidatesTokenCount": 12,
                "cachedContentTokenCount": 640,
            },
        },
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    # promptTokenCount already includes the cached share.
    assert resp.usage == {
        "input_tokens": 900,
        "output_tokens": 12,
        "cache_read_tokens": 640,
        "cache_write_tokens": 0,
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_thinking_tokens_count_as_output(transport):
    """2.5+ models bill their thinking as output, but report it apart from
    candidatesTokenCount."""
    provider = GeminiProvider(api_key="g-secret")
    transport.responder = lambda request: httpx.Response(
        200,
        json={
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
            "usageMetadata": {
                "promptTokenCount": 300,
                "candidatesTokenCount": 40,
                "thoughtsTokenCount": 1100,
            },
        },
    )

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.usage["output_tokens"] == 1140
    assert "cache_read_tokens" not in resp.usage
    await provider.aclose()
