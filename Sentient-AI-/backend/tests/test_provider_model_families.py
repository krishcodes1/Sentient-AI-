"""Tests that each vendor's current model families get a request body its API
accepts: the exact JSON sent to Anthropic, OpenAI and Gemini per model family
(plus the per-request timeout and the usage counts read back), and that the
setup wizard only suggests current, priced, tool-capable models.

Why it exists: Vendors change what a request may contain from one model
generation to the next (Claude Sonnet 5 thinks by default and rejects sampling
parameters, GPT-6 Luna takes tools on Chat Completions only with reasoning
off, Gemini 3 takes a thinking level instead of a budget). A test that only
checks the arguments handed to an SDK misses what the SDK puts on the wire,
so these run the real Anthropic and OpenAI SDKs, and the Gemini provider's
own httpx client, over an ``httpx.MockTransport``: every assertion is about
the bytes a vendor would receive, and nothing here opens a connection or
needs a key.

Sources for each rule are cited next to the code in
services/agent/providers.py and api/routes/setup.py.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from api.routes.setup import SUGGESTED_MODELS
from services.agent.providers import (
    AnthropicProvider,
    DeepseekProvider,
    GeminiProvider,
    GrokProvider,
    GroqProvider,
    MistralProvider,
    OpenAIProvider,
    ProviderError,
    ToolCall,
)
from services.usage.pricing import price_for

# Captured before any test patches httpx, so the wire clients below are
# always the real class.
_RealAsyncClient = httpx.AsyncClient

TOOLS = [
    {
        "name": "search",
        "description": "Search the web",
        "parameters": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        },
    },
    {"name": "ping"},
]

PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

# A tool round as the runtime sends it: the policy system prompt, the
# user's ask, the model's own words, then the tool results as a user turn
# carrying a screenshot (never a role="tool" message).
CONVERSATION: list[dict[str, Any]] = [
    {"role": "system", "content": "POLICY"},
    {"role": "user", "content": "find cats"},
    {"role": "assistant", "content": "Looking."},
    {
        "role": "user",
        "content": [
            {"type": "text", "text": "<tool_result>page</tool_result>"},
            {"type": "image", "media_type": "image/png", "data": PNG_B64},
        ],
    },
]

# Fields no request may carry for the thinking/reasoning model families:
# each is a 400 on at least one current model.
FORBIDDEN_SAMPLING = {"temperature", "top_p", "top_k", "max_tokens", "max_completion_tokens"}


class Wire:
    """Records every request that reaches the transport and scripts replies."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responder: Callable[[httpx.Request], httpx.Response] = lambda r: httpx.Response(
            200, json={}
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responder(request)

    @property
    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests]

    def client(self, **kwargs: Any) -> httpx.AsyncClient:
        return _RealAsyncClient(transport=httpx.MockTransport(self.handle), **kwargs)


# ---------------------------------------------------------------------------
# Anthropic (real SDK, mocked socket)
# ---------------------------------------------------------------------------


def _anthropic_message(
    content: list[dict[str, Any]], *, stop_reason: str = "end_turn", model: str = "claude-sonnet-5"
) -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


@pytest.fixture
def anthropic_wire(monkeypatch) -> Wire:
    import anthropic

    real = anthropic.AsyncAnthropic
    wire = Wire()
    wire.responder = lambda r: httpx.Response(
        200, json=_anthropic_message([{"type": "text", "text": "ok"}])
    )

    def _factory(**kwargs: Any) -> Any:
        return real(http_client=wire.client(), **kwargs)

    monkeypatch.setattr(anthropic, "AsyncAnthropic", _factory)
    return wire


def _anthropic_expected_messages() -> list[dict[str, Any]]:
    return [
        {"role": "user", "content": "find cats"},
        {"role": "assistant", "content": "Looking."},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "<tool_result>page</tool_result>"},
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": PNG_B64},
                },
            ],
        },
    ]


_ANTHROPIC_TOOLS = [
    {
        "name": "search",
        "description": "Search the web",
        "input_schema": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        },
    },
    {
        "name": "ping",
        "description": "",
        "input_schema": {"type": "object", "properties": {}},
        "cache_control": {"type": "ephemeral"},
    },
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model",
    ["claude-sonnet-5", "claude-opus-5-5", "claude-opus-5", "claude-fable-5-1"],
)
async def test_anthropic_thinking_models_get_room_to_think_and_an_explicit_effort(
    anthropic_wire, model
):
    provider = AnthropicProvider(api_key="sk-ant-test", model=model)

    resp = await provider.complete(CONVERSATION, tools=TOOLS)

    assert resp.content == "ok"
    assert anthropic_wire.requests[0].url.path == "/v1/messages"
    assert anthropic_wire.bodies[0] == {
        "model": model,
        "max_tokens": 16000,
        "messages": _anthropic_expected_messages(),
        "system": [{"type": "text", "text": "POLICY", "cache_control": {"type": "ephemeral"}}],
        "tools": _ANTHROPIC_TOOLS,
        "output_config": {"effort": "medium"},
    }
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model",
    ["claude-haiku-4-5-20251001", "claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-8"],
)
async def test_anthropic_models_that_think_only_when_asked_keep_the_plain_request(
    anthropic_wire, model
):
    # Haiku 4.5 does not support effort, and the 4.x models do not think
    # unless asked, so their request is exactly what it has always been.
    provider = AnthropicProvider(api_key="sk-ant-test", model=model)

    await provider.complete(CONVERSATION, tools=TOOLS)

    assert anthropic_wire.bodies[0] == {
        "model": model,
        "max_tokens": 4096,
        "messages": _anthropic_expected_messages(),
        "system": [{"type": "text", "text": "POLICY", "cache_control": {"type": "ephemeral"}}],
        "tools": _ANTHROPIC_TOOLS,
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_anthropic_request_never_carries_parameters_newer_models_reject(anthropic_wire):
    provider = AnthropicProvider(api_key="sk-ant-test", model="claude-opus-5-5")

    await provider.complete(CONVERSATION, tools=TOOLS)

    body = anthropic_wire.bodies[0]
    # Sampling knobs are a 400 on Opus 4.7+ and Sonnet 5, forced tool use
    # on Opus 5.5, and thinking cannot be disabled there.
    for field in ("temperature", "top_p", "top_k", "tool_choice", "thinking"):
        assert field not in body, field
    await provider.aclose()


@pytest.mark.asyncio
async def test_anthropic_reply_is_the_text_blocks_only(anthropic_wire):
    anthropic_wire.responder = lambda r: httpx.Response(
        200,
        json=_anthropic_message(
            [
                # display "omitted" (the default on the thinking models):
                # an empty thinking field plus the signature.
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": "Found them."},
                {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {"q": "cats"}},
            ],
            stop_reason="tool_use",
        ),
    )
    provider = AnthropicProvider(api_key="sk-ant-test", model="claude-sonnet-5")

    resp = await provider.complete([{"role": "user", "content": "go"}], tools=TOOLS)

    assert resp.content == "Found them."
    assert resp.tool_calls == [ToolCall(id="toolu_1", name="search", arguments={"q": "cats"})]
    await provider.aclose()


@pytest.mark.asyncio
async def test_anthropic_output_limit_before_any_text_is_an_error_not_a_blank_reply(
    anthropic_wire,
):
    anthropic_wire.responder = lambda r: httpx.Response(
        200,
        json=_anthropic_message(
            [{"type": "thinking", "thinking": "", "signature": "sig"}], stop_reason="max_tokens"
        ),
    )
    provider = AnthropicProvider(api_key="sk-ant-test", model="claude-sonnet-5")

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete([{"role": "user", "content": "go"}])

    assert "max_tokens" in str(excinfo.value)
    await provider.aclose()


@pytest.mark.asyncio
async def test_anthropic_tool_call_cut_off_by_the_output_limit_is_never_run(anthropic_wire):
    anthropic_wire.responder = lambda r: httpx.Response(
        200,
        json=_anthropic_message(
            [
                {"type": "text", "text": "Clicking."},
                {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {}},
            ],
            stop_reason="max_tokens",
        ),
    )
    provider = AnthropicProvider(api_key="sk-ant-test", model="claude-sonnet-5")

    with pytest.raises(ProviderError):
        await provider.complete([{"role": "user", "content": "go"}], tools=TOOLS)
    await provider.aclose()


@pytest.mark.asyncio
async def test_anthropic_text_cut_off_by_the_output_limit_is_still_returned(anthropic_wire):
    anthropic_wire.responder = lambda r: httpx.Response(
        200,
        json=_anthropic_message(
            [{"type": "text", "text": "A long answer"}], stop_reason="max_tokens"
        ),
    )
    provider = AnthropicProvider(api_key="sk-ant-test", model="claude-haiku-4-5-20251001")

    resp = await provider.complete([{"role": "user", "content": "go"}])

    assert resp.content == "A long answer"
    await provider.aclose()


_ANTHROPIC_SSE = "".join(
    f"event: {event}\ndata: {json.dumps(data)}\n\n"
    for event, data in [
        (
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-5",
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                },
            },
        ),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Hel"},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "lo"},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 5},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]
)


@pytest.mark.asyncio
async def test_anthropic_stream_sends_the_same_model_aware_request(anthropic_wire):
    anthropic_wire.responder = lambda r: httpx.Response(
        200, text=_ANTHROPIC_SSE, headers={"content-type": "text/event-stream"}
    )
    provider = AnthropicProvider(api_key="sk-ant-test", model="claude-sonnet-5")

    chunks = [c async for c in provider.stream([{"role": "user", "content": "hi"}], tools=TOOLS)]

    assert "".join(chunks) == "Hello"
    assert anthropic_wire.bodies[0] == {
        "model": "claude-sonnet-5",
        "max_tokens": 16000,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": _ANTHROPIC_TOOLS,
        "output_config": {"effort": "medium"},
        "stream": True,
    }
    # A stream receives events as it goes, so the shared read budget stays.
    assert anthropic_wire.requests[0].extensions["timeout"]["read"] == 120.0
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model", "read_timeout"),
    [
        # Thinking models: nothing arrives until thinking plus reply is
        # written, so the non-streamed call gets the SDK's own allowance for
        # a 16000-token reply rather than the 120s hang budget.
        ("claude-sonnet-5", 450.0),
        ("claude-opus-5-5", 450.0),
        # 4096-token replies fit the shared budget, as they always have.
        ("claude-haiku-4-5-20251001", 120.0),
    ],
)
async def test_anthropic_non_streamed_timeout_fits_the_reply_budget(
    anthropic_wire, model, read_timeout
):
    provider = AnthropicProvider(api_key="sk-ant-test", model=model)

    await provider.complete(CONVERSATION, tools=TOOLS)

    timeout = anthropic_wire.requests[0].extensions["timeout"]
    assert timeout["read"] == read_timeout
    # The per-request timeout is not a body field.
    assert "timeout" not in anthropic_wire.bodies[0]
    await provider.aclose()


# ---------------------------------------------------------------------------
# OpenAI and the vendors sharing its chat-completions schema
# ---------------------------------------------------------------------------


def _chat_completion(model: str, content: str = "ok") -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
    }


@pytest.fixture
def openai_wire(monkeypatch) -> Wire:
    import openai

    real = openai.AsyncOpenAI
    wire = Wire()

    def _reply(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_completion(json.loads(request.content)["model"]))

    wire.responder = _reply

    def _factory(**kwargs: Any) -> Any:
        return real(http_client=wire.client(), **kwargs)

    monkeypatch.setattr(openai, "AsyncOpenAI", _factory)
    return wire


_OPENAI_MESSAGES = [
    {"role": "system", "content": "POLICY"},
    {"role": "user", "content": "find cats"},
    {"role": "assistant", "content": "Looking."},
    {
        "role": "user",
        "content": [
            {"type": "text", "text": "<tool_result>page</tool_result>"},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}},
        ],
    },
]

_OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search the web",
            "parameters": {
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"],
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


@pytest.mark.asyncio
@pytest.mark.parametrize("model", ["gpt-6-luna", "gpt-6-sol", "gpt-6-luna-2026-05-18"])
async def test_gpt6_sol_and_luna_turn_reasoning_off_when_tools_are_offered(openai_wire, model):
    provider = OpenAIProvider(api_key="sk-test", model=model)

    resp = await provider.complete(CONVERSATION, tools=TOOLS)

    assert resp.content == "ok"
    assert openai_wire.requests[0].url.path == "/v1/chat/completions"
    assert openai_wire.bodies[0] == {
        "model": model,
        "messages": _OPENAI_MESSAGES,
        "tools": _OPENAI_TOOLS,
        "reasoning_effort": "none",
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_gpt6_luna_without_tools_keeps_its_default_reasoning(openai_wire):
    # The setup wizard's test call: no tools, so nothing forces reasoning
    # off and the model runs at its own default.
    provider = OpenAIProvider(api_key="sk-test", model="gpt-6-luna")

    await provider.complete([{"role": "user", "content": "Reply with the single word OK."}])

    assert openai_wire.bodies[0] == {
        "model": "gpt-6-luna",
        "messages": [{"role": "user", "content": "Reply with the single word OK."}],
    }
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model", ["gpt-5.4-nano", "gpt-5.6-luna", "gpt-5-mini", "gpt-4o-mini", "gpt-4o"]
)
async def test_earlier_gpt_models_take_tools_with_the_plain_request(openai_wire, model):
    provider = OpenAIProvider(api_key="sk-test", model=model)

    await provider.complete(CONVERSATION, tools=TOOLS)

    assert openai_wire.bodies[0] == {
        "model": model,
        "messages": _OPENAI_MESSAGES,
        "tools": _OPENAI_TOOLS,
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_gpt6_astra_is_refused_before_sending_a_tool_request(openai_wire):
    provider = OpenAIProvider(api_key="sk-test", model="gpt-6-astra")

    with pytest.raises(ProviderError) as excinfo:
        await provider.complete(CONVERSATION, tools=TOOLS)

    assert "gpt-6-luna" in str(excinfo.value)
    assert openai_wire.requests == []
    # A plain chat still works: only tool use needs the other API.
    await provider.complete([{"role": "user", "content": "hi"}])
    assert openai_wire.bodies[0] == {
        "model": "gpt-6-astra",
        "messages": [{"role": "user", "content": "hi"}],
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_openai_requests_never_carry_parameters_reasoning_models_reject(openai_wire):
    for model in ("gpt-6-luna", "gpt-5.4-nano"):
        provider = OpenAIProvider(api_key="sk-test", model=model)
        await provider.complete(CONVERSATION, tools=TOOLS)
        await provider.aclose()

    for body in openai_wire.bodies:
        assert not FORBIDDEN_SAMPLING & set(body), body
        # Images ride in a user message, never in a role="tool" message,
        # which Chat Completions does not accept images in.
        assert all(m["role"] != "tool" for m in body["messages"])


def _sse(chunks: list[dict[str, Any]]) -> str:
    return "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"


@pytest.mark.asyncio
async def test_openai_stream_sends_the_same_model_aware_request(openai_wire):
    chunk = {
        "id": "c1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "gpt-6-luna",
        "choices": [{"index": 0, "delta": {"content": "Hi"}, "finish_reason": None}],
    }
    openai_wire.responder = lambda r: httpx.Response(
        200, text=_sse([chunk]), headers={"content-type": "text/event-stream"}
    )
    provider = OpenAIProvider(api_key="sk-test", model="gpt-6-luna")

    chunks = [c async for c in provider.stream([{"role": "user", "content": "hi"}], tools=TOOLS)]

    assert chunks == ["Hi"]
    assert openai_wire.bodies[0] == {
        "model": "gpt-6-luna",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
        "tools": _OPENAI_TOOLS,
        "reasoning_effort": "none",
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_openai_cache_writes_are_counted_when_reported(openai_wire):
    # GPT-5.6 and later bill cache writes at 1.25x input and report them in
    # usage.prompt_tokens_details.cache_write_tokens; read through the real
    # SDK, which may predate the field.
    reply = _chat_completion("gpt-6-luna")
    reply["usage"] = {
        "prompt_tokens": 3000,
        "completion_tokens": 40,
        "total_tokens": 3040,
        "prompt_tokens_details": {"cached_tokens": 1024, "cache_write_tokens": 1536},
    }
    openai_wire.responder = lambda r: httpx.Response(200, json=reply)
    provider = OpenAIProvider(api_key="sk-test", model="gpt-6-luna")

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.usage == {
        "input_tokens": 3000,
        "output_tokens": 40,
        "cache_read_tokens": 1024,
        "cache_write_tokens": 1536,
    }
    await provider.aclose()


@pytest.mark.asyncio
async def test_openai_without_a_cache_write_field_reports_zero_writes(openai_wire):
    # Earlier models (and the vendors sharing the schema) send no such field.
    reply = _chat_completion("gpt-5.4-nano")
    reply["usage"] = {
        "prompt_tokens": 3000,
        "completion_tokens": 40,
        "total_tokens": 3040,
        "prompt_tokens_details": {"cached_tokens": 2048},
    }
    openai_wire.responder = lambda r: httpx.Response(200, json=reply)
    provider = OpenAIProvider(api_key="sk-test", model="gpt-5.4-nano")

    resp = await provider.complete([{"role": "user", "content": "hi"}])

    assert resp.usage["cache_write_tokens"] == 0
    assert resp.usage["cache_read_tokens"] == 2048
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_cls", "model", "host"),
    [
        (GrokProvider, "grok-4.3", "api.x.ai"),
        (DeepseekProvider, "deepseek-flash", "api.deepseek.com"),
        (GroqProvider, "openai/gpt-oss-120b", "api.groq.com"),
        (MistralProvider, "mistral-large-latest", "api.mistral.ai"),
        # An OpenAI-looking id on another vendor must not pick up an
        # OpenAI-only field that vendor would reject.
        (GroqProvider, "gpt-6-luna", "api.groq.com"),
    ],
)
async def test_other_chat_completions_vendors_keep_the_plain_request(
    openai_wire, provider_cls, model, host
):
    provider = provider_cls(api_key="k-test", model=model)
    messages = [{"role": "system", "content": "POLICY"}, {"role": "user", "content": "hi"}]

    await provider.complete(messages, tools=TOOLS)

    assert openai_wire.requests[0].url.host == host
    assert openai_wire.bodies[0] == {"model": model, "messages": messages, "tools": _OPENAI_TOOLS}
    await provider.aclose()


# ---------------------------------------------------------------------------
# Gemini (the provider's own httpx client, mocked socket)
# ---------------------------------------------------------------------------


def _gemini_reply(parts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 2},
    }


async def _gemini(model: str, wire: Wire) -> GeminiProvider:
    provider = GeminiProvider(api_key="g-test", model=model)
    await provider._client.aclose()
    provider._client = wire.client(headers={"x-goog-api-key": "g-test"})
    return provider


@pytest.fixture
def gemini_wire() -> Wire:
    wire = Wire()
    wire.responder = lambda r: httpx.Response(200, json=_gemini_reply([{"text": "ok"}]))
    return wire


_GEMINI_CONTENTS = [
    {"role": "user", "parts": [{"text": "find cats"}]},
    {"role": "model", "parts": [{"text": "Looking."}]},
    {
        "role": "user",
        "parts": [
            {"text": "<tool_result>page</tool_result>"},
            {"inlineData": {"mimeType": "image/png", "data": PNG_B64}},
        ],
    },
]

_GEMINI_TOOLS = [
    {
        "functionDeclarations": [
            {
                "name": "search",
                "description": "Search the web",
                "parameters": {
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                    "required": ["q"],
                },
            },
            {"name": "ping", "description": "", "parameters": {"type": "object", "properties": {}}},
        ]
    }
]


@pytest.mark.asyncio
async def test_gemini3_ordinary_round_leaves_thinking_and_temperature_at_the_defaults(gemini_wire):
    provider = await _gemini("gemini-3.5-flash-lite", gemini_wire)

    resp = await provider.complete(CONVERSATION, tools=TOOLS)

    assert resp.content == "ok"
    assert (
        gemini_wire.requests[0].url.path == "/v1beta/models/gemini-3.5-flash-lite:generateContent"
    )
    assert gemini_wire.bodies[0] == {
        "contents": _GEMINI_CONTENTS,
        "systemInstruction": {"parts": [{"text": "POLICY"}]},
        "tools": _GEMINI_TOOLS,
    }
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model", "thinking_config"),
    [
        # Gemini 3+: the lowest thinkingLevel each model accepts.
        ("gemini-3.5-flash-lite", {"thinkingLevel": "minimal"}),
        ("gemini-3.1-flash-lite", {"thinkingLevel": "minimal"}),
        ("gemini-3.5-flash", {"thinkingLevel": "minimal"}),
        ("gemini-3.6-flash", {"thinkingLevel": "minimal"}),
        ("gemini-3-flash-preview", {"thinkingLevel": "minimal"}),
        ("gemini-3.8-flash", {"thinkingLevel": "low"}),  # "minimal" is a 400 here
        ("gemini-3.7-flash", {"thinkingLevel": "low"}),
        ("gemini-3.1-pro-preview", {"thinkingLevel": "low"}),
        # Gemini 2.5 Flash / Flash-Lite: a zero budget turns thinking off.
        ("gemini-2.5-flash", {"thinkingBudget": 0}),
        ("gemini-2.5-flash-lite", {"thinkingBudget": 0}),
    ],
)
async def test_gemini_browser_round_asks_each_family_for_its_least_thinking(
    gemini_wire, model, thinking_config
):
    provider = await _gemini(model, gemini_wire)
    assert provider.supports_thinking_budget is True

    await provider.complete([{"role": "user", "content": "hi"}], tools=TOOLS, thinking_budget=0)

    body = gemini_wire.bodies[0]
    # Only one of thinkingLevel / thinkingBudget: both together are a 400.
    assert body["generationConfig"] == {"thinkingConfig": thinking_config}
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("model", ["gemini-2.5-pro", "gemini-2.0-flash", "gemini-flash-latest"])
async def test_gemini_models_without_a_safe_setting_keep_the_api_default(gemini_wire, model):
    # 2.5 Pro rejects a zero budget, 2.0 has no thinkingConfig, and an alias
    # can move to any generation: none of them is sent a thinking field.
    provider = await _gemini(model, gemini_wire)
    assert provider.supports_thinking_budget is False

    await provider.complete([{"role": "user", "content": "hi"}], thinking_budget=0)

    assert "generationConfig" not in gemini_wire.bodies[0]
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("model", ["gemini-3.8-flash", "gemini-3.5-flash-lite"])
@pytest.mark.parametrize("budget", [2048, -1])
async def test_gemini3_budget_other_than_zero_keeps_the_model_default(gemini_wire, model, budget):
    # -1 is Google's "dynamic" (more thinking, not less) and a positive
    # budget has no level equivalent: neither may become the lowest level.
    provider = await _gemini(model, gemini_wire)

    await provider.complete([{"role": "user", "content": "hi"}], thinking_budget=budget)

    assert "generationConfig" not in gemini_wire.bodies[0]
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini25_flash_dynamic_budget_is_sent_as_is(gemini_wire):
    # On 2.5 Flash the budget itself is the API's field, so -1 (dynamic)
    # goes through unchanged.
    provider = await _gemini("gemini-2.5-flash", gemini_wire)

    await provider.complete([{"role": "user", "content": "hi"}], thinking_budget=-1)

    assert gemini_wire.bodies[0]["generationConfig"] == {"thinkingConfig": {"thinkingBudget": -1}}
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini_stream_sends_the_same_thinking_level(gemini_wire):
    # The alt=sse framing: one compact JSON chunk per "data:" line.
    gemini_wire.responder = lambda r: httpx.Response(
        200,
        text=f"data: {json.dumps(_gemini_reply([{'text': 'Hi'}]))}\n\n"
        f"data: {json.dumps(_gemini_reply([{'text': ' there'}]))}\n\n",
        headers={"content-type": "text/event-stream"},
    )
    provider = await _gemini("gemini-3.8-flash", gemini_wire)

    chunks = [
        c async for c in provider.stream([{"role": "user", "content": "hi"}], thinking_budget=0)
    ]

    assert chunks == ["Hi", " there"]
    assert (
        gemini_wire.requests[0].url.path == "/v1beta/models/gemini-3.8-flash:streamGenerateContent"
    )
    assert gemini_wire.requests[0].url.params["alt"] == "sse"
    assert gemini_wire.bodies[0]["generationConfig"] == {"thinkingConfig": {"thinkingLevel": "low"}}
    await provider.aclose()


@pytest.mark.asyncio
async def test_gemini3_reply_skips_thought_parts_and_reads_signed_calls(gemini_wire):
    # Gemini 3 attaches thoughtSignature to parts. The runtime never sends
    # functionCall parts back (results travel as a user text turn), so the
    # strict signature check on function-call history never applies.
    gemini_wire.responder = lambda r: httpx.Response(
        200,
        json=_gemini_reply(
            [
                {"text": "planning", "thought": True},
                {"text": "On it.", "thoughtSignature": "c2ln"},
                {
                    "functionCall": {"id": "fc_1", "name": "search", "args": {"q": "cats"}},
                    "thoughtSignature": "c2lnMg==",
                },
            ]
        ),
    )
    provider = await _gemini("gemini-3.8-flash", gemini_wire)

    resp = await provider.complete([{"role": "user", "content": "go"}], tools=TOOLS)

    assert resp.content == "On it."
    assert [(c.name, c.arguments) for c in resp.tool_calls] == [("search", {"q": "cats"})]
    await provider.aclose()


def test_gemini_default_model_is_one_a_new_key_can_reach():
    # Google limits the 2.5 models to accounts that already used them.
    assert GeminiProvider.__init__.__defaults__ == ("gemini-3.5-flash-lite",)


# ---------------------------------------------------------------------------
# Setup wizard suggestions
# ---------------------------------------------------------------------------


def test_setup_suggests_current_models_first():
    assert SUGGESTED_MODELS["gemini"][0] == "gemini-3.5-flash-lite"
    assert SUGGESTED_MODELS["anthropic"][0] == "claude-sonnet-5"
    assert SUGGESTED_MODELS["openai"][0] == "gpt-6-luna"
    # No longer reachable with a new Gemini key (2.5) or shut down (2.0).
    assert not [m for m in SUGGESTED_MODELS["gemini"] if m.startswith("gemini-2.")]
    assert "gpt-4o-mini" not in SUGGESTED_MODELS["openai"]


@pytest.mark.parametrize(
    ("provider", "model"),
    [(p, m) for p, models in SUGGESTED_MODELS.items() for m in models],
)
def test_every_suggested_model_has_a_list_price(provider, model):
    # Without a price the usage view shows "cost unknown" for the very
    # model the wizard recommended.
    assert price_for(provider, model) is not None, f"{provider}/{model} has no price"


@pytest.mark.parametrize("model", SUGGESTED_MODELS["openai"])
def test_every_suggested_openai_model_can_take_tools(openai_wire, model):
    provider = OpenAIProvider(api_key="sk-test", model=model)
    # Would raise for a model that cannot call tools over Chat Completions.
    provider._request_kwargs([{"role": "user", "content": "hi"}], TOOLS)
