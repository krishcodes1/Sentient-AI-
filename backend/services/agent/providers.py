"""LLM provider abstraction layer.

Supports Anthropic Claude, OpenAI, Google Gemini, xAI Grok, Deepseek,
Mistral, Groq, and Ollama (local) backends. Every provider normalises
its output into a common ``LLMResponse``.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


# ---------------------------------------------------------------------------
# Common response types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation requested by the LLM."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMResponse:
    """Normalised response from any LLM provider."""
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class LLMProvider(abc.ABC):
    """Interface every LLM backend must implement."""

    @abc.abstractmethod
    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse: ...

    @abc.abstractmethod
    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ): ...


# ---------------------------------------------------------------------------
# Anthropic Claude
# ---------------------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """Anthropic Claude via the official ``anthropic`` async SDK."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        import anthropic
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
            }
            for t in tools
        ]

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
        system: Optional[str] = None
        rest: list[dict[str, Any]] = []
        for m in messages:
            if m.get("role") == "system":
                system = m["content"]
            else:
                rest.append({"role": m["role"], "content": m["content"]})
        return system, rest

    @staticmethod
    def _parse_tool_calls(content_blocks: list[Any]) -> list[ToolCall]:
        calls: list[ToolCall] = []
        for block in content_blocks:
            if getattr(block, "type", None) == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, arguments=block.input or {}))
        return calls

    async def complete(self, messages, tools=None) -> LLMResponse:
        system, msgs = self._convert_messages(messages)
        kwargs: dict[str, Any] = {"model": self._model, "max_tokens": 4096, "messages": msgs}
        if system:
            kwargs["system"] = system
        anthropic_tools = self._convert_tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        resp = await self._client.messages.create(**kwargs)
        text_parts = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
        return LLMResponse(
            content="".join(text_parts),
            tool_calls=self._parse_tool_calls(resp.content),
            model=resp.model,
            usage={"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens},
        )

    async def stream(self, messages, tools=None):
        system, msgs = self._convert_messages(messages)
        kwargs: dict[str, Any] = {"model": self._model, "max_tokens": 4096, "messages": msgs}
        if system:
            kwargs["system"] = system
        anthropic_tools = self._convert_tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools
        async with self._client.messages.stream(**kwargs) as stream:
            async for text in stream.text_stream:
                yield text


# ---------------------------------------------------------------------------
# OpenAI-Compatible Provider (base for OpenAI, Grok, Deepseek, Groq, Mistral)
# ---------------------------------------------------------------------------


class OpenAICompatibleProvider(LLMProvider):
    """Base class for any provider using the OpenAI-compatible chat API.

    Works with: OpenAI, xAI Grok, Deepseek, Groq, Mistral, and any
    other provider that exposes an OpenAI-compatible endpoint.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        provider_name: str = "openai",
    ):
        import openai
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = openai.AsyncOpenAI(**kwargs)
        self._model = model
        self._provider_name = provider_name

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
        ]

    @staticmethod
    def _parse_tool_calls(choices: Any) -> list[ToolCall]:
        calls: list[ToolCall] = []
        msg = choices[0].message
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
        return calls

    async def complete(self, messages, tools=None) -> LLMResponse:
        kwargs: dict[str, Any] = {"model": self._model, "messages": messages}
        oai_tools = self._convert_tools(tools)
        if oai_tools:
            kwargs["tools"] = oai_tools

        resp = await self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        return LLMResponse(
            content=choice.message.content or "",
            tool_calls=self._parse_tool_calls(resp.choices),
            model=resp.model or self._model,
            usage={
                "input_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
            },
        )

    async def stream(self, messages, tools=None):
        kwargs: dict[str, Any] = {"model": self._model, "messages": messages, "stream": True}
        oai_tools = self._convert_tools(tools)
        if oai_tools:
            kwargs["tools"] = oai_tools
        stream = await self._client.chat.completions.create(**kwargs)
        async for chunk in stream:
            delta = chunk.choices[0].delta if chunk.choices else None
            if delta and delta.content:
                yield delta.content


class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI GPT models."""
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        super().__init__(api_key=api_key, model=model, provider_name="openai")


class GrokProvider(OpenAICompatibleProvider):
    """xAI Grok models via OpenAI-compatible API."""
    def __init__(self, api_key: str, model: str = "grok-3"):
        super().__init__(
            api_key=api_key,
            model=model,
            base_url="https://api.x.ai/v1",
            provider_name="grok",
        )


class DeepseekProvider(OpenAICompatibleProvider):
    """Deepseek models via OpenAI-compatible API."""
    def __init__(self, api_key: str, model: str = "deepseek-chat"):
        super().__init__(
            api_key=api_key,
            model=model,
            base_url="https://api.deepseek.com",
            provider_name="deepseek",
        )


class GroqProvider(OpenAICompatibleProvider):
    """Groq ultra-fast inference via OpenAI-compatible API."""
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        super().__init__(
            api_key=api_key,
            model=model,
            base_url="https://api.groq.com/openai/v1",
            provider_name="groq",
        )


class MistralProvider(OpenAICompatibleProvider):
    """Mistral AI models via OpenAI-compatible API."""
    def __init__(self, api_key: str, model: str = "mistral-large-latest"):
        super().__init__(
            api_key=api_key,
            model=model,
            base_url="https://api.mistral.ai/v1",
            provider_name="mistral",
        )


# ---------------------------------------------------------------------------
# Google Gemini
# ---------------------------------------------------------------------------


class GeminiProvider(LLMProvider):
    """Google Gemini via the REST API."""

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash"):
        self._api_key = api_key
        self._model = model
        self._base_url = "https://generativelanguage.googleapis.com/v1beta"
        self._client = httpx.AsyncClient(timeout=120.0)

    def _build_url(self, action: str = "generateContent") -> str:
        return f"{self._base_url}/models/{self._model}:{action}?key={self._api_key}"

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
        system_instruction = None
        contents: list[dict[str, Any]] = []
        for m in messages:
            role = m.get("role", "user")
            if role == "system":
                system_instruction = m["content"]
                continue
            gemini_role = "model" if role == "assistant" else "user"
            contents.append({"role": gemini_role, "parts": [{"text": m["content"]}]})
        return system_instruction, contents

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        function_declarations = []
        for t in tools:
            function_declarations.append({
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("parameters", {"type": "object", "properties": {}}),
            })
        return [{"functionDeclarations": function_declarations}]

    async def complete(self, messages, tools=None) -> LLMResponse:
        system_instruction, contents = self._convert_messages(messages)
        payload: dict[str, Any] = {"contents": contents}
        if system_instruction:
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}
        gemini_tools = self._convert_tools(tools)
        if gemini_tools:
            payload["tools"] = gemini_tools

        resp = await self._client.post(self._build_url(), json=payload)
        resp.raise_for_status()
        data = resp.json()

        # Parse response
        candidates = data.get("candidates", [])
        if not candidates:
            return LLMResponse(content="", model=self._model)

        parts = candidates[0].get("content", {}).get("parts", [])
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        for i, part in enumerate(parts):
            if "text" in part:
                text_parts.append(part["text"])
            elif "functionCall" in part:
                fc = part["functionCall"]
                tool_calls.append(ToolCall(
                    id=f"gemini_{i}",
                    name=fc.get("name", ""),
                    arguments=fc.get("args", {}),
                ))

        usage_meta = data.get("usageMetadata", {})
        return LLMResponse(
            content="".join(text_parts),
            tool_calls=tool_calls,
            model=self._model,
            usage={
                "input_tokens": usage_meta.get("promptTokenCount", 0),
                "output_tokens": usage_meta.get("candidatesTokenCount", 0),
            },
        )

    async def stream(self, messages, tools=None):
        system_instruction, contents = self._convert_messages(messages)
        payload: dict[str, Any] = {"contents": contents}
        if system_instruction:
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        async with self._client.stream(
            "POST", self._build_url("streamGenerateContent"), json=payload
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line.lstrip("[,"))
                except json.JSONDecodeError:
                    continue
                parts = chunk.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                for part in parts:
                    if "text" in part:
                        yield part["text"]


# ---------------------------------------------------------------------------
# Ollama (local)
# ---------------------------------------------------------------------------


class OllamaProvider(LLMProvider):
    """Ollama local models via the REST API."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=120.0)

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
        ]

    async def complete(self, messages, tools=None) -> LLMResponse:
        payload: dict[str, Any] = {"model": self._model, "messages": messages, "stream": False}
        ollama_tools = self._convert_tools(tools)
        if ollama_tools:
            payload["tools"] = ollama_tools

        resp = await self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()

        tool_calls: list[ToolCall] = []
        msg = data.get("message", {})
        for idx, tc in enumerate(msg.get("tool_calls", [])):
            fn = tc.get("function", {})
            tool_calls.append(ToolCall(id=f"ollama_{idx}", name=fn.get("name", ""), arguments=fn.get("arguments", {})))

        return LLMResponse(
            content=msg.get("content", ""),
            tool_calls=tool_calls,
            model=data.get("model", self._model),
            usage={
                "input_tokens": data.get("prompt_eval_count", 0),
                "output_tokens": data.get("eval_count", 0),
            },
        )

    async def stream(self, messages, tools=None):
        payload: dict[str, Any] = {"model": self._model, "messages": messages, "stream": True}
        ollama_tools = self._convert_tools(tools)
        if ollama_tools:
            payload["tools"] = ollama_tools

        async with self._client.stream("POST", "/api/chat", json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue
                content = chunk.get("message", {}).get("content", "")
                if content:
                    yield content


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

PROVIDER_REGISTRY: dict[str, type[LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "grok": GrokProvider,
    "deepseek": DeepseekProvider,
    "groq": GroqProvider,
    "mistral": MistralProvider,
    "ollama": OllamaProvider,
}


def create_provider(
    provider_name: str,
    model: str,
    *,
    api_key: Optional[str] = None,
    base_url: str = "http://localhost:11434",
) -> LLMProvider:
    """Instantiate the correct provider based on *provider_name*."""
    if provider_name not in PROVIDER_REGISTRY:
        supported = ", ".join(sorted(PROVIDER_REGISTRY.keys()))
        raise ValueError(f"Unknown LLM provider: {provider_name!r}. Supported: {supported}")

    if provider_name == "ollama":
        return OllamaProvider(base_url=base_url, model=model)

    if not api_key:
        raise ValueError(f"{provider_name.upper()}_API_KEY is required for the {provider_name} provider")

    provider_cls = PROVIDER_REGISTRY[provider_name]

    if provider_name == "gemini":
        return GeminiProvider(api_key=api_key, model=model)

    # All OpenAI-compatible providers
    return provider_cls(api_key=api_key, model=model)  # type: ignore[call-arg]
