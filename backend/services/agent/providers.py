"""LLM provider abstraction layer.

Supports Anthropic Claude, OpenAI, and Ollama (local) backends.
Every provider normalises its output into a common ``LLMResponse``.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Common response types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A single tool invocation requested by the LLM."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
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
    ) -> LLMResponse:
        """Send *messages* (with optional *tools*) and return a normalised response."""

    @abc.abstractmethod
    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ):
        """Yield incremental content chunks.  Sub-classes yield ``str`` pieces."""


# ---------------------------------------------------------------------------
# Anthropic Claude
# ---------------------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """Anthropic Claude via the official ``anthropic`` async SDK."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        import anthropic

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        """Convert generic tool dicts into Anthropic's tool schema."""
        if not tools:
            return None
        converted: list[dict[str, Any]] = []
        for t in tools:
            converted.append(
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
                }
            )
        return converted

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
        """Split a system message out (Anthropic uses a top-level param) and return the rest."""
        system: str | None = None
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
                calls.append(
                    ToolCall(id=block.id, name=block.name, arguments=block.input or {})
                )
        return calls

    # -- public API --------------------------------------------------------

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        system, msgs = self._convert_messages(messages)
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": msgs,
        }
        if system:
            kwargs["system"] = system
        anthropic_tools = self._convert_tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        resp = await self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        for block in resp.content:
            if getattr(block, "type", None) == "text":
                text_parts.append(block.text)

        return LLMResponse(
            content="".join(text_parts),
            tool_calls=self._parse_tool_calls(resp.content),
            model=resp.model,
            usage={
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            },
        )

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ):
        system, msgs = self._convert_messages(messages)
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 4096,
            "messages": msgs,
        }
        if system:
            kwargs["system"] = system
        anthropic_tools = self._convert_tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        async with self._client.messages.stream(**kwargs) as stream:
            async for text in stream.text_stream:
                yield text


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------


class OpenAIProvider(LLMProvider):
    """OpenAI GPT models via the official ``openai`` async SDK."""

    def __init__(self, api_key: str, model: str = "gpt-4o"):
        import openai

        self._client = openai.AsyncOpenAI(api_key=api_key)
        self._model = model

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        converted: list[dict[str, Any]] = []
        for t in tools:
            converted.append(
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                    },
                }
            )
        return converted

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

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
        }
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

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ):
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": True,
        }
        oai_tools = self._convert_tools(tools)
        if oai_tools:
            kwargs["tools"] = oai_tools

        stream = await self._client.chat.completions.create(**kwargs)
        async for chunk in stream:
            delta = chunk.choices[0].delta if chunk.choices else None
            if delta and delta.content:
                yield delta.content


# ---------------------------------------------------------------------------
# Ollama (local)
# ---------------------------------------------------------------------------


class OllamaProvider(LLMProvider):
    """Ollama local models via the REST API."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3"):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=120.0)

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        converted: list[dict[str, Any]] = []
        for t in tools:
            converted.append(
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                    },
                }
            )
        return converted

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": False,
        }
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
            tool_calls.append(
                ToolCall(
                    id=f"ollama_{idx}",
                    name=fn.get("name", ""),
                    arguments=fn.get("arguments", {}),
                )
            )

        return LLMResponse(
            content=msg.get("content", ""),
            tool_calls=tool_calls,
            model=data.get("model", self._model),
            usage={
                "input_tokens": data.get("prompt_eval_count", 0),
                "output_tokens": data.get("eval_count", 0),
            },
        )

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ):
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": True,
        }
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


def create_provider(
    provider_name: str,
    model: str,
    *,
    api_key: str | None = None,
    base_url: str = "http://localhost:11434",
) -> LLMProvider:
    """Instantiate the correct provider based on *provider_name*."""
    match provider_name:
        case "anthropic":
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY is required for the Anthropic provider")
            return AnthropicProvider(api_key=api_key, model=model)
        case "openai":
            if not api_key:
                raise ValueError("OPENAI_API_KEY is required for the OpenAI provider")
            return OpenAIProvider(api_key=api_key, model=model)
        case "ollama":
            return OllamaProvider(base_url=base_url, model=model)
        case _:
            raise ValueError(f"Unknown LLM provider: {provider_name!r}")
