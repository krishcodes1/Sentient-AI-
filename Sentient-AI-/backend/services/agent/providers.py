"""LLM provider abstraction layer.

Supports Anthropic Claude, OpenAI, Google Gemini, xAI Grok, Deepseek,
Mistral, Groq, and Ollama (local) backends. Every provider normalises
its output into a common ``LLMResponse``.

Message content is either a plain string or a list of provider-agnostic
content blocks (see ``normalize_content``), which is how image attachments
reach the model. Each provider translates the blocks into its own
multimodal wire format; a provider with no vision support refuses the turn
rather than dropping the image, because silently answering a "what is this
product?" question without the photo is worse than an error.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Common response types
# ---------------------------------------------------------------------------


class ProviderError(Exception):
    """A provider call failed. The message is safe to surface to users and
    logs: it never contains request URLs, API keys, or auth headers."""

    def __init__(self, provider: str, status_code: int | None, detail: str):
        self.provider = provider
        self.status_code = status_code
        self.detail = detail
        suffix = f" (HTTP {status_code})" if status_code else ""
        super().__init__(f"{provider} provider error{suffix}: {detail}")


ProviderNotConfiguredReason = Literal["not_set_up", "user_provider_unavailable"]


class ProviderNotConfigured(ProviderError):
    """No API key is available for the provider a turn resolved to.

    ``reason`` says whose problem it is, because the fix differs:

    * ``not_set_up`` — the install itself has no usable provider yet (or its
      key was removed). Routes answer 503 with ``setup_url``; once setup is
      complete (/setup then redirects away) with code
      ``provider_unavailable`` and ``settings_url`` instead.
    * ``user_provider_unavailable`` — the install works, but the provider this
      user pinned in Settings has no key here. Routes answer 409 with
      ``settings_url``; /setup cannot fix someone's personal choice.

    ``str()`` is the bare sentence, without ProviderError's "<name> provider
    error:" prefix and without any URL: the web app and Telegram show it
    verbatim, and the link travels separately so a chat channel never shows
    a bare relative path.
    """

    SETUP_MESSAGE = "No AI provider is configured yet. Add an API key to start chatting."

    _CODES: dict[str, str] = {
        "not_set_up": "provider_not_configured",
        "user_provider_unavailable": "user_provider_unavailable",
    }

    def __init__(
        self,
        provider: str,
        *,
        reason: ProviderNotConfiguredReason,
        detail: Optional[str] = None,
    ):
        if reason not in self._CODES:
            raise ValueError(f"unknown ProviderNotConfigured reason: {reason!r}")
        message = detail or self.SETUP_MESSAGE
        super().__init__(provider, None, message)
        self.reason: ProviderNotConfiguredReason = reason
        self.args = (message,)

    @property
    def code(self) -> str:
        """Machine-readable code carried on every surface (HTTP detail,
        stream error frame, channel outcome)."""
        return self._CODES[self.reason]


def _raise_provider_error(provider: str, exc: httpx.HTTPStatusError) -> None:
    """Convert an httpx error into a ProviderError without leaking the URL."""
    body = exc.response.text[:300] if exc.response is not None else ""
    raise ProviderError(provider, exc.response.status_code, body) from None


def _raise_transport_error(provider: str, exc: httpx.TransportError) -> None:
    """Convert an httpx transport failure (connect/read timeout, refused
    connection, DNS failure) into a ProviderError without leaking the URL.
    These escape from the request call itself, so the HTTPStatusError
    handlers never see them."""
    raise ProviderError(
        provider, None, f"could not reach the provider ({type(exc).__name__})"
    ) from None


# ---------------------------------------------------------------------------
# Provider-agnostic content blocks
# ---------------------------------------------------------------------------
#
# A message's ``content`` is either a ``str`` (the overwhelmingly common
# case, left untouched so text-only requests keep their exact wire shape) or
# a list of blocks:
#
#   {"type": "text",  "text": "..."}
#   {"type": "image", "media_type": "image/png", "data": "<base64>"}
#
# Image ``data`` is raw base64 with no ``data:`` prefix. It is never logged
# and never scanned as text — the bytes are opaque to every layer above the
# provider.

TEXT_BLOCK = "text"
IMAGE_BLOCK = "image"


def normalize_content(content: Any) -> list[dict[str, Any]]:
    """Return *content* as a block list, wrapping a bare string."""
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return [{"type": TEXT_BLOCK, "text": "" if content is None else str(content)}]


def content_text(content: Any) -> str:
    """Extract only the textual part of a message's content.

    Callers that reason about what the user *said* — prompt scanning, token
    estimation, summarisation — use this so image payloads never reach them
    as a giant base64 string.
    """
    if not isinstance(content, list):
        return "" if content is None else str(content)
    return "\n".join(
        str(b.get("text", ""))
        for b in content
        if isinstance(b, dict) and b.get("type") == TEXT_BLOCK
    )


def has_images(messages: list[dict[str, Any]]) -> bool:
    """True when any message carries an image block."""
    return any(
        isinstance(m.get("content"), list)
        and any(
            isinstance(b, dict) and b.get("type") == IMAGE_BLOCK
            for b in m["content"]
        )
        for m in messages
    )


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation requested by the LLM."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMResponse:
    """Normalised response from any LLM provider.

    ``usage`` carries the same keys whatever the vendor:

    - ``input_tokens``: the WHOLE prompt, cached share included. Vendors
      disagree on this (Anthropic's own ``input_tokens`` leaves cached
      tokens out; OpenAI's and Gemini's prompt counts include them), and a
      per-message counter that meant different things per provider could
      not be compared or summed.
    - ``output_tokens``: everything billed as output, including reasoning
      ("thinking") tokens a vendor reports separately.
    - ``cache_read_tokens``: the part of ``input_tokens`` served from the
      prompt cache. Present only when the vendor reported it: a zero it
      never sent would read as "nothing was cached" when the truth is
      "this vendor does not say".
    - ``cache_write_tokens``: the part of ``input_tokens`` written to the
      cache at a surcharge. Only Anthropic bills cache writes; everyone
      else reports a true 0.
    """
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class LLMProvider(abc.ABC):
    """Interface every LLM backend must implement."""

    # Whether this backend accepts image content blocks. Declared per
    # provider class rather than per model: the runtime has to answer
    # "can I send this photo?" before the request, and a wrong *yes* costs
    # a failed turn while a wrong *no* costs an actionable error message.
    supports_vision: bool = False

    # Name used in ProviderError; subclasses that serve several vendors
    # override it per instance.
    _provider_name: str = ""

    def _reject_images(self, messages: list[dict[str, Any]]) -> None:
        """Refuse a turn carrying images this backend cannot read.

        Dropping the image instead would leave the model answering a
        question about a picture it never saw, with nothing in the reply to
        say so.
        """
        if self.supports_vision or not has_images(messages):
            return
        name = self._provider_name or type(self).__name__
        raise ProviderError(
            name,
            None,
            (
                f"the '{name}' provider does not accept image attachments. "
                "Choose a vision-capable provider (Anthropic, OpenAI, or "
                "Gemini) in Settings, or send the message without images."
            ),
        )

    def _log_cache_usage(self, usage: dict[str, int]) -> None:
        """Record what the provider billed as cached vs fresh input.

        Prompt caching is invisible unless it is measured: a prefix that
        silently stops matching looks exactly like a prefix that never
        cached, and both just show up as a larger bill.
        """
        read = usage.get("cache_read_tokens")
        written = usage.get("cache_write_tokens") or 0
        if read is None and not written:
            return
        logger.info(
            "provider_prompt_cache",
            provider=self._provider_name or type(self).__name__,
            cache_read_tokens=read or 0,
            cache_write_tokens=written,
            input_tokens=usage.get("input_tokens", 0),
        )

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

    async def aclose(self) -> None:
        """Release owned HTTP resources. Called when the runtime evicts a
        cached provider instance; default is a no-op for providers that
        own nothing."""


# Outbound request budget for every provider. The SDK defaults are ~10
# minutes with retries — long enough that one hung provider pins server
# resources (a DB pool connection, an SSE stream) for the whole stretch.
_REQUEST_TIMEOUT_SECONDS = 120.0
_MAX_RETRIES = 2


# ---------------------------------------------------------------------------
# Anthropic Claude
# ---------------------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """Anthropic Claude via the official ``anthropic`` async SDK."""

    supports_vision = True
    _provider_name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        import anthropic
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            timeout=_REQUEST_TIMEOUT_SECONDS,
            max_retries=_MAX_RETRIES,
        )
        self._model = model

    async def aclose(self) -> None:
        await self._client.close()

    @staticmethod
    def _convert_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        converted = [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
            }
            for t in tools
        ]
        # Cache breakpoint on the LAST tool. Anthropic caches the request
        # prefix up to each marker, and tools sit ahead of the system
        # prompt in that prefix, so this one marker covers every tool
        # schema. It is what makes a stable tool array pay for itself:
        # cached input bills at ~10% of fresh input, and the schemas are
        # re-sent verbatim on every turn of a conversation.
        converted[-1]["cache_control"] = {"type": "ephemeral"}
        return converted

    @staticmethod
    def _convert_content(content: Any) -> Any:
        """Translate provider-agnostic blocks into Anthropic content.

        A string is passed through untouched so text-only turns keep the
        exact payload they have always sent.
        """
        if not isinstance(content, list):
            return content
        blocks: list[dict[str, Any]] = []
        for part in normalize_content(content):
            if part.get("type") == IMAGE_BLOCK:
                blocks.append(
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": part.get("media_type", ""),
                            "data": part.get("data", ""),
                        },
                    }
                )
            else:
                blocks.append({"type": "text", "text": str(part.get("text", ""))})
        return blocks

    @classmethod
    def _convert_messages(cls, messages: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
        # Concatenate ALL system messages rather than letting a later one
        # overwrite an earlier one. The first system message is the
        # security policy; silently dropping it because some other layer
        # appended a second system message would remove the entire
        # injection-defense contract. Order is preserved.
        system_parts: list[str] = []
        rest: list[dict[str, Any]] = []
        for m in messages:
            if m.get("role") == "system":
                # The policy slot is text-only: an image can never carry
                # instruction authority.
                system_parts.append(content_text(m.get("content", "")))
            else:
                rest.append(
                    {"role": m["role"], "content": cls._convert_content(m.get("content", ""))}
                )
        system = "\n\n".join(system_parts) if system_parts else None
        return system, rest

    @staticmethod
    def _system_blocks(system: str) -> list[dict[str, Any]]:
        """Wrap the system prompt in a cacheable text block.

        A second breakpoint here (the tools array carries the first) means
        a turn where the memory block changed but the tools did not still
        gets a cache hit on the tools prefix instead of paying full price
        for everything.
        """
        return [
            {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
        ]

    @staticmethod
    def _usage(raw: Any) -> dict[str, int]:
        """Normalise SDK usage to the cross-provider shape (see LLMResponse).

        Anthropic's ``input_tokens`` counts only the prompt AFTER the last
        cache breakpoint; the cached prefix is reported separately as reads
        and creations. With breakpoints on the system prompt and the tools,
        that prefix is most of every request, so the three are added back
        together here — reading ``input_tokens`` alone undercounted the
        prompt several times over on a warm cache.

        The cache fields only appear on responses from models that support
        prompt caching, so they are read defensively and omitted rather
        than reported as a misleading zero.
        """
        read = getattr(raw, "cache_read_input_tokens", None)
        written = getattr(raw, "cache_creation_input_tokens", None)
        usage = {
            "input_tokens": raw.input_tokens + (read or 0) + (written or 0),
            "output_tokens": raw.output_tokens,
        }
        if read is not None:
            usage["cache_read_tokens"] = read
        if written is not None:
            usage["cache_write_tokens"] = written
        return usage

    @staticmethod
    def _parse_tool_calls(content_blocks: list[Any]) -> list[ToolCall]:
        calls: list[ToolCall] = []
        for block in content_blocks:
            if getattr(block, "type", None) == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, arguments=block.input or {}))
        return calls

    def _build_kwargs(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None
    ) -> dict[str, Any]:
        system, msgs = self._convert_messages(messages)
        kwargs: dict[str, Any] = {"model": self._model, "max_tokens": 4096, "messages": msgs}
        if system:
            kwargs["system"] = self._system_blocks(system)
        anthropic_tools = self._convert_tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools
        return kwargs

    async def complete(self, messages, tools=None) -> LLMResponse:
        kwargs = self._build_kwargs(messages, tools)

        import anthropic
        try:
            resp = await self._client.messages.create(**kwargs)
        except anthropic.APIError as exc:
            raise ProviderError(
                "anthropic", getattr(exc, "status_code", None), str(exc)[:300]
            ) from None
        text_parts = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
        usage = self._usage(resp.usage)
        self._log_cache_usage(usage)
        return LLMResponse(
            content="".join(text_parts),
            tool_calls=self._parse_tool_calls(resp.content),
            model=resp.model,
            usage=usage,
        )

    async def stream(self, messages, tools=None):
        kwargs = self._build_kwargs(messages, tools)
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

    Vision is opt-in per subclass: sharing the chat-completions schema says
    nothing about whether the vendor accepts ``image_url`` parts.
    """

    supports_vision = False

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        provider_name: str = "openai",
    ):
        import openai
        kwargs: dict[str, Any] = {
            "api_key": api_key,
            "timeout": _REQUEST_TIMEOUT_SECONDS,
            "max_retries": _MAX_RETRIES,
        }
        if base_url:
            kwargs["base_url"] = base_url
        self._client = openai.AsyncOpenAI(**kwargs)
        self._model = model
        self._provider_name = provider_name

    async def aclose(self) -> None:
        await self._client.close()

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
    def _convert_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Translate content blocks into OpenAI ``content`` parts.

        Messages whose content is already a string are copied through
        unchanged: the chat-completions API treats a bare string and a
        one-element text-part array as equivalent, and the string form is
        what the automatic prompt cache has been seeing all along.
        """
        converted: list[dict[str, Any]] = []
        for m in messages:
            content = m.get("content", "")
            if not isinstance(content, list):
                converted.append(dict(m))
                continue
            parts: list[dict[str, Any]] = []
            for part in normalize_content(content):
                if part.get("type") == IMAGE_BLOCK:
                    media_type = part.get("media_type", "")
                    data = part.get("data", "")
                    parts.append(
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{media_type};base64,{data}"},
                        }
                    )
                else:
                    parts.append({"type": "text", "text": str(part.get("text", ""))})
            converted.append({**m, "content": parts})
        return converted

    @staticmethod
    def _usage(raw: Any) -> dict[str, int]:
        """Normalise usage to the cross-provider shape (see LLMResponse).

        ``prompt_tokens`` already includes the cached share, and
        ``completion_tokens`` already includes reasoning tokens, so both
        are taken as-is. Cache hits are reported under
        ``usage.prompt_tokens_details.cached_tokens`` (OpenAI, xAI, Groq);
        DeepSeek reports the same fact as ``prompt_cache_hit_tokens``.
        Vendors that share the schema but report neither simply omit it.
        Automatic caching has no write surcharge on any of these vendors,
        so the write count is a true zero.
        """
        if raw is None:
            return {"input_tokens": 0, "output_tokens": 0, "cache_write_tokens": 0}
        usage = {
            "input_tokens": raw.prompt_tokens,
            "output_tokens": raw.completion_tokens,
            "cache_write_tokens": 0,
        }
        cached = getattr(
            getattr(raw, "prompt_tokens_details", None), "cached_tokens", None
        )
        if not isinstance(cached, int):
            cached = getattr(raw, "prompt_cache_hit_tokens", None)
        if isinstance(cached, int):
            usage["cache_read_tokens"] = cached
        return usage

    @staticmethod
    def _parse_tool_calls(choices: Any) -> list[ToolCall]:
        calls: list[ToolCall] = []
        if not choices:
            return calls
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
        self._reject_images(messages)
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": self._convert_messages(messages),
        }
        oai_tools = self._convert_tools(tools)
        if oai_tools:
            kwargs["tools"] = oai_tools

        import openai
        try:
            resp = await self._client.chat.completions.create(**kwargs)
        except openai.APIError as exc:
            raise ProviderError(
                self._provider_name, getattr(exc, "status_code", None), str(exc)[:300]
            ) from None
        # An empty choices array is a real occurrence during provider
        # outages/content filtering; without this guard it surfaces as an
        # IndexError → generic 500 instead of the designed 502.
        if not resp.choices:
            raise ProviderError(
                self._provider_name,
                None,
                "Provider returned an empty response (no choices)",
            )
        choice = resp.choices[0]
        usage = self._usage(resp.usage)
        self._log_cache_usage(usage)
        return LLMResponse(
            content=choice.message.content or "",
            tool_calls=self._parse_tool_calls(resp.choices),
            model=resp.model or self._model,
            usage=usage,
        )

    async def stream(self, messages, tools=None):
        self._reject_images(messages)
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": self._convert_messages(messages),
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


class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI GPT models."""

    supports_vision = True

    def __init__(self, api_key: str, model: str = "gpt-4o"):
        super().__init__(api_key=api_key, model=model, provider_name="openai")


class GrokProvider(OpenAICompatibleProvider):
    """xAI Grok models via OpenAI-compatible API."""

    supports_vision = True

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

    supports_vision = True

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

    supports_vision = True
    _provider_name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash"):
        self._api_key = api_key
        # Gemini model ids are lowercase; normalise so a misconfigured
        # "Gemini-2.5-Flash" still resolves.
        self._model = model.lower()
        self._base_url = "https://generativelanguage.googleapis.com/v1beta"
        # Key travels in a header, never in the URL, so it cannot leak into
        # logs or tracebacks.
        self._client = httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT_SECONDS, headers={"x-goog-api-key": api_key}
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _build_url(self, action: str = "generateContent") -> str:
        return f"{self._base_url}/models/{self._model}:{action}"

    @staticmethod
    def _convert_parts(content: Any) -> list[dict[str, Any]]:
        """Translate content blocks into Gemini ``parts``.

        Images ride as ``inlineData`` (base64 + mime type), which is the
        camelCase spelling the rest of this payload already uses.
        """
        if not isinstance(content, list):
            return [{"text": "" if content is None else str(content)}]
        parts: list[dict[str, Any]] = []
        for part in normalize_content(content):
            if part.get("type") == IMAGE_BLOCK:
                parts.append(
                    {
                        "inlineData": {
                            "mimeType": part.get("media_type", ""),
                            "data": part.get("data", ""),
                        }
                    }
                )
            else:
                parts.append({"text": str(part.get("text", ""))})
        return parts

    @classmethod
    def _convert_messages(cls, messages: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
        # Concatenate all system messages (see AnthropicProvider): the
        # security policy must never be evicted by a later system message.
        system_parts: list[str] = []
        contents: list[dict[str, Any]] = []
        for m in messages:
            role = m.get("role", "user")
            if role == "system":
                system_parts.append(content_text(m.get("content", "")))
                continue
            gemini_role = "model" if role == "assistant" else "user"
            contents.append(
                {"role": gemini_role, "parts": cls._convert_parts(m.get("content", ""))}
            )
        system_instruction = "\n\n".join(system_parts) if system_parts else None
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

    @staticmethod
    def _usage(usage_meta: Optional[dict[str, Any]]) -> dict[str, int]:
        """Normalise ``usageMetadata`` to the cross-provider shape (see
        LLMResponse).

        ``promptTokenCount`` already includes the cached share. Output is
        ``candidatesTokenCount`` PLUS ``thoughtsTokenCount``: 2.5+ models
        think before answering, Google bills those tokens as output, and
        the candidates count leaves them out — on a reasoning-heavy turn
        they are most of the output bill. Implicit caching has no write
        surcharge.
        """
        meta = usage_meta or {}
        usage = {
            "input_tokens": meta.get("promptTokenCount") or 0,
            "output_tokens": (meta.get("candidatesTokenCount") or 0)
            + (meta.get("thoughtsTokenCount") or 0),
            "cache_write_tokens": 0,
        }
        # Absent on models or requests where nothing was cached.
        cached = meta.get("cachedContentTokenCount")
        if cached is not None:
            usage["cache_read_tokens"] = cached
        return usage

    async def complete(self, messages, tools=None) -> LLMResponse:
        system_instruction, contents = self._convert_messages(messages)
        payload: dict[str, Any] = {"contents": contents}
        if system_instruction:
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}
        gemini_tools = self._convert_tools(tools)
        if gemini_tools:
            payload["tools"] = gemini_tools

        try:
            resp = await self._client.post(self._build_url(), json=payload)
        except httpx.TransportError as exc:
            _raise_transport_error("gemini", exc)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _raise_provider_error("gemini", exc)
        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise ProviderError(
                "gemini", resp.status_code, "provider returned a non-JSON response"
            ) from None

        # Parse response. An empty candidates list means Gemini refused or
        # filtered the request (promptFeedback carries the reason) — surface
        # it instead of returning blank content that would be persisted as
        # an empty assistant message and poison the semantic cache.
        candidates = data.get("candidates", [])
        if not candidates:
            feedback = data.get("promptFeedback") or {}
            reason = feedback.get("blockReason") or "no candidates returned"
            raise ProviderError(
                "gemini", None, f"provider returned an empty response ({reason})"
            )

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

        # Candidates with neither text nor tool calls (e.g. finishReason
        # SAFETY/RECITATION) are a failed completion, not a silent blank.
        if not text_parts and not tool_calls:
            finish = candidates[0].get("finishReason") or "unknown"
            raise ProviderError(
                "gemini",
                None,
                f"provider returned an empty completion (finishReason: {finish})",
            )

        usage = self._usage(data.get("usageMetadata"))
        self._log_cache_usage(usage)
        return LLMResponse(
            content="".join(text_parts),
            tool_calls=tool_calls,
            model=self._model,
            usage=usage,
        )

    async def stream(self, messages, tools=None):
        system_instruction, contents = self._convert_messages(messages)
        payload: dict[str, Any] = {"contents": contents}
        if system_instruction:
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}
        gemini_tools = self._convert_tools(tools)
        if gemini_tools:
            payload["tools"] = gemini_tools

        try:
            async with self._client.stream(
                "POST", self._build_url("streamGenerateContent"), json=payload
            ) as resp:
                try:
                    # The body of a streamed response has not been read yet, so
                    # the error path must read it before touching .text —
                    # otherwise httpx raises ResponseNotRead and the caller sees
                    # that instead of a ProviderError.
                    if resp.is_error:
                        await resp.aread()
                    resp.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    _raise_provider_error("gemini", exc)
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line.lstrip("[,"))
                    except json.JSONDecodeError:
                        continue
                    # Gemini emits trailing chunks that carry only usageMetadata
                    # with an EMPTY candidates list. A dict .get default does not
                    # apply to a present-but-empty value, so indexing [0] here
                    # raised IndexError and killed the stream mid-answer.
                    candidates = chunk.get("candidates") or []
                    if not candidates:
                        continue
                    parts = candidates[0].get("content", {}).get("parts", []) or []
                    for part in parts:
                        if "text" in part:
                            yield part["text"]
        except httpx.TransportError as exc:
            _raise_transport_error("gemini", exc)


# ---------------------------------------------------------------------------
# Ollama (local)
# ---------------------------------------------------------------------------


class OllamaProvider(LLMProvider):
    """Ollama local models via the REST API.

    Vision is off: whether a locally pulled model can read an image is a
    property of the model, not of the server, and this layer has no way to
    ask. Refusing is the honest answer — a vision-blind local model would
    otherwise answer confidently about a picture it never received.
    """

    supports_vision = False
    _provider_name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._client = httpx.AsyncClient(
            base_url=self._base_url, timeout=_REQUEST_TIMEOUT_SECONDS
        )

    async def aclose(self) -> None:
        await self._client.aclose()

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
        self._reject_images(messages)
        payload: dict[str, Any] = {"model": self._model, "messages": messages, "stream": False}
        ollama_tools = self._convert_tools(tools)
        if ollama_tools:
            payload["tools"] = ollama_tools

        try:
            resp = await self._client.post("/api/chat", json=payload)
        except httpx.TransportError as exc:
            _raise_transport_error("ollama", exc)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _raise_provider_error("ollama", exc)
        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise ProviderError(
                "ollama", resp.status_code, "provider returned a non-JSON response"
            ) from None

        tool_calls: list[ToolCall] = []
        msg = data.get("message", {})
        for idx, tc in enumerate(msg.get("tool_calls", [])):
            fn = tc.get("function", {})
            tool_calls.append(ToolCall(id=f"ollama_{idx}", name=fn.get("name", ""), arguments=fn.get("arguments", {})))

        return LLMResponse(
            content=msg.get("content", ""),
            tool_calls=tool_calls,
            model=data.get("model", self._model),
            # Ollama has no prompt cache to report and nothing to bill.
            usage={
                "input_tokens": data.get("prompt_eval_count", 0),
                "output_tokens": data.get("eval_count", 0),
                "cache_write_tokens": 0,
            },
        )

    async def stream(self, messages, tools=None):
        self._reject_images(messages)
        payload: dict[str, Any] = {"model": self._model, "messages": messages, "stream": True}
        ollama_tools = self._convert_tools(tools)
        if ollama_tools:
            payload["tools"] = ollama_tools

        try:
            async with self._client.stream("POST", "/api/chat", json=payload) as resp:
                try:
                    # See GeminiProvider.stream: the error body must be read
                    # before raise_for_status, or .text raises ResponseNotRead
                    # and masks the ProviderError.
                    if resp.is_error:
                        await resp.aread()
                    resp.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    _raise_provider_error("ollama", exc)
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
        except httpx.TransportError as exc:
            _raise_transport_error("ollama", exc)


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
