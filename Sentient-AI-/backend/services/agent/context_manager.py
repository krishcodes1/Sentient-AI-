"""
Smart Context Manager for Crawler AI.

Solves the OpenClaw token explosion problem by implementing:
1. Sliding window — keep only the last N messages in full
2. Conversation summarization — compress older messages into summaries
3. Tool result compression — truncate large tool outputs
4. Bounded, STABLE tool loading — a fixed tool array per tool set
5. Token counting — accurate estimation to prevent silent overflow

This prevents the 100k+ token problem where the full conversation
history + all tool schemas + all tool results are sent on every request.

A second, equally expensive problem is churn. Every provider bills a
cached prompt prefix at roughly a tenth of a fresh one, and the prefix is
matched byte for byte from position zero: system prompt, then tools, then
history. Anything that reshuffles an earlier element invalidates the cache
for everything after it, so the pieces of the request that do not change
between turns are kept byte-identical here on purpose.
"""

from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from services.agent.providers import IMAGE_BLOCK, content_text


# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------

# Average chars per token varies by model. Using ~3.5 chars/token
# which is more accurate than the naive chars/4 used by OpenClaw
# (their ~4.0 estimate causes ~47% undercounting).
_CHARS_PER_TOKEN = 3.5


def estimate_tokens(text: str) -> int:
    """Estimate token count for a string. More accurate than chars/4."""
    if not text:
        return 0
    return max(1, int(len(text) / _CHARS_PER_TOKEN))


# What one image costs the model. Every vendor prices images by pixel
# area, which this layer never sees — it holds base64 whose LENGTH says
# nothing about token cost. A flat figure in the range a phone photo
# actually bills is far closer than measuring the encoded string, which
# would read a 3 MB JPEG as ~850k tokens and trip the emergency trim on
# every image message.
_IMAGE_TOKENS = 1_200


def estimate_message_tokens(message: dict[str, Any]) -> int:
    """Estimate tokens for a single message including role overhead."""
    # ~4 tokens overhead per message (role, delimiters)
    overhead = 4
    content = message.get("content", "")
    if isinstance(content, str):
        return overhead + estimate_tokens(content)
    if isinstance(content, list):
        total = overhead
        for part in content:
            if isinstance(part, dict) and part.get("type") == IMAGE_BLOCK:
                total += _IMAGE_TOKENS
            elif isinstance(part, dict):
                total += estimate_tokens(json.dumps(part))
            else:
                total += estimate_tokens(str(part))
        return total
    return overhead


def estimate_tool_schema_tokens(tools: list[dict[str, Any]]) -> int:
    """Estimate tokens consumed by tool definitions."""
    if not tools:
        return 0
    # ~36 tokens per tool on average, plus fixed overhead
    return 50 + sum(estimate_tokens(json.dumps(t)) for t in tools)


# ---------------------------------------------------------------------------
# Context budget
# ---------------------------------------------------------------------------

# Model context window sizes (input tokens). Exact ids only; anything
# newer is resolved by family below, because this table goes stale the
# moment a vendor ships a model and nobody here notices.
MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    # Anthropic
    "claude-opus-4-20250514": 200_000,
    "claude-sonnet-4-20250514": 200_000,
    "claude-haiku-4-5-20251001": 200_000,
    # OpenAI
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "o1-preview": 128_000,
    "o1": 200_000,
    # Gemini
    "gemini-2.5-pro": 1_000_000,
    "gemini-2.5-flash": 1_000_000,
    "gemini-2.0-flash": 1_000_000,
    # Grok
    "grok-3": 131_072,
    "grok-3-mini": 131_072,
    # Deepseek
    "deepseek-chat": 64_000,
    "deepseek-reasoner": 64_000,
    # Groq
    "llama-3.3-70b-versatile": 128_000,
    "mixtral-8x7b-32768": 32_768,
    # Mistral
    "mistral-large-latest": 128_000,
    "mistral-small-latest": 128_000,
    # Ollama (conservative defaults)
    "llama3.2": 128_000,
    "mistral": 32_000,
    "codellama": 16_000,
    "mixtral": 32_000,
}

# Per-family floor for a model id the table has never heard of. Matched on
# the longest prefix, so "claude-sonnet-4-6" resolves through "claude-"
# instead of falling all the way through. These are the smallest window
# the family has shipped, so a newer member is under-estimated rather than
# over-estimated — the failure mode is trimming a little early, not an
# oversized request the provider rejects.
_MODEL_FAMILY_WINDOWS: tuple[tuple[str, int], ...] = (
    ("claude-", 200_000),
    ("gpt-4o", 128_000),
    ("gpt-", 128_000),
    ("o1", 128_000),
    ("o3", 200_000),
    ("o4", 200_000),
    ("gemini-", 1_000_000),
    ("grok-", 131_072),
    ("deepseek-", 64_000),
    ("mistral-", 128_000),
    ("magistral-", 128_000),
    ("llama-3", 128_000),
    ("llama3", 128_000),
    ("qwen", 32_768),
    ("mixtral", 32_768),
)

# Where an unrecognised model lands. The old 32k default was punitive:
# every model released after this table was written got budgeted at a
# sixth of its real window, which triggered summarization and emergency
# trims on conversations the model could have held in full. 128k is the
# floor across every hosted family the platform supports, and the budget
# is an estimate feeding a trim heuristic — not a hard API limit — so a
# slightly generous guess costs one provider-side error at worst, while a
# stingy one silently degrades every long conversation.
_DEFAULT_CONTEXT_WINDOW = 128_000

# Reserve tokens for the model's response
_RESPONSE_RESERVE = 4096


def get_context_window(model: str) -> int:
    """Get the context window size for a model.

    Falls back to the model's family (longest matching prefix) and then to
    a sensible platform default, so an unrecognised id is not punished
    with a window six times smaller than it actually has.
    """
    name = (model or "").strip().lower()
    if name in MODEL_CONTEXT_WINDOWS:
        return MODEL_CONTEXT_WINDOWS[name]
    best = ""
    window = _DEFAULT_CONTEXT_WINDOW
    for prefix, size in _MODEL_FAMILY_WINDOWS:
        if name.startswith(prefix) and len(prefix) > len(best):
            best, window = prefix, size
    return window


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------


def summarize_messages(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a compressed summary of a batch of messages.

    This is a rule-based summarizer (no LLM call needed). It extracts
    key information and discards verbose tool outputs.
    """
    user_points: list[str] = []
    assistant_points: list[str] = []
    tool_actions: list[str] = []

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        # Multimodal turns summarize by their text alone: the base64 of an
        # attachment says nothing a summary can use, and folding it in
        # would put megabytes of it back into the very context this is
        # compressing.
        text = content_text(content)

        if role == "user":
            # Keep first 200 chars of each user message
            user_points.append(text[:200].strip())

        elif role == "assistant":
            # Keep first 300 chars of each assistant response
            assistant_points.append(text[:300].strip())

        elif role == "tool":
            name = msg.get("name", "unknown")
            # Just note the tool was called, don't keep the full result
            tool_actions.append(name)

    summary_parts: list[str] = []
    if user_points:
        summary_parts.append("User asked: " + " | ".join(user_points))
    if assistant_points:
        summary_parts.append("Assistant responded: " + " | ".join(assistant_points))
    if tool_actions:
        summary_parts.append(f"Tools used: {', '.join(set(tool_actions))}")

    # Emit the summary as a USER-role message, never system. A second
    # system message competes with SECURITY_SYSTEM_PROMPT for the single
    # system slot that Anthropic and Gemini expose (their _convert_messages
    # keeps only the last system message), which would silently drop the
    # entire injection-defense / financial / approval contract on any
    # conversation long enough to trigger summarization. As conversation
    # history, the summary belongs in the dialogue, not the policy slot.
    return {
        "role": "user",
        "content": f"[Conversation summary of {len(messages)} earlier messages]\n" + "\n".join(summary_parts),
    }


# ---------------------------------------------------------------------------
# Tool result compression
# ---------------------------------------------------------------------------


def compress_tool_result(result: str, max_chars: int = 2000) -> str:
    """Compress a tool result to fit within a character budget.

    Keeps the beginning and end of the result (most useful parts)
    and replaces the middle with a truncation notice.
    """
    if len(result) <= max_chars:
        return result

    keep_each = max_chars // 2 - 50
    return (
        result[:keep_each]
        + f"\n\n... [{len(result) - max_chars} chars truncated] ...\n\n"
        + result[-keep_each:]
    )


# ---------------------------------------------------------------------------
# Tool selection
# ---------------------------------------------------------------------------


def select_offered_tools(
    tools: list[dict[str, Any]],
    active_connectors: list[str],
    max_tools: int = 15,
) -> list[dict[str, Any]]:
    """Choose the bounded tool array to offer, deterministically.

    This used to re-score every tool against the latest user message, so
    the same conversation offered a different set — in a different order —
    on every turn. Two costs came out of that:

    - The tool array is part of the cached request prefix. Reordering it
      invalidates the cache for the system prompt and the tools on every
      single turn, which is most of what a turn is billed for.
    - A tool the model used two messages ago could vanish because the
      newest message happened not to mention it, which reads to the model
      as a capability that comes and goes.

    Selection now depends only on the tool set and the user's active
    connectors, both of which change when the user changes a connector and
    not otherwise. That makes the array byte-identical turn to turn, and
    makes which tools got dropped reproducible instead of a function of
    phrasing.

    Ordering within a tier is by name so that two calls with the same
    inputs produce the same array regardless of how the tool list was
    assembled.
    """
    if len(tools) <= max_tools:
        return tools

    active = {c.lower() for c in active_connectors}

    def rank(tool: dict[str, Any]) -> tuple[int, str]:
        # Tools from a connector the user has actually enabled come first;
        # everything else keeps a stable alphabetical order behind them.
        connector = (tool.get("connector_type") or "").lower()
        return (0 if connector in active else 1, tool.get("name", ""))

    return sorted(tools, key=rank)[:max_tools]


# ---------------------------------------------------------------------------
# Turn replay cache
# ---------------------------------------------------------------------------


@dataclass
class CacheEntry:
    query_hash: str
    response: str
    usage: dict[str, int]
    created_at: float = field(default_factory=time.monotonic)
    hits: int = 0


class TurnReplayCache:
    """Short-lived de-duplication for a turn that is submitted twice.

    This was written as a "semantic cache", and it was never one: it keys
    on an exact hash, so nothing but a byte-identical request can hit it.
    It is kept, deliberately narrowed, as what it actually does — absorbing
    a double-submit or a client retry of the SAME turn — because that is a
    real event (the chat UI retries a dropped SSE stream) and a second
    provider round-trip for it is pure waste.

    What it is NOT is a cost lever. The saving that matters comes from
    provider prompt caching, which bills a repeated prefix at ~10% and hits
    on every turn of every conversation rather than on an exact repeat.
    Widening this one to "similar" questions was considered and rejected:
    an answer is only correct for the conversation that produced it, and
    similarity matching across users is a cross-tenant leak waiting for a
    bad embedding.

    Two guards keep it honest:

    - ``scope`` (``"<user_id>:<conversation_id>"``) is hashed into the key,
      so an entry can never be served to another user or another thread.
    - Entries expire after ``ttl_seconds``. A retry arrives in seconds; an
      identical request half an hour later is a new question about a world
      that may have moved on, and should reach the model.

    The whole prepared message list is hashed, not just its tail. The old
    last-three-messages key meant two different conversations that happened
    to end the same way collided — held apart only by ``scope``, with the
    consequence of getting that wrong being one user's answer shown to
    another.
    """

    _DEFAULT_TTL_SECONDS = 120.0

    def __init__(self, max_entries: int = 500, ttl_seconds: float | None = None):
        self._cache: dict[str, CacheEntry] = {}
        self._max_entries = max_entries
        self._ttl_seconds = (
            self._DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        )

    @staticmethod
    def _hash_query(messages: list[dict[str, Any]], scope: str = "") -> str:
        payload = scope + "\n" + json.dumps(messages, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def get(
        self, messages: list[dict[str, Any]], scope: str = ""
    ) -> Optional[CacheEntry]:
        key = self._hash_query(messages, scope)
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.monotonic() - entry.created_at > self._ttl_seconds:
            del self._cache[key]
            return None
        entry.hits += 1
        return entry

    def put(
        self,
        messages: list[dict[str, Any]],
        response: str,
        usage: dict[str, int],
        scope: str = "",
    ) -> None:
        if len(self._cache) >= self._max_entries:
            # Evict the oldest entry. Evicting the least-HIT one kept
            # whatever had been replayed most, which in a TTL'd retry cache
            # is exactly the entry closest to expiring anyway.
            oldest = min(self._cache, key=lambda k: self._cache[k].created_at)
            del self._cache[oldest]

        key = self._hash_query(messages, scope)
        self._cache[key] = CacheEntry(query_hash=key, response=response, usage=usage)


# ---------------------------------------------------------------------------
# Context Manager
# ---------------------------------------------------------------------------


@dataclass
class ContextBudget:
    """Token budget breakdown for a request."""
    total_window: int
    system_prompt: int
    tool_schemas: int
    conversation: int
    response_reserve: int
    available: int


class ContextManager:
    """Manages conversation context to prevent token explosion.

    Key strategies:
    1. Sliding window: keep last `window_size` messages in full
    2. Summarization: compress older messages into a summary
    3. Tool result compression: truncate large outputs
    4. Stable tool selection: a bounded, deterministic tool array
    5. Token budgeting: track and enforce limits
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        window_size: int = 12,
        summary_trigger: int = 20,
        max_tool_result_chars: int = 2000,
    ):
        self.model = model
        self.window_size = window_size
        self.summary_trigger = summary_trigger
        self.max_tool_result_chars = max_tool_result_chars
        self._cache = TurnReplayCache()

    def get_budget(
        self,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ContextBudget:
        """Calculate the token budget for a request."""
        total = get_context_window(self.model)
        sys_tokens = estimate_tokens(system_prompt)
        tool_tokens = estimate_tool_schema_tokens(tools)
        conv_tokens = sum(estimate_message_tokens(m) for m in messages)
        available = total - sys_tokens - tool_tokens - conv_tokens - _RESPONSE_RESERVE

        return ContextBudget(
            total_window=total,
            system_prompt=sys_tokens,
            tool_schemas=tool_tokens,
            conversation=conv_tokens,
            response_reserve=_RESPONSE_RESERVE,
            available=max(0, available),
        )

    def prepare_context(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        system_prompt: str = "",
        conversation_id: str = "",
        active_connectors: list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Prepare optimized messages and tools for an LLM request.

        Returns:
            Tuple of (optimized_messages, optimized_tools)
        """
        # Step 1: Compress tool results in messages
        optimized_messages = self._compress_tool_results(messages)

        # Step 2: Apply sliding window + summarization
        optimized_messages = self._apply_sliding_window(
            optimized_messages, conversation_id
        )

        # Step 3: Pick the tool array. Deliberately independent of the
        # messages above — see select_offered_tools.
        optimized_tools = select_offered_tools(tools, active_connectors or [])

        # Step 4: Check budget and trim if needed
        budget = self.get_budget(system_prompt, optimized_messages, optimized_tools)
        if budget.available < 500:
            # Emergency trim: keep the last 6 non-system messages, but NEVER
            # drop system messages — index 0 carries the security system
            # prompt and the user's memory block, and the provider layer
            # builds its system prompt only from system-role messages. The
            # sliding-window step already preserves them; this trim must too.
            system_messages = [
                m for m in optimized_messages if m.get("role") == "system"
            ]
            rest = [m for m in optimized_messages if m.get("role") != "system"]
            optimized_messages = system_messages + rest[-6:]

        return optimized_messages, optimized_tools

    def check_cache(
        self, messages: list[dict[str, Any]], scope: str = ""
    ) -> Optional[CacheEntry]:
        """Return a just-produced answer for a byte-identical repeat of this
        turn within ``scope`` (see :class:`TurnReplayCache`)."""
        return self._cache.get(messages, scope=scope)

    def cache_response(
        self,
        messages: list[dict[str, Any]],
        response: str,
        usage: dict[str, int],
        scope: str = "",
    ) -> None:
        """Record this turn's answer so an immediate retry can skip the
        provider round-trip (within ``scope``)."""
        self._cache.put(messages, response, usage, scope=scope)

    def _compress_tool_results(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Compress large tool results in the message history."""
        result: list[dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "tool":
                compressed = dict(msg)
                content = compressed.get("content", "")
                if isinstance(content, str) and len(content) > self.max_tool_result_chars:
                    compressed["content"] = compress_tool_result(content, self.max_tool_result_chars)
                result.append(compressed)
            else:
                result.append(msg)
        return result

    def _apply_sliding_window(
        self,
        messages: list[dict[str, Any]],
        conversation_id: str,
    ) -> list[dict[str, Any]]:
        """Apply sliding window with summarization.

        Keeps the system message + last `window_size` messages in full.
        Summarizes anything older.
        """
        if len(messages) <= self.window_size:
            return messages

        # Separate system messages from conversation
        system_msgs = [m for m in messages if m.get("role") == "system"]
        conv_msgs = [m for m in messages if m.get("role") != "system"]

        if len(conv_msgs) <= self.window_size:
            return messages

        # Split into old (to summarize) and recent (to keep)
        old_msgs = conv_msgs[:-self.window_size]
        recent_msgs = conv_msgs[-self.window_size:]

        # Summarize old messages. The summary is returned inline in the
        # message list — deliberately not accumulated on the instance:
        # this ContextManager lives on the process-wide runtime, and a
        # per-turn append (each entry re-covering the whole tail of the
        # conversation) was an unbounded memory leak.
        if len(old_msgs) >= 4:
            summary = summarize_messages(old_msgs)
            return system_msgs + [summary] + recent_msgs

        return system_msgs + recent_msgs
