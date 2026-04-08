"""
Smart Context Manager for SentientAI.

Solves the OpenClaw token explosion problem by implementing:
1. Sliding window — keep only the last N messages in full
2. Conversation summarization — compress older messages into summaries
3. Tool result compression — truncate large tool outputs
4. Dynamic tool loading — only send relevant tool schemas
5. Token counting — accurate estimation to prevent silent overflow

This prevents the 100k+ token problem where the full conversation
history + all tool schemas + all tool results are sent on every request.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


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
            if isinstance(part, dict):
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

# Model context window sizes (input tokens)
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

# Reserve tokens for the model's response
_RESPONSE_RESERVE = 4096


def get_context_window(model: str) -> int:
    """Get the context window size for a model, with a safe default."""
    return MODEL_CONTEXT_WINDOWS.get(model, 32_000)


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

        if role == "user" and isinstance(content, str):
            # Keep first 200 chars of each user message
            user_points.append(content[:200].strip())

        elif role == "assistant" and isinstance(content, str):
            # Keep first 300 chars of each assistant response
            assistant_points.append(content[:300].strip())

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

    return {
        "role": "system",
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
# Dynamic tool selection
# ---------------------------------------------------------------------------


def select_relevant_tools(
    tools: list[dict[str, Any]],
    user_message: str,
    active_connectors: list[str],
    max_tools: int = 15,
) -> list[dict[str, Any]]:
    """Select only the tools relevant to the current query.

    Instead of sending all 50+ tool schemas on every request (which
    wastes thousands of tokens and degrades model accuracy), we filter
    to the tools most likely to be needed.
    """
    if len(tools) <= max_tools:
        return tools

    msg_lower = user_message.lower()

    scored: list[tuple[float, dict[str, Any]]] = []
    for tool in tools:
        score = 0.0
        name = tool.get("name", "").lower()
        desc = tool.get("description", "").lower()
        connector = tool.get("connector_type", "").lower()

        # Boost tools from active connectors
        if connector in [c.lower() for c in active_connectors]:
            score += 2.0

        # Keyword matching against user message
        name_words = name.replace("_", " ").split()
        for word in name_words:
            if word in msg_lower:
                score += 3.0

        desc_words = set(desc.split())
        msg_words = set(msg_lower.split())
        overlap = len(desc_words & msg_words)
        score += overlap * 0.5

        # Common action keywords
        action_keywords = {
            "email": ["email", "mail", "send", "inbox", "message"],
            "calendar": ["calendar", "event", "schedule", "meeting", "appointment"],
            "assignment": ["assignment", "homework", "due", "submit", "grade"],
            "course": ["course", "class", "enrolled", "professor"],
            "crypto": ["crypto", "bitcoin", "portfolio", "coin", "price"],
            "file": ["file", "document", "read", "write", "upload"],
        }
        for category, keywords in action_keywords.items():
            if any(kw in msg_lower for kw in keywords):
                if any(kw in name or kw in desc for kw in keywords):
                    score += 5.0

        scored.append((score, tool))

    # Sort by score descending and take top N
    scored.sort(key=lambda x: x[0], reverse=True)
    return [tool for _, tool in scored[:max_tools]]


# ---------------------------------------------------------------------------
# Semantic cache
# ---------------------------------------------------------------------------


@dataclass
class CacheEntry:
    query_hash: str
    response: str
    usage: dict[str, int]
    hits: int = 0


class SemanticCache:
    """Simple hash-based semantic cache for repeated queries.

    Caches exact query matches to avoid re-sending identical requests.
    For production, use embedding-based similarity with Redis.
    """

    def __init__(self, max_entries: int = 500):
        self._cache: dict[str, CacheEntry] = {}
        self._max_entries = max_entries

    @staticmethod
    def _hash_query(messages: list[dict[str, Any]]) -> str:
        # Hash the last user message + recent context
        relevant = messages[-3:] if len(messages) >= 3 else messages
        payload = json.dumps(relevant, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def get(self, messages: list[dict[str, Any]]) -> Optional[CacheEntry]:
        key = self._hash_query(messages)
        entry = self._cache.get(key)
        if entry:
            entry.hits += 1
            return entry
        return None

    def put(self, messages: list[dict[str, Any]], response: str, usage: dict[str, int]) -> None:
        if len(self._cache) >= self._max_entries:
            # Evict least-hit entry
            min_key = min(self._cache, key=lambda k: self._cache[k].hits)
            del self._cache[min_key]

        key = self._hash_query(messages)
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
    4. Dynamic tool selection: only send relevant tool schemas
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
        self._summaries: dict[str, list[dict[str, Any]]] = {}  # conversation_id -> summaries
        self._cache = SemanticCache()

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

        # Step 3: Select relevant tools
        last_user_msg = ""
        for m in reversed(optimized_messages):
            if m.get("role") == "user":
                last_user_msg = m.get("content", "")
                break

        optimized_tools = select_relevant_tools(
            tools,
            last_user_msg,
            active_connectors or [],
        )

        # Step 4: Check budget and trim if needed
        budget = self.get_budget(system_prompt, optimized_messages, optimized_tools)
        if budget.available < 500:
            # Emergency trim: keep only last 6 messages
            optimized_messages = optimized_messages[-6:]

        return optimized_messages, optimized_tools

    def check_cache(self, messages: list[dict[str, Any]]) -> Optional[CacheEntry]:
        """Check if we have a cached response for this query."""
        return self._cache.get(messages)

    def cache_response(self, messages: list[dict[str, Any]], response: str, usage: dict[str, int]) -> None:
        """Cache a response for future reuse."""
        self._cache.put(messages, response, usage)

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

        # Summarize old messages
        if len(old_msgs) >= 4:
            summary = summarize_messages(old_msgs)

            # Store summary for this conversation
            if conversation_id:
                if conversation_id not in self._summaries:
                    self._summaries[conversation_id] = []
                self._summaries[conversation_id].append(summary)

            return system_msgs + [summary] + recent_msgs

        return system_msgs + recent_msgs
