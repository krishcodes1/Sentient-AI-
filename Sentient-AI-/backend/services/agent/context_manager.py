"""Fits a conversation, its tool schemas and its tool results into the model's
context window before each LLM request.

Why it exists: Without a budget the history plus every schema and result
outgrows the window and fails or silently truncates; the agent runtime calls
this on every turn, and the agent route reuses its tool-result compression.

Connects to: nothing external; pure functions over the message list and
tool schemas.
Used by: AgentRuntime on every turn (window, capped summary, tool
selection, replay cache) and api/routes/agent.py (compress_tool_result).

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


# Ceiling on the rolling summary of older messages (~500 tokens). It is
# re-sent on every model call of every turn, and a chat channel reuses one
# thread for months: uncapped, it grew ~330 chars per past exchange forever.
SUMMARY_MAX_CHARS = 2000


def summarize_messages(
    messages: list[dict[str, Any]], max_chars: int = SUMMARY_MAX_CHARS
) -> dict[str, Any]:
    """Create a compressed summary of a batch of messages.

    This is a rule-based summarizer (no LLM call needed). It extracts
    key information and discards verbose tool outputs. The points are kept
    newest first within ``max_chars``: the exchanges just before the
    verbatim window matter most, and the oldest are the first to go.
    """
    points: list[tuple[str, str]] = []
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
            points.append(("user", text[:200].strip()))

        elif role == "assistant":
            # Keep first 300 chars of each assistant response
            points.append(("assistant", text[:300].strip()))

        elif role == "tool":
            name = msg.get("name", "unknown")
            # Just note the tool was called, don't keep the full result
            tool_actions.append(name)

    def newest_within(items: list[str], budget: int) -> list[str]:
        kept: list[str] = []
        used = 0
        for point in reversed(items):
            cost = len(point) + 3  # the " | " joining it to its neighbour
            if used + cost > budget:
                break
            kept.append(point)
            used += cost
        kept.reverse()
        return kept

    # The person's own words get first claim on the budget: they are short
    # and carry what has to survive (preferences, decisions, names), while
    # the assistant's longer answers mostly restate them. The assistant
    # gets whatever the user points leave, and at least a quarter.
    all_user = [point for role, point in points if role == "user"]
    all_assistant = [point for role, point in points if role == "assistant"]
    user_points = newest_within(all_user, max_chars - max_chars // 4)
    user_used = sum(len(point) + 3 for point in user_points)
    assistant_points = newest_within(all_assistant, max_chars - user_used)
    omitted = len(points) - len(user_points) - len(assistant_points)

    summary_parts: list[str] = []
    if omitted:
        summary_parts.append(f"(The {omitted} oldest points are left out.)")
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


# Built-in tools the assistant's everyday answers depend on (looking things
# up, and today's date for anything time-relative). Offered whenever they
# exist, however many connector tools compete for the bounded array.
CORE_TOOL_NAMES = frozenset({"web.search", "web.fetch_page", "reminders.now"})

# How many tools one request offers. See select_offered_tools for why 20.
OFFERED_TOOL_CAP = 20

# The tool priority list: which tool of a family takes the family's first
# slot when the array is trimmed, then its second, and so on; the family's
# other tools follow by name. Alphabetical order alone put reminders.cancel
# ahead of reminders.create, canvas.get_assignments ahead of
# canvas.get_courses (whose ids every other Canvas call needs), and
# google_workspace.search_emails and get_message, which repeat what
# get_messages already returns, ahead of send_email.
#
# Entries are "<connector type>.<action>", so a second account's
# "canvas__<slug>.get_courses" matches too. Only the order of entries of the
# same family matters: this ranks tools within their family and never adds a
# tool to the array or takes a slot from another family. To extend it, add
# one line per tool, most useful first, next to its family's other lines.
# Keep it short: a family's leftovers already follow in a stable order.
TOOL_PRIORITY: tuple[str, ...] = (
    # web.research only saves rounds (web.search plus web.fetch_page, both
    # core, do what it does); nothing else reads a JavaScript-built page.
    "web.screenshot",
    "web.research",
    "reminders.create",
    "reminders.list",
    "reminders.cancel",
    # get_upcoming answers "what is due, missing or late" across every
    # course in one call, which is what get_assignments per course was for;
    # grade_whatif returns the current grade as get_grades does, plus the
    # what-if and target answers, so both rank above the tool they cover.
    # submit_assignment is built only once the owner granted the write
    # scope, and nothing else submits, so it ranks above those reads.
    "canvas.get_upcoming",
    "canvas.get_courses",
    "canvas.submit_assignment",
    "canvas.grade_whatif",
    "canvas.get_assignments",
    "canvas.get_grades",
    "google_workspace.get_messages",
    "google_workspace.get_events",
    "google_workspace.send_email",
    "google_workspace.create_event",
    "desktop.observe",
    # browser.read gives the refs and the navigation every other browser
    # tool acts on, and browser.act and browser.checkout (feat/purchases)
    # sort ahead of it by name.
    "browser.read",
    # A page watch is created before it is listed or deleted.
    "watch.create",
    "watch.list",
    "watch.delete",
)
_PRIORITY_RANK = {name: rank for rank, name in enumerate(TOOL_PRIORITY)}

# Tools the trim keeps once they are built, by taking a slot from a later
# pick (select_offered_tools, step 4). Entries are "<connector type>.<action>"
# like TOOL_PRIORITY's.
#
# The undo of something that keeps running: whenever a family's create tool
# is offered, the tools that list what it made and take it back are offered
# too. A reminder fires and a page watch fetches its page (standing
# background egress) long after the chat, and chat is the only place the
# owner can find and stop one, so the trim must never leave the assistant
# able to start one it cannot stop.
UNDO_COMPANIONS: dict[str, tuple[str, ...]] = {
    "reminders.create": ("reminders.list", "reminders.cancel"),
    "watch.create": ("watch.list", "watch.delete"),
}

# A connector's write tools are kept too, with no list to maintain here:
# build_tools marks every connector (not built-in) WRITE and DELETE tool
# ``connector_write`` from its catalog entry, so adding a connector stays
# one file plus one registry line. Each is built only once the owner
# granted its write scope, and no other tool does what it does, so it
# takes the slot of an offered tool that only repeats another offered one
# (COVERED_TOOLS).

# A tool whose job other tools of its own family already do, while all of
# them are offered: web.search plus web.fetch_page do what web.research
# does in one call; get_upcoming carries the submitted, missing and late
# flags; grade_whatif returns the current grade; get_messages takes any
# query and returns whole messages; get_events shows when the user is busy.
COVERED_TOOLS: dict[str, tuple[str, ...]] = {
    "web.research": ("web.search", "web.fetch_page"),
    "canvas.get_submissions": ("canvas.get_upcoming",),
    "canvas.get_grades": ("canvas.grade_whatif",),
    "google_workspace.get_message": ("google_workspace.get_messages",),
    "google_workspace.search_emails": ("google_workspace.get_messages",),
    "google_workspace.check_availability": ("google_workspace.get_events",),
}


def _tool_family(tool: dict[str, Any]) -> str:
    """The namespace a tool is offered under: ``web`` for ``web.search``,
    ``canvas__<slug>`` for a second Canvas account, ``mcp.<label>`` for
    one MCP server. Each account and each server is its own family, so one
    large server cannot crowd another out."""
    name = tool.get("name", "")
    namespace = name.rpartition(".")[0]
    return namespace or (tool.get("connector_type") or "").lower() or name


def _catalog_key(tool: dict[str, Any]) -> str:
    """The ``<connector type>.<action>`` key the lists above name a tool by,
    whichever account or namespace it is offered under."""
    namespace, _, action = tool.get("name", "").rpartition(".")
    connector = (tool.get("connector_type") or namespace.partition("__")[0]).lower()
    return f"{connector}.{action}"


def _sibling(tool: dict[str, Any], key: str) -> str:
    """The name the catalog tool *key* has in *tool*'s own family:
    ``canvas__<slug>.get_upcoming`` next to ``canvas__<slug>.get_grades``."""
    return f"{tool.get('name', '').rpartition('.')[0]}.{key.rpartition('.')[2]}"


def _within_family_rank(tool: dict[str, Any]) -> tuple[int, str]:
    """``TOOL_PRIORITY`` position first (unlisted tools after every listed
    one), then name: a total order, since tool names are unique."""
    return (_PRIORITY_RANK.get(_catalog_key(tool), len(TOOL_PRIORITY)), tool.get("name", ""))


def _round_robin(tools: list[dict[str, Any]], slots: int) -> list[dict[str, Any]]:
    """Up to ``slots`` of ``tools``, one per family per round.

    Families take turns in name order, and each gives up its tools in
    ``_within_family_rank`` order, so every family gets its first tool
    before any family gets a second one, and a family only runs out of
    turns when it runs out of tools.
    """
    if slots <= 0:
        return []
    families: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        families.setdefault(_tool_family(tool), []).append(tool)
    queues = [sorted(families[family], key=_within_family_rank) for family in sorted(families)]

    picked: list[dict[str, Any]] = []
    for depth in range(max((len(queue) for queue in queues), default=0)):
        for queue in queues:
            if depth < len(queue):
                picked.append(queue[depth])
                if len(picked) == slots:
                    return picked
    return picked


def _keep_undo_and_granted_writes(
    tools: list[dict[str, Any]], core: list[dict[str, Any]], picks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Step 4 of ``select_offered_tools``: *core* plus *picks* (the round-
    robin's, in the order it made them), with every built undo companion of
    an offered create tool and every built granted write swapped in.

    Each one missing takes the slot of the latest pick that holds no such
    promise itself and is not its family's first pick (so every family
    keeps its lead). A tool that only repeats offered ones (``COVERED_TOOLS``)
    goes first; an undo companion may then take any such pick, a granted
    write only a covered one. When nothing is left to take, it stays out.
    """
    by_name = {t.get("name", ""): t for t in tools}
    kept = [t.get("name", "") for t in core]
    order = [t.get("name", "") for t in picks]
    offered = set(kept) | set(order)

    protected: set[str] = set()
    families: set[str] = set()
    for tool in picks:
        if _tool_family(tool) not in families:
            families.add(_tool_family(tool))
            protected.add(tool.get("name", ""))

    wanted: list[tuple[str, bool]] = []
    for tool in picks:
        for key in UNDO_COMPANIONS.get(_catalog_key(tool), ()):
            name = _sibling(tool, key)
            if name in by_name:
                # The create tool stays with its undo.
                protected.add(tool.get("name", ""))
                wanted.append((name, True))
    writes = [t for t in tools if t.get("connector_write")]
    wanted += [(t.get("name", ""), False) for t in sorted(writes, key=_within_family_rank)]
    protected.update(name for name, _ in wanted)

    def covered(name: str) -> bool:
        tool = by_name[name]
        keys = COVERED_TOOLS.get(_catalog_key(tool), ())
        return bool(keys) and all(_sibling(tool, key) in offered for key in keys)

    for name, from_any_pick in wanted:
        if name in offered:
            continue
        candidates = [n for n in reversed(order) if n not in protected]
        victim = next((n for n in candidates if covered(n)), None)
        if victim is None and from_any_pick and candidates:
            victim = candidates[0]
        if victim is None:
            continue
        order[order.index(victim)] = name
        offered.discard(victim)
        offered.add(name)
    return [by_name[name] for name in kept + order]


def select_offered_tools(
    tools: list[dict[str, Any]],
    active_connectors: list[str],
    max_tools: int = OFFERED_TOOL_CAP,
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

    What survives a trim, in order:

    1. ``CORE_TOOL_NAMES``, always. The runtime lists every built-in type
       among the "active" connectors, and one 16-tool connector used to
       push web.search off the array, silently taking away the ability to
       look anything up.
    2. Tools of the active connectors, shared round-robin across families
       (a namespace: ``web``, ``canvas``, one ``mcp.<label>`` server; see
       ``_round_robin``), each family giving up its tools in
       ``TOOL_PRIORITY`` order. So every active family is offered its most
       useful tool before any family gets a second one (as long as there
       are fewer families than free slots). This used to be one
       alphabetical cut over all of them, which filled the array with
       canvas.* and google_workspace.* and left nothing for the families
       that sort last: with the default switches plus Canvas and Google
       on their default read scopes (19 tools), web.screenshot,
       reminders.list and both system tools were silently never offered,
       and once their write scopes were granted (22 tools) reminders.create,
       reminders.cancel and google_workspace.send_email as well.
    3. Whatever room is left, the same way, for connectors not active.
       (The runtime counts every connector it offers as active, so in a
       chat turn this group is empty.)
    4. Two promises the round-robin alone does not keep
       (``_keep_undo_and_granted_writes``). Whenever a create tool in
       ``UNDO_COMPANIONS`` is offered, so are the tools that list and undo
       what it makes: a reminder or a page watch the assistant can start,
       it can also find and stop. And every connector write the owner
       granted (a tool marked ``connector_write``, which build_tools sets
       from the catalog) is offered while the array still holds a tool
       that only repeats offered ones (``COVERED_TOOLS``).
       Each takes the slot of the latest pick that is not a family's first
       and not itself promised, a repeat first; a write takes only a
       repeat.

    The cap is 20, not 15. Measured with build_tools: the default switches
    plus Canvas and Google on their default read scopes build 19 tools, so
    at 15 even the fair cut drops canvas.get_calendar_events and
    canvas.get_submissions, and every family added after them only deepens
    the cut. At 20 that everyday set fits whole, and later growth is
    shared out instead of falling on whoever sorts last. Cost: those 19
    schemas estimate at about 1940 tokens against about 1660 for the fair
    15 (``estimate_tool_schema_tokens``), and a connector tool at 50 to
    100, so the five extra slots cost a few hundred tokens a model call;
    the array sits in the cached prefix, billed at roughly a tenth after
    the first call of a conversation. Going higher is not free in another
    way: providers advise keeping a request to about twenty functions,
    beyond which the model picks among them less reliably.

    Since then web.research, memory.remember, canvas.get_upcoming and
    canvas.grade_whatif have joined that everyday set (23 tools), so it is
    trimmed again, and the priority list decides what goes:
    canvas.get_submissions (get_upcoming carries the submitted, missing and
    late flags), google_workspace.search_emails (get_messages takes any
    query) and canvas.get_calendar_events, whose course events are the one
    thing no offered tool lists. With the write scopes granted too (26
    tools) canvas.get_grades, check_availability and get_message go as
    well, never a write. Page watch on top (29) also takes web.research,
    canvas.get_assignments and canvas.grade_whatif: step 4 hands
    web.research's slot to create_event. With every switch on (33 tools,
    nine families) the undo tools take the slots of web.research and
    system.install_capability, and Gmail's send_email and Calendar's
    create_event stay out, since the only picks left to give way are
    families' second tools (test_offered_tools pins both lists).

    The result is sorted by those three groups, then by name, and tool
    names are unique, so it does not depend on the order the list was
    assembled in. A list already within the cap is returned as it is.

    Expected to be replaced: the connectors spec (§4.5, "Offering tools at
    scale") offers core tools, the tools a conversation loaded through
    ``tools.find``, and each connector's ``ToolSpec.starter`` reads. When
    that lands, ``TOOL_PRIORITY`` and ``COVERED_TOOLS``, hand tables kept
    per family, go with it; the undo and granted-write promises still hold.
    """
    if len(tools) <= max_tools:
        return tools

    active = {c.lower() for c in active_connectors}

    def tier(tool: dict[str, Any]) -> int:
        if tool.get("name", "") in CORE_TOOL_NAMES:
            return 0
        if (tool.get("connector_type") or "").lower() in active:
            return 1
        return 2

    def rank(tool: dict[str, Any]) -> tuple[int, str]:
        return (tier(tool), tool.get("name", ""))

    core = sorted((t for t in tools if tier(t) == 0), key=rank)[:max_tools]
    picks: list[dict[str, Any]] = []
    for level in (1, 2):
        picks += _round_robin(
            [t for t in tools if tier(t) == level], max_tools - len(core) - len(picks)
        )
    return sorted(_keep_undo_and_granted_writes(tools, core, picks), key=rank)


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

    One instance serves every turn in the process, and turns run on
    different models (the install default, or a user's own pick), so the
    budget is sized per call: pass ``model`` to ``prepare_context`` /
    ``get_budget``. ``self.model`` is only the fallback when a caller has
    no model to name.
    """

    def __init__(
        self,
        model: str = "claude-sonnet-5",
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
        model: Optional[str] = None,
    ) -> ContextBudget:
        """Calculate the token budget for a request to ``model`` (default:
        the constructor's)."""
        total = get_context_window(model or self.model)
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
        model: Optional[str] = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Prepare optimized messages and tools for an LLM request to
        ``model`` — the model the turn actually runs on, whose window the
        budget is sized for (default: the constructor's).

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
        budget = self.get_budget(
            system_prompt, optimized_messages, optimized_tools, model=model
        )
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
