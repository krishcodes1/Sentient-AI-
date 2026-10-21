"""Pure building blocks of MCP tool pinning: the canonical form and sha256
fingerprint of a tool's raw definition, hidden-character handling, the copy
kept in the database, the review lines and diff the owner reads, exposed names
that survive restarts, the reconcile plan for one discovery, and the decision
for one call, plus the owner's review (detail, order, approve, keep off) and the
server-URL comparison behind a credential edit. No I/O: no database, no
network, no clock (callers pass ``now``).

Why it exists: an MCP server can change what a tool says it does at any moment
(a "rug pull"), and Crawler used to hand the new text to the AI on the next
turn. services/mcp/pin_store.py remembers a fingerprint of every tool's raw
definition per connector and holds a changed or new tool until the owner
approves it on the Security page. Everything that decides what changed, what
may be offered, and what the owner is shown lives here as pure functions over
plain data, so it is tested without a database and gives the same answer in
every process: a fingerprint must never depend on hash seeds, object addresses
or the platform's newline convention, or every pinned tool would be re-flagged
after a restart.

Connects to: services.mcp.client (MCPToolInfo, whose ``raw`` field carries the
entry exactly as the server sent it), services.mcp.integration (the exposed-name
rules, imported lazily because integration imports this module), the prompt
guards (the invisible-character set and the injection patterns).
Used by: services/mcp/pin_store.py, pin_check.py, integration.py and the
/api/security/mcp routes (all WAVE 1 of the security wave, S5).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import math
import re
import unicodedata
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional, TypeVar, cast
from urllib.parse import urlsplit, urlunsplit

import structlog

from services.agent.prompt_guard import _INVISIBLE_CHARS, normalize_for_scan
from services.connectors.base import PromptGuard

if TYPE_CHECKING:
    from services.mcp.client import MCPToolInfo

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# What a definition covers. The first three are always present (None when the
# server left the key out); the optional ones only when the server sent them.
DEFINITION_KEYS: tuple[str, ...] = ("name", "description", "inputSchema")
OPTIONAL_DEFINITION_KEYS: tuple[str, ...] = ("title", "annotations", "outputSchema")

# Nesting deeper than this is replaced by a fixed marker. Real schemas are a
# handful of levels deep; the cap keeps a hostile or cyclic value from
# recursing without end.
MAX_CANON_DEPTH = 64

# An int this wide cannot be printed in decimal under Python's digit limit
# (4300 digits), so it is fingerprinted by its hex digits instead.
_BIGINT_BITS = 13_000

# Pin statuses, review kinds and how an approved hash was trusted. Strings
# checked in code (models/mcp_tool_pin.py has no CHECK constraints).
STATUS_APPROVED = "approved"
STATUS_NEEDS_REVIEW = "needs_review"
STATUS_KEPT_OFF = "kept_off"
REVIEW_CHANGED = "changed"
REVIEW_NEW = "new"
TRUSTED_FIRST_USE = "first_use"
TRUSTED_OWNER_TEST = "owner_test"
TRUSTED_OWNER_REVIEW = "owner_review"

TrustSource = Literal["first_use", "owner_test"]
TRUST_SOURCES: tuple[str, ...] = (TRUSTED_FIRST_USE, TRUSTED_OWNER_TEST)

# The server sentinel (review SEC-F5): one row per server, written the first
# time the server is seen, so a server first seen with zero tools still counts
# as "already pinned" and the first tools it adds later are held for review.
# It is never offered, reviewed, counted or marked removed.
SENTINEL_STATUS = "server_seen"
SENTINEL_NAME_KEY = "0" * 64

# Storage limits. A server controls how many tools it advertises and how big
# each definition is; these keep a hostile server from growing the table.
MAX_PINS_PER_SERVER = 500
MAX_STORED_DEFINITION_BYTES = 32 * 1024
REMOVED_PIN_RETENTION = timedelta(days=180)
MAX_REMOTE_NAME_CHARS = 512

# The refusal vocabulary (pinned by tests/test_mcp_pin_plan.py). Policy for
# all of them is PIN_POLICY; the call-check name is the same string.
PIN_POLICY = "mcp_pin"
RULE_DEFINITION_CHANGED = "mcp_definition_changed"
RULE_TOOL_UNREVIEWED = "mcp_tool_unreviewed"
RULE_TOOL_KEPT_OFF = "mcp_tool_kept_off"
RULE_TOOL_REMOVED = "mcp_tool_removed"
RULE_PIN_UNAVAILABLE = "mcp_pin_unavailable"
REFUSAL_RULES: tuple[str, ...] = (
    RULE_DEFINITION_CHANGED,
    RULE_TOOL_UNREVIEWED,
    RULE_TOOL_KEPT_OFF,
    RULE_TOOL_REMOVED,
    RULE_PIN_UNAVAILABLE,
)

# Review output limits (the review route returns these lines as JSON).
MAX_REVIEW_LINES = 600
MAX_REVIEW_LINE_CHARS = 2000
# Lines fed to difflib per side. A stored definition is at most 32 KiB, so
# this only bites on a schema built to make the diff slow.
MAX_DIFF_INPUT_LINES = 5000

# ---------------------------------------------------------------------------
# Canonical definition and fingerprints
# ---------------------------------------------------------------------------


def _dumps(value: Any) -> str:
    """The one JSON spelling every fingerprint uses."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _plain_str(value: str) -> str:
    # str.__str__ returns the underlying text even for a subclass that
    # overrides __str__, so a subclass cannot change what is fingerprinted.
    return str.__str__(value)


def _canonical_key(key: Any) -> str:
    if isinstance(key, str):
        return _plain_str(key)
    if key is None or isinstance(key, (bool, int, float)):
        return f"$key:{type(key).__name__}:{_dumps(_canonical(key, 0, set()))}"
    return f"$key:{type(key).__name__}"


def _canonical(value: Any, depth: int, stack: set[int]) -> Any:
    """JSON-safe, process-independent form of *value* (see ``canonical_json``).

    Never ``repr()`` and never ``default=str``: an ``object()`` prints its
    address, which differs in every process, so junk becomes a fixed marker
    naming only its type.
    """
    if value is None or value is True or value is False:
        return value
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        number = int(value)
        if number.bit_length() > _BIGINT_BITS:
            return {"$bigint": format(number, "x")}
        return number
    if isinstance(value, float):
        real = float(value)
        if math.isnan(real):
            return {"$nonfinite": "nan"}
        if math.isinf(real):
            return {"$nonfinite": "inf" if real > 0 else "-inf"}
        return real
    if isinstance(value, str):
        # No Unicode or newline normalisation: a homoglyph or a carriage
        # return must change the fingerprint.
        return _plain_str(value)
    if isinstance(value, (list, tuple, Mapping)):
        if depth > MAX_CANON_DEPTH:
            return {"$truncated": "depth"}
        marker = id(value)
        if marker in stack:
            # A container inside itself: the structure, not the address,
            # decides where this marker lands, so it is the same everywhere.
            return {"$truncated": "cycle"}
        stack.add(marker)
        try:
            if isinstance(value, Mapping):
                return _canonical_mapping(value, depth, stack)
            return [_canonical(item, depth + 1, stack) for item in value]
        finally:
            stack.discard(marker)
    return {"$unsupported": type(value).__name__}


def _canonical_mapping(value: Mapping[Any, Any], depth: int, stack: set[int]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in value.items():
        canonical_key = _canonical_key(key)
        canonical_item = _canonical(item, depth + 1, stack)
        if canonical_key in out:
            # Two junk keys can read the same after conversion (two object()
            # keys). Keep the value whose JSON sorts first, so insertion order
            # never decides the fingerprint.
            if _dumps(canonical_item) >= _dumps(out[canonical_key]):
                continue
        out[canonical_key] = canonical_item
    return out


def canonical_value(value: Any) -> Any:
    """The JSON-safe projection ``canonical_json`` prints: ``None``/``bool``/``int``/
    ``str`` as is, finite floats as is, NaN/Infinity as ``{"$nonfinite": ...}``,
    lists and tuples as lists, mappings with string keys (a non-string key becomes
    ``"$key:<type>:<json>"`` for int/float/bool/None, else ``"$key:<type>"``),
    nesting past ``MAX_CANON_DEPTH`` as ``{"$truncated": "depth"}``, a container
    inside itself as ``{"$truncated": "cycle"}``, anything else as
    ``{"$unsupported": "<type name>"}``. Idempotent."""
    return _canonical(value, 0, set())


def canonical_json(value: Any) -> str:
    """``json.dumps(canonical_value(value), sort_keys=True, separators=(",", ":"),
    ensure_ascii=False, allow_nan=False)``: one spelling per definition, whatever
    the key order of the wire JSON and whichever process computes it."""
    return _dumps(canonical_value(value))


def definition_of(info: MCPToolInfo) -> dict[str, Any]:
    """The JSON-safe projection of what the server said about one tool, from the raw
    entry when the client kept it, else from the info's fields (tests build infos
    directly).

    From ``raw``: always ``name``, ``description`` and ``inputSchema`` (None when
    the server left the key out), plus ``title``, ``annotations`` and
    ``outputSchema`` only when present and not None. The raw entry is the one the
    server sent before sanitising, so text past the 500-character cap or inside a
    span the prompt guard redacted still counts.
    """
    raw = getattr(info, "raw", None)
    definition: dict[str, Any]
    if isinstance(raw, Mapping):
        definition = {key: raw.get(key) for key in DEFINITION_KEYS}
        for key in OPTIONAL_DEFINITION_KEYS:
            if raw.get(key) is not None:
                definition[key] = raw.get(key)
    else:
        definition = {
            "name": info.name,
            "description": info.description,
            "inputSchema": info.input_schema,
        }
    return cast(dict[str, Any], canonical_value(definition))


def _sha256_text(text: str) -> str:
    # surrogatepass: a lone surrogate from the wire must hash, not raise.
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def definition_hash(definition: Mapping[str, Any]) -> str:
    """64-hex sha256 of ``canonical_json(definition).encode("utf-8", "surrogatepass")``."""
    return _sha256_text(canonical_json(definition))


def name_key(remote_name: str) -> str:
    """64-hex sha256 of the remote tool name, UTF-8 with surrogatepass. The pin's
    bounded unique key: a server controls tool names and could send a huge one."""
    return _sha256_text(_plain_str(remote_name))


# ---------------------------------------------------------------------------
# Hidden characters
# ---------------------------------------------------------------------------

_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co"})
_VISIBLE_CONTROLS = frozenset({"\n", "\t"})
# Fast path: only characters outside printable ASCII can be hidden.
_MAYBE_HIDDEN = re.compile(r"[^\x20-\x7e\n\t]")
_LONE_SURROGATE = re.compile(r"[\ud800-\udfff]")
_TAG_FIRST, _TAG_LAST = 0xE0020, 0xE007E
# Characters that a model may read as a plain space once hidden ones are
# removed: the exotic spaces, and the line/paragraph separators (which a
# review would otherwise render as a line break, faking a diff line).
_SPACE_LIKE = frozenset({chr(cp) for cp in range(0x2000, 0x200B)} | {"\u2028", "\u2029"})


def is_hidden(ch: str) -> bool:
    """Whether one character is invisible to a reader: every prompt-guard invisible
    character (zero-width, bidi controls, tag characters, exotic spaces), every
    other control, format, surrogate or private-use character except newline and
    tab (so a carriage return counts), the line and paragraph separators, and the
    variation selectors 17-256 (U+E0100-U+E01EF), which can smuggle bytes after an
    emoji."""
    if ch in _VISIBLE_CONTROLS:
        return False
    if _INVISIBLE_CHARS.match(ch) or ch in _SPACE_LIKE:
        return True
    if 0xE0100 <= ord(ch) <= 0xE01EF:
        return True
    return unicodedata.category(ch) in _HIDDEN_CATEGORIES


def _hidden_positions(text: str) -> list[int]:
    return [m.start() for m in _MAYBE_HIDDEN.finditer(text) if is_hidden(m.group())]


def _strings_of(value: Any) -> list[str]:
    """Every string and dict key in a canonical value, depth first."""
    found: list[str] = []
    pending: list[Any] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            found.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return found


def count_hidden(value: Any) -> int:
    """How many characters a reader cannot see, over every string and dict key in
    *value* (see ``is_hidden``)."""
    return sum(len(_hidden_positions(text)) for text in _strings_of(canonical_value(value)))


def strip_hidden(text: str) -> tuple[str, int]:
    """Text a model may read: exotic spaces U+2000-U+200A (and the line and paragraph
    separators) become a plain space, every other hidden character is removed.
    Returns ``(clean_text, how_many_were_hidden)``."""
    positions = _hidden_positions(text)
    if not positions:
        return text, 0
    out: list[str] = []
    last = 0
    for index in positions:
        out.append(text[last:index])
        if text[index] in _SPACE_LIKE:
            out.append(" ")
        last = index + 1
    out.append(text[last:])
    return "".join(out), len(positions)


def decoded_tags(text: str) -> str:
    """The ASCII that the Unicode tag characters (U+E0020-U+E007E) in *text* spell,
    in order; "" when there are none. Tag characters are an invisible twin of
    every ASCII character, used to hide whole sentences from a reader."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if _TAG_FIRST <= ord(ch) <= _TAG_LAST)


# ---------------------------------------------------------------------------
# The stored copy, and the instruction flag
# ---------------------------------------------------------------------------


def storable_text(text: str) -> str:
    """NUL becomes U+2400 and a lone surrogate U+FFFD: Postgres JSON and text
    columns cannot hold either. Display copies only; hashes never come from here."""
    return _LONE_SURROGATE.sub("\ufffd", text.replace("\x00", "\u2400"))


def display_remote_name(remote_name: str) -> str:
    """The ``remote_name`` column: storable, capped at 512 characters."""
    return storable_text(_plain_str(remote_name))[:MAX_REMOTE_NAME_CHARS]


def _storable(value: Any) -> Any:
    if isinstance(value, str):
        return storable_text(value)
    if isinstance(value, dict):
        # Sorted, so two keys that read the same once cleaned resolve the same
        # way everywhere (the hash is unaffected: it is never taken from here).
        return {storable_text(k): _storable(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_storable(item) for item in value]
    return value


def storable_definition(definition: Mapping[str, Any]) -> dict[str, Any]:
    """The copy kept in the database: NUL -> U+2400, lone surrogates -> U+FFFD
    (Postgres JSON cannot hold them), and ``{"$too_large": True, "bytes": n}`` above
    32 KiB of canonical JSON. The hash is always taken from the in-memory raw
    definition, never from this copy."""
    canonical = canonical_value(definition)
    size = len(_dumps(canonical).encode("utf-8", "surrogatepass"))
    if size > MAX_STORED_DEFINITION_BYTES:
        return {"$too_large": True, "bytes": size}
    stored = _storable(canonical)
    return stored if isinstance(stored, dict) else {"$unsupported": type(stored).__name__}


def is_too_large(stored: Optional[Mapping[str, Any]]) -> bool:
    """Whether a stored definition is the too-large marker."""
    return stored is not None and stored.get("$too_large") is True


def looks_like_instructions(definition: Mapping[str, Any]) -> bool:
    """The definition carries text shaped like an instruction to an AI: the
    connector prompt guard's patterns (connectors/base.py ``PromptGuard``) match a
    value or key, as written, in its de-obfuscated form (zero-width splices,
    homoglyphs and fullwidth letters folded), or as the text its tag characters
    spell. A flag for the review card only; nothing is blocked because of it."""
    for text in _strings_of(canonical_value(definition)):
        if PromptGuard.scan(text)[1]:
            return True
        normalized = normalize_for_scan(text)
        if normalized != text and PromptGuard.scan(normalized)[1]:
            return True
        hidden_text = decoded_tags(text)
        if hidden_text and PromptGuard.scan(hidden_text)[1]:
            return True
    return False


# ---------------------------------------------------------------------------
# Review text and diff
# ---------------------------------------------------------------------------

ReviewOp = Literal["context", "added", "removed", "hunk"]


@dataclass(frozen=True)
class TextPart:
    """A piece of one review line: visible text, or one run of hidden characters
    shown as a label ("U+200B", "12 hidden characters")."""

    text: str
    hidden: bool = False
    decoded: Optional[str] = None  # for a run holding tag characters: the ASCII they spell

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "hidden": self.hidden, "decoded": self.decoded}


@dataclass(frozen=True)
class ReviewLine:
    """One line of the review: its role in the diff and its parts. The API returns
    parts, never strings with escape markers, so a server cannot fake a "hidden"
    marker by writing one literally and the frontend never needs innerHTML."""

    op: ReviewOp
    parts: tuple[TextPart, ...]

    @property
    def text(self) -> str:
        return "".join(part.text for part in self.parts)

    def to_dict(self) -> dict[str, Any]:
        return {"op": self.op, "parts": [part.to_dict() for part in self.parts]}


def _sized_parts(line: str) -> list[tuple[TextPart, int]]:
    """``text_parts`` with each part's length in the source line (a hidden run's
    label is short whatever the run's length, so the two differ)."""
    positions = _hidden_positions(line)
    if not positions:
        return [(TextPart(line), len(line))] if line else []
    parts: list[tuple[TextPart, int]] = []
    visible_from = 0
    index = 0
    while index < len(positions):
        start = positions[index]
        end = start + 1
        index += 1
        while index < len(positions) and positions[index] == end:
            end += 1
            index += 1
        if start > visible_from:
            parts.append((TextPart(line[visible_from:start]), start - visible_from))
        run = line[start:end]
        label = f"U+{ord(run):04X}" if len(run) == 1 else f"{len(run)} hidden characters"
        parts.append((TextPart(label, hidden=True, decoded=decoded_tags(run) or None), len(run)))
        visible_from = end
    if visible_from < len(line):
        parts.append((TextPart(line[visible_from:]), len(line) - visible_from))
    return parts


def text_parts(line: str) -> tuple[TextPart, ...]:
    """Split a line into visible text and hidden runs. A hidden run becomes one part
    whose text is ``"U+200B"`` for a single character or ``"12 hidden characters"``
    for a run; a run holding tag characters (U+E0020-U+E007E) also carries
    ``decoded=<the ASCII they spell>`` (other hidden characters spliced between
    them are skipped, so splicing cannot hide the sentence from the owner)."""
    return tuple(part for part, _ in _sized_parts(line))


def _json_block(value: Any) -> list[str]:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    return ["  " + part for part in text.split("\n")]


def _text_field(key: str, value: Any, *, inline: bool) -> list[str]:
    """``key: value`` for a one-line string field, ``key:`` plus indented lines for a
    multi-line one. Split on "\\n" only, so a carriage return or another line
    break stays in the line and shows up as a hidden character."""
    if value is None:
        return [f"{key}:", "  (none)"]
    if not isinstance(value, str):
        # Not text (a server sent a number or an object): shown as JSON under a
        # header that says so, so "5" and 5 never look alike.
        return [f"{key} (not text):", *_json_block(value)]
    if value == "":
        return [f"{key}:", "  (empty)"]
    if inline and "\n" not in value:
        return [f"{key}: {value}"]
    return [f"{key}:", *("  " + part for part in value.split("\n"))]


def review_lines(stored: Optional[Mapping[str, Any]]) -> list[str]:
    """The definition as lines a person can compare: ``"name: ..."``, ``"title: ..."``
    (when present), ``"description:"`` then each description line indented by two
    spaces (``"  (empty)"`` when empty), then ``"inputSchema:"``, ``"annotations:"``,
    ``"outputSchema:"`` (when present) each followed by
    ``json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)`` indented by
    two spaces. A too-large stored definition gives one line saying so."""
    if not stored:
        return []
    if is_too_large(stored):
        size = stored.get("bytes")
        return [
            f"This definition is too large to show line by line ({size} bytes). "
            "Its fingerprint still covers all of it."
        ]
    lines = _text_field("name", stored.get("name"), inline=True)
    if stored.get("title") is not None:
        lines += _text_field("title", stored.get("title"), inline=True)
    lines += _text_field("description", stored.get("description"), inline=False)
    lines.append("inputSchema:")
    lines += _json_block(stored.get("inputSchema"))
    for key in ("annotations", "outputSchema"):
        if stored.get(key) is not None:
            lines.append(f"{key}:")
            lines += _json_block(stored.get(key))
    return lines


_LINE_CUT_NOTE = (
    "This line goes on for {count} more {noun} that are not shown here. A difference "
    "there still changed the fingerprint."
)


def _capped_parts(line: str, cap: int) -> tuple[tuple[TextPart, ...], int]:
    """The parts of *line* that fit in *cap* rendered characters, and how many
    characters of the source line were left out.

    The cap counts what the owner reads (a run of hidden characters is one short
    label), never the raw characters: counting raw characters let a server pad a
    line with 2000 zero-width characters so that the visible sentence after them
    never reached the review, while the model read it once they were stripped."""
    shown: list[TextPart] = []
    used = 0
    consumed = 0
    for part, source_length in _sized_parts(line):
        size = len(part.text)
        if used + size <= cap:
            shown.append(part)
            used += size
            consumed += source_length
            continue
        room = cap - used
        if not part.hidden and room > 0:
            shown.append(TextPart(part.text[:room]))
            consumed += room
        break
    return tuple(shown), len(line) - consumed


def _review_line(op: ReviewOp, text: str) -> tuple[list[ReviewLine], bool]:
    """One review line, capped; a cut line is followed by a hunk line that says how
    much of it is not shown, so a difference past the cut never reads as two
    identical lines."""
    parts, left_out = _capped_parts(text, MAX_REVIEW_LINE_CHARS)
    lines = [ReviewLine(op, parts)]
    if left_out > 0:
        noun = "character" if left_out == 1 else "characters"
        note = _LINE_CUT_NOTE.format(count=left_out, noun=noun)
        lines.append(ReviewLine("hunk", (TextPart(note),)))
    return lines, left_out > 0


def _finish(raw: Sequence[tuple[ReviewOp, str]], truncated: bool) -> tuple[list[ReviewLine], bool]:
    if len(raw) > MAX_REVIEW_LINES:
        truncated = True
        raw = raw[:MAX_REVIEW_LINES]
    out: list[ReviewLine] = []
    for op, text in raw:
        lines, cut = _review_line(op, text)
        truncated = truncated or cut
        out.extend(lines)
    return out, truncated


def review_listing(
    stored: Optional[Mapping[str, Any]], *, op: Literal["context", "added"] = "context"
) -> tuple[list[ReviewLine], bool]:
    """Every line of one definition with the same *op* (``context`` for a tool with
    nothing waiting, ``added`` for a new tool), capped like ``review_diff``."""
    return _finish([(op, line) for line in review_lines(stored)], False)


def review_diff(
    old: Optional[Mapping[str, Any]], new: Mapping[str, Any]
) -> tuple[list[ReviewLine], bool]:
    """``difflib.unified_diff(review_lines(old), review_lines(new), lineterm="", n=3)``
    without its two header lines, as ReviewLines; *old* None (a new tool) gives every
    line as "added". At most 600 lines, each at most 2000 characters as the owner
    reads them (a run of hidden characters counts as its short label), and a cut line
    is followed by one hunk line saying how much of it is not shown; the bool says
    whether anything was cut. Identical definitions give no lines."""
    if old is None:
        return review_listing(new, op="added")
    truncated = False
    old_lines = review_lines(old)
    new_lines = review_lines(new)
    if len(old_lines) > MAX_DIFF_INPUT_LINES or len(new_lines) > MAX_DIFF_INPUT_LINES:
        truncated = True
        old_lines = old_lines[:MAX_DIFF_INPUT_LINES]
        new_lines = new_lines[:MAX_DIFF_INPUT_LINES]
    raw: list[tuple[ReviewOp, str]] = []
    diff = difflib.unified_diff(old_lines, new_lines, lineterm="", n=3)
    for position, line in enumerate(diff):
        if position < 2:
            # The "---" / "+++" file headers. Skipped by position, never by
            # prefix: a removed line that itself starts with "--" must stay.
            continue
        sign, text = line[:1], line[1:]
        if sign == "@":
            raw.append(("hunk", line))
        elif sign == "+":
            raw.append(("added", text))
        elif sign == "-":
            raw.append(("removed", text))
        else:
            raw.append(("context", text))
    return _finish(raw, truncated)


# ---------------------------------------------------------------------------
# Exposed names that survive restarts and collisions
# ---------------------------------------------------------------------------

_ItemT = TypeVar("_ItemT")
_PROVIDER_SAFE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _assign_names(
    label: str,
    items: Sequence[tuple[str, str, _ItemT]],
    pinned: Mapping[str, str],
) -> list[tuple[str, _ItemT]]:
    """``(exposed, item)`` for ``(remote_name, name_key, item)`` triples; see
    ``assign_exposed_names``."""
    # Deferred: integration imports this module (strip_hidden in its
    # sanitiser), so a module-level import here would be circular.
    from services.mcp.integration import (
        _MAX_FULL_NAME_LEN,
        _MAX_TOOL_COMPONENT_LEN,
        MCP_PREFIX,
        sanitize_tool_name,
    )

    # The same budget as sanitized_tool_entries: "mcp.<label>.<tool>" must fit.
    budget = min(_MAX_FULL_NAME_LEN - len(MCP_PREFIX) - 2 - len(label), _MAX_TOOL_COMPONENT_LEN)

    unique: list[tuple[str, str, _ItemT]] = []
    remote_seen: set[str] = set()
    duplicates = 0
    for remote, key, item in items:
        if remote in remote_seen:
            # Two entries with one remote name are indistinguishable at
            # tools/call; the first one wins and the second is never offered.
            duplicates += 1
            continue
        remote_seen.add(remote)
        unique.append((remote, key, item))
    if duplicates:
        # Counts only: remote names are third-party text and stay out of logs.
        logger.warning("mcp_tool_duplicate_name", server=label, count=duplicates)

    used = {name for name in pinned.values() if name}
    taken: set[str] = set()
    exposed: list[Optional[str]] = [None] * len(unique)
    order = sorted(range(len(unique)), key=lambda i: unique[i][0])

    # First pass: a pinned tool keeps the name stored on its pin while it
    # still fits the budget (a longer label may make it not fit).
    for i in order:
        stored = pinned.get(unique[i][1])
        if (
            stored
            and len(stored) <= budget
            and stored not in taken
            and _PROVIDER_SAFE.match(stored)
        ):
            exposed[i] = stored
            taken.add(stored)

    # Second pass: everything else, in remote-name order with the suffix loop
    # of sanitized_tool_entries, never taking a name any pin holds (removed
    # pins included), so an approved name can never move to a newcomer.
    unresolvable = 0
    # Where each base's suffix search stopped: ``used`` is fixed and ``taken``
    # only grows, so resuming there gives exactly the names a search from "_2"
    # would, in linear rather than quadratic time when a server sends many
    # names that normalize to one base.
    next_suffix: dict[str, int] = {}
    for i in order:
        if exposed[i] is not None:
            continue
        base = sanitize_tool_name(unique[i][0])[: max(budget, 0)]
        if not base:
            unresolvable += 1
            continue
        candidate = base
        suffix_n = next_suffix.get(base, 2)
        while candidate in used or candidate in taken:
            suffix = f"_{suffix_n}"
            candidate = base[: max(1, budget - len(suffix))] + suffix
            suffix_n += 1
        next_suffix[base] = suffix_n
        taken.add(candidate)
        exposed[i] = candidate
    if unresolvable:
        logger.warning("mcp_tool_name_unresolvable", server=label, count=unresolvable)

    return [(name, unique[i][2]) for i, name in enumerate(exposed) if name is not None]


def assign_exposed_names(
    label: str, infos: Sequence[MCPToolInfo], pinned: Mapping[str, str]
) -> list[tuple[str, MCPToolInfo]]:
    """(exposed, info) per resolvable tool, in advertisement order. A tool with a pin
    keeps the exposed name stored on it (*pinned* maps name_key -> exposed_name, for
    every pin of the server, removed ones included); a new tool is derived like
    ``sanitized_tool_entries`` but never takes a name any pin holds. With *pinned*
    empty and distinct remote names the result equals
    ``sanitized_tool_entries(label, infos)``. A second info with an already-seen
    remote name is dropped (logged ``mcp_tool_duplicate_name``)."""
    return _assign_names(label, [(info.name, name_key(info.name), info) for info in infos], pinned)


# ---------------------------------------------------------------------------
# The reconcile plan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeenTool:
    """One tool of one discovery, with its fingerprint."""

    # The info the catalog and dispatcher go on with. services.mcp.integration
    # always hands in the sanitised info (the hash and definition come from the
    # raw entry first), so no raw server text travels past this point.
    info: MCPToolInfo
    remote_name: str
    name_key: str
    definition_hash: str
    hidden_chars: int
    definition: Optional[dict[str, Any]]  # storable form; None on a cache hit


def seen_tool(info: MCPToolInfo) -> SeenTool:
    """A fresh discovery's SeenTool, built from the RAW info (before sanitising):
    fingerprint, name key, hidden-character count and the storable definition."""
    definition = definition_of(info)
    return SeenTool(
        info=info,
        remote_name=info.name,
        name_key=name_key(info.name),
        definition_hash=definition_hash(definition),
        hidden_chars=count_hidden(definition),
        definition=storable_definition(definition),
    )


@dataclass(frozen=True)
class PinState:
    """The light, hot-path projection of a pin row (no definitions)."""

    id: uuid.UUID
    name_key: str
    exposed_name: str
    status: str
    review_kind: Optional[str]
    approved_hash: Optional[str]
    pending_hash: Optional[str]
    removed: bool
    approved_hidden_chars: int
    updated_at: datetime
    removed_at: Optional[datetime] = None  # for the 180-day prune and the cap

    @property
    def is_sentinel(self) -> bool:
        return self.status == SENTINEL_STATUS or self.name_key == SENTINEL_NAME_KEY

    @classmethod
    def from_row(cls, row: Any) -> PinState:
        """From a ``models.mcp_tool_pin.McpToolPin`` row, or a SELECT of its light
        columns (anything with those attributes)."""
        removed_at = getattr(row, "removed_at", None)
        return cls(
            id=row.id,
            name_key=row.name_key,
            exposed_name=row.exposed_name,
            status=row.status,
            review_kind=row.review_kind,
            approved_hash=row.approved_hash,
            pending_hash=row.pending_hash,
            removed=removed_at is not None,
            approved_hidden_chars=int(row.approved_hidden_chars or 0),
            updated_at=row.updated_at,
            removed_at=removed_at,
        )


@dataclass(frozen=True)
class HeldChange:
    """A new pending definition this write records: one ``mcp_tool_changed`` audit
    row, and a channel message when the pin ends up waiting for review (never for a
    kept-off pin)."""

    kind: str  # REVIEW_CHANGED or REVIEW_NEW
    definition_hash: str  # the new pending hash
    previous_hash: Optional[str]  # the approved hash it differs from; None for a new tool
    notify: bool


@dataclass(frozen=True)
class NewPin:
    """A row to insert. ``columns()`` gives the McpToolPin keyword arguments (the
    caller adds ``user_id`` and ``connector_id``)."""

    name_key: str
    remote_name: str
    exposed_name: str
    status: str
    first_seen_at: datetime
    updated_at: datetime
    review_kind: Optional[str] = None
    trusted_how: Optional[str] = None
    approved_hash: Optional[str] = None
    approved_definition: Optional[dict[str, Any]] = None
    approved_hidden_chars: int = 0
    pending_hash: Optional[str] = None
    pending_definition: Optional[dict[str, Any]] = None
    pending_hidden_chars: int = 0
    change_count: int = 0
    approved_at: Optional[datetime] = None
    changed_at: Optional[datetime] = None
    held: Optional[HeldChange] = None

    @property
    def is_sentinel(self) -> bool:
        return self.status == SENTINEL_STATUS

    def columns(self) -> dict[str, Any]:
        return {
            "name_key": self.name_key,
            "remote_name": self.remote_name,
            "exposed_name": self.exposed_name,
            "status": self.status,
            "review_kind": self.review_kind,
            "trusted_how": self.trusted_how,
            "approved_hash": self.approved_hash,
            "approved_definition": self.approved_definition,
            "approved_hidden_chars": self.approved_hidden_chars,
            "pending_hash": self.pending_hash,
            "pending_definition": self.pending_definition,
            "pending_hidden_chars": self.pending_hidden_chars,
            "change_count": self.change_count,
            "first_seen_at": self.first_seen_at,
            "approved_at": self.approved_at,
            "changed_at": self.changed_at,
            "updated_at": self.updated_at,
        }


# What an update does, for logs and for the store's audit and notify choices.
Transition = Literal[
    "changed",  # approved -> needs_review/changed
    "pending_replaced",  # needs_review: another new definition replaces the waiting one
    "kept_off_changed",  # kept_off: a new definition is recorded, the pin stays off
    "reverted",  # needs_review -> approved: the server went back to the approved definition
    "returned",  # a removed tool is advertised again (removed_at cleared, nothing else)
    "renamed",  # only the exposed name was re-derived (a longer label)
    "removed",  # the server stopped advertising the tool
]


@dataclass(frozen=True)
class PinUpdate:
    """A conditional UPDATE of one row: ``WHERE id = :pin_id AND status =
    :expect_status AND pending_hash IS NOT DISTINCT FROM :expect_pending_hash`` (the
    store may also compare ``updated_at``). A row count of 0 means another worker
    made the transition first: this call then neither audits nor notifies for that
    pin and does not offer the tool this turn."""

    pin_id: uuid.UUID
    name_key: str
    transition: Transition
    expect_status: str
    expect_pending_hash: Optional[str]
    expect_updated_at: datetime
    values: Mapping[str, Any]  # McpToolPin column -> new value (updated_at included)
    bump_change_count: bool = False  # SET change_count = change_count + 1
    held: Optional[HeldChange] = None


@dataclass(frozen=True)
class ReconcilePlan:
    """What one discovery means for one server: which tools may be offered and run,
    and the smallest set of writes that records what changed."""

    entries: tuple[tuple[str, SeenTool], ...]  # (exposed, tool), advertisement order
    offered: frozenset[str]  # name_keys that may be offered and run
    rules: Mapping[str, str]  # name_key -> refusal rule for every other entry
    inserts: tuple[NewPin, ...]
    updates: tuple[PinUpdate, ...]
    first_use: bool  # the server had no rows at all (no pin, no sentinel)
    needs_discovery: bool  # a write was needed but definitions were absent (cache hit)
    deletes: tuple[uuid.UUID, ...] = ()  # pins pruned (180-day retention, or the cap)
    removed_exposed: frozenset[str] = frozenset()  # exposed names held by removed pins
    withheld_over_cap: int = 0  # tools neither pinned nor offered: the server is at the cap

    @property
    def has_writes(self) -> bool:
        return bool(self.inserts or self.updates or self.deletes)

    @property
    def pinned_on_first_use(self) -> int:
        """How many tools this plan trusts on first use (the ``mcp_tool_pinned``
        audit row's count); 0 when it is not a first use."""
        if not self.first_use:
            return 0
        return sum(1 for pin in self.inserts if pin.status == STATUS_APPROVED)

    def offered_entries(self) -> list[tuple[str, SeenTool]]:
        return [(exposed, tool) for exposed, tool in self.entries if tool.name_key in self.offered]

    def resolve(self, exposed_name: str) -> tuple[Optional[SeenTool], Optional[str]]:
        """The dispatcher's lookup of ``mcp.<label>.<exposed_name>``:
        ``(tool, None)`` when it may run, ``(tool, rule)`` when it is held,
        ``(None, "mcp_tool_removed")`` when only a removed pin holds the name, and
        ``(None, None)`` when the server does not advertise it at all."""
        for exposed, tool in self.entries:
            if exposed == exposed_name:
                if tool.name_key in self.offered:
                    return tool, None
                return tool, self.rules.get(tool.name_key, RULE_TOOL_UNREVIEWED)
        if exposed_name in self.removed_exposed:
            return None, RULE_TOOL_REMOVED
        return None, None


def _rule_for_kind(review_kind: Optional[str]) -> str:
    return RULE_DEFINITION_CHANGED if review_kind == REVIEW_CHANGED else RULE_TOOL_UNREVIEWED


def _pending_values(tool: SeenTool, definition: dict[str, Any], now: datetime) -> dict[str, Any]:
    return {
        "pending_hash": tool.definition_hash,
        "pending_definition": definition,
        "pending_hidden_chars": tool.hidden_chars,
        "changed_at": now,
    }


def _sentinel(now: datetime, source: str) -> NewPin:
    return NewPin(
        name_key=SENTINEL_NAME_KEY,
        remote_name="",
        exposed_name="",
        status=SENTINEL_STATUS,
        trusted_how=source,
        first_seen_at=now,
        updated_at=now,
    )


def _utc(moment: datetime) -> datetime:
    # SQLite hands DateTime(timezone=True) columns back without a zone while
    # the service clock is aware; both mean UTC here, and comparing them
    # unnormalised would raise TypeError.
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _oldest_first(pin: PinState) -> tuple[int, datetime, str]:
    # Pins without a removal time sort first: their age is unknown, so they
    # are treated as the oldest.
    if pin.removed_at is None:
        return (0, _utc(pin.updated_at), pin.name_key)
    return (1, _utc(pin.removed_at), pin.name_key)


@dataclass(frozen=True)
class _Step:
    rule: Optional[str]  # None: the tool may be offered
    update: Optional[PinUpdate] = None
    needs_discovery: bool = False


def _plan_existing(
    pin: PinState, exposed: str, tool: SeenTool, now: datetime, *, fresh: bool
) -> _Step:
    """The decision table's row for a seen tool that already has a pin. On a
    cached listing (*fresh* False) nothing that depends on what the server
    advertises is written: see ``plan_reconcile``."""
    values: dict[str, Any] = {}
    transition: Optional[Transition] = None
    bump = False
    held: Optional[HeldChange] = None
    rule: Optional[str] = None
    needs_definition = False

    if pin.status == STATUS_APPROVED:
        if tool.definition_hash != pin.approved_hash:
            rule = RULE_DEFINITION_CHANGED
            needs_definition = True
            if tool.definition is not None:
                values.update(_pending_values(tool, tool.definition, now))
                values.update(status=STATUS_NEEDS_REVIEW, review_kind=REVIEW_CHANGED)
                transition, bump = "changed", True
                held = HeldChange(
                    REVIEW_CHANGED, tool.definition_hash, pin.approved_hash, notify=True
                )
    elif pin.status == STATUS_NEEDS_REVIEW:
        if pin.approved_hash is not None and tool.definition_hash == pin.approved_hash:
            # The server went back to what the owner approved: nothing left to
            # review. A later change to the same definition is told again.
            values.update(
                status=STATUS_APPROVED,
                review_kind=None,
                pending_hash=None,
                pending_definition=None,
                pending_hidden_chars=0,
                notified_hash=None,
            )
            transition = "reverted"
        elif tool.definition_hash == pin.pending_hash:
            rule = _rule_for_kind(pin.review_kind)
        else:
            kind = pin.review_kind or (
                REVIEW_CHANGED if pin.approved_hash is not None else REVIEW_NEW
            )
            rule = _rule_for_kind(kind)
            needs_definition = True
            if tool.definition is not None:
                values.update(_pending_values(tool, tool.definition, now))
                values["review_kind"] = kind
                transition, bump = "pending_replaced", True
                held = HeldChange(kind, tool.definition_hash, pin.approved_hash, notify=True)
    elif pin.status == STATUS_KEPT_OFF:
        rule = RULE_TOOL_KEPT_OFF
        if tool.definition_hash not in (pin.approved_hash, pin.pending_hash):
            needs_definition = True
            if tool.definition is not None:
                kind = REVIEW_CHANGED if pin.approved_hash is not None else REVIEW_NEW
                values.update(_pending_values(tool, tool.definition, now))
                values["review_kind"] = kind
                transition, bump = "kept_off_changed", True
                # Recorded and audited, never messaged: the owner chose to keep
                # this tool off.
                held = HeldChange(kind, tool.definition_hash, pin.approved_hash, notify=False)
    else:
        # A status this code does not know: hold the tool, write nothing new.
        rule = RULE_TOOL_UNREVIEWED

    if needs_definition and (tool.definition is None or not fresh):
        # A cache hit cannot record a new definition: write nothing for this
        # tool (not even removed_at) and ask for a fresh listing.
        return _Step(rule, needs_discovery=True)
    if not fresh and (transition is not None or pin.removed):
        # The cached list can be older than this row: another worker's fresh
        # tools/list may have held a change or marked the tool removed after
        # it was taken. Taking a hold off ("reverted") or clearing removed_at
        # ("returned") from it would undo that newer fact, and the call check
        # reads only the row. Hold the tool and ask for a fresh listing, which
        # makes either transition if it is still true.
        return _Step(
            rule
            if rule is not None
            else (RULE_TOOL_REMOVED if pin.removed else _rule_for_kind(pin.review_kind)),
            needs_discovery=True,
        )
    if pin.removed:
        values["removed_at"] = None
        transition = transition or "returned"
    if pin.exposed_name != exposed:
        values["exposed_name"] = exposed
        transition = transition or "renamed"
    if not values or transition is None:
        return _Step(rule)
    values["updated_at"] = now
    return _Step(
        rule,
        PinUpdate(
            pin_id=pin.id,
            name_key=pin.name_key,
            transition=transition,
            expect_status=pin.status,
            expect_pending_hash=pin.pending_hash,
            expect_updated_at=pin.updated_at,
            values=values,
            bump_change_count=bump,
            held=held,
        ),
    )


def plan_reconcile(
    label: str,
    pins: Sequence[PinState],
    seen: Sequence[SeenTool],
    *,
    now: datetime,
    source: TrustSource,
    max_pins: int = MAX_PINS_PER_SERVER,
    retention: timedelta = REMOVED_PIN_RETENTION,
    fresh: Optional[bool] = None,
) -> ReconcilePlan:
    """What one discovery means for one server: which tools may be offered, and the
    smallest set of writes that records what changed. Financial tools never reach
    here (the caller drops them first).

    *fresh* says whether *seen* is a tools/list made for this call (True) or the
    catalog's cached list (False). Left as None, a list counts as fresh when every
    tool carries its definition, so an empty list counts as fresh: a catalog
    cache hit must pass ``fresh=False`` so that an empty cached list is not
    taken for a fresh one. A tool without a definition always makes the list
    cached, whatever *fresh* says.

    Decision table, for each seen tool T and its pin P (by name_key):

    - no P, server has no rows at all: trust on first use (insert ``approved``,
      ``trusted_how=source``) plus the server sentinel, once; offered.
    - no P, server already has rows: insert ``needs_review``/``new``; held.
    - ``approved``, same hash: offered (writes only to clear ``removed_at`` or a
      re-derived exposed name). Another hash: ``needs_review``/``changed``; held.
    - ``needs_review``: the approved hash again -> back to ``approved``, offered;
      the pending hash -> no write, held; another hash -> pending replaced, held.
    - ``kept_off``: the approved or pending hash -> no write; another hash ->
      pending replaced; held either way.

    Every pin not seen and not yet removed gets ``removed_at=now``. When a write
    for T needs its definition and T came from the cache (no definition), nothing
    is written for T, T is not offered and ``needs_discovery`` is set.

    A cached list only reads. It may be up to the cache TTL older than the rows
    (the dispatcher's fresh tools/list, the owner's Test or another worker may
    have written since), so it never writes anything that depends on what the
    server advertises: no first-use pins or sentinel, no new or changed
    definition, no revert, no ``removed_at`` set or cleared. A tool whose row
    such a write would change is held and ``needs_discovery`` is set; a pin
    missing from the cached list is left as it is. Only a re-derived exposed
    name (it follows the label, not the listing) is written from a cache hit.
    """
    if source not in TRUST_SOURCES:
        raise ValueError(f"unknown trust source {source!r}")

    tool_pins = [pin for pin in pins if not pin.is_sentinel]
    by_key: dict[str, PinState] = {}
    for pin in tool_pins:
        by_key.setdefault(pin.name_key, pin)
    first_use = not pins

    usable = [tool for tool in seen if tool.name_key != SENTINEL_NAME_KEY]
    is_fresh = (fresh is not False) and all(tool.definition is not None for tool in usable)
    seen_keys = {tool.name_key for tool in usable}
    pinned_names = {pin.name_key: pin.exposed_name for pin in tool_pins}
    named = _assign_names(
        label, [(tool.remote_name, tool.name_key, tool) for tool in usable], pinned_names
    )
    entries = tuple(named)
    gone = [pin for pin in tool_pins if pin.name_key not in seen_keys]
    # A fresh listing marks every missing pin removed below; a cached one
    # marks nothing, so only pins already removed hold their names as removed.
    removed_exposed = frozenset(
        pin.exposed_name for pin in gone if pin.exposed_name and (is_fresh or pin.removed)
    )

    offered: set[str] = set()
    rules: dict[str, str] = {}
    inserts: list[NewPin] = []
    updates: list[PinUpdate] = []
    needs_discovery = False

    if first_use:
        if not is_fresh:
            # A cache hit cannot be trusted on first use (there is nothing to
            # store), and a sentinel alone would hold every tool as new on
            # the next fresh discovery. Write nothing and ask for one. An
            # empty cached list too: it may predate the server's tools.
            for _, tool in named:
                rules[tool.name_key] = RULE_PIN_UNAVAILABLE
            return ReconcilePlan(
                entries=entries,
                offered=frozenset(),
                rules=rules,
                inserts=(),
                updates=(),
                first_use=True,
                needs_discovery=True,
            )
        inserts.append(_sentinel(now, source))
        withheld = 0
        for exposed, tool in named:
            if len(inserts) - 1 >= max_pins:
                withheld += 1
                rules[tool.name_key] = RULE_TOOL_UNREVIEWED
                continue
            definition = cast(dict[str, Any], tool.definition)
            inserts.append(
                NewPin(
                    name_key=tool.name_key,
                    remote_name=display_remote_name(tool.remote_name),
                    exposed_name=exposed,
                    status=STATUS_APPROVED,
                    trusted_how=source,
                    approved_hash=tool.definition_hash,
                    approved_definition=definition,
                    approved_hidden_chars=tool.hidden_chars,
                    first_seen_at=now,
                    approved_at=now,
                    updated_at=now,
                )
            )
            offered.add(tool.name_key)
        if withheld:
            logger.warning("mcp_pin_cap_reached", server=label, withheld=withheld)
        return ReconcilePlan(
            entries=entries,
            offered=frozenset(offered),
            rules=rules,
            inserts=tuple(inserts),
            updates=(),
            first_use=True,
            needs_discovery=False,
            withheld_over_cap=withheld,
        )

    new_tools: list[tuple[str, SeenTool]] = []
    unpinned_in_cache = 0
    for exposed, tool in named:
        existing = by_key.get(tool.name_key)
        if existing is None:
            rules[tool.name_key] = RULE_TOOL_UNREVIEWED
            if not is_fresh:
                unpinned_in_cache += 1
            else:
                new_tools.append((exposed, tool))
            continue
        step = _plan_existing(existing, exposed, tool, now, fresh=is_fresh)
        if step.rule is None:
            offered.add(tool.name_key)
        else:
            rules[tool.name_key] = step.rule
        if step.update is not None:
            updates.append(step.update)
        needs_discovery = needs_discovery or step.needs_discovery

    if unpinned_in_cache:
        # A cached tool with no pin needs a fresh listing to be recorded, but
        # only when that listing could record it: the server is under the cap,
        # or a removed pin could be pruned to make room. A server sitting at
        # the cap would otherwise ask for a fresh tools/list (and a hash of
        # every definition) on every chat build, which defeats the cache and
        # hands the server control of that load; its extra tools stay withheld.
        room = max_pins - len(tool_pins) + sum(1 for pin in gone if pin.removed)
        needs_discovery = needs_discovery or room > 0

    # "Not seen this discovery" means not in a fresh tools/list. A cached list
    # can predate a tool another listing just recorded (a new tool held for
    # review, or one the owner just approved), and marking that removed would
    # refuse it with the wrong rule and flip removed_at until the cache expires.
    for pin in gone if is_fresh else ():
        if not pin.removed:
            updates.append(
                PinUpdate(
                    pin_id=pin.id,
                    name_key=pin.name_key,
                    transition="removed",
                    expect_status=pin.status,
                    expect_pending_hash=pin.pending_hash,
                    expect_updated_at=pin.updated_at,
                    values={"removed_at": now, "updated_at": now},
                )
            )

    # The cap: room is made by pruning the oldest removed pins first; a new
    # tool that still does not fit is neither pinned nor offered.
    deletes: list[uuid.UUID] = []
    withheld = 0
    room = max_pins - len(tool_pins)
    if len(new_tools) > room:
        prunable = sorted((pin for pin in gone if pin.removed), key=_oldest_first)
        for pin in prunable[: len(new_tools) - room]:
            deletes.append(pin.id)
        room += len(deletes)
        withheld = max(0, len(new_tools) - room)
        new_tools = new_tools[: max(room, 0)]
        if withheld:
            logger.warning("mcp_pin_cap_reached", server=label, withheld=withheld)

    for exposed, tool in new_tools:
        definition = cast(dict[str, Any], tool.definition)
        inserts.append(
            NewPin(
                name_key=tool.name_key,
                remote_name=display_remote_name(tool.remote_name),
                exposed_name=exposed,
                status=STATUS_NEEDS_REVIEW,
                review_kind=REVIEW_NEW,
                pending_hash=tool.definition_hash,
                pending_definition=definition,
                pending_hidden_chars=tool.hidden_chars,
                change_count=1,
                first_seen_at=now,
                changed_at=now,
                updated_at=now,
                held=HeldChange(REVIEW_NEW, tool.definition_hash, None, notify=True),
            )
        )

    # Retention: removed pins older than 180 days go, but only inside a write
    # that happens anyway (the hot read path never writes just to prune).
    if inserts or updates or deletes:
        pruned = set(deletes)
        for pin in gone:
            if (
                pin.removed
                and pin.removed_at is not None
                and _utc(now) - _utc(pin.removed_at) > retention
                and pin.id not in pruned
            ):
                deletes.append(pin.id)
                pruned.add(pin.id)

    return ReconcilePlan(
        entries=entries,
        offered=frozenset(offered),
        rules=rules,
        inserts=tuple(inserts),
        updates=tuple(updates),
        first_use=False,
        needs_discovery=needs_discovery,
        deletes=tuple(deletes),
        removed_exposed=removed_exposed,
        withheld_over_cap=withheld,
    )


# ---------------------------------------------------------------------------
# One call: may mcp.<label>.<tool> be carded or run?
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PinDecision:
    """The pure answer behind ``McpPinService.check_call``."""

    allowed: bool
    rule: str = ""
    hidden_chars: int = 0  # of the approved definition, for the card's security note


def _decide_one(exposed_name: str, pins: Sequence[PinState]) -> PinDecision:
    if not pins:
        # Never seen: the dispatcher trusts it on first use with a fresh
        # tools/list, so the call check lets it reach the card.
        return PinDecision(True)
    holders = sorted(
        (pin for pin in pins if not pin.is_sentinel and pin.exposed_name == exposed_name),
        key=lambda pin: pin.name_key,
    )
    current = [pin for pin in holders if not pin.removed]
    if not current:
        return PinDecision(False, RULE_TOOL_REMOVED if holders else RULE_TOOL_UNREVIEWED)
    for pin in current:
        if pin.status == STATUS_APPROVED:
            continue
        if pin.status == STATUS_NEEDS_REVIEW:
            return PinDecision(False, _rule_for_kind(pin.review_kind))
        if pin.status == STATUS_KEPT_OFF:
            return PinDecision(False, RULE_TOOL_KEPT_OFF)
        return PinDecision(False, RULE_TOOL_UNREVIEWED)
    return PinDecision(True, hidden_chars=max(pin.approved_hidden_chars for pin in current))


def decide_call(exposed_name: str, servers: Sequence[Sequence[PinState]]) -> PinDecision:
    """Whether ``mcp.<label>.<exposed_name>`` may be carded or run, given the pins of
    every active MCP connector with that label (one sequence per connector).

    Allowed when there is no such connector, when every connector has the name
    approved, or when a connector has no rows at all yet. Refused when any
    connector holds it (two servers with one label: refuse if either holds it,
    which never loosens anything): ``mcp_definition_changed`` /
    ``mcp_tool_unreviewed`` by review kind, ``mcp_tool_kept_off``,
    ``mcp_tool_removed`` when only a removed pin holds the name, and
    ``mcp_tool_unreviewed`` for a name no pin holds on a pinned server."""
    hidden = 0
    for pins in servers:
        decision = _decide_one(exposed_name, pins)
        if not decision.allowed:
            return decision
        hidden = max(hidden, decision.hidden_chars)
    return PinDecision(True, hidden_chars=hidden)


def refusal_message(rule: str, *, tool: str, label: str) -> str:
    """The sentence the model and the owner read for a refusal, built from the
    label slug and the exposed name only (never anything the server wrote)."""
    if rule == RULE_DEFINITION_CHANGED:
        return (
            f"The MCP tool '{tool}' on '{label}' changed its description or inputs since it "
            "was approved, so Crawler did not run it. Review the change on the Security page "
            "(MCP reviews)."
        )
    if rule == RULE_TOOL_UNREVIEWED:
        return (
            f"The MCP tool '{tool}' on '{label}' is new on that server and has not been "
            "reviewed, so Crawler did not run it. Review it on the Security page (MCP reviews)."
        )
    if rule == RULE_TOOL_KEPT_OFF:
        return (
            f"You chose to keep the MCP tool '{tool}' on '{label}' off. Turn it back on from "
            "the Security page (MCP reviews)."
        )
    if rule == RULE_TOOL_REMOVED:
        return f"MCP server '{label}' no longer advertises the tool approved as '{tool}'."
    # mcp_pin_unavailable, and anything unexpected: fail closed with the
    # "try again" sentence.
    return (
        f"Crawler could not check the MCP tool '{tool}' against what was approved, so it "
        "did not run it. Try again in a moment."
    )


def refusal_result(rule: str, *, tool: str, label: str) -> dict[str, Any]:
    """The dispatcher's and the executor backstop's refusal dict (scaffold A22 shape),
    recognised by ``call_checks.call_check_refusal``."""
    return {
        "ok": False,
        "refused": True,
        "call_check": PIN_POLICY,
        "policy": PIN_POLICY,
        "rule": rule,
        "error": refusal_message(rule, tool=tool, label=label),
    }


# ---------------------------------------------------------------------------
# The owner's review: the detail, the list order, approve and keep off
# ---------------------------------------------------------------------------
#
# Each takes a pin row (models.mcp_tool_pin.McpToolPin) or anything with its
# column names, and only reads it: the routes and pin_store apply the values.

_UNSHOWABLE_CHANGE = (
    "The difference is in characters that cannot be shown as written (a NUL or a broken "
    "character). Its fingerprint still changed."
)
_TOO_LARGE_CHANGE = (
    "Both versions are too large to show line by line, and they are the same size "
    "({size} bytes), so the difference cannot be shown. Its fingerprint still changed."
)
_FAR_DOWN_CHANGE = (
    "The difference is past the first {lines} lines of the definition, too far down to "
    "show. Its fingerprint still changed."
)


def _unshown_change(
    old: Optional[Mapping[str, Any]], new: Mapping[str, Any], truncated: bool
) -> ReviewLine:
    """The one hunk line for a change the line diff cannot show, naming the real
    reason: both versions too large (their markers read alike when the sizes
    match), the difference past the diff's input cap, or text that only differs
    in characters the stored copy cannot hold."""
    if is_too_large(new) or is_too_large(old):
        marker = new if is_too_large(new) else (old or {})
        text = _TOO_LARGE_CHANGE.format(size=marker.get("bytes"))
    elif truncated:
        text = _FAR_DOWN_CHANGE.format(lines=MAX_DIFF_INPUT_LINES)
    else:
        text = _UNSHOWABLE_CHANGE
    return ReviewLine("hunk", (TextPart(text),))


@dataclass(frozen=True)
class ReviewDetail:
    """What the review card shows for one pin (the route's ``McpToolReviewDetail``
    minus the pin view and the server name)."""

    definition_hash: str  # the hash Approve must send back
    previous_hash: Optional[str]  # the approved hash a waiting definition differs from
    hidden_characters: int
    looks_like_instructions: bool
    too_large: bool
    lines: tuple[ReviewLine, ...]
    truncated: bool

    def flags(self) -> dict[str, Any]:
        return {
            "hidden_characters": self.hidden_characters,
            "looks_like_instructions": self.looks_like_instructions,
            "too_large": self.too_large,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "definition_hash": self.definition_hash,
            "previous_hash": self.previous_hash,
            "flags": self.flags(),
            "lines": [line.to_dict() for line in self.lines],
            "truncated": self.truncated,
        }


def is_waiting(pin: Any) -> bool:
    """A pin the owner can approve from the review: ``needs_review``, or ``kept_off``
    (its waiting or approved definition is what "Turn back on" approves)."""
    return pin.status == STATUS_NEEDS_REVIEW or (
        pin.status == STATUS_KEPT_OFF
        and (pin.pending_hash is not None or pin.approved_hash is not None)
    )


def shown_hash(pin: Any) -> Optional[str]:
    """The hash the review shows and Approve must send: the waiting definition's
    when there is one, else the approved one."""
    return pin.pending_hash if pin.pending_hash is not None else pin.approved_hash


def review_detail(pin: Any) -> ReviewDetail:
    """The review of one pin: for a waiting change, the diff from the approved to the
    waiting definition; for a waiting new tool, every line added; with nothing
    waiting, every line of the approved definition as context. ``flags`` describe
    the version ``definition_hash`` names."""
    waiting = pin.pending_hash is not None
    shown: Mapping[str, Any]
    if waiting:
        shown = pin.pending_definition or {}
        hidden = int(pin.pending_hidden_chars or 0)
        previous = pin.approved_hash
        if pin.approved_hash is not None and pin.approved_definition is not None:
            lines, truncated = review_diff(pin.approved_definition, shown)
            if not lines and pin.approved_hash != pin.pending_hash:
                # The hashes differ but the line diff is empty: two raw
                # definitions can store alike (NUL and U+2400 both store as
                # U+2400), two too-large markers of one size read alike, or
                # the difference lies past the diff's input cap. Say which,
                # rather than show an empty change.
                lines = [_unshown_change(pin.approved_definition, shown, truncated)]
        else:
            lines, truncated = review_listing(shown, op="added")
    else:
        shown = pin.approved_definition or {}
        hidden = int(pin.approved_hidden_chars or 0)
        previous = None
        lines, truncated = review_listing(shown, op="context")
    too_large = is_too_large(shown)
    return ReviewDetail(
        definition_hash=str(shown_hash(pin) or ""),
        previous_hash=previous,
        hidden_characters=hidden,
        looks_like_instructions=(not too_large) and looks_like_instructions(shown),
        too_large=too_large,
        lines=tuple(lines),
        truncated=truncated,
    )


def _review_rank(pin: Any) -> tuple[Any, ...]:
    removed = getattr(pin, "removed_at", None) is not None
    name = str(pin.exposed_name or "")
    if removed:
        return (3, name)
    if pin.status == STATUS_NEEDS_REVIEW:
        changed = getattr(pin, "changed_at", None)
        # Newest change first; a missing time sorts last within the group.
        stamp = -_utc(changed).timestamp() if changed is not None else float("inf")
        return (0, stamp, name)
    if pin.status == STATUS_KEPT_OFF:
        return (1, name)
    return (2, name)


def sort_for_review(pins: Sequence[_ItemT]) -> list[_ItemT]:
    """The Security tab's order: waiting tools (newest change first), then kept off,
    then approved by name, removed ones last. The sentinel is left out."""
    return sorted(
        (pin for pin in pins if getattr(pin, "status", None) != SENTINEL_STATUS),
        key=_review_rank,
    )


ApprovalOutcome = Literal["approve", "unchanged", "stale"]


@dataclass(frozen=True)
class ApprovalDecision:
    """What an Approve with *definition_hash* does to one pin: ``approve`` (apply
    ``values``), ``unchanged`` (already approved with that hash: 200, no write) or
    ``stale`` (the hash shown is no longer current: 409)."""

    outcome: ApprovalOutcome
    values: Mapping[str, Any]
    previous_hash: Optional[str] = None  # for the mcp_tool_review_approved audit row
    review_kind: Optional[str] = None


def decide_approval(pin: Any, definition_hash: str, *, now: datetime) -> ApprovalDecision:
    """The single and the server-wide Approve, for one pin. Nothing is ever
    approved unless *definition_hash* is exactly the version the owner was shown."""
    if pin.status == SENTINEL_STATUS:
        return ApprovalDecision("stale", {})
    if pin.pending_hash is not None:
        if definition_hash != pin.pending_hash:
            return ApprovalDecision("stale", {})
        return ApprovalDecision(
            "approve",
            {
                "status": STATUS_APPROVED,
                "trusted_how": TRUSTED_OWNER_REVIEW,
                "approved_hash": pin.pending_hash,
                "approved_definition": pin.pending_definition,
                "approved_hidden_chars": int(pin.pending_hidden_chars or 0),
                "pending_hash": None,
                "pending_definition": None,
                "pending_hidden_chars": 0,
                "review_kind": None,
                "notified_hash": None,
                "approved_at": now,
                "updated_at": now,
            },
            previous_hash=pin.approved_hash,
            review_kind=pin.review_kind,
        )
    if pin.status == STATUS_KEPT_OFF:
        if pin.approved_hash is None or definition_hash != pin.approved_hash:
            return ApprovalDecision("stale", {})
        return ApprovalDecision(
            "approve",
            {
                "status": STATUS_APPROVED,
                "trusted_how": TRUSTED_OWNER_REVIEW,
                "approved_at": now,
                "updated_at": now,
            },
            previous_hash=pin.approved_hash,
        )
    if pin.status == STATUS_APPROVED and definition_hash == pin.approved_hash:
        return ApprovalDecision("unchanged", {})
    return ApprovalDecision("stale", {})


def keep_off_values(pin: Any, *, now: datetime) -> Optional[dict[str, Any]]:
    """The columns "Keep it off" sets (any status -> ``kept_off``, the waiting
    definition kept for display); None when it is already off (idempotent)."""
    if pin.status == STATUS_KEPT_OFF or pin.status == SENTINEL_STATUS:
        return None
    return {"status": STATUS_KEPT_OFF, "updated_at": now}


# ---------------------------------------------------------------------------
# Server moves (credential edits)
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443}
# "scheme://user:password@" at the start of a URL that urlsplit cannot take
# apart. Anchored, and each part is one character class, so it runs in linear
# time on any input.
_LEADING_USERINFO = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/?#]*@")


def normalized_server_url(url: str) -> str:
    """The form two MCP server URLs are compared in when the owner edits a
    connector's credentials: scheme and host lower-cased, a default port dropped,
    trailing "/" stripped from the path, query and fragment kept, and any
    userinfo ("user:password@") dropped. A password rotated inside the URL is a
    credential change like a header-only one: the pins stay, which is the safe
    direction (S5 4.9). Resetting them would drop every tool held for review and
    let the next Test trust them all on first use again. Dropping the userinfo
    also keeps a password out of this string. A URL that does not parse is
    compared as written (stripped, userinfo dropped)."""
    text = str(url or "").strip()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return _LEADING_USERINFO.sub(r"\1", text)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path.rstrip("/"), parts.query, parts.fragment))


def same_server(old_url: str, new_url: str) -> bool:
    """Whether a credential edit still points at the same MCP server (pins kept) or
    at another one (pins reset, its tools trusted on first use again)."""
    return normalized_server_url(old_url) == normalized_server_url(new_url)
