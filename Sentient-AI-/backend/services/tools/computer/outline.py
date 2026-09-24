"""Turns a backend's accessibility tree into the browser-style outline lines the
model reads (``- button "Send" [ref=d12]``), numbering refs, redacting secure
fields, dropping hidden and off-screen elements, and capping depth and size.

Why it exists: The model acts on refs rather than pixels, so the outline is the
agent's whole view of an app. Building it in one pure function keeps the format
identical to the browser outline, guarantees a password value can never be
written out, and makes the caps testable without a desktop.

Line format::

    <two spaces per level>- <role> ["<name>"] [ref=dN] [focused] [disabled] [value="<v>" | value=[redacted]]

Names and values are single-line, control and format characters removed,
truncated with an ellipsis, and quoted with backslash escapes, so text from
an app can never forge a line or a ref. Unnamed structural containers (a
nameless "group") are skipped and their children lifted a level.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from services.tools.computer import rules
from services.tools.computer.backend import Node

DEFAULT_MAX_CHARS = 6000
MAX_CHARS_LIMIT = 12000
MIN_MAX_CHARS = 200
# Raw tree depth (nameless groups count too, though they add no indent).
MAX_DEPTH = 60
MAX_LINES = 600
MAX_VISITED = 20000
MAX_NAME_CHARS = 100
MAX_VALUE_CHARS = 200
MAX_ROLE_CHARS = 40

_STRUCTURAL = frozenset(
    {
        "",
        "group",
        "scroll area",
        "split group",
        "layout area",
        "layout item",
        "unknown",
        "pane",
        "custom",
        "generic",
        "section",
        "none",
    }
)
_WS = re.compile(r"\s+")


@dataclass(frozen=True)
class Outline:
    lines: tuple[str, ...]
    refs: Mapping[str, Node]
    truncated: bool
    secure_fields_redacted: int
    # The number the next outline for this user starts at.
    next_ref: int


def _is_break(ch: str) -> bool:
    return ch in "\r\n\t\v\f" or unicodedata.category(ch) in ("Zl", "Zp")


def clean_text(text: object, limit: int) -> str:
    """One line of plain text: whitespace collapsed, control/format
    characters dropped, at most *limit* characters (ellipsis included)."""
    if text is None:
        return ""
    raw = text if isinstance(text, str) else str(text)
    spaced = "".join(" " if _is_break(ch) else ch for ch in raw)
    kept = "".join(ch for ch in spaced if not unicodedata.category(ch).startswith("C"))
    single = _WS.sub(" ", kept).strip()
    if len(single) > limit:
        single = single[: max(limit - 1, 0)].rstrip() + "…"
    return single


def quote(text: object, limit: int) -> str:
    """*text* cleaned and wrapped in double quotes, with backslash escapes."""
    cleaned = clean_text(text, limit)
    return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _role(node: Node) -> str:
    role = clean_text(node.role, MAX_ROLE_CHARS).lower()
    role = "".join(ch for ch in role if ch not in '"[]')
    return role.strip()


def _line(
    indent: int, role: str, name: str, ref: str, node: Node, secure: bool, value: Optional[str]
) -> str:
    parts = ["  " * indent + "- " + (role or "element")]
    if name:
        parts.append(quote(name, MAX_NAME_CHARS))
    parts.append(f"[ref={ref}]")
    if node.focused:
        parts.append("[focused]")
    if not node.enabled:
        parts.append("[disabled]")
    if secure:
        parts.append("value=[redacted]")
    elif value:
        parts.append("value=" + quote(value, MAX_VALUE_CHARS))
    return " ".join(parts)


def build_outline(
    roots: Sequence[Node],
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_lines: int = MAX_LINES,
    max_depth: int = MAX_DEPTH,
    ref_start: int = 1,
    include_hidden: bool = False,
) -> Outline:
    """Outline *roots* (depth first, in order) within the caps.

    Every emitted line gets the next ref, ``d<ref_start>`` onwards. Hidden
    and off-screen elements are dropped with everything under them unless
    *include_hidden* (used for the payment scan, which must see a card
    field scrolled out of view). Hitting a cap stops the walk and sets
    ``truncated``.
    """
    lines: list[str] = []
    refs: dict[str, Node] = {}
    used = 0
    truncated = False
    redacted = 0
    next_ref = ref_start
    visited = 0
    stack: list[tuple[Node, int, int]] = [(node, 0, 0) for node in reversed(list(roots))]
    while stack:
        node, indent, depth = stack.pop()
        visited += 1
        if visited > MAX_VISITED:
            truncated = True
            break
        if not include_hidden and (node.hidden or node.offscreen):
            continue
        if depth >= max_depth:
            truncated = True
            continue
        role = _role(node)
        name = clean_text(node.name, MAX_NAME_CHARS)
        secure = rules.looks_secure(node)
        value = None if secure else clean_text(node.value, MAX_VALUE_CHARS) or None
        if role == "text" and not name and value:
            name, value = clean_text(value, MAX_NAME_CHARS), None
        skip = (
            role in _STRUCTURAL and not name and not value and not secure and not node.focused
        ) or (role == "text" and not name)
        child_indent = indent
        if not skip:
            ref = f"d{next_ref}"
            line = _line(indent, role, name, ref, node, secure, value)
            cost = len(line) + 1
            if len(lines) >= max_lines or used + cost > max_chars:
                truncated = True
                break
            lines.append(line)
            used += cost
            refs[ref] = node
            next_ref += 1
            if secure:
                redacted += 1
            child_indent = indent + 1
        for child in reversed(tuple(node.children or ())):
            stack.append((child, child_indent, depth + 1))
    return Outline(tuple(lines), refs, truncated, redacted, next_ref)
