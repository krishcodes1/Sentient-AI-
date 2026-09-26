"""Renders Notion blocks as Markdown and parses Markdown into Notion blocks.

Why it exists: the model reads and writes plain Markdown, while the Notion API
speaks block objects with rich-text arrays. This module is the translation in
both directions, and it enforces Notion's request limits on the way in: at
most 2000 characters per rich-text object, 100 rich-text objects per array,
100 children per request and one level of nesting per list item. Files are
never downloaded: file blocks render as their name and type only.

It connects to the sibling action modules ``reads.py`` (get_page,
get_block_children), ``writes.py`` (create_page, append_blocks, update_block,
add_comment), ``common.py`` (rich-text building, block-tree loading) and
``properties.py``. It talks to no external service and depends only on
``services.connectors.base`` (ConnectorError) and the standard library.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from typing import Any, Iterable, Optional
from urllib.parse import unquote, urlparse

from services.connectors.base import ConnectorError

#: Notion's limit on one rich-text object's content (UTF-16 code units).
RICH_TEXT_MAX_CHARS = 2000
#: Notion's limit on the elements of any array (rich text, children).
ARRAY_MAX_ITEMS = 100
#: Children one append (or page create) request may carry.
CHILDREN_PER_REQUEST = 100
#: Blocks, nested ones included, one request may carry.
BLOCKS_PER_REQUEST = 1000
#: Longest Markdown accepted in one write call.
MAX_MARKDOWN_CHARS = 100_000
#: Most blocks (nested ones included) one write call may create.
MAX_WRITE_BLOCKS = 500
#: Longest link Notion accepts in a rich-text object.
_MAX_LINK_CHARS = 2000
#: Nesting of inline formatting the parser follows before treating the rest
#: as plain text (bounds recursion on hostile input).
_MAX_INLINE_DEPTH = 4

LIST_TYPES = frozenset({"bulleted_list_item", "numbered_list_item", "to_do"})
#: Blocks whose rich text update_block may replace.
TEXT_BLOCK_TYPES = frozenset(
    {
        "paragraph",
        "heading_1",
        "heading_2",
        "heading_3",
        "bulleted_list_item",
        "numbered_list_item",
        "to_do",
        "toggle",
        "quote",
        "callout",
        "code",
    }
)
#: Blocks whose children are separate pages; never descended into.
NO_DESCEND_TYPES = frozenset({"child_page", "child_database"})
_CONTAINER_TYPES = frozenset({"column_list", "column", "synced_block"})
_FILE_TYPES = frozenset({"image", "video", "audio", "file", "pdf"})
_LINK_TYPES = frozenset({"bookmark", "embed", "link_preview"})
_SILENT_TYPES = frozenset({"table_of_contents", "breadcrumb"})

# Languages the Notion API accepts for code blocks (2022-06-28), plus the
# aliases people type after a Markdown fence.
_CODE_LANGUAGES = frozenset(
    {
        "abap", "arduino", "bash", "basic", "c", "clojure", "coffeescript", "c++",
        "c#", "css", "dart", "diff", "docker", "elixir", "elm", "erlang", "flow",
        "fortran", "f#", "gherkin", "glsl", "go", "graphql", "groovy", "haskell",
        "html", "java", "javascript", "json", "julia", "kotlin", "latex", "less",
        "lisp", "livescript", "lua", "makefile", "markdown", "markup", "matlab",
        "mermaid", "nix", "objective-c", "ocaml", "pascal", "perl", "php",
        "plain text", "powershell", "prolog", "protobuf", "python", "r", "reason",
        "ruby", "rust", "sass", "scala", "scheme", "scss", "shell", "sql", "swift",
        "typescript", "vb.net", "verilog", "vhdl", "visual basic", "webassembly",
        "xml", "yaml", "java/c/c++/c#",
    }
)
_LANGUAGE_ALIASES = {
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "py": "python",
    "sh": "shell",
    "zsh": "shell",
    "console": "shell",
    "ps1": "powershell",
    "yml": "yaml",
    "md": "markdown",
    "rb": "ruby",
    "rs": "rust",
    "kt": "kotlin",
    "cpp": "c++",
    "cs": "c#",
    "csharp": "c#",
    "dockerfile": "docker",
    "text": "plain text",
    "txt": "plain text",
    "plaintext": "plain text",
}


# ---------------------------------------------------------------------------
# Rendering: Notion -> Markdown
# ---------------------------------------------------------------------------


def rich_text_plain(items: Any) -> str:
    """The plain text of a rich-text array (no formatting)."""
    if not isinstance(items, list):
        return ""
    parts: list[str] = []
    for item in items:
        text = _item_text(item)
        if text:
            parts.append(text)
    return "".join(parts)


def _item_text(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    text = item.get("plain_text")
    if isinstance(text, str):
        return text
    inner = item.get("text")
    if isinstance(inner, dict) and isinstance(inner.get("content"), str):
        return str(inner["content"])
    equation = item.get("equation")
    if isinstance(equation, dict) and isinstance(equation.get("expression"), str):
        return str(equation["expression"])
    return ""


def _safe_href(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.startswith(("https://", "http://")) and len(value) <= _MAX_LINK_CHARS:
        if not any(ch.isspace() or ch in "()" for ch in value):
            return value
    return None


def _decorate(text: str, annotations: dict[str, Any], href: Optional[str]) -> str:
    """*text* wrapped in the Markdown for its annotations and link.

    Markers hug the non-blank core (``**bold** `` not ``**bold **``), and a
    multi-line run is decorated line by line so each line parses back.
    """
    if "\n" in text:
        return "\n".join(_decorate(part, annotations, href) for part in text.split("\n"))
    core = text.strip()
    if not core:
        return text
    lead = text[: len(text) - len(text.lstrip())]
    trail = text[len(text.rstrip()) :]
    if annotations.get("code") is True and "`" not in core:
        core = f"`{core}`"
    if annotations.get("italic") is True:
        core = f"_{core}_"
    if annotations.get("bold") is True:
        core = f"**{core}**"
    if annotations.get("strikethrough") is True:
        core = f"~~{core}~~"
    if href:
        core = f"[{core}]({href})"
    return lead + core + trail


def rich_text_to_markdown(items: Any) -> str:
    """A rich-text array as inline Markdown (bold, italic, code, strike, links)."""
    if not isinstance(items, list):
        return ""
    parts: list[str] = []
    for item in items:
        text = _item_text(item)
        if not text or not isinstance(item, dict):
            continue
        if item.get("type") == "equation":
            parts.append(f"${text}$")
            continue
        annotations = item.get("annotations")
        href = _safe_href(item.get("href"))
        if href is None:
            inner = item.get("text")
            link = inner.get("link") if isinstance(inner, dict) else None
            href = _safe_href(link.get("url")) if isinstance(link, dict) else None
        parts.append(_decorate(text, annotations if isinstance(annotations, dict) else {}, href))
    return "".join(parts)


def _file_label(data: dict[str, Any]) -> str:
    """A file block's name: its name, caption or URL file name, never the URL."""
    name = data.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()[:200]
    caption = rich_text_plain(data.get("caption")).strip()
    if caption:
        return caption[:200]
    for key in ("file", "external"):
        source = data.get(key)
        link = source.get("url") if isinstance(source, dict) else None
        if isinstance(link, str) and link:
            try:
                path = urlparse(link).path
            except ValueError:
                continue
            base = unquote(path.rsplit("/", 1)[-1]).strip()
            if base:
                return base[:200]
    return "file"


def _table_markdown(block: dict[str, Any], data: dict[str, Any]) -> str:
    rows = block.get("_children")
    if not isinstance(rows, list):
        return "[table]"
    cells_by_row: list[list[str]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("type") != "table_row":
            continue
        row_data = row.get("table_row")
        cells = row_data.get("cells") if isinstance(row_data, dict) else None
        if not isinstance(cells, list):
            continue
        cells_by_row.append(
            [
                rich_text_to_markdown(cell).replace("|", "\\|").replace("\n", " ")
                for cell in cells
            ]
        )
    if not cells_by_row:
        return "[table]"
    width = max(len(row) for row in cells_by_row)
    lines = []
    for index, row in enumerate(cells_by_row):
        padded = row + [""] * (width - len(row))
        lines.append("| " + " | ".join(padded) + " |")
        if index == 0:
            lines.append("|" + " --- |" * width)
    return "\n".join(lines)


def _block_body(block: dict[str, Any], btype: str, number: int) -> str:
    """The Markdown for the block itself, without its children."""
    raw = block.get(btype)
    data: dict[str, Any] = raw if isinstance(raw, dict) else {}
    text = rich_text_to_markdown(data.get("rich_text"))
    if btype == "paragraph" or btype == "template":
        return text
    if btype in ("heading_1", "heading_2", "heading_3"):
        return "#" * int(btype[-1]) + " " + text
    if btype == "bulleted_list_item":
        return "- " + text
    if btype == "numbered_list_item":
        return f"{max(number, 1)}. " + text
    if btype == "to_do":
        return ("- [x] " if data.get("checked") is True else "- [ ] ") + text
    if btype == "toggle":
        return "\u25b8 " + text
    if btype in ("quote", "callout"):
        icon = data.get("icon")
        emoji = icon.get("emoji") if isinstance(icon, dict) else None
        if btype == "callout" and isinstance(emoji, str) and emoji:
            text = f"{emoji} {text}"
        return "\n".join(f"> {line}" if line else ">" for line in text.split("\n"))
    if btype == "code":
        language = data.get("language")
        label = language if isinstance(language, str) and language != "plain text" else ""
        content = rich_text_plain(data.get("rich_text"))
        fence = "```"
        while fence in content:
            fence += "`"
        return f"{fence}{label}\n{content}\n{fence}"
    if btype == "divider":
        return "---"
    if btype == "equation":
        expression = data.get("expression")
        return f"$${expression}$$" if isinstance(expression, str) else "[equation]"
    if btype in NO_DESCEND_TYPES:
        title = data.get("title")
        label = title if isinstance(title, str) and title else "Untitled"
        kind = "page" if btype == "child_page" else "database"
        return f"[child {kind}: {label}] (id {block.get('id', '?')})"
    if btype in _FILE_TYPES:
        return f"[{btype}: {_file_label(data)}]"
    if btype in _LINK_TYPES:
        href = _safe_href(data.get("url"))
        return f"[{btype}: {href}]" if href else f"[{btype}]"
    if btype == "link_to_page":
        target = data.get("page_id") or data.get("database_id")
        return f"[link to page {target}]" if isinstance(target, str) else "[link to page]"
    if btype == "table":
        return _table_markdown(block, data)
    if btype == "table_row":
        cells = data.get("cells")
        if not isinstance(cells, list):
            return "[table_row]"
        rendered = (rich_text_to_markdown(c).replace("|", "\\|").replace("\n", " ") for c in cells)
        return "| " + " | ".join(rendered) + " |"
    if btype in _SILENT_TYPES or btype in _CONTAINER_TYPES:
        return ""
    return f"[{btype}]"


def render_block(
    block: dict[str, Any], *, indent: int = 0, number: int = 0, markers: bool = True
) -> str:
    """One block (and any loaded ``_children``) as Markdown lines.

    Children the caller loaded ride in ``block["_children"]``; a block that
    has children which were not loaded gets a marker line naming the block
    id (unless *markers* is False), so the reader knows to call
    get_block_children for it.
    """
    btype = block.get("type")
    if not isinstance(btype, str) or not btype:
        btype = "unknown"
    pad = "  " * indent
    body = _block_body(block, btype, number)
    lines = [pad + line if line else line for line in body.split("\n")] if body else []
    children = block.get("_children")
    child_indent = indent if btype in _CONTAINER_TYPES else indent + 1
    if btype == "table" or btype in NO_DESCEND_TYPES:
        pass
    elif isinstance(children, list) and children:
        lines.extend(render_blocks(children, indent=child_indent))
    elif markers and block.get("has_children") is True:
        lines.append(
            "  " * child_indent
            + f"[nested content not loaded: get_block_children block_id={block.get('id', '?')}]"
        )
    return "\n".join(lines)


def render_blocks(blocks: Any, *, indent: int = 0) -> list[str]:
    """Each top-level block rendered (numbered lists count up), empties dropped."""
    if not isinstance(blocks, list):
        return []
    parts: list[str] = []
    number = 0
    for block in blocks:
        if not isinstance(block, dict):
            continue
        number = number + 1 if block.get("type") == "numbered_list_item" else 0
        text = render_block(block, indent=indent, number=number)
        if text:
            parts.append(text)
    return parts


def blocks_to_markdown(blocks: Any) -> str:
    """Blocks as one Markdown document: list items on consecutive lines,
    everything else separated by a blank line."""
    if not isinstance(blocks, list):
        return ""
    out: list[str] = []
    previous_list = False
    number = 0
    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        number = number + 1 if btype == "numbered_list_item" else 0
        text = render_block(block, number=number)
        if not text:
            continue
        is_list = btype in LIST_TYPES
        if out:
            out.append("\n" if (is_list and previous_list) else "\n\n")
        out.append(text)
        previous_list = is_list
    return "".join(out)


# ---------------------------------------------------------------------------
# Parsing: Markdown -> Notion
# ---------------------------------------------------------------------------

#: Characters that can open an inline span.
_OPENER_RE = re.compile(r"[`\[*~_]")
#: Positions the scanner indexes: newlines (spans never cross one), and where
#: each kind of span may close. The zero-width patterns find overlapping
#: markers and require a non-blank character before the closing marker.
_CLOSER_RES = {
    "\n": re.compile("\n"),
    "`": re.compile(r"`"),
    "]": re.compile(r"\]"),
    "*": re.compile(r"\*"),
    "**": re.compile(r"(?<=\S)(?=\*\*)"),
    "~~": re.compile(r"(?<=\S)(?=~~)"),
    "_": re.compile(r"(?<=\S)(?=_(?!\w))"),
}
#: The link target after ``](``, up to and including the closing ``)``.
_LINK_TARGET_RE = re.compile(r"(https?://[^\s()]+)\)")

_Segment = tuple[str, dict[str, bool], Optional[str]]
#: (end of the span, annotation or "code" / "link", inner start, inner end, link)
_Span = tuple[int, str, int, int, Optional[str]]


def _is_word(char: str) -> bool:
    """Regex ``\\w`` for one character (letters, digits, underscore)."""
    return char.isalnum() or char == "_"


class _InlineScanner:
    """Finds inline Markdown spans in O(n log n) time.

    The rules are those of the classic regex (``code``, ``[text](https://..)``,
    ``**bold**``, ``~~strike~~``, ``*italic*``, ``_italic_``; spans never cross
    a line; the earliest span wins, and at one position code, link, bold and
    strikethrough are tried before italic), but every closing marker is looked
    up in a sorted position index instead of rescanning the rest of the line.
    A regex with an open-ended lazy span takes quadratic time on a long line of
    unclosed openers (``_a _a _a ...``), which would block the event loop; this
    scanner handles 100 000 such characters in milliseconds.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self._positions: dict[str, list[int]] = {}
        self._link_ends: dict[int, Optional[int]] = {}

    def _index(self, key: str) -> list[int]:
        """Sorted positions of closer *key*, computed on first use."""
        found = self._positions.get(key)
        if found is None:
            found = [match.start() for match in _CLOSER_RES[key].finditer(self.text)]
            self._positions[key] = found
        return found

    def _first(self, key: str, start: int, stop: int) -> int:
        """The first position of closer *key* in ``[start, stop)``, or -1."""
        positions = self._index(key)
        index = bisect_left(positions, start)
        if index < len(positions) and positions[index] < stop:
            return positions[index]
        return -1

    def _line_end(self, position: int) -> int:
        """The index of the first newline at or after *position* (or the end)."""
        newlines = self._index("\n")
        index = bisect_left(newlines, position)
        return newlines[index] if index < len(newlines) else len(self.text)

    def _link_end(self, start: int) -> Optional[int]:
        """The end of ``https://...)`` starting at *start*, cached, since many
        ``[`` openers can share one ``](`` and must not rescan its target."""
        if start not in self._link_ends:
            match = _LINK_TARGET_RE.match(self.text, start)
            self._link_ends[start] = match.end() if match else None
        return self._link_ends[start]

    def span_at(self, i: int) -> Optional[_Span]:
        """The span opening at *i*, or None."""
        text = self.text
        char = text[i]
        stop = self._line_end(i)
        after = text[i + 1] if i + 1 < len(text) else ""
        if char == "`":
            close = self._first("`", i + 1, stop)
            return (close + 1, "code", i + 1, close, None) if close > i + 1 else None
        if char == "[":
            close = self._first("]", i + 1, stop)
            if close > i + 1 and text.startswith("(", close + 1):
                link_end = self._link_end(close + 2)
                if link_end is not None:
                    return link_end, "link", i + 1, close, text[close + 2 : link_end - 1]
            return None
        if char in "*~" and after == char:
            # ``**`` / ``~~``: when it cannot close, ``*`` italic cannot open
            # here either (its first character may not be another ``*``).
            if i + 2 < len(text) and not text[i + 2].isspace():
                close = self._first(char * 2, i + 3, stop)
                if close >= 0:
                    flag = "bold" if char == "*" else "strikethrough"
                    return close + 2, flag, i + 2, close, None
            return None
        if char == "*":
            if i > 0 and (_is_word(text[i - 1]) or text[i - 1] == "*"):
                return None
            if not after or after.isspace():
                return None
            # Italic text holds no ``*``: only the next one can close it.
            close = self._first("*", i + 1, stop)
            if close < 0 or text[close - 1].isspace():
                return None
            beyond = text[close + 1] if close + 1 < len(text) else ""
            if beyond and (_is_word(beyond) or beyond == "*"):
                return None
            return close + 1, "italic", i + 1, close, None
        if char == "_":
            if i > 0 and _is_word(text[i - 1]):
                return None
            if not after or after.isspace() or after == "_":
                return None
            close = self._first("_", i + 2, stop)
            return (close + 1, "italic", i + 1, close, None) if close >= 0 else None
        return None


def _inline_segments(
    text: str, annotations: dict[str, bool], href: Optional[str], depth: int = 0
) -> list[_Segment]:
    if depth >= _MAX_INLINE_DEPTH:
        return [(text, annotations, href)] if text else []
    segments: list[_Segment] = []
    scanner = _InlineScanner(text)
    position = 0  # end of the text already emitted
    search_from = 0
    while True:
        opener = _OPENER_RE.search(text, search_from)
        if opener is None:
            break
        span = scanner.span_at(opener.start())
        if span is None:
            search_from = opener.start() + 1
            continue
        end, kind, inner_start, inner_end, target = span
        if opener.start() > position:
            segments.append((text[position : opener.start()], annotations, href))
        inner = text[inner_start:inner_end]
        if kind == "code":
            segments.append((inner, {**annotations, "code": True}, href))
        elif kind == "link":
            link = href or (target if target and len(target) <= _MAX_LINK_CHARS else None)
            segments.extend(_inline_segments(inner, annotations, link, depth + 1))
        else:
            segments.extend(_inline_segments(inner, {**annotations, kind: True}, href, depth + 1))
        position = search_from = end
    if position < len(text):
        segments.append((text[position:], annotations, href))
    return segments


def split_text(text: str, limit: int = RICH_TEXT_MAX_CHARS) -> list[str]:
    """*text* in chunks of at most *limit* UTF-16 code units (how Notion
    counts), never splitting a character."""
    if not text:
        return []
    chunks: list[str] = []
    start = 0
    units = 0
    for index, char in enumerate(text):
        width = 2 if ord(char) > 0xFFFF else 1
        if units + width > limit:
            chunks.append(text[start:index])
            start = index
            units = 0
        units += width
    chunks.append(text[start:])
    return chunks


def _text_object(content: str, annotations: dict[str, bool], href: Optional[str]) -> dict[str, Any]:
    text: dict[str, Any] = {"content": content}
    if href:
        text["link"] = {"url": href}
    item: dict[str, Any] = {"type": "text", "text": text}
    if annotations:
        item["annotations"] = dict(annotations)
    return item


def markdown_to_rich_text(text: str, *, formatting: bool = True) -> list[dict[str, Any]]:
    """Inline Markdown as a rich-text array, every object within 2000 chars.

    The array may exceed Notion's 100 elements for very long text; callers
    split it with :func:`split_rich_text`.
    """
    if not text:
        return []
    segments = _inline_segments(text, {}, None) if formatting else [(text, {}, None)]
    items: list[dict[str, Any]] = []
    for content, marks, href in segments:
        for chunk in split_text(content):
            items.append(_text_object(chunk, marks, href))
    return items


def split_rich_text(items: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """A rich-text array cut into arrays of at most 100 elements (one per block)."""
    if not items:
        return [[]]
    return [items[i : i + ARRAY_MAX_ITEMS] for i in range(0, len(items), ARRAY_MAX_ITEMS)]


def _text_blocks(kind: str, text: str, **extra: Any) -> list[dict[str, Any]]:
    """One block of *kind* holding *text*, or several when the rich text
    exceeds one array (each continues the previous)."""
    rich = markdown_to_rich_text(text, formatting=kind != "code")
    return [
        {"object": "block", "type": kind, kind: {"rich_text": part, **extra}}
        for part in split_rich_text(rich)
    ]


def _code_language(label: str) -> str:
    value = label.strip().lower()
    value = _LANGUAGE_ALIASES.get(value, value)
    return value if value in _CODE_LANGUAGES else "plain text"


# Line patterns are kept free of ambiguous quantifier pairs (such as
# ``\s*[^`]*`` or a lazy ``.*?`` before ``(?:\s+#+)?``): on a long line those
# backtrack in quadratic time, so fences and closing hashes are cut by hand.
_HEADING_RE = re.compile(r"^(?P<hashes>#{1,6})(?P<rest>\s.*)$")
_DIVIDER_RE = re.compile(r"^(?:-{3,}|\*{3,}|_{3,})$")
_TODO_RE = re.compile(r"^[-*+]\s+\[(?P<mark>[ xX])\]\s*(?P<text>.*)$")
_BULLET_RE = re.compile(r"^[-*+]\s+(?P<text>.*)$")
_NUMBER_RE = re.compile(r"^\d{1,9}[.)]\s+(?P<text>.*)$")
_QUOTE_RE = re.compile(r"^>\s?(?P<text>.*)$")


def _fence(stripped: str) -> Optional[tuple[str, str]]:
    """``(fence, language)`` when *stripped* opens a fenced code block: three
    or more backticks or tildes, then an optional language with no backtick."""
    char = stripped[:1]
    if char not in ("`", "~"):
        return None
    run = len(stripped) - len(stripped.lstrip(char))
    language = stripped[run:]
    if run < 3 or "`" in language:
        return None
    return stripped[:run], language.strip()


def _heading(stripped: str) -> Optional[tuple[int, str]]:
    """``(level, text)`` for an ATX heading line; a closing run of ``#``
    after whitespace is dropped (``## Title ##``), ``## Learn C#`` keeps it."""
    match = _HEADING_RE.match(stripped)
    if match is None:
        return None
    rest = match.group("rest")
    closing = len(rest) - len(rest.rstrip("#"))
    if closing and rest[: len(rest) - closing][-1:].isspace():
        rest = rest[: len(rest) - closing]
    return len(match.group("hashes")), rest.strip()


def _indent_width(line: str) -> int:
    width = 0
    for char in line:
        if char == " ":
            width += 1
        elif char == "\t":
            width += 4
        else:
            break
    return width


def _list_block(stripped: str) -> Optional[list[dict[str, Any]]]:
    todo = _TODO_RE.match(stripped)
    if todo:
        return _text_blocks("to_do", todo.group("text"), checked=todo.group("mark") in "xX")
    bullet = _BULLET_RE.match(stripped)
    if bullet:
        return _text_blocks("bulleted_list_item", bullet.group("text"))
    number = _NUMBER_RE.match(stripped)
    if number:
        return _text_blocks("numbered_list_item", number.group("text"))
    return None


class _Parser:
    """Line-oriented Markdown reader producing Notion block objects."""

    def __init__(self) -> None:
        self.blocks: list[dict[str, Any]] = []
        self.paragraph: list[str] = []
        self.quote: list[str] = []
        # The last top-level list item: indented lines nest under it.
        self.list_parent: Optional[dict[str, Any]] = None

    def flush(self) -> None:
        if self.paragraph:
            self.add(_text_blocks("paragraph", "\n".join(self.paragraph)))
            self.paragraph = []
        if self.quote:
            self.add(_text_blocks("quote", "\n".join(self.quote)))
            self.quote = []

    def add(self, blocks: list[dict[str, Any]], *, keeps_list: bool = False) -> None:
        self.blocks.extend(blocks)
        self.list_parent = blocks[-1] if keeps_list and blocks else None

    def nest(self, children: list[dict[str, Any]]) -> None:
        assert self.list_parent is not None
        payload = self.list_parent[self.list_parent["type"]]
        nested = payload.setdefault("children", [])
        nested.extend(children)
        if len(nested) > CHILDREN_PER_REQUEST:
            raise ConnectorError(
                f"A list item can hold at most {CHILDREN_PER_REQUEST} nested blocks."
            )

    def code(self, lines: list[str], start: int, fence: str, language: str) -> int:
        """Consume a fenced code block; returns the index after it."""
        body: list[str] = []
        index = start
        while index < len(lines):
            candidate = lines[index].strip()
            if candidate.startswith(fence[0] * len(fence)) and set(candidate) == {fence[0]}:
                index += 1
                break
            body.append(lines[index])
            index += 1
        self.add(_text_blocks("code", "\n".join(body), language=_code_language(language)))
        return index

    def line(self, raw: str) -> None:
        stripped = raw.strip()
        indent = _indent_width(raw)
        quote = _QUOTE_RE.match(stripped) if indent < 4 else None
        if quote is not None:
            if self.paragraph:
                self.flush()
            self.quote.append(quote.group("text"))
            return
        if self.quote:
            self.flush()
        if _DIVIDER_RE.match(stripped.replace(" ", "")):
            self.flush()
            self.add([{"object": "block", "type": "divider", "divider": {}}])
            return
        listed = _list_block(stripped)
        if listed is not None:
            self.flush()
            if indent >= 2 and self.list_parent is not None:
                self.nest(listed)
            else:
                self.add(listed, keeps_list=True)
            return
        heading = _heading(stripped)
        if heading is not None:
            self.flush()
            level, title = heading
            self.add(_text_blocks(f"heading_{min(level, 3)}", title))
            return
        if indent >= 2 and self.list_parent is not None and not self.paragraph:
            self.nest(_text_blocks("paragraph", stripped))
            return
        self.list_parent = None
        self.paragraph.append(stripped)


def markdown_to_blocks(markdown: Any) -> list[dict[str, Any]]:
    """Markdown as Notion block objects ready for an append request.

    Supports headings (h4 to h6 become h3), paragraphs, bulleted and
    numbered lists, to-dos, one level of nested list items, quotes, fenced
    code blocks and dividers, with bold, italic, code, strikethrough and
    http(s) links inline. Raises ConnectorError for non-text input, text
    over MAX_MARKDOWN_CHARS, or more than MAX_WRITE_BLOCKS blocks.
    """
    if not isinstance(markdown, str):
        raise ConnectorError("Markdown content must be a string.")
    if len(markdown) > MAX_MARKDOWN_CHARS:
        raise ConnectorError(
            f"Markdown content is {len(markdown)} characters; the limit per call is "
            f"{MAX_MARKDOWN_CHARS}. Split it across several append_blocks calls."
        )
    lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    parser = _Parser()
    index = 0
    while index < len(lines):
        raw = lines[index].rstrip()
        fence = _fence(raw.strip())
        if fence is not None:
            parser.flush()
            index = parser.code(lines, index + 1, *fence)
            continue
        if not raw.strip():
            parser.flush()
            index += 1
            continue
        parser.line(raw)
        index += 1
    parser.flush()
    total = count_blocks(parser.blocks)
    if total > MAX_WRITE_BLOCKS:
        raise ConnectorError(
            f"The Markdown makes {total} blocks; one call may add at most "
            f"{MAX_WRITE_BLOCKS}. Split it across several append_blocks calls."
        )
    return parser.blocks


def count_blocks(blocks: Iterable[dict[str, Any]]) -> int:
    """Blocks including their nested children."""
    total = 0
    for block in blocks:
        payload = block.get(block.get("type", ""), {})
        children = payload.get("children") if isinstance(payload, dict) else None
        total += 1 + (count_blocks(children) if isinstance(children, list) else 0)
    return total


def batch_blocks(
    blocks: list[dict[str, Any]],
    *,
    max_children: int = CHILDREN_PER_REQUEST,
    max_total: int = BLOCKS_PER_REQUEST,
) -> list[list[dict[str, Any]]]:
    """Top-level blocks grouped into requests Notion accepts: at most
    *max_children* per request and *max_total* including nested ones."""
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_total = 0
    for block in blocks:
        size = count_blocks([block])
        if current and (len(current) >= max_children or current_total + size > max_total):
            batches.append(current)
            current, current_total = [], 0
        current.append(block)
        current_total += size
    if current:
        batches.append(current)
    return batches
