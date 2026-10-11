"""Renders the assistant's Markdown as Telegram HTML (parse_mode "HTML"), so a
reply shows real bold, italics, code and quotes instead of raw ``**stars**``,
and splits long Markdown into Telegram-sized parts.

Why it exists: the model writes Markdown, and Telegram shows it raw unless a
message names a parse mode. HTML is the safe one to generate: every character
of the text is escaped and only a fixed handful of tags is ever emitted (b, i,
s, code, pre, blockquote), so markup the model or a web page wrote
(``<a href=...>``, ``<tg-spoiler>``) is shown literally. Links are written out
as "text (url)", never as an ``<a>`` whose target the reader cannot see.
Everything here is pure (no I/O) and runs in linear time on hostile input.

Connects to: services/notifications/telegram.py (``_api`` renders flagged
text, ``_send_reply`` and ``send_text`` split it), services/automation/
delivery.py and the trigger runs (which mark model replies with
TelegramMarkdown), the inline scanner in services/connectors/notion_api/
markdown.py and ``utf16_len`` in services/notifications/cards.py.
"""

from __future__ import annotations

import html
import re
from itertools import islice
from typing import Callable, Optional

from services.connectors.notion_api.markdown import inline_segments
from services.notifications.cards import utf16_len


class TelegramMarkdown(str):
    """A str holding the assistant's Markdown, for a Telegram sender to show
    formatted. Any string operation on it (slicing, joining, masking that
    hides something) gives a plain str back, which is sent as plain text:
    losing the mark fails safe. Every other channel treats it as the plain
    str it is."""

    __slots__ = ()


# Smallest part split_markdown makes (a fence must fit with room to spare).
_MIN_LIMIT = 64
# A longer line is shown as plain text: no message holds one (senders split
# first), and it bounds the inline scanner's work on hostile input.
_INLINE_MAX_CHARS = 4096
# Characters that can start inline formatting; a line without one is text.
_OPENER_RE = re.compile(r"[`\[*~_]")
# A fence's language, as Telegram's <pre><code class="language-x"> takes it.
_LANGUAGE_RE = re.compile(r"^[a-z0-9+#-]{1,20}$")
# The tags render_html emits, which visible_text removes again.
_TAG_RE = re.compile(r'</?(?:b|i|s|code|pre|blockquote)>|<code class="language-[a-z0-9+#-]{1,20}">')
_BULLET_RE = re.compile(r"^[-*+][ \t]+(.*)$")
_TASK_RE = re.compile(r"^\[([ xX])\](?:[ \t]+(.*))?$")
_NUMBER_RE = re.compile(r"^(\d{1,9}[.)])[ \t]+(.*)$")
_TABLE_RULE_CELL_RE = re.compile(r"^:?-+:?$")
_CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")
# Between table cells: the first that keeps the row no longer than its
# source line (so a part's visible text never outgrows its Markdown).
_CELL_SEPARATORS = ("  ·  ", " · ", "·")
# A bare URL: its ``_``, ``*`` and ``~`` are part of the address, never
# formatting. Trailing punctuation and markers are left outside it.
_BARE_URL_RE = re.compile(r"https?://[^\s<>()\[\]`]+", re.IGNORECASE)
_URL_TRAILING = ".,;:!?*_~'\""
_URL_MARKERS = "_*~"
# A web address in visible text, as far as no Markdown marker could reach.
_SHOWN_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>()\[\]\"'`*~]+", re.IGNORECASE)
# Punctuation that ends a sentence, not an address: a closing marker can
# stand between the two in the Markdown (``**https://x.io**.``).
_SHOWN_URL_TRAILING = ".,;:!?"


def _escape(text: str) -> str:
    # Quotes stay as they are: Telegram only needs &, < and > escaped.
    return html.escape(text, quote=False)


def _lines(markdown: str) -> list[str]:
    return str(markdown).replace("\r\n", "\n").replace("\r", "\n").split("\n")


# ── fences ───────────────────────────────────────────────────────────────


def _fence_open(line: str) -> Optional[tuple[str, str]]:
    """``(fence, info)`` when *line* opens a fenced code block: three or more
    backticks or tildes, then an info string (with no backtick after a
    backtick fence, so ```` ```x``` ```` on one line is not a fence)."""
    stripped = line.strip()
    char = stripped[:1]
    if char not in ("`", "~"):
        return None
    run = len(stripped) - len(stripped.lstrip(char))
    if run < 3:
        return None
    info = stripped[run:]
    if char == "`" and "`" in info:
        return None
    return stripped[:run], info.strip()


def _fence_closes(line: str, fence: str) -> bool:
    """True when *line* closes a block opened by *fence*: the same character,
    at least as many, and nothing else."""
    stripped = line.strip()
    return len(stripped) >= len(fence) and stripped == fence[0] * len(stripped)


def _language(info: str) -> Optional[str]:
    words = info.split(None, 1)
    language = words[0].lower() if words else ""
    return language if _LANGUAGE_RE.match(language) else None


# ── inline ───────────────────────────────────────────────────────────────


def _shield_urls(text: str) -> tuple[str, Optional[dict[int, str]]]:
    """*text* with the ``_``, ``*`` and ``~`` inside bare URLs swapped for
    private-use stand-ins absent from it (so ``https://x.io/_a_/b`` is never
    read as italics), and the table that swaps them back (None when nothing
    was swapped)."""
    if "://" not in text:
        return text, None
    spans: list[tuple[int, int]] = []
    for match in _BARE_URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING)
        if any(marker in url for marker in _URL_MARKERS):
            spans.append((match.start(), match.start() + len(url)))
    if not spans:
        return text, None
    used = set(text)
    stand_ins = list(
        islice((chr(code) for code in range(0xE000, 0xF900) if chr(code) not in used), len(_URL_MARKERS))
    )
    if len(stand_ins) < len(_URL_MARKERS):
        return text, None
    forward = str.maketrans(dict(zip(_URL_MARKERS, stand_ins, strict=True)))
    back = {ord(stand_in): marker for marker, stand_in in zip(_URL_MARKERS, stand_ins, strict=True)}
    pieces: list[str] = []
    position = 0
    for start, end in spans:
        pieces.append(text[position:start])
        pieces.append(text[start:end].translate(forward))
        position = end
    pieces.append(text[position:])
    return "".join(pieces), back


def _wrap(text: str, marks: dict[str, bool], bold: bool) -> str:
    """One run as HTML, its tags always in the same order so they balance.
    Code carries no other formatting (Telegram does not nest it)."""
    if not text:
        return ""
    out = _escape(text)
    if marks.get("code"):
        return f"<code>{out}</code>"
    if marks.get("strikethrough"):
        out = f"<s>{out}</s>"
    if marks.get("italic"):
        out = f"<i>{out}</i>"
    if bold or marks.get("bold"):
        out = f"<b>{out}</b>"
    return out


def _inline(text: str, *, bold: bool = False) -> str:
    """One line of inline Markdown as HTML. A link becomes its text and then
    its address in brackets (only the address when they are the same), so
    where it goes is always visible."""
    if not text:
        return ""
    if len(text) > _INLINE_MAX_CHARS or not _OPENER_RE.search(text):
        return _wrap(text, {}, bold)
    shielded, back = _shield_urls(text)

    def restore(value: str) -> str:
        return value.translate(back) if back else value

    segments = inline_segments(shielded)
    out: list[str] = []
    index = 0
    while index < len(segments):
        content, marks, href = segments[index]
        if href is None:
            out.append(_wrap(restore(content), marks, bold))
            index += 1
            continue
        label: list[str] = []
        while index < len(segments) and segments[index][2] == href:
            run = restore(segments[index][0])
            label.append(run)
            out.append(_wrap(run, segments[index][1], bold))
            index += 1
        target = restore(href)
        if "".join(label).strip() != target:
            out.append(f" ({_escape(target)})")
    return "".join(out)


# ── lines and blocks ─────────────────────────────────────────────────────


def _is_rule(stripped: str) -> bool:
    """``---``, ``***`` or ``___`` (spaces allowed between) alone on a line."""
    compact = stripped.replace(" ", "")
    return len(compact) >= 3 and compact[0] in "-*_" and compact == compact[0] * len(compact)


def _heading(stripped: str) -> Optional[str]:
    """The text of an ATX heading line (``## Title``, a closing ``##`` run
    dropped), or None."""
    run = len(stripped) - len(stripped.lstrip("#"))
    if not 1 <= run <= 6:
        return None
    rest = stripped[run:]
    if rest and rest[0] not in " \t":
        return None
    rest = rest.strip()
    closing = len(rest) - len(rest.rstrip("#"))
    if closing == len(rest):
        return ""
    if closing and rest[len(rest) - closing - 1] in " \t":
        rest = rest[: len(rest) - closing].rstrip()
    return rest


def _line(line: str) -> str:
    """One line outside a code block, table or quote as HTML: a heading in
    bold, a list item with its marker, a rule as a blank line."""
    stripped = line.strip()
    if not stripped or _is_rule(stripped):
        return ""
    heading = _heading(stripped)
    if heading is not None:
        return _inline(heading, bold=True)
    body = line.lstrip()
    indent = _escape(line[: len(line) - len(body)])
    bullet = _BULLET_RE.match(body)
    if bullet is not None:
        rest = bullet.group(1).rstrip()
        task = _TASK_RE.match(rest)
        if task is not None:
            box = "☑" if task.group(1) in "xX" else "☐"
            return f"{indent}{box} {_inline(task.group(2) or '')}"
        return f"{indent}• {_inline(rest)}"
    number = _NUMBER_RE.match(body)
    if number is not None:
        return f"{indent}{number.group(1)} {_inline(number.group(2).rstrip())}"
    return _inline(line.rstrip())


def _quote_content(line: str) -> Optional[str]:
    """What follows ``>`` (and one space) on a blockquote line, or None."""
    body = line.lstrip()
    if not body.startswith(">"):
        return None
    content = body[1:]
    return content[1:] if content.startswith(" ") else content


def _code_block(lines: list[str], index: int, fence: tuple[str, str], out: list[str]) -> int:
    """Render the fenced block opening at *index* (unclosed: it runs to the
    end); returns the index after it. The content is escaped, never parsed."""
    marker, info = fence
    body: list[str] = []
    index += 1
    while index < len(lines):
        if _fence_closes(lines[index], marker):
            index += 1
            break
        body.append(lines[index])
        index += 1
    content = "\n".join(body)
    if not content.strip():
        out.append(content)
        return index
    language = _language(info)
    if language:
        out.append(f'<pre><code class="language-{language}">{_escape(content)}</code></pre>')
    else:
        out.append(f"<pre>{_escape(content)}</pre>")
    return index


def _quote_block(lines: list[str], index: int, out: list[str]) -> int:
    """Render the run of ``>`` lines at *index* as one blockquote."""
    rendered: list[str] = []
    while index < len(lines):
        content = _quote_content(lines[index])
        if content is None:
            break
        rendered.append(_line(content))
        index += 1
    if any(rendered):
        out.append("<blockquote>" + "\n".join(rendered) + "</blockquote>")
    else:
        out.extend(rendered)
    return index


def _cells(line: str) -> list[str]:
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    return [cell.strip().replace("\\|", "|") for cell in _CELL_SPLIT_RE.split(body)]


def _is_table_rule(line: str) -> bool:
    """``|---|:---:|`` under a table's header row."""
    if "|" not in line or "-" not in line:
        return False
    return all(_TABLE_RULE_CELL_RE.match(cell) for cell in _cells(line))


def _table_row(line: str, *, bold: bool) -> str:
    rendered = [_inline(cell, bold=bold) for cell in _cells(line)]
    shown = utf16_len(visible_text("".join(rendered)))
    room = utf16_len(line)
    gaps = len(rendered) - 1
    separator = next(
        (sep for sep in _CELL_SEPARATORS if shown + gaps * len(sep) <= room), _CELL_SEPARATORS[-1]
    )
    return separator.join(rendered)


def _table(lines: list[str], index: int, out: list[str]) -> int:
    """Render the GFM table whose header row is at *index*: the header in
    bold, the rule row dropped, each row's cells side by side."""
    out.append(_table_row(lines[index], bold=True))
    index += 2
    while index < len(lines):
        line = lines[index]
        if (
            not line.strip()
            or "|" not in line
            or _fence_open(line) is not None
            or _quote_content(line) is not None
        ):
            break
        out.append(_table_row(line, bold=False))
        index += 1
    return index


def render_html(markdown: str) -> str:
    """*markdown* as Telegram HTML: fenced code as pre (with its language),
    headings in bold, quotes as blockquote, list items with a bullet (an
    ordered item keeps its number), tables as rows of cells, and bold,
    italic, strikethrough, code and links inline. Everything else is
    escaped text, so the result always parses, and its visible text is
    never longer than the Markdown."""
    lines = _lines(markdown)
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        fence = _fence_open(line)
        if fence is not None:
            index = _code_block(lines, index, fence, out)
        elif _quote_content(line) is not None:
            index = _quote_block(lines, index, out)
        elif "|" in line and index + 1 < len(lines) and _is_table_rule(lines[index + 1]):
            index = _table(lines, index, out)
        else:
            out.append(_line(line))
            index += 1
    return "\n".join(out)


def visible_text(html_text: str) -> str:
    """What Telegram shows for *html_text* made by render_html: the tags
    removed and the entities read back."""
    return html.unescape(_TAG_RE.sub("", html_text))


def _new_link(markdown: str, url: str) -> bool:
    """True when *url*, shown without the punctuation after it, is not in
    *markdown* as written."""
    return url.rstrip(_SHOWN_URL_TRAILING) not in markdown


def adds_links(markdown: str, shown: str) -> bool:
    """True when *shown* (the visible text of *markdown* rendered) has a web
    address *markdown* does not: markers inside one (``htt**ps://x.io**``)
    would get past checks that read the Markdown, such as the trigger runs'
    defanging of foreign links. Punctuation after an address does not count
    (``**https://x.io**.`` shows ``https://x.io.``)."""
    return any(_new_link(markdown, url) for url in _SHOWN_URL_RE.findall(shown))


def replace_new_links(markdown: str, shown: str, replace: Callable[[str], str]) -> str:
    """*shown* with each web address adds_links would find there passed
    through *replace* (the rest as it is)."""

    def one(match: re.Match[str]) -> str:
        url = match.group(0)
        return replace(url) if _new_link(markdown, url) else url

    return _SHOWN_URL_RE.sub(one, shown)


# ── splitting ────────────────────────────────────────────────────────────


class _Fence:
    """An open code block: its fence, its opening line, and whether a part
    that ends inside it closes it and the next one opens it again."""

    __slots__ = ("fence", "opener", "carried")

    def __init__(self, fence: str, opener: str, carried: bool) -> None:
        self.fence = fence
        self.opener = opener
        self.carried = carried


class _Line:
    """One source line (with its newline) and the code fence around it."""

    __slots__ = ("text", "units", "before", "after", "blank")

    def __init__(self, text: str, before: Optional[_Fence], after: Optional[_Fence]) -> None:
        self.text = text
        self.units = utf16_len(text)
        # The code block open where the line starts and where it ends;
        # None outside one.
        self.before = before
        self.after = after
        self.blank = not text.strip()


def _source_lines(text: str, limit: int) -> list[_Line]:
    """*text*'s lines with the fence state around each. A fence too long to
    close and reopen within a part (over ``limit // 4``) is not carried."""
    records: list[_Line] = []
    state: Optional[_Fence] = None
    raw = text.split("\n")
    for number, line in enumerate(raw):
        if number < len(raw) - 1:
            line += "\n"
        elif not line:
            break
        before = state
        if state is None:
            fence = _fence_open(line)
            if fence is not None:
                opener = line.strip()
                carried = utf16_len(opener) + len(fence[0]) + 2 <= limit // 4
                state = _Fence(fence[0], opener, carried)
        elif _fence_closes(line, state.fence):
            state = None
        records.append(_Line(line, before, state))
    return records


def _reopen(state: Optional[_Fence]) -> str:
    return f"{state.opener}\n" if state is not None and state.carried else ""


def _close(record: _Line) -> str:
    """What closes *record*'s open code block when a part ends on it."""
    state = record.after
    if state is None or not state.carried:
        return ""
    return state.fence if record.text.endswith("\n") else f"\n{state.fence}"


def _assemble(records: list[_Line]) -> str:
    body = _reopen(records[0].before) + "".join(record.text for record in records)
    return (body + _close(records[-1])).strip("\n")


def _prefix_within(text: str, room: int) -> int:
    """The length of the longest prefix of *text* within *room* UTF-16 units
    (never half of a character), cut after a space in its second half when
    there is one."""
    units = 0
    cut = 0
    for char in text:
        width = 2 if ord(char) > 0xFFFF else 1
        if units + width > room:
            break
        units += width
        cut += 1
    space = text.rfind(" ", cut // 2, cut)
    if 0 < space and cut < len(text):
        cut = space + 1
    return max(cut, 1)


def _hard_split(record: _Line, limit: int, parts: list[str]) -> _Line:
    """Append full parts of an over-long line to *parts*; return the rest
    (which fits), with the same fence state."""
    head = _reopen(record.before)
    state = record.before
    close = f"\n{state.fence}" if state is not None and state.carried else ""
    room = max(limit - utf16_len(head) - len(close), 2)
    text = record.text
    remaining = record.units
    while remaining + utf16_len(head) + len(_close(record)) > limit:
        cut = _prefix_within(text, room)
        piece = text[:cut]
        parts.append((head + piece + close).strip("\n"))
        text = text[cut:]
        remaining -= utf16_len(piece)
    return _Line(text, record.before, record.after)


def split_markdown(text: str, limit: int) -> list[str]:
    """*text* (Markdown) in parts of at most *limit* UTF-16 units, cut at a
    blank line when one leaves the part at least half full, else at a line
    end; a line longer than a part is cut (after a space where it can, never
    inside a character). A part that ends inside a code fence closes it, and
    the next part opens it again with the same language, so every part
    renders on its own. An empty text gives no parts."""
    if limit < _MIN_LIMIT:
        raise ValueError(f"limit must be at least {_MIN_LIMIT}, got {limit}")
    source = "\n".join(_lines(text))
    if not source.strip():
        return []
    if utf16_len(source) <= limit:
        return [source]
    records = _source_lines(source, limit)
    parts: list[str] = []
    start = 0
    while start < len(records):
        size = utf16_len(_reopen(records[start].before))
        end = start
        blank_cut = -1
        while end < len(records):
            record = records[end]
            if size + record.units + len(_close(record)) > limit:
                break
            size += record.units
            end += 1
            if record.blank and size >= limit // 2:
                blank_cut = end
        if end == start:
            records[start] = _hard_split(records[start], limit, parts)
            continue
        if end < len(records):
            if blank_cut > start:
                end = blank_cut
            opener = records[end - 1]
            if end - 1 > start and opener.before is None and opener.after is not None:
                # Never end a part on the line that opens a code block.
                end -= 1
        part = _assemble(records[start:end])
        if part.strip():
            parts.append(part)
        start = end
    return parts


def close_fence(markdown: str) -> str:
    """*markdown* with a code fence it leaves open closed at its end, so
    text appended after it is not shown as code."""
    state: Optional[str] = None
    for line in _lines(markdown):
        if state is None:
            fence = _fence_open(line)
            if fence is not None:
                state = fence[0]
        elif _fence_closes(line, state):
            state = None
    if state is None:
        return markdown
    return f"{markdown}\n{state}" if not markdown.endswith("\n") else f"{markdown}{state}"


__all__ = [
    "TelegramMarkdown",
    "adds_links",
    "close_fence",
    "render_html",
    "replace_new_links",
    "split_markdown",
    "visible_text",
]
