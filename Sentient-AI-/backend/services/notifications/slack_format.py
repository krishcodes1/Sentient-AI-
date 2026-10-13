"""Renders the model's Markdown replies as Slack mrkdwn for the Slack DM
channel, and splits rendered text into Slack-sized messages.

Why it exists: Slack reads message text as mrkdwn, not CommonMark. A single
*x* is bold there and `code` works, but the **bold**, # headings,
[text](url) links and pipe tables a model writes show up raw. A reply the
model wrote, and only that (the channel marks it SlackMarkdown), is rendered
here: **x** becomes *x*, *x* and _x_ become _x_, ~~x~~ becomes ~x~, a heading
becomes a bold line, [text](url) becomes "text (url)", a table becomes plain
lines, "- item" becomes "• item", and a fenced block loses its language
label. Approval cards, command replies and external text never come here:
they keep slack_escape alone.

Security rules:
- Every piece of text goes through slack_escape (&, <, >), so nothing the
  model writes can become a mention or a <url|label> link, and a link's
  target is always shown in the text, never hidden behind its label.
- The caller masks the raw Markdown first (services/security/channels.py).
  render_reply then masks the visible text (what the reader sees once the
  markers are gone and links are spelled out) again; when that hides
  anything more, the formatting is dropped and the masked visible text goes
  out plain.

Connects to: services/notifications/slack.py (SlackChannel._send_reply),
services/connectors/notion_api/markdown.py (inline_spans: the inline span
rules the Notion writer uses), services/security/channels.py and
services/notifications/cards.py (split_text). No I/O.
"""

from __future__ import annotations

import re
from typing import Optional

from services.connectors.notion_api.markdown import InlineSpan, inline_spans
from services.notifications import cards
from services.security import channels as secret_text

# How deep inline spans are followed before the rest is plain text (bounds
# the recursion on hostile input, as the Notion parser does).
_MAX_INLINE_DEPTH = 4
# The mrkdwn marker of each kind of span the scanner finds (code and links
# are handled on their own).
_MARKERS = {"bold": "*", "italic": "_", "strikethrough": "~"}
_FENCE = "```"
_BULLET = "• "
_CELL_SEPARATOR = " · "
# What split may add to a part: a reopened and a closed ``` block, and an
# entity moved over from the part before.
_SPLIT_ROOM = 16

# Kept free of ambiguous quantifier pairs, as in the Notion parser: a
# closing run of "#" is cut by hand.
_HEADING_RE = re.compile(r"^(?P<hashes>#{1,6})(?P<rest>\s.*)$")
_DIVIDER_RE = re.compile(r"^(?:-{3,}|\*{3,}|_{3,})$")
_CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")


def slack_escape(text: str) -> str:
    """Escape the three characters Slack treats as markup, so text the model
    wrote can never become a disguised link or a mention."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_unescape(text: str) -> str:
    """Undo the escaping Slack applies to message text in events."""
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


class SlackMarkdown(str):
    """The model's own reply: Markdown the Slack channel renders as mrkdwn
    (render_reply). Opt-in on purpose: a plain str (an approval card, a
    command reply, a tool's or anyone else's text) is never rendered and
    goes out escaped, exactly as typed."""

    __slots__ = ()


class _Out:
    """The rendered reply, built twice over: the mrkdwn sent to Slack and
    the text its reader sees (no markers), which the masking re-check reads."""

    def __init__(self) -> None:
        self.mrkdwn: list[str] = []
        self.visible: list[str] = []

    def text(self, value: str) -> None:
        self.mrkdwn.append(slack_escape(value))
        self.visible.append(value)

    def marker(self, value: str) -> None:
        self.mrkdwn.append(value)


def _is_word(char: str) -> bool:
    return char.isalnum() or char == "_"


def _at_word_boundary(text: str, span: InlineSpan) -> bool:
    """Whether *span* has no letter or digit right outside it. Slack only
    reads a marker at a word boundary, so "**foo**bar" sent as "*foo*bar"
    would show its asterisks."""
    before = text[span.start - 1] if span.start else ""
    after = text[span.end] if span.end < len(text) else ""
    return not (_is_word(before) or _is_word(after))


def _inline(out: _Out, text: str, active: frozenset[str] = frozenset(), depth: int = 0) -> None:
    """One line's inline Markdown as mrkdwn. A kind already *active* (bold
    in a bold heading) is not marked again, and a span Slack would not read
    (see _at_word_boundary) keeps its text without markers."""
    if depth >= _MAX_INLINE_DEPTH:
        out.text(text)
        return
    position = 0
    for span in inline_spans(text):
        out.text(text[position : span.start])
        inner = text[span.inner_start : span.inner_end]
        if span.kind == "code":
            out.marker("`")
            out.text(inner)
            out.marker("`")
        elif span.kind == "link":
            # The label, then the target in plain sight: never <url|label>.
            _inline(out, inner, active, depth + 1)
            if span.target and inner.strip() != span.target:
                out.text(f" ({span.target})")
        else:
            marked = span.kind not in active and _at_word_boundary(text, span)
            marker = _MARKERS[span.kind] if marked else ""
            out.marker(marker)
            _inline(out, inner, active | {span.kind} if marked else active, depth + 1)
            out.marker(marker)
        position = span.end
    out.text(text[position:])


def _bold_line(out: _Out, cells: list[str]) -> None:
    """*cells* (a heading's text, or a table's header row) as one bold line."""
    out.marker("*")
    for index, cell in enumerate(cells):
        if index:
            out.text(_CELL_SEPARATOR)
        _inline(out, cell, frozenset({"bold"}))
    out.marker("*")


def _plain_cells(out: _Out, cells: list[str]) -> None:
    for index, cell in enumerate(cells):
        if index:
            out.text(_CELL_SEPARATOR)
        _inline(out, cell)


def _heading(stripped: str) -> Optional[str]:
    """An ATX heading line's text (a closing run of "#" after whitespace
    dropped, so "## Learn C#" keeps it), or None for any other line."""
    match = _HEADING_RE.match(stripped)
    if match is None:
        return None
    rest = match.group("rest")
    closing = len(rest) - len(rest.rstrip("#"))
    if closing and rest[: len(rest) - closing][-1:].isspace():
        rest = rest[: len(rest) - closing]
    return rest.strip()


def _fence(stripped: str) -> Optional[str]:
    """The fence a line opens a fenced code block with (three or more
    backticks or tildes, then an optional language), or None."""
    char = stripped[:1]
    if char not in ("`", "~"):
        return None
    run = len(stripped) - len(stripped.lstrip(char))
    if run < 3 or (char == "`" and "`" in stripped[run:]):
        return None
    return stripped[:run]


def _closes(stripped: str, fence: str) -> bool:
    return len(stripped) >= len(fence) and stripped == fence[0] * len(stripped)


def _is_delimiter_row(line: str) -> bool:
    """A table's "| --- | :-: |" row."""
    stripped = line.strip()
    return "|" in stripped and "-" in stripped and set(stripped) <= set("|:- \t")


def _cells(row: str) -> list[str]:
    """A table row's non-empty cells: outer pipes dropped, "\\|" unescaped."""
    stripped = row.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    cells = (cell.strip().replace("\\|", "|") for cell in _CELL_SPLIT_RE.split(stripped))
    return [cell for cell in cells if cell]


class _Renderer:
    """Reads Markdown line by line into an _Out."""

    def __init__(self) -> None:
        self.out = _Out()
        self._lines = 0

    def new_line(self) -> None:
        if self._lines:
            self.out.text("\n")
        self._lines += 1

    def render(self, lines: list[str]) -> None:
        fence: Optional[str] = None  # the open code block's fence
        index = 0
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            index += 1
            if fence is not None:
                self.new_line()
                if _closes(stripped, fence):
                    self.out.marker(_FENCE)
                    fence = None
                else:
                    self.out.text(line)
                continue
            opened = _fence(stripped)
            if opened is not None:
                # Slack shows a language label as the block's first line.
                self.new_line()
                self.out.marker(_FENCE)
                fence = opened
                continue
            if "|" in line and index < len(lines) and _is_delimiter_row(lines[index]):
                rows = [line]
                index += 1
                while index < len(lines) and "|" in lines[index] and lines[index].strip():
                    rows.append(lines[index])
                    index += 1
                self.table(rows)
                continue
            self.line(line, stripped)
        if fence is not None:
            self.new_line()
            self.out.marker(_FENCE)

    def table(self, rows: list[str]) -> None:
        """A pipe table as plain lines: the header row bold, then one line
        per row, cells joined by a middle dot."""
        header = _cells(rows[0])
        if header:
            self.new_line()
            _bold_line(self.out, header)
        for row in rows[1:]:
            cells = _cells(row)
            if cells:
                self.new_line()
                _plain_cells(self.out, cells)

    def line(self, line: str, stripped: str) -> None:
        self.new_line()
        title = _heading(stripped)
        if title is not None:
            if title:
                _bold_line(self.out, [title])
            return
        bullet = line.lstrip(" \t")
        if (
            bullet[:1] in ("-", "*", "+")
            and bullet[1:2] in (" ", "\t")
            and not _DIVIDER_RE.match(stripped.replace(" ", ""))
        ):
            self.out.text(line[: len(line) - len(bullet)] + _BULLET)
            _inline(self.out, bullet[2:].lstrip())
            return
        _inline(self.out, line)


def render(markdown: str) -> tuple[str, str]:
    """*markdown* as Slack mrkdwn (every piece of text escaped), and the text
    a reader of it sees."""
    renderer = _Renderer()
    renderer.render(markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n"))
    out = renderer.out
    return "".join(out.mrkdwn), "".join(out.visible)


def render_reply(masked: str, *, channel: str = "slack") -> tuple[str, int]:
    """*masked* (the model's reply, masked raw by the caller) as mrkdwn, and
    how many more values the check on its visible text hid.

    Rendering can join what the Markdown kept apart ("sk-**abc**" reads
    "sk-abc"), so the visible text is masked again. When that changes
    anything (a value found, or the detector failing), the formatting is
    dropped and the masked visible text goes out escaped and plain."""
    mrkdwn, visible = render(masked)
    checked, hidden = secret_text.mask_text(visible, channel=channel)
    if checked != visible:
        return slack_escape(checked), hidden
    return mrkdwn, 0


def split(text: str, *, max_chars: int) -> list[str]:
    """Escaped Slack *text* in messages of at most *max_chars*, broken on
    line boundaries where possible (cards.split_text). A cut never lands
    inside an &amp;, &lt; or &gt; entity, and a ``` block cut across two
    messages is closed at the end of the first and opened again at the
    start of the next, so each message renders by itself."""
    parts = cards.split_text(text, max_chars=max_chars - _SPLIT_ROOM)
    for index in range(len(parts) - 1):
        # Every & of escaped text opens an entity: one with no ; yet was cut.
        cut = parts[index].rfind("&")
        if cut >= 0 and ";" not in parts[index][cut:]:
            parts[index + 1] = parts[index][cut:] + parts[index + 1]
            parts[index] = parts[index][:cut]
    fitted: list[str] = []
    inside = False
    for part in parts:
        if not part:
            continue
        if inside:
            part = f"{_FENCE}\n{part}"
        # Slack toggles a code block at every ```, wherever it stands.
        inside = part.count(_FENCE) % 2 == 1
        if inside:
            part += _FENCE if part.endswith("\n") else f"\n{_FENCE}"
        fitted.append(part)
    return fitted


__all__ = [
    "SlackMarkdown",
    "render",
    "render_reply",
    "slack_escape",
    "slack_unescape",
    "split",
]
