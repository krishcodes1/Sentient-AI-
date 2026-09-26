"""Aria snapshot -> filtered outline with refs (spec §5, contracts §3).

Why a filter at all: Playwright's ai-mode snapshot is written for a model
that can afford to read everything. Ours cannot. The outline is what the
model sees after *every* action, so each line costs tokens on each step,
and each line is untrusted page content. This module makes the page
small (wrappers, off-viewport nodes and redundant name-from-content text
go), safe (password / one-time-code / card-field values and anything the
toolkit typed are redacted; cross-origin frames become one line) and
navigable (``[ref=eN]`` survives untouched so ``aria-ref=`` resolves).
Which fields hold a card is decided by ``checkout.markers``, the one
classifier the checkout, the screenshot mask and browser.act share; a
typed secret made of digits (a card number, a CVC) is redacted in every
grouping a page can print it (``redact``).

What Playwright 1.63 gives us, verified against the bundled renderer:
``[ref=eN]`` (``fKeN`` inside frames -- and on the *main* frame after the
first navigation in a tab, so refs are opaque tokens here), ``[cursor=pointer]``
(div-buttons), ``[aria-hidden]``, ``[active]`` (focus, not visibility),
``[box=x,y,w,h]`` viewport-relative when ``boxes=True``, and the state
markers ``[checked]`` ``[disabled]`` ``[expanded]`` ``[level=N]``
``[pressed]`` ``[selected]`` ``[invalid]``. It does *not* mark password
inputs (their values are printed in clear) and it inlines cross-origin
iframes; ``page_facts`` asks the page for those two things.

The filter is pure so it can be unit-tested on saved fixtures; only
``outline``/``find``/``page_facts`` touch a live page.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import quote, quote_plus, urlsplit, urlunsplit

import structlog

from services.tools.browser.checkout import markers

logger = structlog.get_logger(__name__)

DEFAULT_LIMIT_CHARS = 8000
FULL_LIMIT_CHARS = 24000
DEFAULT_VIEWPORT = (1280, 800)
REDACTED = "[redacted]"
FIND_MAX_BLOCKS = 20
FACTS_TIMEOUT_S = 3.0
# The longest a snapshot waits for the page's frames (``snapshot_raw``).
SNAPSHOT_TIMEOUT_MS = 8_000
_LOAD_LAZY_FRAMES_JS = (
    "() => { for (const f of document.querySelectorAll('iframe[loading=lazy i]')) f.loading = 'eager'; }"
)
# A typed secret shorter than this would redact every occurrence of one
# or two characters across the page; the toolkit only ever adds whole
# passwords, whole OTP codes and whole card values.
_MIN_SECRET_CHARS = 3
# A digit-only secret this long is a card number: it is redacted in every
# grouping a page prints it ("4242 4242 4242 4242", "4242-4242-…"); a
# shorter one (a CVC, an expiry as MMYY) only as a whole digit run, so
# "987" inside an order id is not taken for the security code.
_PAN_MIN_DIGITS = 12
_DIGIT_GAP = r"[\s\-.\u00a0\u2007\u202f]*"
# What JavaScript's encodeURIComponent / encodeURI leave unescaped beyond
# ASCII letters, digits and ``-_.`` (which ``quote`` never escapes).
_JS_URI_COMPONENT_SAFE = "!~*'()"
_JS_URI_SAFE = ";,/?:@&=+$!~*'()#"

# Roles the model can act on. They are never dropped as wrappers, never
# treated as screen-reader-only, and never folded into a parent's name.
_INTERACTIVE_ROLES = frozenset(
    {
        "button",
        "link",
        "textbox",
        "searchbox",
        "checkbox",
        "radio",
        "combobox",
        "listbox",
        "option",
        "menuitem",
        "menuitemcheckbox",
        "menuitemradio",
        "slider",
        "spinbutton",
        "switch",
        "tab",
        "treeitem",
        "iframe",
    }
)
# Roles whose inline value may be a typed secret.
_FIELD_ROLES = frozenset({"textbox", "searchbox", "spinbutton", "combobox"})
# Unnamed nodes with these roles carry no information of their own.
_WRAPPER_ROLES = frozenset({"generic", "none", "presentation"})
# Nearest of these is the "row context" returned by find (spec §5).
_CONTEXT_ROLES = ("row", "listitem", "article")
# Fallback when page facts are unavailable or a site labels a field
# without the autocomplete attribute: the name alone is enough to redact.
# The card-field half of the rule is the checkout's own (markers).
_SECRET_NAME_RE = markers.SECRET_NAME_RE

_LINE_RE = re.compile(r"^(?P<indent> *)- (?P<body>.*)$")
_KEY_RE = re.compile(
    r"^(?P<role>[a-z][a-z-]*)"
    r'(?: (?P<name>"(?:[^"\\]|\\.)*"|/(?:[^/\\]|\\.)*/))?'
    r"(?P<markers>(?: \[[a-z-]+(?:=[^\]]*)?\])*)$"
)
_MARKER_RE = re.compile(r" \[(?P<key>[a-z-]+)(?:=(?P<value>[^\]]*))?\]")
_KEY_SEP_RE = re.compile(r":( |$)")

_IFRAME_FACTS_JS = """el => {
  let same = false;
  try { void el.contentWindow.location.href; same = true; } catch (e) {}
  let origin = null;
  try {
    const src = el.getAttribute('src') || '';
    origin = src ? new URL(src, document.baseURI).origin : null;
  } catch (e) {}
  return { same, origin };
}"""
# What kind of secret a field holds, from its live attributes and labels:
# password, one-time-code, or a cc-* token for a card field found by its
# autocomplete token or by what the site calls it (markers.FIELD_KIND_JS).
_FIELD_FACTS_JS = markers.FIELD_KIND_JS


@dataclass(frozen=True)
class Outline:
    url: str
    title: str
    lines: list[str]
    refs: int
    chars: int
    truncated: bool


@dataclass(frozen=True)
class PageFacts:
    """What the YAML cannot tell the filter. ``None`` means "unknown" and
    every unknown fails closed: all iframes are treated as external and
    every field value is redacted."""

    viewport: tuple[int, int] = DEFAULT_VIEWPORT
    external_frames: Optional[Mapping[str, str]] = None  # ref -> origin
    secret_fields: Optional[Mapping[str, str]] = None  # ref -> kind
    # field ref -> the words on the default button of the field's form
    # (what a submit through that field sends it with); the write tier's
    # purchase rule reads it before any card is made.
    form_buttons: Optional[Mapping[str, str]] = None


UNKNOWN_FACTS = PageFacts()


@dataclass
class _Node:
    depth: int
    role: str  # element role, "text", or a prop name such as "/url"
    name: Optional[str]  # name token as rendered, quotes included
    markers: list[tuple[str, Optional[str]]]
    text: Optional[str]  # inline value as rendered (may be quoted)
    children: list["_Node"] = field(default_factory=list)

    def marker(self, key: str) -> Optional[str]:
        for k, v in self.markers:
            if k == key:
                return v or ""
        return None

    @property
    def ref(self) -> Optional[str]:
        return self.marker("ref") or None

    @property
    def box(self) -> Optional[tuple[int, int, int, int]]:
        raw = self.marker("box")
        if raw is None:
            return None
        try:
            x, y, w, h = (int(part) for part in raw.split(","))
        except ValueError:
            return None
        return x, y, w, h

    @property
    def interactive(self) -> bool:
        return self.role in _INTERACTIVE_ROLES or self.marker("cursor") == "pointer"


# -- parsing ---------------------------------------------------------------


def _plain(token: Optional[str]) -> str:
    """The human text behind a rendered name/value token."""
    if not token:
        return ""
    if token.startswith('"') and token.endswith('"') and len(token) >= 2:
        try:
            return str(json.loads(token))
        except ValueError:
            return token[1:-1]
    return token


def _split_body(body: str) -> tuple[str, Optional[str], bool]:
    """-> (key, inline value or None, has_children).

    Playwright single-quotes a key that contains ``: `` (a name such as
    ``"Quiz 2: Loops"``), doubling any ``'`` inside; otherwise the first
    ``: `` or a trailing ``:`` ends the key.
    """
    if body.startswith("'"):
        i = 1
        while True:
            j = body.find("'", i)
            if j == -1:
                return body, None, False
            if body[j + 1 : j + 2] == "'":
                i = j + 2
                continue
            key = body[1:j].replace("''", "'")
            rest = body[j + 1 :]
            break
    else:
        m = _KEY_SEP_RE.search(body)
        if m is None:
            return body, None, False
        key, rest = body[: m.start()], body[m.start() :]
    if rest == "":
        return key, None, False
    if rest == ":":
        return key, None, True
    return key, rest[2:], False


def _parse(raw: str) -> list[_Node]:
    roots: list[_Node] = []
    stack: list[_Node] = []
    for line in raw.splitlines():
        m = _LINE_RE.match(line)
        if m is None:
            continue
        depth = len(m.group("indent")) // 2
        key, value, _ = _split_body(m.group("body"))
        if key == "text":
            node = _Node(depth, "text", None, [], value)
        elif key.startswith("/"):
            node = _Node(depth, key, None, [], value)
        else:
            km = _KEY_RE.match(key)
            if km is None:
                # Not a shape the renderer produces; keep it visible as text
                # rather than silently dropping page content.
                node = _Node(depth, "text", None, [], key if value is None else f"{key}: {value}")
            else:
                markers = [
                    (mm.group("key"), mm.group("value"))
                    for mm in _MARKER_RE.finditer(km.group("markers"))
                ]
                node = _Node(depth, km.group("role"), km.group("name"), markers, value)
        while stack and stack[-1].depth >= depth:
            stack.pop()
        if stack:
            stack[-1].children.append(node)
        else:
            roots.append(node)
        stack.append(node)
    return roots


# -- pruning (mode rules, redaction) -------------------------------------


def _is_sr_only(node: _Node) -> bool:
    """Canvas' ``.screenreader-only`` is a 1x1 clipped box; the older
    pattern parks text far off the left edge; ``font-size:0`` gives a
    zero-height box. Interactive nodes are exempt (``option`` under a
    closed ``combobox`` is 0x0 and still selectable)."""
    box = node.box
    if box is None or node.role == "option" or (node.interactive and node.ref):
        return False
    x, _y, w, h = box
    return (w <= 1 and h <= 1) or w == 0 or h == 0 or x + w <= 0


@dataclass(frozen=True)
class Needles:
    """Every form a secret can take in the YAML, ready to apply: literal
    needles (as typed, JSON-escaped inside a quoted name, percent-encoded
    in a ``/url`` value), longest first so a shorter secret never splits a
    longer one's replacement, plus one pattern per digit-only secret
    (``_digit_pattern``)."""

    literals: tuple[str, ...]
    patterns: tuple["re.Pattern[str]", ...]

    def apply(self, value: str, replacement: str = REDACTED) -> str:
        for needle in self.literals:
            if needle in value:
                value = value.replace(needle, replacement)
        for pattern in self.patterns:
            value = pattern.sub(replacement, value)
        return value


def _digit_pattern(secret: str) -> "re.Pattern[str]":
    """A digit-only secret as a pattern: a card number matches with any
    spaces, dashes or dots between its digits; anything shorter matches
    as a whole digit run only. Neither matches inside a longer run of
    digits, which would be a different number."""
    if len(secret) >= _PAN_MIN_DIGITS:
        body = _DIGIT_GAP.join(secret)
    else:
        body = re.escape(secret)
    return re.compile(rf"(?<!\d){body}(?!\d)")


def _redaction_needles(secrets: Sequence[str]) -> Needles:
    literals: set[str] = set()
    patterns: list["re.Pattern[str]"] = []
    for secret in secrets:
        if len(secret) < _MIN_SECRET_CHARS:
            continue
        if secret.isdigit():
            patterns.append(_digit_pattern(secret))
            continue
        # A card number a page shows grouped ("4242 4242 4242 4242" read
        # off a secret field) is the same number in any other grouping.
        digits = re.sub(r"[\s\-.]", "", secret)
        if digits.isdigit() and len(digits) >= _PAN_MIN_DIGITS:
            patterns.append(_digit_pattern(digits))
        literals.update(
            (
                secret,
                json.dumps(secret, ensure_ascii=False)[1:-1],
                quote(secret, safe=""),
                quote(secret),
                quote_plus(secret, safe=""),
                quote(secret, safe=_JS_URI_COMPONENT_SAFE),  # encodeURIComponent
                quote(secret, safe=_JS_URI_SAFE),  # encodeURI
            )
        )
    return Needles(tuple(sorted(literals, key=len, reverse=True)), tuple(patterns))


def redact(text: str, secrets: Sequence[str], replacement: str = REDACTED) -> str:
    """*text* with every typed secret replaced, in every form the outline
    redacts it in. The one function a toolkit uses on page text it returns
    (a confirmation, a title, a label), so the outline and the rest of a
    tool result hide the same things."""
    return _redaction_needles(secrets).apply(text, replacement)


def _redact_text(value: Optional[str], needles: Needles) -> Optional[str]:
    if value is None:
        return None
    return needles.apply(value)


def _has_value(node: _Node) -> bool:
    """A field shows its value inline, or (``<select>``) as the option
    marked ``[selected]`` among its children."""
    return node.text is not None or bool(node.children)


def _is_secret_field(node: _Node, facts: PageFacts) -> bool:
    if node.role not in _FIELD_ROLES or not _has_value(node):
        return False
    # page_facts can only ask the page about nodes that carry a ref, so a
    # ref-less field (0x0 box) is as unknown as every field on a page whose
    # facts failed: fail closed.
    if facts.secret_fields is None or node.ref is None:
        return True
    if node.ref in facts.secret_fields:
        return True
    return bool(_SECRET_NAME_RE.search(_plain(node.name)))


def _field_secrets(nodes: list[_Node], facts: PageFacts) -> list[str]:
    """Values of the secret fields, so they are redacted wherever else the
    page repeats them. Playwright names an element from the *value* of an
    input it is ``aria-labelledby``, and names links/cells from content,
    so blanking the field's own line would leave the secret in a
    neighbour's name (measured on Chromium with Playwright 1.63)."""
    values: list[str] = []
    for node in nodes:
        if _is_secret_field(node, facts):
            if node.text is not None:
                values.append(_plain(node.text))
            values.extend(
                _plain(child.name)
                for child in node.children
                if child.marker("selected") is not None
            )
        values.extend(_field_secrets(node.children, facts))
    return values


def _secret_needles(tree: list[_Node], secrets: Sequence[str], facts: PageFacts) -> Needles:
    return _redaction_needles([*secrets, *_field_secrets(tree, facts)])


def _droppable_dup(node: _Node, parent_name: str) -> bool:
    """A non-interactive descendant whose whole text already sits in the
    parent's accessible name (Playwright names links/cells from content)."""
    if node.role.startswith("/") or node.interactive:
        return False
    if node.role == "text":
        return _plain(node.text) in parent_name
    if node.text is not None and _plain(node.text) not in parent_name:
        return False
    if node.name is not None and _plain(node.name) not in parent_name:
        return False
    return all(_droppable_dup(child, parent_name) for child in node.children)


def _dedupe_labels(children: list[_Node]) -> list[_Node]:
    """``<label><input> Remember me</label>`` renders the label text twice:
    as the control's name and as a text sibling. Drop the sibling."""
    out: list[_Node] = []
    for i, node in enumerate(children):
        if node.role == "text":
            plain = _plain(node.text)
            neighbours = children[i - 1 : i] + children[i + 1 : i + 2]
            if any(n.interactive and n.name and plain in _plain(n.name) for n in neighbours):
                continue
        out.append(node)
    return out


def _prune(
    nodes: list[_Node],
    *,
    account_mode: bool,
    needles: Needles,
    facts: PageFacts,
) -> list[_Node]:
    """*needles* comes from ``_secret_needles``: typed secrets plus the
    values of every secret field on the page, in all rendered forms."""
    out: list[_Node] = []
    for node in nodes:
        if node.marker("aria-hidden") is not None:
            continue
        if node.role == "iframe":
            if facts.external_frames is None or node.ref in facts.external_frames:
                origin = (facts.external_frames or {}).get(node.ref or "") or "unknown origin"
                out.append(
                    _Node(
                        node.depth,
                        "iframe",
                        None,
                        [m for m in node.markers if m[0] == "ref"],
                        f"[external tool frame: {origin}, not shown]",
                    )
                )
                continue
        if not account_mode and _is_sr_only(node):
            continue
        name = _redact_text(node.name, needles)
        if node.role == "/url" and node.text is not None:
            text: Optional[str] = strip_url(node.text, account_mode)
        else:
            text = node.text
        secret_field = _is_secret_field(node, facts)
        if secret_field:
            text = REDACTED
        text = _redact_text(text, needles)
        # A secret <select> shows its value as the [selected] option.
        children = (
            []
            if secret_field
            else _dedupe_labels(
                _prune(node.children, account_mode=account_mode, needles=needles, facts=facts)
            )
        )
        if name and node.role not in _WRAPPER_ROLES:
            plain_name = _plain(name)
            children = [c for c in children if not _droppable_dup(c, plain_name)]
        is_wrapper = (
            node.role in _WRAPPER_ROLES
            and not name
            and text is None
            and node.marker("cursor") != "pointer"
        )
        if is_wrapper:
            out.extend(children)
            continue
        out.append(replace(node, name=name, text=text, children=children))
    return out


# -- selection and rendering ----------------------------------------------


def _render_key(node: _Node) -> str:
    key = node.role
    if node.name:
        key += f" {node.name}"
    for k, v in node.markers:
        if k == "box":
            continue
        key += f" [{k}]" if v is None else f" [{k}={v}]"
    if _KEY_SEP_RE.search(key):
        key = "'" + key.replace("'", "''") + "'"
    return key


def _render(node: _Node, depth: int, has_children: bool) -> str:
    if node.role == "text" or node.role.startswith("/"):
        return f"{'  ' * depth}- {node.role}: {node.text}"
    line = f"{'  ' * depth}- {_render_key(node)}"
    if node.text is not None:
        line += f": {node.text}"
    elif has_children:
        line += ":"
    return line


def _in_viewport(node: _Node, height: int, inherited: bool) -> bool:
    box = node.box
    if box is None:
        return inherited
    _x, y, _w, h = box
    if h == 0:
        return inherited
    return y < height and y + h > 0


def _select(
    nodes: list[_Node],
    *,
    depth: int,
    full: bool,
    query: Optional[str],
    height: int,
    inherited: bool,
) -> list[str]:
    lines: list[str] = []
    for node in nodes:
        visible = _in_viewport(node, height, inherited)
        line = _render(node, depth, bool(node.children))
        keep = full or visible or (query is not None and query in line.lower())
        child_lines = _select(
            node.children, depth=depth + 1, full=full, query=query, height=height, inherited=visible
        )
        if keep or child_lines:
            lines.append(line if child_lines or node.text is not None else line.removesuffix(":"))
            lines.extend(child_lines)
    return lines


def _cap(lines: list[str], limit_chars: int) -> tuple[list[str], int, bool]:
    kept: list[str] = []
    chars = 0
    for line in lines:
        extra = len(line) + (1 if kept else 0)
        if chars + extra > limit_chars:
            return kept, chars, True
        kept.append(line)
        chars += extra
    return kept, chars, False


def _count_refs(lines: Sequence[str]) -> int:
    return sum(1 for line in lines if "[ref=" in line)


def filter_yaml(
    raw: str,
    *,
    query: Optional[str] = None,
    full: bool = False,
    account_mode: bool,
    secrets: Sequence[str] = (),
    limit_chars: int = DEFAULT_LIMIT_CHARS,
    facts: PageFacts = UNKNOWN_FACTS,
) -> Outline:
    """Pure: raw ai-mode YAML -> outline fields (url/title left empty).

    The cap is 8000 by default and 24000 for ``full``; an explicit smaller
    ``limit_chars`` is honoured, and nothing can exceed ``FULL_LIMIT_CHARS``.
    """
    limit = FULL_LIMIT_CHARS if full and limit_chars == DEFAULT_LIMIT_CHARS else limit_chars
    limit = min(limit, FULL_LIMIT_CHARS)
    parsed = _parse(raw)
    needles = _secret_needles(parsed, secrets, facts)
    tree = _prune(parsed, account_mode=account_mode, needles=needles, facts=facts)
    lines = _select(
        tree,
        depth=0,
        full=full,
        query=query.lower() if query else None,
        height=facts.viewport[1],
        inherited=True,
    )
    kept, chars, truncated = _cap(lines, limit)
    return Outline("", "", kept, _count_refs(kept), chars, truncated)


def find_lines(
    raw: str,
    text: str,
    *,
    context: bool = True,
    account_mode: bool = True,
    secrets: Sequence[str] = (),
    facts: PageFacts = UNKNOWN_FACTS,
) -> list[str]:
    """Lines matching *text* with their nearest row/listitem/article.

    Searches the whole page (no viewport cut) after the same pruning and
    redaction as the outline, so ``find("password")`` is not a side door.
    """
    needle = text.lower()
    parsed = _parse(raw)
    needles = _secret_needles(parsed, secrets, facts)
    tree = _prune(parsed, account_mode=account_mode, needles=needles, facts=facts)
    blocks: list[list[str]] = []
    seen: set[int] = set()

    def walk(node: _Node, ancestors: list[_Node]) -> None:
        if needle in _render(node, 0, False).lower():
            root = node
            if context:
                for candidate in reversed(ancestors):
                    if candidate.role in _CONTEXT_ROLES:
                        root = candidate
                        break
            if id(root) not in seen:
                seen.add(id(root))
                if context:
                    blocks.append(
                        _select([root], depth=0, full=True, query=None, height=0, inherited=True)
                    )
                else:
                    blocks.append([_render(node, 0, False).rstrip(":")])
        for child in node.children:
            walk(child, ancestors + [node])

    for root in tree:
        walk(root, [])
    lines = [line for block in blocks[:FIND_MAX_BLOCKS] for line in block]
    if len(blocks) > FIND_MAX_BLOCKS:
        lines.append(f"[+{len(blocks) - FIND_MAX_BLOCKS} more matches; refine the text]")
    return lines


def strip_url(url: str, account_mode: bool) -> str:
    """ACCOUNT mode: query string and fragment removed (they carry tokens,
    search terms and student ids); PUBLIC mode: unchanged (flight deep
    links live in the query). Both modes drop ``user:password@`` userinfo:
    it is a credential, never navigation state."""
    parts = urlsplit(url)
    netloc = _host_port(parts.netloc)
    if not account_mode:
        if netloc == parts.netloc:
            return url
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _host_port(netloc: str) -> str:
    return netloc.rpartition("@")[2]


def host_path(url: str) -> str:
    """``host/path`` without scheme, userinfo, query or fragment: the form
    every toolkit-written one-liner uses, so the runtime keeps one format."""
    parts = urlsplit(url)
    target = _host_port(parts.netloc) + (parts.path if parts.path != "/" else "")
    return target if len(target) <= 80 else target[:79] + "…"


def _label(args: Mapping[str, Any]) -> str:
    for key in ("name", "text", "query", "url", "direction", "reason"):
        value = args.get(key)
        if value:
            value = host_path(str(value)) if key == "url" else str(value)
            if len(value) > 40:
                value = value[:39] + "…"
            return f'"{value}"' if key in ("name", "text", "query", "reason") else value
    if args.get("index") is not None:
        return str(args["index"])
    return str(args.get("ref") or "")


def summarize(
    action: str, args: Mapping[str, Any], outline: Outline, *, step: Optional[int] = None
) -> str:
    """One toolkit-written line that replaces an old observation."""
    head = f"[step {step}] " if step is not None else ""
    label = _label(args)
    tail = f"{host_path(outline.url)} · {outline.refs} refs"
    if outline.truncated:
        tail += " · truncated"
    return f"{head}{action}{' ' + label if label else ''} → {tail}"


# -- live page ---------------------------------------------------------------


async def page_facts(page: Any, raw: str) -> PageFacts:
    """Ask the page what the YAML hides. Fails closed on any error."""
    size = page.viewport_size or {}
    viewport = (
        int(size.get("width") or DEFAULT_VIEWPORT[0]),
        int(size.get("height") or DEFAULT_VIEWPORT[1]),
    )
    iframes: list[str] = []
    fields: list[str] = []

    def collect(nodes: list[_Node]) -> None:
        for node in nodes:
            if node.ref:
                if node.role == "iframe":
                    iframes.append(node.ref)
                elif node.role in _FIELD_ROLES and _has_value(node):
                    fields.append(node.ref)
            collect(node.children)

    collect(_parse(raw))

    async def gather() -> tuple[dict[str, str], dict[str, str]]:
        frame_infos = await asyncio.gather(
            *(page.locator(f"aria-ref={ref}").evaluate(_IFRAME_FACTS_JS) for ref in iframes)
        )
        kinds = await asyncio.gather(
            *(page.locator(f"aria-ref={ref}").evaluate(_FIELD_FACTS_JS) for ref in fields)
        )
        external = {
            ref: (info.get("origin") or "unknown origin")
            for ref, info in zip(iframes, frame_infos, strict=True)
            if not info.get("same")
        }
        secret = {ref: kind for ref, kind in zip(fields, kinds, strict=True) if kind}
        return external, secret

    try:
        external, secret = await asyncio.wait_for(gather(), FACTS_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 - unknown facts fail closed
        logger.warning("browser_page_facts_failed", error=type(exc).__name__)
        return PageFacts(viewport=viewport)
    return PageFacts(viewport=viewport, external_frames=external, secret_fields=secret)


async def snapshot_raw(page: Any) -> str:
    """The one place the raw snapshot is taken; refs are valid until the
    next snapshot of any kind (Playwright keeps only the last one).

    The snapshot waits for the document of every iframe it shows, and a
    lazy one far below the fold (``loading="lazy"``, a video embed) has
    none until it is scrolled to: Playwright's 30 s default then ran out
    on every look at the page. While a frame has no document (URL "") the
    page's lazy frames are told to load now, as scrolling to them would,
    and the wait is bounded (SNAPSHOT_TIMEOUT_MS) either way: a frame
    still without a document is left out of the outline."""
    main = getattr(page, "main_frame", None)
    if main is not None and any(frame is not main and not frame.url for frame in page.frames):
        try:
            await asyncio.wait_for(main.evaluate(_LOAD_LAZY_FRAMES_JS), FACTS_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001 - the bounded snapshot still answers
            logger.debug("browser_lazy_frames_failed", error=type(exc).__name__)
    return await page.locator("body").aria_snapshot(mode="ai", boxes=True, timeout=SNAPSHOT_TIMEOUT_MS)


async def outline(
    page: Any,
    *,
    query: Optional[str] = None,
    full: bool = False,
    account_mode: bool,
    secrets: Sequence[str] = (),
    limit_chars: int = DEFAULT_LIMIT_CHARS,
) -> Outline:
    raw = await snapshot_raw(page)
    facts = await page_facts(page, raw)
    filtered = filter_yaml(
        raw,
        query=query,
        full=full,
        account_mode=account_mode,
        secrets=secrets,
        limit_chars=limit_chars,
        facts=facts,
    )
    # The URL (a GET form puts field values in the query) and the title are
    # page-controlled too: the same secrets are redacted there, before the
    # title is cut so a truncation can never leave half a secret behind.
    needles = _secret_needles(_parse(raw), secrets, facts)
    url = _redact_text(strip_url(page.url, account_mode), needles) or ""
    title = (_redact_text(await page.title(), needles) or "")[:200]
    return replace(filtered, url=url, title=title)


async def find(
    page: Any, text: str, *, account_mode: bool, secrets: Sequence[str] = ()
) -> list[str]:
    """Live twin of ``find_lines``: the same pruning and redaction."""
    raw = await snapshot_raw(page)
    facts = await page_facts(page, raw)
    return find_lines(raw, text, account_mode=account_mode, secrets=secrets, facts=facts)
