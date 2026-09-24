"""HTML readers for the built-in web tools.

Stdlib ``html.parser`` only. A scraping dependency would buy tidier
selectors at the cost of another package parsing hostile input inside
the agent's process, and neither reader needs more than tag/attribute
events.

Both readers treat their input as hostile markup, never as a document
that follows a schema: unclosed tags, missing attributes and reordered
containers must degrade to fewer results, never to an exception.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

# Content inside these never reads as page text: it is code, chrome, or
# controls. Dropping it is most of what makes a fetched page cheap
# enough to put in front of a model.
_SKIPPED_TAGS = frozenset(
    {
        "script",
        "style",
        "noscript",
        "template",
        "svg",
        "canvas",
        "iframe",
        "form",
        "nav",
        "header",
        "footer",
        "aside",
        "button",
        "select",
        "option",
        "datalist",
    }
)

# Tags whose boundaries are line breaks in the rendered page. Without
# them a whole article collapses into one unreadable line.
_BLOCK_TAGS = frozenset(
    {
        "p",
        "div",
        "br",
        "hr",
        "li",
        "ul",
        "ol",
        "tr",
        "td",
        "th",
        "table",
        "section",
        "article",
        "main",
        "blockquote",
        "pre",
        "figcaption",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
    }
)

_WHITESPACE = re.compile(r"[^\S\n]+")
_BLANK_LINES = re.compile(r"\n{3,}")


class _ReadableTextParser(HTMLParser):
    """Collects the text a reader would see, plus the document title."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str = ""
        self._parts: list[str] = []
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag in _SKIPPED_TAGS:
            self._skip_depth += 1
            return
        if tag == "title":
            self._in_title = True
        if tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED_TAGS:
            # Clamped at zero: a stray close tag for a container that was
            # never opened must not unskip the rest of the document.
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "title":
            self._in_title = False
        if tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
            return
        if self._skip_depth:
            return
        self._parts.append(data)

    @property
    def text(self) -> str:
        collapsed = _WHITESPACE.sub(" ", "".join(self._parts))
        lines = [line.strip() for line in collapsed.split("\n")]
        return _BLANK_LINES.sub("\n\n", "\n".join(line for line in lines if line)).strip()


def extract_readable_text(html: str) -> tuple[str, str]:
    """Return ``(title, text)`` for *html*.

    Malformed markup yields whatever was parseable rather than raising:
    a partial read of a broken page is more useful to the agent than an
    error, and the caller caps the result either way.
    """
    parser = _ReadableTextParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - hostile markup, never fatal
        pass
    return parser.title.strip(), parser.text


class _SearchResultParser(HTMLParser):
    """Reads DuckDuckGo's no-JavaScript result page.

    The markup is keyed on class names (``result__a``, ``result__snippet``)
    rather than on nesting depth, because the surrounding containers
    change far more often than those hooks do.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[dict[str, str]] = []
        self._capture: Optional[str] = None
        self._buffer: list[str] = []
        self._href: str = ""
        self._depth = 0

    @staticmethod
    def _classes(attrs: list[tuple[str, Optional[str]]]) -> set[str]:
        for name, value in attrs:
            if name == "class" and value:
                return set(value.split())
        return set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if self._capture is not None:
            # Inline markup inside a title or snippet (<b>, <span>) is
            # nested, so track depth instead of ending on its close tag.
            self._depth += 1
            return
        classes = self._classes(attrs)
        if "result__a" in classes:
            self._capture = "title"
            self._href = dict(attrs).get("href") or ""
        elif "result__snippet" in classes:
            self._capture = "snippet"
        else:
            return
        self._buffer = []
        self._depth = 0

    def handle_endtag(self, tag: str) -> None:
        if self._capture is None:
            return
        if self._depth:
            self._depth -= 1
            return
        text = " ".join("".join(self._buffer).split())
        if self._capture == "title":
            url = _unwrap_redirect(self._href)
            if url and text:
                self.results.append({"title": text, "url": url, "snippet": ""})
        elif self.results and not self.results[-1]["snippet"]:
            self.results[-1]["snippet"] = text
        self._capture = None
        self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._capture is not None:
            self._buffer.append(data)


def _is_search_engine_host(hostname: Optional[str]) -> bool:
    host = (hostname or "").lower()
    return host == "duckduckgo.com" or host.endswith(".duckduckgo.com")


def _unwrap_redirect(href: str) -> Optional[str]:
    """Resolve a DuckDuckGo click-tracking link to its destination.

    Results are wrapped as ``//duckduckgo.com/l/?uddg=<encoded target>``.
    Sponsored rows are wrapped twice — the target is itself a
    ``duckduckgo.com/y.js`` ad-click URL carrying the real advertiser
    behind more tracking — so unwrapping loops, and anything still
    pointing at the search engine after that is dropped. That is what
    keeps ads out of the results the model reads, and it also drops
    javascript: hrefs and relative links.
    """
    if not href:
        return None
    if href.startswith("//"):
        href = f"https:{href}"

    parsed = urlparse(href)
    for _ in range(3):
        if not _is_search_engine_host(parsed.hostname):
            break
        target = parse_qs(parsed.query).get("uddg")
        if not target or not target[0]:
            return None
        href = target[0]
        parsed = urlparse(href)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if _is_search_engine_host(parsed.hostname):
        return None
    return href


def parse_search_results(html: str, limit: int, snippet_chars: int) -> list[dict[str, Any]]:
    """Parse *html* into at most *limit* ``{title, url, snippet}`` dicts.

    Titles and snippets are cut here rather than at the call site: a
    search result set is one of the few tool payloads the model reads in
    full, so its size has to be bounded before it is ever assembled.
    """
    parser = _SearchResultParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - hostile markup, never fatal
        pass

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in parser.results:
        if result["url"] in seen:
            continue
        seen.add(result["url"])
        results.append(
            {
                "title": result["title"][:140],
                "url": result["url"][:500],
                "snippet": result["snippet"][:snippet_chars],
            }
        )
        if len(results) >= limit:
            break
    return results
