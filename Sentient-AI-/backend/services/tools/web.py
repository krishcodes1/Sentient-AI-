"""Implements the web.* built-in tools: DuckDuckGo and Bing search, page fetch as text,
research (one search plus a parallel read of its top sources), and a
Playwright screenshot.

Why it exists: These are the only tools every user gets without credentials, so
the tool registry dispatches web.* here, where every request goes through the
egress guard and every returned field is capped.

Built-in web tools: search, page fetch, research, screenshot.

These are the only tools every user gets without configuring anything —
they need no credentials, no OAuth and no connector row, because they
only read public pages. That also means they are the tools most likely
to be pointed at a hostile URL, so three constraints shape the module:

- **Egress.** Every request goes through ``services.tools.net``, which
  validates the destination against ``core.network_security`` and pins
  the connection to the addresses that check looked at, on the first hop
  and on every redirect. Private, loopback and link-local stay
  unreachable.
- **Trust.** Nothing fetched here is trusted. Results are returned as
  plain data to the runtime, which scans them on the way to the model.
  This module adds no trust of its own and does no unscanned shortcut.
- **Cost.** Every field that comes back is capped. The user pays per
  token for anything a tool returns, and a page is unbounded input.

``search`` asks the turn's own model provider first when it has a web
search of its own (Gemini with Google Search; ``_search_with_provider``):
the pages that search cited, each with its own address, never the model's
prose. Outside a turn, on any other provider, or when that search fails or
cites nothing, the keyless search below answers as before.

``search`` never reports a bot check as an empty search. When the
endpoint answers with anything but a results page (a status other than
200, or DuckDuckGo's "anomaly" challenge) it asks Bing's plain results
page next, over the same guarded client. When that has no result rows
either, or rows that answer only part of the query (Bing's plain page
answers a long query with the results for its first word alone;
``_off_topic`` is the check), it runs the query in Crawler's own browser,
when the executor hands it one ("Control a browser" is on): the
browser.read session, read tier, behind the same egress guard, one page
load per results page and no clicks. Rows that still answer only part of
the query come back with a ``note`` that says so and what to do next;
with no rows at all the answer is ``blocked`` with what to do instead.

``fetch_page`` answers a site that refuses automated readers (HTTP 401,
403, 429 or 503) with the status and a hint: use another source, or the
browser. ``research`` keeps that hint on a source refused the same way.

``screenshot`` needs Playwright, which is deliberately *not* in
requirements.txt: it pulls a browser download that most deployments do
not want. Without it the action returns an actionable error instead of
raising. To enable it:

    pip install playwright && python -m playwright install chromium

``research`` adds no egress of its own: it runs ``search`` (with its
browser fallback and its ``blocked`` answer) and then ``fetch_page`` on
each chosen result, so every page it reads passes the same guard, caps
and text extraction as a single fetch. Rows the search notes as answering
only part of the query are not read at all.

Every action is read-only. There is no form submission, no login and no
purchase path in this module, and the permission engine blocks every
non-read category for the ``web`` connector type as a second layer.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import re
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Mapping, Optional
from urllib.parse import urlencode, urlsplit

import httpx
import structlog

from services.agent import turn_context
from services.knowledge.text import STOPWORDS
from services.security.egress import shown_to_model
from services.tools.html_text import (
    clean_result_rows,
    extract_readable_text,
    parse_bing_results,
    parse_search_results,
)
from services.tools.net import (
    AddressResolver,
    EgressBlocked,
    build_guarded_client,
    validated_addresses,
)
from services.tools.text_budget import clip_as_shown, shown_length
from services.tools.video.sources import is_youtube_host, is_youtube_url

logger = structlog.get_logger(__name__)

# top10:video_transcripts. Crawler never reads YouTube pages: their text is
# not the video, and YouTube's terms forbid automated access. fetch_page
# answers this for a YouTube link (and for a redirect to one, which the
# client refuses before connecting), and research skips YouTube results.
YOUTUBE_PAGE_POINTER = (
    "This is a YouTube video page; its fetched text is not the video. "
    "Use video.transcript with this link."
)

# DuckDuckGo's no-JavaScript endpoint: real results, no API key, no
# account. The HTML variant is used over lite/ because it is the one
# that carries snippets.
SEARCH_ENDPOINT = "https://html.duckduckgo.com/html/"

# Bing's results page, asked over plain HTTP (the same guarded client) when
# the endpoint above answers with a bot check, which it now does for most
# requests. Bing serves result rows with no JavaScript, so a default
# install, whose "Control a browser" switch is off, can still search.
BING_SEARCH_ENDPOINT = "https://www.bing.com/search"

# Results pages that render for a real browser, tried in order in
# Crawler's own browser when the endpoint above asks for a bot check.
# ``{query}`` is the encoded ``q=...`` pair. Tests point them at the fake
# site (``WebToolkit(search_pages=...)``).
BROWSER_SEARCH_PAGES: tuple[str, ...] = (
    "https://duckduckgo.com/?{query}&ia=web",
    "https://www.bing.com/search?{query}",
)

SEARCH_BLOCKED = (
    "The search engine asked for a bot check, so web search is unavailable right now."
)
SEARCH_BLOCKED_HINT = (
    "Open the site you need and use its links or its own search, or ask the person for "
    "the link. Don't guess addresses."
)

# What the model reads with rows that answer only part of its query
# (_off_topic), and what web.research answers instead of reading such rows.
# Both say what to do next. "The exact name first and in quotes" is the kind
# of query Bing's plain page did answer on topic.
_SEARCH_AGAIN = (
    "Search again with fewer words, with the exact name first and in quotes, or open the "
    "site you need and use its own search. Don't guess addresses."
)
SEARCH_OFF_TOPIC_NOTE = f"These results match only part of the query. {_SEARCH_AGAIN}"
RESEARCH_OFF_TOPIC_NOTE = (
    f"The search results matched only part of the query, so none was read. {_SEARCH_AGAIN}"
)
# Query words that say nothing about the topic, so a good answer need not
# repeat them: the knowledge base's function words, when and where, and the
# parts every address has.
_QUERY_FILLERS = STOPWORDS | {"tonight", "today", "tomorrow", "near", "www", "com", "http", "https"}
_QUERY_WORD = re.compile(r"[^\W_]{3,}")

# What DuckDuckGo serves instead of results when it takes a request for a
# bot: HTTP 202 and an "anomaly" page with a picture challenge ("Select
# all squares containing a duck"). The markers are its markup; the text
# is checked only on a page with no result rows.
_CHALLENGE_MARKERS = ("anomaly-modal", "anomaly.js", 'id="challenge-form"')
_CHALLENGE_TEXT = re.compile(
    r"bots use duckduckgo|complete the following challenge|select all squares|"
    r"unusual traffic|not a robot|verify (that )?you('re| are) (a )?human",
    re.IGNORECASE,
)

# Reads result rows off a results page as a real browser renders it:
# DuckDuckGo's JavaScript page (``result-title-a``) and Bing's
# (``li.b_algo``). Links are read, never followed; ads are left out by the
# selectors and by clean_result_rows afterwards.
_BROWSER_RESULTS_JS = r"""
() => {
  const clean = el => (el ? (el.innerText || el.textContent || '') : '').replace(/\s+/g, ' ').trim();
  const rows = [];
  const add = (link, snippet) => {
    if (rows.length < 30) rows.push({title: clean(link), url: link.href || '', snippet: clean(snippet)});
  };
  document.querySelectorAll('a[data-testid="result-title-a"]').forEach(a => {
    const box = a.closest('article, li');
    add(a, box && box.querySelector('[data-result="snippet"], [data-testid="result-snippet"]'));
  });
  document.querySelectorAll('li.b_algo h2 a').forEach(a => {
    const box = a.closest('li.b_algo');
    add(a, box && box.querySelector('.b_caption p, p[class*="b_lineclamp"], .b_algoSlug'));
  });
  return {
    rows,
    host: location.hostname,
    challenge: !!document.querySelector('[class*="anomaly-modal"], #challenge-form'),
    text: (document.body ? document.body.innerText : '').slice(0, 2000),
  };
}
"""
# Matches once the rows (or DuckDuckGo's challenge) are on the page.
_BROWSER_RESULTS_READY = (
    'a[data-testid="result-title-a"], li.b_algo h2 a, [class*="anomaly-modal"], #challenge-form'
)
# One results page in the browser, load to rows; two pages at most.
_BROWSER_PAGE_TIMEOUT_S = 20.0

# Identify honestly. Wikimedia (and anyone else following the same robot
# policy) answers a browser UA coming from a non-browser TLS stack with
# 403, and serves this one; a spoofed Chrome string buys nothing that a
# truthful one does not, on any host tried.
_USER_AGENT = "CrawlerAI/0.1 (+https://github.com/krishcodes1/Sentient-AI-)"

# The provider's own search (Gemini's Google Search) names each page by a
# redirect link on this host; the page's address is that link's Location.
_PROVIDER_REDIRECT_HOST = "vertexaisearch.cloud.google.com"
# The longest one such link may take to answer.
_PROVIDER_LINK_TIMEOUT_S = 8.0
# In a line the provider's search cited: a markdown link keeps its text
# only; then any address the model wrote itself goes (it invents them: with
# a scheme, starting www., or a host followed by a path), and citation and
# markdown marks with it.
_PROVIDER_MARKDOWN_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_PROVIDER_MARKUP = re.compile(
    r"[a-z][a-z0-9+.-]*://\S+|\bwww\.\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/\S*|\[\d+\]|[*_`#]+",
    re.IGNORECASE,
)
# "Title - what the page has": the first dash set off by spaces; a line
# without one is split at its first colon ("Mission: Impossible - ..." is
# split at the dash).
_PROVIDER_DASH = re.compile(r"\s+[-\u2013\u2014]\s+")
_PROVIDER_COLON = re.compile(r":\s+")

_MAX_RESULTS = 10
_DEFAULT_RESULTS = 5
_SNIPPET_CHARS = 200

DEFAULT_PAGE_CHARS = 4000
# The most page text one fetch returns, counted as the model sees it (see
# _clip_as_shown). It was 20000, but the runtime showed the model only a
# 2000-char head and tail of any result, so a larger max_chars never showed
# more. The runtime now keeps a fetch whole up to its web.fetch_page budget
# (services/agent/runtime.py RESULT_CHAR_BUDGETS), sized from this number;
# raising one means raising the other. 12000 is three times the default
# and about 3400 tokens, so a round that reads three long pages stays near
# 10k tokens.
MAX_PAGE_CHARS = 12000
# Read cap for the response body itself. Independent of the character
# cap: a 50 MB page must not be buffered just to throw 99% of it away.
_MAX_BODY_BYTES = 2 * 1024 * 1024

_READABLE_CONTENT_TYPES = ("text/html", "application/xhtml", "text/plain", "text/")

# What a site answers a reader it takes for a bot: a sign-in wall, a refusal,
# a rate limit, or a bot check served as "unavailable". Asking again gets the
# same answer, so the error carries what still works.
_REFUSED_STATUSES = frozenset({401, 403, 429, 503})
# What every failed page read tells the model to do next, so it answers from the
# search rows it already has instead of retrying a site that will not open.
_USE_SEARCH_INSTEAD = (
    "Don't retry this page. Answer from the search results you already have and name "
    "the source, or say plainly what is still missing."
)
FETCH_REFUSED_HINT = f"This site blocks automated reads. {_USE_SEARCH_INSTEAD}"
# Playwright raises a bare ``Error`` for a page that closes the connection or
# refuses the browser; its reason is this code (``net::ERR_HTTP2_PROTOCOL_ERROR``).
_BROWSER_ERROR_CODE = re.compile(r"net::ERR_[A-Z0-9_]+")

# web.research: one READ call that searches and reads the top results, so
# a comparison costs one tool round instead of a search plus a fetch per
# source. The caps bound the fan-out: at most 8 pages, 4 at a time, each
# on its own clock. The excerpts also share one total, which keeps a full
# result inside the runtime's budget for this tool (RESULT_CHAR_BUDGETS)
# so the model never gets a source cut out of the middle of the payload.
_RESEARCH_MAX_QUERY_CHARS = 300
_RESEARCH_DEFAULT_SOURCES = 5
_RESEARCH_MAX_SOURCES = 8
_RESEARCH_DEFAULT_CHARS = 1200
_RESEARCH_MIN_CHARS = 200
_RESEARCH_MAX_CHARS = 3000
_RESEARCH_TOTAL_CHARS = 10000
_RESEARCH_CONCURRENCY = 4
_RESEARCH_PAGE_TIMEOUT_S = 10.0
_RESEARCH_TITLE_CHARS = 140
_RESEARCH_URL_CHARS = 500
# A link whose path names a document, archive or media file would only be
# refused by fetch_page's content-type check, after taking a source slot
# and a round trip, so research passes over it before the fan-out.
_NON_TEXT_SUFFIXES = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".epub",
    ".zip", ".gz", ".tgz", ".tar", ".7z", ".rar", ".exe", ".msi", ".dmg", ".apk", ".iso",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico", ".tif", ".tiff",
    ".mp3", ".mp4", ".m4a", ".wav", ".ogg", ".avi", ".mov", ".mkv", ".webm",
)  # fmt: skip

# The executor's kill-switch check for the web call in progress, never a
# model argument: execute() sets it around one call and research() asks
# it before each page. A ContextVar because one toolkit serves every
# user's turns at once.
_stop_check: ContextVar[Optional[Callable[[], bool]]] = ContextVar("web_stop_check", default=None)

# top10:file_extraction. A PDF, Word, PowerPoint or Excel response is read
# as sections in the sandboxed document reader (services/files) instead of
# being refused as "not readable text": declared by its content type, or
# sent as a generic binary type and confirmed by its magic bytes. HTML is
# untouched. Reading a document also needs "Read files and documents"
# (the executor binds the document context and the switch is read when a
# document turns up). web.research reads at most two documents per call,
# text layer only, under the WEB_RESEARCH preset (_DocumentBudget).
_DOCUMENT_MIMES = frozenset(
    {
        "application/pdf",
        "application/x-pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
)
# Legacy Office types (.doc, .xls, .ppt) are never read, but they take the
# document path too, so services/files/detect refuses them with its own
# sentence (save it as .docx or PDF; a password-protected file: never send
# the password) rather than "not readable text".
_LEGACY_OFFICE_MIMES = frozenset(
    {"application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint"}
)
_GENERIC_BINARY_MIMES = frozenset(
    {
        "application/octet-stream",
        "binary/octet-stream",
        "application/download",
        "application/force-download",
        "application/x-download",
    }
)
_DOCUMENT_SUFFIXES = (".pdf", ".docx", ".pptx", ".xlsx")
_RESEARCH_MAX_DOCUMENTS = 2
_DOCUMENT_PEEK_BYTES = 1024


class _DocumentBudget:
    """How one web.research call reads documents: the preset and how many
    document sources it still may read."""

    def __init__(self, preset: Any, slots: int) -> None:
        self.preset = preset
        self.left = slots

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


_document_budget: ContextVar[Optional[_DocumentBudget]] = ContextVar(
    "web_document_budget", default=None
)


class _PendingDocument:
    """A document response read into memory, parsed once the connection is
    closed."""

    def __init__(self, data: bytes, name: str, mime: Optional[str], url: str, preset: Any) -> None:
        self.data = data
        self.name = name
        self.mime = mime
        self.url = url
        self.preset = preset

_SCREENSHOT_WIDTH = 1024
_SCREENSHOT_HEIGHT = 768
# Encoded-image ceiling. The runtime stringifies a tool result into the
# follow-up LLM call, so an inline data URL is billed as tokens: base64
# of 128 KiB is already ~45k of them. Anything larger comes back as
# dimensions and a note instead of an image.
_MAX_INLINE_IMAGE_BYTES = 4 * 1024 * 1024

_IMAGE_FORMATS = {"png": "image/png", "jpeg": "image/jpeg"}
_JPEG_QUALITY = 70

# Names the capability the way system.install_capability knows it, so the
# model connects "the browser is missing" to the sanctioned fix, and tells
# it how to put that to the person: in plain words, never the tool name,
# what is passed to it or a command to run (docs/bot-message-style.md).
# There is no pip command here on purpose: the model used to pass it on
# to people who are not developers. The install card (and the Install
# button on the Permissions page) is the way to add the browser.
_MISSING_BROWSER_HINT = (
    "This is the 'browser' capability. To offer the install, call "
    "system.install_capability with name='browser'; the person approves it "
    "first. Ask them in plain words, for example \"I need to add a web browser "
    "first. It's a one-time download of about 150 to 300 MB. Okay?\" Never show "
    "them the tool name, what you pass to it or a command to run."
)

CaptureResult = tuple[bytes, str, int, int]
# Loads one results page in Crawler's own browser and runs a script on it:
# ``(url, script, ready_selector) -> {"ok": True, <what the script
# returned>}``, or an error; ``unavailable`` when the browser may not be
# used (the executor's ``_results_page``).
BrowserPage = Callable[[str, str, str], Awaitable[dict[str, Any]]]


class WebToolError(Exception):
    """Raised for a web-tool failure that is the caller's to report."""


class PlaywrightUnavailable(WebToolError):
    """Raised when screenshots are asked for without a usable browser.

    Separate from a capture that failed: this one is fixed by an install
    command, and saying so is the whole point of the error.
    """


def _error(message: str, **extra: Any) -> dict[str, Any]:
    """Structured failure. Tool errors are results, not exceptions: the
    model has to be able to read what went wrong and try something else."""
    return {"ok": False, "error": message, **extra}


# The shown-length measure and clip moved to services/tools/text_budget.py,
# shared with the document windows (services/files/window.py); these names
# stay for the callers and tests that know them.
_shown_length = shown_length
_clip_as_shown = clip_as_shown


def _challenged(status_code: int, html: str, results: list[dict[str, Any]]) -> bool:
    """True when the endpoint's answer is not a results page: any status
    but 200, DuckDuckGo's anomaly markup, or no rows on a page that reads
    like a bot check. Only then is an empty answer not a real one."""
    if status_code != 200:
        return True
    lowered = html.lower()
    if any(marker in lowered for marker in _CHALLENGE_MARKERS):
        return True
    return not results and _CHALLENGE_TEXT.search(html) is not None


def _off_topic(query: str, rows: list[dict[str, Any]]) -> bool:
    """True when *rows* answer only part of *query*: it has three or more
    topic words (three letters or digits and up, fillers left out) and
    fewer than half of them appear anywhere in the rows' titles, addresses
    and snippets. Bing's plain page answers a long query with the results
    for its first word alone, and those rows are organic and well formed,
    so only their words tell. Fewer than three words say too little."""
    words = set(_QUERY_WORD.findall(query.lower())) - _QUERY_FILLERS
    if len(words) < 3:
        return False
    # A deliberate simplification: a substring count, with no stemming and
    # no ranking. It leans towards "on topic"; a wrong "off topic" costs one
    # browser search or a note that is still true. If it misfires, score
    # each row on its own.
    text = " ".join(f"{row['title']} {row['url']} {row['snippet']}" for row in rows).lower()
    return 2 * sum(word in text for word in words) < len(words)


class WebToolkit:
    """Executes the built-in ``web.*`` actions.

    Every network seam is injectable so tests exercise the real parsing
    and the real egress policy without touching the network:
    ``transport`` replaces the socket layer, ``resolver`` replaces DNS,
    ``capture`` replaces the browser.
    """

    def __init__(
        self,
        *,
        timeout_s: float = 20.0,
        resolver: AddressResolver = validated_addresses,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        capture: Optional[Callable[..., Any]] = None,
        playwright_loader: Optional[Callable[[], Any]] = None,
        search_pages: tuple[str, ...] = BROWSER_SEARCH_PAGES,
        research_page_timeout_s: float = _RESEARCH_PAGE_TIMEOUT_S,
    ) -> None:
        self._timeout_s = timeout_s
        self._research_page_timeout_s = research_page_timeout_s
        self._resolver = resolver
        self._transport = transport
        self._capture = capture
        self._playwright_loader = playwright_loader or _load_playwright
        self._search_pages = search_pages

    # -- Dispatch ------------------------------------------------------------

    async def execute(
        self,
        action: str,
        params: dict[str, Any],
        *,
        browser: Optional[BrowserPage] = None,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> dict[str, Any]:
        """Run one ``web.*`` action. Unknown actions fail closed.

        *browser* and *cancelled* are the executor's, never the model's:
        search's fallback (see ``search``, which research runs too) and the
        check for the user's Stop on this call, which research asks before
        each page it reads. The handlers the arguments are bound to do not
        take them, so no tool argument can stand in for either."""

        async def search(query: str, max_results: int = _DEFAULT_RESULTS) -> dict[str, Any]:
            return await self.search(query, max_results, browser=browser)

        async def research(
            query: str,
            max_sources: int = _RESEARCH_DEFAULT_SOURCES,
            chars_per_source: int = _RESEARCH_DEFAULT_CHARS,
        ) -> dict[str, Any]:
            return await self.research(query, max_sources, chars_per_source, browser=browser)

        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "search": search,
            "fetch_page": self.fetch_page,
            "research": research,
            "screenshot": self.screenshot,
        }
        handler = handlers.get(action)
        if handler is None:
            return _error(f"Unknown web action '{action}'.")

        params = params or {}
        # Bind before calling rather than catching TypeError around the
        # call: a TypeError raised *inside* a handler is a bug and must
        # not be reported to the model as its own bad arguments.
        try:
            inspect.signature(handler).bind(**params)
        except TypeError as exc:
            return _error(f"Invalid arguments for web.{action}: {exc}")

        token = _stop_check.set(cancelled)
        try:
            return await handler(**params)
        except EgressBlocked as exc:
            return _error(str(exc), blocked=True)
        except WebToolError as exc:
            return _error(str(exc))
        except httpx.TimeoutException as exc:
            # Slow is not blocked: only say what to do next (screenshots time out in Playwright, not here).
            return _error(
                f"The site did not answer in time ({type(exc).__name__}).",
                **({"hint": _USE_SEARCH_INSTEAD} if action == "fetch_page" else {}),
            )
        except httpx.HTTPError as exc:
            return _error(f"Request failed: {type(exc).__name__}")
        finally:
            _stop_check.reset(token)

    def _client(self, *, follow_redirects: bool = True) -> httpx.AsyncClient:
        return build_guarded_client(
            timeout_s=self._timeout_s,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept-Language": "en-US,en;q=0.9",
            },
            resolver=_no_youtube(self._resolver),
            transport=self._transport,
            follow_redirects=follow_redirects,
        )

    # -- Actions -------------------------------------------------------------

    async def search(
        self,
        query: str,
        max_results: int = _DEFAULT_RESULTS,
        *,
        browser: Optional[BrowserPage] = None,
    ) -> dict[str, Any]:
        """Search the public web and return compact result rows.

        In a turn whose model provider has a web search of its own, that
        search answers first (``_search_with_provider``,
        ``source: "google"``); the rest is the keyless search, which also
        answers whenever the provider's has nothing.

        An answer that is not a results page (``_challenged``) is never
        reported as an empty search: the query goes to Bing's plain results
        page (``source: "bing"``), then to Crawler's own browser when
        *browser* is given (``source: "browser"``), and when neither has
        result rows it is reported as ``blocked`` with a hint that keeps the
        model from guessing addresses.

        Bing's rows are not taken on trust either: when they answer only
        part of the query (``_off_topic``) the browser is asked as if Bing
        had none, and rows that still answer only part of it, from either,
        come back with a ``note`` saying so and what to do next."""
        query = (query or "").strip()
        if not query:
            return _error("A non-empty 'query' is required.")

        try:
            limit = max(1, min(int(max_results), _MAX_RESULTS))
        except (TypeError, ValueError):
            limit = _DEFAULT_RESULTS

        cited = await self._search_with_provider(query, limit)
        if cited is not None:
            return cited

        url = f"{SEARCH_ENDPOINT}?{urlencode({'q': query})}"
        async with self._client() as client:
            response = await client.get(url)

        status = response.status_code
        results = parse_search_results(response.text, limit, _SNIPPET_CHARS) if status == 200 else []
        if not _challenged(status, response.text, results):
            # A results page. With no rows and nothing that reads as a bot
            # check, the engine searched and found nothing: a fact about
            # the query, so the model may rephrase.
            return {"ok": True, "query": query, "results": results, "count": len(results)}

        logger.warning("web_search_challenged", status_code=status)
        found = await self._search_bing(query, limit)
        if browser is not None and (found is None or _off_topic(query, found["results"])):
            # Bing's rows are kept in case the browser has none.
            found = await self._search_in_browser(query, limit, browser) or found
        if found is None:
            return _error(
                SEARCH_BLOCKED, blocked=True, hint=SEARCH_BLOCKED_HINT, status_code=status
            )
        if _off_topic(query, found["results"]):
            logger.warning("web_search_off_topic", source=found["source"])
            found["note"] = SEARCH_OFF_TOPIC_NOTE
        return found

    async def _search_with_provider(self, query: str, limit: int) -> Optional[dict[str, Any]]:
        """Run *query* on the web search the turn's own model provider has
        (``turn_context.current().search_web``: Gemini's Google Search);
        its rows, or None so the keyless search answers: outside a turn, on
        a provider without one, in an unattended run with no budget left,
        on any failure, and when no cited page has a usable address.

        Only what the search cited comes back, never the model's prose: the
        line each page was cited for (``_provider_row``) and the page's own
        address (``_page_address``). What the call cost is recorded as the
        turn's cost. The provider may also bill each search by itself, on
        top of its tokens; that fee is the provider's and is not counted
        here."""
        turn = turn_context.current()
        if turn is None or turn.search_web is None:
            return None
        if turn.usd_left is not None and turn.usd_left() <= 0:
            return None
        if shown_to_model(query) != query:
            # The query holds something the provider is not shown: a key, or
            # a contact detail the owner hides from the AI provider (the
            # model wrote a placeholder; the real value was put back for
            # the tool). The keyless search takes it, as it always did.
            logger.info("web_search_provider_skipped", why="private_query")
            return None
        try:
            answer = await turn.search_web(query, max_results=limit)
        except Exception as exc:  # noqa: BLE001 - whatever failed, the keyless search still can
            logger.warning("web_search_provider_failed", error_type=type(exc).__name__)
            return None
        if not isinstance(answer, Mapping):
            return None
        usage = answer.get("usage")
        if isinstance(usage, Mapping) and usage:
            turn.record_usage(usage)
        cited = answer.get("sources")
        sources = [s for s in cited if isinstance(s, Mapping)] if isinstance(cited, list) else []
        if not sources:
            return None
        try:
            async with self._client(follow_redirects=False) as client:
                addresses = await asyncio.gather(
                    *(self._page_address(client, source.get("link")) for source in sources)
                )
            rows = clean_result_rows(
                [
                    _provider_row(source, url)
                    for source, url in zip(sources, addresses, strict=True)
                    if url
                ],
                limit,
                _SNIPPET_CHARS,
            )
        except Exception as exc:  # noqa: BLE001 - an address of an odd shape costs the search nothing
            logger.warning("web_search_provider_rows_failed", error_type=type(exc).__name__)
            return None
        if not rows:
            logger.warning("web_search_provider_no_rows", cited=len(sources))
            return None
        return {"ok": True, "query": query, "source": "google", "results": rows, "count": len(rows)}

    async def _page_address(self, client: httpx.AsyncClient, link: Any) -> Optional[str]:
        """The address of the page a provider's search link names, or None.
        A link that is already a page (https, not on the provider's
        redirect host) is that address and is not requested. A redirect
        link is asked once through the guarded client, never followed: the
        page's address is where it points, when that is an http(s) one."""
        if not isinstance(link, str) or not link.startswith("https://"):
            return None
        try:
            if urlsplit(link).hostname != _PROVIDER_REDIRECT_HOST:
                return link
            response = await asyncio.wait_for(client.get(link), _PROVIDER_LINK_TIMEOUT_S)
            target = response.headers.get("location", "") if response.is_redirect else ""
            if not target.startswith(("https://", "http://")):
                return None
            urlsplit(target)  # an address no parser reads is no row
        except (EgressBlocked, httpx.HTTPError, httpx.InvalidURL, TimeoutError, ValueError) as exc:
            # InvalidURL: httpx reads the Location even when it does not follow
            # it. ValueError: a link or a Location that is no address at all.
            logger.warning("web_search_provider_link_failed", error_type=type(exc).__name__)
            return None
        return target

    async def _search_bing(self, query: str, limit: int) -> Optional[dict[str, Any]]:
        """Run *query* on Bing's plain results page; its rows, or None when
        it has none (a bot check, an error, a layout the parser does not
        read, a request that failed), so the search moves on instead of
        reporting an empty one. One GET through the guarded client; the
        result links are unwrapped, never followed."""
        url = f"{BING_SEARCH_ENDPOINT}?{urlencode({'q': query})}"
        try:
            async with self._client() as client:
                response = await client.get(url)
        except (EgressBlocked, httpx.HTTPError) as exc:
            logger.warning("web_search_bing_failed", error_type=type(exc).__name__)
            return None
        status = response.status_code
        rows = parse_bing_results(response.text, limit, _SNIPPET_CHARS) if status == 200 else []
        if not rows:
            logger.warning("web_search_bing_no_rows", status_code=status)
            return None
        return {"ok": True, "query": query, "source": "bing", "results": rows, "count": len(rows)}

    async def _search_in_browser(
        self, query: str, limit: int, browser: BrowserPage
    ) -> Optional[dict[str, Any]]:
        """Run *query* on each of ``search_pages`` in Crawler's own browser
        until one shows result rows; None when the browser may not be used,
        or every page was challenged, empty, did not load or failed. Each
        page is one GET load, bounded by _BROWSER_PAGE_TIMEOUT_S; the result
        links are read off the page and unwrapped, never followed."""
        encoded = urlencode({"q": query})
        for template in self._search_pages:
            try:
                page = await asyncio.wait_for(
                    browser(template.format(query=encoded), _BROWSER_RESULTS_JS, _BROWSER_RESULTS_READY),
                    _BROWSER_PAGE_TIMEOUT_S,
                )
            except TimeoutError:
                logger.warning("web_search_browser_timed_out")
                continue
            except Exception as exc:  # noqa: BLE001 - a browser that fails has no rows
                # It is also asked after an answer Bing did give; raising here
                # would turn that answer into an error.
                logger.warning("web_search_browser_failed", error_type=type(exc).__name__)
                continue
            if page.get("unavailable"):
                return None
            if not page.get("ok"):
                continue
            # A results address can redirect somewhere else (a search
            # engine's own shortcut syntax, an interstitial). Rows are only
            # read off the engine's own page: another site could mark up its
            # page to look like results.
            landed = page.get("host")
            if isinstance(landed, str) and landed and landed != urlsplit(template).hostname:
                logger.warning("web_search_browser_left_engine")
                continue
            rows = clean_result_rows(page.get("rows"), limit, _SNIPPET_CHARS)
            if rows:
                return {
                    "ok": True,
                    "query": query,
                    "source": "browser",
                    "results": rows,
                    "count": len(rows),
                }
            challenged = bool(page.get("challenge")) or bool(
                _CHALLENGE_TEXT.search(str(page.get("text") or ""))
            )
            logger.warning("web_search_browser_no_rows", challenged=challenged)
        return None

    async def fetch_page(self, url: str, max_chars: int = DEFAULT_PAGE_CHARS) -> dict[str, Any]:
        """Fetch a public page and return its readable text."""
        if not url or not isinstance(url, str):
            return _error("A 'url' is required.")
        if is_youtube_url(url.strip()):
            # top10:video_transcripts
            return _error(YOUTUBE_PAGE_POINTER, youtube=True)

        try:
            limit = max(200, min(int(max_chars), MAX_PAGE_CHARS))
        except (TypeError, ValueError):
            limit = DEFAULT_PAGE_CHARS

        async with self._client() as client:
            async with client.stream("GET", url) as response:
                if response.status_code >= 400:
                    refused = response.status_code in _REFUSED_STATUSES
                    return _error(
                        f"Fetch failed with HTTP {response.status_code}.",
                        status_code=response.status_code,
                        url=str(response.url),
                        **({"hint": FETCH_REFUSED_HINT} if refused else {}),
                    )
                content_type = (response.headers.get("content-type") or "").lower()
                # top10:file_extraction: a PDF or Office document is read as
                # sections (_document_body, then _read_document below).
                pending = await self._document_body(response, content_type)
                if isinstance(pending, dict):
                    return pending
                if pending is None and content_type and not content_type.startswith(
                    _READABLE_CONTENT_TYPES
                ):
                    return _error(
                        f"Content type '{content_type.split(';')[0]}' is not readable text.",
                        url=str(response.url),
                    )

                chunks: list[bytes] = []
                size = 0
                if pending is None:
                    async for chunk in response.aiter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= _MAX_BODY_BYTES:
                            break
                final_url = str(response.url)
                encoding = response.charset_encoding or "utf-8"

        if pending is not None:
            # Parsed after the connection is closed: the parse can take the
            # preset's whole deadline.
            return await self._read_document(pending, limit)
        raw = b"".join(chunks)
        try:
            body = raw.decode(encoding, errors="replace")
        except LookupError:
            # The page named a charset Python has no codec for; utf-8 with
            # replacement always decodes rather than 500-ing the fetch.
            body = raw.decode("utf-8", errors="replace")
        title, text = extract_readable_text(body)
        clipped = _clip_as_shown(text, limit)
        truncated = len(clipped) < len(text)
        text = clipped.rstrip() if truncated else text

        # The note only promises what a retry can deliver: up to
        # MAX_PAGE_CHARS the runtime shows the model everything returned
        # here, and past it a larger max_chars returns the same text.
        note: dict[str, str] = {}
        if truncated and limit < MAX_PAGE_CHARS:
            note["note"] = (
                f"Truncated at max_chars={limit}. Request a larger max_chars "
                f"(up to {MAX_PAGE_CHARS}) if the answer was cut off."
            )
        elif truncated:
            note["note"] = (
                f"Truncated at max_chars={limit}, the most web.fetch_page "
                "returns; a larger max_chars will not show more of this page."
            )

        return {
            "ok": True,
            "url": final_url,
            "title": title[:200],
            "text": text,
            "truncated": truncated,
            "chars": len(text),
            **note,
        }

    # -- Documents (top10:file_extraction) ------------------------------------

    async def _document_body(
        self, response: httpx.Response, content_type: str
    ) -> Optional[_PendingDocument | dict[str, Any]]:
        """None when *response* is not a document (the page path goes on);
        a _PendingDocument holding its bytes; or an error result: file
        reading is off, the document is too large, research already read
        its two documents, or a generic binary that is not a document."""
        from services.files import messages as file_messages
        from services.files.context import document_refusal
        from services.files.detect import looks_like_document
        from services.files.limits import WEB_PAGE

        mime = content_type.split(";", 1)[0].strip()
        declared = mime in _DOCUMENT_MIMES or mime in _LEGACY_OFFICE_MIMES
        if not declared and mime not in _GENERIC_BINARY_MIMES:
            return None
        final_url = str(response.url)
        budget = _document_budget.get()
        preset = budget.preset if budget is not None else WEB_PAGE
        stream = response.aiter_bytes()
        head = bytearray()
        if not declared:
            async for chunk in stream:
                head += chunk
                if len(head) >= _DOCUMENT_PEEK_BYTES:
                    break
            if not looks_like_document(bytes(head)):
                return _error(f"Content type '{mime}' is not readable text.", url=final_url)
        refusal = await document_refusal()
        if refusal is not None:
            return _error(refusal, url=final_url, capability="file_reading")
        if budget is not None and not budget.take():
            return _error(
                f"web.research reads at most {_RESEARCH_MAX_DOCUMENTS} documents per call; "
                "open this one with web.fetch_page.",
                url=final_url,
            )
        declared_size = response.headers.get("content-length")
        if declared_size and declared_size.isdigit() and int(declared_size) > preset.max_bytes:
            return _error(
                file_messages.too_large(int(declared_size), preset.max_bytes),
                url=final_url,
                code="too_large",
            )
        data = head
        async for chunk in stream:
            data += chunk
            if len(data) > preset.max_bytes:
                return _error(
                    file_messages.too_large(None, preset.max_bytes), url=final_url, code="too_large"
                )
        name = urlsplit(final_url).path.rsplit("/", 1)[-1] or "document"
        return _PendingDocument(bytes(data), name[:200], mime if declared else None, final_url, preset)

    async def _read_document(self, pending: _PendingDocument, limit: int) -> dict[str, Any]:
        """The document as web.fetch_page returns it: the url, a title, the
        first sections (sized by max_chars, at least WINDOW_MIN_CHARS), a
        doc_id that files.read continues, and how to continue."""
        from services.files.context import current as current_documents
        from services.files.documents import read_document
        from services.files.limits import WINDOW_MIN_CHARS

        bound = current_documents()
        if bound is None:
            from services.files import messages as file_messages

            return _error(file_messages.SWITCHED_OFF, url=pending.url, capability="file_reading")
        result = await read_document(
            pending.data,
            name=pending.name,
            declared_mime=pending.mime,
            source="web",
            preset=pending.preset,
            user_id=bound.user_id,
            max_chars=max(WINDOW_MIN_CHARS, limit),
        )
        if not result.get("ok"):
            return _error(
                str(result.get("error") or "The document could not be read."),
                url=pending.url,
                code=result.get("code"),
            )
        title = str(result.get("title") or result.get("name") or "")[:200]
        document: dict[str, Any] = {"ok": True, "url": pending.url, "title": title}
        for key in (
            "kind",
            "pages_total",
            "sections_total",
            "sections",
            "doc_id",
            "next_start",
            "truncated",
            "scanned_pages_unread",
            "hint",
        ):
            if key in result:
                document[key] = result[key]
        return document

    async def research(
        self,
        query: str,
        max_sources: int = _RESEARCH_DEFAULT_SOURCES,
        chars_per_source: int = _RESEARCH_DEFAULT_CHARS,
        *,
        browser: Optional[BrowserPage] = None,
    ) -> dict[str, Any]:
        """Search, then read the top results in parallel as cited excerpts.

        The search is ``search`` itself, *browser* fallback included, so a
        bot check is answered the same way (``blocked`` with its hint, which
        is returned as the call's error) and never read as no sources. Rows
        it notes as answering only part of the query are not read: the call
        returns no sources and a note with what to do next.

        Never raises. A failed search is the call's error; a page that
        fails (HTTP error, not text, a blocked redirect, too slow) is one
        source with ``ok: False`` and an error (and fetch_page's hint, when
        the site refused the reader) while the rest still come
        back. A result whose host the egress policy refuses is skipped
        before any request and the next result takes its place.

        ``results`` is a top-level list with one dict per source: the shape
        the runtime's per-item scan (``_scan_and_redact_result``) redacts
        one poisoned source in without dropping the others.
        """
        if not isinstance(query, str) or not query.strip():
            return _error("A non-empty 'query' is required.")
        query = query.strip()
        if len(query) > _RESEARCH_MAX_QUERY_CHARS:
            return _error(
                f"The 'query' is limited to {_RESEARCH_MAX_QUERY_CHARS} characters; "
                "shorten it to the key terms."
            )
        wanted = _bounded(max_sources, 1, _RESEARCH_MAX_SOURCES, _RESEARCH_DEFAULT_SOURCES)
        chars = _bounded(
            chars_per_source, _RESEARCH_MIN_CHARS, _RESEARCH_MAX_CHARS, _RESEARCH_DEFAULT_CHARS
        )

        try:
            found = await self.search(query, max_results=_MAX_RESULTS, browser=browser)
        except EgressBlocked as exc:
            return _error(str(exc), blocked=True)
        except httpx.HTTPError as exc:
            return _error(f"Search failed: {type(exc).__name__}")
        if not found.get("ok"):
            return found
        if found.get("note") == SEARCH_OFF_TOPIC_NOTE:
            # The rows answer only part of the query: reading them would
            # spend the call on pages about something else.
            return {"ok": True, "query": query, "results": [], "note": RESEARCH_OFF_TOPIC_NOTE}

        # top10:file_extraction: document links are candidates only while
        # documents may be read in this call (at most two, WEB_RESEARCH).
        from services.files.context import current as current_documents
        from services.files.context import document_refusal
        from services.files.limits import WEB_RESEARCH

        documents = current_documents() is not None and await document_refusal() is None
        chosen = await self._admit(
            _research_candidates(found.get("results") or [], documents=documents), wanted
        )
        if not chosen:
            return {
                "ok": True,
                "query": query,
                "results": [],
                "note": (
                    "The search found no readable sources for this query. "
                    "Try different search terms."
                ),
            }

        limit = min(chars, max(_RESEARCH_MIN_CHARS, _RESEARCH_TOTAL_CHARS // len(chosen)))
        gate = asyncio.Semaphore(_RESEARCH_CONCURRENCY)
        stop = _stop_check.get()
        budget_token = _document_budget.set(
            _DocumentBudget(WEB_RESEARCH, _RESEARCH_MAX_DOCUMENTS) if documents else None
        )
        try:
            sources = await asyncio.gather(
                *(self._read_source(row, limit, gate, stop) for row in chosen)
            )
        finally:
            _document_budget.reset(budget_token)
        return {
            "ok": True,
            "query": query,
            **({"source": found["source"]} if found.get("source") else {}),
            "results": list(sources),
        }

    async def _admit(self, rows: list[dict[str, Any]], wanted: int) -> list[dict[str, Any]]:
        """The first *wanted* of *rows*, best first, whose host passes the
        egress policy. Checked in rank order, a batch at a time, so a
        refused result is replaced by the next one down.

        This only picks what to read. The guarded client checks and pins
        every hop again when the page is fetched, so a pass here grants
        nothing on its own.
        """
        admitted: list[dict[str, Any]] = []
        pending = list(rows)
        while pending and len(admitted) < wanted:
            need = wanted - len(admitted)
            batch, pending = pending[:need], pending[need:]
            verdicts = await asyncio.gather(*(self._admissible(row["url"]) for row in batch))
            admitted.extend(row for row, ok in zip(batch, verdicts, strict=True) if ok)
        return admitted

    async def _admissible(self, url: str) -> bool:
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._resolver, url), self._research_page_timeout_s
            )
        except Exception:  # noqa: BLE001 - refused, unresolvable or slow: all a skip
            return False
        return True

    async def _read_source(
        self,
        row: dict[str, Any],
        limit: int,
        gate: asyncio.Semaphore,
        stop: Optional[Callable[[], bool]],
    ) -> dict[str, Any]:
        """Read one chosen result through fetch_page; never raises."""
        url = row["url"]
        source: dict[str, Any] = {
            "title": str(row.get("title") or "")[:_RESEARCH_TITLE_CHARS],
            "url": url[:_RESEARCH_URL_CHARS],
            "host": _host_of(url),
            "excerpt": "",
            "ok": False,
        }
        async with gate:
            if _stop_requested(stop):
                source["error"] = "Stopped before this page was read."
                return source
            try:
                page = await asyncio.wait_for(
                    self.fetch_page(url, max_chars=limit), self._research_page_timeout_s
                )
            except asyncio.TimeoutError:
                source["error"] = (
                    f"The page did not load within {self._research_page_timeout_s:g} seconds."
                )
                return source
            except EgressBlocked as exc:
                source["error"] = str(exc)
                return source
            except httpx.HTTPError as exc:
                source["error"] = f"Request failed: {type(exc).__name__}"
                return source
            except Exception as exc:  # noqa: BLE001 - one bad page is a result, not a failed call
                logger.warning(
                    "web_research_page_failed",
                    host=source["host"],
                    error_type=type(exc).__name__,
                )
                source["error"] = f"The page could not be read ({type(exc).__name__})."
                return source

        if not page.get("ok"):
            source["error"] = str(page.get("error") or "The page could not be read.")
            if page.get("hint"):
                # fetch_page's "this site refuses automated readers": without
                # it a call whose sources all refused reads as a dead end.
                source["hint"] = str(page["hint"])
            return source
        final_url = str(page.get("url") or url)
        source["url"] = final_url[:_RESEARCH_URL_CHARS]
        source["host"] = _host_of(final_url)
        if isinstance(page.get("sections"), list):
            # A document: its first sections up to the shared limit, and the
            # doc_id files.read continues (top10:file_extraction).
            source["excerpt"] = _document_excerpt(page["sections"], limit)
            source["doc_id"] = page.get("doc_id")
            source["kind"] = page.get("kind")
        else:
            source["excerpt"] = str(page.get("text") or "")
        source["ok"] = True
        if not source["title"]:
            source["title"] = str(page.get("title") or "")[:_RESEARCH_TITLE_CHARS]
        return source

    async def screenshot(
        self,
        url: str,
        *,
        full_page: bool = False,
        image_format: str = "jpeg",
        width: int = _SCREENSHOT_WIDTH,
        height: int = _SCREENSHOT_HEIGHT,
    ) -> dict[str, Any]:
        """Capture *url* and return it as a data URL.

        Needs Playwright (see the module docstring); returns an error
        describing the install when it is missing, because an optional
        capability that raises reads to the model as a broken platform.
        """
        if not url or not isinstance(url, str):
            return _error("A 'url' is required.")

        image_format = (image_format or "jpeg").lower()
        if image_format not in _IMAGE_FORMATS:
            return _error(
                f"Unsupported image format '{image_format}'. Use png or jpeg."
            )

        # The browser does its own DNS and takes no pin from us, so the
        # policy is applied before launch — and again to the URL the page
        # actually settled on, which is the one a redirect controls.
        await asyncio.to_thread(self._resolver, url)

        capture = self._capture or self._playwright_capture
        try:
            image, final_url, shot_width, shot_height = await capture(
                url,
                full_page=full_page,
                width=int(width),
                height=int(height),
                image_format=image_format,
            )
        except PlaywrightUnavailable as exc:
            return _error(
                str(exc),
                playwright_available=False,
                capability="browser",
            )
        except WebToolError as exc:
            return _error(str(exc))

        if final_url != url:
            await asyncio.to_thread(self._resolver, final_url)

        result: dict[str, Any] = {
            "ok": True,
            "url": final_url,
            "format": image_format,
            "width": shot_width,
            "height": shot_height,
            "bytes": len(image),
        }
        if len(image) > _MAX_INLINE_IMAGE_BYTES:
            result["image_omitted"] = (
                f"The capture is {len(image) // 1024} KB, over the "
                f"{_MAX_INLINE_IMAGE_BYTES // 1024} KB inline limit. Retry with "
                "image_format='jpeg', full_page=false, or a smaller viewport."
            )
            return result

        encoded = base64.b64encode(image).decode("ascii")
        result["image"] = f"data:{_IMAGE_FORMATS[image_format]};base64,{encoded}"
        return result

    # -- Playwright seam -----------------------------------------------------

    async def _playwright_capture(
        self, url: str, *, full_page: bool, width: int, height: int, image_format: str
    ) -> CaptureResult:
        module = self._playwright_loader()
        if module is None:
            raise PlaywrightUnavailable(
                "Screenshots need the web browser add-on (Playwright), which isn't "
                f"installed yet. {_MISSING_BROWSER_HINT}"
            )

        try:
            async with module.async_playwright() as playwright:
                browser = await playwright.chromium.launch()
                try:
                    page = await browser.new_page(
                        viewport={"width": width, "height": height}
                    )
                    await page.goto(url, wait_until="load")
                    options: dict[str, Any] = {
                        "full_page": full_page,
                        "type": image_format,
                    }
                    if image_format == "jpeg":
                        options["quality"] = _JPEG_QUALITY
                    image = await page.screenshot(**options)
                    final_url = page.url
                finally:
                    await browser.close()
        except Exception as exc:  # noqa: BLE001 - browser failures are results
            message = str(exc)
            if "executable doesn't exist" in message.lower():
                raise PlaywrightUnavailable(
                    "The web browser add-on (Playwright) is only partly installed: its "
                    f"browser is missing. {_MISSING_BROWSER_HINT}"
                ) from exc
            logger.warning("web_screenshot_failed", url=url, error=message)
            # The browser's reason is its net:: code; the message around it
            # carries the address, so only the code is kept.
            code = _BROWSER_ERROR_CODE.search(message)
            reason = code.group(0) if code else type(exc).__name__
            raise WebToolError(f"Screenshot failed: {reason}. {_USE_SEARCH_INSTEAD}") from exc

        return image, final_url, width, height


def _provider_row(source: Mapping[str, Any], url: str) -> dict[str, str]:
    """One search row from a page the provider's search cited: the cited
    line up to its first dash (or, with no dash, its first colon) as the
    title and the rest as the snippet; a line without either, or no line
    at all, is the snippet under the site's name. Markdown, citation
    marks, list numbers and any address in the line are dropped, so the
    only address a row carries is *url*, the search's own."""
    line = _PROVIDER_MARKDOWN_LINK.sub(r"\1", str(source.get("text") or ""))
    line = " ".join(_PROVIDER_MARKUP.sub(" ", line).split())
    line = re.sub(r"^(?:\d+[.)]|[-\u2022])\s+", "", line)
    parts = _PROVIDER_DASH.split(line, maxsplit=1)
    if len(parts) != 2:
        parts = _PROVIDER_COLON.split(line, maxsplit=1)
    site = " ".join(str(source.get("site") or "").split()) or _host_of(url)
    if len(parts) == 2 and parts[0] and parts[1]:
        return {"title": parts[0], "url": url, "snippet": parts[1]}
    return {"title": site, "url": url, "snippet": line}


def _bounded(value: Any, low: int, high: int, default: int) -> int:
    """*value* as an int clamped to [low, high]; *default* when it is not one."""
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError, OverflowError):
        return default


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _no_youtube(resolver: AddressResolver) -> AddressResolver:
    """*resolver* refusing every YouTube host, on every hop (a redirect to
    YouTube included), before a socket is opened (top10:video_transcripts)."""

    def resolve(url: str) -> tuple[str, ...]:
        if is_youtube_url(url):
            raise EgressBlocked(YOUTUBE_PAGE_POINTER)
        return resolver(url)

    return resolve


def _document_excerpt(sections: list[Any], limit: int) -> str:
    """A document source's excerpt: its first sections, labelled, up to
    *limit* characters as shown."""
    parts: list[str] = []
    for item in sections:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(f"[{item.get('label') or ''}] {item['text']}".strip())
    return clip_as_shown("\n\n".join(parts), limit).rstrip()


def _research_candidates(
    rows: list[dict[str, Any]], *, documents: bool = False
) -> list[dict[str, Any]]:
    """Search rows worth reading, best first: http(s) only, one per host
    ("www." folded in, so a site is not read twice under two names), and
    not a link to a document or media file. With *documents* (the document
    reader may be used in this call), links to PDF, Word, PowerPoint and
    Excel files stay, at most _RESEARCH_MAX_DOCUMENTS of them; media,
    archives and legacy .doc/.xls/.ppt are skipped either way."""
    picked: list[dict[str, Any]] = []
    seen: set[str] = set()
    document_links = 0
    for row in rows:
        url = row.get("url")
        if not isinstance(url, str):
            continue
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        host = _host_of(url)
        if parts.scheme not in ("http", "https") or not host:
            continue
        if is_youtube_host(host):
            # top10:video_transcripts: a video is read with video.transcript.
            continue
        path = parts.path.lower()
        is_document = documents and path.endswith(_DOCUMENT_SUFFIXES)
        if is_document and document_links >= _RESEARCH_MAX_DOCUMENTS:
            continue
        if not is_document and path.endswith(_NON_TEXT_SUFFIXES):
            continue
        key = host[4:] if host.startswith("www.") else host
        if key in seen:
            continue
        seen.add(key)
        if is_document:
            document_links += 1
        picked.append(row)
    return picked


def _stop_requested(stop: Optional[Callable[[], bool]]) -> bool:
    if stop is None:
        return False
    try:
        return bool(stop())
    except Exception:  # noqa: BLE001 - no answer is not a "carry on"
        logger.warning("web_research_stop_check_failed")
        return True


def _load_playwright() -> Any:
    """Import Playwright's async API, or None when it is not installed."""
    try:
        import playwright.async_api as async_api
    except ImportError:
        return None
    return async_api
