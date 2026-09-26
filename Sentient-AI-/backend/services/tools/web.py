"""Implements the web.* built-in tools: DuckDuckGo search, page fetch as text,
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

``screenshot`` needs Playwright, which is deliberately *not* in
requirements.txt: it pulls a browser download that most deployments do
not want. Without it the action returns an actionable error instead of
raising. To enable it:

    pip install playwright && python -m playwright install chromium

``research`` adds no egress of its own: it runs ``search`` and then
``fetch_page`` on each chosen result, so every page it reads passes the
same guard, caps and text extraction as a single fetch.

Every action is read-only. There is no form submission, no login and no
purchase path in this module, and the permission engine blocks every
non-read category for the ``web`` connector type as a second layer.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import re
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlencode, urlsplit

import httpx
import structlog

# The characters the runtime writes out as visible \uXXXX escapes before it
# shows a result to the model (runtime._wrap_tool_results); a stdlib-only
# module, so importing it here pulls nothing else from the agent package.
from services.agent.prompt_guard import _INVISIBLE_CHARS as _HIDDEN_CHARS
from services.tools.html_text import extract_readable_text, parse_search_results
from services.tools.net import (
    AddressResolver,
    EgressBlocked,
    build_guarded_client,
    validated_addresses,
)

logger = structlog.get_logger(__name__)

# DuckDuckGo's no-JavaScript endpoint: real results, no API key, no
# account. The HTML variant is used over lite/ because it is the one
# that carries snippets.
SEARCH_ENDPOINT = "https://html.duckduckgo.com/html/"

# When DuckDuckGo suspects a bot it answers HTTP 202 with a "select the
# ducks" challenge page instead of results. Parsed as a results page that is
# an empty result set, which tells the model to rephrase a query that was
# fine. These are the challenge page's own markers; they are checked only
# when no results were parsed, so a normal page cannot trip them.
_SEARCH_CHALLENGE_RE = re.compile(r'anomaly-modal|id="challenge-form"|/anomaly\.js', re.IGNORECASE)

# Identify honestly. Wikimedia (and anyone else following the same robot
# policy) answers a browser UA coming from a non-browser TLS stack with
# 403, and serves this one; a spoofed Chrome string buys nothing that a
# truthful one does not, on any host tried.
_USER_AGENT = "CrawlerAI/0.1 (+https://github.com/krishcodes1/Sentient-AI-)"

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

_SCREENSHOT_WIDTH = 1024
_SCREENSHOT_HEIGHT = 768
# Encoded-image ceiling. The runtime stringifies a tool result into the
# follow-up LLM call, so an inline data URL is billed as tokens: base64
# of 128 KiB is already ~45k of them. Anything larger comes back as
# dimensions and a note instead of an image.
_MAX_INLINE_IMAGE_BYTES = 4 * 1024 * 1024

_IMAGE_FORMATS = {"png": "image/png", "jpeg": "image/jpeg"}
_JPEG_QUALITY = 70

_PLAYWRIGHT_INSTALL_HINT = (
    "pip install playwright && python -m playwright install chromium"
)
# Names the capability the way system.install_capability knows it, so the
# model connects "the browser is missing" to the sanctioned fix instead of
# telling the user to run pip themselves.
_MISSING_BROWSER_HINT = (
    "This is the 'browser' capability: call system.install_capability with "
    "name='browser' (the user will be asked to approve the install), or "
    f"install it by hand with: {_PLAYWRIGHT_INSTALL_HINT}"
)

CaptureResult = tuple[bytes, str, int, int]


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


def _shown_length(text: str) -> int:
    """How many characters *text* takes in the JSON the runtime shows the
    model: a line break or a quote is two, and an invisible character
    (a soft hyphen, a zero-width joiner, a Unicode tag letter) is the six
    or twelve of the escape the runtime writes it out as."""
    shown = json.dumps(text, ensure_ascii=False)[1:-1]
    return len(_HIDDEN_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], shown))


def _clip_as_shown(text: str, limit: int) -> str:
    """The longest start of *text* whose shown length is at most *limit*.

    Counting raw characters let a page of short lines (a table, a list)
    come out a third longer than *limit* once escaped, overrun the
    runtime's web.fetch_page budget and lose its middle there instead.
    """
    # Every character shows as at least one, so a text longer than the
    # limit cannot fit, and the whole of a 2 MB page is never escaped.
    if len(text) <= limit and _shown_length(text) <= limit:
        return text
    low, high = 0, min(len(text), limit)
    while low < high:
        middle = (low + high + 1) // 2
        if _shown_length(text[:middle]) <= limit:
            low = middle
        else:
            high = middle - 1
    return text[:low]


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
        research_page_timeout_s: float = _RESEARCH_PAGE_TIMEOUT_S,
    ) -> None:
        self._timeout_s = timeout_s
        self._research_page_timeout_s = research_page_timeout_s
        self._resolver = resolver
        self._transport = transport
        self._capture = capture
        self._playwright_loader = playwright_loader or _load_playwright

    # -- Dispatch ------------------------------------------------------------

    async def execute(
        self,
        action: str,
        params: dict[str, Any],
        *,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> dict[str, Any]:
        """Run one ``web.*`` action. Unknown actions fail closed.

        *cancelled* is the executor's check for the user's Stop on this
        call; research asks it before each page it reads.
        """
        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "search": self.search,
            "fetch_page": self.fetch_page,
            "research": self.research,
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
        except httpx.HTTPError as exc:
            return _error(f"Request failed: {type(exc).__name__}")
        finally:
            _stop_check.reset(token)

    def _client(self) -> httpx.AsyncClient:
        return build_guarded_client(
            timeout_s=self._timeout_s,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept-Language": "en-US,en;q=0.9",
            },
            resolver=self._resolver,
            transport=self._transport,
        )

    # -- Actions -------------------------------------------------------------

    async def search(
        self, query: str, max_results: int = _DEFAULT_RESULTS
    ) -> dict[str, Any]:
        """Search the public web and return compact result rows."""
        query = (query or "").strip()
        if not query:
            return _error("A non-empty 'query' is required.")

        try:
            limit = max(1, min(int(max_results), _MAX_RESULTS))
        except (TypeError, ValueError):
            limit = _DEFAULT_RESULTS

        url = f"{SEARCH_ENDPOINT}?{urlencode({'q': query})}"
        async with self._client() as client:
            response = await client.get(url)

        if response.status_code >= 400:
            return _error(
                f"Search failed with HTTP {response.status_code}.",
                status_code=response.status_code,
            )

        results = parse_search_results(response.text, limit, _SNIPPET_CHARS)
        if not results and (
            response.status_code == 202 or _SEARCH_CHALLENGE_RE.search(response.text)
        ):
            # Not an empty result set: the search engine refused to answer.
            # Solving its challenge is not ours to do, so say what happened.
            logger.warning("web_search_challenged", status_code=response.status_code)
            return _error(
                "The search engine (DuckDuckGo) answered with a human-verification "
                "challenge instead of results, so web search is unavailable for now. "
                "This usually clears on its own after a while. Tell the user; do "
                "not retry or rephrase the search.",
                search_blocked=True,
            )
        if not results:
            # Distinguishable from a network failure on purpose: a zero
            # result set is a fact about the query, and the model should
            # rephrase rather than retry.
            return {"ok": True, "query": query, "results": [], "count": 0}
        return {"ok": True, "query": query, "results": results, "count": len(results)}

    async def fetch_page(self, url: str, max_chars: int = DEFAULT_PAGE_CHARS) -> dict[str, Any]:
        """Fetch a public page and return its readable text."""
        if not url or not isinstance(url, str):
            return _error("A 'url' is required.")

        try:
            limit = max(200, min(int(max_chars), MAX_PAGE_CHARS))
        except (TypeError, ValueError):
            limit = DEFAULT_PAGE_CHARS

        async with self._client() as client:
            async with client.stream("GET", url) as response:
                if response.status_code >= 400:
                    return _error(
                        f"Fetch failed with HTTP {response.status_code}.",
                        status_code=response.status_code,
                        url=str(response.url),
                    )
                content_type = (response.headers.get("content-type") or "").lower()
                if content_type and not content_type.startswith(_READABLE_CONTENT_TYPES):
                    return _error(
                        f"Content type '{content_type.split(';')[0]}' is not readable text.",
                        url=str(response.url),
                    )

                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= _MAX_BODY_BYTES:
                        break
                final_url = str(response.url)
                encoding = response.charset_encoding or "utf-8"

        body = b"".join(chunks).decode(encoding, errors="replace")
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

    async def research(
        self,
        query: str,
        max_sources: int = _RESEARCH_DEFAULT_SOURCES,
        chars_per_source: int = _RESEARCH_DEFAULT_CHARS,
    ) -> dict[str, Any]:
        """Search, then read the top results in parallel as cited excerpts.

        Never raises. A failed search is the call's error; a page that
        fails (HTTP error, not text, a blocked redirect, too slow) is one
        source with ``ok: False`` and an error while the rest still come
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
            found = await self.search(query, max_results=_MAX_RESULTS)
        except EgressBlocked as exc:
            return _error(str(exc), blocked=True)
        except httpx.HTTPError as exc:
            return _error(f"Search failed: {type(exc).__name__}")
        if not found.get("ok"):
            return found

        chosen = await self._admit(_research_candidates(found.get("results") or []), wanted)
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
        sources = await asyncio.gather(
            *(self._read_source(row, limit, gate, stop) for row in chosen)
        )
        return {"ok": True, "query": query, "results": list(sources)}

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
            return source
        final_url = str(page.get("url") or url)
        source["url"] = final_url[:_RESEARCH_URL_CHARS]
        source["host"] = _host_of(final_url)
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
                install=_PLAYWRIGHT_INSTALL_HINT,
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
                f"Screenshots need Playwright, which is not installed. {_MISSING_BROWSER_HINT}"
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
                    f"Playwright is installed but its browser is not. {_MISSING_BROWSER_HINT}"
                ) from exc
            logger.warning("web_screenshot_failed", url=url, error=message)
            raise WebToolError(f"Screenshot failed: {type(exc).__name__}") from exc

        return image, final_url, width, height


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


def _research_candidates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Search rows worth reading, best first: http(s) only, one per host
    ("www." folded in, so a site is not read twice under two names), and
    not a link to a document or media file."""
    picked: list[dict[str, Any]] = []
    seen: set[str] = set()
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
        if parts.path.lower().endswith(_NON_TEXT_SUFFIXES):
            continue
        key = host[4:] if host.startswith("www.") else host
        if key in seen:
            continue
        seen.add(key)
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
