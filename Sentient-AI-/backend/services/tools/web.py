"""Built-in web tools: search, page fetch, screenshot.

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

All three actions are read-only. There is no form submission, no login
and no purchase path in this module, and the permission engine blocks
every non-read category for the ``web`` connector type as a second
layer.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlencode

import httpx
import structlog

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

# Identify honestly. Wikimedia (and anyone else following the same robot
# policy) answers a browser UA coming from a non-browser TLS stack with
# 403, and serves this one; a spoofed Chrome string buys nothing that a
# truthful one does not, on any host tried.
_USER_AGENT = (
    "SentientAI/1.0 (self-hosted personal agent; "
    "+https://github.com/krishcodes1/Sentient-AI-)"
)

_MAX_RESULTS = 10
_DEFAULT_RESULTS = 5
_SNIPPET_CHARS = 200

_DEFAULT_PAGE_CHARS = 4000
_MAX_PAGE_CHARS = 20000
# Read cap for the response body itself. Independent of the character
# cap: a 50 MB page must not be buffered just to throw 99% of it away.
_MAX_BODY_BYTES = 2 * 1024 * 1024

_READABLE_CONTENT_TYPES = ("text/html", "application/xhtml", "text/plain", "text/")

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
    ) -> None:
        self._timeout_s = timeout_s
        self._resolver = resolver
        self._transport = transport
        self._capture = capture
        self._playwright_loader = playwright_loader or _load_playwright

    # -- Dispatch ------------------------------------------------------------

    async def execute(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one ``web.*`` action. Unknown actions fail closed."""
        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "search": self.search,
            "fetch_page": self.fetch_page,
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

        try:
            return await handler(**params)
        except EgressBlocked as exc:
            return _error(str(exc), blocked=True)
        except WebToolError as exc:
            return _error(str(exc))
        except httpx.HTTPError as exc:
            return _error(f"Request failed: {type(exc).__name__}")

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
        if not results:
            # Distinguishable from a network failure on purpose: a zero
            # result set is a fact about the query, and the model should
            # rephrase rather than retry.
            return {"ok": True, "query": query, "results": [], "count": 0}
        return {"ok": True, "query": query, "results": results, "count": len(results)}

    async def fetch_page(
        self, url: str, max_chars: int = _DEFAULT_PAGE_CHARS
    ) -> dict[str, Any]:
        """Fetch a public page and return its readable text."""
        if not url or not isinstance(url, str):
            return _error("A 'url' is required.")

        try:
            limit = max(200, min(int(max_chars), _MAX_PAGE_CHARS))
        except (TypeError, ValueError):
            limit = _DEFAULT_PAGE_CHARS

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
        truncated = len(text) > limit
        if truncated:
            text = text[:limit].rstrip()

        return {
            "ok": True,
            "url": final_url,
            "title": title[:200],
            "text": text,
            "truncated": truncated,
            "chars": len(text),
            **(
                {
                    "note": (
                        f"Truncated to {limit} characters. Request a larger "
                        "max_chars if the answer was cut off."
                    )
                }
                if truncated
                else {}
            ),
        }

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


def _load_playwright() -> Any:
    """Import Playwright's async API, or None when it is not installed."""
    try:
        import playwright.async_api as async_api
    except ImportError:
        return None
    return async_api
