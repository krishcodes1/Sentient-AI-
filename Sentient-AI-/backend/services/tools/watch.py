"""Implements the watch.* built-in tools (create, list and delete the caller's
page watches) and the guarded fetch that turns a watched page into a
normalised text snapshot and its hash.

Why it exists: The tool registry dispatches watch.* here with the caller's
identity, and the page-watch sweeper fetches through the same function, so
the URL rules (http(s) only, guard-checked, length-capped), the per-user
limits and the fetch limits (guarded client, size cap, timeout, HTML only)
live in one place.

Page watch: "tell me on Telegram when this page changes".

The agent saves a watch; the sweeper in
``services.notifications.page_watch`` checks it on schedule and sends the
owner a deterministic message (no model call) when the page's readable text
changes. Four constraints shape the module:

- **Ownership.** ``user_id`` is the caller's identity as the executor knows
  it, never a tool argument. A foreign or unknown id reads as "not found".
- **Egress.** A watch is standing background egress, so the URL is held to
  the network policy when it is saved (``validated_addresses``: http(s),
  no private or loopback address) and every check goes through
  ``build_guarded_client`` (SSRF check and DNS pinning on every hop), with a
  timeout, a body cap and HTML only.
- **Trust.** Page text is untrusted data. It is hashed and excerpted, never
  returned to the model by these tools and never used to decide anything
  but "did it change".
- **The approval card.** create and delete run only after the owner
  approves the card, and the card must show the whole URL: ``precheck``
  refuses, before any card, arguments that could never run or would not fit
  on it, and ``describe`` states the card's sentence from the arguments.

Tool errors are results, not exceptions.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlsplit

import httpx
import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from services.agent.prompt_guard import _INVISIBLE_CHARS
from services.tools.html_text import extract_readable_text
from services.tools.net import (
    AddressResolver,
    EgressBlocked,
    build_guarded_client,
    validated_addresses,
)

logger = structlog.get_logger(__name__)

MIN_INTERVAL_MINUTES = 30
MAX_INTERVAL_MINUTES = 7 * 24 * 60
DEFAULT_INTERVAL_MINUTES = 60
MAX_WATCHES_PER_USER = 20
# The page_watches columns are these sizes (models/page_watch.py).
URL_MAX_CHARS = 500
LABEL_MAX_CHARS = 80

# The part of the last snapshot kept for the change summary. The hash
# decides whether a page changed; this only says roughly what changed.
EXCERPT_CHARS = 2000
# Ends an excerpt that stopped before the page did, so the summary can tell
# "the page ended here" from "Crawler stopped keeping it here".
EXCERPT_CUT_MARK = "…"

# Same honest identity as web.fetch_page (see services/tools/web.py).
USER_AGENT = "CrawlerAI/0.1 (+https://github.com/krishcodes1/Sentient-AI-)"
FETCH_TIMEOUT_S = 15.0
MAX_BODY_BYTES = 1024 * 1024
_HTML_TYPES = ("text/html", "application/xhtml+xml")
_MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9.+-]{0,40}/[a-z0-9][a-z0-9.+-]{0,60}")

# Telegram's approval card shows a call's arguments as indented JSON cut at
# 700 characters (services/notifications/telegram.py, _short_json). A watch
# whose arguments would be cut is refused before the card, so the owner
# always sees the whole URL they approve.
_CARD_ARGUMENT_CHARS = 690
# A URL is plain printable ASCII: nothing the card's JSON would escape or a
# reader could mistake. The class is "!" to "~" without the double quote,
# the backslash and the angle brackets, so no spaces or control characters.
_URL_CHARS_RE = re.compile(r"[!#-;=?-\[\]-~]+")
_LIST_URL_CHARS = 150
_LIST_ERROR_CHARS = 100
# watch.list keeps its rows, as the model is shown them, within this many
# characters, so RESULT_CHAR_BUDGETS["watch.list"] (services/agent/runtime.py)
# holds the whole list and the runtime never cuts watches, and the ids
# watch.delete needs, out of its middle; raise both together. Twenty rows at
# their longest (an 80-character label of quotes, each escaped, the URL cut
# at 150, an error cut at 100) come to about 13600; only a label of
# invisible characters, each shown as a \uXXXX escape, can go past this.
LIST_ROWS_CHARS = 14_000
# Unicode LINE SEPARATOR and PARAGRAPH SEPARATOR: line breaks in a label.
_LINE_SEPARATORS = (chr(0x2028), chr(0x2029))


class WatchFetchError(Exception):
    """A check that could not read the page. The message is this module's
    own short sentence (safe to store and show), never text from the page."""


@dataclass(frozen=True)
class PageSnapshot:
    """One check's result: the page's normalised readable text and its hash."""

    text: str
    digest: str


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _not_found() -> dict[str, Any]:
    return _error("Page watch not found. Call watch.list for the ids.", not_found=True)


def _utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes for timezone-aware columns; every
    # value written here is UTC, so that is the only reading of a naive one.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return _utc(value).isoformat(timespec="seconds") if value is not None else None


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _shown_chars(value: Any) -> int:
    """*value*'s size as the runtime shows it to the model: compact JSON,
    non-ASCII kept, and invisible characters back in their escaped form."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return len(_INVISIBLE_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], text))


# -- Snapshots -----------------------------------------------------------------


def normalise_text(text: str) -> str:
    """Collapse whitespace inside lines and drop blank lines, so re-flowed
    markup or a stray space does not read as a change."""
    lines = (" ".join(line.split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def snapshot_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def excerpt(text: str, limit: int = EXCERPT_CHARS) -> str:
    """The first whole lines of *text* that fit in *limit* characters, with
    ``EXCERPT_CUT_MARK`` on a line of its own when the text went on."""
    if len(text) <= limit:
        return text
    kept: list[str] = []
    size = 0
    for line in text.split("\n"):
        extra = len(line) + (1 if kept else 0)
        if size + extra > limit:
            if not kept:
                kept.append(line[:limit])
            break
        kept.append(line)
        size += extra
    return "\n".join(kept + [EXCERPT_CUT_MARK])


def _media_type(header: str) -> str:
    media = header.split(";", 1)[0].strip().lower()
    # The header is the remote server's text: keep it only when it is a
    # plain media type, so nothing else reaches a stored error or the model.
    return media if _MEDIA_TYPE_RE.fullmatch(media) else "unknown"


async def fetch_snapshot(
    url: str,
    *,
    resolver: AddressResolver = validated_addresses,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    timeout_s: float = FETCH_TIMEOUT_S,
) -> PageSnapshot:
    """Fetch *url* through the guarded client and return its snapshot.

    Raises ``WatchFetchError`` for anything that is not a readable HTML page
    within the limits. *resolver* and *transport* are the seams tests use;
    the network policy still runs in front of a mock transport.
    """
    try:
        client = build_guarded_client(
            timeout_s=timeout_s,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
            resolver=resolver,
            transport=transport,
        )
    except EgressBlocked as exc:
        raise WatchFetchError("The network security policy refused the connection.") from exc

    try:
        async with client:
            async with client.stream("GET", url) as response:
                if response.status_code >= 400:
                    raise WatchFetchError(f"The page answered HTTP {response.status_code}.")
                media = _media_type(response.headers.get("content-type") or "")
                if media not in _HTML_TYPES:
                    raise WatchFetchError(f"The page is not HTML (it is '{media}').")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY_BYTES:
                        # A page past the cap is compared on its first part.
                        break
                encoding = response.charset_encoding or "utf-8"
    except EgressBlocked as exc:
        raise WatchFetchError("The address is not allowed by the network security policy.") from exc
    except httpx.TimeoutException as exc:
        raise WatchFetchError("The page did not answer in time.") from exc
    except httpx.TooManyRedirects as exc:
        raise WatchFetchError("The page redirected too many times.") from exc
    except httpx.HTTPError as exc:
        raise WatchFetchError(f"The request failed ({type(exc).__name__}).") from exc

    # Parsing up to a megabyte of markup is CPU work; the sweeper shares the
    # event loop with every chat, so it runs in a thread.
    return await asyncio.to_thread(_snapshot_of, b"".join(chunks)[:MAX_BODY_BYTES], encoding)


def _snapshot_of(raw: bytes, encoding: str) -> PageSnapshot:
    try:
        body = raw.decode(encoding, errors="replace")
    except LookupError:
        # An unknown charset name from the server.
        body = raw.decode("utf-8", errors="replace")
    _title, text = extract_readable_text(body)
    text = normalise_text(text)
    return PageSnapshot(text=text, digest=snapshot_digest(text))


# -- Argument rules ------------------------------------------------------------


def _clean_url(value: Any) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(value, str) or not value.strip():
        return None, "A 'url' is required: the absolute http(s) address of the page."
    url = value.strip()
    if len(url) > URL_MAX_CHARS:
        return None, f"The url is too long ({len(url)} chars; max {URL_MAX_CHARS})."
    if not _URL_CHARS_RE.fullmatch(url):
        return None, (
            "The url must be plain ASCII with no spaces, quotes or angle brackets; "
            "percent-encode anything else."
        )
    try:
        parts = urlsplit(url)
        # urlsplit checks the port only when it is read.
        _port = parts.port
    except ValueError:
        return None, "The url is malformed."
    if parts.scheme.lower() not in ("http", "https"):
        return None, "Only http:// and https:// pages can be watched."
    if not parts.hostname:
        return None, "The url has no host."
    if parts.username is not None or parts.password is not None:
        return None, "The url must not carry a username or password."
    return url, None


def _clean_label(value: Any) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(value, str) or not value.strip():
        return None, (
            "A short 'label' is required: what the page is, as the alert "
            "should name it (e.g. 'Fall course schedule')."
        )
    # Checked before spaces are collapsed: a line break or a tab is refused,
    # not quietly turned into something the card never showed.
    if any(ord(ch) < 32 or 0x7F <= ord(ch) < 0xA0 or ch in _LINE_SEPARATORS for ch in value):
        return None, "The label must be one line with no control characters."
    label = " ".join(value.split())
    if len(label) > LABEL_MAX_CHARS:
        return None, f"The label is too long ({len(label)} chars; max {LABEL_MAX_CHARS})."
    return label, None


def _clean_interval(value: Any) -> tuple[Optional[int], Optional[str]]:
    if value is None:
        return DEFAULT_INTERVAL_MINUTES, None
    if isinstance(value, bool):
        return None, "'interval_minutes' must be a whole number of minutes."
    if isinstance(value, float):
        if not value.is_integer():
            return None, "'interval_minutes' must be a whole number of minutes."
        value = int(value)
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return None, "'interval_minutes' must be a whole number of minutes."
    if not MIN_INTERVAL_MINUTES <= minutes <= MAX_INTERVAL_MINUTES:
        return None, (
            f"'interval_minutes' must be between {MIN_INTERVAL_MINUTES} and "
            f"{MAX_INTERVAL_MINUTES} (a week)."
        )
    return minutes, None


@dataclass(frozen=True)
class WatchRequest:
    url: str
    label: str
    interval_minutes: int


def validate_create(params: dict[str, Any]) -> tuple[Optional[WatchRequest], Optional[str]]:
    """The rules for a new watch that need no network or database: the
    toolkit applies them before saving, and the executor before a card."""
    unknown = sorted(set(params) - {"url", "label", "interval_minutes"})
    if unknown:
        return None, f"Unknown argument(s) for watch.create: {', '.join(unknown)}."
    url, err = _clean_url(params.get("url"))
    if err or url is None:
        return None, err
    label, err = _clean_label(params.get("label"))
    if err or label is None:
        return None, err
    interval, err = _clean_interval(params.get("interval_minutes"))
    if err or interval is None:
        return None, err
    try:
        card = json.dumps(params, indent=2, default=str)
    except (TypeError, ValueError):
        return None, "The arguments could not be shown on the approval card."
    if len(card) > _CARD_ARGUMENT_CHARS:
        return None, (
            "The url and label are too long to show in full on the approval "
            "card; use a shorter label."
        )
    return WatchRequest(url=url, label=label, interval_minutes=interval), None


def _watch_uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


def _no_factory() -> Any:
    raise RuntimeError("no database session factory")


def _host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


class WatchToolkit:
    """Executes the built-in ``watch.*`` actions for one caller.

    ``session_factory`` is the application's async session factory; without
    one every action is refused (fail closed). ``resolver`` is the network
    policy check a new URL must pass (tests hand in a DNS stand-in).
    """

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        *,
        resolver: AddressResolver = validated_addresses,
    ) -> None:
        self._session_factory = session_factory
        self._resolver = resolver

    # -- Dispatch ------------------------------------------------------------

    def _handlers(self) -> dict[str, Callable[..., Awaitable[dict[str, Any]]]]:
        return {"create": self.create, "list": self.list, "delete": self.delete}

    async def execute(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """Run one ``watch.*`` action as *user_id*. Unknown actions fail closed."""
        handler = self._handlers().get(action)
        if handler is None:
            return _error(f"Unknown watch action '{action}'.")

        # The owner is whoever the executor says is calling. A user_id the
        # model put in the arguments is dropped, not honored.
        params = {k: v for k, v in (params or {}).items() if k != "user_id"}
        try:
            inspect.signature(handler).bind(user_id, **params)
        except TypeError as exc:
            return _error(f"Invalid arguments for watch.{action}: {exc}")

        try:
            return await handler(user_id, **params)
        except SQLAlchemyError as exc:
            logger.error("watch_tool_db_error", action=action, error_type=type(exc).__name__)
            return _error("Page watch storage is unavailable; try again shortly.")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error(
                "watch_tool_unexpected_error", action=action, error_type=type(exc).__name__
            )
            return _error(f"Page watch action failed: {type(exc).__name__}")

    # -- Approval card hooks (sync: no network, no database) -----------------

    def precheck(self, action: str, params: dict[str, Any]) -> Optional[dict[str, Any]]:
        """The result a call would get even once approved, when that is
        knowable without the network or the database; None otherwise.

        Judged on the arguments exactly as the card would show them, so any
        extra key (a ``user_id`` included) is refused here rather than shown
        to the owner and then dropped."""
        params = dict(params or {})
        if action == "create":
            _request, err = validate_create(params)
            return _error(err, refused=True) if err else None
        if action == "delete":
            if set(params) - {"watch_id"}:
                return _error("watch.delete takes only 'watch_id'.", refused=True)
            if _watch_uuid(params.get("watch_id")) is None:
                return {**_not_found(), "refused": True}
        return None

    def describe(self, action: str, params: dict[str, Any]) -> Optional[str]:
        """The approval card's sentence, from the arguments; None when they
        do not make a valid call (the card then keeps its generic line)."""
        params = dict(params or {})
        if action == "create":
            request, err = validate_create(params)
            if err or request is None:
                return None
            return (
                f'Watch "{request.label}" ({_host(request.url)}) every '
                f"{request.interval_minutes} minutes and message you on Telegram "
                "when its text changes. Full address below."
            )
        if action == "delete":
            target = _watch_uuid(params.get("watch_id"))
            if target is None:
                return None
            return f"Delete page watch {target}; Crawler stops checking that page."
        return None

    # -- Helpers -------------------------------------------------------------

    def _owner(self, user_id: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(user_id))
        except (TypeError, ValueError):
            return None

    def _ready(
        self, user_id: str
    ) -> tuple[Optional[uuid.UUID], Callable[[], Any], Optional[dict[str, Any]]]:
        """The caller's id and the session factory, or the refusal to return."""
        factory = self._session_factory
        if factory is None:
            return (
                None,
                _no_factory,
                _error("Page watch is not configured (no database session factory)."),
            )
        owner = self._owner(user_id)
        if owner is None:
            return None, factory, _error("Page watch needs a signed-in user.")
        return owner, factory, None

    async def _telegram_linked(self, session: Any, owner: uuid.UUID) -> bool:
        from models.user import User

        chat_id = (
            await session.execute(select(User.telegram_chat_id).where(User.id == owner))
        ).scalar_one_or_none()
        return chat_id is not None

    # -- Actions -------------------------------------------------------------

    async def create(
        self,
        user_id: str,
        url: Any = None,
        label: Any = None,
        interval_minutes: Any = None,
    ) -> dict[str, Any]:
        """Save a watch on *url* for the caller; the first check takes the baseline."""
        owner, factory, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _error("Page watch needs a signed-in user.")
        params: dict[str, Any] = {"url": url, "label": label}
        if interval_minutes is not None:
            params["interval_minutes"] = interval_minutes
        request, err = validate_create(params)
        if err or request is None:
            return _error(err or "Invalid page watch.")

        # The same policy every check will meet, applied now: a page the
        # sweeper could never reach (a private address, a name that does
        # not resolve) is refused rather than saved. getaddrinfo blocks.
        try:
            await asyncio.to_thread(self._resolver, request.url)
        except EgressBlocked as exc:
            return _error(f"That address cannot be watched: {exc}", blocked=True)

        from models.page_watch import PageWatch

        now = datetime.now(timezone.utc)
        watch = PageWatch(
            # Assigned here so the id can be reported without a re-read.
            id=uuid.uuid4(),
            user_id=owner,
            url=request.url,
            label=request.label,
            interval_minutes=request.interval_minutes,
            # Due at once: the sweeper's first check records the baseline.
            next_check_at=now,
            created_at=now,
        )
        async with factory() as session:
            count = (
                await session.execute(
                    select(func.count()).select_from(PageWatch).where(PageWatch.user_id == owner)
                )
            ).scalar_one()
            if count >= MAX_WATCHES_PER_USER:
                return _error(
                    f"You already have {MAX_WATCHES_PER_USER} page watches, the most "
                    "allowed. Delete one first (watch.list shows them)."
                )
            existing = (
                await session.execute(
                    select(PageWatch.id).where(
                        PageWatch.user_id == owner, PageWatch.url == request.url
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                return _error(
                    "That page is already watched.", watch_id=str(existing), duplicate=True
                )
            linked = await self._telegram_linked(session, owner)
            session.add(watch)
            try:
                await session.commit()
            except IntegrityError:
                # Saved by a concurrent call between the check and the commit.
                await session.rollback()
                return _error("That page is already watched.", duplicate=True)

        result: dict[str, Any] = {
            "ok": True,
            "watch_id": str(watch.id),
            "label": request.label,
            "url": request.url,
            "interval_minutes": request.interval_minutes,
            "status": "active",
            "note": (
                "The first check, within about a minute, records the page as it "
                "is now; the user gets a Telegram message when its text changes "
                "after that."
            ),
        }
        if not linked:
            result["telegram_linked"] = False
            result["warning"] = (
                "This account has no linked Telegram chat, so a change will only "
                "show in watch.list until the user links one in Settings → Telegram."
            )
        return result

    async def list(self, user_id: str) -> dict[str, Any]:
        """The caller's watches, oldest first, with when each last changed."""
        owner, factory, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _error("Page watch needs a signed-in user.")

        from models.page_watch import PageWatch, PageWatchStatus

        async with factory() as session:
            rows = (
                (
                    await session.execute(
                        select(PageWatch)
                        .where(PageWatch.user_id == owner)
                        .order_by(PageWatch.created_at, PageWatch.id)
                        .limit(MAX_WATCHES_PER_USER)
                    )
                )
                .scalars()
                .all()
            )
            linked = await self._telegram_linked(session, owner)

        now = datetime.now(timezone.utc)
        watches: list[dict[str, Any]] = []
        used = 0
        for row in rows:
            item: dict[str, Any] = {
                "id": str(row.id),
                "label": row.label,
                "url": _cut(row.url, _LIST_URL_CHARS),
                "interval_minutes": row.interval_minutes,
                "status": row.status.value,
                "last_checked_at": _iso(row.last_checked_at),
                "last_changed_at": _iso(row.last_changed_at),
            }
            if row.status == PageWatchStatus.active:
                item["next_check_in_minutes"] = max(
                    0, round((_utc(row.next_check_at) - now) / timedelta(minutes=1))
                )
            if row.consecutive_errors:
                item["consecutive_errors"] = row.consecutive_errors
            if row.last_error:
                item["last_error"] = _cut(row.last_error, _LIST_ERROR_CHARS)
            size = _shown_chars(item) + 1  # and its comma
            if used + size > LIST_ROWS_CHARS:
                break
            watches.append(item)
            used += size
        result: dict[str, Any] = {
            "ok": True,
            "count": len(rows),
            "telegram_linked": linked,
            "watches": watches,
        }
        if len(watches) < len(rows):
            # Only reachable with labels full of escaped characters; the
            # model must not report the list as complete.
            result["shown"] = len(watches)
            result["note"] = (
                f"Only the oldest {len(watches)} of the user's {len(rows)} watches "
                "fit in this list; the rest have very long labels."
            )
        return result

    async def delete(self, user_id: str, watch_id: Any = None) -> dict[str, Any]:
        """Delete one of the caller's watches; the sweeper stops checking it."""
        owner, factory, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _error("Page watch needs a signed-in user.")
        target = _watch_uuid(watch_id)
        if target is None:
            return _not_found()

        from models.page_watch import PageWatch

        async with factory() as session:
            row = (
                await session.execute(
                    select(PageWatch).where(PageWatch.id == target, PageWatch.user_id == owner)
                )
            ).scalar_one_or_none()
            if row is None:
                return _not_found()
            label, url = row.label, row.url
            await session.delete(row)
            await session.commit()

        return {"ok": True, "watch_id": str(target), "label": label, "url": url, "deleted": True}
