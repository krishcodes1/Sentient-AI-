"""Runs the background sweeper that checks due page watches, compares each
page's readable text with the last snapshot, and tells the owner on Telegram
when it changed.

Why it exists: A watch has to keep working with no chat open and survive a
restart; main.py starts this poll loop next to the reminder sweeper, and it
claims each due watch atomically before fetching it, so two workers (or a
restart mid-check) never check or notify twice.

Page-watch checks.

Built like ``ReminderService``: a poll loop (every 60 s) that claims due
rows with a conditional UPDATE, then does the slow part outside the claim.
Claiming moves ``next_check_at`` one interval ahead, which doubles as a
lease: a check lost to a crash is simply retried an interval later.

Per check: fetch through the guarded client (``fetch_snapshot``) under a
total deadline (``CHECK_DEADLINE_SECONDS``), hash the normalised text and
compare. The first check records the baseline; a
different hash later is a change. The owner then gets a deterministic
message, built here with no model call: the label, the watched URL and a
short, capped summary of which lines changed. Page text is untrusted and
never reaches the model or decides anything here. In the message it is
defanged so that the watched URL is the only link Telegram will draw, and
withheld outright when PromptGuard flags it.

Failures back off exponentially (never faster than the watch's interval)
and after ``ERROR_LIMIT`` in a row the watch stops (status ``error``) with
one message saying so. Delivery is Telegram only; with no linked chat the
change is still recorded (``last_changed_at``) so watch.list reports it.

The owner's ``page_watch`` switch is re-read every sweep: nothing is
fetched while it is off or blocked (no Telegram bot token, or the owner's
Telegram switch off), and a gate that cannot answer counts as off.
"""

from __future__ import annotations

import asyncio
import difflib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlsplit

import structlog
from sqlalchemy import select, update

from services.tools.watch import (
    EXCERPT_CHARS,
    EXCERPT_CUT_MARK,
    PageSnapshot,
    WatchFetchError,
    excerpt,
    fetch_snapshot,
)

logger = structlog.get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 60
# Checks per sweep; the rest wait for the next tick. Checks run one after
# another, so with CHECK_DEADLINE_SECONDS this bounds how long one sweep
# can take (20 × 45 s).
MAX_CHECKS_PER_SWEEP = 20
# The longest one check may take, from the request to the parsed page. The
# guarded client's timeout bounds each connect and each read, not the whole
# fetch: a server that sends a few bytes every few seconds would otherwise
# hold the one sweeper, and every other user's watches behind it, for as
# long as it liked.
CHECK_DEADLINE_SECONDS = 45.0
# Failures in a row before a watch stops being checked.
ERROR_LIMIT = 5
# Longest back-off between failed checks, unless the interval is longer.
MAX_BACKOFF_MINUTES = 24 * 60

# The change summary: a few changed lines, each capped, the whole capped.
SUMMARY_MAX_LINES = 6
SUMMARY_LINE_CHARS = 140
SUMMARY_CHARS = 700
# Lines of the new page compared with the saved excerpt. The excerpt is the
# page's first ~2000 characters, so its counterpart is near the top too.
_COMPARE_LINES = 1000

_WITHHELD = (
    "(The changed text is not shown: it looked like instructions aimed at an "
    "AI assistant. Open the page to read it.)"
)
_BEYOND_EXCERPT = (
    "(The change is further down the page than the part Crawler keeps a copy "
    "of. Open the page to see it.)"
)

# Telegram draws links for URLs, bare domains, e-mail addresses, @mentions
# and /commands in plain text. Page text is not allowed any of them: a dot
# between two word characters, every slash and every @ become look-alikes
# Telegram does not link, so the watched URL stays the message's only link.
_DOT_BETWEEN_WORDS = re.compile(r"(?<=\w)\.(?=\w)")
_ONE_DOT_LEADER = chr(0x2024)
_DEFANG = str.maketrans({"/": chr(0x2215), "@": chr(0xFF20)})  # DIVISION SLASH, FULLWIDTH AT
_MINUS = chr(0x2212)


def defang(text: str) -> str:
    """*text* with nothing Telegram would turn into a link or a command."""
    return _DOT_BETWEEN_WORDS.sub(_ONE_DOT_LEADER, text).translate(_DEFANG)


def _cap(line: str, limit: int = SUMMARY_LINE_CHARS) -> str:
    return line if len(line) <= limit else line[: limit - 1] + "…"


def change_lines(old_excerpt: Optional[str], new_text: str) -> list[tuple[str, str]]:
    """``("+", line)`` for added and ``("-", line)`` for removed lines, in
    page order, comparing the saved excerpt with the new page's text.

    When the saved excerpt was cut short (it ends with the cut mark), the
    old page went on past its last line, so the new page's lines after that
    point are not additions: they are just past what was kept. A change
    that reaches the excerpt's last line therefore shows at most as many
    new lines as the old lines it replaced, and a first line the excerpt
    had to shorten counts as unchanged while the new page's first line
    still starts with it.
    """
    old_lines = (old_excerpt or "").split("\n") if old_excerpt else []
    cut = bool(old_lines) and old_lines[-1] == EXCERPT_CUT_MARK
    if cut:
        old_lines = old_lines[:-1]
    new_lines = new_text.split("\n")[:_COMPARE_LINES] if new_text else []
    if (
        cut
        and len(old_lines) == 1
        and len(old_lines[0]) >= EXCERPT_CHARS
        and new_lines
        and new_lines[0].startswith(old_lines[0])
    ):
        # ``excerpt`` shortens a line only when it is the first and longer
        # than the whole excerpt; the part it kept is still there.
        return []
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    changes: list[tuple[str, str]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if cut and i1 == len(old_lines):
            # Past the end of the saved excerpt: nothing to compare with.
            continue
        if cut and i2 == len(old_lines):
            # Runs to the end of the excerpt, so the new side runs on into
            # text past what was kept. Count only as many new lines as the
            # old lines they replace.
            j2 = min(j2, j1 + (i2 - i1))
        changes.extend(("-", line) for line in old_lines[i1:i2])
        changes.extend(("+", line) for line in new_lines[j1:j2])
    return changes


def change_summary(
    old_excerpt: Optional[str], new_text: str, *, scan: Callable[[str], bool]
) -> str:
    """The capped, defanged "what changed" block of a change message.

    *scan* answers whether page text is safe to show (PromptGuard); text it
    flags is withheld, never forwarded.
    """
    changes = change_lines(old_excerpt, new_text)
    if not changes:
        return _BEYOND_EXCERPT
    shown = changes[:SUMMARY_MAX_LINES]
    raw = "\n".join(text for _sign, text in shown)
    if not scan(raw):
        return _WITHHELD
    lines: list[str] = []
    size = 0
    for sign, text in shown:
        line = f"{'+' if sign == '+' else _MINUS} {_cap(defang(text))}"
        if size + len(line) + 1 > SUMMARY_CHARS:
            break
        lines.append(line)
        size += len(line) + 1
    hidden = len(changes) - len(lines)
    if hidden:
        lines.append(f"… and {hidden} more changed line{'s' if hidden != 1 else ''}.")
    return "\n".join(lines)


def change_message(label: str, url: str, summary: str, interval_minutes: int) -> str:
    """The Telegram text for a change. Plain text; *url* is its only link."""
    return (
        f"🔔 Page changed: {defang(label)}\n"
        f"{url}\n\n"
        f"What changed:\n{summary}\n\n"
        f"Crawler checks this page every {interval_minutes} minutes."
    )


def stopped_message(label: str, url: str, reason: str, failures: int) -> str:
    """The Telegram text for a watch that stopped after repeated failures."""
    return (
        f"⚠️ Stopped watching: {defang(label)}\n"
        f"{url}\n\n"
        f"The last {failures} checks failed. Last problem: {defang(reason)}\n"
        "Ask Crawler to delete this watch and create it again once the page works."
    )


def _prompt_guard_scan() -> Callable[[str], bool]:
    from services.agent.prompt_guard import PromptGuard

    guard = PromptGuard()
    return lambda text: guard.scan(text).is_safe


def _host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


@dataclass(frozen=True)
class _Claim:
    """What a check needs from its row, read when it was claimed."""

    id: uuid.UUID
    user_id: uuid.UUID
    url: str
    label: str
    interval_minutes: int
    last_hash: Optional[str]
    last_excerpt: Optional[str]
    consecutive_errors: int


class PageWatchService:
    """Sweeps due page watches, checks them, and sends change messages.

    ``send(user_id, text)`` is the channel (the Telegram manager's
    ``send_text``, which answers False while no chat is linked or no poller
    runs). ``enabled()`` is the owner's ``page_watch`` switch, re-read every
    sweep; None means no gate (tests). ``fetch(url)`` returns a
    ``PageSnapshot`` or raises ``WatchFetchError``; it defaults to the
    guarded fetch, and a fetch still running after ``check_deadline_s`` is
    abandoned and counts as a failed check. ``clock`` and ``scan`` are test
    seams.
    """

    def __init__(
        self,
        session_factory: Callable[[], Any],
        send: Optional[Callable[[str, str], Any]] = None,
        *,
        enabled: Optional[Callable[[], Awaitable[bool]]] = None,
        fetch: Optional[Callable[[str], Awaitable[PageSnapshot]]] = None,
        interval_seconds: int = SWEEP_INTERVAL_SECONDS,
        check_deadline_s: float = CHECK_DEADLINE_SECONDS,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        scan: Optional[Callable[[str], bool]] = None,
        audit: bool = True,
    ) -> None:
        self._session_factory = session_factory
        self.send = send
        self._enabled = enabled
        self._fetch = fetch or fetch_snapshot
        self._interval = interval_seconds
        self._check_deadline_s = check_deadline_s
        self._clock = clock
        self._scan = scan
        self._audit_enabled = audit
        self._task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="page-watch-sweeper")
        logger.info("page_watch_sweeper_started", interval=self._interval)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Type only: a message can quote a URL with a token in it.
                logger.warning("page_watch_sweep_failed", error_type=type(exc).__name__)
            await asyncio.sleep(self._interval)

    async def _is_enabled(self) -> bool:
        if self._enabled is None:
            return True
        try:
            return (await self._enabled()) is True
        except Exception as exc:
            # A switch that cannot be read is off: nothing is fetched.
            logger.warning("page_watch_gate_failed", error_type=type(exc).__name__)
            return False

    async def sweep_once(self) -> int:
        """Check every due watch (up to ``MAX_CHECKS_PER_SWEEP``). Returns how many were checked."""
        if not await self._is_enabled():
            return 0
        claims = await self._claim_due(self._clock())
        for claim in claims:
            await self._check(claim)
        return len(claims)

    async def _claim_due(self, now: datetime) -> list[_Claim]:
        from models.page_watch import PageWatch, PageWatchStatus
        from models.user import User

        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        PageWatch.id,
                        PageWatch.user_id,
                        PageWatch.url,
                        PageWatch.label,
                        PageWatch.interval_minutes,
                        PageWatch.last_hash,
                        PageWatch.last_excerpt,
                        PageWatch.consecutive_errors,
                    )
                    .join(User, User.id == PageWatch.user_id)
                    .where(
                        PageWatch.status == PageWatchStatus.active,
                        PageWatch.next_check_at <= now,
                        User.is_active.is_(True),
                    )
                    .order_by(PageWatch.next_check_at)
                    .limit(MAX_CHECKS_PER_SWEEP)
                )
            ).all()
            claims: list[_Claim] = []
            for row in rows:
                # Conditional update: whoever moves the row past "due" owns
                # this check. The new time is also the retry after a crash.
                result = await session.execute(
                    update(PageWatch)
                    .where(
                        PageWatch.id == row.id,
                        PageWatch.status == PageWatchStatus.active,
                        PageWatch.next_check_at <= now,
                    )
                    .values(next_check_at=now + timedelta(minutes=row.interval_minutes))
                )
                if result.rowcount != 1:
                    continue
                claims.append(
                    _Claim(
                        id=row.id,
                        user_id=row.user_id,
                        url=row.url,
                        label=row.label,
                        interval_minutes=row.interval_minutes,
                        last_hash=row.last_hash,
                        last_excerpt=row.last_excerpt,
                        consecutive_errors=row.consecutive_errors or 0,
                    )
                )
            await session.commit()
        return claims

    async def _check(self, claim: _Claim) -> None:
        try:
            # A total deadline, not just the client's per-read timeout: the
            # checks run one at a time, so one page that never finishes
            # would otherwise stop every other watch from being checked.
            snapshot = await asyncio.wait_for(self._fetch(claim.url), self._check_deadline_s)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            await self._record_failure(claim, "The page did not finish loading in time.")
            return
        except WatchFetchError as exc:
            await self._record_failure(claim, str(exc))
            return
        except Exception as exc:
            await self._record_failure(claim, f"The check failed ({type(exc).__name__}).")
            return
        try:
            await self._record_success(claim, snapshot)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "page_watch_record_failed", watch_id=str(claim.id), error_type=type(exc).__name__
            )

    async def _update(self, watch_id: uuid.UUID, values: dict[str, Any]) -> bool:
        """Apply *values* to a still-active watch. False when it was deleted
        or stopped meanwhile (then nothing is sent either)."""
        from models.page_watch import PageWatch, PageWatchStatus

        async with self._session_factory() as session:
            result = await session.execute(
                update(PageWatch)
                .where(PageWatch.id == watch_id, PageWatch.status == PageWatchStatus.active)
                .values(**values)
            )
            await session.commit()
        return result.rowcount == 1

    async def _record_success(self, claim: _Claim, snapshot: PageSnapshot) -> None:
        now = self._clock()
        values: dict[str, Any] = {
            "last_checked_at": now,
            "next_check_at": now + timedelta(minutes=claim.interval_minutes),
            "consecutive_errors": 0,
            "last_error": None,
        }
        changed = claim.last_hash is not None and snapshot.digest != claim.last_hash
        if claim.last_hash is None or changed:
            values["last_hash"] = snapshot.digest
            values["last_excerpt"] = excerpt(snapshot.text)
        if changed:
            # Recorded whether or not a message goes out, so watch.list
            # reports the change even with no linked Telegram chat.
            values["last_changed_at"] = now
        if not await self._update(claim.id, values) or not changed:
            return
        scan = self._scan or _prompt_guard_scan()
        summary = change_summary(claim.last_excerpt, snapshot.text, scan=scan)
        text = change_message(claim.label, claim.url, summary, claim.interval_minutes)
        delivered = await self._deliver(claim, text)
        logger.info("page_watch_changed", watch_id=str(claim.id), delivered=delivered)
        await self._audit(claim, "changed", {"delivered": delivered})

    async def _record_failure(self, claim: _Claim, reason: str) -> None:
        from models.page_watch import ERROR_MAX_CHARS, PageWatchStatus

        now = self._clock()
        failures = claim.consecutive_errors + 1
        reason = reason[:ERROR_MAX_CHARS]
        values: dict[str, Any] = {
            "last_checked_at": now,
            "consecutive_errors": failures,
            "last_error": reason,
        }
        stopped = failures >= ERROR_LIMIT
        if stopped:
            values["status"] = PageWatchStatus.error
        else:
            backoff = min(
                claim.interval_minutes * 2**failures,
                max(MAX_BACKOFF_MINUTES, claim.interval_minutes),
            )
            values["next_check_at"] = now + timedelta(minutes=backoff)
        logger.info(
            "page_watch_check_failed",
            watch_id=str(claim.id),
            failures=failures,
            stopped=stopped,
        )
        try:
            updated = await self._update(claim.id, values)
        except Exception as exc:
            logger.warning(
                "page_watch_record_failed", watch_id=str(claim.id), error_type=type(exc).__name__
            )
            return
        if updated and stopped:
            delivered = await self._deliver(
                claim, stopped_message(claim.label, claim.url, reason, failures)
            )
            await self._audit(claim, "stopped", {"delivered": delivered, "failures": failures})

    async def _deliver(self, claim: _Claim, text: str) -> bool:
        if self.send is None:
            return False
        try:
            # The Telegram manager answers False while no poller runs or the
            # user has no linked chat; the change stays recorded either way.
            return (await self.send(str(claim.user_id), text)) is not False
        except Exception as exc:
            # Not retried: a broken channel must not turn into a storm.
            logger.warning(
                "page_watch_delivery_failed", watch_id=str(claim.id), error_type=type(exc).__name__
            )
            return False

    async def _audit(self, claim: _Claim, action: str, data: dict[str, Any]) -> None:
        """One row in the owner's audit log for what the sweeper did on its
        own. The host only: a URL's path or query can carry a token."""
        if not self._audit_enabled:
            return
        from models.audit import AuditStatus
        from services.audit import append_audit_log

        try:
            async with self._session_factory() as session:
                await append_audit_log(
                    session,
                    user_id=claim.user_id,
                    connector_name="watch",
                    action=action,
                    endpoint="page_watch_sweeper",
                    scope_used="page_watch",
                    status=AuditStatus.approved,
                    request_data={"watch_id": str(claim.id), "host": _host(claim.url), **data},
                )
                await session.commit()
        except Exception as exc:
            logger.warning(
                "page_watch_audit_failed", watch_id=str(claim.id), error_type=type(exc).__name__
            )
