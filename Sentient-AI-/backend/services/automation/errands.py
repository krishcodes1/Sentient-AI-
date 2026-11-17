"""Background errands: one thing the owner wants bought ("order this perfume for
my girlfriend", with a name, a link and a date), planned for a day, run then
as an unattended agent turn in Crawler's browser, and ended with exactly one
approval: the purchase card.

Why it exists: the owner's goal, in their words: "in one approval, not 1000
approvals; the whole point of an assistant is to take work off the user". An
errand run searches, compares and goes through the shop up to the checkout
page with no card (website errand steps, app_approvals.errand_covers), and
parks the one browser.checkout card. That card is pushed to Telegram like
every card, says "Errand: <title>. Nothing has been paid yet.", waits
``card_hours`` (12, at most 48) and keeps its checkout page open that long
(``BrowserCheckoutToolkit.hold``, for that card's own checkout). Approve pays
(the checkout re-checks the same page, the caps, the merchant and the total)
and the owner gets one message: what was bought, for how much, where, and the
confirmation the checkout read, with its picture. A page that changed or
closed meanwhile plans the errand again at once, so a new run makes a new
card. Deny cancels the errand and lets the held page go.

The rules, in short:
- ``ErrandService`` creates (idempotent per calendar event), plans, lists,
  cancels and retries errands; its sweeper re-reads the "errand_runs" switch
  before every pass (and "calendar_errands" for an errand from the calendar)
  and stops a run in flight once its switch is off (it is planned again),
  while cards nobody answered keep running out either way; it runs one
  errand at a time (a user's next errand waits while one is running or
  awaiting its card: they share one browser window), postpones a run while
  the owner is using that browser themselves, has a checkout of their own
  waiting or a website-step card waiting in chat, and gives up after
  ``MAX_ATTEMPTS`` runs;
- the card a run parked is found by the run's origin, not by what the run
  reported, so a card stored as the run's deadline landed is still the
  errand's; only a live card made since that run started counts (never an
  earlier run's, expired or not); an approval moves the errand on only for
  that card;
- a run that stops on a page that needs the owner (a sign-in) or a site that
  turns the browser away, or a checkout that hits one at approval, marks the
  errand "waiting" and tells the owner what is needed and where; /errands
  "Try again" plans it again, and an errand given up ("failed") in the last
  ``GAVE_UP_DAYS`` days too;
- an order that was sent but not confirmed marks the errand "unsure": it may
  have been bought, so nothing plans it again (not a calendar edit, not Try
  again);
- cancelling an errand stops its run, closes its card and lets its held
  checkout page go;
- every message is Crawler's own words plus the owner's own title and item;
  the model's reply is passed on as a scheduled run's is, URL queries
  stripped; logs carry ids, statuses and exception types only.

Connects to: services/automation/turns.py (the errand runner),
services/agent/unattended.py (the errand fence and card note),
api/routes/agent.py (``purchase_decided`` and ``card_denied`` from the
decision path), services/automation/errand_commands.py (/errands), main.py
(wiring), models/errand.py, services/tools/browser/checkout/toolkit.py
(``hold`` and ``busy``).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import aliased

from services.agent.unattended import ERRAND_ORIGIN_PREFIX
from services.automation.ledger import AutomationLedger
from services.automation.runner import UnattendedOutcome, UnattendedRequest
from services.capabilities.calendar_errands import KEY as CALENDAR_KEY
from services.capabilities.errand_runs import ERRAND_SETTINGS_DEFAULTS, KEY
from services.notifications.sweeper import SweepLoop, claim

logger = structlog.get_logger(__name__)

# What an errand run may use: reads and the website steps (the fence lists a
# step with the reads), and its one card.
ERRAND_READS = ("web.search", "web.fetch_page", "web.research", "browser.read", "browser.act")
ERRAND_WRITES = ("browser.checkout",)
SWEEP_INTERVAL_SECONDS = 60
QUEUE_WAIT_SECONDS = 60.0
# Runs an errand gets (each run that reached the model counts) before it is
# given up as failed.
MAX_ATTEMPTS = 3
# The most the errand settings may ask for, whatever was saved: a card (and
# its held checkout page and parked browser) waits two days at most, one run
# holds the errand slot an hour at most.
SETTING_CEILINGS = {"card_hours": 48, "deadline_minutes": 60, "max_rounds": 100}
# Due errands looked at per sweep, so one owner who is busy in the browser
# does not hold up another's.
_DUE_BATCH = 10
# How long /errands keeps listing an errand given up, with "Try again".
GAVE_UP_DAYS = 7
# A card past its TTL by this much, or a run past its deadline by this much,
# is no longer waited on.
_GRACE = timedelta(minutes=10)
_ASK_EVERY_STEP = "browser_ask_every_step"
_CHECKOUT = "browser.checkout"
_STEP = "browser.act"
# The checkout's refusals that mean the page the owner approved is gone.
_STALE_RULES = frozenset({"screen_changed", "unbound_approval"})
_STOP_WAIT_S = 10.0
_HEADER = "\U0001f6d2 Errand: {title}"

_BUDGET = "I've used today's budget for errands, so I'll do this one tomorrow."
_STOPPED = (
    "I stopped this errand because you asked me to. Send /errands to try it again or cancel it."
)
_ASK_ON = (
    "I can't do errands in the background while 'Ask before every website step' is on. "
    "Turn it off in Settings, under Permissions, then send /errands and tap Try again."
)
_RETRY = "I'll try again tomorrow."
_GAVE_UP = "I've tried {n} times, so I've stopped. Send /errands if you want me to try again."
_EXPIRED = "Your OK on the payment ran out, so nothing was paid. I'm setting it up again now."
_EXPIRED_GAVE_UP = "Your OK on the payment ran out, so nothing was paid, and I've stopped trying."
_EXPIRED_SWITCHED_OFF = (
    "Your OK on the payment ran out, so nothing was paid. Errands are turned off in Settings, "
    "so I'll set this one up again once you turn them back on."
)
_TAKE_OVER = (
    "I need you first: {what}{where}. Do that in Crawler's browser window on your computer, "
    "then send /errands and tap Try again."
)
_SITE_REFUSED_NEXT = "Send /errands to try it again or cancel it."
_BOUGHT = "✅ Done: I bought {item} for ${amount} on {site}."
_CONFIRMATION = "The order page says: {text}"
_STALE = (
    "⚠️ Nothing was paid for {title}: the checkout page changed or closed before your "
    "OK. I'm going back to the shop now, and you'll get a new approval."
)
_STALE_GAVE_UP = (
    "⚠️ Nothing was paid for {title}: the checkout page changed or closed before your "
    "OK, and I've tried {n} times, so I've stopped."
)
_UNSURE = (
    "⚠️ I placed the order for {title} on {site}, but I couldn't confirm it went through. "
    "Please check {site} before ordering again. I won't try this errand again."
)
_BANK_CHECK = (
    "⚠️ I placed the order for {title} on {site}, and your bank wants to confirm the "
    "payment. Do that in Crawler's browser window on your computer within {hours} hours, "
    "or the payment may not go through. Please check {site} before ordering again. "
    "I won't try this errand again."
)
_REFUSED = "⚠️ Nothing was paid for {title}. {reason}"
_DENIED = "You said no to the payment, so I cancelled this errand."
_CANCELLED = "You cancelled this errand."

Sender = Callable[[str, str], Awaitable[Any]]
SettingsSource = Callable[[], Awaitable[Mapping[str, Any]]]
Hold = Callable[[str, float, str], bool]


def _utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _card_now() -> datetime:
    """The approval store's clock (services/agent/approvals.py): a card's
    created_at and expires_at are written and judged by it, not by the
    service's ``clock``."""
    return datetime.now(timezone.utc)


def plan_run_on(needed_by: Optional[date], today: date, lead_days: int) -> date:
    """The day an errand runs: *lead_days* before it is needed (so it
    arrives in time), never before *today*; today when no date was given."""
    if needed_by is None:
        return today
    return max(today, needed_by - timedelta(days=max(lead_days, 0)))


def errand_text(
    title: str,
    item: str,
    link: Optional[str],
    needed_by: Optional[date],
    details: Optional[str] = None,
) -> str:
    """The owner's errand in their own words: the run's prompt and its
    trusted text (links and words from it are not taint)."""
    lines = [title, f"Item: {item}"]
    if details:
        lines.append(f"Details: {details}")
    if link:
        lines.append(f"Link: {link}")
    if needed_by is not None:
        lines.append(f"Needed by: {needed_by:%A %B} {needed_by.day}, {needed_by.year}")
    return "\n".join(lines)


def _clean(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _link(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text[:2048] if text.startswith(("https://", "http://")) and " " not in text else None


@dataclass(frozen=True)
class _Job:
    """What a run needs from its errand row, read when it was claimed."""

    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    item: str
    link: Optional[str]
    needed_by: Optional[date]
    attempts: int
    conversation_id: Optional[uuid.UUID]
    details: Optional[str] = None

    @property
    def origin(self) -> str:
        return f"{ERRAND_ORIGIN_PREFIX}{self.id}"


def _job_of(row: Any) -> _Job:
    return _Job(
        id=row.id,
        user_id=row.user_id,
        title=row.title,
        item=row.item,
        link=row.link,
        needed_by=row.needed_by,
        attempts=row.attempts,
        conversation_id=row.conversation_id,
        details=row.details,
    )


@dataclass(frozen=True)
class _Card:
    """A purchase card an errand's run parked: its action id and the
    checkout it was made for."""

    action_id: str
    checkout_id: str


class ErrandService:
    """Creates and sweeps errands (see the module docstring).

    ``runner`` is the errand runner (``UnattendedTurnRunner.errand_runner``);
    ``send(user_id, text)`` reaches only that user's own linked chats;
    ``enabled_keys`` answers the owner's effectively-on capabilities;
    ``settings`` the errand_runs settings; ``hold(user_id, seconds,
    checkout_id)`` keeps a just-parked checkout and its browser page, and
    with 0 seconds lets them go (the checkout toolkit's); ``busy(user_id)``
    says the owner is using Crawler's browser or has a checkout of their own
    waiting (by default the ``busy`` of the toolkit ``hold`` belongs to; a
    website-step card waiting in chat is read from the approval store);
    ``deny(action_id, user_id)`` closes a card nobody should approve any more
    (the runtime's ``deny_action``). ``clock`` and ``interval_seconds`` are
    test seams."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        runner: Any = None,
        send: Optional[Sender] = None,
        enabled_keys: Optional[Callable[[], Awaitable[frozenset[str]]]] = None,
        settings: Optional[SettingsSource] = None,
        hold: Optional[Hold] = None,
        busy: Optional[Callable[[str], bool]] = None,
        deny: Optional[Callable[[str, str], Awaitable[Any]]] = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        interval_seconds: float = SWEEP_INTERVAL_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self.runner = runner
        self._send = send
        self._enabled_keys = enabled_keys
        self._settings = settings
        self._hold = hold
        # main.py passes the checkout toolkit's bound hold; its busy comes along.
        self._busy = busy or getattr(getattr(hold, "__self__", None), "busy", None)
        self._deny = deny
        self._clock = clock
        self._ledger = AutomationLedger(session_factory, clock=clock, errands=True)
        self._task: Optional[asyncio.Task[None]] = None
        # The errand the run in ``_task`` is for (cancel() stops it), and
        # whether it came from the calendar (its own switch stops it too).
        self._running: Optional[uuid.UUID] = None
        self._running_calendar = False
        # A wake() sweep and the tick's must not both start a run.
        self._sweeping = asyncio.Lock()
        # wake()'s sweeps, held so the loop does not drop them half-way.
        self._wakes: set[asyncio.Task[int]] = set()
        self._sweeper = SweepLoop(
            name="errand", interval_seconds=interval_seconds, sweep=self.sweep_once
        )

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        await self._sweeper.start()

    async def stop(self) -> None:
        """Stop sweeping, then cancel the run in flight (its errand is
        planned again). Bounded, so a wedged run cannot hold shutdown."""
        await self._sweeper.stop()
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            await asyncio.wait({task}, timeout=_STOP_WAIT_S)

    async def wait_idle(self) -> None:
        """Wait for the run in flight (tests, shutdown)."""
        while self._task is not None and not self._task.done():
            await asyncio.gather(self._task, return_exceptions=True)

    def wake(self) -> None:
        """Sweep now rather than at the next tick (an errand was just planned
        again after a stale approval). Best effort: the tick still comes."""
        try:
            task = asyncio.get_running_loop().create_task(self._sweeper.run_once())
        except RuntimeError:
            return
        self._wakes.add(task)
        task.add_done_callback(self._wakes.discard)

    # -- settings and gates ----------------------------------------------------

    async def limits(self) -> dict[str, int]:
        """The errand_runs settings, the defaults when they cannot be read,
        and never above ``SETTING_CEILINGS``."""
        values: dict[str, Any] = dict(ERRAND_SETTINGS_DEFAULTS)
        if self._settings is not None:
            try:
                values.update(await self._settings())
            except Exception as exc:
                logger.warning("errand_settings_unreadable", error_type=type(exc).__name__)
        limits = {k: int(values[k]) for k in ERRAND_SETTINGS_DEFAULTS}
        for key, ceiling in SETTING_CEILINGS.items():
            limits[key] = min(max(limits[key], 1), ceiling)
        return limits

    async def _keys(self) -> Optional[frozenset[str]]:
        if self._enabled_keys is None:
            return frozenset({KEY})
        try:
            return frozenset(await self._enabled_keys())
        except Exception as exc:
            logger.warning("errand_gate_failed", error_type=type(exc).__name__)
            return None

    async def _owner_busy(self, user_id: Any) -> bool:
        """Whether the owner is using Crawler's browser themselves, has a
        checkout of their own waiting, or has a website-step card waiting
        in chat (a pending browser.act card, bound to the page an errand run
        would take; the browser session itself never says so). A check that
        fails says no: it only spares the owner a clash."""
        try:
            if self._busy is not None and self._busy(str(user_id)):
                return True
            return await self._step_card_waiting(user_id)
        except Exception as exc:
            logger.warning("errand_busy_check_failed", error_type=type(exc).__name__)
            return False

    async def _step_card_waiting(self, user_id: Any) -> bool:
        from models.pending_action import PendingAction, PendingActionStatus

        async with self._session_factory() as session:
            found = await session.execute(
                select(PendingAction.id)
                .where(
                    PendingAction.user_id == uuid.UUID(str(user_id)),
                    PendingAction.tool_name == _STEP,
                    PendingAction.status == PendingActionStatus.pending,
                    PendingAction.expires_at > _card_now(),
                )
                .limit(1)
            )
            return found.first() is not None

    # -- the owner's errands -----------------------------------------------------

    async def create(
        self,
        user_id: Any,
        *,
        source: str,
        title: str,
        item: str,
        link: Optional[str] = None,
        needed_by: Optional[date] = None,
        details: Optional[str] = None,
        source_ref: Optional[str] = None,
        source_updated: Optional[datetime] = None,
        event_day: Optional[date] = None,
        source_fingerprint: Optional[str] = None,
    ) -> Any:
        """Plan an errand and return its row. A calendar event already
        planned (same ``source_ref``) is returned as it is, unless its words
        changed (title, item, details, link, needed by) while it is still
        planned or waiting: then it is planned again from the new words. A
        ``source_updated`` older than the row's is a stale copy and never
        plans it again; any other is kept on the row, with the calendar
        event's day (``event_day``) and the note's fingerprint
        (``source_fingerprint``) when given. A running errand,
        one on its card and a finished one (done, failed, unsure, cancelled)
        are never planned again here. Raises ValueError for an unknown
        source or an empty title or item."""
        from models.errand import (
            DETAILS_MAX_CHARS,
            ERRAND_SOURCES,
            ITEM_MAX_CHARS,
            SOURCE_REF_MAX_CHARS,
            TITLE_MAX_CHARS,
            Errand,
        )

        if source not in ERRAND_SOURCES:
            raise ValueError(f"unknown errand source: {source!r}")
        clean_title, clean_item = _clean(title, TITLE_MAX_CHARS), _clean(item, ITEM_MAX_CHARS)
        if not clean_title or not clean_item:
            raise ValueError("an errand needs a title and an item")
        owner = uuid.UUID(str(user_id))
        ref = source_ref[:SOURCE_REF_MAX_CHARS] if source_ref else None
        now = self._clock()
        run_on = plan_run_on(needed_by, now.date(), (await self.limits())["lead_days"])
        words = {
            "title": clean_title,
            "item": clean_item,
            "details": _clean(details, DETAILS_MAX_CHARS) or None,
            "link": _link(link),
            "needed_by": needed_by,
        }
        async with self._session_factory() as session:
            row = None
            if ref:
                row = (
                    await session.execute(
                        select(Errand).where(
                            Errand.user_id == owner,
                            Errand.source == source,
                            Errand.source_ref == ref,
                        )
                    )
                ).scalar_one_or_none()
            if row is not None:
                stale = (
                    source_updated is not None
                    and row.source_updated is not None
                    and _utc(source_updated) < _utc(row.source_updated)
                )
                changed = any(getattr(row, name) != value for name, value in words.items())
                if not stale and changed and row.status in ("planned", "waiting"):
                    for name, value in words.items():
                        setattr(row, name, value)
                    row.run_on, row.status, row.attempts, row.last_message = (
                        run_on,
                        "planned",
                        0,
                        None,
                    )
                if not stale:
                    # The newest copy's change time, day (the day the
                    # calendar finder judges a deleted note by) and
                    # fingerprint (what a restart compares).
                    row.source_updated = source_updated or row.source_updated
                    row.event_day = event_day or row.event_day
                    row.source_fingerprint = source_fingerprint or row.source_fingerprint
                await session.commit()
                return row
            row = Errand(
                user_id=owner,
                source=source,
                source_ref=ref,
                source_updated=source_updated,
                event_day=event_day,
                source_fingerprint=source_fingerprint,
                run_on=run_on,
                status="planned",
                attempts=0,
                **words,
            )
            session.add(row)
            await session.commit()
        logger.info("errand_planned", errand_id=str(row.id), source=source)
        return row

    async def remember_note(
        self, errand_id: Any, *, fingerprint: str, event_day: Optional[date]
    ) -> None:
        """Keep a calendar note's fingerprint on its errand, and its event
        day when the row has none, without planning anything: the calendar
        finder saw the note unchanged and read nothing."""
        from models.errand import Errand

        async with self._session_factory() as session:
            row = await session.get(Errand, errand_id)
            if row is None:
                return
            row.source_fingerprint = fingerprint
            row.event_day = row.event_day or event_day
            await session.commit()

    async def listed_errands(self, user_id: Any) -> list[Any]:
        """What /errands lists: the user's errands that are not finished,
        and those given up (failed) in the last ``GAVE_UP_DAYS`` days, which
        "Try again" can plan again, soonest first."""
        from models.errand import OPEN_STATUSES, Errand

        recent = self._clock() - timedelta(days=GAVE_UP_DAYS)
        async with self._session_factory() as session:
            rows = await session.execute(
                select(Errand)
                .where(
                    Errand.user_id == uuid.UUID(str(user_id)),
                    or_(
                        Errand.status.in_(OPEN_STATUSES),
                        and_(Errand.status == "failed", Errand.updated_at >= recent),
                    ),
                )
                .order_by(Errand.run_on, Errand.created_at)
            )
            return list(rows.scalars().all())

    async def cancel(self, user_id: Any, errand_id: Any) -> Optional[Any]:
        """Cancel one of the user's open errands: a run in flight is stopped,
        every purchase card it parked is closed so nothing can be paid, and
        the checkout page held for it is let go. None when there is no such
        open errand."""
        from models.errand import OPEN_STATUSES, Errand

        async with self._session_factory() as session:
            row = await _own(session, Errand, user_id, errand_id)
            if row is None or row.status not in OPEN_STATUSES:
                return None
            was_running = row.status == "running"
            row.status, row.last_message = "cancelled", _CANCELLED
            await session.commit()
        if was_running:
            await self.stop_run(row.id)
        await self.close_cards(f"{ERRAND_ORIGIN_PREFIX}{row.id}", str(row.user_id))
        logger.info("errand_cancelled", errand_id=str(row.id))
        return row

    async def stop_run(self, errand_id: Any) -> None:
        """Stop the run in flight when it is *errand_id*'s, at once (its
        browser step is cut short); bounded like ``stop``."""
        task = self._task
        if task is None or task.done() or self._running != errand_id:
            return
        task.cancel()
        await asyncio.wait({task}, timeout=_STOP_WAIT_S)

    async def retry(self, user_id: Any, errand_id: Any) -> Optional[Any]:
        """Plan a waiting (or given up) errand again for today and sweep.
        None when there is no such errand to try again: one that may have
        bought ("unsure") never is."""
        from models.errand import Errand

        async with self._session_factory() as session:
            row = await _own(session, Errand, user_id, errand_id)
            if row is None or row.status not in ("waiting", "failed"):
                return None
            row.status, row.run_on, row.attempts = "planned", self._clock().date(), 0
            await session.commit()
        self.wake()
        return row

    def release(self, user_id: str, checkout_id: str) -> None:
        """Let a held checkout and its parked browser page go (its card was
        denied or its errand cancelled). Best effort."""
        if self._hold is None or not checkout_id:
            return
        try:
            self._hold(user_id, 0.0, checkout_id)
        except Exception as exc:
            logger.warning("errand_release_failed", error_type=type(exc).__name__)

    # -- the sweep -------------------------------------------------------------

    async def due(self, today: date, limit: int = 1, *, calendar: bool = True) -> list[Any]:
        """Planned errands whose day has come, of active users who have no
        errand running or awaiting its card (one browser window each),
        soonest first. Without *calendar* (the calendar_errands switch is
        off), none that came from the calendar."""
        from models.errand import Errand
        from models.user import User

        # ponytail: one errand in flight per user, since all share one
        # browser window; a tab per errand if owners stack many errands.
        busy = aliased(Errand)
        in_flight = (
            select(busy.id)
            .where(
                busy.user_id == Errand.user_id, busy.status.in_(("running", "awaiting_approval"))
            )
            .exists()
        )
        query = (
            select(Errand)
            .join(User, User.id == Errand.user_id)
            .where(
                Errand.status == "planned",
                Errand.run_on <= today,
                User.is_active.is_(True),
                ~in_flight,
            )
            .order_by(Errand.run_on, Errand.created_at)
            .limit(limit)
        )
        if not calendar:
            query = query.where(Errand.source != "calendar")
        async with self._session_factory() as session:
            return list((await session.execute(query)).scalars().all())

    async def sweep_once(self) -> int:
        """Let go of cards and runs nobody waits on any more (even while the
        switches are off), stop the run in flight once its switch is off
        ("errand_runs", or "calendar_errands" for an errand from the
        calendar: it is planned again), then start the next due errand when
        none is running, passing over an owner who is using the browser
        themselves. Returns how many started."""
        keys = await self._keys()
        if keys is None:
            return 0
        async with self._sweeping:
            limits = await self.limits()
            await self._release_stale(limits, keys)
            task = self._task
            if task is not None and not task.done():
                if not _allowed(keys, calendar=self._running_calendar):
                    logger.info("errand_run_switched_off", errand_id=str(self._running))
                    await self.stop_run(self._running)
                return 0
            if KEY not in keys:
                return 0
            now = self._clock()
            # ponytail: run days are UTC dates; use the owner's time zone if
            # starting up to a day early or late ever matters.
            rows = await self.due(now.date(), _DUE_BATCH, calendar=CALENDAR_KEY in keys)
            for row in rows:
                if await self._owner_busy(row.user_id):
                    logger.info("errand_postponed_owner_busy", errand_id=str(row.id))
                    continue
                job = await self._claim(row, now)
                if job is not None:
                    self._running = job.id
                    self._running_calendar = row.source == "calendar"
                    self._task = asyncio.create_task(
                        self._run(job, keys, limits), name="errand-run"
                    )
                    return 1
            return 0

    async def _claim(self, row: Any, now: datetime) -> Optional[_Job]:
        from models.errand import Errand

        async with self._session_factory() as session:
            won = await claim(
                session,
                update(Errand)
                .where(Errand.id == row.id, Errand.status == "planned")
                .values(status="running", attempts=Errand.attempts + 1, updated_at=now)
                .execution_options(synchronize_session=False),
            )
            await session.commit()
        if not won:
            return None
        job = _job_of(row)
        return replace(job, attempts=job.attempts + 1)

    async def _release_stale(self, limits: Mapping[str, int], keys: frozenset[str]) -> None:
        """A purchase card past its TTL: the errand is planned again (or,
        after MAX_ATTEMPTS runs, failed) and the owner told, in words that
        say when its switch (*keys*) is off so it waits for them. A run that
        outlived its deadline (the process stopped mid-run): planned
        again."""
        from models.errand import Errand

        now = self._clock()
        card_cutoff = now - timedelta(hours=limits["card_hours"]) - _GRACE
        run_cutoff = now - timedelta(minutes=limits["deadline_minutes"]) - _GRACE
        told: list[tuple[str, str]] = []
        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(Errand).where(
                            or_(
                                and_(
                                    Errand.status == "awaiting_approval",
                                    Errand.updated_at < card_cutoff,
                                ),
                                and_(Errand.status == "running", Errand.updated_at < run_cutoff),
                            )
                        )
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                if row.status == "running":
                    if self._task is None or self._task.done():
                        row.status, row.updated_at = "planned", now
                    continue
                gave_up = row.attempts >= MAX_ATTEMPTS
                row.status = "failed" if gave_up else "planned"
                row.run_on, row.updated_at = now.date(), now
                on = _allowed(keys, calendar=row.source == "calendar")
                row.last_message = (
                    _EXPIRED_GAVE_UP if gave_up else _EXPIRED if on else _EXPIRED_SWITCHED_OFF
                )
                told.append((str(row.user_id), _message(row.title, row.last_message)))
            await session.commit()
        for user_id, text in told:
            await self._tell(user_id, text)

    # -- one run ---------------------------------------------------------------

    async def _run(self, job: _Job, keys: frozenset[str], limits: Mapping[str, int]) -> None:
        # Only a card made from here on is this run's (``_cards``).
        started = _card_now()
        try:
            if _ASK_EVERY_STEP in keys:
                await self._finish(job, None, limits, started, waiting=_ASK_ON)
                return
            outcome = await self._execute(job, limits)
            # Inside the try: a stop that lands while _finish records the
            # parked card goes through the shielded _replan, which finds a
            # card made since the run started; on a row no longer running
            # it changes nothing.
            await self._finish(job, outcome, limits, started)
        except asyncio.CancelledError:
            await asyncio.shield(self._replan(job, limits, started))
            raise
        except Exception as exc:
            logger.error("errand_run_failed", errand_id=str(job.id), error_type=type(exc).__name__)
            await self._replan(job, limits, started, counted=True)
            return

    async def _execute(self, job: _Job, limits: Mapping[str, int]) -> UnattendedOutcome:
        if self.runner is None:
            return UnattendedOutcome(status="failed")
        run_id = await self._ledger.start_run(job.user_id, job.origin, "errand")
        text = errand_text(job.title, job.item, job.link, job.needed_by, job.details)
        outcome: UnattendedOutcome = await self.runner.run(
            UnattendedRequest(
                user_id=str(job.user_id),
                origin=job.origin,
                label=job.title,
                prompt=text,
                reads=ERRAND_READS,
                writes=ERRAND_WRITES,
                conversation_id=str(job.conversation_id) if job.conversation_id else None,
                conversation_title=f"Errand: {job.title}",
                max_usd=limits["run_cap_cents"] / 100,
                max_rounds=limits["max_rounds"],
                deadline_s=limits["deadline_minutes"] * 60.0,
                run_id=run_id,
                queue_wait_s=QUEUE_WAIT_SECONDS,
                card_ttl_minutes=limits["card_hours"] * 60,
            )
        )
        if run_id is not None:
            # The run's outcome (and any card it parked) matters more than
            # its ledger row: a write that fails is logged, not raised.
            try:
                await self._ledger.finish_run(
                    run_id,
                    status=outcome.status,
                    input_tokens=int(outcome.usage.get("input_tokens") or 0),
                    output_tokens=int(outcome.usage.get("output_tokens") or 0),
                    cost_usd=float(outcome.cost_usd or 0.0),
                    message_id=outcome.message_id,
                )
            except Exception as exc:
                logger.warning("errand_ledger_failed", error_type=type(exc).__name__)
        return outcome

    async def _finish(
        self,
        job: _Job,
        outcome: Optional[UnattendedOutcome],
        limits: Mapping[str, int],
        started: datetime,
        *,
        waiting: Optional[str] = None,
    ) -> None:
        """Move the errand on from what its run did, and tell the owner when
        there is something to tell (a parked card tells them itself). The
        card is the one the run parked under the errand's origin, whatever
        the outcome says (a run whose deadline landed while its card was
        stored reports none): a live card made since the run *started*,
        never an earlier run's, expired or not."""
        from models.errand import Errand

        today = self._clock().date()
        text: Optional[str] = None
        card = (
            await self._parked_card(job.origin, str(job.user_id), started)
            if waiting is None
            else None
        )
        async with self._session_factory() as session:
            row = await session.get(Errand, job.id)
            if row is None or row.status != "running":
                # Cancelled while it ran: a card it parked must not be paid.
                await session.commit()
                await self.close_cards(job.origin, str(job.user_id))
                return
            if outcome is not None and outcome.conversation_id:
                row.conversation_id = uuid.UUID(outcome.conversation_id)
            reply = (outcome.reply or "").strip() if outcome is not None else ""
            if waiting is not None:
                row.status, text = "waiting", waiting
            elif card is not None:
                row.status, row.approval_action_id = "awaiting_approval", uuid.UUID(card.action_id)
            elif outcome is None:
                row.status = "planned"
            elif outcome.status == "skipped_busy":
                row.status, row.attempts = "planned", job.attempts - 1
            elif outcome.status == "skipped_budget":
                row.status, row.attempts = "planned", job.attempts - 1
                row.run_on, text = today + timedelta(days=1), _BUDGET
            elif outcome.stopped_on and "cap" not in outcome.stopped_on:
                row.status, text = "waiting", _needs_you(outcome.stopped_on)
            elif outcome.status == "stopped":
                row.status, text = "waiting", _STOPPED
            elif job.attempts >= MAX_ATTEMPTS:
                row.status = "failed"
                text = "\n\n".join(p for p in (reply, _GAVE_UP.format(n=job.attempts)) if p)
            else:
                row.status, row.run_on = "planned", today + timedelta(days=1)
                text = "\n\n".join(p for p in (reply, _RETRY) if p)
            if text is not None:
                row.last_message = text
            # The card's wait is counted from here (_release_stale).
            row.updated_at = self._clock()
            await session.commit()
        logger.info(
            "errand_run_finished",
            errand_id=str(job.id),
            status=outcome.status if outcome is not None else "not_run",
            errand_status=row.status,
        )
        if card is not None:
            self._hold_card(job, card, limits)
        if text is not None:
            await self._tell(str(job.user_id), _message(job.title, text))

    async def _replan(
        self, job: _Job, limits: Mapping[str, int], started: datetime, *, counted: bool = False
    ) -> None:
        """A run that did not finish: waits on the card it parked (a live
        one made since it *started*), if it parked one, else is planned
        again. A shutdown does not count as an
        attempt; a crash does (*counted*), so one that keeps crashing is
        failed after MAX_ATTEMPTS instead of retried every minute. Only a
        row still "running" changes (a cancelled one stays cancelled). Best
        effort."""
        from models.errand import Errand

        gave_up = counted and job.attempts >= MAX_ATTEMPTS
        try:
            card = await self._parked_card(job.origin, str(job.user_id), started)
            values: dict[str, Any] = (
                {
                    "status": "awaiting_approval",
                    "approval_action_id": uuid.UUID(card.action_id),
                    "updated_at": self._clock(),
                }
                if card is not None
                else {
                    "status": "failed" if gave_up else "planned",
                    "attempts": job.attempts if counted else job.attempts - 1,
                }
            )
            async with self._session_factory() as session:
                won = await claim(
                    session,
                    update(Errand)
                    .where(Errand.id == job.id, Errand.status == "running")
                    .values(**values)
                    .execution_options(synchronize_session=False),
                )
                await session.commit()
            if won and card is not None:
                self._hold_card(job, card, limits)
        except Exception as exc:
            logger.warning("errand_replan_failed", error_type=type(exc).__name__)

    def _hold_card(self, job: _Job, card: _Card, limits: Mapping[str, int]) -> None:
        if self._hold is None:
            return
        try:
            held = self._hold(str(job.user_id), limits["card_hours"] * 3600.0, card.checkout_id)
        except Exception as exc:
            logger.warning("errand_hold_failed", error_type=type(exc).__name__)
            held = False
        if not held:
            # The approval will find the page gone and plan it again.
            logger.warning("errand_checkout_not_held", errand_id=str(job.id))

    async def _parked_card(
        self, origin: str, user_id: str, since: datetime
    ) -> Optional[_Card]:
        """The newest live purchase card made under *origin* since *since*
        (the run's start), or None."""
        cards = await self._cards(origin, user_id, since)
        return cards[0] if cards else None

    async def _cards(
        self, origin: str, user_id: str, since: Optional[datetime] = None
    ) -> list[_Card]:
        """Every purchase card still waiting under *origin* and not past its
        expiry (the approval store marks a card expired only when it lists
        or decides it), made since *since* when given, newest first."""
        from models.pending_action import PendingAction, PendingActionStatus

        query = (
            select(PendingAction.id, PendingAction.arguments)
            .where(
                PendingAction.user_id == uuid.UUID(user_id),
                PendingAction.origin == origin,
                PendingAction.tool_name == _CHECKOUT,
                PendingAction.status == PendingActionStatus.pending,
                PendingAction.expires_at > _card_now(),
            )
            .order_by(PendingAction.created_at.desc())
        )
        if since is not None:
            query = query.where(PendingAction.created_at >= since)
        async with self._session_factory() as session:
            rows = await session.execute(query)
            return [_Card(str(action_id), _checkout_id(arguments)) for action_id, arguments in rows]

    async def close_cards(self, origin: str, user_id: str) -> None:
        """Close every card still waiting under *origin* and let its held
        checkout go: nothing of that errand may be paid any more."""
        try:
            cards = await self._cards(origin, user_id)
        except Exception as exc:
            logger.warning("errand_cards_unreadable", error_type=type(exc).__name__)
            return
        for card in cards:
            await self._deny_card(card.action_id, user_id)
            self.release(user_id, card.checkout_id)

    async def _deny_card(self, action_id: str, user_id: str) -> None:
        if self._deny is None:
            return
        try:
            await self._deny(action_id, user_id)
        except Exception as exc:
            logger.warning("errand_card_deny_failed", error_type=type(exc).__name__)

    async def _tell(self, user_id: str, text: str) -> None:
        if self._send is None:
            return
        from api.routes.agent import strip_url_queries

        try:
            await self._send(user_id, strip_url_queries(text))
        except Exception as exc:
            logger.warning("errand_message_failed", error_type=type(exc).__name__)


async def _own(session: Any, model: Any, user_id: Any, errand_id: Any) -> Any:
    """The errand *errand_id* when it is *user_id*'s, else None."""
    try:
        row = await session.get(model, uuid.UUID(str(errand_id)))
        owner = uuid.UUID(str(user_id))
    except (TypeError, ValueError):
        return None
    return row if row is not None and row.user_id == owner else None


def _checkout_id(arguments: Any) -> str:
    """The checkout a purchase card was made for (its ``_checkout`` facts)."""
    facts = arguments.get("_checkout") if isinstance(arguments, Mapping) else None
    value = facts.get("checkout_id") if isinstance(facts, Mapping) else None
    return value if isinstance(value, str) else ""


def _message(title: str, text: str) -> str:
    return f"{_HEADER.format(title=title)}\n\n{text}"


def _allowed(keys: frozenset[str], *, calendar: bool) -> bool:
    """Whether the switches in *keys* let an errand run: "errand_runs", and
    "calendar_errands" too for one from the calendar."""
    return KEY in keys and (not calendar or CALENDAR_KEY in keys)


def _take_over(needs: Any) -> str:
    """What the owner must do first and where, in the runtime's own fixed
    words for what a page wants (a page's own words never reach them)."""
    from services.agent.runtime import _HANDOFF_FALLBACK, _HANDOFF_WHAT

    needs = needs if isinstance(needs, Mapping) else {}
    what = _HANDOFF_WHAT.get(str(needs.get("kind")), _HANDOFF_FALLBACK)
    url = needs.get("url")
    where = f" ({url})" if isinstance(url, str) and url.startswith(("https://", "http://")) else ""
    return _TAKE_OVER.format(what=what, where=where)


def _needs_you(stopped: Mapping[str, Any]) -> str:
    """What a run that stopped on a page that needs the owner tells them,
    and where; a site that turned the browser away in the runtime's words."""
    from services.agent.runtime import site_refused_reply

    needs = stopped.get("needs_human")
    if not isinstance(needs, Mapping):
        return f"{site_refused_reply(stopped)} {_SITE_REFUSED_NEXT}"
    return _take_over(needs)


# -- the decision path (api/routes/agent.py) ------------------------------------

_service: Optional[ErrandService] = None


def configure(service: Optional[ErrandService]) -> None:
    """Make *service* the process's errand service (main.py), for the
    decision path and /errands."""
    global _service
    _service = service


def current() -> Optional[ErrandService]:
    return _service


def is_errand_origin(origin: Any) -> bool:
    return isinstance(origin, str) and origin.startswith(ERRAND_ORIGIN_PREFIX)


async def purchase_decided(
    db: Any, origin: str, user_id: Any, result: Any, action_id: Any = None
) -> Optional[str]:
    """Move an errand on once its purchase card (*action_id*) was approved
    and the checkout ran, and return the one message the owner gets (None
    when the card belongs to no errand of theirs, or is not the card the
    errand waits on and bought nothing). Bought: done, with what, how much,
    where and the confirmation the checkout read, whatever card of the
    errand did it, so it never runs again after a purchase. Sent but
    unconfirmed: "unsure", never planned again (a retry could buy twice); a
    bank check after the order went out says where to do it and for how
    long. For the card the errand waits on only: the page changed or
    closed: planned again for an immediate run (``wake``), unless it has had
    its MAX_ATTEMPTS runs; a page that needs the owner (a sign-in): waiting,
    with what and where; refused: failed. Commits."""
    from models.errand import Errand
    from services.tools.browser.session import PENDING_IDLE_SECONDS

    row = await _own(db, Errand, user_id, origin[len(ERRAND_ORIGIN_PREFIX) :])
    if row is None:
        return None
    result = result if isinstance(result, Mapping) else {}
    own_card = row.status == "awaiting_approval" and (
        action_id is None or str(row.approval_action_id) == str(action_id)
    )
    bought, sent = result.get("ok") is True, bool(result.get("filled"))
    if not (bought or sent or own_card):
        return None
    card = action_id if action_id is not None else row.approval_action_id
    site = str(result.get("merchant") or await _card_host(db, card) or "the shop")
    replan = False
    if bought:
        row.status = "done"
        line = _BOUGHT.format(item=row.item, amount=result.get("amount", "?"), site=site)
        confirmation = " ".join(str(result.get("confirmation_text_summary") or "").split())
        text = f"{line}\n\n{_CONFIRMATION.format(text=confirmation)}" if confirmation else line
    elif sent:
        row.status = "unsure"
        if result.get("needs_human"):
            hours = PENDING_IDLE_SECONDS // 3600
            text = _BANK_CHECK.format(title=row.title, site=site, hours=hours)
        else:
            text = _UNSURE.format(title=row.title, site=site)
    elif result.get("rule") in _STALE_RULES:
        if row.attempts >= MAX_ATTEMPTS:
            row.status, text = "failed", _STALE_GAVE_UP.format(title=row.title, n=row.attempts)
        else:
            row.status, row.run_on, replan = "planned", datetime.now(timezone.utc).date(), True
            text = _STALE.format(title=row.title)
    elif result.get("rule") == "needs_human" or result.get("needs_human"):
        row.status = "waiting"
        text = _REFUSED.format(title=row.title, reason=_take_over(result.get("needs_human")))
    else:
        reason = (
            " ".join(str(result.get("error") or "").split()) or "The checkout didn't go through."
        )
        row.status, text = "failed", _REFUSED.format(title=row.title, reason=reason)
    row.last_message = text
    await db.commit()
    logger.info("errand_purchase_decided", errand_id=str(row.id), errand_status=row.status)
    if replan and _service is not None:
        _service.wake()
    return text


async def _card_arguments(db: Any, action_id: Any) -> Optional[Mapping[str, Any]]:
    from models.pending_action import PendingAction

    try:
        card = uuid.UUID(str(action_id))
    except (TypeError, ValueError):
        return None
    arguments = (
        await db.execute(select(PendingAction.arguments).where(PendingAction.id == card))
    ).scalar_one_or_none()
    return arguments if isinstance(arguments, Mapping) else None


async def _card_host(db: Any, action_id: Any) -> Optional[str]:
    """The shop's host the purchase card was made for (its ``_checkout``
    facts, read off the page): a failed checkout's result does not name it.
    None when the card is not in the database."""
    if action_id is None:
        return None
    arguments = await _card_arguments(db, action_id)
    facts = arguments.get("_checkout") if arguments is not None else None
    host = facts.get("host") if isinstance(facts, Mapping) else None
    return host if isinstance(host, str) and host else None


async def card_denied(db: Any, action_id: str, user_id: Any) -> bool:
    """Cancel the open errand whose purchase card the owner just denied
    (found by the card's origin): its run in flight is stopped, any other
    card of it closed and the held checkout page let go. False when the
    card was no errand's. Commits."""
    from models.errand import OPEN_STATUSES, Errand
    from models.pending_action import PendingAction

    try:
        card, owner = uuid.UUID(str(action_id)), uuid.UUID(str(user_id))
    except (TypeError, ValueError):
        return False
    found = (
        await db.execute(
            select(PendingAction.origin, PendingAction.arguments).where(
                PendingAction.id == card, PendingAction.user_id == owner
            )
        )
    ).one_or_none()
    origin = found[0] if found is not None else None
    if not isinstance(origin, str) or not is_errand_origin(origin):
        return False
    row = await _own(db, Errand, owner, origin[len(ERRAND_ORIGIN_PREFIX) :])
    if row is None or row.status not in OPEN_STATUSES:
        return False
    was_running = row.status == "running"
    row.status, row.last_message = "cancelled", _DENIED
    await db.commit()
    logger.info("errand_cancelled_by_denial", errand_id=str(row.id))
    if _service is not None:
        if was_running:
            await _service.stop_run(row.id)
        _service.release(str(owner), _checkout_id(found[1]))
        await _service.close_cards(origin, str(owner))
    return True
