"""Weekly app approvals: the owner allows Crawler to operate one app on this
computer for 7 days, from one desktop.act approval card, and only for
requests from the Telegram chat or the browser that allowed it.

Why it exists: every desktop.act had its own approval card, and every card
ends the turn; the task resumes after the tap as a new turn that sends the
whole conversation to the model again. Reading one day in Calendar took six
taps and about 129k tokens (spec 2026-09-25-weekly-app-approvals). With an
app allowed, its acts that only look around in it (``weekly_covers``) run at
once, in the same turn, under every toolkit rule and the taint gate, until the
week is up; then the next act raises a normal card that offers the week again.
Typing, and any click or key that could change or send something, keeps its
card: nobody looks at an act a weekly approval runs.

Tied to a channel (``Channel``): a Telegram approval holds only for turns from
the same Telegram chat (the linked private chat, which is all the bot
serves), and a web approval only for the same browser, named by a random
device id it sends as ``X-Crawler-Device`` and stored here only as a SHA-256.
A turn with no channel (a missing header, an automation) never uses one.

Only apps on ``rules.WEEKLY_APPS`` can be allowed: browsers, mail and chat
apps and anything with a store keep a card for every act.

Connects to: the runtime (``AgentRuntime`` finds an approval before parking a
desktop.act and makes one when a card is approved with ``remember="week"``),
api/routes/agent.py (the channel of each web turn, the card's ``weekly_app``),
api/routes/app_approvals.py (list, revoke), the Telegram bot (the card's
third button, /apps), and the ``app_approvals`` table.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Mapping, Optional, Protocol

import structlog

from services.tools.computer import keys as keymod
from services.tools.computer import rules
from services.tools.computer.toolkit import CARD_KEY, WEEKLY_MARK

logger = structlog.get_logger(__name__)

# How long one "Allow for 7 days" lasts; allowing again renews it.
WEEK = timedelta(days=7)
# The one tool an approval covers.
TOOL = "desktop.act"
# The decision option that allows the card's app for a week.
REMEMBER_WEEK = "week"
# The request header a browser names itself by (the web app's device id).
DEVICE_HEADER = "X-Crawler-Device"
# A device id as the web app makes it (crypto.randomUUID()), or any id of
# that alphabet and length.
_DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{16,100}")
# desktop.act actions that name their app themselves.
_APP_ACTIONS = frozenset({"open_app", "focus_window"})
# What a weekly approval covers (``weekly_covers``): looking around in the
# app. Keys that move through a view, bare or with cmd (Calendar's next and
# previous period).
_NAV_KEYS = frozenset({"up", "down", "left", "right", "pageup", "pagedown", "home", "end"})
_NAV_KEY_MODIFIERS = frozenset({"cmd"})
# Elements a click only selects or shows: a day, a row, a tab, a view.
_NAV_ROLES = frozenset(
    {"cell", "row", "list", "table", "tab", "radio button", "text", "static text", "image"}
)
# Buttons that only move through a view ("Next month", "Today", "Week").
_NAV_BUTTON = re.compile(
    r"(?:go\s+)?(?:next|previous|prev|back|today)(?:\s+(?:day|week|month|year|page))?"
    r"|day|week|month|year|zoom\s+(?:in|out)",
    re.IGNORECASE,
)
# Names of controls that change or send something, whatever their role: a
# weekly approval never clicks one ("Decline" on an invitation mails the
# organizer).
_CONSEQUENTIAL = re.compile(
    r"\b(?:send|share|invit\w*|accept|decline|maybe|tentative|reply|forward|delete|remove"
    r"|trash|erase|save|export|print|publish|post|submit|confirm|buy|pay|purchase|order"
    r"|subscribe|sign|call|facetime|message|e-?mail|upload|attach|install|allow)\b",
    re.IGNORECASE,
)

ChannelKind = Literal["telegram", "web"]
CHANNEL_KINDS: tuple[str, ...] = ("telegram", "web")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Naive timestamps (the SQLite backend) as UTC-aware."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


@dataclass(frozen=True)
class Channel:
    """Where a turn's request came from, as an approval is tied to it:
    ``("telegram", <chat id>)`` or ``("web", <sha256 of the device id>)``."""

    kind: ChannelKind
    key: str

    @classmethod
    def telegram(cls, chat_id: int) -> "Channel":
        return cls("telegram", str(int(chat_id)))

    @classmethod
    def web(cls, device_id: Any) -> Optional["Channel"]:
        """The browser a device id names, or None when it is missing or not
        one (the turn then uses no weekly approval)."""
        if not isinstance(device_id, str) or not _DEVICE_ID.fullmatch(device_id):
            return None
        return cls("web", hashlib.sha256(device_id.encode("ascii")).hexdigest())


@dataclass(frozen=True)
class WeeklyApproval:
    """Store-agnostic view of one approval."""

    id: str
    user_id: str
    app: str
    channel_kind: str
    channel_key: str
    granted_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime] = None

    def holds_for(self, channel: Optional[Channel]) -> bool:
        return (
            channel is not None
            and channel.kind == self.channel_kind
            and channel.key == self.channel_key
        )


def target_app(tool_name: str, arguments: Any) -> Optional[str]:
    """The app a desktop.act call acts in: the ``app`` it names for
    open_app and focus_window, else the app of the screen it is bound to
    (``CARD_KEY``, set by ``ComputerToolkit.bind``). None for any other
    tool, or when the call names none."""
    if tool_name != TOOL or not isinstance(arguments, Mapping):
        return None
    if arguments.get("action") in _APP_ACTIONS:
        app = arguments.get("app")
    else:
        screen = arguments.get(CARD_KEY)
        app = screen.get("app") if isinstance(screen, Mapping) else None
    return app.strip() if isinstance(app, str) and app.strip() else None


def weekly_app_for(tool_name: str, arguments: Any) -> Optional[str]:
    """The app (its weekly-list display name, e.g. "Calendar") a card for
    this call may be allowed for a week, or None: desktop.act only, and only
    in an app on ``rules.WEEKLY_APPS``. *arguments* are the card's (bound)."""
    app = target_app(tool_name, arguments)
    return rules.weekly_app(app) if app else None


def weekly_covers(arguments: Any) -> bool:
    """True when a weekly app approval may run this (bound) desktop.act with
    no card: it only looks around in the app. Scrolling; opening or
    switching to the app (the toolkit then leaves alone a front app that may
    be taking a password); navigation keys; and a click by ref on an element
    that only selects or shows something (a day cell, a row, a tab, a
    "Next month" button), as ``bind`` recorded it (``target``). Never
    ``type``, a click by coordinates, or a click on anything named like a
    control that changes or sends something (Send, Decline, Delete, Save).
    Nobody looks at these acts, and a click by ref carries no text the
    taint gate could match, so everything else keeps its card."""
    if not isinstance(arguments, Mapping):
        return False
    action = arguments.get("action")
    if action == "scroll" or action in _APP_ACTIONS:
        return True
    if action == "key":
        try:
            combo = keymod.parse_combo(arguments.get("keys"))
        except keymod.KeyComboError:
            return False
        return combo.key in _NAV_KEYS and combo.modifiers <= _NAV_KEY_MODIFIERS
    if action not in ("click", "double_click") or not isinstance(arguments.get("ref"), str):
        return False
    screen = arguments.get(CARD_KEY)
    target = screen.get("target") if isinstance(screen, Mapping) else None
    if not isinstance(target, Mapping):
        return False
    role, name = target.get("role"), target.get("name")
    if not isinstance(role, str) or not isinstance(name, str):
        return False
    role, name = role.strip().lower(), name.strip()
    if _CONSEQUENTIAL.search(name):
        return False
    return role in _NAV_ROLES or (role == "button" and bool(_NAV_BUTTON.fullmatch(name)))


def weekly_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """*arguments* (bound, as a card's) marked as run by a weekly approval
    (``WEEKLY_MARK`` on the screen): the toolkit then never brings the app
    forward, since no tap came just before the act."""
    screen = arguments.get(CARD_KEY)
    marked = {**(screen if isinstance(screen, Mapping) else {}), WEEKLY_MARK: True}
    return {**arguments, CARD_KEY: marked}


def _key(app: str) -> str:
    return rules.squash(app)


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


class AppApprovalStore(Protocol):
    async def allow(
        self,
        *,
        user_id: str,
        app: str,
        channel: Channel,
        source_action_id: Optional[str] = None,
    ) -> WeeklyApproval: ...

    async def find(
        self, *, user_id: str, app: str, channel: Channel
    ) -> Optional[WeeklyApproval]: ...

    async def record_use(self, approval_id: str) -> None: ...

    async def list_active(self, user_id: str) -> list[WeeklyApproval]: ...

    async def revoke(self, *, user_id: str, approval_id: str) -> Optional[WeeklyApproval]: ...

    async def revoke_channel(self, *, user_id: str, kind: str) -> int: ...


@dataclass
class _MemRecord:
    approval: WeeklyApproval
    app_key: str
    revoked: bool = False
    uses: int = 0


class InMemoryAppApprovalStore:
    """Single-process store for tests and a runtime with no database; main.py
    injects ``DbAppApprovalStore``."""

    def __init__(self, now: Callable[[], datetime] = _utcnow) -> None:
        self._now = now
        self._records: dict[str, _MemRecord] = {}

    def _live(self, record: _MemRecord, now: datetime) -> bool:
        return not record.revoked and record.approval.expires_at > now

    def _matching(self, user_id: str, app: str, channel: Channel) -> Optional[_MemRecord]:
        now, key = self._now(), _key(app)
        for record in self._records.values():
            a = record.approval
            if (
                a.user_id == user_id
                and record.app_key == key
                and a.holds_for(channel)
                and self._live(record, now)
            ):
                return record
        return None

    async def allow(
        self,
        *,
        user_id: str,
        app: str,
        channel: Channel,
        source_action_id: Optional[str] = None,
    ) -> WeeklyApproval:
        now = self._now()
        record = self._matching(user_id, app, channel)
        if record is not None:
            record.approval = replace(record.approval, granted_at=now, expires_at=now + WEEK)
            return record.approval
        approval = WeeklyApproval(
            id=str(uuid.uuid4()),
            user_id=user_id,
            app=app,
            channel_kind=channel.kind,
            channel_key=channel.key,
            granted_at=now,
            expires_at=now + WEEK,
        )
        self._records[approval.id] = _MemRecord(approval=approval, app_key=_key(app))
        return approval

    async def find(self, *, user_id: str, app: str, channel: Channel) -> Optional[WeeklyApproval]:
        record = self._matching(user_id, app, channel)
        return record.approval if record is not None else None

    async def record_use(self, approval_id: str) -> None:
        record = self._records.get(approval_id)
        if record is not None:
            record.uses += 1
            record.approval = replace(record.approval, last_used_at=self._now())

    async def list_active(self, user_id: str) -> list[WeeklyApproval]:
        now = self._now()
        live = [
            r.approval
            for r in self._records.values()
            if r.approval.user_id == user_id and self._live(r, now)
        ]
        return sorted(live, key=lambda a: a.expires_at)

    async def revoke(self, *, user_id: str, approval_id: str) -> Optional[WeeklyApproval]:
        record = self._records.get(approval_id)
        if record is None or record.revoked or record.approval.user_id != user_id:
            return None
        record.revoked = True
        return record.approval

    async def revoke_channel(self, *, user_id: str, kind: str) -> int:
        count = 0
        for record in self._records.values():
            a = record.approval
            if a.user_id == user_id and a.channel_kind == kind and not record.revoked:
                record.revoked = True
                count += 1
        return count


class DbAppApprovalStore:
    """Persists approvals in the ``app_approvals`` table, with its own
    short-lived sessions (the runtime that calls it has no request scope).
    Expiry is compared in Python, as the approval store does, so a naive
    SQLite timestamp and an aware Postgres one read the same."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        if session_factory is None:
            from core.database import async_session

            session_factory = async_session
        self._session_factory = session_factory
        self._now = now

    @staticmethod
    def _view(row: Any) -> WeeklyApproval:
        return WeeklyApproval(
            id=str(row.id),
            user_id=str(row.user_id),
            app=row.app_name,
            channel_kind=row.channel_kind,
            channel_key=row.channel_key,
            granted_at=_as_utc(row.granted_at),
            expires_at=_as_utc(row.expires_at),
            last_used_at=_as_utc(row.last_used_at) if row.last_used_at else None,
        )

    @staticmethod
    def _uuid(value: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(value))
        except ValueError:
            return None

    async def _live_rows(self, session: Any, user_uuid: uuid.UUID, **where: Any) -> list[Any]:
        from sqlalchemy import select

        from models.app_approval import AppApproval

        query = select(AppApproval).where(
            AppApproval.user_id == user_uuid,
            AppApproval.tool == TOOL,
            AppApproval.revoked_at.is_(None),
        )
        for column, value in where.items():
            query = query.where(getattr(AppApproval, column) == value)
        now = self._now()
        rows = (await session.execute(query)).scalars().all()
        return [row for row in rows if _as_utc(row.expires_at) > now]

    async def allow(
        self,
        *,
        user_id: str,
        app: str,
        channel: Channel,
        source_action_id: Optional[str] = None,
    ) -> WeeklyApproval:
        from models.app_approval import AppApproval

        user_uuid = uuid.UUID(user_id)
        source = self._uuid(source_action_id) if source_action_id else None
        now = self._now()
        async with self._session_factory() as session:
            live = await self._live_rows(
                session,
                user_uuid,
                app_key=_key(app),
                channel_kind=channel.kind,
                channel_key=channel.key,
            )
            if live:
                row = live[0]
                row.granted_at, row.expires_at = now, now + WEEK
                row.source_action_id = source
            else:
                row = AppApproval(
                    user_id=user_uuid,
                    tool=TOOL,
                    app_key=_key(app),
                    app_name=app,
                    channel_kind=channel.kind,
                    channel_key=channel.key,
                    granted_at=now,
                    expires_at=now + WEEK,
                    source_action_id=source,
                )
                session.add(row)
            await session.flush()
            view = self._view(row)
            await session.commit()
        return view

    async def find(self, *, user_id: str, app: str, channel: Channel) -> Optional[WeeklyApproval]:
        user_uuid = self._uuid(user_id)
        if user_uuid is None:
            return None
        async with self._session_factory() as session:
            live = await self._live_rows(
                session,
                user_uuid,
                app_key=_key(app),
                channel_kind=channel.kind,
                channel_key=channel.key,
            )
            return self._view(live[0]) if live else None

    async def record_use(self, approval_id: str) -> None:
        from sqlalchemy import update

        from models.app_approval import AppApproval

        approval_uuid = self._uuid(approval_id)
        if approval_uuid is None:
            return
        async with self._session_factory() as session:
            await session.execute(
                update(AppApproval)
                .where(AppApproval.id == approval_uuid)
                .values(uses=AppApproval.uses + 1, last_used_at=self._now())
            )
            await session.commit()

    async def list_active(self, user_id: str) -> list[WeeklyApproval]:
        user_uuid = self._uuid(user_id)
        if user_uuid is None:
            return []
        async with self._session_factory() as session:
            live = await self._live_rows(session, user_uuid)
            return sorted((self._view(row) for row in live), key=lambda a: a.expires_at)

    async def revoke(self, *, user_id: str, approval_id: str) -> Optional[WeeklyApproval]:
        from sqlalchemy import select

        from models.app_approval import AppApproval

        user_uuid, approval_uuid = self._uuid(user_id), self._uuid(approval_id)
        if user_uuid is None or approval_uuid is None:
            return None
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AppApproval).where(
                        AppApproval.id == approval_uuid,
                        AppApproval.user_id == user_uuid,
                        AppApproval.revoked_at.is_(None),
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            row.revoked_at = self._now()
            view = self._view(row)
            await session.commit()
        return view

    async def revoke_channel(self, *, user_id: str, kind: str) -> int:
        from sqlalchemy import update

        from models.app_approval import AppApproval

        user_uuid = self._uuid(user_id)
        if user_uuid is None:
            return 0
        async with self._session_factory() as session:
            result = await session.execute(
                update(AppApproval)
                .where(
                    AppApproval.user_id == user_uuid,
                    AppApproval.channel_kind == kind,
                    AppApproval.revoked_at.is_(None),
                )
                .values(revoked_at=self._now())
            )
            await session.commit()
        # An UPDATE's result is a CursorResult, which counts the rows.
        return int(getattr(result, "rowcount", 0) or 0)
