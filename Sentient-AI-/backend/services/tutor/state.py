"""Tutor mode's per-conversation state, as stored on
``conversations.tutor_state``, and ``TutorTurn``, which carries it through one
turn (or one command) together with the owner's locks for that user.

Why it exists: whether a chat is in tutor mode has three sources, in this
order: a course lock that engaged in this conversation (sticky: once the chat
named the course it stays locked), an account lock that applies to the user,
and the person's own switch. The state is read once per turn, changed in
memory as the turn goes (the model's tutor.start, a lock engaging from the
message or a tool call's arguments), and written back by the caller only
when it changed, merged over whatever a command wrote meanwhile
(``merge_for_persist``), so a ``/tutor off`` sent while a turn runs is never
lost and no row lock (FOR UPDATE) is needed.

Stored shape (version 1)::

    {"v": 1, "user_on": bool, "user_set_at": iso | null,
     "lock": {"lock_id": str, "label": str (<= 40), "matched_by":
              "text" | "tool_args" | "url", "since": iso} | null}

Any malformed value reads as off, like ``LoadedTools.from_stored``.

Connects to: services/tutor/locks.py, prompt.py and policy.py; the agent
runtime (through services/tutor/hooks.py) and services/tutor/service.py.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional, Sequence

from services.tutor.commands import off_command as _off_command
from services.tutor.commands import on_command as _on_command
from services.tutor.locks import (
    MATCHED_BY,
    MATCHED_BY_TEXT,
    CourseLock,
    match_call,
    match_text,
    sanitize_label,
)
from services.tutor.policy import (
    TUTOR_START_TOOL,
    TUTOR_WITHHELD_TOOLS,
    canonical_name,
    is_url_tool,
)
from services.tutor.prompt import (
    VARIANT_LOCKED_ACCOUNT,
    VARIANT_LOCKED_COURSE,
    VARIANT_ON,
    notice_for,
    render_tutor_block,
    swap_tutor_block,
)

STATE_VERSION = 1
_MAX_ID_CHARS = 64
_MAX_STAMP_CHARS = 64
# Page URLs a turn's own calls named, kept for the graded-page rule.
_MAX_SEEN_URLS = 32

# Effective sources, strongest first.
SOURCE_COURSE = "course"
SOURCE_ACCOUNT = "account"
SOURCE_USER = "user"
SOURCE_OFF = "off"

# What an audit row says the mode went from and to.
MODE_OFF = "off"
MODE_ON = "on"
MODE_LOCKED = "locked"

EVENT_MODE_CHANGED = "tutor_mode_changed"
EVENT_LOCK_ENGAGED = "tutor_lock_engaged"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_stamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value or len(value) > _MAX_STAMP_CHARS:
        return None
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError:
        return None
    return stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class EngagedLock:
    """A course lock that engaged in this conversation."""

    lock_id: str
    label: str
    matched_by: str
    since: str

    @classmethod
    def from_stored(cls, value: Any) -> Optional["EngagedLock"]:
        if not isinstance(value, dict):
            return None
        lock_id = value.get("lock_id")
        matched_by = value.get("matched_by")
        since = value.get("since")
        if not isinstance(lock_id, str) or not lock_id or len(lock_id) > _MAX_ID_CHARS:
            return None
        if matched_by not in MATCHED_BY or _parse_stamp(since) is None:
            return None
        return cls(
            lock_id=lock_id,
            label=sanitize_label(value.get("label")),
            matched_by=str(matched_by),
            since=str(since),
        )

    def to_stored(self) -> dict[str, Any]:
        return {
            "lock_id": self.lock_id,
            "label": sanitize_label(self.label),
            "matched_by": self.matched_by,
            "since": self.since,
        }


@dataclass(frozen=True)
class TutorState:
    """What ``conversations.tutor_state`` holds: the person's own switch
    (``user_on``, set at ``user_set_at``) and the course lock that engaged
    in the conversation, if any."""

    user_on: bool = False
    user_set_at: Optional[str] = None
    lock: Optional[EngagedLock] = None

    @classmethod
    def from_stored(cls, value: Any) -> "TutorState":
        """Read a stored column value. NULL, a non-dict, another version or
        a bad field reads as off (a bad lock is dropped, a bad switch is off)."""
        if not isinstance(value, dict) or value.get("v") != STATE_VERSION:
            return cls()
        user_on = value.get("user_on")
        stamp = value.get("user_set_at")
        return cls(
            user_on=user_on is True,
            user_set_at=stamp if _parse_stamp(stamp) is not None else None,
            lock=EngagedLock.from_stored(value.get("lock")),
        )

    def to_stored(self) -> dict[str, Any]:
        return {
            "v": STATE_VERSION,
            "user_on": self.user_on,
            "user_set_at": self.user_set_at,
            "lock": self.lock.to_stored() if self.lock is not None else None,
        }


def merge_for_persist(stored: TutorState, turn: TutorState) -> TutorState:
    """What to write back after a turn: *turn*'s state merged over what is
    *stored* now (a command may have written meanwhile).

    An engaged lock is sticky: whichever side has one keeps it. When both
    do, the turn's wins: it started from what was stored, so a different
    lock there is one it engaged after the stored one's row was deleted.
    The person's switch follows whoever set it last (``user_set_at``; never
    set is oldest)."""
    lock = turn.lock if turn.lock is not None else stored.lock
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    stored_at = _parse_stamp(stored.user_set_at) or epoch
    turn_at = _parse_stamp(turn.user_set_at) or epoch
    newer = turn if turn_at > stored_at else stored
    return TutorState(user_on=newer.user_on, user_set_at=newer.user_set_at, lock=lock)


@dataclass(frozen=True)
class Effective:
    """Whether tutor mode is on for this conversation now, and why:
    ``source`` is "course" (an engaged course lock that still exists),
    "account" (an account lock that applies), "user" (the person's own
    switch) or "off". ``label`` is the lock's sanitised label."""

    on: bool
    source: str
    lock_id: Optional[str] = None
    label: str = ""

    @property
    def variant(self) -> Optional[str]:
        """The ``<tutor_mode>`` block variant (services/tutor/prompt.py)."""
        return {
            SOURCE_USER: VARIANT_ON,
            SOURCE_COURSE: VARIANT_LOCKED_COURSE,
            SOURCE_ACCOUNT: VARIANT_LOCKED_ACCOUNT,
        }.get(self.source)

    @property
    def mode(self) -> str:
        """"off", "on" or "locked", as audit rows and the web view say it."""
        if self.source in (SOURCE_COURSE, SOURCE_ACCOUNT):
            return MODE_LOCKED
        return MODE_ON if self.on else MODE_OFF

    @property
    def locked(self) -> bool:
        return self.source in (SOURCE_COURSE, SOURCE_ACCOUNT)


class TutorTurn:
    """Tutor mode for one turn (or one command) of one conversation.

    Built by ``services.tutor.service.load_tutor_turn`` with the stored
    state and the locks that apply to the user (their own and the
    every-account ones); only ever built when the ``tutor_mode`` capability
    is on, so a turn with the switch off has no TutorTurn at all.

    ``changed`` is set when the state changed and the caller must persist
    it (``persist_tutor_state``); ``notice`` is the line the reply gains
    when this turn switched the mode on; ``drain_events`` hands over the
    audit events (``tutor_mode_changed``, ``tutor_lock_engaged``) once.
    """

    def __init__(
        self,
        state: TutorState,
        locks: Iterable[CourseLock] = (),
        *,
        channel: str = "web",
        conversation_id: str = "",
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.state = state
        self._locks: tuple[CourseLock, ...] = tuple(locks)
        self.channel = channel
        self.conversation_id = conversation_id
        self._now = now or _utcnow
        self.changed = False
        self.notice: Optional[str] = None
        self._events: list[dict[str, Any]] = []
        # The block the system message ends with now (hooks.begin_turn,
        # hooks.end_of_round keep it current).
        self.applied_block: Optional[str] = None
        self.seen_urls: list[str] = []
        # False for a turn whose newest user-role message is not the
        # person's own words (the turn resumed after an approval ends on the
        # approved call's result): tool output never engages a lock.
        self.text_engages = True

    # -- reading --------------------------------------------------------

    @property
    def locks(self) -> tuple[CourseLock, ...]:
        return self._locks

    @property
    def off_command(self) -> str:
        return _off_command(self.channel)

    @property
    def on_command(self) -> str:
        return _on_command(self.channel)

    def _engaged_lock(self) -> Optional[CourseLock]:
        """The course lock the conversation engaged, while its row exists
        (a deleted lock no longer holds the chat)."""
        engaged = self.state.lock
        if engaged is None:
            return None
        return next(
            (lock for lock in self._locks if lock.is_course and lock.lock_id == engaged.lock_id),
            None,
        )

    def _account_lock(self) -> Optional[CourseLock]:
        return next((lock for lock in self._locks if lock.is_account), None)

    @property
    def effective(self) -> Effective:
        engaged = self._engaged_lock()
        if engaged is not None:
            return Effective(True, SOURCE_COURSE, engaged.lock_id, engaged.label or "this course")
        account = self._account_lock()
        if account is not None:
            return Effective(True, SOURCE_ACCOUNT, account.lock_id, "this account")
        if self.state.user_on:
            return Effective(True, SOURCE_USER)
        return Effective(False, SOURCE_OFF)

    @property
    def block(self) -> Optional[str]:
        """The ``<tutor_mode>`` block for the effective state, or None."""
        return render_tutor_block(self.effective.variant)

    def allows(self, tool_name: Any) -> bool:
        """Whether *tool_name* may be offered or run now. While tutor mode is
        on, the withheld tools are not, and neither is tutor.start (it is
        offered only while the mode is off). Everything else is."""
        if not self.effective.on:
            return True
        canonical = canonical_name(tool_name)
        return canonical != TUTOR_START_TOOL and canonical not in TUTOR_WITHHELD_TOOLS

    def lock_labels(self) -> list[str]:
        """The labels of the locks that apply to this person, for status."""
        return [
            lock.label if lock.is_course else "this account" for lock in self._locks if lock.label
        ]

    # -- changing -------------------------------------------------------

    def _stamp(self) -> str:
        return self._now().astimezone(timezone.utc).isoformat()

    def _mode_changed(self, before: Effective, after: Effective, via: str) -> None:
        if before.mode == after.mode and before.variant == after.variant:
            return
        self._events.append(
            {
                "event": EVENT_MODE_CHANGED,
                "from": before.mode,
                "to": after.mode,
                "via": via,
                "conversation_id": self.conversation_id,
            }
        )

    def _engage(self, lock: CourseLock, matched_by: str) -> bool:
        if self._engaged_lock() is not None or not lock.is_course:
            return False
        before = self.effective
        self.state = replace(
            self.state,
            lock=EngagedLock(lock.lock_id, lock.label, matched_by, self._stamp()),
        )
        self.changed = True
        self._events.append(
            {"event": EVENT_LOCK_ENGAGED, "lock_id": lock.lock_id, "matched_by": matched_by}
        )
        after = self.effective
        if after.variant != before.variant:
            self._mode_changed(before, after, "lock")
            self.notice = notice_for(after.variant, off_command=self.off_command, label=after.label)
        return True

    def engage_from_text(self, text: Any) -> bool:
        """Engage the first course lock the person's own message names.
        Only ever given the newest user message, never a tool result."""
        if not self.text_engages or self._engaged_lock() is not None:
            return False
        lock = match_text((lock for lock in self._locks if lock.is_course), text)
        return lock is not None and self._engage(lock, MATCHED_BY_TEXT)

    def engage_from_call(self, tool_name: Any, arguments: Any) -> bool:
        """Engage the course lock a tool call's own arguments touch (a Canvas
        ``course_id``, a ``/courses/<id>/`` URL). Also notes a page URL the
        call opens, for the graded-page rule."""
        if isinstance(arguments, dict) and is_url_tool(canonical_name(tool_name)):
            url = arguments.get("url")
            if isinstance(url, str) and url.strip() and len(self.seen_urls) < _MAX_SEEN_URLS:
                self.seen_urls.append(url.strip())
        if self._engaged_lock() is not None:
            return False
        found = match_call(self._locks, tool_name, arguments)
        return found is not None and self._engage(*found)

    def start_by_tool(self) -> dict[str, Any]:
        """Answer the model's tutor.start: switch the mode on for this
        conversation (the person's switch, as if they had typed /tutor on)."""
        before = self.effective
        if before.on:
            return {"ok": True, "tutor": "on", "note": "already on"}
        self.state = replace(self.state, user_on=True, user_set_at=self._stamp())
        self.changed = True
        after = self.effective
        self._mode_changed(before, after, "tool")
        self.notice = notice_for(after.variant, off_command=self.off_command, label=after.label)
        return {"ok": True, "tutor": "on"}

    def set_user(self, on: bool, *, via: str) -> tuple[Effective, Effective]:
        """The person's own switch (a command, or the web toggle): recorded
        with the time, so it wins over an older write when merged. A lock
        still holds the chat when it is switched off. Returns the effective
        state before and after."""
        before = self.effective
        self.state = replace(self.state, user_on=bool(on), user_set_at=self._stamp())
        self.changed = True
        after = self.effective
        self._mode_changed(before, after, via)
        return before, after

    def drain_events(self) -> list[dict[str, Any]]:
        """The audit events so far, handed over once."""
        events, self._events = self._events, []
        return events

    def take_notice(self) -> Optional[str]:
        notice, self.notice = self.notice, None
        return notice

    # -- the system message --------------------------------------------

    def block_changed(self) -> bool:
        """Whether the block the system message carries is out of date."""
        return self.block != self.applied_block

    def apply_block(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """*messages* with the system message's tutor block brought up to date."""
        block = self.block
        swapped = swap_tutor_block(messages, self.applied_block, block)
        self.applied_block = block
        return swapped

    def offered(self, schemas: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        """*schemas* (tool dicts with a "name") without what ``allows`` refuses."""
        return [schema for schema in schemas if self.allows(schema.get("name", ""))]
