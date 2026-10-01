"""The owner's schedule commands in chat: Telegram's /schedules (with Run now,
Pause and Resume buttons), /briefing and /timezone, and Slack's matching
"schedules", "briefing" and "timezone" keywords, all answered from one set of
functions.

Why it exists: pausing, resuming or running a task from the phone is the
owner's own action, so it needs no approval card, but it must be exactly as
scoped as the web routes: every command runs for the account the chat is
linked to (checked by the channel before anything here runs, and again for
every button press), a task id or number that is not theirs reads as not
found, and every change is audited with ids only. Telegram and Slack register
these through their dispatch tables, so neither channel's own code changes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import structlog

logger = structlog.get_logger(__name__)

# Telegram button prefixes (4 characters, reserved in the plan): run now,
# pause, resume.
TELEGRAM_BUTTONS = {"scn:": "run", "scp:": "pause", "scr:": "resume"}
_VERBS = ("run", "pause", "resume")
_NOT_AVAILABLE = "Scheduled tasks are not available right now."
_NO_TASKS = (
    "You have no scheduled tasks yet. Ask Crawler to set one up, e.g. “every weekday "
    "at 8am, summarise what's due on Canvas”, or “send me a daily briefing at 7:30”."
)


@dataclass
class ScheduleBackend:
    """What the commands act through: the schedule toolkit (list, pause,
    resume), the sweeper (run now) and the session factory (the zone)."""

    toolkit: Any
    service: Any
    session_factory: Callable[[], Any]


_backend: Optional[ScheduleBackend] = None


def configure(backend: Optional[ScheduleBackend]) -> None:
    """Set (or clear) the process's backend; main.wire_services does."""
    global _backend
    _backend = backend


def current() -> Optional[ScheduleBackend]:
    return _backend


def _defang(text: str) -> str:
    from services.notifications.page_watch import defang

    return defang(text)


async def _audit(user_id: str, action: str, endpoint: str, data: dict[str, Any]) -> None:
    backend = current()
    if backend is None:
        return
    from models.audit import AuditStatus
    from services.audit import append_audit_log

    try:
        async with backend.session_factory() as session:
            await append_audit_log(
                session,
                user_id=user_id,
                connector_name="schedule",
                action=action,
                endpoint=endpoint,
                scope_used="scheduled_tasks",
                status=AuditStatus.approved,
                request_data=data,
            )
            await session.commit()
    except Exception as exc:
        logger.error("schedule_command_audit_failed", error_type=type(exc).__name__)


async def task_rows(user_id: str) -> Optional[list[dict[str, Any]]]:
    """The user's tasks as schedule.list shows them, oldest first; None
    when they cannot be read."""
    backend = current()
    if backend is None:
        return None
    result = await backend.toolkit.list(user_id)
    if not result.get("ok"):
        return None
    return list(result.get("tasks") or [])


def list_text(rows: list[dict[str, Any]], *, how: str) -> str:
    """The numbered list; *how* says how to act on a number."""
    if not rows:
        return _NO_TASKS
    lines = ["Your scheduled tasks:"]
    for index, row in enumerate(rows, start=1):
        status = str(row.get("status") or "")
        line = f"{index}. {_defang(str(row.get('label') or ''))} — {row.get('schedule')} ({row.get('timezone')})"
        if status != "active":
            line += f" · {status}"
        details = []
        if row.get("next_run_local"):
            details.append(f"next {row['next_run_local']}")
        if row.get("last_status"):
            details.append(f"last run: {row['last_status']}")
        if details:
            line += "\n   " + " · ".join(details)
        lines.append(line)
    lines.append("")
    lines.append(how)
    return "\n".join(lines)


def _resolve(rows: list[dict[str, Any]], ref: str) -> Optional[dict[str, Any]]:
    """The row a number from the list or a task id names, or None."""
    ref = ref.strip()
    if ref.isdigit():
        index = int(ref)
        return rows[index - 1] if 1 <= index <= len(rows) else None
    try:
        wanted = str(uuid.UUID(ref))
    except ValueError:
        return None
    return next((row for row in rows if row.get("id") == wanted), None)


async def act(user_id: str, verb: str, ref: str, *, endpoint: str) -> str:
    """Run now, pause or resume the user's task *ref* (a list number or an
    id); the reply to show. Never touches another user's task."""
    backend = current()
    rows = await task_rows(user_id)
    if backend is None or rows is None:
        return _NOT_AVAILABLE
    row = _resolve(rows, ref)
    if row is None:
        return "No such task. Send /schedules (Slack: schedules) for the list."
    label = _defang(str(row.get("label") or "the task"))
    if verb == "run":
        result = await backend.service.run_now(user_id, row["id"])
        if not result.get("ok"):
            return str(result.get("error") or "Could not run it now.")
        await _audit(user_id, "run_now", endpoint, {"task_id": row["id"]})
        return f"Running “{label}” now; the result follows here."
    paused = verb == "pause"
    result = await backend.toolkit.set_paused(user_id, row["id"], paused)
    if not result.get("ok"):
        return str(result.get("error") or "Could not change it.")
    await _audit(user_id, "pause" if paused else "resume", endpoint, {"task_id": row["id"]})
    if paused:
        return f"Paused “{label}”. It does not run until you resume it."
    nxt = result.get("next_run_local")
    return f"Resumed “{label}”." + (f" Next run: {nxt}." if nxt else "")


async def briefing_now(user_id: str, *, endpoint: str) -> str:
    """Send the user's daily briefing now, or say how to set one up."""
    rows = await task_rows(user_id)
    if rows is None:
        return _NOT_AVAILABLE
    row = next((r for r in rows if r.get("kind") == "briefing"), None)
    if row is None:
        return (
            "You have no daily briefing yet. Ask Crawler, e.g. “send me a daily briefing "
            "at 7:30 with Canvas and my calendar”."
        )
    return await act(user_id, "run", row["id"], endpoint=endpoint)


async def timezone_reply(user_id: str, argument: str, *, endpoint: str) -> str:
    """Show the saved zone, or save a new one (an IANA name)."""
    from models.user import User
    from services.scheduler.timezones import parse_zone

    backend = current()
    if backend is None:
        return _NOT_AVAILABLE
    owner = uuid.UUID(user_id)
    async with backend.session_factory() as session:
        user = await session.get(User, owner)
        if user is None:
            return _NOT_AVAILABLE
        if not argument.strip():
            if user.timezone:
                return f"Your time zone: {user.timezone}. Change it with /timezone Europe/London (Slack: timezone Europe/London)."
            return "No time zone saved yet. Send /timezone America/Chicago (an IANA name; Slack: timezone America/Chicago)."
        zone, error = parse_zone(argument.strip())
        if zone is None:
            return str(error)
        user.timezone = argument.strip()
        await session.commit()
    await _audit(user_id, "timezone", endpoint, {"timezone": argument.strip()})
    return f"Saved: {argument.strip()}. Tasks you already have keep their own time zone."


# -- Telegram --------------------------------------------------------------------

_TELEGRAM_HOW = "Tap a button, or send /schedules run 2, /schedules pause 2 or /schedules resume 2."


def _telegram_keyboard(rows: list[dict[str, Any]]) -> dict[str, Any]:
    buttons: list[list[dict[str, str]]] = []
    for index, row in enumerate(rows, start=1):
        line = [{"text": f"▶ Run {index}", "callback_data": f"scn:{row['id']}"}]
        if row.get("status") == "active":
            line.append({"text": f"⏸ Pause {index}", "callback_data": f"scp:{row['id']}"})
        elif row.get("status") in ("paused", "error"):
            line.append({"text": f"⏯ Resume {index}", "callback_data": f"scr:{row['id']}"})
        buttons.append(line)
    return {"inline_keyboard": buttons}


async def telegram_schedules(service: Any, chat_id: int, user_id: str, argument: str) -> None:
    """/schedules, or /schedules run|pause|resume N."""
    verb, _, ref = argument.strip().partition(" ")
    if verb.lower() in _VERBS and ref.strip():
        text = await act(user_id, verb.lower(), ref, endpoint="telegram:/schedules")
        await service._api("sendMessage", chat_id=chat_id, text=text)
        return
    rows = await task_rows(user_id)
    if rows is None:
        await service._api("sendMessage", chat_id=chat_id, text=_NOT_AVAILABLE)
        return
    params: dict[str, Any] = {"chat_id": chat_id, "text": list_text(rows, how=_TELEGRAM_HOW)[:3900]}
    if rows:
        params["reply_markup"] = _telegram_keyboard(rows[:20])
    await service._api("sendMessage", **params)


async def telegram_button(
    service: Any, verb: str, chat_id: Optional[int], target: str, answer: Callable[[str], Awaitable[None]]
) -> None:
    """A Run now / Pause / Resume press: only from the pressing person's own
    linked chat (A1), and only on their own task."""
    user_id = await service._user_for_chat(chat_id)
    if chat_id is None or user_id is None:
        await answer("This chat is not linked to a Crawler AI account.")
        return
    text = await act(user_id, verb, target, endpoint="telegram:/schedules")
    await answer(text[:190])
    await service._api("sendMessage", chat_id=chat_id, text=text)


def register_telegram(service: Any) -> None:
    """Add /schedules, /briefing and /timezone to a TelegramService."""

    async def schedules(chat_id: int, user_id: str, argument: str) -> None:
        await telegram_schedules(service, chat_id, user_id, argument)

    async def briefing(chat_id: int, user_id: str, _argument: str) -> None:
        text = await briefing_now(user_id, endpoint="telegram:/briefing")
        await service._api("sendMessage", chat_id=chat_id, text=text)

    async def timezone(chat_id: int, user_id: str, argument: str) -> None:
        text = await timezone_reply(user_id, argument, endpoint="telegram:/timezone")
        await service._api("sendMessage", chat_id=chat_id, text=text)

    service._commands["/schedules"] = schedules
    service._commands["/briefing"] = briefing
    service._commands["/timezone"] = timezone


def register_telegram_buttons(service: Any) -> None:
    """Route the scn: / scp: / scr: buttons of a TelegramService."""
    for prefix, verb in TELEGRAM_BUTTONS.items():

        def route(
            chat_id: Optional[int],
            target: str,
            answer: Callable[[str], Awaitable[None]],
            verb: str = verb,
        ) -> Awaitable[None]:
            return telegram_button(service, verb, chat_id, target, answer)

        service._callback_routes[prefix] = route


# -- Slack ------------------------------------------------------------------------

_SLACK_HOW = 'Reply "schedules run 2", "schedules pause 2" or "schedules resume 2".'


def register_slack(channel: Any) -> None:
    """Add the schedules, briefing and timezone keywords to a SlackChannel
    (tried after stop, pending and new; anything else goes to the chat)."""

    async def reply(where: str, text: str) -> None:
        await channel._post_text(where, text)

    def _keyword_schedules(message: Any) -> Optional[Awaitable[None]]:
        words = message.text.strip().split()
        if not words or words[0].lower() != "schedules":
            return None
        if len(words) == 1:

            async def show() -> None:
                rows = await task_rows(channel.user_id)
                await reply(message.channel, _NOT_AVAILABLE if rows is None else list_text(rows, how=_SLACK_HOW))

            return show()
        if len(words) == 3 and words[1].lower() in _VERBS:

            async def change() -> None:
                text = await act(channel.user_id, words[1].lower(), words[2], endpoint="slack:schedules")
                await reply(message.channel, text)

            return change()
        return None

    def _keyword_briefing(message: Any) -> Optional[Awaitable[None]]:
        if message.text.strip().lower() != "briefing":
            return None

        async def run() -> None:
            await reply(message.channel, await briefing_now(channel.user_id, endpoint="slack:briefing"))

        return run()

    def _keyword_timezone(message: Any) -> Optional[Awaitable[None]]:
        words = message.text.strip().split()
        if not words or words[0].lower() != "timezone" or len(words) > 2:
            return None
        argument = words[1] if len(words) == 2 else ""

        async def run() -> None:
            await reply(
                message.channel,
                await timezone_reply(channel.user_id, argument, endpoint="slack:timezone"),
            )

        return run()

    channel._text_handlers.extend([_keyword_schedules, _keyword_briefing, _keyword_timezone])
