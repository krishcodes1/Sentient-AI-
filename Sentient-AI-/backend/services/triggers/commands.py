"""The owner's trigger commands in chat: Telegram's /triggers (a numbered list
with Pause and Resume buttons, and the text fallbacks "/triggers pause 2",
"/triggers resume 2", "/triggers delete 2" then "/triggers delete 2 yes") and
Slack's matching "triggers" keywords, all answered from one set of functions.

Why it exists: pausing, resuming or deleting a trigger from the phone is the
owner's own action, so it needs no approval card, but it must be exactly as
scoped as the web routes: every command runs for the account the chat is
linked to (checked by the channel before anything here runs, and again for
every button press), a trigger number or id that is not theirs reads as not
found, a delete needs a second "yes", and every change is audited with ids
only (endpoint "telegram:/triggers" or "slack:triggers"). Telegram and Slack
register these through their dispatch tables.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, tzinfo
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.triggers import sources as src

logger = structlog.get_logger(__name__)

# Telegram button prefixes (4 characters, reserved in the plan).
TELEGRAM_BUTTONS = {"tgp:": "pause", "tgr:": "resume"}
_VERBS = ("pause", "resume", "delete")
_NOT_AVAILABLE = "Triggers are not available right now."
_NO_TRIGGERS = (
    "You have no triggers yet. Ask Crawler, e.g. “tell me when Professor Smith emails me” "
    "or “ping me when a Canvas announcement is posted”."
)
_ACTIONS = {"pause": "trigger_paused", "resume": "trigger_resumed", "delete": "trigger_deleted"}


@dataclass
class TriggerBackend:
    """What the commands act through: the trigger toolkit (list, pause,
    resume, delete) and the session factory (the audit rows)."""

    toolkit: Any
    session_factory: Callable[[], Any]


_backend: Optional[TriggerBackend] = None


def configure(backend: Optional[TriggerBackend]) -> None:
    """Set (or clear) the process's backend; main.wire_services does."""
    global _backend
    _backend = backend


def current() -> Optional[TriggerBackend]:
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
                connector_name="triggers",
                action=action,
                endpoint=endpoint,
                scope_used="event_triggers",
                status=AuditStatus.approved,
                request_data=data,
            )
            await session.commit()
    except Exception as exc:
        logger.error("trigger_command_audit_failed", error_type=type(exc).__name__)


async def trigger_rows(user_id: str) -> Optional[list[dict[str, Any]]]:
    """The user's triggers as triggers.list shows them, oldest first; None
    when they cannot be read."""
    backend = current()
    if backend is None:
        return None
    result = await backend.toolkit.list_triggers(user_id)
    if not result.get("ok"):
        return None
    return list(result.get("triggers") or [])


async def user_zone(user_id: str) -> Optional[tzinfo]:
    """The user's saved time zone, or None (then this computer's zone is
    used); never raises."""
    backend = current()
    if backend is None:
        return None
    from sqlalchemy import select

    from models.user import User
    from services.scheduler.timezones import parse_zone

    try:
        async with backend.session_factory() as session:
            zone = (
                await session.execute(select(User.timezone).where(User.id == uuid.UUID(str(user_id))))
            ).scalar_one_or_none()
    except Exception as exc:
        logger.warning("trigger_list_zone_unreadable", error_type=type(exc).__name__)
        return None
    tz, _err = parse_zone(zone) if zone else (None, None)
    return tz


def _when(value: Any, tz: Optional[tzinfo]) -> str:
    """A stored UTC time as the chats show it ("Wed Sep 30 10:03"), in *tz*
    or else this computer's zone; the value itself when it is not a time."""
    try:
        moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    local = moment.astimezone(tz) if tz is not None else moment.astimezone()
    return f"{local:%a} {local:%b} {local.day} {local:%H:%M}"


def _phrase(source: Any) -> str:
    spec = src.SPECS.get(str(source))
    return spec.phrase if spec is not None else str(source)


def list_text(rows: list[dict[str, Any]], *, how: str, tz: Optional[tzinfo] = None) -> str:
    """The numbered list (label, source, mode, status, last fired in *tz*
    or this computer's zone, runs today); *how* says how to act on a
    number."""
    if not rows:
        return _NO_TRIGGERS
    lines = ["Your triggers:"]
    for index, row in enumerate(rows, start=1):
        mode = "runs a task" if row.get("mode") == "run_task" else "messages you"
        line = f"{index}. {_defang(str(row.get('label') or ''))} — {_phrase(row.get('source'))}, {mode}"
        status = str(row.get("status") or "")
        if status != "active":
            line += f" · {status}"
        details = []
        if row.get("last_fired_at"):
            details.append(f"last fired {_when(row['last_fired_at'], tz)}")
        if row.get("mode") == "run_task":
            details.append(f"runs today {row.get('runs_today', 0)}/{row.get('max_runs_per_day')}")
        if row.get("last_error"):
            details.append(f"problem: {_defang(str(row['last_error']))}")
        if details:
            line += "\n   " + " · ".join(details)
        lines.append(line)
    lines.append("")
    lines.append(how)
    return "\n".join(lines)


def _resolve(rows: list[dict[str, Any]], ref: str) -> Optional[dict[str, Any]]:
    """The row a number from the list or a trigger id names, or None."""
    ref = ref.strip()
    if ref.isdigit():
        index = int(ref)
        return rows[index - 1] if 1 <= index <= len(rows) else None
    try:
        wanted = str(uuid.UUID(ref))
    except ValueError:
        return None
    return next((row for row in rows if row.get("id") == wanted), None)


async def act(user_id: str, verb: str, ref: str, *, endpoint: str, confirmed: bool = False, how_confirm: str = "") -> str:
    """Pause, resume or delete the user's trigger *ref* (a list number or an
    id); the reply to show. A delete without *confirmed* only asks for the
    "yes". Never touches another user's trigger."""
    backend = current()
    rows = await trigger_rows(user_id)
    if backend is None or rows is None:
        return _NOT_AVAILABLE
    row = _resolve(rows, ref)
    if row is None:
        return "No such trigger. Send /triggers (Slack: triggers) for the list."
    label = _defang(str(row.get("label") or "the trigger"))
    if verb == "delete":
        if not confirmed:
            return f"Delete “{label}” and its queued events? Send {how_confirm} to confirm."
        result = await backend.toolkit.delete_trigger(user_id, row["id"])
        if not result.get("ok"):
            return str(result.get("error") or "Could not delete it.")
        await _audit(user_id, _ACTIONS["delete"], endpoint, {"trigger_id": row["id"]})
        return f"Deleted “{label}”. Its conversation is kept."
    paused = verb == "pause"
    result = await backend.toolkit.set_paused(user_id, row["id"], paused)
    if not result.get("ok"):
        return str(result.get("error") or "Could not change it.")
    await _audit(user_id, _ACTIONS[verb], endpoint, {"trigger_id": row["id"]})
    if paused:
        return f"Paused “{label}”. Nothing is checked or sent until you resume it."
    return f"Resumed “{label}”. It checks again now; what arrived while it was paused is not sent."


# -- Telegram --------------------------------------------------------------------

_TELEGRAM_HOW = "Tap a button, or send /triggers pause 2, /triggers resume 2 or /triggers delete 2."


def _telegram_keyboard(rows: list[dict[str, Any]]) -> dict[str, Any]:
    buttons: list[list[dict[str, str]]] = []
    for index, row in enumerate(rows, start=1):
        if row.get("status") == "active":
            buttons.append([{"text": f"⏸ Pause {index}", "callback_data": f"tgp:{row['id']}"}])
        else:
            buttons.append([{"text": f"⏯ Resume {index}", "callback_data": f"tgr:{row['id']}"}])
    return {"inline_keyboard": buttons}


def _parse(argument: str) -> tuple[str, str, bool]:
    """(verb, ref, confirmed) from "pause 2", "delete 2 yes"."""
    words = argument.strip().split()
    if len(words) >= 2 and words[0].lower() in _VERBS:
        confirmed = len(words) == 3 and words[0].lower() == "delete" and words[2].lower() == "yes"
        if len(words) == 2 or confirmed:
            return words[0].lower(), words[1], confirmed
    return "", "", False


async def telegram_triggers(service: Any, chat_id: int, user_id: str, argument: str) -> None:
    """/triggers, or /triggers pause|resume|delete N [yes]."""
    verb, ref, confirmed = _parse(argument)
    if verb:
        text = await act(
            user_id,
            verb,
            ref,
            endpoint="telegram:/triggers",
            confirmed=confirmed,
            how_confirm=f"/triggers delete {ref} yes",
        )
        await service._api("sendMessage", chat_id=chat_id, text=text)
        return
    rows = await trigger_rows(user_id)
    if rows is None:
        await service._api("sendMessage", chat_id=chat_id, text=_NOT_AVAILABLE)
        return
    text = list_text(rows, how=_TELEGRAM_HOW, tz=await user_zone(user_id))
    params: dict[str, Any] = {"chat_id": chat_id, "text": text[:3900]}
    if rows:
        params["reply_markup"] = _telegram_keyboard(rows[:20])
    await service._api("sendMessage", **params)


async def telegram_button(
    service: Any, verb: str, chat_id: Optional[int], target: str, answer: Callable[[str], Awaitable[None]]
) -> None:
    """A Pause / Resume press: only from the pressing person's own linked
    chat, and only on their own trigger."""
    user_id = await service._user_for_chat(chat_id)
    if chat_id is None or user_id is None:
        await answer("This chat is not linked to a Crawler AI account.")
        return
    text = await act(user_id, verb, target, endpoint="telegram:/triggers")
    await answer(text[:190])
    await service._api("sendMessage", chat_id=chat_id, text=text)


def register_telegram(service: Any) -> None:
    """Add /triggers to a TelegramService."""

    async def triggers(chat_id: int, user_id: str, argument: str) -> None:
        await telegram_triggers(service, chat_id, user_id, argument)

    service._commands["/triggers"] = triggers


def register_telegram_buttons(service: Any) -> None:
    """Route the tgp: / tgr: buttons of a TelegramService."""
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

_SLACK_HOW = 'Reply "triggers pause 2", "triggers resume 2" or "triggers delete 2".'


def register_slack(channel: Any) -> None:
    """Add the "triggers" keywords to a SlackChannel (tried after the ones
    registered before; anything else goes to the chat)."""

    def _keyword_triggers(message: Any) -> Optional[Awaitable[None]]:
        words = message.text.strip().split()
        if not words or words[0].lower() != "triggers":
            return None
        if len(words) == 1:

            async def show() -> None:
                rows = await trigger_rows(channel.user_id)
                if rows is None:
                    await channel._post_text(message.channel, _NOT_AVAILABLE)
                    return
                tz = await user_zone(channel.user_id)
                await channel._post_text(message.channel, list_text(rows, how=_SLACK_HOW, tz=tz))

            return show()
        verb, ref, confirmed = _parse(" ".join(words[1:]))
        if not verb:
            return None

        async def change() -> None:
            text = await act(
                channel.user_id,
                verb,
                ref,
                endpoint="slack:triggers",
                confirmed=confirmed,
                how_confirm=f'"triggers delete {ref} yes"',
            )
            await channel._post_text(message.channel, text)

        return change()

    channel._text_handlers.append(_keyword_triggers)
