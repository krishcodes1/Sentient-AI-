"""Telegram's /errands: the owner's open errands (what, by when, where each
stands), with a "Cancel" button on each (callback prefix ``erc:``), and those
given up in the last week; a "Try again" button (``err:``) on one that waits
for them or was given up.

Why it exists: errands run in the background for days or months, so the
owner must be able to see and stop every one from their phone, in the style
of /apps and /schedules, and pick one up again once they have done what it
needed (a sign-in), or after Crawler stopped trying (the "I've tried 3 times"
message sends them here). Cancelling one whose purchase card waits closes
that card too, so nothing can be paid.

Connects to: services/notifications/telegram.py (registers both under its
command and button tables), services/automation/errands.py (the configured
ErrandService). Shows only the owner's own titles, items and dates.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.automation import errands

logger = structlog.get_logger(__name__)

CB_CANCEL = "erc:"
CB_RETRY = "err:"
_BUTTON_CHARS = 60

NO_ERRANDS = "You have no open errands."
_UNAVAILABLE = "I couldn't load your errands right now. Please try again in a minute."
_HEAD = "Your errands:"
_STATE = {
    "planned": "I'll start on {run_on}",
    "running": "I'm working on it now",
    "awaiting_approval": "waiting for your OK on the payment",
    "waiting": "waiting for you",
    "failed": "I stopped trying",
}
# The errands a "Try again" button can plan again (ErrandService.retry).
_RETRYABLE = ("waiting", "failed")


def _day(value: Optional[date]) -> str:
    return f"{value:%a %b} {value.day}" if value is not None else ""


def errand_line(row: Any) -> str:
    """One errand as a list line: its title and item, by when, and where it
    stands ("• Perfume for Anna: Chanel No 5, needed by Fri Dec 18, I'll
    start on Fri Dec 11")."""
    line = f"• {row.title}"
    if row.item and row.item != row.title:
        line += f": {row.item}"
    if row.needed_by is not None:
        line += f", needed by {_day(row.needed_by)}"
    state = _STATE.get(row.status)
    return f"{line}, {state.format(run_on=_day(row.run_on))}" if state else line


async def telegram_errands(service: Any, chat_id: int, user_id: str) -> None:
    """/errands: every open errand and every one given up this week, each
    with its buttons."""
    errand_service = errands.current()
    try:
        if errand_service is None:
            raise RuntimeError("errands are not wired")
        rows = await errand_service.listed_errands(user_id)
    except Exception as exc:
        logger.warning("telegram_errands_lookup_failed", error_type=type(exc).__name__)
        await service._api("sendMessage", chat_id=chat_id, text=_UNAVAILABLE)
        return
    if not rows:
        await service._api("sendMessage", chat_id=chat_id, text=NO_ERRANDS)
        return
    buttons: list[list[dict[str, str]]] = []
    for row in rows:
        if row.status in _RETRYABLE:
            buttons.append(
                [
                    {
                        "text": f"Try {row.title} again"[:_BUTTON_CHARS],
                        "callback_data": CB_RETRY + str(row.id),
                    }
                ]
            )
        if row.status == "failed":
            continue
        buttons.append(
            [
                {
                    "text": f"Cancel {row.title}"[:_BUTTON_CHARS],
                    "callback_data": CB_CANCEL + str(row.id),
                }
            ]
        )
    text = "\n".join([_HEAD, "", *(errand_line(row) for row in rows)])
    await service._api(
        "sendMessage", chat_id=chat_id, text=text, reply_markup={"inline_keyboard": buttons}
    )


async def telegram_errand_button(
    service: Any,
    chat_id: Optional[int],
    errand_id: str,
    answer: Callable[[str], Awaitable[None]],
    *,
    retry: bool,
) -> None:
    """A /errands button, once the pressing account proves it owns a linked
    chat; the service scopes the change to that user."""
    user_id = await service._user_for_chat(chat_id)
    errand_service = errands.current()
    if chat_id is None or user_id is None:
        await answer("This chat is not linked to a Crawler AI account.")
        return
    if errand_service is None:
        await answer("I can't do that right now. Please try again in a minute.")
        return
    try:
        if retry:
            row = await errand_service.retry(user_id, errand_id)
        else:
            row = await errand_service.cancel(user_id, errand_id)
    except Exception as exc:
        logger.warning("telegram_errand_button_failed", error_type=type(exc).__name__)
        await answer("I couldn't do that right now. Please try again.")
        return
    if row is None:
        await answer("That errand is already finished.")
        return
    if retry:
        await answer("Trying again.")
        text = f"I'm on it: {row.title}. I'll ask you before paying."
    else:
        await answer("Cancelled.")
        text = f"Done. I cancelled {row.title}, and nothing was paid."
    await service._api("sendMessage", chat_id=chat_id, text=text)


def register_telegram(service: Any) -> None:
    """Add /errands to a TelegramService."""

    async def handler(chat_id: int, user_id: str, _argument: str) -> None:
        await telegram_errands(service, chat_id, user_id)

    service._commands["/errands"] = handler


def register_telegram_buttons(service: Any) -> None:
    """Route the erc: and err: buttons of a TelegramService."""

    def cancel(
        chat_id: Optional[int], target: str, answer: Callable[[str], Awaitable[None]]
    ) -> Awaitable[None]:
        return telegram_errand_button(service, chat_id, target, answer, retry=False)

    def retry(
        chat_id: Optional[int], target: str, answer: Callable[[str], Awaitable[None]]
    ) -> Awaitable[None]:
        return telegram_errand_button(service, chat_id, target, answer, retry=True)

    service._callback_routes[CB_CANCEL] = cancel
    service._callback_routes[CB_RETRY] = retry
