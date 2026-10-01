"""Flashcard reviews and practice quizzes on Telegram, with no model involved:
/decks, /review [n], /quiz n [count] and /export n [anki|csv], the text
fallbacks /show /again /hard /good /easy /skip /end and /a-/f, and the inline
buttons (sra: srg: srk: sre: sqc: sqr: sqg: sqe:).

Why it exists: the StudyChannel flow (services/study/channel.py) is drawn here
for Telegram and registered through TelegramService's dispatch tables, so the
bot's own code does not change. Every command and press runs only for the
account the chat is linked to (the service checks the link before a command;
a press is checked here, as every button route does), only while the owner's
study switch is on, and as tracked chat work under a per-chat study lock, not
the turn lock: a running agent turn never blocks a review. A press is
answered as soon as its database step is done; showing an answer edits the
card's message, a grade freezes it and sends the next card, and a repeated
press answers "Already answered" and changes nothing. Every callback_data is
at most 64 bytes. /export sends the file with sendDocument (multipart, like
_send_photo), its name limited to letters, digits, space, '_' and '-'.
"""

from __future__ import annotations

import asyncio
import weakref
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.security import channels as secret_text
from services.study import channel as study_channel
from services.study import srs
from services.study.channel import StudyChannel
from services.study.render import CALLBACK_MAX_BYTES, LETTERS, Screen

logger = structlog.get_logger(__name__)

COMMANDS = ("/decks", "/review", "/quiz", "/export")
FALLBACK_WORDS = ("show", "again", "hard", "good", "easy", "skip", "end", *(c.lower() for c in LETTERS))
BUTTON_PREFIXES = ("sra:", "srg:", "srk:", "sre:", "sqc:", "sqr:", "sqg:", "sqe:")
_MESSAGE_CHARS = 4000
_REMEMBERED_MESSAGES = 2000
_NOT_AVAILABLE = "Flashcards are not available right now."
_NOT_LINKED = "This chat is not linked to a Crawler AI account."


def _when_denied() -> str:
    from services.capabilities.study import CAPABILITY

    return CAPABILITY.when_denied


class _ChatState:
    """Per service: each chat's study lock, and the message each card or
    question was sent as (so a press can edit it)."""

    def __init__(self) -> None:
        self.locks: dict[int, asyncio.Lock] = {}
        self.messages: OrderedDict[tuple[int, str], int] = OrderedDict()


_STATES: weakref.WeakKeyDictionary[Any, _ChatState] = weakref.WeakKeyDictionary()


def _state(service: Any) -> _ChatState:
    found = _STATES.get(service)
    if found is None:
        found = _ChatState()
        _STATES[service] = found
    return found


def _key(chat_id: int) -> str:
    return f"telegram:{chat_id}"


def keyboard(screen: Screen) -> Optional[dict[str, Any]]:
    """The screen's buttons as an inline keyboard (a button whose data would
    exceed Telegram's 64 bytes is left out)."""
    rows = [
        [{"text": b.label, "callback_data": b.data} for b in row if len(b.data.encode("utf-8")) <= CALLBACK_MAX_BYTES]
        for row in screen.buttons
    ]
    rows = [r for r in rows if r]
    return {"inline_keyboard": rows} if rows else None


def message_token(data: str) -> Optional[str]:
    """Which card or question a button (or a screen's first button) belongs
    to: ``item:<id>`` or ``quiz:<attempt>:<position>``."""
    prefix, target = data[:4], data[4:]
    if prefix in ("sra:", "srg:", "srk:") and target:
        return "item:" + target.split(":", 1)[0]
    if prefix in ("sqc:", "sqr:", "sqg:") and target.count(":") >= 1:
        attempt, position = target.split(":")[:2]
        return f"quiz:{attempt}:{position}"
    return None


def _screen_token(screen: Screen) -> Optional[str]:
    for row in screen.buttons:
        for button in row:
            token = message_token(button.data)
            if token is not None:
                return token
    return None


async def send_screen(service: Any, chat_id: int, screen: Screen) -> Optional[int]:
    params: dict[str, Any] = {"chat_id": chat_id, "text": screen.text[:_MESSAGE_CHARS]}
    markup = keyboard(screen)
    if markup is not None:
        params["reply_markup"] = markup
    result = await service._api("sendMessage", **params)
    message_id = result.get("message_id") if isinstance(result, dict) else None
    token = _screen_token(screen)
    if isinstance(message_id, int) and token is not None:
        messages = _state(service).messages
        messages[(chat_id, token)] = message_id
        while len(messages) > _REMEMBERED_MESSAGES:
            messages.popitem(last=False)
    return message_id if isinstance(message_id, int) else None


async def edit_screen(service: Any, chat_id: int, message_id: int, screen: Screen) -> None:
    """Replace a sent card or question with *screen* (no keyboard when the
    screen has no buttons: the message is frozen)."""
    params: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": screen.text[:_MESSAGE_CHARS]}
    markup = keyboard(screen)
    if markup is not None:
        params["reply_markup"] = markup
    await service._api("editMessageText", **params)


async def send_document(
    service: Any, chat_id: int, filename: str, data: bytes, media_type: str, caption: str = ""
) -> bool:
    """Upload a file to the chat (multipart sendDocument, modelled on
    TelegramService._send_photo). The caption is masked as a text message
    is; failures are logged, never raised."""
    caption = secret_text.mask_text(caption, channel="telegram")[0]
    try:
        resp = await service._client.post(
            "/sendDocument",
            data={"chat_id": str(chat_id), "caption": caption[:1024]},
            files={"document": (filename, data, media_type)},
        )
        body = resp.json()
        if not body.get("ok"):
            logger.warning(
                "telegram_api_error",
                method="sendDocument",
                code=body.get("error_code"),
                description=str(body.get("description", ""))[:200],
            )
            return False
        return True
    except Exception as exc:
        logger.warning("telegram_request_failed", method="sendDocument", error_type=type(exc).__name__)
        return False


def _run(service: Any, chat_id: int, work: Callable[[], Awaitable[None]]) -> None:
    """Run *work* as the chat's tracked work under its study lock."""

    async def locked() -> None:
        lock = _state(service).locks.setdefault(chat_id, asyncio.Lock())
        async with lock:
            try:
                await work()
            except Exception as exc:  # a failed review step must not kill the poller's task set
                logger.error("telegram_study_failed", chat_id=chat_id, error_type=type(exc).__name__)
                await service._api("sendMessage", chat_id=chat_id, text="That did not work; try again.")

    service._track(chat_id, locked(), name=f"telegram-study-{chat_id}")


async def _ready(service: Any, chat_id: int) -> Optional[StudyChannel]:
    """The study flow, or None after telling the chat why not."""
    study = study_channel.current()
    if study is None:
        await service._api("sendMessage", chat_id=chat_id, text=_NOT_AVAILABLE)
        return None
    if not await study.is_enabled():
        await service._api("sendMessage", chat_id=chat_id, text=_when_denied())
        return None
    return study


def _number(text: str) -> Optional[int]:
    return int(text) if text.isdecimal() and len(text) <= 6 else None


# -- commands ---------------------------------------------------------------------


def register_telegram(service: Any) -> None:
    """Add /decks, /review, /quiz, /export and the review fallbacks."""

    def command(handler: Callable[[StudyChannel, int, str, str], Awaitable[None]]) -> Callable[[int, str, str], Awaitable[None]]:
        async def run(chat_id: int, user_id: str, argument: str) -> None:
            async def work() -> None:
                study = await _ready(service, chat_id)
                if study is not None:
                    await handler(study, chat_id, user_id, argument)

            _run(service, chat_id, work)

        return run

    async def decks(study: StudyChannel, chat_id: int, user_id: str, _argument: str) -> None:
        await send_screen(service, chat_id, await study.decks(user_id))

    async def review(study: StudyChannel, chat_id: int, user_id: str, argument: str) -> None:
        text = argument.strip()
        number = _number(text) if text else None
        if text and number is None:
            await service._api("sendMessage", chat_id=chat_id, text="Send /review, or /review 2 for deck 2.")
            return
        await send_screen(service, chat_id, await study.review_start(_key(chat_id), user_id, "telegram", number))

    async def quiz(study: StudyChannel, chat_id: int, user_id: str, argument: str) -> None:
        parts = argument.split()
        numbers = [_number(p) for p in parts]
        if not 1 <= len(parts) <= 2 or any(n is None for n in numbers):
            await service._api("sendMessage", chat_id=chat_id, text="Send /quiz 2 for deck 2, or /quiz 2 10 for ten questions.")
            return
        count = numbers[1] if len(numbers) == 2 else None
        await send_screen(service, chat_id, await study.quiz_start(_key(chat_id), user_id, "telegram", numbers[0], count))

    async def export(study: StudyChannel, chat_id: int, user_id: str, argument: str) -> None:
        parts = argument.lower().split()
        number = _number(parts[0]) if parts else None
        fmt = parts[1] if len(parts) > 1 else "anki"
        if number is None or len(parts) > 2:
            await service._api("sendMessage", chat_id=chat_id, text="Send /export 2, or /export 2 csv, for deck 2.")
            return
        made, reason = await study.export_file(user_id, number, fmt)
        if made is None:
            await service._api("sendMessage", chat_id=chat_id, text=reason)
            return
        filename, data, media_type = made
        caption = "Anki: File → Import this file." if fmt == "anki" else "Open it in a spreadsheet."
        if not await send_document(service, chat_id, filename, data, media_type, caption):
            await service._api("sendMessage", chat_id=chat_id, text="The file could not be sent; try again shortly.")

    service._commands["/decks"] = command(decks)
    service._commands["/review"] = command(review)
    service._commands["/quiz"] = command(quiz)
    service._commands["/export"] = command(export)

    for word in FALLBACK_WORDS:

        async def fallback(study: StudyChannel, chat_id: int, user_id: str, _argument: str, word: str = word) -> None:
            for screen in await study.word(_key(chat_id), user_id, "telegram", word):
                await send_screen(service, chat_id, screen)

        service._commands[f"/{word}"] = command(fallback)


# -- buttons ----------------------------------------------------------------------


async def _press(
    service: Any,
    chat_id: int,
    user_id: str,
    prefix: str,
    target: str,
    answer: Callable[[str], Awaitable[None]],
) -> None:
    study = study_channel.current()
    if study is None:
        await answer(_NOT_AVAILABLE)
        return
    if not await study.is_enabled():
        await answer(_when_denied()[:190])
        return
    key = _key(chat_id)
    parts = target.split(":")
    screens: Optional[list[Screen]] = None
    if prefix == "sra:" and len(parts) == 1:
        screens = [await study.show(key, user_id, parts[0])]
    elif prefix == "srg:" and len(parts) == 2 and parts[1] in ("1", "2", "3", "4"):
        screens = await study.grade(key, user_id, "telegram", srs.rating_name(int(parts[1])), parts[0])
    elif prefix == "srk:" and len(parts) == 1:
        screens = await study.skip(key, user_id, "telegram", parts[0])
    elif prefix == "sre:":
        screens = [await study.end(key, user_id)]
    elif prefix == "sqc:" and len(parts) == 3 and parts[1].isdecimal() and parts[2].isdecimal():
        screens = await study.quiz_answer(key, user_id, int(parts[2]), parts[0], int(parts[1]))
    elif prefix == "sqr:" and len(parts) == 2 and parts[1].isdecimal():
        screens = [await study.quiz_reveal(key, user_id, parts[0], int(parts[1]))]
    elif prefix == "sqg:" and len(parts) == 3 and parts[1].isdecimal() and parts[2] in ("0", "1"):
        screens = await study.quiz_self_grade(key, user_id, parts[2] == "1", parts[0], int(parts[1]))
    elif prefix == "sqe:" and len(parts) == 1:
        screens = [await study.quiz_end(key, user_id, parts[0])]
    if not screens:
        await answer("Unknown action.")
        return
    first, rest = screens[0], screens[1:]
    await answer(first.notice)
    if first.stale:
        return
    token = message_token(prefix + target)
    message_id = _state(service).messages.get((chat_id, token)) if token else None
    if message_id is not None:
        await edit_screen(service, chat_id, message_id, first)
    else:
        await send_screen(service, chat_id, first)
    for screen in rest:
        await send_screen(service, chat_id, screen)


def register_telegram_buttons(service: Any) -> None:
    """Route the study buttons: only from the pressing person's own linked
    chat (A1), only on their own cards and quizzes."""
    for prefix in BUTTON_PREFIXES:

        async def route(
            chat_id: Optional[int],
            target: str,
            answer: Callable[[str], Awaitable[None]],
            prefix: str = prefix,
        ) -> None:
            user_id = await service._user_for_chat(chat_id)
            if chat_id is None or user_id is None:
                await answer(_NOT_LINKED)
                return
            chat, owner = int(chat_id), str(user_id)

            async def work() -> None:
                await _press(service, chat, owner, prefix, target, answer)

            _run(service, chat, work)

        service._callback_routes[prefix] = route
