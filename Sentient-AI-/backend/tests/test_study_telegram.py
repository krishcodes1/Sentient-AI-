"""Tests for flashcards on Telegram with no model: /decks numbers the decks,
/review shows a card with Show answer, the sra: press edits it to the answer
with grade buttons that preview each interval, an srg: press freezes it and
sends the next card, a second press answers "Already answered" and changes
nothing, another account's card or an unlinked chat gets nothing, the
switch off answers with its when_denied, the /show and /good fallbacks work
with a cursor and say "No card is waiting" without one, /quiz runs on sqc:
presses with a position guard and ends with a score, /export sends a document,
card text is defanged, and every callback_data fits Telegram's 64 bytes.

Why it exists: these presses change the user's review schedule without an
approval card, so the A1 link check, per-user scoping and the conditional
updates must hold for each one. The Bot API is a recorder; the database is
in-memory SQLite; the clock is a fake.
"""

from __future__ import annotations

import itertools
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from services.study import channel as study_channel
from services.study import telegram as study_telegram
from services.study.channel import StudyChannel
from services.study.engine import StudyEngine
from services.study.render import CALLBACK_MAX_BYTES, LETTERS, grade_buttons
from services.study.srs import CardState, previews
from services.tools.study import StudyToolkit
from tests.conftest import make_user, telegram_dm

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
LINKED, STRANGER = 9101, 9102


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


class _FakeClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    async def post(self, path, data=None, files=None, json=None):
        self.posts.append((path, dict(data or {}), dict(files or {})))

        class _Resp:
            @staticmethod
            def json():
                return {"ok": True, "result": {}}

        return _Resp()

    async def aclose(self) -> None:
        return None


@pytest.fixture
def study(session_factory):
    clock = Clock()
    state = {"on": True}

    async def enabled():
        return state["on"]

    channel = StudyChannel(
        StudyEngine(session_factory, clock=clock, default_timezone=lambda: "UTC"),
        enabled=enabled,
        clock=clock,
        session_factory=session_factory,
    )
    study_channel.configure(channel)
    yield channel, state, clock
    study_channel.configure(None)


async def telegram(user_id: str):
    from services.notifications.telegram import TelegramService

    service = TelegramService(token="123:fake-token", session_factory=lambda: None)
    await service._client.aclose()
    service._client = _FakeClient()  # type: ignore[assignment]
    sent: list[tuple[str, dict[str, Any]]] = []
    ids = itertools.count(500)

    async def api(method: str, **params: Any) -> Any:
        sent.append((method, params))
        return {"message_id": next(ids)} if method == "sendMessage" else {}

    async def user_for_chat(chat_id: Any):
        return user_id if chat_id == LINKED else None

    service._api = api  # type: ignore[method-assign]
    service._user_for_chat = user_for_chat  # type: ignore[method-assign]
    return service, sent


def press(data: str, chat_id: int = LINKED, sender: int | None = None) -> dict[str, Any]:
    return {
        "id": "press",
        "data": data,
        "from": {"id": sender if sender is not None else chat_id, "is_bot": False},
        "message": {"message_id": 3, "chat": {"id": chat_id, "type": "private"}},
    }


async def say(service, text: str, chat_id: int = LINKED, **kw: Any) -> None:
    await service._handle_message(telegram_dm(chat_id, text, **kw))
    await service.wait_for_chats()


async def tap(service, data: str, **kw: Any) -> None:
    await service._handle_callback(press(data, **kw))
    await service.wait_for_chats()


def texts(sent, method: str = "sendMessage") -> list[str]:
    return [p["text"] for m, p in sent if m == method]


def buttons(params: dict[str, Any]) -> list[str]:
    return [b["callback_data"] for row in params.get("reply_markup", {}).get("inline_keyboard", []) for b in row]


def answers(sent) -> list[str]:
    return [p["text"] for m, p in sent if m == "answerCallbackQuery"]


async def a_deck(session_factory, user, clock, title="Bio 101 – Lecture 3", items=None):
    kit = StudyToolkit(session_factory, clock=clock, default_timezone=lambda: "UTC")
    saved = await kit.execute(
        "save",
        {"title": title, "items": items or [{"front": f"Term {i}?", "back": f"Meaning {i}"} for i in range(2)]},
        str(user.id),
    )
    assert saved["ok"], saved
    return kit, saved


@pytest.mark.asyncio
async def test_decks_are_numbered_and_review_says_when_nothing_is_due(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-decks@example.com")
    service, sent = await telegram(str(user.id))
    await say(service, "/review")
    assert "Nothing is due right now" in texts(sent)[-1]
    await a_deck(session_factory, user, clock)
    clock.now += timedelta(seconds=1)  # decks are numbered oldest first
    await a_deck(session_factory, user, clock, title="Chem 201")
    await say(service, "/decks")
    listing = texts(sent)[-1]
    assert "1. Bio 101 – Lecture 3 — 2 cards" in listing and "2. Chem 201 — 2 cards" in listing
    await say(service, "/review 9")
    assert "no deck with that number" in texts(sent)[-1]


@pytest.mark.asyncio
async def test_show_edits_the_card_and_a_grade_freezes_it_and_sends_the_next(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-review@example.com")
    _kit, saved = await a_deck(session_factory, user, clock)
    service, sent = await telegram(str(user.id))

    await say(service, "/review")
    method, card = sent[-1]
    assert method == "sendMessage" and "Term 0?" in card["text"] and "Meaning 0" not in card["text"]
    first = saved["added_ids"][0]
    assert buttons(card) == [f"sra:{first}", f"srk:{first}", "sre:"]
    card_message = 500

    await tap(service, f"sra:{first}")
    edits = [p for m, p in sent if m == "editMessageText"]
    assert edits[-1]["message_id"] == card_message and "Answer: Meaning 0" in edits[-1]["text"]
    labels = [b["text"] for row in edits[-1]["reply_markup"]["inline_keyboard"] for b in row]
    assert labels[:4] == ["Again · 10m", "Hard · 1d", "Good · 1d", "Easy · 4d"]

    await tap(service, f"srg:{first}:3")
    frozen = [p for m, p in sent if m == "editMessageText"][-1]
    assert frozen["text"].endswith("✅ Good · next in 1 day") and "reply_markup" not in frozen
    assert "Term 1?" in texts(sent)[-1]
    assert answers(sent)[-1] == "Saved"

    before = len(sent)
    await tap(service, f"srg:{first}:4")  # a second press on the same card
    assert answers(sent)[-1] == "Already answered"
    assert [m for m, _p in sent[before:]] == ["answerCallbackQuery"]


@pytest.mark.asyncio
async def test_another_accounts_card_and_an_unlinked_chat_get_nothing(session_factory, study):
    _channel, _state, clock = study
    owner, _ = await make_user(session_factory, "tg-owner@example.com")
    other, _ = await make_user(session_factory, "tg-other@example.com")
    _kit, saved = await a_deck(session_factory, owner, clock)
    service, sent = await telegram(str(other.id))
    await tap(service, f"sra:{saved['added_ids'][0]}")
    await tap(service, f"srg:{saved['added_ids'][0]}:3")
    assert "Answer: Meaning 0" not in "".join(str(p) for _m, p in sent)
    assert answers(sent) == ["No card is waiting", "No card is waiting"]
    stranger_service, stranger_sent = await telegram(str(owner.id))
    await tap(stranger_service, f"sra:{saved['added_ids'][0]}", chat_id=STRANGER)
    assert answers(stranger_sent) == ["This chat is not linked to a Crawler AI account."]
    await say(stranger_service, "/review", chat_id=STRANGER)
    await say(stranger_service, "/review", chat_id=-100123, sender_id=LINKED, chat_type="group")
    assert [m for m, _p in stranger_sent] == ["answerCallbackQuery"]


@pytest.mark.asyncio
async def test_the_switch_off_answers_with_when_denied(session_factory, study):
    _channel, state, clock = study
    user, _ = await make_user(session_factory, "tg-off@example.com")
    _kit, saved = await a_deck(session_factory, user, clock)
    service, sent = await telegram(str(user.id))
    state["on"] = False
    await say(service, "/review")
    assert texts(sent)[-1] == "Flashcards and quizzes are turned off. The owner can turn them on in Settings → Permissions."
    await tap(service, f"sra:{saved['added_ids'][0]}")
    assert answers(sent)[-1].startswith("Flashcards and quizzes are turned off")


@pytest.mark.asyncio
async def test_text_fallbacks_with_and_without_a_cursor(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-fallback@example.com")
    await a_deck(session_factory, user, clock)
    service, sent = await telegram(str(user.id))
    await say(service, "/good")
    assert texts(sent)[-1] == "No card is waiting. Send /review."
    await say(service, "/review")
    await say(service, "/good")
    assert "Look at the answer first" in texts(sent)[-1]
    await say(service, "/show")
    assert "Answer: Meaning 0" in texts(sent)[-1]
    await say(service, "/good")
    assert texts(sent)[-2].endswith("✅ Good · next in 1 day") and "Term 1?" in texts(sent)[-1]
    await say(service, "/end")
    assert texts(sent)[-1].startswith("Review ended: 1 cards reviewed")
    await say(service, "/show")
    assert texts(sent)[-1] == "No card is waiting. Send /review."


@pytest.mark.asyncio
async def test_a_quiz_runs_on_presses_with_a_position_guard_and_ends_with_a_score(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-quiz@example.com")
    item = {
        "kind": "choice",
        "front": "Which organelle makes ATP?",
        "choices": ["Ribosome", "Mitochondrion", "Golgi apparatus"],
        "answer": 1,
        "choice_notes": ["Ribosomes make proteins.", "", "It packages proteins."],
        "tags": ["cells"],
    }
    await a_deck(session_factory, user, clock, items=[item, {"front": "What is ATP?", "back": "Energy currency"}])
    service, sent = await telegram(str(user.id))
    await say(service, "/quiz 1 2")
    question = sent[-1][1]
    assert "question 1 of 2" in question["text"] and "Mitochondrion" in question["text"]
    choice_buttons = [d for d in buttons(question) if d.startswith("sqc:")]
    shown = [line.split(") ", 1)[1] for line in question["text"].split("\n") if line[:2] in {f"{c})" for c in LETTERS}]
    wrong = choice_buttons[shown.index("Golgi apparatus")]
    right = choice_buttons[shown.index("Mitochondrion")]

    await tap(service, wrong)
    feedback = [p for m, p in sent if m == "editMessageText"][-1]
    assert "❌ You picked" in feedback["text"] and "Why not: It packages proteins." in feedback["text"]
    assert "question 2 of 2" in texts(sent)[-1]
    before = len(sent)
    await tap(service, right)  # the first question is already answered
    assert answers(sent)[-1] == "Already answered" and len(sent) == before + 1

    reveal = [d for d in buttons(sent[-2][1]) if d.startswith("sqr:")] or [
        d for m, p in sent if m == "sendMessage" for d in buttons(p) if d.startswith("sqr:")
    ]
    await tap(service, reveal[-1])
    revealed = [p for m, p in sent if m == "editMessageText"][-1]
    assert "Answer: Energy currency" in revealed["text"]
    got_it = [d for d in buttons(revealed) if d.startswith("sqg:") and d.endswith(":1")]
    await tap(service, got_it[0])
    assert texts(sent)[-1].startswith("Quiz done · Bio 101 – Lecture 3: 1/2 (50%).")
    assert "To work on: cells" in texts(sent)[-1] and "send /review" in texts(sent)[-1]


@pytest.mark.asyncio
async def test_export_sends_a_document(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-export@example.com")
    await a_deck(session_factory, user, clock)
    service, sent = await telegram(str(user.id))
    await say(service, "/export 1 csv")
    [(path, fields, files)] = service._client.posts
    assert path == "/sendDocument" and fields["chat_id"] == str(LINKED)
    name, data, media_type = files["document"]
    assert name == "Bio 101 Lecture 3.csv" and media_type == "text/csv" and b"Term 0?" in data
    await say(service, "/export 7")
    assert "no deck with that number" in texts(sent)[-1]
    await say(service, "/export 1 pdf")
    assert "anki or csv" in texts(sent)[-1]


@pytest.mark.asyncio
async def test_card_text_is_defanged(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-defang@example.com")
    await a_deck(
        session_factory,
        user,
        clock,
        items=[{"front": "Where is the syllabus? (pi is 3.14)", "back": "https://evil.example.com/x /start @admin"}],
    )
    service, sent = await telegram(str(user.id))
    await say(service, "/review")
    await say(service, "/show")
    shown = texts(sent)[-1]
    assert "3.14" in shown and "https://evil.example.com" not in shown and "/start" not in shown
    assert "@admin" not in shown and "evil․example․com" in shown


def _choice_items(n: int) -> list[dict[str, Any]]:
    return [
        {
            "kind": "choice",
            "front": f"Question {name}?",
            "choices": [f"{name} wrong", f"{name} right", f"{name} other"],
            "answer": 1,
        }
        for name in ("alpha", "beta", "gamma", "delta")[:n]
    ]


async def _attempt_items(session_factory, attempt_id: str) -> list[Any]:
    """The attempt's items in quiz order, as stored."""
    from models.study import StudyItem, StudyQuizAttempt

    async with session_factory() as session:
        attempt = await session.get(StudyQuizAttempt, uuid.UUID(attempt_id))
        ids = [uuid.UUID(i) for i in attempt.item_ids]
        rows = {r.id: r for r in (await session.execute(select(StudyItem).where(StudyItem.id.in_(ids)))).scalars()}
    return [rows[i] for i in ids]


async def _delete_item(session_factory, item_id) -> None:
    from sqlalchemy import delete

    from models.study import StudyItem, StudyReview

    async with session_factory() as session:
        await session.execute(delete(StudyReview).where(StudyReview.item_id == item_id))
        await session.execute(delete(StudyItem).where(StudyItem.id == item_id))
        await session.commit()


def _right_letter(attempt_id: str, item: Any) -> int:
    from services.study.engine import shuffled_order

    return shuffled_order(attempt_id, item.id, len(item.choices)).index(item.answer_index)


@pytest.mark.asyncio
async def test_a_question_deleted_before_the_current_one_does_not_shift_the_answers(session_factory, study):
    channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-quiz-shift@example.com")
    await a_deck(session_factory, user, clock, items=_choice_items(3))
    key, uid = f"telegram:{LINKED}", str(user.id)
    await channel.quiz_start(key, uid, "telegram", 1, 3)
    attempt_id = channel.cursor(key, uid).attempt_id
    first, second, third = await _attempt_items(session_factory, attempt_id)
    await channel.quiz_answer(key, uid, _right_letter(attempt_id, first), attempt_id, 0)
    # The first card is deleted while question 2 is on screen; the press on
    # question 2 (position 1) answers question 2, not question 3.
    await _delete_item(session_factory, first.id)
    feedback, nxt = await channel.quiz_answer(key, uid, _right_letter(attempt_id, second), attempt_id, 1)
    assert "Question 2 of 3" in feedback.text and second.front in feedback.text
    assert "✅ Correct" in feedback.text and third.front not in feedback.text
    assert "question 3 of 3" in nxt.text and third.front in nxt.text
    from models.study import StudyQuizAttempt

    async with session_factory() as session:
        attempt = await session.get(StudyQuizAttempt, uuid.UUID(attempt_id))
    assert [a["item_id"] for a in attempt.answers] == [str(first.id), str(second.id)]
    assert attempt.position == 2 and attempt.correct == 2


@pytest.mark.asyncio
async def test_a_deleted_current_question_is_skipped_without_an_answer(session_factory, study):
    channel, _state, clock = study
    user, _ = await make_user(session_factory, "tg-quiz-gone@example.com")
    await a_deck(session_factory, user, clock, items=_choice_items(3))
    key, uid = f"telegram:{LINKED}", str(user.id)
    await channel.quiz_start(key, uid, "telegram", 1, 3)
    attempt_id = channel.cursor(key, uid).attempt_id
    first, second, third = await _attempt_items(session_factory, attempt_id)
    await _delete_item(session_factory, first.id)
    gone, nxt = await channel.quiz_answer(key, uid, 0, attempt_id, 0)
    assert gone.text == study_channel.QUESTION_GONE and not gone.stale
    assert "question 2 of 3" in nxt.text and second.front in nxt.text
    # The last question goes too: answering question 2 ends the quiz.
    await _delete_item(session_factory, third.id)
    feedback, done = await channel.quiz_answer(key, uid, _right_letter(attempt_id, second), attempt_id, 1)
    assert "✅ Correct" in feedback.text and done.text.startswith("Quiz done")
    from models.study import StudyQuizAttempt

    async with session_factory() as session:
        attempt = await session.get(StudyQuizAttempt, uuid.UUID(attempt_id))
    assert [a["item_id"] for a in attempt.answers] == [str(second.id)]
    assert attempt.status == "finished"


def test_every_callback_data_fits_64_bytes():
    ids = [str(uuid.uuid4()) for _ in range(200)] + ["f" * 8 + "-" + "f" * 4 + "-" + "f" * 4 + "-" + "f" * 4 + "-" + "f" * 12]
    for item_id in ids:
        for button in grade_buttons(item_id, previews(CardState(), NOW)):
            assert len(button.data.encode()) <= CALLBACK_MAX_BYTES
        for data in (
            f"sra:{item_id}",
            f"srk:{item_id}",
            "sre:",
            f"sqc:{item_id}:29:5",
            f"sqr:{item_id}:29",
            f"sqg:{item_id}:29:1",
            f"sqe:{item_id}",
        ):
            assert len(data.encode()) <= CALLBACK_MAX_BYTES, data
            assert data[:4] in study_telegram.BUTTON_PREFIXES


def test_help_lists_the_study_commands():
    from services.notifications.telegram import HELP_LINES

    help_text = "\n".join(HELP_LINES)
    for command in ("/decks", "/review", "/quiz", "/export", "/show"):
        assert command in help_text
