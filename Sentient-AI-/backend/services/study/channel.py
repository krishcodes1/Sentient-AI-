"""Model-free flashcard reviews and practice quizzes for the chat channels:
Telegram (buttons, with slash-command fallbacks) and Slack DMs (text keywords).

Why it exists: a review on the phone should cost no tokens and never wait on
an agent turn, and both channels must behave the same, so the flow lives here
once and speaks in ``Screen`` values (services/study/render.py); the channels
only draw them. A review or quiz in progress is a cursor kept in memory per
chat for 30 minutes. Every lookup is scoped to the account the chat is linked
to (the channel checks the link first), so another user's deck, card or quiz
reads as not found; grades and answers go through the engine's conditional
updates, so a second press changes nothing ("Already answered"). The whole
flow is gated by the owner's "Flashcards and practice quizzes" switch, read
again for every command. Card text is made channel-safe before it is shown.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.study import engine as study_engine
from services.study import export as study_export
from services.study import render, srs
from services.study.engine import StudyEngine, as_uuid, shuffled_order
from services.study.render import LETTERS, Button, Screen, channel_safe

logger = structlog.get_logger(__name__)

CURSOR_TTL = timedelta(minutes=30)
QUIZ_DEFAULT_COUNT = 10
MAX_CURSORS = 1000
# The words a waiting card or question answers to (Telegram: "/" + word).
CURSOR_WORDS = frozenset(
    {"show", "again", "hard", "good", "easy", "skip", "end", *(c.lower() for c in LETTERS)}
)
NO_CURSOR = "No card is waiting. Send /review."
NO_CURSOR_SLACK = 'No card is waiting. Send "review".'
QUESTION_GONE = "That question was deleted from the deck, so it is skipped."
_BOOKS = "\U0001F4DA"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _on_slack(key: str) -> bool:
    """Whether the chat *key* is a Slack DM ("slack:..."; Telegram's are
    "telegram:...")."""
    return key.startswith("slack:")


def _say(key: str, words: str) -> str:
    """How the owner sends *words* in this chat: "/review 2" on Telegram,
    '"review 2"' in Slack, where a leading "/" is Slack's own slash command
    and never reaches Crawler."""
    return f'"{words}"' if _on_slack(key) else f"/{words}"


def _no_cursor(key: str) -> str:
    return NO_CURSOR_SLACK if _on_slack(key) else NO_CURSOR


def _slots(attempt: Any, items: list[Any]) -> list[Optional[Any]]:
    """The attempt's questions by position, as ``attempt.item_ids`` stores
    them: a question deleted since the quiz started is None. Positions (and
    the button payloads that carry one) count over the stored list, never
    over the items that are left."""
    by_id = {item.id: item for item in items}
    slots: list[Optional[Any]] = []
    for raw in attempt.item_ids or []:
        item_key = as_uuid(raw)
        slots.append(by_id.get(item_key) if item_key is not None else None)
    return slots


@dataclass
class Cursor:
    """A review or quiz in progress in one chat."""

    user_id: str
    mode: str  # review | quiz
    channel: str  # telegram | slack
    expires_at: datetime
    deck_id: Optional[uuid.UUID] = None
    item_id: Optional[str] = None
    shown: bool = False
    reviewed: int = 0
    limit: int = 20
    attempt_id: Optional[str] = None
    revealed: set[int] = field(default_factory=set)


class StudyChannel:
    """The review and quiz flow for one process's chat channels.

    ``enabled`` answers whether the owner's study switch is on (read for
    every command; an error counts as off)."""

    def __init__(
        self,
        engine: StudyEngine,
        *,
        enabled: Callable[[], Awaitable[bool]],
        clock: Callable[[], datetime] = _utcnow,
        session_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.engine = engine
        self._enabled = enabled
        self._clock = clock
        self._session_factory = session_factory
        self._cursors: dict[str, Cursor] = {}

    async def is_enabled(self) -> bool:
        try:
            return bool(await self._enabled())
        except Exception as exc:  # an unreadable switch is off (fail closed)
            logger.warning("study_channel_gate_failed", error_type=type(exc).__name__)
            return False

    # -- cursors ---------------------------------------------------------------

    def cursor(self, key: str, user_id: str) -> Optional[Cursor]:
        """The chat's live cursor for *user_id*, or None (expired ones go)."""
        now = self._clock()
        for stale in [k for k, c in self._cursors.items() if c.expires_at <= now]:
            del self._cursors[stale]
        found = self._cursors.get(key)
        if found is None or found.user_id != str(user_id):
            return None
        return found

    def has_cursor(self, key: str, user_id: str) -> bool:
        return self.cursor(key, user_id) is not None

    def _keep(self, key: str, cursor: Cursor) -> Cursor:
        cursor.expires_at = self._clock() + CURSOR_TTL
        self._cursors[key] = cursor
        while len(self._cursors) > MAX_CURSORS:
            self._cursors.pop(next(iter(self._cursors)))
        return cursor

    def _drop(self, key: str) -> None:
        self._cursors.pop(key, None)

    @staticmethod
    def _owner(user_id: str) -> uuid.UUID:
        owner = as_uuid(str(user_id))
        if owner is None:
            raise ValueError("not a user id")
        return owner

    # -- decks -----------------------------------------------------------------

    async def _deck_by_number(self, user_id: str, number: Any) -> Optional[Any]:
        decks = await self.engine.numbered_decks(self._owner(user_id))
        if isinstance(number, int) and 1 <= number <= len(decks):
            return decks[number - 1]
        return None

    async def decks(self, user_id: str, *, slack: bool = False) -> Screen:
        decks, stats = await self.engine.list_decks(self._owner(user_id))
        if not decks:
            return Screen("You have no flashcard decks yet. Ask Crawler to make some from your notes or a course file.")
        lines = [f"{_BOOKS} Your decks:"]
        for number, deck in enumerate(decks, start=1):
            s = stats.get(deck.id, {})
            due = int(s.get("due_now", 0))
            line = f"{number}. {channel_safe(deck.title)} — {int(s.get('items', 0))} cards"
            if due:
                line += f", {due} due"
            if not deck.in_reviews:
                line += " (not in reviews)"
            lines.append(line)
        lines.append("")
        if slack:
            lines.append('Reply "review 2" to review deck 2, or "quiz 2 10" for a 10-question quiz.')
        else:
            lines.append("Send /review 2 to review deck 2, /quiz 2 10 for a 10-question quiz, /export 2 to download it.")
        return Screen("\n".join(lines)[:3900])

    # -- review ----------------------------------------------------------------

    async def review_start(self, key: str, user_id: str, channel: str, deck_number: Optional[int]) -> Screen:
        owner = self._owner(user_id)
        deck_id: Optional[uuid.UUID] = None
        if deck_number is not None:
            deck = await self._deck_by_number(user_id, deck_number)
            if deck is None:
                return Screen(f"There is no deck with that number. Send {_say(key, 'decks')} for the list.")
            deck_id = deck.id
        settings = await self.engine.settings(owner)
        cursor = Cursor(
            user_id=str(user_id),
            mode="review",
            channel=channel,
            expires_at=self._clock() + CURSOR_TTL,
            deck_id=deck_id,
            limit=settings.session_size,
        )
        return await self._next_card(key, cursor, first=True)

    async def _next_card(self, key: str, cursor: Cursor, *, first: bool = False) -> Screen:
        owner = self._owner(cursor.user_id)
        if cursor.reviewed >= cursor.limit:
            self._drop(key)
            return Screen(
                f"Session done: {cursor.reviewed} cards reviewed. Send {_say(key, 'review')} for more, "
                "or take a break."
            )
        queue = await self.engine.queue(owner, limit=1, deck_id=cursor.deck_id)
        if not queue["items"]:
            self._drop(key)
            if first:
                return Screen(f"Nothing is due right now. 🎉 Send {_say(key, 'decks')} to see your decks.")
            return Screen(f"All caught up: {cursor.reviewed} cards reviewed. Nothing else is due now.")
        item = queue["items"][0]
        cursor.item_id, cursor.shown = str(item.id), False
        self._keep(key, cursor)
        left = min(cursor.limit - cursor.reviewed, queue["due"] + queue["new_available"])
        title = channel_safe(queue["titles"].get(item.deck_id, "Flashcards"))
        header = f"{_BOOKS} {title} · {left} to go" + (" · new" if item.last_reviewed_at is None else "")
        return self._front_screen(item, header)

    def _front_screen(self, item: Any, header: str) -> Screen:
        choices = self._review_choices(item)
        text = render.front_text(item.front, choices, header)
        return Screen(
            text,
            (
                (Button("Show answer", f"sra:{item.id}", "show"),),
                (Button("Skip", f"srk:{item.id}", "skip"), Button("End", "sre:", "end")),
            ),
        )

    @staticmethod
    def _review_choices(item: Any) -> Optional[list[str]]:
        if item.kind != "choice" or not item.choices:
            return None
        order = shuffled_order(f"review:{item.repetitions}:{item.lapses}", item.id, len(item.choices))
        return [item.choices[i] for i in order]

    def _answer_screen(self, item: Any) -> Screen:
        choices = self._review_choices(item)
        answer_index: Optional[int] = None
        if choices is not None and item.answer_index is not None:
            order = shuffled_order(f"review:{item.repetitions}:{item.lapses}", item.id, len(item.choices))
            answer_index = order.index(item.answer_index) if item.answer_index in order else None
        text = render.answer_text(item.front, item.back, choices, answer_index, item.explanation)
        intervals = srs.previews(study_engine.card_state(item), self._clock())
        grades = render.grade_buttons(str(item.id), intervals)
        return Screen(
            text,
            (grades[:2], grades[2:], (Button("Skip", f"srk:{item.id}", "skip"), Button("End", "sre:", "end"))),
        )

    async def _review_item(self, key: str, user_id: str, item_id: Optional[str]) -> tuple[Optional[Any], Optional[Cursor]]:
        cursor = self.cursor(key, user_id)
        target = item_id or (cursor.item_id if cursor is not None and cursor.mode == "review" else None)
        if target is None:
            return None, cursor
        async with self.engine.session() as session:
            item = await self.engine.item(session, self._owner(user_id), target)
        return item, cursor

    async def show(self, key: str, user_id: str, item_id: Optional[str] = None) -> Screen:
        item, cursor = await self._review_item(key, user_id, item_id)
        if item is None:
            return Screen(_no_cursor(key), notice="No card is waiting", stale=True)
        due = study_engine._utc(item.due_at)
        if item.suspended or (due is not None and due > self._clock()):
            return Screen("That card is already answered.", notice="Already answered", stale=True)
        if cursor is not None and cursor.item_id == str(item.id):
            cursor.shown = True
            self._keep(key, cursor)
        return self._answer_screen(item)

    async def grade(
        self, key: str, user_id: str, channel: str, rating: Any, item_id: Optional[str] = None
    ) -> list[Screen]:
        """The graded card, frozen, and the next one (or the end)."""
        item, cursor = await self._review_item(key, user_id, item_id)
        if item is None:
            return [Screen(_no_cursor(key), notice="No card is waiting", stale=True)]
        result = await self.engine.grade(self._owner(user_id), item.id, rating, mode="review", channel=channel)
        if not result.ok:
            return [Screen("Already answered.", notice="Already answered", stale=True)]
        answer = self._answer_screen(item)
        frozen = Screen(f"{answer.text}\n\n{render.frozen_line(result.rating, result.interval)}", notice="Saved")
        if cursor is None or cursor.mode != "review":
            cursor = Cursor(
                user_id=str(user_id),
                mode="review",
                channel=channel,
                expires_at=self._clock() + CURSOR_TTL,
                limit=(await self.engine.settings(self._owner(user_id))).session_size,
            )
        cursor.reviewed += 1
        return [frozen, await self._next_card(key, cursor)]

    async def skip(self, key: str, user_id: str, channel: str, item_id: Optional[str] = None) -> list[Screen]:
        item, cursor = await self._review_item(key, user_id, item_id)
        if item is None:
            return [Screen(_no_cursor(key), notice="No card is waiting", stale=True)]
        if not await self.engine.skip(self._owner(user_id), item.id):
            return [Screen("Already answered.", notice="Already answered", stale=True)]
        frozen = Screen(f"{render.front_text(item.front, self._review_choices(item))}\n\n⏭ Skipped for an hour", notice="Skipped")
        if cursor is None or cursor.mode != "review":
            cursor = Cursor(
                user_id=str(user_id), mode="review", channel=channel, expires_at=self._clock() + CURSOR_TTL
            )
        return [frozen, await self._next_card(key, cursor)]

    async def end(self, key: str, user_id: str) -> Screen:
        cursor = self.cursor(key, user_id)
        self._drop(key)
        if cursor is None:
            return Screen(f"Nothing to end. Send {_say(key, 'review')} to start.", notice="Nothing to end")
        if cursor.mode == "quiz" and cursor.attempt_id:
            return await self.quiz_end(key, user_id, cursor.attempt_id)
        return Screen(
            f"Review ended: {cursor.reviewed} cards reviewed. Send {_say(key, 'review')} to go on.",
            notice="Ended",
        )

    # -- quiz --------------------------------------------------------------------

    async def quiz_start(
        self, key: str, user_id: str, channel: str, deck_number: Optional[int], count: Optional[int]
    ) -> Screen:
        deck = await self._deck_by_number(user_id, deck_number)
        if deck is None:
            return Screen(
                f"Send {_say(key, 'quiz')} with a deck number, e.g. {_say(key, 'quiz 2 10')}. "
                f"{_say(key, 'decks')} lists them."
            )
        wanted = QUIZ_DEFAULT_COUNT if count is None else max(1, min(study_engine.QUIZ_MAX_ITEMS, count))
        started = await self.engine.quiz_start(self._owner(user_id), deck.id, count=wanted, channel=channel)
        if not started.get("ok"):
            return Screen("That deck has no cards to quiz on yet.")
        attempt = started["attempt"]
        cursor = Cursor(
            user_id=str(user_id),
            mode="quiz",
            channel=channel,
            expires_at=self._clock() + CURSOR_TTL,
            deck_id=deck.id,
            attempt_id=str(attempt.id),
        )
        self._keep(key, cursor)
        return self._question_screen(attempt, _slots(attempt, started["items"]), deck.title, 0)

    def _question_screen(self, attempt: Any, slots: list[Optional[Any]], title: str, position: int) -> Screen:
        item = slots[position]
        if item is None:  # callers pass over deleted questions first
            return Screen(QUESTION_GONE, notice="Question deleted", stale=True)
        header = f"Quiz · {channel_safe(title)} · question {position + 1} of {len(slots)}"
        end_row = (Button("End quiz", f"sqe:{attempt.id}", "end"),)
        if item.kind == "choice" and item.choices:
            order = shuffled_order(str(attempt.id), item.id, len(item.choices))
            shown = [item.choices[i] for i in order]
            letters = tuple(
                Button(LETTERS[i], f"sqc:{attempt.id}:{position}:{i}", LETTERS[i].lower()) for i in range(len(shown))
            )
            rows = (letters[:3], letters[3:]) if len(letters) > 3 else (letters,)
            return Screen(render.front_text(item.front, shown, header), (*rows, end_row))
        return Screen(
            render.front_text(item.front, None, header) + "\n\n(Think of the answer, then reveal it.)",
            ((Button("Reveal", f"sqr:{attempt.id}:{position}", "show"),), end_row),
        )

    async def _live_attempt(
        self, key: str, user_id: str, attempt_id: Optional[str]
    ) -> tuple[Optional[tuple[Any, list[Any], Any]], Optional[Cursor]]:
        cursor = self.cursor(key, user_id)
        target = attempt_id or (cursor.attempt_id if cursor is not None and cursor.mode == "quiz" else None)
        if target is None:
            return None, cursor
        return await self.engine.attempt(self._owner(user_id), target), cursor

    async def _after_answer(
        self, key: str, cursor: Optional[Cursor], attempt: Any, slots: list[Optional[Any]], title: str, user_id: str
    ) -> Screen:
        position = int(attempt.position or 0)
        # Questions deleted since the quiz started are passed over (never
        # answered, never shown), so the next one shown is the one stored
        # at the attempt's position.
        while position < len(slots) and slots[position] is None:
            if not await self.engine.quiz_pass(self._owner(user_id), attempt, position):
                return Screen("Already answered.", notice="Already answered", stale=True)
            position += 1
        if position >= len(slots):
            return await self.quiz_end(key, user_id, str(attempt.id))
        if cursor is not None:
            self._keep(key, cursor)
        return self._question_screen(attempt, slots, title, position)

    async def quiz_answer(
        self, key: str, user_id: str, choice: int, attempt_id: Optional[str] = None, position: Optional[int] = None
    ) -> list[Screen]:
        found, cursor = await self._live_attempt(key, user_id, attempt_id)
        if found is None:
            return [Screen(_no_cursor(key), notice="No quiz is running", stale=True)]
        attempt, items, deck = found
        slots = _slots(attempt, items)
        at = int(attempt.position or 0) if position is None else position
        if attempt.status != "active" or at != int(attempt.position or 0) or at >= len(slots):
            return [Screen("Already answered.", notice="Already answered", stale=True)]
        item = slots[at]
        if item is None:
            gone = Screen(QUESTION_GONE, notice="Question deleted")
            return [gone, await self._after_answer(key, cursor, attempt, slots, deck.title, user_id)]
        if item.kind != "choice" or not item.choices:
            return [
                Screen(
                    f"This question has no choices: reveal it ({_say(key, 'show')}), then say whether you "
                    f"got it ({_say(key, 'good')} or {_say(key, 'again')}).",
                    notice="Reveal it first",
                    stale=True,
                )
            ]
        order = shuffled_order(str(attempt.id), item.id, len(item.choices))
        if not 0 <= choice < len(order):
            return [Screen("That letter is not one of the choices.", notice="Not a choice", stale=True)]
        stored = order[choice]
        right = item.answer_index if item.answer_index is not None else -1
        correct = stored == right
        if not await self.engine.record_answers(
            self._owner(user_id), attempt, [{"item_id": str(item.id), "choice": choice, "correct": correct}], position=at
        ):
            return [Screen("Already answered.", notice="Already answered", stale=True)]
        shown = [item.choices[i] for i in order]
        right_shown = order.index(right) if right in order else None
        lines = [render.front_text(item.front, shown, f"Question {at + 1} of {len(slots)}")]
        if correct:
            lines.append(f"✅ Correct: {LETTERS[choice]}) {channel_safe(shown[choice])}")
        else:
            lines.append(f"❌ You picked {LETTERS[choice]}) {channel_safe(shown[choice])}")
            notes = list(item.choice_notes or [])
            if stored < len(notes) and notes[stored]:
                lines.append(f"Why not: {channel_safe(notes[stored])}")
            if right_shown is not None:
                lines.append(f"Right answer: {LETTERS[right_shown]}) {channel_safe(shown[right_shown])}")
        if item.explanation:
            lines.append(f"Why: {channel_safe(item.explanation)}")
        feedback = Screen("\n\n".join(lines), notice="Correct!" if correct else "Not quite")
        return [feedback, await self._after_answer(key, cursor, attempt, slots, deck.title, user_id)]

    async def quiz_reveal(
        self, key: str, user_id: str, attempt_id: Optional[str] = None, position: Optional[int] = None
    ) -> Screen:
        found, cursor = await self._live_attempt(key, user_id, attempt_id)
        if found is None:
            return Screen(_no_cursor(key), notice="No quiz is running", stale=True)
        attempt, items, deck = found
        slots = _slots(attempt, items)
        at = int(attempt.position or 0) if position is None else position
        if attempt.status != "active" or at != int(attempt.position or 0) or at >= len(slots):
            return Screen("Already answered.", notice="Already answered", stale=True)
        item = slots[at]
        if item is None:
            nxt = await self._after_answer(key, cursor, attempt, slots, deck.title, user_id)
            if nxt.stale:
                return nxt
            return Screen(f"{QUESTION_GONE}\n\n{nxt.text}", nxt.buttons, notice="Question deleted")
        if item.kind == "choice":
            return Screen("Pick a letter for this one.", notice="Pick a letter", stale=True)
        if cursor is not None:
            cursor.revealed.add(at)
            self._keep(key, cursor)
        text = render.answer_text(item.front, item.back, None, None, item.explanation, f"Question {at + 1} of {len(slots)}")
        return Screen(
            text,
            (
                (
                    Button("✅ I got it", f"sqg:{attempt.id}:{at}:1", "good"),
                    Button("❌ I missed it", f"sqg:{attempt.id}:{at}:0", "again"),
                ),
                (Button("End quiz", f"sqe:{attempt.id}", "end"),),
            ),
        )

    async def quiz_self_grade(
        self, key: str, user_id: str, correct: bool, attempt_id: Optional[str] = None, position: Optional[int] = None
    ) -> list[Screen]:
        found, cursor = await self._live_attempt(key, user_id, attempt_id)
        if found is None:
            return [Screen(_no_cursor(key), notice="No quiz is running", stale=True)]
        attempt, items, deck = found
        slots = _slots(attempt, items)
        at = int(attempt.position or 0) if position is None else position
        if attempt.status != "active" or at != int(attempt.position or 0) or at >= len(slots):
            return [Screen("Already answered.", notice="Already answered", stale=True)]
        item = slots[at]
        if item is None:
            gone = Screen(QUESTION_GONE, notice="Question deleted")
            return [gone, await self._after_answer(key, cursor, attempt, slots, deck.title, user_id)]
        if item.kind == "choice":
            return [Screen("Pick a letter for this one.", notice="Pick a letter", stale=True)]
        if position is None and (cursor is None or at not in cursor.revealed):
            return [Screen(f"Reveal the answer first ({_say(key, 'show')}).", notice="Reveal it first", stale=True)]
        if not await self.engine.record_answers(
            self._owner(user_id), attempt, [{"item_id": str(item.id), "choice": None, "correct": correct}], position=at
        ):
            return [Screen("Already answered.", notice="Already answered", stale=True)]
        text = render.answer_text(item.front, item.back, None, None, item.explanation, f"Question {at + 1} of {len(slots)}")
        mark = "✅ Got it" if correct else "❌ Missed: it comes back in your next review"
        feedback = Screen(f"{text}\n\n{mark}", notice="Saved")
        return [feedback, await self._after_answer(key, cursor, attempt, slots, deck.title, user_id)]

    async def quiz_end(self, key: str, user_id: str, attempt_id: Optional[str] = None) -> Screen:
        found, cursor = await self._live_attempt(key, user_id, attempt_id)
        if cursor is not None and (attempt_id is None or cursor.attempt_id == attempt_id):
            self._drop(key)
        if found is None:
            return Screen("No quiz is running.", notice="No quiz is running", stale=True)
        attempt, items, deck = found
        if attempt.status != "active":
            return Screen("This quiz has already ended.", notice="Already ended", stale=True)
        finished = await self.engine.quiz_finish(self._owner(user_id), attempt.id)
        if finished is None:
            return Screen("No quiz is running.", notice="No quiz is running", stale=True)
        summary = study_engine.quiz_summary(finished, items, deck.title)
        lines = [f"Quiz done · {channel_safe(deck.title)}: {summary['score']} ({summary['percent']}%)."]
        if summary["weakest_tags"]:
            lines.append("To work on: " + ", ".join(channel_safe(t) for t in summary["weakest_tags"]))
        if summary["now_due_for_review"]:
            lines.append(f"{summary['now_due_for_review']} missed cards are due now: send {_say(key, 'review')}.")
        return Screen("\n".join(lines), notice="Quiz finished")

    # -- text words (Telegram fallbacks, Slack keywords) -------------------------

    async def word(self, key: str, user_id: str, channel: str, word: str) -> list[Screen]:
        """A waiting card's or question's word: show, again, hard, good,
        easy, skip, end, or a letter."""
        cursor = self.cursor(key, user_id)
        word = word.strip().lower()
        if cursor is None:
            return [Screen(NO_CURSOR_SLACK if channel == "slack" or _on_slack(key) else NO_CURSOR)]
        if word == "end":
            return [await self.end(key, user_id)]
        if cursor.mode == "review":
            if word == "show":
                return [await self.show(key, user_id)]
            if word in srs.RATINGS:
                if not cursor.shown:
                    return [Screen("Look at the answer first (show), then grade it.")]
                return await self.grade(key, user_id, channel, word)
            if word == "skip":
                return await self.skip(key, user_id, channel)
            return [Screen("This is a review card: show, then again, hard, good or easy (or skip / end).")]
        if word in {c.lower() for c in LETTERS}:
            return await self.quiz_answer(key, user_id, LETTERS.index(word.upper()))
        if word == "show":
            return [await self.quiz_reveal(key, user_id)]
        if word in ("good", "again"):
            return await self.quiz_self_grade(key, user_id, word == "good")
        return [Screen("Pick a letter, or show / good / again for a question without choices (end to stop).")]

    # -- export ------------------------------------------------------------------

    async def export_file(self, user_id: str, deck_number: Optional[int], fmt: str) -> tuple[Optional[tuple[str, bytes, str]], str]:
        """``((filename, bytes, media type), "")`` for the user's deck
        *deck_number*, or ``(None, reason)``. Audited as study_export."""
        if fmt not in study_export.FORMATS:
            return None, "Send /export with a deck number and anki or csv, e.g. /export 2 csv."
        deck = await self._deck_by_number(user_id, deck_number)
        if deck is None:
            return None, "There is no deck with that number. Send /decks for the list."
        found = await self.engine.deck_items(self._owner(user_id), deck.id)
        if found is None:
            return None, "There is no deck with that number. Send /decks for the list."
        _deck, items = found
        if not items:
            return None, "That deck has no cards to export yet."
        data = study_export.render_file(fmt, deck.title, items)
        if self._session_factory is None or not await study_export.record_export(
            self._session_factory, str(user_id), str(deck.id), fmt, len(items), endpoint="telegram:/export"
        ):
            return None, "The export could not be recorded, so it was not sent. Try again shortly."
        return (study_export.safe_filename(deck.title, fmt), data, study_export.MEDIA_TYPES[fmt]), ""


# The process's channel flow, set by main.wire_services (None until then:
# the commands then say study is not available).
_channel: Optional[StudyChannel] = None


def configure(channel: Optional[StudyChannel]) -> None:
    global _channel
    _channel = channel


def current() -> Optional[StudyChannel]:
    return _channel
