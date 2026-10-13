"""Tests for flashcards in a Slack DM with no model: "decks", "review" and
"quiz <n> [count]" start a session, "show", "again", "hard", "good", "easy",
"skip", "end" and "a"-"f" act only while a card or question is waiting (and
otherwise go to the chat), any other text goes to the chat, every keyword goes
to the chat while the owner's study switch is off, and a message from anyone
but the linked Slack user is never answered.

Why it exists: Slack has no buttons here, so these words are the review; they
must never swallow ordinary chat and must act only for the channel's own
account. The Slack API is a recorder; the database is in-memory SQLite.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from services.study import channel as study_channel
from services.study.channel import StudyChannel
from services.study.engine import StudyEngine
from services.tools.study import StudyToolkit
from tests.conftest import make_user

TEAM, LINKED, STRANGER, DM = "T0TEAM001", "U0LINKED1", "U0OTHER01", "D0DM00001"
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


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


def slack(user_id: str):
    from services.connectors.slack import SlackConnector
    from services.notifications import slack as slack_mod

    connector = SlackConnector.from_credentials({"bot_token": "xoxb-x", "app_token": "xapp-x"})
    channel = slack_mod.SlackChannel(
        connector_id="11111111-1111-1111-1111-111111111111",
        user_id=user_id,
        bot_token="xoxb-x",
        app_token="xapp-x",
        session_factory=lambda: None,
        connector=connector,
    )
    channel.team_id, channel.bot_user_id = TEAM, "U0BOT0001"
    link = SimpleNamespace(team_id=TEAM, slack_user_id=LINKED, link_code_hash=None, link_expires_at=None)

    async def load_link():
        return link

    posted: list[str] = []
    chats: list[str] = []

    async def post_text(where, text):
        posted.append(text)
        return {}

    channel._load_link = load_link  # type: ignore[method-assign]
    channel._post_text = post_text  # type: ignore[method-assign]
    channel._handle_chat = lambda where, text: chats.append(text)  # type: ignore[method-assign]
    return channel, posted, chats


def dm(text: str, n: int, sender: str = LINKED) -> dict[str, Any]:
    return {
        "type": "event_callback",
        "team_id": TEAM,
        "event_id": f"Ev{n:08d}",
        "event": {"type": "message", "channel": DM, "user": sender, "text": text, "ts": f"{n}.000100", "channel_type": "im"},
    }


class _Say:
    def __init__(self, channel) -> None:
        self.channel = channel
        self.n = 0

    async def __call__(self, text: str, sender: str = LINKED) -> None:
        self.n += 1
        await self.channel._on_events_api(dm(text, self.n, sender))
        await self.channel.wait_idle()


async def a_deck(session_factory, user, clock, items=None):
    kit = StudyToolkit(session_factory, clock=clock, default_timezone=lambda: "UTC")
    saved = await kit.execute(
        "save",
        {"title": "Spanish vocab", "items": items or [{"front": f"el perro {i}", "back": f"the dog {i}"} for i in range(2)]},
        str(user.id),
    )
    assert saved["ok"], saved
    return saved


@pytest.mark.asyncio
async def test_review_show_and_grade_by_keyword(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "slack-review@example.com")
    await a_deck(session_factory, user, clock)
    channel, posted, chats = slack(str(user.id))
    say = _Say(channel)
    await say("decks")
    assert "1. Spanish vocab — 2 cards" in posted[-1] and 'Reply "review 2"' in posted[-1]
    await say("review")
    assert "el perro 0" in posted[-1] and posted[-1].endswith("Reply show / skip / end")
    await say("Show")
    assert "Answer: the dog 0" in posted[-1] and "Reply again / hard / good / easy / skip / end" in posted[-1]
    await say("good")
    assert posted[-2].endswith("✅ Good · next in 1 day") and "el perro 1" in posted[-1]
    await say("end")
    assert posted[-1] == 'Review ended: 1 cards reviewed. Send "review" to go on.'
    await say("good")  # no cursor any more: ordinary chat
    assert chats == ["good"]


@pytest.mark.asyncio
async def test_replies_name_slack_words_never_slash_commands(session_factory, study):
    """Slack keeps a leading "/" for its own slash commands, so a hint
    telling the user to send "/review" could never reach Crawler."""
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "slack-words@example.com")
    channel, posted, _chats = slack(str(user.id))
    say = _Say(channel)
    await say("review")
    assert posted[-1] == 'Nothing is due right now. 🎉 Send "decks" to see your decks.'
    await a_deck(
        session_factory,
        user,
        clock,
        items=[
            {"front": "¿Qué es 'gato'?", "back": "cat"},
            {"kind": "choice", "front": "¿'dog'?", "choices": ["el gato", "el perro"], "answer": 1},
        ],
    )
    await say("review 9")
    assert posted[-1] == 'There is no deck with that number. Send "decks" for the list.'
    await say("quiz 9")
    assert posted[-1] == 'Send "quiz" with a deck number, e.g. "quiz 2 10". "decks" lists them.'
    await say("quiz 1 2")
    assert "question 1 of 2" in posted[-1]  # the choice question comes first
    shown = [line.split(") ", 1)[1] for line in posted[-1].split("\n") if line[:2] in ("A)", "B)")]
    await say("ab"[shown.index("el gato")])  # wrong
    assert "question 2 of 2" in posted[-1]
    await say("a")  # the second question has no choices
    assert posted[-1].startswith('This question has no choices: reveal it ("show"), then say whether you got it ("good" or "again").')
    await say("good")
    assert posted[-1] == 'Reveal the answer first ("show").'
    await say("show")
    await say("again")
    assert posted[-1].endswith('2 missed cards are due now: send "review".')
    for text in posted:
        for command in ("/review", "/decks", "/quiz", "/show", "/good", "/again"):
            assert command not in text, text


@pytest.mark.asyncio
async def test_cursor_words_go_to_chat_without_a_cursor_and_other_text_always_does(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "slack-chat@example.com")
    await a_deck(session_factory, user, clock)
    channel, posted, chats = slack(str(user.id))
    say = _Say(channel)
    for text in ("show", "a", "review my notes please", "quiz me", "decks please", "easy"):
        await say(text)
    assert chats == ["show", "a", "review my notes please", "quiz me", "decks please", "easy"]
    assert posted == []
    names = [h.__name__ for h in channel._text_handlers]
    # After the built-ins and the scheduler's keywords; later skills' keywords
    # (triggers, grants) may follow it.
    assert names.index("_keyword_study") > names.index("_keyword_timezone")


@pytest.mark.asyncio
async def test_a_quiz_by_letters(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "slack-quiz@example.com")
    item = {
        "kind": "choice",
        "front": "¿Cómo se dice 'dog'?",
        "choices": ["el gato", "el perro"],
        "answer": 1,
        "choice_notes": ["That is a cat.", ""],
    }
    await a_deck(session_factory, user, clock, items=[item])
    channel, posted, chats = slack(str(user.id))
    say = _Say(channel)
    await say("quiz 1 5")
    assert "question 1 of 1" in posted[-1] and posted[-1].endswith("Reply a / b / end")
    shown = [line.split(") ", 1)[1] for line in posted[-1].split("\n") if line[:2] in ("A)", "B)")]
    letter = "ab"[shown.index("el perro")]
    await say(letter)
    assert "✅ Correct" in posted[-2] and posted[-1].startswith("Quiz done · Spanish vocab: 1/1 (100%)")
    await say(letter)  # the quiz is over: ordinary chat
    assert chats == [letter]


@pytest.mark.asyncio
async def test_every_keyword_goes_to_chat_while_study_is_off(session_factory, study):
    _channel, state, clock = study
    user, _ = await make_user(session_factory, "slack-off@example.com")
    await a_deck(session_factory, user, clock)
    channel, posted, chats = slack(str(user.id))
    say = _Say(channel)
    state["on"] = False
    for text in ("review", "decks", "quiz 1"):
        await say(text)
    assert posted == [] and chats == ["review", "decks", "quiz 1"]


@pytest.mark.asyncio
async def test_an_unlinked_sender_is_never_answered(session_factory, study):
    _channel, _state, clock = study
    user, _ = await make_user(session_factory, "slack-stranger@example.com")
    await a_deck(session_factory, user, clock)
    channel, posted, chats = slack(str(user.id))
    await _Say(channel)("review", sender=STRANGER)
    assert posted == [] and chats == []
