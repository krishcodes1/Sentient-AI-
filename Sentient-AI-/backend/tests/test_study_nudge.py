"""Tests for the "cards are due" nudge: the study_due renderer answers None while
the owner's study switch is off or when nothing is due by the end of the
user's local day; otherwise one sentence with the count and at most three
defanged deck titles, never card text, at most 500 characters, counting new
cards only up to what is left of today's allowance and only decks in reviews.
study.settings schedules it through the real ScheduleService's nudge path, the
sweeper sends it to the linked channels with no model call, and turning the
reminder off cancels the task.

Why it exists: a nudge goes out unattended to Telegram and Slack, so it must
say only what is safe there and nothing when there is nothing to say. The
database is in-memory SQLite; the clock, the senders and the runner are fakes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from models.installation import INSTALLATION_ROW_ID, Installation
from models.scheduled_task import AutomationRun, ScheduledTask
from services.notifications.schedules import ScheduleService
from services.scheduler import renderers
from services.study import nudges
from services.study.nudges import NUDGE_MAX_CHARS, nudge_text, render_due_nudge
from services.tools.study import StudyToolkit
from tests.conftest import make_user

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)  # 08:00 in New York
SECRET_FRONT = "What is the Krebs cycle's first step?"


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


async def _switch(session_factory, on: bool) -> None:
    async with session_factory() as session:
        row = await session.get(Installation, INSTALLATION_ROW_ID)
        if row is None:
            row = Installation(id=INSTALLATION_ROW_ID, capabilities={})
            session.add(row)
        row.capabilities = {**(row.capabilities or {}), "study": on}
        await session.commit()


async def _render(session_factory, user, now=NOW):
    async with session_factory() as session:
        return await render_due_nudge(session, str(user.id), now)


def _cards(n: int, prefix: str) -> list[dict[str, Any]]:
    return [{"front": f"{prefix} {SECRET_FRONT} {i}", "back": "Acetyl-CoA joins oxaloacetate"} for i in range(n)]


def test_the_renderer_is_registered_at_import_under_the_study_switch():
    renderer = renderers.get_renderer("study_due")
    assert renderer is not None and renderer.capability == "study"
    assert renderer.render is render_due_nudge


@pytest.mark.asyncio
async def test_nothing_while_the_switch_is_off_or_nothing_is_due(session_factory):
    user, _ = await make_user(session_factory, "nudge-none@example.com")
    kit = StudyToolkit(session_factory, clock=Clock(), default_timezone=lambda: "UTC")
    assert await _render(session_factory, user) is None  # no installation row: off
    await kit.execute("save", {"title": "Bio 101", "items": _cards(2, "A")}, str(user.id))
    await _switch(session_factory, False)
    assert await _render(session_factory, user) is None
    await _switch(session_factory, True)
    assert await _render(session_factory, user) is not None
    await kit.execute("settings", {"new_per_day": 0}, str(user.id))
    assert await _render(session_factory, user) is None  # new cards only, none allowed today
    assert await _render(session_factory, type("U", (), {"id": "not-a-user"})()) is None


@pytest.mark.asyncio
async def test_counts_and_three_defanged_titles_never_card_text(session_factory):
    user, _ = await make_user(session_factory, "nudge-text@example.com")
    await _switch(session_factory, True)
    kit = StudyToolkit(session_factory, clock=Clock(), default_timezone=lambda: "UTC")
    await kit.execute("settings", {"new_per_day": 100}, str(user.id))
    for title, count in (("Bio 101 – Lecture 3", 12), ("Chem 201", 6), ("see evil.example.com", 2), ("Physics", 1)):
        await kit.execute("save", {"title": title, "items": _cards(count, title)}, str(user.id))
    hidden = await kit.execute("save", {"title": "Hidden", "items": _cards(3, "H")}, str(user.id))
    await kit.execute("edit", {"deck_id": hidden["deck_id"], "in_reviews": False}, str(user.id))
    text = await _render(session_factory, user)
    assert text == (
        "\U0001F4DA 21 flashcards are due: Bio 101 – Lecture 3 (12), Chem 201 (6), "
        "see evil․example․com (2) and 1 more deck. "
        'Send /review on Telegram or "review" in Slack.'
    )
    assert SECRET_FRONT not in text and "Acetyl" not in text and len(text) <= NUDGE_MAX_CHARS


@pytest.mark.asyncio
async def test_due_by_the_end_of_the_local_day_and_the_new_card_allowance(session_factory):
    from models.user import User

    user, _ = await make_user(session_factory, "nudge-day@example.com")
    async with session_factory() as session:
        (await session.get(User, user.id)).timezone = "America/New_York"
        await session.commit()
    await _switch(session_factory, True)
    clock = Clock()
    kit = StudyToolkit(session_factory, clock=clock, default_timezone=lambda: "UTC")
    await kit.execute("settings", {"new_per_day": 3}, str(user.id))
    saved = await kit.execute("save", {"title": "Deck", "items": _cards(6, "D")}, str(user.id))
    for item_id in saved["added_ids"][:2]:  # two new cards introduced today, due tomorrow
        await kit.execute("review", {"action": "grade", "item_id": item_id, "rating": "good"}, str(user.id))
    assert "1 flashcard is due" in (await _render(session_factory, user))  # 3 - 2 new left
    # Tomorrow 07:00 New York: the two graded cards are due by the day's end,
    # and the allowance is back to 3.
    tomorrow = NOW + timedelta(hours=23)
    assert "5 flashcards are due" in (await _render(session_factory, user, tomorrow))


def test_the_text_never_passes_500_characters():
    decks = [("T" * 200, 5), ("U" * 200, 5), ("V" * 200, 5), ("W", 1)]
    text = nudge_text(16, decks)
    assert len(text) <= NUDGE_MAX_CHARS and text.startswith("\U0001F4DA 16 flashcards are due")


# -- through the schedule service -------------------------------------------------


class _Outbox:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []

    def sender(self, channel: str):
        async def send(user_id, text):
            self.sent.append((channel, user_id, text))
            return True

        return send


class _NoRunner:
    async def run(self, request):  # pragma: no cover - a nudge never runs a model turn
        raise AssertionError("a nudge must not run an agent turn")

    async def budget_left(self, user_id, *, exclude_run_id=None):  # pragma: no cover
        raise AssertionError("a nudge has no budget")


@pytest.mark.asyncio
async def test_settings_schedule_the_nudge_and_the_sweeper_sends_it(session_factory):
    user, _ = await make_user(session_factory, "nudge-e2e@example.com")
    await _switch(session_factory, True)
    clock, outbox = Clock(), _Outbox()

    async def enabled():
        return frozenset({"study"})

    service = ScheduleService(
        session_factory,
        runner=_NoRunner(),
        senders={"telegram": outbox.sender("telegram"), "slack": outbox.sender("slack")},
        enabled_keys=enabled,
        clock=clock,
        delivery_pause_s=0,
    )
    kit = StudyToolkit(session_factory, clock=clock, nudges=service, default_timezone=lambda: "UTC")
    await kit.execute("save", {"title": "Bio 101", "items": _cards(4, "B")}, str(user.id))
    on = await kit.execute("settings", {"reminder": True, "hour": 8, "timezone": "America/New_York"}, str(user.id))
    assert on["ok"] and on["reminder"]["recurrence"] == {"freq": "daily", "time": "08:00"}
    assert on["reminder"]["timezone"] == "America/New_York"
    async with session_factory() as session:
        [task] = (await session.execute(select(ScheduledTask))).scalars().all()
    assert (task.kind, task.options, task.label) == ("nudge", {"renderer": "study_due"}, "Flashcards due")
    assert task.next_run_at.replace(tzinfo=timezone.utc) == NOW + timedelta(days=1)
    # The hour moves without a second task.
    moved = await kit.execute("settings", {"hour": 19}, str(user.id))
    assert moved["reminder"]["recurrence"]["time"] == "19:00"

    clock.now = NOW + timedelta(hours=11, minutes=1)  # 19:01 New York, the same day
    assert await service.sweep_once() == 1
    await service.wait_idle()
    texts = [t for _channel, _user, t in outbox.sent]
    assert texts and "4 flashcards are due: Bio 101 (4)" in texts[0]
    assert SECRET_FRONT not in "".join(texts)
    async with session_factory() as session:
        [run] = (await session.execute(select(AutomationRun))).scalars().all()
    assert run.status == "ok" and run.input_tokens == 0

    off = await kit.execute("settings", {"reminder": False}, str(user.id))
    assert off["ok"]
    async with session_factory() as session:
        assert (await session.execute(select(ScheduledTask))).scalars().all() == []


@pytest.mark.asyncio
async def test_the_sweeper_skips_the_nudge_while_study_is_off(session_factory):
    user, _ = await make_user(session_factory, "nudge-off@example.com")
    clock, outbox = Clock(), _Outbox()

    async def enabled():
        return frozenset({"scheduled_tasks"})

    service = ScheduleService(
        session_factory,
        runner=_NoRunner(),
        senders={"telegram": outbox.sender("telegram")},
        enabled_keys=enabled,
        clock=clock,
        delivery_pause_s=0,
    )
    task_id = await service.upsert_nudge(
        user.id,
        renderer=nudges.RENDERER,
        label=nudges.LABEL,
        recurrence={"freq": "daily", "time": "08:00"},
        timezone="UTC",
        channels=("telegram",),
    )
    async with session_factory() as session:
        (await session.get(ScheduledTask, uuid.UUID(task_id))).next_run_at = NOW
        await session.commit()
    assert await service.sweep_once() == 0 and outbox.sent == []
