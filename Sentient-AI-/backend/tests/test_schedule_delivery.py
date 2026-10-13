"""Tests for how an unattended run's result reaches the owner: the header
names the task and its local time, notes say what waits for them or was not
available, the footer carries the usage line and how to pause (worded per
channel), URL query strings are gone, a long result is cut to four parts and a
pointer to the web app, and delivery goes only through the senders given,
counting a channel only when its first part went out.

Why it exists: these messages leave for Telegram's and Slack's servers with
nobody reviewing them, so their shape and limits are pinned here. Fake
senders only.
"""

from __future__ import annotations

import pytest

from services.automation import delivery
from services.automation.delivery import MAX_PARTS, PART_CHARS, compose, deliver
from services.automation.runner import UnattendedOutcome


def outcome(**fields) -> UnattendedOutcome:
    base = {"status": "ok", "reply": "Two items are due."}
    base.update(fields)
    return UnattendedOutcome(**base)


def test_compose_has_the_header_reply_and_the_telegram_footer():
    [text] = compose("Canvas summary", "Tue 08:00", outcome(), "telegram")
    assert text.startswith("\U0001f5d3 Canvas summary · Tue 08:00\n\nTwo items are due.")
    assert text.endswith("/schedules to pause")


def test_slack_gets_its_own_pause_and_pending_words():
    [text] = compose("Canvas summary", "Tue 08:00", outcome(cards=1), "slack")
    assert "1 action is waiting for your approval (send pending)." in text
    assert text.endswith('reply "schedules" to pause')


def test_notes_for_cards_unavailable_tools_budget_and_stops():
    [text] = compose(
        "Weekly",
        "Mon 09:00",
        outcome(status="over_budget", cards=2, unavailable=("canvas.get_upcoming",), budget_usd=0.05),
        "telegram",
    )
    assert "2 actions are waiting for your approval (/pending)." in text
    assert "Not available this run: canvas.get_upcoming." in text
    assert "Stopped at this task's $0.05 budget." in text
    for status, words in (
        ("timed_out", "took longer"),
        ("stopped", "asked Crawler to stop"),
        ("not_configured", "No AI provider"),
    ):
        assert words in compose("x", "Mon 09:00", outcome(status=status), "telegram")[0]


def test_url_queries_are_stripped_and_the_label_is_defanged():
    [text] = compose(
        "news.example.com digest",
        "Tue 08:00",
        outcome(reply="See https://news.example.com/a?token=SECRET#frag"),
        "telegram",
    )
    assert "token=SECRET" not in text and "https://news.example.com/a" in text
    assert "news.example.com digest" not in text  # the label is not a link


def test_a_usage_line_is_added_when_the_run_used_a_model():
    [text] = compose(
        "x",
        "Tue 08:00",
        outcome(usage={"input_tokens": 1200, "output_tokens": 300}, provider="anthropic", model="claude-sonnet-4-6"),
        "telegram",
    )
    assert "tokens" in text and text.endswith("/schedules to pause")


def test_a_long_result_is_cut_to_four_parts_and_a_pointer():
    reply = "\n".join(f"line {i} " + "x" * 90 for i in range(200))
    parts = compose("Big", "Tue 08:00", outcome(reply=reply), "telegram")
    assert len(parts) <= MAX_PARTS + 2
    assert all(delivery.cards.utf16_len(p) <= PART_CHARS for p in parts)
    assert any('the conversation "Scheduled: Big"' in p for p in parts)
    assert parts[-1].endswith("/schedules to pause")


@pytest.mark.asyncio
async def test_deliver_sends_each_channel_its_parts_and_reports_who_got_it():
    sent: list[tuple[str, str, str]] = []

    def sender(name, answer=True):
        async def send(user_id, text):
            sent.append((name, user_id, text))
            if isinstance(answer, Exception):
                raise answer
            return answer

        return send

    pauses: list[float] = []

    async def no_sleep(seconds):
        pauses.append(seconds)

    got = await deliver(
        "u1",
        {"telegram": ["a", "b"], "slack": ["c"]},
        ("telegram", "slack", "telegram"),
        {"telegram": sender("telegram"), "slack": sender("slack", False)},
        sleep=no_sleep,
    )
    assert got == ("telegram",)
    assert sent == [("telegram", "u1", "a"), ("telegram", "u1", "b"), ("slack", "u1", "c")]
    assert pauses == [delivery.PART_PAUSE_S]


@pytest.mark.asyncio
async def test_a_failing_or_missing_channel_is_not_delivered_and_never_retried():
    calls: list[str] = []

    async def broken(user_id, text):
        calls.append(text)
        raise RuntimeError("telegram down")

    got = await deliver("u1", ["one", "two"], ("telegram", "slack"), {"telegram": broken}, pause_s=0)
    assert got == () and calls == ["one"]
