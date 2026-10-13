"""Tests for the /tutor command grammar and its fixed replies: only a whole
message is a command, the web and Telegram take the slash forms with an
optional @bot suffix, a Slack DM takes the bare words, and each reply names
the off command of the channel it goes to.

Why it exists: a command is how the person, and only the person, switches
tutor mode. "tutor me in calc" or "/tutoring" treated as a command would eat
an ordinary question, and a Slack reply telling someone to type "/tutor off"
would point at a command Slack's client swallows.
"""

from __future__ import annotations

import pytest

from services.tutor.commands import (
    REPLY_OFF,
    REPLY_STAYS_LOCKED_ACCOUNT,
    off_command,
    parse_tutor_argument,
    parse_tutor_command,
    reply_for,
    usage_line,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("/tutor on", "on"),
        ("/tutor off", "off"),
        ("/tutor status", "status"),
        ("/tutor", "status"),
        ("  /TUTOR   On  ", "on"),
        ("/Tutor OFF", "off"),
        ("/tutor@CrawlerBot on", "on"),
        ("/tutor@crawler_bot", "status"),
        ("/tutor\ton", "on"),
    ],
)
def test_slash_forms_are_commands(text, expected):
    assert parse_tutor_command(text, slash_required=True) == expected


@pytest.mark.parametrize(
    "text",
    [
        "tutor me in calc",
        "/tutoring",
        "/tutor please",
        "/tutor on now",
        "/tutor on.",
        "please /tutor on",
        "tutor on",  # bare forms are Slack's only
        "",
        "   ",
        "/tutor@ on",
    ],
)
def test_anything_else_is_an_ordinary_message_on_the_web_and_telegram(text):
    assert parse_tutor_command(text, slash_required=True) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [("tutor on", "on"), ("Tutor OFF", "off"), ("tutor status", "status"), ("tutor", "status")],
)
def test_slack_takes_the_bare_words(text, expected):
    assert parse_tutor_command(text, slash_required=False) == expected


@pytest.mark.parametrize("text", ["/tutor on", "tutor me", "tutoring", "tutor on please"])
def test_slack_refuses_the_slash_and_longer_forms(text):
    assert parse_tutor_command(text, slash_required=False) is None


def test_non_text_and_overlong_input_is_never_a_command():
    assert parse_tutor_command(None, slash_required=True) is None
    assert parse_tutor_command(42, slash_required=False) is None
    assert parse_tutor_command("/tutor " + " " * 200 + "on", slash_required=True) is None


@pytest.mark.parametrize(
    ("argument", "expected"),
    [("on", "on"), ("OFF", "off"), (" status ", "status"), ("", "status"), ("please", None), (None, None)],
)
def test_telegram_argument(argument, expected):
    assert parse_tutor_argument(argument) == expected


def test_each_channel_names_its_own_off_command():
    assert off_command("web") == "/tutor off"
    assert off_command("telegram") == "/tutor off"
    assert off_command("slack") == "tutor off"
    assert "tutor on" in usage_line("slack") and "/tutor" not in usage_line("slack")
    assert "/tutor on" in usage_line("telegram")


def test_on_reply_names_the_channel_off_command():
    web = reply_for("on", source="user", label="", channel="web")
    slack = reply_for("on", source="user", label="", channel="slack")
    assert web == (
        "Tutor mode is on for this chat. I'll guide you with questions and hints instead of "
        "giving final answers, and check your steps as you go. /tutor off switches it off."
    )
    assert slack.endswith("tutor off switches it off.") and "/tutor" not in slack


def test_off_on_a_locked_chat_says_it_stays_locked():
    assert reply_for("off", source="course", label="MATH 221", channel="telegram") == (
        "This chat stays in tutor mode: the owner locked it for MATH 221. Only the owner can "
        "change that, in Settings → Permissions."
    )
    assert reply_for("off", source="account", label="this account", channel="web") == (
        REPLY_STAYS_LOCKED_ACCOUNT
    )
    assert reply_for("off", source="off", label="", channel="web") == REPLY_OFF


def test_status_lists_the_state_and_the_locks_that_apply():
    status = reply_for(
        "status", source="user", label="", channel="web", lock_labels=["MATH 221", "CHEM 101", "MATH 221"]
    )
    assert status.splitlines() == [
        "Tutor mode: on in this chat (you turned it on). /tutor off switches it off.",
        "Owner locks that apply to you: CHEM 101, MATH 221.",
    ]
    off = reply_for("status", source="off", label="", channel="slack")
    assert off.splitlines() == [
        "Tutor mode: off in this chat. tutor on turns it on.",
        "No owner locks apply to you.",
    ]
    locked = reply_for("status", source="course", label="MATH 221", channel="web", lock_labels=["MATH 221"])
    assert locked.startswith("Tutor mode: on in this chat (the owner locked it for MATH 221).")
