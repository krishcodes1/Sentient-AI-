"""Tests for the approval-card helpers and the untruncated Telegram card:
every detail is shown in full as plain labelled lines (nested values, lists,
text on several lines, flags, empty values), text inside a value can never
pass for another line of the card, splitting never drops or rewrites content
and keeps every part within the limit (UTF-16 aware for Telegram), the check
code is stable, sensitive and grouped, and a long Telegram card goes out as
labelled, paced parts that never interleave with another card's, with the
question, the check code and the buttons on the last one. An oversized
card, or one with a lost part, becomes a notice with no buttons. The reply
notes, the expiry, the decision line and the grant line are plain words:
never a tool id, never an em or en dash.

Why it exists: an approval card that cuts its details, or whose buttons sit
under a message that does not say what they approve, lets the owner approve
something they cannot see (spec F3); one that reads like a developer log
(tool ids, JSON, "Arguments digest") is no use to the person deciding
(docs/bot-message-style.md).

Connects to: services/notifications/cards.py, services/action_text.py (the
labels and phrases) and the approval card in services/notifications/
telegram.py, with the Bot API faked at the httpx transport
(FakeTelegramAPI from tests/test_telegram.py).
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from services.action_text import known_tools
from services.notifications import cards
from services.notifications.cards import (
    DETAIL_INDENT,
    DIGEST_HEX_CHARS,
    MAX_CARD_PARTS,
    CardLayout,
    arguments_digest,
    ask_line,
    check_code,
    check_code_line,
    decided_at_text,
    decision_line,
    detail_pairs,
    expires_in_text,
    layout_card,
    low_risk_line,
    render_details,
    send_card_parts,
    split_text,
    turn_notes,
    utf16_len,
    waiting_cards_note,
)
from tests.test_telegram import FakeTelegramAPI, _link, _make_service

EM_DASH, EN_DASH = chr(0x2014), chr(0x2013)


def _no_dashes(text: str) -> bool:
    return EM_DASH not in text and EN_DASH not in text


# ── arguments_digest / check_code ──────────────────────────────────────


def test_digest_is_short_lowercase_hex() -> None:
    digest = arguments_digest({"to": "a@example.com"})
    assert len(digest) == DIGEST_HEX_CHARS
    assert all(c in "0123456789abcdef" for c in digest)


def test_digest_ignores_key_order_and_is_stable() -> None:
    a = {"to": "a@example.com", "body": {"x": 1, "y": [1, 2]}}
    b = {"body": {"y": [1, 2], "x": 1}, "to": "a@example.com"}
    assert arguments_digest(a) == arguments_digest(b) == arguments_digest(dict(a))


@pytest.mark.parametrize(
    "changed",
    [
        {"to": "b@example.com", "body": "hi"},
        {"to": "a@example.com", "body": "hi "},
        {"to": "a@example.com", "body": "hi", "cc": "c@example.com"},
        {"to": "a@example.com"},
        {"To": "a@example.com", "body": "hi"},
        {"to": "a@example.com", "body": ["hi"]},
    ],
)
def test_digest_changes_with_any_key_or_value(changed: dict) -> None:
    assert arguments_digest(changed) != arguments_digest({"to": "a@example.com", "body": "hi"})


def test_digest_distinguishes_types_and_handles_unicode_and_odd_values() -> None:
    assert arguments_digest({"n": 1}) != arguments_digest({"n": "1"})
    assert arguments_digest({"s": "café"}) != arguments_digest({"s": "cafe"})
    # Values JSON cannot encode fall back to str instead of raising.
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert arguments_digest({"at": when}) == arguments_digest({"at": str(when)})
    assert len(arguments_digest({})) == DIGEST_HEX_CHARS


def test_check_code_groups_the_whole_digest_in_fours() -> None:
    args = {"q": "x"}
    digest = arguments_digest(args)
    code = check_code(args)
    assert code == " ".join([digest[0:4], digest[4:8], digest[8:12], digest[12:16]])
    assert re.fullmatch(r"[0-9a-f]{4}( [0-9a-f]{4}){3}", code)
    assert code.replace(" ", "") == digest
    assert check_code_line(args) == f"Check code {code}"


# ── detail_pairs / render_details ──────────────────────────────────────

EMAIL = "google_workspace.send_email"


def test_details_are_plain_labelled_lines_in_the_arguments_order() -> None:
    args = {"to": "priya@acme.com", "subject": "Friday lunch", "body": "Hi Priya, noon?"}
    assert detail_pairs(EMAIL, args) == [
        ("To", "priya@acme.com"),
        ("Subject", "Friday lunch"),
        ("Message", "Hi Priya, noon?"),
    ]
    assert render_details(EMAIL, args) == (
        "To: priya@acme.com\nSubject: Friday lunch\nMessage: Hi Priya, noon?"
    )


def test_render_details_shows_no_json_or_code_syntax() -> None:
    args = {"message_id": "18c2f", "max_results": 5, "include_spam": False}
    rendered = render_details("x.y", args)
    assert rendered == "Email ID: 18c2f\nMax results: 5\nInclude spam: No"
    for code in ("{", "}", '"', "_", "true", "false", "null"):
        assert code not in rendered


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        (None, "(none)"),
        ("", "(empty)"),
        (True, "Yes"),
        (False, "No"),
        (0, "0"),
        (2.5, "2.5"),
        ([], "(none)"),
        ({}, "(none)"),
        (["only@one.com"], "only@one.com"),
    ],
)
def test_plain_values_read_as_words(value: Any, shown: str) -> None:
    assert detail_pairs("x.y", {"field": value}) == [("Field", shown)]
    assert render_details("x.y", {"field": value}) == f"Field: {shown}"


def test_known_fixed_values_are_shown_in_everyday_words() -> None:
    assert render_details("system.install_capability", {"name": "speech_to_text"}) == (
        "Add-on: Voice notes"
    )


def test_every_leaf_value_is_shown_in_full_under_its_label() -> None:
    long_text = "word " * 2000
    args = {
        "to": ["a@example.com", "b@example.com"],
        "body": "Hi,\n\nsee you at noon.\nBye",
        "event": {
            "summary": long_text,
            "start": {"dateTime": "2026-10-14T09:00:00", "timeZone": "Europe/Paris"},
            "reminders": [],
            "private": True,
            "location": None,
            "notes": "",
        },
        "attendees": [
            {"email": "c@example.com", "optional": False},
            {"email": "d@example.com"},
        ],
        "amount": 1999.99,
    }
    rendered = render_details("google_workspace.create_event", args)
    lines = rendered.split("\n")
    # Every leaf, whole, somewhere in the card (an exact ISO time in words
    # that name the same moment).
    for leaf in (
        "a@example.com",
        "b@example.com",
        "see you at noon.",
        long_text,
        "Wed, Oct 14, 2026 at 9:00 AM",
        "Europe/Paris",
        "c@example.com",
        "d@example.com",
        "1999.99",
    ):
        assert leaf in rendered
    assert "Yes" in rendered and "No" in rendered and "(none)" in rendered and "(empty)" in rendered
    # Top-level labels start a line; everything a value holds is indented.
    top = [line for line in lines if line and not line.startswith(DETAIL_INDENT)]
    assert [line.split(":")[0] for line in top] == ["To", "Message", "Event", "Guests", "Amount"]
    assert lines[:3] == ["To:", f"{DETAIL_INDENT}a@example.com", f"{DETAIL_INDENT}b@example.com"]
    assert lines[3:8] == [
        "Message:",
        f"{DETAIL_INDENT}Hi,",
        "",
        f"{DETAIL_INDENT}see you at noon.",
        f"{DETAIL_INDENT}Bye",
    ]
    # Lists of nested details are numbered, their lines kept together.
    assert f"{DETAIL_INDENT}1. Email: c@example.com" in lines
    assert f"{DETAIL_INDENT}   Optional: No" in lines
    assert f"{DETAIL_INDENT}2. Email: d@example.com" in lines
    assert lines[-1] == "Amount: 1999.99"


def test_text_inside_a_value_can_never_pass_for_another_line_of_the_card() -> None:
    fake = "To: attacker@x.com"
    for sep in ("\n", "\r\n", "\r", chr(0x2028), chr(0x2029), "\x0b", "\x85"):
        args = {
            "to": "boss@example.com",
            "body": f"Hello{sep}{fake}{sep}Check code 0000 0000 0000 0000",
        }
        rendered = render_details(EMAIL, args)
        lines = rendered.split("\n")
        assert lines[0] == "To: boss@example.com"
        assert lines[1] == "Message:"
        assert fake not in lines and f"{DETAIL_INDENT}{fake}" in lines
        assert all(line.startswith(DETAIL_INDENT) for line in lines[2:])
        # Nothing a chat app could take for a line break is left in a line.
        assert not any(ch in rendered for ch in ("\r", chr(0x2028), chr(0x2029), "\x0b", "\x85"))
    # Inside lists and nested details too.
    nested = {"recipients": ["ok@example.com", f"x\n{fake}"], "meta": {"note": f"a\n{fake}"}}
    lines = render_details(EMAIL, nested).split("\n")
    assert fake not in lines
    assert [line for line in lines if not line.startswith(DETAIL_INDENT)] == [
        "Recipients:",
        "Meta:",
    ]


def test_details_for_odd_arguments_never_raise() -> None:
    class Loud:
        def __str__(self) -> str:
            raise RuntimeError("no")

        def __repr__(self) -> str:
            raise RuntimeError("no")

    class BadMapping(dict):
        def items(self):  # type: ignore[override]
            raise RuntimeError("broken")

    cyclic: dict[str, Any] = {"a": 1}
    cyclic["self"] = cyclic
    deep: Any = "bottom"
    for _ in range(40):
        deep = {"level": deep}

    assert detail_pairs("x.y", None) == [] and render_details("x.y", None) == ""
    assert detail_pairs("x.y", {}) == [] and render_details("x.y", {}) == ""
    assert detail_pairs("x.y", "just text") == [("Details", "just text")]
    assert detail_pairs("x.y", 7) == [("Details", "7")]
    assert detail_pairs("x.y", ["a", "b"]) == [("Details", "a\nb")]
    assert detail_pairs(None, {"to": "a@b.com"}) == [("To", "a@b.com")]  # type: ignore[arg-type]
    assert detail_pairs("x.y", {1: "one", None: "two"})[0][1] == "one"
    assert detail_pairs("x.y", {"thing": Loud()}) == [("Thing", "(a value I can't show)")]
    assert detail_pairs("x.y", BadMapping(a=1))[0][0] == "Details"
    assert "a" in render_details("x.y", cyclic)
    assert "bottom" in render_details("x.y", deep)
    assert render_details("x.y", {"when": datetime(2026, 1, 2, tzinfo=timezone.utc)}) == (
        "When: 2026-01-02 00:00:00+00:00"
    )


# ── split_text ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("max_chars", [64, 100, 257, 3900])
def test_chunks_round_trip_and_stay_within_limit(max_chars: int) -> None:
    args = {
        "to": ["a@example.com", "b@example.com"],
        "body": "line one\nline two " * 200,
        "nested": {"items": [{"i": i, "text": "t" * (i * 7)} for i in range(40)]},
    }
    rendered = render_details(EMAIL, args)
    chunks = split_text(rendered, max_chars=max_chars)
    assert "".join(chunks) == rendered
    assert all(0 < len(c) <= max_chars for c in chunks)
    assert len(chunks) > 1


def test_chunks_break_on_line_boundaries_when_lines_fit() -> None:
    chunks = split_text(
        render_details("x.y", {f"k{i}": "v" * 30 for i in range(50)}), max_chars=200
    )
    # Every line is short, so every chunk but the last ends at a newline.
    assert all(c.endswith("\n") for c in chunks[:-1])


def test_huge_single_string_is_hard_split_without_loss() -> None:
    rendered = render_details("x.y", {"blob": "A" * 100_003})
    chunks = split_text(rendered, max_chars=3900)
    assert "".join(chunks) == rendered
    assert all(len(c) <= 3900 for c in chunks)
    assert len(chunks) <= len(rendered) // 3900 + 3


def test_utf16_length_counts_astral_characters_twice() -> None:
    assert utf16_len("abc") == 3
    assert utf16_len("é") == 1
    assert utf16_len("\U0001f600") == 2
    assert utf16_len("a\U0001f600b") == 4


def test_utf16_chunks_fit_telegram_units_and_never_split_a_character() -> None:
    rendered = render_details("x.y", {"emoji": "\U0001f600" * 5000, "mixed": "a\U0001f389b" * 700})
    chunks = split_text(rendered, max_chars=3900, length=utf16_len)
    assert "".join(chunks) == rendered
    assert all(utf16_len(c) <= 3900 for c in chunks)
    # Measured by code points the same parts would be about half full, so
    # the UTF-16 measure really drove the split.
    assert max(len(c) for c in chunks) < 3900
    for chunk in chunks:
        chunk.encode("utf-8")  # no lone surrogate from a split pair


def test_split_text_rejects_a_limit_too_small_to_progress() -> None:
    with pytest.raises(ValueError):
        split_text("abc", max_chars=10)


def test_split_text_edge_cases() -> None:
    assert split_text("", max_chars=64) == []
    assert split_text("short", max_chars=64) == ["short"]
    text = "x" * 64 + "\n" + "y" * 64
    parts = split_text(text, max_chars=64)
    assert "".join(parts) == text
    assert all(len(p) <= 64 for p in parts)


def test_split_text_tops_up_a_part_before_hard_splitting_a_long_line() -> None:
    text = "ab\n" + "x" * 200
    parts = split_text(text, max_chars=64)
    assert parts[0] == "ab\n" + "x" * 61  # filled, not sent three characters long
    assert "".join(parts) == text
    assert all(len(p) <= 64 for p in parts)


def test_split_text_top_up_never_splits_a_two_unit_character() -> None:
    text = "a" * 62 + "\n" + "\U0001f600" * 100  # one unit of room left
    parts = split_text(text, max_chars=64, length=utf16_len)
    assert parts[0] == "a" * 62 + "\n"
    assert "".join(parts) == text
    assert all(utf16_len(p) <= 64 for p in parts)


# ── layout_card ────────────────────────────────────────────────────────

TOOL = "github.merge_pr"
SENTENCE = "\U0001f510 Merge pull request #7 in o/r on GitHub"
ASK = "Okay to go ahead? This expires in 14 minutes."
_MARKER = re.compile(r"\n\(This part ends with (\d+) blank spaces?\.\)\Z")


def _head() -> list[str]:
    return [SENTENCE, "", "⚠️ It merges into the main branch."]


def _code8(args: Any) -> str:
    digest = arguments_digest(args)
    return f"{digest[:4]} {digest[4:8]}"


def _content_of(card: CardLayout) -> str:
    """What the leading parts carry, without their header and marker lines,
    checking each header names the card and its part number."""
    pieces = []
    for index, part in enumerate(card.leading, start=1):
        header, _, rest = part.partition("\n")
        assert header == f"{card.label}, part {index} of {card.parts}"
        marker = _MARKER.search(rest)
        if marker:
            rest = rest[: marker.start()]
            body = rest.rstrip("\n")
            assert len(body) - len(body.rstrip()) == int(marker.group(1))
        pieces.append(rest)
    return "".join(pieces)


def _survives_channel_trimming(message: str) -> bool:
    """Telegram trims blanks at both ends of a message; only newlines at
    the end may be lost (they are line joins, not content)."""
    return message == message.lstrip() and message.rstrip() == message.rstrip("\n")


def _messages(card: CardLayout) -> list[str]:
    return [*card.leading, "\n".join(card.final_lines)]


def _closing(card: CardLayout) -> str:
    return (
        f"That's all of request {card.label.removeprefix('Request ')} "
        f"(part {card.parts} of {card.parts}). The details are in the messages above."
    )


def test_short_card_reads_like_the_style_guide() -> None:
    args = {
        "to": "priya@acme.com",
        "subject": "Friday lunch",
        "body": "Hi Priya, are we still on for noon?",
    }
    head = ["\U0001f510 Send an email to priya@acme.com from your Gmail"]
    card = layout_card(head, args, tool_name=EMAIL, max_chars=3900, ask=ASK)
    assert card.leading == () and card.notice is None and card.parts == 1
    assert list(card.final_lines) == [
        head[0],
        "",
        "To: priya@acme.com",
        "Subject: Friday lunch",
        "Message: Hi Priya, are we still on for noon?",
        "",
        ASK,
        check_code_line(args),
    ]
    assert card.label == f"Request {_code8(args)}"


def test_short_card_without_an_ask_ends_with_the_check_code() -> None:
    args = {"repo": "o/r", "number": 7}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=3900)
    assert list(card.final_lines[: len(_head())]) == _head()
    assert card.final_lines[-1] == check_code_line(args)
    assert render_details(TOOL, args) in "\n".join(card.final_lines)
    text = "\n".join(card.final_lines)
    for jargon in ("Arguments", "digest", "Tool:", TOOL, "{"):
        assert jargon not in text


def test_card_without_arguments_has_no_details_block() -> None:
    card = layout_card(_head(), {}, tool_name=TOOL, max_chars=3900, ask=ASK)
    assert card.leading == ()
    assert list(card.final_lines) == [*_head(), "", ASK, check_code_line({})]


def test_card_masks_secrets_before_rendering_and_codes_the_real_arguments() -> None:
    token = "ghp_" + "FAKE" * 9
    args = {"to": "a@example.com", "options": {"headers": [f"Authorization: token {token}"]}}
    card = layout_card(_head(), args, tool_name=EMAIL, max_chars=3900, ask=ASK)
    text = "\n".join(card.final_lines)
    assert token not in text and "[hidden: GitHub token]" in text
    assert "To: a@example.com" in text
    assert card.final_lines[-1] == check_code_line(args)


def test_long_card_parts_are_labelled_and_round_trip_exactly() -> None:
    args = {"body": "paragraph\n" * 300, "blob": "Z" * 2000}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=500, max_parts=50, ask=ASK)
    assert len(card.leading) > 2
    assert all(len(m) <= 500 for m in _messages(card))
    assert all(_survives_channel_trimming(m) for m in _messages(card))
    # Exact: nothing dropped, nothing rewritten, not even blanks.
    assert _content_of(card) == render_details(TOOL, args)
    # The button message repeats the head, names the card and asks.
    assert list(card.final_lines) == [*_head(), "", _closing(card), "", ASK, check_code_line(args)]


@pytest.mark.parametrize(
    ("args", "max_chars", "length"),
    [
        # The review's reproduction: once left a bare digest on the buttons.
        ({"path": "a", "content": "Q" * 7750}, 3900, utf16_len),
        ({"emoji": "\U0001f600" * 6000}, 3900, utf16_len),
        ({"lines": ["x" * 50] * 300}, 3900, len),
        ({"a": " " * 9000, "b": "x"}, 3900, len),
    ],
)
def test_button_message_always_names_the_request_and_its_check_code(
    args, max_chars, length
) -> None:
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=max_chars, length=length, ask=ASK)
    assert card.leading and card.notice is None
    final = "\n".join(card.final_lines)
    assert card.label == f"Request {_code8(args)}"
    assert final.startswith(SENTENCE)
    assert _closing(card) in card.final_lines
    assert card.final_lines[-2:] == (ASK, check_code_line(args))
    assert all(length(m) <= max_chars for m in _messages(card))
    assert _content_of(card) == render_details(TOOL, args)
    for message in _messages(card):
        assert TOOL not in message and "Arguments" not in message and _no_dashes(message)


def test_blank_runs_at_part_ends_are_kept_and_marked() -> None:
    args = {"a": " " * 9000, "b": "x"}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=3900)
    assert any(_MARKER.search(part) for part in card.leading)
    assert all(_survives_channel_trimming(m) for m in _messages(card))
    assert _content_of(card) == render_details(TOOL, args)


def test_head_too_long_to_repeat_moves_into_the_first_part() -> None:
    head = [SENTENCE, "", "⚠️ " + "w" * 5000]
    args = {"q": "x"}
    card = layout_card(head, args, tool_name=TOOL, max_chars=3900, ask=ASK)
    # The last message repeats just the sentence, never a tool id.
    assert list(card.final_lines) == [SENTENCE, "", _closing(card), "", ASK, check_code_line(args)]
    assert _content_of(card) == "\n".join([*head, "", render_details(TOOL, args)])
    assert all(len(m) <= 3900 for m in _messages(card))


def test_a_first_head_line_too_long_to_repeat_is_clipped_on_the_last_message_only() -> None:
    sentence = "\U0001f510 Type " + "s" * 6000
    args = {"text": "x"}
    card = layout_card([sentence], args, tool_name=TOOL, max_chars=3900, ask=ASK)
    reminder = card.final_lines[0]
    assert reminder.endswith("…") and sentence.startswith(reminder[:-1])
    assert card.final_lines[-2:] == (ASK, check_code_line(args))
    # The whole sentence is still in the parts above.
    assert _content_of(card) == "\n".join([sentence, "", render_details(TOOL, args)])
    assert all(len(m) <= 3900 for m in _messages(card))


def test_card_over_the_part_cap_becomes_a_notice() -> None:
    args = {"blob": "B" * 100_000}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=3900, ask=ASK)
    assert card.leading == () and card.final_lines == ()
    assert card.parts > MAX_CARD_PARTS
    assert card.notice == (
        f"{card.label} is too long to show here (it would take {card.parts} messages). "
        "Open the Crawler web app to read it and decide there."
    )
    assert "BBBB" not in card.notice
    assert len(card.notice) <= 3900


def test_card_at_exactly_the_cap_is_laid_out_in_parts() -> None:
    args = {"body": "y" * 12_000}
    needed = layout_card(_head(), args, tool_name=TOOL, max_chars=3900).parts
    assert 2 < needed <= MAX_CARD_PARTS
    at_cap = layout_card(_head(), args, tool_name=TOOL, max_chars=3900, max_parts=needed)
    assert at_cap.notice is None and at_cap.parts == needed
    over = layout_card(_head(), args, tool_name=TOOL, max_chars=3900, max_parts=needed - 1)
    assert over.notice is not None and over.leading == ()


def test_layout_rejects_limits_that_leave_no_room() -> None:
    with pytest.raises(ValueError):
        layout_card(_head(), {"a": "b" * 5000}, tool_name=TOOL, max_chars=3900, max_parts=1)
    with pytest.raises(ValueError):
        layout_card(_head(), {"a": "b" * 5000}, tool_name=TOOL, max_chars=3900, ask="a" * 3900)


# ── send_card_parts ────────────────────────────────────────────────────


class _Chat:
    """Records sends; the send numbered *fail_at* (1-based) is lost."""

    def __init__(self, fail_at: int | None = None) -> None:
        self.sent: list[str] = []
        self.fail_at = fail_at

    async def send(self, text: str) -> bool:
        self.sent.append(text)
        return len(self.sent) != self.fail_at


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    recorded: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        recorded.append(seconds)

    monkeypatch.setattr(cards, "asyncio", SimpleNamespace(sleep=fake_sleep))
    return recorded


def _three_part_card() -> CardLayout:
    card = layout_card(_head(), {"body": "y" * 6000}, tool_name=TOOL, max_chars=3900)
    assert len(card.leading) == 2
    return card


@pytest.mark.asyncio
async def test_send_card_parts_sends_every_part_in_order_and_paced(sleeps) -> None:
    card, chat = _three_part_card(), _Chat()
    assert await send_card_parts(card, chat.send, retry_hint="Retry.") is True
    assert chat.sent == list(card.leading)
    assert sleeps == [cards.PART_INTERVAL_S] * (len(card.leading) + 1)
    assert cards.PART_INTERVAL_S >= 1.0  # about one message a second per chat


@pytest.mark.asyncio
async def test_send_card_parts_single_message_card_sends_nothing_first(sleeps) -> None:
    card, chat = layout_card(_head(), {"q": 1}, tool_name=TOOL, max_chars=3900), _Chat()
    assert await send_card_parts(card, chat.send, retry_hint="Retry.") is True
    assert chat.sent == [] and sleeps == []


@pytest.mark.asyncio
async def test_send_card_parts_sends_only_the_notice_for_an_oversized_card(sleeps) -> None:
    card = layout_card(_head(), {"blob": "B" * 100_000}, tool_name=TOOL, max_chars=3900)
    chat = _Chat()
    assert await send_card_parts(card, chat.send, retry_hint="Retry.") is False
    assert chat.sent == [card.notice]


@pytest.mark.asyncio
async def test_send_card_parts_stops_and_explains_when_a_part_is_lost(sleeps) -> None:
    card, chat = _three_part_card(), _Chat(fail_at=2)
    assert await send_card_parts(card, chat.send, retry_hint="Send /pending.") is False
    assert chat.sent[:2] == list(card.leading[:2])
    assert len(chat.sent) == 3
    code = card.label.removeprefix("Request ")
    assert chat.sent[2] == (
        f"Part 2 of {card.parts} of request {code} didn't come through, so I left the "
        "buttons off to be safe. Send /pending."
    )
    assert cards.FAILED_PART_NOTICE_DELAY_S in sleeps


# ── the words around a card ────────────────────────────────────────────


def _in(minutes: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes, seconds=30)).isoformat()


class _InMinutes(float):
    """A deadline this many minutes from when the test runs. The timestamp
    is made inside the test, not at collection: a long suite can run a
    test many minutes after it was collected."""


@pytest.mark.parametrize(
    ("expires", "words"),
    [
        (_InMinutes(14), "14 minutes"),
        (_InMinutes(1), "1 minute"),
        (_InMinutes(0), "less than a minute"),
        (_InMinutes(-30), "less than a minute"),
        (_InMinutes(75), "75 minutes"),
        (_InMinutes(5 * 60), "about 5 hours"),
        (_InMinutes(3 * 24 * 60), "about 3 days"),
        ("not a time", "a few minutes"),
        ("", "a few minutes"),
        (None, "a few minutes"),
    ],
)
def test_expires_in_text_is_plain_words(expires: Any, words: str) -> None:
    if isinstance(expires, _InMinutes):
        expires = _in(expires)
    assert expires_in_text(expires) == words


def test_expires_in_text_reads_a_naive_timestamp_as_utc() -> None:
    naive = (datetime.now(timezone.utc) + timedelta(minutes=14, seconds=30)).replace(tzinfo=None)
    assert expires_in_text(naive.isoformat()) == "14 minutes"


def test_ask_line_wording() -> None:
    assert ask_line(_in(14)) == "Okay to go ahead? This expires in 14 minutes."
    assert ask_line("garbage") == "Okay to go ahead? This expires in a few minutes."


def test_decided_at_text_is_a_local_clock_time() -> None:
    afternoon = datetime(2026, 10, 13, 17, 25).astimezone()
    assert decided_at_text(afternoon) == "5:25 PM"
    assert decided_at_text(datetime(2026, 10, 13, 0, 5).astimezone()) == "12:05 AM"
    assert decided_at_text(datetime(2026, 10, 13, 12, 0).astimezone()) == "12:00 PM"
    assert decided_at_text(datetime(2026, 10, 13, 9, 7).astimezone()) == "9:07 AM"
    assert re.fullmatch(r"\d{1,2}:\d{2} (AM|PM)", decided_at_text())
    assert re.fullmatch(r"\d{1,2}:\d{2} (AM|PM)", decided_at_text("nonsense"))  # type: ignore[arg-type]


def test_decision_line_wording() -> None:
    assert decision_line(True, at="5:25 PM") == "✅ Approved at 5:25 PM."
    assert decision_line(False, at="5:25 PM") == "❌ Denied at 5:25 PM. I didn't do it."
    assert decision_line(True, at="") == "✅ Approved."
    assert decision_line(False, at=None) == "❌ Denied. I didn't do it."  # type: ignore[arg-type]


def test_turn_notes_wording() -> None:
    one = turn_notes(
        {"pending_approvals": ["google_workspace.send_email"]}, pending_hint="send pending"
    )
    assert one == (
        "\n\n\U0001f510 I need your OK first to send an email. The request is just above, "
        "or send pending to see it again."
    )
    several = turn_notes(
        {"pending_approvals": ["google_workspace.send_email", "system.install_capability"]},
        pending_hint="send /pending",
    )
    assert several == (
        "\n\n\U0001f510 I need your OK on 2 things first: send an email; install an add-on. "
        "The requests are just above, or send /pending to see them again."
    )
    blocked = turn_notes({"blocked": ["desktop.act"]}, pending_hint="send pending")
    assert blocked == (
        "\n\n⛔ I skipped one step because your safety settings don't allow it: "
        "click or type in an app on your computer."
    )
    repeated = turn_notes(
        {"blocked": ["desktop.act", "desktop.act", "browser.act"]}, pending_hint="x"
    )
    assert repeated.startswith(
        "\n\n⛔ I skipped 3 steps because your safety settings don't allow them: "
        "click or type in an app on your computer (2 times); "
    )
    assert turn_notes({}, pending_hint="send pending") == ""
    assert turn_notes({"pending_approvals": [], "blocked": None}, pending_hint="send pending") == ""


def test_turn_notes_never_name_a_tool() -> None:
    tools = [*known_tools(), "mcp.brave_search.web_search", "acme__1f2e.do_thing", "weird"]
    for tool in tools:
        notes = turn_notes(
            {"pending_approvals": [tool], "blocked": [tool]}, pending_hint="send pending"
        )
        assert tool not in notes, tool
        assert "_" not in notes, (tool, notes)
        assert _no_dashes(notes)
    odd = turn_notes(
        {"pending_approvals": [None, 5, {"x": 1}], "blocked": "desktop.act"}, pending_hint=""
    )
    assert "desktop.act" not in odd and odd.count("\U0001f510") == 1


def test_low_risk_line_wording() -> None:
    line = low_risk_line(
        "School Gmail",
        [
            "save email drafts (nothing is sent)",
            "star, mark important or apply your own labels to emails",
        ],
        how="/grants lists and revokes.",
    )
    assert line == (
        "Or let me make small changes on School Gmail for 7 days without asking: save email "
        "drafts (nothing is sent); star, mark important or apply your own labels to emails. "
        "I'll still ask before I send, delete or share anything, and before anything other "
        "people can see. /grants lists and revokes."
    )
    many = low_risk_line("Drive", [f"note {i}" for i in range(6)], how="")
    assert "note 3; and 2 more. I'll still ask" in many and "note 4" not in many
    assert low_risk_line("Drive", [], how="").startswith(
        "Or let me make small changes on Drive for 7 days without asking. I'll still ask"
    )


def test_waiting_cards_note_wording() -> None:
    assert waiting_cards_note(0, pending_hint="send pending") == ""
    assert waiting_cards_note(1, pending_hint="send pending") == (
        "\n\nOne request is still waiting for your OK (send pending to see it). "
        "If you approve it, I'll do just that one thing and the task stays stopped."
    )
    assert waiting_cards_note(3, pending_hint="send pending") == (
        "\n\n3 requests are still waiting for your OK (send pending to see them). "
        "If you approve one, I'll do just that one thing and the task stays stopped."
    )


def test_no_card_text_has_an_em_or_en_dash() -> None:
    args = {
        "to": ["a@b.com"],
        "body": "x\ny",
        "nested": {"k": [1, {"z": None}]},
        "blob": "q" * 9000,
    }
    outputs = [
        render_details(EMAIL, args),
        *(f"{label}: {value}" for label, value in detail_pairs(EMAIL, args)),
        check_code_line(args),
        ask_line(_in(3)),
        ask_line("bad"),
        decision_line(True, at=decided_at_text()),
        decision_line(False, at=decided_at_text()),
        turn_notes(
            {"pending_approvals": ["a.b", "c.d"], "blocked": ["e.f"]}, pending_hint="send pending"
        ),
        low_risk_line("Gmail", ["a", "b", "c", "d", "e"], how="Send grants."),
        waiting_cards_note(1, pending_hint="send pending"),
        waiting_cards_note(2, pending_hint="send pending"),
        cards.NOTHING_PENDING_TEXT,
    ]
    for max_chars in (500, 3900):
        card = layout_card(
            _head(), args, tool_name=EMAIL, max_chars=max_chars, max_parts=50, ask=ASK
        )
        outputs += _messages(card)
    outputs.append(
        layout_card(_head(), {"b": "B" * 100_000}, tool_name=TOOL, max_chars=3900).notice
    )
    for text in outputs:
        assert text is not None and _no_dashes(text), text[:200]


# ── Telegram approval card ─────────────────────────────────────────────

SEND_EMAIL = "google_workspace.send_email"


@pytest.fixture
def fake_api(monkeypatch):
    api = FakeTelegramAPI()
    real_client_cls = httpx.AsyncClient

    def _factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(api.handler)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return api


@pytest.fixture
def no_pacing(monkeypatch) -> None:
    monkeypatch.setattr(cards, "PART_INTERVAL_S", 0.0)
    monkeypatch.setattr(cards, "FAILED_PART_NOTICE_DELAY_S", 0.0)


def _stored_action(user_id: str, arguments: dict, action_id: str = "card-1"):
    from services.agent.approvals import StoredAction

    now = datetime.now(timezone.utc)
    return StoredAction(
        action_id=action_id,
        user_id=user_id,
        tool_name=SEND_EMAIL,
        arguments=arguments,
        reason="Sending email requires approval",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=15)).isoformat(),
    )


def _label(args: dict) -> str:
    return f"Request {_code8(args)}"


@pytest.mark.asyncio
async def test_telegram_short_card_is_one_message_with_the_check_code(session_factory, fake_api):
    user = await _link(session_factory, "tg-card-short@example.com", 901)
    service = _make_service(session_factory)
    args = {"to": "prof@example.com", "body": "hi"}
    await service.notify_pending(_stored_action(str(user.id), args))
    sent = fake_api.sent_messages()
    assert len(sent) == 1
    text = sent[0]["text"]
    assert "To: prof@example.com\nMessage: hi" in text
    assert '"to"' not in text and "Arguments" not in text
    assert check_code_line(args) in text
    assert sent[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"] == "apv:card-1"
    await service._client.aclose()


@pytest.mark.asyncio
async def test_telegram_long_card_is_never_truncated(session_factory, fake_api, no_pacing):
    user = await _link(session_factory, "tg-card-long@example.com", 902)
    service = _make_service(session_factory)
    body = "".join(f"line {i:05d} of the email body \U0001f600\n" for i in range(400))
    args = {"to": "prof@example.com", "body": body, "tail_marker": "END-OF-ARGS"}
    await service.notify_pending(_stored_action(str(user.id), args))

    sent = fake_api.sent_messages()
    assert len(sent) > 2
    assert all(m["chat_id"] == 902 for m in sent)
    assert all(utf16_len(m["text"]) <= 4096 for m in sent)
    # Only the last message carries the buttons; it names the request it
    # closes and carries the check code.
    assert [("reply_markup" in m) for m in sent] == [False] * (len(sent) - 1) + [True]
    last = sent[-1]["text"]
    assert f"That's all of request {_code8(args)} (part {len(sent)} of {len(sent)})." in last
    assert check_code_line(args) in last
    # Every details part is labelled, and together they carry every body
    # line, whole and indented under its label, with nothing cut.
    content = []
    for index, message in enumerate(sent[:-1], start=1):
        header, _, rest = message["text"].partition("\n")
        assert header == f"{_label(args)}, part {index} of {len(sent)}"
        marker = _MARKER.search(rest)
        content.append(rest[: marker.start()] if marker else rest)
    joined = "".join(content)
    assert joined == render_details(SEND_EMAIL, args)
    for line in body.splitlines():
        assert f"\n{DETAIL_INDENT}{line}\n" in joined
    assert joined.endswith("Tail marker: END-OF-ARGS")
    assert "…" not in joined
    await service._client.aclose()


@pytest.mark.asyncio
async def test_telegram_card_sends_no_buttons_and_says_so_when_a_part_is_lost(
    session_factory, fake_api, monkeypatch, no_pacing
):
    user = await _link(session_factory, "tg-card-lost@example.com", 903)
    original = fake_api.handler

    def failing(request: httpx.Request) -> httpx.Response:
        response = original(request)
        if len(fake_api.sent_messages()) == 1:  # the first card part is lost
            return httpx.Response(200, json={"ok": False, "error_code": 429, "description": "slow"})
        return response

    # The service's client is built with the handler looked up now.
    monkeypatch.setattr(fake_api, "handler", failing)
    service = _make_service(session_factory)
    args = {"body": "B" * 9_000}
    await service.notify_pending(_stored_action(str(user.id), args))  # never raises
    sent = fake_api.sent_messages()
    assert len(sent) == 2  # the lost first part, then the notice
    assert all("reply_markup" not in m for m in sent)
    notice = sent[1]["text"]
    assert re.match(rf"Part 1 of \d+ of request {_code8(args)} didn't come through", notice)
    assert "left the buttons off" in notice and "/pending" in notice
    await service._client.aclose()


@pytest.mark.asyncio
async def test_telegram_oversized_card_is_one_notice_without_buttons(
    session_factory, fake_api, no_pacing
):
    user = await _link(session_factory, "tg-card-huge@example.com", 904)
    service = _make_service(session_factory)
    args = {"path": "notes.txt", "content": "B" * 100_000}
    await service.notify_pending(_stored_action(str(user.id), args))
    sent = fake_api.sent_messages()
    assert len(sent) == 1
    assert "reply_markup" not in sent[0]
    text = sent[0]["text"]
    assert text.startswith(f"{_label(args)} is too long to show here")
    assert "web app" in text
    assert "BBBB" not in text
    # The chat is not left locked: the next card goes out with its buttons.
    await service.notify_pending(_stored_action(str(user.id), {"q": "ok"}, "card-2"))
    after = fake_api.sent_messages()
    assert len(after) == 2
    assert after[1]["reply_markup"]["inline_keyboard"][0][0]["callback_data"] == "apv:card-2"
    await service._client.aclose()


@pytest.mark.asyncio
async def test_telegram_concurrent_cards_never_interleave_their_parts(
    session_factory, fake_api, no_pacing
):
    user = await _link(session_factory, "tg-card-race@example.com", 905)
    service = _make_service(session_factory)
    args_a = {"body": "A" * 9_000}
    args_b = {"body": "b" * 9_000}
    await asyncio.gather(
        service.notify_pending(_stored_action(str(user.id), args_a, "card-a")),
        service.notify_pending(_stored_action(str(user.id), args_b, "card-b")),
    )
    sent = fake_api.sent_messages()
    codes = {"card-a": _code8(args_a), "card-b": _code8(args_b)}
    # Every message names exactly one request.
    assert all(sum(code in m["text"] for code in codes.values()) == 1 for m in sent)
    owner = [next(a for a, code in codes.items() if code in m["text"]) for m in sent]
    is_button = ["reply_markup" in m for m in sent]
    # Each card's details parts form one unbroken run, in order.
    part_owners = [o for o, button in zip(owner, is_button, strict=True) if not button]
    runs = [o for i, o in enumerate(part_owners) if i == 0 or part_owners[i - 1] != o]
    assert sorted(runs) == ["card-a", "card-b"]
    for action_id, code in codes.items():
        own = [
            m["text"]
            for o, m, b in zip(owner, sent, is_button, strict=True)
            if o == action_id and not b
        ]
        assert len(own) >= 2
        assert all(
            t.startswith(f"Request {code}, part {i} of ") for i, t in enumerate(own, start=1)
        )
    # Each button message names its own request, approves that card only,
    # and comes after that card's parts.
    buttons = [i for i, button in enumerate(is_button) if button]
    assert sorted(owner[i] for i in buttons) == ["card-a", "card-b"]
    args_of = {"card-a": args_a, "card-b": args_b}
    for index in buttons:
        action_id = owner[index]
        keyboard = sent[index]["reply_markup"]["inline_keyboard"][0]
        assert keyboard[0]["callback_data"] == f"apv:{action_id}"
        assert check_code_line(args_of[action_id]) in sent[index]["text"]
        last_part = max(i for i, o in enumerate(owner) if o == action_id and not is_button[i])
        assert index > last_part
    await service._client.aclose()


def test_telegram_card_locks_are_per_chat_and_go_away_with_the_service():
    import gc

    from services.notifications import telegram

    service = telegram.TelegramService.__new__(telegram.TelegramService)
    other = telegram.TelegramService.__new__(telegram.TelegramService)
    lock = telegram._card_lock(service, 1)
    assert telegram._card_lock(service, 1) is lock
    assert telegram._card_lock(service, 2) is not lock
    assert telegram._card_lock(other, 1) is not lock

    # A service another test dropped can still be waiting for the cycle
    # collector (its command and button tables hold handlers bound to it),
    # so count only the live ones.
    gc.collect()
    held = len(telegram._CARD_LOCKS)
    del service
    gc.collect()
    assert len(telegram._CARD_LOCKS) == held - 1
