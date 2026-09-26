"""Tests for the approval-card helpers and the untruncated Telegram card:
arguments render in full, splitting never drops or rewrites content and
keeps every part within the limit (UTF-16 aware for Telegram), the digest
is stable and sensitive, and a long Telegram card goes out as labelled,
paced parts that never interleave with another card's, with the tool, the
digest and the buttons on the last one. An oversized card, or one with a
lost part, becomes a notice with no buttons.

Why it exists: an approval card that cuts its arguments, or whose buttons
sit under a message that does not say what they approve, lets the owner
approve something they cannot see (spec F3).

Connects to: services/notifications/cards.py and the approval card in
services/notifications/telegram.py, with the Bot API faked at the httpx
transport (FakeTelegramAPI from tests/test_telegram.py).
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from services.notifications import cards
from services.notifications.cards import (
    DIGEST_HEX_CHARS,
    MAX_CARD_PARTS,
    CardLayout,
    arguments_digest,
    card_argument_chunks,
    digest_line,
    layout_card,
    render_arguments,
    send_card_parts,
    split_text,
    utf16_len,
)
from tests.test_telegram import FakeTelegramAPI, _link, _make_service

# ── arguments_digest ───────────────────────────────────────────────────


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


def test_digest_line_format() -> None:
    args = {"q": "x"}
    assert digest_line(args) == f"Arguments digest: {arguments_digest(args)}"


# ── render_arguments / card_argument_chunks ─────────────────────────────


def test_render_is_full_pretty_json_with_unicode_kept() -> None:
    args = {"subject": "Café \U0001f600", "body": "x" * 5000}
    rendered = render_arguments(args)
    assert json.loads(rendered) == args
    assert "Café \U0001f600" in rendered
    assert "\n  " in rendered  # indented


@pytest.mark.parametrize("empty", [None, {}])
def test_no_arguments_give_no_rendering_and_no_chunks(empty) -> None:
    assert render_arguments(empty) == ""
    assert card_argument_chunks(empty, max_chars=100) == []


def test_small_arguments_are_a_single_chunk() -> None:
    args = {"q": "hello"}
    assert card_argument_chunks(args, max_chars=1000) == [render_arguments(args)]


@pytest.mark.parametrize("max_chars", [64, 100, 257, 3900])
def test_chunks_round_trip_and_stay_within_limit(max_chars: int) -> None:
    args = {
        "to": ["a@example.com", "b@example.com"],
        "body": "line one\nline two " * 200,
        "nested": {"items": [{"i": i, "text": "t" * (i * 7)} for i in range(40)]},
    }
    chunks = card_argument_chunks(args, max_chars=max_chars)
    assert "".join(chunks) == render_arguments(args)
    assert all(0 < len(c) <= max_chars for c in chunks)
    assert len(chunks) > 1


def test_chunks_break_on_line_boundaries_when_lines_fit() -> None:
    args = {f"k{i}": "v" * 30 for i in range(50)}
    chunks = card_argument_chunks(args, max_chars=200)
    # Every line is short, so every chunk but the last ends at a newline.
    assert all(c.endswith("\n") for c in chunks[:-1])


def test_huge_single_string_is_hard_split_without_loss() -> None:
    args = {"blob": "A" * 100_003}
    chunks = card_argument_chunks(args, max_chars=3900)
    assert "".join(chunks) == render_arguments(args)
    assert all(len(c) <= 3900 for c in chunks)
    assert len(chunks) <= len(render_arguments(args)) // 3900 + 3


def test_utf16_length_counts_astral_characters_twice() -> None:
    assert utf16_len("abc") == 3
    assert utf16_len("é") == 1
    assert utf16_len("\U0001f600") == 2
    assert utf16_len("a\U0001f600b") == 4


def test_utf16_chunks_fit_telegram_units_and_never_split_a_character() -> None:
    args = {"emoji": "\U0001f600" * 5000, "mixed": "a\U0001f389b" * 700}
    chunks = card_argument_chunks(args, max_chars=3900, length=utf16_len)
    assert "".join(chunks) == render_arguments(args)
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
_MARKER = re.compile(r"\n\[this part ends with (\d+) blank characters\]\Z")


def _head() -> list[str]:
    return ["Approval required", "", f"Tool: {TOOL}", "Why: merging needs approval"]


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


def test_short_card_is_one_message_ending_with_the_digest() -> None:
    args = {"repo": "o/r", "number": 7}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=3900)
    assert card.leading == () and card.notice is None and card.parts == 1
    assert list(card.final_lines[: len(_head())]) == _head()
    assert card.final_lines[-1] == digest_line(args)
    assert render_arguments(args) in "\n".join(card.final_lines)


def test_card_without_arguments_has_no_arguments_block() -> None:
    card = layout_card(_head(), {}, tool_name=TOOL, max_chars=3900)
    assert card.leading == ()
    assert "Arguments:" not in card.final_lines
    assert card.final_lines[-1] == digest_line({})


def test_long_card_parts_are_labelled_and_round_trip_exactly() -> None:
    args = {"body": "paragraph\n" * 300, "blob": "Z" * 2000}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=500, max_parts=50)
    assert len(card.leading) > 2
    assert all(len(m) <= 500 for m in _messages(card))
    assert all(_survives_channel_trimming(m) for m in _messages(card))
    # Exact: nothing dropped, nothing rewritten, not even blanks.
    assert _content_of(card) == "\n".join(["Arguments:", render_arguments(args)])
    # The button message repeats the head and names the card.
    assert list(card.final_lines[: len(_head())]) == _head()
    assert f"Part {card.parts} of {card.parts} of {card.label}." in card.final_lines[-2]
    assert card.final_lines[-1] == digest_line(args)


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
def test_button_message_always_names_the_tool_and_the_digest(args, max_chars, length) -> None:
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=max_chars, length=length)
    assert card.leading and card.notice is None
    final = "\n".join(card.final_lines)
    assert f"Tool: {TOOL}" in final
    assert card.final_lines[-1] == digest_line(args)
    assert card.label == f"Approval {arguments_digest(args)} (Tool: {TOOL})"
    assert f"Part {card.parts} of {card.parts} of {card.label}." in final
    assert all(length(m) <= max_chars for m in _messages(card))
    assert _content_of(card) == "\n".join(["Arguments:", render_arguments(args)])


def test_blank_runs_at_part_ends_are_kept_and_marked() -> None:
    args = {"a": " " * 9000, "b": "x"}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=3900)
    assert any(_MARKER.search(part) for part in card.leading)
    assert all(_survives_channel_trimming(m) for m in _messages(card))
    assert _content_of(card) == "\n".join(["Arguments:", render_arguments(args)])


def test_head_too_long_to_repeat_moves_into_the_first_part() -> None:
    head = ["Approval required", "", f"Tool: {TOOL}", "Why: " + "w" * 5000]
    args = {"q": "x"}
    card = layout_card(head, args, tool_name=TOOL, max_chars=3900)
    assert card.final_lines[0] == f"Tool: {TOOL}"
    assert card.final_lines[-1] == digest_line(args)
    assert _content_of(card) == "\n".join([*head, "", "Arguments:", render_arguments(args)])
    assert all(len(m) <= 3900 for m in _messages(card))


def test_card_over_the_part_cap_becomes_a_notice() -> None:
    args = {"blob": "B" * 100_000}
    card = layout_card(_head(), args, tool_name=TOOL, max_chars=3900)
    assert card.leading == () and card.final_lines == ()
    assert card.parts > MAX_CARD_PARTS
    assert card.notice is not None
    assert card.notice.startswith(card.label)
    assert f"{len(render_arguments(args))} characters" in card.notice
    assert "web app" in card.notice
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
        layout_card(_head(), {"a": "b" * 5000}, tool_name="t" * 3900, max_chars=3900)


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
    notice = chat.sent[2]
    assert notice.startswith(card.label)
    assert f"part 2 of {card.parts} was not delivered" in notice
    assert "no buttons" in notice and notice.endswith("Send /pending.")
    assert cards.FAILED_PART_NOTICE_DELAY_S in sleeps


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
    return f"Approval {arguments_digest(args)} (Tool: {SEND_EMAIL})"


@pytest.mark.asyncio
async def test_telegram_short_card_is_one_message_with_digest(session_factory, fake_api):
    user = await _link(session_factory, "tg-card-short@example.com", 901)
    service = _make_service(session_factory)
    args = {"to": "prof@example.com", "body": "hi"}
    await service.notify_pending(_stored_action(str(user.id), args))
    sent = fake_api.sent_messages()
    assert len(sent) == 1
    text = sent[0]["text"]
    assert '"to": "prof@example.com"' in text
    assert digest_line(args) in text
    assert text.rstrip().endswith("min.")
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
    # Only the last message carries the buttons; it names the tool and the
    # card, and ends with the digest and the expiry.
    assert [("reply_markup" in m) for m in sent] == [False] * (len(sent) - 1) + [True]
    last = sent[-1]["text"]
    assert f"Tool: {SEND_EMAIL}" in last
    assert f"Part {len(sent)} of {len(sent)} of {_label(args)}." in last
    assert digest_line(args) in last
    # Every argument part is labelled, and together they carry every body
    # line, JSON-escaped, with nothing cut.
    content = []
    for index, message in enumerate(sent[:-1], start=1):
        header, _, rest = message["text"].partition("\n")
        assert header == f"{_label(args)}, part {index} of {len(sent)}"
        marker = _MARKER.search(rest)
        content.append(rest[: marker.start()] if marker else rest)
    joined = "".join(content)
    assert joined == "\n".join(["Arguments:", render_arguments(args)])
    assert json.dumps(body, ensure_ascii=False)[1:-1] in joined
    assert "END-OF-ARGS" in joined
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
    assert notice.startswith(_label(args))
    assert "part 1 of" in notice and "was not delivered" in notice
    assert "/pending" in notice and "web app" in notice
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
    assert text.startswith(_label(args))
    assert "too long to show here" in text and "web app" in text
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
    labels = {"card-a": _label(args_a), "card-b": _label(args_b)}
    # Every message names exactly one card.
    assert all(sum(label in m["text"] for label in labels.values()) == 1 for m in sent)
    owner = [next(a for a, label in labels.items() if label in m["text"]) for m in sent]
    is_button = ["reply_markup" in m for m in sent]
    # Each card's argument parts form one unbroken run, in order.
    part_owners = [o for o, button in zip(owner, is_button, strict=True) if not button]
    runs = [o for i, o in enumerate(part_owners) if i == 0 or part_owners[i - 1] != o]
    assert sorted(runs) == ["card-a", "card-b"]
    for action_id, label in labels.items():
        own = [
            m["text"]
            for o, m, b in zip(owner, sent, is_button, strict=True)
            if o == action_id and not b
        ]
        assert len(own) >= 2
        assert all(t.startswith(f"{label}, part {i} of ") for i, t in enumerate(own, start=1))
    # Each button message names its own card, approves that card only, and
    # comes after that card's parts.
    buttons = [i for i, button in enumerate(is_button) if button]
    assert sorted(owner[i] for i in buttons) == ["card-a", "card-b"]
    for index in buttons:
        action_id = owner[index]
        keyboard = sent[index]["reply_markup"]["inline_keyboard"][0]
        assert keyboard[0]["callback_data"] == f"apv:{action_id}"
        assert f"Tool: {SEND_EMAIL}" in sent[index]["text"]
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

    held = len(telegram._CARD_LOCKS)
    del service
    gc.collect()
    assert len(telegram._CARD_LOCKS) == held - 1
