"""Tests for showing the assistant's Markdown formatted on Telegram
(services/notifications/telegram_format.py and its use in telegram.py,
automation/delivery.py and the trigger runs): bold, italic, strikethrough,
code, fences, headings, lists, quotes and tables become the few tags
Telegram's HTML takes; markup the model wrote is escaped and shown; a link
shows its address and no <a> is ever made; identifiers and URLs with
underscores stay as written; unbalanced markers stay literal; long replies
split into parts that each fit Telegram, a code block closed and reopened
across them; hostile input renders in linear time. At the choke point
(_api) only flagged text is formatted, the private flag never leaves, a
400 for the formatting resends the masked plain text once, a 429 is never
retried, and a secret that only appears once the Markdown is read goes as
masked plain text. App text (/help, /kb, approval cards, voice echo,
progress lines, command replies, the turn's notes) is sent as written.

Why it exists: formatting is a second reading of untrusted text before it
leaves for Telegram's servers; it must never hide a link's target, never
reveal a masked value, and never lose a reply to a parse error. Fake HTTP
transports and fake senders only: no network.
"""

from __future__ import annotations

import json
import re
import time
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, Callable, Optional

import httpx
import pytest
import pytest_asyncio
import structlog
from structlog.testing import capture_logs

from services.automation.delivery import compose
from services.automation.runner import UnattendedOutcome
from services.notifications.cards import utf16_len
from services.notifications.telegram_format import (
    TelegramMarkdown,
    adds_links,
    close_fence,
    render_html,
    split_markdown,
    visible_text,
)

CHAT = 7301
CARD = "4111 1111 1111 1111"
TOKEN = "ghp_" + "FAKE" * 9
ALLOWED_TAGS = {"b", "i", "s", "code", "pre", "blockquote"}
_TAG_RE = re.compile(r'<(/?)([a-z-]+)(?: class="language-[a-z0-9+#-]{1,20}")?>')
_FAST_S = 1.0


def assert_well_formed(html: str) -> None:
    """Only the allowed tags, every one closed in order, and no other < or >."""
    stack: list[str] = []
    for match in _TAG_RE.finditer(html):
        closing, name = match.group(1), match.group(2)
        assert name in ALLOWED_TAGS, html
        if closing:
            assert stack and stack[-1] == name, html
            stack.pop()
        else:
            stack.append(name)
    assert stack == [], html
    rest = _TAG_RE.sub("", html)
    assert "<" not in rest and ">" not in rest, html


def shown(markdown: str) -> str:
    html = render_html(markdown)
    assert_well_formed(html)
    return visible_text(html)


# ── rendering ────────────────────────────────────────────────────────────


def test_bold_italic_strikethrough_and_code_become_tags():
    html = render_html("**Bold**, *italic*, _also_, ~~gone~~ and `x < y`")
    assert html == (
        "<b>Bold</b>, <i>italic</i>, <i>also</i>, <s>gone</s> and <code>x &lt; y</code>"
    )


def test_nested_bold_and_italic_are_balanced():
    html = render_html("**bold _both_ end** and _one **two** three_")
    assert_well_formed(html)
    assert "<b><i>both</i></b>" in html and "<b><i>two</i></b>" in html
    assert visible_text(html) == "bold both end and one two three"


def test_code_carries_no_other_formatting():
    # Telegram does not nest code inside bold, so the code wins.
    assert render_html("**`run`**") == "<code>run</code>"
    assert render_html("# The `main` loop") == "<b>The </b><code>main</code><b> loop</b>"


def test_a_fence_keeps_its_language_and_its_content_is_never_parsed():
    html = render_html("Run:\n```python\nprint('<b>' & **x**)\n```\nDone.")
    assert html == (
        "Run:\n"
        '<pre><code class="language-python">print(\'&lt;b&gt;\' &amp; **x**)</code></pre>\n'
        "Done."
    )
    assert render_html("~~~\nplain _text_\n~~~") == "<pre>plain _text_</pre>"
    # A language Telegram's class could not carry is dropped, not passed on.
    assert render_html('```"><a href=x>\ncode\n```') == "<pre>code</pre>"
    assert render_html("```Objective-C\ncode\n```") == (
        '<pre><code class="language-objective-c">code</code></pre>'
    )


def test_an_unclosed_fence_runs_to_the_end():
    assert render_html("Look:\n```js\nlet a = 1;\nlet b = 2;") == (
        'Look:\n<pre><code class="language-js">let a = 1;\nlet b = 2;</code></pre>'
    )
    # Three backticks inside a line are not a fence.
    assert "<pre>" not in render_html("Use ```x``` here")


def test_headings_lists_quotes_and_rules():
    markdown = "\n".join(
        [
            "# Plan",
            "## Steps ##",
            "- one",
            "  * nested",
            "+ three",
            "1. first",
            "2) second",
            "- [ ] open",
            "- [x] done",
            "---",
            "> quoted **here**",
            "> and on",
            "",
            "#hashtag stays",
        ]
    )
    assert render_html(markdown) == "\n".join(
        [
            "<b>Plan</b>",
            "<b>Steps</b>",
            "• one",
            "  • nested",
            "• three",
            "1. first",
            "2) second",
            "☐ open",
            "☑ done",
            "",
            "<blockquote>quoted <b>here</b>\nand on</blockquote>",
            "",
            "#hashtag stays",
        ]
    )


def test_a_table_shows_its_header_in_bold_and_drops_the_rule_row():
    markdown = "| Course | Due |\n|---|:--:|\n| CS101 | **Fri** |\n| MA200 | Mon |\n\nAfter."
    assert render_html(markdown) == (
        "<b>Course</b>  ·  <b>Due</b>\nCS101  ·  <b>Fri</b>\nMA200  ·  Mon\n\nAfter."
    )
    # A tight table keeps a separator that is no longer than its source.
    assert shown("a|b\n-|-\nc|d") == "a·b\nc·d"


def test_markup_the_model_wrote_is_escaped_and_shown():
    markdown = (
        '<a href="https://evil.example/x">Click</a> <tg-spoiler>secret</tg-spoiler> '
        "<b>bold?</b> & &amp; <blockquote>"
    )
    html = render_html(markdown)
    assert "<a" not in html and "<tg-spoiler" not in html and "<b>" not in html
    assert html == (
        '&lt;a href="https://evil.example/x"&gt;Click&lt;/a&gt; '
        "&lt;tg-spoiler&gt;secret&lt;/tg-spoiler&gt; &lt;b&gt;bold?&lt;/b&gt; "
        "&amp; &amp;amp; &lt;blockquote&gt;"
    )
    assert visible_text(html) == markdown


def test_quotes_are_never_escaped():
    assert render_html("He said \"hi\" and 'bye'") == "He said \"hi\" and 'bye'"


@pytest.mark.parametrize(
    ("markdown", "expected"),
    [
        ("See [the docs](https://docs.example.com/a_b)", "See the docs (https://docs.example.com/a_b)"),
        ("[https://a.example](https://a.example)", "https://a.example"),
        ("**[bold link](https://a.example)** after", "<b>bold link</b> (https://a.example) after"),
        ("[x](javascript:alert(1))", "[x](javascript:alert(1))"),
    ],
)
def test_a_link_shows_its_address(markdown, expected):
    assert render_html(markdown) == expected


def test_no_a_tag_is_ever_made():
    samples = [
        "[a](https://x.example) [b](http://y.example)",
        '<a href="https://x.example">x</a>',
        "[[nested](https://x.example)](https://y.example)",
        "[a](https://x.example/(paren)) and [b](<https://x.example>)",
    ]
    for markdown in samples:
        html = render_html(markdown)
        assert "<a" not in html
        assert_well_formed(html)


@pytest.mark.parametrize(
    "text",
    [
        "Waiting on google_workspace.send_email and notion_api.create_page",
        "snake_case_name, __init__, _private_var and CONSTANT_NAME",
        "https://example.com/a_b_c/_d_/e*f*~g~ and http://x.example/__x__",
        "2 * 3 * 4 = 24 and a*b*c",
        "Price: $5 & up",
    ],
)
def test_identifiers_and_urls_stay_as_written(text):
    assert render_html(text).replace("&amp;", "&") == text
    assert shown(text) == text


def test_bold_around_a_url_still_works():
    assert render_html("**https://example.com**") == "<b>https://example.com</b>"


@pytest.mark.parametrize(
    "text",
    ["**not closed", "_open and never shut", "`one tick", "~~half", "[label](", "* not a list*"],
)
def test_unbalanced_markers_stay_literal(text):
    html = render_html(text)
    assert_well_formed(html)
    assert visible_text(html).lstrip("• ") in (text, text.lstrip("* "))


def test_visible_text_is_never_longer_than_the_markdown():
    samples = [
        "| a | b |\n|---|---|\n| c | d |",
        "a|b|c\n-|-|-\nd|e|f",
        "[x](https://x.example) **y** _z_ `w`",
        "# H\n> q\n- l\n1. n\n```py\ncode\n```",
        "\U0001f600 **\U0001f600** [\U0001f600](https://x.example)",
    ]
    for markdown in samples:
        assert utf16_len(shown(markdown)) <= utf16_len(markdown)


# ── splitting ────────────────────────────────────────────────────────────


def test_short_text_is_one_part_and_empty_text_none():
    assert split_markdown("Hello **you**", 100) == ["Hello **you**"]
    assert split_markdown("", 100) == [] and split_markdown("\n\n", 100) == []
    with pytest.raises(ValueError):
        split_markdown("x", 10)


def test_a_split_prefers_a_blank_line_then_a_line_end():
    first = "\n".join(f"first {i}" for i in range(8))
    second = "\n".join(f"second {i}" for i in range(8))
    parts = split_markdown(first + "\n\n" + second, 120)
    assert parts == [first, second]
    lines = "\n".join(f"line number {i}" for i in range(30))
    for part in split_markdown(lines, 100):
        assert utf16_len(part) <= 100
        assert all(line.startswith("line number ") for line in part.split("\n"))


def test_a_fence_split_across_parts_is_closed_and_reopened():
    code = "\n".join(f"value_{i} = {i}  # <keep>" for i in range(40))
    markdown = "Intro.\n\n```python\n" + code + "\n```\n\nOutro."
    parts = split_markdown(markdown, 300)
    assert len(parts) > 2
    for index, part in enumerate(parts):
        assert utf16_len(part) <= 300
        if 0 < index < len(parts) - 1:
            assert part.startswith("```python\n") and part.endswith("\n```")
        html = render_html(part)
        assert_well_formed(html)
        assert "**" not in visible_text(html)
    rendered = [render_html(part) for part in parts]
    assert all('<code class="language-python">' in html for html in rendered[1:-1])
    # Nothing lost: every code line arrives once.
    shown_lines = "\n".join(visible_text(html) for html in rendered).split("\n")
    for i in range(40):
        assert shown_lines.count(f"value_{i} = {i}  # <keep>") == 1


def test_a_part_never_ends_on_the_line_that_opens_a_fence():
    markdown = "a" * 50 + "\n" + "b" * 40 + "\n```\n" + "c" * 30 + "\n```"
    assert split_markdown(markdown, 100) == ["a" * 50 + "\n" + "b" * 40, "```\n" + "c" * 30 + "\n```"]


def test_every_part_fits_telegram_even_with_emoji():
    line = "\U0001f600 **done** \U0001f389 " * 40
    markdown = "\n".join([line] * 30) + "\n" + "\U0001f680" * 5000
    parts = split_markdown(markdown, 3900)
    assert len(parts) > 3
    for part in parts:
        assert utf16_len(part) <= 3900
        assert utf16_len(visible_text(render_html(part))) <= 4096
    # No character is cut in half, and none is lost.
    assert sum(part.count("\U0001f680") for part in parts) == 5000


def test_close_fence_closes_only_an_open_block():
    assert close_fence("```\ncode") == "```\ncode\n```"
    assert close_fence("~~~~py\ncode\n") == "~~~~py\ncode\n~~~~"
    assert close_fence("```\ncode\n```") == "```\ncode\n```"
    assert close_fence("no code") == "no code"


_HOSTILE = {
    "unclosed italics": "_a " * 30000,
    "stars": "**" * 50000,
    "brackets": "[" * 50000,
    "backticks": "`" * 50000,
    "mixed lines": ("*_~`[" * 600 + "\n") * 33,
    "nested lines": ("**_~~`" * 500 + "\n") * 33,
    "italic lines": ("_a " * 1000 + "\n") * 33,
    "bracket lines": ("[" * 3000 + "\n") * 33,
    "link openers": ("[a](https://x.example/" * 170 + "\n") * 35,
    "closed spans": ("**a** _b_ `c` ~~d~~ [e](https://x.example) " * 80 + "\n") * 33,
    "pipes": ("| a " * 10 + "|\n|---|\n") * 3000,
    "fences": "```\n" * 25000,
    "trailing spaces": "# a" + " " * 100000 + "b",
}


@pytest.mark.parametrize("markdown", _HOSTILE.values(), ids=_HOSTILE.keys())
def test_hostile_markdown_renders_and_splits_in_linear_time(markdown):
    started = time.perf_counter()
    html = render_html(markdown)
    assert time.perf_counter() - started < _FAST_S
    assert "<a" not in html
    started = time.perf_counter()
    parts = split_markdown(markdown, 3900)
    assert time.perf_counter() - started < _FAST_S
    assert all(utf16_len(part) <= 3900 for part in parts)


def test_telegram_markdown_fails_safe_to_a_plain_str():
    marked = TelegramMarkdown("**hi** there")
    assert isinstance(marked, str) and marked == "**hi** there"
    for derived in (marked[:4], marked + "!", marked.strip(), f"{marked}", str(marked)):
        assert type(derived) is str


# ── the choke point (_api) ───────────────────────────────────────────────


class Bot:
    """The Bot API behind a MockTransport: records each request's method and
    JSON body and answers with *answer(body)* (ok by default)."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.answer: Optional[Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]] = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        body = json.loads(request.content or b"{}")
        self.requests.append((method, body))
        if self.answer is not None:
            status, data = self.answer(body)
            return httpx.Response(status, json=data)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    def sends(self) -> list[dict[str, Any]]:
        return [body for method, body in self.requests if method == "sendMessage"]


@pytest.fixture
def telegram(monkeypatch):
    from services.notifications.telegram import TelegramService

    bot = Bot()
    real = httpx.AsyncClient

    def factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(bot.handler)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    service = TelegramService(token="123:fake-token", session_factory=lambda: None)

    async def linked(_user_id: str) -> int:
        return CHAT

    monkeypatch.setattr(service, "linked_chat_id", linked)
    return service, bot


def _shown_of(body: dict[str, Any]) -> str:
    return visible_text(body["text"]) if body.get("parse_mode") == "HTML" else body["text"]


@pytest.mark.asyncio
async def test_the_markdown_flag_sends_html_and_never_the_private_keys(telegram):
    service, bot = telegram
    result = await service._api(
        "sendMessage", chat_id=CHAT, text="**Done** & <ok>", _markdown=True, _plain_tail="\n\n<1 & 2>"
    )
    assert result == {"message_id": 1}
    [body] = bot.sends()
    assert body == {
        "chat_id": CHAT,
        "text": "<b>Done</b> &amp; &lt;ok&gt;\n\n&lt;1 &amp; 2&gt;",
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": True},
    }
    await service._client.aclose()


@pytest.mark.asyncio
async def test_unflagged_text_goes_exactly_as_before(telegram):
    service, bot = telegram
    await service._api("sendMessage", chat_id=CHAT, text="**raw** <b> & _x_")
    assert bot.sends() == [
        {"chat_id": CHAT, "text": "**raw** <b> & _x_", "link_preview_options": {"is_disabled": True}}
    ]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_masking_runs_before_formatting(telegram):
    service, bot = telegram
    await service._api("sendMessage", chat_id=CHAT, text=f"**Key:** {TOKEN}", _markdown=True)
    [body] = bot.sends()
    assert body["parse_mode"] == "HTML"
    assert body["text"] == "<b>Key:</b> [hidden: GitHub token]"
    await service._client.aclose()


@contextmanager
def fresh_logs(monkeypatch):
    """structlog capture that sees the Telegram service's warnings in a full run.

    The app sets cache_logger_on_first_use, so a module logger an earlier test
    used after configure_logging() keeps its old processors and bypasses the
    capture; bind a fresh one inside it (as tests/test_telegram_decisions.py does).
    """
    from services.notifications import telegram as telegram_module

    with capture_logs() as logs:
        monkeypatch.setattr(telegram_module, "logger", structlog.get_logger(telegram_module.__name__))
        yield logs


@pytest.mark.asyncio
async def test_a_rejected_format_resends_the_masked_plain_text_once(telegram, monkeypatch):
    service, bot = telegram

    def answer(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if body.get("parse_mode"):
            return 400, {
                "ok": False,
                "error_code": 400,
                "description": "Bad Request: can't parse entities: Unsupported start tag",
            }
        return 200, {"ok": True, "result": {"message_id": 2}}

    bot.answer = answer
    with fresh_logs(monkeypatch) as logs:
        result = await service._api(
            "sendMessage", chat_id=CHAT, text=f"**Card** {CARD}", _markdown=True, _plain_tail="\n\nnote"
        )
    assert result == {"message_id": 2}
    first, second = bot.sends()
    assert first["parse_mode"] == "HTML"
    assert "parse_mode" not in second
    assert second["text"] == "**Card** [hidden: card number]\n\nnote"
    assert [entry["event"] for entry in logs if entry["event"] == "telegram_html_rejected"] == [
        "telegram_html_rejected"
    ]
    await service._client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "description"),
    [(429, "Too Many Requests: retry after 5"), (500, "Internal Server Error")],
)
async def test_a_rate_limit_or_server_error_is_never_retried(telegram, status, description):
    service, bot = telegram
    bot.answer = lambda body: (status, {"ok": False, "error_code": status, "description": description})
    result = await service._api("sendMessage", chat_id=CHAT, text="**hi**", _markdown=True)
    assert result is None
    assert len(bot.sends()) == 1
    await service._client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "markdown",
    ["Card: 4111 **1111** 1111 1111", "Card: `4111` `1111` `1111` `1111`", "Card: 4111 _1111_ 1111 1111"],
)
async def test_a_secret_split_by_markers_goes_as_masked_plain_text(telegram, markdown, monkeypatch):
    service, bot = telegram
    with fresh_logs(monkeypatch) as logs:
        await service._api("sendMessage", chat_id=CHAT, text=markdown, _markdown=True, _plain_tail="\n\nnote")
    [body] = bot.sends()
    assert "parse_mode" not in body
    assert body["text"] == "Card: [hidden: card number]\n\nnote"
    assert "1111" not in body["text"]
    assert any(entry.get("reason") == "masked_value" for entry in logs)
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_split_secret_never_lets_a_split_address_through_either(telegram):
    service, bot = telegram
    markdown = "Card 4111 **1111** 1111 1111 at htt**ps://evil.example/pay** or https://ok.example/a"
    await service._api("sendMessage", chat_id=CHAT, text=markdown, _markdown=True)
    [body] = bot.sends()
    assert "parse_mode" not in body and "1111" not in body["text"]
    assert "https://evil.example" not in body["text"] and "evil" in body["text"]
    assert body["text"].endswith(" or https://ok.example/a")
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_value_only_the_formatting_joins_is_counted_in_the_footer(telegram):
    service, bot = telegram
    await service._send_reply(CHAT, f"Card 4111 **1111** 1111 1111, token {TOKEN}", {})
    [body] = bot.sends()
    assert "parse_mode" not in body
    assert body["text"].startswith("Card [hidden: card number], token [hidden: GitHub token]\n\n")
    assert "Crawler hid 2 values" in body["text"]
    await service._client.aclose()


def test_adds_links_spots_an_address_only_the_formatting_makes():
    for markdown in (
        "htt**ps://evil.example/x**",
        "w**ww.**evil.example",
        "https://evil`.`example",
        "htt**ps://evil.example**.",
        "htt**ps://evil.example**, then",
        # An underscore keeps the address going, so an allowed prefix
        # (mail.google.com) cannot hide the new host after it.
        "Open https://mail.google.com/mail/u/0 then h**ttps://mail.google.com_x.evil.com/login**",
    ):
        assert adds_links(markdown, shown(markdown)), markdown
    for markdown in (
        "**https://ok.example**",
        "[docs](https://ok.example/a_b?x=1&y=2)",
        "see https://ok.example/_a_/b",
        "no links at all",
    ):
        assert not adds_links(markdown, shown(markdown)), markdown


_PUNCTUATED_URLS = [
    "Open `http://localhost:3000`.",
    "The docs are at **https://docs.python.org/3/**.",
    "See [https://example.com](https://example.com).",
    "Use `https://api.example.com/v1`, then retry.",
    "Visit *www.example.com*!",
    "Try ~~https://old.example~~; it moved.",
    "Is it **https://ok.example/a**?",
]


@pytest.mark.parametrize("markdown", _PUNCTUATED_URLS)
def test_punctuation_after_a_formatted_address_is_not_a_new_link(markdown):
    assert not adds_links(markdown, shown(markdown))


@pytest.mark.asyncio
@pytest.mark.parametrize("markdown", _PUNCTUATED_URLS)
async def test_a_formatted_address_before_punctuation_is_sent_formatted(telegram, markdown, monkeypatch):
    service, bot = telegram
    with fresh_logs(monkeypatch) as logs:
        await service._api("sendMessage", chat_id=CHAT, text=markdown, _markdown=True)
    [body] = bot.sends()
    assert body["parse_mode"] == "HTML"
    assert not any(entry["event"] == "telegram_markdown_withheld" for entry in logs)
    await service._client.aclose()


@pytest.mark.asyncio
async def test_an_address_split_by_markers_goes_as_plain_text(telegram, monkeypatch):
    service, bot = telegram
    with fresh_logs(monkeypatch) as logs:
        await service._api("sendMessage", chat_id=CHAT, text="Open htt**ps://evil.example/x**", _markdown=True)
    [body] = bot.sends()
    assert "parse_mode" not in body and body["text"] == "Open htt**ps://evil.example/x**"
    assert any(entry.get("reason") == "new_link" for entry in logs)
    await service._client.aclose()


@pytest.mark.asyncio
async def test_text_that_shows_nothing_formatted_goes_plain(telegram):
    service, bot = telegram
    await service._api("sendMessage", chat_id=CHAT, text="---", _markdown=True)
    [body] = bot.sends()
    assert body["text"] == "---" and "parse_mode" not in body
    await service._client.aclose()


# ── replies ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_reply_is_formatted_and_its_notes_stay_exact(telegram):
    service, bot = telegram

    async def chat(user_id: str, text: str, new_conversation: bool = False) -> dict[str, Any]:
        return {
            "content": "**Drafted** the email & saved it.",
            "pending_approvals": ["google_workspace.send_email"],
            "blocked": ["shell_exec"],
            "usage": {"input_tokens": 1200, "output_tokens": 300},
        }

    service.chat = chat
    await service._handle_chat(CHAT, "user-1", "draft it")
    await service.wait_for_chats()
    reply = bot.sends()[-1]
    assert reply["parse_mode"] == "HTML"
    assert reply["text"].startswith("<b>Drafted</b> the email &amp; saved it.\n\n")
    text = visible_text(reply["text"])
    assert "\U0001f510 Waiting on your approval for: google_workspace.send_email. " in text
    assert "Blocked by security policy: shell_exec" in text
    assert "tokens" in text.splitlines()[-1]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_every_part_of_a_long_reply_fits_and_the_usage_line_comes_last(telegram):
    service, bot = telegram
    content = "\n".join(f"\U0001f600 **item {i}** \U0001f389 " + "\U0001f680" * 60 for i in range(120))
    outcome = {"usage": {"input_tokens": 10, "output_tokens": 5}}
    await service._send_reply(CHAT, content, outcome, "\n\n\U0001f510 Waiting on your approval for: x.y.")
    sends = bot.sends()
    assert len(sends) > 3
    for body in sends:
        assert body["parse_mode"] == "HTML"
        assert utf16_len(_shown_of(body)) <= 4096
    last = _shown_of(sends[-1])
    assert "Waiting on your approval for: x.y." in last
    assert "tokens" in last.splitlines()[-1]
    assert sum(_shown_of(body).count("\U0001f680") for body in sends) == 120 * 60
    await service._client.aclose()


@pytest.mark.asyncio
async def test_notes_too_long_for_the_last_part_follow_on_their_own(telegram):
    service, bot = telegram
    notes = "\n\n\U0001f510 Waiting on your approval for: " + ", ".join(f"tool_{i}.run" for i in range(40))
    await service._send_reply(CHAT, "x" * 3890, {}, notes)
    first, second = bot.sends()
    assert first["parse_mode"] == "HTML" and first["text"] == "x" * 3890
    assert "parse_mode" not in second and second["text"] == notes.lstrip("\n")
    await service._client.aclose()


# ── app text stays plain ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_help_kb_usage_and_command_replies_are_sent_as_written(telegram):
    from services.knowledge import channels as knowledge_channels
    from services.notifications.telegram import HELP_LINES

    service, bot = telegram
    await service._handle_help(CHAT)
    await service._commands["/kb"](CHAT, "user-1", "")
    await service._handle_new(CHAT)
    help_text, usage, fresh = bot.sends()
    for body in (help_text, usage, fresh):
        assert "parse_mode" not in body
    assert "/kb <collection>" in help_text["text"]
    assert all(line in help_text["text"] for line in HELP_LINES if line)
    assert usage["text"] == knowledge_channels.USAGE
    assert fresh["text"].startswith("Fresh start")
    await service._client.aclose()


@pytest.mark.asyncio
async def test_an_approval_card_and_a_progress_line_are_sent_as_written(telegram):
    service, bot = telegram
    arguments = {"subject": "**Hi** <b>there</b> & _you_", "to": "prof.lee@uni.edu"}
    action = SimpleNamespace(
        action_id="act-1",
        user_id="user-1",
        tool_name="google_workspace.send_email",
        arguments=arguments,
        reason="Send an email",
        risk_note=None,
        expires_at="2099-01-01T00:00:00+00:00",
    )
    await service.notify_pending(action)
    progress = service._turn_progress(CHAT)
    await progress._send("Searching the web for **news** <now>")
    card, line = bot.sends()
    assert "parse_mode" not in card and "parse_mode" not in line
    assert "**Hi** <b>there</b> & _you_" in card["text"]
    assert "Tool: google_workspace.send_email" in card["text"]
    assert line["text"] == "Searching the web for **news** <now>"
    await service._client.aclose()


@pytest.fixture
def voice_bot(monkeypatch):
    """The voice tests' fake Bot API (getFile and the file download too)."""
    from tests.test_telegram_voice import FakeBot

    fake = FakeBot()
    real = httpx.AsyncClient

    def factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handler)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return fake


@pytest.mark.asyncio
async def test_a_voice_echo_is_sent_as_written_and_the_reply_formatted(session_factory, voice_bot):
    from tests.test_telegram import _link
    from tests.test_telegram_voice import FakeLocal, RecordingChat, voice_message
    from tests.test_telegram_voice import service as voice_service

    await _link(session_factory, "tg-format-voice@example.com", 3101)
    svc = voice_service(session_factory, RecordingChat(), local=FakeLocal("Is **CS101** <due> & _when_?"))
    await svc._handle_message(voice_message(3101))
    await svc.wait_for_chats()
    echo, reply = voice_bot.sends()[0], voice_bot.sends()[-1]
    assert "parse_mode" not in echo and "Is **CS101** <due> & _when_?" in echo["text"]
    assert reply["parse_mode"] == "HTML" and reply["text"].startswith("Two assignments are due.")
    await svc._client.aclose()


@pytest.mark.asyncio
async def test_send_text_of_a_plain_str_is_unchanged(telegram):
    service, bot = telegram
    assert await service.send_text("user-1", "Reminder: **pay** <rent> & _call_ mom")
    [body] = bot.sends()
    assert body == {
        "chat_id": CHAT,
        "text": "Reminder: **pay** <rent> & _call_ mom",
        "link_preview_options": {"is_disabled": True},
    }
    await service._client.aclose()


@pytest.mark.asyncio
async def test_send_text_of_markdown_is_formatted_and_sent_whole_in_parts(telegram):
    service, bot = telegram
    assert await service.send_text("user-1", TelegramMarkdown("**Weekly** digest & more"))
    long = TelegramMarkdown("\n".join(f"**row {i}** " + "\U0001f600" * 50 for i in range(200)))
    assert await service.send_text("user-1", long)
    short, *parts = bot.sends()
    assert short["parse_mode"] == "HTML" and short["text"] == "<b>Weekly</b> digest &amp; more"
    assert len(parts) > 1
    for body in parts:
        assert body["parse_mode"] == "HTML" and utf16_len(visible_text(body["text"])) <= 4096
    assert parts[0]["text"].startswith("<b>row 0</b> ")
    assert "row 199" in visible_text(parts[-1]["text"])
    assert sum(visible_text(body["text"]).count("\U0001f600") for body in parts) == 200 * 50
    await service._client.aclose()


@pytest.mark.asyncio
async def test_an_emoji_heavy_trigger_run_arrives_with_its_notes(telegram):
    from services.triggers.facts import run_text

    service, bot = telegram
    reply = "".join("Assignment update \U0001f4da" + "\U0001f525" * 20 + " details here.\n\n" for _ in range(46))
    text = run_text(
        "Canvas",
        reply,
        notes=["1 action is waiting for your approval (/pending)."],
        usage_line="1.2k tokens",
        allowed=(),
        web_title="Trigger: Canvas",
    )
    assert 3500 < utf16_len(text) <= 4096
    assert await service.send_text("user-1", TelegramMarkdown(text))
    [body] = bot.sends()
    assert body["parse_mode"] == "HTML"
    assert visible_text(body["text"]).endswith(
        "1 action is waiting for your approval (/pending).\n1.2k tokens"
    )
    await service._client.aclose()


@pytest.mark.asyncio
async def test_send_text_stops_at_the_first_part_telegram_refuses(telegram):
    service, bot = telegram
    bot.answer = lambda body: (400, {"ok": False, "error_code": 400, "description": "Bad Request: chat not found"})
    long = TelegramMarkdown("\n".join("row " + "\U0001f600" * 50 for _ in range(200)))
    assert not await service.send_text("user-1", long)
    assert len(bot.sends()) == 1
    await service._client.aclose()


# ── scheduled and trigger deliveries ─────────────────────────────────────


def _outcome(**fields: Any) -> UnattendedOutcome:
    base: dict[str, Any] = {"status": "ok", "reply": "**Two** items are due & one is late.\n- CS101\n- MA200"}
    base.update(fields)
    return UnattendedOutcome(**base)


@pytest.mark.asyncio
async def test_a_scheduled_result_is_formatted_on_telegram_and_plain_on_slack(telegram):
    service, bot = telegram
    telegram_parts = compose("Canvas summary", "Tue 08:00", _outcome(), "telegram")
    slack_parts = compose("Canvas summary", "Tue 08:00", _outcome(), "slack")
    assert all(isinstance(part, TelegramMarkdown) for part in telegram_parts)
    assert all(type(part) is str for part in slack_parts)
    assert slack_parts == [
        "\U0001f5d3 Canvas summary · Tue 08:00\n\n"
        "**Two** items are due & one is late.\n- CS101\n- MA200\n\n"
        'reply "schedules" to pause'
    ]
    for part in telegram_parts:
        assert await service.send_text("user-1", part)
    [body] = bot.sends()
    assert body["parse_mode"] == "HTML"
    assert body["text"] == (
        "\U0001f5d3 Canvas summary · Tue 08:00\n\n"
        "<b>Two</b> items are due &amp; one is late.\n• CS101\n• MA200\n\n"
        "/schedules to pause"
    )
    await service._client.aclose()


def test_a_scheduled_reply_that_leaves_a_fence_open_is_closed_before_the_notes():
    [part] = compose("Code", "Tue 08:00", _outcome(reply="```py\nx = 1", cards=1), "telegram")
    html = render_html(part)
    assert html.endswith("1 action is waiting for your approval (/pending).\n\n/schedules to pause")
    assert '<pre><code class="language-py">x = 1</code></pre>' in html


@pytest_asyncio.fixture
async def slack(monkeypatch):
    """A Slack channel whose chat.postMessage bodies are recorded."""
    from services.connectors.slack import SlackConnector
    from services.notifications import slack as slack_mod

    connector = SlackConnector.from_credentials({"bot_token": "xoxb-x", "app_token": "xapp-x"})
    channel = slack_mod.SlackChannel(
        connector_id="11111111-1111-1111-1111-111111111111",
        user_id="22222222-2222-2222-2222-222222222222",
        bot_token="xoxb-x",
        app_token="xapp-x",
        session_factory=lambda: None,
        connector=connector,
    )
    posted: list[dict[str, Any]] = []

    async def send_chat(method: str, body: dict[str, Any], action: str) -> dict[str, Any]:
        posted.append(body)
        return {"ok": True, "ts": "1.0"}

    async def dm() -> str:
        return "D0DM00001"

    channel._connector._send_chat = send_chat  # type: ignore[method-assign]
    channel._linked_dm = dm  # type: ignore[method-assign]
    monkeypatch.setattr(slack_mod.SlackChannel, "running", property(lambda self: True))
    yield channel, posted
    await channel._connector.close()


@pytest.mark.asyncio
async def test_slack_send_text_treats_telegram_markdown_as_its_plain_text(slack):
    channel, posted = slack
    text = "⚡ Prof mail\n**Office hours** moved to 3pm & <soon>."
    assert await channel.send_text(channel.user_id, TelegramMarkdown(text))
    assert await channel.send_text(channel.user_id, text)
    assert len(posted) == 2 and posted[0] == posted[1]


@pytest.mark.asyncio
async def test_slack_gets_a_trigger_run_with_the_fence_its_reply_left_open_closed(slack):
    from services.triggers.facts import run_text

    channel, posted = slack
    text = run_text(
        "Prof mail", "Here:\n```\ncode", notes=["note"], usage_line="1k tokens", allowed=(), web_title="x"
    )
    assert text == "⚡ Prof mail\nHere:\n```\ncode\n```\nnote\n1k tokens"
    assert await channel.send_text(channel.user_id, TelegramMarkdown(text))
    assert posted == [{"channel": "D0DM00001", "text": text}]


def test_a_trigger_run_closes_a_fence_its_cut_leaves_open():
    from services.triggers.facts import run_text

    reply = "Here:\n```\n" + "line\n" * 2000
    text = run_text(
        "Prof mail", reply, notes=["note"], usage_line="1k tokens", allowed=(), web_title="Trigger: Prof mail"
    )
    assert len(text) <= 3300
    body = text.split("\n", 1)[1]
    assert close_fence(body) == body
    html = render_html(text)
    assert html.endswith("note\n1k tokens")
    assert "The rest is in the web app" in html.split("</pre>")[-1]
