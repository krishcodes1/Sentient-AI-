"""Tests for the Markdown to Slack mrkdwn renderer and the message splitter
(services/notifications/slack_format.py): each conversion, escaping of &, <
and >, links that always show their target, the masking re-check on the
visible text, and splits that never cut an entity or leave a code block open.

Why it exists: the renderer writes markup into messages the model's words fill,
so what it may produce (and never produce) is pinned down here. Pure functions:
no channel, no network.
"""

from __future__ import annotations

import re
import time

import pytest

from services.notifications import slack_format
from services.notifications.slack_format import SlackMarkdown, render, render_reply, split
from services.security import redact as redact_module
from services.security.policies import CHANNEL_WITHHELD

TOKEN = "ghp_" + "FAKE" * 9


def mrkdwn(markdown: str) -> str:
    return render(markdown)[0]


# ── inline conversions ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("markdown", "expected"),
    [
        ("**bold**", "*bold*"),
        ("*italic*", "_italic_"),
        ("_italic_", "_italic_"),
        ("~~gone~~", "~gone~"),
        ("`code`", "`code`"),
        ("a **b** and *c* then ~~d~~.", "a *b* and _c_ then ~d~."),
        ("**a _b_ c**", "*a _b_ c*"),
        ("**Note:** read it", "*Note:* read it"),
        ("plain *x* stays one word", "plain _x_ stays one word"),
    ],
)
def test_inline_markdown_becomes_mrkdwn(markdown, expected):
    assert mrkdwn(markdown) == expected


def test_code_spans_keep_their_content_unconverted():
    assert mrkdwn("run `a**b**_c_` now") == "run `a**b**_c_` now"


def test_a_span_slack_would_not_read_keeps_its_text_without_markers():
    # Slack only reads a marker at a word boundary: "*bar*baz" would show
    # its asterisks, so the text goes out without them.
    assert mrkdwn("foo**bar**baz and **ok**.") == "foobarbaz and *ok*."


def test_a_kind_already_active_is_not_marked_twice():
    assert mrkdwn("# Big **bold** title") == "*Big bold title*"
    assert mrkdwn("_a *b* c_") == "_a b c_"


def test_plain_text_and_unmatched_markers_are_left_alone():
    assert mrkdwn("5 * 3 * 2 = 30, snake_case_name, ~/bin") == (
        "5 * 3 * 2 = 30, snake_case_name, ~/bin"
    )


# ── links ────────────────────────────────────────────────────────────────


def test_a_link_shows_its_label_then_its_target():
    assert mrkdwn("See [the docs](https://example.com/a) now") == (
        "See the docs (https://example.com/a) now"
    )


def test_a_link_labelled_with_its_own_url_shows_it_once():
    assert mrkdwn("[https://example.com](https://example.com)") == "https://example.com"


def test_a_formatted_link_label_keeps_its_formatting():
    assert mrkdwn("**[docs](https://example.com)**") == "*docs (https://example.com)*"


def test_no_link_ever_hides_its_target_behind_a_label():
    out = mrkdwn(
        "[click](https://evil.test/x) <https://evil.test|safe> [a](https://b.test?x=1&y=2)"
    )
    assert "<" not in out and ">" not in out and "|safe&gt;" in out
    assert "click (https://evil.test/x)" in out
    assert "a (https://b.test?x=1&amp;y=2)" in out


def test_only_http_links_are_links():
    assert mrkdwn("[x](javascript:alert(1))") == "[x](javascript:alert(1))"


# ── blocks ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("markdown", "expected"),
    [
        ("# Title", "*Title*"),
        ("### Plan for *today*", "*Plan for _today_*"),
        ("## Learn C#", "*Learn C#*"),
        ("## Closed ##", "*Closed*"),
        ("#hashtag", "#hashtag"),
        ("#", "#"),
    ],
)
def test_headings_become_bold_lines(markdown, expected):
    assert mrkdwn(markdown) == expected


def test_bullets_become_dots_and_keep_their_nesting():
    markdown = "- one\n  * **two**\n+ three\n1. first\n2. second"
    assert mrkdwn(markdown) == "• one\n  • *two*\n• three\n1. first\n2. second"


def test_dividers_and_quotes_are_left_as_written():
    assert mrkdwn("---\n* * *\n> quoted **x**") == "---\n* * *\n&gt; quoted *x*"


def test_tables_become_plain_lines_with_a_bold_header():
    markdown = "\n".join(
        [
            "Due soon:",
            "| Course | Due | Note |",
            "| --- | :-: | --- |",
            "| Calc | **Fri** | |",
            "| Bio \\| Lab | Mon | `lab_2` |",
            "",
            "Good luck.",
        ]
    )
    assert mrkdwn(markdown).split("\n") == [
        "Due soon:",
        "*Course · Due · Note*",
        "Calc · *Fri*",
        "Bio | Lab · Mon · `lab_2`",
        "",
        "Good luck.",
    ]


def test_a_pipe_without_a_delimiter_row_is_not_a_table():
    assert mrkdwn("a | b\nc | d") == "a | b\nc | d"


def test_fenced_code_loses_its_label_and_keeps_its_content_verbatim():
    markdown = "Try:\n```python\nif a < b and **c**:\n    x = [1](https://e.com)\n```\nDone."
    assert mrkdwn(markdown) == (
        "Try:\n```\nif a &lt; b and **c**:\n    x = [1](https://e.com)\n```\nDone."
    )


def test_tilde_fences_and_longer_fences_close_on_their_own_kind():
    assert mrkdwn("~~~\n```\n**x**\n~~~") == "```\n```\n**x**\n```"
    assert mrkdwn("````\n```\nstill code\n````") == "```\n```\nstill code\n```"


def test_an_unclosed_fence_is_closed_at_the_end():
    assert mrkdwn("```\nlast line") == "```\nlast line\n```"


def test_windows_line_ends_are_read_as_lines():
    assert mrkdwn("# A\r\n**b**\rc") == "*A*\n*b*\nc"


# ── escaping and visible text ────────────────────────────────────────────


def test_every_piece_of_text_is_escaped():
    out = mrkdwn(
        "<@U0123> & <!channel> **<b>** `a<b>&c` [x&y](https://e.com/?a=1&b=2)\n"
        "# <h> & co\n| <t> | & |\n|---|---|\n| <c> | d |\n```\n<pre> & >\n```"
    )
    assert "<" not in out and ">" not in out
    assert re.findall(r"&(?!amp;|lt;|gt;)", out) == []
    assert "&lt;@U0123&gt; &amp; &lt;!channel&gt;" in out
    assert "`a&lt;b&gt;&amp;c`" in out


def test_visible_text_has_no_markers_and_spells_out_links():
    _, visible = render("**Hi** _there_, see [docs](https://e.com) & `x`")
    assert visible == "Hi there, see docs (https://e.com) & x"


def test_hostile_input_renders_in_linear_ish_time():
    for markdown in ("_a " * 30_000, "[" * 50_000 + "](" * 50_000, "**x" * 30_000):
        started = time.perf_counter()
        render(markdown)
        assert time.perf_counter() - started < 5.0


def test_deep_nesting_stops_at_the_depth_bound():
    # strike > bold > italic > link > code: the code span is a fifth level,
    # past the bound, so it stays plain text (its backticks read literally).
    out, visible = render("~~a **b _c [d `e`](https://e.com) c_ b** a~~")
    assert out == "~a *b _c d `e` (https://e.com) c_ b* a~"
    assert visible == "a b c d `e` (https://e.com) c b a"


# ── masking re-check ─────────────────────────────────────────────────────


def test_a_clean_reply_keeps_its_formatting():
    assert render_reply("**Done** at [home](https://e.com)") == (
        "*Done* at home (https://e.com)",
        0,
    )


def test_a_value_only_rendering_reveals_drops_the_formatting_and_is_masked():
    # Raw, the token is split by "**" and no detector sees it; once the
    # markers go (an intra-word span keeps no markers), it reads whole.
    split_token = TOKEN[:4] + "**" + TOKEN[4:] + "** & more"
    body, hidden = render_reply(split_token)
    assert hidden == 1
    assert "FAKE" not in body
    assert body == "[hidden: GitHub token] &amp; more"


def test_a_detector_failure_on_the_visible_text_sends_the_withheld_notice(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("detector bug")

    monkeypatch.setattr(redact_module, "find", boom)
    assert render_reply("**anything**") == (slack_format.slack_escape(CHANNEL_WITHHELD), 0)


def test_the_marker_is_a_plain_str_that_slicing_drops():
    reply = SlackMarkdown("**x**")
    assert isinstance(reply, str) and reply == "**x**"
    assert not isinstance(reply[:2], SlackMarkdown)
    assert not isinstance(reply + " more", SlackMarkdown)


# ── splitting ────────────────────────────────────────────────────────────


def test_short_text_is_one_part_and_empty_text_none():
    assert split("hello", max_chars=100) == ["hello"]
    assert split("", max_chars=100) == []


def test_parts_fit_the_limit_and_join_back():
    text = "\n".join(f"line {n} *bold* &amp; more" for n in range(400))
    parts = split(text, max_chars=500)
    assert len(parts) > 1
    assert all(len(part) <= 500 for part in parts)
    assert "".join(parts) == text


def test_a_cut_never_lands_inside_an_entity():
    text = "&amp;" * 300 + "&lt;" * 300
    for limit in range(80, 100):
        parts = split(text, max_chars=limit)
        assert "".join(parts) == text
        for part in parts:
            assert len(part) <= limit
            assert re.fullmatch(r"(?:&amp;|&lt;)+", part), part


def test_a_code_block_cut_across_parts_is_closed_and_reopened():
    code = "\n".join(f"x = {n}  # &lt;{n}&gt;" for n in range(200))
    text = f"Here:\n```\n{code}\n```\nAfter."
    parts = split(text, max_chars=400)
    assert len(parts) > 2
    for part in parts:
        assert len(part) <= 400
        assert part.count("```") % 2 == 0
    assert parts[1].startswith("```\n")
    assert parts[0].endswith("```")
    unfenced = "".join(parts).replace("```\n", "").replace("```", "")
    assert unfenced == text.replace("```\n", "").replace("```", "")


def test_a_hard_cut_code_line_is_closed_on_its_own_line():
    text = "```\n" + "y" * 900 + "\n```"
    parts = split(text, max_chars=300)
    assert all(len(part) <= 300 for part in parts)
    assert all(part.count("```") == 2 for part in parts)
    assert parts[0].endswith("y\n```")
