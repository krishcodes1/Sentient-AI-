"""Tests for the Notion Markdown renderer and parser and the property helpers.

Why it exists: the Notion connector reads pages as Markdown and writes
Markdown back as blocks. These tests pin both directions (round trips for
every supported block type and inline format), Notion's request limits
(2000 characters per rich-text object, 100 elements per array, 100 children
per request) and the compact property rendering and write-value building.
Connects to: services/connectors/notion_api/markdown.py and
services/connectors/notion_api/properties.py. Pure functions: no network.
"""

from __future__ import annotations

import json
import random
import re
import time
from typing import Optional

import pytest

from services.connectors.base import ConnectorError
from services.connectors.notion_api.markdown import (
    ARRAY_MAX_ITEMS,
    CHILDREN_PER_REQUEST,
    MAX_MARKDOWN_CHARS,
    MAX_WRITE_BLOCKS,
    RICH_TEXT_MAX_CHARS,
    _inline_segments,
    batch_blocks,
    blocks_to_markdown,
    count_blocks,
    markdown_to_blocks,
    markdown_to_rich_text,
    render_block,
    render_blocks,
    rich_text_to_markdown,
    split_text,
)
from services.connectors.notion_api.properties import (
    MAX_PROPERTIES_JSON_CHARS,
    MAX_PROPERTY_TEXT_CHARS,
    build_properties,
    is_notion_id,
    needs_schema,
    page_title,
    precheck_properties,
    render_properties,
    render_property,
    render_schema,
)

ID = "1a2b3c4d5e6f47809a1b2c3d4e5f6a7b"
ID2 = "2b3c4d5e-6f70-4809-a1b2-c3d4e5f6a7b8"


def as_returned(blocks: list[dict]) -> list[dict]:
    """What Notion hands back for blocks we sent: rich text gains
    ``plain_text``/``href`` and nested children arrive as loaded children."""
    out = []
    for index, block in enumerate(blocks):
        kind = block["type"]
        data = dict(block[kind])
        if "rich_text" in data:
            data["rich_text"] = [
                {
                    **item,
                    "plain_text": item["text"]["content"],
                    "href": (item["text"].get("link") or {}).get("url"),
                }
                for item in data["rich_text"]
            ]
        children = data.pop("children", None)
        returned = {"id": f"id-{index}", "type": kind, kind: data, "has_children": bool(children)}
        if children:
            returned["_children"] = as_returned(children)
        out.append(returned)
    return out


def text_item(text: str, **annotations) -> dict:
    return {"type": "text", "plain_text": text, "annotations": annotations, "href": None}


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------

ROUND_TRIP_DOCS = [
    "# Heading one\n\n## Heading two\n\n### Heading three",
    "A paragraph with **bold**, _italic_, `code`, ~~strike~~ and a "
    "[link](https://example.com/a?b=1).\nIt keeps its second line.",
    "- one\n- two\n  - nested under two\n- three",
    "1. first\n2. second\n3. third",
    "- [ ] open task\n- [x] finished task",
    "> a quote\n> across two lines",
    "```python\nprint('hi')\n```",
    "````\ncode with ``` inside\n````",
    "Before\n\n---\n\nAfter",
    "**_bold italic_** and **`bold code`**",
    "## Learn C#",
]


@pytest.mark.parametrize("markdown", ROUND_TRIP_DOCS)
def test_markdown_round_trips_through_blocks(markdown):
    blocks = markdown_to_blocks(markdown)
    assert blocks_to_markdown(as_returned(blocks)) == markdown


def test_parser_builds_the_expected_block_types():
    blocks = markdown_to_blocks(
        "# T\n\npara\n\n- b\n1. n\n- [x] t\n> q\n```js\nx\n```\n---\n#### deep"
    )
    assert [b["type"] for b in blocks] == [
        "heading_1",
        "paragraph",
        "bulleted_list_item",
        "numbered_list_item",
        "to_do",
        "quote",
        "code",
        "divider",
        "heading_3",
    ]
    assert blocks[4]["to_do"]["checked"] is True
    assert blocks[6]["code"]["language"] == "javascript"


def test_inline_formatting_becomes_annotations_and_links():
    rich = markdown_to_rich_text("a **b** _c_ `d` ~~e~~ [f](https://x.test/p)")
    by_text = {item["text"]["content"]: item for item in rich}
    assert by_text["b"]["annotations"] == {"bold": True}
    assert by_text["c"]["annotations"] == {"italic": True}
    assert by_text["d"]["annotations"] == {"code": True}
    assert by_text["e"]["annotations"] == {"strikethrough": True}
    assert by_text["f"]["text"]["link"] == {"url": "https://x.test/p"}
    assert "annotations" not in by_text["a "]


def test_snake_case_and_non_http_links_stay_plain_text():
    rich = markdown_to_rich_text("my_var_name and [x](javascript:alert(1))")
    assert "".join(item["text"]["content"] for item in rich) == (
        "my_var_name and [x](javascript:alert(1))"
    )
    assert all("link" not in item["text"] for item in rich)
    assert all("annotations" not in item for item in rich)


def test_unknown_code_language_falls_back_to_plain_text():
    (block,) = markdown_to_blocks("```brainfudge\n+++\n```")
    assert block["code"]["language"] == "plain text"
    assert block["code"]["rich_text"][0]["text"]["content"] == "+++"


def test_code_is_not_parsed_for_inline_markdown():
    (block,) = markdown_to_blocks("```\n**not bold** _x_\n```")
    assert block["code"]["rich_text"] == [
        {"type": "text", "text": {"content": "**not bold** _x_"}}
    ]


def test_unclosed_code_fence_runs_to_the_end():
    (block,) = markdown_to_blocks("```\nline 1\nline 2")
    assert block["code"]["rich_text"][0]["text"]["content"] == "line 1\nline 2"


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


def test_long_paragraph_is_chunked_to_2000_characters_per_rich_text():
    (block,) = markdown_to_blocks("x" * 4500)
    contents = [item["text"]["content"] for item in block["paragraph"]["rich_text"]]
    assert [len(c) for c in contents] == [2000, 2000, 500]


def test_chunking_counts_utf16_units_and_never_splits_a_character():
    emoji = "\U0001f600"  # two UTF-16 code units
    chunks = split_text(emoji * 1500)
    assert all(len(chunk.encode("utf-16-le")) // 2 <= RICH_TEXT_MAX_CHARS for chunk in chunks)
    assert "".join(chunks) == emoji * 1500
    assert len(chunks) == 2


def test_text_past_100_rich_text_objects_splits_into_more_blocks():
    # Each "**b** p " makes two rich-text objects (bold, then plain).
    blocks = markdown_to_blocks("**b** p " * 60)
    assert [b["type"] for b in blocks] == ["paragraph", "paragraph"]
    assert len(blocks[0]["paragraph"]["rich_text"]) == ARRAY_MAX_ITEMS
    assert len(blocks[1]["paragraph"]["rich_text"]) == 20


def test_batches_respect_100_children_per_request():
    blocks = markdown_to_blocks("\n\n".join(f"p{i}" for i in range(250)))
    batches = batch_blocks(blocks)
    assert [len(b) for b in batches] == [100, 100, 50]


def test_batches_respect_the_total_block_limit_with_nested_children():
    parent = markdown_to_blocks("- parent\n" + "\n".join(f"  - c{i}" for i in range(9)))[0]
    batches = batch_blocks([parent] * 30, max_total=100)
    assert all(count_blocks(batch) <= 100 for batch in batches)
    assert sum(len(batch) for batch in batches) == 30


def test_too_many_blocks_is_refused():
    with pytest.raises(ConnectorError, match="at most"):
        markdown_to_blocks("\n\n".join("p" for _ in range(MAX_WRITE_BLOCKS + 1)))


def test_too_long_markdown_is_refused():
    with pytest.raises(ConnectorError, match="limit per call"):
        markdown_to_blocks("x" * (MAX_MARKDOWN_CHARS + 1))


def test_too_many_nested_items_under_one_list_item_is_refused():
    markdown = "- parent\n" + "\n".join(f"  - c{i}" for i in range(CHILDREN_PER_REQUEST + 1))
    with pytest.raises(ConnectorError, match="nested"):
        markdown_to_blocks(markdown)


@pytest.mark.parametrize("value", [None, 5, ["a"], {"a": 1}])
def test_non_text_markdown_is_refused(value):
    with pytest.raises(ConnectorError, match="must be a string"):
        markdown_to_blocks(value)


def test_hostile_inline_nesting_does_not_recurse_forever():
    rich = markdown_to_rich_text("**_" * 5000 + "x" + "_**" * 5000)
    assert "".join(item["text"]["content"] for item in rich).count("x") == 1


# ---------------------------------------------------------------------------
# Hostile input: parsing stays linear (no event-loop stalls)
# ---------------------------------------------------------------------------

#: A parse of at most MAX_MARKDOWN_CHARS must finish far below this; the old
#: regex parser took from 5 to 90 seconds on these inputs.
_FAST_S = 1.0

_HOSTILE_MARKDOWN = {
    "unclosed underscore italics": "_a " * 33000,
    "unclosed bold": "**a " * 25000,
    "unclosed strikethrough": "~~a " * 25000,
    "unclosed star italics": "*a " * 33000,
    "unclosed code": "`a" * 33000,
    "many brackets sharing one link": "[" * 45000 + "](http://" + "a" * 45000,
    "closed spans": "**a** _b_ ~~c~~ `d` " * 4500,
    "fence with long blank run": "```" + " " * 90000 + "`",
    "tilde fence with backtick": "~" * 45000 + "a" * 45000 + "`",
    "heading with long blank run": "# a" + " " * 90000 + "b",
    "heading with long hash run": "# a" + " #" * 45000 + "b",
}


@pytest.mark.parametrize("markdown", _HOSTILE_MARKDOWN.values(), ids=_HOSTILE_MARKDOWN.keys())
def test_hostile_markdown_parses_in_linear_time(markdown):
    assert len(markdown) <= MAX_MARKDOWN_CHARS
    started = time.perf_counter()
    blocks = markdown_to_blocks(markdown)
    assert time.perf_counter() - started < _FAST_S
    assert blocks


@pytest.mark.parametrize("text", ["_a " * 6667, "**a " * 5000, "~~a " * 5000])
def test_hostile_inline_text_parses_in_linear_time_and_keeps_every_character(text):
    started = time.perf_counter()
    rich = markdown_to_rich_text(text)
    assert time.perf_counter() - started < _FAST_S
    assert "".join(item["text"]["content"] for item in rich) == text
    assert all("annotations" not in item for item in rich)


# The regex the scanner replaced. It is quadratic on long lines, but on short
# ones it is the reference the scanner must agree with exactly.
_REFERENCE_RE = re.compile(
    r"`(?P<code>[^`\n]+)`"
    r"|\[(?P<ltext>[^\]\n]+)\]\((?P<href>https?://[^\s()]+)\)"
    r"|\*\*(?=\S)(?P<bold>[^\n]+?)(?<=\S)\*\*"
    r"|~~(?=\S)(?P<strike>[^\n]+?)(?<=\S)~~"
    r"|(?<![\w*])\*(?=[^\s*])(?P<italic>[^*\n]+?)(?<=\S)\*(?![\w*])"
    r"|(?<![\w_])_(?=[^\s_])(?P<uitalic>[^\n]+?)(?<=\S)_(?![\w_])"
)


def _reference_segments(text: str, marks: dict, href: Optional[str], depth: int = 0) -> list:
    if depth >= 4:
        return [(text, marks, href)] if text else []
    out: list = []
    position = 0
    for match in _REFERENCE_RE.finditer(text):
        if match.start() > position:
            out.append((text[position : match.start()], marks, href))
        groups = match.groupdict()
        if groups["code"] is not None:
            out.append((groups["code"], {**marks, "code": True}, href))
        elif groups["ltext"] is not None:
            out.extend(_reference_segments(groups["ltext"], marks, href or groups["href"], depth + 1))
        else:
            for group, flag in (
                ("bold", "bold"), ("strike", "strikethrough"), ("italic", "italic"), ("uitalic", "italic")
            ):
                if groups[group] is not None:
                    out.extend(_reference_segments(groups[group], {**marks, flag: True}, href, depth + 1))
                    break
        position = match.end()
    if position < len(text):
        out.append((text[position:], marks, href))
    return out


def test_inline_scanner_matches_the_reference_regex_on_random_text():
    rng = random.Random(20260925)
    alphabet = [
        "*", "*", "_", "_", "~", "`", "[", "]", "(", ")", "a", "b", " ", " ", "\n", "é",
        "https://x.io", "http://y", "1",
    ]  # fmt: skip
    for _ in range(4000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 18)))
        assert _inline_segments(text, {}, None) == _reference_segments(text, {}, None), text


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("## Title ##", ("heading_2", "Title")),
        ("# Title   #", ("heading_1", "Title")),
        ("## Learn C#", ("heading_2", "Learn C#")),
        ("#### deep #", ("heading_3", "deep")),
        ("#\tTabbed", ("heading_1", "Tabbed")),
    ],
)
def test_heading_lines_drop_only_a_closing_hash_run(line, expected):
    (block,) = markdown_to_blocks(line)
    kind, text = expected
    assert block["type"] == kind
    assert "".join(i["text"]["content"] for i in block[kind]["rich_text"]) == text


@pytest.mark.parametrize("line", ["####### seven", "#nospace", "#"])
def test_non_heading_hash_lines_stay_paragraphs(line):
    (block,) = markdown_to_blocks(line)
    assert block["type"] == "paragraph"


def test_fences_accept_tildes_and_refuse_a_backtick_in_the_language():
    (tilde,) = markdown_to_blocks("~~~~ py \nx = 1\n~~~~")
    assert tilde["type"] == "code" and tilde["code"]["language"] == "python"
    assert tilde["code"]["rich_text"][0]["text"]["content"] == "x = 1"
    (inline,) = markdown_to_blocks("```a`b")
    assert inline["type"] == "paragraph"


def test_long_property_text_is_refused_before_parsing():
    with pytest.raises(ConnectorError, match=f"longer than {MAX_PROPERTY_TEXT_CHARS}"):
        precheck_properties({"Name": {"title": "_a " * 7000}})
    with pytest.raises(ConnectorError, match="Property 'Notes'"):
        build_properties({"Notes": "x" * (MAX_PROPERTY_TEXT_CHARS + 1)}, {"Notes": "rich_text"})
    with pytest.raises(ConnectorError, match="rich-text items"):
        precheck_properties({"Name": {"title": [text_item("a")] * (ARRAY_MAX_ITEMS + 1)}})


def test_oversized_properties_object_is_refused():
    values = {f"p{i}": "x" * 5000 for i in range(25)}
    assert len(json.dumps(values)) > MAX_PROPERTIES_JSON_CHARS
    with pytest.raises(ConnectorError, match="larger than"):
        precheck_properties(values)


# ---------------------------------------------------------------------------
# Renderer details
# ---------------------------------------------------------------------------


def test_file_blocks_render_name_and_type_never_the_url():
    block = {
        "id": ID,
        "type": "image",
        "image": {
            "type": "file",
            "file": {"url": "https://s3.us-west-2.amazonaws.com/secure/diagram.png?X-Amz-Signature=abc"},
        },
    }
    rendered = render_block(block)
    assert rendered == "[image: diagram.png]"
    assert "amazonaws" not in rendered and "Signature" not in rendered


def test_unknown_block_types_render_as_their_type_name():
    assert render_block({"type": "ai_block", "ai_block": {}}) == "[ai_block]"
    assert render_block({"type": 7}) == "[unknown]"


def test_child_pages_are_named_with_their_id():
    block = {"id": ID, "type": "child_page", "child_page": {"title": "Notes"}, "has_children": True}
    assert render_block(block) == f"[child page: Notes] (id {ID})"


def test_unloaded_children_get_a_marker_naming_the_block():
    block = {
        "id": ID,
        "type": "toggle",
        "toggle": {"rich_text": [text_item("More")]},
        "has_children": True,
    }
    assert render_block(block) == (
        f"▸ More\n  [nested content not loaded: get_block_children block_id={ID}]"
    )
    assert render_block(block, markers=False) == "▸ More"


def test_tables_render_as_markdown_tables():
    row = lambda *cells: {  # noqa: E731
        "type": "table_row",
        "table_row": {"cells": [[text_item(c)] for c in cells]},
    }
    table = {
        "type": "table",
        "table": {"table_width": 2},
        "_children": [row("Name", "Qty"), row("a|b", "2")],
    }
    assert render_block(table) == "| Name | Qty |\n| --- | --- |\n| a\\|b | 2 |"


def test_numbering_restarts_after_a_non_numbered_block():
    number = lambda t: {"type": "numbered_list_item", "numbered_list_item": {"rich_text": [text_item(t)]}}  # noqa: E731
    para = {"type": "paragraph", "paragraph": {"rich_text": [text_item("p")]}}
    assert render_blocks([number("a"), number("b"), para, number("c")]) == [
        "1. a",
        "2. b",
        "p",
        "1. c",
    ]


def test_rich_text_renderer_keeps_whitespace_outside_markers_and_equations():
    items = [
        text_item("bold ", bold=True),
        {"type": "equation", "plain_text": "x^2", "equation": {"expression": "x^2"}},
    ]
    assert rich_text_to_markdown(items) == "**bold** $x^2$"


@pytest.mark.parametrize(
    "hostile",
    [
        None,
        "text",
        [None, 3, "x", {"type": "paragraph"}],
        [{"type": "paragraph", "paragraph": None}],
        [{"type": "paragraph", "paragraph": {"rich_text": "not a list"}}],
        [{"type": "code", "code": {"rich_text": [{"plain_text": 5}], "language": 9}}],
        [{"type": "image", "image": {"file": {"url": 12}}}],
        [{"type": "bookmark", "bookmark": {"url": "javascript:alert(1)"}}],
        [{"type": "paragraph", "paragraph": {"rich_text": [text_item("z" * 200_000)]}}],
    ],
)
def test_hostile_blocks_render_without_crashing(hostile):
    rendered = blocks_to_markdown(hostile)
    assert isinstance(rendered, str)
    assert "javascript:" not in rendered


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

PAGE_PROPERTIES = {
    "Name": {"type": "title", "title": [text_item("Launch plan")]},
    "Notes": {"type": "rich_text", "rich_text": [text_item("n" * 500)]},
    "Points": {"type": "number", "number": 3},
    "Stage": {"type": "select", "select": {"name": "Beta", "color": "red"}},
    "Tags": {"type": "multi_select", "multi_select": [{"name": "a"}, {"name": "b"}]},
    "Status": {"type": "status", "status": {"name": "Done"}},
    "Due": {"type": "date", "date": {"start": "2026-10-01", "end": "2026-10-03"}},
    "Owner": {"type": "people", "people": [{"id": ID, "name": "Ada"}, {"id": ID2}]},
    "Done": {"type": "checkbox", "checkbox": True},
    "Link": {"type": "url", "url": "https://example.com"},
    "Mail": {"type": "email", "email": "a@example.com"},
    "Phone": {"type": "phone_number", "phone_number": "+1 555"},
    "Related": {"type": "relation", "relation": [{"id": ID}], "has_more": True},
    "Score": {"type": "formula", "formula": {"type": "number", "number": 7.5}},
    "Total": {"type": "rollup", "rollup": {"type": "number", "number": 12}},
    "Dates": {
        "type": "rollup",
        "rollup": {"type": "array", "array": [{"type": "date", "date": {"start": "2026-01-01"}}]},
    },
    "Attachments": {"type": "files", "files": [{"name": "spec.pdf", "file": {"url": "https://s3/x"}}]},
    "Key": {"type": "unique_id", "unique_id": {"prefix": "TASK", "number": 42}},
    "Mystery": {"type": "button", "button": {}},
}


def test_every_common_property_type_renders_compactly():
    rendered = render_properties(PAGE_PROPERTIES, max_chars=100)
    assert rendered == {
        "Name": "Launch plan",
        "Notes": "n" * 100 + "...",
        "Points": 3,
        "Stage": "Beta",
        "Tags": ["a", "b"],
        "Status": "Done",
        "Due": "2026-10-01 to 2026-10-03",
        "Owner": ["Ada", ID2],
        "Done": True,
        "Link": "https://example.com",
        "Mail": "a@example.com",
        "Phone": "+1 555",
        "Related": [ID, "... more"],
        "Score": 7.5,
        "Total": 12,
        "Dates": ["2026-01-01"],
        "Attachments": ["spec.pdf"],
        "Key": "TASK-42",
        "Mystery": "<button>",
    }


def test_title_can_be_skipped_and_is_found_by_page_title():
    assert "Name" not in render_properties(PAGE_PROPERTIES, skip_title=True)
    assert page_title({"properties": PAGE_PROPERTIES}) == "Launch plan"
    assert page_title({"title": [text_item("DB")]}) == "DB"
    assert page_title(None) == ""


@pytest.mark.parametrize(
    "prop",
    [
        None,
        "x",
        {"type": 5},
        {"type": "number", "number": "NaN"},
        {"type": "number", "number": float("nan")},
        {"type": "select", "select": None},
        {"type": "multi_select", "multi_select": "a"},
        {"type": "people", "people": [None, 4]},
        {"type": "formula", "formula": None},
        {"type": "rollup", "rollup": {"type": "array", "array": [None]}},
        {"type": "date", "date": {"start": None}},
    ],
)
def test_hostile_property_values_do_not_crash(prop):
    value = render_property(prop)
    json.dumps(value)  # always JSON-serialisable


def test_schema_rendering_lists_select_options():
    schema = render_schema(
        {
            "Name": {"type": "title", "title": {}},
            "Stage": {"type": "select", "select": {"options": [{"name": "Alpha"}, {"name": "Beta"}]}},
            "Broken": "nope",
        }
    )
    assert schema == {"Name": "title", "Stage": {"type": "select", "options": ["Alpha", "Beta"]}}


def test_plain_values_are_converted_using_the_schema():
    schema = {
        "Name": "title",
        "Points": "number",
        "Stage": "select",
        "Tags": "multi_select",
        "Due": "date",
        "Done": "checkbox",
        "Owner": "people",
        "Link": "url",
    }
    built = build_properties(
        {
            "Name": "Plan **v2**",
            "Points": "4",
            "Stage": "Beta",
            "Tags": "a, b",
            "Due": "2026-10-01",
            "Done": "true",
            "Owner": [ID],
            "Link": None,
        },
        schema,
    )
    assert built["Name"]["title"][1] == {
        "type": "text",
        "text": {"content": "v2"},
        "annotations": {"bold": True},
    }
    assert built["Points"] == {"number": 4.0}
    assert built["Stage"] == {"select": {"name": "Beta"}}
    assert built["Tags"] == {"multi_select": [{"name": "a"}, {"name": "b"}]}
    assert built["Due"] == {"date": {"start": "2026-10-01"}}
    assert built["Done"] == {"checkbox": True}
    assert built["Owner"] == {"people": [{"id": ID}]}
    assert built["Link"] == {"url": None}


def test_typed_values_need_no_schema():
    values = {"Status": {"status": "Done"}, "Stage": {"select": {"name": "Beta"}}}
    assert needs_schema(values) is False
    assert build_properties(values, None) == {
        "Status": {"status": {"name": "Done"}},
        "Stage": {"select": {"name": "Beta"}},
    }
    assert needs_schema({"Status": "Done"}) is True


@pytest.mark.parametrize(
    ("values", "schema", "message"),
    [
        ({}, {}, "non-empty"),
        ("Status=Done", {}, "non-empty"),
        ({"Nope": "x"}, {"Name": "title"}, "no such property"),
        ({"Points": "many"}, {"Points": "number"}, "expected a number"),
        ({"Done": "maybe"}, {"Done": "checkbox"}, "true or false"),
        ({"Owner": ["../../users"]}, {"Owner": "people"}, "Notion ids"),
        ({"Stage": "a,b"}, {"Stage": "select"}, "commas"),
        ({"Made": "x"}, {"Made": "created_time"}, "cannot be written"),
        ({"x" * 0: "v"}, {}, "non-empty text"),
    ],
)
def test_bad_property_values_are_refused_with_the_property_named(values, schema, message):
    with pytest.raises(ConnectorError, match=message):
        build_properties(values, schema)


def test_precheck_catches_bad_typed_values_without_a_schema():
    precheck_properties({"Status": "Done"})  # plain: checked after the schema read
    with pytest.raises(ConnectorError, match="Property 'Due'"):
        precheck_properties({"Due": {"date": 5}})
    with pytest.raises(ConnectorError, match="At most"):
        precheck_properties({f"p{i}": "x" for i in range(51)})


def test_notion_id_shapes():
    assert is_notion_id(ID) and is_notion_id(ID2)
    for bad in ("", "abc", "../" + ID, ID + "/x", ID.upper() + "0", None, 5):
        assert not is_notion_id(bad)
