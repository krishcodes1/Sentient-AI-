"""Context manager: what goes into the cached prefix, and what it costs.

The expensive properties here are not functional ones. A tool array that
reorders between turns costs a full-price prompt on every turn of every
conversation; a context window guessed six times too small forces
summarization on threads the model could have held whole. Both are silent
until someone reads the bill, so they get tests.
"""

from __future__ import annotations

import pytest

from services.agent.context_manager import (
    ContextManager,
    TurnReplayCache,
    estimate_message_tokens,
    get_context_window,
    select_offered_tools,
    summarize_messages,
)


def _tools(count: int, connector: str = "canvas") -> list[dict]:
    return [
        {
            "name": f"{connector}.tool_{i:02d}",
            "description": f"does thing {i}",
            "parameters": {"type": "object", "properties": {}},
            "connector_type": connector,
        }
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Tool-set stability
# ---------------------------------------------------------------------------


def test_small_tool_sets_are_passed_through_untouched():
    tools = _tools(5)
    assert select_offered_tools(tools, ["canvas"]) is tools


def test_the_offered_tool_set_does_not_depend_on_what_the_user_said():
    """The whole point: selection is a function of the tool set and the
    active connectors, so the array that renders at position 0 of the
    request is byte-identical turn to turn and the provider's cache can
    actually match it."""
    tools = _tools(40)
    first = select_offered_tools(tools, ["canvas"])
    second = select_offered_tools(tools, ["canvas"])
    assert first == second
    # Order is stable too — a reshuffled array invalidates the cache just
    # as thoroughly as a changed one.
    assert [t["name"] for t in first] == [t["name"] for t in second]


def test_prepare_context_offers_the_same_tools_across_turns():
    manager = ContextManager(model="claude-sonnet-4-20250514")
    tools = _tools(30)

    _, turn_one = manager.prepare_context(
        [{"role": "user", "content": "send an email to my professor"}],
        tools,
        active_connectors=["canvas"],
    )
    _, turn_two = manager.prepare_context(
        [
            {"role": "user", "content": "send an email to my professor"},
            {"role": "assistant", "content": "done"},
            {"role": "user", "content": "now what is the weather"},
        ],
        tools,
        active_connectors=["canvas"],
    )
    assert turn_one == turn_two


def test_active_connectors_outrank_inactive_ones():
    """Trimming has to drop something; it drops from connectors the user
    has not enabled first, and only then alphabetically."""
    tools = _tools(10, "canvas") + _tools(10, "dormant")
    offered = select_offered_tools(tools, ["canvas"], max_tools=10)
    assert {t["connector_type"] for t in offered} == {"canvas"}


def test_changing_connectors_changes_the_set_and_nothing_else_does():
    tools = _tools(10, "canvas") + _tools(10, "gmail")
    with_canvas = select_offered_tools(tools, ["canvas"], max_tools=10)
    with_gmail = select_offered_tools(tools, ["gmail"], max_tools=10)
    assert with_canvas != with_gmail
    assert {t["connector_type"] for t in with_gmail} == {"gmail"}


def test_tool_count_stays_bounded():
    assert len(select_offered_tools(_tools(200), ["canvas"], max_tools=15)) == 15


# ---------------------------------------------------------------------------
# Context windows
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model, expected",
    [
        ("gpt-4o", 128_000),
        ("gemini-2.5-flash", 1_000_000),
        ("mixtral-8x7b-32768", 32_768),
    ],
)
def test_known_models_use_their_exact_window(model, expected):
    assert get_context_window(model) == expected


@pytest.mark.parametrize(
    "model, expected",
    [
        # Every one of these is a model id the table has never seen. Before
        # the family fallback they all budgeted at 32k.
        ("claude-sonnet-4-6", 200_000),
        ("claude-opus-4-1-20250805", 200_000),
        ("gpt-5", 128_000),
        ("gemini-3-pro-preview", 1_000_000),
        ("grok-4", 131_072),
        ("deepseek-v3", 64_000),
    ],
)
def test_unseen_models_resolve_through_their_family(model, expected):
    assert get_context_window(model) == expected


def test_an_unknown_family_gets_a_usable_default_not_a_punitive_one():
    window = get_context_window("some-vendor-model-v9")
    assert window == 128_000
    assert window > 32_000


def test_model_ids_are_matched_case_insensitively():
    assert get_context_window("Claude-Sonnet-4-6") == get_context_window(
        "claude-sonnet-4-6"
    )


def test_a_blank_model_still_returns_a_budget():
    assert get_context_window("") > 0


# ---------------------------------------------------------------------------
# Multimodal token accounting
# ---------------------------------------------------------------------------


def test_an_image_is_estimated_by_the_model_not_by_its_base64_length():
    """Measuring the encoded string would read a few megabytes of photo as
    hundreds of thousands of tokens and trip the emergency trim on every
    message that carries one."""
    huge = "A" * 3_000_000
    message = {
        "role": "user",
        "content": [
            {"type": "text", "text": "what is this?"},
            {"type": "image", "media_type": "image/jpeg", "data": huge},
        ],
    }
    estimate = estimate_message_tokens(message)
    assert estimate < 2_000
    # It is not free either — an image really does consume context.
    assert estimate > 500


def test_summaries_use_the_text_of_a_multimodal_turn():
    summary = summarize_messages(
        [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "identify this shelf"},
                    {"type": "image", "media_type": "image/png", "data": "B" * 5000},
                ],
            },
            {"role": "assistant", "content": "It is a KALLAX."},
        ]
        * 2
    )
    assert "identify this shelf" in summary["content"]
    assert "B" * 100 not in summary["content"]


# ---------------------------------------------------------------------------
# Turn replay cache
# ---------------------------------------------------------------------------


def test_replay_cache_serves_an_identical_retry_within_scope():
    cache = TurnReplayCache()
    messages = [{"role": "user", "content": "hi"}]
    cache.put(messages, "answer", {"input_tokens": 5}, scope="u1:c1")
    assert cache.get(messages, scope="u1:c1").response == "answer"


@pytest.mark.parametrize("other_scope", ["u2:c1", "u1:c2", ""])
def test_replay_cache_never_crosses_a_scope(other_scope):
    cache = TurnReplayCache()
    messages = [{"role": "user", "content": "what is my balance?"}]
    cache.put(messages, "private answer", {}, scope="u1:c1")
    assert cache.get(messages, scope=other_scope) is None


def test_replay_cache_keys_on_the_whole_turn_not_just_its_tail():
    """The old key hashed the last three messages, so two threads that
    happened to end the same way collided and were held apart by scope
    alone."""
    cache = TurnReplayCache()
    tail = [
        {"role": "user", "content": "and then?"},
        {"role": "assistant", "content": "then this"},
        {"role": "user", "content": "go on"},
    ]
    cache.put([{"role": "user", "content": "topic A"}, *tail], "A", {}, scope="s")
    assert cache.get([{"role": "user", "content": "topic B"}, *tail], scope="s") is None


def test_replay_cache_entries_expire():
    cache = TurnReplayCache(ttl_seconds=0)
    messages = [{"role": "user", "content": "hi"}]
    cache.put(messages, "stale", {}, scope="u1:c1")
    assert cache.get(messages, scope="u1:c1") is None


def test_replay_cache_evicts_the_oldest_when_full():
    cache = TurnReplayCache(max_entries=2)
    for i in range(3):
        cache.put([{"role": "user", "content": str(i)}], str(i), {}, scope="s")
    assert cache.get([{"role": "user", "content": "0"}], scope="s") is None
    assert cache.get([{"role": "user", "content": "2"}], scope="s").response == "2"
