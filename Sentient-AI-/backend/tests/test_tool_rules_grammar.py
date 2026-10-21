"""Tests for the tool-rule grammar (services/security/tool_rules/grammar.py): they prove a rule is
accepted and normalised, that every refusal comes with the plain reason the Security page shows
(name, tool pattern, each operator's value, the regular-expression safety checks, secret-shaped
values, limits, duplicates), that summaries read as plain English, that the audit digest never
carries a value, and which catalog tools a glob covers.

Why it exists: an owner rule is evaluated on every tool call. A pattern that backtracks without
bound would stall the server, a name with an address would leak into audit rows and chats, and a
secret saved as a rule value would sit in plaintext. Pure: no database, no network (Windows CI).
"""

from __future__ import annotations

import importlib
from datetime import datetime, timezone

import pytest

from services.security.tool_rules import grammar, texts
from services.security.tool_rules.engine import Condition, OwnerRule
from services.security.tool_rules.grammar import (
    RuleValidationError,
    compile_regex,
    validate_rule,
    validate_tool_pattern,
)


def _refusal(name="Big refunds", tool="google_workspace.send_email", conditions=None, existing=()):
    with pytest.raises(RuleValidationError) as caught:
        validate_rule(name, tool, conditions or [], existing=list(existing))
    return str(caught.value)


def _owner_rule(name, tool, conditions, rule_id="r1"):
    return OwnerRule(
        id=rule_id,
        name=name,
        tool=tool,
        conditions=tuple(conditions),
        created_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
    )


def _pattern_refusal(pattern):
    with pytest.raises(RuleValidationError) as caught:
        compile_regex(pattern)
    return str(caught.value)


# ---------------------------------------------------------------------------
# Whole rules, names and tool patterns
# ---------------------------------------------------------------------------


def test_a_rule_with_a_name_a_tool_pattern_and_two_conditions_is_accepted_and_normalised():
    draft = validate_rule(
        "  Big   mailings to the press ",
        "  Google_Workspace.Send_Email ",
        [
            {"arg": "to", "op": "domain_in", "value": ["NYTimes.com.", "wsj.com", "nytimes.com"]},
            {"arg": "subject", "op": "in_list", "value": [" Embargo ", 2026, "embargo", ""]},
        ],
        existing=[],
    )
    assert draft.name == "Big mailings to the press"
    assert draft.tool == "google_workspace.send_email"
    assert draft.conditions == (
        Condition("to", "domain_in", ("nytimes.com", "wsj.com")),
        Condition("subject", "in_list", ("Embargo", "2026", "embargo")),
    )


def test_a_rule_name_with_an_at_sign_or_a_link_is_refused_so_audit_rows_never_carry_addresses():
    for bad in (
        "Mail bob@example.com",
        "See https://evil.example/x",
        "Rules for evil.com",
        "www dot www.example",
        "ab",
        "x" * 61,
        "Refunds \U0001f4b8",
        "Tab\tand ‮flip",
        None,
        42,
    ):
        assert _refusal(name=bad) == texts.NAME_INVALID, bad
    accepted = validate_rule(
        "Mr. Smith's refunds (v1.2) & co/ops", "mcp.stripe.*", [], existing=[]
    )
    assert accepted.name == "Mr. Smith's refunds (v1.2) & co/ops"
    # Whitespace runs (line breaks included) collapse to one space.
    assert validate_rule("Line\nbreak  rule", "mcp.x.*", [], existing=[]).name == "Line break rule"


def test_a_tool_pattern_outside_the_glob_alphabet_is_refused():
    for bad in ("google_workspace.send email", "gmail/[x]", "a+b", "mcp.github.*!", "é.send"):
        with pytest.raises(RuleValidationError) as caught:
            validate_tool_pattern(bad)
        assert str(caught.value) == texts.TOOL_CHARSET, bad
    for missing in ("", "   ", None, 7):
        with pytest.raises(RuleValidationError) as caught:
            validate_tool_pattern(missing)
        assert str(caught.value) == texts.TOOL_MISSING
    with pytest.raises(RuleValidationError) as caught:
        validate_tool_pattern("a" * 121)
    assert str(caught.value) == texts.TOOL_TOO_LONG
    assert validate_tool_pattern("MCP.GitHub.*") == "mcp.github.*"
    assert validate_tool_pattern("google_workspace.?end_email") == "google_workspace.?end_email"


def test_a_tool_pattern_that_only_matches_tools_find_or_tutor_is_refused():
    for runtime_only in ("tools.find", "TOOLS.FIND", "tools.*", "tutor.*", "tutor.stop", "tool?.find"):
        with pytest.raises(RuleValidationError) as caught:
            validate_tool_pattern(runtime_only)
        assert str(caught.value) == texts.TOOL_RUNTIME_ONLY, runtime_only
    # Patterns that also reach other tools (or MCP tools) are fine: the engine skips the
    # runtime's own tools whatever the pattern says.
    for broad in ("*", "*find", "t*", "*.*"):
        assert validate_tool_pattern(broad) == broad


# ---------------------------------------------------------------------------
# Operators and their values
# ---------------------------------------------------------------------------

_GOOD_AND_BAD = {
    "equals": (("  Bob  ", "Bob"), (500, 500.0), [None, "", True, ["a"], "x" * 201]),
    "not_equals": (("draft", "draft"), (2.5, 2.5), [None, "  ", False, {"a": 1}]),
    "contains": (("urgent wire", "urgent wire"), ("​urgent", "​urgent"), [5, "", "​", None]),
    "regex": ((r"inv-\d{4,8}", r"inv-\d{4,8}"), ("a.*c", "a.*c"), ["", "(", 7, "x" * 101]),
    "in_list": ((["a", "b", "a"], ("a", "b")), ([1, "1.5"], ("1", "1.5")), [[], "abc", [""], ["x"] * 51]),
    "domain_in": ((["MyCo.com"], ("myco.com",)), ("a.org, b.net", ("a.org", "b.net")), [[], ["myco"], ["*.myco.com"]]),
    "domain_not_in": ((["sub.myco.com."], ("sub.myco.com",)), (["münchen.de"], ("xn--mnchen-3ya.de",)), [[], ["https://myco.com"], 5]),
    "number_gt": ((500, 500.0), ("$1,250.50", 1250.5), ["many", None, True, float("inf"), [1]]),
    "number_lt": ((0, 0.0), (-3.25, -3.25), ["", "ten", float("nan")]),
}


@pytest.mark.parametrize("op", grammar.OPS)
def test_every_operator_checks_its_value_type(op):
    good_one, good_two, bad_values = _GOOD_AND_BAD[op]
    for given, stored in (good_one, good_two):
        draft = validate_rule(
            "Operator check", "mcp.any.*", [{"arg": "field", "op": op, "value": given}], existing=[]
        )
        assert draft.conditions == (Condition("field", op, stored),), (op, given)
    for bad in bad_values:
        with pytest.raises(RuleValidationError) as caught:
            validate_rule(
                "Operator check", "mcp.any.*", [{"arg": "field", "op": op, "value": bad}], existing=[]
            )
        assert str(caught.value), (op, bad)


def test_an_unknown_operator_a_bad_argument_or_a_reserved_argument_is_refused_with_its_reason():
    def reason(condition):
        return _refusal(conditions=[condition])

    assert reason({"arg": "to", "op": "startswith", "value": "x"}) == texts.OP_UNKNOWN
    assert reason({"arg": "to", "op": "equals"}) == texts.CONDITION_SHAPE
    assert reason(["to", "equals", "x"]) == texts.CONDITION_SHAPE
    for bad_arg in ("to field", "a.b.c.d.e", "", "**", "x" * 41, None):
        assert reason({"arg": bad_arg, "op": "equals", "value": "x"}) == texts.ARG_INVALID
    assert reason({"arg": "_upload", "op": "equals", "value": "x"}) == texts.ARG_RESERVED
    assert reason({"arg": "fields._ref", "op": "equals", "value": "x"}) == texts.ARG_RESERVED
    assert _refusal(conditions="not a list") == texts.CONDITIONS_NOT_LIST
    assert reason({"arg": "amount", "op": "number_gt", "value": "lots"}) == texts.needs_number(
        "is more than"
    )


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------


def test_a_regex_with_a_nested_repeat_or_a_repeated_alternation_is_refused_with_a_plain_reason():
    for pattern in ("(a+)+$", "(a|aa)*", "(.*a){20}", r"^(\w+\s?)*$", "(ab?)+", "(?:cat|dog)+"):
        assert _pattern_refusal(pattern) == texts.PATTERN_NESTED, pattern
    # A repeat of plain characters, an optional group (it never repeats) and a group written
    # once ({1}) are fine.
    for pattern in ("(?:ab)+c", r"(?:\d\d\d-)+x", "(cat|dog)", "(?:a{1,5})?c", "(a|b)+", "(?:a{2}b){1}c"):
        assert compile_regex(pattern).flags & 2  # re.IGNORECASE


def test_a_fixed_repeat_inside_a_repeated_group_is_refused_as_a_nested_repeat_like_the_spec_says():
    # S9 §4.3 refuses "a repeat inside a repeat". A fixed inner repeat was let through before
    # and multiplied the work of every backtrack: on 4,000 characters the first took about 32 s,
    # the second 22 s, the third 17 s and the fourth 1.8 s (the checker's measurements).
    for pattern in (
        r"\w*(?:\w{50}){50}!",
        r".*(?:a{50}){50}b",
        r"a.*(?:a{50}){20}c",
        r"[a-z]{0,50}(?:[a-z]{50}){50}x",
        r"(?:a{50}){50}b",
        r"(?:\d{3}-)+x",
        r"\d{1,3}(?:,\d{3}){0,5}",
        r"(?:(?:ab){2}){3}",
    ):
        assert _pattern_refusal(pattern) == texts.PATTERN_NESTED, pattern
    # Writing the inner characters out is fine: the step estimate below costs each of them.
    compile_regex(r"\d{1,3}(?:,\d\d\d){0,5}")


def test_a_regex_with_a_backreference_or_lookaround_is_refused():
    for pattern in (r"(a)\1", "(?=x)y", "(?!x)y", "(?<=x)y", "(?<!x)y", "(a)?(?(1)b|c)"):
        assert _pattern_refusal(pattern) == texts.PATTERN_LOOKAROUND, pattern


def test_a_regex_with_two_open_ended_repeats_is_refused_and_the_reason_suggests_a_limit():
    for pattern in ("a.*b.*c", "x+y+", "a{2,}b*", "a*?b+?"):
        reason = _pattern_refusal(pattern)
        assert reason == texts.PATTERN_OPEN_REPEATS, pattern
        assert "{1,20}" in reason
    assert compile_regex("a.*c").search("A then C")


def test_a_regex_over_one_hundred_characters_or_a_repeat_above_fifty_is_refused():
    assert _pattern_refusal("x" * 101) == texts.PATTERN_LENGTH
    assert _pattern_refusal("") == texts.PATTERN_LENGTH
    for pattern in ("a{0,51}", "a{51}", "a{60,70}"):
        assert _pattern_refusal(pattern) == texts.PATTERN_BIG_REPEAT, pattern
    compile_regex("a{0,50}")
    compile_regex("a{50}")
    compile_regex("x" * 100)


def test_a_regex_whose_backtracking_choices_multiply_past_the_cap_is_refused_as_too_slow():
    # Each of these passes the nesting, open-repeat and {0,50} checks, yet takes seconds (or,
    # for twenty "a?", about a minute) to fail on 4,000 characters, or (the last four) several
    # times what one open-ended repeat costs.
    for pattern in (
        "a{0,50}a{0,50}a{0,50}c",
        "a?" * 20 + "c",
        "a.*a{0,50}c",
        "[^x]*[^y]{0,40}z",
        "(?:ab)*(?:ab){0,50}c",
        "a.*b?c",
        "a{0,50}a{0,50}c",
        "(?:a+)?c",
        "a?" * 10 + "c",
        "colou?r.*x",
    ):
        assert _pattern_refusal(pattern) == texts.PATTERN_TOO_SLOW, pattern
    for pattern in (
        "a.*c",
        "a{0,30}a{0,30}c",
        "a?" * 9 + "c",
        r"[a-z]{2,10}\.[a-z]{2,6}",
        r"https?://\S{0,50}evil",
        "colou?r.{0,40}x",
    ):
        compile_regex(pattern)
    assert grammar.MAX_BACKTRACK_CHOICES == grammar.REGEX_TEXT_CAP
    assert grammar.MAX_BOUNDED_CHOICES == 1000


def test_a_regex_whose_fixed_repeats_or_literals_redo_their_work_at_every_backtrack_is_refused_as_too_slow():
    # One choice per position, but at each the rest of the pattern matches many characters
    # before failing: ".*a{50}b" took about 1.1 s on 4,000 "a"s, and seven or more "\w{50}"
    # after a "\w{0,50}" take as long as an open-ended repeat with a long tail.
    for pattern in (
        r".*a{50}b",
        r".*\w{12}!",
        r"\w*\w{40}!",
        ".*aaaaab",
        r"a.*a{20}c",
        r"\w{0,50}" + r"\w{50}" * 8 + "!",
        r"[^x]*[^y]{0,40}z",
    ):
        assert _pattern_refusal(pattern) == texts.PATTERN_TOO_SLOW, pattern
        assert "smaller limits" in _pattern_refusal(pattern)
    # Natural patterns pass: an open-ended repeat followed by a word or a short code, and the
    # same code after a bounded gap.
    for pattern in (
        ".*invoice",
        "wire.*transfer",
        r"from:.*@evil\.com",
        r"^re:.*urgent",
        r"inv.*\d{4}",
        r"inv.{0,50}\d{6}",
        r"\w{0,50}" + r"\w{50}" * 7 + "!",
        r"password\s*[:=]",
    ):
        compile_regex(pattern)
    assert grammar.MAX_SEARCH_STEPS == 5 * grammar.REGEX_TEXT_CAP**2


def test_the_search_step_estimate_counts_matched_characters_and_spares_words_that_cannot_overlap():
    n2 = grammar.REGEX_TEXT_CAP**2
    steps = grammar.pattern_search_steps
    # "a.*c": consuming the text and one try per position, about n squared in all.
    assert 0.99 * n2 <= steps("a.*c") <= 1.01 * n2
    # A tail that can match at every position costs per character; a word that cannot overlap
    # itself ("abcdef") costs far less than one that can ("aaaaab"), though both are six long.
    assert steps(".*abcdef") < 3.5 * n2 < 5.5 * n2 < steps(".*aaaaab")
    assert steps(r".*\d{4}") > steps(r".*\d{3}") > steps(r".*\d{2}")
    assert steps(r".*a{50}b") > grammar.MAX_SEARCH_STEPS
    # Without an open-ended repeat: every start, every way, every character.
    assert steps(r"\w{0,50}\w{50}!") == grammar.REGEX_TEXT_CAP * (50 + 51 * 51)
    # Case-insensitive: "A" and "a" can match the same character, "a" and "b" cannot.
    assert steps(".*Aaaaab") == steps(".*aaaaab") > steps(".*abcdef")


def test_an_invalid_or_unsupported_regex_is_refused_plainly():
    for pattern in ("(", "[a-", "a{2,1}", "(?P<x>a)(?P=x)"):
        reason = _pattern_refusal(pattern)
        assert reason in (texts.PATTERN_INVALID, texts.PATTERN_LOOKAROUND), pattern


def test_patterns_are_refused_plainly_when_the_interpreter_has_no_regex_parser(monkeypatch):
    real_import = importlib.import_module

    def no_parser(name, *args, **kwargs):
        if name in ("re._parser", "re._constants"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(grammar.importlib, "import_module", no_parser)
    compile_regex.cache_clear()
    try:
        assert _pattern_refusal("plain words") == texts.PATTERNS_UNAVAILABLE
    finally:
        compile_regex.cache_clear()


# ---------------------------------------------------------------------------
# Secret-shaped values, domains, limits, duplicates
# ---------------------------------------------------------------------------


def test_a_value_that_looks_like_a_key_or_card_number_is_refused_without_echoing_it():
    secrets_found = {
        "card": ({"arg": "body", "op": "contains", "value": "4111 1111 1111 1111"}, "4111"),
        "aws key": ({"arg": "note", "op": "equals", "value": "AKIA" + "FAKEFAKEFAKEFAKE"}, "AKIA"),
        "stated password": (
            {"arg": "password", "op": "equals", "value": "Tr0ub4dor&3"},
            "Tr0ub4dor",
        ),
        "ssn in a list": (
            {"arg": "id", "op": "in_list", "value": ["fine", "123-45-6789"]},
            "123-45",
        ),
        "github token pattern": ({"arg": "x", "op": "regex", "value": "ghp_" + "FAKE" * 9}, "ghp_"),
    }
    for label, (condition, secret_part) in secrets_found.items():
        reason = _refusal(conditions=[condition])
        assert reason == texts.SECRET_VALUE, label
        assert secret_part not in reason
    assert _refusal(name="sk-" + "FAKE" * 6) in (texts.SECRET_VALUE, texts.NAME_INVALID)
    # Ordinary values pass: amounts, domains, addresses, phone numbers are not secrets.
    validate_rule(
        "Ordinary values",
        "mcp.stripe.*",
        [
            {"arg": "amount", "op": "number_gt", "value": 500},
            {"arg": "to", "op": "in_list", "value": ["billing@myco.com", "+44 20 7946 0958"]},
            {"arg": "to", "op": "domain_not_in", "value": ["myco.com"]},
        ],
        existing=[],
    )


def test_domain_values_are_lowercased_idna_encoded_and_wildcards_or_schemes_are_refused():
    draft = validate_rule(
        "Domains",
        "microsoft.create_event",
        [{"arg": "attendees", "op": "domain_not_in", "value": ["MyCo.COM.", "münchen.de", "myco.com"]}],
        existing=[],
    )
    assert draft.conditions[0].value == ("myco.com", "xn--mnchen-3ya.de")
    for bad in ("*.myco.com", "https://myco.com", "bob@myco.com", "localhost", "my co.com", "myco.c0m"):
        reason = _refusal(conditions=[{"arg": "to", "op": "domain_in", "value": [bad]}])
        assert reason == texts.not_a_domain(bad), bad
    # A refused value that looks secret-shaped, or is long, is never echoed.
    long_bad = "x" * 70
    assert _refusal(conditions=[{"arg": "to", "op": "domain_in", "value": [long_bad]}]) == (
        texts.NOT_A_DOMAIN_GENERIC
    )
    assert _refusal(conditions=[{"arg": "to", "op": "domain_in", "value": [42]}]) == (
        texts.NOT_A_DOMAIN_GENERIC
    )


def test_more_than_fifty_rules_five_conditions_or_fifty_list_items_is_refused():
    existing = [_owner_rule(f"Rule {i}", f"mcp.s{i}.*", []) for i in range(50)]
    assert _refusal(existing=existing) == texts.TOO_MANY_RULES
    six = [{"arg": "a", "op": "equals", "value": str(i)} for i in range(6)]
    assert _refusal(conditions=six) == texts.TOO_MANY_CONDITIONS
    validate_rule("Five is fine", "mcp.x.*", six[:5], existing=existing[:49])
    many = [f"v{i}" for i in range(51)]
    assert _refusal(conditions=[{"arg": "a", "op": "in_list", "value": many}]) == texts.needs_values(
        "is one of"
    )
    domains = [f"d{i}.com" for i in range(51)]
    assert _refusal(
        conditions=[{"arg": "a", "op": "domain_in", "value": domains}]
    ) == texts.needs_values("has an address or link at")
    assert _refusal(
        conditions=[{"arg": "a", "op": "in_list", "value": ["x" * 201]}]
    ) == texts.VALUE_TOO_LONG


def test_a_duplicate_name_or_an_identical_rule_is_refused():
    first = _owner_rule(
        "Large Stripe refunds",
        "mcp.stripe.*",
        [Condition("amount", "number_gt", 500.0), Condition("to", "in_list", ("A", "b"))],
    )
    assert _refusal(name="large STRIPE refunds", tool="mcp.other.*", existing=[first]) == (
        texts.NAME_TAKEN
    )
    assert _refusal(name="More than 10 recipients", tool="mcp.other.*") == texts.NAME_TAKEN
    reason = _refusal(
        name="Another name",
        tool="MCP.Stripe.*",
        conditions=[
            {"arg": "to", "op": "in_list", "value": ["b", "a"]},
            {"arg": "amount", "op": "number_gt", "value": "500"},
        ],
        existing=[first],
    )
    assert reason == texts.identical_rule("Large Stripe refunds")
    validate_rule(
        "Another name",
        "mcp.stripe.*",
        [{"arg": "amount", "op": "number_gt", "value": 501}],
        existing=[first],
    )


# ---------------------------------------------------------------------------
# Summaries, digests, operators, the catalog
# ---------------------------------------------------------------------------


def test_the_summary_reads_as_plain_english_for_every_operator_and_for_no_conditions():
    def summary(tool, op, value, arg="to"):
        return grammar.summarize(tool, [Condition(arg, op, value)])

    send = "google_workspace.send_email"
    assert summary(send, "equals", "Bob") == f'Ask before {send} when "to" is "Bob".'
    assert summary(send, "not_equals", 3.0) == f'Ask before {send} when "to" is not 3.'
    assert summary(send, "contains", "wire") == f'Ask before {send} when "to" contains "wire".'
    assert summary(send, "regex", "inv-[0-9]+") == (
        f'Ask before {send} when "to" matches the pattern "inv-[0-9]+".'
    )
    assert summary(send, "in_list", ("a", "b")) == f'Ask before {send} when "to" is one of "a", "b".'
    assert summary(send, "domain_in", ("nytimes.com", "wsj.com")) == (
        'Ask before google_workspace.send_email when "to" has an address or link at '
        "nytimes.com, wsj.com."
    )
    assert summary("microsoft.create_event", "domain_not_in", ("myco.com", "myco.org"), "attendees") == (
        'Ask before microsoft.create_event when "attendees" has an address or link outside '
        "myco.com, myco.org."
    )
    assert summary("mcp.stripe.*", "number_gt", 500.0, "amount") == (
        'Ask before any mcp.stripe.* call when "amount" is more than 500.'
    )
    assert summary(send, "number_lt", 1250.5, "*") == (
        f"Ask before {send} when any argument is less than 1250.5."
    )
    assert grammar.summarize(send, []) == f"Ask before every {send} call."
    assert grammar.summarize("mcp.stripe.*", []) == "Ask before any mcp.stripe.* call."
    two = grammar.summarize(
        send, [Condition("to", "domain_in", ("a.com",)), Condition("subject", "contains", "x")]
    )
    assert two == f'Ask before {send} when "to" has an address or link at a.com and "subject" contains "x".'
    long_list = tuple(f"v{i}" for i in range(12))
    assert summary(send, "in_list", long_list).endswith('"v9" and 2 more.')


def test_the_digest_changes_with_any_value_and_never_contains_one():
    base = validate_rule(
        "Press list",
        "google_workspace.send_email",
        [{"arg": "to", "op": "in_list", "value": ["editor@nytimes.example", "desk@wsj.example"]}],
        existing=[],
    )
    changed = validate_rule(
        "Press list",
        "google_workspace.send_email",
        [{"arg": "to", "op": "in_list", "value": ["editor@nytimes.example", "desk@ft.example"]}],
        existing=[],
    )
    digest = grammar.rule_digest(base)
    assert len(digest) == 16 and int(digest, 16) >= 0
    assert digest != grammar.rule_digest(changed)
    assert digest == grammar.rule_digest(
        _owner_rule(base.name, base.tool, base.conditions, rule_id="other")
    )
    fields = grammar.audit_fields(base, rule_id="7c0e")
    assert fields == {
        "rule_id": "7c0e",
        "name": "Press list",
        "tool": "google_workspace.send_email",
        "args": ["to"],
        "ops": ["in_list"],
        "digest": digest,
    }
    flat = repr(fields)
    assert "nytimes" not in flat and "wsj" not in flat and "@" not in flat


def test_condition_json_turns_whole_numbers_into_ints_and_lists_into_lists():
    assert grammar.conditions_json(
        [
            Condition("amount", "number_gt", 500.0),
            Condition("amount", "number_lt", 2.5),
            Condition("to", "domain_in", ("a.com",)),
            Condition("subject", "equals", "x"),
        ]
    ) == [
        {"arg": "amount", "op": "number_gt", "value": 500},
        {"arg": "amount", "op": "number_lt", "value": 2.5},
        {"arg": "to", "op": "domain_in", "value": ["a.com"]},
        {"arg": "subject", "op": "equals", "value": "x"},
    ]


def test_operator_options_and_limits_match_the_grammar_and_the_refusal_texts():
    options = grammar.operator_options()
    assert [o["op"] for o in options] == list(grammar.OPS)
    assert {o["op"]: o["value"] for o in options}["in_list"] == "list"
    assert {o["op"]: o["label"] for o in options}["number_gt"] == "is more than"
    assert set(grammar.OP_VALUE_KINDS.values()) == {"text", "list", "number", "pattern"}
    assert dict(grammar.LIMITS) == {
        "max_rules": 50,
        "max_conditions": 5,
        "max_list_items": 50,
        "max_value_chars": 200,
        "max_regex_chars": 100,
        "regex_text_cap": 4000,
    }
    assert str(grammar.MAX_RULES) in texts.TOO_MANY_RULES
    assert str(grammar.MAX_CONDITIONS) in texts.TOO_MANY_CONDITIONS
    assert str(grammar.MAX_VALUE_CHARS) in texts.VALUE_TOO_LONG
    assert str(grammar.MAX_REGEX_CHARS) in texts.PATTERN_LENGTH
    assert str(grammar.MAX_BOUNDED_REPEAT) in texts.PATTERN_BIG_REPEAT
    assert str(grammar.MAX_LIST_ITEMS) in texts.needs_values("x")


def test_a_stored_rule_is_read_back_through_todays_validator():
    rule = grammar.owner_rule_from_stored(
        rule_id="7c0e",
        name="Large Stripe refunds",
        tool="mcp.stripe.*",
        conditions=[{"arg": "amount", "op": "number_gt", "value": 500}],
        created_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
        created_by=None,
    )
    assert rule.id == "7c0e" and rule.conditions == (Condition("amount", "number_gt", 500.0),)
    with pytest.raises(RuleValidationError):
        grammar.owner_rule_from_stored(
            rule_id="x",
            name="Old pattern",
            tool="mcp.x.*",
            conditions=[{"arg": "body", "op": "regex", "value": "(a+)+$"}],
            created_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
        )


def test_matching_tools_lists_catalog_tools_counts_reads_and_flags_mcp_patterns():
    matches, mcp = grammar.matching_tools("google_workspace.send_*")
    assert ("google_workspace.send_email", "write") in matches and not mcp
    everything, mcp_all = grammar.matching_tools("google_workspace.*")
    categories = {category for _, category in everything}
    assert "read" in categories and "write" in categories
    assert grammar.matching_tools("mcp.github.*") == ([], True)
    assert grammar.matching_tools("*")[1] is True
    assert grammar.matching_tools("m*")[1] is True
    assert grammar.matching_tools("google_workspace.*")[1] is False
    names = {name for name, _, _ in grammar.catalog()}
    assert "tools.find" not in names and "tutor.start" not in names
    assert "google_workspace.send_email" in names
    by_name = {name: args for name, _, args in grammar.catalog()}
    assert "to" in by_name["google_workspace.send_email"]
    assert all(not a.startswith("_") for args in by_name.values() for a in args)
    assert grammar.catalog() == sorted(grammar.catalog())


def test_can_match_prefix_follows_the_glob():
    assert grammar.can_match_prefix("mcp.*", "mcp.")
    assert grammar.can_match_prefix("m?p.x", "mcp.")
    assert grammar.can_match_prefix("*", "mcp.")
    assert grammar.can_match_prefix("mc*", "mcp.")
    assert not grammar.can_match_prefix("mcx.*", "mcp.")
    assert not grammar.can_match_prefix("google_workspace.*", "mcp.")
    assert not grammar.can_match_prefix("mc", "mcp.")


# ---------------------------------------------------------------------------
# Capturing groups and multi-character repeat bodies (recheck finding: both cost several times
# what the step estimate counted, so accepted patterns ran 1.1-1.3 s on hostile text)
# ---------------------------------------------------------------------------


def test_capturing_groups_are_compiled_as_non_capturing_with_the_same_meaning():
    compiled = compile_regex(r"(ab)+(?P<tail>c|d)")
    assert compiled.pattern == r"(?:ab)+(?:c|d)"
    match = compiled.search("xxABABd")
    assert match is not None and match.group(0) == "ABABd"
    assert compiled.groups == 0
    # Escapes, classes and the other group kinds are copied as written.
    assert compile_regex(r"\(a\)[(]x[^)]y(?i:z)").pattern == r"\(a\)[(]x[^)]y(?i:z)"
    assert compile_regex(r"[]a(]b(c)").pattern == r"[]a(]b(?:c)"
    assert compile_regex(r"(?#note (here)a(b)").search("AB")  # a comment ends at its ")"
    # The parser reads a pattern with captures and its capture-free twin as the same pattern.
    assert grammar.pattern_search_steps(r"\w{0,50}" + r"(((\w))){50}" * 7 + "!") == (
        grammar.pattern_search_steps(r"\w{0,50}" + r"\w{50}" * 7 + "!")
    )


def test_a_pattern_whose_capture_free_twin_reads_differently_is_refused_not_changed(monkeypatch):
    monkeypatch.setattr(grammar, "_without_captures", lambda pattern: pattern + "x")
    grammar.compile_regex.cache_clear()
    try:
        assert _pattern_refusal("(ab)c") == texts.PATTERN_UNSUPPORTED
        monkeypatch.setattr(grammar, "_without_captures", lambda pattern: pattern)
        grammar.compile_regex.cache_clear()
        assert _pattern_refusal("(ab)c") == texts.PATTERN_UNSUPPORTED  # a capture is left
    finally:
        grammar.compile_regex.cache_clear()


def test_a_repeat_of_more_than_one_character_costs_the_general_repeat_weight():
    n2 = grammar.REGEX_TEXT_CAP**2
    steps = grammar.pattern_search_steps
    assert grammar.GENERAL_REPEAT_WEIGHT == 4.0
    # One character per iteration runs in a tight loop; two run through the general repeat.
    assert steps(r".*\w{12}!") < steps(r".*(?:\w\w){6}!")
    assert steps(r"(?:\w\w){0,25}(?:\w\w){12}!") > 4 * steps(r"\w{0,25}\w{12}!")
    # The recheck's shape (0.7 s at 0.9 of the old limit) is now refused; natural repeats of
    # a short group still pass.
    assert _pattern_refusal(r"(?:\w\w){0,25}(?:\w\w){0,25}(?:\w\w){12}!") == texts.PATTERN_TOO_SLOW
    assert steps(r"(?:\w\w){0,25}(?:\w\w){0,25}(?:\w\w){12}!") > grammar.MAX_SEARCH_STEPS
    for pattern in ("(?:ab)+c", r"(?:\d\d\d-)+x", r"(?:\w\w)*\w{2}!", r"\d{1,3}(?:,\d\d\d){0,5}"):
        compile_regex(pattern)
    assert steps("(?:ab)+c") > steps("a+c") >= n2 / 2


# ---------------------------------------------------------------------------
# Drafts, stored names and rows today's validator refuses
# ---------------------------------------------------------------------------


def test_a_draft_without_a_name_is_checked_like_a_rule_but_not_against_saved_rules():
    draft = grammar.validate_draft(
        "Google_Workspace.Send_Email", [{"arg": "to", "op": "domain_in", "value": "NYTimes.com"}]
    )
    assert (draft.name, draft.tool) == ("", "google_workspace.send_email")
    assert draft.conditions == (Condition("to", "domain_in", ("nytimes.com",)),)
    with pytest.raises(RuleValidationError) as caught:
        grammar.validate_draft("google_workspace.send_email", [{"arg": "password", "op": "equals", "value": "Tr0ub4dor&3!x"}])
    assert str(caught.value) == texts.SECRET_VALUE
    with pytest.raises(RuleValidationError) as caught:
        grammar.validate_draft("Tools.Find", [])
    assert str(caught.value) == texts.TOOL_RUNTIME_ONLY


def test_a_stored_name_is_shown_only_when_todays_check_still_accepts_it():
    assert grammar.stored_name("  Large   refunds ") == "Large refunds"
    for bad in ("pay bob@evil.com", "see https://x.example", "evil.com", "", None, "x" * 61):
        assert grammar.stored_name(bad) == texts.UNREADABLE_RULE_NAME
