"""Tests for the named policies and the functions that apply them
(services/security/policies.py and redact.py): one table of input, policy and
outcome (refuse, keep, or the exact masked text), the audit and log key-name
rules, tool-argument findings by path, and failing closed when the detector
itself fails.

Why it exists: each sink's answer to the same text differs on purpose (audit
masks a card-length order number, the model does not; memory refuses a stated
passcode, a tool call does not; nothing but the model pseudonymiser touches an
email). A table keeps those differences deliberate and visible.
"""

from __future__ import annotations

import pytest

from services.security import redact as redact_module
from services.security.policies import (
    AUDIT,
    CHANNEL,
    CHANNEL_WITHHELD,
    INDEX,
    LOGS,
    MEMORY,
    MODEL_FLOOR,
    MODEL_PERSONAL,
    MODEL_WITHHELD,
    POLICIES,
    REDACTED,
    TOOL_ARGS,
)
from services.security.redact import (
    DETECTOR_ERROR_LABEL,
    SecretLogFilter,
    argument_findings,
    contains,
    first_finding,
    mask_arguments,
    redact_log_event,
    redact_obj,
    redact_text,
)

GITHUB = "ghp_" + "FAKE" * 9
CARD = "4111 1111 1111 1111"
ORDER = "1727712345678"

REFUSE, KEEP = "refuse", "keep"

# (text, policy, expected): "refuse"/"keep" for refuse-mode policies (and
# "keep" for text a mask leaves alone), else the exact masked text.
TABLE = [
    (f"My key is {GITHUB}", MEMORY, REFUSE),
    ("My SSN is 123-45-6789", MEMORY, REFUSE),
    ("IBAN GB82 WEST 1234 5698 7654 32", MEMORY, REFUSE),
    ("PIN: 4821", MEMORY, REFUSE),
    ("The wifi passcode = hunter", MEMORY, REFUSE),
    (f"order {ORDER}", MEMORY, REFUSE),
    ("Their phone is +1 212 555 0100", MEMORY, KEEP),
    ("Email me at prof.lee@uni.edu", MEMORY, KEEP),
    ("Prefers meetings after 11am", MEMORY, KEEP),
    (f"use {GITHUB} please", TOOL_ARGS, REFUSE),
    (f"card {CARD}", TOOL_ARGS, REFUSE),
    ("PIN: 4821", TOOL_ARGS, REFUSE),
    ("The wifi passcode = hunter", TOOL_ARGS, KEEP),
    (f"order {ORDER}", TOOL_ARGS, KEEP),
    ("write to prof.lee@uni.edu", TOOL_ARGS, KEEP),
    ("api_key = YOUR_API_KEY", TOOL_ARGS, KEEP),
    (f"use {GITHUB} please", AUDIT, f"use {REDACTED} please"),
    (f"order {ORDER}", AUDIT, f"order {REDACTED}"),
    ("password is Tr0ub4dor&3", AUDIT, f"password is {REDACTED}"),
    ("SSN 123-45-6789 on file", AUDIT, f"SSN {REDACTED} on file"),
    ("call +1 212 555 0100 or prof.lee@uni.edu", AUDIT, KEEP),
    (f"token {GITHUB}", LOGS, f"token {REDACTED}"),
    (f"card {CARD} today", CHANNEL, "card [hidden: card number] today"),
    (f"key {GITHUB}", CHANNEL, "key [hidden: GitHub token]"),
    (f"order {ORDER}", CHANNEL, KEEP),
    ("email prof.lee@uni.edu, 1600 Pennsylvania Avenue NW", CHANNEL, KEEP),
    (f"key {GITHUB}", MODEL_FLOOR, "key [hidden by Crawler: GitHub token]"),
    ("SSN 123-45-6789", MODEL_FLOOR, "SSN [hidden by Crawler: US Social Security number]"),
    (f"order {ORDER}", MODEL_FLOOR, KEEP),
    ("Passcode: 123456", MODEL_FLOOR, KEEP),
    ("email prof.lee@uni.edu", MODEL_FLOOR, KEEP),
    (f"key {GITHUB}", INDEX, "key [hidden by Crawler: GitHub token]"),
    ("email prof.lee@uni.edu or (212) 555-0100", MODEL_PERSONAL, "email [email] or [phone]"),
    (f"key {GITHUB}", MODEL_PERSONAL, KEEP),
]


@pytest.mark.parametrize(("text", "policy", "expected"), TABLE)
def test_policy_table(text, policy, expected):
    if expected == REFUSE:
        assert contains(text, policy) is True
    elif expected == KEEP:
        assert contains(text, policy) is False
        assert redact_text(text, policy).text == text
    else:
        redacted = redact_text(text, policy)
        assert redacted.text == expected and redacted.hidden >= 1 and not redacted.withheld


def test_every_policy_is_registered_and_index_equals_the_floor():
    assert set(POLICIES) == {
        "memory", "audit", "logs", "channel", "tool_args", "model_floor", "model_personal", "index"
    }
    for field in ("kinds", "min_confidence", "mode", "placeholder", "withheld"):
        assert getattr(INDEX, field) == getattr(MODEL_FLOOR, field)


def test_redacted_counts_by_label():
    redacted = redact_text(f"{GITHUB} and {GITHUB} and {CARD}", CHANNEL)
    assert redacted.counts == {"GitHub token": 2, "card number": 1}
    assert redacted.hidden == 3


# ── key names ────────────────────────────────────────────────────────────


def test_audit_key_names_are_unchanged():
    data = {"code": "x", "state": "y", "zip_code": "10001", "statement": "ok", "api_key": "k"}
    assert redact_obj(data, AUDIT) == {
        "code": REDACTED, "state": REDACTED, "zip_code": "10001", "statement": "ok", "api_key": REDACTED
    }


def test_logs_keep_input_tokens_and_mask_exact_secret_names():
    event = {"event": "done", "input_tokens": 5, "token": "abc", "Authorization": "x", "tokens_used": 3}
    assert redact_obj(event, LOGS) == {
        "event": "done", "input_tokens": 5, "token": REDACTED, "Authorization": REDACTED, "tokens_used": 3
    }


def test_redact_obj_walks_lists_tuples_and_leaves_other_values():
    data = {"a": [f"x {GITHUB}", 3, None, True], "b": (GITHUB,), "c": 1.5}
    assert redact_obj(data, AUDIT) == {"a": [f"x {REDACTED}", 3, None, True], "b": (REDACTED,), "c": 1.5}


# ── tool arguments ───────────────────────────────────────────────────────


def test_argument_findings_name_the_path_and_label_never_the_value():
    arguments = {
        "query": "weather",
        "to": ["prof.lee@uni.edu"],
        "headers": {"X-Note": f"key {GITHUB}"},
        "items": [{"body": "fine"}, {"body": f"card {CARD}"}],
        "password": "Tr0ub4dor&3",
    }
    hits = argument_findings(arguments, TOOL_ARGS)
    assert hits == [
        ("headers.X-Note", "GitHub token"),
        ("items[1].body", "card number"),
        ("password", "password"),
    ]
    assert GITHUB not in str(hits)


def test_a_secret_used_as_a_key_is_named_without_its_value():
    hits = argument_findings({GITHUB: "x"}, TOOL_ARGS)
    assert hits == [("[hidden key]", "GitHub token")]
    assert mask_arguments({GITHUB: "x", "q": "ok"}, TOOL_ARGS) == {"[hidden key]": "x", "q": "ok"}


def test_mask_arguments_replaces_exactly_the_flagged_values():
    arguments = {"q": f"use {GITHUB}", "n": 4111111111111111, "keep": "hello", "pin": "4821"}
    assert mask_arguments(arguments, TOOL_ARGS) == {
        "q": REDACTED, "n": REDACTED, "keep": "hello", "pin": REDACTED
    }


def test_contact_details_in_arguments_pass():
    assert argument_findings({"to": "prof.lee@uni.edu", "phone": "+1 212 555 0100"}, TOOL_ARGS) == []


# ── failing closed ───────────────────────────────────────────────────────


@pytest.fixture
def broken_detector(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("detector bug")

    monkeypatch.setattr(redact_module, "find", boom)


def test_a_detector_error_fails_closed_everywhere(broken_detector):
    assert contains("anything", MEMORY) is True
    assert contains("anything", TOOL_ARGS) is True
    assert redact_text("anything", AUDIT).text == REDACTED
    assert redact_text("anything", CHANNEL).text == CHANNEL_WITHHELD
    assert redact_text("anything", MODEL_FLOOR).text == MODEL_WITHHELD
    assert redact_text("anything", MODEL_FLOOR).withheld is True
    assert first_finding("anything", CHANNEL).label == DETECTOR_ERROR_LABEL
    hits = argument_findings({"q": "anything"}, TOOL_ARGS)
    assert hits and {label for _path, label in hits} == {DETECTOR_ERROR_LABEL}
    assert redact_obj({"q": "anything"}, AUDIT) == {"q": REDACTED}


def test_text_over_the_limit_is_treated_as_a_detector_failure():
    huge = "a" * 2_000_001
    assert contains(huge, MEMORY) is True
    assert redact_text(huge, MODEL_FLOOR).text == MODEL_WITHHELD


# ── logs ─────────────────────────────────────────────────────────────────


def test_log_processor_and_filter_are_policy_logs():
    event = redact_log_event(None, "info", {"event": f"saw {GITHUB}", "error": ValueError(GITHUB)})
    assert GITHUB not in str(event)
    assert event["event"] == f"saw {REDACTED}"
    assert isinstance(SecretLogFilter(), object)
