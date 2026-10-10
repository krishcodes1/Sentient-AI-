"""Tests for the shared secret detector (services/security/secrets.py): one
positive per rule, placed in prose, JSON, a URL and at the end of a sentence;
the negatives that must stay readable (paging tokens, meeting passcodes, commit
SHAs, UUIDs, ISBNs, order ids, Slack ts values, timestamps, the whole security
system prompt); the validators; leftmost-longest merging; that a Finding never
holds its text; the 2,000,000-character limit; and 1 MB of each rule's worst
case in under 2 seconds.

Why it exists: every sink (memory, audit, logs, Telegram, Slack, tool
arguments, the model request) trusts this one table, so a missed format leaks
everywhere at once and an over-eager one breaks ordinary text everywhere at
once. Every token below is built from obvious fake filler.
"""

from __future__ import annotations

import json
import time

import pytest

from services.agent.runtime import SECURITY_SYSTEM_PROMPT
from services.security import secrets as sec
from services.security.secrets import (
    MAX_SCAN_CHARS,
    RULES,
    Confidence,
    Finding,
    Kind,
    ScanTooLarge,
    card_iin,
    find,
    iban_mod97,
    itin_valid,
    looks_like_credential,
    luhn,
    secret_name,
    shannon_entropy,
    ssn_valid,
)

_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.ZmFrZS1zaWduYXR1cmU"
# A made-up high-entropy value for the KEY=value rule. Kept in two pieces, like
# the other fake keys here, so secret scanners (GitHub push protection matched
# it as a provider key when written whole) do not take the fixture for a key.
_FAKE_ASSIGNED_SECRET = "aB3dE5fG7hJ9kL1m" + "N3pQ5rS7tU9vW1xY"


def _with_luhn(prefix: str) -> str:
    """*prefix* plus the digit that makes it pass Luhn."""
    for digit in "0123456789":
        if luhn(prefix + digit):
            return prefix + digit
    raise AssertionError("no check digit")


VISA_19 = _with_luhn("400000000000000000")

# rule id -> (the text that holds it, the part that must be hidden)
POSITIVES: dict[str, tuple[str, str]] = {
    "anthropic_api_key": ("sk-ant-api03-" + "FAKEfake0000" * 3,) * 2,
    "openai_project_key": ("sk-proj-" + "FAKEfake_0000-" * 3,) * 2,
    "sk_api_key": ("sk-" + "FAKE" * 6,) * 2,
    "google_api_key": ("AIza" + "FAKEfake" * 4 + "000",) * 2,
    "groq_api_key": ("gsk_" + "FAKEfake" * 5,) * 2,
    "xai_api_key": ("xai-" + "FAKEfake" * 5,) * 2,
    "github_fine_grained_token": ("github_pat_" + "FAKE" * 6 + "_" + "fake" * 10,) * 2,
    "github_token": ("ghp_" + "FAKE" * 9,) * 2,
    "gitlab_token": ("glpat-" + "FAKEfake" * 3,) * 2,
    "slack_token": ("xoxb-0000-1111-FAKEFAKEFAKE",) * 2,
    "slack_app_token": ("xapp-1-A000FAKE-0000-FAKEFAKE",) * 2,
    "notion_secret": ("secret_" + "FAKE" * 11,) * 2,
    "notion_token": ("ntn_" + "FAKE" * 11,) * 2,
    "google_access_token": ("ya29.a0-FAKE_" + "fake" * 8,) * 2,
    "google_refresh_token": ("1//0g-FAKE_" + "fake" * 8,) * 2,
    "google_client_secret": ("GOCSPX-" + "FAKE" * 7,) * 2,
    "microsoft_access_token": ("EwB" + "FAKE+/fake" * 12 + "==",) * 2,
    "microsoft_account_token": ("M.C519_BAY.0.U.-Cfake!FAKE*" + "fake$FAKE" * 4,) * 2,
    "microsoft_entra_refresh_token": ("1.AXEA" + "fakeFAKE-_" * 11,) * 2,
    "jwt": (_JWT, _JWT),
    "aws_access_key": ("AKIA" + "FAKEFAKEFAKEFAKE",) * 2,
    "aws_temporary_access_key": ("ASIA" + "FAKEFAKEFAKEFAKE",) * 2,
    "telegram_bot_token": ("123456789:" + "AAFAKE_fake-" * 2 + "FAKEfake000",) * 2,
    "canvas_token": ("1234~" + "FAKEfake" * 8,) * 2,
    "private_key": (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowFAKEFAKEfake\n-----END RSA PRIVATE KEY-----",
        "MIIEowFAKEFAKEfake",
    ),
    "signed_link_signature": (
        "https://files.example.com/f?X-Amz-Date=20260930&X-Amz-Signature=" + "ab12" * 16,
        "ab12" * 16,
    ),
    "link_password": ("https://owner:Hunter22pass@files.example.com/x", "Hunter22pass"),
    "authorization_header": ("Authorization: Bearer FAKEfake0123456789", "FAKEfake0123456789"),
    "bearer_token": ("Bearer FAKEfake0123456789abcdEFGH", "FAKEfake0123456789abcdEFGH"),
    "secret_assignment": (
        "EXAMPLE_API_KEY=" + _FAKE_ASSIGNED_SECRET,
        _FAKE_ASSIGNED_SECRET,
    ),
    "stated_password": ("my password is Tr0ub4dor&3", "Tr0ub4dor&3"),
    "stated_api_secret": ("the api key is FAKEfake1234", "FAKEfake1234"),
    "stated_pin_or_card_code": ("PIN: 4821", "4821"),
    "stated_secret_loose": ("The wifi passcode = hunter", "passcode = h"),
    "card_number": ("4111111111111111",) * 2,
    "card_number_grouped": ("4111 1111 1111 1111",) * 2,
    "card_number_grouped_19": (
        " ".join([VISA_19[0:4], VISA_19[4:8], VISA_19[8:12], VISA_19[12:16], VISA_19[16:]]),
    ) * 2,
    "card_number_4_6_5": ("3782 822463 10005",) * 2,
    "card_length_number": ("1234567890123",) * 2,
    "card_groups_loose": ("1234 5678 9012 3456",) * 2,
    "card_groups_amex_loose": ("1234 567890 12345",) * 2,
    "iban": ("GB82 WEST 1234 5698 7654 32",) * 2,
    "stated_bank_account": ("bank account number: 12345678", "12345678"),
    "us_ssn": ("123-45-6789",) * 2,
    "us_itin": ("912-70-1234",) * 2,
    "us_ssn_stated": ("SSN 123456789", "123456789"),
    "passport_number": ("passport number: X12345678", "X12345678"),
    "drivers_licence_number": ("driver's license D1234-5678", "D1234-5678"),
    "email": ("prof.lee@uni.edu",) * 2,
    "phone_nanp": ("(212) 555-0100",) * 2,
    "phone_e164": ("+44 20 7946 0958",) * 2,
    "us_street_address": ("1600 Pennsylvania Avenue NW",) * 2,
    "birth_date": ("DOB: 04/12/1990", "04/12/1990"),
    # top10:flashcards_quizzes
    "study_export_token": ("cse_" + "FAKEfake0000" * 3 + "FAKEfak",) * 2,
}

_BY_ID = {rule.id: rule for rule in RULES}


def test_every_rule_has_a_positive_and_ids_are_unique():
    assert len(_BY_ID) == len(RULES)
    assert set(POSITIVES) == set(_BY_ID)


def _contexts(sample: str) -> list[str]:
    contexts = [
        f"Here it is: {sample} and more text after it",
        json.dumps({"note": "value follows", "value": sample, "n": 3}),
        f"It was {sample}.",
    ]
    if " " not in sample and "\n" not in sample:
        contexts.append(f"https://example.com/page?ref=1&q={sample}&x=2")
    return contexts


@pytest.mark.parametrize("rule_id", sorted(POSITIVES))
def test_each_rule_finds_its_format_in_prose_json_urls_and_sentences(rule_id):
    rule = _BY_ID[rule_id]
    sample, secret = POSITIVES[rule_id]
    for text in _contexts(sample):
        found = sec._candidates(text, [rule])
        assert found, f"{rule_id} missed in {text!r}"
        # What a sink acting on this rule's kind and level would do.
        masked = text
        for finding in reversed(find(text, kinds=[rule.kind], min_confidence=rule.confidence)):
            masked = masked[: finding.start] + "#" + masked[finding.end :]
        encoded = json.dumps(secret)[1:-1] if text.startswith("{") else secret
        assert encoded not in masked, f"{rule_id} left its value in {masked!r}"


def test_labels_are_readable_and_carry_no_value():
    for rule in RULES:
        assert rule.label and rule.label == rule.label.strip()
        assert len(rule.label) <= 40


NEGATIVES = [
    '"nextPageToken": "CiAKGjBpNDd2Nmp2Zml2cXRwYjBpOXAaBQoDCOgH"',
    "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=RFNwdAIAAQAAAB8xOmJvYkBleGFtcGxlLmNvbQ",
    "https://zoom.us/j/81234567890?pwd=Ab12CdEfGh34IjKlMn56OpQrSt78UvWx",
    "Join Zoom Meeting, Meeting ID: 812 3456 7890, Passcode: 123456",
    "Passcode: 123456",
    "commit 3f2a9c7e1b4d5f60718293a4b5c6d7e8f9012345",
    "id 123e4567-e89b-12d3-a456-426614174000",
    "ISBN 978-0-306-40615-7 and 9780306406157",
    "Amazon order 112-4567890-1234567 shipped",
    "Slack ts 1727712345.123456",
    "created at 1727712345678 ms",
    "Discord user 812345678901234567",
    "Exams are on 2026-09-25 and 09/30/2026",
    "Your password was changed yesterday",
    "The password is incorrect.",
    "sk-learn-tutorial-for-beginners",
    "api_key = YOUR_API_KEY",
    "MISTRAL_API_KEY=your-mistral-api-key-goes-here",
    "password: ********",
    "secret_santa is on friday",
    "the github_pat_ prefix names a token type",
    "release 1.A of the plan, then 0.A for the draft",
    "an M.C. Escher print",
    "version 10.2.3 on host 192.168.100.200",
    "Is taking CSCI 260 on Wednesdays at 11:00",
    "Student ID ends in 4821",
    "Call extension 5550 about room 212",
    "https://example.com/a/b?c=d&page=2",
    "https://api.example.com:8443/v1/items",
    # top10:flashcards_quizzes: course codes and names that merely start
    # like an export token.
    "CSE 142 notes, cse_lab_notes_week_3 and cse_142_midterm_review",
]


@pytest.mark.parametrize("text", NEGATIVES)
def test_ordinary_text_has_no_finding_at_medium(text):
    assert find(text, min_confidence=Confidence.MEDIUM) == []


def test_the_whole_security_system_prompt_has_no_finding():
    assert find(SECURITY_SYSTEM_PROMPT) == []
    assert find(SECURITY_SYSTEM_PROMPT, min_confidence=Confidence.MEDIUM) == []


def test_the_broad_card_rule_is_low_only():
    [finding] = find("created at 1727712345678 ms")
    assert finding.rule == "card_length_number" and finding.confidence is Confidence.LOW


def test_passcodes_are_a_memory_hint_only():
    [finding] = find("Passcode: 123456", min_confidence=Confidence.HINT)
    assert finding.confidence is Confidence.HINT
    assert find("Passcode: 123456") == []


# ── validators ───────────────────────────────────────────────────────────


def test_luhn_and_issuer_prefix():
    assert luhn("4111111111111111") and not luhn("4111111111111112")
    assert not luhn("41111111x1111111")
    assert card_iin("4111111111111111") and card_iin("378282246310005")
    assert card_iin("5555555555554444") and card_iin("6011111111111117")
    assert not card_iin("1727712345678")  # a millisecond timestamp
    assert not card_iin("411111111111111")  # a Visa is 13, 16 or 19 digits
    assert not card_iin("812345678901234567")


def test_iban_mod97():
    assert iban_mod97("GB82 WEST 1234 5698 7654 32")
    assert iban_mod97("DE89370400440532013000")
    assert not iban_mod97("GB82 WEST 1234 5698 7654 33")
    assert not iban_mod97("GB82")


def test_ssn_and_itin_rules():
    assert ssn_valid("123", "45", "6789")
    for area, group, serial in [("000", "12", "3456"), ("666", "12", "3456"), ("900", "12", "3456"),
                                ("123", "00", "4567"), ("123", "45", "0000")]:
        assert not ssn_valid(area, group, serial)
    assert itin_valid("912", "70", "1234") and itin_valid("999", "94", "1234")
    assert not itin_valid("912", "93", "1234") and not itin_valid("123", "70", "1234")
    assert find("912-93-1234", min_confidence=Confidence.MEDIUM) == []
    assert find("000-12-3456", min_confidence=Confidence.MEDIUM) == []


def test_shannon_entropy_gates_assignments():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy(_FAKE_ASSIGNED_SECRET) > 3.5
    low = "API_TOKEN=" + "ab" * 15
    assert find(low, min_confidence=Confidence.MEDIUM) == []


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("api_key", True),
        ("client_secret", True),
        ("GITHUB_TOKEN", True),
        ("OPENAI_KEY", True),
        ("password", True),
        ("x-api-key", True),
        ("nextPageToken", False),
        ("$skiptoken", False),
        ("deltaToken", False),
        ("publishable_key", False),
        ("idempotency_key", False),
        ("cache_key", False),
        ("pwd", False),
    ],
)
def test_secret_names(name, expected):
    assert secret_name(name) is expected


def test_strict_stated_secrets_differ_from_the_loose_memory_form():
    loose = find("PIN: 4821", min_confidence=Confidence.HINT)
    assert loose and find("my pin number was reset", min_confidence=Confidence.MEDIUM) == []
    assert find("password is hunter", min_confidence=Confidence.MEDIUM) == []
    assert find("password is hunter", min_confidence=Confidence.HINT)


def test_looks_like_credential_covers_prefixes_and_findings():
    for code in ("xoxb-test-token", "ghp_abcdef", "ya29.fake", "sk-short"):
        assert looks_like_credential(code)
    assert looks_like_credential("error for " + "ghp_" + "FAKE" * 9)
    for code in ("invalid_token", "channel_not_found", "PERMISSION_DENIED"):
        assert not looks_like_credential(code)


# ── merging, findings, limits ────────────────────────────────────────────


def test_overlapping_matches_merge_leftmost_longest():
    key = "sk-ant-api03-" + "FAKEfake0000" * 3
    [finding] = find(f"key {key} end")
    assert finding.rule == "anthropic_api_key" and finding.label == "Anthropic API key"
    assert (finding.start, finding.end) == (4, 4 + len(key))

    a = Finding("a", Kind.credential, "A", 0, 10, Confidence.MEDIUM)
    b = Finding("b", Kind.credential, "B", 5, 20, Confidence.HIGH)
    c = Finding("c", Kind.credential, "C", 20, 25, Confidence.LOW)
    merged = sec._merge([c, b, a])
    assert [(f.rule, f.start, f.end, f.confidence) for f in merged] == [
        ("a", 0, 20, Confidence.HIGH),
        ("c", 20, 25, Confidence.LOW),
    ]


def test_a_bearer_jwt_is_one_finding():
    text = f"Authorization: Bearer {_JWT}"
    found = find(text, kinds=[Kind.credential], min_confidence=Confidence.MEDIUM)
    assert len(found) == 1 and text[found[0].start : found[0].end] == _JWT


def test_a_finding_never_holds_its_text():
    token = "ghp_" + "FAKE" * 9
    [finding] = find(f"use {token}")
    assert token not in repr(finding) and token not in str(finding)
    assert not any(token in str(getattr(finding, name)) for name in finding.__dataclass_fields__)


def test_scan_too_large_and_type_errors():
    with pytest.raises(ScanTooLarge):
        find("a" * (MAX_SCAN_CHARS + 1))
    assert find("a" * 10) == []
    with pytest.raises(TypeError):
        find(b"bytes")  # type: ignore[arg-type]
    assert looks_like_credential("a" * (MAX_SCAN_CHARS + 1)) is True


def _adversarial(sample: str) -> list[str]:
    """Worst cases built from a positive: the format cut short before it
    completes, and the whole thing with its last character dropped, each
    repeated to 1 MB with and without separators."""
    size = 1_000_000
    seeds = {sample[: max(1, len(sample) // 2)], sample[:-1], sample[:4], sample}
    texts = []
    for seed in seeds:
        for joiner in ("", " ", "."):
            unit = seed + joiner
            texts.append((unit * (size // len(unit) + 1))[:size])
    return texts


@pytest.mark.parametrize("rule_id", sorted(POSITIVES))
def test_one_megabyte_of_worst_case_input_per_rule_is_fast(rule_id):
    rule = _BY_ID[rule_id]
    for text in _adversarial(POSITIVES[rule_id][0]):
        started = time.perf_counter()
        sec._candidates(text, [rule])
        assert time.perf_counter() - started < 2.0, f"{rule_id} is slow on {text[:40]!r}"


def test_the_whole_table_on_one_megabyte_of_prose_is_bounded():
    prose = ("Meeting at 10:30 in room 204; call 555. The quick brown fox. " * 20000)[:1_000_000]
    started = time.perf_counter()
    find(prose, min_confidence=Confidence.HINT)
    assert time.perf_counter() - started < 10.0
