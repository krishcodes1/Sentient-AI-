"""Tests for the audit sanitizer's token patterns: Slack, GitHub, Notion and
Google tokens and full JWTs are redacted wherever they sit in tool arguments
or results (nested dicts, lists, inside prose), OAuth flow key names are
redacted whole, and ordinary text that merely looks similar is left alone.

Why it exists: connector tokens can end up in an argument or a result (a
pasted token, an echoed header), and the audit log is append-only, so a
missed format leaks forever while an over-eager one ruins the log.

Connects to: services/audit.py (``_sanitize``, ``sanitize_request_data``
and ``append_audit_log``). Every token below is built from obviously fake
filler so no real credential appears in source.
"""

from __future__ import annotations

import json

import pytest

from models.audit import AuditStatus
from services.audit import _sanitize, append_audit_log, sanitize_request_data

REDACTED = "***REDACTED***"

# Fake tokens shaped like the real formats (prefix plus a body long enough
# to pass each pattern's floor). The filler makes them obviously fake.
_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.ZmFrZS1zaWduYXR1cmU"
FAKE_TOKENS = {
    "slack_bot": "xoxb-0000-1111-FAKEFAKEFAKE",
    "slack_user": "xoxp-0000-1111-FAKEFAKEFAKE",
    "slack_app_legacy": "xoxa-2-FAKEFAKEFAKE",
    "slack_refresh": "xoxr-FAKEFAKEFAKE",
    "slack_rotating": "xoxe-1-FAKEFAKEFAKE",
    "slack_app_level": "xapp-1-A000FAKE-0000-FAKEFAKE",
    "github_fine_grained": "github_pat_" + "FAKE" * 6 + "_" + "fake" * 10,
    "github_classic": "ghp_" + "FAKE" * 9,
    "github_oauth": "gho_" + "FAKE" * 9,
    "github_user_to_server": "ghu_" + "FAKE" * 9,
    "github_server_to_server": "ghs_" + "FAKE" * 9,
    "github_refresh": "ghr_" + "FAKE" * 9,
    "notion_legacy": "secret_" + "FAKE" * 11,
    "notion": "ntn_" + "FAKE" * 11,
    "google_access": "ya29.a0-FAKE_" + "fake" * 8,
    "google_refresh": "1//0g-FAKE_" + "fake" * 8,
    "google_client_secret": "GOCSPX-" + "FAKE" * 7,
    "jwt": _JWT,
    # Microsoft: personal-account opaque access token, personal-account
    # refresh token (and code) shapes, Entra ID v2 refresh tokens.
    "microsoft_access": "EwB" + "FAKE+/fake" * 12 + "==",
    "microsoft_msa_refresh": "M.C519_BAY.0.U.-Cfake!FAKE*" + "fake$FAKE" * 4,
    "microsoft_msa_code": "M.R3_BL2.2.U." + "FAKE-fake_" * 4,
    "microsoft_aad_refresh_0": "0.ARoA" + "FAKEfake_-" * 10 + ".AgAB" + "fake*" * 4,
    "microsoft_aad_refresh_1": "1.AXEA" + "fakeFAKE-_" * 11,
}


@pytest.mark.parametrize("name", sorted(FAKE_TOKENS))
def test_token_is_redacted_inside_nested_arguments_and_results(name: str) -> None:
    token = FAKE_TOKENS[name]
    payload = {
        "query": f"use {token} please",
        "items": [{"body": f"Authorisation header was {token}."}, token],
        "nested": {"deeper": [{"text": f"({token})"}]},
    }
    sanitized = _sanitize(payload)
    dumped = json.dumps(sanitized)
    assert token not in dumped
    assert sanitized["query"] == f"use {REDACTED} please"
    assert sanitized["items"][0]["body"] == f"Authorisation header was {REDACTED}."
    assert sanitized["items"][1] == REDACTED
    assert sanitized["nested"]["deeper"][0]["text"] == f"({REDACTED})"


def test_full_jwt_is_redacted_not_only_its_header() -> None:
    payload, signature = _JWT.split(".")[1:]
    out = _sanitize(f"Bearer {_JWT} end")
    assert out == f"Bearer {REDACTED} end"
    assert payload not in out and signature not in out


def test_jwe_with_five_segments_is_redacted_whole() -> None:
    jwe = "eyJhbGciOiJkaXIifQ..RkFLRWl2.RkFLRWNpcGhlcnRleHQ.RkFLRXRhZw"
    assert _sanitize(jwe) == REDACTED


def test_bare_jwt_header_is_still_redacted() -> None:
    assert _sanitize("eyJhbGciOiJub25lIn0. rest") == f"{REDACTED} rest"


def test_classic_github_token_longer_than_36_is_redacted_to_its_end() -> None:
    token = "ghp_" + "FAKE" * 12
    assert _sanitize(token) == REDACTED


def test_several_tokens_in_one_string_are_all_redacted() -> None:
    text = " ".join(FAKE_TOKENS.values())
    out = _sanitize(text)
    assert out == " ".join([REDACTED] * len(FAKE_TOKENS))


@pytest.mark.parametrize(
    "key",
    [
        "code_verifier",
        "codeVerifier",
        "device_code",
        "DeviceCode",
        "client_secret",
        "refresh_token",
        "oauth_client_secret",
        "oauth_device_code",
        "code",
        "Code",
        "state",
        "STATE",
        "oauth_state",
        "oauth-code",
        "auth_code",
        "authorization_code",
    ],
)
def test_oauth_flow_key_names_are_redacted_whole(key: str) -> None:
    sanitized = _sanitize({"outer": [{key: "harmless-looking-value"}]})
    assert sanitized == {"outer": [{key: REDACTED}]}


@pytest.mark.parametrize(
    "key",
    [
        "device_code_url",
        "device-code-uri",
        "statement",
        "state_name",
        "us_state",
        "zip_code",
        "barcode",
        "code_review",
        "error_code",
        "status_code",
    ],
)
def test_keys_that_only_contain_code_or_state_are_kept(key: str) -> None:
    data = {"outer": {key: "visible"}}
    assert _sanitize(data) == data


@pytest.mark.parametrize(
    "text",
    [
        "secret_santa is on friday",
        "the secret_key_rotation_policy document",
        "secret_" + "short",
        "ntn_ab12",
        "xoxb-short",
        "xapp-1",
        "ghp_" + "a" * 20,
        "GOCSPX-short",
        "ya29.short",
        "1//2 of the pie",
        "path/1//" + "a" * 40,
        "SGVsbG8gd29ybGQsIHRoaXMgaXMgb3JkaW5hcnkgYmFzZTY0Lg==",
        "123e4567-e89b-12d3-a456-426614174000",
        "call me at 212555012345",
        "commit 3f2a9c7e1b4d5f60718293a4b5c6d7e8f9012345",
        "eyJ",
        "the github_pat_ prefix names a token type",
        "https://example.com/a/b?c=d",
        # Microsoft look-alikes: the prefixes alone, short bodies, prose.
        "EwB",
        "EwB" + "a" * 60,
        "XEwB" + "a" * 120,
        "an M.C. Escher print",
        "M.C519_BAY.0.U.short",
        "M.Com degree from 2019",
        "release 1.A of the plan, then 0.A for the draft",
        "0.A" + "a" * 60,
        "10.A" + "a" * 120,
        "v2.0.A" + "a" * 120,
        "section 1.A.2 and 1.A.3 of the contract",
    ],
)
def test_ordinary_text_is_not_redacted(text: str) -> None:
    assert _sanitize(text) == text


@pytest.mark.parametrize(
    "name",
    ["microsoft_access", "microsoft_msa_refresh", "microsoft_msa_code", "microsoft_aad_refresh_0"],
)
def test_microsoft_token_at_the_end_of_a_sentence_keeps_the_full_stop(name: str) -> None:
    token = FAKE_TOKENS[name]
    assert _sanitize(f"The token was {token}. Next line") == f"The token was {REDACTED}. Next line"


def test_existing_formats_still_redacted() -> None:
    out = _sanitize(
        {
            "a": "sk-" + "FAKE" * 6,
            "b": "AKIA" + "FAKEFAKEFAKEFAKE",
            "c": "card 4111111111111111 on file",
        }
    )
    assert out == {"a": REDACTED, "b": REDACTED, "c": f"card {REDACTED} on file"}


def test_non_string_values_pass_through_unchanged() -> None:
    data = {"count": 3, "ok": True, "ratio": 0.5, "none": None}
    assert _sanitize(data) == data


def test_sanitize_request_data_serializes_redacted_payload() -> None:
    token = FAKE_TOKENS["notion"]
    stored = json.loads(sanitize_request_data({"page": {"note": f"key {token}"}}))
    assert stored == {"page": {"note": f"key {REDACTED}"}}


@pytest.mark.asyncio
async def test_append_audit_log_stores_redacted_arguments_and_summary(session_factory):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory, email="audit-token-patterns@example.com")
    slack = FAKE_TOKENS["slack_bot"]
    google = FAKE_TOKENS["google_refresh"]
    async with session_factory() as session:
        row = await append_audit_log(
            session,
            user_id=user.id,
            connector_name="slack",
            action="post_message",
            endpoint="agent.tool_executed",
            scope_used="chat.write",
            status=AuditStatus.approved,
            request_data={"channel": "C123", "text": f"token is {slack}"},
            response_summary=f"echoed {google}",
            reasoning_chain=[{"step": f"saw {_JWT}"}],
        )
        await session.commit()

    stored = json.dumps([row.request_data, row.response_summary, row.reasoning_chain], default=str)
    for secret in (slack, google, _JWT):
        assert secret not in stored
    assert row.request_data == {"channel": "C123", "text": f"token is {REDACTED}"}
    assert row.response_summary == f"echoed {REDACTED}"


# ── formats the shared detector added (services/security) ─────────────────

NEW_FORMATS = {
    "anthropic": "sk-ant-api03-" + "FAKEfake0000" * 3,
    "openai_project": "sk-proj-" + "FAKEfake_0000-" * 3,
    "google_api_key": "AIza" + "FAKEfake" * 4 + "000",
    "telegram_bot": "123456789:" + "AAFAKE_fake-" * 2 + "FAKEfake000",
    # top10:flashcards_quizzes: a study export link's one-time token.
    "study_export_token": "cse_" + "FAKEfake0000" * 3 + "FAKEfak",
}


@pytest.mark.parametrize("name", sorted(NEW_FORMATS))
def test_provider_keys_and_bot_tokens_are_now_redacted(name: str) -> None:
    token = NEW_FORMATS[name]
    assert _sanitize({"note": f"key {token} end"}) == {"note": f"key {REDACTED} end"}


def test_a_stated_password_and_an_ssn_are_redacted() -> None:
    assert _sanitize("password is Tr0ub4dor&3") == f"password is {REDACTED}"
    assert _sanitize("SSN 123-45-6789 on file") == f"SSN {REDACTED} on file"


def test_contact_details_are_kept() -> None:
    text = "mail prof.lee@uni.edu, call (212) 555-0100, 1600 Pennsylvania Avenue NW"
    assert _sanitize(text) == text
