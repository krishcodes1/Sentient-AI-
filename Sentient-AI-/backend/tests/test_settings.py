"""Tests for the Settings and account request models: the tier enum, rate-limit
range, password-length, and email-format validation rules on these Pydantic
models reject invalid input and accept every valid combination.

Why it exists: These rules run before any database or provider call, so a
regression here would let invalid settings reach code that assumes they were
already checked.

Validation tests for the Settings/account request models.

These exercise the Pydantic request models directly (no DB), which is
where the tier-enum, rate-limit-range, and password-length rules live.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.routes.auth import (
    PasswordChangeRequest,
    ProfileUpdateRequest,
    SettingsUpdateRequest,
)


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


def test_password_change_accepts_valid():
    body = PasswordChangeRequest(current_password="oldpass1", new_password="newpass12")
    assert body.new_password == "newpass12"


def test_password_change_rejects_short_new_password():
    with pytest.raises(ValidationError):
        PasswordChangeRequest(current_password="oldpass1", new_password="short")


def test_password_change_requires_current_password():
    with pytest.raises(ValidationError):
        PasswordChangeRequest(new_password="newpass12")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Settings update
# ---------------------------------------------------------------------------


def test_settings_accepts_valid_tier_and_rate_limit():
    body = SettingsUpdateRequest(
        default_permission_tier="admin_only",
        rate_limit=120,
        llm_provider="ollama",
        llm_model="llama3.2:1b",
    )
    assert body.default_permission_tier == "admin_only"
    assert body.rate_limit == 120
    assert body.llm_provider == "ollama"


def test_settings_rejects_invalid_tier():
    with pytest.raises(ValidationError):
        SettingsUpdateRequest(default_permission_tier="superuser")  # type: ignore[arg-type]


def test_settings_rejects_rate_limit_too_low():
    with pytest.raises(ValidationError):
        SettingsUpdateRequest(rate_limit=5)


def test_settings_rejects_rate_limit_too_high():
    with pytest.raises(ValidationError):
        SettingsUpdateRequest(rate_limit=1000)


def test_settings_allows_all_four_valid_tiers():
    for tier in ("auto_approve", "user_confirm", "admin_only", "hard_blocked"):
        body = SettingsUpdateRequest(default_permission_tier=tier)  # type: ignore[arg-type]
        assert body.default_permission_tier == tier


def test_settings_all_fields_optional():
    # An empty update is valid (used when a section only changes one field)
    body = SettingsUpdateRequest()
    assert body.default_permission_tier is None
    assert body.rate_limit is None
    assert body.llm_provider is None
    assert body.llm_model is None


# ---------------------------------------------------------------------------
# Profile update
# ---------------------------------------------------------------------------


def test_profile_accepts_valid_email():
    body = ProfileUpdateRequest(name="Rafi", email="rafi@example.com")
    assert body.email == "rafi@example.com"
    assert body.name == "Rafi"


def test_profile_rejects_malformed_email():
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(email="not-an-email")


def test_profile_allows_name_only():
    body = ProfileUpdateRequest(name="Just A Name")
    assert body.name == "Just A Name"
    assert body.email is None
