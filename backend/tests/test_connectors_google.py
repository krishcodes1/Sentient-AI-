"""Unit tests for the GoogleWorkspaceConnector send_email and refresh flows.

These tests use ``httpx.MockTransport`` to intercept outbound calls so we
can assert exactly which Gmail endpoints get hit. The intent is to lock
down the P0 double-send bug fix: the connector must NEVER both create a
draft and call ``messages.send`` for the same logical send.

NOTE: ``respx`` is not currently in ``requirements-dev.txt``. If you want
to switch to respx for richer matching, add it to that file (a separate
agent owns dependency management).
"""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from services.connectors.google_workspace import GoogleWorkspaceConnector


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class CallRecorder:
    """Capture every request that hits the mock transport."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        url = str(request.url)
        if url.endswith("/gmail/v1/users/me/drafts"):
            return httpx.Response(
                200,
                json={"id": "draft-abc123", "message": {"id": "msg-x"}},
            )
        if url.endswith("/gmail/v1/users/me/drafts/send"):
            return httpx.Response(
                200,
                json={"id": "msg-from-draft", "threadId": "thr-from-draft"},
            )
        if url.endswith("/gmail/v1/users/me/messages/send"):
            return httpx.Response(
                200,
                json={"id": "msg-direct", "threadId": "thr-direct"},
            )
        if "oauth2.googleapis.com/token" in url:
            return httpx.Response(
                200,
                json={
                    "access_token": "new-access",
                    "refresh_token": "rotated-refresh",
                    "scope": "https://www.googleapis.com/auth/gmail.compose",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        return httpx.Response(404, json={"error": f"unmocked: {url}"})


def _make_connector(recorder: CallRecorder) -> GoogleWorkspaceConnector:
    """Build a connector wired to a mock transport."""
    connector = GoogleWorkspaceConnector(
        client_id="cid",
        client_secret="csec",
    )
    connector._access_token = "test-access"
    connector._refresh_token = "test-refresh"
    connector._authenticated = True
    transport = httpx.MockTransport(recorder)
    # Pre-seed the shared client so ``_get_client`` returns it.
    connector._http_client = httpx.AsyncClient(transport=transport)
    return connector


def _endpoint_calls(recorder: CallRecorder, suffix: str) -> list[httpx.Request]:
    return [c for c in recorder.calls if str(c.url).endswith(suffix)]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_unconfirmed_creates_draft_only() -> None:
    """user_confirmed=False must hit drafts.create exactly once and never send."""
    from services.connectors.base import UserConfirmationRequired

    rec = CallRecorder()
    conn = _make_connector(rec)

    with pytest.raises(UserConfirmationRequired) as exc_info:
        await conn.send_email(
            to="alice@example.com",
            subject="Hi",
            body="Hello",
        )

    # Exactly one draft create, zero sends of any flavor.
    assert len(_endpoint_calls(rec, "/gmail/v1/users/me/drafts")) == 1
    assert _endpoint_calls(rec, "/messages/send") == []
    assert _endpoint_calls(rec, "/drafts/send") == []

    # The error should expose the draft id and the Gmail review URL.
    assert "draft-abc123" in str(exc_info.value.details)
    assert "mail.google.com/mail/u/0/#drafts/draft-abc123" in str(
        exc_info.value.details
    )

    await conn.close()


@pytest.mark.asyncio
async def test_send_email_confirmed_sends_directly() -> None:
    """user_confirmed=True (no draft_id) must hit messages.send and skip drafts."""
    rec = CallRecorder()
    conn = _make_connector(rec)

    result = await conn.send_email(
        to="alice@example.com",
        subject="Hi",
        body="Hello",
        user_confirmed=True,
    )

    assert result["status"] == "sent"
    assert result["message_id"] == "msg-direct"

    assert len(_endpoint_calls(rec, "/messages/send")) == 1
    # Crucially: NO draft was created on the direct-send path.
    assert _endpoint_calls(rec, "/gmail/v1/users/me/drafts") == []
    assert _endpoint_calls(rec, "/drafts/send") == []

    # Verify the body sent contains a urlsafe-b64 raw message (no padding).
    sent = _endpoint_calls(rec, "/messages/send")[0]
    body_json = json.loads(sent.content.decode())
    raw = body_json["raw"]
    assert "=" not in raw  # rstripped
    decoded = base64.urlsafe_b64decode(raw + "==").decode()
    assert "alice@example.com" in decoded
    assert "Subject: Hi" in decoded

    await conn.close()


@pytest.mark.asyncio
async def test_send_existing_draft_via_drafts_send() -> None:
    """user_confirmed=True with a draft_id must call drafts.send with {id: draft_id}."""
    rec = CallRecorder()
    conn = _make_connector(rec)

    result = await conn.send_email(
        to="alice@example.com",
        subject="Hi",
        body="Hello",
        user_confirmed=True,
        draft_id="draft-abc123",
    )

    assert result["status"] == "sent"
    assert result["message_id"] == "msg-from-draft"
    assert result["draft_id"] == "draft-abc123"

    drafts_send_calls = _endpoint_calls(rec, "/drafts/send")
    assert len(drafts_send_calls) == 1
    body = json.loads(drafts_send_calls[0].content.decode())
    assert body == {"id": "draft-abc123"}

    # No re-creation of a draft, no messages.send fallback.
    assert _endpoint_calls(rec, "/gmail/v1/users/me/drafts") == []
    assert _endpoint_calls(rec, "/messages/send") == []

    await conn.close()


@pytest.mark.asyncio
async def test_refresh_token_updates_access_and_rotated_refresh() -> None:
    """Refresh response must update access_token and persist a rotated refresh token."""
    rec = CallRecorder()
    conn = _make_connector(rec)
    conn._refresh_token = "old-refresh"

    await conn._refresh_access_token()

    assert conn._access_token == "new-access"
    assert conn._refresh_token == "rotated-refresh"
    assert "https://www.googleapis.com/auth/gmail.compose" in conn._granted_scopes

    await conn.close()


@pytest.mark.asyncio
async def test_oauth_url_uses_select_account_on_first_auth() -> None:
    """Initial auth uses prompt=select_account, re-auth omits prompt."""
    conn = GoogleWorkspaceConnector(client_id="cid", client_secret="csec")

    first_url, _ = conn.generate_auth_url(first_auth=True)
    assert "prompt=select_account" in first_url
    assert "prompt=consent" not in first_url

    reauth_url, _ = conn.generate_auth_url(first_auth=False)
    assert "prompt=" not in reauth_url
