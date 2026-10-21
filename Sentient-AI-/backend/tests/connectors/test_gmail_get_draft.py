"""Tests for the Gmail connector's ``get_draft`` READ (security S1): they prove it
returns a draft's recipients, subject and plain-text body from one GET of the draft,
that it is a READ on the gmail.read scope (never offered or run as a write), and that
a malformed draft id is refused before any request is made.

Why it exists: the send_draft card can only say who a saved draft goes to, and how
many hidden characters it carries, because this READ exists (S1 deviation 6). All
HTTP goes to ``httpx.MockTransport`` with the network-policy hook armed; no real
network or credentials.
"""

from __future__ import annotations

import base64

import httpx
import pytest

from services.connectors.base import ConnectorError
from services.connectors.definition import ActionCategory
from services.connectors.registry import REGISTRY
from tests.connectors.test_google_workspace_support import make, no_dns, query  # noqa: F401

pytestmark = pytest.mark.usefixtures("no_dns")


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _draft(text: str) -> dict:
    return {
        "id": "r-123",
        "message": {
            "id": "m-9",
            "payload": {
                "mimeType": "multipart/alternative",
                "headers": [
                    {"name": "To", "value": "Ana <ana@partner.example>"},
                    {"name": "Cc", "value": "ops@northwind.example"},
                    {"name": "Bcc", "value": "audit@northwind.example"},
                    {"name": "Subject", "value": "Invoice 4471"},
                ],
                "parts": [
                    {"partId": "0", "mimeType": "text/plain", "body": {"data": _b64(text)}},
                    {"partId": "1", "mimeType": "text/html", "body": {"data": _b64("<p>x</p>")}},
                ],
            },
        },
    }


@pytest.mark.asyncio
async def test_get_draft_returns_the_recipients_subject_and_text_body():
    connector, seen = make(lambda request: httpx.Response(200, json=_draft("Please pay today.")))
    shaped = await connector.get_draft("r-123")

    [request] = seen
    assert request.method == "GET"
    assert request.url.host == "gmail.googleapis.com"
    assert request.url.path == "/gmail/v1/users/me/drafts/r-123"
    assert query(request) == {"format": "full"}
    assert shaped == {
        "draft_id": "r-123",
        "message_id": "m-9",
        "to": "Ana <ana@partner.example>",
        "cc": "ops@northwind.example",
        "bcc": "audit@northwind.example",
        "subject": "Invoice 4471",
        "body": "Please pay today.",
    }


@pytest.mark.asyncio
async def test_get_draft_says_when_a_long_body_was_cut():
    connector, _seen = make(lambda request: httpx.Response(200, json=_draft("x" * 25_000)))
    shaped = await connector.get_draft("r-123")
    assert len(shaped["body"]) <= 20_000 + 200 and shaped["truncated"] is True


def test_get_draft_is_a_read_on_the_gmail_read_scope():
    [google] = [definition for definition in REGISTRY if definition.key == "google_workspace"]
    [spec] = [spec for spec in google.actions if spec.action == "get_draft"]
    assert spec.category == ActionCategory.READ
    assert spec.required_scope == "gmail.read"
    assert spec.always_confirm is False and spec.outbound is None
    assert spec.parameters["required"] == ["draft_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "   ", "r-1\nX-Header: evil", None, 42])
async def test_get_draft_refuses_a_malformed_id_without_a_request(bad):
    connector, seen = make(lambda request: httpx.Response(200, json=_draft("never")))
    with pytest.raises(ConnectorError):
        await connector.get_draft(bad)  # type: ignore[arg-type]
    assert seen == []
