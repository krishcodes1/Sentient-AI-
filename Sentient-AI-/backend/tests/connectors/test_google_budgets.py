"""Tests that the Google lists (Gmail messages, a search, a thread, Drive
files) reach the model whole.

Why it exists: the runtime keeps only the head and tail of a result over its
action's budget (services/agent/runtime.py RESULT_CHAR_BUDGETS, 2000 chars by
default), so a list without an entry showed the model its first and last
rows. These run realistic default-sized lists through the same compact JSON
and ``compress_tool_result`` with the real budgets. HTTP goes to
``httpx.MockTransport`` only.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from services.agent.context_manager import ContextManager, compress_tool_result
from services.agent.runtime import result_char_budget
from tests.connectors.test_google_workspace_support import make, no_dns  # noqa: F401 - fixture

pytestmark = pytest.mark.usefixtures("no_dns")


def model_view(action: str, result: Any) -> str:
    """What the model is shown of *result* inside the executor's envelope."""
    envelope = {"ok": True, "connector": "google_workspace", "action": action, "result": result}
    payload = json.dumps(envelope, default=str, ensure_ascii=False, separators=(",", ":"))
    budget = result_char_budget(f"google_workspace.{action}", ContextManager().max_tool_result_chars)
    return compress_tool_result(payload, budget)


def message(message_id: str) -> dict[str, Any]:
    """A typical inbox message: long body, Gmail's ~200-char snippet, usual headers."""
    headers = {
        "Subject": "Re: Project update for the quarterly review meeting next week",
        "From": "Jordan Smith <jordan.smith@example-company.com>",
        "To": "Rafi Hossain <rafi@example.com>",
        "Date": "Tue, 18 Nov 2026 14:32:11 +0000",
    }
    text = "Hello, here is the latest on the project. " * 120
    return {
        "id": message_id,
        "threadId": "18c2f3a4b5d6e7f8",
        "snippet": text[:200],
        "labelIds": ["INBOX", "CATEGORY_UPDATES", "UNREAD", "IMPORTANT"],
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [{"name": k, "value": v} for k, v in headers.items()],
            "parts": [{"partId": "0", "mimeType": "text/plain", "body": {
                "data": base64.urlsafe_b64encode(text.encode()).decode().rstrip("="),
            }}],
        },
    }


def inbox(count: int):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [{"id": f"18c2f3a4b5d6{i:04x}"} for i in range(count)]})
        return httpx.Response(200, json=message(request.url.path.rsplit("/", 1)[-1]))

    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize(("action", "count"), [("get_messages", 20), ("search_emails", 25)])
async def test_a_default_mail_list_reaches_the_model_whole(action, count):
    connector, _ = make(inbox(count))
    messages = await (connector.get_messages() if action == "get_messages" else connector.search_emails("project"))
    assert len(messages) == count
    view = model_view(action, messages)
    assert "chars truncated" not in view
    assert messages[-1]["id"] in view


@pytest.mark.asyncio
async def test_a_thread_of_twenty_reaches_the_model_whole():
    thread = {"id": "t1", "messages": [message(f"m{i}") for i in range(20)]}
    connector, _ = make(lambda _request: httpx.Response(200, json=thread))
    view = model_view("get_thread", await connector.get_thread("t1"))
    assert "chars truncated" not in view


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["search_files", "list_folder"])
async def test_a_default_drive_list_reaches_the_model_whole(action):
    file_id = "1AbCdEfGhIjKlMnOpQrStUvWxYz0123456"
    row = {
        "id": file_id,
        "name": "Quarterly review notes and action items.docx",
        "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "modifiedTime": "2026-11-18T14:32:11.000Z",
        "size": "48213",
        "webViewLink": f"https://docs.google.com/document/d/{file_id}/edit?usp=drivesdk",
        "parents": [file_id],
    }
    connector, _ = make(lambda _request: httpx.Response(200, json={"files": [row] * 10}))
    files = await getattr(connector, action)()
    assert len(files) == 10
    assert "chars truncated" not in model_view(action, files)
