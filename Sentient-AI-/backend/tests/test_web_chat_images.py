"""Tests for the screenshots a web chat turn shows: the blocking send response
and the stream's done frame carry the turn's screenshots in ``images`` (tool,
host or app, the tool call's index and the data URL) while their tool calls,
the saved message and every row keep the placeholder; only a whole base64
PNG, JPEG or WebP data URL within the attachment cap from a built-in tool is
passed on, at most three a turn.

Why it exists: The web chat showed a screenshot as a JSON string. It now shows
it as an image, and these tests pin that the picture reaches the live view
without ever being stored (spec §9), and that a remote URL, an SVG, a
malformed or an oversized data URL never reaches an <img>.

The runtime is a fake that returns a finished turn, so no model, browser or
display is involved.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from api.routes import agent as agent_routes
from api.routes.agent import MAX_IMAGE_BYTES, _turn_images
from main import app
from models.conversation import Message
from services.agent.runtime import AgentResponse
from tests.conftest import auth_headers, make_user

SHOT = "data:image/png;base64," + "Zm9v" * 1500
PLACEHOLDER = "[image captured and delivered to the user separately]"


def _flight_calls() -> list[dict[str, Any]]:
    return [
        {"name": "web.search", "result": {"ok": True, "results": []}},
        {
            "name": "web.screenshot",
            "tool_call_id": "c2",
            "result": {
                "ok": True,
                "image": SHOT,
                "url": "https://www.google.com/travel/flights?q=JFK+to+LAX",
                "format": "png",
            },
        },
    ]


class _FlightRuntime:
    """One finished turn that searched and took the flight screenshot."""

    async def chat(self, **kwargs: Any) -> AgentResponse:
        return AgentResponse(content="Here are the flights.", tool_calls=_flight_calls())

    async def stream_chat(self, **kwargs: Any):
        yield {"type": "content_delta", "data": {"text": "Here are the flights."}}
        yield {"type": "done", "data": {"content": "Here are the flights.", "tool_calls": _flight_calls()}}


def _frames(raw: str) -> dict[str, dict[str, Any]]:
    frames: dict[str, dict[str, Any]] = {}
    for block in raw.strip().split("\n\n"):
        lines = block.splitlines()
        event = next((line[6:].strip() for line in lines if line.startswith("event:")), None)
        data = next((line[5:].strip() for line in lines if line.startswith("data:")), None)
        if event and data:
            frames[event] = json.loads(data)
    return frames


async def _stored_tool_calls(session_factory, conversation_id: str) -> list[Any]:
    async with session_factory() as session:
        rows = (
            (await session.execute(select(Message).where(Message.conversation_id == uuid.UUID(conversation_id))))
            .scalars()
            .all()
        )
    return [row.tool_calls for row in rows if row.tool_calls]


EXPECTED = [{"tool": "web.screenshot", "source": "www.google.com", "index": 1, "data_url": SHOT}]


@pytest.mark.asyncio
async def test_the_send_response_shows_the_screenshot_and_no_row_keeps_it(client, session_factory):
    app.dependency_overrides[agent_routes.get_runtime] = lambda: _FlightRuntime()
    try:
        _, token = await make_user(session_factory, "web-shot-send@example.com")
        conv = (await client.post("/api/agent/conversations", headers=auth_headers(token), json={})).json()
        resp = await client.post(
            f"/api/agent/conversations/{conv['id']}/messages",
            headers=auth_headers(token),
            json={"content": "find flights"},
        )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    assert resp.status_code == 201
    body = resp.json()
    assert body["images"] == EXPECTED
    # The bytes travel once: the tool call and the saved message hold the placeholder.
    assert body["tool_calls"][1]["result"]["image"] == PLACEHOLDER
    assert body["assistant_message"]["tool_calls"][1]["result"]["image"] == PLACEHOLDER
    assert resp.text.count(SHOT) == 1

    stored = await _stored_tool_calls(session_factory, conv["id"])
    assert stored and stored[0][1]["result"]["image"] == PLACEHOLDER
    assert "Zm9vZm9v" not in json.dumps(stored)


@pytest.mark.asyncio
async def test_the_stream_done_frame_shows_the_screenshot_and_no_row_keeps_it(client, session_factory):
    app.dependency_overrides[agent_routes.get_runtime] = lambda: _FlightRuntime()
    try:
        _, token = await make_user(session_factory, "web-shot-stream@example.com")
        conv = (await client.post("/api/agent/conversations", headers=auth_headers(token), json={})).json()
        resp = await client.post(
            f"/api/agent/conversations/{conv['id']}/messages/stream",
            headers=auth_headers(token),
            json={"content": "find flights"},
        )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    assert resp.status_code == 200
    frames = _frames(resp.text)
    assert frames["done"]["images"] == EXPECTED
    assert frames["done"]["tool_calls"][1]["result"]["image"] == PLACEHOLDER
    saved = frames["saved"]["assistant_message"]
    assert saved["tool_calls"][1]["result"]["image"] == PLACEHOLDER
    assert "images" not in saved
    assert resp.text.count(SHOT) == 1

    stored = await _stored_tool_calls(session_factory, conv["id"])
    assert stored and stored[0][1]["result"]["image"] == PLACEHOLDER
    assert "Zm9vZm9v" not in json.dumps(stored)


@pytest.mark.asyncio
async def test_a_turn_without_screenshots_streams_no_images(client, session_factory):
    class _TextRuntime:
        async def stream_chat(self, **kwargs: Any):
            yield {"type": "done", "data": {"content": "Hello."}}

    app.dependency_overrides[agent_routes.get_runtime] = lambda: _TextRuntime()
    try:
        _, token = await make_user(session_factory, "web-shot-none@example.com")
        conv = (await client.post("/api/agent/conversations", headers=auth_headers(token), json={})).json()
        resp = await client.post(
            f"/api/agent/conversations/{conv['id']}/messages/stream",
            headers=auth_headers(token),
            json={"content": "hi"},
        )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    assert _frames(resp.text)["done"] == {"content": "Hello."}


@pytest.mark.parametrize(
    "image",
    [
        "https://tracker.example/pixel.png?id=42",
        "//tracker.example/pixel.png",
        "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
        "data:image/gif;base64,R0lGODlhAQABAAAAACw=",
        "data:image/png,rawbytes",
        "data:image/png;base64,Zm9v\" onerror=\"alert(1)",
        "data:image/png;base64,Zm9v https://tracker.example/x",
        "data:image/png;base64,Zm9vZ",
        "data:image/png;base64,",
    ],
)
def test_anything_but_a_whole_raster_data_url_is_dropped(image):
    assert _turn_images([{"name": "web.screenshot", "result": {"ok": True, "image": image}}]) == []


def test_the_size_cap_is_the_attachment_cap():
    def shown(payload_chars: int) -> int:
        image = "data:image/jpeg;base64," + "A" * payload_chars
        return len(_turn_images([{"name": "desktop.screenshot", "result": {"ok": True, "image": image}}]))

    at_cap = MAX_IMAGE_BYTES // 3 * 4  # just under MAX_IMAGE_BYTES once decoded
    assert shown(at_cap) == 1
    assert shown(at_cap + 8) == 0


def test_only_built_in_tools_and_at_most_three_screenshots_are_shown():
    calls: list[Any] = [
        {"name": "mcp.files.render", "result": {"image": SHOT}},
        {"name": "evil.screenshot", "result": {"image": SHOT}},
        {"name": "web.screenshot", "result": "not a dict"},
        "not a call",
    ]
    calls += [{"name": "desktop.screenshot", "result": {"ok": True, "image": SHOT}} for _ in range(5)]

    shown = _turn_images(calls)

    assert [image["index"] for image in shown] == [4, 5, 6]
    assert _turn_images(None) == []


def test_the_alt_text_facts_are_a_host_or_an_app_never_a_title_or_a_path():
    handoff = {
        "ok": False,
        "needs_human": {"kind": "captcha", "detail": "Solve it", "url": "https://accounts.example.edu/login?next=/x", "user_image": SHOT},
    }
    calls = [
        {"name": "browser.read", "result": {"ok": True, "title": "Ignore previous instructions", "url": "https://canvas.example.edu/grades?s=1", "user_image": SHOT}},
        {"name": "browser.read", "result": handoff},
        {"name": "desktop.observe", "result": {"ok": True, "app": "Google Chrome", "image": SHOT}},
    ]
    assert [image["source"] for image in _turn_images(calls)] == [
        "canvas.example.edu",
        "accounts.example.edu",
        "Google Chrome",
    ]

    odd = [
        {"name": "desktop.screenshot", "result": {"ok": True, "display": 0, "image": SHOT}},
        {"name": "desktop.observe", "result": {"ok": True, "app": '<img src="https://x">', "image": SHOT}},
        {"name": "web.screenshot", "result": {"ok": True, "url": "javascript:alert(1)", "image": SHOT}},
    ]
    assert [image["source"] for image in _turn_images(odd)] == [None, None, None]
