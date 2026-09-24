"""Image attachments and token accounting on the chat routes.

Two things a cost study asked for and the platform could not answer:

- A user can attach photos to a message. The bytes are validated hard at
  the boundary (type, size, count), reach the provider as multimodal
  content, and leave only metadata behind in the transcript.
- Every assistant turn records what it was billed, on the blocking path
  and the streaming path alike, so per-conversation cost is a query rather
  than a log-scraping exercise.

Nothing here calls a provider: the runtime is either a stub or the real
runtime driven by a scripted provider, exactly as the rest of the suite
does it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from tests.conftest import auth_headers, make_user

BACKEND_DIR = Path(__file__).resolve().parents[1]

# A one-pixel PNG: real bytes, small enough to inline, and decodable by
# anything that wants to check the payload survived the round trip.
PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmM"
    "IQAAAABJRU5ErkJggg=="
)
PNG_B64 = base64.b64encode(PNG_BYTES).decode()


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class UsageRuntime:
    """Stands in for AgentRuntime, reporting a fixed token bill and
    recording the messages the route handed it."""

    def __init__(self, usage=None, content="ok"):
        self.seen_messages = []
        self._usage = usage if usage is not None else {
            "input_tokens": 1234,
            "output_tokens": 56,
        }
        self._content = content

    async def chat(self, messages, tools, user_id, conversation_id=None, **kwargs):
        from services.agent.runtime import AgentResponse

        self.seen_messages.append(list(messages))
        return AgentResponse(content=self._content, usage=dict(self._usage))

    async def stream_chat(self, messages, tools, user_id, conversation_id=None, **kwargs):
        self.seen_messages.append(list(messages))
        yield {"type": "start", "data": {}}
        yield {
            "type": "done",
            "data": {
                "content": self._content,
                "usage": dict(self._usage),
                "tool_calls": [],
                "pending_approvals": [],
                "blocked_actions": [],
            },
        }


def _parse_sse(text: str):
    frames = []
    for block in text.strip().split("\n\n"):
        event, data = "message", "{}"
        for line in block.splitlines():
            if line.startswith("event:"):
                event = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data = line[len("data:"):].strip()
        frames.append((event, json.loads(data)))
    return frames


async def _conversation(client: httpx.AsyncClient, token: str) -> str:
    created = await client.post(
        "/api/agent/conversations",
        json={"title": "Vision"},
        headers=auth_headers(token),
    )
    return created.json()["id"]


# ---------------------------------------------------------------------------
# Image validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "images, why",
    [
        (
            [{"media_type": "image/svg+xml", "data": PNG_B64}],
            "SVG carries script and is not on the allowed list",
        ),
        (
            [{"media_type": "application/pdf", "data": PNG_B64}],
            "a document is not an image",
        ),
        (
            [{"media_type": "image/png", "data": "not base64!!"}],
            "undecodable payload",
        ),
        (
            [{"media_type": "image/png", "data": ""}],
            "empty payload",
        ),
        (
            [{"media_type": "image/png", "data": PNG_B64}] * 5,
            "more attachments than the per-message cap",
        ),
    ],
)
async def test_unacceptable_attachments_are_refused(
    client, session_factory, images, why
):
    _, token = await make_user(session_factory, "reject@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime()
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={"content": "what is this?", "images": images},
            headers=auth_headers(token),
        )
        assert resp.status_code == 422, why
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_oversize_image_is_refused_without_decoding_it(client, session_factory):
    """The cap is on the decoded bytes, and the encoded length is checked
    first so an enormous body is rejected rather than expanded in memory."""
    from api.routes.agent import MAX_IMAGE_BYTES

    _, token = await make_user(session_factory, "huge@example.com")
    from api.routes import agent as agent_routes
    from main import app

    oversize = base64.b64encode(b"\x00" * (MAX_IMAGE_BYTES + 1)).decode()

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime()
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={
                "content": "big",
                "images": [{"media_type": "image/png", "data": oversize}],
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 422
        assert "MB limit" in resp.text
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_data_url_is_split_and_its_media_type_governs(client, session_factory):
    """A browser hands the client a data URL. Its media type is the one the
    bytes actually came with, so it must override a mismatched field rather
    than let a JPEG be relayed to the provider labelled as a PNG."""
    _, token = await make_user(session_factory, "dataurl@example.com")
    from api.routes import agent as agent_routes
    from main import app

    runtime = UsageRuntime()
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={
                "content": "identify this",
                "images": [
                    {
                        "media_type": "image/png",
                        "data": f"data:image/jpeg;base64,{PNG_B64}",
                    }
                ],
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 201

        blocks = runtime.seen_messages[0][-1]["content"]
        image_block = next(b for b in blocks if b["type"] == "image")
        assert image_block["media_type"] == "image/jpeg"
        # The prefix was stripped: what reaches the provider is bare base64.
        assert image_block["data"] == PNG_B64
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_data_url_must_be_base64(client, session_factory):
    _, token = await make_user(session_factory, "urlencoded@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime()
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={
                "content": "hi",
                "images": [{"media_type": "image/png", "data": "data:image/png,%00%01"}],
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 422
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


# ---------------------------------------------------------------------------
# Images reach the model; bytes do not reach the database
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_images_ride_on_the_newest_user_turn(client, session_factory):
    _, token = await make_user(session_factory, "vision@example.com")
    from api.routes import agent as agent_routes
    from main import app

    runtime = UsageRuntime()
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={
                "content": "which shelf is this?",
                "images": [
                    {"media_type": "image/jpeg", "data": PNG_B64},
                    {"media_type": "image/webp", "data": PNG_B64},
                ],
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 201

        blocks = runtime.seen_messages[0][-1]["content"]
        assert blocks[0] == {"type": "text", "text": "which shelf is this?"}
        assert [b["media_type"] for b in blocks[1:]] == ["image/jpeg", "image/webp"]
        assert all(b["data"] == PNG_B64 for b in blocks[1:])
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_a_photo_on_its_own_is_a_complete_message(client, session_factory):
    """Sending a picture with no caption is the whole point of the feature —
    "what is this?" is implied by the act of sending it."""
    _, token = await make_user(session_factory, "caption@example.com")
    from api.routes import agent as agent_routes
    from main import app

    runtime = UsageRuntime()
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={"images": [{"media_type": "image/png", "data": PNG_B64}]},
            headers=auth_headers(token),
        )
        assert resp.status_code == 201
        blocks = runtime.seen_messages[0][-1]["content"]
        assert [b["type"] for b in blocks] == ["text", "image"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["messages", "messages/stream"])
async def test_a_turn_with_neither_text_nor_images_is_refused(
    client, session_factory, path
):
    _, token = await make_user(session_factory, f"empty-{path.count('/')}@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime()
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/{path}",
            json={"content": "   "},
            headers=auth_headers(token),
        )
        assert resp.status_code == 422
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_only_attachment_metadata_is_persisted(client, session_factory):
    """The row records what was attached; the bytes are not in the database
    (see models.conversation.Message.attachments)."""
    from models.conversation import Message, MessageRole

    _, token = await make_user(session_factory, "meta@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime()
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={
                "content": "what is this?",
                "images": [{"media_type": "image/png", "data": PNG_B64}],
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 201
        assert resp.json()["user_message"]["attachments"] == [
            {
                "media_type": "image/png",
                "size_bytes": len(PNG_BYTES),
                "sha256": hashlib.sha256(PNG_BYTES).hexdigest(),
            }
        ]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    async with session_factory() as session:
        rows = (
            await session.execute(
                select(Message).where(Message.role == MessageRole.user)
            )
        ).scalars().all()
    stored = rows[0]
    assert stored.content == "what is this?"
    # The base64 payload appears nowhere on the row.
    assert PNG_B64 not in json.dumps(
        {"content": stored.content, "attachments": stored.attachments}
    )


@pytest.mark.asyncio
async def test_a_message_without_images_stores_no_attachments(
    client, session_factory
):
    _, token = await make_user(session_factory, "plain@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime()
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={"content": "no pictures here"},
            headers=auth_headers(token),
        )
        assert resp.status_code == 201
        assert resp.json()["user_message"]["attachments"] is None
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


# ---------------------------------------------------------------------------
# Token usage is recorded on both send paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blocking_send_records_usage_and_conversation_totals(
    client, session_factory
):
    _, token = await make_user(session_factory, "billing@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime(
        usage={"input_tokens": 900, "output_tokens": 30}
    )
    try:
        conv_id = await _conversation(client, token)
        for _ in range(2):
            resp = await client.post(
                f"/api/agent/conversations/{conv_id}/messages",
                json={"content": "hello"},
                headers=auth_headers(token),
            )
            assert resp.status_code == 201
        assistant = resp.json()["assistant_message"]
        assert assistant["input_tokens"] == 900
        assert assistant["output_tokens"] == 30
        # The user's own row is an input to the same call, not a second
        # charge, so it carries no counts of its own.
        assert resp.json()["user_message"]["input_tokens"] is None

        thread = await client.get(
            f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
        )
        assert thread.json()["total_input_tokens"] == 1800
        assert thread.json()["total_output_tokens"] == 60
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_streaming_send_records_usage(client, session_factory):
    _, token = await make_user(session_factory, "streambill@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime(
        usage={"input_tokens": 412, "output_tokens": 17}, content="Streamed."
    )
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages/stream",
            json={"content": "hello"},
            headers=auth_headers(token),
        )
        assert resp.status_code == 200
        saved = dict(_parse_sse(resp.text))["saved"]["assistant_message"]
        assert saved["input_tokens"] == 412
        assert saved["output_tokens"] == 17

        thread = await client.get(
            f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
        )
        assert thread.json()["total_input_tokens"] == 412
        assert thread.json()["total_output_tokens"] == 17
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_a_turn_that_reported_nothing_stores_null_not_zero(
    client, session_factory
):
    """A replay-cache hit, or a provider that does not report counts, must
    leave the columns NULL: summing a guessed zero into a cost view would
    understate it and look like a real measurement."""
    _, token = await make_user(session_factory, "nousage@example.com")
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = lambda: UsageRuntime(usage={})
    try:
        conv_id = await _conversation(client, token)
        resp = await client.post(
            f"/api/agent/conversations/{conv_id}/messages",
            json={"content": "hello"},
            headers=auth_headers(token),
        )
        assert resp.status_code == 201
        assert resp.json()["assistant_message"]["input_tokens"] is None
        assert resp.json()["assistant_message"]["output_tokens"] is None

        thread = await client.get(
            f"/api/agent/conversations/{conv_id}", headers=auth_headers(token)
        )
        assert thread.json()["total_input_tokens"] == 0
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


# ---------------------------------------------------------------------------
# Migration 0006
# ---------------------------------------------------------------------------


NEW_COLUMNS = {"input_tokens", "output_tokens", "attachments"}


def _alembic_config(db_path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def _message_columns(db_path) -> set[str]:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        return {c["name"] for c in sa.inspect(engine).get_columns("messages")}
    finally:
        engine.dispose()


def test_migration_0006_adds_the_usage_and_attachment_columns(tmp_path):
    db_path = tmp_path / "usage.db"
    config = _alembic_config(db_path)

    command.upgrade(config, "0004_telegram_link")
    assert NEW_COLUMNS & _message_columns(db_path) == set()

    command.upgrade(config, "0006_message_usage")
    assert NEW_COLUMNS <= _message_columns(db_path)

    command.downgrade(config, "0004_telegram_link")
    assert NEW_COLUMNS & _message_columns(db_path) == set()


def test_migration_0006_tolerates_columns_that_already_exist(tmp_path):
    """The adoption path: a pre-Alembic database is built from model
    metadata — which already has these columns — then stamped and upgraded.
    The guards are what keep that from dying on a duplicate column."""
    import models  # noqa: F401 — registers every model on Base.metadata
    from core.database import Base

    db_path = tmp_path / "adopted.db"
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    assert NEW_COLUMNS <= _message_columns(db_path)

    config = _alembic_config(db_path)
    command.stamp(config, "0001_baseline")
    command.upgrade(config, "head")

    assert NEW_COLUMNS <= _message_columns(db_path)
