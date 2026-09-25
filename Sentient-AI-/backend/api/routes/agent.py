"""Serves the /agent API: conversation CRUD and search, sending a message
(buffered or as an SSE stream) through the AgentRuntime, listing and
deciding pending tool approvals, stopping a running task, and the appliers
that let the Telegram poller run the same chat and approval pipelines.

Why it exists: This is where the HTTP layer, the tool registry, memory
injection and the runtime meet: it builds each turn's tool set and
<permissions> block from the install's capabilities, enforces the per-user rate
limit, persists user and assistant messages with their token usage, and resumes
a paused turn after an approval, so an out-of-band channel reuses this path
instead of a second copy.

Connects to: AgentRuntime (services/agent/runtime.py), the Conversation
and Message tables, the tool registry and capability report, the memory
service and the approval store.
Used by: the web chat UI over HTTP, and main.py, which mounts the router
and hands build_chat_applier / build_decision_applier to the Telegram bot.
"""

from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional, Union, get_args

import asyncio
import base64
import binascii
import hashlib
import json
import re
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core.config import settings
from core.database import async_session, get_db
from core.validation import SafeStr
from models.connector import ConnectorConfig
from models.conversation import Conversation, Message, MessageRole
from models.memory import Memory
from models.pending_action import PendingAction
from models.user import User
from services import capabilities as capability_registry
from services.auth import get_current_user
from services.capabilities.prompt import render_permissions_block
from services.memory import render_memory_block
from services.agent import cancel as agent_cancel
from services.agent.context_manager import compress_tool_result
from services.agent.providers import ProviderError, ProviderNotConfigured
from services.agent.runtime import (
    AgentRuntime,
    EventSink,
    TurnUsage,
    is_browser_tool,
    redact_binary_for_model,
    tool_call_facts,
)
from services.agent.tool_registry import ConnectorSpec, build_tools, effective_tier, resolve_tool

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])

# Where each ProviderNotConfigured is fixed. "not_set_up" is the install's
# gap (first-run setup: an AI provider key); "user_provider_unavailable" is
# the user's own Settings choice. Every answer — the HTTP error, the stream
# error frame, the channel reply — carries the matching code and URL so the
# client can link straight to the fix.
SETUP_URL = "/setup"
SETTINGS_URL = "/settings"

# The install has no usable key although setup was completed (the key was
# removed from .env, or the stored keys were cleared). /setup redirects
# away once setup is complete, so the pointer is Settings instead.
_NOT_SET_UP_CODE = "provider_not_configured"
_UNAVAILABLE_AFTER_SETUP_CODE = "provider_unavailable"

_NOT_CONFIGURED_POINTERS: dict[str, dict[str, str]] = {
    _NOT_SET_UP_CODE: {"setup_url": SETUP_URL},
    _UNAVAILABLE_AFTER_SETUP_CODE: {"settings_url": SETTINGS_URL},
    "user_provider_unavailable": {"settings_url": SETTINGS_URL},
}


async def _setup_completed(installation: Any) -> bool:
    """Whether the owner finished setup. False when unwired or when the
    answer cannot be read: the original setup pointer then stands, and a
    broken probe never turns the not-configured answer into a 500."""
    if installation is None:
        return False
    try:
        return bool(await installation.setup_completed())
    except Exception as exc:
        logger.warning("setup_state_unreadable", error_type=type(exc).__name__)
        return False


async def _not_configured_info(code: str, installation: Any) -> dict[str, str]:
    """``{"code": ..., "<setup|settings>_url": ...}`` for one failure, by the
    code the runtime raised (``ProviderNotConfigured.code``)."""
    if code == _NOT_SET_UP_CODE and await _setup_completed(installation):
        code = _UNAVAILABLE_AFTER_SETUP_CODE
    return {"code": code, **_NOT_CONFIGURED_POINTERS.get(code, {})}


async def _not_configured_http_error(
    exc: ProviderNotConfigured, installation: Any
) -> HTTPException:
    """503 when the install has no usable provider (the service genuinely
    cannot answer anyone); 409 when only this user's pinned provider lacks
    a key — the request conflicts with their own Settings, which they can
    change."""
    status_code = (
        status.HTTP_409_CONFLICT
        if exc.reason == "user_provider_unavailable"
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return HTTPException(
        status_code=status_code,
        detail={
            "message": str(exc),
            **await _not_configured_info(exc.code, installation),
        },
    )


class UserRateLimiter:
    """In-process sliding-window rate limiter keyed by user id, enforcing
    the per-user ``User.rate_limit`` (agent messages per minute) chosen on
    the Settings page.

    NOTE: this is per-process state. Each uvicorn worker enforces the
    limit independently, so a multi-worker / multi-instance deployment
    needs a shared store (e.g. Redis) for globally exact enforcement;
    until then each worker still bounds the user at the configured rate.
    """

    _WINDOW_SECONDS = 60.0
    # How many expired entries a single call may reclaim. Every key is
    # swept at most once, so the total sweep work is proportional to the
    # number of keys ever created — amortized O(1) per request — while the
    # cap keeps one unlucky caller from paying for a whole dictionary of
    # expired windows in a single hot-path call.
    _SWEEP_PER_CALL = 8

    def __init__(self) -> None:
        # An OrderedDict (not defaultdict) because eviction needs an order
        # to walk: entries sit in least-recently-used order, so the bounded
        # sweep in allow() finds expired windows without ever scanning
        # every user. The previous plain dict only ever grew — one key plus
        # one drained deque per distinct user id the worker had ever
        # served, held for the life of the process.
        self._events: OrderedDict[str, deque[float]] = OrderedDict()

    def allow(self, user_id: str, limit: int) -> bool:
        if limit <= 0:  # defensive: never lock an account out entirely
            return True
        now = time.monotonic()
        self._evict_expired(now)

        window = self._events.get(user_id)
        if window is None:
            window = deque()
            self._events[user_id] = window
        else:
            # Refresh recency even when the call is about to be refused, so
            # a user who is actively being throttled stays at the far end of
            # the eviction order rather than drifting toward the front.
            self._events.move_to_end(user_id)

        while window and now - window[0] >= self._WINDOW_SECONDS:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True

    def _evict_expired(self, now: float) -> None:
        """Drop least-recently-used entries whose window has fully aged out.

        The eviction test is on the NEWEST timestamp: an entry only goes
        when every event it holds is already outside the window, i.e. when
        allow() would have trimmed the deque empty anyway. Forgetting such
        a key is indistinguishable from keeping it, which is what makes
        eviction safe to run ahead of the limit check — a user who is
        currently over the limit necessarily has an in-window event, so
        their window can never be reset out from under them by memory
        pressure from other users.
        """
        for _ in range(self._SWEEP_PER_CALL):
            entry = next(iter(self._events.items()), None)
            if entry is None:
                return
            evicted_user, window = entry
            if window and now - window[-1] < self._WINDOW_SECONDS:
                return
            del self._events[evicted_user]


_user_rate_limiter = UserRateLimiter()


def get_runtime(request: Request) -> AgentRuntime:
    """Return the singleton AgentRuntime stored on app.state.

    Raises 503 while the app has not been wired (wire_services has not run;
    a runtime construction error fails startup instead of landing here). A
    missing provider key is not such a failure: the runtime resolves keys
    per turn and a turn without one answers ProviderNotConfigured instead.
    """
    runtime: Optional[AgentRuntime] = getattr(request.app.state, "agent_runtime", None)
    if runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent runtime is not available. Check the server logs.",
        )
    return runtime


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
#
# Identity comes exclusively from the verified JWT (get_current_user), never
# from request bodies or query strings. Accepting a caller-supplied user_id
# here was an IDOR: any client could read or act on another user's data.


class CreateConversationRequest(BaseModel):
    # max_length matches the Conversation.title column (String(512)); without
    # it an over-long title overflows the column and raises an unhandled 500.
    title: SafeStr = Field(default="New Conversation", min_length=1, max_length=512)


class UpdateConversationRequest(BaseModel):
    title: SafeStr = Field(min_length=1, max_length=200)


# Image attachments. The caps are deliberately tight: images are relayed
# verbatim to a paid API, and every vendor rejects oversized payloads
# anyway — far better to answer 422 here than to spend a provider
# round-trip discovering it.
#
# These bound what the server PROCESSES, not what it reads: FastAPI has the
# whole body buffered before any validator or dependency runs, so the
# ceiling on a request body is whatever the ASGI layer allows (today,
# nothing). That gap is not new — a 1GB body was already buffered before
# `content`'s max_length could reject it — but four 5MB images raise the
# legitimate ceiling from ~100KB to ~28MB, which makes a body-size
# middleware the right next piece of work. See the proposal alongside this
# change.
ImageMediaType = Literal["image/png", "image/jpeg", "image/webp", "image/gif"]
ALLOWED_IMAGE_TYPES = get_args(ImageMediaType)
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGES_PER_MESSAGE = 4

# data:<media type>;base64,<payload> — the form a browser's FileReader
# produces, accepted so the client does not have to split it apart.
_DATA_URL_RE = re.compile(
    r"^data:(?P<media_type>[\w.+-]+/[\w.+-]+)(?P<params>;[^,]*)?,", re.IGNORECASE
)


class ImageAttachment(BaseModel):
    """One image sent alongside a chat message.

    ``data`` is base64 with no ``data:`` prefix. A full data URL — what a
    browser's FileReader hands the client — is also accepted and split
    apart, and its own media type then governs: if the URL and the field
    disagree, the bytes came with the URL, so trusting the field would let
    a PNG be relayed to the provider labelled as something else.
    """

    media_type: ImageMediaType = "image/png"
    data: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _split_data_url(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        data = values.get("data")
        if not isinstance(data, str):
            return values
        match = _DATA_URL_RE.match(data)
        if not match:
            return values
        if "base64" not in (match.group("params") or ""):
            raise ValueError("image data URLs must be base64-encoded")
        # Rewritten before field validation, so an unsupported media type
        # carried by the URL is rejected by the Literal like any other.
        return {
            **values,
            "media_type": match.group("media_type").lower(),
            "data": data[match.end():],
        }

    @field_validator("data")
    @classmethod
    def _decodable_and_within_cap(cls, value: str) -> str:
        # Checked before decoding: base64 inflates by 4/3, so bounding the
        # encoded length bounds the work done here, instead of decoding an
        # arbitrarily large string only to find out it was too big.
        if len(value) > MAX_IMAGE_BYTES * 4 // 3 + 4:
            raise ValueError(
                f"image exceeds the {MAX_IMAGE_BYTES // (1024 * 1024)}MB limit"
            )
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("image data is not valid base64") from None
        if not raw:
            raise ValueError("image data is empty")
        if len(raw) > MAX_IMAGE_BYTES:
            raise ValueError(
                f"image exceeds the {MAX_IMAGE_BYTES // (1024 * 1024)}MB limit"
            )
        return value

    def metadata(self) -> dict[str, Any]:
        """What is persisted on the Message row: enough to tell a later
        reader what was attached, none of the bytes. The digest is what a
        future object store would key the blob by."""
        raw = base64.b64decode(self.data, validate=True)
        return {
            "media_type": self.media_type,
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }


class SendMessageRequest(BaseModel):
    # No min_length: a photo on its own is a complete question ("what is
    # this?" is implied by sending it). The routes still reject a turn that
    # is empty of both text and images.
    content: SafeStr = Field(default="", max_length=100_000)
    images: list[ImageAttachment] = Field(
        default_factory=list, max_length=MAX_IMAGES_PER_MESSAGE
    )

    def is_empty(self) -> bool:
        return not self.content.strip() and not self.images


class MessageResponse(BaseModel):
    id: uuid.UUID
    conversation_id: uuid.UUID
    role: MessageRole
    content: str
    tool_calls: Optional[Union[Dict, List]] = None
    attachments: Optional[List] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cache_read_tokens: Optional[int] = None
    cache_write_tokens: Optional[int] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ConversationResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime
    messages: list[MessageResponse] = []
    # Everything the provider has billed for this thread, so a cost view
    # needs one request rather than a scan of the transcript.
    total_input_tokens: int = 0
    total_output_tokens: int = 0

    model_config = {"from_attributes": True}


class ConversationListItem(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ToolCallOut(BaseModel):
    name: str
    result: Any
    tool_call_id: Optional[str] = None


class TurnImageOut(BaseModel):
    """A screenshot one of this turn's tools took, for the live web view
    only: rows keep the placeholder (spec §9), so a reload shows none.
    ``index`` is the tool call it belongs to; ``tool`` and ``source`` (the
    page's host or the app) are the facts its alt text names."""

    tool: str
    source: Optional[str] = None
    index: int
    data_url: str


class PendingApprovalOut(BaseModel):
    action_id: str
    tool_name: str
    arguments: Dict[str, Any] = {}
    reason: str
    expires_at: Optional[str] = None
    conversation_id: Optional[str] = None
    # Warning surfaced on the approval card when the action's arguments were
    # shaped by untrusted external content.
    risk_note: Optional[str] = None


class BlockedActionOut(BaseModel):
    tool_name: str
    reason: str
    policy: str


class AgentTurnResponse(BaseModel):
    """The full result of one chat turn: saved user/assistant messages plus
    structured runtime metadata for the UI to render.
    """

    user_message: MessageResponse
    assistant_message: MessageResponse
    tool_calls: list[ToolCallOut] = []
    pending_approvals: list[PendingApprovalOut] = []
    blocked_actions: list[BlockedActionOut] = []
    images: list[TurnImageOut] = []


class ApprovalDecisionRequest(BaseModel):
    approved: bool


class ApprovalDecisionResponse(BaseModel):
    action_id: str
    approved: bool
    result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


async def _capability_view(installation: Any) -> tuple[frozenset[str], str]:
    """The owner's effective capability set and the ``<permissions>`` block
    describing it, both from ONE report so the tools offered and what the
    agent is told about them can never disagree.

    ``installation`` is ``app.state.installation``; unwired (a test app
    that never ran the lifespan) the registry defaults stand in, so screen
    capture stays off exactly as it would on a fresh install.
    """
    if installation is not None:
        statuses = await installation.report()
    else:
        statuses = capability_registry.report(
            capability_registry.default_switches(),
            capability_registry.default_context(),
        )
    enabled = frozenset(s.key for s in statuses if s.effective == "on")
    return enabled, render_permissions_block(statuses)


async def _build_tools_and_memory(
    mcp_catalog: Any,
    current_user: User,
    db: AsyncSession,
    installation: Any = None,
) -> tuple[list, Optional[str], str]:
    """Build the runtime tool list (connector + MCP tools), the memory
    block and the permissions block for a user. Shared by the blocking and
    streaming send paths so both offer exactly the same tools and context.
    Takes the MCP catalog and installation service directly (not a
    Request) so out-of-band callers — the Telegram approval poller — can
    run the same pipeline without an HTTP request.
    """
    conn_result = await db.execute(
        select(ConnectorConfig).where(
            ConnectorConfig.user_id == current_user.id,
            ConnectorConfig.is_active.is_(True),
        )
    )
    connector_rows = list(conn_result.scalars().all())
    connector_specs = [
        ConnectorSpec(
            connector_type=c.connector_type.value,
            is_active=c.is_active,
            granted_scopes=tuple(c.granted_scopes) if c.granted_scopes else None,
            permission_tier=(
                c.permission_tier.value if c.permission_tier else "user_confirm"
            ),
            # Two active rows of one type collide on tool name without
            # these: the model sees a single entry and only the newest row
            # is reachable (see build_tools).
            connector_id=str(c.id),
            display_name=c.display_name,
        )
        for c in connector_rows
    ]
    enabled_capabilities, permissions_text = await _capability_view(installation)
    tools = build_tools(
        connector_specs,
        user_default_tier=current_user.default_permission_tier,
        is_admin=current_user.is_admin,
        enabled_capabilities=enabled_capabilities,
    )

    if any(spec.connector_type == "mcp" for spec in connector_specs):
        if mcp_catalog is not None:
            from services.mcp.integration import slugify_label, split_mcp_tool

            excluded_labels = {
                slugify_label(c.display_name)
                for c in connector_rows
                if c.connector_type.value == "mcp"
                and effective_tier(
                    c.permission_tier.value if c.permission_tier else None,
                    current_user.default_permission_tier,
                )
                in ("admin_only", "hard_blocked")
            }
            mcp_tools = await mcp_catalog.tools_for_user(str(current_user.id))
            if excluded_labels:
                mcp_tools = [
                    t
                    for t in mcp_tools
                    if (split_mcp_tool(t.name) or ("", ""))[0] not in excluded_labels
                ]
            tools += mcp_tools

    memory_block: Optional[str] = None
    if getattr(current_user, "memory_enabled", True):
        mem_result = await db.execute(
            select(Memory)
            .where(Memory.user_id == current_user.id)
            .order_by(Memory.created_at.desc())
        )
        memory_block = render_memory_block(list(mem_result.scalars().all()))

    return tools, memory_block, permissions_text


async def _get_owned_conversation(
    conversation_id: uuid.UUID,
    user: User,
    db: AsyncSession,
    *,
    with_messages: bool = False,
) -> Conversation:
    """Load a conversation and verify ownership.

    Returns 404 (not 403) for conversations owned by someone else so the
    endpoint does not leak which conversation ids exist.

    ``with_messages`` eager-loads the transcript. Conversation.messages is
    lazy="raise", so only the callers that actually serialize messages pay
    for loading them.
    """
    stmt = select(Conversation).where(Conversation.id == conversation_id)
    if with_messages:
        stmt = stmt.options(selectinload(Conversation.messages))
    result = await db.execute(stmt)
    conversation = result.scalar_one_or_none()
    if conversation is None or conversation.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        )
    return conversation


def _attach_images(
    history: list[dict[str, Any]], images: list[ImageAttachment]
) -> None:
    """Replace the newest user turn's text content with multimodal blocks.

    History is rebuilt from Message rows, which hold text only — the image
    bytes exist for exactly one turn, in memory, on their way to the
    provider. This splices them back onto the turn they arrived with, and
    is a no-op if the tail is not the user message that was just written.
    """
    if not images or not history or history[-1].get("role") != "user":
        return
    history[-1] = {
        "role": "user",
        "content": [
            {"type": "text", "text": history[-1].get("content", "")},
            *(
                {
                    "type": "image",
                    "media_type": image.media_type,
                    "data": image.data,
                }
                for image in images
            ),
        ],
    }


def _usage_columns(
    usage: Optional[Dict[str, Any]],
    provider: Optional[str],
    model: Optional[str],
) -> dict[str, Any]:
    """Map a runtime usage dict, and the provider/model that ran the turn,
    onto the Message columns.

    A turn that reported nothing (a replay-cache hit, a provider that does
    not return counts) stores NULL rather than 0 — "not billed" and "we
    never found out" are different facts, and summing a guessed zero into a
    cost view would quietly understate it.

    Provider and model are required arguments so no persistence path can
    forget them: without the model a turn's tokens cannot be priced.
    Callers pass the pair the runtime reports it ran on
    (``AgentResponse.provider``/``model``, or the stream's done frame) —
    never the account row, whose NULL means "whatever the install default
    was", which is not a price. The server default is only a fallback for
    a runtime that reported nothing.
    """
    usage = usage or {}

    def _count(key: str) -> Optional[int]:
        value = usage.get(key)
        return value if isinstance(value, int) else None

    return {
        "input_tokens": _count("input_tokens"),
        "output_tokens": _count("output_tokens"),
        "cache_read_tokens": _count("cache_read_tokens"),
        "cache_write_tokens": _count("cache_write_tokens"),
        "llm_provider": (provider or settings.LLM_PROVIDER or "").strip().lower()[:32]
        or None,
        "llm_model": (model or settings.LLM_MODEL or "").strip()[:128] or None,
    }


def _like_pattern(term: str) -> str:
    """Build a contains-pattern, neutralizing LIKE's own wildcards.

    Without this, searching for ``100%`` or ``draft_1`` would be read as a
    pattern rather than as text — ``%`` matching everything is the worst
    case, since it silently returns the whole table as if it were a hit.
    The escape character is declared on the comparison itself below.
    """
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@router.get("/conversations", response_model=list[ConversationListItem])
async def list_conversations(
    q: Optional[str] = Query(
        default=None,
        max_length=200,
        description="Filter to conversations whose title or messages contain this text",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Conversation]:
    """List the authenticated user's conversations, newest first.

    With ``q``, returns only conversations whose title matches or that
    contain a matching message. Matching happens in SQL — a transcript is
    unbounded, so filtering in Python would mean loading every message the
    user has ever sent to answer one search.
    """
    query = select(Conversation).where(Conversation.user_id == current_user.id)

    term = (q or "").strip()
    if term:
        pattern = _like_pattern(term)
        # EXISTS rather than a JOIN: a conversation with twenty matching
        # messages must come back once, not twenty times.
        message_match = (
            select(Message.id)
            .where(
                Message.conversation_id == Conversation.id,
                Message.content.ilike(pattern, escape="\\"),
            )
            .exists()
        )
        query = query.where(
            or_(Conversation.title.ilike(pattern, escape="\\"), message_match)
        )

    query = query.order_by(Conversation.updated_at.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post(
    "/conversations",
    response_model=ConversationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_conversation(
    body: CreateConversationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConversationResponse:
    """Start a new agent conversation for the authenticated user."""
    conversation = Conversation(user_id=current_user.id, title=body.title)
    db.add(conversation)
    await db.flush()
    await db.refresh(conversation)
    # Built explicitly rather than validated from the ORM object: a brand
    # new conversation has no messages, and Conversation.messages is
    # lazy="raise", so serializing straight from the model would try to
    # load a collection that is known to be empty.
    return ConversationResponse(
        id=conversation.id,
        user_id=conversation.user_id,
        title=conversation.title,
        created_at=conversation.created_at,
        updated_at=conversation.updated_at,
        messages=[],
    )


@router.get("/conversations/{conversation_id}", response_model=ConversationResponse)
async def get_conversation(
    conversation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConversationResponse:
    """Retrieve one of the authenticated user's conversations with messages,
    plus what the provider has billed across the thread.

    The totals are summed from the transcript already loaded here rather
    than with an aggregate query — the rows are in hand, and this endpoint
    is held to a query budget (tests/test_query_efficiency.py).
    """
    conversation = await _get_owned_conversation(
        conversation_id, current_user, db, with_messages=True
    )
    messages = list(conversation.messages)
    return ConversationResponse(
        id=conversation.id,
        user_id=conversation.user_id,
        title=conversation.title,
        created_at=conversation.created_at,
        updated_at=conversation.updated_at,
        messages=[MessageResponse.model_validate(m) for m in messages],
        total_input_tokens=sum(m.input_tokens or 0 for m in messages),
        total_output_tokens=sum(m.output_tokens or 0 for m in messages),
    )


@router.patch("/conversations/{conversation_id}", response_model=ConversationListItem)
async def update_conversation(
    conversation_id: uuid.UUID,
    body: UpdateConversationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Conversation:
    """Rename one of the authenticated user's conversations (owner-scoped)."""
    title = body.title.strip()
    if not title:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Title cannot be blank",
        )
    conversation = await _get_owned_conversation(conversation_id, current_user, db)
    conversation.title = title
    conversation.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(conversation)
    return conversation


@router.delete("/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(
    conversation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete one of the authenticated user's conversations and all of its
    messages (owner-scoped). Returns 204 on success.

    Postgres cascades via the FK ``ondelete=CASCADE``; the children are
    also deleted explicitly so backends without FK enforcement (e.g. the
    SQLite test database) behave identically.
    """
    conversation = await _get_owned_conversation(conversation_id, current_user, db)
    await db.execute(
        delete(PendingAction).where(PendingAction.conversation_id == conversation.id)
    )
    await db.execute(delete(Message).where(Message.conversation_id == conversation.id))
    await db.delete(conversation)
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=AgentTurnResponse,
    status_code=status.HTTP_201_CREATED,
)
async def send_message(
    conversation_id: uuid.UUID,
    body: SendMessageRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    runtime: AgentRuntime = Depends(get_runtime),
) -> AgentTurnResponse:
    """Send a user message, run the agent, and persist the assistant reply.

    Returns both saved messages plus any tool calls, pending approvals, or
    blocked actions surfaced by the runtime.
    """
    if body.is_empty():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message content cannot be empty",
        )

    # Per-user rate limit (Settings page). In-process sliding window; see
    # UserRateLimiter for the multi-worker caveat.
    if not _user_rate_limiter.allow(str(current_user.id), current_user.rate_limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: your account allows "
                f"{current_user.rate_limit} agent messages per minute. "
                "Wait a moment and try again."
            ),
        )

    # The message is accepted: a Stop pressed from here on ends this turn,
    # even while the setup below (history, tools, memory) is still running.
    stop_mark = agent_cancel.mark(str(current_user.id))

    conversation = await _get_owned_conversation(conversation_id, current_user, db)

    # 1. Persist the user message. Only attachment METADATA is stored; see
    #    models.conversation.Message.attachments for why the bytes are not.
    user_message = Message(
        conversation_id=conversation.id,
        role=MessageRole.user,
        content=body.content.strip(),
        attachments=[image.metadata() for image in body.images] or None,
    )
    db.add(user_message)
    await db.flush()
    await db.refresh(user_message)

    # 2. Build chat history for the runtime
    history_result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation.id)
        .order_by(Message.created_at)
    )
    rows = list(history_result.scalars().all())
    history = [{"role": m.role.value, "content": m.content} for m in rows]
    task_id = _task_id_of(rows)
    _attach_images(history, body.images)

    # 3. Build the tool list (connectors + MCP) and memory block. The
    #    runtime's permission adapter and executor (injected at startup)
    #    handle tiering, approval, and dispatch. A user with no connectors
    #    gets an empty list and simply chats with the LLM.
    tools, memory_block, permissions_text = await _build_tools_and_memory(
        getattr(request.app.state, "mcp_catalog", None),
        current_user,
        db,
        getattr(request.app.state, "installation", None),
    )

    # Release the pooled connection before the LLM turn: committing ends
    # the transaction, so the minutes a slow provider can take are not
    # spent pinning one of the pool's connections (which would let ~30
    # concurrent chats starve every other endpoint). The user message is
    # durable from here even if the turn fails.
    await db.commit()

    try:
        agent_response = await runtime.chat(
            messages=history,
            tools=tools,
            user_id=str(current_user.id),
            conversation_id=str(conversation.id),
            llm_provider=current_user.llm_provider,
            llm_model=current_user.llm_model,
            memory_block=memory_block,
            permissions_text=permissions_text,
            task_id=task_id,
            stop_mark=stop_mark,
        )
    except ProviderNotConfigured as exc:
        # Not an upstream failure: no key for the provider this turn needs.
        # 503 + setup_url when the install is not set up (settings_url once
        # setup is complete), 409 + settings_url when only the user's own
        # choice is unavailable.
        logger.warning(
            "send_message_provider_not_configured",
            conversation_id=str(conversation.id),
            provider=exc.provider,
            reason=exc.reason,
        )
        raise await _not_configured_http_error(
            exc, getattr(request.app.state, "installation", None)
        ) from None
    except ProviderError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from None

    # 4. Persist the assistant message (with tool calls if any) and bump
    #    the conversation's activity timestamp so newest-first ordering in
    #    the sidebar reflects real activity.
    assistant_message = Message(
        conversation_id=conversation.id,
        role=MessageRole.assistant,
        content=agent_response.content,
        # Image data is delivered, never stored (spec §9): the row keeps the placeholder the model saw.
        tool_calls=redact_binary_for_model(agent_response.tool_calls) or None,
        **_usage_columns(
            agent_response.usage, agent_response.provider, agent_response.model
        ),
    )
    db.add(assistant_message)
    conversation.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(assistant_message)

    return AgentTurnResponse(
        user_message=MessageResponse.model_validate(user_message),
        assistant_message=MessageResponse.model_validate(assistant_message),
        # Screenshots travel once, checked, in ``images``; each result keeps
        # the placeholder its row holds.
        tool_calls=[
            ToolCallOut(
                name=tc.get("name", ""),
                result=redact_binary_for_model(tc.get("result")),
                tool_call_id=tc.get("tool_call_id"),
            )
            for tc in agent_response.tool_calls
        ],
        pending_approvals=[
            PendingApprovalOut(
                action_id=pa.action_id,
                tool_name=pa.tool_name,
                arguments=pa.arguments,
                reason=pa.reason,
                expires_at=pa.expires_at,
                conversation_id=pa.conversation_id,
                risk_note=pa.risk_note,
            )
            for pa in agent_response.pending_approvals
        ],
        blocked_actions=[
            BlockedActionOut(
                tool_name=ba.tool_name,
                reason=ba.reason,
                policy=ba.policy,
            )
            for ba in agent_response.blocked_actions
        ],
        images=[TurnImageOut(**image) for image in _turn_images(agent_response.tool_calls)],
    )


def _sse(event: str, data: dict[str, Any]) -> str:
    """Format one Server-Sent Event frame."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


# Session factory for persistence that must outlive the request (client
# disconnected mid-stream). Module-level so tests can substitute their own
# factory.
_detached_session_factory = async_session


async def _persist_assistant_detached(
    conversation_id: uuid.UUID,
    content: str,
    tool_calls: Optional[list],
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
) -> None:
    """Persist an assistant turn outside any request session.

    Used when the SSE consumer disconnected before the turn was saved: the
    turn's side effects (tools that executed) already happened, so the
    transcript must record them — otherwise the rebuilt history would show
    no reply and the model would repeat the side effect on retry.
    """
    try:
        async with _detached_session_factory() as session:
            session.add(
                Message(
                    conversation_id=conversation_id,
                    role=MessageRole.assistant,
                    content=content,
                    tool_calls=redact_binary_for_model(tool_calls) or None,
                    **_usage_columns(usage, llm_provider, llm_model),
                )
            )
            conversation = await session.get(Conversation, conversation_id)
            if conversation is not None:
                conversation.updated_at = datetime.now(timezone.utc)
            await session.commit()
        logger.info(
            "assistant_turn_persisted_after_disconnect",
            conversation_id=str(conversation_id),
        )
    except Exception as exc:  # pragma: no cover - depends on DB failure
        logger.error(
            "assistant_turn_persist_failed_after_disconnect",
            conversation_id=str(conversation_id),
            error=str(exc),
        )


@router.post("/conversations/{conversation_id}/messages/stream")
async def stream_message(
    conversation_id: uuid.UUID,
    body: SendMessageRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    runtime: AgentRuntime = Depends(get_runtime),
) -> StreamingResponse:
    """Streaming variant of send_message using Server-Sent Events.

    Emits real-time progress (tool_call/tool_result/pending_approval/blocked
    as the agent loop reaches them), then typewriter-streams the final
    answer, then a ``done`` event carrying the saved message ids. Every
    security layer is identical to the blocking path — the stream is an
    adapter over the same ``runtime.chat``.

    The user message is persisted before streaming; the assistant message is
    persisted in a fresh session once the turn completes, so the DB write
    does not depend on the request session staying open across the stream.
    """
    if body.is_empty():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message content cannot be empty",
        )
    if not _user_rate_limiter.allow(str(current_user.id), current_user.rate_limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: your account allows "
                f"{current_user.rate_limit} agent messages per minute. "
                "Wait a moment and try again."
            ),
        )

    # Accepted: a Stop pressed from here on ends this turn (see send_message).
    stop_mark = agent_cancel.mark(str(current_user.id))

    conversation = await _get_owned_conversation(conversation_id, current_user, db)

    user_message = Message(
        conversation_id=conversation.id,
        role=MessageRole.user,
        content=body.content.strip(),
        attachments=[image.metadata() for image in body.images] or None,
    )
    db.add(user_message)
    await db.flush()
    await db.refresh(user_message)
    user_message_out = MessageResponse.model_validate(user_message).model_dump()

    history_result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation.id)
        .order_by(Message.created_at)
    )
    rows = list(history_result.scalars().all())
    history = [{"role": m.role.value, "content": m.content} for m in rows]
    task_id = _task_id_of(rows)
    _attach_images(history, body.images)
    installation = getattr(request.app.state, "installation", None)
    tools, memory_block, permissions_text = await _build_tools_and_memory(
        getattr(request.app.state, "mcp_catalog", None),
        current_user,
        db,
        installation,
    )
    conv_id = conversation.id
    user_provider = current_user.llm_provider
    user_model = current_user.llm_model
    user_id_str = str(current_user.id)

    # Release the pooled connection for the duration of the stream: the
    # session object stays usable (persistence below reacquires briefly),
    # but the minutes-long LLM turn no longer pins a pool slot. Also makes
    # the user message durable even if the stream dies.
    await db.commit()

    async def _persist_orphaned(response) -> None:
        # The client went away before the turn was saved; record it with a
        # session of our own so the executed tools aren't lost from history.
        await _persist_assistant_detached(
            conv_id,
            response.content or "",
            response.tool_calls or None,
            response.usage,
            response.provider,
            response.model,
        )

    async def event_stream():
        yield _sse("user_message", {"user_message": user_message_out})

        final_content = ""
        tool_calls_payload: list[dict[str, Any]] = []
        usage_payload: dict[str, Any] = {}
        # The pair the turn actually ran on, from the done frame.
        turn_provider: Optional[str] = None
        turn_model: Optional[str] = None
        turn_done = False
        turn_errored = False
        saved_confirmed = False
        try:
            try:
                async for event in runtime.stream_chat(
                    messages=history,
                    tools=tools,
                    user_id=user_id_str,
                    conversation_id=str(conv_id),
                    llm_provider=user_provider,
                    llm_model=user_model,
                    memory_block=memory_block,
                    on_orphaned=_persist_orphaned,
                    permissions_text=permissions_text,
                    task_id=task_id,
                    stop_mark=stop_mark,
                ):
                    etype = event.get("type", "message")
                    data = event.get("data", {})
                    if etype == "ping":
                        # SSE comment frame: keeps proxies from timing the
                        # stream out during silent stretches; ignored by
                        # spec-compliant parsers (and ours).
                        yield ": ping\n\n"
                        continue
                    if etype == "error":
                        # The runtime follows an error frame with an empty
                        # done frame; remember it so the failed turn is not
                        # persisted as an empty assistant message below.
                        turn_errored = True
                        code = str(data.get("code"))
                        if code in _NOT_CONFIGURED_POINTERS:
                            # Same code and pointer the blocking route's
                            # 503/409 carries (setup_url or settings_url).
                            data = {
                                **data,
                                **await _not_configured_info(code, installation),
                            }
                    if etype == "done":
                        final_content = data.get("content", "")
                        tool_calls_payload = data.get("tool_calls", []) or []
                        usage_payload = data.get("usage", {}) or {}
                        turn_provider = data.get("provider") or None
                        turn_model = data.get("model") or None
                        turn_done = True
                        if tool_calls_payload:
                            # As send_message: the screenshots once, checked,
                            # and the tool calls with the row's placeholder.
                            data = {
                                **data,
                                "tool_calls": redact_binary_for_model(tool_calls_payload),
                                "images": _turn_images(tool_calls_payload),
                            }
                    yield _sse(etype, data)
            except GeneratorExit:
                raise
            except Exception:  # pragma: no cover - defensive
                yield _sse("error", {"reason": "The assistant failed to respond."})
                yield _sse("done", {})
                return

            if turn_errored or not (final_content.strip() or tool_calls_payload):
                # Errored or empty turn: nothing worth persisting. The client
                # already received the error frame; writing an empty row here
                # is what used to leave permanent blank bubbles in the
                # transcript.
                yield _sse("saved", {"assistant_message": None})
                return

            # Persist the assistant message. The request DB session is still
            # open here — FastAPI finalizes yield-dependencies only after the
            # streaming response body is exhausted — and using it means the
            # write respects the same session (and test overrides) as the
            # rest of the request.
            try:
                assistant = Message(
                    conversation_id=conv_id,
                    role=MessageRole.assistant,
                    content=final_content,
                    tool_calls=redact_binary_for_model(tool_calls_payload) or None,
                    **_usage_columns(usage_payload, turn_provider, turn_model),
                )
                db.add(assistant)
                conversation.updated_at = datetime.now(timezone.utc)
                await db.flush()
                await db.refresh(assistant)
                assistant_out = MessageResponse.model_validate(assistant).model_dump()
            except Exception:  # pragma: no cover - defensive
                # The content already streamed; a persistence failure just
                # means the client should refetch the thread on next load
                # (the finally below retries with a detached session). Roll
                # back so a half-flushed write can't ALSO commit at request
                # teardown and duplicate the detached retry.
                try:
                    await db.rollback()
                except Exception:
                    pass
                yield _sse("saved", {"assistant_message": None})
            else:
                yield _sse("saved", {"assistant_message": assistant_out})
                saved_confirmed = True
        finally:
            if (
                turn_done
                and not turn_errored
                and not saved_confirmed
                and (final_content.strip() or tool_calls_payload)
            ):
                # The consumer disconnected between the turn completing and
                # the saved frame being delivered. The request session's
                # write is rolled back with the aborted request, so persist
                # with a detached session instead. (Disconnects BEFORE the
                # done event are covered by on_orphaned above.)
                asyncio.create_task(
                    _persist_assistant_detached(
                        conv_id,
                        final_content,
                        tool_calls_payload,
                        usage_payload,
                        turn_provider,
                        turn_model,
                    )
                )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable proxy buffering (nginx)
            "Connection": "keep-alive",
        },
    )


@router.get("/approvals", response_model=list[PendingApprovalOut])
async def list_pending_approvals(
    current_user: User = Depends(get_current_user),
    runtime: AgentRuntime = Depends(get_runtime),
) -> list[PendingApprovalOut]:
    """Return the authenticated user's currently-pending approval requests."""
    pending = await runtime.list_pending_approvals(str(current_user.id))
    return [
        PendingApprovalOut(
            action_id=p.action_id,
            tool_name=p.tool_name,
            arguments=p.arguments,
            reason=p.reason,
            expires_at=p.expires_at,
            conversation_id=p.conversation_id,
            risk_note=p.risk_note,
        )
        for p in pending
    ]


# Most messages a Telegram turn (or a resume after an approval) reads back.
# The context manager keeps only the newest 12 verbatim and folds the rest
# into a size-capped summary, so rows older than this could only ever reach
# the model as a clipped summary line — not worth loading every row of a
# thread that is reused for months.
CHANNEL_HISTORY_LIMIT = 60

# Assistant row written when a turn ends without a reply (stopped from the
# chat, or failed after some model calls were already billed). It keeps the
# transcript alternating user/assistant and carries the billed tokens.
_STOPPED_REPLY = "[Stopped before the reply was finished.]"
_FAILED_REPLY = "[No reply: the model provider returned an error.]"


async def _recent_messages(
    db: AsyncSession, conversation_id: Any, limit: int = CHANNEL_HISTORY_LIMIT
) -> list[Any]:
    """The newest ``limit`` messages of a conversation, oldest first, with
    only the columns a turn uses (id, role, content): ``tool_calls`` can
    hold whole tool results, screenshot data URLs included, that the
    history never needs."""
    rows = (
        await db.execute(
            select(Message.id, Message.role, Message.content)
            .where(Message.conversation_id == conversation_id)
            .order_by(Message.created_at.desc())
            .limit(limit)
        )
    ).all()
    return list(reversed(rows))


def _unfinished_turn_message(
    conversation_id: Any, turn: TurnUsage, content: str
) -> Message:
    """The row that closes a turn that never returned: its billed tokens,
    and the tool calls it recorded before it ended (a call a chat's /stop
    landed on still finishes and is recorded, runtime._RunsToEnd)."""
    return Message(
        conversation_id=conversation_id,
        role=MessageRole.assistant,
        content=content,
        tool_calls=redact_binary_for_model(turn.tool_calls) or None,
        **_usage_columns(turn.usage, turn.provider, turn.model),
    )


@dataclass
class ApprovedCall:
    """The call an approval just ran, for the turn resumed after it: the
    tool, the result as the tool returned it, and the id of the transcript
    row that records the decision (``_decide_and_record``)."""

    tool_name: str
    result: Any
    row_id: Any


@dataclass
class ResumedTurn:
    """What the turn resumed after an approval produced: the assistant row
    to persist, and what a channel's reply must add to its text — the
    approvals the turn parked, the calls security policy blocked, and the
    photos it captured (the same facts ``build_chat_applier`` returns for
    a message turn)."""

    message: Message
    pending_approvals: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    images: list[dict[str, str]] = field(default_factory=list)


def resume_failure_text(exc: BaseException) -> str:
    """Why the turn resumed after an approval could not go on, in plain
    words for the person: the kind of failure, never the provider's
    response body, a key or a traceback (a ProviderError's detail carries
    the vendor's own text). A not-configured provider keeps its own
    sentence, which names the fix."""
    if isinstance(exc, ProviderNotConfigured):
        return str(exc)
    if isinstance(exc, ProviderError):
        status = exc.status_code
        detail = (exc.detail or "").lower()
        if status == 429:
            return "the AI provider rate-limited the request"
        if status in (401, 403):
            return "the AI provider rejected the API key"
        if status is not None and status >= 500:
            return "the AI provider had a server error"
        if status is not None and status >= 400:
            return "the AI provider rejected the request"
        if "could not reach" in detail:
            return "the AI provider could not be reached"
        if "empty" in detail:
            return "the AI model returned an empty reply"
        return "the AI provider returned an error"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "the request timed out"
    return "an unexpected error occurred"


# Longest toolkit-written error a channel's fallback line quotes.
_APPROVED_ERROR_CHARS = 200


def _approved_action_line(result: Dict[str, Any]) -> str:
    """What the approved action did, for a channel's reply when the resumed
    turn left none — from facts only: the computer toolkit's own sentence
    for a desktop.act (``open Calendar``), the tool's name otherwise. A
    desktop result that says it failed quotes the toolkit's error text (its
    own words, never the screen's); any other tool's failure is only named,
    since its error text can come from a third party."""
    tool = str(result.get("tool") or "").strip() or "the action"
    outcome = result.get("result")
    if not isinstance(outcome, dict):
        return f"The approved action ran: {tool}."
    error = outcome.get("error")
    failed = outcome.get("ok") is False or (isinstance(error, str) and error.strip())
    if failed:
        if tool.startswith("desktop.") and isinstance(error, str) and error.strip():
            return (
                "The approved action did not go through: "
                f"{' '.join(error.split())[:_APPROVED_ERROR_CHARS]}"
            )
        return f"The approved action did not go through: {tool} reported an error."
    did = outcome.get("did")
    if tool.startswith("desktop.") and isinstance(did, str) and did.strip():
        return f"The approved action ran: {' '.join(did.split())}."
    return f"The approved action ran: {tool}."


def _channel_photos(tool_calls: Any, account: bool) -> list[dict[str, str]]:
    """The photos a channel delivers for a turn: images its tools captured
    (web.screenshot, desktop.screenshot, browser screenshots and handoffs),
    at most MAX_CHANNEL_IMAGES so a turn that loops on a screenshot tool
    cannot flood the chat. On a turn that read a logged-in site
    (``account``), captions lose their URL queries (spec §9)."""
    images: list[dict[str, str]] = []
    for tc in tool_calls if isinstance(tool_calls, list) else []:
        if len(images) >= MAX_CHANNEL_IMAGES:
            break
        name = str(tc.get("name", ""))
        result = tc.get("result")
        data_url = _channel_image(name, result)
        if data_url is None or not isinstance(result, dict):
            continue
        caption = _channel_caption(name, result)
        images.append(
            {"data_url": data_url, "caption": strip_url_queries(caption) if account else caption}
        )
    return images


async def _resume_after_approval(
    mcp_catalog: Any,
    current_user: User,
    db: AsyncSession,
    runtime: AgentRuntime,
    conversation: Conversation,
    installation: Any = None,
    turn: Optional[TurnUsage] = None,
    stop_mark: Optional[int] = None,
    on_event: Optional[EventSink] = None,
    approved: Optional[ApprovedCall] = None,
) -> Optional[ResumedTurn]:
    """Run one more agent turn after an approved action executed.

    The model gets the tool output it was waiting on as the last, user-role
    message of its history: the approved call's result whole, in the
    runtime's tool-result envelope (``AgentRuntime.approved_call_message``),
    in place of the transcript's "[Approved] Executed ... Result:" row. That
    row is cut at 2000 characters (a desktop.act's fresh outline is mostly
    gone by then), and as the newest row it would end the history on an
    assistant turn, which a provider reads as a continuation of the model's
    own words rather than something to answer (Gemini returns an empty
    completion for one). Without ``approved`` the rows are sent as they are.
    Returns the turn (see :class:`ResumedTurn`) or None when there is
    nothing to add.

    Tools are rebuilt exactly as the send path does, so the resumed turn is
    subject to the same permissions, taint gate, and scanning — an approval
    unlocks the one action the user approved, not a freer agent.

    ``turn``, when given, is filled in with the resumed turn's usage and
    model (see :class:`TurnUsage`), so a channel can show what it cost.

    ``stop_mark`` is the ``resume_stop_mark`` ``approve_action`` returned:
    a Stop pressed while the card waited, or after the Approve tap, ends
    this turn before its first model call.

    ``on_event``, when given, receives this turn's progress events live (a
    channel's progress lines).
    """
    rows = await _recent_messages(db, conversation.id)
    if approved is not None:
        history = [
            {"role": r.role.value, "content": r.content}
            for r in rows
            if r.id != approved.row_id
        ]
        history.append(
            {
                "role": "user",
                "content": runtime.approved_call_message(approved.tool_name, approved.result),
            }
        )
    else:
        history = [{"role": r.role.value, "content": r.content} for r in rows]
    if not history:
        return None
    # The decision row is an assistant message, so this is still the user
    # message that started the task: the resume keeps its caps.
    task_id = _task_id_of(rows)

    tools, memory_block, permissions_text = await _build_tools_and_memory(
        mcp_catalog, current_user, db, installation
    )
    # Return the pooled connection before the (potentially minutes-long)
    # resumed turn; everything written so far — the decision message — is
    # durable from here.
    await db.commit()
    turn = turn if turn is not None else TurnUsage()
    try:
        agent_response = await runtime.chat(
            messages=history,
            tools=tools,
            user_id=str(current_user.id),
            conversation_id=str(conversation.id),
            llm_provider=current_user.llm_provider,
            llm_model=current_user.llm_model,
            memory_block=memory_block,
            permissions_text=permissions_text,
            task_id=task_id,
            usage_sink=turn,
            stop_mark=stop_mark,
            event_sink=on_event,
        )
    except asyncio.CancelledError:
        # Stopped from a chat channel mid-turn: keep the calls already
        # billed, then let the cancellation finish unwinding.
        db.add(_unfinished_turn_message(conversation.id, turn, _STOPPED_REPLY))
        await db.commit()
        raise
    if not (agent_response.content or "").strip():
        return None
    message = Message(
        conversation_id=conversation.id,
        role=MessageRole.assistant,
        content=agent_response.content,
        tool_calls=redact_binary_for_model(agent_response.tool_calls) or None,
        **_usage_columns(
            agent_response.usage, agent_response.provider, agent_response.model
        ),
    )
    # Photos come from the live response, before redaction (spec §9).
    return ResumedTurn(
        message=message,
        pending_approvals=[pa.tool_name for pa in agent_response.pending_approvals],
        blocked=[ba.tool_name for ba in agent_response.blocked_actions],
        images=_channel_photos(
            agent_response.tool_calls, _account_mode(agent_response.tool_calls)
        ),
    )


def _render_decision_message(
    approved: bool, tool_name: str, result: Optional[Dict[str, Any]]
) -> tuple[str, Optional[list]]:
    """Build the assistant Message content (and tool_calls payload) that
    records an approval decision in the conversation transcript."""
    if not approved:
        return (
            f"[Denied] The pending action '{tool_name}' was not executed.",
            None,
        )
    try:
        rendered = json.dumps(result, default=str, indent=2)
    except (TypeError, ValueError):
        rendered = str(result)
    rendered = compress_tool_result(rendered, 2000)
    content = f"[Approved] Executed '{tool_name}'.\n\nResult:\n{rendered}"
    try:
        safe_result = json.loads(json.dumps(result, default=str))
    except (TypeError, ValueError):
        safe_result = {"result": str(result)}
    return content, [{"name": tool_name, "result": safe_result, "approved": True}]


async def _parked_task_id(db: AsyncSession, current_user: User, action_id: str) -> Optional[str]:
    """The task id of a pending action: the newest user message of the
    conversation it was parked in (the same identity ``_task_id_of`` gives
    the turn that parked it), so the approved call runs under that turn's
    TaskState. None when the action is unknown or has no conversation; the
    runtime then falls back to the conversation id.

    Read through the request's own session rather than a second one: the
    decision below must stay the only other database work in this request
    (the approval store's single-use update)."""
    try:
        action_uuid = uuid.UUID(action_id)
    except ValueError:
        return None
    newest = (
        await db.execute(
            select(Message.id)
            .join(PendingAction, PendingAction.conversation_id == Message.conversation_id)
            .join(Conversation, Conversation.id == Message.conversation_id)
            .where(
                PendingAction.id == action_uuid,
                PendingAction.user_id == current_user.id,
                Conversation.user_id == current_user.id,
                Message.role == MessageRole.user,
            )
            .order_by(Message.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return str(newest) if newest is not None else None


async def _apply_decision(
    db: AsyncSession,
    runtime: AgentRuntime,
    mcp_catalog: Any,
    current_user: User,
    action_id: str,
    approved: bool,
    installation: Any = None,
    on_event: Optional[EventSink] = None,
) -> Dict[str, Any]:
    """Decide a pending action, persist the outcome into its conversation,
    and (on approval) run the resumed agent turn. Shared by the HTTP route
    and out-of-band decision channels (Telegram); returns the runtime's
    result dict, or {"error": ...} for unknown/expired/foreign actions.

    The decision, the tool it runs and the transcript row recording it
    finish together even if this call is cancelled (a chat's /stop): a
    tool that already ran but was never written down would be invisible
    to the next turn, which could then run it again. Only the resumed
    turn after them can be stopped, by that cancel or by a stop request
    (``services.agent.cancel``) made since the card was raised.

    ``on_event`` goes to the resumed turn (``_resume_after_approval``).
    """
    # The task (spec §10) the parked call belongs to, looked up before the
    # decision releases the connection: the approved call then runs under
    # the same per-task browser caps as the turn that parked it.
    task_id = await _parked_task_id(db, current_user, action_id) if approved else None
    result, conversation, recorded = await _finish_even_if_cancelled(
        _decide_and_record(db, runtime, current_user, action_id, approved, task_id)
    )
    # For the resumed turn only; never shown to the user.
    resume_stop_mark = result.pop("resume_stop_mark", None)
    if "error" in result or conversation is None or not approved:
        return result

    # Resume the task. Without this the agent dead-ends after an approval —
    # the tool ran, but the user had to send another message just to get
    # the answer it was fetched for. Run one more turn over the updated
    # transcript so the assistant actually uses the result and continues.
    #
    # Best effort: the approval already happened and is recorded, so a
    # resume failure must not turn into a failed request. It is still told
    # to the channel in plain words (``assistant_notes["error"]``): a
    # swallowed failure left Telegram with a line that said nothing.
    turn = TurnUsage()
    approved_call = (
        ApprovedCall(str(result.get("tool", "")), result.get("result"), recorded.id)
        if recorded is not None
        else None
    )
    try:
        resumed = await _resume_after_approval(
            mcp_catalog,
            current_user,
            db,
            runtime,
            conversation,
            installation,
            turn,
            stop_mark=resume_stop_mark,
            on_event=on_event,
            approved=approved_call,
        )
        if resumed is not None:
            db.add(resumed.message)
            conversation.updated_at = datetime.now(timezone.utc)
            await db.flush()
            # Only a channel reads these (the HTTP route drops them). Like
            # build_chat_applier, a resumed turn that read a logged-in site
            # loses URL queries before they reach Telegram (spec §9); the
            # turn's usage lets the channel show what it cost, and the
            # notes what its reply must add (a card it parked, a block).
            result["assistant_reply"] = (
                strip_url_queries(resumed.message.content)
                if _account_mode(resumed.message.tool_calls)
                else resumed.message.content
            )
            result["assistant_turn"] = turn
            result["assistant_notes"] = {
                "pending_approvals": resumed.pending_approvals,
                "blocked": resumed.blocked,
                "images": resumed.images,
            }
    except Exception as exc:
        logger.warning(
            "resume_after_approval_failed",
            conversation_id=str(conversation.id),
            error_type=type(exc).__name__,
            error=str(exc)[:200],
        )
        result["assistant_notes"] = {"error": resume_failure_text(exc)}
        # The calls the turn ran before failing (a desktop.observe) and the
        # tokens it billed close the turn in the transcript, as a message
        # turn's failure does (build_chat_applier); without the row they
        # would vanish, and the next turn could run them again.
        if any(turn.usage.values()) or turn.tool_calls:
            try:
                db.add(_unfinished_turn_message(conversation.id, turn, _FAILED_REPLY))
                conversation.updated_at = datetime.now(timezone.utc)
                await db.flush()
            except Exception as row_exc:
                await db.rollback()
                logger.error("resume_failure_row_not_written", error=str(row_exc)[:200])
    return result


async def _decide_and_record(
    db: AsyncSession,
    runtime: AgentRuntime,
    current_user: User,
    action_id: str,
    approved: bool,
    task_id: Optional[str] = None,
) -> tuple[Dict[str, Any], Optional[Conversation], Optional[Message]]:
    """Apply the decision (on approval: run the tool under ``task_id``'s
    caps) and commit the transcript row that records it. Returns the
    runtime's result, the conversation the row went into and the row
    itself (both None when there was none to write)."""
    # Release the pooled connection before the decision: an approval
    # executes the real tool (connector/MCP HTTP), which does not need it.
    await db.commit()

    if approved:
        result = await runtime.approve_action(action_id, str(current_user.id), task_id=task_id)
    else:
        result = await runtime.deny_action(action_id, str(current_user.id))

    if "error" in result:
        return result, None, None

    # Persist the outcome into the conversation the action came from.
    conv_id = result.pop("conversation_id", None)
    tool_name = result.get("tool", "")
    if not conv_id:
        return result, None, None
    try:
        conv_uuid = uuid.UUID(str(conv_id))
    except ValueError:
        return result, None, None
    conversation = (
        await db.execute(select(Conversation).where(Conversation.id == conv_uuid))
    ).scalar_one_or_none()
    if conversation is None or conversation.user_id != current_user.id:
        return result, None, None
    # The row (content and tool_calls) records the placeholder, never image
    # data (spec §9); the caller still gets the result as the tool returned it.
    content, tool_calls_payload = _render_decision_message(
        approved, tool_name, redact_binary_for_model(result.get("result"))
    )
    recorded = Message(
        conversation_id=conversation.id,
        role=MessageRole.assistant,
        content=content,
        tool_calls=tool_calls_payload,
    )
    db.add(recorded)
    conversation.updated_at = datetime.now(timezone.utc)
    # Durable before anything that can be interrupted runs.
    await db.commit()
    return result, conversation, recorded


async def _finish_even_if_cancelled(coro: Any) -> Any:
    """Await ``coro`` to its end even if the caller is cancelled meanwhile,
    then honour the cancellation. For short sections that must not stop
    half-way (a side effect and the record of it)."""
    task = asyncio.ensure_future(coro)
    cancelled = False
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            if task.done():
                # The section itself was cancelled (e.g. loop shutdown).
                raise
            cancelled = True
    if cancelled:
        raise asyncio.CancelledError
    return result


def build_decision_applier(app: Any, session_factory: Any = async_session):
    """Async callback for out-of-band approval channels (the Telegram
    poller): (user_id, action_id, approved) -> outcome dict. Runs the same
    decide → record → resume pipeline as POST /approvals/{action_id},
    with its own DB session from ``session_factory`` and an explicit
    commit at the end.

    ``on_event``, when given, receives the resumed turn's progress events
    live, as ``build_chat_applier``'s does for a message turn."""

    async def apply(
        user_id: str,
        action_id: str,
        approved: bool,
        *,
        on_event: Optional[EventSink] = None,
    ) -> Dict[str, Any]:
        runtime: Optional[AgentRuntime] = getattr(app.state, "agent_runtime", None)
        if runtime is None:
            return {"error": "Agent runtime is not available."}
        mcp_catalog = getattr(app.state, "mcp_catalog", None)
        async with session_factory() as db:
            user = (
                await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
            ).scalar_one_or_none()
            if user is None or not user.is_active:
                return {"error": "Unknown account."}
            result = await _apply_decision(
                db,
                runtime,
                mcp_catalog,
                user,
                action_id,
                approved,
                getattr(app.state, "installation", None),
                on_event=on_event,
            )
            await db.commit()

        if "error" in result:
            return result
        summary = None
        outcome: Dict[str, Any] = {}
        if approved:
            reply = (result.get("assistant_reply") or "").strip()
            notes = result.get("assistant_notes") or {}
            if reply:
                # The whole reply: the channel splits long text into several
                # messages, and a cut here would also cut the usage line.
                summary = reply
            else:
                # No reply to relay, so the channel hears what ran and why
                # it stops here, from facts. The chat can carry the whole
                # result, so nothing sends the person to the web app.
                ran = _approved_action_line(result)
                failure = notes.get("error")
                summary = (
                    f"{ran} But I couldn't continue: {failure}. Send 'continue' to try again."
                    if failure
                    else f"{ran} The assistant did not add a reply. Send 'continue' to go on."
                )
            turn = result.get("assistant_turn")
            if reply and isinstance(turn, TurnUsage):
                outcome = {
                    "usage": dict(turn.usage),
                    "provider": turn.provider,
                    "model": turn.model,
                    "served_model": turn.served_model,
                }
            # What the reply must add, as build_chat_applier reports them.
            outcome.update(
                {
                    "pending_approvals": list(notes.get("pending_approvals") or []),
                    "blocked": list(notes.get("blocked") or []),
                    "images": list(notes.get("images") or []),
                }
            )
        return {
            "status": "approved" if approved else "denied",
            "summary": summary,
            **outcome,
        }

    return apply


# Title of the conversation an out-of-band channel (Telegram) writes into.
# One per user, reused across messages, so the transcript is visible and
# resumable from the web app like any other conversation.
TELEGRAM_CONVERSATION_TITLE = "Telegram"

# Most tool-captured images one channel turn delivers (the web chat's
# toolScreenshots.ts names the same limit in its note).
MAX_CHANNEL_IMAGES = 3

# The only images a channel forwards: base64 raster data URLs of the types
# the built-in screenshot tools produce. SVG (which can carry script) and
# anything else never reach the person's chat as a photo.
_CHANNEL_IMAGE_URL = re.compile(r"data:image/(?:jpeg|png|webp);base64,")

_URL_WITH_QUERY = re.compile(r"(https?://[^\s<>\"'()]+?)[?#][^\s<>\"'()]*", re.IGNORECASE)


def strip_url_queries(text: str) -> str:
    """Query strings and fragments removed from every URL in *text* (spec
    §9): on a turn that read a logged-in site they carry tokens and ids."""
    return _URL_WITH_QUERY.sub(r"\1", text)


def _task_id_of(rows: list[Any]) -> Optional[str]:
    """The task identity (spec §10): the newest user message's id, so a
    task keeps its caps across approval and handoff resumes."""
    for row in reversed(rows):
        if row.role == MessageRole.user:
            return str(row.id)
    return None


def _account_mode(tool_calls: Any) -> bool:
    """True when this turn touched a logged-in site: any browser result
    whose ``mode`` is "account" — or that carries no mode at all (a toolkit
    that does not say is treated as private, fail closed)."""
    for tc in tool_calls if isinstance(tool_calls, list) else []:
        if not isinstance(tc, dict):
            continue
        result = tc.get("result")
        if is_browser_tool(tc.get("name")) and isinstance(result, dict):
            if result.get("mode", "account") == "account":
                return True
    return False


def _channel_caption(name: str, result: dict[str, Any]) -> str:
    needs = result.get("needs_human")
    if isinstance(needs, dict) and needs.get("detail"):
        return str(needs["detail"])
    return str(
        result.get("title")
        or result.get("final_url")
        or result.get("url")
        or ("Your screen" if name.startswith("desktop.") else "")
    )


def _channel_image(name: str, result: Any) -> Optional[str]:
    """The data URL a channel may deliver for one tool call, else None.

    Only built-in tools qualify: a third-party (MCP) tool, or a name that
    does not resolve, could hand the person an arbitrary picture that
    looks like one of ours.
    """
    from services.mcp.integration import is_mcp_tool

    if is_mcp_tool(name) or resolve_tool(name) is None or not isinstance(result, dict):
        return None
    # A browser screenshot's ``user_image`` is the person's copy (masked,
    # never shown to the model); a handoff nests it under ``needs_human``;
    # ``image`` is the model's copy or a web/desktop screenshot. Whichever
    # exists is delivered; with both, the person's.
    needs = result.get("needs_human")
    candidates = [needs.get("user_image")] if isinstance(needs, dict) else []
    candidates += [result.get("user_image"), result.get("image")]
    for image in candidates:
        if isinstance(image, str) and _CHANNEL_IMAGE_URL.match(image):
            return image
    return None


# What the web chat renders as an <img>: the whole string one base64 PNG,
# JPEG or WebP data URL (nothing after the payload), no bigger than an
# attachment may be. Anything else is dropped, never shown.
_WEB_IMAGE_URL = re.compile(r"data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}")
_MAX_WEB_IMAGE_CHARS = len("data:image/jpeg;base64,") + MAX_IMAGE_BYTES * 4 // 3 + 4

# An app name the alt text may carry; any other name is left out.
_IMAGE_APP_NAME = re.compile(r"[\w .&'+()-]{1,60}")


def _image_source(name: str, result: dict[str, Any]) -> Optional[str]:
    """What a screenshot shows, for its alt text: the page's host (never
    its path or query) or, for a desktop tool, the app. Facts only: no
    page title and nothing the model wrote."""
    needs = result.get("needs_human")
    for where in (needs if isinstance(needs, dict) else {}, result):
        for key in ("final_url", "url"):
            host = tool_call_facts({"url": where.get(key)}).get("host")
            if host:
                return host
    app = result.get("app")
    if name.startswith("desktop.") and isinstance(app, str) and _IMAGE_APP_NAME.fullmatch(app):
        return app
    return None


def _turn_images(tool_calls: Any) -> list[dict[str, Any]]:
    """The screenshots a web turn shows live: what a channel would deliver
    (see _channel_image), each checked against _WEB_IMAGE_URL and the
    attachment cap, at most MAX_CHANNEL_IMAGES. Read from the live response
    before redaction and never written to a row (spec §9)."""
    images: list[dict[str, Any]] = []
    for index, tc in enumerate(tool_calls if isinstance(tool_calls, list) else []):
        if len(images) >= MAX_CHANNEL_IMAGES:
            break
        if not isinstance(tc, dict):
            continue
        name = str(tc.get("name", ""))
        result = tc.get("result")
        data_url = _channel_image(name, result)
        if data_url is None or not isinstance(result, dict):
            continue
        payload = data_url.partition(",")[2]
        if (
            len(data_url) > _MAX_WEB_IMAGE_CHARS
            or len(payload) % 4
            or not _WEB_IMAGE_URL.fullmatch(data_url)
        ):
            continue
        images.append(
            {"tool": name, "source": _image_source(name, result), "index": index, "data_url": data_url}
        )
    return images


def build_chat_applier(app: Any, session_factory: Any = async_session):
    """Async callback for chat arriving over an out-of-band channel:
    (user_id, text, new_conversation=False) -> outcome dict. Runs the same
    turn pipeline as POST /conversations/{id}/messages — rate limit,
    persisted user message, tools + memory, runtime.chat (prompt guard,
    tiering, approvals, audit), persisted assistant message with usage —
    with its own DB session. Returns {"error": str} instead of raising.

    ``stop_mark`` (``services.agent.cancel.mark``) lets the channel pass the
    mark it took when the message arrived, so a /stop sent while the message
    waited for its turn also ends it; omitted, the mark is taken on entry.

    ``on_event``, when given, receives the turn's progress events live."""

    async def chat(
        user_id: str,
        text: str,
        *,
        new_conversation: bool = False,
        stop_mark: Optional[int] = None,
        on_event: Optional[EventSink] = None,
    ) -> Dict[str, Any]:
        # Accepted: a stop from here on ends this turn, setup included.
        if stop_mark is None:
            stop_mark = agent_cancel.mark(user_id)
        runtime: Optional[AgentRuntime] = getattr(app.state, "agent_runtime", None)
        if runtime is None:
            return {"error": "The assistant is not available right now."}
        content = (text or "").strip()
        if not content:
            return {"error": "Message content cannot be empty."}
        mcp_catalog = getattr(app.state, "mcp_catalog", None)
        installation = getattr(app.state, "installation", None)

        async with session_factory() as db:
            user = (
                await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
            ).scalar_one_or_none()
            if user is None or not user.is_active:
                return {"error": "Unknown account."}
            if not _user_rate_limiter.allow(str(user.id), user.rate_limit):
                return {
                    "error": (
                        f"Rate limit exceeded: your account allows "
                        f"{user.rate_limit} agent messages per minute."
                    )
                }

            conversation = None
            if not new_conversation:
                conversation = (
                    await db.execute(
                        select(Conversation)
                        .where(
                            Conversation.user_id == user.id,
                            Conversation.title == TELEGRAM_CONVERSATION_TITLE,
                        )
                        .order_by(Conversation.updated_at.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
            if conversation is None:
                conversation = Conversation(
                    user_id=user.id, title=TELEGRAM_CONVERSATION_TITLE
                )
                db.add(conversation)
                await db.flush()

            db.add(
                Message(
                    conversation_id=conversation.id,
                    role=MessageRole.user,
                    content=content,
                )
            )
            await db.flush()
            # The channel thread is reused indefinitely (until /new), so read
            # back only its recent tail; the newest user message, which names
            # the task, is always in it.
            rows = await _recent_messages(db, conversation.id)
            history = [{"role": r.role.value, "content": r.content} for r in rows]
            task_id = _task_id_of(rows)
            tools, memory_block, permissions_text = await _build_tools_and_memory(
                mcp_catalog, user, db, installation
            )
            conversation_id = conversation.id
            provider, model = user.llm_provider, user.llm_model
            # The user message is durable from here; release the pooled
            # connection for the (possibly long) turn.
            await db.commit()

        # Filled in while the turn runs: a turn stopped from the chat (task
        # cancelled) or failing after some model calls still records the
        # tokens those calls billed.
        turn = TurnUsage()

        async def record_unfinished(content: str) -> None:
            async with session_factory() as db:
                db.add(_unfinished_turn_message(conversation_id, turn, content))
                await db.commit()

        try:
            agent_response = await runtime.chat(
                messages=history,
                tools=tools,
                user_id=user_id,
                conversation_id=str(conversation_id),
                llm_provider=provider,
                llm_model=model,
                memory_block=memory_block,
                permissions_text=permissions_text,
                task_id=task_id,
                usage_sink=turn,
                stop_mark=stop_mark,
                event_sink=on_event,
            )
        except asyncio.CancelledError:
            # /stop: the reply will never come. Close the turn in the
            # transcript (so the next turn does not see an unanswered
            # message) and keep its billed tokens and the calls that ran,
            # then keep unwinding.
            await record_unfinished(_STOPPED_REPLY)
            raise
        except ProviderNotConfigured as exc:
            # The channel sends "error" verbatim: the bare sentence, with the
            # code and the matching setup_url/settings_url alongside.
            logger.warning(
                "channel_chat_provider_not_configured",
                conversation_id=str(conversation_id),
                provider=exc.provider,
                reason=exc.reason,
            )
            return {
                "error": str(exc),
                **await _not_configured_info(exc.code, installation),
                "conversation_id": str(conversation_id),
            }
        except ProviderError as exc:
            # The channel shows the user the error; without this line the
            # server side had no record that an out-of-band turn failed.
            logger.warning(
                "channel_chat_provider_error",
                conversation_id=str(conversation_id),
                error=str(exc)[:200],
            )
            if any(turn.usage.values()):
                # Earlier calls of this turn were billed before the failing
                # one; without a row their tokens vanish from /usage.
                await record_unfinished(_FAILED_REPLY)
            return {"error": str(exc), "conversation_id": str(conversation_id)}

        async with session_factory() as db:
            conversation = (
                await db.execute(
                    select(Conversation).where(Conversation.id == conversation_id)
                )
            ).scalar_one()
            db.add(
                Message(
                    conversation_id=conversation.id,
                    role=MessageRole.assistant,
                    content=agent_response.content,
                    tool_calls=redact_binary_for_model(agent_response.tool_calls) or None,
                    **_usage_columns(
                        agent_response.usage,
                        agent_response.provider,
                        agent_response.model,
                    ),
                )
            )
            conversation.updated_at = datetime.now(timezone.utc)
            await db.commit()

        # Images a tool captured (web.screenshot, desktop.screenshot,
        # browser screenshots and handoffs) are delivered to the person as
        # photos; the model only ever saw a placeholder (see
        # runtime.redact_binary_for_model). On a turn that read a
        # logged-in site, URLs lose their query strings and fragments
        # before they reach Telegram's servers (spec §9).
        account = _account_mode(agent_response.tool_calls)
        reply = strip_url_queries(agent_response.content) if account else agent_response.content

        return {
            "content": reply,
            "conversation_id": str(conversation_id),
            "images": _channel_photos(agent_response.tool_calls, account),
            "tool_calls": [tc.get("name", "") for tc in agent_response.tool_calls],
            "pending_approvals": [
                pa.tool_name for pa in agent_response.pending_approvals
            ],
            "blocked": [ba.tool_name for ba in agent_response.blocked_actions],
            # This turn's own calls only (every round of its tool loop), and
            # the model that ran it: what a per-reply cost line prices.
            "usage": dict(agent_response.usage),
            "provider": agent_response.provider,
            "model": agent_response.model,
            "served_model": agent_response.served_model,
        }

    return chat


@router.post("/approvals/{action_id}", response_model=ApprovalDecisionResponse)
async def decide_approval(
    action_id: str,
    body: ApprovalDecisionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    runtime: AgentRuntime = Depends(get_runtime),
) -> ApprovalDecisionResponse:
    """Approve or deny a pending action. On approval the runtime executes the
    tool call; on denial the action is dropped. Only the user who owns the
    pending action can decide it — ownership is checked against the JWT.

    The decision (and, for approvals, the tool result) is persisted as an
    assistant Message in the originating conversation, so the transcript
    shows the outcome and the LLM's subsequent turns — whose history is
    rebuilt from Message rows — know the action ran.
    """
    result = await _apply_decision(
        db,
        runtime,
        getattr(request.app.state, "mcp_catalog", None),
        current_user,
        action_id,
        body.approved,
        getattr(request.app.state, "installation", None),
    )
    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"],
        )
    result.pop("assistant_reply", None)
    result.pop("assistant_turn", None)
    result.pop("assistant_notes", None)

    return ApprovalDecisionResponse(
        action_id=action_id,
        approved=body.approved,
        result=result,
    )


@router.post("/stop")
async def stop_running_task(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, bool]:
    """The web Stop button: ask the signed-in user's running task to stop.

    Records a stop (``services.agent.cancel``) that ends each of the user's
    turns accepted before it: the runtime checks before every model round
    and every tool call, and the computer toolkit before every desktop
    action. The turn then ends through its normal path with a short
    "Stopped." reply, so the SSE stream still sends its ``done`` frame and
    the reply is saved like any other. Work the user starts afterwards is
    not affected, except the turn resumed from an approval card that was
    already waiting: the approved action runs, and that turn then ends as
    "Stopped.". With nothing running this is otherwise harmless.

    The stop is recorded before the audit row is written, so a failed audit
    write never keeps it from taking effect.
    """
    # Imported here rather than at the top so this endpoint stays one
    # self-contained block at the end of the file.
    from models.audit import AuditStatus
    from services.agent.runtime import USER_STOPPED_POLICY
    from services.audit import append_audit_log

    agent_cancel.request_cancel(str(current_user.id))
    try:
        await append_audit_log(
            db,
            user_id=current_user.id,
            connector_name="agent",
            action="stop_requested",
            endpoint="/api/agent/stop",
            scope_used="agent",
            status=AuditStatus.approved,
            reasoning_chain={
                "event": "stop_requested",
                "policy": USER_STOPPED_POLICY,
                "channel": "web",
            },
        )
    except Exception as exc:
        await db.rollback()
        logger.error("stop_request_audit_failed", error=str(exc)[:200])
    return {"ok": True}
