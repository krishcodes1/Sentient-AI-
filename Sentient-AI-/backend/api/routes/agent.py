from __future__ import annotations
from typing import Any, Dict, List, Optional, Union

import asyncio
import json
import time
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core.database import async_session, get_db
from core.validation import SafeStr
from models.connector import ConnectorConfig
from models.conversation import Conversation, Message, MessageRole
from models.memory import Memory
from models.pending_action import PendingAction
from models.user import User
from services.auth import get_current_user
from services.memory import render_memory_block
from services.agent.context_manager import compress_tool_result
from services.agent.providers import ProviderError
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import ConnectorSpec, build_tools, effective_tier

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])


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

    Raises 503 if the runtime failed to initialize at startup (e.g. missing
    API key for the configured LLM provider).
    """
    runtime: Optional[AgentRuntime] = getattr(request.app.state, "agent_runtime", None)
    if runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Agent runtime is not available. Check the LLM provider configuration "
                "(LLM_PROVIDER, LLM_MODEL, and the matching *_API_KEY env var)."
            ),
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


class SendMessageRequest(BaseModel):
    content: SafeStr = Field(min_length=1, max_length=100_000)


class MessageResponse(BaseModel):
    id: uuid.UUID
    conversation_id: uuid.UUID
    role: MessageRole
    content: str
    tool_calls: Optional[Union[Dict, List]] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ConversationResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime
    messages: list[MessageResponse] = []

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


class ApprovalDecisionRequest(BaseModel):
    approved: bool


class ApprovalDecisionResponse(BaseModel):
    action_id: str
    approved: bool
    result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


async def _build_tools_and_memory(
    request: Request,
    current_user: User,
    db: AsyncSession,
) -> tuple[list, Optional[str]]:
    """Build the runtime tool list (connector + MCP tools) and the memory
    block for a user. Shared by the blocking and streaming send paths so
    both offer exactly the same tools and context.
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
        )
        for c in connector_rows
    ]
    tools = build_tools(
        connector_specs,
        user_default_tier=current_user.default_permission_tier,
        is_admin=current_user.is_admin,
    )

    if any(spec.connector_type == "mcp" for spec in connector_specs):
        mcp_catalog = getattr(request.app.state, "mcp_catalog", None)
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

    return tools, memory_block


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
) -> Conversation:
    """Retrieve one of the authenticated user's conversations with messages."""
    return await _get_owned_conversation(
        conversation_id, current_user, db, with_messages=True
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
    if not body.content.strip():
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

    conversation = await _get_owned_conversation(conversation_id, current_user, db)

    # 1. Persist the user message
    user_message = Message(
        conversation_id=conversation.id,
        role=MessageRole.user,
        content=body.content.strip(),
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
    history = [
        {"role": m.role.value, "content": m.content}
        for m in history_result.scalars().all()
    ]

    # 3. Build the tool list (connectors + MCP) and memory block. The
    #    runtime's permission adapter and executor (injected at startup)
    #    handle tiering, approval, and dispatch. A user with no connectors
    #    gets an empty list and simply chats with the LLM.
    tools, memory_block = await _build_tools_and_memory(request, current_user, db)

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
        )
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
        tool_calls=agent_response.tool_calls or None,
    )
    db.add(assistant_message)
    conversation.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(assistant_message)

    return AgentTurnResponse(
        user_message=MessageResponse.model_validate(user_message),
        assistant_message=MessageResponse.model_validate(assistant_message),
        tool_calls=[
            ToolCallOut(
                name=tc.get("name", ""),
                result=tc.get("result"),
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
                    tool_calls=tool_calls or None,
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
    if not body.content.strip():
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

    conversation = await _get_owned_conversation(conversation_id, current_user, db)

    user_message = Message(
        conversation_id=conversation.id,
        role=MessageRole.user,
        content=body.content.strip(),
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
    history = [
        {"role": m.role.value, "content": m.content}
        for m in history_result.scalars().all()
    ]
    tools, memory_block = await _build_tools_and_memory(request, current_user, db)
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
            conv_id, response.content or "", response.tool_calls or None
        )

    async def event_stream():
        yield _sse("user_message", {"user_message": user_message_out})

        final_content = ""
        tool_calls_payload: list[dict[str, Any]] = []
        turn_done = False
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
                ):
                    etype = event.get("type", "message")
                    data = event.get("data", {})
                    if etype == "ping":
                        # SSE comment frame: keeps proxies from timing the
                        # stream out during silent stretches; ignored by
                        # spec-compliant parsers (and ours).
                        yield ": ping\n\n"
                        continue
                    if etype == "done":
                        final_content = data.get("content", "")
                        tool_calls_payload = data.get("tool_calls", []) or []
                        turn_done = True
                    yield _sse(etype, data)
            except GeneratorExit:
                raise
            except Exception:  # pragma: no cover - defensive
                yield _sse("error", {"reason": "The assistant failed to respond."})
                yield _sse("done", {})
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
                    tool_calls=tool_calls_payload or None,
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
            if turn_done and not saved_confirmed:
                # The consumer disconnected between the turn completing and
                # the saved frame being delivered. The request session's
                # write is rolled back with the aborted request, so persist
                # with a detached session instead. (Disconnects BEFORE the
                # done event are covered by on_orphaned above.)
                asyncio.create_task(
                    _persist_assistant_detached(
                        conv_id, final_content, tool_calls_payload
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


async def _resume_after_approval(
    request: Request,
    current_user: User,
    db: AsyncSession,
    runtime: AgentRuntime,
    conversation: Conversation,
) -> Optional[Message]:
    """Run one more agent turn after an approved action executed.

    The transcript already contains the "[Approved] Executed ... Result:"
    message, so rebuilding history from Message rows gives the model the
    tool output it was waiting on. Returns the assistant Message to persist,
    or None when there is nothing to add.

    Tools are rebuilt exactly as the send path does, so the resumed turn is
    subject to the same permissions, taint gate, and scanning — an approval
    unlocks the one action the user approved, not a freer agent.
    """
    history_result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation.id)
        .order_by(Message.created_at)
    )
    history = [
        {"role": m.role.value, "content": m.content}
        for m in history_result.scalars().all()
    ]
    if not history:
        return None

    tools, memory_block = await _build_tools_and_memory(request, current_user, db)
    # Return the pooled connection before the (potentially minutes-long)
    # resumed turn; everything written so far — the decision message — is
    # durable from here.
    await db.commit()
    agent_response = await runtime.chat(
        messages=history,
        tools=tools,
        user_id=str(current_user.id),
        conversation_id=str(conversation.id),
        llm_provider=current_user.llm_provider,
        llm_model=current_user.llm_model,
        memory_block=memory_block,
    )
    if not (agent_response.content or "").strip():
        return None
    return Message(
        conversation_id=conversation.id,
        role=MessageRole.assistant,
        content=agent_response.content,
        tool_calls=agent_response.tool_calls or None,
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
    # Release the request's pooled connection before the decision: an
    # approval executes the real tool (connector/MCP HTTP) and then runs a
    # resumed agent turn, neither of which needs this session.
    await db.commit()

    if body.approved:
        result = await runtime.approve_action(action_id, str(current_user.id))
    else:
        result = await runtime.deny_action(action_id, str(current_user.id))

    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"],
        )

    # Persist the outcome into the conversation the action came from.
    conv_id = result.pop("conversation_id", None)
    tool_name = result.get("tool", "")
    if conv_id:
        try:
            conv_uuid = uuid.UUID(str(conv_id))
        except ValueError:
            conv_uuid = None
        if conv_uuid is not None:
            conv_result = await db.execute(
                select(Conversation).where(Conversation.id == conv_uuid)
            )
            conversation = conv_result.scalar_one_or_none()
            if conversation is not None and conversation.user_id == current_user.id:
                content, tool_calls_payload = _render_decision_message(
                    body.approved, tool_name, result.get("result")
                )
                db.add(
                    Message(
                        conversation_id=conversation.id,
                        role=MessageRole.assistant,
                        content=content,
                        tool_calls=tool_calls_payload,
                    )
                )
                conversation.updated_at = datetime.now(timezone.utc)
                await db.flush()

                # Resume the task. Without this the agent dead-ends after an
                # approval — the tool ran, but the user had to send another
                # message just to get the answer it was fetched for. Run one
                # more turn over the updated transcript so the assistant
                # actually uses the result and continues.
                #
                # Best effort: the approval already happened and is recorded,
                # so a resume failure must not turn into a failed request.
                if body.approved:
                    try:
                        resumed = await _resume_after_approval(
                            request, current_user, db, runtime, conversation
                        )
                        if resumed is not None:
                            db.add(resumed)
                            conversation.updated_at = datetime.now(timezone.utc)
                            await db.flush()
                    except Exception as exc:
                        logger.warning(
                            "resume_after_approval_failed",
                            conversation_id=str(conversation.id),
                            error=str(exc),
                        )

    return ApprovalDecisionResponse(
        action_id=action_id,
        approved=body.approved,
        result=result,
    )
