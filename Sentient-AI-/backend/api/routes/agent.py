from __future__ import annotations
from typing import Any, Dict, List, Optional, Union

import json
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.connector import ConnectorConfig
from models.conversation import Conversation, Message, MessageRole
from models.pending_action import PendingAction
from models.user import User
from services.auth import get_current_user
from services.agent.context_manager import compress_tool_result
from services.agent.providers import ProviderError
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import ConnectorSpec, build_tools, effective_tier

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

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, user_id: str, limit: int) -> bool:
        if limit <= 0:  # defensive: never lock an account out entirely
            return True
        now = time.monotonic()
        window = self._events[user_id]
        while window and now - window[0] >= self._WINDOW_SECONDS:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True


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
    title: str = "New Conversation"


class UpdateConversationRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)


class SendMessageRequest(BaseModel):
    content: str


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


async def _get_owned_conversation(
    conversation_id: uuid.UUID,
    user: User,
    db: AsyncSession,
) -> Conversation:
    """Load a conversation and verify ownership.

    Returns 404 (not 403) for conversations owned by someone else so the
    endpoint does not leak which conversation ids exist.
    """
    result = await db.execute(
        select(Conversation).where(Conversation.id == conversation_id)
    )
    conversation = result.scalar_one_or_none()
    if conversation is None or conversation.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        )
    return conversation


@router.get("/conversations", response_model=list[ConversationListItem])
async def list_conversations(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Conversation]:
    """List the authenticated user's conversations, newest first."""
    query = (
        select(Conversation)
        .where(Conversation.user_id == current_user.id)
        .order_by(Conversation.updated_at.desc())
        .offset(offset)
        .limit(limit)
    )
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
) -> Conversation:
    """Start a new agent conversation for the authenticated user."""
    conversation = Conversation(user_id=current_user.id, title=body.title)
    db.add(conversation)
    await db.flush()
    await db.refresh(conversation)
    return conversation


@router.get("/conversations/{conversation_id}", response_model=ConversationResponse)
async def get_conversation(
    conversation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Conversation:
    """Retrieve one of the authenticated user's conversations with messages."""
    return await _get_owned_conversation(conversation_id, current_user, db)


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

    # 3. Build the tool list from the user's active connectors. The
    #    runtime's permission adapter and executor (injected at startup)
    #    handle tiering, approval, and dispatch. A user with no connectors
    #    gets an empty list and simply chats with the LLM.
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
    # user_tier defaults to STANDARD: the User model has no role/admin
    # field yet, so admin-tier tools are not unlocked for anyone. When a
    # role column is added, resolve it here and pass user_tier=... so
    # ADMIN_ONLY tools become available to admins.
    #
    # Each connector's stored permission_tier is enforced here, floored by
    # the user's account-level default (the stricter of the two wins).
    tools = build_tools(
        connector_specs,
        user_default_tier=current_user.default_permission_tier,
    )

    # Registered MCP servers contribute their discovered tools under the
    # mcp.<server>.<tool> namespace; every one of them requires approval.
    # MCP connectors whose effective tier is admin_only contribute nothing.
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

    try:
        agent_response = await runtime.chat(
            messages=history,
            tools=tools,
            user_id=str(current_user.id),
            conversation_id=str(conversation.id),
            llm_provider=current_user.llm_provider,
            llm_model=current_user.llm_model,
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
        )
        for p in pending
    ]


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

    return ApprovalDecisionResponse(
        action_id=action_id,
        approved=body.approved,
        result=result,
    )
