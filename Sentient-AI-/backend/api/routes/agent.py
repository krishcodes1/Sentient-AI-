from __future__ import annotations
from typing import Any, Dict, List, Optional, Union

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.conversation import Conversation, Message, MessageRole
from services.agent.runtime import AgentRuntime

router = APIRouter(prefix="/agent", tags=["agent"])


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


class CreateConversationRequest(BaseModel):
    user_id: uuid.UUID
    title: str = "New Conversation"


class SendMessageRequest(BaseModel):
    content: str
    user_id: uuid.UUID
    role: MessageRole = MessageRole.user


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
    user_id: uuid.UUID
    approved: bool


class ApprovalDecisionResponse(BaseModel):
    action_id: str
    approved: bool
    result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/conversations", response_model=list[ConversationListItem])
async def list_conversations(
    user_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[Conversation]:
    """List a user's conversations, newest first."""
    query = (
        select(Conversation)
        .where(Conversation.user_id == user_id)
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
    db: AsyncSession = Depends(get_db),
) -> Conversation:
    """Start a new agent conversation."""
    conversation = Conversation(user_id=body.user_id, title=body.title)
    db.add(conversation)
    await db.flush()
    await db.refresh(conversation)
    return conversation


@router.get("/conversations/{conversation_id}", response_model=ConversationResponse)
async def get_conversation(
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Conversation:
    """Retrieve a conversation with its messages."""
    result = await db.execute(
        select(Conversation).where(Conversation.id == conversation_id)
    )
    conversation = result.scalar_one_or_none()
    if conversation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        )
    return conversation


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=AgentTurnResponse,
    status_code=status.HTTP_201_CREATED,
)
async def send_message(
    conversation_id: uuid.UUID,
    body: SendMessageRequest,
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

    # Load the conversation and confirm ownership
    conv_result = await db.execute(
        select(Conversation).where(Conversation.id == conversation_id)
    )
    conversation = conv_result.scalar_one_or_none()
    if conversation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        )
    if conversation.user_id != body.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Conversation belongs to a different user",
        )

    # 1. Persist the user message
    user_message = Message(
        conversation_id=conversation_id,
        role=MessageRole.user,
        content=body.content.strip(),
    )
    db.add(user_message)
    await db.flush()
    await db.refresh(user_message)

    # 2. Build chat history for the runtime
    history_result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation_id)
        .order_by(Message.created_at)
    )
    history = [
        {"role": m.role.value, "content": m.content}
        for m in history_result.scalars().all()
    ]

    # 3. Run the agent. Tools list is empty until the connector registry is
    #    wired in; the runtime will simply return the LLM text.
    agent_response = await runtime.chat(
        messages=history,
        tools=[],
        user_id=str(body.user_id),
    )

    # 4. Persist the assistant message (with tool calls if any)
    assistant_message = Message(
        conversation_id=conversation_id,
        role=MessageRole.assistant,
        content=agent_response.content,
        tool_calls=agent_response.tool_calls or None,
    )
    db.add(assistant_message)
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
    user_id: uuid.UUID,
    runtime: AgentRuntime = Depends(get_runtime),
) -> list[PendingApprovalOut]:
    """Return the user's currently-pending approval requests."""
    pending = runtime.list_pending_approvals(str(user_id))
    return [
        PendingApprovalOut(
            action_id=p.action_id,
            tool_name=p.tool_name,
            arguments=p.arguments,
            reason=p.reason,
        )
        for p in pending
    ]


@router.post("/approvals/{action_id}", response_model=ApprovalDecisionResponse)
async def decide_approval(
    action_id: str,
    body: ApprovalDecisionRequest,
    runtime: AgentRuntime = Depends(get_runtime),
) -> ApprovalDecisionResponse:
    """Approve or deny a pending action. On approval the runtime executes the
    tool call; on denial the action is dropped.
    """
    if body.approved:
        result = await runtime.approve_action(action_id, str(body.user_id))
    else:
        result = await runtime.deny_action(action_id, str(body.user_id))

    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"],
        )

    return ApprovalDecisionResponse(
        action_id=action_id,
        approved=body.approved,
        result=result,
    )
