from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings, settings as app_settings
from core.database import get_db
from core.security import decrypt_credentials
from models.conversation import Conversation, Message, MessageRole
from models.user import User
from services.auth import get_current_user

router = APIRouter(prefix="/agent", tags=["agent"])


# ── Schemas ───────────────────────────────────────────────────────────────


class CreateConversationRequest(BaseModel):
    title: str = "New Conversation"


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


class ConversationListItem(BaseModel):
    id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ConversationResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime
    messages: list[MessageResponse] = []

    model_config = {"from_attributes": True}


class ChatResponse(BaseModel):
    user_message: MessageResponse
    assistant_message: MessageResponse


# ── Helpers ───────────────────────────────────────────────────────────────


def _build_user_settings(user: User) -> Settings:
    """Build a Settings-like object with the user's LLM config overlaid."""
    overrides: dict[str, Any] = {
        "LLM_PROVIDER": user.llm_provider,
        "LLM_MODEL": user.llm_model,
        "SECRET_KEY": app_settings.SECRET_KEY,
        "ENCRYPTION_KEY": app_settings.ENCRYPTION_KEY,
        "DATABASE_URL": app_settings.DATABASE_URL,
    }

    if user.llm_api_key_enc:
        api_key = decrypt_credentials(user.llm_api_key_enc)
        provider_key_field = f"{user.llm_provider.upper()}_API_KEY"
        overrides[provider_key_field] = api_key

    return Settings(**overrides)  # type: ignore[call-arg]


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.get("/conversations", response_model=list[ConversationListItem])
async def list_conversations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Conversation)
        .where(Conversation.user_id == current_user.id)
        .order_by(Conversation.updated_at.desc())
    )
    return result.scalars().all()


@router.post(
    "/conversations",
    response_model=ConversationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_conversation(
    body: CreateConversationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
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
):
    result = await db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.user_id == current_user.id,
        )
    )
    conversation = result.scalar_one_or_none()
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=ChatResponse,
    status_code=status.HTTP_201_CREATED,
)
async def send_message(
    conversation_id: uuid.UUID,
    body: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.user_id == current_user.id,
        )
    )
    conversation = result.scalar_one_or_none()
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")

    if not body.content.strip():
        raise HTTPException(status_code=422, detail="Message content cannot be empty")

    # 1. Persist the user message
    user_msg = Message(
        conversation_id=conversation_id,
        role=MessageRole.user,
        content=body.content.strip(),
    )
    db.add(user_msg)
    await db.flush()
    await db.refresh(user_msg)

    # 2. Build conversation history for the LLM
    msg_result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation_id)
        .order_by(Message.created_at)
    )
    all_messages = msg_result.scalars().all()

    llm_messages: list[dict[str, Any]] = [
        {"role": "system", "content": "You are SentientAI, a helpful and secure AI assistant. Be concise and helpful."}
    ]
    for m in all_messages:
        llm_messages.append({"role": m.role.value, "content": m.content})

    # 3. Call the LLM via AgentRuntime
    try:
        from services.agent.runtime import AgentRuntime

        user_settings = _build_user_settings(current_user)
        runtime = AgentRuntime(user_settings)
        agent_response = await runtime.chat(
            messages=llm_messages,
            tools=[],
            user_id=str(current_user.id),
        )
        assistant_content = agent_response.content
    except Exception as exc:
        assistant_content = f"I'm sorry, I encountered an error connecting to the AI provider. Please check your API key in Settings.\n\nError: {exc}"

    # 4. Persist the assistant message
    assistant_msg = Message(
        conversation_id=conversation_id,
        role=MessageRole.assistant,
        content=assistant_content,
    )
    db.add(assistant_msg)

    # Update conversation title from first user message
    if conversation.title == "New Conversation":
        conversation.title = body.content.strip()[:80]

    conversation.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(assistant_msg)

    return ChatResponse(
        user_message=MessageResponse.model_validate(user_msg),
        assistant_message=MessageResponse.model_validate(assistant_msg),
    )
