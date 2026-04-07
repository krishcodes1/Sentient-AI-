from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from models.conversation import Conversation, Message, MessageRole

router = APIRouter(prefix="/agent", tags=["agent"])


class CreateConversationRequest(BaseModel):
    user_id: uuid.UUID
    title: str = "New Conversation"


class SendMessageRequest(BaseModel):
    content: str
    role: MessageRole = MessageRole.user


class MessageResponse(BaseModel):
    id: uuid.UUID
    conversation_id: uuid.UUID
    role: MessageRole
    content: str
    tool_calls: dict | list | None = None
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
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
)
async def send_message(
    conversation_id: uuid.UUID,
    body: SendMessageRequest,
    db: AsyncSession = Depends(get_db),
) -> Message:
    """Append a message to a conversation."""
    result = await db.execute(
        select(Conversation).where(Conversation.id == conversation_id)
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        )

    if not body.content.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message content cannot be empty",
        )

    message = Message(
        conversation_id=conversation_id,
        role=body.role,
        content=body.content.strip(),
    )
    db.add(message)
    await db.flush()
    await db.refresh(message)
    return message
