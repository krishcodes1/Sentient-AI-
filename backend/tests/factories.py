"""factory_boy factories for SentientAI ORM models.

These factories produce in-memory model instances. Callers are responsible
for adding the instance to a session and committing — keeping the factories
session-agnostic lets them be used in either sync or async tests.

Example:
    from tests.factories import UserFactory

    user = UserFactory(email="x@y.com")
    db_session.add(user)
    await db_session.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import factory
from factory import Factory, LazyAttribute, LazyFunction, Sequence, SubFactory

from core.security import encrypt_credentials, hash_password
from models.audit import AuditLog, AuditStatus
from models.channel import Channel, ChannelType
from models.connector import (
    AuthMethod,
    ConnectorConfig,
    ConnectorType,
    PermissionTier,
)
from models.conversation import Conversation, Message, MessageRole
from models.user import User


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UserFactory(Factory):
    """Build a :class:`User` instance with sensible defaults."""

    class Meta:
        model = User

    id = LazyFunction(uuid.uuid4)
    email = Sequence(lambda n: f"user{n}@example.com")
    name = Sequence(lambda n: f"User {n}")
    hashed_password = LazyFunction(lambda: hash_password("TestPassword123!"))
    is_active = True
    llm_provider = "openai"
    llm_model = "gpt-4o"
    llm_api_key_enc = None
    onboarding_completed = False
    created_at = LazyFunction(_now)
    updated_at = LazyFunction(_now)


class AuditLogFactory(Factory):
    """Build an :class:`AuditLog` row."""

    class Meta:
        model = AuditLog

    id = LazyFunction(uuid.uuid4)
    user_id = LazyFunction(uuid.uuid4)
    timestamp = LazyFunction(_now)
    connector_name = "canvas"
    action = "list_courses"
    endpoint = "/api/v1/courses"
    scope_used = "courses:read"
    status = AuditStatus.APPROVED
    reasoning_chain = None
    detection_method = None
    confidence_score = None
    request_data = None
    response_summary = None
    integrity_hash = LazyFunction(lambda: "0" * 64)
    request_id = LazyFunction(lambda: str(uuid.uuid4()))


class ConversationFactory(Factory):
    """Build a :class:`Conversation`."""

    class Meta:
        model = Conversation

    id = LazyFunction(uuid.uuid4)
    user_id = LazyFunction(uuid.uuid4)
    title = Sequence(lambda n: f"Conversation {n}")
    created_at = LazyFunction(_now)
    updated_at = LazyFunction(_now)


class MessageFactory(Factory):
    """Build a :class:`Message` row."""

    class Meta:
        model = Message

    id = LazyFunction(uuid.uuid4)
    conversation_id = LazyFunction(uuid.uuid4)
    role = MessageRole.user
    content = "Hello, world."
    tool_calls = None
    created_at = LazyFunction(_now)


class ChannelFactory(Factory):
    """Build a :class:`Channel`."""

    class Meta:
        model = Channel

    id = LazyFunction(uuid.uuid4)
    user_id = LazyFunction(uuid.uuid4)
    channel_type = ChannelType.webchat
    display_name = Sequence(lambda n: f"Channel {n}")
    is_enabled = True
    config_enc = None
    config_meta = None
    created_at = LazyFunction(_now)
    updated_at = LazyFunction(_now)


class ConnectorConfigFactory(Factory):
    """Build a :class:`ConnectorConfig` with encrypted credentials."""

    class Meta:
        model = ConnectorConfig

    id = LazyFunction(uuid.uuid4)
    user_id = LazyFunction(uuid.uuid4)
    connector_type = ConnectorType.canvas
    display_name = Sequence(lambda n: f"Connector {n}")
    is_active = True
    auth_method = AuthMethod.api_key
    encrypted_credentials = LazyFunction(
        lambda: encrypt_credentials('{"api_key": "test-key"}')
    )
    granted_scopes: list[str] = factory.LazyFunction(list)
    permission_tier = PermissionTier.user_confirm
    rate_limit_per_minute = 30
    created_at = LazyFunction(_now)
    updated_at = LazyFunction(_now)
