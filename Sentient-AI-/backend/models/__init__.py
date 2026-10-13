"""Imports every ORM model so Base.metadata is complete, and re-exports them and their enums."""

from models.app_approval import AppApproval
from models.audit import AuditLog, AuditStatus
from models.connector import (
    AuthMethod,
    ConnectorConfig,
    ConnectorType,
    PermissionTier,
)
from models.conversation import Conversation, Message, MessageRole
from models.installation import INSTALLATION_ROW_ID, Installation
from models.memory import Memory, MemoryCategory, MemorySource
from models.oauth_state import OAuthFlowKind, OAuthFlowStatus, OAuthState
from models.page_watch import PageWatch, PageWatchStatus
from models.pending_action import PendingAction, PendingActionStatus
from models.reminder import Reminder, ReminderSource, ReminderStatus
from models.slack_link import SlackChannelLink
from models.user import User
from models.vault_item import VaultItem

# Each top10 skill adds its imports under its own anchor. isort is off
# here so they stay there and parallel branches merge cleanly.
# isort: off
# top10:secret_pii_redaction

# top10:file_extraction
from models.user_file import UserFile

# top10:scheduler_briefing
from models.scheduled_task import AutomationRun, ScheduledTask

# top10:tutor_mode
from models.tutor_lock import TutorLock

# top10:knowledge_base
from models.knowledge import KbChunk, KbCollection, KbDocument, KbEmbedding, KbPosting

# top10:flashcards_quizzes
from models.study import StudyDeck, StudyItem, StudyQuizAttempt, StudyReview, StudySettings

# top10:event_triggers
from models.event_trigger import EventTrigger, TriggerEvent

# top10:permission_tiers
from models.permission_grant import PermissionGrantRow

# top10:voice_notes

# top10:video_transcripts
from models.media_transcript import MediaTranscript

# isort: on

__all__ = [
    "INSTALLATION_ROW_ID",
    "AppApproval",
    "AuditLog",
    "AuditStatus",
    "AuthMethod",
    "ConnectorConfig",
    "ConnectorType",
    "Conversation",
    "Installation",
    "Memory",
    "MemoryCategory",
    "MemorySource",
    "Message",
    "MessageRole",
    "OAuthFlowKind",
    "OAuthFlowStatus",
    "OAuthState",
    "PageWatch",
    "PageWatchStatus",
    "PendingAction",
    "PendingActionStatus",
    "PermissionTier",
    "Reminder",
    "ReminderSource",
    "ReminderStatus",
    "SlackChannelLink",
    "User",
    "VaultItem",
    # top10:secret_pii_redaction

    # top10:file_extraction
    "UserFile",

    # top10:scheduler_briefing
    "AutomationRun",
    "ScheduledTask",

    # top10:tutor_mode
    "TutorLock",

    # top10:knowledge_base
    "KbChunk",
    "KbCollection",
    "KbDocument",
    "KbEmbedding",
    "KbPosting",

    # top10:flashcards_quizzes
    "StudyDeck",
    "StudyItem",
    "StudyQuizAttempt",
    "StudyReview",
    "StudySettings",

    # top10:event_triggers
    "EventTrigger",
    "TriggerEvent",

    # top10:permission_tiers
    "PermissionGrantRow",

    # top10:voice_notes

    # top10:video_transcripts
    "MediaTranscript",

]
