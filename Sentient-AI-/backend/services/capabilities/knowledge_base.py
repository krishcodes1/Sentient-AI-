"""Declares the "knowledge_base" capability that gates the knowledge.* tools
(search, read, list, add, remove), the Telegram "/kb" caption and the owner's
knowledge base limits.

Why it exists: the registry lists it so the owner can switch the knowledge
base off in one place. It is on by default and low risk: documents are saved
only when the user asks (every save and delete from chat goes through an
approval card), the index lives on this computer, and passages reach the
model only as untrusted, scanned tool results. The limits are whole numbers
from 1 to 10000 (documents per user, MB of text per user, MB per file, and
thousands of embedding tokens per user per day), editable through
PUT /api/capabilities/knowledge_base/settings.
"""

from __future__ import annotations

from services.capabilities.base import Capability
from services.knowledge.limits import KNOWLEDGE_SETTINGS_DEFAULTS

__all__ = ["CAPABILITY", "KNOWLEDGE_SETTINGS_DEFAULTS"]

CAPABILITY = Capability(
    key="knowledge_base",
    label="Knowledge base (your documents)",
    description=(
        "Save documents you choose (uploads, web pages, Drive, OneDrive, Canvas and Notion "
        "files, notes) to collections on this computer and search them with citations. "
        "Saving or deleting from chat asks first."
    ),
    tools=("knowledge.",),
    default_enabled=True,
    risk="low",
    when_denied=(
        "The knowledge base is turned off. The owner can turn it on in Settings → Permissions."
    ),
)
