"""Declares the "knowledge_semantic" capability: the knowledge base's meaning
(vector) index, built in the background and used by knowledge.search.

Why it exists: building the index sends document text to an embedding model.
With Ollama that stays on this computer; with Gemini or OpenAI the passages
(keys, card and ID numbers always removed first, contact details too while
"Hide personal details" is on) go to the owner's configured AI provider, so
it is its own switch, off by default, medium risk, and needs the knowledge
base on. It gates no tool (tools=()): the embed sweeper and knowledge.search
read it. It is blocked when the install's provider has no embedding model
(ReportContext.embedding_backend is empty); keyword search still works then.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext

NO_BACKEND_REASON = (
    "Your AI provider has no embedding model Crawler can use; keyword search still works. "
    "Use Gemini, OpenAI or Ollama, or set KB_EMBEDDINGS=ollama."
)


def availability(ctx: ReportContext) -> Availability:
    if ctx.embedding_backend:
        return Availability(True)
    return Availability(False, NO_BACKEND_REASON)


CAPABILITY = Capability(
    key="knowledge_semantic",
    label="Smarter knowledge search (meaning index)",
    description=(
        "Also finds passages by meaning. With Ollama the index is built on this computer; "
        "with Gemini or OpenAI your document text (with keys, card and ID numbers removed) "
        "is sent to that provider (your configured AI provider) to build it."
    ),
    tools=(),
    default_enabled=False,
    risk="medium",
    requires=("knowledge_base",),
    when_denied=(
        "Smarter knowledge search is off, so knowledge.search uses keywords only. The owner "
        "can turn it on in Settings → Permissions."
    ),
    availability=availability,
)
