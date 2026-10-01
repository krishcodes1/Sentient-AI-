"""The document context a tool call runs in: whose documents, which registry
and sandbox, and whether "Read files and documents" is on.

Why it exists: web.fetch_page and the connector file readers find a PDF in
the middle of a call, deep in code that has no user id and no capability
gate. The executor binds a DocumentContext around the web and connector
dispatch (ConnectorToolExecutor._web_call and _invoke_connector); the reader
asks ``document_refusal`` when it meets a document. The switch is read then,
lazily, through the executor's own capability gate, the way the web
search's browser fallback reads its switch: a call that never meets a
document never reads the report. Unbound, or a gate that fails, answers with
file_reading's when_denied text (fail closed).
"""

from __future__ import annotations

import contextlib
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterator, Optional

import structlog

from services.files import messages

logger = structlog.get_logger(__name__)

# Answers None when documents may be read, else the refusal text.
DocumentGate = Callable[[], Awaitable[Optional[str]]]


@dataclass(frozen=True)
class DocumentContext:
    """``user_id`` is the executor's (never a tool argument's); ``registry``
    a DocumentRegistry and ``sandbox`` a Sandbox; ``gate`` the lazy switch
    check (None: allowed, for callers that already checked it)."""

    user_id: str
    registry: Any
    sandbox: Any
    gate: Optional[DocumentGate] = None


_current: ContextVar[Optional[DocumentContext]] = ContextVar("document_context", default=None)


def current() -> Optional[DocumentContext]:
    """The context bound for the call in progress, or None."""
    return _current.get()


@contextlib.contextmanager
def bind(context: Optional[DocumentContext]) -> Iterator[Optional[DocumentContext]]:
    """Make *context* current for the body (None unbinds)."""
    token = _current.set(context)
    try:
        yield context
    finally:
        _current.reset(token)


async def document_refusal(context: Optional[DocumentContext] = None) -> Optional[str]:
    """None when documents may be read in *context* (the current one by
    default); otherwise the sentence to answer with."""
    context = context if context is not None else current()
    if context is None:
        return messages.SWITCHED_OFF
    if context.gate is None:
        return None
    try:
        return await context.gate()
    except Exception as exc:  # fail closed; the type only (a message can quote a DSN)
        logger.warning("document_gate_failed", error_type=type(exc).__name__)
        return messages.SWITCHED_OFF
