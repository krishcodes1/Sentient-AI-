"""Implements the security.* built-in family: one dispatcher that hands each
action to the handler a security skill registered at startup. Today's
actions are security.check_scam (S3: wording and link checks on a message the
user asks about), security.check_file (S10: a VirusTotal lookup by
fingerprint) and security.upload_to_virustotal (S10: a WRITE that sends one
file after its own approval card).

Why it exists: two skills built in parallel answer actions of one tool family,
and the executor has one ``_Builtin`` per family. Keeping the family's
dispatch here, with the skills registering their handlers from main.py, means
neither skill edits the executor and an action whose skill is not wired is
refused with a plain sentence instead of running anything. The executor still
decides approval before any call reaches this module (the upload is in its
confirm set); the handlers get ``approved`` only to know a person said yes.

Connects to: services/agent/tool_registry.py (the "security" catalog, the
executor's ``_builtins`` entry and the upload's card hooks, which read
``file_reputation``), main.py (registers the handlers),
services/scam_check (``check_for_tool``), services/file_reputation
(``FileReputationToolkit``).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional

import structlog

logger = structlog.get_logger(__name__)

# A handler answers one action for the executor's user: the call's parameters,
# the user id (the executor's, never the model's) and whether a person approved
# this exact call. It returns {"ok": True, ...} or {"ok": False, "error": ...}.
SecurityHandler = Callable[..., Awaitable[dict[str, Any]]]

# The two answers this module gives itself, fixed so the model is never shown
# an exception or a guess about why a check did not run.
NOT_AVAILABLE = "This safety check is not available right now."
CHECK_FAILED = "The safety check failed; nothing was checked."

# The S10 actions use_file_reputation registers, in catalog order.
FILE_ACTIONS: tuple[str, ...] = ("check_file", "upload_to_virustotal")


class SecurityToolkit:
    """The security.* built-in family: each action is answered by the handler a
    security skill registered at startup (main.py). An unregistered action is
    refused, never run."""

    def __init__(self) -> None:
        self._handlers: dict[str, SecurityHandler] = {}
        # S10's FileReputationToolkit once main.py wires it: the executor's
        # card hooks for security.upload_to_virustotal (describe, bind,
        # precheck) read it here, and refuse the upload while it is None.
        self.file_reputation: Optional[Any] = None

    def register(self, action: str, handler: SecurityHandler) -> None:
        """Answer *action* with *handler* from now on (a later registration of
        the same action replaces the earlier one)."""
        self._handlers[action] = handler

    def use_file_reputation(self, toolkit: Any) -> None:
        """Registers check_file and upload_to_virustotal to *toolkit*.execute and
        keeps the toolkit for describe/bind/precheck (the executor's upload card
        hooks)."""
        self.file_reputation = toolkit
        for action in FILE_ACTIONS:
            self.register(action, _file_handler(toolkit, action))

    async def execute(
        self, action: str, params: dict[str, Any], user_id: str, *, approved: bool = False
    ) -> dict[str, Any]:
        """Run *action*'s handler for *user_id*. Unknown -> {"ok": False, "error":
        NOT_AVAILABLE}; a handler that raises -> its error type is logged and the
        answer is {"ok": False, "error": CHECK_FAILED}. Never raises."""
        handler = self._handlers.get(action)
        if handler is None:
            return {"ok": False, "error": NOT_AVAILABLE}
        try:
            result = await handler(params, user_id, approved=approved)
        except Exception as exc:
            # Type only: a handler's message could quote the text being checked.
            logger.error("security_check_failed", action=action, error_type=type(exc).__name__)
            return {"ok": False, "error": CHECK_FAILED}
        if not isinstance(result, dict):
            logger.error("security_check_bad_result", action=action, result_type=type(result).__name__)
            return {"ok": False, "error": CHECK_FAILED}
        return result


def _file_handler(toolkit: Any, action: str) -> SecurityHandler:
    """A handler that forwards one S10 action to its toolkit (a closure per
    action, so the toolkit's ``execute`` keeps its own signature)."""

    async def handle(params: dict[str, Any], user_id: str, *, approved: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = await toolkit.execute(action, params, user_id, approved=approved)
        return result

    return handle
