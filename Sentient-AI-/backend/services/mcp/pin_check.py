"""The MCP tool-pin call check (security S5): slot 2 of the pre-dispatch
call checks. An MCP tool whose definition is not the one the owner approved
is refused before any card, again at approval and again at execute.

Why it exists: the catalog stops offering a changed tool, but a card parked
before the change, or a model that names the tool anyway, must not run the
new definition. The check reads the pins (database only, no cache: it is the
fail-closed gate, and MCP calls are rare) and never escalates, because every
MCP call already needs a card. What it answers:

- not an MCP call: the check does not apply (no I/O at all);
- the switch off, a malformed name, or no active MCP connector with that
  label: Allow (the adapter and the dispatcher answer those cases as today);
- every connector with the label has the tool approved, or a connector has no
  pins yet (the dispatcher pins it on first use): Allow, or a warning note
  when the approved definition carried hidden characters (Crawler removed them
  before the AI read it, and the owner deciding on the card should know);
- otherwise Refuse with the pin's rule and the fixed sentence of
  pinning.refusal_message, policy ``mcp_pin``; a database error refuses with
  ``mcp_pin_unavailable`` (fail closed). The pipeline drops notes at the
  approve and execute stages, so there the check only ever refuses.

Connects to: services/security/call_checks.py (the pipeline),
services/mcp/pin_store.py (``McpPinService.check_call``), main.py.
"""

from __future__ import annotations

import structlog

from services.mcp.pin_notify import hidden_text_note
from services.mcp.pin_store import McpPinService
from services.mcp.pinning import PIN_POLICY, RULE_PIN_UNAVAILABLE, refusal_message
from services.security.call_checks import ALLOW, CallFacts, Note, Refuse, SecurityNote, Verdict

logger = structlog.get_logger(__name__)

CHECK_NAME = "mcp_pin"
MCP_PIN_POLICY = PIN_POLICY


def _is_mcp(call: CallFacts) -> bool:
    # Deferred: integration imports the pin store.
    from services.mcp.integration import is_mcp_tool

    return bool(call.is_mcp) or is_mcp_tool(str(call.canonical))


def _unavailable(tool_name: str) -> Refuse:
    from services.mcp.integration import split_mcp_tool

    label, tool = split_mcp_tool(tool_name) or ("", tool_name)
    return Refuse(
        rule=RULE_PIN_UNAVAILABLE,
        message=refusal_message(RULE_PIN_UNAVAILABLE, tool=tool, label=label),
        policy=MCP_PIN_POLICY,
    )


class McpPinCallCheck:
    """S5's place in the call checks (see the module docstring)."""

    name = CHECK_NAME
    policy = MCP_PIN_POLICY
    stages: frozenset[str] = frozenset({"turn", "approve", "execute"})
    timeout_s = 1.0

    def __init__(self, pins: McpPinService) -> None:
        self._pins = pins

    def applies_to(self, call: CallFacts) -> bool:
        """MCP calls only; cheap and without I/O."""
        return _is_mcp(call)

    async def check(self, call: CallFacts) -> Verdict:
        """Allow, a hidden-text note, or a refusal for a changed, new, kept-off,
        removed or unreadable pin. Arguments are never read."""
        if not _is_mcp(call):
            return ALLOW
        tool_name = str(call.canonical or call.tool_name)
        try:
            verdict = await self._pins.check_call(str(call.user_id), tool_name)
        except Exception as exc:
            # check_call answers its own database errors; anything else is a
            # bug, and an integrity gate that cannot decide refuses.
            logger.warning("mcp_pin_check_crashed", error_type=type(exc).__name__)
            return _unavailable(tool_name)
        if not verdict.allowed:
            if not verdict.rule or not verdict.message:
                return _unavailable(tool_name)
            return Refuse(rule=verdict.rule, message=verdict.message, policy=MCP_PIN_POLICY)
        note = hidden_text_note(verdict.hidden_chars)
        parsed = SecurityNote.from_value(note) if note is not None else None
        if parsed is not None:
            return Note((parsed,))
        return ALLOW
