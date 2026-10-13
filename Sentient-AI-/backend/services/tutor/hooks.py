"""The call-outs the agent runtime makes into tutor mode during a turn: the
block at the start, each tool call before the permission check, the
graded-page rule after a browser act is bound, the round boundary, and the
end of the turn.

Why it exists: runtime.py is shared by many features, so each call-out
there is a few lines that land here, where the tutor logic lives. Every
function takes the turn's ``TutorTurn`` and is only called when there is
one (the ``tutor_mode`` capability is on and the turn runs in a
conversation).

Connects to: services/agent/runtime.py (the caller; PrecheckRefusal is
imported at call time, since the runtime imports this module) and
services/tutor/state.py, policy.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog

from services.tutor.policy import (
    GRADED_PAGE_REASON,
    GRADED_WORK_RULE,
    TUTOR_MODE_POLICY,
    TUTOR_RULE_POLICY,
    TUTOR_START_TOOL,
    WITHHELD_LOCKED_REASON,
    WITHHELD_REASON,
    canonical_name,
    graded_work_page,
    is_withheld,
)
from services.tutor.state import TutorTurn

logger = structlog.get_logger(__name__)

# The browser.act card's page (``services.tools.browser.act.CARD_KEY``) and
# its address, the sha1 of the page URL without its fragment
# (``services.tools.browser.pagememory.page_address``).
_PAGE_KEY = "_page"
_BROWSER_ACT = "browser.act"


def _newest_user_text(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if message.get("role") != "user":
            continue
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return " ".join(
                str(part.get("text", ""))
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        return ""
    return ""


def begin_turn(tutor: TutorTurn, messages: list[dict[str, Any]]) -> Optional[str]:
    """Engage a course lock the newest user message names, then return the
    block the system message starts the turn with (None: tutor mode off).
    Run before the system prompt is built, so the first request, and the
    replay cache's key, already carry the right block."""
    tutor.engage_from_text(_newest_user_text(messages))
    tutor.applied_block = tutor.block
    return tutor.applied_block


@dataclass(frozen=True)
class CallAnswer:
    """What the runtime records for a call tutor mode answered itself: its
    result record, the block (reason, policy) when it was refused, and
    whether it ran (tutor.start does; a refusal does not)."""

    record: dict[str, Any]
    blocked: Optional[tuple[str, str]] = None
    ran: bool = False


EventSink = Callable[[dict[str, Any]], Awaitable[None]]


async def answer_call(
    tutor: TutorTurn,
    tool_call_id: str,
    tool_name: str,
    arguments: Any,
    *,
    user_id: str,
    emit: EventSink,
    audit: Any,
) -> Optional[CallAnswer]:
    """Tutor mode's part of one tool call, before the permission check.

    - tutor.start is answered here (it turns the mode on; the block comes
      in from the next round).
    - Any other call's own arguments may engage a course lock first, then a
      withheld tool (canvas.submit_assignment) is refused while the mode is
      on: a ``tool_blocked`` row under policy ``tutor_mode``, and the
      refusal as the call's result so the model can say why.
    None: the call goes on through the usual checks."""
    if canonical_name(tool_name) == TUTOR_START_TOOL:
        result = tutor.start_by_tool()
        await emit({"type": "tool_call", "data": {"name": tool_name}})
        try:
            await audit.log(
                {
                    "event": "tool_executed",
                    "user_id": user_id,
                    "tool": tool_name,
                    "arguments": {},
                    "result_summary": str(result.get("tutor", "")),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        except Exception as exc:  # the switch only made the assistant stricter
            logger.error("audit_write_failed_tutor_start", error=str(exc)[:200])
        await emit({"type": "tool_result", "data": {"name": tool_name}})
        return CallAnswer(
            record={"tool_call_id": tool_call_id, "name": tool_name, "result": result},
            ran=True,
        )

    tutor.engage_from_call(tool_name, arguments)
    if not (tutor.effective.on and is_withheld(tool_name)):
        return None
    reason = (
        WITHHELD_LOCKED_REASON
        if tutor.effective.locked
        else WITHHELD_REASON.format(off=tutor.off_command)
    )
    await emit(
        {"type": "blocked", "data": {"tool": tool_name, "reason": reason, "policy": TUTOR_MODE_POLICY}}
    )
    try:
        await audit.log(
            {
                "event": "tool_blocked",
                "user_id": user_id,
                "tool": tool_name,
                "arguments": arguments,
                "reason": reason,
                "policy": TUTOR_MODE_POLICY,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as exc:  # nothing ran, so the refusal stands
        logger.error("audit_write_failed_tutor_refusal", tool=tool_name, error=str(exc)[:200])
    return CallAnswer(
        record={
            "tool_call_id": tool_call_id,
            "name": tool_name,
            "result": {"ok": False, "refused": True, "error": reason},
        },
        blocked=(reason, TUTOR_MODE_POLICY),
    )


def _page_address(url: str) -> str:
    """``services.tools.browser.pagememory.page_address``: kept in step with
    it by tests/test_tutor_runtime.py."""
    return hashlib.sha1(url.partition("#")[0].encode("utf-8")).hexdigest()


def _remembered_page_url(executor: Any, user_id: str) -> Optional[str]:
    """The URL of the page the browser toolkits last observed for *user_id*
    (the page a browser.act card is bound to), when the executor is the
    real one; None otherwise."""
    try:
        memory = getattr(getattr(executor, "_act", None), "_memory", None)
        get = getattr(memory, "get", None)
        last = get(user_id) if callable(get) else None
        url = getattr(last, "url", None)
    except Exception:
        return None
    return url if isinstance(url, str) and url else None


def bound_page_url(
    tutor: TutorTurn, card_arguments: Mapping[str, Any], *, executor: Any, user_id: str
) -> Optional[str]:
    """The URL of the page a browser.act card is bound to: the address on
    the card is a hash, so it is matched against the page the browser last
    observed and the pages this turn's own calls opened. None when no
    candidate matches."""
    page = card_arguments.get(_PAGE_KEY)
    address = page.get("address") if isinstance(page, Mapping) else None
    if not isinstance(address, str) or not address:
        return None
    candidates = [_remembered_page_url(executor, user_id), *reversed(tutor.seen_urls)]
    for url in candidates:
        if url and _page_address(url) == address:
            return url
    return None


def graded_page_refusal(
    tutor: TutorTurn,
    tool_name: str,
    card_arguments: Mapping[str, Any],
    *,
    executor: Any,
    user_id: str,
) -> Any:
    """A ``PrecheckRefusal`` (policy ``tutor_rule``, rule
    ``graded_work_page``) for a browser.act bound to a Canvas quiz,
    assignment-submission or graded-discussion page while tutor mode is on;
    None otherwise (the card is made as usual)."""
    if not tutor.effective.on or canonical_name(tool_name) != _BROWSER_ACT:
        return None
    url = bound_page_url(tutor, card_arguments, executor=executor, user_id=user_id)
    if url is None or not graded_work_page(url):
        return None
    # Deferred: the runtime imports this module.
    from services.agent.runtime import PrecheckRefusal

    return PrecheckRefusal(
        reason=GRADED_PAGE_REASON,
        policy=TUTOR_RULE_POLICY,
        result={"ok": False, "refused": True, "rule": GRADED_WORK_RULE, "error": GRADED_PAGE_REASON},
        rule=GRADED_WORK_RULE,
    )


def end_of_round(
    tutor: TutorTurn,
    messages: list[dict[str, Any]],
    all_tool_schemas: list[dict[str, Any]],
    tool_schemas: list[dict[str, Any]],
) -> Optional[tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]]:
    """When this round changed the mode: the messages with the new block at
    the end of the system message, and both tool lists without what the
    mode now withholds (tutor.start included). None when nothing changed."""
    if not tutor.block_changed():
        return None
    return (
        tutor.apply_block(messages),
        tutor.offered(all_tool_schemas),
        tutor.offered(tool_schemas),
    )


async def end_turn(tutor: TutorTurn, final_content: str, *, user_id: str, audit: Any) -> str:
    """The reply with this turn's notice (the mode came on), and the turn's
    tutor events written to the audit log. Audit rows carry ids and
    how-it-happened only, never message text or what matched."""
    for event in tutor.drain_events():
        name = event.pop("event")
        try:
            await audit.log(
                {
                    "event": name,
                    "user_id": user_id,
                    "arguments": event,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        except Exception as exc:  # the state itself is persisted by the caller
            logger.error("audit_write_failed_tutor_event", tutor_event=name, error=str(exc)[:200])
    notice = tutor.take_notice()
    if not notice:
        return final_content
    body = (final_content or "").rstrip()
    return f"{body}\n\n{notice}" if body else notice
