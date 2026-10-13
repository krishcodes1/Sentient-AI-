"""Decides whether a tool call may go ahead with the arguments it carries, and
writes the turn's one "sensitive data hidden" audit row.

Why it exists: the runtime runs this for EVERY tool call (reads, web.*, MCP and
tools.find included), after the prompt-guard argument scan and before the
weekly-app branch and any approval card; approve_action runs it again on the
stored arguments. A call is refused when it carries a placeholder this turn
never minted, or a key, password, card, bank or ID number. What the model,
the audit row and the blocked event are told names the field and the kind of
value, never the value.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Protocol

import structlog

from services.security.egress import ModelEgress
from services.security.policies import AUDIT, REDACTED, TOOL_ARGS
from services.security.redact import (
    DETECTOR_ERROR_LABEL,
    argument_findings,
    mask_arguments,
    redact_obj,
)
from services.security.secrets import with_article

logger = structlog.get_logger(__name__)

SECRET_GUARD_POLICY = "secret_guard"
UNKNOWN_PLACEHOLDER_RULE = "unknown_placeholder"
CREDENTIAL_RULE = "credential_in_arguments"
HIDDEN_EVENT = "sensitive_data_hidden"

# Tools whose stored card arguments carry what the runtime bound them to
# under a reserved "_" key (the screen or page the card was made from),
# which the model can never set and which is never sent anywhere.
_RESERVED_KEY_TOOLS = frozenset({"desktop.act", "browser.act", "browser.checkout"})


@dataclass(frozen=True)
class GuardRefusal:
    """Why a call was refused. ``result`` is what the model is shown;
    ``audit_arguments`` is the call's arguments with every flagged value
    replaced, for the audit row."""

    rule: str
    reason: str
    result: dict[str, Any]
    audit_arguments: Any


class AuditSink(Protocol):
    async def log(self, entry: dict[str, Any]) -> None: ...


def _credential_refusal(arguments: Any, hits: list[tuple[str, str]]) -> GuardRefusal:
    fields = [{"field": path, "looks_like": label} for path, label in hits]
    path, label = hits[0]
    if label == DETECTOR_ERROR_LABEL:
        said = f"Crawler could not check the '{path}' argument for keys or card numbers"
    else:
        said = f"The '{path}' argument holds what looks like {with_article(label)}"
    error = (
        f"Refused: {said}. Crawler never puts keys, passwords, card, bank or ID numbers "
        "into a tool call, and nothing was sent. If it was only an example, write "
        "YOUR_API_KEY (or a similar placeholder) instead; if a real one is needed, ask "
        "the user to enter it themselves where it is needed."
    )
    reason = (
        "The call's arguments carry what looks like "
        + ", ".join(sorted({with_article(h[1]) for h in hits}))
        + f" ({', '.join(dict.fromkeys(h[0] for h in hits))}); refused before any card."
    )
    # Flagged values are replaced whole; the rest still passes the audit
    # sanitiser (again on the way in).
    audit_arguments = redact_obj(mask_arguments(arguments, TOOL_ARGS, REDACTED), AUDIT)
    return GuardRefusal(
        rule=CREDENTIAL_RULE,
        reason=reason,
        result={"ok": False, "refused": True, "rule": CREDENTIAL_RULE, "error": error, "fields": fields},
        audit_arguments=audit_arguments,
    )


def check_call(
    tool_call_id: str, arguments: Any, egress: Optional[ModelEgress]
) -> Optional[GuardRefusal]:
    """The refusal for one tool call, or None when it may go ahead: a
    placeholder this turn never minted (the call's own error: the model
    is told to use the ones it was given), or a key, password, card, bank
    or ID number in any argument (a security block)."""
    unknown = egress.unknown_placeholders(tool_call_id) if egress is not None else []
    if unknown:
        count = len(unknown)
        error = (
            f"Refused: the arguments use {count} placeholder{'s' if count != 1 else ''} "
            "Crawler did not give you in this conversation. Copy placeholders exactly as "
            "they appear, or ask the user for the detail; nothing was sent."
        )
        return GuardRefusal(
            rule=UNKNOWN_PLACEHOLDER_RULE,
            reason=f"{count} unknown placeholder{'s' if count != 1 else ''} in the arguments",
            result={"ok": False, "refused": True, "rule": UNKNOWN_PLACEHOLDER_RULE, "error": error},
            audit_arguments=arguments,
        )
    hits = argument_findings(arguments, TOOL_ARGS)
    if hits:
        return _credential_refusal(arguments, hits)
    return None


def check_stored(tool_name: str, arguments: Any) -> Optional[GuardRefusal]:
    """The refusal for an approved card's stored arguments, or None. The
    reserved "_" keys a desktop.act, browser.act or browser.checkout card
    stores (the screen or page it was made from) are not read."""
    if tool_name in _RESERVED_KEY_TOOLS and isinstance(arguments, Mapping):
        arguments = {k: v for k, v in arguments.items() if not str(k).startswith("_")}
    hits = argument_findings(arguments, TOOL_ARGS)
    return _credential_refusal(arguments, hits) if hits else None


def _describe(summary: Mapping[str, int], provider: str) -> str:
    parts = [
        f"{count} {label}{'' if count == 1 or label.endswith('s') else 's'}"
        for label, count in sorted(summary.items())
    ]
    listed = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return f"Hid {listed} from the AI provider ({provider or 'unknown'})."


async def record_hidden(
    audit: AuditSink, user_id: str, provider: str, egress: Optional[ModelEgress]
) -> None:
    """Write the turn's one ``sensitive_data_hidden`` audit row when values
    new this turn were hidden from the provider: labels, counts and the
    provider only. Best effort: the turn has finished either way."""
    if egress is None:
        return
    summary = egress.hidden_summary()
    if not summary:
        return
    logger.info(
        "model_egress_hidden",
        values=sum(summary.values()),
        kinds=len(summary),
        withheld_parts=egress.withheld_parts,
    )
    try:
        await audit.log(
            {
                "event": HIDDEN_EVENT,
                "user_id": user_id,
                "arguments": {
                    "provider": provider,
                    "hidden": [
                        {"label": label, "count": count} for label, count in sorted(summary.items())
                    ],
                },
                "reason": _describe(summary, provider),
                "policy": "model_egress",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as exc:  # noqa: BLE001 - never fails a finished turn
        logger.error("audit_write_failed_sensitive_data_hidden", error_type=type(exc).__name__)


__all__ = [
    "CREDENTIAL_RULE",
    "GuardRefusal",
    "HIDDEN_EVENT",
    "SECRET_GUARD_POLICY",
    "UNKNOWN_PLACEHOLDER_RULE",
    "check_call",
    "check_stored",
    "record_hidden",
]
