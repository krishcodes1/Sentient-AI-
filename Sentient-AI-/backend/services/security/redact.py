"""Applies a policy to text and to JSON-like data: says whether text holds a
secret, masks it, walks dicts and lists, lists the tool arguments that carry
one, and masks log events and log records.

Why it exists: every sink calls the same few functions instead of running the
detector itself, so each fails closed the same way: a detector error counts as
"found" for a refusal, and withholds the whole text for a mask.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, MutableMapping, Optional

from services.security.policies import LOGS, REDACTED, Policy
from services.security.secrets import Finding, Kind, find

# A finding reported when the detector itself failed: callers that refuse
# treat it as a hit, and it names no value.
DETECTOR_ERROR_LABEL = "value Crawler could not check"
# How deep redact_obj and argument_findings walk nested data; anything deeper
# is replaced whole (a mask) or reported (a refusal).
MAX_DEPTH = 32


@dataclass(frozen=True)
class Redacted:
    """Masked text and how many values of each label were hidden.
    ``withheld`` is True when the detector failed and the whole text was
    replaced by the policy's withheld marker."""

    text: str
    counts: dict[str, int] = field(default_factory=dict)
    withheld: bool = False

    @property
    def hidden(self) -> int:
        return sum(self.counts.values())


def findings(text: str, policy: Policy) -> list[Finding]:
    """The findings *policy* acts on in *text*. May raise (ScanTooLarge,
    a detector bug); the functions below turn that into a fail-closed
    answer."""
    return find(text, kinds=policy.kinds, min_confidence=policy.min_confidence)


def contains(text: str, policy: Policy) -> bool:
    """True when *text* holds anything *policy* acts on. A detector error
    returns True: a caller that refuses on True refuses what it could not
    check."""
    try:
        return bool(findings(text, policy))
    except Exception:  # noqa: BLE001 - fail closed
        return True


def first_finding(text: str, policy: Policy) -> Optional[Finding]:
    """The first finding *policy* acts on in *text*, or None. A detector
    error returns a finding labelled ``DETECTOR_ERROR_LABEL`` spanning the
    whole text, so a caller that acts on a finding still acts."""
    try:
        found = findings(text, policy)
    except Exception:  # noqa: BLE001 - fail closed
        return Finding("detector_error", Kind.credential, DETECTOR_ERROR_LABEL, 0, len(text), policy.min_confidence)
    return found[0] if found else None


def mask(text: str, found: list[Finding], placeholder: str) -> tuple[str, dict[str, int]]:
    """*text* with every finding replaced by *placeholder* (``{label}`` is
    the finding's label), and the count per label."""
    parts: list[str] = []
    counts: Counter[str] = Counter()
    cursor = 0
    for finding in found:
        parts.append(text[cursor : finding.start])
        parts.append(placeholder.format(label=finding.label))
        counts[finding.label] += 1
        cursor = finding.end
    parts.append(text[cursor:])
    return "".join(parts), dict(counts)


def redact_text(text: str, policy: Policy) -> Redacted:
    """*text* with what *policy* acts on replaced by its placeholder. A
    detector error gives the policy's withheld marker instead of the text."""
    try:
        found = findings(text, policy)
    except Exception:  # noqa: BLE001 - fail closed
        return Redacted(policy.withheld, {DETECTOR_ERROR_LABEL: 1}, withheld=True)
    if not found:
        return Redacted(text)
    masked, counts = mask(text, found, policy.placeholder)
    return Redacted(masked, counts)


def _key_redacted(key: Any, policy: Policy) -> bool:
    return policy.key_names is not None and bool(policy.key_names.search(str(key)))


def redact_obj(data: Any, policy: Policy, *, _depth: int = 0) -> Any:
    """A copy of *data* with every string masked by *policy* and, when the
    policy has key-name rules, the whole value of a matching key replaced
    by its placeholder. Dicts, lists and tuples are walked; other values
    are returned as they are."""
    if _depth > MAX_DEPTH:
        return policy.withheld
    if isinstance(data, str):
        return redact_text(data, policy).text
    if isinstance(data, dict):
        out: dict[Any, Any] = {}
        for key, value in data.items():
            if _key_redacted(key, policy):
                out[key] = policy.placeholder if "{label}" not in policy.placeholder else policy.withheld
            else:
                out[key] = redact_obj(value, policy, _depth=_depth + 1)
        return out
    if isinstance(data, list):
        return [redact_obj(item, policy, _depth=_depth + 1) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_obj(item, policy, _depth=_depth + 1) for item in data)
    return data


def _scan_labels(text: str, policy: Policy) -> list[str]:
    try:
        return [f.label for f in findings(text, policy)]
    except Exception:  # noqa: BLE001 - fail closed
        return [DETECTOR_ERROR_LABEL]


def _join(path: str, key: Any) -> str:
    return f"{path}.{key}" if path else str(key)


HIDDEN_KEY = "[hidden key]"


def _leaf_labels(value: Any, key: Any, policy: Policy) -> list[str]:
    """Labels *policy* finds in one leaf value: the value alone, then (when
    it has none) the value read as ``key: value``."""
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        return []
    labels = _scan_labels(text, policy)
    if not labels and isinstance(key, str) and text:
        # Only what reaches into the value counts: a finding in the key
        # alone is the key's own (argument_findings reports it there).
        stated = f"{key}: {text}"
        offset = len(key) + 2
        try:
            labels = [f.label for f in findings(stated, policy) if f.end > offset]
        except Exception:  # noqa: BLE001 - fail closed
            labels = [DETECTOR_ERROR_LABEL]
    return labels


def _key_labels(key: Any, policy: Policy) -> list[str]:
    return _scan_labels(key, policy) if isinstance(key, str) else []


def argument_findings(arguments: Any, policy: Policy) -> list[tuple[str, str]]:
    """``(path, label)`` for every value in *arguments* that *policy* acts
    on: "query", "to[0]", "headers.Authorization". A string under a key is
    also read as ``key: value``, so ``{"password": "Tr0ub4dor&3"}`` counts
    as a stated password. Keys are scanned too; a key that holds a finding
    is named ``[hidden key]`` in the path. Never the values."""
    hits: list[tuple[str, str]] = []

    def walk(value: Any, path: str, key: Any, depth: int) -> None:
        if depth > MAX_DEPTH:
            hits.append((path or "arguments", DETECTOR_ERROR_LABEL))
            return
        if isinstance(value, dict):
            for child_key, child in value.items():
                key_labels = _key_labels(child_key, policy)
                child_path = _join(path, HIDDEN_KEY if key_labels else child_key)
                hits.extend((child_path, label) for label in key_labels)
                walk(child, child_path, child_key, depth + 1)
            return
        if isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]", key, depth + 1)
            return
        hits.extend((path or "arguments", label) for label in _leaf_labels(value, key, policy))

    walk(arguments, "", None, 0)
    return list(dict.fromkeys(hits))


def mask_arguments(arguments: Any, policy: Policy, replacement: str = REDACTED) -> Any:
    """A copy of *arguments* with every value ``argument_findings`` would
    report replaced whole by *replacement*, and every key holding a finding
    renamed ``[hidden key]`` (numbered when there are several)."""

    def walk(value: Any, key: Any, depth: int) -> Any:
        if depth > MAX_DEPTH:
            return replacement
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            for child_key, child in value.items():
                name = child_key
                if _key_labels(child_key, policy):
                    name = HIDDEN_KEY if HIDDEN_KEY not in out else f"{HIDDEN_KEY} {len(out) + 1}"
                out[name] = walk(child, child_key, depth + 1)
            return out
        if isinstance(value, list):
            return [walk(item, key, depth + 1) for item in value]
        if isinstance(value, tuple):
            return tuple(walk(item, key, depth + 1) for item in value)
        return replacement if _leaf_labels(value, key, policy) else value

    return walk(arguments, None, 0)


def redact_log_event(_logger: Any, _method: str, event_dict: MutableMapping[str, Any]) -> Any:
    """structlog processor: every value of the event masked with LOGS (key
    names whole, values by the detector), exception text included; an
    exception object passed as a value is logged as its masked text. Never
    raises: a failure replaces the event with a marker."""
    try:
        event = {
            key: str(value) if isinstance(value, BaseException) else value
            for key, value in event_dict.items()
        }
        return redact_obj(event, LOGS)
    except Exception:  # noqa: BLE001 - a log line must never break the caller
        return {"event": LOGS.withheld, "log_redaction_failed": True}


def _redact_arg(value: Any) -> Any:
    return redact_text(value, LOGS).text if isinstance(value, str) else value


class SecretLogFilter(logging.Filter):
    """Masks secrets in stdlib log records (uvicorn's access and error
    logs, httpx): the message and each of its arguments, then the formatted
    whole, and the exception text. The record is always kept, and its
    arguments keep their shape (uvicorn's access formatter unpacks them)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = _redact_arg(record.msg)
            if isinstance(record.args, tuple):
                record.args = tuple(_redact_arg(arg) for arg in record.args)
            elif isinstance(record.args, dict):
                record.args = {key: _redact_arg(arg) for key, arg in record.args.items()}
            message = record.getMessage()
            redacted = redact_text(message, LOGS)
            if redacted.text != message and record.name != "uvicorn.access":
                # A value split across the message and an argument.
                record.msg, record.args = redacted.text, None
            if record.exc_info and not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = redact_text(record.exc_text, LOGS).text
        except Exception:  # noqa: BLE001 - a malformed record is left to the handler
            return True
        return True


__all__ = [
    "DETECTOR_ERROR_LABEL",
    "Redacted",
    "SecretLogFilter",
    "argument_findings",
    "contains",
    "findings",
    "first_finding",
    "mask",
    "mask_arguments",
    "redact_log_event",
    "redact_obj",
    "redact_text",
]
