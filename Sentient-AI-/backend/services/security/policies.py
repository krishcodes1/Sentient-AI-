"""Names what each place that handles text does with a finding: refuse the text,
mask the value, or swap it for a placeholder.

Why it exists: the detector (``secrets.py``) only says where a value is. Memory,
the audit log, the logs, Telegram and Slack, tool arguments, the model request
and a search index each need a different answer, and keeping those answers in
one table means a sink cannot quietly drift from the others.

The deliberate split on cards: the audit log and memory keep their broad "any
13-19 digit run" rule (LOW), so nothing they redacted or refused before gets
through now. Channels, tool arguments and the model act from MEDIUM, where a
card needs the Luhn check and an issuer prefix, so order numbers, chat ids and
millisecond timestamps stay readable there.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Optional

from services.security.secrets import CONTACT_KINDS, SECRET_KINDS, Confidence, Kind

Mode = Literal["refuse", "mask", "pseudonymize"]

REDACTED = "***REDACTED***"

# What the model sees in place of a message part the detector could not
# check (a scan error, text over the size limit).
MODEL_WITHHELD = "[withheld by Crawler: could not be checked for secrets]"
# What a chat channel sends in place of text the detector could not check.
CHANNEL_WITHHELD = (
    "Crawler could not check this message for keys or card numbers, so it is not "
    "shown here. Open Crawler AI to read it."
)

# Key names whose whole value the audit log redacts, matched anywhere in the
# key (moved from services/audit.py): OAuth PKCE verifiers, a device code only
# at the end of the key (so "device_code_url" is kept), and OAuth codes and
# states only as the WHOLE key ("statement", "zip_code", "barcode" are kept).
AUDIT_KEY_NAMES = re.compile(
    r"(token|password|passwd|secret|api[_-]?key|access[_-]?key|"
    r"authorization|credential|private[_-]?key|client[_-]?secret|"
    r"session[_-]?id|cookie|bearer|refresh[_-]?token|ssn|"
    r"credit[_-]?card|card[_-]?number|cvv|cvc|"
    r"code[_-]?verifier|device[_-]?code(?![_-]?[a-z0-9]))|"
    r"^(?:code|state|oauth[_-]?(?:code|state)|auth[_-]?code)$",
    re.IGNORECASE,
)

# Key names whose value the logs mask, compared whole and case-insensitively
# (moved from core/security.py). Exact names, so "input_tokens" is kept.
LOG_KEY_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "credentials",
        "credit_card",
        "ssn",
        "encryption_key",
        "secret_key",
        "access_token",
        "refresh_token",
    }
)
_LOG_KEY_NAMES_RE = re.compile(
    "^(?:" + "|".join(re.escape(name) for name in sorted(LOG_KEY_NAMES)) + ")$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Policy:
    """How one sink treats findings.

    ``kinds`` and ``min_confidence`` choose the rules; ``mode`` says what
    happens to a finding; ``placeholder`` is the replacement text, where
    ``{label}`` is the finding's label; ``key_names`` (when set) redacts a
    dict value whole when its key matches; ``withheld`` replaces the whole
    text when the detector fails.
    """

    name: str
    kinds: frozenset[Kind]
    min_confidence: Confidence
    mode: Mode
    placeholder: str
    key_names: Optional["re.Pattern[str]"] = None
    withheld: str = REDACTED


MEMORY = Policy(
    name="memory",
    kinds=SECRET_KINDS,
    min_confidence=Confidence.HINT,
    mode="refuse",
    placeholder="[hidden: {label}]",
)

AUDIT = Policy(
    name="audit",
    kinds=SECRET_KINDS,
    min_confidence=Confidence.LOW,
    mode="mask",
    placeholder=REDACTED,
    key_names=AUDIT_KEY_NAMES,
    withheld=REDACTED,
)

LOGS = Policy(
    name="logs",
    kinds=SECRET_KINDS,
    min_confidence=Confidence.LOW,
    mode="mask",
    placeholder=REDACTED,
    key_names=_LOG_KEY_NAMES_RE,
    withheld=REDACTED,
)

CHANNEL = Policy(
    name="channel",
    kinds=SECRET_KINDS,
    min_confidence=Confidence.MEDIUM,
    mode="mask",
    placeholder="[hidden: {label}]",
    withheld=CHANNEL_WITHHELD,
)

TOOL_ARGS = Policy(
    name="tool_args",
    kinds=SECRET_KINDS,
    min_confidence=Confidence.MEDIUM,
    mode="refuse",
    placeholder="[hidden: {label}]",
)

MODEL_FLOOR = Policy(
    name="model_floor",
    kinds=SECRET_KINDS,
    min_confidence=Confidence.MEDIUM,
    mode="mask",
    placeholder="[hidden by Crawler: {label}]",
    withheld=MODEL_WITHHELD,
)

# Contact details for a cloud model: swapped for per-turn placeholders
# (services/security/pseudonyms.py). ``placeholder`` is the irreversible
# form, used past the per-turn cap and for embeddings: "[email]".
MODEL_PERSONAL = Policy(
    name="model_personal",
    kinds=CONTACT_KINDS,
    min_confidence=Confidence.MEDIUM,
    mode="pseudonymize",
    placeholder="[{label}]",
    withheld=MODEL_WITHHELD,
)

# Stored search passages (the knowledge base): the model floor, so a search
# never returns a raw key.
INDEX = Policy(
    name="index",
    kinds=MODEL_FLOOR.kinds,
    min_confidence=MODEL_FLOOR.min_confidence,
    mode=MODEL_FLOOR.mode,
    placeholder=MODEL_FLOOR.placeholder,
    withheld=MODEL_FLOOR.withheld,
)

POLICIES: dict[str, Policy] = {
    p.name: p
    for p in (MEMORY, AUDIT, LOGS, CHANNEL, TOOL_ARGS, MODEL_FLOOR, MODEL_PERSONAL, INDEX)
}

__all__ = [
    "AUDIT",
    "AUDIT_KEY_NAMES",
    "CHANNEL",
    "CHANNEL_WITHHELD",
    "INDEX",
    "LOGS",
    "LOG_KEY_NAMES",
    "MEMORY",
    "MODEL_FLOOR",
    "MODEL_PERSONAL",
    "MODEL_WITHHELD",
    "Mode",
    "POLICIES",
    "Policy",
    "REDACTED",
    "TOOL_ARGS",
]
