"""Tracks values that entered the conversation from untrusted tool results and
flags tool arguments that reuse them.

Why it exists: A write whose arguments were derived from fetched content must
not run on standing consent; the runtime asks TaintTracker before auto-
approving so such calls reach a human instead.

CaMeL-lite taint tracking for the agent loop.

Deterministic, server-side defense against indirect prompt injection that
drives a *side-effectful* action. The model-facing envelope (spotlighting)
and the system prompt are probabilistic — a capable enough attack can still
talk the model into calling a write tool. This layer does not rely on the
model behaving: it tracks which values entered the conversation from
UNTRUSTED tool results, and refuses to let those values silently
parameterize an auto-approved write.

The rule, following DeepMind's CaMeL and Willison's dual-LLM pattern:

    A side-effectful tool call whose arguments are derived from untrusted
    tool-result data may not be auto-approved. It is re-escalated to the
    human approval flow instead of executing on standing consent.

So "read the latest email and reply to the sender" still works — it just
surfaces an approval card showing the tainted recipient, instead of firing
a send on a recipient an attacker may have injected. Reads are never gated
(they have no side effect); writes that already require approval are
unaffected (a human sees them regardless).

Taint is detected on high-signal *redirection / exfiltration indicators* —
email addresses, URLs/hosts, and long verbatim strings — rather than on
incidental word overlap, so a model-drafted email body does not trip the
gate just because it quotes a word from the source message.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# Indicators an attacker uses to redirect a side effect: where a message
# goes (recipient), where data is sent (URL/host), or an exact identifier
# copied verbatim from injected content.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

# An opaque identifier / code / token: a run this long that carries a digit
# or several separators, so it is not an ordinary natural-language word.
# Copied verbatim from untrusted data into a write argument (an account
# number, confirmation code, or smuggled token), it is treated as
# attacker-controlled.
_MIN_TOKEN_LEN = 12
_OPAQUE_TOKEN_RE = re.compile(r"[^\s]{%d,}" % _MIN_TOKEN_LEN)
_HAS_DIGIT_RE = re.compile(r"\d")
_SEPARATORS = "-_./:"

# A whole verbatim run this long copied from untrusted data is also flagged
# even without opaque shape (a smuggled phrase).
_MIN_VERBATIM_LEN = 24


def _is_opaque(token: str) -> bool:
    """True for identifier-shaped tokens (has a digit, or 2+ separators)."""
    if len(token) < _MIN_TOKEN_LEN:
        return False
    if _HAS_DIGIT_RE.search(token):
        return True
    return sum(token.count(sep) for sep in _SEPARATORS) >= 2


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def extract_indicators(text: str) -> set[str]:
    """Pull redirection/exfiltration indicators out of a blob of text.

    Returns a set of normalized indicator strings (emails, full URLs, and
    bare hostnames). Used on both the untrusted corpus and on individual
    argument values; an intersection means the argument points somewhere
    that appeared in untrusted data.
    """
    if not text:
        return set()
    indicators: set[str] = set()
    for match in _EMAIL_RE.findall(text):
        indicators.add(match.lower())
    for match in _URL_RE.findall(text):
        indicators.add(match.rstrip(".,);").lower())
    for match in _HOST_RE.findall(text):
        # Skip hosts that are only the domain half of an email already
        # captured; the email itself is the stronger indicator.
        indicators.add(match.lower())
    for match in _OPAQUE_TOKEN_RE.findall(text):
        token = match.strip(_SEPARATORS + ".,;)")
        if _is_opaque(token):
            indicators.add(token.lower())
    return indicators


def _iter_arg_strings(arguments: Any) -> Iterable[str]:
    """Yield every string leaf in a (possibly nested) arguments object."""
    if isinstance(arguments, str):
        yield arguments
    elif isinstance(arguments, dict):
        for value in arguments.values():
            yield from _iter_arg_strings(value)
    elif isinstance(arguments, (list, tuple)):
        for value in arguments:
            yield from _iter_arg_strings(value)


class TaintTracker:
    """Accumulates untrusted tool-result text and flags derived arguments.

    One instance lives for a single ``chat`` turn. Tool results are folded
    in as they are produced; each subsequent tool call is checked against
    everything gathered so far.
    """

    def __init__(self) -> None:
        self._corpus_parts: list[str] = []
        self._normalized_corpus: str = ""
        self._indicators: set[str] = set()

    def add_result(self, payload: Any) -> None:
        """Record an (untrusted) tool result as tainted source material."""
        text = payload if isinstance(payload, str) else _stringify(payload)
        if not text:
            return
        self._corpus_parts.append(text)
        self._normalized_corpus = _normalize(" ".join(self._corpus_parts))
        self._indicators |= extract_indicators(text)

    def taint_reason(self, arguments: Any) -> str | None:
        """Return a human-readable reason if *arguments* are derived from
        untrusted data, else ``None``.

        Two signals, both high-precision:
        1. An argument contains an email/URL/host that appeared in the
           untrusted corpus (redirection / exfiltration target).
        2. An argument contains a long verbatim run copied from the corpus
           (opaque identifier or smuggled instruction fragment).
        """
        if not self._indicators and not self._normalized_corpus:
            return None

        for raw in _iter_arg_strings(arguments):
            if not raw:
                continue
            arg_indicators = extract_indicators(raw)
            overlap = arg_indicators & self._indicators
            if overlap:
                sample = sorted(overlap)[0]
                return (
                    f"argument references '{sample}', which came from an "
                    "untrusted tool result"
                )
            norm = _normalize(raw)
            if len(norm) >= _MIN_VERBATIM_LEN and norm in self._normalized_corpus:
                snippet = norm[:40] + ("…" if len(norm) > 40 else "")
                return (
                    f"argument copies verbatim text ('{snippet}') from an "
                    "untrusted tool result"
                )
        return None

    def is_tainted(self, arguments: Any) -> bool:
        return self.taint_reason(arguments) is not None


def _stringify(payload: Any) -> str:
    import json

    try:
        return json.dumps(payload, default=str)
    except (TypeError, ValueError):
        return str(payload)
