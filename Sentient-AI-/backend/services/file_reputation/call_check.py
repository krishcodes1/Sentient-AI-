"""The file reputation call check (security S10): slot 5, last, of the
pre-dispatch call checks. It adds a note to the card of a call that would
forward an email with an attachment VirusTotal flags, or save a flagged
upload to the knowledge base. It never escalates and never refuses.

Why it exists: a flagged file must not travel on unnoticed through a forward
or into the knowledge base; those calls always have a card (both forwards are
``always_confirm`` and ``knowledge.add`` keeps its card), so a note on it is
enough. The check reads one indexed row per matching call and nothing else:

- ``google_workspace.forward`` / ``microsoft.forward``: the keyed hash of
  ``"<family>:<message_id>"`` (``store.message_source_key``, the same rule the
  mail check wrote it with) is looked up among this person's flagged checks.
  Gmail forwards only a message's text; Outlook forwards its attachments too,
  so the two notes say what really travels.
- ``knowledge.add`` with ``file_ids``: this person's uploads joined to their
  flagged checks by fingerprint.

It reads ``call.user_id``, ``call.canonical`` (the slug already removed) and
``call.arguments`` and nothing else, and only at stage "turn": as a backstop
(approve, execute) a note has no card to sit on, so it is inert there. It
fails open: an error or a slow database answers Allow and logs the error type
(the pipeline writes rows only for escalations and refusals). Notes carry
counts and fixed words only, never a file name, a message id or vendor text.

Known limit (S10 4.9): one row is kept per person and file, so when the same
flagged file arrived in two emails only the newest message's key is kept, and
forwarding the older one gets no note. S2's own finding on that mail stands.

Connects to: services/security/call_checks.py (the pipeline and its types),
services/file_reputation/store.py (the two queries), main.py (built with the
session factory and registered last in ``standard_pipeline``).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, Callable, Optional

import structlog

from services.file_reputation.store import FileReputationStore, FlaggedFile, message_source_key
from services.file_reputation.verdicts import FileVerdict
from services.security.call_checks import ALLOW, CallFacts, Note, SecurityNote, Severity, Verdict

logger = structlog.get_logger(__name__)

CHECK_NAME = "file_reputation"
FILE_REPUTATION_POLICY = "file_reputation"
NOTE_KIND = "file_flagged"
# The three tools a note can be about (the canonical names).
TOOLS = frozenset({"google_workspace.forward", "microsoft.forward", "knowledge.add"})
_FORWARDS = frozenset({"google_workspace.forward", "microsoft.forward"})
# The check answers Allow on its own well inside the pipeline's turn-stage
# floor (10 s), so a slow database never turns into a "check failed" note.
QUERY_TIMEOUT_S = 3.0
# knowledge.add takes at most 10 file ids; more than this is not a real call.
_MAX_FILE_IDS = 20

# What each forward really sends on (gmail.py forward: "Attachments are not
# forwarded"; Outlook's /forward carries them).
_FORWARD_TAIL = {
    "google_workspace": (
        "Gmail forwards only its text, but that text may be part of the same attack."
    ),
    "microsoft": "Forwarding it passes the file on.",
}


def _flagged_words(found: FlaggedFile) -> tuple[str, str]:
    """("41 of 72", " as malicious") or ("2 of 70", "") for a flagged snapshot: the counts the
    file check's own sentences use (``FileVerdict.flagged_by``)."""
    verdict = FileVerdict(
        sha256="",
        verdict="malicious" if found.verdict == "malicious" else "suspicious",
        malicious=max(found.malicious, 0),
        suspicious=max(found.suspicious, 0),
        engines=max(found.engines, 0),
    )
    counts = f"{verdict.flagged_by} of {verdict.engines}"
    return counts, (" as malicious" if verdict.verdict == "malicious" else "")


def _severity(found: FlaggedFile) -> Severity:
    return "high" if found.verdict == "malicious" else "warn"


def forward_note(family: str, found: FlaggedFile) -> SecurityNote:
    """The note for forwarding a message whose attachment is flagged."""
    counts, how = _flagged_words(found)
    text = (
        f"This email has an attachment that {counts} security vendors on VirusTotal flag{how}. "
        f"{_FORWARD_TAIL.get(family, _FORWARD_TAIL['microsoft'])}"
    )
    return SecurityNote(kind=NOTE_KIND, severity=_severity(found), text=text)


def save_note(found: Mapping[str, FlaggedFile]) -> Optional[SecurityNote]:
    """The note for saving uploads to the knowledge base when some are flagged: the worst one
    (malicious first, then the most vendors), and how many are flagged when it is more than
    one. None when nothing is flagged."""
    if not found:
        return None
    worst = sorted(
        found.values(),
        key=lambda f: (f.verdict != "malicious", -max(f.malicious, 0), -max(f.suspicious, 0)),
    )[0]
    counts, how = _flagged_words(worst)
    if len(found) == 1:
        text = f"A file being saved is flagged{how} by {counts} security vendors on VirusTotal."
    else:
        text = (
            f"{len(found)} of the files being saved are flagged by security vendors on "
            f"VirusTotal; the worst is flagged{how} by {counts}."
        )
    return SecurityNote(kind=NOTE_KIND, severity=_severity(worst), text=text)


def _file_ids(arguments: Mapping[str, Any]) -> list[str]:
    raw = arguments.get("file_ids")
    if not isinstance(raw, (list, tuple)):
        return []
    ids = [item.strip() for item in raw[:_MAX_FILE_IDS] if isinstance(item, str) and item.strip()]
    return list(dict.fromkeys(ids))


class FileReputationCallCheck:
    """S10's place in the call checks (see the module docstring): a ``file_flagged`` note on a
    forward of a message with a flagged attachment or a knowledge-base save of a flagged upload;
    Allow for everything else."""

    name = CHECK_NAME
    policy = FILE_REPUTATION_POLICY
    stages: frozenset[str] = frozenset({"turn"})
    timeout_s = 1.0

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        store: Optional[FileReputationStore] = None,
        query_timeout_s: float = QUERY_TIMEOUT_S,
    ) -> None:
        self._session_factory = session_factory
        self._store = store if store is not None else FileReputationStore(session_factory)
        self._query_timeout_s = query_timeout_s

    def applies_to(self, call: CallFacts) -> bool:
        """Only at stage "turn", only the three tools, and only when the call names what the
        check would look up (a message id, or file ids). No I/O."""
        if call.stage != "turn" or call.canonical not in TOOLS:
            return False
        arguments = call.arguments if isinstance(call.arguments, Mapping) else {}
        if call.canonical == "knowledge.add":
            return bool(_file_ids(arguments))
        message_id = arguments.get("message_id")
        return isinstance(message_id, str) and bool(message_id.strip())

    async def check(self, call: CallFacts) -> Verdict:
        """A file_flagged note, or Allow. Never raises, never escalates, never refuses."""
        try:
            if not self.applies_to(call):
                return ALLOW
            note = await asyncio.wait_for(self._note_for(call), timeout=self._query_timeout_s)
        except Exception as exc:  # a timeout included: the check only ever adds notes
            logger.warning("file_reputation_call_check_failed", error_type=type(exc).__name__)
            return ALLOW
        return Note(notes=(note,)) if note is not None else ALLOW

    async def _note_for(self, call: CallFacts) -> Optional[SecurityNote]:
        arguments = call.arguments
        if call.canonical in _FORWARDS:
            family = call.canonical.split(".", 1)[0]
            key = message_source_key(family, arguments.get("message_id"))
            if key is None:
                return None
            found = await self._store.flagged_by_source_key(call.user_id, key)
            return forward_note(family, found) if found is not None else None
        flagged = await self._store.flagged_uploads(call.user_id, _file_ids(arguments))
        return save_note(flagged)
