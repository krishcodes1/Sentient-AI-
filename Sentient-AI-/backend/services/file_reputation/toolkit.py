"""The file tools of the security.* family (security S10):
security.check_file (a VirusTotal lookup by fingerprint) and
security.upload_to_virustotal (a WRITE that sends one file, only after its
own approval card), with the card hooks the executor calls for the upload.

Why it exists: the executor's security family dispatches by action
(services/tools/security_checks.py) and its upload card needs a precheck,
a bind that stores the file's facts under the reserved ``_upload`` key, and
a sentence built from those facts, never from the model's words. All of it
reads the one ``FileReputationService``. The rules kept here:

- check_file takes exactly one of ``file_id`` (one of this person's own
  uploads: ``user_files`` is read for them only) or ``sha256`` (64 hex
  characters, e.g. from a mail connector's get_attachment_hash). Only the
  fingerprint is looked up; the answer never says "safe". The model tells the
  person about a flagged answer it gets here (``alert="caller"``); a late
  answer from the queue is told by the service.
- upload_to_virustotal is refused before any card for bad arguments, a call
  that brings its own ``_upload`` (only the bind writes it), no check of the
  file, a file VirusTotal already knows, a personal document nobody picked on
  the Security page (review SEC-F2), or bytes that can no longer be had.
- It runs only with ``approved`` (a person approved its card) and only with
  the facts its bind stored: the fingerprint must match them and the check
  row they name, so a call that skipped the card can never send anything.

Connects to: services/tools/security_checks.py (``use_file_reputation``),
services/agent/tool_registry.py (the upload's describe, bind and precheck
hooks, filed under ``FILE_REPUTATION_RULE_POLICY``),
services/file_reputation/service.py, main.py.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

import structlog

from services.file_reputation import byte_sink
from services.file_reputation.service import (
    UPLOAD_INVALID,
    UPLOAD_UNKNOWN_FILE,
    FileReputationService,
)
from services.file_reputation.verdicts import stored_card_sentence

logger = structlog.get_logger(__name__)

# The policy a refused upload is filed under; tool_registry.py and runtime.py
# use the same literal (pinned by tests/test_security_toolkit.py).
FILE_REPUTATION_RULE_POLICY = "file_reputation_rule"
# The reserved argument key the upload card stores the file's facts under.
UPLOAD_CARD_KEY = "_upload"

CHECK_FILE = "check_file"
UPLOAD = "upload_to_virustotal"
# How long check_file waits for room in VirusTotal's minute window (S10 4.5).
CHECK_WAIT_S = 20.0
# Where an upload's file_id says the file came from, as a check row's source.
_CHANNEL_SOURCES = frozenset({"web", "telegram", "slack"})

CHECK_ONE_OF = "Give exactly one of file_id (an upload's id) or sha256 (64 hex characters)."
CHECK_BAD_SHA = "sha256 must be a SHA-256 fingerprint: 64 hex characters."
CHECK_NOT_YOURS = "That file_id is not one of your uploads (or it expired)."
CHECK_DOCUMENT_ID = (
    "That id is a connector document, not an upload. For an email attachment, call the mail "
    "connector's get_attachment_hash and then security.check_file with the sha256 it answers."
)
UNKNOWN_ACTION = "That security file action does not exist."
UPLOAD_ONLY_SHA = (
    "security.upload_to_virustotal takes only the sha256 that security.check_file answered; "
    "Crawler adds the file's facts to the card itself."
)
UPLOAD_NEEDS_CARD = (
    "Sending a file to VirusTotal needs its own approval card every time; nothing was sent."
)
UPLOAD_CARD_MISMATCH = (
    "The approval card does not match this file's check any more, so nothing was sent. Check "
    "the file again and ask for a new card."
)
UPLOAD_UNAVAILABLE = "Uploads to VirusTotal could not be checked right now; nothing was sent."


def _refusal(rule: str, message: str) -> dict[str, Any]:
    return {"ok": False, "rule": rule, "error": message}


def _given(value: Any) -> bool:
    return value is not None and not (isinstance(value, str) and not value.strip())


class FileReputationToolkit:
    """security.check_file and security.upload_to_virustotal for the executor's security
    family (see the module docstring)."""

    def __init__(self, service: FileReputationService) -> None:
        self._service = service

    # -- dispatch -------------------------------------------------------------------------

    async def execute(
        self, action: str, params: dict[str, Any], user_id: str, *, approved: bool = False
    ) -> dict[str, Any]:
        """Run one file action for *user_id*. Never raises (the family logs a crash by type,
        but every expected failure is answered here)."""
        if action == CHECK_FILE:
            return await self._check_file(params, user_id)
        if action == UPLOAD:
            return await self._upload(params, user_id, approved=approved)
        return {"ok": False, "error": UNKNOWN_ACTION}

    async def _check_file(self, params: Mapping[str, Any], user_id: str) -> dict[str, Any]:
        file_id, sha256 = params.get("file_id"), params.get("sha256")
        if _given(file_id) == _given(sha256):
            return {"ok": False, "error": CHECK_ONE_OF}
        if _given(file_id):
            if not isinstance(file_id, str):
                return {"ok": False, "error": CHECK_NOT_YOURS}
            wanted = file_id.strip()
            if wanted.startswith("tmp_"):
                return {"ok": False, "error": CHECK_DOCUMENT_ID}
            upload = await self._service.store.uploaded_file(user_id, wanted)
            if upload is None:
                return {"ok": False, "error": CHECK_NOT_YOURS}
            verdict = await self._service.check_hash(
                user_id,
                upload.sha256,
                name=upload.name,
                size_bytes=upload.size_bytes,
                media_type=upload.media_type,
                source=upload.source if upload.source in _CHANNEL_SOURCES else "web",
                priority="explicit",
                wait_s=CHECK_WAIT_S,
                alert="caller",
            )
            return verdict.as_tool_result()
        digest = byte_sink.normalise_sha256(sha256)
        if digest is None:
            return {"ok": False, "error": CHECK_BAD_SHA}
        verdict = await self._service.check_hash(
            user_id, digest, source="hash", priority="explicit", wait_s=CHECK_WAIT_S, alert="caller"
        )
        return verdict.as_tool_result()

    async def _upload(
        self, params: Mapping[str, Any], user_id: str, *, approved: bool
    ) -> dict[str, Any]:
        if not approved:
            # The executor refuses an unapproved WRITE first; this is the last layer.
            return {"ok": False, "requires_approval": True, "error": UPLOAD_NEEDS_CARD}
        facts = params.get(UPLOAD_CARD_KEY)
        sha256 = params.get("sha256")
        digest = byte_sink.normalise_sha256(sha256)
        if not isinstance(facts, Mapping) or digest is None:
            return _refusal("invalid_arguments", UPLOAD_INVALID)
        if byte_sink.normalise_sha256(facts.get("sha256")) != digest:
            return _refusal("invalid_arguments", UPLOAD_INVALID)
        # Only the bind writes check_id, and the model never sees a check's id: the card's
        # facts must name the person's current check of this very file.
        row = await self._service.store.check_for(user_id, digest)
        if row is None:
            return _refusal("unknown_file", UPLOAD_UNKNOWN_FILE)
        if facts.get("check_id") != row.id:
            return _refusal("invalid_arguments", UPLOAD_CARD_MISMATCH)
        return await self._service.upload(user_id, digest, facts)

    # -- the upload card's hooks ------------------------------------------------------------

    @staticmethod
    def _argument_problem(params: Mapping[str, Any]) -> Optional[dict[str, Any]]:
        """The refusal for an upload call whose own arguments are wrong: anything but the
        sha256 (``_upload`` above all: only the bind writes it), or a sha256 that is not one."""
        extra = [key for key in params if key != "sha256"]
        if extra:
            return _refusal("invalid_arguments", UPLOAD_ONLY_SHA)
        if byte_sink.normalise_sha256(params.get("sha256")) is None:
            return _refusal("invalid_arguments", UPLOAD_INVALID)
        return None

    async def precheck(
        self, action: str, params: dict[str, Any], user_id: str
    ) -> Optional[dict[str, Any]]:
        """upload_to_virustotal only: the refusal before any card ({'ok': False, 'rule',
        'error'}) for bad arguments, a call that brings its own _upload, no row for this
        fingerprint, a file VirusTotal already knows, a personal document, or bytes that can no
        longer be had. None otherwise."""
        if action != UPLOAD:
            return None
        problem = self._argument_problem(params)
        if problem is not None:
            return problem
        digest = byte_sink.normalise_sha256(params.get("sha256"))
        assert digest is not None  # _argument_problem checked it
        try:
            return await self._service.upload_precheck(user_id, digest)
        except Exception as exc:
            logger.warning("file_reputation_precheck_failed", error_type=type(exc).__name__)
            return _refusal("unavailable", UPLOAD_UNAVAILABLE)

    async def bind(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """{'sha256', '_upload': {'sha256','name','size_bytes','source','check_id'}}, keeping
        held bytes for the card's 60 minutes; or {'ok': False, 'refused': True, 'rule', 'error'}
        when the call's arguments or the person's check no longer allow a card."""
        if action != UPLOAD:
            return {**_refusal("invalid_arguments", UNKNOWN_ACTION), "refused": True}
        problem = self._argument_problem(params)
        if problem is not None:
            return {**problem, "refused": True}
        digest = byte_sink.normalise_sha256(params.get("sha256"))
        assert digest is not None
        try:
            facts = await self._service.upload_facts(user_id, digest)
        except LookupError:
            return {**_refusal("unknown_file", UPLOAD_UNKNOWN_FILE), "refused": True}
        except Exception as exc:
            logger.warning("file_reputation_bind_failed", error_type=type(exc).__name__)
            return {**_refusal("unavailable", UPLOAD_UNAVAILABLE), "refused": True}
        return {"sha256": digest, UPLOAD_CARD_KEY: facts}

    def describe(self, action: str, params: Mapping[str, Any], user_id: str) -> Optional[str]:
        """The card sentence from ``_upload`` (S10 1.1): the file's name, size and short
        fingerprint, and who VirusTotal shares it with. Calls no backend; None without the
        bound facts (the generic reason then)."""
        if action != UPLOAD:
            return None
        facts = params.get(UPLOAD_CARD_KEY)
        if not isinstance(facts, Mapping):
            return None
        digest = byte_sink.normalise_sha256(facts.get("sha256")) or byte_sink.normalise_sha256(
            params.get("sha256")
        )
        if digest is None:
            return None
        return stored_card_sentence(facts.get("name"), facts.get("size_bytes"), digest)
