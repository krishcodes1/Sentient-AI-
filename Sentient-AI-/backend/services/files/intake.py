"""Takes files a person sends (web chat, Telegram, Slack) into the store, one
way for every channel.

Why it exists: an upload is refused the same way wherever it comes from: the
owner's "Read files and documents" switch is checked first, the UPLOAD
preset applies, the name is screened (prompting.prompt_name), the text is
stored encrypted (store.UserFileStore), and an audit row says what happened
with codes and counts only (``file_uploaded`` / ``file_upload_refused``),
never a name or any text. Callers get the stored files and, per refused
file, its display name, code and user-safe sentence.

Security wave (S10): a file screen main.py hands in (use_screen; S10's
FileReputationService) sees every inbound file first, refused ones included,
so a file can be looked up in VirusTotal by its fingerprint; annotate then
adds a flagged file's check to its attachment entry. Without a screen, and
whenever the screen fails, intake behaves exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Protocol, Sequence

import structlog

from services.files import messages
from services.files.prompting import sanitize_display_name
from services.files.sections import ExtractionRefused
from services.files.store import UserFileInfo, UserFileStore

logger = structlog.get_logger(__name__)

# None when files may be read, else the refusal text (file_reading's
# when_denied, or its blocked reason).
IntakeGate = Callable[[], Awaitable[Optional[str]]]
AuditSink = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True)
class InboundFile:
    """A file as a channel received it. ``source`` is "web", "telegram" or
    "slack"; ``media_type`` is what the sender declared (the bytes decide)."""

    name: str
    media_type: str
    data: bytes
    source: str
    # Security wave (S10): where the channel can hand the bytes over again
    # (Telegram's file_id), for a file check's later upload; None elsewhere.
    source_ref: Optional[str] = None


class FileScreen(Protocol):
    """What intake asks about every inbound file (security wave, S10's
    FileReputationService): ``screen`` returns at once and never decides
    whether the file is stored; ``annotate`` adds facts to attachment
    entries (a flagged file's check) and returns them."""

    async def screen(self, user_id: str, inbound: InboundFile) -> None: ...

    async def annotate(self, user_id: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class IntakeError:
    name: str
    code: str
    message: str


@dataclass
class IntakeResult:
    files: list[UserFileInfo] = field(default_factory=list)
    errors: list[IntakeError] = field(default_factory=list)


class FileIntake:
    """Stores inbound files for a user (see the module doc). ``gate`` is
    the file_reading check (None: always allowed, for tests); ``audit`` the
    runtime audit logger's ``log`` (None: no audit row)."""

    def __init__(
        self,
        store: UserFileStore,
        *,
        gate: Optional[IntakeGate] = None,
        audit: Optional[AuditSink] = None,
        screen: Optional[FileScreen] = None,
    ) -> None:
        self.store = store
        self._gate = gate
        self._audit = audit
        # Security wave (S10): None until main.py hands one in (use_screen).
        self._screen = screen

    def use_screen(self, screen: FileScreen) -> None:
        """Wire the file screen after construction (main.py; security wave)."""
        self._screen = screen

    async def refusal(self) -> Optional[str]:
        """None when files may be read now, else the sentence to answer
        with (a gate that fails refuses)."""
        if self._gate is None:
            return None
        try:
            return await self._gate()
        except Exception as exc:
            logger.warning("file_intake_gate_failed", error_type=type(exc).__name__)
            return messages.SWITCHED_OFF

    async def ingest(self, user_id: str, files: Sequence[InboundFile]) -> IntakeResult:
        result = IntakeResult()
        refusal = await self.refusal()
        for inbound in files:
            await self._screen_one(user_id, inbound)
            display = sanitize_display_name(inbound.name)
            if refusal is not None:
                result.errors.append(IntakeError(display, "switched_off", refusal))
                await self._record(user_id, inbound, code="switched_off")
                continue
            try:
                info = await self.store.ingest(
                    user_id,
                    data=inbound.data,
                    name=inbound.name,
                    declared_mime=inbound.media_type,
                    source=inbound.source,
                )
            except ExtractionRefused as refused:
                result.errors.append(IntakeError(display, refused.code, refused.message))
                await self._record(user_id, inbound, code=refused.code)
                continue
            result.files.append(info)
            await self._record(user_id, inbound, info=info)
        return result

    async def _screen_one(self, user_id: str, inbound: InboundFile) -> None:
        """Hand one inbound file to the screen (security wave, S10). A screen
        that fails is logged by type and never stops the upload."""
        if self._screen is None:
            return
        try:
            await self._screen.screen(user_id, inbound)
        except Exception as exc:
            logger.warning("file_screen_failed", error_type=type(exc).__name__)

    async def annotate(self, user_id: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Attachment entries as the screen annotates them (a flagged file's
        check added; security wave, S10): *entries* unchanged without a
        screen, or when the screen fails or answers anything but a list
        (logged by type)."""
        if self._screen is None:
            return entries
        try:
            annotated = await self._screen.annotate(user_id, entries)
        except Exception as exc:
            logger.warning("file_annotate_failed", error_type=type(exc).__name__)
            return entries
        if not isinstance(annotated, list):
            logger.warning("file_annotate_bad_answer", answer_type=type(annotated).__name__)
            return entries
        return annotated

    async def _record(
        self,
        user_id: str,
        inbound: InboundFile,
        *,
        info: Optional[UserFileInfo] = None,
        code: Optional[str] = None,
    ) -> None:
        if self._audit is None:
            return
        facts: dict[str, Any] = {"source": inbound.source, "size_bytes": len(inbound.data)}
        if info is not None:
            facts.update(
                {
                    "file_id": info.id,
                    "kind": info.kind,
                    "pages": info.pages,
                    "sections": info.sections_count,
                    "chars": info.chars,
                    "deduped": info.deduped,
                    "truncated": info.truncated,
                }
            )
        entry: dict[str, Any] = {
            "event": "file_uploaded" if info is not None else "file_upload_refused",
            "user_id": user_id,
            "tool": "files.upload",
            "arguments": facts,
        }
        if code is not None:
            entry["reason"] = code
            entry["rule"] = code
        try:
            await self._audit(entry)
        except Exception as exc:  # the upload stands; the log says the row is missing
            logger.error("file_intake_audit_failed", error_type=type(exc).__name__)
