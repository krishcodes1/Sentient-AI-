"""Declares the "voice_notes" capability: Telegram voice notes transcribed on
this computer with Whisper, echoed back, then answered like a typed message.

Why it exists: the owner decides whether the bot listens at all, and this
switch keeps the recording on this computer (the model runs in a worker
process with no network; the audio is never stored). It claims no tools
(tools=()): it is an input feature, read per note by
services/notifications/voice.py from InstallationService.capability_statuses
(a read error refuses the note). It needs the optional speech_to_text
install (faster-whisper and the pinned base model, about 250 MB), which the
Install button and system.install_capability offer; in a Docker image built
without WITH_SPEECH_TO_TEXT=1 it is unavailable. Off by default. When it is
on, it always wins over "voice_notes_cloud": a failure here is never sent to
the cloud instead.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext

NOT_INSTALLED_REASON = "Local speech-to-text is not installed yet (about 250 MB, once)."
CONTAINER_REASON = (
    "Local speech-to-text is not part of this Docker image. Rebuild with "
    "WITH_SPEECH_TO_TEXT=1, or use 'Voice notes, transcribed by your AI provider'."
)


def availability(ctx: ReportContext) -> Availability:
    """Available once the engine and the model are on disk
    (``ctx.speech_local_installed``, from transcribe.local_engine_installed)."""
    if ctx.speech_local_installed:
        return Availability(True)
    if ctx.in_container:
        return Availability(False, CONTAINER_REASON)
    return Availability(False, NOT_INSTALLED_REASON)


CAPABILITY = Capability(
    key="voice_notes",
    label="Voice notes, transcribed on this computer",
    description=(
        "Turn Telegram voice notes into text on this computer (Whisper), show what was "
        "heard, and answer it like a typed message. The recording never leaves this "
        "computer and is not kept."
    ),
    tools=(),
    default_enabled=False,
    risk="low",
    when_denied=(
        "Transcribing voice notes on this computer is turned off. The owner can turn it "
        "on in Settings → Permissions; until then, type the message."
    ),
    availability=availability,
    install="speech_to_text",
)
