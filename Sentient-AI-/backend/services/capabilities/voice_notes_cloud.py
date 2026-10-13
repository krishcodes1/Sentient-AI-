"""Declares the "voice_notes_cloud" capability: Telegram voice notes sent to
the AI provider this account's chats already use (Gemini) to be turned into
text, when transcription on this computer is off or not installed.

Why it exists: sending a recording off the machine is a separate consent from
transcribing it locally, so it is its own switch (medium risk, off by
default). It claims no tools (tools=()): services/notifications/voice.py
reads it per note, only when "voice_notes" is not on, and only uses it when
the account's own turn provider can hear audio
(providers.provider_hears_audio). The provider hears the recording; Crawler
keeps only the text. Available when the install's default provider hears
audio (``ctx.default_provider_audio``).
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext

NO_AUDIO_PROVIDER_REASON = (
    "Your AI provider can't listen to audio (Gemini can). Use 'Voice notes, "
    "transcribed on this computer' instead."
)


def availability(ctx: ReportContext) -> Availability:
    if ctx.default_provider_audio:
        return Availability(True)
    return Availability(False, NO_AUDIO_PROVIDER_REASON)


CAPABILITY = Capability(
    key="voice_notes_cloud",
    label="Voice notes, transcribed by your AI provider",
    description=(
        "When transcription on this computer is off or not installed, send Telegram "
        "voice notes to the AI provider your chats already use (Gemini) to turn them "
        "into text. The provider hears the recording; Crawler keeps only the text."
    ),
    tools=(),
    default_enabled=False,
    risk="medium",
    when_denied=(
        "Sending voice notes to the AI provider for transcription is turned off. The "
        "owner can turn it on in Settings → Permissions, or use 'Voice notes, "
        "transcribed on this computer'."
    ),
    availability=availability,
)
