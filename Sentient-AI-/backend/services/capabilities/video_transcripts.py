"""Declares the "video_transcripts" capability that gates the video.* tools
(video.transcript and video.list), and the limits the owner can change.

Why it exists: the registry lists it so the owner can switch transcript
reading off in one place. It is read-only public-web access, like
web_browsing, so it is low risk and on by default; it requires "Browse the
web", because every publisher transcript and the YouTube check are web
fetches, so with that switch off it reports blocked. Whether a YouTube video
can be read is decided per call from the turn's own provider (Gemini only),
never here: captions and podcast transcripts work with every provider. The
limits (whole numbers from 1 to 10000, like every capability setting) cap the
provider video one call and one user's day may use, and how long a transcript
is kept after its last use; the toolkit reads them through
``VideoSettings.video_limits()``.
"""

from __future__ import annotations

from services.capabilities.base import Capability

# Minutes of YouTube video one provider call reads (verbatim reads a third),
# minutes per user per UTC day, and days a transcript is kept after its last
# use.
VIDEO_SETTINGS_DEFAULTS = {
    "video_minutes_per_call": 45,
    "video_minutes_per_day": 240,
    "keep_transcripts_days": 14,
}

CAPABILITY = Capability(
    key="video_transcripts",
    label="Summarise videos and podcasts",
    description=(
        "Read the captions or transcript of a YouTube video, lecture recording or podcast "
        "episode you link, so Crawler can summarise it and answer questions with timestamps. "
        "YouTube videos are read by your AI provider (Gemini only)."
    ),
    tools=("video.",),
    default_enabled=True,
    risk="low",
    requires=("web_browsing",),
    when_denied=(
        "Reading videos and podcasts is turned off. The owner can turn it on in Settings → "
        "Permissions."
    ),
)
