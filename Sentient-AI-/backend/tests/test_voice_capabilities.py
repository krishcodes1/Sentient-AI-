"""Tests for the two voice-note switches: both registered, tool-less and off
by default with their own labels; "Voice notes, transcribed on this
computer" blocked with the install reason until speech_to_text is installed
(and with the Docker reason in a container), offering the installer in the
<permissions> block; "Voice notes, transcribed by your AI provider"
available only when the default provider hears audio; default_context
filling both facts; and the Dockerfile's pinned model matching the code.

Why it exists: the switches are the owner's consent for listening at all and
for sending a recording off the machine; their availability must follow the
environment facts, never a guess.
"""

from __future__ import annotations

import re
from pathlib import Path

from services import capabilities
from services.capabilities import voice_notes, voice_notes_cloud
from services.capabilities.base import ReportContext
from services.capabilities.prompt import render_permissions_block
from services.tools import transcribe
from services.tools.system import ALLOWLIST


def _ctx(**facts) -> ReportContext:
    base = {"in_container": False, "platform": "win32", "telegram_configured": True, "browser_installed": False}
    base.update(facts)
    return ReportContext(**base)


def _status(key: str, switches: dict, ctx: ReportContext):
    return capabilities.statuses_by_key(capabilities.report(switches, ctx))[key]


def test_both_are_registered_tool_less_and_off_by_default():
    local = capabilities.get("voice_notes")
    cloud = capabilities.get("voice_notes_cloud")
    assert local.label == "Voice notes, transcribed on this computer"
    assert cloud.label == "Voice notes, transcribed by your AI provider"
    assert local.tools == () and cloud.tools == ()
    assert local.default_enabled is False and cloud.default_enabled is False
    assert local.risk == "low" and cloud.risk == "medium"
    assert local.install == "speech_to_text" and cloud.install is None
    labels = [c.label for c in capabilities.REGISTRY]
    assert len(labels) == len(set(labels))
    switches = capabilities.default_switches()
    assert switches["voice_notes"] is False and switches["voice_notes_cloud"] is False
    assert "Settings → Permissions" in local.when_denied and "type the message" in local.when_denied
    assert "The recording never leaves this computer" in local.description
    assert "The provider hears the recording" in cloud.description


def test_local_is_blocked_until_installed_and_says_why():
    on = {"voice_notes": True}
    missing = _status("voice_notes", on, _ctx())
    assert missing.effective == "blocked"
    assert missing.reason == voice_notes.NOT_INSTALLED_REASON
    assert missing.install_size_hint == ALLOWLIST["speech_to_text"].size_hint == "~250 MB download"
    docker = _status("voice_notes", on, _ctx(in_container=True, platform="linux"))
    assert docker.effective == "blocked" and "WITH_SPEECH_TO_TEXT=1" in docker.reason
    ready = _status("voice_notes", on, _ctx(speech_local_installed=True))
    assert ready.effective == "on"
    in_image = _status("voice_notes", on, _ctx(in_container=True, speech_local_installed=True))
    assert in_image.effective == "on"
    assert _status("voice_notes", {}, _ctx(speech_local_installed=True)).effective == "off"


def test_the_permissions_block_offers_the_speech_install_when_installs_is_on():
    ctx = _ctx()
    block = render_permissions_block(capabilities.report({"voice_notes": True, "installs": True}, ctx))
    assert (
        "- Voice notes, transcribed on this computer: blocked — "
        f"{voice_notes.NOT_INSTALLED_REASON} You may offer system.install_capability(name='speech_to_text')."
    ) in block
    without = render_permissions_block(capabilities.report({"voice_notes": True, "installs": False}, ctx))
    assert "name='speech_to_text'" not in without


def test_cloud_is_available_only_when_the_default_provider_hears_audio():
    on = {"voice_notes_cloud": True}
    deaf = _status("voice_notes_cloud", on, _ctx(default_provider="anthropic"))
    assert deaf.effective == "blocked" and deaf.reason == voice_notes_cloud.NO_AUDIO_PROVIDER_REASON
    hears = _status("voice_notes_cloud", on, _ctx(default_provider="gemini", default_provider_audio=True))
    assert hears.effective == "on"


def test_default_context_fills_both_facts(monkeypatch):
    monkeypatch.setattr(transcribe, "local_engine_installed", lambda model_dir=None: True)
    ctx = capabilities.default_context(default_provider="gemini")
    assert ctx.speech_local_installed is True and ctx.default_provider_audio is True
    monkeypatch.setattr(transcribe, "local_engine_installed", lambda model_dir=None: False)
    ctx = capabilities.default_context(default_provider="anthropic")
    assert ctx.speech_local_installed is False and ctx.default_provider_audio is False
    # The two facts are the last fields (wave order), after default_provider.
    names = list(ReportContext.__dataclass_fields__)
    assert names[-2:] == ["speech_local_installed", "default_provider_audio"]
    assert names.index("default_provider") < names.index("speech_local_installed")


def test_the_docker_image_fetches_the_same_pinned_model():
    dockerfile = Path(transcribe.BACKEND_DIR).parent / "docker" / "Dockerfile.backend"
    text = dockerfile.read_text(encoding="utf-8")
    assert "ARG WITH_SPEECH_TO_TEXT=0" in text
    assert f'revision="{transcribe.SPEECH_MODEL_REVISION}"' in text
    assert f'"{transcribe.SPEECH_MODEL_SHA256}"' in text
    assert f'repo_id="{transcribe.SPEECH_MODEL_REPO}"' in text
    assert '"faster-whisper>=1.2,<1.3"' in text and "--only-binary=:all:" in text
    assert re.fullmatch(r"[0-9a-f]{40}", transcribe.SPEECH_MODEL_REVISION)
    assert re.fullmatch(r"[0-9a-f]{64}", transcribe.SPEECH_MODEL_SHA256)
    for compose in ("docker-compose.yml", "docker-compose.prod.yml"):
        body = (dockerfile.parent / compose).read_text(encoding="utf-8")
        assert "WITH_SPEECH_TO_TEXT: ${WITH_SPEECH_TO_TEXT:-0}" in body
