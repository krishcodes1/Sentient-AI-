"""Tests for services/tools/transcribe.py: audio sniffing and declared types,
the per-user quota with an injected clock, the local engine's exact worker
argv, secret-free environment, deadline, answer parsing, busy queue, and a
real stand-in worker killed at its deadline and on cancel, and the provider
engine's one-shot payload, "[no speech]", refusals before any call and a
provider error that shows no body.

Why it exists: a voice note is untrusted bytes; every bound on it (type,
size, length, quota, one worker at a time, no secrets in the child) lives in
this module, and the Windows CI job runs this file for the real-process
kills.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time

import pytest

from services.tools import transcribe
from services.tools.transcribe import (
    PROVIDER_SYSTEM_INSTRUCTION,
    AudioClip,
    LocalWhisperEngine,
    ProviderAudioEngine,
    VoiceQuota,
    family_of_declared,
    sniff_audio_type,
)
from services.workers import WorkerResult, run_worker

OGG_OPUS = b"OggS\x00\x02" + b"\x00" * 22 + b"\x01\x13OpusHead\x01\x01" + b"\x00" * 40
OGG_VORBIS = b"OggS\x00\x02" + b"\x00" * 22 + b"\x01\x1e\x01vorbis" + b"\x00" * 40
MP3_ID3 = b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\x00" * 60
MP3_SYNC = b"\xff\xfb\x90\x64" + b"\x00" * 60
ADTS_AAC = b"\xff\xf1\x50\x80" + b"\x00" * 60
WAV = b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 50
FLAC = b"fLaC\x00\x00\x00\x22" + b"\x00" * 60
M4A = b"\x00\x00\x00\x20ftypM4A \x00\x00\x00\x00" + b"\x00" * 50
MP4_VIDEO = b"\x00\x00\x00\x20ftypavc1\x00\x00\x00\x00" + b"\x00" * 50
WEBM = b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01" + b"\x00" * 60


# ── sniffing and declared types ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("data", "family"),
    [
        (OGG_OPUS, "ogg"),
        (OGG_VORBIS, "ogg"),
        (MP3_ID3, "mp3"),
        (MP3_SYNC, "mp3"),
        (WAV, "wav"),
        (FLAC, "flac"),
        (M4A, "m4a"),
        (WEBM, "webm"),
        (b"OggS" + b"\x00" * 60, None),  # Ogg without an audio codec header
        (ADTS_AAC, None),
        (MP4_VIDEO, None),
        (b"%PDF-1.7 not audio", None),
        (b"", None),
        (b"MZ\x90\x00", None),
    ],
)
def test_sniff_audio_type(data, family):
    assert sniff_audio_type(data) == family


@pytest.mark.parametrize(
    ("mime", "name", "family"),
    [
        ("audio/ogg", "", "ogg"),
        ("audio/ogg; codecs=opus", "", "ogg"),
        ("AUDIO/MPEG", "", "mp3"),
        ("audio/x-wav", "", "wav"),
        ("audio/mp4", "", "m4a"),
        ("audio/webm", "", "webm"),
        ("video/mp4", "clip.mp3", None),  # a declared type always wins
        ("application/pdf", "", None),
        ("", "talk.mp3", "mp3"),
        ("", "talk.m4a", "m4a"),
        ("", "talk.exe", None),
        ("", "", None),
    ],
)
def test_the_declared_family(mime, name, family):
    assert family_of_declared(mime, name) == family


# ── quota ───────────────────────────────────────────────────────────────


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_the_eleventh_note_in_ten_minutes_is_refused_until_the_window_passes():
    clock = Clock()
    quota = VoiceQuota(clock=clock)
    for _ in range(10):
        assert quota.refusal("u1", 5) is None
        quota.take("u1", 5)
        clock.now += 1
    assert quota.refusal("u1", 5) == "burst"
    assert quota.refusal("u2", 5) is None  # per user
    clock.now += 600
    assert quota.refusal("u1", 5) is None


def test_the_sixty_first_audio_minute_is_refused_until_the_day_passes():
    clock = Clock()
    quota = VoiceQuota(clock=clock)
    for _ in range(6):
        assert quota.refusal("u1", 600) is None
        quota.take("u1", 600)
        clock.now += 601  # outside the ten-minute window each time
    assert quota.seconds_used("u1") == 3600
    assert quota.refusal("u1", 1) == "daily"
    assert quota.refusal("u1", 0) == "daily"
    clock.now += 24 * 3600
    assert quota.refusal("u1", 600) is None


def test_a_note_that_would_pass_the_daily_minutes_is_refused():
    clock = Clock()
    quota = VoiceQuota(clock=clock)
    quota.take("u1", 3500)
    assert quota.refusal("u1", 60) is None
    assert quota.refusal("u1", 200) == "daily"
    quota.add_seconds("u1", 100)
    assert quota.refusal("u1", 1) == "daily"


# ── the local engine ────────────────────────────────────────────────────


def _answer(payload: dict, exit_code: int = 0, **flags) -> WorkerResult:
    return WorkerResult(
        exit_code=exit_code,
        stdout=(json.dumps(payload) + "\n").encode(),
        stderr_tail="",
        timed_out=flags.get("timed_out", False),
        cancelled=flags.get("cancelled", False),
        truncated=flags.get("truncated", False),
    )


class FakeRunner:
    def __init__(self, result: WorkerResult) -> None:
        self.result = result
        self.calls: list[tuple[list[str], dict]] = []

    async def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        return self.result


def test_local_engine_installed_needs_the_packages_and_every_model_file(tmp_path, monkeypatch):
    class Spec:
        pass

    monkeypatch.setattr(transcribe.importlib.util, "find_spec", lambda name: Spec())
    for name in ("config.json", "model.bin", "tokenizer.json"):
        (tmp_path / name).write_text("x")
    assert transcribe.local_engine_installed(str(tmp_path)) is False  # no vocabulary.*
    (tmp_path / "vocabulary.txt").write_text("x")
    assert transcribe.local_engine_installed(str(tmp_path)) is True
    (tmp_path / "model.bin").unlink()
    assert transcribe.local_engine_installed(str(tmp_path)) is False
    (tmp_path / "model.bin").write_text("x")
    monkeypatch.setattr(
        transcribe.importlib.util, "find_spec", lambda name: None if name == "ctranslate2" else Spec()
    )
    assert transcribe.local_engine_installed(str(tmp_path)) is False


def test_the_model_directory_follows_the_environment(monkeypatch):
    monkeypatch.setenv("CRAWLER_SPEECH_MODEL_DIR", "/opt/crawler-speech/faster-whisper-base")
    assert transcribe.speech_model_dir() == "/opt/crawler-speech/faster-whisper-base"
    monkeypatch.delenv("CRAWLER_SPEECH_MODEL_DIR")
    default = transcribe.speech_model_dir()
    assert default.startswith(sys.prefix)
    assert default.replace("\\", "/").endswith("share/crawler-ai/speech/faster-whisper-base")


@pytest.mark.asyncio
async def test_the_worker_argv_stdin_cwd_and_deadline_are_fixed(monkeypatch):
    runner = FakeRunner(_answer({"ok": True, "text": "What's due this week?", "language": "en", "duration_s": 3.2}))
    engine = LocalWhisperEngine(runner=runner, model_dir="/models/fw-base", threads=2)
    result = await engine.transcribe(AudioClip(data=OGG_OPUS, family="ogg", duration_s=12))
    assert result.ok and result.text == "What's due this week?" and result.language == "en"
    assert result.engine == "local" and result.model == "faster-whisper-base"
    ((argv, kwargs),) = runner.calls
    assert argv == [
        sys.executable,
        "-m",
        "services.tools.transcribe_worker",
        "--model-dir",
        "/models/fw-base",
        "--format",
        "ogg",
        "--max-seconds",
        "600",
        "--threads",
        "2",
    ]
    assert kwargs["stdin"] == OGG_OPUS
    assert kwargs["cwd"] == transcribe.BACKEND_DIR
    assert os.path.isfile(os.path.join(kwargs["cwd"], "services", "tools", "transcribe_worker.py"))
    assert kwargs["deadline_s"] == 72
    assert kwargs["max_stdout_bytes"] == 256 * 1024
    m4a = await engine.transcribe(AudioClip(data=M4A, family="m4a"))
    assert m4a.ok
    assert runner.calls[-1][0][6] == "mp4"


def test_the_deadline_is_a_minute_plus_the_length_at_most_eleven_minutes():
    assert LocalWhisperEngine.deadline_s(0) == 60
    assert LocalWhisperEngine.deadline_s(125.2) == 186
    assert LocalWhisperEngine.deadline_s(None) == 660
    assert LocalWhisperEngine.deadline_s(5000) == 660


@pytest.mark.asyncio
async def test_the_worker_environment_holds_no_secrets(monkeypatch):
    for name in ("SECRET_KEY", "ENCRYPTION_KEY", "GEMINI_API_KEY", "TELEGRAM_BOT_TOKEN", "DATABASE_URL", "AUDIT_HMAC_KEY"):
        monkeypatch.setenv(name, f"value-of-{name}")
    monkeypatch.setenv("PYTHONPATH", "/somewhere/else")
    runner = FakeRunner(_answer({"ok": True, "text": "hi"}))
    await LocalWhisperEngine(runner=runner).transcribe(AudioClip(data=OGG_OPUS, family="ogg"))
    env = runner.calls[0][1]["env"]
    assert env["HF_HUB_OFFLINE"] == "1"
    for name in ("SECRET_KEY", "ENCRYPTION_KEY", "GEMINI_API_KEY", "TELEGRAM_BOT_TOKEN", "DATABASE_URL", "AUDIT_HMAC_KEY", "PYTHONPATH"):
        assert name not in env
    assert not any(value.startswith("value-of-") for value in env.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("result", "code"),
    [
        (_answer({"ok": True, "text": "hi"}, exit_code=1), "failed"),
        (WorkerResult(0, b"not json\n", "", False, False, False), "failed"),
        (WorkerResult(0, b"", "", False, False, False), "failed"),
        (_answer({"ok": True, "text": "hi"}, truncated=True), "failed"),
        (_answer({"ok": True, "text": "hi"}, timed_out=True), "timeout"),
        (_answer({"ok": True, "text": "hi"}, cancelled=True), "cancelled"),
        (_answer({"ok": False, "error": "too_long"}, exit_code=1), "too_long"),
        (_answer({"ok": False, "error": "no_audio_stream"}, exit_code=1), "format"),
        (_answer({"ok": False, "error": "decode_failed"}, exit_code=1), "decode_failed"),
        (_answer({"ok": False, "error": "model_missing"}, exit_code=1), "engine_missing"),
        (_answer({"ok": False, "error": "engine_missing"}, exit_code=1), "engine_missing"),
        (_answer({"ok": False, "error": "something else"}, exit_code=1), "failed"),
        (_answer({"ok": True, "text": "   "}), "no_speech"),
    ],
)
async def test_a_bad_or_failed_worker_answer_is_never_ok(result, code):
    transcript = await LocalWhisperEngine(runner=FakeRunner(result)).transcribe(
        AudioClip(data=OGG_OPUS, family="ogg")
    )
    assert transcript.ok is False and transcript.error == code and transcript.text == ""


@pytest.mark.asyncio
async def test_a_long_transcript_is_capped():
    runner = FakeRunner(_answer({"ok": True, "text": "word " * 10000}))
    transcript = await LocalWhisperEngine(runner=runner).transcribe(AudioClip(data=OGG_OPUS, family="ogg"))
    assert transcript.ok and len(transcript.text) <= 20000


@pytest.mark.asyncio
async def test_one_runs_three_wait_and_the_next_is_busy():
    release = asyncio.Event()
    started: list[int] = []

    async def slow(argv, **kwargs):
        started.append(1)
        await release.wait()
        return _answer({"ok": True, "text": "done"})

    engine = LocalWhisperEngine(runner=slow)
    clip = AudioClip(data=OGG_OPUS, family="ogg")
    jobs = [asyncio.create_task(engine.transcribe(clip)) for _ in range(4)]
    for _ in range(20):
        await asyncio.sleep(0)
    assert len(started) == 1  # one runs, three wait for the slot
    busy = await engine.transcribe(clip)
    assert busy.ok is False and busy.error == "busy"
    release.set()
    results = await asyncio.gather(*jobs)
    assert all(r.ok for r in results) and len(started) == 4


@pytest.mark.asyncio
async def test_a_waiting_note_that_never_gets_the_slot_is_busy():
    release = asyncio.Event()

    async def slow(argv, **kwargs):
        await release.wait()
        return _answer({"ok": True, "text": "done"})

    engine = LocalWhisperEngine(runner=slow, queue_wait_s=0.05)
    clip = AudioClip(data=OGG_OPUS, family="ogg")
    first = asyncio.create_task(engine.transcribe(clip))
    await asyncio.sleep(0)
    second = await engine.transcribe(clip)
    assert second.error == "busy"
    release.set()
    assert (await first).ok


@pytest.mark.asyncio
async def test_cancelling_the_task_reaches_the_runner():
    entered = asyncio.Event()
    seen: list[str] = []

    async def hanging(argv, **kwargs):
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            seen.append("cancelled")
            raise
        return _answer({"ok": True, "text": "never"})

    engine = LocalWhisperEngine(runner=hanging)
    task = asyncio.create_task(engine.transcribe(AudioClip(data=OGG_OPUS, family="ogg")))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert seen == ["cancelled"]
    assert engine._in_flight == 0


# ── real stand-in workers (the Windows CI job runs these) ───────────────


def _stand_in(script: str, **overrides):
    """A runner that starts *script* (a real child process) through the real
    run_worker with the engine's own environment, stdin and caps."""

    async def runner(argv, **kwargs):
        kwargs.update(overrides)
        return await run_worker([sys.executable, "-c", script], **kwargs)

    return runner


def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
            return handle.read().split()[2] != "Z"
    except OSError:
        return False


@pytest.mark.asyncio
async def test_a_real_worker_reads_stdin_and_answers_one_line():
    script = (
        "import json,sys; data=sys.stdin.buffer.read(); "
        "print(json.dumps({'ok': True, 'text': 'heard %d bytes' % len(data), 'language': 'en'}))"
    )
    engine = LocalWhisperEngine(runner=_stand_in(script))
    transcript = await engine.transcribe(AudioClip(data=OGG_OPUS, family="ogg"))
    assert transcript.ok and transcript.text == f"heard {len(OGG_OPUS)} bytes"


@pytest.mark.asyncio
async def test_a_real_worker_is_killed_at_its_deadline(tmp_path):
    marker = tmp_path / "pid"
    script = f"import os,time; open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(60)"
    engine = LocalWhisperEngine(runner=_stand_in(script, deadline_s=1.5))
    started = time.monotonic()
    transcript = await engine.transcribe(AudioClip(data=OGG_OPUS, family="ogg"))
    assert transcript.ok is False and transcript.error == "timeout"
    assert time.monotonic() - started < 30
    pid = int(marker.read_text())
    for _ in range(50):
        if not _alive(pid):
            break
        await asyncio.sleep(0.1)
    assert not _alive(pid)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "darwin", reason="no /proc to tell a reaped child from a zombie")
async def test_a_real_worker_is_killed_when_the_task_is_cancelled(tmp_path):
    marker = tmp_path / "pid"
    script = f"import os,time; open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(60)"
    engine = LocalWhisperEngine(runner=_stand_in(script))
    task = asyncio.create_task(engine.transcribe(AudioClip(data=OGG_OPUS, family="ogg")))
    for _ in range(200):
        if marker.exists() and marker.read_text():
            break
        await asyncio.sleep(0.05)
    pid = int(marker.read_text())
    assert _alive(pid)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(50):
        if not _alive(pid):
            break
        await asyncio.sleep(0.1)
    assert not _alive(pid)


# ── the provider engine ─────────────────────────────────────────────────


class FakeRuntime:
    def __init__(self, text: str = "Remind me at six to call mom.", error: Exception | None = None) -> None:
        self.text = text
        self.error = error
        self.calls: list[dict] = []

    async def complete_once(self, messages, *, llm_provider, llm_model, system):
        from services.agent.runtime import OnceResult

        self.calls.append({"messages": messages, "provider": llm_provider, "model": llm_model, "system": system})
        if self.error is not None:
            raise self.error
        return OnceResult(
            text=self.text, usage={"input_tokens": 390, "output_tokens": 9}, provider=llm_provider, model=llm_model
        )


@pytest.mark.asyncio
async def test_the_provider_engine_sends_one_audio_block_with_the_fixed_instruction():
    runtime = FakeRuntime()
    engine = ProviderAudioEngine(lambda: runtime)
    transcript = await engine.transcribe(
        AudioClip(data=OGG_OPUS, family="ogg", duration_s=4), llm_provider="gemini", llm_model="gemini-3.5-flash-lite"
    )
    assert transcript.ok and transcript.text == "Remind me at six to call mom."
    assert transcript.engine == "gemini" and transcript.model == "gemini-3.5-flash-lite"
    assert transcript.usage == {"input_tokens": 390, "output_tokens": 9}
    (call,) = runtime.calls
    assert call["system"] == PROVIDER_SYSTEM_INSTRUCTION
    assert call["provider"] == "gemini" and call["model"] == "gemini-3.5-flash-lite"
    assert call["messages"] == [
        {
            "role": "user",
            "content": [
                {"type": "audio", "media_type": "audio/ogg", "data": base64.b64encode(OGG_OPUS).decode("ascii")}
            ],
        }
    ]
    mp3 = await engine.transcribe(AudioClip(data=MP3_ID3, family="mp3"), llm_provider="gemini", llm_model="m")
    assert mp3.ok and runtime.calls[-1]["messages"][0]["content"][0]["media_type"] == "audio/mp3"


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", ["[no speech]", "[No speech].", "   "])
async def test_no_speech_from_the_provider(answer):
    engine = ProviderAudioEngine(lambda: FakeRuntime(text=answer))
    transcript = await engine.transcribe(AudioClip(data=OGG_OPUS, family="ogg"), llm_provider="gemini", llm_model="m")
    assert transcript.ok is False and transcript.error == "no_speech"
    assert transcript.usage  # the call was still billed


@pytest.mark.asyncio
async def test_the_provider_engine_refuses_before_any_call():
    runtime = FakeRuntime()
    engine = ProviderAudioEngine(lambda: runtime)
    big = AudioClip(data=OGG_OPUS + b"\x00" * (14 * 1024 * 1024), family="ogg")
    assert (await engine.transcribe(big, llm_provider="gemini", llm_model="m")).error == "too_large"
    for family, data in (("m4a", M4A), ("webm", WEBM)):
        refused = await engine.transcribe(AudioClip(data=data, family=family), llm_provider="gemini", llm_model="m")
        assert refused.error == "format_needs_local"
    assert runtime.calls == []


@pytest.mark.asyncio
async def test_a_provider_error_is_a_code_without_its_body():
    from services.agent.providers import ProviderError, ProviderNotConfigured

    body = "upstream said: key=AIzaSECRET and the whole request"
    engine = ProviderAudioEngine(lambda: FakeRuntime(error=ProviderError("gemini", 500, body)))
    transcript = await engine.transcribe(AudioClip(data=OGG_OPUS, family="ogg"), llm_provider="gemini", llm_model="m")
    assert transcript.ok is False and transcript.error == "provider_failed"
    assert "AIza" not in repr(transcript)
    missing = ProviderAudioEngine(
        lambda: FakeRuntime(error=ProviderNotConfigured("gemini", reason="user_provider_unavailable"))
    )
    result = await missing.transcribe(AudioClip(data=OGG_OPUS, family="ogg"), llm_provider="gemini", llm_model="m")
    assert result.error == "provider_not_configured"
    none = ProviderAudioEngine(lambda: None)
    assert (await none.transcribe(AudioClip(data=OGG_OPUS, family="ogg"), llm_provider="gemini", llm_model="m")).error == (
        "provider_not_configured"
    )
