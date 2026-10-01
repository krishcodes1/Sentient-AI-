"""Tests for the speech-to-text worker (services/tools/transcribe_worker.py):
its arguments, the demuxer allowlist, the decode cut-off past --max-seconds
with a fake decoder, the one-line answer of a real worker process when the
engine is missing (nothing on stderr), and, only where faster-whisper and the
model are installed, a real transcription of a second of silence.

Why it exists: the worker decodes strangers' audio; it must force the
demuxer the server chose, stop decoding at the length limit, and never write
anything but one JSON line.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import wave
from pathlib import Path

import pytest

from services.tools import transcribe
from services.tools import transcribe_worker as worker
from services.workers import safe_child_env

BACKEND = Path(transcribe.BACKEND_DIR)


def test_arguments_are_checked():
    args = worker.parse_args(["--model-dir", "/m", "--format", "ogg", "--max-seconds", "600", "--threads", "99"])
    assert args.model_dir == "/m" and args.format == "ogg" and args.max_seconds == 600
    assert args.threads == 16
    for bad in (
        ["--model-dir", "/m", "--format", "matroska", "--max-seconds", "600"],
        ["--model-dir", "/m", "--format", "ogg", "--max-seconds", "601"],
        ["--model-dir", "/m", "--format", "ogg", "--max-seconds", "0"],
        ["--format", "ogg", "--max-seconds", "60"],
    ):
        with pytest.raises(SystemExit):
            worker.parse_args(bad)


def test_the_demuxers_match_the_server_side_map():
    assert set(transcribe.DEMUXERS.values()) == worker.ALLOWED_DEMUXERS


# ── decode with a fake PyAV and a fake numpy ────────────────────────────


class FakeArray:
    def __init__(self, values: list[float]) -> None:
        self.values = list(values)

    @property
    def shape(self) -> tuple[int]:
        return (len(self.values),)

    def reshape(self, _shape: int) -> "FakeArray":
        return self

    def astype(self, _dtype: object) -> "FakeArray":
        return self

    def __truediv__(self, other: float) -> "FakeArray":
        return FakeArray([v / other for v in self.values])


class FakeNumpy:
    float32 = "float32"

    @staticmethod
    def asarray(value):
        return value if isinstance(value, FakeArray) else FakeArray(value)

    @staticmethod
    def concatenate(chunks):
        return FakeArray([v for chunk in chunks for v in chunk.values])

    @staticmethod
    def zeros(n, dtype=None):
        return FakeArray([0.0] * n)


class FakeFrame:
    def __init__(self, samples: int) -> None:
        self.samples = samples

    def to_ndarray(self):
        return FakeArray([16384] * self.samples)


class FakeStream:
    type = "audio"


class FakeContainer:
    def __init__(self, frames: int, stream: bool = True) -> None:
        self.frames = frames
        self.streams = [FakeStream()] if stream else []
        self.decoded = 0
        self.closed = False

    def decode(self, stream):
        for _ in range(self.frames):
            self.decoded += 1
            yield FakeFrame(16000)  # one second a frame

    def close(self):
        self.closed = True


class FakeResampler:
    def __init__(self, **kwargs) -> None:
        assert kwargs == {"format": "s16", "layout": "mono", "rate": 16000}

    def resample(self, frame):
        return [] if frame is None else [frame]


class FakeAv:
    AudioResampler = FakeResampler

    def __init__(self, container: FakeContainer | None = None, error: Exception | None = None) -> None:
        self.container = container
        self.error = error
        self.opened: list[tuple[str, str]] = []

    def open(self, source, mode="r", format=None):
        assert isinstance(source, io.BytesIO)
        self.opened.append((mode, format))
        if self.error is not None:
            raise self.error
        return self.container


def test_decoding_forces_the_demuxer_and_resamples_to_16k_mono():
    av = FakeAv(FakeContainer(frames=2))
    samples, error = worker.decode_audio(b"audio", "ogg", 600, av, FakeNumpy)
    assert error == "" and samples.shape == (32000,)
    assert samples.values[0] == 0.5
    assert av.opened == [("r", "ogg")]
    assert av.container.closed


def test_decoding_stops_just_past_max_seconds():
    container = FakeContainer(frames=100)
    samples, error = worker.decode_audio(b"audio", "mp3", 2, FakeAv(container), FakeNumpy)
    assert samples is None and error == "too_long"
    # Two seconds plus a second of grace: the fourth second stops it.
    assert container.decoded == 4 and container.closed
    ok, error = worker.decode_audio(b"audio", "mp3", 3, FakeAv(FakeContainer(frames=4)), FakeNumpy)
    assert error == "" and ok.shape == (64000,)


def test_decode_failures_are_codes():
    assert worker.decode_audio(b"x", "ogg", 600, FakeAv(FakeContainer(1, stream=False)), FakeNumpy)[1] == (
        "no_audio_stream"
    )
    assert worker.decode_audio(b"x", "ogg", 600, FakeAv(error=ValueError("bad")), FakeNumpy)[1] == "decode_failed"
    assert worker.decode_audio(b"x", "matroska", 600, FakeAv(FakeContainer(1)), FakeNumpy)[1] == "decode_failed"


def test_model_present_needs_every_file(tmp_path):
    assert worker.model_present(str(tmp_path)) is False
    for name in ("config.json", "model.bin", "tokenizer.json", "vocabulary.json"):
        (tmp_path / name).write_text("x")
    assert worker.model_present(str(tmp_path)) is True
    assert worker.model_present(str(tmp_path / "missing")) is False


# ── the real process ────────────────────────────────────────────────────


def _run_worker_process(data: bytes, model_dir: str, fmt: str = "ogg") -> subprocess.CompletedProcess:
    argv = [
        sys.executable,
        "-m",
        "services.tools.transcribe_worker",
        "--model-dir",
        model_dir,
        "--format",
        fmt,
        "--max-seconds",
        "600",
        "--threads",
        "1",
    ]
    return subprocess.run(
        argv,
        input=data,
        capture_output=True,
        cwd=str(BACKEND),
        env=safe_child_env({"HF_HUB_OFFLINE": "1"}),
        timeout=120,
    )


@pytest.mark.skipif(
    transcribe.local_engine_installed(), reason="faster-whisper is installed here; the missing-engine answer cannot occur"
)
def test_a_real_worker_without_the_engine_answers_one_line_and_nothing_on_stderr(tmp_path):
    done = _run_worker_process(b"OggS secret words", str(tmp_path))
    lines = [line for line in done.stdout.decode().splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0]) == {"ok": False, "error": "engine_missing"}
    assert done.returncode == 1
    assert done.stderr == b""


def _silent_wav(seconds: float = 1.0) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(2)
        out.setframerate(16000)
        out.writeframes(b"\x00\x00" * int(16000 * seconds))
    return buffer.getvalue()


def test_a_real_transcription_where_the_engine_is_installed():
    pytest.importorskip("faster_whisper")
    if not transcribe.local_engine_installed():
        pytest.skip("the speech model is not installed here")
    done = _run_worker_process(_silent_wav(), transcribe.speech_model_dir(), fmt="wav")
    answer = json.loads(done.stdout.decode().strip().splitlines()[-1])
    assert answer["ok"] is True and answer["duration_s"] == pytest.approx(1.0, abs=0.1)
    assert answer["text"] == ""  # silence: nothing heard
