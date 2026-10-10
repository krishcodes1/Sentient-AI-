"""The speech-to-text worker process: reads one recording from stdin, decodes it
with a forced demuxer, and writes one JSON line with what Whisper heard.

Why it exists: decoding a stranger's audio file (FFmpeg inside PyAV) and
running the model belong in a process of their own that the server can kill
at a deadline or on /stop, that holds no server secrets, and that a crash
cannot take down. services/tools/transcribe.LocalWhisperEngine starts it as
``python -m services.tools.transcribe_worker --model-dir DIR --format <demuxer>
--max-seconds 600 --threads N`` with an allowlisted environment
(HF_HUB_OFFLINE=1). It imports only the standard library, av, numpy and
faster_whisper, never the app's settings.

Output, one line on stdout: {"ok": true, "text", "language",
"language_probability", "duration_s"} or {"ok": false, "error": too_long |
no_audio_stream | decode_failed | model_missing | engine_missing}. The
transcript is never written to stderr, and library logging is switched off.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
from typing import Any, Optional, Sequence

SAMPLE_RATE = 16000
# The demuxers the worker will force; anything else is refused before any
# decoding (the server picks one from the sniffed type).
ALLOWED_DEMUXERS = frozenset({"ogg", "mp3", "wav", "flac", "mp4", "webm"})
# Telegram rounds a note's length; a second of grace past --max-seconds.
_GRACE_SECONDS = 1
# The Bot API's file limit, plus room: stdin is never read past this.
MAX_INPUT_BYTES = 20 * 1024 * 1024
_MODEL_FILES = ("config.json", "model.bin", "tokenizer.json")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="transcribe_worker", add_help=False)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--format", required=True, choices=sorted(ALLOWED_DEMUXERS))
    parser.add_argument("--max-seconds", type=int, required=True)
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args(argv)
    if not 1 <= args.max_seconds <= 600:
        parser.error("--max-seconds must be between 1 and 600")
    args.threads = max(1, min(int(args.threads), 16))
    return args


def emit(answer: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(answer, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _as_frames(value: Any) -> list[Any]:
    """PyAV's resample() answers a list (newer) or one frame or None."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def decode_audio(data: bytes, demuxer: str, max_seconds: int, av: Any, np: Any) -> tuple[Any, str]:
    """16 kHz mono float32 samples of *data* read with *demuxer*, or
    (None, error code). Decoding stops as soon as the audio passes
    *max_seconds* (plus a second of grace), which bounds CPU and memory."""
    if demuxer not in ALLOWED_DEMUXERS:
        return None, "decode_failed"
    limit = (max_seconds + _GRACE_SECONDS) * SAMPLE_RATE
    try:
        container = av.open(io.BytesIO(data), mode="r", format=demuxer)
    except Exception:  # noqa: BLE001 - any decoder failure is one code
        return None, "decode_failed"
    try:
        stream = next((s for s in container.streams if getattr(s, "type", "") == "audio"), None)
        if stream is None:
            return None, "no_audio_stream"
        resampler = av.AudioResampler(format="s16", layout="mono", rate=SAMPLE_RATE)
        chunks: list[Any] = []
        total = 0

        def take(frames: list[Any]) -> bool:
            nonlocal total
            for out in frames:
                samples = np.asarray(out.to_ndarray()).reshape(-1)
                total += int(samples.shape[0])
                if total > limit:
                    return False
                chunks.append(samples)
            return True

        for frame in container.decode(stream):
            if not take(_as_frames(resampler.resample(frame))):
                return None, "too_long"
        if not take(_as_frames(resampler.resample(None))):
            return None, "too_long"
    except Exception:  # noqa: BLE001 - a damaged file is one code
        return None, "decode_failed"
    finally:
        try:
            container.close()
        except Exception:  # noqa: BLE001
            pass
    if not chunks:
        return np.zeros(0, dtype=np.float32), ""
    joined = np.concatenate(chunks).astype(np.float32) / 32768.0
    return joined, ""


def model_present(model_dir: str) -> bool:
    try:
        return all(os.path.isfile(os.path.join(model_dir, name)) for name in _MODEL_FILES) and any(
            name.startswith("vocabulary.") for name in os.listdir(model_dir)
        )
    except OSError:
        return False


def run(args: argparse.Namespace, data: bytes) -> dict[str, Any]:
    """The whole job for one recording; the answer to emit."""
    if len(data) > MAX_INPUT_BYTES:
        return {"ok": False, "error": "decode_failed"}
    try:
        import av
        import numpy as np
        from faster_whisper import WhisperModel
    except Exception:  # noqa: BLE001 - not installed (or broken)
        return {"ok": False, "error": "engine_missing"}
    if not model_present(args.model_dir):
        return {"ok": False, "error": "model_missing"}
    samples, error = decode_audio(data, args.format, args.max_seconds, av, np)
    if error:
        return {"ok": False, "error": error}
    duration_s = round(int(samples.shape[0]) / SAMPLE_RATE, 2)
    if duration_s <= 0:
        return {"ok": True, "text": "", "language": "", "language_probability": 0.0, "duration_s": 0.0}
    try:
        model = WhisperModel(
            args.model_dir,
            device="cpu",
            compute_type="int8",
            cpu_threads=args.threads,
            local_files_only=True,
        )
        segments, info = model.transcribe(
            samples,
            beam_size=1,
            vad_filter=True,
            condition_on_previous_text=False,
        )
        text = " ".join(str(segment.text).strip() for segment in segments).strip()
    except Exception:  # noqa: BLE001 - the model failed on this input
        return {"ok": False, "error": "decode_failed"}
    return {
        "ok": True,
        "text": text,
        "language": str(getattr(info, "language", "") or ""),
        "language_probability": round(float(getattr(info, "language_probability", 0.0) or 0.0), 3),
        "duration_s": duration_s,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Nothing a library logs may carry what was heard to stderr.
    logging.disable(logging.CRITICAL)
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    args = parse_args(argv)
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    try:
        answer = run(args, data)
    except Exception:  # noqa: BLE001 - one line, never a traceback with text in it
        answer = {"ok": False, "error": "decode_failed"}
    emit(answer)
    return 0 if answer.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
