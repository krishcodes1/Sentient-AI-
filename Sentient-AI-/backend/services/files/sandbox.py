"""Runs the parser worker on one file and collects what it reports, under the
output caps; an in-process twin serves the tests.

Why it exists: this is the parent side of the isolation boundary. Each file
gets a fresh ``[sys.executable, -I, worker/main.py]`` process (never reused)
through services/workers.run_worker: an allowlisted environment with no
secrets, a fresh temporary working directory that is deleted afterwards, the
bytes on stdin, and the preset's deadline. At most WORKER_SLOTS workers run
per process; a caller waits WORKER_QUEUE_WAIT_S for one and is then told
Crawler is busy. The worker's NDJSON lines are read as they arrive, so on a
deadline the sections already streamed are kept (marked partial), and the
caps hold whatever the worker sends: 1 MB per line and 1,000,000 characters
per document. A worker that dies without finishing is a damaged file. A
working directory something left behind (a crash, a power cut) is removed
once it is an hour old, by the next run that comes along.

Logs carry facts only (kind, size, pages, seconds, exit code, outcome),
never a name, text or URL.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence

import structlog

from services.files import messages
from services.files.limits import (
    MAX_DOCUMENT_CHARS,
    MAX_LINE_BYTES,
    MAX_PDF_PAGES,
    MAX_WORKER_STDOUT_BYTES,
    WORKER_QUEUE_WAIT_S,
    WORKER_SLOTS,
    Preset,
)
from services.files.sections import ExtractionRefused, RawUnit
from services.files.worker.protocol import encode_header
from services.workers import WorkerBusy, WorkerSlots, run_worker, safe_child_env

logger = structlog.get_logger(__name__)

WORKER_MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker", "main.py")

# One pool of worker slots per server process, shared by every sandbox.
_SLOTS = WorkerSlots(WORKER_SLOTS)

# Each run's working directory: tempfile.mkdtemp(prefix=WORKDIR_PREFIX).
WORKDIR_PREFIX = "crawler-file-"
# A working directory this old is left over (no run lasts anywhere near
# this long), and the sweep for them runs at most this often.
STALE_WORKDIR_S = 3600.0
_SWEEP_EVERY_S = 3600.0
_next_sweep = 0.0


def sweep_stale_workdirs(root: Optional[str] = None, *, older_than_s: float = STALE_WORKDIR_S) -> int:
    """Remove this sandbox's working directories in *root* (the temp folder)
    last changed more than *older_than_s* ago; how many went. Only plain
    directories named WORKDIR_PREFIX..., never a link or a junction; errors
    are ignored (another process may hold one)."""
    folder = root or tempfile.gettempdir()
    cutoff = time.time() - older_than_s
    removed = 0
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return 0
    for entry in entries:
        try:
            if (
                not entry.name.startswith(WORKDIR_PREFIX)
                or entry.is_symlink()
                or getattr(entry, "is_junction", lambda: False)()
                or not entry.is_dir(follow_symlinks=False)
                or entry.stat(follow_symlinks=False).st_mtime > cutoff
            ):
                continue
        except OSError:
            continue
        shutil.rmtree(entry.path, ignore_errors=True)
        if not os.path.exists(entry.path):
            removed += 1
    return removed


async def _sweep_when_due() -> None:
    """sweep_stale_workdirs off the event loop, at most once per
    _SWEEP_EVERY_S per server process."""
    global _next_sweep
    now = time.monotonic()
    if now < _next_sweep:
        return
    _next_sweep = now + _SWEEP_EVERY_S
    try:
        removed = await asyncio.to_thread(sweep_stale_workdirs)
    except Exception as exc:  # noqa: BLE001 - housekeeping never fails a parse
        logger.warning("file_workdir_sweep_failed", error_type=type(exc).__name__)
        return
    if removed:
        logger.info("file_workdirs_swept", removed=removed)


def default_worker_argv() -> list[str]:
    return [sys.executable, "-I", WORKER_MAIN]


@dataclass
class WorkerOutput:
    """What one worker run reported. ``done`` means the worker reached its
    end; ``timed_out`` that the deadline stopped it (units read so far are
    kept); ``error`` a refusal code it sent."""

    title: str = ""
    pages_total: Optional[int] = None
    units: list[RawUnit] = field(default_factory=list)
    scanned: list[int] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: Optional[str] = None
    done: bool = False
    truncated: bool = False
    timed_out: bool = False
    chars: int = 0


class _Collector:
    """Turns protocol lines into a WorkerOutput, holding the character cap.
    A line that is not a protocol object is ignored (counted as a warning
    once)."""

    def __init__(self, max_chars: int = MAX_DOCUMENT_CHARS) -> None:
        self.output = WorkerOutput()
        self._max_chars = max_chars
        self._bad_line = False

    def __call__(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            self._bad(None)
            return
        if not isinstance(message, dict):
            self._bad(None)
            return
        kind = message.get("t")
        out = self.output
        if kind == "unit":
            self._unit(message)
        elif kind == "meta":
            title = message.get("title")
            out.title = title[:300] if isinstance(title, str) else ""
            pages = message.get("pages_total")
            out.pages_total = pages if isinstance(pages, int) and not isinstance(pages, bool) and pages >= 0 else None
        elif kind == "scan":
            page = message.get("page")
            if isinstance(page, int) and not isinstance(page, bool) and len(out.scanned) < 500:
                out.scanned.append(page)
        elif kind == "warn":
            code = message.get("code")
            if isinstance(code, str) and code and len(out.warnings) < 50:
                out.warnings.append(code[:64])
        elif kind == "error":
            code = message.get("code")
            out.error = code[:64] if isinstance(code, str) and code else "corrupt"
        elif kind == "done":
            out.done = True
            if message.get("truncated") is True:
                out.truncated = True
        else:
            self._bad(message)

    def _cut(self) -> None:
        """The character cap dropped text: truncated, with its warning."""
        self.output.truncated = True
        if "truncated_at_chars" not in self.output.warnings:
            self.output.warnings.append("truncated_at_chars")

    def _bad(self, _message: object) -> None:
        if not self._bad_line:
            self._bad_line = True
            self.output.warnings.append("worker_bad_line")

    def _unit(self, message: dict[str, object]) -> None:
        out = self.output
        text = message.get("text")
        label = message.get("label")
        page = message.get("page")
        src = message.get("src")
        if not isinstance(text, str):
            return
        if out.chars >= self._max_chars:
            self._cut()
            return
        room = self._max_chars - out.chars
        if len(text) > room:
            text = text[:room]
            self._cut()
        out.chars += len(text)
        out.units.append(
            RawUnit(
                label=label[:200] if isinstance(label, str) else "",
                page=page if isinstance(page, int) and not isinstance(page, bool) else None,
                text=text,
                src=src if src in ("text", "ocr") else "text",
            )
        )


class Sandbox(Protocol):
    """Runs one parse. Raises ExtractionRefused("busy") when no worker is
    free in time; every other outcome is in the WorkerOutput."""

    async def run(
        self,
        data: bytes,
        *,
        kind: str,
        preset: Preset,
        delimiter: str = ",",
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> WorkerOutput: ...


def _header(data: bytes, kind: str, preset: Preset, delimiter: str) -> bytes:
    return encode_header(
        kind=kind,
        size=len(data),
        deadline_s=preset.deadline_s,
        max_pages=MAX_PDF_PAGES,
        ocr_pages=preset.ocr_pages,
        delimiter=delimiter,
    )


class SubprocessSandbox:
    """The real sandbox: one isolated worker process per file."""

    def __init__(
        self,
        *,
        worker_argv: Optional[Sequence[str]] = None,
        slots: Optional[WorkerSlots] = None,
        queue_wait_s: float = WORKER_QUEUE_WAIT_S,
        deadline_s: Optional[float] = None,
    ) -> None:
        # worker_argv and deadline_s are test seams (a script that sleeps,
        # crashes or prints its environment; a short deadline).
        self._argv = list(worker_argv) if worker_argv is not None else None
        self._slots = slots or _SLOTS
        self._queue_wait_s = queue_wait_s
        self._deadline_s = deadline_s

    async def run(
        self,
        data: bytes,
        *,
        kind: str,
        preset: Preset,
        delimiter: str = ",",
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> WorkerOutput:
        collector = _Collector()
        argv = self._argv or default_worker_argv()
        deadline = self._deadline_s if self._deadline_s is not None else preset.deadline_s
        started = time.monotonic()
        try:
            async with self._slots.acquire(self._queue_wait_s):
                await _sweep_when_due()
                workdir = tempfile.mkdtemp(prefix=WORKDIR_PREFIX)
                try:
                    result = await run_worker(
                        argv,
                        stdin=_header(data, kind, preset, delimiter) + data,
                        env=safe_child_env(),
                        cwd=workdir,
                        deadline_s=deadline,
                        max_stdout_bytes=MAX_WORKER_STDOUT_BYTES,
                        on_line=collector,
                        max_line_bytes=MAX_LINE_BYTES,
                        cancelled=cancelled,
                    )
                finally:
                    shutil.rmtree(workdir, ignore_errors=True)
        except WorkerBusy:
            logger.warning("file_worker_busy", kind=kind, size=len(data))
            raise ExtractionRefused("busy", messages.BUSY) from None
        output = collector.output
        output.timed_out = result.timed_out
        if result.truncated:
            output.truncated = True
            output.warnings.append("output_capped")
        if result.cancelled and output.error is None:
            output.error = "cancelled"
        elif not output.done and not result.timed_out and not result.truncated and output.error is None:
            # Exited (or was killed by its own limits) without finishing.
            output.error = "corrupt"
        logger.info(
            "file_worker_finished",
            kind=kind,
            size=len(data),
            pages=output.pages_total,
            units=len(output.units),
            seconds=round(time.monotonic() - started, 2),
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            outcome=output.error or ("partial" if result.timed_out else "ok"),
        )
        return output


class InProcessSandbox:
    """Runs the worker's parsers in this process (in a thread), through the
    same protocol and caps. For tests: no isolation, no deadline kill."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run(
        self,
        data: bytes,
        *,
        kind: str,
        preset: Preset,
        delimiter: str = ",",
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> WorkerOutput:
        from services.files.worker.main import run as run_parser

        self.calls.append(kind)
        collector = _Collector()
        lines: list[bytes] = []
        header = json.loads(_header(data, kind, preset, delimiter))
        await asyncio.to_thread(run_parser, header, data, lines.append)
        for line in lines:
            collector(line.rstrip(b"\n"))
        if not collector.output.done and collector.output.error is None:
            collector.output.error = "corrupt"
        return collector.output
