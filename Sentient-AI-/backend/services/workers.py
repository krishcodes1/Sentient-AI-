"""Runs one isolated child process with an allowlisted environment, a
deadline, capped output and cancellation, and limits how many run at once.

Why it exists: the document parser (services/files/sandbox.py), and later
speech-to-text and media workers, all need the same careful child process:
no shell, no server secrets in its environment (``safe_child_env``), killed
at its deadline, on the caller's stop and when the awaiting task is
cancelled, with stdout read line by line under per-line and total caps so a
partial answer survives a kill. Windows' selector event loop cannot start
subprocesses (NotImplementedError); a threaded ``subprocess.Popen`` runner
takes over there with the same contract.

Nothing here logs the child's output: its stdout and stderr may hold text
read from a user's file.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
import queue
import re
import subprocess
import threading
import time
import weakref
from dataclasses import dataclass
from typing import AsyncIterator, Awaitable, Callable, Mapping, Optional, Sequence

import structlog

logger = structlog.get_logger(__name__)

# The only variables a child inherits. Never SECRET_KEY, ENCRYPTION_KEY,
# AUDIT_HMAC_KEY, DATABASE_URL, provider keys or bot tokens.
CHILD_ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "HOME",
)
# An ``extra`` variable whose name looks like it carries a secret is dropped.
_SECRET_NAME = re.compile(
    r"SECRET|PASSW|TOKEN|API_?KEY|PRIVATE|CREDENTIAL|DATABASE_URL|ENCRYPTION|HMAC|_KEY$",
    re.IGNORECASE,
)

_STDERR_TAIL_BYTES = 4096
_READ_CHUNK = 65536
_POLL_S = 0.1
# How long a run whose task was cancelled waits for its killed child to
# exit before the CancelledError goes on. The caller's cleanup comes next
# (the sandbox removes the child's working directory), and Windows keeps a
# directory that a process still has as its working directory.
REAP_S = 2.0


def safe_child_env(extra: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """The environment for a child process: CHILD_ENV_ALLOWLIST from this
    process's environment, plus *extra* minus any name that looks secret."""
    env: dict[str, str] = {}
    for name in CHILD_ENV_ALLOWLIST:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    for name, value in (extra or {}).items():
        if _SECRET_NAME.search(name) or name.upper().startswith("PYTHON"):
            continue
        env[str(name)] = str(value)
    return env


@dataclass
class WorkerResult:
    """How a child ended. ``exit_code`` is None when it was killed before
    exiting on its own. ``stdout`` holds the output only when no ``on_line``
    was given (lines handed to on_line are not kept twice). ``truncated``:
    a line or the total output passed its cap and the child was stopped."""

    exit_code: Optional[int]
    stdout: bytes
    stderr_tail: str
    timed_out: bool
    cancelled: bool
    truncated: bool


class WorkerBusy(Exception):
    """No worker slot came free within the caller's wait."""


class WorkerSlots:
    """At most *limit* workers at once in this process (per event loop: a
    server has one; the test suite starts a loop per test)."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._semaphores: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, asyncio.Semaphore
        ] = weakref.WeakKeyDictionary()

    def _semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        semaphore = self._semaphores.get(loop)
        if semaphore is None:
            semaphore = self._semaphores[loop] = asyncio.Semaphore(self.limit)
        return semaphore

    @contextlib.asynccontextmanager
    async def acquire(self, timeout_s: float) -> AsyncIterator[None]:
        """Hold one slot for the body; raises WorkerBusy when none comes
        free within *timeout_s* seconds."""
        semaphore = self._semaphore()
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout_s)
        except (TimeoutError, asyncio.TimeoutError):
            raise WorkerBusy() from None
        try:
            yield
        finally:
            semaphore.release()


class _LineSplitter:
    """Feeds complete lines to *on_line* and enforces the caps; tells the
    caller to stop once one is passed."""

    def __init__(
        self,
        on_line: Optional[Callable[[bytes], None]],
        max_line_bytes: int,
        max_stdout_bytes: int,
    ) -> None:
        self._on_line = on_line
        self._max_line = max_line_bytes
        self._max_total = max_stdout_bytes
        self._pending = bytearray()
        self._kept = bytearray()
        self.total = 0
        self.truncated = False

    def feed(self, chunk: bytes) -> bool:
        """False once a cap is passed (the child must be stopped)."""
        if self.truncated:
            return False
        self.total += len(chunk)
        if self.total > self._max_total:
            self.truncated = True
            room = len(chunk) - (self.total - self._max_total)
            chunk = chunk[: max(room, 0)]
        if self._on_line is None:
            self._kept += chunk
            return not self.truncated
        self._pending += chunk
        while True:
            newline = self._pending.find(b"\n")
            if newline == -1:
                break
            line = bytes(self._pending[:newline])
            del self._pending[: newline + 1]
            if len(line) > self._max_line:
                self.truncated = True
                return False
            if line:
                self._on_line(line)
        if len(self._pending) > self._max_line:
            self.truncated = True
            self._pending.clear()
            return False
        return not self.truncated

    def finish(self) -> bytes:
        """Flush a last line without a newline; the kept stdout."""
        if self._on_line is not None and self._pending and not self.truncated:
            if len(self._pending) <= self._max_line:
                self._on_line(bytes(self._pending))
            self._pending.clear()
        return bytes(self._kept)


def _tail(buffer: bytearray, chunk: bytes) -> None:
    buffer += chunk
    if len(buffer) > _STDERR_TAIL_BYTES:
        del buffer[: len(buffer) - _STDERR_TAIL_BYTES]


def _stopped(cancelled: Optional[Callable[[], bool]]) -> bool:
    if cancelled is None:
        return False
    try:
        return bool(cancelled())
    except Exception:  # noqa: BLE001 - no answer means stop, fail closed
        return True


async def run_worker(
    argv: Sequence[str],
    *,
    stdin: bytes,
    env: Mapping[str, str],
    cwd: str,
    deadline_s: float,
    max_stdout_bytes: int,
    on_line: Optional[Callable[[bytes], None]] = None,
    max_line_bytes: int = 1048576,
    cancelled: Optional[Callable[[], bool]] = None,
) -> WorkerResult:
    """Run *argv* (no shell) with *stdin* written to it and *env* as its
    whole environment, and wait for it within *deadline_s* seconds.

    stdout is read as it comes: with *on_line* every complete line is
    handed to it as bytes (a line over *max_line_bytes*, or more than
    *max_stdout_bytes* in total, stops the child and sets ``truncated``);
    lines already handed over are the caller's even when the child is then
    killed. The child is killed at the deadline (``timed_out``), when
    *cancelled* answers True (``cancelled``), and when the awaiting task is
    cancelled (the CancelledError propagates after the kill). In the
    threaded fallback *on_line* is called from a worker thread, so it must
    be quick and thread-safe (appending to a list is).
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(env),
            cwd=cwd,
        )
    except NotImplementedError:
        return await _run_threaded(
            argv,
            stdin=stdin,
            env=env,
            cwd=cwd,
            deadline_s=deadline_s,
            max_stdout_bytes=max_stdout_bytes,
            on_line=on_line,
            max_line_bytes=max_line_bytes,
            cancelled=cancelled,
        )
    splitter = _LineSplitter(on_line, max_line_bytes, max_stdout_bytes)
    stderr_tail = bytearray()
    timed_out = was_cancelled = False

    async def write_stdin() -> None:
        assert process.stdin is not None
        try:
            process.stdin.write(stdin)
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except Exception:  # noqa: BLE001
                pass

    async def read_stdout() -> None:
        assert process.stdout is not None
        while True:
            chunk = await process.stdout.read(_READ_CHUNK)
            if not chunk:
                return
            if not splitter.feed(chunk):
                _kill(process)
                return

    async def read_stderr() -> None:
        assert process.stderr is not None
        while True:
            chunk = await process.stderr.read(_READ_CHUNK)
            if not chunk:
                return
            _tail(stderr_tail, chunk)

    async def watch_stop() -> None:
        while True:
            await asyncio.sleep(_POLL_S)
            if _stopped(cancelled):
                return

    writer = asyncio.create_task(write_stdin())
    readers = [asyncio.create_task(read_stdout()), asyncio.create_task(read_stderr())]
    watcher = asyncio.create_task(watch_stop()) if cancelled is not None else None
    try:
        waiting: set[asyncio.Task[None]] = set(readers)
        if watcher is not None:
            waiting.add(watcher)
        deadline = time.monotonic() + max(deadline_s, 0.0)
        while any(not r.done() for r in readers):
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            done, _ = await asyncio.wait(waiting, timeout=left, return_when=asyncio.FIRST_COMPLETED)
            if watcher is not None and watcher in done:
                was_cancelled = True
                break
            waiting -= done
        if timed_out or was_cancelled:
            _kill(process)
        try:
            await asyncio.wait_for(process.wait(), 5.0)
        except (TimeoutError, asyncio.TimeoutError):
            _kill(process)
        for reader in readers:
            try:
                await asyncio.wait_for(reader, 2.0)
            except (TimeoutError, asyncio.TimeoutError, asyncio.CancelledError):
                pass
    except asyncio.CancelledError:
        _kill(process)
        await _reap(process.wait())
        raise
    finally:
        helpers = [writer, *readers] + ([watcher] if watcher is not None else [])
        for task in helpers:
            if not task.done():
                task.cancel()
        if process.returncode is None:
            _kill(process)
        # Close the pipes and the transport now (a closed transport also
        # kills a child that is somehow still running), rather than leave
        # them to the garbage collector after the event loop is gone.
        transport = getattr(process, "_transport", None)
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001 - best effort cleanup
                pass
    stdout = splitter.finish()
    killed = timed_out or was_cancelled or splitter.truncated
    return WorkerResult(
        exit_code=None if killed and process.returncode not in (0,) else process.returncode,
        stdout=stdout,
        stderr_tail=bytes(stderr_tail).decode("utf-8", "replace"),
        timed_out=timed_out,
        cancelled=was_cancelled,
        truncated=splitter.truncated,
    )


def _kill(process: object) -> None:
    try:
        process.kill()  # type: ignore[attr-defined]
    except (ProcessLookupError, OSError):
        pass


async def _reap(exited: Awaitable[object]) -> None:
    """Wait at most REAP_S for *exited* (the killed child's exit), shielded:
    the task awaiting the run is being cancelled, and the cancellation goes
    on afterwards whatever happens here."""
    try:
        await asyncio.wait_for(asyncio.shield(exited), REAP_S)
    except (asyncio.CancelledError, TimeoutError, asyncio.TimeoutError, Exception):  # noqa: BLE001
        pass


async def _run_threaded(
    argv: Sequence[str],
    *,
    stdin: bytes,
    env: Mapping[str, str],
    cwd: str,
    deadline_s: float,
    max_stdout_bytes: int,
    on_line: Optional[Callable[[bytes], None]],
    max_line_bytes: int,
    cancelled: Optional[Callable[[], bool]],
) -> WorkerResult:
    """run_worker for an event loop that cannot start subprocesses (the
    Windows selector loop): the same contract on subprocess.Popen and
    threads. Task cancellation sets a flag the runner thread checks between
    reads; it then kills the child."""
    stop = threading.Event()
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(
        None,
        functools.partial(
            _blocking_run,
            list(argv),
            stdin=stdin,
            env=dict(env),
            cwd=cwd,
            deadline_s=deadline_s,
            max_stdout_bytes=max_stdout_bytes,
            on_line=on_line,
            max_line_bytes=max_line_bytes,
            cancelled=cancelled,
            stop=stop,
        ),
    )
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        stop.set()
        # The runner thread kills the child at its next check and waits for
        # it; give it that long before the caller cleans up.
        await _reap(future)
        raise


def _blocking_run(
    argv: list[str],
    *,
    stdin: bytes,
    env: dict[str, str],
    cwd: str,
    deadline_s: float,
    max_stdout_bytes: int,
    on_line: Optional[Callable[[bytes], None]],
    max_line_bytes: int,
    cancelled: Optional[Callable[[], bool]],
    stop: threading.Event,
) -> WorkerResult:
    process = subprocess.Popen(  # noqa: S603 - argv is the caller's fixed list, no shell
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
    )
    chunks: queue.Queue[Optional[bytes]] = queue.Queue()
    stderr_tail = bytearray()

    def write_stdin() -> None:
        assert process.stdin is not None
        try:
            process.stdin.write(stdin)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    def read_stdout() -> None:
        assert process.stdout is not None
        try:
            while True:
                chunk = process.stdout.read1(_READ_CHUNK)  # type: ignore[attr-defined]
                if not chunk:
                    break
                chunks.put(chunk)
        except (OSError, ValueError):
            pass
        chunks.put(None)

    def read_stderr() -> None:
        assert process.stderr is not None
        try:
            while True:
                chunk = process.stderr.read1(_READ_CHUNK)  # type: ignore[attr-defined]
                if not chunk:
                    break
                _tail(stderr_tail, chunk)
        except (OSError, ValueError):
            pass

    threads = [
        threading.Thread(target=write_stdin, daemon=True),
        threading.Thread(target=read_stdout, daemon=True),
        threading.Thread(target=read_stderr, daemon=True),
    ]
    for thread in threads:
        thread.start()
    splitter = _LineSplitter(on_line, max_line_bytes, max_stdout_bytes)
    deadline = time.monotonic() + max(deadline_s, 0.0)
    timed_out = was_cancelled = False
    try:
        while True:
            if stop.is_set() or _stopped(cancelled):
                was_cancelled = True
                break
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            try:
                chunk = chunks.get(timeout=min(_POLL_S, left))
            except queue.Empty:
                continue
            if chunk is None:
                break
            if not splitter.feed(chunk):
                break
    finally:
        if timed_out or was_cancelled or splitter.truncated:
            _kill(process)
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            _kill(process)
            process.wait(timeout=5.0)
        for thread in threads:
            thread.join(timeout=2.0)
        for stream in (process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
    stdout = splitter.finish()
    killed = timed_out or was_cancelled or splitter.truncated
    return WorkerResult(
        exit_code=None if killed and process.returncode != 0 else process.returncode,
        stdout=stdout,
        stderr_tail=bytes(stderr_tail).decode("utf-8", "replace"),
        timed_out=timed_out,
        cancelled=was_cancelled,
        truncated=splitter.truncated,
    )
