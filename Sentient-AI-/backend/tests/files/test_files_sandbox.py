"""Tests for the parser sandbox and the shared worker runner with real child
processes: the real worker end to end, and stand-in worker scripts that
stall, crash, flood their output, print their environment or try the
network.

Why it exists: the isolation boundary is only as good as its behaviour under
a hostile or broken worker: the deadline keeps what was read, the caps cut
what is too much, a crash is a damaged file, no secret reaches the child's
environment, sockets fail inside the worker, a full pool answers busy, and
the threaded fallback (Windows' selector loop) behaves the same. The Windows
CI job runs this file too.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import textwrap

import pytest

from services.files.documents import build_extraction, extract
from services.files.limits import CONNECTOR, UPLOAD
from services.files.sandbox import SubprocessSandbox
from services.files.sections import ExtractionRefused
from services.workers import WorkerBusy, WorkerSlots, run_worker, safe_child_env
from tests.files import builders as b

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A stand-in worker: reads (and ignores) its input, then runs BODY.
_PRELUDE = """
import json, os, sys, time
sys.stdin.buffer.read()
def emit(obj):
    sys.stdout.buffer.write(json.dumps(obj).encode() + b"\\n")
    sys.stdout.buffer.flush()
"""


def script(tmp_path, body: str) -> list[str]:
    path = tmp_path / "worker_stand_in.py"
    path.write_text(_PRELUDE + textwrap.dedent(body), encoding="utf-8")
    return [sys.executable, "-I", str(path)]


def unit(text: str, page: int = 1) -> dict:
    return {"t": "unit", "label": f"Page {page}", "page": page, "text": text}


@pytest.mark.asyncio
async def test_the_real_worker_reads_a_pdf_a_docx_and_an_xlsx():
    sandbox = SubprocessSandbox()
    pdf = await extract(b.make_pdf(["Syllabus page"]), name="s.pdf", declared_mime=None, preset=UPLOAD, sandbox=sandbox)
    assert pdf.sections[0].text == "Syllabus page"
    docx = await extract(b.make_docx(), name="s.docx", declared_mime=None, preset=UPLOAD, sandbox=sandbox)
    assert "Midterm" in docx.sections[0].text
    xlsx = await extract(b.make_xlsx({"G": [["a", 1]]}), name="g.xlsx", declared_mime=None, preset=UPLOAD, sandbox=sandbox)
    assert xlsx.sections[0].text == "a\t1"


@pytest.mark.asyncio
async def test_a_large_text_file_streams_in_pieces_under_the_line_cap():
    # 1.2 MB of text as one unit would pass the 1 MB line cap; the worker
    # sends it in pieces, and every character arrives (up to the char cap).
    text = ('\t"quoted" \\line\\ of notes\n' * 60000).encode("utf-8")
    extraction = await extract(text, name="notes.txt", declared_mime=None, preset=UPLOAD, sandbox=SubprocessSandbox())
    assert extraction.sections[0].label == "Part 1"
    assert extraction.chars > 1_000_000 * 0.9
    assert "output_capped" not in extraction.warnings


@pytest.mark.asyncio
async def test_the_deadline_keeps_the_sections_already_streamed(tmp_path):
    argv = script(
        tmp_path,
        """
        emit({"t": "meta", "title": "", "pages_total": 9})
        emit({"t": "unit", "label": "Page 1", "page": 1, "text": "first page"})
        emit({"t": "unit", "label": "Page 2", "page": 2, "text": "second page"})
        time.sleep(30)
        """,
    )
    sandbox = SubprocessSandbox(worker_argv=argv, deadline_s=1.5)
    output = await sandbox.run(b"x", kind="pdf", preset=UPLOAD)
    assert output.timed_out is True
    assert [u.text for u in output.units] == ["first page", "second page"]
    extraction = build_extraction(
        output, kind="pdf", media_type="application/pdf", detect_warnings=(), size=1, name="a.pdf", preset=UPLOAD
    )
    assert extraction.truncated is True
    assert "timed_out_after_page:2" in extraction.warnings


@pytest.mark.asyncio
async def test_a_deadline_with_nothing_read_is_a_timeout(tmp_path):
    argv = script(tmp_path, "time.sleep(30)\n")
    output = await SubprocessSandbox(worker_argv=argv, deadline_s=1.0).run(b"x", kind="pdf", preset=UPLOAD)
    with pytest.raises(ExtractionRefused) as caught:
        build_extraction(output, kind="pdf", media_type="application/pdf", detect_warnings=(), size=1, name="a", preset=UPLOAD)
    assert caught.value.code == "timeout"


@pytest.mark.asyncio
async def test_an_oversized_line_is_cut_and_the_worker_stopped(tmp_path):
    argv = script(
        tmp_path,
        """
        emit({"t": "unit", "label": "Page 1", "page": 1, "text": "kept"})
        emit({"t": "unit", "label": "Page 2", "page": 2, "text": "x" * (2 * 1024 * 1024)})
        emit({"t": "done", "truncated": False})
        """,
    )
    output = await SubprocessSandbox(worker_argv=argv).run(b"x", kind="pdf", preset=UPLOAD)
    assert [u.text for u in output.units] == ["kept"]
    assert output.truncated is True and "output_capped" in output.warnings


@pytest.mark.asyncio
async def test_too_many_characters_are_cut(tmp_path):
    argv = script(
        tmp_path,
        """
        for page in range(1, 13):
            emit({"t": "unit", "label": f"Page {page}", "page": page, "text": "y" * 100000})
        emit({"t": "done", "truncated": False})
        """,
    )
    output = await SubprocessSandbox(worker_argv=argv).run(b"x", kind="pdf", preset=UPLOAD)
    assert output.chars == 1_000_000
    assert output.truncated is True


@pytest.mark.asyncio
async def test_a_crash_is_a_damaged_file(tmp_path):
    argv = script(tmp_path, 'emit({"t": "unit", "label": "Page 1", "page": 1, "text": "x"})\nsys.exit(3)\n')
    output = await SubprocessSandbox(worker_argv=argv).run(b"x", kind="pdf", preset=UPLOAD)
    assert output.error == "corrupt"
    with pytest.raises(ExtractionRefused) as caught:
        build_extraction(output, kind="pdf", media_type="application/pdf", detect_warnings=(), size=1, name="a", preset=UPLOAD)
    assert caught.value.code == "corrupt"


@pytest.mark.asyncio
async def test_the_worker_environment_holds_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "super-secret-key-value")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h/db")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    argv = script(
        tmp_path,
        """
        emit({"t": "unit", "label": "Page 1", "page": 1, "text": json.dumps(sorted(os.environ))})
        emit({"t": "done", "truncated": False})
        """,
    )
    output = await SubprocessSandbox(worker_argv=argv).run(b"x", kind="pdf", preset=UPLOAD)
    names = set(json.loads(output.units[0].text))
    for secret in ("SECRET_KEY", "DATABASE_URL", "ENCRYPTION_KEY", "ANTHROPIC_API_KEY", "TELEGRAM_BOT_TOKEN"):
        assert secret not in names
    assert names <= {"PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "HOME"} | {
        # Windows adds its own process variables to every child.
        n for n in names if n.startswith(("COMSPEC", "PATHEXT", "WINDIR", "SYSTEMDRIVE", "__"))
    }


def test_safe_child_env_drops_secret_looking_extras(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "x")
    env = safe_child_env({"OMP_THREADS": "1", "MY_API_KEY": "k", "SESSION_TOKEN": "t", "PYTHONPATH": "/x"})
    assert env.get("OMP_THREADS") == "1"
    assert "MY_API_KEY" not in env and "SESSION_TOKEN" not in env and "PYTHONPATH" not in env
    assert "SECRET_KEY" not in env


@pytest.mark.asyncio
async def test_sockets_raise_inside_the_worker(tmp_path):
    argv = script(
        tmp_path,
        f"""
        sys.path.insert(0, {BACKEND!r})
        from services.files.worker.main import disable_network
        disable_network()
        import socket
        results = []
        for attempt in (lambda: socket.socket(), lambda: socket.create_connection(("example.com", 80)),
                        lambda: socket.getaddrinfo("example.com", 80)):
            try:
                attempt()
                results.append("connected")
            except OSError:
                results.append("refused")
        emit({{"t": "unit", "label": "Page 1", "page": 1, "text": ",".join(results)}})
        emit({{"t": "done", "truncated": False}})
        """,
    )
    output = await SubprocessSandbox(worker_argv=argv).run(b"x", kind="pdf", preset=UPLOAD)
    assert output.units[0].text == "refused,refused,refused"


@pytest.mark.asyncio
async def test_a_full_pool_answers_busy_after_the_queue_wait(tmp_path):
    argv = script(tmp_path, 'time.sleep(3)\nemit({"t": "done", "truncated": False})\n')
    slots = WorkerSlots(1)
    first = SubprocessSandbox(worker_argv=argv, slots=slots)
    second = SubprocessSandbox(worker_argv=argv, slots=slots, queue_wait_s=0.2)
    running = asyncio.create_task(first.run(b"x", kind="pdf", preset=UPLOAD))
    await asyncio.sleep(0.3)
    with pytest.raises(ExtractionRefused) as caught:
        await second.run(b"x", kind="pdf", preset=UPLOAD)
    assert caught.value.code == "busy"
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running


@pytest.mark.asyncio
async def test_worker_slots_raise_worker_busy():
    slots = WorkerSlots(1)
    async with slots.acquire(1.0):
        with pytest.raises(WorkerBusy):
            async with slots.acquire(0.05):
                pass


@pytest.mark.asyncio
async def test_the_popen_fallback_runs_the_real_worker(monkeypatch):
    async def no_subprocesses(*args, **kwargs):
        raise NotImplementedError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_subprocesses)
    extraction = await extract(
        b.make_pdf(["fallback page"]), name="a.pdf", declared_mime=None, preset=CONNECTOR, sandbox=SubprocessSandbox()
    )
    assert extraction.sections[0].text == "fallback page"


@pytest.mark.asyncio
async def test_the_popen_fallback_keeps_the_deadline(monkeypatch, tmp_path):
    async def no_subprocesses(*args, **kwargs):
        raise NotImplementedError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_subprocesses)
    argv = script(tmp_path, 'emit({"t": "unit", "label": "Page 1", "page": 1, "text": "early"})\ntime.sleep(30)\n')
    lines: list[bytes] = []
    result = await run_worker(
        argv, stdin=b"x", env=safe_child_env(), cwd=str(tmp_path), deadline_s=1.0,
        max_stdout_bytes=1_000_000, on_line=lines.append,
    )
    assert result.timed_out is True and result.exit_code is None
    assert json.loads(lines[0])["text"] == "early"


@pytest.mark.asyncio
async def test_run_worker_stops_when_cancelled_is_true(tmp_path):
    argv = script(tmp_path, "time.sleep(30)\n")
    result = await run_worker(
        argv, stdin=b"", env=safe_child_env(), cwd=str(tmp_path), deadline_s=20.0,
        max_stdout_bytes=1000, cancelled=lambda: True,
    )
    assert result.cancelled is True and result.timed_out is False


@pytest.mark.asyncio
async def test_run_worker_kills_the_child_when_its_task_is_cancelled(tmp_path):
    marker = tmp_path / "alive.txt"
    argv = script(tmp_path, f"time.sleep(2)\nopen({str(marker)!r}, 'w').write('still running')\n")
    task = asyncio.create_task(
        run_worker(argv, stdin=b"", env=safe_child_env(), cwd=str(tmp_path), deadline_s=20.0, max_stdout_bytes=1000)
    )
    await asyncio.sleep(0.5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(2.5)
    assert not marker.exists()


@pytest.mark.asyncio
async def test_run_worker_without_on_line_keeps_stdout(tmp_path):
    argv = script(tmp_path, 'sys.stdout.write("plain output")\n')
    result = await run_worker(
        argv, stdin=b"", env=safe_child_env(), cwd=str(tmp_path), deadline_s=20.0, max_stdout_bytes=1000
    )
    assert result.exit_code == 0 and result.stdout == b"plain output"


def _recording_mkdtemp(monkeypatch, root) -> list[str]:
    """The sandbox's working directories, made under *root* and recorded."""
    import tempfile

    made: list[str] = []
    real = tempfile.mkdtemp

    def mkdtemp(*args, **kwargs):
        kwargs["dir"] = str(root)
        path = real(*args, **kwargs)
        made.append(path)
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    return made


@pytest.mark.asyncio
@pytest.mark.parametrize("threaded", [False, True])
async def test_cancelling_the_task_removes_the_working_directory(tmp_path, monkeypatch, threaded):
    # Stop and the Telegram /stop cancel the task awaiting a parse; the
    # killed child must have exited before the directory is removed
    # (Windows keeps a directory a process still has as its cwd).
    if threaded:
        async def no_subprocesses(*args, **kwargs):
            raise NotImplementedError

        monkeypatch.setattr(asyncio, "create_subprocess_exec", no_subprocesses)
    workdirs = tmp_path / "work"
    workdirs.mkdir()
    made = _recording_mkdtemp(monkeypatch, workdirs)
    argv = script(tmp_path, "time.sleep(30)\n")
    task = asyncio.ensure_future(SubprocessSandbox(worker_argv=argv).run(b"x", kind="pdf", preset=UPLOAD))
    for _ in range(50):
        await asyncio.sleep(0.1)
        if made:
            break
    await asyncio.sleep(0.5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(made) == 1 and not os.path.exists(made[0])
    assert os.listdir(workdirs) == []


def test_stale_working_directories_are_swept_and_nothing_else(tmp_path):
    import time

    from services.files import sandbox

    old = time.time() - sandbox.STALE_WORKDIR_S - 60
    stale = tmp_path / "crawler-file-stale"
    (stale / "inner").mkdir(parents=True)
    fresh = tmp_path / "crawler-file-fresh"
    fresh.mkdir()
    other = tmp_path / "someone-else"
    other.mkdir()
    a_file = tmp_path / "crawler-file-note.txt"
    a_file.write_text("x")
    for path in (stale, other, a_file):
        os.utime(path, (old, old))
    assert sandbox.sweep_stale_workdirs(str(tmp_path)) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["crawler-file-fresh", "crawler-file-note.txt", "someone-else"]
    assert sandbox.sweep_stale_workdirs(str(tmp_path / "missing")) == 0


@pytest.mark.asyncio
async def test_the_sweep_runs_at_most_once_an_hour(monkeypatch):
    from services.files import sandbox

    calls: list[object] = []
    monkeypatch.setattr(sandbox, "sweep_stale_workdirs", lambda *a, **k: calls.append(a) or 0)
    monkeypatch.setattr(sandbox, "_next_sweep", 0.0)
    await sandbox._sweep_when_due()
    await sandbox._sweep_when_due()
    assert len(calls) == 1
    monkeypatch.setattr(sandbox, "_next_sweep", 0.0)

    def broken(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(sandbox, "sweep_stale_workdirs", broken)
    await sandbox._sweep_when_due()  # never fails a parse
