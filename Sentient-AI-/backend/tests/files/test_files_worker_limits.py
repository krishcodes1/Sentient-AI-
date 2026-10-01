"""Tests for services/files/worker/limits.py: the POSIX rlimits (with a fake
resource module everywhere, and for real in a child on POSIX) and the Windows
job object (with a ctypes-level fake everywhere, and for real on Windows).

Why it exists: the worker's memory and CPU limits turn a hostile file into a
quick, contained failure; they are applied from inside the worker, so they
are tested both as calls and as their effect on a real child. The Windows
CI job runs this file too.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import textwrap

import pytest

from services.files.worker import limits

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeResource:
    RLIMIT_AS = 9
    RLIMIT_CPU = 0
    RLIMIT_FSIZE = 1
    RLIM_INFINITY = -1

    def __init__(self, refuse=()):
        self.set: dict[int, tuple[int, int]] = {}
        self._refuse = set(refuse)

    def getrlimit(self, which):
        return (-1, -1)

    def setrlimit(self, which, value):
        if which in self._refuse:
            raise ValueError("not allowed")
        self.set[which] = value


def test_posix_limits_set_memory_cpu_and_no_file_writes():
    fake = FakeResource()
    applied = limits.apply_posix_rlimits(20.0, fake)
    assert applied == ["memory", "cpu", "fsize"]
    assert fake.set[FakeResource.RLIMIT_AS] == (768 * 1024 * 1024,) * 2
    assert fake.set[FakeResource.RLIMIT_CPU] == (25, 25)
    assert fake.set[FakeResource.RLIMIT_FSIZE] == (0, 0)


def test_macos_skips_a_refused_memory_limit():
    fake = FakeResource(refuse={FakeResource.RLIMIT_AS})
    assert limits.apply_posix_rlimits(10.0, fake, darwin=True) == ["cpu", "fsize"]


def test_a_lower_hard_limit_is_kept():
    class Low(FakeResource):
        def getrlimit(self, which):
            return (100, 100)

    fake = Low()
    limits.apply_posix_rlimits(1000.0, fake)
    assert fake.set[FakeResource.RLIMIT_CPU] == (100, 100)


class FakeKernel32:
    """ctypes-level stand-in: records the job calls and reads the limits."""

    def __init__(self, fail: str = "") -> None:
        self.calls: list[str] = []
        self.info = None
        self._fail = fail

    def CreateJobObjectW(self, attributes, name):
        self.calls.append("create")
        return 0 if self._fail == "create" else 1234

    def SetInformationJobObject(self, job, info_class, pointer, size):
        self.calls.append("set")
        assert info_class == limits.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS
        assert size == ctypes.sizeof(limits.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
        # Copied now: the structure behind the pointer lives only for the call.
        self.info = limits.JOBOBJECT_EXTENDED_LIMIT_INFORMATION.from_buffer_copy(
            ctypes.cast(pointer, ctypes.POINTER(limits.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)).contents
        )
        return 0 if self._fail == "set" else 1

    def GetCurrentProcess(self):
        return 99

    def AssignProcessToJobObject(self, job, process):
        self.calls.append("assign")
        assert (job, process) == (1234, 99)
        return 1


def test_windows_job_object_limits_with_a_fake_kernel32():
    fake = FakeKernel32()
    applied = limits.apply_windows_job(20.0, kernel32=fake)
    assert fake.calls == ["create", "set", "assign"]
    assert "job_memory" in applied and "job_active_process" in applied
    info = fake.info
    assert info.ProcessMemoryLimit == 768 * 1024 * 1024
    basic = info.BasicLimitInformation
    assert basic.ActiveProcessLimit == 1
    assert basic.LimitFlags & limits.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert basic.LimitFlags & limits.JOB_OBJECT_LIMIT_PROCESS_MEMORY
    assert basic.LimitFlags & limits.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    assert basic.PerProcessUserTimeLimit == 25 * 10_000_000


@pytest.mark.parametrize("fail", ["create", "set"])
def test_a_refused_job_object_applies_nothing(fail):
    assert limits.apply_windows_job(5.0, kernel32=FakeKernel32(fail=fail)) == []


def test_apply_limits_never_raises(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("no")

    monkeypatch.setattr(limits, "apply_posix_rlimits", boom)
    monkeypatch.setattr(limits, "apply_windows_job", boom)
    assert limits.apply_limits(5.0, platform="linux") == []
    assert limits.apply_limits(5.0, platform="win32") == []


def _child(code: str) -> subprocess.CompletedProcess:
    body = f"import sys\nsys.path.insert(0, {BACKEND!r})\n" + textwrap.dedent(code)
    return subprocess.run(  # noqa: S603 - a fixed test script
        [sys.executable, "-I", "-c", body], capture_output=True, text=True, timeout=60
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimits")
def test_posix_rlimits_are_set_in_a_real_child():
    result = _child(
        """
        import resource
        from services.files.worker.limits import apply_limits
        apply_limits(10.0)
        print(resource.getrlimit(resource.RLIMIT_CPU)[0], resource.getrlimit(resource.RLIMIT_FSIZE)[0])
        """
    )
    assert result.returncode == 0, result.stderr
    cpu, fsize = result.stdout.split()
    assert int(cpu) <= 15 and int(fsize) == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows job objects")
def test_a_real_windows_job_object_stops_the_worker_starting_children():
    result = _child(
        """
        import subprocess
        from services.files.worker.limits import apply_limits
        applied = apply_limits(10.0)
        try:
            subprocess.run([sys.executable, "-c", "pass"], timeout=20)
            outcome = "started"
        except OSError:
            outcome = "refused"
        print(",".join(applied), outcome)
        """
    )
    assert result.returncode == 0, result.stderr
    applied, outcome = result.stdout.split()
    assert "job_active_process" in applied
    assert outcome == "refused"
