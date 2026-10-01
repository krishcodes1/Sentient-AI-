"""Applies the parser worker's own resource limits, from inside the worker,
before it reads the file.

Why it exists: a hostile document can at worst make a pure-Python parser (or
Pillow) use a lot of memory or CPU; these limits turn that into a quick,
contained failure of one short-lived process.

- POSIX: RLIMIT_AS 768 MiB, RLIMIT_CPU of the deadline plus 5 s, and
  RLIMIT_FSIZE 0 (the worker writes no file; CPython ignores SIGXFSZ, so a
  write fails instead of killing it). macOS is best effort: its kernel
  often refuses RLIMIT_AS, which is then skipped.
- Windows: a Job Object made with ctypes, with a 768 MiB per-process
  memory limit, one active process (no children) and kill-on-close, which
  the process assigns to itself.

This module is the one deliberate exception to "services/platform holds all
OS branches" (docs/CODE-MAP.md): the worker must not import the app, and
services.platform pulls in structlog and the capabilities package.

Stdlib only (ctypes, resource).
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any, Optional

MEMORY_BYTES = 768 * 1024 * 1024
CPU_GRACE_S = 5

# Windows job object constants (winnt.h).
JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9

# The job handle stays referenced for the life of the process: closing it
# would kill the process (kill-on-close).
_job_handle: Any = None


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def windows_limit_info(deadline_s: float) -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION:
    """The job limits the worker runs under on Windows."""
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    basic = info.BasicLimitInformation
    basic.LimitFlags = (
        JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_TIME
    )
    basic.ActiveProcessLimit = 1
    # 100-nanosecond units of user-mode CPU time.
    basic.PerProcessUserTimeLimit = int((deadline_s + CPU_GRACE_S) * 10_000_000)
    info.ProcessMemoryLimit = MEMORY_BYTES
    return info


def apply_windows_job(deadline_s: float, kernel32: Any = None) -> list[str]:
    """Put this process in a new job object with the worker's limits.
    Returns the names of what was applied ([] when the OS refused)."""
    global _job_handle
    if kernel32 is None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return []
    info = windows_limit_info(deadline_s)
    if not kernel32.SetInformationJobObject(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        return []
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        return []
    _job_handle = job
    return ["job_memory", "job_active_process", "job_kill_on_close", "job_cpu_time"]


def _lower(resource_module: Any, which: int, value: int) -> bool:
    """Set soft and hard limit *which* to *value*, or to the current hard
    limit when that is lower. False when the OS refuses."""
    try:
        _soft, hard = resource_module.getrlimit(which)
        infinity = getattr(resource_module, "RLIM_INFINITY", -1)
        target = value if hard in (infinity, -1) or hard > value else hard
        resource_module.setrlimit(which, (target, target))
        return True
    except (ValueError, OSError):
        return False


def apply_posix_rlimits(
    deadline_s: float, resource_module: Any = None, *, darwin: bool = False
) -> list[str]:
    """Lower this process's rlimits. Returns the names applied."""
    if resource_module is None:
        import resource as resource_module  # POSIX only
    applied: list[str] = []
    if _lower(resource_module, resource_module.RLIMIT_AS, MEMORY_BYTES):
        applied.append("memory")
    elif not darwin:
        # Linux always supports RLIMIT_AS; failing to set it is odd enough
        # to leave a trace in the worker's stderr tail, never in logs.
        sys.stderr.write("rlimit_as_refused\n")
    if _lower(resource_module, resource_module.RLIMIT_CPU, int(deadline_s) + CPU_GRACE_S):
        applied.append("cpu")
    if _lower(resource_module, resource_module.RLIMIT_FSIZE, 0):
        applied.append("fsize")
    return applied


def apply_limits(deadline_s: float, *, platform: Optional[str] = None) -> list[str]:
    """Apply the worker's limits for this platform (best effort: a refusal
    by the OS leaves that limit off, and the parent's deadline and output
    caps still hold)."""
    platform = platform or sys.platform
    try:
        if platform == "win32":
            return apply_windows_job(deadline_s)
        return apply_posix_rlimits(deadline_s, darwin=platform == "darwin")
    except Exception:  # noqa: BLE001 - a missing API must not stop the parse
        return []
