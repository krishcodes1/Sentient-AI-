"""Reports whether Crawler runs in a container, on which platform, and from which
real executable.

Why it exists: Availability rules and the macOS permission probe need these
facts, and the registry gathers them once per report instead of on every tool
call.

Where is Crawler running? Read once per report, never per tool call.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def in_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("CRAWLER_CONTAINER", "") == "1"


def platform_name() -> str:
    return sys.platform


# Room libproc needs for a path (PROC_PIDPATHINFO_MAXSIZE, 4 * MAXPATHLEN).
_PROC_PIDPATHINFO_MAXSIZE = 4 * 1024


def crawler_executable() -> str:
    """The program the OS attaches permission grants to, named the way the
    owner finds it in Privacy & Security: the process's real executable as
    the kernel reports it and, on macOS, the enclosing ``.app`` when there
    is one. python.org's framework Python starts ``bin/python3.x`` only as
    a launcher that re-executes ``Resources/Python.app``; the grant lands
    on that app (listed as "Python"), so naming the launcher sent owners to
    an entry that did nothing. Falls back to ``sys.executable`` resolved
    past the venv symlink when the kernel cannot be asked."""
    path = _process_executable() or os.path.realpath(sys.executable)
    return _app_bundle(path) if sys.platform == "darwin" else path


def _process_executable() -> str:
    """The running process's executable from the kernel (macOS ``proc_pidpath``),
    or "" where that is unavailable or fails, so the caller falls back."""
    if sys.platform != "darwin":
        return ""
    try:
        import ctypes
        import ctypes.util

        lib = ctypes.CDLL(ctypes.util.find_library("proc"))
        buf = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
        if lib.proc_pidpath(os.getpid(), buf, _PROC_PIDPATHINFO_MAXSIZE) <= 0:
            return ""
        return buf.value.decode("utf-8", "surrogateescape")
    except Exception:
        return ""


def _app_bundle(path: str) -> str:
    """``.../Python.app/Contents/MacOS/Python`` becomes ``.../Python.app``:
    the Privacy list shows the bundle, and the bundle is what the owner
    adds with the + button. A plain binary (Homebrew's Python) is returned
    as it is."""
    marker = ".app/Contents/MacOS/"
    at = path.find(marker)
    return path[: at + len(".app")] if at >= 0 else path
