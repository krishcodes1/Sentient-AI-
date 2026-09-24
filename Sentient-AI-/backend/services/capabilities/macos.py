"""Calls CoreGraphics through ctypes to check or request the macOS Screen
Recording permission and to open its Settings pane.

Why it exists: The screen capability's probe needs a prompt-free permission
check, and isolating the ctypes calls here lets every function return None off
macOS instead of crashing.

ctypes shims over CoreGraphics for the Screen Recording permission.

Every function returns None (or False) when not on macOS or when the
framework cannot be loaded, so callers degrade to "unknown" instead of
crashing on Linux CI or inside a container.
"""

from __future__ import annotations

import ctypes
import functools
import subprocess
import sys
from typing import Optional

SETTINGS_URL_PREFIX = "x-apple.systempreferences:"
SCREEN_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
)
_CORE_GRAPHICS = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
# Absolute, so a PATH entry ahead of /usr/bin can never stand in for it.
_OPEN = "/usr/bin/open"


@functools.lru_cache(maxsize=1)
def _core_graphics() -> Optional[ctypes.CDLL]:
    # Loaded once per process: the probe runs on every uncached report.
    if sys.platform != "darwin":
        return None
    try:
        return ctypes.cdll.LoadLibrary(_CORE_GRAPHICS)
    except OSError:
        return None


def _bool_function(name: str):
    cg = _core_graphics()
    if cg is None:
        return None
    try:
        fn = getattr(cg, name)
    except AttributeError:  # macOS < 10.15 has no TCC gate for this
        return None
    fn.argtypes = []
    fn.restype = ctypes.c_bool
    return fn


def screen_capture_preflight() -> Optional[bool]:
    """Whether this process may capture the screen (no prompt shown)."""
    fn = _bool_function("CGPreflightScreenCaptureAccess")
    return None if fn is None else bool(fn())


def screen_capture_request() -> Optional[bool]:
    """Ask macOS to show the Screen Recording prompt (once per binary)."""
    fn = _bool_function("CGRequestScreenCaptureAccess")
    return None if fn is None else bool(fn())


def open_settings(url: str = SCREEN_SETTINGS_URL) -> bool:
    """Open System Settings on the pane the user has to toggle.

    Only System Settings deep links are accepted (ValueError otherwise):
    ``open`` launches whatever a URL or path names, so this must never
    become a way to open anything else. True when ``open`` succeeded.
    """
    if not url.startswith(SETTINGS_URL_PREFIX):
        raise ValueError(f"not a System Settings URL: {url!r}")
    if sys.platform != "darwin":
        return False
    try:
        proc = subprocess.run([_OPEN, url], check=False, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0
