"""ctypes shims over CoreGraphics for the Screen Recording permission.

Every function returns None (or False) when not on macOS or when the
framework cannot be loaded, so callers degrade to "unknown" instead of
crashing on Linux CI or inside a container.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from typing import Optional

SCREEN_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
)
_CORE_GRAPHICS = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"


def _core_graphics() -> Optional[ctypes.CDLL]:
    if sys.platform != "darwin":
        return None
    try:
        return ctypes.cdll.LoadLibrary(_CORE_GRAPHICS)
    except OSError:
        return None


def screen_capture_preflight() -> Optional[bool]:
    """Whether this process may capture the screen (no prompt shown)."""
    cg = _core_graphics()
    if cg is None:
        return None
    try:
        fn = cg.CGPreflightScreenCaptureAccess
    except AttributeError:  # macOS < 10.15 has no TCC gate for this
        return None
    fn.restype = ctypes.c_bool
    return bool(fn())


def screen_capture_request() -> Optional[bool]:
    """Ask macOS to show the Screen Recording prompt (once per binary)."""
    cg = _core_graphics()
    if cg is None:
        return None
    try:
        fn = cg.CGRequestScreenCaptureAccess
    except AttributeError:
        return None
    fn.restype = ctypes.c_bool
    return bool(fn())


def open_settings(url: str = SCREEN_SETTINGS_URL) -> bool:
    """Open System Settings on the pane the user has to toggle."""
    if sys.platform != "darwin":
        return False
    try:
        subprocess.run(["open", url], check=False, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
