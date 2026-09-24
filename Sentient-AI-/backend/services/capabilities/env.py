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


def crawler_executable() -> str:
    """The binary running Crawler, resolved past symlinks. macOS attaches
    permission grants (Screen Recording) to the real binary, not to the
    venv symlink sys.executable usually is, so this is the one the owner
    must toggle — and the one every probe and message names."""
    return os.path.realpath(sys.executable)
