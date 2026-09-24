"""Where is Crawler running? Read once per report, never per tool call."""

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
