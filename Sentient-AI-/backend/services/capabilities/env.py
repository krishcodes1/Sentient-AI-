"""Where is Crawler running? Read once per report, never per tool call."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def in_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("CRAWLER_CONTAINER", "") == "1"


def platform_name() -> str:
    return sys.platform
