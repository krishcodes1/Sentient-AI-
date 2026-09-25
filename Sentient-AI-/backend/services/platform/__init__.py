"""``current()`` picks the Platform once per process (spec §11.1).

This package is the only place that may branch on the OS for browser
control. ``CRAWLER_PLATFORM`` overrides detection so the Mac suite runs
on Linux CI and the Windows suite on the owner's Mac; the container
marker (``services.capabilities.env.in_container``) wins over the host OS
because a Linux container must never try to open a window.
"""

from __future__ import annotations

import functools
import os
import sys
from typing import Callable

import structlog

from services.capabilities.env import in_container
from services.platform.base import Platform, PlatformName
from services.platform.container import ContainerPlatform
from services.platform.linux import LinuxPlatform
from services.platform.mac import MacPlatform
from services.platform.windows import WindowsPlatform

__all__ = ["OVERRIDE_ENV", "Platform", "PlatformName", "current", "detect_name"]

logger = structlog.get_logger(__name__)

OVERRIDE_ENV = "CRAWLER_PLATFORM"
_FACTORIES: dict[str, Callable[[], Platform]] = {
    "mac": MacPlatform,
    "windows": WindowsPlatform,
    "linux": LinuxPlatform,
    "container": ContainerPlatform,
}


def detect_name() -> PlatformName:
    """The override when set (a typo is an error, not a silent fallback),
    else the container marker, else the host OS."""
    override = os.environ.get(OVERRIDE_ENV, "").strip().lower()
    if override:
        if override not in _FACTORIES:
            raise ValueError(
                f"{OVERRIDE_ENV} must be one of {sorted(_FACTORIES)}, not {override!r}"
            )
        return override  # type: ignore[return-value]
    if in_container():
        return "container"
    if sys.platform == "darwin":
        return "mac"
    if sys.platform.startswith("win"):
        return "windows"
    return "linux"


@functools.lru_cache(maxsize=1)
def current() -> Platform:
    """The process's Platform, built on first use and kept. Tests call
    ``current.cache_clear()`` after changing CRAWLER_PLATFORM. The log
    line here is the "chosen at startup" record: main.wire_services makes
    the first call."""
    name = detect_name()
    platform = _FACTORIES[name]()
    logger.info("platform_selected", platform=name, browser_channel=platform.browser_channel())
    return platform
