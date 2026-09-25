"""macOS: the installed Google Chrome, Application Support, osascript.

(Mac implementation of spec §11.1; windows.py is its twin.)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from services.platform.base import (
    APP_DIR_NAME,
    TIMEOUT_S,
    PlatformName,
    PosixPlatform,
    Runner,
    run_argv,
)

# Absolute, so a PATH entry ahead of /usr/bin can never stand in for it
# (the rule services/capabilities/macos.py already follows).
_OSASCRIPT = "/usr/bin/osascript"
CHROME_APP = Path("/Applications/Google Chrome.app")
# Process names as System Events reports them. Playwright >= 1.57 bundles
# Chrome for Testing, not a "Chromium.app", on macOS.
_CHROME_PROCESS = "Google Chrome"
_BUNDLED_PROCESS = "Google Chrome for Testing"


class MacPlatform(PosixPlatform):
    name: PlatformName = "mac"
    LSOF = "/usr/sbin/lsof"

    def __init__(
        self,
        *,
        runner: Runner = run_argv,
        home: Optional[Path] = None,
        chrome_app: Path = CHROME_APP,
    ) -> None:
        super().__init__(runner=runner, home=home)
        self._chrome_app = chrome_app

    def browser_channel(self) -> Optional[str]:
        # channel="chrome" makes Playwright launch /Applications/Google
        # Chrome.app; without it the bundled Chromium (None) is used.
        return "chrome" if self._chrome_app.is_dir() else None

    def data_dir(self) -> Path:
        return self._home / "Library" / "Application Support" / APP_DIR_NAME

    def bring_to_front(self, *, pid: Optional[int] = None, title: Optional[str] = None) -> bool:
        # By pid when the session manager knows the browser process;
        # otherwise the running browser process by name. Always through
        # System Events on an existing process: `tell application X to
        # activate` would *launch* the owner's own Chrome (their personal
        # profile) if Crawler's window were gone. ``title`` is part of the
        # Protocol for Windows; AppleScript window-by-title is fragile and
        # a handoff does not need it. Nothing model-supplied reaches the
        # script: pid is forced through int() and the name is a constant.
        if pid is not None:
            target = f"unix id is {int(pid)}"
        else:
            name = _CHROME_PROCESS if self.browser_channel() == "chrome" else _BUNDLED_PROCESS
            target = f'name is "{name}"'
        script = (
            'tell application "System Events" to set frontmost of '
            f"(first process whose {target}) to true"
        )
        code, _ = self._run([_OSASCRIPT, "-e", script], TIMEOUT_S)
        return code == 0
