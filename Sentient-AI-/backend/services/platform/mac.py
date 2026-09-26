"""macOS: the installed Google Chrome, Application Support, osascript, and
the login Keychain for the vault key (purchases spec §4).

(Mac implementation of spec §11.1; windows.py is its twin.) Secrets go
through ``/usr/bin/security`` as generic passwords under one service
name, so the owner can find and remove them in Keychain Access. The
tool is run as ``security -i`` and the whole command, the base64 value
included, is written to its stdin: an argument would sit in the process
table (``ps``, exec auditing) for as long as the tool runs, and ``man
security`` documents ``-i`` (commands from stdin) and warns against
putting a password in argv.
"""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from typing import Optional

import structlog

from services.platform.base import (
    APP_DIR_NAME,
    TIMEOUT_S,
    PlatformName,
    PosixPlatform,
    Runner,
    SecretStoreUnavailable,
    run_argv,
    secret_name,
)

logger = structlog.get_logger(__name__)

# Absolute, so a PATH entry ahead of /usr/bin can never stand in for it
# (the rule services/capabilities/macos.py already follows).
_OSASCRIPT = "/usr/bin/osascript"
_SECURITY = "/usr/bin/security"
CHROME_APP = Path("/Applications/Google Chrome.app")
# Process names as System Events reports them. Playwright >= 1.57 bundles
# Chrome for Testing, not a "Chromium.app", on macOS.
_CHROME_PROCESS = "Google Chrome"
_BUNDLED_PROCESS = "Google Chrome for Testing"
# The Keychain "service" every Crawler secret is filed under; the account
# is "<vault id>-<name>" so two installs sharing a login keychain (a
# reinstall with a fresh data dir) never read each other's key.
KEYCHAIN_SERVICE = "Crawler AI vault"
# `security` exit status for errSecItemNotFound: the one failure that
# means "nothing stored" rather than "could not look".
_NOT_FOUND = 44
# What a word on a `security -i` command line may contain. The service
# name and the base64 value are constants and the account is a uuid plus a
# validated secret name, so anything else is a bug; refusing it here keeps
# the interactive parser's quoting rules out of the picture entirely.
_LINE_WORD = re.compile(r"[A-Za-z0-9 ._+/=:-]{1,512}")
# What the owner reads when the login keychain will not answer (locked,
# a denied prompt, the tool missing); the exit code goes to the log only.
KEYCHAIN_UNAVAILABLE = "Crawler could not open this Mac's Keychain. Unlock the Mac and try again."


def _quoted(word: str) -> str:
    """*word* double-quoted for one ``security -i`` line; ValueError for
    anything outside ``_LINE_WORD`` (a quote, a newline, a control char)."""
    if not _LINE_WORD.fullmatch(word):
        raise ValueError("not a keychain command word")
    return f'"{word}"'


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

    # -- secrets (the vault key) --------------------------------------------

    def _account(self, name: str) -> str:
        return f"{self.vault_id()}-{secret_name(name)}"

    def _keychain(self, *words: str) -> tuple[int, str]:
        """Run one keychain command through ``security -i``: the words,
        quoted, as one line on stdin, so nothing but ``-i`` is ever an
        argument. The tool exits with that command's status (the line
        must end in a newline or it is never run)."""
        line = " ".join(_quoted(word) for word in words) + "\n"
        return self._run([_SECURITY, "-i"], TIMEOUT_S, stdin=line)

    def get_secret(self, name: str) -> Optional[bytes]:
        # `-w` prints only the password; with stderr merged, any other exit
        # code's output is the tool's error text. Not-found is the only
        # code read as "absent": a locked or denied keychain must not make
        # the caller mint a new key over the one it cannot read.
        account = self._account(name)
        code, out = self._keychain(
            "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"
        )
        if code == _NOT_FOUND:
            return None
        if code != 0:
            logger.warning("keychain_read_failed", code=code)
            raise SecretStoreUnavailable(KEYCHAIN_UNAVAILABLE)
        try:
            return base64.b64decode(out.strip(), validate=True)
        except (binascii.Error, ValueError):
            raise SecretStoreUnavailable("the Keychain item is not in Crawler's format")

    def set_secret(self, name: str, value: bytes) -> None:
        # -U updates an existing item in place instead of failing on it.
        # The value is the last word of the stdin line, never an argument.
        account = self._account(name)
        code, _ = self._keychain(
            "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", account,
            "-w", base64.b64encode(value).decode("ascii"),
        )
        if code != 0:
            logger.warning("keychain_write_failed", code=code)
            raise SecretStoreUnavailable(KEYCHAIN_UNAVAILABLE)

    def delete_secret(self, name: str) -> None:
        account = self._account(name)
        code, _ = self._keychain("delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account)
        if code not in (0, _NOT_FOUND):
            logger.warning("keychain_delete_failed", code=code)
            raise SecretStoreUnavailable(KEYCHAIN_UNAVAILABLE)
