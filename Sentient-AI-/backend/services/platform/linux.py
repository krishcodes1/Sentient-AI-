"""Native Linux (a developer's machine, not the container): XDG data dir,
Chrome from /opt when installed. Not first-class (spec §11.1 names Mac
and Windows); it exists so the container layer has a POSIX base.

No OS secret store is wired here (no Keychain, no DPAPI; the Secret
Service API varies by desktop), so the vault key has nowhere to live
and every secret call raises: services/vault falls back to its dev-file
provider in tests and is disabled otherwise (purchases spec §4)."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Optional

from services.platform.base import (
    APP_DIR_NAME,
    PlatformName,
    PosixPlatform,
    Runner,
    SecretStoreUnavailable,
    run_argv,
)

CHROME_BIN = Path("/opt/google/chrome/chrome")
_NO_STORE = "There is no OS secret store for the vault key on Linux."


class LinuxPlatform(PosixPlatform):
    name: PlatformName = "linux"
    LSOF = "/usr/bin/lsof"

    def __init__(
        self,
        *,
        runner: Runner = run_argv,
        home: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        chrome_bin: Path = CHROME_BIN,
    ) -> None:
        super().__init__(runner=runner, home=home, env=env)
        self._chrome_bin = chrome_bin

    def browser_channel(self) -> Optional[str]:
        return "chrome" if self._chrome_bin.is_file() else None

    def data_dir(self) -> Path:
        xdg = self._env.get("XDG_DATA_HOME")
        return (Path(xdg) if xdg else self._home / ".local" / "share") / APP_DIR_NAME

    def get_secret(self, name: str) -> Optional[bytes]:
        raise SecretStoreUnavailable(_NO_STORE)

    def set_secret(self, name: str, value: bytes) -> None:
        raise SecretStoreUnavailable(_NO_STORE)

    def delete_secret(self, name: str) -> None:
        raise SecretStoreUnavailable(_NO_STORE)
