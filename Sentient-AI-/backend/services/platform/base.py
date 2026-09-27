"""The one place that may differ per OS (spec §11.1, contracts §1).

Everything that needs a browser channel, a private profile directory, the
app-data root, a window brought forward or a "who owns this port"
diagnostic asks ``services.platform.current()`` and calls the Platform it
gets. Nothing else in the backend branches on the OS for browser control,
so every OS-specific behaviour has exactly one Mac, one Windows and one
container implementation, and one test for each that runs on any OS.

The vault's key custody (purchases spec §4) goes through the same seam:
``get_secret``/``set_secret``/``delete_secret`` reach the OS secret store
(Keychain on Mac, DPAPI on Windows) and raise ``SecretStoreUnavailable``
where there is none (Linux, the container), so services/vault never
learns which OS it is on. ``vault_id`` is the install's stable identity
for those secrets: a uuid in ``<data_dir>/vault-id``.

Shared helpers live here so mac.py, linux.py and windows.py stay small.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import uuid
from pathlib import Path
from typing import Literal, Mapping, Optional, Protocol

PlatformName = Literal["mac", "windows", "linux", "container"]

# argv (+ optional stdin text) -> (returncode, combined output). Every
# platform takes one so tests assert *which argv would run*, and what it
# would be fed, without running it (as SystemToolkit does).
class Runner(Protocol):
    def __call__(
        self, argv: list[str], timeout_s: float, stdin: Optional[str] = None
    ) -> tuple[int, str]: ...

APP_DIR_NAME = "Crawler AI"
PROFILES_DIR_NAME = "browser-profiles"
VAULT_ID_FILE = "vault-id"
# One deadline for every OS probe: these are diagnostics and window
# nudges, never something a tool result should wait longer for.
TIMEOUT_S = 10.0

_USER_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
# Secret names become a Keychain account suffix and a file name; the
# vault uses constants, so anything else is a bug, not a request.
_SECRET_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class SecretStoreUnavailable(Exception):
    """This platform has no OS secret store the vault key may live in, or
    the store refused (locked Keychain, DPAPI failure). Callers fail
    closed: a key that cannot be read is never replaced by a fresh one,
    because that would silently orphan every blob sealed under it."""


class Platform(Protocol):
    name: PlatformName

    def browser_channel(self) -> Optional[str]:
        """"chrome" | "msedge" | None (None = Playwright's bundled Chromium)."""

    def profile_dir(self, user_id: str) -> Path:
        """The persistent browser profile for *user_id*, created private."""

    def data_dir(self) -> Path:
        """App-data root (spec §11.1). Not created here."""

    def bring_to_front(self, *, pid: Optional[int] = None, title: Optional[str] = None) -> bool:
        """Raise the browser window for a handoff. False when it could not."""

    def port_owner(self, port: int) -> Optional[str]:
        """"pid name" of the process listening on *port*, for diagnostics."""

    def get_secret(self, name: str) -> Optional[bytes]:
        """The bytes stored under *name* in the OS secret store; None when
        nothing is stored. Raises SecretStoreUnavailable when the store
        cannot answer (never None: absent and unreadable must differ)."""

    def set_secret(self, name: str, value: bytes) -> None:
        """Store *value* under *name*, replacing what was there."""

    def delete_secret(self, name: str) -> None:
        """Remove *name*; a name that is not stored is not an error."""

    def vault_id(self) -> str:
        """This install's stable id for its secrets: a uuid kept in
        ``<data_dir>/vault-id`` (0600), created on first use."""


def secret_name(name: str) -> str:
    """*name* when it is a plain identifier; ValueError otherwise, before
    it can reach an argv or a path."""
    if not _SECRET_NAME.fullmatch(name):
        raise ValueError(f"not a secret name: {name!r}")
    return name


def read_or_create_id(path: Path) -> str:
    """The uuid in *path*, or a fresh one written there (0600) on first use.

    Never overwrites: an existing file that does not hold a uuid is an
    OSError, because replacing it would change the Keychain account the
    vault key lives under and orphan the key. A symlink is refused for
    the same reason make_private_dir refuses one. Two processes racing
    to create the file both end up with the one that won (O_EXCL)."""
    if path.is_symlink():
        raise OSError(f"refusing a symlinked id file: {path}")
    existing = _read_id(path)
    if existing is not None:
        return existing
    path.parent.mkdir(parents=True, exist_ok=True)
    fresh = str(uuid.uuid4())
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        winner = _read_id(path)
        if winner is None:
            raise OSError(f"id file appeared but holds no id: {path}")
        return winner
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(fresh + "\n")
    return fresh


def _read_id(path: Path) -> Optional[str]:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    if not text:
        return None
    try:
        return str(uuid.UUID(text))
    except ValueError:
        raise OSError(f"id file does not hold a uuid: {path}")


def run_argv(
    argv: list[str], timeout_s: float, stdin: Optional[str] = None
) -> tuple[int, str]:
    """Run one fixed argv: no shell, stdout+stderr merged, stdin closed
    unless *stdin* is given, in which case that text is fed to it.

    *stdin* exists for what must never be an argument: the vault key
    goes to ``security -i`` this way (mac.py), because argv is readable
    in the process table while the tool runs. Failing to start (binary
    missing) or to finish (timeout) reads as ``(-1, "")``: platform probes
    must degrade to "unknown", never raise into a tool result. Nothing
    model-supplied ever reaches *argv* or *stdin*.
    """
    try:
        proc = subprocess.run(
            argv,
            # subprocess.run refuses a stdin together with input; with
            # input the pipe is its own.
            stdin=subprocess.DEVNULL if stdin is None else None,
            input=None if stdin is None else stdin.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_s,
            check=False,
            # A backend started without a console (the desktop app) would
            # otherwise flash a window for every icacls/netstat probe.
            # The constant only exists on Windows; 0 is "no flags".
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    return proc.returncode, proc.stdout.decode("utf-8", errors="replace")


def profile_path(data_dir: Path, user_id: str) -> Path:
    """``<data_dir>/browser-profiles/<user_id>``. User ids are UUIDs, so
    anything else (a slash, a dot, a space) is a path attack, not an id."""
    if not _USER_ID.fullmatch(user_id):
        raise ValueError(f"not a user id: {user_id!r}")
    return data_dir / PROFILES_DIR_NAME / user_id


def make_private_dir(path: Path) -> Path:
    """Create *path* (and parents) and make it 0700 — also when it already
    existed with looser bits, because the profile holds live cookies.

    A symlink in the leaf's place is refused, not followed: chmod and the
    browser would both land wherever it points (a shared scratch dir makes
    that plantable). Fails closed with OSError."""
    if path.is_symlink():
        raise OSError(f"refusing a symlinked profile directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(f"not a directory: {path}")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and info.st_uid != getuid():
        raise OSError(f"profile directory is owned by another user: {path}")
    path.chmod(stat.S_IRWXU)
    return path


def parse_lsof(output: str) -> Optional[str]:
    """``lsof -F pc`` prints ``p<pid>`` then ``c<command>`` per process;
    the first pair becomes "pid command". None when nothing listens."""
    pid: Optional[str] = None
    for line in output.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = line[1:]
        elif line.startswith("c") and pid is not None:
            return f"{pid} {line[1:]}"
    return None


class PosixPlatform:
    """What Mac and Linux share: 0700 profile dirs and lsof. Subclasses set
    ``name`` and ``LSOF`` and implement ``data_dir``/``browser_channel``."""

    name: PlatformName
    LSOF: str

    def __init__(
        self,
        *,
        runner: Runner = run_argv,
        home: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._run = runner
        self._home = home or Path.home()
        self._env: Mapping[str, str] = os.environ if env is None else env

    def data_dir(self) -> Path:  # pragma: no cover - every subclass overrides
        raise NotImplementedError

    def profile_dir(self, user_id: str) -> Path:
        return make_private_dir(profile_path(self.data_dir(), user_id))

    def vault_id(self) -> str:
        return read_or_create_id(self.data_dir() / VAULT_ID_FILE)

    def bring_to_front(self, *, pid: Optional[int] = None, title: Optional[str] = None) -> bool:
        # No portable way to raise an X11/Wayland window, and the container
        # has no window at all: the handoff falls back to the Telegram
        # screenshot (spec §11.1 "n/a"). Mac overrides this.
        return False

    def port_owner(self, port: int) -> Optional[str]:
        # lsof exits 1 when nothing matches, so the output, not the code,
        # decides; a missing binary is (-1, "") from the runner → None.
        _, out = self._run(
            [self.LSOF, "-nP", f"-iTCP:{int(port)}", "-sTCP:LISTEN", "-Fpc"], TIMEOUT_S
        )
        return parse_lsof(out)
