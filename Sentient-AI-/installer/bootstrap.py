#!/usr/bin/env python3
"""Runs the double-click installer: a loopback-only HTTP server that serves
installer/page.html and the small JSON API its buttons call to check Docker, write the
two secret keys into backend/.env, run ``docker compose up --build`` and open the app.

Why it exists: a new owner should reach a running Crawler AI without typing a command,
so the two launchers only locate a Python 3.9+ and exec this one stdlib-only file, which
keeps every platform difference, the token/Origin checks and the compose build state
machine in one place; installer/tests import it directly.

Crawler AI bootstrap installer.

Double-clicking ``Install Crawler AI.command`` (macOS) or ``Install Crawler
AI.bat`` (Windows) runs this script. It serves one local page
(``installer/page.html``) on 127.0.0.1 and a small JSON API that the page
drives with buttons, so a new owner never types a command:

    GET  /api/check          preflight: Docker, Compose v2, ports, disk, keys
    POST /api/keys           write backend/.env with SECRET_KEY/ENCRYPTION_KEY
    POST /api/build          docker compose up --build -d, then wait for health
    GET  /api/build/status   incremental build output + state
    POST /api/open           open http://localhost:3000
    POST /api/start-docker   open Docker Desktop (macOS, Windows)
    POST /api/quit           stop this server

Standard library only; runs on the Python 3.9 that ships with Apple's Command
Line Tools and on any python.org / Microsoft Store Python 3.9+ on Windows.
Platform differences live in small helpers (current_os, build_env,
Preflight.port_holder, _chmod_private, default_start_docker). Security model (details in installer/README.md): loopback-only
bind, a one-time token on every API call plus an Origin/Referer check against
this server's own origin, and key values are never logged or returned.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import csv
import errno
import hmac
import http.client
import io
import itertools
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Callable, Iterable, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from typing import Any, NamedTuple
from urllib.parse import parse_qs, urlsplit

LOGGER_NAME = "crawler_installer"
log = logging.getLogger(LOGGER_NAME)
compose_log = logging.getLogger(LOGGER_NAME + ".compose")

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT = 3999
MAX_PORT = 4010
APP_URL = "http://localhost:3000"
HEALTH_URL = "http://127.0.0.1:8000/api/health"
FRONTEND_URL = "http://127.0.0.1:3000/"
DOCKER_DESKTOP_URL = "https://www.docker.com/products/docker-desktop/"

KEY_NAMES = ("SECRET_KEY", "ENCRYPTION_KEY")
# Mirrors _PLACEHOLDER_MARKERS in backend/core/config.py, which refuses to
# boot with any of these in SECRET_KEY.
PLACEHOLDER_MARKERS = ("replace_me", "changeme", "change-me", "your-secret")
SECRET_KEY_MIN = 32
SECRET_KEY_MAX = 512
# Characters that python-dotenv / Compose's env_file parser treat specially
# (quoting, escapes, ${VAR} interpolation, inline comments). Refusing them in a
# custom SECRET_KEY keeps the value byte-identical once the backend reads it.
ENV_UNSAFE_CHARS = frozenset("\"'`\\$#")

# (port, what uses it): the host ports docker/docker-compose.yml publishes.
APP_PORTS: tuple[tuple[int, str], ...] = (
    (3000, "web app"),
    (8000, "API"),
    (5432, "database"),
    (6379, "Redis"),
)
MIN_FREE_DISK_GB = 10.0

MAX_BODY_BYTES = 16 * 1024
MAX_DRAIN_BYTES = 1024 * 1024
MAX_LOG_LINES = 2000
MAX_LINE_CHARS = 4000
MAX_LINES_PER_STATUS = 500
CHECK_TIMEOUT_S = 10.0
HEALTH_POLL_S = 3.0
HEALTH_TIMEOUT_S = 20 * 60.0
FRONTEND_WAIT_S = 90.0
BUILD_TIMEOUT_S = 2 * 60 * 60.0

# Where Docker Desktop and Homebrew put binaries on macOS/Linux. A .command
# launched from Finder usually has these on PATH already; this covers the
# per-user Docker install (~/.docker/bin) and shells with a trimmed PATH.
POSIX_EXTRA_PATH_DIRS = (
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "~/.docker/bin",
    "/Applications/Docker.app/Contents/Resources/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
)
# Docker Desktop for Windows' CLI folders, relative to %ProgramFiles% /
# %ProgramData%. Its installer adds them to PATH, but only for new sessions.
WINDOWS_EXTRA_PATH_DIRS = (
    ("PROGRAMFILES", "Docker\\Docker\\resources\\bin"),
    ("PROGRAMDATA", "DockerDesktop\\version-bin"),
)
# The only variables that reach docker subprocesses besides PATH/HOME. No
# COMPOSE_FILE (it would silently build a different stack) and nothing that
# could carry an API key from the user's shell.
ENV_ALLOWLIST = (
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "DOCKER_DEFAULT_PLATFORM",
    "DOCKER_BUILDKIT",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)
# Windows programs (Docker's CLI included) misbehave without these: Winsock
# needs SYSTEMROOT, the Docker CLI finds its config via USERPROFILE.
WINDOWS_ENV_ALLOWLIST = (
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMPUTERNAME",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)
# os.open() on Windows defaults to text mode, which would rewrite \n as \r\n.
_O_BINARY = getattr(os, "O_BINARY", 0)


def current_os(platform: str | None = None) -> str:
    """'mac', 'windows' or 'linux' (any other POSIX system counts as linux)."""
    name = sys.platform if platform is None else platform
    if name == "darwin":
        return "mac"
    if name.startswith("win"):
        return "windows"
    return "linux"


def launcher_name(os_name: str | None = None) -> str:
    """The file a user double-clicks to start this installer."""
    return "Install Crawler AI.bat" if (os_name or current_os()) == "windows" else "Install Crawler AI.command"


# ── Paths ────────────────────────────────────────────────────────────────────


class InstallerPaths:
    """Every file the installer touches, relative to the project folder
    (the one holding backend/, docker/, frontend/ and installer/)."""

    def __init__(self, project_dir: Path) -> None:
        self.project_dir = Path(project_dir)
        self.installer_dir = self.project_dir / "installer"
        self.backend_dir = self.project_dir / "backend"
        self.docker_dir = self.project_dir / "docker"
        self.env_file = self.backend_dir / ".env"
        self.env_example = self.backend_dir / ".env.example"
        self.compose_file = self.docker_dir / "docker-compose.yml"
        self.page = self.installer_dir / "page.html"
        self.log_file = self.installer_dir / "bootstrap.log"

    @classmethod
    def default(cls) -> InstallerPaths:
        return cls(Path(__file__).resolve().parent.parent)


# ── Environment for subprocesses ─────────────────────────────────────────────


def _env_get(source: Any, name: str) -> str | None:
    """Case-insensitive lookup (Windows environment names ignore case)."""
    if name in source:
        return source[name]
    upper = name.upper()
    for key, value in source.items():
        if key.upper() == upper:
            return value
    return None


def extra_path_dirs(os_name: str, source: Any) -> list[str]:
    if os_name == "windows":
        dirs = []
        for var, sub in WINDOWS_EXTRA_PATH_DIRS:
            base = _env_get(source, var)
            if base:
                dirs.append(str(PureWindowsPath(base) / sub))
        return dirs
    return [str(Path(d).expanduser()) for d in POSIX_EXTRA_PATH_DIRS]


def augmented_path(
    base: str | None = None, os_name: str | None = None, source: Any = None
) -> str:
    os_name = os_name or current_os()
    source = os.environ if source is None else source
    sep = ";" if os_name == "windows" else ":"
    current = (_env_get(source, "PATH") or "") if base is None else base
    parts = [p for p in current.split(sep) if p]
    for extra in extra_path_dirs(os_name, source):
        if extra not in parts:
            parts.append(extra)
    return sep.join(parts)


def build_env(source: Any = None, os_name: str | None = None) -> dict[str, str]:
    """Minimal environment for docker/lsof/netstat: PATH, HOME/USERPROFILE,
    Docker and proxy variables, plus the handful Windows itself needs."""
    os_name = os_name or current_os()
    src = os.environ if source is None else source
    if os_name == "windows":
        allowed = {name.upper() for name in ENV_ALLOWLIST + WINDOWS_ENV_ALLOWLIST}
        env = {key: value for key, value in src.items() if key.upper() in allowed}
    else:
        env = {key: src[key] for key in ENV_ALLOWLIST if key in src}
        env.setdefault("HOME", str(Path.home()))
    env["PATH"] = augmented_path(_env_get(src, "PATH") or "", os_name, src)
    # Plain, colourless output reads well in the page's log panel.
    env["COMPOSE_ANSI"] = "never"
    env["BUILDKIT_PROGRESS"] = "plain"
    return env


class CmdResult(NamedTuple):
    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None


def run_cmd(
    argv: Sequence[str],
    timeout: float,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> CmdResult:
    """Run argv (no shell) with a timeout; never raises."""
    try:
        proc = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env,
            cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError:
        return CmdResult(False, None, "", "", "not_found")
    except subprocess.TimeoutExpired:
        return CmdResult(False, None, "", "", "timeout")
    except OSError as exc:
        return CmdResult(False, None, "", "", exc.strerror or exc.__class__.__name__)
    return CmdResult(proc.returncode == 0, proc.returncode, proc.stdout or "", proc.stderr or "", None)


# ── Private files ────────────────────────────────────────────────────────────


def _chmod_private(fd_or_path: Any, os_name: str | None = None) -> bool:
    """Make a file owner-only (0600). Returns whether that was applied.

    Windows has no POSIX modes (os.chmod only toggles read-only), so there the
    file keeps the ACL it inherits from its folder (normally the user's
    profile, which is already private to them); hardening it with explicit
    ACLs is a follow-up. Never raises.
    """
    if (os_name or current_os()) == "windows":
        return False
    try:
        if isinstance(fd_or_path, int):
            os.fchmod(fd_or_path, 0o600)
        else:
            os.chmod(fd_or_path, 0o600)
    except (OSError, AttributeError, NotImplementedError):
        return False
    return True


def write_private_file(path: Path, data: str) -> None:
    """Atomically replace ``path`` with ``data``; the result is mode 0600."""
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
    _chmod_private(fd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape", newline="") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    _chmod_private(path)


def create_private_file(path: Path, data: bytes) -> None:
    """Create a new file (never overwrite) with mode 0600."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
    _chmod_private(fd)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def ensure_private_log(path: Path, rotate_bytes: int = 5 * 1024 * 1024) -> None:
    """Create the log file 0600 (and keep it 0600); start fresh past 5 MB."""
    try:
        if path.exists() and path.stat().st_size > rotate_bytes:
            os.replace(str(path), str(path) + ".1")
    except OSError:
        pass
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_BINARY, 0o600)
    _chmod_private(fd)
    os.close(fd)


# ── Keys ─────────────────────────────────────────────────────────────────────

_B64_RE = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_KEY_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<export>export[ \t]+)?"
    r"(?P<name>SECRET_KEY|ENCRYPTION_KEY)[ \t]*=(?P<value>.*)$"
)


def secret_key_problem(value: object) -> str | None:
    """Why ``value`` can't be SECRET_KEY, or None. Never echoes the value."""
    if not isinstance(value, str) or not value:
        return "Enter a SECRET_KEY."
    if any(ch.isspace() for ch in value):
        return "SECRET_KEY must not contain spaces or line breaks."
    if len(value) < SECRET_KEY_MIN:
        return f"SECRET_KEY must be at least {SECRET_KEY_MIN} characters."
    if len(value) > SECRET_KEY_MAX:
        return f"SECRET_KEY must be at most {SECRET_KEY_MAX} characters."
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value):
        return "SECRET_KEY must use plain letters, digits and symbols (ASCII)."
    if any(ch in ENV_UNSAFE_CHARS for ch in value):
        return (
            "SECRET_KEY must not contain quotes, backticks, backslashes, $ or # "
            "(.env files treat them specially)."
        )
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return "SECRET_KEY still looks like a placeholder; use a random value."
    if len(set(value)) < 8:
        return "SECRET_KEY is too repetitive; use a random value."
    return None


def encryption_key_problem(value: object) -> str | None:
    """Why ``value`` can't be ENCRYPTION_KEY (base64 of exactly 32 bytes), or None."""
    if not isinstance(value, str) or not value:
        return "Enter an ENCRYPTION_KEY."
    if any(ch.isspace() for ch in value):
        return "ENCRYPTION_KEY must not contain spaces or line breaks."
    if len(value) > 128 or not _B64_RE.fullmatch(value):
        return (
            "ENCRYPTION_KEY must be base64 text (A-Z, a-z, 0-9, + / or - _, "
            "with = padding at the end)."
        )
    try:
        raw = base64.b64decode(value.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError):
        return "ENCRYPTION_KEY isn't valid base64; check the = padding at the end."
    if len(raw) != 32:
        return f"ENCRYPTION_KEY must decode to exactly 32 bytes (this one decodes to {len(raw)})."
    return None


def generate_keys() -> tuple[str, str]:
    """Same recipe as the one-liner in backend/.env.example."""
    return secrets.token_urlsafe(48), base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _env_value(raw: str) -> str:
    value = raw.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end > 0 else value[1:]
    comment = value.find(" #")
    return value[:comment].rstrip() if comment >= 0 else value


def _looks_real(name: str, value: str) -> bool:
    if name == "SECRET_KEY":
        stripped = value.strip()
        lowered = stripped.lower()
        return len(stripped) >= SECRET_KEY_MIN and not any(m in lowered for m in PLACEHOLDER_MARKERS)
    return encryption_key_problem(value) is None


def env_key_status(env_path: Path) -> dict[str, bool]:
    """Whether SECRET_KEY / ENCRYPTION_KEY in ``env_path`` look real.

    Only the two key lines are inspected and their values never leave this
    function: the result is one boolean per key.
    """
    status = dict.fromkeys(KEY_NAMES, False)
    try:
        with open(str(env_path), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                match = _KEY_LINE_RE.match(line.rstrip("\r\n"))
                if match:  # last assignment wins, as in python-dotenv
                    name = match.group("name")
                    status[name] = _looks_real(name, _env_value(match.group("value")))
    except OSError:
        pass
    return status


def replace_keys(text: str, values: dict[str, str]) -> str:
    """Replace the ``NAME=`` lines for each key in ``values``; keep every other
    line byte-for-byte. Keys with no line are appended at the end."""
    out: list[str] = []
    seen = set()
    for part in text.split("\n"):
        body = part.removesuffix("\r")
        ending = "\r" if part.endswith("\r") else ""
        match = _KEY_LINE_RE.match(body)
        if match and match.group("name") in values:
            name = match.group("name")
            out.append(
                "{}{}{}={}{}".format(
                    match.group("indent"), match.group("export") or "", name, values[name], ending
                )
            )
            seen.add(name)
        else:
            out.append(part)
    result = "\n".join(out)
    missing = [name for name in values if name not in seen]
    if missing:
        if result and not result.endswith("\n"):
            result += "\n"
        result += "".join(f"{name}={values[name]}\n" for name in missing)
    return result


class KeyWriter:
    """Creates or updates backend/.env with SECRET_KEY and ENCRYPTION_KEY."""

    def __init__(
        self, env_path: Path, example_path: Path, clock: Callable[[], float] = time.time
    ) -> None:
        self.env_path = Path(env_path)
        self.example_path = Path(example_path)
        self._clock = clock
        self._lock = threading.Lock()

    def write(
        self,
        mode: str,
        secret_key: str | None = None,
        encryption_key: str | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        if mode == "generate":
            secret_key, encryption_key = generate_keys()
        elif mode == "custom":
            errors = {}
            problem = secret_key_problem(secret_key)
            if problem:
                errors["secret_key"] = problem
            problem = encryption_key_problem(encryption_key)
            if problem:
                errors["encryption_key"] = problem
            if errors:
                log.info("custom keys rejected (%s)", ", ".join(sorted(errors)))
                return {"ok": False, "reason": "invalid", "errors": errors}
        else:
            return {
                "ok": False,
                "reason": "invalid",
                "errors": {"mode": "Choose 'generate' or 'custom'."},
            }
        assert secret_key is not None and encryption_key is not None

        with self._lock:
            exists = self.env_path.exists()
            if exists and not overwrite:
                log.info("backend/.env already exists; not replacing keys without overwrite")
                return {"ok": False, "reason": "exists"}
            backup_name = None
            try:
                if exists:
                    original = self.env_path.read_bytes()
                    backup_name = self._backup(original)
                    base = original.decode("utf-8", errors="surrogateescape")
                elif self.example_path.is_file():
                    base = self.example_path.read_text(encoding="utf-8", errors="surrogateescape")
                else:
                    log.warning("backend/.env.example is missing; cannot create backend/.env")
                    return {"ok": False, "reason": "no_example"}
                updated = replace_keys(
                    base, {"SECRET_KEY": secret_key, "ENCRYPTION_KEY": encryption_key}
                )
                write_private_file(self.env_path, updated)
            except OSError as exc:
                log.error(
                    "could not write backend/.env: %s", exc.strerror or exc.__class__.__name__
                )
                return {"ok": False, "reason": "write_failed"}

        log.info(
            "wrote backend/.env (mode=%s, replaced_existing=%s, backup=%s)",
            mode,
            exists,
            backup_name or "none",
        )
        result: dict[str, Any] = {"ok": True, "wrote": True, "mode": mode}
        if backup_name:
            result["backup"] = "backend/" + backup_name
        return result

    def _backup(self, data: bytes) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(self._clock()))
        for attempt in range(100):
            suffix = "" if attempt == 0 else f"-{attempt}"
            name = f".env.bak-{stamp}{suffix}"
            try:
                create_private_file(self.env_path.with_name(name), data)
                return name
            except FileExistsError:
                continue
        raise OSError(errno.EEXIST, "too many backups this second")


# ── Preflight ────────────────────────────────────────────────────────────────


_ADDR_IN_USE = {errno.EADDRINUSE, 10048}  # 10048 = WSAEADDRINUSE


def port_is_free(port: int, os_name: str | None = None) -> bool:
    """True when nothing listens on ``port`` and Docker could publish it."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return False
    except OSError:
        pass
    windows = (os_name or current_os()) == "windows"
    candidates = [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET, "127.0.0.1")]
    if socket.has_ipv6:
        candidates += [(socket.AF_INET6, "::"), (socket.AF_INET6, "::1")]
    for family, addr in candidates:
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue
        with sock:
            # POSIX: SO_REUSEADDR so a TIME_WAIT leftover isn't mistaken for a
            # listener (binding the exact address a listener holds still
            # fails). On Windows the same option lets a bind *steal* a busy
            # port, so there it stays off.
            if not windows:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except (OSError, AttributeError):
                    pass
            try:
                sock.bind((addr, port))
            except OSError as exc:
                if exc.errno in _ADDR_IN_USE or getattr(exc, "winerror", None) in _ADDR_IN_USE:
                    return False
    return True


# lsof truncates COMMAND to 9 characters, so Docker Desktop's
# com.docker.backend shows up as "com.docke"; on Windows it's
# com.docker.backend.exe (tasklist doesn't truncate).
_DOCKER_PROCESSES = ("com.docke", "vpnkit", "docker")


def _holder_label(command: str, pid: str) -> tuple[str, bool]:
    if command.lower().startswith(_DOCKER_PROCESSES):
        return f"Docker Desktop (pid {pid})", True
    return f"{command} (pid {pid})", False


def _holders(entries: Iterable[tuple[str, str]]) -> dict[str, Any] | None:
    labels: list[str] = []
    docker = False
    for command, pid in entries:
        label, is_docker = _holder_label(command, pid)
        docker = docker or is_docker
        if label not in labels:
            labels.append(label)
    if not labels:
        return None
    return {"holder": ", ".join(labels[:3]), "docker": docker}


def parse_lsof(output: str) -> dict[str, Any] | None:
    """``lsof -nP -iTCP:<port> -sTCP:LISTEN`` output (macOS/Linux) -> who holds the port."""
    entries = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            entries.append((parts[0].replace("\\x20", " ")[:40], parts[1]))
    return _holders(entries)


def parse_netstat(output: str, port: int) -> list[str]:
    """PIDs listening on ``port`` in ``netstat -ano`` output (Windows).

    State names are localised ("LISTENING", "ABHÖREN", ...), so a listener is
    recognised by its foreign address instead: 0.0.0.0:0 / [::]:0.
    """
    pids: list[str] = []
    suffix = f":{int(port)}"
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        local, foreign, pid = parts[1], parts[2], parts[-1]
        listening = local.endswith(suffix) and foreign in ("0.0.0.0:0", "[::]:0")
        if listening and pid.isdigit() and pid != "0" and pid not in pids:
            pids.append(pid)
    return pids


def parse_tasklist(output: str) -> str | None:
    """Image name from ``tasklist /FI "PID eq N" /FO CSV /NH`` output (Windows)."""
    for row in csv.reader(io.StringIO(output)):
        if len(row) >= 2 and row[1].strip().isdigit():
            return row[0].strip()[:60]
    return None


def disk_free_gb(path: Path) -> float:
    try:
        return round(shutil.disk_usage(str(path)).free / (1024**3), 1)
    except OSError:
        return -1.0


# The installer always builds under this Compose project name. Without an
# explicit name Compose derives one from the folder ("docker"), so a second
# checkout would silently take over an existing stack's containers and
# volumes; a fixed name keeps every install's data in its own volumes.
COMPOSE_PROJECT = "crawler-ai"


def _compose_project_name(compose_file: Path) -> str:
    return COMPOSE_PROJECT


def _same_file(a: str, b: Path) -> bool:
    try:
        left = Path(a).expanduser().resolve()
        right = Path(b).resolve()
    except (OSError, ValueError, RuntimeError):
        return False
    # normcase: Windows paths compare case-insensitively.
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def find_stack(ls_json: str, compose_file: Path) -> dict[str, Any]:
    """Parse ``docker compose ls --all --format json``.

    ``existing_stack``: a project built from this folder's compose file
    (any name — a stack started by hand is called "docker" after the
    folder; the installer's own is ``COMPOSE_PROJECT``).
    ``stack_conflict``: a *different* folder's project using the installer's
    project name; building here would recreate its containers.
    """
    result: dict[str, Any] = {
        "existing_stack": False,
        "existing_stack_status": None,
        "existing_stack_name": None,
        "stack_conflict": None,
    }
    try:
        projects = json.loads(ls_json or "[]")
    except ValueError:
        return result
    if not isinstance(projects, list):
        return result
    our_name = _compose_project_name(compose_file)
    for project in projects:
        if not isinstance(project, dict):
            continue
        name = str(project.get("Name", ""))[:80]
        status = str(project.get("Status", ""))[:80]
        files = [f.strip() for f in str(project.get("ConfigFiles", "")).split(",") if f.strip()]
        if any(_same_file(f, compose_file) for f in files):
            result["existing_stack"] = True
            result["existing_stack_status"] = status
            result["existing_stack_name"] = name
        elif name.lower() == our_name:
            folder = str(Path(files[0]).parent.parent) if files else ""
            result["stack_conflict"] = {"name": name, "status": status, "folder": folder[:300]}
    return result


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


_DOCKER_INSTALL_FIX: dict[str, tuple[str, tuple[str, str]]] = {
    "mac": (
        (
            "Docker Desktop isn't installed. Download Docker Desktop for Mac (pick Apple chip or "
            "Intel chip), drag it into Applications, open it once and accept its terms, then "
            "click Re-check."
        ),
        (DOCKER_DESKTOP_URL, "Download Docker Desktop for Mac"),
    ),
    "windows": (
        (
            "Docker Desktop isn't installed. Download Docker Desktop for Windows and run it; keep "
            "\"Use WSL 2\" ticked (Docker Desktop needs WSL 2) and restart if it asks. Open "
            "Docker Desktop once and accept its terms, then click Re-check."
        ),
        (DOCKER_DESKTOP_URL, "Download Docker Desktop for Windows"),
    ),
    "linux": (
        (
            "Docker isn't installed. Install Docker Desktop for Linux (or Docker Engine with the "
            "Compose plugin), then click Re-check."
        ),
        (DOCKER_DESKTOP_URL, "Get Docker Desktop"),
    ),
}
_DOCKER_START_FIX = {
    "mac": (
        "Docker Desktop is installed but not running. Open Docker Desktop and wait until it says "
        "Running (the whale in the menu bar stops moving), then click Re-check."
    ),
    "windows": (
        "Docker Desktop is installed but not running. Open it from the Start menu and wait until "
        "it says Engine running. If it asks to install or update WSL 2, follow its prompt and "
        "restart. Then click Re-check."
    ),
    "linux": (
        "Docker is installed but not running. Start Docker Desktop (or the docker service), then "
        "click Re-check."
    ),
}


def _port_fix_text(port: dict[str, Any], stack_conflict: bool) -> str:
    where = f"Port {port['port']} ({port['service']})"
    consequence = f"or Crawler AI's {port['service']} can't start."
    holder = port["holder"]
    if port["docker"] and holder and "," not in holder:
        # Docker Desktop itself isn't the problem; one of its containers is.
        likely = " (probably the other Crawler AI copy below)" if stack_conflict else ""
        return (
            f"{where} is already taken by a Docker container{likely}. Stop that container in "
            f"Docker Desktop before building, {consequence}"
        )
    if holder:
        them = "them" if "," in holder else "it"
        return f"{where} is in use by {holder}. Quit {them} before building, {consequence}"
    return f"{where} is in use by another app. Quit it before building, {consequence}"


def _fix(
    fix_id: str, severity: str, text: str, link: tuple[str, str] | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {"id": fix_id, "severity": severity, "text": text}
    if link:
        entry["link"] = {"href": link[0], "label": link[1]}
    return entry


class Preflight:
    """Read-only checks: what's installed, running, free and configured."""

    def __init__(
        self,
        paths: InstallerPaths,
        *,
        env: dict[str, str] | None = None,
        run: Callable[[Sequence[str], float], CmdResult] | None = None,
        which: Callable[[str], str | None] | None = None,
        port_free: Callable[[int], bool] | None = None,
        disk_free: Callable[[], float] | None = None,
        os_name: str | None = None,
    ) -> None:
        self.paths = paths
        self.os_name = os_name or current_os()
        self.env = build_env(os_name=self.os_name) if env is None else env
        self._run = run or (lambda argv, timeout: run_cmd(argv, timeout, env=self.env))
        self._which = which or (lambda name: shutil.which(name, path=self.env.get("PATH")))
        self._port_free = port_free or (lambda port: port_is_free(port, self.os_name))
        self._disk_free = disk_free or (lambda: disk_free_gb(self.paths.project_dir))

    def port_holder(self, port: int) -> dict[str, Any] | None:
        """Who listens on ``port``: lsof on macOS/Linux, netstat + tasklist on Windows."""
        if self.os_name == "windows":
            return self._windows_port_holder(port)
        lsof = self._which("lsof")
        if not lsof and Path("/usr/sbin/lsof").exists():
            lsof = "/usr/sbin/lsof"
        if not lsof:
            return None
        res = self._run([lsof, "-nP", f"-iTCP:{int(port)}", "-sTCP:LISTEN"], 5.0)
        return parse_lsof(res.stdout) if res.stdout else None

    def _windows_port_holder(self, port: int) -> dict[str, Any] | None:
        netstat = self._which("netstat")
        if not netstat:
            return None
        pids = parse_netstat(self._run([netstat, "-ano"], CHECK_TIMEOUT_S).stdout, port)
        tasklist = self._which("tasklist")
        entries = []
        for pid in pids[:3]:
            name = None
            if tasklist:
                res = self._run([tasklist, "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], CHECK_TIMEOUT_S)
                name = parse_tasklist(res.stdout)
            entries.append((name or "a program", pid))
        return _holders(entries)

    def check(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "os": self.os_name,
            "docker_installed": False,
            "docker_version": None,
            "docker_running": False,
            "compose_v2": False,
            "compose_version": None,
            "ports": [],
            "disk_free_gb": self._disk_free(),
            "env_exists": self.paths.env_file.exists(),
            "env_keys_set": False,
            "existing_stack": False,
            "existing_stack_status": None,
            "stack_conflict": None,
        }
        docker = self._which("docker")
        if docker:
            version = self._run([docker, "--version"], CHECK_TIMEOUT_S)
            report["docker_installed"] = version.ok
            report["docker_version"] = _first_line(version.stdout) if version.ok else None
        if report["docker_installed"]:
            info = self._run([docker, "info", "--format", "{{.ServerVersion}}"], CHECK_TIMEOUT_S)
            report["docker_running"] = info.ok and bool(info.stdout.strip())
            compose = self._run([docker, "compose", "version", "--short"], CHECK_TIMEOUT_S)
            report["compose_v2"] = compose.ok
            report["compose_version"] = _first_line(compose.stdout) if compose.ok else None
        if report["docker_running"] and report["compose_v2"]:
            listing = self._run(
                [docker, "compose", "ls", "--all", "--format", "json"], CHECK_TIMEOUT_S
            )
            if listing.ok:
                report.update(find_stack(listing.stdout, self.paths.compose_file))

        stack_status = str(report["existing_stack_status"] or "")
        stack_running = report["existing_stack"] and stack_status.startswith("running")
        for port, service in APP_PORTS:
            entry: dict[str, Any] = {
                "port": port,
                "service": service,
                "free": True,
                "holder": None,
                "docker": False,
                "ours": False,
            }
            if not self._port_free(port):
                entry["free"] = False
                holder = self.port_holder(port)
                if holder:
                    entry["holder"] = holder["holder"]
                    entry["docker"] = bool(holder["docker"])
                    entry["ours"] = bool(holder["docker"] and stack_running)
            report["ports"].append(entry)

        if report["env_exists"]:
            report["env_keys_set"] = all(env_key_status(self.paths.env_file).values())
        report["ready"] = bool(report["docker_running"] and report["compose_v2"])
        report["fixes"] = self._fixes(report, self.os_name)
        return report

    @staticmethod
    def _fixes(r: dict[str, Any], os_name: str = "mac") -> list[dict[str, Any]]:
        fixes: list[dict[str, Any]] = []
        if not r["docker_installed"]:
            fixes.append(_fix("docker_installed", "error", *_DOCKER_INSTALL_FIX[os_name]))
        elif not r["docker_running"]:
            fixes.append(_fix("docker_running", "error", _DOCKER_START_FIX[os_name]))
        if r["docker_installed"] and not r["compose_v2"]:
            fixes.append(_fix(
                "compose_v2", "error",
                "Docker Compose (v2 or newer) is missing. Update Docker Desktop to the latest "
                "version (it checks for updates in its Settings), then click Re-check.",
                (DOCKER_DESKTOP_URL, "Get the latest Docker Desktop"),
            ))
        for port in r["ports"]:
            if port["free"] or port["ours"]:
                continue
            fixes.append(_fix("ports", "warning", _port_fix_text(port, bool(r["stack_conflict"]))))
        if 0 <= r["disk_free_gb"] < MIN_FREE_DISK_GB:
            fixes.append(_fix(
                "disk", "warning",
                "Only {} GB free. The first build downloads about 3.6 GB and needs roughly {:.0f} GB "
                "of room; free some space first.".format(r["disk_free_gb"], MIN_FREE_DISK_GB),
            ))
        if r["env_keys_set"]:
            fixes.append(_fix("env", "info", "Keys already set in backend/.env. You can skip to Build."))
        elif r["env_exists"]:
            fixes.append(_fix(
                "env", "info",
                "backend/.env exists but its SECRET_KEY / ENCRYPTION_KEY aren't set yet. Step 2 "
                "fills them in and keeps a backup.",
            ))
        if r["existing_stack"]:
            stack_name = r.get("existing_stack_name") or ""
            if stack_name and stack_name != COMPOSE_PROJECT:
                fixes.append(_fix(
                    "existing_stack", "warning",
                    "A Crawler AI stack from this folder is already {} under the Compose project "
                    "'{}' (started by hand, not by this installer). Building here creates a separate "
                    "'{}' stack with its own database, which cannot start while the other one holds "
                    "the ports. Stop the other one first (cd docker && docker compose stop) or just "
                    "open http://localhost:3000.".format(
                        r["existing_stack_status"] or "present", stack_name, COMPOSE_PROJECT
                    ),
                ))
            else:
                fixes.append(_fix(
                    "existing_stack", "info",
                    "Crawler AI is already set up from this folder ({}). Build & start updates it; your "
                    "data is kept.".format(r["existing_stack_status"] or "stopped"),
                ))
        if r["stack_conflict"]:
            conflict = r["stack_conflict"]
            where = " ({})".format(conflict["folder"]) if conflict.get("folder") else ""
            fixes.append(_fix(
                "stack_conflict", "warning",
                "Another copy of Crawler AI{} is set up in Docker as \"{}\" ({}). Building here "
                "would replace its containers. Stop it in Docker Desktop first, or run the "
                "installer from that copy.".format(where, conflict["name"], conflict["status"] or "stopped"),
            ))
        return fixes


# ── Build ────────────────────────────────────────────────────────────────────

IDLE, BUILDING, STARTING, HEALTHY, FAILED = "idle", "building", "starting", "healthy", "failed"

_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|[\x00-\x08\x0b-\x1f\x7f]"
)
_CONTAINER_RE = re.compile(
    r"\bContainer\s+\S+\s+(?:Creat|Recreat|Start|Running|Waiting|Healthy)", re.IGNORECASE
)
_DIAGNOSES = (
    (
        re.compile(
            r"Cannot connect to the Docker daemon|Is the docker daemon running|"
            r"docker daemon is not running|dockerDesktopLinuxEngine|docker_engine.*cannot find",
            re.IGNORECASE,
        ),
        "Docker Desktop isn't running. Open it, wait for Running, then click Retry.",
    ),
    (
        re.compile(
            r"port is already allocated|address already in use|ports are not available",
            re.IGNORECASE,
        ),
        (
            "A port Crawler AI needs (3000, 8000, 5432 or 6379) is taken by another app. "
            "Quit it, then click Retry."
        ),
    ),
    (
        re.compile(r"no space left on device", re.IGNORECASE),
        (
            "Docker ran out of disk space. Free some in Docker Desktop (Settings > Resources, "
            "or Troubleshoot > Clean / Purge data), then click Retry."
        ),
    ),
    (
        re.compile(r"env file .*not found|\.env: no such file", re.IGNORECASE),
        "backend/.env is missing. Go back to step 2 and save the keys.",
    ),
    (
        re.compile(
            r"TLS handshake timeout|i/o timeout|temporary failure in name resolution|no such host|"
            r"connection reset by peer|unexpected EOF",
            re.IGNORECASE,
        ),
        "Docker couldn't finish downloading. Check your internet connection, then click Retry.",
    ),
)


def diagnose(lines: Iterable[str]) -> str | None:
    """A plain-English hint for the most common compose failures."""
    tail = list(lines)[-200:]
    for line in reversed(tail):
        for pattern, hint in _DIAGNOSES:
            if pattern.search(line):
                return hint
    return None


_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_ok(url: str, timeout: float = 5.0) -> bool:
    """True when ``url`` answers 2xx. Bypasses any proxy (it's our own loopback)."""
    try:
        with _NO_PROXY_OPENER.open(url, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
        return False


def detached_child_kwargs(os_name: str | None = None) -> dict[str, Any]:
    """Keep Ctrl+C in the installer's window away from docker compose; the
    installer stops compose itself on the way out (BuildRunner.stop)."""
    if (os_name or current_os()) == "windows":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
    return {"start_new_session": True}


def compose_up_argv(env: dict[str, str]) -> list[str] | None:
    docker = shutil.which("docker", path=env.get("PATH"))
    return [docker, "compose", "-p", COMPOSE_PROJECT, "up", "--build", "-d"] if docker else None


def compose_logs_argv(env: dict[str, str]) -> list[str] | None:
    docker = shutil.which("docker", path=env.get("PATH"))
    return [docker, "compose", "-p", COMPOSE_PROJECT, "logs", "--no-color", "--tail", "60", "backend"] if docker else None


class BuildRunner:
    """Runs ``docker compose up --build -d``, then waits for the backend.

    States: idle -> building -> starting -> healthy | failed. A failed run may
    be retried; a running or healthy one may not (the API answers 409).
    """

    def __init__(
        self,
        docker_dir: Path,
        *,
        argv: Sequence[str] | None = None,
        logs_argv: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        probe: Callable[[str], bool] | None = None,
        health_url: str = HEALTH_URL,
        frontend_url: str | None = FRONTEND_URL,
        poll_interval: float = HEALTH_POLL_S,
        health_timeout: float = HEALTH_TIMEOUT_S,
        frontend_wait: float = FRONTEND_WAIT_S,
        build_timeout: float = BUILD_TIMEOUT_S,
        max_lines: int = MAX_LOG_LINES,
    ) -> None:
        self.docker_dir = Path(docker_dir)
        self.env = build_env() if env is None else env
        self._argv = list(argv) if argv is not None else None
        self._logs_argv = list(logs_argv) if logs_argv is not None else None
        self._real_docker = argv is None
        self._probe = probe
        self.health_url = health_url
        self.frontend_url = frontend_url
        self.poll_interval = poll_interval
        self.health_timeout = health_timeout
        self.frontend_wait = frontend_wait
        self.build_timeout = build_timeout

        self._lock = threading.Lock()
        self._lines: collections.deque = collections.deque(maxlen=max_lines)
        self._total = 0
        self.state = IDLE
        self.phase: str | None = None
        self.error: str | None = None
        self._started_at: float | None = None
        self._finished_at: float | None = None
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen | None = None
        self._stop = threading.Event()
        self._timed_out = False
        self._attempts = 0

    # -- public API -----------------------------------------------------------

    def start(self) -> bool:
        with self._lock:
            if self.state in (BUILDING, STARTING, HEALTHY):
                return False
            self._attempts += 1
            retry = self.state == FAILED
            self.state = BUILDING
            self.phase = "building"
            self.error = None
            self._timed_out = False
            self._started_at = time.monotonic()
            self._finished_at = None
            self._stop.clear()
        if retry:
            self._append(f"----- retry #{self._attempts - 1} -----")
        log.info("build started (attempt %d)", self._attempts)
        self._thread = threading.Thread(target=self._run, name="compose-build", daemon=True)
        self._thread.start()
        return True

    def status(self, since: int = 0) -> dict[str, Any]:
        with self._lock:
            first = self._total - len(self._lines)
            start = min(max(since, first), self._total)
            offset = start - first
            lines = list(itertools.islice(self._lines, offset, offset + MAX_LINES_PER_STATUS))
            result: dict[str, Any] = {
                "state": self.state,
                "phase": self.phase,
                "lines": lines,
                "next": start + len(lines),
                "elapsed_s": self._elapsed(),
            }
            if self.error:
                result["error"] = self.error
        return result

    def tail(self, count: int = 30) -> list[str]:
        with self._lock:
            return list(self._lines)[-count:]

    def wait(self, timeout: float | None = None) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def stop(self, timeout: float = 10.0) -> None:
        """Called on shutdown: stop waiting and terminate a running compose."""
        self._stop.set()
        proc = self._proc
        if proc is not None and proc.poll() is None:
            log.info("stopping docker compose because the installer is closing")
            try:
                proc.terminate()
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    # -- internals ------------------------------------------------------------

    def _elapsed(self) -> int:
        if self._started_at is None:
            return 0
        end = self._finished_at if self._finished_at is not None else time.monotonic()
        return int(end - self._started_at)

    def _append(self, raw: str, from_compose: bool = True) -> None:
        text = raw.rstrip("\n")
        if "\r" in text:  # progress redraws: keep the final state of the line
            text = next((seg for seg in reversed(text.split("\r")) if seg.strip()), "")
        text = _ANSI_RE.sub("", text.replace("\n", " "))[:MAX_LINE_CHARS]
        with self._lock:
            self._lines.append(text)
            self._total += 1
            if from_compose and self.state == BUILDING and _CONTAINER_RE.search(text):
                self.phase = "starting_containers"
        compose_log.info("%s", text)

    def _set(self, state: str, phase: str | None) -> None:
        with self._lock:
            self.state = state
            self.phase = phase

    def _finish(self, state: str, error: str | None = None) -> None:
        with self._lock:
            self.state = state
            self.phase = None
            self.error = error
            self._finished_at = time.monotonic()
        if error:
            log.warning("build %s: %s", state, error)
        else:
            log.info("build %s after %ss", state, self._elapsed())

    def _check(self, url: str) -> bool:
        probe = self._probe or http_ok  # looked up at call time so tests can patch http_ok
        try:
            return bool(probe(url))
        except Exception:  # noqa: BLE001 - a probe must never kill the runner
            return False

    def _run(self) -> None:
        try:
            self._run_inner()
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("build crashed")
            self._finish(
                FAILED, f"The installer hit an unexpected error ({exc.__class__.__name__})."
            )

    def _run_inner(self) -> None:
        argv = self._argv if self._argv is not None else compose_up_argv(self.env)
        if not argv:
            self._finish(
                FAILED,
                "Docker isn't installed or couldn't be found. Install Docker Desktop, then click Retry.",
            )
            return
        echo = (
            f"$ docker compose -p {COMPOSE_PROJECT} up --build -d"
            if self._real_docker
            else "$ " + " ".join(argv)
        )
        self._append(echo, from_compose=False)
        try:
            proc = subprocess.Popen(
                list(argv),
                cwd=str(self.docker_dir),
                env=self.env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                **detached_child_kwargs(),
            )
        except OSError as exc:
            reason = exc.strerror or exc.__class__.__name__
            self._finish(FAILED, f"Couldn't start Docker Compose ({reason}).")
            return
        self._proc = proc
        watchdog = threading.Timer(self.build_timeout, self._kill_for_timeout, args=(proc,))
        watchdog.daemon = True
        watchdog.start()
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                self._append(raw)
            try:
                returncode = proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
                returncode = proc.wait(timeout=10)
        finally:
            watchdog.cancel()
            if proc.stdout is not None:
                proc.stdout.close()
        log.info("docker compose exited with code %s", returncode)

        if self._stop.is_set():
            self._finish(FAILED, "The installer was closed before the build finished.")
            return
        if self._timed_out:
            self._finish(
                FAILED,
                f"The build took longer than {int(self.build_timeout // 60)} minutes and was stopped. Check your internet "
                "connection, then click Retry.",
            )
            return
        if returncode != 0:
            hint = diagnose(self.tail(200))
            message = f"Docker Compose stopped with exit code {returncode}."
            self._finish(FAILED, message + (" " + hint if hint else " The log above says why."))
            return

        self._set(STARTING, "waiting_backend")
        self._append(f"Waiting for the backend at {self.health_url} ...")
        deadline = time.monotonic() + self.health_timeout
        while not self._check(self.health_url):
            if self._stop.is_set():
                self._finish(FAILED, "The installer was closed before the backend came up.")
                return
            if time.monotonic() >= deadline:
                self._append_backend_logs()
                self._finish(
                    FAILED,
                    f"The containers started, but the backend didn't answer within {int(self.health_timeout // 60)} minutes. "
                    "The backend's last log lines are above.",
                )
                return
            self._stop.wait(self.poll_interval)
        self._append("Backend is healthy.")

        if self.frontend_url:
            self._set(STARTING, "waiting_frontend")
            deadline = time.monotonic() + self.frontend_wait
            frontend_up = self._check(self.frontend_url)
            while not frontend_up and time.monotonic() < deadline and not self._stop.is_set():
                self._stop.wait(min(self.poll_interval, 2.0))
                frontend_up = self._check(self.frontend_url)
            if frontend_up:
                self._append("Web app is answering on port 3000.")
            else:
                self._append(
                    "The web app on port 3000 is still starting; give it a minute if the page is blank."
                )
        self._finish(HEALTHY)

    def _kill_for_timeout(self, proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            self._timed_out = True
            log.warning("build exceeded %ss; killing docker compose", int(self.build_timeout))
            try:
                proc.kill()
            except OSError:
                pass

    def _append_backend_logs(self) -> None:
        if self._logs_argv is not None:
            argv: list[str] | None = self._logs_argv
        elif self._real_docker:
            argv = compose_logs_argv(self.env)
        else:
            argv = None
        if not argv:
            return
        self._append("----- last backend log lines -----")
        result = run_cmd(argv, 30.0, env=self.env, cwd=self.docker_dir)
        for line in (result.stdout + result.stderr).splitlines()[-60:]:
            self._append(line)


# ── HTTP ─────────────────────────────────────────────────────────────────────


def docker_desktop_exe(source: Any = None) -> Path | None:
    """Docker Desktop's executable on Windows, if installed in the usual place."""
    base = _env_get(os.environ if source is None else source, "PROGRAMFILES") or "C:\\Program Files"
    exe = Path(base) / "Docker" / "Docker" / "Docker Desktop.exe"
    return exe if exe.is_file() else None


def default_start_docker(os_name: str | None = None) -> bool:
    """Launch Docker Desktop (it keeps running on its own). Never raises."""
    os_name = os_name or current_os()
    if os_name == "mac":
        return run_cmd(["open", "-a", "Docker"], 15.0).ok
    if os_name == "windows":
        exe = docker_desktop_exe()
        startfile = getattr(os, "startfile", None)
        if exe is None or startfile is None:
            return False
        try:
            startfile(str(exe))  # returns immediately, like double-clicking it
        except OSError:
            return False
        return True
    return False


class InstallerApp:
    """Everything the request handler needs; one per server."""

    def __init__(
        self,
        paths: InstallerPaths,
        token: str,
        *,
        preflight: Preflight | None = None,
        key_writer: KeyWriter | None = None,
        runner: BuildRunner | None = None,
        open_url: Callable[[str], Any] | None = None,
        start_docker: Callable[[], bool] | None = None,
    ) -> None:
        self.paths = paths
        self.token = token
        self.preflight = preflight or Preflight(paths)
        self.key_writer = key_writer or KeyWriter(paths.env_file, paths.env_example)
        self.runner = runner or BuildRunner(paths.docker_dir)
        self.open_url = open_url or webbrowser.open
        self.start_docker = start_docker or default_start_docker
        self.port: int | None = None
        self.server: BootstrapServer | None = None
        self._shutdown_requested = threading.Event()

    @property
    def allowed_hosts(self) -> tuple[str, ...]:
        return (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    @property
    def allowed_origins(self) -> tuple[str, ...]:
        return tuple("http://" + host for host in self.allowed_hosts)

    def request_shutdown(self, delay: float = 0.2) -> None:
        if self._shutdown_requested.is_set() or self.server is None:
            return
        self._shutdown_requested.set()
        server = self.server

        def _stop() -> None:
            time.sleep(delay)
            server.shutdown()

        threading.Thread(target=_stop, name="installer-shutdown", daemon=True).start()


class _HttpError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


class BootstrapServer(ThreadingHTTPServer):
    daemon_threads = True
    # No SO_REUSEADDR: if anything already holds the port, move to the next.
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], app: InstallerApp) -> None:
        self.app = app
        super().__init__(address, Handler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Closed tabs cause broken pipes; keep the Terminal window quiet.
        # socketserver calls this from inside its except block.
        log.debug("connection error", exc_info=True)  # noqa: LOG014


class Handler(BaseHTTPRequestHandler):
    server_version = "CrawlerAIInstaller"
    sys_version = ""
    timeout = 30
    server: BootstrapServer
    _body: bytes = b""

    # -- logging: never log the query string (the page URL carries the token)

    def log_request(self, code: Any = "-", size: Any = "-") -> None:
        log.debug("%s %s -> %s", self.command, self.path.split("?", 1)[0][:200], code)

    def log_error(self, format: str, *args: Any) -> None:
        log.debug("http error %s", args[0] if args and isinstance(args[0], int) else "")

    def log_message(self, format: str, *args: Any) -> None:
        pass

    # -- verbs

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._send_json(405, {"ok": False, "reason": "method_not_allowed"})

    def do_PUT(self) -> None:
        self._send_json(405, {"ok": False, "reason": "method_not_allowed"})

    def do_DELETE(self) -> None:
        self._send_json(405, {"ok": False, "reason": "method_not_allowed"})

    def do_PATCH(self) -> None:
        self._send_json(405, {"ok": False, "reason": "method_not_allowed"})

    def do_OPTIONS(self) -> None:
        # No CORS, ever: a cross-origin preflight gets a flat refusal.
        self._send_json(403, {"ok": False, "reason": "forbidden"})

    # -- plumbing

    @property
    def app(self) -> InstallerApp:
        return self.server.app

    def _dispatch(self, method: str) -> None:
        path, _, query = self.path.partition("?")
        self._body = b""
        try:
            # Read the (small, capped) body before anything else: replying and
            # closing with unread bytes in the socket makes the OS send a RST,
            # which can swallow the response the browser needs to see.
            self._body = self._consume_body()
            if self.headers.get("Host", "") not in self.app.allowed_hosts:
                raise _HttpError(403, "forbidden")  # DNS-rebinding guard
            if method == "GET" and path in ("/", "/index.html"):
                self._serve_page()
                return
            if not path.startswith("/api/"):
                raise _HttpError(404, "not_found")
            if not self._authorized():
                raise _HttpError(403, "forbidden")
            status, payload = self._route(method, path, parse_qs(query))
            self._send_json(status, payload)
        except _HttpError as exc:
            self._send_json(exc.status, {"ok": False, "reason": exc.reason})
        except Exception:
            log.exception("request failed: %s %s", method, path[:200])
            self._send_json(500, {"ok": False, "reason": "internal_error"})

    def _authorized(self) -> bool:
        token = self.headers.get("X-Bootstrap-Token", "")
        expected = self.app.token.encode("utf-8")
        if not token or not hmac.compare_digest(token.encode("utf-8"), expected):
            return False
        origin = self.headers.get("Origin")
        if origin is not None:
            return origin in self.app.allowed_origins
        referer = self.headers.get("Referer")
        if not referer:
            return False
        parts = urlsplit(referer)
        return f"{parts.scheme}://{parts.netloc}" in self.app.allowed_origins

    def _consume_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            if self.headers.get("Transfer-Encoding"):
                raise _HttpError(411, "length_required")
            return b""
        try:
            length = int(raw_length)
        except ValueError:
            raise _HttpError(400, "bad_length") from None
        if length < 0:
            raise _HttpError(400, "bad_length")
        if length > MAX_BODY_BYTES:
            if length <= MAX_DRAIN_BYTES:
                self.rfile.read(length)  # discard, so the 413 arrives cleanly
            raise _HttpError(413, "too_large")
        return self.rfile.read(length) if length else b""

    def _read_json(self) -> dict[str, Any]:
        if not self._body:
            return {}
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            raise _HttpError(415, "json_required")
        try:
            body = json.loads(self._body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise _HttpError(400, "bad_json") from None
        if not isinstance(body, dict):
            raise _HttpError(400, "bad_json")
        return body

    def _route(
        self, method: str, path: str, query: dict[str, list[str]]
    ) -> tuple[int, dict[str, Any]]:
        app = self.app
        if path == "/api/check":
            self._require(method, "GET")
            report = app.preflight.check()
            report["build_state"] = app.runner.state
            return 200, report
        if path == "/api/keys":
            self._require(method, "POST")
            body = self._read_json()
            if app.runner.state in (BUILDING, STARTING):
                return 409, {"ok": False, "reason": "build_running"}
            mode = body.get("mode", "generate")
            if mode not in ("generate", "custom"):
                errors = {"mode": "Choose 'generate' or 'custom'."}
                return 400, {"ok": False, "reason": "invalid", "errors": errors}
            custom = mode == "custom"
            result = app.key_writer.write(
                mode,
                secret_key=body.get("secret_key") if custom else None,
                encryption_key=body.get("encryption_key") if custom else None,
                overwrite=body.get("overwrite") is True,
            )
            if result.get("ok"):
                return 200, result
            return {"exists": 409, "invalid": 400}.get(result.get("reason", ""), 500), result
        if path == "/api/build":
            self._require(method, "POST")
            self._read_json()
            if not all(env_key_status(app.paths.env_file).values()):
                return 400, {"ok": False, "reason": "keys_missing"}
            if not app.runner.start():
                return 409, {"ok": False, "reason": "already_started", "state": app.runner.state}
            return 202, {"ok": True, "state": app.runner.state}
        if path == "/api/build/status":
            self._require(method, "GET")
            try:
                since = max(0, int((query.get("since") or ["0"])[0]))
            except ValueError:
                since = 0
            return 200, app.runner.status(since)
        if path == "/api/open":
            self._require(method, "POST")
            self._read_json()
            opened = bool(app.open_url(APP_URL))
            log.info("opened %s in the browser (ok=%s)", APP_URL, opened)
            return 200, {"ok": opened, "url": APP_URL}
        if path == "/api/start-docker":
            self._require(method, "POST")
            self._read_json()
            started = bool(app.start_docker())
            log.info("asked macOS to open Docker Desktop (ok=%s)", started)
            return 200, {"ok": started}
        if path == "/api/quit":
            self._require(method, "POST")
            self._read_json()
            log.info("quit requested from the page")
            app.request_shutdown()
            return 200, {"ok": True}
        raise _HttpError(404, "not_found")

    @staticmethod
    def _require(method: str, expected: str) -> None:
        if method != expected:
            raise _HttpError(405, "method_not_allowed")

    def _common_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._common_headers()
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _serve_page(self) -> None:
        try:
            html = self.app.paths.page.read_text(encoding="utf-8")
        except OSError:
            raise _HttpError(500, "page_missing") from None
        nonce = secrets.token_urlsafe(18)
        body = html.replace("__CSP_NONCE__", nonce).encode("utf-8")
        csp = (
            f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src data:; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", csp)
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self._common_headers()
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def make_server(
    app: InstallerApp,
    host: str = "127.0.0.1",
    ports: Iterable[int] = range(DEFAULT_PORT, MAX_PORT + 1),
) -> BootstrapServer:
    """Bind the first free port in ``ports`` (0 = any free port, for tests)."""
    last_error: OSError | None = None
    for port in ports:
        try:
            server = BootstrapServer((host, port), app)
        except OSError as exc:
            last_error = exc
            continue
        app.port = server.server_address[1]
        app.server = server
        return server
    raise last_error or OSError(errno.EADDRINUSE, "no free port")


# ── Entry point ──────────────────────────────────────────────────────────────


def configure_logging(log_path: Path | None, verbose: bool = False) -> list[logging.Handler]:
    """File log (0600) for everything; the Terminal only sees warnings."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    handlers: list[logging.Handler] = []
    if log_path is not None:
        ensure_private_log(log_path)
        file_handler = logging.FileHandler(str(log_path), mode="a", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s | %(message)s")
        )
        handlers.append(file_handler)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("  %(message)s"))
    # Compose output belongs in the page and the file, not the Terminal.
    console.addFilter(lambda record: not record.name.startswith(compose_log.name))
    handlers.append(console)
    for handler in handlers:
        logger.addHandler(handler)
    return handlers


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crawler AI bootstrap installer (serves a local setup page)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"first port to try on 127.0.0.1 (default %(default)s; falls back up to {MAX_PORT})",
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="don't open the browser; print the URL instead"
    )
    parser.add_argument(
        "--check-only", action="store_true", help="print the preflight report as JSON and exit"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="log debug detail to the Terminal and bootstrap.log"
    )
    return parser.parse_args(argv)


def _say(text: str = "") -> None:
    print(text, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    args = parse_args(argv)
    paths = InstallerPaths.default()

    if args.check_only:
        configure_logging(None, verbose=args.verbose)
        _say(json.dumps(Preflight(paths).check(), indent=2))
        return 0

    configure_logging(paths.log_file, verbose=args.verbose)
    env = build_env()
    token = secrets.token_urlsafe(32)
    app = InstallerApp(
        paths,
        token,
        preflight=Preflight(paths, env=env),
        runner=BuildRunner(paths.docker_dir, env=env),
    )
    first = max(1, min(args.port, 65535))
    last = max(first, MAX_PORT)
    try:
        server = make_server(app, ports=range(first, last + 1))
    except OSError:
        _say(
            f"  Couldn't find a free port between {first} and {last}. Close other installer windows and "
            "try again."
        )
        return 1

    url = f"http://127.0.0.1:{app.port}/?t={token}"
    log.info("installer listening on 127.0.0.1:%s", app.port)

    def _on_signal(signum: int, _frame: Any) -> None:
        log.info("received signal %s; shutting down", signum)
        app.request_shutdown(delay=0)

    # SIGHUP: the macOS Terminal window closed. SIGBREAK: Ctrl+Break or the
    # console window closing on Windows.
    for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _on_signal)
            except (OSError, ValueError):
                pass

    if args.no_browser:
        _say("  Crawler AI installer is running. Open this address in your browser:")
    else:
        _say("  Opening the Crawler AI installer in your browser…")
        _say("  If nothing opens, paste this address into your browser:")
    _say("  " + url)
    _say()
    _say("  Keep this window open while you install. Close it (or press Ctrl+C) to stop.")
    if not args.no_browser:
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        _say()
        _say("  Stopping the installer…")
    finally:
        app.runner.stop()
        server.server_close()
        log.info("installer stopped")
    _say("  The installer has stopped. You can close this window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
