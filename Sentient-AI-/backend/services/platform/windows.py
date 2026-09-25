"""Windows: Edge or Chrome, %LOCALAPPDATA%, icacls, user32, netstat.

(Windows implementation of spec §11.1; mac.py is its twin.) Nothing here
touches a Windows-only symbol at import time, so the module and its
tests load on every OS; user32 is reached through a small shim
(``User32``) that tests replace.
"""

from __future__ import annotations

import csv
import ctypes
import os
import sys
from pathlib import Path, PureWindowsPath
from typing import Mapping, Optional, Protocol

from services.platform.base import (
    APP_DIR_NAME,
    TIMEOUT_S,
    PlatformName,
    Runner,
    profile_path,
    run_argv,
)

# Where Playwright's channel="chrome" looks, under each of these bases.
# (os.environ upper-cases names on Windows, so "PROGRAMFILES(X86)" is right.)
CHROME_EXE_PARTS = ("Google", "Chrome", "Application", "chrome.exe")
_CHROME_BASES = ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")


class User32(Protocol):
    """The four user32 calls bring_to_front needs, so a fake stands in on
    Mac/Linux and the real one is built only on Windows."""

    def find_window(self, title: str) -> int: ...

    def window_for_pid(self, pid: int) -> int: ...

    def set_foreground(self, hwnd: int) -> bool: ...

    def flash(self, hwnd: int) -> None: ...


class _CtypesUser32:
    """Real user32.dll. Constructed only when sys.platform is win32, which
    is why the Windows-only ctypes names are looked up here, not at import.

    Every function gets explicit argtypes/restype: ctypes' default is a C
    ``int``, which truncates a 64-bit HWND returned by FindWindowW."""

    _SW_RESTORE = 9

    def __init__(self) -> None:
        from ctypes import wintypes

        u = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined]
        self._enum_proc = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )
        u.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        u.FindWindowW.restype = wintypes.HWND
        u.EnumWindows.argtypes = [self._enum_proc, wintypes.LPARAM]
        u.EnumWindows.restype = wintypes.BOOL
        u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        u.GetWindowThreadProcessId.restype = wintypes.DWORD
        u.IsWindowVisible.argtypes = [wintypes.HWND]
        u.IsWindowVisible.restype = wintypes.BOOL
        u.IsIconic.argtypes = [wintypes.HWND]
        u.IsIconic.restype = wintypes.BOOL
        u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        u.ShowWindow.restype = wintypes.BOOL
        u.SetForegroundWindow.argtypes = [wintypes.HWND]
        u.SetForegroundWindow.restype = wintypes.BOOL
        u.FlashWindow.argtypes = [wintypes.HWND, wintypes.BOOL]
        u.FlashWindow.restype = wintypes.BOOL
        self._u = u
        self._dword = wintypes.DWORD

    def find_window(self, title: str) -> int:
        return int(self._u.FindWindowW(None, title) or 0)

    def window_for_pid(self, pid: int) -> int:
        found = 0

        def visit(hwnd: int, _lparam: int) -> bool:
            nonlocal found
            owner = self._dword()
            self._u.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == pid and self._u.IsWindowVisible(hwnd):
                found = int(hwnd or 0)
                return False  # stop enumerating
            return True

        # Kept in a local so the callback outlives the EnumWindows call.
        callback = self._enum_proc(visit)
        self._u.EnumWindows(callback, 0)
        return found

    def set_foreground(self, hwnd: int) -> bool:
        # A minimised window would take focus but stay on the taskbar.
        if self._u.IsIconic(hwnd):
            self._u.ShowWindow(hwnd, self._SW_RESTORE)
        return bool(self._u.SetForegroundWindow(hwnd))

    def flash(self, hwnd: int) -> None:
        self._u.FlashWindow(hwnd, True)


def parse_netstat(output: str, port: int) -> Optional[int]:
    """``netstat -ano -p tcp``: the PID of the first listening row whose
    local address ends in ``:<port>`` (IPv4 ``0.0.0.0:80`` or IPv6 ``[::]:80``)."""
    for line in output.splitlines():
        parts = line.split()
        # Proto, Local, Foreign, State..., PID. The State word is localised
        # ("ABHÖREN", "ÉCOUTE"), so a listener is recognised by its foreign
        # address instead: 0.0.0.0:0 / [::]:0, port 0, on every locale.
        if len(parts) < 5 or parts[0] != "TCP" or not parts[-1].isdigit():
            continue
        local_port = parts[1].rsplit(":", 1)[-1]
        foreign_port = parts[2].rsplit(":", 1)[-1]
        if local_port == str(port) and foreign_port == "0":
            return int(parts[-1])
    return None


def parse_tasklist(output: str, pid: int) -> Optional[str]:
    """``tasklist /FO CSV /NH`` prints ``"chrome.exe","4242","Console","1","187,532 K"``;
    returns the image name of *pid*. When no task matches, tasklist prints
    an INFO line instead of CSV, which is why a one-column row is skipped."""
    for row in csv.reader(output.splitlines()):
        if len(row) >= 2 and row[1] == str(pid):
            return row[0]
    return None


class WindowsPlatform:
    name: PlatformName = "windows"

    def __init__(
        self,
        *,
        runner: Runner = run_argv,
        env: Optional[Mapping[str, str]] = None,
        user32: Optional[User32] = None,
    ) -> None:
        self._run = runner
        self._env: Mapping[str, str] = os.environ if env is None else env
        self._user32 = user32

    def _system32(self, exe: str) -> str:
        # Absolute, like the Mac binaries: never whatever PATH finds first.
        # PureWindowsPath so the spelling is the same on every OS (tests).
        root = self._env.get("SYSTEMROOT") or r"C:\Windows"
        return str(PureWindowsPath(root) / "System32" / exe)

    def _account(self) -> str:
        """``DOMAIN\\user`` on a domain-joined machine (icacls needs the
        qualified name there), the bare user name on a workgroup machine,
        where USERDOMAIN is just the computer name."""
        user = self._env.get("USERNAME")
        if not user:
            raise OSError("USERNAME is not set; cannot scope the profile ACL to the current user")
        domain = self._env.get("USERDOMAIN") or ""
        machine = self._env.get("COMPUTERNAME") or ""
        if domain and domain.upper() != machine.upper():
            return f"{domain}\\{user}"
        return user

    def browser_channel(self) -> Optional[str]:
        # Chrome when installed (Playwright's own lookup order); Edge ships
        # with Windows 10/11, so it is the fallback and the answer is never None.
        for var in _CHROME_BASES:
            base = self._env.get(var)
            if base and Path(base).joinpath(*CHROME_EXE_PARTS).is_file():
                return "chrome"
        return "msedge"

    def data_dir(self) -> Path:
        base = self._env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_DIR_NAME

    def profile_dir(self, user_id: str) -> Path:
        path = profile_path(self.data_dir(), user_id)
        path.mkdir(parents=True, exist_ok=True)
        # Drop inherited ACEs and grant only the signed-in account: the
        # Windows spelling of 0700 for a profile that holds live session
        # cookies. The account name comes from the environment, never from
        # the model, and a failure is a refusal (as a failed chmod is on Mac).
        # `/reset` first drops any explicit ACE an existing directory carries
        # (`/grant:r` only replaces the named account's own ACEs), the twin
        # of chmod-ing a loose Mac profile back to 0700.
        account = self._account()
        icacls = self._system32("icacls.exe")
        steps = (
            [icacls, str(path), "/reset"],
            [icacls, str(path), "/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F"],
        )
        for argv in steps:
            code, out = self._run(argv, TIMEOUT_S)
            if code != 0:
                raise OSError(
                    f"icacls could not restrict {path} to {account}: {out.strip()[-200:]}"
                )
        return path

    def bring_to_front(self, *, pid: Optional[int] = None, title: Optional[str] = None) -> bool:
        user32 = self._user32
        if user32 is None and sys.platform.startswith("win"):
            user32 = self._user32 = _CtypesUser32()
        if user32 is None:
            return False
        hwnd = user32.find_window(title) if title else 0
        if not hwnd and pid is not None:
            hwnd = user32.window_for_pid(int(pid))
        if not hwnd:
            return False
        if user32.set_foreground(hwnd):
            return True
        # UIPI or the foreground-lock refused the switch (another app has
        # focus): flash the taskbar button so the owner still notices.
        user32.flash(hwnd)
        return False

    def port_owner(self, port: int) -> Optional[str]:
        _, out = self._run([self._system32("netstat.exe"), "-ano", "-p", "tcp"], TIMEOUT_S)
        pid = parse_netstat(out, int(port))
        if pid is None:
            return None
        _, out = self._run(
            [self._system32("tasklist.exe"), "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            TIMEOUT_S,
        )
        name = parse_tasklist(out, pid)
        return f"{pid} {name}" if name else str(pid)
