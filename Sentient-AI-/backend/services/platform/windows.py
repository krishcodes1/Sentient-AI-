"""Windows: Edge or Chrome, %LOCALAPPDATA%, icacls, user32, netstat, and
DPAPI for the vault key (purchases spec §4).

(Windows implementation of spec §11.1; mac.py is its twin.) Nothing here
touches a Windows-only symbol at import time, so the module and its
tests load on every OS; user32 and crypt32 are reached through small
shims (``User32``, ``Crypt32``) that tests replace.

A secret is ``CryptProtectData`` ciphertext (user scope, no UI) in
``<data_dir>/secrets/<name>.dpapi``: only the signed-in Windows account
can unprotect it, on this machine, and the directory is ACL'd to that
account like a browser profile as a second fence.
"""

from __future__ import annotations

import csv
import ctypes
import os
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping, Optional, Protocol

from services.platform.base import (
    APP_DIR_NAME,
    TIMEOUT_S,
    VAULT_ID_FILE,
    PlatformName,
    Runner,
    SecretStoreUnavailable,
    profile_path,
    read_or_create_id,
    run_argv,
    secret_name,
)

# Where Playwright's channel="chrome" looks, under each of these bases.
# (os.environ upper-cases names on Windows, so "PROGRAMFILES(X86)" is right.)
CHROME_EXE_PARTS = ("Google", "Chrome", "Application", "chrome.exe")
_CHROME_BASES = ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")
SECRETS_DIR_NAME = "secrets"
SECRET_SUFFIX = ".dpapi"


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


class Crypt32(Protocol):
    """The two DPAPI calls the secret store needs, so a fake stands in on
    Mac/Linux and the real one is built only on Windows."""

    def protect(self, data: bytes) -> bytes: ...

    def unprotect(self, blob: bytes) -> bytes: ...


class _CtypesCrypt32:
    """Real crypt32.dll: CryptProtectData/CryptUnprotectData with
    CRYPTPROTECT_UI_FORBIDDEN, user scope (no LOCAL_MACHINE flag), no
    extra entropy. Constructed only when sys.platform is win32, which is
    why the Windows-only ctypes names are looked up here, not at import.

    Both calls take and return a DATA_BLOB; the output buffer is
    LocalAlloc'd by the OS and freed here right after it is copied out."""

    _UI_FORBIDDEN = 0x01

    def __init__(self) -> None:
        from ctypes import wintypes

        class DataBlob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        c = ctypes.WinDLL("crypt32", use_last_error=True)  # type: ignore[attr-defined]
        k = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        blob_p = ctypes.POINTER(DataBlob)
        # (pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct,
        # dwFlags, pDataOut); the description and prompt pointers stay NULL.
        for fn in (c.CryptProtectData, c.CryptUnprotectData):
            fn.argtypes = [
                blob_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_void_p, wintypes.DWORD, blob_p,
            ]
            fn.restype = wintypes.BOOL
        k.LocalFree.argtypes = [ctypes.c_void_p]
        k.LocalFree.restype = ctypes.c_void_p
        self._blob = DataBlob
        self._crypt32 = c
        self._kernel32 = k

    def _call(self, fn: Any, data: bytes) -> bytes:
        # The buffer outlives the call: DataBlob only points into it.
        buffer = ctypes.create_string_buffer(data, len(data))
        blob_in = self._blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        blob_out = self._blob()
        ok = fn(ctypes.byref(blob_in), None, None, None, None, self._UI_FORBIDDEN,
                ctypes.byref(blob_out))
        if not ok:
            # Windows-only in ctypes (and in typeshed), hence the getattr.
            last_error = getattr(ctypes, "get_last_error", None)
            raise SecretStoreUnavailable(
                f"DPAPI refused (error {last_error() if last_error else 0})"
            )
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            self._kernel32.LocalFree(blob_out.pbData)

    def protect(self, data: bytes) -> bytes:
        return self._call(self._crypt32.CryptProtectData, data)

    def unprotect(self, blob: bytes) -> bytes:
        return self._call(self._crypt32.CryptUnprotectData, blob)


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
        crypt32: Optional[Crypt32] = None,
    ) -> None:
        self._run = runner
        self._env: Mapping[str, str] = os.environ if env is None else env
        self._user32 = user32
        self._crypt32 = crypt32

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
        return self._private_dir(profile_path(self.data_dir(), user_id))

    def _private_dir(self, path: Path) -> Path:
        """Create *path* and restrict it to the signed-in account.

        Drop inherited ACEs and grant only that account: the Windows
        spelling of 0700 for a profile that holds live session cookies or
        the directory that holds the vault key. The account name comes
        from the environment, never from the model, and a failure is a
        refusal (as a failed chmod is on Mac). `/reset` first drops any
        explicit ACE an existing directory carries (`/grant:r` only
        replaces the named account's own ACEs), the twin of chmod-ing a
        loose Mac profile back to 0700."""
        path.mkdir(parents=True, exist_ok=True)
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

    # -- secrets (the vault key) --------------------------------------------

    def vault_id(self) -> str:
        return read_or_create_id(self.data_dir() / VAULT_ID_FILE)

    def _secret_path(self, name: str) -> Path:
        return self.data_dir() / SECRETS_DIR_NAME / f"{secret_name(name)}{SECRET_SUFFIX}"

    def _dpapi(self) -> Crypt32:
        shim = self._crypt32
        if shim is None and sys.platform.startswith("win"):
            shim = self._crypt32 = _CtypesCrypt32()
        if shim is None:
            raise SecretStoreUnavailable("DPAPI is only available on Windows")
        return shim

    def get_secret(self, name: str) -> Optional[bytes]:
        try:
            blob = self._secret_path(name).read_bytes()
        except FileNotFoundError:
            return None
        # A file that exists but will not unprotect (another account, a
        # reinstalled Windows) is unavailable, not absent: see base.py.
        return self._dpapi().unprotect(blob)

    def set_secret(self, name: str, value: bytes) -> None:
        blob = self._dpapi().protect(value)
        path = self._secret_path(name)
        self._private_dir(path.parent)
        # Write beside, then replace: a crash mid-write must not leave a
        # truncated file that reads as "stored" next time.
        staging = path.with_name(path.name + ".tmp")
        staging.write_bytes(blob)
        os.replace(staging, path)

    def delete_secret(self, name: str) -> None:
        self._secret_path(name).unlink(missing_ok=True)

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
