"""Implements the Windows ComputerBackend: reads windows through UI Automation
(the ``uiautomation`` package) and injects mouse and keyboard input with
``SendInput``.

Why it exists: desktop.observe and desktop.act need a real Windows backend.
Everything Windows-only (uiautomation/comtypes, and user32, kernel32, advapi32,
shell32 and version.dll through ctypes) loads lazily on first use, so this module
imports on macOS and Linux and the tests drive it with a fake ``uiautomation``
module and a recording Win32 shim: no real clicks, keys or screen reads on a
development machine.

What it guarantees on top of the toolkit's hard rules (defence in depth, because
this layer is the last one before input reaches another program):

- **UIPI.** Windows silently drops input sent to a window that runs at a higher
  integrity level (an app started "as administrator"), and ``SendInput`` does
  not report it. Every action first checks the target process with
  ``OpenProcess`` + ``OpenProcessToken`` + ``GetTokenInformation(TokenElevation)``
  and refuses with an explanation when it is elevated, or when Windows will not
  say (fail closed). ``outline`` refuses the same way, which is how the limit
  is reported in desktop.observe.
- **Secure fields.** ``IsPassword`` elements are marked ``secure`` and their
  value is never read. ``type_text`` refuses a secure target, re-checks the live
  element, and also refuses when the element that has keyboard focus is a
  password field.
- **App names.** Names come from the process image, mapped to the names the
  toolkit's blocked-app rule uses (cmd.exe and console windows -> "Command
  Prompt", powershell/pwsh -> "PowerShell", Settings -> "System Settings", ...),
  so a shell cannot slip past the rule under its executable name.
- **open_app** takes a bare app name only (no paths, URLs, arguments or script
  files) and refuses shells, terminals, system tools and password managers even
  if the toolkit's rule were bypassed.

Coordinates are physical pixels on the main display (multi-monitor is out of
scope for v1); the real Win32 layer makes the process per-monitor DPI aware so
UI Automation rectangles and ``SendInput`` agree.
"""

from __future__ import annotations

import contextlib
import ctypes
import importlib
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Sequence

import structlog

from services.tools.computer import rules
from services.tools.computer.backend import (
    AppInfo,
    AppNotFoundError,
    BlockedTargetError,
    ClickTarget,
    ComputerBackend,
    CoveredTargetError,
    ElementGoneError,
    ElevatedTargetError,
    KeyCombo,
    Node,
    PermissionState,
    Point,
    SecureTargetError,
    WindowInfo,
)

logger = structlog.get_logger(__name__)

# --- Limits ------------------------------------------------------------------

MAX_OUTLINE_NODES = 2000
# The raw UIA tree can be far deeper than the outline (unnamed panes are
# flattened away), so the depth and visit caps apply to the raw walk.
MAX_RAW_DEPTH = 40
MAX_VISITED = 4000
# Every UIA property read is a cross-process call; a pathological window
# (a huge data grid) must not stall the agent turn.
WALK_BUDGET_S = 8.0
MAX_TEXT_CHARS = 2000
# Characters per SendInput batch when typing. Very long bursts overflow some
# apps' message handling and drop characters.
TEXT_CHUNK_CHARS = 64
TEXT_CHUNK_PAUSE_S = 0.01
# After a typed Tab or Enter (which can move focus, e.g. from a user name
# field to a password field) the app gets this long to settle before focus
# is checked again and typing continues.
FOCUS_SETTLE_S = 0.15
MAX_SCROLL = 50
_NAME_CHARS = 300
_VALUE_CHARS = 500
_MAX_SHORTCUTS_SCANNED = 5000
_LOG_DETAIL_CHARS = 200


# --- Errors ------------------------------------------------------------------


class WindowsRefusal(PermissionError):
    """An action this backend refuses on purpose.

    The message is written for the owner and is safe to show the model: it
    names only the app and the rule that applied.
    """


class UIPIBlockedError(WindowsRefusal, ElevatedTargetError):
    """The target window runs elevated (or Windows will not say), so input
    would be silently dropped by User Interface Privilege Isolation."""


class SecureFieldError(WindowsRefusal, SecureTargetError):
    """The target, or the element that has keyboard focus, is a password field
    (or which element has focus cannot be told)."""


class BlockedAppError(WindowsRefusal, BlockedTargetError):
    """open_app was asked for a shell, terminal, system tool or password
    manager, or focus_window resolved to a window of one."""


class CoveredError(LookupError, CoveredTargetError):
    """Another window is on top of the click point."""


def _blocked_app_error(message: str, app: str) -> BlockedAppError:
    err = BlockedAppError(message)
    err.app = app  # OSError's __init__ does not take keyword arguments
    return err


class StaleElementError(ElementGoneError, LookupError):
    """The element a ref pointed at is gone or changed since the last outline."""


class WindowsAppNotFoundError(AppNotFoundError, LookupError):
    """No open window (or, for open_app, installed app) by that name."""


_STALE_MESSAGE = "The window changed since it was last observed; observe it again."
_SECURE_MESSAGE = (
    "That is a password field. Crawler never types into password fields; please type it yourself."
)
_FOCUS_UNKNOWN_MESSAGE = (
    "Crawler could not check which field has the keyboard focus, so it did not type."
)


def _uipi_message(app: str, *, known: bool) -> str:
    if known:
        return (
            f"Windows does not let Crawler control {app} because {app} is running as "
            "administrator (User Interface Privilege Isolation blocks input to elevated "
            f'windows). Do this step yourself, or close {app} and reopen it without "Run '
            'as administrator".'
        )
    return (
        f"Windows would not let Crawler check whether {app} is running as administrator, "
        "so Crawler will not control it. Please do this step yourself."
    )


def _blocked_launch_message(name: str) -> str:
    return (
        f"Crawler does not open {name}: shells, terminals, system settings, admin tools "
        "and password managers are off limits. Open it yourself if you need it."
    )


# --- SendInput structures ----------------------------------------------------
# Declared with fixed-width ctypes types (not ctypes.wintypes, which is
# Windows-only on some Pythons) so they build, and are testable, on any OS.
# ULONG_PTR is pointer sized, which c_size_t is on every Windows ABI; on a
# 64-bit host sizeof(INPUT) is 40, as SendInput's cbSize requires.

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1

MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_HWHEEL = 0x1000
MOUSEEVENTF_ABSOLUTE = 0x8000

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

WHEEL_DELTA = 120
# Marks every event Crawler injects ("CRAW"), so a low-level hook (a future
# kill switch, or the owner's own tooling) can tell agent input from theirs.
CRAWLER_EXTRA_INFO = 0x43524157


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_int32),
        ("dy", ctypes.c_int32),
        ("mouseData", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("time", ctypes.c_uint32),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_uint16),
        ("wScan", ctypes.c_uint16),
        ("dwFlags", ctypes.c_uint32),
        ("time", ctypes.c_uint32),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", ctypes.c_uint32),
        ("wParamL", ctypes.c_uint16),
        ("wParamH", ctypes.c_uint16),
    ]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", ctypes.c_uint32), ("u", _INPUTUNION)]


class _POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_int32), ("y", ctypes.c_int32)]


def mouse_input(dx: int, dy: int, flags: int, data: int = 0) -> INPUT:
    """One MOUSEINPUT. ``data`` may be negative (wheel down); it is stored as
    the two's-complement DWORD Windows expects."""
    return INPUT(
        type=INPUT_MOUSE,
        u=_INPUTUNION(mi=MOUSEINPUT(dx, dy, data & 0xFFFFFFFF, flags, 0, CRAWLER_EXTRA_INFO)),
    )


def key_input(vk: int, scan: int, flags: int) -> INPUT:
    return INPUT(
        type=INPUT_KEYBOARD,
        u=_INPUTUNION(ki=KEYBDINPUT(vk, scan & 0xFFFF, flags, 0, CRAWLER_EXTRA_INFO)),
    )


def _absolute(value: int, size: int) -> int:
    """Map a pixel on the main display to SendInput's 0..65535 range."""
    return round(value * 65535 / max(size - 1, 1))


# --- Keys --------------------------------------------------------------------

VK_BACK = 0x08
VK_TAB = 0x09
VK_RETURN = 0x0D
VK_SHIFT = 0x10
VK_CONTROL = 0x11
VK_MENU = 0x12
VK_LWIN = 0x5B

# The toolkit's grammar is shared with the Mac, so "cmd" is the platform's
# primary shortcut modifier: Ctrl here (cmd+s saves on both). The Windows key
# is spelled win / windows / super / meta.
_MODIFIER_VKS = {
    "ctrl": VK_CONTROL,
    "control": VK_CONTROL,
    "cmd": VK_CONTROL,
    "command": VK_CONTROL,
    "alt": VK_MENU,
    "option": VK_MENU,
    "opt": VK_MENU,
    "shift": VK_SHIFT,
    "win": VK_LWIN,
    "windows": VK_LWIN,
    "super": VK_LWIN,
    "meta": VK_LWIN,
}
_MODIFIER_ORDER = (VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN)

_NAMED_VKS = {
    "enter": VK_RETURN,
    "return": VK_RETURN,
    "tab": VK_TAB,
    "esc": 0x1B,
    "escape": 0x1B,
    "space": 0x20,
    "backspace": VK_BACK,
    "delete": 0x2E,
    "del": 0x2E,
    "forwarddelete": 0x2E,
    "insert": 0x2D,
    "ins": 0x2D,
    "home": 0x24,
    "end": 0x23,
    "pageup": 0x21,
    "pgup": 0x21,
    "pagedown": 0x22,
    "pgdn": 0x22,
    "left": 0x25,
    "up": 0x26,
    "right": 0x27,
    "down": 0x28,
    "arrowleft": 0x25,
    "arrowup": 0x26,
    "arrowright": 0x27,
    "arrowdown": 0x28,
    "menu": 0x5D,
    "apps": 0x5D,
    "plus": 0xBB,
    "minus": 0xBD,
    "comma": 0xBC,
    "period": 0xBE,
}
# Punctuation keys by their unshifted US-layout character. VK_OEM_PLUS,
# _MINUS, _COMMA and _PERIOD mean the same key on every layout; the others
# (OEM_1..OEM_7) are the US positions.
_CHAR_VKS = {
    " ": 0x20,
    "=": 0xBB,
    "-": 0xBD,
    ",": 0xBC,
    ".": 0xBE,
    ";": 0xBA,
    "/": 0xBF,
    "`": 0xC0,
    "[": 0xDB,
    "\\": 0xDC,
    "]": 0xDD,
    "'": 0xDE,
}
# Keys on the extended part of the keyboard; without the flag some apps read
# the numpad variant (Home -> numpad 7).
_EXTENDED_VKS = frozenset(
    {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x5C, 0x5D}
)
_FKEY_RE = re.compile(r"f([1-9]|1[0-9]|2[0-4])")


def key_vk(key: str) -> int:
    """The virtual-key code for one key of the grammar. Raises ValueError."""
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string.")
    if len(key) == 1:
        # isascii() first: casefold/lower can turn one non-ASCII character
        # into two ("ß" -> "ss"), which must not pass as a letter key.
        ch = key.lower()
        if key.isascii() and ("a" <= ch <= "z" or "0" <= ch <= "9"):
            return ord(ch.upper())
        if ch in _CHAR_VKS:
            return _CHAR_VKS[ch]
        raise ValueError(f"Unsupported key {key!r}.")
    name = re.sub(r"[\s_-]", "", key.casefold())
    if name in _NAMED_VKS:
        return _NAMED_VKS[name]
    match = _FKEY_RE.fullmatch(name)
    if match:
        return 0x70 + int(match.group(1)) - 1
    raise ValueError(f"Unsupported key {key!r}.")


def combo_vks(combo: KeyCombo) -> tuple[list[int], int]:
    """(modifier VKs in press order, key VK) for a KeyCombo. Raises ValueError
    on an unknown modifier (Fn/Globe cannot be sent on Windows) or key."""
    mods: list[int] = []
    for raw in combo.modifiers:
        vk = _MODIFIER_VKS.get(str(raw).strip().casefold())
        if vk is None:
            raise ValueError(f"Unsupported modifier {raw!r}; use ctrl, alt, shift or win.")
        if vk not in mods:
            mods.append(vk)
    mods.sort(key=_MODIFIER_ORDER.index)
    return mods, key_vk(combo.key)


# --- UI Automation vocabulary ------------------------------------------------

_CT_BUTTON = 50000
_CT_CHECKBOX = 50002
_CT_COMBOBOX = 50003
_CT_EDIT = 50004
_CT_HYPERLINK = 50005
_CT_LIST_ITEM = 50007
_CT_MENU_ITEM = 50011
_CT_RADIO = 50013
_CT_SCROLLBAR = 50014
_CT_SLIDER = 50015
_CT_SPINNER = 50016
_CT_TAB_ITEM = 50019
_CT_TREE_ITEM = 50024
_CT_THUMB = 50027
_CT_DATA_ITEM = 50029
_CT_DOCUMENT = 50030
_CT_SPLIT_BUTTON = 50031
_CT_HEADER_ITEM = 50035

_ROLES = {
    50000: "button",
    50001: "calendar",
    50002: "checkbox",
    50003: "combo box",
    50004: "text field",
    50005: "link",
    50006: "image",
    50007: "list item",
    50008: "list",
    50009: "menu",
    50010: "menu bar",
    50011: "menu item",
    50012: "progress bar",
    50013: "radio button",
    50014: "scroll bar",
    50015: "slider",
    50016: "spinner",
    50017: "status bar",
    50018: "tab group",
    50019: "tab",
    50020: "text",
    50021: "toolbar",
    50022: "tooltip",
    50023: "tree",
    50024: "tree item",
    50025: "custom",
    50026: "group",
    50027: "thumb",
    50028: "table",
    50029: "row",
    50030: "document",
    50031: "split button",
    50032: "window",
    50033: "pane",
    50034: "header",
    50035: "column header",
    50036: "table",
    50037: "title bar",
    50038: "separator",
    50039: "zoom",
    50040: "app bar",
}
# Shown even without a name: the model needs to see where it can act.
_INTERACTIVE_TYPES = frozenset(
    {
        _CT_BUTTON,
        _CT_CHECKBOX,
        _CT_COMBOBOX,
        _CT_EDIT,
        _CT_HYPERLINK,
        _CT_LIST_ITEM,
        _CT_MENU_ITEM,
        _CT_RADIO,
        _CT_SLIDER,
        _CT_SPINNER,
        _CT_TAB_ITEM,
        _CT_TREE_ITEM,
        _CT_DATA_ITEM,
        _CT_DOCUMENT,
        _CT_SPLIT_BUTTON,
        _CT_HEADER_ITEM,
    }
)
# Scroll bars and their thumbs are pure noise in an outline (Line up, Page
# down, ...); the scroll action covers them.
_SKIP_SUBTREE_TYPES = frozenset({_CT_SCROLLBAR, _CT_THUMB})
# Text entry: kept in the outline even when scrolled off-screen, so the
# toolkit's payment scan still sees a card field out of view.
_FIELD_TYPES = frozenset({_CT_EDIT, _CT_COMBOBOX})
_VALUE_TYPES = frozenset({_CT_EDIT, _CT_COMBOBOX, _CT_DOCUMENT, _CT_SPINNER, _CT_DATA_ITEM})
# Where InvokePattern means exactly "a single click". On list and tree
# items Invoke means "open" (a double click), so those get a real click.
_INVOKE_TYPES = frozenset({_CT_BUTTON, _CT_MENU_ITEM, _CT_HYPERLINK, _CT_SPLIT_BUTTON})
_PATTERN_FALLBACK_IDS = {"InvokePattern": 10000, "ValuePattern": 10002}

# Top-level windows that belong to the shell, not to an app.
_SHELL_CLASSES = frozenset(
    {
        "Shell_TrayWnd",
        "Shell_SecondaryTrayWnd",
        "Progman",
        "WorkerW",
        "NotifyIconOverflowWindow",
        "TopLevelWindowForOverflowXamlIsland",
        "Windows.UI.Core.CoreWindow",
    }
)
_UWP_FRAME_HOST = "applicationframehost"
_UWP_CORE_WINDOW = "Windows.UI.Core.CoreWindow"

# Console windows are owned by the console host, not by the shell running in
# them, so they are named by window class. Any console counts as a shell.
_WINDOW_CLASS_APPS = {
    "ConsoleWindowClass": "Command Prompt",
    "PseudoConsoleWindow": "Command Prompt",
    "CASCADIA_HOSTING_WINDOW_CLASS": "Windows Terminal",
}
# Executable stem (casefolded) -> the app name the toolkit sees. Everything
# the toolkit's blocked-app rule names must be here under the rule's spelling;
# the rest are common apps whose file description is not their usual name.
_KNOWN_APPS = {
    "cmd": "Command Prompt",
    "conhost": "Command Prompt",
    "openconsole": "Windows Terminal",
    "windowsterminal": "Windows Terminal",
    "wt": "Windows Terminal",
    "powershell": "PowerShell",
    "powershell_ise": "PowerShell",
    "pwsh": "PowerShell",
    "regedit": "Registry Editor",
    "regedt32": "Registry Editor",
    "taskmgr": "Task Manager",
    "systemsettings": "System Settings",
    "systemsettingsadminflows": "System Settings",
    "control": "System Settings",
    "mmc": "Microsoft Management Console",
    "logonui": "Login Window",
    "lockapp": "Lock Screen",
    "consent": "User Account Control",
    "credentialuibroker": "Windows Security",
    # The Start menu and its search run anything typed into them.
    "startmenuexperiencehost": "Start Menu",
    "searchhost": "Windows Search",
    "searchapp": "Windows Search",
    "searchui": "Windows Search",
    "1password": "1Password",
    "bitwarden": "Bitwarden",
    "lastpass": "LastPass",
    "dashlane": "Dashlane",
    "keepass": "KeePass",
    "keepassxc": "KeePassXC",
    "crawler": "Crawler AI",
    "crawler ai": "Crawler AI",
    "explorer": "File Explorer",
    "msedge": "Microsoft Edge",
    "chrome": "Google Chrome",
    "firefox": "Firefox",
    "notepad": "Notepad",
    "calc": "Calculator",
    "calculatorapp": "Calculator",
    "mspaint": "Paint",
    "winword": "Word",
    "excel": "Excel",
    "powerpnt": "PowerPoint",
    "outlook": "Outlook",
    "olk": "Outlook",
}
# A suspended UWP app's frame has no inner window to name it by; its title
# is all there is.
_UWP_TITLE_APPS = {"settings": "System Settings"}

# open_app: friendly name -> what ShellExecute can find on PATH / App Paths.
_LAUNCH_ALIASES = {
    "calculator": "calc",
    "paint": "mspaint",
    "file explorer": "explorer",
    "microsoft edge": "msedge",
    "edge": "msedge",
    "google chrome": "chrome",
    "word": "winword",
    "microsoft word": "winword",
    "microsoft excel": "excel",
    "powerpoint": "powerpnt",
    "microsoft powerpoint": "powerpnt",
    "snipping tool": "snippingtool",
}
# Never launched by open_app, whatever the toolkit decided: every route to a
# command line, system configuration or stored credentials.
_BLOCKED_LAUNCH = frozenset(
    {
        "cmd",
        "command prompt",
        "powershell",
        "windows powershell",
        "powershell_ise",
        "windows powershell ise",
        "pwsh",
        "powershell 7",
        "wt",
        "windows terminal",
        "windowsterminal",
        "terminal",
        "openconsole",
        "conhost",
        "bash",
        "wsl",
        "ubuntu",
        "ssh",
        "iterm2",
        "warp",
        "regedit",
        "regedt32",
        "registry editor",
        "taskmgr",
        "task manager",
        "mmc",
        "control",
        "control panel",
        "settings",
        "system settings",
        "systemsettings",
        "system preferences",
        "gpedit",
        "secpol",
        "services",
        "compmgmt",
        "computer management",
        "eventvwr",
        "msconfig",
        "system configuration",
        "taskschd",
        "task scheduler",
        "schtasks",
        "diskpart",
        "mshta",
        "wscript",
        "cscript",
        "rundll32",
        "regsvr32",
        "msiexec",
        "certutil",
        "bitsadmin",
        "sc",
        "net",
        "reg",
        "runas",
        "winget",
        "1password",
        "bitwarden",
        "lastpass",
        "dashlane",
        "keepass",
        "keepassxc",
        "credential manager",
        "keychain access",
        "passwords",
        "crawler",
        "crawler ai",
    }
)
# Start Menu names wrap the same tools in longer names ("Windows PowerShell
# (x86)", "Developer Command Prompt for VS 2022", "Git Bash", "Python 3.12",
# "Ubuntu 22.04"), so a name is also refused when any word in it is one of
# these, or when it contains one of the phrases. Over-blocking a harmless
# app with such a word in its name is the accepted cost.
_BLOCKED_LAUNCH_WORDS = frozenset(
    {
        "cmd",
        "powershell",
        "pwsh",
        "terminal",
        "shell",
        "console",
        "prompt",
        "bash",
        "zsh",
        "wsl",
        "ubuntu",
        "debian",
        "kali",
        "cygwin",
        "msys2",
        "mingw64",
        "putty",
        "ssh",
        "python",
        "pythonw",
        "idle",
        "node",
        "regedit",
        "registry",
        "taskmgr",
        "settings",
        "1password",
        "bitwarden",
        "lastpass",
        "dashlane",
        "keepass",
        "keepassxc",
        "keeper",
        "roboform",
        "nordpass",
        "enpass",
        "crawler",
    }
)
_BLOCKED_LAUNCH_PHRASES = (
    "command prompt",
    "control panel",
    "task manager",
    "task scheduler",
    "event viewer",
    "computer management",
    "disk management",
    "system configuration",
    "group policy",
    "security policy",
    "credential manager",
)
# Letters (any script), digits, spaces and a little punctuation. No path
# separators, drive or URL colons, environment variables or shell syntax.
_APP_NAME_RE = re.compile(r"[^\W_][\w .+'()-]{0,99}")


# --- Win32 access ------------------------------------------------------------

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION_CLASS = 20  # TOKEN_INFORMATION_CLASS.TokenElevation
GA_ROOT = 2
SW_RESTORE = 9
SW_SHOWNORMAL = 1
SM_CXSCREEN = 0
SM_CYSCREEN = 1
MAPVK_VK_TO_VSC = 0
_DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4


class _Win32Api:
    """The real user32/kernel32/advapi32/shell32/version calls, via ctypes.

    Built on first use by WindowsBackend, never at import. Tests substitute an
    object with the same methods that records the INPUT structs instead.
    """

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("The Windows input layer is only available on Windows.")
        # ctypes.WinDLL exists only on Windows; going through Any keeps mypy
        # (which checks this module on every OS) quiet without an ignore.
        ct: Any = ctypes
        self._user32: Any = ct.WinDLL("user32", use_last_error=True)
        self._kernel32: Any = ct.WinDLL("kernel32", use_last_error=True)
        self._advapi32: Any = ct.WinDLL("advapi32", use_last_error=True)
        self._shell32: Any = ct.WinDLL("shell32", use_last_error=True)
        self._version: Any = ct.WinDLL("version", use_last_error=True)
        self._declare()
        self._make_dpi_aware(ct)

    def _declare(self) -> None:
        handle = ctypes.c_void_p
        dword = ctypes.c_uint32
        u, k, a, s, v = self._user32, self._kernel32, self._advapi32, self._shell32, self._version
        u.SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int]
        u.SendInput.restype = ctypes.c_uint
        u.GetSystemMetrics.argtypes = [ctypes.c_int]
        u.GetSystemMetrics.restype = ctypes.c_int
        u.GetForegroundWindow.argtypes = []
        u.GetForegroundWindow.restype = handle
        u.SetForegroundWindow.argtypes = [handle]
        u.SetForegroundWindow.restype = ctypes.c_int
        u.IsIconic.argtypes = [handle]
        u.IsIconic.restype = ctypes.c_int
        u.ShowWindow.argtypes = [handle, ctypes.c_int]
        u.ShowWindow.restype = ctypes.c_int
        u.GetWindowThreadProcessId.argtypes = [handle, ctypes.POINTER(dword)]
        u.GetWindowThreadProcessId.restype = dword
        u.WindowFromPoint.argtypes = [_POINT]
        u.WindowFromPoint.restype = handle
        u.GetAncestor.argtypes = [handle, ctypes.c_uint]
        u.GetAncestor.restype = handle
        u.GetCursorPos.argtypes = [ctypes.POINTER(_POINT)]
        u.GetCursorPos.restype = ctypes.c_int
        u.MapVirtualKeyW.argtypes = [ctypes.c_uint, ctypes.c_uint]
        u.MapVirtualKeyW.restype = ctypes.c_uint
        k.OpenProcess.argtypes = [dword, ctypes.c_int, dword]
        k.OpenProcess.restype = handle
        k.CloseHandle.argtypes = [handle]
        k.CloseHandle.restype = ctypes.c_int
        k.QueryFullProcessImageNameW.argtypes = [
            handle,
            dword,
            ctypes.c_wchar_p,
            ctypes.POINTER(dword),
        ]
        k.QueryFullProcessImageNameW.restype = ctypes.c_int
        a.OpenProcessToken.argtypes = [handle, dword, ctypes.POINTER(handle)]
        a.OpenProcessToken.restype = ctypes.c_int
        a.GetTokenInformation.argtypes = [
            handle,
            ctypes.c_int,
            ctypes.c_void_p,
            dword,
            ctypes.POINTER(dword),
        ]
        a.GetTokenInformation.restype = ctypes.c_int
        s.ShellExecuteW.argtypes = [
            handle,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        s.ShellExecuteW.restype = handle
        v.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(dword)]
        v.GetFileVersionInfoSizeW.restype = dword
        v.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, dword, dword, ctypes.c_void_p]
        v.GetFileVersionInfoW.restype = ctypes.c_int
        v.VerQueryValueW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint),
        ]
        v.VerQueryValueW.restype = ctypes.c_int

    def _make_dpi_aware(self, ct: Any) -> None:
        """Physical pixels everywhere: UIA rectangles, GetSystemMetrics and
        SendInput must use the same coordinate space. Already-set awareness
        (uiautomation may set it at import) makes these calls fail harmlessly."""
        try:
            fn = self._user32.SetProcessDpiAwarenessContext
            fn.argtypes = [ctypes.c_void_p]
            fn.restype = ctypes.c_int
            if fn(ctypes.c_void_p(_DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)):
                return
        except (AttributeError, OSError):
            pass
        try:
            ct.WinDLL("shcore").SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            pass

    # Input -------------------------------------------------------------

    def send_input(self, inputs: Sequence[INPUT]) -> int:
        array = (INPUT * len(inputs))(*inputs)
        return int(self._user32.SendInput(len(inputs), array, ctypes.sizeof(INPUT)))

    def scan_code(self, vk: int) -> int:
        return int(self._user32.MapVirtualKeyW(vk, MAPVK_VK_TO_VSC))

    def screen_size(self) -> tuple[int, int]:
        return (
            int(self._user32.GetSystemMetrics(SM_CXSCREEN)),
            int(self._user32.GetSystemMetrics(SM_CYSCREEN)),
        )

    def cursor_pos(self) -> tuple[int, int]:
        point = _POINT()
        if not self._user32.GetCursorPos(ctypes.byref(point)):
            return (0, 0)
        return (int(point.x), int(point.y))

    # Windows -----------------------------------------------------------

    def foreground_window(self) -> int:
        return int(self._user32.GetForegroundWindow() or 0)

    def set_foreground_window(self, hwnd: int) -> bool:
        return bool(self._user32.SetForegroundWindow(hwnd))

    def is_iconic(self, hwnd: int) -> bool:
        return bool(self._user32.IsIconic(hwnd))

    def restore_window(self, hwnd: int) -> None:
        self._user32.ShowWindow(hwnd, SW_RESTORE)

    def window_pid(self, hwnd: int) -> int:
        pid = ctypes.c_uint32(0)
        self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value)

    def window_at(self, x: int, y: int) -> int:
        """The top-level window under a screen point, or 0."""
        hwnd = self._user32.WindowFromPoint(_POINT(x, y))
        if not hwnd:
            return 0
        return int(self._user32.GetAncestor(hwnd, GA_ROOT) or hwnd)

    # Processes ---------------------------------------------------------

    def process_elevated(self, pid: int) -> bool | None:
        """True/False from the process token's TokenElevation, or None when
        Windows will not tell (which, from a non-elevated caller, usually
        means the process is elevated)."""
        process = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            return None
        try:
            token = ctypes.c_void_p()
            if not self._advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
                return None
            try:
                elevation = ctypes.c_uint32(0)
                returned = ctypes.c_uint32(0)
                ok = self._advapi32.GetTokenInformation(
                    token,
                    TOKEN_ELEVATION_CLASS,
                    ctypes.byref(elevation),
                    ctypes.sizeof(elevation),
                    ctypes.byref(returned),
                )
                if not ok:
                    return None
                return bool(elevation.value)
            finally:
                self._kernel32.CloseHandle(token)
        finally:
            self._kernel32.CloseHandle(process)

    def process_image(self, pid: int) -> str | None:
        process = self._kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            return None
        try:
            size = ctypes.c_uint32(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not self._kernel32.QueryFullProcessImageNameW(
                process, 0, buffer, ctypes.byref(size)
            ):
                return None
            return buffer.value or None
        finally:
            self._kernel32.CloseHandle(process)

    def file_description(self, path: str) -> str | None:
        """The FileDescription from an executable's version resource (the
        name Task Manager shows), or None."""
        size = self._version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        data = ctypes.create_string_buffer(size)
        if not self._version.GetFileVersionInfoW(path, 0, size, data):
            return None
        pointer = ctypes.c_void_p()
        length = ctypes.c_uint(0)
        codes: list[tuple[int, int]] = []
        if (
            self._version.VerQueryValueW(
                data, "\\VarFileInfo\\Translation", ctypes.byref(pointer), ctypes.byref(length)
            )
            and pointer.value
            and length.value >= 4
        ):
            words = (ctypes.c_uint16 * (length.value // 2)).from_address(pointer.value)
            codes = [(words[i], words[i + 1]) for i in range(0, len(words) - 1, 2)]
        for lang, codepage in [*codes, (0x0409, 0x04B0), (0x0409, 0x04E4)]:
            key = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileDescription"
            if (
                self._version.VerQueryValueW(data, key, ctypes.byref(pointer), ctypes.byref(length))
                and pointer.value
                and length.value > 1
            ):
                text = ctypes.wstring_at(pointer.value).strip()
                if text:
                    return text[:_NAME_CHARS]
        return None

    def shell_execute(self, target: str, directory: str | None) -> int:
        """ShellExecuteW "open"; the return value is > 32 on success."""
        result = self._shell32.ShellExecuteW(None, "open", target, None, directory, SW_SHOWNORMAL)
        return int(result or 0)


# --- Small helpers -------------------------------------------------------------


@dataclass(frozen=True)
class _ElementRef:
    """What a Node's handle holds: how to find the element again.

    UIA element objects are COM pointers tied to the thread (apartment) that
    read them, and the toolkit may act from a different worker thread than
    the one that observed. So the ref stores the window handle and the child
    index path, re-walks it in the acting thread, and checks the element is
    still the same one (type, name, runtime id) before touching it.
    """

    window: int
    path: tuple[int, ...]
    control_type: int
    name: str
    runtime_id: tuple[int, ...] | None


@dataclass(frozen=True)
class _AppId:
    name: str
    stem: str
    pids: tuple[int, ...]


@dataclass(frozen=True)
class _Owner:
    """The window an action is meant for: its handle, the processes that
    own it (a UWP frame and its app), and the app name for messages."""

    window: int
    pids: tuple[int, ...]
    app: str


def _log_failure(event: str, exc: BaseException, **fields: Any) -> None:
    logger.warning(
        event,
        error_type=type(exc).__name__,
        error=str(exc)[:_LOG_DETAIL_CHARS],
        **fields,
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _clean(text: Any, limit: int = _NAME_CHARS) -> str:
    return " ".join(str(text or "").split())[:limit]


def _bounds(rect: Any) -> tuple[int, int, int, int]:
    left, top = int(rect.left), int(rect.top)
    return left, top, max(int(rect.right) - left, 0), max(int(rect.bottom) - top, 0)


def _center(bounds: tuple[int, int, int, int]) -> Point:
    x, y, w, h = bounds
    return x + w // 2, y + h // 2


def _pid(ctl: Any) -> int:
    try:
        return int(ctl.ProcessId or 0)
    except Exception:
        return 0


def _hwnd(ctl: Any) -> int:
    try:
        return int(ctl.NativeWindowHandle or 0)
    except Exception:
        return 0


def _class_name(ctl: Any) -> str:
    try:
        return str(ctl.ClassName or "")
    except Exception:
        return ""


def _is_secure(ctl: Any) -> bool:
    """IsPassword, failing closed: an element whose flag cannot be read is
    treated as a password field."""
    try:
        return bool(ctl.IsPassword)
    except Exception:
        return True


def _role(control_type: int, ctl: Any) -> str:
    role = _ROLES.get(control_type)
    if role:
        return role
    type_name = str(getattr(ctl, "ControlTypeName", "") or "").removesuffix("Control")
    words = re.findall(r"[A-Z][a-z]*|[a-z]+", type_name)
    return " ".join(words).lower() or "element"


def _node_role(control_type: int, ctl: Any, secure: bool) -> str:
    """The shared role vocabulary: a password edit is a "secure text field"."""
    if secure and control_type == _CT_EDIT:
        return "secure text field"
    return _role(control_type, ctl)


def _has_focus(ctl: Any) -> bool:
    try:
        return bool(ctl.HasKeyboardFocus)
    except Exception:
        return False


def _is_enabled(ctl: Any) -> bool:
    try:
        value = ctl.IsEnabled
    except Exception:
        return True
    return True if value is None else bool(value)


@dataclass
class _Draft:
    """A node under construction: the walk is iterative and finds a node's
    children after the node itself, while ``Node`` is frozen."""

    fields: dict[str, Any]
    children: list["_Draft"] = field(default_factory=list)

    def freeze(self) -> Node:
        # Recursion is bounded by MAX_RAW_DEPTH.
        return Node(**self.fields, children=tuple(c.freeze() for c in self.children))


def _pattern_id(uia: Any, name: str) -> int:
    return int(getattr(getattr(uia, "PatternId", None), name, _PATTERN_FALLBACK_IDS[name]))


def _get_pattern(ctl: Any, pattern_id: int) -> Any:
    try:
        return ctl.GetPattern(pattern_id)
    except Exception:
        return None


def _read_value(ctl: Any, control_type: int, value_pattern: int) -> str | None:
    if control_type not in _VALUE_TYPES:
        return None
    pattern = _get_pattern(ctl, value_pattern)
    if pattern is None:
        return None
    try:
        value = pattern.Value
    except Exception:
        return None
    return None if value is None else str(value)[:_VALUE_CHARS]


def _runtime_id(ctl: Any) -> tuple[int, ...] | None:
    getter = getattr(ctl, "GetRuntimeId", None)
    if getter is None:
        return None
    try:
        return tuple(int(part) for part in getter())
    except Exception:
        return None


def _set_focus(ctl: Any) -> bool:
    try:
        return bool(ctl.SetFocus())
    except Exception:
        return False


def _as_point(value: Any) -> Point:
    if not (
        isinstance(value, (tuple, list)) and len(value) == 2 and all(_is_int(v) for v in value)
    ):
        raise TypeError("A click target must be an outline node or an (x, y) pair of integers.")
    return int(value[0]), int(value[1])


def _check_text(text: Any) -> None:
    if not isinstance(text, str):
        raise TypeError("text must be a string.")
    if not text:
        raise ValueError("There is no text to type.")
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"text is longer than {MAX_TEXT_CHARS} characters.")
    if any((ord(ch) < 0x20 and ch not in "\n\r\t") or ch == "\x7f" for ch in text):
        raise ValueError("text contains control characters; use the key action for special keys.")
    try:
        text.encode("utf-16-le")
    except UnicodeEncodeError:
        raise ValueError("text contains an invalid character.")


def _check_app_query(app: Any) -> str:
    if not isinstance(app, str) or not app.strip() or len(app) > 200:
        raise ValueError("app must be a non-empty app name.")
    return app.strip()


def _launch_key(name: str) -> str:
    key = name.casefold().strip()
    return key[:-4] if key.endswith(".exe") else key


def _launch_blocked(name: str) -> bool:
    key = _launch_key(name)
    if key in _BLOCKED_LAUNCH:
        return True
    words = re.findall(r"[^\W_]+", key)
    if _BLOCKED_LAUNCH_WORDS.intersection(words):
        return True
    spaced = f" {' '.join(words)} "
    return any(f" {phrase} " in spaced for phrase in _BLOCKED_LAUNCH_PHRASES)


def _matches(query: str, ident: _AppId) -> bool:
    key = _launch_key(query)
    return key == ident.name.casefold() or (bool(ident.stem) and key == ident.stem.casefold())


def _default_start_menu_dirs() -> list[Path]:
    dirs = []
    for variable in ("APPDATA", "ProgramData"):
        base = os.environ.get(variable)
        if base:
            dirs.append(Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs")
    return dirs


# --- The backend ---------------------------------------------------------------


class WindowsBackend:
    """ComputerBackend for Windows. Every seam is injectable: ``uia`` (the
    uiautomation module), ``win32`` (an object with ``_Win32Api``'s methods),
    the platform name, the Start Menu folders, and the sleep/clock used for
    typing pauses and the outline time budget."""

    name = "windows"

    def __init__(
        self,
        *,
        uia: Any | None = None,
        win32: Any | None = None,
        platform: str | None = None,
        start_menu_dirs: Iterable[Path] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._uia_module = uia
        self._win32 = win32
        self._platform = platform if platform is not None else sys.platform
        self._start_menu_dirs = list(start_menu_dirs) if start_menu_dirs is not None else None
        self._sleep = sleep
        self._clock = clock
        self._descriptions: dict[str, str | None] = {}

    # Loading -------------------------------------------------------------

    def _uia(self) -> Any:
        if self._uia_module is None:
            self._uia_module = importlib.import_module("uiautomation")
        return self._uia_module

    @property
    def _w32(self) -> Any:
        if self._win32 is None:
            self._win32 = _Win32Api()
        return self._win32

    @contextlib.contextmanager
    def _session(self) -> Iterator[Any]:
        """UI Automation needs COM initialised in the calling thread, and the
        toolkit calls from worker threads."""
        uia = self._uia()
        initializer = getattr(uia, "UIAutomationInitializerInThread", None)
        if initializer is None:
            yield uia
            return
        with initializer():
            yield uia

    # Availability and permission ------------------------------------------

    def available(self) -> tuple[bool, str]:
        if self._platform != "win32":
            return False, "Controlling the computer through UI Automation needs Windows."
        try:
            self._uia()
        except ImportError:
            return False, (
                "The 'uiautomation' package is not installed. Run: pip install -r requirements.txt"
            )
        except Exception as exc:
            _log_failure("windows_uia_load_failed", exc)
            return False, "Windows UI Automation could not be loaded."
        return True, ""

    def permission(self) -> PermissionState:
        # Windows has no per-app grant for UI Automation or SendInput. The
        # one limit (UIPI: no input to elevated windows) is per target and is
        # reported by outline() and every action.
        return "not_required"

    def request_permission(self) -> None:
        return None

    # Reading ---------------------------------------------------------------

    def list_apps(self) -> list[AppInfo]:
        with self._session() as uia:
            foreground = self._w32.foreground_window()
            active: dict[tuple[str, int], bool] = {}
            for ctl, ident in self._app_windows(uia):
                key = (ident.name, ident.pids[-1])
                active[key] = active.get(key, False) or _hwnd(ctl) == foreground
            # UIPI: Crawler's input cannot reach an elevated app; say so in
            # desktop.observe's app list.
            return [
                AppInfo(
                    name=name,
                    pid=pid,
                    active=is_active,
                    elevated=self._w32.process_elevated(pid) is True,
                )
                for (name, pid), is_active in active.items()
            ]

    def list_windows(self) -> list[WindowInfo]:
        with self._session() as uia:
            counts: dict[str, int] = {}
            windows: list[WindowInfo] = []
            for ctl, ident in self._app_windows(uia):
                index = counts.get(ident.name.casefold(), 0)
                counts[ident.name.casefold()] = index + 1
                windows.append(WindowInfo(app=ident.name, title=_clean(ctl.Name), index=index))
        return windows

    def frontmost(self) -> tuple[str, str]:
        with self._session() as uia:
            foreground = self._w32.foreground_window()
            if not foreground:
                return "", ""
            ctl = uia.ControlFromHandle(foreground)
            if ctl is None:
                return self._process_identity(self._w32.window_pid(foreground)).name, ""
            return self._identity(ctl).name, _clean(ctl.Name)

    def outline(self, app: str | None, max_nodes: int) -> list[Node]:
        """The window as a tree: a one-element list holding the window node,
        whose ``children`` are the elements inside it (see ``_walk``)."""
        if not _is_int(max_nodes) or max_nodes < 1:
            raise ValueError("max_nodes must be a positive integer.")
        limit = min(max_nodes, MAX_OUTLINE_NODES)
        with self._session() as uia:
            window, hwnd = self._pick_window(uia, app)
            ident = self._identity(window)
            self._require_not_elevated(ident.pids, ident.name)
            return self._walk(uia, window, hwnd, limit)

    def _walk(self, uia: Any, root: Any, hwnd: int, limit: int) -> list[Node]:
        """Depth-first, in screen-reader order, at most *limit* nodes.
        Zero-size subtrees are dropped, unnamed structural containers (panes,
        groups) are flattened away (their children are lifted to the nearest
        node above), and secure values are never read. Off-screen elements are
        dropped with their subtree, except text fields: those are kept,
        marked ``offscreen`` and not descended into, so the toolkit's payment
        scan still sees a card field scrolled out of view."""
        value_pattern = _pattern_id(uia, "ValuePattern")
        deadline = self._clock() + WALK_BUDGET_S
        top = _Draft({})  # holds the window node
        emitted = 0
        # (control, child-index path, raw depth, draft its node goes under)
        stack: list[tuple[Any, tuple[int, ...], int, _Draft]] = [(root, (), 0, top)]
        visited = 0
        while stack and emitted < limit:
            ctl, path, raw_depth, parent = stack.pop()
            visited += 1
            if visited > MAX_VISITED or self._clock() > deadline:
                logger.info("windows_outline_budget_reached", visited=visited, nodes=emitted)
                break
            try:
                control_type = int(ctl.ControlType)
                if path and control_type in _SKIP_SUBTREE_TYPES:
                    continue
                bounds = _bounds(ctl.BoundingRectangle)
                if path and (bounds[2] <= 0 or bounds[3] <= 0):
                    continue
                offscreen = bool(path) and bool(ctl.IsOffscreen)
                if offscreen and control_type not in _FIELD_TYPES:
                    continue
                name = _clean(ctl.Name)
                draft = parent
                if not path or control_type in _INTERACTIVE_TYPES or name:
                    secure = _is_secure(ctl)
                    draft = _Draft(
                        {
                            "role": _node_role(control_type, ctl, secure),
                            "name": name,
                            "value": (
                                None if secure else _read_value(ctl, control_type, value_pattern)
                            ),
                            "secure": secure,
                            "bounds": bounds,
                            "focused": _has_focus(ctl),
                            "enabled": _is_enabled(ctl),
                            "offscreen": offscreen,
                            "handle": _ElementRef(hwnd, path, control_type, name, _runtime_id(ctl)),
                        }
                    )
                    parent.children.append(draft)
                    emitted += 1
                    if offscreen or secure:
                        continue
                children = list(ctl.GetChildren() or []) if raw_depth < MAX_RAW_DEPTH else []
            except Exception as exc:  # a vanished or unreadable element: skip its subtree
                _log_failure("windows_outline_node_failed", exc)
                continue
            for index in range(len(children) - 1, -1, -1):
                stack.append((children[index], (*path, index), raw_depth + 1, draft))
        return [draft.freeze() for draft in top.children]

    def focused(self) -> Node | None:
        """The element with keyboard focus, or None when there is none. An
        element whose password flag cannot be read counts as secure, and a
        failure to ask raises (the toolkit then refuses to type)."""
        with self._session() as uia:
            ctl = uia.GetFocusedControl()
            if ctl is None:
                return None
            control_type = int(ctl.ControlType)
            secure = _is_secure(ctl)
            return Node(
                role=_node_role(control_type, ctl, secure),
                name=_clean(ctl.Name),
                value=(
                    None
                    if secure
                    else _read_value(ctl, control_type, _pattern_id(uia, "ValuePattern"))
                ),
                secure=secure,
                focused=True,
            )

    # Acting ------------------------------------------------------------------

    def click(self, node_or_point: ClickTarget, *, double: bool = False) -> None:
        if isinstance(node_or_point, Node):
            located = self._invoke_or_locate(node_or_point, double=double)
            if located is None:
                return
            point, owner = located
            self._click_at(point, double=double, owner=owner)
        else:
            # A point click belongs to the window in front (the app the
            # toolkit checked): refuse when another window covers the point.
            point = _as_point(node_or_point)
            with self._session() as uia:
                foreground = self._w32.foreground_window()
                if not foreground:
                    raise LookupError("No window is in front to click in.")
                ident = self._foreground_identity(uia, "click in")
            self._click_at(point, double=double, owner=_Owner(foreground, ident.pids, ident.name))

    def _invoke_or_locate(self, node: Node, *, double: bool) -> tuple[Point, _Owner] | None:
        """Invoke a button-like element through UIA (no pointer movement), or
        return the element's current centre, and the window that must be
        under it, for a real click."""
        with self._session() as uia:
            ctl, window = self._resolve(uia, node)
            ident = self._identity(window)
            pids = (*ident.pids, _pid(ctl))
            self._require_not_elevated(pids, ident.name)
            if not double and int(ctl.ControlType) in _INVOKE_TYPES:
                pattern = _get_pattern(ctl, _pattern_id(uia, "InvokePattern"))
                if pattern is not None:
                    pattern.Invoke()
                    return None
            owner = _Owner(node.handle.window, pids, ident.name)
            return self._visible_center(ctl, node), owner

    def _visible_center(self, ctl: Any, node: Node) -> Point:
        bounds = _bounds(ctl.BoundingRectangle)
        if bool(ctl.IsOffscreen) or bounds[2] <= 0 or bounds[3] <= 0:
            label = node.name or node.role
            raise StaleElementError(
                f'"{label}" is not visible on screen; scroll it into view and observe again.'
            )
        return _center(bounds)

    def _click_at(self, point: Point, *, double: bool, owner: _Owner | None = None) -> None:
        x, y = point
        width, height = self._w32.screen_size()
        if not (0 <= x < width and 0 <= y < height):
            raise ValueError(f"({x}, {y}) is outside the main display ({width}x{height}).")
        if owner is not None:
            self._require_uncovered(x, y, owner)
        self._require_point_not_elevated(x, y)
        inputs = [
            mouse_input(
                _absolute(x, width), _absolute(y, height), MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
            )
        ]
        for _ in range(2 if double else 1):
            inputs.append(mouse_input(0, 0, MOUSEEVENTF_LEFTDOWN))
            inputs.append(mouse_input(0, 0, MOUSEEVENTF_LEFTUP))
        self._send(inputs)

    def type_text(self, text: str, target: Node | None) -> None:
        _check_text(text)
        click: tuple[Point, _Owner] | None = None
        with self._session() as uia:
            if target is not None:
                if target.secure:
                    raise SecureFieldError(_SECURE_MESSAGE)
                ctl, window = self._resolve(uia, target)
                if _is_secure(ctl):
                    raise SecureFieldError(_SECURE_MESSAGE)
                ident = self._identity(window)
                owner = _Owner(target.handle.window, (*ident.pids, _pid(ctl)), ident.name)
                self._require_not_elevated(owner.pids, ident.name)
                if not _set_focus(ctl):
                    click = (self._visible_center(ctl, target), owner)
                elif not self._bring_to_front(owner):
                    # Keys go to the window in front; UIA focus alone does
                    # not guarantee that is the target's window.
                    raise OSError(
                        f"Windows did not let Crawler bring {ident.name} to the front, "
                        "so it did not type."
                    )
            else:
                ident = self._foreground_identity(uia, "type into")
                self._require_not_elevated(ident.pids, ident.name)
        if click is not None:
            self._click_at(click[0], double=False, owner=click[1])
        with self._session() as uia:
            self._require_focus_not_secure(uia)
        self._send_text(text)

    def key(self, combo: KeyCombo) -> None:
        modifiers, vk = combo_vks(combo)
        with self._session() as uia:
            ident = self._foreground_identity(uia, "send keys to")
            self._require_not_elevated(ident.pids, ident.name)
        inputs = [self._vk_input(m, up=False) for m in modifiers]
        inputs += [self._vk_input(vk, up=False), self._vk_input(vk, up=True)]
        inputs += [self._vk_input(m, up=True) for m in reversed(modifiers)]
        self._send(inputs)

    def scroll(self, direction: str, amount: int) -> None:
        if direction not in ("up", "down", "left", "right"):
            raise ValueError("direction must be up, down, left or right.")
        if not _is_int(amount) or not 1 <= amount <= MAX_SCROLL:
            raise ValueError(f"amount must be a whole number from 1 to {MAX_SCROLL}.")
        width, height = self._w32.screen_size()
        with self._session() as uia:
            foreground = self._w32.foreground_window()
            if not foreground:
                raise LookupError("No window is in front to scroll.")
            window = uia.ControlFromHandle(foreground)
            try:
                box = _bounds(window.BoundingRectangle) if window is not None else None
            except Exception as exc:  # scroll where the pointer is
                _log_failure("windows_scroll_bounds_failed", exc)
                box = None
        x, y = self._w32.cursor_pos()
        inputs: list[INPUT] = []
        # The wheel goes to the window under the pointer. If the pointer is
        # outside the window in front, move it to that window's centre first
        # so the scroll lands where the agent is working.
        if box is not None and box[2] > 0 and box[3] > 0:
            bx, by, bw, bh = box
            if not (bx <= x < bx + bw and by <= y < by + bh):
                cx, cy = _center(box)
                x, y = min(max(cx, 0), width - 1), min(max(cy, 0), height - 1)
                inputs.append(
                    mouse_input(
                        _absolute(x, width),
                        _absolute(y, height),
                        MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    )
                )
        self._require_point_not_elevated(x, y)
        flag = MOUSEEVENTF_WHEEL if direction in ("up", "down") else MOUSEEVENTF_HWHEEL
        delta = WHEEL_DELTA if direction in ("up", "right") else -WHEEL_DELTA
        # One event per notch: some apps handle a single notch per message.
        inputs += [mouse_input(0, 0, flag, delta) for _ in range(amount)]
        self._send(inputs)

    def open_app(self, name: str) -> None:
        query = _check_app_query(name)
        key = _launch_key(query)
        if _launch_blocked(query):
            raise _blocked_app_error(
                _blocked_launch_message(query), rules.blocked_app(query) or query
            )
        if not _APP_NAME_RE.fullmatch(query):
            raise ValueError(
                "open_app takes an app name only (no paths, links, arguments or special characters)."
            )
        shortcut = self._find_shortcut(key)
        if shortcut is not None:
            target = str(shortcut)
        else:
            # Bare names go to ShellExecute's PATH / App Paths lookup, so
            # anything that is not an app (a script, a document, a .msc
            # snap-in) is refused rather than opened.
            if PureWindowsPath(query).suffix.casefold() not in ("", ".exe"):
                raise ValueError(f"{query!r} is not an app name.")
            target = _LAUNCH_ALIASES.get(key, query)
            if _launch_blocked(target):
                raise _blocked_app_error(
                    _blocked_launch_message(query), rules.blocked_app(query) or query
                )
        code = self._w32.shell_execute(target, os.environ.get("USERPROFILE") or None)
        if code <= 32:
            if code in (2, 3):  # ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
                raise WindowsAppNotFoundError(f"No app called {query!r} was found.")
            raise OSError(f"Windows could not open {query!r} (error {code}).")

    def focus_window(self, app: str, index: int) -> None:
        query = _check_app_query(app)
        if not _is_int(index) or index < 0:
            raise ValueError("index must be 0 or greater.")
        with self._session() as uia:
            matches = [
                (ctl, ident) for ctl, ident in self._app_windows(uia) if _matches(query, ident)
            ]
            if not matches:
                raise WindowsAppNotFoundError(f"No open window belongs to {query!r}.")
            if index >= len(matches):
                raise WindowsAppNotFoundError(
                    f"{matches[0][1].name} has {len(matches)} window(s); there is no window {index}."
                )
            ctl, ident = matches[index]
            # The query may have matched an executable stem the toolkit's
            # blocked-app rule never saw ("pwsh", "OpenConsole"): re-check
            # what the window really is before raising it.
            for name in (ident.name, ident.stem):
                blocked = rules.blocked_app(name) if name else None
                if blocked:
                    raise _blocked_app_error(
                        f"Crawler does not switch to {ident.name}: shells, terminals, system "
                        "settings, admin tools and password managers are off limits.",
                        blocked,
                    )
            self._require_not_elevated(ident.pids, ident.name)
            hwnd = _hwnd(ctl)
            if not hwnd:
                raise LookupError(_STALE_MESSAGE)
            if self._w32.is_iconic(hwnd):
                self._w32.restore_window(hwnd)
            if not self._w32.set_foreground_window(hwnd):
                # Windows' foreground lock can refuse a background process;
                # UIA's SetFocus on the window is allowed to activate it.
                _set_focus(ctl)
            foreground = self._w32.foreground_window()
            if foreground != hwnd and self._w32.window_pid(foreground) not in ident.pids:
                raise OSError(f"Windows did not let Crawler bring {ident.name} to the front.")

    # Internals -----------------------------------------------------------------

    def _app_windows(self, uia: Any) -> list[tuple[Any, _AppId]]:
        """Top-level app windows, front to back, with their app identity.
        Minimised windows are included (focus_window restores them)."""
        windows = []
        for ctl in uia.GetRootControl().GetChildren() or []:
            try:
                if not _clean(ctl.Name) or _class_name(ctl) in _SHELL_CLASSES:
                    continue
                windows.append((ctl, self._identity(ctl)))
            except Exception as exc:
                _log_failure("windows_list_window_failed", exc)
        return windows

    def _pick_window(self, uia: Any, app: str | None) -> tuple[Any, int]:
        foreground = self._w32.foreground_window()
        if app is None:
            window = uia.ControlFromHandle(foreground) if foreground else None
            if window is None:
                raise LookupError("No window is in front right now.")
            return window, foreground
        query = _check_app_query(app)
        if foreground:
            window = uia.ControlFromHandle(foreground)
            if window is not None and _matches(query, self._identity(window)):
                return window, foreground
        for ctl, ident in self._app_windows(uia):
            if _matches(query, ident):
                return ctl, _hwnd(ctl)
        raise WindowsAppNotFoundError(f"No open window belongs to {query!r}.")

    def _foreground_identity(self, uia: Any, verb: str) -> _AppId:
        foreground = self._w32.foreground_window()
        if not foreground:
            raise LookupError(f"No window is in front to {verb}.")
        window = uia.ControlFromHandle(foreground)
        if window is None:
            return self._process_identity(self._w32.window_pid(foreground))
        return self._identity(window)

    def _resolve(self, uia: Any, node: Node) -> tuple[Any, Any]:
        """(element, its top-level window) for a node from an earlier outline,
        or StaleElementError when it is gone or no longer the same element."""
        ref = node.handle
        if not isinstance(ref, _ElementRef):
            raise TypeError("This element did not come from the Windows backend.")
        try:
            window = uia.ControlFromHandle(ref.window) if ref.window else None
            ctl = window
            for index in ref.path:
                if ctl is None:
                    break
                children = list(ctl.GetChildren() or [])
                ctl = children[index] if index < len(children) else None
            if (
                ctl is None
                or int(ctl.ControlType) != ref.control_type
                or _clean(ctl.Name) != ref.name
            ):
                raise StaleElementError(_STALE_MESSAGE)
            live_id = _runtime_id(ctl)
            if ref.runtime_id is not None and live_id is not None and live_id != ref.runtime_id:
                raise StaleElementError(_STALE_MESSAGE)
        except StaleElementError:
            raise
        except Exception as exc:
            _log_failure("windows_resolve_failed", exc)
            raise StaleElementError(_STALE_MESSAGE) from exc
        return ctl, window

    def _identity(self, window: Any) -> _AppId:
        """Which app a top-level window belongs to, named the way the
        toolkit's rules spell it."""
        pid = _pid(window)
        by_class = _WINDOW_CLASS_APPS.get(_class_name(window))
        if by_class:
            return _AppId(by_class, "", (pid,))
        image = self._w32.process_image(pid) if pid > 0 else None
        stem = PureWindowsPath(image).stem if image else ""
        if stem.casefold() == _UWP_FRAME_HOST:
            # UWP apps (Calculator, Settings) live in a frame owned by
            # ApplicationFrameHost; the app is the process of the inner
            # CoreWindow. Input can reach both, so both pids are checked.
            inner = self._uwp_inner_pid(window, pid)
            if inner:
                inner_id = self._process_identity(inner)
                return _AppId(inner_id.name, inner_id.stem, (pid, inner))
            title = _clean(window.Name)
            return _AppId(_UWP_TITLE_APPS.get(title.casefold(), title or "App"), stem, (pid,))
        return self._process_identity(pid, image)

    def _uwp_inner_pid(self, window: Any, frame_pid: int) -> int:
        try:
            for child in window.GetChildren() or []:
                if _class_name(child) == _UWP_CORE_WINDOW:
                    inner = _pid(child)
                    if inner and inner != frame_pid:
                        return inner
        except Exception as exc:
            _log_failure("windows_uwp_lookup_failed", exc)
        return 0

    def _process_identity(self, pid: int, image: str | None = None) -> _AppId:
        if image is None and pid > 0:
            image = self._w32.process_image(pid)
        if not image:
            return _AppId(f"process {pid}", "", (pid,))
        stem = PureWindowsPath(image).stem
        known = _KNOWN_APPS.get(stem.casefold())
        if known:
            return _AppId(known, stem, (pid,))
        if image not in self._descriptions:
            try:
                self._descriptions[image] = self._w32.file_description(image)
            except Exception as exc:
                _log_failure("windows_file_description_failed", exc)
                self._descriptions[image] = None
        return _AppId(_clean(self._descriptions[image]) or stem, stem, (pid,))

    def _require_not_elevated(self, pids: Iterable[int], app: str) -> None:
        """UIPI: refuse when any target process is elevated, or when Windows
        will not say (fail closed; from a normal process that usually means
        the target is elevated)."""
        for pid in dict.fromkeys(pids):
            state = self._w32.process_elevated(pid) if pid > 0 else None
            if state is False:
                continue
            logger.info("windows_uipi_refused", app=app, pid=pid, elevated=state)
            raise UIPIBlockedError(_uipi_message(app, known=state is True))

    def _owns(self, hwnd: int, owner: _Owner) -> bool:
        return bool(hwnd) and (hwnd == owner.window or self._w32.window_pid(hwnd) in owner.pids)

    def _bring_to_front(self, owner: _Owner) -> bool:
        if self._owns(self._w32.foreground_window(), owner):
            return True
        self._w32.set_foreground_window(owner.window)
        return self._owns(self._w32.foreground_window(), owner)

    def _require_uncovered(self, x: int, y: int, owner: _Owner) -> None:
        """A click on an element must land on that element's window, not on
        whatever covers it (which may be an app the toolkit would refuse)."""
        if self._owns(self._w32.window_at(x, y), owner):
            return
        self._w32.set_foreground_window(owner.window)
        if self._owns(self._w32.window_at(x, y), owner):
            return
        raise CoveredError(
            f"That spot in {owner.app} is covered by another window; bring {owner.app} "
            "to the front and observe again."
        )

    def _require_point_not_elevated(self, x: int, y: int) -> None:
        hwnd = self._w32.window_at(x, y)
        if not hwnd:
            raise LookupError(f"There is no window at ({x}, {y}).")
        pid = self._w32.window_pid(hwnd)
        self._require_not_elevated((pid,), self._process_identity(pid).name)

    def _require_focus_not_secure(self, uia: Any) -> None:
        try:
            focused = uia.GetFocusedControl()
        except Exception as exc:
            _log_failure("windows_focus_read_failed", exc)
            raise SecureFieldError(_FOCUS_UNKNOWN_MESSAGE) from exc
        if focused is None:
            # Nothing reports focus: keys typed blind land wherever it is.
            raise SecureFieldError(_FOCUS_UNKNOWN_MESSAGE)
        if _is_secure(focused):
            raise SecureFieldError(_SECURE_MESSAGE)

    def _find_shortcut(self, key: str) -> Path | None:
        """A Start Menu shortcut named like the app ("Visual Studio Code"),
        which is how most installed apps can be opened by their display name."""
        dirs = (
            self._start_menu_dirs
            if self._start_menu_dirs is not None
            else _default_start_menu_dirs()
        )
        scanned = 0
        for base in dirs:
            try:
                if not base.is_dir():
                    continue
                for path in sorted(base.rglob("*.lnk")):
                    scanned += 1
                    if scanned > _MAX_SHORTCUTS_SCANNED:
                        return None
                    if path.stem.casefold() == key:
                        return path
            except OSError as exc:
                _log_failure("windows_start_menu_scan_failed", exc)
        return None

    def _vk_input(self, vk: int, *, up: bool) -> INPUT:
        flags = (KEYEVENTF_KEYUP if up else 0) | (
            KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED_VKS else 0
        )
        return key_input(vk, self._w32.scan_code(vk), flags)

    def _text_batches(self, text: str) -> list[tuple[list[INPUT], bool]]:
        """SendInput batches for ``text``, each flagged when it ends with a key
        that can move focus.

        Line breaks and tabs are real Enter and Tab presses (apps expect
        those, not a typed U+000A); everything else is KEYEVENTF_UNICODE, one
        down/up per UTF-16 code unit, so characters outside the BMP (emoji)
        go through as their surrogate pair. A batch ends after at most
        TEXT_CHUNK_CHARS characters, and right after every Tab or Enter.
        """
        batches: list[tuple[list[INPUT], bool]] = []
        current: list[INPUT] = []
        count = 0
        for ch in text.replace("\r\n", "\n").replace("\r", "\n"):
            vk = VK_RETURN if ch == "\n" else VK_TAB if ch == "\t" else None
            if vk is not None:
                current += [self._vk_input(vk, up=False), self._vk_input(vk, up=True)]
            else:
                encoded = ch.encode("utf-16-le")
                for offset in range(0, len(encoded), 2):
                    unit = int.from_bytes(encoded[offset : offset + 2], "little")
                    current.append(key_input(0, unit, KEYEVENTF_UNICODE))
                    current.append(key_input(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP))
            count += 1
            if vk is not None or count >= TEXT_CHUNK_CHARS:
                batches.append((current, vk is not None))
                current, count = [], 0
        if current:
            batches.append((current, False))
        return batches

    def _send_text(self, text: str) -> None:
        """Type in batches. Before every batch after the first, the same
        window must still be in front and the focused element must not be a
        password field: a Tab in "alice<Tab>hunter2" moves focus from the
        user name to the password field, and the rest must not follow it."""
        window = self._w32.foreground_window()
        batches = self._text_batches(text)
        for index, (inputs, _) in enumerate(batches):
            if index:
                moved_focus = batches[index - 1][1]
                self._sleep(FOCUS_SETTLE_S if moved_focus else TEXT_CHUNK_PAUSE_S)
                with self._session() as uia:
                    if self._w32.foreground_window() != window:
                        raise OSError(
                            "The window in front changed while typing, so Crawler stopped."
                        )
                    self._require_focus_not_secure(uia)
            self._send(inputs)

    def _send(self, inputs: list[INPUT]) -> None:
        if not inputs:
            return
        sent = self._w32.send_input(inputs)
        if sent != len(inputs):
            raise OSError(
                "Windows blocked the input (the screen may be locked, or a system prompt is in front)."
            )


if TYPE_CHECKING:  # mypy proves WindowsBackend implements the protocol exactly

    def _conforms(backend: WindowsBackend) -> ComputerBackend:
        return backend
