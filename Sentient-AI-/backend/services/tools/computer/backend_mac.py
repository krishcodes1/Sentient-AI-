"""Implements the macOS ComputerBackend for computer_control: reads the
accessibility tree of an app's focused window and operates it with AXPress,
synthetic Quartz events and NSWorkspace.

Why it exists: desktop.observe / desktop.act need one concrete way to see and
drive native Mac apps. Every pyobjc call goes through an injectable ``PyObjC``
bundle, so the unit tests run this whole module against fakes and no test
ever posts a real click or keystroke or reads the real accessibility tree.

Frameworks used (spec section 5): ``ApplicationServices`` for the AXUIElement
tree and the Accessibility trust check, ``Quartz`` for CGEvent mouse,
keyboard and scroll-wheel events (and the live window list), ``AppKit`` for
NSWorkspace / NSRunningApplication.

The toolkit enforces the hard rules before calling in. This backend repeats
the ones only it can check reliably, as defence in depth:

- the value of a secure text field (subrole ``AXSecureTextField``) is never
  read; a text field whose subrole cannot be read is treated as secure;
- text is never typed into a secure field, whether it was targeted by ref or
  merely has keyboard focus, and focus is re-checked before every chunk (after
  a pause when a typed Return or Tab may have moved it); when focus cannot be
  read at all, nothing is typed;
- open_app and focus_window refuse an app that resolves to a blocked one
  (``rules.blocked_app``) by its bundle name, localized name or bundle id, so
  a localized spelling the toolkit could not recognise does not get through;
- a synthetic click is sent only when the element under the point belongs to
  the frontmost app (another app's window on top, or an unanswerable check,
  refuses);
- acting refuses up front when the process is not trusted for Accessibility
  (macOS would otherwise drop the events silently);
- modifier keys pressed for a combo are always released, even on error.

Limitation: ``key()`` uses ANSI (US layout) virtual key codes, so a letter
shortcut lands on the physical key a US keyboard has there.
"""

from __future__ import annotations

import inspect
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Literal, Optional, cast

import structlog

from services.tools.computer import rules
from services.tools.computer.backend import (
    AppInfo,
    AppNotFoundError,
    BlockedTargetError,
    Bounds,
    ClickTarget,
    ComputerBackend,
    CoveredTargetError,
    ElementGoneError,
    KeyCombo,
    Node,
    PermissionState,
    SecureTargetError,
    WindowInfo,
)

logger = structlog.get_logger(__name__)

ACCESSIBILITY_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
)

MAX_TEXT_CHARS = 2000
# CGEventKeyboardSetUnicodeString: longer strings are truncated by the
# event system, so text goes out in chunks of at most this many UTF-16 units.
UNICODE_CHUNK_UNITS = 20
MAX_SCROLL_LINES = 50
MAX_DEPTH = 40
MAX_VALUE_CHARS = 2000
MAX_NAME_CHARS = 300
# Elements examined per emitted node before the walk gives up: unnamed
# containers and off-screen rows cost reads but produce no lines.
VISIT_FACTOR = 10
AX_MESSAGING_TIMEOUT_S = 1.0
OUTLINE_DEADLINE_S = 5.0
OPEN_APP_WAIT_S = 5.0
# Pause after every posted event so the target app neither coalesces nor
# drops a burst of synthetic input.
EVENT_GAP_S = 0.008
FOCUS_SETTLE_S = 0.05
# After a typed Return or Tab (which can move focus, e.g. from a user name
# field to a password field) the app gets this long to handle it before focus
# is read again and typing goes on. Matches the Windows backend.
KEY_SETTLE_S = 0.15
POLL_INTERVAL_S = 0.1

# --- Apple constants -----------------------------------------------------
# Literal values (ABI-stable, from the SDK headers) so the fakes in the
# tests need not define them; a test checks each against real pyobjc.
AX_SUCCESS = 0  # kAXErrorSuccess
AX_ERR_INVALID_ELEMENT = -25202  # kAXErrorInvalidUIElement
AX_ERR_ATTRIBUTE_UNSUPPORTED = -25205  # kAXErrorAttributeUnsupported
AX_ERR_API_DISABLED = -25211  # kAXErrorAPIDisabled
AX_ERR_NO_VALUE = -25212  # kAXErrorNoValue
AX_VALUE_CGPOINT = 1  # kAXValueCGPointType
AX_VALUE_CGSIZE = 2  # kAXValueCGSizeType

CG_HID_EVENT_TAP = 0  # kCGHIDEventTap
CG_LEFT_MOUSE_DOWN = 1  # kCGEventLeftMouseDown
CG_LEFT_MOUSE_UP = 2  # kCGEventLeftMouseUp
CG_MOUSE_MOVED = 5  # kCGEventMouseMoved
CG_MOUSE_BUTTON_LEFT = 0  # kCGMouseButtonLeft
CG_MOUSE_CLICK_STATE = 1  # kCGMouseEventClickState
CG_SCROLL_UNIT_LINE = 1  # kCGScrollEventUnitLine
CG_WINDOW_LIST_ALL = 0  # kCGWindowListOptionAll
CG_WINDOW_LIST_EXCLUDE_DESKTOP = 16  # kCGWindowListExcludeDesktopElements
CG_NULL_WINDOW_ID = 0  # kCGNullWindowID
CG_WINDOW_OWNER_PID = "kCGWindowOwnerPID"
CG_WINDOW_LAYER = "kCGWindowLayer"

NS_ACTIVATION_POLICY_REGULAR = 0  # NSApplicationActivationPolicyRegular
NS_ACTIVATE_IGNORING_OTHER_APPS = 2  # NSApplicationActivateIgnoringOtherApps

# --- Keys ------------------------------------------------------------------
# Modifier -> (event flag mask, virtual key code of the left-hand key).
MODIFIERS: dict[str, tuple[int, int]] = {
    "ctrl": (0x40000, 0x3B),  # kCGEventFlagMaskControl, kVK_Control
    "alt": (0x80000, 0x3A),  # kCGEventFlagMaskAlternate, kVK_Option
    "shift": (0x20000, 0x38),  # kCGEventFlagMaskShift, kVK_Shift
    "cmd": (0x100000, 0x37),  # kCGEventFlagMaskCommand, kVK_Command
}
_MODIFIER_ORDER = ("ctrl", "alt", "shift", "cmd")
_MODIFIER_ALIASES = {
    "cmd": "cmd",
    "command": "cmd",
    "⌘": "cmd",
    "ctrl": "ctrl",
    "control": "ctrl",
    "⌃": "ctrl",
    "alt": "alt",
    "option": "alt",
    "opt": "alt",
    "⌥": "alt",
    "shift": "shift",
    "⇧": "shift",
}
_FORBIDDEN_MODIFIERS = frozenset({"fn", "function", "globe"})

# kVK_ANSI_* codes for printable keys (US layout positions).
_CHAR_KEYCODES: dict[str, int] = {
    "a": 0x00, "s": 0x01, "d": 0x02, "f": 0x03, "h": 0x04, "g": 0x05, "z": 0x06,
    "x": 0x07, "c": 0x08, "v": 0x09, "b": 0x0B, "q": 0x0C, "w": 0x0D, "e": 0x0E,
    "r": 0x0F, "y": 0x10, "t": 0x11, "o": 0x1F, "u": 0x20, "i": 0x22, "p": 0x23,
    "l": 0x25, "j": 0x26, "k": 0x28, "n": 0x2D, "m": 0x2E,
    "1": 0x12, "2": 0x13, "3": 0x14, "4": 0x15, "6": 0x16, "5": 0x17, "9": 0x19,
    "7": 0x1A, "8": 0x1C, "0": 0x1D,
    "=": 0x18, "-": 0x1B, "]": 0x1E, "[": 0x21, "'": 0x27, ";": 0x29, "\\": 0x2A,
    ",": 0x2B, "/": 0x2C, ".": 0x2F, "`": 0x32, " ": 0x31,
}  # fmt: skip

# Named keys (kVK_*). Names are matched lower-case with spaces, "_" and "-"
# removed, so "Page Down", "page_down" and "pagedown" are the same key.
_NAMED_KEYCODES: dict[str, int] = {
    # The shared grammar (keys.py): "backspace" deletes to the left (the Mac
    # key labelled delete), "delete" deletes to the right (forward delete).
    "return": 0x24, "enter": 0x24, "tab": 0x30, "space": 0x31,
    "backspace": 0x33, "escape": 0x35, "esc": 0x35,
    "delete": 0x75, "del": 0x75, "forwarddelete": 0x75, "home": 0x73, "end": 0x77,
    # "plus" is the =/+ key (cmd+plus zooms in), as on Windows (VK_OEM_PLUS).
    "plus": 0x18,
    "pageup": 0x74, "pagedown": 0x79,
    "left": 0x7B, "right": 0x7C, "down": 0x7D, "up": 0x7E,
    "arrowleft": 0x7B, "arrowright": 0x7C, "arrowdown": 0x7D, "arrowup": 0x7E,
    "leftarrow": 0x7B, "rightarrow": 0x7C, "downarrow": 0x7D, "uparrow": 0x7E,
    "f1": 0x7A, "f2": 0x78, "f3": 0x63, "f4": 0x76, "f5": 0x60, "f6": 0x61,
    "f7": 0x62, "f8": 0x64, "f9": 0x65, "f10": 0x6D, "f11": 0x67, "f12": 0x6F,
    "f13": 0x69, "f14": 0x6B, "f15": 0x71, "f16": 0x6A, "f17": 0x40, "f18": 0x4F,
    "f19": 0x50, "f20": 0x5A,
    "minus": 0x1B, "equal": 0x18, "equals": 0x18, "leftbracket": 0x21,
    "rightbracket": 0x1E, "backslash": 0x2A, "semicolon": 0x29, "quote": 0x27,
    "apostrophe": 0x27, "comma": 0x2B, "period": 0x2F, "dot": 0x2F, "slash": 0x2C,
    "grave": 0x32, "backtick": 0x32,
}  # fmt: skip

# --- Outline shaping --------------------------------------------------------
_TEXT_ENTRY_ROLES = frozenset({"AXTextField", "AXTextArea", "AXComboBox", "AXSecureTextField"})
# A secure field can only be one of these; for them an unreadable subrole
# means "treat as secure" rather than "read the value anyway".
_MAYBE_SECURE_ROLES = frozenset({"AXTextField", "AXComboBox", "AXSecureTextField"})
_SECURE_SUBROLE = "AXSecureTextField"
# Emitted only when they carry a name or a value; their children are always
# walked (and take their place in the indentation).
_QUIET_WHEN_EMPTY = frozenset(
    {
        "AXGroup",
        "AXSplitGroup",
        "AXScrollArea",
        "AXLayoutArea",
        "AXLayoutItem",
        "AXUnknown",
        "AXSplitter",
        "AXImage",
        "AXStaticText",
        "AXGrowArea",
        "AXMatte",
    }
)
# Never emitted nor walked: pure chrome with nothing the agent should act on.
_SKIPPED_SUBTREES = frozenset({"AXScrollBar"})
# Children outside these elements' bounds are not visible (scrolled away).
_CLIPPING_ROLES = frozenset({"AXWindow", "AXSheet", "AXDrawer", "AXScrollArea"})
_TOGGLE_ROLES = frozenset({"AXCheckBox", "AXRadioButton"})
_TOGGLE_SUBROLES = frozenset({"AXSwitch", "AXToggle"})
_TOGGLE_STATES = {0: "off", 1: "on", 2: "mixed"}

# Labels follow the shared role vocabulary in backend.py; anything not
# listed is the AX role in plain words ("AXRadioButton" -> "radio button").
_ROLE_LABELS = {
    "AXStaticText": "text",
    "AXCheckBox": "checkbox",
    "AXPopUpButton": "pop up button",
    "AXTextField": "text field",
    "AXTextArea": "text area",
    "AXComboBox": "combo box",
    "AXSecureTextField": "secure text field",
}
_SUBROLE_LABELS = {
    "AXSecureTextField": "secure text field",
    "AXSearchField": "search field",
    "AXCloseButton": "close button",
    "AXMinimizeButton": "minimize button",
    "AXZoomButton": "zoom button",
    "AXFullScreenButton": "full screen button",
    "AXSwitch": "switch",
    "AXToggle": "toggle button",
}
_CAMEL_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

_NOT_TRUSTED = (
    "macOS has not granted Accessibility to Crawler. Open System Settings → "
    "Privacy & Security → Accessibility and turn it on for the Crawler process."
)
_SECURE_REFUSAL = (
    "That is a password field. Crawler never types into password fields; "
    "the owner has to fill it in."
)
_FOCUS_UNKNOWN = (
    "Crawler could not tell which field has keyboard focus, so it did not type "
    "(it never types blind, in case it is a password field)."
)
_COVERED = (
    "Another app's window is over that spot (or macOS would not say whose window it "
    "is), so Crawler did not click."
)
_STALE = "That element is no longer on screen. Observe again and use a fresh ref."
_LOG_DETAIL_CHARS = 200


class MacElementGoneError(ElementGoneError, LookupError):
    """The AXUIElement behind a ref is gone (kAXErrorInvalidUIElement)."""


class MacAppNotFoundError(AppNotFoundError, LookupError):
    """No running (or, for open_app, installed) app or window by that name."""


class MacSecureFieldError(SecureTargetError, PermissionError):
    """The target, or the element with keyboard focus, is (or may be) a
    password field. Still a PermissionError for callers that only know that."""


class MacBlockedAppError(BlockedTargetError):
    """open_app / focus_window resolved to an app the hard rules block."""


class MacCoveredError(CoveredTargetError):
    """The element under a synthetic click is not the frontmost app's."""


# --- pyobjc access ---------------------------------------------------------


@dataclass(frozen=True)
class PyObjC:
    """The three pyobjc framework modules this backend calls.

    Injected as a unit so tests hand the backend fakes for every entry point
    and nothing reaches the real window server.
    """

    ax: Any  # ApplicationServices (HIServices: AXUIElement*, AXValue*, AXIsProcessTrusted*)
    quartz: Any  # Quartz (CoreGraphics: CGEvent*, CGWindowList*)
    appkit: Any  # AppKit (NSWorkspace, NSRunningApplication, NSURL, ...)


def load_pyobjc() -> PyObjC:
    """Import the real frameworks. Raises ImportError when pyobjc is absent."""
    import AppKit
    import ApplicationServices
    import Quartz

    return PyObjC(ax=ApplicationServices, quartz=Quartz, appkit=AppKit)


# Every symbol the backend touches, per module; available() reports the
# first missing ones instead of failing mid-action on an old pyobjc.
REQUIRED_SYMBOLS: dict[str, tuple[str, ...]] = {
    "ax": (
        "AXIsProcessTrusted",
        "AXIsProcessTrustedWithOptions",
        "kAXTrustedCheckOptionPrompt",
        "AXUIElementCreateApplication",
        "AXUIElementCreateSystemWide",
        "AXUIElementCopyAttributeValue",
        "AXUIElementCopyElementAtPosition",
        "AXUIElementCopyActionNames",
        "AXUIElementPerformAction",
        "AXUIElementSetAttributeValue",
        "AXUIElementSetMessagingTimeout",
        "AXUIElementGetPid",
        "AXValueGetValue",
    ),
    "quartz": (
        "CGEventCreateMouseEvent",
        "CGEventCreateKeyboardEvent",
        "CGEventKeyboardSetUnicodeString",
        "CGEventCreateScrollWheelEvent",
        "CGEventSetFlags",
        "CGEventSetIntegerValueField",
        "CGEventPost",
        "CGWindowListCopyWindowInfo",
    ),
    "appkit": (
        "NSWorkspace",
        "NSRunningApplication",
        "NSURL",
        "NSWorkspaceOpenConfiguration",
    ),
}


def _pid_alive(pid: int) -> bool:
    """Whether a process exists. Signal 0 is a permission check, never sent."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


# Built from the constructor, not the dataclass fields, so a Node that
# lacks an optional field (``enabled``) still gets built from the rest.
_NODE_PARAMS = frozenset(inspect.signature(Node).parameters)


def _make_node(**fields: Any) -> Node:
    return Node(**{k: v for k, v in fields.items() if k in _NODE_PARAMS})


@dataclass
class _Draft:
    """A node under construction: the walk is iterative and finds a node's
    children after the node itself, while ``Node`` is frozen."""

    fields: dict[str, Any]
    children: list["_Draft"] = field(default_factory=list)

    def freeze(self) -> Node:
        # Recursion is bounded by MAX_DEPTH.
        return _make_node(**self.fields, children=tuple(c.freeze() for c in self.children))


@dataclass(frozen=True)
class _App:
    # The .app bundle's file name without ".app" ("System Settings",
    # "Terminal"): not localized, so the toolkit's blocked-app rule matches
    # on every system language. Falls back to the localized name.
    name: str
    pid: int
    bundle_id: str
    running: Any  # NSRunningApplication
    localized: str = ""


@dataclass(frozen=True)
class _Described:
    role: str
    subrole: str
    name: str
    value: Optional[str]
    secure: bool
    enabled: bool


# --- Pure helpers ------------------------------------------------------------


def _text(value: Any, limit: int = MAX_NAME_CHARS) -> str:
    if not isinstance(value, str):
        return ""
    return _cap(value.strip(), limit)


def _cap(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _humanize(ax_name: str) -> str:
    bare = ax_name[2:] if ax_name.startswith("AX") else ax_name
    words = _CAMEL_WORD.findall(bare)
    return " ".join(w.lower() for w in words) or "element"


def _role_label(role: str, subrole: str) -> str:
    if subrole in _SUBROLE_LABELS:
        return _SUBROLE_LABELS[subrole]
    return _ROLE_LABELS.get(role) or _humanize(role)


def _format_value(role: str, subrole: str, value: Any) -> Optional[str]:
    if value is None:
        return None
    toggle = role in _TOGGLE_ROLES or subrole in _TOGGLE_SUBROLES
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, int):
        return _TOGGLE_STATES.get(value, str(value)) if toggle else str(value)
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, str):
        return _cap(value, MAX_VALUE_CHARS) if value else None
    return None  # element refs, AXValue structs, URLs: nothing a line can show


def _area(bounds: Bounds) -> int:
    return max(bounds[2], 0) * max(bounds[3], 0)


def _intersect(a: Bounds, b: Bounds) -> Optional[Bounds]:
    left, top = max(a[0], b[0]), max(a[1], b[1])
    right, bottom = min(a[0] + a[2], b[0] + b[2]), min(a[1] + a[3], b[1] + b[3])
    if right <= left or bottom <= top:
        return None
    return (left, top, right - left, bottom - top)


def _centre(bounds: Bounds) -> tuple[int, int]:
    return bounds[0] + bounds[2] // 2, bounds[1] + bounds[3] // 2


def _utf16_units(text: str) -> int:
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in text)


def _utf16_chunks(text: str, limit: int = UNICODE_CHUNK_UNITS) -> Iterator[str]:
    """Split ``text`` into pieces of at most ``limit`` UTF-16 units, never
    cutting a surrogate pair in half."""
    chunk: list[str] = []
    units = 0
    for ch in text:
        width = 2 if ord(ch) > 0xFFFF else 1
        if chunk and units + width > limit:
            yield "".join(chunk)
            chunk, units = [], 0
        chunk.append(ch)
        units += width
    if chunk:
        yield "".join(chunk)


def _segments(text: str) -> list[tuple[Literal["text", "key"], str]]:
    """Text runs to type as Unicode, and the Return/Tab presses between them.

    Line breaks become Return and tabs become Tab (a Unicode "\\n" is not a
    Return keystroke to most apps). Any other control character is refused.
    """
    out: list[tuple[Literal["text", "key"], str]] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            out.append(("text", "".join(run)))
            run.clear()

    for ch in text.replace("\r\n", "\n").replace("\r", "\n"):
        if ch == "\n":
            flush()
            out.append(("key", "return"))
        elif ch == "\t":
            flush()
            out.append(("key", "tab"))
        elif ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0:
            raise ValueError("The text contains a control character that cannot be typed.")
        else:
            run.append(ch)
    flush()
    return out


def _normalize_modifiers(modifiers: Iterable[str]) -> tuple[str, ...]:
    """Canonical modifier names in press order, without duplicates."""
    seen: set[str] = set()
    for raw in modifiers:
        token = str(raw).strip().lower()
        if token in _FORBIDDEN_MODIFIERS:
            raise ValueError("The fn/Globe key is not allowed.")
        if token == "win":
            raise ValueError("A Mac has no Windows key; use cmd, ctrl, alt/option or shift.")
        canonical = _MODIFIER_ALIASES.get(token)
        if canonical is None:
            raise ValueError(f"Unknown modifier {raw!r}; use cmd, ctrl, alt/option or shift.")
        seen.add(canonical)
    return tuple(m for m in _MODIFIER_ORDER if m in seen)


def _key_name(key: str) -> str:
    """The table key for ``key``: a single character, or a squashed name."""
    raw = str(key)
    if len(raw) == 1:
        return raw.lower()
    return re.sub(r"[\s_\-]+", "", raw.strip().lower())


def keycode_for(key: str) -> int:
    """Virtual key code for one key of the combo grammar; ValueError otherwise."""
    name = _key_name(key)
    if name in _FORBIDDEN_MODIFIERS:
        raise ValueError("The fn/Globe key is not allowed.")
    if name in ("insert", "ins"):
        raise ValueError("A Mac keyboard has no Insert key; use cmd+v to paste.")
    code = _CHAR_KEYCODES.get(name)
    if code is None:
        code = _NAMED_KEYCODES.get(name)
    if code is None:
        raise ValueError(f"Unsupported key {key!r}.")
    return code


def _inserts_text(modifiers: tuple[str, ...], key: str) -> bool:
    """Would this combo put characters into the focused field?

    Plain or shifted/option printable keys do, and so does paste (cmd+v).
    Navigation keys (Tab, Return, arrows, Escape) do not, so the agent can
    still move away from a password field.
    """
    name = _key_name(key)
    if "cmd" in modifiers:
        return name == "v"
    if "ctrl" in modifiers:
        return False
    return name in _CHAR_KEYCODES or name == "space"


def _clean_app_name(name: str) -> str:
    clean = str(name or "").strip()
    if clean.lower().endswith(".app"):
        clean = clean[:-4].strip()
    if (
        not clean
        or len(clean) > 200
        or "/" in clean
        or clean.startswith(".")
        or any(ord(ch) < 0x20 for ch in clean)
    ):
        raise ValueError("Give the app by its name, for example 'TextEdit'.")
    return clean


def _int(value: Any, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bundle_name(running: Any) -> str:
    """The app bundle's file name without ".app" (not localized), or ""."""
    try:
        url = running.bundleURL()
        path = str(url.path()) if url is not None else ""
    except Exception:  # no bundle (a bare executable) or an older object
        return ""
    base = os.path.basename(path.rstrip("/"))
    if base.lower().endswith(".app"):
        base = base[:-4]
    return _text(base)


# --- The backend -------------------------------------------------------------


class MacBackend:
    """``ComputerBackend`` for macOS on top of pyobjc.

    ``api`` defaults to the real frameworks, loaded on first use.
    ``open_settings``, ``sleep``, ``clock`` and ``pid_alive`` are injectable
    so tests control every side effect and every wait; ``platform`` (default
    ``sys.platform``) lets the faked tests run on Linux CI too. Constructing
    one touches nothing: pyobjc loads on first use.
    """

    name = "mac"

    def __init__(
        self,
        api: Optional[PyObjC] = None,
        *,
        open_settings: Optional[Callable[[str], Any]] = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        pid_alive: Optional[Callable[[int], bool]] = None,
        platform: Optional[str] = None,
    ) -> None:
        self._api = api
        self._open_settings = open_settings
        self._sleep = sleep
        self._clock = clock
        self._pid_alive = pid_alive or _pid_alive
        self._platform = platform if platform is not None else sys.platform

    @property
    def api(self) -> PyObjC:
        if self._api is None:
            self._api = load_pyobjc()
        return self._api

    # -- availability and permission ----------------------------------------

    def available(self) -> tuple[bool, str]:
        if self._platform != "darwin":
            return False, "This backend controls macOS only."
        try:
            api = self.api
        except ImportError:
            return False, "pyobjc is not installed. Run: pip install -r requirements.txt"
        missing = [
            f"{part}.{symbol}"
            for part, symbols in REQUIRED_SYMBOLS.items()
            for symbol in symbols
            if not hasattr(getattr(api, part), symbol)
        ]
        if missing:
            return False, f"pyobjc is too old (missing {', '.join(missing[:3])}). Upgrade pyobjc."
        return True, "pyobjc loaded"

    def permission(self) -> PermissionState:
        """Accessibility trust of this process, checked without a prompt."""
        if not self.available()[0]:
            return "unknown"
        try:
            return "granted" if bool(self.api.ax.AXIsProcessTrusted()) else "denied"
        except Exception as exc:
            _log_failure("computer.mac.permission_failed", exc)
            return "unknown"

    def request_permission(self) -> None:
        """Show macOS's Accessibility prompt and open the pane to toggle."""
        if self.available()[0]:
            ax = self.api.ax
            try:
                ax.AXIsProcessTrustedWithOptions({ax.kAXTrustedCheckOptionPrompt: True})
            except Exception as exc:
                _log_failure("computer.mac.permission_prompt_failed", exc)
        opener = self._open_settings
        if opener is None:
            # Imported here: the capability registry imports the capability
            # modules, which may import this backend.
            from services.capabilities import macos

            opener = macos.open_settings
        opener(ACCESSIBILITY_SETTINGS_URL)

    def _require_trust(self) -> None:
        if not bool(self.api.ax.AXIsProcessTrusted()):
            raise PermissionError(_NOT_TRUSTED)

    # -- apps and windows ---------------------------------------------------

    def list_apps(self) -> list[AppInfo]:
        front = self._frontmost_pid()
        return [
            AppInfo(name=app.name, pid=app.pid, active=app.pid == front)
            for app in self._running_apps()
        ]

    def list_windows(self) -> list[WindowInfo]:
        windows: list[WindowInfo] = []
        for app in self._running_apps():
            for index, window in enumerate(self._windows_of(self._app_element(app.pid))):
                title = _text(self._attr(window, "AXTitle"))
                windows.append(WindowInfo(app=app.name, title=title, index=index))
        return windows

    def frontmost(self) -> tuple[str, str]:
        found = self._frontmost_app()
        if found is None:
            return "", ""
        pid, app_element = found
        title = ""
        try:
            window = self._focused_window(app_element)
            if window is not None:
                title = _text(self._attr(window, "AXTitle"))
        except PermissionError:
            pass  # the app name still helps; the title needs Accessibility
        return self._app_name(pid, app_element), title

    # -- outline --------------------------------------------------------------

    def outline(self, app: Optional[str], max_nodes: int) -> list[Node]:
        """The app's focused window as a tree: a one-element list holding the
        window node, whose ``children`` are the elements inside it.

        ``app`` None means the frontmost app. At most ``max_nodes`` nodes in
        all; the walk also stops at ``MAX_DEPTH``, after ``VISIT_FACTOR``
        element reads per allowed node, or after ``OUTLINE_DEADLINE_S``.
        Unnamed containers are not nodes (their children are lifted to the
        nearest node above). Elements scrolled out of view are dropped with
        their subtree, except text-entry fields: those are kept, marked
        ``offscreen`` and not descended into, so the toolkit's payment scan
        still sees a card field scrolled above the fold.
        """
        if max_nodes < 1:
            return []
        if app:
            app_element = self._app_element(self._find_app(app).pid)
        else:
            found = self._frontmost_app()
            if found is None:
                return []
            app_element = found[1]
        window = self._focused_window(app_element)
        if window is None:
            return []
        return self._walk(window, max_nodes)

    def _walk(self, root: Any, max_nodes: int) -> list[Node]:
        deadline = self._clock() + OUTLINE_DEADLINE_S
        visits_left = max(max_nodes * VISIT_FACTOR, 200)
        top = _Draft({})  # holds the window node
        emitted = 0
        # (element, draft its node goes under, clip rect, tree level, parent's name)
        stack: list[tuple[Any, _Draft, Optional[Bounds], int, str]] = [(root, top, None, 0, "")]
        while stack and emitted < max_nodes and visits_left > 0:
            if self._clock() > deadline:
                logger.info("computer.mac.outline_deadline", nodes=emitted)
                break
            visits_left -= 1
            element, parent, clip, level, parent_name = stack.pop()
            err, role_value = self._copy(element, "AXRole")
            if err == AX_ERR_INVALID_ELEMENT:
                continue  # vanished mid-walk
            role = _text(role_value) or "AXUnknown"
            if role in _SKIPPED_SUBTREES and level > 0:
                continue
            bounds = self._bounds(element)
            offscreen = False
            if level > 0 and bounds is not None and clip is not None and _area(bounds) > 0:
                if _intersect(bounds, clip) is None:
                    if role not in _TEXT_ENTRY_ROLES:
                        continue  # scrolled out of view: skip it and everything inside
                    offscreen = True
            info = self._describe(element, role)
            # The window itself is always the root node, so the toolkit can
            # check a click point against its bounds.
            emit = level == 0 or (
                (bounds is None or _area(bounds) > 0)
                and not (role in _QUIET_WHEN_EMPTY and not info.name and not info.value)
            )
            if emit and level > 0 and role == "AXStaticText" and info.name == parent_name:
                emit = False  # a button's own label, already on the button's line
            draft = parent
            if emit:
                focused = role in _TEXT_ENTRY_ROLES and bool(self._attr(element, "AXFocused"))
                draft = _Draft(
                    {
                        "role": _role_label(info.role, info.subrole),
                        "name": info.name,
                        "value": info.value,
                        "secure": info.secure,
                        "bounds": bounds,
                        "handle": element,
                        "enabled": info.enabled,
                        "focused": focused,
                        "offscreen": offscreen,
                    }
                )
                parent.children.append(draft)
                emitted += 1
            if offscreen or info.secure or level >= MAX_DEPTH:
                continue
            child_clip = clip
            if role in _CLIPPING_ROLES and bounds is not None and _area(bounds) > 0:
                child_clip = bounds if clip is None else (_intersect(bounds, clip) or bounds)
            children = self._attr(element, "AXChildren") or ()
            name_for_children = info.name if emit else parent_name
            for child in reversed(list(children)):
                stack.append((child, draft, child_clip, level + 1, name_for_children))
        return [draft.freeze() for draft in top.children]

    def focused(self) -> Optional[Node]:
        """The element with keyboard focus (asked system-wide), described
        like an outline node; None when nothing has focus or its role cannot
        be read. Its value is not read when it is, or may be, secure."""
        element = self._focused_element()
        if element is None:
            return None
        err, role_value = self._copy(element, "AXRole")
        if err != AX_SUCCESS:
            return None
        role = _text(role_value) or "AXUnknown"
        info = self._describe(element, role)
        return _make_node(
            role=_role_label(info.role, info.subrole),
            name=info.name,
            value=info.value,
            secure=info.secure,
            bounds=self._bounds(element),
            handle=element,
            enabled=info.enabled,
            focused=True,
        )

    def _describe(self, element: Any, role: str) -> _Described:
        """Read what a line needs. The subrole is read before, and instead
        of, the value of anything that might be a password field."""
        err_sub, subrole_value = self._copy(element, "AXSubrole")
        subrole = _text(subrole_value) if err_sub == AX_SUCCESS else ""
        secure = self._secure_from(role, subrole, err_sub)
        name = _text(self._attr(element, "AXTitle")) or _text(self._attr(element, "AXDescription"))
        value: Optional[str] = None
        if not secure:
            value = _format_value(role, subrole, self._attr(element, "AXValue"))
        if not name and role in _TEXT_ENTRY_ROLES:
            name = _text(self._attr(element, "AXPlaceholderValue"))
        if role == "AXStaticText":
            name, value = _text(value) or name, None
        enabled_value = self._attr(element, "AXEnabled")
        enabled = True if enabled_value is None else bool(enabled_value)
        return _Described(role, subrole, name, value, secure, enabled)

    @staticmethod
    def _secure_from(role: str, subrole: str, subrole_err: int) -> bool:
        if role == _SECURE_SUBROLE or subrole == _SECURE_SUBROLE:
            return True
        # Fail closed: a field that could be a password field but will not
        # say what it is gets treated as one.
        return role in _MAYBE_SECURE_ROLES and subrole_err not in (
            AX_SUCCESS,
            AX_ERR_NO_VALUE,
            AX_ERR_ATTRIBUTE_UNSUPPORTED,
        )

    def _is_secure(self, element: Any) -> bool:
        err_role, role_value = self._copy(element, "AXRole")
        err_sub, subrole_value = self._copy(element, "AXSubrole")
        role = _text(role_value) if err_role == AX_SUCCESS else ""
        subrole = _text(subrole_value) if err_sub == AX_SUCCESS else ""
        return self._secure_from(role, subrole, err_sub)

    # -- actions --------------------------------------------------------------

    def click(self, node_or_point: ClickTarget, *, double: bool = False) -> None:
        """AXPress when the element supports it (single click), otherwise a
        synthetic left click at the element's centre; a double click is
        always synthetic, with click state 1 then 2."""
        self._require_trust()
        if isinstance(node_or_point, tuple) and not hasattr(node_or_point, "handle"):
            x, y = node_or_point
            self._post_click(int(x), int(y), double)
            return
        self._click_node(cast(Node, node_or_point), double)

    def _click_node(self, node: Node, double: bool) -> None:
        handle = node.handle
        bounds = node.bounds
        if handle is not None:
            err, _ = self._copy(handle, "AXRole")
            if err == AX_ERR_INVALID_ELEMENT:
                raise MacElementGoneError(_STALE)
            if not double and "AXPress" in self._actions(handle):
                err = self.api.ax.AXUIElementPerformAction(handle, "AXPress")
                if err == AX_SUCCESS:
                    return
                if err == AX_ERR_INVALID_ELEMENT:
                    raise MacElementGoneError(_STALE)
                logger.info("computer.mac.axpress_failed", ax_error=int(err))
            bounds = self._bounds(handle) or bounds  # it may have moved since observe
        if bounds is None or _area(bounds) == 0:
            raise MacElementGoneError("That element has no position on screen to click.")
        x, y = _centre(bounds)
        self._post_click(x, y, double)

    def type_text(self, text: str, target: Optional[Node]) -> None:
        """Type ``text`` into ``target`` (focused first) or the focused element.

        Refuses a secure target, and re-checks before every chunk that
        keyboard focus is not on a secure field.
        """
        if not text:
            return
        if len(text) > MAX_TEXT_CHARS:
            raise ValueError(f"Text is limited to {MAX_TEXT_CHARS} characters per call.")
        segments = _segments(text)
        self._require_trust()
        if target is not None:
            handle = target.handle
            if target.secure or (handle is not None and self._is_secure(handle)):
                raise MacSecureFieldError(_SECURE_REFUSAL)
            self._focus(target)
        after_key = False
        for kind, payload in segments:
            if after_key:
                # The Return/Tab just typed may move focus (to a password
                # field, say) once the app handles it; read focus after that.
                self._sleep(KEY_SETTLE_S)
            if kind == "key":
                self._refuse_if_focus_secure()
                self._tap(_NAMED_KEYCODES[payload])
                after_key = True
                continue
            after_key = False
            for chunk in _utf16_chunks(payload):
                self._refuse_if_focus_secure()
                self._type_chunk(chunk)

    def key(self, combo: KeyCombo) -> None:
        """Press modifiers, tap the key, release modifiers in reverse order.

        Modifier keys get their own down/up events and every event carries
        the matching flags, so both flag-reading and key-tracking apps see
        the combo. Releases happen in ``finally``: a failure never leaves a
        modifier held down.
        """
        modifiers = _normalize_modifiers(combo.modifiers)
        code = keycode_for(combo.key)
        self._require_trust()
        if _inserts_text(modifiers, combo.key):
            self._refuse_if_focus_secure()
        flags = 0
        held: list[str] = []
        try:
            for modifier in modifiers:
                mask, mod_code = MODIFIERS[modifier]
                flags |= mask
                self._key_event(mod_code, True, flags)
                held.append(modifier)
            self._key_event(code, True, flags)
            self._key_event(code, False, flags)
        finally:
            for modifier in reversed(held):
                mask, mod_code = MODIFIERS[modifier]
                flags &= ~mask
                self._key_event(mod_code, False, flags)

    def scroll(self, direction: str, amount: int) -> None:
        """Scroll the view under the pointer by ``amount`` lines (capped)."""
        if direction not in ("up", "down"):
            raise ValueError("Scroll direction must be 'up' or 'down'.")
        lines = _int(amount, 0)
        if lines < 1:
            raise ValueError("Scroll amount must be at least 1 line.")
        lines = min(lines, MAX_SCROLL_LINES)
        delta = lines if direction == "up" else -lines  # positive wheel delta = up
        self._require_trust()
        quartz = self.api.quartz
        create2 = getattr(quartz, "CGEventCreateScrollWheelEvent2", None)
        if create2 is not None:  # fixed-arity variant (macOS 13+): no varargs bridging
            event = create2(None, CG_SCROLL_UNIT_LINE, 1, delta, 0, 0)
        else:
            event = quartz.CGEventCreateScrollWheelEvent(None, CG_SCROLL_UNIT_LINE, 1, delta)
        self._post(event)

    def open_app(self, name: str) -> None:
        """Bring a running app forward, or launch it by name and wait
        (up to ``OPEN_APP_WAIT_S``) for it to show up."""
        clean = _clean_app_name(name)
        try:
            running: Optional[_App] = self._find_app(clean)
        except AppNotFoundError:
            running = None
        if running is not None:
            self._refuse_blocked(running)
            self._activate(running)
            return
        appkit = self.api.appkit
        workspace = self._workspace()
        path = workspace.fullPathForApplication_(clean)
        if path and str(path).endswith(".app"):
            blocked = rules.blocked_app(os.path.basename(str(path).rstrip("/")))
            if blocked:
                raise MacBlockedAppError(f"{clean!r} is {blocked}.", app=blocked)
            config = appkit.NSWorkspaceOpenConfiguration.configuration()
            config.setActivates_(True)
            url = appkit.NSURL.fileURLWithPath_(str(path))
            # A real handler rather than None: pyobjc then always has a block
            # to hand over, and a launch failure is at least logged. The
            # outcome itself is observed by _wait_for_app.
            workspace.openApplicationAtURL_configuration_completionHandler_(
                url, config, _log_open_result
            )
        elif not workspace.launchApplication_(clean):
            raise MacAppNotFoundError(f"No app named {clean!r} was found on this Mac.")
        self._wait_for_app(clean)

    def focus_window(self, app: str, index: int) -> None:
        """Raise window ``index`` of ``app`` (as listed by list_windows) and
        activate the app."""
        self._require_trust()
        target = self._find_app(app)
        self._refuse_blocked(target)
        windows = self._windows_of(self._app_element(target.pid))
        if not 0 <= index < len(windows):
            raise MacAppNotFoundError(
                f"{target.name} has {len(windows)} window(s); there is no window {index}."
            )
        window = windows[index]
        ax = self.api.ax
        if self._attr(window, "AXMinimized"):
            ax.AXUIElementSetAttributeValue(window, "AXMinimized", False)
        err = ax.AXUIElementPerformAction(window, "AXRaise")
        if err == AX_ERR_INVALID_ELEMENT:
            raise MacElementGoneError(_STALE)
        ax.AXUIElementSetAttributeValue(window, "AXMain", True)
        self._activate(target)

    # -- AX plumbing ------------------------------------------------------------

    def _copy(self, element: Any, attribute: str) -> tuple[int, Any]:
        err, value = self.api.ax.AXUIElementCopyAttributeValue(element, attribute, None)
        if err == AX_ERR_API_DISABLED:
            raise PermissionError(_NOT_TRUSTED)
        return int(err), value

    def _attr(self, element: Any, attribute: str) -> Any:
        err, value = self._copy(element, attribute)
        return value if err == AX_SUCCESS else None

    def _actions(self, element: Any) -> set[str]:
        err, names = self.api.ax.AXUIElementCopyActionNames(element, None)
        if err != AX_SUCCESS or not names:
            return set()
        return {str(n) for n in names}

    def _bounds(self, element: Any) -> Optional[Bounds]:
        position = self._attr(element, "AXPosition")
        size = self._attr(element, "AXSize")
        if position is None or size is None:
            return None
        ax = self.api.ax
        ok_pos, point = ax.AXValueGetValue(position, AX_VALUE_CGPOINT, None)
        ok_size, extent = ax.AXValueGetValue(size, AX_VALUE_CGSIZE, None)
        if not (ok_pos and ok_size):
            return None
        try:
            return (round(point.x), round(point.y), round(extent.width), round(extent.height))
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None

    def _app_element(self, pid: int) -> Any:
        ax = self.api.ax
        element = ax.AXUIElementCreateApplication(pid)
        # A hung app must not hang the agent: every AX call on this element
        # (and its descendants) gives up after this long.
        ax.AXUIElementSetMessagingTimeout(element, AX_MESSAGING_TIMEOUT_S)
        return element

    def _windows_of(self, app_element: Any) -> list[Any]:
        return list(self._attr(app_element, "AXWindows") or ())

    def _focused_window(self, app_element: Any) -> Any:
        for attribute in ("AXFocusedWindow", "AXMainWindow"):
            window = self._attr(app_element, attribute)
            if window is not None:
                return window
        windows = self._windows_of(app_element)
        return windows[0] if windows else None

    def _focused_element(self) -> Any:
        system = self.api.ax.AXUIElementCreateSystemWide()
        return self._attr(system, "AXFocusedUIElement")

    def _refuse_if_focus_secure(self) -> None:
        """Refuse when the focused element is, or may be, a password field,
        and when focus (or what the focused element is) cannot be read: keys
        typed blind would land wherever focus happens to be."""
        focused = self._focused_element()
        if focused is None:
            raise MacSecureFieldError(_FOCUS_UNKNOWN)
        err, _ = self._copy(focused, "AXRole")
        if err != AX_SUCCESS:
            raise MacSecureFieldError(_FOCUS_UNKNOWN)
        if self._is_secure(focused):
            raise MacSecureFieldError(_SECURE_REFUSAL)

    def _refuse_blocked(self, app: _App) -> None:
        """Refuse an app the hard rules block under any of its names."""
        for name in (app.name, app.localized, app.bundle_id):
            blocked = rules.blocked_app(name) if name else None
            if blocked:
                raise MacBlockedAppError(f"{app.name!r} is {blocked}.", app=blocked)

    def _require_uncovered(self, x: int, y: int) -> None:
        """The element under (x, y) must belong to the frontmost app (the one
        the toolkit checked); otherwise a synthetic click would land in an
        app that was never checked, maybe a blocked one floating on top."""
        found = self._frontmost_app()
        if found is None:
            raise MacCoveredError(_COVERED)
        ax = self.api.ax
        err, element = ax.AXUIElementCopyElementAtPosition(
            ax.AXUIElementCreateSystemWide(), float(x), float(y), None
        )
        if err == AX_ERR_API_DISABLED:
            raise PermissionError(_NOT_TRUSTED)
        if err != AX_SUCCESS or element is None:
            raise MacCoveredError(_COVERED)
        err, pid = ax.AXUIElementGetPid(element, None)
        if err != AX_SUCCESS or _int(pid) != found[0]:
            logger.info("computer.mac.click_covered", ax_error=int(err))
            raise MacCoveredError(_COVERED)

    def _focus(self, target: Node) -> None:
        handle = target.handle
        if handle is not None:
            err = self.api.ax.AXUIElementSetAttributeValue(handle, "AXFocused", True)
            if err == AX_SUCCESS:
                self._sleep(FOCUS_SETTLE_S)
                return
            if err == AX_ERR_INVALID_ELEMENT:
                raise MacElementGoneError(_STALE)
        bounds = (self._bounds(handle) if handle is not None else None) or target.bounds
        if bounds is None or _area(bounds) == 0:
            raise MacElementGoneError("Could not focus that element; click it first.")
        self._post_click(*_centre(bounds), False)
        self._sleep(FOCUS_SETTLE_S)

    # -- running apps -------------------------------------------------------------

    def _workspace(self) -> Any:
        return self.api.appkit.NSWorkspace.sharedWorkspace()

    def _running_apps(self) -> list[_App]:
        """Regular (Dock) apps that are running now.

        NSWorkspace only refreshes its list when the main run loop runs,
        which never happens under uvicorn, so an app launched after the first
        call would be missing and a quit one would linger. Dead pids are
        dropped, and the window server's live window list adds any regular
        app that owns a normal window but is not in NSWorkspace's list yet.
        """
        found: dict[int, _App] = {}
        for running in self._workspace().runningApplications() or ():
            app = self._app_record(running)
            if app is not None:
                found.setdefault(app.pid, app)
        lookup = self.api.appkit.NSRunningApplication
        for info in self._window_list():
            pid = _int(info.get(CG_WINDOW_OWNER_PID))
            if pid <= 0 or pid in found or _int(info.get(CG_WINDOW_LAYER)) != 0:
                continue
            running = lookup.runningApplicationWithProcessIdentifier_(pid)
            app = self._app_record(running) if running is not None else None
            if app is not None:
                found[pid] = app
        return sorted(found.values(), key=lambda a: (a.name.casefold(), a.pid))

    def _app_record(self, running: Any) -> Optional[_App]:
        try:
            if _int(running.activationPolicy()) != NS_ACTIVATION_POLICY_REGULAR:
                return None
            pid = _int(running.processIdentifier())
            localized = _text(running.localizedName())
            bundle_id = _text(running.bundleIdentifier())
        except Exception as exc:
            _log_failure("computer.mac.app_record_failed", exc)
            return None
        name = _bundle_name(running) or localized
        if pid <= 0 or not name or not self._pid_alive(pid):
            return None
        return _App(name=name, pid=pid, bundle_id=bundle_id, running=running, localized=localized)

    def _window_list(self) -> list[Any]:
        try:
            infos = self.api.quartz.CGWindowListCopyWindowInfo(
                CG_WINDOW_LIST_ALL | CG_WINDOW_LIST_EXCLUDE_DESKTOP, CG_NULL_WINDOW_ID
            )
        except Exception as exc:
            _log_failure("computer.mac.window_list_failed", exc)
            return []
        return list(infos or ())

    def _find_app(self, name: str) -> _App:
        wanted = _clean_app_name(name).casefold()
        apps = self._running_apps()
        for field_name in ("name", "localized", "bundle_id"):
            for app in apps:
                value = getattr(app, field_name)
                if value and value.casefold() == wanted:
                    return app
        raise MacAppNotFoundError(f"{name!r} is not running.")

    def _frontmost_app(self) -> Optional[tuple[int, Any]]:
        """(pid, AX app element) of the app with keyboard focus.

        Asks the accessibility server first, which is live; NSWorkspace's
        answer can be stale (see ``_running_apps``) and is only the fallback,
        e.g. when Accessibility is not granted yet.
        """
        ax = self.api.ax
        try:
            app_element = self._attr(ax.AXUIElementCreateSystemWide(), "AXFocusedApplication")
        except PermissionError:
            app_element = None
        if app_element is not None:
            err, pid = ax.AXUIElementGetPid(app_element, None)
            if err == AX_SUCCESS and _int(pid) > 0:
                ax.AXUIElementSetMessagingTimeout(app_element, AX_MESSAGING_TIMEOUT_S)
                return _int(pid), app_element
        running = self._workspace().frontmostApplication()
        if running is None:
            return None
        pid = _int(running.processIdentifier())
        if pid <= 0:
            return None
        return pid, self._app_element(pid)

    def _frontmost_pid(self) -> int:
        found = self._frontmost_app()
        return found[0] if found is not None else -1

    def _app_name(self, pid: int, app_element: Any) -> str:
        running = self.api.appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
        name = ""
        if running is not None:
            name = _bundle_name(running) or _text(running.localizedName())
        if name:
            return name
        try:
            return _text(self._attr(app_element, "AXTitle"))
        except PermissionError:
            return ""

    def _activate(self, app: _App) -> None:
        if app.running.activateWithOptions_(NS_ACTIVATE_IGNORING_OTHER_APPS):
            return
        # Refused (e.g. focus-stealing prevention): ask the app through AX.
        err = self.api.ax.AXUIElementSetAttributeValue(
            self._app_element(app.pid), "AXFrontmost", True
        )
        if err != AX_SUCCESS:
            logger.info("computer.mac.activate_failed", ax_error=int(err))

    def _wait_for_app(self, name: str) -> None:
        deadline = self._clock() + OPEN_APP_WAIT_S
        while True:
            try:
                self._find_app(name)
                return
            except AppNotFoundError:
                pass
            if self._clock() >= deadline:
                logger.info("computer.mac.open_app_not_seen", waited_s=OPEN_APP_WAIT_S)
                return
            self._sleep(POLL_INTERVAL_S)

    # -- events ---------------------------------------------------------------------

    def _post(self, event: Any) -> None:
        if event is None:
            raise RuntimeError("macOS could not create the input event.")
        self.api.quartz.CGEventPost(CG_HID_EVENT_TAP, event)
        self._sleep(EVENT_GAP_S)

    def _post_click(self, x: int, y: int, double: bool) -> None:
        self._require_uncovered(x, y)
        quartz = self.api.quartz
        point = (float(x), float(y))
        moved = quartz.CGEventCreateMouseEvent(None, CG_MOUSE_MOVED, point, CG_MOUSE_BUTTON_LEFT)
        quartz.CGEventSetFlags(moved, 0)
        self._post(moved)
        for click_state in (1, 2) if double else (1,):
            for kind in (CG_LEFT_MOUSE_DOWN, CG_LEFT_MOUSE_UP):
                event = quartz.CGEventCreateMouseEvent(None, kind, point, CG_MOUSE_BUTTON_LEFT)
                # Flags cleared so a modifier the owner happens to hold does
                # not turn the click into a cmd-/shift-click.
                quartz.CGEventSetFlags(event, 0)
                quartz.CGEventSetIntegerValueField(event, CG_MOUSE_CLICK_STATE, click_state)
                self._post(event)

    def _key_event(self, code: int, down: bool, flags: int) -> None:
        quartz = self.api.quartz
        event = quartz.CGEventCreateKeyboardEvent(None, code, down)
        quartz.CGEventSetFlags(event, flags)
        self._post(event)

    def _tap(self, code: int) -> None:
        self._key_event(code, True, 0)
        self._key_event(code, False, 0)

    def _type_chunk(self, chunk: str) -> None:
        quartz = self.api.quartz
        units = _utf16_units(chunk)
        for down in (True, False):
            event = quartz.CGEventCreateKeyboardEvent(None, 0, down)
            quartz.CGEventSetFlags(event, 0)
            quartz.CGEventKeyboardSetUnicodeString(event, units, chunk)
            self._post(event)


def _log_failure(event: str, exc: BaseException) -> None:
    logger.warning(event, error_type=type(exc).__name__, error=str(exc)[:_LOG_DETAIL_CHARS])


def _log_open_result(app: Any, error: Any) -> None:
    """Completion handler for NSWorkspace's openApplicationAtURL (runs on an
    AppKit queue; only logs)."""
    if error is not None:
        logger.warning("computer.mac.open_app_failed", error=str(error)[:_LOG_DETAIL_CHARS])


if TYPE_CHECKING:  # mypy proves MacBackend implements the protocol exactly

    def _conforms(backend: MacBackend) -> ComputerBackend:
        return backend
