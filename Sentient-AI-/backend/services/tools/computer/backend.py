"""Declares the ComputerBackend protocol every platform backend implements, the
plain data it exchanges with the toolkit (AppInfo, WindowInfo, Node, KeyCombo),
and select_backend(), which picks the backend for this OS.

Why it exists: The toolkit enforces every safety rule against this one narrow
surface, so a Mac, Windows or in-memory fake backend can be swapped in without
touching the rules, and no unit test ever needs a real desktop.

Contract for backend authors:

- Constructing a backend must not touch the OS (no permission prompt, no
  accessibility read): ``select_backend`` runs at wiring time and inside
  capability reports.
- Names returned by ``frontmost()`` and ``list_apps()`` are accepted back by
  ``outline()``, ``open_app()`` and ``focus_window()``. Prefer a stable,
  non-localized name (the executable or bundle name) so the blocked-app list
  in ``rules.py`` matches on every system language.
- ``Node.value`` of a secure field must be ``None``: the backend never reads
  it (Mac ``AXSecureTextField`` subrole, Windows UIA ``IsPassword``).
- ``Node.role`` uses the shared, lower-case vocabulary: "window", "button",
  "text field", "secure text field", "text area", "search field",
  "combo box", "checkbox", "radio button", "link", "menu item",
  "pop up button", "tab", "slider", "text" (static text), "image",
  "group", "list", "row", "cell", "table", "toolbar", "menu bar".
- Every exception a backend raises is logged, never shown to the model;
  the toolkit writes its own message for the ``BackendError`` subclasses
  below and a generic one for anything else.
- A backend re-checks the hard rules it alone can see and refuses before
  sending input: ``BlockedTargetError`` when a name resolves to a blocked app
  (a localized name, bundle id or executable), ``SecureTargetError`` when
  keyboard focus is (or may be) on a password field, ``CoveredTargetError``
  when another app's window is over a click point. The toolkit reports these
  as refusals under the matching rule.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Literal, Optional, Protocol, Union, runtime_checkable

import structlog

logger = structlog.get_logger(__name__)

PermissionState = Literal["granted", "denied", "not_required", "unknown"]
Point = tuple[int, int]
# x, y, width, height in screen points, origin at the main display's top left.
Bounds = tuple[int, int, int, int]

# Canonical modifier names, in the order a combo is written out.
MODIFIERS: tuple[str, ...] = ("cmd", "ctrl", "alt", "shift", "win")


class BackendError(Exception):
    """Base class for failures the toolkit explains in its own words."""


class BackendUnavailableError(BackendError):
    """This backend cannot run here (wrong OS, missing dependency)."""


class AppNotFoundError(BackendError):
    """No running (or, for open_app, installed) app or window by that name."""


class ElementGoneError(BackendError):
    """The element a ref pointed at no longer exists."""


class ElevatedTargetError(BackendError):
    """Windows: the target runs as administrator, so UIPI blocks input to it."""


class BlockedTargetError(BackendError):
    """The backend resolved the target to an app the hard rules block (a
    localized name, bundle id or executable the toolkit could not see), and
    refused before acting. ``app`` is the blocked entry's display name."""

    # A class default too: a subclass that also derives from OSError is built
    # by OSError's __init__, which never runs this one.
    app: str = ""

    def __init__(self, message: str = "", *, app: str = "") -> None:
        super().__init__(message)
        self.app = app


class SecureTargetError(BackendError):
    """The target, or the element that has keyboard focus, is a password
    field, so the backend stopped before typing (more) into it."""


class CoveredTargetError(BackendError):
    """The click point is covered by another app's window (or the owner of
    the point cannot be told), so the click could land in an app the hard
    rules never checked."""


@dataclass(frozen=True)
class AppInfo:
    name: str
    pid: int
    active: bool = False
    # Windows only: runs elevated, so Crawler's input cannot reach it (UIPI).
    elevated: bool = False


@dataclass(frozen=True)
class WindowInfo:
    app: str
    title: str
    # Position among that app's windows, 0 = front. What focus_window takes.
    index: int


@dataclass(frozen=True)
class Node:
    """One accessibility element. ``handle`` is the backend's own reference
    (an AXUIElement, a UIA control, a fake id) and is never shown to the
    model or compared for equality between nodes."""

    role: str
    name: str = ""
    value: Optional[str] = None
    secure: bool = False
    bounds: Optional[Bounds] = None
    focused: bool = False
    enabled: bool = True
    hidden: bool = False
    offscreen: bool = False
    children: tuple["Node", ...] = ()
    handle: Any = field(default=None, compare=False, repr=False)

    def contains(self, point: Point) -> bool:
        """True when *point* falls inside this element's bounds."""
        if self.bounds is None:
            return False
        x, y, width, height = self.bounds
        if width <= 0 or height <= 0:
            return False
        px, py = point
        return x <= px < x + width and y <= py < y + height


@dataclass(frozen=True)
class KeyCombo:
    """Zero or more canonical modifiers plus exactly one key (see keys.py)."""

    modifiers: frozenset[str]
    key: str

    def __str__(self) -> str:
        return "+".join([m for m in MODIFIERS if m in self.modifiers] + [self.key])


ClickTarget = Union[Node, Point]


@runtime_checkable
class ComputerBackend(Protocol):
    name: str

    def available(self) -> tuple[bool, str]: ...

    def permission(self) -> PermissionState: ...

    def request_permission(self) -> None: ...

    def list_apps(self) -> list[AppInfo]: ...

    def list_windows(self) -> list[WindowInfo]: ...

    def frontmost(self) -> tuple[str, str]:
        """(app name, front window title); ("", "") when nothing is in front."""
        ...

    def focused(self) -> Optional[Node]:
        """The element with keyboard focus in the frontmost app, or None
        when it cannot be told. The toolkit refuses to type blind."""
        ...

    def outline(self, app: Optional[str], max_nodes: int) -> list[Node]:
        """The front window of *app* (the frontmost app when None) as a
        tree, root first, at most *max_nodes* elements."""
        ...

    def click(self, target: ClickTarget, *, double: bool = False) -> None: ...

    def type_text(self, text: str, target: Optional[Node]) -> None: ...

    def key(self, combo: KeyCombo) -> None: ...

    def scroll(self, direction: str, amount: int) -> None: ...

    def open_app(self, name: str) -> None: ...

    def focus_window(self, app: str, index: int) -> None: ...


class UnavailableBackend:
    """Stands in where no backend can run: reports why, and refuses
    everything else."""

    name = "unavailable"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def available(self) -> tuple[bool, str]:
        return False, self.reason

    def permission(self) -> PermissionState:
        return "unknown"

    def _refuse(self, *_args: Any, **_kwargs: Any) -> Any:
        raise BackendUnavailableError(self.reason)

    request_permission = _refuse
    list_apps = _refuse
    list_windows = _refuse
    frontmost = _refuse
    focused = _refuse
    outline = _refuse
    click = _refuse
    type_text = _refuse
    key = _refuse
    scroll = _refuse
    open_app = _refuse
    focus_window = _refuse


# Accepts the names services.platform uses ("mac", "windows") and the
# sys.platform spellings capability reports carry ("darwin", "win32").
_PLATFORM_ALIASES: dict[str, str] = {
    "mac": "mac",
    "macos": "mac",
    "darwin": "mac",
    "windows": "windows",
    "win32": "windows",
}
_BACKENDS: dict[str, tuple[str, str, str]] = {
    "mac": ("services.tools.computer.backend_mac", "MacBackend", "macOS"),
    "windows": ("services.tools.computer.backend_windows", "WindowsBackend", "Windows"),
}


def select_backend(platform_name: str) -> ComputerBackend:
    """The backend for *platform_name*; an ``UnavailableBackend`` for any
    other platform, or when the platform's backend cannot be imported or
    constructed (its dependencies are missing)."""
    key = _PLATFORM_ALIASES.get(str(platform_name).strip().lower())
    if key is None:
        return UnavailableBackend(
            "Controlling the computer is supported on macOS and Windows only."
        )
    module_name, class_name, label = _BACKENDS[key]
    try:
        module = importlib.import_module(module_name)
        backend = getattr(module, class_name)()
    except Exception as exc:  # missing module or dependency: unavailable, never a crash
        logger.info(
            "computer_backend_unavailable",
            platform=key,
            error_type=type(exc).__name__,
            error=str(exc)[:200],
        )
        return UnavailableBackend(
            f"The {label} control component is not installed in this copy of Crawler."
        )
    return backend
