"""An in-memory desktop (apps, windows, an accessibility tree, keyboard focus)
that implements ComputerBackend and records every call.

Why it exists: Every unit test of computer control runs against this instead of
a real Mac or PC, so no test ever clicks, types or reads the developer's screen.
``events`` records only the calls that would change something (click, type,
key, scroll, open_app, focus_window, request_permission); ``reads`` records the
rest, so a test can prove a refused action never reached the backend at all.
"""

from __future__ import annotations

import dataclasses
import itertools
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Optional

from services.tools.computer.backend import (
    AppInfo,
    AppNotFoundError,
    Bounds,
    ClickTarget,
    ElementGoneError,
    KeyCombo,
    Node,
    PermissionState,
    WindowInfo,
)

_handles = itertools.count(1)


def make_node(role: str, name: str = "", *, handle: Any = None, **fields: Any) -> Node:
    """A Node with a unique handle unless one is given (tests refer to
    elements by handle when they check what an event hit)."""
    return Node(
        role=role,
        name=name,
        handle=handle if handle is not None else f"n{next(_handles)}",
        **fields,
    )


@dataclass
class FakeWindow:
    title: str
    nodes: tuple[Node, ...] = ()
    bounds: Optional[Bounds] = (0, 0, 800, 600)


@dataclass
class FakeApp:
    name: str
    pid: int
    windows: list[FakeWindow] = field(default_factory=list)
    elevated: bool = False


class FakeBackend:
    name = "fake"

    def __init__(
        self,
        apps: Iterable[FakeApp] = (),
        *,
        frontmost: Optional[str] = None,
        installed: Iterable[str] = (),
        focused: Any = None,
        permission: PermissionState = "granted",
        available: tuple[bool, str] = (True, ""),
    ) -> None:
        self.apps: dict[str, FakeApp] = {app.name: app for app in apps}
        self.front: Optional[str] = frontmost or next(iter(self.apps), None)
        self.installed = set(installed)
        self.focused_handle = focused
        self.permission_state: PermissionState = permission
        self.availability = available
        self.values: dict[Any, str] = {}
        self.events: list[tuple[Any, ...]] = []
        self.reads: list[str] = []
        # Method name → exception it raises (after being recorded).
        self.failures: dict[str, BaseException] = {}
        # Called after each recorded event, to change the desktop the way
        # the real app would (e.g. a click that opens another app).
        self.on_event: Optional[Callable[["FakeBackend", tuple[Any, ...]], None]] = None

    # ── helpers ──────────────────────────────────────────────────────────

    def _read(self, method: str) -> None:
        self.reads.append(method)
        failure = self.failures.get(method)
        if failure is not None:
            raise failure

    def _event(self, *event: Any) -> None:
        self.events.append(event)
        failure = self.failures.get(str(event[0]))
        if failure is not None:
            raise failure
        if self.on_event is not None:
            self.on_event(self, event)

    def _walk(self, nodes: Iterable[Node]) -> Iterator[Node]:
        for node in nodes:
            yield node
            yield from self._walk(node.children)

    def _find(self, handle: Any) -> Optional[Node]:
        for app in self.apps.values():
            for window in app.windows:
                for node in self._walk(window.nodes):
                    if node.handle == handle:
                        return node
        return None

    def _live(self, node: Node, budget: list[int]) -> Optional[Node]:
        if budget[0] <= 0:
            return None
        budget[0] -= 1
        children = []
        for child in node.children:
            live = self._live(child, budget)
            if live is None:
                break
            children.append(live)
        return dataclasses.replace(
            node,
            value=node.value if node.secure else self.values.get(node.handle, node.value),
            focused=node.handle is not None and node.handle == self.focused_handle,
            children=tuple(children),
        )

    def set_value(self, handle: Any, value: str) -> None:
        self.values[handle] = value

    # ── ComputerBackend ─────────────────────────────────────────────────

    def available(self) -> tuple[bool, str]:
        self._read("available")
        return self.availability

    def permission(self) -> PermissionState:
        self._read("permission")
        return self.permission_state

    def request_permission(self) -> None:
        self._event("request_permission")

    def list_apps(self) -> list[AppInfo]:
        self._read("list_apps")
        return [
            AppInfo(app.name, app.pid, active=app.name == self.front, elevated=app.elevated)
            for app in self.apps.values()
        ]

    def list_windows(self) -> list[WindowInfo]:
        self._read("list_windows")
        return [
            WindowInfo(app.name, window.title, index)
            for app in self.apps.values()
            for index, window in enumerate(app.windows)
        ]

    def frontmost(self) -> tuple[str, str]:
        self._read("frontmost")
        if self.front is None or self.front not in self.apps:
            return "", ""
        windows = self.apps[self.front].windows
        return self.front, windows[0].title if windows else ""

    def focused(self) -> Optional[Node]:
        self._read("focused")
        if self.focused_handle is None:
            return None
        node = self._find(self.focused_handle)
        if node is None:
            return None
        return self._live(node, [1])

    def outline(self, app: Optional[str], max_nodes: int) -> list[Node]:
        self._read("outline")
        name = app if app is not None else self.front
        if name is None or name not in self.apps:
            raise AppNotFoundError(f"no running app {name!r}")
        windows = self.apps[name].windows
        if not windows:
            return []
        window = windows[0]
        root = Node(
            role="window",
            name=window.title,
            bounds=window.bounds,
            children=window.nodes,
            handle=f"window:{name}",
        )
        live = self._live(root, [max_nodes])
        return [live] if live is not None else []

    def click(self, target: ClickTarget, *, double: bool = False) -> None:
        if isinstance(target, Node):
            self._event("click", target.handle, double)
            if self._find(target.handle) is None:
                raise ElementGoneError(str(target.handle))
        else:
            self._event("click", tuple(target), double)

    def type_text(self, text: str, target: Optional[Node]) -> None:
        handle = target.handle if target is not None else self.focused_handle
        self._event("type", text, handle)
        node = self._find(handle)
        if node is None:
            raise ElementGoneError(str(handle))
        self.values[handle] = self.values.get(handle, node.value or "") + text

    def key(self, combo: KeyCombo) -> None:
        self._event("key", str(combo))

    def scroll(self, direction: str, amount: int) -> None:
        self._event("scroll", direction, amount)

    def open_app(self, name: str) -> None:
        self._event("open_app", name)
        if name not in self.apps:
            if name not in self.installed:
                raise AppNotFoundError(name)
            self.apps[name] = FakeApp(name, 1000 + len(self.apps), [FakeWindow(name)])
        self.front = name

    def focus_window(self, app: str, index: int) -> None:
        self._event("focus_window", app, index)
        target = self.apps.get(app)
        if target is None or not 0 <= index < len(target.windows):
            raise AppNotFoundError(f"{app} window {index}")
        target.windows.insert(0, target.windows.pop(index))
        self.front = app
