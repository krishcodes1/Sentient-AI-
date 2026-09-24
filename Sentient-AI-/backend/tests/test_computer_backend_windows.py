"""Tests for the Windows computer_control backend: the UI Automation tree walk,
secure-field handling, invoke-versus-SendInput clicks, the INPUT structs built
for typing, key combos and the wheel, UIPI refusals, app naming and open_app.

Why it exists: Nothing here touches Windows. A fake ``uiautomation`` module
stands in for the accessibility tree and a recording Win32 shim stands in for
user32/kernel32/advapi32/shell32, capturing every INPUT struct that would have
gone to SendInput, so the suite runs on macOS and Linux CI and never sends a
real click or key on the developer's machine.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
import types
from pathlib import Path

import pytest

from services.tools.computer import backend_windows as bw
from services.tools.computer.backend import (
    AppNotFoundError,
    BlockedTargetError,
    ComputerBackend,
    CoveredTargetError,
    ElementGoneError,
    ElevatedTargetError,
    KeyCombo,
    Node,
    SecureTargetError,
    select_backend,
)
from services.tools.computer.backend_windows import (
    CRAWLER_EXTRA_INFO,
    INPUT,
    INPUT_KEYBOARD,
    INPUT_MOUSE,
    KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE,
    MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_HWHEEL,
    MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MOVE,
    MOUSEEVENTF_WHEEL,
    BlockedAppError,
    SecureFieldError,
    StaleElementError,
    UIPIBlockedError,
    WindowsBackend,
    WindowsRefusal,
)

# UIA control type ids used by the fake desktop.
BUTTON, EDIT, LIST_ITEM, LIST, MENU_BAR, MENU_ITEM = 50000, 50004, 50007, 50008, 50010, 50011
SCROLL_BAR, GROUP, WINDOW, PANE, TEXT = 50014, 50026, 50032, 50033, 50020

SCREEN = (1920, 1080)


# --- Fakes -------------------------------------------------------------------


class FakeRect:
    def __init__(self, left, top, right, bottom):
        self.left, self.top, self.right, self.bottom = left, top, right, bottom


class FakeInvoke:
    def __init__(self, ctl):
        self._ctl = ctl

    def Invoke(self):
        self._ctl.invoked += 1


class FakeValue:
    def __init__(self, ctl):
        self._ctl = ctl

    @property
    def Value(self):
        self._ctl.value_reads += 1
        return self._ctl.value


_RUNTIME_IDS = iter(range(1, 10_000))


class FakeControl:
    """Enough of uiautomation.Control for the backend."""

    def __init__(
        self,
        control_type,
        name="",
        *,
        rect=(0, 0, 100, 20),
        offscreen=False,
        password=False,
        pid=100,
        hwnd=0,
        cls="",
        children=(),
        invoke=False,
        value=None,
        focus_ok=True,
        broken=False,
    ):
        self._control_type = control_type
        self.Name = name
        self.BoundingRectangle = FakeRect(*rect)
        self.IsOffscreen = offscreen
        self.password = password
        self.ProcessId = pid
        self.NativeWindowHandle = hwnd
        self.ClassName = cls
        self.children = list(children)
        self.invoke = invoke
        self.invoked = 0
        self.value = value
        self.value_reads = 0
        self.focus_ok = focus_ok
        self.focus_calls = 0
        self.broken = broken
        self.runtime_id = (42, next(_RUNTIME_IDS))
        self.desk = None

    @property
    def ControlType(self):
        if self.broken:
            raise RuntimeError("COM error: element not available")
        return self._control_type

    @property
    def IsPassword(self):
        if self.password == "raise":
            raise RuntimeError("COM error")
        return self.password

    def GetChildren(self):
        return list(self.children)

    def GetPattern(self, pattern_id):
        if pattern_id == 10000 and self.invoke:
            return FakeInvoke(self)
        if pattern_id == 10002 and self.value is not None:
            return FakeValue(self)
        return None

    def SetFocus(self):
        self.focus_calls += 1
        if self.focus_ok and self.desk is not None:
            self.desk.uia.focused = self
        return self.focus_ok

    def GetRuntimeId(self):
        return list(self.runtime_id)


class FakeUia(types.SimpleNamespace):
    """A stand-in for the uiautomation module. Every tree access must happen
    inside UIAutomationInitializerInThread, as it must on real Windows."""

    PatternId = types.SimpleNamespace(InvokePattern=10000, ValuePattern=10002)

    def __init__(self, root):
        super().__init__()
        self.root = root
        self.focused = None
        self.focus_error = False
        self.sessions = 0
        self.active = 0
        outer = self

        class Initializer:
            def __enter__(self):
                outer.sessions += 1
                outer.active += 1

            def __exit__(self, *exc):
                outer.active -= 1

        self.UIAutomationInitializerInThread = Initializer

    def _in_session(self):
        assert self.active > 0, "UI Automation used outside UIAutomationInitializerInThread"

    def GetRootControl(self):
        self._in_session()
        return self.root

    def ControlFromHandle(self, hwnd):
        self._in_session()
        for ctl in self.root.children:
            if ctl.NativeWindowHandle == hwnd:
                return ctl
        return None

    def GetFocusedControl(self):
        self._in_session()
        if self.focus_error:
            raise RuntimeError("COM error")
        return self.focused


def _copy(inp):
    return INPUT.from_buffer_copy(bytes(inp))


class FakeWin32:
    """Records SendInput batches as real INPUT structs; answers the rest
    from dictionaries."""

    def __init__(self):
        self.sent = []
        self.send_result = None
        self.foreground = 0
        self.pids = {}
        self.images = {}
        self.descriptions = {}
        self.description_calls = 0
        self.elevated = {}
        # None: whatever window is in front is under every point.
        self.point_window = None
        self.points = []
        self.on_send = None
        self.cursor = (0, 0)
        self.size = SCREEN
        self.iconic = set()
        self.restored = []
        self.fg_calls = []
        self.fg_result = True
        self.shell_calls = []
        self.shell_result = 42

    def send_input(self, inputs):
        self.sent.append([_copy(i) for i in inputs])
        if self.on_send is not None:
            self.on_send(self.sent[-1])
        return len(inputs) if self.send_result is None else self.send_result

    def scan_code(self, vk):
        return {0x0D: 0x1C, 0x09: 0x0F, 0x11: 0x1D}.get(vk, 0)

    def screen_size(self):
        return self.size

    def cursor_pos(self):
        return self.cursor

    def foreground_window(self):
        return self.foreground

    def set_foreground_window(self, hwnd):
        self.fg_calls.append(hwnd)
        if self.fg_result:
            self.foreground = hwnd
        return self.fg_result

    def is_iconic(self, hwnd):
        return hwnd in self.iconic

    def restore_window(self, hwnd):
        self.restored.append(hwnd)

    def window_pid(self, hwnd):
        return self.pids.get(hwnd, 0)

    def window_at(self, x, y):
        self.points.append((x, y))
        return self.foreground if self.point_window is None else self.point_window

    def process_elevated(self, pid):
        return self.elevated.get(pid, False)

    def process_image(self, pid):
        return self.images.get(pid)

    def file_description(self, path):
        self.description_calls += 1
        return self.descriptions.get(path)

    def shell_execute(self, target, directory):
        self.shell_calls.append((target, directory))
        return self.shell_result


class Desk:
    """A fake desktop: two Notepad windows, a console, PowerShell, a UWP
    Calculator, an app named by its file description, and the taskbar."""

    def __init__(self):
        self.edit = FakeControl(
            EDIT, "Text editor", rect=(10, 40, 790, 590), value="hello", pid=100
        )
        self.line_up = FakeControl(BUTTON, "Line up", rect=(780, 40, 790, 50), pid=100)
        self.scrollbar = FakeControl(
            SCROLL_BAR, "Vertical", rect=(780, 40, 790, 590), children=[self.line_up]
        )
        self.pane = FakeControl(
            PANE, "", rect=(0, 0, 800, 600), children=[self.edit, self.scrollbar]
        )
        self.file_menu = FakeControl(MENU_ITEM, "File", rect=(0, 20, 40, 40), invoke=True)
        self.edit_menu = FakeControl(
            MENU_ITEM, "Edit", rect=(40, 20, 80, 40), offscreen=True, invoke=True
        )
        self.menubar = FakeControl(
            MENU_BAR,
            "Application",
            rect=(0, 20, 800, 40),
            children=[self.file_menu, self.edit_menu],
        )
        self.save = FakeControl(BUTTON, "Save", rect=(100, 100, 180, 130), invoke=True)
        self.item = FakeControl(LIST_ITEM, "a.txt", rect=(200, 200, 300, 220), invoke=True)
        self.files = FakeControl(LIST, "Files", rect=(200, 180, 400, 400), children=[self.item])
        self.password = FakeControl(
            EDIT, "Password", rect=(10, 500, 300, 520), password=True, value="hunter2"
        )
        self.hidden_button = FakeControl(BUTTON, "Hidden", rect=(0, 0, 10, 10))
        self.empty_group = FakeControl(GROUP, "", rect=(0, 0, 0, 0), children=[self.hidden_button])
        self.notepad = FakeControl(
            WINDOW,
            "Untitled - Notepad",
            rect=(0, 0, 800, 600),
            pid=100,
            hwnd=0x100,
            cls="Notepad",
            children=[
                self.pane,
                self.menubar,
                self.save,
                self.files,
                self.password,
                self.empty_group,
            ],
        )
        self.taskbar = FakeControl(PANE, "Taskbar", pid=10, hwnd=0x10, cls="Shell_TrayWnd")
        self.console = FakeControl(
            WINDOW, "C:\\WINDOWS\\system32\\cmd.exe", pid=200, hwnd=0x200, cls="ConsoleWindowClass"
        )
        self.pwsh = FakeControl(WINDOW, "PowerShell 7", pid=300, hwnd=0x300, cls="CASCADIA_OTHER")
        self.notes_edit = FakeControl(EDIT, "Notes body", rect=(910, 40, 1490, 490), pid=101)
        self.notes = FakeControl(
            WINDOW,
            "notes.txt - Notepad",
            rect=(900, 0, 1500, 500),
            pid=101,
            hwnd=0x400,
            cls="Notepad",
            children=[self.notes_edit],
        )
        self.core = FakeControl(WINDOW, "Calculator", pid=501, cls="Windows.UI.Core.CoreWindow")
        self.calc_button = FakeControl(
            BUTTON, "Seven", rect=(1000, 700, 1050, 750), pid=501, invoke=True
        )
        self.core.children = [self.calc_button]
        self.calc = FakeControl(
            WINDOW,
            "Calculator",
            rect=(950, 550, 1300, 1000),
            pid=500,
            hwnd=0x500,
            cls="ApplicationFrameWindow",
            children=[self.core],
        )
        self.thing = FakeControl(WINDOW, "Doc1", pid=600, hwnd=0x600, cls="ThingWnd")
        self.untitled = FakeControl(WINDOW, "", pid=700, hwnd=0x700)
        self.root = FakeControl(
            PANE,
            "Desktop 1",
            children=[
                self.notepad,
                self.taskbar,
                self.console,
                self.pwsh,
                self.notes,
                self.calc,
                self.thing,
                self.untitled,
            ],
        )
        self.uia = FakeUia(self.root)
        self.w32 = FakeWin32()
        self.w32.foreground = 0x100
        self.w32.pids = {0x100: 100, 0x200: 200, 0x300: 300, 0x400: 101, 0x500: 500, 0x600: 600}
        self.w32.images = {
            100: "C:\\Windows\\System32\\notepad.exe",
            101: "C:\\Windows\\System32\\notepad.exe",
            200: "C:\\Windows\\System32\\conhost.exe",
            300: "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
            500: "C:\\Windows\\System32\\ApplicationFrameHost.exe",
            501: "C:\\Program Files\\WindowsApps\\Calc\\CalculatorApp.exe",
            600: "C:\\Apps\\thing.exe",
        }
        self.w32.descriptions = {"C:\\Apps\\thing.exe": "Thing Editor"}
        for ctl in self._all(self.root):
            ctl.desk = self
        self.uia.focused = self.edit
        self.sleeps = []

    def _all(self, ctl):
        yield ctl
        for child in ctl.children:
            yield from self._all(child)

    def backend(self, **kw):
        kw.setdefault("start_menu_dirs", [])
        return WindowsBackend(
            uia=self.uia, win32=self.w32, platform="win32", sleep=self.sleeps.append, **kw
        )


@pytest.fixture
def desk():
    return Desk()


def decode(inp):
    if inp.type == INPUT_MOUSE:
        assert inp.mi.dwExtraInfo == CRAWLER_EXTRA_INFO
        return ("mouse", inp.mi.dx, inp.mi.dy, inp.mi.mouseData, inp.mi.dwFlags)
    assert inp.type == INPUT_KEYBOARD
    assert inp.ki.dwExtraInfo == CRAWLER_EXTRA_INFO
    return ("key", inp.ki.wVk, inp.ki.wScan, inp.ki.dwFlags)


def events(desk):
    return [decode(i) for batch in desk.w32.sent for i in batch]


def walk(roots, depth=0):
    """(node, depth) pairs of an outline tree, pre-order."""
    out = []
    for node in roots:
        out.append((node, depth))
        out.extend(walk(node.children, depth + 1))
    return out


def flat(roots):
    return [node for node, _ in walk(roots)]


def by_name(roots, name):
    return next(n for n in flat(roots) if n.name == name)


def abs_x(x):
    return round(x * 65535 / (SCREEN[0] - 1))


def abs_y(y):
    return round(y * 65535 / (SCREEN[1] - 1))


# --- Import safety, availability, permission, struct layout -------------------


def test_module_imports_without_windows_dependencies():
    backend_root = Path(__file__).resolve().parents[1]
    code = (
        "import sys, ctypes\n"
        "import services.tools.computer.backend_windows\n"
        "print(sorted(n for n in ('uiautomation', 'comtypes', 'ctypes.wintypes') if n in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=backend_root, capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows guard")
def test_real_win32_layer_refuses_to_load_off_windows():
    with pytest.raises(OSError):
        bw._Win32Api()


def test_unavailable_off_windows():
    ok, reason = WindowsBackend(platform="darwin").available()
    assert ok is False
    assert "Windows" in reason


def test_unavailable_without_uiautomation(monkeypatch):
    monkeypatch.setitem(sys.modules, "uiautomation", None)  # import raises ImportError
    ok, reason = WindowsBackend(platform="win32").available()
    assert ok is False
    assert "uiautomation" in reason


def test_available_with_uiautomation(desk):
    assert desk.backend().available() == (True, "")


def test_permission_is_not_required(desk):
    backend = desk.backend()
    assert backend.name == "windows"
    assert backend.permission() == "not_required"
    assert backend.request_permission() is None


@pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="64-bit layout")
def test_input_struct_matches_the_windows_x64_layout():
    assert ctypes.sizeof(INPUT) == 40
    assert ctypes.sizeof(bw.MOUSEINPUT) == 32
    assert ctypes.sizeof(bw.KEYBDINPUT) == 24
    assert INPUT.u.offset == 8


# --- Outline -------------------------------------------------------------------


def test_outline_walks_the_front_window(desk):
    nodes = desk.backend().outline(None, 100)
    assert len(nodes) == 1  # the window is the one root; the rest are its children
    assert [(d, n.role, n.name) for n, d in walk(nodes)] == [
        (0, "window", "Untitled - Notepad"),
        (1, "text field", "Text editor"),  # the unnamed pane is flattened away
        (1, "menu bar", "Application"),
        (2, "menu item", "File"),  # "Edit" is off-screen and dropped
        (1, "button", "Save"),
        (1, "list", "Files"),
        (2, "list item", "a.txt"),
        (1, "secure text field", "Password"),
        # the scroll bar subtree and the zero-size group are dropped
    ]
    assert nodes[0].bounds == (0, 0, 800, 600)  # the toolkit checks click points on it
    editor = by_name(nodes, "Text editor")
    assert editor.value == "hello"
    assert editor.secure is False
    assert editor.bounds == (10, 40, 780, 550)
    assert by_name(nodes, "Save").value is None  # buttons carry no value
    assert desk.uia.active == 0  # the COM session was closed again


def test_outline_marks_password_fields_secure_and_never_reads_them(desk):
    nodes = desk.backend().outline(None, 100)
    password = by_name(nodes, "Password")
    assert password.secure is True
    assert password.value is None
    assert desk.password.value_reads == 0


def test_outline_treats_an_unreadable_password_flag_as_secure(desk):
    desk.edit.password = "raise"
    editor = by_name(desk.backend().outline(None, 100), "Text editor")
    assert editor.secure is True
    assert editor.value is None
    assert desk.edit.value_reads == 0


def test_outline_respects_max_nodes(desk):
    backend = desk.backend()
    assert len(flat(backend.outline(None, 3))) == 3
    with pytest.raises(ValueError):
        backend.outline(None, 0)


def test_outline_stops_at_the_time_budget(desk):
    ticks = iter(range(0, 1000, 3))
    nodes = flat(desk.backend(clock=lambda: next(ticks)).outline(None, 100))
    assert 0 < len(nodes) < 8


def test_outline_skips_an_element_that_errors(desk):
    desk.save.broken = True
    names = [n.name for n in flat(desk.backend().outline(None, 100))]
    assert "Save" not in names
    assert "Files" in names


def test_outline_by_app_name(desk):
    backend = desk.backend()
    nodes = backend.outline("Calculator", 50)
    assert nodes[0].name == "Calculator"
    assert by_name(nodes, "Seven").role == "button"
    assert backend.outline("notepad.exe", 50)[0].name == "Untitled - Notepad"
    with pytest.raises(AppNotFoundError):
        backend.outline("Photoshop", 50)


def test_outline_with_nothing_in_front(desk):
    desk.w32.foreground = 0
    with pytest.raises(LookupError):
        desk.backend().outline(None, 50)


def test_outline_of_an_elevated_window_is_refused(desk):
    desk.w32.elevated[100] = True
    with pytest.raises(UIPIBlockedError) as err:
        desk.backend().outline(None, 50)
    assert "Notepad" in str(err.value)
    assert "administrator" in str(err.value)


def test_outline_checks_the_uwp_app_process_too(desk):
    desk.w32.elevated[501] = True
    with pytest.raises(UIPIBlockedError):
        desk.backend().outline("Calculator", 50)


# --- Apps and windows ----------------------------------------------------------


def test_list_apps_uses_the_names_the_toolkit_rules_use(desk):
    apps = desk.backend().list_apps()
    assert [(a.name, a.pid, a.active) for a in apps] == [
        ("Notepad", 100, True),
        ("Command Prompt", 200, False),  # console window, named by class
        ("PowerShell", 300, False),  # pwsh.exe
        ("Notepad", 101, False),
        ("Calculator", 501, False),  # the UWP app, not ApplicationFrameHost
        ("Thing Editor", 600, False),  # from the file description
    ]


def test_file_descriptions_are_cached(desk):
    backend = desk.backend()
    backend.list_apps()
    backend.list_apps()
    assert desk.w32.description_calls == 1


def test_list_windows_indexes_per_app(desk):
    windows = desk.backend().list_windows()
    notepads = [(w.title, w.index) for w in windows if w.app == "Notepad"]
    assert notepads == [("Untitled - Notepad", 0), ("notes.txt - Notepad", 1)]
    assert all(w.title for w in windows)
    assert "Taskbar" not in [w.title for w in windows]


def test_suspended_uwp_settings_is_named_system_settings(desk):
    desk.calc.Name = "Settings"
    desk.calc.children = []
    names = [a.name for a in desk.backend().list_apps()]
    assert "System Settings" in names


def test_frontmost(desk):
    backend = desk.backend()
    assert backend.frontmost() == ("Notepad", "Untitled - Notepad")
    desk.w32.foreground = 0x200
    assert backend.frontmost() == ("Command Prompt", "C:\\WINDOWS\\system32\\cmd.exe")
    desk.w32.foreground = 0
    assert backend.frontmost() == ("", "")


# --- Click ---------------------------------------------------------------------


def test_click_invokes_a_button_without_moving_the_pointer(desk):
    backend = desk.backend()
    save = by_name(backend.outline(None, 100), "Save")
    backend.click(save)
    assert desk.save.invoked == 1
    assert desk.w32.sent == []


def test_click_on_a_list_item_is_a_real_click_not_invoke(desk):
    backend = desk.backend()
    item = by_name(backend.outline(None, 100), "a.txt")
    backend.click(item)
    assert desk.item.invoked == 0  # Invoke on a list item means "open"
    assert events(desk) == [
        ("mouse", abs_x(250), abs_y(210), 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE),
        ("mouse", 0, 0, 0, MOUSEEVENTF_LEFTDOWN),
        ("mouse", 0, 0, 0, MOUSEEVENTF_LEFTUP),
    ]


def test_double_click_always_uses_sendinput(desk):
    backend = desk.backend()
    save = by_name(backend.outline(None, 100), "Save")
    backend.click(save, double=True)
    assert desk.save.invoked == 0
    assert [e[4] for e in events(desk)] == [
        MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
        MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP,
    ]


def test_click_on_a_covered_element_is_refused(desk):
    backend = desk.backend()
    item = by_name(backend.outline(None, 100), "a.txt")
    desk.w32.point_window = 0x600  # another app's window is on top of the item
    with pytest.raises(LookupError) as err:
        backend.click(item)
    assert "covered" in str(err.value)
    assert desk.w32.fg_calls == [0x100]  # it tried bringing Notepad forward first
    assert desk.w32.sent == []


def test_click_brings_the_element_window_forward_when_covered(desk):
    backend = desk.backend()
    item = by_name(backend.outline(None, 100), "a.txt")
    desk.w32.foreground = 0x400  # the other Notepad window is in front
    backend.click(item)
    assert desk.w32.fg_calls == [0x100]
    assert len(events(desk)) == 3


def test_click_at_a_point(desk):
    desk.backend().click((1919, 0))
    first = events(desk)[0]
    assert first == ("mouse", 65535, 0, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE)
    # Checked twice before sending: not covered, and not elevated.
    assert desk.w32.points == [(1919, 0), (1919, 0)]


@pytest.mark.parametrize("point", [(1920, 10), (-1, 10), (10, 1080)])
def test_click_off_the_main_display_is_refused(desk, point):
    with pytest.raises(ValueError):
        desk.backend().click(point)
    assert desk.w32.sent == []


@pytest.mark.parametrize("bad", [(1.5, 2), (1,), "10,10", (True, 3)])
def test_click_target_must_be_a_node_or_int_pair(desk, bad):
    with pytest.raises(TypeError):
        desk.backend().click(bad)


def test_click_on_an_elevated_window_is_refused(desk):
    desk.w32.elevated[100] = True
    with pytest.raises(UIPIBlockedError) as err:
        desk.backend().click((50, 50))
    assert "running as administrator" in str(err.value)
    assert desk.w32.sent == []


def test_click_when_elevation_cannot_be_read_is_refused(desk):
    desk.w32.elevated[100] = None
    with pytest.raises(UIPIBlockedError) as err:
        desk.backend().click((50, 50))
    assert "would not let Crawler check" in str(err.value)
    assert desk.w32.sent == []


def test_invoke_on_an_elevated_window_is_refused(desk):
    backend = desk.backend()
    save = by_name(backend.outline(None, 100), "Save")
    desk.w32.elevated[100] = True
    with pytest.raises(UIPIBlockedError):
        backend.click(save)
    assert desk.save.invoked == 0


def test_click_on_a_changed_element_is_stale(desk):
    backend = desk.backend()
    save = by_name(backend.outline(None, 100), "Save")
    desk.save.Name = "Don't Save"
    with pytest.raises(StaleElementError):
        backend.click(save)
    assert desk.save.invoked == 0


def test_click_on_a_replaced_element_is_stale(desk):
    backend = desk.backend()
    save = by_name(backend.outline(None, 100), "Save")
    impostor = FakeControl(BUTTON, "Save", rect=(100, 100, 180, 130), invoke=True)
    desk.notepad.children[2] = impostor  # same place, type and name; new runtime id
    with pytest.raises(StaleElementError):
        backend.click(save)
    assert impostor.invoked == 0


def test_click_after_the_window_closed_is_stale(desk):
    backend = desk.backend()
    save = by_name(backend.outline(None, 100), "Save")
    desk.root.children.remove(desk.notepad)
    with pytest.raises(StaleElementError):
        backend.click(save)


def test_click_on_a_node_from_another_backend_is_rejected(desk):
    foreign = Node(
        role="button",
        name="Save",
        value=None,
        secure=False,
        bounds=(0, 0, 1, 1),
        handle=object(),
    )
    with pytest.raises(TypeError):
        desk.backend().click(foreign)


# --- Typing ----------------------------------------------------------------------


def unicode_events(text):
    out = []
    raw = text.encode("utf-16-le")
    for i in range(0, len(raw), 2):
        unit = int.from_bytes(raw[i : i + 2], "little")
        out.append(("key", 0, unit, KEYEVENTF_UNICODE))
        out.append(("key", 0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP))
    return out


def test_type_text_packs_unicode_and_real_enter_and_tab(desk):
    desk.backend().type_text("Hi\r\n😀\tx", None)
    assert events(desk) == [
        *unicode_events("H"),
        *unicode_events("i"),
        ("key", 0x0D, 0x1C, 0),
        ("key", 0x0D, 0x1C, KEYEVENTF_KEYUP),
        *unicode_events("😀"),  # surrogate pair D83D DE00
        ("key", 0x09, 0x0F, 0),
        ("key", 0x09, 0x0F, KEYEVENTF_KEYUP),
        *unicode_events("x"),
    ]
    assert [e[2] for e in unicode_events("😀")[::2]] == [0xD83D, 0xDE00]
    # A new batch after each Enter and Tab, with time for focus to settle.
    assert len(desk.w32.sent) == 3
    assert desk.sleeps == [bw.FOCUS_SETTLE_S, bw.FOCUS_SETTLE_S]


def test_typing_stops_when_a_tab_lands_in_a_password_field(desk):
    def tab_moves_focus(batch):
        if any(i.type == INPUT_KEYBOARD and i.ki.wVk == 0x09 for i in batch):
            desk.uia.focused = desk.password

    desk.w32.on_send = tab_moves_focus
    with pytest.raises(SecureFieldError):
        desk.backend().type_text("alice\thunter2", None)
    assert events(desk) == [
        *unicode_events("alice"),
        ("key", 0x09, 0x0F, 0),
        ("key", 0x09, 0x0F, KEYEVENTF_KEYUP),
    ]  # "hunter2" was never sent


def test_typing_stops_when_another_window_comes_to_the_front(desk):
    def steal_focus(batch):
        desk.w32.foreground = 0x400

    desk.w32.on_send = steal_focus
    with pytest.raises(OSError):
        desk.backend().type_text("a" * 100, None)
    assert [len(batch) for batch in desk.w32.sent] == [128]


def test_type_text_is_sent_in_chunks(desk):
    desk.backend().type_text("a" * 150, None)
    assert [len(batch) for batch in desk.w32.sent] == [128, 128, 44]
    assert desk.sleeps == [bw.TEXT_CHUNK_PAUSE_S, bw.TEXT_CHUNK_PAUSE_S]


def test_type_text_into_a_target_focuses_it_first(desk):
    backend = desk.backend()
    editor = by_name(backend.outline(None, 100), "Text editor")
    desk.uia.focused = desk.save
    backend.type_text("ok", editor)
    assert desk.edit.focus_calls == 1
    assert events(desk) == unicode_events("ok")


def test_type_text_brings_a_background_target_to_the_front(desk):
    backend = desk.backend()
    desk.w32.foreground = 0x400
    body = by_name(backend.outline(None, 100), "Notes body")
    desk.w32.foreground = 0x100
    backend.type_text("ok", body)
    assert desk.w32.fg_calls == [0x400]
    assert events(desk) == unicode_events("ok")


def test_type_text_refuses_when_the_target_cannot_come_to_the_front(desk):
    backend = desk.backend()
    desk.w32.foreground = 0x400
    body = by_name(backend.outline(None, 100), "Notes body")
    desk.w32.foreground = 0x100
    desk.w32.fg_result = False
    with pytest.raises(OSError):
        backend.type_text("ok", body)
    assert desk.w32.sent == []


def test_type_text_clicks_a_target_that_will_not_take_focus(desk):
    backend = desk.backend()
    editor = by_name(backend.outline(None, 100), "Text editor")
    desk.edit.focus_ok = False
    backend.type_text("ok", editor)
    got = events(desk)
    assert got[:3] == [
        ("mouse", abs_x(400), abs_y(315), 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE),
        ("mouse", 0, 0, 0, MOUSEEVENTF_LEFTDOWN),
        ("mouse", 0, 0, 0, MOUSEEVENTF_LEFTUP),
    ]
    assert got[3:] == unicode_events("ok")


def test_type_text_refuses_a_secure_target(desk):
    backend = desk.backend()
    password = by_name(backend.outline(None, 100), "Password")
    with pytest.raises(SecureFieldError):
        backend.type_text("hunter2", password)
    assert desk.w32.sent == []
    assert desk.password.focus_calls == 0


def test_type_text_rechecks_the_live_element(desk):
    backend = desk.backend()
    editor = by_name(backend.outline(None, 100), "Text editor")
    desk.edit.password = True  # became a password field since the outline
    with pytest.raises(SecureFieldError):
        backend.type_text("secret", editor)
    assert desk.w32.sent == []


def test_type_text_refuses_when_a_password_field_has_focus(desk):
    desk.uia.focused = desk.password
    with pytest.raises(SecureFieldError):
        desk.backend().type_text("secret", None)
    assert desk.w32.sent == []


def test_type_text_refuses_when_focus_cannot_be_read(desk):
    desk.uia.focus_error = True
    with pytest.raises(WindowsRefusal):
        desk.backend().type_text("secret", None)
    assert desk.w32.sent == []


def test_type_text_into_an_elevated_window_is_refused(desk):
    desk.w32.elevated[100] = True
    with pytest.raises(UIPIBlockedError):
        desk.backend().type_text("hello", None)
    assert desk.w32.sent == []


@pytest.mark.parametrize(
    "text, error",
    [
        ("", ValueError),
        ("a" * 2001, ValueError),
        ("bell\x07", ValueError),
        ("\ud800", ValueError),
        (42, TypeError),
    ],
)
def test_type_text_validates_the_text(desk, text, error):
    with pytest.raises(error):
        desk.backend().type_text(text, None)
    assert desk.w32.sent == []


def test_a_short_sendinput_is_an_error(desk):
    desk.w32.send_result = 0
    with pytest.raises(OSError):
        desk.backend().type_text("x", None)


# --- Keys ------------------------------------------------------------------------


def test_cmd_s_is_ctrl_s(desk):
    desk.backend().key(KeyCombo(frozenset({"cmd"}), "s"))
    assert events(desk) == [
        ("key", 0x11, 0x1D, 0),
        ("key", 0x53, 0, 0),
        ("key", 0x53, 0, KEYEVENTF_KEYUP),
        ("key", 0x11, 0x1D, KEYEVENTF_KEYUP),
    ]
    assert len(desk.w32.sent) == 1  # one atomic SendInput batch


def test_modifiers_press_in_order_and_release_in_reverse(desk):
    desk.backend().key(KeyCombo(frozenset({"shift", "ctrl", "control"}), "left"))
    assert [(e[1], e[3]) for e in events(desk)] == [
        (0x11, 0),
        (0x10, 0),
        (0x25, KEYEVENTF_EXTENDEDKEY),
        (0x25, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP),
        (0x10, KEYEVENTF_KEYUP),
        (0x11, KEYEVENTF_KEYUP),
    ]


def test_win_key_is_extended(desk):
    desk.backend().key(KeyCombo(frozenset({"win"}), "e"))
    assert events(desk)[0][1:] == (0x5B, 0, KEYEVENTF_EXTENDEDKEY)


@pytest.mark.parametrize(
    "key, vk",
    [
        ("a", 0x41),
        ("Z", 0x5A),
        ("7", 0x37),
        ("f5", 0x74),
        ("F24", 0x87),
        ("enter", 0x0D),
        ("Return", 0x0D),
        ("esc", 0x1B),
        ("space", 0x20),
        ("page_down", 0x22),
        ("Page Up", 0x21),
        ("backspace", 0x08),
        ("delete", 0x2E),
        ("tab", 0x09),
        ("=", 0xBB),
        ("-", 0xBD),
        ("plus", 0xBB),
        (",", 0xBC),
        (".", 0xBE),
        ("/", 0xBF),
        ("[", 0xDB),
        ("up", 0x26),
    ],
)
def test_key_vk_mapping(key, vk):
    assert bw.key_vk(key) == vk


@pytest.mark.parametrize("key", ["", "ß", "f25", "hyper", "ctrl", "shift"])
def test_unknown_keys_are_rejected(key):
    with pytest.raises(ValueError):
        bw.key_vk(key)


@pytest.mark.parametrize("modifier", ["fn", "globe", "hyper"])
def test_unsendable_modifiers_are_rejected(desk, modifier):
    with pytest.raises(ValueError):
        desk.backend().key(KeyCombo(frozenset({modifier}), "f"))
    assert desk.w32.sent == []


def test_keys_to_an_elevated_window_are_refused(desk):
    desk.w32.foreground = 0x300
    desk.w32.elevated[300] = True
    with pytest.raises(UIPIBlockedError) as err:
        desk.backend().key(KeyCombo(frozenset({"ctrl"}), "c"))
    assert "PowerShell" in str(err.value)
    assert desk.w32.sent == []


def test_keys_with_nothing_in_front(desk):
    desk.w32.foreground = 0
    with pytest.raises(LookupError):
        desk.backend().key(KeyCombo(frozenset(), "enter"))


# --- Scroll ----------------------------------------------------------------------


def test_scroll_down_sends_one_notch_per_step(desk):
    desk.w32.cursor = (300, 300)  # inside the front window
    desk.backend().scroll("down", 3)
    assert events(desk) == [("mouse", 0, 0, (-120) & 0xFFFFFFFF, MOUSEEVENTF_WHEEL)] * 3
    assert desk.w32.points == [(300, 300)]


def test_scroll_moves_the_pointer_into_the_front_window_first(desk):
    desk.w32.cursor = (1800, 1000)  # outside Notepad (0,0 - 800,600)
    desk.backend().scroll("up", 1)
    assert events(desk) == [
        ("mouse", abs_x(400), abs_y(300), 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE),
        ("mouse", 0, 0, 120, MOUSEEVENTF_WHEEL),
    ]
    assert desk.w32.points == [(400, 300)]


def test_horizontal_scroll(desk):
    desk.w32.cursor = (300, 300)
    backend = desk.backend()
    backend.scroll("right", 1)
    backend.scroll("left", 1)
    assert events(desk) == [
        ("mouse", 0, 0, 120, MOUSEEVENTF_HWHEEL),
        ("mouse", 0, 0, (-120) & 0xFFFFFFFF, MOUSEEVENTF_HWHEEL),
    ]


@pytest.mark.parametrize(
    "direction, amount", [("sideways", 1), ("down", 0), ("down", 51), ("up", 2.5), ("up", True)]
)
def test_scroll_validates_arguments(desk, direction, amount):
    with pytest.raises(ValueError):
        desk.backend().scroll(direction, amount)
    assert desk.w32.sent == []


def test_scroll_over_an_elevated_window_is_refused(desk):
    desk.w32.cursor = (300, 300)
    desk.w32.elevated[100] = True
    with pytest.raises(UIPIBlockedError):
        desk.backend().scroll("down", 1)
    assert desk.w32.sent == []


# --- Open app ----------------------------------------------------------------------


def test_open_app_by_friendly_name(desk, monkeypatch):
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\owner")
    backend = desk.backend()
    backend.open_app("Calculator")
    backend.open_app("notepad")
    assert desk.w32.shell_calls == [("calc", "C:\\Users\\owner"), ("notepad", "C:\\Users\\owner")]


def test_open_app_prefers_a_start_menu_shortcut(desk, tmp_path):
    programs = tmp_path / "Programs"
    (programs / "Visual Studio Code").mkdir(parents=True)
    shortcut = programs / "Visual Studio Code" / "Visual Studio Code.lnk"
    shortcut.write_bytes(b"")
    desk.backend(start_menu_dirs=[tmp_path / "missing", programs]).open_app("visual studio code")
    assert desk.w32.shell_calls[0][0] == str(shortcut)


@pytest.mark.parametrize(
    "name",
    [
        "cmd",
        "CMD.EXE",
        "Command Prompt",
        "PowerShell",
        "pwsh",
        "Windows Terminal",
        "wt",
        "regedit",
        "Registry Editor",
        "Task Manager",
        "taskmgr",
        "Settings",
        "Control Panel",
        "1Password",
        "Bitwarden",
        "mshta",
        "rundll32",
        "Crawler AI",
        "Windows PowerShell (x86)",
        "Developer Command Prompt for VS 2022",
        "Git Bash",
        "Python 3.12 (64-bit)",
        "Ubuntu 22.04",
        "Node.js",
        "Terminal Preview",
        "Azure Cloud Shell",
        "Sound Settings",
    ],
)
def test_open_app_refuses_shells_system_tools_and_password_managers(desk, name, tmp_path):
    programs = tmp_path / "Programs"
    programs.mkdir()
    (programs / f"{name}.lnk").write_bytes(b"")  # even when a shortcut exists
    with pytest.raises(BlockedAppError):
        desk.backend(start_menu_dirs=[programs]).open_app(name)
    assert desk.w32.shell_calls == []


@pytest.mark.parametrize(
    "name",
    [
        "C:\\Windows\\System32\\calc.exe",
        "..\\evil",
        "ms-photos:",
        "https://example.com",
        "notepad && calc",
        "%COMSPEC%",
        "evil.bat",
        "setup.msi",
        "notepad /c",
        "  ",
        "",
    ],
)
def test_open_app_takes_a_bare_app_name_only(desk, name):
    with pytest.raises(ValueError):
        desk.backend().open_app(name)
    assert desk.w32.shell_calls == []


@pytest.mark.parametrize("name", ["Notepad++", "Visual Studio Code", "Paint.NET", "Spotify"])
def test_open_app_does_not_overblock_ordinary_apps(desk, name, tmp_path):
    shortcut = tmp_path / f"{name}.lnk"
    shortcut.write_bytes(b"")
    desk.backend(start_menu_dirs=[tmp_path]).open_app(name)
    assert desk.w32.shell_calls[0][0] == str(shortcut)


def test_open_app_needs_a_shortcut_for_a_dotted_name(desk, tmp_path):
    with pytest.raises(ValueError):
        desk.backend(start_menu_dirs=[tmp_path]).open_app("Paint.NET")
    assert desk.w32.shell_calls == []


def test_open_app_reports_a_missing_app(desk):
    desk.w32.shell_result = 2
    with pytest.raises(LookupError):
        desk.backend().open_app("Photoshop")
    desk.w32.shell_result = 5
    with pytest.raises(OSError):
        desk.backend().open_app("Photoshop")


# --- Focus window -------------------------------------------------------------------


def test_focus_window_by_app_and_index(desk):
    desk.backend().focus_window("Notepad", 1)
    assert desk.w32.fg_calls == [0x400]
    assert desk.w32.restored == []


def test_focus_window_restores_a_minimised_window(desk):
    desk.w32.iconic.add(0x400)
    desk.backend().focus_window("notepad", 1)
    assert desk.w32.restored == [0x400]


def test_focus_window_falls_back_to_uia_and_reports_failure(desk):
    desk.w32.fg_result = False
    with pytest.raises(OSError):
        desk.backend().focus_window("Notepad", 1)
    assert desk.notes.focus_calls == 1


def test_focus_window_lookup_errors(desk):
    backend = desk.backend()
    with pytest.raises(LookupError):
        backend.focus_window("Notepad", 2)
    with pytest.raises(LookupError):
        backend.focus_window("Photoshop", 0)
    with pytest.raises(ValueError):
        backend.focus_window("Notepad", -1)


@pytest.mark.parametrize("query", ["pwsh", "PowerShell", "Command Prompt", "pwsh.exe"])
def test_focus_window_refuses_a_window_that_resolves_to_a_blocked_app(desk, query):
    # The toolkit checks the model's spelling; the backend matches executable
    # stems too, so it re-checks what the window really is before raising it.
    with pytest.raises(BlockedAppError) as err:
        desk.backend().focus_window(query, 0)
    assert isinstance(err.value, BlockedTargetError)
    assert desk.w32.fg_calls == [] and desk.w32.restored == []
    assert desk.pwsh.focus_calls == 0 and desk.console.focus_calls == 0


def test_click_at_a_point_covered_by_another_app_is_refused(desk):
    desk.w32.point_window = 0x600  # "Thing Editor" sits over Notepad there
    with pytest.raises(CoveredTargetError) as err:
        desk.backend().click((50, 50))
    assert isinstance(err.value, LookupError)
    assert desk.w32.sent == []


def test_backend_refusals_are_core_error_types():
    assert issubclass(SecureFieldError, SecureTargetError)
    assert issubclass(BlockedAppError, BlockedTargetError)
    assert issubclass(bw.CoveredError, CoveredTargetError)
    assert issubclass(bw.CoveredError, LookupError)


def test_focus_window_on_an_elevated_window_is_refused(desk):
    desk.w32.elevated[101] = True
    with pytest.raises(UIPIBlockedError):
        desk.backend().focus_window("Notepad", 1)
    assert desk.w32.fg_calls == []


# --- COM sessions -------------------------------------------------------------------


def test_every_call_runs_inside_a_uia_thread_session(desk):
    backend = desk.backend()
    backend.list_apps()
    backend.list_windows()
    backend.frontmost()
    backend.outline(None, 10)
    backend.key(KeyCombo(frozenset(), "a"))
    assert desk.uia.sessions == 5
    assert desk.uia.active == 0


# --- Conformance with the core protocol (backend.py) ------------------------------


def test_the_backend_implements_the_protocol(desk):
    assert isinstance(desk.backend(), ComputerBackend)


def test_select_backend_returns_the_windows_backend_without_loading_anything(monkeypatch):
    monkeypatch.setitem(sys.modules, "uiautomation", None)  # any import would raise
    for name in ("windows", "win32", "Windows"):
        backend = select_backend(name)
        assert isinstance(backend, WindowsBackend)
        assert backend._uia_module is None and backend._win32 is None


def test_failures_are_the_core_error_types():
    assert issubclass(UIPIBlockedError, ElevatedTargetError)
    assert issubclass(StaleElementError, ElementGoneError)
    assert issubclass(bw.WindowsAppNotFoundError, AppNotFoundError)
    # Still the built-in types the backend's own callers catch.
    assert issubclass(UIPIBlockedError, PermissionError)
    assert issubclass(StaleElementError, LookupError)
    assert issubclass(bw.WindowsAppNotFoundError, LookupError)


def test_missing_apps_and_windows_raise_app_not_found(desk):
    backend = desk.backend()
    with pytest.raises(AppNotFoundError):
        backend.focus_window("Photoshop", 0)
    with pytest.raises(AppNotFoundError):
        backend.focus_window("Notepad", 5)
    desk.w32.shell_result = 2  # ERROR_FILE_NOT_FOUND
    with pytest.raises(AppNotFoundError):
        backend.open_app("Nope")


def test_outline_keeps_an_off_screen_text_field_for_the_payment_check(desk):
    card = FakeControl(EDIT, "Card number", rect=(10, 900, 300, 920), offscreen=True, value="")
    card.children = [FakeControl(TEXT, "inner", rect=(10, 900, 300, 920))]
    desk.notepad.children.append(card)
    nodes = flat(desk.backend().outline(None, 100))
    node = by_name([*nodes], "Card number")
    assert node.offscreen is True
    assert "inner" not in [n.name for n in nodes]  # not descended into
    assert "Edit" not in [n.name for n in nodes]  # an off-screen menu item still goes


def test_outline_reports_focus_and_disabled_state(desk):
    desk.edit.HasKeyboardFocus = True
    desk.save.IsEnabled = False
    nodes = desk.backend().outline(None, 100)
    assert by_name(nodes, "Text editor").focused is True
    assert by_name(nodes, "Save").enabled is False
    assert by_name(nodes, "Files").focused is False and by_name(nodes, "Files").enabled is True


def test_focused_describes_the_focused_element(desk):
    node = desk.backend().focused()
    assert node is not None
    assert (node.role, node.name, node.value, node.secure, node.focused) == (
        "text field",
        "Text editor",
        "hello",
        False,
        True,
    )
    assert desk.uia.active == 0


def test_focused_never_reads_a_password_value(desk):
    desk.uia.focused = desk.password
    node = desk.backend().focused()
    assert node is not None and node.secure is True and node.value is None
    assert node.role == "secure text field"
    assert desk.password.value_reads == 0


def test_focused_none_or_error(desk):
    desk.uia.focused = None
    assert desk.backend().focused() is None
    desk.uia.focus_error = True
    with pytest.raises(RuntimeError):  # the toolkit treats this as "unknown": no typing
        desk.backend().focused()


def test_list_apps_marks_elevated_apps(desk):
    desk.w32.elevated[300] = True
    apps = {a.pid: a for a in desk.backend().list_apps()}
    assert apps[300].elevated is True
    assert apps[100].elevated is False


# --- The toolkit on top of this backend (all fakes) -------------------------------


@pytest.mark.asyncio
async def test_toolkit_observes_and_acts_through_the_windows_backend(desk):
    import re

    from services.tools.computer.toolkit import ComputerToolkit

    kit = ComputerToolkit(desk.backend(), cancel_flag=lambda uid: False)
    result = await kit.execute("observe", {"action": "outline"}, user_id="u1")
    assert result["ok"] is True, result
    assert result["frontmost_app"] == "Notepad"
    assert result["secure_fields_redacted"] == 1
    assert "hunter2" not in "\n".join(result["outline"])

    def ref(needle):
        line = next(line for line in result["outline"] if needle in line)
        return re.search(r"\[ref=(d\d+)\]", line).group(1)

    refused = await kit.execute(
        "act", {"action": "type", "ref": ref('"Password"'), "text": "x"}, user_id="u1"
    )
    assert refused["ok"] is False and refused["refused"] is True
    assert desk.w32.sent == []

    done = await kit.execute("act", {"action": "click", "ref": ref('"Save"')}, user_id="u1")
    assert done["ok"] is True, done
    assert desk.save.invoked == 1 and desk.w32.sent == []
