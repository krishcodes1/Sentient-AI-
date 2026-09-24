"""Tests for the macOS computer_control backend against fake pyobjc modules: the
accessibility-tree walk, secure-field handling, AXPress versus synthetic clicks,
Unicode typing chunks, key-code mapping, scroll events and app/window control.

Why it exists: The real backend posts input to the window server and reads other
apps' UI. Here every pyobjc entry point is a fake handed to the backend, and an
autouse fixture swaps the real posting/acting/reading functions for tripwires,
so no test can click, type, scroll or read the accessibility tree on the
development machine — and any test that tried would fail.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from services.tools.computer import backend_mac as bm
from services.tools.computer.backend import (
    AppInfo,
    AppNotFoundError,
    BlockedTargetError,
    ComputerBackend,
    CoveredTargetError,
    ElementGoneError,
    KeyCombo,
    Node,
    SecureTargetError,
    WindowInfo,
    select_backend,
)

# Everything below runs against fakes (platform="darwin" is injected), so the
# suite also runs on Linux CI; only the real-pyobjc symbol check needs a Mac.

_REAL_LOAD = bm.load_pyobjc

# Real pyobjc functions that act on, or read from, the live desktop.
_REAL_ENTRY_POINTS = {
    "Quartz": (
        "CGEventPost",
        "CGEventPostToPid",
        "CGEventPostToPSN",
        "CGEventTapPostEvent",
        "CGWindowListCopyWindowInfo",
    ),
    "ApplicationServices": (
        "AXIsProcessTrusted",
        "AXIsProcessTrustedWithOptions",
        "AXUIElementCreateApplication",
        "AXUIElementCreateSystemWide",
        "AXUIElementCopyAttributeValue",
        "AXUIElementCopyActionNames",
        "AXUIElementPerformAction",
        "AXUIElementSetAttributeValue",
        "AXUIElementCopyElementAtPosition",
    ),
    "AppKit": ("NSWorkspace", "NSRunningApplication"),
}


class _Tripwire:
    """Stands in for a real pyobjc function or class; any use is recorded."""

    def __init__(self, label: str, calls: list[str]) -> None:
        self._label = label
        self._calls = calls

    def __call__(self, *args, **kwargs):
        self._calls.append(self._label)
        raise AssertionError(f"a unit test reached the real {self._label}")

    def __getattr__(self, attr: str):
        self._calls.append(f"{self._label}.{attr}")
        raise AssertionError(f"a unit test reached the real {self._label}.{attr}")


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch):
    """Safety net for the whole module: nothing real is posted or read.

    Backends under test get fakes injected; this also replaces the real
    entry points, the default loader, the pid probe and the Settings opener,
    so a backend built without fakes fails loudly instead of acting. The
    calls are also recorded, because the backend swallows some exceptions.
    """
    calls: list[str] = []
    monkeypatch.setattr(bm, "load_pyobjc", _Tripwire("load_pyobjc", calls))
    monkeypatch.setattr(bm, "_pid_alive", _Tripwire("os.kill probe", calls))
    from services.capabilities import macos

    monkeypatch.setattr(macos, "open_settings", _Tripwire("macos.open_settings", calls))
    for module_name, names in _REAL_ENTRY_POINTS.items():
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        for name in names:
            if hasattr(module, name):
                monkeypatch.setattr(module, name, _Tripwire(f"{module_name}.{name}", calls))
    yield
    assert calls == [], f"real desktop entry points were used: {calls}"


# --- Fakes -------------------------------------------------------------------


class AXVal:
    """Fake AXValueRef holding a CGPoint or CGSize."""

    def __init__(self, kind, payload):
        self.kind = kind
        self.payload = payload


class El:
    """Fake AXUIElement. Keyword attributes get the AX prefix: Title= -> AXTitle."""

    def __init__(self, role, label=None, *, children=(), actions=(), pos=None, size=None, **attrs):
        self.label = label or role
        self.attrs = {"AXRole": role}
        for key, value in attrs.items():
            self.attrs["AX" + key] = value
        if pos is not None:
            self.attrs["AXPosition"] = AXVal(1, SimpleNamespace(x=pos[0], y=pos[1]))
        if size is not None:
            self.attrs["AXSize"] = AXVal(2, SimpleNamespace(width=size[0], height=size[1]))
        if children:
            self.attrs["AXChildren"] = tuple(children)
        self.actions = tuple(actions)
        self.errors: dict[str, int] = {}
        self.action_results: dict[str, int] = {}
        self.set_results: dict[str, int] = {}
        self.invalid = False
        self.pid = None

    def move(self, x, y):
        self.attrs["AXPosition"] = AXVal(1, SimpleNamespace(x=x, y=y))


class FakeAX:
    kAXTrustedCheckOptionPrompt = "AXTrustedCheckOptionPrompt"

    def __init__(self, log):
        self.log = log
        self.trusted = True
        self.api_disabled = False
        self.system = El("AXSystemWide", "system")
        self.apps: dict[int, El] = {}
        self.reads: list[tuple[str, str]] = []
        self.performed: list[tuple[str, str]] = []
        self.set_calls: list[tuple[str, str, object]] = []
        self.prompts: list[dict] = []
        self.timeouts: list[tuple[str, float]] = []
        self.on_read = None
        # (x, y) -> (err, element) for AXUIElementCopyElementAtPosition; None
        # means the frontmost app's element is under every point.
        self.element_at = None
        self.positions: list[tuple[float, float]] = []

    def AXUIElementCopyElementAtPosition(self, application, x, y, out):
        assert out is None and application is self.system
        self.positions.append((x, y))
        if self.element_at is not None:
            return self.element_at(x, y)
        front = self.system.attrs.get("AXFocusedApplication")
        hit = El("AXButton", "under-the-pointer")
        hit.pid = front.pid if front is not None else None
        return 0, hit

    def AXIsProcessTrusted(self):
        return self.trusted

    def AXIsProcessTrustedWithOptions(self, options):
        self.prompts.append(dict(options))
        return self.trusted

    def AXUIElementCreateApplication(self, pid):
        return self.apps.setdefault(pid, El("AXApplication", f"app-{pid}"))

    def AXUIElementCreateSystemWide(self):
        return self.system

    def AXUIElementCopyAttributeValue(self, element, attribute, out):
        assert out is None
        self.reads.append((element.label, attribute))
        if self.on_read is not None:
            self.on_read(element, attribute)
        if self.api_disabled:
            return -25211, None
        if element.invalid:
            return -25202, None
        if attribute in element.errors:
            return element.errors[attribute], None
        if attribute in element.attrs:
            return 0, element.attrs[attribute]
        return -25205, None

    def AXUIElementCopyActionNames(self, element, out):
        assert out is None
        if element.invalid:
            return -25202, None
        return 0, element.actions

    def AXUIElementPerformAction(self, element, action):
        self.performed.append((element.label, action))
        self.log.append(("perform", element.label, action))
        if element.invalid:
            return -25202
        return element.action_results.get(action, 0)

    def AXUIElementSetAttributeValue(self, element, attribute, value):
        self.set_calls.append((element.label, attribute, value))
        self.log.append(("set", element.label, attribute))
        if element.invalid:
            return -25202
        err = element.set_results.get(attribute, 0)
        if err == 0 and attribute == "AXFocused" and value:
            self.system.attrs["AXFocusedUIElement"] = element
        return err

    def AXUIElementSetMessagingTimeout(self, element, seconds):
        self.timeouts.append((element.label, seconds))
        return 0

    def AXUIElementGetPid(self, element, out):
        assert out is None
        return (0, element.pid) if element.pid else (-25202, 0)

    def AXValueGetValue(self, value, kind, out):
        assert out is None
        return value.kind == kind, value.payload


class Ev:
    """Fake CGEvent."""

    def __init__(self, kind, **data):
        self.kind = kind
        self.flags = None
        self.fields: dict[int, int] = {}
        self.text = None
        self.__dict__.update(data)


class FakeQuartz:
    def __init__(self, log):
        self.log = log
        self.posted: list[Ev] = []
        self.window_infos: list[dict] = []
        self.fail_post = None
        self.on_post = None

    def CGEventCreateMouseEvent(self, source, event_type, point, button):
        assert source is None
        return Ev("mouse", type=event_type, point=point, button=button)

    def CGEventCreateKeyboardEvent(self, source, code, down):
        assert source is None
        return Ev("key", code=code, down=down)

    def CGEventKeyboardSetUnicodeString(self, event, length, text):
        # The real call takes the length in UTF-16 units; >20 gets truncated.
        assert length == len(text.encode("utf-16-le")) // 2
        assert length <= 20
        event.text = text

    def CGEventCreateScrollWheelEvent(self, source, units, count, delta):
        return Ev("scroll", units=units, count=count, delta=delta, variant=1)

    def CGEventCreateScrollWheelEvent2(self, source, units, count, wheel1, wheel2, wheel3):
        return Ev(
            "scroll", units=units, count=count, delta=wheel1, variant=2, rest=(wheel2, wheel3)
        )

    def CGEventSetFlags(self, event, flags):
        event.flags = flags

    def CGEventSetIntegerValueField(self, event, field, value):
        event.fields[field] = value

    def CGEventPost(self, tap, event):
        assert tap == 0  # kCGHIDEventTap
        if self.fail_post is not None and self.fail_post(event):
            raise RuntimeError("post failed")
        self.posted.append(event)
        self.log.append(("post", event.kind))
        if self.on_post is not None:
            self.on_post(self.posted)

    def CGWindowListCopyWindowInfo(self, options, relative_to):
        assert options == 16 and relative_to == 0
        return list(self.window_infos)


class RunApp:
    """Fake NSRunningApplication."""

    def __init__(self, name, pid, bundle="", policy=0):
        self.name, self.pid, self.bundle, self.policy = name, pid, bundle, policy
        self.activations: list[int] = []
        self.activate_result = True

    def localizedName(self):
        return self.name

    def processIdentifier(self):
        return self.pid

    def bundleIdentifier(self):
        return self.bundle

    def activationPolicy(self):
        return self.policy

    def activateWithOptions_(self, options):
        self.activations.append(options)
        return self.activate_result


class FakeConfig:
    def __init__(self):
        self.activates = None

    def setActivates_(self, flag):
        self.activates = flag


class FakeWorkspace:
    def __init__(self):
        self.apps: list[RunApp] = []
        self.front = None
        self.paths: dict[str, str] = {}
        self.launchable: set[str] = set()
        self.opened: list[tuple[object, object]] = []
        self.launched: list[str] = []
        self.on_open = None
        self.open_error = None

    def runningApplications(self):
        return list(self.apps)

    def frontmostApplication(self):
        return self.front

    def fullPathForApplication_(self, name):
        return self.paths.get(name)

    def openApplicationAtURL_configuration_completionHandler_(self, url, config, handler):
        self.opened.append((url, config.activates))
        if self.on_open is not None:
            self.on_open()
        handler(None, self.open_error)  # AppKit calls back with (app, error)

    def launchApplication_(self, name):
        self.launched.append(name)
        ok = name in self.launchable
        if ok and self.on_open is not None:
            self.on_open()
        return ok


class FakeAppKit:
    def __init__(self):
        self.workspace = FakeWorkspace()
        self.by_pid: dict[int, RunApp] = {}
        workspace = self.workspace
        self.NSWorkspace = SimpleNamespace(sharedWorkspace=lambda: workspace)
        self.NSRunningApplication = SimpleNamespace(
            runningApplicationWithProcessIdentifier_=lambda pid: self.by_pid.get(pid)
        )
        self.NSURL = SimpleNamespace(fileURLWithPath_=lambda path: ("file-url", path))
        self.NSWorkspaceOpenConfiguration = SimpleNamespace(configuration=FakeConfig)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Desk(SimpleNamespace):
    pass


def make_desk() -> Desk:
    """TextEdit (frontmost per AX) with one rich window, Safari (frontmost per
    a stale NSWorkspace), Notes (only in the live window list), a background
    agent and a quit app that NSWorkspace still lists."""
    log: list[tuple] = []
    ax, quartz, appkit = FakeAX(log), FakeQuartz(log), FakeAppKit()

    bold_label = El("AXStaticText", "bold-label", Value="Bold", pos=(112, 62), size=(30, 16))
    bold = El(
        "AXButton",
        "bold",
        Title="Bold",
        actions=("AXPress", "AXShowMenu"),
        children=(bold_label,),
        pos=(110, 60),
        size=(40, 20),
    )
    save = El(
        "AXButton",
        "save",
        Title="Save",
        Enabled=False,
        actions=("AXPress",),
        pos=(160, 60),
        size=(40, 20),
    )
    toolbar = El("AXToolbar", "toolbar", children=(bold, save), pos=(100, 50), size=(800, 40))
    body = El("AXTextArea", "body", Value="hello world", pos=(100, 100), size=(800, 300))
    password = El(
        "AXTextField",
        "password",
        Subrole="AXSecureTextField",
        Title="Password",
        Value="hunter2",
        children=(El("AXStaticText", "secret-child", Value="hunter2"),),
        pos=(100, 420),
        size=(200, 24),
    )
    wrap = El("AXCheckBox", "wrap", Title="Wrap", Value=1, pos=(320, 420), size=(80, 20))
    group = El("AXGroup", "group", children=(wrap,), pos=(300, 410), size=(200, 40))
    visible_row = El("AXButton", "visible-row", Description="Row A", pos=(120, 480), size=(100, 20))
    hidden_row = El("AXButton", "hidden-row", Description="Row Z", pos=(120, 900), size=(100, 20))
    scrollbar = El("AXScrollBar", "scrollbar", Value=0.0, pos=(880, 470), size=(15, 80))
    scroll = El(
        "AXScrollArea",
        "scroll",
        children=(visible_row, hidden_row, scrollbar),
        pos=(100, 470),
        size=(800, 80),
    )
    inner = El("AXButton", "inner", Title="Inner", pos=(150, 500), size=(10, 10))
    ghost = El("AXButton", "ghost", Title="Ghost", children=(inner,), pos=(0, 0), size=(0, 0))
    status = El("AXStaticText", "status", Value="Status: ready", pos=(100, 560), size=(200, 20))
    search = El(
        "AXTextField",
        "search",
        Subrole="AXSearchField",
        PlaceholderValue="Search",
        Value="",
        pos=(600, 420),
        size=(150, 22),
    )
    window = El(
        "AXWindow",
        "window",
        Title="Untitled.txt",
        children=(toolbar, body, password, group, scroll, ghost, status, search),
        pos=(100, 50),
        size=(800, 600),
    )
    second = El(
        "AXWindow", "second", Title="Notes.txt", Minimized=True, pos=(0, 0), size=(400, 300)
    )
    textedit_ax = El("AXApplication", "textedit-app", Title="TextEdit", FocusedWindow=window)
    textedit_ax.attrs["AXWindows"] = (window, second)
    textedit_ax.pid = 101

    safari_window = El("AXWindow", "safari-window", Title="Apple", pos=(0, 0), size=(1200, 800))
    safari_ax = El("AXApplication", "safari-app", Title="Safari", FocusedWindow=safari_window)
    safari_ax.attrs["AXWindows"] = (safari_window,)
    safari_ax.pid = 202

    ax.apps.update({101: textedit_ax, 202: safari_ax, 505: El("AXApplication", "notes-app")})
    ax.system.attrs["AXFocusedApplication"] = textedit_ax
    ax.system.attrs["AXFocusedUIElement"] = body

    textedit = RunApp("TextEdit", 101, "com.apple.TextEdit")
    safari = RunApp("Safari", 202, "com.apple.Safari")
    agent = RunApp("Helper Agent", 303, "com.example.agent", policy=2)
    quit_app = RunApp("Quit App", 404, "com.example.quit")
    notes = RunApp("Notes", 505, "com.apple.Notes")
    appkit.workspace.apps = [textedit, safari, agent, quit_app]
    appkit.workspace.front = safari  # stale: AX says TextEdit
    appkit.by_pid = {101: textedit, 202: safari, 303: agent, 404: quit_app, 505: notes}
    quartz.window_infos = [
        {"kCGWindowOwnerPID": 101, "kCGWindowLayer": 0, "kCGWindowOwnerName": "TextEdit"},
        {"kCGWindowOwnerPID": 505, "kCGWindowLayer": 0, "kCGWindowOwnerName": "Notes"},
        {"kCGWindowOwnerPID": 606, "kCGWindowLayer": 25, "kCGWindowOwnerName": "Menu Extra"},
    ]

    clock = Clock()
    sleeps: list[float] = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock.now += seconds

    settings_opened: list[str] = []
    backend = bm.MacBackend(
        api=bm.PyObjC(ax=ax, quartz=quartz, appkit=appkit),
        open_settings=settings_opened.append,
        sleep=sleep,
        clock=clock,
        pid_alive=lambda pid: pid != 404,
        platform="darwin",
    )
    return Desk(
        ax=ax,
        quartz=quartz,
        appkit=appkit,
        backend=backend,
        log=log,
        clock=clock,
        sleeps=sleeps,
        settings_opened=settings_opened,
        el=SimpleNamespace(
            bold=bold,
            save=save,
            body=body,
            password=password,
            wrap=wrap,
            visible_row=visible_row,
            hidden_row=hidden_row,
            scrollbar=scrollbar,
            status=status,
            search=search,
            window=window,
            second=second,
            textedit_ax=textedit_ax,
        ),
        apps=SimpleNamespace(textedit=textedit, safari=safari, notes=notes),
    )


@pytest.fixture
def desk() -> Desk:
    return make_desk()


def walk(roots, depth=0):
    """(node, depth) pairs of an outline tree, pre-order."""
    out = []
    for node in roots:
        out.append((node, depth))
        out.extend(walk(node.children, depth + 1))
    return out


def flat(roots):
    return [node for node, _ in walk(roots)]


def shape(roots):
    return [(n.role, n.name, n.value, n.secure, d, n.enabled) for n, d in walk(roots)]


def events(posted):
    out = []
    for ev in posted:
        if ev.kind == "mouse":
            out.append(("mouse", ev.type, ev.point, ev.fields.get(1), ev.flags))
        elif ev.kind == "key":
            out.append(("key", ev.code, ev.down, ev.flags, ev.text))
        else:
            out.append(("scroll", ev.units, ev.count, ev.delta, ev.variant))
    return out


def node_for(desk, label):
    nodes = flat(desk.backend.outline(None, 100))
    return next(n for n in nodes if n.handle is getattr(desk.el, label))


# --- Contract with pyobjc ------------------------------------------------------


def test_fakes_cover_every_symbol_the_backend_needs(desk):
    for part, symbols in bm.REQUIRED_SYMBOLS.items():
        module = getattr(desk.backend.api, part)
        missing = [s for s in symbols if not hasattr(module, s)]
        assert missing == [], f"fake {part} lacks {missing}"


def test_real_pyobjc_has_the_symbols_and_constant_values_used():
    pytest.importorskip("ApplicationServices")
    pytest.importorskip("Quartz")
    pytest.importorskip("AppKit")
    real = _REAL_LOAD()  # imports only; every desktop entry point is a tripwire
    for part, symbols in bm.REQUIRED_SYMBOLS.items():
        module = getattr(real, part)
        assert [s for s in symbols if not hasattr(module, s)] == []
    ax, q, ak = real.ax, real.quartz, real.appkit
    assert (
        ax.kAXErrorSuccess,
        ax.kAXErrorInvalidUIElement,
        ax.kAXErrorAttributeUnsupported,
        ax.kAXErrorAPIDisabled,
        ax.kAXErrorNoValue,
        ax.kAXValueCGPointType,
        ax.kAXValueCGSizeType,
    ) == (
        bm.AX_SUCCESS,
        bm.AX_ERR_INVALID_ELEMENT,
        bm.AX_ERR_ATTRIBUTE_UNSUPPORTED,
        bm.AX_ERR_API_DISABLED,
        bm.AX_ERR_NO_VALUE,
        bm.AX_VALUE_CGPOINT,
        bm.AX_VALUE_CGSIZE,
    )
    assert (
        q.kCGHIDEventTap,
        q.kCGEventLeftMouseDown,
        q.kCGEventLeftMouseUp,
        q.kCGEventMouseMoved,
        q.kCGMouseButtonLeft,
        q.kCGMouseEventClickState,
        q.kCGScrollEventUnitLine,
        q.kCGWindowListOptionAll,
        q.kCGWindowListExcludeDesktopElements,
        q.kCGNullWindowID,
        q.kCGWindowOwnerPID,
        q.kCGWindowLayer,
    ) == (
        bm.CG_HID_EVENT_TAP,
        bm.CG_LEFT_MOUSE_DOWN,
        bm.CG_LEFT_MOUSE_UP,
        bm.CG_MOUSE_MOVED,
        bm.CG_MOUSE_BUTTON_LEFT,
        bm.CG_MOUSE_CLICK_STATE,
        bm.CG_SCROLL_UNIT_LINE,
        bm.CG_WINDOW_LIST_ALL,
        bm.CG_WINDOW_LIST_EXCLUDE_DESKTOP,
        bm.CG_NULL_WINDOW_ID,
        bm.CG_WINDOW_OWNER_PID,
        bm.CG_WINDOW_LAYER,
    )
    assert bm.MODIFIERS["ctrl"][0] == q.kCGEventFlagMaskControl
    assert bm.MODIFIERS["alt"][0] == q.kCGEventFlagMaskAlternate
    assert bm.MODIFIERS["shift"][0] == q.kCGEventFlagMaskShift
    assert bm.MODIFIERS["cmd"][0] == q.kCGEventFlagMaskCommand
    assert ak.NSApplicationActivationPolicyRegular == bm.NS_ACTIVATION_POLICY_REGULAR
    assert ak.NSApplicationActivateIgnoringOtherApps == bm.NS_ACTIVATE_IGNORING_OTHER_APPS


# --- Availability and permission -----------------------------------------------


def test_available_with_pyobjc(desk):
    assert desk.backend.available() == (True, "pyobjc loaded")
    assert desk.backend.name == "mac"


def test_unavailable_and_unknown_without_pyobjc(monkeypatch):
    def missing():
        raise ImportError("No module named 'AppKit'")

    monkeypatch.setattr(bm, "load_pyobjc", missing)
    backend = bm.MacBackend(platform="darwin")
    ok, reason = backend.available()
    assert ok is False and "pyobjc is not installed" in reason
    assert backend.permission() == "unknown"


def test_unavailable_when_pyobjc_lacks_a_symbol(desk):
    del desk.appkit.NSWorkspaceOpenConfiguration
    ok, reason = desk.backend.available()
    assert ok is False and "appkit.NSWorkspaceOpenConfiguration" in reason


def test_permission_reads_trust_without_prompting(desk):
    assert desk.backend.permission() == "granted"
    desk.ax.trusted = False
    assert desk.backend.permission() == "denied"
    assert desk.ax.prompts == []


def test_permission_unknown_when_the_check_fails(desk):
    def boom():
        raise RuntimeError("tcc")

    desk.ax.AXIsProcessTrusted = boom
    assert desk.backend.permission() == "unknown"


def test_request_permission_prompts_and_opens_the_accessibility_pane(desk):
    desk.backend.request_permission()
    assert desk.ax.prompts == [{"AXTrustedCheckOptionPrompt": True}]
    assert desk.settings_opened == [bm.ACCESSIBILITY_SETTINGS_URL]
    assert bm.ACCESSIBILITY_SETTINGS_URL.endswith("?Privacy_Accessibility")


def test_request_permission_defaults_to_the_shared_settings_opener(desk, monkeypatch):
    from services.capabilities import macos

    opened: list[str] = []
    monkeypatch.setattr(macos, "open_settings", opened.append)
    backend = bm.MacBackend(api=desk.backend.api)
    backend.request_permission()
    assert opened == [bm.ACCESSIBILITY_SETTINGS_URL]


# --- Apps and windows ------------------------------------------------------------


def test_list_apps_is_live_regular_apps_with_ax_frontmost(desk):
    assert desk.backend.list_apps() == [
        AppInfo(name="Notes", pid=505, active=False),  # only the window list knew it
        AppInfo(name="Safari", pid=202, active=False),  # NSWorkspace's stale "front"
        AppInfo(name="TextEdit", pid=101, active=True),
    ]


def test_frontmost_uses_the_accessibility_server(desk):
    assert desk.backend.frontmost() == ("TextEdit", "Untitled.txt")
    assert ("textedit-app", bm.AX_MESSAGING_TIMEOUT_S) in desk.ax.timeouts


def test_frontmost_falls_back_to_nsworkspace_without_accessibility(desk):
    desk.ax.api_disabled = True
    assert desk.backend.frontmost() == ("Safari", "")


def test_list_windows_indexes_per_app(desk):
    assert desk.backend.list_windows() == [
        WindowInfo(app="Safari", title="Apple", index=0),
        WindowInfo(app="TextEdit", title="Untitled.txt", index=0),
        WindowInfo(app="TextEdit", title="Notes.txt", index=1),
    ]


# --- Outline ------------------------------------------------------------------------


def test_outline_walks_the_focused_window(desk):
    roots = desk.backend.outline(None, 100)
    assert len(roots) == 1  # the window is the one root; the rest are its children
    nodes = flat(roots)
    assert shape(roots) == [
        ("window", "Untitled.txt", None, False, 0, True),
        ("toolbar", "", None, False, 1, True),
        ("button", "Bold", None, False, 2, True),  # its own label text is folded in
        ("button", "Save", None, False, 2, False),
        ("text area", "", "hello world", False, 1, True),
        ("secure text field", "Password", None, True, 1, True),
        ("checkbox", "Wrap", "on", False, 1, True),  # unnamed group collapsed
        ("button", "Row A", None, False, 1, True),  # "Row Z" is scrolled away
        ("button", "Inner", None, False, 1, True),  # zero-size parent not shown
        ("text", "Status: ready", None, False, 1, True),
        ("search field", "Search", None, False, 1, True),
    ]
    assert nodes[0].handle is desk.el.window
    assert nodes[0].bounds == (100, 50, 800, 600)  # the toolkit checks click points on it
    assert nodes[2].handle is desk.el.bold
    assert nodes[2].bounds == (110, 60, 40, 20)
    assert all(isinstance(n, Node) for n in nodes)
    assert not any(n.offscreen or n.hidden for n in nodes)


def test_outline_never_reads_a_secure_value_or_its_children(desk):
    nodes = flat(desk.backend.outline(None, 100))
    password = next(n for n in nodes if n.handle is desk.el.password)
    assert password.secure is True and password.value is None
    assert ("password", "AXValue") not in desk.ax.reads
    assert ("password", "AXChildren") not in desk.ax.reads
    assert not any(label == "secret-child" for label, _ in desk.ax.reads)
    assert all("hunter2" not in str((n.name, n.value)) for n in nodes)


def test_outline_treats_a_field_with_an_unreadable_subrole_as_secure(desk):
    desk.el.search.errors["AXSubrole"] = -25204  # kAXErrorCannotComplete
    nodes = flat(desk.backend.outline(None, 100))
    search = next(n for n in nodes if n.handle is desk.el.search)
    assert search.secure is True and search.value is None
    assert ("search", "AXValue") not in desk.ax.reads


def test_outline_skips_off_screen_subtrees_cheaply(desk):
    desk.backend.outline(None, 100)
    hidden_reads = {attr for label, attr in desk.ax.reads if label == "hidden-row"}
    assert hidden_reads == {"AXRole", "AXPosition", "AXSize"}
    assert {attr for label, attr in desk.ax.reads if label == "scrollbar"} == {"AXRole"}


def test_outline_respects_the_node_budget(desk):
    assert [n.name for n in flat(desk.backend.outline(None, 3))] == ["Untitled.txt", "", "Bold"]
    desk.ax.reads.clear()
    assert desk.backend.outline(None, 0) == []
    assert desk.ax.reads == []


def test_outline_caps_depth(desk):
    leaf = El("AXButton", "leaf", Title="leaf", pos=(120, 70), size=(5, 5))
    node = leaf
    for i in range(60):
        node = El("AXGroup", f"g{i}", Title=f"g{i}", children=(node,), pos=(110, 60), size=(50, 50))
    desk.el.window.attrs["AXChildren"] = (node,)
    pairs = walk(desk.backend.outline(None, 500))
    assert max(d for _, d in pairs) == bm.MAX_DEPTH
    assert "leaf" not in [n.name for n, _ in pairs]


def test_outline_stops_at_the_deadline(desk):
    def slow(element, attribute):
        if attribute == "AXRole":
            desk.clock.now += 1.0

    desk.ax.on_read = slow
    nodes = flat(desk.backend.outline(None, 100))
    assert 0 < len(nodes) < 11


def test_outline_of_a_named_app(desk):
    assert desk.backend.outline("safari", 10)[0].name == "Apple"
    assert desk.backend.outline("com.apple.TextEdit", 1)[0].name == "Untitled.txt"
    with pytest.raises(AppNotFoundError):
        desk.backend.outline("Nope", 10)


def test_outline_without_accessibility_raises_permission_error(desk):
    desk.ax.api_disabled = True
    with pytest.raises(PermissionError):
        desk.backend.outline("TextEdit", 10)


def test_outline_builds_nodes_without_optional_fields(desk, monkeypatch):
    monkeypatch.setattr(bm, "_NODE_PARAMS", frozenset(bm._NODE_PARAMS) - {"enabled"})
    nodes = flat(desk.backend.outline(None, 100))
    assert all(n.enabled is True for n in nodes)  # Node's default, not an error


# --- Click ----------------------------------------------------------------------------


def test_click_presses_through_accessibility_when_supported(desk):
    desk.backend.click(node_for(desk, "bold"))
    assert desk.ax.performed == [("bold", "AXPress")]
    assert desk.quartz.posted == []


def test_click_falls_back_to_a_synthetic_click_at_the_centre(desk):
    desk.backend.click(node_for(desk, "visible_row"))
    assert desk.ax.performed == []
    assert events(desk.quartz.posted) == [
        ("mouse", bm.CG_MOUSE_MOVED, (170.0, 490.0), None, 0),
        ("mouse", bm.CG_LEFT_MOUSE_DOWN, (170.0, 490.0), 1, 0),
        ("mouse", bm.CG_LEFT_MOUSE_UP, (170.0, 490.0), 1, 0),
    ]


def test_click_uses_the_live_position_when_the_element_moved(desk):
    row = node_for(desk, "visible_row")
    desk.el.visible_row.move(300, 500)
    desk.backend.click(row)
    assert desk.quartz.posted[-1].point == (350.0, 510.0)


def test_click_falls_back_when_axpress_fails(desk):
    desk.el.bold.action_results["AXPress"] = -25204
    desk.backend.click(node_for(desk, "bold"))
    assert desk.ax.performed == [("bold", "AXPress")]
    assert [e.point for e in desk.quartz.posted] == [(130.0, 70.0)] * 3


def test_double_click_is_synthetic_with_click_state_two(desk):
    desk.backend.click(node_for(desk, "bold"), double=True)
    assert desk.ax.performed == []
    assert [(e.type, e.fields.get(1)) for e in desk.quartz.posted] == [
        (bm.CG_MOUSE_MOVED, None),
        (bm.CG_LEFT_MOUSE_DOWN, 1),
        (bm.CG_LEFT_MOUSE_UP, 1),
        (bm.CG_LEFT_MOUSE_DOWN, 2),
        (bm.CG_LEFT_MOUSE_UP, 2),
    ]


def test_click_at_a_point(desk):
    desk.backend.click((10, 20))
    assert {e.point for e in desk.quartz.posted} == {(10.0, 20.0)}
    assert len(desk.quartz.posted) == 3


def test_click_on_a_vanished_element_refuses(desk):
    bold = node_for(desk, "bold")
    desk.el.bold.invalid = True
    with pytest.raises(ElementGoneError):
        desk.backend.click(bold)
    assert desk.ax.performed == [] and desk.quartz.posted == []


def test_click_without_accessibility_refuses_before_posting(desk):
    row = node_for(desk, "visible_row")
    desk.ax.trusted = False
    with pytest.raises(PermissionError):
        desk.backend.click(row)
    with pytest.raises(PermissionError):
        desk.backend.click((1, 1))
    assert desk.quartz.posted == []


# --- Typing ---------------------------------------------------------------------------


def test_utf16_chunks_never_split_a_surrogate_pair():
    assert list(bm._utf16_chunks("a" * 19 + "\U0001f600")) == ["a" * 19, "\U0001f600"]
    assert list(bm._utf16_chunks("b" * 45)) == ["b" * 20, "b" * 20, "b" * 5]
    assert list(bm._utf16_chunks("")) == []


def test_type_text_posts_unicode_chunks_and_return_tab_keys(desk):
    text = "Hello, world! Hello, world! \U0001f600\U0001f600\U0001f600\nnext\tline"
    desk.backend.type_text(text, None)
    posted = events(desk.quartz.posted)
    assert all(e[3] == 0 for e in posted)  # no modifier flags leak in
    downs = [e for e in posted if e[2] is True]
    ups = [e for e in posted if e[2] is False]
    assert [(d[1], d[4]) for d in downs] == [(d[1], d[4]) for d in ups]
    assert [(d[1], d[4]) for d in downs] == [
        (0, "Hello, world! Hello,"),
        (0, " world! \U0001f600\U0001f600\U0001f600"),
        (0x24, None),  # Return
        (0, "next"),
        (0x30, None),  # Tab
        (0, "line"),
    ]


def test_type_text_focuses_the_target_first(desk):
    body = node_for(desk, "body")
    desk.log.clear()
    desk.backend.type_text("hi", body)
    assert desk.log[0] == ("set", "body", "AXFocused")
    assert desk.log[1:] == [("post", "key"), ("post", "key")]
    assert desk.quartz.posted[0].text == "hi"


def test_type_text_clicks_to_focus_when_ax_focus_is_refused(desk):
    desk.el.status.set_results["AXFocused"] = -25205
    target = node_for(desk, "status")
    desk.backend.type_text("x", target)
    kinds = [e.kind for e in desk.quartz.posted]
    assert kinds == ["mouse", "mouse", "mouse", "key", "key"]
    assert desk.quartz.posted[1].point == (200.0, 570.0)


def test_type_text_refuses_a_secure_target(desk):
    password = node_for(desk, "password")
    with pytest.raises(PermissionError):
        desk.backend.type_text("hunter2", password)
    # A node that claims not to be secure is re-checked live.
    disguised = Node(
        role="text field",
        name="Password",
        value=None,
        secure=False,
        bounds=(100, 420, 200, 24),
        handle=desk.el.password,
    )
    with pytest.raises(PermissionError):
        desk.backend.type_text("hunter2", disguised)
    assert desk.quartz.posted == [] and desk.ax.set_calls == []


def test_type_text_refuses_when_focus_is_on_a_secure_field(desk):
    desk.ax.system.attrs["AXFocusedUIElement"] = desk.el.password
    with pytest.raises(PermissionError):
        desk.backend.type_text("hunter2", None)
    assert desk.quartz.posted == []


def test_type_text_stops_when_focus_moves_to_a_secure_field(desk):
    def after(posted):
        if len(posted) == 2:  # first chunk done: a password prompt steals focus
            desk.ax.system.attrs["AXFocusedUIElement"] = desk.el.password

    desk.quartz.on_post = after
    with pytest.raises(PermissionError):
        desk.backend.type_text("x" * 60, None)
    assert [e.text for e in desk.quartz.posted] == ["x" * 20, "x" * 20]


def test_type_text_validates_input(desk):
    with pytest.raises(ValueError):
        desk.backend.type_text("bell\x07", None)
    with pytest.raises(ValueError):
        desk.backend.type_text("y" * (bm.MAX_TEXT_CHARS + 1), None)
    desk.backend.type_text("", None)
    assert desk.quartz.posted == []


def test_type_text_without_accessibility_refuses(desk):
    desk.ax.trusted = False
    with pytest.raises(PermissionError):
        desk.backend.type_text("hi", None)
    assert desk.quartz.posted == []


# --- Keys -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "code"),
    [
        ("a", 0x00),
        ("S", 0x01),
        ("z", 0x06),
        ("0", 0x1D),
        ("9", 0x19),
        ("-", 0x1B),
        ("/", 0x2C),
        ("return", 0x24),
        ("Enter", 0x24),
        ("tab", 0x30),
        ("space", 0x31),
        ("backspace", 0x33),
        ("delete", 0x75),  # the shared grammar: delete = forward delete
        ("plus", 0x18),
        ("esc", 0x35),
        ("forward_delete", 0x75),
        ("Page Down", 0x79),
        ("left", 0x7B),
        ("up", 0x7E),
        ("f1", 0x7A),
        ("F5", 0x60),
        ("f12", 0x6F),
    ],
)
def test_keycode_table(key, code):
    assert bm.keycode_for(key) == code


@pytest.mark.parametrize("key", ["fn", "globe", "capslock", "ö", "f21", "", "insert"])
def test_keycode_rejects_unsupported_keys(key):
    with pytest.raises(ValueError):
        bm.keycode_for(key)


def test_key_combo_presses_and_releases_modifiers_with_flags(desk):
    desk.backend.key(KeyCombo(modifiers=frozenset({"cmd"}), key="s"))
    assert events(desk.quartz.posted) == [
        ("key", 0x37, True, 0x100000, None),
        ("key", 0x01, True, 0x100000, None),
        ("key", 0x01, False, 0x100000, None),
        ("key", 0x37, False, 0, None),
    ]


def test_key_modifiers_are_normalized_and_ordered(desk):
    desk.backend.key(KeyCombo(modifiers=frozenset({"Shift", "control", "shift"}), key="tab"))
    assert events(desk.quartz.posted) == [
        ("key", 0x3B, True, 0x40000, None),
        ("key", 0x38, True, 0x60000, None),
        ("key", 0x30, True, 0x60000, None),
        ("key", 0x30, False, 0x60000, None),
        ("key", 0x38, False, 0x40000, None),
        ("key", 0x3B, False, 0, None),
    ]


def test_key_with_option_alias(desk):
    desk.backend.key(KeyCombo(modifiers=frozenset({"option"}), key="left"))
    assert events(desk.quartz.posted)[1] == ("key", 0x7B, True, 0x80000, None)


@pytest.mark.parametrize("modifiers", [("fn",), ("globe",), ("hyper",), ("win",)])
def test_key_rejects_forbidden_or_unknown_modifiers(desk, modifiers):
    with pytest.raises(ValueError):
        desk.backend.key(KeyCombo(modifiers=frozenset(modifiers), key="q"))
    assert desk.quartz.posted == []


def test_key_releases_modifiers_when_the_key_fails(desk):
    desk.quartz.fail_post = lambda ev: ev.kind == "key" and ev.code == 0x01 and ev.down
    with pytest.raises(RuntimeError):
        desk.backend.key(KeyCombo(modifiers=frozenset({"cmd", "shift"}), key="s"))
    assert events(desk.quartz.posted) == [
        ("key", 0x38, True, 0x20000, None),
        ("key", 0x37, True, 0x120000, None),
        ("key", 0x37, False, 0x20000, None),
        ("key", 0x38, False, 0, None),
    ]


def test_key_that_would_insert_text_into_a_secure_field_refuses(desk):
    desk.ax.system.attrs["AXFocusedUIElement"] = desk.el.password
    for combo in (
        KeyCombo(frozenset(), "a"),
        KeyCombo(frozenset({"shift"}), "1"),
        KeyCombo(frozenset({"cmd"}), "v"),
    ):
        with pytest.raises(PermissionError):
            desk.backend.key(combo)
    assert desk.quartz.posted == []
    desk.backend.key(KeyCombo(frozenset(), "tab"))  # moving away is fine
    desk.backend.key(KeyCombo(frozenset({"cmd"}), "a"))
    assert len(desk.quartz.posted) == 2 + 4


def test_key_without_accessibility_refuses(desk):
    desk.ax.trusted = False
    with pytest.raises(PermissionError):
        desk.backend.key(KeyCombo(frozenset({"cmd"}), "s"))
    assert desk.quartz.posted == []


# --- Scroll ---------------------------------------------------------------------------


def test_scroll_posts_line_wheel_events(desk):
    desk.backend.scroll("up", 3)
    desk.backend.scroll("down", 5)
    desk.backend.scroll("down", 1000)
    assert events(desk.quartz.posted) == [
        ("scroll", bm.CG_SCROLL_UNIT_LINE, 1, 3, 2),
        ("scroll", bm.CG_SCROLL_UNIT_LINE, 1, -5, 2),
        ("scroll", bm.CG_SCROLL_UNIT_LINE, 1, -bm.MAX_SCROLL_LINES, 2),
    ]
    assert desk.quartz.posted[0].rest == (0, 0)


def test_scroll_uses_the_variadic_call_on_older_pyobjc(desk):
    desk.quartz.CGEventCreateScrollWheelEvent2 = None
    desk.backend.scroll("up", 2)
    assert events(desk.quartz.posted) == [("scroll", bm.CG_SCROLL_UNIT_LINE, 1, 2, 1)]


@pytest.mark.parametrize(("direction", "amount"), [("left", 1), ("sideways", 1), ("up", 0)])
def test_scroll_validates(desk, direction, amount):
    with pytest.raises(ValueError):
        desk.backend.scroll(direction, amount)
    assert desk.quartz.posted == []


def test_scroll_without_accessibility_refuses(desk):
    desk.ax.trusted = False
    with pytest.raises(PermissionError):
        desk.backend.scroll("down", 1)
    assert desk.quartz.posted == []


# --- Open app / focus window --------------------------------------------------------


def test_open_app_activates_a_running_app(desk):
    desk.backend.open_app("safari")
    desk.backend.open_app("TextEdit.app")
    assert desk.apps.safari.activations == [bm.NS_ACTIVATE_IGNORING_OTHER_APPS]
    assert desk.apps.textedit.activations == [bm.NS_ACTIVATE_IGNORING_OTHER_APPS]
    assert desk.appkit.workspace.opened == [] and desk.appkit.workspace.launched == []


def test_open_app_launches_by_url_and_waits_for_it(desk):
    path = "/System/Applications/Calculator.app"
    desk.appkit.workspace.paths["Calculator"] = path
    calculator = RunApp("Calculator", 707, "com.apple.calculator")

    def launched():  # appears in the live window list, not in NSWorkspace's
        desk.appkit.by_pid[707] = calculator
        desk.quartz.window_infos.append({"kCGWindowOwnerPID": 707, "kCGWindowLayer": 0})

    desk.appkit.workspace.on_open = launched
    desk.backend.open_app("Calculator")
    assert desk.appkit.workspace.opened == [(("file-url", path), True)]
    assert bm.POLL_INTERVAL_S not in desk.sleeps  # seen at once, no waiting


def test_open_app_falls_back_to_launch_and_gives_up_waiting(desk):
    desk.appkit.workspace.launchable.add("Legacy")
    desk.backend.open_app("Legacy")
    assert desk.appkit.workspace.launched == ["Legacy"]
    assert desk.sleeps and set(desk.sleeps) == {bm.POLL_INTERVAL_S}
    assert sum(desk.sleeps) >= bm.OPEN_APP_WAIT_S - 1e-6


def test_open_app_launch_error_from_appkit_is_logged_not_raised(desk):
    path = "/Applications/Broken.app"
    desk.appkit.workspace.paths["Broken"] = path
    desk.appkit.workspace.open_error = "The application could not be launched."
    desk.backend.open_app("Broken")  # waits for it, then gives up quietly
    assert desk.appkit.workspace.opened == [(("file-url", path), True)]


def test_open_app_unknown_raises(desk):
    with pytest.raises(AppNotFoundError):
        desk.backend.open_app("Nope")


@pytest.mark.parametrize("name", ["", "   ", "/Applications/Evil.app", "../x", ".hidden", "a\x00b"])
def test_open_app_takes_names_not_paths(desk, name):
    with pytest.raises(ValueError):
        desk.backend.open_app(name)
    assert desk.appkit.workspace.opened == [] and desk.appkit.workspace.launched == []


def test_focus_window_raises_unminimizes_and_activates(desk):
    desk.backend.focus_window("TextEdit", 1)
    assert desk.ax.set_calls == [("second", "AXMinimized", False), ("second", "AXMain", True)]
    assert desk.ax.performed == [("second", "AXRaise")]
    assert desk.apps.textedit.activations == [bm.NS_ACTIVATE_IGNORING_OTHER_APPS]


def test_focus_window_falls_back_to_ax_frontmost(desk):
    desk.apps.safari.activate_result = False
    desk.backend.focus_window("Safari", 0)
    assert ("safari-app", "AXFrontmost", True) in desk.ax.set_calls


def test_focus_window_bad_index_or_app(desk):
    with pytest.raises(AppNotFoundError):
        desk.backend.focus_window("TextEdit", 5)
    with pytest.raises(AppNotFoundError):
        desk.backend.focus_window("Nope", 0)
    assert desk.ax.performed == []


def test_focus_window_without_accessibility_refuses(desk):
    desk.ax.trusted = False
    with pytest.raises(PermissionError):
        desk.backend.focus_window("TextEdit", 0)
    assert desk.ax.performed == []


# --- Helpers --------------------------------------------------------------------------


def test_role_labels():
    assert bm._role_label("AXTextField", "") == "text field"
    assert bm._role_label("AXTextField", "AXSecureTextField") == "secure text field"
    assert bm._role_label("AXMenuBarItem", "") == "menu bar item"
    assert bm._role_label("AXDisclosureTriangle", "") == "disclosure triangle"
    assert bm._role_label("AXButton", "AXCloseButton") == "close button"
    assert bm._role_label("AXPopUpButton", "") == "pop up button"
    assert bm._role_label("AXRadioButton", "") == "radio button"
    assert bm._role_label("AXMenuItem", "") == "menu item"


def test_values_are_formatted_for_lines():
    assert bm._format_value("AXCheckBox", "", 0) == "off"
    assert bm._format_value("AXCheckBox", "", 2) == "mixed"
    assert bm._format_value("AXCheckBox", "AXSwitch", True) == "on"
    assert bm._format_value("AXSlider", "", 0.5) == "0.5"
    assert bm._format_value("AXSlider", "", 3) == "3"
    assert bm._format_value("AXTextField", "", "") is None
    assert bm._format_value("AXTextArea", "", "z" * 5000).endswith("…")
    assert bm._format_value("AXGroup", "", object()) is None


# --- Conformance with the core protocol (backend.py) ------------------------------


class BundledApp(RunApp):
    """A fake NSRunningApplication that also knows its bundle's path."""

    def __init__(self, name, pid, bundle, path):
        super().__init__(name, pid, bundle)
        self.path = path

    def bundleURL(self):
        return SimpleNamespace(path=lambda: self.path)


def test_the_backend_implements_the_protocol(desk):
    assert isinstance(desk.backend, ComputerBackend)


def test_select_backend_returns_the_mac_backend_without_touching_the_os():
    for name in ("mac", "darwin", "macOS"):
        assert isinstance(select_backend(name), bm.MacBackend)
    # The autouse tripwires prove construction loaded no pyobjc and read nothing.


def test_lookup_failures_are_the_core_error_types():
    assert issubclass(bm.MacElementGoneError, ElementGoneError)
    assert issubclass(bm.MacAppNotFoundError, AppNotFoundError)
    # Still LookupErrors, for callers that only know the built-in type.
    assert issubclass(bm.MacElementGoneError, LookupError)
    assert issubclass(bm.MacAppNotFoundError, LookupError)


def test_outline_always_roots_at_the_window_even_without_a_size(desk):
    desk.el.window.attrs["AXSize"] = AXVal(2, SimpleNamespace(width=0, height=0))
    roots = desk.backend.outline(None, 100)
    assert len(roots) == 1 and roots[0].handle is desk.el.window
    assert roots[0].role == "window"


def test_outline_marks_the_focused_field(desk):
    desk.el.body.attrs["AXFocused"] = True
    assert node_for(desk, "body").focused is True
    assert node_for(desk, "bold").focused is False


def test_outline_keeps_a_scrolled_away_text_field_for_the_payment_check(desk):
    card = El(
        "AXTextField",
        "card",
        Title="Card number",
        Value="",
        children=(El("AXStaticText", "card-child", Value="x"),),
        pos=(120, 950),
        size=(200, 20),
    )
    scroll = next(c for c in desk.el.window.attrs["AXChildren"] if c.label == "scroll")
    scroll.attrs["AXChildren"] = (*scroll.attrs["AXChildren"], card)
    nodes = flat(desk.backend.outline(None, 100))
    node = next(n for n in nodes if n.handle is card)
    assert node.offscreen is True and node.name == "Card number"
    assert ("card-child", "AXRole") not in desk.ax.reads  # not descended into
    assert "Row Z" not in [n.name for n in nodes]  # other scrolled-away elements still go


def test_focused_describes_the_focused_element(desk):
    node = desk.backend.focused()
    assert node is not None and node.handle is desk.el.body
    assert (node.role, node.value, node.secure, node.focused) == (
        "text area",
        "hello world",
        False,
        True,
    )


def test_focused_never_reads_a_secure_value(desk):
    desk.ax.system.attrs["AXFocusedUIElement"] = desk.el.password
    node = desk.backend.focused()
    assert node is not None and node.secure is True and node.value is None
    assert node.role == "secure text field"
    assert ("password", "AXValue") not in desk.ax.reads


def test_focused_is_none_when_nothing_or_nothing_readable_has_focus(desk):
    del desk.ax.system.attrs["AXFocusedUIElement"]
    assert desk.backend.focused() is None
    desk.ax.system.attrs["AXFocusedUIElement"] = desk.el.body
    desk.el.body.errors["AXRole"] = -25204
    assert desk.backend.focused() is None


def test_apps_are_named_by_their_bundle_not_the_localized_name(desk):
    settings = BundledApp(
        "Systemeinstellungen",
        808,
        "com.apple.systempreferences",
        "/System/Applications/System Settings.app",
    )
    desk.appkit.workspace.apps.append(settings)
    desk.appkit.by_pid[808] = settings
    names = [a.name for a in desk.backend.list_apps()]
    assert "System Settings" in names and "Systemeinstellungen" not in names
    # The bundle name, the localized name and the bundle id all find an app.
    calculator = BundledApp(
        "Rechner", 809, "com.apple.calculator", "/System/Applications/Calculator.app"
    )
    desk.appkit.workspace.apps.append(calculator)
    desk.appkit.by_pid[809] = calculator
    for query in ("Calculator", "Rechner", "com.apple.calculator"):
        desk.backend.open_app(query)
    assert calculator.activations == [bm.NS_ACTIVATE_IGNORING_OTHER_APPS] * 3


@pytest.mark.parametrize(
    "query", ["System Settings", "Systemeinstellungen", "com.apple.systempreferences"]
)
def test_a_name_that_resolves_to_a_blocked_app_is_refused(desk, query):
    # The toolkit checks the model's spelling; only the backend sees that a
    # localized name ("Systemeinstellungen") is System Settings. Neither
    # open_app nor focus_window may bring it forward.
    settings = BundledApp(
        "Systemeinstellungen",
        808,
        "com.apple.systempreferences",
        "/System/Applications/System Settings.app",
    )
    desk.appkit.workspace.apps.append(settings)
    desk.appkit.by_pid[808] = settings
    settings_ax = El("AXApplication", "settings-app")
    settings_ax.attrs["AXWindows"] = (El("AXWindow", "settings-window", Title="Wi-Fi"),)
    desk.ax.apps[808] = settings_ax
    with pytest.raises(BlockedTargetError) as err:
        desk.backend.open_app(query)
    assert err.value.app == "System Settings"
    with pytest.raises(BlockedTargetError):
        desk.backend.focus_window(query, 0)
    assert settings.activations == []
    assert desk.ax.performed == [] and desk.ax.set_calls == []


def test_open_app_refuses_a_launch_that_resolves_to_a_blocked_bundle(desk):
    desk.appkit.workspace.paths["Terminal-DE"] = "/System/Applications/Utilities/Terminal.app"
    with pytest.raises(BlockedTargetError):
        desk.backend.open_app("Terminal-DE")
    assert desk.appkit.workspace.opened == [] and desk.appkit.workspace.launched == []


def test_type_text_lets_focus_settle_after_tab_before_typing_on(desk):
    # "alice<Tab>hunter2": the Tab moves focus to the password field. The app
    # handles the Tab asynchronously, so focus is re-read only after a pause.
    def after(posted):
        last = posted[-1]
        if last.kind == "key" and last.code == 0x30 and last.down is False:
            desk.ax.system.attrs["AXFocusedUIElement"] = desk.el.password

    desk.quartz.on_post = after
    with pytest.raises(SecureTargetError) as err:
        desk.backend.type_text("alice\thunter2", None)
    assert isinstance(err.value, PermissionError)
    assert [e.text for e in desk.quartz.posted if e.text and e.down] == ["alice"]
    assert bm.KEY_SETTLE_S in desk.sleeps


def test_type_text_fails_closed_when_focus_cannot_be_read(desk):
    del desk.ax.system.attrs["AXFocusedUIElement"]
    with pytest.raises(SecureTargetError):
        desk.backend.type_text("hi", None)
    # Focusing a target that then does not report focus is no better.
    body = node_for(desk, "body")
    desk.ax.system.errors["AXFocusedUIElement"] = -25204
    with pytest.raises(SecureTargetError):
        desk.backend.type_text("hi", body)
    desk.ax.system.errors.clear()
    desk.ax.system.attrs["AXFocusedUIElement"] = desk.el.body
    desk.el.body.errors["AXRole"] = -25204  # focus there, but what is it?
    with pytest.raises(SecureTargetError):
        desk.backend.type_text("hi", None)
    with pytest.raises(SecureTargetError):
        desk.backend.key(KeyCombo(frozenset(), "a"))
    assert desk.quartz.posted == []


def test_click_at_a_point_covered_by_another_app_is_refused(desk):
    safari_hit = El("AXButton", "safari-button")
    safari_hit.pid = 202
    desk.ax.element_at = lambda x, y: (0, safari_hit)
    with pytest.raises(CoveredTargetError):
        desk.backend.click((150, 150))
    # A synthetic click at an element's centre is checked the same way.
    with pytest.raises(CoveredTargetError):
        desk.backend.click(node_for(desk, "visible_row"))
    with pytest.raises(CoveredTargetError):
        desk.backend.click(node_for(desk, "bold"), double=True)
    assert desk.quartz.posted == []
    assert desk.ax.positions == [(150.0, 150.0), (170.0, 490.0), (130.0, 70.0)]


def test_click_fails_closed_when_the_point_cannot_be_checked(desk):
    desk.ax.element_at = lambda x, y: (-25204, None)  # kAXErrorCannotComplete
    with pytest.raises(CoveredTargetError):
        desk.backend.click((150, 150))
    nobody = El("AXButton", "no-pid")  # AXUIElementGetPid fails for it
    desk.ax.element_at = lambda x, y: (0, nobody)
    with pytest.raises(CoveredTargetError):
        desk.backend.click((150, 150))
    assert desk.quartz.posted == []


def test_axpress_needs_no_point_check(desk):
    safari_hit = El("AXButton", "safari-button")
    safari_hit.pid = 202
    desk.ax.element_at = lambda x, y: (0, safari_hit)
    desk.backend.click(node_for(desk, "bold"))  # acts on the element, not a point
    assert desk.ax.performed == [("bold", "AXPress")]
    assert desk.ax.positions == [] and desk.quartz.posted == []


def test_focus_by_click_is_checked_for_cover_too(desk):
    desk.el.status.set_results["AXFocused"] = -25205
    target = node_for(desk, "status")
    safari_hit = El("AXButton", "safari-button")
    safari_hit.pid = 202
    desk.ax.element_at = lambda x, y: (0, safari_hit)
    with pytest.raises(CoveredTargetError):
        desk.backend.type_text("x", target)
    assert desk.quartz.posted == []


def test_backend_refusals_are_core_error_types():
    assert issubclass(bm.MacSecureFieldError, SecureTargetError)
    assert issubclass(bm.MacSecureFieldError, PermissionError)
    assert issubclass(bm.MacBlockedAppError, BlockedTargetError)
    assert issubclass(bm.MacCoveredError, CoveredTargetError)


def test_frontmost_uses_the_bundle_name(desk):
    terminal = BundledApp(
        "Terminal-DE", 909, "com.apple.Terminal", "/System/Applications/Utilities/Terminal.app"
    )
    desk.appkit.by_pid[909] = terminal
    term_ax = El("AXApplication", "terminal-app")
    term_ax.pid = 909
    desk.ax.system.attrs["AXFocusedApplication"] = term_ax
    assert desk.backend.frontmost() == ("Terminal", "")


# --- The toolkit on top of this backend (all fakes) -------------------------------


@pytest.mark.asyncio
async def test_toolkit_observes_and_acts_through_the_mac_backend(desk):
    import re

    from services.tools.computer.toolkit import ComputerToolkit

    kit = ComputerToolkit(desk.backend, cancel_flag=lambda uid: False)
    result = await kit.execute("observe", {"action": "outline"}, user_id="u1")
    assert result["ok"] is True, result
    assert result["frontmost_app"] == "TextEdit"
    assert result["secure_fields_redacted"] == 1
    assert "hunter2" not in "\n".join(result["outline"])

    def ref(needle):
        line = next(line for line in result["outline"] if needle in line)
        return re.search(r"\[ref=(d\d+)\]", line).group(1)

    assert "value=[redacted]" in next(line for line in result["outline"] if "Password" in line)
    refused = await kit.execute(
        "act", {"action": "type", "ref": ref('"Password"'), "text": "x"}, user_id="u1"
    )
    assert refused["ok"] is False and refused["refused"] is True
    assert desk.quartz.posted == [] and desk.ax.set_calls == []

    done = await kit.execute("act", {"action": "click", "ref": ref('"Bold"')}, user_id="u1")
    assert done["ok"] is True, done
    assert desk.ax.performed == [("bold", "AXPress")]
