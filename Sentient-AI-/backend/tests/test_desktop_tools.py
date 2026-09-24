"""Tests for the desktop.screenshot tool: the screenshot is downscaled to a
bounded JPEG, that grabber and permission-probe failures are reported
generically to the model but in detail in the log, and that oversize or
malformed capture data is refused rather than raised.

Why it exists: Nothing here touches a real display: every failure mode of the
injected grabber, the macOS permission preflight, and the multi-monitor `mss`
indexing is exercised so a capture bug fails a test instead of leaking a raw
stack trace to the model.

desktop.screenshot. Nothing here touches the real display: every test
injects a grabber, a fake ``mss`` module, or patches the macOS preflight.
"""

from __future__ import annotations

import base64
import io
import sys
import threading
import types

import pytest
from PIL import Image

from services import capabilities
from services.capabilities import env as cap_env
from services.capabilities import screen
from services.capabilities.base import ProbeResult
from services.tools import desktop
from services.tools.desktop import DesktopToolkit

GRANTED = ProbeResult("granted")


def fake_grabber(width=3000, height=2000):
    def grab(display: int):
        return b"\x10\x20\x30" * (width * height), width, height

    return grab


def must_not_grab(display: int):
    raise AssertionError("the grabber must not run")


class RecordingLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def warning(self, event, **fields):
        self.events.append((event, fields))

    info = debug = error = exception = warning


@pytest.fixture
def log(monkeypatch):
    rec = RecordingLogger()
    monkeypatch.setattr(desktop, "logger", rec)
    return rec


# ── happy path and existing contract ────────────────────────────────────


@pytest.mark.asyncio
async def test_screenshot_downscales_to_1280_jpeg():
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is True
    assert set(result) == {
        "ok",
        "image",
        "image_format",
        "width",
        "height",
        "display",
        "captured_at",
    }
    assert result["image_format"] == "jpeg"
    assert result["image"].startswith("data:image/jpeg;base64,")
    assert max(result["width"], result["height"]) == 1280
    raw = base64.b64decode(result["image"].split(",", 1)[1])
    img = Image.open(io.BytesIO(raw))
    assert img.format == "JPEG" and img.size == (result["width"], result["height"])
    assert result["display"] == 0 and "captured_at" in result


@pytest.mark.asyncio
async def test_screenshot_refused_when_probe_denied():
    denied = ProbeResult(
        "denied", "no grant", fix_url="x-apple.systempreferences:x", fix_steps=("Open Settings",)
    )
    kit = DesktopToolkit(grabber=must_not_grab, probe=lambda: denied)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert result["fix_url"] == "x-apple.systempreferences:x"
    assert result["fix_steps"] == ["Open Settings"]
    assert "no grant" in result["error"]


@pytest.mark.asyncio
async def test_unknown_action_and_bad_args_fail_closed():
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: GRANTED)
    assert (await kit.execute("type", {}))["ok"] is False
    assert (await kit.execute("screenshot", {"display": "zero"}))["ok"] is False


# ── item 4: exception text stays in the log ─────────────────────────────


@pytest.mark.asyncio
async def test_grabber_failure_is_generic_to_the_model_and_detailed_in_the_log(log):
    secret = "no display at /Users/someone/private/path " + "x" * 500

    def boom(display):
        raise OSError(secret)

    kit = DesktopToolkit(grabber=boom, probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {"display": 1})
    assert result == {"ok": False, "error": "Screen capture failed."}
    ((event, fields),) = log.events
    assert event == "desktop_screenshot_failed"
    assert fields["error"].startswith("no display at /Users/someone")
    assert len(fields["error"]) == 200


@pytest.mark.asyncio
async def test_grabber_returning_garbage_is_reported_not_raised(log):
    kit = DesktopToolkit(grabber=lambda display: None, probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {})
    assert result == {"ok": False, "error": "Screen capture failed."}


# ── item 1: validate the buffer, bound memory ───────────────────────────


@pytest.mark.asyncio
async def test_short_buffer_is_refused_not_raised(log):
    kit = DesktopToolkit(grabber=lambda d: (b"\x00" * 10, 100, 100), probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert "image" not in result


@pytest.mark.asyncio
async def test_long_buffer_is_refused_not_raised(log):
    kit = DesktopToolkit(grabber=lambda d: (b"\x00" * (4 * 4 * 3 + 1), 4, 4), probe=lambda: GRANTED)
    assert (await kit.execute("screenshot", {}))["ok"] is False


@pytest.mark.asyncio
async def test_oversize_dimensions_are_refused_before_decoding(log, monkeypatch):
    def no_decode(*a, **k):
        raise AssertionError("Pillow must not see an oversize capture")

    monkeypatch.setattr(Image, "frombytes", no_decode)
    # The buffer is deliberately empty: the pixel bound must be checked
    # before the length, so a huge claim never reaches Pillow.
    kit = DesktopToolkit(grabber=lambda d: (b"", 10_000, 10_000), probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert "too large" in result["error"]


@pytest.mark.asyncio
async def test_just_over_the_pixel_bound_is_refused(log, monkeypatch):
    monkeypatch.setattr(desktop, "MAX_PIXELS", 100)
    kit = DesktopToolkit(grabber=fake_grabber(11, 10), probe=lambda: GRANTED)
    assert (await kit.execute("screenshot", {}))["ok"] is False
    kit = DesktopToolkit(grabber=fake_grabber(10, 10), probe=lambda: GRANTED)
    assert (await kit.execute("screenshot", {}))["ok"] is True


def test_max_pixels_is_forty_megapixels():
    assert desktop.MAX_PIXELS == 40_000_000


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "shot",
    [
        (b"", 0, 10),
        (b"", 10, 0),
        (b"", -4, -4),
        (b"\x00" * 3, True, True),
        (b"\x00" * 3, 1.0, 1),
        (None, 1, 1),
        ("\x00\x00\x00", 1, 1),
    ],
)
async def test_invalid_capture_shapes_are_refused_not_raised(log, shot):
    kit = DesktopToolkit(grabber=lambda d: shot, probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert "image" not in result


@pytest.mark.asyncio
async def test_pillow_failure_is_reported_not_raised(log, monkeypatch):
    def broken(*a, **k):
        raise ValueError("decoder exploded with internal detail")

    monkeypatch.setattr(Image, "frombytes", broken)
    kit = DesktopToolkit(grabber=fake_grabber(4, 4), probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {})
    assert result == {"ok": False, "error": "Could not encode the screenshot."}
    assert log.events and log.events[0][0] == "desktop_screenshot_encode_failed"


# ── item 2: capture and encode off the event loop, in one hop ───────────


@pytest.mark.asyncio
async def test_capture_and_encode_run_in_one_worker_thread(monkeypatch):
    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}
    real_frombytes = Image.frombytes

    def grab(display):
        seen["grab"] = threading.get_ident()
        return b"\x00" * (8 * 8 * 3), 8, 8

    def frombytes(*a, **k):
        seen["encode"] = threading.get_ident()
        return real_frombytes(*a, **k)

    monkeypatch.setattr(Image, "frombytes", frombytes)
    kit = DesktopToolkit(grabber=grab, probe=lambda: GRANTED)
    assert (await kit.execute("screenshot", {}))["ok"] is True
    assert seen["grab"] != loop_thread
    assert seen["encode"] == seen["grab"]


@pytest.mark.asyncio
async def test_probe_exception_fails_closed(log):
    def exploding_probe():
        raise RuntimeError("ctypes blew up")

    kit = DesktopToolkit(grabber=must_not_grab, probe=exploding_probe)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert result["error"] == "The permission check failed."
    assert "ctypes" not in result["error"]
    assert log.events and log.events[0][0] == "desktop_probe_failed"


# The default probe: availability first, then the registry's cached probe.


def _environment(monkeypatch, *, container=False, platform="darwin"):
    monkeypatch.setattr(cap_env, "in_container", lambda: container)
    monkeypatch.setattr(cap_env, "platform_name", lambda: platform)


@pytest.fixture
def clean_probe_cache():
    capabilities.clear_probe_cache()
    yield
    capabilities.clear_probe_cache()


@pytest.mark.asyncio
async def test_default_probe_refuses_in_a_container(monkeypatch, clean_probe_cache):
    _environment(monkeypatch, container=True)
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: True)
    kit = DesktopToolkit(grabber=must_not_grab)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert "container" in result["error"].lower()


@pytest.mark.asyncio
async def test_default_probe_refuses_on_linux(monkeypatch, clean_probe_cache):
    _environment(monkeypatch, platform="linux")
    kit = DesktopToolkit(grabber=must_not_grab)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert "macos and windows only" in result["error"].lower()


@pytest.mark.asyncio
async def test_default_probe_refuses_when_macos_denies(monkeypatch, clean_probe_cache):
    _environment(monkeypatch, platform="darwin")
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: False)
    kit = DesktopToolkit(grabber=must_not_grab)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert result["fix_url"].startswith("x-apple.systempreferences:")
    assert result["fix_steps"]


@pytest.mark.asyncio
async def test_default_probe_allows_windows(monkeypatch, clean_probe_cache):
    _environment(monkeypatch, platform="win32")
    kit = DesktopToolkit(grabber=fake_grabber(4, 4))
    assert (await kit.execute("screenshot", {}))["ok"] is True


@pytest.mark.asyncio
async def test_default_probe_uses_the_ten_second_cache(monkeypatch, clean_probe_cache):
    _environment(monkeypatch, platform="darwin")
    calls = {"n": 0}

    def preflight():
        calls["n"] += 1
        return True

    monkeypatch.setattr(screen.macos, "screen_capture_preflight", preflight)
    kit = DesktopToolkit(grabber=fake_grabber(4, 4))
    assert (await kit.execute("screenshot", {}))["ok"] is True
    assert (await kit.execute("screenshot", {}))["ok"] is True
    assert calls["n"] == 1


def test_cached_probe_helper_answers_not_required_without_a_probe(clean_probe_cache):
    ctx = desktop._screen_context()
    assert capabilities.cached_probe("web_browsing", ctx).state == "not_required"


# ── item 3: display bounds ──────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("display", [True, False, -1, -100, 1.0, None])
async def test_bad_display_values_are_refused(display):
    kit = DesktopToolkit(grabber=must_not_grab, probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {"display": display})
    assert result["ok"] is False


@pytest.mark.asyncio
async def test_negative_display_error_is_clear():
    kit = DesktopToolkit(grabber=must_not_grab, probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {"display": -1})
    assert "0 or greater" in result["error"]


class _Shot:
    def __init__(self, width: int, height: int) -> None:
        self.width, self.height = width, height
        self.rgb = b"\x40\x50\x60" * (width * height)


def _fake_mss(monkeypatch, monitors):
    grabbed: list[dict] = []

    class FakeMSS:
        def __init__(self) -> None:
            self.monitors = monitors

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def grab(self, monitor):
            grabbed.append(monitor)
            return _Shot(monitor["width"], monitor["height"])

    module = types.ModuleType("mss")
    module.mss = FakeMSS  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mss", module)
    return grabbed


ALL = {"left": 0, "top": 0, "width": 12, "height": 4, "name": "all"}
MAIN = {"left": 0, "top": 0, "width": 8, "height": 4, "name": "main"}
SIDE = {"left": 8, "top": 0, "width": 4, "height": 2, "name": "side"}


def test_mss_grab_indexes_physical_monitors(monkeypatch):
    grabbed = _fake_mss(monkeypatch, [ALL, MAIN, SIDE])
    assert desktop._mss_grab(0)[1:] == (8, 4)
    assert desktop._mss_grab(1)[1:] == (4, 2)
    assert [m["name"] for m in grabbed] == ["main", "side"]


def test_mss_grab_past_the_end_names_the_count(monkeypatch):
    grabbed = _fake_mss(monkeypatch, [ALL, MAIN, SIDE])
    with pytest.raises(desktop.DisplayNotFoundError) as info:
        desktop._mss_grab(3)
    assert str(info.value) == "display 3 not found; 2 display(s) available"
    assert grabbed == []


def test_mss_grab_falls_back_to_the_union_monitor(monkeypatch):
    grabbed = _fake_mss(monkeypatch, [ALL])
    assert desktop._mss_grab(0)[1:] == (12, 4)
    assert grabbed == [ALL]
    with pytest.raises(desktop.DisplayNotFoundError, match="1 display\\(s\\) available"):
        desktop._mss_grab(1)


def test_mss_grab_with_no_monitors_at_all(monkeypatch):
    _fake_mss(monkeypatch, [])
    with pytest.raises(desktop.DisplayNotFoundError, match="0 display\\(s\\) available"):
        desktop._mss_grab(0)


@pytest.mark.asyncio
async def test_default_grabber_reports_the_display_it_captured(monkeypatch):
    grabbed = _fake_mss(monkeypatch, [ALL, MAIN, SIDE])
    kit = DesktopToolkit(probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {"display": 1})
    assert result["ok"] is True
    assert result["display"] == 1
    assert (result["width"], result["height"]) == (4, 2)
    assert grabbed == [SIDE]


@pytest.mark.asyncio
async def test_default_grabber_missing_display_reaches_the_model(monkeypatch):
    _fake_mss(monkeypatch, [ALL, MAIN, SIDE])
    kit = DesktopToolkit(probe=lambda: GRANTED)
    result = await kit.execute("screenshot", {"display": 3})
    assert result == {"ok": False, "error": "display 3 not found; 2 display(s) available"}


# ── item 5: the module docstring does not overclaim ─────────────────────


def test_module_docstring_does_not_overclaim():
    doc = desktop.__doc__ or ""
    assert "web.screenshot" not in doc
    assert "telegram" not in doc.lower()
