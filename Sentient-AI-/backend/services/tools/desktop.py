"""Implements the desktop.screenshot built-in tool: captures a display, downscales
it and returns it as a JPEG data URL.

Why it exists: The tool registry dispatches desktop.* here; an injectable
grabber and permission probe keep the capture path testable without a display,
and every failure comes back as a result instead of an exception.

desktop.* built-in tools: what is on this computer's display.

Capability "screen": off by default, and only available on macOS and
Windows outside a container. The grabber and the permission probe are
injectable so tests never touch a display.

``desktop.screenshot`` returns ``{"ok": True, "image": <JPEG data URL>,
"image_format": "jpeg", "width", "height", "display", "captured_at"}``,
downscaled so the long edge is at most ``MAX_EDGE_PX``. ``width`` and
``height`` are those of the encoded image, ``display`` is the index that
was captured. Every failure is ``{"ok": False, "error": ...}``: no
exception escapes ``execute()``, and exception text goes to the log, never
to the model.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import io
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog

from services import capabilities
from services.capabilities import env as cap_env
from services.capabilities import screen
from services.capabilities.base import ProbeResult, ReportContext

logger = structlog.get_logger(__name__)

Grabber = Callable[[int], tuple[bytes, int, int]]  # raw RGB bytes, width, height

MAX_EDGE_PX = 1280
JPEG_QUALITY = 70
# Largest raw capture handed to Pillow. A 6K display is about 20 MP, so
# this leaves headroom for real hardware while capping the RGB buffer at
# 120 MB and Pillow's decoded copy at about the same.
MAX_PIXELS = 40_000_000
_LOG_DETAIL_CHARS = 200


class DisplayNotFoundError(LookupError):
    """The requested display index is past the last attached display.

    The message holds only integers, so it is safe to return to the model.
    """


def _mss_grab(display: int) -> tuple[bytes, int, int]:
    # mss is a hard requirement (requirements.txt), not an optional extra.
    # The import is local only so loading this module stays cheap and tests
    # can substitute a fake through sys.modules. The mss instance is created
    # and used in the same (worker) thread, which mss requires on Windows.
    import mss

    with mss.mss() as sct:
        # monitors[0] is the union of every display and [1:] the physical
        # ones; fall back to the union when no physical display is listed.
        monitors = sct.monitors[1:] or sct.monitors[:1]
        if not 0 <= display < len(monitors):
            # Never clamp: capturing a different display than the one asked
            # for would silently show the model the wrong screen.
            raise DisplayNotFoundError(
                f"display {display} not found; {len(monitors)} display(s) available"
            )
        shot = sct.grab(monitors[display])
        return shot.rgb, shot.width, shot.height


def _screen_context() -> ReportContext:
    """The facts the screen availability check and probe read, and no more.

    ``telegram_configured`` and ``browser_installed`` are fixed False:
    neither screen function reads them, so looking them up on every
    capture would be wasted work.
    """
    return ReportContext(
        in_container=cap_env.in_container(),
        platform=cap_env.platform_name(),
        telegram_configured=False,
        browser_installed=False,
        # The same resolved binary the report names, so the probe checks
        # the grant the owner was told to give (and shares its cache entry).
        executable=cap_env.crawler_executable(),
    )


def _probe_now() -> ProbeResult:
    """May a capture run here, now?

    Availability comes first, so a container or an unsupported OS refuses
    even if the capability gate upstream is misconfigured. The permission
    probe then goes through the registry's shared 10 s cache.
    """
    ctx = _screen_context()
    avail = screen.availability(ctx)
    if not avail.available:
        return ProbeResult("denied", avail.reason)
    return capabilities.cached_probe(screen.CAPABILITY.key, ctx)


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _log_failure(event: str, exc: BaseException, **fields: Any) -> None:
    logger.warning(
        event,
        error_type=type(exc).__name__,
        error=str(exc)[:_LOG_DETAIL_CHARS],
        **fields,
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _capture_problem(rgb: Any, width: Any, height: Any) -> Optional[str]:
    """Why a grabber's output cannot be encoded, or None when it can.

    The pixel bound is checked before the buffer length so an absurd claim
    is refused on its numbers alone.
    """
    if not isinstance(rgb, (bytes, bytearray)):
        return "Screen capture returned no image data."
    if not (_is_int(width) and _is_int(height)):
        return "Screen capture returned invalid dimensions."
    if width <= 0 or height <= 0:
        return "Screen capture returned an empty image."
    if width * height > MAX_PIXELS:
        return (
            f"The display is too large to capture ({width}x{height}; "
            f"the limit is {MAX_PIXELS:,} pixels)."
        )
    if len(rgb) != width * height * 3:
        return "Screen capture returned an image of the wrong size."
    return None


class DesktopToolkit:
    def __init__(
        self,
        grabber: Optional[Grabber] = None,
        probe: Optional[Callable[[], ProbeResult]] = None,
    ) -> None:
        self._grab = grabber or _mss_grab
        self._probe = probe or _probe_now

    async def execute(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one ``desktop.*`` action. Unknown actions fail closed."""
        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "screenshot": self.screenshot,
        }
        handler = handlers.get(action)
        if handler is None:
            return _error(f"Unknown desktop action '{action}'.")
        params = params or {}
        try:
            inspect.signature(handler).bind(**params)
        except TypeError as exc:
            return _error(f"Invalid arguments for desktop.{action}: {exc}")
        try:
            return await handler(**params)
        except Exception as exc:  # last resort: never raise into the agent loop
            _log_failure("desktop_action_failed", exc, action=action)
            return _error(f"desktop.{action} failed.")

    async def screenshot(self, display: int = 0) -> dict[str, Any]:
        if not _is_int(display):
            return _error("display must be an integer (0 = main display).")
        if display < 0:
            return _error("display must be 0 or greater (0 = main display).")
        try:
            probe = self._probe()
        except Exception as exc:  # fail closed: no answer is not a yes
            _log_failure("desktop_probe_failed", exc)
            return _error("The permission check failed.")
        if probe.state == "denied":
            return _error(
                f"Cannot capture the screen: {probe.detail}",
                fix_url=probe.fix_url,
                fix_steps=list(probe.fix_steps),
            )
        return await asyncio.to_thread(self._grab_and_encode, display)

    def _grab_and_encode(self, display: int) -> dict[str, Any]:
        """Capture one display and encode it as a downscaled JPEG.

        Runs in a worker thread: the grab and Pillow's decode, resize and
        encode are all too slow and memory-heavy for the event loop.
        """
        try:
            rgb, width, height = self._grab(display)
        except DisplayNotFoundError as exc:
            return _error(str(exc))
        except Exception as exc:
            _log_failure("desktop_screenshot_failed", exc, display=display)
            return _error("Screen capture failed.")

        problem = _capture_problem(rgb, width, height)
        if problem is not None:
            logger.warning(
                "desktop_screenshot_invalid",
                display=display,
                problem=problem,
                width=width if _is_int(width) else None,
                height=height if _is_int(height) else None,
                size=len(rgb) if isinstance(rgb, (bytes, bytearray)) else None,
            )
            return _error(problem)

        try:
            from PIL import Image

            image = Image.frombytes("RGB", (width, height), rgb)
            image.thumbnail((MAX_EDGE_PX, MAX_EDGE_PX))
            buf = io.BytesIO()
            image.save(buf, format="JPEG", quality=JPEG_QUALITY, optimize=True)
        except Exception as exc:
            _log_failure("desktop_screenshot_encode_failed", exc, display=display)
            return _error("Could not encode the screenshot.")

        data_url = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
        return {
            "ok": True,
            "image": data_url,
            "image_format": "jpeg",
            "width": image.width,
            "height": image.height,
            # The index captured: an out-of-range index raises rather than
            # being clamped, so this is never a different display.
            "display": display,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
