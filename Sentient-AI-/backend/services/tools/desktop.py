"""desktop.* built-in tools: what is on this computer's display.

Capability "screen" (off by default). The grabber and the permission probe
are injectable so tests never need a display. The result has the same
shape as web.screenshot so the runtime's vision feed and the Telegram
photo delivery apply unchanged.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import io
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.capabilities.base import ProbeResult

logger = structlog.get_logger(__name__)

Grabber = Callable[[int], tuple[bytes, int, int]]  # raw RGB bytes, width, height

MAX_EDGE_PX = 1280
JPEG_QUALITY = 70


def _mss_grab(display: int) -> tuple[bytes, int, int]:
    import mss  # imported lazily: absent on servers that never capture

    with mss.mss() as sct:
        monitors = sct.monitors[1:] or sct.monitors[:1]
        index = max(0, min(display, len(monitors) - 1))
        shot = sct.grab(monitors[index])
        return shot.rgb, shot.width, shot.height


def _probe_now() -> ProbeResult:
    from services import capabilities
    from services.capabilities import screen

    return screen.probe(capabilities.default_context())


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


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
        return await handler(**params)

    async def screenshot(self, display: int = 0) -> dict[str, Any]:
        if not isinstance(display, int) or isinstance(display, bool):
            return _error("display must be an integer (0 = main display).")
        probe = self._probe()
        if probe.state == "denied":
            return _error(
                f"Cannot capture the screen: {probe.detail}",
                fix_url=probe.fix_url,
                fix_steps=list(probe.fix_steps),
            )
        try:
            rgb, width, height = await asyncio.to_thread(self._grab, display)
        except Exception as exc:
            logger.warning("desktop_screenshot_failed", error=str(exc)[:200])
            return _error(f"Screen capture failed: {exc}")

        from PIL import Image

        image = Image.frombytes("RGB", (width, height), rgb)
        image.thumbnail((MAX_EDGE_PX, MAX_EDGE_PX))
        buf = io.BytesIO()
        image.save(buf, format="JPEG", quality=JPEG_QUALITY, optimize=True)
        data_url = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
        return {
            "ok": True,
            "image": data_url,
            "image_format": "jpeg",
            "width": image.width,
            "height": image.height,
            "display": display,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
