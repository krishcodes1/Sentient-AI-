from __future__ import annotations

import base64
import io

import pytest
from PIL import Image

from services.capabilities.base import ProbeResult
from services.tools.desktop import DesktopToolkit


def fake_grabber(width=3000, height=2000):
    def grab(display: int):
        return b"\x10\x20\x30" * (width * height), width, height
    return grab


@pytest.mark.asyncio
async def test_screenshot_downscales_to_1280_jpeg():
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: ProbeResult("granted"))
    result = await kit.execute("screenshot", {})
    assert result["ok"] is True
    assert result["image_format"] == "jpeg"
    assert result["image"].startswith("data:image/jpeg;base64,")
    assert max(result["width"], result["height"]) == 1280
    raw = base64.b64decode(result["image"].split(",", 1)[1])
    img = Image.open(io.BytesIO(raw))
    assert img.format == "JPEG" and img.size == (result["width"], result["height"])
    assert result["display"] == 0 and "captured_at" in result


@pytest.mark.asyncio
async def test_screenshot_refused_when_probe_denied():
    denied = ProbeResult("denied", "no grant", fix_url="x-apple.systempreferences:x", fix_steps=("Open Settings",))
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: denied)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert result["fix_url"] == "x-apple.systempreferences:x"
    assert "no grant" in result["error"]


@pytest.mark.asyncio
async def test_grabber_failure_is_reported_not_raised():
    def boom(display):
        raise OSError("no display")
    kit = DesktopToolkit(grabber=boom, probe=lambda: ProbeResult("granted"))
    result = await kit.execute("screenshot", {"display": 1})
    assert result["ok"] is False and "no display" in result["error"]


@pytest.mark.asyncio
async def test_unknown_action_and_bad_args_fail_closed():
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: ProbeResult("granted"))
    assert (await kit.execute("type", {}))["ok"] is False
    assert (await kit.execute("screenshot", {"display": "zero"}))["ok"] is False
