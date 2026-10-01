"""Tests for the two Installable fields file_extraction added to the installer
(services/tools/system.py): ``native_only`` entries are refused in a
container, and ``platforms`` entries off their platforms, before any step
runs.

Why it exists: later allowlist entries (local text recognition, speech to
text) install things only a Mac or PC can use; the installer must refuse them
where they cannot work instead of running pip there.
"""

from __future__ import annotations

import sys

import pytest

from services.tools import system


def _entry(**fields) -> system.Installable:
    return system.Installable(
        description="test entry",
        size_hint="~1 MB",
        steps=(("never-run",),),
        detect=lambda: False,
        **fields,
    )


@pytest.fixture
def toolkit(monkeypatch):
    ran: list[list[str]] = []

    async def runner(argv, timeout):
        ran.append(argv)
        return 0, ""

    kit = system.SystemToolkit(runner=runner, detector=lambda name: False)
    kit.ran = ran
    return kit


def test_the_defaults_change_nothing():
    entry = _entry()
    assert entry.native_only is False and entry.platforms is None
    # The entries that predate the fields keep the defaults; only the ones
    # that install something a Mac or PC alone can use set native_only
    # (speech_to_text, top10:voice_notes).
    native = {name for name, item in system.ALLOWLIST.items() if item.native_only}
    assert native <= {"local_ocr", "speech_to_text"}
    assert system.ALLOWLIST["browser"].native_only is False and system.ALLOWLIST["browser"].platforms is None


@pytest.mark.asyncio
async def test_a_native_only_entry_is_refused_in_a_container(toolkit, monkeypatch):
    monkeypatch.setitem(system.ALLOWLIST, "native_thing", _entry(native_only=True))
    monkeypatch.setattr("services.capabilities.env.in_container", lambda: True)
    result = await toolkit.install_capability("native_thing")
    assert result["ok"] is False and "container" in result["error"]
    assert toolkit.ran == []


@pytest.mark.asyncio
async def test_an_entry_for_another_platform_is_refused(toolkit, monkeypatch):
    other = "darwin" if sys.platform != "darwin" else "win32"
    monkeypatch.setitem(system.ALLOWLIST, "elsewhere", _entry(platforms=frozenset({other})))
    result = await toolkit.install_capability("elsewhere")
    assert result["ok"] is False and "operating system" in result["error"]
    assert toolkit.ran == []


@pytest.mark.asyncio
async def test_an_entry_for_this_platform_runs(toolkit, monkeypatch):
    monkeypatch.setitem(system.ALLOWLIST, "here", _entry(platforms=frozenset({sys.platform})))
    monkeypatch.setattr("services.capabilities.env.in_container", lambda: False)
    await toolkit.install_capability("here")
    assert toolkit.ran == [["never-run"]]
