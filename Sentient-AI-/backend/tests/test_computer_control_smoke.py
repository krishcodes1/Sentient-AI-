"""Tests for scripts/computer_control_smoke.py (the real-Mac smoke test) against
the in-memory fake desktop: the dry run observes and checks the refusals
without sending a single input call, and the guard refuses input in dry-run.

Why it exists: The smoke script is the only code that drives a real desktop on
purpose. Its default mode must never send input, whatever the machine; these
tests prove that with a fake backend, so nothing here touches the real screen.
"""

from __future__ import annotations

import argparse
import sys

import pytest

from scripts import computer_control_smoke as smoke
from services.tools.computer import backend as backend_module
from services.tools.computer.backend import KeyCombo
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node


def _desktop(front: str = "Terminal") -> FakeBackend:
    return FakeBackend(
        [
            FakeApp(
                "Terminal",
                1,
                [FakeWindow("bash", (make_node("text area", "Shell", handle="shell"),))],
            ),
            FakeApp(
                "TextEdit",
                2,
                [
                    FakeWindow(
                        "Untitled",
                        (
                            make_node("text area", "Doc", handle="doc"),
                            make_node("text field", "Password", handle="pw", secure=True),
                        ),
                    )
                ],
            ),
        ],
        frontmost=front,
        focused="shell" if front == "Terminal" else "doc",
    )


async def _dry_run(monkeypatch, capsys, fake):
    monkeypatch.setattr(backend_module, "select_backend", lambda _name: fake)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(smoke, "_display_report", lambda: "main display 1920x1080 (fake)")
    code = await smoke.run(argparse.Namespace(act=False, dry_run=False, request_permission=False))
    return code, capsys.readouterr().out


def test_the_guard_refuses_input_in_dry_run_and_passes_reads():
    fake = _desktop()
    guard = smoke.GuardedBackend(fake, allow_input=False)
    assert guard.frontmost() == ("Terminal", "bash")
    for call in (
        lambda: guard.key(KeyCombo(frozenset({"cmd"}), "a")),
        lambda: guard.type_text("x", None),
        lambda: guard.click((1, 1)),
        lambda: guard.scroll("down", 1),
        lambda: guard.open_app("TextEdit"),
        lambda: guard.focus_window("TextEdit", 0),
        lambda: guard.request_permission(),
    ):
        with pytest.raises(smoke.ObserveOnlyError):
            call()
    assert fake.events == []
    assert [c[0] for c in guard.inputs] == [
        "key",
        "type_text",
        "click",
        "scroll",
        "open_app",
        "focus_window",
        "request_permission",
    ]


def test_the_guard_forwards_input_with_act():
    fake = _desktop()
    guard = smoke.GuardedBackend(fake, allow_input=True)
    guard.open_app("TextEdit")
    assert fake.events == [("open_app", "TextEdit")]
    assert guard.sent("open_app") == [("open_app", "TextEdit")]


@pytest.mark.asyncio
async def test_the_dry_run_from_terminal_refuses_input_to_it(monkeypatch, capsys):
    fake = _desktop("Terminal")
    code, out = await _dry_run(monkeypatch, capsys, fake)
    assert code == 0, out
    assert fake.events == []  # nothing was clicked, typed, pressed or opened
    assert "[PASS] list apps" in out
    assert "[PASS] outline the front window" in out
    assert "[PASS] refuse to open Terminal" in out
    assert "[PASS] refuse input to 'Terminal'" in out
    assert "[SKIP] refuse typing into a password field" in out
    assert "[FAIL]" not in out
    assert "Dry run finished" in out


@pytest.mark.asyncio
async def test_the_dry_run_refuses_typing_into_a_visible_password_field(monkeypatch, capsys):
    fake = _desktop("TextEdit")
    code, out = await _dry_run(monkeypatch, capsys, fake)
    assert code == 0, out
    assert fake.events == []
    assert "[PASS] refuse typing into a password field" in out
    assert "[SKIP] refuse input to a blocked front app" in out
    assert "[FAIL]" not in out


@pytest.mark.asyncio
async def test_the_dry_run_stops_when_accessibility_is_not_granted(monkeypatch, capsys):
    fake = FakeBackend([FakeApp("TextEdit", 2, [FakeWindow("Untitled")])], permission="denied")
    monkeypatch.setattr(backend_module, "select_backend", lambda _name: fake)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(smoke, "_display_report", lambda: "fake")

    code = await smoke.run(argparse.Namespace(act=False, dry_run=True, request_permission=False))
    out = capsys.readouterr().out
    assert code == 2
    assert "Privacy & Security > Accessibility" in out
    assert fake.events == []  # no permission prompt without --request-permission
