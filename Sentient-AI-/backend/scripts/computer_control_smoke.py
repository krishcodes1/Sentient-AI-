"""Checks computer control end to end on a real Mac: the ComputerToolkit over the
real MacBackend (pyobjc), with every hard rule in the path.

Why it exists: The unit tests run every backend against fakes, so nothing there
proves the real accessibility tree, synthetic events and permission checks
work. This script is that proof, run by hand on the owner's throwaway test Mac
(see docs/testing/computer-control-headless-mac.md). It is never run in CI and
never on a development machine.

Two modes:

- default (``--dry-run``): observe only. The backend is wrapped so that any
  input call (click, type, key, scroll, open app, focus window, permission
  prompt) raises instead of reaching macOS, and the refusal checks use the
  toolkit's ``precheck``, which calls no backend at all.
- ``--act``: also opens TextEdit, types "hello from Crawler", presses cmd+a,
  opens and cancels the Save sheet, checks the Stop flag, and opens a local
  test page in Safari to prove typing into a password field is refused. Real
  mouse and keyboard events are sent; run it only on the test Mac.

Usage, from the backend folder:

    python3 scripts/computer_control_smoke.py            # dry run
    python3 scripts/computer_control_smoke.py --act      # sends real input

Exit code 0 when no check failed, 1 when one did, 2 when the Mac is not set up
(not macOS, pyobjc missing, Accessibility not granted).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

USER = "smoke-test"
TYPED_TEXT = "hello from Crawler"
# Not a real secret: typed at a password field only to prove it is refused.
DECOY_PASSWORD = "not-a-real-password"
SETTLE_S = 1.5
COUNTDOWN_S = 5

_TEST_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Crawler secure field test</title></head>
<body>
<h1>Crawler secure field test</h1>
<label>User name <input type="text" name="user"></label>
<label>Password <input type="password" name="password"></label>
</body></html>
"""


class ObserveOnlyError(RuntimeError):
    """An input call reached the guard in dry-run mode."""


class GuardedBackend:
    """Passes reads straight through to the real backend and records every
    input call. With ``allow_input`` False, input calls raise instead."""

    def __init__(self, inner: Any, *, allow_input: bool) -> None:
        self._inner = inner
        self._allow_input = allow_input
        self.name = str(inner.name)
        self.inputs: list[tuple[Any, ...]] = []

    def _input(self, method: str, *args: Any, **kwargs: Any) -> Any:
        self.inputs.append((method, *args))
        if not self._allow_input:
            raise ObserveOnlyError(f"dry run: {method} was not sent")
        return getattr(self._inner, method)(*args, **kwargs)

    # Reads.
    def available(self) -> tuple[bool, str]:
        return self._inner.available()

    def permission(self) -> Any:
        return self._inner.permission()

    def list_apps(self) -> list[Any]:
        return self._inner.list_apps()

    def list_windows(self) -> list[Any]:
        return self._inner.list_windows()

    def frontmost(self) -> tuple[str, str]:
        return self._inner.frontmost()

    def focused(self) -> Any:
        return self._inner.focused()

    def outline(self, app: Optional[str], max_nodes: int) -> list[Any]:
        return self._inner.outline(app, max_nodes)

    # Input.
    def request_permission(self) -> None:
        self._input("request_permission")

    def click(self, target: Any, *, double: bool = False) -> None:
        self._input("click", target, double=double)

    def type_text(self, text: str, target: Any) -> None:
        self._input("type_text", text, target)

    def key(self, combo: Any) -> None:
        self._input("key", combo)

    def scroll(self, direction: str, amount: int) -> None:
        self._input("scroll", direction, amount)

    def open_app(self, name: str) -> None:
        self._input("open_app", name)

    def focus_window(self, app: str, index: int) -> None:
        self._input("focus_window", app, index)

    def sent(self, method: str) -> list[tuple[Any, ...]]:
        return [call for call in self.inputs if call[0] == method]


class Report:
    def __init__(self) -> None:
        self.failed = 0

    def line(self, status: str, name: str, detail: str = "") -> None:
        if status == "FAIL":
            self.failed += 1
        print(f"[{status}] {name}" + (f" - {detail}" if detail else ""), flush=True)

    def check(self, ok: bool, name: str, detail: str = "") -> bool:
        self.line("PASS" if ok else "FAIL", name, detail)
        return ok


def _ref(result: dict[str, Any], match: Callable[[str], bool]) -> Optional[str]:
    for line in result.get("outline") or ():
        if match(line):
            found = re.search(r"\[ref=(d\d+)\]", line)
            if found:
                return found.group(1)
    return None


def _show(result: dict[str, Any], limit: int = 15) -> None:
    lines = list(result.get("outline") or ())
    for line in lines[:limit]:
        print(f"      {line}")
    if len(lines) > limit:
        print(f"      ... {len(lines) - limit} more line(s)")


def _refused(result: Optional[dict[str, Any]], rule: str) -> bool:
    return result is not None and result.get("refused") is True and result.get("rule") == rule


def _display_report() -> str:
    """Main display geometry only (no pixels are read). A headless Mac with
    no display or virtual display attached reports none or a tiny one."""
    try:
        import Quartz

        display = Quartz.CGMainDisplayID()
        bounds = Quartz.CGDisplayBounds(display)
        width, height = int(bounds.size.width), int(bounds.size.height)
        asleep = bool(Quartz.CGDisplayIsAsleep(display))
    except Exception as exc:  # report, never crash the smoke test on this
        return f"could not read the display ({type(exc).__name__})"
    if width <= 0 or height <= 0:
        return "no main display: attach a display, a dummy HDMI plug or a virtual display"
    return f"main display {width}x{height}" + (" (asleep: wake it)" if asleep else "")


async def run(args: argparse.Namespace) -> int:
    from services.tools.computer.backend import select_backend
    from services.tools.computer.toolkit import ComputerToolkit

    report = Report()
    from services.capabilities.env import crawler_executable

    python = crawler_executable()
    print(f"Entry that needs the grants: {python}")
    if sys.platform != "darwin":
        print("This smoke test is for macOS only.")
        return 2
    print(f"Display: {_display_report()}")

    real = select_backend("mac")
    ok, reason = real.available()
    if not report.check(ok, "backend available", reason):
        print("Install the Mac dependencies: pip install -r requirements.txt")
        return 2
    state = real.permission()
    if state != "granted":
        report.line("FAIL", "Accessibility permission", f"state is {state!r}")
        print(
            "Grant Accessibility to the binary above: System Settings > Privacy & Security > "
            "Accessibility > + (press cmd+shift+G to paste the path), then run this again."
        )
        if args.request_permission:
            real.request_permission()  # shows macOS's prompt and opens the pane
            print("Opened the Accessibility pane.")
        return 2
    report.line("PASS", "Accessibility permission", "granted")

    backend = GuardedBackend(real, allow_input=args.act)
    cancelled = {"flag": False}
    kit = ComputerToolkit(backend, cancel_flag=lambda _uid: cancelled["flag"])

    async def observe(**params: Any) -> dict[str, Any]:
        return await kit.execute("observe", {"action": "outline", **params}, user_id=USER)

    async def act(**params: Any) -> dict[str, Any]:
        result = await kit.execute("act", params, user_id=USER)
        time.sleep(0.3)
        return result

    # ── observe (both modes) ──────────────────────────────────────────────
    apps = await kit.execute("observe", {"action": "apps"}, user_id=USER)
    names = [a["name"] for a in apps.get("apps") or ()]
    report.check(
        bool(apps.get("ok")) and bool(names),
        "list apps",
        f"{len(names)} app(s), front: {apps.get('frontmost_app')!r}; " + ", ".join(names[:12]),
    )
    windows = await kit.execute("observe", {"action": "windows"}, user_id=USER)
    report.check(
        bool(windows.get("ok")),
        "list windows",
        f"{len(windows.get('windows') or ())} window(s)",
    )
    front = await observe()
    if report.check(
        bool(front.get("ok")) and bool(front.get("outline")),
        "outline the front window",
        f"app {front.get('app')!r}, {front.get('refs')} ref(s), "
        f"{front.get('secure_fields_redacted')} secure field(s) redacted"
        + ("" if front.get("ok") else f", error: {front.get('error')}"),
    ):
        _show(front)
    if backend.inputs:
        report.line("FAIL", "observing sent no input", repr(backend.inputs))

    # ── refusals that need no input (both modes) ─────────────────────────
    terminal = kit.precheck({"action": "open_app", "app": "Terminal"}, user_id=USER)
    report.check(_refused(terminal, "blocked_app"), "refuse to open Terminal", str(terminal))
    if front.get("ok"):
        pressed = kit.precheck({"action": "key", "keys": "enter"}, user_id=USER)
        if _refused(pressed, "blocked_app"):
            report.line("PASS", f"refuse input to {front.get('app')!r}", str(pressed))
        else:
            report.line(
                "SKIP",
                "refuse input to a blocked front app",
                f"front app {front.get('app')!r} is not blocked (run this from Terminal to check)",
            )
        secure_ref = _ref(front, lambda line: "value=[redacted]" in line)
        if secure_ref:
            typed = kit.precheck(
                {"action": "type", "ref": secure_ref, "text": DECOY_PASSWORD}, user_id=USER
            )
            if typed and typed.get("refused") and typed.get("rule") != "secure_field":
                report.line(
                    "SKIP",
                    "refuse typing into a password field",
                    f"refused earlier by the {typed.get('rule')!r} rule",
                )
            else:
                report.check(
                    _refused(typed, "secure_field"),
                    "refuse typing into a password field",
                    str(typed),
                )
        else:
            report.line(
                "SKIP",
                "refuse typing into a password field",
                "no password field in the front window (--act opens a test page)",
            )

    if not args.act:
        print("\nDry run finished: nothing was clicked, typed or opened. Use --act for the rest.")
        return 1 if report.failed else 0

    # ── act (--act only) ─────────────────────────────────────────────────
    print(f"\nSending real input in {COUNTDOWN_S} s. Press ctrl+C now to stop.", flush=True)
    time.sleep(COUNTDOWN_S)

    opened = await act(action="open_app", app="TextEdit")
    report.check(bool(opened.get("ok")), "open TextEdit", str(opened.get("error") or ""))
    time.sleep(SETTLE_S)
    doc = await observe()

    def text_area(line: str) -> bool:
        return line.lstrip().startswith("- text area")

    if doc.get("ok") and _ref(doc, text_area) is None:
        # TextEdit opens with its Open panel: ask for a new document.
        await act(action="key", keys="cmd+n")
        time.sleep(SETTLE_S)
        doc = await observe()
    area = _ref(doc, text_area)
    if report.check(
        bool(doc.get("ok")) and doc.get("app") == "TextEdit" and area is not None,
        "outline TextEdit",
        f"front {doc.get('frontmost_app')!r}, text area ref {area}",
    ):
        _show(doc, 8)
        typed = await act(action="type", ref=area, text=TYPED_TEXT)
        report.check(bool(typed.get("ok")), f"type {TYPED_TEXT!r}", str(typed.get("error") or ""))
        after = await observe()
        report.check(
            any(TYPED_TEXT in line for line in after.get("outline") or ()),
            "the text is in the document",
        )
        selected = await act(action="key", keys="cmd+a")
        report.check(bool(selected.get("ok")), "press cmd+a", str(selected.get("error") or ""))

        saving = await act(action="key", keys="cmd+s")
        time.sleep(SETTLE_S)
        sheet = await observe()
        has_sheet = _ref(sheet, lambda line: '"Save"' in line and "button" in line) is not None
        report.check(bool(saving.get("ok")) and has_sheet, "cmd+s opens the Save sheet")
        cancelled_sheet = await act(action="key", keys="escape")
        time.sleep(SETTLE_S)
        closed = await observe()
        still = _ref(closed, lambda line: '"Save"' in line and "button" in line) is not None
        report.check(bool(cancelled_sheet.get("ok")) and not still, "escape cancels the Save sheet")

        # The kill switch: with the Stop flag set nothing is sent.
        keys_before = len(backend.sent("key"))
        cancelled["flag"] = True
        stopped = await act(action="key", keys="cmd+a")
        cancelled["flag"] = False
        report.check(
            _refused(stopped, "cancelled") and len(backend.sent("key")) == keys_before,
            "Stop cancels the next action",
            str(stopped.get("error") or ""),
        )

    launched = await act(action="open_app", app="Terminal")
    report.check(
        _refused(launched, "blocked_app") and ("open_app", "Terminal") not in backend.inputs,
        "refuse to open Terminal (live)",
        str(launched.get("error") or ""),
    )

    # A password field in a local page in Safari (a regular app, not blocked).
    page = Path(tempfile.mkdtemp(prefix="crawler-smoke-")) / "secure-field.html"
    page.write_text(_TEST_PAGE, encoding="utf-8")
    subprocess.run(["open", "-a", "Safari", str(page)], check=False, timeout=30)
    time.sleep(SETTLE_S * 2)
    web = await observe(app="Safari")
    secure_ref = _ref(web, lambda line: "value=[redacted]" in line)
    if report.check(
        bool(web.get("ok")) and secure_ref is not None,
        "Safari test page shows a secure field",
        f"{web.get('secure_fields_redacted')} redacted"
        + ("" if web.get("ok") else f", error: {web.get('error')}"),
    ):
        types_before = len(backend.sent("type_text"))
        refused = await act(action="type", ref=secure_ref, text=DECOY_PASSWORD)
        report.check(
            _refused(refused, "secure_field") and len(backend.sent("type_text")) == types_before,
            "refuse typing into the password field",
            str(refused.get("error") or ""),
        )
    else:
        _show(web, 25)

    print(
        "\nDone. TextEdit has an unsaved document and Safari has the test page open: close "
        "them by hand (TextEdit: cmd+w, then Delete)."
    )
    return 1 if report.failed else 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="observe only; send no input (the default)",
    )
    mode.add_argument(
        "--act",
        action="store_true",
        help="also send real mouse and keyboard input (test Mac only)",
    )
    parser.add_argument(
        "--request-permission",
        action="store_true",
        help="when Accessibility is not granted, show macOS's prompt and open the pane",
    )
    args = parser.parse_args(argv)
    import structlog

    # Only warnings: the check lines are the output.
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nStopped.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
