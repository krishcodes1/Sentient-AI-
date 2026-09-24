"""Declares the "computer_control" capability behind desktop.observe and
desktop.act, with its availability rule and its macOS Accessibility probe.

Why it exists: Letting the agent click and type in any app is the riskiest thing
Crawler can do, so it is off by default, native only (never in a container, not
on Linux in v1), and on macOS it needs the Accessibility grant; declaring those
facts here lets the registry, the wizard and the gates explain a refusal instead
of failing mid-action.

Control this computer: desktop.observe, desktop.act.

Availability: not in a container, macOS or Windows only, and the platform's
control backend must import (pyobjc on macOS, uiautomation on Windows). The
backend check is injected (``build_capability(backend_available=...)``), so
reports and tests never import an OS toolkit they do not need.
Probe: on macOS, ``AXIsProcessTrustedWithOptions`` without a prompt; denied →
the Accessibility pane, and steps naming the binary that needs the grant.
Windows needs no grant; windows running as administrator cannot be controlled
(UIPI), which the probe detail and ``desktop.observe`` say.

Declared only: the coordinator appends ``CAPABILITY`` to ``REGISTRY`` when
the desktop catalog gains ``observe`` and ``act``.
"""

from __future__ import annotations

import ctypes
import functools
import sys
from typing import Callable, Optional

from services.capabilities import macos
from services.capabilities.base import Availability, Capability, ProbeResult, ReportContext

ACCESSIBILITY_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
)
_APP_SERVICES = "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices"
_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

BackendCheck = Callable[[str], tuple[bool, str]]


# ── macOS Accessibility (ctypes, so no pyobjc is needed to ask) ─────────────


@functools.lru_cache(maxsize=2)
def _framework(path: str) -> Optional[ctypes.CDLL]:
    if sys.platform != "darwin":
        return None
    try:
        return ctypes.cdll.LoadLibrary(path)
    except OSError:
        return None


def accessibility_trusted() -> Optional[bool]:
    """Whether this process may control other apps (no prompt shown).
    None off macOS or when the framework cannot be asked."""
    lib = _framework(_APP_SERVICES)
    if lib is None:
        return None
    try:
        fn = lib.AXIsProcessTrustedWithOptions
    except AttributeError:
        return None
    fn.argtypes = [ctypes.c_void_p]
    fn.restype = ctypes.c_bool
    return bool(fn(None))


def accessibility_prompt() -> Optional[bool]:
    """Ask macOS to show its Accessibility prompt for this binary
    (``kAXTrustedCheckOptionPrompt``). None when it cannot be asked."""
    hs = _framework(_APP_SERVICES)
    cf = _framework(_CORE_FOUNDATION)
    if hs is None or cf is None:
        return None
    try:
        prompt_key = ctypes.c_void_p.in_dll(hs, "kAXTrustedCheckOptionPrompt")
        true_value = ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue")
        key_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(cf, "kCFTypeDictionaryKeyCallBacks"))
        value_callbacks = ctypes.addressof(
            ctypes.c_byte.in_dll(cf, "kCFTypeDictionaryValueCallBacks")
        )
        create = cf.CFDictionaryCreate
        release = cf.CFRelease
        check = hs.AXIsProcessTrustedWithOptions
    except (AttributeError, ValueError):
        return None
    create.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    release.argtypes = [ctypes.c_void_p]
    release.restype = None
    check.argtypes = [ctypes.c_void_p]
    check.restype = ctypes.c_bool
    keys = (ctypes.c_void_p * 1)(prompt_key.value)
    values = (ctypes.c_void_p * 1)(true_value.value)
    options = create(None, keys, values, 1, key_callbacks, value_callbacks)
    if not options:
        return None
    try:
        return bool(check(options))
    finally:
        release(options)


def _open_accessibility_settings() -> None:
    macos.open_settings(ACCESSIBILITY_SETTINGS_URL)


def _default_backend_available(platform: str) -> tuple[bool, str]:
    # Imported here: the toolkit package is not needed to build a report
    # until this capability is actually asked about.
    from services.tools.computer.backend import select_backend

    return select_backend(platform).available()


# ── capability ─────────────────────────────────────────────────────────────


def make_availability(
    backend_available: BackendCheck,
) -> Callable[[ReportContext], Availability]:
    def availability(ctx: ReportContext) -> Availability:
        if ctx.in_container:
            return Availability(
                False,
                "Not available in this environment (container). It works when Crawler runs "
                "directly on your Mac or PC.",
            )
        if ctx.platform not in ("darwin", "win32"):
            return Availability(
                False, "Controlling the computer is supported on macOS and Windows only."
            )
        ok, reason = backend_available(ctx.platform)
        if not ok:
            return Availability(
                False, reason or "The control component for this system is not installed."
            )
        return Availability(True)

    return availability


def make_probe(
    trusted: Callable[[], Optional[bool]],
) -> Callable[[ReportContext], ProbeResult]:
    def probe(ctx: ReportContext) -> ProbeResult:
        if ctx.platform == "win32":
            return ProbeResult(
                "not_required",
                "Windows needs no permission. Windows that run as administrator cannot be "
                "controlled (Windows blocks it).",
            )
        if ctx.platform != "darwin":
            return ProbeResult("unknown", "No permission check on this platform.")
        granted = trusted()
        if granted is None:
            return ProbeResult("unknown", "Could not query the macOS Accessibility permission.")
        who = ctx.executable or "the Crawler process"
        if granted:
            return ProbeResult("granted", f"Accessibility is granted to {who}.")
        return ProbeResult(
            "denied",
            f"macOS has not granted Accessibility to {who}.",
            fix_url=ACCESSIBILITY_SETTINGS_URL,
            fix_steps=(
                "Open System Settings → Privacy & Security → Accessibility.",
                f"Turn on the switch for {who} (use + to add it if it is not listed; if Crawler "
                "was started from Terminal, that is the app to switch on).",
                "Restart Crawler.",
            ),
        )

    return probe


def make_request_access(
    prompt: Callable[[], Optional[bool]],
    open_settings: Callable[[], None],
) -> Callable[[], None]:
    def request_access() -> None:
        prompt()
        open_settings()

    return request_access


def build_capability(
    *,
    backend_available: Optional[BackendCheck] = None,
    trusted: Optional[Callable[[], Optional[bool]]] = None,
    prompt: Optional[Callable[[], Optional[bool]]] = None,
    open_settings: Optional[Callable[[], None]] = None,
) -> Capability:
    """The capability, with its OS checks injectable (tests pass fakes)."""
    return Capability(
        key="computer_control",
        label="Control this computer",
        description=(
            "Look at the apps on this computer and click, type, press keys and open apps in "
            "them, asking you to approve every action."
        ),
        tools=("desktop.observe", "desktop.act"),
        default_enabled=False,
        risk="high",
        when_denied=(
            "Controlling this computer is turned off. The owner can turn it on in "
            "Settings → Permissions."
        ),
        availability=make_availability(backend_available or _default_backend_available),
        probe=make_probe(trusted or accessibility_trusted),
        request_access=make_request_access(
            prompt or accessibility_prompt, open_settings or _open_accessibility_settings
        ),
    )


CAPABILITY = build_capability()
