from services.capabilities import macos
from services.capabilities.base import Availability, Capability, ProbeResult, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.in_container:
        return Availability(
            False,
            "Not available in this environment (container). It works when Crawler runs directly on your Mac or PC.",
        )
    if ctx.platform not in ("darwin", "win32"):
        return Availability(False, "Desktop capture is supported on macOS and Windows only.")
    return Availability(True)


def probe(ctx: ReportContext) -> ProbeResult:
    if ctx.platform == "win32":
        return ProbeResult("not_required", "Windows needs no permission for screen capture.")
    if ctx.platform != "darwin":
        return ProbeResult("unknown", "No permission check on this platform.")
    granted = macos.screen_capture_preflight()
    if granted is None:
        return ProbeResult("unknown", "Could not query the macOS Screen Recording permission.")
    who = ctx.executable or "the Crawler process"
    if granted:
        return ProbeResult("granted", f"Screen Recording is granted to {who}.")
    return ProbeResult(
        "denied",
        f"macOS has not granted Screen Recording to {who}.",
        fix_url=macos.SCREEN_SETTINGS_URL,
        fix_steps=(
            "Open System Settings → Privacy & Security → Screen Recording.",
            f"Turn on the switch for {who} (or for Terminal, if Crawler was started from it).",
            "Restart Crawler.",
        ),
    )


def request_access() -> None:
    macos.screen_capture_request()
    macos.open_settings()


CAPABILITY = Capability(
    key="screen",
    label="See my screen",
    description="Take a picture of what is on this computer's display when you ask for it.",
    tools=("desktop.screenshot",),
    default_enabled=False,
    risk="high",
    when_denied="Seeing the screen is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
    probe=probe,
    request_access=request_access,
)
