from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.browser_installed:
        return Availability(True)
    return Availability(False, "The hidden browser is not installed yet (about 150–300 MB).")


CAPABILITY = Capability(
    key="site_screenshots",
    label="Screenshots of websites",
    description="Open a web page in a hidden browser and take a picture of it, for pages that cannot be read as text (flights, products).",
    tools=("web.screenshot",),
    default_enabled=True,
    risk="low",
    when_denied="Website screenshots are turned off. The owner can turn them on in Settings → Permissions.",
    availability=availability,
    install="browser",
)
