"""Control a browser: browser.read now; browser.login (phase 2) and
browser.act (phase 3) join under the same "browser." family prefix.

Off by default and high risk: it drives a real browser in a private
Crawler profile that may hold the owner's logins. Available when the
Playwright package is importable and there is a browser to drive: the
installed Chrome/Edge the platform layer names, or the bundled Chromium
the Installs capability can add (install="browser")."""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if not ctx.playwright_installed:
        return Availability(False, "Playwright is not installed. Run: pip install playwright")
    if ctx.browser_channel or ctx.browser_installed:
        return Availability(True)
    return Availability(
        False,
        "No browser to drive. Install Google Chrome or Microsoft Edge, or the "
        "bundled Chromium (about 150–300 MB).",
    )


CAPABILITY = Capability(
    key="browser_control",
    label="Control a browser",
    description=(
        "Open websites in Crawler's own browser, read what is on the page and "
        "move between pages, so tasks work on sites that have no API."
    ),
    tools=("browser.",),
    default_enabled=False,
    risk="high",
    when_denied="Browser control is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
    install="browser",
)
