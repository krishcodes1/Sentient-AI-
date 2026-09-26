"""Declares the "browser_act" capability ("Fill in forms and click on sites")
behind browser.act, with its availability rule and the switch it needs on.

Why it exists: Reading a page and acting on it are different risks. With
"Control a browser" on, Crawler can open and read sites; typing into a form
or clicking a button there can send a message, sign the owner up or place an
order. So acting is a switch of its own, off by default: every act still
waits for the owner's approval card, and that card shows a picture of the
page with the target outlined, so nothing is sent (and no money moves)
without the owner having seen the page first.

Fill in forms and click on sites: browser.act (WRITE, one approval card per
step). It needs "Control a browser" on as well (the page is opened and read
through browser.read): ``requires`` makes the report say so, and the tool
registry's ``_REQUIRED_CAPABILITIES`` makes every gate refuse it.

Availability reads only the report context: native Mac or Windows, where the
owner can see Crawler's browser window, never a container.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext
from services.capabilities.computer_control import platform_of

CONTAINER_REASON = (
    "Not available in this environment (container). Filling in forms and clicking "
    "works when Crawler runs directly on your Mac or PC."
)
PLATFORM_REASON = "Filling in forms and clicking is available on macOS and Windows only."


def availability(ctx: ReportContext) -> Availability:
    """Native Mac or Windows only, like buying: the owner approves each step
    from a picture of the page and can look at the browser window itself."""
    platform = platform_of(ctx)
    if ctx.in_container or platform == "container":
        return Availability(False, CONTAINER_REASON)
    if platform not in ("mac", "windows"):
        return Availability(False, PLATFORM_REASON)
    return Availability(True)


CAPABILITY = Capability(
    key="browser_act",
    label="Fill in forms and click on sites",
    description=(
        "Type into forms, choose options and click buttons on sites in Crawler's "
        "browser; you approve every step on a card with a picture of the page."
    ),
    tools=("browser.act",),
    default_enabled=False,
    risk="high",
    when_denied=(
        "Filling in forms and clicking is off. Turn on 'Fill in forms and click on "
        "sites' in Permissions."
    ),
    availability=availability,
    requires=("browser_control",),
)
