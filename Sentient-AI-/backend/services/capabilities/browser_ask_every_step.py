"""Declares the "browser_ask_every_step" capability ("Ask before every website
step"): whether a website errand asks once per outcome or once per step.

Why it exists: the owner's principle is that an assistant takes work off the
person "in one approval, not 1000 approvals". Booking one movie ticket asked
them to approve a cookie banner, the showtime, a pop-up's Cancel and the
showtime again; buying a chain lube asked for "Add to cart", then "Proceed to
checkout". With this switch off (the default) the steps of a website errand
run without a card, and what commits the person (paying, sending, posting,
deleting, cancelling, signing up, agreeing to terms, typing their details)
keeps exactly one. With it on, every browser.act step gets its card, as it
always did, and the one-hour site approvals work as before.

A policy switch, not a toolkit: it claims no tools (tools=()), needs "Fill in
forms and click on sites" on, and is read per browser.act call by the runtime
(``AgentRuntime._asks_every_website_step``) from the same capability report
the permission adapter gates tools with. A report that cannot be read counts
as on: nothing runs unasked on a guess.

Connects to: services/agent/runtime.py (the no-card path), services/agent/
app_approvals.py (``errand_covers``: which steps), services/tools/browser/
act.py (``_errand``: the live page's word on each step).
"""

from __future__ import annotations

from services.capabilities.base import Capability

KEY = "browser_ask_every_step"

CAPABILITY = Capability(
    key=KEY,
    label="Ask before every website step",
    description=(
        "With this off, Crawler does the steps of a website errand (searching, opening pages, "
        "choosing options, adding to the cart, going to checkout) without a card and still asks "
        "before anything that pays, sends, posts, deletes, cancels, signs you up, agrees to terms "
        "or types your details. With it on, every step gets a card as before."
    ),
    tools=(),
    default_enabled=False,
    risk="low",
    when_denied=(
        "Website steps that commit the person to nothing (searching, opening pages, choosing "
        "options, adding to the cart, going on to the next page) run without asking; anything "
        "that pays, sends, posts, deletes, cancels, signs them up, agrees to terms or types their "
        "details still waits for their OK. The owner can turn on 'Ask before every website step' in "
        "Settings, under Permissions."
    ),
    requires=("browser_act",),
)
