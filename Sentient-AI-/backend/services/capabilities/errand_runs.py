"""Declares the "errand_runs" capability ("Do errands for me in the background")
and the limits every errand run gets.

Why it exists: the owner's goal is an assistant that sees "order this perfume
for my girlfriend" on their calendar and, a few days before it is needed,
finds the best price and orders it "in one approval, not 1000 approvals". An
errand run uses Crawler's browser with nobody watching, so it gets its own
switch, off by default and high risk, that needs "Fill in forms and click on
sites" and "Buy things for me" on. The run itself only searches, reads pages
and takes the steps that commit the owner to nothing; its one approval card
is the purchase, which the purchase caps still bound.

A policy switch: it claims no tools (tools=()); the errand sweeper
(services/automation/errands.py) reads it before it claims an errand and
again before every run. The settings are whole numbers like every capability
setting: the cost of one run and of a day of runs (cents), runs a day, the
rounds and minutes one run may take, how many hours the purchase card waits
and how many days before the needed-by date a run starts. The errand service
caps three of them whatever was saved (``SETTING_CEILINGS``: the card waits
48 hours at most, a run takes 60 minutes and 100 rounds at most), since the
card's wait also keeps the checkout page and a logged-in browser open.
"""

from __future__ import annotations

from services.capabilities.base import Capability

KEY = "errand_runs"

ERRAND_SETTINGS_DEFAULTS = {
    "run_cap_cents": 40,
    "day_cap_cents": 120,
    "runs_per_day": 6,
    "max_rounds": 40,
    "deadline_minutes": 15,
    "card_hours": 12,
    "lead_days": 7,
}

CAPABILITY = Capability(
    key=KEY,
    label="Do errands for me in the background",
    description=(
        "When an errand is due (like an order you noted on your calendar), Crawler finds the "
        "best price, adds it to the cart and goes to checkout in its browser while you're away, "
        "then asks you once before paying. Nothing is bought until you approve."
    ),
    tools=(),
    default_enabled=False,
    risk="high",
    when_denied=(
        "Background errands are off. The owner can turn on 'Do errands for me in the "
        "background' in Settings, under Permissions."
    ),
    requires=("browser_act", "purchases"),
)
