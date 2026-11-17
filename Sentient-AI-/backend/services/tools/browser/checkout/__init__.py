"""browser.checkout: Crawler pays for something in its own browser, with a
safeguard on every step (purchases spec §6): with the card in the owner's
vault on a page with card fields, or with the card the shop keeps on file
on a final page that shows it next to the order total.

Why a package of its own: buying is the one browser action that moves the
owner's money, so its facts (``facts``), its money and merchant parsing
(``amounts``, ``merchant``), its spending ledger (``ledger``) and the
toolkit that ties them together (``toolkit``) are kept apart from
``browser.read`` and ``browser.act`` and are each testable on their own.
Modules are imported by their own paths; only the two constants every
channel needs live here, so importing them never loads Playwright.
"""

from __future__ import annotations

# Shown on every purchase approval card (web, Telegram) and on the model's
# card arguments. The frontend copies the string and a test checks the copy
# against tests/fixtures/purchase_notice.txt, so change both together.
NOTICE = "Crawler can make mistakes. Check the amount and the site before you approve."

# Every rule name a checkout can be refused under, in the order the flow
# checks them: precheck (no browser: the arguments, the stop flag, the
# settings), begin (a person's step on the page, the page facts, then the
# vault and its stored card, only when the page has card fields), run
# (after the owner approved). The runtime files a refusal under
# ``purchase_rule`` with the rule name, so these are audit vocabulary and
# must stay stable.
CHECKOUT_RULES: tuple[str, ...] = (
    "invalid_arguments",
    "cancelled",
    "check_failed",
    "needs_human",
    "insecure_page",
    "merchant_mismatch",
    "no_total",
    "ambiguous_total",
    "currency",
    "no_card_fields",
    "submit_target",
    "over_cap",
    "over_daily_cap",
    "vault_unavailable",
    "no_card",
    "unbound_approval",
    "screen_changed",
)
