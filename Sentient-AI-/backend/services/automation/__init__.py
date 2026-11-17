"""Shared machinery for work that runs while the owner is away: the tool fence
(``fence``), the run ledger and its budget sums (``ledger``), the runner
contract (``runner``) and how results are delivered (``delivery``); and
background errands that end in one purchase card (``errands``, with
Telegram's /errands in ``errand_commands``).

Why it exists: scheduled tasks and event triggers must run under exactly the
same rules and the same daily budget, and errand runs under the same fence
with a browser and a budget of their own, so they share these modules
instead of each keeping its own copy.
"""
