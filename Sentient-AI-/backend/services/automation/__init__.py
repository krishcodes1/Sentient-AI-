"""Shared machinery for work that runs while the owner is away: the tool fence
(``fence``), the run ledger and its budget sums (``ledger``), the runner
contract (``runner``) and how results are delivered (``delivery``).

Why it exists: scheduled tasks (this wave) and event triggers (wave 2) must
run under exactly the same rules and the same daily budget, so they share
these modules instead of each keeping its own copy.
"""
