"""Goals and plans (the "goals" capability): a user's goals with ordered
milestones and a progress log, kept per user in the database.

Why it exists: groups the goals store (``services.goals.store``), which holds
every rule a goal obeys, and the audit reduction of goals.* results
(``services.goals.audit_facts``), so the goals.* tools
(services/tools/goals.py) and the /api/goals routes share one set of rules.
Kept import-light: nothing is imported here, so the runtime can import
``services.goals.audit_facts`` without loading the store.
"""
