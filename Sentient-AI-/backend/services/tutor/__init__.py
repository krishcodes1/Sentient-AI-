"""Tutor mode: a per-conversation Socratic mode, and the owner's locks that
force it on for chosen Canvas courses or whole accounts.

Why it exists: a student who asks Crawler for help with schoolwork should
be taught, not handed the answer, and an owner (a parent, a school) must be
able to make that hold for a course without trusting the model to remember.
Everything here is prompt text, stored state and deterministic gates; there
is no extra model call and no background work.

Modules:
- ``state``: the stored per-conversation state and the per-turn ``TutorTurn``.
- ``locks``: matching the owner's locks and validating a new one.
- ``prompt``: the fixed ``<tutor_mode>`` blocks and the reply notices.
- ``policy``: the withheld tools and the graded-page rule.
- ``commands``: the ``/tutor on|off|status`` grammar and its replies.
- ``service``: loading, persisting and the owner's lock CRUD (database).
- ``hooks``: the small call-outs the agent runtime makes during a turn.

Nothing here imports the agent runtime or the tool registry at module
level: the runtime imports ``hooks`` and ``state``, so those imports are
deferred to call time.
"""
