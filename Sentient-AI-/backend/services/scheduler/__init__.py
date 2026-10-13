"""The scheduler's pure pieces: recurrence rules and their next occurrence
(``recurrence``), IANA time zone checks (``timezones``), nudge renderers other
features register (``renderers``), the daily briefing's reads and text
(``briefing``) and the owner's Telegram and Slack commands (``commands``).

Why it exists: the schedule toolkit, the sweeper (services/notifications/
schedules.py), the REST routes and the chat channels all need the same rules;
keeping them here, with no database of their own, lets each be tested alone.
"""
