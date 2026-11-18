"""Errands found in the owner's own calendar notes: the calendar sources
(calendar.py) and the finder that plans them (finder.py).

Why it exists: keeps reading the calendar and deciding what a note asks for
apart from running an errand, which services/automation/errands.py owns.

Connects to: services/automation/errands.py (``ErrandService.create`` and
``cancel``), main.py (wiring).
"""
