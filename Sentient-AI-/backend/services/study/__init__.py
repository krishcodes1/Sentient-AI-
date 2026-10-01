"""Flashcards and practice quizzes (the "study" capability): decks stored per
user, deterministic SM-2 reviews, quizzes graded in code, Anki/CSV export and
a model-free "cards are due" nudge.

Why it exists: groups the study engine so the study.* tools
(services/tools/study.py), the Telegram and Slack review commands and the
schedule sweeper's nudge share one set of rules. Kept import-light: the agent
runtime imports ``services.study.prompt`` from here.
"""
