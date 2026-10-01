"""Declares the "study" capability: flashcard decks and practice quizzes, and the
study.* tools, the Telegram and Slack review commands and the "cards are due"
nudge it gates.

Why it exists: studying is an opt-in feature (nine more tool schemas and a
prompt block in every turn while on), so the owner gets one switch for it,
off by default: with it off every request is byte-identical to one on an
install without the feature, apart from its <permissions> line. It is always
available: it needs no program, no OS permission and no channel (Telegram
and Slack only add model-free reviews). The Telegram and Slack commands and
the nudge renderer re-read the same switch.
"""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    return Availability(True)


CAPABILITY = Capability(
    key="study",
    label="Flashcards and practice quizzes",
    description=(
        "Make flashcard decks and practice quizzes from your notes and course files, "
        "review them on a spaced-repetition schedule in chat, Telegram or Slack, and "
        "export decks for Anki."
    ),
    tools=("study.",),
    default_enabled=False,
    risk="low",
    when_denied=(
        "Flashcards and quizzes are turned off. The owner can turn them on in "
        "Settings → Permissions."
    ),
    availability=availability,
)
