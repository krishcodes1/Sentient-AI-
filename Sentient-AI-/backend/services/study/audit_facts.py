"""What an audit row keeps of a study.* result: ids, counts, grades,
intervals, scores and Crawler's own error words; never a card's front, back,
choices, explanation or notes, a deck title, a tag or an export link.

Why it exists: card text comes from the user's study material (often an
uploaded document whose text the file reader keeps out of the log) and is
kept in the deck they can edit or delete. The arguments of study.save and
study.edit are kept as counts and lengths (services/audit), but a review,
quiz or deck listing returns the cards themselves, and the runtime stores the
first 500 characters of every result in the append-only audit log, so
runtime.result_for_audit hands study results here first.
"""

from __future__ import annotations

from typing import Any

from services.agent.audit_facts import FactRules, keep_facts

_IDS = frozenset({"deck_id", "item_id", "attempt_id"})

# A quiz answer as study.quiz submit reports it: whether it was right, never
# the choice picked, the right answer or why.
_ANSWER = FactRules(text=frozenset({"item_id"}))

# The review reminder a settings call or a progress report shows.
_REMINDER = FactRules(
    text=frozenset({"timezone"}),
    names=frozenset({"channels"}),
    rows={"recurrence": FactRules(text=frozenset({"freq", "time"}), names=frozenset({"days"}))},
)

_RESULT = FactRules(
    text=_IDS
    | frozenset(
        {
            "rating",
            "interval",
            "next_due",
            "status",
            "score",
            "format",
            "timezone",
            "rule",
            "code",
        }
    ),
    # Which fields a study.edit changed (field names, not their text).
    names=frozenset({"changed"}),
    rows={
        "results": _ANSWER,
        "deck": FactRules(text=frozenset({"deck_id"})),
        "reminder": _REMINDER,
        "nudge": _REMINDER,
    },
)


def study_result_for_audit(result: Any) -> Any:
    """*result* of a study.* call reduced to its facts."""
    return keep_facts(result, _RESULT)
