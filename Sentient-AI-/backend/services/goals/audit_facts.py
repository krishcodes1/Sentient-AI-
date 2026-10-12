"""What an audit row keeps of a goals.* result: ids, statuses, categories,
check-in choices, dates, counts, progress and Crawler's own error words; never
a goal's title, description or current state, a milestone's title or a
progress note.

Why it exists: those fields are the user's own words, kept in goals they can
edit or delete on the Goals page. The arguments of every goals.* call keep
only their ids, choices and dates, and everything else as lengths and counts
(services/audit), but goals.list and goals.get return the goals themselves,
and the runtime stores the first 500 characters of every result in the
append-only audit log, so runtime.result_for_audit hands goals results here
first.
"""

from __future__ import annotations

from typing import Any

from services.agent.audit_facts import FactRules, keep_facts

# A milestone: its id, state and dates (its position is a number and kept).
_MILESTONE = FactRules(text=frozenset({"id", "state", "due_date", "done_at"}))

# A progress note: who wrote it, when, and which milestone it is about.
_ENTRY = FactRules(text=frozenset({"id", "source", "milestone_id", "created_at"}))

_GOAL = FactRules(
    text=frozenset(
        {
            "id",
            "category",
            "status",
            "check_in",
            "target_date",
            "created_at",
            "updated_at",
            "completed_at",
        }
    ),
    rows={
        # {done, total}: numbers only.
        "progress": FactRules(),
        "milestones": _MILESTONE,
        "entries": _ENTRY,
    },
)

_RESULT = FactRules(
    text=frozenset({"rule", "goal_id", "existing_goal_id"}),
    rows={
        "goal": _GOAL,
        "goals": _GOAL,
        "entry": _ENTRY,
        # What a delete removed: the goal's id and counts.
        "deleted": FactRules(text=frozenset({"goal_id"})),
    },
)


def goals_result_for_audit(result: Any) -> Any:
    """*result* of a goals.* call reduced to its facts."""
    return keep_facts(result, _RESULT)
