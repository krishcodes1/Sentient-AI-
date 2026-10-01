"""What an audit row keeps of a schedule.* result: ids, kind, status, the
schedule and time zone, counts, tool and channel names, and Crawler's own
error words; never a task's prompt, a briefing's topic, a label or a run's
last error.

Why it exists: the scheduler keeps a task's prompt and topic in its task row,
which the owner can delete, and its audit rows hold ids, status, cost and tool
names only. The arguments of schedule.create and schedule.briefing are kept
length-only (services/audit._LENGTH_ONLY_ARGUMENTS), but a schedule.list
result carries each prompt's first 200 characters, and the runtime stores the
first 500 characters of every result in the append-only audit log, so
runtime.result_for_audit hands schedule results here first.
"""

from __future__ import annotations

from typing import Any

from services.agent.audit_facts import FactRules, keep_facts

# One task as schedule.list shows it (services/tools/schedule.task_row).
_TASK = FactRules(
    text=frozenset(
        {
            "id",
            "task_id",
            "kind",
            "schedule",
            "timezone",
            "status",
            "next_run_local",
            "last_run_local",
            "last_status",
            "renderer",
        }
    ),
    names=frozenset({"channels", "tools", "write_tools", "sections"}),
)

_RESULT = FactRules(
    text=_TASK.text | frozenset({"rule", "code"}),
    names=_TASK.names,
    rows={"tasks": _TASK},
)


def schedule_result_for_audit(result: Any) -> Any:
    """*result* of a schedule.* call reduced to its facts."""
    return keep_facts(result, _RESULT)
