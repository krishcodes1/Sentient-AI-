"""What an audit row keeps of a triggers.* result: ids, source, mode,
status, counts, times and a refusal's rule code; never a trigger's prompt,
label, account, sender or subject filters, last error, an error sentence (it
may quote a sender the call gave), or anything a fire saw (subjects, senders,
posts).

Why it exists: a trigger's audit rows carry ids, counts and cost only. The
arguments of triggers.create and triggers.update are kept length-only
(services/audit), but triggers.list returns each trigger's filters and task
prompt and triggers.history returns capped facts of what each fire saw
(untrusted, third-party text), and the runtime stores the first 500
characters of every result in the append-only audit log, so
runtime.result_for_audit hands trigger results here first.
"""

from __future__ import annotations

from typing import Any

from services.agent.audit_facts import FactRules, keep_facts

# One trigger as triggers.list shows it (services/tools/triggers.trigger_row).
_TRIGGER = FactRules(
    text=frozenset(
        {"id", "trigger_id", "source", "mode", "status", "last_checked_at", "last_fired_at"}
    ),
)

# One fire as triggers.history shows it: when, how many and what became of
# them; its note and facts are dropped (counted).
_FIRE = FactRules(text=frozenset({"detected_at", "outcome"}))

_RESULT = FactRules(
    text=_TRIGGER.text | frozenset({"rule", "code"}),
    # Which columns a triggers.update changed (names, not values).
    names=frozenset({"changed"}),
    rows={"triggers": _TRIGGER, "fires": _FIRE},
    errors=False,
)


def triggers_result_for_audit(result: Any) -> Any:
    """*result* of a triggers.* call reduced to its facts."""
    return keep_facts(result, _RESULT)
