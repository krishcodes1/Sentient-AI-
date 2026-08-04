"""Every runtime audit event must map to a deliberate row status.

``_EVENT_STATUS`` falls back to ``blocked`` for unknown event names. That
default is right for safety but wrong for reporting: an event that is
added to the runtime and forgotten here is silently filed as a refusal,
so the audit UI shows a red "Blocked" row for an action that actually
succeeded (this happened to `tool_approved`, caught only in end-to-end
verification because unit tests asserted event names, not statuses).

Rather than restate the mapping, this test reads the event names the
runtime actually emits out of its source and requires each to be
registered.
"""

from __future__ import annotations

import re
from pathlib import Path

from models.audit import AuditStatus
from services.audit import _EVENT_STATUS

_RUNTIME_SOURCE = (
    Path(__file__).resolve().parent.parent / "services" / "agent" / "runtime.py"
)


def _emitted_event_names() -> set[str]:
    source = _RUNTIME_SOURCE.read_text(encoding="utf-8")
    return set(re.findall(r'"event":\s*"([a-z_]+)"', source))


def test_runtime_emits_at_least_the_known_events():
    """Guards the extraction itself — if this regex stops matching, the
    coverage test below would pass vacuously."""
    emitted = _emitted_event_names()
    assert {
        "tool_executing",
        "tool_executed",
        "tool_blocked",
        "tool_pending_approval",
    } <= emitted, f"event extraction looks broken; found {emitted}"


def test_every_emitted_event_has_an_explicit_status():
    missing = sorted(_emitted_event_names() - set(_EVENT_STATUS))
    assert not missing, (
        "these runtime audit events are not registered in _EVENT_STATUS and "
        f"would be recorded as 'blocked': {missing}"
    )


def test_intent_events_are_not_recorded_as_blocked():
    """The pre-execution intent rows record that an action is starting, not
    that it was refused."""
    for event in ("tool_executing", "tool_approved"):
        assert _EVENT_STATUS[event] is not AuditStatus.blocked


def test_success_events_are_recorded_as_approved():
    for event in ("tool_executed", "tool_approved_and_executed"):
        assert _EVENT_STATUS[event] is AuditStatus.approved


def test_refusal_events_are_recorded_as_blocked():
    for event in ("tool_blocked", "tool_denied", "tool_expired", "input_blocked"):
        assert _EVENT_STATUS[event] is AuditStatus.blocked
