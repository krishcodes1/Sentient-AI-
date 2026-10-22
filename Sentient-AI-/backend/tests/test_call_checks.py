"""Tests for the call-checks pipeline (services/security/call_checks.py): they prove
the checks run in the fixed order and only at their own stages; a refusal stops the
run and wins; notes are validated, de-duplicated, ordered by severity and capped
with a "more notes" line; a check that raises or times out escalates, notes,
refuses or is ignored exactly as its stage requires (a read never becomes a card);
executor answers carry the check, policy and rule and are recognised; escalation
sentences join, de-duplicate and cap; and note severities and texts are normalised
so a misspelling or an invisible character can never weaken a card.

Why it exists: five security skills plug their checks into this one pipeline, and
the runtime and the executor trust its answer to decide whether a call runs, asks
or is refused. Every rule here is fail-closed by design, so each one is pinned.
Everything is pure: scripted checks, no runtime, no network.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

import pytest

from services.agent.tool_registry import RUNTIME_BUILTIN_TYPES, resolve_tool
from services.security import call_checks
from services.security.call_checks import (
    ALLOW,
    BACKSTOP_TIMEOUT_S,
    CHECK_FAILED_NOTE,
    CHECK_FAILED_REASON,
    CHECK_FAILED_REFUSAL,
    CHECK_FAILED_RULE,
    CHECK_ORDER,
    DEFAULT_EXECUTE_ESCALATION,
    EMPTY_OUTCOME,
    MAX_NOTES,
    NOTE_TEXT_CHARS,
    PIPELINE_CHECK,
    REASON_CHARS,
    RUNTIME_ANSWERED_TYPES,
    Allow,
    CallCheckPipeline,
    CallFacts,
    CheckOutcome,
    Escalate,
    Escalation,
    Note,
    Refusal,
    Refuse,
    SecurityNote,
    call_check_refusal,
    has_warnings,
    notes_from,
    standard_pipeline,
)

SEND = "google_workspace.send_email"
READ = "google_workspace.get_message"
MCP = "mcp.notes.save"
ALL_STAGES = frozenset({"turn", "approve", "execute"})


@dataclass
class FakeCheck:
    """A scripted check. ``verdict`` is a verdict, an exception to raise,
    "hang" (never answers), or a callable of the call giving one of those."""

    name: str
    verdict: Any = ALLOW
    stages: frozenset[str] = ALL_STAGES
    policy: str = ""
    timeout_s: float = 1.0
    applies: Any = True
    calls: list[CallFacts] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.policy:
            self.policy = f"{self.name}_policy"

    def applies_to(self, call: CallFacts) -> bool:
        if isinstance(self.applies, BaseException):
            raise self.applies
        return bool(self.applies)

    async def check(self, call: CallFacts) -> Any:
        self.calls.append(call)
        verdict = self.verdict(call) if callable(self.verdict) else self.verdict
        if isinstance(verdict, BaseException):
            raise verdict
        if verdict == "hang":
            await asyncio.sleep(3600)
        return verdict


def facts(stage: str = "turn", tool: str = SEND, **fields: Any) -> CallFacts:
    """A call at *stage*, with the registry's spec for *tool* (none for MCP)."""
    is_mcp = tool.startswith("mcp.")
    resolved = None if is_mcp else resolve_tool(tool)
    return CallFacts(
        stage=stage,  # type: ignore[arg-type]
        user_id="u1",
        tool_name=tool,
        canonical=tool,
        arguments=fields.pop("arguments", {"to": "ann@example.com"}),
        spec=resolved.spec if resolved is not None else None,
        is_mcp=is_mcp,
        **fields,
    )


def note(kind: str, severity: str = "info", text: Optional[str] = None) -> SecurityNote:
    return SecurityNote(kind, severity, text or f"{kind} text")  # type: ignore[arg-type]


def pipeline(*checks: FakeCheck, audit: Any = None) -> CallCheckPipeline:
    return CallCheckPipeline(list(checks), audit=audit)


# ── construction and order ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_empty_pipeline_answers_the_empty_outcome_without_running_anything():
    empty = CallCheckPipeline()
    assert not empty and empty.names == ()
    outcome = await empty.run(facts())
    assert outcome is EMPTY_OUTCOME
    assert outcome.refusal is None and not outcome.escalated and outcome.notes == ()
    assert outcome.execute_result() is None
    assert outcome.reason_suffix(auto_run=True) == "" and outcome.audit_fields() == {}


@pytest.mark.asyncio
async def test_checks_run_in_the_fixed_order_and_an_unknown_or_misordered_check_is_refused_at_construction():
    assert CHECK_ORDER == ("tool_rules", "mcp_pin", "site_rules", "outbound", "file_reputation")
    seen: list[str] = []

    def recording(name: str) -> FakeCheck:
        return FakeCheck(name, verdict=lambda call: seen.append(name) or ALLOW)

    full = pipeline(*(recording(name) for name in CHECK_ORDER))
    assert full.names == CHECK_ORDER and bool(full)
    await full.run(facts())
    assert seen == list(CHECK_ORDER)

    with pytest.raises(ValueError, match="unknown call check"):
        CallCheckPipeline([FakeCheck("antivirus")])
    with pytest.raises(ValueError, match="twice"):
        CallCheckPipeline([FakeCheck("outbound"), FakeCheck("outbound")])
    with pytest.raises(ValueError, match="out of order"):
        CallCheckPipeline([FakeCheck("outbound"), FakeCheck("tool_rules")])


def test_standard_pipeline_keeps_the_production_order_and_leaves_out_missing_checks():
    built = standard_pipeline(
        file_reputation=FakeCheck("file_reputation"),
        tool_rules=FakeCheck("tool_rules"),
        outbound=FakeCheck("outbound"),
    )
    assert built.names == ("tool_rules", "outbound", "file_reputation")
    assert standard_pipeline().names == () and not standard_pipeline()


def test_the_runtime_answered_families_match_the_registry():
    """The pipeline may not import the registry, so it keeps its own copy."""
    assert RUNTIME_ANSWERED_TYPES == RUNTIME_BUILTIN_TYPES


# ── verdicts ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_refusal_stops_the_later_checks_and_wins_over_an_escalation():
    first = FakeCheck("tool_rules", Escalate((note("tool_rule", "warn"),), "Rule B1 asks first.", rule="builtin:b1"))
    refusing = FakeCheck("mcp_pin", Refuse(rule="tool_changed", message="The tool changed."))
    later = FakeCheck("outbound", Note((note("later"),)))
    outcome = await pipeline(first, refusing, later).run(facts(runs_without_card=True))
    assert later.calls == []
    assert outcome.refusal == Refusal("mcp_pin", "mcp_pin_policy", "tool_changed", "The tool changed.")
    # The escalation is kept but the refusal is what every caller acts on.
    assert outcome.escalated
    assert outcome.execute_result() == outcome.refusal.result()
    # A refusal's own policy wins over the check's.
    own = FakeCheck("site_rules", Refuse(rule="blocked_site", message="No.", policy="site_rules"))
    outcome = await pipeline(own).run(facts())
    assert outcome.refusal is not None and outcome.refusal.policy == "site_rules"


@pytest.mark.asyncio
async def test_notes_and_escalations_accumulate_in_severity_then_check_order():
    rules = FakeCheck("tool_rules", Note((note("a_info", "info"), note("b_warn", "warn"))))
    pins = FakeCheck(
        "mcp_pin",
        Escalate((note("c_high", "high"),), "Pins ask.", rule="pin:1", names_rule=True),
    )
    outbound = FakeCheck(
        "outbound",
        Escalate((note("d_warn", "warn"), note("e_info", "info")), "Outbound asks.", rule="o:1"),
    )
    outcome = await pipeline(rules, pins, outbound).run(facts(runs_without_card=True))
    assert outcome.note_kinds() == ["c_high", "b_warn", "d_warn", "a_info", "e_info"]
    assert [e.check for e in outcome.escalations] == ["mcp_pin", "outbound"]
    assert outcome.escalations[0] == Escalation(
        check="mcp_pin", policy="mcp_pin_policy", reason="Pins ask.", rule="pin:1",
        refusal_text="", names_rule=True,
    )
    assert outcome.rule() == "pin:1,o:1"
    assert outcome.warns
    assert outcome.audit_fields() == {
        "rule": "pin:1,o:1",
        "note_kinds": ["c_high", "b_warn", "d_warn", "a_info", "e_info"],
    }
    assert outcome.note_dicts()[0] == {"kind": "c_high", "severity": "high", "text": "c_high text"}


@pytest.mark.asyncio
async def test_notes_are_validated_deduplicated_and_capped_at_eight_with_a_more_notes_line():
    many = tuple(note(f"n{i}", "info", f"note number {i}") for i in range(11))
    noisy = (
        {"kind": "Bad Kind", "severity": "warn", "text": "dropped: kind"},
        {"kind": "no_text", "severity": "warn", "text": ""},
        "not a note",
        {"kind": "dup", "severity": "warn", "text": "same"},
        {"kind": "dup", "severity": "warn", "text": "same"},
    )
    outcome = await pipeline(
        FakeCheck("tool_rules", Note(noisy)),  # type: ignore[arg-type]
        FakeCheck("outbound", Note(many)),
    ).run(facts())
    assert len(outcome.notes) == MAX_NOTES
    assert outcome.notes[0] == SecurityNote("dup", "warn", "same")
    assert [n.kind for n in outcome.notes[1:-1]] == [f"n{i}" for i in range(6)]
    # 12 good notes, 8 shown: 7 kept, the 8th line stands for the other 5.
    assert outcome.notes[-1] == SecurityNote("more_notes", "info", "and 5 more security notes")
    # notes_from validates and caps stored values the same way, never with a "more" line.
    stored = notes_from([*noisy, *(n.to_dict() for n in many)])
    assert len(stored) == MAX_NOTES and stored[0] == {"kind": "dup", "severity": "warn", "text": "same"}
    assert notes_from(None) == [] and notes_from({"kind": "x"}) == [] and notes_from("x") == []


# ── a check that breaks ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_check_that_raises_escalates_a_call_that_would_run_without_a_card():
    later = FakeCheck("outbound", Note((note("still_runs"),)))
    outcome = await pipeline(FakeCheck("tool_rules", RuntimeError("db down")), later).run(
        facts(runs_without_card=True)
    )
    assert outcome.failed == ("tool_rules",)
    assert outcome.escalations == (
        Escalation(
            check="tool_rules", policy="tool_rules_policy", reason=CHECK_FAILED_REASON,
            rule=CHECK_FAILED_RULE, refusal_text="", names_rule=False,
        ),
    )
    assert SecurityNote("check_failed", "warn", CHECK_FAILED_NOTE) in outcome.notes
    # The later checks still run and add their notes.
    assert len(later.calls) == 1 and "still_runs" in outcome.note_kinds()
    assert outcome.refusal is None


@pytest.mark.asyncio
async def test_a_check_that_raises_only_adds_a_note_to_a_call_already_going_to_a_card():
    outcome = await pipeline(FakeCheck("site_rules", ValueError("boom"))).run(
        facts(will_card=True, runs_without_card=False)
    )
    assert not outcome.escalated and outcome.refusal is None
    assert outcome.notes == (SecurityNote("check_failed", "warn", CHECK_FAILED_NOTE),)
    assert outcome.reason_suffix(auto_run=True) == ""


@pytest.mark.asyncio
async def test_a_check_that_times_out_is_handled_like_one_that_raised(monkeypatch):
    monkeypatch.setattr(call_checks, "TURN_TIMEOUT_FLOOR_S", 0.01)
    monkeypatch.setattr(call_checks, "BACKSTOP_TIMEOUT_S", 0.01)
    hanging = FakeCheck("outbound", "hang", timeout_s=0.01)
    turn = await pipeline(hanging).run(facts(runs_without_card=True))
    assert turn.failed == ("outbound",) and turn.escalated
    execute = await pipeline(FakeCheck("outbound", "hang")).run(facts("execute"))
    assert execute.refusal == Refusal("outbound", PIPELINE_CHECK, CHECK_FAILED_RULE, CHECK_FAILED_REFUSAL)


def test_the_turn_stage_waits_at_least_the_floor_and_the_backstops_stay_quick():
    assert call_checks.TURN_TIMEOUT_FLOOR_S == 10.0 and BACKSTOP_TIMEOUT_S == 5.0


@pytest.mark.asyncio
async def test_a_check_that_raises_at_approval_refuses_the_call():
    later = FakeCheck("outbound")
    outcome = await pipeline(FakeCheck("mcp_pin", RuntimeError("x")), later).run(
        facts("approve", person_approved=True)
    )
    assert outcome.refusal == Refusal("mcp_pin", PIPELINE_CHECK, CHECK_FAILED_RULE, CHECK_FAILED_REFUSAL)
    assert later.calls == []


@pytest.mark.asyncio
async def test_a_check_that_raises_at_execute_refuses_writes_and_mcp_but_lets_reads_run():
    def broken() -> CallCheckPipeline:
        return pipeline(FakeCheck("tool_rules", RuntimeError("x")))

    write = await broken().run(facts("execute", SEND, runs_without_card=True))
    assert write.refusal is not None and write.refusal.policy == PIPELINE_CHECK
    mcp = await broken().run(facts("execute", MCP, person_approved=True))
    assert mcp.refusal is not None and mcp.refusal.rule == CHECK_FAILED_RULE
    read = await broken().run(facts("execute", READ, arguments={"message_id": "m1"}))
    assert read.refusal is None and read.failed == ("tool_rules",) and read.notes == ()


@pytest.mark.asyncio
async def test_a_check_that_raises_on_a_read_or_tools_find_at_the_turn_stage_adds_nothing():
    for tool in (READ, "tools.find", "tutor.start"):
        outcome = await pipeline(FakeCheck("tool_rules", RuntimeError("x"))).run(
            facts("turn", tool, arguments={}, runs_without_card=True)
        )
        assert outcome.failed == ("tool_rules",), tool
        assert outcome.notes == () and not outcome.escalated and outcome.refusal is None, tool


@pytest.mark.asyncio
async def test_a_check_answering_something_that_is_not_a_verdict_is_handled_like_one_that_raised():
    outcome = await pipeline(FakeCheck("outbound", {"ok": True})).run(facts("execute"))
    assert outcome.refusal is not None and outcome.refusal.rule == CHECK_FAILED_RULE


@pytest.mark.asyncio
async def test_a_bug_in_the_pipeline_is_handled_like_a_failure_of_the_pipeline_itself():
    class BrokenStages(FakeCheck):
        @property  # type: ignore[override]
        def stages(self) -> frozenset[str]:
            raise RuntimeError("bug")

        @stages.setter
        def stages(self, value: frozenset[str]) -> None:
            pass

    outcome = await pipeline(BrokenStages("outbound")).run(facts("approve", person_approved=True))
    assert outcome.refusal == Refusal(
        PIPELINE_CHECK, PIPELINE_CHECK, CHECK_FAILED_RULE, CHECK_FAILED_REFUSAL
    )
    turn = await pipeline(BrokenStages("outbound")).run(facts(runs_without_card=True))
    assert turn.failed == (PIPELINE_CHECK,) and turn.escalations[0].check == PIPELINE_CHECK


# ── stages ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_execute_stage_escalation_refuses_an_unapproved_call_and_is_ignored_for_a_person_approved_one():
    escalating = FakeCheck(
        "tool_rules",
        Escalate((note("tool_rule", "warn"),), "Rule asks.", rule="owner:1", refusal_text="Ask the owner first."),
    )
    standing = await pipeline(escalating).run(
        facts("execute", runs_without_card=True, approval="tier")
    )
    assert standing.notes == ()  # notes have no card to go on here
    assert standing.execute_result() == {
        "ok": False,
        "requires_approval": True,
        "call_check": "tool_rules",
        "policy": "tool_rules_policy",
        "rule": "owner:1",
        "error": "Ask the owner first.",
    }
    approved = await pipeline(escalating).run(facts("execute", person_approved=True))
    assert approved.execute_result() is None and not approved.escalated


@pytest.mark.asyncio
async def test_notes_and_escalations_are_ignored_at_the_approve_stage():
    outcome = await pipeline(
        FakeCheck("tool_rules", Escalate((note("x", "high"),), "Asks.")),
        FakeCheck("outbound", Note((note("y", "warn"),))),
    ).run(facts("approve", person_approved=True))
    assert outcome is EMPTY_OUTCOME


@pytest.mark.asyncio
async def test_a_check_outside_its_stages_or_not_applying_is_never_awaited():
    turn_only = FakeCheck("file_reputation", Refuse("r", "m"), stages=frozenset({"turn"}))
    not_applying = FakeCheck("outbound", Refuse("r", "m"), applies=False)
    outcome = await pipeline(not_applying, turn_only).run(facts("execute"))
    assert outcome is EMPTY_OUTCOME
    assert turn_only.calls == [] and not_applying.calls == []
    # applies_to that breaks counts as "applies": the check is asked.
    asked = FakeCheck("outbound", Note((note("asked"),)), applies=RuntimeError("x"))
    outcome = await pipeline(asked).run(facts())
    assert len(asked.calls) == 1 and outcome.note_kinds() == ["asked"]


# ── audit rows and executor answers ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_refusal_with_an_audit_event_writes_one_row_of_facts_and_survives_an_audit_failure():
    rows: list[dict[str, Any]] = []

    async def audit(entry: dict[str, Any]) -> None:
        rows.append(entry)

    refusing = FakeCheck(
        "site_rules",
        Refuse(
            rule="owner_blocked", message="The owner blocked this site.", policy="site_rules",
            audit_event="site_rule_blocked", audit_facts={"rule_id": "r1", "count": 1},
        ),
    )
    outcome = await pipeline(refusing, audit=audit).run(
        facts("execute", "browser.read", arguments={"url": "https://evil.example/x"})
    )
    assert outcome.refusal is not None
    [row] = rows
    assert row["event"] == "site_rule_blocked" and row["user_id"] == "u1"
    assert row["tool"] == "browser.read" and row["policy"] == "site_rules"
    assert row["rule"] == "owner_blocked" and row["arguments"] == {"rule_id": "r1", "count": 1}
    assert "timestamp" in row and "evil.example" not in str(row)

    async def failing(entry: dict[str, Any]) -> None:
        raise RuntimeError("audit store is down")

    outcome = await pipeline(refusing, audit=failing).run(facts("execute", "browser.read"))
    assert outcome.refusal is not None and outcome.refusal.rule == "owner_blocked"
    # Without an audit_event no row is written.
    plain = FakeCheck("site_rules", Refuse(rule="r", message="m"))
    rows.clear()
    await pipeline(plain, audit=audit).run(facts())
    assert rows == []


def test_execute_results_carry_call_check_policy_rule_and_a_fixed_error():
    refusal = Refusal("mcp_pin", "mcp_pin", "tool_changed", "The tool changed since you approved it.")
    assert refusal.result() == {
        "ok": False,
        "refused": True,
        "call_check": "mcp_pin",
        "policy": "mcp_pin",
        "rule": "tool_changed",
        "error": "The tool changed since you approved it.",
    }
    precheck = refusal.precheck()
    assert (precheck.reason, precheck.policy, precheck.rule) == (
        "The tool changed since you approved it.", "mcp_pin", "tool_changed",
    )
    assert precheck.result == refusal.result()
    escalated = CheckOutcome(
        escalations=(Escalation("outbound", "outbound_rule", "Asks.", "o:1", ""),)
    )
    assert escalated.execute_result() == {
        "ok": False,
        "requires_approval": True,
        "call_check": "outbound",
        "policy": "outbound_rule",
        "rule": "o:1",
        "error": DEFAULT_EXECUTE_ESCALATION,
    }


def test_call_check_refusal_recognises_only_pipeline_answers():
    refusal = Refusal("site_rules", "site_rules", "owner_blocked", "Blocked.").result()
    assert call_check_refusal(refusal) == ("Blocked.", "site_rules", "owner_blocked")
    escalation = CheckOutcome(
        escalations=(Escalation("tool_rules", "tool_rules", "Asks.", "owner:1", "Ask first."),)
    ).execute_result()
    assert call_check_refusal(escalation) == ("Ask first.", "tool_rules", "owner:1")
    for other in (
        None,
        "refused",
        {"ok": True, "call_check": "outbound", "refused": True},
        {"ok": False, "error": "Unknown tool"},
        {"ok": False, "capability": "web_browsing", "state": "off", "error": "Off."},
        {"ok": False, "call_check": "antivirus", "refused": True, "error": "x"},
        {"ok": False, "call_check": "outbound", "error": "no refused or requires_approval flag"},
        {"ok": False, "requires_approval": True, "error": "a connector's own confirmation"},
    ):
        assert call_check_refusal(other) is None, other


# ── reasons ──────────────────────────────────────────────────────────────────


def test_the_escalation_reason_joins_unique_sentences_and_is_capped():
    def esc(reason: str, check: str = "tool_rules") -> Escalation:
        return Escalation(check, "p", reason, "", "", names_rule=True)

    outcome = CheckOutcome(
        escalations=(esc("Rule B1 asks first."), esc("Rule B1 asks first.", "outbound"), esc("And this."))
    )
    assert outcome.reason_suffix(auto_run=False) == "Rule B1 asks first. And this."
    long = CheckOutcome(escalations=(esc("a" * 300 + "."), esc("b" * 300 + ".")))
    assert long.reason_suffix(auto_run=True) == "a" * 300 + "."  # whole sentences only
    huge = CheckOutcome(escalations=(esc("c" * 900),))
    capped = huge.reason_suffix(auto_run=True)
    assert len(capped) == REASON_CHARS and capped.endswith("…")


def test_reason_suffix_keeps_rule_naming_sentences_and_drops_auto_run_ones_unless_asked():
    outcome = CheckOutcome(
        escalations=(
            Escalation("tool_rules", "tool_rules", "Your rule 'No new payees' asks first.", "owner:1", "", True),
            Escalation("outbound", "outbound_rule", "Crawler would have done this without asking.", "", "", False),
        )
    )
    assert outcome.reason_suffix(auto_run=False) == "Your rule 'No new payees' asks first."
    assert outcome.reason_suffix(auto_run=True) == (
        "Your rule 'No new payees' asks first. Crawler would have done this without asking."
    )


# ── notes ────────────────────────────────────────────────────────────────────


def test_has_warnings_reads_stored_dicts_and_note_objects():
    assert has_warnings([{"kind": "a", "severity": "warn", "text": "t"}])
    assert has_warnings((note("b", "high"),))
    assert not has_warnings([{"kind": "a", "severity": "info", "text": "t"}, note("c", "info")])
    assert not has_warnings(None) and not has_warnings([]) and not has_warnings("warn")
    # A note that is not a note cannot warn; an old severity word still does.
    assert not has_warnings([{"kind": "", "severity": "high", "text": "t"}])
    assert has_warnings([{"kind": "x", "severity": "medium", "text": "t"}])


def test_note_severity_aliases_map_to_warn_or_high_and_an_unknown_one_never_reads_as_info():
    def severity(word: Any) -> str:
        made = SecurityNote.from_value({"kind": "k", "severity": word, "text": "t"})
        assert made is not None
        return made.severity

    assert severity("warning") == "warn" and severity("medium") == "warn"
    assert severity("danger") == "high" and severity("critical") == "high"
    assert severity("HIGH") == "high" and severity(" Info ") == "info"
    for unknown in ("severe", "", None, 3, "low"):
        assert severity(unknown) == "warn", unknown


def test_note_text_never_carries_bidi_tag_or_zero_width_characters():
    raw = (
        "Send\tto\r\neve‮@moc.example and "
        "​hidden‍﻿\U000e0041tag\x07bell" + "x" * 400
    )
    made = SecurityNote.from_value({"kind": "recipient_lookalike", "severity": "high", "text": raw})
    assert made is not None
    assert made.text.startswith("Send to eve@moc.example and hiddentagbell")
    for ch in ("‮", "​", "‍", "﻿", "\U000e0041", "\x07", "\t", "\n", " "):
        assert ch not in made.text
    assert len(made.text) == NOTE_TEXT_CHARS and made.text.endswith("…")
    assert SecurityNote.from_value({"kind": "k", "severity": "info", "text": "​ \n"}) is None
    assert SecurityNote.from_value(made) == made
    assert isinstance(ALLOW, Allow) and Note((made,)).notes == (made,)
