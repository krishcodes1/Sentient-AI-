"""Tests for core types: ScanResult, RailContext, RailAction, Verdict."""
from __future__ import annotations

from openclaw_guardrails.types import (
    RailAction,
    RailContext,
    RailDecision,
    ScanResult,
    Verdict,
)


class TestVerdictEnum:
    def test_verdict_values(self):
        assert Verdict.PASS.value == "pass"
        assert Verdict.BLOCK.value == "block"
        assert Verdict.FLAG.value == "flag"
        assert Verdict.REDACT.value == "redact"


class TestRailAction:
    def test_default_action_is_log(self):
        assert RailAction.LOG.value == "log"

    def test_actions_cover_v1_catalog(self):
        names = {a.value for a in RailAction}
        assert {"block", "redact", "log", "flag", "refuse", "regenerate"}.issubset(names)


class TestScanResult:
    def test_blocked_when_any_decision_blocks(self):
        result = ScanResult(
            text="hi",
            decisions=[
                RailDecision(rail_name="pii", verdict=Verdict.PASS),
                RailDecision(rail_name="jailbreak", verdict=Verdict.BLOCK, reason="x"),
            ],
        )
        assert result.is_blocked is True

    def test_safe_when_all_pass(self):
        result = ScanResult(
            text="hi",
            decisions=[
                RailDecision(rail_name="pii", verdict=Verdict.PASS),
                RailDecision(rail_name="toxicity", verdict=Verdict.PASS),
            ],
        )
        assert result.is_blocked is False

    def test_transformed_text_defaults_to_none(self):
        result = ScanResult(text="alice@example.com", decisions=[])
        assert result.transformed_text is None
        assert result.effective_text == "alice@example.com"

    def test_transformed_text_when_set(self):
        result = ScanResult(
            text="alice@example.com",
            transformed_text="<EMAIL>",
            decisions=[RailDecision(rail_name="pii", verdict=Verdict.REDACT)],
        )
        assert result.transformed_text == "<EMAIL>"
        assert result.effective_text == "<EMAIL>"


class TestRailContext:
    def test_minimal_context(self):
        ctx = RailContext(user_id="u1")
        assert ctx.user_id == "u1"
        assert ctx.source_messages == []
        assert ctx.metadata == {}

    def test_full_context(self):
        ctx = RailContext(
            user_id="u1",
            source_messages=[{"role": "user", "content": "hi"}],
            metadata={"channel": "telegram"},
        )
        assert ctx.source_messages == [{"role": "user", "content": "hi"}]
        assert ctx.metadata == {"channel": "telegram"}
