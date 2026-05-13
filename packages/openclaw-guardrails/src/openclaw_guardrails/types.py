"""Core types for the guardrails engine.

These are public — anything here is part of the stable v0.x API contract.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    """The outcome of a single rail's evaluation."""

    PASS = "pass"
    BLOCK = "block"
    REDACT = "redact"
    FLAG = "flag"


class RailAction(StrEnum):
    """The action a rail takes when it triggers.

    Configured per-rail by the operator. Determines what the rail's verdict
    looks like when its detection condition is met.
    """

    BLOCK = "block"
    REDACT = "redact"
    LOG = "log"
    FLAG = "flag"
    REFUSE = "refuse"
    REGENERATE = "regenerate"


class RailContext(BaseModel):
    """Per-invocation context passed to every rail.

    Rails read from this; they do not mutate it.
    """

    model_config = ConfigDict(frozen=True)

    user_id: str
    source_messages: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RailDecision(BaseModel):
    """What a single rail decided about a single input."""

    rail_name: str
    verdict: Verdict
    reason: str | None = None
    confidence: float | None = None
    latency_ms: float | None = None
    matched_text: str | None = None
    transformed_text: str | None = None  # set by rails that redact (PII, etc.)


class ScanResult(BaseModel):
    """Aggregated outcome of running a stack of rails over text."""

    text: str
    decisions: list[RailDecision] = Field(default_factory=list)
    transformed_text: str | None = Field(default=None)

    @property
    def effective_text(self) -> str:
        """Returns transformed_text if set, else the original text."""
        return self.transformed_text if self.transformed_text is not None else self.text

    @property
    def is_blocked(self) -> bool:
        return any(d.verdict == Verdict.BLOCK for d in self.decisions)

    @property
    def is_flagged(self) -> bool:
        return any(d.verdict == Verdict.FLAG for d in self.decisions)
