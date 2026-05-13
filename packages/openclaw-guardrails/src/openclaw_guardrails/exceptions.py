"""Public exceptions raised by the guardrails library."""
from __future__ import annotations


class GuardrailsError(Exception):
    """Base exception for all guardrails-related errors."""


class ConfigError(GuardrailsError):
    """Raised when a YAML config or programmatic config is invalid."""


class RailError(GuardrailsError):
    """Raised when an individual rail fails (model load, network, etc.)."""

    def __init__(self, rail_name: str, message: str) -> None:
        super().__init__(f"[{rail_name}] {message}")
        self.rail_name = rail_name
