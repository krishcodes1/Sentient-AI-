"""Pytest fixtures for openclaw-guardrails tests."""
from __future__ import annotations

import pytest


@pytest.fixture
def fake_llm_responses() -> dict[str, str]:
    """Default prompt→response map for fake LLM judge.

    Tests can override entries by monkeypatching this fixture's return.
    """
    return {
        # Set by individual tests as needed.
    }


@pytest.fixture
def fake_llm(fake_llm_responses):
    """A deterministic fake LLM callable suitable for unit tests.

    Looks up the prompt in fake_llm_responses; raises if no match.
    """
    async def _llm(prompt: str, model: str) -> str:
        if prompt in fake_llm_responses:
            return fake_llm_responses[prompt]
        # Default: classify as safe / non-toxic / on-topic
        return '{"verdict": "safe", "confidence": 0.05, "reason": "no match"}'

    return _llm
