# openclaw-guardrails

Provider-agnostic guardrails for LLM applications.

> Status: v0.1.0 — internal use only. Production-quality README lands in Task 14.

## Quick start

See `docs/superpowers/specs/2026-05-13-guardrails-platform-design.md` for the full design.

## Installation

Choose the extras you need:

```bash
pip install openclaw-guardrails             # core only (pydantic + pyyaml)
pip install "openclaw-guardrails[pii]"      # + Microsoft Presidio for PII rail
pip install "openclaw-guardrails[toxicity]" # + Detoxify for ToxicityFilter rail
pip install "openclaw-guardrails[all]"      # everything
```

ML deps (Presidio's spaCy, Detoxify's PyTorch) are intentionally optional so
users who only need a subset of rails don't pay the install cost.

## Development setup

```bash
pip install -e ".[dev]"            # tests + linters, fast install
pip install -e ".[dev,all]"        # tests + linters + ML deps
pytest
```
