"""Holds list prices per (provider, model) and estimates the cost of a turn from
its token counts.

Why it exists: Every cost shown (dashboard, /usage, the Telegram reply line)
needs one price table. Lookups fold spelling only (case, a models/ prefix,
a pinned -001 or -latest suffix), so a model that is not listed shows no
cost rather than a near-miss's wrong one.

Connects to: nothing external; a static price table.
Used by: services/usage/summary.py (dashboard totals, /usage and the
per-reply Telegram cost line) and the setup wizard's model suggestions
(each suggested model must have a price).

List prices used to ESTIMATE what a turn cost.

These are estimates, not a bill. Provider prices change, and the numbers
below ignore much of what makes a real invoice differ from tokens x list
price: long-context tiers, off-peak and batch pricing, free tiers and
negotiated rates. Prompt caching IS modelled, because with cache
breakpoints on every request it is the single largest difference between
a naive estimate and the bill. The provider's own console is the source of
truth; this table exists so a person can see roughly where their spend is
going without leaving the app.

Lookups are exact on (provider, model) after normalising spelling only (see
``normalize_model_id``). A model that is not listed gets no price at all
rather than the price of something that looks similar: a near-miss match
(say, pricing a new Opus at an older Opus's rate) would be off by 3x and
would look just as authoritative as a correct one.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Optional

# The date the CURRENT section below was checked against the providers'
# pricing pages. Review when a provider announces a price change or a
# model is added to the Settings page.
PRICING_AS_OF = "2026-09-24"

# Anthropic bills a (5-minute, ephemeral) cache write at 1.25x the input
# rate.
ANTHROPIC_CACHE_WRITE_MULTIPLIER = 1.25
# OpenAI bills a cache write at 1.25x the input rate on GPT-5.6 and later
# (GPT-6 Luna included), and reports writes only for those models
# (services/agent/providers.OpenAICompatibleProvider._usage), so every write
# count it sends bills at this rate. No other provider here charges for
# writing its cache.
OPENAI_CACHE_WRITE_MULTIPLIER = 1.25
_CACHE_WRITE_MULTIPLIERS = {
    "anthropic": ANTHROPIC_CACHE_WRITE_MULTIPLIER,
    "openai": OPENAI_CACHE_WRITE_MULTIPLIER,
}


class ModelPrice(NamedTuple):
    """USD per 1M tokens."""

    input: float
    # Rate for input tokens served from the prompt cache. None where the
    # provider publishes no cached rate; cached tokens then bill at
    # ``input``, which can only overstate the cost, never hide it.
    cached_input: Optional[float]
    output: float
    # Date the provider retired the model, or a short note. Retired models
    # stay listed so turns recorded while they ran keep a cost.
    retired: Optional[str] = None


_PRICES: dict[tuple[str, str], ModelPrice] = {
    # -- Current, verified against provider pricing pages on PRICING_AS_OF.
    # Anthropic.
    ("anthropic", "claude-sonnet-5"): ModelPrice(2.00, 0.20, 10.00),
    ("anthropic", "claude-opus-5-5"): ModelPrice(4.00, 0.20, 20.00),
    ("anthropic", "claude-haiku-4-5"): ModelPrice(1.00, 0.10, 5.00),
    ("anthropic", "claude-haiku-4-5-20251001"): ModelPrice(1.00, 0.10, 5.00),
    # OpenAI.
    ("openai", "gpt-6-luna"): ModelPrice(0.10, 0.01, 0.50),
    ("openai", "gpt-5.4-nano"): ModelPrice(0.20, 0.02, 1.25),
    ("openai", "gpt-5.6-luna"): ModelPrice(0.20, 0.02, 1.20),
    ("openai", "gpt-5-mini"): ModelPrice(0.25, 0.025, 2.00),
    # Google. Output rates include thinking tokens. The 3.7/3.8 Flash rates
    # are introductory, valid until 2026-12-31 ($1.50 / $0.15 / $7.50 from
    # 2027-01-01); re-check them then.
    ("gemini", "gemini-3.5-flash"): ModelPrice(1.50, 0.15, 9.00),
    ("gemini", "gemini-3.5-flash-lite"): ModelPrice(0.30, 0.03, 2.50),
    # An alias Google moves between releases; it pointed at
    # gemini-3.5-flash-lite when this table was dated.
    ("gemini", "gemini-flash-lite-latest"): ModelPrice(0.30, 0.03, 2.50),
    ("gemini", "gemini-3.1-flash-lite"): ModelPrice(0.25, 0.025, 1.50),
    ("gemini", "gemini-3.7-flash"): ModelPrice(0.75, 0.075, 3.75),
    ("gemini", "gemini-3.8-flash"): ModelPrice(0.75, 0.075, 3.75),
    # DeepSeek, peak-hour rates (off-peak is cheaper; not modelled).
    ("deepseek", "deepseek-flash"): ModelPrice(0.30, 0.006, 1.20),
    # Groq-hosted open models.
    ("groq", "openai/gpt-oss-120b"): ModelPrice(0.15, 0.075, 0.60),
    # xAI.
    ("grok", "grok-4.3"): ModelPrice(1.25, 0.20, 2.50),
    # Mistral publishes no cached-input rate.
    ("mistral", "mistral-large-latest"): ModelPrice(0.50, None, 1.50),
    # -- Retired. Kept so turns recorded while they ran still have a cost.
    ("anthropic", "claude-sonnet-4-0"): ModelPrice(
        3.00, None, 15.00, retired="2026-06-15"
    ),
    ("anthropic", "claude-sonnet-4-20250514"): ModelPrice(
        3.00, None, 15.00, retired="2026-06-15"
    ),
    ("deepseek", "deepseek-chat"): ModelPrice(0.28, None, 0.42, retired="2026-07-24"),
    ("deepseek", "deepseek-reasoner"): ModelPrice(
        0.28, None, 0.42, retired="2026-07-24"
    ),
    ("gemini", "gemini-2.0-flash"): ModelPrice(0.10, None, 0.40, retired="shut down"),
    ("grok", "grok-3"): ModelPrice(3.00, None, 15.00, retired="likely retired"),
    # -- Legacy. Fixed model ids no longer offered in Settings, at the rates
    # recorded before this table was re-verified; not re-checked on
    # PRICING_AS_OF, and with no cached rate on file.
    ("anthropic", "claude-3-5-haiku-latest"): ModelPrice(0.80, None, 4.00),
    ("anthropic", "claude-3-5-haiku-20241022"): ModelPrice(0.80, None, 4.00),
    ("anthropic", "claude-sonnet-4-5"): ModelPrice(3.00, None, 15.00),
    ("anthropic", "claude-sonnet-4-5-20250929"): ModelPrice(3.00, None, 15.00),
    ("anthropic", "claude-sonnet-4-6"): ModelPrice(3.00, None, 15.00),
    ("anthropic", "claude-opus-4-0"): ModelPrice(15.00, None, 75.00),
    ("anthropic", "claude-opus-4-20250514"): ModelPrice(15.00, None, 75.00),
    ("anthropic", "claude-opus-4-1"): ModelPrice(15.00, None, 75.00),
    ("anthropic", "claude-opus-4-1-20250805"): ModelPrice(15.00, None, 75.00),
    ("anthropic", "claude-opus-4-5"): ModelPrice(5.00, None, 25.00),
    ("anthropic", "claude-opus-4-5-20251101"): ModelPrice(5.00, None, 25.00),
    ("anthropic", "claude-opus-4-6"): ModelPrice(5.00, None, 25.00),
    ("openai", "gpt-4o"): ModelPrice(2.50, None, 10.00),
    ("openai", "gpt-4o-mini"): ModelPrice(0.15, None, 0.60),
    ("openai", "o1"): ModelPrice(15.00, None, 60.00),
    ("openai", "o1-preview"): ModelPrice(15.00, None, 60.00),
    ("gemini", "gemini-2.5-flash"): ModelPrice(0.30, None, 2.50),
    ("gemini", "gemini-2.5-flash-lite"): ModelPrice(0.10, None, 0.40),
    # The <=200k-token prompt tier; longer prompts bill higher.
    ("gemini", "gemini-2.5-pro"): ModelPrice(1.25, None, 10.00),
    ("grok", "grok-3-mini"): ModelPrice(0.30, None, 0.50),
    ("groq", "llama-3.3-70b-versatile"): ModelPrice(0.59, None, 0.79),
}

# Providers whose every model runs on the operator's own hardware: there
# is no per-token charge to estimate, so the cost is a real zero rather
# than an unknown.
_FREE_PROVIDERS = frozenset({"ollama"})
_FREE = ModelPrice(0.0, 0.0, 0.0)


# Spellings of one Gemini model that bill identically: a pinned stable
# revision ("-001") and the "-latest" suffix on an already-versioned id.
# Anchored at the end and removed once, never used as a prefix match:
# "gemini-3.5-flash" is a prefix of "gemini-3.5-flash-lite", and the two
# are priced 5x apart. Previews ("-preview-09-2026") are deliberately NOT
# folded into their base model: Google has priced previews differently
# before, so an unlisted preview stays unpriced rather than guessed.
_GEMINI_EQUIVALENT_SUFFIX = re.compile(r"-(?:latest|\d{3})$")


def normalize_model_id(provider: Optional[str], model: Optional[str]) -> str:
    """The spelling a model id is priced (and grouped) under.

    Case and surrounding whitespace never change the model, and Gemini
    accepts its REST resource name ("models/gemini-3.5-flash") for the
    same model, so both are folded away. Nothing else is rewritten here.
    """
    name = (model or "").strip().lower()
    if (provider or "").strip().lower() == "gemini" and name.startswith("models/"):
        name = name[len("models/") :]
    return name


def price_for(provider: Optional[str], model: Optional[str]) -> Optional[ModelPrice]:
    """Per-1M-token rates for one model, or None when unknown."""
    name = (provider or "").strip().lower()
    if name in _FREE_PROVIDERS:
        return _FREE
    model_id = normalize_model_id(name, model)
    if not name or not model_id:
        return None
    # Exact first, so a listed alias ("gemini-flash-lite-latest") keeps its
    # own row instead of being cut down to something else.
    price = _PRICES.get((name, model_id))
    if price is None and name == "gemini":
        base = _GEMINI_EQUIVALENT_SUFFIX.sub("", model_id)
        if base != model_id:
            price = _PRICES.get((name, base))
    return price


def _same_model(provider: Optional[str], a: Optional[str], b: Optional[str]) -> bool:
    """Whether two ids are spellings of one billed model."""
    name = (provider or "").strip().lower()
    left, right = normalize_model_id(name, a), normalize_model_id(name, b)
    if name == "gemini":
        left = _GEMINI_EQUIVALENT_SUFFIX.sub("", left)
        right = _GEMINI_EQUIVALENT_SUFFIX.sub("", right)
    return left == right


def pricing_model_for(
    provider: Optional[str], model: Optional[str], served_model: Optional[str] = None
) -> Optional[str]:
    """The model id a turn should be priced under.

    ``model`` is what was requested; ``served_model`` is what the vendor
    says actually answered, when it says. They differ when ``model`` is a
    moving alias ("gemini-flash-latest"): the bill follows the served
    model, so that is priced, and an unlisted served model stays unpriced
    rather than inheriting the alias's (possibly stale) row.
    """
    if served_model and served_model.strip() and not _same_model(
        provider, model, served_model
    ):
        return served_model
    return model


def estimate_turn_cost_usd(
    provider: Optional[str],
    model: Optional[str],
    usage: Optional[dict[str, int]],
    served_model: Optional[str] = None,
) -> Optional[float]:
    """Estimated USD for one turn's summed usage dict (the runtime's
    ``AgentResponse.usage`` shape), priced under ``pricing_model_for``."""
    counts = usage or {}

    def count(key: str) -> int:
        value = counts.get(key)
        return value if isinstance(value, int) and value > 0 else 0

    return estimate_cost_usd(
        provider,
        pricing_model_for(provider, model, served_model),
        count("input_tokens"),
        count("output_tokens"),
        count("cache_read_tokens"),
        count("cache_write_tokens"),
    )


def estimate_cost_usd(
    provider: Optional[str],
    model: Optional[str],
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> Optional[float]:
    """Estimated USD for a token count on one model, or None when the
    model has no known price.

    ``input_tokens`` is the whole prompt; the cache counts are the parts
    of it read from and written to the prompt cache, so only the remainder
    bills at the plain input rate.
    """
    price = price_for(provider, model)
    if price is None:
        return None
    read = max(cache_read_tokens or 0, 0)
    written = max(cache_write_tokens or 0, 0)
    uncached = max(input_tokens - read - written, 0)
    cached_rate = price.input if price.cached_input is None else price.cached_input
    write_rate = price.input * _CACHE_WRITE_MULTIPLIERS.get((provider or "").strip().lower(), 1.0)
    return round(
        (
            uncached * price.input
            + read * cached_rate
            + written * write_rate
            + output_tokens * price.output
        )
        / 1_000_000,
        8,
    )
