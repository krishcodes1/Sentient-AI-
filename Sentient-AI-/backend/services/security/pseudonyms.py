"""Swaps contact details for numbered placeholders before text goes to a cloud
model, and puts the real values back in what the model returns.

Why it exists: the owner's "Hide personal details from the AI provider" switch.
The model sees [[EMAIL_1@uni.edu]] and [[PHONE_1]] instead of the addresses and
numbers; the reply the person reads and the tool calls they approve carry the
real values again, so nothing downstream works with a placeholder.

Rules:

- One vault per turn, in memory only. It is never stored, logged or sent
  anywhere, and its repr shows counts only.
- A value keeps its placeholder for the whole turn, so the numbering the
  model sees is stable across rounds.
- Placeholder-shaped text already present in content (a web page, an email,
  an earlier reply) is neutralised before hiding, so only placeholders this
  vault minted can ever be restored.
- At most ``MAX_VALUES`` values per turn; beyond that a value is masked
  irreversibly ("[email]").
"""

from __future__ import annotations

import re
from typing import Any

from services.security.policies import MODEL_PERSONAL
from services.security.redact import findings
from services.security.secrets import Kind

MAX_VALUES = 500

PLACEHOLDER_RE = re.compile(
    r"\[\[(EMAIL|PHONE|ADDRESS|DOB)_([0-9]{1,4})(?:@([A-Za-z0-9.-]{1,253}))?\]\]"
)

_PREFIX: dict[Kind, str] = {
    Kind.email: "EMAIL",
    Kind.phone: "PHONE",
    Kind.street_address: "ADDRESS",
    Kind.birth_date: "DOB",
}


def neutralise(text: str) -> str:
    """*text* with every placeholder-shaped run turned into plain text
    ("[[EMAIL_1@x.org]]" -> "[EMAIL_1@x.org]"), so a forged placeholder can
    never be restored to a real value."""
    return PLACEHOLDER_RE.sub(lambda m: "[" + m.group(0)[2:-2] + "]", text)


def placeholders_in(text: str) -> list[str]:
    """Every placeholder-shaped run in *text*, in order."""
    return [m.group(0) for m in PLACEHOLDER_RE.finditer(text)]


class PseudonymVault:
    """Value <-> placeholder for one turn."""

    def __init__(self, max_values: int = MAX_VALUES) -> None:
        self._max_values = max_values
        self._by_value: dict[tuple[Kind, str], str] = {}
        self._by_placeholder: dict[str, str] = {}
        self._next: dict[str, int] = {}
        self._masked = 0

    def __repr__(self) -> str:
        return f"PseudonymVault(values={len(self._by_placeholder)}, masked={self._masked})"

    def __len__(self) -> int:
        return len(self._by_placeholder)

    @property
    def masked(self) -> int:
        """Values masked irreversibly because the vault was full."""
        return self._masked

    def _key(self, kind: Kind, value: str) -> tuple[Kind, str]:
        return (kind, value.casefold() if kind is Kind.email else value)

    def placeholder_for(self, kind: Kind, value: str, label: str) -> str:
        """The placeholder for *value*: the one it already has this turn, a
        new one, or the irreversible "[label]" once the vault is full."""
        key = self._key(kind, value)
        known = self._by_value.get(key)
        if known is not None:
            return known
        prefix = _PREFIX.get(kind)
        if prefix is None or len(self._by_placeholder) >= self._max_values:
            self._masked += 1
            return MODEL_PERSONAL.placeholder.format(label=label)
        index = self._next.get(prefix, 1)
        self._next[prefix] = index + 1
        placeholder = f"[[{prefix}_{index}"
        if kind is Kind.email and "@" in value:
            placeholder += "@" + value.rsplit("@", 1)[1].lower()
        placeholder += "]]"
        self._by_value[key] = placeholder
        self._by_placeholder[placeholder.lower()] = value
        return placeholder

    def hide(self, text: str) -> str:
        """*text* with contact details swapped for placeholders. Raises
        when the detector fails; the caller withholds the text then."""
        return self.hide_and_list(text)[0]

    def hide_and_list(self, text: str) -> tuple[str, list[tuple[str, str]]]:
        """``hide`` plus ``(label, value)`` for each value it swapped, for a
        caller that counts them (and keeps only digests)."""
        text = neutralise(text)
        found = findings(text, MODEL_PERSONAL)
        if not found:
            return text, []
        parts: list[str] = []
        swapped: list[tuple[str, str]] = []
        cursor = 0
        for finding in found:
            value = text[finding.start : finding.end]
            parts.append(text[cursor : finding.start])
            parts.append(self.placeholder_for(finding.kind, value, finding.label))
            swapped.append((finding.label, value))
            cursor = finding.end
        parts.append(text[cursor:])
        return "".join(parts), swapped

    def known(self, placeholder: str) -> bool:
        return placeholder.lower() in self._by_placeholder

    def restore_text(self, text: str) -> str:
        """*text* with every placeholder this vault minted replaced by its
        value; unknown placeholders are left as they are."""
        if "[[" not in text:
            return text
        return PLACEHOLDER_RE.sub(
            lambda m: self._by_placeholder.get(m.group(0).lower(), m.group(0)), text
        )

    def restore_obj(self, data: Any) -> tuple[Any, list[str]]:
        """A copy of *data* (dicts, lists, strings) with placeholders
        restored, and the placeholder-shaped strings this vault never
        minted, in order."""
        unknown: list[str] = []

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                for placeholder in placeholders_in(value):
                    if not self.known(placeholder):
                        unknown.append(placeholder)
                return self.restore_text(value)
            if isinstance(value, dict):
                return {walk(k) if isinstance(k, str) else k: walk(v) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(item) for item in value]
            if isinstance(value, tuple):
                return tuple(walk(item) for item in value)
            return value

        restored = walk(data)
        return restored, list(dict.fromkeys(unknown))


__all__ = [
    "MAX_VALUES",
    "PLACEHOLDER_RE",
    "PseudonymVault",
    "neutralise",
    "placeholders_in",
]
