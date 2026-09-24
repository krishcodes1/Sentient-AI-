"""The registry is what contributors extend. These invariants make a
misdeclared capability fail the build instead of silently doing nothing."""
from __future__ import annotations

import re

import pytest

from services import capabilities
from services.capabilities import _template
from services.capabilities.base import Capability
from services.agent.tool_registry import BUILTIN_CONNECTOR_TYPES, CONNECTOR_CATALOG


def _catalog_tool_names() -> set[str]:
    return {f"{ctype}.{spec.action}" for ctype, specs in CONNECTOR_CATALOG.items() for spec in specs}


def test_every_capability_key_is_snake_case_and_unique():
    keys = [c.key for c in capabilities.REGISTRY]
    assert len(keys) == len(set(keys))
    for key in keys:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", key), key


def test_every_claimed_tool_exists_in_the_catalog():
    names = _catalog_tool_names()
    for cap in capabilities.REGISTRY:
        for pattern in cap.tools:
            if pattern.endswith("."):
                assert any(n.startswith(pattern) for n in names), (cap.key, pattern)
            else:
                assert pattern in names, (cap.key, pattern)


def test_no_tool_is_claimed_twice():
    seen: dict[str, str] = {}
    for name in _catalog_tool_names():
        owners = [c.key for c in capabilities.REGISTRY if c.claims(name)]
        assert len(owners) <= 1, (name, owners)
        if owners:
            seen[name] = owners[0]
    assert seen  # sanity: something is claimed


def test_every_builtin_tool_is_claimed_or_explicitly_always_on():
    for ctype in BUILTIN_CONNECTOR_TYPES:
        for spec in CONNECTOR_CATALOG[ctype]:
            name = f"{ctype}.{spec.action}"
            assert capabilities.capability_for_tool(name) is not None or name in capabilities.ALWAYS_ON_TOOLS, name


def test_declarations_are_complete():
    labels = [c.label for c in capabilities.REGISTRY]
    assert len(labels) == len(set(labels))
    for cap in capabilities.REGISTRY:
        assert cap.when_denied.strip(), cap.key
        assert cap.description.strip(), cap.key
        assert cap.risk in ("low", "medium", "high"), cap.key


def test_template_is_not_registered():
    assert isinstance(_template.CAPABILITY, Capability)
    assert _template.CAPABILITY.key == "example"
    assert all(c.key != "example" for c in capabilities.REGISTRY)


def test_capability_for_tool_matches_exact_and_prefix():
    assert capabilities.capability_for_tool("web.search").key == "web_browsing"
    assert capabilities.capability_for_tool("reminders.create").key == "reminders"
    assert capabilities.capability_for_tool("desktop.screenshot").key == "screen"
    assert capabilities.capability_for_tool("system.capabilities") is None
    assert capabilities.capability_for_tool("gmail.send_email") is None


def test_get_unknown_key_raises():
    with pytest.raises(KeyError):
        capabilities.get("nope")
