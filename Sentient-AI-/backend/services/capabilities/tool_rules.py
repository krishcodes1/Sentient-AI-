"""Declares the "tool_rules" capability: the owner's install-wide switch for checking every tool
call's arguments against the built-in safety rules and the owner's own rules, and asking first
when one is broken.

Why it exists: decisions.md item 3 (Progent-style rules). A call that breaks a rule gets an
approval card naming the rule; it never hard-fails, and no rule can let a call skip a card it
would otherwise get. A policy switch, not a toolkit: it claims no tools, is always available, and
is read by services/security/tool_rules/check.py once per turn (a read error counts as on). On by
default: it only ever adds cards. The rules themselves live in the tool_rules and
tool_rule_builtins tables (migration 0031), edited on the Security page by the owner only.
"""

from __future__ import annotations

from services.capabilities.base import Capability

KEY = "tool_rules"

CAPABILITY = Capability(
    key=KEY,
    label="Ask before calls that break a tool rule",
    description=(
        "Before Crawler runs an action, check it against a few built-in safety rules and the "
        "rules you add on the Security page (for example: an email address Crawler only saw in "
        "a message it read, or more than 10 recipients). A call that breaks one waits for your "
        "approval, and the card names the rule."
    ),
    tools=(),
    default_enabled=True,
    risk="low",
    when_denied=(
        "Tool rules are off, so calls are not checked against the owner's tool rules or the "
        "built-in ones (an address seen only in fetched content, more than 10 recipients, "
        "sharing outside the organisation, a link seen only in fetched content). The owner can "
        "turn on Ask before calls that break a tool rule in Settings → Permissions."
    ),
)
