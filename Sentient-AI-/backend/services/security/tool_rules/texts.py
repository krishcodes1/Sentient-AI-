"""Every sentence the tool rules show a person: the four built-in rules' names and descriptions,
the notes and the reason an approval card carries when a rule is broken, the fixed answer the
executor backstop gives the model, the owner notices for a change that loosens protection, and
the reasons a rule is refused when the owner saves it.

Why it exists: decisions.md item 3 says the card names the rule. The wording lives in one place
so it can be read and reviewed as a whole, and so one rule holds everywhere: a note or a reason
names rules, argument names, counts and the owner's own rule text, and never quotes an argument
value (the card already shows the arguments in full, and a value can be attacker-written).

Connects to: nothing but the standard library.
Used by: builtins.py (names, descriptions, built-in notes), engine.py (owner-rule notes, the
"unavailable" hit), grammar.py (validation reasons, summaries), check.py (the card reason, the note
list and the execute-stage refusal) and api/routes/security_tool_rules.py (the owner notices).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Sequence

# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BuiltinText:
    """What the Security page and the cards say about one built-in rule. ``no_longer`` finishes
    the sentence "Crawler will no longer ..." in the notice sent when the owner turns it off."""

    name: str
    description: str
    no_longer: str


UNTRUSTED_RECIPIENT = BuiltinText(
    name="Address seen only in content Crawler read",
    description=(
        "Ask before a send, share or invite to an email address that appeared in an email, web "
        "page or file Crawler read, or in its own earlier replies, but not in your messages."
    ),
    no_longer=(
        "ask before a send, share or invite to an email address that appeared only in content "
        "it read"
    ),
)
MANY_RECIPIENTS = BuiltinText(
    name="More than 10 recipients",
    description="Ask before one action addresses more than 10 people.",
    no_longer="ask before one action addresses more than 10 people",
)
OUTSIDE_SHARE = BuiltinText(
    name="Sharing outside your organisation",
    description=(
        "Ask before forwarding, sharing a file or inviting someone whose address is not at your "
        "organisation's domains."
    ),
    no_longer=(
        "ask before forwarding, sharing a file or inviting someone outside your organisation"
    ),
)
UNTRUSTED_LINK = BuiltinText(
    name="Link seen only in content Crawler read",
    description=(
        "Ask before a change that includes a link to a site that appeared only in content "
        "Crawler read, not in your messages."
    ),
    no_longer=(
        "ask before a change that includes a link to a site that appeared only in content it read"
    ),
)

# ---------------------------------------------------------------------------
# Card notes (one per broken rule; SecurityNote kind "tool_rule", severity "warn")
# ---------------------------------------------------------------------------

# An argument path is named on a card only when it looks like an argument name. An MCP tool's
# argument keys come from the model's call, so a key could itself carry an address or a sentence.
_SAFE_ARG = re.compile(r"[A-Za-z0-9_]{1,40}(?:\.[A-Za-z0-9_]{1,40}){0,5}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")


def display_arg(path: Optional[str]) -> Optional[str]:
    """*path* when it is safe to print on a card ("to", "event_data.attendees"); else None."""
    if isinstance(path, str) and _SAFE_ARG.fullmatch(path):
        return path
    return None


def _the_address_in(path: Optional[str]) -> str:
    arg = display_arg(path)
    return f'the address in "{arg}"' if arg else "an address in its arguments"


def untrusted_recipient_note(name: str, path: Optional[str]) -> str:
    return (
        f'Tool rule "{name}": {_the_address_in(path)} appeared in content Crawler read in this '
        "request, not in your messages. Check it is someone you meant."
    )


def unusual_recipient_note(name: str, path: Optional[str]) -> str:
    return (
        f'Tool rule "{name}": {_the_address_in(path)} uses unusual characters (it may imitate '
        "another address) and isn't one you typed."
    )


def unreadable_recipient_note(name: str, path: Optional[str]) -> str:
    arg = display_arg(path)
    subject = f'"{arg}"' if arg else "One of its arguments"
    return (
        f'Tool rule "{name}": {subject} holds an address Crawler could not read, so it can\'t '
        "tell who this goes to. Check it is someone you meant."
    )


def many_recipients_note(name: str, count: int) -> str:
    return f'Tool rule "{name}": this addresses {count} people.'


def _listed(items: Sequence[str], limit: int) -> str:
    """The first *limit* items joined by ", ", then "and N more"."""
    shown = list(items[:limit])
    more = len(items) - len(shown)
    text = ", ".join(shown)
    return f"{text} and {more} more" if more > 0 else text


def outside_share_note(name: str, path: Optional[str], org_domains: Sequence[str]) -> str:
    arg = display_arg(path)
    subject = f'"{arg}"' if arg else "One of its arguments"
    return (
        f'Tool rule "{name}": {subject} has an address that is not at your organisation\'s '
        f"domains ({_listed(sorted(org_domains), 3)})."
    )


def outside_share_unread_address_note(
    name: str, path: Optional[str], org_domains: Sequence[str]
) -> str:
    arg = display_arg(path)
    subject = f'"{arg}"' if arg else "One of its arguments"
    return (
        f'Tool rule "{name}": {subject} holds an address Crawler could not read, so it can\'t '
        f"tell whether it is at your organisation's domains ({_listed(sorted(org_domains), 3)})."
    )


def outside_share_unreadable_note(name: str) -> str:
    return (
        f'Tool rule "{name}": Crawler could not read your organisation\'s domains, so this share '
        "asks."
    )


def untrusted_link_note(name: str, path: Optional[str]) -> str:
    arg = display_arg(path)
    where = f'in "{arg}"' if arg else "in its arguments"
    return (
        f'Tool rule "{name}": a link {where} goes to a site that appeared only in content '
        "Crawler read."
    )


def deceptive_link_note(name: str, path: Optional[str]) -> str:
    arg = display_arg(path)
    where = f'in "{arg}"' if arg else "in its arguments"
    return (
        f'Tool rule "{name}": a link {where} is written so that it may open a different site '
        "than the one it shows."
    )


def owner_rule_note(name: str, phrases: Sequence[str]) -> str:
    """The note for one of the owner's own rules: its name and its conditions in the owner's
    words (thresholds, lists and patterns the owner wrote, never the call's values)."""
    if not phrases:
        return f'Your tool rule "{name}" asks before every call it covers.'
    return f'Your tool rule "{name}": {" and ".join(phrases)}.'


def rule_failed_note(name: str, *, owner: bool) -> str:
    whose = "your tool rule" if owner else "the tool rule"
    return f'Crawler could not check {whose} "{name}", so it is asking first.'


UNAVAILABLE_NAME = "rules unavailable"
# A stored rule whose name today's check refuses (a hand edit of the table) is shown as this.
UNREADABLE_RULE_NAME = "a rule that could not be read"
UNAVAILABLE_NOTE = "Crawler could not read your tool rules, so it is asking before this change."

# The executor backstop's answer to the model for a write no person approved that a rule asks
# about. Fixed: the model never learns the owner's rule names.
EXECUTE_REFUSAL = (
    "This needs the owner's approval first: it matches one of their tool rules. Nothing was run."
)

MAX_CARD_NOTES = 5
MAX_REASON_NAMES = 3


def card_notes(notes: Sequence[str], *, limit: int = MAX_CARD_NOTES) -> list[str]:
    """At most *limit* notes, then one "and N more tool rules" line for the rest."""
    kept = list(notes[:limit])
    more = len(notes) - len(kept)
    if more > 0:
        kept.append(f"and {more} more tool rule{'s' if more != 1 else ''}")
    return kept


def card_reason(names: Sequence[str], *, limit: int = MAX_REASON_NAMES) -> str:
    """The sentence appended to the card reason: "Tool rule: <name>." or "Tool rules: <a>; <b>;
    <c>; and N more." (names in order, repeats dropped)."""
    unique = list(dict.fromkeys(n for n in names if n))
    if not unique:
        return ""
    if len(unique) == 1:
        return f"Tool rule: {unique[0]}."
    shown = unique[:limit]
    more = len(unique) - len(shown)
    tail = f"; and {more} more" if more > 0 else ""
    return f"Tool rules: {'; '.join(shown)}{tail}."


# ---------------------------------------------------------------------------
# Owner notices (a change that loosens protection; sent after the change is committed)
# ---------------------------------------------------------------------------


def rule_removed_notice(name: str) -> str:
    return (
        f'Security: a tool rule was removed: "{name}". Crawler will no longer ask before the '
        "calls it matched. If this wasn't you, sign in and check Security → Tool rules."
    )


def builtin_off_notice(text: BuiltinText) -> str:
    return (
        f'Security: a built-in safety rule was turned off: "{text.name}". Crawler will no longer '
        f"{text.no_longer}. If this wasn't you, turn it back on in Security → Tool rules."
    )


# ---------------------------------------------------------------------------
# Rule summaries and condition phrases (the owner's own words)
# ---------------------------------------------------------------------------

SUMMARY_LIST_LIMIT = 10
NOTE_LIST_LIMIT = 3


def _shown_text(value: str) -> str:
    """Owner text as one line inside double quotes (control characters become spaces)."""
    return '"' + " ".join(_CONTROL.sub(" ", value).split()) + '"'


def format_number(value: float) -> str:
    """500.0 -> "500", 1250.5 -> "1250.5"."""
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


def _shown_value(value: object) -> str:
    if isinstance(value, bool):
        return _shown_text(str(value).lower())
    if isinstance(value, (int, float)):
        return format_number(float(value))
    return _shown_text(str(value))


def condition_phrase(arg: str, op: str, value: object, *, list_limit: int) -> str:
    """One condition as a phrase: '"amount" is more than 500', 'any argument contains "x"'."""
    subject = "any argument" if arg == "*" else f'"{arg}"'
    items: list[str] = list(value) if isinstance(value, (list, tuple)) else [str(value)]
    if op == "equals":
        return f"{subject} is {_shown_value(value)}"
    if op == "not_equals":
        return f"{subject} is not {_shown_value(value)}"
    if op == "contains":
        return f"{subject} contains {_shown_value(value)}"
    if op == "regex":
        return f"{subject} matches the pattern {_shown_value(value)}"
    if op == "in_list":
        return f"{subject} is one of {_listed([_shown_text(str(i)) for i in items], list_limit)}"
    if op == "domain_in":
        return f"{subject} has an address or link at {_listed([str(i) for i in items], list_limit)}"
    if op == "domain_not_in":
        return (
            f"{subject} has an address or link outside "
            f"{_listed([str(i) for i in items], list_limit)}"
        )
    if op == "number_gt":
        return f"{subject} is more than {_shown_value(value)}"
    if op == "number_lt":
        return f"{subject} is less than {_shown_value(value)}"
    return f"{subject} {op} {_shown_value(value)}"


def rule_summary(tool: str, phrases: Sequence[str]) -> str:
    """'Ask before google_workspace.send_email when "to" ... .' / 'Ask before any mcp.stripe.*
    call when ...' / 'Ask before every google_workspace.send_email call.'"""
    glob = "*" in tool or "?" in tool
    if not phrases:
        return f"Ask before any {tool} call." if glob else f"Ask before every {tool} call."
    subject = f"any {tool} call" if glob else tool
    return f"Ask before {subject} when {' and '.join(phrases)}."


# ---------------------------------------------------------------------------
# Validation reasons (the 422 detail; shown on the page exactly as sent)
# ---------------------------------------------------------------------------

NAME_INVALID = (
    "Give the rule a name of 3 to 60 letters, digits or simple punctuation (no @ or links)."
)
NAME_TAKEN = "A rule with that name already exists."
TOOL_MISSING = (
    "Name the tool the rule covers, for example google_workspace.send_email or mcp.github.*."
)
TOOL_CHARSET = "That tool pattern can only use lower-case letters, digits, _ . - * and ?."
TOOL_TOO_LONG = "A tool pattern can be at most 120 characters."
TOOL_RUNTIME_ONLY = (
    "That pattern only matches Crawler's own tool search or tutor switch, which rules can't cover."
)
CONDITIONS_NOT_LIST = "Conditions must be a list of argument tests."
TOO_MANY_CONDITIONS = "A rule can have at most 5 conditions."
CONDITION_SHAPE = "Each condition needs an argument, an operator and a value."
ARG_INVALID = (
    "An argument is a name like to, amount or fields.text (letters, digits and _, up to 4 "
    "parts), or * for any argument."
)
ARG_RESERVED = "Arguments that start with _ are Crawler's own card details, which rules can't read."
OP_UNKNOWN = "That operator isn't one a rule can use."
VALUE_TOO_LONG = "Each value can be at most 200 characters."
PATTERN_LENGTH = "A pattern can be 1 to 100 characters."
PATTERN_INVALID = "That pattern isn't a valid regular expression."
PATTERN_OPEN_REPEATS = (
    "A pattern may use at most one open-ended repeat (*, + or {2,}); give the others a limit "
    "such as {1,20}."
)
PATTERN_NESTED = "A pattern may not repeat a group that itself repeats or has alternatives."
PATTERN_LOOKAROUND = "Patterns can't use back-references or look-ahead."
PATTERN_BIG_REPEAT = "A pattern can repeat something at most 50 times, such as {1,50}."
PATTERN_TOO_SLOW = (
    "That pattern could take too long to check on long text; give its repeats smaller limits."
)
PATTERN_UNSUPPORTED = "That pattern uses something rules can't check."
PATTERNS_UNAVAILABLE = "Patterns aren't available on this server."
NOT_A_DOMAIN_GENERIC = "One of the values is not a domain name (use a name like myco.com)."
SECRET_VALUE = "A rule can't hold what looks like a key, password, card, bank or ID number."
TOO_MANY_RULES = "There are already 50 rules; remove one first."


def needs_number(label: str) -> str:
    return f"'{label}' needs a number."


def needs_values(label: str) -> str:
    return f"'{label}' needs between 1 and 50 values."


def needs_text(label: str, *, number_ok: bool) -> str:
    if number_ok:
        return f"'{label}' needs text of 1 to 200 characters, or a number."
    return f"'{label}' needs text of 1 to 200 characters."


def not_a_domain(value: str) -> str:
    return f"'{value}' is not a domain name."


def identical_rule(name: str) -> str:
    return f"An identical rule already exists ('{name}')."


__all__ = [
    "ARG_INVALID",
    "ARG_RESERVED",
    "BuiltinText",
    "CONDITIONS_NOT_LIST",
    "CONDITION_SHAPE",
    "EXECUTE_REFUSAL",
    "MANY_RECIPIENTS",
    "MAX_CARD_NOTES",
    "MAX_REASON_NAMES",
    "NAME_INVALID",
    "NAME_TAKEN",
    "NOTE_LIST_LIMIT",
    "NOT_A_DOMAIN_GENERIC",
    "OP_UNKNOWN",
    "OUTSIDE_SHARE",
    "PATTERNS_UNAVAILABLE",
    "PATTERN_BIG_REPEAT",
    "PATTERN_INVALID",
    "PATTERN_LENGTH",
    "PATTERN_LOOKAROUND",
    "PATTERN_NESTED",
    "PATTERN_OPEN_REPEATS",
    "PATTERN_TOO_SLOW",
    "PATTERN_UNSUPPORTED",
    "SECRET_VALUE",
    "SUMMARY_LIST_LIMIT",
    "TOOL_CHARSET",
    "TOOL_MISSING",
    "TOOL_RUNTIME_ONLY",
    "TOOL_TOO_LONG",
    "TOO_MANY_CONDITIONS",
    "TOO_MANY_RULES",
    "UNAVAILABLE_NAME",
    "UNAVAILABLE_NOTE",
    "UNREADABLE_RULE_NAME",
    "UNTRUSTED_LINK",
    "UNTRUSTED_RECIPIENT",
    "VALUE_TOO_LONG",
    "builtin_off_notice",
    "card_notes",
    "card_reason",
    "condition_phrase",
    "deceptive_link_note",
    "display_arg",
    "format_number",
    "identical_rule",
    "many_recipients_note",
    "needs_number",
    "needs_text",
    "needs_values",
    "not_a_domain",
    "outside_share_note",
    "outside_share_unread_address_note",
    "outside_share_unreadable_note",
    "owner_rule_note",
    "rule_failed_note",
    "rule_removed_notice",
    "rule_summary",
    "unreadable_recipient_note",
    "untrusted_link_note",
    "untrusted_recipient_note",
    "unusual_recipient_note",
]
