"""The four built-in tool rules, on by default, each a key, its texts and a check over one write:
B1 an address seen only in content Crawler read, B2 more than 10 recipients, B3 a share, forward
or invite outside the organisation, B4 a link whose site appears only in content Crawler read.

Why it exists: decisions.md item 3 asks for a few safety rules that are on before the owner writes
any. They never apply to reads (a read sends nothing); engine.evaluate only calls them for writes.
Each check returns the card note for a broken rule, or None. They read argument values but the
notes they write name only argument names and counts (texts.py).

Which arguments hold addresses: the tool's declared ``spec.outbound.recipients`` paths when it
has any (every address inside them counts), else every leaf that IS an address or a list of them
(values.whole_addresses), never an address mentioned inside a message body. An "@" on a declared
path that no readable address accounts for (and an address-shaped list entry that does not parse)
is a recipient the rules cannot place: B1 and B3 ask and B2 counts it, so a spelling the parser
misses can never make a share or send look safe.

B4 and links written to deceive: a link whose authority holds user information, a "\\", a
percent-encoded host or odd slashes (values.Link.deceptive) may open a different site than the
one it shows, so no host the person named exempts it, and it asks even when its hosts were not
seen in read content.

B3 and the organisation: an empty domain set means no organisation is known (a personal install
on a consumer address), and B3 stays quiet; S1's first-time-recipient note does the asking there
(owner decision 8c, review FEA-SF5). None means the domains could not be read: every address then
counts as outside, so the share asks.

Connects to: values.py and texts.py; the CallView and TurnView types of engine.py (typing only,
engine imports this module).
Used by: engine.evaluate; the routes list BUILTINS for the Security page.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional

from services.security.tool_rules import texts, values

if TYPE_CHECKING:
    from services.security.tool_rules.engine import CallView, TurnView

UNTRUSTED_RECIPIENT = "untrusted_recipient"
MANY_RECIPIENTS = "many_recipients"
OUTSIDE_SHARE = "outside_share"
UNTRUSTED_LINK = "untrusted_link"
BUILTIN_KEYS: tuple[str, ...] = (UNTRUSTED_RECIPIENT, MANY_RECIPIENTS, OUTSIDE_SHARE, UNTRUSTED_LINK)

# B2: one action may address at most this many unique people before Crawler asks.
MANY_RECIPIENTS_THRESHOLD = 10

BuiltinCheck = Callable[["CallView", Optional["TurnView"], Optional[frozenset[str]]], Optional[str]]


@dataclass(frozen=True)
class BuiltinRule:
    """One built-in rule: its key (the tool_rule_builtins row key and the audit id after
    "builtin:"), what the page and cards say about it, whether it needs the turn's facts (what
    Crawler read, what the person wrote), and its check."""

    key: str
    text: texts.BuiltinText
    needs_turn: bool
    check: BuiltinCheck

    @property
    def name(self) -> str:
        return self.text.name

    @property
    def description(self) -> str:
        return self.text.description


@dataclass(frozen=True)
class Recipients:
    """Who a call is aimed at: (argument path, address) for every address the rules can read,
    and one argument path per address they cannot (an "@" no address accounts for on a declared
    recipients path, or an address-shaped list entry that does not parse). An unreadable one
    counts as a recipient the rules cannot place: B1 and B3 ask, and B2 counts it."""

    addresses: tuple[tuple[str, values.Address], ...]
    unread: tuple[str, ...]


def recipients_of(call: CallView) -> Recipients:
    """The call's recipients: the declared recipient paths when there are any (every address
    inside them, and every "@" none accounts for), else every whole-address leaf."""
    found: list[tuple[str, values.Address]] = []
    unread: list[str] = []
    if call.recipients:
        for path in call.recipients:
            for leaf in values.select(call.arguments, path):
                addresses, missed = values.address_scan(leaf)
                found.extend((path, a) for a in addresses)
                unread.extend([path] * missed)
    else:
        for path, leaf in values.leaves(call.arguments):
            if isinstance(leaf, str):
                addresses, missed = values.whole_address_scan(leaf)
                found.extend((path, a) for a in addresses)
                unread.extend([path] * missed)
    return Recipients(addresses=tuple(found), unread=tuple(unread))


def address_arguments(call: CallView) -> list[tuple[str, values.Address]]:
    """(argument path, address) for every readable address the call is aimed at."""
    return list(recipients_of(call).addresses)


def _untrusted_recipient(
    call: CallView, turn: Optional[TurnView], org_domains: Optional[frozenset[str]]
) -> Optional[str]:
    if turn is None:
        return None
    recipients = recipients_of(call)
    unusual_path: Optional[str] = None
    unusual_seen = False
    for path, address in recipients.addresses:
        if address.key in turn.owner_addresses:
            continue  # the person typed this address themselves
        if any(turn.untrusted(form) for form in address.forms):
            return texts.untrusted_recipient_note(UNTRUSTED_RECIPIENT_TEXT.name, path)
        if address.unusual and not unusual_seen:
            unusual_seen, unusual_path = True, path
    if unusual_seen:
        return texts.unusual_recipient_note(UNTRUSTED_RECIPIENT_TEXT.name, unusual_path)
    if recipients.unread:
        return texts.unreadable_recipient_note(UNTRUSTED_RECIPIENT_TEXT.name, recipients.unread[0])
    return None


def _many_recipients(
    call: CallView, turn: Optional[TurnView], org_domains: Optional[frozenset[str]]
) -> Optional[str]:
    recipients = recipients_of(call)
    count = len({address.key for _, address in recipients.addresses}) + len(recipients.unread)
    if count > MANY_RECIPIENTS_THRESHOLD:
        return texts.many_recipients_note(MANY_RECIPIENTS_TEXT.name, count)
    return None


def _outside_share(
    call: CallView, turn: Optional[TurnView], org_domains: Optional[frozenset[str]]
) -> Optional[str]:
    if not call.shares_content or not call.recipients:
        return None
    recipients = recipients_of(call)
    if not recipients.addresses and not recipients.unread:
        return None
    if org_domains is None:
        return texts.outside_share_unreadable_note(OUTSIDE_SHARE_TEXT.name)
    if not org_domains:
        return None  # no organisation known: "outside" is undefined (decision 8c)
    for path, address in recipients.addresses:
        if not values.in_domains(address.domain, org_domains):
            return texts.outside_share_note(OUTSIDE_SHARE_TEXT.name, path, sorted(org_domains))
    if recipients.unread:
        # An address the rules cannot read may be anywhere: it cannot count as inside.
        return texts.outside_share_unread_address_note(
            OUTSIDE_SHARE_TEXT.name, recipients.unread[0], sorted(org_domains)
        )
    return None


def _named_by_owner(link: values.Link, owner_hosts: frozenset[str]) -> bool:
    if link.deceptive:
        return False  # it may open a different site than the one the person named
    for host in (link.host, link.raw_host, *link.hosts):
        if host and any(parent in owner_hosts for parent in values.parent_domains(host)):
            return True
    return False


def _untrusted_link(
    call: CallView, turn: Optional[TurnView], org_domains: Optional[frozenset[str]]
) -> Optional[str]:
    if turn is None:
        return None
    deceptive_path: Optional[str] = None
    deceptive_seen = False
    for path, leaf in values.leaves(call.arguments):
        if not isinstance(leaf, str) or ":" not in leaf:
            continue
        for link in values.links_in(leaf):
            if _named_by_owner(link, turn.owner_hosts):
                continue
            lookups = [link.url, link.raw_host, link.host, *link.hosts]
            if any(turn.untrusted(item) for item in lookups if item):
                return texts.untrusted_link_note(UNTRUSTED_LINK_TEXT.name, path)
            if link.deceptive and not deceptive_seen:
                deceptive_seen, deceptive_path = True, path
    if deceptive_seen:
        # A link written to show one site and open another asks whoever wrote it: nothing the
        # person typed can vouch for the site it really opens.
        return texts.deceptive_link_note(UNTRUSTED_LINK_TEXT.name, deceptive_path)
    return None


UNTRUSTED_RECIPIENT_TEXT = texts.UNTRUSTED_RECIPIENT
MANY_RECIPIENTS_TEXT = texts.MANY_RECIPIENTS
OUTSIDE_SHARE_TEXT = texts.OUTSIDE_SHARE
UNTRUSTED_LINK_TEXT = texts.UNTRUSTED_LINK

BUILTINS: tuple[BuiltinRule, ...] = (
    BuiltinRule(UNTRUSTED_RECIPIENT, UNTRUSTED_RECIPIENT_TEXT, True, _untrusted_recipient),
    BuiltinRule(MANY_RECIPIENTS, MANY_RECIPIENTS_TEXT, False, _many_recipients),
    BuiltinRule(OUTSIDE_SHARE, OUTSIDE_SHARE_TEXT, False, _outside_share),
    BuiltinRule(UNTRUSTED_LINK, UNTRUSTED_LINK_TEXT, True, _untrusted_link),
)
_BY_KEY = {rule.key: rule for rule in BUILTINS}


def builtin(key: str) -> Optional[BuiltinRule]:
    """The built-in rule with this key, or None (an unknown key in the table is ignored)."""
    return _BY_KEY.get(key)


__all__ = [
    "BUILTINS",
    "BUILTIN_KEYS",
    "BuiltinRule",
    "MANY_RECIPIENTS",
    "MANY_RECIPIENTS_THRESHOLD",
    "OUTSIDE_SHARE",
    "Recipients",
    "UNTRUSTED_LINK",
    "UNTRUSTED_RECIPIENT",
    "address_arguments",
    "builtin",
    "recipients_of",
]
