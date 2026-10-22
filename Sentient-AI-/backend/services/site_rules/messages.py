"""Every sentence about site rules that the owner, the person approving a
card, or the model reads: refusals of a typed site, API errors, the Check
box's explanations, card notes, read notices and tool refusals.

Why it exists: these sentences are pinned by tests and shown on four
surfaces (the Security tab, approval cards on web/Telegram/Slack, tool
results, guard reasons), so they live in one place and never quote a URL
path, a query or anything a web page wrote. Hosts reaching here come from
``patterns.host_of`` (lower-case ASCII, IDNA) and are shortened by
``short_host`` so a card note stays under ``NOTE_LIMIT`` characters
(Telegram photo captions stop at 1024; several notes share one caption).

This module is a leaf: it imports nothing from ``services.site_rules``, so
every other module of the package can use it without an import cycle.
Callers pass plain strings (a host, a category label, a rule's site);
``snapshot`` turns a verdict into the right call.
"""

from __future__ import annotations

from typing import Mapping, Optional

# A card note (kind "site_sensitive") is at most this long, whatever the
# host (S7 §9 risk 14). The pipeline's own cap is 300 (scaffold D1).
NOTE_LIMIT = 200
# Hosts are shortened to this many characters inside a sentence, keeping
# the end: "…login.example.com" still names the site; the start is where a
# look-alike pads.
HOST_SHOWN = 64

KIND_LABELS: Mapping[str, str] = {
    "blocked": "Blocked",
    "always_ask": "Always ask",
    "trusted": "Trusted",
}

# --- What the owner typed (patterns.parse_site, 422) ---------------------
EMPTY_SITE = "Type a site, like example.com."
NOT_WEB = "Only web sites (http or https) can have a rule."
STAR_INSIDE = "Use a plain site name like example.com; tick Include subdomains to cover the rest."
UNREADABLE_SITE = "That is not a site address Crawler can read. Type a site, like example.com."
TWO_SPELLINGS = (
    "That site name has a letter (ß, ς or an invisible joiner) that browsers spell in two "
    "ways. Type the address the way the browser shows it (it starts with xn--)."
)
IP_SUBDOMAINS = "An IP address has no subdomains; untick Include subdomains."
SINGLE_LABEL = "A rule needs a full site name, like example.com."
TOO_BROAD = "{pattern} would cover a whole top-level domain. Pick a site, like example.com."
TOO_LONG = "That site name is too long: a site address has at most 253 characters."

# --- What the owner chose for it (patterns.validate_kind, 422) -----------
BAD_KIND = "Pick Blocked, Always ask or Trusted."
PROTECTED_BLOCK = (
    "{host} is used to sign in to other sites or to confirm payments, so it cannot be "
    "blocked here: blocking it would stop sign-ins and approved purchases half-way. Use "
    "Always ask instead."
)
LOOKALIKE_TRUST = (
    "This address uses look-alike characters ({host}, which reads as {reads_as}), so it "
    "cannot be marked Trusted. You can block it."
)
UNDECODABLE_TRUST = (
    "This address ({host}) cannot be read as a normal site name, so it cannot be marked "
    "Trusted. You can block it."
)

# --- The API around a rule (store / routes) ------------------------------
NO_SUCH_RULE = "No such site rule."
NO_SUCH_CATEGORY = "No such category."
DUPLICATE_RULE = "There is already a rule for {site}. Change that one instead."
TOO_MANY_RULES = "You have {limit} site rules, the most Crawler keeps. Remove some first."
SAVE_FAILED = "The rule could not be saved. Try again."

# --- Tool results the model reads (call check, observe) ------------------
BLOCKED_CALL = (
    "{host} is blocked in this Crawler's Site rules, so Crawler did not open it or act on "
    "it. The owner can change this on the Security page (Site rules)."
)
BLOCKED_PAGE = (
    "The open page is on {host}, which is blocked in this Crawler's Site rules, so Crawler "
    "will not read it or act on it. The owner can change this on the Security page (Site "
    "rules)."
)
UNAVAILABLE = (
    "Crawler could not read its Site rules just now, so it did not open this site or act on "
    "it. Try again in a moment."
)
# The same sentence browser/_shared.py says when the notice hook itself
# raises (UNAVAILABLE_TEXT): observe refuses to describe a page while no
# rules were ever read.
UNAVAILABLE_PAGE = (
    "Crawler could not read its Site rules just now, so it did not describe this page."
)
# Guard reasons: they follow the toolkits' "Refusing to open <url>: " and
# join neither SENDING_REASONS nor READ_CLICK_REASONS (S7 §4.6).
NAVIGATION_BLOCKED = "the site is blocked in this Crawler's Site rules"
NAVIGATION_UNAVAILABLE = "the owner's site rules could not be read"

# Rule names on refusals (tool results, tool_blocked rows) and page notices.
RULE_BLOCKED = "site_blocked"
RULE_ALWAYS_ASK = "site_always_ask"
RULE_UNAVAILABLE = "site_rules_unavailable"

# An act or checkout on an Always-ask site that would have run without a
# card (a standing consent; today every act is carded, so this is a
# guarantee for any future path). The reason is appended to the card's
# own; the refusal is what the executor's backstop answers instead.
ESCALATE_REASON = "Site rules mark this site Always ask, so Crawler asks before acting on it."
ESCALATE_REFUSAL = (
    "Site rules mark this site Always ask, so this needs the owner's approval first; "
    "nothing was run."
)

# --- Read notices: ``site_notice`` on an Always-ask page (observe) -------
_NOTICE_TAIL = (
    "Reading it is fine; every action on it needs the person's approval, and the approval "
    "card will say it is a sensitive site."
)
READ_NOTICE_BUILTIN = "{host} is a sensitive site ({label} list in Site rules). " + _NOTICE_TAIL
READ_NOTICE_OWNER = (
    "{host} is a sensitive site (the owner marked it Always ask in Site rules). " + _NOTICE_TAIL
)
READ_NOTICE_PROTECTED = (
    "{host} is a sign-in or payment site that Site rules treat as sensitive. " + _NOTICE_TAIL
)
READ_NOTICE_EXEMPT = (
    "{host} is blocked in Site rules but opened as part of a purchase the person approved (a "
    "bank or payment step). Do only what that purchase needs there; every action on it needs "
    "the person's approval."
)

# --- Card notes (kind "site_sensitive", severity "warn") -----------------
_LOOK = "Look at the page before you approve."
CARD_NOTE_BUILTIN = "Sensitive site: {host} is on the built-in {label} list in Site rules. " + _LOOK
CARD_NOTE_OWNER = "You marked {site} Always ask in Site rules. " + _LOOK
CARD_NOTE_OWNER_SUBDOMAINS = "You marked {site} and its subdomains Always ask in Site rules. " + _LOOK
CARD_NOTE_PROTECTED = (
    "Sensitive site: {host} is a sign-in or payment site, so Site rules ask here instead of "
    "blocking it. " + _LOOK
)
CARD_NOTE_EXEMPT = (
    "Sensitive site: {host} is blocked in Site rules and opened only as part of a purchase "
    "you approved. " + _LOOK
)

# --- The Check box on the Security tab (POST .../check) ------------------
EXPLAIN_NONE = "No rule applies to {host}: Crawler treats it like any other site."
EXPLAIN_OFF_PREFIX = "Site rules are off, so nothing applies now. If they were on: "
EFFECTS: Mapping[str, str] = {
    "blocked": "Crawler never opens it or acts on it",
    "always_ask": "Crawler asks before every action there and notes when it reads there",
    "trusted": "Crawler adds no extra warnings there (actions still need your approval)",
}
EXPLAIN_BUILTIN_DEFAULT = "{host} is on the built-in {label} list, so {effect}."
EXPLAIN_BUILTIN_SET = "{host} is on the built-in {label} list, which you set to {kind}, so {effect}."
EXPLAIN_OWNER = "Your rule for {site} ({kind}) covers {host}, so {effect}."
EXPLAIN_PROTECTED = (
    "{host} is used to sign in to other sites or to confirm payments, so Site rules never "
    "block it; Crawler asks before every action there instead."
)


def short_host(host: str, limit: int = HOST_SHOWN) -> str:
    """*host* as shown inside a sentence: whole when short, else "…" plus
    its last characters."""
    if len(host) <= limit:
        return host
    return "…" + host[-(limit - 1):]


def _capped(text: str) -> str:
    # Hosts are already shortened; only a future, longer label could get here.
    return text if len(text) <= NOTE_LIMIT else text[: NOTE_LIMIT - 1] + "…"


def kind_label(kind: Optional[str]) -> str:
    """"Blocked", "Always ask" or "Trusted"; "No rule" for anything else."""
    return KIND_LABELS.get(kind or "", "No rule")


def site_label(site: str, *, include_subdomains: bool) -> str:
    """A rule's target as the owner reads it: "example.com and subdomains"
    or "docs.example.com" (the tab's ``ruleTarget``)."""
    return f"{site} and subdomains" if include_subdomains else site


# --- Owner input -----------------------------------------------------------


def too_broad(pattern: str) -> str:
    return TOO_BROAD.format(pattern=short_host(pattern))


def protected_block(host: str) -> str:
    return PROTECTED_BLOCK.format(host=short_host(host))


def lookalike_trust(host: str, reads_as: str) -> str:
    return LOOKALIKE_TRUST.format(host=short_host(host), reads_as=short_host(reads_as))


def undecodable_trust(host: str) -> str:
    return UNDECODABLE_TRUST.format(host=short_host(host))


def duplicate_rule(site: str) -> str:
    return DUPLICATE_RULE.format(site=short_host(site))


def too_many_rules(limit: int) -> str:
    return TOO_MANY_RULES.format(limit=limit)


# --- Tool results ----------------------------------------------------------


def blocked_call(host: str) -> str:
    """The refusal of a browser or web call to a Blocked site."""
    return BLOCKED_CALL.format(host=short_host(host))


def blocked_page(host: str) -> str:
    """The refusal to read or act on a page already open on a Blocked site."""
    return BLOCKED_PAGE.format(host=short_host(host))


# --- Read notices ----------------------------------------------------------


def read_notice_builtin(host: str, label: str) -> str:
    return READ_NOTICE_BUILTIN.format(host=short_host(host), label=label)


def read_notice_owner(host: str) -> str:
    return READ_NOTICE_OWNER.format(host=short_host(host))


def read_notice_protected(host: str) -> str:
    return READ_NOTICE_PROTECTED.format(host=short_host(host))


def read_notice_exempt(host: str) -> str:
    return READ_NOTICE_EXEMPT.format(host=short_host(host))


# --- Card notes (each at most NOTE_LIMIT characters) -----------------------


def card_note_builtin(host: str, label: str) -> str:
    return _capped(CARD_NOTE_BUILTIN.format(host=short_host(host), label=label))


def card_note_owner(site: str, *, include_subdomains: bool) -> str:
    template = CARD_NOTE_OWNER_SUBDOMAINS if include_subdomains else CARD_NOTE_OWNER
    return _capped(template.format(site=short_host(site)))


def card_note_protected(host: str) -> str:
    return _capped(CARD_NOTE_PROTECTED.format(host=short_host(host)))


def card_note_exempt(host: str) -> str:
    return _capped(CARD_NOTE_EXEMPT.format(host=short_host(host)))


# --- The Check box -----------------------------------------------------------


def explanation(
    host: str,
    *,
    kind: Optional[str],
    source: Optional[str],
    label: str = "",
    category_default: bool = True,
    site: str = "",
    include_subdomains: bool = False,
    protected: bool = False,
    enabled: bool = True,
) -> str:
    """The Check box's answer: which rule applies to *host* and what Crawler
    does there. *source* is "owner", "builtin" or None; *category_default*
    is False when the owner changed the category's kind; *protected* when a
    Blocked rule was set aside on a sign-in or payment host; *enabled* False
    prefixes the answer with "Site rules are off ..."."""
    shown = short_host(host)
    if protected:
        text = EXPLAIN_PROTECTED.format(host=shown)
    elif kind is None or kind not in EFFECTS:
        text = EXPLAIN_NONE.format(host=shown)
    elif source == "owner":
        text = EXPLAIN_OWNER.format(
            site=site_label(short_host(site or host), include_subdomains=include_subdomains),
            kind=kind_label(kind),
            host=shown,
            effect=EFFECTS[kind],
        )
    elif category_default:
        text = EXPLAIN_BUILTIN_DEFAULT.format(host=shown, label=label, effect=EFFECTS[kind])
    else:
        text = EXPLAIN_BUILTIN_SET.format(
            host=shown, label=label, kind=kind_label(kind), effect=EFFECTS[kind]
        )
    return text if enabled else EXPLAIN_OFF_PREFIX + text
