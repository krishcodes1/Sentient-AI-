"""The rules as one immutable view: which rule applies to a host, whether a
navigation must stop, and the sentence a card, a read or the Check box
shows for it.

Why it exists: the browser guard asks on every navigation, redirect hop and
frame, the web toolkit's resolver on every hop, and the call check on every
browser or web call. They must agree and must not touch the database, so
the service builds a ``SiteRuleSnapshot`` from the rows after each owner
change (and on a timer), swaps the reference atomically, and every reader
asks this object: a few dict probes per lookup, no lock, no I/O, and never
an exception for a bad host.

Precedence, written down once (S7 §4.2):

1. the switch is off -> no verdict for any host;
2. an owner host rule that covers the host wins, whatever the built-in list
   says; among owner rules the exact host wins, then the longest "*."
   suffix ("Trust docs.example.com" beats "Block *.example.com");
3. else a built-in entry -> its category's kind (the owner's category
   override, else Always ask);
4. else no verdict;
5. a Blocked result on a protected sign-in, CAPTCHA or payment host is
   answered as Always ask with ``protected=True`` (the API already refuses
   such rules; this catches rows written any other way).

Where two rules reach a host equally (a site on two built-in lists, two
stored rows that normalise to one pattern) the stricter kind wins:
Blocked over Always ask over Trusted.

Inside an approved checkout's order window or its 3-D Secure hand-off
(``exempt=True``) a Blocked verdict is set aside only on a protected host
or a host on the built-in "banks" list, where card issuers' 3-D Secure
pages live; it is answered as Always ask with ``exempted=True``. An owner
Blocked rule on any other host still blocks inside the window (scaffold
A32, review SEC-F4).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Literal, Mapping, Optional

from services.site_rules import messages
from services.site_rules.patterns import (
    PatternIndex,
    RuleKind,
    as_kind,
    host_of,
    is_protected_host,
    is_wildcard,
    normalise_pattern,
    pattern_base,
    stricter,
    strictness,
)
from services.site_rules.sensitive_sites import (
    CATEGORIES,
    CATEGORY_KEYS,
    CHECKOUT_EXEMPT_CATEGORY,
    DEFAULT_CATEGORY_KIND,
    category,
)


@dataclass(frozen=True)
class SiteVerdict:
    kind: Optional[RuleKind]  # None: no rule applies (an ordinary site)
    source: Optional[Literal["owner", "builtin"]] = None
    pattern: Optional[str] = None  # the matching pattern
    category: Optional[str] = None  # built-in category key when source == "builtin"
    rule_id: Optional[str] = None  # owner row id when source == "owner"
    protected: bool = False  # a Blocked verdict was downgraded on a protected host
    # A Blocked verdict set aside inside an approved checkout's window (A32);
    # the kind is then "always_ask", so the page opens and still carries a notice.
    exempted: bool = False


NO_VERDICT = SiteVerdict(None)


@dataclass(frozen=True)
class OwnerRule:
    id: str
    pattern: str
    kind: RuleKind


def _stricter_rule(held: OwnerRule, new: OwnerRule) -> OwnerRule:
    return new if stricter(held.kind, new.kind) != held.kind else held


def _merge_keys(held: tuple[str, ...], new: tuple[str, ...]) -> tuple[str, ...]:
    return held + tuple(key for key in new if key not in held)


# The built-in list does not change at run time: one index for the process.
_BUILTIN: PatternIndex[tuple[str, ...]] = PatternIndex(
    ((site, (c.key,)) for c in CATEGORIES for site in c.sites), merge=_merge_keys
)
_BUILTIN_PATTERNS: tuple[str, ...] = tuple(_BUILTIN.patterns())
_exempt_category = category(CHECKOUT_EXEMPT_CATEGORY)
_CHECKOUT_EXEMPT: PatternIndex[bool] = PatternIndex(
    (site, True) for site in (_exempt_category.sites if _exempt_category else ())
)


def builtin_entry(host: str) -> Optional[tuple[str, tuple[str, ...]]]:
    """(pattern, category keys) of the built-in entry covering *host*, or None,
    whatever the categories' kinds are."""
    return _BUILTIN.lookup(host_of(host))


def overlapping_builtin(pattern: str) -> Optional[str]:
    """A built-in entry *pattern* overlaps (the routes' ``overrides_builtin``),
    or None. Exact patterns are answered by one lookup; a "*." pattern also
    looks for built-in entries inside it."""
    normalised = normalise_pattern(pattern)
    if not normalised:
        return None
    # A built-in entry covers the rule's own site...
    hit = _BUILTIN.lookup(pattern_base(normalised))
    if hit is not None:
        return hit[0]
    # ...or the rule's "*." covers a built-in site (both sides are already
    # normalised, so a suffix test is enough; one GET asks this per rule).
    if is_wildcard(normalised):
        inside = "." + pattern_base(normalised)
        for builtin in _BUILTIN_PATTERNS:
            if pattern_base(builtin).endswith(inside):
                return builtin
    return None


def exempt_in_checkout_window(host: str) -> bool:
    """Whether a Blocked verdict on *host* is set aside inside an approved
    checkout's order window or 3-D Secure hand-off: a protected host, or a
    host on the built-in "banks" list (whoever's rule blocked it)."""
    return _exempt_host(host_of(host))


def _exempt_host(host: str) -> bool:
    """``exempt_in_checkout_window`` for a host ``host_of`` already read
    (read once, so the exemption is judged on the host the rule lookup saw)."""
    if not host:
        return False
    return is_protected_host(host) or _CHECKOUT_EXEMPT.lookup(host) is not None


class SiteRuleSnapshot:
    """Immutable view of every rule, built once per refresh; O(labels) per
    lookup, never raises on a bad host."""

    __slots__ = ("enabled", "loaded_at", "skipped", "_owner", "_rules", "_category_kinds")

    def __init__(
        self,
        *,
        owner: PatternIndex[OwnerRule],
        rules: tuple[OwnerRule, ...],
        category_kinds: Mapping[str, RuleKind],
        enabled: bool,
        loaded_at: float,
        skipped: int = 0,
    ) -> None:
        self.enabled = enabled
        self.loaded_at = loaded_at
        # Rows that could not be read as a rule (a bad pattern or kind):
        # the service logs the count; they cover no host.
        self.skipped = skipped
        self._owner = owner
        self._rules = rules
        self._category_kinds = dict(category_kinds)

    @classmethod
    def build(
        cls,
        owner_rules: Iterable[OwnerRule],
        category_kinds: Mapping[str, Any],
        *,
        enabled: bool,
        loaded_at: float,
    ) -> SiteRuleSnapshot:
        """The snapshot for these rows. Patterns are normalised again (rows
        may have been written by hand); a row that is not a rule is skipped
        and counted; a category key or kind that is not one is ignored (the
        category keeps its default)."""
        rules: list[OwnerRule] = []
        skipped = 0
        for rule in owner_rules:
            pattern = normalise_pattern(getattr(rule, "pattern", None))
            kind = as_kind(getattr(rule, "kind", None))
            if not pattern or kind is None:
                skipped += 1
                continue
            rules.append(OwnerRule(id=str(rule.id), pattern=pattern, kind=kind))
        kinds: dict[str, RuleKind] = {}
        for key, value in category_kinds.items():
            kind = as_kind(value)
            if key in CATEGORY_KEYS and kind is not None:
                kinds[key] = kind
        owner = PatternIndex(((rule.pattern, rule) for rule in rules), merge=_stricter_rule)
        return cls(
            owner=owner,
            rules=tuple(rules),
            category_kinds=kinds,
            enabled=enabled,
            loaded_at=loaded_at,
            skipped=skipped,
        )

    @property
    def rules(self) -> tuple[OwnerRule, ...]:
        """The owner's host rules as read (normalised, bad rows left out)."""
        return self._rules

    def category_kind(self, key: str) -> RuleKind:
        """The kind a built-in category applies now (its override, else Always ask)."""
        return self._category_kinds.get(key, DEFAULT_CATEGORY_KIND)

    def category_overridden(self, key: str) -> bool:
        """Whether the owner set *key* to something other than the default."""
        return self.category_kind(key) != DEFAULT_CATEGORY_KIND

    def verdict(self, host: str) -> SiteVerdict:
        """Which rule applies to *host* (a host or a URL): an owner rule first
        (exact, then the longest "*." suffix), else the built-in list with
        its category's kind; Blocked never on a protected host."""
        return self._verdict(host_of(host))

    def would_apply(self, host: str) -> SiteVerdict:
        """The verdict *host* would get with the switch on (the Check box
        explains the rules even while they are off)."""
        return self._verdict(host_of(host), switch=False)

    def explain(self, host: str) -> str:
        """The Check box's sentence for *host*: which rule would apply and what
        Crawler does there, prefixed "Site rules are off ..." while the switch
        is off."""
        verdict = self.would_apply(host)
        overridden = verdict.category is not None and self.category_overridden(verdict.category)
        return explanation_for(
            host, verdict, enabled=self.enabled, category_default=not overridden
        )

    def _verdict(self, host: str, *, switch: bool = True) -> SiteVerdict:
        if (switch and not self.enabled) or not host:
            return NO_VERDICT
        owner = self._owner.lookup(host)
        if owner is not None:
            pattern, rule = owner
            verdict = SiteVerdict(rule.kind, source="owner", pattern=pattern, rule_id=rule.id)
        else:
            builtin = _BUILTIN.lookup(host)
            if builtin is None:
                return NO_VERDICT
            pattern, keys = builtin
            # max() keeps the first of equals, so list order breaks ties.
            key = max(keys, key=lambda k: strictness(self.category_kind(k)))
            verdict = SiteVerdict(
                self.category_kind(key), source="builtin", pattern=pattern, category=key
            )
        if verdict.kind == "blocked" and is_protected_host(host):
            return replace(verdict, kind="always_ask", protected=True)
        return verdict

    def with_enabled(self, enabled: bool) -> SiteRuleSnapshot:
        """The same rules under another switch position (the service re-reads
        the switch on every call without re-reading the rows)."""
        if enabled == self.enabled:
            return self
        return SiteRuleSnapshot(
            owner=self._owner,
            rules=self._rules,
            category_kinds=self._category_kinds,
            enabled=enabled,
            loaded_at=self.loaded_at,
            skipped=self.skipped,
        )

    def judge(self, url: str, *, exempt: bool = False) -> tuple[str, SiteVerdict]:
        """(host, verdict) for a navigation to, or a page open on, *url*: the
        host read once (``host_of``, "" when there is none, and not read at
        all while the switch is off) and the verdict ``page_verdict`` gives.
        The guard hook, the resolver and the call check use this, so the
        sentence they write names the host the verdict was for."""
        if not self.enabled:
            return "", NO_VERDICT
        host = host_of(url)
        verdict = self._verdict(host)
        if exempt and verdict.kind == "blocked" and _exempt_host(host):
            return host, replace(verdict, kind="always_ask", exempted=True)
        return host, verdict

    def page_verdict(self, url: str, *, exempt: bool) -> SiteVerdict:
        """The verdict for a navigation to, or a page open on, *url*. With
        *exempt* (an approved checkout's order window or its 3-D Secure
        hand-off) a Blocked verdict on a protected or built-in bank host is
        answered as Always ask with ``exempted=True``."""
        return self.judge(url, exempt=exempt)[1]

    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]:
        """messages.NAVIGATION_BLOCKED when *url*'s host is Blocked, else None.
        With *exempt* (an approved checkout's order window or its 3-D Secure
        hand-off) a Blocked verdict is skipped only for a host that is
        protected (PROTECTED_PATTERNS, Appendix B) or in the built-in "banks"
        category; an owner Blocked rule on any other host still blocks inside
        the window (review SEC-F4, scaffold A32: the exemption exists so a
        category-level Block cannot stop a bank's 3-D Secure page, not to
        switch Blocked off for every host). Always ask never stops a
        navigation."""
        if self.page_verdict(url, exempt=exempt).kind == "blocked":
            return messages.NAVIGATION_BLOCKED
        return None

    def __repr__(self) -> str:
        return (
            f"<SiteRuleSnapshot enabled={self.enabled} rules={len(self._rules)} "
            f"categories={self._category_kinds} skipped={self.skipped}>"
        )


# --- Sentences for a verdict -------------------------------------------------


def category_label(key: Optional[str]) -> str:
    """The built-in category's label ("Banks and money accounts"), or ""."""
    found = category(key) if key else None
    return found.label if found else ""


def _shown(host: str) -> str:
    return host_of(host) or host


def read_notice(host: str, verdict: SiteVerdict) -> Optional[str]:
    """The ``site_notice`` a read result carries for an Always-ask page; None
    for any other verdict (Blocked pages are refused, not described)."""
    if verdict.kind != "always_ask":
        return None
    shown = _shown(host)
    if verdict.exempted:
        return messages.read_notice_exempt(shown)
    if verdict.protected:
        return messages.read_notice_protected(shown)
    if verdict.source == "builtin":
        return messages.read_notice_builtin(shown, category_label(verdict.category))
    return messages.read_notice_owner(shown)


def card_note(host: str, verdict: SiteVerdict) -> Optional[str]:
    """The ``site_sensitive`` card note (at most messages.NOTE_LIMIT
    characters) for an act on an Always-ask site; None for any other verdict
    (Trusted and unlisted sites add no note, so pinned card reasons stay)."""
    if verdict.kind != "always_ask":
        return None
    shown = _shown(host)
    if verdict.exempted:
        return messages.card_note_exempt(shown)
    if verdict.protected:
        return messages.card_note_protected(shown)
    if verdict.source == "builtin":
        return messages.card_note_builtin(shown, category_label(verdict.category))
    pattern = verdict.pattern or shown
    return messages.card_note_owner(pattern_base(pattern), include_subdomains=is_wildcard(pattern))


def explanation_for(
    host: str, verdict: SiteVerdict, *, enabled: bool, category_default: bool = True
) -> str:
    """The Check box's sentence for *host* under *verdict* (what would apply
    with the switch on), prefixed with "Site rules are off ..." when
    *enabled* is False. *category_default* is False when the owner changed
    the verdict's category. ``SiteRuleSnapshot.explain`` fills both in."""
    pattern = verdict.pattern or ""
    return messages.explanation(
        _shown(host),
        kind=verdict.kind,
        source=verdict.source,
        label=category_label(verdict.category),
        category_default=category_default,
        site=pattern_base(pattern),
        include_subdomains=is_wildcard(pattern),
        protected=verdict.protected,
        enabled=enabled,
    )
