"""The owner's site rules where Crawler's browser and its other page
fetchers meet the network: the per-user hook the browser guard and the
observe step read, and the resolver wrapper the guarded client calls on
every hop (the web toolkit, page watches, both when one is saved and every
background check, and web pages saved to the knowledge base).

Why it exists: the call check refuses a call that names a Blocked site, but
a page can still link, redirect, open a popup or embed a frame into one,
and a ``web.fetch_page`` can be redirected into one. A page watch saved
before its site was Blocked is fetched in the background with no call at
all. These two seams judge every such hop against the same in-memory
snapshot the call check reads, with no database read and no lock (the
snapshot is immutable and swapped whole), so a rule the owner adds applies
to the very next navigation of every open session.

Failure policy (S7 §4.8): no snapshot was ever loaded -> the guard hook
stops every navigation and observe describes no web page (fail closed);
the web toolkit's resolver lets the hop through (the call check already
refused the call). The resolver given to page watches and knowledge
imports is built with ``fail_closed=True`` and refuses instead: a
background check has no call check in front of it. The guard and observe
also catch anything these hooks raise and fail closed with their own named
reasons.

Connects to: services/site_rules/service.py (the snapshot and the hits),
services/tools/browser/guard.py (``SiteRuleHook``, ``PageNotice``,
``EgressHooks``), services/tools/browser/_shared.py (observe),
services/tools/net.py (``AddressResolver``, ``OwnerRuleBlocked``), main.py
(which fetcher gets which resolver).
"""

from __future__ import annotations

from typing import Literal, Optional, Protocol

import structlog

from services.site_rules import messages
from services.site_rules.patterns import MAX_HOST_CHARS, RuleKind, host_of
from services.site_rules.snapshot import SiteRuleSnapshot, SiteVerdict, read_notice
from services.tools.browser.guard import PageNotice
from services.tools.net import AddressResolver, OwnerRuleBlocked

logger = structlog.get_logger(__name__)

# Where a hit happened, as the Security tab's recent list shows it.
Where = Literal["navigation", "read", "call", "web"]


class RulesSource(Protocol):
    """What the hooks read from ``SiteRulesService``: its current snapshot
    (None until one was loaded) and where hits are recorded."""

    @property
    def snapshot(self) -> Optional[SiteRuleSnapshot]: ...

    def record_hit(
        self,
        *,
        user_id: Optional[str],
        host: str,
        kind: RuleKind,
        where: Where,
        verdict: SiteVerdict,
        audit: bool,
    ) -> None: ...


class SiteRuleGuardHook:
    """One user's view of the site rules for the browser guard
    (``guard.SiteRuleHook``) and the observe step. Pure and in memory: each
    call reads the service's current snapshot, so it never goes stale."""

    __slots__ = ("_service", "_user_id")

    def __init__(self, service: RulesSource, user_id: str) -> None:
        self._service = service
        self._user_id = user_id

    @property
    def user_id(self) -> str:
        return self._user_id

    def navigation_reason(self, url: str, *, exempt: bool) -> Optional[str]:
        """Why a navigation to *url* must stop (a Blocked site, or no rules
        were ever loaded), else None. *exempt* is True inside an approved
        checkout's window, where only protected and bank hosts are set
        aside (scaffold A32)."""
        snapshot = self._service.snapshot
        if snapshot is None:
            return messages.NAVIGATION_UNAVAILABLE
        host, verdict = snapshot.judge(url, exempt=exempt)
        if verdict.kind != "blocked":
            return None
        self._service.record_hit(
            user_id=self._user_id,
            host=host,
            kind="blocked",
            where="navigation",
            verdict=verdict,
            audit=True,
        )
        return messages.NAVIGATION_BLOCKED

    def page_notice(self, url: str, *, exempt: bool) -> Optional[PageNotice]:
        """What observe must say about the page open on *url*: ``blocked``
        (blank it, describe nothing), ``always_ask`` (describe it with a
        notice), else None. A page with no web host (``about:blank``, an
        error page) has nothing to judge."""
        snapshot = self._service.snapshot
        if snapshot is None:
            # Any page with a web host, wrapped ("blob:", "view-source:") or
            # not, is refused while no rules were ever read.
            if not host_of(url):
                return None
            return PageNotice("blocked", messages.RULE_UNAVAILABLE, messages.UNAVAILABLE_PAGE)
        host, verdict = snapshot.judge(url, exempt=exempt)
        if verdict.kind == "blocked":
            self._service.record_hit(
                user_id=self._user_id,
                host=host,
                kind="blocked",
                where="read",
                verdict=verdict,
                audit=True,
            )
            return PageNotice("blocked", messages.RULE_BLOCKED, messages.blocked_page(host))
        if verdict.kind == "always_ask":
            text = read_notice(host, verdict)
            if text is None:  # pragma: no cover - read_notice answers every always_ask verdict
                return None
            self._service.record_hit(
                user_id=self._user_id,
                host=host,
                kind="always_ask",
                where="read",
                verdict=verdict,
                audit=True,
            )
            return PageNotice("always_ask", messages.RULE_ALWAYS_ASK, text)
        return None


def wrap_resolver(
    service: RulesSource, inner: AddressResolver, *, fail_closed: bool = False
) -> AddressResolver:
    """*inner*, refusing every Blocked host before a socket opens: the
    guarded client calls its resolver on every hop (each redirect
    included), research asks it before reading a source, screenshot asks it
    for the first and the final URL, and watch.create asks it before a
    watch is saved. Never exempt: no checkout runs through these fetchers.
    A host no rule blocks goes to *inner* unchanged. Logs the host only,
    never a path or a query.

    The refusal is ``OwnerRuleBlocked`` with S7's own sentence. With
    *fail_closed*, rules that were never read refuse every URL too (the
    "could not read its Site rules" sentence); without it they let the hop
    through, for the web toolkit, whose call check has already refused."""

    def resolve(url: str) -> tuple[str, ...]:
        snapshot = service.snapshot
        if snapshot is None and fail_closed:
            logger.warning("web_site_rules_unavailable")
            raise OwnerRuleBlocked(messages.UNAVAILABLE)
        if snapshot is not None:
            host, verdict = snapshot.judge(url)
            if verdict.kind == "blocked":
                logger.warning(
                    "web_site_rule_blocked",
                    host=messages.short_host(host, MAX_HOST_CHARS),
                    source=verdict.source,
                )
                service.record_hit(
                    user_id=None,
                    host=host,
                    kind="blocked",
                    where="web",
                    verdict=verdict,
                    audit=False,
                )
                raise OwnerRuleBlocked(messages.blocked_call(host))
        return inner(url)

    return resolve
