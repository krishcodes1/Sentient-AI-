"""The site-rules call check (security S7): slot 3 of the pre-dispatch call
checks (tool rules, MCP pins, **site rules**, outbound, file reputation). A
browser or web page call, a page watch or a web page saved to the knowledge
base on a Blocked site is refused before any card; an act or checkout on an
Always-ask site never runs without a card and its card carries a
"sensitive site" note.

Why it exists: the browser guard stops navigations, but a call must be
judged before anything starts (no browser launched for a Blocked site, no
card for an act the rules forbid), a card parked before a rule changed must
be refused at approval, and a read of a page already open on a Blocked site
must be refused too, at every stage (turn, approve, execute).

Which site a call is about:

- ``web.fetch_page``, ``web.screenshot`` and ``browser.read`` ``open``: the
  ``url`` argument (the web toolkit's resolver and the guard judge every
  later hop);
- ``watch.create`` and a ``knowledge.add`` that saves a web page (it has a
  ``url``): the ``url`` argument, so the call is refused before its card
  (their own resolvers judge every hop, and every later background check
  of a watch). A ``knowledge.add`` of a note, an upload or a connected
  app's item opens no site and is not judged;
- ``browser.read``'s actions on the open page: the user's last observed
  page (``page_origin``);
- ``browser.act`` / ``browser.checkout``: at approval and execution of a
  call a person approved, the page the card was made from (``_page`` /
  ``_checkout`` ``origin`` in the stored card arguments); otherwise the
  user's last observed page. A model-supplied ``_page`` is never trusted
  (the act toolkit refuses it anyway).

Verdicts: Blocked -> ``Refuse("site_blocked")`` with the pipeline's
``site_rule_blocked`` audit row (kinds and a keyed host hash only);
Always ask on an act or checkout -> a ``site_sensitive`` warn note when the
call goes to a card (or a person approved it), else an escalation, so it
never runs without one; anything else -> Allow. Rules that were never read
-> ``Refuse("site_rules_unavailable")`` for these tools only (fail closed).
The switch off -> Allow. The check never rewrites arguments and never
raises on purpose; an unreadable page memory is left to the pipeline's
fail-closed handling rather than read as "no page".

Connects to: services/security/call_checks.py (the pipeline),
services/site_rules/service.py (``SiteRulesService.call_check`` builds it),
main.py (``page_origin`` reads the browser toolkits' page memory).
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional, Protocol

from core.config import settings
from services.security.call_checks import (
    ALLOW,
    CallFacts,
    Escalate,
    Note,
    Refuse,
    SecurityNote,
    Verdict,
)
from services.site_rules import messages
from services.site_rules.hooks import RulesSource
from services.site_rules.patterns import host_hash
from services.site_rules.snapshot import SiteRuleSnapshot, SiteVerdict, card_note


class CheckedRules(RulesSource, Protocol):
    """What the check reads from ``SiteRulesService``: a snapshot fresh
    enough to judge a call by (None when none could ever be read)."""

    async def ensure_fresh(self) -> Optional[SiteRuleSnapshot]: ...


CHECK_NAME = "site_rules"
SITE_RULES_POLICY = "site_rules"
NOTE_KIND = "site_sensitive"
AUDIT_EVENT = "site_rule_blocked"

# browser.read actions that read or touch the page already open; "open"
# names its own URL, and "back", "tabs", "switch" and "note" move away or
# touch no page (the guard and observe judge where they land).
_OPEN_PAGE_ACTIONS = frozenset(
    {"snapshot", "find", "text", "scroll", "click", "wait", "screenshot", "handoff"}
)
_URL_TOOLS = frozenset({"web.fetch_page", "web.screenshot", "watch.create", "knowledge.add"})
_WRITE_TOOLS = {"browser.act": "_page", "browser.checkout": "_checkout"}
# Judged only when it saves a web page; its other sources open no site.
_WEB_IMPORT = "knowledge.add"


class SiteRulesCallCheck:
    """S7's place in the call checks (see the module docstring)."""

    name = CHECK_NAME
    policy = SITE_RULES_POLICY
    stages: frozenset[str] = frozenset({"turn", "approve", "execute"})
    timeout_s = 1.0
    TOOLS = frozenset(
        {
            "browser.read",
            "browser.act",
            "browser.checkout",
            "web.fetch_page",
            "web.screenshot",
            "watch.create",
            _WEB_IMPORT,
        }
    )

    def __init__(
        self, service: CheckedRules, *, page_origin: Callable[[str], Optional[str]]
    ) -> None:
        self._service = service
        self._page_origin = page_origin

    def applies_to(self, call: CallFacts) -> bool:
        """The browser and web page tools, watch.create and a knowledge.add
        of a web page; nothing else is ever awaited."""
        if call.canonical == _WEB_IMPORT:
            arguments = call.arguments if isinstance(call.arguments, Mapping) else {}
            return arguments.get("url") is not None
        return call.canonical in self.TOOLS

    async def check(self, call: CallFacts) -> Verdict:
        """Refuse a Blocked site, note (or escalate) an Always-ask one."""
        tool = call.canonical
        if not self.applies_to(call):
            return ALLOW
        snapshot = await self._service.ensure_fresh()
        if snapshot is None:
            return Refuse(messages.RULE_UNAVAILABLE, messages.UNAVAILABLE)
        if not snapshot.enabled:
            return ALLOW
        arguments: Mapping[str, Any] = call.arguments if isinstance(call.arguments, Mapping) else {}
        if tool in _URL_TOOLS:
            host, verdict = snapshot.judge(_text(arguments.get("url")))
            return self._refuse_blocked(call, host, verdict, messages.blocked_call(host))
        if tool == "browser.read":
            action = arguments.get("action")
            if action == "open":
                host, verdict = snapshot.judge(_text(arguments.get("url")))
                return self._refuse_blocked(call, host, verdict, messages.blocked_call(host))
            if action in _OPEN_PAGE_ACTIONS:
                host, verdict = snapshot.judge(self._last_page(call))
                return self._refuse_blocked(call, host, verdict, messages.blocked_page(host))
            return ALLOW
        host, verdict = snapshot.judge(self._acted_on(call, arguments))
        if not host:
            return ALLOW  # no observation, about:blank, an error page: the toolkit refuses
        if verdict.kind == "blocked":
            return self._refuse_blocked(call, host, verdict, messages.blocked_page(host))
        if verdict.kind == "always_ask":
            text = card_note(host, verdict) or messages.ESCALATE_REASON
            note = SecurityNote(NOTE_KIND, "warn", text)
            if call.will_card or call.approved:
                return Note((note,))
            return Escalate(
                (note,),
                reason=messages.ESCALATE_REASON,
                rule=messages.RULE_ALWAYS_ASK,
                refusal_text=messages.ESCALATE_REFUSAL,
            )
        return ALLOW

    def _last_page(self, call: CallFacts) -> str:
        """The user's last observed page. A page memory that raises is not
        answered here: the exception reaches the pipeline, which fails closed
        by stage (S7 §4.5: the check catches nothing it cannot answer)."""
        return _text(self._page_origin(call.user_id))

    def _acted_on(self, call: CallFacts, arguments: Mapping[str, Any]) -> str:
        """The origin an act or checkout acts on: the card's bound page once
        a person approved it (approve and execute), else the last observed
        page. A bound page the card does not carry falls back to the last
        observed one (stricter than judging nothing)."""
        if call.approved and call.stage in ("approve", "execute"):
            bound = arguments.get(_WRITE_TOOLS[call.canonical])
            if isinstance(bound, Mapping):
                origin = _text(bound.get("origin"))
                if origin:
                    return origin
        return self._last_page(call)

    def _refuse_blocked(
        self, call: CallFacts, host: str, verdict: SiteVerdict, message: str
    ) -> Verdict:
        if verdict.kind != "blocked":
            return ALLOW
        self._service.record_hit(
            user_id=call.user_id,
            host=host,
            kind="blocked",
            where="call",
            verdict=verdict,
            audit=False,  # the pipeline writes this refusal's row
        )
        return Refuse(
            messages.RULE_BLOCKED,
            message,
            audit_event=AUDIT_EVENT,
            audit_facts={
                "where": "call",
                "tool": call.canonical,
                "source": verdict.source,
                "category": verdict.category,
                "host_hash": host_hash(host, settings.ENCRYPTION_KEY),
                "kind": "blocked",
            },
        )


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""
