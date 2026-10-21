"""The tool-rules call check (security S9): slot 1 of the pre-dispatch call checks. A call that
breaks a built-in or owner rule on its arguments raises an approval card that names the rule
(decisions 3); it never hard-fails, and it never lets a call skip a card.

Why it exists: Progent-style argument rules must apply wherever a call can run without a person
looking at it (the auto tier, standing consent, weekly approvals, unattended runs). The check
answers by stage (scaffold D1/D2):

- "turn" (inside a turn, ``call.turn`` set): the switch and the rule snapshot are read once per
  turn and kept in the turn's scratch with what the person wrote and what Crawler only read
  (context.turn_view, built on the first call of the turn); every rule may apply. A hit is
  Escalate: an auto-run call becomes a card, a call already going to a card gets the rule's
  name on its reason and one note per rule.
- "turn" without turn facts (``AgentRuntime.park_card``: a mail or upload card parked outside a
  turn): the switch is read directly, and the rules that need the turn (B1, B4) are skipped,
  as at "execute". Never raises because the turn is missing.
- "approve": Allow, before touching the store (a person's tap satisfies every "ask" rule).
- "execute" (the executor's backstop): a call a person approved and every READ go on
  untouched (internal reads such as the briefing's must never break); otherwise B2, B3 and the
  owner rules are checked again, and a hit answers Escalate, which the pipeline turns into a
  requires_approval refusal with a fixed text that never names the owner's rules.

Failure policy (S9 §4.9): a switch that cannot be read counts as on; an unreadable store makes
every write ask (reads go on, logged once per turn); a rule that raises counts as broken; an
organisation-domain lookup that raises makes every share ask. Organisation domains are read
only for a call that shares content, once per turn, and at "execute" from a small cache (256
users, 5 minutes).

Connects to: services/security/call_checks.py (the pipeline and its types), engine.py (the
evaluator), context.py (the turn's view), texts.py (the card texts), store.py, S1's
``OrgDomains.for_user`` (``org_domains``) and the owner's switch (``enabled``), both from main.py.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.security.call_checks import (
    ALLOW,
    CallFacts,
    Escalate,
    SecurityNote,
    Severity,
    Verdict,
)
from services.security.tool_rules import context, engine, texts
from services.security.tool_rules.engine import RuleHit, RuleSnapshot, TurnView
from services.security.tool_rules.store import ToolRuleStore

logger = structlog.get_logger(__name__)

TOOL_RULES_CHECK = "tool_rules"  # the check's name in the pipeline and on audit rows
TOOL_RULES_POLICY = "tool_rules"  # policy recorded on escalation/refusal rows
NOTE_KIND = "tool_rule"
NOTE_SEVERITY: Severity = "warn"
# At "execute" the calling user's organisation domains are kept this long, for this many users.
ORG_DOMAINS_TTL_S = 300.0
ORG_DOMAINS_CACHE_SIZE = 256

_UNSET: Any = object()


@dataclass
class _TurnState:
    """What the check keeps for one turn in ``TurnFacts.scratch["tool_rules"]``."""

    enabled: Optional[bool] = None
    snapshot: Optional[RuleSnapshot] = None
    view: Optional[TurnView] = None
    org_domains: Any = _UNSET  # Optional[frozenset[str]] once read
    warned_unavailable: bool = False


def verdict_for(hits: tuple[RuleHit, ...]) -> Verdict:
    """Allow for no hits; else Escalate naming every broken rule: one warn note per rule (at
    most five, then "and N more tool rules"), the reason sentence naming at most three, the
    rule ids for audit rows, and the executor's fixed refusal text."""
    if not hits:
        return ALLOW
    notes = tuple(
        SecurityNote(NOTE_KIND, NOTE_SEVERITY, text)
        for text in texts.card_notes([hit.note for hit in hits])
    )
    return Escalate(
        notes=notes,
        reason=texts.card_reason([hit.name for hit in hits]),
        rule=engine.rule_ids(hits),
        refusal_text=texts.EXECUTE_REFUSAL,
        names_rule=True,
    )


class ToolRulesCheck:
    """The S9 call check: first in the pipeline. Answers Allow or Escalate (never Refuse);
    Allow at the approve stage; at the execute stage Escalate only for a call no person
    approved, which the pipeline turns into a requires_approval refusal."""

    name = TOOL_RULES_CHECK
    policy = TOOL_RULES_POLICY
    stages: frozenset[str] = frozenset({"turn", "approve", "execute"})
    timeout_s = 1.0

    def __init__(
        self,
        store: ToolRuleStore,
        *,
        enabled: Optional[Callable[[], Awaitable[bool]]] = None,
        org_domains: Optional[Callable[[str], Awaitable[frozenset[str]]]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._enabled = enabled
        self._org_domains = org_domains
        self._clock = clock
        self._org_cache: OrderedDict[str, tuple[float, frozenset[str]]] = OrderedDict()

    @property
    def store(self) -> ToolRuleStore:
        return self._store

    def applies_to(self, call: CallFacts) -> bool:
        """Every call the runtime does not answer itself (tools.find, tutor.*), except where the
        answer is already Allow with no I/O: the approve stage, and at the executor a call a
        person approved or a READ."""
        if not engine.applies_to(call.canonical):
            return False
        if call.stage == "approve":
            return False
        if call.stage == "execute" and (call.person_approved or call.is_read):
            return False
        return True

    async def switch_on(self) -> bool:
        """Whether the owner's "tool_rules" switch is on; a read that fails counts as on."""
        if self._enabled is None:
            return True
        try:
            return bool(await self._enabled())
        except Exception as exc:  # noqa: BLE001 - fail closed: rules stay on
            logger.warning("tool_rules_switch_unreadable", error_type=type(exc).__name__)
            return True

    async def check(self, call: CallFacts) -> Verdict:
        """Allow, or Escalate naming the broken rules (see the module docstring)."""
        if call.stage == "approve" or not engine.applies_to(call.canonical):
            return ALLOW
        if call.stage == "execute":
            if call.person_approved or call.is_read:
                return ALLOW
            return await self._without_turn(call, cached_domains=True)
        if call.turn is None:
            return await self._without_turn(call, cached_domains=False)
        return await self._in_turn(call)

    # -- stages -----------------------------------------------------------------------------

    def _view(self, call: CallFacts) -> engine.CallView:
        return engine.call_view(call.canonical, call.arguments, spec=call.spec, is_mcp=call.is_mcp)

    async def _without_turn(self, call: CallFacts, *, cached_domains: bool) -> Verdict:
        """The execute stage, and a turn-stage call parked outside a turn: no turn facts, so B1
        and B4 are skipped; B2, B3 and the owner's rules apply."""
        if not await self.switch_on():
            return ALLOW
        view = self._view(call)
        snapshot = await self._store.snapshot()
        if snapshot.error and not engine.is_write(view):
            logger.warning("tool_rules_unavailable", stage=call.stage)
            return ALLOW
        domains = (
            await self._domains(call.user_id, cached=cached_domains)
            if view.shares_content
            else frozenset()
        )
        return verdict_for(engine.evaluate(view, snapshot, turn=None, org_domains=domains))

    async def _in_turn(self, call: CallFacts) -> Verdict:
        turn = call.turn
        assert turn is not None
        state = turn.scratch.get(TOOL_RULES_CHECK)
        if not isinstance(state, _TurnState):
            state = _TurnState()
            turn.scratch[TOOL_RULES_CHECK] = state
        if state.enabled is None:
            state.enabled = await self.switch_on()
        if not state.enabled:
            return ALLOW
        if state.snapshot is None:
            state.snapshot = await self._store.snapshot()
        snapshot = state.snapshot
        view = self._view(call)
        if snapshot.error and not engine.is_write(view):
            if not state.warned_unavailable:
                state.warned_unavailable = True
                logger.warning("tool_rules_unavailable", stage=call.stage)
            return ALLOW
        if state.view is None:
            state.view = context.turn_view(
                turn.messages,
                trusted_text=turn.trusted_text or "",
                seen_untrusted=getattr(turn.taint, "seen_untrusted", None),
            )
        domains: Optional[frozenset[str]] = frozenset()
        if view.shares_content:
            if state.org_domains is _UNSET:
                state.org_domains = await self._domains(call.user_id, cached=False)
            domains = state.org_domains
        return verdict_for(engine.evaluate(view, snapshot, turn=state.view, org_domains=domains))

    # -- organisation domains ---------------------------------------------------------------

    async def _domains(self, user_id: str, *, cached: bool) -> Optional[frozenset[str]]:
        """The calling person's organisation domains (lower-case): empty when none is known (or
        no helper is wired), None when the lookup raised (B3 then asks for every share)."""
        if self._org_domains is None:
            return frozenset()
        now = self._clock()
        if cached:
            hit = self._org_cache.get(user_id)
            if hit is not None and now - hit[0] < ORG_DOMAINS_TTL_S:
                self._org_cache.move_to_end(user_id)
                return hit[1]
        try:
            found = frozenset(
                domain.strip().lower().rstrip(".")
                for domain in await self._org_domains(user_id)
                if isinstance(domain, str) and domain.strip()
            )
        except Exception as exc:  # noqa: BLE001 - fail closed: every share asks
            logger.warning("tool_rules_org_domains_unreadable", error_type=type(exc).__name__)
            return None
        self._org_cache[user_id] = (now, found)
        self._org_cache.move_to_end(user_id)
        while len(self._org_cache) > ORG_DOMAINS_CACHE_SIZE:
            self._org_cache.popitem(last=False)
        return found


__all__ = [
    "NOTE_KIND",
    "TOOL_RULES_CHECK",
    "TOOL_RULES_POLICY",
    "ToolRulesCheck",
    "verdict_for",
]
