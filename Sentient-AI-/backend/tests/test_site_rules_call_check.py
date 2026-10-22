"""Tests for the site-rules call check (services/site_rules/check.py), slot
3 of the pre-dispatch call checks: they prove that it applies to the
browser and web page tools, watch.create and a knowledge.add of a web page
only; that opening, fetching, screenshotting, watching or importing a
Blocked site is refused before anything starts (and the refusal carries the
``site_rule_blocked`` audit row with a keyed host hash, never the host or a
URL); that a read on a page already open on a Blocked site is refused while
open, back, tabs, switch and note are not; that an act or checkout on an
Always-ask site gets a "sensitive site" warn note for its card, is escalated
when it would run without one, and is refused at execution when nobody
approved it; that at approval the card's bound page is judged, never a page
the model names; that Trusted and unlisted sites add nothing; that the
switch off allows everything; and that rules which were never read refuse
these tools (fail closed).

Why it exists: the guard stops navigations, but a call must be judged before
a browser starts or a card is made, and a card parked before a rule changed
must be refused when it is approved. Pure: no database, no browser, no
network (the rules are an in-memory snapshot).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

import pytest

from core.config import settings
from services.security.call_checks import (
    CHECK_ORDER,
    Allow,
    CallCheckPipeline,
    CallFacts,
    Escalate,
    Note,
    Refuse,
)
from services.site_rules import check as check_module
from services.site_rules import messages
from services.site_rules.check import SiteRulesCallCheck
from services.site_rules.patterns import host_hash
from tests.site_rules_fakes import FakeSiteRules, snapshot_of

USER = "user-1"
CASINO = "https://example-casino.com/slots?session=SECRET1"
BANK = "https://secure.chase.com/transfer"
DOCS = "https://docs.example.org/guide"
SHOP = "https://shop.example/cart"


def _rules(**kwargs: Any) -> FakeSiteRules:
    rules = kwargs.pop("rules", {"*.example-casino.com": "blocked", "docs.example.org": "trusted"})
    return FakeSiteRules(snapshot_of(rules, **kwargs))


def _check(
    service: Any, *, page: Optional[str] = None, pages: Optional[Mapping[str, str]] = None
) -> SiteRulesCallCheck:
    def page_origin(user_id: str) -> Optional[str]:
        if pages is not None:
            return pages.get(user_id)
        return page

    return SiteRulesCallCheck(service, page_origin=page_origin)


def _call(
    tool: str,
    arguments: Mapping[str, Any],
    *,
    stage: str = "turn",
    approved: bool = False,
    will_card: bool = False,
) -> CallFacts:
    return CallFacts(
        stage=stage,  # type: ignore[arg-type]
        user_id=USER,
        tool_name=tool,
        canonical=tool,
        arguments=arguments,
        person_approved=approved,
        runs_without_card=not will_card and not approved,
        will_card=will_card,
    )


def test_the_check_has_its_final_name_policy_stages_and_is_no_longer_a_stub():
    assert SiteRulesCallCheck.name == "site_rules" == CHECK_ORDER[2]
    assert SiteRulesCallCheck.policy == "site_rules"
    assert SiteRulesCallCheck.stages == frozenset({"turn", "approve", "execute"})
    assert not hasattr(check_module, "SCAFFOLD_STUB")


@pytest.mark.asyncio
async def test_it_applies_only_to_browser_and_web_page_tools():
    service = _rules()
    check = _check(service, page=CASINO)
    for tool in ("browser.read", "browser.act", "browser.checkout", "web.fetch_page", "web.screenshot"):
        assert check.applies_to(_call(tool, {})) is True, tool
    # A new page watch and a web page saved to the knowledge base open a site too.
    assert check.applies_to(_call("watch.create", {"url": CASINO, "label": "x"})) is True
    assert check.applies_to(_call("knowledge.add", {"collection": "c", "url": CASINO})) is True
    for tool in (
        "web.search",  # results pages: the guarded client's resolver judges each hop
        "web.research",  # sources: the wrapped resolver skips a Blocked one
        "google_workspace.send_email",
        "desktop.act",
        "memory.remember",
        "tools.find",
        "watch.list",
        "watch.delete",
        "knowledge.search",
    ):
        assert check.applies_to(_call(tool, {"url": CASINO})) is False, tool
        assert isinstance(await check.check(_call(tool, {"url": CASINO})), Allow)
    assert service.fresh_calls == 0  # nothing else ever reads the rules


@pytest.mark.asyncio
async def test_opening_a_blocked_url_is_refused_before_the_browser_starts():
    service = _rules()
    verdict = await _check(service).check(_call("browser.read", {"action": "open", "url": CASINO}))
    assert isinstance(verdict, Refuse)
    assert verdict.rule == "site_blocked"
    assert verdict.message == messages.blocked_call("example-casino.com")
    assert "SECRET1" not in verdict.message and "/slots" not in verdict.message
    assert service.hits == [
        {"user_id": USER, "host": "example-casino.com", "kind": "blocked", "where": "call", "audit": False}
    ]
    # Any spelling the browser reads as the same site is refused the same way.
    for spelled in ("HTTPS://WWW.Example-Casino.COM.:443/", "https://user@example-casino.com", "example-casino.com"):
        assert isinstance(
            await _check(service).check(_call("browser.read", {"action": "open", "url": spelled})), Refuse
        ), spelled


@pytest.mark.asyncio
async def test_opening_a_sensitive_site_is_allowed():
    service = _rules()
    verdict = await _check(service).check(_call("browser.read", {"action": "open", "url": BANK}))
    assert isinstance(verdict, Allow)  # Always ask reads are allowed; observe adds the notice
    assert service.hits == []


@pytest.mark.asyncio
async def test_reading_while_the_open_page_is_on_a_blocked_site_is_refused_but_open_back_tabs_switch_and_note_are_not():
    service = _rules()
    check = _check(service, page="https://example-casino.com")
    for action in ("snapshot", "find", "text", "scroll", "click", "wait", "screenshot", "handoff"):
        verdict = await check.check(_call("browser.read", {"action": action}))
        assert isinstance(verdict, Refuse), action
        assert verdict.message == messages.blocked_page("example-casino.com")
    for arguments in (
        {"action": "open", "url": SHOP},
        {"action": "open"},
        {"action": "back"},
        {"action": "tabs"},
        {"action": "switch", "index": 1},
        {"action": "note", "text": "remember this"},
    ):
        assert isinstance(await check.check(_call("browser.read", arguments)), Allow), arguments
    # A page on an ordinary site is read as usual.
    assert isinstance(
        await _check(service, page=SHOP).check(_call("browser.read", {"action": "snapshot"})), Allow
    )


@pytest.mark.asyncio
async def test_an_act_on_an_always_ask_site_adds_a_warning_note_for_its_card():
    service = _rules()
    verdict = await _check(service, page="https://secure.chase.com").check(
        _call("browser.act", {"action": "type", "ref": "e3", "text": "100"}, will_card=True)
    )
    assert isinstance(verdict, Note)
    (note,) = verdict.notes
    assert (note.kind, note.severity) == ("site_sensitive", "warn")
    assert note.text == (
        "Sensitive site: secure.chase.com is on the built-in Banks and money accounts list in "
        "Site rules. Look at the page before you approve."
    )
    assert len(note.text) <= messages.NOTE_LIMIT
    # An owner's own Always-ask rule names the rule instead.
    owner = FakeSiteRules(snapshot_of({"*.example-bank.test": "always_ask"}))
    verdict = await _check(owner, page="https://www.example-bank.test").check(
        _call("browser.act", {"action": "click", "ref": "e1"}, will_card=True)
    )
    assert isinstance(verdict, Note)
    assert verdict.notes[0].text == (
        "You marked example-bank.test and its subdomains Always ask in Site rules. "
        "Look at the page before you approve."
    )


@pytest.mark.asyncio
async def test_an_act_on_an_always_ask_site_that_would_run_without_a_card_is_escalated():
    service = _rules()
    verdict = await _check(service, page="https://secure.chase.com").check(
        _call("browser.act", {"action": "click", "ref": "e1"}, will_card=False)
    )
    assert isinstance(verdict, Escalate)
    assert verdict.rule == "site_always_ask"
    assert verdict.reason == messages.ESCALATE_REASON
    assert verdict.refusal_text == messages.ESCALATE_REFUSAL
    assert verdict.names_rule is False
    assert [note.kind for note in verdict.notes] == ["site_sensitive"]


@pytest.mark.asyncio
async def test_an_always_ask_act_nobody_approved_is_refused_at_execution_by_the_pipeline():
    # A standing consent (any future path) reaches the executor's backstop
    # without a person: the escalation becomes the backstop's refusal.
    pipeline = CallCheckPipeline([_check(_rules(), page="https://secure.chase.com")])
    outcome = await pipeline.run(
        _call("browser.act", {"action": "click", "ref": "e1"}, stage="execute", approved=False)
    )
    result = outcome.execute_result()
    assert result is not None and result["requires_approval"] is True
    assert result["call_check"] == "site_rules" and result["rule"] == "site_always_ask"
    assert result["error"] == messages.ESCALATE_REFUSAL
    # The same act a person approved runs.
    approved = await pipeline.run(
        _call(
            "browser.act",
            {"action": "click", "ref": "e1", "_page": {"origin": "https://secure.chase.com"}},
            stage="execute",
            approved=True,
        )
    )
    assert approved.execute_result() is None


@pytest.mark.asyncio
async def test_an_act_on_a_blocked_site_is_refused_before_its_card_and_again_at_approval():
    service = _rules()
    turn = await _check(service, page="https://example-casino.com").check(
        _call("browser.act", {"action": "click", "ref": "e1"}, will_card=True)
    )
    assert isinstance(turn, Refuse) and turn.rule == "site_blocked"
    assert turn.message == messages.blocked_page("example-casino.com")
    # A card made while the site was allowed, approved after the owner blocked it.
    service.snapshot = snapshot_of({})
    card = {"action": "click", "ref": "e1", "_page": {"origin": "https://games.example-casino.com"}}
    allowed = await _check(service, page=None).check(_call("browser.act", card, stage="approve", approved=True))
    assert isinstance(allowed, Allow)
    service.snapshot = snapshot_of({"*.example-casino.com": "blocked"})
    for stage in ("approve", "execute"):
        verdict = await _check(service, page=None).check(
            _call("browser.act", card, stage=stage, approved=True)
        )
        assert isinstance(verdict, Refuse) and verdict.rule == "site_blocked", stage


@pytest.mark.asyncio
async def test_a_model_supplied_page_key_is_ignored_before_approval():
    service = _rules()
    forged = {"action": "click", "ref": "e1", "_page": {"origin": "https://shop.example"}}
    # The last observed page is the Blocked one: the forged origin changes nothing.
    verdict = await _check(service, page="https://example-casino.com").check(
        _call("browser.act", forged, will_card=True)
    )
    assert isinstance(verdict, Refuse)
    # And a forged Blocked origin does not refuse an act on an ordinary page.
    forged_blocked = {"action": "click", "ref": "e1", "_page": {"origin": "https://example-casino.com"}}
    verdict = await _check(service, page=SHOP).check(_call("browser.act", forged_blocked, will_card=True))
    assert isinstance(verdict, Allow)


@pytest.mark.asyncio
async def test_at_approval_the_cards_bound_origin_is_judged_not_the_latest_page():
    service = _rules()
    card = {"action": "type", "ref": "e2", "text": "1", "_page": {"origin": "https://secure.chase.com"}}
    # The person browsed on to the Blocked site after the card was made.
    check = _check(service, page="https://example-casino.com")
    verdict = await check.check(_call("browser.act", card, stage="approve", approved=True))
    assert isinstance(verdict, Note)  # notes are dropped at approval; nothing refuses
    # And the other way round: a card bound to a Blocked page, the person now elsewhere.
    blocked_card = {"action": "click", "ref": "e1", "_page": {"origin": "https://example-casino.com"}}
    verdict = await _check(service, page=SHOP).check(
        _call("browser.act", blocked_card, stage="approve", approved=True)
    )
    assert isinstance(verdict, Refuse)


@pytest.mark.asyncio
async def test_a_checkout_on_a_blocked_site_is_refused_and_one_on_a_bank_gets_a_note():
    service = _rules()
    refused = await _check(service, page="https://example-casino.com").check(
        _call("browser.checkout", {"action": "pay"}, will_card=True)
    )
    assert isinstance(refused, Refuse) and refused.rule == "site_blocked"
    noted = await _check(service, page="https://secure.chase.com").check(
        _call("browser.checkout", {"action": "pay"}, will_card=True)
    )
    assert isinstance(noted, Note) and noted.notes[0].kind == "site_sensitive"
    # At approval the checkout's own bound origin is judged.
    bound = {"action": "pay", "_checkout": {"origin": "https://example-casino.com"}}
    verdict = await _check(service, page=SHOP).check(
        _call("browser.checkout", bound, stage="approve", approved=True)
    )
    assert isinstance(verdict, Refuse)


@pytest.mark.asyncio
async def test_an_act_with_no_observed_page_is_left_to_the_toolkit():
    service = _rules()
    for page in (None, "", "about:blank", "chrome-error://chromewebdata/"):
        verdict = await _check(service, page=page).check(
            _call("browser.act", {"action": "click", "ref": "e1"}, will_card=True)
        )
        assert isinstance(verdict, Allow), page  # the act toolkit refuses needs_observe


@pytest.mark.asyncio
async def test_a_page_memory_that_raises_is_not_read_as_no_page():
    def broken(user_id: str) -> Optional[str]:
        raise RuntimeError("page memory gone")

    check = SiteRulesCallCheck(_rules(), page_origin=broken)
    with pytest.raises(RuntimeError):
        await check.check(_call("browser.act", {"action": "click", "ref": "e1"}, will_card=True))
    # Through the pipeline that is a failed check: at approval, a refusal.
    outcome = await CallCheckPipeline([check]).run(
        _call("browser.act", {"action": "click", "ref": "e1"}, stage="approve", approved=True)
    )
    assert outcome.refusal is not None and outcome.refusal.rule == "call_check_failed"


@pytest.mark.asyncio
async def test_web_fetch_page_and_screenshot_of_a_blocked_url_are_refused():
    service = _rules()
    for tool in ("web.fetch_page", "web.screenshot"):
        verdict = await _check(service).check(_call(tool, {"url": CASINO}))
        assert isinstance(verdict, Refuse) and verdict.rule == "site_blocked", tool
        assert verdict.message == messages.blocked_call("example-casino.com")
        assert isinstance(await _check(service).check(_call(tool, {"url": BANK})), Allow), tool
        assert isinstance(await _check(service).check(_call(tool, {})), Allow), tool


@pytest.mark.asyncio
async def test_a_page_watch_or_web_page_import_on_a_blocked_site_is_refused_before_its_card():
    # Blocked means never opened (S7): a watch would fetch the site in the
    # background, and an imported page could be read back through
    # knowledge.search. Refused before the card and again at approval.
    service = _rules()
    for tool, arguments in (
        ("watch.create", {"url": CASINO, "label": "Promos"}),
        ("knowledge.add", {"collection": "Reading", "url": CASINO}),
    ):
        for stage, approved in (("turn", False), ("approve", True), ("execute", True)):
            call = _call(tool, arguments, stage=stage, approved=approved, will_card=not approved)
            assert _check(service).applies_to(call) is True, tool
            verdict = await _check(service).check(call)
            assert isinstance(verdict, Refuse) and verdict.rule == "site_blocked", (tool, stage)
            assert verdict.message == messages.blocked_call("example-casino.com")
            assert verdict.audit_event == "site_rule_blocked"
            assert verdict.audit_facts is not None and verdict.audit_facts["tool"] == tool
        # Any site no rule blocks is left alone, Always-ask ones included.
        for url in (SHOP, BANK):
            verdict = await _check(service).check(_call(tool, {**arguments, "url": url}, will_card=True))
            assert isinstance(verdict, Allow), (tool, url)


@pytest.mark.asyncio
async def test_a_knowledge_add_that_opens_no_site_is_never_judged_even_with_unread_rules():
    service = FakeSiteRules(None)
    check = _check(service)
    for arguments in (
        {"collection": "Reading", "text": "Chapter one is due Friday.", "title": "Due"},
        {"collection": "Reading", "file_ids": ["5d0f3c55-7d4e-4b8c-9a55-2b6f2f7a0c11"]},
        {"collection": "Reading", "connector": "google_workspace", "ids": ["doc-1"]},
    ):
        call = _call("knowledge.add", arguments, will_card=True)
        assert check.applies_to(call) is False
        assert isinstance(await check.check(call), Allow)
    assert service.fresh_calls == 0
    # One that saves a web page, and any page watch, fail closed instead.
    for tool, arguments in (
        ("knowledge.add", {"collection": "Reading", "url": SHOP}),
        ("watch.create", {"url": SHOP, "label": "Cart"}),
    ):
        verdict = await check.check(_call(tool, arguments, will_card=True))
        assert isinstance(verdict, Refuse), tool
        assert (verdict.rule, verdict.message) == ("site_rules_unavailable", messages.UNAVAILABLE)


@pytest.mark.asyncio
async def test_a_trusted_site_gets_no_note():
    service = FakeSiteRules(snapshot_of({"secure.chase.com": "trusted"}))
    for tool in ("browser.act", "browser.checkout"):
        verdict = await _check(service, page="https://secure.chase.com").check(
            _call(tool, {"action": "click"}, will_card=True)
        )
        assert isinstance(verdict, Allow), tool
    # An unlisted site adds nothing either, so pinned card reasons stay as they are.
    verdict = await _check(service, page=DOCS).check(_call("browser.act", {"action": "click"}, will_card=True))
    assert isinstance(verdict, Allow)


@pytest.mark.asyncio
async def test_with_the_switch_off_every_call_is_allowed():
    service = _rules(enabled=False)
    calls = [
        _call("browser.read", {"action": "open", "url": CASINO}),
        _call("web.fetch_page", {"url": CASINO}),
        _call("browser.act", {"action": "click"}, will_card=False),
    ]
    for call in calls:
        assert isinstance(await _check(service, page="https://example-casino.com").check(call), Allow)
    assert service.hits == []


@pytest.mark.asyncio
async def test_rules_that_cannot_be_read_refuse_browser_and_web_page_calls():
    service = FakeSiteRules(None)
    for tool, arguments in (
        ("browser.read", {"action": "open", "url": SHOP}),
        ("browser.read", {"action": "tabs"}),
        ("browser.act", {"action": "click"}),
        ("browser.checkout", {"action": "pay"}),
        ("web.fetch_page", {"url": SHOP}),
        ("web.screenshot", {"url": SHOP}),
    ):
        verdict = await _check(service, page=SHOP).check(_call(tool, arguments))
        assert isinstance(verdict, Refuse), tool
        assert (verdict.rule, verdict.message) == ("site_rules_unavailable", messages.UNAVAILABLE)
        assert verdict.audit_event is None
    # Every other tool is untouched: the check does not apply to it.
    assert _check(service).applies_to(_call("web.search", {"query": "x"})) is False


@pytest.mark.asyncio
async def test_a_refusal_carries_the_site_rule_blocked_audit_event_and_hashed_facts():
    rows: list[dict[str, Any]] = []

    async def audit(row: dict[str, Any]) -> None:
        rows.append(row)

    service = FakeSiteRules(snapshot_of({}, {"brokers": "blocked"}))
    pipeline = CallCheckPipeline([_check(service)], audit=audit)
    outcome = await pipeline.run(
        _call("web.fetch_page", {"url": "https://www.fidelity.com/accounts?ssn=SECRET2"})
    )
    assert outcome.refusal is not None
    assert (outcome.refusal.check, outcome.refusal.policy, outcome.refusal.rule) == (
        "site_rules",
        "site_rules",
        "site_blocked",
    )
    (row,) = rows
    assert row["event"] == "site_rule_blocked" and row["user_id"] == USER
    assert row["arguments"] == {
        "where": "call",
        "tool": "web.fetch_page",
        "source": "builtin",
        "category": "brokers",
        "host_hash": host_hash("www.fidelity.com", settings.ENCRYPTION_KEY),
        "kind": "blocked",
    }
    assert len(row["arguments"]["host_hash"]) == 16
    text = repr(row)
    assert "fidelity" not in text and "SECRET2" not in text and "/accounts" not in text
