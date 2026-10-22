"""Tests for how main.wire_services connects the owner's site rules: they
prove that one ``SiteRulesService`` is built, loaded and hung on app.state;
that its per-user guard hook goes to all three browser toolkits (read, act,
checkout); that the executor's web toolkit refuses a Blocked host on every
hop through the wrapped resolver; that watch.create, the page-watch
sweeper's background checks and knowledge web imports refuse one too (with
S7's sentence, and every URL while no rules were ever read), and the call
check refuses a watch or an import of one before its card; that the
site-rules check sits third in
the call checks (after MCP pins, before outbound) and reads the browser
toolkits' own page memory; and that turning the switch off in Settings
suspends every rule at once (and on again restores them).

Why it exists: every S7 seam is passed in by main.py; a toolkit built
without the hooks, a web toolkit built without the wrapper, or a check
reading another page memory would leave a way around the rules that no unit
test of the package itself can see. Runs wire_services against the test
database with a fake Telegram service; app.state is restored afterwards.
"""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio

from core.config import settings
from models.browser_site_rule import BrowserSiteRule
from services.security.call_checks import CHECK_ORDER, CallFacts
from services.site_rules import messages
from services.site_rules.check import SiteRulesCallCheck
from services.site_rules.service import SiteRulesService
from services.tools.browser import snapshot as snap
from services.tools.net import EgressBlocked, OwnerRuleBlocked
from tests.conftest import make_user
from tests.test_telegram_manager import FakeService


@pytest_asyncio.fixture
async def wired(session_factory, monkeypatch):
    from main import app, wire_services

    async with session_factory() as session:
        session.add(BrowserSiteRule(target_type="host", target="*.example-casino.com", kind="blocked"))
        await session.commit()
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    FakeService.instances.clear()
    saved = dict(app.state._state)
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        yield app.state
    finally:
        service = getattr(app.state, "site_rules", None)
        if isinstance(service, SiteRulesService):
            await service.drain()
        await app.state.telegram_manager.stop()
        await app.state.slack_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)


def _call(tool: str, arguments: dict[str, Any], *, user: str = "ann") -> CallFacts:
    return CallFacts(stage="turn", user_id=user, tool_name=tool, canonical=tool, arguments=arguments)


@pytest.mark.asyncio
async def test_wire_services_builds_the_service_and_hands_its_hooks_to_all_three_browser_toolkits(wired):
    service = wired.site_rules
    assert isinstance(service, SiteRulesService)
    # The first snapshot was read at start-up, from the database.
    snapshot = service.snapshot
    assert snapshot is not None and snapshot.enabled is True
    assert [rule.pattern for rule in snapshot.rules] == ["*.example-casino.com"]
    executor = wired.tool_executor
    toolkits = (executor._browser, executor._act, executor._checkout)
    for toolkit in toolkits:
        hooks = toolkit._egress_hooks
        assert hooks is not None and hooks.site_rules == service.guard_hook_for, type(toolkit).__name__
        assert hooks.reputation is not None  # S4's slot, beside S7's
    hook = executor._browser._egress_hooks.site_rules("ann")
    assert hook.navigation_reason("https://www.example-casino.com/", exempt=False) == (
        messages.NAVIGATION_BLOCKED
    )


@pytest.mark.asyncio
async def test_the_executors_web_toolkit_refuses_blocked_hosts(wired):
    resolve = wired.tool_executor._web._resolver
    for url in ("https://www.example-casino.com/promo?x=1", "https://EXAMPLE-CASINO.com./"):
        with pytest.raises(EgressBlocked) as caught:
            resolve(url)
        assert str(caught.value) == messages.blocked_call(
            "www.example-casino.com" if "www" in url else "example-casino.com"
        )


def _refuses_as_blocked(resolve) -> None:
    for url in ("https://www.example-casino.com/promo?x=1", "https://EXAMPLE-CASINO.com./"):
        with pytest.raises(OwnerRuleBlocked) as caught:
            resolve(url)
        assert str(caught.value) == messages.blocked_call(
            "www.example-casino.com" if "www" in url else "example-casino.com"
        )


@pytest.mark.asyncio
async def test_watch_create_uses_the_site_rules_resolver(wired):
    resolve = wired.tool_executor._watch._resolver
    _refuses_as_blocked(resolve)
    # A host no rule matches meets the plain network policy, unchanged
    # (an IP literal: no DNS query is made).
    with pytest.raises(EgressBlocked) as caught:
        resolve("http://127.0.0.1/admin")
    assert not isinstance(caught.value, OwnerRuleBlocked)


@pytest.mark.asyncio
async def test_knowledge_web_imports_use_the_site_rules_resolver(wired):
    knowledge = wired.tool_executor.knowledge_toolkit
    assert wired.knowledge is knowledge  # the toolkit main.py configures is the wrapped one
    _refuses_as_blocked(knowledge._url_resolver)


@pytest.mark.asyncio
async def test_the_page_watch_sweeper_fetches_through_the_site_rules_and_fails_closed(wired):
    from services.tools.watch import WatchFetchError

    # A watch saved before the site was Blocked: its background check is
    # refused before any request, with S7's sentence as the reason.
    with pytest.raises(WatchFetchError) as caught:
        await wired.page_watches._fetch("https://www.example-casino.com/promo")
    assert str(caught.value) == messages.blocked_call("www.example-casino.com")
    # Rules that were never read (the start-up read failed): the watch and
    # knowledge resolvers refuse every URL. The sweeper's own fetch reads
    # the rules first, so it judges by them again once they load.
    service = wired.site_rules
    saved, service._snapshot = service._snapshot, None
    try:
        for resolve in (wired.tool_executor._watch._resolver, wired.knowledge._url_resolver):
            with pytest.raises(OwnerRuleBlocked) as unread:
                resolve("https://news.example/")
            assert str(unread.value) == messages.UNAVAILABLE
        with pytest.raises(WatchFetchError) as caught:
            await wired.page_watches._fetch("https://www.example-casino.com/")
        assert str(caught.value) == messages.blocked_call("www.example-casino.com")
        assert service.snapshot is not None
    finally:
        service._snapshot = service._snapshot or saved


@pytest.mark.asyncio
async def test_watch_create_and_a_knowledge_web_import_are_refused_before_their_cards(wired):
    for tool, arguments in (
        ("watch.create", {"url": "https://example-casino.com/", "label": "Promos"}),
        ("knowledge.add", {"collection": "Reading", "url": "https://example-casino.com/"}),
    ):
        outcome = await wired.call_checks.run(_call(tool, arguments))
        assert outcome.refusal is not None, tool
        assert (outcome.refusal.check, outcome.refusal.rule) == ("site_rules", "site_blocked")


@pytest.mark.asyncio
async def test_the_site_rules_check_runs_after_mcp_pins_and_before_outbound_checks(wired):
    pipeline = wired.call_checks
    assert pipeline.names == CHECK_ORDER
    assert pipeline.names.index("site_rules") == pipeline.names.index("mcp_pin") + 1
    assert pipeline.names.index("outbound") == pipeline.names.index("site_rules") + 1
    check = pipeline._checks[2]
    assert isinstance(check, SiteRulesCallCheck) and check._service is wired.site_rules
    # A Blocked URL is refused through the production pipeline.
    outcome = await pipeline.run(_call("browser.read", {"action": "open", "url": "https://example-casino.com/"}))
    assert outcome.refusal is not None
    assert (outcome.refusal.check, outcome.refusal.rule) == ("site_rules", "site_blocked")
    # The check reads the browser toolkits' own page memory: a page the read
    # toolkit remembers on a Blocked site makes the next read of it refused.
    memory = wired.tool_executor._browser._memory
    assert memory is wired.tool_executor._act._memory
    memory.remember("ann", url="https://games.example-casino.com/lobby", outline_lines=[], facts=snap.PageFacts())
    outcome = await pipeline.run(_call("browser.read", {"action": "snapshot"}))
    assert outcome.refusal is not None and outcome.refusal.rule == "site_blocked"
    # Another user's page is not this user's.
    outcome = await pipeline.run(_call("browser.read", {"action": "snapshot"}, user="bob"))
    assert outcome.refusal is None


@pytest.mark.asyncio
async def test_turning_the_switch_off_in_settings_suspends_every_rule_at_once(wired, session_factory):
    owner, _token = await make_user(session_factory, "owner@example.com")
    service = wired.site_rules
    async with session_factory() as session:
        session.add(BrowserSiteRule(target_type="host", target="docs.example.org", kind="trusted"))
        await session.commit()
    # A row written behind the service's back is not seen until the snapshot
    # is refreshed or marked stale...
    assert len(service.snapshot.rules) == 1
    blocked = _call("web.fetch_page", {"url": "https://example-casino.com/"})
    assert (await wired.call_checks.run(blocked)).refusal is not None
    # ...and the Settings switch (a "capabilities" change) does both: the
    # rows are read again, and the switch is off, so nothing applies.
    await wired.installation.set_capabilities({"browser_site_rules": False}, actor_id=owner.id)
    assert (await wired.call_checks.run(blocked)).refusal is None
    snapshot = service.snapshot
    assert snapshot is not None and snapshot.enabled is False
    assert {rule.pattern for rule in snapshot.rules} == {"*.example-casino.com", "docs.example.org"}
    hook = service.guard_hook_for("ann")
    assert hook.navigation_reason("https://example-casino.com/", exempt=False) is None
    # On again: the rules apply again, at once.
    await wired.installation.set_capabilities({"browser_site_rules": True}, actor_id=owner.id)
    assert (await wired.call_checks.run(blocked)).refusal is not None
    assert hook.navigation_reason("https://example-casino.com/", exempt=False) == messages.NAVIGATION_BLOCKED
