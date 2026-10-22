"""Tests for the security wave's WAVE 0 scaffold: they prove every stub module a
skill will replace imports on its own and carries its stub marker, that
wiring the app builds every security service without starting a sweeper or
sending anything over the network, that the connector registry still
imports with every write taking ``user_confirmed``, and that the
``requires_real`` marker skips, runs or fails as the integration state says.

Why it exists: ten skills are built in parallel against these stubs (scaffold
H2). A name that drifted, an import cycle that only shows when a module is
imported first, or a stub that quietly does something would surface late,
in another skill's tests. Each builder runs this file first (scaffold H4);
the two cases marked for integration run once the integrator sets
``tests.security_stubs.INTEGRATED``.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.config import settings
from tests import security_stubs
from tests.conftest import make_user
from tests.security_stubs import INTEGRATED, STUB_MODULES, is_stub, requires_real

BACKEND = Path(__file__).resolve().parents[1]


def test_every_stub_module_imports_and_is_marked_as_a_stub():
    """Every module of STUB_MODULES imports. One whose docstring still says it
    is a WAVE 0 stub carries ``SCAFFOLD_STUB = True``; a builder removes the
    line (never sets it False) when the real code lands, and is_stub agrees
    with the marker."""
    unmarked = []
    for name in STUB_MODULES:
        module = importlib.import_module(name)
        marker = getattr(module, "SCAFFOLD_STUB", None)
        assert marker in (True, None), f"{name}: SCAFFOLD_STUB is {marker!r}; remove the line instead"
        if "WAVE 0 stub" in (module.__doc__ or "") and marker is not True:
            unmarked.append(name)
        assert is_stub(name) is (marker is True), name
    assert unmarked == []


def test_the_stub_list_names_each_module_once_and_only_modules_that_exist():
    assert len(set(STUB_MODULES)) == len(STUB_MODULES)
    for name in STUB_MODULES:
        path = BACKEND.joinpath(*name.split(".")).with_suffix(".py")
        assert path.is_file(), name


def _import_alone(name: str) -> tuple[str, int, str]:
    done = subprocess.run(
        [sys.executable, "-c", f"import {name}"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return name, done.returncode, done.stderr[-2000:]


def test_every_stub_module_imports_first_in_a_fresh_interpreter():
    """An import cycle (a stub importing tool_registry or runtime at module
    level, scaffold J12) only shows when that module is the first one a
    process imports, so each is imported alone in its own interpreter. The
    environment conftest set (keys, database URL) is inherited."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_import_alone, STUB_MODULES))
    failures = [f"{name}: {stderr}" for name, code, stderr in results if code != 0]
    assert failures == []


class _NoNetwork:
    """Records any HTTP request an httpx client tries to send, and refuses it."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        calls = self.calls

        async def refuse_async(client, request, *args, **kwargs):
            calls.append(str(request.url.host))
            raise httpx.ConnectError("no network in this test", request=request)

        def refuse(client, request, *args, **kwargs):
            calls.append(str(request.url.host))
            raise httpx.ConnectError("no network in this test", request=request)

        monkeypatch.setattr(httpx.AsyncClient, "send", refuse_async)
        monkeypatch.setattr(httpx.Client, "send", refuse)


@pytest.mark.asyncio
async def test_wire_services_builds_every_security_service_without_starting_a_sweeper_or_a_network_call(
    session_factory, monkeypatch
):
    """wire_services builds each skill's service and the call checks, and
    nothing more: no task it started is still running afterwards (the
    sweepers start only in the lifespan) and no HTTP request was attempted
    (nothing is sent anywhere without the owner's key, decisions 2)."""
    from main import app, wire_services
    from services.security.call_checks import CHECK_ORDER
    from tests.test_telegram_manager import FakeService

    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "", raising=False)
    network = _NoNetwork()
    network.install(monkeypatch)
    saved = dict(app.state._state)
    before = set(asyncio.all_tasks())
    await wire_services(app, session_factory, telegram_service_factory=FakeService)
    try:
        await asyncio.sleep(0)
        started = {task for task in asyncio.all_tasks() - before if not task.done()}
        assert started == set(), sorted(task.get_name() for task in started)
        assert network.calls == []

        state = app.state
        for name in (
            "owner_send",
            "link_reputation",
            "site_rules",
            "mcp_pins",
            "outbound",
            "organisation_domains",
            "org_domains",
            "tool_rules_store",
            "tool_rules_check",
            "file_reputation",
            "file_reputation_sweeper",
            "mail_scan",
            "breach_monitor",
            "approval_store",
            "call_checks",
        ):
            assert getattr(state, name, None) is not None, name
        assert state.call_checks.names == CHECK_ORDER
        assert getattr(state.file_reputation_sweeper, "running", False) is False
    finally:
        await app.state.telegram_manager.stop()
        await app.state.slack_manager.stop()
        app.state._state.clear()
        app.state._state.update(saved)


@pytest.mark.asyncio
async def test_the_stub_services_answer_not_built_and_never_safe():
    """The contracts other skills code against give inert answers until their
    skill lands: no key can be saved (each tester refuses, so no key is
    stored before the code that uses it exists), a file is never "safe", a
    link is never looked up and never shown unchecked, and no organisation
    is known. Each part runs only while its module is still a stub, so a
    real tester never reaches the network from here."""
    if is_stub("services.reputation.links"):
        from services.reputation.links import LinkReputation
        from services.reputation.links import test_google_key as google_test_key

        google = await google_test_key("safe_browsing", "AIza" + "x" * 35)
        assert (google.ok, google.detail) == (False, "Google keys cannot be checked yet.")
        reputation = LinkReputation(object())
        [report] = await reputation.check(["https://example.com/a?token=secret"], purpose="chat")
        assert (report.level, report.service_status, report.shown) == ("unknown", "no_key", "")
        assert await reputation.remote_configured() is False
        assert await reputation.navigation_check("https://example.com/", None) is None

    if is_stub("services.breach.hibp"):
        from services.breach.hibp import check_key as hibp_check_key

        hibp = await hibp_check_key("a" * 32)
        assert (hibp.ok, hibp.detail) == (False, "Have I Been Pwned keys cannot be checked yet.")

    if is_stub("services.file_reputation.virustotal"):
        from services.file_reputation.virustotal import test_key as virustotal_test_key

        virustotal = await virustotal_test_key("a" * 64)
        assert (virustotal.ok, virustotal.detail) == (False, "VirusTotal keys cannot be checked yet.")

    if is_stub("services.file_reputation.service"):
        from services.file_reputation.service import FileReputationService

        service = FileReputationService(
            lambda: None, settings=object(), audit=lambda row: None, send=lambda u, t: None
        )
        verdict = await service.check_hash("u1", "a" * 64)
        assert (verdict.verdict, verdict.reason, verdict.flagged) == ("not_checked", "not_built", False)
        assert await service.remote_configured() is False
        entries = [{"kind": "file", "name": "a.pdf"}]
        assert await service.annotate("u1", entries) is entries

    if is_stub("services.security.link_checks"):
        from services.security.link_checks import LocalOnlyLinkChecker

        local = LocalOnlyLinkChecker()
        [report] = await local.check(["https://example.com/a?token=secret"], purpose="chat")
        assert (report.level, report.service_status, report.shown) == ("unknown", "no_key", "")
        assert await local.remote_configured() is False

    if is_stub("services.security.outbound_store"):
        from services.security.outbound_store import OrgDomains

        assert await OrgDomains(lambda: None).for_user("u1") == frozenset()


@pytest.mark.asyncio
async def test_each_call_check_has_its_final_name_policy_and_stages_and_a_stub_applies_to_no_call():
    """The five checks main wires (scaffold D3, A28): their names fit
    CHECK_ORDER, their policies are the ones refusal rows record, their
    stages are fixed; while a check's module is still a stub it applies to
    no call and allows, so production behaves as before."""
    from services.file_reputation.call_check import FileReputationCallCheck
    from services.mcp.pin_check import McpPinCallCheck
    from services.mcp.pin_store import McpPinService
    from services.security.call_checks import ALLOW, CHECK_ORDER, CallFacts, standard_pipeline
    from services.security.outbound import OutboundCheck
    from services.security.tool_rules import InMemoryToolRuleStore, ToolRulesCheck
    from services.site_rules.service import SiteRulesService

    async def on() -> bool:
        return True

    checks = {
        "services.security.tool_rules.check": ToolRulesCheck(InMemoryToolRuleStore()),
        "services.mcp.pin_check": McpPinCallCheck(McpPinService(lambda: None)),
        "services.site_rules.check": SiteRulesService(lambda: None, enabled=on).call_check(
            page_origin=lambda user_id: None
        ),
        "services.security.outbound": OutboundCheck(
            executor=None, known=None, org_domains=None, users=None
        ),
        "services.file_reputation.call_check": FileReputationCallCheck(lambda: None),
    }
    every_stage = frozenset({"turn", "approve", "execute"})
    expected = [
        ("tool_rules", "tool_rules", every_stage),
        ("mcp_pin", "mcp_pin", every_stage),
        ("site_rules", "site_rules", every_stage),
        ("outbound", "outbound_rule", every_stage),
        ("file_reputation", "file_reputation", frozenset({"turn"})),
    ]
    assert [(c.name, c.policy, frozenset(c.stages)) for c in checks.values()] == expected
    assert standard_pipeline(
        tool_rules=checks["services.security.tool_rules.check"],
        mcp_pin=checks["services.mcp.pin_check"],
        site_rules=checks["services.site_rules.check"],
        outbound=checks["services.security.outbound"],
        file_reputation=checks["services.file_reputation.call_check"],
    ).names == CHECK_ORDER

    call = CallFacts(
        stage="turn",
        user_id="u1",
        tool_name="google_workspace.forward",
        canonical="google_workspace.forward",
        arguments={"message_id": "m1", "to": "someone@example.com"},
    )
    for module, check in checks.items():
        if is_stub(module):
            assert check.applies_to(call) is False, module
            assert await check.check(call) is ALLOW, module


@pytest.mark.skipif(not INTEGRATED, reason="runs once the integrator sets INTEGRATED")
def test_no_security_stub_remains_after_integration():
    assert [name for name in STUB_MODULES if is_stub(name)] == []


@pytest.mark.skipif(not INTEGRATED, reason="runs once the integrator sets INTEGRATED")
@pytest.mark.asyncio
async def test_org_domains_for_user_knows_the_sign_in_domain_after_integration(session_factory):
    """S9's rule B3 needs the organisation of a user with a company address
    (scaffold A24, review INT-S2)."""
    from services.security.outbound_store import OrgDomains

    user, _ = await make_user(session_factory, "ann@northwind.com")
    assert await OrgDomains(session_factory).for_user(str(user.id)) == frozenset({"northwind.com"})


def test_the_registry_imports_and_every_write_takes_user_confirmed():
    """Every connector action that is not a READ (FINANCIAL ones are always
    hard-blocked and exempt, as validate_registry rules) has a keyword-only
    ``user_confirmed`` defaulting to False, or the registry would refuse to
    import (review INT-M1)."""
    from services.connectors.definition import ActionCategory
    from services.connectors.registry import REGISTRY, validate_registry

    assert validate_registry() == []
    missing = []
    for definition in REGISTRY:
        for spec in definition.actions:
            if spec.category in (ActionCategory.READ, ActionCategory.FINANCIAL):
                continue
            method = getattr(definition.connector_class, spec.action, None)
            param = inspect.signature(method).parameters.get("user_confirmed") if method else None
            if param is None or param.kind is not param.KEYWORD_ONLY or param.default is not False:
                missing.append(f"{definition.key}.{spec.action}")
    assert missing == []


def test_requires_real_skips_a_test_that_needs_a_stub_before_integration(monkeypatch):
    monkeypatch.setattr(security_stubs, "INTEGRATED", False)
    mark = requires_real("services.security.not_written_either", "services.security.not_written_yet")
    assert mark.mark.name == "skipif"
    assert mark.mark.args == (True,)
    assert "services.security.not_written_either" in mark.kwargs["reason"]
    assert "services.security.not_written_yet" in mark.kwargs["reason"]


def test_requires_real_runs_a_test_whose_modules_are_real(monkeypatch):
    monkeypatch.setattr(security_stubs, "INTEGRATED", True)
    mark = requires_real("services.security.call_checks", "services.security.lookalike")
    assert mark.mark.name == "skipif"
    assert mark.mark.args == (False,)


def test_requires_real_fails_a_test_whose_module_is_still_a_stub_after_integration(monkeypatch):
    monkeypatch.setattr(security_stubs, "INTEGRATED", True)
    mark = requires_real("services.security.call_checks", "services.security.not_written_yet")
    [condition] = mark.mark.args
    assert isinstance(condition, str)
    with pytest.raises(pytest.fail.Exception, match="services.security.not_written_yet"):
        eval(condition, {})  # what pytest does with a string condition at setup


def test_requires_real_needs_a_module_name():
    with pytest.raises(ValueError):
        requires_real()
