"""Tests for the "link_reputation" capability and for LinkReputation reading the real
InstallationService: they prove the capability is a policy switch (no tool), on by default and
low risk; it reads blocked with a plain fix until a Safe Browsing or Web Risk key exists, and an
HIBP or VirusTotal key alone does not unblock it; an environment key unblocks it without a
stored one; its two limits default to 60 a minute and 2,000 a day inside the settings bounds;
the model's permissions block never calls a link safe; and the lookup service follows a key
saved or removed, the owner's switch and the owner's limits without a restart.

Why it exists: decisions 2 promise that nothing is sent to Google until the owner adds a key and
that the owner can switch it off; the capability's availability and the service's per-call read
of it are what keep that promise. Keys here are built by concatenation so no scanner sees one;
no network: check_ssrf is replaced and MockTransport answers.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest

import core.network_security as netsec
from core.config import SERVICE_KEY_FIELDS, settings
from services import capabilities as registry
from services.capabilities import link_reputation as capability
from services.capabilities.base import ReportContext
from services.capabilities.prompt import render_permissions_block
from services.installation import SETTING_MAX, SETTING_MIN, InstallationService
from services.reputation import links
from services.reputation.links import LinkReputation
from tests.conftest import make_user

GOOGLE_KEY = "AIza" + "FAKEfake" * 4 + "000"


@pytest.fixture(autouse=True)
def _no_env_keys_and_no_dns(monkeypatch) -> Iterator[None]:
    for attr in SERVICE_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, None, raising=False)

    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        return netsec.SSRFCheckResult(safe=True, resolved_ip="203.0.113.10",
                                      resolved_ips=("203.0.113.10",))

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    monkeypatch.setattr(links, "DEFAULT_TRANSPORT", None)
    yield


def _status(service_keys: frozenset[str], *, on: bool = True):
    ctx = ReportContext(in_container=False, platform="linux", telegram_configured=False,
                        browser_installed=False, service_keys=service_keys)
    statuses = registry.report({"link_reputation": on}, ctx, use_cache=False)
    return registry.statuses_by_key(statuses)["link_reputation"]


def test_link_reputation_is_a_policy_switch_on_by_default_low_risk_and_claims_no_tool():
    cap = registry.get("link_reputation")
    assert cap is capability.CAPABILITY
    assert cap.tools == () and cap.default_enabled is True and cap.risk == "low"
    assert cap.label == "Check links with Google Safe Browsing"
    assert registry.default_switches()["link_reputation"] is True
    assert registry.capability_for_tool("security.check_scam") is not cap


def test_it_is_blocked_until_a_safe_browsing_or_web_risk_key_exists_with_a_plain_fix():
    blocked = _status(frozenset())
    assert blocked.effective == "blocked"
    assert blocked.reason == "Add a Google Safe Browsing or Web Risk key in Security → Service keys."
    assert _status(frozenset({"safe_browsing"})).effective == "on"
    assert _status(frozenset({"web_risk"})).effective == "on"
    assert _status(frozenset({"safe_browsing"}), on=False).effective == "off"


def test_a_hibp_or_virustotal_key_alone_does_not_unblock_it():
    assert _status(frozenset({"hibp"})).effective == "blocked"
    assert _status(frozenset({"virustotal"})).effective == "blocked"
    assert _status(frozenset({"hibp", "virustotal"})).effective == "blocked"


def test_its_settings_default_to_sixty_a_minute_and_two_thousand_a_day_within_bounds():
    defaults = registry.settings_defaults("link_reputation")
    assert defaults == {"lookups_per_minute": 60, "lookups_per_day": 2000}
    assert all(SETTING_MIN <= value <= SETTING_MAX for value in defaults.values())
    assert _status(frozenset({"web_risk"})).to_dict()["key"] == "link_reputation"


def test_the_permissions_block_never_tells_the_model_a_link_is_safe():
    for keys, on in ((frozenset(), True), (frozenset({"safe_browsing"}), False),
                     (frozenset({"safe_browsing"}), True)):
        block = render_permissions_block([_status(keys, on=on)])
        lowered = block.lower().replace("safe browsing", "")
        assert "is safe" not in lowered and "are safe" not in lowered and "safe link" not in lowered
    denied = capability.CAPABILITY.when_denied
    assert "never describe a link as safe" in denied


@pytest.mark.asyncio
async def test_the_report_follows_a_key_saved_or_removed_without_a_restart(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.org")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    rep = LinkReputation(svc, transport=httpx.MockTransport(handler))
    url = "https://shop.example.org/item"
    assert (await rep.check_one(url, purpose="chat")).service_status == "no_key"
    assert await rep.remote_configured() is False

    await svc.set_service_key("safe_browsing", GOOGLE_KEY, actor_id=user.id)
    report = await rep.check_one(url, purpose="chat")
    assert report.service_status == "not_listed" and report.service == "safe_browsing"
    assert seen[-1].headers["X-Goog-Api-Key"] == GOOGLE_KEY
    assert await rep.remote_configured() is True

    await svc.set_capabilities({"link_reputation": False}, actor_id=user.id)
    assert (await rep.check_one("https://other.example.org/", purpose="chat")).service_status == "off"
    await svc.set_capabilities({"link_reputation": True}, actor_id=user.id)

    await svc.set_service_key("safe_browsing", None, actor_id=user.id)
    assert (await rep.check_one("https://third.example.org/", purpose="chat")).service_status == "no_key"
    assert len(seen) == 1

    status = await rep.status()
    assert status["capability"] == "blocked" and status["service"] is None
    assert GOOGLE_KEY not in json.dumps(status)


@pytest.mark.asyncio
async def test_the_owners_limits_reach_the_service_without_a_restart(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.org")
    await svc.set_service_key("web_risk", GOOGLE_KEY, actor_id=user.id)
    await svc.set_capability_settings("link_reputation", {"lookups_per_minute": 1}, actor_id=user.id)
    rep = LinkReputation(svc, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service_status == "not_listed"
    assert (await rep.check_one("https://b.example.org/", purpose="chat")).service_status == "rate_limited"
    status = await rep.status()
    assert status["service"] == "web_risk" and status["lookups_per_minute"] == 1


@pytest.mark.asyncio
async def test_an_env_key_unblocks_it_and_a_stored_key_is_not_needed(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    assert (await svc.capability_statuses())["link_reputation"].effective == "blocked"
    monkeypatch.setattr(settings, "WEB_RISK_API_KEY", GOOGLE_KEY, raising=False)
    svc.invalidate()
    assert (await svc.capability_statuses())["link_reputation"].effective == "on"
    assert (await svc.service_key_status())["web_risk"] == {"key_from_env": True, "key_stored": False}
    rep = LinkReputation(svc, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service == "web_risk"
