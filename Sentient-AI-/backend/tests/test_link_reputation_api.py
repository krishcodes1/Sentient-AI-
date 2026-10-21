"""Tests for the owner's link-check routes (security10 S4): GET
/api/security/link-reputation/status and the Google rows of the shared Service keys routes
with S4's real key tester behind them. They prove the status is owner-only, answers 503 until
the service is wired and carries counts and limits but never a key, a link or a host; saving a
Google key tests it against Google's own test page first and stores it only when Google
accepted it; a key in the wrong format is refused with 422 before anything is sent and is never
echoed; a key typed while the server's .env provides one is refused with 409 (the configured
key can still be tested); and the key list names both Google services with booleans only.

Why it exists: these routes are the owner's only window on what the lookups cost and the only
way a Google key enters the install (decisions 2: nothing is sent without the owner's own key).
No network: core.network_security.check_ssrf is replaced and links.DEFAULT_TRANSPORT (the seam
the key routes' tester uses) is an httpx.MockTransport. Keys are built by concatenation so no
scanner sees a literal one.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import pytest_asyncio

import core.network_security as netsec
from api.routes import security_keys as key_routes
from core.config import SERVICE_KEY_FIELDS, settings
from services.installation import InstallationService
from services.reputation import links
from services.reputation.links import LinkReputation
from tests.conftest import auth_headers, make_user

OWNER = {"email": "owner@example.com", "password": "password-123", "name": "Owner"}
GOOGLE_KEY = "AIza" + "FAKEfake" * 4 + "000"
OTHER_GOOGLE_KEY = "AIza" + "OTHERkey" * 4 + "111"
PUBLIC_IP = "203.0.113.10"   # TEST-NET-3; check_ssrf is replaced
STATUS_KEYS = {
    "capability", "reason", "service", "both_keys", "lookups_last_minute", "lookups_per_minute",
    "lookups_last_day", "lookups_per_day", "counting_since", "cache_entries",
    "dangerous_found_last_day", "not_checked_last_day", "cooling_down_until", "last_problem",
}
_MISSING = object()


class Google:
    """Both Google endpoints behind MockTransport: ``answer`` is the status every request gets
    (200 means "no match" except for ``listed`` URLs); every request is recorded."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.answer = 200
        self.listed: dict[str, str] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.answer != 200:
            return httpx.Response(self.answer, json={"error": {"status": "PERMISSION_DENIED"}})
        if request.url.host == "safebrowsing.googleapis.com":
            entries = json.loads(request.content)["threatInfo"]["threatEntries"]
            matches = [{"threatType": self.listed[e["url"]], "threat": {"url": e["url"]}}
                       for e in entries if e["url"] in self.listed]
            return httpx.Response(200, json={"matches": matches} if matches else {})
        return httpx.Response(200, json={})


@pytest.fixture
def google(monkeypatch) -> Iterator[Google]:
    """Google as the key routes' tester and the status service reach it, with no DNS."""
    fake = Google()

    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        return netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,))

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    monkeypatch.setattr(links, "DEFAULT_TRANSPORT", httpx.MockTransport(fake.handler))
    yield fake


@pytest_asyncio.fixture
async def env(client, session_factory, monkeypatch):
    """The installation service and S4's service on app.state, as wire_services leaves them,
    with no service key in the environment and fresh rate-limit buckets."""
    from main import app

    for attr in SERVICE_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, None, raising=False)
    key_routes._reset_rate_limits()
    installation = InstallationService(session_factory)
    service = LinkReputation(installation)
    saved = {name: getattr(app.state, name, _MISSING) for name in ("installation", "link_reputation")}
    app.state.installation = installation
    app.state.link_reputation = service
    try:
        yield SimpleNamespace(installation=installation, service=service, app=app)
    finally:
        for name, previous in saved.items():
            if previous is _MISSING:
                if hasattr(app.state, name):
                    delattr(app.state, name)
            else:
                setattr(app.state, name, previous)
        key_routes._reset_rate_limits()


async def _owner(client) -> tuple[dict[str, str], uuid.UUID]:
    resp = await client.post("/api/setup/owner", json=OWNER)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return auth_headers(body["access_token"]), uuid.UUID(body["user"]["id"])


STATUS = "/api/security/link-reputation/status"


@pytest.mark.asyncio
async def test_link_check_status_is_owner_only(client, env, google, session_factory):
    headers, _ = await _owner(client)
    anonymous = await client.get(STATUS)
    assert anonymous.status_code in (401, 403)
    _member, token = await make_user(session_factory, "member@example.com")
    member = await client.get(STATUS, headers=auth_headers(token))
    assert member.status_code == 403
    owner = await client.get(STATUS, headers=headers)
    assert owner.status_code == 200 and set(owner.json()) == STATUS_KEYS
    assert google.requests == []


@pytest.mark.asyncio
async def test_link_check_status_answers_503_until_wired(client, env, google):
    headers, _ = await _owner(client)
    delattr(env.app.state, "link_reputation")
    resp = await client.get(STATUS, headers=headers)
    assert resp.status_code == 503
    assert resp.json()["detail"] == "The server is still starting. Try again shortly."


@pytest.mark.asyncio
async def test_link_check_status_carries_no_key_no_link_and_no_host(client, env, google):
    headers, owner_id = await _owner(client)
    # Without a key: blocked with the capability's own reason, no service, nothing counted.
    blocked = (await client.get(STATUS, headers=headers)).json()
    assert blocked["capability"] == "blocked" and blocked["service"] is None
    assert blocked["reason"] == "Add a Google Safe Browsing or Web Risk key in Security → Service keys."
    await env.installation.set_service_key("safe_browsing", GOOGLE_KEY, actor_id=owner_id)
    google.listed["https://paypa1-verify.xyz/login"] = "SOCIAL_ENGINEERING"
    reports = await env.service.check(
        ["https://paypa1-verify.xyz/login?session=abc", "https://news.example.org/a"], purpose="chat"
    )
    assert [r.level for r in reports] == ["dangerous", "no_known_threats"]
    resp = await client.get(STATUS, headers=headers)
    body = resp.json()
    assert set(body) == STATUS_KEYS
    assert (body["capability"], body["service"], body["both_keys"]) == ("on", "safe_browsing", False)
    assert body["lookups_last_minute"] == 1 and body["lookups_per_minute"] == 60
    assert body["lookups_per_day"] == 2000 and body["dangerous_found_last_day"] == 1
    for secret in (GOOGLE_KEY, "paypa1", "news.example.org", "session", "abc"):
        assert secret not in resp.text, secret


@pytest.mark.asyncio
async def test_saving_a_google_key_tests_it_first_and_stores_only_on_success(client, env, google):
    headers, _ = await _owner(client)
    google.answer = 403
    refused = await client.put("/api/security/keys/safe_browsing", json={"key": GOOGLE_KEY},
                               headers=headers)
    assert refused.status_code == 400
    assert refused.json()["detail"] == (
        "Google refused the key: the Safe Browsing API is not turned on for this key's project, "
        "or the key is restricted to other APIs."
    )
    assert await env.installation.service_key("safe_browsing") is None
    # The test looked up Google's own test page, with the key in a header and never the URL.
    (request,) = google.requests
    assert request.url.host == "safebrowsing.googleapis.com"
    assert request.headers["X-Goog-Api-Key"] == GOOGLE_KEY and GOOGLE_KEY not in str(request.url)
    assert json.loads(request.content)["threatInfo"]["threatEntries"] == [
        {"url": links.SAFE_BROWSING_TEST_URL}
    ]
    google.answer = 200
    saved = await client.put("/api/security/keys/web_risk", json={"key": GOOGLE_KEY}, headers=headers)
    assert saved.status_code == 200
    assert saved.json()["service"]["key_stored"] is True and GOOGLE_KEY not in saved.text
    assert await env.installation.service_key("web_risk") == GOOGLE_KEY
    assert google.requests[-1].url.host == "webrisk.googleapis.com"
    assert google.requests[-1].url.params["uri"] == links.WEB_RISK_TEST_URL
    # The key test counted against neither the owner's limits nor the cache.
    status = (await client.get(STATUS, headers=headers)).json()
    assert status["lookups_last_day"] == 0 and status["cache_entries"] == 0
    assert status["service"] == "web_risk"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix", [("POST", "/test"), ("PUT", "")])
async def test_a_google_key_in_the_wrong_format_is_refused_without_echoing_it(
    client, env, google, method, suffix
):
    headers, _ = await _owner(client)
    typed = "AIza-not-a-key-SECRETVALUE"
    resp = await client.request(method, f"/api/security/keys/safe_browsing{suffix}",
                                json={"key": typed}, headers=headers)
    assert resp.status_code == 422
    assert resp.json() == {"detail": (
        "That does not look like a Google API key (they start with AIza and are 39 characters long)."
    )}
    assert "SECRETVALUE" not in resp.text
    assert google.requests == []
    assert await env.installation.service_key("safe_browsing") is None


@pytest.mark.asyncio
async def test_typing_a_google_key_the_environment_provides_is_refused_with_409(
    client, env, google, monkeypatch
):
    headers, _ = await _owner(client)
    monkeypatch.setattr(settings, "SAFE_BROWSING_API_KEY", OTHER_GOOGLE_KEY, raising=False)
    env.installation.invalidate()
    for method, suffix in (("POST", "/test"), ("PUT", "")):
        resp = await client.request(method, f"/api/security/keys/safe_browsing{suffix}",
                                    json={"key": GOOGLE_KEY}, headers=headers)
        assert resp.status_code == 409
        assert resp.json()["detail"] == (
            "Google Safe Browsing is set in the server's .env file; change it there."
        )
        assert GOOGLE_KEY not in resp.text and OTHER_GOOGLE_KEY not in resp.text
    assert google.requests == []
    # With nothing typed, the configured key is the one tested.
    tested = await client.post("/api/security/keys/safe_browsing/test", json={}, headers=headers)
    assert tested.json() == {"ok": True, "detail": "Google answered: the key works."}
    assert google.requests[-1].headers["X-Goog-Api-Key"] == OTHER_GOOGLE_KEY
    assert OTHER_GOOGLE_KEY not in tested.text


@pytest.mark.asyncio
async def test_the_key_list_names_both_google_services_with_booleans_only(client, env, google,
                                                                           monkeypatch):
    headers, owner_id = await _owner(client)
    await env.installation.set_service_key("safe_browsing", GOOGLE_KEY, actor_id=owner_id)
    monkeypatch.setattr(settings, "WEB_RISK_API_KEY", OTHER_GOOGLE_KEY, raising=False)
    env.installation.invalidate()
    resp = await client.get("/api/security/keys", headers=headers)
    assert resp.status_code == 200
    rows: dict[str, dict[str, Any]] = {row["name"]: row for row in resp.json()["services"]}
    assert rows["safe_browsing"]["label"] == "Google Safe Browsing"
    assert rows["web_risk"]["label"] == "Google Web Risk"
    assert (rows["safe_browsing"]["key_stored"], rows["safe_browsing"]["key_from_env"]) == (True, False)
    assert (rows["web_risk"]["key_stored"], rows["web_risk"]["key_from_env"]) == (False, True)
    for name in ("safe_browsing", "web_risk"):
        assert rows[name]["key_hint"] == "Starts with AIza, 39 characters"
        assert isinstance(rows[name]["key_stored"], bool) and isinstance(rows[name]["key_from_env"], bool)
    assert GOOGLE_KEY not in resp.text and OTHER_GOOGLE_KEY not in resp.text
    # Both keys usable: the status says Web Risk is used.
    status = (await client.get(STATUS, headers=headers)).json()
    assert (status["service"], status["both_keys"]) == ("web_risk", True)
