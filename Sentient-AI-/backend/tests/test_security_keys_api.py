"""Tests for the Service keys routes (/api/security/keys): they prove every
route is owner-only, the list answers booleans and never a key, an unknown
service is a 404 and a malformed key a 422 that never echo the input, a key
the environment already provides is refused with 409, testing runs the
service's own check and stores nothing, saving stores only a key that passed
(a stub tester refuses to store), a blob that no longer decrypts is never
overwritten (409), removing a key leaves the environment's untouched, tests
and saves share five attempts a minute per owner and service (429 with
Retry-After), a saved key reaches the report fact at once, and no response or
log line ever carries a key.

Why it exists: these routes are the only way a key for an outside security
service enters the install (decisions 2: nothing is sent anywhere without
the owner's own key). The real testers belong to their skills and reach the
network, so every test here installs scripted testers; an autouse guard
fails any outbound httpx request. Keys are built by concatenation so no
scanner sees a literal one.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import os
import uuid
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
import structlog
from sqlalchemy import select

from api.routes import security_keys as key_routes
from core.config import SERVICE_KEY_FIELDS, settings
from models.audit import AuditLog
from services.installation import UNREADABLE_SERVICE_KEYS_MESSAGE, InstallationService
from services.reputation import keys as key_registry
from services.reputation.keys import KeyTestResult
from tests.conftest import auth_headers, make_user

OWNER = {"email": "owner@example.com", "password": "password-123", "name": "Owner"}
GOOGLE_KEY = "AIza" + "FAKEfake" * 4 + "000"
OTHER_GOOGLE_KEY = "AIza" + "OTHERkey" * 4 + "111"
HIBP_KEY = "a" * 32
VIRUSTOTAL_KEY = "b" * 64

_real_send = httpx.AsyncClient.send
_MISSING = object()


class ScriptedTesters:
    """Stands in for every service's tester: records each key it is handed
    and answers what the test set (default: accepted)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.answers: dict[str, object] = {}

    def for_service(self, name: str):
        async def tester(key: str) -> KeyTestResult:
            self.calls.append((name, key))
            answer = self.answers.get(name, KeyTestResult(True, "The service accepted the key."))
            if isinstance(answer, BaseException):
                raise answer
            if callable(answer):
                return await answer(key)  # type: ignore[no-any-return]
            return answer  # type: ignore[return-value]

        return tester


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Any httpx request that is not the test client talking to the app fails
    the test (host only in the message: a URL could carry a key)."""

    async def guarded_send(self, request, *args, **kwargs):
        if request.url.host != "testserver":
            raise AssertionError(f"network call to {request.url.host}")
        return await _real_send(self, request, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "send", guarded_send)


@pytest.fixture
def testers(monkeypatch) -> ScriptedTesters:
    """The real rows with scripted testers, as the routes see them."""
    scripted = ScriptedTesters()
    specs = tuple(
        dataclasses.replace(spec, tester=scripted.for_service(spec.name))
        for spec in key_registry.service_key_specs()
    )
    by_name = {spec.name: spec for spec in specs}
    monkeypatch.setattr(key_routes, "service_key_specs", lambda: specs)
    monkeypatch.setattr(key_routes, "spec_for", by_name.get)
    return scripted


@pytest_asyncio.fixture
async def env(client, session_factory, monkeypatch):
    """The installation service the lifespan will own, on app.state, with no
    service key in the environment and fresh rate-limit buckets."""
    from main import app

    for attr in SERVICE_KEY_FIELDS.values():
        monkeypatch.setattr(settings, attr, None, raising=False)
    key_routes._reset_rate_limits()
    installation = InstallationService(session_factory)
    previous = getattr(app.state, "installation", _MISSING)
    app.state.installation = installation
    try:
        yield SimpleNamespace(installation=installation, app=app)
    finally:
        if previous is _MISSING:
            if hasattr(app.state, "installation"):
                delattr(app.state, "installation")
        else:
            app.state.installation = previous
        key_routes._reset_rate_limits()


async def _owner(client) -> tuple[dict[str, str], uuid.UUID]:
    resp = await client.post("/api/setup/owner", json=OWNER)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return auth_headers(body["access_token"]), uuid.UUID(body["user"]["id"])


async def _audit(session_factory, action: str) -> list[AuditLog]:
    async with session_factory() as s:
        return list(
            (await s.execute(select(AuditLog).where(AuditLog.action == action))).scalars()
        )


@pytest.fixture
def captured_logs(monkeypatch):
    """structlog capture for the routes and the installation service, each
    with a fresh logger bound inside the capture (see test_setup_api)."""
    from services import installation as installation_module

    with structlog.testing.capture_logs() as logs:
        for module in (key_routes, installation_module):
            monkeypatch.setattr(module, "logger", structlog.get_logger(module.__name__))
        yield logs


# ── access ───────────────────────────────────────────────────────────────────

_ROUTES = [
    ("GET", "/api/security/keys"),
    ("POST", "/api/security/keys/safe_browsing/test"),
    ("PUT", "/api/security/keys/safe_browsing"),
    ("DELETE", "/api/security/keys/safe_browsing"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", _ROUTES)
async def test_every_key_route_refuses_a_signed_out_caller_and_a_member(
    client, env, testers, session_factory, method, path
):
    await _owner(client)
    anonymous = await client.request(method, path, json={"key": GOOGLE_KEY})
    assert anonymous.status_code in (401, 403)
    _member, token = await make_user(session_factory, "member@example.com")
    member = await client.request(method, path, json={"key": GOOGLE_KEY}, headers=auth_headers(token))
    assert member.status_code == 403
    assert member.json()["detail"] == "Only the owner of this install can change this."
    assert testers.calls == []
    assert await env.installation.service_key("safe_browsing") is None


@pytest.mark.asyncio
async def test_the_routes_answer_503_until_the_installation_service_is_wired(client, testers):
    from main import app

    resp = await client.post("/api/setup/owner", json=OWNER)
    headers = auth_headers(resp.json()["access_token"])
    previous = getattr(app.state, "installation", _MISSING)
    if previous is not _MISSING:
        delattr(app.state, "installation")
    try:
        assert (await client.get("/api/security/keys", headers=headers)).status_code == 503
    finally:
        if previous is not _MISSING:
            app.state.installation = previous


# ── listing ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_list_names_every_service_with_booleans_only_and_never_a_key(
    client, env, testers, monkeypatch
):
    headers, owner_id = await _owner(client)
    await env.installation.set_service_key("hibp", HIBP_KEY, actor_id=owner_id)
    monkeypatch.setattr(settings, "WEB_RISK_API_KEY", OTHER_GOOGLE_KEY, raising=False)
    env.installation.invalidate()

    resp = await client.get("/api/security/keys", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["secrets_unreadable"] is False
    rows = {row["name"]: row for row in body["services"]}
    assert list(rows) == ["safe_browsing", "web_risk", "hibp", "virustotal"]
    for row in body["services"]:
        assert set(row) == {
            "name", "label", "used_for", "note", "console_url", "key_hint",
            "key_from_env", "key_stored",
        }
    assert (rows["hibp"]["key_from_env"], rows["hibp"]["key_stored"]) == (False, True)
    assert (rows["web_risk"]["key_from_env"], rows["web_risk"]["key_stored"]) == (True, False)
    assert rows["virustotal"]["label"] == "VirusTotal"
    assert HIBP_KEY not in resp.text and OTHER_GOOGLE_KEY not in resp.text


# ── validation ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix", [("POST", "/test"), ("PUT", ""), ("DELETE", "")])
async def test_an_unknown_service_is_a_404_that_never_echoes_the_name(
    client, env, testers, method, suffix
):
    headers, _ = await _owner(client)
    name = "AIzaLooksLikeAKey" + "x" * 22
    resp = await client.request(
        method, f"/api/security/keys/{name}{suffix}", json={"key": GOOGLE_KEY}, headers=headers
    )
    assert resp.status_code == 404
    assert resp.json() == {"detail": "No such service."}
    assert name not in resp.text and GOOGLE_KEY not in resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix", [("POST", "/test"), ("PUT", "")])
@pytest.mark.parametrize(
    "content",
    [
        b'{"key": "AIza-too-short-SECRETVALUE"}',
        b'{"key": 12345}',
        b'["AIza-not-an-object-SECRETVALUE"]',
        b"AIza-not-json-SECRETVALUE",
        b'{"key": "' + b"A" * 5000 + b'"}',
    ],
    ids=["wrong_shape", "not_text", "not_an_object", "not_json", "too_large"],
)
async def test_a_malformed_key_or_body_is_a_422_that_never_echoes_it(
    client, env, testers, method, suffix, content
):
    headers, _ = await _owner(client)
    resp = await client.request(
        method,
        f"/api/security/keys/safe_browsing{suffix}",
        content=content,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert resp.status_code == 422
    assert "SECRETVALUE" not in resp.text and "AAAA" not in resp.text
    assert testers.calls == []
    assert await env.installation.service_key("safe_browsing") is None


@pytest.mark.asyncio
async def test_each_service_checks_its_own_format(client, env, testers):
    headers, _ = await _owner(client)
    wrong = await client.put(
        "/api/security/keys/virustotal", json={"key": HIBP_KEY}, headers=headers
    )
    assert wrong.status_code == 422
    assert wrong.json() == {"detail": "A VirusTotal key is 64 characters, 0-9 and a-f."}
    hibp = await client.put("/api/security/keys/hibp", json={"key": VIRUSTOTAL_KEY}, headers=headers)
    assert hibp.json() == {"detail": "A Have I Been Pwned key is 32 characters, 0-9 and a-f."}
    # Surrounding spaces are stripped; nothing else is changed.
    saved = await client.put(
        "/api/security/keys/virustotal", json={"key": f"  {VIRUSTOTAL_KEY}\n"}, headers=headers
    )
    assert saved.status_code == 200
    assert testers.calls == [("virustotal", VIRUSTOTAL_KEY)]
    assert await env.installation.service_key("virustotal") == VIRUSTOTAL_KEY


@pytest.mark.asyncio
@pytest.mark.parametrize("method,suffix", [("POST", "/test"), ("PUT", "")])
async def test_a_typed_key_the_environment_already_provides_is_refused_with_409(
    client, env, testers, monkeypatch, method, suffix
):
    headers, _ = await _owner(client)
    monkeypatch.setattr(settings, "SAFE_BROWSING_API_KEY", OTHER_GOOGLE_KEY, raising=False)
    resp = await client.request(
        method, f"/api/security/keys/safe_browsing{suffix}", json={"key": GOOGLE_KEY}, headers=headers
    )
    assert resp.status_code == 409
    assert resp.json() == {
        "detail": "Google Safe Browsing is set in the server's .env file; change it there."
    }
    assert testers.calls == []
    env.installation.invalidate()
    assert (await env.installation.service_key_status())["safe_browsing"]["key_stored"] is False


# ── testing ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_testing_runs_the_services_own_check_and_stores_nothing(
    client, env, testers, session_factory
):
    headers, _ = await _owner(client)
    resp = await client.post(
        "/api/security/keys/web_risk/test", json={"key": GOOGLE_KEY}, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "detail": "The service accepted the key."}
    assert testers.calls == [("web_risk", GOOGLE_KEY)]
    assert await env.installation.service_key("web_risk") is None
    assert await _audit(session_factory, "service_key_updated") == []


@pytest.mark.asyncio
async def test_testing_without_a_typed_key_uses_the_configured_one_or_asks_for_one(
    client, env, testers, monkeypatch
):
    headers, owner_id = await _owner(client)
    for body in ({}, {"key": "   "}, {"key": None}):
        resp = await client.post("/api/security/keys/hibp/test", json=body, headers=headers)
        assert resp.json() == {"ok": False, "error": "Enter a key."}
    empty = await client.post("/api/security/keys/hibp/test", headers=headers)
    assert empty.json() == {"ok": False, "error": "Enter a key."}
    assert testers.calls == []

    await env.installation.set_service_key("hibp", HIBP_KEY, actor_id=owner_id)
    stored = await client.post("/api/security/keys/hibp/test", json={}, headers=headers)
    assert stored.json()["ok"] is True
    monkeypatch.setattr(settings, "HIBP_API_KEY", "c" * 32, raising=False)
    from_env = await client.post("/api/security/keys/hibp/test", json={}, headers=headers)
    assert from_env.json()["ok"] is True
    assert testers.calls == [("hibp", HIBP_KEY), ("hibp", "c" * 32)]


@pytest.mark.asyncio
async def test_a_refused_raising_or_slow_test_answers_ok_false_and_never_quotes_the_key(
    client, env, testers, monkeypatch
):
    headers, _ = await _owner(client)
    url = "/api/security/keys/safe_browsing/test"

    testers.answers["safe_browsing"] = KeyTestResult(False, f"Google rejected {GOOGLE_KEY}.")
    refused = await client.post(url, json={"key": GOOGLE_KEY}, headers=headers)
    assert refused.json() == {"ok": False, "error": "Google rejected [redacted]."}

    testers.answers["safe_browsing"] = RuntimeError(f"HTTP 400 for key={GOOGLE_KEY}")
    raised = await client.post(url, json={"key": GOOGLE_KEY}, headers=headers)
    assert raised.json() == {"ok": False, "error": "Could not check the key (RuntimeError)."}

    async def slow(_key: str) -> KeyTestResult:
        await asyncio.sleep(5)
        return KeyTestResult(True, "late")

    testers.answers["safe_browsing"] = slow
    monkeypatch.setattr(key_routes, "_TEST_TIMEOUT_S", 0.05)
    timed_out = await client.post(url, json={"key": GOOGLE_KEY}, headers=headers)
    assert timed_out.json() == {"ok": False, "error": "Could not check the key (TimeoutError)."}

    async def wrong_type(_key: str):
        return {"ok": True}

    testers.answers["safe_browsing"] = wrong_type
    odd = await client.post(url, json={"key": GOOGLE_KEY}, headers=headers)
    assert odd.json() == {"ok": False, "error": "Could not check the key (dict)."}
    for resp in (refused, raised, timed_out, odd):
        assert resp.status_code == 200 and GOOGLE_KEY not in resp.text
    assert await env.installation.service_key("safe_browsing") is None


# ── saving and removing ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_saving_tests_first_and_stores_only_a_key_that_passed(
    client, env, testers, session_factory
):
    headers, owner_id = await _owner(client)
    testers.answers["virustotal"] = KeyTestResult(False, "VirusTotal rejected the key.")
    refused = await client.put(
        "/api/security/keys/virustotal", json={"key": VIRUSTOTAL_KEY}, headers=headers
    )
    assert refused.status_code == 400
    assert refused.json() == {"detail": "VirusTotal rejected the key."}
    assert await env.installation.service_key("virustotal") is None
    assert await _audit(session_factory, "service_key_updated") == []

    testers.answers.pop("virustotal")
    saved = await client.put(
        "/api/security/keys/virustotal", json={"key": VIRUSTOTAL_KEY}, headers=headers
    )
    assert saved.status_code == 200
    assert saved.json() == {
        "ok": True,
        "service": {
            "name": "virustotal",
            "label": "VirusTotal",
            "used_for": key_registry.spec_for("virustotal").used_for,  # type: ignore[union-attr]
            "note": key_registry.spec_for("virustotal").note,  # type: ignore[union-attr]
            "console_url": "https://www.virustotal.com/gui/my-apikey",
            "key_hint": "64 hex characters",
            "key_from_env": False,
            "key_stored": True,
        },
        "detail": "The service accepted the key.",
    }
    assert VIRUSTOTAL_KEY not in saved.text
    assert await env.installation.service_key("virustotal") == VIRUSTOTAL_KEY
    (row,) = await _audit(session_factory, "service_key_updated")
    assert (row.user_id, row.endpoint, row.request_data) == (
        owner_id,
        "/api/security/keys/virustotal",
        {"service": "virustotal", "key_stored": True},
    )


@pytest.mark.asyncio
async def test_a_stub_tester_refuses_to_store_a_key(client, env, monkeypatch):
    """Until a skill's tester exists, no key for it can be saved: the lazy
    tester of a module that is not built answers its "cannot be checked yet"
    sentence, which saving turns into a 400."""
    headers, _ = await _owner(client)
    real = key_registry.spec_for("hibp")
    assert real is not None
    stub = dataclasses.replace(
        real,
        tester=key_registry._lazy_tester(
            "services.breach.not_built_" + uuid.uuid4().hex,
            "check_key",
            not_built="Have I Been Pwned keys cannot be checked yet.",
        ),
    )
    monkeypatch.setattr(key_routes, "spec_for", {"hibp": stub}.get)
    resp = await client.put("/api/security/keys/hibp", json={"key": HIBP_KEY}, headers=headers)
    assert resp.status_code == 400
    assert resp.json() == {"detail": "Have I Been Pwned keys cannot be checked yet."}
    assert await env.installation.service_key("hibp") is None


@pytest.mark.asyncio
async def test_saving_or_removing_is_refused_while_the_stored_blob_cannot_be_read(
    client, env, testers, monkeypatch, session_factory
):
    headers, owner_id = await _owner(client)
    await env.installation.set_service_key("web_risk", GOOGLE_KEY, actor_id=owner_id)
    monkeypatch.setattr(
        settings, "ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    )
    env.installation.invalidate()

    listing = await client.get("/api/security/keys", headers=headers)
    assert listing.json()["secrets_unreadable"] is True
    saved = await client.put(
        "/api/security/keys/safe_browsing", json={"key": OTHER_GOOGLE_KEY}, headers=headers
    )
    removed = await client.delete("/api/security/keys/web_risk", headers=headers)
    for resp in (saved, removed):
        assert resp.status_code == 409
        assert resp.json() == {"detail": UNREADABLE_SERVICE_KEYS_MESSAGE}
    assert testers.calls == []
    assert len(await _audit(session_factory, "service_key_updated")) == 1
    status = await client.get("/api/setup/status")
    assert status.json()["secrets_unreadable"] is True


@pytest.mark.asyncio
async def test_removing_deletes_only_the_stored_key_and_leaves_the_environment_key(
    client, env, testers, monkeypatch
):
    headers, owner_id = await _owner(client)
    await env.installation.set_service_key("safe_browsing", GOOGLE_KEY, actor_id=owner_id)
    monkeypatch.setattr(settings, "SAFE_BROWSING_API_KEY", OTHER_GOOGLE_KEY, raising=False)

    resp = await client.delete("/api/security/keys/safe_browsing", headers=headers)
    assert resp.status_code == 204 and resp.content == b""
    status = (await env.installation.service_key_status())["safe_browsing"]
    assert status == {"key_from_env": True, "key_stored": False}
    assert await env.installation.service_key("safe_browsing") == OTHER_GOOGLE_KEY
    # Removing a key that is not stored is not an error.
    again = await client.delete("/api/security/keys/safe_browsing", headers=headers)
    assert again.status_code == 204


@pytest.mark.asyncio
async def test_tests_and_saves_share_five_attempts_a_minute_per_service_then_answer_429(
    client, env, testers
):
    headers, _ = await _owner(client)
    for _ in range(3):
        resp = await client.post(
            "/api/security/keys/safe_browsing/test", json={"key": GOOGLE_KEY}, headers=headers
        )
        assert resp.status_code == 200
    for _ in range(2):
        resp = await client.put(
            "/api/security/keys/safe_browsing", json={"key": GOOGLE_KEY}, headers=headers
        )
        assert resp.status_code == 200
    limited = await client.post(
        "/api/security/keys/safe_browsing/test", json={"key": GOOGLE_KEY}, headers=headers
    )
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 61
    assert GOOGLE_KEY not in limited.text
    assert len(testers.calls) == 5
    # Another service has its own bucket, and removing is never limited.
    other = await client.post(
        "/api/security/keys/web_risk/test", json={"key": GOOGLE_KEY}, headers=headers
    )
    assert other.status_code == 200
    assert (await client.delete("/api/security/keys/safe_browsing", headers=headers)).status_code == 204


# ── the report fact and the leak guards ─────────────────────────────────────


@pytest.mark.asyncio
async def test_a_saved_key_reaches_the_report_fact_at_once_and_a_removal_takes_it_away(
    client, env, testers
):
    headers, _ = await _owner(client)
    assert (await env.installation.context()).service_keys == frozenset()
    await client.put("/api/security/keys/hibp", json={"key": HIBP_KEY}, headers=headers)
    assert (await env.installation.context()).service_keys == frozenset({"hibp"})
    await client.delete("/api/security/keys/hibp", headers=headers)
    assert (await env.installation.context()).service_keys == frozenset()


@pytest.mark.asyncio
async def test_no_response_or_log_line_ever_carries_a_key(
    client, env, testers, captured_logs, session_factory
):
    headers, _ = await _owner(client)
    responses = [
        await client.post(
            "/api/security/keys/safe_browsing/test", json={"key": GOOGLE_KEY}, headers=headers
        ),
        await client.put(
            "/api/security/keys/safe_browsing", json={"key": GOOGLE_KEY}, headers=headers
        ),
        await client.get("/api/security/keys", headers=headers),
    ]
    testers.answers["safe_browsing"] = RuntimeError(f"failed for {GOOGLE_KEY}")
    responses.append(
        await client.post(
            "/api/security/keys/safe_browsing/test", json={"key": GOOGLE_KEY}, headers=headers
        )
    )
    responses.append(await client.delete("/api/security/keys/safe_browsing", headers=headers))
    for resp in responses:
        assert GOOGLE_KEY not in resp.text
    events = [entry["event"] for entry in captured_logs]
    assert {"security_key_tested", "security_key_saved", "security_key_removed"} <= set(events)
    for entry in captured_logs:
        assert GOOGLE_KEY not in repr(entry)
        if entry["event"].startswith("security_key_"):
            assert set(entry) <= {"event", "log_level", "service", "ok", "error_type"}
    for row in await _audit(session_factory, "service_key_updated"):
        assert GOOGLE_KEY not in repr(row.request_data)
