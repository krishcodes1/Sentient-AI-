"""Tests for the "purchases" capability and its settings: the declaration (off
by default, high risk, claims browser.checkout only), availability (native Mac
or Windows only, with the container reason), the settings defaults on the
report, the InstallationService's capability_settings / set_capability_settings
/ purchase_caps, and the owner-only PUT /api/capabilities/{key}/settings route.

Why it exists: Buying is the ability the owner turns on deliberately and bounds
with two numbers; each seam here is where a mistake would let a purchase run
with the switch off, in a container with no vault, or past a cap that never
reached the toolkit. Nothing here touches a browser, a card or the network.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import select

from models.audit import AuditLog
from services import capabilities as registry
from services.capabilities import purchases
from services.capabilities.base import CapabilityStatus, ReportContext
from services.installation import SETTING_MAX, InstallationService
from tests.conftest import auth_headers, make_user


def _ctx(**overrides):
    base = {
        "in_container": False,
        "platform": "darwin",
        "telegram_configured": False,
        "browser_installed": True,
        "host_platform": "mac",
    }
    return ReportContext(**{**base, **overrides})


# ── declaration ──────────────────────────────────────────────────────────


def test_declaration_is_off_by_default_high_risk_and_claims_checkout_only():
    cap = purchases.CAPABILITY
    assert cap.key == "purchases" and cap.label == "Buy things for me"
    assert cap.default_enabled is False and cap.risk == "high"
    assert cap.tools == ("browser.checkout",)
    assert cap.when_denied == "Buying things is off. Turn on 'Buy things for me' in Permissions."
    assert cap.install is None and cap.probe is None
    assert purchases.PURCHASE_SETTINGS_DEFAULTS == {"per_purchase_cap_usd": 25, "per_day_cap_usd": 50}


def test_registry_claims_checkout_for_purchases_read_for_browser_control_act_for_browser_act():
    assert registry.get("purchases") is purchases.CAPABILITY
    assert registry.capability_for_tool("browser.checkout").key == "purchases"
    assert registry.capability_for_tool("browser.read").key == "browser_control"
    assert registry.capability_for_tool("browser.act").key == "browser_act"
    # Exact names, not the family prefix: checkout must not be claimed twice.
    assert registry.get("browser_control").tools == ("browser.read",)
    assert "purchases" in registry.keys() and registry.default_switches()["purchases"] is False


def test_settings_defaults_are_the_purchase_caps_and_nothing_else():
    assert registry.settings_defaults("purchases") == {"per_purchase_cap_usd": 25, "per_day_cap_usd": 50}
    assert registry.settings_defaults("purchases") is not purchases.PURCHASE_SETTINGS_DEFAULTS
    for key in registry.keys():
        if key != "purchases":
            assert registry.settings_defaults(key) == {}, key
    assert registry.settings_defaults("nope") == {}


# ── availability ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("host_platform", ["mac", "windows"])
def test_available_on_mac_and_windows(host_platform):
    assert purchases.availability(_ctx(host_platform=host_platform)).available is True


def test_container_reason_names_the_vault():
    for ctx in (_ctx(in_container=True), _ctx(host_platform="container")):
        avail = purchases.availability(ctx)
        assert avail.available is False
        assert avail.reason == purchases.CONTAINER_REASON
        assert "container" in avail.reason and "card vault" in avail.reason


def test_linux_is_not_available():
    avail = purchases.availability(_ctx(platform="linux", host_platform="linux"))
    assert avail.available is False and avail.reason == purchases.PLATFORM_REASON
    # An older context without host_platform derives it from sys.platform.
    assert purchases.availability(_ctx(platform="linux", host_platform="")).available is False
    assert purchases.availability(_ctx(platform="win32", host_platform="")).available is True


def test_report_says_off_then_blocked_in_a_container():
    off = registry.statuses_by_key(registry.report({}, _ctx(), use_cache=False))["purchases"]
    assert (off.effective, off.enabled, off.available) == ("off", False, True)
    on = registry.statuses_by_key(
        registry.report({"purchases": True}, _ctx(in_container=True), use_cache=False)
    )["purchases"]
    assert on.effective == "blocked" and on.reason == purchases.CONTAINER_REASON


# ── settings on the status record ────────────────────────────────────────


def test_status_carries_settings_and_serialises_them():
    status = registry.statuses_by_key(registry.report({}, _ctx(), use_cache=False))["purchases"]
    # The registry knows no stored values: an empty, read-only mapping.
    assert dict(status.settings) == {}
    with pytest.raises(TypeError):
        status.settings["per_day_cap_usd"] = 1  # type: ignore[index]
    body = status.to_dict()
    assert body["settings"] == {}
    assert set(body) == set(CapabilityStatus.__dataclass_fields__)


# ── InstallationService ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_capability_settings_are_the_defaults_until_the_owner_changes_them(session_factory):
    svc = InstallationService(session_factory)
    assert await svc.capability_settings("purchases") == {
        "per_purchase_cap_usd": 25,
        "per_day_cap_usd": 50,
    }
    assert await svc.capability_settings("screen") == {}
    with pytest.raises(KeyError):
        await svc.capability_settings("nope")
    assert await svc.purchase_caps() == (Decimal("25"), Decimal("50"))


@pytest.mark.asyncio
async def test_report_fills_the_purchase_settings(session_factory):
    svc = InstallationService(session_factory)
    by_key = registry.statuses_by_key(await svc.report())
    assert dict(by_key["purchases"].settings) == {"per_purchase_cap_usd": 25, "per_day_cap_usd": 50}
    assert dict(by_key["screen"].settings) == {}
    assert by_key["purchases"].to_dict()["settings"]["per_day_cap_usd"] == 50


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key", "patch"),
    [
        ("purchases", {"per_purchase_cap_usd": 0}),
        ("purchases", {"per_purchase_cap_usd": 0.99}),
        ("purchases", {"per_purchase_cap_usd": 25.5}),  # a cap is a whole number of dollars
        ("purchases", {"per_day_cap_usd": 9999.01}),
        ("purchases", {"per_purchase_cap_usd": -5}),
        ("purchases", {"per_day_cap_usd": SETTING_MAX + 1}),
        ("purchases", {"per_day_cap_usd": True}),
        ("purchases", {"per_day_cap_usd": "25"}),
        ("purchases", {"per_day_cap_usd": None}),
        ("purchases", {"per_day_cap_usd": float("nan")}),
        ("purchases", {"per_hour_cap_usd": 5}),
        ("screen", {"anything": 1}),
    ],
)
async def test_set_capability_settings_rejects_bad_values_and_writes_nothing(
    session_factory, key, patch
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    with pytest.raises(ValueError):
        await svc.set_capability_settings(key, patch, actor_id=user.id)
    async with session_factory() as s:
        assert (await s.execute(select(AuditLog))).scalars().first() is None
    assert await svc.capability_settings("purchases") == {
        "per_purchase_cap_usd": 25,
        "per_day_cap_usd": 50,
    }


@pytest.mark.asyncio
async def test_set_capability_settings_unknown_capability_is_a_key_error(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    with pytest.raises(KeyError):
        await svc.set_capability_settings("nope", {"x": 1}, actor_id=user.id)


@pytest.mark.asyncio
async def test_set_capability_settings_is_audited_with_the_values_and_fires_a_change(
    session_factory,
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    topics: list[str] = []

    async def listen(topic: str) -> None:
        topics.append(topic)

    svc.on_change(listen)
    await svc.set_capability_settings("purchases", {"per_day_cap_usd": 80.0}, actor_id=user.id)
    assert topics == ["capabilities"]
    async with session_factory() as s:
        row = (await s.execute(select(AuditLog).order_by(AuditLog.seq.desc()))).scalars().first()
    assert row is not None
    assert (row.connector_name, row.action) == ("installation", "capability_settings_updated")
    assert row.endpoint == "/api/capabilities/purchases/settings"
    assert row.request_data == {"capability": "purchases", "changes": {"per_day_cap_usd": 80.0}}
    assert row.user_id == user.id


@pytest.mark.asyncio
async def test_set_capability_settings_persists_partially_and_merges_with_defaults(
    session_factory,
):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "owner@example.com")
    merged = await svc.set_capability_settings(
        "purchases", {"per_day_cap_usd": 120}, actor_id=user.id
    )
    assert merged == {"per_purchase_cap_usd": 25, "per_day_cap_usd": 120}
    # A fresh service reads it back from the row, defaults still merged.
    again = InstallationService(session_factory)
    assert await again.capability_settings("purchases") == merged
    assert await again.purchase_caps() == (Decimal("25"), Decimal("120"))
    by_key = registry.statuses_by_key(await again.report())
    assert dict(by_key["purchases"].settings) == merged
    # A second patch keeps the first (whole dollars only: 9.99 is refused).
    await again.set_capability_settings("purchases", {"per_purchase_cap_usd": 9}, actor_id=user.id)
    assert await again.purchase_caps() == (Decimal("9"), Decimal("120"))


def test_merged_settings_ignore_stale_and_foreign_keys():
    stored = {"purchases": {"per_day_cap_usd": 7, "old_key": 1}, "screen": {"x": 2}}
    assert InstallationService._merged_settings("purchases", stored) == {
        "per_purchase_cap_usd": 25,
        "per_day_cap_usd": 7,
    }
    assert InstallationService._merged_settings("screen", stored) == {}


def test_stored_settings_read_an_empty_or_odd_column_as_nothing():
    from services.installation import _stored_settings

    assert _stored_settings(SimpleNamespace(capability_settings=None)) == {}
    assert _stored_settings(SimpleNamespace(capability_settings=[])) == {}
    assert _stored_settings(SimpleNamespace(capability_settings={"purchases": {"a": 1}, "x": 3})) == {
        "purchases": {"a": 1}
    }


# ── PUT /api/capabilities/{key}/settings ─────────────────────────────────


@pytest_asyncio.fixture
async def installation(session_factory, monkeypatch):
    from api.routes import capabilities as capabilities_routes
    from main import app

    service = InstallationService(session_factory)
    app.state.installation = service
    monkeypatch.setattr(capabilities_routes, "_session_factory", session_factory)
    registry.clear_probe_cache()
    yield service
    try:
        del app.state.installation
    except AttributeError:
        pass
    registry.clear_probe_cache()


@pytest_asyncio.fixture
async def owner(client, installation):
    created = await client.post(
        "/api/setup/owner", json={"email": "owner@example.com", "password": "password-123"}
    )
    assert created.status_code == 200, created.text
    body = created.json()
    return auth_headers(body["access_token"]), body["user"]["id"]


@pytest_asyncio.fixture
async def guest(owner, session_factory):
    _user, token = await make_user(session_factory, "guest@example.com")
    return auth_headers(token)


def _by_key(body):
    return {item["key"]: item for item in body["capabilities"]}


@pytest.mark.asyncio
async def test_settings_route_is_admin_only(client, guest):
    resp = await client.put(
        "/api/capabilities/purchases/settings",
        json={"settings": {"per_day_cap_usd": 5}},
        headers=guest,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_settings_route_404_for_an_unknown_capability(client, owner):
    headers, _ = owner
    resp = await client.put(
        "/api/capabilities/teleport/settings", json={"settings": {"x": 1}}, headers=headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "settings",
    [
        {"per_day_cap_usd": "25"},
        {"per_day_cap_usd": True},
        {"per_day_cap_usd": None},
        {"per_day_cap_usd": 0},
        {"per_day_cap_usd": 0.5},
        {"per_day_cap_usd": 25.5},  # in bounds, but a cap is a whole number of dollars
        {"per_day_cap_usd": 10001},
        {"per_day_cap_usd": 20000},
        {"per_hour_cap_usd": 3},
    ],
)
async def test_settings_route_422_for_bad_values(client, owner, settings):
    headers, _ = owner
    resp = await client.put(
        "/api/capabilities/purchases/settings", json={"settings": settings}, headers=headers
    )
    assert resp.status_code == 422, resp.text
    value = settings.get("per_day_cap_usd")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # An amount out of bounds is refused in the owner's words (the
        # Permissions page shows the detail as it is): the bounds in
        # dollars, never the setting's internal name. The other shapes
        # never pass the request model.
        assert resp.json()["detail"] == "Caps must be between $1 and $10,000."
        assert "per_day_cap_usd" not in resp.text
    # Nothing changed.
    after = _by_key((await client.get("/api/capabilities", headers=headers)).json())
    assert after["purchases"]["settings"] == {"per_purchase_cap_usd": 25, "per_day_cap_usd": 50}


@pytest.mark.asyncio
async def test_settings_route_422_for_a_capability_without_settings(client, owner):
    headers, _ = owner
    resp = await client.put(
        "/api/capabilities/screen/settings", json={"settings": {"x": 1}}, headers=headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_settings_route_returns_the_report_and_audits(client, owner, session_factory):
    headers, user_id = owner
    resp = await client.put(
        "/api/capabilities/purchases/settings",
        json={"settings": {"per_purchase_cap_usd": 40}},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = _by_key(resp.json())
    assert set(body) == set(registry.keys())
    assert body["purchases"]["settings"] == {"per_purchase_cap_usd": 40, "per_day_cap_usd": 50}
    import uuid

    async with session_factory() as session:
        rows = (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.user_id == uuid.UUID(user_id))
                .where(AuditLog.action == "capability_settings_updated")
            )
        ).scalars().all()
    assert len(rows) == 1
    assert rows[0].request_data == {"capability": "purchases", "changes": {"per_purchase_cap_usd": 40}}


@pytest.mark.asyncio
async def test_settings_route_with_an_empty_patch_changes_nothing(client, owner, session_factory):
    headers, user_id = owner
    resp = await client.put(
        "/api/capabilities/purchases/settings", json={"settings": {}}, headers=headers
    )
    assert resp.status_code == 200
    import uuid

    async with session_factory() as session:
        rows = (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.user_id == uuid.UUID(user_id))
                .where(AuditLog.action == "capability_settings_updated")
            )
        ).scalars().all()
    assert rows == []
