from __future__ import annotations

from services import capabilities
from services.capabilities.base import ReportContext
from services.capabilities import screen
from services.capabilities.prompt import render_permissions_block


def ctx(**over) -> ReportContext:
    base = {
        "in_container": False,
        "platform": "darwin",
        "telegram_configured": True,
        "browser_installed": True,
        "executable": "/usr/bin/python3",
    }
    base.update(over)
    return ReportContext(**base)


def by_key(statuses):
    return {s.key: s for s in statuses}


def test_defaults_have_screen_off_and_web_on():
    switches = capabilities.default_switches()
    assert switches["screen"] is False
    assert switches["web_browsing"] is True


def test_off_switch_wins_over_everything(monkeypatch):
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: True)
    st = by_key(capabilities.report({"screen": False}, ctx(), use_cache=False))["screen"]
    assert st.effective == "off"
    assert "off" in st.reason.lower()


def test_container_blocks_screen_even_when_enabled():
    st = by_key(capabilities.report({"screen": True}, ctx(in_container=True), use_cache=False))["screen"]
    assert st.effective == "blocked"
    assert "container" in st.reason.lower()
    assert st.can_request_access is False


def test_macos_denied_probe_blocks_with_fix(monkeypatch):
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: False)
    st = by_key(capabilities.report({"screen": True}, ctx(), use_cache=False))["screen"]
    assert st.effective == "blocked"
    assert st.probe_state == "denied"
    assert st.fix_url and st.fix_url.startswith("x-apple.systempreferences:")
    assert st.fix_steps
    assert st.can_request_access is True


def test_macos_granted_probe_is_on(monkeypatch):
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: True)
    st = by_key(capabilities.report({"screen": True}, ctx(), use_cache=False))["screen"]
    assert st.effective == "on"


def test_windows_needs_no_permission():
    st = by_key(capabilities.report({"screen": True}, ctx(platform="win32"), use_cache=False))["screen"]
    assert st.effective == "on"
    assert st.probe_state == "not_required"


def test_site_screenshots_blocked_until_browser_installed():
    st = by_key(capabilities.report({}, ctx(browser_installed=False), use_cache=False))["site_screenshots"]
    assert st.effective == "blocked"
    assert st.install == "browser"


def test_telegram_blocked_without_token():
    st = by_key(capabilities.report({}, ctx(telegram_configured=False), use_cache=False))["telegram"]
    assert st.effective == "blocked"


def test_enabled_keys_only_returns_on(monkeypatch):
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: False)
    keys = capabilities.enabled_keys({"screen": True}, ctx(browser_installed=False))
    assert "web_browsing" in keys and "reminders" in keys
    assert "screen" not in keys and "site_screenshots" not in keys


def test_probe_is_cached_for_ten_seconds(monkeypatch):
    calls = {"n": 0}

    def fake():
        calls["n"] += 1
        return True

    monkeypatch.setattr(screen.macos, "screen_capture_preflight", fake)
    capabilities.clear_probe_cache()
    capabilities.report({"screen": True}, ctx())
    capabilities.report({"screen": True}, ctx())
    assert calls["n"] == 1
    capabilities.clear_probe_cache()


def test_render_permissions_block_lists_every_state(monkeypatch):
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: False)
    text = render_permissions_block(capabilities.report({"screen": True, "reminders": False}, ctx(browser_installed=False), use_cache=False))
    assert text.startswith("<permissions>") and text.endswith("</permissions>")
    assert "- Browse the web: on" in text
    assert "- Reminders: off" in text
    assert "- See my screen: blocked" in text
    assert "system.install_capability(name='browser')" in text


def test_to_dict_is_json_friendly():
    d = capabilities.report({}, ctx(), use_cache=False)[0].to_dict()
    assert isinstance(d["fix_steps"], list) and isinstance(d["tools"], list)
    assert set(d) >= {"key", "label", "effective", "reason", "enabled", "can_request_access"}
