from __future__ import annotations

from types import SimpleNamespace

import pytest

from services import capabilities
from services.capabilities import macos, screen
from services.capabilities.base import (
    Availability,
    Capability,
    ProbeResult,
    ReportContext,
)
from services.capabilities.prompt import render_permissions_block


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    capabilities.clear_probe_cache()
    yield
    capabilities.clear_probe_cache()


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


def make_cap(key: str = "fake", **over) -> Capability:
    fields = {
        "key": key,
        "label": f"Fake {key}",
        "description": "A capability used only by these tests.",
        "tools": (),
        "default_enabled": True,
        "risk": "low",
        "when_denied": f"Fake {key} is off.",
    }
    fields.update(over)
    return Capability(**fields)


def only(monkeypatch, *caps: Capability) -> None:
    """Report over exactly *caps* instead of the real registry."""
    monkeypatch.setattr(capabilities, "REGISTRY", caps)


class _RecordingLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict]] = []

    def warning(self, event: str, **kw) -> None:
        self.records.append((event, kw))

    def events(self, name: str) -> list[dict]:
        return [kw for event, kw in self.records if event == name]


# -- Defaults and the effective-state rule --------------------------------


def test_defaults_have_screen_off_and_web_on():
    switches = capabilities.default_switches()
    assert switches["screen"] is False
    assert switches["web_browsing"] is True


def test_off_switch_wins_over_everything(monkeypatch):
    # Off beats both a denied permission and an unavailable environment,
    # and the probe is never consulted for a capability that is off.
    calls = {"n": 0}

    def denied():
        calls["n"] += 1
        return False

    monkeypatch.setattr(screen.macos, "screen_capture_preflight", denied)
    st = by_key(
        capabilities.report({"screen": False}, ctx(in_container=True), use_cache=False)
    )["screen"]
    assert st.effective == "off"
    assert "off" in st.reason.lower()
    assert calls["n"] == 0


def test_container_blocks_screen_even_when_enabled():
    st = by_key(capabilities.report({"screen": True}, ctx(in_container=True), use_cache=False))["screen"]
    assert st.effective == "blocked"
    assert "container" in st.reason.lower()
    assert st.can_request_access is False
    assert st.probe_state == "unknown"


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


def test_macos_preflight_unanswered_is_unknown_and_counts_as_on(monkeypatch):
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: None)
    st = by_key(capabilities.report({"screen": True}, ctx(), use_cache=False))["screen"]
    assert st.probe_state == "unknown"
    assert st.effective == "on"
    assert st.can_request_access is False


def test_unknown_probe_counts_as_on(monkeypatch):
    only(monkeypatch, make_cap(probe=lambda _ctx: ProbeResult("unknown", "No idea.")))
    (st,) = capabilities.report({}, ctx(), use_cache=False)
    assert st.probe_state == "unknown"
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


def test_can_request_access_needs_a_request_callable(monkeypatch):
    only(monkeypatch, make_cap(probe=lambda _ctx: ProbeResult("denied", "Not granted.")))
    (st,) = capabilities.report({}, ctx(), use_cache=False)
    assert st.effective == "blocked"
    assert st.probe_state == "denied"
    assert st.can_request_access is False


# -- Switch values ---------------------------------------------------------


@pytest.mark.parametrize("value", ["false", "true", 1, "yes", [True]])
def test_non_boolean_switch_values_read_as_off(value):
    # Switches arrive from storage and the API. bool("false") is True, so
    # anything but a real True must mean off rather than on.
    st = by_key(capabilities.report({"screen": value}, ctx(platform="win32"), use_cache=False))["screen"]
    assert st.enabled is False
    assert st.effective == "off"


def test_missing_or_null_switch_uses_the_default():
    statuses = by_key(capabilities.report({"web_browsing": None}, ctx(), use_cache=False))
    assert statuses["web_browsing"].enabled is True
    assert statuses["screen"].enabled is False


# -- The probe is only consulted when it can matter -------------------------


def _counting_probe(calls: list[str]):
    def probe(_ctx: ReportContext) -> ProbeResult:
        calls.append("probe")
        raise AssertionError("the probe must not run here")

    return probe


def test_probe_is_not_called_when_switched_off(monkeypatch):
    calls: list[str] = []
    only(monkeypatch, make_cap(probe=_counting_probe(calls)))
    (st,) = capabilities.report({"fake": False}, ctx(), use_cache=False)
    assert calls == []
    assert st.effective == "off"
    assert st.probe_state == "unknown"
    assert st.probe_detail == "Not checked while off or unavailable."


def test_probe_is_not_called_when_unavailable(monkeypatch):
    calls: list[str] = []
    only(
        monkeypatch,
        make_cap(
            availability=lambda _ctx: Availability(False, "Not here."),
            probe=_counting_probe(calls),
        ),
    )
    (st,) = capabilities.report({}, ctx(), use_cache=False)
    assert calls == []
    assert st.effective == "blocked"
    assert st.reason == "Not here."
    assert st.probe_state == "unknown"


def test_capability_without_probe_reports_not_required(monkeypatch):
    only(monkeypatch, make_cap())
    (st,) = capabilities.report({"fake": False}, ctx(), use_cache=False)
    assert st.probe_state == "not_required"


# -- Fail closed -------------------------------------------------------------


def test_availability_that_raises_blocks_and_is_logged(monkeypatch):
    log = _RecordingLogger()
    monkeypatch.setattr(capabilities, "logger", log)

    def broken(_ctx: ReportContext) -> Availability:
        raise RuntimeError("boom")

    only(monkeypatch, make_cap(availability=broken))
    (st,) = capabilities.report({}, ctx(), use_cache=False)
    assert st.effective == "blocked"
    assert st.available is False
    assert st.reason == "Could not check whether this is available."
    (record,) = log.events("capability_availability_failed")
    assert record["capability"] == "fake"
    assert "boom" in record["error"]


def test_probe_that_raises_blocks_instead_of_counting_as_on(monkeypatch):
    log = _RecordingLogger()
    monkeypatch.setattr(capabilities, "logger", log)

    def broken(_ctx: ReportContext) -> ProbeResult:
        raise OSError("tcc unavailable")

    only(monkeypatch, make_cap(probe=broken))
    cap = capabilities.REGISTRY[0]
    for st in (
        capabilities._status(cap, True, ctx(), use_cache=False),
        capabilities.report({}, ctx())[0],
    ):
        assert st.effective == "blocked"
        assert st.probe_state == "denied"
        assert st.reason == "The permission check failed."
    assert log.events("capability_probe_failed")
    assert "fake" not in capabilities.enabled_keys({}, ctx())


# -- The probe cache -------------------------------------------------------


def test_probe_is_cached_for_ten_seconds(monkeypatch):
    calls = {"n": 0}

    def fake():
        calls["n"] += 1
        return True

    monkeypatch.setattr(screen.macos, "screen_capture_preflight", fake)
    capabilities.report({"screen": True}, ctx())
    capabilities.report({"screen": True}, ctx())
    assert calls["n"] == 1


def test_probe_cache_expires_after_the_ttl(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(capabilities, "time", SimpleNamespace(monotonic=lambda: clock["t"]))
    calls = {"n": 0}

    def fake():
        calls["n"] += 1
        return True

    monkeypatch.setattr(screen.macos, "screen_capture_preflight", fake)
    capabilities.report({"screen": True}, ctx())
    clock["t"] += 9.0
    capabilities.report({"screen": True}, ctx())
    assert calls["n"] == 1
    clock["t"] += 1.5  # now 10.5 s after the first probe
    capabilities.report({"screen": True}, ctx())
    assert calls["n"] == 2


def test_probe_cache_is_keyed_by_context(monkeypatch):
    # Windows answers not_required without a preflight; that answer must
    # not be served for a macOS report that follows it.
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: False)
    win = by_key(capabilities.report({"screen": True}, ctx(platform="win32")))["screen"]
    assert win.effective == "on"
    mac = by_key(capabilities.report({"screen": True}, ctx(platform="darwin")))["screen"]
    assert mac.effective == "blocked"
    assert mac.probe_state == "denied"


# -- The <permissions> block -----------------------------------------------


def test_render_permissions_block_lists_every_state(monkeypatch):
    monkeypatch.setattr(screen.macos, "screen_capture_preflight", lambda: False)
    text = render_permissions_block(capabilities.report({"screen": True, "reminders": False}, ctx(browser_installed=False), use_cache=False))
    assert text.startswith("<permissions>") and text.endswith("</permissions>")
    assert "- Browse the web: on" in text
    assert "- Reminders: off" in text
    assert "- See my screen: blocked" in text
    assert "system.install_capability(name='browser')" in text


def test_render_permissions_block_offers_no_install_when_installs_is_off():
    statuses = capabilities.report({"installs": False}, ctx(browser_installed=False), use_cache=False)
    text = render_permissions_block(statuses)
    assert "- Screenshots of websites: blocked" in text
    assert "install_capability" not in text


def test_render_permissions_block_offers_no_install_without_an_installs_status():
    statuses = [
        s
        for s in capabilities.report({}, ctx(browser_installed=False), use_cache=False)
        if s.key != "installs"
    ]
    assert "install_capability" not in render_permissions_block(iter(statuses))


def test_to_dict_is_json_friendly():
    d = capabilities.report({}, ctx(), use_cache=False)[0].to_dict()
    assert isinstance(d["fix_steps"], list) and isinstance(d["tools"], list)
    assert set(d) >= {"key", "label", "effective", "reason", "enabled", "can_request_access"}


# -- macOS shims -----------------------------------------------------------


def test_open_settings_refuses_anything_but_a_settings_deep_link(monkeypatch):
    def must_not_run(*_a, **_kw):
        raise AssertionError("open must not be launched for this URL")

    monkeypatch.setattr(macos.subprocess, "run", must_not_run)
    with pytest.raises(ValueError):
        macos.open_settings("https://example.com")
    with pytest.raises(ValueError):
        macos.open_settings("file:///Applications/Calculator.app")


@pytest.mark.parametrize("returncode, expected", [(0, True), (1, False)])
def test_open_settings_uses_the_absolute_open_and_reports_its_exit(monkeypatch, returncode, expected):
    seen: list[list[str]] = []

    def fake_run(argv, **_kw):
        seen.append(argv)
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(macos.sys, "platform", "darwin")
    monkeypatch.setattr(macos.subprocess, "run", fake_run)
    assert macos.open_settings() is expected
    assert seen == [["/usr/bin/open", macos.SCREEN_SETTINGS_URL]]


def test_an_installable_capability_carries_its_download_size():
    """The Permissions page shows the size next to the Install button; it
    comes from the one ALLOWLIST entry the install would run."""
    from services.tools.system import ALLOWLIST

    statuses = by_key(capabilities.report({}, ctx(browser_installed=False)))
    shots = statuses["site_screenshots"]
    assert shots.install == "browser"
    assert shots.install_size_hint == ALLOWLIST["browser"].size_hint
    assert shots.to_dict()["install_size_hint"] == ALLOWLIST["browser"].size_hint

    for key, status in statuses.items():
        if status.install is None:
            assert status.install_size_hint is None, key
            assert status.to_dict()["install_size_hint"] is None


def test_default_context_names_the_resolved_interpreter(monkeypatch, tmp_path):
    # macOS attaches the Screen Recording grant to the real binary, not to
    # the venv symlink that sys.executable usually is.
    real = tmp_path / "python3.12"
    real.write_text("")
    link = tmp_path / "venv-python"
    link.symlink_to(real)
    monkeypatch.setattr("sys.executable", str(link))
    assert capabilities.default_context().executable == str(real.resolve())


def test_the_report_and_screen_capture_name_one_executable(monkeypatch, tmp_path):
    """The Permissions page tells the owner which binary to grant; the
    capture tool checks the grant for a binary too. They must name the same
    one (and share probe-cache entries), so both come from one helper."""
    from services.capabilities.env import crawler_executable
    from services.tools import desktop

    real = tmp_path / "python3.13"
    real.write_text("")
    link = tmp_path / "venv-python"
    link.symlink_to(real)
    monkeypatch.setattr("sys.executable", str(link))

    assert crawler_executable() == str(real.resolve())
    assert capabilities.default_context().executable == crawler_executable()
    assert desktop._screen_context().executable == crawler_executable()
