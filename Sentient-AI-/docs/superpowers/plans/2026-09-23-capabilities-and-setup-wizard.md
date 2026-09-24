# Capabilities, Permissions & Setup Wizard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the capability/permission foundation of Crawler AI (formerly SentientAI): a registry of switchable capabilities, an `installation` record, tool gating, a `desktop.screenshot` tool, a Permissions page, and a first-run `/setup` wizard that stores the AI key and Telegram token — so contributors can add features as single capability files.

**Architecture:** A `services/capabilities/` registry declares each capability (tools, defaults, OS probe, "if denied" line). An `InstallationService` owns one DB row (switches, provider, encrypted secrets) with `.env > DB > default` precedence. `build_tools` and the executor gate on the enabled set; the runtime appends a `<permissions>` block to the system prompt. A `TelegramManager` starts/stops the poller at runtime. The frontend renders one `CapabilityList` in both the wizard and Settings.

**Tech Stack:** FastAPI, SQLAlchemy 2 (async), Alembic, pydantic-settings, httpx, `mss` + `Pillow` (new), React 18 + TypeScript + Vite, vitest + Testing Library.

**Spec:** `docs/superpowers/specs/2026-09-23-capabilities-and-setup-wizard-design.md` — read §4–§9 before any task.

---

## 0. Working rules (every agent)

- **Repo root is nested:** `/Users/krish/Sentient-AI-/Sentient-AI-` (git toplevel is `/Users/krish/Sentient-AI-`). Ignore `/Users/krish/Sentient-AI-/backend`, `/frontend`, `/docker` — stale leftovers.
- **Never read or print `backend/.env`.** Use `backend/.env.example` for names.
- **Never touch the running Docker stack** (compose project `docker`) or ports 3000/5173/8000/5432/6379. Do not start servers; unit tests only.
- **No LLM calls, no Telegram calls** in tests: mock `create_provider` / `httpx`.
- **Commands:**
  - Backend tests: `cd /Users/krish/Sentient-AI-/Sentient-AI-/backend && python3 -m pytest tests/<file> -q` (Python 3.13, SQLite; all deps installed). Lint: `python3 -m ruff check .`
  - Frontend: `cd /Users/krish/Sentient-AI-/Sentient-AI-/frontend && npx vitest run src/<file>`; types: `npx tsc -b`; lint: `npx eslint .`
- **Commits:** small, one per task step group, message `feat|fix|test|docs(scope): …`. **Do not add a `Co-Authored-By` line** (owner's rule for this repo).
- **Code style:** match the neighbouring file (docstrings explain *why*, `from __future__ import annotations`, structlog logger, fail-closed errors as `{"ok": False, "error": "..."}`).

### Waves (parallel plan)

| Wave | Tasks | Depends on |
|---|---|---|
| 0 | Commit + push current tree (lead) | — |
| 1 (parallel, separate worktrees) | T1 capabilities package · T2 installation record + service · T3 Telegram manager · T4 runtime provider resolver + permissions text · T5 frontend Permissions UI · T6 frontend Setup wizard · T7 rename to Crawler AI | nothing (each codes against §1 contracts) |
| 2 (parallel, after wave 1 merged) | T8 executor map + wiring (`main.py`, `agent.py`) · T9 capabilities API · T10 setup API · T11 docs/compose/deps/upgrade stamp | T1–T4 |
| 3 | Integration: full suites, Docker live check, push (lead) | all |

---

## 1. Shared contracts (read before coding; do not deviate)

### 1.1 `services/capabilities/base.py` (owned by T1; everyone imports it)

```python
ProbeState = Literal["granted", "denied", "not_required", "unknown"]
Effective = Literal["on", "off", "blocked"]
Risk = Literal["low", "medium", "high"]

@dataclass(frozen=True)
class ReportContext:
    in_container: bool
    platform: str            # sys.platform
    telegram_configured: bool
    browser_installed: bool
    executable: str = ""     # sys.executable; macOS attaches grants to this binary

@dataclass(frozen=True)
class Availability:
    available: bool
    reason: str = ""

@dataclass(frozen=True)
class ProbeResult:
    state: ProbeState
    detail: str = ""
    fix_url: Optional[str] = None
    fix_steps: tuple[str, ...] = ()

@dataclass(frozen=True)
class Capability:
    key: str; label: str; description: str
    tools: tuple[str, ...]          # exact "web.search" or prefix "reminders."
    default_enabled: bool
    risk: Risk
    when_denied: str
    availability: Callable[[ReportContext], Availability] = always_available
    probe: Optional[Callable[[ReportContext], ProbeResult]] = None
    request_access: Optional[Callable[[], None]] = None
    install: Optional[str] = None   # key in services.tools.system.ALLOWLIST
    def claims(self, tool_name: str) -> bool: ...

@dataclass(frozen=True)
class CapabilityStatus:
    key, label, description, risk, enabled, default_enabled, available,
    availability_reason, probe_state, probe_detail, fix_url, fix_steps,
    effective, reason, can_request_access, install, when_denied, tools
    def to_dict(self) -> dict[str, Any]   # fix_steps/tools as lists
```

### 1.2 `services/capabilities/__init__.py` API

```python
REGISTRY: tuple[Capability, ...]
ALWAYS_ON_TOOLS: frozenset[str] = frozenset({"system.capabilities"})
def get(key: str) -> Capability                      # KeyError if unknown
def keys() -> tuple[str, ...]
def capability_for_tool(tool_name: str) -> Optional[Capability]
def default_switches() -> dict[str, bool]
def default_context(*, telegram_configured: bool = False) -> ReportContext
def report(switches: Mapping[str, bool], ctx: ReportContext, *, use_cache: bool = True) -> list[CapabilityStatus]
def enabled_keys(switches: Mapping[str, bool], ctx: ReportContext) -> frozenset[str]   # effective == "on"
def clear_probe_cache() -> None
```
Effective rule: `off` if not enabled → else `blocked` if `not availability.available` → else `blocked` if probe `denied` → else `on`. `unknown`/`not_required` count as on. Probe results cached 10 s per key.

`services/capabilities/prompt.py`: `render_permissions_block(statuses: Iterable[CapabilityStatus]) -> str` → `<permissions>…</permissions>`.

### 1.3 `services/installation.py` — `InstallationService` (owned by T2)

```python
class InstallationService:
    def __init__(self, session_factory, *, config=settings) -> None
    async def capabilities(self) -> dict[str, bool]                       # defaults merged with stored
    async def set_capabilities(self, patch: Mapping[str, bool], *, actor_id) -> list[CapabilityStatus]
    async def context(self) -> ReportContext
    async def report(self) -> list[CapabilityStatus]
    async def enabled_keys(self) -> frozenset[str]                        # cached ≤5 s
    async def llm_defaults(self) -> tuple[str, str]                       # (provider, model)
    async def llm_api_key(self, provider: str) -> Optional[str]           # env > DB; "" for ollama
    async def provider_configured(self) -> bool
    async def set_llm(self, provider: str, model: str, api_key: Optional[str], *, actor_id) -> None
    async def telegram_token(self) -> Optional[str]                       # env > DB
    async def set_telegram_token(self, token: Optional[str], *, actor_id) -> None
    async def registration_allowed(self) -> bool
    async def has_users(self) -> bool
    async def needs_setup(self) -> bool                                   # not has_users or setup_completed_at is None
    async def setup_completed(self) -> bool
    async def mark_setup_complete(self, *, allow_registration: bool, actor_id) -> None
    async def stamp_setup_if_legacy(self) -> bool                         # users exist + env key → stamp
    def on_change(self, callback: Callable[[str], Awaitable[None]]) -> None   # topic: "capabilities"|"llm"|"telegram"|"setup"
    def invalidate(self) -> None
```
Audit rows: `connector_name="installation"`, actions `capabilities_updated` (request_data `{"changes": {key: bool}}`), `provider_updated` (`{"provider", "model", "key_stored": bool}`), `telegram_updated` (`{"configured": bool}`), `setup_completed` (`{"allow_registration": bool}`), `endpoint` = the API path, `scope_used="admin"`, `status=AuditStatus.approved`.

`core/config.py` gains `PROVIDER_KEY_FIELDS: dict[str, str]` (provider → settings attribute) — the map currently private in `services/agent/runtime.py` (`_PROVIDER_KEY_MAP`); runtime re-exports it.

### 1.4 Runtime additions (owned by T4)

```python
class ProviderSettingsSource(Protocol):
    async def llm_defaults(self) -> tuple[str, str]: ...
    async def llm_api_key(self, provider: str) -> Optional[str]: ...

class ProviderNotConfigured(ProviderError): ...   # in services/agent/providers.py

AgentRuntime.__init__(..., settings_source: Optional[ProviderSettingsSource] = None)
AgentRuntime.chat(..., permissions_text: Optional[str] = None)
AgentRuntime.invalidate_providers() -> None
```

### 1.5 Telegram manager (owned by T3)

```python
class TelegramManager:
    def __init__(self, session_factory, *, on_start: Optional[Callable[[TelegramService], None]] = None,
                 service_factory: Callable[..., TelegramService] = TelegramService) -> None
    current: Optional[TelegramService]
    @property def is_running(self) -> bool
    async def apply(self, token: Optional[str], enabled: bool) -> str   # "started"|"restarted"|"stopped"|"unchanged"
    async def stop(self) -> None
    async def notify_pending(self, action) -> None
    async def send_text(self, user_id: str, text: str) -> bool
    async def bot_username(self) -> Optional[str]
```

### 1.6 HTTP shapes (owned by T9/T10; frontend T5/T6 code against these)

```
GET  /api/capabilities                         -> {"capabilities": [CapabilityStatus.to_dict()…]}
PUT  /api/capabilities   {"capabilities": {key: bool}}   (admin) -> same shape
POST /api/capabilities/{key}/request-access    (admin) -> {"ok": true, "status": CapabilityStatus} | 409 {"detail": reason}
POST /api/capabilities/{key}/install           (admin) -> {"ok": bool, ...install result} | 409 if no install

GET  /api/setup/status  -> {"needs_setup": bool, "has_owner": bool, "provider_configured": bool, "setup_completed": bool}
POST /api/setup/owner   {"email","password","name"?}  (only while zero users) -> {"access_token","token_type":"bearer","user":{…}} | 409
GET  /api/setup/providers (admin) -> {"providers":[{"name","key_from_env":bool,"key_stored":bool,"models":[…]}], "current":{"provider","model"}}
POST /api/setup/provider/test {"provider","model","api_key"?} (admin) -> {"ok":true,"reply":"OK"} | {"ok":false,"error":"…"}
PUT  /api/setup/provider     {"provider","model","api_key"?} (admin) -> {"ok":true} | 400 {"detail": error}
POST /api/setup/telegram/test {"token"} (admin) -> {"ok":true,"bot_username":"…"} | {"ok":false,"error":"…"}
PUT  /api/setup/telegram      {"token"} (admin) -> {"ok":true,"bot_username":"…"}
DELETE /api/setup/telegram    (admin) -> 204
POST /api/setup/complete {"allow_registration": bool} (admin) -> {"ok": true}
```

### 1.7 Frontend types (`src/types/index.ts`, owned by T5; T6 adds setup types)

```ts
export type CapabilityEffective = "on" | "off" | "blocked";
export type ProbeState = "granted" | "denied" | "not_required" | "unknown";
export interface CapabilityStatus {
  key: string; label: string; description: string; risk: "low" | "medium" | "high";
  enabled: boolean; default_enabled: boolean; available: boolean; availability_reason: string;
  probe_state: ProbeState; probe_detail: string; fix_url: string | null; fix_steps: string[];
  effective: CapabilityEffective; reason: string; can_request_access: boolean;
  install: string | null; when_denied: string; tools: string[];
}
export interface SetupStatus { needs_setup: boolean; has_owner: boolean; provider_configured: boolean; setup_completed: boolean; }
export interface SetupProvider { name: string; key_from_env: boolean; key_stored: boolean; models: string[]; }
```

---

## 2. File map

| Path | Task | Responsibility |
|---|---|---|
| `backend/services/capabilities/{__init__,base,env,macos,prompt,_template}.py` + 6 capability files + `README.md` | T1 | registry, report, prompt block, contributor guide |
| `backend/services/tools/desktop.py` | T1 | `desktop.screenshot` toolkit |
| `backend/services/agent/tool_registry.py` | T1 (catalog/gates), T8 (toolkit map, system report) | catalog, `build_tools` gate, executor |
| `backend/services/agent/permissions.py` | T1 | `desktop` policy rows |
| `backend/tests/test_capabilities_registry.py`, `test_capabilities_report.py`, `test_desktop_tools.py`, `test_capability_gating.py` | T1 | |
| `backend/models/installation.py`, `alembic/versions/0008_installation.py`, `services/installation.py`, `tests/test_installation.py` | T2 | |
| `backend/core/config.py` | T2 | `PROVIDER_KEY_FIELDS` |
| `backend/services/notifications/telegram_manager.py`, `tests/test_telegram_manager.py` | T3 | |
| `backend/services/agent/runtime.py`, `providers.py`, `tests/test_runtime_provider_resolution.py` | T4 | lazy provider, `permissions_text` |
| `backend/api/routes/agent.py` | T4 (error mapping), T8 (wiring, images) | |
| `frontend/src/types/index.ts`, `services/api.ts`, `components/CapabilityList.tsx` (+test), `pages/Settings.tsx` | T5 | |
| `frontend/src/pages/Setup.tsx` (+test), `App.tsx`, `services/api.ts` | T6 | |
| rename surface (see T7) | T7 | |
| `backend/main.py`, `api/routes/telegram.py`, `services/tools/system.py` | T8 | wiring |
| `backend/api/routes/capabilities.py`, `tests/test_capabilities_api.py` | T9 | |
| `backend/api/routes/setup.py`, `api/routes/auth.py` (extract `create_account`), `tests/test_setup_api.py` | T10 | |
| `backend/requirements.txt`, `docker/docker-compose*.yml`, `README.md`, `.env.example`, `core/database.py` or `main.py` (stamp) | T11 | |

---

## Wave 0 — Task 0: commit and push the working tree (lead)

- [ ] **Step 1: Run both suites**

```bash
cd /Users/krish/Sentient-AI-/Sentient-AI-/backend && python3 -m pytest tests -q -x -p no:cacheprovider 2>&1 | tail -5
```
```bash
cd /Users/krish/Sentient-AI-/Sentient-AI-/frontend && npx vitest run 2>&1 | tail -5 && npx tsc -b
```
Expected: backend `… passed`, frontend `… passed`, tsc silent.

- [ ] **Step 2: Commit the remaining 36 modified + 19 untracked files and push**

```bash
cd /Users/krish/Sentient-AI- && git add -A Sentient-AI-/ .github/ README.md 2>/dev/null; git status --short | head -60
```
Confirm no `backend/.env` in the list (it is gitignored), then:
```bash
git commit -q -m "feat: web/system/usage tools, migration 0007, frontend usage panels and tests" && git push -u origin feat/full-platform-completion && git log --oneline -1
```

---

## Wave 1 — Task 1: capabilities package (T1, part A)

**Files:**
- Create: `backend/services/capabilities/__init__.py`, `base.py`, `env.py`, `macos.py`, `prompt.py`, `_template.py`, `README.md`, `web_browsing.py`, `site_screenshots.py`, `screen.py`, `reminders.py`, `installs.py`, `telegram.py`
- Test: `backend/tests/test_capabilities_registry.py`, `backend/tests/test_capabilities_report.py`

- [ ] **Step 1: Write the failing registry tests**

`backend/tests/test_capabilities_registry.py`:
```python
"""The registry is what contributors extend. These invariants make a
misdeclared capability fail the build instead of silently doing nothing."""
from __future__ import annotations

import re

import pytest

from services import capabilities
from services.capabilities import _template
from services.capabilities.base import Capability
from services.agent.tool_registry import BUILTIN_CONNECTOR_TYPES, CONNECTOR_CATALOG


def _catalog_tool_names() -> set[str]:
    return {f"{ctype}.{spec.action}" for ctype, specs in CONNECTOR_CATALOG.items() for spec in specs}


def test_every_capability_key_is_snake_case_and_unique():
    keys = [c.key for c in capabilities.REGISTRY]
    assert len(keys) == len(set(keys))
    for key in keys:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", key), key


def test_every_claimed_tool_exists_in_the_catalog():
    names = _catalog_tool_names()
    for cap in capabilities.REGISTRY:
        for pattern in cap.tools:
            if pattern.endswith("."):
                assert any(n.startswith(pattern) for n in names), (cap.key, pattern)
            else:
                assert pattern in names, (cap.key, pattern)


def test_no_tool_is_claimed_twice():
    seen: dict[str, str] = {}
    for name in _catalog_tool_names():
        owners = [c.key for c in capabilities.REGISTRY if c.claims(name)]
        assert len(owners) <= 1, (name, owners)
        if owners:
            seen[name] = owners[0]
    assert seen  # sanity: something is claimed


def test_every_builtin_tool_is_claimed_or_explicitly_always_on():
    for ctype in BUILTIN_CONNECTOR_TYPES:
        for spec in CONNECTOR_CATALOG[ctype]:
            name = f"{ctype}.{spec.action}"
            assert capabilities.capability_for_tool(name) is not None or name in capabilities.ALWAYS_ON_TOOLS, name


def test_declarations_are_complete():
    labels = [c.label for c in capabilities.REGISTRY]
    assert len(labels) == len(set(labels))
    for cap in capabilities.REGISTRY:
        assert cap.when_denied.strip(), cap.key
        assert cap.description.strip(), cap.key
        assert cap.risk in ("low", "medium", "high"), cap.key


def test_template_is_not_registered():
    assert isinstance(_template.CAPABILITY, Capability)
    assert _template.CAPABILITY.key == "example"
    assert all(c.key != "example" for c in capabilities.REGISTRY)


def test_capability_for_tool_matches_exact_and_prefix():
    assert capabilities.capability_for_tool("web.search").key == "web_browsing"
    assert capabilities.capability_for_tool("reminders.create").key == "reminders"
    assert capabilities.capability_for_tool("desktop.screenshot").key == "screen"
    assert capabilities.capability_for_tool("system.capabilities") is None
    assert capabilities.capability_for_tool("gmail.send_email") is None


def test_get_unknown_key_raises():
    with pytest.raises(KeyError):
        capabilities.get("nope")
```

`backend/tests/test_capabilities_report.py`:
```python
from __future__ import annotations

from services import capabilities
from services.capabilities.base import ProbeResult, ReportContext
from services.capabilities import screen
from services.capabilities.prompt import render_permissions_block


def ctx(**over) -> ReportContext:
    base = dict(in_container=False, platform="darwin", telegram_configured=True, browser_installed=True, executable="/usr/bin/python3")
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd backend && python3 -m pytest tests/test_capabilities_registry.py tests/test_capabilities_report.py -q`
Expected: `ModuleNotFoundError: No module named 'services.capabilities'`

- [ ] **Step 3: Create `base.py`**

```python
"""Capability declarations.

A capability is the unit the owner switches on or off. One declaration
drives four things at once: the Permissions page and setup wizard, the
tool gates (offer and dispatch), the agent's own <permissions> block, and
`system.capabilities`. Keep this module free of OS and database access:
availability and probe callables read only the ReportContext they are
given, which is what makes every capability testable without a display.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional

ProbeState = Literal["granted", "denied", "not_required", "unknown"]
Effective = Literal["on", "off", "blocked"]
Risk = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class ReportContext:
    """Facts about the running environment, gathered once per report."""

    in_container: bool
    platform: str
    telegram_configured: bool
    browser_installed: bool
    executable: str = ""


@dataclass(frozen=True)
class Availability:
    available: bool
    reason: str = ""


@dataclass(frozen=True)
class ProbeResult:
    state: ProbeState
    detail: str = ""
    fix_url: Optional[str] = None
    fix_steps: tuple[str, ...] = ()


def always_available(_ctx: ReportContext) -> Availability:
    return Availability(True)


@dataclass(frozen=True)
class Capability:
    key: str
    label: str
    description: str
    tools: tuple[str, ...]
    default_enabled: bool
    risk: Risk
    when_denied: str
    availability: Callable[[ReportContext], Availability] = always_available
    probe: Optional[Callable[[ReportContext], ProbeResult]] = None
    request_access: Optional[Callable[[], None]] = None
    install: Optional[str] = None

    def claims(self, tool_name: str) -> bool:
        """True when this capability gates *tool_name*. A pattern ending in
        "." matches a whole family ("reminders." → reminders.create …)."""
        for pattern in self.tools:
            if pattern.endswith("."):
                if tool_name.startswith(pattern):
                    return True
            elif tool_name == pattern:
                return True
        return False


@dataclass(frozen=True)
class CapabilityStatus:
    key: str
    label: str
    description: str
    risk: Risk
    enabled: bool
    default_enabled: bool
    available: bool
    availability_reason: str
    probe_state: ProbeState
    probe_detail: str
    fix_url: Optional[str]
    fix_steps: tuple[str, ...]
    effective: Effective
    reason: str
    can_request_access: bool
    install: Optional[str]
    when_denied: str
    tools: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "risk": self.risk,
            "enabled": self.enabled,
            "default_enabled": self.default_enabled,
            "available": self.available,
            "availability_reason": self.availability_reason,
            "probe_state": self.probe_state,
            "probe_detail": self.probe_detail,
            "fix_url": self.fix_url,
            "fix_steps": list(self.fix_steps),
            "effective": self.effective,
            "reason": self.reason,
            "can_request_access": self.can_request_access,
            "install": self.install,
            "when_denied": self.when_denied,
            "tools": list(self.tools),
        }
```

- [ ] **Step 4: Create `env.py` and `macos.py`**

`env.py`:
```python
"""Where is Crawler running? Read once per report, never per tool call."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def in_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("CRAWLER_CONTAINER", "") == "1"


def platform_name() -> str:
    return sys.platform
```

`macos.py`:
```python
"""ctypes shims over CoreGraphics for the Screen Recording permission.

Every function returns None (or False) when not on macOS or when the
framework cannot be loaded, so callers degrade to "unknown" instead of
crashing on Linux CI or inside a container.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from typing import Optional

SCREEN_SETTINGS_URL = (
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
)
_CORE_GRAPHICS = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"


def _core_graphics() -> Optional[ctypes.CDLL]:
    if sys.platform != "darwin":
        return None
    try:
        return ctypes.cdll.LoadLibrary(_CORE_GRAPHICS)
    except OSError:
        return None


def screen_capture_preflight() -> Optional[bool]:
    """Whether this process may capture the screen (no prompt shown)."""
    cg = _core_graphics()
    if cg is None:
        return None
    try:
        fn = cg.CGPreflightScreenCaptureAccess
    except AttributeError:  # macOS < 10.15 has no TCC gate for this
        return None
    fn.restype = ctypes.c_bool
    return bool(fn())


def screen_capture_request() -> Optional[bool]:
    """Ask macOS to show the Screen Recording prompt (once per binary)."""
    cg = _core_graphics()
    if cg is None:
        return None
    try:
        fn = cg.CGRequestScreenCaptureAccess
    except AttributeError:
        return None
    fn.restype = ctypes.c_bool
    return bool(fn())


def open_settings(url: str = SCREEN_SETTINGS_URL) -> bool:
    """Open System Settings on the pane the user has to toggle."""
    if sys.platform != "darwin":
        return False
    try:
        subprocess.run(["open", url], check=False, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
```

- [ ] **Step 5: Create the six capability files**

`web_browsing.py`:
```python
from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="web_browsing",
    label="Browse the web",
    description="Search the public web and read pages as text to answer questions and research tasks.",
    tools=("web.search", "web.fetch_page"),
    default_enabled=True,
    risk="low",
    when_denied="Web browsing is turned off. The owner can turn it on in Settings → Permissions.",
)
```

`site_screenshots.py`:
```python
from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.browser_installed:
        return Availability(True)
    return Availability(False, "The hidden browser is not installed yet (about 150–300 MB).")


CAPABILITY = Capability(
    key="site_screenshots",
    label="Screenshots of websites",
    description="Open a web page in a hidden browser and take a picture of it, for pages that cannot be read as text (flights, products).",
    tools=("web.screenshot",),
    default_enabled=True,
    risk="low",
    when_denied="Website screenshots are turned off. The owner can turn them on in Settings → Permissions.",
    availability=availability,
    install="browser",
)
```

`screen.py`:
```python
from services.capabilities import macos
from services.capabilities.base import Availability, Capability, ProbeResult, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.in_container:
        return Availability(
            False,
            "Not available in this environment (container). It works when Crawler runs directly on your Mac or PC.",
        )
    if ctx.platform not in ("darwin", "win32"):
        return Availability(False, "Desktop capture is supported on macOS and Windows only.")
    return Availability(True)


def probe(ctx: ReportContext) -> ProbeResult:
    if ctx.platform == "win32":
        return ProbeResult("not_required", "Windows needs no permission for screen capture.")
    if ctx.platform != "darwin":
        return ProbeResult("unknown", "No permission check on this platform.")
    granted = macos.screen_capture_preflight()
    if granted is None:
        return ProbeResult("unknown", "Could not query the macOS Screen Recording permission.")
    who = ctx.executable or "the Crawler process"
    if granted:
        return ProbeResult("granted", f"Screen Recording is granted to {who}.")
    return ProbeResult(
        "denied",
        f"macOS has not granted Screen Recording to {who}.",
        fix_url=macos.SCREEN_SETTINGS_URL,
        fix_steps=(
            "Open System Settings → Privacy & Security → Screen Recording.",
            f"Turn on the switch for {who} (or for Terminal, if Crawler was started from it).",
            "Restart Crawler.",
        ),
    )


def request_access() -> None:
    macos.screen_capture_request()
    macos.open_settings()


CAPABILITY = Capability(
    key="screen",
    label="See my screen",
    description="Take a picture of what is on this computer's display when you ask for it.",
    tools=("desktop.screenshot",),
    default_enabled=False,
    risk="high",
    when_denied="Seeing the screen is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
    probe=probe,
    request_access=request_access,
)
```

`reminders.py`:
```python
from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="reminders",
    label="Reminders",
    description="Set, list and cancel reminders that are delivered to you (Telegram when linked).",
    tools=("reminders.",),
    default_enabled=True,
    risk="low",
    when_denied="Reminders are turned off. The owner can turn them on in Settings → Permissions.",
)
```

`installs.py`:
```python
from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="installs",
    label="Install optional software (asks first)",
    description="Install optional components from a fixed list, such as the hidden browser, after asking you each time.",
    tools=("system.install_capability",),
    default_enabled=True,
    risk="medium",
    when_denied="Installing software is turned off. The owner can turn it on in Settings → Permissions.",
)
```

`telegram.py`:
```python
from services.capabilities.base import Availability, Capability, ReportContext


def availability(ctx: ReportContext) -> Availability:
    if ctx.telegram_configured:
        return Availability(True)
    return Availability(False, "No Telegram bot token is configured yet. Add one in Settings → Telegram.")


CAPABILITY = Capability(
    key="telegram",
    label="Telegram chat and approvals",
    description="Chat with Crawler from Telegram and approve actions from your phone.",
    tools=(),
    default_enabled=True,
    risk="medium",
    when_denied="Telegram is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
)
```

- [ ] **Step 6: Create `__init__.py` (registry + report)**

```python
"""The capability registry. See README.md for how to add one."""

from __future__ import annotations

import sys
import time
from typing import Iterable, Mapping, Optional

from services.capabilities import (
    installs,
    reminders,
    screen,
    site_screenshots,
    telegram,
    web_browsing,
)
from services.capabilities.base import (
    Capability,
    CapabilityStatus,
    ProbeResult,
    ReportContext,
)
from services.capabilities.env import in_container, platform_name

REGISTRY: tuple[Capability, ...] = (
    web_browsing.CAPABILITY,
    site_screenshots.CAPABILITY,
    screen.CAPABILITY,
    reminders.CAPABILITY,
    installs.CAPABILITY,
    telegram.CAPABILITY,
)

# Tools no capability gates. Listed explicitly so that a new built-in tool
# nobody claimed fails the registry test instead of being silently always-on.
ALWAYS_ON_TOOLS: frozenset[str] = frozenset({"system.capabilities"})

_BY_KEY: dict[str, Capability] = {c.key: c for c in REGISTRY}

_PROBE_TTL_S = 10.0
_probe_cache: dict[str, tuple[float, ProbeResult]] = {}


def get(key: str) -> Capability:
    return _BY_KEY[key]


def keys() -> tuple[str, ...]:
    return tuple(_BY_KEY)


def capability_for_tool(tool_name: str) -> Optional[Capability]:
    for cap in REGISTRY:
        if cap.claims(tool_name):
            return cap
    return None


def default_switches() -> dict[str, bool]:
    return {c.key: c.default_enabled for c in REGISTRY}


def default_context(*, telegram_configured: bool = False) -> ReportContext:
    from services.tools.system import browser_installed

    return ReportContext(
        in_container=in_container(),
        platform=platform_name(),
        telegram_configured=telegram_configured,
        browser_installed=browser_installed(),
        executable=sys.executable,
    )


def clear_probe_cache() -> None:
    _probe_cache.clear()


def _cached_probe(cap: Capability, ctx: ReportContext, use_cache: bool) -> ProbeResult:
    assert cap.probe is not None
    now = time.monotonic()
    if use_cache:
        hit = _probe_cache.get(cap.key)
        if hit is not None and now - hit[0] < _PROBE_TTL_S:
            return hit[1]
    result = cap.probe(ctx)
    _probe_cache[cap.key] = (now, result)
    return result


def _status(cap: Capability, enabled: bool, ctx: ReportContext, use_cache: bool) -> CapabilityStatus:
    avail = cap.availability(ctx)
    probe = ProbeResult("not_required")
    if enabled and avail.available and cap.probe is not None:
        probe = _cached_probe(cap, ctx, use_cache)

    if not enabled:
        effective, reason = "off", "Turned off by the owner."
    elif not avail.available:
        effective, reason = "blocked", avail.reason
    elif probe.state == "denied":
        effective, reason = "blocked", probe.detail
    else:
        effective, reason = "on", ""

    return CapabilityStatus(
        key=cap.key,
        label=cap.label,
        description=cap.description,
        risk=cap.risk,
        enabled=enabled,
        default_enabled=cap.default_enabled,
        available=avail.available,
        availability_reason=avail.reason,
        probe_state=probe.state,
        probe_detail=probe.detail,
        fix_url=probe.fix_url,
        fix_steps=probe.fix_steps,
        effective=effective,  # type: ignore[arg-type]
        reason=reason,
        can_request_access=bool(cap.request_access) and avail.available and probe.state == "denied",
        install=cap.install,
        when_denied=cap.when_denied,
        tools=cap.tools,
    )


def report(
    switches: Mapping[str, bool], ctx: ReportContext, *, use_cache: bool = True
) -> list[CapabilityStatus]:
    return [
        _status(cap, bool(switches.get(cap.key, cap.default_enabled)), ctx, use_cache)
        for cap in REGISTRY
    ]


def enabled_keys(switches: Mapping[str, bool], ctx: ReportContext) -> frozenset[str]:
    return frozenset(s.key for s in report(switches, ctx) if s.effective == "on")


def statuses_by_key(statuses: Iterable[CapabilityStatus]) -> dict[str, CapabilityStatus]:
    return {s.key: s for s in statuses}
```

- [ ] **Step 7: Create `prompt.py`, `_template.py`, `README.md`**

`prompt.py`:
```python
"""The <permissions> block the runtime appends to the system prompt so the
agent explains what is off instead of guessing or claiming it cannot."""

from __future__ import annotations

from typing import Iterable

from services.capabilities.base import CapabilityStatus


def render_permissions_block(statuses: Iterable[CapabilityStatus]) -> str:
    lines: list[str] = []
    for s in statuses:
        if s.effective == "on":
            lines.append(f"- {s.label}: on")
        elif s.effective == "off":
            lines.append(f"- {s.label}: off — {s.when_denied}")
        else:
            extra = f" To fix: {s.fix_steps[0]}" if s.fix_steps else ""
            if s.install:
                extra += f" You may offer system.install_capability(name='{s.install}')."
            lines.append(f"- {s.label}: blocked — {s.reason}{extra}")
    return "<permissions>\n" + "\n".join(lines) + "\n</permissions>"
```

`_template.py`:
```python
"""Copy this file to services/capabilities/<key>.py, fill it in, and add
CAPABILITY to REGISTRY in __init__.py. Every field is explained here.
This file is NOT registered; the registry test checks that."""

from __future__ import annotations

from services.capabilities.base import Availability, Capability, ProbeResult, ReportContext


def availability(ctx: ReportContext) -> Availability:
    """Can this environment do it at all? Read ctx only — no OS calls here."""
    return Availability(True)


def probe(ctx: ReportContext) -> ProbeResult:
    """OS permission check (native installs only). Return "denied" with a
    fix_url and fix_steps when the user has to flip a switch themselves."""
    return ProbeResult("not_required")


def request_access() -> None:
    """Trigger the OS prompt and/or open the right settings pane."""


CAPABILITY = Capability(
    key="example",                      # snake_case, stable: used in storage and the API
    label="Example capability",         # shown in the wizard and Settings
    description="One sentence: what the agent can do when this is on.",
    tools=("example.read", "example."), # exact names or a family prefix ending in "."
    default_enabled=False,              # high-risk capabilities start off
    risk="medium",                      # low | medium | high — shown as a badge
    when_denied="Example is turned off. The owner can turn it on in Settings → Permissions.",
    availability=availability,
    probe=probe,                        # omit when nothing to check
    request_access=request_access,      # omit when nothing to request
    install=None,                       # or an ALLOWLIST key from services/tools/system.py
)
```

`README.md`:
```markdown
# Adding a capability

A capability is one switch the owner sees in the setup wizard and in
Settings → Permissions. Declaring it drives everything else: the tools it
unlocks are offered only when it is on, refused at dispatch when it is off,
and the agent's `<permissions>` block tells it (and the user) why.

## Five steps

1. **Toolkit.** Write `services/tools/<family>.py` with
   `async def execute(self, action, params, ...) -> dict` returning
   `{"ok": True, ...}` or `{"ok": False, "error": "..."}`. Fail closed.
2. **Catalog and policy.** In `services/agent/tool_registry.py` add the
   `ToolSpec`s under `CONNECTOR_CATALOG["<family>"]`, add `<family>` to
   `BUILTIN_CONNECTOR_TYPES` and `_BUILTIN_STANCE`, and register the toolkit
   in `ConnectorToolExecutor._builtins`. In `services/agent/permissions.py`
   add one policy row per `ActionCategory` (hard-block what you don't use).
3. **Capability file.** Copy `_template.py` to `services/capabilities/<key>.py`,
   fill it in, and append `CAPABILITY` to `REGISTRY` in `__init__.py`.
4. **Tests.** Toolkit behaviour with fakes (no display, no network), and one
   report test for your `availability`/`probe`.
5. **Run** `python3 -m pytest tests/test_capabilities_registry.py tests/test_capabilities_report.py -q`.
   It fails if a claimed tool does not exist, a tool is claimed twice, a
   built-in tool is unclaimed, or `when_denied` is empty.

Nothing in the wizard, Settings, the gates or the prompt needs changing.

## Rules

- Consequential actions (send, create account, spend, delete, install,
  type into a form) must be WRITE/DELETE/EXECUTE in the catalog so the
  approval flow applies. READ runs unattended when the capability is on.
- Never ask the user for a password in chat; credentials go through the
  Connectors UI and are filled in by the toolkit.
- OS permission grants attach to the running binary on macOS; say which
  one in `probe()` (`ctx.executable`).
```

- [ ] **Step 8: Run the tests**

Run: `cd backend && python3 -m pytest tests/test_capabilities_registry.py tests/test_capabilities_report.py -q`
Expected: `test_every_claimed_tool_exists_in_the_catalog` and `test_capability_for_tool_matches_exact_and_prefix` FAIL on `desktop.screenshot` (added in Task 2); everything else PASS.

- [ ] **Step 9: Commit**

```bash
git add backend/services/capabilities backend/tests/test_capabilities_registry.py backend/tests/test_capabilities_report.py
git commit -m "feat(capabilities): registry, report and prompt block for owner-switchable capabilities"
```

---

## Wave 1 — Task 2: `desktop.screenshot` + offer/dispatch gates (T1, part B — same agent, after Task 1)

**Files:**
- Create: `backend/services/tools/desktop.py`, `backend/tests/test_desktop_tools.py`, `backend/tests/test_capability_gating.py`
- Modify: `backend/services/agent/tool_registry.py` (catalog, `BUILTIN_CONNECTOR_TYPES`, `_BUILTIN_STANCE`, `build_tools`, executor), `backend/services/agent/permissions.py` (policy rows), `backend/requirements.txt` (add `mss>=9.0,<11`, `Pillow>=10.0,<12`)

- [ ] **Step 1: Install the two new dependencies locally**

Run: `python3 -m pip install "mss>=9.0,<11" "Pillow>=10.0,<12"` then add both lines to `backend/requirements.txt` after `playwright`, with a comment: `# Desktop capture for desktop.screenshot (capability "screen").`

- [ ] **Step 2: Write the failing toolkit tests**

`backend/tests/test_desktop_tools.py`:
```python
from __future__ import annotations

import base64
import io

import pytest
from PIL import Image

from services.capabilities.base import ProbeResult
from services.tools.desktop import DesktopToolkit


def fake_grabber(width=3000, height=2000):
    def grab(display: int):
        return b"\x10\x20\x30" * (width * height), width, height
    return grab


@pytest.mark.asyncio
async def test_screenshot_downscales_to_1280_jpeg():
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: ProbeResult("granted"))
    result = await kit.execute("screenshot", {})
    assert result["ok"] is True
    assert result["image_format"] == "jpeg"
    assert result["image"].startswith("data:image/jpeg;base64,")
    assert max(result["width"], result["height"]) == 1280
    raw = base64.b64decode(result["image"].split(",", 1)[1])
    img = Image.open(io.BytesIO(raw))
    assert img.format == "JPEG" and img.size == (result["width"], result["height"])
    assert result["display"] == 0 and "captured_at" in result


@pytest.mark.asyncio
async def test_screenshot_refused_when_probe_denied():
    denied = ProbeResult("denied", "no grant", fix_url="x-apple.systempreferences:x", fix_steps=("Open Settings",))
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: denied)
    result = await kit.execute("screenshot", {})
    assert result["ok"] is False
    assert result["fix_url"] == "x-apple.systempreferences:x"
    assert "no grant" in result["error"]


@pytest.mark.asyncio
async def test_grabber_failure_is_reported_not_raised():
    def boom(display):
        raise OSError("no display")
    kit = DesktopToolkit(grabber=boom, probe=lambda: ProbeResult("granted"))
    result = await kit.execute("screenshot", {"display": 1})
    assert result["ok"] is False and "no display" in result["error"]


@pytest.mark.asyncio
async def test_unknown_action_and_bad_args_fail_closed():
    kit = DesktopToolkit(grabber=fake_grabber(), probe=lambda: ProbeResult("granted"))
    assert (await kit.execute("type", {}))["ok"] is False
    assert (await kit.execute("screenshot", {"display": "zero"}))["ok"] is False
```

`backend/tests/test_capability_gating.py`:
```python
"""Off-by-default must hold at BOTH gates without any wiring: a caller that
forgets the enabled set gets the registry defaults, and the executor
refuses a tool whose capability is off."""
from __future__ import annotations

import pytest

from services.agent.tool_registry import (
    BUILTIN_CONNECTOR_TYPES,
    ConnectorToolExecutor,
    build_tools,
)


def names(tools):
    return {t.name for t in tools}


def test_desktop_is_a_builtin_type():
    assert "desktop" in BUILTIN_CONNECTOR_TYPES


def test_default_offer_excludes_screen_and_includes_web():
    offered = names(build_tools([]))
    assert "desktop.screenshot" not in offered
    assert {"web.search", "web.fetch_page", "reminders.create", "system.capabilities"} <= offered


def test_explicit_enabled_set_gates_the_offer():
    offered = names(build_tools([], enabled_capabilities=frozenset({"screen"})))
    assert "desktop.screenshot" in offered
    assert "web.search" not in offered and "reminders.create" not in offered
    assert "system.capabilities" in offered  # always-on


@pytest.mark.asyncio
async def test_executor_refuses_tool_of_off_capability():
    async def gate():
        return frozenset({"web_browsing"})
    ex = ConnectorToolExecutor(session_factory=None, capability_gate=gate)
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["ok"] is False
    assert result.get("capability") == "screen"
    assert "turned off" in result["error"].lower()


@pytest.mark.asyncio
async def test_executor_default_gate_is_registry_defaults():
    ex = ConnectorToolExecutor(session_factory=None)
    result = await ex.execute("desktop.screenshot", {}, user_id="u1")
    assert result["ok"] is False and result.get("capability") == "screen"
```

- [ ] **Step 3: Run to verify they fail**

Run: `python3 -m pytest tests/test_desktop_tools.py tests/test_capability_gating.py -q` → `ModuleNotFoundError: services.tools.desktop` / `TypeError: unexpected keyword 'enabled_capabilities'`.

- [ ] **Step 4: Create `services/tools/desktop.py`**

```python
"""desktop.* built-in tools: what is on this computer's display.

Capability "screen" (off by default). The grabber and the permission probe
are injectable so tests never need a display. The result has the same
shape as web.screenshot so the runtime's vision feed and the Telegram
photo delivery apply unchanged.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import io
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.capabilities.base import ProbeResult

logger = structlog.get_logger(__name__)

Grabber = Callable[[int], tuple[bytes, int, int]]  # raw RGB bytes, width, height

MAX_EDGE_PX = 1280
JPEG_QUALITY = 70


def _mss_grab(display: int) -> tuple[bytes, int, int]:
    import mss  # imported lazily: absent on servers that never capture

    with mss.mss() as sct:
        monitors = sct.monitors[1:] or sct.monitors[:1]
        index = max(0, min(display, len(monitors) - 1))
        shot = sct.grab(monitors[index])
        return shot.rgb, shot.width, shot.height


def _probe_now() -> ProbeResult:
    from services import capabilities
    from services.capabilities import screen

    return screen.probe(capabilities.default_context())


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


class DesktopToolkit:
    def __init__(
        self,
        grabber: Optional[Grabber] = None,
        probe: Optional[Callable[[], ProbeResult]] = None,
    ) -> None:
        self._grab = grabber or _mss_grab
        self._probe = probe or _probe_now

    async def execute(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one ``desktop.*`` action. Unknown actions fail closed."""
        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "screenshot": self.screenshot,
        }
        handler = handlers.get(action)
        if handler is None:
            return _error(f"Unknown desktop action '{action}'.")
        params = params or {}
        try:
            inspect.signature(handler).bind(**params)
        except TypeError as exc:
            return _error(f"Invalid arguments for desktop.{action}: {exc}")
        return await handler(**params)

    async def screenshot(self, display: int = 0) -> dict[str, Any]:
        if not isinstance(display, int) or isinstance(display, bool):
            return _error("display must be an integer (0 = main display).")
        probe = self._probe()
        if probe.state == "denied":
            return _error(
                f"Cannot capture the screen: {probe.detail}",
                fix_url=probe.fix_url,
                fix_steps=list(probe.fix_steps),
            )
        try:
            rgb, width, height = await asyncio.to_thread(self._grab, display)
        except Exception as exc:
            logger.warning("desktop_screenshot_failed", error=str(exc)[:200])
            return _error(f"Screen capture failed: {exc}")

        from PIL import Image

        image = Image.frombytes("RGB", (width, height), rgb)
        image.thumbnail((MAX_EDGE_PX, MAX_EDGE_PX))
        buf = io.BytesIO()
        image.save(buf, format="JPEG", quality=JPEG_QUALITY, optimize=True)
        data_url = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
        return {
            "ok": True,
            "image": data_url,
            "image_format": "jpeg",
            "width": image.width,
            "height": image.height,
            "display": display,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
```

- [ ] **Step 5: Catalog, policy, built-in type**

In `services/agent/permissions.py`, next to the `system` rows, add:
```python
    # desktop: a picture of the screen is a read; there is no write surface
    # yet (input control is a later capability with its own rows).
    ("desktop", ActionCategory.READ): PermissionTier.AUTO_APPROVE,
    ("desktop", ActionCategory.WRITE): PermissionTier.HARD_BLOCKED,
    ("desktop", ActionCategory.DELETE): PermissionTier.HARD_BLOCKED,
    ("desktop", ActionCategory.EXECUTE): PermissionTier.HARD_BLOCKED,
    ("desktop", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
```
In `tool_registry.py` `CONNECTOR_CATALOG`, after `"system"`:
```python
    # Built-in, capability "screen" (off by default): the owner turns it on
    # in Settings → Permissions. Reads the display; never types or clicks.
    "desktop": [
        ToolSpec(
            "screenshot",
            "Take a picture of what is currently on this computer's screen "
            "(the real desktop, not a web page). Use when the user asks what "
            "they are looking at or to send them a screenshot of the computer.",
            ActionCategory.READ,
            _schema(display={"type": "integer", "description": "Display index, 0 = main"}),
        ),
    ],
```
Then `BUILTIN_CONNECTOR_TYPES = ("web", "reminders", "system", "desktop")` and `_BUILTIN_STANCE["desktop"] = "user_confirm"` (with a comment: reads are auto by policy; the capability switch is the real gate).

- [ ] **Step 6: Offer gate in `build_tools`**

Add keyword `enabled_capabilities: Optional[frozenset[str]] = None` to `build_tools`. At the top of the body:
```python
    from services import capabilities as capability_registry

    if enabled_capabilities is None:
        # No wiring supplied: fall back to the registry defaults so a caller
        # that forgets the argument can never switch on an off-by-default
        # capability (screen). Wired callers pass the owner's effective set.
        enabled_capabilities = frozenset(
            k for k, on in capability_registry.default_switches().items() if on
        )
```
And where each `Tool(...)` is appended, skip when gated:
```python
            cap = capability_registry.capability_for_tool(tool_name)
            if cap is not None and cap.key not in enabled_capabilities:
                continue
```
(`tool_name` is the `f"{prefix}.{spec.action}"` the function already builds; place the check right before constructing the `Tool`.) Update the docstring: "``enabled_capabilities`` is the owner's effective set (see services/capabilities); tools of any other capability are not offered."

- [ ] **Step 7: Dispatch gate in the executor**

`ConnectorToolExecutor.__init__` gains `desktop_toolkit: Optional[DesktopToolkit] = None` and `capability_gate: Optional[Callable[[], Awaitable[frozenset[str]]]] = None`; store `self._desktop = desktop_toolkit or DesktopToolkit()` and `self._capability_gate = capability_gate`. Add:
```python
    async def _enabled_capabilities(self) -> frozenset[str]:
        if self._capability_gate is not None:
            return await self._capability_gate()
        from services import capabilities as capability_registry

        return frozenset(k for k, on in capability_registry.default_switches().items() if on)
```
In `execute`, right after the `user_confirmed` stripping and before the `web` branch:
```python
        from services import capabilities as capability_registry

        cap = capability_registry.capability_for_tool(tool_name)
        if cap is not None and cap.key not in await self._enabled_capabilities():
            # Second gate, independent of the offer: a tool the owner turned
            # off is refused even if the model somehow names it.
            logger.info("tool_capability_off", tool=tool_name, capability=cap.key, user_id=user_id)
            return {
                "ok": False,
                "capability": cap.key,
                "error": f"{cap.label} is turned off. {cap.when_denied}",
            }
```
Add the `desktop` branch after `system`:
```python
        if resolved.connector_type == "desktop":
            if resolved.spec.category != ActionCategory.READ:
                return {"ok": False, "error": f"Desktop action '{resolved.action}' is not permitted."}
            return await self._desktop.execute(resolved.action, dict(arguments))
```

- [ ] **Step 8: Run the new tests, then the whole registry/tool suite**

Run: `python3 -m pytest tests/test_desktop_tools.py tests/test_capability_gating.py tests/test_capabilities_registry.py tests/test_capabilities_report.py -q` → all PASS.
Run: `python3 -m pytest tests/test_tool_registry.py tests/test_system_tools.py tests/test_web_tools.py tests/test_agent_loop_security.py -q` → PASS (fix any test that asserted the exact built-in list by adding `desktop`).

- [ ] **Step 9: Commit**

```bash
git add backend/services/tools/desktop.py backend/services/agent/tool_registry.py backend/services/agent/permissions.py backend/requirements.txt backend/tests/test_desktop_tools.py backend/tests/test_capability_gating.py
git commit -m "feat(desktop): desktop.screenshot tool behind the off-by-default screen capability; gate tools at offer and dispatch"
```

---

## Wave 1 — Task 3: installation record + `InstallationService` (T2)

**Files:**
- Create: `backend/models/installation.py`, `backend/alembic/versions/0008_installation.py`, `backend/services/installation.py`, `backend/tests/test_installation.py`
- Modify: `backend/models/__init__.py` (export), `backend/core/config.py` (`PROVIDER_KEY_FIELDS`)

> This task imports `services.capabilities` (Task 1). Until Task 1 is merged, run these tests in a worktree that has Task 1's branch merged in, or stub with `git merge <task1-branch>` locally.

- [ ] **Step 1: Write the failing tests**

`backend/tests/test_installation.py`:
```python
from __future__ import annotations

import pytest
from sqlalchemy import select

from core.config import settings
from models.audit import AuditLog
from services.installation import InstallationService
from tests.conftest import make_user


@pytest.mark.asyncio
async def test_capabilities_default_then_patch_and_audit(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    caps = await svc.capabilities()
    assert caps["screen"] is False and caps["web_browsing"] is True

    user, _token = await make_user(session_factory, "owner@example.com")
    statuses = await svc.set_capabilities({"screen": True, "reminders": False}, actor_id=user.id)
    by = {s.key: s for s in statuses}
    assert by["reminders"].enabled is False
    assert (await svc.capabilities())["screen"] is True

    async with session_factory() as s:
        row = (await s.execute(select(AuditLog).order_by(AuditLog.created_at.desc()))).scalars().first()
    assert row.connector_name == "installation" and row.action == "capabilities_updated"


@pytest.mark.asyncio
async def test_unknown_capability_key_is_rejected(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    with pytest.raises(ValueError):
        await svc.set_capabilities({"nope": True}, actor_id=user.id)


@pytest.mark.asyncio
async def test_api_key_env_wins_over_db(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "", raising=False)
    await svc.set_llm("gemini", "gemini-2.5-flash", "db-key", actor_id=user.id)
    assert await svc.llm_api_key("gemini") == "db-key"
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-key", raising=False)
    svc.invalidate()
    assert await svc.llm_api_key("gemini") == "env-key"
    assert await svc.llm_defaults() == ("gemini", "gemini-2.5-flash")
    assert await svc.provider_configured() is True


@pytest.mark.asyncio
async def test_secrets_are_encrypted_at_rest(session_factory):
    from models.installation import Installation
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("openai", "gpt-4o-mini", "sk-secret-value", actor_id=user.id)
    await svc.set_telegram_token("123456:ABCDEFghijklmnopqrstuvwxyz0123456789", actor_id=user.id)
    async with session_factory() as s:
        row = (await s.execute(select(Installation))).scalar_one()
    assert b"sk-secret-value" not in (row.llm_api_keys or b"")
    assert b"123456:" not in (row.telegram_bot_token or b"")
    assert await svc.telegram_token() == "123456:ABCDEFghijklmnopqrstuvwxyz0123456789"


@pytest.mark.asyncio
async def test_ollama_needs_no_key(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    await svc.set_llm("ollama", "llama3.2", None, actor_id=user.id)
    assert await svc.llm_api_key("ollama") == ""
    assert await svc.provider_configured() is True


@pytest.mark.asyncio
async def test_needs_setup_and_completion(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True, raising=False)
    assert await svc.needs_setup() is True
    assert await svc.registration_allowed() is True  # env applies before setup
    user, _ = await make_user(session_factory, "o@example.com")
    assert await svc.needs_setup() is True  # owner exists but wizard not finished
    await svc.mark_setup_complete(allow_registration=False, actor_id=user.id)
    assert await svc.needs_setup() is False
    assert await svc.registration_allowed() is False  # stored switch applies after


@pytest.mark.asyncio
async def test_legacy_install_is_stamped_when_env_key_present(session_factory, monkeypatch):
    svc = InstallationService(session_factory)
    await make_user(session_factory, "o@example.com")
    monkeypatch.setattr(settings, "LLM_PROVIDER", "gemini", raising=False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "env-key", raising=False)
    assert await svc.stamp_setup_if_legacy() is True
    assert await svc.needs_setup() is False
    assert await svc.stamp_setup_if_legacy() is False  # idempotent


@pytest.mark.asyncio
async def test_on_change_fires_with_topic(session_factory):
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "o@example.com")
    seen: list[str] = []

    async def cb(topic: str) -> None:
        seen.append(topic)

    svc.on_change(cb)
    await svc.set_capabilities({"screen": True}, actor_id=user.id)
    await svc.set_telegram_token(None, actor_id=user.id)
    assert seen == ["capabilities", "telegram"]
```

- [ ] **Step 2: Run to verify they fail** → `ModuleNotFoundError: services.installation`.

- [ ] **Step 3: `core/config.py`** — add after `_PROVIDER_KEY_MAP`-equivalent needs (near the LLM section):
```python
# Provider name → the Settings attribute that holds its API key. Shared by
# the runtime and the installation service so the ".env wins" rule has one
# definition.
PROVIDER_KEY_FIELDS: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "grok": "GROK_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}
```
(Place it at module level after the `Settings` class, before `settings = Settings()`; in `services/agent/runtime.py` replace the literal `_PROVIDER_KEY_MAP = {...}` with `from core.config import PROVIDER_KEY_FIELDS as _PROVIDER_KEY_MAP`.)

- [ ] **Step 4: `models/installation.py`**

```python
"""The one-row installation record: the owner's capability switches, the
server-wide AI provider and its encrypted keys, the encrypted Telegram bot
token, and whether first-run setup has been completed. Values in the
environment override this row (see services/installation.py)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, Integer, LargeBinary, String, Uuid, false
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base

INSTALLATION_ROW_ID = 1


class Installation(Base):
    __tablename__ = "installation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    llm_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    llm_model: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    llm_api_keys: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    telegram_bot_token: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    allow_registration: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    setup_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    updated_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(), nullable=True)
```
Export `Installation`, `INSTALLATION_ROW_ID` from `models/__init__.py`.

- [ ] **Step 5: Migration `0008_installation.py`** (guarded like 0007 — an adopted legacy DB already has the table from metadata):
```python
"""One-row installation record for owner switches, provider and secrets.

Revision ID: 0008_installation
Revises: 0007_message_model
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_installation"
down_revision = "0007_message_model"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table("installation"):
        op.create_table(
            "installation",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
            sa.Column("capabilities", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("llm_provider", sa.String(50), nullable=True),
            sa.Column("llm_model", sa.String(200), nullable=True),
            sa.Column("llm_api_keys", sa.LargeBinary(), nullable=True),
            sa.Column("telegram_bot_token", sa.LargeBinary(), nullable=True),
            sa.Column("allow_registration", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("setup_completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_by_user_id", sa.Uuid(), nullable=True),
        )
    bind = op.get_bind()
    exists = bind.execute(sa.text("SELECT 1 FROM installation WHERE id = 1")).first()
    if exists is None:
        bind.execute(sa.text("INSERT INTO installation (id, capabilities, allow_registration, updated_at) VALUES (1, '{}', false, CURRENT_TIMESTAMP)"))


def downgrade() -> None:
    if _has_table("installation"):
        op.drop_table("installation")
```
(On SQLite `false` in raw SQL is fine — SQLAlchemy `sa.false()` is used for the column default; the insert uses `0`/`false` portable form: use `sa.false()` via `sa.insert(sa.table(...))` if the raw string fails on SQLite; test on both.) Add a migration test in `tests/test_migrations.py` style used by 0005/0006 tests: upgrade creates the row; downgrade drops the table.

- [ ] **Step 6: `services/installation.py`**

```python
"""Owner-level configuration of this Crawler install.

One row (models.installation) holds the capability switches, the default
AI provider/model, encrypted provider keys and the encrypted Telegram bot
token. Precedence is environment > database > default: a key in .env
(Docker, CI) always wins, so nothing there changes; the wizard fills the
row for native installs where there is no .env to edit.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog
from sqlalchemy import func, select

from core.config import PROVIDER_KEY_FIELDS, settings
from core.security import decrypt_credentials, encrypt_credentials
from models.audit import AuditStatus
from models.installation import INSTALLATION_ROW_ID, Installation
from models.user import User
from services import capabilities as registry
from services.audit import append_audit_log
from services.capabilities.base import CapabilityStatus, ReportContext

logger = structlog.get_logger(__name__)

ChangeCallback = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class _Snapshot:
    capabilities: dict[str, bool]
    llm_provider: Optional[str]
    llm_model: Optional[str]
    llm_api_keys: dict[str, str]
    telegram_bot_token: Optional[str]
    allow_registration: bool
    setup_completed_at: Optional[datetime]


class InstallationService:
    CACHE_TTL_S = 5.0

    def __init__(self, session_factory: Callable[[], Any], *, config: Any = settings) -> None:
        self._session_factory = session_factory
        self._config = config
        self._snapshot: Optional[tuple[float, _Snapshot]] = None
        self._callbacks: list[ChangeCallback] = []
        self._lock = asyncio.Lock()

    # ── loading ────────────────────────────────────────────────────────

    async def _get_or_create(self, session: Any) -> Installation:
        row = await session.get(Installation, INSTALLATION_ROW_ID)
        if row is None:
            row = Installation(id=INSTALLATION_ROW_ID, capabilities={})
            session.add(row)
            await session.flush()
        return row

    @staticmethod
    def _decrypt_keys(blob: Optional[bytes]) -> dict[str, str]:
        if not blob:
            return {}
        try:
            data = json.loads(decrypt_credentials(blob))
        except Exception:  # wrong ENCRYPTION_KEY or corrupt blob: treat as absent
            logger.warning("installation_keys_undecryptable")
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    async def _load(self) -> _Snapshot:
        now = time.monotonic()
        if self._snapshot is not None and now - self._snapshot[0] < self.CACHE_TTL_S:
            return self._snapshot[1]
        async with self._session_factory() as session:
            row = await self._get_or_create(session)
            await session.commit()
            token = None
            if row.telegram_bot_token:
                try:
                    token = decrypt_credentials(row.telegram_bot_token)
                except Exception:
                    logger.warning("installation_token_undecryptable")
            snap = _Snapshot(
                capabilities={str(k): bool(v) for k, v in (row.capabilities or {}).items()},
                llm_provider=row.llm_provider,
                llm_model=row.llm_model,
                llm_api_keys=self._decrypt_keys(row.llm_api_keys),
                telegram_bot_token=token,
                allow_registration=bool(row.allow_registration),
                setup_completed_at=row.setup_completed_at,
            )
        self._snapshot = (now, snap)
        return snap

    def invalidate(self) -> None:
        self._snapshot = None

    def on_change(self, callback: ChangeCallback) -> None:
        self._callbacks.append(callback)

    async def _changed(self, topic: str) -> None:
        self.invalidate()
        for cb in list(self._callbacks):
            try:
                await cb(topic)
            except Exception as exc:  # a listener must never break a save
                logger.warning("installation_listener_failed", topic=topic, error=str(exc)[:200])

    async def _audit(self, actor_id: Any, action: str, endpoint: str, data: dict[str, Any]) -> None:
        async with self._session_factory() as session:
            await append_audit_log(
                session,
                user_id=actor_id,
                connector_name="installation",
                action=action,
                endpoint=endpoint,
                scope_used="admin",
                status=AuditStatus.approved,
                request_data=data,
            )
            await session.commit()

    # ── capabilities ───────────────────────────────────────────────────

    async def capabilities(self) -> dict[str, bool]:
        stored = (await self._load()).capabilities
        return {**registry.default_switches(), **{k: v for k, v in stored.items() if k in registry.keys()}}

    async def set_capabilities(self, patch: Mapping[str, bool], *, actor_id: Any) -> list[CapabilityStatus]:
        unknown = sorted(set(patch) - set(registry.keys()))
        if unknown:
            raise ValueError(f"Unknown capabilities: {', '.join(unknown)}")
        changes = {k: bool(v) for k, v in patch.items()}
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                row.capabilities = {**(row.capabilities or {}), **changes}
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(actor_id, "capabilities_updated", "/api/capabilities", {"changes": changes})
        await self._changed("capabilities")
        return await self.report()

    async def context(self) -> ReportContext:
        return registry.default_context(telegram_configured=bool(await self.telegram_token()))

    async def report(self) -> list[CapabilityStatus]:
        return registry.report(await self.capabilities(), await self.context())

    async def enabled_keys(self) -> frozenset[str]:
        return registry.enabled_keys(await self.capabilities(), await self.context())

    # ── AI provider ────────────────────────────────────────────────────

    async def llm_defaults(self) -> tuple[str, str]:
        snap = await self._load()
        provider = (snap.llm_provider or self._config.LLM_PROVIDER or "").strip().lower()
        model = (snap.llm_model or self._config.LLM_MODEL or "").strip()
        return provider, model

    async def llm_api_key(self, provider: str) -> Optional[str]:
        name = (provider or "").strip().lower()
        if name == "ollama":
            return ""
        attr = PROVIDER_KEY_FIELDS.get(name)
        env_value = (getattr(self._config, attr, "") or "").strip() if attr else ""
        if env_value:
            return env_value
        stored = (await self._load()).llm_api_keys.get(name, "").strip()
        return stored or None

    async def provider_configured(self) -> bool:
        provider, _model = await self.llm_defaults()
        return bool(provider) and (await self.llm_api_key(provider)) is not None

    async def set_llm(self, provider: str, model: str, api_key: Optional[str], *, actor_id: Any) -> None:
        name = (provider or "").strip().lower()
        if name not in PROVIDER_KEY_FIELDS and name != "ollama":
            raise ValueError(f"Unknown provider '{provider}'")
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                keys = self._decrypt_keys(row.llm_api_keys)
                if api_key:
                    keys[name] = api_key.strip()
                row.llm_api_keys = encrypt_credentials(json.dumps(keys)) if keys else None
                row.llm_provider = name
                row.llm_model = model.strip()
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(actor_id, "provider_updated", "/api/setup/provider", {"provider": name, "model": model, "key_stored": bool(api_key)})
        await self._changed("llm")

    # ── Telegram ───────────────────────────────────────────────────────

    async def telegram_token(self) -> Optional[str]:
        env_value = (getattr(self._config, "TELEGRAM_BOT_TOKEN", "") or "").strip()
        if env_value:
            return env_value
        return (await self._load()).telegram_bot_token or None

    async def set_telegram_token(self, token: Optional[str], *, actor_id: Any) -> None:
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                row.telegram_bot_token = encrypt_credentials(token.strip()) if token else None
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(actor_id, "telegram_updated", "/api/setup/telegram", {"configured": bool(token)})
        await self._changed("telegram")

    # ── setup state ────────────────────────────────────────────────────

    async def has_users(self) -> bool:
        async with self._session_factory() as session:
            return (await session.execute(select(func.count()).select_from(User))).scalar_one() > 0

    async def setup_completed(self) -> bool:
        return (await self._load()).setup_completed_at is not None

    async def needs_setup(self) -> bool:
        return not await self.has_users() or not await self.setup_completed()

    async def registration_allowed(self) -> bool:
        snap = await self._load()
        if snap.setup_completed_at is None:
            return bool(self._config.ALLOW_REGISTRATION)
        return snap.allow_registration

    async def mark_setup_complete(self, *, allow_registration: bool, actor_id: Any) -> None:
        async with self._lock:
            async with self._session_factory() as session:
                row = await self._get_or_create(session)
                row.setup_completed_at = datetime.now(timezone.utc)
                row.allow_registration = bool(allow_registration)
                row.updated_by_user_id = actor_id
                await session.commit()
        await self._audit(actor_id, "setup_completed", "/api/setup/complete", {"allow_registration": bool(allow_registration)})
        await self._changed("setup")

    async def stamp_setup_if_legacy(self) -> bool:
        """An install that predates the wizard (users exist, key in .env)
        must not be forced through it after an upgrade."""
        if await self.setup_completed() or not await self.has_users():
            return False
        if not await self.provider_configured():
            return False
        async with self._session_factory() as session:
            row = await self._get_or_create(session)
            row.setup_completed_at = datetime.now(timezone.utc)
            await session.commit()
        self.invalidate()
        logger.info("installation_setup_stamped_legacy")
        return True
```

- [ ] **Step 7: Run** `python3 -m pytest tests/test_installation.py tests/test_migrations.py -q` → PASS. Then `python3 -m ruff check services/installation.py models/installation.py`.

- [ ] **Step 8: Commit**
```bash
git add backend/models/installation.py backend/models/__init__.py backend/alembic/versions/0008_installation.py backend/services/installation.py backend/core/config.py backend/services/agent/runtime.py backend/tests/test_installation.py backend/tests/test_migrations.py
git commit -m "feat(installation): one-row installation record and service (switches, provider keys, telegram token; env > db > default)"
```

---

## Wave 1 — Task 4: Telegram manager (T3)

**Files:** Create `backend/services/notifications/telegram_manager.py`, `backend/tests/test_telegram_manager.py`.

- [ ] **Step 1: Failing tests**

```python
from __future__ import annotations

import pytest

from services.notifications.telegram_manager import TelegramManager


class FakeService:
    instances: list["FakeService"] = []

    def __init__(self, token, session_factory, decide=None, chat=None):
        self.token = token
        self.started = False
        self.stopped = False
        self.decide = decide
        self.chat = chat
        FakeService.instances.append(self)

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def notify_pending(self, action):
        self.notified = action

    async def send_text(self, user_id, text):
        return True

    async def bot_username(self):
        return "crawler_bot"


@pytest.fixture(autouse=True)
def _reset():
    FakeService.instances.clear()


@pytest.mark.asyncio
async def test_apply_starts_restarts_stops_and_is_idempotent():
    hooks: list[str] = []
    mgr = TelegramManager(session_factory=object(), on_start=lambda svc: hooks.append(svc.token), service_factory=FakeService)
    assert mgr.is_running is False
    assert await mgr.apply("111:aaa", True) == "started"
    assert mgr.is_running and FakeService.instances[-1].started and hooks == ["111:aaa"]
    assert await mgr.apply("111:aaa", True) == "unchanged"
    assert await mgr.apply("222:bbb", True) == "restarted"
    assert FakeService.instances[0].stopped and FakeService.instances[-1].token == "222:bbb"
    assert await mgr.apply("222:bbb", False) == "stopped"
    assert mgr.is_running is False and mgr.current is None
    assert await mgr.apply(None, True) == "unchanged"


@pytest.mark.asyncio
async def test_proxies_noop_when_stopped_and_forward_when_running():
    mgr = TelegramManager(session_factory=object(), service_factory=FakeService)
    await mgr.notify_pending({"id": 1})  # no error
    assert await mgr.send_text("u", "hi") is False
    assert await mgr.bot_username() is None
    await mgr.apply("111:aaa", True)
    await mgr.notify_pending({"id": 2})
    assert FakeService.instances[-1].notified == {"id": 2}
    assert await mgr.send_text("u", "hi") is True
    assert await mgr.bot_username() == "crawler_bot"
    await mgr.stop()
    assert mgr.is_running is False
```

- [ ] **Step 2: Run → fails (module missing).**

- [ ] **Step 3: Implement**

```python
"""Starts, restarts and stops the Telegram poller at runtime.

main.py wires the approval store and the reminder sweeper to this manager
once; whether a poller exists behind it can change whenever the owner
saves or clears the bot token in the wizard. Proxies are no-ops while
stopped so callers never need to know.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Optional

import structlog

from services.notifications.telegram import TelegramService

logger = structlog.get_logger(__name__)


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:16]


class TelegramManager:
    def __init__(
        self,
        session_factory: Any,
        *,
        on_start: Optional[Callable[[Any], None]] = None,
        service_factory: Callable[..., Any] = TelegramService,
    ) -> None:
        self._session_factory = session_factory
        self._on_start = on_start
        self._factory = service_factory
        self.current: Optional[Any] = None
        self._fingerprint: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self.current is not None

    async def apply(self, token: Optional[str], enabled: bool) -> str:
        want = bool(token) and enabled
        fp = _fingerprint(token) if token else None
        if not want:
            if self.current is None:
                return "unchanged"
            await self.stop()
            return "stopped"
        if self.current is not None and fp == self._fingerprint:
            return "unchanged"
        restarted = self.current is not None
        if restarted:
            await self.stop()
        service = self._factory(token=token, session_factory=self._session_factory)
        if self._on_start is not None:
            self._on_start(service)
        await service.start()
        self.current, self._fingerprint = service, fp
        logger.info("telegram_manager_applied", state="restarted" if restarted else "started")
        return "restarted" if restarted else "started"

    async def stop(self) -> None:
        service, self.current, self._fingerprint = self.current, None, None
        if service is not None:
            await service.stop()
            logger.info("telegram_manager_stopped")

    async def notify_pending(self, action: Any) -> None:
        if self.current is not None:
            await self.current.notify_pending(action)

    async def send_text(self, user_id: str, text: str) -> bool:
        if self.current is None:
            return False
        return await self.current.send_text(user_id, text)

    async def bot_username(self) -> Optional[str]:
        if self.current is None:
            return None
        return await self.current.bot_username()
```

- [ ] **Step 4: Run → PASS. Commit** `feat(telegram): manager that starts/stops the poller at runtime`.

---

## Wave 1 — Task 5: runtime provider resolver + `permissions_text` (T4)

**Files:** Modify `backend/services/agent/providers.py` (`ProviderNotConfigured`), `backend/services/agent/runtime.py`, `backend/api/routes/agent.py` (error mapping only). Test: `backend/tests/test_runtime_provider_resolution.py`.

- [ ] **Step 1: Failing tests**

```python
from __future__ import annotations

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ProviderNotConfigured
from services.agent.runtime import AgentRuntime


class Source:
    def __init__(self, provider="gemini", model="gemini-2.5-flash", keys=None):
        self.provider, self.model, self.keys = provider, model, keys or {}
        self.calls = 0

    async def llm_defaults(self):
        return self.provider, self.model

    async def llm_api_key(self, provider):
        self.calls += 1
        return self.keys.get(provider)


class FakeProvider:
    def __init__(self, api_key, model):
        self.api_key, self.model = api_key, model

    async def complete(self, messages, tools=None):
        return LLMResponse(content="hi", tool_calls=[])

    async def aclose(self):
        pass


def runtime(source, monkeypatch):
    import services.agent.runtime as rt
    monkeypatch.setattr(rt, "create_provider", lambda provider_name, model, api_key, base_url=None: FakeProvider(api_key, model))
    return AgentRuntime(config=settings, approval_store=InMemoryApprovalStore(), settings_source=source)


@pytest.mark.asyncio
async def test_runtime_constructs_without_any_key(monkeypatch):
    rt = runtime(Source(keys={}), monkeypatch)
    with pytest.raises(ProviderNotConfigured):
        await rt._resolve_provider(None, None)


@pytest.mark.asyncio
async def test_key_resolved_lazily_and_cached_until_invalidated(monkeypatch):
    src = Source(keys={"gemini": "k1"})
    rt = runtime(src, monkeypatch)
    p1 = await rt._resolve_provider(None, None)
    p2 = await rt._resolve_provider(None, None)
    assert p1 is p2 and p1.api_key == "k1" and src.calls == 1
    src.keys["gemini"] = "k2"
    rt.invalidate_providers()
    p3 = await rt._resolve_provider(None, None)
    assert p3.api_key == "k2"


@pytest.mark.asyncio
async def test_permissions_text_is_folded_into_system_prompt():
    msgs = AgentRuntime._with_system_prompt([{"role": "user", "content": "hi"}], None, "<permissions>\n- X: on\n</permissions>")
    assert msgs[0]["role"] == "system" and "<permissions>" in msgs[0]["content"]
    assert msgs[0]["content"].index("<today>") < msgs[0]["content"].index("<permissions>")
```

- [ ] **Step 2: Run → fails.**

- [ ] **Step 3: Implement**

In `providers.py` after `ProviderError`:
```python
class ProviderNotConfigured(ProviderError):
    """No API key is available for the selected provider — the install has
    not been set up yet (or the key was removed). Routes answer 503 with a
    pointer to /setup; channels say the same sentence."""

    def __init__(self, provider: str):
        super().__init__(provider, None, "No AI provider is configured yet. Finish setup at /setup or add a key in Settings.")
```

In `runtime.py`:
1. `from core.config import PROVIDER_KEY_FIELDS as _PROVIDER_KEY_MAP` (if Task 3 has not landed yet, keep the literal; the merge resolves it).
2. Add near the top:
```python
class ProviderSettingsSource(Protocol):
    async def llm_defaults(self) -> tuple[str, str]: ...
    async def llm_api_key(self, provider: str) -> Optional[str]: ...


class _ConfigSettingsSource:
    """Default source: the process environment / .env, exactly as before."""

    def __init__(self, config: Any) -> None:
        self._config = config

    async def llm_defaults(self) -> tuple[str, str]:
        return (self._config.LLM_PROVIDER or "").strip().lower(), (self._config.LLM_MODEL or "").strip()

    async def llm_api_key(self, provider: str) -> Optional[str]:
        if provider == "ollama":
            return ""
        attr = _PROVIDER_KEY_MAP.get(provider)
        value = (getattr(self._config, attr, None) or "").strip() if attr else ""
        return value or None
```
3. `__init__`: add `settings_source: Optional[ProviderSettingsSource] = None`; set `self._source = settings_source or _ConfigSettingsSource(config)`; **delete** the eager `create_provider` block and `self._provider`; keep `self._context_manager = ContextManager(model=config.LLM_MODEL)`.
4. Replace `_resolve_provider` with an async version:
```python
    async def _resolve_provider(self, provider_name: Optional[str], model: Optional[str]) -> LLMProvider:
        default_provider, default_model = await self._source.llm_defaults()
        name = (provider_name or default_provider or "").strip().lower()
        model_name = (model or default_model or "").strip()
        cache_key = (name, model_name)
        cached = self._provider_cache.get(cache_key)
        if cached is not None:
            self._provider_cache.move_to_end(cache_key)
            return cached
        api_key = await self._source.llm_api_key(name)
        if api_key is None:
            raise ProviderNotConfigured(name or "unknown")
        try:
            provider = create_provider(provider_name=name, model=model_name, api_key=api_key or None, base_url=self._config.OLLAMA_BASE_URL)
        except (ValueError, ImportError) as exc:
            raise ProviderError(name, None, f"The '{name}' provider is not configured on this server ({exc}). Choose a different provider or add its API key.") from None
        self._provider_cache[cache_key] = provider
        while len(self._provider_cache) > self._PROVIDER_CACHE_MAX:
            _k, evicted = self._provider_cache.popitem(last=False)
            self._schedule_close(evicted)
        return provider

    def invalidate_providers(self) -> None:
        """Forget every cached provider (the owner changed a key or the default)."""
        for provider in self._provider_cache.values():
            self._schedule_close(provider)
        self._provider_cache.clear()

    @staticmethod
    def _schedule_close(provider: LLMProvider) -> None:
        try:
            asyncio.get_running_loop().create_task(provider.aclose())
        except RuntimeError:
            pass
```
   Update every caller: `provider = await self._resolve_provider(llm_provider, llm_model)` in `chat` (and the streaming path if it resolves separately). Replace `self._turn_provider = ...` with a local `turn_provider = name` obtained from the resolved pair (make `_resolve_provider` also return/set the name: simplest is `self._turn_provider` → pass `provider_name` explicitly to the follow-up image-block helper at line ~570; change `getattr(self, "_turn_provider", "")` to a `provider_name: str` parameter threaded from `chat`). Search `_turn_provider` and `self._provider` and remove all uses; `aclose()` of the runtime iterates the cache.
5. `chat(..., permissions_text: Optional[str] = None)` and `_with_system_prompt(messages, memory_block=None, permissions_text=None)`: `tail = f"\n\n{today_line}" + (f"\n\n{permissions_text}" if permissions_text else "") + (f"\n\n{memory_block}" if memory_block else "")`. Update the two call sites that pass `SECURITY_SYSTEM_PROMPT` directly (line ~803) only if they build the system message themselves.
6. `api/routes/agent.py`: before each `except ProviderError as exc:` (blocking send ~768, streaming path, channel applier ~1397) add:
```python
    except ProviderNotConfigured as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={"message": str(exc), "setup_url": "/setup"}) from None
```
   (streaming: emit the error event with `setup_url`; channel applier: return `{"content": str(exc), "error": "provider_not_configured"}` so Telegram sends the sentence).

- [ ] **Step 4: Run** the new test plus `tests/test_agent_loop_security.py tests/test_providers.py tests/test_agent_runtime_vision.py tests/test_system_tools.py -q`. Fix tests that constructed `AgentRuntime` expecting an eager provider (they now need a `settings_source` with a key or a patched `create_provider`).

- [ ] **Step 5: Commit** `feat(runtime): resolve provider keys lazily from a settings source; ProviderNotConfigured → 503 /setup; permissions block in system prompt`.

---

## Wave 1 — Task 6: frontend Permissions UI (T5)

**Files:** Modify `frontend/src/types/index.ts`, `frontend/src/services/api.ts`, `frontend/src/pages/Settings.tsx`. Create `frontend/src/components/CapabilityList.tsx`, `frontend/src/components/CapabilityList.test.tsx`, `frontend/src/test/capabilities.ts` (fixtures).

- [ ] **Step 1: Types + API functions** (contract §1.6/§1.7). In `api.ts`:
```ts
export async function getCapabilities(): Promise<CapabilityStatus[]> {
  const data = await request<{ capabilities: CapabilityStatus[] }>("/capabilities");
  return data.capabilities;
}
export async function updateCapabilities(patch: Record<string, boolean>): Promise<CapabilityStatus[]> {
  const data = await request<{ capabilities: CapabilityStatus[] }>("/capabilities", { method: "PUT", body: JSON.stringify({ capabilities: patch }) });
  return data.capabilities;
}
export async function requestCapabilityAccess(key: string): Promise<CapabilityStatus> {
  const data = await request<{ ok: boolean; status: CapabilityStatus }>(`/capabilities/${key}/request-access`, { method: "POST" });
  return data.status;
}
export async function installCapability(key: string): Promise<{ ok: boolean; error?: string }> {
  return request(`/capabilities/${key}/install`, { method: "POST" });
}
```
(Use the file's existing `request` helper name and signature — read the top of `api.ts` first.)

- [ ] **Step 2: Failing component test** `CapabilityList.test.tsx`:
```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import CapabilityList from "@/components/CapabilityList";
import { CAPS } from "@/test/capabilities";

describe("CapabilityList", () => {
  it("renders label, risk, status line and a switch per capability", () => {
    render(<CapabilityList items={CAPS} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    expect(screen.getByText("See my screen")).toBeInTheDocument();
    expect(screen.getByText(/high/i)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /see my screen/i })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByText(/not granted screen recording/i)).toBeInTheDocument();
  });

  it("calls onToggle with the new value", async () => {
    const onToggle = vi.fn();
    render(<CapabilityList items={CAPS} editable onToggle={onToggle} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    await userEvent.click(screen.getByRole("switch", { name: /browse the web/i }));
    expect(onToggle).toHaveBeenCalledWith("web_browsing", false);
  });

  it("shows Grant access only when the OS denied it, Install only when installable", () => {
    render(<CapabilityList items={CAPS} editable onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    expect(screen.getByRole("button", { name: /grant access/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /install/i })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /grant access|install/i })).toHaveLength(2);
  });

  it("is read-only for non-owners", () => {
    render(<CapabilityList items={CAPS} editable={false} onToggle={vi.fn()} onRequestAccess={vi.fn()} onInstall={vi.fn()} />);
    for (const sw of screen.getAllByRole("switch")) expect(sw).toBeDisabled();
    expect(screen.getByText(/only the owner can change/i)).toBeInTheDocument();
  });
});
```
`src/test/capabilities.ts` exports `CAPS: CapabilityStatus[]` with four rows: `web_browsing` (on), `screen` (enabled, blocked, probe_state "denied", fix_url set, can_request_access true, reason "macOS has not granted Screen Recording to /usr/bin/python3."), `site_screenshots` (blocked, install "browser", reason "The hidden browser is not installed yet"), `reminders` (off).

- [ ] **Step 3: Implement `CapabilityList.tsx`**: props `{ items, editable, onToggle(key, enabled), onRequestAccess(key), onInstall(key), busyKey?: string | null }`. Each row: `<h3>` label, risk badge (`--accent-danger` for high, `--accent-warning` medium, muted low — reuse the CSS variables Settings uses), description, a `<button role="switch" aria-checked aria-label={label} disabled={!editable || busy}>` (44 px min height), status line coloured by `effective` ("On", "Off — …", "Blocked — reason"), and, when `can_request_access`, a "Grant access" button; when `install && !available`, an "Install (~300 MB)" button; when `fix_url`, an "Open System Settings" link is not possible from the browser — render the `fix_steps` as a small ordered list instead. Read-only mode renders a line "Only the owner can change these." Follow the panel/label classes from `Settings.tsx` (`panelStyle`, `labelCls`).

- [ ] **Step 4: Settings section** — in `Settings.tsx` add a **Permissions** section right after "Security settings": on mount `getCapabilities()`; `editable = !!me?.is_admin`; `onToggle` → `updateCapabilities({[key]: enabled})` → replace list; `onRequestAccess` → `requestCapabilityAccess(key)` → refresh list; `onInstall` → `installCapability(key)` then refresh. Show the section's error text inline like other sections. Also add `is_admin?: boolean` to the `User` type if missing.

- [ ] **Step 5: Run** `npx vitest run src/components/CapabilityList.test.tsx && npx tsc -b && npx eslint src/components/CapabilityList.tsx src/pages/Settings.tsx` → green.

- [ ] **Step 6: Commit** `feat(frontend): Permissions section with CapabilityList`.

---

## Wave 1 — Task 7: frontend `/setup` wizard (T6)

**Files:** Create `frontend/src/pages/Setup.tsx`, `frontend/src/pages/Setup.test.tsx`. Modify `frontend/src/App.tsx`, `frontend/src/services/api.ts`, `frontend/src/types/index.ts`.

- [ ] **Step 1: API functions** (contract §1.6):
```ts
export async function getSetupStatus(): Promise<SetupStatus>        // GET /setup/status, no auth header required
export async function createOwner(data: RegisterData): Promise<AuthResponse>   // POST /setup/owner; store token like login() does
export async function getSetupProviders(): Promise<{ providers: SetupProvider[]; current: { provider: string; model: string } }>
export async function testProvider(body: { provider: string; model: string; api_key?: string }): Promise<{ ok: boolean; reply?: string; error?: string }>
export async function saveProvider(body: { provider: string; model: string; api_key?: string }): Promise<void>
export async function testTelegram(token: string): Promise<{ ok: boolean; bot_username?: string; error?: string }>
export async function saveTelegram(token: string): Promise<{ bot_username: string }>
export async function completeSetup(body: { allow_registration: boolean }): Promise<void>
```

- [ ] **Step 2: Failing test** `Setup.test.tsx` (mock `@/services/api` with `vi.mock`): (a) renders step 1 "Create the owner account"; submitting calls `createOwner` and advances to "AI provider"; (b) on the provider step, **Save** is disabled until `testProvider` resolves `{ok:true}`; (c) a provider with `key_from_env: true` shows "Provided by server configuration" and no key field; (d) the Permissions step renders `CapabilityList` from `getCapabilities`; (e) the Summary step lists each capability with "Works"/"Not available"/"Off" and clicking **Finish** calls `completeSetup({allow_registration: false})` and navigates to `/`.

- [ ] **Step 3: Implement `Setup.tsx`**: a five-step state machine (`owner | provider | telegram | permissions | summary`) with a progress header, one card per step, Back/Next. Reuse `CapabilityList`. Provider step: radio buttons over `providers` (same list/order as Settings), model text input prefilled from the first suggestion (`gemini-2.5-flash` for gemini), key input hidden when `key_from_env`, **Test** button shows the reply or the error, **Save & continue** enabled only after a passing test. Telegram step: BotFather instructions (3 lines), token input, **Test**, **Save**, then a "Link your chat" button that calls the existing `createTelegramLink()` and shows the `t.me` link; **Skip** allowed. Summary: table from `getCapabilities()` with "What works / what doesn't", a checkbox "Allow other people to create accounts on this Crawler" (off), a "Crawler never…" list (buy, move money, run as admin, install marketplace skills), **Finish**.

- [ ] **Step 4: Routing** in `App.tsx`: add `const Setup = lazy(() => import("./pages/Setup"))`, route `<Route path="/setup" element={<Setup />} />` outside `ProtectedRoute`, and a `SetupGate` wrapper that fetches `getSetupStatus()` once (state `unknown | needs | done`), renders `RouteFallback` while unknown, and `<Navigate to="/setup" replace />` when `needs` and `location.pathname !== "/setup"`. After `completeSetup`, the wizard calls a `refresh()` passed via context or simply `window.location.assign("/")` (acceptable: one full reload after setup).

- [ ] **Step 5: Run** `npx vitest run src/pages/Setup.test.tsx && npx tsc -b && npx eslint src` → green. **Commit** `feat(frontend): first-run /setup wizard`.

---

## Wave 1 — Task 8: rename to Crawler AI (T7)

**Files (strings only):** `backend/services/agent/runtime.py` (identity lines ~60, 80, 156), `backend/services/notifications/telegram.py` (~49, 628, 652, 712), `backend/api/routes/agent.py` (~1294 approval summary), `backend/main.py` (FastAPI `title`/`description`, `shutting_down_sentientai` log), `backend/services/tools/web.py` (~63 User-Agent → `CrawlerAI/0.1 (+https://github.com/krishcodes1/Sentient-AI-)`), `backend/services/mcp/client.py` (~273 `clientInfo.name` → `crawler-ai`), `backend/api/routes/auth.py` (~741 export filename → `crawler-ai-export-…`), `backend/api/routes/telegram.py` docstring, `backend/.env.example` comments, `backend/tests/test_agent_loop_security.py` (~389) and any MCP `clientInfo` test; `frontend/index.html` `<title>Crawler AI</title>`, `frontend/src/components/Brand.tsx` alt text, `frontend/src/pages/Login.tsx` badge, `frontend/src/services/api.ts` (~656 filename), `frontend/package.json` `name: "crawler-ai-frontend"`, `frontend/src/theme.tsx` (~15: read `crawler.theme`, falling back to and migrating the old `sentientai` key once), `README.md`, `SECURITY.md`.

**Do NOT change:** `core/security.py` HMAC derivation string (~116), Postgres role/db `sentientai` (compose, `.env.example` `DATABASE_URL`), Redis key prefixes, compose project/service names, `--claw-*` CSS tokens, repo paths.

- [ ] **Step 1:** `grep -rni "sentient" backend frontend/src frontend/index.html README.md SECURITY.md --exclude-dir=node_modules --exclude-dir=dist -l` and edit each user-facing occurrence; keep the identifiers listed above.
- [ ] **Step 2:** Run `python3 -m pytest tests/test_agent_loop_security.py tests/test_mcp_client.py tests/test_telegram.py -q` and `npx vitest run && npx tsc -b`. Fix string assertions.
- [ ] **Step 3:** Commit `chore: rename SentientAI to Crawler AI in user-facing strings (identifiers unchanged)`.

---

## Wave 2 — Task 9: executor toolkit map + wiring (T8) — after Tasks 1–5 merge

**Files:** `backend/services/agent/tool_registry.py`, `backend/services/tools/system.py`, `backend/main.py`, `backend/api/routes/agent.py`, `backend/api/routes/telegram.py`. Tests: `backend/tests/test_wiring.py`.

- [ ] **Step 1: Toolkit map.** In `ConnectorToolExecutor.__init__` replace the four toolkit attributes with:
```python
        self._builtins: dict[str, _Builtin] = {
            "web": _Builtin(lambda a, p, uid, ok: self._web.execute(a, p), {ActionCategory.READ}, set()),
            "reminders": _Builtin(lambda a, p, uid, ok: self._reminders.execute(a, p, uid), {ActionCategory.READ, ActionCategory.WRITE}, set()),
            "system": _Builtin(lambda a, p, uid, ok: self._system.execute(a, p), {ActionCategory.READ, ActionCategory.WRITE}, {ActionCategory.WRITE}),
            "desktop": _Builtin(lambda a, p, uid, ok: self._desktop.execute(a, p), {ActionCategory.READ}, set()),
        }
```
with
```python
@dataclass(frozen=True)
class _Builtin:
    call: Callable[[str, dict[str, Any], str, bool], Awaitable[dict[str, Any]]]
    allowed: set[ActionCategory]
    confirm: set[ActionCategory]   # categories that need approved=True
```
and one generic branch replacing the four `if resolved.connector_type == …` blocks:
```python
        builtin = self._builtins.get(resolved.connector_type)
        if builtin is not None:
            if resolved.spec.category not in builtin.allowed:
                return {"ok": False, "error": f"{resolved.connector_type} action '{resolved.action}' is not permitted."}
            if resolved.spec.category in builtin.confirm and not approved:
                return {"ok": False, "requires_approval": True, "error": f"Action requires user confirmation: {tool_name} runs only after the user approves it."}
            return await builtin.call(resolved.action, dict(arguments), user_id, approved)
```
Keep the `system` refusal text identical to today's (tests assert it). Run `tests/test_system_tools.py tests/test_reminder_tools.py tests/test_web_tools.py tests/test_desktop_tools.py tests/test_capability_gating.py`.

- [ ] **Step 2: `system.capabilities` reports permissions.** `SystemToolkit.__init__(..., report_source: Optional[Callable[[], Awaitable[list[CapabilityStatus]]]] = None)`; in `capabilities()` add `"permissions": [s.to_dict() for s in await self._report_source()]` when set (the existing `"capabilities"` list of installables stays). Update the `system.capabilities` ToolSpec description: "…and the owner's permission switches (what is on, off or blocked and why)".

- [ ] **Step 3: `agent.py` wiring.** `_build_tools_and_memory(mcp_catalog, current_user, db, installation)` returns `(tools, memory_block, permissions_text)`: `enabled = await installation.enabled_keys()`; `build_tools(..., enabled_capabilities=enabled)`; `permissions_text = render_permissions_block(await installation.report())`. Update the four call sites (lines ~747, 937, 1135, 1378) to pass `request.app.state.installation` (or `app.state.installation` in the appliers) and forward `permissions_text=` to `runtime.chat(...)`. Generalise image delivery (~1431): replace the `endswith("web.screenshot")` condition with `isinstance(result, dict) and str(result.get("image", "")).startswith("data:image/")`, caption `result.get("final_url") or result.get("url") or ("Your screen" if name.startswith("desktop.") else "")`, cap `images` at 3.

- [ ] **Step 4: `main.py` wiring.**
```python
    installation = InstallationService(async_session)
    app.state.installation = installation
    await installation.stamp_setup_if_legacy()

    telegram_manager = TelegramManager(async_session, on_start=lambda svc: _wire_telegram(app, svc))
    app.state.telegram_manager = telegram_manager
    approval_store = NotifyingApprovalStore(DbApprovalStore(session_factory=async_session), notify=telegram_manager.notify_pending)
    app.state.agent_runtime = AgentRuntime(config=settings, permission_engine=RuntimePermissionAdapter(),
        tool_executor=ConnectorToolExecutor(session_factory=async_session, capability_gate=installation.enabled_keys,
                                            system_toolkit=SystemToolkit(report_source=installation.report)),
        audit_service=RuntimeAuditLogger(session_factory=async_session), approval_store=approval_store,
        settings_source=installation)
    app.state.mcp_catalog = MCPToolCatalog(MCPConnectorLoader(async_session))
    await telegram_manager.apply(await installation.telegram_token(), (await installation.capabilities())["telegram"])
    reminder_service = ReminderService(session_factory=async_session, send=telegram_manager.send_text)

    async def _on_change(topic: str) -> None:
        if topic == "llm":
            app.state.agent_runtime.invalidate_providers()
        if topic in ("telegram", "capabilities"):
            await telegram_manager.apply(await installation.telegram_token(), (await installation.capabilities())["telegram"])
    installation.on_change(_on_change)
```
with `def _wire_telegram(app, svc): svc.decide = agent.build_decision_applier(app); svc.chat = agent.build_chat_applier(app)`. Shutdown: `await telegram_manager.stop()`. Remove the old `telegram_service` block; keep `app.state.telegram` as a compatibility alias **property**: simplest is to set `app.state.telegram = telegram_manager` and change `api/routes/telegram.py::_service` to `getattr(request.app.state, "telegram_manager", None)` returning `manager.current`. `ReminderService.send` must tolerate `False` returns (it already treats a falsy result as "not delivered").

- [ ] **Step 5: Tests** `tests/test_wiring.py`: with the `client` fixture, (a) `GET /api/health` still 200; (b) a Telegram-off install exposes `GET /api/telegram/status` → `configured: false`; (c) after `app.state.installation.set_telegram_token("1:x"*10…)` with a `service_factory` patched to the FakeService from Task 4, `configured` becomes true without a restart. Run the **full** backend suite: `python3 -m pytest tests -q`.

- [ ] **Step 6: Commit** `feat: wire installation service, capability gates, permissions prompt and telegram manager into the app`.

---

## Wave 2 — Task 10: capabilities API (T9)

**Files:** Create `backend/api/routes/capabilities.py`, `backend/tests/test_capabilities_api.py`. Modify `backend/main.py` (`include_router`), `backend/api/routes/__init__.py`.

- [ ] **Step 1: Failing tests** — using `client` + `make_user`/register via `/api/auth/register` (first user is admin): `GET /api/capabilities` as any user returns the list with `screen.effective == "off"`; `PUT` as non-admin → 403; `PUT {"capabilities": {"screen": true}}` as admin → `screen.enabled true` and (in tests, not a container… set `CRAWLER_CONTAINER=1` via `monkeypatch.setenv` to force `blocked`) `effective == "blocked"`; `PUT` unknown key → 422; `POST /api/capabilities/screen/request-access` in a container → 409; `POST /api/capabilities/site_screenshots/install` with `SystemToolkit.install_capability` patched → returns its result and writes an audit row `capability_install_finished`; `POST /api/capabilities/web_browsing/install` → 409.

- [ ] **Step 2: Implement**
```python
router = APIRouter(prefix="/capabilities", tags=["capabilities"])

class CapabilitiesPatch(BaseModel):
    capabilities: dict[str, bool]

def _installation(request: Request) -> InstallationService: return request.app.state.installation

def _require_admin(user: User) -> None:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Only the owner can change permissions")

@router.get("")
async def list_capabilities(request, current_user=Depends(get_current_user)):
    return {"capabilities": [s.to_dict() for s in await _installation(request).report()]}

@router.put("")
async def update_capabilities(body: CapabilitiesPatch, request, current_user=Depends(get_current_user)):
    _require_admin(current_user)
    try:
        statuses = await _installation(request).set_capabilities(body.capabilities, actor_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"capabilities": [s.to_dict() for s in statuses]}

@router.post("/{key}/request-access")
async def request_access(key, request, current_user=Depends(get_current_user)):
    _require_admin(current_user)
    try: cap = capabilities.get(key)
    except KeyError: raise HTTPException(404, "Unknown capability")
    status_ = capabilities.statuses_by_key(await _installation(request).report()).get(key)
    if cap.request_access is None or not status_.available:
        raise HTTPException(409, detail=status_.availability_reason or "This capability has nothing to request here.")
    await asyncio.to_thread(cap.request_access)
    capabilities.clear_probe_cache()
    # audit: connector_name="installation", action="capability_access_requested", request_data={"capability": key}
    fresh = capabilities.statuses_by_key(await _installation(request).report())[key]
    return {"ok": True, "status": fresh.to_dict()}

@router.post("/{key}/install")
async def install(key, request, current_user=Depends(get_current_user)):
    _require_admin(current_user)
    try: cap = capabilities.get(key)
    except KeyError: raise HTTPException(404, "Unknown capability")
    if not cap.install: raise HTTPException(409, "This capability has nothing to install.")
    # audit capability_install_started; run SystemToolkit().install_capability(cap.install); audit capability_install_finished with {"ok": result["ok"]}
    return result
```
Register: `app.include_router(capabilities.router, prefix="/api")` next to the others.

- [ ] **Step 3: Run tests, commit** `feat(api): capabilities endpoints (report, update, request-access, install)`.

---

## Wave 2 — Task 11: setup API (T10)

**Files:** Create `backend/api/routes/setup.py`, `backend/tests/test_setup_api.py`. Modify `backend/api/routes/auth.py` (extract `create_account`), `backend/main.py`.

- [ ] **Step 1: Extract `create_account`** from `register` in `auth.py`:
```python
async def create_account(db: AsyncSession, *, email: str, password: str, name: Optional[str], endpoint: str) -> User:
    """Create a user; the first account on the install becomes the owner (admin)."""
```
containing the duplicate-email 409, password-length 422, first-account check, `User(...)`, `append_auth_event(...)` — `register` becomes: registration gate + `return await create_account(...)`. The registration gate now asks `request.app.state.installation.registration_allowed()` (fallback to `settings.ALLOW_REGISTRATION` when the state is absent in unit tests).

- [ ] **Step 2: Failing tests** (`client` fixture; patch `services.agent.providers.create_provider` and `httpx.AsyncClient.get` for Telegram `getMe`): status before/after owner; owner creation returns a bearer token and `is_admin`; second owner call → 409; non-admin on `/setup/providers` → 403; `provider/test` returns `{ok:false,error}` when the fake provider raises `ProviderError`, `{ok:true}` otherwise; `PUT /setup/provider` refuses to save on a failed test (400) and stores on success (`installation.llm_api_key("gemini") == "k"`); `telegram/test` → bot username; `PUT /setup/telegram` stores and `manager.apply` was called; `DELETE` clears; `complete` stamps and `GET /setup/status.setup_completed` is true; rate limit: 6th `provider/test` in a minute → 429; secrets never appear in any response body.

- [ ] **Step 3: Implement** per §1.6. Provider test helper:
```python
async def _try_provider(provider: str, model: str, api_key: Optional[str]) -> dict[str, Any]:
    try:
        llm = create_provider(provider_name=provider, model=model, api_key=api_key or None, base_url=settings.OLLAMA_BASE_URL)
    except (ValueError, ImportError) as exc:
        return {"ok": False, "error": str(exc)}
    try:
        resp = await asyncio.wait_for(llm.complete([{"role": "user", "content": "Reply with the single word OK."}]), timeout=30)
        return {"ok": True, "reply": (resp.content or "")[:40]}
    except (ProviderError, asyncio.TimeoutError) as exc:
        return {"ok": False, "error": str(exc) or "timed out"}
    finally:
        await llm.aclose()
```
Key resolution for the test: `body.api_key or await installation.llm_api_key(body.provider)`; if none and provider != ollama → `{ok:false, error:"Enter an API key."}`. Telegram token format `^\d+:[A-Za-z0-9_-]{30,}$` → else 422; `getMe` via `httpx.AsyncClient(timeout=10)`. Rate limiter: module dict `{user_id: deque[timestamps]}`, 5 per 60 s for the two `/test` routes. Models list for `/setup/providers`: reuse `LLM_MODELS` from the frontend? No — define `SUGGESTED_MODELS = {"gemini": ["gemini-2.5-flash", "gemini-2.5-flash-lite"], "anthropic": ["claude-sonnet-5", "claude-haiku-4-5-20251001"], "openai": ["gpt-4o-mini"], "ollama": ["llama3.2"], ...}` in `setup.py`.

- [ ] **Step 4: Run tests + full suite; commit** `feat(api): first-run setup endpoints (owner, provider test/save, telegram, complete)`.

---

## Wave 2 — Task 12: docs, compose, deps, upgrade path (T11)

- [ ] `docker/docker-compose.yml` and `docker-compose.prod.yml`: add `CRAWLER_CONTAINER: "1"` to the backend `environment`. Add `mss`/`Pillow` are already in requirements (Task 2); rebuild note in README.
- [ ] `README.md`: new section "First run: the setup wizard" (open http://localhost:3000 → `/setup`), "Permissions" (what each switch does; `See my screen` is unavailable in Docker), and update "Environment Variables" to say `.env` values override the wizard. Fix the Ollama URL (`host.docker.internal` under Docker) and the "restart" wording (`docker compose up -d backend`).
- [ ] `.env.example`: comment above the LLM keys: "Optional when you use the setup wizard; a value here always wins."
- [ ] Commit `docs: setup wizard, permissions and container flag`.

---

## Wave 3 — integration (lead)

- [ ] Merge all branches; `python3 -m pytest tests -q`; `ruff check .`; `npx vitest run && npx tsc -b && npx eslint .`.
- [ ] Docker live check on a **fresh** compose project: `docker compose -p crawler-wizard -f docker/docker-compose.yml up --build -d` with an override for ports (18000/13000/15432/16379) and a scratch `.env` **without** LLM keys → `/setup` appears → owner → provider test (mock not possible live: use Ollama or the owner's key) → permissions show `See my screen: Not available in this environment (container)` → complete → chat works. Tear down with `down -v`.
- [ ] Push; write the "what landed / how to add a capability" note for the team (link `backend/services/capabilities/README.md`).
