# Capabilities, permissions and the first-run setup wizard

**Date:** 2026-09-23 · **Product:** Crawler AI (formerly SentientAI) · **Status:** approved design

## 1. Goal

Make Crawler AI easy to set up and easy to control. A first-run wizard asks the owner what the agent may do, and the agent's tools switch on and off from those answers. Anything the agent cannot do is shown in the wizard and explained by the agent. The design works today in the Docker test stack and later, unchanged, in a native install on a Mac or Windows PC.

This is also the base other contributors build on. Adding a feature is one new "capability" file plus its tools; the wizard, the Settings page, tool gating and the agent's own self-description pick it up automatically.

### In scope

- A capability registry (one file per capability).
- A single `installation` record that stores the owner's switches, the AI provider and its API key, and the Telegram bot token.
- Tool gating from the switches, enforced when tools are offered, when they run, and in the prompt.
- A `desktop.screenshot` tool ("See my screen") with a macOS Screen Recording check.
- A `/setup` wizard and a Permissions section in Settings.
- A guide and template for adding capabilities.

### Out of scope (later projects)

- Per-user narrowing of the owner's switches.
- Native packaging, `install.sh`, LaunchAgent, OS keychain.
- Mouse and keyboard control, accessibility trees, OCR of screenshots.
- Files, shell and browser-control tools (they will be capabilities added with this framework).

## 1.1 Design principle: goal-driven autonomy

The agent is expected to work out *how* to do what it is asked. Told "make a call for me", it should find a service that places free calls from the browser, sign up, and place the call, on its own. Permissions therefore gate **capabilities** (may it browse, see the screen, control a browser, run commands), never **tasks**. Approval is asked only at consequential steps: creating an account, sending a message, spending money, deleting or installing something. Everything below serves this:

- the `<permissions>` block and each capability's `when_denied` line let the agent say precisely which capability it lacks and how the owner turns it on, instead of claiming it "cannot";
- the summary table in the wizard is honest about what does not exist yet, so the owner's expectations match the agent's;
- the framework is built so the capabilities that this example needs later (`browser_control`: navigate, click, type, fill forms; later `files`, `shell`) plug in as single files with their own approval rules.

**Reference example.** "Open Canvas in Chrome, sign in, and tell me which assignments are missing" must work with no Canvas API: the agent opens the site, signs in, reads the page and reports. This is the `browser_control` capability (next project). Its design is fixed now so the base fits it:

- Port OpenClaw's browser-tool pattern (MIT): an accessibility snapshot of the page with numbered refs, then `click` / `type` / `select` by ref, plus `navigate`, `back`, `read`. Snapshots are capped in size to keep cost low.
- Borrow NemoClaw's credential rule: site passwords are stored encrypted through the Connectors UI and filled in by the toolkit. The model, the chat transcript and Telegram never see them. Asking for a password in chat is refused.
- Reads run without approval; typing into a form, submitting, creating an account or checking out are consequential steps that use the approval flow.
- A visible browser window is used when the owner must intervene (MFA, captcha); a dedicated Crawler browser profile keeps the owner's own sessions separate.

## 2. Decisions already made

| Decision | Choice |
|---|---|
| Who controls switches | Per computer; only the owner (first account, `is_admin`) can change them. Every account gets what the owner allowed. |
| Where secrets live | The wizard stores the API key and bot token encrypted in the database. A value in `.env` still wins if present. |
| Docker | Kept for tests and CI only. Same code; the report says what is unavailable in a container. |
| Include desktop screenshots | Yes, off by default. |

## 3. Architecture

```
frontend  /setup wizard  ──┐
          Settings ▸ Permissions ──┤  GET/PUT /api/capabilities, /api/setup/*
                                   ▼
backend   api/routes/setup.py, api/routes/capabilities.py
                │
                ▼
          services/installation.py  (InstallationService: switches, provider, token; env > DB > default)
                │                     │                 │
                ▼                     ▼                 ▼
   services/capabilities/      AgentRuntime         TelegramManager
   registry + report()         provider resolver    start / stop / restart
                │
                ▼
   tool_registry.build_tools  (offer gate)  ─▶  ConnectorToolExecutor (dispatch gate)
                │
                ▼
   system prompt <permissions> block  (agent awareness)
```

## 4. Capability registry (`backend/services/capabilities/`)

### 4.1 Files

```
services/capabilities/
  __init__.py          REGISTRY, get(key), capability_for_tool(name), report(...)
  base.py              Capability, Availability, ProbeResult, CapabilityStatus
  _template.py         copy-me template with every field explained
  README.md            "How to add a capability" (see §12)
  web_browsing.py      web.search, web.fetch_page
  site_screenshots.py  web.screenshot   (needs the headless browser installed)
  screen.py            desktop.screenshot (macOS Screen Recording probe)
  reminders.py         reminders.*
  installs.py          system.install_capability
  telegram.py          channel capability, no tools
```

### 4.2 The `Capability` declaration

```python
@dataclass(frozen=True)
class Capability:
    key: str                 # stable id used in storage and the API, e.g. "screen"
    label: str               # "See my screen"
    description: str         # one sentence for the owner
    tools: tuple[str, ...]   # exact tool names ("web.search") or a prefix ending in "." ("reminders.")
    default_enabled: bool
    risk: Literal["low", "medium", "high"]
    when_denied: str         # what the agent says if asked while the capability is off
    availability: Callable[[ReportContext], Availability] = always_available  # reads ctx only, never the OS
    probe: Callable[[ReportContext], ProbeResult] | None = None      # OS permission check, native only; may call the OS
    request_access: Callable[[], None] | None = None    # trigger the OS prompt / open settings
    install: str | None = None   # key in services.tools.system.ALLOWLIST that makes it available
```

- `Availability(available: bool, reason: str)`. Examples: `screen` is unavailable inside a container or on Linux; `site_screenshots` is unavailable until Chromium is installed.
- `ProbeResult(state: "granted" | "denied" | "not_required" | "unknown", detail: str, fix_url: str | None, fix_steps: tuple[str, ...])`.
- `system.capabilities` and `reminders.now` (the model's clock) are in `ALWAYS_ON_TOOLS` and always offered; that list wins over a family prefix, so `reminders.` does not gate `reminders.now`. Any tool not claimed by a capability is always on; the registry test lists the allowed exceptions explicitly so a forgotten claim fails the build.

### 4.3 `report()` and effective state

For each capability, `report(switches: dict[str, bool])` returns a `CapabilityStatus`:

```
enabled       owner switch (missing or null → default_enabled; anything but a literal true → off)
availability  from availability()
probe         from probe() if available and enabled (else "unknown", not checked); cached 10 s per context
effective     "on" | "off" | "blocked"
reason, fix_url, fix_steps
```

Rule: `off` if not enabled; else `blocked` if unavailable or probe is `denied`; else `on`. `unknown` and `not_required` count as on. Fail closed: an `availability()` that raises reads as unavailable and a `probe()` that raises reads as `denied`, so a broken check blocks instead of turning a capability on.

`enabled_keys()` returns the keys whose effective state is `on`. This is the only set the tool gates use.

### 4.4 v1 capabilities

| key | label | tools | default | risk | availability / probe |
|---|---|---|---|---|---|
| `web_browsing` | Browse the web | `web.search`, `web.fetch_page` | on | low | always |
| `site_screenshots` | Screenshots of websites | `web.screenshot` | on | low | Chromium installed (`system.browser_installed()`); `install="browser"` |
| `screen` | See my screen | `desktop.screenshot` | **off** | high | not in a container; macOS: `CGPreflightScreenCaptureAccess`; Windows: `not_required`; Linux: `unknown` |
| `reminders` | Reminders | `reminders.` (except `reminders.now`, always on) | on | low | always |
| `installs` | Install software (asks first) | `system.install_capability` | on | medium | always |
| `telegram` | Telegram chat and approvals | none | on | medium | blocked until a bot token is configured |

### 4.5 Environment detection

`in_container()` is true when `/.dockerenv` exists or `CRAWLER_CONTAINER=1` is set. `docker/docker-compose.yml` and `docker-compose.prod.yml` set the variable. The macOS probe uses `ctypes` on `/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics` (`CGPreflightScreenCaptureAccess`, `CGRequestScreenCaptureAccess`); no new dependency. The deep link is `x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture`, opened with `/usr/bin/open` (only `x-apple.systempreferences:` URLs are accepted) because the backend runs on the user's Mac. The report also names the process that holds the grant (`sys.executable` resolved past symlinks), because macOS attaches the grant to the binary.

## 5. Storage: the `installation` record

### 5.1 Table (Alembic `0008_installation`)

Single row, `id = 1`, created by the migration.

| column | type | notes |
|---|---|---|
| `capabilities` | JSON | `{key: bool}`; missing keys use the registry default |
| `llm_provider` | text, nullable | server default provider |
| `llm_model` | text, nullable | |
| `llm_api_keys` | bytes, nullable | AES-256-GCM blob of `{provider: key}` via `core.security.encrypt_credentials` |
| `telegram_bot_token` | bytes, nullable | encrypted |
| `allow_registration` | bool | default false |
| `setup_completed_at` | timestamptz, nullable | |
| `updated_at`, `updated_by_user_id` | | |

The existing per-user `llm_provider` / `llm_model` on `users` stay: a user may pick a model; the key always comes from the installation or the environment.

### 5.2 Precedence: `.env` > database > default

- API key for provider P: `settings.<P>_API_KEY` if non-empty, else the stored key, else none.
- Telegram token: `settings.TELEGRAM_BOT_TOKEN` if non-empty, else stored.
- Default provider and model: the stored values if the owner chose them in the wizard, else `settings.LLM_PROVIDER` / `settings.LLM_MODEL` (which carry their own defaults). Keys follow the environment-first rule above; the provider choice follows the owner-first rule because a wizard choice must not be silently undone by a stale `.env` default.
- Registration: `/auth/register` answers 403 until setup completes, even with zero users (the first account comes from `/setup/owner`), and after that the stored switch applies; `settings.ALLOW_REGISTRATION` decides only when no installation service is wired and seeds the switch when §5.3 stamps an upgraded install.

The wizard shows "Provided by server configuration" for any secret that comes from `.env` and does not ask for it.

### 5.3 Upgrade of an existing install

At startup, if users already exist, the wizard has not stored a provider, and the environment supplies the provider key (a key saved by the wizard does not count — an owner who quit mid-wizard resumes it), `setup_completed_at` is stamped automatically so an existing deployment (your Docker stack) is not forced into the wizard. Everything else keeps its defaults, which reproduce today's behaviour: all existing capabilities on, `screen` off.

### 5.4 `InstallationService` (`backend/services/installation.py`)

```
capabilities()                    -> dict[str, bool]
set_capabilities(patch, actor)    -> list[CapabilityStatus]   audited
report()                          -> list[CapabilityStatus]
enabled_keys()                    -> frozenset[str]
llm_defaults()                    -> (provider, model)
llm_api_key(provider)             -> str | None               env > DB
set_llm(provider, model, api_key | None, actor)               audited; key stored only if given
telegram_token()                  -> str | None
set_telegram_token(token | None, actor)                       audited
registration_allowed()            -> bool
needs_setup()                     -> bool   (no users, or setup_completed_at is null)
mark_setup_complete(allow_registration, actor)                audited
on_change(callback)               subscribers: runtime cache invalidation, Telegram manager
```

It owns short-lived sessions from the application session factory, like the other services. A small in-process cache (5 s) keeps `enabled_keys()` cheap per turn.

## 6. Runtime integration

### 6.1 Provider resolution

`AgentRuntime` no longer builds a provider at startup (today `main.py` sets `agent_runtime = None` when the key is missing). It takes a `settings_source` (`ProviderSettingsSource`: `llm_defaults()` → the install's `(provider, model)`, `llm_api_key(provider)` → key, `""` for Ollama, `None` when missing; `InstallationService` implements it, and the default reads `.env`) and asks it at turn time. Providers are cached per `(provider, model)`; saving a new key calls `runtime.invalidate_providers()` through `on_change`. A turn holds its provider on a reference-counted lease, so invalidation or LRU eviction retires an in-use instance and closes it when the turn ends; `runtime.aclose()` closes everything at shutdown.

Per-user choice: `users.llm_provider`/`llm_model` are nullable (Alembic `0009_user_llm_nullable`). `NULL` — the default for new accounts, and what the startup backfill sets on rows still holding the server's configured pair — means "use this Crawler's default": the turn takes the source's defaults and ignores the per-user model. `PATCH /auth/settings` accepts `null` for both; Settings offers it as "Use this Crawler's default". `AgentResponse.provider/model` (and the stream's `done` frame) name the pair that actually ran, and that is what the stored message records.

If no key resolves, the turn raises `ProviderNotConfigured(provider, reason=...)` (a `ProviderError`) with a URL-free sentence:
- `not_set_up` — the install has no usable key: `503 {"message", "code": "provider_not_configured", "setup_url": "/setup"}`.
- `user_provider_unavailable` — the install works but the user's pinned provider has no key: `409 {"message", "code": "user_provider_unavailable", "settings_url": "/settings"}`.

The stream `error` frame and the Telegram channel outcome carry the same `code` and URL; the web client appends "Open /setup to finish setup." or "Change it in Settings." to the sentence.

### 6.2 Telegram manager (`services/notifications/telegram_manager.py`)

Holds the current `TelegramService` or none. `apply(token, enabled)` starts, restarts or stops the poller. It exposes `notify_pending`, `send_text` and `send_photo` proxies that do nothing while stopped, so the approval store and the reminder sweeper are wired once at startup and never need to know whether Telegram is on. On every start it sets `decide` and `chat` from `api.routes.agent` exactly as `main.py` does today. `/api/telegram/status` reports the manager's state.

### 6.3 Gating

1. **Offer.** `build_tools(..., enabled_capabilities: frozenset[str] | None)` drops every tool whose capability is not in the set. `None` means the registry defaults, so a caller that forgets the argument cannot switch on `screen`.
2. **Dispatch.** `ConnectorToolExecutor.execute` re-checks built-in tools against `installation.enabled_keys()` and refuses with `{"ok": false, "error": "<label> is turned off. <when_denied>"}`. The refusal is audited as `tool_blocked` with `reason=capability_off`.
3. **Prompt.** The route passes `permissions_text` to the runtime, which appends a `<permissions>` block after `<capabilities>`:
   ```
   - Browse the web: on
   - See my screen: off — if asked, say it can be turned on in Settings → Permissions
   - Screenshots of websites: blocked — browser not installed; offer system.install_capability
   ```
   It changes only when settings change, so the cached prompt prefix is kept.

`system.capabilities` returns the same report (switch, availability, OS permission, install state) so the agent explains rather than guesses.

### 6.4 Built-in toolkit registry

Today the executor dispatches built-ins through an `if` chain (`tool_registry.py:999-1035`). It becomes a map `{connector_type: toolkit}` where every toolkit implements `execute(action, params, *, user_id, approved)`. Adding a tool family is one map entry.

## 7. `desktop.screenshot`

- Toolkit `services/tools/desktop.py`, connector type `desktop`, capability `screen`.
- Catalog: `ToolSpec("screenshot", ..., ActionCategory.READ, schema {display: integer})`. Policy rows: `desktop` READ → `AUTO_APPROVE`; WRITE, DELETE, EXECUTE, FINANCIAL → `HARD_BLOCKED`. `BUILTIN_CONNECTOR_TYPES` gains `"desktop"`; `_BUILTIN_STANCE["desktop"] = "user_confirm"`.
- Capture with `mss`; scale to at most 1280 px on the long edge; JPEG quality 70 with Pillow. The grabber is injectable so tests run without a display.
- Result shape matches `web.screenshot`: `{"ok": true, "image": "data:image/jpeg;base64,…", "width", "height", "image_format": "jpeg", "display", "captured_at"}`. The existing vision feed (`runtime.py:561`, max 2 images) applies unchanged.
- If the probe reports `denied`, the tool returns `{"ok": false, "error": …, "fix_url": …}` instead of trying.
- Telegram delivery (`api/routes/agent.py` around line 1431) is generalised: any tool result with an `image` data URL is sent with `sendPhoto`, at most 3 per turn.
- Every capture is audited through the existing intent row. The image is untrusted content like every tool result; text injection in pixels is a known gap (OCR is out of scope).
- New dependencies: `mss`, `Pillow`.

## 8. HTTP API

All under `/api`. Admin means `current_user.is_admin`.

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /setup/status` | none | `{needs_setup, has_owner, provider_configured, setup_completed}` |
| `POST /setup/owner` | none, only while zero users exist | create the admin, return a token; uses the same auth-IP rate bucket as login |
| `GET /setup/providers` | admin | providers, whether each key comes from the environment, model suggestions |
| `POST /setup/provider/test` | admin, 5/min | tiny no-tools completion with the given or configured key |
| `PUT /setup/provider` | admin | runs the test server-side; saves only on success |
| `POST /setup/telegram/test` | admin, 5/min | `getMe`; returns the bot username |
| `PUT /setup/telegram` · `DELETE /setup/telegram` | admin | save and start, or stop and clear |
| `POST /setup/complete` | admin | stamps completion, stores the registration switch |
| `GET /capabilities` | any user | full report |
| `PUT /capabilities` | admin | partial `{key: bool}`; returns the report |
| `POST /capabilities/{key}/request-access` | admin, native only | runs `request_access` (OS prompt, open System Settings) |
| `POST /capabilities/{key}/install` | admin | runs the allowlisted install for `capability.install`; same steps and audit as `system.install_capability` |

Secrets are never returned; responses say `configured: true` at most. Every write appends an audit row: `installation_capabilities_updated` (with the diff), `installation_provider_updated`, `installation_telegram_updated`, `installation_setup_completed`, `capability_access_requested`, `capability_install_started` / `_finished`.

## 9. Frontend

- `App.tsx` fetches `/api/setup/status` once; while `needs_setup` every route redirects to `/setup`. The wizard keeps the token from the owner step for the following steps. After `/setup/complete` the app re-fetches status.
- `/setup` (lazy page) with five steps: **Owner account → AI provider → Telegram (optional) → Permissions → Summary.**
  - Provider: choose provider, paste a key unless "provided by server configuration", choose a model (`gemini-2.5-flash` preselected), **Test**; Save is enabled only after a passing test.
  - Telegram: BotFather instructions, token, **Test**, Save, then the existing link-code flow (`/api/telegram/link`) with a `https://t.me/<bot>?start=<code>` link.
  - Permissions: `CapabilityList` — toggle, label, description, risk badge, availability / OS status line, **Grant access** and **Install** buttons where the capability offers them.
  - Summary: a "What works / what doesn't" table from the report, the "Allow other people to create accounts" switch (off), **Finish**.
- Settings gains a **Permissions** section that renders the same `CapabilityList` (editable for the owner, read-only otherwise) and moves the server-side provider key and Telegram token management next to the existing per-user model choice and Telegram link controls.
- New `api.ts` functions and types mirror §8.

## 10. Docker versus native

Same code path. In the Docker stack the report shows `screen` as "Not available in this environment (container). Works when Crawler runs directly on your Mac." and `request-access` returns 409 with that reason. The compose files set `CRAWLER_CONTAINER=1`. On a Mac the probe and the Grant button are real. Nothing else differs.

## 11. Security

- Secrets: stored with the existing AES key; never echoed; child processes are not given them.
- The owner endpoint works only while the users table is empty, then returns 409. Registration stays closed by default after setup.
- Denied capabilities are enforced at offer, dispatch and prompt; the dispatch gate is the one that matters and is tested directly.
- `screen` is off by default, high risk, audited on every capture, unavailable in containers, and refused when macOS has not granted Screen Recording.
- Test endpoints are rate-limited so they cannot be used to probe keys or burn credit.
- Capability, provider and Telegram changes are audited with the actor.
- The prompt block is derived from the report, not from model input.

## 12. Extensibility for contributors

`services/capabilities/README.md` documents the five steps, and `_template.py` is the starting point:

1. Write the toolkit in `services/tools/<family>.py` with `execute(action, params, *, user_id, approved)`.
2. Add its `ToolSpec`s to `CONNECTOR_CATALOG`, the permission rows to `permissions.py`, the type to `BUILTIN_CONNECTOR_TYPES` and `_BUILTIN_STANCE`, and the toolkit to the executor map.
3. Copy `_template.py` to `services/capabilities/<key>.py`, fill in the fields, and add it to `REGISTRY`.
4. Add tests: toolkit behaviour, and the capability's `when_denied` and `availability`.
5. Run `pytest tests/test_capabilities_registry.py`, which enforces: every claimed tool exists in the catalog; no tool is claimed twice; every catalog tool is claimed or in the explicit always-on list; `when_denied` is non-empty; keys are `snake_case`.

The wizard, the Settings page, the gates and the `<permissions>` block need no changes.

## 13. Testing

Backend (pytest, SQLite and the Postgres CI job):
- registry invariants (§12.5); report matrix over enabled × availability × probe; `enabled_keys()`.
- `build_tools` drops tools of off/blocked capabilities and keeps `system.capabilities`; `None` uses defaults.
- executor refusal for an off capability, with the audit row.
- `InstallationService`: env > DB precedence for keys, token, provider and registration; encryption round trip; `needs_setup`; upgrade stamping; `on_change` firing.
- runtime: no provider at boot, `ProviderNotConfigured` → 503 with `setup_url`; cache invalidation after `set_llm`.
- Telegram manager: start / restart / stop with a fake Bot API; proxies no-op while stopped.
- setup and capabilities routes: owner only when empty then 409; admin-only writes; test endpoints rate-limited; secrets never in responses; audit rows.
- desktop toolkit with a fake grabber: scaling, JPEG output, probe-denied path; macOS probe mocked.
- migration `0008` upgrade / downgrade against a database with existing users.

Frontend (vitest): redirect while `needs_setup`; wizard step flow with mocked API; `CapabilityList` states (on / off / blocked / grant / install); Settings Permissions read-only for non-admins.

Live: fresh Docker database → wizard end to end → chat works → `screen` row reads "not available in container". Later, a native run on the Mac shows the real probe.

## 14. Delivery

- **Phase 0 (prerequisite):** run both suites, commit the ~118 uncommitted files on `feat/full-platform-completion`, push, so contributors can pull.
- **Phase 0b — rename to Crawler AI:** user-facing strings only: system-prompt identity, Telegram messages, FastAPI title, web User-Agent, MCP `clientInfo`, export filenames, frontend copy and page title, README and SECURITY.md, `.env.example` comments, package names in `package.json`. Kept unchanged on purpose: the Postgres role and database name (`sentientai`; renaming orphans existing data), the compose project, the audit HMAC key-derivation string (existing rows must still verify), Redis key prefixes (safe either way, so left alone), and the repository path. The `localStorage` theme key is migrated, not just renamed. Tests that assert the identity strings are updated with them.
- **Phase 1 — foundation:** §4, §5, §6.3 gates, §6.4 toolkit map, §7, `GET/PUT /capabilities` + `request-access` + `install`, Settings ▸ Permissions, README and template, tests. Testable in Docker on its own.
- **Phase 2 — wizard:** §5.2 secrets in the database, §6.1 provider resolver, §6.2 Telegram manager, `/setup` API and page, summary table, upgrade stamping, tests.

Both phases land as reviewed commits on the branch; Phase 1 is the base contributors extend.
