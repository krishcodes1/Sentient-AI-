# Crawler AI — team handoff (2026-09-23)

Branch: `feat/full-platform-completion`. Pull it, then read this once.

## What landed tonight

The **capability / permission foundation** and the **first-run setup wizard**. Design: `docs/superpowers/specs/2026-09-23-capabilities-and-setup-wizard-design.md`. Plan: `docs/superpowers/plans/2026-09-23-capabilities-and-setup-wizard.md`.

- `backend/services/capabilities/` — one file per capability (what the agent may do). The wizard, the Settings ▸ Permissions page, the three tool gates and the agent's own `<permissions>` prompt block are all generated from these files.
- `installation` table + `services/installation.py` — the owner's switches, the AI provider and its key, the Telegram token (encrypted). Rule: **`.env` > database > default**.
- `/setup` wizard (owner account → AI provider, tested before it saves → Telegram → Permissions → summary of what works / what doesn't). Settings has a **Permissions** section and an owner-only **Server** section for changes later.
- `desktop.screenshot` ("See my screen"): off by default, high risk, unavailable inside Docker, needs macOS Screen Recording when native.
- Registration is closed until setup completes; the first account comes from the wizard and is the owner (admin).

## Run it

Docker (for testing only — the product target is a native install later):

```bash
cd Sentient-AI-/docker && docker compose up --build -d
```

Open http://localhost:3000 — you are redirected to `/setup`. A fresh database needs no `.env` keys: the wizard asks. Values in `backend/.env` still win if present.

Tests:

```bash
cd Sentient-AI-/backend && python3 -m pytest tests -q
```

```bash
cd Sentient-AI-/frontend && npx vitest run && npx tsc -b
```

## Add a capability (the point of the base)

Read `backend/services/capabilities/README.md` — five steps, ~30 minutes for a simple tool family:

1. Toolkit in `services/tools/<family>.py` (`execute(action, params) -> dict`, fail closed).
2. `ToolSpec`s in `CONNECTOR_CATALOG`, policy rows in `permissions.py`, type in `BUILTIN_CONNECTOR_TYPES` + `_BUILTIN_STANCE`, entry in the executor's `_builtins` map.
3. Copy `services/capabilities/_template.py` → `<key>.py`, add to `REGISTRY`.
4. Tests for the toolkit and for your capability's `availability` / `probe`.
5. `python3 -m pytest tests/test_capabilities_registry.py tests/test_capabilities_report.py tests/test_wiring.py tests/test_capability_gating.py -q` — it fails loudly if you misdeclare anything.

Rules that are enforced, not optional: consequential actions (send, create account, spend, delete, install, type into a form) are WRITE/DELETE/EXECUTE so the approval flow applies; never ask for a password in chat; secrets never reach logs, audit rows or error bodies.

## Next projects (in order)

1. **`browser_control`** capability: OpenClaw-style accessibility snapshot with numbered refs + click/type/select by ref; site credentials stored through the Connectors UI and filled by the toolkit (the model never sees them). Reference example: "open Canvas in Chrome, sign in, list my missing assignments".
2. **Native install**: `install.sh` / `install.ps1`, per-user config dir, auto-generated keys, SQLite default, background service, `crawler doctor`. The wizard is already the thing the installer opens.
3. **Cost controls**: per-task hard cap, daily cap, cost footer on replies.

## Open items / gotchas

- Brand artwork still says the old name (`frontend/public/brand/sentientai-*`); a text wordmark is used until new assets exist.
- One frontend test is intermittently flaky (timing); rerun passes. Backend: the test client's random IP pool can collide in the auth rate limiter, rarely.
- Login still shows "Create one" after setup even when registration is closed (it returns 403).
- No "promote to owner" feature yet; the last owner account cannot be deleted.
- Replay cache key does not include the model.
