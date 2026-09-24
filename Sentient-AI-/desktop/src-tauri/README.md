# Crawler AI desktop app — Rust core (`src-tauri/`)

The Tauri 2 process behind `Crawler AI.app` / `Crawler AI Setup.exe`: it checks the
computer, writes the two security keys, copies the bundled Crawler AI source into a
per-user stack folder and drives `docker compose -p crawler-ai` there. Design:
`docs/superpowers/specs/2026-09-24-desktop-app-design.md`.

## Layout

| File | What it does |
| --- | --- |
| `src/preflight.rs` | `CommandRunner` trait + `SystemRunner` (argv only, allowlisted env, timeouts, no console window on Windows); Docker / Compose v2 / ports / disk checks; `compose ls` parsing with bootstrap.py's existing-stack / conflict rules; plain-English fixes |
| `src/keys.rs` | SECRET_KEY (48 CSPRNG bytes, URL-safe base64, 64 chars) and ENCRYPTION_KEY (32 bytes, URL-safe base64 with padding); validation identical to `installer/bootstrap.py` (replayed from `testdata/`); writes `backend/.env` from the bundled `.env.example`, replacing only those two lines, owner-only, with a backup |
| `src/stack.rs` | Copy the bundle to `<data>/Crawler AI/stack/<version>`, `compose up --build -d` / `start` / `stop` / `logs --tail 200 backend`, health polling (`:8000/api/health` every 3 s up to 20 min, then `:3000`), phases, failure hints |
| `src/platform.rs` | Stack paths per OS, child-process environment, `which`, owner-only files (0600, or `icacls /inheritance:r /grant:r *<SID>:F` on Windows), opening Docker Desktop and web links |
| `src/commands.rs` | `#[tauri::command]` wrappers (the UI contract below), `stack://log` / `stack://phase` events, and the hooks the tray uses (`is_installed`, start/stop in the background); `register(builder)` is the hook for `main.rs` |
| `src/windows.rs` | The `setup` window (bundled UI, IPC) and the `crawler` window (http://localhost:3000, no IPC), and where each may navigate |
| `src/updates.rs` | "Check for updates" against GitHub Releases (tray dialog and the `check_updates` command) |
| `src/main.rs`, `src/tray.rs` | The app: single instance, close-to-tray, Dock reopen, tray menu |
| `build.rs`, `capabilities/setup.json` | App ACL: build.rs turns every `#[tauri::command]` in `src/commands.rs` into the `app-commands` permission set, which only the `setup` window is granted; the `crawler` window gets nothing (`src/acl_tests.rs` proves it) |

Stack folder: `~/Library/Application Support/Crawler AI/stack/<version>/` on Mac,
`%LOCALAPPDATA%\Crawler AI\stack\<version>\` on Windows. A new version adopts the
previous version's `backend/.env` so the data in the shared `crawler-ai_*` volumes stays
readable.

## IPC contract (setup window only)

The contract is `desktop/ui/src/bridge.ts`; a unit test in `commands.rs` fails when the
command list here and there differ. Arguments and payloads are snake_case. Errors reject
with a plain string.

| Command | Arguments | Returns |
| --- | --- | --- |
| `preflight` | — | `PreflightReport`: `os`, `docker_installed`, `docker_version`, `docker_running`, `compose_v2`, `compose_version`, `ports[] {port, service, free, holder, docker, ours}`, `disk_free_gb`, `env_exists`, `env_keys_set`, `existing_stack`, `existing_stack_status`, `existing_stack_name`, `stack_conflict {name, status, folder, earlier_app_version}`, `ready`, `fixes[] {id, severity, text, link {href, label}}`. Adopts an earlier version's keys first. |
| `open_docker_desktop` | — | `{ok}` (Mac `open -a Docker`, Windows `Docker Desktop.exe`) |
| `save_keys` | `mode` (`"generate"` \| `"custom"`), `secret_key?`, `encryption_key?`, `overwrite?` | `{ok, reason, errors {secret_key?, encryption_key?, mode?}, mode, replaced_existing, backup, message}`; `reason` is `invalid` \| `exists` \| `no_example` \| `write_failed` \| `random_failed`. Keys are never returned. |
| `start_install` | — | `{ok, started, reason}` (`reason: "busy"` if a job runs); progress arrives as events |
| `install_status` | — | `{phase, elapsed_s, error}`: the running or failed job's phase; otherwise `idle` (not installed), `healthy` or `stopped` from the live stack |
| `open_crawler` | — | `null`; opens/focuses the Crawler AI window, hides the setup window |
| `stack_start` | — | same as `start_install` (for an installed, stopped stack) |
| `stack_stop` | — | `null`; cancels a running job first, then emits phase `stopped` |
| `app_info` | — | `{version, platform ("mac" \| "windows"), installed}` |
| `check_updates` | — | `{latest, url, newer}` from GitHub Releases (`desktop-v*` tags) |

Events (emitted to the `setup` window): `stack://phase` →
`{phase, error, elapsed_s}` with `phase` one of `copying`, `building`, `starting`,
`waiting`, `healthy`, `failed` (`error` set on `failed`) and `stopped` after Stop;
`stack://log` → the line as a plain string. The tray's "Show logs" also sends
`tray://show-logs` (no payload).

## Develop

```sh
cd Sentient-AI-/desktop/src-tauri
cargo test                       # no Docker, no UI build, no real ports needed
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Debug builds use `desktop/stack/` or, failing that, this repository's own
`backend/ frontend/ docker/` as the bundle (secrets, caches and tests are never
copied). Release builds expect the packaging step to ship it as the resource
`stack/` (tauri.conf.json `bundle.resources: {"../stack/": "stack/"}`).
