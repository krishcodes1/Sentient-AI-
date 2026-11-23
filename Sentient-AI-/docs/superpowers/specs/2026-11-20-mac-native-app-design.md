# Native Mac app (no Docker)

## Goal

On a Mac, Crawler AI is one app: download the `.dmg`, drag it to Applications, open it.
The app installs and runs everything itself, with no Homebrew, Terminal or Docker, so
screen and computer control work and macOS asks for permissions in the name
**Crawler AI** (today they go to Terminal).

Windows keeps the Docker stack. Nothing changes there.

## What the user does

1. Opens the `.dmg`, drags Crawler AI to Applications, opens it. It is signed with the
   owner's Developer ID and notarized, so Gatekeeper shows no warning.
2. The setup window checks the Mac (macOS 13+, free disk, port 3000 free), then installs:
   Python 3.12 and the backend packages, Playwright's Chromium, a private database, fresh
   keys. There is no Docker step and no keys step on Mac. First open takes a few minutes and
   needs internet; progress and the live log show as they do today.
3. The window becomes Crawler AI and the in-app wizard asks for the owner account and the AI
   provider key, as today.
4. Screen Recording / Accessibility / Automation prompts name Crawler AI.

Later opens start the database and backend and show Crawler AI once it answers.

## Runtime

| Piece | Where | How it runs |
|---|---|---|
| uv | `Crawler AI.app/Contents/MacOS/uv` (Tauri `externalBin`) | builds the venv |
| PostgreSQL 16 | `Contents/Resources/postgres/` (relocatable zonky build, universal) | `pg_ctl` child of the app; **Unix socket only** (`listen_addresses=''`) in a 0700 folder |
| Backend source | `Contents/Resources/stack/backend`, copied per version like today | uvicorn on `127.0.0.1:3000` |
| Frontend | built once at app build time into `stack/frontend-dist` | served by the backend (`FRONTEND_DIST`) on the same origin |
| Python + packages | `~/Library/Application Support/Crawler AI/native/venv` | installed from a hash-locked lockfile |
| Database files | `…/Crawler AI/native/postgres` | |
| Socket, pid files, logs | `…/Crawler AI/native/{run,logs}` | |
| Downloads cache | `~/Library/Caches/Crawler AI/{uv,python,playwright}` | |

The backend's own data (browser profiles, vault id) stays where it already lives:
`~/Library/Application Support/Crawler AI`. Keys stay in `stack/<version>/backend/.env`
(owner-only), carried across versions by the existing `adopt_previous_env`.

Serving everything on `127.0.0.1:3000` keeps the OAuth redirect base
(`OAUTH_REDIRECT_BASE` default `http://127.0.0.1:3000`) unchanged.

### Lifecycle

- **Open:** if installed, start Postgres and the backend in the background and show
  Crawler AI when `/api/health` answers; otherwise the setup window.
- **Close window:** hides it; the menu-bar icon stays and the backend keeps running
  (schedules keep firing).
- **Quit:** stops the backend, then Postgres (fast shutdown). Unlike the Docker stack,
  the native stack is the app's own processes, so it does not outlive the app.
- Tray Start / Stop / Show logs work on the native stack.

### Process control

A bundled script, `stack/mac/crawler-native.sh` (`install | start | stop`), does the work,
derived from the proven `crawler.sh`. The Rust side runs it through the existing
`CommandRunner::stream` and turns its `==> phase` lines into the existing setup phases, so
the setup UI, tray and job state are reused. A `StackOps` trait gives `Core` either the
Docker `Stack` (Windows, Linux dev) or the new `NativeStack` (macOS).

## Backend change

When `FRONTEND_DIST` is set, the backend serves that folder: real files as-is, every other
non-`/api` GET falls back to `index.html`, with the same security headers the production
nginx sets (CSP, `X-Frame-Options: DENY`, `nosniff`, Referrer-Policy, Permissions-Policy).
`/api` routes are never shadowed. Unset (Docker, dev) means no change.

## Security

- Developer ID signature, hardened runtime, notarization. Every Mach-O in the app (uv,
  Postgres binaries and libraries) is signed with the same identity.
- New entitlement: `com.apple.security.automation.apple-events` plus
  `NSAppleEventsUsageDescription` (the backend drives apps through `osascript`).
- First-open downloads are pinned: `requirements.lock` with a SHA-256 for every package,
  generated at build time, installed with `--require-hashes`. uv verifies the Python
  download's checksum.
- Postgres has no TCP port; a random password anyway. Backend binds `127.0.0.1` only,
  `ALLOWED_HOSTS` is `localhost` and `127.0.0.1`.
- Keys come from the OS CSPRNG through the existing `KeyWriter`; `.env` is 0600; keys are
  never shown or logged.
- The Crawler AI window still has no IPC access (`acl_tests.rs` unchanged).

## Build

`npm run tauri build` on a Mac, from `desktop/`, after a prep script that:

1. builds `frontend/` into `stack/frontend-dist`,
2. downloads pinned uv and zonky Postgres 16 for arm64 and x86_64, checks their SHA-256,
   and `lipo`s universal binaries,
3. writes `requirements.lock` (`uv pip compile --generate-hashes`, macOS, Python 3.12),
4. signs the Postgres Mach-Os with `APPLE_SIGNING_IDENTITY` when set (ad-hoc otherwise).

`desktop.yml` runs the same prep on its macOS job; its signing secrets already exist.

## Testing

- Rust: `NativeStack` phases, failures and cancel with the existing fake runner/probe/clock;
  `StackOps` selection per OS; tray/ACL tests stay green.
- Backend: static serving, SPA fallback, headers, `/api` not shadowed, unset = no route.
- Script: `crawler-native.sh` install/start/stop against a temp folder on this Mac.
- By hand: a fresh macOS user account on the owner's Mac, from the signed `.dmg`, through
  first open, the in-app wizard, the permission prompts (named Crawler AI) and Quit.

## Out of scope

Windows changes, in-app auto-update (the existing "Check for updates" stays), Open at
Login, an offline install, and moving an existing `~/CrawlerAI` install's data into the app
(done once by hand on the owner's Mac, not an app feature).
