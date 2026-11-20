# Native Mac app Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On macOS the Crawler AI desktop app installs and runs Crawler AI natively (no Docker),
so one double-click does everything and macOS permissions belong to Crawler AI.

**Architecture:** A bundled shell script (`desktop/mac/crawler-native.sh`, derived from the
proven `crawler.sh`) does install/start/stop. `Stack` gains a native mode on macOS that runs
the script through the existing `CommandRunner::stream` and maps its `==> ` lines to the
existing phases, so commands, job state, tray and setup UI are reused. The backend serves the
prebuilt frontend on `127.0.0.1:3000` when `FRONTEND_DIST` is set. Spec:
`docs/superpowers/specs/2026-11-20-mac-native-app-design.md`.

**Tech Stack:** Tauri 2 (Rust), React/Vite (setup UI), FastAPI/Starlette, bash, uv,
zonky PostgreSQL 16.16 (universal, EDB-signed), Playwright.

Paths below are relative to `Sentient-AI-/` unless they start with `/`.

---

## File map

| File | Change |
|---|---|
| `backend/core/config.py` | `FRONTEND_DIST: str = ""` |
| `backend/main.py` | serve `FRONTEND_DIST` (SPA fallback, `/api` never shadowed); `/` JSON only when unset |
| `backend/tests/test_frontend_dist.py` | new |
| `desktop/mac/crawler-native.sh` | new: `install`, `start`, `stop` |
| `desktop/scripts/prep-mac.sh` | new: uv (universal), Postgres, frontend build, hash lockfile |
| `desktop/scripts/stage-stack.mjs` (+ test) | also stage `mac/` |
| `desktop/src-tauri/tauri.macos.conf.json` | new: externalBin uv, Postgres resources, mac beforeBuildCommand |
| `desktop/src-tauri/Info.plist` | new: `NSAppleEventsUsageDescription` |
| `desktop/src-tauri/Entitlements.plist` | + `com.apple.security.automation.apple-events` |
| `desktop/src-tauri/src/native.rs` | new: native paths, argv, install/start/stop, tests |
| `desktop/src-tauri/src/stack.rs` | `native: Option<NativeLayout>`; methods branch; `wait_healthy` takes a log source |
| `desktop/src-tauri/src/commands.rs` | native keys before install; start-then-open; stop on exit |
| `desktop/src-tauri/src/main.rs` | auto-start on launch (mac); stop on `RunEvent::Exit` (mac) |
| `desktop/ui/src/components/Setup.tsx`, `InstallStep.tsx`, `platform.ts`, `OpenStep.tsx`, `RunningScreen.tsx`, `phase.ts` (+ tests) | mac = Install (auto) + Open, no Docker wording |

---

### Task 1: Backend serves the built frontend

**Files:** `backend/core/config.py`, `backend/main.py`, `backend/tests/test_frontend_dist.py`

- [ ] Write the failing test: build a tiny dist (`index.html`, `assets/app.js`) in `tmp_path`,
  call `mount_frontend(app, dist)` on a fresh `FastAPI()` that has `GET /api/ping`, then assert with
  `TestClient`:
  - `GET /` and `GET /settings/profile` → 200, body of `index.html`, `text/html`
  - `GET /assets/app.js` → 200, the file
  - `GET /api/ping` → the route's JSON; `GET /api/nope` → 404 JSON, not `index.html`
  - `GET /../main.py` style traversal → never outside the dist (Starlette refuses it)
- [ ] Run `cd backend && ../../venv/bin/python -m pytest tests/test_frontend_dist.py -q`: fails (no `mount_frontend`).
- [ ] Implement in `main.py` (after every router, before the exception handlers):

```python
class _SpaFiles(StaticFiles):
    """The built frontend: real files as they are, any other path is the SPA's index.html.
    /api/* is never answered with the page, so an unknown API path stays a 404."""

    async def get_response(self, path: str, scope):  # type: ignore[override]
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404 or path == "api" or path.startswith("api/"):
                raise
            return await super().get_response("index.html", scope)


def mount_frontend(target: FastAPI, dist: str) -> None:
    target.mount("/", _SpaFiles(directory=dist, html=True), name="frontend")


if settings.FRONTEND_DIST:
    mount_frontend(app, settings.FRONTEND_DIST)
```

  and register the `GET /` JSON route only when `FRONTEND_DIST` is empty. The existing
  `SecurityHeadersMiddleware` already adds the SPA CSP and headers to every response.
- [ ] Tests pass; full `pytest -q` subset for `test_route_security.py` still passes.
- [ ] Commit `feat(backend): serve the built frontend when FRONTEND_DIST is set`.

### Task 2: `crawler-native.sh`

**Files:** `desktop/mac/crawler-native.sh`

Environment the app passes (via `/usr/bin/env` in argv): `CRAWLER_VERSION`,
`CRAWLER_STACK` (= `stack/<version>`, holds `backend/`, `frontend-dist/`, `mac/`),
`CRAWLER_HOME` (= `~/Library/Application Support/Crawler AI/native`),
`CRAWLER_CACHE` (= `~/Library/Caches/Crawler AI`), `CRAWLER_UV` (bundled uv),
`CRAWLER_PG` (bundled Postgres root with `bin/`).

- `install`: checks (macOS ≥ 13, ≥ 3 GB free, port 3000 free or ours); `uv venv --seed
  --python 3.12` with `UV_PYTHON_INSTALL_DIR=$CRAWLER_HOME/python` (not in Caches: the venv
  links to it) and `UV_CACHE_DIR=$CRAWLER_CACHE/uv`; `uv pip install --require-hashes -r
  backend/requirements.lock`; `python -m playwright install chromium` into
  `$CRAWLER_HOME/playwright`; `initdb` once (scram, random password, `listen_addresses=''`,
  socket dir `$CRAWLER_HOME/run`); write `DATABASE_URL` (socket URL, `%20`-escaped),
  `REDIS_URL=`, `ALLOWED_HOSTS=["localhost","127.0.0.1"]` into the existing `.env`
  (keys already written by the app); then `start`; then write `$CRAWLER_HOME/installed-version`.
  Every stage prints `==> building` / `==> starting` first so Rust can map phases.
- `start`: Postgres (`pg_ctl -w start` unless running), backend (`nohup uvicorn main:app
  --host 127.0.0.1 --port 3000`, `FRONTEND_DIST`, `PLAYWRIGHT_BROWSERS_PATH`, pid file,
  log to `$CRAWLER_HOME/logs/backend.log`), returns once spawned (Rust waits for health).
- `stop`: backend pid (TERM, 10 s, KILL), pkill its browser profiles, `pg_ctl -m fast stop`.
- Errors: one plain line `error: <what to do>` and exit 1.

- [ ] Write it.
- [ ] Smoke test on this Mac with every path under the scratchpad and the real bundled
  pieces from Task 3: `install` → `curl 127.0.0.1:3000/api/health` 200 and `/` is the SPA →
  `stop` → nothing listening, `start` again works.
- [ ] Commit `feat(desktop): native macOS stack script`.

### Task 3: Build prep and bundling

**Files:** `desktop/scripts/prep-mac.sh`, `desktop/scripts/stage-stack.mjs` (+ test),
`desktop/src-tauri/tauri.macos.conf.json`, `desktop/src-tauri/Info.plist`,
`desktop/src-tauri/Entitlements.plist`, `desktop/.gitignore` entries for generated output.

- `prep-mac.sh` (idempotent, run from `desktop/`):
  1. uv `0.11.7`: download `uv-aarch64-apple-darwin.tar.gz` and `uv-x86_64-apple-darwin.tar.gz`
     from the GitHub release, check pinned SHA-256s, `lipo -create` →
     `src-tauri/binaries/uv-universal-apple-darwin`, and copy to `uv-aarch64-apple-darwin` /
     `uv-x86_64-apple-darwin` (Tauri's per-target sidecar names).
  2. Postgres: zonky `embedded-postgres-binaries-darwin-arm64v8-16.16.0.jar` (already
     universal), pinned SHA-256, extract `postgres-darwin-arm_64.txz` → `desktop/postgres/`,
     delete library copies no Mach-O references (`otool -L`), keep EDB's signatures.
  3. `npm ci && npm run build` in `../frontend` → `stack/frontend-dist`.
  4. `<bundled uv> pip compile ../backend/requirements.txt --universal --python-version 3.12
     --generate-hashes -o stack/backend/requirements.lock` (the bundled uv, so CI needs no
     extra tool: `desktop.yml`'s macOS job gets all of this through `beforeBuildCommand`).
- `stage-stack.mjs`: add `mac` to what it stages (from `desktop/mac`), keep `frontend-dist`
  and `requirements.lock` across restages; test asserts `stack/mac/crawler-native.sh` exists.
- `tauri.macos.conf.json`: `bundle.externalBin: ["binaries/uv"]`,
  `bundle.resources: {"../stack/": "stack/", "../postgres/": "postgres/"}`,
  `build.beforeBuildCommand: "npm run build:ui && npm run stage-stack && bash scripts/prep-mac.sh"`.
- `Info.plist`: `NSAppleEventsUsageDescription` = "Crawler AI controls other apps when you
  ask it to."; Entitlements: add `com.apple.security.automation.apple-events`.

- [ ] Write; run `bash scripts/prep-mac.sh`; `npm test` passes.
- [ ] Commit `build(desktop): bundle uv, Postgres and the built frontend on macOS`.

### Task 4: Native mode in `Stack`

**Files:** `desktop/src-tauri/src/native.rs`, `stack.rs`, `lib.rs`

- `NativeLayout { home, cache, uv, pg }` with `NativeLayout::for_this_mac(resource_dir)`.
- `Stack.native: Option<NativeLayout>`; `Stack::with_native(...)`. When set:
  - `is_installed`: keys set **and** `home/installed-version` == version.
  - `install`: Copying (same `copy_bundle`, `BUNDLE_DIRS` + `frontend-dist`, `mac`) → keys
    present or fail → script `install` streamed; `==> building`/`==> starting` drive phases;
    `error:` lines become the failure message → `wait_healthy`.
  - `start`: Starting → script `start` → `wait_healthy`.
  - `stop`: script `stop`.
  - logs: last lines of `home/logs/backend.log`.
  - `health_url`/`frontend_url` = `http://127.0.0.1:3000/api/health` and `/`.
- `wait_healthy(job, logs: &dyn Fn(usize) -> Vec<String>)` so both modes share it.
- Tests (FakeRunner/ScriptedProbe/FakeClock): install walks Copying→Building→Starting→
  Waiting→Healthy and the argv is `/usr/bin/env CRAWLER_…= /bin/bash <stack>/mac/crawler-native.sh install`;
  an `error:` line fails with that text; cancel → "Stopped before…"; `is_installed` needs the
  version file; `start` before install fails; stop runs `stop`.
- [ ] Tests first, then code; `cargo test` green.
- [ ] Commit `feat(desktop): native stack mode for macOS`.

### Task 5: App behaviour on macOS

**Files:** `desktop/src-tauri/src/commands.rs`, `main.rs`, `platform.rs` (if a helper is needed)

- `Core::new`: on `Os::Mac` build the stack with `NativeLayout::for_this_mac`.
- Install job on Mac: `adopt_previous_env()`, then `keys.write(KeyMode::Generate, false)` if
  keys are not all set (never overwrite), before `stack.install`.
- `start_then_open(app)`: Start job; on `Ok` → `windows::open_crawler_window`.
- main.rs (mac + native): on launch, installed but not answering → `start_then_open` and show
  the status window; `RunEvent::Exit` → `stack.stop()` (blocking, bounded by the script's own
  timeouts).
- Tests: job-state tests unchanged; a unit test that Mac core picks native.
- [ ] Commit `feat(desktop): start on open and stop on quit on macOS`.

### Task 6: Setup UI on macOS

**Files:** `desktop/ui/src/components/Setup.tsx`, `InstallStep.tsx`, `OpenStep.tsx`,
`RunningScreen.tsx`, `platform.ts`, `phase.ts` and their tests.

- Mac: steps "Install & start" (starts by itself) and "Open Crawler AI"; Windows unchanged.
- Wording: `PlatformWords.runsIn` (mac "on this Mac", windows "in Docker Desktop"),
  `quitStops` note on mac; phase labels neutral ("Installing…" not Docker-specific).
- Tests: Setup on mac renders two steps and calls `startInstall` without a click.
- [ ] `npm --prefix ui test` green. Commit `feat(desktop-ui): one-screen setup on macOS`.

### Task 7: Build, sign, run

- [ ] `npm run tauri -- build --target universal-apple-darwin --bundles app,dmg` with
  `APPLE_SIGNING_IDENTITY` (owner's Developer ID from the login keychain).
- [ ] `codesign --verify --deep --strict` the app; notarize with the owner's own
  `notarytool` keychain profile (the owner runs `store-credentials`; agents never see it);
  `spctl -a -vv` says Notarized Developer ID.
- [ ] Run it as this user: first open → wizard → Screen Recording prompt names Crawler AI →
  Quit stops ports 3000 and Postgres.

### Task 8: Move the owner's `~/CrawlerAI` data in (one-off, not app code)

- [ ] Stop the old install; replace the `~/Library/Application Support/Crawler AI` symlink with
  a real folder holding `browser-profiles/` and `vault-id`.
- [ ] Put the old `SECRET_KEY`/`ENCRYPTION_KEY` (and connector settings) into the app's
  `.env` before first open; after install, `pg_dump` the old database and restore it into the
  app's database over its socket; restart; check sign-in and connectors.
