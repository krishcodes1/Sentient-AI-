# Crawler AI desktop app: setup window

The window people see when they open the Crawler AI app: a four-step setup on first run
(Check this computer, Security keys, Install & start, Open) and a status screen afterwards
(Open Crawler AI, Start, Stop, Show logs, Check for updates). Vite + React 18 + TypeScript,
bundled by Tauri 2 from `dist/`. Design: `docs/superpowers/specs/2026-09-24-desktop-app-design.md`.
Look and wording follow the browser installer (`installer/page.html`).

## Commands

```bash
npm install
npm run dev        # Vite on http://localhost:5174 (tauri.conf.json's devUrl)
npm test           # vitest, bridge mocked, no Rust or Docker needed
npm run lint       # eslint, --max-warnings 0
npm run typecheck  # tsc --noEmit
npm run build      # tsc + vite build + scripts/check-dist.mjs (CSP check) -> dist/
```

Opened in a normal browser, `npm run dev` runs against an in-memory stand-in
(`src/devFake.ts`) and shows a "Preview" banner. Scenarios: `?docker=off`, `?docker=missing`,
`?ports=busy`, `?keys=set`, `?fail=1` (first install fails, Retry succeeds), `?installed=1`
(status screen), `?platform=windows`. The stand-in is compiled out of release builds.

## Talking to Rust

Only `src/bridge.ts` calls `invoke` / `listen`. Names and payloads:

| Command / event | Arguments | Returns |
| --- | --- | --- |
| `preflight` | none | `{docker_installed, docker_running, compose_v2, compose_version, ports:[{port, service, free, holder}], disk_free_gb, env_keys_set, existing_stack, stack_conflict, ready, fixes:[{id, severity, text, url?}]}` |
| `open_docker_desktop` | none | anything; `false` or `{ok:false}` means it couldn't be opened |
| `save_keys` | `mode` ("generate" or "custom"), `secret_key?`, `encryption_key?`, `overwrite?`, as flat snake_case arguments | `{ok, reason?}`; `reason:"exists"` asks for an overwrite confirmation |
| `start_install` | none | `{ok}` |
| `install_status` | none | `{phase, elapsed_s, error?}` |
| `open_crawler`, `stack_start`, `stack_stop` | none | ignored (a rejected promise shows the error) |
| `app_info` | none | `{version, platform:"mac" or "windows", installed}` |
| `check_updates` | none | `{latest?, url, newer}` |
| event `stack://log` | | one line of output (string) |
| event `stack://phase` | | `{phase, elapsed_s, error?}` |

Phase names the UI knows: `idle`, `preparing`/`copying`/`extracting`, `pulling`, `building`,
`starting`/`starting_containers`, `waiting`/`waiting_backend`/`waiting_frontend`, `healthy`
(or `running`), `stopping`, `stopped`, `failed` (or any phase with `error`). An unknown phase
shows as "Working…" and never ends the progress view.

Links (Docker download, update page) are rendered as `https` anchors with `target="_blank"`;
the Rust side decides how to open them in the default browser.

## Content-Security-Policy

The bundle has no inline scripts or styles, no web fonts, and no remote or `data:` resources,
so it runs under `default-src 'self'`. `scripts/check-dist.mjs` fails the build if that changes.
