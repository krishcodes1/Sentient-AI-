# Crawler AI desktop app

A normal app people download and double-click (`.dmg` on Mac, `Setup.exe` on Windows) that
installs, starts and opens Crawler AI with no Terminal and no `.env` editing. It runs the same
Docker stack as the bootstrap installer (Compose project `crawler-ai`), so the app, the
bootstrap and the CLI all manage one stack. Design: `docs/superpowers/specs/2026-09-24-desktop-app-design.md`.

```
desktop/
  package.json          the app version (single source) + scripts; Tauri CLI
  app-icon.png          1024 px source for the icon set (placeholder art)
  scripts/stage-stack.mjs   copies ../backend ../frontend ../docker into stack/ (no .env, no deps, no tests)
  src-tauri/            Rust: the app process
    tauri.conf.json     product name, identifier, bundle targets, CSP, macOS/Windows settings
    capabilities/setup.json   IPC for the "setup" window only
    build.rs            derives the app-command ACL from src/commands.rs
    Entitlements.plist  hardened-runtime entitlements (network client only)
    src/lib.rs          the library: setup logic + windows (what `cargo test` covers)
    src/windows.rs      the setup and Crawler AI windows, and where each may navigate
    src/{preflight,keys,stack,platform,commands}.rs   setup logic (Docker checks, keys, compose)
    src/main.rs         the app: single instance, close-to-tray, Dock reopen
    src/tray.rs         tray / menu-bar menu
    src/updates.rs      "Check for updates" against GitHub Releases
    src/acl_tests.rs    proves the Crawler AI window has no IPC access
  ui/                   Vite + React: the four-step setup + status screen (bundled, no remote resources)
  stack/                generated at build time; not committed
```

## How it behaves

- **First launch** opens the setup window (bundled UI). When setup finishes, the window
  becomes Crawler AI: a second window loads `http://localhost:3000` and the setup window hides.
- **Later launches** open Crawler AI directly if it is installed and answering on port 3000,
  otherwise the status window (where Start lives).
- **Closing a window hides it**; the tray / menu-bar icon stays. Clicking the Dock icon (Mac) or
  left-clicking the tray icon (Windows; right-click shows the menu) brings it back.
- **Tray menu:** Open Crawler AI · Start · Stop · Show logs · Check for updates · Quit.
  **Quit exits the app and leaves the stack running.**
- **One instance:** launching again focuses the running app.

### Security model

- Two windows, two trust levels. Only the window labelled `setup` (the bundled UI) has IPC:
  `capabilities/setup.json` grants it Tauri core, events and the `app-commands` set. The
  Crawler AI window (`crawler`) is in no capability, so the web app cannot start/stop the stack
  or read files. `src/acl_tests.rs` proves this with Tauri's mock runtime on every `cargo test`.
- `build.rs` turns every `#[tauri::command]` in `src/commands.rs` into an `allow-<name>`
  permission and bundles them as `app-commands`; with that manifest in place Tauri checks every
  app command against the capabilities. Add commands to `commands.rs` and they work from the
  setup window with no other edit; a command defined elsewhere is denied.
- Links that leave Crawler AI (or the setup UI) open in the default browser, never inside the
  app; `file:`, `javascript:` and custom schemes are dropped. `target="_blank"` / `window.open`
  never create app windows.
- CSP on the bundled UI: `default-src 'self'`, scripts from the bundle only, no remote resources.
- The bundled stack source is inside the signed app, so the signature covers the exact code
  Docker builds. `.env` files and their backups, private keys and certificates (`.pem`, `.key`,
  `.p8`, `.p12`, `.pfx`, SSH keys), local databases and `docker/data/` are never bundled
  (`scripts/stage-stack.test.mjs`, run in CI on every push).

## Develop

Prerequisites:

| | Mac | Windows |
|---|---|---|
| Rust | `rustup` (stable). Universal builds also need `rustup target add aarch64-apple-darwin x86_64-apple-darwin` | `rustup` with the MSVC toolchain + "Desktop development with C++" (Visual Studio Build Tools) |
| Node | 20 or newer | 20 or newer |
| System | Xcode Command Line Tools (`xcode-select --install`), macOS 13+ | WebView2 (built into Windows 10/11) |
| To run the stack | Docker Desktop | Docker Desktop (WSL 2 backend) |

```bash
cd Sentient-AI-/desktop
npm install
npm --prefix ui install
npm run dev            # UI dev server on :5174 + the app with hot reload
```

Tests (CI runs all three before every build):

```bash
npm test                                         # stage-stack: what ships, what never does
npm --prefix ui test                             # setup UI (vitest)
cargo test --manifest-path src-tauri/Cargo.toml  # Rust: preflight, keys, stack, navigation, tray, updates, IPC ACL
```

## Build

The version lives in **`desktop/package.json` only** (`tauri.conf.json` reads it; `stack/VERSION`
is written from it). `beforeBuildCommand` builds `ui/` and runs `scripts/stage-stack.mjs`.

**Mac** (on a Mac):

```bash
npm run tauri -- build --bundles app,dmg                                  # this Mac's architecture
npm run tauri -- build --target universal-apple-darwin --bundles app,dmg  # Apple silicon + Intel
# → src-tauri/target/[universal-apple-darwin/]release/bundle/dmg/Crawler AI_<version>_<arch>.dmg
```

Without signing variables the app is **ad-hoc signed** (hardened runtime, entitlements applied,
resources sealed): it runs on the machine that built it, and elsewhere after
*System Settings → Privacy & Security → Open Anyway* once.

**Windows** (on Windows):

```bash
npm run tauri -- build --bundles nsis
# → src-tauri\target\release\bundle\nsis\Crawler AI_<version>_x64-setup.exe
```

Per-user install (no admin rights), unsigned for now: SmartScreen shows *More info → Run anyway*.

## Release (GitHub Actions)

`.github/workflows/desktop.yml` builds the universal `.dmg` and the Windows `.exe`, runs the
tests first, and uploads both (plus `SHA256SUMS.txt`) to a **draft pre-release**
`desktop-v<version>`. Start it from *Actions → Desktop app → Run workflow*, or push a tag:

```bash
# bump "version" in desktop/package.json, commit, then:
git tag desktop-v0.1.0 && git push origin desktop-v0.1.0
```

The owner reviews the draft and publishes it. A published release is never modified by a
re-run; bump the version instead. "Check for updates" in the app looks at published
`desktop-v*` releases (pre-releases included, drafts not).

## Signing (owner only)

Signing material is set by the owner as **GitHub Actions secrets** (Settings → Secrets and
variables → Actions) or, for a local signed build, as environment variables in their own
shell. It is never committed and never handled by agents. The workflow signs and notarizes
only when these exist; otherwise it produces the ad-hoc build.

| Secret / variable | What |
|---|---|
| `APPLE_CERTIFICATE` | base64 of the *Developer ID Application* `.p12` (`base64 -i cert.p12 \| pbcopy`) |
| `APPLE_CERTIFICATE_PASSWORD` | the `.p12` export password |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_API_ISSUER`, `APPLE_API_KEY`, `APPLE_API_KEY_P8` | notarization with an App Store Connect API key (issuer id, key id, contents of `AuthKey_<id>.p8`). Locally, set `APPLE_API_KEY_PATH` to the `.p8` file instead of `APPLE_API_KEY_P8`. |
| `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | or notarization with an Apple ID + app-specific password |

Windows code signing (Azure Trusted Signing or an OV certificate) and the signed in-app
updater (its own key, stored as a secret) are planned for later releases.

## Headless-Mac test checklist

What CI cannot cover — Gatekeeper, the tray, real Docker — is checked by hand on the test Mac.
The app needs a logged-in **GUI session**: connect with Screen Sharing (Finder → Go → Connect
to Server → `vnc://<mac-name>.local`). SSH alone is enough for building and for the `docker`
checks below, not for the windows.

**Before**

- [ ] macOS 13 or newer; Docker Desktop installed, started once, running (`docker version`, `docker compose version`).
- [ ] Ports free: `lsof -nP -iTCP -sTCP:LISTEN | grep -E ':(3000|8000|5432|6379) '` prints nothing
      (an old stack: `docker compose -p crawler-ai down` — keeps the data volumes).
- [ ] Get the build: the `.dmg` from the draft release (check it: `shasum -a 256 Crawler-AI-*.dmg`
      against `SHA256SUMS.txt`), or build on the Mac with the commands above.
- [ ] To watch the app's own log, start it from Terminal: `"/Applications/Crawler AI.app/Contents/MacOS/crawler-ai"`.

**Install and first run**

- [ ] Open the `.dmg`, drag Crawler AI to Applications, open it. Unsigned build: System Settings →
      Privacy & Security → Open Anyway (once). Signed build: opens with no warning;
      `spctl -a -vv "/Applications/Crawler AI.app"` says `accepted … Notarized Developer ID`.
- [ ] `codesign --verify --deep --strict "/Applications/Crawler AI.app"` prints nothing.
- [ ] The setup window opens and the menu-bar "C" icon appears.
- [ ] Step 1: all checks pass. Quit Docker Desktop → Docker shows as not running and
      "Open Docker Desktop" starts it; run `python3 -m http.server 3000` → port 3000 is flagged;
      stop it → re-check passes.
- [ ] Step 2 "Generate for me": afterwards `ls -l ~/Library/Application\ Support/Crawler\ AI/stack/<version>/backend/.env`
      shows `-rw-------`, and no key appears in the window or the log.
- [ ] Step 3: live log, phase line and elapsed time; ends with "Crawler AI is running";
      `docker compose ls` lists `crawler-ai`.
- [ ] Step 4: the window becomes Crawler AI (`localhost:3000`) and the in-app wizard works.
- [ ] A link to another site (e.g. the BotFather link in the Telegram step) opens in the
      default browser, not inside the app.

**Everyday use**

- [ ] Closing the window (red button or ⌘W) hides it; the menu-bar icon stays; clicking the
      Dock icon brings it back.
- [ ] Tray → Stop: `docker compose -p crawler-ai ps` shows the containers stopped.
      Tray → Start: they come back. Tray → Show logs: the status window with the log.
- [ ] Tray → Check for updates: a dialog (up to date / update available / couldn't check).
- [ ] Opening the app again while it runs focuses the existing window (no second menu-bar icon).
- [ ] Tray → Quit: the app exits and `docker compose -p crawler-ai ps` still shows the stack running.
- [ ] Launch again: opens Crawler AI directly. With the stack stopped (or after a reboot before
      Docker starts): opens the status window, not an error page; Start works.

**Clean up** (the Mac is a test machine): quit the app, delete it from Applications, then
`docker compose -p crawler-ai down -v` (deletes Crawler AI's data) and
`rm -rf ~/Library/Application\ Support/Crawler\ AI`.

## Replacing the placeholder icon

Put the new 1024 × 1024 PNG at `desktop/app-icon.png`, then:

```bash
npx tauri icon app-icon.png -o src-tauri/icons
rm -rf src-tauri/icons/{android,ios} src-tauri/icons/Square*Logo.png src-tauri/icons/StoreLogo.png src-tauri/icons/64x64.png
```

`src-tauri/icons/tray-template.png` is the menu-bar icon: 44 × 44, black on transparent (macOS
tints it for light and dark menu bars).
