# Crawler AI installer

A double-click installer for Mac and Windows. It replaces the manual steps
(copy `backend/.env.example`, generate two keys, `docker compose up --build`,
open the browser) with a local web page and four buttons.

| You double-click | On | It runs |
|---|---|---|
| `Install Crawler AI.command` | macOS | `python3 installer/bootstrap.py` |
| `Install Crawler AI.bat` | Windows | `py -3 installer\bootstrap.py`, or `python installer\bootstrap.py` |

A Terminal (Mac) or Command Prompt (Windows) window opens and says
"Opening the Crawler AI installer in your browser…". The page opens at
`http://127.0.0.1:3999/` (the next free port up to 4010 if 3999 is taken).
Keep that window open while you install. Closing it, or pressing Ctrl+C,
stops the installer.

## The four steps

1. **Check your computer.** Is Docker Desktop installed and running? Is
   Docker Compose v2 or newer there? Are ports 3000, 8000, 5432 and 6379
   free, and is there enough disk space? Are keys already set in
   `backend/.env`? Is a Crawler AI stack already set up? Each failed check
   comes with a sentence saying how to fix it and, where it helps, a link to
   Docker Desktop. On a Mac or PC with Docker Desktop installed but stopped,
   an **Open Docker Desktop** button starts it and the page re-checks by
   itself. Continue unlocks once Docker is running and Compose is present.
   Port warnings don't block you. If `backend/.env` already has real keys,
   the page skips straight to Build.
2. **Security keys.** Choose *Generate for me* (the default) or *Use my
   own*. The installer writes `SECRET_KEY` and `ENCRYPTION_KEY` into
   `backend/.env`, which it creates from `backend/.env.example` with every
   other line kept. If `.env` already exists, it asks first. Replacing keys
   changes only those two lines and keeps a backup, `backend/.env.bak-<time>`.
3. **Build & start.** Runs `docker compose up --build -d` in `docker/`, the
   same command as the manual setup, and streams its output into the page.
   It then waits for `http://127.0.0.1:8000/api/health` (checking every 3 s
   for up to 20 minutes) and gives the web app on port 3000 up to 90 s to
   answer. The first build downloads about 3.6 GB. If it fails, the page
   shows the last 30 lines, a plain-English hint for common causes (Docker
   stopped, port taken, disk full, network) and a **Retry** button.
4. **Open Crawler AI.** Opens `http://localhost:3000`, where the app's own
   setup wizard takes over: owner account, AI key, Telegram, permissions.
   **Close installer** stops the local server. Crawler AI keeps running in
   Docker Desktop.

## First run from a downloaded ZIP

Files downloaded from the internet carry a "this came from the internet"
mark, so the operating system asks before running them the first time. A
`git clone` doesn't carry that mark, so you won't see these prompts.

**macOS (Gatekeeper).** Double-clicking `Install Crawler AI.command` from an
unzipped GitHub download shows "cannot be opened because it is from an
unidentified developer" (or "Apple could not verify…").

- macOS 14 and earlier: right-click (or Control-click) the file, choose
  **Open**, then **Open** again. You only need to do this once.
- macOS 15 and later: double-click it once and dismiss the warning. Then go
  to **System Settings › Privacy & Security**, scroll to the message about
  "Install Crawler AI.command", click **Open Anyway** and confirm.
- If it opens in a text editor or says you don't have permission, your unzip
  tool dropped the executable bit. Run `chmod +x "Install Crawler AI.command"`
  once, or run `python3 installer/bootstrap.py` from the project folder.
- No Python yet? The `.command` file offers Apple's Command Line Tools
  (`xcode-select --install`), which include Python 3.9. Double-click again
  after they finish installing.

**Windows (SmartScreen).** Double-clicking `Install Crawler AI.bat` from an
extracted ZIP may show "Windows protected your PC". Click **More info**, then
**Run anyway**. It may instead show "Open File – Security Warning"; click
**Run**. To avoid the prompt entirely, right-click the ZIP, choose
**Properties**, tick **Unblock**, and extract again.

- No Python yet? The `.bat` explains the two options and opens the download
  page: the **Microsoft Store** ("Python 3.12", then Get), or
  **python.org/downloads**, where you must tick *Add python.exe to PATH* in
  its installer. Double-click the `.bat` again afterwards.
- Docker Desktop for Windows needs **WSL 2** (Windows Subsystem for Linux).
  Its installer turns WSL 2 on for you. Restart when it asks, then open
  Docker Desktop once to accept its terms.

## Security

- **Loopback only.** The server binds `127.0.0.1`, never `0.0.0.0`, so
  nothing on your network can reach it.
- **One-time token.** Each run makes a fresh `secrets.token_urlsafe(32)`
  token and opens the browser at `http://127.0.0.1:<port>/?t=<token>`. The
  page moves the token into `sessionStorage` and removes it from the address
  bar. Every `/api/*` request must carry it in `X-Bootstrap-Token`, plus an
  `Origin` (or, for GETs, `Referer`) equal to the installer's own origin and
  a `Host` header naming it. Anything else gets 403. That blocks other
  websites and DNS-rebinding tricks from driving the installer, even though
  it runs on your machine. There are no CORS headers, and preflight
  (`OPTIONS`) requests are refused.
- **Locked-down page.** `page.html` is the only file served. It gets a
  per-response nonce Content-Security-Policy (`default-src 'none'`, scripts
  and styles only with that nonce, `connect-src 'self'`) and loads nothing
  from the internet. The one external link is Docker Desktop's download
  page, which opens in a new tab.
- **Never sees your AI API key.** You enter the provider key later, in the
  app's setup wizard, not here.
- **Keys are never logged or shown.** Generated keys use the same recipe as
  `backend/.env.example`: `secrets.token_urlsafe(48)` for `SECRET_KEY` and
  `base64.urlsafe_b64encode(os.urandom(32))` for `ENCRYPTION_KEY`. They are
  written straight to `backend/.env` and never returned to the page, logged
  or echoed. Custom keys are validated before anything is written.
  `SECRET_KEY` needs at least 32 characters with no whitespace or
  `.env`-special characters. `ENCRYPTION_KEY` must be base64 or URL-safe
  base64 of exactly 32 bytes. The checks only ever report whether the keys
  are *set*.
- **Private files.** `backend/.env`, its `.env.bak-*` backups and
  `installer/bootstrap.log` are written with mode 0600 (owner-only). Windows
  has no such modes, so there the files inherit the folder's permissions.
  Keep the project inside your user folder. Tightening this with explicit
  ACLs is planned.
- **Replacing keys has a cost.** Anything the app already encrypted with the
  old `ENCRYPTION_KEY` (saved AI keys, connector sign-ins) must be entered
  again, and sessions signed with the old `SECRET_KEY` end. The confirm
  dialog says so.
- **Subprocesses.** Every command is an argument list (never a shell) with a
  timeout: `docker --version`, `docker info`, `docker compose version`,
  `docker compose ls`, `lsof`, or `netstat` plus `tasklist` on Windows, and
  the build itself. Each runs with a minimal environment: PATH, HOME or
  USERPROFILE, Docker and proxy variables, and the Windows system variables
  Docker needs. API keys in your shell and a stray `COMPOSE_FILE` don't
  leak in.
- **Log.** `installer/bootstrap.log` (rotated at 5 MB) records events and
  build output, never key values. Request paths are logged without their
  query string, so the token stays out of it too.

## Good to know

- Ports: the check reports who holds a busy port (`lsof` on Mac,
  `netstat -ano` plus `tasklist` on Windows). A port held by your own
  running Crawler AI counts as fine.
- Same-named stacks: Compose names the project after the `docker/` folder
  ("docker"). If a *different* copy of Crawler AI is already running under
  that name, the check warns you. Building here would replace that copy's
  containers.
- Closing the installer mid-build stops `docker compose`. Running it again
  resumes from Docker's build cache.
- Reloading the page (or reopening it within the same browser tab) resumes
  where you were, including a build in progress.
- Linux isn't a target for the double-click flow, but
  `python3 installer/bootstrap.py` works there too.

## For developers

```bash
python3 installer/bootstrap.py [--port N] [--no-browser] [--check-only] [--verbose]
```

- `--check-only` prints the preflight report as JSON and exits. It runs only
  read-only Docker commands.
- `--no-browser` prints the URL instead of opening it.
- `--verbose` adds debug detail to the window and the log.

The script uses only the standard library and runs on Python 3.9+, which is
what Apple's Command Line Tools ship. Platform differences live in small
helpers: `current_os`, `build_env`, `Preflight.port_holder`,
`_chmod_private` and `default_start_docker`.

Tests (pytest, temp dirs, fake subprocesses; they never call Docker):

```bash
cd Sentient-AI-
python3 -m pytest installer/tests -q
```

| File | Purpose |
|---|---|
| `../Install Crawler AI.command` | macOS launcher (LF line endings, mode 755) |
| `../Install Crawler AI.bat` | Windows launcher (CRLF line endings; see `../.gitattributes`) |
| `bootstrap.py` | Local server, preflight, key writer, build runner |
| `page.html` | The four-step page (inline CSS and JS, no external resources) |
| `tests/` | pytest suite |
