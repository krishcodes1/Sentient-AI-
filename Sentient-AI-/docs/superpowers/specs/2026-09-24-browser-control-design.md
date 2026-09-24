# `browser_control` — the agent drives a real browser

**Date:** 2026-09-24 · **Product:** Crawler AI · **Status:** approved design (owner decisions recorded in §2)

## 1. Goal

Give the agent a browser it can use the way a person does — open a site, read what is on the page, click, type, sign in — so tasks like "open Canvas, log in, tell me which assignments are missing" and "find the cheapest flight and send me a screenshot" work with no site API. Do it at cents per task, with the owner's passwords never reaching the model, and with every consequential action approved by the owner.

Reference tasks:
- **Canvas (logged-in, private):** navigate courses, grades and the planner; report where things are and what is missing.
- **Flights (public):** search, read fares, screenshot.
- **Sign up for a free calling service and place a call:** sign-up is in scope (consequential steps approved); the call itself needs audio routing and is a later capability.

Out of scope for this project: file upload/download, running JavaScript, the owner's everyday Chrome profile, CAPTCHA solving (never), audio.

## 2. Owner decisions (2026-09-24)

| Decision | Choice |
|---|---|
| First slice | The full slice: read, act, and login — built in the order §12 gives, each part gated and tested before the next. |
| Passwords | Stored in an encrypted vault whose key lives **only in the Mac's Keychain**; decryption is impossible off that machine. |
| How Crawler logs in | Both: the owner may sign in by hand in Crawler's own window (session persists), or store a login in the vault for `browser.login`. Chosen per site. |
| Approvals | Consequential actions only (submit, send, buy, sign up, call, delete, confirm, typing into a new site, and the login itself). Reading and navigating never prompt. |
| What leaves the Mac | Text summaries by default for logged-in sites; screenshots of them only when asked, with secret fields masked and image data not kept in the database. |
| Model and budget | Gemini 2.5 Flash, thinking capped for browser steps; per-task caps (~60 actions, ~$0.25) then a "continue?" message. |

## 3. Why OpenClaw cost $10 and this design will not

OpenClaw keeps every page snapshot in the conversation and resends all of them on every step, so cost grows with the square of the step count; 60–75 steps reach $10 on Flash. This design keeps **only the latest page** in context, replaces older observations with **one-line summaries written by the toolkit** (not by the model), caps snapshot size, returns the new page inline after every action (no separate "look" turn), and enforces hard per-task caps. Honest estimate: cents to low tens of cents per task; measured before the number goes in the docs.

## 4. Architecture

```
Telegram / web ─▶ agent route ─▶ AgentRuntime ─▶ tool_registry executor
                                                   │  browser.read / browser.act / browser.login
                                                   ▼
                                   services/tools/browser/  (toolkit)
                                   ├─ session.py      BrowserSessionManager: one context per user
                                   ├─ snapshot.py     aria snapshot → filtered outline with refs
                                   ├─ actions.py      open/click/type/… on refs + gates
                                   ├─ login.py        vault-backed, origin-bound fill
                                   ├─ handoff.py      MFA/CAPTCHA detector + parked turn
                                   └─ guard.py        egress + consequential-action checks
                                   services/vault.py   Keychain-bound secret store
                                   Playwright ─▶ Chrome (native, headed) | Chromium (Docker, headless)
```

- **Native (Mac/Windows):** `launch_persistent_context(user_data_dir=<app-data>/browser-profiles/<user_id>, channel="chrome" | "msedge", headless=False)` — the user's installed Chrome/Edge, a **separate Crawler profile** (0700), controlled over the pipe (no open CDP port). The window is the handoff surface.
- **Docker (test/CI):** headless Chromium (already in the image), `new_context(storage_state=<encrypted per-user blob>, service_workers="block", accept_downloads=False, permissions=[])`, `shm_size: 1g`.
- **Modes:** each task runs in `ACCOUNT` mode (a logged-in site: private data rules apply) or `PUBLIC` mode (a throwaway logged-out context). Mode is derived from whether the origin has a stored session/credential.
- **Limits:** ≤3 sessions and ≤4 tabs per session; idle reaper (10–15 min) that never closes a session waiting on approval or handoff. Sessions are per process (single uvicorn worker).

## 5. Page representation

- `page.aria_snapshot(mode="ai")` → YAML lines like `- button "Submit" [ref=e7]`; frame refs `f1e12`.
- **Filter** (toolkit, before the model sees it): keep interactive roles and named content roles; keep `generic` nodes that carry `[cursor=pointer]` (div-buttons); drop aria-hidden, unnamed wrappers and off-tree noise; **keep screen-reader-only text on ACCOUNT origins** (Canvas puts "Missing"/"Late" there); replace dropped cross-origin frames with one line `[external tool frame: <origin>, not shown]`; redact the values of password / one-time-code / `cc-*` fields and any secret the toolkit typed; keep same-origin paths (`/courses/123/assignments`) but strip query strings and fragments.
- **Size:** default 8k characters (~2–3k tokens, fits Google Flights) with a `truncated` flag and counts; `snapshot(full=true)` up to 24k; `find(text)` returns matching lines **with their row/listitem/article context** (assignment name next to "Missing"); `text(ref)` returns visible text only (no hidden-text side door).
- **What stays in context:** only the latest observation. Every earlier browser result is replaced by a toolkit-written one-liner: `[step 4] click "Grades" → canvas.school.edu/courses/123/grades · 48 refs`. A small **task-facts block** (≤2k chars) carries `note(text)` entries and pinned `find` results across steps so multi-course aggregation works.
- **Images:** `screenshot(...)` returns `user_image` (delivered to Telegram, never to the model) unless `for_model=true`, which also returns `image` (≤768 px). The runtime prunes image blocks from every follow-up except the newest.
- Every observation is untrusted content: it goes through the existing result fence, PromptGuard and the taint gate; **per-line** redaction (one flagged line must not blank the whole page).

## 6. Actions

Three static tools (keeps the offered list small; flat schemas for Gemini):

| Tool | Tier | Actions |
|---|---|---|
| `browser.read` | READ (auto) | `open(url)`, `snapshot(query?, full?)`, `find(text)`, `text(ref?)`, `scroll(dir)`, `back`, `tabs`/`switch(n)`, `wait(text \| ms≤10s)`, `screenshot(ref?, for_model?)`, `note(text)`, `handoff(reason)`, `click(ref)` **only for non-consequential targets** |
| `browser.act` | WRITE (approval) | `type(ref, text)`, `select(ref, value)`, `press(Enter)`, `submit(ref)`, `click(ref)` for consequential targets |
| `browser.login` | WRITE (approval) | `login(site)` — no secret argument; the toolkit fills from the vault |

**Consequential = decided by the toolkit at execution time, from live page facts, not by the model:** the target is a submit control, or sits in a form containing a password/payment field, or its accessible name matches the action list (send, submit, post, pay, buy, order, delete, confirm, sign up, register, subscribe, call, accept, agree, allow, authorize — plus site packs later), or the click would navigate with a non-GET top-level request. A read-tier `click` on such a target is refused with "use browser.act". Financial fields/controls (`cc-*`, IBAN, payment iframes, pay/buy/place-order with payment fields present) are **hard-blocked**. OAuth consent/scope-grant screens for a client not in the site's recorded chain are blocked; the SSO authorize redirects Canvas uses are allowed.

Refs resolve through Playwright's `aria-ref` locator (Playwright pinned to 1.63.x with a contract test); a stale ref returns "stale ref: re-snapshot" within 3 s rather than hanging.

## 7. Vault and login

- **Vault key:** generated once per install and stored in the **macOS Keychain** (`security add-generic-password -s "Crawler AI vault" -a <install-id>`; read with `-w` at use time). It never appears in `.env`, the database, logs, or backups. On Windows: DPAPI/Credential Manager. In Docker/CI: the vault is **disabled** unless `CRAWLER_VAULT_DEV_KEY_FILE` is set (tests only). Consequence: a copied database cannot be decrypted anywhere but the owner's Mac.
- **Store:** `site_credentials` (migration 0010): `label`, `origins[]` (site hosts and the SSO IdP hosts learned from the redirect chain), `username_masked`, `blob` (AES-256-GCM of `{username, password}` under the vault key), `last_used_at`, `failed_attempts`. Entered through the web UI only (Connectors → Site logins); never through chat; no TOTP seeds.
- **`browser.login(site)`** fills only when **all** hold: the top-level origin **and** the input's frame origin match a recorded origin (or an IdP reached by redirect from one); the target is a visible `input[type=password]` or the recorded username field; the form posts to the same origin or the IdP; the page was reached by navigation, not by a link the model typed. Anything else: refuse, Telegram alert "a page on X asked for your Canvas password", audit row. Returns `{ok, site, logged_in_as: "j***@school.edu"}`. Lockout protection: ≤2 attempts per site per hour.
- **Manual mode:** "Sign in in the Crawler window" — the headed window comes to the front, the owner signs in, the session persists in the private profile. A "Forget browser sessions" button wipes the profile. Both modes are offered per site.

## 8. Human handoff (MFA, CAPTCHA, unusual-traffic pages)

- **Detector** (before every action): CAPTCHA frames (reCAPTCHA, hCaptcha, Turnstile, Arkose) that are **visible/blocking**, "verify you are human"/"unusual traffic" pages, IdP MFA pages (Duo, Entra, Okta) and OTP fields, and `bots.html`-style URLs. Plain 403/429 responses are **not** treated as challenges (Canvas uses them for locked content and throttling).
- On detection the tool returns `needs_human` and the **turn ends** (no polling inside a tool call — that would hold the per-chat lock). A masked screenshot and explanation go to Telegram with a **Done** button; the pending state is parked like an approval and resumes through the same mechanism. `/code 123456` on Telegram is intercepted before the model and typed into the OTP field recorded at handoff, on the IdP origin only; codes are never stored in message rows. Push MFA (Duo push, Entra number-match shown in the screenshot) works in both Docker and native; image-grid CAPTCHAs work natively (the owner solves them in the window) and are reported as impossible in Docker.
- The agent never clicks a challenge; there is no solver, stealth flag, user-agent spoofing or proxy. If a site refuses an automation-controlled browser, the agent says so and offers the site's token/API route where one exists.

## 9. Egress and safety

- Every model-supplied URL passes `check_ssrf`; only `http(s)`; no userinfo, `data:`, `blob:`, `javascript:`, `file:`.
- Interim (this project): a `context.route` handler aborts top-level navigations to private/loopback addresses and any non-GET top-level navigation from a read-tier action; XHR/fetch are left alone (SPAs need them). Later: the pinned local egress proxy from the NemoClaw notes, shared with `web.screenshot`.
- **Telegram:** `link_preview_options={"is_disabled": true}` on every agent message (a page could make the reply carry a URL with private data; Telegram's servers fetch previews instantly). In ACCOUNT mode, query strings and fragments are stripped from URLs in the final reply.
- Screenshots: masked (password/OTP/card fields), `user_image` stripped before rows persist; Telegram is not end-to-end encrypted — said once in the wizard.

## 10. Cost controls

- Gemini `thinkingConfig` budget low/off for browser steps (today the call sends none, so thinking is on).
- Per-tool result budget for browser results (8k chars) separate from the 2k default; image pruning as in §5.
- A **task identity** carried across approval/handoff resumes so caps do not reset: ~60 browser actions and ~$0.25 per task → "continue?" on Telegram; loop detector keyed on action+args.
- Escalation: 2.5 Flash first; after two failed attempts on a step, one round on a stronger Flash.

## 11. Docker vs native

| | Docker (test/CI) | Native Mac/Windows |
|---|---|---|
| Browser | headless Chromium in the image | installed Chrome/Edge, headed, private Crawler profile |
| Login | vault + Telegram MFA (push, `/code`) | manual in the window **or** vault |
| CAPTCHA | reported as impossible | owner solves in the window |
| Vault | disabled (dev key file for tests only) | Keychain / DPAPI bound |
| Bot walls | more frequent | fewer |

## 11.1 Platform layer (Mac and Windows are both first-class)

Every OS-specific behaviour goes through one interface, `services/platform/` with `mac.py`, `windows.py` and `linux_container.py` (Docker/CI), chosen at startup. Nothing outside that package may branch on `sys.platform`. Each feature in this spec ships with **both** implementations and both test suites; a feature that only works on one OS is not done.

| Concern | Mac | Windows | Docker/CI |
|---|---|---|---|
| Vault key custody | Keychain (`/usr/bin/security` generic password, per install id) | DPAPI via `CryptProtectData` (ctypes) + Credential Manager entry; user-scoped so the blob is unreadable by other accounts and other machines | disabled; dev key file for tests |
| Browser | installed Chrome, `channel="chrome"`; Chromium fallback | installed Edge, `channel="msedge"` (always present on Windows 10/11); Chrome if installed | headless Chromium |
| Profile dir | `~/Library/Application Support/Crawler AI/browser-profiles/<user>` (0700) | `%LOCALAPPDATA%\Crawler AI\browser-profiles\<user>` (ACL: current user only) | in-memory + encrypted storage_state |
| Window to front on handoff | `osascript` activate / `NSRunningApplication` via pyobjc if present | `SetForegroundWindow` via ctypes (respects UIPI; falls back to flashing the taskbar) | n/a (Telegram screenshot only) |
| Screenshots/masking | same code (Playwright) | same code | same code |
| Permissions probe | Screen Recording etc. (existing `capabilities/screen.py`) | none required for browser; UIPI note for input | container: unavailable |
| Install launcher | `Install Crawler AI.command` | `Install Crawler AI.bat` (+ `.ps1`) | compose |
| Test machine | the owner's Mac | a Windows 11 VM for the team; CI `windows-latest` covers unit tests only (no interactive desktop) | GitHub Actions |

## 12. Delivery order

1. **Read:** session manager, snapshot pipeline, `browser.read`, runtime changes (latest-observation policy, summaries, notes block, result budget, image pruning, thinking cap, task caps), Telegram link-preview fix, egress guard, Canvas playbook lines in the prompt, fake-site test harness. Native on the Mac first; Docker as the CI harness.
2. **Login:** vault (Keychain-bound), `site_credentials` + UI, `browser.login`, manual-login flow, handoff with parked turn and `/code`.
3. **Act:** `browser.act`, consequential detection, approval cards built from page facts, PUBLIC-mode typing (flight search boxes).
4. **Polish:** window-to-front on handoff, "Forget browser sessions", site packs (a good area for contributors).

Each phase includes its Windows implementation and tests (§11.1); phases 1–2 are verified on the Windows VM before phase 3 starts.

## 13. Testing

- Unit: snapshot filter on saved fixtures (a Canvas-like grades page with sr-only "Missing", a Google-Flights-like results page, a page with a hidden injection line), `find` row context, click gate (submit / password form / name list / non-GET nav), consequential detection, vault key binding (blob unreadable without the Keychain key), origin binding (refuse on a look-alike host and inside a cross-origin frame), challenge detector (no false positive on an invisible reCAPTCHA badge or a 403), caps and task identity across a resume, per-line redaction, Telegram preview flag.
- Integration (Docker, CI): a local fake site served by `http.server` — login form, SSO redirect chain, OTP page, blocking CAPTCHA frame, a grades table — driven end to end through the runtime with a fake model.
- Live (native): the owner's school login in the Crawler window (SSO acceptance check first), then the Canvas and Flights reference tasks with cost measured via `usage`.
