# Crawler AI — team backlog (2026-09-24)

What to build next, cut into pieces one person can own. Read `docs/team-handoff-2026-09-23.md` (how to run and add a capability) and `docs/CODE-MAP.md` (where everything is) first.

**How to claim work:** open a GitHub issue titled with the item's ID (e.g. `C2 — cost footer on every reply`), branch from `feat/full-platform-completion` as `feat/<id>-<short-name>`, one PR per item with tests. Every source file keeps its top "What / Why" header. Commit messages are reviewed by Krish. Never commit `.env`, keys, or screenshots of real accounts.

**Rules that apply to everything:** consequential actions (send, buy, sign up, delete, install, type into a form) go through the approval flow; secrets never reach logs, audit rows, error bodies or the model; every feature ships for **Mac and Windows**; cost per task stays in cents (measure with `/usage`).

**Reserved (Krish + agents, in progress):** `browser_control` phase 1–3 (spec: `docs/superpowers/specs/2026-09-24-browser-control-design.md`). Don't start browser tools; do take the tracks below, which the browser work depends on or sits beside.

---

## Track A — Telegram channel (highest value, mostly independent)
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| A1 | **Sender verification**: store the Telegram user id at link time; require `from.id` to match on messages and button callbacks; accept private chats only | `services/notifications/telegram.py` | a message from another account in the same chat is ignored and audited | S |
| A2 | **Shipped.** **`/stop`** on Telegram and the web Stop button (see "A2 as shipped" below the table) | `telegram.py _handle_stop`, `api/routes/agent.py stop_running_task`, `Chat.tsx handleStop`, `services/agent/cancel.py` | done: a long turn stops at its next step (web) or at once (Telegram, once a step already running has finished); the web stop writes `stop_requested` and `turn_stopped` rows. Still open: an audit row for a Telegram `/stop` | S |
| A3 | **Inbound photos, documents and captions** (only `text` is read today) → attachments on the user message; images fed to vision models | `telegram.py _handle_message`, `agent.py build_chat_applier` | a photo sent from the phone reaches the model | S |
| A4 | **Voice notes → text** (Gemini audio or local Whisper), 20 MB cap | `telegram.py`, a `services/tools/transcribe.py` | a voice note becomes a normal turn | M |
| A5 | `/model`, `/budget`, `/usage` polish; stream replies by editing the message every ~1 s | `telegram.py` | visible typing progress on the phone | S |
| A6 | **Shipped.** Mid-turn progress lines ("Taking a screenshot…") from runtime events, for message turns and the turn resumed after an approval | `runtime.py event_sink` → `services/notifications/progress.py` → `telegram.py` | done: progress appears before the final reply | S |

**A2 as shipped.**

- The web Stop button calls `POST /api/agent/stop`, which records a stop for the signed-in user (`services.agent.cancel.request_cancel`) and a `stop_requested` audit row. The runtime checks before every model round and every tool call, and computer control before every desktop action; a tool call that has started is never cut short. The turn then ends with a short "Stopped." reply on the open stream, saved like any other reply, with a `turn_stopped` row and a `user_stopped` row for each step it skipped. If the server has not ended the turn within 10 s, the page cuts its stream.
- Telegram `/stop` (Rafi, #34) records the same stop and also cancels that chat's running tasks (message turns and approval decisions): nothing more is sent for that request, and the reply is "⏹ Stopped. Nothing more will be sent for that request." A tool call already running, or an approval card being stored, still finishes and gets its audit row first (`runtime._RunsToEnd`); a call whose intent row was being written does not start, and gets a `user_stopped` row after it. Stopping the bot (server shutdown, or turning Telegram off) takes no new message first, then waits at most 10 s for such a call. The transcript gets "[Stopped before the reply was finished.]" with the tokens billed so far and the tool calls that ran.
- A stop ends the work accepted before it and nothing later: a new message or an Approve tap takes a fresh mark, so nothing has to lift a stop. A stop from either channel reaches the account's work on both, including a Telegram message still queued behind the chat's running turn (it takes its mark when it arrives).
- Approval cards that are waiting stay approvable after a stop; nothing denies them. Approve runs that one action (the tap came after the stop), and the turn it resumes ends as "Stopped." before its first model call. Telegram's `/stop` reply says so when cards are waiting ("1 action is still waiting for your approval (/pending). Approving it runs that one action; its task stays stopped."), including when nothing was running. An approval already running when `/stop` arrives still finishes its action and records it; only the turn after it is cancelled.
- On Telegram, Approve/Deny is answered at once ("Approving…" / "Denying…") and runs off the poll loop, so `/stop` is received while an approved action or its resumed turn runs.

Still open: a Telegram `/stop` writes no audit row of its own (the web stop's `stop_requested` has no Telegram twin), and the turn it cancels writes no `turn_stopped` row.

## Track B — Cost control (blocks nothing, saves money every day)
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| B1 | **Cost footer on every reply** ("5.3k in · 0.2k out · 2 calls · ≈$0.002"; "cached reply · $0") on Telegram and web | `agent.py`, `services/usage/pricing.py`, `TokenUsage.tsx` | every reply shows it | S |
| B2 | **Daily budget per user** ($1 default, set in the wizard/Settings): warn at 80 %, stop at 100 % | `services/usage/`, `installation.py`, Settings | a capped user gets a clear message, audited | S |
| B3 | Pricing table: Gemini 2.5-flash-lite, 3.x flash ids, price changes by date; usage shows "unpriced" never blank | `services/usage/pricing.py` | `/usage` prices every model in `Settings.tsx` | S |
| B4 | Replay cache key includes the model (today a model switch can return the old model's answer within 2 min) | `services/agent/context_manager.py` | test proves it | S |
| B5 | Loop detector on by default (hash of tool+args, 3 repeats → refuse) — coordinate with Krish, the browser work adds per-task caps | `runtime.py` | test | S |
| B6 | Route tool-selection rounds to Flash-Lite, escalate to Flash for vision and the final answer | `runtime.py`, `providers.py` | measured token drop on the flight task | M |

## Track C — Connectors and skills (what makes it "do anything")
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| C1 | **Built on `feat/connectors`, live check still open.** **Google OAuth consent flow** (the redirect route was missing, so Google Workspace died after about 1 h). Shared OAuth broker: "Sign in with Google" (PKCE, single-use hashed state, fixed redirect URI), tokens refreshed 120 s before expiry and saved, grant revoked at Google when the connector is deleted, Reconnect and "Grant more access" on the card. Google also gained Drive, Docs, Sheets and Contacts | `services/connectors/oauth.py`, `oauth_config.py`, `google_workspace.py` + `google_api/`, `api/routes/oauth.py`, `Connectors.tsx`; owner setup in `docs/connectors-setup.md` | code and tests done. Still open: set `GOOGLE_OAUTH_CLIENT_ID`/`GOOGLE_OAUTH_CLIENT_SECRET` and confirm Gmail/Calendar stay connected for a week (a Google app left in "Testing" issues refresh tokens that expire after 7 days) | M |
| C2 | **Canvas assignments copilot** on the token connector: `canvas.get_assignments`, missing/late detection, due-this-week summary; prompt playbook | `services/connectors/canvas.py`, `tool_registry.py` catalog | "what's due this week" answers correctly against a real Canvas token | M |
| C3 | **Built on `feat/connectors`, live check still open.** **Microsoft 365 / Outlook** connector (Graph OAuth) for Windows-first users: Outlook mail and calendar, OneDrive files, To Do and contacts (34 actions). Browser sign-in or device code, public client (no secret), work, school and personal accounts | `services/connectors/microsoft.py` + `microsoft_api/` | code and tests done: reads mail and events; send, reply, forward, share links and every delete always ask for approval. Still open: register the app (`MICROSOFT_OAUTH_CLIENT_ID`, see `docs/connectors-setup.md`) and try it against a real mailbox | M |
| C4 | **MCP stdio transport** (+ localhost exception for user-registered servers) so any MCP server can be plugged in | `services/mcp/client.py`, `core/network_security.py` | Playwright MCP runs as a subprocess and its tools are offered, approval-gated | M |
| C5 | **SKILL.md loader**: name+description injected, body on demand, scripts only via approval, no marketplace auto-install | new `services/skills/` | a local skill folder changes agent behaviour | M |
| C6 | Search fallback (Brave/Tavily/SearXNG) + detect DuckDuckGo's anti-bot page (returns 0 results silently today) | `services/tools/web.py` | test with a captured anti-bot page | S |
| C7 | **Built on `feat/connectors`, live check still open.** **GitHub** (41 actions: repos, files, issues, pull requests, Actions runs and failed logs, releases; device-flow sign-in or a fine-grained token), **Notion** (15 actions: search, pages, databases, comments; internal integration secret) and **Slack** (17 workspace actions plus the Slack DM chat and approvals channel over Socket Mode, linked with a one-time code on the card) | `services/connectors/github.py` + `github_api/`, `notion.py` + `notion_api/`, `slack.py` + `slack_api/`, `services/notifications/slack.py`, `slack_manager.py`, `api/routes/slack.py` | code and tests done. Still open: register the GitHub OAuth app (`GITHUB_OAUTH_CLIENT_ID`, see `docs/connectors-setup.md`) and try each against a real account and workspace, including an approval from a Slack DM | M |
| C8 | **Deferred from the connectors spec (4.3, 6, 10).** OAuth client id and secret overrides in Settings ▸ Server: resolve `.env`, then an encrypted Installation column, then empty, like the Telegram token. Today `oauth_config.resolve_client` reads `.env` only (owner decision: the Settings UI collides with the purchases work) | `services/connectors/oauth_config.py`, `models/installation.py` + migration, `services/installation.py`, `Settings.tsx` | the owner sets or clears a client id without a restart; the secret is stored encrypted and never returned by the API | M |
| C9 | **Deferred from the connectors spec (6).** Slack DM channel status in Settings ▸ Server next to Telegram: running or not, and which accounts are linked. Today only the `slack` capability's availability shows it | `Settings.tsx`, a small status route beside `api/routes/slack.py` | the owner sees whether Slack DMs run without opening a connector card | S |
| C10 | **Deferred from the connectors spec (4.3).** Device-code relay on Telegram: when a GitHub or Microsoft device sign-in starts, the bot can send the code and link to the user's linked chat | `services/notifications/telegram.py`, `services/connectors/oauth.py` | a device sign-in can be finished from the phone; the code is never logged | S |
| C11 | **Built on `feat/connectors`.** "Needs reconnect" badge on a connector card: when the provider refuses a sign-in row's refresh token, the OAuth broker stores a `needs_reconnect` flag in the row's encrypted credentials, the connector list returns it, and the card shows an amber badge with a Reconnect button. A reconnect, a pasted token or a later successful refresh clears it | `services/connectors/oauth.py`, `api/routes/connectors.py`, `Connectors.tsx` | a revoked Google or Microsoft grant shows the badge and the Reconnect button (live check still open) | S |

## Track D — Scheduling and automations
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| D1 | **Recurring reminders** (croniter/APScheduler); `agent_turn` payload runs a task on schedule with its own budget (off by default) | `models/reminder.py`, `services/notifications/reminders.py`, `services/tools/reminders.py` | "every weekday at 8am summarise Canvas" runs | M |
| D2 | **Reminders / automations page** in the web UI (API exists, no frontend) | `frontend/src/pages/Reminders.tsx`, Sidebar | list, create, cancel | S |
| D3 | Inbound webhook with a bearer token; payload treated as untrusted | `api/routes/webhooks.py` | a webhook can start a turn, audited | S |

## Track E — Frontend and design
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| E1 | **Brand artwork**: logo, emblem, wordmark for "Crawler AI" (light + dark), replacing the 4 old files | `frontend/public/brand/`, `Brand.tsx` (drop the interim text wordmark) | login and sidebar show the new mark | M |
| E2 | **Shipped.** **Screenshots inline in web chat**: the send response and the stream's `done` event carry the turn's screenshots as `images` (base64 PNG/JPEG/WebP data URLs only, at most 3, never saved) and keep them on screen through an approval's refetch; a reloaded thread shows "Screenshot not kept — ask again to see it", a 4th screenshot in one reply "not shown (limit of 3 per reply)" | `api/routes/agent.py _turn_images`, `Chat.tsx ToolCallBadge`, `components/ToolScreenshot.tsx` | done: tool images render as images. Still open: the turn resumed after a web approval shows no screenshot until asked again | S |
| E3 | **Shipped.** Login page: hide "Create one" when registration is closed; show the setup-in-progress hint | `Login.tsx` (reads `registration_open` from `GET /setup/status`) | done: no 403 dead ends; a register refused with 403 asks the status again and shows the matching hint (new accounts off, or finish setup) | S |
| E4 | Mobile pass on the wizard, Permissions and Settings ▸ Server (375 px) | those pages | no horizontal scroll, 44 px targets | S |
| E5 | "Promote to owner" (second admin) in Settings, so the last-owner guard has a path | `api/routes/auth.py`, Settings | audited, tested | S |

## Track F — Security hardening (self-contained items; the big ones are with Krish)
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| F1 | **Panic action**: revoke connector tokens, pause all tools, stop the poller; Telegram `/panic` and a Settings button | `api/routes/`, `telegram.py` | one tap stops everything, audited | S |
| F2 | **Taint check on every `web.*` call** (URL host/path/query and the search query), allowing values from the user's own message | `runtime.py` taint gate | regression test with the flight URL | M |
| F3 | **Mostly done on `feat/connectors`.** **Approval cards never truncate** recipients/URLs/paths; show a hash of the exact arguments. Telegram and Slack cards now show every argument in full, split into labelled parts sent about one per second (buttons on the last part), and end with `Arguments digest: <16 hex>` (sha256 of the canonical arguments). A card that would need more than 8 messages is replaced by a notice pointing to the web app, with no buttons | `services/notifications/cards.py`, `telegram.py` approval card, Slack card in `services/notifications/slack.py` | tests in `test_notification_cards.py`. Still open, after `feat/purchases` merges: move Telegram's private card helpers (`_card_arguments`, `_usage_line`, `_with_turn_notes`, `_expires_in_text`, `_chunks`) into `cards.py` and drop the unused `_short_json`; show the digest on the web approval card too (`Chat.tsx`, Dashboard) | S |
| F4 | **Partly done on `feat/connectors`.** Irreversible-action policy: delete, new recipient, shell side effects never auto-approved. Registry connectors must mark every DELETE `always_confirm` (validated at import), and every send, reply, forward, post, comment, review, merge, publish, share, workflow dispatch and run cancel is marked too. `always_confirm` is enforced at three layers (offer, permission adapter, executor), and an `auto_approve` connector tier never lifts it. The gmail, google_calendar and github DELETE rows moved from `admin_only` to `user_confirm` so the card can appear | `services/connectors/registry.py`, `services/agent/tool_registry.py`, `services/agent/permissions.py` | tests in `test_connector_registry.py`, `test_tool_registry.py`. Still open: it is a per-action flag, not a general rule in `permissions.py`; no separate "new recipient" check (sends are covered only because every send asks), and nothing for shell side effects | S |
| F5 | Host header allowlist + Origin check on SSE and state-changing requests | `api/middleware/security.py` | tests | S |
| F6 | **Shared secret detector** (NemoClaw regex set + entropy) on memory writes, audit sanitiser, outbound Telegram text, write-tool args; fails closed | `services/security/secrets.py` (new) | a pasted key never lands in memory or Telegram | M |
| F7 | Refuse an Ollama endpoint that listens on a non-loopback address | `core/config.py` startup check | test | S |
| F8 | JWT out of localStorage into an HttpOnly SameSite=Strict cookie | `api/routes/auth.py`, `api.ts` | login/refresh/logout still work | M |

## Track G — Native install (coordinate with Krish; the installer already exists for Docker)
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| G1 | **SQLite by default** natively: `aiosqlite` in `requirements.txt`, WAL/busy_timeout, re-verify single-use approvals and audit seq without `FOR UPDATE` | `core/database.py`, `services/audit.py`, `services/agent/approvals.py` | full suite green on SQLite with a concurrency test | M |
| G2 | **Config from a per-user directory** (`CRAWLER_HOME` / platformdirs) instead of a `.env` in the working directory; auto-generate SECRET_KEY / ENCRYPTION_KEY / AUDIT_HMAC_KEY on first run | `core/config.py` | boots from any cwd with no `.env` | M |
| G3 | **Serve the built SPA from FastAPI** (SPA fallback) so users don't need Node | `main.py`, `frontend` build output | `http://127.0.0.1:8000/` serves the app | S |
| G4 | Package restructure (`[project]` table, `crawler` CLI, `crawler-gateway` no-console script), wheel build in CI | `backend/pyproject.toml`, CI | `uv tool install crawler-ai` works | L |
| G5 | Background service: LaunchAgent (Mac) / Scheduled Task (Windows) via `crawler service install`; `crawler doctor` | new `crawler/cli.py` | survives reboot; doctor reports keys, DB, browser, Telegram 409 | M |
| G6 | `/api/ready` (provider configured, poller state, browser installed, service status) used by the installer and doctor | `api/routes/health.py` | installer's "Backend loaded" uses it | S |

## Track H — Testing and CI
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| H1 | Fix the flaky auth-rate-limit collision in tests (random IP pool of 254) | `tests/conftest.py` | 10 consecutive green runs | S |
| H2 | macOS and Windows CI jobs: SQLite boot test + Playwright screenshot smoke; Windows VM for desktop checks | `.github/workflows/ci.yml` | both jobs green | M |
| H3 | Slim the images (3.6 GB, 1.03 GB Playwright layer); publish prebuilt images to GHCR so Build is a pull | `docker/`, CI | first install under 5 minutes | M |
| H4 | Adversarial test suite (AgentDojo-style) with a regression test per known incident class | `tests/adversarial/` | runs in CI | M |

---

### Suggested first picks (one per person, all independent)
1. **A1 + A2** — Telegram sender check and `/stop` (safety, small, very visible).
2. **B1 + B2** — cost footer and daily budget (the thing everyone will look at).
3. **C1** — Google OAuth fix (an existing connector that currently dies in an hour).
4. **E1** — brand artwork (design, no code conflicts).
5. **G1 + G3** — SQLite default and serving the SPA (the two prerequisites for the native installer).
