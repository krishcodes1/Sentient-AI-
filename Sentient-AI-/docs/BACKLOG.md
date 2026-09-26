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
| C1 | **Google OAuth consent flow** — the redirect route is missing, so Google Workspace dies after ~1 h | `services/connectors/google_workspace.py`, new `api/routes/oauth.py`, Connectors UI | Gmail/Calendar stay connected for a week | M |
| C2 | **Shipped.** **Canvas assignments copilot** on the token connector: `canvas.get_upcoming` (due in the next N days plus missing/late work, every course in one call) and `canvas.grade_whatif`, with their prompt lines (see "C2 and C6 as shipped" below the table) | `services/connectors/canvas.py`, `canvas_upcoming.py`, `canvas_grades.py`, `tool_registry.py` catalog | done against a fake Canvas in tests. Still open: the "what's due this week" acceptance run against a real Canvas token | M |
| C3 | **Microsoft 365 / Outlook** mail + calendar connector (Graph OAuth) for Windows-first users | new `services/connectors/microsoft.py` | read mail and events; send needs approval | M |
| C4 | **MCP stdio transport** (+ localhost exception for user-registered servers) so any MCP server can be plugged in | `services/mcp/client.py`, `core/network_security.py` | Playwright MCP runs as a subprocess and its tools are offered, approval-gated | M |
| C5 | **SKILL.md loader**: name+description injected, body on demand, scripts only via approval, no marketplace auto-install | new `services/skills/` | a local skill folder changes agent behaviour | M |
| C6 | Search fallback (Brave/Tavily/SearXNG) + detect DuckDuckGo's anti-bot page. **Detection shipped** (see below); the fallback is still open | `services/tools/web.py` | test with a captured anti-bot page (detection: `tests/test_web_tools.py`) | S |

**C2 and C6 as shipped (2026-09-25).**

- `canvas.get_upcoming` (scope `assignments.read`): everything due in the next N days (default 7, at most 30) across every active course, plus missing and late work, in one call; rows are shaped in `canvas_upcoming.py`. The prompt routes "what is due, missing or late" to it only when it is offered; without a Canvas connector the browser playbook's route (the planner, `find('Missing')`) applies.
- `canvas.grade_whatif` (scope `grades.read`, READ, nothing is sent to Canvas): Canvas's own grade math in `canvas_grades.py` (group weights, drop rules, excused work), what-if scores and the score needed for a target. The prompt forbids the model's own grade arithmetic while the tool is offered.
- C6, detection half: when DuckDuckGo answers with HTTP 202 or its challenge page and no results, `web.search` returns an error with `search_blocked: true` instead of 0 results, and `web.research` reports the same instead of "no sources". The error tells the model "do not retry or rephrase"; when the fallback lands, change that text, and `web.research` inherits the fallback through `web.search`.

**Also shipped 2026-09-25 (no backlog item).**

- `web.research` (capability `web_browsing`, READ, runs unattended): one search, then a parallel read of the top sources (5 by default, at most 8), cited by URL.
- `web.fetch_page` returns at most 12000 characters of page text, and its result budget (`RESULT_CHAR_BUDGETS`, 16000 with the URL, title and keys) lets a full fetch reach the model whole instead of a 2000-character head and tail.
- `memory.remember` (capability `save_memories`, on by default): saves one fact the user stated about themselves, always through the approval card showing the exact text; refuses secrets (`services/tools/memory.py:looks_like_secret`), duplicates, and memory that is switched off or full.
- Page watch: `watch.create`/`list`/`delete` (capability `page_watch`, off by default, available only while Telegram can deliver the alerts). Create and delete go through the approval card; the sweeper (`services/notifications/page_watch.py`, wired in `main.py` next to `ReminderService`) checks each page on its interval with leased claims, a guarded fetch and error backoff, and messages the owner on Telegram when the text changes. Migration `0011_page_watches` (it keeps revising 0009; see its docstring for the merge with `0010_vault_items`).
- The offered-tool array holds 20 tools (was 15), shared round-robin across families; a family's order comes from `TOOL_PRIORITY`, and the undo tools of an offered reminder or page-watch create, then every granted connector write, take the slots of later picks (a write only a tool that repeats an offered one), so with every switch on some writes still stay out (`context_manager.select_offered_tools`; `tests/test_offered_tools.py` pins what the largest configurations drop). The connectors spec §4.5 (`tools.find`, `loaded_tools`, `ToolSpec.starter`) is expected to replace the hand tables.

## Track D — Scheduling and automations
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| D1 | **Recurring reminders** (croniter/APScheduler); `agent_turn` payload runs a task on schedule with its own budget (off by default). Page watch already is a narrow, model-free scheduled job: build on its sweeper's design (leased claims, backoff, the capability switch re-read every sweep) rather than add a second scheduler | `models/reminder.py`, `services/notifications/reminders.py`, `services/tools/reminders.py`, `services/notifications/page_watch.py` | "every weekday at 8am summarise Canvas" runs | M |
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
| F2 | **Taint check on every `web.*` call** (URL host/path/query and the search query, including `web.research`'s query, which is sent to DuckDuckGo unattended and whose results pick up to 8 pages it then reads), allowing values from the user's own message | `runtime.py` taint gate | regression test with the flight URL | M |
| F3 | **Approval cards never truncate** recipients/URLs/paths; show a hash of the exact arguments | `telegram.py` card builder | test | S |
| F4 | Irreversible-action policy: delete, new recipient, shell side effects never auto-approved | `services/agent/permissions.py` | tests per rule | S |
| F5 | Host header allowlist + Origin check on SSE and state-changing requests | `api/middleware/security.py` | tests | S |
| F6 | **Shared secret detector** (NemoClaw regex set + entropy) on memory writes, audit sanitiser, outbound Telegram text, write-tool args; fails closed. `memory.remember` already refuses secrets with its own `services/tools/memory.py:looks_like_secret` (audit's patterns plus `_SECRET_RE`); move both into the shared module, together with the token formats the connectors spec (§4.3, Redaction) adds to `audit.py`, so each format lands once | `services/security/secrets.py` (new) | a pasted key never lands in memory or Telegram | M |
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
