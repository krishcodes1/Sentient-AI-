# Crawler AI — team backlog (2026-09-24)

What to build next, cut into pieces one person can own. Read `docs/team-handoff-2026-09-23.md` (how to run and add a capability) and `docs/CODE-MAP.md` (where everything is) first.

**How to claim work:** open a GitHub issue titled with the item's ID (e.g. `C2 — cost footer on every reply`), branch from `feat/full-platform-completion` as `feat/<id>-<short-name>`, one PR per item with tests. Every source file keeps its top "What / Why" header. Commit messages are reviewed by Krish. Never commit `.env`, keys, or screenshots of real accounts.

**Rules that apply to everything:** consequential actions (send, buy, sign up, delete, install, type into a form) go through the approval flow; secrets never reach logs, audit rows, error bodies or the model; every feature ships for **Mac and Windows**; cost per task stays in cents (measure with `/usage`).

**Reserved (Krish + agents, in progress):** `browser_control` phase 1–3 (spec: `docs/superpowers/specs/2026-09-24-browser-control-design.md`). Don't start browser tools; do take the tracks below, which the browser work depends on or sits beside.

**Shipped 2026-09-25: `purchases`** (spec: `docs/superpowers/specs/2026-09-25-purchases-design.md`). Buying is a switch the owner turns on ("Buy things for me", off by default) with two caps (per purchase $25, per day $50, editable in Permissions). The card is entered once in Settings → Payment card and sealed under a key only the OS holds (Keychain through `security -i` on stdin, never argv; DPAPI on Windows; minted when the first card is stored; a container has no vault and says so instead of showing the form). `browser.act` (fill, select, check, click, press, submit; one card per call, shown as one plain sentence; never into a password or card field, never on `http://`, never an order button, a form holding a card, a POST to an order path or a button on a review page with a payment method on file) gets the model to the checkout page; `browser.checkout` reads the total, the items and the card fields off the page itself, refuses `http://`, the wrong or a look-alike merchant, an ambiguous total, a submit target off the page's origin, a foreign currency, a missing card form and anything over the caps before any card exists (the per-day cap counts every submitted card, confirmed or not), then shows one approval card with the amount, the merchant, the items, a masked screenshot and "Crawler can make mistakes. Check the amount and the site before you approve." Approve fills the card from the vault at that moment and only while the page is still the one on the card; the confirmation screenshot reaches the owner in the web chat and on Telegram, the model offers a reminder, and a checkout that stops after the fill clears the card fields before answering. The number never reaches the model, chat, an event, an audit row or a log line (`tests/test_purchase_flow.py` holds the whole chain to that; `tests/test_purchase_card_text.py` that a normal purchase card carries no security jargon). The prompt learns about checkout only when the tool is offered; with buying off a request differs from before the feature only by the `<permissions>` line for the new switch and, under Control a browser, the `browser.act` tool. Telegram gets the card as a photo with the same caption. Still open: `browser.login` from the vault's `login` records (spec §7), non-USD checkouts (refused today), saved addresses (the model fills them through `browser.act` from what the person says), more than one stored card, a Telegram photo card after a server restart (the picture lives in memory; the text card stands in).

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
| C2 | **Shipped.** **Canvas assignments copilot** on the token connector: `canvas.get_upcoming` (due in the next N days plus missing/late work, every course in one call) and `canvas.grade_whatif`, with their prompt lines (see "C2 and C6 as shipped" below the table) | `services/connectors/canvas.py`, `canvas_upcoming.py`, `canvas_grades.py`, `ACTIONS` in `canvas.py` | done against a fake Canvas in tests. Still open: the "what's due this week" acceptance run against a real Canvas token | M |
| C3 | **Built on `feat/connectors`, live check still open.** **Microsoft 365 / Outlook** connector (Graph OAuth) for Windows-first users: Outlook mail and calendar, OneDrive files, To Do and contacts (34 actions). Browser sign-in or device code, public client (no secret), work, school and personal accounts | `services/connectors/microsoft.py` + `microsoft_api/` | code and tests done: reads mail and events; send, reply, forward, share links and every delete always ask for approval. Still open: register the app (`MICROSOFT_OAUTH_CLIENT_ID`, see `docs/connectors-setup.md`) and try it against a real mailbox | M |
| C4 | **MCP stdio transport** (+ localhost exception for user-registered servers) so any MCP server can be plugged in | `services/mcp/client.py`, `core/network_security.py` | Playwright MCP runs as a subprocess and its tools are offered, approval-gated | M |
| C5 | **SKILL.md loader**: name+description injected, body on demand, scripts only via approval, no marketplace auto-install | new `services/skills/` | a local skill folder changes agent behaviour | M |
| C6 | Search fallback (Brave/Tavily/SearXNG) + detect DuckDuckGo's anti-bot page. **Detection shipped, with a fallback to Crawler's own browser** (see below); a second search engine is still open | `services/tools/web.py` | test with a captured anti-bot page (`tests/test_web_tools.py`) | S |
| C7 | **Built on `feat/connectors`, live check still open.** **GitHub** (41 actions: repos, files, issues, pull requests, Actions runs and failed logs, releases; device-flow sign-in or a fine-grained token), **Notion** (15 actions: search, pages, databases, comments; internal integration secret) and **Slack** (17 workspace actions plus the Slack DM chat and approvals channel over Socket Mode, linked with a one-time code on the card) | `services/connectors/github.py` + `github_api/`, `notion.py` + `notion_api/`, `slack.py` + `slack_api/`, `services/notifications/slack.py`, `slack_manager.py`, `api/routes/slack.py` | code and tests done. Still open: register the GitHub OAuth app (`GITHUB_OAUTH_CLIENT_ID`, see `docs/connectors-setup.md`) and try each against a real account and workspace, including an approval from a Slack DM | M |
| C8 | **Deferred from the connectors spec (4.3, 6, 10).** OAuth client id and secret overrides in Settings ▸ Server: resolve `.env`, then an encrypted Installation column, then empty, like the Telegram token. Today `oauth_config.resolve_client` reads `.env` only (owner decision: the Settings UI collides with the purchases work) | `services/connectors/oauth_config.py`, `models/installation.py` + migration, `services/installation.py`, `Settings.tsx` | the owner sets or clears a client id without a restart; the secret is stored encrypted and never returned by the API | M |
| C9 | **Deferred from the connectors spec (6).** Slack DM channel status in Settings ▸ Server next to Telegram: running or not, and which accounts are linked. Today only the `slack` capability's availability shows it | `Settings.tsx`, a small status route beside `api/routes/slack.py` | the owner sees whether Slack DMs run without opening a connector card | S |
| C10 | **Deferred from the connectors spec (4.3).** Device-code relay on Telegram: when a GitHub or Microsoft device sign-in starts, the bot can send the code and link to the user's linked chat | `services/notifications/telegram.py`, `services/connectors/oauth.py` | a device sign-in can be finished from the phone; the code is never logged | S |
| C11 | **Built on `feat/connectors`.** "Needs reconnect" badge on a connector card: when the provider refuses a sign-in row's refresh token, the OAuth broker stores a `needs_reconnect` flag in the row's encrypted credentials, the connector list returns it, and the card shows an amber badge with a Reconnect button. A reconnect, a pasted token or a later successful refresh clears it | `services/connectors/oauth.py`, `api/routes/connectors.py`, `Connectors.tsx` | a revoked Google or Microsoft grant shows the badge and the Reconnect button (live check still open) | S |

**C2 and C6 as shipped (2026-09-25).**

- `canvas.get_upcoming` (scope `assignments.read`): everything due in the next N days (default 7, at most 30) across every active course, plus missing and late work, in one call; rows are shaped in `canvas_upcoming.py`. The prompt routes "what is due, missing or late" to it only when it is offered; without a Canvas connector the browser playbook's route (the planner, `find('Missing')`) applies.
- `canvas.grade_whatif` (scope `grades.read`, READ, nothing is sent to Canvas): Canvas's own grade math in `canvas_grades.py` (group weights, drop rules, excused work), what-if scores and the score needed for a target. The prompt forbids the model's own grade arithmetic while the tool is offered.
- C6: when DuckDuckGo answers with anything but a results page (a status other than 200, or its challenge page), `web.search` runs the query in Crawler's own browser while "Control a browser" is on, and otherwise answers `blocked: true` with a hint instead of 0 results. `web.research` runs the same search, so it reads the sources the fallback found, or reports the same `blocked` answer instead of "no sources".

**Also shipped 2026-09-25 (no backlog item).**

- `web.research` (capability `web_browsing`, READ, runs unattended): one search, then a parallel read of the top sources (5 by default, at most 8), cited by URL.
- `web.fetch_page` returns at most 12000 characters of page text, and its result budget (`RESULT_CHAR_BUDGETS`, 16000 with the URL, title and keys) lets a full fetch reach the model whole instead of a 2000-character head and tail.
- `memory.remember` (capability `save_memories`, on by default): saves one fact the user stated about themselves, always through the approval card showing the exact text; refuses secrets (`services/tools/memory.py:looks_like_secret`), duplicates, and memory that is switched off or full.
- Page watch: `watch.create`/`list`/`delete` (capability `page_watch`, off by default, available only while Telegram can deliver the alerts). Create and delete go through the approval card; the sweeper (`services/notifications/page_watch.py`, wired in `main.py` next to `ReminderService`) checks each page on its interval with leased claims, a guarded fetch and error backoff, and messages the owner on Telegram when the text changes. Migration `0011_page_watches` (on 0009), joined with the connectors line by `0015_merge_page_watches`.
- The offered-tool array (`context_manager.select_offered_tools`, 24 tools, with `tools.find` for the rest) never offers a reminder or page-watch create without the tools that list and undo what it makes (`UNDO_COMPANIONS`); `memory.remember` and the page-watch tools are built-in starters, and `canvas.get_upcoming` is a Canvas starter.
- When the starters do not all fit, each skill's entry point (`tool_registry.LEAD_STARTER_TOOLS`: the tool its prompt playbook names, e.g. `knowledge.search`, `schedule.create`, `video.transcript`, `desktop.observe`/`desktop.act`) and each connected account's first starter go first; second tools (`schedule.briefing`, `study.review`, extra reads, `web.screenshot`, the installer) give way (`tests/test_offered_tools.py`).

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
| F3 | **Mostly done on `feat/connectors`.** **Approval cards never truncate** recipients/URLs/paths; show a hash of the exact arguments. Telegram and Slack cards now show every argument in full, split into labelled parts sent about one per second (buttons on the last part), and end with `Arguments digest: <16 hex>` (sha256 of the canonical arguments). A card that would need more than 8 messages is replaced by a notice pointing to the web app, with no buttons | `services/notifications/cards.py`, `telegram.py` approval card, Slack card in `services/notifications/slack.py` | tests in `test_notification_cards.py`. Still open, after `feat/purchases` merges: move Telegram's private card helpers (`_card_arguments`, `_usage_line`, `_with_turn_notes`, `_expires_in_text`, `_chunks`) into `cards.py` and drop the unused `_short_json`; show the digest on the web approval card too (`Chat.tsx`, Dashboard) | S |
| F4 | **Partly done on `feat/connectors`.** Irreversible-action policy: delete, new recipient, shell side effects never auto-approved. Registry connectors must mark every DELETE `always_confirm` (validated at import), and every send, reply, forward, post, comment, review, merge, publish, share, workflow dispatch and run cancel is marked too. `always_confirm` is enforced at three layers (offer, permission adapter, executor), and an `auto_approve` connector tier never lifts it. The gmail, google_calendar and github DELETE rows moved from `admin_only` to `user_confirm` so the card can appear | `services/connectors/registry.py`, `services/agent/tool_registry.py`, `services/agent/permissions.py` | tests in `test_connector_registry.py`, `test_tool_registry.py`. Still open: it is a per-action flag, not a general rule in `permissions.py`; no separate "new recipient" check (sends are covered only because every send asks), and nothing for shell side effects | S |
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

<!-- top10:secret_pii_redaction -->
**F6 shipped (top-10 `secret_pii_redaction`).** One detector and policy table in
`backend/services/security/` (`secrets.py` holds every format audit.py and
memory.py knew plus provider keys, bot and Canvas tokens, PEM keys, an entropy
check on `KEY=value`, cards with Luhn and issuer prefix, IBAN, SSN/ITIN, stated
passport and licence numbers, and contact details). Memory writes (the tool and
`POST`/`PATCH /api/memories`, now 422) are refused; audit rows and logs are
masked; Telegram and Slack text and cards are masked (the card digest still
hashes the real arguments); every tool call carrying a key, card, bank or ID
number is refused (`secret_guard`); and a floor that cannot be switched off
masks those in every model request. The owner switch "Hide personal details
from the AI provider" (`hide_personal_details`, on by default) sends contact
details to cloud providers as `[[EMAIL_1@uni.edu]]`-style placeholders that are
restored in replies and approved actions. Design:
`docs/superpowers/specs/2026-09-30-secret-pii-redaction-design.md`.

<!-- top10:file_extraction -->
### File extraction (top10) status and follow-ups

- **A3 — done** (documents, captions and photos): Telegram documents and photos reach the agent (`telegram.py` media routes, `build_chat_applier` `files=` / `images=`); Slack DM `file_share` too. Web chat uploads PDF, Word, PowerPoint, Excel, CSV, text, Markdown, HTML and JSON files; connectors and `web.fetch_page` read PDF and Office files as sections.
- **Deferred to a follow-up PR (phase 4, as the plan allowed):** local OCR of scanned pages (`local_ocr` ALLOWLIST entry, Windows.Media.Ocr / Apple Vision in the worker, `ReportContext.local_ocr_installed`), the `scan_vision` capability with `files.view_page` and `VISION_ONLY_TOOLS`, and the `user_file_pages` table. Until then scanned pages are reported as unread (`scanned_pages_unread`) and the model is told never to guess them. `Installable.native_only` / `platforms` already exist for that entry.
- Follow-ups: a Files page in Settings (list / forget uploads); ODF (.odt/.ods/.odp) and RTF/EPUB readers; watching PDFs with page watch; a per-model vision flag for Ollama; local OCR of screenshots so PromptGuard can scan pixel text; live checks against a real Canvas (verifier URL, InstFS/S3 redirect hosts) and Slack `files:read` on existing apps.
- `canvas.list_files` is not a starter tool: Canvas already declares the registry's maximum of four; the model reaches it with `tools.find`.

<!-- top10:scheduler_briefing -->
### D1 status: scheduled tasks and the daily briefing (top10 `scheduler_briefing`)

**Done, with one deliberate deviation from the D1 row above (an owner decision).** D1 asked
for an `agent_turn` payload on the reminders table driven by croniter/APScheduler. It ships
instead as a separate `scheduled_tasks` table (migration `0017_scheduled_tasks`) with
standard-library recurrence (`services/scheduler/recurrence.py`, zoneinfo only) on one shared
poll loop (`services/notifications/sweeper.py` `SweepLoop`, which page watch now uses too).
There is no croniter, no APScheduler and no second scheduler engine. Reminders keep their
one-shot claim; a daily run needs a budget, a history (`automation_runs`), pausing and an error
count, which do not fit that row. Plain recurring reminders are a small follow-up that reuses
`recurrence.py`.

- The owner turns on "Scheduled tasks and daily briefing" (`scheduled_tasks`, off by default).
  `schedule.create` / `schedule.briefing` / `schedule.pause` / `schedule.delete` are always
  approval cards; `schedule.list` is a read.
- Runs are unattended agent turns under a fence (`services/agent/unattended.py`,
  `services/automation/`): only the listed reads run, listed writes only park a 180-minute
  card whose approval runs that one call and resumes no turn, everything else is refused,
  web reads steered by tool results are refused, and each run and each day has a budget
  (5 cents a run, 25 cents a day, 24 runs a day by default; the owner changes them under the
  switch in Settings → Permissions). A run never counts against its own budget, and the wait
  for one of the shared runner's two slots is not part of a run's deadline: a scheduled run
  waits up to 5 minutes (else it is skipped as `skipped_busy`, not a failure), a trigger run
  20 seconds (else its events go back to the queue).
- A nudge whose switch is off moves on to its next time (never made up later), and one whose
  renderer is gone is stopped, so neither crowds the due tasks out of the sweeper's scan.
- The briefing is built from direct reads (Canvas, calendar, optionally mail sender and
  subject only, a news topic) with an optional three-line overview (off by default).
- Results go to the owner's linked Telegram chat and Slack DM and to a web conversation
  "Scheduled: <label>". Telegram: `/schedules`, `/briefing`, `/timezone`; Slack: the same
  words. REST: `/api/schedules` (what the D2 page will use).
- "Every weekday at 8am summarise Canvas" runs: that is D1's done-when.

<!-- top10:tutor_mode -->

**C12 — Tutor mode (top-10 #4, research item 109). Shipped on the top10 branch.** A per-conversation Socratic mode: the chat guides with questions and escalating hints, checks the student's steps and never hands over a final answer, full solution, finished code or finished essay for schoolwork, while logistics (due dates, grades, planning) stay normal.

- Switching: `/tutor on|off|status` on the web and Telegram, bare `tutor on|off|status` in a Slack DM (never a model call), `PUT /api/agent/conversations/{id}/tutor`, or the model's runtime built-in `tutor.start` (it can only turn the mode on; there is no `tutor.stop`).
- Owner locks (`tutor_locks`, Settings ▸ Permissions ▸ Tutor locks, owner only): a Canvas course (id, code, name, aliases) or a whole account, for one account or every account. A course lock engages in a chat, permanently, when the person's message names the course, a Canvas call's `course_id` is the course, or a page URL has `/courses/<id>/`. Nobody lifts a lock from a chat, a channel or a tool.
- While on: the fixed `<tutor_mode>` block ends the system message (no owner or Canvas text in it); `canvas.submit_assignment` is withheld at offer, dispatch (`tutor_mode` policy) and approval; `browser.act` is refused before its card on Canvas quiz, assignment and discussion pages (`tutor_rule` / `graded_work_page`). Reads are never restricted.
- One capability, `tutor_mode` (on by default, low risk); off means no offer, no block, nothing withheld and every lock dormant.
- Code: `services/tutor/`, `api/routes/tutor.py`, `components/TutorLocks.tsx`; migration `0019_tutor_mode`.
- Unattended runs: scheduled and trigger runs carry their conversation's tutor state (`services/automation/turns.py` passes `tutor=ctx.tutor` and stores a lock the run engaged), so account and course locks apply with nobody watching; `tutor.*` itself is outside every unattended fence.
- Still open: a Chat.tsx "Tutor" pill backed by the GET/PUT route; New Quizzes (LTI) pages and other LMSs are not covered by the graded-page rule; honest limits: a guardrail, not proctoring (`/new` starts an unlocked thread until the course is named again, unless an account lock applies).

<!-- top10:knowledge_base -->
### Knowledge base (top10 `knowledge_base`, research item 97) status and follow-ups

**Done.** Per-user collections of saved documents, searched with a pure-Python BM25 index held
in plain tables (`kb_collections`, `kb_documents`, `kb_chunks`, `kb_postings`, `kb_embeddings`;
migration `0020_knowledge_base`), so ranking is the same on SQLite and Postgres with no pgvector,
FTS5, tsvector or sqlite-vec. Passages cite by page, slide, sheet or section ('Syllabus.pdf, p. 3').

- "Knowledge base (your documents)" (`knowledge_base`, on by default) gates `knowledge.search`,
  `knowledge.read`, `knowledge.list` (reads) and `knowledge.add`, `knowledge.remove` (always an
  approval card). Sources: an upload's `file_id`, a public URL (needs "Browse the web"), a
  connected app's files read through that connector's own READ action (Drive, OneDrive, Canvas
  `get_file_text`, Notion `get_page`), or a note. Limits (documents, MB of text, MB per file,
  embedding tokens a day) are the capability's settings.
- Every passage is redacted (the INDEX policy) and PromptGuard-scanned before it is stored; a
  flagged passage is kept but withheld (never returned, never embedded).
- "Smarter knowledge search (meaning index)" (`knowledge_semantic`, off by default) adds a vector
  index built by a background sweeper with the install-wide provider's embedding model (Gemini,
  OpenAI) or Ollama (`KB_EMBEDDINGS=ollama`); search fuses it with BM25 (RRF). Other providers
  keep keyword search.
- Telegram: a document captioned `/kb <collection>` is saved (the linked user's own act).
- Deviations from the design, per the build brief: no Knowledge web page and no upload route
  (files come from the chat composer's uploads), and no connector `fetch_for_index` path.
- Follow-ups: a Knowledge page (browse, rename, delete, view withheld passages); Slack file-share
  ingest; a `<knowledge_base>` prompt block listing collections; linking a collection to a Canvas
  course (`course_ref` is stored but unused); counting embedding spend in B2 budgets; more
  embedding providers (Mistral); numpy as an optional `fast_vector_search` install.

<!-- top10:flashcards_quizzes -->
### Flashcards and practice quizzes (top10 `flashcards_quizzes`)

**Done.** A built-in `study` family behind the "Flashcards and practice quizzes" switch (off by
default, low risk). The agent turns the user's material (pasted notes, `files.read`, knowledge
search, Canvas, Drive, Notion) into stored decks of cards and multiple-choice items with an
explanation and a note on why each wrong option is wrong (migration `0021_study`).
- Scheduling is a deterministic in-house SM-2 (`services/study/srs.py`) with a daily new-card
  cap; no fsrs, no genanki.
- Reviews and quizzes run in chat (`study.review`, `study.quiz`: quiz answers stay server-side
  and choices are graded in code), and with no model on Telegram (`/decks`, `/review`, `/quiz`,
  `/export`, buttons plus `/show` ... `/end` fallbacks) and in Slack DMs (keywords).
- The daily "cards are due" reminder is a scheduler nudge (`study_due` renderer), not a second
  scheduler: counts and deck titles only. `study.settings` turns it on or off.
- Export as an Anki TSV or a CSV through a one-time 10-minute `cse_` link or `/export`.
- Only `study.delete` has a card; saving, editing, reviews, quizzes and settings run without one
  (like `reminders.create`).
- Left for later: native `.apkg` export (genanki), FSRS, AnkiConnect push, Slack Block Kit
  buttons and file export, and a model-free web review page.

<!-- top10:event_triggers -->
### D4 — App-event triggers (top10 `event_triggers`, research item 19)

**Done.** "When X happens in a connected app, tell me, or run this task", owner-approved rules
checked by a model-free sweeper (`services/notifications/event_triggers.py`, on the shared
`SweepLoop`) through each trigger's own connector row and its existing READ actions (scopes,
rate limits, token refresh and the network policy all apply). Migration `0022_event_triggers`
(`event_triggers`, `trigger_events`); a trigger dies with its connector row.

- Sources: new mail from named senders or with a subject (Gmail, Outlook), Canvas
  announcements, new assignments and grades, a calendar event about to start (Google,
  Outlook), a new file in a Drive or OneDrive folder, and a page watch's change. The first
  check only records a baseline; items are deduplicated by hashed ids; at most 5 per check
  ("…and N more"). New connector reads: `canvas.get_announcements`,
  `canvas.get_recent_grades`, and `list_folder(newest_first)` on Drive and OneDrive.
- Two switches, both off by default: "Tell me when something happens in my apps"
  (`event_triggers`, needs Telegram or Slack) and "Run a task when something happens in my
  apps" (`trigger_runs`, high risk, gates `mode=run_task`).
- notify (the default): a fixed-format message built in code, defanged, subjects PromptGuard
  flags withheld, never a mail body, no model call. run_task: one unattended run through the
  scheduler's runner and budget (the source connector's reads, its writes only as 180-minute
  approval cards when allowed, the facts as untrusted seed data, 4 rounds, a per-trigger daily
  cap); a mail task needs an exact sender allowlist, re-checked on the parsed address.
- `triggers.create` / `update` / `delete` are always approval cards (the account is pinned on
  the card); `triggers.list` and `triggers.history` are reads. No unattended run can create
  or change a trigger. Telegram `/triggers` (Pause/Resume buttons, "/triggers delete 2 yes"),
  Slack "triggers …", REST `GET/PATCH/DELETE /api/triggers` (for the D2 page).
- Still open: webhooks (D3) could queue `trigger_events` later; more sources (GitHub review
  requests, Slack mentions, Notion edits); SPF/DKIM checks before trusting a From header;
  quiet hours; a web page for triggers (D2); `web.*` in trigger runs once F2's taint check
  for web calls ships.

<!-- top10:permission_tiers -->
### F4 and item 128: risk grades, the low-risk tier and 7-day grants (top10 `permission_tiers`)

**F4: the tightening half of "argument-aware confirmation" is done; sends are never loosened.**
Every connector call is graded LOW, MEDIUM or HIGH in code (`services/agent/risk.py`) from its
catalog entry and the arguments sent. A HIGH call never runs without a card under any tier, so
`auto_approve` no longer runs invitations (guests on an event), side-door deletes (Gmail TRASH or
SPAM, an Outlook move to Deleted Items or Junk), public gists or repositories, or EXECUTE actions
(`github.rerun_failed_jobs`). Four actions that speak for the user became `always_confirm`
(`canvas.submit_assignment`, both `respond_to_invite`, `slack.invite_to_channel`), extending
connectors spec §4.4 by its own criteria. Still open from F4: shell side effects, and a general
"new recipient" rule beyond invitations (every send still asks).

**128: done.** A per-connection tier "Allow low-risk changes" (`low_risk`, migration
`0023_permission_grants`) and 7-day grants from a card ("Allow low-risk changes on <account> for
7 days"; Settings, Telegram `/grants`, Slack `grants`) run only LOW calls without a card, at most
10 a turn, never in an unattended turn, never after a PromptGuard-flagged result, with an executor
backstop and a "Done without asking" line on the reply. The owner switch "Make low-risk changes
without asking" is on by default (owner decision; it loosens nothing by itself). Archive and
mark-read stay MEDIUM in v1 (owner decision).

Follow-ups: the per-turn cap and the 7-day length are constants, not owner settings; F1's panic
button should also call `PermissionGrantStore.revoke_all`; the tripwire does not suspend weekly
desktop app approvals (weekly spec unchanged); the account export does not list grants.

<!-- top10:voice_notes -->
### Voice notes (top10) status and follow-ups

- **A4 — done** (sized L, not M: the killable secret-free worker, the forwarded-audio trust handling and the provider audio block): a Telegram voice note or audio file (at most 20 MB and 10 minutes) is transcribed, echoed silently ("🎤 Heard: “…”"), then run through the normal `build_chat_applier` turn. Two switches, both off by default: **Voice notes, transcribed on this computer** (`voice_notes`, faster-whisper base in a worker process, installed through the `speech_to_text` ALLOWLIST entry; wins whenever it is on, never falls back to the cloud) and **Voice notes, transcribed by your AI provider** (`voice_notes_cloud`, Gemini audio through `complete_once`; ogg, mp3, wav and flac only, up to 14 MB). The owner's own non-forwarded note counts as typed text; forwarded notes and audio files are PromptGuard-scanned (withheld when flagged) and fenced as shared content (`services/agent/shared_content.py`), which also taints writes. Audio stays in memory only. Quotas (10 notes per 10 minutes, 60 audio minutes a day) are in memory and reset on restart. Docker: build with `WITH_SPEECH_TO_TEXT=1`.
- Follow-ups: Slack audio clips (today a text reply; needs the files-pri download and the same service), OpenAI / Groq / Mistral `/audio/transcriptions` engines with per-minute pricing, a web mic/upload button, audio token pricing (Gemini audio is priced at the text rate), owner-editable quotas, and a model-size choice (base vs small).

<!-- top10:video_transcripts -->
### Video and podcast transcripts (top10 `video_transcripts`, research id 98)

**Phase 1 done.** `video.transcript` turns a link into timestamped passages the model summarises
and cites (M:SS); `video.list` lists the user's saved transcripts. The switch is "Summarise videos
and podcasts" (`video_transcripts`, on by default, low risk, needs "Browse the web").

- Sources, cheapest and most faithful first: a podcast feed's `<podcast:transcript>` (Apple
  Podcasts links resolved through the public iTunes lookup), a lecture page's `<track>` captions,
  a captions file (VTT, SRT, SBV, TTML/DFXP, Podcast-Index JSON, HTML, plain text), then YouTube.
- **YouTube is never fetched.** youtube.com's robots.txt disallows `/api/` (timedtext) and
  `/youtubei/`, the terms forbid automated access, and `captions.download` needs edit rights on
  the video. Crawler's only YouTube request is the public oEmbed endpoint (title, channel, a 404
  or private video caught before any spend), enforced on every hop by the toolkit's client; the
  video itself is read by the turn's own provider when that is Gemini (its documented YouTube URL
  input: 0.25 fps, low media resolution, a JSON schema, no tools), never with the install's
  Gemini key behind another provider. No yt-dlp, youtube-transcript-api or pytube, and no browser
  fallback: a 403, 429 or bot check is reported. `web.fetch_page` answers a YouTube link with a
  pointer to `video.transcript`, and `web.research` skips YouTube results.
- Limits (the capability's settings): 45 provider minutes per call (verbatim a third), 240 per
  user per day counted from the billed seconds stored on the rows, transcripts kept 14 days after
  their last use (200 per user, least recently used first out; `TranscriptJanitor` every 6 h).
  The provider read's tokens are added to the turn's usage and cost (`services/agent/turn_context.py`),
  so the cost footer, the task cap and an unattended run's budget count it.
- Phase 2 (audio transcription through voice_notes' engine) is a follow-up after voice_notes
  merges: until then an episode or link with no published text answers "This episode has no
  published transcript; transcribing audio is not available yet."
- The owner sets the three limits under the switch in Settings → Permissions
  (`CapabilitySettings.tsx`, as for scheduled tasks and the knowledge base).
- Follow-ups: a bundled lecture-notes skill; lecture recordings behind Canvas LTI tools
  (Studio, Panopto, Kaltura).
