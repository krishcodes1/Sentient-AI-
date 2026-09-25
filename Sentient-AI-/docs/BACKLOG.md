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
| A2 | **`/stop`** command on Telegram (the web Stop button already stops the task; see "A2 details" below the table) | `telegram.py _handle_message`, `_handle_help` | a /stop sent during a long Telegram turn ends it at its next step with the "Stopped." reply; the runtime's `turn_stopped` audit row is written | S |
| A3 | **Inbound photos, documents and captions** (only `text` is read today) → attachments on the user message; images fed to vision models | `telegram.py _handle_message`, `agent.py build_chat_applier` | a photo sent from the phone reaches the model | S |
| A4 | **Voice notes → text** (Gemini audio or local Whisper), 20 MB cap | `telegram.py`, a `services/tools/transcribe.py` | a voice note becomes a normal turn | M |
| A5 | `/model`, `/budget`, `/usage` polish; stream replies by editing the message every ~1 s | `telegram.py` | visible typing progress on the phone | S |
| A6 | Mid-turn progress lines ("Taking a screenshot…") from runtime events | `runtime.py event_sink` → `telegram.py` | progress appears before the final reply | S |

**A2 details.** What already works:

- `POST /api/agent/stop` records a stop for the signed-in user (`services.agent.cancel.request_cancel`), and the web Stop button calls it.
- A stop ends the running task at its next step: the runtime checks before every model round and every tool call, and computer control before every desktop action. A tool call that has started is never cut short. The turn then ends with a short "Stopped." reply, saved like any other reply.
- Approval cards that are waiting stay approvable after a stop. Approve runs that one action (the tap came after the stop), and the task it resumes stays stopped. Nothing denies pending cards.
- On Telegram, Approve/Deny runs off the poll loop, so a /stop is received while an approved action or its resumed turn runs.

What is left: Telegram `/stop` calls `request_cancel(user_id)` directly in `_handle_message`, not through the per-chat lock (the running turn holds that lock). Add the import with the others, then the command next to `/new`:

```python
from services.agent import cancel as agent_cancel

        elif command == "/stop":
            user_id = await self._user_for_chat(chat_id)
            if user_id:
                agent_cancel.request_cancel(user_id)
                text = "Stopping: the running task ends before its next step."
            else:
                text = _NOT_LINKED_TEXT
            await self._api("sendMessage", chat_id=chat_id, text=text)
```

and add `"/stop — stop the running task\n"` to the command list in `_handle_help`. `tests/test_telegram_decisions.py` adds the command this way in a subclass; point those tests at the real command once it lands.

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
| C2 | **Canvas assignments copilot** on the token connector: `canvas.get_assignments`, missing/late detection, due-this-week summary; prompt playbook | `services/connectors/canvas.py`, `tool_registry.py` catalog | "what's due this week" answers correctly against a real Canvas token | M |
| C3 | **Microsoft 365 / Outlook** mail + calendar connector (Graph OAuth) for Windows-first users | new `services/connectors/microsoft.py` | read mail and events; send needs approval | M |
| C4 | **MCP stdio transport** (+ localhost exception for user-registered servers) so any MCP server can be plugged in | `services/mcp/client.py`, `core/network_security.py` | Playwright MCP runs as a subprocess and its tools are offered, approval-gated | M |
| C5 | **SKILL.md loader**: name+description injected, body on demand, scripts only via approval, no marketplace auto-install | new `services/skills/` | a local skill folder changes agent behaviour | M |
| C6 | Search fallback (Brave/Tavily/SearXNG) + detect DuckDuckGo's anti-bot page (returns 0 results silently today) | `services/tools/web.py` | test with a captured anti-bot page | S |

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
| E2 | **Screenshots inline in web chat** (today a JSON string) | `Chat.tsx`, `MarkdownMessage.tsx` | tool images render as images | S |
| E3 | Login page: hide "Create one" when registration is closed; show the setup-in-progress hint (partly done) | `Login.tsx` | no 403 dead ends | S |
| E4 | Mobile pass on the wizard, Permissions and Settings ▸ Server (375 px) | those pages | no horizontal scroll, 44 px targets | S |
| E5 | "Promote to owner" (second admin) in Settings, so the last-owner guard has a path | `api/routes/auth.py`, Settings | audited, tested | S |

## Track F — Security hardening (self-contained items; the big ones are with Krish)
| ID | Item | Where | Done when | Size |
|---|---|---|---|---|
| F1 | **Panic action**: revoke connector tokens, pause all tools, stop the poller; Telegram `/panic` and a Settings button | `api/routes/`, `telegram.py` | one tap stops everything, audited | S |
| F2 | **Taint check on every `web.*` call** (URL host/path/query and the search query), allowing values from the user's own message | `runtime.py` taint gate | regression test with the flight URL | M |
| F3 | **Approval cards never truncate** recipients/URLs/paths; show a hash of the exact arguments | `telegram.py` card builder | test | S |
| F4 | Irreversible-action policy: delete, new recipient, shell side effects never auto-approved | `services/agent/permissions.py` | tests per rule | S |
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
