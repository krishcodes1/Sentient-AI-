# Crawler AI — Code Map

A new contributor's tour of the repo. Project root is `Sentient-AI-/` (this file's
grandparent dir); the outer git repo just wraps it plus `.github/`. Backend
is FastAPI + SQLAlchemy (async) + Alembic on Postgres; frontend is
React 19 + Vite + TanStack Query + Tailwind v4. The product is internally
"Crawler AI" (formerly SentientAI) — see `README.md` for the pitch.

## How a chat message flows (web)

1. `frontend/src/pages/Chat.tsx` + `frontend/src/components/ChatComposer.tsx` — user types, submits.
2. `frontend/src/services/api.ts` — `sendMessageStream` opens an SSE POST to `/api/agent/conversations/{id}/messages/stream`.
3. `backend/api/routes/agent.py` `stream_message` — auth, loads conversation, calls `_build_tools_and_memory` (capability-gated tool list + rendered memory block).
4. `backend/services/agent/runtime.py` `AgentRuntime.stream_chat` → `_run_turn` — orchestrates the turn.
5. `backend/services/agent/prompt_guard.py` `RuntimePromptGuard.scan_input` — screens user text for injection before anything else runs.
6. `backend/services/agent/providers.py` — the resolved `LLMProvider` (Anthropic/OpenAI-compatible/Ollama) is called for a completion.
7. On a tool call: `backend/services/agent/tool_registry.py` `ConnectorToolExecutor.execute` (or a `services/tools/*` built-in toolkit), gated by `backend/services/agent/permissions.py` and `backend/services/agent/taint.py`.
8. Every intent, tool call and result is appended to the hash-chained log via `backend/services/audit.py` `append_audit_log`.
9. Output is re-scanned (`scan_output`) and redacted if tainted; usage is recorded via `backend/services/usage/summary.py`; `_persist_assistant_detached` in `agent.py` saves the `Message` row and streams the SSE `done` event.
10. `frontend/src/components/MarkdownMessage.tsx` renders the reply; `TokenUsage.tsx` shows the cost line; `ToolScreenshot.tsx` shows a screenshot a tool took, which reaches the live turn once (the `done` event's `images`) and is never saved.

Telegram is a **full chat channel plus approval channel**. Plain text sent to
the bot (`backend/services/notifications/telegram.py`, long-polled from
`getUpdates`) is handed to the `chat` callback built by `agent.py`
`build_chat_applier`, which runs the exact pipeline above (rate limit,
persisted user message, tools + memory, `AgentRuntime.chat`, persisted reply)
inside a per-user conversation titled "Telegram"; screenshots come back via
`sendPhoto`. An Approve/Deny button tap goes to `_handle_callback` → the
`decide` callback from `build_decision_applier` →
`AgentRuntime.approve_action`/`deny_action`, which resumes the parked tool
call through the same executor → audit → and Telegram edits the original
message with the verdict. An approval then runs one more turn
(`_resume_after_approval`), whose history ends on a user-role message
carrying the approved call's whole result in the runtime's tool-result
envelope (`AgentRuntime.approved_call_message`), and its reply goes to the
chat with any card it parked named; when that turn fails or says nothing,
the chat gets what ran and why it stopped, in plain words
(`resume_failure_text`), never a pointer to the web app.

## How a capability switch flows

1. Setup wizard (`frontend/src/pages/Setup.tsx`) or Settings → Permissions (`frontend/src/components/CapabilityList.tsx`) calls `PATCH /api/capabilities`.
2. `backend/api/routes/capabilities.py` `update_capabilities` (admin-only) → `backend/services/installation.py` `InstallationService.set_capabilities` persists the switch and audits it.
3. Each turn, `agent.py` `_capability_view` calls `installation.report()`, which runs every `backend/services/capabilities/*.py` module's `availability()`/`probe()`.
4. `backend/services/agent/tool_registry.py` `build_tools(enabled_capabilities=...)` gates which tools are even offered to the model this turn.
5. `backend/services/capabilities/prompt.py` `render_permissions_block(statuses)` builds the `<permissions>` block `runtime.py` appends to the system prompt, so the model (and the user) knows what's on/off and why.

**Files most likely touched when adding a new tool family** (per
`backend/services/capabilities/README.md`'s "Five steps"):
1. **`backend/services/tools/<family>.py`** — new toolkit (create).
2. **`backend/services/agent/tool_registry.py`** — catalog entry, `_BUILTIN_STANCE`, executor wiring.
3. **`backend/services/capabilities/<key>.py`** — capability declaration (copy `_template.py`), registered in `services/capabilities/__init__.py`.

---

## Entry points & wiring

- `backend/main.py` — FastAPI app: lifespan, `wire_services` (builds installation, telegram manager, runtime, MCP catalog, reminders onto `app.state`), router mounting, global exception handlers.
- `backend/core/config.py` — `Settings` (pydantic-settings): env vars, provider key fields, placeholder-secret rejection.
- `backend/core/database.py` — async engine/session factory, Alembic-adoption logic for pre-Alembic databases, `backfill_user_llm_defaults`.
- `backend/core/security.py` — password hashing, JWT issue/verify, AES-GCM credential encryption, audit HMAC hashing.
- `backend/core/validation.py` — shared Pydantic validators (`SafeStr`, email/model-id checks).
- `backend/core/http_pinning.py` — connect-time DNS pinning for outbound HTTP (anti-TOCTOU/rebinding).
- `backend/core/network_security.py` — SSRF policy: blocks private/reserved address ranges, per-connector host allowlists.
- `backend/core/logging_config.py` — process-wide `structlog` setup.
- `backend/api/middleware/security.py` — security headers, per-IP rate limiting, request-ID middleware stack.

## API routes (`backend/api/routes/`)

- `_deps.py` — shared deps: `installation_service(request)`, `require_admin`.
- `agent.py` — conversations CRUD, send/stream message, approvals list/decide (`PendingApprovalOut.image` carries a purchase card's screenshot while the checkout is pending; `ApprovalDecisionResponse.images` + `message_id` carry the approved call's own pictures, a checkout's confirmation page, which `_apply_decision` also hands the Telegram applier ahead of the resumed turn's), `POST /agent/stop` (the web Stop button), and the chat/decision appliers the Telegram bot runs; the biggest route file (turn orchestration glue).
- `auth.py` — register/login/refresh, profile & password change, account export/delete, settings.
- `capabilities.py` — capability report + owner-only switch updates + install trigger.
- `connectors.py` — connector CRUD, credential validation, health stats.
- `memory.py` — persistent-memory CRUD.
- `reminders.py` — reminder CRUD.
- `setup.py` — first-run wizard: owner account, provider choice+test, Telegram token, completion.
- `telegram.py` — link-code generation/status/unlink for the approval channel.
- `usage.py` — signed-in account's token/cost usage summary.
- `audit.py` — read-only audit log list/stats/integrity-verify (no write endpoint by design).
- `vault.py` — the owner's payment card (owner-only): `GET /vault/items` (masked views, plus `available` and the `reason` the Settings page shows instead of the form; a 200 always, and it never mints the key), `PUT /vault/card` (loopback peer only; 409 `vault_unavailable` in a container; 422 never echoes the input), `DELETE /vault/items/{id}`. No route returns a number or a blob.

## Agent runtime (`backend/services/agent/`)

- `runtime.py` — `AgentRuntime`: provider leasing, system-prompt assembly, `chat`/`stream_chat`/`_run_turn`, approval resume, image handling; stop checks at step boundaries, the executor's pre-card checks (`precheck_approval`, `approval_arguments`, the async `approval_arguments_async` a `browser.checkout` card is built by, filed under `purchase_rule` when it refuses), a card's picture (`PendingApproval.image`, served through `approval_image` and never stored), the `<purchases>` prompt block sent only when `browser.checkout` is offered (`PURCHASES_SYSTEM_PROMPT`; `SECURITY_SYSTEM_PROMPT` is as before the feature), `_card_risk_note` (no taint heads-up on a checkout card whose merchant is the page's host; plain wording otherwise), `approved_call_message(image_delivered=…)` with `IMAGE_NOT_SHOWN` when no channel forwards a picture, the latest-observation policy for browser and desktop outlines, desktop results audited as facts only, and the browser spend estimate priced per model.
- `cancel.py` — per-user stop requests (the web Stop button, Telegram `/stop`): each piece of work takes a mark when accepted and a stop ends work marked before it; the runtime and the computer toolkit check it.
- `providers.py` — `LLMProvider` abstraction: `AnthropicProvider`, `OpenAICompatibleProvider` (OpenAI/Grok/DeepSeek/Groq/Ollama), tool-call/content normalization.
- `prompt_guard.py` — multi-layer prompt-injection scanner: normalization (base64/hex/homoglyph/zero-width), pattern detection, threat levels.
- `taint.py` — CaMeL-lite taint tracking: flags untrusted tool-result content flowing into later tool arguments, escalates auto-approved writes.
- `permissions.py` — `PermissionEngine`: tiers, `ActionCategory`, hard-blocked actions, per-connector policy rows. `("browser", FINANCIAL)` is `USER_CONFIRM` (`FINANCIAL_CONFIRM_KEYS`); every connector's FINANCIAL row stays hard-blocked.
- `tool_registry.py` — connector/tool catalog, capability gating (`_capabilities_of`: the claiming capability plus `_REQUIRED_CAPABILITIES`, so `browser.checkout` needs `purchases` and `browser_control`), `ConnectorToolExecutor` (dispatch to built-in toolkits, connectors, MCP; `FINANCIAL_BUILTINS` names the one financial action ever dispatched, `browser.checkout`; the approval hooks `describe_approval` / `precheck_approval` / `approval_arguments` / `approval_arguments_async` / `approval_image` route `desktop.act`, `browser.act` and `browser.checkout` to their toolkits).
- `approvals.py` — `ApprovalStore` implementations (in-memory + DB-backed `PendingAction` rows), single-use/expiry semantics.
- `context_manager.py` — token estimation, per-model context windows, message summarization/compression, offered-tool-set selection, turn-replay cache.

## Built-in tools (`backend/services/tools/`)

- `desktop.py` — `desktop.screenshot` (mss capture, downscale, capability-gated).
- `web.py` — `web.search`/`web.fetch_page`/`web.screenshot` (Playwright-backed).
- `html_text.py` — readable-text extraction and search-result parsing helpers used by `web.py`.
- `net.py` — egress guard (SSRF-checked HTTP client) shared by the web tools.
- `reminders.py` — `reminders.now`/`create`/`list`/`cancel` (the model's clock + scheduling).
- `system.py` — capability report tool + `system.install_capability` (fixed argv allowlist installer, e.g. hidden browser).
- `browser/` — Crawler's own browser (one per user, `session.py`; egress guard `guard.py`; sign-in/2FA handoff `handoff.py`; ARIA outline `snapshot.py`). `actions.py` is `browser.read` (READ; its click, which has no card, only follows a plain link to no order path (an order history aside) or clicks a control outside any form on a page with no total, payment method on file or wallet, `markers.read_click_allowed`, and the guard never lets it, or a handoff the model asked for, open an order step or send anything to an order address; while it clicks, no page script sends anything but a GET), `act.py` is `browser.act` (WRITE, one card per call, tied to the page by `_page` (origin, address and outline, for every act, a key press included); `bind_async` puts a masked picture of the page with the target outlined in red on every card, kept in memory and served by `approval_image`, and a money warning from the page's facts; never into a password or card field, never on `http://`, never a click, submit or Enter that pays — the control that would send the form is judged (`markers.pays`): a purchase-worded button, a form holding a card, a POST to an order path, or a button on a page showing an order total next to a payment method on file is `use_checkout`), `checkout/` is `browser.checkout` (FINANCIAL, one card per purchase: `markers.py` is the one classifier of card fields, buttons that pay and pages where an order is placed, shared by the facts, the outline, the screenshot mask and `browser.act`; `facts.py` reads the origin, the on-screen total nearest the card form, items, card fields and the order button's target off the page, `merchant.py` refuses the wrong or a look-alike host, `amounts.py` parses money, `ledger.py` writes the `purchases` audit rows and sums the last 24 h over every submitted card (a decline excepted), `toolkit.py` runs precheck → begin (the card's facts and an in-memory screenshot) → run (decrypts the card at fill time only, submits, reads the confirmation)). `pagememory.py` is the page the last read observed, which act and checkout are checked against; `_shared.py` holds the helpers the three toolkits share (the outline, the masked screenshot, the handoff and its window: `hand_over` when a toolkit hands the page to the person, `take_back` on the agent's next action).
- `computer/` — desktop.observe / desktop.act on this platform's backend (see `docs/superpowers/specs/2026-09-24-computer-control-design.md`).

## Vault and platform secrets

- `backend/services/vault/` — the owner's card, "encrypted in its purse": `keys.py` (`PlatformKeyProvider` = one 32-byte key held only by the OS store, minted by the first `get` — the first card stored — while `check` only reads; `DevFileKeyProvider` for tests and a developer's Linux box, never picked on a Mac or PC; `DisabledKeyProvider` in a container; `select_key_provider`), `crypto.py` (AES-256-GCM `seal`/`open_`, Luhn, brand), `service.py` (`VaultService`: `put_card` validates before touching the key, one card per user, `open_card` only from the checkout toolkit, views are masked). No number, CVC or blob ever reaches a log line, an audit row, an API response or the model.
- `backend/services/platform/` — the only OS branches: `mac.py` (Keychain via `/usr/bin/security -i` with the command, key included, on stdin so the key is never in argv; service "Crawler AI vault"), `windows.py` (DPAPI `CryptProtectData` through a `Crypt32` shim, ciphertext under `<data_dir>/secrets/`), `linux.py` / `container.py` (`SecretStoreUnavailable`); `base.py` adds `get_secret`/`set_secret`/`delete_secret`/`vault_id` to the `Platform` protocol.

## Capabilities (`backend/services/capabilities/`)

- `README.md` — how to add a capability (five steps); read this before touching the registry.
- `__init__.py` — `REGISTRY` of all capabilities, `capability_for_tool`, `default_switches`, `default_context`, probe caching.
- `base.py` — `Capability`, `Availability`, `ProbeResult`, `ReportContext`, `CapabilityStatus` dataclasses.
- `_template.py` — copy-and-fill starting point for a new capability.
- `env.py` — one-shot environment facts (container/platform/executable path) fed into `ReportContext`.
- `installs.py` — the `installs` capability (gates `system.install_capability`).
- `macos.py` — ctypes shims over CoreGraphics for macOS Screen Recording permission preflight/request.
- `screen.py` — the `desktop.screenshot` capability (high-risk, off by default, blocked in containers).
- `site_screenshots.py` — the `web.screenshot` capability.
- `telegram.py` — the Telegram capability (a channel, claims no tools).
- `prompt.py` — `render_permissions_block`: turns statuses into the `<permissions>` system-prompt section.
- `purchases.py` — the `purchases` capability ("Buy things for me": off by default, high risk, claims `browser.checkout`, native Mac/Windows only because it needs the card vault); `PURCHASE_SETTINGS_DEFAULTS` are the per-purchase ($25) and per-day ($50) caps the owner edits in Permissions.
- `browser_control.py` — the `browser_control` capability (`browser.read`; `browser.act` and `browser.checkout` need it too, through `_REQUIRED_CAPABILITIES`).
- `browser_act.py` — the `browser_act` capability ("Fill in forms and click on sites": off by default, high risk, claims `browser.act`, native Mac/Windows only, `requires=("browser_control",)` so the report shows it blocked while Control a browser is not on).
- `reminders.py` — the `reminders` capability.
- `web_browsing.py` — the `web_browsing` capability (`web.search`, `web.fetch_page`).

## Installation & settings

- `backend/services/installation.py` — `InstallationService`: owner switches, provider/key resolution (`.env` > DB > default), Telegram token, registration lock, capability report assembly, and a capability's owner-editable numbers (`capability_settings` / `set_capability_settings`, audited as `capability_settings_updated`; `purchase_caps()` is what the checkout toolkit enforces).
- `backend/models/installation.py` — the single-row `Installation` table (`capability_settings` JSON holds only what the owner changed, so a new default reaches every install).
- `backend/api/routes/setup.py` / `capabilities.py` — the HTTP surface over the above (see routes section).

## Connectors (`backend/services/connectors/`)

- `base.py` — `BaseConnector` framework: rate limiting, error types (`AuthenticationError`, `HardBlockError`, `UserConfirmationRequired`), `path_segment` helper.
- `canvas.py` — Canvas LMS connector (courses, assignments, grades).
- `google_workspace.py` — Gmail/Calendar connector.
- `robinhood.py` — Robinhood Crypto connector (read-heavy; trading hard-blocked).
- `factory.py` — builds a live connector instance from stored (encrypted) credentials; credential validation.
- `backend/models/connector.py` — `ConnectorConfig` model, `ConnectorType`/`AuthMethod`/`PermissionTier` enums.

## MCP (`backend/services/mcp/`)

- `client.py` — minimal JSON-RPC 2.0 over Streamable HTTP MCP client, SSE parsing.
- `integration.py` — wires discovered MCP tools into the tool/permission/audit pipeline; financial-tool-name blocking; name sanitization/namespacing (`mcp.<server>.<tool>`).
- `activity.py` — in-process activity recorder used for connector health stats.

## Notifications (`backend/services/notifications/`)

- `telegram.py` — long-polling `TelegramService`: link-code linking, `/stop`/`/new`/`/pending`/`/usage`/`/help`, message + callback (approve/deny) handling as per-chat tracked tasks, the per-reply cost line, `NotifyingApprovalStore`.
- `telegram_manager.py` — starts/restarts/stops the poller at runtime as settings change; serializes concurrent apply calls.
- `progress.py` — `TurnProgress`: turns a running turn's tool_call events into short fact-only lines ("Opening canvas.nyit.edu…") and paces them (2 s grace, one per 4 s, no repeats, 6 per turn, the reply at least 1 s after the last line).
- `reminders.py` — `ReminderService`: delivers due reminders (Telegram when linked).

## Usage / pricing (`backend/services/usage/`)

- `pricing.py` — list-price table and `estimate_cost_usd` per model.
- `summary.py` — aggregates one account's usage across today/7d/30d/all-time windows, per-model breakdown, timezone-aware bucketing.

## Other services

- `backend/services/audit.py` — `RuntimeAuditLogger` + `append_audit_log`/`append_auth_event`: HMAC hash-chained, per-user tamper-evident log.
- `backend/services/auth.py` — registration, authentication, account lockout tracking.
- `backend/services/memory.py` — renders saved per-user memories into the system prompt; injection screening on write.
- `backend/scripts/verify_audit_log.py` — standalone CLI to verify the audit chain's integrity end to end.

## Models & migrations

Models (`backend/models/`): `user.py` (User, telegram link fields), `conversation.py` (Conversation/Message/MessageRole), `audit.py` (AuditLog/AuditStatus, hash chain columns), `connector.py` (ConnectorConfig + enums), `installation.py` (single-row Installation), `memory.py` (Memory/MemoryCategory/MemorySource), `pending_action.py` (PendingAction — persisted approvals), `reminder.py` (Reminder/ReminderSource/ReminderStatus), `vault_item.py` (VaultItem — the owner's sealed card: kind, label, masked, AES-GCM blob; never plaintext).

Migrations (`backend/alembic/versions/`), oldest first:
- `0001_baseline_schema.py` — baseline schema (everything `create_all()` used to build); stamped, never run, on pre-Alembic DBs.
- `0002_user_is_admin.py` — adds `users.is_admin`, promotes the first account.
- `0003_hot_path_indexes.py` — composite indexes for hot per-user queries.
- `0004_telegram_link.py` — Telegram approval linking columns on `users`.
- `0005_reminders.py` — the `reminders` table.
- `0006_message_usage.py` — per-message token accounting + image attachment metadata.
- `0007_message_model.py` — records which provider/model produced each assistant message.
- `0008_installation.py` — the one-row `installation` table (owner switches, provider, secrets).
- `0009_user_llm_nullable.py` — makes a user's provider/model nullable ("follow the install default").
- `0010_vault_items.py` — the `vault_items` table and `installation.capability_settings` (guarded like 0008/0009).

`backend/alembic/env.py` — reads `DATABASE_URL` from `core.config.settings` (no second credential copy); `backend/alembic/README.md` explains the adoption logic for pre-Alembic deployments.

## Backend tests (`backend/tests/`, one theme per file)

`conftest.py` sets dummy env vars, DB session fixtures, auth helpers. Themes:
account export · admin role/tier · agent-loop security · vision/image turns · approval arg re-scanning · approval flow (DB+memory stores, concurrency) · auth-event audit trail · audit event→status mapping · HMAC audit hashing · audit service chaining · audit stats endpoint · auth hardening (XFF, lockout) · capabilities HTTP API · capabilities registry invariants · capability report logic · capability gating at both call sites · concurrency/failure modes · connector behavior (Canvas/Google/Robinhood) · connector route policy · context manager budgets/windows · conversation lifecycle routes · conversation search · desktop screenshot tool · executor security (credentials, scopes) · installation service · MCP integration · MCP client protocol · MCP DNS pinning (rebinding) · persistent memory CRUD · memory search · message usage/attachments · legacy-DB migration adoption · migration schema drift · network policy (SSRF per connector) · Ollama streaming errors · production-hardening config checks · prompt-guard false positives · prompt-guard normalization evasion · prompt-injection red-team suite · provider layer (Anthropic/OpenAI-compatible) · query-efficiency regressions · reminder tools · reminder CRUD/sweeper · resume-after-approval · route-level security · lazy provider resolution · security-middleware ordering · session refresh · Settings/account validation · setup wizard API · SSRF address policy · stream resilience/audit ordering · SSE streaming · built-in system tools (install allowlist) · taint tracking · Telegram approval channel · Telegram decisions answered at once and run off the poll loop (`test_telegram_decisions.py`) · Telegram progress lines (`test_telegram_progress.py`) · Telegram cost line, linked account only and `/stop` (`test_telegram_cost_safety.py`) · the turn resumed after an approved desktop action reaches the chat, or says why it could not (`test_telegram_desktop_resume.py`) · stop requests and the runtime's stop boundaries (`test_agent_cancel.py`, `test_runtime_stop.py`) · desktop acts refused before the card and cards tied to their screen (`test_computer_precheck.py`) · desktop latest-observation policy (`test_desktop_observation_policy.py`) · current provider model families (`test_provider_model_families.py`) · web chat screenshots shown live and never stored (`test_web_chat_images.py`) · Telegram manager lifecycle · tool registry/executor · token usage accounting · per-user LLM follows install default · audit-log verifier CLI · built-in web tools · app wiring (`test_wiring.py`).

Purchases (2026-09-25): the vault (`test_vault_crypto.py`, `test_vault_keys.py`, `test_vault_service.py`, `test_vault_api.py`), the platform secret stores with a recorded `security` argv and a fake DPAPI shim (`test_platform.py`), `browser.act` and the page memory (`test_browser_act.py`), the act switch, the picture on every act card, its money warning and the read-tier click (`test_browser_act_card.py`), the risk note absent on a real-looking host (`test_purchase_card_text.py`), the decision path's confirmation pictures for the web and Telegram (`test_resume_after_approval.py`), the fake site's checkout pages and TLS harness (`test_fakesite_checkout.py`), the checkout parts (`test_checkout_amounts.py`, `test_checkout_merchant.py`, `test_checkout_facts.py`, `test_checkout_ledger.py`) and toolkit (`test_checkout_toolkit.py`), the capability and its caps (`test_purchases_capability.py`), the permission/registry/runtime/Telegram wiring on fakes (`test_purchases_wiring.py`, `test_telegram_purchase_card.py`), and the whole chain through the runtime on the real executor, toolkits, vault, ledger and audit log against the fake shop over TLS (`test_purchase_flow.py`: one card, Approve pays from the vault with the number reaching nothing the model sees, Deny fills nothing, cap / http / wrong or look-alike merchant / changed page / switch off refused). `tests/fixtures/purchase_notice.txt` is the notice the frontend copies.

## Frontend pages (`frontend/src/pages/`)

- `Chat.tsx` — main conversation UI: message list, tool/approval cards, streaming.
- `Connectors.tsx` — connector list, create/edit/health.
- `Dashboard.tsx` — home: approvals, connector health, usage snapshot.
- `Login.tsx` — login/register ("Create one" only while registration is open; otherwise a plain hint. A register attempt that gets 403 asks the setup status again and shows the matching hint).
- `Memory.tsx` — memory list/create/edit/search.
- `Settings.tsx` — profile, password, Permissions (capabilities), owner Server section, account export/delete.
- `Setup.tsx` — first-run wizard: owner account → provider → Telegram → permissions → summary.
- `AuditLogs.tsx` — audit log browser + integrity verification.
- `approvalCountdown.ts` — shared TTL-countdown hook for approval cards (kept out of Chat's chunk so Dashboard doesn't pull in react-markdown).
- `approvalArguments.ts` — `shownArguments`: the arguments an approval card displays, without the reserved keys a `desktop.act` (`_screen`), `browser.act` (`_page`) or `browser.checkout` (`_checkout`) card stores; `isSentenceCard` (a `browser.act` card is its reason sentence alone, no JSON); `purchaseCard` reads a checkout card's facts and `approvalImage` accepts only a base64 image data URL (shared by Chat and Dashboard).
- `purchaseNotice.ts` — `PURCHASE_NOTICE`, the frontend's copy of the backend's notice ("Crawler can make mistakes…"); a vitest holds it equal to `backend/tests/fixtures/purchase_notice.txt`.

## Frontend components (`frontend/src/components/`)

- `Brand.tsx` — logo/wordmark variants.
- `CapabilityList.tsx` — renders capability switches (on/blocked-with-fix/blocked-until-installed/off) for Setup and Settings; with an `onSettingsChange` handler (Settings only) it renders `CapabilitySettings` under a switch.
- `CapabilitySettings.tsx` — the `purchases` row's "Per purchase (USD)" / "Per day (USD)" fields (`min=1 max=10000`, the server's bounds), saved on blur or Enter through `PUT /capabilities/purchases/settings`.
- `ChatComposer.tsx` — message input: text, image attach/paste/drag.
- `ConfirmDialog.tsx` — branded async `window.confirm()` replacement, focus-trapped.
- `ErrorBoundary.tsx` — top-level React error boundary.
- `FormFeedback.tsx` — `ErrorAlert`/`ResultLine` shared form feedback.
- `MarkdownMessage.tsx` — exfiltration-safe markdown renderer for assistant output (untrusted content can't inject live links/images unchecked).
- `PaymentCardSettings.tsx` — Settings ▸ "Payment card" (owner only): the masked stored card with Delete, or the `autoComplete="off"` entry form; posts once, clears the inputs, never renders a stored number; the reason a container gives (`GET /vault/items` `available: false`, or a 409 on save) replaces the form.
- `ProviderErrorText.tsx` — turns an API "fix pointer" into a Settings/Setup link.
- `ProviderForm.tsx` — shared provider-choice form (Setup wizard + Settings ▸ Server).
- `PurchaseApproval.tsx` — the `browser.checkout` approval card (Chat's `ApprovalCard`, Dashboard's `ApprovalRow`): the screenshot, Pay / To / With facts, item lines, the model's note and the notice above Approve/Deny.
- `ServerSettings.tsx` — owner-only Server section (provider, registration toggle).
- `ThemeToggle.tsx` — light/system/dark switch.
- `TokenUsage.tsx` — per-message token/cache caption.
- `ToolScreenshot.tsx` — a tool's screenshot under its tool call, or a note: "Screenshot not kept" after a reload, "not shown" past the 3-per-reply limit.
- `UsagePanel.tsx` — usage-by-window summary panel.
- `formStyles.ts` — shared Tailwind class/style constants for Setup + ProviderForm.
- `toolScreenshots.ts` — which image URLs the chat may show (base64 PNG/JPEG/WebP data URLs only), screenshot alt text, the saved placeholder, which note stands in for a missing screenshot.
- `usageFormat.ts` — token/cost formatting + `Intl.NumberFormat` (fixed locale).
- `layout/Layout.tsx` — app shell: sidebar + outlet, mobile drawer.
- `layout/Sidebar.tsx` — nav links.

## Frontend hooks

- `useFocusTrap.ts` — traps Tab focus inside a modal/drawer.
- `useMediaQuery.ts` — `useSyncExternalStore`-based media-query hook (drives desktop/mobile layout decisions in JS).
- `useResolvedColors.ts` — resolves CSS custom properties to concrete color strings for recharts (which can't consume `var()`).

## Frontend services / types

- `services/api.ts` — the entire backend client: auth, conversations, streaming SSE parsing, connectors, capabilities, usage, setup.
- `types/index.ts` — shared TypeScript types mirroring backend Pydantic models (User, Conversation, CapabilityStatus, UsageSummary, etc).
- `theme.tsx` — `ThemeProvider`/`useTheme` (light/dark/system), synced with `index.html`'s inline bootstrap script.
- `main.tsx` — app bootstrap: router, QueryClient, ThemeProvider, self-hosted font imports.
- `App.tsx` — route table; pages other than Login are lazy-loaded for bundle size.

## Frontend tests (grouped by theme)

Component tests mirror their component 1:1 (`CapabilityList`, `ChatComposer`, `ConfirmDialog`, `ErrorBoundary`, `MarkdownMessage`, `ProviderErrorText`, `TokenUsage`, `UsagePanel`, `Layout`), plus `toolScreenshots.test.ts`. Page tests: `Dashboard.test.tsx`, `Settings.test.tsx`, `Setup.test.tsx`, `Chat.stop.test.tsx` (the Stop button asks the server and keeps the stream), `Chat.screenshots.test.tsx` (a turn's screenshot shows as an image and survives an approval's refetch; a reloaded thread shows the note), `Login.test.tsx` ("Create one" or the closed-registration hint, and the 403 fallback), `approvalCountdown.test.ts`, `approvalArguments.test.ts`. Service tests: `api.test.ts` (general client), `api.approvals.test.ts`, `api.refresh.test.ts` (401→refresh flow), `api.setup.test.ts`, `api.stop.test.ts`. `theme.test.tsx` (theme persistence/sync), `App.test.tsx` (routing/setup redirect). `test/` holds shared fixtures, not tests: `setup.ts` (jsdom matchMedia polyfill), `http.ts` (fetch/location doubles), `capabilities.ts` and `usage.ts` (realistic fixture bodies).

Purchases (2026-09-25): `CapabilitySettings.test.tsx`, `PaymentCardSettings.test.tsx` (never renders a number, posts once, clears the inputs, keeps the form on 422, shows the container's reason from the list or a 409, names a card once, deletes with confirm), `PurchaseApproval.test.tsx` (plus a Dashboard integration case: the purchase card with Approve/Deny and no JSON block), `Chat.approvalCards.test.tsx` and `Dashboard.actCard.test.tsx` (a `browser.act` card is one sentence; the confirmation picture after Approve), `purchaseNotice.test.ts` (equal to the backend fixture), and purchase cases in `CapabilityList.test.tsx`, `Settings.test.tsx` and `approvalArguments.test.ts`.

## Docker & CI

- `docker/Dockerfile.backend` — multi-stage: `dev` (hot-reload uvicorn) / `prod` (non-root, healthcheck).
- `docker/Dockerfile.frontend` — multi-stage: `dev` (Vite server) / `prod` (static build behind nginx, inlined config, `/api` reverse proxy).
- `docker/docker-compose.yml` — dev stack: Postgres, backend, frontend, bind-mounted source.
- `docker/docker-compose.prod.yml` — prod stack: built images, Postgres/Redis not published to host, required `POSTGRES_PASSWORD`, `ALLOWED_HOSTS` note.
- `.github/workflows/ci.yml` — 5 jobs: `lint` (ruff+mypy), `frontend` (build/lint/vitest+coverage/npm audit), `backend` (pytest on sqlite, coverage), `backend-postgres` (migrate + pytest against real Postgres), secret scan (gitleaks). Runs on every branch push, not just PRs.
- `.github/dependabot.yml` — weekly bumps for pip, npm, docker, github-actions.

## Docs

- `README.md` — project pitch/setup.
- `SECURITY.md` — security posture/reporting.
- `docs/team-handoff-2026-09-23.md` — handoff notes for the capabilities/setup-wizard work that landed on `feat/full-platform-completion`.
- `docs/superpowers/specs/2026-09-23-capabilities-and-setup-wizard-design.md` — design doc for that work.
- `docs/superpowers/plans/2026-09-23-capabilities-and-setup-wizard.md` — implementation plan for that work.
- `docs/superpowers/specs/2026-09-25-purchases-design.md` — design and the five implementation contracts for `purchases` (the vault, `browser.act`, `browser.checkout`, the wiring, the frontend).
- `docs/testing/headless-mac-full-test.md` — the full live test on the headless test Mac (native install, wizard, Telegram, macOS grants, every agent flow, and section 5.2 for a purchase that stops at the approval card); `docs/testing/computer-control-headless-mac.md` is the low-level computer-control smoke test.
- `backend/alembic/README.md` — migration workflow + pre-Alembic adoption.
- `backend/services/capabilities/README.md` — how to add a capability (five steps, referenced above).
