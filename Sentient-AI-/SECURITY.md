# Crawler AI Security Model

Crawler AI is a consent-based agent platform: the assistant can read and act
on a user's connected services, but **every capability is opt-in, scoped,
rate-limited, logged, and — for anything sensitive — gated behind explicit
user approval**. This document describes the layers, where each is enforced
in code, and what is still open.

## Principles

1. **Deny by default.** Unknown tools, unknown connectors, ungranted scopes,
   non-allowlisted hosts, and financial actions are refused without
   configuration to the contrary.
2. **Consent before impact.** Write actions (sending email, submitting
   assignments, creating events) and *all* finance reads require explicit
   per-action user approval. Approvals are single-use, owned, and expire.
3. **Money never moves.** Trading, transfers, withdrawals, and purchases are
   hard-blocked at four independent layers and cannot be enabled by any
   configuration, prompt, or API call.
4. **External content is data, not instructions.** Tool results, emails,
   documents, and MCP responses are sanitized and wrapped in an untrusted
   envelope before the model sees them.
5. **Everything leaves a trail.** Agent activity is written to a per-user,
   hash-chained audit log that detects tampering, deletion, and reordering.

## Identity and access

- **Authentication** — bcrypt password hashing, JWT bearer tokens (HS256,
  configurable expiry). `services/auth.py`.
- **Authorization** — every agent/connector/audit route requires a valid JWT
  (`Depends(get_current_user)`), and the user id is derived **only** from the
  token. Resource lookups filter on the owner and return 404 for rows the
  caller does not own, so ids are not enumerable. `api/routes/*.py`,
  enforced by tests in `tests/test_route_security.py`.
- **No client-supplied identity.** Request bodies and query strings carry no
  `user_id`; an earlier IDOR (any caller could read or act on any user's
  data, including approving other users' pending actions) was closed by this
  change.
- **Audit writes are server-side only.** The public `POST /api/audit/`
  endpoint was removed because it allowed forging validly-chained entries.
- **Rate limiting** — per-IP limits: a general bucket
  (`RATE_LIMIT_PER_MINUTE`, default 60) and a stricter credential bucket for
  `/auth/login` + `/auth/register` (`AUTH_RATE_LIMIT_PER_MINUTE`, default 10)
  to slow brute force. Counting uses a Redis fixed-window counter
  (`REDIS_URL`), shared across workers; if Redis is unreachable or errors,
  the limiter falls back to an in-memory sliding window so the API never
  goes down with Redis. `X-Forwarded-For` is trusted for client-IP
  attribution **only** when the direct peer is a configured trusted proxy
  (`TRUSTED_PROXIES`, default loopback + private ranges), so a directly
  reachable client cannot spoof the header to mint a fresh bucket per
  request and defeat the throttle. `api/middleware/security.py`.

  **The default `TRUSTED_PROXIES` is wide, and that is a real risk.** It
  covers every RFC1918/ULA range because that is where nginx sits in the
  shipped compose topology — which also means any host that can reach the
  API from a private range (a sidecar container, a machine on the same
  LAN, a neighbouring pod) is believed when it claims a client IP. Narrow
  it to the proxy's own address where the deployment allows; the app logs
  a startup warning in production while it is wider than loopback.
- **Per-account lockout** — per-IP limits leave the attacker holding the
  denominator, because they choose the source addresses. Consecutive failed
  sign-ins are therefore also counted per account and lock it for
  `LOCKOUT_DURATION_MINUTES` after `LOCKOUT_THRESHOLD` failures (defaults 15
  and 5). The lock is checked *before* the password is verified, so a locked
  account does not open for a correct guess; a successful sign-in clears the
  counter; and the counter is kept for addresses with no account too, so the
  response does not reveal which addresses exist. State is process-local, so
  a multi-worker deployment allows up to (workers x threshold) failures
  before the lock engages — still a ceiling the attacker cannot widen.
  `services/auth.py::AccountLockout`.
- **Re-authentication for irreversible operations** — changing the account
  email and deleting the account both require the current password, not just
  a bearer token. A token is a capability that outlives the tab it was
  minted in; without this, one leaked token converts into permanent
  ownership (move the account to an attacker-controlled address) or total
  loss. `api/routes/auth.py::_require_current_password`.
- **Email normalization** — accounts are keyed on a trimmed, lowercased
  email, so casing cannot create duplicate accounts or lock a user out.

## Credential handling

- Connector credentials are encrypted with **AES-256-GCM** (random 96-bit
  nonce per blob) under `ENCRYPTION_KEY` before touching the database, and
  are never returned by any API. `core/security.py`.
- Decryption happens only inside the tool executor / connection test, for the
  duration of a single dispatch. `services/agent/tool_registry.py`.
- Audit rows and logs pass through a sanitizer that redacts secret-shaped
  keys and values (tokens, API keys, JWTs, card numbers). `services/audit.py`.

## Permission model

Two cooperating mechanisms decide what the agent may do:

**Action tiers** (`services/agent/permissions.py`) classify every catalog
action (READ / WRITE / DELETE / EXECUTE / FINANCIAL) per connector:

| Tier | Meaning |
|------|---------|
| `auto_approve` | Runs immediately (read-only actions on trusted services) |
| `user_confirm` | Parked until the user approves it |
| `admin_only`   | Usable only by the deployment owner (`users.is_admin`); contributes no tools at all for anyone else |
| `hard_blocked` | Never runs, not configurable |

Robinhood reads are `user_confirm` — even *viewing* financial data requires
consent per action. All FINANCIAL category actions are `hard_blocked`.

The owner is the first account to register, which on a self-hosted install
is whoever deployed it. There is no UI to transfer or grant the role; see
"Known gaps" below.

**Granted scopes** (least privilege) gate which actions exist at all:

- Creating a connector without choosing scopes grants only its **read**
  scopes; write scopes must be granted explicitly in the UI.
- Tools outside the granted scopes are not offered to the model, and the
  executor re-checks scopes at dispatch (defense in depth). Legacy
  connectors with empty scope lists are treated as **read-only**.

**Capability switches** (`services/capabilities/`) are a third, orthogonal
control: coarse, owner-only toggles (Browse the web, Screenshots of
websites, See my screen, Reminders, Save memories, Watch web pages for
changes, Install optional software, Telegram) set in the setup wizard or
Settings → Permissions, on top of the action tiers and scopes above.

- Only the owner (`users.is_admin`) can change them (`PUT /api/capabilities`);
  every other user gets a read-only view.
- Enforced at three independent points: **offer** (`build_tools` drops every
  tool whose capability is not effectively on), **dispatch** (the permission
  adapter, and the executor as a backstop, re-read the owner's report by key
  — `InstallationService.capability_statuses()` — on every call and refuse
  anything short of `on`, even if somehow requested), and the **prompt** (a
  `<permissions>` block, derived from the same report, tells the model which
  switches are on/off/blocked so it explains rather than guesses or
  retries). A dispatch refusal is audited as `tool_blocked` with one of
  three policies: `capability_off` (the owner switched it off),
  `capability_blocked` (switched on but unusable here — not installed, or
  no OS permission), or `capability_gate_error` (the owner's settings could
  not be read, so the tool is refused — fail closed; the recorded reason is
  fixed text, never the underlying error).
- `screen` (screen capture) is off by default, high risk, and additionally
  gated on the OS having granted screen-recording to the backend process;
  it reports "unavailable" rather than attempting capture inside a
  container (`CRAWLER_CONTAINER=1` in the compose files).
- Secrets the wizard stores — provider API keys and the Telegram bot
  token — are encrypted at rest the same way as connector credentials:
  AES-256-GCM via `core.security.encrypt_credentials` under
  `ENCRYPTION_KEY`, never returned by any API. A value set in `backend/.env`
  (a provider key, `TELEGRAM_BOT_TOKEN`) always overrides whatever the
  wizard has stored, so a compromised database cannot be used to redirect
  traffic to an attacker-controlled key when the environment pins one.
- Every capability, provider, Telegram and registration change is audited
  with the acting user.
- Open registration is the owner's switch (setup wizard, then
  `PUT /api/setup/registration` from Settings), closed by default. An
  explicit `ALLOW_REGISTRATION=false` in the environment locks it closed
  whatever the switch says, and the switch then cannot be changed (409).

## Approval flow

`requires_approval` tool calls are persisted to the `pending_actions` table
(`services/agent/approvals.py`) and surfaced in the chat and on the
dashboard. The store enforces, independently of the UI:

- **Ownership** — only the requesting user can decide the action.
- **Single use** — a decided action can never run twice.
- **Expiry** — undecided actions expire after `APPROVAL_TTL_MINUTES`
  (default 15) and can never run.

On approval the executor receives `approved=True`, which unlocks connectors
that demand per-call confirmation (`user_confirmed=True` is injected on
retry). A model-supplied `user_confirmed` argument is **stripped** before
dispatch, so the LLM cannot smuggle its own consent.

## Financial safety (four layers)

1. The permission engine hard-blocks the FINANCIAL category and a name
   deny-list (`trade`, `buy`, `sell`, `transfer`, `withdraw`, ...).
2. Hard-blocked tools are never offered to the model (`build_tools`).
3. The executor independently refuses FINANCIAL actions that somehow arrive.
4. The Robinhood connector itself raises `HardBlockError` for every
   trading/transfer method, and its network policy only allowlists
   read endpoints. MCP tools with financial-looking names are suppressed at
   discovery and blocked at dispatch.

## Prompt-injection defenses

Layered per current research (OpenAI instruction hierarchy, Microsoft
spotlighting, DeepMind CaMeL, OWASP LLM Top 10):

- **Instruction-hierarchy system prompt** — every conversation runs under a
  non-negotiable contract expressing an explicit chain of command (system >
  user > model > tool output), untrusted-data handling, hard limits (money
  never moves, approval-gated writes, no secret disclosure, no exfiltration),
  and tool-use rules. `services/agent/runtime.py`. On long conversations the
  security prompt is preserved: the rule-based history summary is a
  user-role message (never a second system message), and the Anthropic /
  Gemini adapters concatenate all system messages, so the policy can never
  be evicted from the single system slot.
- **Spotlighted untrusted-result envelope** — tool output returns to the
  model fenced by tags carrying a fresh per-turn random boundary token
  (`<tool_result_<nonce> ... trust="untrusted">`). A malicious result cannot
  forge the closing fence (it cannot predict the nonce), any collision is
  neutralized before wrapping, and tag attributes are sanitized — so
  injected content stays quarantined as data.
- **CaMeL-lite taint gate** — deterministic, server-side, model-independent.
  Values that enter from untrusted tool results are tracked across rounds;
  a side-effectful call auto-approved by the user's standing consent is
  re-escalated to the human approval flow when its arguments derive from
  that untrusted data (a redirected recipient/URL or a copied identifier).
  This closes the "injected instruction drives an auto-approved write" hole
  in code, not in the model. `services/agent/taint.py`.
- **PromptGuard scanning** — user input, tool arguments, tool results, and
  model output (including the post-tool completion) are scanned (pattern +
  heuristic layers: role hijack, instruction override, homoglyphs,
  zero-width chars, base64 payloads). `services/agent/prompt_guard.py`.
- **Normalization pre-pass** — regex guards are bypassed by *encoding*, not
  novel phrasing, so every layer runs against both the raw text and a
  canonical form (NFKC, zero-width stripped, homoglyphs folded,
  separator-spliced words like `i-g-n-o-r-e` collapsed), plus decoded
  base64/hex payloads. Detections found only after normalization are
  labeled `:normalized` so evasion attempts stay visible. Held to a 0%
  false-positive gate on a benign corpus that includes near-misses
  ("ignore the typo…"), hyphenated prose, and non-Latin script.
- **Approval-time argument scanning** — arguments are scanned *before* an
  action is parked for approval (an injection-laden action is refused, never
  offered for approval) and re-scanned at execution time, so what the
  approval card showed is binding. Actions whose arguments derive from
  untrusted content carry a `risk_note` the UI renders as a warning above
  the Approve button.
- **Connector-level sanitization** — connector and MCP responses pass through
  a regex scrubber that redacts common injection phrases before the LLM
  layer. `services/connectors/base.py`.
- **Memory screening** — saved memories are injected into every future
  system prompt, so a poisoned memory is a persistent injection. Memory
  content is scanned on write and rejected (422) if it trips the guard.
  `services/memory.py`.
- **Exfiltration-safe rendering** — the UI never auto-fetches model-emitted
  images (the EchoLeak channel) and never parses raw HTML; links are inert
  until clicked and show their destination host.
  `frontend/src/components/MarkdownMessage.tsx`.
- **Red-team regression suite** — a CI-friendly adversarial corpus asserts a
  100% detection floor and 0% false-positive ceiling against the guard, plus
  envelope-breakout cases. `backend/tests/test_prompt_injection_redteam.py`.

Streaming turns run through the same `runtime.chat` and therefore inherit
every layer above; the final answer is fully scanned before any of it is
streamed to the client.

These are mitigations, not proofs: pattern-based defenses can be bypassed.
The deterministic backstops — the taint gate and the approval flow — are
what a hijacked model cannot talk its way around: a sensitive action still
requires the human clicking Approve.

## Network security

`core/network_security.py`, enforced via an httpx request hook installed on
every connector client (covers redirects too):

- **SSRF protection** — outbound URLs resolve through a blocklist of private,
  loopback, link-local, CGN, multicast, and IPv4-mapped-IPv6 ranges; only
  http/https schemes are allowed. MCP requests get the same check.
- **The checked address is the connected address.** Checking a hostname and
  then letting the socket resolve it again leaves a window in which a
  hostile DNS server answers with a public address for the check and an
  internal one for the connection. MCP clients therefore *pin* the
  addresses that passed the check and dial only those; a host with no
  validated pin is refused rather than resolved, so the failure mode is
  closed. `services/mcp/client.py`, covered by
  `tests/test_mcp_dns_pinning.py`.
- **Per-connector allowlists (deny-by-default)** — Canvas may reach only
  `*.instructure.com` `/api/v1/` and the OAuth token endpoint
  `/login/oauth2/token`, Google only the specific googleapis hosts and
  paths, Robinhood only `trading.robinhood.com` read-only crypto paths
  (`/api/v1/crypto/trading/accounts/`, `/api/v1/crypto/trading/holdings/`,
  `/api/v1/crypto/marketdata/`) — order/trade endpoints are not
  allowlisted, so trades are blocked at the network layer as well.

## Audit log

- Every tool execution, block, pending approval, approval, denial, and
  expiry is written through one code path (`services/audit.py::append_audit_log`).
- **Account events share the chain.** Sign-ins, failed sign-ins, lockouts,
  account creation, sign-out, password changes (including refused ones) and
  refused account deletions are written through
  `services/audit.py::append_auth_event` under the `auth` connector name.
  They get the same property as tool rows: an adversary with database write
  access cannot quietly drop the failed attempts that preceded a successful
  sign-in without breaking a chain link. The refusal rows are committed
  before their HTTP error is raised, so the record does not roll back with
  the request that produced it. The one event that cannot be chained is a
  completed account deletion — the cascade that erases the account erases
  its audit rows, which is the correct outcome for an erasure request, so
  the durable record of it is the application log.
- Rows carry an **HMAC-SHA256** `integrity_hash` over a canonical payload
  that includes `previous_hash`, forming a per-user chain: field tampering,
  row deletion, and reordering all surface as mismatches. The hash covers the
  security-semantic columns — `reasoning_chain` (why an action was blocked),
  `detection_method`, and `confidence_score` — so a database-write adversary
  cannot rewrite a "blocked, critical threat" row into a benign one without
  breaking the hash. (`timestamp` is intentionally excluded because DB
  round-trip precision would cause false positives; ordering is instead
  protected by the `previous_hash` chain plus a monotonic per-user `seq`.)
- **The key is the threat model.** The hash is keyed with `AUDIT_HMAC_KEY`
  (derived from `ENCRYPTION_KEY` when unset). The guarantee is precisely:
  *an attacker who can write to the database but does not hold the key
  cannot forge history.* An unkeyed digest gave no such guarantee — anyone
  with DB write access could recompute the whole chain. Store the key
  separately from the database and its backups, or the guarantee is void.
  Set it before the first write: there is no key versioning.
- **Legacy rows are not "verified".** Entries written before this upgrade
  carry the old unkeyed SHA-256. `GET /api/audit/{id}/verify` reports them
  as `legacy: true, valid: false` — a third state, distinct from both
  keyed-verified and tampered. Calling them valid would have been a
  downgrade with teeth: an adversary with database write access can
  compute an unkeyed digest for a row they invent, so "valid" would have
  been available to anyone who could write the row. Only the keyed HMAC
  sets `valid`. The unkeyed path is additionally gated on `seq IS NULL`
  (every post-upgrade row has a seq), so a forged row that keeps a seq
  cannot reach the fallback at all. Run the whole-table verifier with
  `--require-hmac` to fail on any row that is not keyed.
- Verify per-row in the UI (expand a row → integrity check), via
  `GET /api/audit/{id}/verify`, or for the whole table with
  `python -m scripts.verify_audit_log` (add `--require-hmac` once every row
  post-dates the upgrade).
- A per-user asyncio lock prevents chain forks under concurrency **within a
  single process** — see deployment caveats below.

## MCP servers

Users can register external MCP servers (Streamable HTTP). Trust posture:

- Tools surface as `mcp.<server>.<tool>`; **every** call requires user
  approval, with no auto-approve tier.
- Financial-pattern tool names are never offered and are blocked at dispatch.
- Server URLs are SSRF-checked on every request; responses are sanitized
  like first-party connector output and wrapped in the untrusted envelope.

## Operational hardening

- Security headers on every API response (CSP, HSTS, nosniff, frame-deny,
  permissions-policy, no-store) — including throttled ones. The rate
  limiter short-circuits with its own 429, so it is mounted *inside* the
  header and request-id middleware; mounted outside, the one class of
  response an attacker can provoke on demand would be the only one served
  unhardened and untraceable. `backend/main.py`.
- The production SPA carries its own headers: nginx sets CSP (with
  `frame-ancestors 'none'`), `X-Frame-Options`, `nosniff`,
  `Referrer-Policy` and `Permissions-Policy` on the document it serves.
  That page is where a tool call gets approved, so a frameable UI is one
  where a click aimed at something else approves an action. The directives
  live in `location /` rather than at server level, because `add_header`
  also appends to proxied responses and would otherwise emit a second CSP
  next to the backend's on every `/api/` call. `docker/Dockerfile.frontend`.
- CORS restricted to configured origins with enumerated methods/headers.
- `X-Request-ID` correlation on every request; structured logging throughout.
- Generic 500 handler that never leaks stack traces to clients.
- Production deployment (`docker/docker-compose.prod.yml`): backend runs as
  a non-root user without hot reload or source bind mounts, the frontend is
  a static build served by nginx with an `/api` reverse proxy, Postgres and
  Redis are not published to the host, and the backend has a container
  healthcheck.

## Known gaps and remaining work

Tracked honestly so nobody mistakes this for finished security work:

- **Rotate the Gemini API key.** A real `GEMINI_API_KEY` existed in the local
  `backend/.env` during development (the file is gitignored, but
  `backend.env.save` was briefly tracked). In addition, the previous Gemini
  integration sent the key as a URL query parameter, so it may survive in
  request logs and proxies (this is now fixed — the key travels in a request
  header). Rotate it at https://aistudio.google.com/apikey and regenerate
  `SECRET_KEY` / `ENCRYPTION_KEY` before any deployment. Re-encrypting stored
  credentials is required after an `ENCRYPTION_KEY` change.
- **Single-process assumptions.** The HTTP rate limiter is now Redis-backed
  (shared across workers, with a per-process in-memory fallback if Redis is
  down), and audit-chain appends are serialized at the database with
  `SELECT ... FOR UPDATE` on the user row, so the chain is safe across
  workers. The per-connector rate limiters and the MCP tool cache are still
  per-process: behind multiple workers each enforces its own limit, so the
  effective ceiling is (workers x limit).
- **Sessions** — no MFA and no password reset flow, and the SPA stores the
  JWT in `localStorage` (an XSS foothold could exfiltrate it; CSP
  mitigates). Consider httpOnly cookies + CSRF protection. What is in
  place: `POST /api/auth/refresh` renews a still-valid token in place, so a
  session slides rather than dropping the user mid-sentence, bounded by
  `SESSION_MAX_HOURS` (default 12) measured from the original login — past
  that the user logs in again. It is deliberately not a refresh-token
  scheme: there is no second, longer-lived credential to steal. Changing
  the password revokes every outstanding token (each JWT carries a
  `token_epoch` claim checked against the user row). Signing out is
  client-side: the token stays technically valid until it expires, so
  password change is the lever for revoking access across devices.
- **OAuth UX** — Canvas/Google connectors accept pasted tokens; a proper
  redirect-based OAuth flow (the PKCE plumbing already exists in the
  connector classes) is the intended replacement.
- **Admin role** — the first account to register owns the deployment
  (`users.is_admin`). An `admin_only` connector is usable only by that
  account; for everyone else it contributes no tools at all. There is no UI
  to transfer or grant the role — change the column directly if you need to.
- **Migrations** — Alembic owns the schema (`backend/alembic/`). The
  production container runs `alembic upgrade head` before starting the
  server, and startup also upgrades so a bare `uvicorn main:app` dev run
  works unchanged. A database that predates Alembic is detected and
  stamped automatically on the next boot, so upgrading needs no operator
  action — see `backend/alembic/README.md`. Remaining gap: the upgrade
  runs in-process as well as in the container CMD, so a multi-worker
  deployment could race it; run the migration as its own deploy step if
  you scale out.
- **X-Forwarded-For trust** — XFF is honored only when the direct peer is
  inside `TRUSTED_PROXIES` (see "Rate limiting" above), so a directly
  reachable client cannot spoof its way into fresh rate-limit buckets. The
  shipped default still trusts every private range, which is wider than a
  single proxy needs; the per-account lockout is what bounds sign-in
  regardless, and narrowing the list is the follow-up. The
  production nginx proxy (`docker/Dockerfile.frontend`) additionally
  overwrites XFF with the real client address, and the prod compose does
  not publish the backend port at all — keep it that way; the nginx proxy
  is the only intended entry point.
- **TLS** — nothing in the compose stack terminates TLS. Put a
  TLS-terminating reverse proxy or load balancer in front of the frontend
  service before exposing it beyond localhost/LAN.

## Reporting

This is a student project under active development. If you find a
vulnerability, open a private GitHub security advisory on the repository
rather than a public issue.
