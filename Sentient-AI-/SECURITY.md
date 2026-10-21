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
  Token formats are matched wherever they appear inside a string: Slack
  (`xoxb-`, `xoxp-` and the other `xox?-` kinds, `xapp-`), GitHub
  (`github_pat_`, `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`), Notion
  (`secret_`, `ntn_`), Google (`ya29.` access tokens, `1//` refresh tokens,
  `GOCSPX-` client secrets), Microsoft (`EwB...` personal access tokens,
  `M.C...`/`M.R...` personal refresh tokens and codes, `0.A`/`1.A` work and
  school refresh tokens) and full JWTs. Prefixes that also occur in prose
  need a long unbroken body, so ordinary words survive. Keys named
  `code_verifier`, `device_code` or `client_secret` are redacted, and so is
  a key that is exactly `code`, `state`, `auth_code` or `oauth_code`/
  `oauth_state` (matched whole, so `statement` or `zip_code` are kept).
  Covered by `tests/test_audit_token_patterns.py`.

## Permission model

Two cooperating mechanisms decide what the agent may do:

**Action tiers** (`services/agent/permissions.py`) classify every catalog
action (READ / WRITE / DELETE / EXECUTE / FINANCIAL) per connector:

| Tier | Meaning |
|------|---------|
| `auto_approve` | Runs immediately (read-only actions on trusted services); on a connection, changes run without a card except anything graded HIGH |
| `low_risk`     | On a connection ("Allow low-risk changes"): only actions graded LOW run without a card |
| `user_confirm` | Parked until the user approves it |
| `admin_only`   | Usable only by the deployment owner (`users.is_admin`); contributes no tools at all for anyone else |
| `hard_blocked` | Never runs, not configurable |

Robinhood reads are `user_confirm` — even *viewing* financial data requires
consent per action. All FINANCIAL category actions are `hard_blocked`.

Connectors declared in `services/connectors/registry.py` get generated
default rows (READ `auto_approve`, WRITE/DELETE/EXECUTE `user_confirm`,
FINANCIAL `hard_blocked`); a hand-written row in `permissions.py` always
wins, and the registry refuses any FINANCIAL row that is not
`hard_blocked`. The gmail, google_calendar and github DELETE rows are
`user_confirm` (they were `admin_only`), so the approval card can appear.

**Always-confirm actions.** Some actions get an approval card under every
tier, even on a connector the user set to `auto_approve`: every DELETE (the
registry refuses a DELETE without the flag), and every send, reply,
forward, post, comment, review, merge, file write that may land on a
default branch, release publish, workflow dispatch, run cancel, share and
share link. The flag (`ToolSpec.always_confirm`) is enforced at three
independent points in `services/agent/tool_registry.py`: `build_tools`
never offers such a tool as auto-run, the runtime permission adapter turns
an "approved" decision into "requires approval", and the executor refuses
the call unless a human approved it, before any rate-limit slot or network
request is spent. Connector methods for non-READ actions also raise
`UserConfirmationRequired` before any request unless the executor passes
the approval through.

**Risk grades and standing consent** (`services/agent/risk.py`,
`services/agent/permission_grants.py`). Every connector call gets a grade
computed in code from its catalog entry and the arguments actually sent;
the model never grades anything. READ is LOW; DELETE, EXECUTE, FINANCIAL
and always-confirm actions are HIGH; a WRITE is MEDIUM unless its spec opts
into LOW (`risk="low"`: drafts, stars and your own labels, private events
without guests, new files and folders at the top of a drive, new docs and
contacts, To Do tasks, reading GitHub notifications). Arguments can only
escalate: Gmail's TRASH or SPAM, an Outlook move to Deleted Items or Junk,
guests on an event and a public gist or repository are HIGH; archiving and
mark-read, a folder and an overwrite are MEDIUM; an argument the action
does not take is MEDIUM; a check that fails is HIGH. Built-in and MCP tools
are HIGH. Standing consent is then decided per call, after the permission
check and never in an unattended turn:

- `auto_approve` runs a call unless it grades HIGH (a HIGH call gets a card
  with a plain risk note, which tightens the tier: it no longer runs
  invitations, trash moves or workflow re-runs unattended).
- The `low_risk` tier, or a 7-day grant the owner gave from a card ("Allow
  low-risk changes on <account> for 7 days", per user and connection, not
  per channel), runs a call only when it grades LOW, the owner's switch
  "Make low-risk changes without asking" (`low_risk_actions`) is on, and
  fewer than 10 such runs happened this turn; the reply then ends with a
  "Done without asking" line built from tool names and account labels.
- Any tool result PromptGuard flags suspends all standing consent for the
  rest of the turn.
- The taint gate still applies; a LOW call may name an object id only when
  the same connection returned it this turn in an `id` field (`ref_args`).
- The executor re-grades the arguments it sends and re-checks the tier, the
  grant and the switch before any rate-limit slot or network request.

A grant is offered only on an untainted, attended card for a LOW action with
no origin; it is re-checked when the button is pressed, audited
(`permission_grant_granted`; revoked if that row cannot be written), listed
and revoked in Settings, Telegram `/grants` and Slack `grants` / `revoke
grants`, taken back when the connection's credentials are replaced, it is
reconnected or a scope is added, and deleted with the connection or the
user. Tier changes are audited (`connector_tier_changed`,
`account_tier_changed`).

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
changes, Install optional software, Telegram, Slack chat and approvals)
set in the setup wizard or Settings → Permissions, on top of the action
tiers and scopes above.

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

**Weekly app approvals** (`services/agent/app_approvals.py`, spec
`docs/superpowers/specs/2026-09-25-weekly-app-approvals-design.md`): a
`desktop.act` card in an app on `rules.WEEKLY_APPS` (Calendar, Reminders,
Notes, Contacts, Clock, Calculator and similar local apps with no store; no
text editors) also offers "Allow <app> for 7 days". Pressing it approves the
card and lets later acts in that one app that only look around in it
(scrolling, switching to it, navigation keys, clicks on cells, tabs and
buttons like "Next month") run without a card, until the week is up. Typing,
and clicks on anything that changes or sends something (Send, Decline,
Share, Delete, Save), keep their card. Such an act never brings its app
forward, and never switches apps while the owner may be typing a password
in the front app. The approval
is tied to the channel it was given from: the linked Telegram chat (checked
again against the account's linked chat on every turn), or one browser, by a
random device id the web app sends as `X-Crawler-Device` and the server keeps
only as a SHA-256. A turn from anywhere else, or with no channel, gets cards
as before. What still applies inside an allowed app: every computer-control
hard rule, the prompt-guard argument scan, and the taint gate (an act whose
arguments came from untrusted tool data gets a card with the risk note).
Browsers, mail and chat apps, stores and file managers are never on the list,
so money and messages keep a card per action. Approvals are listed and
revoked from Settings → Permissions and Telegram `/apps`; unlinking Telegram
revokes the ones given from it. Grants, revocations and every act a weekly
approval ran are audited (`app_approval_granted`, `app_approval_revoked`,
`approval: "weekly"` on the act's rows). A grant the audit log cannot record
is taken back.

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
  in code, not in the model. `services/agent/taint.py`. Telegram messages
  the owner forwards to the bot are fenced as someone else's words, so the
  taint gate and tool rule B1 treat their addresses and links as untrusted,
  and are never run as commands (a forwarded `/start CODE` links nothing).
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

### Pre-dispatch call checks (security wave)

Every tool call passes one ordered pipeline of checks
(`services/security/call_checks.py`: tool rules, MCP tool pins, browser site
rules, outbound messages, file reputation) in the agent turn after the secret
guard, again when its card is approved, and once more as a backstop in the
executor. A check can add a note to the approval card, turn a call that would
have run without a card into a card (and withdraw any standing consent for
it), or refuse the call before any card; nothing lets a call skip a card. A
check that fails or times out is only logged for a read; for any other call
it means a card (with a note saying the check could not run) in the turn,
and a refusal at approval and in the executor.
Notes are typed (a kind, a severity, one sentence with control and
direction-override characters removed), stored on the card and shown on the
web, Telegram and Slack, and a card with a warning never offers "Allow for 7
days" or "Allow low-risk changes".

### Outbound message checks

Before anything Crawler writes leaves the account, S1 removes the characters a reader cannot see
that are used to smuggle text: Unicode tag characters, bidi overrides and isolates, long runs of
zero-width characters and meaningless variation selectors in the text other people read and in
every MCP argument, and tag and bidi characters from every other argument of every write (names
included). This floor runs at the approval card and again right before dispatch, on every path,
whatever the owner's switch says, so no card shows text the owner cannot see and nothing hidden
reaches another person. A recipient address that hides any such character is refused before any
card. With "Check messages before they go out" on (the default), the card also says who the
message really goes to (first time Crawler sends there, outside the organisation, a look-alike of
a familiar address, the real recipients of a reply or a saved draft) and which links can carry
data out (images that load by themselves, long coded values, link text naming another site, the
owner's Google lookup); a flagged call that would have run without a card gets one, and a card
with a warning never offers standing consent. "Could not check" is always said; nothing is called
safe. The sent-to history keeps per-user keyed fingerprints (HMAC under a key derived from
`ENCRYPTION_KEY`), never an address; only `scheme://host/` of a link is handed to the link
lookup, and nothing leaves without the owner's key.

### Scam checks when asked

Crawler can check a message, link, screenshot or QR code for signs of a scam when someone asks
(`/scam` in a web chat, Telegram or Slack, Security ▸ Check for scams, or the
`security.check_scam` tool in a chat turn). The checked message is someone else's words: it is
checked outside the chat turn, sent to the account's own AI provider inside a fence with a fixed
preamble, and stored fenced, so its links and addresses stay untrusted in later turns. Crawler's
fixed rules decide the verdict; the AI can raise it but never lower it, the advice comes from a
fixed table, and the AI's own reasons are dropped when they hold a link, a domain, an address, a
phone number or wording aimed at an AI (a scanner error withholds them all). No answer says
"safe", and no link in an answer is clickable (defanged in Telegram and Slack, code text on the
web, punycode for look-alike letters). Links go to Google Safe Browsing / Web Risk only with the
owner's key; files are looked up by fingerprint only. Pictures are never stored; audit rows hold
verdicts, counts, codes and sha256s, never the text, a link or a host.

### MCP tool pinning

Crawler remembers a fingerprint (sha256 of a canonical form) of what every tool of a connected MCP
server says it does: its name, description and input schema exactly as the server sent them, plus
its title, annotations and output schema when present. While "Hold changed MCP tools for review"
is on (the default), a tool whose definition changes, or a new tool on a server already in use, is
not offered to the AI, and the call check and the dispatcher refuse to run it, until the owner has
seen the exact difference on Security ▸ MCP reviews and approved that version; an approval names
the hash that was shown and is refused if the server changed the tool again. The dispatcher checks
a fresh tool list before every call, so a change made after the approval card was shown is still
caught. Invisible characters (zero-width, bidi controls, Unicode tag characters) are removed from
every tool description and schema before the model reads them and shown to the owner as labelled
chips with the text they spell. Changes are told on the owner's linked chats by tool name only,
never with the server's words. A server seen for the first time is trusted as it is (trust on
first use), and pinning fails closed: if the pins cannot be read or written, the server's tools are
withheld.

### Tool rules

Every tool call's arguments are checked against four built-in rules and the owner's own rules
before it runs, and a call that breaks one waits for the owner's approval on a card that names
the rule; a rule never blocks a call outright and can never let one skip a card. The built-in
rules ask before a send, share or invite to an address that appeared only in content Crawler
read (an email, a web page, a file, a forwarded message or Crawler's own earlier replies) or that
uses look-alike characters, before one action addresses more than 10 people, before a forward,
share or invite outside the owner's organisation, and before a change that includes a link to a
site seen only in read content. Owner rules (Security → Tool rules, owner only, web only) match a
tool glob and up to five argument conditions; values are normalised (invisible characters,
fullwidth and look-alike letters) so a spliced word cannot dodge a rule, patterns pass a static
safety check that bounds their cost, and anything that cannot be checked asks. The executor
refuses a write a rule matches that no person approved, with a fixed text that never tells the
model the rule. Removing a rule or turning a built-in off notifies the owner on Telegram and
Slack; every change is audited with ids, names and a digest, never a condition value.

## Network security

`core/network_security.py`, enforced via an httpx request hook installed on
every connector client. Connectors do not follow redirects by default; a
download call that opts in follows at most three, and every hop runs the
same hook. A connector with no network policy set refuses every request
(fail closed), and the check (which resolves DNS) runs in a worker thread
so it never blocks the event loop.

- **SSRF protection**: outbound URLs resolve through a blocklist of private,
  loopback, link-local, CGN, multicast, and IPv4-mapped-IPv6 ranges; only
  http/https schemes are allowed. MCP requests get the same check.
- **The checked address is the connected address.** Checking a hostname and
  then letting the socket resolve it again leaves a window in which a
  hostile DNS server answers with a public address for the check and an
  internal one for the connection. Connector clients, MCP clients and the
  web tools therefore *pin* the addresses that passed the check and dial
  only those (`core/http_pinning.py`); a host with no validated pin is
  refused rather than resolved, and a transport that cannot be pinned is a
  refusal, never a fallback. Covered by `tests/test_mcp_dns_pinning.py` and
  `tests/test_connector_pinning.py`.
- **Policy rules**: `https_only` policies refuse plain http and any port
  but 443; exact hosts are matched before wildcards regardless of list
  order; a `*` glob is allowed only in the leftmost label and never
  crosses a dot; a host with no path prefixes allows nothing. Download
  hosts (`redirect_hosts`) are reachable only by GET without our
  credentials. WebSocket endpoints are checked separately
  (`check_websocket_policy`: wss, port 443, exact hosts, public addresses)
  without widening the http/https scheme allowlist.
- **Error text**: connector errors report the HTTP status, a short vendor
  error code and a fixed hint, never the vendor's response body (which can
  echo a token).
- **Per-connector allowlists (deny-by-default).** Each connector's
  `NetworkSpec` (in its module, turned into a policy by
  `services/connectors/registry.py` at import) names exact hosts and path
  prefixes; the registry refuses a host with no path prefix, and every
  connector except Canvas is https-only. Canvas may reach only
  `*.instructure.com` (or the Canvas host the user configured) `/api/v1/`
  and the OAuth token endpoint `/login/oauth2/token`. Robinhood only reaches `trading.robinhood.com`
  read-only crypto paths (`/api/v1/crypto/trading/accounts/`,
  `/api/v1/crypto/trading/holdings/`, `/api/v1/crypto/marketdata/`): order
  and trade endpoints are not allowlisted, so trades are blocked at the
  network layer as well. Google reaches only the Gmail, Calendar, Drive,
  Docs, Sheets and People API paths plus its OAuth token, revoke and
  consent endpoints. Microsoft reaches only `graph.microsoft.com/v1.0/me/`
  and the `login.microsoftonline.com` token and device-code endpoints.
  GitHub reaches the `api.github.com` paths its actions use and the
  `github.com` device-code and token endpoints. Notion reaches only the
  `api.notion.com/v1/` endpoints its actions use. Slack reaches
  `slack.com/api/` and its file upload host, and its Socket Mode sockets
  may open only to `wss-primary.slack.com`, `wss-backup.slack.com` and
  `wss.slack.com`. File downloads that redirect (OneDrive content, GitHub
  Actions logs) may follow only to the listed storage hosts, by GET,
  without our credentials.

### Owner keys for outside security services

Google Safe Browsing or Web Risk, Have I Been Pwned and VirusTotal are used
only with the owner's own key, entered in Security → Service keys (or set in
`.env`, which wins). A key is tested before it is stored, stored encrypted
(AES-256-GCM) and never sent back to the browser; without a key nothing is
sent to that service. The one keyless lookup is the Pwned Passwords range
check, which sends only the first five characters of a password's SHA-1
hash, through this server. Each service's requests go through its own
network policy and the SSRF-checked client.

### Link reputation

Links in mail alerts, scam checks, outgoing messages and pages Crawler's browser opens are
checked on this server for look-alike letters, brand imitations, bare IP addresses, credentials
before an "@", shorteners, script links and link text that names another site, reading each link
the way a browser does. With the owner's own Google Safe Browsing or Web Risk key (and the
"Check links with Google Safe Browsing" switch on), links are also looked up in Google's list of
dangerous sites. Only the link is sent, in a reduced form: for the browser only the site's
scheme and host; otherwise the path without userinfo or fragment, and the query only when it
carries nothing that looks like a token, a code, a session id, a secret or an e-mail address.
Non-public hosts are never sent. The key travels in a request header through the
`link_reputation` network policy and the SSRF-checked client; verdicts are kept in memory only,
within Google's stated cache lifetime; logs never carry a link, host or key. A lookup that fails
never blocks anything and is reported as "not checked"; no answer is ever called "safe". The
browser refuses only a page Google lists.

### Breach monitoring

Crawler can watch the owners' email addresses for new data breaches with Have I Been Pwned, using
the owner's own key (Security → Service keys); without a key nothing is sent, and the owner can
turn it off in Settings → Permissions. Only owner accounts are watched: each owner's sign-in
address plus at most 10 addresses they add, looked up once a week, paced to the key's rate
limit. Addresses are stored encrypted (AES-256-GCM) and found by a keyed HMAC, never in plain
text; no log line, audit row or error message carries an address or the key, which travels only
in a request header. The request goes through the SSRF-checked client under a network policy
that allows only HIBP's two API paths over HTTPS, and the SSRF check sees only the host, so the
address never reaches a log. Alerts are fixed sentences (no model), go only to the owner's own
linked Telegram and Slack chats, never name a breach HIBP marks sensitive, and defang the
vendor's text so the attribution is the only link. The password check on the same page hashes
the password in the browser and sends only the first 5 hex characters of its SHA-1 to Crawler,
which asks Pwned Passwords for every suffix with that prefix (padded) and hands the list back;
the match is made in the browser. The password never leaves the browser, and nothing about a
check is kept: no cache, no audit row, and no log line with the prefix or the number of entries.
The proxy is limited to 20 checks a minute per user.

### Site rules for Crawler's browser

The owner can mark sites **Blocked**, **Always ask** or **Trusted** (Security → Site rules, owner
only; never from chat). Banks, brokers, crypto exchanges and tax and government portals (161 sites)
are Always ask by default. The rules are enforced at four points: the pre-dispatch call checks
(a browser or web page call, a new page watch or a web page saved to the knowledge base on a
Blocked site is refused before anything starts, and again when a card is approved; an act on an
Always-ask site carries a "sensitive site" note and never runs without a card), the browser egress
guard after its SSRF check (navigations, redirect hops, popups and frames), the observe step (a
page on a Blocked site is blanked and never described), and the resolver of every other page
fetcher (every hop of a web fetch, research source or screenshot, of a knowledge-base web import,
and of each background page-watch check, so a watch saved before its site was Blocked stops
fetching it). Inside an approved
checkout's order window or 3-D Secure hand-off, a Blocked verdict is set aside only for protected
sign-in, CAPTCHA and payment hosts and hosts on the built-in banks list; Blocked rules over those
protected hosts are refused outright. Hosts are read the way Chromium reads them, so a rule cannot
be evaded by spelling a host differently, and every reading is linear in the URL's length. Rules
that cannot be read fail closed for the browser and web page tools, page watches and knowledge-base
web imports. Hosts reach the audit log only
as keyed hashes (HMAC-SHA256 under a key derived from `ENCRYPTION_KEY`); nothing is sent anywhere.

### File reputation

Crawler can look files up in VirusTotal with the owner's own key (Security → Service keys);
without a key, or with "Check files with VirusTotal" off in Settings → Permissions, nothing is
hashed, stored or sent. Only a file's SHA-256 is sent automatically, through the SSRF-checked
client under a network policy that lets the lookup reach only `GET /api/v3/files/<sha256>` on
`www.virustotal.com` over HTTPS (uploads and analysis polls have their own policy); the key
travels only in the `x-apikey` header and never appears in a URL, log line, audit row or
response. Answers are cached, VirusTotal's limits are kept in a request log written before each
request, and only stats, dates, a sanitised threat label and the type description are read from
an answer (names, tags, comments and vendor texts never are). A file is uploaded only after its
own approval card, which says that VirusTotal shares uploads with security companies; at
approval the bytes are fetched again and must hash to the card's fingerprint, the neutral name
`file` is sent, and a restart, a changed file or a missing key sends nothing. Personal documents
are never kept for an upload and cannot be proposed from a chat. Telegram file ids and mail
message references are stored encrypted (AES-GCM) and mail message ids only as an HMAC; audit
rows carry fingerprints, counts and codes, never a file name, message id or key. The upload tool
is never offered to an unattended run. A rejected key pauses lookups for 10 minutes and alerts
the owner at most once a day.

## Scam and phishing checks on new email

Crawler checks every new email in each connected Gmail and Outlook inbox for signs of a scam
(switch "Check new email for scams" in Settings → Permissions, on by default; the first check of
each account only records where the inbox is). The checks run on this computer: the receiving
provider's own topmost Authentication-Results (lower copies, which a sender can forge, are never
read), look-alike and mixed-script sender domains, Reply-To domains, links whose text names
another site, code links, forms, risky and disguised attachments, pressure wording, hidden
characters and text aimed at AI assistants, plus the link reputation service when its key is set
(URLs sent without query, fragment or user name, at most five per email, one per site). Mail
that is not flagged leaves only a 16-character hash. Only flagged mail reaches an AI provider,
and only an excerpt of at most 1,500 characters with link hosts (never full links), inside the
untrusted-data fence, with contact details replaced by placeholders for a cloud provider; a local
Ollama can be set with `MAIL_REVIEW_OLLAMA_MODEL`. Reviews have their own daily cap per person and
never use the shared budget for tasks run while away. The review can make a finding stricter but
never silence it: a weak finding goes quiet only when the sender authenticated, every sign is
weak and the review found none, and an answer carrying instructions is withheld. Alerts are
fixed sentences (the review's lines are stripped of links, addresses and phone numbers and
checked by PromptGuard), defang every domain, withhold a subject that reads like instructions,
never quote the body and never call an email safe. Nothing in the mailbox changes without an
approval card (Move to Spam/Junk, parked with the same checks as any card); Block sender is not
offered. Audit rows hold ids, counts and signal codes only.

## Connector sign-in (OAuth broker)

Google, Microsoft and GitHub connectors can be connected by signing in
instead of pasting a token. One broker handles every provider
(`services/connectors/oauth.py`, routes in `api/routes/oauth.py`, flow rows
in the `oauth_states` table):

- **No secrets in source.** Client ids (and Google's secret) come only from
  `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`,
  `MICROSOFT_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_ID` in the
  environment (`services/connectors/oauth_config.py`), default empty. An
  empty one leaves that sign-in unavailable, and the start route answers
  503 naming the variable, never a value. Microsoft and GitHub are public
  clients with no secret; Google's "Desktop app" secret is one Google itself
  does not treat as confidential, and it still stays out of the repository.
  Setup: `docs/connectors-setup.md`.
- **State.** Each browser sign-in gets 32 random bytes of `state`. Only its
  HMAC-SHA256 is stored, keyed from `ENCRYPTION_KEY` under its own domain
  label, so a database reader cannot complete someone's flow. A flow expires
  after 10 minutes and is single use: exactly one callback can move it out
  of `pending` (a conditional update), and a replay is refused and audited
  as `state_reused`. A user may have at most 10 sign-ins in flight.
- **PKCE.** Every browser sign-in sends an S256 code challenge; the
  verifier (64 random bytes) is stored encrypted and wiped when the flow
  completes.
- **Fixed redirect URI.** The redirect URI is built only from
  `OAUTH_REDIRECT_BASE` (validated at boot as a bare `http(s)` origin: no
  path, query, fragment or user info) plus `/api/oauth/callback/<provider>`,
  never from the request's Host header, so a forged header cannot send a
  code elsewhere. Our parameters also override any `authorize_params` a
  connector declares.
- **The callback page.** `/api/oauth/callback/<provider>` is the one
  connector route without a bearer token (the stored state is what binds it
  to a user). It returns static HTML with no script, the same body for every
  failure, and never echoes the code or state. It is sent with
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and it
  shares the stricter login rate-limit bucket.
- **Access-log scrubbing.** The callback URL carries the code and state, so
  the query string is stripped from uvicorn's access-log lines for that
  path (`core/logging_config.py`), and the production nginx logs that
  location with the path only and no Referer, keeping only `crit` error
  lines there (`docker/Dockerfile.frontend`). The broker's own log lines
  name flows by id and carry no code, state, verifier, device code or
  token.
- **Strict token handling.** Token responses are validated (types, sizes,
  positive expiry) and stored encrypted like every other credential. A
  provider's error text is never shown to the user; the status route
  reports fixed messages and only ever shows a user their own flows. When
  the token response lists the granted scopes, the connector records only
  those, so a permission the user declined on the consent screen never
  becomes a tool; a sign-in that granted none of the requested scopes
  fails.
- **Refresh.** Before a tool call or connection test, an access token that
  expires within 120 s is refreshed under a per-connector lock and saved
  before use. A refused refresh token asks the user to reconnect; a refusal
  of the server's own client (`invalid_client` and similar) says so
  instead, since reconnecting cannot fix it. A call the provider refuses as
  unauthenticated gets at most one forced refresh and one retry; a 403 (a
  missing scope) never does.
- **Revoke on delete.** Deleting a connector commits first, then revokes
  its grant at the provider in the background (best effort, audited as
  `oauth_revoked`). Google and Slack have revoke endpoints that need no
  client secret. GitHub (its revoke needs the app's secret), Microsoft (the
  only option signs the user out everywhere) and Notion (internal
  integrations have none) do not, so the user removes the grant on the
  provider's site.
- **Audit.** Completed sign-ins (`oauth_connected`, with the granted scopes)
  and failed ones (with a short reason code) are written to the user's audit
  chain.

## Slack DM channel

A user can chat with Crawler and approve actions in a Slack DM, using the
bot and app-level tokens stored on their own Slack connector
(`services/notifications/slack.py`, `slack_manager.py`, owner switch
"Slack chat and approvals"):

- **Linking.** The connector card mints a one-time code (10 minutes, 5 per
  minute per user, only its HMAC stored, compared in constant time). The
  Slack account that DMs that code to the Crawler bot becomes the only one
  the channel serves; Slack user ids are never taken from the browser.
- **Every event is checked** before anything else: it must be a DM, written
  by a person (no bot, no subtype), in the workspace the bot token belongs
  to, from the linked Slack user. Slack Connect partner teams and
  redelivered events are dropped. Anyone else gets no reply.
- **Socket.** The Socket Mode URL is checked with `check_websocket_policy`
  (wss, port 443, the three Slack hosts, public addresses) and dialled at
  the validated address with TLS checked against the real host name. The
  URL carries a ticket and is never logged, and neither is any token.
- **Approvals** use the same decision pipeline as the web and Telegram, and
  the card shows every argument in full with the arguments digest.
- **One socket per Slack app.** Slack hands each event to any one open
  connection of an app, so connectors sharing an app are grouped and only
  one runs; the others report `app_token_in_use`.

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
- **Consent phishing.** The state ties a callback to the user who
  *started* a sign-in; whoever approves the consent links *their* provider
  account to the starter's connector. For browser sign-in this is closed
  off: with the default loopback `OAUTH_REDIRECT_BASE`
  (`http://127.0.0.1:3000`) only a browser on the server's machine can
  finish a flow, and with any other base the start response sets an
  HttpOnly, SameSite=Lax cookie scoped to the callback path (an HMAC of the
  state), and a callback without it ends the flow before the code is
  exchanged. A device-code sign-in (GitHub, and Microsoft's fallback)
  cannot be bound this way (RFC 8628 section 5.4): on a shared server, a
  registered user could send someone their `user_code` and receive that
  person's grant. The code is shown only to the user who started the flow.
  An owner who does not trust every account on a shared server can leave
  `GITHUB_OAUTH_CLIENT_ID` empty so GitHub is connected with pasted tokens.
- **Sign-in coverage.** Canvas, Notion, Slack and Robinhood still take
  pasted tokens only, and GitHub also accepts a pasted token. Client ids come
  from the environment only; an owner setting for them in the UI is not
  built yet.
- **Revoke gaps.** Deleting a GitHub, Microsoft or Notion connector cannot
  revoke its grant (see "Revoke on delete"), and Slack's app-level token
  (`xapp-`) can only be deleted on the Slack app's page. The user removes
  those grants on the provider's site.
- **Coarse provider scopes.** GitHub's OAuth `repo` scope is read and write
  on every private repository the user can reach. Crawler's own catalog
  scopes still decide which tools exist, but the stored token could do
  more; a fine-grained personal access token limited to chosen
  repositories is the least-privilege option. `workflow` is never
  requested.
- **Google app status.** A Google OAuth app left in "Testing" issues
  refresh tokens that expire after 7 days, and an unverified app shows
  Google's warning screen; see `docs/connectors-setup.md`.
- **Slack DM channel.** One backend process per install: two processes (or
  two deployments) on one Slack app would split its DMs and button presses
  at random. Two different app-level tokens of the same Slack app, pasted
  with two different bot tokens, cannot be detected and would split too.
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
