# Connectors: design

Date: 2026-09-25. Branch: `feat/connectors-and-skills` (from `origin/main` at `5f6ddc1`).
Backlog items covered:
- **C1:** Google OAuth.
- **C3:** Microsoft 365.
- **F3:** approval cards never truncate arguments.
- **F4:** irreversible actions always ask. This spec covers the connector side of it.

The companion spec is `2026-09-25-skills-design.md`.

## 1. Goal

Crawler should be able to do everything a person can do in the five services people use
most, and do it without the supply-chain holes that let malware into OpenClaw.
**Adding a connector must be easy**: one new file in `backend/services/connectors/`, plus one
line in the registry. No other backend or frontend file needs to change (§3).

The owner chose these five on 2026-09-25:

| Connector | Scope |
|---|---|
| Google Workspace | Finish OAuth. Add Drive, Docs, Sheets and Contacts to Gmail and Calendar. |
| GitHub | Repos, issues, PRs, Actions, releases and notifications |
| Notion | Search, pages, databases and comments |
| Slack | Workspace tools, plus a chat channel like Telegram |
| Microsoft 365 | Outlook mail, calendar, OneDrive, To Do and contacts |

## 2. What we learned from OpenClaw

- **Integrations are shell commands.** OpenClaw integrates most services as *skills* that tell the model to run a CLI (`gh`, `gogcli`, `ntn`) through its `exec` shell tool. The CLI runs with the user's full privileges.
- **The malware used that path.** Every major incident used the shell and install path: Koi "ClawHavoc", with 341 and later 824 malicious skills; Snyk "ToxicSkills"; Cisco's #1-ranked malicious skill; and Unit 42's scanner evasion. In practice that meant a fake "Prerequisites" step that installed a stealer, a `curl | bash` one-liner, or silent `curl` exfiltration.
- **Our answer.** Our connectors are first-party code that calls each vendor's REST API. There is no shell, no installer and no vendor SDK. The skills spec covers the skill side of the same story.

## 3. Where connectors live, and how to add one

### 3.1 Layout

```
backend/services/connectors/
├── README.md          # how to add a connector (the steps in §3.3)
├── _template.py       # copy this to start a new connector
├── registry.py        # REGISTRY: one line per connector, plus validation and derived tables
├── definition.py      # ConnectorDefinition, AuthSpec, CredentialField, NetworkSpec
├── base.py            # BaseConnector (existing; gains allow-map dispatch and pinned HTTP)
├── factory.py         # create_connector, now driven by the registry (same public names)
├── oauth.py           # the OAuth broker (PKCE + loopback, device flow, refresh, revoke)
├── canvas.py          # existing, gains a DEFINITION
├── google_workspace.py# existing, extended, gains a DEFINITION
├── robinhood.py       # existing, gains a DEFINITION
├── github.py          # new
├── notion.py          # new
├── slack.py           # new
└── microsoft.py       # new
```

### 3.2 One file declares everything

Each connector module holds its connector class and a module-level `DEFINITION`:

```python
DEFINITION = ConnectorDefinition(
    key="github",                       # the connector_type stored in the DB and used in tool names
    label="GitHub",
    description="Repos, issues, pull requests, Actions and releases.",
    icon="github",                      # a frontend icon name; unknown names fall back to a plug
    auth=AuthSpec.device_flow(provider="github", ...) or AuthSpec.token(fields=(...)),
    network=NetworkSpec(
        https_only=True,
        hosts={"api.github.com": ("/",), "github.com": ("/login/device/code", "/login/oauth/access_token")},
        redirect_hosts={},              # pre-signed download hosts, GET only (§4.2)
    ),
    actions=(ToolSpec(...), ...),       # the tool catalog for this connector
    connector_class=GitHubConnector,
    docs_url="https://github.com/settings/personal-access-tokens/new",
)
```

`registry.py` imports each module and lists its `DEFINITION` in `REGISTRY`. Every table that is hand-written today is **derived** from the registry. The public names stay the same, because tests and other modules import them:

| Derived table | Today |
|---|---|
| The connector entries of `CONNECTOR_CATALOG` | hand-written in `tool_registry.py` |
| `CREDENTIAL_REQUIREMENTS`, `NETWORK_POLICY_KEYS`, the `create_connector` if/elif chain | `factory.py` |
| The connector entries of `DEFAULT_POLICIES` | `core/network_security.py` |
| The connector rows of `_DEFAULT_POLICIES` | `permissions.py` |
| The frontend `SERVICES` list, icon map and scope-risk guessing | replaced by `GET /api/connectors/types` |

Existing keys stay exactly as they are: `google` remains the Google network-policy key, and `gmail` and `google_calendar` remain Google's permission keys.

**Permission rows are generated from each action's category:**

| Category | Tier |
|---|---|
| READ | AUTO_APPROVE |
| WRITE | USER_CONFIRM |
| DELETE | USER_CONFIRM, and always-confirm (§4.4) |
| EXECUTE | USER_CONFIRM |
| FINANCIAL | HARD_BLOCKED |

New rows never use ADMIN_ONLY. The runtime permission adapter is built once for a standard user, so ADMIN_ONLY is blocked even for the owner at call time.

### 3.3 Adding a connector

1. Copy `backend/services/connectors/_template.py` to `<key>.py`. Fill in the class and `DEFINITION`.
2. Add one line to `REGISTRY` in `registry.py`.
3. Copy `backend/tests/connectors/_template_test.py` to `test_<key>.py` and fill in the recorded responses.
4. Run `pytest tests/test_connector_registry.py tests/connectors/test_<key>.py`.

`test_connector_registry.py` checks every definition automatically. The frontend picks the connector up from `GET /api/connectors/types`, so no UI code changes.

### 3.4 Registry validation

These checks run at import and again in `test_connector_registry.py`:

- **Key rules.**
  - The key matches `^[a-z][a-z0-9_]{1,31}$` and does not contain `__`.
  - It is not a built-in family (`web`, `reminders`, `system`, `desktop`, `browser`, `skills`, `learnings`, `graph`, `tools`) and not `mcp` or `custom`.
  - It is unique.
- **Action rules.** Every action has:
  - a `required_scope`, so no connector silently accepts any scope string;
  - a category other than FINANCIAL, unless the connector sets `financial_ok=True` (only Robinhood today, whose financial actions stay hard-blocked);
  - a name not in the global hard-block list (`transfer`, `buy`, `sell`, `deposit`, `wire` and the rest), because a match there is silently dropped;
  - no parameter named `url` or `action`, because `tool_call_facts` echoes those two keys into progress events.
- **Allow-map rules.** Every action name maps to a public coroutine on the connector class. That coroutine's keyword parameters equal the action's schema properties, plus `user_confirmed` for non-READ actions. The model's arguments become method keyword arguments, so this parity is checked, not assumed.
- **Network rules.**
  - Every host in `NetworkSpec` lists at least one path prefix. A host with no paths would otherwise allow every path.
  - The auth endpoints (token, device code, revoke) are inside the spec.
  - `https_only` is set for every new connector.
- **Auth rules.** OAuth definitions declare how each catalog scope maps to provider scopes.

### 3.5 The database column

`connector_configs.connector_type` changes from the Postgres `connector_type` ENUM to `VARCHAR(64)` in migration `0010_connector_type_string`. The new value is validated against the registry at the API boundary.

- **Postgres** uses `ALTER COLUMN … TYPE VARCHAR(64) USING connector_type::text` and then drops the enum type.
- **SQLite** uses `batch_alter_table`.
- **Guards.** Like revisions 0003 to 0009, it inspects the column first, so the adoption test's create_all, stamp, upgrade and downgrade sequence passes.
- **Downgrade** recreates the enum with the original five labels. Rows of new types are refused with a clear error.
- **Python.** The `ConnectorType` enum stays, for existing imports and comparisons. Code that read `.connector_type.value` now reads the plain string.
- **Unknown types.** A stored row whose type is no longer registered is listed as "unavailable" and never offered. It does not crash the connectors list, the health page, the account export or the chat turn.

### 3.6 Catalog endpoint

`GET /api/connectors/types` requires the signed-in user. It is declared before `/{connector_id}`. For each definition it returns:
- `key`, `label`, `description`, `icon` and `docs_url`;
- the auth kind (`token`, `oauth`, `device`);
- the credential fields (key, label, type, placeholder, required, hint);
- the read and write scopes, each with its risk;
- `creatable` (false for `custom`).

`Connectors.tsx` renders its cards and forms from this response. The rules the current forms enforce stay:
- read scopes are preselected;
- write scopes are opt-in;
- PATCH replaces credentials wholesale;
- rate-limit bounds are 1 to 600, with a default of 30.

## 4. Shared foundation

These rules apply to every connector. They are the "secure" half of the brief.

### 4.1 No vendor SDKs

Every connector calls the vendor's REST API through `BaseConnector`'s `httpx` client. There is one
new direct dependency, `websockets`, which is already installed as part of `uvicorn[standard]`. We
pin it in `requirements.txt` for Slack Socket Mode (§5.4) and dial it only through our own
pinned socket. No vendor package, post-install hook or vendor SDK is trusted.

### 4.2 Network policy hardening

Today connectors resolve DNS twice and fail open when no policy is set. This spec fixes both.

- **DNS pinning.** `BaseConnector._get_client` uses `PinnedHTTPTransport`, which the MCP client and web tools already use, fed by `resolve_public_addresses`. It runs through `asyncio.to_thread`, so DNS no longer blocks the event loop. `PinningUnavailable` is a refusal, never a fallback to an unpinned client.
- **Fail closed.** `_enforce_network_policy` raises when no policy key is set, instead of returning.
- **HTTPS only.** `NetworkPolicy` gains `https_only`, which also refuses non-443 ports. Every new connector sets it.
- **Most specific match.** Host matching checks exact hosts before wildcards, whatever order they are listed in. It also adds a restricted **leftmost-label glob**, such as `productionresultssa*.blob.core.windows.net`, for vendor download hosts.
- **Download redirects.** `redirect_hosts` allow pre-signed download redirects (GET only, never with our Authorization header) for:
  - GitHub Actions logs, which redirect to Azure blob storage;
  - OneDrive `/content`, which redirects to `*-my.sharepoint.com` and `*.files.1drv.com`;
  - Notion files on S3;
  - Drive export hosts.

  Everything else stays deny-by-default. Where a vendor offers a raw response (GitHub `Accept: application/vnd.github.raw`), the connector uses it instead of following a redirect.
- **WebSockets.** A separate `ws_hosts` list covers WebSocket endpoints. Slack Socket Mode uses `wss-primary.slack.com` and `wss-backup.slack.com` as exact hosts. They are checked by `check_websocket_policy`, which does not widen the global `http`/`https` scheme allowlist.
- **Tests.** Existing tests monkeypatch `core.network_security.check_ssrf` by module attribute, so the checker keeps calling it that way.

### 4.3 OAuth broker (`services/connectors/oauth.py`, `api/routes/oauth.py`)

One broker serves every provider.

- **Redirect URI.** It is `http://127.0.0.1:3000/api/oauth/callback/<provider>`. Port 3000 is the only published port in both the production stack and the desktop app, and nginx proxies `/api/` to the backend. A new `OAUTH_REDIRECT_BASE` setting (default `http://127.0.0.1:3000`) lets other deployments change it. The dead `localhost:8000/oauth/callback` defaults in the Canvas and Google classes are removed.
- **Starting a flow.** `POST /api/oauth/<provider>/start` requires the signed-in user and a connector draft (display name, scopes, tier). It creates an `oauth_states` row:
  - a random 32-byte `state` (stored as a hash);
  - the PKCE S256 verifier, encrypted;
  - the user id and provider;
  - the requested catalog scopes and the draft fields;
  - an expiry 10 minutes out.

  The route returns the provider's consent URL. The browser opens it in the system browser, because the desktop app sends non-Crawler URLs there.
- **Callback.** `GET /api/oauth/callback/<provider>?code&state` cannot require a bearer token, because it is a browser redirect. The `state` row is what binds it to the user.
  - The row is single-use: it is deleted inside the same transaction that saves the connector.
  - The code is exchanged through a connector instance that has the network policy armed.
  - The granted provider scopes are stored in the credentials.
  - The route returns a static HTML "Connected, you can close this tab" page, with `Referrer-Policy: no-referrer` and no inline script, which the CSP forbids anyway.
  - It is rate-limited like the auth routes.
  - Errors return the same page with a generic message. The code and state are never logged.
- **Status.** The UI polls `GET /api/oauth/<provider>/status?flow=<id>` every 3 seconds, like the Telegram link flow does. It never uses `window.opener`.
- **Device flow** is used for GitHub, and as a fallback for Microsoft on headless machines.
  - `POST /api/oauth/<provider>/device` returns `user_code` and `verification_uri`.
  - The backend polls the token endpoint in a background task at the provider's interval.
  - The UI polls the same status endpoint.
  - This also works from Telegram: the bot can send the code.
- **Tokens.**
  - The access token, refresh token, expiry and granted scopes live in `encrypted_credentials`.
  - Every OAuth connector implements `updated_credentials(original)`, which captures rotated refresh tokens (Microsoft rotates on every refresh) and removes `code` and `code_verifier`.
  - Canvas starts persisting its rotated token too.
  - The `/test` route persists refreshed tokens, and `health_check` may refresh once.
- **Revoke on disconnect.** Deleting a connector commits first. Then it calls the provider's revoke endpoint (Google, GitHub, Slack `auth.revoke`, Notion has none) as a best-effort task, and audits the result. It never revokes before commit, because a failed commit would leave a live row with dead credentials. Account deletion revokes every connector the same way.
- **Client IDs.** New settings `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` (a Desktop-app secret, which Google treats as non-confidential), `MICROSOFT_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_ID`. They are resolved `.env`, then an encrypted Installation column, then the shipped default, the same way the Telegram token is resolved. The owner can override them in Settings ▸ Server.
- **Pasted tokens.** Notion and Slack use pasted tokens (§5.3, §5.4), because their OAuth needs an HTTPS redirect and a confidential secret. GitHub also accepts a pasted fine-grained token.
- **Incremental consent.** A missing scope comes back to the model as a clear tool error that names the scope. The connector card offers "Grant <scope>", which starts a new OAuth flow for the extra scope. Google uses `include_granted_scopes`.
- **Redaction.** `audit.py`'s sensitive-value patterns learn the new token formats, so they are redacted if they ever appear in arguments or results:
  - Slack: `xoxb-`, `xoxp-`, `xapp-`;
  - GitHub: `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`;
  - Notion: `secret_`, `ntn_`;
  - Google: `ya29.` and `1//`;
  - Microsoft: `EwB` and refresh tokens.

### 4.4 Actions, categories and always-confirm

- Every action is a `ToolSpec` with a category and a `required_scope`.
- `ToolSpec` gains `always_confirm: bool`. An always-confirm action gets an approval card under every tier, including an auto-approve account default. It is enforced at three layers, because the current auto downgrade happens in the first:
  1. `build_tools` never relabels it as "auto".
  2. `RuntimePermissionAdapter` returns `requires_approval` for it.
  3. The executor refuses it when `approved` is false.
- **Always-confirm actions:**
  - every DELETE;
  - every send, reply, forward or post that leaves the user's account: email, Slack posts, GitHub comments, PR reviews and Notion comments;
  - merging a PR, committing to a default branch, publishing a release, dispatching or cancelling a workflow;
  - sharing or permission changes: Drive `share_file`, OneDrive `create_share_link`, GitHub `add_collaborator`.
- **Relation to the "user choice" rule.** Always-confirm is an approval card, not a block, so it fits the owner's "user choice over hard limits" rule. Letting sends to known recipients run unattended needs the arguments passed into the permission check, which the runtime does not do today. That is listed as a follow-up in §11.
- **Untruncated cards (F3).** Approval cards show every argument in full. The Telegram card no longer cuts arguments at 700 characters: it splits long cards into several messages, and each card ends with a hash of the exact arguments. The Slack card does the same.
- Write methods keep the existing contract: a keyword-only `user_confirmed=False` that raises `UserConfirmationRequired` before any request.

### 4.5 Offering tools at scale

Today the model is offered at most 15 tools, chosen alphabetically after three core tools, so most connector tools would never be seen. The array must also stay byte-identical from turn to turn, because it is part of the cached prompt prefix. The new selection is deterministic and stable within a conversation:

1. **Core tools.**
   - These are the existing three.
   - `tools.find` is new: an always-on READ built-in in the `tools` family.
   - `skills.read` is added when the `skills` capability is on.
2. **Loaded tools.**
   - These are tools this conversation has already loaded through `tools.find` or used.
   - They are stored on the conversation in a new `loaded_tools` JSON column, capped at 24 names with the oldest dropped first.
3. **Starter tools.**
   - These come from each connected connector.
   - `ToolSpec` gains `starter: bool`. Each connector marks two to four everyday reads, such as `github.list_issues` or `google_workspace.search_emails`.
4. **Everything else** is reachable through `tools.find`.

The cap rises from 15 to 24. `tools.find(query, connector?)` returns up to eight matching tool names with their one-line descriptions, and adds them to `loaded_tools`. The runtime rebuilds the offered array before the next model round of the same turn. The array therefore changes only when the model loads something, not on every turn.

- **What still works unchanged.** Dispatch keeps its current rule: a tool that was not offered but is named still passes every permission and capability check.
- **The prompt.** `SECURITY_SYSTEM_PROMPT` stops hard-coding connector setup instructions. It says "use `tools.find` to discover actions for a connected service".
- **Result budgets.** `RESULT_CHAR_BUDGETS` gains entries for long results: `github.get_pr_diff`, `github.get_failed_logs`, `notion.get_page`, `google_workspace.get_file_text` and `microsoft.get_file_text`.

### 4.6 Untrusted content and cost

- **Untrusted results.** Every result passes through `PromptGuard` and counts as untrusted tool output for the taint tracker. Emails, issues, Notion pages and Slack messages are the channels an attacker controls.
- **Output shaping.** Each action returns only the fields the model needs. Bodies are plain text with a size cap per action and a "truncated, call X for more" hint. Lists default to 10 items, with a hard maximum of 50.
- **Path segments.** Every id placed in a URL path uses `path_segment()`.
- **Error text.** `BaseConnector.execute` stops echoing `exc.response.text[:300]`, because a vendor error body can echo a token. It now reports the status code and a vendor error code where one is present. Tests assert that no token appears in any error.

### 4.7 Testing

Each connector has `backend/tests/connectors/test_<key>.py`, built on `httpx.MockTransport` through the existing `connector._http_client` injection. Tests assert:
- the method, host, `raw_path` and query of every request, and that no token appears in results or errors;
- that write actions raise `UserConfirmationRequired` before any request;
- the pagination caps and the output shaping;
- the refresh and `updated_credentials` behaviour;
- that the network policy refuses an off-list host and an off-list redirect (through `_enforce_network_policy`).

`test_connector_registry.py` checks the contract in §3.4 for every registered connector. No test calls a real vendor.

## 5. The five connectors

Tool names are `<key>.<action>`. The keys are `google_workspace`, `github`, `notion`, `slack` and `microsoft`. Actions marked † are always-confirm.

### 5.1 Google Workspace (`google_workspace.py`, extended; finishes C1)

**Auth:** the OAuth broker, with PKCE and a loopback redirect. **Permission keys:** the existing `gmail` and `google_calendar`, plus new `google_drive`, `google_docs`, `google_sheets` and `google_contacts`.

| Area | READ | WRITE | DELETE |
|---|---|---|---|
| Gmail | search_emails, get_message, get_thread, list_labels, get_attachment_text | send_email†, reply†, forward†, create_draft, send_draft†, modify_labels | trash_message† |
| Calendar | get_events, check_availability, list_calendars | create_event, update_event, respond_to_invite | delete_event† |
| Drive | search_files, get_file_text, list_folder | upload_file, create_folder, move_file, rename_file, share_file† | trash_file† |
| Docs | get_document | create_document, append_text, replace_text | |
| Sheets | get_values, get_metadata | update_values, append_rows, add_sheet | clear_range† |
| Contacts | search_contacts, get_contact | create_contact, update_contact | delete_contact† |

### 5.2 GitHub (`github.py`)

**Auth:** the device flow with Crawler's OAuth App, or a pasted fine-grained personal access token. Scopes are `repo`, `workflow`, `read:org` and `notifications`, each mapped to catalog scopes.

| Area | READ | WRITE | DELETE |
|---|---|---|---|
| Repos | list_repos, get_repo, get_file, list_tree, search_code, list_branches, list_commits, compare | create_repo, create_branch, put_file (non-default branch; a default branch is †) | delete_branch† |
| Issues | list_issues, get_issue, search_issues, list_comments | create_issue, comment†, update_issue | |
| Pull requests | list_prs, get_pr, get_pr_diff, get_pr_checks, list_reviews | create_pr, review_pr†, request_reviewers, merge_pr† | |
| Actions | list_runs, get_run, get_failed_logs | rerun_failed_jobs, dispatch_workflow† | cancel_run† |
| Other | list_notifications, list_releases, get_release | mark_notification_read, create_release (draft), publish_release†, create_gist | |

`delete_repo` is deliberately absent.

### 5.3 Notion (`notion.py`)

**Auth:** an internal integration token, pasted. It sees only the pages the user shares with the integration. **Header:** `Notion-Version` pinned to `2022-06-28`.

| READ | WRITE | DELETE |
|---|---|---|
| search, get_page (properties plus blocks rendered as Markdown), get_block_children, query_database, get_database, list_comments, list_users | create_page, append_blocks (from Markdown), update_page_properties, create_database_row, update_block, add_comment† | archive_page†, delete_block† |

### 5.4 Slack (`slack.py`, plus `services/notifications/slack.py`)

**Auth:** Crawler ships a Slack app manifest in `backend/services/connectors/slack_manifest.json`. The card links to Slack's "create app from manifest" page. The user pastes:
- the bot token, `xoxb-`;
- the app-level token for Socket Mode, `xapp-`;
- optionally a user token, `xoxp-`, which only search needs.

**Workspace tools:**

| READ | WRITE | DELETE |
|---|---|---|
| list_channels, get_history, get_thread, search_messages (user token), list_users, get_user, get_file_info | post_message†, reply_in_thread†, add_reaction, upload_file†, set_status, create_channel, invite_to_channel, schedule_message† | delete_message†, archive_channel† |

Every post forces `unfurl_links=false` and `unfurl_media=false` at one choke point, so Slack never fetches private URLs.

**Chat channel (`services/notifications/slack.py`).** It mirrors the Telegram channel and reuses the shared appliers.

- **Connection.** A Socket Mode client connects to the URL returned by `apps.connections.open`. That URL is validated by `check_websocket_policy`, dialled through a pinned socket with redirects off, and every envelope is acknowledged within 3 seconds. The work runs in tracked tasks under a per-chat lock, like Telegram's.
- **Authorisation before anything else.** Only `channel_type == "im"` DMs are accepted. The sender must not be a bot, and `team_id` must match the configured workspace. A button press is checked against `payload.user.id`. An unlinked sender gets no reply.
- **Linking.** Linking uses a one-time code: `token_urlsafe(24)`, valid for 10 minutes, single-use, with a unique index, and exclusive, so linking a Slack user detaches them from any other account. The code lives in new `users.slack_link_code`, `slack_link_expires_at` and `slack_user_id` columns, added in migration `0011`.
- **Conversation.** A DM runs `build_chat_applier` with a `channel="slack"` parameter. The Slack thread is the conversation titled "Slack", separate from "Telegram". The appliers gain the channel name, instead of the hard-coded Telegram title.
- **Approvals.** Approval cards are Block Kit Approve and Deny buttons, decided through `build_decision_applier` and never by writing to the table directly. `NotifyingApprovalStore` fans out to every running channel, and a failed notification never blocks the approval. Reminder delivery fans out the same way.
- **Lifecycle.** `SlackManager` mirrors `TelegramManager`: it serialises start and stop, stops the old client before starting a new one, and is wired in `main.wire_services` with a `slack` change topic.
- **Capability.** A new `slack` capability sits beside `telegram`. `ReportContext` gains `slack_configured: bool = False`.
- **Single-process note.** Two processes on one Slack app token would split events silently, so the channel runs only in the web worker. The README documents this.

### 5.5 Microsoft 365 (`microsoft.py`, C3)

**Auth:** PKCE with a loopback redirect, on a multi-tenant public client with no secret, with the device flow as fallback. **Scopes** are requested incrementally: `Mail.ReadWrite`, `Mail.Send`, `Calendars.ReadWrite`, `Files.ReadWrite`, `Tasks.ReadWrite`, `Contacts.Read` and `offline_access`.

| Area | READ | WRITE | DELETE |
|---|---|---|---|
| Mail | list_messages, search_messages, get_message, get_attachment_text, list_folders | send_mail†, reply†, forward†, create_draft, move_message, flag_message | delete_message† |
| Calendar | list_events, find_meeting_times, list_calendars | create_event, update_event, respond_to_invite | delete_event† |
| OneDrive | search_files, get_file_text, list_folder | upload_file, create_folder, move_file, create_share_link† | delete_file† |
| To Do | list_task_lists, list_tasks | create_task, update_task, complete_task | delete_task† |
| Contacts | search_contacts | | |

The key is `microsoft`. It must not be `graph`, which is the skills spec's built-in family.

## 6. Frontend

- **Settings ▸ Connectors** is driven by `GET /api/connectors/types`.
  - Each type shows one card and one "Connect" flow. OAuth opens the system browser and polls. The device flow shows the code with a copy button and polls. Token paste shows the typed fields and a docs link. For Slack it also shows the manifest link.
  - The card lists read and write scopes with their risk from the backend, plus "Grant more" for incremental consent.
  - The shared icon map and catalog helpers live in plain `.ts` modules, because of the `react-refresh/only-export-components` lint rule.
- **Settings ▸ Server** gains the OAuth client-ID overrides and the Slack channel token status, next to Telegram.
- **Tests.** Every `vi.mock("@/services/api")` factory that renders these pages gains the new exports.

## 7. Error handling

- **Refresh fails.** `AuthenticationError` makes the result say "Reconnect GitHub in Settings ▸ Connectors", and the card shows "Needs reconnect".
- **Missing scope.** The result names the scope, and the card offers "Grant". The tool description tells the model not to retry.
- **Rate limits.** On a 429, or a GitHub secondary rate limit, the connector honours `Retry-After` once if it is 10 seconds or less. After that it returns a clear error and does not loop.
- **Unknown connector type in the DB.** The row is shown as unavailable and never offered.
- **OAuth state problems.** A state that expired, was reused or does not match returns the generic callback page and an audit event.

## 8. Build order

Each step ends with the backend and frontend suites green, ruff, mypy, eslint and tsc clean, and new tests for everything the step adds.

1. **Registry.** `definition.py`, `registry.py`, `DEFINITION`s for canvas, google_workspace and robinhood, the derived tables, the `0010` string-column migration, the `types` endpoint and the catalog-driven `Connectors.tsx`. Behaviour is unchanged, and the existing tests pass.
2. **Safety rails.** `always_confirm` at three layers, untruncated cards, audit token patterns, the error-text redaction, DNS pinning, fail-closed policy, `https_only`, most-specific host matching, leftmost-label globs, `redirect_hosts` and `ws_hosts`.
3. **Tool offering.** `tools.find`, `loaded_tools` (migration), starter tools, the cap of 24, and the prompt changes.
4. **OAuth broker.** The `oauth_states` table, the routes, device flow, refresh persistence, revoke-after-commit, client-ID settings and the UI flows.
5. **GitHub and Notion.** These are token-based.
6. **Google Workspace**, extended.
7. **Microsoft 365.**
8. **Slack**: tools first, then the Socket Mode channel.

Steps 5 to 8 are independent once 1 to 4 have landed.

## 9. Documentation to update

- `docs/CODE-MAP.md`: the connector and tool-family recipes.
- `backend/services/capabilities/README.md`.
- `docs/team-handoff-2026-09-23.md`: the built-in recipe.
- `SECURITY.md`: the permission model, the network allowlists by connector, and the OAuth gap.
- `README.md`: the integrations list and the action count.
- `backend/alembic/README.md`: the enum checks.
- `docs/BACKLOG.md`: the status of C1, C3, F3 and F4.
- The Windows CI job's test list: add the registry and connector tests.

## 10. Open items for the owner

- **Google verification.** Gmail read and send are "restricted" scopes. Until Google verifies Crawler's OAuth client, which needs a security assessment, a shipped client is capped at 100 test users and shows an "unverified app" screen. For the investor presentation and early users, the owner can use their own Google Cloud client through the Settings ▸ Server override.
- **App registrations.** Someone with the company accounts must register:
  - the Google Desktop client;
  - the Microsoft multi-tenant public client;
  - the GitHub OAuth App, with the device flow enabled.

  Their public client IDs then go into config. The Slack manifest needs no registration.

## 11. Follow-ups, out of scope here

- **Argument-aware confirmation**, for example auto-send to known recipients. It needs the arguments passed into `RuntimePermissionAdapter.check`.
- **A per-user permission adapter**, so that ADMIN_ONLY works for the owner at call time.
- **Multi-worker deployments** for the channel pollers and the executor rate limiters.

## 12. Sources

- OpenClaw skills and exec docs: https://github.com/openclaw/openclaw/blob/main/docs/tools/skills.md
- OpenClaw channels: https://docs.openclaw.ai/channels
- Koi ClawHavoc: https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html
- Snyk ToxicSkills: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
- Cisco: https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare
- Unit 42: https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
