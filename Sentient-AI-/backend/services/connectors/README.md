# Connectors

Each connector is one module in this directory that ends with a `DEFINITION`
(a `ConnectorDefinition` from `definition.py`). `registry.py` lists every
definition in `REGISTRY`, validates them at import, and derives every table
that used to be written by hand:

| Derived from `REGISTRY` | Consumed by |
|---|---|
| Connector entries of `CONNECTOR_CATALOG` | `services/agent/tool_registry.py` (tools offered to the model) |
| `CREDENTIAL_REQUIREMENTS`, `NETWORK_POLICY_KEYS`, `create_connector` | `factory.py` (plus the hand-kept `mcp` entry) |
| Network allowlists (`DEFAULT_POLICIES[policy_key]`) | `core/network_security.py`, armed at import |
| Default permission rows | `services/agent/permissions.py` via `register_default_policies` (hand-written rows win) |
| `connector_types_payload()` | `GET /api/connectors/types`, which the Connectors page renders |

`mcp` and `custom` are not registry connectors: MCP servers are dispatched by
`services/mcp`, and `custom` cannot be created.

## Adding a connector

1. Copy `_template.py` to `<key>.py`. Rename the class, replace the endpoints,
   the `ACTIONS` tuple and the `DEFINITION`. The key is the `connector_type`
   stored in the database and the first segment of every tool name
   (`<key>.<action>`).
2. Add one line to `REGISTRY` in `registry.py`: `_load("<key>"),`.
3. Copy `tests/connectors/_template_test.py` to `tests/connectors/test_<key>.py`,
   delete its `pytest.skip(...)` line and fill in recorded responses shaped
   like the provider's documentation.
4. Run:

   ```
   .venv/Scripts/python.exe -m pytest tests/test_connector_registry.py tests/connectors/test_<key>.py -q -p no:cacheprovider
   ```

`tests/test_connector_registry.py` checks every definition automatically. The
frontend picks the connector up from `GET /api/connectors/types`, so no UI
code changes. Optional extras outside this directory: progress phrases in
`services/notifications/progress.py`, result budgets in
`services/agent/runtime.py` (`RESULT_CHAR_BUDGETS`, for actions that return
long text), and a line in `frontend/src/components/connectorIcons.ts` when
`DEFINITION.icon` names a lucide icon that map does not list yet (the card
shows a plug icon until then). A connector with OAuth sign-in also needs
its client id setting (see "Signing in with OAuth" below).

The tests use no real network and no real credentials: point
`connector._http_client` at `httpx.AsyncClient(transport=httpx.MockTransport(handler))`
and assert on method, host, `request.url.raw_path`, query and body. Cover
401, 403, 404, 429 (with and without `Retry-After`), 5xx, timeouts,
malformed JSON and pagination that ends early or loops, and check that
every non-READ action raises `UserConfirmationRequired` before any request
and that no token appears in a result or error.

## Rules the registry enforces

A bad definition stops the app at import with a list of every problem.

- **Key.** Matches `^[a-z][a-z0-9_]{1,31}$`, has no `__`, is unique, and is
  not reserved (`web`, `reminders`, `system`, `desktop`, `browser`, `skills`,
  `learnings`, `graph`, `tools`, `memory`, `mcp`, `custom`). Label,
  description and icon are not empty; `docs_url`, when set, is `https://`.
- **Uniqueness across connectors.** Permission keys, network policy keys and
  OAuth provider names each belong to one connector only.
- **Actions.**
  - Every action has a `required_scope` shaped `area.read` / `area.write`. A
    scope is used either by READ actions or by non-READ actions, never both.
  - FINANCIAL actions, and names on the global hard-block list (`transfer`,
    `buy`, `sell`, ...), are only allowed with `financial_ok=True`. They stay
    hard-blocked everywhere and never appear as grantable scopes.
  - Every DELETE sets `always_confirm=True`. Also mark every send, reply,
    post, comment, merge, publish, share and permission change
    `always_confirm`: it then gets an approval card under every tier.
  - Mark 2 to 4 everyday reads `starter=True` (at most 4, READ only).
  - No parameter is named `url`, `action` or `user_confirmed`.
- **Dispatch parity.** Every non-FINANCIAL action is a public coroutine on the
  connector class, and `_ACTIONS` (or a legacy `_ACTION_MAP`) lists exactly
  those names. The coroutine's keyword parameters equal the schema
  properties; a parameter without a default is `required` in the schema.
  Non-READ methods also take keyword-only `user_confirmed: bool = False` and
  raise `UserConfirmationRequired` before any request.
- **Network.** Every host (and every `redirect_hosts` entry) lists at least
  one path prefix starting with `/` (a host with none would allow every
  path). Hosts are bare lowercase names with at least two labels, and `*`
  only appears in the leftmost label. `https_only` is set for every
  connector except Canvas. OAuth token, device-code and revoke URLs are
  https and allowed by the spec.
- **Auth.** Methods are distinct values of `token`, `oauth`, `device`, in
  the order the Connectors page offers them. `token` needs credential fields
  (unique keys, at least one required); `oauth`/`device` need an `OAuthSpec`
  whose `client_id_setting` names a `Settings` attribute (never a literal
  id or secret) and whose `scope_map` maps every catalog scope and nothing
  else. `oauth` also needs an https `authorize_url`, `device` a
  `device_code_url`. An `OAuthSpec` without either method is refused.
- **Permissions.** Generated rows: READ auto-approve, WRITE/DELETE/EXECUTE
  user-confirm, FINANCIAL hard-blocked. `policy_overrides` may only name the
  connector's own policy keys, never use ADMIN_ONLY (the runtime adapter
  runs as a standard user, so it would block the action for everyone) and
  never loosen FINANCIAL.

## Module layout

See `_template.py`. In short: header docstring, `ACTIONS`, the connector
class (`_ACTIONS` from `ACTIONS`, `authenticate` stores the token without
network I/O, `_auth_headers`, `_execute_action` calls `self._dispatch`,
`health_check` makes one cheap authenticated GET), then `DEFINITION`. Use
`self._request` / `self._request_json` for HTTP, `path_segment()` for every
id placed in a URL path, and the helpers in `shaping.py` for limits, text
caps and pagination. Connectors that need something at construction time
override `from_credentials`; user-configured hosts go through
`policy_extra_hosts`; credential format checks go in `validate_credentials`;
rotated tokens are returned by `updated_credentials`; `revoke()` revokes the
grant at the provider after the connector is deleted, and runs only when the
class sets `SUPPORTS_REVOKE = True` (leave it False when the provider has no
revoke endpoint usable without a client secret). A grant another connector
still uses (the same token, or another sign-in through this install's OAuth
client) is never revoked; the deletion is audited as `skipped_shared`.

### Large connectors: `<key>_api/`

A connector whose module would pass about 700 lines splits its actions by
area into a package next to it, as `google_api/`, `microsoft_api/`,
`github_api/`, `notion_api/` and `slack_api/` do. Each area module (with the
same kind of header docstring) exports an `<AREA>_ACTIONS` tuple of
`ToolSpec`s and a mixin class holding those action coroutines; shared
constants and helpers go in a `common.py` or `client.py`. `<key>.py` then
assembles the class (mixins first, `BaseConnector` last), sets
`ACTIONS = AREA1_ACTIONS + AREA2_ACTIONS + ...` and
`_ACTIONS = frozenset(spec.action for spec in ACTIONS)`, and ends with
`DEFINITION`. The registry checks the assembled class, so a mixin method
that drifts from its schema fails at import.

### HTTP: `_request`, `_auth_headers` and `_static_headers`

`self._request(method, url, *, params=None, json=None, data=None,
content=None, headers=None, authorized=True, follow_redirects=False)` sends
through the connector's one httpx client, which checks the network policy
in a worker thread and dials only the DNS answers that passed the check. It
returns 2xx responses only. It retries once at most: a rate limit (429, or
a 403 carrying `Retry-After` or `x-ratelimit-remaining: 0`) after the wait
the provider asked for when that is 10 s or less (a short backoff when it
named none), and 502/503/504 or connection errors for idempotent methods
(GET, HEAD, OPTIONS, PUT, DELETE) only. Other
failures become `AuthenticationError` (401, 403), `RateLimitExceededError`
(429) or `ConnectorError`, with the status and a short vendor error code on
the exception (`status_code`, `vendor_code`) and in the message, never the
response body. `_request_json` adds JSON parsing (204 or empty is `{}`,
malformed is a `ConnectorError`). Tests stub `connector._sleep`.

Two header hooks, kept apart on purpose:

- `_auth_headers()` returns ONLY secrets (`Authorization`, an API key
  header). They are merged when `authorized=True`, count as credentials for
  the network policy (so a request carrying one can never reach a download
  host) and are scrubbed from error codes. A non-secret header left here
  would shut the download hosts a redirect-following call needs.
- `_static_headers()` returns non-secret headers sent on every request,
  `authorized=False` included: API versions and media types such as
  GitHub's `Accept` and `X-GitHub-Api-Version` or `Notion-Version`.

Download hosts (`NetworkSpec.redirect_hosts`) are reached only by GET and
only without our credentials. Providers that answer HTTP 200 with an error
body (Slack's `{"ok": false}`) must map it themselves to the same exception
types, with the vendor code only.

### Signing in with OAuth

A connector gets browser sign-in (`"oauth"`) and/or a device code
(`"device"`) by listing the method in `AuthSpec.methods` and declaring an
`OAuthSpec`: `provider` (the URL segment of `/api/oauth/<provider>/...`),
`token_url`, `authorize_url` and/or `device_code_url`, optional
`revoke_url`, `client_id_setting` (and `client_secret_setting` only when the
provider demands a secret), `scope_map` (catalog scope to provider scopes,
least privilege), `base_scopes` sent on every request (for example
`offline_access`), extra `authorize_params`, and `pkce` (default True).

The shared broker in `oauth.py` does the rest: the start, callback and
device routes (`api/routes/oauth.py`), the stored flow row, the code
exchange, the device poller, refresh 120 s before expiry (the executor and
the connection test call `ensure_fresh_credentials`), and the background
revoke after a delete. The connector itself only reads `access_token` from
its credentials. Stored OAuth credentials look like
`{"access_token", "refresh_token"?, "expires_at", "token_type",
"granted_scopes", "oauth_provider"}`.

The client id comes only from the environment: add the setting (default
`""`) to `core/config.py` and `backend/.env.example`, and document how to
register the app in `docs/connectors-setup.md`. With the setting empty the
page shows sign-in as not set up and the start route answers 503 naming the
variable. `oauth_config.redirect_uri(provider)` is the redirect URI to
register: `<OAUTH_REDIRECT_BASE>/api/oauth/callback/<provider>`.

### How the model finds a connector's tools

A request offers the model at most 24 tools. When a user's connectors add
up to more, the slots go to the core built-ins (`web.search`,
`web.fetch_page`, `reminders.now`, `tools.find`), then the tools this
conversation loaded, then `starter=True` actions, then the rest. The model
reaches everything else with `tools.find(query, connector?)`, which ranks
the tools the user can use this turn by words in the tool name (weight 3)
and description (weight 1) and loads up to 8 of them into the conversation
(`Conversation.loaded_tools`, at most 24 names). So: mark 2 to 4 everyday
reads as starters, and write action names and descriptions with the words
a user would say ("send an email", "list pull requests").
