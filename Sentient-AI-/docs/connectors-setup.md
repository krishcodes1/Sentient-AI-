# Connector setup for the owner

This guide is for whoever runs a Crawler AI install. It explains the one-time
setup some connectors need on the server side: registering an OAuth app with
Google, Microsoft or GitHub so users get a "Sign in" button, and creating the
Slack app and Notion integration users paste tokens from. Everything here
matches the code in `backend/services/connectors/` (each connector's
`DEFINITION`) and `backend/core/config.py`.

Users then connect their own accounts on the **Connectors** page. Nothing in
this guide gives the server access to anyone's data by itself.

## At a glance

| Connector | Needs server setup? | Environment variables | How users connect |
|---|---|---|---|
| Google Workspace | Only for "Sign in with Google" | `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` | Sign in with Google, or paste an OAuth token |
| Microsoft 365 | Yes (sign-in is the only way) | `MICROSOFT_OAUTH_CLIENT_ID` | Sign in with Microsoft, or sign in with a code |
| GitHub | Only for "Sign in with a code" | `GITHUB_OAUTH_CLIENT_ID` | Sign in with a code (device flow), or paste a fine-grained token |
| Slack | No | none | Paste the tokens of a Slack app created from the manifest |
| Notion | No | none | Paste an internal integration secret |
| Canvas, Robinhood | No | none | Paste a token (see the hint on each card) |

All sign-in settings live in `backend/.env` (see `backend/.env.example`) and
default to empty. Never commit real values. After changing `backend/.env`,
restart the backend; under Docker run `docker compose up -d backend` (a plain
`docker compose restart` does not re-read the file).

While a client id is empty, the service's card on the Connectors page says
sign-in is not set up on this server, and the sign-in start route answers
503 with a message naming the missing variable (never a value). Pasting a
token still works where the service offers it.

## The redirect URI

After consent, the provider sends the browser to:

```
<OAUTH_REDIRECT_BASE>/api/oauth/callback/<provider>
```

- `OAUTH_REDIRECT_BASE` defaults to `http://127.0.0.1:3000`, the address the
  app is served on (the frontend on port 3000 forwards `/api/` to the
  backend in development and in the production image). It must be an
  `http(s)` origin with no path, query or fragment; the backend refuses to
  start otherwise.
- `<provider>` is `google`, `microsoft` or `github`.
- So with the default, the redirect URIs are:
  - `http://127.0.0.1:3000/api/oauth/callback/google`
  - `http://127.0.0.1:3000/api/oauth/callback/microsoft`
  - `http://127.0.0.1:3000/api/oauth/callback/github` (GitHub only uses the
    device flow, but its form asks for a callback URL)

The backend builds this URI only from `OAUTH_REDIRECT_BASE`, never from the
incoming request, so it must match what you register exactly. If people
reach the app at another address (for example `https://crawler.example.com`
behind a TLS proxy), set `OAUTH_REDIRECT_BASE` to that origin and register
the matching URIs instead.

The default loopback address has a security benefit: only a browser on the
same machine can finish a sign-in. With any other base, starting a sign-in
sets a short-lived cookie for the callback path, and only the browser that
holds it can finish that sign-in. So people must open Crawler at exactly
`OAUTH_REDIRECT_BASE` (same host name) and approve the sign-in in that same
browser. Device-code sign-in cannot be bound this way (see "Known gaps" in
`SECURITY.md`).

## Least privilege, in general

- Crawler's own permissions ("catalog scopes" such as `gmail.read` or
  `mail.send`) decide which tools exist for a connector. A sign-in asks the
  provider only for the provider scopes of the permissions the user ticked;
  by default that is every read permission and nothing else. "Grant more
  access" on the card adds permissions later without starting over.
- When the provider reports which scopes it granted, Crawler records only
  those, so a permission the user declined on the consent screen never
  becomes a tool.
- Deletes, sends, posts, merges, publishes and shares always show an
  approval card, whatever approval tier the user picks.

## Google (Sign in with Google)

Crawler uses a Google OAuth client of type **Desktop app**, with PKCE. Google
does not treat a Desktop app's client secret as confidential, but it still
belongs in `backend/.env` only.

1. In the [Google Cloud console](https://console.cloud.google.com/), create
   a project (or pick one) for this install.
2. Enable the APIs the connector calls (APIs and Services, Library):
   **Gmail API**, **Google Calendar API**, **Google Drive API**, **Google
   Docs API**, **Google Sheets API** and **People API**. You can leave out
   the ones for areas nobody will grant.
3. Configure the OAuth consent screen (in newer consoles: Google Auth
   Platform, Branding and Audience):
   - User type **Internal** if everyone signs in with accounts of your own
     Google Workspace organization, otherwise **External**.
   - For External apps in "Testing", add every user's Google address under
     test users.
4. Create the client (Credentials, Create credentials, OAuth client ID):
   application type **Desktop app**. Copy the client id and secret into
   `backend/.env`:

   ```
   GOOGLE_OAUTH_CLIENT_ID=<client id>.apps.googleusercontent.com
   GOOGLE_OAUTH_CLIENT_SECRET=<client secret>
   ```

   A Desktop app client has no redirect URI field: Google accepts loopback
   addresses such as `http://127.0.0.1:3000/api/oauth/callback/google` for
   it. If you set `OAUTH_REDIRECT_BASE` to an address that is not loopback,
   Google needs a client of type **Web application** instead, with
   `<OAUTH_REDIRECT_BASE>/api/oauth/callback/google` listed as an authorized
   redirect URI. Its secret is confidential: keep it only in `backend/.env`.
5. Restart the backend. The Google card now offers "Sign in with Google".

Crawler asks Google for offline access with a fresh consent each time, so
it receives a refresh token. It refreshes the access token shortly before it
expires and saves the new one. Deleting the connector revokes the grant at
Google, unless another Google connector on this install signed in through
the same OAuth client (Google revokes per account and client, so that
connector would stop working too); the user can then remove access at
myaccount.google.com/permissions.

**Scopes.** Each Crawler permission maps to one Google scope (all under
`https://www.googleapis.com/auth/`):

| Crawler permission | Google scope | Notes |
|---|---|---|
| `gmail.read` | `gmail.readonly` | |
| `gmail.send` | `gmail.send` | send only, cannot read |
| `gmail.compose` | `gmail.compose` | drafts, reply, forward |
| `gmail.modify` | `gmail.modify` | labels, move to trash |
| `calendar.read` | `calendar.readonly` | |
| `calendar.write` | `calendar.events` | events only, not calendar settings |
| `drive.read` | `drive.readonly` | |
| `drive.write` | `drive` | full Drive access; there is no narrower scope for editing existing files |
| `docs.read` / `docs.write` | `documents.readonly` / `documents` | |
| `sheets.read` / `sheets.write` | `spreadsheets.readonly` / `spreadsheets` | |
| `contacts.read` / `contacts.write` | `contacts.readonly` / `contacts` | |

**Limits of an unverified app.** Several of these scopes are ones Google
calls "sensitive" or "restricted" (`gmail.readonly`, `gmail.compose`,
`gmail.modify`, `drive` and `drive.readonly` are restricted). Publishing an
External app that
requests them needs Google's verification, and restricted scopes also need
a security assessment. Without verification:

- An app in **Testing** works only for the test users you listed (at most
  100), and Google issues refresh tokens that **expire after 7 days**.
  Crawler then reports that Google Workspace needs to be reconnected, and
  the user signs in again with Reconnect on the card.
- An app set to **In production** but not verified shows Google's "Google
  hasn't verified this app" warning (users continue through "Advanced"), and
  Google caps how many users can grant it.
- An **Internal** app (Google Workspace organizations only) needs no
  verification and has neither limit, but only accounts of that
  organization can sign in.

For a personal or small install, Testing with your own addresses listed is
the simplest route; plan on reconnecting weekly, or use Internal if you have
a Workspace organization.

## Microsoft 365 (Sign in with Microsoft)

Crawler signs in through Microsoft's `common` endpoint, so one app
registration serves work, school and personal accounts. It is a **public
client**: no client secret. Users can sign in in the browser (PKCE) or with
a device code on a machine without a browser.

1. In the [Microsoft Entra admin center](https://entra.microsoft.com/), go
   to App registrations, New registration.
2. Supported account types: **Accounts in any organizational directory and
   personal Microsoft accounts**.
3. Redirect URI: platform **Public client/native (mobile and desktop)**
   (shown as "Mobile and desktop applications" under Authentication), URI
   `http://127.0.0.1:3000/api/oauth/callback/microsoft` (or your own
   `OAUTH_REDIRECT_BASE` plus that path). Do not use the "Web" or "Single-page
   application" platforms: Crawler redeems the code from the server without
   a secret, which Microsoft allows only for public client redirect URIs.
4. Under Authentication, Advanced settings, set **Allow public client
   flows** to **Yes**. The device code option needs it.
5. Copy the **Application (client) ID** into `backend/.env`:

   ```
   MICROSOFT_OAUTH_CLIENT_ID=<application id>
   ```

6. Restart the backend.

Adding API permissions in the portal is optional: Crawler asks for the
delegated Microsoft Graph permissions below at sign-in. Listing them under
API permissions lets a tenant administrator grant consent ahead of time.
Work and school tenants may require an administrator to approve any new app,
depending on their user consent settings; personal accounts approve it
themselves.

**Scopes.** `offline_access` is always requested (it provides the refresh
token). Then, per Crawler permission:

| Crawler permission | Graph permission (delegated) |
|---|---|
| `mail.read` | `Mail.Read` |
| `mail.write` | `Mail.ReadWrite` (drafts, move, flag, delete) |
| `mail.send` | `Mail.Send` (send, reply, forward) |
| `calendar.read` | `Calendars.Read` (also covers finding meeting times) |
| `calendar.write` | `Calendars.ReadWrite` |
| `files.read` | `Files.Read` |
| `files.write` | `Files.ReadWrite` |
| `tasks.read` / `tasks.write` | `Tasks.Read` / `Tasks.ReadWrite` |
| `contacts.read` | `Contacts.Read` |

Microsoft has no endpoint that revokes a single app's grant, so deleting the
connector cannot revoke it. Users remove the app at
[myapps.microsoft.com](https://myapps.microsoft.com) (work and school) or
[account.live.com/consent/Manage](https://account.live.com/consent/Manage)
(personal).

## GitHub (Sign in with a code)

GitHub sign-in uses the **device flow** of a GitHub **OAuth App**: the card
shows a code, the user enters it at github.com, and the backend picks up the
token. No client secret is needed or used.

1. On GitHub: Settings, Developer settings, **OAuth Apps**, **New OAuth
   App** (under an organization's settings if the organization should own
   it).
2. Fill in a name and homepage URL. The form requires an **Authorization
   callback URL**; enter `http://127.0.0.1:3000/api/oauth/callback/github`
   (the device flow never uses it).
3. Register the app, then tick **Enable Device Flow** and save.
4. Copy the **Client ID** into `backend/.env` (do not generate a client
   secret; Crawler does not use one):

   ```
   GITHUB_OAUTH_CLIENT_ID=<client id>
   ```

5. Restart the backend.

**Scopes.** GitHub's OAuth scopes are coarse:

| Crawler permissions | GitHub scope |
|---|---|
| `repo.read` | `repo`, `read:org` |
| `repo.write`, `repo.create`, `issues.*`, `pulls.*`, `actions.*`, `releases.*` | `repo` |
| `notifications.read`, `notifications.write` | `notifications` |
| `gists.write` | `gist` |

`repo` is read **and** write access to every private repository the user can
reach, even when the user granted Crawler only read permissions. Crawler's
own permissions still decide which tools exist, but the stored token could
do more. The `workflow` scope is never requested, so with the device sign-in
Crawler refuses to change files under `.github/workflows/` and says why (a
fine-grained token with the Workflows permission can). For least privilege, users
can instead paste a **fine-grained personal access token** limited to chosen
repositories and permissions (Contents, Issues, Pull requests, Actions and
Metadata; read-only unless they want changes). Notifications need the
sign-in or a classic token.

Organizations that restrict OAuth App access must approve the app before
their repositories show up. Deleting the connector cannot revoke a GitHub
token (GitHub's revoke call needs the app's client secret); users remove the
app at github.com, Settings, Applications, or delete a pasted token at
github.com, Settings, Developer settings.

## Slack (tokens from a manifest app)

No server setup. Each user creates a Slack app for their workspace and
pastes its tokens. The Slack card has a **Create the Slack app from its
manifest** link that opens Slack's "create app" page with Crawler's manifest
(`backend/services/connectors/slack_manifest.json`) filled in. The manifest
turns on Socket Mode, so Slack needs no public URL for this install.

1. Open the manifest link on the Slack card, choose the workspace and create
   the app. (Or, at [api.slack.com/apps](https://api.slack.com/apps),
   Create New App, From a manifest, and paste the JSON file.)
2. **Install to Workspace** (a workspace administrator may have to approve
   it).
3. **Bot token** (`xoxb-`, required): OAuth and Permissions, Bot User OAuth
   Token.
4. **App-level token** (`xapp-`, only for Slack DMs with Crawler): Basic
   Information, App-Level Tokens, Generate Token and Scopes, with the
   `connections:write` scope.
5. **User token** (`xoxp-`, only for message search and setting your
   status): OAuth and Permissions, User OAuth Token.
6. On the Connectors page, add Slack and paste the tokens. Invite the app to
   any channel Crawler should read (`/invite @Crawler`).
7. For DMs: on the Slack connector's card, click **Link Slack DMs** and send
   the code it shows to the Crawler bot in a Slack DM within 10 minutes.

**Scopes in the manifest.** Bot: `channels:read`, `groups:read`,
`channels:history`, `groups:history`, `chat:write`, `reactions:write`,
`users:read`, `files:read`, `files:write`, `channels:manage`,
`groups:write`, `im:read`, `im:history`, `im:write` (the `im:` ones are for
the DM channel). User: `search:read`, `users.profile:write`. Group DMs
(`mpim:*`), email addresses (`users:read.email`), `chat:write.public` and
`channels:join` are not requested. Leave out the user token if you do not
need search or status, and the app-level token if you do not want DMs.

Use **one Slack app per Crawler user** for DMs: Slack delivers each event to
any one open connection of an app, so Crawler runs only one DM channel per
app and holds back other connectors that share it. Deleting the connector
revokes the bot and user tokens, unless another connector still uses the
same token; the app-level token can only be deleted on the app's Basic
Information page.

## Notion (internal integration secret)

No server setup. Each user creates an internal integration in their Notion
workspace and pastes its secret.

1. Open [notion.so/profile/integrations](https://www.notion.so/profile/integrations)
   and create a new integration of type **Internal** for the workspace.
2. Capabilities: **Read content** is enough for reading. Add **Update
   content** and **Insert content** for editing and creating pages, **Read
   comments** and **Insert comments** for comments, and user information
   without email addresses for listing workspace members.
3. Copy the **Internal Integration Secret** and paste it on the Notion card.
4. Share each page or database Crawler should see with the integration:
   page menu, Connections, then pick the integration. Pages inside a shared
   page are included.

Crawler sees only what is shared with the integration. Unticking a
capability in Notion is the provider-side limit; Crawler's own permissions
(`notion.read`, `notion.write`, `notion.comment`, `notion.delete`) still
decide which tools exist. Internal integration secrets cannot be revoked
through the API: rotate or delete the secret in the integration's settings.

## Troubleshooting

- **"Sign-in ... is not configured on this server"**: the named variable is
  empty in `backend/.env`, or the backend was not restarted after setting
  it. For Google, both the client id and the secret must be set.
- **The provider says the redirect URI does not match** (Google
  `redirect_uri_mismatch`, Microsoft `AADSTS50011`): the registered URI must
  equal `<OAUTH_REDIRECT_BASE>/api/oauth/callback/<provider>` exactly,
  including `127.0.0.1` versus `localhost` and the port.
- **"Sign-in did not complete"** page: start again from the Connectors page.
  A sign-in expires after 10 minutes and each link works once. On a server
  whose `OAUTH_REDIRECT_BASE` is not loopback, the sign-in must also finish
  in the browser that started it, with Crawler opened at that exact origin.
- **A signed-in connection asks to reconnect**: the provider refused the
  refresh token (for a Google app in Testing, after 7 days). Use Reconnect
  on the card. If the message says the server's sign-in configuration was
  refused, the client id or secret in `backend/.env` is wrong or was
  rotated, and reconnecting will not help until it is fixed.
