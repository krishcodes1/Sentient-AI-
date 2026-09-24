# Crawler AI

[![CI](https://github.com/krishcodes1/Sentient-AI-/actions/workflows/ci.yml/badge.svg)](https://github.com/krishcodes1/Sentient-AI-/actions/workflows/ci.yml)

**Secure-by-Design Agentic AI Platform**

A self-hosted AI assistant platform with security, user control, and auditability built into every layer. Crawler AI integrates with Canvas LMS, Google Workspace, Robinhood Crypto, and more — with fine-grained permission scoping, multi-layer prompt injection defense, and tamper-evident audit logging.

**Assistant features:** streaming chat with live tool-progress and rendered
markdown, persistent per-user memory (saved facts injected into every
conversation, screened for injection on write), an explicit human-approval
flow for sensitive actions, and eight swappable LLM providers.

**Author:** Krish Shroff — CSCI-456 Senior Project, New York Institute of Technology

---

## Supported AI Providers

| Provider | Models | API Key Required |
|----------|--------|-----------------|
| **Anthropic** | Claude Opus 4, Sonnet 4, Haiku 4.5 | `ANTHROPIC_API_KEY` |
| **OpenAI** | GPT-4o, GPT-4o-mini, o1 | `OPENAI_API_KEY` |
| **Google Gemini** | Gemini 2.5 Pro, 2.5 Flash, 2.0 Flash | `GEMINI_API_KEY` |
| **xAI Grok** | Grok-3, Grok-3-mini | `GROK_API_KEY` |
| **Deepseek** | Deepseek Chat, Deepseek Reasoner | `DEEPSEEK_API_KEY` |
| **Groq** | LLaMA 3.3 70B, Mixtral 8x7B | `GROQ_API_KEY` |
| **Mistral** | Mistral Large, Mistral Small | `MISTRAL_API_KEY` |
| **Ollama** | LLaMA 3.2, Mistral, CodeLLaMA (local) | None (free, runs locally) |

---

## Quick Start

### Prerequisites

- **Python 3.11+** — [python.org/downloads](https://www.python.org/downloads/)
- **Node.js 20+** — [nodejs.org](https://nodejs.org/)
- **PostgreSQL 15+** — [postgresql.org](https://www.postgresql.org/download/)
- **Redis 7+** — [redis.io](https://redis.io/download)
- **Docker** (optional, for easiest setup) — [docker.com](https://www.docker.com/get-started/)

---

## Setup Instructions

### Option 1: Docker (Easiest — Works on Windows, Mac, Linux)

1. **Install Docker Desktop**
   - **Mac:** Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
   - **Windows:** Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/). Enable WSL 2 when prompted.
   - **Linux:** `sudo apt install docker.io docker-compose-v2` (Ubuntu/Debian) or `sudo dnf install docker docker-compose` (Fedora)

2. **Clone the repo**

   The project lives in the `Sentient-AI-/` subdirectory of the repository,
   so change into it after cloning:
   ```bash
   git clone https://github.com/krishcodes1/Sentient-AI-.git
   cd Sentient-AI-/Sentient-AI-
   ```

3. **Configure environment**
   ```bash
   cp backend/.env.example backend/.env
   ```
   Edit `backend/.env` and add your API key (see [Environment Variables](#environment-variables) below).

4. **Start everything**
   ```bash
   cd docker
   docker compose up --build
   ```
   Keep `--build` every time you pull changes. The source is bind-mounted,
   so without it the code is current but the installed Python/npm
   packages are whatever the images had when they were last built.

5. **Open the app**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

Docker notes:

- Frontend `node_modules` lives in a Docker volume that survives rebuilds.
  The dev container reinstalls into it on start whenever
  `package-lock.json` changed, so a new dependency never goes missing. To
  throw the volume away anyway: `docker compose up --build --renew-anon-volumes`.
- The Vite proxy reaches the API as `backend:8000`, so the dev compose
  adds `backend` to `ALLOWED_HOSTS` itself (this overrides the value in
  `backend/.env` for the Docker stack only).
- **One running deployment per Telegram bot token.** Telegram delivers
  each update to only one poller, so two stacks on the same
  `TELEGRAM_BOT_TOKEN` (say, the server and a dev stack on your laptop)
  split approvals between them at random, and the backend logs
  `telegram_poller_conflict`. Leave the token empty everywhere except the
  deployment that owns the bot, or make a separate bot for development.

**Production deployment:** the dev compose above runs hot-reload servers
with the source bind-mounted. For production shape (non-root backend, no
reload, static frontend served by nginx with an `/api` proxy, internal-only
Postgres/Redis and backend, container healthchecks, graceful shutdown,
log rotation) use the production compose file:

```bash
cd docker
POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')" \
  docker compose -f docker-compose.prod.yml up --build -d
```

Production checklist:

- `POSTGRES_PASSWORD` is **required** (compose refuses to start without
  it). Put it in `docker/.env` so restarts reuse the same value.
- Set real keys in `backend/.env` — the app refuses to boot with the
  `.env.example` placeholders or keys shorter than 32 chars, and with
  `ENVIRONMENT=production` it fails fast (instead of limping) when the
  database is unreachable.
- Registration is closed unless you open it: the wizard's Summary step
  defaults "Allow other people to create accounts" to off, and you can
  change it later in Settings. Leave `ALLOW_REGISTRATION` unset to manage
  it from the wizard/Settings; set `ALLOW_REGISTRATION=false` to lock it
  closed (the Settings switch then cannot open it). An existing deployment
  that skips the wizard on upgrade starts closed too, unless its `.env`
  explicitly says `ALLOW_REGISTRATION=true`. Open registration lets anyone
  who finds the URL create accounts billed to your LLM API keys.
- Set `CORS_ORIGINS` to your real frontend origin and `ALLOWED_HOSTS`
  to your hostname. `AUDIT_HMAC_KEY` should be a dedicated key stored
  away from the database. Startup logs a warning for each of these that
  is still on its development default.
- `ALLOWED_HOSTS` must list the hostname people actually browse to, e.g.
  `["assistant.example.com"]`: nginx (and a Caddy/Traefik proxy in front
  of it) forwards the browser's `Host` header unchanged, and the backend
  answers any other host with 400 `Invalid host header`. Add `"localhost"`
  if you also test through http://localhost:3000. Don't use `["*"]`. The
  backend's container healthcheck sends the first entry as its `Host`.
- **TLS**: nothing in the stack terminates TLS. Put a TLS-terminating
  reverse proxy in front of port 3000 before exposing it beyond your
  LAN — e.g. [Caddy](https://caddyserver.com) with a two-line
  Caddyfile (`assistant.example.com { reverse_proxy localhost:3000 }`),
  Traefik, nginx + certbot, or a cloud load balancer. Only port 443 on
  that proxy should be reachable from the internet.
- `/docs`, `/redoc`, and `/openapi.json` are disabled automatically when
  `ENVIRONMENT=production`.
- **Upgrading an existing deployment**: nothing to do. The schema is
  managed by Alembic now, and a database created before that change is
  detected and adopted on the next startup (it is stamped at the baseline,
  then any newer migrations run). Fresh databases migrate normally. See
  [backend/alembic/README.md](Sentient-AI-/backend/alembic/README.md).

---

### Option 2: Manual Setup (Mac)

1. **Install dependencies**
   ```bash
   # Install Homebrew if you don't have it
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

   # Install PostgreSQL and Redis
   brew install postgresql@16 redis node python@3.12

   # Start services
   brew services start postgresql@16
   brew services start redis
   ```

2. **Create the database**
   ```bash
   psql postgres -c "CREATE ROLE sentientai LOGIN PASSWORD 'sentientai';"
   createdb -O sentientai sentientai
   ```

   > The role has to **own** the database. `GRANT ALL PRIVILEGES ON DATABASE`
   > alone is not enough on PostgreSQL 15 and newer: PG15 revoked `CREATE` on
   > schema `public` from `PUBLIC`, so the first migration dies with
   > `permission denied for schema public`. If you already created the
   > database the old way, fix it with
   > `psql -d sentientai -c "GRANT ALL ON SCHEMA public TO sentientai;"`.

3. **Set up the backend**
   ```bash
   cd backend
   cp .env.example .env
   # Edit .env and add your API key

   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python main.py
   ```

4. **Set up the frontend** (in a new terminal)
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

5. **Open the app:** http://localhost:3000

---

### Option 3: Manual Setup (Windows)

1. **Install dependencies**
   - Download and install **Python 3.12+** from [python.org](https://www.python.org/downloads/) — check "Add Python to PATH"
   - Download and install **Node.js 20+** from [nodejs.org](https://nodejs.org/)
   - Download and install **PostgreSQL 16** from [postgresql.org/download/windows](https://www.postgresql.org/download/windows/) — remember the password you set
   - Download and install **Redis** via [Memurai](https://www.memurai.com/get-memurai) (Redis-compatible for Windows) or use WSL

2. **Create the database** (open pgAdmin or Command Prompt)
   ```cmd
   psql -U postgres
   CREATE ROLE sentientai LOGIN PASSWORD 'sentientai';
   CREATE DATABASE sentientai OWNER sentientai;
   \q
   ```

   > `OWNER` matters. `GRANT ALL PRIVILEGES ON DATABASE` alone is not enough
   > on PostgreSQL 15 and newer: PG15 revoked `CREATE` on schema `public`
   > from `PUBLIC`, so the first migration dies with `permission denied for
   > schema public`. To fix a database you already created the old way, run
   > `GRANT ALL ON SCHEMA public TO sentientai;` while connected **to that
   > database** (`psql -U postgres -d sentientai`).

3. **Set up the backend** (Command Prompt or PowerShell)
   ```cmd
   cd backend
   copy .env.example .env
   :: Edit .env with notepad and add your API key
   notepad .env

   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   python main.py
   ```

4. **Set up the frontend** (new terminal)
   ```cmd
   cd frontend
   npm install
   npm run dev
   ```

5. **Open the app:** http://localhost:3000

---

### Option 4: Manual Setup (Linux / Ubuntu)

1. **Install dependencies**
   ```bash
   sudo apt update
   sudo apt install python3.12 python3.12-venv python3-pip nodejs npm postgresql redis-server

   # Start services
   sudo systemctl start postgresql redis-server
   sudo systemctl enable postgresql redis-server
   ```

2. **Create the database**
   ```bash
   sudo -u postgres psql -c "CREATE ROLE sentientai LOGIN PASSWORD 'sentientai';"
   sudo -u postgres psql -c "CREATE DATABASE sentientai OWNER sentientai;"
   ```

   > `OWNER` matters. `GRANT ALL PRIVILEGES ON DATABASE` alone is not enough
   > on PostgreSQL 15 and newer: PG15 revoked `CREATE` on schema `public`
   > from `PUBLIC`, so the first migration dies with `permission denied for
   > schema public`. To fix a database you already created the old way:
   > `sudo -u postgres psql -d sentientai -c "GRANT ALL ON SCHEMA public TO sentientai;"`

3. **Set up the backend**
   ```bash
   cd backend
   cp .env.example .env
   nano .env  # Add your API key

   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python main.py
   ```

4. **Set up the frontend** (new terminal)
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

5. **Open the app:** http://localhost:3000

---

### Option 5: Free Local AI (No API Key Needed)

If you don't want to pay for API keys, use **Ollama** for free local AI:

1. **Install Ollama:** [ollama.com/download](https://ollama.com/download) (Mac, Windows, Linux)

2. **Pull a model**
   ```bash
   ollama pull llama3.2
   ```

3. **Set in your `.env`**

   Ollama runs on your host machine, not inside a container, so the URL
   the backend needs depends on how the backend itself is running:

   ```env
   LLM_PROVIDER=ollama
   LLM_MODEL=llama3.2
   # Native run (Option 2/3/4 above): the backend reaches Ollama directly.
   OLLAMA_BASE_URL=http://localhost:11434
   # Docker (Option 1): `localhost` inside the backend container is the
   # container itself, not your Mac/PC — use Docker's host alias instead:
   # OLLAMA_BASE_URL=http://host.docker.internal:11434
   ```

4. Run the backend and frontend as described above. No API key needed.

---

## First run: the setup wizard

The very first time you open the app — http://localhost:3000 — with no
accounts created yet, every route redirects to `/setup` for a one-time
wizard. It has five steps:

1. **Owner account.** Create the first user. This account becomes the
   deployment's **owner/admin** — there is no separate invite step, and no
   UI to transfer or grant that role afterwards (edit the database directly
   if you ever need to).
2. **AI provider.** Choose a provider and model, paste an API key (skipped
   if one is already `configured` from `backend/.env`), and click **Test**.
   The key is verified with a real, tiny request before **Save** is even
   enabled, so a bad key never gets silently stored.
3. **Telegram (optional).** Paste a bot token from @BotFather, **Test** it,
   save, then link your phone with the generated `t.me/<bot>?start=<code>`
   link. Skip this step entirely if you don't want Telegram approvals.
4. **Permissions.** Turn each capability on or off — see
   [Permissions](#permissions) below for what each one does. You can revisit
   these later in Settings.
5. **Summary.** A "what works / what doesn't" table built from the actual
   capability report, plus the **"Allow other people to create accounts"**
   switch. It defaults to **off**: after setup, registration is closed
   unless you turn it on here or later in Settings — otherwise anyone who
   finds the URL could create an account billed to your LLM API keys. With
   `ALLOW_REGISTRATION=false` in `backend/.env` the switch is locked closed
   and shown read-only.

Anything you set with `.env` (`backend/.env.example`) takes precedence over
whatever the wizard stores (for `ALLOW_REGISTRATION`, only `false` does) —
see [Environment Variables](#environment-variables) below. If your `.env`
already has a working provider key when the backend starts and an account
exists, setup is considered already done and the wizard is skipped (useful
when upgrading an existing Docker deployment); registration then starts
closed unless `.env` explicitly sets `ALLOW_REGISTRATION=true`.

Building a new capability? See
[`backend/services/capabilities/README.md`](backend/services/capabilities/README.md)
for the five-step contributor guide.

## Permissions

Every tool the agent can use is gated by one of these switches. They are
offered to the model only when on, refused again at dispatch if somehow
requested while off, and summarized for the model in its own prompt so it
can explain rather than guess. The owner sets them in the setup wizard's
Permissions step or later in **Settings → Permissions**; everyone else sees
them read-only.

| Switch | Unlocks | Default |
|--------|---------|---------|
| **Browse the web** | Searching the public web and reading pages as text (`web.search`, `web.fetch_page`) | On |
| **Screenshots of websites** | Opening a page in a hidden browser and capturing it as an image, for pages that don't read well as text — flights, products (`web.screenshot`). Needs the hidden browser installed (~150–300 MB); the wizard/Settings can install it for you. | On |
| **See my screen** | Taking a picture of this computer's display when asked (`desktop.screenshot`). High risk, off by default, and audited on every capture. **Not available inside Docker** — the compose files set `CRAWLER_CONTAINER=1` so the capability reports "unavailable in this environment" instead of failing; it works when the backend runs directly on a Mac or Windows machine, and additionally needs the OS's screen-recording permission granted to the backend process. | Off |
| **Reminders** | Setting, listing and cancelling reminders, delivered to you over Telegram when it's linked | On |
| **Install optional software** | Installing optional components from a fixed list (e.g. the hidden browser above), asking you before every install | On |
| **Telegram chat and approvals** | Chatting with Crawler from Telegram and approving pending actions from your phone. Needs a bot token configured (`.env` or the wizard's Telegram step). | On |

See `backend/services/capabilities/README.md` if you're adding a new one —
declaring a capability there is what drives the switch, the gating, and the
prompt text; nothing else needs to change.

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and configure. **`.env` values
always override whatever the setup wizard has stored** — the precedence is
`.env` > database (wizard) > built-in default. That means the AI provider
keys and `TELEGRAM_BOT_TOKEN` below are **optional** if you plan to use the
[setup wizard](#first-run-the-setup-wizard) instead: leave them blank, start
the app, and add the provider and (optionally) Telegram from the wizard or
Settings. Set them here instead when you want them fixed by deployment
config (e.g. a shared server) rather than owner-editable at runtime.
`ALLOW_REGISTRATION` is the one exception to "`.env` wins": only `false`
overrides the owner's switch (it locks registration closed); leave it unset
to manage registration from the wizard/Settings. Either
way, after editing `backend/.env` for a Docker deployment, apply it with
`docker compose up -d backend` — a plain `docker compose restart` does not
re-read the `.env` file, it only restarts the process with the environment
it already has.

| Variable | Required? | Description |
|----------|-----------|-------------|
| `SECRET_KEY` | Yes | Signs your login tokens. Generate with the command below. |
| `ENCRYPTION_KEY` | Yes | Encrypts stored API keys in the database, including provider keys and the Telegram bot token saved through the setup wizard. Generate with the command below. |
| `DATABASE_URL` | Yes | PostgreSQL connection string. Default works with Docker. |
| `REDIS_URL` | Recommended | Redis connection string (used for shared rate limiting; the API falls back to in-memory rate limiting if Redis is unreachable). Default works with Docker. |
| `LLM_PROVIDER` | Yes | Which AI to use: `anthropic`, `openai`, `gemini`, `grok`, `deepseek`, `groq`, `mistral`, or `ollama`. Optional when using the wizard, which can set this instead. |
| `LLM_MODEL` | Yes | Model name (e.g., `claude-sonnet-5`, `gpt-4o`, `gemini-2.5-flash`). Optional when using the wizard. |
| `ANTHROPIC_API_KEY` | If using Anthropic | Get from [console.anthropic.com](https://console.anthropic.com). Optional when using the wizard — see above. |
| `OPENAI_API_KEY` | If using OpenAI | Get from [platform.openai.com](https://platform.openai.com/api-keys). Optional when using the wizard. |
| `GEMINI_API_KEY` | If using Gemini | Get from [aistudio.google.com](https://aistudio.google.com/apikey). Optional when using the wizard. |
| `GROK_API_KEY` | If using Grok | Get from [console.x.ai](https://console.x.ai). Optional when using the wizard. |
| `DEEPSEEK_API_KEY` | If using Deepseek | Get from [platform.deepseek.com](https://platform.deepseek.com). Optional when using the wizard. |
| `GROQ_API_KEY` | If using Groq | Get from [console.groq.com](https://console.groq.com). Optional when using the wizard. |
| `MISTRAL_API_KEY` | If using Mistral | Get from [console.mistral.ai](https://console.mistral.ai). Optional when using the wizard. |
| `OLLAMA_BASE_URL` | If using Ollama | Native run: `http://localhost:11434` (default). Under Docker, `localhost` means the backend container itself, not your host, so use `http://host.docker.internal:11434` instead. |
| `TELEGRAM_BOT_TOKEN` | No | Bot token from @BotFather for Telegram chat and approvals. Optional when using the wizard, which can save and test it instead; see [Permissions](#permissions). |
| `RATE_LIMIT_PER_MINUTE` | No | General per-IP API rate limit (default 60) |
| `AUTH_RATE_LIMIT_PER_MINUTE` | No | Stricter per-IP limit on login/register (default 10) |
| `TRUSTED_PROXIES` | Review for prod | CIDRs whose `X-Forwarded-For` is believed for client-IP attribution. Default trusts loopback + all private ranges (where the compose nginx sits) — narrow it to your proxy's address if anything else can reach the API from a private network. |
| `LOCKOUT_THRESHOLD` | No | Failed sign-ins before one account is locked (default 5) |
| `LOCKOUT_DURATION_MINUTES` | No | How long that lock lasts (default 15) |
| `TOKEN_EXPIRE_MINUTES` | No | JWT lifetime (default 60) |
| `SESSION_MAX_HOURS` | No | Ceiling on how long refreshing can extend one session, measured from login (default 12) |
| `APPROVAL_TTL_MINUTES` | No | How long a pending tool approval stays actionable (default 15) |
| `CORS_ORIGINS` | No | Allowed browser origins (default localhost dev ports) |
| `ALLOW_REGISTRATION` | No | Leave unset to manage open registration from the wizard/Settings (the switch on the Summary step, then in Settings — see [First run: the setup wizard](#first-run-the-setup-wizard) — which defaults to **closed**). Set `false` to lock it closed whatever that switch says. `true` opens nothing by itself; it only seeds the switch as open when an existing install is carried past the wizard on upgrade. The first account always comes from the wizard's owner step. |
| `PASSWORD_MIN_LENGTH` | No | Minimum password length, floor 8 (default 8) |
| `ALLOWED_HOSTS` | No | Accepted `Host` headers; set your real hostname in production (default `["*"]`) |
| `LOG_LEVEL` | No | Log verbosity; production emits JSON lines (default `INFO`) |
| `ENVIRONMENT` | Recommended (prod) | `development` or `production`. `production` hides `/docs`, `/redoc` and the OpenAPI schema, makes an unreachable database fatal at boot instead of a warning, and turns on the startup config warnings (default `development`). |
| `AUDIT_HMAC_KEY` | Recommended (prod) | Dedicated key for the tamper-evident audit log; see `.env.example` |

**You only need ONE API key** — whichever provider you choose.

### Generating Your Security Keys

Run this single command in your terminal — it prints both keys at once:

```bash
python3 -c "import secrets, base64, os; print('SECRET_KEY=' + secrets.token_urlsafe(48)); print('ENCRYPTION_KEY=' + base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

You'll see output like:
```
SECRET_KEY=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef...
ENCRYPTION_KEY=xYz789AbCdEf012GhIjKlMnOpQrStUvWxYz456789A=
```

Copy those two lines into your `backend/.env` file, replacing the `REPLACE_ME` placeholders.

> **Windows users**: Use `python` instead of `python3` in the command above.

---

## Architecture

```
crawler-ai/
├── backend/                    # Python / FastAPI
│   ├── core/                   # Config, database, security, network policy
│   ├── models/                 # SQLAlchemy ORM models (incl. pending_actions)
│   ├── services/
│   │   ├── agent/              # LLM runtime, providers, prompt guard, permissions, approvals, tool registry
│   │   ├── connectors/         # Canvas LMS, Google Workspace, Robinhood + factory
│   │   ├── mcp/                # MCP client + server integration (experimental)
│   │   ├── audit.py            # Tamper-evident audit logging (hash chain)
│   │   └── auth.py             # JWT authentication
│   ├── alembic/                # Schema migrations (see alembic/README.md)
│   ├── api/                    # FastAPI routes + middleware
│   ├── scripts/                # Operator tools (audit-log verifier)
│   └── tests/                  # pytest suite (route security, executor, approvals, audit, MCP)
├── frontend/                   # React / TypeScript / Vite / Tailwind
│   └── src/
│       ├── pages/              # Login, Dashboard, Chat, Connectors, Audit Logs, Memory, Settings
│       ├── components/         # Brand, ConfirmDialog, ErrorBoundary, MarkdownMessage, layout/
│       └── services/           # API client
└── docker/                     # Docker Compose (dev + prod), Dockerfiles
```

### Security Features

The full security model — every layer, where it is enforced, and what is
still open — lives in **[SECURITY.md](SECURITY.md)**. Highlights:

- **JWT-scoped API** — identity comes only from the verified token; every
  resource is owner-scoped (no client-supplied user ids, no IDOR)
- **Explicit consent flow** — sensitive actions are persisted as pending
  approvals (owned, single-use, expiring) and run only after the user clicks
  Approve, in chat or on the dashboard
- **Least-privilege scopes** — connectors default to read-only; write scopes
  are granted per connector and re-checked at dispatch
- **Financial transaction hard block** — trades/transfers permanently blocked
  at four independent layers, regardless of config
- **Multi-layer prompt injection defense** — instruction-hierarchy system
  prompt, nonce-spotlighted untrusted tool-result envelope, a deterministic
  CaMeL-lite taint gate (injected data can't drive an auto-approved write),
  input/argument/output scanning, connector response sanitization, and a
  CI red-team regression suite
- **Exfiltration-safe rendering** — assistant markdown never auto-fetches
  model-emitted images (the EchoLeak channel) or parses raw HTML; links are
  inert and show their destination host
- **AES-256-GCM credential encryption** — secrets encrypted at rest, never
  returned by any API, decrypted only at dispatch
- **SHA-256 chain-linked audit logs** — tamper-evident history with per-row
  verification in the UI and a CLI verifier
- **SSRF protection + deny-by-default network policies** — connectors and
  MCP servers can only reach allowlisted, public endpoints (redirects included)
- **MCP server support (experimental)** — register external MCP servers;
  every MCP tool requires approval, financial-looking tools are refused
- **Rate limiting** — per-IP throttling with a stricter bucket on
  login/register, plus per-connector rate limits
- **Security headers** — CSP, HSTS, X-Frame-Options, nosniff, etc.
- **Session revocation** — changing your password invalidates every
  outstanding token, not just future ones
- **Admin role** — the first account registered owns the deployment;
  `admin_only` connectors are usable only by it
- **Data export** — Settings → Export my data downloads every conversation,
  memory, connector setting, and audit record as JSON (credentials excluded)

### Smart Context Management

Crawler AI solves the token explosion problem seen in platforms like OpenClaw:

- **Sliding window** — keeps last 12 messages in full, summarizes older ones
- **Tool result compression** — truncates large API responses to 2000 chars
- **Dynamic tool selection** — sends only the relevant schemas rather than the
  whole catalog (17 built-in connector actions today, plus every tool exposed
  by the MCP servers a user has registered, which is unbounded)
- **Semantic caching** — caches identical queries to avoid duplicate API calls
- **Accurate token estimation** — uses ~3.5 chars/token (not the broken 4.0 estimate that causes 47% undercounting)

---

## License

This project is part of the CSCI-456 Senior Project at New York Institute of Technology.

**Author:** Krish Shroff (Team Leader)

**Team:** Rafi Hossain, Miadul Haque, Edrich Silva
