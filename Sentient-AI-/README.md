# SentientAI

[![CI](https://github.com/krishcodes1/Sentient-AI-/actions/workflows/ci.yml/badge.svg)](https://github.com/krishcodes1/Sentient-AI-/actions/workflows/ci.yml)

**Secure-by-Design Agentic AI Platform**

A self-hosted AI assistant platform with security, user control, and auditability built into every layer. SentientAI integrates with Canvas LMS, Google Workspace, Robinhood Crypto, and more — with fine-grained permission scoping, multi-layer prompt injection defense, and tamper-evident audit logging.

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

5. **Open the app**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

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
- After registering your own account, set `ALLOW_REGISTRATION=false` —
  otherwise anyone who finds the URL can create accounts billed to your
  LLM API keys.
- Set `CORS_ORIGINS` to your real frontend origin and `ALLOWED_HOSTS`
  to your hostname. `AUDIT_HMAC_KEY` should be a dedicated key stored
  away from the database. Startup logs a warning for each of these that
  is still on its development default.
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
   createdb sentientai
   psql sentientai -c "CREATE USER sentientai WITH PASSWORD 'sentientai'; GRANT ALL PRIVILEGES ON DATABASE sentientai TO sentientai;"
   ```

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
   CREATE DATABASE sentientai;
   CREATE USER sentientai WITH PASSWORD 'sentientai';
   GRANT ALL PRIVILEGES ON DATABASE sentientai TO sentientai;
   \q
   ```

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
   sudo -u postgres psql -c "CREATE DATABASE sentientai;"
   sudo -u postgres psql -c "CREATE USER sentientai WITH PASSWORD 'sentientai';"
   sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sentientai TO sentientai;"
   ```

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
   ```env
   LLM_PROVIDER=ollama
   LLM_MODEL=llama3.2
   OLLAMA_BASE_URL=http://localhost:11434
   ```

4. Run the backend and frontend as described above. No API key needed.

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and configure:

| Variable | Required? | Description |
|----------|-----------|-------------|
| `SECRET_KEY` | Yes | Signs your login tokens. Generate with the command below. |
| `ENCRYPTION_KEY` | Yes | Encrypts stored API keys in the database. Generate with the command below. |
| `DATABASE_URL` | Yes | PostgreSQL connection string. Default works with Docker. |
| `REDIS_URL` | Recommended | Redis connection string (used for shared rate limiting; the API falls back to in-memory rate limiting if Redis is unreachable). Default works with Docker. |
| `LLM_PROVIDER` | Yes | Which AI to use: `anthropic`, `openai`, `gemini`, `grok`, `deepseek`, `groq`, `mistral`, or `ollama` |
| `LLM_MODEL` | Yes | Model name (e.g., `claude-sonnet-4-20250514`, `gpt-4o`, `gemini-2.5-flash`) |
| `ANTHROPIC_API_KEY` | If using Anthropic | Get from [console.anthropic.com](https://console.anthropic.com) |
| `OPENAI_API_KEY` | If using OpenAI | Get from [platform.openai.com](https://platform.openai.com/api-keys) |
| `GEMINI_API_KEY` | If using Gemini | Get from [aistudio.google.com](https://aistudio.google.com/apikey) |
| `GROK_API_KEY` | If using Grok | Get from [console.x.ai](https://console.x.ai) |
| `DEEPSEEK_API_KEY` | If using Deepseek | Get from [platform.deepseek.com](https://platform.deepseek.com) |
| `GROQ_API_KEY` | If using Groq | Get from [console.groq.com](https://console.groq.com) |
| `MISTRAL_API_KEY` | If using Mistral | Get from [console.mistral.ai](https://console.mistral.ai) |
| `OLLAMA_BASE_URL` | If using Ollama | Default: `http://localhost:11434` |
| `RATE_LIMIT_PER_MINUTE` | No | General per-IP API rate limit (default 60) |
| `AUTH_RATE_LIMIT_PER_MINUTE` | No | Stricter per-IP limit on login/register (default 10) |
| `TOKEN_EXPIRE_MINUTES` | No | JWT lifetime (default 60) |
| `APPROVAL_TTL_MINUTES` | No | How long a pending tool approval stays actionable (default 15) |
| `CORS_ORIGINS` | No | Allowed browser origins (default localhost dev ports) |
| `ALLOW_REGISTRATION` | No | Set `false` after creating your account so strangers can't register (default `true`) |
| `PASSWORD_MIN_LENGTH` | No | Minimum password length, floor 8 (default 8) |
| `ALLOWED_HOSTS` | No | Accepted `Host` headers; set your real hostname in production (default `["*"]`) |
| `LOG_LEVEL` | No | Log verbosity; production emits JSON lines (default `INFO`) |
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
sentientai/
├── backend/                    # Python / FastAPI
│   ├── core/                   # Config, database, security, network policy
│   ├── models/                 # SQLAlchemy ORM models (incl. pending_actions)
│   ├── services/
│   │   ├── agent/              # LLM runtime, providers, prompt guard, permissions, approvals, tool registry
│   │   ├── connectors/         # Canvas LMS, Google Workspace, Robinhood + factory
│   │   ├── mcp/                # MCP client + server integration (experimental)
│   │   ├── audit.py            # Tamper-evident audit logging (hash chain)
│   │   └── auth.py             # JWT authentication
│   ├── api/                    # FastAPI routes + middleware
│   └── tests/                  # pytest suite (route security, executor, approvals, audit, MCP)
├── frontend/                   # React / TypeScript / Vite / Tailwind
│   └── src/
│       ├── pages/              # Dashboard, Chat, Connectors, Audit Logs, Settings
│       ├── components/         # Layout, Sidebar
│       └── services/           # API client
└── docker/                     # Docker Compose, Dockerfiles
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

SentientAI solves the token explosion problem seen in platforms like OpenClaw:

- **Sliding window** — keeps last 12 messages in full, summarizes older ones
- **Tool result compression** — truncates large API responses to 2000 chars
- **Dynamic tool selection** — sends only relevant tool schemas instead of all 50+
- **Semantic caching** — caches identical queries to avoid duplicate API calls
- **Accurate token estimation** — uses ~3.5 chars/token (not the broken 4.0 estimate that causes 47% undercounting)

---

## License

This project is part of the CSCI-456 Senior Project at New York Institute of Technology.

**Author:** Krish Shroff (Team Leader)

**Team:** Rafi Hossain, Miadul Haque, Edrich Silva
