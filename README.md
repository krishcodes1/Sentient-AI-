# SentientAI

**Secure AI Agent Platform — Powered by OpenClaw**

A self-hosted AI assistant platform that wraps [OpenClaw](https://github.com/openclaw/openclaw) as its core agent engine, adding a security dashboard, multi-provider LLM support, and a management UI. Connect your AI to Telegram, Discord, Slack, WhatsApp, Signal, and more — with any AI provider you choose.

**Author:** Krish Shroff

---

## How It Works

```
Telegram / Discord / Slack / WhatsApp / Signal / WebChat
                    │
                    ▼
       ┌────────────────────────┐
       │   OpenClaw Gateway     │  ← Core agent engine (port 18789)
       │   (wrapped by us)      │
       └────────────┬───────────┘
                    │
       ┌────────────┴───────────┐
       │   SentientAI Backend   │  ← Management API (port 8000)
       │   (FastAPI + Postgres) │     Manages config, users, channels
       └────────────┬───────────┘
                    │
       ┌────────────┴───────────┐
       │   SentientAI Frontend  │  ← Dashboard UI (port 3000)
       │   (React + Tailwind)   │     Onboarding, chat, settings
       └────────────────────────┘
```

SentientAI writes your LLM and channel settings to `openclaw.json`, which the OpenClaw gateway reads to connect to messaging platforms and route conversations through your chosen AI.

---

## Supported AI Providers

Users choose their provider during onboarding. **Not locked to any single vendor.**

| Provider | Models | API Key |
|----------|--------|---------|
| **Anthropic** | Claude Opus 4, Sonnet 4, Haiku 4.5 | `ANTHROPIC_API_KEY` |
| **OpenAI** | GPT-4o, GPT-4o-mini, o1 | `OPENAI_API_KEY` |
| **Google Gemini** | Gemini 2.5 Pro, 2.5 Flash, 2.0 Flash | `GEMINI_API_KEY` |
| **xAI Grok** | Grok-3, Grok-3-mini | `GROK_API_KEY` |
| **Deepseek** | Deepseek Chat, Deepseek Reasoner | `DEEPSEEK_API_KEY` |
| **Groq** | LLaMA 3.3 70B, Mixtral 8x7B | `GROQ_API_KEY` |
| **Mistral** | Mistral Large, Mistral Small | `MISTRAL_API_KEY` |
| **Ollama** | LLaMA 3.2, Mistral, CodeLLaMA (local, free) | None |

## Supported Channels (via OpenClaw)

| Channel | Setup |
|---------|-------|
| **Telegram** | Bot token from @BotFather |
| **Discord** | Bot token from Developer Portal |
| **Slack** | Bot token + App token |
| **WhatsApp** | QR code scan (via Baileys) |
| **Signal** | Linked device |
| **WebChat** | Built-in at gateway URL |

---

## Quick Start — Docker (Recommended)

### Prerequisites

- **Docker Desktop** — [docker.com/get-started](https://www.docker.com/get-started/)
- **One AI API key** (or use Ollama for free local AI)

### Step-by-step

```bash
# 1. Clone the repo
git clone https://github.com/krishcodes1/Sentient-AI-.git
cd Sentient-AI-

# 2. Set up your environment file
cp backend/.env.example backend/.env
```

Edit `backend/.env` and set your AI provider API key (see [Environment Variables](#environment-variables)).

```bash
# 3. Start all services
cd docker
docker compose up --build
```

This starts 5 services:
- **PostgreSQL** (port 5432) — database
- **Redis** (port 6379) — caching
- **OpenClaw Gateway** (port 18789) — agent engine + channel connections
- **SentientAI Backend** (port 8000) — API server
- **SentientAI Frontend** (port 3000) — dashboard UI

```bash
# 4. Open the dashboard
open http://localhost:3000
```

### First-time setup

1. **Create an account** at http://localhost:3000 (Register with email + password)
2. **Onboarding wizard** walks you through:
   - Enter your display name
   - Choose your AI provider (OpenAI, Anthropic, Gemini, etc.)
   - Enter your API key
   - Pick a model
3. **Go to Channels** to connect Telegram, Discord, Slack, etc.
4. **Start chatting** via the Chat page or through your connected channels

### Useful URLs

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| OpenClaw Gateway UI | http://localhost:18789/openclaw |
| OpenClaw Health | http://localhost:18789/healthz |

### Stopping

```bash
# Stop all services
docker compose down

# Stop and remove all data (fresh start)
docker compose down -v
```

---

## Manual Setup (Without Docker)

### Prerequisites

- Python 3.11+
- Node.js 20+
- PostgreSQL 15+
- Redis 7+

### Mac

```bash
# Install deps
brew install postgresql@16 redis node python@3.12
brew services start postgresql@16
brew services start redis

# Create database
createdb sentientai
psql sentientai -c "CREATE USER sentientai WITH PASSWORD 'sentientai'; GRANT ALL PRIVILEGES ON DATABASE sentientai TO sentientai;"

# Backend
cd backend
cp .env.example .env   # Edit and add your API key
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

### Windows

```cmd
:: Install Python 3.12+, Node.js 20+, PostgreSQL 16, Redis (via Memurai or WSL)
:: Create database via pgAdmin or psql

cd backend
copy .env.example .env
:: Edit .env with notepad
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python main.py

:: New terminal
cd frontend
npm install
npm run dev
```

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install python3.12 python3.12-venv python3-pip nodejs npm postgresql redis-server
sudo systemctl start postgresql redis-server
sudo -u postgres psql -c "CREATE DATABASE sentientai;"
sudo -u postgres psql -c "CREATE USER sentientai WITH PASSWORD 'sentientai';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sentientai TO sentientai;"

cd backend
cp .env.example .env   # Edit and add your API key
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py

# New terminal
cd frontend && npm install && npm run dev
```

### Free Local AI (No API Key)

```bash
# Install Ollama: https://ollama.com/download
ollama pull llama3.2

# Set in backend/.env:
# LLM_PROVIDER=ollama
# LLM_MODEL=llama3.2
```

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and configure:

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | JWT signing key |
| `ENCRYPTION_KEY` | Yes | AES-256-GCM key for encrypting stored API keys |
| `DATABASE_URL` | Yes | PostgreSQL connection string (default works with Docker) |
| `REDIS_URL` | Yes | Redis connection string (default works with Docker) |
| `LLM_PROVIDER` | Yes | Default provider: `anthropic`, `openai`, `gemini`, `grok`, `deepseek`, `groq`, `mistral`, or `ollama` |
| `LLM_MODEL` | Yes | Default model name |
| `OPENCLAW_GATEWAY_URL` | Yes | OpenClaw gateway URL (Docker: `http://openclaw:18789`) |
| `*_API_KEY` | One | API key for your chosen provider |

### Generating Security Keys

```bash
python3 -c "import secrets, base64, os; print('SECRET_KEY=' + secrets.token_urlsafe(48)); print('ENCRYPTION_KEY=' + base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

---

## Architecture

```
sentientai/
├── backend/                       # Python / FastAPI
│   ├── core/                      # Config, database, security
│   ├── models/                    # User, Channel, Conversation, Message, Audit
│   ├── services/
│   │   ├── agent/                 # LLM runtime, 8 providers, context manager
│   │   └── openclaw/              # Config manager — writes openclaw.json
│   └── api/routes/                # Auth, Agent, Channels, Connectors, Audit
├── frontend/                      # React / TypeScript / Vite / Tailwind
│   └── src/
│       ├── pages/                 # Dashboard, Chat, Channels, Audit, Settings
│       ├── components/            # Layout, Sidebar
│       └── services/              # API client
└── docker/                        # Docker Compose + Dockerfiles
    └── docker-compose.yml         # PostgreSQL, Redis, OpenClaw, Backend, Frontend
```

### How the OpenClaw Wrapper Works

1. User signs up and completes onboarding (picks AI provider + API key)
2. Backend writes `openclaw.json` to a shared Docker volume with the user's model config
3. User connects channels (Telegram bot token, Discord token, etc.) via the Channels page
4. Backend encrypts tokens in the database, regenerates `openclaw.json` with channel configs
5. OpenClaw gateway reads the config and connects to all configured messaging platforms
6. Messages from any channel are routed through the user's chosen AI provider

### Security Features

- AES-256-GCM credential encryption for stored API keys and channel tokens
- JWT authentication with bcrypt password hashing
- Tiered permission engine (auto-approve, user-confirm, admin-only, hard-blocked)
- Prompt injection defense (input scanning, output validation)
- SHA-256 tamper-evident audit logs
- Security headers (X-Frame-Options, CSP, HSTS)
- Rate limiting per IP
- SSRF protection with DNS validation

---

## API Endpoints

### Auth
- `POST /api/auth/register` — Create account
- `POST /api/auth/login` — Login
- `GET /api/auth/me` — Current user
- `PATCH /api/auth/settings` — Update profile/LLM config

### Chat
- `GET /api/agent/conversations` — List conversations
- `POST /api/agent/conversations` — Create conversation
- `GET /api/agent/conversations/:id` — Get conversation with messages
- `POST /api/agent/conversations/:id/messages` — Send message (calls LLM)

### Channels (OpenClaw)
- `GET /api/channels` — List configured channels
- `POST /api/channels` — Connect a new channel
- `PATCH /api/channels/:id` — Update channel config
- `DELETE /api/channels/:id` — Remove channel
- `GET /api/channels/openclaw/status` — Gateway health check
- `POST /api/channels/openclaw/restart` — Force config re-sync

---

## License

This project is part of the CSCI-456 Senior Project at New York Institute of Technology.

**Author:** Krish Shroff (Team Leader)

**Team:** Rafi Hossain, Miadul Haque, Edrich Silva
