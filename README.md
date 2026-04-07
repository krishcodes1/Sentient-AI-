# SentientAI

**Secure-by-Design Agentic AI Platform**

A self-hosted AI assistant platform with security, user control, and auditability built into every layer. SentientAI integrates with Canvas LMS, Google Workspace, Robinhood Crypto, and more — with fine-grained permission scoping, multi-layer prompt injection defense, and tamper-evident audit logging.

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
   ```bash
   git clone https://github.com/krishcodes1/Sentient-AI-.git
   cd Sentient-AI-
   ```

3. **Configure environment**
   ```bash
   cp backend/.env.example backend/.env
   ```
   Edit `backend/.env` and add your API key (see [Environment Variables](#environment-variables) below).

4. **Start everything**
   ```bash
   cd docker
   docker compose up
   ```

5. **Open the app**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

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
| `SECRET_KEY` | Yes | Random string for signing JWT auth tokens. Pre-generated in `.env.example`. Change for production. |
| `ENCRYPTION_KEY` | Yes | Base64-encoded 32-byte key for AES-256-GCM encryption of stored credentials. Pre-generated in `.env.example`. |
| `DATABASE_URL` | Yes | PostgreSQL connection string. Default works with Docker. |
| `REDIS_URL` | Yes | Redis connection string. Default works with Docker. |
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

**You only need ONE API key** — whichever provider you choose.

To generate new secure keys:
```bash
python3 -c "import secrets, base64, os; print('SECRET_KEY=' + secrets.token_urlsafe(48)); print('ENCRYPTION_KEY=' + base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

---

## Architecture

```
sentientai/
├── backend/                    # Python / FastAPI
│   ├── core/                   # Config, database, security, network policy
│   ├── models/                 # SQLAlchemy ORM models
│   ├── services/
│   │   ├── agent/              # LLM runtime, providers, prompt guard, permissions, context manager
│   │   ├── connectors/         # Canvas LMS, Google Workspace, Robinhood
│   │   ├── audit.py            # Tamper-evident audit logging
│   │   └── auth.py             # JWT authentication
│   └── api/                    # FastAPI routes + middleware
├── frontend/                   # React / TypeScript / Vite / Tailwind
│   └── src/
│       ├── pages/              # Dashboard, Chat, Connectors, Audit Logs, Settings
│       ├── components/         # Layout, Sidebar
│       └── services/           # API client
└── docker/                     # Docker Compose, Dockerfiles
```

### Security Features

- **Multi-layer prompt injection defense** — regex pattern matching, heuristic analysis, output validation
- **Tiered permission engine** — auto-approve, user-confirm, admin-only, hard-blocked
- **Financial transaction hard block** — trades/transfers permanently blocked regardless of config
- **AES-256-GCM credential encryption** — API keys encrypted at rest
- **SHA-256 chain-linked audit logs** — tamper-evident, immutable action history
- **SSRF protection** — DNS resolution + IP validation against all private ranges (NemoClaw-inspired)
- **Deny-by-default network policies** — connectors can only reach allowlisted hosts/paths
- **OAuth 2.0 + PKCE** — secure auth for Canvas and Google integrations
- **Security headers** — X-Frame-Options, CSP, HSTS, etc.
- **Rate limiting** — per-IP request throttling

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
