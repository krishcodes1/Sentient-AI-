# Architecture

System overview, request flows, data model, and trust boundaries.

## Table of Contents

- [High-Level Diagram](#high-level-diagram)
- [Component Responsibilities](#component-responsibilities)
- [Request Flows](#request-flows)
- [Data Model](#data-model)
- [Trust Boundaries](#trust-boundaries)
- [Multi-Tenant Model](#multi-tenant-model)
- [Future Direction](#future-direction)

## High-Level Diagram

```
   Telegram   Discord   Slack   WhatsApp   Signal   WebChat
       │         │        │         │         │        │
       └─────────┴────────┼─────────┴─────────┴────────┘
                          │
                          ▼
              ┌──────────────────────────┐
              │   OpenClaw Gateway       │   port 18789
              │   (Node, channel        │   wraps OpenClaw,
              │    adapters, routing)   │   reads openclaw.json
              └────────────┬─────────────┘
                           │  HTTP webhook / WS
                           ▼
              ┌──────────────────────────┐
              │   SentientAI Backend     │   port 8000
              │   (FastAPI, async)       │   auth, agent runtime,
              │                          │   audit, encryption
              └──────┬───────────┬───────┘
                     │           │
                     ▼           ▼
              ┌─────────┐  ┌──────────┐
              │Postgres │  │  Redis   │
              │  16     │  │   7      │
              │ durable │  │ rate-lim,│
              │ store   │  │ cache,   │
              │         │  │ pending  │
              └─────────┘  └──────────┘
                     ▲
                     │
              ┌──────┴──────────────────┐
              │   SentientAI Frontend   │   port 3000
              │   (React + Vite + TS    │   served by Nginx
              │    + Tailwind, prod)    │   in production
              └─────────────────────────┘
                          ▲
                          │  HTTPS
                          │
                       Browser
```

## Component Responsibilities

### Frontend (`frontend/`)

- **Stack:** React 18, Vite, TypeScript, Tailwind CSS.
- **Owns:** UI rendering, auth state in localStorage, API client, optimistic updates, websocket subscriptions for live chat.
- **Does not own:** business logic, secrets, persistent state. The frontend is a thin client over the backend API.
- **Production serving:** built static bundle served by Nginx (the multi-stage Dockerfile takes care of this); the dev server is `vite dev` only.

### Backend (`backend/`)

- **Stack:** FastAPI, SQLAlchemy 2.0 (async), Alembic, Pydantic v2, structlog.
- **Owns:** authentication (`api/routes/auth.py`), authorization, business logic, LLM orchestration (`services/agent/runtime.py`), encryption (`core/security.py`), audit logging, rate limiting, OpenClaw config sync.
- **Does not own:** the messaging channels themselves. It writes `openclaw.json` and lets the gateway take it from there.

### OpenClaw Gateway

- **Stack:** Node, packaged from the upstream `openclaw` npm module.
- **Owns:** channel adapters (Telegram bot polling, Discord WS, Slack events API, WhatsApp/Baileys, Signal, WebChat). Routes inbound messages to the backend webhook; routes outbound responses to the right channel.
- **Configured by:** `openclaw.json`, written by the backend whenever a user's settings or channels change. Lives on a shared Docker volume (`openclaw_config`).

### PostgreSQL

- **Version:** 16 (Alpine).
- **Owns:** all durable state — users, conversations, messages, channels, connectors, audit logs.
- **Encryption:** AES-256-GCM ciphertext for credential columns; rest of the schema is plaintext.
- **Connection pool:** SQLAlchemy async engine with default pool of 5 + 10 overflow per worker.

### Redis

- **Version:** 7 (Alpine).
- **Owns:** rate-limit sliding-window counters, pending tool-approval state (waiting on user-confirm tier), short-lived cache for LLM provider model lists.
- **Not** a primary store — failure of Redis degrades the system gracefully (rate limit fails open, pending approvals lost on a restart).

## Request Flows

### Web chat: user sends a message

```
[Browser]                    [Frontend]                  [Backend]                [LLM provider]    [Postgres]
  user types  ─────────────►  POST /api/agent/conversations/:id/messages
                                                    │
                                                    ├─ get_current_user (JWT)
                                                    ├─ ownership check on conversation
                                                    ├─ persist user message ──────────────────────►
                                                    ├─ load conversation context ◄─────────────────
                                                    ├─ prompt-guard scan
                                                    ├─ runtime.invoke(provider, model, messages) ──► HTTPS
                                                    │                              ◄────────────────
                                                    ├─ output validation + audit
                                                    ├─ persist assistant message ────────────────►
                                                    │
              ◄─────────────  200 { message }
  render
```

### Telegram: user messages a bot

```
[Telegram user] ─► [Telegram BotAPI] ─► [OpenClaw Gateway] ─► [Backend webhook]
                                                                      │
                                                                      ├─ identify channel → user
                                                                      ├─ load or create conversation
                                                                      ├─ same LLM flow as above
                                                                      ▼
                                                              [LLM provider]
                                                                      │
                                                                      ▼
                                            [Backend response] ─► [OpenClaw] ─► [Telegram BotAPI] ─► [Telegram user]
```

The gateway is fire-and-forget on the inbound side: it forwards to the backend webhook and the backend is responsible for round-tripping the response back through the gateway.

## Data Model

Core tables (a fuller ER diagram is on the roadmap):

| Table | Owns | Encrypted columns |
|---|---|---|
| `users` | identity, default LLM provider/model | `llm_api_key_enc` |
| `conversations` | user-scoped chat threads | (none) |
| `messages` | individual chat turns | (none — content is plaintext by design) |
| `channels` | per-user channel configs (Telegram bot, etc.) | `token_enc` |
| `connectors` | per-user external integrations (Canvas, Google) | `credentials_enc` |
| `audit_logs` | append-only audit chain | (none — but `previous_hash` chains) |

All user-scoped tables include `user_id` and a foreign key to `users`. Every query that reads or writes them filters by `user_id`.

## Trust Boundaries

```
       [Browser]  ──  untrusted; everything must be re-validated server-side
            │
       Internet (TLS)
            │
       [Caddy reverse proxy]  ──  trust boundary 1: terminates TLS
            │
       [Backend]  ──  the trust kernel; authn + authz live here
       │  │
       │  ├─► [Postgres]  ──  trusted; private network
       │  └─► [Redis]     ──  trusted; private network
       │
       │ HTTP webhook / outbound HTTPS
       ▼
       [OpenClaw Gateway]  ──  semi-trusted; we write its config but it talks to the public internet
            │
            ▼
       [Telegram / Discord / Slack / ...]  ──  untrusted; treat all inbound channel content as user input
```

- **Input validation** happens at the Pydantic schema layer on the backend. The frontend's validation is for UX, not security.
- **Output sanitization** (escaping, content security) happens at the React rendering layer for plain content, and at the channel adapter for channel-specific markup.
- **Tool calls** generated by the LLM are validated against schemas and the permission tier system before any side effect is taken.

## Multi-Tenant Model

SentientAI is **single-tenant per deployment, multi-user inside that tenant.** One install serves one team / class / organization. Users in the same install share a Postgres database but have strictly isolated rows (`user_id` filter on every query).

Cross-tenant isolation (multiple organizations on one cluster) is not in scope for the senior-project release and would require namespacing every query by `tenant_id`, separating audit chains, and rethinking the OpenClaw config layout.

## Future Direction

- **PWA** — manifest + service worker for offline-capable mobile-web experience. (Tier 1, near-term.)
- **Native mobile app** — React Native, sharing the API client. (Tier 2.)
- **Kubernetes manifests** — Helm chart, horizontal pod autoscaler, separate StatefulSets for Postgres/Redis. (Tier 2.)
- **Multi-region active-active** — requires CRDT-style audit chain or a single-writer election. (Tier 3.)
- **Plugin marketplace** — third-party connectors with a sandboxed runtime. (Tier 3.)
- **Voice channel** — Twilio + Whisper STT + provider TTS. (Tier 3.)

See [ROADMAP.md](ROADMAP.md) for tracking.
