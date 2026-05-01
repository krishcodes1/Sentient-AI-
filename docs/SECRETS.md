# Secrets Management

How SentientAI handles credentials, where to put them, how to rotate them, and what to do when they leak.

## Table of Contents

- [Why This Matters](#why-this-matters)
- [Generating Secrets](#generating-secrets)
- [Required vs Optional Variables](#required-vs-optional-variables)
- [Key Rotation Procedures](#key-rotation-procedures)
- [Leaked Key Response](#leaked-key-response)
- [Where Not to Put Secrets](#where-not-to-put-secrets)
- [Recommended Secret Managers](#recommended-secret-managers)

## Why This Matters

SentientAI stores per-user LLM API keys, channel bot tokens (Telegram, Discord, Slack), and connector credentials (Canvas, Google, Robinhood) on behalf of every user. These are encrypted at rest with **AES-256-GCM** using `ENCRYPTION_KEY`. JWT session tokens are signed with `SECRET_KEY`. If either key leaks, every encrypted record and every active session is at risk.

Treat `SECRET_KEY` and `ENCRYPTION_KEY` like database root passwords. They are not configuration — they are crown jewels.

## Generating Secrets

### Recommended one-liner

```bash
python3 -c "import secrets, base64, os; print('SECRET_KEY=' + secrets.token_urlsafe(48)); print('ENCRYPTION_KEY=' + base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

### OpenSSL alternative

```bash
echo "SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')"
echo "ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')"
```

`ENCRYPTION_KEY` must be exactly 32 bytes (URL-safe-base64-encoded → 44 characters with `=` padding) — the AES-256-GCM cipher requires it.

## Required vs Optional Variables

| Variable | Required | Purpose | How to generate |
|---|---|---|---|
| `SECRET_KEY` | Yes | Signs JWT access + refresh tokens | `secrets.token_urlsafe(48)` |
| `ENCRYPTION_KEY` | Yes | AES-256-GCM key encrypting per-user credentials in Postgres | `base64.urlsafe_b64encode(os.urandom(32))` |
| `DATABASE_URL` | Yes | Postgres DSN; contains DB password | Set at provision time |
| `REDIS_URL` | Yes | Redis DSN for rate limits + cache | Set at provision time |
| `LLM_PROVIDER` | Yes | Default provider name | One of `anthropic`/`openai`/`gemini`/`grok`/`deepseek`/`groq`/`mistral`/`ollama` |
| `LLM_MODEL` | Yes | Default model identifier | Provider-specific (e.g. `claude-sonnet-4-20250514`) |
| `OPENCLAW_GATEWAY_URL` | Yes | Internal URL of OpenClaw gateway | `http://openclaw:18789` in Docker |
| `ANTHROPIC_API_KEY` | Conditional | Required only if Anthropic is the chosen provider | console.anthropic.com |
| `OPENAI_API_KEY` | Conditional | Required only if OpenAI is the chosen provider | platform.openai.com |
| `GEMINI_API_KEY` | Conditional | Google AI Studio key | aistudio.google.com/apikey |
| `GROK_API_KEY` / `DEEPSEEK_API_KEY` / `GROQ_API_KEY` / `MISTRAL_API_KEY` | Conditional | Provider-specific | See `.env.example` |
| `CORS_ORIGINS` | Optional | JSON list of allowed origins | Default permits localhost dev |
| `RATE_LIMIT_PER_MINUTE` | Optional | Per-IP rate limit | Default `60` |
| `TOKEN_EXPIRE_MINUTES` | Optional | Access token lifetime | Default `60` |

## Key Rotation Procedures

### `SECRET_KEY` rotation (JWT signing key)

Rotating invalidates every active session — by design.

1. Generate the new key (see above).
2. Edit `backend/.env`, replacing `SECRET_KEY=...`.
3. **Drain old sessions:** announce a 60-minute maintenance window so users finish in-flight work.
4. Restart the backend: `docker compose restart backend`.
5. All clients will receive `401` and the frontend will redirect to `/login`. Users re-login normally.

### `ENCRYPTION_KEY` rotation

This is **irreversible without a migration.** Rotating without migrating breaks every encrypted credential in the database — users would have to re-enter every API key and bot token.

The dual-key migration approach:

1. Add a transient `ENCRYPTION_KEY_OLD` env var; keep the old key value there.
2. Set `ENCRYPTION_KEY` to the new value.
3. Run a migration script that, for every encrypted column (`users.llm_api_key_enc`, `channels.token_enc`, `connectors.credentials_enc`):
   - decrypts with `ENCRYPTION_KEY_OLD`
   - re-encrypts with `ENCRYPTION_KEY`
   - writes back in a single transaction
4. Verify a sample of records can be decrypted with the new key.
5. Remove `ENCRYPTION_KEY_OLD` from the env and restart the backend.

Until the migration scaffolding ships (tracked on [ROADMAP.md](ROADMAP.md)), the safer path is: announce maintenance, force re-onboarding, rotate the key. Crude but correct.

### Per-provider API key rotation (Anthropic, OpenAI, etc.)

Comparatively painless:

1. Edit `backend/.env`, update the relevant `*_API_KEY=...` line.
2. `docker compose restart backend openclaw`.
3. Channel adapters (Telegram bot, Discord bot, etc.) re-handshake automatically. Users' per-account keys (entered through onboarding) are unaffected.

## Leaked Key Response

If you suspect any secret has been exposed:

1. **Revoke at the provider immediately.** Anthropic / OpenAI / Telegram / Discord all expose a "revoke key" or "regenerate token" button. Do that first — minutes matter.
2. **Generate a replacement** (same procedure as the rotation flows above).
3. **Update `backend/.env`** and restart the affected services.
4. **Audit:** review `audit_logs` for unauthorized actions in the leak window. Filter by IP, by `tool_call`, by user. The audit chain is SHA-256-linked, so tampering is detectable.
5. **Notify affected users** if any per-user data could have been exposed.
6. **Postmortem:** how did it leak? Tighten the gap (CI logs, screenshots, accidental commit, etc.).

## Where Not to Put Secrets

- **Never** check `backend/.env` into git. It's gitignored — keep it that way.
- **Never** hardcode secrets in `docker-compose.yml`. Reference them via `env_file:` or `${VAR}` interpolation.
- **Never** bake secrets into a `Dockerfile` (`ENV`, `ARG`). They persist in image layers forever and ship to anyone who can pull the image.
- **Never** paste secrets into chat logs, Slack, screenshots, or PR descriptions.
- **Never** enable verbose logging that prints request bodies — they may contain `Authorization` headers in development.

## Recommended Secret Managers

For anything beyond a single demo VM, externalize secrets:

| Tool | Best for | Integration |
|---|---|---|
| **HashiCorp Vault** | Self-hosted, full audit, dynamic secrets | Pull at startup via Vault Agent or sidecar |
| **AWS Secrets Manager** | AWS-native deployments | IAM-scoped reads, automatic rotation |
| **Doppler** | Multi-env (dev/staging/prod) sync | `doppler run -- docker compose up` |
| **1Password Connect** | Small teams already on 1Password | Self-hosted Connect server, SDK injection |

In every case the pattern is: secrets manager populates `backend/.env` (or sets env vars on the container directly) at deploy time. The application code is unchanged.
