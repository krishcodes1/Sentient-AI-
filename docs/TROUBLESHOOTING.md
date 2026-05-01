# Troubleshooting

Common failure modes and their fixes. If your issue isn't listed, file a GitHub issue with logs, environment, and reproduction steps.

## Table of Contents

- [Connectivity](#connectivity)
- [Database](#database)
- [Authentication](#authentication)
- [Encryption](#encryption)
- [OpenClaw Gateway](#openclaw-gateway)
- [Channels](#channels)
- [LLM Providers](#llm-providers)
- [Frontend](#frontend)
- [Performance](#performance)
- [Migrations](#migrations)

## Connectivity

### Cannot connect to backend at `localhost:8000`

**Likely cause:** backend container is not running or crashed at startup.

**Fix:**

```bash
docker compose ps                       # Is `backend` listed and "Up"?
docker compose logs --tail=200 backend  # What did it crash on?
docker compose restart backend
```

Common startup failures: missing `SECRET_KEY` / `ENCRYPTION_KEY`, malformed `DATABASE_URL`, port 8000 already bound on the host.

## Database

### `Database error: relation "users" does not exist`

**Likely cause:** migrations have not been applied.

**Fix:**

```bash
docker compose exec backend alembic upgrade head
```

In production, migrations are not auto-applied. Set `AUTO_MIGRATE=true` only in development; in prod, run upgrades manually as part of the deploy.

## Authentication

### Login returns `401` with the correct password

**Likely cause:** `SECRET_KEY` changed between restarts. Every issued JWT was signed with the old key; the new key rejects them.

**Fix:**

- Pin `SECRET_KEY` in `backend/.env` and **never let it regenerate at startup** (some setups regenerate on first boot if the value is missing).
- If you intentionally rotated the key, this is expected — users must re-login. Clear browser localStorage or hit the logout endpoint.

## Encryption

### `Encrypted credentials decode error` / GCM tag mismatch

**Likely cause:** `ENCRYPTION_KEY` is not the key that was used to encrypt the data. Either it changed, or the database was restored from a backup taken under a different key.

**Fix:**

- Restore the original `ENCRYPTION_KEY` from your secret manager.
- If the original key is unrecoverable: users must re-enter every API key and bot token. Run a one-time script to clear `*_enc` columns and trigger re-onboarding.
- See the [SECRETS.md key rotation runbook](SECRETS.md#encryption_key-rotation) for the dual-key migration approach.

## OpenClaw Gateway

### `OpenClaw gateway unhealthy`

**Likely cause:** binary install failed, wrong port binding, or workspace permissions.

**Fix:**

```bash
docker compose logs --tail=200 openclaw
docker compose exec openclaw ls -la /home/node/.openclaw
docker compose exec openclaw which openclaw
```

Common causes:
- `npm install -g openclaw@latest` failed (network, registry mirror) — restart the container so the install retries.
- Port `18789` is already bound on the host — `lsof -i :18789` to find the offender.
- `/home/node/.openclaw` is not writable — check the named volume's ownership.

## Channels

### Telegram bot not responding

**Likely cause:** invalid token, gateway not reaching `api.telegram.org`, or webhook conflict.

**Fix:**

- Validate the token: `curl https://api.telegram.org/bot<TOKEN>/getMe`. If this returns `401`, regenerate via @BotFather.
- Check outbound DNS from the openclaw container: `docker compose exec openclaw getent hosts api.telegram.org`.
- If the bot was previously configured with a webhook elsewhere, switch to polling: delete the old webhook (`/deleteWebhook`).

### Discord returns `401`

**Likely cause:** bot token revoked, regenerated, or pasted with a leading/trailing whitespace. Or the bot lacks the required intents/scopes.

**Fix:**

- Re-copy the token from the Discord Developer Portal (it shows once on regenerate; if you missed it, regenerate again).
- Re-invite the bot to the server with the OAuth2 URL that grants `bot` + `applications.commands` scopes.

### WhatsApp QR code never appears

**Known limitation.** WhatsApp via Baileys requires interactive session pairing and persistent session storage that the current containerized setup doesn't fully wire up. Tracked on [ROADMAP.md](ROADMAP.md). Workaround: pair locally, copy the resulting session files into the named volume.

## LLM Providers

### LLM provider returns `401`

**Likely cause:** API key is invalid, expired, or out of credits.

**Fix:**

- Test the key directly with `curl` to the provider's `/models` endpoint.
- Check the provider dashboard for billing status.
- Rotate the key (see [SECRETS.md](SECRETS.md#per-provider-api-key-rotation-anthropic-openai-etc)).
- For per-user keys (entered through onboarding), the user re-enters via the Settings page; the new key is encrypted and replaces the old one.

## Frontend

### Frontend shows a blank page

**Likely cause:** unhandled JS error, or CORS blocked the API call so the app can't bootstrap.

**Fix:**

1. Open browser DevTools → Console. Look for red errors.
2. Network tab: are API calls returning `200`, or being blocked with "CORS missing allow origin"?
3. If CORS: add your frontend origin to `CORS_ORIGINS` in `backend/.env`:

   ```env
   CORS_ORIGINS=["https://app.example.com","http://localhost:3000"]
   ```

   Restart the backend.

## Performance

### Slow response times

**Likely cause:** any of: DB connection pool exhaustion, Redis down, LLM provider latency, or N+1 queries.

**Fix in order:**

```bash
docker compose exec db psql -U sentientai -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"
docker compose exec redis redis-cli ping
docker compose logs --tail=100 backend | grep -i 'duration\|slow'
```

- If many `idle in transaction` connections, suspect a missing `await session.commit()`.
- If Redis is unreachable, rate-limit middleware fails open (allows everything) but per-user pending-approval state is lost.
- LLM latency is bounded by the provider; consider switching `LLM_PROVIDER` to `groq` for testing — it's typically the fastest.

### Memory growing over time

**Likely cause:** `--reload` mode (dev) leaks workers; or unbounded conversation history caching in memory.

**Fix:**

- In production, the entrypoint must not pass `--reload`. Use multi-worker uvicorn:

  ```bash
  uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
  ```

- Profile with `py-spy`:

  ```bash
  docker compose exec backend pip install py-spy
  docker compose exec backend py-spy dump --pid 1
  ```

## Migrations

### `Migration failed: column already exists`

**Likely cause:** an earlier startup ran `Base.metadata.create_all`, which created tables/columns directly. Alembic now thinks it needs to add them but Postgres says they're already there.

**Fix:** mark the database as already at HEAD without running anything, then proceed with future migrations normally:

```bash
docker compose exec backend alembic stamp head
```

**Going forward:** the production startup path no longer calls `create_all`. Migrations are the single source of schema truth.
