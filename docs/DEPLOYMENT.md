# Deployment Guide

End-to-end instructions for deploying SentientAI to production. For local development, see the project [README](../README.md).

## Table of Contents

- [Pre-flight Checklist](#pre-flight-checklist)
- [Recommended Deployment Targets](#recommended-deployment-targets)
- [Single-VM Docker Compose Deployment](#single-vm-docker-compose-deployment)
- [Updating](#updating)
- [Rolling Back](#rolling-back)
- [Logs and Diagnostics](#logs-and-diagnostics)
- [Backups](#backups)
- [Resource Sizing](#resource-sizing)

## Pre-flight Checklist

Before you point DNS at anything, work through this list:

- [ ] **Rotate all default credentials** in `backend/.env.example`. The defaults are placeholders; never deploy them.
- [ ] **Choose your LLM provider** and procure a paid API key (or stand up Ollama for local inference).
- [ ] **Generate fresh secrets** for `SECRET_KEY` and `ENCRYPTION_KEY`. See [SECRETS.md](SECRETS.md).
- [ ] **Configure DNS** — point an A record (or AAAA) at the host, e.g. `app.example.com`.
- [ ] **Choose a deployment target** (see below).
- [ ] **Enable firewall** on the host: allow only 22, 80, 443. Internal ports (5432, 6379, 8000, 18789) must not be public.
- [ ] **Plan your backup strategy** before there's data to lose.

## Recommended Deployment Targets

| Target | Best for | Notes |
|---|---|---|
| **Single-VM Docker Compose** | Senior project demo, small teams (<50 users) | Cheapest, simplest. Recommended starting point. |
| **Single-host Caddy + Compose** | Public-facing demo with TLS | Adds Caddy on top of the compose stack for automatic HTTPS. |
| **Kubernetes** | Multi-region, HA, auto-scaling | **Manifests not yet included.** Tracked on [ROADMAP.md](ROADMAP.md). |

## Single-VM Docker Compose Deployment

Assumes Ubuntu 22.04 LTS or later. Other distros work; commands may differ.

### 1. Provision the VM

Minimum: **2 GB RAM, 20 GB disk, 1 vCPU.** See [Resource Sizing](#resource-sizing) for higher tiers. Open inbound 22, 80, 443 only.

### 2. Install Docker and Compose

```bash
sudo apt update && sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker
```

### 3. Clone the repository

```bash
git clone https://github.com/krishcodes1/Sentient-AI-.git
cd Sentient-AI-/docker
```

### 4. Configure environment

```bash
cp ../backend/.env.example ../backend/.env
nano ../backend/.env   # Replace SECRET_KEY, ENCRYPTION_KEY, *_API_KEY
```

See [SECRETS.md](SECRETS.md) for generating values and the rotation runbook.

### 5. Pull and start services

```bash
docker compose pull
docker compose up -d
```

### 6. Run database migrations

```bash
docker compose exec backend alembic upgrade head
```

In production, migrations are **not** auto-applied — they must be run explicitly on each release.

### 7. Reverse proxy with Caddy (TLS + WebSocket upgrade)

Install Caddy on the host (`sudo apt install caddy`), then write `/etc/caddy/Caddyfile`:

```caddy
app.example.com {
    encode gzip zstd

    @websocket {
        header Connection *Upgrade*
        header Upgrade websocket
    }

    handle /api/* {
        reverse_proxy localhost:8000
    }

    handle /openclaw/* {
        reverse_proxy @websocket localhost:18789
        reverse_proxy localhost:18789
    }

    handle {
        reverse_proxy localhost:3000
    }
}
```

Reload: `sudo systemctl reload caddy`. Caddy auto-issues TLS certs from Let's Encrypt.

### 8. Verify

```bash
curl https://app.example.com/api/health
# {"status":"healthy","version":"0.1.0"}
```

## Updating

```bash
cd Sentient-AI-
git pull
cd docker
docker compose pull
docker compose up -d
docker compose exec backend alembic upgrade head
```

Schema changes ship as Alembic revisions; the upgrade is safe to run on a hot system.

## Rolling Back

```bash
docker compose down
git checkout <previous-tag>
docker compose up -d
docker compose exec backend alembic downgrade -1
```

Only roll back one migration at a time. Test downgrades on a staging copy first — destructive migrations cannot always be reversed safely.

## Logs and Diagnostics

```bash
docker compose logs -f --tail=200 backend     # Follow backend logs
docker compose logs --tail=500 openclaw       # Recent gateway logs
docker compose ps                             # Service health snapshot
docker compose exec backend python -m alembic current   # Current migration
```

## Backups

### PostgreSQL — daily pg_dump

Add to root's crontab (`sudo crontab -e`):

```cron
0 3 * * * docker compose -f /opt/Sentient-AI-/docker/docker-compose.yml exec -T db pg_dump -U sentientai sentientai | gzip > /var/backups/sentientai-$(date +\%F).sql.gz
0 4 * * * find /var/backups -name 'sentientai-*.sql.gz' -mtime +14 -delete
```

### Named volumes — weekly tarball

```bash
docker run --rm -v sentientai_pgdata:/data -v /var/backups:/out alpine \
  tar czf /out/pgdata-$(date +%F).tar.gz -C /data .
```

Replicate `/var/backups` off-host (S3, B2, restic) — local backups don't survive a host failure.

## Resource Sizing

| Scale | RAM | CPU | Disk | Notes |
|---|---|---|---|---|
| 1 user (demo) | 1 GB | 1 vCPU | 10 GB | Single VM is fine. |
| 10 users | 2 GB | 2 vCPU | 20 GB | Default compose stack. |
| 100 users | 4–8 GB | 4 vCPU | 50 GB | Move Postgres to a dedicated host or managed DB. |
| 1000+ users | Move to Kubernetes; partition by tenant. | | | See [ROADMAP.md](ROADMAP.md). |

LLM inference happens at the provider (Anthropic/OpenAI/etc.), so compute on the host is dominated by the FastAPI worker pool and Postgres. Bottleneck is almost always Postgres connections — tune `pool_size` before scaling vertically.
