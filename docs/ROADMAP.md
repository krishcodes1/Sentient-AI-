# Roadmap

Honest about scope: this is a CSCI-456 Senior Project at NYIT, not a venture-backed startup. The roadmap reflects what one student team can ship in a semester, what's realistic to extend after, and what's aspirational.

## Tier 1 — Ship before final demo

- [x] Production-grade Docker Compose (multi-stage builds, non-root, healthchecks)
- [x] Alembic migrations replacing `Base.metadata.create_all`
- [x] Auth on `/api/connectors` and `/api/audit` (closes IDOR P0)
- [x] AAD-bound AES-256-GCM for credential encryption
- [x] SHA-256-chained audit logs with `previous_hash`
- [x] Refresh tokens + account lockout + password reset
- [x] Connectors page in the dashboard
- [x] Mobile-responsive sidebar (hamburger), PWA manifest, service worker
- [x] CI: lint, typecheck, test, build, security scan on every PR
- [x] Comprehensive docs: deployment, secrets, security, troubleshooting, architecture, contributing

## Tier 2 — Next 1–2 quarters (post-graduation friendly)

- [ ] **Native mobile app** (React Native), reusing the API client and design tokens
- [ ] **Kubernetes manifests** + Helm chart for multi-replica deploys
- [ ] **GDPR data export endpoint** (`GET /api/me/export` → tar.gz of every user-owned row)
- [ ] **`ENCRYPTION_KEY` rotation tooling** — dual-key migration script, drop-in admin command
- [ ] **WhatsApp session storage** — fix the QR-pairing limitation, persist Baileys session to a managed volume
- [ ] **Per-user usage metering** — token counts, cost attribution per provider
- [ ] **OpenAPI client generation** for the frontend (eliminates hand-written API types)

## Tier 3 — Aspirational

- [ ] **Multi-region active-active** — requires CRDT-style audit chain or single-writer election
- [ ] **Plugin marketplace** for third-party connectors, sandboxed runtime
- [ ] **Browser extension client** — sidebar that surfaces SentientAI on any page
- [ ] **Voice channel** — Twilio in, Whisper STT, provider TTS, voice-mode conversations
- [ ] **Multi-tenant SaaS mode** — namespace every query by `tenant_id`, separate audit chains
- [ ] **SOC 2 Type II / HIPAA readiness** — would require formal security program, audit, etc.

## Out of scope

- **Custom model training.** SentientAI is a frontend over upstream LLM providers; we don't host or fine-tune models.
- **Trading / fund movement.** Robinhood and similar connectors are read-only by hard-blocked invariant — see [SECURITY.md](SECURITY.md#tiered-permissions).
