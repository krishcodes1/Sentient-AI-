# SentientAI Guardrails Platform — Design Spec

**Date:** 2026-05-13
**Status:** Approved — ready for implementation plan
**Author:** Krish Shroff (with team: Rafi Hossain, Miadul Haque, Edrich Silva)
**Target launch:** ~4 weeks from spec date

---

## 1. Context

SentientAI is a multi-provider AI agent platform that wraps OpenClaw as its agent runtime. It currently supports 8 LLM providers (Anthropic, OpenAI, Gemini, Grok, Deepseek, Groq, Mistral, Ollama) and 6 channels (Telegram, Discord, Slack, WhatsApp, Signal, WebChat). Tier 1 production hardening is complete: Alembic migrations, AAD-bound AES-256-GCM encryption, SHA-256 audit chain, IDOR fixes, JWT refresh tokens, PWA, CI.

The product is being repositioned. Today it markets itself as "a secure AI agent platform." Going forward, it markets itself as **"NeMo Guardrails for every AI provider — with a friendly UI."** NVIDIA's NeMo Guardrails is open source but recommends NVIDIA NIM for production, and requires the Colang DSL — a real barrier for non-developers. SentientAI's edge is **provider-neutrality, no DSL, and a configuration UI any operator can use.**

The codebase stays **closed source for now** (private repo) for IP protection and to keep commercial options open. The library is architected as if it will be open-sourced; that decision is deferred until post-graduation.

## 2. Goals

1. Ship a **production version** (not a demo) at a public URL with real users, monitoring, and backups within ~4 weeks.
2. Build **`openclaw-guardrails`**, a Python library with a stable public API, providing input/output/execution rails across every supported LLM provider.
3. Wrap the library with a **friendly configuration UI** so non-developers can enable/tune/test guardrails in three clicks.
4. Reposition existing security features (prompt-injection defense, tiered tool permissions, SHA-256 audit chain) as first-class guardrails.

## 3. Non-Goals

- **Open-source release** — deferred decision; keep the architecture ready for it.
- **Colang-style DSL** — YAML + UI is sufficient for V1; full programmable flow language is a V2 ask.
- **Retrieval rails** — RAG isn't a primary product surface today.
- **Custom user rails SDK** — V2.
- **Multi-language PII / non-English content moderation** — V2.
- **Multi-tenant SaaS mode** — out of scope; SentientAI remains single-tenant per deployment.

## 4. Architecture & Repository Structure

**Monorepo layout:**

```
sentientai/
├── packages/
│   └── openclaw-guardrails/        # the library (private for now)
│       ├── pyproject.toml
│       ├── src/openclaw_guardrails/
│       │   ├── __init__.py         # public API only
│       │   ├── engine.py           # GuardrailsEngine orchestrator
│       │   ├── config.py           # YAML loader + Pydantic schema
│       │   ├── rails/              # individual rail implementations
│       │   ├── providers/          # provider-agnostic LLM adapters
│       │   ├── types.py            # ScanResult, RailContext
│       │   └── exceptions.py
│       ├── tests/                  # unit tests, no app dependencies
│       └── README.md               # written as if PyPI-ready
│
├── backend/                        # SentientAI FastAPI app
│   ├── services/guardrails/        # adapter: DB config → engine
│   └── api/routes/guardrails.py    # config / simulate / metrics
│
├── frontend/                       # SentientAI React app
│   └── src/pages/Guardrails/       # config UI, simulator, dashboard
│
└── docker/                         # deployment
```

**Rationale:**
- Library is **private** but production-quality. A future open-source release is a `git subtree split` — no refactor needed.
- Backend imports the library locally: `pip install -e packages/openclaw-guardrails`. Same in-process speed as middleware; no network hop.
- Library is **provider-agnostic** from day one. `providers/` reuses SentientAI's existing multi-provider adapter code.
- Tests live with the library; runnable without booting the app.

**Public API surface (locked for V1, will not break):**

```python
from openclaw_guardrails import GuardrailsEngine, ScanResult, rails

# Config-driven (most common)
engine = GuardrailsEngine.from_yaml("rails.yaml")

# Or code-driven (for SDK users)
engine = GuardrailsEngine(rails=[rails.PII(), rails.Jailbreak()])

# Scan input before LLM call
result: ScanResult = await engine.scan_input(text, context={"user_id": "..."})

# Scan LLM output before returning to user
result: ScanResult = await engine.scan_output(text, source_messages=[...])

# Gate a tool / function call (execution rails)
result: ScanResult = await engine.check_tool_call(
    tool_name="send_email",
    args={"to": "...", "body": "..."},
    context={"user_id": "..."},
)
```

Three public symbols, three methods. Small surface = easy to keep stable.

## 5. Rails Catalog (V1)

Nine rails across three layers (5 input + 3 output + 1 execution). All work on every provider SentientAI supports.

### Input rails (run on user message before LLM is called)

| Rail | What it does | Action options |
|---|---|---|
| `PIIDetection` | Detects emails, phones, SSNs, credit cards, addresses, names | redact / block / log |
| `JailbreakDetection` | LLM-judge + pattern matching for prompt-injection attacks | block / log |
| `ToxicityFilter` | Profanity, hate speech, harassment | block / log |
| `TopicalControl` | Refuses queries outside allowed topic list | refuse with custom message |
| `LengthLimit` | Reject inputs above N tokens (cost control) | block |

### Output rails (run on LLM response before returning)

| Rail | What it does | Action options |
|---|---|---|
| `HallucinationCheck` | Compares response against provided sources; flags unsupported claims | flag / regenerate |
| `PIILeakage` | Strips PII the LLM hallucinated | redact |
| `ResponseToxicity` | Same as input rail but on LLM output | block / regenerate |

### Execution rails (run on tool/function calls)

| Rail | What it does | Action options |
|---|---|---|
| `ToolPermission` | Refactor of existing tiered permission system into a rail | auto / confirm / admin / block |

### V1 implementation choices

- **PII:** Microsoft Presidio (Apache 2.0, runs locally, no API key)
- **Jailbreak:** LLM-as-judge using a small/cheap model (Haiku 4.5 or GPT-4o-mini); pattern-matching short-circuit for obvious cases
- **Toxicity:** Detoxify (Apache 2.0, runs locally, no API key)
- **Topical:** LLM-as-judge with user-configured `allowed_topics` list
- **Hallucination:** LLM-as-judge comparing response to source context; fires only when sources are provided
- **Length:** stdlib tokenizer per provider

Everything runs in-process. No external API keys required beyond the existing LLM provider key.

### Deliberately deferred to V2+

- Retrieval rails (filter RAG sources)
- Self-check rails (LLM asks itself "is this safe?")
- Custom Python rails SDK
- Multi-language PII

## 6. Rules Config Format

Two formats, one schema. UI for non-developers, YAML for power users; both produce the same internal config.

### YAML format (power users + library users)

```yaml
version: 1
input_rails:
  - rail: pii
    action: redact
    types: [email, phone, ssn, credit_card]
  - rail: jailbreak
    action: block
    threshold: 0.7
    judge_model: claude-haiku-4-5
  - rail: topical
    action: refuse
    refusal_message: "I can only help with customer service questions."
    allowed_topics: [billing, returns, account_management]
  - rail: toxicity
    action: block
    threshold: 0.8

output_rails:
  - rail: hallucination
    action: regenerate
    require_citations: true
  - rail: pii_leakage
    action: redact

execution_rails:
  - rail: tool_permission
    tools:
      send_email: { tier: confirm }
      delete_calendar_event: { tier: block }
      query_database: { tier: auto }
```

### Internal schema (DB-backed)

```
users.guardrails_config JSONB
```

Same shape as YAML. UI writes via `PATCH /api/guardrails/config`. The engine reads this dict directly.

### UI mapping

Each rail in the catalog appears as a card with:
- Toggle (on/off)
- Action dropdown (block / redact / log / refuse)
- Threshold slider where applicable (0–1, visualized as "strict ↔ permissive")
- Custom message text field where applicable
- "Test in simulator" button

YAML import/export buttons provide portability between deployments.

### Default presets (shipped)

- 🟢 **Customer-facing** — PII redact, jailbreak block, toxicity block, topical control
- 🟡 **Internal team** — PII log-only, jailbreak block, others off
- 🔴 **Developer/testing** — Everything log-only, nothing blocks

New users pick one during onboarding (see §7).

## 7. User-Facing Features

Four new pages plus inline integration with existing pages.

### Guardrails Overview (new sidebar entry)

- Big status indicator: "🛡️ 5 rails active" or "⚠️ No rails configured"
- Last 7-day bar chart: requests scanned / blocked / flagged
- Top blocked categories
- "Configure rails" CTA

### Configure Rails

Two-column layout:
- **Left:** rail catalog as cards
- **Right:** selected rail's config panel
- **Top bar:** Import YAML / Export YAML

Plain-English explanations beneath each rail name.

### Simulator / Playground

- Input box, "Scan with current config" button, results panel
- Per-rail result: pass/fail, reason, latency
- "Save as test case" → regression suite

### Observability Dashboard

- Time-series charts (24h / 7d / 30d): scans, blocks, flags
- Per-rail breakdown
- Average latency per rail
- "Recent blocks" table with timestamp, rail, input excerpt, reason, "Mark as false positive"

### Inline integration

- **Chat page:** Blocked messages show "Blocked by [Rail name]. [Why?] [Allow once (admin only)]"
- **Audit log:** Rail events join the SHA-256 chain as a new event type
- **Channels page:** Inherit user's rail config (per-channel override is V2)

### Navigation

Sidebar order: Dashboard / Chat / Channels / **Guardrails** / Connectors / Audit / Settings.

### Onboarding wizard addition

New step between API-key entry and finish: "Choose a Guardrails preset" with the three presets above. Editable anytime from Guardrails page.

## 8. Production Deployment

### Cloud: Fly.io

**Why:** native Docker support, managed Postgres + Upstash Redis, ~$5/month minimum, free tier for dev, built-in TLS, custom domain, no vendor lock-in.

### Topology

```
Cloudflare DNS + WAF
        │
        ▼
sentientai.app  (custom domain)
        │
        ▼
Fly.io edge (TLS termination)
        │
        ├─► sentientai-frontend  (1-2 machines, nginx)
        ├─► sentientai-backend   (2-3 machines, uvicorn workers, autoscale)
        ├─► sentientai-openclaw  (1 machine)
        ├─► fly-pg               (managed Postgres, daily snapshots)
        └─► upstash-redis        (managed Redis)
```

### Monitoring & alerting

| Tool | Watches | Cost |
|---|---|---|
| Sentry | Backend + frontend errors | Free tier 5k/month |
| Better Stack | Centralized logs | Free tier 1GB/month |
| Fly metrics | CPU/mem/network | Free |
| UptimeRobot | External uptime (5-min) | Free, 50 monitors |

### Backups

- Postgres: Fly daily snapshots (7-day retention)
- Weekly cron: `pg_dump` → Cloudflare R2
- OpenClaw config volume: nightly backup to R2
- Restore drill documented in `docs/DEPLOYMENT.md`, tested pre-launch

### Production security checklist

- All secrets in Fly secrets store (not in repo)
- Database not publicly accessible (Fly private network only)
- Cloudflare WAF in front: rate limit, DDoS, OWASP basic rules
- HSTS preload, CSP strict, X-Frame-Options DENY (verify in prod headers)
- Sentry scrubs PII from error reports
- No `--reload`, `DEBUG=false`, no `/docs` route in production
- Cloudflare Turnstile on signup
- Email verification before account activation
- Privacy policy + ToS published

### Performance targets

| Metric | Target |
|---|---|
| API p50 (non-LLM) | < 100ms |
| API p95 (non-LLM) | < 500ms |
| LLM scan latency (per rail) | < 200ms |
| Frontend TTI (4G) | < 2s |
| Uptime SLO | 99.5% |

### Free-tier onboarding for "average users"

Ollama path lets people sign up with zero credit card, zero API key. Demo conversation pre-populated showing rail events.

### Documentation deliverables

- Public landing page at sentientai.app
- User docs at sentientai.app/docs — Quickstart, How rails work, FAQ
- Status page (Better Stack free)
- Privacy policy + ToS pages
- Updated `docs/CHANGELOG.md`

## 9. Phasing & Milestones (4 weeks)

### Week 1 — Foundation

**Goal:** working library with 3 essential rails, integrated into backend behind a feature flag.

- Scaffold `packages/openclaw-guardrails/`
- `engine.py`, `config.py`, `providers/` (refactor existing multi-provider adapter)
- Rails: `PIIDetection` (Presidio), `JailbreakDetection` (LLM-judge), `ToxicityFilter` (Detoxify)
- ≥10 unit tests per rail
- Backend wires `engine.scan_input/scan_output` into chat route, gated by `GUARDRAILS_ENABLED`

**Exit:** type-check passes, 30+ tests green, PII-laden chat message gets redacted in real time.

### Week 2 — Complete rails + API + UI shell

**Goal:** all 9 rails working; backend exposes config + simulate endpoints; frontend has a Guardrails section.

- Rails: `TopicalControl`, `LengthLimit`, `HallucinationCheck`, `PIILeakage`, `ToolPermission` (refactor existing tiered perms)
- Alembic migration: `users.guardrails_config JSONB` with default
- Backend API: `GET/PATCH /api/guardrails/config`, `POST /api/guardrails/simulate`, `GET /api/guardrails/metrics?range=7d`, `POST /api/guardrails/config/import|export`
- Frontend: Guardrails sidebar entry; Configure Rails page complete; stubs for Overview/Simulator/Observability
- E2E test: toggle rail in UI → message blocked in chat

**Exit:** all 9 rails pass unit tests, non-developer can enable/tune any rail through UI, config persists.

### Week 3 — Simulator + Observability + Onboarding + integration

**Goal:** the "wow demo" features work; existing pages integrate rails.

- Simulator page (live scan, save-as-test-case)
- Observability dashboard (time-series, recent blocks, false-positive feedback)
- Chat: inline "Blocked by [Rail]" UI; admin "Allow once" override
- Audit log: rail events on SHA-256 chain
- Onboarding wizard: preset-picker step
- Tooltips and plain-English copy on all rail cards
- Performance pass: per-rail scan latency <200ms

**Exit:** simulator demo runs <500ms end-to-end, observability shows real metrics, blocked chats render in-line UI, onboarding ships preset picker.

### Week 4 — Production deployment + launch

**Goal:** real public URL, real users, monitoring + backups + docs.

- Fly.io project: 5 apps, custom domain, TLS
- Secrets in Fly store
- Cloudflare DNS + WAF + Turnstile
- Sentry (backend + frontend SDKs, source maps)
- Better Stack log shipping
- UptimeRobot 3 monitors (frontend, backend `/health`, openclaw `/healthz`)
- Backups: pg_dump → R2 cron, restore drill executed
- Public landing page + Quickstart docs
- Privacy/ToS published
- Email verification flow
- Security pass: `npm audit`, `pip-audit`, `gitleaks` all green
- Load test: 100 concurrent users
- **LAUNCH:** r/LocalLLaMA, HN Show, Twitter

**Exit:** sentientai.app live, public signup works, first 10 external users complete onboarding, error rate <0.1%, p95 API latency <500ms in real traffic.

### Team allocation (suggested)

| | Week 1 | Week 2 | Week 3 | Week 4 |
|---|---|---|---|---|
| **Krish** | Library architecture, engine | Tool permission refactor, integration | Performance, audit chain | Deploy lead, security pass |
| **Rafi** | PII rail, Presidio | Topical / Length / Hallucination + API | Observability backend | Backups, restore drill |
| **Miadul** | Library tests | Configure Rails UI | Simulator + Observability UI, chat integration | Landing page, docs |
| **Edrich** | Jailbreak rail, LLM-judge framework | Toxicity rail + API | Onboarding preset, polish | Monitoring (Sentry/BetterStack/UptimeRobot) |

Flex roles — Krish re-balances if anyone is blocked.

## 10. Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| LLM-judge rails slow / expensive | UX feel, cost | Cheap models (Haiku/4o-mini); pattern short-circuit before LLM |
| Presidio is heavy (~200MB) | Container size | Lazy-load; regex-based fallback rail |
| Detoxify model download fails on first launch | Onboarding fail | Pre-bake into Docker image |
| Fly free tier insufficient under launch | Outage on launch | Budget $20/month, scale to paid plan launch-day |
| One team member blocked → slip | Schedule | Daily 10-min sync, parallel work, Krish flexes |
| Closed-source repo accidentally leaks | IP exposure | Pre-launch leak scan; private repo permissions audit |
| Security regression from rails refactor | Existing IDOR/JWT protections | All rail PRs require auth + IDOR test before merge |

## 11. Success Criteria

**Technical:**
- Library importable and runnable independently of SentientAI app
- All 9 rails pass ≥10 unit tests each
- p95 LLM scan latency <200ms per rail
- E2E test: toggle UI → behavior change verified
- Zero high/critical vulnerabilities in `npm audit` / `pip-audit` / `gitleaks` at launch

**Product:**
- Non-developer can configure rails in 3 clicks from onboarding
- Simulator returns results in <500ms
- Observability dashboard shows real metrics within 1h of first scan
- Three onboarding presets available and chosen during signup

**Production:**
- sentientai.app reachable with valid TLS
- Public signup → first chat in <5 minutes
- Monitoring + alerting fire on real errors (validated by injecting test errors pre-launch)
- Daily Postgres backup verified by performing a restore drill before launch
- 10 external users complete onboarding within first week
- Uptime ≥99.5% in first 30 days

**Strategic:**
- README + landing page position SentientAI clearly against NeMo Guardrails (no DSL, multi-provider, friendly UI)
- Library architected so a future open-source release is a `git subtree split`, not a refactor

## 12. Open Questions / Future Decisions

- **Open-source timing:** revisit post-graduation. Default: stay closed unless commercial path is unclear by then.
- **Domain name:** sentientai.app vs. alternative — needs availability check + team agreement.
- **Custom rail SDK (V2):** Python? Or higher-level config-only? Decide after V1 user feedback.
- **Per-channel rail overrides (V2):** customer-facing chat may want stricter rails than internal Slack; design TBD.
- **Free-tier limits:** how many requests/day for free users before requiring API key? TBD pre-launch.
