# Security

Threat model, defense-in-depth layers, disclosure policy, and compliance notes for SentientAI.

## Table of Contents

- [Threat Model](#threat-model)
- [Defense Layers](#defense-layers)
  - [Authentication](#authentication)
  - [Authorization](#authorization)
  - [Encryption at Rest](#encryption-at-rest)
  - [Encryption in Transit](#encryption-in-transit)
  - [Prompt Injection Defense](#prompt-injection-defense)
  - [Tiered Permissions](#tiered-permissions)
  - [Audit Logging](#audit-logging)
  - [SSRF Protection](#ssrf-protection)
  - [Rate Limiting](#rate-limiting)
  - [Container Hardening](#container-hardening)
- [Disclosure Policy](#disclosure-policy)
- [Compliance Notes](#compliance-notes)

## Threat Model

### In scope

- **Per-user credential theft.** A logged-in attacker should not be able to read another user's stored API keys, channel tokens, or connector credentials.
- **Prompt injection.** Untrusted text (user message, document content, channel webhook payload) attempting to override the system prompt or coerce tool calls.
- **IDOR (Insecure Direct Object Reference).** Authenticated user requesting another user's conversation, audit log, or channel by ID.
- **SSRF (Server-Side Request Forgery).** LLM-generated URLs causing the backend to fetch internal-network resources (cloud metadata, intranet, localhost services).
- **Audit log tampering.** Insider or attacker with DB access modifying or deleting audit entries to hide malicious activity.
- **Credential leakage in logs.** API keys appearing in stack traces, request bodies, or error responses.

### Out of scope

- **Physical access to the host.** Disk encryption, BIOS, hardware tampering — assumed mitigated by the cloud provider.
- **Supply-chain compromise** of upstream dependencies (PyPI, npm, Docker Hub). Pinned versions and CI security scans help, but a malicious maintainer of `cryptography` is outside our threat model.
- **Compromise of upstream LLM providers.** If Anthropic's API leaks user prompts, we cannot prevent that.

## Defense Layers

### Authentication

- **Password hashing:** `bcrypt` with default work factor (12 rounds). Plain passwords are never logged or stored.
- **JWT access tokens:** Signed with `SECRET_KEY` (HS256). Short-lived (default 60 min, configurable via `TOKEN_EXPIRE_MINUTES`).
- **Refresh tokens** *(PR pending)*: Long-lived, single-use, rotated on every refresh; revocation list backed by Redis.
- **Account lockout** *(PR pending)*: Five failed logins → 15-minute lockout, exponential backoff after that.
- **Password reset** *(PR pending)*: Single-use token with 30-minute expiry, sent via email out-of-band.

### Authorization

Every authenticated route declares `current_user: User = Depends(get_current_user)`. Beyond that, every database query that touches user-owned rows includes an explicit `WHERE user_id = current_user.id` clause. Ownership is checked at the query level — never trust the client to send the right ID.

The `/api/connectors` and `/api/audit` routes were the historical IDOR weak points; the production-readiness branch adds `Depends(get_current_user)` and ownership filtering to both. See [CHANGELOG.md](CHANGELOG.md).

### Encryption at Rest

User secrets (LLM API keys, channel bot tokens, connector credentials) are encrypted with **AES-256-GCM** before being written to Postgres.

- **Key:** `ENCRYPTION_KEY` (32 raw bytes, URL-safe-base64-encoded in env).
- **Nonce:** 96-bit random value, prepended to ciphertext.
- **AAD (Additional Authenticated Data):** `"<user_id>:<field_name>"`. Binding ciphertext to its owner means a row-swap attack — copying user A's encrypted key into user B's row — fails the GCM tag check at decrypt time.
- **Storage format:** `base64(nonce || ciphertext || tag)`.

Database backups inherit this encryption. The DB password protects the data dump; `ENCRYPTION_KEY` protects the cell contents. Compromise of either alone is not enough.

### Encryption in Transit

- **External traffic:** TLS terminated at the reverse proxy. Recommended setup: Caddy with automatic Let's Encrypt issuance — see [DEPLOYMENT.md](DEPLOYMENT.md).
- **Internal Docker network:** Plaintext between services (backend ↔ db, backend ↔ openclaw). Acceptable because the network is private to the host; never bind these ports to the public interface.
- **Outbound to LLM providers:** All providers enforce HTTPS. The HTTP client validates certificates by default — never set `verify=False`.

### Prompt Injection Defense

Layered, not perfect — assume some attempts will get through and design downstream layers accordingly.

- **Input scanning** (`services/agent/prompt_guard.py`): regex + heuristic patterns flag known jailbreak phrases, role-injection markers, and tool-spoofing attempts.
- **NFKC normalization:** Unicode is normalized before scanning to defeat homoglyph and zero-width-char obfuscation.
- **Output validation:** Tool-call arguments are schema-checked before execution; structured fields (URLs, file paths, SQL) are validated against allowlists.
- **System prompt isolation:** User input is wrapped in delimiters and the system prompt explicitly instructs the model to ignore instructions inside delimited regions.

### Tiered Permissions

Every tool call falls into one of four tiers:

| Tier | Behavior | Examples |
|---|---|---|
| `auto-approve` | Runs immediately | Read-only: list emails, fetch calendar, read Canvas grades |
| `user-confirm` | Halts and asks user via UI | Send email, post to Slack, modify calendar event |
| `admin-only` | Requires admin role | Delete connector, modify user settings |
| `hard-blocked` | Refused regardless of config | Place a trade, transfer funds, execute arbitrary shell |

**Financial transactions are hard-blocked irrespective of user or admin configuration.** Robinhood and similar connectors are read-only by design. This is a code-level invariant, not a setting.

### Audit Logging

Every privileged action writes an entry to `audit_logs`:

- `user_id`, `action`, `resource`, `metadata`, `timestamp`, `ip`, `user_agent`
- `previous_hash`: SHA-256 of the prior entry's serialized fields
- `entry_hash`: SHA-256 of this entry's fields including `previous_hash`

Modifying or deleting any entry breaks the chain — every subsequent hash becomes invalid and verification fails. Entries are append-only at the application layer; DB-level revoke of UPDATE/DELETE on `audit_logs` is recommended in production.

### SSRF Protection

When the agent or a connector fetches a URL:

1. **DNS resolution** happens once, up front. The resolved IP is then used directly for the connection — defeats DNS-rebinding.
2. **IP allowlist:** the resolved IP must be public. Denied ranges:
   - RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Loopback (`127.0.0.0/8`, `::1`)
   - Link-local (`169.254.0.0/16`, `fe80::/10`) — including AWS/GCP/Azure metadata at `169.254.169.254`
   - IPv6 ULA (`fc00::/7`)
   - `0.0.0.0/8`, multicast, reserved
3. **Scheme allowlist:** `http`, `https` only.

### Rate Limiting

- **Per-IP** rate limit (default 60 req/min) via `RateLimitMiddleware`, backed by Redis sliding window.
- **Per-user** rate limit on LLM-invoking routes — prevents one user from exhausting upstream quota for everyone.
- Authentication endpoints (`/login`, `/register`, `/password-reset`) have a stricter per-IP limit to slow credential stuffing.

### Container Hardening

The production Dockerfiles:

- Run as a **non-root user** (`appuser`, UID 1001).
- Use a **read-only root filesystem** with explicit `tmpfs` mounts for writable paths.
- Drop **all Linux capabilities** (`cap_drop: [ALL]`) and add back only what's needed.
- Pin the **base image by digest**, not just tag.
- Run **multi-stage builds** so the runtime image contains only the final artifact, no build tooling.

## Disclosure Policy

Found a vulnerability? Please report it responsibly:

- **Email:** security@sentientai.example (replace with your domain)
- **PGP key:** available on request
- **Scope:** the latest `main` branch and the most recent tagged release.
- **Out of scope:** denial of service, social engineering, physical attacks, issues in third-party dependencies (please report those upstream).

We aim to acknowledge reports within **72 hours** and ship a fix or mitigation within **30 days** for critical issues. We will credit reporters in the release notes unless anonymity is requested.

## Compliance Notes

- **GDPR data export endpoint** is on the roadmap. Today, raw export is possible via direct DB query; a self-service "Download my data" endpoint is tracked on [ROADMAP.md](ROADMAP.md).
- **Audit log retention** is configurable; default is "retain forever." For GDPR-compliant deployments, set a retention window (e.g. 365 days) and run a scheduled redaction job.
- **CCPA / SOC 2 / HIPAA**: SentientAI is not certified against any of these. The architectural primitives (encryption, audit, RBAC) make a future certification effort feasible but are not in scope for the senior project release.
- **Subprocessor disclosure:** if you deploy SentientAI publicly, your terms of service must list the LLM providers (Anthropic, OpenAI, etc.) as data subprocessors — every user message is sent to the provider for inference.
