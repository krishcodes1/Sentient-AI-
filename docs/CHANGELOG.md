# Changelog

All notable changes will be documented in this file. Format: [Keep a Changelog](https://keepachangelog.com/), versioning [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Production-grade Docker Compose with multi-stage Dockerfiles, non-root containers, healthchecks
- Alembic database migrations
- Pytest test suite for backend; Vitest for frontend
- GitHub Actions CI: lint, typecheck, test, build, security scans
- Authentication on previously-unauthenticated `/api/connectors` and `/api/audit` routes (CRITICAL — fixes IDOR)
- AAD on AES-256-GCM credential encryption (binds ciphertext to user+field)
- AuditLog `previous_hash` column for true SHA-256 chain integrity
- Refresh tokens, account lockout after failed logins, password reset endpoint
- Connectors page in frontend dashboard
- Mobile-responsive sidebar with hamburger; PWA manifest + service worker
- Toast notification system, error boundaries, 401 redirect interceptor

### Changed
- Replaced `python-jose` with `PyJWT` (CVE-2024-33663/33664)
- Replaced `Base.metadata.create_all` startup with Alembic upgrade flow
- Production Docker no longer uses `--reload`; uses `gunicorn`-style multi-worker uvicorn
- Frontend served via nginx in production (was Vite dev server)
- OpenClaw config volume corrected (was unreachable to gateway)

### Fixed
- IDOR vulnerabilities on `/api/connectors` and `/api/audit` (P0)
- `AuditStatus` enum casing mismatch causing AttributeError on every stats call
- Gmail send double-posting (drafts endpoint + messages/send)
- Robinhood request signing (path/params mismatch)
- Atomic write of `openclaw.json` (was tearable mid-write)

### Security
- Rotated all default credentials in `.env.example`
- Bound Postgres/Redis to internal network only
- Added `TrustedHostMiddleware` and host header validation

## [0.1.0] - 2026-04-09
- Initial public release for senior project demo
