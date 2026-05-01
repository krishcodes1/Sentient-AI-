# Contributing

Thanks for your interest in contributing to SentientAI. This is a CSCI-456 Senior Project at NYIT and external contributions are welcome.

## Table of Contents

- [Local Development Setup](#local-development-setup)
- [Project Structure](#project-structure)
- [Git Workflow](#git-workflow)
- [Commit Conventions](#commit-conventions)
- [Pull Request Checklist](#pull-request-checklist)
- [Code Style](#code-style)
- [Testing](#testing)
- [Adding a New LLM Provider](#adding-a-new-llm-provider)
- [Adding a New Channel](#adding-a-new-channel)
- [Adding a New Connector](#adding-a-new-connector)

## Local Development Setup

See the [README quick start](../README.md#quick-start--docker-recommended). For non-Docker local dev, the [Manual Setup](../README.md#manual-setup-without-docker) section covers Mac/Windows/Linux.

## Project Structure

```
Sentient-AI-/
├── backend/                       Python · FastAPI
│   ├── core/                      config, database, security primitives
│   ├── models/                    SQLAlchemy ORM models
│   ├── services/
│   │   ├── agent/                 LLM runtime + providers
│   │   ├── connectors/            Canvas, Google, Robinhood
│   │   └── openclaw/              writes openclaw.json
│   ├── api/routes/                FastAPI routers
│   ├── alembic/                   migrations
│   └── tests/                     pytest suite
├── frontend/                      React · TypeScript · Vite · Tailwind
│   └── src/
│       ├── pages/                 route components
│       ├── components/            reusable UI
│       └── services/              API client (axios), MSW handlers
├── docker/                        Compose + Dockerfiles
└── docs/                          this directory
```

## Git Workflow

- **Branch from `main`** for every change: `git checkout -b feat/short-description`.
- **Open a PR back to `main`** when ready. CI runs lint, typecheck, tests, build, and security scans.
- **Squash-merge** is the default — keeps `main` history clean. Your branch can be as messy as you like.
- **Don't push to `main` directly.** Branch protection enforces this on the GitHub side.

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<optional body>
```

| Type | Use when |
|---|---|
| `feat` | New user-visible feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change with no behavior change |
| `test` | Adding or updating tests |
| `chore` | Tooling, deps, CI, build |
| `perf` | Performance improvement |
| `style` | Formatting, no code change |

Examples:

```
feat(auth): add password reset endpoint
fix(connectors): correct Robinhood request signing for path params
refactor(agent): extract provider factory into its own module
docs(deployment): add Caddy reverse proxy snippet
```

## Pull Request Checklist

Before requesting review:

- [ ] `ruff check backend/` is clean
- [ ] `mypy backend/` (or the equivalent `pyright`) passes
- [ ] `pytest backend/tests` passes
- [ ] `npm run lint` and `npm run typecheck` pass in `frontend/`
- [ ] `npm run test` passes in `frontend/`
- [ ] Docs in `docs/` updated if behavior or interfaces changed
- [ ] [CHANGELOG.md](CHANGELOG.md) `[Unreleased]` section updated
- [ ] No secrets, API keys, or `.env` content in the diff

## Code Style

- **Python:** [`ruff`](https://docs.astral.sh/ruff/) for lint + format. Line length **100**. Type hints on all public functions.
- **TypeScript:** [`prettier`](https://prettier.io/) + [`eslint`](https://eslint.org/). Line length **100**. Strict mode in `tsconfig.json`.
- **Imports:** stdlib → third-party → local, with blank lines between groups (handled by ruff/eslint auto-fixes).
- **No emoji in source code, log lines, or commit messages** unless the user-facing string genuinely requires one.

## Testing

- **Backend:** [`pytest`](https://docs.pytest.org/) with `pytest-asyncio`. Live in `backend/tests/`. Run: `pytest backend/`.
- **Frontend:** [`vitest`](https://vitest.dev/) for unit tests, [`@testing-library/react`](https://testing-library.com/docs/react-testing-library/intro/) for component tests. Run: `npm run test` inside `frontend/`.
- **LLM mocking:** **don't mock LLM clients in your tests.** Use [MSW](https://mswjs.io/) handlers under `frontend/src/mocks/` (and equivalent `respx`/`httpx_mock` setups for the backend). Mocking at the HTTP layer keeps tests realistic.
- **Integration tests** spin up Postgres + Redis via testcontainers. They're slower; mark them `@pytest.mark.integration` and run separately in CI.

## Adding a New LLM Provider

1. **Subclass `LLMProvider`** in `backend/services/agent/providers.py`. Implement `invoke()`, `stream()`, and `list_models()`.
2. **Register in the factory** at the bottom of that file (the `PROVIDER_REGISTRY` dict).
3. **Add the API key env var** to `backend/.env.example` with a comment pointing at the provider's key page.
4. **Add the provider name** to `VALID_PROVIDERS` in `backend/api/routes/auth.py`.
5. **Update the README provider table** and the onboarding wizard in `frontend/src/pages/Onboarding.tsx`.
6. **Tests:** add a `tests/services/agent/test_<provider>_provider.py` with happy-path, retry, and 401 cases (use `respx` to intercept HTTP).

## Adding a New Channel

1. **Extend the schema** in `backend/services/openclaw/config_manager.py` with the new channel's config shape.
2. **Add a UI template** in `frontend/src/pages/Channels.tsx` — fields, validation, instructions for the user (where to get the token, how to invite the bot, etc.).
3. **Update the README channel table.**
4. **Document any quirks** in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

OpenClaw itself handles the wire protocol — we configure it.

## Adding a New Connector

1. **Subclass `BaseConnector`** in `backend/services/connectors/`.
2. **Register** in `backend/services/connectors/__init__.py`.
3. **Define the permission tier** for each tool the connector exposes (auto-approve / user-confirm / admin-only / hard-blocked). Read-only by default.
4. **Add OAuth or credential entry UI** in `frontend/src/pages/Connectors.tsx`.
5. **Tests:** mock the connector's API at the HTTP layer; cover auth refresh, rate-limit handling, and permission-tier enforcement.
