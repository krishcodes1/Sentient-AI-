"""Crawler AI — Secure-by-Design Agentic AI Platform."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from typing import Any, Callable

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.trustedhost import TrustedHostMiddleware

from core.config import settings
from core.database import async_session, engine, get_db, init_db
from core.logging_config import configure_logging

configure_logging()
from api.middleware.security import (
    RateLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from api.routes import (
    agent,
    audit,
    auth,
    capabilities,
    connectors,
    memory,
    reminders,
    setup,
    telegram,
    usage,
)
from services.agent.approvals import DbApprovalStore
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
)
from services.audit import RuntimeAuditLogger
from services.installation import InstallationService
from services.mcp.integration import MCPConnectorLoader, MCPToolCatalog
from services.notifications.reminders import ReminderService
from services.notifications.telegram import NotifyingApprovalStore, TelegramService
from services.notifications.telegram_manager import TelegramManager
from services.tools.system import SystemToolkit

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(
        "starting_crawler_ai",
        environment=settings.ENVIRONMENT,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.LLM_MODEL,
    )
    for warning in settings.production_warnings():
        logger.warning("production_config_warning", detail=warning)
    try:
        await init_db()
        logger.info("database_initialized")
    except Exception as exc:
        logger.error("database_init_failed", error=str(exc))
        if settings.ENVIRONMENT == "production":
            # Fail fast: a DB-less API 500s on every real request while
            # passing a naive healthcheck. Exiting lets the container
            # restart-loop until the database is reachable.
            raise
        logger.warning("app_starting_without_database")

    await wire_services(app)
    reminder_service: ReminderService = app.state.reminders
    await reminder_service.start()

    yield
    logger.info("shutting_down_crawler_ai")
    await reminder_service.stop()
    await app.state.telegram_manager.stop()
    await engine.dispose()


def _wire_telegram(app: FastAPI, service: TelegramService) -> None:
    """Point a poller at the agent pipelines. The manager calls this on
    every (re)start, so a bot token saved while the server runs gets the
    same approval and chat wiring as one present at boot."""
    service.decide = agent.build_decision_applier(app)
    service.chat = agent.build_chat_applier(app)


async def wire_services(
    app: FastAPI,
    session_factory: Callable[[], Any] = async_session,
    *,
    telegram_service_factory: Callable[..., TelegramService] = TelegramService,
) -> None:
    """Build the owner-configurable services and hang them on app.state.

    Everything the owner can change at runtime (capability switches, AI
    provider and key, Telegram token) lives in the InstallationService,
    and every consumer reads it through a seam that picks changes up
    without a restart: the tool gates and the <permissions> block ask it
    per turn, the runtime resolves its provider from it per turn (and
    drops cached providers on an "llm" change), and the TelegramManager is
    re-applied on a "telegram" or "capabilities" change. The approval
    store and the reminder sweeper are wired to the manager once; its
    proxies are no-ops while no poller runs.

    Split out of the lifespan so tests can wire an app against their own
    database and a fake Telegram service. Does not start the reminder
    sweeper (the lifespan does).
    """
    installation = InstallationService(session_factory)
    app.state.installation = installation
    try:
        # An install that predates the setup wizard must not be pushed
        # through it after an upgrade.
        await installation.stamp_setup_if_legacy()
    except Exception as exc:
        # Only reachable in development without a database (production
        # already failed fast above); every request would fail anyway.
        logger.warning("installation_stamp_failed", error_type=type(exc).__name__)

    telegram_manager = TelegramManager(
        session_factory,
        on_start=lambda service: _wire_telegram(app, service),
        service_factory=telegram_service_factory,
    )
    app.state.telegram_manager = telegram_manager
    # Compatibility alias for code that still reads app.state.telegram; it
    # is the manager now, never a bare service.
    app.state.telegram = telegram_manager

    # Pending actions are pushed to each user's linked Telegram chat while
    # a poller runs, and the Approve/Deny press flows through the same
    # decision pipeline as the web UI.
    approval_store = NotifyingApprovalStore(
        DbApprovalStore(session_factory=session_factory),
        notify=telegram_manager.notify_pending,
    )

    # One installer for the whole process: the agent's approved
    # system.install_capability and the owner's Install button on the
    # Permissions page share this instance, and with it the lock that keeps
    # two installs of the same component from racing two pip processes.
    system_toolkit = SystemToolkit(report_source=installation.report)
    app.state.system_toolkit = system_toolkit

    try:
        # All security-relevant services own short-lived sessions via the
        # application session factory: the executor decrypts credentials and
        # dispatches real connectors, the audit logger writes hash-chained
        # rows, and the approval store persists pending actions across
        # restarts and workers. The capability gate is enforced at both
        # the permission seam (blocked before anything runs, audited as
        # capability_off) and the executor (the backstop).
        app.state.agent_runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(
                capability_gate=installation.enabled_keys
            ),
            tool_executor=ConnectorToolExecutor(
                session_factory=session_factory,
                capability_gate=installation.enabled_keys,
                system_toolkit=system_toolkit,
            ),
            audit_service=RuntimeAuditLogger(session_factory=session_factory),
            approval_store=approval_store,
            settings_source=installation,
        )
        logger.info("agent_runtime_initialized")
    except Exception as exc:
        # The runtime needs no provider key at boot any more (a turn
        # without one answers "not configured"), so this only catches a
        # genuine construction bug. Keep serving health and setup; agent
        # routes answer 503 until it is fixed.
        logger.error("agent_runtime_init_failed", error=str(exc))
        app.state.agent_runtime = None

    # Tool discovery for user-registered MCP servers (short-TTL cache).
    app.state.mcp_catalog = MCPToolCatalog(MCPConnectorLoader(session_factory))

    async def _apply_telegram() -> None:
        switches = await installation.capabilities()
        await telegram_manager.apply(
            await installation.telegram_token(), switches.get("telegram", False)
        )

    async def _on_change(topic: str) -> None:
        if topic == "llm":
            runtime = getattr(app.state, "agent_runtime", None)
            if runtime is not None:
                runtime.invalidate_providers()
        if topic in ("telegram", "capabilities"):
            await _apply_telegram()

    installation.on_change(_on_change)

    try:
        await _apply_telegram()
    except Exception as exc:
        # A bad token or an unreachable Telegram must not keep the API
        # down; the owner can fix the token in Settings. Type only: the
        # message can quote a bot-token URL.
        logger.warning("telegram_start_failed", error_type=type(exc).__name__)

    # Reminders sweep regardless of whether a delivery channel runs — the
    # rows are still user-visible in the API; only the out-of-band push
    # needs Telegram, and the manager's send_text reports False while none
    # is running.
    app.state.reminders = ReminderService(
        session_factory=session_factory,
        send=telegram_manager.send_text,
    )


_is_production = settings.ENVIRONMENT == "production"

app = FastAPI(
    title="Crawler AI",
    description="Secure-by-Design Agentic AI Platform",
    version="0.1.0",
    lifespan=lifespan,
    # The interactive docs and schema are developer conveniences; in
    # production they hand an attacker the full authenticated API surface.
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)

# ── Middleware (the LAST one added is the outermost) ──────────────────────────
# Rate limiting is added before the header/request-id layers so it ends up
# INSIDE them. A throttled request short-circuits with a 429 from the
# limiter itself and never reaches anything further in, so anything that
# must appear on every response — the security headers and the correlation
# id — has to wrap the limiter, not sit under it. Otherwise exactly the
# responses an attacker provokes are the ones served unhardened and
# untraceable.
if settings.ALLOWED_HOSTS and settings.ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=settings.RATE_LIMIT_PER_MINUTE,
    auth_max_requests=settings.AUTH_RATE_LIMIT_PER_MINUTE,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    # Enumerate exactly what the SPA uses; wildcards + credentials is a
    # combination browsers reject and an unnecessarily wide surface anyway.
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api")
app.include_router(agent.router, prefix="/api")
app.include_router(connectors.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(memory.router, prefix="/api")
app.include_router(reminders.router, prefix="/api")
app.include_router(telegram.router, prefix="/api")
app.include_router(usage.router, prefix="/api")
app.include_router(capabilities.router, prefix="/api")
app.include_router(setup.router, prefix="/api")


@app.get("/")
async def root() -> dict[str, str]:
    info = {
        "name": "Crawler AI",
        "version": "0.1.0",
        "health": "/api/health",
    }
    if not _is_production:
        info["docs"] = "/docs"
    return info


@app.get("/api/health")
async def health_check(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Liveness + database reachability.

    The Docker healthcheck polls this endpoint; returning 503 when the
    database is unreachable keeps the container (and everything gated on
    its health, like the frontend's depends_on) honest about whether the
    API can actually serve requests.
    """
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        logger.warning("health_check_database_unreachable")
        # Reset the session so get_db's trailing commit doesn't raise a
        # second time and turn this 503 into a 500.
        try:
            await db.rollback()
        except Exception:
            pass
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "reason": "database unreachable"},
        )
    return JSONResponse(content={"status": "healthy", "version": "0.1.0"})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """422 that says where and why, never what was sent.

    FastAPI's stock body repeats each failing field's ``input`` (for a
    missing field, the whole request body) plus the validator's ``ctx``,
    so a login or setup request missing one field would send the password
    or API key next to it straight back into the response, the browser's
    devtools and any proxy log. Only type, location and message survive.
    """
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"type": err.get("type"), "loc": list(err.get("loc", ())), "msg": err.get("msg")}
                for err in exc.errors()
            ]
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error("unhandled_exception", request_id=request_id, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
    )


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.ENVIRONMENT == "development",
    )
