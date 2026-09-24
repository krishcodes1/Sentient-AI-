"""SentientAI — Secure-by-Design Agentic AI Platform."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Request
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
    connectors,
    memory,
    reminders,
    telegram,
    usage,
)
from services.agent.approvals import ApprovalStore, DbApprovalStore
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
)
from services.audit import RuntimeAuditLogger
from services.mcp.integration import MCPConnectorLoader, MCPToolCatalog
from services.notifications.reminders import ReminderService
from services.notifications.telegram import NotifyingApprovalStore, TelegramService

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(
        "starting_sentientai",
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

    # Optional Telegram approval channel: when a bot token is configured,
    # pending actions are pushed to each user's linked chat and the
    # Approve/Deny press flows through the same decision pipeline as the
    # web UI. Created before the runtime so the approval store can be
    # wrapped with the notifier.
    telegram_service = None
    if settings.TELEGRAM_BOT_TOKEN:
        telegram_service = TelegramService(
            token=settings.TELEGRAM_BOT_TOKEN,
            session_factory=async_session,
        )
    app.state.telegram = telegram_service

    approval_store: ApprovalStore = DbApprovalStore(session_factory=async_session)
    if telegram_service is not None:
        approval_store = NotifyingApprovalStore(
            approval_store, notify=telegram_service.notify_pending
        )

    try:
        # All security-relevant services own short-lived sessions via the
        # application session factory: the executor decrypts credentials and
        # dispatches real connectors, the audit logger writes hash-chained
        # rows, and the approval store persists pending actions across
        # restarts and workers.
        app.state.agent_runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(),
            tool_executor=ConnectorToolExecutor(session_factory=async_session),
            audit_service=RuntimeAuditLogger(session_factory=async_session),
            approval_store=approval_store,
        )
        logger.info("agent_runtime_initialized", provider=settings.LLM_PROVIDER)
    except Exception as exc:
        logger.error("agent_runtime_init_failed", error=str(exc))
        app.state.agent_runtime = None

    # Tool discovery for user-registered MCP servers (short-TTL cache).
    app.state.mcp_catalog = MCPToolCatalog(MCPConnectorLoader(async_session))

    if telegram_service is not None:
        # The decision callback needs app.state (runtime + MCP catalog),
        # so it is wired after both exist.
        telegram_service.decide = agent.build_decision_applier(app)
        telegram_service.chat = agent.build_chat_applier(app)
        await telegram_service.start()
        logger.info("telegram_approvals_enabled")

    # Reminders sweep regardless of whether a delivery channel exists — the
    # rows are still user-visible in the API; only the out-of-band push
    # needs Telegram.
    reminder_service = ReminderService(
        session_factory=async_session,
        send=telegram_service.send_text if telegram_service is not None else None,
    )
    app.state.reminders = reminder_service
    await reminder_service.start()

    yield
    logger.info("shutting_down_sentientai")
    await reminder_service.stop()
    if telegram_service is not None:
        await telegram_service.stop()
    await engine.dispose()


_is_production = settings.ENVIRONMENT == "production"

app = FastAPI(
    title="SentientAI",
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
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
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


@app.get("/")
async def root() -> dict[str, str]:
    info = {
        "name": "SentientAI",
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
