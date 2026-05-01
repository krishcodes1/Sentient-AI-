"""SentientAI — Secure-by-Design Agentic AI Platform."""

from __future__ import annotations

import os
import subprocess
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from pathlib import Path

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from core.config import settings
from core.database import async_session
from core.logging import configure_logging
from api.middleware.request_id import RequestIDMiddleware
from api.middleware.security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from api.middleware.trust_proxy import TrustProxyMiddleware
from api.routes import agent, audit, auth, channels, connectors, openclaw_embed

# ── Versioning / uptime ───────────────────────────────────────────────────────
__VERSION__ = "0.2.0"
START_TIME = time.time()


# ── Logging + config validation must run before app creation ─────────────────
configure_logging(settings.ENVIRONMENT, settings.LOG_LEVEL)
settings.validate_for_environment()

logger = structlog.get_logger(__name__)


def _auto_migrate_enabled() -> bool:
    """Auto-migrate only in development AND when explicitly opted in."""
    if settings.ENVIRONMENT != "development":
        return False
    return os.environ.get("AUTO_MIGRATE", "").lower() == "true"


def _run_alembic_upgrade() -> None:
    """Invoke ``alembic upgrade head`` from the backend directory."""
    backend_dir = Path(__file__).resolve().parent
    subprocess.run(
        ["alembic", "upgrade", "head"],
        cwd=str(backend_dir),
        check=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(
        "starting_sentientai",
        environment=settings.ENVIRONMENT,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.LLM_MODEL,
        version=__VERSION__,
    )
    if _auto_migrate_enabled():
        try:
            _run_alembic_upgrade()
            logger.info("database_migrated", method="alembic_upgrade_head")
        except Exception as exc:
            logger.error("database_migration_failed", error=str(exc))
            logger.warning("app_starting_without_migration")
    else:
        logger.info(
            "skipping_auto_migration",
            message=(
                "Skipping auto-migration in production; "
                "run 'alembic upgrade head' manually."
            ),
        )
    yield
    logger.info("shutting_down_sentientai")


app = FastAPI(
    title="SentientAI",
    description="Secure-by-Design Agentic AI Platform",
    version=__VERSION__,
    lifespan=lifespan,
)

# ── Middleware (applied bottom-to-top) ────────────────────────────────────────
# Order matters: middlewares execute in REVERSE order of registration on the
# inbound path. We want:
#   1. RequestIDMiddleware first (binds the request id to the log context for
#      every other middleware to use).
#   2. TrustProxyMiddleware next (rewrites client IP before rate limiting).
#   3. TrustedHostMiddleware (drop unknown Host headers ASAP).
#   4. SecurityHeaders / RateLimit / CORS sit closest to the app.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.add_middleware(RateLimitMiddleware, max_requests=settings.RATE_LIMIT_PER_MINUTE)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)
app.add_middleware(
    TrustProxyMiddleware,
    trusted_networks=settings.TRUSTED_PROXIES,
)
app.add_middleware(RequestIDMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api")
app.include_router(agent.router, prefix="/api")
app.include_router(channels.router, prefix="/api")
app.include_router(connectors.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(openclaw_embed.router, prefix="/api")


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": "SentientAI",
        "version": __VERSION__,
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
async def health_check() -> JSONResponse:
    """Liveness + dependency check.

    - Pings the database with ``SELECT 1``.
    - If a Redis client lives in ``app.state.redis``, pings it.
    - Returns ``healthy`` when all probes succeed (HTTP 200), otherwise
      ``degraded`` with HTTP 503.
    """
    db_status = "err"
    redis_status: str = "skipped"
    overall_ok = True

    # Database probe
    try:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        overall_ok = False
        logger.warning("health_db_probe_failed", error=str(exc))

    # Redis probe (only if a client was attached during startup)
    redis_client = getattr(app.state, "redis", None)
    if redis_client is not None:
        try:
            ping = redis_client.ping()
            # redis-py async returns a coroutine; sync returns bool
            if hasattr(ping, "__await__"):
                await ping
            redis_status = "ok"
        except Exception as exc:
            redis_status = "err"
            overall_ok = False
            logger.warning("health_redis_probe_failed", error=str(exc))

    body = {
        "status": "healthy" if overall_ok else "degraded",
        "db": db_status,
        "redis": redis_status,
        "version": __VERSION__,
        "uptime_seconds": int(time.time() - START_TIME),
    }
    return JSONResponse(status_code=200 if overall_ok else 503, content=body)


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
