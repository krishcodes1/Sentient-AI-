"""Structured logging configuration for SentientAI.

Configures :mod:`structlog` with JSON output in production and a
human-friendly console renderer in development. Routes the root
:mod:`logging` logger through the same pipeline so third-party libraries
(uvicorn, sqlalchemy, anthropic SDK, etc.) emit structured records too.
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(env: str, level: str = "INFO") -> None:
    """Configure structlog and the stdlib logging root logger.

    Args:
        env: The environment name (``"development"``, ``"production"``,
            ``"test"``, ...). ``"development"`` uses a colourised console
            renderer; everything else emits JSON.
        level: The minimum log level (e.g. ``"INFO"``, ``"DEBUG"``).
            Falls back to ``INFO`` if the string is not a valid level.
    """
    timestamper = structlog.processors.TimeStamper(fmt="iso")
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if env == "development":
        renderer: object = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()
    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Quiet noisy libraries in prod
    if env != "development":
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
