"""Process-wide structlog configuration.

Called once from main.py before the app starts serving. Production emits
one JSON object per line (machine-parseable, safe for log shippers);
development keeps structlog's readable console rendering. The level comes
from LOG_LEVEL, and merge_contextvars lets middleware bind a request_id
that then appears on every log line emitted while handling that request.
"""

from __future__ import annotations

import logging

import structlog

from core.config import settings


def configure_logging() -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    # httpx logs every request line at INFO, URL included, and a Telegram
    # Bot API URL carries the bot token in its path. Only their warnings
    # and errors are worth keeping.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    renderer: structlog.typing.Processor
    if settings.ENVIRONMENT == "production":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )
