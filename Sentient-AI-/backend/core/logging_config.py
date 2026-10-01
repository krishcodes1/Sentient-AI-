"""Configures structlog once for the whole process: JSON lines in production,
console rendering in development, level from LOG_LEVEL.

Why it exists: main.py calls ``configure_logging()`` before importing the
routers so every module's logger shares one renderer and the request_id the
middleware binds; it also silences httpx's per-request INFO lines, which would
print the Telegram bot token inside Bot API URLs, and strips the query string
(an OAuth code and state) from uvicorn's access-log lines for the OAuth
callback. Every structlog event and every uvicorn and httpx record also passes
the shared secret detector (services/security, policy LOGS), so a key, token,
card or ID number that reaches a log line is masked.

Process-wide structlog configuration.

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
from services.security.redact import SecretLogFilter, redact_log_event

# The OAuth broker's callback (api/routes/oauth.py) arrives as
# /api/oauth/callback/<provider>?code=...&state=..., and both values are
# secrets until the flow completes.
_OAUTH_CALLBACK_PATH = "/api/oauth/callback/"
# A flashcard deck's one-time download link, /api/study/export?t=cse_...
# (api/routes/study.py): the token is a secret until it is used.
_STUDY_EXPORT_PATH = "/api/study/export"
# Paths whose query string is a secret and never reaches an access log.
_SECRET_QUERY_PATHS = (_OAUTH_CALLBACK_PATH, _STUDY_EXPORT_PATH)


def _has_secret_query_path(value: str) -> bool:
    return any(path in value for path in _SECRET_QUERY_PATHS)


class OAuthCallbackQueryFilter(logging.Filter):
    """Strips the query string from uvicorn access-log lines for the paths
    whose query is a secret (the OAuth callback's code and state, a study
    export link's one-time token), so it never reaches a log file.

    uvicorn logs ``'%s - "%s %s HTTP/%s" %d'`` with the path-and-query as one
    argument; that argument is rewritten in place and the record is kept.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and any(
            isinstance(arg, str) and _has_secret_query_path(arg) for arg in args
        ):
            record.args = tuple(_strip_query(arg) for arg in args)
        elif isinstance(record.msg, str) and _has_secret_query_path(record.msg):
            record.msg = _strip_query(record.msg)
        return True


# The filter's general name (it is no longer the OAuth callback's alone).
SecretQueryFilter = OAuthCallbackQueryFilter


def _strip_query(value: object) -> object:
    if not isinstance(value, str) or not _has_secret_query_path(value):
        return value
    head, sep, tail = value.partition("?")
    if not sep:
        return value
    # Keep whatever follows the URL on the same line (a quoted request line).
    rest = tail.split(" ", 1)
    return head + ("?[redacted]" + (" " + rest[1] if len(rest) > 1 else ""))


_OAUTH_CALLBACK_FILTER = OAuthCallbackQueryFilter()

# Masks keys, tokens, card and ID numbers in stdlib log records (a Telegram
# bot-token URL in an httpx warning, a token echoed in an uvicorn error):
# services.security.redact, policy LOGS.
_SECRET_LOG_FILTER = SecretLogFilter()
_SECRET_FILTERED_LOGGERS = ("uvicorn.access", "uvicorn.error", "httpx", "httpcore", "")


def _install_secret_filter() -> None:
    """Put the secret filter on each logger in ``_SECRET_FILTERED_LOGGERS``
    (the root included) and on every handler they have now. A logger's
    filter survives uvicorn's dictConfig; a handler's sees records that
    propagate to it from any child logger."""
    for name in _SECRET_FILTERED_LOGGERS:
        target = logging.getLogger(name)
        if _SECRET_LOG_FILTER not in target.filters:
            target.addFilter(_SECRET_LOG_FILTER)
        for handler in target.handlers:
            if _SECRET_LOG_FILTER not in handler.filters:
                handler.addFilter(_SECRET_LOG_FILTER)


def configure_logging() -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    # httpx logs every request line at INFO, URL included, and a Telegram
    # Bot API URL carries the bot token in its path. Only their warnings
    # and errors are worth keeping.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Idempotent: configure_logging may run more than once per process.
    # uvicorn's own dictConfig replaces handlers but keeps logger filters.
    access_logger = logging.getLogger("uvicorn.access")
    if _OAUTH_CALLBACK_FILTER not in access_logger.filters:
        access_logger.addFilter(_OAUTH_CALLBACK_FILTER)
    _install_secret_filter()

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
            # After the traceback is text, before anything is rendered: keys,
            # tokens, card and ID numbers in any value (and the values of
            # secret key names) become ***REDACTED***.
            redact_log_event,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )
