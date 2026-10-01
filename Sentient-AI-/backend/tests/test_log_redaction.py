"""Tests for secret masking in logs (services/security/redact.py, wired by
core/logging_config.py): the structlog processor masks nested values, the
values of secret key names and exception text while keeping input_tokens; the
stdlib filter masks a Telegram bot-token URL in an httpx record and keeps
uvicorn's access-log arguments in the shape its formatter unpacks; and
configure_logging puts both in place.

Why it exists: a log file is copied, shipped and pasted into bug reports, so a
key that reaches one line is as good as published. No real handler writes
anywhere: records are built and filtered in memory.
"""

from __future__ import annotations

import logging

import structlog

from core import logging_config
from services.security.redact import SecretLogFilter, redact_log_event
from services.security.secrets import find

TOKEN = "ghp_" + "FAKE" * 9
BOT_URL = "https://api.telegram.org/bot123456789:" + "AAFAKE_fake-" * 2 + "FAKEfake000/getUpdates"
REDACTED = "***REDACTED***"


def test_the_processor_masks_nested_values_and_secret_key_names():
    event = redact_log_event(
        None,
        "info",
        {
            "event": "connector_call",
            "input_tokens": 1200,
            "token": "short-but-secret",
            "details": {"headers": [f"Bearer {TOKEN}"], "note": f"used {TOKEN}"},
        },
    )
    assert event["input_tokens"] == 1200
    assert event["token"] == REDACTED
    assert event["details"]["note"] == f"used {REDACTED}"
    assert TOKEN not in str(event)


def test_the_processor_masks_exception_text():
    try:
        raise ValueError(f"upstream said {TOKEN}")
    except ValueError:
        formatted = structlog.processors.format_exc_info(None, "error", {"event": "boom", "exc_info": True})
    assert TOKEN in formatted["exception"]
    event = redact_log_event(None, "error", formatted)
    assert TOKEN not in event["exception"] and REDACTED in event["exception"]
    # An exception object passed as a value is logged as its masked text.
    event = redact_log_event(None, "error", {"event": "x", "error": RuntimeError(TOKEN)})
    assert event["error"] == REDACTED


def _record(name: str, msg: str, args: tuple = ()) -> logging.LogRecord:
    return logging.LogRecord(name, logging.WARNING, __file__, 1, msg, args, None)


def test_the_filter_masks_a_bot_token_url():
    record = _record("httpx", 'HTTP Request: POST %s "HTTP/1.1 409 Conflict"', (BOT_URL,))
    assert SecretLogFilter().filter(record) is True
    message = record.getMessage()
    assert "AAFAKE" not in message and REDACTED in message
    assert find(message) == []


def test_the_filter_keeps_uvicorn_access_arguments_in_shape():
    record = _record(
        "uvicorn.access",
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "GET", f"/api/x?key={TOKEN}", "1.1", 200),
    )
    SecretLogFilter().filter(record)
    assert isinstance(record.args, tuple) and len(record.args) == 5
    assert record.args[4] == 200
    assert TOKEN not in record.getMessage()


def test_the_filter_masks_exception_text_and_never_drops_a_record():
    try:
        raise RuntimeError(f"failed with {TOKEN}")
    except RuntimeError:
        import sys

        record = logging.LogRecord("uvicorn.error", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
    assert SecretLogFilter().filter(record) is True
    assert TOKEN not in (record.exc_text or "") and "RuntimeError" in (record.exc_text or "")

    broken = _record("x", "%s %s", ("only one",))
    assert SecretLogFilter().filter(broken) is True


def test_configure_logging_installs_the_processor_and_filters():
    root_handler = logging.StreamHandler()
    root = logging.getLogger()
    root.addHandler(root_handler)
    try:
        logging_config.configure_logging()
        processors = structlog.get_config()["processors"]
        exc_index = processors.index(structlog.processors.format_exc_info)
        assert processors[exc_index + 1] is redact_log_event
        for name in ("uvicorn.access", "uvicorn.error", "httpx"):
            assert any(isinstance(f, SecretLogFilter) for f in logging.getLogger(name).filters)
        assert any(isinstance(f, SecretLogFilter) for f in root_handler.filters)
    finally:
        root.removeHandler(root_handler)
        # Leave pytest's own capture handlers as they were.
        for handler in root.handlers:
            for f in [f for f in handler.filters if isinstance(f, SecretLogFilter)]:
                handler.removeFilter(f)
