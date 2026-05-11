"""Test setup. Sets dummy env vars before any project modules import,
because core.config.Settings is instantiated at import time and requires
SECRET_KEY and ENCRYPTION_KEY.
"""

from __future__ import annotations

import base64
import os
import secrets

os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault(
    "ENCRYPTION_KEY",
    base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8"),
)
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("LLM_PROVIDER", "anthropic")
os.environ.setdefault("LLM_MODEL", "claude-sonnet-4-6")
