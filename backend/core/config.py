from __future__ import annotations

import base64
import os
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigurationError(Exception):
    """Raised when application configuration fails validation for the
    target environment (e.g. production safety checks)."""


# Sentinel placeholder values that must NEVER appear in a production secret.
_PLACEHOLDER_SECRETS = frozenset(
    {
        "replace-me",
        "change-me",
        "REPLACE_ME",
        "CHANGE_ME",
        "default-secret-key",
    }
)


class Settings(BaseSettings):
    """Application configuration loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://sentientai:sentientai@localhost:5432/sentientai"
    )

    # ── Redis / Celery ────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Security — required, no defaults ──────────────────────────────────
    SECRET_KEY: str = Field(..., description="JWT signing key")
    ENCRYPTION_KEY: str = Field(
        ...,
        description="Base64-encoded 32-byte key for AES-256-GCM credential encryption",
    )

    # ── CORS ──────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:5173"]

    # ── LLM provider ─────────────────────────────────────────────────────
    LLM_PROVIDER: str = Field(
        default="anthropic",
        pattern="^(anthropic|openai|gemini|grok|deepseek|groq|mistral|ollama)$",
        description="LLM backend: anthropic, openai, gemini, grok, deepseek, groq, mistral, or ollama",
    )
    LLM_MODEL: str = "claude-sonnet-4-20250514"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    ANTHROPIC_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    GROK_API_KEY: Optional[str] = None
    DEEPSEEK_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    MISTRAL_API_KEY: Optional[str] = None

    # ── OpenClaw Gateway ──────────────────────────────────────────────────
    # URL the backend uses (Docker: http://openclaw:18789)
    OPENCLAW_GATEWAY_URL: str = "http://localhost:18789"
    # URL the user's browser should load for Control UI / iframe (host-published port)
    OPENCLAW_GATEWAY_BROWSER_URL: str = "http://127.0.0.1:18789"
    OPENCLAW_CONFIG_DIR: str = "/openclaw-config"

    # ── Rate limiting ─────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60

    # ── Auth ──────────────────────────────────────────────────────────────
    TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    LOCKOUT_THRESHOLD: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    PASSWORD_MIN_LENGTH: int = 12

    # ── Environment ───────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"

    # ── Observability / hardening ─────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    # WARNING: production MUST narrow this to known hostnames.
    # Leaving "*" lets any Host header through and is unsafe in production.
    ALLOWED_HOSTS: list[str] = ["*"]
    # WARNING: only populate when running behind a known reverse proxy whose
    # IPs (or CIDRs) are listed here. Otherwise X-Forwarded-For is ignored.
    TRUSTED_PROXIES: list[str] = []

    # --- field validators (Pydantic v2): parse comma-separated env vars ---

    @field_validator("CORS_ORIGINS", "ALLOWED_HOSTS", "TRUSTED_PROXIES", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        """Allow ``CORS_ORIGINS=a,b,c`` style env vars to populate list fields.

        Accepts:
        - a list (already parsed) — passes through
        - a string — split on commas, trim whitespace, drop empties
        - anything else — leaves to Pydantic to coerce/error
        """
        if isinstance(v, str):
            # Reject the JSON-ish form rather than half-parsing it.
            stripped = v.strip()
            if not stripped:
                return []
            if stripped.startswith("[") and stripped.endswith("]"):
                # Let pydantic-settings handle JSON list parsing.
                return v
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return v

    # --- production safety check ----------------------------------------

    def validate_for_environment(self) -> None:
        """Enforce production-only safety invariants.

        Raises:
            ConfigurationError: if any production check fails. The message
                names the failing check so misconfiguration is obvious in
                the startup log.
        """
        if self.ENVIRONMENT != "production":
            return

        # SECRET_KEY must be strong and not a known placeholder.
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            raise ConfigurationError(
                "SECRET_KEY must be at least 32 characters in production "
                f"(got {len(self.SECRET_KEY) if self.SECRET_KEY else 0})."
            )
        if self.SECRET_KEY in _PLACEHOLDER_SECRETS:
            raise ConfigurationError(
                "SECRET_KEY is set to a known placeholder value; "
                "generate a real secret before running in production."
            )

        # ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).
        try:
            decoded = base64.urlsafe_b64decode(self.ENCRYPTION_KEY)
        except Exception as exc:  # pragma: no cover - exotic decode errors
            raise ConfigurationError(
                f"ENCRYPTION_KEY is not valid urlsafe base64: {exc}"
            ) from exc
        if len(decoded) != 32:
            raise ConfigurationError(
                "ENCRYPTION_KEY must decode to exactly 32 bytes "
                f"(decoded length: {len(decoded)})."
            )

        # DATABASE_URL must not point at localhost / dev defaults.
        db_url_lower = self.DATABASE_URL.lower()
        for forbidden in ("localhost", "127.0.0.1", "sentientai:sentientai"):
            if forbidden in db_url_lower:
                raise ConfigurationError(
                    f"DATABASE_URL must not contain '{forbidden}' in production."
                )

        # LLM provider must have its API key set (except ollama, which is local).
        provider_to_env = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY",
            "grok": "GROK_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
            "groq": "GROQ_API_KEY",
            "mistral": "MISTRAL_API_KEY",
        }
        if self.LLM_PROVIDER in provider_to_env:
            attr = provider_to_env[self.LLM_PROVIDER]
            value = getattr(self, attr, None)
            if not value:
                raise ConfigurationError(
                    f"LLM_PROVIDER={self.LLM_PROVIDER} requires {attr} to be set."
                )

        # CORS must be explicit, not wildcarded, and non-empty.
        if not self.CORS_ORIGINS:
            raise ConfigurationError(
                "CORS_ORIGINS must contain at least one allowed origin in production."
            )
        if "*" in self.CORS_ORIGINS:
            raise ConfigurationError(
                "CORS_ORIGINS must not contain '*' in production "
                "(incompatible with allow_credentials=True)."
            )


settings = Settings()  # type: ignore[call-arg]
