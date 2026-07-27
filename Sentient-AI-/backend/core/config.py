from __future__ import annotations

from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # ── Redis (shared rate limiting) ──────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Security — required, no defaults ──────────────────────────────────
    SECRET_KEY: str = Field(..., description="JWT signing key")
    ENCRYPTION_KEY: str = Field(
        ...,
        description="Base64-encoded 32-byte key for AES-256-GCM credential encryption",
    )
    # Key for the audit-log integrity HMAC (HMAC-SHA256). Optional: when
    # unset, a key is derived deterministically from ENCRYPTION_KEY so keyed
    # hashing works with zero extra configuration. A dedicated key is better:
    # the audit chain's guarantee is exactly "an attacker with database write
    # access but WITHOUT this key cannot forge history", so storing it
    # separately from the DB-encryption key (and DB backups) is the whole
    # point. An attacker holding the app's ENCRYPTION_KEY can recompute the
    # derived fallback key and still forge.
    AUDIT_HMAC_KEY: Optional[str] = Field(
        default=None,
        description="Dedicated key for the HMAC-SHA256 audit-log integrity hash",
    )

    @field_validator("AUDIT_HMAC_KEY")
    @classmethod
    def _audit_hmac_key_is_strong(cls, v: Optional[str]) -> Optional[str]:
        """Reject a weak dedicated audit key at startup.

        The whole guarantee is "a database-write adversary without this key
        cannot forge history"; a short/guessable key makes that guarantee
        vacuous, and a silently-accepted one is worse than no key at all
        because the derived ENCRYPTION_KEY fallback it replaces is strong.
        The generator in .env.example emits 64 characters.
        """
        if v is None:
            return v
        v = v.strip()
        if not v:
            # Treat an empty/whitespace value as "unset" so a commented-out
            # style `AUDIT_HMAC_KEY=` in .env falls back to the derived key
            # rather than keying the HMAC on the empty string.
            return None
        if len(v) < 32:
            raise ValueError(
                "AUDIT_HMAC_KEY must be at least 32 characters; generate one with "
                "python3 -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        return v

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

    # ── Rate limiting ─────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60
    # Stricter bucket for credential endpoints (login/register) to slow
    # brute-force attempts. Counted separately from the general limit.
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    # Proxy IP ranges (CIDR) whose X-Forwarded-For header is trusted for
    # client-IP attribution. Only when the DIRECT peer is in one of these
    # ranges is XFF honored; otherwise the peer address is used. This stops
    # a directly-reachable client from spoofing XFF to mint a fresh
    # rate-limit bucket per request and bypass the login brute-force
    # throttle. Defaults cover loopback + RFC1918/ULA private ranges, which
    # is where a reverse proxy (nginx in the compose network) sits. Set to
    # an empty list to never trust XFF.
    TRUSTED_PROXIES: list[str] = [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]

    # ── Auth ──────────────────────────────────────────────────────────────
    TOKEN_EXPIRE_MINUTES: int = 60

    # ── Approvals ─────────────────────────────────────────────────────────
    # How long a pending tool-approval stays actionable before it expires.
    APPROVAL_TTL_MINUTES: int = 15

    # ── Environment ───────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"


settings = Settings()  # type: ignore[call-arg]
