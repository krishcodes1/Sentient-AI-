from __future__ import annotations

from typing import Optional

from pydantic import Field
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
