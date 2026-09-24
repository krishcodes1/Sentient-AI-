from __future__ import annotations

import base64
import ipaddress
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Substrings that mark a copy-pasted example key rather than a generated
# one. Checked case-insensitively against SECRET_KEY so a .env made from
# .env.example without running the generator fails at boot instead of
# signing every session token with a string committed to a public repo.
_PLACEHOLDER_MARKERS = ("replace_me", "changeme", "change-me", "your-secret")


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

    @field_validator("SECRET_KEY")
    @classmethod
    def _secret_key_is_strong(cls, v: str) -> str:
        """Reject the .env.example placeholder and short keys at startup.

        SECRET_KEY signs every session token; a placeholder key committed to
        the public repo (or a short guessable one) lets anyone mint a valid
        JWT for any user id. Unlike ENCRYPTION_KEY — whose placeholder fails
        loudly on first use because it doesn't decode to 32 bytes — a bad
        SECRET_KEY would otherwise never fail at all.
        """
        lowered = v.strip().lower()
        if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
            raise ValueError(
                "SECRET_KEY is still the .env.example placeholder; generate a real "
                "key with python3 -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        if len(v.strip()) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters; generate one with "
                "python3 -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        return v

    @field_validator("ENCRYPTION_KEY")
    @classmethod
    def _encryption_key_decodes(cls, v: str) -> str:
        """Fail at boot — not on the first connector save — when the key is
        not base64 of exactly 32 bytes (which also catches the placeholder)."""
        try:
            raw = base64.urlsafe_b64decode(v)
        except Exception:
            raise ValueError(
                "ENCRYPTION_KEY must be urlsafe-base64; generate one with python3 -c "
                "\"import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())\""
            )
        if len(raw) != 32:
            raise ValueError(
                "ENCRYPTION_KEY must decode to exactly 32 bytes; generate one with python3 -c "
                "\"import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())\""
            )
        return v
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
    # Fallback when LLM_MODEL is unset. claude-sonnet-4-20250514 was retired
    # on 2026-06-15; users.llm_model's server_default still names it (changing
    # that needs a schema migration), and core/database.py moves untouched
    # accounts off that default to this value at startup.
    LLM_MODEL: str = "claude-sonnet-5"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    ANTHROPIC_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    GROK_API_KEY: Optional[str] = None
    DEEPSEEK_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    MISTRAL_API_KEY: Optional[str] = None

    # Tool-call rounds one message may chain (search → open pages → act).
    # Each round is another provider call, so this bounds cost and loops.
    MAX_TOOL_ROUNDS: int = 8

    # ── Telegram approvals (optional) ─────────────────────────────────────
    # Bot token from @BotFather. When set, pending approvals are pushed to
    # each user's linked Telegram chat with Approve/Deny buttons and the
    # decision is taken from there. Empty = feature disabled.
    TELEGRAM_BOT_TOKEN: str = ""

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
    #
    # That default width is a real risk and worth stating plainly rather
    # than burying: ANY host that reaches the API from a private range — a
    # second container on the same bridge network, a machine on the office
    # LAN, a pod neighbour — can then set X-Forwarded-For freely and mint
    # one rate-limit bucket per spoofed address. Narrow this to the proxy's
    # actual address wherever the deployment allows it;
    # production_warnings() flags a non-loopback list at startup. What
    # bounds the login path regardless is LOCKOUT_THRESHOLD, which counts
    # failures per ACCOUNT and so cannot be diluted by choosing source
    # addresses.
    TRUSTED_PROXIES: list[str] = [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]

    # ── Auth ──────────────────────────────────────────────────────────────
    # Consecutive failed logins for one ACCOUNT before it is locked, and how
    # long the lock lasts. Per-IP throttling alone does not bound a
    # brute-force run: the attacker picks the source addresses, so a botnet
    # — or a single host behind a trusted proxy, where X-Forwarded-For
    # decides the bucket — gets a fresh allowance per address while the
    # target account sees every attempt. Counting failures per account is
    # the half of the limit the attacker cannot choose.
    LOCKOUT_THRESHOLD: int = Field(default=5, ge=1, le=100)
    LOCKOUT_DURATION_MINUTES: int = Field(default=15, ge=1, le=1440)
    TOKEN_EXPIRE_MINUTES: int = 60
    # Hard ceiling on how long a session can be extended by refreshing.
    # Refresh trades "logged out mid-sentence every hour" for "a stolen
    # token stays useful a while longer", so the ceiling is what keeps that
    # trade bounded — past it the user logs in again, no exceptions.
    SESSION_MAX_HOURS: int = Field(default=12, ge=1, le=720)
    # Gate on POST /auth/register. Register the owner account, then set
    # false in production so strangers can't create accounts billed to the
    # operator's LLM keys.
    ALLOW_REGISTRATION: bool = True
    # Minimum password length enforced at register/change. 8 is the floor;
    # operators can only raise it.
    PASSWORD_MIN_LENGTH: int = Field(default=8, ge=8, le=128)

    # ── HTTP hardening ────────────────────────────────────────────────────
    # Host headers accepted by the app (Starlette TrustedHostMiddleware).
    # ["*"] disables the check; set to your real hostname(s) in production.
    ALLOWED_HOSTS: list[str] = ["*"]

    # ── Logging ───────────────────────────────────────────────────────────
    LOG_LEVEL: str = Field(
        default="INFO",
        pattern="^(?i:critical|error|warning|info|debug)$",
        description="Minimum level for structlog output",
    )

    # ── Approvals ─────────────────────────────────────────────────────────
    # How long a pending tool-approval stays actionable before it expires.
    APPROVAL_TTL_MINUTES: int = 15

    # ── Environment ───────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"

    def production_warnings(self) -> list[str]:
        """Return misconfigurations worth surfacing at startup in production.

        These are warnings rather than hard failures: each has a legitimate
        (if unusual) production use, unlike placeholder keys, which the
        field validators reject outright in every environment.
        """
        if self.ENVIRONMENT != "production":
            return []
        warnings: list[str] = []
        if any(
            "localhost" in origin or "127.0.0.1" in origin
            for origin in self.CORS_ORIGINS
        ):
            warnings.append(
                "CORS_ORIGINS contains a localhost origin; set it to the real "
                "frontend origin for production"
            )
        if self.AUDIT_HMAC_KEY is None:
            warnings.append(
                "AUDIT_HMAC_KEY is unset; the audit-log HMAC key is derived from "
                "ENCRYPTION_KEY, so a database adversary who also holds that key "
                "can forge history — set a dedicated key stored apart from the DB"
            )
        if self.ALLOW_REGISTRATION:
            warnings.append(
                "registration is open; set ALLOW_REGISTRATION=false once the "
                "owner account exists, or anyone who finds the URL can create "
                "accounts billed to this server's LLM keys"
            )
        if self.ALLOWED_HOSTS == ["*"]:
            warnings.append(
                "ALLOWED_HOSTS is ['*']; set it to the real hostname(s) to "
                "enable Host-header validation"
            )
        wide = self._non_loopback_trusted_proxies()
        if wide:
            warnings.append(
                "TRUSTED_PROXIES trusts X-Forwarded-For from "
                + ", ".join(wide)
                + "; every host that can reach this API from those ranges can "
                "spoof its client IP and mint a fresh rate-limit bucket per "
                "request — narrow it to the reverse proxy's own address"
            )
        return warnings

    def _non_loopback_trusted_proxies(self) -> list[str]:
        """Trusted-proxy entries that extend past loopback.

        Anything wider than the loopback interface means the XFF header is
        believed from hosts other than a proxy running on this machine, so
        client-IP attribution — and every limit keyed on it — is only as
        trustworthy as the narrowest network in the list.
        """
        loopback_v4 = ipaddress.IPv4Network("127.0.0.0/8")
        loopback_v6 = ipaddress.IPv6Network("::1/128")
        wide: list[str] = []
        for cidr in self.TRUSTED_PROXIES:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue  # the rate limiter logs and skips these
            local = (
                net.subnet_of(loopback_v4)
                if isinstance(net, ipaddress.IPv4Network)
                else net.subnet_of(loopback_v6)
            )
            if not local:
                wide.append(cidr)
        return wide


settings = Settings()  # type: ignore[call-arg]
