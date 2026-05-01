"""Manages the OpenClaw gateway configuration file (openclaw.json).

Reads channel/model settings from the database and writes a JSON5-compatible
config file to the shared Docker volume so that the OpenClaw gateway picks
it up on restart or via config.patch RPC.

Concurrency model
-----------------
A module-level :class:`asyncio.Lock` (``_WRITE_LOCK``) serialises concurrent
writes within a single Python process. Two simultaneous channel updates in
the same backend instance can therefore no longer race; the second waits
for the first to complete its temp-file write + ``os.replace`` cycle.

NOTE: This lock does NOT cover the multi-process case (e.g. multiple
uvicorn workers, blue/green deployments). If the deployer runs more than
one writer, they need a cross-process lock — typically a file lock via
``fcntl`` or a ``flock`` on the target directory. That's deliberately the
deployer's problem because the right primitive depends on the deployment
target (single VM vs k8s vs lambda). Within one process this lock is
sufficient.

Atomic write
------------
We never write directly to the destination. Sequence:

1. Validate the config dict against the schema (cheap, in-memory).
2. ``json.dump`` to a temp file in the same directory as the target — same
   directory matters for ``os.replace`` to be atomic on POSIX.
3. ``fsync`` the temp file's fd so the bytes hit disk before the rename.
4. ``os.replace(tmp, target)`` — atomic rename on POSIX.
5. ``finally`` cleans up the temp file if any step raised.

This guarantees the gateway never sees a half-written file: it sees either
the old contents or the new ones.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import structlog
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.security import decrypt_credentials
from models.channel import Channel

logger = structlog.get_logger(__name__)

# Resolve from settings (which already reads OPENCLAW_CONFIG_DIR from env)
# but fall back to env / sensible default to keep tests that monkey-patch
# ``os.environ["OPENCLAW_CONFIG_DIR"]`` after import working.
OPENCLAW_CONFIG_DIR = os.environ.get(
    "OPENCLAW_CONFIG_DIR",
    getattr(settings, "OPENCLAW_CONFIG_DIR", "/openclaw-config"),
)
OPENCLAW_CONFIG_PATH = Path(OPENCLAW_CONFIG_DIR) / "openclaw.json"

# Process-wide write lock — see module docstring for the multi-process caveat.
_WRITE_LOCK = asyncio.Lock()

PROVIDER_MODEL_PREFIX = {
    "anthropic": "anthropic",
    "openai": "openai",
    "gemini": "google",
    "grok": "xai",
    "deepseek": "deepseek",
    "groq": "groq",
    "mistral": "mistral",
    "ollama": "ollama",
}


class OpenClawConfigError(ValueError):
    """Raised when an OpenClaw config dict fails schema validation."""


def _provider_env_key(provider: str) -> str | None:
    """Return the environment variable name OpenClaw expects for a provider."""
    mapping = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "grok": "XAI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "groq": "GROQ_API_KEY",
        "mistral": "MISTRAL_API_KEY",
    }
    return mapping.get(provider)


def _format_model_id(provider: str, model: str) -> str:
    """Convert our provider+model into OpenClaw's 'provider/model' format."""
    prefix = PROVIDER_MODEL_PREFIX.get(provider, provider)
    if "/" in model:
        return model
    return f"{prefix}/{model}"


def _build_channel_config(channel_type: str, config: dict[str, Any]) -> dict[str, Any]:
    """Build the OpenClaw channel config block for a specific channel type."""
    if channel_type == "telegram":
        return {
            "enabled": True,
            "botToken": config.get("bot_token", ""),
            "groupPolicy": config.get("group_policy", "allowlist"),
        }
    elif channel_type == "discord":
        return {
            "enabled": True,
            "token": config.get("bot_token", ""),
            "dm": {
                "enabled": True,
                "policy": config.get("dm_policy", "pairing"),
            },
            "groupPolicy": config.get("group_policy", "allowlist"),
        }
    elif channel_type == "slack":
        result: dict[str, Any] = {
            "botToken": config.get("bot_token", ""),
        }
        if config.get("app_token"):
            result["appToken"] = config["app_token"]
        return result
    elif channel_type == "whatsapp":
        return {
            "dmPolicy": config.get("dm_policy", "pairing"),
            "allowFrom": config.get("allow_from", []),
            "groupPolicy": config.get("group_policy", "allowlist"),
        }
    elif channel_type == "signal":
        return {
            "enabled": True,
            "groupPolicy": config.get("group_policy", "allowlist"),
        }
    return {}


def build_openclaw_config(
    *,
    provider: str,
    model: str,
    api_key: str | None = None,
    channels: list[dict[str, Any]] | None = None,
    agent_name: str = "SentientAI",
    user_id: str | None = None,
) -> dict[str, Any]:
    """Build the complete openclaw.json configuration dict.

    The returned dict is shaped to satisfy :func:`_validate_openclaw_config`
    so any caller that builds via this helper is guaranteed-valid.
    """
    model_id = _format_model_id(provider, model)

    channels_list: list[dict[str, Any]] = []
    channels_block: dict[str, Any] = {}
    if channels:
        for ch in channels:
            ch_type = ch.get("channel_type", "")
            ch_config = ch.get("config", {})
            if ch_type and ch_config:
                channels_block[ch_type] = _build_channel_config(ch_type, ch_config)
                channels_list.append({"type": ch_type})

    env_key = _provider_env_key(provider)
    api_key_env = env_key or ""

    # Schema-shaped ``users`` block — this is what the validator inspects.
    users_block = [
        {
            "user_id": user_id or "default",
            "llm": {
                "provider": provider,
                "model": model,
                "api_key_env": api_key_env,
            },
            "channels": channels_list,
        }
    ]

    config: dict[str, Any] = {
        "version": 1,
        "users": users_block,
        "identity": {
            "name": agent_name,
            "theme": "a helpful, secure AI assistant powered by SentientAI",
            "emoji": "\U0001f9e0",
        },
        "agent": {
            "workspace": "/home/node/.openclaw/workspace",
            "model": {
                "primary": model_id,
            },
        },
        "gateway": {
            "mode": "local",
            "port": 18789,
            "bind": "lan",
        },
        "logging": {
            "level": "info",
        },
    }

    env_block: dict[str, str] = {}
    if env_key and api_key:
        env_block[env_key] = api_key

    if provider == "ollama":
        if "models" not in config:
            config["models"] = {}
        config["models"]["providers"] = {
            "ollama": {
                "baseUrl": "http://host.docker.internal:11434/v1",
                "apiKey": "ollama",
                "api": "openai-responses",
            }
        }

    if channels_block:
        config["channels"] = channels_block

    if env_block:
        config["env"] = env_block

    return config


# ── Schema validation ─────────────────────────────────────────────────────


def _validate_openclaw_config(config: Any) -> None:
    """Hand-rolled schema check.

    Raises :class:`OpenClawConfigError` with a clear message on the first
    problem encountered. We're deliberately not using Pydantic here because
    the config dict is heterogeneous (provider-specific blocks) and the
    minimum required shape is small.

    Required shape::

        {
          "version": int,
          "users": [
            {
              "user_id": str,
              "llm": {"provider": str, "model": str, "api_key_env": str},
              "channels": [ ... ]
            }
          ]
        }
    """
    if not isinstance(config, dict):
        raise OpenClawConfigError(
            f"config must be a dict, got {type(config).__name__}"
        )

    version = config.get("version")
    if not isinstance(version, int):
        raise OpenClawConfigError(
            f"'version' must be an int, got {type(version).__name__}"
        )

    users = config.get("users")
    if not isinstance(users, list):
        raise OpenClawConfigError(
            f"'users' must be a list, got {type(users).__name__}"
        )
    if not users:
        raise OpenClawConfigError("'users' must contain at least one user")

    for idx, user in enumerate(users):
        if not isinstance(user, dict):
            raise OpenClawConfigError(
                f"users[{idx}] must be a dict, got {type(user).__name__}"
            )
        if "user_id" not in user:
            raise OpenClawConfigError(f"users[{idx}].user_id is required")

        llm = user.get("llm")
        if not isinstance(llm, dict):
            raise OpenClawConfigError(
                f"users[{idx}].llm must be a dict, got {type(llm).__name__}"
            )
        for field in ("provider", "model", "api_key_env"):
            if field not in llm:
                raise OpenClawConfigError(
                    f"users[{idx}].llm.{field} is required"
                )
            if not isinstance(llm[field], str):
                raise OpenClawConfigError(
                    f"users[{idx}].llm.{field} must be a string"
                )

        channels = user.get("channels")
        if not isinstance(channels, list):
            raise OpenClawConfigError(
                f"users[{idx}].channels must be a list, got {type(channels).__name__}"
            )


# ── Atomic write ──────────────────────────────────────────────────────────


def _atomic_write_sync(config: dict[str, Any], target_path: Path) -> Path:
    """The synchronous half of the atomic write — runs while we hold the
    asyncio lock, but performs blocking IO. Pulled out so it's easy to test
    in isolation and so the lock-protected critical section is small.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Temp file lives in the same directory so ``os.replace`` is atomic.
    suffix = target_path.suffix + ".tmp." + uuid.uuid4().hex[:8]
    tmp_path = target_path.with_suffix(suffix)

    try:
        # Open with explicit fd so we can fsync before close.
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, target_path)
        return target_path
    finally:
        # If anything above raised (or os.replace itself failed), make sure
        # we don't leave the temp file behind. ``os.replace`` only consumes
        # the temp on success, so a failure leaves it on disk.
        try:
            if tmp_path.exists():
                os.unlink(tmp_path)
        except OSError:
            # Best effort — losing a temp file is not fatal, and we don't
            # want to mask the original exception.
            pass


async def write_openclaw_config(
    config: dict[str, Any],
    target_path: Path | None = None,
) -> Path:
    """Validate and atomically write the OpenClaw config.

    1. Validates against :func:`_validate_openclaw_config` BEFORE touching
       the disk. A bad config never even creates a temp file.
    2. Acquires the process-wide ``_WRITE_LOCK`` so concurrent callers in
       the same process serialise instead of racing.
    3. Writes via temp file + fsync + os.replace.

    Raises :class:`OpenClawConfigError` on validation failure. Any other
    exception (IOError, OSError, ...) is re-raised after best-effort temp
    file cleanup.
    """
    target = target_path or OPENCLAW_CONFIG_PATH

    _validate_openclaw_config(config)

    async with _WRITE_LOCK:
        path = await asyncio.to_thread(_atomic_write_sync, config, target)
        logger.info("openclaw_config_written", path=str(path))
        return path


# ── Gateway reload trigger ────────────────────────────────────────────────


async def trigger_gateway_reload() -> dict[str, Any]:
    """Best-effort POST to the OpenClaw gateway's reload endpoint.

    The reload signal is advisory: the config is already on disk, and the
    gateway will pick it up at the next restart even without this call.
    Failures are logged but never raised.

    TODO: the actual ``/openclaw/reload`` endpoint may not exist on the
    openclaw side yet. If the gateway implements file-watching this whole
    function becomes redundant. Until then, this gives us an explicit
    "config changed" signal that the openclaw container can implement
    when it's ready.

    Returns ``{ok: bool, status_code: int | None, message: str | None}``.
    """
    gateway_url = settings.OPENCLAW_GATEWAY_URL
    url = f"{gateway_url.rstrip('/')}/openclaw/reload"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url)
    except httpx.RequestError as exc:
        # Gateway down / unreachable / DNS failure — expected during initial
        # bring-up before the openclaw container starts. Don't escalate.
        logger.info(
            "openclaw_reload_unreachable",
            url=url,
            error=str(exc),
        )
        return {"ok": False, "status_code": None, "message": str(exc)}

    if 200 <= resp.status_code < 300:
        return {
            "ok": True,
            "status_code": resp.status_code,
            "message": "reload accepted",
        }

    # 4xx/5xx — gateway is up but rejected the call. Log warning and move
    # on; config is on disk and will be picked up at next restart.
    logger.warning(
        "openclaw_reload_non_2xx",
        url=url,
        status_code=resp.status_code,
        body=resp.text[:500] if resp.text else "",
    )
    return {
        "ok": False,
        "status_code": resp.status_code,
        "message": f"gateway returned {resp.status_code}",
    }


# ── Health check helper ───────────────────────────────────────────────────


async def gateway_health() -> dict[str, Any]:
    """GET ``/healthz`` on the OpenClaw gateway.

    Used by ``GET /api/channels/openclaw/status``. Returns a structured
    status the route can include directly in its response. Never raises.
    """
    gateway_url = settings.OPENCLAW_GATEWAY_URL
    url = f"{gateway_url.rstrip('/')}/healthz"

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
    except httpx.RequestError as exc:
        return {
            "ok": False,
            "status": "unreachable",
            "details": str(exc),
        }

    if 200 <= resp.status_code < 300:
        return {
            "ok": True,
            "status": "healthy",
            "details": f"HTTP {resp.status_code}",
        }
    return {
        "ok": False,
        "status": "unhealthy",
        "details": f"HTTP {resp.status_code}",
    }


# ── Per-channel status persistence ────────────────────────────────────────


# Allowed status values — kept in sync with the docstring on
# ``update_channel_status`` and the column server_default in the migration.
_ALLOWED_STATUSES = frozenset(
    {"connected", "disconnected", "error", "connecting", "unconfigured"}
)


async def update_channel_status(
    db: AsyncSession,
    channel_id: Any,
    status: str,
    last_error: str | None = None,
) -> None:
    """UPDATE a channel row's status fields.

    Status enum values: ``connected``, ``disconnected``, ``error``,
    ``connecting``, ``unconfigured``. Caller is responsible for the
    surrounding transaction / commit semantics — this only issues the
    UPDATE statement.
    """
    if status not in _ALLOWED_STATUSES:
        raise ValueError(
            f"invalid status {status!r}; expected one of {sorted(_ALLOWED_STATUSES)}"
        )

    stmt = (
        update(Channel)
        .where(Channel.id == channel_id)
        .values(
            status=status,
            last_error=last_error,
            last_status_at=datetime.now(timezone.utc),
        )
    )
    await db.execute(stmt)


# ── Sync orchestrator ─────────────────────────────────────────────────────


async def sync_openclaw_config_for_user(
    user: Any,
    channels_data: list[dict[str, Any]] | None = None,
) -> Path:
    """Rebuild and write the OpenClaw config based on a User and their channels.

    After a successful write, calls :func:`trigger_gateway_reload` so the
    gateway has a chance to pick up the change immediately. The reload is
    advisory — if it fails we still consider the sync successful because
    the config is on disk.
    """
    api_key: str | None = None
    if user.llm_api_key_enc:
        try:
            api_key = decrypt_credentials(user.llm_api_key_enc)
        except Exception:
            logger.warning("failed_to_decrypt_api_key", user_id=str(user.id))

    config = build_openclaw_config(
        provider=user.llm_provider,
        model=user.llm_model,
        api_key=api_key,
        channels=channels_data,
        agent_name=user.name or "SentientAI",
        user_id=str(user.id),
    )

    path = await write_openclaw_config(config)

    try:
        await trigger_gateway_reload()
    except Exception as exc:  # pragma: no cover — defence in depth
        # trigger_gateway_reload already swallows expected failures, but
        # if something truly unexpected happens we still don't want to
        # fail the channel update — the on-disk write succeeded.
        logger.warning("openclaw_reload_unexpected_error", error=str(exc))

    return path


# TODO: routes/channels.py should call ``await trigger_gateway_reload()``
# directly (or via this orchestrator) at the end of every channel mutation
# endpoint. Right now ``_sync_config`` already calls
# ``sync_openclaw_config_for_user`` which fans out to the reload, so wiring
# is implicit. If/when the route stops going through this orchestrator,
# the explicit call needs to be added there.
