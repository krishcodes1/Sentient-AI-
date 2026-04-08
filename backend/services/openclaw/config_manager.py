"""Manages the OpenClaw gateway configuration file (openclaw.json).

Reads channel/model settings from the database and writes a JSON5-compatible
config file to the shared Docker volume so that the OpenClaw gateway picks
it up on restart or via config.patch RPC.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import structlog

from core.security import decrypt_credentials

logger = structlog.get_logger(__name__)

OPENCLAW_CONFIG_DIR = os.environ.get("OPENCLAW_CONFIG_DIR", "/openclaw-config")
OPENCLAW_CONFIG_PATH = Path(OPENCLAW_CONFIG_DIR) / "openclaw.json"

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
) -> dict[str, Any]:
    """Build the complete openclaw.json configuration dict."""
    model_id = _format_model_id(provider, model)

    config: dict[str, Any] = {
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
    env_key = _provider_env_key(provider)
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

    if channels:
        channels_block: dict[str, Any] = {}
        for ch in channels:
            ch_type = ch.get("channel_type", "")
            ch_config = ch.get("config", {})
            if ch_type and ch_config:
                channels_block[ch_type] = _build_channel_config(ch_type, ch_config)
                for k, v in ch_config.items():
                    if k.endswith("_token") and v and k != "bot_token" and k != "app_token":
                        pass
        if channels_block:
            config["channels"] = channels_block

    if env_block:
        config["env"] = env_block

    return config


def write_openclaw_config(config: dict[str, Any]) -> Path:
    """Write the config dict to the OpenClaw config file on the shared volume."""
    config_dir = Path(OPENCLAW_CONFIG_DIR)
    config_dir.mkdir(parents=True, exist_ok=True)

    workspace_dir = config_dir / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    with open(OPENCLAW_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    logger.info("openclaw_config_written", path=str(OPENCLAW_CONFIG_PATH))
    return OPENCLAW_CONFIG_PATH


async def sync_openclaw_config_for_user(user: Any, channels_data: list[dict[str, Any]] | None = None) -> Path:
    """Rebuild and write the OpenClaw config based on a User object and their channels."""
    api_key = None
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
    )

    return write_openclaw_config(config)
