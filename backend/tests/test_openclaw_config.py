"""Tests for the OpenClaw config manager.

Covers:
- atomic write semantics (failure mid-replace cleans up the temp file and
  leaves the existing target untouched)
- in-process write serialisation under ``asyncio.gather``
- schema validation rejection
- gateway reload best-effort behaviour (unreachable host vs 2xx response)

The autouse ``_stub_openclaw_config`` fixture in ``conftest.py`` stubs the
public writer/orchestrator names with no-ops, but here we want to exercise
the real implementations. We re-import the module by name and call the
underlying functions directly so we don't pick up the monkeypatch.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

# Import the real module — the conftest monkeypatch only rebinds attributes
# on the module, but we call the real functions via attribute lookup that
# the conftest leaves alone (validate, _atomic_write_sync, trigger,
# health). For ``write_openclaw_config`` we reach into the module after
# the autouse fixture restores the real binding.
from services.openclaw import config_manager as cm


# ---------------------------------------------------------------------------
# Fixtures: get a real (un-stubbed) writer + a per-test target file.
# ---------------------------------------------------------------------------


@pytest.fixture
def real_write_openclaw_config(monkeypatch: pytest.MonkeyPatch):
    """Undo the conftest autouse stub so we exercise the real writer.

    The conftest's ``_stub_openclaw_config`` fixture rebinds
    ``write_openclaw_config`` to a sync no-op. We re-import the module to
    refresh the original async implementation, then assign it back onto
    the module (bypassing pytest's monkeypatch tracking — fine because the
    stub fixture cleans up after the test anyway).
    """
    import importlib

    fresh = importlib.import_module("services.openclaw.config_manager")
    importlib.reload(fresh)
    # Make sure the module the test imported as ``cm`` points at the
    # reloaded callables too — re-binding the global from the reloaded
    # module rather than the old reference.
    cm.write_openclaw_config = fresh.write_openclaw_config
    cm._WRITE_LOCK = fresh._WRITE_LOCK
    cm._atomic_write_sync = fresh._atomic_write_sync
    cm._validate_openclaw_config = fresh._validate_openclaw_config
    cm.OpenClawConfigError = fresh.OpenClawConfigError
    cm.trigger_gateway_reload = fresh.trigger_gateway_reload
    cm.gateway_health = fresh.gateway_health
    yield fresh.write_openclaw_config


@pytest.fixture
def target_path(tmp_path: Path) -> Path:
    """An on-disk target path, plus a guarantee that it doesn't exist yet."""
    return tmp_path / "openclaw.json"


def _valid_config() -> dict[str, Any]:
    return {
        "version": 1,
        "users": [
            {
                "user_id": "u-1",
                "llm": {
                    "provider": "openai",
                    "model": "gpt-4o",
                    "api_key_env": "OPENAI_API_KEY",
                },
                "channels": [{"type": "telegram"}],
            }
        ],
    }


# ---------------------------------------------------------------------------
# A. Atomic write
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_is_atomic(
    real_write_openclaw_config,
    target_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``os.replace`` fails mid-call, the temp file is cleaned up and
    the existing target is left untouched."""
    # Pre-populate the target with known good content so we can assert it
    # didn't change.
    original = '{"existing": "content"}'
    target_path.write_text(original)

    def _boom(_src: str, _dst: str) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(cm.os, "replace", _boom)

    with pytest.raises(OSError):
        await real_write_openclaw_config(_valid_config(), target_path)

    # Target unchanged.
    assert target_path.read_text() == original

    # No leftover ``*.tmp.*`` files in the directory.
    leftovers = [
        p for p in target_path.parent.iterdir()
        if ".tmp." in p.name
    ]
    assert leftovers == [], f"leftover temp files: {leftovers}"


@pytest.mark.asyncio
async def test_concurrent_writes_serialized(
    real_write_openclaw_config,
    target_path: Path,
) -> None:
    """Five concurrent writes serialise; the final file is valid JSON
    matching one of the inputs (no torn bytes)."""
    configs: list[dict[str, Any]] = []
    for i in range(5):
        cfg = _valid_config()
        cfg["users"][0]["user_id"] = f"u-{i}"
        configs.append(cfg)

    await asyncio.gather(
        *(real_write_openclaw_config(cfg, target_path) for cfg in configs)
    )

    # File is valid JSON.
    raw = target_path.read_text()
    parsed = json.loads(raw)

    # And matches exactly one of the configs we wrote (no partial merge).
    user_ids = {c["users"][0]["user_id"] for c in configs}
    assert parsed["users"][0]["user_id"] in user_ids


# ---------------------------------------------------------------------------
# B. Validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_config_rejected(
    real_write_openclaw_config,
    target_path: Path,
) -> None:
    """Missing required key raises ``OpenClawConfigError`` and does not
    create the target file."""
    bad = _valid_config()
    del bad["users"][0]["llm"]["api_key_env"]

    with pytest.raises(cm.OpenClawConfigError):
        await real_write_openclaw_config(bad, target_path)

    assert not target_path.exists()


@pytest.mark.asyncio
async def test_invalid_config_missing_version(
    real_write_openclaw_config,
    target_path: Path,
) -> None:
    bad = _valid_config()
    del bad["version"]
    with pytest.raises(cm.OpenClawConfigError):
        await real_write_openclaw_config(bad, target_path)


@pytest.mark.asyncio
async def test_invalid_config_empty_users(
    real_write_openclaw_config,
    target_path: Path,
) -> None:
    bad = _valid_config()
    bad["users"] = []
    with pytest.raises(cm.OpenClawConfigError):
        await real_write_openclaw_config(bad, target_path)


# ---------------------------------------------------------------------------
# C. Gateway reload trigger
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trigger_reload_swallows_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connection error returns ``{ok: False, ...}`` and does not raise."""
    real_async_client = getattr(httpx, "_RealAsyncClient", httpx.AsyncClient)

    def _raise_connect_error(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    transport = httpx.MockTransport(_raise_connect_error)

    class _PatchedClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cm.httpx, "AsyncClient", _PatchedClient)

    result = await cm.trigger_gateway_reload()

    assert result["ok"] is False
    assert result["status_code"] is None
    assert result["message"]


@pytest.mark.asyncio
async def test_trigger_reload_returns_ok_on_2xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 200 response from the gateway returns ``{ok: True, ...}``."""
    real_async_client = getattr(httpx, "_RealAsyncClient", httpx.AsyncClient)

    def _ok(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"reloaded": True})

    transport = httpx.MockTransport(_ok)

    class _PatchedClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cm.httpx, "AsyncClient", _PatchedClient)

    result = await cm.trigger_gateway_reload()

    assert result["ok"] is True
    assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_trigger_reload_warns_on_5xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 500 response logs a WARNING but does not raise."""
    real_async_client = getattr(httpx, "_RealAsyncClient", httpx.AsyncClient)

    def _err(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    transport = httpx.MockTransport(_err)

    class _PatchedClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cm.httpx, "AsyncClient", _PatchedClient)

    result = await cm.trigger_gateway_reload()

    assert result["ok"] is False
    assert result["status_code"] == 500


# ---------------------------------------------------------------------------
# D. Health check helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gateway_health_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_async_client = getattr(httpx, "_RealAsyncClient", httpx.AsyncClient)
    transport = httpx.MockTransport(
        lambda _r: (_ for _ in ()).throw(httpx.ConnectError("nope"))
    )

    class _PatchedClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cm.httpx, "AsyncClient", _PatchedClient)

    result = await cm.gateway_health()
    assert result["ok"] is False
    assert result["status"] == "unreachable"


@pytest.mark.asyncio
async def test_gateway_health_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_async_client = getattr(httpx, "_RealAsyncClient", httpx.AsyncClient)
    transport = httpx.MockTransport(lambda _r: httpx.Response(200))

    class _PatchedClient(real_async_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cm.httpx, "AsyncClient", _PatchedClient)

    result = await cm.gateway_health()
    assert result["ok"] is True
    assert result["status"] == "healthy"
