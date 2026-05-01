"""Smoke tests for application liveness."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_health_endpoint_returns_200(client) -> None:
    """`GET /api/health` should return 200 with a healthy status payload."""
    response = await client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert "version" in body


@pytest.mark.asyncio
async def test_root_endpoint_returns_metadata(client) -> None:
    """`GET /` should expose basic service metadata."""
    response = await client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "SentientAI"
    assert "version" in body
