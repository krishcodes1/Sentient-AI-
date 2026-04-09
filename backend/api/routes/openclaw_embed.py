"""Public-ish metadata for embedding the OpenClaw Control UI in the SentientAI shell."""

from __future__ import annotations

from fastapi import APIRouter

from core.config import settings

router = APIRouter(prefix="/openclaw", tags=["openclaw"])


@router.get("/embed-url")
async def openclaw_embed_url() -> dict[str, str]:
    """Return the gateway base URL for browser iframes (not the Docker internal URL)."""
    base = settings.OPENCLAW_GATEWAY_BROWSER_URL.rstrip("/")
    return {"url": f"{base}/"}
