"""Decides which embedding backend the meaning index uses, and builds it: the
install-wide AI provider's embedding model (Gemini or OpenAI), or Ollama
(on this computer), or none.

Why it exists: the vectors of one install must all come from one model, so
the backend follows the install-wide provider (never a user's personal
choice), with one override: KB_EMBEDDINGS=ollama builds the index with
Ollama even when chats use a cloud provider. Providers with no embedding
model (Claude, Grok, DeepSeek, Groq, Mistral) leave knowledge search
keyword-only, which is a working mode, not an error.

Text is always passed through services.security.egress.redact_for_embedding
first: keys, card and ID numbers never leave, and contact details are
replaced too when the endpoint is a cloud one and the owner hides personal
details. A query embedding gets QUERY_EMBED_TIMEOUT_S; any failure answers
None (the search falls back to keywords).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Optional, Sequence

import structlog

from services.knowledge.limits import EMBED_DIMS, QUERY_EMBED_TIMEOUT_S
from services.knowledge.vectors import normalize

logger = structlog.get_logger(__name__)

BACKENDS = ("ollama", "gemini", "openai")
DEFAULT_MODELS = {
    "gemini": "gemini-embedding-001",
    "openai": "text-embedding-3-small",
    "ollama": "nomic-embed-text",
}
_MODEL_SETTINGS = {
    "gemini": "GEMINI_EMBED_MODEL",
    "openai": "OPENAI_EMBED_MODEL",
    "ollama": "OLLAMA_EMBED_MODEL",
}


def backend_name(default_provider: Optional[str], kb_embeddings: Optional[str] = None) -> str:
    """'ollama', 'gemini', 'openai' or '' (no embedding backend).

    KB_EMBEDDINGS=ollama, or an Ollama install provider, gives 'ollama';
    a Gemini or OpenAI install provider gives itself; anything else ''.
    KB_EMBEDDINGS=off (or none) turns the meaning index off."""
    override = (kb_embeddings or "").strip().lower()
    if override in ("off", "none", "disabled"):
        return ""
    provider = (default_provider or "").strip().lower()
    if override == "ollama" or provider == "ollama":
        return "ollama"
    if provider in ("gemini", "openai"):
        return provider
    return ""


def embed_model(backend: str, config: Any = None) -> str:
    """The embedding model name for *backend* (from the settings)."""
    if config is None:
        from core.config import settings as config
    name = str(getattr(config, _MODEL_SETTINGS.get(backend, ""), "") or "").strip()
    return name or DEFAULT_MODELS.get(backend, "")


def embed_dims(config: Any = None) -> int:
    if config is None:
        from core.config import settings as config
    try:
        dims = int(getattr(config, "KB_EMBED_DIMS", EMBED_DIMS) or EMBED_DIMS)
    except (TypeError, ValueError):
        return EMBED_DIMS
    return max(8, min(dims, 3072))


def model_id(backend: str, model: str, dims: int) -> str:
    """The id stored with every vector, e.g. 'gemini:gemini-embedding-001:256'."""
    return f"{backend}:{model}:{dims}"[:80]


@dataclass(frozen=True)
class Backend:
    """The resolved backend: its name, model, dimensions, stored model id,
    and whether the endpoint is a cloud one."""

    name: str
    model: str
    dims: int
    cloud: bool

    @property
    def id(self) -> str:
        return model_id(self.name, self.model, self.dims)


class EmbeddingSource:
    """Builds the install's embedding backend from the InstallationService
    (the install-wide provider and its key) and the settings. Every method
    fails closed: a backend that cannot be built answers None."""

    def __init__(self, installation: Any, config: Any = None, *, provider_factory: Any = None) -> None:
        self._installation = installation
        if config is None:
            from core.config import settings as config
        self._config = config
        self._factory = provider_factory

    async def backend(self) -> Optional[Backend]:
        try:
            provider, _model = await self._installation.llm_defaults()
        except Exception as exc:  # noqa: BLE001 - no backend rather than a crash
            logger.warning("knowledge_backend_unreadable", error_type=type(exc).__name__)
            return None
        name = backend_name(provider, getattr(self._config, "KB_EMBEDDINGS", None))
        if not name:
            return None
        return Backend(name, embed_model(name, self._config), embed_dims(self._config), self._is_cloud(name))

    def _is_cloud(self, name: str) -> bool:
        if name != "ollama":
            return True
        from services.agent.providers import ollama_base_url
        from services.security.egress import is_local_provider

        base = ollama_base_url(str(getattr(self._config, "OLLAMA_BASE_URL", "") or ""))
        return not is_local_provider("ollama", base)

    async def hide_personal(self) -> bool:
        """The owner's "Hide personal details" switch (a gate error hides)."""
        try:
            return "hide_personal_details" in await self._installation.enabled_keys()
        except Exception:  # noqa: BLE001 - a switch that cannot be read hides
            return True

    async def provider(self, backend: Backend) -> Any:
        """A provider instance able to embed with *backend* (the caller
        closes it with ``aclose``). Raises when no key is configured."""
        if self._factory is not None:
            return self._factory(backend)
        from services.agent.providers import (
            GeminiProvider,
            OllamaProvider,
            OpenAIProvider,
            ollama_base_url,
        )

        if backend.name == "ollama":
            return OllamaProvider(base_url=ollama_base_url(str(self._config.OLLAMA_BASE_URL)), model=backend.model)
        key = await self._installation.llm_api_key(backend.name)
        if not key:
            raise RuntimeError(f"no {backend.name} key is configured")
        if backend.name == "gemini":
            return GeminiProvider(api_key=key)
        return OpenAIProvider(api_key=key)

    async def embed_query(self, query: str, backend: Backend) -> Optional[list[float]]:
        """The query's vector, or None on any failure or after
        QUERY_EMBED_TIMEOUT_S (the search then uses keywords only)."""
        from services.security.egress import redact_for_embedding

        text = redact_for_embedding(query, cloud=backend.cloud, hide_personal=await self.hide_personal())
        provider = None
        try:
            provider = await self.provider(backend)
            vectors = await asyncio.wait_for(
                provider.embed([text], kind="query", dims=backend.dims, model=backend.model),
                timeout=QUERY_EMBED_TIMEOUT_S,
            )
            if not vectors or not vectors[0]:
                return None
            return normalize(vectors[0])
        except Exception as exc:  # noqa: BLE001 - keyword search still works
            logger.info("knowledge_query_embed_failed", error_type=type(exc).__name__)
            return None
        finally:
            if provider is not None:
                await _close(provider)


async def embed_documents(provider: Any, texts: Sequence[str], backend: Backend) -> list[list[float]]:
    """Vectors for already-redacted passage texts, normalised."""
    vectors = await provider.embed(list(texts), kind="document", dims=backend.dims, model=backend.model)
    if len(vectors) != len(texts):
        raise ValueError("the provider returned a different number of vectors")
    return [normalize(v) for v in vectors]


async def _close(provider: Any) -> None:
    closer = getattr(provider, "aclose", None)
    if callable(closer):
        try:
            await closer()
        except Exception as exc:  # noqa: BLE001 - closing never fails a search
            logger.debug("knowledge_provider_close_failed", error_type=type(exc).__name__)


close_provider = _close
