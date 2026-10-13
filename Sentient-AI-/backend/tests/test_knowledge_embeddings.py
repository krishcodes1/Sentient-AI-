"""Tests for the knowledge base's meaning index as search uses it: which
backend an install gets, the knowledge_semantic switch's availability and
requirement, hybrid search finding a paraphrase through a fake embedding
provider, the keyword fallback (switch off, failed or slow query embedding,
vectors of another model), redaction before a query leaves, the vector cache,
and pure-Python scoring equal to numpy's.

Why it exists: semantic search is optional and off by default; when it is off
or broken the knowledge base must keep answering by keywords, and nothing
unredacted may reach the embedding provider.
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from services import capabilities as capability_registry
from services.capabilities.base import ReportContext
from services.knowledge import vectors as kb_vectors
from services.knowledge.embedder import KnowledgeEmbedService
from services.knowledge.embeddings import Backend, EmbeddingSource, backend_name, model_id
from services.knowledge.sources import from_text
from services.knowledge.vectors import VectorCache, VectorRow
from services.tools.knowledge import KnowledgeToolkit
from tests.conftest import make_user

CONCEPTS = [
    {"tuition", "fee", "cost", "price", "pay", "dollar"},
    {"midterm", "exam", "test", "quiz"},
    {"office", "hour", "meet"},
    {"late", "deadline", "penalty"},
]


def concept_vector(text: str) -> list[float]:
    """A tiny 'meaning' model: one dimension per concept (and 4 spare)."""
    from services.knowledge.text import tokens

    words = set(tokens(text))
    vector = [float(len(words & concept)) for concept in CONCEPTS] + [0.0, 0.0, 0.0, 0.01]
    return vector


class FakeProvider:
    def __init__(self, *, fail: bool = False, delay: float = 0.0) -> None:
        self.fail = fail
        self.delay = delay
        self.texts: list[tuple[str, str]] = []
        self.closed = False

    async def embed(self, texts, *, kind, dims, model=None):
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("provider down")
        self.texts.extend((kind, t) for t in texts)
        return [concept_vector(t) for t in texts]

    async def aclose(self) -> None:
        self.closed = True


class FakeInstallation:
    def __init__(self, provider: str = "gemini", hide: bool = True) -> None:
        self.provider = provider
        self.hide = hide

    async def llm_defaults(self):
        return self.provider, "some-model"

    async def enabled_keys(self):
        return frozenset({"hide_personal_details"} if self.hide else set())

    async def llm_api_key(self, provider):
        return "key"


def _config(**extra: Any) -> SimpleNamespace:
    values = {
        "KB_EMBEDDINGS": None,
        "GEMINI_EMBED_MODEL": "fake-embedder",
        "OPENAI_EMBED_MODEL": "o",
        "OLLAMA_EMBED_MODEL": "nomic-embed-text",
        "KB_EMBED_DIMS": 8,
        "OLLAMA_BASE_URL": "http://localhost:11434",
    }
    values.update(extra)
    return SimpleNamespace(**values)


class Gate:
    def __init__(self, off: tuple[str, ...] = ()) -> None:
        self.off = set(off)

    async def __call__(self, key: str) -> Optional[str]:
        return "off" if key in self.off else None


@pytest.mark.parametrize(
    ("provider", "override", "expected"),
    [
        ("gemini", None, "gemini"),
        ("openai", None, "openai"),
        ("ollama", None, "ollama"),
        ("anthropic", None, ""),
        ("grok", None, ""),
        ("mistral", None, ""),
        ("anthropic", "ollama", "ollama"),
        ("gemini", "ollama", "ollama"),
        ("gemini", "off", ""),
        ("anthropic", "gemini", ""),
    ],
)
def test_the_backend_follows_the_install_provider(provider, override, expected):
    assert backend_name(provider, override) == expected


def test_knowledge_semantic_is_off_medium_risk_and_needs_the_knowledge_base():
    cap = capability_registry.get("knowledge_semantic")
    assert cap.default_enabled is False and cap.risk == "medium" and cap.tools == ()
    assert cap.requires == ("knowledge_base",)
    base = capability_registry.get("knowledge_base")
    assert base.default_enabled is True and base.risk == "low" and base.tools == ("knowledge.",)
    assert capability_registry.settings_defaults("knowledge_base") == {
        "documents_per_user": 400,
        "text_mb_per_user": 25,
        "file_mb": 25,
        "embed_ktokens_per_day": 1000,
    }


def _ctx(backend: str) -> ReportContext:
    return ReportContext(
        in_container=False, platform="linux", telegram_configured=False, browser_installed=False, embedding_backend=backend
    )


def test_knowledge_semantic_is_blocked_without_an_embedding_backend():
    switches = {"knowledge_semantic": True, "knowledge_base": True}
    statuses = capability_registry.statuses_by_key(capability_registry.report(switches, _ctx("")))
    semantic = statuses["knowledge_semantic"]
    assert semantic.effective == "blocked"
    assert semantic.reason.startswith("Your AI provider has no embedding model Crawler can use")
    on = capability_registry.statuses_by_key(capability_registry.report(switches, _ctx("gemini")))
    assert on["knowledge_semantic"].effective == "on"
    needs = capability_registry.statuses_by_key(
        capability_registry.report({"knowledge_semantic": True, "knowledge_base": False}, _ctx("gemini"))
    )
    assert needs["knowledge_semantic"].effective == "blocked"


def test_default_context_fills_the_embedding_backend(monkeypatch):
    from core.config import settings

    monkeypatch.setattr(settings, "KB_EMBEDDINGS", None)
    assert capability_registry.default_context(default_provider="openai").embedding_backend == "openai"
    assert capability_registry.default_context(default_provider="anthropic").embedding_backend == ""
    monkeypatch.setattr(settings, "KB_EMBEDDINGS", "ollama")
    assert capability_registry.default_context(default_provider="anthropic").embedding_backend == "ollama"


@pytest.mark.asyncio
async def test_the_embedding_source_resolves_the_backend_and_its_model_id():
    source = EmbeddingSource(FakeInstallation("gemini"), _config())
    backend = await source.backend()
    assert backend == Backend("gemini", "fake-embedder", 8, True)
    assert backend.id == model_id("gemini", "fake-embedder", 8) == "gemini:fake-embedder:8"
    assert await EmbeddingSource(FakeInstallation("anthropic"), _config()).backend() is None
    local = await EmbeddingSource(FakeInstallation("anthropic"), _config(KB_EMBEDDINGS="ollama")).backend()
    assert local is not None and local.name == "ollama" and local.cloud is False
    remote = await EmbeddingSource(FakeInstallation("ollama"), _config(OLLAMA_BASE_URL="http://gpu-box.lan:11434")).backend()
    assert remote is not None and remote.cloud is True


async def _setup(session_factory, email: str, *, provider: Optional[FakeProvider] = None, gate: Optional[Gate] = None, hide: bool = True):
    user, _ = await make_user(session_factory, email)
    fake = provider or FakeProvider()
    source = EmbeddingSource(FakeInstallation("gemini", hide=hide), _config(), provider_factory=lambda backend: fake)
    toolkit = KnowledgeToolkit(session_factory, capability_refusal=gate or Gate(), embeddings=source)
    await toolkit.service.add_document(str(user.id), "Admin", from_text("Tuition fee is five hundred dollars per term.", "Fees"))
    await toolkit.service.add_document(str(user.id), "CS101", from_text("The midterm is on October 12.", "Midterm"))
    embedder = KnowledgeEmbedService(session_factory, source=source, vector_cache=toolkit.service.vector_cache)
    assert await embedder.run_once() == 2
    return str(user.id), toolkit, fake, source


@pytest.mark.asyncio
async def test_hybrid_search_finds_a_paraphrase_that_keywords_miss(session_factory):
    user_id, toolkit, fake, _source = await _setup(session_factory, "hybrid@example.com")
    result = await toolkit.execute("search", {"query": "how much does it cost"}, user_id)
    assert result["mode"] == "hybrid"
    assert result["results"][0]["citation"] == "Fees, part 1"
    assert ("query", "how much does it cost") in fake.texts

    keyword_only = KnowledgeToolkit(
        session_factory,
        service=toolkit.service,
        capability_refusal=Gate(off=("knowledge_semantic",)),
        embeddings=toolkit._embeddings,
    )
    calls = len(fake.texts)
    plain = await keyword_only.execute("search", {"query": "how much does it cost"}, user_id)
    assert plain["mode"] == "keyword" and plain["results"] == []
    assert len(fake.texts) == calls  # the switch off sends nothing


@pytest.mark.asyncio
async def test_a_failed_or_slow_query_embedding_falls_back_to_keywords(session_factory, monkeypatch):
    from services.knowledge import embeddings as embeddings_module

    user_id, toolkit, fake, _source = await _setup(session_factory, "fallback@example.com")
    fake.fail = True
    result = await toolkit.execute("search", {"query": "midterm"}, user_id)
    assert result["mode"] == "keyword" and result["results"][0]["citation"] == "Midterm, part 1"
    fake.fail = False
    fake.delay = 0.5
    monkeypatch.setattr(embeddings_module, "QUERY_EMBED_TIMEOUT_S", 0.05)
    slow = await toolkit.execute("search", {"query": "midterm"}, user_id)
    assert slow["mode"] == "keyword"


@pytest.mark.asyncio
async def test_vectors_of_another_model_are_ignored(session_factory):
    user_id, toolkit, fake, source = await _setup(session_factory, "model@example.com")
    source._config.GEMINI_EMBED_MODEL = "newer-embedder"
    result = await toolkit.execute("search", {"query": "how much does it cost"}, user_id)
    assert result["mode"] == "keyword" and result["results"] == []


@pytest.mark.asyncio
async def test_the_query_is_redacted_before_it_leaves(session_factory):
    user_id, toolkit, fake, _source = await _setup(session_factory, "redact-q@example.com")
    await toolkit.execute("search", {"query": "fee for jane.doe@example.com"}, user_id)
    sent = [t for kind, t in fake.texts if kind == "query"][-1]
    assert "jane.doe@example.com" not in sent and "[email]" in sent


def test_pure_python_scoring_equals_numpy():
    np = pytest.importorskip("numpy")
    assert np is not None
    rows = [
        VectorRow(n, f"d{n % 3}", "c", kb_vectors.unpack(kb_vectors.pack(kb_vectors.normalize([n, 1.0, 2.0 - n, 0.5]))))
        for n in range(20)
    ]
    query = kb_vectors.normalize([1.0, 2.0, 0.0, 1.0])
    pure = kb_vectors.best(query, rows, 10, use_numpy=False)
    fast = kb_vectors.best(query, rows, 10, use_numpy=True)
    assert [c for c, _ in pure] == [c for c, _ in fast]
    assert [s for _, s in pure] == pytest.approx([s for _, s in fast], abs=1e-9)


class _FakeMatrix:
    """What score_numpy uses of a numpy matrix: ``@`` with a vector."""

    def __init__(self, rows, calls):
        self.rows = [[float(x) for x in row] for row in rows]
        calls.append(("array", len(self.rows)))

    def __matmul__(self, vector):
        return [sum(a * b for a, b in zip(row, vector, strict=True)) for row in self.rows]


def _fake_numpy(calls):
    """A stand-in for numpy with only what score_numpy calls (numpy is not
    a dependency, so CI never installs it; faster-whisper brings it in)."""
    return SimpleNamespace(
        float64="float64",
        array=lambda rows, dtype=None: _FakeMatrix(rows, calls),
        asarray=lambda vector, dtype=None: [float(x) for x in vector],
    )


def test_the_numpy_path_scores_like_pure_python_without_numpy(monkeypatch):
    """score_numpy runs whenever numpy is importable (a voice-notes install
    brings it in): its length filter, product and pairing are checked here
    against pure Python through a stand-in module."""
    calls: list[Any] = []
    monkeypatch.setitem(sys.modules, "numpy", _fake_numpy(calls))
    rows = [
        VectorRow(n, f"d{n % 3}", "c", kb_vectors.unpack(kb_vectors.pack(kb_vectors.normalize([n, 1.0, 2.0 - n, 0.5]))))
        for n in range(20)
    ]
    # A vector of another length (an old model's size) is never scored.
    rows.append(VectorRow(99, "d9", "c", kb_vectors.unpack(kb_vectors.pack([1.0, 0.0]))))
    query = kb_vectors.normalize([1.0, 2.0, 0.0, 1.0])
    pure = kb_vectors.best(query, rows, 10, use_numpy=False)
    fast = kb_vectors.best(query, rows, 10, use_numpy=True)
    assert calls == [("array", 20)]
    assert [c for c, _ in fast] == [c for c, _ in pure] and 99 not in [c for c, _ in fast]
    # (Not pytest.approx: it asks sys.modules["numpy"] about its operands.)
    assert all(abs(f - p) < 1e-9 for (_, f), (_, p) in zip(fast, pure, strict=True))
    assert kb_vectors.score_numpy(query, rows[-1:]) == []
    # With numpy importable, best() takes the numpy path by itself.
    monkeypatch.setattr(kb_vectors, "numpy_available", lambda: True)
    assert kb_vectors.best(query, rows, 3) == fast[:3]
    assert calls[-1] == ("array", 20)


def test_packing_is_float32_little_endian_and_normalised():
    vector = kb_vectors.normalize([3.0, 4.0])
    assert vector == pytest.approx([0.6, 0.8])
    blob = kb_vectors.pack(vector)
    assert len(blob) == 8 and blob[:4] == bytes.fromhex("9a99193f")
    assert list(kb_vectors.unpack(blob)) == pytest.approx([0.6, 0.8])
    assert kb_vectors.normalize([0.0, 0.0]) == [0.0, 0.0]


def test_the_vector_cache_is_per_user_and_model_and_bounded():
    row = VectorRow(1, "d", "c", kb_vectors.unpack(kb_vectors.pack([1.0] * 256)))
    cache = VectorCache(max_bytes=3000)
    cache.put("u1", "m", [row])
    cache.put("u2", "m", [row])
    assert cache.get("u1", "m") == [row] and cache.get("u1", "other") is None
    cache.put("u3", "m", [row, row])  # over the budget: the oldest go
    assert cache.get("u2", "m") is None and cache.size_bytes <= 3000
    cache.invalidate("u3")
    assert cache.get("u3", "m") is None
