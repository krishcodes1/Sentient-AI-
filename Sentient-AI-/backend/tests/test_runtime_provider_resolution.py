"""Tests for lazy provider resolution: the runtime builds no LLM provider at
startup, resolves and caches one per (provider, model) only when a turn needs
it, keeps a lease alive until an in-flight turn finishes even across
invalidation, and returns the correct setup_url- or settings_url-pointing
sentence when no key is configured.

Why it exists: A fresh install has no key yet, and the owner adds one through
/setup or Settings while the server keeps running; guards against a stale
cached provider surviving a key change or a turn in flight losing its provider
mid-call.

Lazy provider resolution, leases, ``ProviderNotConfigured`` and the
``<permissions>`` block.

The runtime no longer builds its LLM provider at startup: a fresh install
has no key yet, and the owner adds one through /setup or Settings while
the server keeps running. Keys come from a settings source when a turn
needs them, providers are cached per (provider, model) until the owner
changes something (a turn in flight keeps its instance until it ends), and
a turn with no key fails with one sentence plus a pointer: setup_url when
the install is not set up (503), settings_url when only the user's own
provider choice lacks a key (409).
"""

from __future__ import annotations

import asyncio

import pytest

from core.config import settings
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import (
    LLMResponse,
    ProviderError,
    ProviderNotConfigured,
    ToolCall,
)
from services.agent.runtime import AgentRuntime, PromptGuard, Tool
from services.agent.tool_registry import RuntimePermissionAdapter
from tests.conftest import auth_headers, make_user

# The sentence travels without a URL: routes and channels carry the link in
# ``setup_url`` so a Telegram reply never shows a bare relative path.
SETUP_SENTENCE = "No AI provider is configured yet. Add an API key to start chatting."


class Source:
    def __init__(self, provider="gemini", model="gemini-2.5-flash", keys=None):
        self.provider, self.model, self.keys = provider, model, keys or {}
        self.calls = 0

    async def llm_defaults(self):
        return self.provider, self.model

    async def llm_api_key(self, provider):
        self.calls += 1
        return self.keys.get(provider)


class FakeProvider:
    supports_vision = False

    def __init__(self, api_key, model, responses=None):
        self.api_key, self.model = api_key, model
        self._responses = list(responses or [])
        self.calls = []
        self.closed = False

    async def complete(self, messages, tools=None):
        # A closed provider's HTTP client is gone; using it mid-turn is the
        # bug leases exist to prevent.
        assert not self.closed, "provider used after it was closed"
        self.calls.append(list(messages))
        if self._responses:
            return self._responses.pop(0)
        return LLMResponse(content="hi", tool_calls=[])

    async def stream(self, messages, tools=None):
        yield "hi"

    async def aclose(self):
        self.closed = True


def runtime(source, monkeypatch, **kwargs):
    import services.agent.runtime as rt

    monkeypatch.setattr(
        rt,
        "create_provider",
        lambda provider_name, model, api_key, base_url=None: FakeProvider(api_key, model),
    )
    return AgentRuntime(
        config=settings,
        approval_store=InMemoryApprovalStore(),
        settings_source=source,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# ProviderNotConfigured
# ---------------------------------------------------------------------------


def test_provider_not_configured_is_a_provider_error_that_reads_as_one_sentence():
    exc = ProviderNotConfigured("gemini", reason="not_set_up")
    # Every existing `except ProviderError` keeps catching it.
    assert isinstance(exc, ProviderError)
    assert exc.provider == "gemini" and exc.status_code is None
    # Shown verbatim by the web app and by Telegram, so no
    # "gemini provider error:" prefix — and no "/setup": the link travels
    # separately, in setup_url.
    assert str(exc) == SETUP_SENTENCE
    assert "/setup" not in str(exc)
    assert exc.reason == "not_set_up" and exc.code == "provider_not_configured"


def test_user_provider_unavailable_has_its_own_code():
    exc = ProviderNotConfigured(
        "openai", reason="user_provider_unavailable", detail="pick another"
    )
    assert str(exc) == "pick another"
    assert exc.code == "user_provider_unavailable"


def test_provider_not_configured_requires_a_reason():
    with pytest.raises(TypeError):
        ProviderNotConfigured("gemini")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runtime_constructs_without_any_key(monkeypatch):
    rt = runtime(Source(keys={}), monkeypatch)
    with pytest.raises(ProviderNotConfigured):
        await rt._resolve_provider(None, None)


@pytest.mark.asyncio
async def test_default_source_constructs_without_an_env_key(monkeypatch):
    """main.py builds the runtime with no source: a missing key used to make
    construction raise (and the whole agent API answer 503 forever); now the
    runtime exists and only the turn fails, with the setup sentence."""
    monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", None)
    rt = AgentRuntime(config=settings, approval_store=InMemoryApprovalStore())
    with pytest.raises(ProviderNotConfigured) as excinfo:
        await rt._resolve_provider(None, None)
    assert str(excinfo.value) == SETUP_SENTENCE


@pytest.mark.asyncio
async def test_default_source_reads_env_keys_and_ollama_needs_none(monkeypatch):
    from services.agent.runtime import _ConfigSettingsSource

    monkeypatch.setattr(settings, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(settings, "LLM_MODEL", " gemini-2.5-flash ")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", " g-key ")
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "   ")
    source = _ConfigSettingsSource(settings)
    assert await source.llm_defaults() == ("gemini", "gemini-2.5-flash")
    assert await source.llm_api_key("gemini") == "g-key"
    # Blank is the same as missing.
    assert await source.llm_api_key("openai") is None
    # "" means "no key needed" — distinct from None, "not configured".
    assert await source.llm_api_key("ollama") == ""
    assert await source.llm_api_key("no-such-provider") is None


@pytest.mark.asyncio
async def test_key_resolved_lazily_and_cached_until_invalidated(monkeypatch):
    src = Source(keys={"gemini": "k1"})
    rt = runtime(src, monkeypatch)
    p1 = await rt._resolve_provider(None, None)
    p2 = await rt._resolve_provider(None, None)
    assert p1 is p2 and p1.api_key == "k1" and src.calls == 1
    src.keys["gemini"] = "k2"
    rt.invalidate_providers()
    p3 = await rt._resolve_provider(None, None)
    assert p3.api_key == "k2"


@pytest.mark.asyncio
async def test_context_is_sized_for_the_model_each_turn_runs_on(monkeypatch):
    """Not config.LLM_MODEL: the install default and a user's own pick can
    have windows 15x apart, so each turn budgets for its resolved model."""
    from services.agent.context_manager import ContextManager, get_context_window

    seen: list = []
    real = ContextManager.prepare_context

    def spy(self, *args, **kwargs):
        seen.append(kwargs.get("model"))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(ContextManager, "prepare_context", spy)
    rt = runtime(
        Source(provider="deepseek", model="deepseek-chat", keys={"deepseek": "d", "gemini": "g"}),
        monkeypatch,
    )
    await rt.chat([{"role": "user", "content": "hello"}], [], "u1")
    await rt.chat(
        [{"role": "user", "content": "hello again"}],
        [],
        "u1",
        llm_provider="gemini",
        llm_model="gemini-2.5-flash",
    )
    assert seen == ["deepseek-chat", "gemini-2.5-flash"]
    assert settings.LLM_MODEL not in seen
    assert get_context_window(seen[0]) != get_context_window(seen[1])


@pytest.mark.asyncio
async def test_explicit_default_pair_and_none_share_one_instance(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    assert await rt._resolve_provider("gemini", "gemini-2.5-flash") is (
        await rt._resolve_provider(None, None)
    )


@pytest.mark.asyncio
async def test_invalidate_closes_every_cached_provider(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k", "openai": "o"}), monkeypatch)
    a = await rt._resolve_provider(None, None)
    b = await rt._resolve_provider("openai", "gpt-4o")
    rt.invalidate_providers()
    await asyncio.sleep(0)  # let the scheduled closes run
    assert a.closed and b.closed
    assert await rt._resolve_provider(None, None) is not a


@pytest.mark.asyncio
async def test_a_key_read_before_invalidation_is_never_cached(monkeypatch):
    """The key lookup is awaited. If the owner saves a new key while a turn
    is inside that await, the old key must not land in the cache — it would
    outlive the change until the next one."""
    release = asyncio.Event()

    class SlowSource(Source):
        async def llm_api_key(self, provider):
            value = self.keys.get(provider)
            self.calls += 1
            if self.calls == 1:
                await release.wait()
            return value

    src = SlowSource(keys={"gemini": "old"})
    rt = runtime(src, monkeypatch)
    turn = asyncio.create_task(rt._resolve_provider(None, None))
    await asyncio.sleep(0)
    src.keys["gemini"] = "new"
    rt.invalidate_providers()
    release.set()
    provider = await turn
    assert provider.api_key == "new"
    assert (await rt._resolve_provider(None, None)).api_key == "new"


@pytest.mark.asyncio
async def test_override_without_a_key_names_the_provider(monkeypatch):
    """The install is set up (the default has a key) but the user's Settings
    pick a provider this server has no key for: say which one."""
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    with pytest.raises(ProviderNotConfigured) as excinfo:
        await rt._resolve_provider("openai", "gpt-4o")
    message = str(excinfo.value)
    assert "openai" in message and "not configured" in message
    assert excinfo.value.reason == "user_provider_unavailable"


@pytest.mark.asyncio
async def test_default_provider_is_compared_case_insensitively(monkeypatch):
    """A source that reports its default as "Gemini" still means gemini: a
    user who picked that same provider is looking at an install that is not
    set up, not at a Settings choice of their own to change."""
    rt = runtime(Source(provider="Gemini", model="m", keys={"Gemini": "k"}), monkeypatch)
    with pytest.raises(ProviderNotConfigured) as excinfo:
        await rt._resolve_provider("gemini", "m")
    assert excinfo.value.reason == "not_set_up"


# ---------------------------------------------------------------------------
# A user with no provider of their own follows the install
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_user_provider_follows_the_source_default_and_ignores_the_model(
    monkeypatch,
):
    """NULL provider means "use this Crawler's default". A stray per-user
    model must not be paired with the install's provider: gpt-4o sent to
    Gemini is a failed turn."""
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    assert await rt._select_provider(None, "gpt-4o") == ("gemini", "gemini-2.5-flash")
    assert await rt._select_provider("", "gpt-4o") == ("gemini", "gemini-2.5-flash")
    response = await rt.chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        user_id="u1",
        llm_provider=None,
        llm_model="gpt-4o",
    )
    assert (response.provider, response.model) == ("gemini", "gemini-2.5-flash")


@pytest.mark.asyncio
async def test_response_names_the_pair_that_actually_ran(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k", "openai": "o"}), monkeypatch)
    response = await rt.chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        user_id="u1",
        llm_provider="OpenAI",
        llm_model="gpt-4o",
    )
    assert (response.provider, response.model) == ("openai", "gpt-4o")


def test_use_provider_seeds_the_runtimes_own_source_default():
    """The test helper honours a custom source instead of assuming the
    environment's pair."""
    from tests.conftest import use_provider

    rt = AgentRuntime(
        config=settings,
        approval_store=InMemoryApprovalStore(),
        settings_source=Source(provider=" Gemini ", model="m"),
    )
    marker = FakeProvider("k", "m")
    use_provider(rt, marker)
    assert rt._provider_cache[("gemini", "m")] is marker
    use_provider(rt, marker, pair=("openai", "gpt-4o"))
    assert rt._provider_cache[("openai", "gpt-4o")] is marker


@pytest.mark.asyncio
async def test_use_provider_refuses_a_source_it_cannot_read_synchronously():
    from tests.conftest import use_provider

    class SuspendingSource(Source):
        async def llm_defaults(self):
            await asyncio.sleep(0)
            return self.provider, self.model

    rt = AgentRuntime(
        config=settings,
        approval_store=InMemoryApprovalStore(),
        settings_source=SuspendingSource(),
    )
    with pytest.raises(RuntimeError, match="pair="):
        use_provider(rt, FakeProvider("k", "m"))


# ---------------------------------------------------------------------------
# Key re-reads are bounded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_rereads_stop_after_three_attempts(monkeypatch):
    """Settings that change during every read must not spin the turn
    forever. After three reads the turn runs on the freshest key, and that
    provider is not cached: a later change may already have superseded it."""
    holder = {}

    class ChurningSource(Source):
        async def llm_api_key(self, provider):
            self.calls += 1
            holder["rt"].invalidate_providers()
            return self.keys.get(provider)

    src = ChurningSource(keys={"gemini": "k"})
    rt = holder["rt"] = runtime(src, monkeypatch)
    provider = await rt._resolve_provider(None, None)
    assert provider.api_key == "k"
    assert src.calls == 3
    assert len(rt._provider_cache) == 0


# ---------------------------------------------------------------------------
# Leases: a provider in use is never closed under a turn
# ---------------------------------------------------------------------------


class _InvalidatingExecutor:
    """Runs between the two model rounds of a turn, which is exactly when an
    owner saving a new key would land."""

    def __init__(self, runtime_holder):
        self._holder = runtime_holder
        self.calls = 0

    async def execute(self, tool_name, arguments, user_id, approved=False):
        self.calls += 1
        self._holder["rt"].invalidate_providers()
        await asyncio.sleep(0)  # give a (wrongly) scheduled close its chance
        return {"ok": True}


def _two_round_responses():
    return [
        LLMResponse(
            content="",
            tool_calls=[ToolCall(id="t1", name="reminders.now", arguments={})],
        ),
        LLMResponse(content="It is noon."),
    ]


@pytest.mark.asyncio
async def test_invalidation_mid_turn_waits_for_the_turn_to_finish(monkeypatch):
    import services.agent.runtime as rt_module

    built = []

    def factory(provider_name, model, api_key, base_url=None):
        provider = FakeProvider(
            api_key, model, responses=_two_round_responses() if not built else None
        )
        built.append(provider)
        return provider

    holder = {}
    executor = _InvalidatingExecutor(holder)
    rt = holder["rt"] = AgentRuntime(
        config=settings,
        approval_store=InMemoryApprovalStore(),
        prompt_guard=PromptGuard(),
        tool_executor=executor,
        settings_source=Source(keys={"gemini": "k"}),
    )
    monkeypatch.setattr(rt_module, "create_provider", factory)
    tool = Tool(
        name="reminders.now",
        description="What time is it",
        parameters={"type": "object", "properties": {}},
        connector_type="reminders",
    )

    response = await rt.chat(
        messages=[{"role": "user", "content": "time?"}], tools=[tool], user_id="u1"
    )

    first = built[0]
    assert executor.calls == 1
    assert response.content == "It is noon."
    assert len(first.calls) == 2  # both rounds ran on the same, open provider
    await asyncio.sleep(0)
    assert first.closed, "the retired provider is closed once its turn ends"
    assert rt._retired == {}

    await rt.chat(messages=[{"role": "user", "content": "again"}], tools=[], user_id="u1")
    assert len(built) == 2 and built[1] is not first
    assert built[1].calls and not built[1].closed


@pytest.mark.asyncio
async def test_eviction_retires_a_leased_provider_until_its_turn_ends(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k", "openai": "o"}), monkeypatch)
    rt._PROVIDER_CACHE_MAX = 1
    async with rt._lease("gemini", "gemini-2.5-flash") as leased:
        await rt._resolve_provider("openai", "gpt-4o")  # evicts the leased one
        await asyncio.sleep(0)
        assert not leased.closed
        assert id(leased) in rt._retired
    await asyncio.sleep(0)
    assert leased.closed and rt._retired == {}


@pytest.mark.asyncio
async def test_two_turns_share_a_lease_and_the_last_one_out_closes(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    async with rt._lease("gemini", "gemini-2.5-flash") as first:
        async with rt._lease("gemini", "gemini-2.5-flash") as second:
            assert first is second
            rt.invalidate_providers()
        await asyncio.sleep(0)
        assert not first.closed
    await asyncio.sleep(0)
    assert first.closed


@pytest.mark.asyncio
async def test_aclose_closes_cached_and_retired_providers(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k", "openai": "o"}), monkeypatch)
    cached = await rt._resolve_provider("openai", "gpt-4o")
    async with rt._lease("gemini", "gemini-2.5-flash") as leased:
        await rt.aclose()
        assert leased.closed and cached.closed
    assert len(rt._provider_cache) == 0 and rt._retired == {}


@pytest.mark.asyncio
async def test_override_on_an_install_with_no_key_at_all_gets_the_setup_sentence(
    monkeypatch,
):
    """Account rows carry the provider the server had when they were made,
    so on a fresh install the "override" is usually just that stale value.
    With no key anywhere, the answer is still "finish setup"."""
    rt = runtime(Source(provider="gemini", keys={}), monkeypatch)
    with pytest.raises(ProviderNotConfigured) as excinfo:
        await rt._resolve_provider("anthropic", "claude-sonnet-5")
    assert str(excinfo.value) == SETUP_SENTENCE


@pytest.mark.asyncio
async def test_unknown_or_uninstalled_provider_is_still_a_provider_error(monkeypatch):
    import services.agent.runtime as rt_module

    def boom(**_kwargs):
        raise ImportError("anthropic SDK not installed")

    rt = runtime(Source(provider="anthropic", model="m", keys={"anthropic": "k"}), monkeypatch)
    monkeypatch.setattr(rt_module, "create_provider", boom)
    with pytest.raises(ProviderError) as excinfo:
        await rt._resolve_provider(None, None)
    assert not isinstance(excinfo.value, ProviderNotConfigured)
    assert "anthropic" in str(excinfo.value)


# ---------------------------------------------------------------------------
# chat / stream_chat
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chat_without_a_key_raises_before_any_provider_call(monkeypatch):
    rt = runtime(Source(keys={}), monkeypatch)
    with pytest.raises(ProviderNotConfigured):
        await rt.chat(
            messages=[{"role": "user", "content": "hi"}], tools=[], user_id="u1"
        )


@pytest.mark.asyncio
async def test_stream_chat_marks_a_missing_key_on_its_error_event(monkeypatch):
    rt = runtime(Source(keys={}), monkeypatch)
    events = [
        e
        async for e in rt.stream_chat(
            messages=[{"role": "user", "content": "hi"}], tools=[], user_id="u1"
        )
    ]
    errors = [e for e in events if e["type"] == "error"]
    assert errors == [
        {
            "type": "error",
            "data": {"reason": SETUP_SENTENCE, "code": "provider_not_configured"},
        }
    ]
    assert events[-1] == {"type": "done", "data": {}}


@pytest.mark.asyncio
async def test_stream_chat_marks_an_unavailable_user_provider(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    events = [
        e
        async for e in rt.stream_chat(
            messages=[{"role": "user", "content": "hi"}],
            tools=[],
            user_id="u1",
            llm_provider="openai",
            llm_model="gpt-4o",
        )
    ]
    [error] = [e for e in events if e["type"] == "error"]
    assert error["data"]["code"] == "user_provider_unavailable"
    assert "openai" in error["data"]["reason"]


@pytest.mark.asyncio
async def test_stream_done_frame_names_the_pair_that_ran(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    rt._CONTENT_CHUNK_DELAY = 0
    events = [
        e
        async for e in rt.stream_chat(
            messages=[{"role": "user", "content": "hi"}], tools=[], user_id="u1"
        )
    ]
    done = events[-1]["data"]
    assert (done["provider"], done["model"]) == ("gemini", "gemini-2.5-flash")


def test_permissions_text_is_folded_into_system_prompt():
    msgs = AgentRuntime._with_system_prompt(
        [{"role": "user", "content": "hi"}], None, "<permissions>\n- X: on\n</permissions>"
    )
    assert msgs[0]["role"] == "system" and "<permissions>" in msgs[0]["content"]
    assert msgs[0]["content"].index("<today>") < msgs[0]["content"].index("<permissions>")


def test_permissions_sit_between_today_and_memory():
    content = AgentRuntime._with_system_prompt(
        [{"role": "user", "content": "hi"}],
        "<user_memory>\n- likes tea\n</user_memory>",
        "<permissions>\n- X: on\n</permissions>",
    )[0]["content"]
    assert (
        content.index("<today>")
        < content.index("<permissions>")
        < content.index("<user_memory>")
    )


def test_no_permissions_text_leaves_the_prompt_unchanged():
    base = [{"role": "user", "content": "hi"}]
    assert AgentRuntime._with_system_prompt(base, None, None) == (
        AgentRuntime._with_system_prompt(base, None)
    )


@pytest.mark.asyncio
async def test_chat_sends_the_permissions_block_to_the_provider(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    await rt.chat(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        user_id="u1",
        permissions_text="<permissions>\n- See my screen: off\n</permissions>",
        memory_block="<user_memory>\n- likes tea\n</user_memory>",
    )
    provider = await rt._resolve_provider(None, None)
    system = provider.calls[0][0]
    assert system["role"] == "system"
    assert "- See my screen: off" in system["content"]
    assert system["content"].index("<permissions>") < system["content"].index("<user_memory>")


@pytest.mark.asyncio
async def test_stream_chat_forwards_permissions_text(monkeypatch):
    rt = runtime(Source(keys={"gemini": "k"}), monkeypatch)
    rt._CONTENT_CHUNK_DELAY = 0
    [
        _
        async for _ in rt.stream_chat(
            messages=[{"role": "user", "content": "hi"}],
            tools=[],
            user_id="u1",
            permissions_text="<permissions>\n- Browse the web: on\n</permissions>",
        )
    ]
    provider = await rt._resolve_provider(None, None)
    assert "- Browse the web: on" in provider.calls[0][0]["content"]


class _ScreenshotExecutor:
    async def execute(self, tool_name, arguments, user_id, approved=False):
        return {"ok": True, "url": "https://example.com", "image": "data:image/png;base64,AAAA"}


async def _follow_up_after_screenshot(monkeypatch, default_provider, vision):
    """Run one screenshot round with ``default_provider`` as the source's
    default, on a provider whose ``supports_vision`` is ``vision``, and
    return the follow-up request the model received."""
    import services.agent.runtime as rt_module

    scripted = FakeProvider(
        "k",
        "m",
        responses=[
            LLMResponse(
                content="",
                tool_calls=[ToolCall(id="s1", name="web.screenshot", arguments={"url": "https://example.com"})],
            ),
            LLMResponse(content="I see a page."),
        ],
    )
    scripted.supports_vision = vision
    monkeypatch.setattr(rt_module, "create_provider", lambda **_kwargs: scripted)
    rt = AgentRuntime(
        config=settings,
        approval_store=InMemoryApprovalStore(),
        prompt_guard=PromptGuard(),
        tool_executor=_ScreenshotExecutor(),
        settings_source=Source(provider=default_provider, model="m", keys={default_provider: "k"}),
    )
    await rt.chat(
        messages=[{"role": "user", "content": "screenshot example.com"}],
        tools=[
            Tool(
                name="web.screenshot",
                description="Screenshot a page",
                parameters={"type": "object", "properties": {"url": {"type": "string"}}},
                connector_type="web",
            )
        ],
        user_id="u1",
    )
    return scripted.calls[1][-1]


@pytest.mark.asyncio
async def test_screenshot_image_follows_the_resolved_vision_provider(monkeypatch):
    """Whether the model is shown the screenshot depends on the provider
    instance this turn resolved to (its ``supports_vision``), not on the
    process environment or on a hardcoded list of names."""
    follow_up = await _follow_up_after_screenshot(monkeypatch, "gemini", True)
    assert isinstance(follow_up["content"], list)
    assert any(block.get("type") == "image" for block in follow_up["content"])


@pytest.mark.asyncio
async def test_screenshot_image_is_withheld_from_a_non_vision_provider(monkeypatch):
    follow_up = await _follow_up_after_screenshot(monkeypatch, "groq", False)
    assert isinstance(follow_up["content"], str)


@pytest.mark.asyncio
async def test_screenshot_image_reaches_a_vision_provider_outside_the_old_list(
    monkeypatch,
):
    """Mistral and Grok accept images too; a list of names had silently
    withheld screenshots from them."""
    follow_up = await _follow_up_after_screenshot(monkeypatch, "mistral", True)
    assert isinstance(follow_up["content"], list)


def test_every_provider_class_declares_vision_support():
    from services.agent.providers import PROVIDER_REGISTRY, LLMProvider

    assert LLMProvider.supports_vision is False
    for name, cls in PROVIDER_REGISTRY.items():
        declared = [
            klass for klass in cls.__mro__
            if klass is not LLMProvider and "supports_vision" in vars(klass)
        ]
        assert declared, f"{name} does not declare supports_vision"
        assert isinstance(cls.supports_vision, bool)


# ---------------------------------------------------------------------------
# Routes and channels: not set up -> 503 + setup_url; the user's own
# provider unavailable -> 409 + settings_url
# ---------------------------------------------------------------------------


def _unconfigured_runtime():
    return AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        approval_store=InMemoryApprovalStore(),
        settings_source=Source(keys={}),
    )


def _gemini_only_runtime():
    return AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        approval_store=InMemoryApprovalStore(),
        prompt_guard=PromptGuard(),
        settings_source=Source(keys={"gemini": "k"}),
    )


def _fake_create_provider(monkeypatch):
    import services.agent.runtime as rt_module

    monkeypatch.setattr(
        rt_module,
        "create_provider",
        lambda provider_name, model, api_key, base_url=None: FakeProvider(api_key, model),
    )


async def _pick_provider(session_factory, user_id, provider, model):
    from sqlalchemy import update

    from models.user import User

    async with session_factory() as session:
        await session.execute(
            update(User)
            .where(User.id == user_id)
            .values(llm_provider=provider, llm_model=model)
        )
        await session.commit()


def _frames(text):
    import json

    frames = []
    for block in text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "event" in lines:
            frames.append((lines["event"], json.loads(lines["data"])))
    return frames


@pytest.mark.asyncio
async def test_send_message_without_a_key_is_503_pointing_at_setup(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = _unconfigured_runtime
    try:
        _, token = await make_user(session_factory, "nokey-send@example.com")
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        response = await client.post(
            f"/api/agent/conversations/{created.json()['id']}/messages",
            headers=auth_headers(token),
            json={"content": "hello"},
        )
        assert response.status_code == 503
        assert response.json()["detail"] == {
            "message": SETUP_SENTENCE,
            "code": "provider_not_configured",
            "setup_url": "/setup",
        }
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_send_message_with_an_unavailable_user_provider_is_409_pointing_at_settings(
    client, session_factory, monkeypatch
):
    """The install works; only this user's own choice has no key. That is
    not "service unavailable" and not something /setup can fix: 409 and a
    pointer at the user's Settings."""
    from api.routes import agent as agent_routes
    from main import app

    _fake_create_provider(monkeypatch)
    app.dependency_overrides[agent_routes.get_runtime] = _gemini_only_runtime
    try:
        user, token = await make_user(session_factory, "own-pick@example.com")
        await _pick_provider(session_factory, user.id, "openai", "gpt-4o")
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        response = await client.post(
            f"/api/agent/conversations/{created.json()['id']}/messages",
            headers=auth_headers(token),
            json={"content": "hello"},
        )
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert detail["code"] == "user_provider_unavailable"
        assert detail["settings_url"] == "/settings"
        assert "setup_url" not in detail
        assert "openai" in detail["message"]
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_user_following_the_install_default_chats_on_it(
    client, session_factory, monkeypatch
):
    """A NULL provider on the account runs on whatever the install's default
    is, and the stored message names that pair — not the account row."""
    from sqlalchemy import select

    from api.routes import agent as agent_routes
    from main import app
    from models.conversation import Message, MessageRole

    _fake_create_provider(monkeypatch)
    shared = _gemini_only_runtime()
    app.dependency_overrides[agent_routes.get_runtime] = lambda: shared
    try:
        user, token = await make_user(session_factory, "follower@example.com")
        assert user.llm_provider is None and user.llm_model is None
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        response = await client.post(
            f"/api/agent/conversations/{created.json()['id']}/messages",
            headers=auth_headers(token),
            json={"content": "hello"},
        )
        assert response.status_code == 201, response.text
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)

    async with session_factory() as session:
        row = (
            await session.execute(
                select(Message).where(Message.role == MessageRole.assistant)
            )
        ).scalar_one()
    assert (row.llm_provider, row.llm_model) == ("gemini", "gemini-2.5-flash")


@pytest.mark.asyncio
async def test_stream_without_a_key_sends_an_error_frame_with_setup_url(
    client, session_factory
):
    from api.routes import agent as agent_routes
    from main import app

    app.dependency_overrides[agent_routes.get_runtime] = _unconfigured_runtime
    try:
        _, token = await make_user(session_factory, "nokey-stream@example.com")
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        response = await client.post(
            f"/api/agent/conversations/{created.json()['id']}/messages/stream",
            headers=auth_headers(token),
            json={"content": "hello"},
        )
        assert response.status_code == 200
        frames = _frames(response.text)
        errors = [data for name, data in frames if name == "error"]
        assert errors == [
            {
                "reason": SETUP_SENTENCE,
                "code": "provider_not_configured",
                "setup_url": "/setup",
            }
        ]
        # A failed turn is not persisted as an empty assistant bubble.
        assert ("saved", {"assistant_message": None}) in frames
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_stream_with_an_unavailable_user_provider_points_at_settings(
    client, session_factory, monkeypatch
):
    from api.routes import agent as agent_routes
    from main import app

    _fake_create_provider(monkeypatch)
    app.dependency_overrides[agent_routes.get_runtime] = _gemini_only_runtime
    try:
        user, token = await make_user(session_factory, "own-pick-stream@example.com")
        await _pick_provider(session_factory, user.id, "openai", "gpt-4o")
        created = await client.post(
            "/api/agent/conversations", headers=auth_headers(token), json={}
        )
        response = await client.post(
            f"/api/agent/conversations/{created.json()['id']}/messages/stream",
            headers=auth_headers(token),
            json={"content": "hello"},
        )
        [error] = [data for name, data in _frames(response.text) if name == "error"]
        assert error["code"] == "user_provider_unavailable"
        assert error["settings_url"] == "/settings"
        assert "setup_url" not in error
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_channel_chat_without_a_key_replies_with_the_setup_sentence(session_factory):
    from api.routes.agent import build_chat_applier
    from main import app

    user, _ = await make_user(session_factory, "nokey-telegram@example.com")
    saved_runtime = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = _unconfigured_runtime()
    try:
        chat = build_chat_applier(app, session_factory=session_factory)
        outcome = await chat(str(user.id), "hello")
    finally:
        app.state.agent_runtime = saved_runtime
    # Telegram sends outcome["error"] verbatim, so it must be the sentence.
    assert outcome["error"] == SETUP_SENTENCE
    assert outcome["code"] == "provider_not_configured"
    assert outcome["setup_url"] == "/setup"
    assert outcome["conversation_id"]


@pytest.mark.asyncio
async def test_channel_chat_with_an_unavailable_user_provider_points_at_settings(
    session_factory, monkeypatch
):
    from api.routes.agent import build_chat_applier
    from main import app

    _fake_create_provider(monkeypatch)
    user, _ = await make_user(session_factory, "own-pick-telegram@example.com")
    await _pick_provider(session_factory, user.id, "openai", "gpt-4o")
    saved_runtime = getattr(app.state, "agent_runtime", None)
    app.state.agent_runtime = _gemini_only_runtime()
    try:
        outcome = await build_chat_applier(app, session_factory=session_factory)(
            str(user.id), "hello"
        )
    finally:
        app.state.agent_runtime = saved_runtime
    assert outcome["code"] == "user_provider_unavailable"
    assert outcome["settings_url"] == "/settings"
    assert "setup_url" not in outcome
    assert "openai" in outcome["error"]


# ---------------------------------------------------------------------------
# After setup: the install lost its key. /setup redirects away once setup is
# complete, so every surface points at Settings instead (code
# provider_unavailable), still 503.
# ---------------------------------------------------------------------------

_MISSING = object()


async def _completed_installation(session_factory, owner_id):
    from services.installation import InstallationService

    installation = InstallationService(session_factory)
    await installation.mark_setup_complete(allow_registration=False, actor_id=owner_id)
    return installation


class _Wired:
    """Put a runtime and an installation on app.state for one test."""

    def __init__(self, runtime, installation):
        from main import app

        self.app = app
        self.values = {"agent_runtime": runtime, "installation": installation}
        self.saved: dict = {}

    def __enter__(self):
        for name, value in self.values.items():
            self.saved[name] = getattr(self.app.state, name, _MISSING)
            setattr(self.app.state, name, value)
        return self

    def __exit__(self, *exc):
        for name, value in self.saved.items():
            if value is _MISSING:
                if hasattr(self.app.state, name):
                    delattr(self.app.state, name)
            else:
                setattr(self.app.state, name, value)


@pytest.mark.asyncio
async def test_send_message_after_setup_without_a_key_points_at_settings(
    client, session_factory
):
    from api.routes import agent as agent_routes
    from main import app

    user, token = await make_user(session_factory, "after-setup-send@example.com")
    installation = await _completed_installation(session_factory, user.id)
    runtime = _unconfigured_runtime()
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        with _Wired(runtime, installation):
            created = await client.post(
                "/api/agent/conversations", headers=auth_headers(token), json={}
            )
            response = await client.post(
                f"/api/agent/conversations/{created.json()['id']}/messages",
                headers=auth_headers(token),
                json={"content": "hello"},
            )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "message": SETUP_SENTENCE,
        "code": "provider_unavailable",
        "settings_url": "/settings",
    }


@pytest.mark.asyncio
async def test_stream_after_setup_without_a_key_points_at_settings(client, session_factory):
    from api.routes import agent as agent_routes
    from main import app

    user, token = await make_user(session_factory, "after-setup-stream@example.com")
    installation = await _completed_installation(session_factory, user.id)
    runtime = _unconfigured_runtime()
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        with _Wired(runtime, installation):
            created = await client.post(
                "/api/agent/conversations", headers=auth_headers(token), json={}
            )
            response = await client.post(
                f"/api/agent/conversations/{created.json()['id']}/messages/stream",
                headers=auth_headers(token),
                json={"content": "hello"},
            )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    errors = [data for name, data in _frames(response.text) if name == "error"]
    assert errors == [
        {
            "reason": SETUP_SENTENCE,
            "code": "provider_unavailable",
            "settings_url": "/settings",
        }
    ]


@pytest.mark.asyncio
async def test_channel_chat_after_setup_without_a_key_points_at_settings(session_factory):
    from api.routes.agent import build_chat_applier
    from main import app

    user, _ = await make_user(session_factory, "after-setup-telegram@example.com")
    installation = await _completed_installation(session_factory, user.id)
    with _Wired(_unconfigured_runtime(), installation):
        outcome = await build_chat_applier(app, session_factory=session_factory)(
            str(user.id), "hello"
        )
    assert outcome["error"] == SETUP_SENTENCE
    assert outcome["code"] == "provider_unavailable"
    assert outcome["settings_url"] == "/settings"
    assert "setup_url" not in outcome


@pytest.mark.asyncio
async def test_an_unreadable_setup_state_keeps_the_setup_pointer(client, session_factory):
    """If the installation cannot say whether setup is done, the original
    pointer stands: a broken probe must not turn a 503 into a 500."""
    from api.routes import agent as agent_routes
    from main import app

    class BrokenInstallation:
        async def setup_completed(self):
            raise RuntimeError("database unavailable")

        async def report(self):
            from services import capabilities as registry

            return registry.report(registry.default_switches(), registry.default_context())

    user, token = await make_user(session_factory, "after-setup-broken@example.com")
    runtime = _unconfigured_runtime()
    app.dependency_overrides[agent_routes.get_runtime] = lambda: runtime
    try:
        with _Wired(runtime, BrokenInstallation()):
            created = await client.post(
                "/api/agent/conversations", headers=auth_headers(token), json={}
            )
            response = await client.post(
                f"/api/agent/conversations/{created.json()['id']}/messages",
                headers=auth_headers(token),
                json={"content": "hello"},
            )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "provider_not_configured"
    assert response.json()["detail"]["setup_url"] == "/setup"
