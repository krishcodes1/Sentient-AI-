"""Lazy provider resolution, ``ProviderNotConfigured`` and the
``<permissions>`` block.

The runtime no longer builds its LLM provider at startup: a fresh install
has no key yet, and the owner adds one through /setup or Settings while
the server keeps running. Keys come from a settings source when a turn
needs them, providers are cached per (provider, model) until the owner
changes something, and a turn with no key fails with one sentence that
points at /setup rather than a stack of provider jargon.
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

SETUP_SENTENCE = (
    "No AI provider is configured yet. Finish setup at /setup or add a key "
    "in Settings."
)


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
    def __init__(self, api_key, model, responses=None):
        self.api_key, self.model = api_key, model
        self._responses = list(responses or [])
        self.calls = []
        self.closed = False

    async def complete(self, messages, tools=None):
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
    exc = ProviderNotConfigured("gemini")
    # Every existing `except ProviderError` keeps catching it.
    assert isinstance(exc, ProviderError)
    assert exc.provider == "gemini" and exc.status_code is None
    # Shown verbatim by the web app and by Telegram, so no
    # "gemini provider error:" prefix.
    assert str(exc) == SETUP_SENTENCE


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


async def _follow_up_after_screenshot(monkeypatch, default_provider):
    """Run one screenshot round with ``default_provider`` as the source's
    default and return the follow-up request the model received."""
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
    the SOURCE resolved for this turn, not on the process environment."""
    follow_up = await _follow_up_after_screenshot(monkeypatch, "gemini")
    assert isinstance(follow_up["content"], list)
    assert any(block.get("type") == "image" for block in follow_up["content"])


@pytest.mark.asyncio
async def test_screenshot_image_is_withheld_from_a_non_vision_provider(monkeypatch):
    follow_up = await _follow_up_after_screenshot(monkeypatch, "groq")
    assert isinstance(follow_up["content"], str)


# ---------------------------------------------------------------------------
# Routes and channels: ProviderNotConfigured -> 503 + /setup
# ---------------------------------------------------------------------------


def _unconfigured_runtime():
    return AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        approval_store=InMemoryApprovalStore(),
        settings_source=Source(keys={}),
    )


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
            "setup_url": "/setup",
        }
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)


@pytest.mark.asyncio
async def test_stream_without_a_key_sends_an_error_frame_with_setup_url(
    client, session_factory
):
    import json

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
        frames = []
        for block in response.text.strip().split("\n\n"):
            lines = dict(
                line.split(": ", 1) for line in block.splitlines() if ": " in line
            )
            if "event" in lines:
                frames.append((lines["event"], json.loads(lines["data"])))
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
