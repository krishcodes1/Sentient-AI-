"""Tests for services/agent/turn_context.py and how the runtime binds it: the
turn's (provider, model) is bound only while a turn runs (on the approval
resume path too, and undone when the turn raises), the video reader is the
turn's own Gemini provider's and never another's, a nested call's usage lands
in the turn's usage and cost, and an unattended run's budget counts it.

Why it exists: video.transcript must read YouTube with the turn's own
provider only and bill the turn for it, and a binding that outlived its turn
would hand a later caller a stale provider. Fake providers and executors; no
network.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest

from core.config import settings
from services.agent import turn_context
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime, Tool, TurnUsage
from services.agent.tool_registry import RuntimePermissionAdapter, build_tools
from tests.conftest import auth_headers, make_user, use_provider


class Source:
    def __init__(self, provider: str = "gemini", model: str = "gemini-3.5-flash-lite") -> None:
        self.pair = (provider, model)

    async def llm_defaults(self) -> tuple[str, str]:
        return self.pair

    async def llm_api_key(self, provider: str) -> str:
        return "test-key"


class Scripted:
    """A provider answering from a script; ``read_video_url`` makes it look
    like Gemini's."""

    supports_vision = False

    def __init__(self, responses: list[LLMResponse], *, reader: bool = True) -> None:
        self.responses = list(responses)
        if reader:
            self.read_video_url = self._read

    async def _read(self, **kwargs: Any) -> LLMResponse:
        return LLMResponse(content="{}")

    async def complete(self, messages, tools=None, **kwargs):
        return self.responses.pop(0) if self.responses else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"

    async def aclose(self) -> None:
        return None


class Recording:
    """An executor that records the TurnModel each call sees, and records a
    nested call's usage through it like video.transcript does."""

    def __init__(self, usage: Optional[dict[str, int]] = None) -> None:
        self.seen: list[Optional[turn_context.TurnModel]] = []
        self.usage = usage

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        model = turn_context.current()
        self.seen.append(model)
        if model is not None and self.usage:
            model.record_usage(self.usage)
        return {"ok": True, "passages": []}


def video_tool() -> list[Tool]:
    return [t for t in build_tools([]) if t.name == "video.transcript"]


def call(name: str = "video.transcript") -> LLMResponse:
    return LLMResponse(
        content="",
        tool_calls=[ToolCall(id="c1", name=name, arguments={"url": "https://youtu.be/dQw4w9WgXcQ"})],
        usage={"input_tokens": 10, "output_tokens": 5},
    )


def runtime(monkeypatch, provider: Scripted, executor: Recording, source: Source | None = None) -> AgentRuntime:
    import services.agent.runtime as rt

    monkeypatch.setattr(rt, "create_provider", lambda **_kwargs: provider)
    return AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor,
        approval_store=InMemoryApprovalStore(),
        settings_source=source or Source(),
    )


def test_nothing_is_bound_outside_a_turn():
    assert turn_context.current() is None


def test_bound_and_scope_restore_the_previous_binding():
    first = turn_context.TurnModel("gemini", "m", None, lambda u: None)
    second = turn_context.TurnModel("openai", "m", None, lambda u: None)
    with turn_context.bound(first):
        with turn_context.scope():
            turn_context.bind(second)
            assert turn_context.current() is second
        assert turn_context.current() is first
    assert turn_context.current() is None


def test_the_meter_adds_usage_and_cost():
    meter, usage = turn_context.UsageMeter(), {"input_tokens": 1}
    meter.add(usage, {"input_tokens": 5, "output_tokens": 2, "flag": True, "x": "y"}, 0.25)
    assert usage == {"input_tokens": 6, "output_tokens": 2} and meter.usd == 0.25
    left = meter.left_of(1.0)
    assert left is not None and left() == 0.75 and meter.left_of(None) is None


@pytest.mark.asyncio
async def test_a_turn_binds_its_own_gemini_reader_and_unbinds_after(monkeypatch):
    provider = Scripted([call(), LLMResponse(content="Summary.")])
    executor = Recording()
    agent = runtime(monkeypatch, provider, executor)
    response = await agent.chat(
        messages=[{"role": "user", "content": "summarise"}], tools=video_tool(), user_id="u1"
    )
    assert response.content == "Summary."
    [model] = executor.seen
    assert model is not None and (model.provider, model.model) == ("gemini", "gemini-3.5-flash-lite")
    assert model.read_video_url == provider.read_video_url
    assert model.usd_left is None
    assert turn_context.current() is None


@pytest.mark.asyncio
async def test_another_provider_gets_no_reader_even_with_the_method(monkeypatch):
    provider = Scripted([call(), LLMResponse(content="ok")])
    executor = Recording()
    agent = runtime(monkeypatch, provider, executor, Source("openai", "gpt-4o"))
    await agent.chat(messages=[{"role": "user", "content": "x"}], tools=video_tool(), user_id="u1")
    [model] = executor.seen
    assert model is not None and model.provider == "openai" and model.read_video_url is None


@pytest.mark.asyncio
async def test_recorded_usage_lands_in_the_turn(monkeypatch):
    provider = Scripted([call(), LLMResponse(content="ok", usage={"input_tokens": 1, "output_tokens": 1})])
    executor = Recording(usage={"input_tokens": 50000, "output_tokens": 800})
    agent = runtime(monkeypatch, provider, executor)
    sink = TurnUsage()
    response = await agent.chat(
        messages=[{"role": "user", "content": "x"}], tools=video_tool(), user_id="u1", usage_sink=sink
    )
    assert sink.usage["input_tokens"] == 10 + 50000 + 1
    assert sink.usage["output_tokens"] == 5 + 800 + 1
    assert response.usage is sink.usage


@pytest.mark.asyncio
async def test_an_unattended_runs_budget_counts_the_nested_call(monkeypatch):
    from services.agent.unattended import BUDGET_STOP_REPLY, UnattendedRun

    provider = Scripted([call(), LLMResponse(content="should not be reached")])
    # A read far over the run's budget (millions of tokens at list price).
    executor = Recording(usage={"input_tokens": 5_000_000, "output_tokens": 0})
    agent = runtime(monkeypatch, provider, executor)
    run = UnattendedRun(label="Weekly", origin="schedule:1", reads=frozenset({"video.transcript"}), max_usd=0.05)
    response = await agent.chat(
        messages=[{"role": "user", "content": "summarise the new episode"}],
        tools=video_tool(),
        user_id="u1",
        unattended=run,
    )
    [model] = executor.seen
    assert model is not None and model.usd_left is not None
    assert response.unattended_stop == "budget" and response.content == BUDGET_STOP_REPLY


@pytest.mark.asyncio
async def test_a_turn_that_raises_leaves_nothing_bound(monkeypatch):
    class Exploding(Scripted):
        async def complete(self, messages, tools=None, **kwargs):
            if not self.responses:
                raise RuntimeError("provider is down")
            return self.responses.pop(0)

    provider = Exploding([call()])
    executor = Recording()
    agent = runtime(monkeypatch, provider, executor)
    with pytest.raises(RuntimeError):
        await agent.chat(messages=[{"role": "user", "content": "x"}], tools=video_tool(), user_id="u1")
    assert executor.seen and executor.seen[0] is not None
    assert turn_context.current() is None


@pytest.mark.asyncio
async def test_the_resumed_turn_after_an_approval_is_bound_and_the_approved_call_is_not(
    client, session_factory
):
    from api.routes import agent as agent_routes
    from main import app
    from services.agent.approvals import DbApprovalStore

    provider = Scripted([call(), LLMResponse(content="Here is the summary.")], reader=True)
    executor = Recording()
    agent = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor,
        approval_store=DbApprovalStore(session_factory=session_factory),
    )
    use_provider(agent, provider)
    app.dependency_overrides[agent_routes.get_runtime] = lambda: agent
    try:
        user, token = await make_user(session_factory, "resume-video@example.com")
        conv = (await client.post("/api/agent/conversations", headers=auth_headers(token), json={})).json()
        action = await DbApprovalStore(session_factory=session_factory).create(
            user_id=str(user.id),
            tool_name="google_workspace.send_email",
            arguments={"to": "prof@school.edu", "subject": "s", "body": "b"},
            reason="needs approval",
            conversation_id=conv["id"],
        )
        decided = await client.post(
            f"/api/agent/approvals/{action.action_id}", headers=auth_headers(token), json={"approved": True}
        )
        assert decided.status_code == 200
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    # The approved send ran outside any turn; the resumed turn's
    # video.transcript call ran inside it, on the turn's own model.
    assert executor.seen[0] is None
    assert len(executor.seen) == 2 and executor.seen[1] is not None
    assert executor.seen[1].provider == settings.LLM_PROVIDER.lower()
    assert turn_context.current() is None
