"""Tests for the turn resumed after an approval being run once more when it
failed on a provider hiccup before anything ran or was billed.

Why it exists: after an Approve tap the task goes on in a resumed turn, and
any provider error there ended the task with "Send 'continue' to try again"
on Telegram, even a one-off rate limit or server error. When nothing ran and
nothing was billed, running the turn again repeats nothing, so it is run once
more before the chat is asked to step in. A turn that ran a tool or was
billed is never re-run (its effects and cost are recorded instead, as
before). Drives the real chat and decision appliers over the fake desktop,
with the Bot API faked at the httpx transport; no model or screen is used.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from services.agent import cancel as agent_cancel
from services.agent.providers import LLMResponse, ProviderError, ToolCall
from services.tools.computer import backend as computer_backend
from services.tools.computer.backend_fake import FakeBackend
from tests.test_telegram import FakeTelegramAPI, _link
from tests.test_telegram_desktop_resume import (
    ANSWER,
    OPEN_CALENDAR,
    RAN,
    _ask_then_approve,
    _texts,
    _transcript,
    calendar_desktop,
    wired,
)

OBSERVE = LLMResponse(
    content="",
    tool_calls=[ToolCall(id="o1", name="desktop.observe", arguments={"action": "outline"})],
)


class Scripted:
    """Answers each call with the next step: an LLMResponse, or an exception
    to raise. Records every call's messages."""

    def __init__(self, steps: list[Any]) -> None:
        self.steps = list(steps)
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(list(messages))
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step

    async def stream(self, messages, tools=None):
        yield ""


@pytest.fixture
def fake_api(monkeypatch):
    api = FakeTelegramAPI()
    real_client_cls = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client_cls(**{**kw, "transport": httpx.MockTransport(api.handler)}),
    )
    return api


@pytest.fixture
def touched():
    ids: set[str] = set()
    yield ids
    for uid in ids:
        agent_cancel.clear(uid)


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    from api.routes import agent as agent_routes

    monkeypatch.setattr(agent_routes, "RESUME_RETRY_DELAY_S", 0)
    monkeypatch.setattr(
        computer_backend, "select_backend", lambda name: FakeBackend(available=(True, ""))
    )


async def _run(session_factory, fake_api, touched, email: str, chat_id: int, steps: list[Any]):
    user = await _link(session_factory, email, chat_id)
    touched.add(str(user.id))
    provider = Scripted(steps)
    fake = calendar_desktop()
    async with wired(session_factory, provider, fake) as service:
        await _ask_then_approve(service, fake_api, chat_id)
    return provider, fake


# ── a hiccup before anything ran: run once more ──────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hiccup",
    [
        ProviderError("gemini", 429, "Resource has been exhausted"),
        ProviderError("gemini", 503, "The model is overloaded"),
        ProviderError("anthropic", 529, "overloaded_error"),
        ProviderError("gemini", None, "could not reach the provider (ReadTimeout)", retryable=True),
        ProviderError(
            "gemini",
            None,
            "provider returned an empty completion (finishReason: STOP)",
            retryable=True,
        ),
    ],
    ids=["429", "503", "529", "dropped", "blank"],
)
async def test_a_hiccup_in_the_resumed_turn_is_run_again_and_answers(
    session_factory, fake_api, touched, hiccup
):
    provider, fake = await _run(
        session_factory,
        fake_api,
        touched,
        f"resume-retry-{hiccup.status_code}-{id(hiccup)}@example.com",
        9401,
        [OPEN_CALENDAR, hiccup, ANSWER],
    )
    assert fake.events == [("open_app", "Calendar")]  # the approved act ran once
    texts = _texts(fake_api)
    assert texts[-1].startswith(ANSWER.content), texts
    assert not any("Send 'continue'" in t for t in texts)
    # The second try saw the same history as the first (the approved result
    # is fenced with a fresh one-time token each time, so compare its shape).
    first, second = provider.calls[1], provider.calls[2]
    assert [m["role"] for m in first] == [m["role"] for m in second]
    assert first[-1]["content"].startswith("[Approved] Executed 'desktop.act'")
    assert second[-1]["content"].startswith("[Approved] Executed 'desktop.act'")
    rows = await _transcript(session_factory)
    assert rows[-1].content == ANSWER.content
    assert not any(r.content.startswith("[No reply") for r in rows)


# ── not run again ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_turn_that_already_ran_a_tool_is_not_run_again(session_factory, fake_api, touched):
    # The resumed turn looked at the screen (a tool ran, a model call was
    # billed) and then failed: running it again would repeat that, so the
    # chat is told, as before, and the transcript keeps what ran.
    hiccup = ProviderError("gemini", 503, "The model is overloaded")
    provider, _ = await _run(
        session_factory,
        fake_api,
        touched,
        "resume-ran@example.com",
        9402,
        [OPEN_CALENDAR, OBSERVE, hiccup],
    )
    assert len(provider.calls) == 3
    assert _texts(fake_api)[-1] == (
        f"{RAN} But I couldn't continue: the AI provider had a server error. "
        "Send 'continue' to try again."
    )
    rows = await _transcript(session_factory)
    assert rows[-1].content == "[No reply: the model provider returned an error.]"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "words"),
    [
        (ProviderError("gemini", 401, "API key not valid"), "the AI provider rejected the API key"),
        (ProviderError("gemini", 400, "bad request"), "the AI provider rejected the request"),
    ],
    ids=["401", "400"],
)
async def test_an_error_that_would_repeat_is_not_run_again(
    session_factory, fake_api, touched, error, words
):
    provider, _ = await _run(
        session_factory,
        fake_api,
        touched,
        f"resume-no-retry-{error.status_code}@example.com",
        9403,
        [OPEN_CALENDAR, error],
    )
    assert len(provider.calls) == 2
    assert (
        _texts(fake_api)[-1]
        == f"{RAN} But I couldn't continue: {words}. Send 'continue' to try again."
    )


@pytest.mark.asyncio
async def test_it_is_run_again_once_only(session_factory, fake_api, touched):
    hiccup = ProviderError("gemini", 503, "The model is overloaded")
    provider, _ = await _run(
        session_factory,
        fake_api,
        touched,
        "resume-twice@example.com",
        9404,
        [OPEN_CALENDAR, hiccup, hiccup],
    )
    assert len(provider.calls) == 3
    assert _texts(fake_api)[-1] == (
        f"{RAN} But I couldn't continue: the AI provider had a server error. "
        "Send 'continue' to try again."
    )
