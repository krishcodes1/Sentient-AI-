"""Tests for the turn resumed after an approved desktop action on Telegram:
the answer the owner asked for reaches the chat, and when it cannot, the chat
says what ran and why it stopped, in plain words, never "open the web app".

Why it exists: seen live. "Open calendar and see what I have on the 15th" →
the model asks for desktop.act open_app Calendar → the owner taps Approve →
Telegram shows "Executed 'desktop.act'. Open Crawler AI for the full result."
and nothing else, twice in a row. Three things made that: the turn resumed
after the approval read a history that ended on an assistant row (the
"[Approved] Executed" transcript line), which providers treat as a
continuation of the model's own turn rather than a request (Gemini answers
one with an empty completion, which the runtime raises as a ProviderError);
the row itself is cut at 2000 characters, so the fresh Calendar outline the
act returned was mostly gone; and whatever went wrong in the resumed turn
was swallowed into that dead-end fallback line. These tests drive the real
chat and decision appliers, the database approval store and the computer
toolkit over the in-memory fake desktop, with the Bot API faked at the
httpx transport. Nothing calls a model, Telegram or a real screen.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, AsyncIterator

import httpx
import pytest

from services import capabilities as capability_registry
from services.agent import cancel as agent_cancel
from services.agent.providers import LLMResponse, ProviderError, ProviderNotConfigured, ToolCall
from services.agent.runtime import AgentResponse, AgentRuntime
from services.capabilities.base import ReportContext
from services.tools.computer import backend as computer_backend
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.toolkit import ComputerToolkit
from tests.conftest import telegram_dm, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingProvider
from tests.test_telegram import FakeTelegramAPI, _link
from tests.test_telegram_decisions import _card, _press, _service

ASK = "Open calendar and see what I have to do on the 15th of this month"
OPEN_CALENDAR = LLMResponse(
    content="",
    tool_calls=[
        ToolCall(id="a1", name="desktop.act", arguments={"action": "open_app", "app": "Calendar"})
    ],
)
OBSERVE = LLMResponse(
    content="",
    tool_calls=[ToolCall(id="o1", name="desktop.observe", arguments={"action": "outline"})],
)
SCROLL = LLMResponse(
    content="",
    tool_calls=[
        ToolCall(id="a2", name="desktop.act", arguments={"action": "scroll", "direction": "down"})
    ],
)
ANSWER = LLMResponse(
    content="On the 15th you have Dentist at 10:00 and Team sync at 15:00.",
    usage={"input_tokens": 900, "output_tokens": 40},
)
RAN = "The approved action ran: open Calendar."
DEAD_END = "Open Crawler AI"


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
    """User ids whose stop is forgotten after the test: stops live in
    process memory and would leak into later tests."""
    ids: set[str] = set()
    yield ids
    for uid in ids:
        agent_cancel.clear(uid)


@pytest.fixture
def backend_ready(monkeypatch):
    """select_backend answers an available fake, so computer_control reports
    on (the toolkit itself runs on the test's own FakeBackend)."""
    monkeypatch.setattr(
        computer_backend, "select_backend", lambda name: FakeBackend(available=(True, ""))
    )


def calendar_desktop() -> FakeBackend:
    """Finder in front; Calendar running behind it, its month view listing
    each day's events under that day's cell."""
    days = ((14, ("Gym 07:00",)), (15, ("Dentist 10:00", "Team sync 15:00")), (16, ()))
    cells = tuple(
        make_node(
            "cell",
            f"September {day}",
            children=tuple(make_node("static text", title) for title in titles),
        )
        for day, titles in days
    )
    month = FakeWindow("September 2026", (make_node("button", "Today", handle="today"), *cells))
    return FakeBackend(
        [
            FakeApp("Finder", 1, [FakeWindow("Desktop", (make_node("button", "Macintosh HD"),))]),
            FakeApp("Calendar", 2, [month]),
        ],
        frontmost="Finder",
    )


def _statuses() -> list[Any]:
    """The owner's report with computer_control (and nothing else) on, on a
    host that needs no OS permission for it."""
    ctx = ReportContext(
        in_container=False, platform="win32", telegram_configured=True, browser_installed=True
    )
    switches = {k: k == "computer_control" for k in capability_registry.keys()}
    return capability_registry.report(switches, ctx, use_cache=False)


@asynccontextmanager
async def wired(session_factory, provider, fake: FakeBackend) -> AsyncIterator[Any]:
    """A bot wired to the real chat and decision appliers, over a runtime
    whose desktop tools run on *fake* with computer_control on: every
    desktop.act parks a card (pushed to Telegram), desktop.observe runs
    free."""
    from api.routes.agent import build_chat_applier, build_decision_applier
    from core.config import settings
    from main import app
    from services.agent.approvals import DbApprovalStore
    from services.agent.tool_registry import ConnectorToolExecutor, RuntimePermissionAdapter
    from services.notifications.telegram import NotifyingApprovalStore

    statuses = _statuses()
    by_key = capability_registry.statuses_by_key(statuses)

    async def gate():
        return by_key

    async def report():
        return statuses

    async def setup_completed():
        return True

    service = _service(session_factory)
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate),
        audit_service=RecordingAudit(),
        approval_store=NotifyingApprovalStore(
            DbApprovalStore(session_factory=session_factory), notify=service.notify_pending
        ),
        tool_executor=ConnectorToolExecutor(
            session_factory=None,
            capability_gate=gate,
            computer_toolkit=ComputerToolkit(fake, cancel_flag=agent_cancel.is_cancelled),
        ),
    )
    use_provider(runtime, provider)
    saved = dict(app.state._state)
    app.state.agent_runtime = runtime
    app.state.installation = SimpleNamespace(report=report, setup_completed=setup_completed)
    app.state.mcp_catalog = None
    service.chat = build_chat_applier(app, session_factory=session_factory)
    service.decide = build_decision_applier(app, session_factory=session_factory)
    try:
        yield service
    finally:
        app.state._state.clear()
        app.state._state.update(saved)
        await service._client.aclose()


async def _ask_then_approve(service, api: FakeTelegramAPI, chat_id: int) -> None:
    """The live sequence: the message, the card it parks, the Approve tap
    and the decision that runs after it, to the end."""
    await service._handle_message(telegram_dm(chat_id, ASK))
    await service.wait_for_chats()
    action_id = await _card(api)
    await service._handle_callback(_press("apv:" + action_id, chat_id, 9))
    await service.wait_for_chats()


def _texts(api: FakeTelegramAPI) -> list[str]:
    return [m["text"] for m in api.sent_messages()]


async def _transcript(session_factory) -> list[Any]:
    from sqlalchemy import select

    from models.conversation import Message

    async with session_factory() as session:
        return list((await session.execute(select(Message).order_by(Message.created_at))).scalars())


class Failing:
    """Provider: answers the scripted responses, then fails every call the
    way the vendor's HTTP error reaches the runtime."""

    def __init__(self, responses, error: Exception) -> None:
        self._responses = list(responses)
        self._error = error
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(list(messages))
        if self._responses:
            return self._responses.pop(0)
        raise self._error

    async def stream(self, messages, tools=None):
        yield ""


# -- the answer reaches the chat ----------------------------------------------------


@pytest.mark.asyncio
async def test_an_approved_open_app_is_followed_by_the_days_events(
    session_factory, fake_api, touched, backend_ready
):
    user = await _link(session_factory, "tg-desktop-resume@example.com", 9101)
    touched.add(str(user.id))
    fake = calendar_desktop()
    provider = RecordingProvider([OPEN_CALENDAR, OBSERVE, ANSWER])
    async with wired(session_factory, provider, fake) as service:
        await _ask_then_approve(service, fake_api, 9101)

    # The approved act ran once; the resumed turn looked (free) and answered.
    assert fake.events == [("open_app", "Calendar")]
    assert len(provider.calls) == 3
    texts = _texts(fake_api)
    assert texts[-1].startswith(ANSWER.content), texts
    assert not any(DEAD_END in t for t in texts)
    # The answer is the transcript's last row, with the observe it ran.
    rows = await _transcript(session_factory)
    assert rows[-1].content == ANSWER.content
    assert [tc["name"] for tc in rows[-1].tool_calls] == ["desktop.observe"]


@pytest.mark.asyncio
async def test_the_resumed_turn_reads_the_approved_result_as_a_user_turn_in_full(
    session_factory, fake_api, touched, backend_ready
):
    # A history that ends on an assistant row is a continuation of the
    # model's own turn to every provider (Gemini answers it with an empty
    # completion), and the transcript row is cut at 2000 characters, which
    # loses most of the outline the act came back with. The resumed turn
    # gets the result as a user turn, whole, in the runtime's own tool
    # result envelope.
    user = await _link(session_factory, "tg-desktop-history@example.com", 9102)
    touched.add(str(user.id))
    provider = RecordingProvider([OPEN_CALENDAR, ANSWER])
    async with wired(session_factory, provider, calendar_desktop()) as service:
        await _ask_then_approve(service, fake_api, 9102)

    resumed = [m for m in provider.calls[1]["messages"] if m["role"] != "system"]
    assert [m["role"] for m in resumed] == ["user", "assistant", "user"], resumed
    assert resumed[0]["content"] == ASK
    last = resumed[-1]["content"]
    assert "[Approved] Executed 'desktop.act'" in last
    assert "<tool_result_" in last and 'name="desktop.act"' in last
    # The fresh outline is whole: the 15th's events are already in it.
    assert "Dentist 10:00" in last and "Team sync 15:00" in last
    # The transcript still records the decision as its own row.
    rows = await _transcript(session_factory)
    assert rows[-2].content.startswith("[Approved] Executed 'desktop.act'.")
    assert rows[-1].content == ANSWER.content


@pytest.mark.asyncio
async def test_a_resumed_turn_that_parks_another_act_sends_its_card_and_says_so(
    session_factory, fake_api, touched, backend_ready
):
    user = await _link(session_factory, "tg-desktop-second-card@example.com", 9103)
    touched.add(str(user.id))
    fake = calendar_desktop()
    provider = RecordingProvider([OPEN_CALENDAR, SCROLL])
    async with wired(session_factory, provider, fake) as service:
        await _ask_then_approve(service, fake_api, 9103)
        # The second card is pushed from the store, off the turn.
        assert await _wait_for(lambda: len(_cards(fake_api)) == 2)

    assert fake.events == [("open_app", "Calendar")]  # the scroll waits for its card
    texts = _texts(fake_api)
    assert "Waiting on your approval for: desktop.act" in texts[-1], texts
    assert not any(DEAD_END in t for t in texts)
    assert 'Scroll down in Calendar' in _cards(fake_api)[1]["text"]


def _cards(api: FakeTelegramAPI) -> list[dict[str, Any]]:
    return [m for m in api.sent_messages() if m.get("reply_markup")]


async def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            return False
        await asyncio.sleep(0.01)
    return True


# -- when the resumed turn cannot answer, the chat says so in plain words -----------


@pytest.mark.asyncio
async def test_a_rate_limited_resume_is_explained_and_leaks_nothing(
    session_factory, fake_api, touched, backend_ready
):
    user = await _link(session_factory, "tg-desktop-429@example.com", 9104)
    touched.add(str(user.id))
    body = '{"error": {"message": "Resource has been exhausted", "key": "AIzaSy-secret"}}'
    provider = Failing([OPEN_CALENDAR], ProviderError("gemini", 429, body))
    fake = calendar_desktop()
    async with wired(session_factory, provider, fake) as service:
        await _ask_then_approve(service, fake_api, 9104)

    assert fake.events == [("open_app", "Calendar")]
    texts = _texts(fake_api)
    assert texts[-1] == (
        f"{RAN} But I couldn't continue: the AI provider rate-limited the request. "
        "Send 'continue' to try again."
    ), texts
    assert "AIzaSy-secret" not in "".join(texts) and "Resource has been" not in "".join(texts)
    assert not any(DEAD_END in t for t in texts)


@pytest.mark.asyncio
async def test_a_resume_that_fails_after_a_call_keeps_the_call_in_the_transcript(
    session_factory, fake_api, touched, backend_ready
):
    # The resumed turn looked at the screen, then the provider failed: the
    # observe it ran (and what was billed) close the turn in the transcript,
    # as a message turn's failure does, and the chat hears why.
    user = await _link(session_factory, "tg-desktop-503@example.com", 9105)
    touched.add(str(user.id))
    provider = Failing([OPEN_CALENDAR, OBSERVE], ProviderError("gemini", 503, "unavailable"))
    async with wired(session_factory, provider, calendar_desktop()) as service:
        await _ask_then_approve(service, fake_api, 9105)

    texts = _texts(fake_api)
    assert texts[-1] == (
        f"{RAN} But I couldn't continue: the AI provider had a server error. "
        "Send 'continue' to try again."
    ), texts
    rows = await _transcript(session_factory)
    assert rows[-1].content == "[No reply: the model provider returned an error.]"
    assert [tc["name"] for tc in rows[-1].tool_calls] == ["desktop.observe"]


@pytest.mark.asyncio
async def test_a_resume_with_no_reply_is_told_plainly(
    session_factory, fake_api, touched, backend_ready, monkeypatch
):
    user = await _link(session_factory, "tg-desktop-blank@example.com", 9106)
    touched.add(str(user.id))
    real_chat = AgentRuntime.chat
    turns: list[int] = []

    async def chat(self, *a, **kw):
        turns.append(1)
        if len(turns) == 1:
            return await real_chat(self, *a, **kw)
        return AgentResponse(content="")

    monkeypatch.setattr(AgentRuntime, "chat", chat)
    provider = RecordingProvider([OPEN_CALENDAR])
    async with wired(session_factory, provider, calendar_desktop()) as service:
        await _ask_then_approve(service, fake_api, 9106)

    texts = _texts(fake_api)
    assert texts[-1] == f"{RAN} The assistant did not add a reply. Send 'continue' to go on.", texts
    assert not any(DEAD_END in t for t in texts)


@pytest.mark.asyncio
async def test_an_approved_act_the_toolkit_refused_is_reported_as_such(
    session_factory, fake_api, touched, backend_ready
):
    # The owner switched the app so the approved act was refused, and the
    # resumed turn failed too: the chat must not say the action ran.
    user = await _link(session_factory, "tg-desktop-refused@example.com", 9107)
    touched.add(str(user.id))
    fake = calendar_desktop()
    fake.installed.discard("Calendar")
    del fake.apps["Calendar"]
    provider = Failing([OPEN_CALENDAR], ProviderError("gemini", 429, "slow down"))
    async with wired(session_factory, provider, fake) as service:
        await _ask_then_approve(service, fake_api, 9107)

    texts = _texts(fake_api)
    assert texts[-1] == (
        "The approved action did not go through: Could not find an app named 'Calendar'. "
        "But I couldn't continue: the AI provider rate-limited the request. "
        "Send 'continue' to try again."
    ), texts


# -- the plain words for each failure ------------------------------------------------


@pytest.mark.parametrize(
    ("error", "words"),
    [
        (ProviderError("gemini", 429, "quota"), "the AI provider rate-limited the request"),
        (ProviderError("openai", 401, "bad key"), "the AI provider rejected the API key"),
        (ProviderError("openai", 403, "forbidden"), "the AI provider rejected the API key"),
        (ProviderError("anthropic", 400, "bad request"), "the AI provider rejected the request"),
        (ProviderError("gemini", 500, "boom"), "the AI provider had a server error"),
        (ProviderError("gemini", 529, "overloaded"), "the AI provider had a server error"),
        (
            ProviderError("gemini", None, "could not reach the provider (ConnectTimeout)"),
            "the AI provider could not be reached",
        ),
        (
            ProviderError("gemini", None, "provider returned an empty completion (finishReason: STOP)"),
            "the AI model returned an empty reply",
        ),
        (
            ProviderError("gemini", None, "the model returned an empty response — please retry"),
            "the AI model returned an empty reply",
        ),
        (ProviderError("gemini", None, "something else"), "the AI provider returned an error"),
        (asyncio.TimeoutError(), "the request timed out"),
        (TimeoutError(), "the request timed out"),
        (RuntimeError("Traceback: File x.py line 3 key=sk-live-1"), "an unexpected error occurred"),
    ],
)
def test_resume_failure_text_is_plain_and_never_the_raw_error(error, words):
    from api.routes.agent import resume_failure_text

    text = resume_failure_text(error)
    assert text == words
    assert "sk-live" not in text and "Traceback" not in text and "quota" not in text


def test_resume_failure_text_keeps_the_not_configured_sentence():
    from api.routes.agent import resume_failure_text

    error = ProviderNotConfigured("gemini", reason="not_set_up")
    assert resume_failure_text(error) == ProviderNotConfigured.SETUP_MESSAGE
