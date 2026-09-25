"""Tests for an Approve/Deny press on Telegram: the press is answered at once,
the decision runs as the chat's tracked task off the poll loop, in order with
the chat's other turns, and reports back in the chat; the turn resumed after an
approval shows "typing…" and progress lines; and a /stop sent while the
approved action or the resumed turn runs reaches it.

Why it exists: an approval runs the action and then a whole resumed agent
turn, which can take a minute. Run inline, it held the poll loop that whole
time, so no other update was fetched: a /stop sent then was only seen once the
task had run to its end. These tests drive the real poll loop, the real /stop,
the real chat and decision appliers and the database approval store, with the
Bot API faked at the httpx transport. Nothing calls a model, Telegram, a
desktop or the web.

/stop both requests a stop for the account (``services.agent.cancel``, which
the approved action's own checks see between two steps) and cancels the
chat's tasks: an approved action still finishes and is recorded, and nothing
after it runs or is sent. So does a tool call the cancel lands in, or a card
being stored. Its reply says when approval cards are still waiting, since
their tasks stay stopped once approved. A message queued behind a running
turn takes its stop mark when it arrives, so the web Stop reaches it too, and
a call that ran beside a parked card is named in the reply the resumed turn
reads. Stopping the bot (shutdown, or the owner turning Telegram off) takes
no new message first, then waits a bounded time for a started call.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

import httpx
import pytest

from services.agent import cancel as agent_cancel
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import USER_STOPPED_POLICY
from services.notifications import progress
from services.notifications import telegram as tg
from tests.conftest import make_user, telegram_dm, use_provider
from tests.test_agent_runtime_vision import RecordingAudit, RecordingProvider
from tests.test_runtime_stop import Gate
from tests.test_telegram import FakeTelegramAPI, _link
from tests.test_telegram_progress import FakeClock, drain

# Telegram /stop's reply once the chat's work has unwound, and while it
# still unwinds.
STOPPED = "⏹ Stopped. Nothing more will be sent for that request."
STOPPING = "⏹ Stopping — nothing more will be sent for that request."

SEND_EMAIL = LLMResponse(
    content="Drafted it; approve the card to send.",
    tool_calls=[
        ToolCall(
            id="c1",
            name="google_workspace.send_email",
            arguments={"to": "prof@school.edu", "subject": "s", "body": "b"},
        )
    ],
)
SEARCH = LLMResponse(
    content="",
    tool_calls=[ToolCall(id="c2", name="web.search", arguments={"query": "office hours"})],
)
REMIND = LLMResponse(
    content="",
    tool_calls=[
        ToolCall(id="r1", name="reminders.create", arguments={"text": "Call the dentist"})
    ],
)


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
def stop_requests(monkeypatch):
    """The user ids a stop was requested for, in order, as they happen."""
    seen: list[str] = []
    real = agent_cancel.request_cancel

    def recording(user_id: str) -> None:
        seen.append(user_id)
        real(user_id)

    monkeypatch.setattr(agent_cancel, "request_cancel", recording)
    return seen


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(progress, "_now", fake.now)
    monkeypatch.setattr(progress, "_sleep", fake.sleep)
    return fake


def _service(session_factory, decide=None, chat=None):
    from services.notifications.telegram import TelegramService

    return TelegramService(
        token="123:fake-token", session_factory=session_factory, decide=decide, chat=chat
    )


def _press(data: str, chat_id: Optional[int], message_id: int = 7) -> dict[str, Any]:
    """A button press by the person whose private chat holds the card; with
    no chat, a press that carries none (inline mode)."""
    callback: dict[str, Any] = {"id": "cb", "data": data}
    if chat_id is not None:
        callback["from"] = {"id": chat_id, "is_bot": False}
        callback["message"] = {
            "chat": {"id": chat_id, "type": "private"},
            "message_id": message_id,
            "text": "🔐 Approval required",
        }
    return callback


def _answers(api: FakeTelegramAPI) -> list[str]:
    return [p["text"] for m, p in api.calls if m == "answerCallbackQuery"]


def _edits(api: FakeTelegramAPI) -> list[str]:
    return [p["text"] for m, p in api.calls if m == "editMessageText"]


async def _wait_for(predicate, timeout: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


# -- the press and the decision ------------------------------------------------


@pytest.mark.asyncio
async def test_the_press_is_answered_before_the_decision_runs(session_factory, fake_api):
    user = await _link(session_factory, "tg-decision-answer@example.com", 6060)
    release = asyncio.Event()
    decisions: list[tuple[str, str, bool]] = []

    async def decide(user_id, action_id, approved, *, on_event=None):
        decisions.append((user_id, action_id, approved))
        await release.wait()
        return {"status": "approved", "summary": "Sent, and office hours are 3pm."}

    service = _service(session_factory, decide=decide)
    # Returns while the decision is still running: the poll loop is free.
    await asyncio.wait_for(service._handle_callback(_press("apv:act-1", 6060)), timeout=2)
    assert _answers(fake_api) == ["Approving…"]
    assert _edits(fake_api) == []
    release.set()
    await service.wait_for_chats()

    assert decisions == [(str(user.id), "act-1", True)]
    assert _answers(fake_api) == ["Approving…"]  # a press is answered once
    assert _edits(fake_api) == ["🔐 Approval required\n\n— ✅ Approved from this chat."]
    assert fake_api.sent_messages()[-1]["text"] == "Sent, and office hours are 3pm."
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_refused_decision_is_reported_in_the_chat(session_factory, fake_api):
    await _link(session_factory, "tg-decision-refused@example.com", 6161)

    async def decide(user_id, action_id, approved, *, on_event=None):
        return {"error": "Action not found or already processed"}

    service = _service(session_factory, decide=decide)
    await service._handle_callback(_press("dny:act-2", 6161))
    await service.wait_for_chats()
    assert _answers(fake_api) == ["Denying…"]
    # The press was already answered, so the reason arrives as a message,
    # and the card keeps its buttons.
    assert [m["text"] for m in fake_api.sent_messages()] == [
        "⚠️ Action not found or already processed"
    ]
    assert _edits(fake_api) == []
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_decision_that_fails_is_reported_in_the_chat(session_factory, fake_api):
    await _link(session_factory, "tg-decision-raises@example.com", 6262)

    async def decide(user_id, action_id, approved, *, on_event=None):
        raise RuntimeError("database went away")

    service = _service(session_factory, decide=decide)
    await service._handle_callback(_press("apv:act-3", 6262))
    await service.wait_for_chats()
    assert _answers(fake_api) == ["Approving…"]
    assert [m["text"] for m in fake_api.sent_messages()] == [
        "⚠️ Could not apply that decision — see server logs."
    ]
    assert _edits(fake_api) == []
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_decision_waits_for_the_turn_running_in_its_chat(session_factory, fake_api):
    """The same per-chat lock as message turns: a resumed turn never runs
    beside another turn in the same conversation."""
    await _link(session_factory, "tg-decision-order@example.com", 6363)
    turn_release = asyncio.Event()
    order: list[str] = []

    async def chat(user_id, text, *, new_conversation=False, on_event=None):
        order.append("turn started")
        await turn_release.wait()
        order.append("turn done")
        return {"content": "done"}

    async def decide(user_id, action_id, approved, *, on_event=None):
        order.append("decision")
        return {"status": "denied", "summary": None}

    service = _service(session_factory, decide=decide, chat=chat)
    await service._handle_message(telegram_dm(6363, "hi"))
    assert await _wait_for(lambda: order == ["turn started"])
    await service._handle_callback(_press("dny:act-4", 6363))
    await asyncio.sleep(0.05)
    assert order == ["turn started"]
    turn_release.set()
    await service.wait_for_chats()
    assert order == ["turn started", "turn done", "decision"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_decide_callback_without_on_event_still_decides(session_factory, fake_api):
    """A callback written before progress lines existed runs as before and
    gets no lines, instead of a TypeError."""
    user = await _link(session_factory, "tg-decision-oldsig@example.com", 6464)
    decisions: list[tuple[str, str, bool]] = []

    async def decide(user_id, action_id, approved):
        decisions.append((user_id, action_id, approved))
        return {"status": "approved", "summary": "Done."}

    service = _service(session_factory, decide=decide)
    await service._handle_callback(_press("apv:act-5", 6464))
    await service.wait_for_chats()
    assert decisions == [(str(user.id), "act-5", True)]
    assert [m["text"] for m in fake_api.sent_messages()] == ["Done."]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_a_press_without_its_chat_decides_nothing(session_factory, fake_api):
    # An account with no Telegram link: a press that carries no chat must
    # not be matched to it.
    await make_user(session_factory, email="tg-decision-nochat@example.com")
    decisions: list[Any] = []

    async def decide(user_id, action_id, approved, *, on_event=None):
        decisions.append((user_id, action_id, approved))
        return {"status": "approved", "summary": None}

    service = _service(session_factory, decide=decide)
    await service._handle_callback(_press("apv:act-6", None))
    await service.wait_for_chats()
    assert decisions == []
    assert _answers(fake_api) == ["This chat is not linked to a Crawler AI account."]
    await service._client.aclose()


# -- end to end: the real appliers ---------------------------------------------


class Hold:
    """Executor: the named call is held open until released, and records
    whether a stop was in force when it was released, the check the
    computer toolkit makes between two desktop actions."""

    def __init__(self, held: str) -> None:
        self.held = held
        self.calls: list[str] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.stopped_at_release: list[bool] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append(tool_name)
        if tool_name == self.held:
            self.started.set()
            await self.release.wait()
            self.stopped_at_release.append(agent_cancel.is_cancelled(user_id))
        return {"ok": True, "result": f"{tool_name} finished"}


class TimedSearch:
    """Executor: web.search takes five (fake) seconds; the rest are instant."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls: list[str] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append(tool_name)
        if tool_name == "web.search":
            for _ in range(5):
                await self.clock.advance(1)
        return {"ok": True, "result": f"{tool_name} finished"}


@asynccontextmanager
async def wired(session_factory, provider, executor) -> AsyncIterator[Any]:
    """A bot wired to the real chat and decision appliers, over a runtime
    whose send_email needs approval, parked in the database store, with its
    card pushed to Telegram."""
    from api.routes.agent import build_chat_applier, build_decision_applier
    from core.config import settings
    from main import app
    from services.agent.approvals import DbApprovalStore
    from services.agent.runtime import AgentRuntime
    from services.notifications.telegram import NotifyingApprovalStore

    service = _service(session_factory)
    runtime = AgentRuntime(
        config=settings,
        permission_engine=Gate({"google_workspace.send_email"}),
        audit_service=RecordingAudit(),
        approval_store=NotifyingApprovalStore(
            DbApprovalStore(session_factory=session_factory), notify=service.notify_pending
        ),
        tool_executor=executor,
    )
    use_provider(runtime, provider)
    runtime._CONTENT_CHUNK_DELAY = 0
    saved = dict(app.state._state)
    app.state.agent_runtime = runtime
    app.state.installation = None
    app.state.mcp_catalog = None
    service.chat = build_chat_applier(app, session_factory=session_factory)
    service.decide = build_decision_applier(app, session_factory=session_factory)

    async def quick_sleep(_seconds: float) -> None:
        await asyncio.sleep(0.01)

    service._sleep = quick_sleep
    try:
        yield service
    finally:
        app.state._state.clear()
        app.state._state.update(saved)
        await service._client.aclose()


async def _card(api: FakeTelegramAPI) -> str:
    """The action id on the approval card the turn pushed."""
    assert await _wait_for(lambda: any(m.get("reply_markup") for m in api.sent_messages()))
    for m in api.sent_messages():
        if m.get("reply_markup"):
            return m["reply_markup"]["inline_keyboard"][0][0]["callback_data"][len("apv:") :]
    raise AssertionError("no approval card was sent")


def _tap_update(update_id: int, chat_id: int, action_id: str) -> dict[str, Any]:
    return {
        "ok": True,
        "result": [
            {"update_id": update_id, "callback_query": _press("apv:" + action_id, chat_id, 9)}
        ],
    }


def _text_update(update_id: int, chat_id: int, text: str) -> dict[str, Any]:
    return {
        "ok": True,
        "result": [{"update_id": update_id, "message": telegram_dm(chat_id, text)}],
    }


async def _approve_then_stop(
    service, api: FakeTelegramAPI, chat_id: int, executor: Hold, stop_requests: list[str]
) -> bool:
    """Approve the card through the poll loop, then send /stop while the
    held call runs. Returns whether the stop was requested before the held
    call was released."""
    action_id = await _card(api)
    api.get_updates = [_tap_update(1, chat_id, action_id)]
    poller = asyncio.create_task(service._poll_loop())
    try:
        assert await _wait_for(executor.started.is_set)
        api.get_updates.append(_text_update(2, chat_id, "/stop"))
        requested_while_held = await _wait_for(lambda: bool(stop_requests), timeout=2)
        executor.release.set()
        assert await _wait_for(lambda: not service._chat_tasks)
        await service.wait_for_chats()
        # /stop answers once the chat's cancelled work has unwound.
        assert await _wait_for(lambda: api.sent_messages()[-1]["text"] == STOPPED)
    finally:
        executor.release.set()
        poller.cancel()
        await asyncio.gather(poller, return_exceptions=True)
    return requested_while_held


async def _transcript(session_factory) -> list[str]:
    from sqlalchemy import select

    from models.conversation import Message

    async with session_factory() as session:
        rows = (await session.execute(select(Message).order_by(Message.created_at))).scalars()
        return [r.content.split("\n")[0] for r in rows]


@pytest.mark.asyncio
async def test_a_stop_sent_while_the_approved_action_runs_reaches_its_checks(
    session_factory, fake_api, touched, stop_requests
):
    user = await _link(session_factory, "tg-decision-stop-act@example.com", 7171)
    touched.add(str(user.id))
    executor = Hold("google_workspace.send_email")
    provider = RecordingProvider([SEND_EMAIL, LLMResponse(content="never asked for")])
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(telegram_dm(7171, "email my prof"))
        await service.wait_for_chats()
        requested_while_held = await _approve_then_stop(
            service, fake_api, 7171, executor, stop_requests
        )

    assert requested_while_held, "/stop was not taken while the approved action ran"
    assert stop_requests == [str(user.id)]
    # The action's own check between two steps sees the stop, and the
    # action (already approved) still finishes and is recorded...
    assert executor.stopped_at_release == [True]
    transcript = await _transcript(session_factory)
    assert transcript[-1] == "[Approved] Executed 'google_workspace.send_email'."
    # ...and nothing after it runs or is sent: no resumed turn, no reply.
    assert len(provider.calls) == 1
    texts = [m["text"] for m in fake_api.sent_messages()]
    assert texts[-1] == STOPPED
    assert "never asked for" not in "".join(texts)


@pytest.mark.asyncio
async def test_a_stop_sent_while_the_resumed_turn_runs_ends_it(
    session_factory, fake_api, touched, stop_requests
):
    user = await _link(session_factory, "tg-decision-stop-resume@example.com", 7272)
    touched.add(str(user.id))
    executor = Hold("web.search")
    provider = RecordingProvider(
        [SEND_EMAIL, SEARCH, LLMResponse(content="Sent, and office hours are 3pm.")]
    )
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(telegram_dm(7272, "email my prof"))
        await service.wait_for_chats()
        requested_while_held = await _approve_then_stop(
            service, fake_api, 7272, executor, stop_requests
        )

    assert requested_while_held, "/stop was not taken while the resumed turn ran"
    # The search it had started finishes (a started call is never cut short,
    # and its own checks see the stop), then the resumed turn is cancelled:
    # no further model round, no answer, and the transcript closes the turn
    # as stopped.
    assert executor.calls == ["google_workspace.send_email", "web.search"]
    assert executor.stopped_at_release == [True]
    assert len(provider.calls) == 2
    texts = [m["text"] for m in fake_api.sent_messages()]
    assert texts[-1] == STOPPED
    assert "office hours" not in "".join(texts)
    assert (await _transcript(session_factory))[-1] == "[Stopped before the reply was finished.]"


# -- /stop never cuts a started call or a card half-way --------------------------


class HoldAudit(RecordingAudit):
    """Audit service that holds one event's write open until released, as a
    slow database would, so /stop can land while it is being written. With
    ``fail``, the held write then fails, as a database gone away would."""

    def __init__(self, held: str, *, fail: bool = False) -> None:
        super().__init__()
        self.held = held
        self.fail = fail
        self.reached = asyncio.Event()
        self.release = asyncio.Event()

    async def log(self, entry):
        if entry.get("event") == self.held:
            self.reached.set()
            await self.release.wait()
            if self.fail:
                raise RuntimeError("audit store went away")
        await super().log(entry)


class HoldCreate:
    """Approval store whose create stores the card, then holds its answer
    until released, as a slow database reply would, so /stop can land
    after the card exists but before the turn knows it does."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.reached = asyncio.Event()
        self.release = asyncio.Event()

    async def create(self, **card: Any) -> Any:
        stored = await self.inner.create(**card)
        self.reached.set()
        await self.release.wait()
        return stored

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)


async def _last_message(session_factory):
    from sqlalchemy import select

    from models.conversation import Message

    async with session_factory() as session:
        rows = (await session.execute(select(Message).order_by(Message.created_at))).scalars()
        return list(rows)[-1]


# The line /stop's reply adds while one approval card waits on the account.
ONE_CARD_WAITS = (
    "\n\n1 action is still waiting for your approval (/pending). "
    "Approving it runs that one action; its task stays stopped."
)


@pytest.mark.asyncio
async def test_a_stop_during_a_running_call_lets_it_finish_and_records_it(
    session_factory, fake_api, touched, stop_requests
):
    # /stop cancels the chat's task, but the call it lands in may already
    # have had its effect: it finishes, gets its outcome row, and the row
    # that closes the turn in the transcript names it.
    from main import app

    user = await _link(session_factory, "tg-decision-stop-mid-call@example.com", 7676)
    touched.add(str(user.id))
    executor = Hold("reminders.create")
    provider = RecordingProvider([REMIND, LLMResponse(content="never asked for")])
    async with wired(session_factory, provider, executor) as service:
        audit = app.state.agent_runtime._audit
        await service._handle_message(telegram_dm(7676, "remind me to call the dentist"))
        assert await _wait_for(executor.started.is_set)
        stop = asyncio.create_task(service._handle_message(telegram_dm(7676, "/stop")))
        assert await _wait_for(lambda: bool(stop_requests))
        executor.release.set()
        await stop
        await service.wait_for_chats()

    assert fake_api.sent_messages()[-1]["text"] == STOPPED
    assert executor.stopped_at_release == [True]
    events = [e["event"] for e in audit.entries if e.get("tool") == "reminders.create"]
    assert events == ["tool_executing", "tool_executed"]
    last = await _last_message(session_factory)
    assert last.content == "[Stopped before the reply was finished.]"
    assert [tc["name"] for tc in last.tool_calls] == ["reminders.create"]
    # Nothing ran after it: no further model round.
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_a_stop_while_a_card_is_stored_still_audits_the_card(
    session_factory, fake_api, touched, stop_requests
):
    # The card is stored (and pushed to the chat) before its
    # tool_pending_approval row is written; a card can be approved, so the
    # row is written even when /stop lands in between.
    from main import app
    from services.agent.approvals import DbApprovalStore

    user = await _link(session_factory, "tg-decision-stop-card@example.com", 7777)
    uid = str(user.id)
    touched.add(uid)
    executor = Hold("nothing is held")
    provider = RecordingProvider([SEND_EMAIL, LLMResponse(content="never asked for")])
    async with wired(session_factory, provider, executor) as service:
        audit = HoldAudit("tool_pending_approval")
        app.state.agent_runtime._audit = audit
        await service._handle_message(telegram_dm(7777, "email my prof"))
        assert await _wait_for(audit.reached.is_set)
        await _card(fake_api)  # pushed to the chat before its row is written
        stop = asyncio.create_task(service._handle_message(telegram_dm(7777, "/stop")))
        assert await _wait_for(lambda: bool(stop_requests))
        audit.release.set()
        await stop
        await service.wait_for_chats()
        [card] = await DbApprovalStore(session_factory=session_factory).list_pending(uid)

    [row] = audit.entries
    assert (row["event"], row["action_id"]) == ("tool_pending_approval", card.action_id)
    # The reply says the card still waits, and what approving it does.
    assert fake_api.sent_messages()[-1]["text"] == STOPPED + ONE_CARD_WAITS
    assert executor.calls == []


@pytest.mark.asyncio
async def test_a_card_row_that_fails_after_a_stop_ends_the_turn_as_stopped(
    session_factory, fake_api, touched, stop_requests
):
    # /stop lands while the card's tool_pending_approval row is written,
    # and the write then fails. The stop outranks the failure: the task
    # ends cancelled, so the transcript closes the turn as stopped and no
    # error is sent after the stop's reply.
    from main import app

    user = await _link(session_factory, "tg-decision-stop-card-fails@example.com", 8484)
    touched.add(str(user.id))
    executor = Hold("nothing is held")
    provider = RecordingProvider([SEND_EMAIL, LLMResponse(content="never asked for")])
    async with wired(session_factory, provider, executor) as service:
        app.state.agent_runtime._audit = HoldAudit("tool_pending_approval", fail=True)
        audit = app.state.agent_runtime._audit
        await service._handle_message(telegram_dm(8484, "email my prof"))
        assert await _wait_for(audit.reached.is_set)
        [chat_task] = service._chat_tasks[8484]
        stop = asyncio.create_task(service._handle_message(telegram_dm(8484, "/stop")))
        assert await _wait_for(lambda: bool(stop_requests))
        audit.release.set()
        await stop
        await service.wait_for_chats()

    assert chat_task.cancelled()
    texts = [m["text"] for m in fake_api.sent_messages()]
    assert not any(t.startswith("⚠️") for t in texts), texts
    assert texts[-1] == STOPPED + ONE_CARD_WAITS
    last = await _last_message(session_factory)
    assert last.content == "[Stopped before the reply was finished.]"
    assert executor.calls == []


@pytest.mark.asyncio
async def test_a_stop_while_the_card_is_stored_leaves_it_to_approve_once(
    session_factory, fake_api, touched, stop_requests
):
    # /stop lands after the store wrote the card but before its answer came
    # back. The card is kept and audited, and approving it runs the action
    # once; the stop, made while the card waited, ends the resumed turn.
    from main import app
    from services.agent.approvals import DbApprovalStore

    user = await _link(session_factory, "tg-decision-stop-card-store@example.com", 8686)
    uid = str(user.id)
    touched.add(uid)
    executor = Hold("nothing is held")
    provider = RecordingProvider([SEND_EMAIL, LLMResponse(content="never asked for")])
    async with wired(session_factory, provider, executor) as service:
        runtime = app.state.agent_runtime
        store = HoldCreate(runtime._approvals)
        runtime._approvals = store
        await service._handle_message(telegram_dm(8686, "email my prof"))
        assert await _wait_for(store.reached.is_set)
        [chat_task] = service._chat_tasks[8686]
        stop = asyncio.create_task(service._handle_message(telegram_dm(8686, "/stop")))
        assert await _wait_for(lambda: bool(stop_requests))
        store.release.set()
        await stop
        await service.wait_for_chats()
        [card] = await DbApprovalStore(session_factory=session_factory).list_pending(uid)
        assert service.decide is not None
        outcome = await service.decide(uid, card.action_id, True)
        again = await service.decide(uid, card.action_id, True)

    assert chat_task.cancelled()
    [row] = [e for e in runtime._audit.entries if e["event"] == "tool_pending_approval"]
    assert row["action_id"] == card.action_id
    assert str(outcome["summary"]).startswith("Stopped.")
    assert again.get("error")
    assert executor.calls == ["google_workspace.send_email"]
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_a_stop_while_the_intent_row_is_written_records_the_call_as_skipped(
    session_factory, fake_api, touched, stop_requests
):
    # /stop lands while the call's tool_executing row is written. The write
    # is not cut off, so the row is kept; the call then does not start, and
    # the row gets its outcome: the skip row a stop writes.
    from main import app

    user = await _link(session_factory, "tg-decision-stop-intent@example.com", 8383)
    touched.add(str(user.id))
    executor = Hold("nothing is held")
    provider = RecordingProvider([REMIND, LLMResponse(content="never asked for")])
    async with wired(session_factory, provider, executor) as service:
        app.state.agent_runtime._audit = HoldAudit("tool_executing")
        audit = app.state.agent_runtime._audit
        await service._handle_message(telegram_dm(8383, "remind me to call the dentist"))
        assert await _wait_for(audit.reached.is_set)
        stop = asyncio.create_task(service._handle_message(telegram_dm(8383, "/stop")))
        assert await _wait_for(lambda: bool(stop_requests))
        audit.release.set()
        await stop
        await service.wait_for_chats()

    rows = [(e["event"], e.get("policy")) for e in audit.entries if e.get("tool")]
    assert rows == [("tool_executing", None), ("tool_blocked", USER_STOPPED_POLICY)]
    assert executor.calls == []
    assert fake_api.sent_messages()[-1]["text"] == STOPPED
    last = await _last_message(session_factory)
    assert last.content == "[Stopped before the reply was finished.]"
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_a_message_after_two_stops_runs_once_the_stopped_call_ends(
    session_factory, fake_api, touched, stop_requests, monkeypatch
):
    # Two /stops while a started call runs on: each answers once its short
    # wait is up. A message sent meanwhile waits for the stopped turn to
    # end, then runs as a turn of its own, which neither stop touches.
    from main import app

    monkeypatch.setattr(tg, "_STOP_WAIT_S", 0.2)
    user = await _link(session_factory, "tg-decision-two-stops@example.com", 8585)
    touched.add(str(user.id))
    executor = Hold("reminders.create")
    provider = RecordingProvider([REMIND, LLMResponse(content="The next answer.")])
    async with wired(session_factory, provider, executor) as service:
        audit = app.state.agent_runtime._audit
        await service._handle_message(telegram_dm(8585, "remind me to call the dentist"))
        assert await _wait_for(executor.started.is_set)
        [chat_task] = service._chat_tasks[8585]
        await service._handle_message(telegram_dm(8585, "/stop"))
        await service._handle_message(telegram_dm(8585, "/stop"))
        assert not chat_task.done()
        await service._handle_message(telegram_dm(8585, "and what is on my calendar"))
        before_release = len(fake_api.sent_messages())
        executor.release.set()
        await service.wait_for_chats()

    texts = [m["text"] for m in fake_api.sent_messages()]
    assert texts[:before_release] == [STOPPING, STOPPING]
    assert chat_task.cancelled()
    events = [e["event"] for e in audit.entries if e.get("tool") == "reminders.create"]
    assert events == ["tool_executing", "tool_executed"]
    assert executor.calls == ["reminders.create"]
    # The second model call is the new message's own turn.
    assert len(provider.calls) == 2
    [reply] = texts[before_release:]
    assert reply.startswith("The next answer.\n\n")


@pytest.mark.asyncio
async def test_a_stop_with_nothing_running_says_what_a_waiting_card_will_do(
    session_factory, fake_api, touched
):
    # The stop still counts against the task behind a card that was already
    # waiting (the approved action runs, then that task ends as "Stopped."),
    # so the reply says so rather than only "Nothing is running".
    user = await _link(session_factory, "tg-decision-stop-idle@example.com", 7878)
    uid = str(user.id)
    touched.add(uid)
    executor = Hold("nothing is held")
    provider = RecordingProvider([SEND_EMAIL, LLMResponse(content="Sent, and done.")])
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(telegram_dm(7878, "email my prof"))
        await service.wait_for_chats()
        action_id = await _card(fake_api)
        await service._handle_message(telegram_dm(7878, "/stop"))
        said = fake_api.sent_messages()[-1]["text"]
        assert service.decide is not None
        outcome = await service.decide(uid, action_id, True)

    assert said == "Nothing is running right now." + ONE_CARD_WAITS
    assert executor.calls == ["google_workspace.send_email"]
    assert str(outcome["summary"]).startswith("Stopped.")
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_a_web_stop_reaches_a_message_that_arrived_before_it(
    session_factory, fake_api, touched
):
    # A message queued behind the chat's running turn took its stop mark
    # when it arrived, so the web Stop (POST /api/agent/stop, which only
    # records the stop) pressed while it waited ends it too.
    user = await _link(session_factory, "tg-decision-web-stop-queued@example.com", 7979)
    uid = str(user.id)
    touched.add(uid)
    executor = Hold("web.search")
    provider = RecordingProvider([SEARCH, LLMResponse(content="The queued answer.")])
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(telegram_dm(7979, "look up office hours"))
        assert await _wait_for(executor.started.is_set)
        await service._handle_message(telegram_dm(7979, "and email them to me"))
        # What POST /api/agent/stop does first (api/routes/agent.stop_running_task).
        agent_cancel.request_cancel(uid)
        executor.release.set()
        await service.wait_for_chats()

    texts = [m["text"] for m in fake_api.sent_messages()]
    assert "The queued answer." not in "".join(texts)
    replies = [t.split("\n\n")[0] for t in texts if t.startswith("Stopped.")]
    assert replies == [
        "Stopped. I didn't finish the task. 1 step ran before the stop.",
        "Stopped. I didn't finish the task.",
    ]
    assert len(provider.calls) == 1


# -- stopping the bot while a started call runs ------------------------------------


@pytest.mark.asyncio
async def test_stopping_the_bot_takes_no_new_message_while_a_started_call_ends(
    session_factory, fake_api, touched
):
    # Shutdown, or the owner turning Telegram off, while a started call
    # runs: the poller stops first, so a message sent meanwhile starts no
    # turn, and the call finishes and is recorded before stop() returns.
    from main import app

    user = await _link(session_factory, "tg-decision-shutdown@example.com", 8181)
    touched.add(str(user.id))
    executor = Hold("reminders.create")
    provider = RecordingProvider([REMIND, LLMResponse(content="never asked for")])
    async with wired(session_factory, provider, executor) as service:
        audit = app.state.agent_runtime._audit
        fake_api.get_updates = [_text_update(1, 8181, "remind me to call the dentist")]
        await service.start()
        assert await _wait_for(executor.started.is_set)
        stopping = asyncio.create_task(service.stop())
        # The poller is gone before the message arrives. Handed over any
        # earlier, the poller (which wakes every 10 ms here, in step with
        # _wait_for) could fetch it and be cancelled by stop() inside its
        # account lookup; a query cancelled mid-flight invalidates the
        # pooled connection, and this in-memory database goes with it.
        assert await _wait_for(lambda: service._task is None)
        fake_api.get_updates.append(_text_update(2, 8181, "what is on my calendar"))
        await asyncio.sleep(0.3)
        assert not stopping.done()  # waiting for the started call
        executor.release.set()
        await asyncio.wait_for(stopping, 5)
        assert [t for t in service._all_chat_tasks() if not t.done()] == []
        # Nor does a message handed to it once stopped start anything.
        await service._handle_message(telegram_dm(8181, "one more thing"))
        assert service._all_chat_tasks() == []
        await asyncio.sleep(0.3)

    events = [e["event"] for e in audit.entries if e.get("tool") == "reminders.create"]
    assert events == ["tool_executing", "tool_executed"]
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_stopping_the_bot_does_not_wait_forever_on_a_wedged_call(
    session_factory, fake_api, touched, monkeypatch
):
    # A call that never ends must not hold up the app's shutdown or the
    # owner turning Telegram off: stop() waits _STOP_WAIT_S, logs what is
    # still running and returns; the call is left to end on its own.
    from structlog.testing import capture_logs

    monkeypatch.setattr(tg, "_STOP_WAIT_S", 0.2)
    user = await _link(session_factory, "tg-decision-shutdown-wedged@example.com", 8282)
    touched.add(str(user.id))
    executor = Hold("reminders.create")
    provider = RecordingProvider([REMIND])
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(telegram_dm(8282, "remind me to call the dentist"))
        assert await _wait_for(executor.started.is_set)
        [chat_task] = service._chat_tasks[8282]
        with capture_logs() as logs:
            await asyncio.wait_for(service.stop(), 2.0)
        assert not chat_task.done()
        executor.release.set()
        await service.wait_for_chats()

    [left] = [e for e in logs if e["event"] == "telegram_stop_left_running"]
    assert left["tasks"] == ["telegram-chat-8282"]
    assert chat_task.cancelled()
    assert executor.calls == ["reminders.create"]
    assert len(provider.calls) == 1


# -- a round that parks a card ends the turn ---------------------------------------


@pytest.mark.asyncio
async def test_a_call_that_ran_beside_a_card_is_named_for_the_resumed_turn(
    session_factory, fake_api, touched
):
    # The turn ends on the card, so the model never saw what the reminder
    # beside it returned, and the resumed turn rebuilds its history from
    # message text only: the reply names the call that ran, so nothing
    # there invites setting the reminder again.
    user = await _link(session_factory, "tg-decision-parked-round@example.com", 8080)
    uid = str(user.id)
    touched.add(uid)
    executor = Hold("nothing is held")
    both = LLMResponse(
        content="",
        tool_calls=[
            ToolCall(id="r1", name="reminders.create", arguments={"text": "Office hours at 3"}),
            *SEND_EMAIL.tool_calls,
        ],
    )
    provider = RecordingProvider([both, LLMResponse(content="Sent.")])
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(
            telegram_dm(8080, "remind me about office hours and email my prof")
        )
        await service.wait_for_chats()
        assert service.decide is not None
        await service.decide(uid, await _card(fake_api), True)

    ran = "Ran before asking for approval: reminders.create."
    texts = [m["text"] for m in fake_api.sent_messages()]
    [reply] = [t for t in texts if "Waiting on your approval" in t]
    assert reply.startswith("I need your approval before I can continue.")
    assert ran in reply
    assert executor.calls == ["reminders.create", "google_workspace.send_email"]
    resumed = [m for m in provider.calls[1]["messages"] if m["role"] == "assistant"]
    assert any(ran in str(m["content"]) for m in resumed), resumed


@pytest.mark.asyncio
async def test_the_decision_applier_hands_on_event_to_the_resumed_turn(
    session_factory, fake_api, touched, monkeypatch
):
    from services.agent.runtime import AgentRuntime

    user = await _link(session_factory, "tg-decision-sink@example.com", 7474)
    touched.add(str(user.id))
    sinks: list[Any] = []
    real_chat = AgentRuntime.chat

    async def recording_chat(self, *a, **kw):
        sinks.append(kw.get("event_sink"))
        return await real_chat(self, *a, **kw)

    monkeypatch.setattr(AgentRuntime, "chat", recording_chat)
    events: list[dict[str, Any]] = []

    async def on_event(event: dict[str, Any]) -> None:
        events.append(event)

    executor = Hold("nothing is held")
    provider = RecordingProvider([SEND_EMAIL, SEARCH, LLMResponse(content="Sent.")])
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(telegram_dm(7474, "email my prof"))
        await service.wait_for_chats()
        assert service.decide is not None
        outcome = await service.decide(str(user.id), await _card(fake_api), True, on_event=on_event)

    assert (outcome["status"], outcome["summary"]) == ("approved", "Sent.")
    # The resumed turn's own usage rides along for the reply's cost line.
    assert isinstance(outcome["usage"], dict)
    # The message turn, then the resumed turn: both report to a listener.
    assert len(sinks) == 2 and sinks[1] is on_event
    assert [e["data"]["name"] for e in events if e["type"] == "tool_call"] == ["web.search"]


@pytest.mark.asyncio
async def test_the_resumed_turn_shows_typing_and_progress_lines(
    session_factory, fake_api, touched, clock
):
    user = await _link(session_factory, "tg-decision-progress@example.com", 7373)
    touched.add(str(user.id))
    executor = TimedSearch(clock)
    provider = RecordingProvider(
        [SEND_EMAIL, SEARCH, LLMResponse(content="Sent, and office hours are 3pm.")]
    )
    async with wired(session_factory, provider, executor) as service:
        await service._handle_message(telegram_dm(7373, "email my prof"))
        await service.wait_for_chats()
        action_id = await _card(fake_api)
        before = len(fake_api.calls)
        await service._handle_callback(_press("apv:" + action_id, 7373, 9))
        # The press is answered before anything else happens.
        assert [m for m, _ in fake_api.calls[before:]] == ["answerCallbackQuery"]
        await drain(service, clock)
        after_tap = fake_api.calls[before:]

    assert executor.calls == ["google_workspace.send_email", "web.search"]
    assert ("sendChatAction", {"chat_id": 7373, "action": "typing"}) in after_tap
    sent = [p for m, p in after_tap if m == "sendMessage"]
    lines = [p["text"] for p in sent if p.get("disable_notification")]
    assert lines == ["Searching the web…"]
    # The reply is the resumed turn's answer with its cost line, last, and
    # not silent.
    reply, _, cost = sent[-1]["text"].rpartition("\n\n")
    assert reply == "Sent, and office hours are 3pm."
    assert " tokens · " in cost
    assert "disable_notification" not in sent[-1]
    assert _edits(fake_api) == ["🔐 Approval required\n\n— ✅ Approved from this chat."]
