"""Tests for the progress lines a Telegram turn posts while it runs: the phrase
each tool call earns, the pacing (grace period, one line per interval, no
repeats, a cap per turn, the reply at least a second after the last line),
that a parked approval earns no line, that a URL reaches the chat as its host
only, that a failing or hung send never touches the turn or its final reply,
and that a chat callback written without ``on_event`` still answers.

Why it exists: The lines go to a phone from events the model can steer; these
tests pin that every line is fixed text plus at most a hostname, and that the
pacing keeps a quick answer free of status noise.

Time is a fake clock the tests advance (``progress._now`` / ``progress._sleep``)
and the Bot API is the httpx-level fake from test_telegram.py, so nothing
calls a model or reaches the network, and the only real waiting is the
hung-send tests' ``SEND_WAIT_S``, shortened to 0.3 s.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional

import httpx
import pytest

from services.agent.providers import LLMResponse
from services.agent.runtime import tool_call_facts
from services.notifications import progress
from services.notifications.progress import TurnProgress, phrase_for, takes_on_event
from tests.test_agent_runtime_vision import RecordingProvider
from tests.test_browser_runtime import (
    BROWSER_TOOL,
    WEB_TOOL,
    RecordingExecutor,
    call,
    runtime_with,
)
from tests.conftest import telegram_dm
from tests.test_telegram import FakeTelegramAPI, _link

REPLY = "Your grade in CSCI 380 is an A-. https://canvas.nyit.edu/courses/12/grades"


class FakeClock:
    """A turn's timeline: time moves only when a test advances it, and a
    paced line that is waiting goes out once its moment comes."""

    def __init__(self) -> None:
        self.t = 0.0
        self._sleepers: list[tuple[float, asyncio.Future[None]]] = []

    def now(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._sleepers.append((self.t + seconds, fut))
        await fut

    async def advance(self, seconds: float) -> None:
        self.t += seconds
        due = [s for s in self._sleepers if s[0] <= self.t]
        self._sleepers = [s for s in self._sleepers if s[0] > self.t]
        for _, fut in due:
            if not fut.done():
                fut.set_result(None)
        await settle()


async def settle() -> None:
    # Let woken tasks run until they block again; a send through the httpx
    # mock transport takes a handful of loop turns.
    for _ in range(50):
        await asyncio.sleep(0)


async def close(turn: TurnProgress, clock: FakeClock) -> None:
    """End a turn's progress, moving the fake clock through the reply gap a
    line that just went out holds it for."""
    closing = asyncio.create_task(turn.aclose())
    await settle()
    if not closing.done():
        await clock.advance(progress.REPLY_GAP_S)
    await asyncio.wait_for(closing, timeout=1)


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(progress, "_now", fake.now)
    monkeypatch.setattr(progress, "_sleep", fake.sleep)
    return fake


class FailingProgressAPI(FakeTelegramAPI):
    """Telegram that is unreachable for every progress line (they are the
    only silent sends) and fine for everything else."""

    def handler(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content or b"{}")
        if payload.get("disable_notification"):
            self.calls.append(("sendMessage-failed", payload))
            raise httpx.ConnectError("telegram unreachable")
        return super().handler(request)


def _install(monkeypatch, api: FakeTelegramAPI) -> FakeTelegramAPI:
    real_client_cls = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client_cls(**{**kw, "transport": httpx.MockTransport(api.handler)}),
    )
    return api


@pytest.fixture
def telegram_api(monkeypatch):
    return _install(monkeypatch, FakeTelegramAPI())


def _service(session_factory):
    from services.notifications.telegram import TelegramService

    return TelegramService(token="123:fake-token", session_factory=session_factory)


def tool_call(name: str, **data: Any) -> dict[str, Any]:
    return {"type": "tool_call", "data": {"name": name, **data}}


class Recorder:
    """A send function that notes when each line went out."""

    def __init__(self, clock: FakeClock, fail: bool = False) -> None:
        self.clock = clock
        self.fail = fail
        self.lines: list[tuple[float, str]] = []

    async def __call__(self, line: str) -> None:
        self.lines.append((self.clock.t, line))
        if self.fail:
            raise RuntimeError("telegram down")

    @property
    def texts(self) -> list[str]:
        return [line for _, line in self.lines]


# -- phrases -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "phrase"),
    [
        ({"name": "web.search"}, "Searching the web…"),
        ({"name": "web.fetch_page", "host": "example.com"}, "Reading example.com…"),
        ({"name": "web.fetch_page"}, "Reading a web page…"),
        ({"name": "web.screenshot", "host": "example.com"}, "Taking a screenshot…"),
        (
            {"name": "browser.read", "action": "open", "host": "canvas.nyit.edu"},
            "Opening canvas.nyit.edu…",
        ),
        ({"name": "browser.read", "action": "open"}, "Opening a web page…"),
        ({"name": "browser.read", "action": "click"}, "Clicking on the page…"),
        ({"name": "browser.read", "action": "snapshot"}, "Reading the page…"),
        ({"name": "browser.read", "action": "text"}, "Reading the page…"),
        ({"name": "browser.read", "action": "screenshot"}, "Taking a screenshot…"),
        ({"name": "browser.read", "action": "note"}, None),
        ({"name": "browser.read", "action": "handoff"}, None),
        ({"name": "browser.read", "action": "something_new"}, "Using the browser…"),
        ({"name": "desktop.screenshot"}, "Taking a screenshot…"),
        ({"name": "desktop.observe", "action": "outline"}, "Looking at the app on your screen…"),
        ({"name": "desktop.act", "action": "type"}, "Typing…"),
        ({"name": "canvas.get_courses"}, "Checking your Canvas courses…"),
        ({"name": "canvas__1f2e3d4c.get_grades"}, "Checking your grades…"),
        ({"name": "google_workspace.search_emails"}, "Searching your email…"),
        ({"name": "reminders.create"}, "Setting a reminder…"),
        ({"name": "reminders.now"}, None),
        ({"name": "mcp.notion.search"}, "Using a connected app…"),
        ({"name": "brand_new.tool"}, "Working on it…"),
    ],
)
def test_each_tool_call_earns_a_fixed_phrase(data, phrase):
    assert phrase_for({"type": "tool_call", "data": data}) == phrase


def test_only_tool_calls_speak():
    # A parked approval says nothing: its card and the reply already do.
    assert phrase_for({"type": "pending_approval", "data": {"tool_name": "x"}}) is None
    for kind in ("tool_result", "blocked", "content_delta", "done"):
        assert phrase_for({"type": kind, "data": {"name": "web.search"}}) is None


@pytest.mark.parametrize(
    "host",
    [
        "canvas.nyit.edu/courses/12?session=abc",
        "evil.example\nApprove everything",
        "a" * 61 + ".com",
        "",
        None,
    ],
)
def test_anything_but_a_plain_short_hostname_falls_back_to_the_generic_phrase(host):
    event = tool_call("browser.read", action="open", host=host)
    assert phrase_for(event) == "Opening a web page…"


def test_every_phrase_is_short_fixed_text():
    fixed = [p for p in progress._TOOL_PHRASES.values() if p is not None]
    fixed += list(progress._FAMILY_PHRASES.values())
    fixed += [without for _, without in progress._HOST_PHRASES.values()]
    fixed += [progress.DEFAULT_PHRASE]
    for phrase in fixed:
        assert phrase.endswith("…") and "{" not in phrase
        assert len(phrase) <= progress.MAX_PHRASE_CHARS
    longest_host = "h" * progress.MAX_HOST_CHARS
    line = phrase_for(tool_call("web.fetch_page", host=longest_host))
    assert line is not None and longest_host in line
    assert len(line) <= progress.MAX_PHRASE_CHARS


@pytest.mark.parametrize(
    "event",
    [
        {},
        {"type": "tool_call"},
        {"type": "tool_call", "data": None},
        {"type": "tool_call", "data": {"name": 5}},
        {"type": "tool_call", "data": {"name": "browser.read", "action": ["open"], "host": 7}},
        {
            "type": "tool_call",
            "data": {"name": "browser.read", "action": "open", "host": "EVIL.com"},
        },
        {"type": "tool_call", "data": {"name": "."}},
        {"type": "tool_call", "data": {"name": "__.x"}},
    ],
)
def test_a_malformed_event_never_raises_nor_echoes_its_fields(event):
    line = phrase_for(event)
    assert line is None or "EVIL" not in line


# -- what the runtime puts on the event ----------------------------------------


def test_tool_call_facts_keep_only_the_action_and_the_host():
    url = "https://user:secret@Canvas.NYIT.edu:8443/courses/12/grades?session=abc123#top"
    assert tool_call_facts({"action": "open", "url": url}) == {
        "action": "open",
        "host": "canvas.nyit.edu",
    }
    assert tool_call_facts({"query": "cheap flights to Miami"}) == {}
    assert tool_call_facts({"action": "type", "text": "hunter2", "ref": "d4"}) == {"action": "type"}
    assert tool_call_facts({"url": "file:///etc/passwd"}) == {}
    assert tool_call_facts({"url": "http://[::1"}) == {}
    assert tool_call_facts({"url": "https://example.com./a"}) == {"host": "example.com"}
    assert tool_call_facts({"action": "Open it now!"}) == {}
    assert tool_call_facts("not arguments") == {}


@pytest.mark.parametrize(
    ("url", "host"),
    [
        # A browser reads "\" as "/" and would go to evil.com: no host at all.
        ("https://evil.com\\@canvas.nyit.edu/x", None),
        ("https:\\\\evil.com/", None),
        ("https://canvas.nyit.edu%2F@evil.com/", "evil.com"),
        ("HTTPS://Canvas.NYIT.edu", "canvas.nyit.edu"),
        ("https://canv\tas.nyit.edu/", "canvas.nyit.edu"),
        ("https://bücher.de/", None),
        ("canvas.nyit.edu/courses", None),
        ("https://" + "a" * 5000 + ".com", None),
        ("https://[::1]/", None),
        ("https://10.0.0.1:99999/", "10.0.0.1"),
    ],
)
def test_the_host_is_the_one_a_browser_would_open_or_nothing(url, host):
    assert tool_call_facts({"action": "open", "url": url}).get("host") == host


@pytest.mark.asyncio
async def test_the_runtime_tool_call_event_names_the_host_never_the_url():
    provider = RecordingProvider(
        [
            call(
                "browser.read",
                action="open",
                url="https://canvas.nyit.edu/courses/12?session=abc123",
            ),
            call("web.search", query="nyit registrar hours"),
            LLMResponse(content="done"),
        ]
    )
    events: list[dict[str, Any]] = []

    async def sink(event: dict[str, Any]) -> None:
        events.append(event)

    runtime = runtime_with(provider, RecordingExecutor())
    await runtime.chat(
        messages=[{"role": "user", "content": "check canvas"}],
        tools=[BROWSER_TOOL, WEB_TOOL],
        user_id="u1",
        event_sink=sink,
    )
    assert [e["data"] for e in events if e["type"] == "tool_call"] == [
        {"name": "browser.read", "action": "open", "host": "canvas.nyit.edu"},
        {"name": "web.search"},
    ]
    streamed = json.dumps(events)
    assert "abc123" not in streamed and "/courses" not in streamed
    assert "registrar" not in streamed


# -- pacing --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lines_wait_out_the_grace_period_and_then_one_per_interval(clock):
    sent = Recorder(clock)
    turn = TurnProgress(sent)
    await clock.advance(0.5)
    await turn.on_event(tool_call("web.search"))
    await clock.advance(1.0)
    assert sent.lines == []  # 1.5 s in: a quick answer would still arrive alone
    await clock.advance(0.5)
    assert sent.lines == [(2.0, "Searching the web…")]

    await turn.on_event(tool_call("web.fetch_page", host="example.com"))
    await clock.advance(1.0)
    await turn.on_event(tool_call("browser.read", action="open", host="canvas.nyit.edu"))
    await clock.advance(2.5)
    assert len(sent.lines) == 1  # 5.5 s: the interval since 2.0 has not passed
    await clock.advance(0.5)
    # Only the newest phrase goes out; "Reading example.com…" was stale.
    assert sent.lines[-1] == (6.0, "Opening canvas.nyit.edu…")
    await close(turn, clock)


@pytest.mark.asyncio
async def test_the_same_phrase_is_never_sent_twice_in_a_row(clock):
    sent = Recorder(clock)
    turn = TurnProgress(sent)
    await clock.advance(2)
    for action in ("snapshot", "find", "text", "scroll", "snapshot"):
        await turn.on_event(tool_call("browser.read", action=action))
        await clock.advance(4)
    assert sent.texts == ["Reading the page…", "Scrolling the page…", "Reading the page…"]
    await close(turn, clock)


@pytest.mark.asyncio
async def test_a_turn_sends_at_most_six_lines(clock):
    sent = Recorder(clock)
    turn = TurnProgress(sent)
    names = [
        "web.search",
        "canvas.get_courses",
        "canvas.get_grades",
        "google_workspace.get_messages",
        "google_workspace.get_events",
        "reminders.list",
        "system.capabilities",
        "robinhood.get_crypto_prices",
    ]
    await clock.advance(2)
    for name in names:
        await turn.on_event(tool_call(name))
        await clock.advance(4)
    assert len(sent.lines) == progress.MAX_PER_TURN == 6
    assert sent.texts[-1] == "Checking your reminders…"
    await close(turn, clock)
    await turn.on_event(tool_call("reminders.create"))
    await clock.advance(10)
    assert len(sent.lines) == 6


@pytest.mark.asyncio
async def test_a_turn_that_ends_within_the_grace_period_sends_nothing(clock):
    sent = Recorder(clock)
    turn = TurnProgress(sent)
    await clock.advance(0.5)
    await turn.on_event(tool_call("web.search"))
    await turn.on_event({"type": "pending_approval", "data": {}})
    await clock.advance(1.0)
    await turn.aclose()
    await clock.advance(10)
    await turn.on_event(tool_call("desktop.screenshot"))
    await clock.advance(10)
    assert sent.lines == []


@pytest.mark.asyncio
async def test_a_failing_send_is_dropped_and_the_next_line_still_goes(clock):
    sent = Recorder(clock, fail=True)
    turn = TurnProgress(sent)
    await clock.advance(2)
    await turn.on_event(tool_call("web.search"))
    await clock.advance(4)
    await turn.on_event(tool_call("desktop.screenshot"))
    await clock.advance(4)
    assert sent.texts == ["Searching the web…", "Taking a screenshot…"]
    await turn.aclose()


@pytest.mark.asyncio
async def test_closing_lets_a_line_already_on_its_way_land_first(clock):
    gate = asyncio.Event()
    landed: list[str] = []

    async def slow_send(line: str) -> None:
        await gate.wait()
        landed.append(line)

    turn = TurnProgress(slow_send)
    await clock.advance(2)
    await turn.on_event(tool_call("web.search"))
    await settle()
    # A newer phrase queued behind the send in flight is simply dropped.
    await turn.on_event(tool_call("desktop.screenshot"))
    closing = asyncio.create_task(turn.aclose())
    await settle()
    assert not closing.done()  # the reply waits for the line in flight
    gate.set()
    await settle()
    assert landed == ["Searching the web…"]
    assert not closing.done()  # ...then out the reply gap after it
    # ...and only that: not the queued one's interval, nor the whole
    # SEND_WAIT_S.
    await clock.advance(progress.REPLY_GAP_S)
    await asyncio.wait_for(closing, timeout=0.5)
    assert landed == ["Searching the web…"]


@pytest.mark.asyncio
async def test_the_reply_waits_until_the_last_line_is_a_second_old(clock):
    sent = Recorder(clock)
    turn = TurnProgress(sent)
    await clock.advance(2)
    await turn.on_event(tool_call("web.search"))
    await settle()
    assert sent.lines == [(2.0, "Searching the web…")]
    await clock.advance(0.25)
    closing = asyncio.create_task(turn.aclose())
    await clock.advance(0.5)
    assert not closing.done()  # 2.75 s: the line is not a second old yet
    await clock.advance(0.25)
    await asyncio.wait_for(closing, timeout=1)
    assert clock.t == 3.0


@pytest.mark.asyncio
async def test_a_line_a_second_old_or_more_holds_nothing_back(clock):
    sent = Recorder(clock)
    turn = TurnProgress(sent)
    await clock.advance(2)
    await turn.on_event(tool_call("web.search"))
    await settle()
    assert sent.lines == [(2.0, "Searching the web…")]
    await clock.advance(progress.REPLY_GAP_S)
    # Nothing moves the clock here: the close must not wait on it.
    await asyncio.wait_for(turn.aclose(), timeout=1)
    assert sent.lines == [(2.0, "Searching the web…")]


# -- on Telegram ---------------------------------------------------------------


async def drain(service, clock: FakeClock) -> None:
    """Let the chat's work finish while the fake clock moves on, so a reply
    waiting out its gap after a progress line can go."""
    for _ in range(400):
        if not service._chat_tasks:
            return
        await asyncio.sleep(0.005)
        await clock.advance(0.25)
    raise AssertionError("the chat's work did not finish")


class StampedAPI(FakeTelegramAPI):
    """Notes the fake time at which each chat message went out."""

    def __init__(self, clock: FakeClock) -> None:
        super().__init__()
        self.clock = clock
        self.stamps: list[tuple[float, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/sendMessage"):
            payload = json.loads(request.content or b"{}")
            self.stamps.append((self.clock.t, payload.get("text", "")))
        return super().handler(request)


@pytest.mark.asyncio
async def test_a_parked_turn_sends_no_approval_line_and_its_reply_comes_a_second_later(
    session_factory, monkeypatch, clock
):
    """A turn that ends by parking an approval: its card and reply already
    say so, so the only line is the step before it, and the reply comes at
    least a second after that line (Telegram asks for about one message per
    second per chat)."""
    api = _install(monkeypatch, StampedAPI(clock))
    await _link(session_factory, "tg-progress-gap@example.com", 5050)

    async def chat(user_id, text, *, new_conversation=False, on_event=None):
        await clock.advance(2)
        await on_event(tool_call("web.search"))
        await clock.advance(0.25)
        await on_event(
            {"type": "pending_approval", "data": {"tool_name": "google_workspace.send_email"}}
        )
        await clock.advance(0.25)
        return {"content": "Drafted it.", "pending_approvals": ["google_workspace.send_email"]}

    service = _service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(5050, "email my prof"))
    await drain(service, clock)
    texts = [text for _, text in api.stamps]
    assert len(texts) == 2
    assert texts[0] == "Searching the web…"
    assert texts[1].startswith("Drafted it.")
    (line_at, _), (reply_at, _) = api.stamps
    assert reply_at - line_at >= progress.REPLY_GAP_S
    await service._client.aclose()


def _progress_sends(api: FakeTelegramAPI) -> list[dict[str, Any]]:
    return [p for p in api.sent_messages() if p.get("disable_notification")]


@pytest.mark.asyncio
async def test_a_real_turn_reports_its_steps_and_then_the_unchanged_reply(
    session_factory, telegram_api, clock
):
    """Runtime → chat applier → TelegramService, end to end: each tool takes
    five (fake) seconds, so every step earns its line."""
    from api.routes.agent import build_chat_applier
    from main import app

    await _link(session_factory, "tg-progress-e2e@example.com", 4242)

    class TimedExecutor(RecordingExecutor):
        async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
            for _ in range(5):
                await clock.advance(1)
            return await super().execute(tool_name, arguments, user_id, approved, task_id=task_id)

    provider = RecordingProvider(
        [
            call("web.search", query="nyit canvas login"),
            call(
                "browser.read",
                action="open",
                url="https://canvas.nyit.edu/courses/12/grades?session=abc123",
            ),
            call("browser.read", action="screenshot"),
            LLMResponse(content=REPLY),
        ]
    )
    saved = dict(app.state._state)
    app.state.agent_runtime = runtime_with(provider, TimedExecutor())
    app.state.installation = None
    service = _service(session_factory)
    service.chat = build_chat_applier(app, session_factory=session_factory)
    try:
        await service._handle_message(telegram_dm(4242, "what's my CSCI 380 grade?"))
        await service.wait_for_chats()
    finally:
        app.state._state.clear()
        app.state._state.update(saved)
        await service._client.aclose()

    texts = [m["text"] for m in telegram_api.sent_messages()]
    assert texts[:-1] == ["Searching the web…", "Opening canvas.nyit.edu…", "Taking a screenshot…"]
    assert all("abc123" not in t and "/courses" not in t for t in texts[:-1])
    # The final reply is the model's answer exactly as before (then its cost
    # line), and it is the last message of the turn: no progress line can
    # land after it.
    final = telegram_api.sent_messages()[-1]
    reply, _, cost = final["text"].rpartition("\n\n")
    assert reply == REPLY and " tokens · " in cost
    assert "disable_notification" not in final
    for line in _progress_sends(telegram_api):
        assert line["chat_id"] == 4242
        assert line["link_preview_options"] == {"is_disabled": True}


@pytest.mark.asyncio
async def test_a_quick_turn_sends_only_its_reply(session_factory, telegram_api, clock):
    await _link(session_factory, "tg-progress-quick@example.com", 4343)
    seen: list[Optional[object]] = []

    async def chat(user_id, text, *, new_conversation=False, on_event=None):
        seen.append(on_event)
        await clock.advance(0.5)
        await on_event(tool_call("web.search"))
        await clock.advance(1.0)
        return {"content": "It is 72°F and sunny."}

    service = _service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(4343, "weather?"))
    await service.wait_for_chats()
    await clock.advance(10)
    assert seen and seen[0] is not None
    assert [m["text"] for m in telegram_api.sent_messages()] == ["It is 72°F and sunny."]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_failed_progress_sends_never_touch_the_turn(session_factory, monkeypatch, clock):
    api = _install(monkeypatch, FailingProgressAPI())
    await _link(session_factory, "tg-progress-fail@example.com", 4444)

    async def chat(user_id, text, *, new_conversation=False, on_event=None):
        await clock.advance(2)
        await on_event(tool_call("web.search"))
        await clock.advance(4)
        await on_event(
            tool_call(
                "browser.read",
                **tool_call_facts(
                    {"action": "open", "url": "https://www.google.com/travel/flights?q=JFK"}
                ),
            )
        )
        await clock.advance(4)
        return {"content": REPLY, "pending_approvals": []}

    service = _service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(4444, "flights to Miami?"))
    await drain(service, clock)
    failed = [p["text"] for m, p in api.calls if m == "sendMessage-failed"]
    assert failed == ["Searching the web…", "Opening www.google.com…"]
    assert [m["text"] for m in api.sent_messages()] == [REPLY]
    await service._client.aclose()


def test_on_event_goes_only_to_a_callback_that_takes_it():
    async def before_progress(user_id, text, *, new_conversation=False):
        return {}

    async def named(user_id, text, *, new_conversation=False, on_event=None):
        return {}

    async def open_ended(user_id, text, **kwargs):
        return {}

    assert not takes_on_event(before_progress)
    assert takes_on_event(named) and takes_on_event(open_ended)


@pytest.mark.asyncio
async def test_a_chat_callback_without_on_event_still_answers(session_factory, telegram_api):
    """A callback written before progress lines existed (a teammate's test
    fake, an older applier) runs its turn and gets its reply, with no lines,
    instead of a TypeError and the generic error reply."""
    await _link(session_factory, "tg-progress-oldsig@example.com", 4545)

    async def chat(user_id, text, *, new_conversation=False):
        return {"content": "hello"}

    service = _service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(4545, "hi"))
    await service.wait_for_chats()
    assert [m["text"] for m in telegram_api.sent_messages()] == ["hello"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_two_chats_at_once_each_get_only_their_own_lines(
    session_factory, telegram_api, clock
):
    await _link(session_factory, "tg-progress-a@example.com", 4646)
    await _link(session_factory, "tg-progress-b@example.com", 4747)
    gate = asyncio.Event()

    async def chat(user_id, text, *, new_conversation=False, on_event=None):
        await gate.wait()
        await on_event(tool_call("web.search" if text == "a" else "desktop.screenshot"))
        await clock.advance(3)
        return {"content": f"reply {text}"}

    service = _service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(4646, "a"))
    await service._handle_message(telegram_dm(4747, "b"))
    await asyncio.sleep(0)
    gate.set()
    await drain(service, clock)
    by_chat: dict[int, list[str]] = {}
    for m in telegram_api.sent_messages():
        by_chat.setdefault(m["chat_id"], []).append(m["text"])
    assert by_chat == {
        4646: ["Searching the web…", "reply a"],
        4747: ["Taking a screenshot…", "reply b"],
    }
    await service._client.aclose()


class HangingProgressAPI(FakeTelegramAPI):
    """Telegram that accepts every progress line (the silent sends) and then
    never answers until released; everything else is answered at once."""

    def __init__(self) -> None:
        super().__init__()
        self.release = asyncio.Event()

    async def ahandler(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content or b"{}")
        if payload.get("disable_notification"):
            self.calls.append(("progress-started", payload))
            await self.release.wait()
        return self.handler(request)


@pytest.fixture
def hanging_api(monkeypatch):
    api = HangingProgressAPI()
    real_client_cls = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real_client_cls(**{**kw, "transport": httpx.MockTransport(api.ahandler)}),
    )
    monkeypatch.setattr(progress, "SEND_WAIT_S", 0.3)
    return api


@pytest.mark.asyncio
async def test_a_hung_progress_send_holds_the_reply_back_only_briefly(
    session_factory, hanging_api, clock
):
    await _link(session_factory, "tg-progress-hang@example.com", 4848)

    async def chat(user_id, text, *, new_conversation=False, on_event=None):
        await clock.advance(2)
        await on_event(tool_call("web.search"))
        await clock.advance(0.1)
        return {"content": "final"}

    service = _service(session_factory)
    service.chat = chat
    started = time.monotonic()
    await service._handle_message(telegram_dm(4848, "q"))
    await asyncio.wait_for(service.wait_for_chats(), timeout=5)
    assert time.monotonic() - started < 2.0
    started_lines = [p["text"] for m, p in hanging_api.calls if m == "progress-started"]
    assert started_lines == ["Searching the web…"]
    # The hung line was abandoned; the reply went out regardless.
    assert [m["text"] for m in hanging_api.sent_messages()] == ["final"]
    await service._client.aclose()


@pytest.mark.asyncio
async def test_stopping_the_bot_mid_send_neither_hangs_nor_raises(
    session_factory, hanging_api, clock
):
    await _link(session_factory, "tg-progress-stop@example.com", 4949)
    forever = asyncio.Event()

    async def chat(user_id, text, *, new_conversation=False, on_event=None):
        await clock.advance(2)
        await on_event(tool_call("web.search"))
        await clock.advance(0.1)
        await forever.wait()
        return {"content": "never"}

    service = _service(session_factory)
    service.chat = chat
    await service._handle_message(telegram_dm(4949, "q"))
    for _ in range(300):
        if any(m == "progress-started" for m, _ in hanging_api.calls):
            break
        await asyncio.sleep(0.01)
    assert [m for m, _ in hanging_api.calls if m == "progress-started"] == ["progress-started"]
    await asyncio.wait_for(service.stop(), timeout=5)
    senders = [t for t in asyncio.all_tasks() if t.get_name() == "chat-progress"]
    assert all(t.done() or t.cancelling() for t in senders)
