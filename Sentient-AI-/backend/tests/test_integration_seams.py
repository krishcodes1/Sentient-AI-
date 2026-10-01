"""Tests for the wave-0 integration seams the top10 skills build on: the
reserved migration chain (0017-0024), TurnContext, the single model-call
method (AgentRuntime._provider_complete) and the provider-first order in
chat(), Gemini's _post_with_retries, the default_provider report fact, the
Telegram and Slack dispatch tables, and the top10 anchor comments.

Why it exists: ten skills are built in parallel from this base and merged one
by one; each seam is where their changes meet, so its shape and the behaviour
it replaced (same help text, same keywords, same retries) are pinned here. The
anchor test goes with the anchors in the cleanup PR that removes them. No real
network, provider, Telegram or Slack: everything is faked.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from core.config import settings
from tests.conftest import make_user, telegram_dm

BACKEND_DIR = Path(__file__).resolve().parents[1]
APP_DIR = BACKEND_DIR.parent

# The canonical order of the top10 skills (every anchor group follows it).
KEYS = [
    "secret_pii_redaction",
    "file_extraction",
    "scheduler_briefing",
    "tutor_mode",
    "knowledge_base",
    "flashcards_quizzes",
    "event_triggers",
    "permission_tiers",
    "voice_notes",
    "video_transcripts",
]


# ── the reserved migration chain ─────────────────────────────────────────────

# (revision, down_revision, the skill that fills it)
RESERVED = [
    ("0017_scheduled_tasks", "0016_merge_app_approvals", "scheduler_briefing"),
    ("0018_user_files", "0017_scheduled_tasks", "file_extraction"),
    ("0019_tutor_mode", "0018_user_files", "tutor_mode"),
    ("0020_knowledge_base", "0019_tutor_mode", "knowledge_base"),
    ("0021_study", "0020_knowledge_base", "flashcards_quizzes"),
    ("0022_event_triggers", "0021_study", "event_triggers"),
    ("0023_permission_grants", "0022_event_triggers", "permission_tiers"),
    ("0024_media_transcripts", "0023_permission_grants", "video_transcripts"),
]


def _alembic(db_path: Path) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.attributes["sqlalchemy_url"] = f"sqlite+aiosqlite:///{db_path}"
    config.attributes["configure_logger"] = False
    return config


def test_the_reserved_revisions_form_one_linear_chain_from_0016_to_0024():
    script = ScriptDirectory.from_config(_alembic(Path("unused.db")))
    assert script.get_heads() == ["0024_media_transcripts"]
    # Walking down from the head passes through exactly the reserved ids, in
    # order, and lands on the 0016 merge.
    walked = []
    revision = script.get_revision("0024_media_transcripts")
    while revision is not None and revision.revision != "0016_merge_app_approvals":
        walked.append((revision.revision, revision.down_revision))
        revision = script.get_revision(revision.down_revision)
    assert list(reversed(walked)) == [(rev, down) for rev, down, _ in RESERVED]
    # Linear: nothing else branches off the chain.
    assert script.get_revision("0016_merge_app_approvals").nextrev == frozenset(
        {"0017_scheduled_tasks"}
    )
    for (rev, _, _), (child, _, _) in zip(RESERVED, RESERVED[1:], strict=False):
        assert script.get_revision(rev).nextrev == frozenset({child})
    assert script.get_revision("0024_media_transcripts").nextrev == frozenset()


def test_each_reserved_revision_lives_in_its_own_file():
    versions = BACKEND_DIR / "alembic" / "versions"
    for rev, down, _skill in RESERVED:
        source = (versions / f"{rev}.py").read_text(encoding="utf-8")
        assert f'revision = "{rev}"' in source
        assert f'down_revision = "{down}"' in source


def test_the_chain_upgrades_and_downgrades_end_to_end(tmp_path):
    db_path = tmp_path / "chain.db"
    config = _alembic(db_path)
    command.upgrade(config, "head")
    command.downgrade(config, "0016_merge_app_approvals")
    command.upgrade(config, "head")


# ── TurnContext ──────────────────────────────────────────────────────────────


def test_turn_context_has_the_three_fields_and_later_ones_have_defaults():
    from api.routes.agent import TurnContext

    assert TurnContext._fields[:3] == ("tools", "memory_block", "permissions_text")
    # A field added later needs a default, so no caller changes.
    assert all(name in TurnContext._field_defaults for name in TurnContext._fields[3:])


def test_build_tools_and_memory_takes_the_conversation_as_a_keyword():
    from api.routes.agent import _build_tools_and_memory

    parameter = inspect.signature(_build_tools_and_memory).parameters["conversation"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is None


def test_every_route_call_site_passes_the_conversation_and_reads_attributes():
    tree = ast.parse((BACKEND_DIR / "api" / "routes" / "agent.py").read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_build_tools_and_memory"
    ]
    # send_message, stream_message, _resume_after_approval, build_chat_applier,
    # build_unattended_runner (scheduler_briefing).
    assert len(calls) == 5
    assert all(any(k.arg == "conversation" for k in call.keywords) for call in calls)
    # No caller unpacks the result: a field added later would break it.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Tuple):
            value = node.value.value if isinstance(node.value, ast.Await) else node.value
            assert not (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "_build_tools_and_memory"
            )


@pytest.mark.asyncio
async def test_build_tools_and_memory_returns_a_turn_context(session_factory):
    from api.routes.agent import TurnContext, _build_tools_and_memory
    from models.conversation import Conversation

    user, _ = await make_user(session_factory, "seams-turn-context@example.com")
    async with session_factory() as db:
        conversation = Conversation(user_id=user.id, title="Seams")
        db.add(conversation)
        await db.flush()
        built = await _build_tools_and_memory(None, user, db, conversation=conversation)
        unwired = await _build_tools_and_memory(None, user, db)
    assert isinstance(built, TurnContext)
    assert built.permissions_text.startswith("<permissions>")
    assert {t.name for t in built.tools} == {t.name for t in unwired.tools}
    assert built.memory_block == unwired.memory_block


# ── the single model call, and the provider-first order ──────────────────────


def _runtime_source() -> str:
    return (BACKEND_DIR / "services" / "agent" / "runtime.py").read_text(encoding="utf-8")


def _methods(tree: ast.AST) -> dict[str, ast.AST]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "AgentRuntime":
            return {
                item.name: item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    raise AssertionError("AgentRuntime not found")


def test_runtime_calls_the_provider_only_inside_provider_complete():
    source = _runtime_source()
    assert source.count("provider.complete(") == 1
    line = source[: source.index("provider.complete(")].count("\n") + 1
    methods = _methods(ast.parse(source))
    seam = methods["_provider_complete"]
    assert seam.lineno <= line <= seam.end_lineno
    # _run_turn's model rounds go through it.
    run_turn = methods["_run_turn"]
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_provider_complete"
        for node in ast.walk(run_turn)
    )


class _Source:
    async def llm_defaults(self) -> tuple[str, str]:
        return "gemini", "gemini-2.5-flash"

    async def llm_api_key(self, provider: str) -> str:
        return "test-key"


class _FakeProvider:
    supports_vision = False

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def complete(self, messages, tools=None):
        from services.agent.providers import LLMResponse

        self.calls.append({"messages": list(messages), "tools": tools})
        return LLMResponse(content="hi", tool_calls=[])

    async def stream(self, messages, tools=None):
        yield "hi"

    async def aclose(self) -> None:
        return None


def _runtime(monkeypatch) -> tuple[Any, _FakeProvider]:
    import services.agent.runtime as rt
    from services.agent.approvals import InMemoryApprovalStore

    provider = _FakeProvider()
    monkeypatch.setattr(rt, "create_provider", lambda **_kwargs: provider)
    runtime = rt.AgentRuntime(
        config=settings, approval_store=InMemoryApprovalStore(), settings_source=_Source()
    )
    return runtime, provider


@pytest.mark.asyncio
async def test_a_turn_asks_the_model_through_provider_complete(monkeypatch):
    from services.agent.runtime import SECURITY_SYSTEM_PROMPT, AgentRuntime

    runtime, provider = _runtime(monkeypatch)
    seen: list[dict[str, Any]] = []
    real = AgentRuntime._provider_complete

    async def recording(self, llm, *, messages, tools, **kwargs):
        seen.append({"llm": llm, "tools": tools, "kwargs": kwargs})
        return await real(self, llm, messages=messages, tools=tools, **kwargs)

    monkeypatch.setattr(AgentRuntime, "_provider_complete", recording)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "hello"}], tools=[], user_id="seams-user"
    )
    assert response.content == "hi"
    assert seen == [{"llm": provider, "tools": None, "kwargs": {}}]
    assert len(provider.calls) == 1
    assert provider.calls[0]["messages"][0]["content"].startswith(SECURITY_SYSTEM_PROMPT)


@pytest.mark.asyncio
async def test_chat_picks_the_provider_before_it_builds_the_system_prompt(monkeypatch):
    runtime, _provider = _runtime(monkeypatch)
    order: list[str] = []
    real_select = runtime._select_provider
    real_prompt = runtime._with_system_prompt

    async def select(provider_name, model):
        order.append("provider")
        return await real_select(provider_name, model)

    def prompt(*args, **kwargs):
        order.append("system_prompt")
        return real_prompt(*args, **kwargs)

    monkeypatch.setattr(runtime, "_select_provider", select)
    monkeypatch.setattr(runtime, "_with_system_prompt", prompt)
    response = await runtime.chat(
        messages=[{"role": "user", "content": "hello"}], tools=[], user_id="seams-order"
    )
    assert order == ["provider", "system_prompt"]
    assert (response.provider, response.model) == ("gemini", "gemini-2.5-flash")


# ── Gemini's _post_with_retries ──────────────────────────────────────────────


class _Google:
    """Answers each request with the next scripted response."""

    def __init__(self) -> None:
        self.script: list[httpx.Response | Exception] = []
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.script.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def google(monkeypatch):
    fake = _Google()
    real_client_cls = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(fake.handle)
        return real_client_cls(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return fake


@pytest.fixture
def pauses(monkeypatch) -> list[float]:
    from services.agent.providers import GeminiProvider

    slept: list[float] = []

    async def record(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(GeminiProvider, "_retry_sleep", staticmethod(record))
    return slept


EMBEDDINGS = {"embeddings": [{"values": [0.1, 0.2]}]}


@pytest.mark.asyncio
async def test_post_with_retries_returns_the_body_after_the_same_retries(google, pauses):
    from services.agent.providers import GeminiProvider

    google.script = [
        httpx.Response(503, text="overloaded"),
        httpx.ReadTimeout("read timed out"),
        httpx.Response(200, json=EMBEDDINGS),
    ]
    provider = GeminiProvider(api_key="AIza-secret")
    try:
        url = provider._build_url("batchEmbedContents")
        body = await provider._post_with_retries(url, {"requests": []})
    finally:
        await provider.aclose()
    assert body == EMBEDDINGS
    assert pauses == [1.0, 2.0]
    assert [str(r.url) for r in google.requests] == [url] * 3
    # The client's own timeout applies when none is given.
    assert google.requests[0].extensions["timeout"]["read"] == 120.0


@pytest.mark.asyncio
async def test_post_with_retries_gives_up_on_an_error_that_would_repeat(google, pauses):
    from services.agent.providers import GeminiProvider, ProviderError

    google.script = [httpx.Response(400, text="API key not valid")]
    provider = GeminiProvider(api_key="AIza-secret")
    try:
        with pytest.raises(ProviderError) as excinfo:
            await provider._post_with_retries(provider._build_url(), {"contents": []})
    finally:
        await provider.aclose()
    assert excinfo.value.status_code == 400
    assert "AIza-secret" not in str(excinfo.value)
    assert "generativelanguage" not in str(excinfo.value)
    assert len(google.requests) == 1 and pauses == []


@pytest.mark.asyncio
async def test_post_with_retries_takes_a_timeout_for_one_request(google, pauses):
    from services.agent.providers import GeminiProvider

    google.script = [httpx.Response(200, json=EMBEDDINGS)]
    provider = GeminiProvider(api_key="AIza-secret")
    try:
        await provider._post_with_retries(provider._build_url(), {}, timeout=5.0)
    finally:
        await provider.aclose()
    assert google.requests[0].extensions["timeout"] == {
        "connect": 5.0,
        "read": 5.0,
        "write": 5.0,
        "pool": 5.0,
    }


@pytest.mark.asyncio
async def test_a_body_accept_refuses_is_asked_again_within_the_budget(google, pauses):
    from services.agent.providers import GeminiProvider, ProviderError

    def accept(body: dict[str, Any]) -> None:
        if not body.get("embeddings"):
            raise ProviderError("gemini", None, "blank", retryable=True)

    google.script = [
        httpx.Response(200, json={"embeddings": []}),
        httpx.Response(200, json=EMBEDDINGS),
    ]
    provider = GeminiProvider(api_key="AIza-secret")
    try:
        body = await provider._post_with_retries(provider._build_url(), {}, accept=accept)
    finally:
        await provider.aclose()
    assert body == EMBEDDINGS and pauses == [1.0]


def test_complete_goes_through_post_with_retries():
    from services.agent.providers import GeminiProvider

    assert "self._post_with_retries(" in inspect.getsource(GeminiProvider.complete)


# ── the default_provider report fact ─────────────────────────────────────────


def test_report_context_carries_the_default_provider_last():
    from services import capabilities as registry
    from services.capabilities.base import ReportContext

    fields = dataclasses.fields(ReportContext)
    names = [f.name for f in fields]
    field = fields[names.index("default_provider")]
    assert (field.name, field.default) == ("default_provider", "")
    # Later top10 facts are appended after it, in wave order
    # (top10:knowledge_base added embedding_backend).
    later_order = ("local_ocr_installed", "embedding_backend", "speech_local_installed", "default_provider_audio")
    later = names[names.index("default_provider") + 1 :]
    assert later == [name for name in later_order if name in later]
    assert registry.default_context().default_provider == ""
    assert registry.default_context(default_provider="ollama").default_provider == "ollama"


@pytest.mark.asyncio
async def test_the_installation_report_follows_the_default_provider(
    session_factory, monkeypatch
):
    import services.installation as installation_module
    from services.installation import InstallationService

    monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic", raising=False)
    monkeypatch.setattr(settings, "LLM_MODEL", "claude-sonnet-5", raising=False)
    seen: list[str] = []
    real_report = installation_module.registry.report

    def recording(switches, ctx, **kwargs):
        seen.append(ctx.default_provider)
        return real_report(switches, ctx, **kwargs)

    monkeypatch.setattr(installation_module.registry, "report", recording)
    svc = InstallationService(session_factory)
    user, _ = await make_user(session_factory, "seams-provider@example.com")

    assert (await svc.context()).default_provider == "anthropic"
    await svc.report()
    await svc.report()  # cached
    assert seen == ["anthropic"]
    # An "llm" change drops the cached report, so the next one has the new
    # default provider.
    await svc.set_llm("gemini", "gemini-2.5-flash", "db-key", actor_id=user.id)
    await svc.report()
    assert seen == ["anthropic", "gemini"]


# ── Telegram: commands, help text and button routes ──────────────────────────

BUILTIN_COMMANDS = ["/stop", "/pending", "/new", "/usage", "/apps"]
# Today's /help reply, word for word.
GOLDEN_HELP = (
    "Just type a task or a question and the assistant answers "
    "here — with the same tools, memory and safety checks as "
    "the web app. When an action needs your permission, the "
    "request appears with Approve / Deny buttons. Each reply ends "
    "with what it used, e.g. “5.3k tokens · ≈$0.002”.\n\n"
    "/stop — stop the request that is running now\n"
    "/new — start a fresh conversation\n"
    "/pending — re-send every action waiting for your decision\n"
    "/apps — apps allowed for a week, with a button to revoke each\n"
    "/usage — tokens used today and over the last 30 days\n"
    "/help — this message"
)
LINKED_CHAT = 7101
UNLINKED_CHAT = 7102


def _telegram():
    from services.notifications.telegram import TelegramService

    service = TelegramService(token="123:fake-token", session_factory=lambda: None)
    sent: list[tuple[str, dict[str, Any]]] = []

    async def api(method: str, **params: Any) -> Any:
        sent.append((method, params))
        return {}

    async def user_for_chat(chat_id: Any):
        return "seams-user" if chat_id == LINKED_CHAT else None

    service._api = api  # type: ignore[method-assign]
    service._user_for_chat = user_for_chat  # type: ignore[method-assign]
    return service, sent


@pytest.mark.asyncio
async def test_telegram_registers_the_five_commands_first():
    service, _ = _telegram()
    # Skills append theirs under their anchors, after these.
    assert list(service._commands)[:5] == BUILTIN_COMMANDS
    # /start is answered before the link check and /help for any other
    # "/" word, so neither is in the table.
    assert "/start" not in service._commands and "/help" not in service._commands
    assert all(re.fullmatch(r"/[a-z_]+", name) for name in service._commands)
    await service._client.aclose()


@pytest.mark.asyncio
async def test_telegram_help_is_todays_text_and_new_lines_go_before_help(monkeypatch):
    from services.notifications import telegram

    service, sent = _telegram()
    monkeypatch.setattr(telegram, "HELP_LINES", telegram.HELP_LINES[:5])
    await service._handle_help(LINKED_CHAT)
    assert sent[-1] == ("sendMessage", {"chat_id": LINKED_CHAT, "text": GOLDEN_HELP})

    monkeypatch.setattr(
        telegram, "HELP_LINES", [*telegram.HELP_LINES, "/kb — search your notes"]
    )
    await service._handle_help(LINKED_CHAT)
    assert sent[-1][1]["text"] == GOLDEN_HELP.replace(
        "\n/help", "\n/kb — search your notes\n/help"
    )
    await service._client.aclose()


@pytest.mark.asyncio
async def test_telegram_commands_dispatch_as_before():
    service, _ = _telegram()
    calls: list[tuple[Any, ...]] = []

    def recorder(name: str):
        async def record(*args: Any) -> None:
            calls.append((name, *args))

        return record

    for name in (
        "_handle_stop",
        "_handle_pending",
        "_handle_new",
        "_handle_usage",
        "_handle_apps",
        "_handle_help",
        "_handle_chat",
        "_handle_start",
    ):
        setattr(service, name, recorder(name))

    for text in (
        "/stop",
        "/pending@crawler_test_bot",
        "/NEW",
        "/usage today please",
        "/apps",
        "/help",
        "/nosuchcommand",
        "what is due tomorrow",
        "/start abc123",
    ):
        await service._handle_message(telegram_dm(LINKED_CHAT, text))
    assert calls == [
        ("_handle_stop", LINKED_CHAT, "seams-user"),
        ("_handle_pending", LINKED_CHAT, "seams-user"),
        ("_handle_new", LINKED_CHAT),
        ("_handle_usage", LINKED_CHAT, "seams-user"),
        ("_handle_apps", LINKED_CHAT, "seams-user"),
        ("_handle_help", LINKED_CHAT),
        ("_handle_help", LINKED_CHAT),
        ("_handle_chat", LINKED_CHAT, "seams-user", "what is due tomorrow"),
        ("_handle_start", LINKED_CHAT, "abc123"),
    ]

    # An unlinked chat may only link: every command is dropped unanswered.
    calls.clear()
    for word in BUILTIN_COMMANDS:
        await service._handle_message(telegram_dm(UNLINKED_CHAT, word))
    await service._handle_message(telegram_dm(UNLINKED_CHAT, "/start code"))
    assert calls == [("_handle_start", UNLINKED_CHAT, "code")]

    # A registered command gets the chat, the account and its argument.
    service._commands["/echo"] = recorder("echo")
    await service._handle_message(telegram_dm(LINKED_CHAT, "/echo  some words "))
    assert calls[-1] == ("echo", LINKED_CHAT, "seams-user", "some words")
    await service._client.aclose()


def _press(data: str, chat_id: int) -> dict[str, Any]:
    return {
        "id": "press-1",
        "data": data,
        "from": {"id": chat_id, "is_bot": False},
        "message": {"message_id": 9, "chat": {"id": chat_id, "type": "private"}},
    }


def _answers(sent: list[tuple[str, dict[str, Any]]]) -> list[str]:
    return [p["text"] for m, p in sent if m == "answerCallbackQuery"]


@pytest.mark.asyncio
async def test_telegram_button_routes_dispatch_as_before():
    service, sent = _telegram()
    # The approval buttons stay inline; every other prefix is a route.
    assert "rva:" in service._callback_routes
    assert not {"apv:", "dny:", "apw:"} & set(service._callback_routes)
    assert all(len(prefix) == 4 and prefix.endswith(":") for prefix in service._callback_routes)

    revoked: list[tuple[Any, ...]] = []

    async def revoke(chat_id, user_id, approval_id, answer) -> None:
        revoked.append((chat_id, user_id, approval_id))
        await answer("Calendar revoked.")

    service._handle_revoke_app = revoke  # type: ignore[method-assign]

    await service._handle_callback(_press("zzz:whatever", LINKED_CHAT))
    assert _answers(sent) == ["Unknown action."]

    await service._handle_callback(_press("rva:approval-1", UNLINKED_CHAT))
    assert _answers(sent)[-1] == "This chat is not linked to a Crawler AI account."
    assert revoked == []

    await service._handle_callback(_press("rva:approval-1", LINKED_CHAT))
    assert revoked == [(LINKED_CHAT, "seams-user", "approval-1")]
    assert _answers(sent)[-1] == "Calendar revoked."

    # A registered route gets the (unchecked) chat, the target and answer.
    routed: list[tuple[Any, ...]] = []

    async def route(chat_id, target, answer) -> None:
        routed.append((chat_id, target))
        await answer("Routed.")

    service._callback_routes["tst:"] = route
    await service._handle_callback(_press("tst:abc", LINKED_CHAT))
    assert routed == [(LINKED_CHAT, "abc")]
    assert _answers(sent)[-1] == "Routed."
    await service._client.aclose()


# ── Slack: DM keywords ───────────────────────────────────────────────────────

TEAM = "T0TEAM001"
LINKED = "U0LINKED1"
DM = "D0DM00001"


def _slack():
    from services.connectors.slack import SlackConnector
    from services.notifications import slack as slack_mod

    connector = SlackConnector.from_credentials({"bot_token": "xoxb-x", "app_token": "xapp-x"})
    channel = slack_mod.SlackChannel(
        connector_id="11111111-1111-1111-1111-111111111111",
        user_id="22222222-2222-2222-2222-222222222222",
        bot_token="xoxb-x",
        app_token="xapp-x",
        session_factory=lambda: None,
        connector=connector,
    )
    channel.team_id = TEAM
    channel.bot_user_id = "U0BOT0001"
    link = SimpleNamespace(
        team_id=TEAM, slack_user_id=LINKED, link_code_hash=None, link_expires_at=None
    )

    async def load_link():
        return link

    channel._load_link = load_link  # type: ignore[method-assign]
    return channel


def _dm(text: str, n: int) -> dict[str, Any]:
    return {
        "type": "event_callback",
        "team_id": TEAM,
        "event_id": f"Ev{n:08d}",
        "event": {
            "type": "message",
            "channel": DM,
            "user": LINKED,
            "text": text,
            "ts": f"{n}.000100",
            "channel_type": "im",
        },
    }


@pytest.mark.asyncio
async def test_slack_keywords_dispatch_as_before_and_other_text_goes_to_chat():
    channel = _slack()
    assert channel._text_handlers[:3] == [
        channel._keyword_stop,
        channel._keyword_pending,
        channel._keyword_new,
    ]
    later: list[tuple[str, str]] = []
    chats: list[tuple[str, str]] = []

    def run_later(coro, name: str) -> None:
        # What would run off the socket loop, by task name and coroutine.
        later.append((name, coro.__qualname__))
        coro.close()

    channel._later = run_later  # type: ignore[method-assign]
    channel._handle_chat = lambda ch, text: chats.append((ch, text))  # type: ignore[method-assign]

    for n, text in enumerate(["STOP", "pending", "New", "stop the music", "hello"], start=1):
        await channel._on_events_api(_dm(text, n))
    assert later == [
        ("slack-stop", "SlackChannel._handle_stop"),
        ("slack-pending", "SlackChannel._handle_pending"),
        ("slack-new", "SlackChannel._say_fresh_start"),
    ]
    assert channel._fresh is True
    assert chats == [(DM, "stop the music"), (DM, "hello")]
    await channel._connector.close()


@pytest.mark.asyncio
async def test_slack_new_says_fresh_start_and_a_registered_handler_is_tried_in_order():
    from services.notifications import slack as slack_mod

    channel = _slack()
    posted: list[tuple[str, str]] = []
    handled: list[str] = []

    async def post_text(ch: str, text: str):
        posted.append((ch, text))
        return {}

    def keyword_ping(message) -> Any:
        if message.text.lower() != "ping":
            return None

        async def pong() -> None:
            handled.append(message.text)

        return pong()

    keyword_ping.__name__ = "_keyword_ping"
    channel._post_text = post_text  # type: ignore[method-assign]
    channel._handle_chat = lambda ch, text: handled.append(f"chat:{text}")  # type: ignore[method-assign]
    channel._text_handlers.append(keyword_ping)

    await channel._on_events_api(_dm("new", 1))
    await channel._on_events_api(_dm("Ping", 2))
    await channel._on_events_api(_dm("pingu", 3))
    await channel.wait_idle()
    assert posted == [(DM, "Fresh start: your next message begins a new conversation.")]
    assert sorted(handled) == ["Ping", "chat:pingu"]
    assert slack_mod._reply_task_name(keyword_ping) == "slack-ping"
    await channel._connector.close()


# ── the anchors ──────────────────────────────────────────────────────────────

_NAMED = re.compile(r"^\s*(?:#|//|<!--)\s*top10:([a-z_]+)\s*(?:-->)?\s*$")
_POINT = re.compile(r"^\s*#\s*top10:([a-z_]+):([a-z_]+)\s*$")

# File -> the named anchor groups in it, top to bottom (each group lists all
# ten keys; main.py's lifespan stop block runs in reverse, as stops do).
NAMED_GROUPS: dict[str, list[list[str]]] = {
    "backend/services/agent/tool_registry.py": [KEYS] * 11,
    "backend/services/agent/permissions.py": [KEYS],
    "backend/services/capabilities/__init__.py": [KEYS] * 3,
    "backend/services/agent/context_manager.py": [KEYS],
    "backend/services/agent/runtime.py": [KEYS] * 2,
    "backend/services/notifications/progress.py": [KEYS] * 3,
    "backend/services/audit.py": [KEYS] * 2,
    "backend/models/__init__.py": [KEYS] * 2,
    "backend/main.py": [KEYS, list(reversed(KEYS)), KEYS, KEYS],
    "backend/services/notifications/telegram.py": [KEYS] * 3,
    "backend/services/notifications/slack.py": [KEYS],
    "backend/api/routes/auth.py": [KEYS],
    "backend/services/connectors/registry.py": [KEYS],
    "frontend/src/services/api.ts": [KEYS],
    "frontend/src/types/index.ts": [KEYS],
    "docs/BACKLOG.md": [KEYS],
    "docs/CODE-MAP.md": [KEYS],
}

_SECRET, _SCHED, _TUTOR, _CARDS, _TIERS, _VOICE, _VIDEO = (
    KEYS[i] for i in (0, 2, 3, 5, 7, 8, 9)
)
# runtime.py's point anchors, top to bottom: (point, skills, the method).
POINT_GROUPS: list[tuple[str, list[str], str]] = [
    ("system_prompt", [_SECRET, _CARDS, _SCHED, _TUTOR], "_with_system_prompt"),  # parameters
    ("system_prompt", [_SECRET, _CARDS], "_with_system_prompt"),  # tail: before the date
    ("system_prompt", [_SCHED], "_with_system_prompt"),  # tail: after permissions
    ("system_prompt", [_TUTOR], "_with_system_prompt"),  # tail: after memory
    ("chat_params", [_SCHED, _TUTOR], "chat"),
    ("chat_params", [_SCHED, _TUTOR], "_run_turn"),
    ("turn_start", [_SECRET, _SCHED, _TUTOR, _TIERS, _VOICE, _VIDEO], "_run_turn"),
    ("before_model_call", [_SCHED], "_run_turn"),
    ("call_pre_permission", [_SCHED, _TUTOR], "_run_turn"),
    ("call_post_permission", [_SCHED, _TIERS], "_run_turn"),
    ("call_taint", [_SCHED, _TIERS], "_run_turn"),
    ("call_after_argument_scan", [_SECRET], "_run_turn"),
    ("call_after_bind", [_TUTOR], "_run_turn"),
    ("card_create", [_SCHED, _TIERS], "_run_turn"),
    ("round_end", [_TUTOR], "_run_turn"),
    ("turn_end", [_SECRET, _SCHED, _TUTOR, _TIERS], "_run_turn"),
    ("chat_params", [_SCHED, _TUTOR], "stream_chat"),
    ("approve_action", [_SECRET, _TIERS], "approve_action"),
]


@pytest.mark.parametrize("relative", sorted(NAMED_GROUPS))
def test_every_named_anchor_is_in_place(relative):
    """Skills write only under their own anchors; none may go missing or
    move out of order before the cleanup PR removes them all."""
    path = APP_DIR / relative
    if not path.exists():
        pytest.skip(f"{relative} is not part of this checkout")
    found = [
        m.group(1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if (m := _NAMED.match(line))
    ]
    assert found == [key for group in NAMED_GROUPS[relative] for key in group]


def test_every_runtime_point_anchor_is_in_its_method():
    source = _runtime_source()
    methods = _methods(ast.parse(source))
    found: list[tuple[str, str, str]] = []
    for number, line in enumerate(source.splitlines(), start=1):
        match = _POINT.match(line)
        if match is None:
            continue
        owner = [
            name
            for name, node in methods.items()
            if node.lineno <= number <= node.end_lineno
        ]
        found.append((match.group(1), match.group(2), owner[0] if owner else ""))
    expected = [
        (point, skill, method) for point, skills, method in POINT_GROUPS for skill in skills
    ]
    assert found == expected
