"""Tests for what reaches the AI provider (services/security/egress.py wired at
AgentRuntime._provider_complete): the floor masks a key in a tool result and a
card number in the user's message for every provider; with "Hide personal
details from the AI provider" on and a cloud provider, an email reaches the
model as [[EMAIL_1@uni.edu]] while the approval card, the executor and the reply
get the real address; the <privacy> block appears only then; Ollama on this
computer gets the floor only (on a LAN host it counts as cloud); an unknown
placeholder is refused; a detector error withholds that message part; exactly
one sensitive_data_hidden audit row is written; and the turn resumed after an
approval behaves the same.

Why it exists: the model request is the one place every source (messages,
memories, tool results, documents) leaves the machine together. A scripted
provider records exactly what it was sent; nothing calls a real model.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest

from core.config import settings
from services.agent import runtime as runtime_module
from services.agent.approvals import InMemoryApprovalStore
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import SECURITY_SYSTEM_PROMPT, AgentRuntime
from services.agent.tool_registry import ConnectorSpec, RuntimePermissionAdapter, build_tools
from services.security import egress as egress_module
from services.security import guard as guard_module
from services.security.egress import (
    PRIVACY_SYSTEM_PROMPT,
    ModelEgress,
    bind_egress,
    current_egress,
    is_local_provider,
    redact_for_embedding,
    redact_for_model,
)
from services.security.policies import MODEL_WITHHELD
from tests.conftest import use_provider
from tests.test_wiring import wired_app as wired_app  # noqa: F401 - fixture

TOKEN = "ghp_" + "FAKE" * 9
CARD = "4111 1111 1111 1111"
EMAIL = "prof.lee@uni.edu"
PLACEHOLDER = "[[EMAIL_1@uni.edu]]"
USER = "egress-user"

GOOGLE_TOOLS = build_tools([ConnectorSpec("google_workspace")], include_builtins=False)
AUTO_GOOGLE_TOOLS = build_tools(
    [ConnectorSpec("google_workspace", permission_tier="auto_approve")],
    user_default_tier="auto_approve",
    include_builtins=False,
)


class ScriptedProvider:
    """Returns scripted responses in order; records every call's messages."""

    supports_vision = True

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, tools=None):
        self.calls.append(list(messages))
        return self._responses.pop(0) if self._responses else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"

    def sent(self) -> str:
        return json.dumps(self.calls, default=str)


class RecordingExecutor:
    def __init__(self, result: Any = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._result = result if result is not None else {"ok": True}

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append({"tool": tool_name, "arguments": arguments, "approved": approved})
        return self._result


class RecordingAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def log(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)

    def rows(self, event: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("event") == event]


class _Source:
    def __init__(self, pair: tuple[str, str]) -> None:
        self.pair = pair

    async def llm_defaults(self) -> tuple[str, str]:
        return self.pair

    async def llm_api_key(self, provider: str) -> str:
        return "" if provider == "ollama" else "test-key"


def _runtime(
    provider: ScriptedProvider,
    *,
    pair: tuple[str, str] = ("gemini", "m"),
    hide: Any = True,
    result: Any = None,
):
    executor = RecordingExecutor(result)
    audit = RecordingAudit()
    store = InMemoryApprovalStore()

    gate = None
    if hide is not None:

        async def gate() -> bool:
            if isinstance(hide, Exception):
                raise hide
            return bool(hide)

    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        tool_executor=executor,
        audit_service=audit,
        approval_store=store,
        settings_source=_Source(pair),
        personal_details_hidden=gate,
    )
    use_provider(runtime, provider, pair=pair)
    return runtime, executor, audit, store


def _call(name: str, call_id: str = "t1", content: str = "", **arguments: Any) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=[ToolCall(id=call_id, name=name, arguments=arguments)])


def _system(provider: ScriptedProvider, index: int = 0) -> str:
    return provider.calls[index][0]["content"]


# A tool result is fenced by a boundary of 16 random hex digits drawn per
# call, and an audit row's timestamp has microseconds. Either can hold "4111",
# the card's first digits, by chance, so those digits are looked for only once
# the random value is taken out.
_BOUNDARY = re.compile(r"<tool_result_([0-9a-f]{16}) ")


def _without_boundary(sent: str) -> str:
    [boundary] = set(_BOUNDARY.findall(sent))
    return sent.replace(boundary, "<boundary>")


def _without_timestamp(row: dict[str, Any]) -> str:
    return json.dumps({k: v for k, v in row.items() if k != "timestamp"}, default=str)


# ── the floor, for every provider ────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("pair", [("gemini", "m"), ("ollama", "m")])
async def test_a_token_in_a_tool_result_and_a_card_in_the_message_never_reach_the_provider(pair):
    provider = ScriptedProvider(
        [
            _call("google_workspace.search_emails", query="deploy"),
            LLMResponse(content="Found the deploy email."),
        ]
    )
    runtime, executor, _audit, _ = _runtime(
        provider, pair=pair, hide=False, result={"ok": True, "body": f"the token is {TOKEN}"}
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": f"My card {CARD} was charged; find the deploy email"}],
        tools=GOOGLE_TOOLS,
        user_id=USER,
    )
    assert response.content == "Found the deploy email."
    sent = provider.sent()
    assert TOKEN not in sent and CARD not in sent and "4111" not in _without_boundary(sent)
    assert "[hidden by Crawler: card number]" in sent
    assert "[hidden by Crawler: GitHub token]" in sent
    # The executor and the transcript still hold the real result.
    assert executor.calls and TOKEN in str(response.tool_calls)


@pytest.mark.asyncio
async def test_a_boundary_that_happens_to_hold_the_card_digits_is_no_leak(monkeypatch):
    # About one run in 5,000 draws a boundary holding "4111": the check looked
    # in the whole request and failed with no card data sent. Pinned for the
    # runtime only; other code keeps the real secrets module.
    pinned = SimpleNamespace(token_hex=lambda nbytes: "ab41115474e9b090")
    monkeypatch.setattr(runtime_module, "secrets", pinned)
    provider = ScriptedProvider(
        [_call("google_workspace.search_emails", query="deploy"), LLMResponse(content="ok")]
    )
    runtime, *_ = _runtime(provider, hide=False)
    await runtime.chat(
        messages=[{"role": "user", "content": f"My card {CARD} was charged"}],
        tools=GOOGLE_TOOLS,
        user_id=USER,
    )
    sent = provider.sent()
    assert "<tool_result_ab41115474e9b090 " in sent
    assert CARD not in sent and "4111" not in _without_boundary(sent)


@pytest.mark.asyncio
async def test_a_boundary_is_never_all_digits(monkeypatch):
    # About one draw in 47,000 is all digits and passes as a card number, which
    # the egress floor masks: the fence would become fixed text an attacker knows.
    drawn = iter(["5555555555554444", "ab41115474e9b090"])
    monkeypatch.setattr(runtime_module, "secrets", SimpleNamespace(token_hex=lambda nbytes: next(drawn)))
    provider = ScriptedProvider(
        [_call("google_workspace.search_emails", query="deploy"), LLMResponse(content="ok")]
    )
    runtime, *_ = _runtime(provider, hide=False)
    await runtime.chat(
        messages=[{"role": "user", "content": "Find the deploy email"}], tools=GOOGLE_TOOLS, user_id=USER
    )
    sent = provider.sent()
    assert "<tool_result_ab41115474e9b090 " in sent and "</tool_result_ab41115474e9b090>" in sent
    assert "5555555555554444" not in sent and "tool_result_[hidden" not in sent


@pytest.mark.asyncio
async def test_with_the_switch_off_the_system_message_is_unchanged():
    provider = ScriptedProvider([LLMResponse(content="hi")])
    runtime, *_ = _runtime(provider, hide=False)
    await runtime.chat(
        messages=[{"role": "user", "content": f"hello, write to {EMAIL}"}], tools=[], user_id=USER
    )
    expected = AgentRuntime._with_system_prompt([{"role": "user", "content": "x"}])[0]["content"]
    assert _system(provider) == expected
    assert _system(provider).startswith(SECURITY_SYSTEM_PROMPT)
    assert "<privacy>" not in _system(provider)
    # Contact details go as written with the switch off.
    assert EMAIL in provider.sent()


# ── placeholders for a cloud provider ────────────────────────────────────


@pytest.mark.asyncio
async def test_an_email_reaches_the_model_as_a_placeholder_and_the_card_gets_the_real_one():
    provider = ScriptedProvider(
        [
            _call(
                "google_workspace.send_email",
                content=f"I will write to {PLACEHOLDER} once you approve.",
                to=PLACEHOLDER,
                subject="Running late",
                body=f"Hi, this is for {PLACEHOLDER}.",
            )
        ]
    )
    runtime, executor, audit, store = _runtime(provider)
    response = await runtime.chat(
        messages=[{"role": "user", "content": f"Tell {EMAIL} I'll be late"}],
        tools=GOOGLE_TOOLS,
        user_id=USER,
    )
    sent = provider.sent()
    assert EMAIL not in sent and PLACEHOLDER in sent
    assert PRIVACY_SYSTEM_PROMPT in _system(provider)
    # The reply and the card carry the real address.
    assert response.content == f"I will write to {EMAIL} once you approve."
    [pending] = response.pending_approvals
    assert pending.arguments["to"] == EMAIL
    assert pending.arguments["body"] == f"Hi, this is for {EMAIL}."
    [stored] = await store.list_pending(USER)
    assert stored.arguments["to"] == EMAIL
    # Approving sends it to the real address.
    result = await runtime.approve_action(pending.action_id, USER)
    assert "error" not in result
    assert executor.calls[-1]["arguments"]["to"] == EMAIL
    assert "[[" not in json.dumps(audit.entries, default=str)


@pytest.mark.asyncio
async def test_an_auto_approved_write_runs_with_the_real_address():
    provider = ScriptedProvider(
        [
            _call("google_workspace.create_draft", to=PLACEHOLDER, subject="s", body="b"),
            LLMResponse(content=f"Sent to {PLACEHOLDER}."),
        ]
    )
    runtime, executor, *_ = _runtime(provider)
    response = await runtime.chat(
        messages=[{"role": "user", "content": f"email {EMAIL} now"}],
        tools=AUTO_GOOGLE_TOOLS,
        user_id=USER,
    )
    assert executor.calls[0]["arguments"]["to"] == EMAIL
    assert response.content == f"Sent to {EMAIL}."


@pytest.mark.asyncio
async def test_numbering_is_stable_across_rounds_and_results_are_hidden_too():
    provider = ScriptedProvider(
        [_call("google_workspace.search_emails", query="late"), LLMResponse(content="ok")]
    )
    runtime, *_ = _runtime(
        provider, result={"ok": True, "from": EMAIL, "phone": "(212) 555-0100"}
    )
    await runtime.chat(
        messages=[{"role": "user", "content": f"any mail from {EMAIL}?"}],
        tools=GOOGLE_TOOLS,
        user_id=USER,
    )
    second_round = json.dumps(provider.calls[1])
    assert second_round.count(PLACEHOLDER) >= 2 and "[[PHONE_1]]" in second_round
    assert EMAIL not in second_round and "555-0100" not in second_round


@pytest.mark.asyncio
async def test_a_gate_error_counts_as_hide_and_unwired_counts_as_off():
    provider = ScriptedProvider([LLMResponse(content="hi")])
    runtime, *_ = _runtime(provider, hide=RuntimeError("switches unreadable"))
    await runtime.chat(messages=[{"role": "user", "content": EMAIL}], tools=[], user_id=USER)
    assert PLACEHOLDER in provider.sent()

    provider = ScriptedProvider([LLMResponse(content="hi")])
    runtime, *_ = _runtime(provider, hide=None)
    await runtime.chat(messages=[{"role": "user", "content": EMAIL}], tools=[], user_id=USER)
    assert EMAIL in provider.sent() and "<privacy>" not in _system(provider)


# ── Ollama ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ollama_on_this_computer_gets_the_floor_only(monkeypatch):
    monkeypatch.setattr(settings, "OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    provider = ScriptedProvider([LLMResponse(content="hi")])
    runtime, *_ = _runtime(provider, pair=("ollama", "m"))
    await runtime.chat(
        messages=[{"role": "user", "content": f"{EMAIL} and {TOKEN}"}], tools=[], user_id=USER
    )
    sent = provider.sent()
    assert EMAIL in sent and TOKEN not in sent
    assert "<privacy>" not in _system(provider)


@pytest.mark.asyncio
async def test_ollama_on_a_lan_host_counts_as_cloud(monkeypatch):
    monkeypatch.setattr(settings, "OLLAMA_BASE_URL", "http://192.168.1.20:11434")
    provider = ScriptedProvider([LLMResponse(content="hi")])
    runtime, *_ = _runtime(provider, pair=("ollama", "m"))
    await runtime.chat(messages=[{"role": "user", "content": EMAIL}], tools=[], user_id=USER)
    assert PLACEHOLDER in provider.sent() and PRIVACY_SYSTEM_PROMPT in _system(provider)


@pytest.mark.parametrize(
    ("provider", "url", "local"),
    [
        ("ollama", "http://localhost:11434", True),
        ("ollama", "http://127.0.0.1:11434", True),
        ("ollama", "http://[::1]:11434", True),
        ("ollama", "http://gpu.localhost:11434", True),
        ("ollama", "http://host.docker.internal:11434", True),
        ("ollama", "http://192.168.1.20:11434", False),
        ("ollama", "http://ollama.example.com", False),
        ("ollama", "", False),
        ("gemini", "http://localhost:11434", False),
    ],
)
def test_is_local_provider(provider, url, local):
    assert is_local_provider(provider, url) is local


# ── refusals and failures ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_unknown_placeholder_is_refused_and_nothing_runs():
    provider = ScriptedProvider(
        [
            _call("google_workspace.send_email", to="[[EMAIL_9@evil.example]]", subject="s", body="b"),
            LLMResponse(content="I could not send it."),
        ]
    )
    runtime, executor, audit, store = _runtime(provider)
    response = await runtime.chat(
        messages=[{"role": "user", "content": f"write to {EMAIL}"}],
        tools=AUTO_GOOGLE_TOOLS,
        user_id=USER,
    )
    assert executor.calls == [] and response.pending_approvals == []
    assert await store.list_pending(USER) == []
    # The call's own error, not a security block.
    assert response.blocked_actions == []
    [record] = response.tool_calls
    assert record["result"]["rule"] == "unknown_placeholder"
    [row] = audit.rows("tool_blocked")
    assert row["policy"] == "secret_guard" and row["rule"] == "unknown_placeholder"


def test_a_reused_call_id_does_not_inherit_an_earlier_refusal():
    egress = ModelEgress(True)
    egress.outbound([{"role": "user", "content": f"write to {EMAIL}"}])
    egress.inbound(_call("google_workspace.send_email", "gemini_0", to="[[EMAIL_7@uni.edu]]"))
    assert egress.unknown_placeholders("gemini_0") == ["[[EMAIL_7@uni.edu]]"]
    # Round 2 numbers its first call gemini_0 again, with clean arguments.
    egress.inbound(_call("web.search", "gemini_0", query="weather"))
    assert egress.unknown_placeholders("gemini_0") == []
    # A new unknown placeholder under the same id is still reported ...
    egress.inbound(_call("google_workspace.send_email", "gemini_0", to="[[EMAIL_8@uni.edu]]"))
    assert egress.unknown_placeholders("gemini_0") == ["[[EMAIL_8@uni.edu]]"]
    # ... and a tool-less reply in between (a one-shot call) changes nothing.
    egress.inbound(LLMResponse(content="a summary"))
    assert egress.unknown_placeholders("gemini_0") == ["[[EMAIL_8@uni.edu]]"]


@pytest.mark.asyncio
async def test_the_corrected_retry_under_the_same_gemini_id_gets_its_card():
    provider = ScriptedProvider(
        [
            _call("google_workspace.send_email", "gemini_0", to="[[EMAIL_9@uni.edu]]", subject="s", body="b"),
            _call("google_workspace.send_email", "gemini_0", to=PLACEHOLDER, subject="s", body="b"),
            LLMResponse(content="Waiting for your approval."),
        ]
    )
    runtime, executor, audit, store = _runtime(provider)
    response = await runtime.chat(
        messages=[{"role": "user", "content": f"write to {EMAIL}"}],
        tools=GOOGLE_TOOLS,
        user_id=USER,
    )
    [refused] = audit.rows("tool_blocked")
    assert refused["rule"] == "unknown_placeholder"
    [pending] = response.pending_approvals
    assert pending.arguments["to"] == EMAIL and executor.calls == []


@pytest.mark.asyncio
async def test_a_detector_error_withholds_that_part_and_the_turn_completes(monkeypatch):
    real = egress_module.findings

    def flaky(text, policy):
        if "BOOM" in text:
            raise RuntimeError("detector bug")
        return real(text, policy)

    monkeypatch.setattr(egress_module, "findings", flaky)
    provider = ScriptedProvider([LLMResponse(content="Sorry, I could not read that.")])
    runtime, *_ = _runtime(provider, hide=False)
    response = await runtime.chat(
        messages=[
            {"role": "user", "content": "earlier message"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": f"BOOM {TOKEN}"},
        ],
        tools=[],
        user_id=USER,
    )
    assert response.content == "Sorry, I could not read that."
    user_parts = [m["content"] for m in provider.calls[0] if m["role"] == "user"]
    assert user_parts == ["earlier message", MODEL_WITHHELD]
    assert TOKEN not in provider.sent()


@pytest.mark.asyncio
async def test_image_parts_pass_through_untouched():
    provider = ScriptedProvider([LLMResponse(content="A cat.")])
    runtime, *_ = _runtime(provider, hide=False)
    image = {"type": "image", "media_type": "image/png", "data": "iVBORw0KGgo" + "A" * 64}
    await runtime.chat(
        messages=[
            {"role": "user", "content": [{"type": "text", "text": f"what is this {TOKEN}"}, image]}
        ],
        tools=[],
        user_id=USER,
    )
    content = provider.calls[0][-1]["content"]
    assert content[1] == image
    assert content[0]["text"] == "what is this [hidden by Crawler: GitHub token]"


# ── the audit row ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_exactly_one_sensitive_data_hidden_row_with_counts_only():
    provider = ScriptedProvider(
        [_call("google_workspace.search_emails", query="x"), LLMResponse(content="done")]
    )
    runtime, _executor, audit, _ = _runtime(
        provider, result={"ok": True, "text": f"{TOKEN} from {EMAIL}"}
    )
    history = [{"role": "user", "content": f"card {CARD}, write to {EMAIL}"}]
    await runtime.chat(messages=history, tools=GOOGLE_TOOLS, user_id=USER)
    [row] = audit.rows("sensitive_data_hidden")
    hidden = {item["label"]: item["count"] for item in row["arguments"]["hidden"]}
    assert hidden == {"card number": 1, "GitHub token": 1, "email": 1}
    assert row["arguments"]["provider"] == "gemini"
    dumped = json.dumps(row, default=str)
    for value in (TOKEN, CARD, EMAIL):
        assert value not in dumped
    assert "4111" not in _without_timestamp(row)
    # The timestamp left out above holds a time and nothing else.
    assert datetime.fromisoformat(row["timestamp"]).isoformat() == row["timestamp"]

    # The next turn re-sends that history: nothing new, no row.
    provider2 = ScriptedProvider([LLMResponse(content="you're welcome")])
    use_provider(runtime, provider2, pair=("gemini", "m"))
    await runtime.chat(
        messages=[*history, {"role": "assistant", "content": "done"}, {"role": "user", "content": "thanks"}],
        tools=[],
        user_id=USER,
    )
    assert len(audit.rows("sensitive_data_hidden")) == 1
    assert CARD not in provider2.sent() and EMAIL not in provider2.sent()


@pytest.mark.asyncio
async def test_a_timestamp_that_happens_to_hold_the_card_digits_is_no_leak(monkeypatch):
    # About one run in 3,300 stamps the row at microseconds holding "4111":
    # the check looked in the whole row and failed with no card data in it.
    pinned = SimpleNamespace(now=lambda tz: datetime(2026, 10, 1, 16, 10, 0, 411100, tzinfo=tz))
    monkeypatch.setattr(guard_module, "datetime", pinned)
    provider = ScriptedProvider([LLMResponse(content="ok")])
    runtime, _executor, audit, _ = _runtime(provider)
    await runtime.chat(
        messages=[{"role": "user", "content": f"card {CARD}"}], tools=[], user_id=USER
    )
    [row] = audit.rows("sensitive_data_hidden")
    assert row["timestamp"] == "2026-10-01T16:10:00.411100+00:00"
    assert CARD not in json.dumps(row) and "4111" not in _without_timestamp(row)


def test_the_event_is_filed_as_approved():
    from models.audit import AuditStatus
    from services.audit import _EVENT_STATUS

    assert _EVENT_STATUS["sensitive_data_hidden"] is AuditStatus.approved


# ── the resumed turn ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_turn_resumed_after_an_approval_behaves_the_same():
    provider = ScriptedProvider(
        [_call("google_workspace.send_email", to=PLACEHOLDER, subject="s", body="b")]
    )
    runtime, executor, audit, _ = _runtime(
        provider, result={"ok": True, "sent_to": EMAIL, "debug": TOKEN}
    )
    first = await runtime.chat(
        messages=[{"role": "user", "content": f"email {EMAIL}"}], tools=GOOGLE_TOOLS, user_id=USER
    )
    [pending] = first.pending_approvals
    ran = await runtime.approve_action(pending.action_id, USER)
    assert executor.calls[-1]["arguments"]["to"] == EMAIL

    resumed_provider = ScriptedProvider([LLMResponse(content=f"Sent to {PLACEHOLDER}.")])
    use_provider(runtime, resumed_provider, pair=("gemini", "m"))
    resumed = await runtime.chat(
        messages=[
            {"role": "user", "content": f"email {EMAIL}"},
            {"role": "user", "content": runtime.approved_call_message(ran["tool"], ran["result"])},
        ],
        tools=GOOGLE_TOOLS,
        user_id=USER,
    )
    sent = resumed_provider.sent()
    assert EMAIL not in sent and TOKEN not in sent and PLACEHOLDER in sent
    assert resumed.content == f"Sent to {EMAIL}."
    assert len(audit.rows("sensitive_data_hidden")) == 2


# ── outside a turn, and the helpers ──────────────────────────────────────


@pytest.mark.asyncio
async def test_a_model_call_outside_a_turn_gets_the_floor():
    provider = ScriptedProvider([LLMResponse(content=f"echo {TOKEN}")])
    runtime, *_ = _runtime(provider, hide=True)
    assert current_egress.get() is None
    response = await runtime._provider_complete(
        provider, messages=[{"role": "user", "content": f"{TOKEN} {EMAIL}"}], tools=None
    )
    sent = provider.sent()
    assert TOKEN not in sent and EMAIL in sent
    assert response.content == f"echo {TOKEN}"


def test_bind_egress_restores_what_was_there():
    outer = ModelEgress(False)
    with bind_egress(outer):
        with pytest.raises(RuntimeError):
            with bind_egress(ModelEgress(True)):
                raise RuntimeError("turn failed")
        assert current_egress.get() is outer
    assert current_egress.get() is None


def test_redact_for_model_and_embedding():
    text = f"{TOKEN} from {EMAIL}, call (212) 555-0100"
    assert redact_for_model(text) == f"[hidden by Crawler: GitHub token] from {EMAIL}, call (212) 555-0100"
    assert redact_for_embedding(text, cloud=True, hide_personal=True) == (
        "[hidden by Crawler: GitHub token] from [email], call [phone]"
    )
    assert EMAIL in redact_for_embedding(text, cloud=False, hide_personal=True)
    assert EMAIL in redact_for_embedding(text, cloud=True, hide_personal=False)
    assert TOKEN not in redact_for_embedding(text, cloud=False, hide_personal=False)


def test_the_privacy_block_shows_no_placeholder_that_could_be_neutralised():
    from services.security.pseudonyms import placeholders_in
    from services.security.secrets import find

    assert placeholders_in(PRIVACY_SYSTEM_PROMPT) == []
    assert find(PRIVACY_SYSTEM_PROMPT) == []
    egress = ModelEgress(True)
    [message] = egress.outbound([{"role": "system", "content": PRIVACY_SYSTEM_PROMPT}])
    assert message["content"] == PRIVACY_SYSTEM_PROMPT
    assert "values=" in repr(egress._vault) and EMAIL not in repr(egress)


# ── main.py wiring ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_main_wires_the_switch_to_the_owner_capability(session_factory, wired_app):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory, "egress-wiring@example.com")
    runtime = wired_app.state.agent_runtime
    gate = runtime._personal_details_hidden
    assert gate is not None and await gate() is True
    await wired_app.state.installation.set_capabilities(
        {"hide_personal_details": False}, actor_id=user.id
    )
    assert await gate() is False
