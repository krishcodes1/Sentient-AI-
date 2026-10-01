"""Tests for a trigger's task run end to end: the trigger sweeper hands one batch
to the shared unattended runner (services/automation/turns.py), which runs the
real AgentRuntime with a scripted provider. The event's facts reach the model
only inside the untrusted envelope (never the system prompt or the owner's
message); a draft whose "to" came from those facts parks a card carrying the
taint note; triggers.create, memory.remember and web.search are refused by the
unattended fence; the turn gets no memory block, no channel and 4 rounds; the
card carries the trigger's origin and a 180-minute TTL, and approving it runs
that one call without resuming a turn; a provider that is not set up falls
back to the plain notice.

Why it exists: a trigger's run is started by mail anyone can send, with nobody
watching; these are the lines between "summarise my professor's email" and an
injected email driving a write or creating more triggers. In-memory SQLite, a
scripted provider, recording executors; no network, no real model.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from core.config import settings
from services.agent.approvals import DbApprovalStore
from services.agent.providers import LLMResponse, ProviderNotConfigured, ToolCall
from services.agent.runtime import AgentRuntime, PromptGuard
from services.agent.tool_registry import ConnectorSpec, RuntimePermissionAdapter, build_tools
from services.agent.unattended import UNATTENDED_FENCE_POLICY
from services.automation.turns import UnattendedTurnRunner
from services.notifications.event_triggers import TriggerService
from services.triggers import facts as shape
from tests.conftest import make_user, use_provider

T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
PROMPT = "Draft a short, polite reply to the sender saying I will be there."


class PollExecutor:
    """The sweeper's reads: one new mail from the allowed sender."""

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        return {
            "ok": True,
            "result": {
                "items": [
                    {
                        "id": "m1",
                        "from": "Prof Smith <smith@univ.edu>",
                        "subject": "Office hours moved",
                        "snippet": "Office hours are now at 3pm.",
                        "body": "Office hours are now at 3pm. Reply to confirm.",
                        "label_ids": ["INBOX"],
                    }
                ]
            },
        }


class RecordingExecutor:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    async def execute(self, tool_name, arguments, user_id, approved=False, *, task_id=None):
        self.calls.append({"tool": tool_name, "arguments": arguments, "approved": approved})
        return {"ok": True, "result": {"draft_id": "d1"}}


class RecordingAudit:
    def __init__(self):
        self.entries: list[dict[str, Any]] = []

    async def log(self, entry):
        self.entries.append(entry)


class ScriptedProvider:
    supports_vision = False

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def complete(self, messages, tools=None, **_kwargs):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": [t["name"] if isinstance(t, dict) and "name" in t else str(t) for t in (tools or [])]})
        if self.responses:
            return self.responses.pop(0)
        return LLMResponse(content="Done.")

    async def stream(self, messages, tools=None):
        yield "done"

    async def aclose(self):
        return None


class Recorded(AgentRuntime):
    """The real runtime, keeping the keyword arguments of each turn."""

    turns: list[dict[str, Any]] = []

    async def chat(self, *args, **kwargs):  # type: ignore[override]
        Recorded.turns.append(kwargs)
        return await super().chat(*args, **kwargs)


class NoChat(AgentRuntime):
    async def chat(self, *args, **kwargs):  # type: ignore[override]
        raise AssertionError("an origin card must never resume a turn")


class Outbox:
    def __init__(self):
        self.sent: list[str] = []

    async def send(self, user_id, text):
        self.sent.append(text)
        return True


def call(n: int, name: str, arguments: dict[str, Any]) -> ToolCall:
    return ToolCall(id=f"c{n}", name=name, arguments=arguments)


async def setup(session_factory, provider, *, runtime_cls=Recorded):
    from models.connector import AuthMethod, ConnectorConfig
    from models.event_trigger import EventTrigger

    user, _ = await make_user(session_factory, f"runs-{uuid.uuid4().hex[:6]}@example.com")
    row = uuid.uuid4()
    trigger_id = uuid.uuid4()
    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                id=row,
                user_id=user.id,
                connector_type="google_workspace",
                display_name="School",
                auth_method=AuthMethod.bearer_token,
                encrypted_credentials=b"x",
                granted_scopes=["gmail.read", "gmail.compose"],
            )
        )
        await session.flush()
        session.add(
            EventTrigger(
                id=trigger_id,
                user_id=user.id,
                label="Prof emails",
                source="email.new",
                connector_id=row,
                filters={"senders": ["smith@univ.edu"]},
                fingerprint=uuid.uuid4().hex,
                mode="run_task",
                prompt=PROMPT,
                allow_writes=True,
                interval_minutes=15,
                max_runs_per_day=6,
                status="active",
                baseline_at=T0 - timedelta(days=1),
                cursor={"watermark": shape.iso(T0 - timedelta(minutes=15)), "seen": []},
                next_check_at=T0,
                created_at=T0 - timedelta(days=1),
                updated_at=T0 - timedelta(days=1),
            )
        )
        await session.commit()
    store = DbApprovalStore(session_factory=session_factory)
    executor = RecordingExecutor()
    audit = RecordingAudit()
    runtime = runtime_cls(
        config=settings,
        permission_engine=RuntimePermissionAdapter(),
        prompt_guard=PromptGuard(),
        tool_executor=executor,
        audit_service=audit,
        approval_store=store,
    )
    if provider is not None:
        use_provider(runtime, provider)

    async def build_context(user_row, db, conversation):
        # Everything a chat turn could offer this user; the runner fences it.
        tools = build_tools(
            [ConnectorSpec("google_workspace", connector_id=str(row), display_name="School")],
            enabled_capabilities=frozenset({"web_browsing", "reminders", "save_memories", "event_triggers"}),
        )
        return SimpleNamespace(tools=tools, memory_block="SAVED MEMORIES", permissions_text="<permissions>p</permissions>")

    async def settings_source():
        return {}

    from api.routes.agent import _usage_columns

    runner = UnattendedTurnRunner(
        runtime=lambda: runtime,
        session_factory=session_factory,
        build_context=build_context,
        usage_columns=_usage_columns,
        settings=settings_source,
        clock=lambda: T0,
    )
    outbox = Outbox()

    async def on():
        return True

    service = TriggerService(
        session_factory,
        executor=PollExecutor(),
        send=outbox.send,
        enabled=on,
        runs_enabled=on,
        runner=runner,
        clock=lambda: T0,
        scan=lambda text: True,
    )
    return SimpleNamespace(
        user=user, row=row, trigger_id=trigger_id, store=store, executor=executor, audit=audit,
        runtime=runtime, service=service, outbox=outbox,
    )


@pytest.mark.asyncio
async def test_a_run_sees_the_event_only_as_untrusted_data_and_is_fenced(session_factory):
    Recorded.turns = []
    provider = ScriptedProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[
                    call(1, "triggers.create", {"label": "more", "source": "email.new"}),
                    call(2, "memory.remember", {"content": "Smith is my professor", "category": "fact"}),
                    call(3, "web.search", {"query": "smith univ"}),
                ],
            ),
            LLMResponse(
                content="",
                tool_calls=[
                    call(4, "google_workspace.create_draft", {"to": "smith@univ.edu", "subject": "Re: Office hours", "body": "I will be there."})
                ],
            ),
        ]
    )
    env = await setup(session_factory, provider)
    await env.service.sweep_once()
    await env.service.wait_idle()

    # The turn: no memory, no channel, the trigger's contract.
    [turn] = Recorded.turns
    assert turn["memory_block"] is None and turn["channel"] is None
    run = turn["unattended"]
    assert run.origin == f"trigger:{env.trigger_id}" and run.max_rounds == 4
    assert run.card_ttl_minutes == 180 and run.trusted_text == PROMPT
    assert "google_workspace.create_draft" in run.writes and run.connector_id == str(env.row)
    offered = {t.name for t in turn["tools"]}
    assert "google_workspace.get_messages" in offered and "google_workspace.create_draft" in offered
    assert not {n for n in offered if n.split(".")[0] in ("triggers", "memory", "web", "tools")}

    # The event only inside the untrusted envelope.
    first = provider.calls[0]["messages"]
    assert "smith@univ.edu" not in first[0]["content"]  # the system prompt
    owner = [m for m in first if m["role"] == "user" and PROMPT in str(m["content"])]
    assert len(owner) == 1 and "smith@univ.edu" not in owner[0]["content"]
    assert owner[0]["content"].startswith('Trigger "Prof emails" fired at')
    seeded = [m for m in first if "smith@univ.edu" in str(m.get("content"))]
    assert len(seeded) == 1 and seeded[0]["role"] == "user"
    assert 'trust="untrusted"' in seeded[0]["content"] and "trigger.event" in seeded[0]["content"]

    # The three the fence refuses, audited; nothing ran.
    fenced = [e["tool"] for e in env.audit.entries if e.get("event") == "tool_blocked" and e.get("policy") == UNATTENDED_FENCE_POLICY]
    assert sorted(fenced) == ["memory.remember", "triggers.create", "web.search"]
    assert env.executor.calls == []

    # The draft: a card with the trigger's origin, the long TTL and the taint note.
    [card] = await env.store.list_pending(str(env.user.id))
    assert card.tool_name == "google_workspace.create_draft" and card.origin == f"trigger:{env.trigger_id}"
    assert card.risk_note.startswith('Proposed by your trigger "Prof emails" while you were away.')
    assert "shaped by external content" in card.risk_note
    minutes = (datetime.fromisoformat(card.expires_at) - datetime.fromisoformat(card.created_at)).total_seconds() / 60
    assert round(minutes) == 180

    # The owner's message: the result, the pending note.
    [text] = env.outbox.sent
    assert text.startswith("⚡ Prof emails")
    assert "1 action is waiting for your approval (/pending; Slack: reply \"pending\")." in text
    assert "Not run (outside this trigger's tools): " in text


@pytest.mark.asyncio
async def test_approving_the_runs_card_runs_that_call_and_resumes_nothing(session_factory):
    from api.routes.agent import build_decision_applier
    from models.conversation import Message

    provider = ScriptedProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[call(1, "google_workspace.create_draft", {"to": "smith@univ.edu", "subject": "Re", "body": "Yes."})],
            )
        ]
    )
    env = await setup(session_factory, provider)
    await env.service.sweep_once()
    await env.service.wait_idle()
    [card] = await env.store.list_pending(str(env.user.id))
    approver = NoChat(
        config=settings,
        prompt_guard=PromptGuard(),
        tool_executor=env.executor,
        audit_service=RecordingAudit(),
        approval_store=env.store,
    )
    app = SimpleNamespace(state=SimpleNamespace(agent_runtime=approver, mcp_catalog=None, installation=None))
    outcome = await build_decision_applier(app, session_factory)(str(env.user.id), card.action_id, True)
    assert outcome["status"] == "approved" and outcome["summary"] == "Done: google_workspace.create_draft ran."
    assert [(c["tool"], c["approved"]) for c in env.executor.calls] == [("google_workspace.create_draft", True)]
    async with session_factory() as session:
        contents = [
            m.content
            for m in (
                await session.execute(select(Message).where(Message.conversation_id == uuid.UUID(card.conversation_id)))
            )
            .scalars()
            .all()
        ]
    assert "Done: google_workspace.create_draft ran." in contents


@pytest.mark.asyncio
async def test_a_provider_that_is_not_set_up_sends_the_notice_with_a_line(session_factory):
    class Unconfigured(AgentRuntime):
        async def chat(self, *args, **kwargs):  # type: ignore[override]
            raise ProviderNotConfigured("gemini", reason="not_set_up")

    env = await setup(session_factory, None, runtime_cls=Unconfigured)
    await env.service.sweep_once()
    await env.service.wait_idle()
    [text] = env.outbox.sent
    assert text.startswith("\U0001f4ec Prof emails: new email from Prof Smith (univ․edu): Office hours moved")
    assert text.endswith("Crawler could not run your task: the AI provider is not set up.")
    assert "Reply to confirm" not in text


@pytest.mark.asyncio
async def test_the_run_is_recorded_in_the_shared_ledger_and_budget(session_factory):
    from models.scheduled_task import AutomationRun

    env = await setup(session_factory, ScriptedProvider([LLMResponse(content="Office hours moved to 3pm.")]))
    await env.service.sweep_once()
    await env.service.wait_idle()
    async with session_factory() as session:
        [run] = list((await session.execute(select(AutomationRun))).scalars().all())
    assert run.origin == f"trigger:{env.trigger_id}" and run.trigger == "event" and run.status == "ok"
    left = await env.service.runner.budget_left(str(env.user.id))
    assert left.runs_left == 23
    [text] = env.outbox.sent
    assert text.startswith("⚡ Prof emails\nOffice hours moved to 3pm.")
