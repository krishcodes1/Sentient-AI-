"""Runs one unattended agent turn end to end: the budget check, the run's own
conversation and message, the fenced tools, ``runtime.chat`` with the
``UnattendedRun`` contract under a deadline, and the stored reply.

Why it exists: api/routes/agent.build_unattended_runner wires this with the
chat pipeline's own pieces (``_build_tools_and_memory``, ``_usage_columns``)
and hangs it on ``app.state.unattended_runner``; the schedule sweeper (and
wave 2's trigger sweeper) call it through the ``UnattendedRunner`` protocol.
A run gets no memory block, a fresh history (only its own message), no chat
channel (so no weekly app approval), no MCP tools, at most two runs per
process at once, and the owner's /stop ends it at a step boundary like any
turn (``runtime.chat`` runs under ``agent_cancel.watching``).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog
from sqlalchemy import select

from services.agent import cancel as agent_cancel
from services.agent.unattended import UNATTENDED_TASK_PREFIX, UnattendedRun
from services.automation.conversations import add_message, ensure_conversation
from services.automation.fence import ALWAYS_READS, build_fence
from services.automation.ledger import AutomationLedger
from services.automation.runner import BudgetState, UnattendedOutcome, UnattendedRequest

logger = structlog.get_logger(__name__)

MAX_CONCURRENT_RUNS = 2
CARD_TTL_MINUTES = 180
_STOPPED_REPLY = "[Stopped before the reply was finished.]"
_TIMED_OUT_REPLY = "[This scheduled run took too long and was stopped.]"
_FAILED_REPLY = "[No reply: the model provider returned an error.]"
_NOT_CONFIGURED_REPLY = "[No reply: no AI provider is set up for this account.]"

# (user, db, conversation) -> the turn context (_build_tools_and_memory).
BuildContext = Callable[[Any, Any, Any], Awaitable[Any]]
UsageColumns = Callable[[Optional[dict[str, Any]], Optional[str], Optional[str]], dict[str, Any]]
SettingsSource = Callable[[], Awaitable[dict[str, Any]]]


def run_message(label: str, when_local: str, prompt: str, origin: str = "") -> str:
    """The run's own user message: the only history the turn gets. A
    trigger's run says it fired (its items follow as untrusted data)."""
    if origin.startswith("trigger:"):
        return f'Trigger "{label}" fired at {when_local}:\n\n{prompt}'
    return f'Scheduled task "{label}", run for {when_local}:\n\n{prompt}'


class UnattendedTurnRunner:
    """The ``UnattendedRunner`` for this process.

    ``runtime`` answers the AgentRuntime (read per run: tests and the app
    swap it); ``build_context`` builds a turn's tools and permissions block;
    ``usage_columns`` maps usage onto the Message columns; ``settings``
    answers the scheduled_tasks capability settings (the shared budgets)."""

    def __init__(
        self,
        *,
        runtime: Callable[[], Any],
        session_factory: Callable[[], Any],
        build_context: BuildContext,
        usage_columns: UsageColumns,
        settings: SettingsSource,
        ledger: Optional[AutomationLedger] = None,
        max_concurrent: int = MAX_CONCURRENT_RUNS,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._runtime = runtime
        self._session_factory = session_factory
        self._build_context = build_context
        self._usage_columns = usage_columns
        self._settings = settings
        self._ledger = ledger or AutomationLedger(session_factory)
        self._slots = asyncio.Semaphore(max_concurrent)
        self._clock = clock

    async def _caps(self) -> tuple[float, float, int]:
        """(per-run USD, per-day USD, runs per day) from the owner's
        settings; the defaults when they cannot be read."""
        from services.capabilities.scheduled_tasks import SCHEDULE_SETTINGS_DEFAULTS as defaults

        try:
            values = dict(await self._settings())
        except Exception as exc:
            logger.warning("unattended_settings_unreadable", error_type=type(exc).__name__)
            values = {}
        run = values.get("run_cap_cents", defaults["run_cap_cents"])
        day = values.get("day_cap_cents", defaults["day_cap_cents"])
        runs = values.get("runs_per_day", defaults["runs_per_day"])
        return float(run) / 100, float(day) / 100, int(runs)

    async def budget_left(self, user_id: str, *, exclude_run_id: Optional[str] = None) -> BudgetState:
        """What is left of *user_id*'s rolling 24-hour unattended budget.
        ``exclude_run_id`` leaves out the ledger row of the run being
        checked: the caller opens it ("running") before the run, and a run
        must not count against its own budget."""
        _run_cap, day_cap, runs_cap = await self._caps()
        spent, runs = await self._ledger.spent_today(user_id, exclude=exclude_run_id)
        return BudgetState(usd_left=round(day_cap - spent, 6), runs_left=runs_cap - runs)

    async def run(self, request: UnattendedRequest) -> UnattendedOutcome:
        """Run *request* once a slot is free. The wait for a slot is bounded
        by ``request.queue_wait_s`` and is not part of the run's own
        deadline; a run that gets no slot in time is "skipped_busy" (it did
        not run, so it is no failure)."""
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=max(request.queue_wait_s, 0.0))
        except asyncio.TimeoutError:
            logger.info("unattended_run_no_slot", run_id=request.run_id)
            return UnattendedOutcome(status="skipped_busy", run_id=request.run_id)
        try:
            return await self._run(request)
        finally:
            self._slots.release()

    async def _run(self, req: UnattendedRequest) -> UnattendedOutcome:
        from models.user import User

        run_cap, _day, _runs = await self._caps()
        max_usd = req.max_usd if req.max_usd is not None else run_cap
        budget = await self.budget_left(req.user_id, exclude_run_id=req.run_id)
        if budget.exhausted:
            return UnattendedOutcome(status="skipped_budget", run_id=req.run_id, budget_usd=max_usd)
        runtime = self._runtime()
        if runtime is None:
            return UnattendedOutcome(status="failed", reply="The assistant is not available.", run_id=req.run_id)
        max_usd = min(max_usd, max(budget.usd_left, 0.0))
        owner = uuid.UUID(req.user_id)
        run_id = req.run_id or str(uuid.uuid4())
        when_local = self._clock().strftime("%Y-%m-%d %H:%M UTC")
        async with self._session_factory() as db:
            user = (await db.execute(select(User).where(User.id == owner))).scalar_one_or_none()
            if user is None or not user.is_active:
                return UnattendedOutcome(status="failed", reply="The account is not active.", run_id=run_id)
            if user.timezone:
                when_local = _local_now(self._clock(), user.timezone) or when_local
            conversation = await ensure_conversation(
                db, owner, req.conversation_id, req.conversation_title or req.label, req.origin
            )
            content = run_message(req.label, when_local, req.prompt, req.origin)
            await add_message(db, conversation, "user", content)
            ctx = await self._build_context(user, db, conversation)
            run = UnattendedRun(
                label=req.label,
                origin=req.origin,
                reads=frozenset(req.reads) | ALWAYS_READS,
                writes=frozenset(req.writes),
                connector_id=req.connector_id,
                trusted_text=req.prompt,
                max_usd=max_usd,
                max_rounds=req.max_rounds,
                card_ttl_minutes=CARD_TTL_MINUTES,
                seed_results=tuple(req.seed_results),
            )
            fenced, missing = build_fence(list(ctx.tools), run)
            conversation_id = conversation.id
            provider, model = user.llm_provider, user.llm_model
            permissions_text = ctx.permissions_text
            # The run's conversation's tutor mode (None while the capability
            # is off): an owner's account or course lock applies to a run
            # nobody is watching too (top10:tutor_mode).
            tutor = getattr(ctx, "tutor", None)
            await db.commit()

        from services.agent.providers import ProviderError, ProviderNotConfigured
        from services.agent.runtime import TurnUsage, estimate_usd

        turn = TurnUsage()
        status, reply, response = "ok", "", None
        try:
            response = await asyncio.wait_for(
                runtime.chat(
                    messages=[{"role": "user", "content": content}],
                    tools=fenced,
                    user_id=req.user_id,
                    conversation_id=str(conversation_id),
                    llm_provider=provider,
                    llm_model=model,
                    memory_block=None,
                    permissions_text=permissions_text,
                    task_id=f"{UNATTENDED_TASK_PREFIX}{run_id}",
                    usage_sink=turn,
                    stop_mark=agent_cancel.mark(req.user_id),
                    channel=None,
                    unattended=run,
                    **({"tutor": tutor} if tutor is not None else {}),
                ),
                timeout=req.deadline_s,
            )
        except asyncio.TimeoutError:
            status, reply = "timed_out", _TIMED_OUT_REPLY
        except ProviderNotConfigured:
            status, reply = "not_configured", _NOT_CONFIGURED_REPLY
        except ProviderError as exc:
            logger.warning("unattended_run_provider_error", run_id=run_id, error_type=type(exc).__name__)
            status, reply = "failed", _FAILED_REPLY
        except asyncio.CancelledError:
            await self._store(conversation_id, _STOPPED_REPLY, turn, None, tutor=tutor)
            raise
        except Exception as exc:
            logger.error("unattended_run_failed", run_id=run_id, error_type=type(exc).__name__)
            status, reply = "failed", _FAILED_REPLY

        cards = 0
        blocked: tuple[str, ...] = ()
        if response is not None:
            reply = response.content
            cards = len(response.pending_approvals)
            blocked = tuple(
                dict.fromkeys(
                    b.tool_name
                    for b in response.blocked_actions
                    if b.policy in ("unattended_fence", "unattended_taint")
                )
            )
            if response.stopped:
                status = "stopped"
            elif response.unattended_stop == "budget":
                status = "over_budget"
            elif cards:
                status = "card_parked"
        usage = dict(response.usage if response is not None else turn.usage)
        used_provider = (response.provider if response is not None else turn.provider) or ""
        used_model = (response.model if response is not None else turn.model) or ""
        served = (response.served_model if response is not None else turn.served_model) or None
        cost = estimate_usd(usage, used_provider, used_model, served) if usage else 0.0
        message_id = await self._store(conversation_id, reply, turn, response, tutor=tutor)
        return UnattendedOutcome(
            status=status,
            reply=reply,
            cards=cards,
            unavailable=tuple(missing),
            usage=usage,
            cost_usd=cost,
            conversation_id=str(conversation_id),
            message_id=message_id,
            run_id=run_id,
            provider=used_provider,
            model=used_model,
            blocked=blocked,
            budget_usd=max_usd,
        )

    async def _store(
        self, conversation_id: Any, reply: str, turn: Any, response: Any, *, tutor: Any = None
    ) -> Optional[str]:
        """Persist the run's assistant row with its usage (and the tool
        calls it recorded), and the conversation's tutor mode when the run
        changed it (a course lock it engaged); best effort, logged by type."""
        from models.conversation import Conversation
        from services.agent.runtime import redact_binary_for_model

        source = response if response is not None else turn
        try:
            async with self._session_factory() as db:
                conversation = await db.get(Conversation, conversation_id)
                if conversation is None:
                    return None
                if tutor is not None:
                    from services.tutor.service import persist_tutor_state

                    await persist_tutor_state(db, conversation, tutor)
                calls = response.tool_calls if response is not None else turn.tool_calls
                message = await add_message(
                    db,
                    conversation,
                    "assistant",
                    reply or "(No reply.)",
                    tool_calls=redact_binary_for_model(calls) or None,
                    **self._usage_columns(dict(source.usage), source.provider or None, source.model or None),
                )
                message_id = str(message.id)
                await db.commit()
            return message_id
        except Exception as exc:
            logger.error("unattended_reply_not_stored", error_type=type(exc).__name__)
            return None


def _local_now(now: datetime, zone: str) -> Optional[str]:
    from services.scheduler.timezones import parse_zone

    tz, _err = parse_zone(zone)
    if tz is None:
        return None
    local = now.astimezone(tz)
    return f"{local:%a %Y-%m-%d %H:%M} ({zone})"
