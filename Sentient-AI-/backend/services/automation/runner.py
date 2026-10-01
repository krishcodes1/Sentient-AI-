"""The contract between whatever decides an unattended run should happen (the
schedule sweeper now, the trigger sweeper in wave 2) and what runs it: the
request, the outcome, the budget state and the runner protocol.

Why it exists: the implementation lives next to the chat pipeline in
api/routes/agent.py (``build_unattended_runner``: conversations, tools,
usage columns, the runtime) and is hung on ``app.state.unattended_runner``;
callers depend only on these types, so they are testable with a fake runner
and never import the routes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol

from services.agent.unattended import SeedResult

# Every status an outcome can have.
OUTCOME_STATUSES = (
    "ok",
    "card_parked",
    "over_budget",
    "failed",
    "stopped",
    "timed_out",
    "not_configured",
    "skipped_budget",
    "skipped_busy",
)
# The ones that count as a failed run for a task's error limit.
FAILED_STATUSES = frozenset({"failed", "timed_out", "not_configured"})


@dataclass(frozen=True)
class UnattendedRequest:
    """One run to make. ``reads`` and ``writes`` are canonical tool names
    (the fence adds the clock); ``prompt`` is the owner's approved text;
    ``conversation_id`` is the conversation to write into (reused when it
    still exists, else a new one titled ``conversation_title``);
    ``max_usd`` None means the owner's per-run cap; ``run_id`` is the
    ledger row this run records into (left out of the budget check);
    ``queue_wait_s`` bounds the wait for a free runner slot, which is not
    part of ``deadline_s`` (no slot in time: "skipped_busy")."""

    user_id: str
    origin: str
    label: str
    prompt: str
    reads: tuple[str, ...]
    writes: tuple[str, ...] = ()
    connector_id: Optional[str] = None
    seed_results: tuple[SeedResult, ...] = ()
    conversation_id: Optional[str] = None
    conversation_title: str = ""
    max_usd: Optional[float] = None
    max_rounds: int = 6
    deadline_s: float = 180.0
    run_id: Optional[str] = None
    queue_wait_s: float = 60.0


@dataclass(frozen=True)
class UnattendedOutcome:
    """What one run did. ``reply`` is the assistant's text (as stored);
    ``cards`` how many approval cards it parked; ``unavailable`` the listed
    tools it could not be offered; ``blocked`` the calls the fence or the
    taint gate refused; ``budget_usd`` the per-run cap it ran under."""

    status: str
    reply: str = ""
    cards: int = 0
    unavailable: tuple[str, ...] = ()
    usage: dict[str, int] = field(default_factory=dict)
    cost_usd: float = 0.0
    conversation_id: Optional[str] = None
    message_id: Optional[str] = None
    run_id: Optional[str] = None
    provider: str = ""
    model: str = ""
    blocked: tuple[str, ...] = ()
    budget_usd: Optional[float] = None


@dataclass(frozen=True)
class BudgetState:
    """What is left of a user's daily unattended budget."""

    usd_left: float
    runs_left: int

    @property
    def exhausted(self) -> bool:
        return self.usd_left <= 0 or self.runs_left <= 0


class UnattendedRunner(Protocol):
    async def run(self, request: UnattendedRequest) -> UnattendedOutcome: ...

    async def budget_left(self, user_id: str, *, exclude_run_id: Optional[str] = None) -> BudgetState: ...
