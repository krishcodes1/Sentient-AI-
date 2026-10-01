"""Tests for study.delete, the one study action behind an approval card: the card's
sentence comes from the deck's facts read from the database (title, items,
reviews), a model-supplied "_deck" is refused before any card, an unknown or
another user's deck is refused under study_rule with no card, the executor
refuses the call unapproved, the approved call checks ownership again and
removes the deck with its items, reviews and quizzes, and the card stays
under an auto_approve account default while every other study action runs
without one.

Why it exists: deleting a deck destroys the user's review history, so it must
never run on the model's say-so, and the owner must see what will go. The
runtime, the permission adapter and the executor are the real ones; the model
is a script and the database is in-memory SQLite.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import func, select

from core.config import settings
from models.study import StudyDeck, StudyItem, StudyQuizAttempt, StudyReview
from services.agent.approvals import InMemoryApprovalStore
from services.agent.permissions import ActionCategory, PermissionEngine, PermissionTier
from services.agent.providers import LLMResponse, ToolCall
from services.agent.runtime import AgentRuntime
from services.agent.tool_registry import (
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
    study_toolkit_of,
)
from services.capabilities import REGISTRY
from services.capabilities import report as capability_report
from services.capabilities import statuses_by_key
from services.capabilities.base import ReportContext
from services.tools.study import DECK_CARD_KEY, STUDY_RULE_POLICY, StudyToolkit
from tests.conftest import make_user, use_provider


def _gate(*keys: str):
    ctx = ReportContext(in_container=False, platform="win32", telegram_configured=False, browser_installed=False)
    switches = {c.key: c.key in keys for c in REGISTRY}
    statuses = statuses_by_key(capability_report(switches, ctx, use_cache=False))

    async def gate():
        return statuses

    return gate


class _Script:
    def __init__(self, *steps: LLMResponse) -> None:
        self.steps = list(steps)

    async def complete(self, messages, tools=None):
        return self.steps.pop(0) if self.steps else LLMResponse(content="done")

    async def stream(self, messages, tools=None):
        yield "done"


class _Audit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def log(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)


def _call(name: str, **arguments: Any) -> LLMResponse:
    return LLMResponse(content="", tool_calls=[ToolCall(id="t1", name=name, arguments=arguments)])


def _runtime(session_factory) -> tuple[AgentRuntime, ConnectorToolExecutor, _Audit]:
    gate = _gate("study")
    executor = ConnectorToolExecutor(session_factory=session_factory, capability_gate=gate)
    audit = _Audit()
    runtime = AgentRuntime(
        config=settings,
        permission_engine=RuntimePermissionAdapter(capability_gate=gate),
        tool_executor=executor,
        audit_service=audit,
        approval_store=InMemoryApprovalStore(),
    )
    return runtime, executor, audit


async def _turn(runtime: AgentRuntime, user_id: str, *steps: LLMResponse, default_tier: str = "user_confirm"):
    use_provider(runtime, _Script(*steps))
    tools = build_tools([], enabled_capabilities=frozenset({"study"}), user_default_tier=default_tier)
    return await runtime.chat(
        messages=[{"role": "user", "content": "Delete my old deck."}], tools=tools, user_id=user_id
    )


async def _deck_with_history(kit: StudyToolkit, user_id: str) -> str:
    saved = await kit.execute(
        "save",
        {
            "title": "Bio 101 – Lecture 3",
            "items": [{"front": f"Term {i}?", "back": f"Meaning {i}"} for i in range(3)],
        },
        user_id,
    )
    for item_id in saved["added_ids"][:2]:
        await kit.execute("review", {"action": "grade", "item_id": item_id, "rating": "good"}, user_id)
    await kit.execute("quiz", {"action": "start", "deck_id": saved["deck_id"]}, user_id)
    return saved["deck_id"]


async def _count(session_factory, model) -> int:
    async with session_factory() as session:
        return int((await session.execute(select(func.count()).select_from(model))).scalar_one())


@pytest.mark.asyncio
@pytest.mark.parametrize("default_tier", ["user_confirm", "auto_approve"])
async def test_the_card_states_the_decks_facts_and_the_approved_delete_cascades(session_factory, default_tier):
    user, _ = await make_user(session_factory, f"delete-{default_tier}@example.com")
    uid = str(user.id)
    runtime, executor, _audit = _runtime(session_factory)
    deck_id = await _deck_with_history(study_toolkit_of(executor), uid)

    response = await _turn(runtime, uid, _call("study.delete", deck_id=deck_id), default_tier=default_tier)

    [card] = response.pending_approvals
    assert card.tool_name == "study.delete"
    assert card.reason == 'Delete the deck "Bio 101 – Lecture 3" (3 items, 2 reviews). This cannot be undone.'
    assert card.arguments == {"deck_id": deck_id, DECK_CARD_KEY: {"title": "Bio 101 – Lecture 3", "items": 3, "reviews": 2}}
    assert await _count(session_factory, StudyDeck) == 1  # nothing until approved

    outcome = await runtime.approve_action(card.action_id, uid)
    assert outcome["result"]["ok"] is True and outcome["result"]["deleted_deck"] is True, outcome
    for model in (StudyDeck, StudyItem, StudyReview, StudyQuizAttempt):
        assert await _count(session_factory, model) == 0, model


@pytest.mark.asyncio
async def test_deleting_some_items_names_how_many(session_factory):
    user, _ = await make_user(session_factory, "delete-items@example.com")
    uid = str(user.id)
    runtime, executor, _audit = _runtime(session_factory)
    kit = study_toolkit_of(executor)
    deck_id = await _deck_with_history(kit, uid)
    listing = await kit.execute("decks", {"deck_id": deck_id}, uid)
    doomed = [row["item_id"] for row in listing["items"][:2]]

    response = await _turn(runtime, uid, _call("study.delete", deck_id=deck_id, item_ids=doomed))
    [card] = response.pending_approvals
    assert card.reason == (
        'Delete 2 items (and their review history) from the deck "Bio 101 – Lecture 3". '
        "This cannot be undone."
    )
    outcome = await runtime.approve_action(card.action_id, uid)
    assert outcome["result"]["deleted_items"] == 2
    assert await _count(session_factory, StudyItem) == 1 and await _count(session_factory, StudyReview) == 0


@pytest.mark.asyncio
async def test_a_model_supplied_deck_fact_is_refused_before_any_card(session_factory):
    user, _ = await make_user(session_factory, "delete-forged@example.com")
    uid = str(user.id)
    runtime, executor, audit = _runtime(session_factory)
    deck_id = await _deck_with_history(study_toolkit_of(executor), uid)
    forged = {"title": "Old scratch deck", "items": 1, "reviews": 0}

    response = await _turn(runtime, uid, _call("study.delete", deck_id=deck_id, **{DECK_CARD_KEY: forged}))

    assert response.pending_approvals == []
    [blocked] = [e for e in audit.entries if e.get("event") == "tool_blocked"]
    assert blocked["policy"] == STUDY_RULE_POLICY and blocked["rule"] == "reserved_argument"
    assert [b.policy for b in response.blocked_actions] == [STUDY_RULE_POLICY]
    assert await _count(session_factory, StudyDeck) == 1


@pytest.mark.asyncio
async def test_an_unknown_or_foreign_deck_gets_no_card(session_factory):
    owner, _ = await make_user(session_factory, "delete-owner@example.com")
    other, _ = await make_user(session_factory, "delete-other@example.com")
    runtime, executor, audit = _runtime(session_factory)
    deck_id = await _deck_with_history(study_toolkit_of(executor), str(owner.id))

    for target in (deck_id, str(uuid.uuid4())):
        response = await _turn(runtime, str(other.id), _call("study.delete", deck_id=target))
        assert response.pending_approvals == []
    refusals = [e for e in audit.entries if e.get("event") == "tool_blocked"]
    assert [e["policy"] for e in refusals] == [STUDY_RULE_POLICY, STUDY_RULE_POLICY]
    # The same answer for someone else's deck and for none at all.
    assert refusals[0]["reason"] == refusals[1]["reason"]
    assert await _count(session_factory, StudyDeck) == 1


@pytest.mark.asyncio
async def test_the_executor_refuses_unapproved_and_rechecks_when_approved(session_factory):
    owner, _ = await make_user(session_factory, "delete-exec@example.com")
    other, _ = await make_user(session_factory, "delete-exec-other@example.com")
    executor = ConnectorToolExecutor(session_factory=session_factory, capability_gate=_gate("study"))
    kit = study_toolkit_of(executor)
    deck_id = await _deck_with_history(kit, str(owner.id))

    unapproved = await executor.execute("study.delete", {"deck_id": deck_id}, user_id=str(owner.id))
    assert unapproved["ok"] is False and unapproved["requires_approval"] is True
    # Approved but never bound (no "_deck" from the card): refused.
    unbound = await executor.execute("study.delete", {"deck_id": deck_id}, user_id=str(owner.id), approved=True)
    assert unbound["ok"] is False and unbound["rule"] == "unbound"
    # A card bound for the owner cannot delete through another account.
    bound = await executor.approval_arguments_async("study.delete", {"deck_id": deck_id}, str(owner.id), task_id=None)
    stolen = await executor.execute("study.delete", bound, user_id=str(other.id), approved=True)
    assert stolen["ok"] is False and stolen.get("not_found")
    assert await _count(session_factory, StudyDeck) == 1
    done = await executor.execute("study.delete", bound, user_id=str(owner.id), approved=True)
    assert done["ok"] is True and await _count(session_factory, StudyDeck) == 0


def test_only_delete_is_carded_whatever_the_account_default():
    for default in ("user_confirm", "auto_approve"):
        tools = {t.name: t for t in build_tools([], enabled_capabilities=frozenset({"study"}), user_default_tier=default)}
        assert tools["study.delete"].permission_tier == "approval", default
        for name in ("study.save", "study.decks", "study.edit", "study.review", "study.quiz", "study.progress", "study.settings", "study.export"):
            assert tools[name].permission_tier == "auto", (default, name)


def test_study_policy_rows():
    engine = PermissionEngine()
    tiers = {cat: engine.check_permission("study", "x", cat).tier for cat in ActionCategory}
    assert tiers == {
        ActionCategory.READ: PermissionTier.AUTO_APPROVE,
        ActionCategory.WRITE: PermissionTier.AUTO_APPROVE,
        ActionCategory.DELETE: PermissionTier.USER_CONFIRM,
        ActionCategory.EXECUTE: PermissionTier.HARD_BLOCKED,
        ActionCategory.FINANCIAL: PermissionTier.HARD_BLOCKED,
    }


def test_the_bind_refusal_policy_names_the_toolkits():
    from services.agent import runtime as runtime_mod

    assert runtime_mod._BIND_REFUSAL_POLICIES["study.delete"] == STUDY_RULE_POLICY
