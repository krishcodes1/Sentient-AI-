"""One integration test of the canonical per-call gate order (plan hotspot on
runtime.py) with every feature that feeds the approval path together: the
unattended fence, tutor mode's withheld tools, the secret guard, standing
consent (tiers and grants), the taint gate, and card creation with its origin
or grant offer.

Why it exists: each feature is tested on its own, but their order is what keeps
them safe together. A low-risk grant must never run a write inside an
unattended turn, a tutor-withheld submission must be refused before any tier
could run it, a key in the arguments must be refused even when the tier would
have run the call, a HIGH call must ask under any tier, and only an attended,
untainted LOW card may offer a grant. The real runtime, adapter, executor and
grant store run over in-memory SQLite; Google is a MockTransport fake and the
model is scripted. services.tutor is imported unconditionally: a renamed or
missing tutor module fails this test rather than skipping its tutor part.
"""

from __future__ import annotations

import pytest

from services.agent.tool_registry import ConnectorSpec, build_tools
from services.agent.unattended import UnattendedRun
from services.tutor.locks import CourseLock
from services.tutor.state import TutorState, TutorTurn
from tests.test_computer_precheck import calls
from tests import test_low_risk_runtime as low_risk
from tests.test_low_risk_runtime import DONE, EVENT, FINAL, MID, MID2, PRIVATE_EVENT, STAR

# The fixtures of the low-risk runtime tests, shared here.
google = low_risk.google
world = low_risk.world

CARD = "4111 1111 1111 1111"  # a Luhn-valid test card number


@pytest.mark.asyncio
async def test_fence_tutor_secret_guard_tiers_taint_and_cards_in_canonical_order(world, google):
    await world.account_default("low_risk")
    connector_id = await world.connect("low_risk")

    # 1. Attended, on the low_risk tier, one round in gate order:
    #    - a LOW star runs on standing consent (no card),
    #    - a LOW draft carrying a card number is refused by the secret guard
    #      although the tier would have run it,
    #    - a HIGH trash asks (a card, with the plain risk note), and ends the
    #      round.
    _runtime, response = await world.run(
        calls(
            ("c1", STAR, {"message_id": MID, "add_label_ids": ["STARRED"]}),
            ("c2", "google_workspace.create_draft", {"to": "me@example.com", "subject": "card", "body": CARD}),
            ("c3", STAR, {"message_id": MID2, "add_label_ids": ["TRASH"]}),
        ),
        FINAL,
    )
    assert google.writes() == [f"POST /gmail/v1/users/me/messages/{MID}/modify"]
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [
        ("google_workspace.create_draft", "secret_guard")
    ]
    [trash] = response.pending_approvals
    assert trash.arguments["add_label_ids"] == ["TRASH"]
    assert "Trash or Spam" in trash.reason and trash.risk_note is None
    assert trash.low_risk_account is None  # the tier already covers LOW calls
    assert response.content.endswith(DONE + "1 × google_workspace.modify_labels on School Gmail.")
    ran = [e for e in world.audit.entries if e["event"] == "tool_executed"]
    assert [(e["tool"], e["approval"]) for e in ran] == [(STAR, "low_risk")]

    # 2. The same account also holds a grant, and the turn is unattended:
    #    the fence refuses what the run was not given, and the one write it
    #    was given still becomes a card with the run's origin and no grant
    #    offer. Neither the tier nor the grant runs anything.
    await world.grants.allow(user_id=world.user_id, connector_id=connector_id)
    google.requests.clear()
    run = UnattendedRun(
        label="Morning tidy",
        origin="schedule:gate-order",
        reads=frozenset({"google_workspace.get_messages"}),
        writes=frozenset({STAR}),
    )
    _runtime, response = await world.run(
        calls(
            ("u1", EVENT, {"event_data": PRIVATE_EVENT}),
            ("u2", STAR, {"message_id": MID, "add_label_ids": ["STARRED"]}),
        ),
        FINAL,
        unattended=run,
    )
    assert google.writes() == []
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [(EVENT, "unattended_fence")]
    [card] = response.pending_approvals
    assert card.tool_name == STAR and card.low_risk_account is None
    stored = {a.action_id: a for a in await world.approvals.list_pending(world.user_id)}[card.action_id]
    assert stored.origin == "schedule:gate-order" and stored.grant_offer is None
    assert DONE not in response.content

    # 3. Tutor mode's withheld tool is refused before the permission check,
    #    so no tier could run it and no card is made.
    lock = CourseLock(
        lock_id="11111111-1111-1111-1111-111111111111",
        scope="course",
        label="MATH 221",
        canvas_course_id="5",
        course_code="MATH 221",
    )
    runtime = world.runtime()
    from tests.conftest import use_provider
    from tests.test_computer_precheck import Script

    use_provider(
        runtime,
        Script(
            calls(("t1", "canvas.submit_assignment", {"course_id": "5", "assignment_id": "9", "submission_data": {}})),
            FINAL,
        ),
    )
    canvas = build_tools(
        [ConnectorSpec("canvas", granted_scopes=("submissions.write",), permission_tier="auto_approve")],
        user_default_tier="auto_approve",
    )
    response = await runtime.chat(
        messages=[{"role": "user", "content": "hand in my problem set"}],
        tools=canvas,
        user_id=world.user_id,
        conversation_id="c1",
        tutor=TutorTurn(TutorState(), [lock], conversation_id="c1"),
    )
    assert [(b.tool_name, b.policy) for b in response.blocked_actions] == [
        ("canvas.submit_assignment", "tutor_mode")
    ]
    assert response.pending_approvals == []
