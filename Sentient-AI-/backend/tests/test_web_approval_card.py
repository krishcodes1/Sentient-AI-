"""The web approval card's plain words: GET /agent/approvals and the
streamed ``pending_approval`` frame carry every value as a labelled detail
(``details``) and the card's check code (``check_code``), the same code the
Telegram and Slack cards end with; the streamed progress, blocked and
decision texts name the action in plain words, never by its tool id.

Why it exists: the web card used to read "Tool google_workspace.send_email
wants to run" over a JSON dump of the arguments, and the transcript recorded
"[Approved] Executed 'google_workspace.send_email'." over the raw result
(docs/bot-message-style.md). These tests pin the new shape: every value
still shown in full (spec F3), the check code computed exactly as the chat
cards compute it, and helpers that never raise on odd input.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from api.routes import agent as agent_routes
from services.agent.runtime import PendingApproval
from services.notifications import cards

EMAIL_TOOL = "google_workspace.send_email"
EMAIL_ARGS = {
    "to": "priya@acme.com",
    "subject": "Friday lunch",
    "body": "Hi Priya,\nare we still on for noon?",
}


def _pending(tool_name: str = EMAIL_TOOL, arguments: Any = None) -> PendingApproval:
    return PendingApproval(
        action_id="a-1",
        tool_name=tool_name,
        arguments=dict(EMAIL_ARGS) if arguments is None else arguments,
        reason="Send an email to priya@acme.com from your Gmail",
        expires_at="2099-01-01T00:00:00+00:00",
        conversation_id=None,
    )


# ── the card's details and check code ────────────────────────────────────


def test_details_label_every_value_in_order_and_keep_every_line():
    fields = agent_routes._approval_card_fields(EMAIL_TOOL, EMAIL_ARGS)
    assert fields["details"] == [
        {"label": label, "value": value}
        for label, value in cards.detail_pairs(EMAIL_TOOL, EMAIL_ARGS)
    ]
    values = [d["value"] for d in fields["details"]]
    assert values == ["priya@acme.com", "Friday lunch", "Hi Priya,\nare we still on for noon?"]
    assert all("_" not in d["label"] and "{" not in d["label"] for d in fields["details"])


def test_the_check_code_is_the_one_the_chat_cards_end_with():
    fields = agent_routes._approval_card_fields(EMAIL_TOOL, EMAIL_ARGS)
    card = cards.layout_card(["🔐 Send an email"], EMAIL_ARGS, tool_name=EMAIL_TOOL, max_chars=4096)
    assert card.final_lines[-1] == f"Check code {fields['check_code']}"
    assert fields["check_code"] == cards.check_code(EMAIL_ARGS)
    groups = fields["check_code"].split(" ")
    assert len(groups) == 4 and all(len(g) == 4 for g in groups)


def test_a_desktop_act_card_leaves_out_the_stored_screen_as_the_chat_card_does():
    arguments = {"action": "type", "text": "hello", "_screen": {"app": "Notepad"}}
    fields = agent_routes._approval_card_fields("desktop.act", arguments)
    shown = cards.card_arguments("desktop.act", arguments)
    assert "_screen" not in shown
    assert fields["check_code"] == cards.check_code(shown)
    assert len(fields["details"]) == 2
    assert "Notepad" not in json.dumps(fields["details"])


@pytest.mark.parametrize(
    "arguments", [None, {}, "text", 7, [1, 2], {"nested": {"deep": [None, True]}}]
)
def test_odd_arguments_never_raise(arguments):
    fields = agent_routes._approval_card_fields(EMAIL_TOOL, arguments)
    assert isinstance(fields["details"], list)
    assert isinstance(fields["check_code"], str)


def test_a_failing_details_builder_leaves_the_details_empty(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr(agent_routes.approval_cards, "detail_pairs", boom)
    monkeypatch.setattr(agent_routes.approval_cards, "check_code", boom)
    fields = agent_routes._approval_card_fields(EMAIL_TOOL, EMAIL_ARGS)
    assert fields == {"details": [], "check_code": None}


def test_the_rest_shape_carries_details_and_check_code():
    out = agent_routes._pending_approval_out(_pending()).model_dump()
    assert out["arguments"] == EMAIL_ARGS
    assert out["details"][0] == {"label": "To", "value": "priya@acme.com"}
    assert out["check_code"] == cards.check_code(EMAIL_ARGS)


# ── the routes ───────────────────────────────────────────────────────────


class _CardRuntime:
    """One pending email card, and a streamed turn that searches, skips a
    step and parks that card."""

    async def list_pending_approvals(self, user_id: str) -> list[PendingApproval]:
        return [_pending()]

    async def stream_chat(self, **kwargs):
        pending = {
            "action_id": "a-1",
            "tool_name": EMAIL_TOOL,
            "arguments": dict(EMAIL_ARGS),
            "reason": "Send an email to priya@acme.com from your Gmail",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "conversation_id": None,
            "risk_note": None,
            "image": None,
            "weekly_app": None,
            "low_risk_account": None,
        }
        blocked = {
            "tool": "desktop.act",
            "reason": "Your safety settings don't allow this.",
            "policy": "p",
        }
        yield {"type": "tool_call", "data": {"name": "web.search"}}
        yield {"type": "tool_result", "data": {"name": "web.search"}}
        yield {"type": "blocked", "data": blocked}
        yield {"type": "pending_approval", "data": pending}
        yield {
            "type": "done",
            "data": {
                "content": "I need your OK first.",
                "tool_calls": [],
                "pending_approvals": [pending],
                "blocked_actions": [
                    {"tool_name": "desktop.act", "reason": blocked["reason"], "policy": "p"}
                ],
            },
        }


def _frames(body: str) -> list[tuple[str, dict[str, Any]]]:
    frames = []
    for block in body.split("\n\n"):
        lines = block.strip().splitlines()
        event = next((line[7:] for line in lines if line.startswith("event: ")), None)
        data = next((line[6:] for line in lines if line.startswith("data: ")), None)
        if event and data:
            frames.append((event, json.loads(data)))
    return frames


@pytest.mark.asyncio
async def test_the_approvals_route_lists_details_and_the_check_code(client, session_factory):
    from main import app
    from tests.conftest import auth_headers, make_user

    app.dependency_overrides[agent_routes.get_runtime] = lambda: _CardRuntime()
    try:
        _, token = await make_user(session_factory, "web-card@example.com")
        listed = await client.get("/api/agent/approvals", headers=auth_headers(token))
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    assert listed.status_code == 200
    [card] = listed.json()
    assert card["details"] == [
        {"label": label, "value": value}
        for label, value in cards.detail_pairs(EMAIL_TOOL, EMAIL_ARGS)
    ]
    assert card["check_code"] == cards.check_code(EMAIL_ARGS)


@pytest.mark.asyncio
async def test_the_stream_speaks_plainly_and_streams_the_whole_card(client, session_factory):
    from main import app
    from tests.conftest import auth_headers, make_user

    app.dependency_overrides[agent_routes.get_runtime] = lambda: _CardRuntime()
    try:
        _, token = await make_user(session_factory, "web-stream@example.com")
        conv = (
            await client.post("/api/agent/conversations", headers=auth_headers(token), json={})
        ).json()
        resp = await client.post(
            f"/api/agent/conversations/{conv['id']}/messages/stream",
            headers=auth_headers(token),
            json={"content": "email Priya"},
        )
    finally:
        app.dependency_overrides.pop(agent_routes.get_runtime, None)
    frames = dict(_frames(resp.text))
    assert frames["tool_call"]["phrase"] == "Searching the web…"
    assert frames["blocked"]["phrase"] == "click or type in an app on your computer"
    assert frames["pending_approval"]["check_code"] == cards.check_code(EMAIL_ARGS)
    assert frames["pending_approval"]["details"][0] == {"label": "To", "value": "priya@acme.com"}
    done = frames["done"]
    assert done["pending_approvals"][0]["check_code"] == cards.check_code(EMAIL_ARGS)
    assert done["blocked_actions"][0]["phrase"] == "click or type in an app on your computer"
    for event in ("tool_call", "blocked"):
        assert "web.search" not in frames[event].get("phrase", "")
        assert "desktop.act" not in frames[event].get("phrase", "")


# ── the transcript's decision rows ───────────────────────────────────────


def test_the_decision_rows_name_the_action_in_plain_words():
    content, payload = agent_routes._render_decision_message(
        True, EMAIL_TOOL, {"ok": True, "id": "m-1"}
    )
    assert content == "You approved my request to send an email, and it's done."
    # The whole result stays with the row for the step's technical details.
    assert payload == [{"name": EMAIL_TOOL, "result": {"ok": True, "id": "m-1"}, "approved": True}]

    failed, _ = agent_routes._render_decision_message(True, EMAIL_TOOL, {"error": "SMTP 550"})
    assert failed == "You approved my request to send an email, but it didn't work."
    assert "SMTP" not in failed

    denied, none = agent_routes._render_decision_message(False, EMAIL_TOOL, None)
    assert denied == "You denied my request to send an email, so I didn't do it."
    assert none is None


@pytest.mark.parametrize("tool_name", ["", None, 5])
def test_a_decision_row_without_a_usable_tool_name_still_reads_plainly(tool_name):
    content, _ = agent_routes._render_decision_message(False, tool_name, None)  # type: ignore[arg-type]
    assert content == "You denied my request to do that step, so I didn't do it."
    assert "—" not in content and "–" not in content and "[" not in content
