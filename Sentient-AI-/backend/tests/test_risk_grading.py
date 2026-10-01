"""Tests for the risk grade every connector action gets (services/agent/risk.py):
the base grade from the catalog, the argument escalations, the golden list of
LOW actions, and that no reason ever quotes an argument.

Why it exists: standing consent (the auto_approve tier, the "Allow low-risk
changes" tier, 7-day grants) runs calls with no card on the strength of this
grade alone. A LOW grade on a send, a delete, a share or an invitation would
let one of those run unattended; adding an action to the LOW set must take a
reviewed change to the golden list below. Pure functions over the real
catalog; nothing runs a connector.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from services.agent import risk
from services.agent.permissions import ActionCategory
from services.agent.risk import Risk, grade_spec, grade_tool, ran_without_asking_line
from services.agent.tool_registry import CONNECTOR_CATALOG
from services.connectors import registry as connector_registry
from services.connectors.definition import ToolSpec, _schema

# The v1 LOW set. Adding to it is a reviewed change: each entry is a small,
# undoable change to the owner's own account that nobody else sees.
GOLDEN_LOW = {
    "google_workspace.create_draft",
    "google_workspace.modify_labels",
    "google_workspace.create_event",
    "google_workspace.upload_file",
    "google_workspace.create_folder",
    "google_workspace.create_document",
    "google_workspace.create_contact",
    "microsoft.create_draft",
    "microsoft.flag_message",
    "microsoft.create_event",
    "microsoft.upload_file",
    "microsoft.create_folder",
    "microsoft.create_task",
    "microsoft.complete_task",
    "github.mark_notification_read",
}

SENTINEL = "SENTINEL-7f3b2c9a-secret"


def _value(prop: dict[str, Any], text: str = "x") -> Any:
    kind = prop.get("type")
    if prop.get("enum"):
        return prop["enum"][0]
    return {
        "integer": 1,
        "number": 1.5,
        "boolean": False,
        "array": [],
        "object": {},
    }.get(str(kind), text)


def representative(spec: ToolSpec, text: str = "x") -> dict[str, Any]:
    """Arguments of the right shape for every schema property."""
    props = (spec.parameters or {}).get("properties", {})
    return {name: _value(prop, text) for name, prop in props.items()}


def connector_specs() -> list[tuple[str, ToolSpec]]:
    return [
        (definition.key, spec)
        for definition in connector_registry.REGISTRY
        for spec in definition.actions
    ]


# ── base grades ─────────────────────────────────────────────────────────────


# One call per golden action that stays on the owner's own account.
LOW_EXAMPLES: dict[str, dict[str, Any]] = {
    "google_workspace.create_draft": {"to": "me@example.com", "subject": "s", "body": "b"},
    "google_workspace.modify_labels": {"message_id": "m1", "add_label_ids": ["STARRED"]},
    "google_workspace.create_event": {
        "event_data": {"summary": "Study", "start": {"date": "2026-10-01"}, "end": {"date": "2026-10-02"}}
    },
    "google_workspace.upload_file": {"name": "notes.txt", "content": "hi"},
    "google_workspace.create_folder": {"name": "Notes"},
    "google_workspace.create_document": {"title": "Lab report"},
    "google_workspace.create_contact": {"given_name": "Sam"},
    "microsoft.create_draft": {"subject": "s", "body": "b"},
    "microsoft.flag_message": {"message_id": "AAMk1"},
    "microsoft.create_event": {"subject": "Gym", "start": "2026-10-01T16:00:00", "end": "2026-10-01T17:00:00"},
    "microsoft.upload_file": {"name": "notes.txt", "content": "hi"},
    "microsoft.create_folder": {"name": "Notes"},
    "microsoft.create_task": {"title": "Finish lab report"},
    "microsoft.complete_task": {"list_id": "L1", "task_id": "T1"},
    "github.mark_notification_read": {"thread_id": "123"},
}


@pytest.mark.parametrize(
    "key,spec", connector_specs(), ids=lambda v: v if isinstance(v, str) else v.action
)
def test_every_connector_action_gets_a_grade_from_its_declaration(key, spec):
    grade = grade_tool(f"{key}.{spec.action}", representative(spec))
    if spec.category in (ActionCategory.DELETE, ActionCategory.EXECUTE, ActionCategory.FINANCIAL):
        assert grade.risk is Risk.HIGH
    elif spec.always_confirm:
        assert grade.risk is Risk.HIGH
    elif spec.category == ActionCategory.READ:
        assert grade.risk is Risk.LOW
    elif spec.risk == "low":
        # Its hand-written example is LOW; what every other argument does to
        # the grade is pinned below.
        example = LOW_EXAMPLES[f"{key}.{spec.action}"]
        assert grade_tool(f"{key}.{spec.action}", example).risk is Risk.LOW, (key, spec.action)
    else:
        assert grade.risk in (Risk.MEDIUM, Risk.HIGH)


# The optional arguments a LOW action may take and stay LOW, each reviewed:
# they only shape the owner's own new item (a draft is not sent, a contact's
# fields stay in the owner's address book) and reach nobody else. Any other
# argument sent with a value (a folder or list that may be shared, guests, an
# overwrite, a system label) must raise the grade.
LOW_KEEPING_ARGUMENTS = {
    ("google_workspace.upload_file", "mime_type"),
    ("google_workspace.create_document", "text"),
    ("google_workspace.create_contact", "family_name"),
    ("google_workspace.create_contact", "email"),
    ("google_workspace.create_contact", "phone"),
    ("google_workspace.create_contact", "organization"),
    ("google_workspace.create_contact", "notes"),
    ("microsoft.create_draft", "to"),
    ("microsoft.create_draft", "cc"),
    ("microsoft.flag_message", "status"),
    ("microsoft.create_event", "time_zone"),
    ("microsoft.create_event", "location"),
    ("microsoft.create_event", "body"),
    ("microsoft.create_task", "note"),
    ("microsoft.create_task", "due_date"),
    ("microsoft.create_task", "importance"),
}


def _filled(prop: dict[str, Any]) -> Any:
    """A non-empty value of the property's shape (the last enum value, so a
    default first value does not hide an escalation)."""
    if prop.get("enum"):
        return prop["enum"][-1]
    kind = str(prop.get("type"))
    if kind == "array":
        items = prop.get("items")
        return [_filled(items) if isinstance(items, dict) and items else "x"]
    if kind == "object":
        return {"x": "y"}
    return {"integer": 1, "number": 1.5, "boolean": True}.get(kind, "x")


@pytest.mark.parametrize("name", sorted(GOLDEN_LOW))
def test_any_other_argument_of_a_low_action_raises_its_grade_unless_reviewed(name):
    key, _, action = name.partition(".")
    spec = next(s for k, s in connector_specs() if k == key and s.action == action)
    example = LOW_EXAMPLES[name]
    for arg, prop in (spec.parameters or {}).get("properties", {}).items():
        if arg in example:
            continue
        grade = grade_tool(name, {**example, arg: _filled(prop)})
        if (name, arg) in LOW_KEEPING_ARGUMENTS:
            assert grade.risk is Risk.LOW, (name, arg)
        else:
            assert grade.risk is not Risk.LOW, (name, arg)


def test_every_reviewed_low_keeping_argument_exists():
    for name, arg in LOW_KEEPING_ARGUMENTS:
        key, _, action = name.partition(".")
        spec = next(s for k, s in connector_specs() if k == key and s.action == action)
        assert name in GOLDEN_LOW and arg in (spec.parameters or {}).get("properties", {}), (name, arg)


def test_a_task_in_a_named_to_do_list_asks_first():
    assert grade_tool("microsoft.create_task", {"title": "Lab"}).is_low
    named = grade_tool("microsoft.create_task", {"title": "Lab", "list_id": "AAMkList"})
    assert named.risk is Risk.MEDIUM and "may be shared" in named.reason


def test_the_low_eligible_set_is_exactly_the_golden_list():
    low = {
        f"{key}.{spec.action}"
        for key, spec in connector_specs()
        if risk.low_risk_eligible(spec)
    }
    assert low == GOLDEN_LOW
    # Every name on it exists in the catalog the executor dispatches from.
    for name in GOLDEN_LOW:
        key, _, action = name.partition(".")
        assert any(spec.action == action for spec in CONNECTOR_CATALOG[key]), name


def test_every_low_action_is_a_write_without_always_confirm_and_has_a_note():
    for key, spec in connector_specs():
        if spec.risk == "low":
            assert spec.category == ActionCategory.WRITE, (key, spec.action)
            assert not spec.always_confirm
            assert 0 < len(spec.low_risk_note) <= risk.LOW_RISK_NOTE_MAX_CHARS


def test_builtin_mcp_and_unknown_tools_are_high():
    for name in (
        "web.fetch_page",
        "reminders.create",
        "memory.remember",
        "desktop.act",
        "schedule.create",
        "mcp_server__tool",
        "mcp.some_tool",
        "nonsense",
        "google_workspace.no_such_action",
    ):
        assert grade_tool(name, {}).risk is Risk.HIGH, name


def test_a_slugged_name_grades_like_the_plain_one():
    plain = grade_tool("google_workspace.modify_labels", {"message_id": "m1", "add_label_ids": ["STARRED"]})
    slugged = grade_tool(
        "google_workspace__1a2b3c4d.modify_labels", {"message_id": "m1", "add_label_ids": ["STARRED"]}
    )
    assert plain == slugged and plain.is_low


@pytest.mark.parametrize(
    "tool",
    [
        "google_workspace.send_email",
        "google_workspace.reply",
        "google_workspace.forward",
        "google_workspace.share_file",
        "google_workspace.trash_message",
        "microsoft.send_mail",
        "microsoft.delete_message",
        "microsoft.create_share_link",
        "slack.post_message",
        "github.merge_pr",
        "github.rerun_failed_jobs",
        "github.dispatch_workflow",
        "robinhood.execute_trade",
        "canvas.submit_assignment",
        "google_workspace.respond_to_invite",
        "microsoft.respond_to_invite",
        "slack.invite_to_channel",
    ],
)
def test_sends_deletes_shares_runs_and_payments_are_high(tool):
    key, _, action = tool.partition(".")
    spec = next(s for s in CONNECTOR_CATALOG[key] if s.action == action)
    assert grade_tool(tool, representative(spec)).risk is Risk.HIGH


# ── escalations ─────────────────────────────────────────────────────────────

LABELS = "google_workspace.modify_labels"


@pytest.mark.parametrize(
    "add,remove,expected",
    [
        (["STARRED"], None, Risk.LOW),
        (["IMPORTANT"], ["STARRED"], Risk.LOW),
        (["Label_12"], None, Risk.LOW),
        (None, ["Label_3"], Risk.LOW),
        (["TRASH"], None, Risk.HIGH),
        (["spam"], None, Risk.HIGH),
        (None, ["TRASH"], Risk.HIGH),
        (["STARRED", "TRASH"], None, Risk.HIGH),
        (None, ["INBOX"], Risk.MEDIUM),
        (None, ["UNREAD"], Risk.MEDIUM),
        (["CATEGORY_PROMOTIONS"], None, Risk.MEDIUM),
        (["SENT"], None, Risk.MEDIUM),
        (None, None, Risk.MEDIUM),
    ],
)
def test_gmail_label_changes(add, remove, expected):
    arguments: dict[str, Any] = {"message_id": "18c2f0a9b1d2e3f4"}
    if add is not None:
        arguments["add_label_ids"] = add
    if remove is not None:
        arguments["remove_label_ids"] = remove
    assert grade_tool(LABELS, arguments).risk is expected


@pytest.mark.parametrize(
    "folder,expected",
    [
        ("archive", Risk.MEDIUM),
        ("AAMkAGI2TG93AAA=", Risk.MEDIUM),
        ("deleteditems", Risk.HIGH),
        ("DeletedItems", Risk.HIGH),
        ("junkemail", Risk.HIGH),
        ("recoverableitemsdeletions", Risk.HIGH),
    ],
)
def test_outlook_moves(folder, expected):
    grade = grade_tool(
        "microsoft.move_message", {"message_id": "AAMk1", "destination_folder": folder}
    )
    assert grade.risk is expected


def test_outlook_flag_and_draft_are_low():
    assert grade_tool("microsoft.flag_message", {"message_id": "AAMk1", "status": "flagged"}).is_low
    assert grade_tool("microsoft.create_draft", {"subject": "s", "body": "b"}).is_low


def test_calendar_events_without_guests_are_low_and_invitations_high():
    private = {"summary": "Study group", "start": {"dateTime": "2026-10-01T16:00:00Z"}, "end": {"dateTime": "2026-10-01T18:00:00Z"}}
    assert grade_tool("google_workspace.create_event", {"event_data": private}).is_low
    invited = {**private, "attendees": [{"email": "sam@example.com"}]}
    assert grade_tool("google_workspace.create_event", {"event_data": invited}).is_high
    # A key the check does not know stays MEDIUM (visibility, conferencing).
    public = {**private, "visibility": "public"}
    assert grade_tool("google_workspace.create_event", {"event_data": public}).risk is Risk.MEDIUM
    meet = {**private, "conferenceData": {"createRequest": {}}}
    assert grade_tool("google_workspace.create_event", {"event_data": meet}).risk is Risk.MEDIUM
    # Updating the guest list is HIGH; other updates stay MEDIUM.
    assert grade_tool(
        "google_workspace.update_event", {"event_id": "e1", "attendees": ["sam@example.com"]}
    ).is_high
    assert grade_tool("google_workspace.update_event", {"event_id": "e1", "summary": "x"}).risk is Risk.MEDIUM
    base = {"subject": "Gym", "start": "2026-10-01T16:00:00", "end": "2026-10-01T17:00:00"}
    assert grade_tool("microsoft.create_event", base).is_low
    assert grade_tool("microsoft.create_event", {**base, "attendees": ["sam@example.com"]}).is_high
    assert grade_tool("microsoft.create_event", {**base, "calendar_id": "AAMkCal"}).risk is Risk.MEDIUM


def test_files_in_the_root_are_low_and_folders_or_overwrites_medium():
    assert grade_tool("google_workspace.upload_file", {"name": "a.txt", "content": "hi"}).is_low
    assert grade_tool(
        "google_workspace.upload_file", {"name": "a.txt", "content": "hi", "folder_id": "root"}
    ).is_low
    assert grade_tool(
        "google_workspace.upload_file", {"name": "a.txt", "content": "hi", "folder_id": "1AbC"}
    ).risk is Risk.MEDIUM
    assert grade_tool("google_workspace.create_folder", {"name": "Notes"}).is_low
    assert grade_tool(
        "google_workspace.create_folder", {"name": "Notes", "parent_id": "1AbC"}
    ).risk is Risk.MEDIUM
    assert grade_tool("microsoft.upload_file", {"name": "a.txt", "content": "hi"}).is_low
    assert grade_tool(
        "microsoft.upload_file", {"name": "a.txt", "content": "hi", "overwrite": False}
    ).is_low
    assert grade_tool(
        "microsoft.upload_file", {"name": "a.txt", "content": "hi", "overwrite": True}
    ).risk is Risk.MEDIUM
    assert grade_tool(
        "microsoft.upload_file", {"name": "a.txt", "content": "hi", "folder_id": "01ABC"}
    ).risk is Risk.MEDIUM
    assert grade_tool(
        "microsoft.create_folder", {"name": "N", "parent_folder_id": "01ABC"}
    ).risk is Risk.MEDIUM


def test_public_gists_and_repositories_are_high():
    assert grade_tool("github.create_gist", {"filename": "a.md", "content": "x"}).risk is Risk.MEDIUM
    assert grade_tool("github.create_gist", {"filename": "a.md", "content": "x", "public": True}).is_high
    assert grade_tool("github.create_repo", {"name": "r"}).risk is Risk.MEDIUM
    assert grade_tool("github.create_repo", {"name": "r", "private": True}).risk is Risk.MEDIUM
    assert grade_tool("github.create_repo", {"name": "r", "private": False}).is_high
    # A string where a boolean belongs escalates too, never loosens.
    assert grade_tool("github.create_repo", {"name": "r", "private": "false"}).is_high


def test_an_argument_the_action_does_not_take_or_of_the_wrong_type_is_medium():
    assert grade_tool("github.mark_notification_read", {"thread_id": "123"}).is_low
    extra = grade_tool("github.mark_notification_read", {"thread_id": "123", "all": True})
    assert extra.risk is Risk.MEDIUM and extra.reason == risk.REASON_UNEXPECTED_ARGUMENT
    typed = grade_tool("github.mark_notification_read", {"thread_id": ["123"]})
    assert typed.risk is Risk.MEDIUM and typed.reason == risk.REASON_WRONG_TYPE
    enum = grade_tool("microsoft.flag_message", {"message_id": "m", "status": "burn"})
    assert enum.risk is Risk.MEDIUM
    # The model may not smuggle the confirmation flag into a LOW call.
    confirmed = grade_tool("microsoft.flag_message", {"message_id": "m", "user_confirmed": True})
    assert confirmed.risk is Risk.MEDIUM
    assert grade_spec(
        next(s for s in CONNECTOR_CATALOG["github"] if s.action == "mark_notification_read"),
        "not an object",
    ).risk is Risk.MEDIUM


def _spec(**kwargs: Any) -> ToolSpec:
    base: dict[str, Any] = {
        "action": "do",
        "description": "d",
        "category": ActionCategory.WRITE,
        "parameters": _schema(item_id={"type": "string"}),
        "required_scope": "area.write",
    }
    base.update(kwargs)
    return ToolSpec(**base)


def test_a_check_that_raises_grades_high():
    def broken(_arguments: Any) -> Any:
        raise RuntimeError("boom")

    grade = grade_spec(_spec(risk="low", low_risk_note="n", risk_check=broken), {"item_id": "1"})
    assert grade.is_high and grade.reason == risk.REASON_CHECK_FAILED


def test_a_check_that_answers_nonsense_grades_high():
    grade = grade_spec(
        _spec(risk="low", low_risk_note="n", risk_check=lambda _a: ("extreme", "why")), {"item_id": "1"}
    )
    assert grade.is_high


def test_a_check_can_never_lower_a_grade():
    lowering = lambda _a: ("low", "harmless")  # noqa: E731
    assert grade_spec(_spec(risk_check=lowering), {"item_id": "1"}).risk is Risk.MEDIUM
    high = _spec(category=ActionCategory.DELETE, always_confirm=True, risk_check=lowering)
    assert grade_spec(high, {"item_id": "1"}).is_high
    medium_on_high = _spec(
        category=ActionCategory.DELETE, always_confirm=True, risk_check=lambda _a: ("medium", "m")
    )
    assert grade_spec(medium_on_high, {"item_id": "1"}).is_high


def test_no_reason_ever_quotes_an_argument():
    for key, spec in connector_specs():
        arguments = representative(spec, text=SENTINEL)
        # Nested objects and lists carry it too.
        for name, prop in (spec.parameters or {}).get("properties", {}).items():
            if prop.get("type") == "object":
                arguments[name] = {"summary": SENTINEL, "attendees": [{"email": SENTINEL}], SENTINEL: 1}
            elif prop.get("type") == "array":
                arguments[name] = [SENTINEL]
        arguments[SENTINEL] = SENTINEL
        grade = grade_tool(f"{key}.{spec.action}", arguments)
        assert SENTINEL not in grade.reason, (key, spec.action)
        assert SENTINEL not in risk.card_note(grade)


# ── what people read ────────────────────────────────────────────────────────


def test_the_done_without_asking_line_is_built_from_facts():
    line = ran_without_asking_line(
        [
            ("google_workspace.modify_labels", "School Gmail"),
            ("google_workspace.modify_labels", "School Gmail"),
            ("google_workspace.modify_labels", "School Gmail"),
            ("microsoft.create_task", "Personal"),
        ]
    )
    assert line == (
        "Done without asking (low-risk changes you allowed): 3 × google_workspace.modify_labels "
        "on School Gmail; 1 × microsoft.create_task on Personal."
    )
    assert ran_without_asking_line([]) == ""


def test_the_connector_types_payload_lists_each_connectors_low_actions():
    payload = {entry["key"]: entry for entry in connector_registry.connector_types_payload()}
    gmail_low = {row["action"] for row in payload["google_workspace"]["low_risk"]}
    assert "modify_labels" in gmail_low and "send_email" not in gmail_low
    assert payload["robinhood"]["low_risk"] == []
    assert payload["github"]["low_risk"] == [
        {"action": "mark_notification_read", "note": "mark GitHub notifications read"}
    ]
    json.dumps(payload)  # serializable as served
