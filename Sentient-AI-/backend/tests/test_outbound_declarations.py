"""Tests for the outbound declarations S1 reads (``ToolSpec.outbound``,
services/connectors/definition.py): they prove every action that speaks for the
owner (every non-READ always-confirm action, and every low-risk write that takes an
address) either declares which of its arguments leave the account or is exempt with a
written reason; that every declared path starts at a schema property and every
``resolve`` names its id argument; that exactly the seven mail sends feed the sent-to
history; that the registry refuses a declaration on a READ; and that the two built-in
acts declare the text they type.

Why it exists: S1's full hidden-character rules, its link checks and its recipient
notes reach only what is declared (everything else gets the always-safe subset), so a
new send that forgets its declaration would quietly lose them. This is the list a new
connector author meets.
"""

from __future__ import annotations

from services.agent.tool_registry import CONNECTOR_CATALOG, resolve_tool
from services.connectors.definition import (
    OUTBOUND_RESOLVE,
    ActionCategory,
    Outbound,
    ToolSpec,
    _schema,
    outbound_problems,
)
from services.connectors.registry import REGISTRY

# Actions that need no declaration, each with the reason (S1 design 4.3). Every
# DELETE and every FINANCIAL action is exempt by category.
EXEMPT: dict[str, str] = {
    "google_workspace.respond_to_invite": "answers an invitation with a fixed choice, no free text",
    "google_workspace.create_contact": "own storage: a contact card is saved, nothing is sent",
    "microsoft.create_share_link": "makes a link the owner shares themselves; sends nothing",
    "slack.invite_to_channel": "takes Slack user ids, not addresses, and carries no text",
    "github.publish_release": "publishes a release whose text was checked when it was written",
    "github.dispatch_workflow": "an EXECUTE: its inputs go to a CI run (tool rules' concern, S9)",
}
# Argument names that hold an email address.
ADDRESS_ARGUMENTS = frozenset({"to", "cc", "bcc", "email", "emails", "attendees", "recipients"})
MAIL_SENDS = {
    "google_workspace.send_email",
    "google_workspace.reply",
    "google_workspace.forward",
    "google_workspace.send_draft",
    "microsoft.send_mail",
    "microsoft.reply",
    "microsoft.forward",
}


def _connector_specs() -> list[tuple[str, ToolSpec]]:
    return [(f"{d.key}.{spec.action}", spec) for d in REGISTRY for spec in d.actions]


def _every_spec() -> list[tuple[str, ToolSpec]]:
    found = dict(_connector_specs())
    for connector_type, specs in CONNECTOR_CATALOG.items():
        for spec in specs:
            found.setdefault(f"{connector_type}.{spec.action}", spec)
    return sorted(found.items())


def _properties(spec: ToolSpec) -> dict:
    return dict((spec.parameters or {}).get("properties") or {})


def test_every_message_sending_write_declares_its_outbound_fields_or_is_exempt_with_a_reason():
    missing = []
    for name, spec in _connector_specs():
        if spec.category in (ActionCategory.READ, ActionCategory.DELETE, ActionCategory.FINANCIAL):
            continue
        names_an_address = bool(ADDRESS_ARGUMENTS & set(_properties(spec)))
        must = spec.always_confirm or (spec.risk == "low" and names_an_address)
        if must and spec.outbound is None and name not in EXEMPT:
            missing.append(name)
    assert missing == []
    # Every exemption names a real action that really has no declaration, with a reason.
    declared = dict(_connector_specs())
    for name, reason in EXEMPT.items():
        assert name in declared, name
        assert declared[name].outbound is None, name
        assert len(reason) > 20, name


def test_every_declared_path_names_a_schema_property():
    seen = 0
    for name, spec in _every_spec():
        out = spec.outbound
        if out is None:
            continue
        seen += 1
        properties = _properties(spec)
        assert outbound_problems(spec, properties) == [], name
        for path in (*out.content, *out.recipients):
            first, _, rest = path.partition(".")
            assert first in properties, (name, path)
            nested = properties[first].get("properties")
            if rest and isinstance(nested, dict):
                assert rest.split(".", 1)[0] in nested, (name, path)
    assert seen >= 39  # the 39 rows of the S1 4.3 table, the two built-in acts included


def test_resolve_names_its_id_argument():
    resolving = {
        name: spec for name, spec in _every_spec() if spec.outbound and spec.outbound.resolve
    }
    assert {name: spec.outbound.resolve for name, spec in resolving.items()} == {  # type: ignore[union-attr]
        "google_workspace.reply": "reply",
        "google_workspace.send_draft": "draft",
        "microsoft.reply": "reply",
    }
    for name, spec in resolving.items():
        assert OUTBOUND_RESOLVE[spec.outbound.resolve] in _properties(spec), name  # type: ignore[union-attr,index]


def test_history_is_declared_on_exactly_the_seven_mail_sends():
    history = {name for name, spec in _every_spec() if spec.outbound and spec.outbound.history}
    assert history == MAIL_SENDS
    # Drafts are saved, not sent: they never feed the history and never "deliver".
    drafts = {name: spec.outbound for name, spec in _every_spec() if name.endswith(".create_draft")}
    assert {name: (out.delivers, out.history) for name, out in drafts.items()} == {  # type: ignore[union-attr]
        "google_workspace.create_draft": (False, False),
        "microsoft.create_draft": (False, False),
    }


def test_the_registry_refuses_an_outbound_declaration_on_a_read():
    read = ToolSpec(
        "peek",
        "Read something.",
        ActionCategory.READ,
        _schema(query={"type": "string", "description": "q"}),
        outbound=Outbound(content=("query",)),
    )
    problems = outbound_problems(read, {"query"})
    assert any("only a non-READ action" in problem for problem in problems)
    # And the other refusals the declaration can meet.
    write = ToolSpec("post", "Post.", ActionCategory.WRITE, _schema(text={"type": "string"}))
    empty = outbound_problems(ToolSpec(**{**write.__dict__, "outbound": Outbound()}), {"text"})
    assert any("names no argument" in problem for problem in empty)
    unknown = outbound_problems(
        ToolSpec(**{**write.__dict__, "outbound": Outbound(content=("body",))}), {"text"}
    )
    assert any("does not start with a parameter" in problem for problem in unknown)
    draft_history = outbound_problems(
        ToolSpec(
            **{
                **write.__dict__,
                "outbound": Outbound(
                    content=("text",), recipients=("text",), delivers=False, history=True
                ),
            }
        ),
        {"text"},
    )
    assert any("only for an action that delivers" in problem for problem in draft_history)


def test_browser_and_desktop_act_declare_their_typed_text():
    desktop = resolve_tool("desktop.act")
    browser = resolve_tool("browser.act")
    assert desktop is not None and browser is not None
    assert desktop.spec.outbound == Outbound(content=("text",))
    assert browser.spec.outbound == Outbound(content=("text", "fields"))
    # Own-storage writes declare nothing: they get only the always-safe subset.
    for name in ("memory.remember", "schedule.create", "reminders.create"):
        resolved = resolve_tool(name)
        assert resolved is not None and resolved.spec.outbound is None, name
