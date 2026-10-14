"""Tests for services/action_text.py, the plain words of every action that can
ask the owner for approval: the card sentence, the reply-note phrase, the app
name, the detail labels and the plain words for fixed values.

Why it exists: these strings go straight to a phone. The tests pin that every
tool in the approval catalog gets its own readable sentence with realistic
arguments, with no arguments and with junk arguments, without ever raising;
that no sentence, phrase or label shows a tool id, JSON braces, snake_case or
a dash; that free text is clipped in the sentence while recipients, links and
paths never are; that the add-on sentences agree with the real install
allowlist; and that the module stays pure (standard library only).

Nothing here calls a model, a connector or the network.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Iterator, Mapping

import pytest

from services import action_text
from services.action_text import (
    CLIP_CHARS,
    GENERIC_PHRASE,
    GENERIC_SENTENCE,
    app_name,
    approval_sentence,
    exact_moment,
    field_label,
    field_value,
    short_phrase,
)


@pytest.mark.parametrize(
    ("value", "words"),
    [
        ("2026-10-14T09:00:00", "Wed, Oct 14, 2026 at 9:00 AM"),
        ("2026-10-16T10:00:00-04:00", "Fri, Oct 16, 2026 at 10:00 AM (UTC-4)"),
        ("2026-10-16T10:00:30Z", "Fri, Oct 16, 2026 at 10:00:30 AM UTC"),
        ("2026-10-16 22:15:00+05:30", "Fri, Oct 16, 2026 at 10:15 PM (UTC+5:30)"),
        ("2026-10-16", "Fri, Oct 16, 2026"),
        # Not exactly a date: left for the card to show as written.
        ("2026-10-16T10:00:00.123Z", None),
        (" 2026-10-16", None),
        ("2026-13-40", None),
        ("next Friday", None),
        (None, None),
        (5, None),
    ],
)
def test_exact_moment_keeps_the_same_moment_in_words(value, words) -> None:
    assert exact_moment(value) == words

# Every tool that can put an approval card in front of the owner (the
# research catalog of 99 chat actions plus the unattended-only cards), with
# realistic arguments. Values carry no braces, underscores or dashes, so
# whatever of those shows up in a sentence came from the template.
CATALOG: dict[str, dict[str, Any]] = {
    "system.install_capability": {"name": "browser"},
    "desktop.act": {"action": "type", "text": "Hello there", "app": "Notes"},
    "browser.act": {"action": "fill", "ref": "e12", "text": "Priya Shah"},
    "browser.checkout": {
        "merchant": "ticketmaster.com",
        "amount": 84.5,
        "note": "two concert tickets",
    },
    "memory.remember": {"content": "Prefers morning meetings", "category": "preference"},
    "watch.create": {
        "url": "https://nyit.edu/fall",
        "label": "Fall schedule",
        "interval_minutes": 60,
    },
    "watch.delete": {"watch_id": "4f1c"},
    "files.forget": {"file_id": "f42"},
    "schedule.create": {
        "label": "Canvas summary",
        "prompt": "Tell me what is due",
        "freq": "weekly",
        "time": "08:00",
        "days": ["mon", "wed"],
        "tools": ["canvas.get_upcoming"],
        "timezone": "Europe/London",
        "channels": ["telegram", "slack"],
    },
    "schedule.briefing": {
        "freq": "weekdays",
        "time": "07:30",
        "sections": ["canvas", "calendar", "email"],
        "topic": "space news",
        "channels": ["telegram"],
    },
    "schedule.pause": {"task_id": "t1", "paused": True},
    "schedule.delete": {"task_id": "t1"},
    "knowledge.add": {"collection": "Biology", "url": "https://bio.example/cells"},
    "knowledge.remove": {"collection": "Biology"},
    "study.delete": {"deck_id": "d1", "item_ids": ["i1", "i2"]},
    "triggers.create": {
        "label": "Prof emails",
        "source": "email.new",
        "senders": ["prof@nyit.edu"],
        "mode": "notify",
        "interval_minutes": 15,
    },
    "triggers.update": {"trigger_id": "tr1", "label": "Professor mail", "allow_writes": True},
    "triggers.delete": {"trigger_id": "tr1"},
    "canvas.submit_assignment": {
        "course_id": "12",
        "assignment_id": "34",
        "submission_data": {"submission_type": "online_text_entry", "body": "My essay"},
    },
    "google_workspace.send_email": {
        "to": "priya@acme.com",
        "subject": "Friday lunch",
        "body": "Noon?",
    },
    "google_workspace.reply": {"message_id": "m1", "body": "Sounds good", "reply_all": True},
    "google_workspace.forward": {"message_id": "m1", "to": "sam@acme.com", "note": "See below"},
    "google_workspace.create_draft": {"to": "priya@acme.com", "subject": "Draft", "body": "Hi"},
    "google_workspace.send_draft": {"draft_id": "r1"},
    "google_workspace.modify_labels": {
        "message_id": "m1",
        "add_label_ids": ["STARRED"],
        "remove_label_ids": ["UNREAD", "INBOX"],
    },
    "google_workspace.trash_message": {"message_id": "m1"},
    "google_workspace.create_event": {
        "event_data": {
            "summary": "Dentist",
            "start": {"dateTime": "2026-09-25T10:00:00-04:00", "timeZone": "America/New_York"},
            "end": {"dateTime": "2026-09-25T11:00:00-04:00"},
            "attendees": [{"email": "sam@acme.com"}],
        }
    },
    "google_workspace.update_event": {
        "event_id": "e1",
        "summary": "Dentist",
        "start": "2026-09-26T10:00:00-04:00",
        "attendees": ["sam@acme.com"],
    },
    "google_workspace.respond_to_invite": {"event_id": "e1", "response": "tentative"},
    "google_workspace.delete_event": {"event_id": "e1", "notify_attendees": True},
    "google_workspace.upload_file": {
        "name": "notes.txt",
        "content": "Hi",
        "mime_type": "text/plain",
    },
    "google_workspace.create_folder": {"name": "Receipts"},
    "google_workspace.move_file": {"file_id": "f1", "folder_id": "f2"},
    "google_workspace.rename_file": {"file_id": "f1", "name": "Budget 2026"},
    "google_workspace.share_file": {"file_id": "f1", "email": "sam@acme.com", "role": "writer"},
    "google_workspace.trash_file": {"file_id": "f1"},
    "google_workspace.create_document": {"title": "Trip plan", "text": "Day one"},
    "google_workspace.append_text": {"document_id": "d1", "text": "More"},
    "google_workspace.replace_text": {
        "document_id": "d1",
        "find": "Tuesday",
        "replace_with": "Friday",
    },
    "google_workspace.update_values": {
        "spreadsheet_id": "s1",
        "a1_range": "Sheet1!A1:B2",
        "values": [[1, 2]],
    },
    "google_workspace.append_rows": {
        "spreadsheet_id": "s1",
        "a1_range": "Sheet1!A1",
        "values": [[1], [2]],
    },
    "google_workspace.add_sheet": {"spreadsheet_id": "s1", "title": "March"},
    "google_workspace.clear_range": {"spreadsheet_id": "s1", "a1_range": "Sheet1!A1:D20"},
    "google_workspace.create_contact": {
        "given_name": "Priya",
        "family_name": "Shah",
        "email": "priya@acme.com",
    },
    "google_workspace.update_contact": {"resource_name": "people/c1", "phone": "555 0100"},
    "google_workspace.delete_contact": {"resource_name": "people/c1"},
    "robinhood.get_crypto_portfolio": {},
    "robinhood.get_crypto_prices": {"symbols": ["BTC", "ETH"]},
    "robinhood.get_crypto_holdings": {},
    "slack.post_message": {"channel": "C0123ABCD", "text": "Hello team"},
    "slack.reply_in_thread": {"channel": "general", "thread_ts": "1700000000.1", "text": "Thanks"},
    "slack.add_reaction": {"channel": "general", "ts": "1700000000.1", "name": "tada"},
    "slack.upload_file": {"channel": "general", "filename": "notes.md", "content": "Hi"},
    "slack.set_status": {"text": "Out to lunch", "emoji": ":pizza:", "expires_in_minutes": 60},
    "slack.create_channel": {"name": "launch", "is_private": True},
    "slack.invite_to_channel": {"channel": "launch", "users": ["U0123ABCD", "U0456EFGH"]},
    "slack.schedule_message": {"channel": "general", "text": "Standup", "post_at": 1790000000},
    "slack.delete_message": {"channel": "general", "ts": "1700000000.1"},
    "slack.archive_channel": {"channel": "launch"},
    "microsoft.send_mail": {
        "to": ["priya@acme.com"],
        "subject": "Hi",
        "body": "Hello",
        "cc": ["sam@acme.com"],
    },
    "microsoft.reply": {"message_id": "m1", "comment": "Thanks"},
    "microsoft.forward": {"message_id": "m1", "to": ["sam@acme.com"], "comment": "FYI"},
    "microsoft.create_draft": {"subject": "Plans", "body": "Hi"},
    "microsoft.move_message": {"message_id": "m1", "destination_folder": "archive"},
    "microsoft.flag_message": {"message_id": "m1", "status": "complete"},
    "microsoft.delete_message": {"message_id": "m1"},
    "microsoft.create_event": {
        "subject": "Sync",
        "start": "2026-10-01T09:00:00",
        "end": "2026-10-01T09:30:00",
        "time_zone": "Pacific Standard Time",
        "attendees": ["sam@acme.com"],
    },
    "microsoft.update_event": {"event_id": "e1", "location": "Room 4"},
    "microsoft.respond_to_invite": {"event_id": "e1", "response": "accept", "send_response": True},
    "microsoft.delete_event": {"event_id": "e1"},
    "microsoft.upload_file": {"name": "notes.txt", "content": "Hi", "overwrite": True},
    "microsoft.create_folder": {"name": "Receipts"},
    "microsoft.move_file": {
        "item_id": "i1",
        "destination_folder_id": "f2",
        "new_name": "Old receipts",
    },
    "microsoft.create_share_link": {"item_id": "i1", "link_type": "edit", "scope": "anonymous"},
    "microsoft.delete_file": {"item_id": "i1"},
    "microsoft.create_task": {"title": "Pay rent", "due_date": "2026-10-02", "importance": "high"},
    "microsoft.update_task": {"list_id": "l1", "task_id": "t1", "title": "Pay rent early"},
    "microsoft.complete_task": {"list_id": "l1", "task_id": "t1"},
    "microsoft.delete_task": {"list_id": "l1", "task_id": "t1"},
    "github.create_repo": {"name": "notes", "private": True},
    "github.create_branch": {"owner": "octo", "repo": "site", "branch": "fix", "from_ref": "main"},
    "github.put_file": {
        "owner": "octo",
        "repo": "site",
        "path": "docs/notes.md",
        "content": "Hi",
        "message": "Add notes",
    },
    "github.delete_branch": {"owner": "octo", "repo": "site", "branch": "fix"},
    "github.create_issue": {"owner": "octo", "repo": "site", "title": "Login is broken"},
    "github.comment": {"owner": "octo", "repo": "site", "number": 12, "body": "Looks good"},
    "github.update_issue": {
        "owner": "octo",
        "repo": "site",
        "number": 12,
        "state": "closed",
        "state_reason": "completed",
    },
    "github.create_pr": {
        "owner": "octo",
        "repo": "site",
        "title": "Fix login",
        "head": "fix",
        "base": "main",
    },
    "github.review_pr": {
        "owner": "octo",
        "repo": "site",
        "number": 7,
        "event": "request_changes",
        "body": "Please add tests",
    },
    "github.request_reviewers": {
        "owner": "octo",
        "repo": "site",
        "number": 7,
        "reviewers": ["mona"],
    },
    "github.merge_pr": {"owner": "octo", "repo": "site", "number": 7, "merge_method": "rebase"},
    "github.rerun_failed_jobs": {"owner": "octo", "repo": "site", "run_id": 99},
    "github.dispatch_workflow": {
        "owner": "octo",
        "repo": "site",
        "workflow": "deploy",
        "ref": "main",
    },
    "github.cancel_run": {"owner": "octo", "repo": "site", "run_id": 99},
    "github.mark_notification_read": {"thread_id": "n1"},
    "github.create_release": {"owner": "octo", "repo": "site", "tag_name": "v2"},
    "github.publish_release": {"owner": "octo", "repo": "site", "release_id": 5},
    "github.create_gist": {"filename": "notes", "content": "Hi", "public": False},
    "notion.create_page": {"parent_page_id": "p1", "title": "Reading list"},
    "notion.append_blocks": {"block_id": "b1", "markdown": "More"},
    "notion.update_page_properties": {"page_id": "p1", "properties": {"Status": "Done"}},
    "notion.create_database_row": {"database_id": "d1", "properties": {"Name": "Buy milk"}},
    "notion.update_block": {"block_id": "b1", "checked": True},
    "notion.add_comment": {"page_id": "p1", "text": "Nice"},
    "notion.archive_page": {"page_id": "p1"},
    "notion.delete_block": {"block_id": "b1"},
    "reminders.create": {"title": "Call mom", "delay_minutes": 90},
    "reminders.cancel": {"reminder_id": "r1"},
    "study.save": {"title": "Cells", "items": [{"front": "A", "back": "B"}]},
    "study.edit": {"deck_id": "d1", "item_id": "i1", "front": "New front"},
    "study.review": {"action": "grade", "item_id": "i1", "rating": "good"},
    "study.quiz": {"action": "start", "deck_id": "d1"},
    "study.settings": {"reminder": True, "hour": 18},
}

MCP_TOOLS = ("mcp.linear.create_issue", "mcp.brave_search.webSearch", "mcp.my-notes.find_page")

JUNK_VALUES: tuple[Any, ...] = (
    None,
    0,
    -1,
    3.5,
    float("nan"),
    float("inf"),
    True,
    "",
    "   ",
    "\n\t",
    [],
    {},
    [None, 1, {}, ["x"]],
    {"a": {"b": [1]}, "dateTime": 5, "email": None},
    "x" * 5000,
    10**5000,
    object(),
)


class ExplodingMapping(Mapping[str, Any]):
    """A mapping whose every read fails, as a broken caller might pass."""

    def __getitem__(self, key: str) -> Any:
        raise RuntimeError("boom")

    def get(self, key: str, default: Any = None) -> Any:
        raise RuntimeError("boom")

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("boom")

    def __len__(self) -> int:
        raise RuntimeError("boom")

    def __contains__(self, key: object) -> bool:
        raise RuntimeError("boom")


# A dotted pair of lower-case identifiers, as a tool id looks.
TOOL_ID_RE = re.compile(r"\b[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\b")
FORBIDDEN = ("{", "}", "_", "\u2014", "\u2013", "\n", "\r")


def _values(value: Any) -> list[str]:
    """Every string (and number) inside an argument value."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, bool):
        return []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, Mapping):
        return [text for item in value.values() for text in _values(item)]
    if isinstance(value, (list, tuple)):
        return [text for item in value for text in _values(item)]
    return []


def _template_part(sentence: str, arguments: Mapping[str, Any]) -> str:
    """The sentence with every argument value taken out, so the strict
    checks only see the words the template wrote."""
    for value in sorted(_values(arguments), key=len, reverse=True):
        if value:
            sentence = sentence.replace(value, " ")
    return " ".join(sentence.split())


def _assert_plain(text: str, tool: str) -> None:
    assert text and text.strip() == text
    for bad in FORBIDDEN:
        assert bad not in text, f"{tool}: {bad!r} in {text!r}"
    assert not TOOL_ID_RE.search(text), f"{tool}: tool-id-like text in {text!r}"
    assert tool not in text


def _junk_arguments(tool: str, junk: Any) -> dict[str, Any]:
    keys = set(CATALOG.get(tool, {})) | {"name", "to", "text", "event_data", "channel", "action"}
    return dict.fromkeys(keys, junk)


# ---------------------------------------------------------------------------
# approval_sentence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", sorted(CATALOG))
def test_every_catalog_tool_has_its_own_plain_sentence(tool: str) -> None:
    arguments = CATALOG[tool]
    sentence = approval_sentence(tool, arguments)
    assert sentence and sentence[0].isupper()
    # A tool in the table never falls back to the generic "Use <app> to ...".
    assert not sentence.startswith("Use "), sentence
    assert "\n" not in sentence and tool not in sentence
    _assert_plain(_template_part(sentence, arguments), tool)
    # Two sentences at most.
    assert sentence.count(". ") <= 1


@pytest.mark.parametrize("tool", sorted(CATALOG))
def test_every_catalog_tool_reads_well_with_no_arguments(tool: str) -> None:
    for arguments in ({}, None):
        sentence = approval_sentence(tool, arguments)
        _assert_plain(sentence, tool)
        assert not sentence.startswith("Use ")


@pytest.mark.parametrize("tool", sorted(CATALOG))
def test_every_catalog_tool_survives_junk_arguments(tool: str) -> None:
    for junk in JUNK_VALUES:
        sentence = approval_sentence(tool, _junk_arguments(tool, junk))
        assert isinstance(sentence, str) and sentence
        assert "\n" not in sentence and tool not in sentence
        for bad in ("{", "}", "\u2014", "\u2013"):
            assert bad not in sentence, (tool, junk, sentence)
        # The builder itself coped: a builder that raised would have fallen
        # back to the generic "Use <app> to ..." sentence.
        assert not sentence.startswith("Use "), (tool, junk, sentence)
    for arguments in ([], "name=browser", 42, ExplodingMapping()):
        sentence = approval_sentence(tool, arguments)  # type: ignore[arg-type]
        _assert_plain(sentence, tool)
        assert not sentence.startswith("Use ")


def test_bad_tool_names_get_the_generic_sentence() -> None:
    for name in (None, "", "   ", 42, ["x"]):
        assert approval_sentence(name, {"to": "a"}) == GENERIC_SENTENCE  # type: ignore[arg-type]


def test_mcp_and_unknown_tools_fall_back_to_app_and_action() -> None:
    assert (
        approval_sentence("mcp.linear.create_issue", {"title": "Bug"})
        == "Use Linear to create issue"
    )
    assert approval_sentence("mcp.brave_search.webSearch", None) == "Use Brave Search to web search"
    assert approval_sentence("mcp.github_mcp.list_repos", {}) == "Use GitHub MCP to list repos"
    assert approval_sentence("mcp.linear", {}) == "Use Linear"
    assert approval_sentence("todoist.add_task", {"content": "Milk"}) == "Use Todoist to add task"
    assert (
        approval_sentence("google_workspace.brand_new", {})
        == "Use your Google account to brand new"
    )
    for tool in MCP_TOOLS:
        _assert_plain(approval_sentence(tool, {"q": "x"}), tool)


def test_a_second_connection_reads_like_the_first() -> None:
    plain = approval_sentence("google_workspace.send_email", {"to": "a@b.com"})
    assert approval_sentence("google_workspace__1f2e3d4c.send_email", {"to": "a@b.com"}) == plain
    assert short_phrase("canvas__1f2e3d4c.submit_assignment") == "hand in an assignment"


def test_install_sentences_name_the_add_on_and_its_size() -> None:
    assert approval_sentence("system.install_capability", {"name": "browser"}) == (
        "Install the web browser add-on so I can open websites, click around and take pictures "
        "of pages for you. It's a one-time download of about 150 to 300 MB."
    )
    assert approval_sentence("system.install_capability", {"name": "speech_to_text"}) == (
        "Install the voice notes add-on so I can turn your Telegram voice notes into text on "
        "this computer. It's a one-time download of about 250 MB, and your recordings never "
        "leave this computer."
    )
    assert approval_sentence("system.install_capability", {"name": "ocr_engine"}) == (
        "Install the OCR engine add-on on this computer"
    )
    assert (
        approval_sentence("system.install_capability", {}) == "Install an add-on on this computer"
    )
    assert field_label("system.install_capability", "name") == "Add-on"
    assert field_value("system.install_capability", "name", "speech_to_text") == "Voice notes"
    assert field_value("system.install_capability", "name", "browser") == "Web browser"


def test_install_sentences_match_the_real_allowlist() -> None:
    """Every installable add-on has its own sentence, and the sizes in it
    are the ones services/tools/system.py advertises."""
    from services.tools.system import ALLOWLIST

    generic = approval_sentence("system.install_capability", {"name": "something_else"})
    for name, installable in ALLOWLIST.items():
        sentence = approval_sentence("system.install_capability", {"name": name})
        assert sentence != generic and "add-on" in sentence
        for number in re.findall(r"\d+", installable.size_hint):
            assert number in sentence, (name, installable.size_hint, sentence)
        assert "MB" in sentence
        assert field_value("system.install_capability", "name", name)


def test_email_sentences_name_every_recipient_in_full() -> None:
    to = [f"person{n}@example.org" for n in range(12)]
    sentence = approval_sentence("microsoft.send_mail", {"to": to, "bcc": ["boss@example.org"]})
    assert all(address in sentence for address in to)
    assert "hidden copy to boss@example.org" in sentence
    assert approval_sentence(
        "google_workspace.send_email", CATALOG["google_workspace.send_email"]
    ) == ("Send an email to priya@acme.com from your Gmail")
    assert (
        approval_sentence("google_workspace.reply", {"message_id": "m1"})
        == "Reply to an email in your Gmail"
    )


def test_free_text_is_clipped_but_links_and_paths_are_not() -> None:
    title = "A very long document title that keeps going " * 5
    sentence = approval_sentence("google_workspace.create_document", {"title": title})
    assert sentence.endswith('…"') and len(sentence) < CLIP_CHARS + 40
    assert title.strip() not in sentence

    url = "https://example.org/" + "a" * 300
    assert url in approval_sentence("watch.create", {"url": url})
    path = "docs/" + "deep/" * 40 + "notes.md"
    assert path in approval_sentence("github.put_file", {"owner": "o", "repo": "r", "path": path})


def test_sentences_stay_on_one_line() -> None:
    sentence = approval_sentence(
        "google_workspace.create_event",
        {"event_data": {"summary": "Line one\nTo: someone@else.com\u2028line three"}},
    )
    assert "\n" not in sentence and "\u2028" not in sentence
    assert "Line one To: someone@else.com line three" in sentence


def test_ids_are_never_dressed_up_as_names() -> None:
    assert (
        approval_sentence("slack.post_message", {"channel": "C0123ABCD"})
        == "Post a message in a Slack channel"
    )
    assert (
        approval_sentence("slack.post_message", {"channel": "#general"})
        == "Post a message in #general on Slack"
    )
    assert approval_sentence("slack.post_message", {"channel": "D0123ABCD"}) == (
        "Post a message in a private Slack chat"
    )
    assert approval_sentence(
        "slack.invite_to_channel", {"channel": "launch", "users": ["U0123ABCD", "mona"]}
    ) == ("Invite mona and 1 other person to #launch on Slack")
    assert approval_sentence("google_workspace.trash_message", {"message_id": "18c2"}) == (
        "Move an email to the trash in your Gmail. Gmail deletes it for good after 30 days."
    )
    assert approval_sentence("microsoft.move_message", {"destination_folder": "A" * 60}) == (
        "Move an email in your Outlook to another folder"
    )


def test_label_changes_are_plain_words() -> None:
    assert approval_sentence(
        "google_workspace.modify_labels", CATALOG["google_workspace.modify_labels"]
    ) == ("Change an email in your Gmail: star it, mark it read and archive it")
    assert (
        approval_sentence(
            "google_workspace.modify_labels",
            {"add_label_ids": ["Label_7", "CATEGORY_SOCIAL", "TRASH"]},
        )
        == "Change an email in your Gmail: move it to the Social tab, move it to the trash and add one of your labels"
    )


def test_times_read_as_dates() -> None:
    assert approval_sentence(
        "google_workspace.create_event", CATALOG["google_workspace.create_event"]
    ) == (
        'Add "Dentist" to your Google Calendar on Fri, Sep 25, 2026 at 10:00 AM New York time '
        "and invite sam@acme.com"
    )
    # A naive Outlook time is read in its time zone, UTC when none is given.
    assert approval_sentence(
        "microsoft.create_event", {"subject": "Sync", "start": "2026-10-01T09:00:00"}
    ) == ('Add "Sync" to your Outlook calendar on Thu, Oct 1, 2026 at 9:00 AM UTC')
    assert approval_sentence(
        "reminders.create", {"title": "Call mom", "due_at": "2026-09-24T21:05:00-04:00"}
    ) == ('Remind you about "Call mom" on Thu, Sep 24, 2026 at 9:05 PM')
    assert approval_sentence("schedule.create", CATALOG["schedule.create"]) == (
        'Set up the scheduled task "Canvas summary" to run every Monday and Wednesday at 8:00 AM '
        "(London time) and send you the result on Telegram and Slack"
    )
    assert approval_sentence(
        "schedule.create", {"freq": "monthly", "day_of_month": 22, "time": "18:00"}
    ) == ("Set up a scheduled task to run on the 22nd of every month at 6:00 PM")
    # Text that is not a date is shown as it is (clipped), never dropped.
    assert "next Tuesday" in approval_sentence(
        "reminders.create", {"title": "x", "due_at": "next Tuesday"}
    )


def test_a_few_more_sentences() -> None:
    assert approval_sentence("browser.checkout", CATALOG["browser.checkout"]) == (
        'Pay $84.50 to ticketmaster.com for "two concert tickets"'
    )
    assert approval_sentence("triggers.create", CATALOG["triggers.create"]) == (
        'Set up "Prof emails" to message you whenever a new email arrives from prof@nyit.edu'
    )
    assert approval_sentence("github.update_issue", CATALOG["github.update_issue"]) == (
        "Close issue #12 in octo/site on GitHub as done"
    )
    assert approval_sentence("schedule.pause", {"paused": True}) == (
        "Pause a scheduled task. It won't run until you turn it back on."
    )
    assert approval_sentence("slack.set_status", {"text": ""}) == "Clear your Slack status"
    assert approval_sentence("desktop.act", {"action": "key", "keys": "cmd+s"}) == (
        "Press Cmd+S in an app on your computer"
    )


# ---------------------------------------------------------------------------
# short_phrase and app_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", sorted(CATALOG) + list(MCP_TOOLS))
def test_every_tool_has_a_short_phrase(tool: str) -> None:
    phrase = short_phrase(tool)
    assert phrase[0].islower()
    assert not phrase.endswith((".", "!", "?"))
    _assert_plain(phrase, tool)


def test_short_phrase_examples_and_fallbacks() -> None:
    assert short_phrase("google_workspace.send_email") == "send an email"
    assert short_phrase("microsoft.send_mail") == "send an email"
    assert short_phrase("system.install_capability") == "install an add-on"
    assert short_phrase("desktop.act") == "click or type in an app on your computer"
    assert short_phrase("google_workspace.modify_labels") == "change labels on an email"
    assert short_phrase("robinhood.execute_trade") == "buy or sell crypto"
    assert short_phrase("mcp.linear.create_issue") == "use Linear"
    assert short_phrase("todoist.add_task") == "use Todoist"
    assert short_phrase("google_workspace.brand_new") == "use your Google account"
    for name in (None, "", 7):
        assert short_phrase(name) == GENERIC_PHRASE  # type: ignore[arg-type]


def test_described_tools_have_phrases_too() -> None:
    for tool in (
        "browser.act",
        "browser.checkout",
        "memory.remember",
        "watch.create",
        "watch.delete",
        "files.forget",
        "schedule.create",
        "schedule.briefing",
        "schedule.pause",
        "schedule.delete",
        "knowledge.add",
        "knowledge.remove",
        "study.delete",
        "triggers.create",
        "triggers.update",
        "triggers.delete",
        "reminders.create",
        "reminders.cancel",
        "browser.read",
        "desktop.screenshot",
        "web.fetch_page",
    ):
        phrase = short_phrase(tool)
        assert not phrase.startswith("use "), tool
        _assert_plain(phrase, tool)


def test_app_names() -> None:
    assert app_name("google_workspace.send_email") == "Gmail"
    assert app_name("google_workspace.create_event") == "Google Calendar"
    assert app_name("google_workspace.share_file") == "Google Drive"
    assert app_name("google_workspace.brand_new") == "your Google account"
    assert app_name("microsoft.send_mail") == "Outlook"
    assert app_name("microsoft.upload_file") == "OneDrive"
    assert app_name("microsoft.create_task") == "Microsoft To Do"
    assert app_name("github.merge_pr") == "GitHub"
    assert app_name("notion.create_page") == "Notion"
    assert app_name("slack.post_message") == "Slack"
    assert app_name("canvas.submit_assignment") == "Canvas"
    assert app_name("robinhood.get_crypto_prices") == "Robinhood"
    assert app_name("desktop.act") == "your computer"
    assert app_name("system.install_capability") == "your computer"
    assert app_name("browser.act") == "the web browser"
    assert app_name("mcp.brave_search.webSearch") == "Brave Search"
    assert app_name("mcp..x") == "a connected app"
    assert app_name(None) == "an app"  # type: ignore[arg-type]
    for tool in sorted(CATALOG) + list(MCP_TOOLS):
        _assert_plain(app_name(tool), tool)


# ---------------------------------------------------------------------------
# field_label and field_value
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", sorted(CATALOG))
def test_every_argument_gets_an_everyday_label(tool: str) -> None:
    for key in CATALOG[tool]:
        label = field_label(tool, key)
        assert label[0].isupper(), (tool, key, label)
        assert ":" not in label
        _assert_plain(label, tool)


def test_field_label_lookup_order_and_fallback() -> None:
    assert field_label("google_workspace.send_email", "to") == "To"
    assert field_label("microsoft.send_mail", "bcc") == "Bcc (hidden copy)"
    assert field_label("slack.post_message", "text") == "Message"
    assert field_label("google_workspace.reply", "body") == "Your reply"
    assert field_label("google_workspace.send_email", "body") == "Message"
    assert field_label("anything.at_all", "url") == "Link"
    assert field_label("anything.at_all", "message_id") == "Email ID"
    assert field_label("anything.at_all", "max_results") == "Max results"
    assert field_label("anything.at_all", "event_id") == "Event ID"
    assert field_label("anything.at_all", "a1_range") == "Cells"
    assert field_label("anything.at_all", "_account") == "Account"
    assert field_label("anything.at_all", "_screen_size") == "Screen size"
    assert field_label("anything.at_all", "dueDate") == "Due date"
    assert field_label("anything.at_all", "callback_url") == "Callback link"
    assert field_label("anything.at_all", "file_ids") == "File IDs"
    assert field_label("google_workspace.create_event", "event_data.start") == "Starts"
    assert field_label("google_workspace.create_event", "event_data.attendees.0.email") == "Email"
    assert field_label("mcp.linear.create_issue", "teamId") == "Team ID"
    for junk in (None, "", "___", 5, ["x"], "..."):
        assert field_label("google_workspace.send_email", junk) == "Detail"  # type: ignore[arg-type]
    assert field_label(None, "to") == "To"  # type: ignore[arg-type]


def test_field_values_turn_code_words_into_plain_ones() -> None:
    assert field_value("google_workspace.respond_to_invite", "response", "tentative") == "Maybe"
    assert field_value("microsoft.respond_to_invite", "response", "decline") == "No"
    assert field_value("github.update_issue", "state_reason", "not_planned") == "Won't do"
    assert (
        field_value("canvas.submit_assignment", "submission_data.submission_type", "online_url")
        == "Link"
    )
    assert field_value("google_workspace.modify_labels", "remove_label_ids", "UNREAD") == "Unread"
    assert field_value("schedule.create", "days", "mon") == "Monday"
    assert field_value("schedule.briefing", "channels", "telegram") == "Telegram"
    assert field_value("google_workspace.send_email", "to", "priya@acme.com") is None
    assert field_value("google_workspace.respond_to_invite", "response", 3) is None
    assert field_value(None, None, None) is None  # type: ignore[arg-type]
    for table in action_text._VALUE_WORDS.values():
        for words in table.values():
            for word in words.values():
                _assert_plain(word, "value")


# ---------------------------------------------------------------------------
# Purity
# ---------------------------------------------------------------------------


def test_the_module_uses_the_standard_library_only() -> None:
    """Any layer may import it (cards, runtime, channels), so it must not
    import any of them back."""
    tree = ast.parse(Path(action_text.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "math", "re", "dataclasses", "datetime", "typing"}


def test_the_module_text_has_no_dashes() -> None:
    source = Path(action_text.__file__).read_text(encoding="utf-8")
    assert "\u2014" not in source and "\u2013" not in source


def test_known_tools_lists_the_table() -> None:
    known = action_text.known_tools()
    assert set(CATALOG) <= set(known)
    assert list(known) == sorted(known)


def test_every_connector_action_has_words() -> None:
    """A new connector action gets its words here before it ships: every
    action that can ask for approval (anything but a read, and Robinhood's
    reads, which ask too) has its own sentence and phrase, and every read
    at least its own phrase."""
    from services.connectors.registry import catalog_entries

    for family, specs in catalog_entries().items():
        for spec in specs:
            tool = f"{family}.{spec.action}"
            category = str(getattr(spec.category, "value", spec.category)).lower()
            phrase = short_phrase(tool)
            assert not phrase.startswith("use "), tool
            _assert_plain(phrase, tool)
            if category != "read" or family == "robinhood":
                assert tool in CATALOG or family == "robinhood", tool
                sentence = approval_sentence(tool, {})
                assert not sentence.startswith("Use "), tool
                _assert_plain(sentence, tool)
