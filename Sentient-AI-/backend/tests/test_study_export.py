"""Tests for flashcard exports: the Anki TSV (its header lines, HTML escaping,
newlines as <br>, tabs removed, the choice-item layout), the CSV (its columns
and the formula-injection guard), the one-time cse_ tokens (single use, a
10-minute life on a fake clock, bound to one user, deck and format), the
download routes (identical 404s for unknown, expired and used tokens, the
attachment/no-store/nosniff headers, the signed-in route scoped to its user),
the study_export audit row (ids and counts, never card text), the access-log
filter that strips ?t= and the audit sanitiser that hides a cse_ token.

Why it exists: an export link is a bearer secret for the user's study data;
it must work once, briefly, for one deck, and never land in a log. The
database is in-memory SQLite and the clock is a fake.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from models.audit import AuditLog
from services.audit import _sanitize
from services.study import export as study_export
from services.study.export import ExportTokens, anki_tsv, csv_cell, csv_text, safe_filename
from services.tools.study import StudyToolkit
from tests.conftest import auth_headers, make_user

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def item(**fields):
    base = {
        "kind": "card",
        "front": "What is <ATP>?",
        "back": "Adenosine\ttriphosphate\nthe cell's energy & currency",
        "choices": None,
        "answer_index": None,
        "explanation": None,
        "choice_notes": None,
        "tags": ["bio 101", "energy"],
        "difficulty": None,
        "source_note": None,
    }
    return SimpleNamespace(**{**base, **fields})


def test_anki_tsv_has_its_headers_and_escapes_html_newlines_and_tabs():
    text = anki_tsv("Bio 101\t– Lecture 3", [item()])
    lines = text.split("\n")
    assert lines[:5] == [
        "#separator:tab",
        "#html:true",
        "#notetype:Basic",
        "#deck:Bio 101 – Lecture 3",
        "#tags column:3",
    ]
    front, back, tags = lines[5].split("\t")
    assert front == "What is &lt;ATP&gt;?"
    assert back == "Adenosine triphosphate<br>the cell's energy &amp; currency"
    assert tags == "bio_101 energy"


def test_a_choice_item_lists_its_options_the_answer_and_why_the_others_are_wrong():
    choice = item(
        kind="choice",
        front="Which organelle makes ATP?",
        back="Mitochondrion",
        choices=["Ribosome", "Mitochondrion"],
        answer_index=1,
        explanation="Oxidative phosphorylation.",
        choice_notes=["Ribosomes make proteins.", None],
    )
    front, back, _tags = anki_tsv("Deck", [choice]).split("\n")[5].split("\t")
    assert front == "Which organelle makes ATP?<br><br>A) Ribosome<br>B) Mitochondrion"
    assert back == "<b>B)</b> Mitochondrion<br><br>Oxidative phosphorylation.<br>A) is wrong: Ribosomes make proteins."


@pytest.mark.parametrize("risky", ["=HYPERLINK(\"http://x\")", "+1+1", "-2", "@SUM(A1)", "\tcmd", "\rcmd"])
def test_csv_cells_that_a_spreadsheet_would_run_get_an_apostrophe(risky):
    assert csv_cell(risky) == "'" + risky
    assert csv_cell("plain") == "plain" and csv_cell(None) == ""


def test_csv_columns_and_rows():
    rows = list(csv.reader(io.StringIO(csv_text([item(front="=cmd|' /C calc'!A0")]))))
    assert rows[0] == list(study_export.CSV_COLUMNS)
    assert rows[1][0] == "card" and rows[1][1] == "'=cmd|' /C calc'!A0"
    assert rows[1][7] == "bio 101 energy"
    assert study_export.render_file("csv", "Deck", [item()]).startswith("﻿".encode("utf-8"))


def test_file_names_keep_only_safe_characters():
    assert safe_filename("Bio 101 – Lecture 3: <cells>/../x", "anki") == "Bio 101 Lecture 3 cells x.txt"
    assert safe_filename("", "csv") == "flashcards.csv"
    assert len(safe_filename("x" * 200, "csv")) == 60 + len(".csv")


def test_a_token_works_once_within_ten_minutes_for_its_deck_only():
    clock = Clock()
    tokens = ExportTokens(clock=clock)
    token = tokens.mint("u1", "d1", "anki")
    assert token.startswith("cse_") and len(token) == 4 + 43
    grant = tokens.redeem(token)
    assert grant is not None and (grant.user_id, grant.deck_id, grant.fmt) == ("u1", "d1", "anki")
    assert tokens.redeem(token) is None  # used
    late = tokens.mint("u1", "d1", "csv")
    clock.now += timedelta(minutes=10)
    assert tokens.redeem(late) is None  # expired
    assert len(tokens) == 0
    for junk in (None, "", "cse_short", "x" * 47, token + "x"):
        assert tokens.redeem(junk) is None
    with pytest.raises(ValueError):
        tokens.mint("u1", "d1", "apkg")


def test_only_the_hash_is_kept_and_the_store_is_capped():
    tokens = ExportTokens(clock=Clock(), cap=3)
    minted = [tokens.mint("u", str(i), "anki") for i in range(5)]
    assert len(tokens) == 3
    assert not any(t in repr(tokens._grants) for t in minted)
    assert tokens.redeem(minted[0]) is None and tokens.redeem(minted[4]) is not None


# -- the routes -------------------------------------------------------------------


@pytest.fixture
def tokens():
    from main import app

    store = ExportTokens(clock=Clock())
    app.state.study_exports = store
    yield store
    del app.state.study_exports


async def _deck(session_factory, user, tokens):
    kit = StudyToolkit(session_factory, exports=tokens, default_timezone=lambda: "UTC")
    saved = await kit.execute(
        "save",
        {"title": "Bio 101 – Lecture 3", "items": [{"front": "What is ATP?", "back": "Energy currency"}]},
        str(user.id),
    )
    return kit, saved["deck_id"]


@pytest.mark.asyncio
async def test_the_link_downloads_once_with_safe_headers_and_writes_an_audit_row(client, session_factory, tokens):
    user, _ = await make_user(session_factory, "dl@example.com")
    kit, deck_id = await _deck(session_factory, user, tokens)
    link = await kit.execute("export", {"deck_id": deck_id, "format": "csv"}, str(user.id))
    first = await client.get(link["url"])
    assert first.status_code == 200
    assert first.headers["content-disposition"] == 'attachment; filename="Bio 101 Lecture 3.csv"'
    assert "no-store" in first.headers["cache-control"]
    assert first.headers["x-content-type-options"] == "nosniff"
    assert first.headers["content-type"].startswith("text/csv")
    assert "What is ATP?" in first.content.decode("utf-8-sig")
    async with session_factory() as session:
        [row] = (await session.execute(select(AuditLog).where(AuditLog.action == "study_export"))).scalars().all()
    stored = json.dumps([row.request_data, row.response_summary, row.reasoning_chain], default=str)
    assert row.request_data == {"deck_id": deck_id, "format": "csv", "count": 1}
    assert "ATP" not in stored and "cse_" not in stored and row.connector_name == "study"
    used = await client.get(link["url"])
    unknown = await client.get("/api/study/export?t=cse_" + "A" * 43)
    missing = await client.get("/api/study/export")
    garbage = await client.get("/api/study/export?t=" + "x" * 5000)
    assert {r.status_code for r in (used, unknown, missing, garbage)} == {404}
    assert len({r.text for r in (used, unknown, missing, garbage)}) == 1


@pytest.mark.asyncio
async def test_an_expired_link_is_the_same_404(client, session_factory, tokens):
    user, _ = await make_user(session_factory, "expired@example.com")
    kit, deck_id = await _deck(session_factory, user, tokens)
    link = await kit.execute("export", {"deck_id": deck_id}, str(user.id))
    tokens._clock.now += timedelta(minutes=11)
    expired = await client.get(link["url"])
    unknown = await client.get("/api/study/export?t=cse_" + "B" * 43)
    assert expired.status_code == unknown.status_code == 404 and expired.text == unknown.text


@pytest.mark.asyncio
async def test_a_link_for_a_deleted_deck_is_the_same_404(client, session_factory, tokens):
    user, _ = await make_user(session_factory, "gone@example.com")
    kit, deck_id = await _deck(session_factory, user, tokens)
    link = await kit.execute("export", {"deck_id": deck_id}, str(user.id))
    bound = await kit.bind("delete", {"deck_id": deck_id}, str(user.id))
    assert (await kit.execute("delete", bound, str(user.id)))["ok"]
    gone = await client.get(link["url"])
    assert gone.status_code == 404 and gone.json() == {"detail": "Not found."}


@pytest.mark.asyncio
async def test_the_signed_in_route_is_scoped_to_its_user(client, session_factory, tokens):
    owner, owner_token = await make_user(session_factory, "route-owner@example.com")
    _other, other_token = await make_user(session_factory, "route-other@example.com")
    _kit, deck_id = await _deck(session_factory, owner, tokens)
    mine = await client.get(f"/api/study/decks/{deck_id}/export?format=anki", headers=auth_headers(owner_token))
    assert mine.status_code == 200 and mine.content.decode("utf-8").startswith("#separator:tab")
    assert mine.headers["content-disposition"].endswith('.txt"')
    theirs = await client.get(f"/api/study/decks/{deck_id}/export", headers=auth_headers(other_token))
    none = await client.get(f"/api/study/decks/{uuid.uuid4()}/export", headers=auth_headers(owner_token))
    assert theirs.status_code == none.status_code == 404
    anonymous = await client.get(f"/api/study/decks/{deck_id}/export")
    assert anonymous.status_code in (401, 403)
    bad_format = await client.get(f"/api/study/decks/{deck_id}/export?format=apkg", headers=auth_headers(owner_token))
    assert bad_format.status_code == 422


# -- logs and audit ---------------------------------------------------------------


def test_the_access_log_filter_strips_the_token_query():
    from core.logging_config import OAuthCallbackQueryFilter, SecretQueryFilter

    token = "cse_" + "C" * 43
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "GET", f"/api/study/export?t={token}", "1.1", 200), None,
    )
    assert SecretQueryFilter is OAuthCallbackQueryFilter
    assert OAuthCallbackQueryFilter().filter(record) is True
    assert record.args[2] == "/api/study/export?[redacted]"
    assert token not in record.getMessage()
    # Other paths keep their query.
    other = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "GET", "/api/study/decks/x/export?format=csv", "1.1", 200), None,
    )
    OAuthCallbackQueryFilter().filter(other)
    assert other.args[2] == "/api/study/decks/x/export?format=csv"


def test_the_audit_sanitiser_hides_an_export_token():
    token = "cse_" + "D" * 43
    assert _sanitize({"url": f"/api/study/export?t={token}"}) == {"url": "/api/study/export?t=***REDACTED***"}


def test_audit_rows_keep_only_the_size_of_card_text():
    from services.audit import redact_tool_arguments

    saved = redact_tool_arguments(
        "study.save",
        {"title": "Bio 101", "items": [{"front": "What is ATP?", "back": "Energy"}] * 3},
    )
    assert saved == {"title": "Bio 101", "items": "<3 items>"}
    assert redact_tool_arguments("study.save", {"items": [{"front": "x"}]})["items"] == "<1 item>"
    edited = redact_tool_arguments("study.edit", {"item_id": "i1", "front": "What is ATP?", "tags": ["bio"]})
    assert edited == {"item_id": "i1", "front": "<12 characters>", "tags": "***REDACTED***"}
    # Other tools' list fields are still hidden outright.
    assert redact_tool_arguments("desktop.act", {"text": ["secret"]}) == {"text": "***REDACTED***"}


def test_the_token_reaches_the_model_but_never_the_audit_log_or_the_logs():
    """The model must pass the link on (it works once, for 10 minutes), so
    the model floor keeps it; the audit log and the log lines hide it."""
    from services.security.egress import redact_for_model
    from services.security.policies import LOGS, TOOL_ARGS
    from services.security.redact import contains, redact_text

    token = "cse_" + "E" * 43
    text = f"Download: /api/study/export?t={token}"
    assert redact_for_model(text) == text
    assert not contains(text, TOOL_ARGS)
    assert token not in redact_text(text, LOGS).text
    assert token not in json.dumps(_sanitize({"result": text}))
