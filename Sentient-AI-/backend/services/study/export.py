"""Writes a deck as an Anki-importable TSV or as a CSV, and mints the one-time
links the web chat downloads them through.

Why it exists: a deck is the user's own data, so it must leave in formats
other tools read, with no extra dependency (no genanki). The TSV carries
Anki's own header lines (#separator:tab, #html:true, #notetype:Basic, #deck,
#tags column), HTML-escaped with newlines as <br>. The CSV guards against
formula injection: a cell that starts with = + - @, a tab or a carriage
return gets a leading apostrophe, so a spreadsheet shows it as text.

The download link carries a token, not the user's session: ``cse_`` plus 32
random bytes, valid once, for 10 minutes, bound to one user, deck and
format. Only its sha256 is kept, in memory (at most 1000; a restart ends
them all). The ``cse_`` prefix is a registered secret format
(services/security/secrets.py), so the audit log and the log filters hide
it.
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import re
import secrets
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Sequence

import structlog

from services.study.render import LETTERS

logger = structlog.get_logger(__name__)

FORMATS = ("anki", "csv")
TOKEN_PREFIX = "cse_"
TOKEN_TTL_MINUTES = 10
MAX_TOKENS = 1000
FILENAME_MAX_CHARS = 60
_TOKEN_RE = re.compile(r"cse_[A-Za-z0-9_-]{43}")
_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9 _-]+")
_CSV_RISKY_START = ("=", "+", "-", "@", "\t", "\r")
CSV_COLUMNS = (
    "kind",
    "front",
    "back",
    "choices",
    "answer",
    "explanation",
    "choice_notes",
    "tags",
    "difficulty",
    "source_note",
)
MEDIA_TYPES = {"anki": "text/tab-separated-values", "csv": "text/csv"}
EXTENSIONS = {"anki": "txt", "csv": "csv"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def safe_filename(title: str, fmt: str) -> str:
    """The download's file name: the deck title reduced to letters, digits,
    spaces, '_' and '-', at most 60 characters, plus the format's
    extension."""
    base = " ".join(_FILENAME_UNSAFE.sub(" ", title or "").split())[:FILENAME_MAX_CHARS].strip()
    return f"{base or 'flashcards'}.{EXTENSIONS.get(fmt, 'txt')}"


# -- Anki ------------------------------------------------------------------------


def _html(text: Optional[str]) -> str:
    """HTML-escaped, one line: newlines as <br>, tabs as spaces."""
    value = html.escape(text or "", quote=False).replace("\t", " ")
    return value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def _anki_tags(tags: Sequence[str]) -> str:
    # Anki separates tags with spaces, so a tag's own spaces become "_".
    return " ".join("_".join(str(t).split()) for t in tags or () if str(t).strip())


def _anki_sides(item: Any) -> tuple[str, str]:
    if item.kind == "choice" and item.choices:
        choices = list(item.choices)
        front = _html(item.front) + "<br><br>" + "<br>".join(
            f"{LETTERS[i]}) {_html(c)}" for i, c in enumerate(choices[: len(LETTERS)])
        )
        right = item.answer_index if isinstance(item.answer_index, int) else 0
        back = f"<b>{LETTERS[right]})</b> {_html(choices[right])}" if 0 <= right < len(choices) else _html(item.back)
        if item.explanation:
            back += "<br><br>" + _html(item.explanation)
        for index, note in enumerate(list(item.choice_notes or [])[: len(choices)]):
            if note and index != right:
                back += f"<br>{LETTERS[index]}) is wrong: {_html(note)}"
        return front, back
    back = _html(item.back)
    if item.explanation:
        back += "<br><br>" + _html(item.explanation)
    return _html(item.front), back


def anki_tsv(deck_title: str, items: Sequence[Any]) -> str:
    """The deck as a tab-separated file Anki imports as Basic notes into a
    deck of the same name, tags in the third column."""
    deck = " ".join(str(deck_title or "Flashcards").replace("\t", " ").split())
    lines = [
        "#separator:tab",
        "#html:true",
        "#notetype:Basic",
        f"#deck:{deck}",
        "#tags column:3",
    ]
    for item in items:
        front, back = _anki_sides(item)
        lines.append(f"{front}\t{back}\t{_anki_tags(item.tags or ())}")
    return "\n".join(lines) + "\n"


# -- CSV -------------------------------------------------------------------------


def csv_cell(value: Any) -> str:
    """One CSV cell: text, with a leading apostrophe when a spreadsheet
    would read it as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_CSV_RISKY_START) else text


def csv_text(items: Sequence[Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for item in items:
        choices = list(item.choices or [])
        answer = ""
        if item.kind == "choice" and isinstance(item.answer_index, int) and 0 <= item.answer_index < len(LETTERS):
            answer = LETTERS[item.answer_index]
        notes = " | ".join(
            f"{LETTERS[i]}: {n}" for i, n in enumerate(list(item.choice_notes or [])[: len(LETTERS)]) if n
        )
        row = (
            item.kind,
            item.front,
            item.back,
            " | ".join(choices),
            answer,
            item.explanation or "",
            notes,
            " ".join(item.tags or ()),
            item.difficulty or "",
            item.source_note or "",
        )
        writer.writerow([csv_cell(v) for v in row])
    return out.getvalue()


def render_file(fmt: str, deck_title: str, items: Sequence[Any]) -> bytes:
    """The file's bytes: UTF-8 (the CSV with a byte-order mark, so a
    spreadsheet reads it as UTF-8)."""
    if fmt == "csv":
        return ("﻿" + csv_text(items)).encode("utf-8")
    return anki_tsv(deck_title, items).encode("utf-8")


# -- one-time links --------------------------------------------------------------


@dataclass(frozen=True)
class ExportGrant:
    user_id: str
    deck_id: str
    fmt: str
    expires_at: datetime


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class ExportTokens:
    """One-time download tokens, kept as sha256 hashes in memory. Expired
    ones are pruned on every mint and redeem; past ``cap`` the oldest go."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = _utcnow,
        ttl_minutes: int = TOKEN_TTL_MINUTES,
        cap: int = MAX_TOKENS,
    ) -> None:
        self._clock = clock
        self._ttl = timedelta(minutes=ttl_minutes)
        self._cap = cap
        self._grants: OrderedDict[str, ExportGrant] = OrderedDict()

    def __len__(self) -> int:
        return len(self._grants)

    @property
    def ttl_minutes(self) -> int:
        return int(self._ttl.total_seconds() // 60)

    def _prune(self, now: datetime) -> None:
        for key in [k for k, g in self._grants.items() if g.expires_at <= now]:
            del self._grants[key]

    def mint(self, user_id: Any, deck_id: Any, fmt: str) -> str:
        """A new token for *user_id*'s deck in *fmt*."""
        if fmt not in FORMATS:
            raise ValueError("format must be anki or csv")
        now = self._clock()
        self._prune(now)
        while len(self._grants) >= self._cap:
            self._grants.popitem(last=False)
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        self._grants[_digest(token)] = ExportGrant(str(user_id), str(deck_id), fmt, now + self._ttl)
        return token

    def redeem(self, token: Any) -> Optional[ExportGrant]:
        """The grant *token* was minted for, used up now; None for an
        unknown, expired or already used token (the caller answers all
        three the same way)."""
        now = self._clock()
        self._prune(now)
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            return None
        grant = self._grants.pop(_digest(token), None)
        if grant is None or grant.expires_at <= now:
            return None
        return grant


# The process's tokens: the study toolkit mints into it and the download
# route redeems from it (main.py hangs the same instance on app.state).
EXPORT_TOKENS = ExportTokens()


async def record_export(
    session_factory: Callable[[], Any],
    user_id: str,
    deck_id: str,
    fmt: str,
    count: int,
    *,
    endpoint: str,
) -> bool:
    """Write the study_export audit row for one download (deck id, format
    and item count; never card text). False when it could not be written:
    the caller then sends nothing (a download is never unrecorded)."""
    from models.audit import AuditStatus
    from services.audit import append_audit_log

    try:
        async with session_factory() as session:
            await append_audit_log(
                session,
                user_id=user_id,
                connector_name="study",
                action="study_export",
                endpoint=endpoint,
                scope_used="study",
                status=AuditStatus.approved,
                request_data={"deck_id": deck_id, "format": fmt, "count": count},
            )
            await session.commit()
        return True
    except Exception as exc:
        logger.error("study_export_audit_failed", error_type=type(exc).__name__)
        return False
