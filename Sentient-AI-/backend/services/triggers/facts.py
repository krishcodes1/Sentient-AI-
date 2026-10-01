"""Shapes what a trigger saw into small, capped facts, and builds every message
the owner is sent about a trigger, with no model: the notify lines, the "and N
more" note, the daily-limit and stop notices, and the result of a task run.

Why it exists: everything a trigger reads (a mail subject, a Canvas post, a
file name) is written by someone else, so it is untrusted. Facts keep only a
few short fields per item (a mail body only for a task run's untrusted
envelope, never in a message), and every message is built here from fixed
formats: third-party text is defanged so the service's own link is the only
one a chat app draws, text PromptGuard flags is withheld rather than shown,
and URL queries are stripped from a run's reply. Nothing here decides an
action or reaches the network.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone, tzinfo
from email.utils import parseaddr
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

# Per-item caps (characters) and the whole item's serialised size.
LINE_CHARS = 200
NAME_CHARS = 80
SNIPPET_CHARS = 500
BODY_CHARS = 1500
FACTS_MAX_BYTES = 4096
# What triggers.history shows of each fact.
HISTORY_FACT_CHARS = 120
# Most items one message or one run carries.
MAX_ITEMS_PER_BATCH = 5

MAILBOX = "\U0001f4ec"
MEGAPHONE = "\U0001f4e2"
MEMO = "\U0001f4dd"
CHECK = "\u2705"
CALENDAR = "\U0001f4c5"
FOLDER = "\U0001f4c1"
BELL = "\U0001f514"
LIGHTNING = "\u26a1"
WARNING = "\u26a0\ufe0f"
PAUSE = "\u23f8"

RUNS_OFF_LINE = "(Task runs are off, so only this notice was sent.)"
RUNNER_MISSING_LINE = "(Task runs are not available right now, so only this notice was sent.)"
NOT_CONFIGURED_LINE = "Crawler could not run your task: the AI provider is not set up."
RUN_FAILED_LINE = "Crawler could not run your task this time, so only this notice was sent."
_WITHHELD = "(The {what} is not shown: it looked like instructions aimed at an AI assistant.)"
# The connector's own guard (services/connectors/base.PromptGuard) leaves
# this where it cut an injection out; such text is withheld too.
_REDACTED_MARK = "[REDACTED]"
_BLANK_LOOKING = frozenset("\u034f\u115f\u1160\u17b4\u17b5\u3164\uffa0")
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()]+", re.IGNORECASE)
_CANVAS_COURSE_RE = re.compile(r"/courses/([0-9]{1,20})(?:/|$)")

Scan = Callable[[str], bool]

# The hosts a run's reply may link to, by connector type, besides the ones
# the item facts carry (a Canvas instance's own host). Anything else is
# defanged: shown as text a chat app does not turn into a link.
SERVICE_HOSTS: dict[str, tuple[str, ...]] = {
    "google_workspace": (
        "mail.google.com",
        "calendar.google.com",
        "docs.google.com",
        "drive.google.com",
    ),
    "microsoft": (
        "outlook.office.com",
        "outlook.office365.com",
        "outlook.live.com",
        "onedrive.live.com",
        "sharepoint.com",
    ),
    "canvas": (),
}


def external_key(source: str, ident: str) -> str:
    """sha256 hex of "<source>:<external id>": the dedupe key (64 chars)."""
    return hashlib.sha256(f"{source}:{ident}".encode("utf-8")).hexdigest()


def iso(moment: Optional[datetime]) -> Optional[str]:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: Any) -> Optional[datetime]:
    """An ISO 8601 time as an aware UTC datetime, or None. Graph's
    7-digit fractions and a trailing " (Zone)" are tolerated."""
    if not isinstance(value, str) or not value.strip() or len(value) > 80:
        return None
    text = value.strip()
    zone_name = None
    if text.endswith(")") and " (" in text:
        text, _, zone_name = text[:-1].partition(" (")
    match = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?)(\.\d+)?(Z|[+-]\d\d:?\d\d)?$", text)
    if match is None:
        return None
    base, _fraction, offset = match.groups()
    try:
        parsed = datetime.fromisoformat(base + (offset or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_zone(zone_name))
    return parsed.astimezone(timezone.utc)


def _zone(name: Optional[str]) -> tzinfo:
    if not name or name.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:
        return timezone.utc


def clean_line(value: Any, limit: int) -> str:
    """One printable line of at most *limit* characters ("" for non-text)."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(c if c.isprintable() and c not in _BLANK_LOOKING else " " for c in value)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def clean_text(value: Any, limit: int) -> str:
    """Printable text with its line breaks, at most *limit* characters."""
    if not isinstance(value, str):
        return ""
    lines = []
    for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        kept = "".join(c if c.isprintable() and c not in _BLANK_LOOKING else " " for c in line)
        lines.append(" ".join(kept.split()))
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def sender_address(value: Any) -> Optional[str]:
    """The address a From header names, lowercased, or None. The display
    name never counts: '"smith@univ.edu" <evil@x.com>' is evil@x.com."""
    if not isinstance(value, str) or not value.strip():
        return None
    _name, address = parseaddr(value)
    address = address.strip().lower()
    if address.count("@") != 1 or not re.fullmatch(r"[^@\s]+@[a-z0-9.-]+\.[a-z0-9-]{2,}", address):
        return None
    return address


def sender_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    name, _address = parseaddr(value)
    return clean_line(name, NAME_CHARS)


def sender_allowed(address: Optional[str], senders: Sequence[str]) -> bool:
    """Whether *address* is on the allowlist: an exact address, or an
    "@domain" entry naming exactly its domain. No list allows everyone."""
    if not senders:
        return True
    if address is None:
        return False
    domain = address.rpartition("@")[2]
    for entry in senders:
        entry = entry.lower()
        if entry.startswith("@"):
            if domain == entry[1:]:
                return True
        elif address == entry:
            return True
    return False


def canvas_course_id(url: Any) -> Optional[str]:
    if not isinstance(url, str):
        return None
    match = _CANVAS_COURSE_RE.search(urlsplit(url).path if "://" in url else url)
    return match.group(1) if match else None


def _sanitised(facts: dict[str, Any]) -> dict[str, Any]:
    """The connector guard's pass over every string (an injection pattern
    becomes [REDACTED]), then the whole item held to FACTS_MAX_BYTES by
    trimming its longest text first."""
    from services.connectors.base import PromptGuard

    cleaned, _ = PromptGuard.scan(facts)
    shaped: dict[str, Any] = dict(cleaned)
    for key in ("body", "text", "snippet"):
        if _size(shaped) <= FACTS_MAX_BYTES:
            break
        value = shaped.get(key)
        if isinstance(value, str) and value:
            excess = _size(shaped) - FACTS_MAX_BYTES
            keep = max(0, len(value) - excess - 8)
            shaped[key] = value[:keep].rstrip() + "…" if keep else ""
    while _size(shaped) > FACTS_MAX_BYTES:
        longest = max(
            (k for k, v in shaped.items() if isinstance(v, str) and v),
            key=lambda k: len(shaped[k]),
            default=None,
        )
        if longest is None:
            break
        shaped[longest] = shaped[longest][: len(shaped[longest]) // 2]
    return shaped


def _size(facts: Mapping[str, Any]) -> int:
    return len(json.dumps(facts, ensure_ascii=False, default=str).encode("utf-8"))


# -- Shaping one item ------------------------------------------------------------


def email_facts(raw: Mapping[str, Any], *, preview_key: str = "snippet") -> dict[str, Any]:
    header = raw.get("from")
    address = sender_address(header) or ""
    facts: dict[str, Any] = {
        "kind": "email",
        "from": clean_line(header, LINE_CHARS),
        "from_name": sender_name(header),
        "from_address": clean_line(address, 120),
        "domain": clean_line(address.rpartition("@")[2], NAME_CHARS),
        "subject": clean_line(raw.get("subject"), LINE_CHARS),
        "received": clean_line(raw.get("date") or raw.get("received"), 64),
        "snippet": clean_text(raw.get(preview_key), SNIPPET_CHARS),
    }
    body = clean_text(raw.get("body"), BODY_CHARS)
    if body:
        facts["body"] = body
    return _sanitised(facts)


def announcement_facts(row: Mapping[str, Any]) -> dict[str, Any]:
    return _sanitised(
        {
            "kind": "announcement",
            "course": clean_line(row.get("course"), NAME_CHARS),
            "course_id": clean_line(str(row.get("course_id") or ""), 24),
            "title": clean_line(row.get("title"), LINE_CHARS),
            "posted_at": clean_line(row.get("posted_at"), 40),
            "author": clean_line(row.get("author"), NAME_CHARS),
            "text": clean_text(row.get("text"), BODY_CHARS),
            "html_url": clean_line(row.get("html_url"), 300),
        }
    )


def assignment_facts(row: Mapping[str, Any]) -> dict[str, Any]:
    points = row.get("points_possible")
    return _sanitised(
        {
            "kind": "assignment",
            "course": clean_line(row.get("course"), NAME_CHARS),
            "title": clean_line(row.get("title"), LINE_CHARS),
            "type": clean_line(row.get("type"), 24),
            "due_at": clean_line(row.get("due_at"), 40),
            "points_possible": points if isinstance(points, (int, float)) and not isinstance(points, bool) else None,
            "html_url": clean_line(row.get("html_url"), 300),
        }
    )


def grade_facts(row: Mapping[str, Any]) -> dict[str, Any]:
    def number(value: Any) -> Any:
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None

    return _sanitised(
        {
            "kind": "grade",
            "course": clean_line(row.get("course"), NAME_CHARS),
            "course_id": clean_line(str(row.get("course_id") or ""), 24),
            "assignment": clean_line(row.get("assignment"), LINE_CHARS),
            "graded_at": clean_line(row.get("graded_at"), 40),
            "score": number(row.get("score")),
            "grade": clean_line(str(row.get("grade")) if row.get("grade") is not None else "", 24),
            "points_possible": number(row.get("points_possible")),
            "html_url": clean_line(row.get("html_url"), 300),
        }
    )


def event_facts(*, title: Any, start: datetime, end: Any, location: Any) -> dict[str, Any]:
    return _sanitised(
        {
            "kind": "event",
            "title": clean_line(title, LINE_CHARS),
            "start": iso(start),
            "end": clean_line(end, 64),
            "location": clean_line(location, LINE_CHARS),
        }
    )


def file_facts(*, name: Any, modified: Any, link: Any) -> dict[str, Any]:
    return _sanitised(
        {
            "kind": "file",
            "name": clean_line(name, LINE_CHARS),
            "modified": clean_line(modified, 40),
            "link": clean_line(link, 300),
        }
    )


def page_facts(*, label: str, host: str) -> dict[str, Any]:
    return {"kind": "page", "label": clean_line(label, NAME_CHARS), "host": clean_line(host, 120)}


# -- Messages ---------------------------------------------------------------------


def default_scan() -> Scan:
    """PromptGuard (the runtime's) as a yes/no "safe to show" check."""
    from services.agent.prompt_guard import PromptGuard

    guard = PromptGuard()
    return lambda text: guard.scan(text).is_safe


def defang(text: str) -> str:
    from services.notifications.page_watch import defang as page_defang

    return page_defang(text)


def _shown(value: Any, what: str, scan: Scan) -> str:
    """Third-party *value* as a message shows it: withheld when PromptGuard
    flags it (or the connector already cut an injection out of it),
    otherwise defanged."""
    text = clean_line(value, LINE_CHARS)
    if not text:
        return ""
    if _REDACTED_MARK in text or not scan(text):
        return _WITHHELD.format(what=what)
    return defang(text)


def _local(moment: Optional[datetime], tz: Optional[tzinfo]) -> str:
    if moment is None:
        return "an unknown time"
    if tz is None:
        return moment.astimezone(timezone.utc).strftime("%a %b %d %H:%M UTC")
    return moment.astimezone(tz).strftime("%a %b %d %H:%M")


def _link(url: Any) -> Optional[str]:
    """A connector-built link to the service's own page, or None."""
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 300:
        return None
    if any(c.isspace() or not c.isprintable() for c in url):
        return None
    return url


def item_line(
    source: str,
    label: str,
    facts: Mapping[str, Any],
    *,
    show_score: bool = False,
    tz: Optional[tzinfo] = None,
    now: Optional[datetime] = None,
    scan: Scan,
) -> str:
    """The fixed-format line for one item. Bodies never appear."""
    name = defang(clean_line(label, NAME_CHARS))
    if source == "email.new":
        who = (
            _shown(facts.get("from_name"), "sender name", scan)
            or _shown(facts.get("from_address"), "sender", scan)
            or "someone"
        )
        domain = defang(clean_line(facts.get("domain"), NAME_CHARS)) or "unknown domain"
        subject = _shown(facts.get("subject"), "subject", scan) or "(no subject)"
        return f"{MAILBOX} {name}: new email from {who} ({domain}): {subject}"
    if source == "canvas.announcement":
        course = _shown(facts.get("course"), "course name", scan) or "Canvas"
        title = _shown(facts.get("title"), "title", scan) or "(untitled)"
        line = f"{MEGAPHONE} {course}: {title}"
        link = _link(facts.get("html_url"))
        return f"{line}\n{link}" if link else line
    if source == "canvas.assignment":
        course = _shown(facts.get("course"), "course name", scan) or "Canvas"
        title = _shown(facts.get("title"), "title", scan) or "(untitled)"
        due = parse_time(facts.get("due_at"))
        when = f", due {_local(due, tz)}" if due else ""
        return f"{MEMO} New assignment in {course}: {title}{when}"
    if source == "canvas.grade":
        course = _shown(facts.get("course"), "course name", scan) or "Canvas"
        title = _shown(facts.get("assignment"), "assignment name", scan) or "(untitled)"
        line = f"{CHECK} Grade posted in {course}: {title}"
        if show_score:
            score, points = facts.get("score"), facts.get("points_possible")
            grade = clean_line(facts.get("grade"), 24)
            if isinstance(score, (int, float)) and isinstance(points, (int, float)) and points:
                line += f" ({_num(score)}/{_num(points)})"
            elif grade:
                line += f" ({defang(grade)})"
        return line
    if source == "calendar.starting_soon":
        start = parse_time(facts.get("start"))
        minutes = 0
        if start is not None and now is not None:
            minutes = max(0, round((start - now).total_seconds() / 60))
        title = _shown(facts.get("title"), "title", scan) or "(untitled)"
        place = _shown(facts.get("location"), "location", scan)
        at = start.astimezone(tz).strftime("%H:%M") if start is not None and tz else (
            start.strftime("%H:%M UTC") if start is not None else "soon"
        )
        line = f"{CALENDAR} In {minutes} min: {title} at {at}"
        return f"{line}, {place}" if place else line
    if source == "files.new_in_folder":
        file_name = _shown(facts.get("name"), "file name", scan) or "(unnamed)"
        return f"{FOLDER} New file in {name}: {file_name}"
    if source == "page.changed":
        return f"{BELL} {name} changed"
    return f"{BELL} {name}: something new"


def _num(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.2f}".rstrip("0").rstrip(".")


def notify_text(
    source: str,
    label: str,
    items: Sequence[Mapping[str, Any]],
    *,
    more: int = 0,
    show_score: bool = False,
    tz: Optional[tzinfo] = None,
    now: Optional[datetime] = None,
    scan: Optional[Scan] = None,
    extra_lines: Iterable[str] = (),
) -> str:
    """The whole notify message: one fixed-format line per item, then
    "…and N more." and any extra lines (a task that could not run)."""
    check = scan or default_scan()
    lines = [
        item_line(source, label, facts, show_score=show_score, tz=tz, now=now, scan=check)
        for facts in items[:MAX_ITEMS_PER_BATCH]
    ]
    if not lines:
        lines = [item_line(source, label, {}, tz=tz, now=now, scan=check)]
    hidden = more + max(0, len(items) - MAX_ITEMS_PER_BATCH)
    if hidden:
        lines.append(f"…and {hidden} more.")
    lines.extend(line for line in extra_lines if line)
    return "\n".join(lines)


def stopped_text(label: str, reason: str, failures: int) -> str:
    return (
        f"{WARNING} Stopped trigger \"{defang(clean_line(label, NAME_CHARS))}\": {reason}\n"
        f"The last {failures} checks failed. Resume it with /triggers (Slack: reply "
        "\"triggers\") once the problem is fixed, or ask Crawler to delete it."
    )


def limit_text(label: str, reason: str) -> str:
    return (
        f"{PAUSE} Trigger \"{defang(clean_line(label, NAME_CHARS))}\" did not run its task: "
        f"{reason} Newer events today are skipped without another message; it runs again "
        "tomorrow (UTC)."
    )


def history_fact(facts: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """What triggers.history shows of one item: a few capped fields, never
    a body or a full address."""
    if not isinstance(facts, Mapping):
        return {}
    keep = ("kind", "domain", "subject", "course", "title", "assignment", "start", "name", "label", "host")
    shown: dict[str, Any] = {}
    for key in keep:
        value = facts.get(key)
        if isinstance(value, str) and value:
            shown[key] = clean_line(value, HISTORY_FACT_CHARS)
    return shown


# -- A task run's result ---------------------------------------------------------------


def allowed_hosts(connector_type: Optional[str], items: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
    """The hosts a run's reply may link to: the connector's service hosts
    and the hosts of links the connector itself built into the facts."""
    hosts = list(SERVICE_HOSTS.get(connector_type or "", ()))
    for facts in items:
        for key in ("html_url", "link"):
            url = _link(facts.get(key))
            if url:
                host = (urlsplit(url).hostname or "").lower()
                if host:
                    hosts.append(host)
    return tuple(dict.fromkeys(hosts))


def _host_allowed(host: str, allowed: Sequence[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowed)


def defang_foreign_urls(text: str, allowed: Sequence[str]) -> str:
    """Every URL in *text* whose host is not one of *allowed* (or a
    subdomain) written so no chat app links it."""

    def one(match: re.Match[str]) -> str:
        url = match.group(0)
        target = url if "://" in url else f"https://{url}"
        try:
            host = urlsplit(target).hostname or ""
        except ValueError:
            host = ""
        if host and _host_allowed(host, allowed) and url.lower().startswith("https://"):
            return url
        return defang(url)

    return _URL_RE.sub(one, text)


def run_text(
    label: str,
    reply: str,
    *,
    notes: Sequence[str],
    usage_line: Optional[str],
    allowed: Sequence[str],
    web_title: str,
    max_chars: int = 3300,
) -> str:
    """The result of a task run as one message: "⚡ <label>", the reply,
    the notes and the usage line; URL queries stripped and foreign URLs
    defanged; cut to *max_chars* with a pointer to the web thread."""
    from api.routes.agent import strip_url_queries

    body = (reply or "").strip() or "(No reply this run.)"
    body = defang_foreign_urls(strip_url_queries(body), allowed)
    head = f"{LIGHTNING} {defang(clean_line(label, NAME_CHARS))}"
    tail = [n for n in notes if n]
    if usage_line:
        tail.append(usage_line)
    footer = "\n".join(tail)
    room = max_chars - len(head) - len(footer) - 4
    if len(body) > room:
        pointer = f"\n… The rest is in the web app, in the conversation \"{web_title}\"."
        body = body[: max(0, room - len(pointer))].rstrip() + pointer
    return "\n".join(part for part in (head, body, footer) if part)
