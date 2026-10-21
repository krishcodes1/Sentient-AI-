"""The breach monitor's owner-facing texts, built in code from fixed sentences:
the Telegram/Slack alerts (a new breach, the first check's summary, a refused
key, an address that stopped being checked), the failure sentences the tab and
Check now show, and the short notes of a Check now answer.

Why it exists: these messages reach the owner's chats with nobody reviewing
them and quote third-party text (a breach's title and domain from Have I Been
Pwned), so nothing here goes through a model, and every piece of vendor text
is cleaned to one line and defanged with ``page_watch.defang`` so that
Telegram draws no link from it: the attribution host is the message's only
link. The watched address appears only as a hint (``k•••@example.com``) whose
``@`` and dots are defanged too. A breach HIBP marks sensitive is never named
on a channel. A failed lookup always reads as "not checked" with its reason,
never as "no breaches" (resolutions, cross-cutting failure policy).
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Optional, Sequence

from services.breach.hibp import Breach
from services.connectors.base import clean_display_text
from services.notifications.page_watch import defang

ATTRIBUTION = "Source: Have I Been Pwned (haveibeenpwned.com)."
MAX_LISTED = 5
MAX_DATA_CLASSES_SHOWN = 6
DATA_CLASS_SHOWN_CHARS = 40
TITLE_SHOWN_CHARS = 160
DOMAIN_SHOWN_CHARS = 253

FAILURE_SENTENCES: dict[str, str] = {
    "key_missing": "No Have I Been Pwned key is saved, so nothing was sent.",
    "key_refused": "Have I Been Pwned refused the API key. Update it in Security → Service keys.",
    "rate_limited": "Have I Been Pwned asked Crawler to slow down. Crawler tries again in an hour.",
    "address_refused": "Have I Been Pwned would not look this address up.",
    "unavailable": "Have I Been Pwned could not be reached.",
    "bad_answer": "Have I Been Pwned's answer could not be read.",
    "refused_by_policy": "The network policy refused the request to Have I Been Pwned.",
    "unreadable": "This address can no longer be read (the server's encryption key changed). Remove it and add it again.",
    "timeout": "Have I Been Pwned did not answer in time.",
}

_ARROW = "→"
_WHERE = f"Crawler {_ARROW} Security {_ARROW} Breach monitor"
_NEW_ICON = "\U0001f513"  # OPEN LOCK
_ON_ICON = "\U0001f6e1️"  # SHIELD
_WARN_ICON = "⚠️"  # WARNING SIGN
_BULLET = "•"
_ELLIPSIS = "…"
_SENSITIVE_LINE = f"{_BULLET} A breach marked sensitive (see the Security page)"


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _shown(text: Optional[str], max_chars: int) -> str:
    """Third-party text as one defanged line: control characters become spaces, whitespace
    collapses, the result is cut to *max_chars*, and nothing in it can become a link."""
    return defang(clean_display_text(text, max_chars)) if text else ""


def _hint(hint: str) -> str:
    return defang(clean_display_text(hint, 300))


_RETRY_CLAUSE = " Crawler tries again"


def failure_sentence(code: Optional[str], *, retrying: bool = True) -> Optional[str]:
    """The owner-facing sentence for a stored failure code; None for no code. An unknown code
    reads as "could not be reached" (the code itself is never shown). With *retrying* False
    (the address is stopped or paused, so nothing looks it up on its own) any "Crawler tries
    again ..." promise is left out: it would never come true."""
    if not code:
        return None
    sentence = FAILURE_SENTENCES.get(code, FAILURE_SENTENCES["unavailable"])
    if not retrying:
        sentence = sentence.split(_RETRY_CLAUSE, 1)[0]
    return sentence


def _breach_line(breach: Breach) -> str:
    """'• Example Shop (example-shop․com), breached 2026-08-30. Exposed: email addresses.'"""
    if breach.sensitive:
        return _SENSITIVE_LINE
    title = _shown(breach.title, TITLE_SHOWN_CHARS) or _shown(breach.name, TITLE_SHOWN_CHARS)
    line = f"{_BULLET} {title}"
    domain = _shown(breach.domain, DOMAIN_SHOWN_CHARS)
    if domain:
        line += f" ({domain})"
    if breach.breach_date is not None:
        line += f", breached {breach.breach_date.isoformat()}"
    line += "."
    classes = [
        _shown(item.lower(), DATA_CLASS_SHOWN_CHARS)
        for item in breach.data_classes[:MAX_DATA_CLASSES_SHOWN]
    ]
    classes = [item for item in classes if item]
    if classes:
        line += f" Exposed: {', '.join(classes)}."
    return line


def new_breaches_message(hint: str, breaches: Sequence[Breach]) -> str:
    """The alert for breaches seen for the first time by a scheduled check (at most
    MAX_LISTED named, sensitive ones never named)."""
    count = len(breaches)
    lines = [
        f"{_NEW_ICON} New data breach: {_hint(hint)}",
        f"Have I Been Pwned lists this address in {_plural(count, 'new breach', 'new breaches')}:",
    ]
    lines.extend(_breach_line(breach) for breach in breaches[:MAX_LISTED])
    if count > MAX_LISTED:
        lines.append(f"{_ELLIPSIS}and {count - MAX_LISTED} more on the Security page.")
    lines.append("")
    lines.append(
        "What to do: change the password you used there, and anywhere you reused it, "
        "and turn on two-step sign-in where you can."
    )
    lines.append(f"Details: {_WHERE}. {ATTRIBUTION}")
    return "\n".join(lines)


def _newest(breaches: Sequence[Breach]) -> Optional[Breach]:
    """The most recent breach that may be named on a channel (never a sensitive one)."""
    named = [breach for breach in breaches if not breach.sensitive]
    if not named:
        return None
    floor = datetime.min.replace(tzinfo=timezone.utc)
    return max(
        named,
        key=lambda b: (b.breach_date or date.min, b.added_at or floor),
    )


def baseline_message(hint: str, breaches: Sequence[Breach]) -> str:
    """The one summary after an address's first (background) check."""
    shown_hint = _hint(hint)
    if not breaches:
        return (
            f"{_ON_ICON} Breach monitoring is on for {shown_hint}. It is not in any breach "
            f"Have I Been Pwned knows of. Crawler checks again every week. {ATTRIBUTION}"
        )
    known = _plural(len(breaches), "known breach", "known breaches")
    newest = _newest(breaches)
    note = ""
    if newest is not None:
        title = _shown(newest.title, TITLE_SHOWN_CHARS) or _shown(newest.name, TITLE_SHOWN_CHARS)
        when = f", {newest.breach_date.isoformat()}" if newest.breach_date is not None else ""
        note = f" (the newest: {title}{when})"
    return "\n".join(
        [
            f"{_ON_ICON} Breach monitoring is on for {shown_hint}.",
            f"It appears in {known}{note}. Crawler will tell you when it shows up in a new one; "
            "it checks every week.",
            f"See the list: {_WHERE}. {ATTRIBUTION}",
        ]
    )


def key_refused_message() -> str:
    """Sent once per owner, the first time a check is refused for the key."""
    return (
        f"{_WARN_ICON} Breach checks paused: Have I Been Pwned refused the API key. Update it in "
        f"Crawler {_ARROW} Security {_ARROW} Service keys; checks start again on their own after that."
    )


def _reason(code: str) -> str:
    """The failure sentence's first sentence without its full stop, for a parenthesis."""
    sentence = failure_sentence(code) or FAILURE_SENTENCES["unavailable"]
    first = sentence.split(". ", 1)[0]
    return first[:-1] if first.endswith(".") else first


def stopped_message(hint: str, failures: int, code: str) -> str:
    """Sent once when an address stops being checked after failures in a row."""
    last = "the last check failed" if failures == 1 else f"the last {failures} checks failed"
    return (
        f"{_WARN_ICON} Stopped checking {_hint(hint)} for breaches: {last} ({_reason(code)}). "
        f"Open {_WHERE} and press Check now to try again."
    )


# ---------------------------------------------------------------------------
# Check now notes (the CheckReport's ``note``)
# ---------------------------------------------------------------------------


def checked_note(new_count: int) -> str:
    """'Found in 1 new breach.' / 'Found in 3 new breaches.' / 'No new breaches.'"""
    if new_count <= 0:
        return "No new breaches."
    return f"Found in {_plural(new_count, 'new breach', 'new breaches')}."


def retry_sentence(delay: timedelta) -> str:
    """'Crawler tries again in 1 hour.' (minutes under an hour, else whole hours)."""
    seconds = max(0, int(delay.total_seconds()))
    if seconds < 3600:
        minutes = max(1, round(seconds / 60))
        return f"Crawler tries again in {_plural(minutes, 'minute', 'minutes')}."
    hours = max(1, round(seconds / 3600))
    return f"Crawler tries again in {_plural(hours, 'hour', 'hours')}."


def not_checked_note(
    code: str, retry_in: Optional[timedelta] = None, *, retrying: bool = True
) -> str:
    """'Not checked: <failure sentence>' plus the retry sentence when *retry_in* is given
    (the caller leaves it out where the failure sentence already says what happens next).
    With *retrying* False the address is not looked up again on its own (stopped or paused),
    so no retry is promised at all."""
    sentence = failure_sentence(code, retrying=retrying) or FAILURE_SENTENCES["unavailable"]
    note = f"Not checked: {sentence}"
    if retry_in is not None and retrying:
        note += f" {retry_sentence(retry_in)}"
    return note
