"""Every message and card text of the mail scam scan (security S2), built in
code: the alert a flagged email gets on Telegram and Slack, the "stopped",
"too many alerts this hour" and daily-summary lines, the approval card's
reason, risk note and security note, and the name an account goes by.

Why it exists: the alert is read about an email an attacker wrote, so no
text in it may come from that email unchecked or from the model unfiltered.
Third-party values (the sender's name and address, the subject) go through
the same rules the trigger notices use (services/triggers/facts.py): one
printable line, withheld when PromptGuard flags it or the connector already
cut an injection out of it, otherwise defanged so no chat app turns a
domain, an address or a path into a link. Crawler's own reasons are the
fixed sentences of services/security/mail_checks.py; the only model text is
the review's sanitised reasons (services/mail_scan/review.py). The body is
never quoted and nothing here ever calls an email safe. The same plain text
goes to Telegram and Slack (fan_out_send sends a str, so no Markdown is
parsed) and fits one message on each.

Connects to: services/notifications/mail_scan.py (the sweeper sends these),
services/mail_scan/actions.py (the card's reason and notes),
api/routes/security_mail.py (the account names).
"""

from __future__ import annotations

from datetime import datetime, timezone, tzinfo
from typing import Any, Callable, Mapping, Optional, Sequence

from services.security.mail_checks import Hit, reason_lines
from services.triggers import facts as shape

Scan = Callable[[str], bool]

# One alert stays well inside one Telegram message (4,096) and one Slack
# section (3,000).
ALERT_MAX_CHARS = 1800
NOTE_TEXT_CHARS = 200
NAME_CHARS = 80
ADDRESS_CHARS = 120
ACCOUNT_CHARS = 60
MODEL_NAME_CHARS = 60
MAX_CHECK_NOTES = 3

SIREN = "\U0001f6a8"
WARNING = "\u26a0\ufe0f"
PAUSE = "\u23f8"
INFO = "\u2139\ufe0f"
BULLET = "\u2022"
ARROW = "\u2192"

HEADERS: Mapping[str, str] = {
    "likely_scam": f"{SIREN} Likely scam email",
    "suspicious": f"{WARNING} Suspicious email",
}
_WHY: Mapping[str, str] = {
    "likely_scam": "Why Crawler thinks so:",
    "suspicious": "Why Crawler flagged it:",
}
# Same text as event_triggers._PENDING_HINT: one message reaches Telegram and
# Slack alike, so the command is named for both.
PENDING_HINT = '/pending; Slack: reply "pending"'
TAB = f"Security page {ARROW} Mail alerts"
NO_FURTHER_SIGNS = "AI review: found no further signs (Crawler's own findings above still stand)."
CARD_NOTE = "Proposed by Crawler's mail check while you were away. Nothing has been done yet."
_WITHHELD = "(The {what} is not shown: it looked like instructions aimed at an AI assistant.)"
_REDACTED_MARK = "[REDACTED]"

PROVIDER_NAMES: Mapping[str, str] = {"gmail": "Gmail", "outlook": "Outlook"}
# Where Move-to-Spam/Junk puts a message, in each mailbox's own words.
SPAM_FOLDERS: Mapping[str, str] = {"gmail": "Spam", "outlook": "Junk Email"}
# The connector permission a card needs, as the Connectors page shows it.
MODIFY_SCOPES: Mapping[str, str] = {"gmail": "gmail.modify", "outlook": "mail.write"}

# Fixed advice by the kind of the strongest sign (advice_kind below).
WHAT_TO_DO: Mapping[str, str] = {
    "attachments": (
        "Don't open its attachments, click its links or reply. If you were expecting a file, "
        "ask the sender another way first."
    ),
    "payment": (
        "Before you pay or reply, check with the sender another way, using a phone number or "
        "address you already have."
    ),
    "credentials": (
        "Don't sign in through its links or share any code. If you think it might be real, go to "
        "the company's site yourself by typing its address."
    ),
    "links": (
        "Don't click its links, open its attachments or reply. If you think it might be real, go "
        "to the company's site yourself by typing its address."
    ),
}

# The short phrase a card's security note uses for each hit, strongest
# first. {arg} is only ever a brand domain from mail_checks.BRAND_DOMAINS.
_NOTE_PHRASES: Mapping[str, str] = {
    "link_malicious": "a link is on a list of dangerous sites",
    "attachment_malicious": "VirusTotal reports an attachment as harmful",
    "sender_lookalike_brand": "the sender imitates {arg}",
    "sender_lookalike_owner": "the sender imitates your organisation's domain",
    "sender_mixed_script": "the sender's domain uses look-alike letters",
    "sender_unreadable": "the From address can be read two ways",
    "auth_dmarc_fail": "DMARC failed",
    "auth_compauth_fail": "Microsoft could not confirm the sender",
    "auth_spf_fail": "SPF failed",
    "reply_to_lookalike": "replies go to a look-alike domain",
    "reply_to_freemail": "replies go to a free webmail address",
    "display_name_brand": "the sender's name claims a well-known company",
    "display_name_address": "the sender's name shows another address",
    "link_text_mismatch": "a link hides its real destination",
    "link_lookalike": "a link imitates a well-known site",
    "link_script": "a link runs code or opens a file",
    "link_credentials": "a link hides a user name",
    "link_ip": "a link goes to a bare IP address",
    "link_suspicious": "the link check marked a link as suspicious",
    "attachment_disguised": "an attachment hides its real type",
    "attachment_risky": "an attachment is a risky file type",
    "attachment_suspicious": "VirusTotal reports an attachment as suspicious",
    "form_in_body": "it has a form to type into",
    "pressure_payment": "it pushes for money or a payment change",
    "pressure_credentials": "it pushes you to sign in or share a code",
    "reply_to_mismatch": "replies go to another domain",
    "link_shortener": "a link uses a link shortener",
    "link_suspicious_tld": "a link goes to a throwaway-site ending",
    "hidden_characters": "it hides characters",
    "injection_text": "it holds text aimed at AI assistants",
    "auth_none": "nothing vouches for the sender",
}
_NOTE_ORDER = {code: index for index, code in enumerate(_NOTE_PHRASES)}


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def provider_name(provider: str) -> str:
    return PROVIDER_NAMES.get(provider, "Mail")


def spam_folder(provider: str) -> str:
    return SPAM_FOLDERS.get(provider, "Spam")


def account_label(display_name: Any, provider: str) -> str:
    """The name an account goes by in messages and on the tab: the
    connector's own name followed by the mailbox kind ("School Gmail"), the
    name alone when it already says the kind, "Gmail" when it is blank.
    Defanged: a connector name is the person's text but may look like a
    domain."""
    kind = provider_name(provider)
    name = shape.clean_line(display_name, ACCOUNT_CHARS)
    if not name:
        return kind
    label = name if kind.lower() in name.lower() else f"{name} {kind}"
    return shape.defang(label)


def shown(value: Any, what: str, scan: Scan, *, limit: int = shape.LINE_CHARS) -> str:
    """Third-party *value* as an alert shows it: one printable line,
    withheld when PromptGuard flags it (or the connector already cut an
    injection out of it), otherwise defanged. "" for nothing."""
    text = shape.clean_line(value, limit)
    if not text:
        return ""
    try:
        clean = scan(text)
    except Exception:  # a guard that cannot answer withholds
        clean = False
    if _REDACTED_MARK in text or not clean:
        return _WITHHELD.format(what=what)
    return shape.defang(text)


def received_text(value: Any, tz: Optional[tzinfo]) -> str:
    """When the email arrived, in the person's zone ("Tue Oct 14 09:12"),
    UTC when no zone is set, "an unknown time" when it cannot be read."""
    moment = value if isinstance(value, datetime) else shape.parse_time(value)
    if moment is None:
        return "an unknown time"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if tz is None:
        return moment.astimezone(timezone.utc).strftime("%a %b %d %H:%M UTC")
    return moment.astimezone(tz).strftime("%a %b %d %H:%M")


def advice_kind(hits: Sequence[Hit]) -> str:
    """Which WHAT_TO_DO line fits: an attachment sign first, then a request
    for money (or replies sent elsewhere), then a request to sign in, then
    links."""
    codes = {hit.code for hit in hits}
    if any(code.startswith("attachment_") for code in codes):
        return "attachments"
    if "link_malicious" in codes:
        return "links"
    if "pressure_payment" in codes or codes & {"reply_to_freemail", "reply_to_lookalike"}:
        return "payment"
    if "pressure_credentials" in codes:
        return "credentials"
    return "links"


def missing_scope_hint(provider: str) -> str:
    """Why no card was made: the account lacks the permission to move mail."""
    return (
        f"To move mail to {spam_folder(provider)} from Crawler, allow "
        f'"{MODIFY_SCOPES.get(provider, "gmail.modify")}" for this {provider_name(provider)} '
        "account in Connectors."
    )


def card_line(provider: str, *, card: Optional[str], card_hint: Optional[str]) -> str:
    """The alert's last line: the card that follows, why there is none, or
    (a suspicious alert) where one click makes it."""
    folder = spam_folder(provider)
    if card:
        return f"A card to move it to {folder} follows ({PENDING_HINT}). Details: {TAB}."
    if card_hint:
        return f"{card_hint} Details: {TAB}."
    return f"To move it to {folder}, open {TAB} (one click makes the card)."


def _model_name(review: Any) -> str:
    # The install's own model name ("gemini-2.5-flash"), never the email's
    # text: one printable line, not defanged.
    return shape.clean_line(getattr(review, "model", "") or getattr(review, "provider", ""), MODEL_NAME_CHARS)


def review_line(review: Any, review_note: Optional[str]) -> str:
    """The alert's AI line: the review's sanitised reasons, the fixed "no
    further signs" line for a review that found nothing more (it never takes
    back Crawler's own findings), or the note saying why no review ran."""
    if review is None:
        note = shape.clean_line(review_note, NOTE_TEXT_CHARS)
        return note or "AI review: not done."
    verdict = getattr(review, "verdict", "")
    if verdict not in ("likely_scam", "suspicious"):
        return NO_FURTHER_SIGNS
    model = _model_name(review)
    head = f"AI review ({model}):" if model else "AI review:"
    reasons = [r for r in getattr(review, "reasons", ()) if isinstance(r, str) and r]
    if reasons:
        return f"{head} {' '.join(reasons)}"
    if verdict == "likely_scam":
        return f"{head} it also judged this a likely scam."
    return f"{head} it also found warning signs."


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "\u2026"


def alert_text(
    *,
    account: str,
    provider: str,
    verdict: str,
    display: Mapping[str, Any],
    hits: Sequence[Hit],
    review: Any,
    review_note: Optional[str],
    check_notes: Sequence[str],
    card: Optional[str],
    card_hint: Optional[str],
    tz: Optional[tzinfo],
    scan: Scan,
) -> str:
    """The alert of S2.md 1.1: the subject through the withheld rule, the
    sender and every domain defanged, Crawler's fixed reasons, the AI line,
    fixed advice and the card line. Never a body, never "safe", at most
    ALERT_MAX_CHARS characters (the AI line is shortened first)."""
    kind = verdict if verdict in HEADERS else "suspicious"
    sender = _map(display.get("from"))
    name = shown(sender.get("name"), "sender name", scan, limit=NAME_CHARS)
    address = shape.defang(shape.clean_line(sender.get("address"), ADDRESS_CHARS))
    who = ", ".join(part for part in (name, address) if part) or "an unknown sender"
    subject = shown(display.get("subject"), "subject", scan) or "(no subject)"
    head = [
        f"{HEADERS[kind]} ({account})",
        f"From: {who}",
        f"Subject: {subject}",
        f"Received: {received_text(display.get('received'), tz)}",
    ]
    reasons = [f"{BULLET} {line}" for line in reason_lines(hits)]
    notes = [
        f"{BULLET} {shape.clean_line(n, NOTE_TEXT_CHARS)}"
        for n in list(dict.fromkeys(n for n in check_notes if isinstance(n, str) and n))[:MAX_CHECK_NOTES]
    ]
    ai = review_line(review, review_note)
    tail = [
        f"What to do: {WHAT_TO_DO[advice_kind(hits)]}",
        card_line(provider, card=card, card_hint=card_hint),
    ]

    def build(why: list[str], ai_line: str) -> str:
        blocks = ["\n".join(head)]
        if why or notes:
            blocks.append("\n".join([_WHY[kind], *why, *notes]))
        blocks.append(ai_line)
        blocks.extend(tail)
        return "\n\n".join(blocks)

    text = build(reasons, ai)
    if len(text) > ALERT_MAX_CHARS:
        room = ALERT_MAX_CHARS - (len(text) - len(ai))
        ai = _clip(ai, max(room, 60))
        text = build(reasons, ai)
    while len(text) > ALERT_MAX_CHARS and len(reasons) > 1:
        reasons = reasons[:-1]
        text = build(reasons, ai)
    return _clip(text, ALERT_MAX_CHARS)


def stopped_text(account: str, reason: str) -> str:
    """Sent once when an account's checks stop after repeated failures;
    *reason* is the sweeper's own sentence, never vendor text."""
    return (
        f"{PAUSE} Crawler stopped checking new mail in {account} for scams: {reason} "
        f"Reconnect it, or press Resume on the {TAB}."
    )


def overflow_text(count: int) -> str:
    """At most once an hour per person: more suspicious mail was flagged
    than is pushed (a likely scam is always pushed)."""
    if count == 1:
        return (
            f"{WARNING} 1 more suspicious email was flagged in the last hour. It is on the {TAB} "
            "(no more messages about them this hour)."
        )
    return (
        f"{WARNING} {count} more suspicious emails were flagged in the last hour. They are on the "
        f"{TAB} (no more messages about them this hour)."
    )


def summary_text(count: int) -> str:
    """The daily line for weak findings no AI review was available for."""
    if count == 1:
        return (
            f"{INFO} 1 email with weak warning signs was not sent to you today (no AI review was "
            f"available for it). It is on the {TAB}."
        )
    return (
        f"{INFO} {count} emails with weak warning signs were not sent to you today (no AI review "
        f"was available for them). They are on the {TAB}."
    )


def card_reason(kind: str, provider: str) -> str:
    """The approval card's fixed reason (S2.md 4.7). Only Move to Spam/Junk
    exists in this wave (owner decision 8a: Block sender is deferred)."""
    if provider == "outlook":
        return (
            "Move a suspected scam email to Junk Email (flagged by Crawler's mail check). You can "
            "move it back from Junk Email."
        )
    return (
        "Move a suspected scam email to Spam (flagged by Crawler's mail check). You can move it "
        "back from Spam."
    )


def card_note() -> str:
    return CARD_NOTE


def security_note(verdict: str, hits: Sequence[Hit]) -> dict[str, str]:
    """The card's typed note (scaffold A3, E1): kind "mail_scam", severity
    "high" for a likely scam and "warn" otherwise, and one line naming up to
    three signs in fixed words (a brand domain at most, defanged)."""
    phrases: list[str] = []
    for hit in sorted((h for h in hits if h.code in _NOTE_PHRASES), key=lambda h: _NOTE_ORDER[h.code]):
        phrase = _NOTE_PHRASES[hit.code]
        if "{arg}" in phrase:
            arg = shape.defang(shape.clean_line(hit.arg, 80)) if hit.arg else ""
            phrase = phrase.format(arg=arg) if arg else "the sender imitates a well-known company"
        if phrase not in phrases:
            phrases.append(phrase)
        if len(phrases) >= 3:
            break
    label = "Likely scam" if verdict == "likely_scam" else "Suspicious"
    text = f"{label}: {'; '.join(phrases)}." if phrases else f"{label} email (flagged by Crawler's mail check)."
    return {
        "kind": "mail_scam",
        "severity": "high" if verdict == "likely_scam" else "warn",
        "text": _clip(text, NOTE_TEXT_CHARS),
    }
