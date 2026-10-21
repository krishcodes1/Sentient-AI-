"""The texts S10 sends a person on their own channels (Telegram, Slack): a flagged file, a
finished VirusTotal scan, a scan that did not finish, and the owner's notice that VirusTotal
rejected the saved key.

Why it exists: alerts are built from facts only (the file's sanitised name, VirusTotal's counts
and its sanitised threat label), with no model call, so nothing a file or VirusTotal contains can
steer what Crawler says. Names and labels are defanged with ``page_watch.defang``: ".zip" and
".mov" are top-level domains, so Telegram would otherwise turn "invoice.zip" into a link. The
wording never calls a file safe: no detections is "not a guarantee it is safe".

Pure (string building only).

Used by: services/file_reputation/service.py (sends them through ``fan_out_send`` and audits
``file_reputation_alerted``) and the key-rejected notice through ``app.state.owner_send``.
"""

from __future__ import annotations

import unicodedata
from typing import Optional

from services.file_reputation.verdicts import NOT_A_GUARANTEE, FileVerdict
from services.notifications.page_watch import defang

ALERT_NAME_CHARS = 120
ANALYSIS_TIMEOUT_MINUTES = 15
_DETAILS = "Details: Security → File checks."
_CHECK_LATER = "Check it again later in Security → File checks."

KEY_REJECTED_ALERT = (
    "VirusTotal rejected the key saved in Security → Service keys, so files are not being "
    "checked. Replace the key there."
)


def alert_name(name: Optional[str]) -> str:
    """*name* as an alert shows it: control and format characters removed (bidi overrides
    included), whitespace collapsed, at most 120 characters, then defanged. "file" when nothing
    is left."""
    text = "".join(
        " " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch
        for ch in str(name or "")
    )
    text = " ".join(text.split())
    if len(text) > ALERT_NAME_CHARS:
        text = text[: ALERT_NAME_CHARS - 1].rstrip() + "…"
    return defang(text or "file")


def _label(verdict: FileVerdict) -> str:
    return f" ({defang(verdict.threat_label)})" if verdict.threat_label else ""


def flagged_alert(name: Optional[str], verdict: FileVerdict) -> Optional[str]:
    """The alert for a malicious or suspicious file; None for any other verdict (clean,
    unknown and not-checked answers are never alerted)."""
    shown = alert_name(name)
    if verdict.verdict == "malicious":
        return (
            f'⚠️ File check: VirusTotal flags "{shown}" as malicious: {verdict.flagged_by} of '
            f"{verdict.engines} security vendors{_label(verdict)}. Don't open it or send it on. "
            f"{_DETAILS}"
        )
    if verdict.verdict == "suspicious":
        return (
            f"⚠️ File check: {verdict.flagged_by} of {verdict.engines} security vendors on "
            f'VirusTotal flag "{shown}"{_label(verdict)}. A few detections can be false alarms, '
            f"so treat it with care. {_DETAILS}"
        )
    return None


def analysis_done_alert(name: Optional[str], verdict: FileVerdict) -> str:
    """The message when an uploaded file's scan finished: the flagged wording for a flagged
    file, otherwise how many vendors looked at it (never "safe")."""
    flagged = flagged_alert(name, verdict)
    if flagged is not None:
        return flagged
    shown = alert_name(name)
    if verdict.verdict == "no_detections":
        return (
            f'File check: VirusTotal finished scanning "{shown}": none of {verdict.engines} '
            f"security vendors flag it. {NOT_A_GUARANTEE}"
        )
    return (
        f'File check: VirusTotal finished scanning "{shown}", but none of its security vendors '
        f"could judge it. {_CHECK_LATER}"
    )


def analysis_timeout_alert(name: Optional[str]) -> str:
    """The one message when VirusTotal had not finished after about 15 minutes of polls."""
    return (
        f'File check: VirusTotal had not finished scanning "{alert_name(name)}" after '
        f"{ANALYSIS_TIMEOUT_MINUTES} minutes. {_CHECK_LATER}"
    )
