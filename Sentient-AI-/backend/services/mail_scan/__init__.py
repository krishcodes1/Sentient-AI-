"""The mail scam scan (security S2): every new email in each connected Gmail
and Outlook inbox is checked on this computer; flagged mail gets one AI
review and an alert on the person's own channels, then a Move-to-Spam/Junk
approval card. Nothing is moved without that card.

Why it exists: a phishing email is most dangerous in the minutes after it
arrives, before anyone asks Crawler about it. This package holds the
review (review.py), the message and card texts (messages.py) and the card
plans and the account export (actions.py); the sweeper is
services/notifications/mail_scan.py and the pure checks live in
services/security (mail_facts, mail_checks). The constants below are what
every part names the same way.

Connects to: services/notifications/mail_scan.py (the sweeper and the route
methods), api/routes/security_mail.py, api/routes/auth.py (the export).
"""

from __future__ import annotations

# The switch every step re-reads (services/capabilities/mail_scam_scan.py).
CAPABILITY = "mail_scam_scan"
# connector_name on every audit row the scan writes (ids, counts and codes only).
AUDIT_CONNECTOR = "mail_security"
# Cards parked for a finding carry origin "mailcheck:<finding uuid>" (45
# characters; pending_actions.origin holds 64). Approving one runs the one
# call and never resumes a turn.
ORIGIN_PREFIX = "mailcheck:"
# The connector types whose mail is checked, and the provider name the
# facts, the rows and the texts use for each.
PROVIDER_OF: dict[str, str] = {"google_workspace": "gmail", "microsoft": "outlook"}
# The scope a connector row needs before its inbox is read (an empty scope
# list is a legacy row, which the executor still lets READ).
READ_SCOPE: dict[str, str] = {"google_workspace": "gmail.read", "microsoft": "mail.read"}
