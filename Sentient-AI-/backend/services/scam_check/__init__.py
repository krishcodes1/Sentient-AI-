"""On-demand scam checks (security S3): "is this a scam?" for a message, link,
screenshot or QR code the person asks about, from /scam in Telegram, "scam ..."
in a Slack DM, /scam in a web chat, the Security page's Check for scams tab,
and the security.check_scam tool in a chat turn.

Why it exists: people get phishing texts and emails daily and ask whether to
trust them. The pasted message is someone else's words, so it is checked
outside the chat turn and fenced as untrusted: free local checks first, links
through the link reputation service, then (out of turn only) one look by the
account's own AI provider, which can raise the verdict but never lower it. The
answer is never "safe".

Import rule: nothing in this package imports api.routes.agent at module level
(agent.py imports services.scam_check.web), so the import stays one-way.

Connects to: services/notifications/telegram.py and slack.py (the channel
hooks, channels.py), api/routes/agent.py (web.py), main.py (service.py),
services/tools/security_checks.py (security.check_scam).
"""

from services.scam_check.service import (
    ScamCheckRequest,
    ScamCheckResult,
    ScamCheckService,
    ScamFile,
    ScamImage,
    scam_check_for,
)
from services.scam_check.web import parse_scam_command

__all__ = [
    "ScamCheckRequest",
    "ScamCheckResult",
    "ScamCheckService",
    "ScamFile",
    "ScamImage",
    "parse_scam_command",
    "scam_check_for",
]
