"""Declares the "tutor_mode" capability: the owner's one switch for tutor mode,
which gates the runtime built-in tutor.start, the /tutor commands, the
<tutor_mode> block and the owner's tutor locks.

Why it exists: tutor mode (services/tutor) makes a chat guide with questions
and hints instead of handing over final answers, and lets the owner lock it
on for chosen Canvas courses or accounts. It is on by default and low risk
(it only ever makes the assistant stricter), and off means off everywhere:
tutor.start is not offered and is refused as capability_off, a /tutor
command answers with ``when_denied``, no block is added, nothing is withheld
and every lock is dormant until the switch comes back on.

tutor.start is a runtime built-in (answered by the agent runtime, not a
toolkit), claimed here through the ``tutor.`` family prefix like any other
built-in tool.
"""

from __future__ import annotations

from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="tutor_mode",
    label="Tutor mode (hints, not answers)",
    description=(
        "Lets a chat switch to tutor mode (/tutor on, or asking Crawler to tutor you), "
        "where it guides with questions and hints instead of handing over final answers. "
        "The owner can lock it on for chosen courses or accounts."
    ),
    tools=("tutor.",),
    default_enabled=True,
    risk="low",
    when_denied="Tutor mode is turned off. The owner can turn it on in Settings → Permissions.",
)
