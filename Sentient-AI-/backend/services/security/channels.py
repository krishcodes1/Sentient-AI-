"""Masks keys, passwords, card, bank and ID numbers in text a chat channel
(Telegram, Slack) sends, and words the lines the person sees about it.

Why it exists: a chat app keeps its own copy of every message, outside
Crawler's reach, so a secret the model or a tool result put in a reply must be
hidden before it is sent. Both channels use these helpers at their one send
choke point and before splitting a long reply, so a value can never straddle
two messages. Contact details are never masked here: this is the owner's own
chat.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog

from services.security.policies import CHANNEL, CHANNEL_WITHHELD
from services.security.redact import DETECTOR_ERROR_LABEL, first_finding, redact_text
from services.security.secrets import Kind, with_article

logger = structlog.get_logger(__name__)

LOCK = "\U0001f512"


def mask_text(text: str, *, channel: str) -> tuple[str, int]:
    """*text* with every key, password, card, bank or ID number replaced by
    "[hidden: <label>]", and how many were hidden. When the detector fails
    the whole text becomes the withheld notice."""
    redacted = redact_text(text, CHANNEL)
    if redacted.withheld:
        logger.warning("channel_text_withheld", channel=channel)
        return CHANNEL_WITHHELD, 0
    if redacted.hidden:
        logger.info("channel_text_redacted", channel=channel, values=redacted.hidden)
    return redacted.text, redacted.hidden


def hidden_footer(hidden: int, *, app: str) -> str:
    """The one line a reply ends with when values were hidden from it."""
    if hidden == 1:
        return (
            f"{LOCK} Crawler hid 1 value that looks like a key, card or ID number. "
            f"It is not shown on {app}."
        )
    return (
        f"{LOCK} Crawler hid {hidden} values that look like a key, card or ID number. "
        f"They are not shown on {app}."
    )


def mask_reply(text: str, *, app: str, channel: str) -> str:
    """A whole reply masked before it is split into messages, with the
    footer appended when anything was hidden."""
    masked, hidden = mask_text(text, channel=channel)
    if hidden:
        masked = f"{masked}\n\n{hidden_footer(hidden, app=app)}"
    return masked


def inbound_warning(text: str, *, app: str) -> Optional[str]:
    """The line sent before a turn when the person's own message holds a
    key, password, card, bank or ID number (labels only), or None."""
    finding = first_finding(text, CHANNEL)
    if finding is None or finding.label == DETECTOR_ERROR_LABEL:
        return None
    looks_like = with_article(finding.label)
    if finding.kind is Kind.credential:
        advice = "revoke it and make a new one"
    else:
        advice = "delete that message from the chat"
    return (
        f"{LOCK} Your message has what looks like {looks_like}. Crawler hid it from the AI, "
        f"but {app} keeps a copy of this chat: {advice}."
    )


def mask_blocks(blocks: Any, *, channel: str) -> Any:
    """A copy of Slack *blocks* with the text of every plain_text object
    masked (section text, context elements, button labels)."""
    if isinstance(blocks, list):
        return [mask_blocks(item, channel=channel) for item in blocks]
    if isinstance(blocks, dict):
        out = {key: mask_blocks(value, channel=channel) for key, value in blocks.items()}
        if out.get("type") == "plain_text" and isinstance(blocks.get("text"), str):
            out["text"] = mask_text(blocks["text"], channel=channel)[0]
        return out
    return blocks


__all__ = ["LOCK", "hidden_footer", "inbound_warning", "mask_blocks", "mask_reply", "mask_text"]
