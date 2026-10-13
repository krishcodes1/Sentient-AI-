"""The chat side of low-risk grants: Telegram's /grants (with a Revoke button
per grant, callback prefix ``rvg:``) and Slack's "grants" and "revoke grants"
keywords, plus the texts both channels show.

Why it exists: a 7-day grant lets one account's small, undoable changes run
without a card (permission tiers, services/agent/permission_grants.py). The
owner must be able to see and end every grant from wherever they are, not only
in Settings, and the approval card must say what the grant button allows.
Grants are per connection and not bound to a channel, so every channel lists
all of the user's grants.

Connects to: services/notifications/telegram.py and slack.py (the dispatch
tables call register_telegram, register_telegram_buttons and register_slack
under their permission_tiers anchors), the grants store over the channel's
session factory, and the audit log (``permission_grant_revoked``, with
revoked_from "telegram" or "slack"). Only ids, labels and dates are shown or
logged.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import structlog

from services.agent.permission_grants import (
    DbPermissionGrantStore,
    PermissionGrant,
    audit_revoked,
)

logger = structlog.get_logger(__name__)

# /grants: revoke one grant (4 characters plus a uuid fits callback_data).
CB_REVOKE_GRANT = "rvg:"

# Grants only: an account on the Auto Approve or "Allow low-risk changes"
# tier runs changes without a grant, so this never says "every change asks".
NO_GRANTS_TEXT = (
    "No account has a 7-day low-risk grant. Each account still follows its permission "
    "tier (Settings and the Connectors page)."
)
_UNAVAILABLE = "Could not read the allowed accounts right now."
_LIST_HEAD = (
    "Crawler makes low-risk changes (stars, labels, drafts, private events, to-dos) "
    "on these accounts without asking, until the date shown:"
)


def _day(when: Any) -> str:
    """A date as the chats show it ("Fri Oct 2"), in this computer's zone."""
    try:
        moment = when if isinstance(when, datetime) else datetime.fromisoformat(str(when))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        local = moment.astimezone()
    except (TypeError, ValueError):
        return str(when)
    return f"{local:%a} {local:%b} {local.day}"


def grant_line(grant: PermissionGrant) -> str:
    """One grant as a list line: the account, until when, when last used."""
    line = f"• {grant.account or 'An account'} — until {_day(grant.expires_at)}"
    if grant.last_used_at is not None:
        runs = "change" if grant.uses == 1 else "changes"
        line += f", last used {_day(grant.last_used_at)} ({grant.uses} {runs})"
    return line


def grants_text(grants: list[PermissionGrant]) -> str:
    """The list of live grants, or the plain "none" text."""
    if not grants:
        return NO_GRANTS_TEXT
    return "\n".join([_LIST_HEAD, "", *(grant_line(g) for g in grants)])


def _store(session_factory: Any) -> DbPermissionGrantStore:
    return DbPermissionGrantStore(session_factory)


async def _audit(
    session_factory: Any,
    user_id: str,
    *,
    revoked_from: str,
    endpoint: str,
    grant: Optional[PermissionGrant] = None,
    count: Optional[int] = None,
) -> None:
    """The permission_grant_revoked row. Best effort: revoking only takes a
    permission away."""
    try:
        async with session_factory() as session:
            await audit_revoked(
                session,
                user_id=user_id,
                connector_type=grant.connector_type if grant is not None else "",
                endpoint=endpoint,
                revoked_from=revoked_from,
                grant_id=grant.id if grant is not None else None,
                connector_id=grant.connector_id if grant is not None else None,
                count=count,
            )
            await session.commit()
    except Exception as exc:
        logger.error("permission_grant_revoke_audit_failed", error_type=type(exc).__name__)


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------


async def telegram_grants(service: Any, chat_id: int, user_id: str) -> None:
    """/grants: every live grant, each with its Revoke button."""
    try:
        grants = await _store(service._session_factory).list_live(user_id)
    except Exception as exc:
        logger.warning("telegram_grants_lookup_failed", error_type=type(exc).__name__)
        await service._api("sendMessage", chat_id=chat_id, text=_UNAVAILABLE)
        return
    if not grants:
        await service._api("sendMessage", chat_id=chat_id, text=NO_GRANTS_TEXT)
        return
    buttons = [
        [{"text": f"Revoke {g.account or 'this account'}"[:60], "callback_data": CB_REVOKE_GRANT + g.id}]
        for g in grants
    ]
    await service._api(
        "sendMessage",
        chat_id=chat_id,
        text=grants_text(grants),
        reply_markup={"inline_keyboard": buttons},
    )


async def telegram_revoke(
    service: Any,
    chat_id: Optional[int],
    grant_id: str,
    answer: Callable[[str], Awaitable[None]],
) -> None:
    """The /grants Revoke button (``rvg:``), once the pressing account proves
    it owns a linked chat; the store scopes the revoke to that user."""
    user_id = await service._user_for_chat(chat_id)
    if chat_id is None or user_id is None:
        await answer("This chat is not linked to a Crawler AI account.")
        return
    try:
        revoked = await _store(service._session_factory).revoke(user_id=user_id, grant_id=grant_id)
    except Exception as exc:
        logger.warning("telegram_grant_revoke_failed", error_type=type(exc).__name__)
        await answer("Could not revoke that right now.")
        return
    if revoked is None:
        await answer("That grant has already ended.")
        return
    account = revoked.account or "That account"
    await answer(f"{account} revoked.")
    await _audit(
        service._session_factory,
        user_id,
        revoked_from="telegram",
        endpoint="telegram:/grants",
        grant=revoked,
    )
    await service._api(
        "sendMessage",
        chat_id=chat_id,
        text=f"{account} no longer makes low-risk changes without asking; its next change asks first.",
    )


def register_telegram(service: Any) -> None:
    """Add /grants to a TelegramService."""

    async def grants(chat_id: int, user_id: str, _argument: str) -> None:
        await telegram_grants(service, chat_id, user_id)

    service._commands["/grants"] = grants


def register_telegram_buttons(service: Any) -> None:
    """Route the rvg: button of a TelegramService."""

    def route(
        chat_id: Optional[int], target: str, answer: Callable[[str], Awaitable[None]]
    ) -> Awaitable[None]:
        return telegram_revoke(service, chat_id, target, answer)

    service._callback_routes[CB_REVOKE_GRANT] = route


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


def register_slack(channel: Any) -> None:
    """Add the "grants" and "revoke grants" keywords to a SlackChannel. The
    channel serves one linked user, checked before any keyword runs."""

    def _keyword_grants(message: Any) -> Optional[Awaitable[None]]:
        text = " ".join(message.text.strip().lower().split())
        if text == "grants":
            return _slack_list(channel, message.channel)
        if text == "revoke grants":
            return _slack_revoke_all(channel, message.channel)
        return None

    channel._text_handlers.append(_keyword_grants)


async def _slack_list(channel: Any, where: str) -> None:
    try:
        grants = await _store(channel._session_factory).list_live(channel.user_id)
    except Exception as exc:
        logger.warning("slack_grants_lookup_failed", error_type=type(exc).__name__)
        await channel._post_text(where, _UNAVAILABLE)
        return
    text = grants_text(grants)
    if grants:
        text += '\n\nSend "revoke grants" to turn them all off.'
    await channel._post_text(where, text)


async def _slack_revoke_all(channel: Any, where: str) -> None:
    try:
        count = await _store(channel._session_factory).revoke_all(user_id=channel.user_id)
    except Exception as exc:
        logger.warning("slack_grants_revoke_failed", error_type=type(exc).__name__)
        await channel._post_text(where, "Could not revoke them right now.")
        return
    if not count:
        await channel._post_text(where, NO_GRANTS_TEXT)
        return
    await _audit(
        channel._session_factory,
        channel.user_id,
        revoked_from="slack",
        endpoint="slack:revoke grants",
        count=count,
    )
    noun = "account" if count == 1 else "accounts"
    await channel._post_text(
        where, f"Revoked low-risk changes on {count} {noun}: every change asks first again."
    )
