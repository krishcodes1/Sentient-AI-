"""Slack workspace tools connector: read channels, history, threads, search, users
and files, and (with approval) post, reply, schedule, react, upload text files,
set status, create, invite, archive and delete.

Why it exists: spec section 5.4 (tools part). The user creates a Slack app from
the shipped ``slack_manifest.json`` (one click via ``MANIFEST_URL``) and pastes
its tokens; no Slack SDK, no install-wide token. The Socket Mode DM chat channel
(services/notifications/slack.py, run by slack_manager.py) reuses the tokens
stored here (``bot_token`` and ``app_token``).

It connects to ``services/connectors/registry.py`` (one ``_load("slack")``
line), which turns ``DEFINITION`` into catalog, permission and network rows.
External service: the Slack Web API (https://slack.com/api/) and the upload
host files.slack.com. Depends on ``slack_api`` (the action mixins), ``base``
and ``definition``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from .base import AuthenticationError, BaseConnector, ConnectorError
from .definition import AuthSpec, ConnectorDefinition, CredentialField, NetworkSpec, ToolSpec
from .slack_api.client import API_BASE, TOKEN_PREFIXES, UPLOAD_HOST, UPLOAD_PATH_PREFIX
from .slack_api.reads import READ_ACTIONS, SlackReadsMixin
from .slack_api.writes import WRITE_ACTIONS, SlackWritesMixin

ACTIONS: tuple[ToolSpec, ...] = READ_ACTIONS + WRITE_ACTIONS

# Why each Slack scope in slack_manifest.json is there (JSON has no comments):
# Bot token (xoxb-):
#   channels:read, groups:read        list_channels (public / private).
#   channels:history, groups:history  get_history and get_thread.
#   chat:write                        post_message, reply_in_thread, schedule_message,
#                                     delete_message (the app's own messages).
#   reactions:write                   add_reaction.
#   users:read                        list_users, get_user.
#   files:read, files:write           get_file_info; upload_file.
#   channels:manage, groups:write     create_channel, invite_to_channel, archive_channel.
#   im:read, im:history, im:write     the later DM channel: read DM info, receive
#                                     message.im events, open the DM to reply.
# User token (xoxp-, optional):
#   search:read                       search_messages (Slack has no bot search).
#   users.profile:write               set_status.
# Not requested: mpim:* (group DMs are not listed or read by any action),
# users:read.email, chat:write.public, channels:join.
MANIFEST_PATH = Path(__file__).with_name("slack_manifest.json")


def _manifest_url() -> str:
    """Slack's "create app from manifest" link, prefilled with the manifest."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    compact = json.dumps(manifest, separators=(",", ":"), ensure_ascii=True)
    return "https://api.slack.com/apps?new_app=1&manifest_json=" + quote(compact, safe="")


# Computed once at import.
MANIFEST_URL = _manifest_url()


class SlackConnector(SlackReadsMixin, SlackWritesMixin, BaseConnector):
    """Slack Web API connector (bot token; user token for search and status)."""

    # The dispatch allow-map comes from ACTIONS, so they cannot drift apart.
    _ACTIONS = frozenset(spec.action for spec in ACTIONS)
    SUPPORTS_REVOKE = True

    @property
    def name(self) -> str:
        return "Slack"

    @property
    def connector_type(self) -> str:
        return "messaging"

    @property
    def required_scopes(self) -> list[str]:
        return sorted({spec.required_scope for spec in ACTIONS if spec.required_scope})

    @classmethod
    def from_credentials(
        cls, credentials: dict[str, Any], *, timeout_s: Optional[float] = None
    ) -> BaseConnector:
        connector = cls(timeout_s=timeout_s)
        # Tokens are known up front so revoke() works without authenticate().
        connector._store_tokens(credentials)
        return connector

    @classmethod
    def validate_credentials(cls, credentials: dict[str, Any]) -> list[str]:
        """Prefix checks only; the values are never echoed."""
        problems: list[str] = []
        for key, prefix in TOKEN_PREFIXES.items():
            value = credentials.get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                continue  # missing required fields are reported by the factory
            if not isinstance(value, str) or not value.strip().startswith(prefix):
                problems.append(f"{key} must start with {prefix}")
        return problems

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Store the tokens. No network here; health_check proves they work."""
        self._store_tokens(credentials)
        if not self._bot_token:
            raise AuthenticationError("Slack needs a bot token (xoxb-).")
        self._authenticated = True
        return True

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    async def health_check(self) -> bool:
        try:
            await self._call("auth.test")
            return True
        except ConnectorError:
            return False

    async def revoke(self) -> bool:
        """Revoke the bot and user tokens with ``auth.revoke`` (best effort).

        The app-level token (xapp-) cannot be revoked this way: Slack only
        lets the user delete it on the app's Basic Information page, so it is
        left alone here. True only when every stored token was revoked.
        """
        tokens = [token for token in (self._bot_token, self._user_token) if token]
        if not tokens:
            return False
        revoked_all = True
        for token in tokens:
            try:
                data = await self._request_json(
                    "POST",
                    f"{API_BASE}/auth.revoke",
                    headers={"Authorization": f"Bearer {token}"},
                    authorized=False,
                )
            except ConnectorError:
                revoked_all = False
                continue
            if not (isinstance(data, dict) and data.get("ok") is True and data.get("revoked")):
                revoked_all = False
        return revoked_all


DEFINITION = ConnectorDefinition(
    key="slack",
    label="Slack",
    description="Read channels, threads and people; post, react and share files with approval.",
    icon="slack",
    auth=AuthSpec(
        methods=("token",),
        fields=(
            CredentialField(
                "bot_token",
                "Bot token (xoxb-...)",
                placeholder="xoxb-...",
                hint="Create the app from the manifest link, install it, then copy "
                "OAuth & Permissions, Bot User OAuth Token.",
            ),
            CredentialField(
                "app_token",
                "App-level token (xapp-...), only needed for Slack DMs with Crawler",
                required=False,
                placeholder="xapp-...",
                hint="Basic Information, App-Level Tokens, with the connections:write scope.",
            ),
            CredentialField(
                "user_token",
                "User token (xoxp-...), only needed for search and status",
                required=False,
                placeholder="xoxp-...",
                hint="OAuth & Permissions, User OAuth Token.",
            ),
        ),
        token_auth_method="bearer_token",
        notes=(
            "Open the manifest link to create the Crawler Slack app, install it to your "
            "workspace and paste its tokens. Invite the app to a channel before asking "
            "Crawler to read it."
        ),
    ),
    network=NetworkSpec(
        policy_key="slack",
        hosts={"slack.com": ("/api/",), UPLOAD_HOST: (UPLOAD_PATH_PREFIX,)},
        https_only=True,
        # Socket Mode hosts for the DM channel (checked by check_websocket_policy):
        # the two apps.connections.open returns in practice, plus the one
        # Slack's Socket Mode docs show, so a host change does not fail closed.
        ws_hosts=("wss-primary.slack.com", "wss-backup.slack.com", "wss.slack.com"),
    ),
    actions=ACTIONS,
    connector_class=SlackConnector,
    docs_url=MANIFEST_URL,
)
