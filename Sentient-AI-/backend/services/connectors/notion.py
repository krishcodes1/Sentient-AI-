"""Notion connector: search, read and edit the pages and databases a user has
shared with their Notion internal integration.

Why it exists: Notion is where many users keep notes, tasks and wikis. This
connector lets the agent find pages, read them as Markdown, query databases,
and (with approval) create pages, append Markdown content, update properties
and blocks, comment, archive pages and delete blocks. Files are never
downloaded: file blocks are reported by name and type only.

It connects to the connector registry (``DEFINITION``), the tool executor and
the permission engine through ``services/connectors/registry.py``. It talks to
the Notion REST API at https://api.notion.com/v1 (``Notion-Version``
2022-06-28) with a pasted internal integration secret. The actions live in
``notion_api/reads.py`` and ``notion_api/writes.py``; this module adds the
credentials, headers, health check and ``DEFINITION``.
"""

from __future__ import annotations

from typing import Any, Optional

from .base import AuthenticationError, ConnectorError, ConnectorUnreachable, json_object
from .definition import AuthSpec, ConnectorDefinition, CredentialField, NetworkSpec, ToolSpec
from .notion_api.common import API, NOTION_VERSION
from .notion_api.reads import READ_ACTIONS, ReadsMixin
from .notion_api.writes import DELETE_ACTIONS, WRITE_ACTIONS, WritesMixin

ACTIONS: tuple[ToolSpec, ...] = READ_ACTIONS + WRITE_ACTIONS + DELETE_ACTIONS


class NotionConnector(ReadsMixin, WritesMixin):
    """Connector for the Notion REST API (internal integration secret)."""

    _ACTIONS = frozenset(spec.action for spec in ACTIONS)

    def __init__(self, timeout_s: Optional[float] = None) -> None:
        # Notion averages 3 requests per second per integration and answers
        # bursts with 429 + Retry-After, which _request honours once. This
        # limiter counts actions per minute for this connector instance.
        super().__init__(timeout_s=timeout_s, rate_limit=60)
        self._token: Optional[str] = None

    @property
    def name(self) -> str:
        return "Notion"

    @property
    def connector_type(self) -> str:
        return "productivity"

    @property
    def required_scopes(self) -> list[str]:
        return sorted({spec.required_scope for spec in ACTIONS if spec.required_scope})

    @classmethod
    def validate_credentials(cls, credentials: dict[str, Any]) -> list[str]:
        token = str(credentials.get("access_token") or "").strip()
        if token and any(char.isspace() for char in token):
            return ["access_token must be the connection's API token on its own, without spaces"]
        return []

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Store the secret. No network here; health_check proves it works."""
        token = str(credentials.get("access_token") or "").strip()
        if not token:
            raise AuthenticationError(
                "Notion needs its connection API token. Reconnect Notion in Connectors."
            )
        self._token = token
        self._authenticated = True
        return True

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def _static_headers(self) -> dict[str, str]:
        return {"Notion-Version": NOTION_VERSION, "Accept": "application/json"}

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    async def health_check(self) -> bool:
        """One cheap authenticated call: the integration's own bot user."""
        try:
            response = await self._request("GET", f"{API}/users/me")
        except ConnectorUnreachable:
            self._health_problem = "unreachable"
            return False
        except ConnectorError:
            return False
        me = json_object(response)
        bot = me.get("bot")
        workspace = bot.get("workspace_name") if isinstance(bot, dict) else None
        self._remember_identity(account=workspace, user=me.get("name"))
        return True

    async def revoke(self) -> bool:
        # Internal integration secrets have no revoke endpoint (Notion's
        # /v1/oauth/revoke is for public OAuth integrations and needs their
        # client secret). The user rotates or deletes the secret in Notion's
        # integration settings instead.
        return False


DEFINITION = ConnectorDefinition(
    key="notion",
    label="Notion",
    description="Search, read and edit the Notion pages and databases you share with Crawler.",
    icon="notebook-pen",
    auth=AuthSpec(
        methods=("token",),
        fields=(
            CredentialField(
                "access_token",
                "Connection API token",
                type="password",
                required=True,
                placeholder="Paste the connection's API token",
                hint=(
                    "Create an internal connection, open its Configuration tab and copy the "
                    "API token. Then share the pages you want Crawler to see with it (page "
                    "menu, Connections)."
                ),
            ),
        ),
        token_auth_method="bearer_token",
        notes="Crawler sees only the pages and databases you share with the connection.",
        # Notion renamed integrations to connections in 2026; the old
        # integrations page redirects here.
        token_url="https://app.notion.com/developers/connections",
        token_url_label="Create a Notion connection",
    ),
    network=NetworkSpec(
        policy_key="notion",
        # Exactly the endpoints the actions use. No redirect hosts: files
        # are never downloaded.
        hosts={
            "api.notion.com": (
                "/v1/search",
                "/v1/pages",
                "/v1/blocks/",
                "/v1/databases/",
                "/v1/comments",
                "/v1/users",
            )
        },
        https_only=True,
    ),
    actions=ACTIONS,
    connector_class=NotionConnector,
    docs_url="https://developers.notion.com/guides/get-started/internal-connections",
)
