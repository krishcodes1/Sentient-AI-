"""Copyable skeleton for a new connector (NOT registered, never loaded by the app).

Why it exists: every connector follows the same layout (README.md here): an
``ACTIONS`` tuple, a ``BaseConnector`` subclass with one public coroutine per
action, and a module-level ``DEFINITION``. Copy this file to ``<key>.py``,
rename ``Example``, replace the endpoints and actions, then add one line to
``REGISTRY`` in ``registry.py``. See README.md in this directory.

It connects to ``services/connectors/registry.py`` (which validates the
DEFINITION) and talks to the example API ``https://api.example.com``. It
depends on ``base`` (HTTP helpers, errors, ``path_segment``), ``definition``
(declaration types) and ``shaping`` (limits, text caps, pagination).
"""

from __future__ import annotations

from typing import Any, Optional

from services.agent.permissions import ActionCategory

from .base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    UserConfirmationRequired,
    path_segment,
)
from .definition import (
    AuthSpec,
    ConnectorDefinition,
    CredentialField,
    NetworkSpec,
    ToolSpec,
    _schema,
)
from .shaping import cap_text, clamp_limit, pick

_API = "https://api.example.com/v1"

# Longest note body returned in one call; the rest is flagged as truncated.
_MAX_BODY_CHARS = 4000


# One ToolSpec per action. Rules the registry checks (tests fail otherwise):
# - every action has a required_scope ("<area>.read" / "<area>.write");
# - READ actions take exactly the schema properties as keyword arguments;
#   every other category also takes keyword-only ``user_confirmed=False``;
# - no parameter is named ``url``, ``action`` or ``user_confirmed``;
# - every DELETE, and every send/post/share, sets always_confirm=True;
# - 2 to 4 everyday reads set starter=True (at most 4).
ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_notes",
        "List the user's most recent notes (title and id).",
        ActionCategory.READ,
        _schema(limit={"type": "integer", "description": "How many (default 10, max 50)"}),
        required_scope="notes.read",
        starter=True,
    ),
    ToolSpec(
        "get_note",
        "Read one note by id. Long bodies are truncated; the result says so.",
        ActionCategory.READ,
        _schema(note_id={"type": "string", "description": "Note id", "required": True}),
        required_scope="notes.read",
        starter=True,
    ),
    ToolSpec(
        "create_note",
        "Create a note with a title and body.",
        ActionCategory.WRITE,
        _schema(
            title={"type": "string", "required": True},
            body={"type": "string", "required": True},
        ),
        required_scope="notes.write",
    ),
    ToolSpec(
        "delete_note",
        "Delete a note by id. Cannot be undone.",
        ActionCategory.DELETE,
        _schema(note_id={"type": "string", "required": True}),
        required_scope="notes.write",
        always_confirm=True,
    ),
)


def _json_object(data: Any) -> dict[str, Any]:
    """*data* when the provider answered with a JSON object.

    Any other shape (a list, a string, a number) is a malformed response and
    becomes a clean ``ConnectorError`` instead of an ``AttributeError`` that
    the executor would report as a connector crash.
    """
    if not isinstance(data, dict):
        raise ConnectorError("Malformed response from Example")
    return data


class ExampleConnector(BaseConnector):
    """Connector for the Example notes API (bearer token)."""

    # The dispatch allow-map comes from ACTIONS, so they cannot drift apart.
    _ACTIONS = frozenset(spec.action for spec in ACTIONS)

    def __init__(self, timeout_s: Optional[float] = None) -> None:
        super().__init__(timeout_s=timeout_s, rate_limit=60)
        self._token: Optional[str] = None

    @property
    def name(self) -> str:
        return "Example"

    @property
    def connector_type(self) -> str:
        return "productivity"

    @property
    def required_scopes(self) -> list[str]:
        return sorted({spec.required_scope for spec in ACTIONS if spec.required_scope})

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Store the token. No network here; health_check proves it works."""
        token = str(credentials.get("access_token") or "").strip()
        if not token:
            raise AuthenticationError("Example needs an access_token.")
        self._token = token
        self._authenticated = True
        return True

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    async def health_check(self) -> bool:
        try:
            await self._request("GET", f"{_API}/me")
            return True
        except ConnectorError:
            return False

    # -- Actions (one public coroutine per ToolSpec) ---------------------------

    async def list_notes(self, limit: Any = None) -> list[dict[str, Any]]:
        data = _json_object(
            await self._request_json("GET", f"{_API}/notes", params={"limit": clamp_limit(limit)})
        )
        notes = data.get("notes", [])
        if not isinstance(notes, list):
            raise ConnectorError("Malformed response from Example")
        return [pick(item, "id", "title", "updated_at") for item in notes]

    async def get_note(self, note_id: str) -> dict[str, Any]:
        data = _json_object(
            await self._request_json("GET", f"{_API}/notes/{path_segment(note_id)}")
        )
        body, truncated = cap_text(data.get("body"), _MAX_BODY_CHARS)
        result = {**pick(data, "id", "title", "updated_at"), "body": body, "truncated": truncated}
        if truncated:
            result["hint"] = "Body truncated; open the note in Example to read the rest."
        return result

    async def create_note(
        self, title: str, body: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        if not user_confirmed:
            # Raised BEFORE any request: nothing happens until approved.
            raise UserConfirmationRequired(
                action="create_note", details=f"Create a note titled '{title}'?"
            )
        data = await self._request_json(
            "POST", f"{_API}/notes", json={"title": title, "body": body}
        )
        return pick(data, "id", "title")

    async def delete_note(self, note_id: str, *, user_confirmed: bool = False) -> dict[str, Any]:
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_note", details=f"Delete note {note_id}? This cannot be undone."
            )
        await self._request("DELETE", f"{_API}/notes/{path_segment(note_id)}")
        return {"deleted": True, "id": note_id}


DEFINITION = ConnectorDefinition(
    key="example",
    label="Example",
    description="Read and write notes in Example.",
    icon="plug",  # a frontend icon name; unknown names fall back to a plug
    auth=AuthSpec(
        methods=("token",),
        fields=(
            CredentialField(
                "access_token",
                "Access token",
                placeholder="Paste your Example token",
                hint="Example, Settings, API tokens, New token.",
            ),
        ),
        token_auth_method="bearer_token",
        notes="A personal access token with the notes scopes you grant below.",
    ),
    network=NetworkSpec(
        policy_key="example",
        # Every host lists the path prefixes the connector actually uses.
        hosts={"api.example.com": ("/v1/",)},
        https_only=True,
    ),
    actions=ACTIONS,
    connector_class=ExampleConnector,
    docs_url="https://example.com/docs/api-tokens",
)
