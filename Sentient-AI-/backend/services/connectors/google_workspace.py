"""
Google Workspace connector for SentientAI.

Provides Gmail and Google Calendar access via OAuth 2.0 + PKCE
with incremental authorization.  All email body content is
sanitized via PromptGuard before reaching the LLM layer.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from email.mime.text import MIMEText
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
import structlog

from .base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    PromptGuard,
    UserConfirmationRequired,
    path_segment,
)

logger = structlog.get_logger(__name__)


class GoogleWorkspaceConnector(BaseConnector):
    """Connector for Gmail and Google Calendar APIs."""

    GMAIL_SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.compose",
    ]
    CALENDAR_SCOPES = [
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/calendar.events",
    ]

    _ACTION_MAP: dict[str, str] = {
        "get_messages": "get_messages",
        "get_message": "get_message",
        "send_email": "send_email",
        "search_emails": "search_emails",
        "get_events": "get_events",
        "create_event": "create_event",
        "check_availability": "check_availability",
    }

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str = "http://localhost:8000/oauth/callback/google",
        timeout_s: Optional[float] = None,
    ) -> None:
        super().__init__(timeout_s=timeout_s, rate_limit=60)
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._granted_scopes: set[str] = set()
        self._pkce_verifier: Optional[str] = None

    # -- Properties ----------------------------------------------------------

    @property
    def name(self) -> str:
        return "Google Workspace"

    @property
    def connector_type(self) -> str:
        return "productivity"

    @property
    def required_scopes(self) -> list[str]:
        return self.GMAIL_SCOPES + self.CALENDAR_SCOPES

    # -- OAuth 2.0 + PKCE with incremental auth ------------------------------

    def generate_auth_url(self, scopes: list[str] | None = None) -> tuple[str, str]:
        """Build Google OAuth URL with PKCE.

        Supports *incremental authorization*: pass a subset of scopes to
        request only what is needed right now; further scopes can be
        requested later via a second auth round-trip.

        Returns ``(authorization_url, code_verifier)``.
        """
        requested = scopes or self.required_scopes
        self._pkce_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(self._pkce_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self._redirect_uri,
            "scope": " ".join(requested),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",  # incremental auth
            "state": secrets.token_urlsafe(32),
        }
        url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        return url, self._pkce_verifier

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Complete OAuth token exchange or accept a raw token.

        Accepted keys:
        - ``access_token`` (+ optional ``refresh_token``): use directly.
        - ``code`` + ``code_verifier``: PKCE exchange.
        """
        if token := credentials.get("access_token"):
            self._access_token = token
            self._refresh_token = credentials.get("refresh_token")
            self._authenticated = True
            self._log.info("authenticated_with_token")
            return True

        code = credentials.get("code")
        verifier = credentials.get("code_verifier") or self._pkce_verifier
        if not code or not verifier:
            raise AuthenticationError(
                "Provide 'access_token' or 'code'+'code_verifier'."
            )

        client = self._get_client()
        try:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "redirect_uri": self._redirect_uri,
                    "code": code,
                    "code_verifier": verifier,
                },
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise AuthenticationError(
                f"Google OAuth token exchange failed: {exc.response.status_code}"
            ) from exc

        data = resp.json()
        self._access_token = data["access_token"]
        self._refresh_token = data.get("refresh_token")
        self._granted_scopes = set(data.get("scope", "").split())
        self._authenticated = True
        self._log.info("authenticated_via_oauth", scopes=list(self._granted_scopes))
        return True

    def updated_credentials(
        self, original: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Return a credentials dict to persist when this session produced
        tokens the stored credentials don't have — a refresh rotated the
        access token, or a one-time OAuth code was exchanged. ``None`` when
        nothing changed. Without persisting these, every refreshed token
        died with the connector instance and the user had to re-paste a
        fresh token every hour.
        """
        if not self._access_token:
            return None
        if self._access_token == original.get("access_token") and (
            self._refresh_token or None
        ) == (original.get("refresh_token") or None):
            return None
        updated = dict(original)
        updated["access_token"] = self._access_token
        if self._refresh_token:
            updated["refresh_token"] = self._refresh_token
        # A consumed one-time authorization code must never be replayed.
        updated.pop("code", None)
        updated.pop("code_verifier", None)
        return updated

    async def _refresh_access_token(self) -> None:
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available.")
        client = self._get_client()
        resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": self._refresh_token,
            },
        )
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # Google answers a revoked or expired grant with 400
            # invalid_grant. That is a re-auth prompt, not an outage, so it
            # must not reach BaseConnector.execute as a bare HTTPStatusError.
            raise AuthenticationError(
                f"Google token refresh failed: {exc.response.status_code}"
            ) from exc
        data = resp.json()
        self._access_token = data["access_token"]

    # -- Internal HTTP helpers -----------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"}

    async def _gapi_get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        client = self._get_client()
        resp = await client.get(url, headers=self._headers(), params=params)
        if resp.status_code == 401 and self._refresh_token:
            await self._refresh_access_token()
            resp = await client.get(url, headers=self._headers(), params=params)
        resp.raise_for_status()
        return resp.json()

    async def _gapi_post(self, url: str, json_body: dict[str, Any]) -> Any:
        client = self._get_client()
        resp = await client.post(url, headers=self._headers(), json=json_body)
        if resp.status_code == 401 and self._refresh_token:
            await self._refresh_access_token()
            resp = await client.post(url, headers=self._headers(), json=json_body)
        resp.raise_for_status()
        return resp.json()

    # -- Gmail methods -------------------------------------------------------

    async def get_messages(
        self, query: str = "", max_results: int = 20
    ) -> list[dict[str, Any]]:
        """List Gmail messages matching *query* (Gmail search syntax)."""
        data = await self._gapi_get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            params={"q": query, "maxResults": max_results},
        )
        messages: list[dict[str, Any]] = []
        for msg_stub in data.get("messages", []):
            detail = await self.get_message(msg_stub["id"])
            messages.append(detail)
        return messages

    # Order matters: the whole tree is searched for text/plain before
    # text/html is considered at all, so a plain part buried three levels
    # deep still wins over a top-level HTML alternative.
    _BODY_MIME_PREFERENCE: tuple[str, ...] = ("text/plain", "text/html")

    @staticmethod
    def _decode_part_data(part: dict[str, Any]) -> str:
        """Decode a MIME part's base64url body, tolerating missing padding."""
        encoded = part.get("body", {}).get("data", "")
        if not encoded:
            return ""
        return base64.urlsafe_b64decode(encoded + "==").decode("utf-8", errors="replace")

    @classmethod
    def _find_part(cls, part: dict[str, Any], mime_type: str) -> str:
        """Depth-first search for the first *mime_type* part carrying data."""
        if part.get("mimeType") == mime_type:
            decoded = cls._decode_part_data(part)
            if decoded:
                return decoded
        for child in part.get("parts", []):
            found = cls._find_part(child, mime_type)
            if found:
                return found
        return ""

    @classmethod
    def _extract_body(cls, payload: dict[str, Any]) -> str:
        """Pull the readable text out of a Gmail ``payload`` MIME tree.

        The walk has to recurse: Gmail wraps the text/plain part in a
        multipart/alternative child as soon as the message carries an
        attachment or is multipart/mixed, so scanning only the top level of
        ``payload["parts"]`` returns an empty body for most real mail while
        subject/from/snippet still populate — a silent truncation the caller
        cannot detect. text/html is accepted only as a last resort: markup is
        worse to read than plain text but far better than nothing, and the
        body is sanitized by PromptGuard either way.
        """
        for mime_type in cls._BODY_MIME_PREFERENCE:
            body = cls._find_part(payload, mime_type)
            if body:
                return body
        return ""

    async def get_message(self, message_id: str) -> dict[str, Any]:
        """Fetch a single Gmail message by ID with content sanitization."""
        raw = await self._gapi_get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/"
            f"{path_segment(message_id)}",
            params={"format": "full"},
        )
        # Extract useful fields
        headers_list = raw.get("payload", {}).get("headers", [])
        header_map = {h["name"].lower(): h["value"] for h in headers_list}

        body_data = self._extract_body(raw.get("payload", {}))

        # Sanitize email body before returning
        sanitized_body, _ = PromptGuard.scan(body_data)

        return {
            "id": raw.get("id"),
            "thread_id": raw.get("threadId"),
            "subject": header_map.get("subject", ""),
            "from": header_map.get("from", ""),
            "to": header_map.get("to", ""),
            "date": header_map.get("date", ""),
            "snippet": raw.get("snippet", ""),
            "body": sanitized_body,
            "label_ids": raw.get("labelIds", []),
        }

    async def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Send an email, gated behind explicit user confirmation.

        **Requires USER_CONFIRM**. Without confirmation nothing leaves the
        process: the preview handed to ``UserConfirmationRequired`` is built
        from the arguments, and the message is only composed and sent once
        ``user_confirmed`` is set.

        No Gmail draft is staged for the preview, deliberately. The approval
        flow re-invokes this method with the *same* arguments plus
        ``user_confirmed=True`` (``ConnectorToolExecutor._dispatch``), so a
        draft id minted here cannot survive the round-trip and the confirmed
        send could never adopt it; and on denial nothing calls the connector
        at all, so there is no point where a staged draft could be cleaned
        up. Either way the draft would be orphaned in the user's real
        mailbox — on approval alongside the sent copy, on denial forever.
        """
        if not user_confirmed:
            preview = body if len(body) <= 500 else body[:500] + "..."
            raise UserConfirmationRequired(
                action="send_email",
                details=(
                    f"Send email to '{to}' with subject '{subject}'?\n"
                    f"Body:\n{preview}\n"
                    "Nothing has been created or sent yet; confirm to send."
                ),
            )

        mime = MIMEText(body)
        mime["to"] = to
        mime["subject"] = subject
        raw_msg = base64.urlsafe_b64encode(mime.as_bytes()).decode()

        send_resp = await self._gapi_post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            json_body={"raw": raw_msg},
        )
        return {
            "status": "sent",
            "message_id": send_resp.get("id"),
            "thread_id": send_resp.get("threadId"),
        }

    async def search_emails(self, query: str) -> list[dict[str, Any]]:
        """Search Gmail using Gmail search syntax."""
        return await self.get_messages(query=query, max_results=25)

    # -- Calendar methods ----------------------------------------------------

    async def get_events(
        self,
        time_min: Optional[str] = None,
        time_max: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Fetch calendar events within a time window (RFC 3339 strings).

        Defaults to the next 7 days when no window is given, matching the
        tool catalog where both parameters are optional.
        """
        time_min, time_max = self._default_window(time_min, time_max)
        data = await self._gapi_get(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            params={
                "timeMin": time_min,
                "timeMax": time_max,
                "singleEvents": True,
                "orderBy": "startTime",
                "maxResults": 100,
            },
        )
        return data.get("items", [])

    async def create_event(
        self,
        event_data: dict[str, Any],
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Create a calendar event.

        **Requires USER_CONFIRM** before the event is actually created.
        """
        if not user_confirmed:
            summary = event_data.get("summary", "Untitled event")
            start = event_data.get("start", {})
            raise UserConfirmationRequired(
                action="create_event",
                details=(
                    f"Create calendar event '{summary}' starting at "
                    f"{start.get('dateTime', start.get('date', '?'))}? "
                    "Please confirm."
                ),
            )

        return await self._gapi_post(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            json_body=event_data,
        )

    @staticmethod
    def _default_window(
        time_min: Optional[str], time_max: Optional[str]
    ) -> tuple[str, str]:
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        return (
            time_min or now.isoformat(),
            time_max or (now + timedelta(days=7)).isoformat(),
        )

    async def check_availability(
        self,
        time_min: Optional[str] = None,
        time_max: Optional[str] = None,
    ) -> dict[str, Any]:
        """Check free/busy status for the primary calendar (defaults to the
        next 7 days)."""
        time_min, time_max = self._default_window(time_min, time_max)
        data = await self._gapi_post(
            "https://www.googleapis.com/calendar/v3/freeBusy",
            json_body={
                "timeMin": time_min,
                "timeMax": time_max,
                "items": [{"id": "primary"}],
            },
        )
        calendars = data.get("calendars", {})
        primary = calendars.get("primary", {})
        busy_slots = primary.get("busy", [])
        return {
            "time_min": time_min,
            "time_max": time_max,
            "busy_slots": busy_slots,
            "is_free": len(busy_slots) == 0,
        }

    # -- execute dispatch ----------------------------------------------------

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        method_name = self._ACTION_MAP.get(action)
        if not method_name:
            raise ConnectorError(f"Unknown Google Workspace action: {action}")
        method = getattr(self, method_name)
        result = await method(**params)
        if isinstance(result, list):
            return {"items": result, "count": len(result)}
        return result

    # -- Health check --------------------------------------------------------

    # (scope prefix, probe URL) pairs, cheapest first. The connector is
    # healthy when the stored token can reach *any* surface it was granted:
    # probing Gmail alone failed every calendar-only connector — an
    # incremental-auth grant the platform explicitly supports — and told the
    # user their credentials were invalid when they were merely narrower
    # than the probe.
    _HEALTH_PROBES: tuple[tuple[str, str], ...] = (
        (
            "https://www.googleapis.com/auth/gmail",
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        ),
        (
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/calendar/v3/users/me/calendarList",
        ),
    )

    def _ordered_health_probes(self) -> tuple[tuple[str, str], ...]:
        """Probes to try, granted surfaces first.

        ``_granted_scopes`` is only populated by the OAuth exchange; a
        connector configured with a raw access token knows nothing about
        its scopes, so every probe is tried in that case.
        """
        if not self._granted_scopes:
            return self._HEALTH_PROBES
        granted = tuple(
            probe
            for probe in self._HEALTH_PROBES
            if any(s.startswith(probe[0]) for s in self._granted_scopes)
        )
        return granted or self._HEALTH_PROBES

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            for _, url in self._ordered_health_probes():
                resp = await client.get(url, headers=self._headers())
                if resp.status_code == 200:
                    return True
                if resp.status_code != 403:
                    # 403 is "this token lacks that API's scope" — the only
                    # answer worth trying another surface for. A 401 means
                    # the token itself is bad and every surface will refuse
                    # it, and a 5xx is an outage, not a scope question.
                    return False
            return False
        except Exception:
            return False
