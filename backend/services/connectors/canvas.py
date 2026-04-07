"""
Canvas LMS connector for SentientAI.

Implements OAuth 2.0 + PKCE authentication and provides read/write
access to courses, assignments, grades, calendar, and submissions
via the Canvas REST API.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog

from .base import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    UserConfirmationRequired,
)

logger = structlog.get_logger(__name__)


class CanvasConnector(BaseConnector):
    """Connector for the Canvas LMS REST API.

    Rate limiting is set to 700 requests / 10 minutes (Canvas default),
    which translates to 70 requests/minute for the sliding-window limiter.
    """

    CANVAS_RATE_LIMIT = 70  # 700 per 10 min -> 70 per min

    SCOPES: list[str] = [
        "courses.read",
        "assignments.read",
        "submissions.read",
        "grades.read",
        "calendar.read",
        "submissions.write",
    ]

    # -- Action routing table ------------------------------------------------
    _ACTION_MAP: dict[str, str] = {
        "get_courses": "get_courses",
        "get_assignments": "get_assignments",
        "get_grades": "get_grades",
        "get_calendar_events": "get_calendar_events",
        "get_submissions": "get_submissions",
        "submit_assignment": "submit_assignment",
    }

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str = "http://localhost:8000/oauth/callback/canvas",
        timeout_s: float | None = None,
    ) -> None:
        super().__init__(timeout_s=timeout_s, rate_limit=self.CANVAS_RATE_LIMIT)
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._pkce_verifier: str | None = None

    # -- Properties ----------------------------------------------------------

    @property
    def name(self) -> str:
        return "Canvas LMS"

    @property
    def connector_type(self) -> str:
        return "lms"

    @property
    def required_scopes(self) -> list[str]:
        return list(self.SCOPES)

    # -- OAuth 2.0 + PKCE ----------------------------------------------------

    def generate_auth_url(self) -> tuple[str, str]:
        """Build the Canvas OAuth authorization URL with PKCE.

        Returns ``(authorization_url, code_verifier)`` so the caller can
        store the verifier for the token exchange step.
        """
        self._pkce_verifier = secrets.token_urlsafe(64)
        challenge = (
            hashlib.sha256(self._pkce_verifier.encode())
            .digest()
        )
        import base64
        code_challenge = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()

        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self._redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": " ".join(self.SCOPES),
            "state": secrets.token_urlsafe(32),
        }
        url = f"{self._base_url}/login/oauth2/auth?{urlencode(params)}"
        return url, self._pkce_verifier

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Exchange an authorization *code* for tokens, or use a
        pre-existing *access_token* supplied directly.

        Accepted credential keys:
        - ``access_token``: skip OAuth, use token directly.
        - ``code`` + ``code_verifier``: complete PKCE token exchange.
        """
        if token := credentials.get("access_token"):
            self._access_token = token
            self._authenticated = True
            self._log.info("authenticated_with_token")
            return True

        code = credentials.get("code")
        verifier = credentials.get("code_verifier") or self._pkce_verifier
        if not code or not verifier:
            raise AuthenticationError(
                "Provide either 'access_token' or 'code'+'code_verifier'."
            )

        client = self._get_client()
        try:
            resp = await client.post(
                f"{self._base_url}/login/oauth2/token",
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
                f"Canvas OAuth token exchange failed: {exc.response.status_code}"
            ) from exc

        data = resp.json()
        self._access_token = data["access_token"]
        self._refresh_token = data.get("refresh_token")
        self._authenticated = True
        self._log.info("authenticated_via_oauth")
        return True

    async def _refresh_access_token(self) -> None:
        """Use the refresh token to obtain a new access token."""
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available.")
        client = self._get_client()
        resp = await client.post(
            f"{self._base_url}/login/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": self._refresh_token,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._refresh_token = data.get("refresh_token", self._refresh_token)

    # -- Internal HTTP helpers -----------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"}

    async def _api_get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Perform an authenticated GET against the Canvas API."""
        client = self._get_client()
        url = f"{self._base_url}/api/v1{path}"
        resp = await client.get(url, headers=self._headers(), params=params)

        # Auto-refresh on 401
        if resp.status_code == 401 and self._refresh_token:
            await self._refresh_access_token()
            resp = await client.get(url, headers=self._headers(), params=params)

        resp.raise_for_status()
        return resp.json()

    async def _api_post(self, path: str, json_body: dict[str, Any]) -> Any:
        client = self._get_client()
        url = f"{self._base_url}/api/v1{path}"
        resp = await client.post(url, headers=self._headers(), json=json_body)

        if resp.status_code == 401 and self._refresh_token:
            await self._refresh_access_token()
            resp = await client.post(url, headers=self._headers(), json=json_body)

        resp.raise_for_status()
        return resp.json()

    # -- Public data methods -------------------------------------------------

    async def get_courses(self) -> list[dict[str, Any]]:
        """Fetch all active courses for the authenticated user."""
        return await self._api_get(
            "/courses", params={"enrollment_state": "active", "per_page": 100}
        )

    async def get_assignments(self, course_id: int | str) -> list[dict[str, Any]]:
        """Fetch assignments for a given course."""
        return await self._api_get(
            f"/courses/{course_id}/assignments",
            params={"per_page": 100, "order_by": "due_at"},
        )

    async def get_grades(self, course_id: int | str) -> list[dict[str, Any]]:
        """Fetch the current user's enrollments (which contain grades) for a course."""
        return await self._api_get(
            f"/courses/{course_id}/enrollments",
            params={"user_id": "self", "type[]": "StudentEnrollment"},
        )

    async def get_calendar_events(self) -> list[dict[str, Any]]:
        """Fetch upcoming calendar events."""
        return await self._api_get(
            "/calendar_events", params={"type": "event", "per_page": 50}
        )

    async def get_submissions(
        self, course_id: int | str, assignment_id: int | str
    ) -> list[dict[str, Any]]:
        """Fetch submissions for a specific assignment."""
        return await self._api_get(
            f"/courses/{course_id}/assignments/{assignment_id}/submissions",
            params={"per_page": 100},
        )

    async def submit_assignment(
        self,
        course_id: int | str,
        assignment_id: int | str,
        submission_data: dict[str, Any],
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Submit work to an assignment.

        **Requires USER_CONFIRM** -- callers must set ``user_confirmed=True``
        only after obtaining explicit confirmation from the end user.
        """
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="submit_assignment",
                details=(
                    f"Submitting to assignment {assignment_id} in course {course_id}. "
                    "Please confirm this action."
                ),
            )
        return await self._api_post(
            f"/courses/{course_id}/assignments/{assignment_id}/submissions",
            json_body={"submission": submission_data},
        )

    # -- execute dispatch ----------------------------------------------------

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        method_name = self._ACTION_MAP.get(action)
        if not method_name:
            raise ConnectorError(f"Unknown Canvas action: {action}")
        method = getattr(self, method_name)
        result = await method(**params)
        # Normalise to dict for ConnectorResponse
        if isinstance(result, list):
            return {"items": result, "count": len(result)}
        return result

    # -- Health check --------------------------------------------------------

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            resp = await client.get(
                f"{self._base_url}/api/v1/users/self",
                headers=self._headers(),
            )
            return resp.status_code == 200
        except Exception:
            return False
