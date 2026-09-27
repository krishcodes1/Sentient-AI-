"""Implements the Canvas LMS connector: OAuth 2.0 + PKCE sign-in and course,
assignment, grade, calendar and submission actions over the Canvas REST API.

Why it exists: The factory constructs it for tool execution and the connector
routes; Canvas endpoints and parameter encoding live here so nothing else needs
to know the API.

Canvas LMS connector for Crawler AI.

Implements OAuth 2.0 + PKCE authentication and provides read/write
access to courses, assignments, grades, calendar, and submissions
via the Canvas REST API.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
import structlog

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

logger = structlog.get_logger(__name__)


def _canvas_time(value: Any) -> Optional[datetime]:
    """A Canvas ISO 8601 timestamp as an aware datetime, or None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _shape_course(
    course: dict[str, Any],
    term: dict[str, Any],
    start: Optional[datetime],
    end: Optional[datetime],
) -> dict[str, Any]:
    """The fields of a course the model needs; absent ones are left out."""
    shaped = {k: course[k] for k in ("id", "name", "course_code") if course.get(k) is not None}
    if term.get("name"):
        shaped["term"] = term["name"]
    if start:
        shaped["start_at"] = start.isoformat()
    if end:
        shaped["end_at"] = end.isoformat()
    return shaped


# The tool catalog for Canvas: one ToolSpec per action the model may call.
# The registry derives the connector entries of CONNECTOR_CATALOG from it.
ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_courses",
        "List the user's active Canvas courses.",
        ActionCategory.READ,
        required_scope="courses.read",
        starter=True,
    ),
    ToolSpec(
        "get_assignments",
        "List assignments for a Canvas course.",
        ActionCategory.READ,
        _schema(course_id={"type": "string", "description": "Numeric Canvas course id from canvas.get_courses (not the course code)", "required": True}),
        required_scope="assignments.read",
        starter=True,
    ),
    ToolSpec(
        "get_grades",
        "Get the user's grades for a Canvas course.",
        ActionCategory.READ,
        _schema(course_id={"type": "string", "description": "Numeric Canvas course id from canvas.get_courses (not the course code)", "required": True}),
        required_scope="grades.read",
    ),
    ToolSpec(
        "get_calendar_events",
        "List upcoming Canvas calendar events.",
        ActionCategory.READ,
        required_scope="calendar.read",
        starter=True,
    ),
    ToolSpec(
        "get_submissions",
        "List submissions for a Canvas assignment.",
        ActionCategory.READ,
        _schema(
            course_id={"type": "string", "description": "Numeric Canvas course id from canvas.get_courses (not the course code)", "required": True},
            assignment_id={"type": "string", "description": "Numeric Canvas assignment id from canvas.get_assignments", "required": True},
        ),
        required_scope="submissions.read",
    ),
    ToolSpec(
        "submit_assignment",
        "Submit work to a Canvas assignment.",
        ActionCategory.WRITE,
        _schema(
            course_id={"type": "string", "description": "Numeric Canvas course id from canvas.get_courses (not the course code)", "required": True},
            assignment_id={"type": "string", "description": "Numeric Canvas assignment id from canvas.get_assignments", "required": True},
            submission_data={"type": "object", "required": True},
        ),
        required_scope="submissions.write",
    ),
)

# /api/v1/ is the Canvas REST surface; /login/oauth2/token is the OAuth
# code-exchange and refresh endpoint. The interactive /login/oauth2/auth
# page is browser-side and stays blocked. Shared by the hosted
# (*.instructure.com) and self-hosted cases, so a self-hosted instance is
# never reachable at paths the hosted one is not.
_CANVAS_PATHS: tuple[str, ...] = ("/api/v1/", "/login/oauth2/token")


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
        timeout_s: Optional[float] = None,
    ) -> None:
        super().__init__(timeout_s=timeout_s, rate_limit=self.CANVAS_RATE_LIMIT)
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._pkce_verifier: Optional[str] = None

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

    @property
    def instance_host(self) -> str:
        """Hostname of the Canvas instance this connector was built for.

        Canvas is commonly self-hosted, so the static ``*.instructure.com``
        allowlist cannot cover every legitimate deployment. The factory
        feeds this host to ``set_network_policy`` as the one extra name the
        policy accepts; the SSRF address check still applies to it, so a
        host resolving into a private range stays refused.
        """
        from core.network_security import normalize_policy_host

        return normalize_policy_host(self._base_url)

    # -- Registry hooks --------------------------------------------------------

    @classmethod
    def from_credentials(
        cls, credentials: dict[str, Any], *, timeout_s: Optional[float] = None
    ) -> CanvasConnector:
        """Build an instance for the stored ``base_url`` and client pair."""
        return cls(
            base_url=str(credentials["base_url"]),
            client_id=str(credentials.get("client_id", "")),
            client_secret=str(credentials.get("client_secret", "")),
            timeout_s=timeout_s,
        )

    @classmethod
    def validate_credentials(cls, credentials: dict[str, Any]) -> list[str]:
        """``base_url`` must be an http(s) URL that names a host.

        A missing ``base_url`` is reported by the factory's required-field
        check, so only a present value is examined here.
        """
        from core.network_security import normalize_policy_host

        base_url = str(credentials.get("base_url", ""))
        if not base_url:
            return []
        if not base_url.startswith(("http://", "https://")):
            return ["base_url must start with http:// or https://"]
        if not normalize_policy_host(base_url):
            # Without a hostname there is nothing to add to the network
            # allowlist, so every call this connector ever makes would be
            # refused. Say so now instead of at first use.
            return ["base_url must include a hostname"]
        return []

    @property
    def policy_extra_hosts(self) -> tuple[str, ...]:
        """The self-hosted instance host, held to the policy's instance paths.

        A Canvas instance the user self-hosts is not under
        ``*.instructure.com``, so its host is the single extra allowlist
        entry for this connector; the SSRF address policy still applies.
        """
        host = self.instance_host
        return (host,) if host else ()

    def updated_credentials(self, original: dict[str, Any]) -> dict[str, Any] | None:
        """Credentials to persist when this session rotated a token, else None.

        A 401 refresh (``_refresh_access_token``) mints a new access token
        and Canvas may rotate the refresh token with it; a code exchange
        produces both. Without persisting them the next call starts from a
        dead token, and a rotated refresh token would be lost for good.
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
            # Keep the stored refresh token so an expired bearer token can
            # be renewed mid-session (401 -> _refresh_access_token) when
            # refresh credentials were provided with the connector.
            self._refresh_token = credentials.get("refresh_token") or None
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
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # A refused refresh means the grant is gone (revoked, or the
            # refresh token itself expired) and only re-authorization fixes
            # it. Left as a raw HTTPStatusError it would reach
            # BaseConnector.execute as an unclassified upstream failure and
            # be reported as "Canvas is broken".
            raise AuthenticationError(
                f"Canvas token refresh failed: {exc.response.status_code}"
            ) from exc
        data = resp.json()
        self._access_token = data["access_token"]
        self._refresh_token = data.get("refresh_token", self._refresh_token)

    # -- Internal HTTP helpers -----------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"}

    # Pagination safety cap. Canvas paginates every list endpoint via the
    # RFC 5988 ``Link`` header; following rel="next" unboundedly would let a
    # pathological account (or a hostile server) hold a tool call open
    # indefinitely. 10 pages at per_page=100 covers 1,000 items per call.
    _MAX_PAGES = 10

    async def _get_with_refresh(
        self, url: str, params: dict[str, Any] | None = None
    ) -> httpx.Response:
        """One authenticated GET with the 401 -> refresh -> retry dance."""
        client = self._get_client()
        resp = await client.get(url, headers=self._headers(), params=params)

        # Auto-refresh on 401
        if resp.status_code == 401 and self._refresh_token:
            await self._refresh_access_token()
            resp = await client.get(url, headers=self._headers(), params=params)

        resp.raise_for_status()
        return resp

    def _next_page_url(self, resp: httpx.Response) -> Optional[str]:
        """The rel="next" Link target, or None on the last page.

        Only same-instance URLs are followed: the Link header is
        server-supplied, and blindly GETting whatever it names would let a
        compromised Canvas host steer authenticated requests elsewhere.
        """
        next_link = resp.links.get("next", {}).get("url")
        if next_link and next_link.startswith(f"{self._base_url}/"):
            return next_link
        return None

    async def _api_get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Perform an authenticated GET against the Canvas API.

        List responses follow Canvas's Link-header pagination (rel="next")
        up to ``_MAX_PAGES`` pages. Before this, every list silently
        truncated at one page (100 items): a student with 120 assignments
        got 100 back with no indication anything was missing.
        """
        resp = await self._get_with_refresh(
            f"{self._base_url}/api/v1{path}", params=params
        )
        data = resp.json()
        if not isinstance(data, list):
            return data

        items: list[Any] = data
        pages = 1
        next_url = self._next_page_url(resp)
        while next_url and pages < self._MAX_PAGES:
            # The next URL carries the original query string (Canvas bakes
            # it into the Link header), so no params are re-sent.
            resp = await self._get_with_refresh(next_url)
            page = resp.json()
            if not isinstance(page, list) or not page:
                break
            items.extend(page)
            pages += 1
            next_url = self._next_page_url(resp)
        return items

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
        """The user's current and upcoming courses, current first.

        Canvas keeps an enrollment "active" until the school concludes the
        term, so a student can have years of finished courses marked
        active, each a ~3 KB object. Returned raw, 40 of them overflowed
        the result budget and the current term was cut off. So each course
        is reduced to the fields the model needs, courses whose term (and
        course) end dates have all passed are dropped, and courses without
        dates are kept at the end. If nothing is left, the ten most
        recently started courses are returned instead.
        """
        raw = await self._api_get(
            "/courses",
            params={"enrollment_state": "active", "include[]": "term", "per_page": 100},
        )
        if not isinstance(raw, list):
            raise ConnectorError("Malformed response from Canvas LMS")
        now = datetime.now(timezone.utc)
        current: list[tuple[datetime, dict[str, Any]]] = []
        upcoming: list[tuple[datetime, dict[str, Any]]] = []
        undated: list[dict[str, Any]] = []
        ended: list[tuple[datetime, dict[str, Any]]] = []
        for course in raw:
            if not isinstance(course, dict) or course.get("access_restricted_by_date"):
                continue
            raw_term = course.get("term")
            term: dict[str, Any] = raw_term if isinstance(raw_term, dict) else {}
            starts = [t for t in (_canvas_time(course.get("start_at")), _canvas_time(term.get("start_at"))) if t]
            ends = [t for t in (_canvas_time(course.get("end_at")), _canvas_time(term.get("end_at"))) if t]
            shaped = _shape_course(course, term, min(starts) if starts else None, max(ends) if ends else None)
            if ends and max(ends) < now:
                ended.append((min(starts) if starts else max(ends), shaped))
            elif starts and min(starts) > now:
                upcoming.append((min(starts), shaped))
            elif starts or ends:
                # Ongoing without a start date sorts after the dated ones.
                current.append((min(starts) if starts else datetime.min.replace(tzinfo=timezone.utc), shaped))
            else:
                undated.append(shaped)
        result = (
            [c for _, c in sorted(current, key=lambda x: x[0], reverse=True)]
            + [c for _, c in sorted(upcoming, key=lambda x: x[0])]
            + undated
        )
        if not result:
            result = [c for _, c in sorted(ended, key=lambda x: x[0], reverse=True)[:10]]
        return result

    async def get_assignments(self, course_id: int | str) -> list[dict[str, Any]]:
        """Fetch assignments for a given course."""
        return await self._api_get(
            f"/courses/{path_segment(course_id)}/assignments",
            params={"per_page": 100, "order_by": "due_at"},
        )

    async def get_grades(self, course_id: int | str) -> list[dict[str, Any]]:
        """Fetch the current user's enrollments (which contain grades) for a course."""
        return await self._api_get(
            f"/courses/{path_segment(course_id)}/enrollments",
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
            f"/courses/{path_segment(course_id)}/assignments/"
            f"{path_segment(assignment_id)}/submissions",
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
            f"/courses/{path_segment(course_id)}/assignments/"
            f"{path_segment(assignment_id)}/submissions",
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


DEFINITION = ConnectorDefinition(
    key="canvas",
    label="Canvas LMS",
    description="Courses, assignments, grades, calendar events and submissions from your school's Canvas.",
    icon="graduation-cap",
    auth=AuthSpec(
        methods=("token",),
        fields=(
            CredentialField(
                "base_url",
                "Canvas URL",
                type="url",
                placeholder="https://yourschool.instructure.com",
                hint="Your school's Canvas address.",
            ),
            CredentialField(
                "access_token",
                "Access token",
                placeholder="Paste your Canvas access token",
                hint="Canvas, Account, Settings, + New access token.",
            ),
            CredentialField(
                "client_id",
                "Developer key client ID (for token renewal)",
                type="text",
                required=False,
                hint="Only needed with a refresh token.",
            ),
            CredentialField(
                "client_secret",
                "Developer key secret (for token renewal)",
                required=False,
                hint="Only needed with a refresh token.",
            ),
            CredentialField(
                "refresh_token",
                "Refresh token",
                required=False,
                hint="Lets Crawler AI renew an expired access token by itself.",
            ),
        ),
        token_auth_method="bearer_token",
        notes="base_url is your school's Canvas instance, e.g. https://myschool.instructure.com",
    ),
    network=NetworkSpec(
        policy_key="canvas",
        hosts={"*.instructure.com": _CANVAS_PATHS},
        # Self-hosted Canvas instances on plain http are accepted today
        # (validate_credentials allows http:// base URLs).
        https_only=False,
        instance_paths=_CANVAS_PATHS,
    ),
    actions=ACTIONS,
    connector_class=CanvasConnector,
    docs_url="https://canvas.instructure.com/doc/api/file.oauth.html",
)
