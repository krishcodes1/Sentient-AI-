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

from . import canvas_grades
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
        "get_upcoming",
        "Everything due in the next N days across all active Canvas courses, "
        "plus missing and late work, in one call (course, title, type, due_at "
        "in UTC, points, submitted/missing/late, link). Prefer it to "
        "get_assignments per course.",
        ActionCategory.READ,
        _schema(
            days={
                "type": "integer",
                "description": "Days ahead to cover (default 7, at most 30)",
            },
        ),
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
    # Grade math the model must never do itself: canvas_grades computes it
    # from the assignment groups. READ only; what_if never reaches Canvas.
    ToolSpec(
        "grade_whatif",
        "Work out a Canvas course grade exactly as Canvas does (group weights, "
        "drop rules, excused work): the current grade, the grade with the "
        "hypothetical scores in what_if, and the score needed on the ungraded "
        "work to reach target_percent (spread evenly, or on target_assignment). "
        "Use it for every grade calculation and quote its numbers as "
        "estimates, with its assumptions; never compute grades yourself. For "
        "a letter grade, use the user's cutoff or say which one you assumed "
        "(e.g. B+ = 87%). Read-only: nothing is sent to Canvas.",
        ActionCategory.READ,
        _schema(
            course_id={"type": "string", "description": "Numeric Canvas course id from canvas.get_courses (not the course code)", "required": True},
            what_if={
                "type": "array",
                "description": "Hypothetical scores to try; each replaces or fills in one assignment's score",
                "items": {
                    "type": "object",
                    "properties": {
                        "assignment": {
                            "type": "string",
                            "description": "Assignment id or name",
                        },
                        "score": {
                            "type": "number",
                            "description": "Points earned, e.g. 45 for 45/50",
                        },
                        "percent": {
                            "type": "number",
                            "description": "Instead of score: percent of the points, e.g. 90",
                        },
                    },
                    "required": ["assignment"],
                },
            },
            target_percent={
                "type": "number",
                "description": "Course grade to reach, in percent, e.g. 87",
            },
            target_assignment={
                "type": "string",
                "description": "With target_percent: the one assignment (id or name) to solve for; omit to spread it evenly over all ungraded work",
            },
        ),
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
    # Read by the app-event triggers (services/triggers) and offered to the
    # model: compact rows shaped in canvas_activity. Announcements need only
    # courses.read, so existing Canvas rows keep working.
    ToolSpec(
        "get_announcements",
        "Recent announcements in the user's current Canvas courses (or one course), "
        "newest first: course, title, when, author, the text (plain, up to 1500 "
        "characters) and a link.",
        ActionCategory.READ,
        _schema(
            days={"type": "integer", "description": "Days back to cover (default 7, at most 30)"},
            course_id={
                "type": "string",
                "description": "Only this course: numeric id from canvas.get_courses (optional)",
            },
        ),
        required_scope="courses.read",
    ),
    ToolSpec(
        "get_recent_grades",
        "The user's own submissions graded in the last N days across current Canvas "
        "courses (or one course): assignment, course, when graded, score, grade and "
        "points possible.",
        ActionCategory.READ,
        _schema(
            days={"type": "integer", "description": "Days back to cover (default 7, at most 30)"},
            course_id={
                "type": "string",
                "description": "Only this course: numeric id from canvas.get_courses (optional)",
            },
        ),
        required_scope="grades.read",
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
        # Handing in work cannot be taken back and speaks for the student.
        always_confirm=True,
    ),
    # top10:file_extraction: course files, read with the courses.read scope
    # existing rows already hold (no re-grant). list_files falls back to the
    # modules' File items when the course hides its Files page from
    # students; get_file_text reads a file in the sandboxed document reader
    # and returns sections plus a doc_id that files.read continues.
    ToolSpec(
        "list_files",
        "List a Canvas course's files, newest first (id, name, type, size, updated, "
        "locked). Read one with canvas.get_file_text. When the course hides its Files "
        "page, the files linked from its modules are listed instead (source 'modules').",
        ActionCategory.READ,
        _schema(
            course_id={"type": "string", "description": "Numeric Canvas course id from canvas.get_courses (not the course code)", "required": True},
            search={"type": "string", "description": "Words in the file name (2-100 characters), optional"},
            limit={"type": "integer", "description": "How many (1-50, default 20)"},
        ),
        required_scope="courses.read",
        # Not a starter: Canvas already declares the registry's maximum of
        # four (courses, assignments, upcoming, calendar); tools.find
        # reaches it.
    ),
    ToolSpec(
        "get_file_text",
        "Read a Canvas course file (PDF, Word, PowerPoint, Excel, text) as labelled "
        "sections with a doc_id; continue with files.read(doc_id, start=next_start). "
        "Locked files and files over 20 MB are refused.",
        ActionCategory.READ,
        _schema(
            file_id={"type": "string", "description": "Numeric Canvas file id from canvas.list_files", "required": True},
        ),
        required_scope="courses.read",
    ),
)

# /api/v1/ is the Canvas REST surface; /login/oauth2/token is the OAuth
# code-exchange and refresh endpoint. The interactive /login/oauth2/auth
# page is browser-side and stays blocked. Shared by the hosted
# (*.instructure.com) and self-hosted cases, so a self-hosted instance is
# never reachable at paths the hosted one is not. /files/ is a course
# file's download address (canvas.get_file_text; top10:file_extraction),
# which answers with a redirect to Canvas's file storage (redirect_hosts).
_CANVAS_PATHS: tuple[str, ...] = ("/api/v1/", "/login/oauth2/token", "/files/")

# top10:file_extraction: course-file limits and shapes.
_FILES_DEFAULT = 20
_FILES_MAX = 50
_FILE_ID_RE_CHARS = frozenset("0123456789")


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
        "grade_whatif": "grade_whatif",
        "get_calendar_events": "get_calendar_events",
        "get_upcoming": "get_upcoming",
        "get_submissions": "get_submissions",
        "submit_assignment": "submit_assignment",
        # top10:file_extraction
        "list_files": "list_files",
        "get_file_text": "get_file_text",
        "get_announcements": "get_announcements",
        "get_recent_grades": "get_recent_grades",
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

    def _auth_headers(self) -> dict[str, str]:
        """The bearer token for the base helpers (``_request_bytes``, used
        by get_file_text's download): named here, it also counts as a
        credential for the network policy (never sent to a redirect host)
        and is scrubbed from error codes (top10:file_extraction)."""
        return self._headers() if self._access_token else {}

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

    async def grade_whatif(
        self,
        course_id: int | str,
        what_if: Any = None,
        target_percent: Any = None,
        target_assignment: Any = None,
    ) -> dict[str, Any]:
        """Current grade, what-if grade and the score needed for a target,
        worked out by ``canvas_grades`` from the course's assignment groups.

        Read-only: two GETs, and the hypothetical scores exist only as
        arguments; nothing is written back to Canvas. Arguments are checked
        before any request, and the answer is compact numbers rather than
        the raw groups, which would not survive the result budget.
        """
        if isinstance(course_id, bool) or not str(course_id).strip():
            raise ConnectorError("grade_whatif needs a course_id.")
        try:
            request = canvas_grades.parse_request(
                what_if=what_if,
                target_percent=target_percent,
                target_assignment=target_assignment,
            )
        except canvas_grades.GradeInputError as exc:
            raise ConnectorError(str(exc)) from exc
        segment = path_segment(str(course_id).strip())
        # apply_assignment_group_weights lives on the course, not the groups;
        # total_scores adds Canvas's own current score to cross-check against.
        course = await self._api_get(f"/courses/{segment}", params={"include[]": "total_scores"})
        groups = await self._api_get(
            f"/courses/{segment}/assignment_groups",
            params={"include[]": ["assignments", "submission"], "per_page": 100},
        )
        try:
            return canvas_grades.plan(groups, course, request)
        except canvas_grades.GradeInputError as exc:
            raise ConnectorError(str(exc)) from exc

    async def get_calendar_events(self) -> list[dict[str, Any]]:
        """Fetch upcoming calendar events."""
        return await self._api_get(
            "/calendar_events", params={"type": "event", "per_page": 50}
        )

    async def get_upcoming(self, days: Any = None) -> dict[str, Any]:
        """Everything due in the next *days* days across the user's active
        courses, plus missing and late work, as compact rows.

        Two account-wide reads replace a get_assignments call per course:
        the planner (dated items with the user's submission state, read
        from a short lookback so late work shows) and the missing
        submissions list. Both follow pagination through ``_api_get`` and
        take no model-supplied path segment; ``days`` only sets the window.
        Shaping and the size caps live in ``canvas_upcoming``.
        """
        from . import canvas_upcoming as upcoming

        window = upcoming.window_for(days)
        planner = await self._api_get(
            "/planner/items",
            params={
                "start_date": upcoming.iso(window.late_since),
                "end_date": upcoming.iso(window.until),
                "per_page": 100,
            },
        )
        missing = await self._api_get(
            "/users/self/missing_submissions",
            params={"include[]": "course", "per_page": 100},
        )
        return upcoming.summarize(planner, missing, window=window, base_url=self._base_url)

    async def get_announcements(self, days: Any = None, course_id: Any = None) -> dict[str, Any]:
        """Announcements posted in the last *days* days in the user's current
        courses (at most 20, from get_courses) or in *course_id*: one GET
        of /announcements with a context code per course. The arguments are
        checked before any request; shaping and caps live in
        ``canvas_activity``."""
        from . import canvas_activity as activity

        wanted = activity.parse_course_id(course_id)
        span, start = activity.since(days)
        names = activity.course_names(await self.get_courses())
        codes = [wanted] if wanted is not None else list(names)[: activity.MAX_COURSES]
        if not codes:
            return activity.announcements([], names=names, base_url=self._base_url, days=span)
        resp = await self._get_with_refresh(
            f"{self._base_url}/api/v1/announcements",
            params={
                "context_codes[]": [f"course_{code}" for code in codes],
                "start_date": activity.iso(start),
                "per_page": activity.PER_PAGE,
            },
        )
        return activity.announcements(resp.json(), names=names, base_url=self._base_url, days=span)

    async def get_recent_grades(self, days: Any = None, course_id: Any = None) -> dict[str, Any]:
        """The user's own submissions graded in the last *days* days, in
        their current courses (at most 12) or in *course_id*: one
        /students/submissions read per course with ``graded_since`` (a
        student sees only their own). A course the account may not open
        (403, 404) is skipped rather than failing the rest."""
        from . import canvas_activity as activity

        wanted = activity.parse_course_id(course_id)
        span, start = activity.since(days)
        names = activity.course_names(await self.get_courses())
        ids = [wanted] if wanted is not None else list(names)[: activity.MAX_GRADE_COURSES]
        rows: list[dict[str, Any]] = []
        for course in ids:
            try:
                raw = await self._api_get(
                    f"/courses/{path_segment(course)}/students/submissions",
                    params={
                        "graded_since": activity.iso(start),
                        "include[]": "assignment",
                        "per_page": activity.PER_PAGE,
                    },
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (403, 404):
                    continue
                raise
            rows.extend(activity.grade_rows(course, names.get(course, ""), raw, base_url=self._base_url))
        return activity.grades(rows, days=span, courses=len(ids))

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

    # -- Course files (top10:file_extraction) --------------------------------

    @staticmethod
    def _numeric_id(value: Any, field: str) -> str:
        text = str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
        if not text or len(text) > 20 or not set(text) <= _FILE_ID_RE_CHARS:
            raise ConnectorError(f"'{field}' must be a numeric Canvas id.")
        return text

    @staticmethod
    def _shape_file(raw: dict[str, Any]) -> dict[str, Any]:
        shaped: dict[str, Any] = {
            "id": raw.get("id"),
            "name": str(raw.get("display_name") or raw.get("filename") or "")[:200],
            "content_type": str(raw.get("content-type") or "")[:100] or None,
            "size": raw.get("size") if isinstance(raw.get("size"), int) else None,
            "updated_at": raw.get("updated_at"),
            "folder_id": raw.get("folder_id"),
        }
        if raw.get("locked_for_user") or raw.get("locked"):
            shaped["locked"] = True
        if raw.get("hidden") or raw.get("hidden_for_user"):
            shaped["hidden"] = True
        return {k: v for k, v in shaped.items() if v is not None}

    async def list_files(
        self, course_id: Any, search: Any = None, limit: Any = None
    ) -> dict[str, Any]:
        """A course's files, newest first. A course that hides its Files page
        from students answers 401/403 there; the File items of its modules
        are listed instead (``source: "modules"``)."""
        cid = self._numeric_id(course_id, "course_id")
        try:
            top = max(1, min(int(limit), _FILES_MAX)) if limit is not None else _FILES_DEFAULT
        except (TypeError, ValueError):
            raise ConnectorError("'limit' must be a whole number from 1 to 50.") from None
        params: dict[str, Any] = {"sort": "updated_at", "order": "desc", "per_page": top}
        if search is not None:
            words = " ".join(str(search).split())
            if not 2 <= len(words) <= 100:
                raise ConnectorError("'search' must be 2 to 100 characters.")
            params["search_term"] = words
        try:
            resp = await self._get_with_refresh(
                f"{self._base_url}/api/v1/courses/{path_segment(cid)}/files", params=params
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in (401, 403):
                raise
            return await self._files_from_modules(cid, top, params.get("search_term"))
        raw = resp.json()
        if not isinstance(raw, list):
            raise ConnectorError("Malformed response from Canvas LMS")
        files = [self._shape_file(f) for f in raw if isinstance(f, dict)][:top]
        return {
            "course_id": cid,
            "source": "files",
            "files": files,
            "count": len(files),
            "hint": "Read one with canvas.get_file_text(file_id).",
        }

    async def _files_from_modules(
        self, cid: str, top: int, search: Optional[str]
    ) -> dict[str, Any]:
        modules = await self._api_get(
            f"/courses/{path_segment(cid)}/modules", params={"include[]": "items", "per_page": 50}
        )
        files: list[dict[str, Any]] = []
        needle = (search or "").lower()
        for module in modules if isinstance(modules, list) else []:
            if not isinstance(module, dict):
                continue
            for item in module.get("items") or []:
                if not isinstance(item, dict) or item.get("type") != "File":
                    continue
                title = str(item.get("title") or "")[:200]
                if needle and needle not in title.lower():
                    continue
                if item.get("content_id") is None:
                    continue
                files.append({"id": item.get("content_id"), "name": title, "module": str(module.get("name") or "")[:100]})
                if len(files) >= top:
                    break
            if len(files) >= top:
                break
        return {
            "course_id": cid,
            "source": "modules",
            "files": files,
            "count": len(files),
            "hint": (
                "This course hides its Files page; these are the files its modules link to. "
                "Read one with canvas.get_file_text(file_id)."
            ),
        }

    async def get_file_text(self, file_id: Any) -> dict[str, Any]:
        """One course file read as a document. Refused before any download
        when it is locked for the user, larger than 20 MB, or its download
        address is not this Canvas's own /files/ path; the download then
        follows Canvas's redirect to its file storage (redirect_hosts: GET
        only, never with the token)."""
        from .documents import MAX_DOCUMENT_BYTES, read_connector_document

        fid = self._numeric_id(file_id, "file_id")
        meta = await self._api_get(f"/files/{path_segment(fid)}")
        if not isinstance(meta, dict):
            raise ConnectorError("Malformed response from Canvas LMS")
        name = str(meta.get("display_name") or meta.get("filename") or f"file-{fid}")[:200]
        if meta.get("locked_for_user"):
            raise ConnectorError("This file is locked for you on Canvas, so it cannot be read.")
        size = meta.get("size")
        if isinstance(size, int) and size > MAX_DOCUMENT_BYTES:
            from services.files import messages as file_messages

            raise ConnectorError(file_messages.too_large(size, MAX_DOCUMENT_BYTES))
        url = meta.get("url")
        if not isinstance(url, str) or not url.startswith(f"{self._base_url}/files/"):
            raise ConnectorError(
                "Canvas did not give a download address on this Canvas instance, so the "
                "file was not downloaded."
            )
        mime = str(meta.get("content-type") or "")[:100] or None
        document = await read_connector_document(
            download=lambda cap: self._request_bytes("GET", url, max_bytes=cap, follow_redirects=True),
            name=name,
            mime=mime,
            source="canvas",
            size=size if isinstance(size, int) else None,
        )
        return {"file_id": fid, "content_type": mime, "size": size, **document}

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
        # A course file's /files/ address redirects to Canvas's file storage
        # (InstFS, or S3 on older instances): GET only, never with our
        # Authorization header (top10:file_extraction).
        redirect_hosts={
            "*.inscloudgate.net": ("/files/",),
            "instructure-uploads*.s3.amazonaws.com": ("/",),
        },
    ),
    actions=ACTIONS,
    connector_class=CanvasConnector,
    docs_url="https://canvas.instructure.com/doc/api/file.oauth.html",
)
