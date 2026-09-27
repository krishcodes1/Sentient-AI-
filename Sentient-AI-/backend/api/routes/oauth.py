"""Serves the /oauth API: start a connector sign-in in the browser, receive the
provider's redirect, start a device-code sign-in, and report a flow's status
to the Connectors page, which polls it every few seconds.

Why it exists: the callback is a browser redirect that cannot carry the
user's bearer token, so it is the one connector route without
authentication; the stored flow row (found by the HMAC of ``state``) is what
binds it to the user, and on a server whose redirect base is not loopback a
cookie set by the start response binds it to the starting browser too. The
page it returns is static HTML with no script, the
same shape for every failure, and never echoes the code or state. The other
three routes require the signed-in user and only ever show a user their own
flows.

Connects the frontend Connectors page to ``services/connectors/oauth.py``
(the broker, which talks to the providers) and ``oauth_config`` (client ids).
The middleware rate-limits the callback like the login routes and sends it
with ``Referrer-Policy: no-referrer``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Callable, Optional
from urllib.parse import urlsplit

import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import async_session
from core.validation import SafeStr
from models.connector import PermissionTier
from models.user import User
from services.auth import get_current_user
from services.connectors import oauth as broker
from services.connectors.definition import ConnectorDefinition
from services.connectors.oauth_config import OAuthNotConfigured, redirect_uri

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/oauth", tags=["oauth"])

# Provider segments are registry names. A segment that does not match this
# shape is a 422 before any lookup (and never reaches a log line unbounded);
# a well-formed name that is not a sign-in provider is a 404.
_PROVIDER_PATTERN = r"^[a-z][a-z0-9_]{1,31}$"
_MAX_QUERY_VALUE = 4096


def session_factory_dependency() -> Callable[[], AsyncSession]:
    """The session factory the broker opens its own transactions with.

    The broker never holds a request session across a provider call, and
    the device poller outlives the request. Tests override this.
    """
    return async_session


# A catalog scope name (``gmail.read``); bounded so a rejected one is safe
# to echo in the 422.
_ScopeName = Annotated[SafeStr, StringConstraints(min_length=1, max_length=128)]


class OAuthDraftRequest(BaseModel):
    """The connector to create (or, with ``connector_id``, to reconnect)."""

    display_name: Optional[SafeStr] = Field(default=None, min_length=1, max_length=255)
    granted_scopes: Optional[list[_ScopeName]] = Field(default=None, max_length=64)
    permission_tier: Optional[PermissionTier] = None
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1, le=600)
    connector_id: Optional[uuid.UUID] = None

    def to_draft(self) -> broker.FlowDraft:
        return broker.FlowDraft(
            display_name=self.display_name,
            granted_scopes=tuple(self.granted_scopes) if self.granted_scopes else None,
            permission_tier=self.permission_tier,
            rate_limit_per_minute=self.rate_limit_per_minute,
            connector_id=self.connector_id,
        )


class StartResponse(BaseModel):
    flow_id: uuid.UUID
    authorization_url: str
    expires_at: datetime


class DeviceResponse(BaseModel):
    flow_id: uuid.UUID
    user_code: str
    verification_uri: str
    expires_at: datetime
    interval: int


def _definition_or_404(provider: str) -> ConnectorDefinition:
    definition = broker.oauth_definition(provider)
    if definition is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown sign-in provider")
    return definition


def _binding_cookie_args(provider: str) -> dict:
    """Where the browser binding cookie lives: only the callback path of the
    redirect URI, HTTPS-only when the redirect base is HTTPS, never readable
    by script, and sent on the provider's top-level redirect (Lax)."""
    target = urlsplit(redirect_uri(provider))
    return {
        "path": target.path,
        "secure": target.scheme == "https",
        "httponly": True,
        "samesite": "lax",
    }


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, OAuthNotConfigured):
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    if isinstance(exc, broker.OAuthFlowError):
        return HTTPException(status_code=exc.status_code, detail=exc.detail)
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="The provider did not start the sign-in. Try again shortly.",
    )


@router.post("/{provider}/start", response_model=StartResponse)
async def start_oauth(
    body: OAuthDraftRequest,
    response: Response,
    provider: str = Path(pattern=_PROVIDER_PATTERN),
    current_user: User = Depends(get_current_user),
    session_factory: Callable[[], AsyncSession] = Depends(session_factory_dependency),
) -> StartResponse:
    """Create a sign-in flow and return the provider's consent URL, which the
    frontend opens in the system browser."""
    definition = _definition_or_404(provider)
    try:
        started = await broker.start_authorization(
            session_factory,
            user_id=current_user.id,
            definition=definition,
            draft=body.to_draft(),
        )
    except (OAuthNotConfigured, broker.OAuthFlowError) as exc:
        raise _http_error(exc) from None
    if started.binding is not None:
        response.set_cookie(
            started.binding.name,
            started.binding.value,
            max_age=int(broker.FLOW_TTL.total_seconds()),
            **_binding_cookie_args(provider),
        )
    return StartResponse(
        flow_id=started.flow_id,
        authorization_url=started.authorization_url,
        expires_at=started.expires_at,
    )


@router.post("/{provider}/device", response_model=DeviceResponse)
async def start_device(
    body: OAuthDraftRequest,
    provider: str = Path(pattern=_PROVIDER_PATTERN),
    current_user: User = Depends(get_current_user),
    session_factory: Callable[[], AsyncSession] = Depends(session_factory_dependency),
) -> DeviceResponse:
    """Start a device-code sign-in: the user types ``user_code`` at
    ``verification_uri``; the backend polls the provider in the background
    and the UI polls ``/status``."""
    definition = _definition_or_404(provider)
    try:
        started = await broker.start_device_flow(
            session_factory,
            user_id=current_user.id,
            definition=definition,
            draft=body.to_draft(),
        )
    except (OAuthNotConfigured, broker.OAuthFlowError) as exc:
        raise _http_error(exc) from None
    except broker.TokenEndpointError as exc:
        logger.warning("oauth_device_start_failed", provider=provider, code=exc.code, status=exc.status)
        raise _http_error(exc) from None
    return DeviceResponse(
        flow_id=started.flow_id,
        user_code=started.user_code,
        verification_uri=started.verification_uri,
        expires_at=started.expires_at,
        interval=started.interval,
    )


@router.get("/{provider}/status")
async def oauth_status(
    provider: str = Path(pattern=_PROVIDER_PATTERN),
    flow: str = Query(..., max_length=64),
    current_user: User = Depends(get_current_user),
    session_factory: Callable[[], AsyncSession] = Depends(session_factory_dependency),
) -> dict:
    """``{status, connector_id?, error?}`` plus the device code fields for a
    device flow. 404 for a flow that is not the caller's."""
    _definition_or_404(provider)
    try:
        flow_id = uuid.UUID(flow)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sign-in not found") from None
    body = await broker.flow_status(
        session_factory, user_id=current_user.id, provider=provider, flow_id=flow_id
    )
    if body is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sign-in not found")
    return body


# ---------------------------------------------------------------------------
# Callback page
# ---------------------------------------------------------------------------

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<style>
body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #0f1115;
  color: #e6e8eb; display: flex; align-items: center; justify-content: center;
  min-height: 100vh; margin: 0; }}
main {{ max-width: 28rem; padding: 2rem; border-radius: 12px; background: #181b21;
  border: 1px solid #2a2f38; text-align: center; }}
h1 {{ font-size: 1.25rem; margin: 0 0 0.75rem; }}
p {{ margin: 0; line-height: 1.5; color: #b4b9c2; }}
</style>
</head>
<body>
<main>
<h1>{title}</h1>
<p>{message}</p>
</main>
</body>
</html>
"""

SUCCESS_PAGE = _PAGE.format(
    title="Connected",
    message="Crawler AI is connected. You can close this tab and go back to the app.",
)
FAILURE_PAGE = _PAGE.format(
    title="Sign-in did not complete",
    message=(
        "Crawler AI could not finish connecting. Close this tab and start again "
        "from Connectors in the app."
    ),
)

_PAGE_HEADERS = {"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}


def _page(success: bool, *, status_code: Optional[int] = None) -> HTMLResponse:
    """The success page (200) or THE failure page (400, or 404 for an
    unknown provider): one body for every failure, so the page reveals
    nothing about why."""
    default = status.HTTP_200_OK if success else status.HTTP_400_BAD_REQUEST
    return HTMLResponse(
        SUCCESS_PAGE if success else FAILURE_PAGE,
        status_code=status_code or default,
        headers=_PAGE_HEADERS,
    )


def _query_value(request: Request, name: str) -> Optional[str]:
    """One query value, or None when absent, repeated or oversized. Read by
    hand so a malformed redirect still gets the HTML page, not a JSON 422."""
    values = request.query_params.getlist(name)
    if len(values) != 1 or len(values[0]) > _MAX_QUERY_VALUE:
        return None
    return values[0]


@router.get("/callback/{provider}", response_class=HTMLResponse, include_in_schema=False)
async def oauth_callback(
    request: Request,
    provider: str,
    session_factory: Callable[[], AsyncSession] = Depends(session_factory_dependency),
) -> HTMLResponse:
    """Where the provider sends the browser back. No bearer token: the
    ``state`` row binds the redirect to the user who started the flow, and
    the binding cookie (when required) to the browser that started it."""
    if broker.oauth_definition(provider) is None:
        return _page(False, status_code=status.HTTP_404_NOT_FOUND)
    error = _query_value(request, "error")
    state = _query_value(request, "state")
    try:
        ok = await broker.complete_callback(
            session_factory,
            provider=provider,
            code=_query_value(request, "code"),
            state=state,
            provider_error=error if error is not None else (
                "invalid_request" if "error" in request.query_params else None
            ),
            cookies=request.cookies,
        )
    except Exception as exc:  # noqa: BLE001 - the browser always gets the page
        logger.error("oauth_callback_failed", provider=provider[:32], error_type=type(exc).__name__)
        ok = False
    page = _page(ok)
    if ok and state:
        # The flow is complete, so its binding cookie is spent. A failed
        # callback leaves it to expire with the flow (10 minutes).
        name = broker.browser_binding(state).name
        if name in request.cookies:
            page.delete_cookie(name, **_binding_cookie_args(provider))
    return page
