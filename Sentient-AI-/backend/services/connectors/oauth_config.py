"""Resolves the OAuth client id (and, for Google, the client secret) a
connector's sign-in uses, and the fixed redirect URI the broker sends.

Why it exists: client ids and secrets must never live in source code. They
come from the ``Settings`` attributes an ``OAuthSpec`` names
(``GOOGLE_OAUTH_CLIENT_ID``, ...), loaded from the environment or
backend/.env. One resolver gives the broker routes a single "not configured"
error that names the missing variable. Setting the ids from the Settings
page instead of the environment is not built yet (see SECURITY.md, "Sign-in
coverage").

Connects ``core.config.settings`` to ``services/connectors/oauth.py``. Talks
to no external service.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core import config
from services.connectors.definition import OAuthSpec


class OAuthNotConfigured(Exception):
    """A client id or secret the provider needs is empty on this server.

    The message names the environment variable to set and is safe to show
    to the user (it never contains a value).
    """

    def __init__(self, setting: str, label: str = "") -> None:
        self.setting = setting
        who = f"{label} sign-in" if label else "Sign-in"
        super().__init__(
            f"{who} is not configured on this server. The owner must set "
            f"{setting} in backend/.env and restart."
        )


@dataclass(frozen=True)
class OAuthClient:
    """The public client id and, when the provider needs one, the secret.

    ``repr`` never shows the secret, so logging the object is harmless.
    """

    client_id: str
    client_secret: str = field(default="", repr=False)


def _setting(name: str) -> str:
    return str(getattr(config.settings, name, "") or "").strip()


def resolve_client(spec: OAuthSpec, *, label: str = "") -> OAuthClient:
    """The client pair for *spec*, read from Settings at call time.

    Raises ``OAuthNotConfigured`` naming the first empty setting: the client
    id always, and the secret only when the spec names a secret setting.
    """
    if not spec.client_id_setting:
        raise OAuthNotConfigured("the OAuth client id setting", label)
    client_id = _setting(spec.client_id_setting)
    if not client_id:
        raise OAuthNotConfigured(spec.client_id_setting, label)
    secret = ""
    if spec.client_secret_setting:
        secret = _setting(spec.client_secret_setting)
        if not secret:
            raise OAuthNotConfigured(spec.client_secret_setting, label)
    return OAuthClient(client_id=client_id, client_secret=secret)


def redirect_uri(provider: str) -> str:
    """The exact redirect URI registered with the provider.

    Built only from ``OAUTH_REDIRECT_BASE`` (validated as an origin at
    boot) and the provider segment, never from the incoming request, so a
    forged Host header cannot redirect a code elsewhere.
    """
    base = str(config.settings.OAUTH_REDIRECT_BASE).rstrip("/")
    return f"{base}/api/oauth/callback/{provider}"


def redirect_base_is_loopback() -> bool:
    """True when ``OAUTH_REDIRECT_BASE`` names this machine (``localhost``,
    a ``*.localhost`` name, or a loopback address such as 127.0.0.1).

    A provider can only send a loopback redirect to a browser on the same
    machine as the server, so such a flow cannot be finished by someone
    else. A shared server with a routable base needs the browser binding
    cookie instead (``services/connectors/oauth.py``).
    """
    host = (urlsplit(str(config.settings.OAUTH_REDIRECT_BASE)).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
