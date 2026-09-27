"""Defines the GitHub connector: repositories, files, issues, pull requests,
Actions runs, notifications, releases and gists through the GitHub REST API.

Why it exists: spec section 5.2 of the connectors design. This module
assembles the action mixins in ``services/connectors/github_api/`` into
``GitHubConnector`` and declares its ``DEFINITION`` (actions, sign-in,
network reach), which ``services/connectors/registry.py`` turns into the
tool catalog, credential rules, network allowlist and permission rows.

Connects to: the GitHub REST API (api.github.com), GitHub's OAuth device flow
(github.com/login/...) through the shared OAuth broker, and the Azure blob
hosts that serve Actions job logs. Depends on ``services.connectors.base``
(HTTP helpers, errors), ``services.connectors.definition`` and the
``github_api`` mixins.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .base import AuthenticationError, ConnectorError
from .definition import (
    AuthSpec,
    ConnectorDefinition,
    CredentialField,
    NetworkSpec,
    OAuthSpec,
    ToolSpec,
)
from .github_api.activity import ACTIVITY_ACTIONS, ActivityMixin
from .github_api.common import API, API_VERSION
from .github_api.issues import ISSUE_ACTIONS, IssuesMixin
from .github_api.pulls import PULL_ACTIONS, PullsMixin
from .github_api.repos import REPO_ACTIONS, ReposMixin
from .github_api.workflows import WORKFLOW_ACTIONS, WorkflowsMixin

ACTIONS: tuple[ToolSpec, ...] = (
    REPO_ACTIONS + ISSUE_ACTIONS + PULL_ACTIONS + WORKFLOW_ACTIONS + ACTIVITY_ACTIONS
)

# A pasted token: printable ASCII, no whitespace (header injection guard).
_TOKEN_RE = re.compile(r"^[\x21-\x7e]{10,400}$")


class GitHubConnector(ReposMixin, IssuesMixin, PullsMixin, WorkflowsMixin, ActivityMixin):
    """Connector for the GitHub REST API (bearer token: fine-grained PAT,
    classic PAT or a device-flow OAuth token)."""

    # The dispatch allow-map comes from ACTIONS, so they cannot drift apart.
    _ACTIONS = frozenset(spec.action for spec in ACTIONS)

    def __init__(self, timeout_s: Optional[float] = None) -> None:
        # GitHub allows 5,000 authenticated requests an hour; 60 a minute
        # per connector keeps a runaway loop well inside that.
        super().__init__(timeout_s=timeout_s, rate_limit=60)
        self._token: Optional[str] = None

    @property
    def name(self) -> str:
        return "GitHub"

    @property
    def connector_type(self) -> str:
        return "developer"

    @property
    def required_scopes(self) -> list[str]:
        return sorted({spec.required_scope for spec in ACTIONS if spec.required_scope})

    @classmethod
    def validate_credentials(cls, credentials: dict[str, Any]) -> list[str]:
        token = credentials.get("access_token")
        if isinstance(token, str) and token.strip() and not _TOKEN_RE.fullmatch(token.strip()):
            return [
                "access_token does not look like a GitHub token (no spaces, 10 to 400 characters)."
            ]
        return []

    async def authenticate(self, credentials: dict[str, Any]) -> bool:
        """Store the token. No network here; health_check proves it works."""
        token = str(credentials.get("access_token") or "").strip()
        if not token:
            raise AuthenticationError(
                "GitHub needs an access_token. Reconnect GitHub in Connectors."
            )
        if not _TOKEN_RE.fullmatch(token):
            raise AuthenticationError(
                "The stored GitHub token is malformed. Reconnect GitHub in Connectors."
            )
        self._token = token
        # A device-flow grant records its scopes; a pasted token does not.
        if credentials.get("oauth_provider") == "github":
            granted = credentials.get("granted_scopes")
            scopes = granted if isinstance(granted, (list, tuple)) else ()
            self._oauth_scopes = frozenset(s for s in scopes if isinstance(s, str))
        else:
            self._oauth_scopes = None
        self._authenticated = True
        return True

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def _static_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "Crawler-AI",
        }

    async def _execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self._dispatch(action, params)

    async def health_check(self) -> bool:
        try:
            await self._request("GET", f"{API}/user")
            return True
        except ConnectorError:
            return False

    async def revoke(self) -> bool:
        # GitHub's only revoke endpoint (DELETE /applications/{client_id}/grant)
        # authenticates with the OAuth app's client secret, which Crawler does
        # not hold (owner decision 5: public client ids only). Device-flow
        # tokens do not expire unless the app opts in, so the user revokes
        # them at github.com/settings/applications; a pasted PAT is deleted
        # at github.com/settings/tokens.
        return False


# GitHub OAuth scopes are coarse: "repo" is read AND write on every private
# repository the user can reach, "notifications" and "gist" cover their
# areas, and "read:org" lets org repositories and teams be listed. Crawler's
# catalog scopes still gate every action (the executor checks them against
# the scopes granted on the connector row), so a user who grants only
# repo.read gets no write tools even though the GitHub token could write.
# "workflow" (needed only to change files under .github/workflows/) is
# deliberately never requested: workflow files run with the repository's
# secrets. For a device-flow token, put_file refuses such paths up front
# (GitHubApiBase._check_workflow_path) with a message saying why, instead of
# asking for approval of a call GitHub would reject. A fine-grained personal
# access token limited to chosen repositories and permissions (including
# Workflows when wanted) is the least-privilege option.
_SCOPE_MAP: dict[str, tuple[str, ...]] = {
    "repo.read": ("repo", "read:org"),
    "repo.write": ("repo",),
    "repo.create": ("repo",),
    "issues.read": ("repo",),
    "issues.write": ("repo",),
    "pulls.read": ("repo",),
    "pulls.write": ("repo",),
    "actions.read": ("repo",),
    "actions.write": ("repo",),
    "releases.read": ("repo",),
    "releases.write": ("repo",),
    "notifications.read": ("notifications",),
    "notifications.write": ("notifications",),
    "gists.write": ("gist",),
}


DEFINITION = ConnectorDefinition(
    key="github",
    label="GitHub",
    description=(
        "Repositories, files, issues, pull requests, Actions runs and logs, "
        "notifications, releases and gists."
    ),
    icon="github",
    auth=AuthSpec(
        methods=("device", "token"),
        fields=(
            CredentialField(
                "access_token",
                "Fine-grained personal access token",
                placeholder="github_pat_...",
                hint=(
                    "GitHub, Settings, Developer settings, Fine-grained tokens. Pick only the "
                    "repositories Crawler should reach and the least permissions you need: "
                    "Contents, Issues, Pull requests and Actions (read-only unless you want "
                    "Crawler to make changes), plus Metadata."
                ),
            ),
        ),
        oauth=OAuthSpec(
            provider="github",
            token_url="https://github.com/login/oauth/access_token",
            device_code_url="https://github.com/login/device/code",
            client_id_setting="GITHUB_OAUTH_CLIENT_ID",
            scope_map=_SCOPE_MAP,
        ),
        token_auth_method="bearer_token",
        notes=(
            "Sign in with a device code, or paste a fine-grained personal access token. "
            "Notifications need the device sign-in or a classic token."
        ),
    ),
    network=NetworkSpec(
        policy_key="github",
        hosts={
            "api.github.com": (
                "/user",
                "/issues",
                "/orgs/",
                "/repos/",
                "/search/",
                "/notifications",
                "/gists",
            ),
            "github.com": ("/login/device/code", "/login/oauth/access_token"),
        },
        https_only=True,
        # Actions job logs: GET .../actions/jobs/<id>/logs answers 302 to a
        # pre-signed URL on GitHub's results storage (Azure blob accounts
        # productionresultssa0..N) or, for older runs, the legacy pipelines
        # host. Reachable only by GET without our credentials.
        redirect_hosts={
            "productionresultssa*.blob.core.windows.net": ("/actions-results/",),
            "pipelines.actions.githubusercontent.com": ("/",),
        },
    ),
    actions=ACTIONS,
    connector_class=GitHubConnector,
    docs_url="https://github.com/settings/personal-access-tokens/new",
)
