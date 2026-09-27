"""Tests for the GitHub connector's shared behaviour: the declaration, token
handling, headers, the failure matrix, rate limits, the network allowlist,
token hygiene, hostile payloads and the real tool pipeline.

Why it exists: spec section 4.7 requires behavioural, failure and
security tests for every connector. The per-area action tests live in the
sibling ``test_github_*.py`` files and import ``make_connector`` from here.

Exercises ``services/connectors/github.py`` through ``httpx.MockTransport``
only (no network, no real credentials); the pipeline section goes through
``build_tools``, ``RuntimePermissionAdapter`` and ``ConnectorToolExecutor``
with the real factory.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

import httpx
import pytest

import core.network_security as netsec
from services.agent.tool_registry import (
    ConnectorSpec,
    ConnectorToolExecutor,
    RuntimePermissionAdapter,
    build_tools,
)
from services.connectors import factory, registry
from services.connectors.base import (
    AuthenticationError,
    ConnectorError,
    RateLimitExceededError,
    UserConfirmationRequired,
)
from services.connectors.github import ACTIONS, DEFINITION, GitHubConnector
from services.connectors.registry import validate_registry

TOKEN = "ghp_" + "test0000000000000000000000000000000000"  # obviously fake, split for scanners
API = "https://api.github.com"
Handler = Callable[[httpx.Request], httpx.Response]


def make_connector(handler: Handler) -> tuple[GitHubConnector, list[httpx.Request]]:
    """An authenticated connector whose HTTP goes to *handler*; records requests."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    connector = GitHubConnector()
    connector._authenticated = True
    connector._token = TOKEN
    connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(recording))

    async def no_sleep(_seconds: float) -> None:
        return None

    connector._sleep = no_sleep
    return connector, seen


def ok(payload: Any, status: int = 200, **headers: str) -> Handler:
    return lambda request: httpx.Response(status, json=payload, headers=headers)


def body_of(request: httpx.Request) -> Any:
    return json.loads(request.content)


# ---------------------------------------------------------------------------
# Declaration
# ---------------------------------------------------------------------------


def test_definition_passes_registry_validation():
    assert validate_registry([DEFINITION]) == []


def test_github_is_registered_with_its_network_policy():
    assert registry.get_definition("github") is DEFINITION
    assert registry.definition_for_provider("github") is DEFINITION
    policy = netsec.DEFAULT_POLICIES["github"]
    assert policy.https_only is True
    assert "productionresultssa*.blob.core.windows.net" in policy.redirect_hosts


def test_action_names_match_the_spec_table():
    expected = {
        "list_repos",
        "get_repo",
        "get_file",
        "list_tree",
        "search_code",
        "list_branches",
        "list_commits",
        "compare",
        "create_repo",
        "create_branch",
        "put_file",
        "delete_branch",
        "list_issues",
        "get_issue",
        "search_issues",
        "list_comments",
        "create_issue",
        "comment",
        "update_issue",
        "list_prs",
        "get_pr",
        "get_pr_diff",
        "get_pr_checks",
        "list_reviews",
        "create_pr",
        "review_pr",
        "request_reviewers",
        "merge_pr",
        "list_runs",
        "get_run",
        "get_failed_logs",
        "rerun_failed_jobs",
        "dispatch_workflow",
        "cancel_run",
        "list_notifications",
        "list_releases",
        "get_release",
        "mark_notification_read",
        "create_release",
        "publish_release",
        "create_gist",
    }
    assert {a.action for a in ACTIONS} == expected
    assert "delete_repo" not in expected


def test_categories_always_confirm_and_starters():
    by_name = {a.action: a for a in ACTIONS}
    always = {a.action for a in ACTIONS if a.always_confirm}
    assert always == {
        "put_file",
        "delete_branch",
        "comment",
        "review_pr",
        "merge_pr",
        "dispatch_workflow",
        "cancel_run",
        "publish_release",
    }
    assert {a.action for a in ACTIONS if a.category.value == "execute"} == {
        "rerun_failed_jobs",
        "dispatch_workflow",
    }
    assert {a.action for a in ACTIONS if a.category.value == "delete"} == {
        "delete_branch",
        "cancel_run",
    }
    starters = [a for a in ACTIONS if a.starter]
    assert 2 <= len(starters) <= 4
    assert all(a.category.value == "read" for a in starters)
    assert by_name["list_issues"].starter


def test_oauth_spec_maps_every_catalog_scope_to_minimal_classic_scopes():
    oauth = DEFINITION.auth.oauth
    assert oauth is not None
    assert DEFINITION.auth.methods == ("device", "token")
    assert oauth.device_code_url == "https://github.com/login/device/code"
    assert oauth.token_url == "https://github.com/login/oauth/access_token"
    assert oauth.client_id_setting == "GITHUB_OAUTH_CLIENT_ID"
    assert set(oauth.scope_map) == {a.required_scope for a in ACTIONS}
    assert oauth.provider_scopes(["notifications.read"]) == ("notifications",)
    assert oauth.provider_scopes(["gists.write"]) == ("gist",)
    assert "workflow" not in oauth.provider_scopes(list(oauth.scope_map))
    field = DEFINITION.auth.fields[0]
    assert (field.key, field.type, field.required) == ("access_token", "password", True)


def test_no_dashes_in_user_facing_strings():
    texts = [a.description for a in ACTIONS] + [
        DEFINITION.description,
        DEFINITION.auth.notes,
        DEFINITION.auth.fields[0].hint,
    ]
    for text in texts:
        assert chr(0x2014) not in text and chr(0x2013) not in text


# ---------------------------------------------------------------------------
# Token handling and headers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_stores_the_token_without_network():
    connector = GitHubConnector()
    assert await connector.authenticate({"access_token": f"  {TOKEN}  "}) is True
    assert connector._auth_headers() == {"Authorization": f"Bearer {TOKEN}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("creds", [{}, {"access_token": ""}, {"access_token": "   "}])
async def test_authenticate_requires_a_token(creds):
    with pytest.raises(AuthenticationError, match="Reconnect GitHub"):
        await GitHubConnector().authenticate(creds)


@pytest.mark.asyncio
async def test_authenticate_refuses_a_token_with_whitespace_inside():
    with pytest.raises(AuthenticationError) as exc:
        await GitHubConnector().authenticate({"access_token": "ghp_abc def\r\nX-Evil: 1"})
    assert "ghp_abc" not in str(exc.value)


def test_validate_credentials_flags_malformed_tokens_without_echoing_them():
    assert GitHubConnector.validate_credentials({"access_token": TOKEN}) == []
    problems = GitHubConnector.validate_credentials({"access_token": "ghp_bad token"})
    assert problems and "ghp_bad" not in problems[0]


@pytest.mark.asyncio
async def test_every_request_carries_token_and_version_headers():
    connector, seen = make_connector(ok({"login": "octo"}))
    assert await connector.health_check() is True
    (request,) = seen
    assert (request.method, request.url.host, request.url.raw_path) == (
        "GET",
        "api.github.com",
        b"/user",
    )
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert request.headers["Accept"] == "application/vnd.github+json"
    assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert connector._static_headers().keys().isdisjoint({"Authorization"})


@pytest.mark.asyncio
async def test_health_check_is_false_on_any_connector_error():
    connector, seen = make_connector(ok({"message": "Bad credentials"}, status=401))
    assert await connector.health_check() is False
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_revoke_returns_false_without_any_request():
    connector, seen = make_connector(ok({}))
    assert await connector.revoke() is False
    assert seen == []


@pytest.mark.asyncio
async def test_dispatch_refuses_unknown_and_private_actions():
    connector, seen = make_connector(ok({}))
    for action in ("delete_repo", "_request", "_commit_sha", "health_check"):
        with pytest.raises(ConnectorError, match="Unknown GitHub action"):
            await connector.execute(action, {})
    assert seen == []


@pytest.mark.asyncio
async def test_list_results_are_wrapped_as_items_and_count():
    connector, _ = make_connector(ok([{"full_name": "o/r"}]))
    response = await connector.execute("list_repos", {})
    assert response.data == {"items": [{"full_name": "o/r"}], "count": 1}


# ---------------------------------------------------------------------------
# Failure matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_401_asks_to_reconnect_and_never_echoes_the_body_or_token():
    echo = {"message": f"Bad credentials for {TOKEN}", "error": TOKEN}
    connector, _ = make_connector(ok(echo, status=401))
    with pytest.raises(AuthenticationError) as exc:
        await connector.get_repo("o", "r")
    message = str(exc.value)
    assert "HTTP 401 from GitHub" in message and "Reconnect GitHub" in message
    assert TOKEN not in message and "Bad credentials" not in message


@pytest.mark.asyncio
async def test_403_missing_permission_is_an_authentication_error():
    connector, seen = make_connector(
        ok(
            {"message": "Resource not accessible by personal access token"},
            status=403,
            **{"X-Accepted-GitHub-Permissions": "issues=write"},
        )
    )
    with pytest.raises(AuthenticationError, match="missing permission or scope"):
        await connector.create_issue("o", "r", "t", user_confirmed=True)
    assert len(seen) == 1  # a plain 403 is never retried


@pytest.mark.asyncio
async def test_404_is_not_found():
    connector, _ = make_connector(ok({"message": "Not Found"}, status=404))
    with pytest.raises(ConnectorError, match="HTTP 404 from GitHub: not found"):
        await connector.get_issue("o", "r", 7)


@pytest.mark.asyncio
async def test_409_merge_conflict_is_reported():
    connector, seen = make_connector(ok({"message": "Head branch was modified"}, status=409))
    with pytest.raises(ConnectorError, match="HTTP 409 from GitHub: conflict"):
        await connector.merge_pr("o", "r", 3, user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_429_with_short_retry_after_is_retried_once():
    replies = [httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(200, json=[])]
    connector, seen = make_connector(lambda r: replies.pop(0))
    assert await connector.list_repos() == []
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_429_with_long_retry_after_is_not_retried():
    connector, seen = make_connector(ok({}, status=429, **{"Retry-After": "120"}))
    with pytest.raises(RateLimitExceededError, match="Retry after 120 s"):
        await connector.list_repos()
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_secondary_rate_limit_403_with_retry_after_is_retried_once():
    replies = [
        httpx.Response(403, headers={"Retry-After": "3"}, json={"message": "secondary rate limit"}),
        httpx.Response(200, json=[]),
    ]
    connector, seen = make_connector(lambda r: replies.pop(0))
    assert await connector.list_repos() == []
    assert len(seen) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 429])
async def test_primary_rate_limit_names_the_reset_time(status):
    reset = int(time.time()) + 1800
    connector, seen = make_connector(
        ok(
            {"message": "API rate limit exceeded"},
            status=status,
            **{"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)},
        )
    )
    with pytest.raises(RateLimitExceededError) as exc:
        await connector.list_repos()
    message = str(exc.value)
    assert "resets at" in message and "UTC" in message and "in about 30 min" in message
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_primary_rate_limit_without_reset_header_is_still_clear():
    connector, _ = make_connector(ok({}, status=403, **{"x-ratelimit-remaining": "0"}))
    with pytest.raises(RateLimitExceededError, match="did not say when it resets"):
        await connector.list_repos()


@pytest.mark.asyncio
async def test_primary_rate_limit_resetting_within_seconds_is_retried_once():
    reset = int(time.time()) + 3
    replies = [
        httpx.Response(
            403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)}
        ),
        httpx.Response(200, json=[]),
    ]
    connector, seen = make_connector(lambda r: replies.pop(0))
    assert await connector.list_repos() == []
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_500_is_a_provider_error_and_not_retried():
    connector, seen = make_connector(ok({"message": "boom"}, status=500))
    with pytest.raises(ConnectorError, match="provider error"):
        await connector.list_repos()
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_502_on_a_read_is_retried_once():
    replies = [httpx.Response(502), httpx.Response(200, json=[])]
    connector, seen = make_connector(lambda r: replies.pop(0))
    assert await connector.list_repos() == []
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_502_on_a_post_is_not_retried():
    connector, seen = make_connector(lambda r: httpx.Response(502))
    with pytest.raises(ConnectorError):
        await connector.comment("o", "r", 1, "hi", user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_timeout_is_a_clean_connector_error():
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    connector, _ = make_connector(slow)
    with pytest.raises(ConnectorError, match="timed out") as exc:
        await connector.get_repo("o", "r")
    assert TOKEN not in str(exc.value)


@pytest.mark.asyncio
async def test_malformed_json_is_a_connector_error():
    connector, _ = make_connector(lambda r: httpx.Response(200, content=b"<html>oops"))
    with pytest.raises(ConnectorError, match="Malformed response from GitHub"):
        await connector.get_repo("o", "r")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.get_repo("o", "r"),
        lambda c: c.list_repos(),
        lambda c: c.search_code("x"),
        lambda c: c.list_runs("o", "r"),
        lambda c: c.get_pr("o", "r", 1),
    ],
)
@pytest.mark.parametrize("payload", ["a string", 7, None, [1, 2], {"items": "x"}])
async def test_unexpected_json_shapes_never_crash(call, payload):
    connector, _ = make_connector(ok(payload))
    try:
        result = await call(connector)
    except ConnectorError as exc:
        assert "Malformed response from GitHub" in str(exc)
    else:
        assert isinstance(result, (dict, list))


@pytest.mark.asyncio
async def test_missing_fields_give_partial_results_not_errors():
    connector, _ = make_connector(ok({}))
    result = await connector.get_repo("o", "r")
    assert result["topics"] == [] and result["can_push"] is False
    issue = await connector.get_issue("o", "r", 1)
    assert issue["body"] == "" and issue["truncated"] is False and issue["labels"] == []


@pytest.mark.asyncio
async def test_hostile_payload_types_and_sizes_are_contained():
    huge = "A" * 1_000_000
    hostile = [
        {
            "number": 1,
            "title": huge,
            "user": "not-an-object",
            "labels": {"name": "x"},
            "state": ["open"],
            "html_url": {"nested": huge},
        },
        "not-an-issue",
        None,
        {
            "number": 2,
            "title": None,
            "user": {"login": 5},
            "labels": [None, {"name": 9}, {"name": "ok"}],
        },
    ]
    connector, _ = make_connector(ok(hostile))
    first, second = await connector.list_issues("o", "r")
    assert len(first["title"]) == 500
    assert first["author"] is None and first["labels"] == []
    assert "state" not in first and "html_url" not in first
    assert second["title"] is None and second["author"] is None and second["labels"] == ["ok"]
    assert len(json.dumps([first, second])) < 5_000


@pytest.mark.asyncio
async def test_pagination_is_one_request_even_when_a_next_link_exists():
    link = '<https://api.github.com/user/repos?page=2>; rel="next"'
    connector, seen = make_connector(ok([{"full_name": f"o/r{i}"} for i in range(3)], Link=link))
    repos = await connector.list_repos(limit=10)
    assert len(repos) == 3  # the page ended early: no second request
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_a_page_longer_than_the_limit_is_cut_to_the_limit():
    connector, seen = make_connector(ok([{"full_name": f"o/r{i}"} for i in range(80)]))
    repos = await connector.list_repos(limit=500)
    assert len(repos) == 50
    assert seen[0].url.params["per_page"] == "50"


# ---------------------------------------------------------------------------
# Confirmation before any request (every non-READ action)
# ---------------------------------------------------------------------------

WRITE_CALLS: dict[str, Callable[[GitHubConnector], Any]] = {
    "create_repo": lambda c: c.create_repo("new-repo"),
    "create_branch": lambda c: c.create_branch("o", "r", "feature/x"),
    "put_file": lambda c: c.put_file("o", "r", "a.md", "text", "msg"),
    "delete_branch": lambda c: c.delete_branch("o", "r", "feature/x"),
    "create_issue": lambda c: c.create_issue("o", "r", "Bug"),
    "comment": lambda c: c.comment("o", "r", 5, "hello"),
    "update_issue": lambda c: c.update_issue("o", "r", 5, state="closed"),
    "create_pr": lambda c: c.create_pr("o", "r", "T", "feature/x", "main"),
    "review_pr": lambda c: c.review_pr("o", "r", 5, "approve"),
    "request_reviewers": lambda c: c.request_reviewers("o", "r", 5, reviewers=["octo"]),
    "merge_pr": lambda c: c.merge_pr("o", "r", 5),
    "rerun_failed_jobs": lambda c: c.rerun_failed_jobs("o", "r", 9),
    "dispatch_workflow": lambda c: c.dispatch_workflow("o", "r", "deploy.yml", "main"),
    "cancel_run": lambda c: c.cancel_run("o", "r", 9),
    "mark_notification_read": lambda c: c.mark_notification_read("123"),
    "create_release": lambda c: c.create_release("o", "r", "v1.0.0"),
    "publish_release": lambda c: c.publish_release("o", "r", 44),
    "create_gist": lambda c: c.create_gist("notes.md", "hi"),
}


def test_every_non_read_action_has_a_confirmation_case():
    assert set(WRITE_CALLS) == {a.action for a in ACTIONS if a.category.value != "read"}


@pytest.mark.asyncio
@pytest.mark.parametrize("action", sorted(WRITE_CALLS))
async def test_non_read_actions_require_confirmation_before_any_request(action):
    connector, seen = make_connector(ok({}))
    with pytest.raises(UserConfirmationRequired) as exc:
        await WRITE_CALLS[action](connector)
    assert exc.value.action == action
    assert exc.value.details.strip()
    assert seen == []


@pytest.mark.asyncio
async def test_confirmation_texts_name_the_target():
    connector, _ = make_connector(ok({}))
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.merge_pr("octo", "app", 12, merge_method="squash")
    assert "octo/app#12" in exc.value.details and "squash" in exc.value.details
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.create_repo("pub", private=False)
    assert "PUBLIC" in exc.value.details
    with pytest.raises(UserConfirmationRequired) as exc:
        await connector.delete_branch("octo", "app", "old/branch")
    assert "old/branch" in exc.value.details and "octo/app" in exc.value.details


@pytest.mark.asyncio
async def test_invalid_arguments_fail_before_confirmation_and_request():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError) as exc:
        await connector.comment("o", "r", 0, "hi")
    assert not isinstance(exc.value, UserConfirmationRequired)
    assert seen == []


# ---------------------------------------------------------------------------
# Network policy (the registry-armed "github" policy)
# ---------------------------------------------------------------------------


@pytest.fixture
def no_dns(monkeypatch):
    monkeypatch.setattr(netsec, "check_ssrf", lambda url: netsec.SSRFCheckResult(safe=True))


def _armed() -> GitHubConnector:
    connector = GitHubConnector()
    connector._token = TOKEN
    connector.set_network_policy("github")
    return connector


def _authed(method: str, url: str) -> httpx.Request:
    return httpx.Request(method, url, headers={"Authorization": f"Bearer {TOKEN}"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,url",
    [
        ("GET", f"{API}/user"),
        ("GET", f"{API}/user/repos?per_page=10"),
        ("GET", f"{API}/orgs/acme/repos"),
        ("GET", f"{API}/repos/o/r/contents/src/app.py"),
        ("PUT", f"{API}/repos/o/r/pulls/1/merge"),
        ("GET", f"{API}/search/code?q=x"),
        ("GET", f"{API}/notifications"),
        ("PATCH", f"{API}/notifications/threads/1"),
        ("POST", f"{API}/gists"),
        ("POST", "https://github.com/login/device/code"),
        ("POST", "https://github.com/login/oauth/access_token"),
    ],
)
async def test_declared_hosts_and_paths_are_allowed(no_dns, method, url):
    await _armed()._enforce_network_policy(_authed(method, url))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://productionresultssa3.blob.core.windows.net/actions-results/abc/logs.txt?sig=x",
        "https://productionresultssa.blob.core.windows.net/actions-results/abc",
        "https://pipelines.actions.githubusercontent.com/abc/_apis/pipelines/1/runs/2/signedlogcontent/3",
    ],
)
async def test_log_download_hosts_allow_only_credential_free_gets(no_dns, url):
    connector = _armed()
    await connector._enforce_network_policy(httpx.Request("GET", url))
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._enforce_network_policy(_authed("GET", url))
    with pytest.raises(ConnectorError, match="without credentials"):
        await connector._enforce_network_policy(httpx.Request("POST", url))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url,reason",
    [
        ("https://evil.example.com/user", "not in allowlist"),
        ("https://api.github.com.evil.com/user", "not in allowlist"),
        ("https://evilaccount.blob.core.windows.net/actions-results/x", "not in allowlist"),
        (
            "https://productionresultssa1.blob.core.windows.net.evil.com/actions-results/x",
            "not in allowlist",
        ),
        ("https://uploads.github.com/repos/o/r/releases/1/assets", "not in allowlist"),
        ("https://api.github.com/admin/users", "not in allowed paths"),
        ("https://api.github.com/applications/abc/grant", "not in allowed paths"),
        ("https://github.com/settings/tokens", "not in allowed paths"),
        ("http://api.github.com/user", "HTTPS only"),
        ("https://api.github.com:8443/user", "allows only 443"),
        ("https://api.github.com/repos/o/r/%2e%2e/%2e%2e/admin", "dot segment"),
        ("https://api.github.com/repos/o/r/contents/a/%252e%252e/b", "dot segment"),
    ],
)
async def test_off_list_hosts_paths_schemes_and_dot_segments_are_refused(no_dns, url, reason):
    with pytest.raises(ConnectorError, match=reason):
        await _armed()._enforce_network_policy(_authed("GET", url))


@pytest.mark.asyncio
async def test_download_host_is_limited_to_the_results_container(no_dns):
    url = "https://productionresultssa1.blob.core.windows.net/other-container/x"
    with pytest.raises(ConnectorError, match="not in allowed paths"):
        await _armed()._enforce_network_policy(httpx.Request("GET", url))


@pytest.mark.asyncio
async def test_real_requests_all_pass_the_policy(no_dns):
    """Every URL the actions build is inside the allowlist."""
    urls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(request)
        return httpx.Response(200, json=[])

    connector, _ = make_connector(handler)
    connector.set_network_policy("github")
    await connector.list_repos(org="acme")
    await connector.list_issues()
    await connector.list_tree("o", "r", path="src")
    await connector.list_notifications()
    for request in urls:
        await connector._enforce_network_policy(request)


# ---------------------------------------------------------------------------
# The real pipeline: build_tools, the permission adapter and the executor
# ---------------------------------------------------------------------------

ALL_SCOPES = tuple(sorted({a.required_scope or "" for a in ACTIONS}))


def test_build_tools_labels_github_tools():
    for tier in ("auto_approve", "user_confirm"):
        tools = {
            t.name: t
            for t in build_tools(
                [ConnectorSpec("github", granted_scopes=ALL_SCOPES, permission_tier=tier)],
                user_default_tier=tier,
                include_builtins=False,
            )
        }
        assert {name.split(".", 1)[1] for name in tools} == {a.action for a in ACTIONS}
        for spec in ACTIONS:
            tool = tools[f"github.{spec.action}"]
            if spec.always_confirm:
                assert tool.permission_tier == "approval", spec.action
            assert tool.starter is spec.starter, spec.action
        assert tools["github.list_issues"].permission_tier == "auto"
    auto = build_tools(
        [ConnectorSpec("github", granted_scopes=ALL_SCOPES, permission_tier="auto_approve")],
        user_default_tier="auto_approve",
        include_builtins=False,
    )
    assert {t.name: t.permission_tier for t in auto}["github.create_issue"] == "auto"


def test_build_tools_offers_only_granted_scopes():
    tools = build_tools(
        [ConnectorSpec("github", granted_scopes=("issues.read",), permission_tier="user_confirm")],
        include_builtins=False,
    )
    assert {t.name for t in tools} == {
        "github.list_issues",
        "github.get_issue",
        "github.search_issues",
        "github.list_comments",
    }


@pytest.mark.asyncio
async def test_permission_adapter_decisions():
    adapter = RuntimePermissionAdapter()
    assert await adapter.check("u1", "github.list_issues", {}) == "approved"
    for name in ("github.merge_pr", "github.delete_branch", "github.dispatch_workflow"):
        assert await adapter.check("u1", name, {}) == "requires_approval"
    assert await adapter.check("u1", "github.delete_repo", {}) == "blocked"


async def _github_row(session_factory, user_id, scopes=ALL_SCOPES) -> None:
    from core.security import encrypt_credentials
    from models.connector import AuthMethod, ConnectorConfig

    async with session_factory() as session:
        session.add(
            ConnectorConfig(
                user_id=user_id,
                connector_type="github",
                display_name="GitHub",
                auth_method=AuthMethod.bearer_token,
                encrypted_credentials=encrypt_credentials(json.dumps({"access_token": TOKEN})),
                granted_scopes=list(scopes),
                rate_limit_per_minute=30,
            )
        )
        await session.commit()


@pytest.fixture
def github_transport(monkeypatch):
    """The real factory, with each connector's HTTP sent to a mock transport."""
    seen: list[httpx.Request] = []
    real_create = factory.create_connector

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.raw_path.startswith(b"/repos/octo/app/issues"):
            return httpx.Response(200, json=[{"number": 1, "title": "Bug", "state": "open"}])
        if request.url.raw_path == b"/repos/octo/app/pulls/4/merge":
            return httpx.Response(200, json={"merged": True, "sha": "a" * 40, "message": "ok"})
        return httpx.Response(404, json={"message": "Not Found"})

    def create(connector_type, credentials, **kwargs):
        connector = real_create(connector_type, credentials, **kwargs)
        assert connector._network_policy_key == "github"
        connector._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return connector

    monkeypatch.setattr(factory, "create_connector", create)
    return seen


@pytest.mark.asyncio
async def test_executor_runs_a_read_through_the_real_factory(session_factory, github_transport):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _github_row(session_factory, user.id)
    executor = ConnectorToolExecutor(session_factory=session_factory)

    result = await executor.execute(
        "github.list_issues", {"owner": "octo", "repo": "app"}, str(user.id)
    )

    assert result["ok"] is True, result
    assert (result["connector"], result["action"]) == ("github", "list_issues")
    assert result["result"]["count"] == 1
    assert result["result"]["items"][0]["title"] == "Bug"
    (request,) = github_transport
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in json.dumps(result)


@pytest.mark.asyncio
async def test_executor_refuses_then_runs_an_always_confirm_action(
    session_factory, github_transport
):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _github_row(session_factory, user.id)
    executor = ConnectorToolExecutor(session_factory=session_factory)
    args = {"owner": "octo", "repo": "app", "number": 4, "merge_method": "squash"}

    refused = await executor.execute("github.merge_pr", args, str(user.id))
    assert refused["ok"] is False and refused["requires_approval"] is True
    assert github_transport == []

    smuggled = await executor.execute(
        "github.merge_pr", {**args, "user_confirmed": True}, str(user.id)
    )
    assert smuggled["ok"] is False and smuggled["requires_approval"] is True
    assert github_transport == []

    approved = await executor.execute("github.merge_pr", args, str(user.id), approved=True)
    assert approved["ok"] is True, approved
    assert approved["result"] == {"number": 4, "merged": True, "sha": "a" * 40, "message": "ok"}
    (request,) = github_transport
    assert request.method == "PUT"
    assert body_of(request) == {"merge_method": "squash"}


@pytest.mark.asyncio
async def test_executor_refuses_an_action_outside_the_granted_scopes(
    session_factory, github_transport
):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _github_row(session_factory, user.id, scopes=("issues.read",))
    executor = ConnectorToolExecutor(session_factory=session_factory)
    result = await executor.execute(
        "github.merge_pr",
        {"owner": "octo", "repo": "app", "number": 4},
        str(user.id),
        approved=True,
    )
    assert result["ok"] is False
    assert github_transport == []


@pytest.mark.asyncio
async def test_executor_error_results_never_carry_the_token(session_factory, github_transport):
    from tests.conftest import make_user

    user, _ = await make_user(session_factory)
    await _github_row(session_factory, user.id)
    executor = ConnectorToolExecutor(session_factory=session_factory)
    result = await executor.execute(
        "github.get_repo", {"owner": "octo", "repo": "missing"}, str(user.id)
    )
    assert result["ok"] is False and "HTTP 404 from GitHub" in result["error"]
    assert TOKEN not in json.dumps(result)
