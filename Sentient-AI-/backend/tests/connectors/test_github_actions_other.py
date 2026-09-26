"""Tests for the GitHub Actions, notification, release and gist actions: the
exact request each action sends, the shaped result, the failed-log download
through the pre-signed redirect under the real network policy, and a sweep
proving every action's URLs are inside the GitHub allowlist.

Why it exists: spec section 4.7 requires every action's request and
result to be pinned and the declared hosts to match the real requests.
Exercises ``services/connectors/github_api/workflows.py`` and ``activity.py``
through ``httpx.MockTransport`` only; ``make_connector`` comes from
``tests/connectors/test_github.py``.
"""

from __future__ import annotations

import httpx
import pytest

import core.network_security as netsec
from services.connectors.base import AuthenticationError, ConnectorError
from services.connectors.github import GitHubConnector
from services.connectors.github_api.workflows import log_tail
from tests.connectors.test_github import TOKEN, WRITE_CALLS, body_of, make_connector, ok

SHA = "0123456789abcdef0123456789abcdef01234567"
BLOB = "https://productionresultssa7.blob.core.windows.net/actions-results/abc/job.txt?sig=s"

RUN = {
    "id": 42,
    "name": "CI",
    "display_title": "Fix build",
    "status": "completed",
    "conclusion": "failure",
    "event": "push",
    "head_branch": "main",
    "head_sha": SHA,
    "run_number": 7,
    "html_url": "https://github.com/o/r/actions/runs/42",
    "repository": {"huge": "x"},
}
JOBS = {
    "total_count": 3,
    "jobs": [
        {
            "id": 1,
            "name": "test",
            "status": "completed",
            "conclusion": "failure",
            "steps": [
                {"name": "Checkout", "conclusion": "success"},
                {"name": "Run tests", "conclusion": "failure"},
            ],
        },
        {"id": 2, "name": "lint", "status": "completed", "conclusion": "success", "steps": []},
        {
            "id": 3,
            "name": "deploy",
            "status": "completed",
            "conclusion": "timed_out",
            "steps": None,
        },
    ],
}


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_runs_for_a_workflow_file():
    connector, seen = make_connector(ok({"total_count": 1, "workflow_runs": [RUN]}))
    (run,) = await connector.list_runs(
        "o", "r", workflow="ci.yml", branch="main", status="failure", limit=5
    )
    assert seen[0].url.raw_path == (
        b"/repos/o/r/actions/workflows/ci.yml/runs?per_page=5&branch=main&status=failure"
    )
    assert run["id"] == 42 and run["conclusion"] == "failure" and "repository" not in run


@pytest.mark.asyncio
async def test_list_runs_for_the_whole_repo_and_by_workflow_id():
    connector, seen = make_connector(ok({"workflow_runs": []}))
    await connector.list_runs("o", "r")
    await connector.list_runs("o", "r", workflow=123)
    assert seen[0].url.raw_path == b"/repos/o/r/actions/runs?per_page=10"
    assert seen[1].url.raw_path == b"/repos/o/r/actions/workflows/123/runs?per_page=10"


@pytest.mark.asyncio
@pytest.mark.parametrize("workflow", ["../x.yml", "ci", ".hidden.yml", "a/b.yml", "", True])
async def test_workflow_names_are_validated(workflow):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="workflow"):
        await connector.list_runs("o", "r", workflow=workflow)
    assert seen == []


@pytest.mark.asyncio
async def test_get_run_fetches_run_and_jobs():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.raw_path == b"/repos/o/r/actions/runs/42":
            return httpx.Response(200, json=RUN)
        return httpx.Response(200, json=JOBS)

    connector, seen = make_connector(handler)
    result = await connector.get_run("o", "r", 42)
    assert sorted(r.url.raw_path for r in seen) == [
        b"/repos/o/r/actions/runs/42",
        b"/repos/o/r/actions/runs/42/jobs?filter=latest&per_page=50",
    ]
    assert result["failed_jobs"] == 2
    assert result["jobs"][0]["failed_steps"] == ["Run tests"]
    assert result["jobs"][2]["failed_steps"] == []


def test_log_tail_strips_timestamps_and_keeps_the_end():
    log = "".join(f"2026-09-25T10:00:00.1234567Z line {i}\n" for i in range(2000))
    tail, truncated = log_tail(log, 100)
    assert truncated is True and len(tail) <= 100
    assert tail.endswith("line 1999\n") and "2026-09-25T" not in tail
    assert tail.startswith("line ")
    assert log_tail("short\n") == ("short\n", False)


@pytest.mark.asyncio
async def test_get_failed_logs_downloads_only_failed_jobs_and_keeps_the_tail():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path
        if path.startswith(b"/repos/o/r/actions/runs/42/jobs"):
            return httpx.Response(200, json=JOBS)
        if path == b"/repos/o/r/actions/jobs/1/logs":
            return httpx.Response(200, text="x" * 10_000 + "\nError: boom\n")
        if path == b"/repos/o/r/actions/jobs/3/logs":
            return httpx.Response(410, json={"message": "Gone"})
        return httpx.Response(404)

    connector, seen = make_connector(handler)
    result = await connector.get_failed_logs("o", "r", 42)
    paths = sorted(r.url.raw_path for r in seen)
    assert paths == [
        b"/repos/o/r/actions/jobs/1/logs",
        b"/repos/o/r/actions/jobs/3/logs",
        b"/repos/o/r/actions/runs/42/jobs?filter=latest&per_page=50",
    ]
    first, second = result["failed_jobs"]
    assert first["name"] == "test" and first["log_tail"].endswith("Error: boom\n")
    assert first["truncated"] is True and len(first["log_tail"]) <= 6_000
    assert second["name"] == "deploy" and "HTTP 410 from GitHub" in second["log_error"]


@pytest.mark.asyncio
async def test_get_failed_logs_limits_the_number_of_jobs():
    jobs = {"jobs": [{"id": i, "name": f"j{i}", "conclusion": "failure"} for i in range(1, 9)]}

    def handler(request: httpx.Request) -> httpx.Response:
        if b"/jobs?" in request.url.raw_path:
            return httpx.Response(200, json=jobs)
        return httpx.Response(200, text="log")

    connector, seen = make_connector(handler)
    result = await connector.get_failed_logs("o", "r", 42, limit=50)
    assert len(result["failed_jobs"]) == 5 and len(seen) == 6
    assert "8 jobs failed" in result["hint"]


@pytest.mark.asyncio
async def test_get_failed_logs_with_nothing_failed():
    connector, seen = make_connector(
        ok({"jobs": [JOBS["jobs"][1], {"id": "x", "conclusion": "failure"}]})
    )
    result = await connector.get_failed_logs("o", "r", 42)
    assert result["failed_jobs"] == [] and "No job failed" in result["message"]
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_get_failed_logs_propagates_authentication_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        if b"/jobs?" in request.url.raw_path:
            return httpx.Response(200, json=JOBS)
        return httpx.Response(401)

    connector, _ = make_connector(handler)
    with pytest.raises(AuthenticationError):
        await connector.get_failed_logs("o", "r", 42)


@pytest.fixture
def no_dns(monkeypatch):
    monkeypatch.setattr(
        netsec,
        "check_ssrf",
        lambda url: netsec.SSRFCheckResult(
            safe=True, resolved_ip="93.184.216.34", resolved_ips=("93.184.216.34",)
        ),
    )


def _hooked(handler) -> tuple[GitHubConnector, list[httpx.Request]]:
    """A connector whose mock transport still runs the real policy hook."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    connector = GitHubConnector()
    connector._token = TOKEN
    connector._authenticated = True
    connector.set_network_policy("github")
    connector._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(recording),
        event_hooks={"request": [connector._enforce_network_policy]},
        max_redirects=connector.MAX_REDIRECTS,
    )
    return connector, seen


@pytest.mark.asyncio
async def test_job_log_redirect_reaches_the_blob_host_without_the_token(no_dns):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com" and b"/jobs?" in request.url.raw_path:
            return httpx.Response(200, json={"jobs": [JOBS["jobs"][0]]})
        if request.url.host == "api.github.com":
            return httpx.Response(302, headers={"Location": BLOB})
        return httpx.Response(200, text="2026-09-25T10:00:00Z Error: boom\n")

    connector, seen = _hooked(handler)
    result = await connector.get_failed_logs("o", "r", 42)
    assert [r.url.host for r in seen] == [
        "api.github.com",
        "api.github.com",
        "productionresultssa7.blob.core.windows.net",
    ]
    assert seen[1].headers["Authorization"] == f"Bearer {TOKEN}"
    assert "authorization" not in seen[2].headers
    assert result["failed_jobs"][0]["log_tail"] == "Error: boom\n"
    await connector.close()


@pytest.mark.asyncio
async def test_job_log_redirect_to_an_off_list_host_is_refused(no_dns):
    def handler(request: httpx.Request) -> httpx.Response:
        if b"/jobs?" in request.url.raw_path:
            return httpx.Response(200, json={"jobs": [JOBS["jobs"][0]]})
        return httpx.Response(302, headers={"Location": "https://attacker.blob.core.windows.net/x"})

    connector, seen = _hooked(handler)
    result = await connector.get_failed_logs("o", "r", 42)
    assert "blocked by network policy" in result["failed_jobs"][0]["log_error"]
    assert all(r.url.host == "api.github.com" for r in seen)
    await connector.close()


@pytest.mark.asyncio
async def test_rerun_failed_jobs():
    connector, seen = make_connector(ok({}, status=201))
    result = await connector.rerun_failed_jobs("o", "r", 42, user_confirmed=True)
    assert (seen[0].method, seen[0].url.raw_path) == (
        "POST",
        b"/repos/o/r/actions/runs/42/rerun-failed-jobs",
    )
    assert result == {"run_id": 42, "rerun_requested": True}


@pytest.mark.asyncio
async def test_dispatch_workflow_sends_ref_and_string_inputs():
    connector, seen = make_connector(lambda r: httpx.Response(204))
    result = await connector.dispatch_workflow(
        "o",
        "r",
        "deploy.yml",
        "main",
        inputs={"env": "prod", "dry_run": True, "count": 2},
        user_confirmed=True,
    )
    assert (seen[0].method, seen[0].url.raw_path) == (
        "POST",
        b"/repos/o/r/actions/workflows/deploy.yml/dispatches",
    )
    assert body_of(seen[0]) == {
        "ref": "main",
        "inputs": {"env": "prod", "dry_run": "true", "count": "2"},
    }
    assert result == {"workflow": "deploy.yml", "ref": "main", "dispatched": True}


@pytest.mark.asyncio
async def test_dispatch_workflow_keeps_run_details_when_github_returns_them():
    connector, _ = make_connector(ok({"workflow_run_id": 77, "html_url": "h"}))
    result = await connector.dispatch_workflow("o", "r", 5, "v1.0", user_confirmed=True)
    assert result["workflow_run_id"] == 77


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "inputs,match",
    [
        ("env=prod", "object"),
        ({"bad name": "x"}, "identifiers"),
        ({"a": {"b": 1}}, "string"),
        ({f"k{i}": "v" for i in range(30)}, "at most"),
    ],
)
async def test_dispatch_workflow_validates_inputs(inputs, match):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match=match):
        await connector.dispatch_workflow("o", "r", "deploy.yml", "main", inputs=inputs)
    assert seen == []


@pytest.mark.asyncio
async def test_cancel_run():
    connector, seen = make_connector(ok({}, status=202))
    result = await connector.cancel_run("o", "r", "42", user_confirmed=True)
    assert (seen[0].method, seen[0].url.raw_path) == ("POST", b"/repos/o/r/actions/runs/42/cancel")
    assert result == {"run_id": 42, "cancel_requested": True}


# ---------------------------------------------------------------------------
# Notifications, releases, gists
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_notifications():
    item = {
        "id": "123",
        "reason": "mention",
        "unread": True,
        "updated_at": "t",
        "subject": {"title": "Bug", "type": "Issue", "url": "u"},
        "repository": {"full_name": "o/r", "owner": {}},
    }
    connector, seen = make_connector(ok([item]))
    (result,) = await connector.list_notifications(include_read=True, limit=5)
    assert seen[0].url.raw_path == b"/notifications?all=true&participating=false&per_page=5"
    assert result == {
        "id": "123",
        "reason": "mention",
        "unread": True,
        "updated_at": "t",
        "repository": "o/r",
        "title": "Bug",
        "type": "Issue",
    }


@pytest.mark.asyncio
async def test_mark_notification_read():
    connector, seen = make_connector(lambda r: httpx.Response(205))
    result = await connector.mark_notification_read(123, user_confirmed=True)
    assert (seen[0].method, seen[0].url.raw_path) == ("PATCH", b"/notifications/threads/123")
    assert result == {"thread_id": "123", "read": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("thread_id", ["../1", "abc", "", True, None])
async def test_thread_ids_are_validated(thread_id):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="thread_id"):
        await connector.mark_notification_read(thread_id)
    assert seen == []


RELEASE = {
    "id": 44,
    "tag_name": "v1.0.0",
    "name": "One",
    "draft": True,
    "prerelease": False,
    "author": {"login": "octo"},
    "body": "n" * 7000,
    "assets": [
        {
            "name": "a.zip",
            "size": 3,
            "download_count": 1,
            "browser_download_url": "d",
            "uploader": {},
        }
    ],
    "html_url": "h",
}


@pytest.mark.asyncio
async def test_list_releases():
    connector, seen = make_connector(ok([RELEASE]))
    (release,) = await connector.list_releases("o", "r", limit=2)
    assert seen[0].url.raw_path == b"/repos/o/r/releases?per_page=2"
    assert release["tag_name"] == "v1.0.0" and release["author"] == "octo" and "body" not in release


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs,path",
    [
        ({}, b"/repos/o/r/releases/latest"),
        ({"release_id": 44}, b"/repos/o/r/releases/44"),
        ({"tag": "release/v1"}, b"/repos/o/r/releases/tags/release%2Fv1"),
    ],
)
async def test_get_release_by_latest_id_or_tag(kwargs, path):
    connector, seen = make_connector(ok(RELEASE))
    result = await connector.get_release("o", "r", **kwargs)
    assert seen[0].url.raw_path == path
    assert result["truncated"] is True and len(result["body"]) == 6000
    assert result["assets"] == [
        {"name": "a.zip", "size": 3, "download_count": 1, "browser_download_url": "d"}
    ]


@pytest.mark.asyncio
async def test_get_release_refuses_both_selectors():
    connector, seen = make_connector(ok(RELEASE))
    with pytest.raises(ConnectorError, match="not both"):
        await connector.get_release("o", "r", release_id=1, tag="v1")
    assert seen == []


@pytest.mark.asyncio
async def test_create_release_is_always_a_draft():
    connector, seen = make_connector(ok(RELEASE, status=201))
    result = await connector.create_release(
        "o",
        "r",
        "v1.0.0",
        name="One",
        target_commitish="main",
        generate_release_notes=True,
        user_confirmed=True,
    )
    assert (seen[0].method, seen[0].url.raw_path) == ("POST", b"/repos/o/r/releases")
    assert body_of(seen[0]) == {
        "tag_name": "v1.0.0",
        "draft": True,
        "name": "One",
        "target_commitish": "main",
        "prerelease": False,
        "generate_release_notes": True,
    }
    assert result["draft"] is True


@pytest.mark.asyncio
async def test_publish_release():
    connector, seen = make_connector(ok({**RELEASE, "draft": False}))
    result = await connector.publish_release("o", "r", 44, user_confirmed=True)
    assert (seen[0].method, seen[0].url.raw_path) == ("PATCH", b"/repos/o/r/releases/44")
    assert body_of(seen[0]) == {"draft": False}
    assert result["draft"] is False


@pytest.mark.asyncio
async def test_create_gist_is_secret_by_default():
    connector, seen = make_connector(ok({"id": "g1", "html_url": "h", "public": False}, status=201))
    result = await connector.create_gist("notes.md", "hello", description="d", user_confirmed=True)
    assert (seen[0].method, seen[0].url.raw_path) == ("POST", b"/gists")
    assert body_of(seen[0]) == {
        "public": False,
        "files": {"notes.md": {"content": "hello"}},
        "description": "d",
    }
    assert result == {"id": "g1", "html_url": "h", "public": False, "filename": "notes.md"}


@pytest.mark.asyncio
async def test_create_gist_public_is_named_in_the_confirmation():
    from services.connectors.base import UserConfirmationRequired

    connector, seen = make_connector(ok({}))
    with pytest.raises(UserConfirmationRequired, match="PUBLIC"):
        await connector.create_gist("a.txt", "x", public=True)
    with pytest.raises(ConnectorError, match="filename"):
        await connector.create_gist("dir/a.txt", "x")
    assert seen == []


# ---------------------------------------------------------------------------
# Every action's URLs are inside the allowlist
# ---------------------------------------------------------------------------

READ_CALLS = {
    "list_repos": lambda c: c.list_repos(),
    "get_repo": lambda c: c.get_repo("o", "r"),
    "get_file": lambda c: c.get_file("o", "r", "a/b.py", ref="main"),
    "list_tree": lambda c: c.list_tree("o", "r", recursive=True),
    "search_code": lambda c: c.search_code("x"),
    "list_branches": lambda c: c.list_branches("o", "r"),
    "list_commits": lambda c: c.list_commits("o", "r"),
    "compare": lambda c: c.compare("o", "r", "a", "b"),
    "list_issues": lambda c: c.list_issues(),
    "get_issue": lambda c: c.get_issue("o", "r", 1),
    "search_issues": lambda c: c.search_issues("x"),
    "list_comments": lambda c: c.list_comments("o", "r", 1),
    "list_prs": lambda c: c.list_prs("o", "r"),
    "get_pr": lambda c: c.get_pr("o", "r", 1),
    "get_pr_diff": lambda c: c.get_pr_diff("o", "r", 1),
    "get_pr_checks": lambda c: c.get_pr_checks("o", "r", 1),
    "list_reviews": lambda c: c.list_reviews("o", "r", 1),
    "list_runs": lambda c: c.list_runs("o", "r"),
    "get_run": lambda c: c.get_run("o", "r", 1),
    "get_failed_logs": lambda c: c.get_failed_logs("o", "r", 1),
    "list_notifications": lambda c: c.list_notifications(),
    "list_releases": lambda c: c.list_releases("o", "r"),
    "get_release": lambda c: c.get_release("o", "r"),
}


def _universal(request: httpx.Request) -> httpx.Response:
    """A reply shaped well enough for every action to complete."""
    path = request.url.path
    if path.endswith("/logs"):
        return httpx.Response(200, text="log")
    if "/commits/" in path and request.headers.get("Accept") == "application/vnd.github.sha":
        return httpx.Response(200, text=SHA)
    if path.endswith("/jobs"):
        return httpx.Response(200, json={"jobs": [{"id": 5, "conclusion": "failure"}]})
    if (
        request.method == "GET"
        and "/contents/" in path
        and "object" in request.headers.get("Accept", "")
    ):
        return httpx.Response(404)
    if path.endswith("/pulls/1") and request.headers.get("Accept") != "application/vnd.github.diff":
        return httpx.Response(200, json={"number": 1, "head": {"sha": SHA}})
    if path.endswith("/check-runs") or path.endswith("/status"):
        return httpx.Response(200, json={"check_runs": [], "statuses": []})
    if "/search/" in path or path.endswith("/runs"):
        return httpx.Response(200, json={"items": [], "workflow_runs": []})
    if (
        request.method == "GET"
        and (path.endswith("s") or path.endswith("/issues"))
        and "/runs/" not in path
    ):
        return httpx.Response(200, json=[])
    return httpx.Response(200, json={"tree": [], "check_runs": [], "statuses": [], "jobs": []})


@pytest.mark.asyncio
@pytest.mark.parametrize("action", sorted(READ_CALLS) + sorted(WRITE_CALLS))
async def test_every_action_url_passes_the_github_policy(no_dns, action):
    connector, seen = make_connector(_universal)
    connector.set_network_policy("github")
    call = READ_CALLS.get(action)
    if call is not None:
        await call(connector)
    else:
        # The same call the executor makes once the user approved.
        await connector.execute(action, {**_WRITE_ARGS[action], "user_confirmed": True})
    assert seen, action
    for request in seen:
        await connector._enforce_network_policy(request)


_WRITE_ARGS = {
    "create_repo": {"name": "new-repo"},
    "create_branch": {"owner": "o", "repo": "r", "branch": "feature/x"},
    "put_file": {"owner": "o", "repo": "r", "path": "a.md", "content": "text", "message": "msg"},
    "delete_branch": {"owner": "o", "repo": "r", "branch": "feature/x"},
    "create_issue": {"owner": "o", "repo": "r", "title": "Bug"},
    "comment": {"owner": "o", "repo": "r", "number": 5, "body": "hello"},
    "update_issue": {"owner": "o", "repo": "r", "number": 5, "state": "closed"},
    "create_pr": {"owner": "o", "repo": "r", "title": "T", "head": "feature/x", "base": "main"},
    "review_pr": {"owner": "o", "repo": "r", "number": 5, "event": "approve"},
    "request_reviewers": {"owner": "o", "repo": "r", "number": 5, "reviewers": ["octo"]},
    "merge_pr": {"owner": "o", "repo": "r", "number": 5},
    "rerun_failed_jobs": {"owner": "o", "repo": "r", "run_id": 9},
    "dispatch_workflow": {"owner": "o", "repo": "r", "workflow": "deploy.yml", "ref": "main"},
    "cancel_run": {"owner": "o", "repo": "r", "run_id": 9},
    "mark_notification_read": {"thread_id": "123"},
    "create_release": {"owner": "o", "repo": "r", "tag_name": "v1.0.0"},
    "publish_release": {"owner": "o", "repo": "r", "release_id": 44},
    "create_gist": {"filename": "notes.md", "content": "hi"},
}


def test_write_args_cover_every_write_action():
    assert set(_WRITE_ARGS) == set(WRITE_CALLS)


def test_read_calls_cover_every_read_action():
    from services.connectors.github import ACTIONS

    assert set(READ_CALLS) == {a.action for a in ACTIONS if a.category.value == "read"}
