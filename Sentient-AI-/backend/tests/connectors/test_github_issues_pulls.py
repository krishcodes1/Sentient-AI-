"""Tests for the GitHub issue and pull request actions: the exact request
each action sends (method, host, raw path, query, body), the shaped result,
text caps and argument validation.

Why it exists: spec section 4.7 requires every action's request and
result to be pinned. Exercises ``services/connectors/github_api/issues.py``
and ``pulls.py`` through ``httpx.MockTransport`` only; ``make_connector``
comes from ``tests/connectors/test_github.py``.
"""

from __future__ import annotations

import httpx
import pytest

from services.connectors.base import ConnectorError
from tests.connectors.test_github import body_of, make_connector, ok

SHA = "0123456789abcdef0123456789abcdef01234567"

ISSUE = {
    "number": 7,
    "title": "Crash on start",
    "state": "open",
    "state_reason": None,
    "comments": 2,
    "user": {"login": "octo", "id": 1, "avatar_url": "x"},
    "labels": [{"name": "bug", "color": "f00"}],
    "assignees": [{"login": "dev"}],
    "html_url": "https://github.com/o/r/issues/7",
    "body": "It crashes.",
    "reactions": {"+1": 3},
}


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_issues_in_a_repo_excludes_pull_requests():
    pr = {"number": 8, "title": "PR", "pull_request": {"url": "x"}}
    connector, seen = make_connector(ok([ISSUE, pr]))
    result = await connector.list_issues("o", "r", state="closed", labels="bug,ui", limit=2)
    assert seen[0].url.raw_path == b"/repos/o/r/issues?state=closed&per_page=2&labels=bug%2Cui"
    assert result == [
        {
            "number": 7,
            "title": "Crash on start",
            "state": "open",
            "comments": 2,
            "html_url": "https://github.com/o/r/issues/7",
            "author": "octo",
            "labels": ["bug"],
            "is_pull_request": False,
        }
    ]


@pytest.mark.asyncio
async def test_list_issues_without_a_repo_lists_your_assigned_issues():
    item = {**ISSUE, "repository_url": "https://api.github.com/repos/acme/web"}
    connector, seen = make_connector(ok([item]))
    (result,) = await connector.list_issues()
    assert seen[0].url.raw_path == b"/issues?state=open&per_page=10"
    assert result["repository"] == "acme/web"


@pytest.mark.asyncio
async def test_list_issues_argument_rules():
    connector, seen = make_connector(ok([]))
    with pytest.raises(ConnectorError, match="both owner and repo"):
        await connector.list_issues(owner="o")
    with pytest.raises(ConnectorError, match="state"):
        await connector.list_issues("o", "r", state="merged")
    assert seen == []


@pytest.mark.asyncio
async def test_get_issue_caps_the_body():
    connector, seen = make_connector(ok({**ISSUE, "body": "b" * 10_000}))
    result = await connector.get_issue("o", "r", "7")
    assert seen[0].url.raw_path == b"/repos/o/r/issues/7"
    assert result["assignees"] == ["dev"]
    assert len(result["body"]) == 6_000 and result["truncated"] is True
    assert "list_comments" in result["hint"]
    assert "reactions" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("number", [0, -1, "7/../1", "abc", True, 1.5, None])
async def test_numbers_are_validated(number):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="number"):
        await connector.get_issue("o", "r", number)
    assert seen == []


@pytest.mark.asyncio
async def test_search_issues_names_each_repository():
    payload = {"items": [{**ISSUE, "repository_url": "https://api.github.com/repos/o/r"}, "junk"]}
    connector, seen = make_connector(ok(payload))
    result = await connector.search_issues("is:open label:bug", limit=4)
    assert seen[0].url.raw_path == b"/search/issues?q=is%3Aopen+label%3Abug&per_page=4"
    assert len(result) == 1 and result[0]["repository"] == "o/r"


@pytest.mark.asyncio
async def test_list_comments_caps_each_body():
    comments = [{"id": 1, "user": {"login": "a"}, "body": "c" * 3000, "html_url": "h"}]
    connector, seen = make_connector(ok(comments))
    (comment,) = await connector.list_comments("o", "r", 7, limit=3)
    assert seen[0].url.raw_path == b"/repos/o/r/issues/7/comments?per_page=3"
    assert comment["author"] == "a" and len(comment["body"]) == 2000 and comment["truncated"]


@pytest.mark.asyncio
async def test_create_issue_posts_title_body_labels_and_assignees():
    connector, seen = make_connector(ok(ISSUE, status=201))
    result = await connector.create_issue(
        "o", "r", "Crash", body="Steps", labels=["bug"], assignees=["dev"], user_confirmed=True
    )
    (request,) = seen
    assert (request.method, request.url.raw_path) == ("POST", b"/repos/o/r/issues")
    assert body_of(request) == {
        "title": "Crash",
        "body": "Steps",
        "labels": ["bug"],
        "assignees": ["dev"],
    }
    assert result["number"] == 7


@pytest.mark.asyncio
async def test_create_issue_validates_lists():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="labels"):
        await connector.create_issue("o", "r", "t", labels="bug")
    with pytest.raises(ConnectorError, match="title"):
        await connector.create_issue("o", "r", "")
    assert seen == []


@pytest.mark.asyncio
async def test_comment_posts_the_body():
    connector, seen = make_connector(ok({"id": 99, "html_url": "h", "body": "x"}, status=201))
    result = await connector.comment("o", "r", 7, "Thanks!", user_confirmed=True)
    assert (seen[0].method, seen[0].url.raw_path) == ("POST", b"/repos/o/r/issues/7/comments")
    assert body_of(seen[0]) == {"body": "Thanks!"}
    assert result == {"id": 99, "html_url": "h", "number": 7}


@pytest.mark.asyncio
async def test_update_issue_patches_only_given_fields():
    connector, seen = make_connector(ok({**ISSUE, "state": "closed", "state_reason": "completed"}))
    result = await connector.update_issue(
        "o", "r", 7, state="closed", state_reason="completed", labels=[], user_confirmed=True
    )
    assert (seen[0].method, seen[0].url.raw_path) == ("PATCH", b"/repos/o/r/issues/7")
    assert body_of(seen[0]) == {"state": "closed", "state_reason": "completed", "labels": []}
    assert result["state"] == "closed" and result["state_reason"] == "completed"


@pytest.mark.asyncio
async def test_update_issue_needs_a_field():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="at least one field"):
        await connector.update_issue("o", "r", 7)
    assert seen == []


# ---------------------------------------------------------------------------
# Pull requests
# ---------------------------------------------------------------------------

PR = {
    "number": 4,
    "title": "Add feature",
    "state": "open",
    "draft": False,
    "user": {"login": "octo"},
    "head": {"ref": "feature/x", "sha": SHA, "repo": {"huge": "x"}},
    "base": {"ref": "main"},
    "labels": [],
    "merged": False,
    "mergeable": True,
    "additions": 10,
    "requested_reviewers": [{"login": "rev"}],
    "body": "Desc",
    "html_url": "https://github.com/o/r/pull/4",
}


@pytest.mark.asyncio
async def test_list_prs():
    connector, seen = make_connector(ok([PR]))
    (result,) = await connector.list_prs("o", "r", state="all", base="main", limit=3)
    assert seen[0].url.raw_path == b"/repos/o/r/pulls?state=all&per_page=3&base=main"
    assert result == {
        "number": 4,
        "title": "Add feature",
        "state": "open",
        "draft": False,
        "html_url": "https://github.com/o/r/pull/4",
        "author": "octo",
        "head": "feature/x",
        "base": "main",
        "labels": [],
    }


@pytest.mark.asyncio
async def test_get_pr():
    connector, seen = make_connector(ok(PR))
    result = await connector.get_pr("o", "r", 4)
    assert seen[0].url.raw_path == b"/repos/o/r/pulls/4"
    assert result["head_sha"] == SHA and result["mergeable"] is True
    assert result["requested_reviewers"] == ["rev"] and result["body"] == "Desc"


@pytest.mark.asyncio
async def test_get_pr_diff_uses_the_diff_media_type_and_caps():
    diff = "diff --git a/x b/x\n" + "+line\n" * 20_000
    connector, seen = make_connector(lambda r: httpx.Response(200, text=diff))
    result = await connector.get_pr_diff("o", "r", 4)
    assert seen[0].url.raw_path == b"/repos/o/r/pulls/4"
    assert seen[0].headers["Accept"] == "application/vnd.github.diff"
    assert result["truncated"] is True and result["diff"].endswith("+line\n")
    # Sized to the runtime's 12000-character github.get_pr_diff budget.
    assert 9_000 < len(result["diff"]) < 12_000
    assert "compare" in result["hint"] and "get_file" in result["hint"]


@pytest.mark.asyncio
async def test_get_pr_checks_combines_check_runs_and_statuses_failures_first():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path
        if path == b"/repos/o/r/pulls/4":
            return httpx.Response(200, json=PR)
        if path.startswith(f"/repos/o/r/commits/{SHA}/check-runs".encode()):
            return httpx.Response(
                200,
                json={
                    "total_count": 3,
                    "check_runs": [
                        {"name": "lint", "status": "completed", "conclusion": "success"},
                        {
                            "name": "test",
                            "status": "completed",
                            "conclusion": "failure",
                            "html_url": "h",
                        },
                        {"name": "build", "status": "in_progress", "conclusion": None},
                    ],
                },
            )
        if path.startswith(f"/repos/o/r/commits/{SHA}/status".encode()):
            return httpx.Response(
                200,
                json={"state": "failure", "statuses": [{"context": "ci/ext", "state": "error"}]},
            )
        return httpx.Response(404)

    connector, seen = make_connector(handler)
    result = await connector.get_pr_checks("o", "r", 4, limit=3)
    assert len(seen) == 3
    assert result["summary"] == {"failed": 2, "pending": 1, "passed": 1}
    assert [c["name"] for c in result["checks"]] == ["test", "ci/ext", "build"]
    assert result["truncated"] is True and result["head_sha"] == SHA


@pytest.mark.asyncio
async def test_get_pr_checks_refuses_a_missing_head_sha():
    connector, seen = make_connector(ok({"number": 4, "head": {"sha": "../x"}}))
    with pytest.raises(ConnectorError, match="Malformed"):
        await connector.get_pr_checks("o", "r", 4)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_list_reviews():
    reviews = [
        {
            "id": 1,
            "user": {"login": "rev"},
            "state": "APPROVED",
            "body": "LGTM",
            "submitted_at": "t",
        }
    ]
    connector, seen = make_connector(ok(reviews))
    (review,) = await connector.list_reviews("o", "r", 4)
    assert seen[0].url.raw_path == b"/repos/o/r/pulls/4/reviews?per_page=10"
    assert review == {
        "id": 1,
        "state": "APPROVED",
        "submitted_at": "t",
        "author": "rev",
        "body": "LGTM",
        "truncated": False,
    }


@pytest.mark.asyncio
async def test_create_pr_posts_head_base_and_draft():
    connector, seen = make_connector(ok(PR, status=201))
    result = await connector.create_pr(
        "o",
        "r",
        "Add feature",
        "fork-owner:feature/x",
        "main",
        body="Desc",
        draft=True,
        user_confirmed=True,
    )
    assert (seen[0].method, seen[0].url.raw_path) == ("POST", b"/repos/o/r/pulls")
    assert body_of(seen[0]) == {
        "title": "Add feature",
        "head": "fork-owner:feature/x",
        "base": "main",
        "draft": True,
        "body": "Desc",
    }
    assert result["number"] == 4


@pytest.mark.asyncio
async def test_create_pr_validates_branches():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="head"):
        await connector.create_pr("o", "r", "t", "bad..branch", "main")
    with pytest.raises(ConnectorError, match="draft"):
        await connector.create_pr("o", "r", "t", "a", "main", draft="yes")
    assert seen == []


@pytest.mark.asyncio
async def test_review_pr_posts_the_event_in_upper_case():
    connector, seen = make_connector(ok({"id": 5, "state": "CHANGES_REQUESTED"}))
    result = await connector.review_pr(
        "o", "r", 4, "request_changes", body="Fix x", user_confirmed=True
    )
    assert seen[0].url.raw_path == b"/repos/o/r/pulls/4/reviews"
    assert body_of(seen[0]) == {"event": "REQUEST_CHANGES", "body": "Fix x"}
    assert result == {"id": 5, "state": "CHANGES_REQUESTED", "number": 4}


@pytest.mark.asyncio
async def test_review_pr_rules():
    connector, seen = make_connector(ok({"id": 5}))
    with pytest.raises(ConnectorError, match="body"):
        await connector.review_pr("o", "r", 4, "comment")
    with pytest.raises(ConnectorError, match="event"):
        await connector.review_pr("o", "r", 4, "dismiss")
    assert seen == []
    await connector.review_pr("o", "r", 4, "APPROVE", user_confirmed=True)
    assert body_of(seen[0]) == {"event": "APPROVE"}


@pytest.mark.asyncio
async def test_request_reviewers():
    connector, seen = make_connector(
        ok(
            {"requested_reviewers": [{"login": "a"}], "requested_teams": [{"slug": "core"}]},
            status=201,
        )
    )
    result = await connector.request_reviewers(
        "o", "r", 4, reviewers=["a"], team_reviewers=["core"], user_confirmed=True
    )
    assert seen[0].url.raw_path == b"/repos/o/r/pulls/4/requested_reviewers"
    assert body_of(seen[0]) == {"reviewers": ["a"], "team_reviewers": ["core"]}
    assert result == {"number": 4, "requested_reviewers": ["a"], "requested_teams": ["core"]}


@pytest.mark.asyncio
async def test_request_reviewers_needs_someone():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="reviewers"):
        await connector.request_reviewers("o", "r", 4)
    assert seen == []


@pytest.mark.asyncio
async def test_merge_pr_puts_method_and_expected_sha():
    connector, seen = make_connector(
        ok({"merged": True, "sha": SHA, "message": "Pull Request successfully merged"})
    )
    result = await connector.merge_pr(
        "o", "r", 4, merge_method="squash", commit_title="T", sha=SHA, user_confirmed=True
    )
    assert (seen[0].method, seen[0].url.raw_path) == ("PUT", b"/repos/o/r/pulls/4/merge")
    assert body_of(seen[0]) == {"merge_method": "squash", "commit_title": "T", "sha": SHA}
    assert result == {
        "number": 4,
        "merged": True,
        "sha": SHA,
        "message": "Pull Request successfully merged",
    }


@pytest.mark.asyncio
async def test_merge_pr_405_not_mergeable_is_reported():
    connector, _ = make_connector(ok({"message": "Pull Request is not mergeable"}, status=405))
    with pytest.raises(ConnectorError, match="HTTP 405 from GitHub") as exc:
        await connector.merge_pr("o", "r", 4, user_confirmed=True)
    assert "not mergeable" not in str(exc.value)  # the body text is never echoed


@pytest.mark.asyncio
async def test_merge_pr_validates_method_and_sha():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="merge_method"):
        await connector.merge_pr("o", "r", 4, merge_method="octopus")
    with pytest.raises(ConnectorError, match="sha"):
        await connector.merge_pr("o", "r", 4, sha="abc")
    assert seen == []
