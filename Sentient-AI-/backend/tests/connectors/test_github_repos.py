"""Tests for the GitHub repository actions: the exact request each action
sends (method, host, raw path, query, body) and the shaped result, plus
argument validation for owners, repositories, refs and file paths.

Why it exists: spec section 4.7 requires every action's request and
result to be pinned. Exercises ``services/connectors/github_api/repos.py``
through ``httpx.MockTransport`` only; ``make_connector`` comes from
``tests/connectors/test_github.py``.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from services.connectors.base import ConnectorError, UserConfirmationRequired
from tests.connectors.test_github import TOKEN, body_of, make_connector, ok

SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"


# ---------------------------------------------------------------------------
# READ
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_repos_sends_one_sorted_get_and_shapes_the_result():
    payload = [
        {
            "full_name": "octo/app",
            "private": True,
            "description": "d" * 400,
            "default_branch": "main",
            "owner": {"login": "octo", "id": 1},
            "permissions": {"admin": True},
            "html_url": "https://github.com/octo/app",
        }
    ]
    connector, seen = make_connector(ok(payload))
    result = await connector.list_repos(limit=5)
    (request,) = seen
    assert request.method == "GET" and request.url.host == "api.github.com"
    assert request.url.raw_path == b"/user/repos?sort=updated&per_page=5"
    assert result == [
        {
            "full_name": "octo/app",
            "private": True,
            "default_branch": "main",
            "html_url": "https://github.com/octo/app",
            "description": "d" * 300,
        }
    ]


@pytest.mark.asyncio
async def test_list_repos_for_an_org():
    connector, seen = make_connector(ok([]))
    await connector.list_repos(org="acme-inc")
    assert seen[0].url.raw_path == b"/orgs/acme-inc/repos?sort=updated&per_page=10"


@pytest.mark.asyncio
async def test_get_repo_shapes_details():
    payload = {
        "full_name": "octo/app",
        "visibility": "private",
        "topics": ["ai", 5, "x" * 80],
        "permissions": {"push": True},
        "stargazers_count": 3,
        "owner": {"login": "octo"},
    }
    connector, seen = make_connector(ok(payload))
    result = await connector.get_repo("octo", "app")
    assert seen[0].url.raw_path == b"/repos/octo/app"
    assert result["visibility"] == "private" and result["stargazers_count"] == 3
    assert result["topics"] == ["ai", "x" * 50]
    assert result["can_push"] is True
    assert "owner" not in result


@pytest.mark.asyncio
async def test_get_file_requests_raw_content_with_per_segment_encoding():
    connector, seen = make_connector(
        lambda r: httpx.Response(
            200, content=b"line1\nline2\n", headers={"content-type": "text/plain"}
        )
    )
    result = await connector.get_file("octo", "app", "src/my file#1.py", ref="feature/x")
    (request,) = seen
    assert request.url.raw_path == b"/repos/octo/app/contents/src/my%20file%231.py?ref=feature%2Fx"
    assert request.headers["Accept"] == "application/vnd.github.raw+json"
    assert result == {
        "path": "src/my file#1.py",
        "size": 12,
        "total_lines": 2,
        "start_line": 1,
        "content": "line1\nline2\n",
        "truncated": False,
        "ref": "feature/x",
    }


@pytest.mark.asyncio
async def test_get_file_caps_long_files_and_names_the_next_start_line():
    text = "".join(f"line {i:05d}\n" for i in range(5000))  # 11 chars a line
    connector, _ = make_connector(lambda r: httpx.Response(200, content=text.encode()))
    first = await connector.get_file("o", "r", "big.txt")
    assert first["truncated"] is True and first["total_lines"] == 5000
    # Whole lines only, sized to the runtime's default result budget.
    assert first["content"].endswith("\n") and len(first["content"]) <= 2_000
    next_line = first["content"].count("\n") + 1
    assert f"start_line={next_line}" in first["hint"]
    second = await connector.get_file("o", "r", "big.txt", start_line=next_line)
    assert second["content"].startswith(f"line {next_line - 1:05d}\n")


@pytest.mark.asyncio
async def test_get_file_reports_binary_files_without_content():
    connector, _ = make_connector(lambda r: httpx.Response(200, content=b"\x89PNG\x00\x00data"))
    result = await connector.get_file("o", "r", "logo.png")
    assert result["binary"] is True and "content" not in result


@pytest.mark.asyncio
async def test_get_file_on_a_folder_lists_its_entries():
    listing = [{"type": "file", "path": "src/a.py", "sha": SHA, "size": 3, "content": "x"}]
    connector, _ = make_connector(ok(listing))
    result = await connector.get_file("o", "r", "src")
    assert result["type"] == "dir"
    assert result["entries"] == [{"path": "src/a.py", "type": "file", "sha": SHA, "size": 3}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["", "/etc/passwd", "../secrets", "a/../b", "a//b", "a/./b", "a/", "a\\b", "a\x00b", 5, None],
)
async def test_get_file_refuses_unsafe_paths_before_any_request(path):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="path"):
        await connector.get_file("o", "r", path)
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "owner,repo",
    [
        ("", "r"),
        ("o/x", "r"),
        ("o", ""),
        ("o", ".."),
        ("o", "a/b"),
        ("-" * 50, "r"),
        (7, "r"),
        ("o", "r?x"),
    ],
)
async def test_owner_and_repo_are_validated(owner, repo):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="owner|repo"):
        await connector.get_repo(owner, repo)
    assert seen == []


@pytest.mark.asyncio
async def test_list_tree_lists_a_folder_through_the_contents_api():
    listing = [
        {"type": "dir", "path": "src/lib", "sha": SHA, "size": 0},
        {"type": "file", "path": "src/a.py", "sha": SHA2, "size": 10},
    ]
    connector, seen = make_connector(ok(listing))
    result = await connector.list_tree("o", "r", path="/src/", ref="main", limit=1)
    assert seen[0].url.raw_path == b"/repos/o/r/contents/src?ref=main"
    assert result["entries"] == [{"path": "src/lib", "type": "dir", "sha": SHA, "size": 0}]
    assert result["total"] == 2 and result["truncated"] is True and "list_tree" in result["hint"]


@pytest.mark.asyncio
async def test_list_tree_root_without_ref():
    connector, seen = make_connector(ok([]))
    result = await connector.list_tree("o", "r")
    assert seen[0].url.raw_path == b"/repos/o/r/contents"
    assert result == {"path": "/", "entries": [], "total": 0, "truncated": False}


@pytest.mark.asyncio
async def test_list_tree_on_a_file_points_to_get_file():
    connector, _ = make_connector(ok({"type": "file", "path": "a.py"}))
    with pytest.raises(ConnectorError, match="get_file"):
        await connector.list_tree("o", "r", path="a.py")


@pytest.mark.asyncio
async def test_list_tree_recursive_uses_one_git_trees_call_and_filters_by_prefix():
    tree = {
        "sha": SHA,
        "truncated": True,
        "tree": [
            {"path": "src", "type": "tree", "sha": SHA},
            {"path": "src/a.py", "type": "blob", "sha": SHA2, "size": 5, "mode": "100644"},
            {"path": "srcx/b.py", "type": "blob", "sha": SHA2},
            {"path": "lib/sub", "type": "commit", "sha": SHA},
            {"path": 5, "type": "blob"},
        ],
    }
    connector, seen = make_connector(ok(tree))
    result = await connector.list_tree("o", "r", path="src", recursive=True, limit=50)
    assert seen[0].url.raw_path == b"/repos/o/r/git/trees/HEAD?recursive=1"
    assert result["entries"] == [{"path": "src/a.py", "sha": SHA2, "size": 5, "type": "file"}]
    assert result["truncated"] is True  # GitHub said its tree was cut


@pytest.mark.asyncio
async def test_list_tree_recursive_encodes_a_slashed_ref_as_one_segment():
    connector, seen = make_connector(ok({"tree": []}))
    await connector.list_tree("o", "r", ref="feature/x", recursive=True)
    assert seen[0].url.raw_path == b"/repos/o/r/git/trees/feature%2Fx?recursive=1"


@pytest.mark.asyncio
async def test_search_code_shapes_items():
    payload = {
        "total_count": 1,
        "items": [
            {
                "name": "a.py",
                "path": "src/a.py",
                "sha": SHA,
                "html_url": "https://github.com/o/r/blob/main/src/a.py",
                "repository": {"full_name": "o/r", "private": True},
                "score": 1.0,
            }
        ],
    }
    connector, seen = make_connector(ok(payload))
    result = await connector.search_code("parse repo:o/r", limit=3)
    assert seen[0].url.raw_path == b"/search/code?q=parse+repo%3Ao%2Fr&per_page=3"
    assert result == [
        {
            "name": "a.py",
            "path": "src/a.py",
            "sha": SHA,
            "html_url": "https://github.com/o/r/blob/main/src/a.py",
            "repository": "o/r",
        }
    ]


@pytest.mark.asyncio
async def test_search_code_validates_the_query():
    connector, seen = make_connector(ok({}))
    for query in ("", "   ", "x" * 300, None):
        with pytest.raises(ConnectorError, match="query"):
            await connector.search_code(query)
    assert seen == []


@pytest.mark.asyncio
async def test_list_branches():
    connector, seen = make_connector(
        ok([{"name": "main", "protected": True, "commit": {"sha": SHA, "url": "u"}}])
    )
    result = await connector.list_branches("o", "r", limit=2)
    assert seen[0].url.raw_path == b"/repos/o/r/branches?per_page=2"
    assert result == [{"name": "main", "protected": True, "sha": SHA}]


@pytest.mark.asyncio
async def test_list_commits_with_filters():
    payload = [
        {
            "sha": SHA,
            "commit": {
                "message": "Fix bug\n\nLong body",
                "author": {"name": "Octo", "date": "2026-01-01T00:00:00Z"},
            },
            "author": {"login": "octocat"},
            "html_url": "https://github.com/o/r/commit/x",
            "files": [{"patch": "huge"}],
        },
        {"sha": SHA2, "commit": {"message": "Init", "author": {"name": "Anon"}}, "author": None},
    ]
    connector, seen = make_connector(ok(payload))
    result = await connector.list_commits("o", "r", ref="dev", path="src/a.py", author="octocat")
    assert (
        seen[0].url.raw_path
        == b"/repos/o/r/commits?per_page=10&sha=dev&path=src%2Fa.py&author=octocat"
    )
    assert result[0] == {
        "sha": SHA,
        "message": "Fix bug",
        "author": "octocat",
        "date": "2026-01-01T00:00:00Z",
        "html_url": "https://github.com/o/r/commit/x",
    }
    assert result[1]["author"] == "Anon"


@pytest.mark.asyncio
async def test_compare_encodes_each_side_and_caps_files():
    payload = {
        "status": "ahead",
        "ahead_by": 2,
        "behind_by": 0,
        "total_commits": 2,
        "commits": [{"sha": SHA, "commit": {"message": "m"}}],
        "files": [
            {"filename": f"f{i}", "status": "modified", "additions": 1, "patch": "p"}
            for i in range(60)
        ],
    }
    connector, seen = make_connector(ok(payload))
    result = await connector.compare("o", "r", "main", "feature/x", limit=5)
    assert seen[0].url.raw_path == b"/repos/o/r/compare/main...feature%2Fx?per_page=5"
    assert result["ahead_by"] == 2 and len(result["commits"]) == 1
    assert len(result["files"]) == 50 and result["files_total"] == 60
    assert "patch" not in result["files"][0] and "get_file" in result["hint"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ref", ["a..b", "has space", "-x:y", "x.lock", "/lead", "trail/", "a//b", "@", "x@{1}", ""]
)
async def test_bad_refs_are_refused(ref):
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="base|head"):
        await connector.compare("o", "r", ref, "main")
    assert seen == []


# ---------------------------------------------------------------------------
# WRITE and DELETE (confirmed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_repo_is_private_by_default():
    connector, seen = make_connector(ok({"full_name": "me/new", "private": True}, status=201))
    result = await connector.create_repo("new", description="demo", user_confirmed=True)
    (request,) = seen
    assert (request.method, request.url.raw_path) == ("POST", b"/user/repos")
    assert body_of(request) == {
        "name": "new",
        "private": True,
        "auto_init": False,
        "description": "demo",
    }
    assert result == {"full_name": "me/new", "private": True}


@pytest.mark.asyncio
async def test_create_repo_in_an_org():
    connector, seen = make_connector(ok({"full_name": "acme/new"}, status=201))
    await connector.create_repo(
        "new", org="acme", private=False, auto_init=True, user_confirmed=True
    )
    assert seen[0].url.raw_path == b"/orgs/acme/repos"
    assert body_of(seen[0]) == {"name": "new", "private": False, "auto_init": True}


@pytest.mark.asyncio
async def test_create_branch_resolves_the_default_branch_sha_then_creates_the_ref():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, content=SHA.encode())
        return httpx.Response(201, json={"ref": "refs/heads/feature/x", "object": {"sha": SHA}})

    connector, seen = make_connector(handler)
    result = await connector.create_branch("o", "r", "feature/x", user_confirmed=True)
    lookup, create = seen
    assert lookup.url.raw_path == b"/repos/o/r/commits/HEAD"
    assert lookup.headers["Accept"] == "application/vnd.github.sha"
    assert (create.method, create.url.raw_path) == ("POST", b"/repos/o/r/git/refs")
    assert body_of(create) == {"ref": "refs/heads/feature/x", "sha": SHA}
    assert result == {"branch": "feature/x", "sha": SHA, "ref": "refs/heads/feature/x"}


@pytest.mark.asyncio
async def test_create_branch_from_a_sha_needs_no_lookup():
    connector, seen = make_connector(
        ok({"ref": "refs/heads/b", "object": {"sha": SHA}}, status=201)
    )
    await connector.create_branch("o", "r", "b", from_ref=SHA, user_confirmed=True)
    assert len(seen) == 1 and body_of(seen[0])["sha"] == SHA


@pytest.mark.asyncio
async def test_create_branch_refuses_a_non_sha_lookup_answer():
    connector, seen = make_connector(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(ConnectorError, match="commit SHA"):
        await connector.create_branch("o", "r", "b", from_ref="main", user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_put_file_creates_a_new_file_after_a_404_lookup():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(
            201, json={"content": {"sha": SHA2}, "commit": {"sha": SHA, "html_url": "c"}}
        )

    connector, seen = make_connector(handler)
    result = await connector.put_file(
        "o", "r", "docs/new file.md", "héllo", "Add notes", branch="docs", user_confirmed=True
    )
    lookup, put = seen
    assert lookup.url.raw_path == b"/repos/o/r/contents/docs/new%20file.md?ref=docs"
    assert lookup.headers["Accept"] == "application/vnd.github.object+json"
    assert (put.method, put.url.raw_path) == ("PUT", b"/repos/o/r/contents/docs/new%20file.md")
    assert body_of(put) == {
        "message": "Add notes",
        "content": base64.b64encode("héllo".encode()).decode(),
        "branch": "docs",
    }
    assert result == {
        "path": "docs/new file.md",
        "created": True,
        "branch": "docs",
        "commit_sha": SHA,
        "commit_url": "c",
        "content_sha": SHA2,
    }


@pytest.mark.asyncio
async def test_put_file_replaces_an_existing_file_with_its_sha():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"type": "file", "sha": SHA2, "content": ""})
        return httpx.Response(200, json={"content": {"sha": SHA}, "commit": {"sha": SHA}})

    connector, seen = make_connector(handler)
    result = await connector.put_file("o", "r", "a.md", "x", "Update", user_confirmed=True)
    assert body_of(seen[1])["sha"] == SHA2 and "branch" not in body_of(seen[1])
    assert result["created"] is False


@pytest.mark.asyncio
async def test_put_file_with_a_sha_skips_the_lookup():
    connector, seen = make_connector(ok({"commit": {"sha": SHA}}, status=200))
    await connector.put_file("o", "r", "a.md", "", "Empty it", sha=SHA2, user_confirmed=True)
    assert len(seen) == 1 and body_of(seen[0])["sha"] == SHA2 and body_of(seen[0])["content"] == ""


@pytest.mark.asyncio
async def test_put_file_lookup_errors_other_than_404_propagate():
    connector, seen = make_connector(ok({"message": "Forbidden"}, status=403))
    with pytest.raises(ConnectorError, match="HTTP 403"):
        await connector.put_file("o", "r", "a.md", "x", "m", user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_put_file_refuses_to_replace_a_folder():
    connector, seen = make_connector(ok({"type": "dir", "path": "a", "sha": SHA, "entries": []}))
    with pytest.raises(ConnectorError, match="folder"):
        await connector.put_file("o", "r", "a", "x", "m", user_confirmed=True)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_put_file_validates_before_confirmation():
    connector, seen = make_connector(ok({}))
    with pytest.raises(ConnectorError, match="sha"):
        await connector.put_file("o", "r", "a.md", "x", "m", sha="abc")
    with pytest.raises(ConnectorError, match="content"):
        await connector.put_file("o", "r", "a.md", "x" * 1_000_001, "m")
    with pytest.raises(ConnectorError, match="message"):
        await connector.put_file("o", "r", "a.md", "x", "")
    assert seen == []


def _device_flow_credentials(*scopes: str) -> dict[str, object]:
    return {"access_token": TOKEN, "oauth_provider": "github", "granted_scopes": list(scopes)}


@pytest.mark.asyncio
async def test_put_file_refuses_workflow_files_for_a_device_flow_token_before_approval():
    # The device sign-in never requests "workflow", which GitHub needs for
    # these paths: refuse with the reason before the approval card, not
    # after it with a bare HTTP error.
    connector, seen = make_connector(ok({}))
    await connector.authenticate(_device_flow_credentials("repo", "read:org"))
    for confirmed in (False, True):
        with pytest.raises(ConnectorError, match="workflow permission") as info:
            await connector.put_file(
                "o", "r", ".github/workflows/ci.yml", "on: push", "m", user_confirmed=confirmed
            )
        assert type(info.value) is ConnectorError
        assert "Workflows permission" in str(info.value)
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "credentials,path",
    [
        # A pasted token's permissions are unknown here: GitHub decides.
        ({"access_token": TOKEN}, ".github/workflows/ci.yml"),
        # A grant that does carry the workflow scope.
        (_device_flow_credentials("repo", "workflow"), ".github/workflows/ci.yml"),
        # Other files under .github need no extra scope.
        (_device_flow_credentials("repo"), ".github/dependabot.yml"),
        (_device_flow_credentials("repo"), "docs/.github/workflows/x.yml"),
    ],
)
async def test_put_file_workflow_guard_lets_other_cases_reach_approval(credentials, path):
    connector, seen = make_connector(ok({}))
    await connector.authenticate(credentials)
    with pytest.raises(UserConfirmationRequired):
        await connector.put_file("o", "r", path, "x", "m")
    assert seen == []


@pytest.mark.asyncio
async def test_delete_branch_encodes_each_ref_segment():
    connector, seen = make_connector(lambda r: httpx.Response(204))
    result = await connector.delete_branch("o", "r", "feature/my%x", user_confirmed=True)
    (request,) = seen
    assert request.method == "DELETE"
    assert request.url.raw_path == b"/repos/o/r/git/refs/heads/feature/my%25x"
    assert result == {"deleted": True, "branch": "feature/my%x"}


@pytest.mark.asyncio
async def test_results_never_contain_the_token():
    connector, _ = make_connector(ok([{"full_name": "o/r", "description": TOKEN[:5]}]))
    result = await connector.list_repos()
    assert TOKEN not in json.dumps(result)
