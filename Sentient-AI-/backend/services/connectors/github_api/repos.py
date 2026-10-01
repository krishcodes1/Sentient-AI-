"""GitHub repository actions: list and read repositories, files, trees,
branches and commits, search code, and create repositories, branches and
file commits.

Why it exists: the "Repos" row of the GitHub table in the connectors spec
(section 5.2). ``services/connectors/github.py`` mixes ``ReposMixin`` into
``GitHubConnector`` and lists ``REPO_ACTIONS`` in its DEFINITION.

Connects to: the GitHub REST API (``/user/repos``, ``/orgs/<org>/repos``,
``/repos/...``, ``/search/code``). Depends on ``github_api.common``
(validation, shaping, request helpers) and ``services.connectors.shaping``.
"""

from __future__ import annotations

import base64
from typing import Any, Optional

from services.agent import risk
from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import clamp_limit

from .common import (
    ACCEPT_OBJECT,
    ACCEPT_RAW,
    ACCEPT_SHA,
    API,
    DEFAULT_RESULT_CHARS,
    ENVELOPE_RESERVE,
    LIMIT_PROP,
    OWNER_PROP,
    REPO_PROP,
    GitHubApiBase,
    as_list,
    as_object,
    content_path,
    decode_json,
    first_line,
    fit_head,
    flag,
    git_ref,
    is_not_found,
    is_sha,
    json_len,
    list_field,
    login,
    nested,
    nested_str,
    owner_name,
    parse_json_bytes,
    positive_int,
    preview,
    ref_segments,
    repo_name,
    repo_path,
    require_confirmation,
    scalars,
    text_arg,
)

# JSON characters of one whole get_file result. The runtime shows the model
# DEFAULT_RESULT_CHARS of it (there is no RESULT_CHAR_BUDGETS entry for
# github.get_file) and drops the middle of anything longer, which would skip
# lines that the start_line hint then never returns. Sized to fit, the
# content is a run of whole lines and the hint names the very next one.
MAX_FILE_CHARS = DEFAULT_RESULT_CHARS - ENVELOPE_RESERVE
# Bytes of a file get_file downloads (the raw contents API serves files up
# to 100 MB). Lines past this point cannot be paged to; folder listings (at
# most 1,000 entries) stay well inside it.
MAX_FILE_BYTES = 2 * 1024 * 1024
# Paths echoed back in the result are cut to this (they count against it).
MAX_ECHO_PATH_CHARS = 300
# Largest file put_file will commit (characters of text).
MAX_PUT_CHARS = 1_000_000
# Changed files listed by compare.
MAX_COMPARE_FILES = 50
# Longest search query GitHub accepts.
MAX_QUERY_CHARS = 256

_REF_PROP = {
    "type": "string",
    "description": "Branch, tag or commit SHA (default: the repository's default branch)",
}

REPO_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_repos",
        "List repositories you can access, most recently updated first "
        "(or an organization's repositories when org is given).",
        ActionCategory.READ,
        _schema(
            org={"type": "string", "description": "Organization login (optional)"},
            limit=LIMIT_PROP,
        ),
        required_scope="repo.read",
        starter=True,
    ),
    ToolSpec(
        "get_repo",
        "Get a repository's details: description, visibility, default branch, counts.",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP),
        required_scope="repo.read",
    ),
    ToolSpec(
        "get_file",
        "Read a text file from a repository. Long files are cut; the result names "
        "the start_line to pass to read on.",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            path={
                "type": "string",
                "description": "File path, like 'src/app.py'",
                "required": True,
            },
            ref=_REF_PROP,
            start_line={"type": "integer", "description": "First line to return (default 1)"},
        ),
        required_scope="repo.read",
        starter=True,
    ),
    ToolSpec(
        "list_tree",
        "List files and folders in a repository folder (recursive=true lists everything "
        "below it). Entries include the blob sha that put_file needs to update a file.",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            path={"type": "string", "description": "Folder path (default: the root)"},
            ref=_REF_PROP,
            recursive={"type": "boolean", "description": "Include every level below path"},
            limit=LIMIT_PROP,
        ),
        required_scope="repo.read",
    ),
    ToolSpec(
        "search_code",
        "Search code with GitHub search syntax, e.g. 'parse_config repo:owner/name language:python'.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "GitHub code search query", "required": True},
            limit=LIMIT_PROP,
        ),
        required_scope="repo.read",
    ),
    ToolSpec(
        "list_branches",
        "List a repository's branches with their head commit and protection flag.",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, limit=LIMIT_PROP),
        required_scope="repo.read",
    ),
    ToolSpec(
        "list_commits",
        "List recent commits, optionally on a branch, touching a path, or by an author.",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            ref=_REF_PROP,
            path={"type": "string", "description": "Only commits touching this path"},
            author={"type": "string", "description": "GitHub login or email of the author"},
            limit=LIMIT_PROP,
        ),
        required_scope="repo.read",
    ),
    ToolSpec(
        "compare",
        "Compare two branches, tags or commits: ahead/behind counts, commits and changed files.",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            base={"type": "string", "description": "Base branch, tag or SHA", "required": True},
            head={"type": "string", "description": "Head branch, tag or SHA", "required": True},
            limit=LIMIT_PROP,
        ),
        required_scope="repo.read",
    ),
    ToolSpec(
        "create_repo",
        "Create a repository for you (or in an organization). Private unless private=false.",
        ActionCategory.WRITE,
        _schema(
            name={"type": "string", "description": "Repository name", "required": True},
            description={"type": "string"},
            private={"type": "boolean", "description": "Default true"},
            org={"type": "string", "description": "Organization login (optional)"},
            auto_init={"type": "boolean", "description": "Create an initial commit with a README"},
        ),
        required_scope="repo.create",
        # A public repository is published to everyone.
        risk_check=risk.when_value(
            "private", lambda value: value is not True, "high", "it creates a public repository"
        ),
    ),
    ToolSpec(
        "create_branch",
        "Create a branch from another branch, tag or commit (default: the default branch).",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            branch={"type": "string", "description": "New branch name", "required": True},
            from_ref={"type": "string", "description": "Branch, tag or SHA to start from"},
        ),
        required_scope="repo.write",
    ),
    ToolSpec(
        "put_file",
        "Create or replace one text file with a commit. Pass sha (from list_tree) to "
        "update only the version you read.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            path={
                "type": "string",
                "description": "File path, like 'docs/notes.md'",
                "required": True,
            },
            content={
                "type": "string",
                "description": "The complete new file text",
                "required": True,
            },
            message={"type": "string", "description": "Commit message", "required": True},
            branch={"type": "string", "description": "Target branch (default: the default branch)"},
            sha={"type": "string", "description": "Blob sha of the file being replaced"},
        ),
        required_scope="repo.write",
        always_confirm=True,
    ),
    ToolSpec(
        "delete_branch",
        "Delete a branch. Cannot be undone from here.",
        ActionCategory.DELETE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            branch={"type": "string", "description": "Branch to delete", "required": True},
        ),
        required_scope="repo.write",
        always_confirm=True,
    ),
)


def _repo_summary(item: Any) -> dict[str, Any]:
    return {
        **scalars(
            item,
            "full_name",
            "private",
            "default_branch",
            "language",
            "archived",
            "fork",
            "updated_at",
            "html_url",
        ),
        **scalars(item, "description", max_chars=300),
    }


def _tree_entry(item: Any) -> dict[str, Any]:
    kinds = {"blob": "file", "tree": "dir", "commit": "submodule"}
    entry = scalars(item, "path", "sha", "size")
    raw_type = item.get("type") if isinstance(item, dict) else None
    entry["type"] = kinds.get(raw_type, raw_type) if isinstance(raw_type, str) else None
    return entry


def _content_entry(item: Any) -> dict[str, Any]:
    """An entry of a contents-API folder listing (type file, dir, symlink, submodule)."""
    return scalars(item, "path", "type", "sha", "size")


def _is_directory_listing(data: Any) -> bool:
    return (
        isinstance(data, list)
        and bool(data)
        and all(isinstance(i, dict) and {"type", "path", "sha"} <= set(i) for i in data)
    )


def _folder_page(path: str, listing: list[dict[str, Any]]) -> dict[str, Any]:
    """get_file on a folder: as many of its entries as fit the result budget."""
    entries = [_content_entry(e) for e in listing[:50]]
    result: dict[str, Any] = {
        "path": path[:MAX_ECHO_PATH_CHARS],
        "type": "dir",
        "total_entries": len(listing),
        "entries": entries,
        "hint": "This path is a folder; call get_file with one of the entry paths "
        "(list_tree lists every entry).",
    }
    while len(entries) > 1 and json_len(result) > MAX_FILE_CHARS:
        entries.pop()
    return result


def _file_page(
    path: str, ref: Optional[str], raw: bytes, first: int, *, complete: bool = True
) -> dict[str, Any]:
    """get_file on a text file: whole lines from *first* that fit the budget.

    Lines are split on "\\n" only (as editors number them). Only the bytes
    the page can hold are decoded, so a large file is never decoded whole.
    The start_line hint names the line right after the last one returned
    (after a single over-long line, the line after it: its rest is skipped
    and the hint says so). *complete* is False when *raw* is only the first
    MAX_FILE_BYTES of a larger file: its size and line count are unknown
    (``partial_file`` replaces them) and only the whole lines read can be
    paged.
    """
    if not complete:
        # The last line read was cut by the download limit: drop it.
        end = raw.rfind(b"\n")
        raw = raw[: end + 1] if end >= 0 else raw
    total_lines = raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
    result: dict[str, Any] = {"path": path[:MAX_ECHO_PATH_CHARS]}
    if complete:
        result.update(size=len(raw), total_lines=total_lines)
    else:
        result["partial_file"] = True
    result.update(start_line=first, content="", truncated=False)
    if ref is not None:
        result["ref"] = ref
    if first > total_lines:
        if not complete:
            result["hint"] = (
                f"start_line is past line {total_lines}, as far as get_file reads in a "
                f"file over {MAX_FILE_BYTES // (1024 * 1024)} MB."
            )
        elif first > 1:
            result["hint"] = f"start_line is past the end of the file ({total_lines} lines)."
        return result
    rest = raw.split(b"\n", first - 1)[-1] if first > 1 else raw
    # The hint is measured at its widest so the filled result still fits.
    widest = _file_hint(total_lines, total_lines, total_lines, partial=True)
    budget = max(100, MAX_FILE_CHARS - json_len({**result, "truncated": True, "hint": widest}))
    window = rest[: 4 * budget + 4]  # UTF-8: at most 4 bytes a character
    content, cut = fit_head(window.decode("utf-8", errors="replace"), budget)
    truncated = cut or len(window) < len(rest) or not complete
    result["content"] = content
    result["truncated"] = truncated
    if truncated:
        partial = not content.endswith("\n")
        next_line = first + content.count("\n") + (1 if partial else 0)
        result["hint"] = _file_hint(first, next_line - 1, next_line, partial=partial)
    return result


def _file_hint(first: int, last: int, next_line: int, *, partial: bool) -> str:
    shown = (
        f"Line {first} is too long for one result; only its start is shown."
        if partial
        else f"Showing lines {first} to {last}."
    )
    return f"{shown} Call get_file with start_line={next_line} to read on."


class ReposMixin(GitHubApiBase):
    """Repository actions (one public coroutine per REPO_ACTIONS entry)."""

    # -- READ -------------------------------------------------------------

    async def list_repos(
        self, org: Optional[str] = None, limit: Any = None
    ) -> list[dict[str, Any]]:
        per_page = clamp_limit(limit)
        if org is not None:
            data = await self._get_json(
                f"/orgs/{path_segment(owner_name(org))}/repos",
                params={"sort": "updated", "per_page": per_page},
            )
        else:
            data = await self._get_json(
                "/user/repos", params={"sort": "updated", "per_page": per_page}
            )
        return [_repo_summary(item) for item in as_list(data)[:per_page]]

    async def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        data = as_object(await self._get_json(repo_path(owner, repo)))
        return {
            **_repo_summary(data),
            **scalars(
                data,
                "visibility",
                "open_issues_count",
                "stargazers_count",
                "forks_count",
                "pushed_at",
            ),
            "topics": [t[:50] for t in data.get("topics") or [] if isinstance(t, str)][:20],
            "can_push": nested(data, "permissions", "push") is True,
        }

    async def get_file(
        self, owner: str, repo: str, path: str, ref: Optional[str] = None, start_line: Any = None
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        file_path = content_path(path)
        params = {"ref": git_ref(ref)} if ref is not None else None
        first = 1 if start_line is None else positive_int(start_line, "start_line")
        body = await self._get_bytes(
            f"{base}/contents/{file_path}",
            accept=ACCEPT_RAW,
            params=params,
            max_bytes=MAX_FILE_BYTES,
        )
        raw = body.content
        # A folder answers with a JSON listing; a cut body is always a file.
        content_type = body.headers.get("content-type", "")
        if not body.truncated and content_type.startswith("application/json"):
            data = parse_json_bytes(raw)
            if _is_directory_listing(data):
                return _folder_page(path, data)
        if b"\x00" in raw[:8000]:
            result: dict[str, Any] = {"path": path[:MAX_ECHO_PATH_CHARS], "binary": True}
            if not body.truncated:
                result["size"] = len(raw)
            result["hint"] = "This is a binary file; its content is not shown."
            return result
        return _file_page(path, ref, raw, first, complete=not body.truncated)

    async def list_tree(
        self,
        owner: str,
        repo: str,
        path: Optional[str] = None,
        ref: Optional[str] = None,
        recursive: Any = False,
        limit: Any = None,
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        folder = content_path(path or "", allow_root=True)
        prefix = (path or "").strip().strip("/")
        deep = flag(recursive, "recursive") if recursive is not None else False
        count = clamp_limit(limit)
        tree_ref = git_ref(ref) if ref is not None else None
        github_truncated = False
        if deep:
            data = as_object(
                await self._get_json(
                    f"{base}/git/trees/{path_segment(tree_ref or 'HEAD')}",
                    params={"recursive": "1"},
                )
            )
            github_truncated = data.get("truncated") is True
            entries = [
                _tree_entry(item)
                for item in as_list(data.get("tree"))
                if isinstance(item.get("path"), str)
                and (not prefix or item["path"].startswith(prefix + "/"))
            ]
        else:
            url = f"{base}/contents/{folder}" if folder else f"{base}/contents"
            data = await self._get_json(url, params={"ref": tree_ref} if tree_ref else None)
            if isinstance(data, dict):
                raise ConnectorError(
                    f"'{prefix}' is a file, not a folder; call get_file to read it."
                )
            entries = [_content_entry(item) for item in as_list(data)]
        result: dict[str, Any] = {
            "path": prefix or "/",
            "entries": entries[:count],
            "total": len(entries),
            "truncated": len(entries) > count or github_truncated,
        }
        if result["truncated"]:
            result["hint"] = (
                "More entries exist. Call list_tree with a deeper path, or a larger limit (max 50)."
            )
        return result

    async def search_code(self, query: str, limit: Any = None) -> list[dict[str, Any]]:
        q = text_arg(query, "query", max_chars=MAX_QUERY_CHARS)
        per_page = clamp_limit(limit)
        data = await self._get_json("/search/code", params={"q": q, "per_page": per_page})
        return [
            {
                **scalars(item, "name", "path", "sha", "html_url"),
                "repository": nested_str(item, "repository", "full_name"),
            }
            for item in list_field(data, "items")[:per_page]
        ]

    async def list_branches(self, owner: str, repo: str, limit: Any = None) -> list[dict[str, Any]]:
        per_page = clamp_limit(limit)
        data = await self._get_json(
            f"{repo_path(owner, repo)}/branches", params={"per_page": per_page}
        )
        return [
            {**scalars(item, "name", "protected"), "sha": nested_str(item, "commit", "sha")}
            for item in as_list(data)[:per_page]
        ]

    async def list_commits(
        self,
        owner: str,
        repo: str,
        ref: Optional[str] = None,
        path: Optional[str] = None,
        author: Optional[str] = None,
        limit: Any = None,
    ) -> list[dict[str, Any]]:
        per_page = clamp_limit(limit)
        params: dict[str, Any] = {"per_page": per_page}
        if ref is not None:
            params["sha"] = git_ref(ref)
        if path is not None:
            content_path(path)  # validation only; the query carries the raw path
            params["path"] = path
        if author is not None:
            params["author"] = text_arg(author, "author", max_chars=254)
        data = await self._get_json(f"{repo_path(owner, repo)}/commits", params=params)
        return [_commit_summary(item) for item in as_list(data)[:per_page]]

    async def compare(
        self, owner: str, repo: str, base: str, head: str, limit: Any = None
    ) -> dict[str, Any]:
        per_page = clamp_limit(limit)
        basehead = f"{path_segment(git_ref(base, 'base'))}...{path_segment(git_ref(head, 'head'))}"
        data = as_object(
            await self._get_json(
                f"{repo_path(owner, repo)}/compare/{basehead}", params={"per_page": per_page}
            )
        )
        files = as_list(data.get("files") or [])
        result: dict[str, Any] = {
            **scalars(data, "status", "ahead_by", "behind_by", "total_commits", "html_url"),
            "commits": [_commit_summary(c) for c in as_list(data.get("commits") or [])[:per_page]],
            "files": [
                scalars(f, "filename", "status", "additions", "deletions", "changes")
                for f in files[:MAX_COMPARE_FILES]
            ],
            "files_total": len(files),
        }
        if len(files) > MAX_COMPARE_FILES:
            result["hint"] = (
                f"Only the first {MAX_COMPARE_FILES} changed files are listed; "
                "call get_file for a file's content."
            )
        return result

    # -- WRITE --------------------------------------------------------------

    async def create_repo(
        self,
        name: str,
        description: Optional[str] = None,
        private: Any = True,
        org: Optional[str] = None,
        auto_init: Any = False,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        repo = repo_name(name)
        about = text_arg(description, "description", required=False, max_chars=350)
        is_private = flag(private, "private") if private is not None else True
        init = flag(auto_init, "auto_init") if auto_init is not None else False
        owner = owner_name(org) if org is not None else None
        where = f"in organization {owner}" if owner else "on your account"
        require_confirmation(
            user_confirmed,
            "create_repo",
            f"Create a {'private' if is_private else 'PUBLIC'} GitHub repository '{repo}' {where}.",
        )
        body: dict[str, Any] = {"name": repo, "private": is_private, "auto_init": init}
        if about is not None:
            body["description"] = about
        path = f"/orgs/{path_segment(owner)}/repos" if owner else "/user/repos"
        data = as_object(await self._send_json("POST", path, json=body))
        return _repo_summary(data)

    async def create_branch(
        self,
        owner: str,
        repo: str,
        branch: str,
        from_ref: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        name = git_ref(branch, "branch")
        source = git_ref(from_ref, "from_ref") if from_ref is not None else None
        require_confirmation(
            user_confirmed,
            "create_branch",
            f"Create branch '{name}' in {owner}/{repo} from "
            f"{repr(source) if source else 'the default branch'}.",
        )
        sha = (
            source if source and is_sha(source) else await self._commit_sha(base, source or "HEAD")
        )
        data = as_object(
            await self._send_json(
                "POST", f"{base}/git/refs", json={"ref": f"refs/heads/{name}", "sha": sha}
            )
        )
        return {
            "branch": name,
            "sha": nested_str(data, "object", "sha") or sha,
            "ref": data.get("ref"),
        }

    async def put_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: Optional[str] = None,
        sha: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        file_path = content_path(path)
        self._check_workflow_path(path)
        text = text_arg(content, "content", required=False, max_chars=MAX_PUT_CHARS)
        if text is None:
            raise ConnectorError("content must be a string.")
        commit_message = text_arg(message, "message", max_chars=5000)
        target = git_ref(branch, "branch") if branch is not None else None
        blob_sha = sha.strip() if isinstance(sha, str) else None
        if sha is not None and (blob_sha is None or not is_sha(blob_sha)):
            raise ConnectorError(
                "sha must be the 40-character blob sha of the file being replaced."
            )
        require_confirmation(
            user_confirmed,
            "put_file",
            f"Commit '{path}' to {owner}/{repo} on "
            f"{repr(target) if target else 'the default branch'} "
            f"({'replacing blob ' + blob_sha[:7] if blob_sha else 'creating it, or replacing it if it exists'}; "
            f"{len(text)} characters) with message: {preview(commit_message, 120)}",
        )
        if blob_sha is None:
            blob_sha = await self._existing_blob_sha(base, file_path, target)
        body: dict[str, Any] = {
            "message": commit_message,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
        }
        if target:
            body["branch"] = target
        if blob_sha:
            body["sha"] = blob_sha
        response = await self._request("PUT", f"{API}{base}/contents/{file_path}", json=body)
        data = as_object(decode_json(response))
        return {
            "path": path,
            "created": response.status_code == 201,
            "branch": target,
            "commit_sha": nested_str(data, "commit", "sha"),
            "commit_url": nested_str(data, "commit", "html_url"),
            "content_sha": nested_str(data, "content", "sha"),
        }

    # -- DELETE -----------------------------------------------------------

    async def delete_branch(
        self, owner: str, repo: str, branch: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        ref = ref_segments(branch, "branch")
        require_confirmation(
            user_confirmed,
            "delete_branch",
            f"Delete branch '{branch.strip()}' from {owner}/{repo}. Commits only on that branch "
            "stay reachable only by SHA.",
        )
        await self._request("DELETE", f"{API}{base}/git/refs/heads/{ref}")
        return {"deleted": True, "branch": branch.strip()}

    # -- helpers ------------------------------------------------------------

    async def _commit_sha(self, base: str, ref: str) -> str:
        """The commit SHA *ref* points at (one small ``vnd.github.sha`` GET)."""
        response = await self._get_text(f"{base}/commits/{path_segment(ref)}", accept=ACCEPT_SHA)
        sha = response.text.strip()
        if not is_sha(sha):
            raise ConnectorError("GitHub did not return a commit SHA for that ref.")
        return sha

    async def _existing_blob_sha(
        self, base: str, file_path: str, branch: Optional[str]
    ) -> Optional[str]:
        """Blob sha of the file at *file_path*, or None when it does not exist."""
        try:
            data = await self._get_json(
                f"{base}/contents/{file_path}",
                params={"ref": branch} if branch else None,
                accept=ACCEPT_OBJECT,
            )
        except ConnectorError as exc:
            if is_not_found(exc):
                return None
            raise
        item = as_object(data)
        if item.get("type") != "file":
            raise ConnectorError(
                "That path is a folder or a link, not a file; put_file cannot replace it."
            )
        found = item.get("sha")
        if not isinstance(found, str) or not is_sha(found):
            raise ConnectorError("Malformed response from GitHub.")
        return found


def _commit_summary(item: Any) -> dict[str, Any]:
    return {
        "sha": item.get("sha") if isinstance(item.get("sha"), str) else None,
        "message": first_line(nested(item, "commit", "message")),
        "author": login(item.get("author"))
        or nested_str(item, "commit", "author", "name", max_chars=100),
        "date": nested_str(item, "commit", "author", "date", max_chars=40),
        "html_url": item.get("html_url") if isinstance(item.get("html_url"), str) else None,
    }
