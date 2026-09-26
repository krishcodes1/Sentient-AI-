"""GitHub issue actions: list, read, search and comment on issues, and create
or update them.

Why it exists: the "Issues" row of the GitHub table in the connectors spec
(section 5.2). ``services/connectors/github.py`` mixes ``IssuesMixin`` into
``GitHubConnector`` and lists ``ISSUE_ACTIONS`` in its DEFINITION. ``comment``
also works on pull requests (GitHub treats their conversation as an issue).

Connects to: the GitHub REST API (``/issues``, ``/repos/<o>/<r>/issues...``,
``/search/issues``). Depends on ``github_api.common`` (validation, shaping,
request helpers) and ``services.connectors.shaping``.
"""

from __future__ import annotations

from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import clamp_limit

from .common import (
    LIMIT_PROP,
    NUMBER_PROP,
    OWNER_PROP,
    REPO_PROP,
    GitHubApiBase,
    as_list,
    as_object,
    body_fields,
    choice,
    list_field,
    login,
    names,
    positive_int,
    preview,
    repo_path,
    require_confirmation,
    scalars,
    string_list,
    text_arg,
)

# Characters of an issue body returned by get_issue.
MAX_ISSUE_BODY_CHARS = 6_000
# Characters of each comment body returned by list_comments.
MAX_COMMENT_CHARS = 2_000
MAX_QUERY_CHARS = 256

_STATES = ("open", "closed", "all")
_STATE_REASONS = ("completed", "not_planned", "reopened")

ISSUE_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_issues",
        "List issues in a repository (pull requests excluded). Without owner and repo, "
        "lists open issues assigned to you across repositories.",
        ActionCategory.READ,
        _schema(
            owner={"type": "string", "description": "Repository owner (with repo)"},
            repo={"type": "string", "description": "Repository name (with owner)"},
            state={"type": "string", "enum": list(_STATES), "description": "Default open"},
            labels={"type": "string", "description": "Comma-separated label names"},
            limit=LIMIT_PROP,
        ),
        required_scope="issues.read",
        starter=True,
    ),
    ToolSpec(
        "get_issue",
        "Read one issue (or pull request conversation): title, state, labels, body.",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, number=NUMBER_PROP),
        required_scope="issues.read",
    ),
    ToolSpec(
        "search_issues",
        "Search issues and pull requests with GitHub search syntax, e.g. "
        "'is:issue is:open label:bug repo:owner/name'.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "description": "GitHub issue search query", "required": True},
            limit=LIMIT_PROP,
        ),
        required_scope="issues.read",
    ),
    ToolSpec(
        "list_comments",
        "List the comments on an issue or pull request, oldest first.",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, number=NUMBER_PROP, limit=LIMIT_PROP),
        required_scope="issues.read",
    ),
    ToolSpec(
        "create_issue",
        "Open a new issue.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            title={"type": "string", "required": True},
            body={"type": "string", "description": "Markdown body"},
            labels={"type": "array", "items": {"type": "string"}},
            assignees={"type": "array", "items": {"type": "string"}, "description": "Logins"},
        ),
        required_scope="issues.write",
    ),
    ToolSpec(
        "comment",
        "Post a comment on an issue or pull request, publicly under your name.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            number=NUMBER_PROP,
            body={"type": "string", "description": "Markdown comment", "required": True},
        ),
        required_scope="issues.write",
        always_confirm=True,
    ),
    ToolSpec(
        "update_issue",
        "Change an issue's title, body, state (open or closed), labels or assignees.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            number=NUMBER_PROP,
            title={"type": "string"},
            body={"type": "string"},
            state={"type": "string", "enum": ["open", "closed"]},
            state_reason={"type": "string", "enum": list(_STATE_REASONS)},
            labels={
                "type": "array",
                "items": {"type": "string"},
                "description": "Replaces all labels",
            },
            assignees={
                "type": "array",
                "items": {"type": "string"},
                "description": "Replaces all assignees",
            },
        ),
        required_scope="issues.write",
    ),
)


def issue_summary(item: Any) -> dict[str, Any]:
    """The list-view fields of an issue or pull request object."""
    return {
        **scalars(item, "number", "title", "state", "comments", "updated_at", "html_url"),
        "author": login(item.get("user")) if isinstance(item, dict) else None,
        "labels": names(item.get("labels")) if isinstance(item, dict) else [],
        "is_pull_request": isinstance(item, dict) and "pull_request" in item,
    }


def _repository_of(item: dict[str, Any]) -> Optional[str]:
    """``owner/name`` from an issue's ``repository_url`` (search results)."""
    url = item.get("repository_url")
    if not isinstance(url, str) or "/repos/" not in url:
        return None
    return url.rsplit("/repos/", 1)[1][:200]


class IssuesMixin(GitHubApiBase):
    """Issue actions (one public coroutine per ISSUE_ACTIONS entry)."""

    async def list_issues(
        self,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        state: Optional[str] = None,
        labels: Optional[str] = None,
        limit: Any = None,
    ) -> list[dict[str, Any]]:
        if (owner is None) != (repo is None):
            raise ConnectorError(
                "Pass both owner and repo, or neither to list issues assigned to you."
            )
        per_page = clamp_limit(limit)
        params: dict[str, Any] = {
            "state": choice(state, "state", _STATES, "open"),
            "per_page": per_page,
        }
        if labels is not None:
            params["labels"] = text_arg(labels, "labels", max_chars=500)
        path = f"{repo_path(owner, repo)}/issues" if owner is not None else "/issues"
        data = await self._get_json(path, params=params)
        issues = [i for i in as_list(data) if "pull_request" not in i]
        return [
            {**issue_summary(i), "repository": _repository_of(i)}
            if owner is None
            else issue_summary(i)
            for i in issues[:per_page]
        ]

    async def get_issue(self, owner: str, repo: str, number: Any) -> dict[str, Any]:
        n = positive_int(number, "number")
        data = as_object(await self._get_json(f"{repo_path(owner, repo)}/issues/{n}"))
        return {
            **issue_summary(data),
            **scalars(data, "state_reason", "created_at", "closed_at", "locked"),
            "assignees": names(data.get("assignees"), "login"),
            **body_fields(
                data.get("body"),
                MAX_ISSUE_BODY_CHARS,
                f"Body cut at {MAX_ISSUE_BODY_CHARS} characters; the full text is at html_url. "
                "Call list_comments for the discussion.",
            ),
        }

    async def search_issues(self, query: str, limit: Any = None) -> list[dict[str, Any]]:
        q = text_arg(query, "query", max_chars=MAX_QUERY_CHARS)
        per_page = clamp_limit(limit)
        data = await self._get_json("/search/issues", params={"q": q, "per_page": per_page})
        return [
            {**issue_summary(i), "repository": _repository_of(i)}
            for i in list_field(data, "items")[:per_page]
        ]

    async def list_comments(
        self, owner: str, repo: str, number: Any, limit: Any = None
    ) -> list[dict[str, Any]]:
        n = positive_int(number, "number")
        per_page = clamp_limit(limit)
        data = await self._get_json(
            f"{repo_path(owner, repo)}/issues/{n}/comments", params={"per_page": per_page}
        )
        return [
            {
                **scalars(c, "id", "created_at", "html_url"),
                "author": login(c.get("user")),
                **body_fields(
                    c.get("body"),
                    MAX_COMMENT_CHARS,
                    f"Comment cut at {MAX_COMMENT_CHARS} characters; the full text is at html_url.",
                ),
            }
            for c in as_list(data)[:per_page]
        ]

    async def create_issue(
        self,
        owner: str,
        repo: str,
        title: str,
        body: Optional[str] = None,
        labels: Optional[list[str]] = None,
        assignees: Optional[list[str]] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        payload: dict[str, Any] = {"title": text_arg(title, "title", max_chars=256)}
        text = text_arg(body, "body", required=False)
        if text is not None:
            payload["body"] = text
        for key, value in (("labels", labels), ("assignees", assignees)):
            items = string_list(value, key)
            if items is not None:
                payload[key] = items
        require_confirmation(
            user_confirmed,
            "create_issue",
            f"Open an issue in {owner}/{repo} titled '{preview(payload['title'], 120)}'.",
        )
        return issue_summary(
            as_object(await self._send_json("POST", f"{base}/issues", json=payload))
        )

    async def comment(
        self, owner: str, repo: str, number: Any, body: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        n = positive_int(number, "number")
        text = text_arg(body, "body")
        require_confirmation(
            user_confirmed,
            "comment",
            f"Post a public comment as you on {owner}/{repo}#{n} ({len(text or '')} characters): "
            f"{preview(text)}",
        )
        data = as_object(
            await self._send_json("POST", f"{base}/issues/{n}/comments", json={"body": text})
        )
        return {**scalars(data, "id", "html_url", "created_at"), "number": n}

    async def update_issue(
        self,
        owner: str,
        repo: str,
        number: Any,
        title: Optional[str] = None,
        body: Optional[str] = None,
        state: Optional[str] = None,
        state_reason: Optional[str] = None,
        labels: Optional[list[str]] = None,
        assignees: Optional[list[str]] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        n = positive_int(number, "number")
        payload: dict[str, Any] = {}
        if title is not None:
            payload["title"] = text_arg(title, "title", max_chars=256)
        if body is not None:
            payload["body"] = text_arg(body, "body", required=False)
        if state is not None:
            payload["state"] = choice(state, "state", ("open", "closed"))
        if state_reason is not None:
            payload["state_reason"] = choice(state_reason, "state_reason", _STATE_REASONS)
        for key, value in (("labels", labels), ("assignees", assignees)):
            items = string_list(value, key)
            if items is not None:
                payload[key] = items
        if not payload:
            raise ConnectorError("update_issue needs at least one field to change.")
        require_confirmation(
            user_confirmed,
            "update_issue",
            f"Update {owner}/{repo}#{n}: change {', '.join(sorted(payload))}.",
        )
        data = as_object(await self._send_json("PATCH", f"{base}/issues/{n}", json=payload))
        return {**issue_summary(data), **scalars(data, "state_reason")}
