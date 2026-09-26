"""GitHub pull request actions: list and read pull requests, their diff,
checks and reviews, and create, review, request reviewers for and merge them.

Why it exists: the "Pull requests" row of the GitHub table in the connectors
spec (section 5.2). ``services/connectors/github.py`` mixes ``PullsMixin``
into ``GitHubConnector`` and lists ``PULL_ACTIONS`` in its DEFINITION.
``get_pr_diff`` is a long-result action the runtime budgets by name.

Connects to: the GitHub REST API (``/repos/<o>/<r>/pulls...``,
``/repos/<o>/<r>/commits/<sha>/check-runs`` and ``/status``). Depends on
``github_api.common`` (validation, shaping, request helpers) and
``services.connectors.shaping``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import clamp_limit

from .common import (
    ACCEPT_DIFF,
    ENVELOPE_RESERVE,
    LIMIT_PROP,
    LONG_RESULT_CHARS,
    NUMBER_PROP,
    OWNER_PROP,
    REPO_PROP,
    GitHubApiBase,
    as_list,
    as_object,
    body_fields,
    choice,
    fit_head,
    flag,
    git_ref,
    is_sha,
    json_len,
    login,
    names,
    nested_str,
    positive_int,
    preview,
    repo_path,
    require_confirmation,
    scalars,
    string_list,
    text_arg,
)

# JSON characters of the whole get_pr_diff result: the runtime shows the
# model LONG_RESULT_CHARS of it (its github.get_pr_diff budget), envelope
# included, so the capped diff arrives whole instead of losing its middle.
MAX_DIFF_CHARS = LONG_RESULT_CHARS - ENVELOPE_RESERVE
# Bytes of the diff downloaded and decoded: enough for MAX_DIFF_CHARS
# characters of any UTF-8 text, so a many-megabyte diff is never held whole.
DIFF_WINDOW_BYTES = 4 * MAX_DIFF_CHARS + 4
_DIFF_HINT = (
    "Diff cut after {lines} lines. Call compare for the list of changed "
    "files, then get_file for the ones you need."
)
MAX_PR_BODY_CHARS = 6_000
MAX_REVIEW_CHARS = 1_500
# Check runs fetched for the summary (one page, GitHub's per_page ceiling is 100).
CHECK_RUNS_PAGE = 100

_PR_STATES = ("open", "closed", "all")
_REVIEW_EVENTS = ("approve", "request_changes", "comment")
_MERGE_METHODS = ("merge", "squash", "rebase")
_PASSED = frozenset({"success", "neutral", "skipped"})

PULL_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_prs",
        "List pull requests in a repository, newest first.",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            state={"type": "string", "enum": list(_PR_STATES), "description": "Default open"},
            base={"type": "string", "description": "Only PRs into this branch"},
            limit=LIMIT_PROP,
        ),
        required_scope="pulls.read",
        starter=True,
    ),
    ToolSpec(
        "get_pr",
        "Read one pull request: branches, state, mergeability, size and description.",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, number=NUMBER_PROP),
        required_scope="pulls.read",
    ),
    ToolSpec(
        "get_pr_diff",
        "Get a pull request's unified diff (long diffs are cut; the result says so).",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, number=NUMBER_PROP),
        required_scope="pulls.read",
    ),
    ToolSpec(
        "get_pr_checks",
        "Get the CI checks and commit statuses of a pull request's head commit, failures first.",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, number=NUMBER_PROP, limit=LIMIT_PROP),
        required_scope="pulls.read",
    ),
    ToolSpec(
        "list_reviews",
        "List the reviews on a pull request (approved, changes requested, commented).",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, number=NUMBER_PROP, limit=LIMIT_PROP),
        required_scope="pulls.read",
    ),
    ToolSpec(
        "create_pr",
        "Open a pull request from head into base.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            title={"type": "string", "required": True},
            head={
                "type": "string",
                "description": "Branch with the changes ('user:branch' for a fork)",
                "required": True,
            },
            base={"type": "string", "description": "Branch to merge into", "required": True},
            body={"type": "string", "description": "Markdown description"},
            draft={"type": "boolean", "description": "Open as a draft"},
        ),
        required_scope="pulls.write",
    ),
    ToolSpec(
        "review_pr",
        "Submit a review on a pull request under your name: approve, request_changes or comment.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            number=NUMBER_PROP,
            event={"type": "string", "enum": list(_REVIEW_EVENTS), "required": True},
            body={"type": "string", "description": "Review text (required unless approving)"},
        ),
        required_scope="pulls.write",
        always_confirm=True,
    ),
    ToolSpec(
        "request_reviewers",
        "Ask people or teams to review a pull request.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            number=NUMBER_PROP,
            reviewers={"type": "array", "items": {"type": "string"}, "description": "User logins"},
            team_reviewers={
                "type": "array",
                "items": {"type": "string"},
                "description": "Team slugs",
            },
        ),
        required_scope="pulls.write",
    ),
    ToolSpec(
        "merge_pr",
        "Merge a pull request (merge, squash or rebase). Pass sha to merge only if the head "
        "has not moved.",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            number=NUMBER_PROP,
            merge_method={
                "type": "string",
                "enum": list(_MERGE_METHODS),
                "description": "Default merge",
            },
            commit_title={"type": "string"},
            commit_message={"type": "string"},
            sha={"type": "string", "description": "Expected head commit SHA"},
        ),
        required_scope="pulls.write",
        always_confirm=True,
    ),
)


def _pr_summary(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return {
        **scalars(item, "number", "title", "state", "draft", "updated_at", "html_url"),
        "author": login(item.get("user")),
        "head": nested_str(item, "head", "ref", max_chars=255),
        "base": nested_str(item, "base", "ref", max_chars=255),
        "labels": names(item.get("labels")),
    }


def _check_outcome(status: Any, conclusion: Any) -> str:
    if status != "completed":
        return "pending"
    return "passed" if conclusion in _PASSED else "failed"


def _status_outcome(state: Any) -> str:
    if state == "success":
        return "passed"
    return "pending" if state == "pending" else "failed"


class PullsMixin(GitHubApiBase):
    """Pull request actions (one public coroutine per PULL_ACTIONS entry)."""

    async def list_prs(
        self,
        owner: str,
        repo: str,
        state: Optional[str] = None,
        base: Optional[str] = None,
        limit: Any = None,
    ) -> list[dict[str, Any]]:
        per_page = clamp_limit(limit)
        params: dict[str, Any] = {
            "state": choice(state, "state", _PR_STATES, "open"),
            "per_page": per_page,
        }
        if base is not None:
            params["base"] = git_ref(base, "base")
        data = await self._get_json(f"{repo_path(owner, repo)}/pulls", params=params)
        return [_pr_summary(item) for item in as_list(data)[:per_page]]

    async def get_pr(self, owner: str, repo: str, number: Any) -> dict[str, Any]:
        n = positive_int(number, "number")
        data = as_object(await self._get_json(f"{repo_path(owner, repo)}/pulls/{n}"))
        return {
            **_pr_summary(data),
            **scalars(
                data,
                "merged",
                "mergeable",
                "mergeable_state",
                "additions",
                "deletions",
                "changed_files",
                "commits",
                "comments",
                "review_comments",
                "created_at",
                "merged_at",
                "closed_at",
            ),
            "head_sha": nested_str(data, "head", "sha", max_chars=40),
            "requested_reviewers": names(data.get("requested_reviewers"), "login"),
            **body_fields(
                data.get("body"),
                MAX_PR_BODY_CHARS,
                f"Description cut at {MAX_PR_BODY_CHARS} characters; the full text is at html_url.",
            ),
        }

    async def get_pr_diff(self, owner: str, repo: str, number: Any) -> dict[str, Any]:
        n = positive_int(number, "number")
        body = await self._get_bytes(
            f"{repo_path(owner, repo)}/pulls/{n}", accept=ACCEPT_DIFF, max_bytes=DIFF_WINDOW_BYTES
        )
        window = body.content
        # The hint is measured at its widest so the filled result still fits.
        widest_hint = _DIFF_HINT.format(lines=window.count(b"\n"))
        overhead = json_len({"number": n, "diff": "", "truncated": True, "hint": widest_hint})
        diff, cut = fit_head(window.decode("utf-8", errors="replace"), MAX_DIFF_CHARS - overhead)
        truncated = cut or body.truncated
        result: dict[str, Any] = {"number": n, "diff": diff, "truncated": truncated}
        if truncated:
            result["hint"] = _DIFF_HINT.format(lines=diff.count("\n"))
        return result

    async def get_pr_checks(
        self, owner: str, repo: str, number: Any, limit: Any = None
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        n = positive_int(number, "number")
        count = clamp_limit(limit)
        pr = as_object(await self._get_json(f"{base}/pulls/{n}"))
        sha = nested_str(pr, "head", "sha", max_chars=40)
        if not sha or not is_sha(sha):
            raise ConnectorError("Malformed response from GitHub.")
        commit = f"{base}/commits/{path_segment(sha)}"
        runs_data, status_data = await asyncio.gather(
            self._get_json(f"{commit}/check-runs", params={"per_page": CHECK_RUNS_PAGE}),
            self._get_json(f"{commit}/status", params={"per_page": CHECK_RUNS_PAGE}),
        )
        checks = [
            {
                "name": run.get("name") if isinstance(run.get("name"), str) else None,
                "kind": "check",
                "outcome": _check_outcome(run.get("status"), run.get("conclusion")),
                **scalars(run, "status", "conclusion", "html_url", "completed_at"),
            }
            for run in as_list(as_object(runs_data).get("check_runs") or [])
        ]
        checks += [
            {
                "name": st.get("context") if isinstance(st.get("context"), str) else None,
                "kind": "status",
                "outcome": _status_outcome(st.get("state")),
                **scalars(st, "state", "target_url", "updated_at"),
                **scalars(st, "description", max_chars=200),
            }
            for st in as_list(as_object(status_data).get("statuses") or [])
        ]
        order = {"failed": 0, "pending": 1, "passed": 2}
        checks.sort(key=lambda c: order[c["outcome"]])
        summary = {k: sum(1 for c in checks if c["outcome"] == k) for k in order}
        total_runs = as_object(runs_data).get("total_count")
        result: dict[str, Any] = {
            "number": n,
            "head_sha": sha,
            "summary": summary,
            "checks": checks[:count],
            "truncated": len(checks) > count,
        }
        if isinstance(total_runs, int) and total_runs > CHECK_RUNS_PAGE:
            result["note"] = (
                f"Only the first {CHECK_RUNS_PAGE} of {total_runs} check runs were counted."
            )
        if result["truncated"]:
            result["hint"] = "More checks exist; call get_pr_checks with a larger limit (max 50)."
        return result

    async def list_reviews(
        self, owner: str, repo: str, number: Any, limit: Any = None
    ) -> list[dict[str, Any]]:
        n = positive_int(number, "number")
        per_page = clamp_limit(limit)
        data = await self._get_json(
            f"{repo_path(owner, repo)}/pulls/{n}/reviews", params={"per_page": per_page}
        )
        return [
            {
                **scalars(r, "id", "state", "submitted_at", "html_url"),
                "author": login(r.get("user")),
                **body_fields(
                    r.get("body"),
                    MAX_REVIEW_CHARS,
                    f"Review cut at {MAX_REVIEW_CHARS} characters; the full text is at html_url.",
                ),
            }
            for r in as_list(data)[:per_page]
        ]

    async def create_pr(
        self,
        owner: str,
        repo: str,
        title: str,
        head: str,
        base: str,
        body: Optional[str] = None,
        draft: Any = False,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        path = repo_path(owner, repo)
        head_ref = text_arg(head, "head", max_chars=300)
        head_branch = (head_ref or "").split(":", 1)[-1]
        git_ref(head_branch, "head")
        payload: dict[str, Any] = {
            "title": text_arg(title, "title", max_chars=256),
            "head": head_ref,
            "base": git_ref(base, "base"),
            "draft": flag(draft, "draft") if draft is not None else False,
        }
        text = text_arg(body, "body", required=False)
        if text is not None:
            payload["body"] = text
        require_confirmation(
            user_confirmed,
            "create_pr",
            f"Open a {'draft ' if payload['draft'] else ''}pull request in {owner}/{repo} from "
            f"'{head_ref}' into '{payload['base']}' titled '{preview(payload['title'], 120)}'.",
        )
        return _pr_summary(as_object(await self._send_json("POST", f"{path}/pulls", json=payload)))

    async def review_pr(
        self,
        owner: str,
        repo: str,
        number: Any,
        event: str,
        body: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        path = repo_path(owner, repo)
        n = positive_int(number, "number")
        verdict = choice(event, "event", _REVIEW_EVENTS) or "comment"
        text = text_arg(body, "body", required=verdict != "approve")
        require_confirmation(
            user_confirmed,
            "review_pr",
            f"Submit a review as you on {owner}/{repo}#{n}: "
            f"{verdict.replace('_', ' ').upper()}"
            + (f", with the text: {preview(text)}" if text else "."),
        )
        payload: dict[str, Any] = {"event": verdict.upper()}
        if text:
            payload["body"] = text
        data = as_object(await self._send_json("POST", f"{path}/pulls/{n}/reviews", json=payload))
        return {**scalars(data, "id", "state", "html_url", "submitted_at"), "number": n}

    async def request_reviewers(
        self,
        owner: str,
        repo: str,
        number: Any,
        reviewers: Optional[list[str]] = None,
        team_reviewers: Optional[list[str]] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        path = repo_path(owner, repo)
        n = positive_int(number, "number")
        people = string_list(reviewers, "reviewers", max_items=15) or []
        teams = string_list(team_reviewers, "team_reviewers", max_items=15) or []
        if not people and not teams:
            raise ConnectorError("request_reviewers needs reviewers or team_reviewers.")
        require_confirmation(
            user_confirmed,
            "request_reviewers",
            f"Ask {', '.join(people + ['team ' + t for t in teams])} to review {owner}/{repo}#{n}.",
        )
        payload: dict[str, Any] = {}
        if people:
            payload["reviewers"] = people
        if teams:
            payload["team_reviewers"] = teams
        data = as_object(
            await self._send_json("POST", f"{path}/pulls/{n}/requested_reviewers", json=payload)
        )
        return {
            "number": n,
            "requested_reviewers": names(data.get("requested_reviewers"), "login"),
            "requested_teams": names(data.get("requested_teams"), "slug"),
        }

    async def merge_pr(
        self,
        owner: str,
        repo: str,
        number: Any,
        merge_method: Optional[str] = None,
        commit_title: Optional[str] = None,
        commit_message: Optional[str] = None,
        sha: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        path = repo_path(owner, repo)
        n = positive_int(number, "number")
        method = choice(merge_method, "merge_method", _MERGE_METHODS, "merge") or "merge"
        payload: dict[str, Any] = {"merge_method": method}
        if commit_title is not None:
            payload["commit_title"] = text_arg(commit_title, "commit_title", max_chars=256)
        if commit_message is not None:
            payload["commit_message"] = text_arg(commit_message, "commit_message", required=False)
        if sha is not None:
            expected = sha.strip() if isinstance(sha, str) else ""
            if not is_sha(expected):
                raise ConnectorError("sha must be a 40-character commit SHA.")
            payload["sha"] = expected
        require_confirmation(
            user_confirmed,
            "merge_pr",
            f"Merge pull request {owner}/{repo}#{n} with the '{method}' method"
            + (f" (only if its head is still {payload['sha'][:7]})" if "sha" in payload else "")
            + ". This changes the target branch.",
        )
        data = as_object(await self._send_json("PUT", f"{path}/pulls/{n}/merge", json=payload))
        return {"number": n, **scalars(data, "merged", "sha", "message")}
