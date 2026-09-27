"""GitHub Actions workflow actions: list and read runs, fetch the logs of
failed jobs, re-run failed jobs, dispatch a workflow and cancel a run.

Why it exists: the "Actions" row of the GitHub table in the connectors spec
(section 5.2). ``services/connectors/github.py`` mixes ``WorkflowsMixin``
into ``GitHubConnector`` and lists ``WORKFLOW_ACTIONS`` in its DEFINITION.
``get_failed_logs`` is a long-result action the runtime budgets by name.

Connects to: the GitHub REST API (``/repos/<o>/<r>/actions/...``). Job logs
are served by a 302 redirect to a short-lived pre-signed download URL on
Azure blob storage (``productionresultssa*.blob.core.windows.net``, or the
legacy ``pipelines.actions.githubusercontent.com``); httpx drops our
Authorization header on that cross-origin hop and the network policy lets
the download host serve only credential-free GETs. Depends on
``github_api.common`` and ``services.connectors.shaping``.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import clamp_limit

from .common import (
    API,
    ENVELOPE_RESERVE,
    LIMIT_PROP,
    LONG_RESULT_CHARS,
    OWNER_PROP,
    REPO_PROP,
    GitHubApiBase,
    as_object,
    choice,
    fit_tail,
    git_ref,
    json_len,
    json_text_cost,
    list_field,
    positive_int,
    repo_path,
    require_confirmation,
    scalars,
)

# JSON characters of the whole get_failed_logs result. The runtime shows the
# model LONG_RESULT_CHARS of it (its github.get_failed_logs budget) and drops
# the MIDDLE of anything longer, which would cut away the error at the end of
# every job's log but the last. The job summaries come first; the rest is
# shared between the fetched logs (a short log leaves its unused share to
# the others), so every job's tail, error line included, arrives whole.
FAILED_LOGS_BUDGET = LONG_RESULT_CHARS - ENVELOPE_RESERVE
# JSON characters kept from the END of one job's log, whatever is left over.
MAX_LOG_TAIL_CHARS = 6_000
# Only the end of a downloaded log is decoded and cleaned: this many bytes
# (or characters) comfortably hold MAX_LOG_TAIL_CHARS of text once per-line
# timestamps (about 30 characters a line) and colour codes are removed.
LOG_WINDOW = 16 * MAX_LOG_TAIL_CHARS
# Room for the top-level fields of the result (run_id, message or hint).
_LOG_RESULT_SLACK = 160
# Failed jobs whose logs one get_failed_logs call downloads (default 3).
MAX_LOG_JOBS = 5
# Jobs listed for a run (one page).
JOBS_PAGE = 50
MAX_WORKFLOW_INPUTS = 25

_FAILED = frozenset({"failure", "timed_out", "startup_failure"})
_RUN_STATUSES = (
    "completed",
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "success",
    "timed_out",
    "in_progress",
    "queued",
    "requested",
    "waiting",
    "pending",
)
_WORKFLOW_FILE_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}\.ya?ml$")
_INPUT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,99}$")
# "2024-05-01T10:00:00.1234567Z " at the start of every log line.
_LOG_TIMESTAMP_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ", re.MULTILINE)
# Terminal colour and cursor codes, then any other control character but
# tab and newline: noise to the model, and six JSON characters each.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_LOG_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_LOG_HINT = "Only the end of the log is shown; html_url opens the whole log."

_RUN_ID_PROP = {
    "type": "integer",
    "description": "Workflow run id (from list_runs)",
    "required": True,
}

WORKFLOW_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_runs",
        "List recent GitHub Actions workflow runs, optionally for one workflow, branch or status.",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            workflow={"type": "string", "description": "Workflow file name (ci.yml) or id"},
            branch={"type": "string"},
            status={"type": "string", "enum": list(_RUN_STATUSES)},
            limit=LIMIT_PROP,
        ),
        required_scope="actions.read",
    ),
    ToolSpec(
        "get_run",
        "Get one workflow run with its jobs and their failed steps.",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, run_id=_RUN_ID_PROP),
        required_scope="actions.read",
    ),
    ToolSpec(
        "get_failed_logs",
        "Get the end of the log of each failed job in a workflow run (the part with the error).",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            run_id=_RUN_ID_PROP,
            limit={
                "type": "integer",
                "description": "Failed jobs to fetch logs for (default 3, max 5)",
            },
        ),
        required_scope="actions.read",
    ),
    ToolSpec(
        "rerun_failed_jobs",
        "Re-run the failed jobs of a workflow run (and the jobs that depend on them).",
        ActionCategory.EXECUTE,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, run_id=_RUN_ID_PROP),
        required_scope="actions.write",
    ),
    ToolSpec(
        "dispatch_workflow",
        "Start a workflow that has a workflow_dispatch trigger, on a branch or tag, with inputs.",
        ActionCategory.EXECUTE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            workflow={
                "type": "string",
                "description": "Workflow file name (deploy.yml) or id",
                "required": True,
            },
            ref={"type": "string", "description": "Branch or tag to run on", "required": True},
            inputs={"type": "object", "description": "Workflow inputs (name to string value)"},
        ),
        required_scope="actions.write",
        always_confirm=True,
    ),
    ToolSpec(
        "cancel_run",
        "Cancel a queued or running workflow run.",
        ActionCategory.DELETE,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, run_id=_RUN_ID_PROP),
        required_scope="actions.write",
        always_confirm=True,
    ),
)


def _workflow_segment(value: Any) -> str:
    """A workflow id or ``.yml``/``.yaml`` file name, as one path segment."""
    if isinstance(value, int) and not isinstance(value, bool):
        return str(positive_int(value, "workflow"))
    text = value.strip() if isinstance(value, str) else ""
    if text.isdigit():
        return str(positive_int(text, "workflow"))
    if not _WORKFLOW_FILE_RE.fullmatch(text) or text.startswith("."):
        raise ConnectorError("workflow must be a workflow id or a file name like 'ci.yml'.")
    return path_segment(text)


def _run_summary(item: Any) -> dict[str, Any]:
    return scalars(
        item,
        "id",
        "name",
        "display_title",
        "status",
        "conclusion",
        "event",
        "head_branch",
        "head_sha",
        "run_number",
        "run_attempt",
        "created_at",
        "updated_at",
        "html_url",
    )


def _failed_steps(job: dict[str, Any]) -> list[str]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [
        str(s["name"])[:200]
        for s in steps
        if isinstance(s, dict) and s.get("conclusion") in _FAILED and isinstance(s.get("name"), str)
    ][:10]


def _job_summary(job: dict[str, Any]) -> dict[str, Any]:
    return {
        **scalars(
            job, "id", "name", "status", "conclusion", "started_at", "completed_at", "html_url"
        ),
        "failed_steps": _failed_steps(job),
    }


def clean_log(text: str, *, starts_mid_line: bool = False) -> str:
    """*text* without per-line timestamps, colour codes and control
    characters. *starts_mid_line* drops the partial first line of a log
    window that did not start at the beginning of the log."""
    if starts_mid_line:
        newline = text.find("\n")
        text = text[newline + 1 :] if newline >= 0 else ""
    text = _ANSI_RE.sub("", _LOG_TIMESTAMP_RE.sub("", text))
    return _LOG_CONTROL_RE.sub("", text)


def log_tail(text: str, max_chars: int = MAX_LOG_TAIL_CHARS) -> tuple[str, bool]:
    """The end of a job log costing at most *max_chars* JSON characters,
    cleaned by ``clean_log``.

    Returns ``(tail, truncated)``. Only the last LOG_WINDOW characters are
    cleaned, so the work does not grow with the size of the log. The cut
    starts at a line boundary when one is near, so the first line is whole.
    """
    window = text[-LOG_WINDOW:]
    cut_window = len(window) < len(text)
    tail, cut = fit_tail(clean_log(window, starts_mid_line=cut_window), max_chars)
    return tail, cut or cut_window


def share_budget(costs: list[int], total: int) -> list[int]:
    """Split *total* between items that each need ``costs[i]``: no item gets
    more than it needs, and what a small item leaves goes to the larger ones."""
    shares = [0] * len(costs)
    remaining = max(0, total)
    order = sorted(range(len(costs)), key=costs.__getitem__)
    for position, index in enumerate(order):
        share = min(costs[index], remaining // (len(order) - position))
        shares[index] = share
        remaining -= share
    return shares


def _fill_log_tails(
    entries: list[dict[str, Any]],
    logs: list[tuple[str, bool, Optional[str]]],
    budget: int,
) -> None:
    """Add each job's log tail (or log error) to its entry, in place, so the
    JSON of the result holding *entries* stays within *budget*.

    The entries are first measured with every fetched log empty and flagged
    as cut (hint included); the rest of the budget is shared between the
    logs by what each one needs, capped at MAX_LOG_TAIL_CHARS.
    """
    fetched: list[int] = []
    for index, (_, _, error) in enumerate(logs):
        if error is not None:
            entries[index]["log_error"] = error
        else:
            entries[index].update(log_tail="", truncated=True, hint=_LOG_HINT)
            fetched.append(index)
    if not fetched:
        return
    available = budget - json_len(entries) - _LOG_RESULT_SLACK
    costs = [min(json_text_cost(logs[i][0]), MAX_LOG_TAIL_CHARS) for i in fetched]
    for index, share in zip(fetched, share_budget(costs, available), strict=True):
        text, cut_window, _ = logs[index]
        tail, cut = fit_tail(text, share)
        entry = entries[index]
        entry["log_tail"] = tail
        entry["truncated"] = cut or cut_window
        if not entry["truncated"]:
            del entry["hint"]


class WorkflowsMixin(GitHubApiBase):
    """GitHub Actions actions (one public coroutine per WORKFLOW_ACTIONS entry)."""

    async def list_runs(
        self,
        owner: str,
        repo: str,
        workflow: Any = None,
        branch: Optional[str] = None,
        status: Optional[str] = None,
        limit: Any = None,
    ) -> list[dict[str, Any]]:
        base = repo_path(owner, repo)
        per_page = clamp_limit(limit)
        params: dict[str, Any] = {"per_page": per_page}
        if branch is not None:
            params["branch"] = git_ref(branch, "branch")
        if status is not None:
            params["status"] = choice(status, "status", _RUN_STATUSES)
        path = (
            f"{base}/actions/workflows/{_workflow_segment(workflow)}/runs"
            if workflow is not None
            else f"{base}/actions/runs"
        )
        data = await self._get_json(path, params=params)
        return [_run_summary(run) for run in list_field(data, "workflow_runs")[:per_page]]

    async def get_run(self, owner: str, repo: str, run_id: Any) -> dict[str, Any]:
        base = repo_path(owner, repo)
        run = positive_int(run_id, "run_id")
        run_data, jobs_data = await asyncio.gather(
            self._get_json(f"{base}/actions/runs/{run}"),
            self._get_json(
                f"{base}/actions/runs/{run}/jobs",
                params={"filter": "latest", "per_page": JOBS_PAGE},
            ),
        )
        jobs = list_field(jobs_data, "jobs")
        return {
            **_run_summary(as_object(run_data)),
            "jobs": [_job_summary(job) for job in jobs],
            "failed_jobs": sum(1 for job in jobs if job.get("conclusion") in _FAILED),
        }

    async def get_failed_logs(
        self, owner: str, repo: str, run_id: Any, limit: Any = None
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        run = positive_int(run_id, "run_id")
        count = clamp_limit(limit, default=3, maximum=MAX_LOG_JOBS)
        jobs = list_field(
            await self._get_json(
                f"{base}/actions/runs/{run}/jobs",
                params={"filter": "latest", "per_page": JOBS_PAGE},
            ),
            "jobs",
        )
        failed = [
            job
            for job in jobs
            if job.get("conclusion") in _FAILED
            and isinstance(job.get("id"), int)
            and not isinstance(job.get("id"), bool)
            and job["id"] > 0
        ]
        selected = failed[:count]
        logs = await asyncio.gather(*(self._job_log(base, job["id"]) for job in selected))
        entries = [_job_summary(job) for job in selected]
        _fill_log_tails(entries, list(logs), FAILED_LOGS_BUDGET)
        result: dict[str, Any] = {"run_id": run, "failed_jobs": entries}
        if not failed:
            result["message"] = "No job failed in the latest attempt of this run."
        elif len(failed) > count:
            result["hint"] = (
                f"{len(failed)} jobs failed; logs are shown for {count}. "
                "Call get_failed_logs with a larger limit (max 5)."
            )
        return result

    async def _job_log(self, base: str, job_id: int) -> tuple[str, bool, Optional[str]]:
        """``(cleaned end of the log, whether earlier text was dropped, error)``
        for one failed job.

        The logs endpoint answers 302 to a pre-signed download URL; the
        request follows it (at most MAX_REDIRECTS hops, each policy
        checked) and httpx strips our Authorization header on that
        cross-origin hop. The log is streamed and only its last LOG_WINDOW
        bytes are kept, decoded and cleaned, so a many-megabyte log costs
        no more memory or event-loop time than a short one. A job whose log
        cannot be fetched (expired logs answer 410) reports why instead of
        failing the whole call.
        """
        try:
            body = await self._request_bytes(
                "GET",
                f"{API}{base}/actions/jobs/{job_id}/logs",
                max_bytes=LOG_WINDOW,
                tail=True,
                follow_redirects=True,
            )
        except ConnectorError as exc:
            if type(exc) is not ConnectorError:
                raise  # authentication and rate-limit errors concern every job
            return "", False, str(exc)
        text = body.content.decode("utf-8", errors="replace")
        return clean_log(text, starts_mid_line=body.truncated), body.truncated, None

    async def rerun_failed_jobs(
        self, owner: str, repo: str, run_id: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        run = positive_int(run_id, "run_id")
        require_confirmation(
            user_confirmed,
            "rerun_failed_jobs",
            f"Re-run the failed jobs of workflow run {run} in {owner}/{repo}.",
        )
        await self._send_json("POST", f"{base}/actions/runs/{run}/rerun-failed-jobs")
        return {"run_id": run, "rerun_requested": True}

    async def dispatch_workflow(
        self,
        owner: str,
        repo: str,
        workflow: Any,
        ref: str,
        inputs: Optional[dict[str, Any]] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        segment = _workflow_segment(workflow)
        target = git_ref(ref, "ref")
        values = _workflow_inputs(inputs)
        require_confirmation(
            user_confirmed,
            "dispatch_workflow",
            f"Start workflow '{workflow}' in {owner}/{repo} on '{target}'"
            + (f" with inputs {values}" if values else "")
            + ". It runs with the repository's secrets and permissions.",
        )
        payload: dict[str, Any] = {"ref": target}
        if values:
            payload["inputs"] = values
        data = await self._send_json(
            "POST", f"{base}/actions/workflows/{segment}/dispatches", json=payload
        )
        result: dict[str, Any] = {"workflow": str(workflow), "ref": target, "dispatched": True}
        if isinstance(data, dict):
            result.update(scalars(data, "workflow_run_id", "html_url"))
        return result

    async def cancel_run(
        self, owner: str, repo: str, run_id: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        run = positive_int(run_id, "run_id")
        require_confirmation(
            user_confirmed,
            "cancel_run",
            f"Cancel workflow run {run} in {owner}/{repo}. Jobs still running are stopped.",
        )
        await self._send_json("POST", f"{base}/actions/runs/{run}/cancel")
        return {"run_id": run, "cancel_requested": True}


def _workflow_inputs(inputs: Any) -> dict[str, str]:
    """Workflow inputs as GitHub expects them: names to string values."""
    if inputs is None:
        return {}
    if not isinstance(inputs, dict):
        raise ConnectorError("inputs must be an object mapping input names to values.")
    if len(inputs) > MAX_WORKFLOW_INPUTS:
        raise ConnectorError(f"A workflow takes at most {MAX_WORKFLOW_INPUTS} inputs.")
    values: dict[str, str] = {}
    for name, value in inputs.items():
        if not isinstance(name, str) or not _INPUT_NAME_RE.fullmatch(name):
            raise ConnectorError("Input names must be identifiers like 'environment'.")
        if isinstance(value, bool):
            values[name] = "true" if value else "false"
        elif isinstance(value, (str, int, float)):
            text = str(value)
            if len(text) > 10_000:
                raise ConnectorError(f"Input '{name}' is too long.")
            values[name] = text
        else:
            raise ConnectorError(f"Input '{name}' must be a string, number or boolean.")
    return values
