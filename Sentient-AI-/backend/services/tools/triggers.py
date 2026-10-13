"""Implements the triggers.* built-in tools (create, list, history, update,
delete) and the same owner operations for the /triggers chat commands and the
REST routes.

Why it exists: a trigger reads a connected app on its own and messages the
owner, or runs a task, for as long as it exists, so every way one is made or
changed goes through one set of rules:
- ownership: ``user_id`` is the caller's identity as the executor (or the
  route) knows it, never a tool argument; a foreign or unknown id reads as
  "not found";
- the account: the trigger is pinned to one connector row of a type the
  source supports, named by its tool namespace (``google_workspace`` or
  ``google_workspace__1a2b3c4d``) or, when exactly one row fits, left out;
  the row must grant the source's read scope. The card's async bind writes
  the resolved row into the reserved ``_account`` argument (the model may
  never supply it), and the approved call must resolve to that same row;
- the switches: ``run_task`` needs "trigger_runs" on and the unattended
  runner wired; ``page.changed`` needs "page_watch" on and one of the
  caller's own watches;
- limits: 10 triggers per user, no duplicate rule (a fingerprint), bounded
  intervals and daily runs, an exact sender allowlist for a mail task.

The approval card's hooks live here too: ``precheck`` (every rule above,
before any card, filed under ``trigger_rule``), ``bind`` (``_account`` and,
for a change, the trigger as it is now under ``_trigger``) and ``describe``
(the card's sentence, from facts). Tool errors are results, never
exceptions; nothing here logs a filter, a prompt or an address.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Optional

import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from services.triggers import RUNS_CAPABILITY, TRIGGER_RULE_POLICY
from services.triggers import facts as shape
from services.triggers import sources as src

logger = structlog.get_logger(__name__)

__all__ = ["TRIGGER_RULE_POLICY", "TriggerToolkit"]

# The event_triggers columns are these sizes (models/event_trigger.py).
LABEL_MAX_CHARS = 80
PROMPT_MAX_CHARS = 600
MAX_TRIGGERS_PER_USER = 10
RUNS_PER_DAY = (1, 24, 6)
HISTORY_LIMIT = (1, 10, 10)
PROMPT_PREVIEW_CHARS = 200
# triggers.list and triggers.history keep their rows, as the model is shown
# them, within these many characters, so RESULT_CHAR_BUDGETS (6000 and
# 5000, runtime.py) hold the whole answer; raise both together.
LIST_ROWS_CHARS = 5000
HISTORY_ROWS_CHARS = 4200

ACCOUNT_KEY = "_account"
TRIGGER_KEY = "_trigger"
RESERVED_ARGS = frozenset({ACCOUNT_KEY, TRIGGER_KEY})
MODES = ("notify", "run_task")

_CREATE_KEYS = frozenset(
    {
        "label",
        "source",
        "account",
        "senders",
        "subject_contains",
        "folder",
        "course_ids",
        "show_score",
        "lead_minutes",
        "watch_id",
        "mode",
        "prompt",
        "allow_writes",
        "interval_minutes",
        "max_runs_per_day",
    }
)
_UPDATE_KEYS = frozenset(
    {
        "trigger_id",
        "paused",
        "label",
        "senders",
        "subject_contains",
        "course_ids",
        "show_score",
        "lead_minutes",
        "prompt",
        "allow_writes",
        "interval_minutes",
        "max_runs_per_day",
    }
)
_IMMUTABLE_KEYS = frozenset({"source", "account", "mode", "folder", "watch_id"})
_UPDATE_FILTERS = ("senders", "subject_contains", "course_ids", "show_score", "lead_minutes")
_ACCOUNT_RE = re.compile(r"^([a-z][a-z0-9_]{1,31}?)(?:__([0-9a-f]{8}))?$")
_LINE_SEPARATORS = (chr(0x2028), chr(0x2029))
# Rules that are a refusal the owner should see as blocked (not the model's
# own mistake, which it fixes by asking the user or calling again).
_REFUSAL_RULES = frozenset(
    {
        "runs_off",
        "runner_unavailable",
        "page_watch_off",
        "trigger_limit",
        "secret",
        "account_scope",
        "reserved_argument",
        "account_changed",
    }
)

CapabilityGate = Callable[[], Awaitable[Mapping[str, Any]]]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _error(message: str, *, rule: str = "invalid_arguments", **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "error": message, "rule": rule, **extra}
    if rule in _REFUSAL_RULES:
        result["refused"] = True
    return result


def _not_found() -> dict[str, Any]:
    return _error("Trigger not found. Call triggers.list for the ids.", rule="not_found", not_found=True)


def _shown_chars(value: Any) -> int:
    from services.agent.prompt_guard import _INVISIBLE_CHARS

    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return len(_INVISIBLE_CHARS.sub(lambda m: json.dumps(m.group())[1:-1], text))


# -- Argument rules ------------------------------------------------------------


def clean_label(value: Any) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(value, str) or not value.strip():
        return None, "A short 'label' is required, e.g. 'Prof. Smith emails'."
    if any(ord(ch) < 32 or 0x7F <= ord(ch) < 0xA0 or ch in _LINE_SEPARATORS for ch in value):
        return None, "The label must be one line with no control characters."
    label = " ".join(value.split())
    if len(label) > LABEL_MAX_CHARS:
        return None, f"The label is too long ({len(label)} chars; max {LABEL_MAX_CHARS})."
    return label, None


def _clean_prompt(value: Any) -> tuple[Optional[str], Optional[str], str]:
    """(prompt, error, rule)."""
    from services.tools.memory import looks_like_secret

    if not isinstance(value, str) or not value.strip():
        return None, "A 'prompt' is required for run_task: what to do each time, in the user's own words.", "invalid_arguments"
    if "\x00" in value:
        return None, "The prompt must not contain null bytes.", "invalid_arguments"
    prompt = value.strip()
    if len(prompt) > PROMPT_MAX_CHARS:
        return None, f"The prompt is too long ({len(prompt)} chars; max {PROMPT_MAX_CHARS}).", "invalid_arguments"
    if looks_like_secret(prompt):
        return (
            None,
            "The prompt looks like it holds a password, key, token or card number. "
            "Triggers never store secrets; write it without one.",
            "secret",
        )
    return prompt, None, ""


def _runs_per_day(value: Any) -> tuple[Optional[int], Optional[str]]:
    low, high, default = RUNS_PER_DAY
    if value is None:
        return default, None
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        return None, f"'max_runs_per_day' must be a whole number from {low} to {high}."
    return value, None


@dataclass(frozen=True)
class TriggerSpec:
    """A new trigger, validated except for what needs the database."""

    label: str
    source: str
    account: Optional[str]
    filters: dict[str, Any]
    mode: str
    prompt: Optional[str]
    allow_writes: bool
    interval_minutes: int
    max_runs_per_day: int


def validate_create(params: Mapping[str, Any]) -> tuple[Optional[TriggerSpec], Optional[dict[str, Any]]]:
    """The triggers.create rules that need no database: ``(spec, None)`` or
    ``(None, error result)``. The reserved bound keys are not the model's
    and are ignored here (the precheck refuses them when the model sends
    them)."""
    params = {k: v for k, v in params.items() if k not in RESERVED_ARGS}
    unknown = sorted(set(params) - _CREATE_KEYS)
    if unknown:
        return None, _error(f"Unknown argument(s) for triggers.create: {', '.join(unknown)}.")
    label, err = clean_label(params.get("label"))
    if err or label is None:
        return None, _error(err or "Invalid label.")
    source = params.get("source")
    if not isinstance(source, str) or source not in src.SOURCES:
        return None, _error(f"'source' must be one of: {', '.join(src.SOURCES)}.")
    account = params.get("account")
    if account is not None:
        if not isinstance(account, str) or not _ACCOUNT_RE.match(account.strip()):
            return None, _error(
                "'account' must be a connector name from your tool names, e.g. google_workspace "
                "or google_workspace__1a2b3c4d."
            )
        account = account.strip()
    filters, err = src.validate_filters(source, params)
    if err or filters is None:
        return None, _error(err or "Invalid filters.")
    mode = params.get("mode") or "notify"
    if mode not in MODES:
        return None, _error("'mode' must be notify (a message) or run_task (run a task).")
    prompt: Optional[str] = None
    if mode == "run_task":
        if source == "page.changed":
            return None, _error(
                "A page-change trigger can only notify you: a task run could not read the page."
            )
        prompt, err, rule = _clean_prompt(params.get("prompt"))
        if err or prompt is None:
            return None, _error(err or "Invalid prompt.", rule=rule or "invalid_arguments")
        if source == "email.new" and not filters.get("senders"):
            return None, _error(
                "A mail trigger that runs a task needs 'senders': the exact addresses or "
                "@domains whose mail may start it."
            )
    elif params.get("prompt") is not None:
        return None, _error("'prompt' is only for mode run_task.")
    allow_writes = params.get("allow_writes", False)
    if allow_writes is None:
        allow_writes = False
    if not isinstance(allow_writes, bool):
        return None, _error("'allow_writes' must be true or false.")
    if allow_writes and mode != "run_task":
        return None, _error("'allow_writes' is only for mode run_task.")
    interval, err = src.interval_for(source, params.get("interval_minutes"))
    if err or interval is None:
        return None, _error(err or "Invalid interval.")
    runs, err = _runs_per_day(params.get("max_runs_per_day"))
    if err or runs is None:
        return None, _error(err or "Invalid max_runs_per_day.")
    return (
        TriggerSpec(
            label=label,
            source=source,
            account=account,
            filters=filters,
            mode=mode,
            prompt=prompt,
            allow_writes=allow_writes,
            interval_minutes=interval,
            max_runs_per_day=runs,
        ),
        None,
    )


def fingerprint(
    source: str, connector_id: Optional[str], filters: Mapping[str, Any], mode: str, prompt: Optional[str]
) -> str:
    """sha256 of the canonical rule: the same rule twice is a duplicate."""
    canonical = json.dumps(
        {
            "source": source,
            "connector_id": connector_id,
            "filters": dict(filters),
            "mode": mode,
            "prompt": prompt,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Account:
    """One connector row a trigger can be pinned to."""

    connector_id: str
    connector_type: str
    label: str
    namespace: str
    scopes: tuple[str, ...]

    def bound(self) -> dict[str, str]:
        return {"connector_id": self.connector_id, "type": self.connector_type, "label": self.label}


@dataclass(frozen=True)
class Plan:
    """A validated trigger with its account resolved and its limits checked."""

    spec: TriggerSpec
    account: Optional[Account]
    fingerprint: str
    watch_label: Optional[str] = None


class TriggerToolkit:
    """Executes the ``triggers.*`` actions for one caller, and the owner's
    own operations (list, pause, resume, delete) for the chat commands and
    the REST routes.

    ``session_factory`` is the application's; without one every action is
    refused (fail closed). ``capability_gate`` answers the owner's report by
    key (the executor's; unwired, the registry defaults apply, so the
    off-by-default switches stay off). ``runner_available`` says whether the
    unattended runner is wired (main.py sets it; unset, task runs are
    refused). ``clock`` is a test seam."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        *,
        capability_gate: Optional[CapabilityGate] = None,
        runner_available: Optional[Callable[[], bool]] = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._session_factory = session_factory
        self._gate = capability_gate
        self._runner_available = runner_available
        self._clock = clock

    def set_runner_available(self, check: Optional[Callable[[], bool]]) -> None:
        self._runner_available = check

    # -- Dispatch ------------------------------------------------------------

    async def execute(
        self, action: str, params: dict[str, Any], user_id: str, *, approved: bool = False
    ) -> dict[str, Any]:
        """Run one ``triggers.*`` action as *user_id* (the executor's). A
        change runs only approved (the executor refuses it before that, so
        this is the second lock). Unknown actions and arguments fail closed."""
        params = {k: v for k, v in (params or {}).items() if k != "user_id"}
        try:
            if action == "list":
                if params:
                    return _error("triggers.list takes no arguments.")
                return await self.list_triggers(user_id)
            if action == "history":
                return await self.history(user_id, params)
            if action in ("create", "update", "delete"):
                if not approved:
                    return _error(
                        f"triggers.{action} runs only after the user approves its card.",
                        rule="requires_approval",
                        requires_approval=True,
                    )
                if action == "create":
                    return await self.create(user_id, params)
                if action == "update":
                    return await self.update(user_id, params)
                return await self.delete(user_id, params)
            return _error(f"Unknown triggers action '{action}'.")
        except SQLAlchemyError as exc:
            logger.error("trigger_tool_db_error", action=action, error_type=type(exc).__name__)
            return _error("Trigger storage is unavailable; try again shortly.", rule="storage")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error("trigger_tool_unexpected_error", action=action, error_type=type(exc).__name__)
            return _error(f"Trigger action failed: {type(exc).__name__}", rule="storage")

    # -- Helpers -------------------------------------------------------------

    def _ready(self, user_id: Any) -> tuple[Optional[uuid.UUID], Optional[dict[str, Any]]]:
        if self._session_factory is None:
            return None, _error("Triggers are not configured (no database).", rule="storage")
        try:
            return uuid.UUID(str(user_id)), None
        except (TypeError, ValueError):
            return None, _error("Triggers need a signed-in user.", rule="storage")

    async def _capability_on(self, key: str) -> bool:
        """Whether capability *key* is effectively on; a gate that fails, or
        no gate and an off-by-default capability, is off."""
        if self._gate is None:
            from services import capabilities as registry

            try:
                return bool(registry.get(key).default_enabled)
            except KeyError:
                return False
        try:
            status = (await self._gate()).get(key)
        except Exception as exc:
            logger.warning("trigger_gate_unreadable", capability=key, error_type=type(exc).__name__)
            return False
        return status is not None and getattr(status, "effective", None) == "on"

    def _runner_ready(self) -> bool:
        check = self._runner_available
        if check is None:
            return False
        try:
            return check() is True
        except Exception:
            return False

    async def _accounts(self, session: Any, owner: uuid.UUID, types: tuple[str, ...]) -> list[Account]:
        """The caller's active rows of *types*, each under the namespace its
        tools are offered under (plain for a type's only row)."""
        from models.connector import ConnectorConfig, connector_type_key
        from services.agent.tool_registry import connector_slug

        if not types:
            return []
        rows = (
            (
                await session.execute(
                    select(ConnectorConfig).where(
                        ConnectorConfig.user_id == owner,
                        ConnectorConfig.is_active.is_(True),
                        ConnectorConfig.connector_type.in_(list(types)),
                    )
                )
            )
            .scalars()
            .all()
        )
        counts: dict[str, int] = {}
        for row in rows:
            key = connector_type_key(row.connector_type)
            counts[key] = counts.get(key, 0) + 1
        accounts = []
        for row in sorted(rows, key=lambda r: (connector_type_key(r.connector_type), str(r.id))):
            kind = connector_type_key(row.connector_type)
            namespace = kind if counts[kind] == 1 else f"{kind}__{connector_slug(str(row.id))}"
            accounts.append(
                Account(
                    connector_id=str(row.id),
                    connector_type=kind,
                    label=shape.clean_line(row.display_name, 40) or kind,
                    namespace=namespace,
                    scopes=tuple(s for s in (row.granted_scopes or []) if isinstance(s, str)),
                )
            )
        return accounts

    async def resolve_account(
        self, session: Any, owner: uuid.UUID, source: str, account: Optional[str]
    ) -> tuple[Optional[Account], Optional[dict[str, Any]]]:
        """The row *account* names for *source* (or the only one that fits
        when it is left out), or why there is none. A slug that matches none
        of the caller's rows (another user's, a deleted one) is unknown."""
        spec = src.SPECS[source]
        if not spec.connector_types:
            if account is not None:
                return None, _error(f"{source} triggers use no connected account; leave 'account' out.")
            return None, None
        candidates = await self._accounts(session, owner, spec.connector_types)
        choices = ", ".join(f"{a.namespace} ({a.label})" for a in candidates)
        if account is None:
            if not candidates:
                apps = " or ".join(src.source_app(source, t) for t in spec.connector_types)
                return None, _error(
                    f"No connected account can do this: connect {apps} in Connectors first.",
                    rule="no_account",
                )
            if len(candidates) > 1:
                return None, _error(
                    f"Several connected accounts can do this; name one in 'account': {choices}.",
                    rule="ambiguous_account",
                )
            found: Optional[Account] = candidates[0]
        else:
            match = _ACCOUNT_RE.match(account)
            kind, slug = (match.group(1), match.group(2)) if match else ("", None)
            if kind not in spec.connector_types:
                return None, _error(
                    f"'{account}' cannot be used for {source}; it needs one of: "
                    f"{', '.join(spec.connector_types)}.",
                    rule="unknown_account",
                )
            if slug is not None:
                found = next((a for a in candidates if a.connector_type == kind and a.namespace == account), None)
            else:
                of_kind = [a for a in candidates if a.connector_type == kind]
                if len(of_kind) > 1:
                    listed = ", ".join(f"{a.namespace} ({a.label})" for a in of_kind)
                    return None, _error(
                        f"You have several {kind} accounts; name one in 'account': {listed}.",
                        rule="ambiguous_account",
                    )
                found = of_kind[0] if of_kind else None
            if found is None:
                return None, _error(
                    f"No connected account '{account}'."
                    + (f" Yours: {choices}." if choices else " Connect one in Connectors first."),
                    rule="unknown_account",
                )
        assert found is not None
        required = src.required_scope(source, found.connector_type)
        if required and found.scopes and required not in found.scopes:
            return None, _error(
                f"The {found.label} account does not grant '{required}', which this trigger "
                "reads with. The owner can grant it by editing the connector.",
                rule="account_scope",
            )
        return found, None

    async def plan(
        self, user_id: Any, spec: TriggerSpec, *, exclude: Optional[uuid.UUID] = None
    ) -> tuple[Optional[Plan], Optional[dict[str, Any]]]:
        """Resolve the account and check the switches, the watch, the
        per-user limit and duplicates. Reads the database only."""
        from models.event_trigger import EventTrigger

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return None, refusal
        assert self._session_factory is not None
        from services import capabilities as registry

        if spec.mode == "run_task":
            if not await self._capability_on(RUNS_CAPABILITY):
                return None, _error(registry.get(RUNS_CAPABILITY).when_denied, rule="runs_off")
            if not self._runner_ready():
                return None, _error(
                    "Task runs are not available right now (the runner is not set up); a "
                    "notify trigger still works.",
                    rule="runner_unavailable",
                )
        watch_label: Optional[str] = None
        async with self._session_factory() as session:
            account, refusal = await self.resolve_account(session, owner, spec.source, spec.account)
            if refusal is not None:
                return None, refusal
            if account is not None:
                err = src.check_filters_for(spec.source, account.connector_type, spec.filters)
                if err:
                    return None, _error(err)
            if spec.source == "page.changed":
                if not await self._capability_on("page_watch"):
                    return None, _error(registry.get("page_watch").when_denied, rule="page_watch_off")
                from models.page_watch import PageWatch

                watch = (
                    await session.execute(
                        select(PageWatch.label).where(
                            PageWatch.id == uuid.UUID(spec.filters["watch_id"]),
                            PageWatch.user_id == owner,
                        )
                    )
                ).scalar_one_or_none()
                if watch is None:
                    return None, _error(
                        "No page watch with that id. watch.list shows the user's watches.",
                        rule="watch_not_found",
                    )
                watch_label = shape.clean_line(watch, 80)
            count_query = select(func.count()).select_from(EventTrigger).where(EventTrigger.user_id == owner)
            if exclude is not None:
                count_query = count_query.where(EventTrigger.id != exclude)
            if exclude is None and (await session.execute(count_query)).scalar_one() >= MAX_TRIGGERS_PER_USER:
                return None, _error(
                    f"You already have {MAX_TRIGGERS_PER_USER} triggers, the most allowed. Delete "
                    "one first (triggers.list shows them).",
                    rule="trigger_limit",
                )
            print_ = fingerprint(
                spec.source, account.connector_id if account else None, spec.filters, spec.mode, spec.prompt
            )
            dup_query = select(EventTrigger.id).where(
                EventTrigger.user_id == owner, EventTrigger.fingerprint == print_
            )
            if exclude is not None:
                dup_query = dup_query.where(EventTrigger.id != exclude)
            if (await session.execute(dup_query)).first() is not None:
                return None, _error(
                    "You already have a trigger with exactly this rule (triggers.list shows it).",
                    rule="duplicate",
                    duplicate=True,
                )
        return Plan(spec=spec, account=account, fingerprint=print_, watch_label=watch_label), None

    async def _owned(self, owner: uuid.UUID, trigger_id: Any) -> Optional[Any]:
        from models.event_trigger import EventTrigger

        try:
            target = uuid.UUID(str(trigger_id))
        except (TypeError, ValueError):
            return None
        assert self._session_factory is not None
        async with self._session_factory() as session:
            return (
                await session.execute(
                    select(EventTrigger).where(EventTrigger.id == target, EventTrigger.user_id == owner)
                )
            ).scalar_one_or_none()

    async def _account_labels(self, owner: uuid.UUID) -> dict[str, str]:
        from models.connector import ConnectorConfig

        assert self._session_factory is not None
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ConnectorConfig.id, ConnectorConfig.display_name).where(
                        ConnectorConfig.user_id == owner
                    )
                )
            ).all()
        return {str(r.id): shape.clean_line(r.display_name, 40) for r in rows}

    # -- Approval card hooks -------------------------------------------------

    async def precheck(self, action: str, params: dict[str, Any], user_id: str) -> Optional[dict[str, Any]]:
        """The result a call would get even once approved, when that is
        knowable now (reading the database, touching nothing); None to ask
        for approval as usual."""
        params = {k: v for k, v in (params or {}).items() if k != "user_id"}
        if action not in ("create", "update", "delete"):
            return None
        reserved = sorted(RESERVED_ARGS & set(params))
        if reserved:
            return _error(
                f"{', '.join(reserved)} is set by Crawler, never given.", rule="reserved_argument"
            )
        if action == "create":
            spec, refusal = validate_create(params)
            if refusal is not None or spec is None:
                return refusal
            _plan, refusal = await self.plan(user_id, spec)
            return refusal
        _row, refusal = await self._change(user_id, action, params, check_only=True)
        return refusal

    async def bind(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """The arguments the card stores and the approved call runs with:
        for create, the resolved account under ``_account`` (and a watch's
        label under ``_trigger``); for update and delete, the trigger as it
        is now under ``_trigger`` (for the card's before and after). A rule
        that fails now answers a refusal instead."""
        params = {k: v for k, v in (params or {}).items() if k not in RESERVED_ARGS and k != "user_id"}
        if action == "create":
            spec, refusal = validate_create(params)
            if spec is None or refusal is not None:
                return {**(refusal or _error("Invalid trigger.")), "refused": True}
            plan, refusal = await self.plan(user_id, spec)
            if plan is None:
                return {**(refusal or _error("Invalid trigger.")), "refused": True}
            bound: dict[str, Any] = {
                **params,
                ACCOUNT_KEY: plan.account.bound() if plan.account is not None else None,
            }
            if plan.watch_label:
                bound[TRIGGER_KEY] = {"watch": plan.watch_label}
            return bound
        if action in ("update", "delete"):
            row, refusal = await self._change(user_id, action, params, check_only=True)
            if row is None:
                return {**(refusal or _not_found()), "refused": True}
            labels = await self._account_labels(row.user_id)
            return {**params, TRIGGER_KEY: _snapshot(row, labels.get(str(row.connector_id or ""), ""))}
        return params

    def describe(self, action: str, params: Mapping[str, Any], user_id: str) -> Optional[str]:
        """The approval card's sentence, from the (bound) arguments; None
        when they do not make a valid call."""
        params = dict(params or {})
        if action == "create":
            spec, refusal = validate_create(params)
            if spec is None or refusal is not None:
                return None
            bound = _bound if isinstance((_bound := params.get(ACCOUNT_KEY)), Mapping) else {}
            extra = _extra if isinstance((_extra := params.get(TRIGGER_KEY)), Mapping) else {}
            return describe_rule(
                spec.source,
                connector_type=str(bound.get("type") or "") or None,
                account_label=str(bound.get("label") or ""),
                filters=spec.filters,
                mode=spec.mode,
                prompt=spec.prompt,
                allow_writes=spec.allow_writes,
                interval=spec.interval_minutes,
                max_runs=spec.max_runs_per_day,
                watch_label=str(extra.get("watch") or ""),
            )
        before = _before if isinstance((_before := params.get(TRIGGER_KEY)), Mapping) else None
        name = f'"{shape.clean_line(before.get("label"), 80)}"' if before else f"trigger {params.get('trigger_id')}"
        if action == "delete":
            what = f" ({src.SPECS[before['source']].phrase})" if before and before.get("source") in src.SPECS else ""
            return f"Delete the trigger {name}{what} and its queued events. Its conversation is kept."
        if action == "update":
            return describe_update(name, params, before)
        return None

    # -- Actions -------------------------------------------------------------

    async def create(self, user_id: str, params: dict[str, Any]) -> dict[str, Any]:
        """Save an approved trigger for the caller. The account must still
        resolve to the row bound on the card."""
        from models.event_trigger import EventTrigger

        if ACCOUNT_KEY not in params:
            return _error(
                "This trigger's card has no bound account; ask again so a new card is made.",
                rule="account_changed",
            )
        bound = params.get(ACCOUNT_KEY)
        spec, refusal = validate_create(params)
        if spec is None or refusal is not None:
            return refusal or _error("Invalid trigger.")
        plan, refusal = await self.plan(user_id, spec)
        if plan is None or refusal is not None:
            return refusal or _error("Invalid trigger.")
        resolved = plan.account.connector_id if plan.account is not None else None
        wanted = bound.get("connector_id") if isinstance(bound, Mapping) else None
        if resolved != wanted:
            return _error(
                "The account this trigger would read is not the one on the approved card; nothing "
                "was saved. Ask again so the card shows the right account.",
                rule="account_changed",
            )
        owner = uuid.UUID(str(user_id))
        now = self._clock()
        trigger_id = uuid.uuid4()
        assert self._session_factory is not None
        async with self._session_factory() as session:
            session.add(
                EventTrigger(
                    id=trigger_id,
                    user_id=owner,
                    label=spec.label,
                    source=spec.source,
                    connector_id=uuid.UUID(resolved) if resolved else None,
                    filters=dict(spec.filters),
                    fingerprint=plan.fingerprint,
                    mode=spec.mode,
                    prompt=spec.prompt,
                    allow_writes=spec.allow_writes,
                    interval_minutes=spec.interval_minutes,
                    max_runs_per_day=spec.max_runs_per_day,
                    runs_today=0,
                    status="active",
                    # A page.changed trigger needs no baseline: the page
                    # watch reports only changes after this.
                    baseline_at=now if spec.source == "page.changed" else None,
                    next_check_at=now,
                    consecutive_errors=0,
                    created_at=now,
                    updated_at=now,
                )
            )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return _error("You already have a trigger with exactly this rule.", rule="duplicate", duplicate=True)
        result: dict[str, Any] = {
            "ok": True,
            "trigger_id": str(trigger_id),
            "label": spec.label,
            "source": spec.source,
            "account": plan.account.label if plan.account else None,
            "mode": spec.mode,
            "status": "active",
        }
        if spec.source != "page.changed":
            result["note"] = "The first check records what is there now; only newer items fire."
        return result

    async def list_triggers(self, user_id: str) -> dict[str, Any]:
        """The caller's triggers, oldest first. Never event content."""
        from models.event_trigger import EventTrigger

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _error("Triggers need a signed-in user.")
        assert self._session_factory is not None
        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(EventTrigger)
                        .where(EventTrigger.user_id == owner)
                        .order_by(EventTrigger.created_at, EventTrigger.id)
                    )
                )
                .scalars()
                .all()
            )
        labels = await self._account_labels(owner)
        today = self._clock().date()
        shown: list[dict[str, Any]] = []
        used = 0
        for row in rows:
            item = trigger_row(row, labels.get(str(row.connector_id or ""), ""), today=today)
            size = _shown_chars(item) + 1
            if used + size > LIST_ROWS_CHARS:
                break
            shown.append(item)
            used += size
        result: dict[str, Any] = {"ok": True, "count": len(rows), "triggers": shown}
        if len(shown) < len(rows):
            result["note"] = f"Only the oldest {len(shown)} of {len(rows)} triggers fit in this list."
        return result

    async def history(self, user_id: str, params: dict[str, Any]) -> dict[str, Any]:
        """Recent fires of one of the caller's triggers: when, how many
        items, what became of them, and a few capped facts per item
        (untrusted content, as any tool result)."""
        from models.event_trigger import TriggerEvent

        extra = sorted(set(params) - {"trigger_id", "limit"})
        if extra:
            return _error("triggers.history takes trigger_id and limit only.")
        low, high, default = HISTORY_LIMIT
        limit = params.get("limit", default)
        if limit is None:
            limit = default
        if isinstance(limit, bool) or not isinstance(limit, int) or not low <= limit <= high:
            return _error(f"'limit' must be a whole number from {low} to {high}.")
        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _not_found()
        row = await self._owned(owner, params.get("trigger_id"))
        if row is None:
            return _not_found()
        assert self._session_factory is not None
        async with self._session_factory() as session:
            events = (
                (
                    await session.execute(
                        select(TriggerEvent)
                        .where(TriggerEvent.trigger_id == row.id, TriggerEvent.user_id == owner)
                        .order_by(TriggerEvent.detected_at.desc(), TriggerEvent.id)
                        .limit(limit * shape.MAX_ITEMS_PER_BATCH)
                    )
                )
                .scalars()
                .all()
            )
        groups: dict[str, list[Any]] = {}
        for event in events:
            key = str(event.batch_id or event.id)
            if key not in groups and len(groups) >= limit:
                continue
            groups.setdefault(key, []).append(event)
        fires: list[dict[str, Any]] = []
        used = 0
        for batch in groups.values():
            first = batch[0]
            fire: dict[str, Any] = {
                "detected_at": shape.iso(_utc(first.detected_at)),
                "items": len(batch),
                "outcome": first.status,
            }
            notes = [e.note for e in batch if e.note]
            if notes:
                fire["note"] = shape.clean_line(notes[0], 100)
            # Facts last: untrusted text, a few capped fields per item.
            facts = [f for f in (shape.history_fact(e.facts) for e in batch) if f]
            if facts:
                fire["facts"] = facts
            size = _shown_chars(fire) + 1
            if used + size > HISTORY_ROWS_CHARS:
                break
            fires.append(fire)
            used += size
        return {
            "ok": True,
            "trigger_id": str(row.id),
            "label": row.label,
            "source": row.source,
            "fires": fires,
        }

    async def _change(
        self, user_id: Any, action: str, params: Mapping[str, Any], *, check_only: bool = False
    ) -> tuple[Optional[Any], Optional[dict[str, Any]]]:
        """The caller's trigger an update or delete names, with the update
        validated against it, or the refusal."""
        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return None, refusal
        params = {k: v for k, v in params.items() if k not in RESERVED_ARGS}
        if action == "delete":
            extra = sorted(set(params) - {"trigger_id"})
            if extra:
                return None, _error("triggers.delete takes only trigger_id.")
        else:
            fixed = sorted(_IMMUTABLE_KEYS & set(params))
            if fixed:
                return None, _error(
                    f"{', '.join(fixed)} cannot be changed; delete the trigger and create a new one."
                )
            extra = sorted(set(params) - _UPDATE_KEYS)
            if extra:
                return None, _error(f"Unknown argument(s) for triggers.update: {', '.join(extra)}.")
        row = await self._owned(owner, params.get("trigger_id"))
        if row is None:
            return None, _not_found()
        if action == "update":
            _values, refusal = await self._update_values(row, params)
            if refusal is not None:
                return None, refusal
        return row, None

    async def _update_values(
        self, row: Any, params: Mapping[str, Any]
    ) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]:
        """The column values an update sets, validated for the trigger's
        source and mode, or the refusal."""
        values: dict[str, Any] = {}
        if "paused" in params:
            if not isinstance(params["paused"], bool):
                return None, _error("'paused' must be true (pause) or false (resume).")
        if params.get("label") is not None:
            label, err = clean_label(params["label"])
            if err or label is None:
                return None, _error(err or "Invalid label.")
            values["label"] = label
        if any(params.get(k) is not None for k in _UPDATE_FILTERS):
            merged = dict(row.filters or {})
            for key in _UPDATE_FILTERS:
                if params.get(key) is not None:
                    merged[key] = params[key]
            filters, err = src.validate_filters(row.source, merged)
            if err or filters is None:
                return None, _error(err or "Invalid filters.")
            values["filters"] = filters
        mode = row.mode
        if params.get("prompt") is not None:
            if mode != "run_task":
                return None, _error("'prompt' is only for a trigger that runs a task.")
            prompt, err, rule = _clean_prompt(params["prompt"])
            if err or prompt is None:
                return None, _error(err or "Invalid prompt.", rule=rule or "invalid_arguments")
            values["prompt"] = prompt
        if params.get("allow_writes") is not None:
            if not isinstance(params["allow_writes"], bool):
                return None, _error("'allow_writes' must be true or false.")
            if params["allow_writes"] and mode != "run_task":
                return None, _error("'allow_writes' is only for a trigger that runs a task.")
            values["allow_writes"] = params["allow_writes"]
        if params.get("interval_minutes") is not None:
            interval, err = src.interval_for(row.source, params["interval_minutes"])
            if err or interval is None:
                return None, _error(err or "Invalid interval.")
            values["interval_minutes"] = interval
        if params.get("max_runs_per_day") is not None:
            runs, err = _runs_per_day(params["max_runs_per_day"])
            if err or runs is None:
                return None, _error(err or "Invalid max_runs_per_day.")
            values["max_runs_per_day"] = runs
        if not values and "paused" not in params:
            return None, _error("Nothing to change: give paused or a field to update.")
        filters = values.get("filters", row.filters or {})
        if row.source == "email.new" and mode == "run_task" and not filters.get("senders"):
            return None, _error("A mail trigger that runs a task must keep at least one sender.")
        if "filters" in values or "prompt" in values:
            print_ = fingerprint(
                row.source,
                str(row.connector_id) if row.connector_id else None,
                filters,
                mode,
                values.get("prompt", row.prompt),
            )
            from models.event_trigger import EventTrigger

            assert self._session_factory is not None
            async with self._session_factory() as session:
                clash = (
                    await session.execute(
                        select(EventTrigger.id).where(
                            EventTrigger.user_id == row.user_id,
                            EventTrigger.fingerprint == print_,
                            EventTrigger.id != row.id,
                        )
                    )
                ).first()
            if clash is not None:
                return None, _error(
                    "Another of your triggers already has exactly this rule.", rule="duplicate", duplicate=True
                )
            values["fingerprint"] = print_
        return values, None

    async def update(self, user_id: str, params: dict[str, Any]) -> dict[str, Any]:
        """Apply an approved change; resuming clears the error count and
        checks again now."""
        from models.event_trigger import EventTrigger

        row, refusal = await self._change(user_id, "update", params)
        if row is None or refusal is not None:
            return refusal or _not_found()
        values, refusal = await self._update_values(row, params)
        if values is None or refusal is not None:
            return refusal or _error("Invalid change.")
        now = self._clock()
        if params.get("paused") is True:
            values["status"] = "paused"
        elif params.get("paused") is False:
            values.update(_resumed(row.source, now))
        values["updated_at"] = now
        assert self._session_factory is not None
        async with self._session_factory() as session:
            current = await session.get(EventTrigger, row.id)
            if current is None or current.user_id != row.user_id:
                return _not_found()
            for key, value in values.items():
                setattr(current, key, value)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return _error("Another of your triggers already has exactly this rule.", rule="duplicate", duplicate=True)
            label, status = current.label, current.status
        changed = sorted(
            k
            for k in values
            if k not in ("updated_at", "fingerprint", "next_check_at", "consecutive_errors", "last_error", "baseline_at", "cursor")
        )
        return {"ok": True, "trigger_id": str(row.id), "label": label, "status": status, "changed": changed}

    async def delete(self, user_id: str, params: dict[str, Any]) -> dict[str, Any]:
        row, refusal = await self._change(user_id, "delete", params)
        if row is None or refusal is not None:
            return refusal or _not_found()
        return await self.delete_trigger(user_id, row.id)

    # -- The owner's own operations (chat commands, REST) ----------------------

    async def set_paused(self, user_id: Any, trigger_id: Any, paused: bool) -> dict[str, Any]:
        """Pause, or resume with the error count cleared and a check now.
        The owner's own action: no card (the command or route is theirs)."""
        from models.event_trigger import EventTrigger

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _not_found()
        row = await self._owned(owner, trigger_id)
        if row is None:
            return _not_found()
        now = self._clock()
        assert self._session_factory is not None
        async with self._session_factory() as session:
            current = await session.get(EventTrigger, row.id)
            if current is None or current.user_id != owner:
                return _not_found()
            if paused:
                current.status = "paused"
            else:
                for key, value in _resumed(current.source, now).items():
                    setattr(current, key, value)
            current.updated_at = now
            label, status = current.label, current.status
            await session.commit()
        return {"ok": True, "trigger_id": str(row.id), "label": label, "status": status}

    async def delete_trigger(self, user_id: Any, trigger_id: Any) -> dict[str, Any]:
        """Delete one of the caller's triggers and its queued events; its
        conversation is kept."""
        from models.event_trigger import EventTrigger

        owner, refusal = self._ready(user_id)
        if refusal is not None or owner is None:
            return refusal or _not_found()
        row = await self._owned(owner, trigger_id)
        if row is None:
            return _not_found()
        assert self._session_factory is not None
        async with self._session_factory() as session:
            current = await session.get(EventTrigger, row.id)
            if current is None or current.user_id != owner:
                return _not_found()
            label = current.label
            await session.delete(current)
            await session.commit()
        return {"ok": True, "trigger_id": str(row.id), "label": label, "deleted": True}


def _resumed(source: str, now: datetime) -> dict[str, Any]:
    """The columns a resume sets: active, the error count cleared, a check
    now, and a new baseline, so what arrived while the trigger was paused
    or stopped is recorded as seen rather than sent as a backlog (a
    page.changed trigger has no baseline to take)."""
    return {
        "status": "active",
        "consecutive_errors": 0,
        "last_error": None,
        "next_check_at": now,
        "baseline_at": now if source == "page.changed" else None,
        "cursor": None,
    }


def _snapshot(row: Any, account_label: str) -> dict[str, Any]:
    """The trigger as a card shows it before a change."""
    return {
        "label": row.label,
        "source": row.source,
        "account": account_label,
        "mode": row.mode,
        "status": row.status,
        "filters": dict(row.filters or {}),
        "prompt": (row.prompt or "")[:PROMPT_PREVIEW_CHARS] if row.prompt else None,
        "allow_writes": bool(row.allow_writes),
        "interval_minutes": row.interval_minutes,
        "max_runs_per_day": row.max_runs_per_day,
    }


def trigger_row(row: Any, account_label: str, *, today: Any = None) -> dict[str, Any]:
    """One trigger as triggers.list, the REST list and the chat commands
    show it: never event content."""
    runs_today = row.runs_today if today is None or row.runs_day == today else 0
    item: dict[str, Any] = {
        "id": str(row.id),
        "label": row.label,
        "source": row.source,
        "account": account_label or None,
        "mode": row.mode,
        "status": row.status,
        "interval_minutes": row.interval_minutes or None,
        "filters": dict(row.filters or {}),
        "last_checked_at": shape.iso(_utc(row.last_checked_at)),
        "last_fired_at": shape.iso(_utc(row.last_fired_at)),
    }
    if row.mode == "run_task":
        prompt = row.prompt or ""
        item["prompt"] = prompt[:PROMPT_PREVIEW_CHARS]
        item["prompt_truncated"] = len(prompt) > PROMPT_PREVIEW_CHARS
        item["allow_writes"] = bool(row.allow_writes)
        item["runs_today"] = runs_today or 0
        item["max_runs_per_day"] = row.max_runs_per_day
    if row.consecutive_errors:
        item["consecutive_errors"] = row.consecutive_errors
    if row.last_error:
        item["last_error"] = row.last_error[:100]
    return item


def _join(words: list[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


def describe_rule(
    source: str,
    *,
    connector_type: Optional[str],
    account_label: str,
    filters: Mapping[str, Any],
    mode: str,
    prompt: Optional[str],
    allow_writes: bool,
    interval: int,
    max_runs: int,
    watch_label: str = "",
) -> str:
    """One plain sentence stating the whole rule, e.g. 'When a new email
    from smith@univ.edu arrives in Gmail (School), run "Summarise it" and
    message you the result. Checks every 15 min, at most 6 runs a day,
    read-only.'"""
    app = src.source_app(source, connector_type)
    where = f"{app} ({account_label})" if account_label else app
    courses = list(filters.get("course_ids") or [])
    in_courses = f" in course{'s' if len(courses) > 1 else ''} {', '.join(courses)}" if courses else ""
    if source == "email.new":
        senders = list(filters.get("senders") or [])
        when = "When a new email"
        if senders:
            when += f" from {_join(senders)}"
        if filters.get("subject_contains"):
            when += f" with \"{filters['subject_contains']}\" in the subject"
        when += f" arrives in {where}"
        if filters.get("folder"):
            when += f" (folder {filters['folder']})"
    elif source == "canvas.announcement":
        when = f"When a new announcement is posted in {where}{in_courses}"
    elif source == "canvas.assignment":
        when = f"When a new assignment shows up in {where}{in_courses}"
    elif source == "canvas.grade":
        score = "with the score" if filters.get("show_score") else "without the score"
        when = f"When a grade is posted in {where}{in_courses} ({score})"
    elif source == "calendar.starting_soon":
        when = f"{filters.get('lead_minutes', 15)} minutes before each event on {where} starts"
    elif source == "files.new_in_folder":
        when = f"When a new file lands in folder {filters.get('folder')} of {where}"
    else:
        when = f"When your page watch \"{watch_label or filters.get('watch_id')}\" sees a change"
    if mode == "run_task":
        short = shape.clean_line(prompt or "", 160)
        does = f', run "{short}" and message you the result'
    else:
        does = ", message you on Telegram or Slack"
    tail: list[str] = []
    if source != "page.changed":
        tail.append(f"Checks every {interval} min")
    if mode == "run_task":
        tail.append(f"at most {max_runs} runs a day")
        tail.append(
            "any change it wants waits for your approval" if allow_writes else "read-only"
        )
    sentence = f"{when}{does}."
    if tail:
        text = ", ".join(tail)
        sentence += f" {text[0].upper()}{text[1:]}."
    return sentence


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "none"
    if value is None or value == "":
        return "none"
    return shape.clean_line(str(value), 120)


def describe_update(name: str, params: Mapping[str, Any], before: Optional[Mapping[str, Any]]) -> str:
    """The update card's sentence: pause, resume, or each change as
    before -> after."""
    if params.get("paused") is True and not any(k for k in params if k not in ("trigger_id", "paused", TRIGGER_KEY)):
        return f"Pause the trigger {name}; nothing is checked or sent until you resume it."
    changes: list[str] = []
    old_filters = dict(before.get("filters") or {}) if before else {}
    for key in ("label", "prompt", "allow_writes", "interval_minutes", "max_runs_per_day"):
        if params.get(key) is not None:
            old = before.get(key) if before else None
            changes.append(f"{key.replace('_', ' ')}: {_value(old)} → {_value(params[key])}")
    for key in _UPDATE_FILTERS:
        if params.get(key) is not None:
            changes.append(f"{key.replace('_', ' ')}: {_value(old_filters.get(key))} → {_value(params[key])}")
    head = f"Change the trigger {name}"
    if params.get("paused") is True:
        head += " and pause it"
    elif params.get("paused") is False:
        head = (
            f"Resume the trigger {name} (checks start again now, its error count is cleared, "
            "and what arrived meanwhile is not sent)"
        )
        if changes:
            head += " and change it"
    return head + (": " + "; ".join(changes) + "." if changes else ".")
