"""Serves Security -> Tool rules (/api/security/tool-rules): the built-in rules and their
switches, the owner's own rules on tool arguments, a preview of what a draft rule would cover,
and the catalog of tools a rule can name.

Why it exists: a rule turns matching calls into approval cards that name it (decisions 3),
install-wide, so every route is owner-only (``require_admin``: 401 signed out, 403 for anyone
else) and web-only, like the tutor locks: no chat command, channel or tool can add or lift a
rule. Rules may only narrow what runs automatically; a change that loosens protection (a rule
removed, a built-in turned off) is the kind a stolen web session would make, so the owner gets
a fact-only notice on every linked channel after it is committed (best effort: a failed or
skipped notice never undoes the change). A refused rule is a 422 whose detail is the
validator's plain reason, shown on the page as sent. Nothing here quotes a condition value in
a log line or an audit row (store.py audits ids, names and a digest).

Connects to: services/security/tool_rules (``app.state.tool_rules_store`` for every read and
write, ``app.state.tool_rules_check`` for the switch), ``app.state.org_domains`` (S1's
``OrgDomains.for_user``, shown read-only), ``app.state.owner_send`` (owner notices).
Used by: the Security page's Tool rules tab (frontend/src/pages/security/ToolRulesTab.tsx);
main.py mounts the router under /api.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes._deps import require_admin
from core.database import get_db
from models.user import User
from services.capabilities.tool_rules import KEY as CAPABILITY_KEY
from services.security.tool_rules import grammar, texts
from services.security.tool_rules.builtins import BUILTINS, builtin
from services.security.tool_rules.check import ToolRulesCheck
from services.security.tool_rules.engine import OwnerRule
from services.security.tool_rules.grammar import RuleValidationError
from services.security.tool_rules.store import ToolRuleStore

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/security/tool-rules", tags=["security"])

# The preview lists at most this many matching catalog tools.
MAX_PREVIEW_MATCHES = 50
MCP_HINT = "mcp.<server>.<tool>"
NOT_WIRED = "Tool rules are not available right now."
NOT_SAVED = "The tool rules could not be read or saved just now. Try again in a moment."
NO_SUCH_RULE = "No such tool rule."
NO_SUCH_BUILTIN = "No such built-in rule."


class ConditionOut(BaseModel):
    arg: str
    op: str
    value: Any


class ToolRuleOut(BaseModel):
    id: str
    name: str
    tool: str
    conditions: list[ConditionOut]
    summary: str
    created_at: str
    # The email of the account that made the rule; None once that account is gone.
    created_by: Optional[str] = None


class BuiltinRuleOut(BaseModel):
    key: str
    name: str
    description: str
    enabled: bool
    changed_at: Optional[str] = None


class OperatorOut(BaseModel):
    op: str
    label: str
    value: Literal["text", "list", "number", "pattern"]


class ToolRulesView(BaseModel):
    # The "tool_rules" switch (Settings -> Permissions): while it is off nothing applies.
    enabled: bool
    # False when the rules could not be read: Crawler then asks before every change.
    store_ok: bool
    builtins: list[BuiltinRuleOut]
    rules: list[ToolRuleOut]
    # The owner's organisation domains (rule B3), read-only here.
    org_domains: list[str]
    limits: dict[str, int]
    operators: list[OperatorOut]


class ToolRuleCreate(BaseModel):
    # Loosely typed on purpose: the validator answers every bad shape with its own plain
    # reason (a 422 detail the page shows as is), not a schema error.
    name: Any = None
    tool: Any = None
    conditions: Any = None


class ToolRuleDraftIn(BaseModel):
    tool: Any = None
    conditions: Any = None


class BuiltinSwitch(BaseModel):
    enabled: bool


class PreviewMatch(BaseModel):
    tool: str
    category: str


class ToolRulePreview(BaseModel):
    valid: bool
    error: Optional[str] = None
    summary: str = ""
    matches: list[PreviewMatch] = []
    # Over every matching catalog tool (not only the ones listed): reads + writes = all.
    reads: int = 0
    writes: int = 0
    mcp: bool = False
    truncated: bool = False


class CatalogTool(BaseModel):
    tool: str
    category: str
    args: list[str]


class ToolRuleCatalog(BaseModel):
    tools: list[CatalogTool]
    mcp_hint: str


# -- helpers ---------------------------------------------------------------------------------


def _store(request: Request) -> ToolRuleStore:
    store = getattr(request.app.state, "tool_rules_store", None)
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=NOT_WIRED)
    return store  # type: ignore[no-any-return]


def _iso(value: Optional[datetime]) -> Optional[str]:
    """ISO 8601 with the offset. Stored times are UTC; SQLite hands them back naive, so the
    page gets the same string for a rule whether it was just made or read back."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


async def _switch_on(request: Request) -> bool:
    """The owner's switch: through the wired check (a read error counts as on), else from the
    installation's capability report, else on (the capability's default)."""
    check = getattr(request.app.state, "tool_rules_check", None)
    if isinstance(check, ToolRulesCheck):
        return await check.switch_on()
    installation = getattr(request.app.state, "installation", None)
    if installation is None:
        return True
    try:
        return CAPABILITY_KEY in await installation.enabled_keys()
    except Exception as exc:  # noqa: BLE001 - a read error counts as on
        logger.warning("tool_rules_switch_unreadable", error_type=type(exc).__name__)
        return True


async def _org_domains(request: Request, owner: User) -> list[str]:
    helper = getattr(request.app.state, "org_domains", None)
    for_user = getattr(helper, "for_user", None)
    if for_user is None:
        return []
    try:
        return sorted(str(d) for d in await for_user(str(owner.id)))
    except Exception as exc:  # noqa: BLE001 - shown read-only; the rule itself fails closed
        logger.warning("tool_rules_org_domains_unreadable", error_type=type(exc).__name__)
        return []


async def _emails(db: AsyncSession, rules: list[OwnerRule]) -> dict[str, str]:
    ids: set[uuid.UUID] = set()
    for rule in rules:
        try:
            if rule.created_by:
                ids.add(uuid.UUID(rule.created_by))
        except ValueError:
            continue
    if not ids:
        return {}
    result = await db.execute(select(User.id, User.email).where(User.id.in_(ids)))
    return {str(row.id): row.email for row in result}


def _rule_out(rule: OwnerRule, emails: dict[str, str]) -> ToolRuleOut:
    return ToolRuleOut(
        id=rule.id,
        name=rule.name,
        tool=rule.tool,
        conditions=[ConditionOut(**c) for c in grammar.conditions_json(rule.conditions)],
        summary=(
            texts.rule_failed_note(rule.name, owner=True)
            if rule.unreadable
            else grammar.summarize(rule.tool, rule.conditions)
        ),
        created_at=_iso(rule.created_at) or "",
        created_by=emails.get(rule.created_by or ""),
    )


def _builtin_out(key: str, enabled: bool, changed_at: Optional[datetime]) -> BuiltinRuleOut:
    rule = builtin(key)
    assert rule is not None
    return BuiltinRuleOut(
        key=key,
        name=rule.name,
        description=rule.description,
        enabled=enabled,
        changed_at=_iso(changed_at),
    )


async def _notify(request: Request, owner: User, text: str, *, change: str) -> None:
    """Tell the acting owner on their channels that protection was loosened. Best effort: an
    absent sender is skipped and logged, a failed send is logged by type; the change stands."""
    send = getattr(request.app.state, "owner_send", None)
    if send is None:
        logger.info("tool_rules_owner_notice_skipped", change=change)
        return
    try:
        delivered = await send(str(owner.id), text)
    except Exception as exc:  # noqa: BLE001 - a notice never undoes the change
        logger.warning(
            "tool_rules_owner_notice_failed", change=change, error_type=type(exc).__name__
        )
        return
    if not delivered:
        logger.info("tool_rules_owner_notice_not_delivered", change=change)


def _invalid(exc: RuleValidationError) -> HTTPException:
    # 422 written as a number: Starlette renamed the constant and warns on the old name.
    return HTTPException(status_code=422, detail=str(exc))


def _unavailable(exc: Exception) -> HTTPException:
    """A store that could not be read or written: logged by type only, a 503 with a fixed
    sentence (nothing was changed)."""
    logger.warning("tool_rules_store_unreadable", error_type=type(exc).__name__)
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=NOT_SAVED)


# -- routes ----------------------------------------------------------------------------------


@router.get("", response_model=ToolRulesView)
async def list_tool_rules(
    request: Request,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ToolRulesView:
    """The built-in rules with their switches, the owner's rules oldest first, the limits and
    operators the form needs, and the owner's organisation domains. ``store_ok`` is False
    (and the lists show the fail-closed state) when the rules could not be read."""
    store = _store(request)
    store_ok = True
    rules: list[OwnerRule] = []
    states: dict[str, tuple[bool, Optional[datetime]]] = {}
    try:
        rules = await store.list_rules()
        states = await store.builtin_states()
    except Exception as exc:  # noqa: BLE001 - the page says so; the check fails closed
        logger.warning("tool_rules_store_unreadable", error_type=type(exc).__name__)
        store_ok, rules, states = False, [], {}
    emails = await _emails(db, rules)
    return ToolRulesView(
        enabled=await _switch_on(request),
        store_ok=store_ok,
        builtins=[
            _builtin_out(rule.key, *states.get(rule.key, (True, None))) for rule in BUILTINS
        ],
        rules=[_rule_out(rule, emails) for rule in rules],
        org_domains=await _org_domains(request, owner),
        limits=dict(grammar.LIMITS),
        operators=[OperatorOut.model_validate(option) for option in grammar.operator_options()],
    )


@router.post("", response_model=ToolRuleOut, status_code=status.HTTP_201_CREATED)
async def add_tool_rule(
    body: ToolRuleCreate,
    request: Request,
    owner: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ToolRuleOut:
    """Add one owner rule (validated and audited); 422 with the plain reason when the
    validator refuses it. Adding a rule only narrows, so no notice is sent."""
    store = _store(request)
    try:
        existing = await store.list_rules()
        draft = grammar.validate_rule(body.name, body.tool, body.conditions, existing=existing)
        rule = await store.create(str(owner.id), draft)
    except RuleValidationError as exc:
        raise _invalid(exc) from None
    except Exception as exc:  # noqa: BLE001 - nothing was saved
        raise _unavailable(exc) from None
    logger.info("tool_rule_created", rule_id=rule.id, conditions=len(rule.conditions))
    return _rule_out(rule, await _emails(db, [rule]))


@router.post("/preview", response_model=ToolRulePreview)
async def preview_tool_rule(
    body: ToolRuleDraftIn,
    _owner: User = Depends(require_admin),
) -> ToolRulePreview:
    """What a draft rule would cover: the catalog tools its glob matches (at most 50 listed,
    every one counted as a read or a write), whether it can match MCP tools, and its summary.
    An invalid draft answers valid: false with the reason (never a 422). Saves nothing."""
    matches: list[tuple[str, str]] = []
    can_mcp = False
    try:
        pattern = grammar.validate_tool_pattern(body.tool)
        matches, can_mcp = grammar.matching_tools(pattern)
    except RuleValidationError:
        pass  # validate_draft below gives the reason
    reads = sum(1 for _name, category in matches if category == "read")
    shown = [PreviewMatch(tool=name, category=category) for name, category in matches]
    counts: dict[str, Any] = {
        "matches": shown[:MAX_PREVIEW_MATCHES],
        "reads": reads,
        "writes": len(matches) - reads,
        "mcp": can_mcp,
        "truncated": len(shown) > MAX_PREVIEW_MATCHES,
    }
    try:
        draft = grammar.validate_draft(body.tool, body.conditions)
    except RuleValidationError as exc:
        return ToolRulePreview(valid=False, error=str(exc), **counts)
    return ToolRulePreview(
        valid=True, summary=grammar.summarize(draft.tool, draft.conditions), **counts
    )


@router.get("/catalog", response_model=ToolRuleCatalog)
async def tool_rule_catalog(_owner: User = Depends(require_admin)) -> ToolRuleCatalog:
    """Every tool a rule can name (the runtime's own tools are not among them), with its
    category and argument names, and how MCP tools are named."""
    return ToolRuleCatalog(
        tools=[
            CatalogTool(tool=name, category=category, args=args)
            for name, category, args in grammar.catalog()
        ],
        mcp_hint=MCP_HINT,
    )


@router.put("/builtins/{key}", response_model=BuiltinRuleOut)
async def set_builtin_tool_rule(
    key: str,
    body: BuiltinSwitch,
    request: Request,
    owner: User = Depends(require_admin),
) -> BuiltinRuleOut:
    """Switch one built-in rule on or off (audited when it changes). Turning one off loosens
    protection, so the owner gets a notice on their channels; turning one on does not."""
    rule = builtin(key)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NO_SUCH_BUILTIN)
    store = _store(request)
    try:
        changed = await store.set_builtin(str(owner.id), key, body.enabled)
    except Exception as exc:  # noqa: BLE001 - nothing was saved
        raise _unavailable(exc) from None
    if changed:
        logger.info("tool_rule_builtin_changed", key=key, enabled=body.enabled)
        if not body.enabled:
            await _notify(request, owner, texts.builtin_off_notice(rule.text), change="builtin_off")
    try:
        enabled, changed_at = (await store.builtin_states()).get(key, (body.enabled, None))
    except Exception as exc:  # noqa: BLE001 - the change is saved; answer what was asked
        logger.warning("tool_rules_store_unreadable", error_type=type(exc).__name__)
        enabled, changed_at = body.enabled, None
    return _builtin_out(key, enabled, changed_at)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_tool_rule(
    rule_id: str,
    request: Request,
    owner: User = Depends(require_admin),
) -> Response:
    """Remove one owner rule (audited); 404 when there is no such rule. Removing a rule
    loosens protection, so the owner gets a notice on their channels."""
    store = _store(request)
    try:
        rule = await store.delete(str(owner.id), rule_id)
    except Exception as exc:  # noqa: BLE001 - nothing was removed
        raise _unavailable(exc) from None
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NO_SUCH_RULE)
    logger.info("tool_rule_deleted", rule_id=rule.id)
    await _notify(request, owner, texts.rule_removed_notice(rule.name), change="rule_removed")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
