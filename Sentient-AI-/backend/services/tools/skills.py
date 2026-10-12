"""Implements the skills.* built-in tools: read a bundled skill's playbook
(skills.read), one of its reference files (skills.read_reference) and its
scan report (skills.scan_report). All three are reads.

Why it exists: the <available_skills> block gives the model only each
skill's name and description; this is how it reads the body on demand.
Every rule about which skill text may reach the model is applied here, on
every call:
- only a skill the loader marked ``ok`` (parsed, scanner-clean, pinned in
  manifest.json) is read, and its files are hashed again first
  (services.skills.loader.current_hash): a skill edited on disk after
  startup is refused and shows as ``changed`` from then on, while files
  that merely could not be read just now refuse that one call (rule
  ``unavailable``) and mark nothing;
- a skill the owner switched off in Settings → Skills (a ``skill_states``
  row with enabled false; no row means on) is refused; without a database
  every skill counts as on, and a database error refuses (fail closed);
- bodies come back as a list of sections split on Markdown headings, so the
  runtime's per-item prompt-guard redaction can never blank a whole skill;
- a result too long for its budget (READ_RESULT_CHARS, measured the way the
  runtime shows it) is refused rather than cut in the middle; a scan report
  keeps as many findings as fit SCAN_REPORT_CHARS and says how many there
  were.
skills.read lists the tools the skill names; the runtime loads the ones this
turn may use into the conversation and rewrites that list to say which it
loaded (AgentRuntime._load_skill_tools); skills.scan_report gives what any
skill declares (declared_tools, requires, at most MAX_TOOLS names a list),
whatever this turn has. Reading never grants a tool or an approval. An
audit row keeps which skill was read, its hash, status and counts, never
its text (skills_result_for_audit).
The skills are install-wide, so no call takes a user: unknown arguments, a
``user_id`` included, fail closed. Tool errors are results
(``{"ok": False, "error": ..., "rule": ...}``), never exceptions. The rules:
unknown_skill, skill_off, skill_unusable, skill_changed, unknown_reference,
invalid_arguments, too_large, storage (the switches could not be read) and
unavailable (the files could not be read just now, or anything unexpected).
"""

from __future__ import annotations

import asyncio
import dataclasses
import itertools
import re
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from models.skill_state import SkillState
from services.skills import manifest as skills_manifest
from services.skills.loader import (
    STATUS_CHANGED,
    SkillCatalog,
    SkillReadError,
    SkillRecord,
    bundled_catalog,
    current_hash,
    mark_changed,
    split_sections,
)
from services.skills.scanner import (
    KEY_PATTERN,
    MAX_NAME_CHARS,
    MAX_TOOLS,
    NAME_PATTERN,
    REFERENCES_DIR,
    TOOL_NAME_PATTERN,
)
from services.tools.text_budget import shown_length

logger = structlog.get_logger(__name__)

# Result sizes as the model is shown them (the whole result, measured by
# text_budget.shown_length). The budgets in runtime.py RESULT_CHAR_BUDGETS
# are these numbers: a 24,000-byte SKILL.md or reference (the loader's cap)
# fits READ_RESULT_CHARS with its JSON escaping, keys and section headings.
READ_RESULT_CHARS = 34000
SCAN_REPORT_CHARS = 8000
# Room kept in a scan report for its keys and the "more did not fit" note.
_REPORT_ROOM_CHARS = 400

_KEYS: dict[str, frozenset[str]] = {
    "read": frozenset({"name"}),
    "read_reference": frozenset({"name", "file"}),
    "scan_report": frozenset({"name"}),
}
# The longest reference path a call may name ("references/" plus a file
# name the scanner allows); anything longer cannot be one.
_MAX_FILE_ARG_CHARS = 96

SWITCHED_OFF_ERROR = (
    "The skill '{name}' is switched off. The owner can switch it on in Settings → Skills."
)
STORAGE_ERROR = "The skill switches could not be read; try again shortly."
UNREADABLE_ERROR = "The skill's files could not be read just now; try again shortly."


def _error(message: str, *, rule: str = "invalid_arguments", **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, "rule": rule, **extra}


def _unknown(action: str, params: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    unknown = sorted(str(k) for k in params if k not in _KEYS[action])
    if not unknown:
        return None
    shown = [k for k in unknown if k.replace("_", "").isalnum() and len(k) <= 24][:4]
    return _error(
        f"Unknown argument(s) for skills.{action}" + (f": {', '.join(shown)}." if shown else ".")
    )


def valid_skill_name(name: Any) -> bool:
    """Whether *name* is spelled like a skill name (a folder name the loader
    accepts), so it is safe to repeat in a reply or an audit row."""
    return (
        isinstance(name, str)
        and 0 < len(name) <= MAX_NAME_CHARS
        and NAME_PATTERN.fullmatch(name) is not None
    )


async def disabled_skill_names(session: AsyncSession) -> frozenset[str]:
    """The skills the owner switched off (a ``skill_states`` row with
    enabled false). A skill with no row is on. Raises on a database error;
    each caller decides how to fail closed."""
    rows = await session.execute(select(SkillState.name).where(SkillState.enabled.is_(False)))
    return frozenset(rows.scalars().all())


# What an audit row keeps of a skills.* result besides counts.
_AUDIT_KEYS = ("ok", "name", "file", "sha256", "status", "pinned", "rule", "findings_total")


def skills_result_for_audit(result: Any) -> Any:
    """What an audit row keeps of a skills.* result: which skill (and
    reference) was read, its hash, status and pin, a refusal's rule, the
    tools loaded, and counts. Never the playbook's text, a heading, a
    finding's message or a refusal's wording (``error`` becomes True)."""
    if not isinstance(result, dict):
        return result
    facts: dict[str, Any] = {
        key: result[key] for key in _AUDIT_KEYS if isinstance(result.get(key), (str, bool, int))
    }
    sections = result.get("sections")
    if isinstance(sections, list):
        facts["sections"] = len(sections)
        facts["chars"] = sum(
            len(item.get("text") or "") for item in sections if isinstance(item, dict)
        )
    references = result.get("references")
    if isinstance(references, list):
        facts["references"] = len(references)
    tools = result.get("tools")
    if isinstance(tools, list):
        facts["tools"] = [name for name in tools if isinstance(name, str)][:16]
    findings = result.get("findings")
    if isinstance(findings, list):
        facts["findings"] = len(findings)
        facts["block_findings"] = sum(
            1 for item in findings if isinstance(item, dict) and item.get("severity") == "block"
        )
    if "error" in result:
        facts["error"] = True
    if result.get("redacted") is True:
        facts["redacted"] = True
    return facts


def _reference_path(record: SkillRecord, file: str) -> Optional[str]:
    """The listed reference *file* names: "references/x.md", or just "x.md"."""
    listed = record.reference_files
    if file in listed:
        return file
    prefixed = f"{REFERENCES_DIR}/{file}"
    return prefixed if prefixed in listed else None


def _spelled(names: tuple[str, ...], pattern: re.Pattern[str]) -> list[str]:
    """The first MAX_TOOLS of *names* spelled the way *pattern* allows and
    at most MAX_NAME_CHARS long: an unusable skill's frontmatter is
    unchecked text, and only a short name can never carry one. However many
    names it lists, or however long, they never crowd out its findings."""
    spelled = (n for n in names if len(n) <= MAX_NAME_CHARS and pattern.fullmatch(n))
    return list(itertools.islice(spelled, MAX_TOOLS))


def _is_pinned(record: SkillRecord) -> bool:
    """Whether manifest.json (beside the skill folders, where the loader read
    it) has an entry for *record*, matching or not."""
    pins = skills_manifest.read_manifest(Path(record.path).parent / "manifest.json")
    return record.name in pins.get("skills", {})


class SkillsToolkit:
    """The skills.* tools over the bundled catalog (or *catalog*, for
    tests), with the owner's per-skill switches read through
    *session_factory*. Construction does no I/O; the catalog is loaded on
    first use (main.py loads it at startup)."""

    def __init__(
        self,
        session_factory: Optional[Callable[[], Any]] = None,
        catalog: Optional[SkillCatalog] = None,
    ) -> None:
        self._session_factory = session_factory
        self._catalog = catalog

    # -- dispatch ------------------------------------------------------------

    async def execute(self, action: str, params: Optional[Mapping[str, Any]]) -> dict[str, Any]:
        """Run one ``skills.*`` action. Unknown actions and arguments fail
        closed; a skill name must be spelled like one."""
        params = dict(params or {})
        if action not in _KEYS:
            return _error(f"Unknown skills action '{action}'.")
        unknown = _unknown(action, params)
        if unknown is not None:
            return unknown
        name = params.get("name")
        if not valid_skill_name(name):
            return _error(
                "'name' must be a skill's name as <available_skills> lists it, e.g. 'goals'."
            )
        try:
            handler = getattr(self, f"_{action}")
            result: dict[str, Any] = await handler(str(name), params)
            return result
        except SkillReadError:
            # Not evidence of a change: this call is refused, nothing marked.
            logger.warning("skills_tool_files_unreadable", action=action)
            return _error(UNREADABLE_ERROR, rule="unavailable")
        except SQLAlchemyError as exc:
            logger.error("skills_tool_db_error", action=action, error_type=type(exc).__name__)
            return _error(STORAGE_ERROR, rule="storage")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error(
                "skills_tool_unexpected_error", action=action, error_type=type(exc).__name__
            )
            return _error(f"The skill could not be read: {type(exc).__name__}", rule="unavailable")

    # -- shared checks -------------------------------------------------------

    def _current(self) -> SkillCatalog:
        return self._catalog if self._catalog is not None else bundled_catalog()

    async def _switched_off(self) -> frozenset[str]:
        if self._session_factory is None:
            return frozenset()
        async with self._session_factory() as session:
            return await disabled_skill_names(session)

    def _mark_changed(self, record: SkillRecord) -> None:
        """Record that *record*'s files no longer match what was loaded, in
        the process-wide catalog (every later view shows ``changed`` until
        a restart) or in this toolkit's own one."""
        if self._catalog is None:
            mark_changed(record.name)
            return
        self._catalog = self._catalog.with_record(
            dataclasses.replace(
                record, status=STATUS_CHANGED, status_reason=skills_manifest.CHANGED_REASON
            )
        )

    async def _files_match(self, record: SkillRecord) -> bool:
        """Whether *record*'s files on disk still hash to what was loaded;
        when they do not, the skill is marked changed. Files that could not
        be read just now raise SkillReadError and mark nothing."""
        now = await asyncio.to_thread(current_hash, record)
        if now == record.sha256:
            return True
        self._mark_changed(record)
        return False

    async def _usable(self, name: str) -> SkillRecord | dict[str, Any]:
        """The skill to read, or the refusal: unknown, switched off, not
        usable, or changed on disk since it was loaded."""
        catalog = self._current()
        off = await self._switched_off()
        record = catalog.get(name)
        if record is None:
            available = [r.name for r in catalog.usable() if r.name not in off]
            listing = (
                f" The skills you can read: {', '.join(available)}."
                if available
                else " No skill can be read on this install."
            )
            return _error(f"There is no skill named '{name}'.{listing}", rule="unknown_skill")
        if name in off:
            return _error(SWITCHED_OFF_ERROR.format(name=name), rule="skill_off")
        if not record.usable:
            return _error(
                f"The skill '{name}' cannot be used: its status is {record.status}. "
                "skills.scan_report shows why.",
                rule="skill_unusable",
                status=record.status,
            )
        if not await self._files_match(record):
            return _error(
                f"The skill '{name}' changed on disk since it was checked, so it cannot be used "
                "until the owner reviews it.",
                rule="skill_changed",
                status=STATUS_CHANGED,
            )
        return record

    @staticmethod
    def _whole(result: dict[str, Any]) -> dict[str, Any]:
        """*result*, or a refusal when it would not reach the model whole."""
        if shown_length(result) <= READ_RESULT_CHARS:
            return result
        return _error(
            "This text is too long to show whole, and a playbook is never cut short.",
            rule="too_large",
        )

    # -- actions -------------------------------------------------------------

    async def _read(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        record = await self._usable(name)
        if isinstance(record, dict):
            return record
        return self._whole(
            {
                "ok": True,
                "name": record.name,
                "title": record.title,
                "sha256": record.sha256,
                "sections": split_sections(record.body),
                "references": list(record.reference_files),
                "tools": list(record.tools),
            }
        )

    async def _read_reference(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        file = params.get("file")
        if not isinstance(file, str) or not file.strip() or len(file) > _MAX_FILE_ARG_CHARS:
            return _error(
                "'file' must be one of the references skills.read listed, "
                "e.g. 'references/checklist.md'."
            )
        record = await self._usable(name)
        if isinstance(record, dict):
            return record
        relpath = _reference_path(record, file.strip())
        if relpath is None:
            listed = list(record.reference_files)
            return _error(
                "That file is not one of this skill's references"
                + (f": {', '.join(listed)}." if listed else "; it has none."),
                rule="unknown_reference",
                references=listed,
            )
        return self._whole(
            {
                "ok": True,
                "name": record.name,
                "file": relpath,
                "sections": split_sections(record.references[relpath]),
            }
        )

    async def _scan_report(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        """The status and findings of any loaded skill, usable or not (the
        skill-vetter playbook reads it); a usable one is re-hashed first.
        Its reach comes from the frontmatter: ``declared_tools`` (every tool
        it names, whether or not this turn has it; skills.read's ``tools``
        is what a read loaded) and ``requires``, as names only, at most
        MAX_TOOLS per list, with ``declared_tools_total`` and
        ``requires_totals`` counting what the frontmatter lists when not all
        of it is shown; ``title`` and ``version`` only while it is usable,
        since a blocked or invalid skill's frontmatter is unreviewed text."""
        catalog = self._current()
        record = catalog.get(name)
        if record is None:
            listing = ", ".join(catalog.names()) or "none"
            return _error(
                f"There is no skill named '{name}'. The installed skills: {listing}.",
                rule="unknown_skill",
            )
        if record.usable and not await self._files_match(record):
            record = dataclasses.replace(
                record, status=STATUS_CHANGED, status_reason=skills_manifest.CHANGED_REASON
            )
        pinned = await asyncio.to_thread(_is_pinned, record)
        findings = [finding.to_dict() for finding in record.findings]
        declared = _spelled(record.tools, TOOL_NAME_PATTERN)
        listed = {
            "connectors": record.requires_connectors,
            "capabilities": record.requires_capabilities,
        }
        requires = {key: _spelled(names, KEY_PATTERN) for key, names in listed.items()}
        result: dict[str, Any] = {
            "ok": True,
            "name": record.name,
            "status": record.status,
            "sha256": record.sha256,
            "pinned": pinned,
            "declared_tools": declared,
            "requires": requires,
        }
        # How many names the frontmatter lists, wherever not all are shown.
        if len(declared) < len(record.tools):
            result["declared_tools_total"] = len(record.tools)
        cut = {key: len(names) for key, names in listed.items() if len(requires[key]) < len(names)}
        if cut:
            result["requires_totals"] = cut
        result["findings"] = findings
        if record.usable:
            result["title"] = record.title
            result["version"] = record.version
        if shown_length(result) <= SCAN_REPORT_CHARS:
            return result
        result["findings"] = []
        result["findings_total"] = len(findings)
        result["note"] = "Only the first findings fit here; Settings → Skills shows them all."
        room = SCAN_REPORT_CHARS - shown_length(result) - _REPORT_ROOM_CHARS
        kept: list[dict[str, Any]] = []
        for finding in findings:
            size = shown_length(finding) + 1
            if size > room:
                break
            kept.append(finding)
            room -= size
        result["findings"] = kept
        return result
