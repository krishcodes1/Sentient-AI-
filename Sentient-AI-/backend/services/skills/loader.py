"""Loads the bundled SKILL.md playbooks from backend/skills/: reads each folder
under the file rules, parses and scans it, hashes it, checks the hash against
manifest.json and gives every skill a status (ok, invalid, blocked,
unpinned or changed).

Why it exists: a skill is text the model follows, so the only skill text
that may reach it is text the team reviewed in a PR and pinned by SHA-256.
Loading is where that is decided, once per process, and never by raising: a
bad skill gets a status and a reason and the rest still load, and a missing
backend/skills/ simply means no skills. The skills.* tools re-check the hash
on every read (current_hash), so a file edited after startup is refused and
shows as ``changed`` from then on (mark_changed); a file that merely could
not be read just now (SkillReadError) refuses that one call and marks
nothing.

Hashing (spec §3.4): a file's hash is the SHA-256 of its bytes with CRLF
turned into LF, so a Windows checkout pins the same bytes as Linux; the
skill's hash is the SHA-256 of the sorted lines "<relative path>\\0<file
hash>\\n". The size constants and Finding live in services.skills.scanner
(which applies them) and are re-exported here.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping, Optional

import structlog

from services.skills import manifest as skills_manifest
from services.skills.scanner import (
    BLOCK,
    CATEGORIES,
    FORMAT_RULES,
    MAX_FILES,
    MAX_REFERENCE_BYTES,
    MAX_SKILL_BYTES,
    MAX_TOOLS,
    MAX_TOTAL_BYTES,
    SKILL_FILE,
    Finding,
    fence_mask,
    file_too_large,
    heading,
    parse_skill_md,
    path_finding,
    scan,
    skill_too_large,
    sort_findings,
    symlink_finding,
)

__all__ = [
    "MANIFEST_PATH",
    "MAX_FILES",
    "MAX_REFERENCE_BYTES",
    "MAX_SKILL_BYTES",
    "MAX_TOOLS",
    "MAX_TOTAL_BYTES",
    "SKILLS_ROOT",
    "STATUSES",
    "Finding",
    "SkillCatalog",
    "SkillReadError",
    "SkillRecord",
    "bundled_catalog",
    "current_hash",
    "file_hash",
    "load_skills",
    "mark_changed",
    "normalise_newlines",
    "reset_bundled_catalog",
    "skill_hash",
    "split_sections",
]

logger = structlog.get_logger(__name__)

# backend/skills, next to services/ (this file is backend/services/skills/loader.py).
SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"
MANIFEST_PATH = SKILLS_ROOT / "manifest.json"

STATUS_OK = "ok"
STATUS_INVALID = "invalid"
STATUS_BLOCKED = "blocked"
STATUS_UNPINNED = "unpinned"
STATUS_CHANGED = "changed"
STATUSES = (STATUS_OK, STATUS_INVALID, STATUS_BLOCKED, STATUS_UNPINNED, STATUS_CHANGED)

# How many directory entries one level may hold before the folder is refused
# without reading further (a skill has at most MAX_FILES files; the slack is
# for the references/ folder and the entries that earn their own finding).
_ENTRY_LIMIT = 2 * MAX_FILES


@dataclass(frozen=True)
class SkillRecord:
    """One bundled skill as loaded. Only an ``ok`` record is usable; the
    others carry what they could read so Settings can show why."""

    name: str
    title: str
    description: str
    version: Optional[str]
    license: Optional[str]
    category: Optional[str]
    tools: tuple[str, ...]
    requires_connectors: tuple[str, ...]
    requires_capabilities: tuple[str, ...]
    # SKILL.md without its frontmatter, LF line endings.
    body: str
    # "references/x.md" -> text.
    references: Mapping[str, str] = field(hash=False)
    # Relative path -> SHA-256 of the LF-normalised bytes.
    files: Mapping[str, str] = field(hash=False)
    sha256: str
    findings: tuple[Finding, ...]
    status: str
    status_reason: Optional[str]
    path: Path
    source: str = "bundled"

    @property
    def usable(self) -> bool:
        return self.status == STATUS_OK

    @property
    def reference_files(self) -> tuple[str, ...]:
        """The readable reference paths, sorted ("references/x.md")."""
        return tuple(sorted(self.references))

    def to_info(self) -> dict[str, Any]:
        """The SkillInfo of spec §4.5, without ``enabled`` (that is the
        owner's switch, kept in the database, not on disk)."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "version": self.version,
            "license": self.license,
            "source": self.source,
            "sha256": self.sha256,
            "status": self.status,
            "status_reason": self.status_reason,
            "tools": list(self.tools),
            "requires": {
                "connectors": list(self.requires_connectors),
                "capabilities": list(self.requires_capabilities),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


class SkillCatalog:
    """The loaded skills by name, sorted. Immutable: with_record returns a
    new catalog."""

    __slots__ = ("_skills",)

    def __init__(self, records: Iterable[SkillRecord] = ()) -> None:
        by_name = {record.name: record for record in records}
        self._skills: Mapping[str, SkillRecord] = MappingProxyType(dict(sorted(by_name.items())))

    @property
    def skills(self) -> Mapping[str, SkillRecord]:
        return self._skills

    def get(self, name: object) -> Optional[SkillRecord]:
        return self._skills.get(name) if isinstance(name, str) else None

    def names(self) -> tuple[str, ...]:
        return tuple(self._skills)

    def usable(self) -> tuple[SkillRecord, ...]:
        return tuple(record for record in self._skills.values() if record.usable)

    def with_record(self, record: SkillRecord) -> SkillCatalog:
        """A copy with *record* added or replacing the one of that name."""
        return SkillCatalog([*self._skills.values(), record])

    def __len__(self) -> int:
        return len(self._skills)

    def __iter__(self) -> Iterator[SkillRecord]:
        return iter(self._skills.values())

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._skills


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #


def normalise_newlines(data: bytes) -> bytes:
    """CRLF to LF, so the same text hashes the same on every OS."""
    return data.replace(b"\r\n", b"\n")


def file_hash(data: bytes) -> str:
    """SHA-256 (hex) of a file's LF-normalised bytes."""
    return hashlib.sha256(normalise_newlines(data)).hexdigest()


def skill_hash(files: Mapping[str, str]) -> str:
    """SHA-256 (hex) of the sorted "<relative path>\\0<file hash>\\n" lines."""
    lines = sorted(f"{relpath}\0{digest}\n" for relpath, digest in files.items())
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #


def split_sections(markdown: str) -> list[dict[str, str]]:
    """Split Markdown on its ATX headings (never inside a fenced code
    block) into ``{"heading", "text"}`` items. Text before the first
    heading has heading ""; a section's text loses its leading and trailing
    blank lines; a section with neither heading nor text is dropped."""
    lines = markdown.replace("\r\n", "\n").split("\n")
    fenced = fence_mask(lines)
    parts: list[tuple[str, list[str]]] = [("", [])]
    for line, in_fence in zip(lines, fenced, strict=True):
        found = None if in_fence else heading(line)
        if found is not None:
            parts.append((found[1], []))
        else:
            parts[-1][1].append(line)
    sections: list[dict[str, str]] = []
    for title, body in parts:
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        text = "\n".join(body)
        if title or text:
            sections.append({"heading": title, "text": text})
    return sections


# --------------------------------------------------------------------------- #
# Reading a skill folder
# --------------------------------------------------------------------------- #


@dataclass
class _Read:
    texts: dict[str, str] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


def _too_many(count_note: str) -> Finding:
    return Finding(
        BLOCK, "too_many_files", ".", None, f"A skill has at most {MAX_FILES} files; {count_note}"
    )


def _entries(path: str) -> Optional[list[os.DirEntry[str]]]:
    """A folder's entries sorted by name, or None past _ENTRY_LIMIT (so a
    folder of a million files is refused without listing it all)."""
    found: list[os.DirEntry[str]] = []
    with os.scandir(path) as listing:
        for entry in listing:
            found.append(entry)
            if len(found) > _ENTRY_LIMIT:
                return None
    return sorted(found, key=lambda entry: entry.name)


def _list_files(skill_dir: Path, findings: list[Finding]) -> list[tuple[str, str]]:
    """The (relative path, path) of every file the layout allows; a finding
    for every symlink, dotfile, other folder, other file and special file."""
    top = _entries(str(skill_dir))
    if top is None:
        findings.append(_too_many(f"this folder holds more than {_ENTRY_LIMIT} entries"))
        return []
    candidates: list[tuple[str, os.DirEntry[str]]] = []
    for entry in top:
        if entry.is_symlink():
            findings.append(symlink_finding(entry.name))
        elif entry.is_dir(follow_symlinks=False):
            problem = path_finding(entry.name, is_dir=True)
            if problem is not None:
                findings.append(problem)
                continue
            inner = _entries(entry.path)
            if inner is None:
                findings.append(_too_many(f"{entry.name}/ holds more than {_ENTRY_LIMIT} entries"))
                return []
            for sub in inner:
                relpath = f"{entry.name}/{sub.name}"
                if sub.is_symlink():
                    findings.append(symlink_finding(relpath))
                elif sub.is_dir(follow_symlinks=False):
                    nested = path_finding(relpath, is_dir=True)
                    if nested is not None:
                        findings.append(nested)
                else:
                    candidates.append((relpath, sub))
        else:
            candidates.append((entry.name, entry))
    if len(candidates) > MAX_FILES:
        findings.append(_too_many(f"this one has {len(candidates)}"))
        return []
    allowed: list[tuple[str, str]] = []
    for relpath, entry in candidates:
        problem = path_finding(relpath)
        if problem is not None:
            findings.append(problem)
        elif not entry.is_file(follow_symlinks=False):
            findings.append(_not_regular(relpath))
        else:
            allowed.append((relpath, entry.path))
    return allowed


def _not_regular(relpath: str) -> Finding:
    return Finding(
        BLOCK, "file_not_allowed", relpath, None, f"{relpath}: only regular files are allowed"
    )


def _read_bytes(relpath: str, path: str, findings: list[Finding]) -> Optional[bytes]:
    """The file's LF-normalised bytes, or None with a finding. Opened without
    following a symlink swapped in after listing, refused past twice the cap
    before reading (CRLF can at most halve the size), and refused, never
    cut, when the normalised bytes are over the cap."""
    cap = MAX_SKILL_BYTES if relpath == SKILL_FILE else MAX_REFERENCE_BYTES
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        if os.path.islink(path):
            findings.append(symlink_finding(relpath))
        else:
            findings.append(
                Finding(BLOCK, "unreadable", relpath, None, f"{relpath} could not be read")
            )
        return None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            findings.append(_not_regular(relpath))
            return None
        if info.st_size > 2 * cap:
            findings.append(file_too_large(relpath, info.st_size, cap))
            return None
        raw = handle.read(2 * cap + 1)
    if len(raw) > 2 * cap:
        findings.append(file_too_large(relpath, None, cap))
        return None
    data = normalise_newlines(raw)
    if len(data) > cap:
        findings.append(file_too_large(relpath, len(data), cap))
        return None
    return data


def _read_skill_dir(skill_dir: Path) -> _Read:
    """Every allowed file's text and hash, plus the file-rule findings."""
    result = _Read()
    try:
        files = _list_files(skill_dir, result.findings)
    except OSError:
        result.findings.append(
            Finding(BLOCK, "unreadable", ".", None, "The skill folder could not be listed")
        )
        return result
    total = 0
    for relpath, path in files:
        data = _read_bytes(relpath, path, result.findings)
        if data is None:
            continue
        result.hashes[relpath] = hashlib.sha256(data).hexdigest()
        total += len(data)
        if b"\x00" in data:
            result.findings.append(
                Finding(BLOCK, "binary_file", relpath, None, f"{relpath} is binary, not text")
            )
            continue
        try:
            result.texts[relpath] = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            line = data[: exc.start].count(b"\n") + 1
            result.findings.append(
                Finding(BLOCK, "not_utf8", relpath, line, f"{relpath} is not valid UTF-8")
            )
    if total > MAX_TOTAL_BYTES:
        result.findings.append(skill_too_large(total))
    return result


class SkillReadError(Exception):
    """A skill's files could not be read just now (an OSError such as
    EMFILE or EACCES, or a file gone between listing and reading). That is
    no evidence they changed: the caller refuses this one call and marks
    nothing."""


def current_hash(record: SkillRecord) -> Optional[str]:
    """Re-read *record*'s folder from disk under the same file rules and
    return its skill hash now, or None when it is gone, is a symlink, lost
    its SKILL.md or breaks a file rule (a real change). Raises
    SkillReadError when a file or the folder could not be read just now.
    The skills.* tools compare this with the pinned hash on every read."""
    try:
        info = os.lstat(record.path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise SkillReadError(record.name) from exc
    if not stat.S_ISDIR(info.st_mode):  # a symlink or a file now
        return None
    try:
        read = _read_skill_dir(record.path)
    except Exception as exc:
        raise SkillReadError(record.name) from exc
    rules = {finding.rule for finding in read.findings if finding.rule in FORMAT_RULES}
    if rules - {"unreadable"}:
        return None
    if rules:
        raise SkillReadError(record.name)
    if SKILL_FILE not in read.texts:
        return None
    return skill_hash(read.hashes)


# --------------------------------------------------------------------------- #
# Building records
# --------------------------------------------------------------------------- #


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _names(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _mapping(value: Any) -> Mapping[Any, Any]:
    return value if isinstance(value, dict) else {}


def _where(finding: Finding) -> str:
    """Where a finding is, as a prefix for status_reason ("." is the whole
    skill folder, and most file findings already start with their path)."""
    if finding.line is not None:
        return f"{finding.file} line {finding.line}: "
    if finding.file == "." or finding.message.startswith(finding.file):
        return ""
    return f"{finding.file}: "


def _status(
    name: str,
    findings: list[Finding],
    sha256: str,
    files: Mapping[str, str],
    pins: Mapping[str, Any],
) -> tuple[str, Optional[str]]:
    """invalid, then blocked (each with its first finding as the reason),
    then the manifest's verdict. A missing SKILL.md is usually the echo of
    another file finding (too large, not UTF-8, a symlink), so that other
    finding is the reason when there is one."""
    invalid = [f for f in findings if f.severity == BLOCK and f.rule in FORMAT_RULES]
    if invalid:
        finding = next((f for f in invalid if f.rule != "skill_md_missing"), invalid[0])
        return STATUS_INVALID, _where(finding) + finding.message
    for finding in findings:
        if finding.severity == BLOCK:
            return STATUS_BLOCKED, _where(finding) + finding.message
    return skills_manifest.pin_status(name, sha256, files, pins)


def _record(
    skill_dir: Path,
    folder: str,
    read: _Read,
    meta: Optional[Mapping[Any, Any]],
    body: str,
    findings: list[Finding],
    pins: Mapping[str, Any],
) -> SkillRecord:
    meta = meta or {}
    crawler = _mapping(_mapping(meta.get("metadata")).get("crawler"))
    requires = _mapping(crawler.get("requires"))
    title = _text(meta.get("title"))
    category = _text(crawler.get("category"))
    sha256 = skill_hash(read.hashes)
    status, reason = _status(folder, findings, sha256, read.hashes, pins)
    return SkillRecord(
        name=folder,
        title=title.strip() if title and title.strip() else folder,
        description=_text(meta.get("description")) or "",
        version=_text(meta.get("version")),
        license=_text(meta.get("license")),
        category=category if category in CATEGORIES else None,
        tools=_names(crawler.get("tools")),
        requires_connectors=_names(requires.get("connectors")),
        requires_capabilities=_names(requires.get("capabilities")),
        body=body,
        references=MappingProxyType(
            {relpath: text for relpath, text in sorted(read.texts.items()) if relpath != SKILL_FILE}
        ),
        files=MappingProxyType(dict(sorted(read.hashes.items()))),
        sha256=sha256,
        findings=tuple(findings),
        status=status,
        status_reason=reason,
        path=skill_dir,
    )


def _load_skill(skill_dir: Path, pins: Mapping[str, Any]) -> SkillRecord:
    folder = skill_dir.name
    read = _read_skill_dir(skill_dir)
    findings = list(read.findings)
    meta: Optional[dict[str, Any]] = None
    body = ""
    skill_md = read.texts.get(SKILL_FILE)
    if skill_md is not None:
        parsed = parse_skill_md(skill_md)
        findings.extend(parsed.findings)
        meta = parsed.meta
        body = parsed.body
    findings.extend(scan(read.texts, meta, folder=folder))
    return _record(skill_dir, folder, read, meta, body, sort_findings(findings), pins)


def _unreadable_skill(skill_dir: Path, finding: Finding, pins: Mapping[str, Any]) -> SkillRecord:
    return _record(skill_dir, skill_dir.name, _Read(), None, "", [finding], pins)


def load_skills(root: Optional[Path] = None, manifest_path: Optional[Path] = None) -> SkillCatalog:
    """Load every skill folder under *root* (default SKILLS_ROOT). Folders
    whose name starts with "_" (the template) or "." are skipped; loose files
    (README.md, CREDITS.md, manifest.json) are not skills. *manifest_path*
    defaults to MANIFEST_PATH, or to <root>/manifest.json when *root* is
    given. Never raises: a missing root is an empty catalog and a skill that
    fails to load gets a status saying why."""
    skills_root = Path(root) if root is not None else SKILLS_ROOT
    if manifest_path is None:
        manifest_path = MANIFEST_PATH if root is None else skills_root / "manifest.json"
    try:
        pins = skills_manifest.read_manifest(manifest_path)
        listing = sorted(os.scandir(skills_root), key=lambda entry: entry.name)
    except Exception:
        return SkillCatalog()
    records: list[SkillRecord] = []
    for entry in listing:
        if entry.name.startswith(("_", ".")):
            continue
        skill_dir = Path(entry.path)
        try:
            if entry.is_symlink():
                records.append(_unreadable_skill(skill_dir, symlink_finding("."), pins))
            elif entry.is_dir(follow_symlinks=False):
                records.append(_load_skill(skill_dir, pins))
        except Exception:
            unreadable = Finding(BLOCK, "unreadable", ".", None, "The skill could not be loaded")
            records.append(_unreadable_skill(skill_dir, unreadable, pins))
    return SkillCatalog(records)


# --------------------------------------------------------------------------- #
# The process-wide bundled catalog
# --------------------------------------------------------------------------- #

_bundled: Optional[SkillCatalog] = None
_bundled_lock = threading.Lock()


def bundled_catalog() -> SkillCatalog:
    """The bundled skills, loaded once per process."""
    global _bundled
    with _bundled_lock:
        if _bundled is None:
            _bundled = load_skills()
            for record in _bundled:
                if not record.usable:
                    logger.warning("skill_not_usable", skill=record.name, status=record.status)
        return _bundled


def reset_bundled_catalog() -> None:
    """Forget the cached catalog (tests, or after the files were fixed)."""
    global _bundled
    with _bundled_lock:
        _bundled = None


def mark_changed(name: str) -> Optional[SkillRecord]:
    """Record that a bundled skill's files no longer match what was loaded
    (a re-read hash mismatch), so every later view shows ``changed`` until
    the process restarts. Returns the record as it now stands, or None when
    the cached catalog does not hold *name*. A skill that was not ``ok`` is
    left as it was: it is unusable already and its own reason is the
    better one."""
    global _bundled
    with _bundled_lock:
        record = _bundled.get(name) if _bundled is not None else None
        if _bundled is None or record is None:
            return None
        if record.status != STATUS_OK:
            return record
        updated = dataclasses.replace(
            record, status=STATUS_CHANGED, status_reason=skills_manifest.CHANGED_REASON
        )
        _bundled = _bundled.with_record(updated)
    logger.warning("skill_changed_on_disk", skill=name)
    return updated
