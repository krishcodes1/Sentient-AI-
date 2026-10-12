"""The SKILL.md rules: what a bundled skill's files may hold, reported as block
and warn findings, each with a stable rule id, the file and the 1-based line.

Why it exists: a skill is text the model follows as a playbook, so it is the
one place a hostile edit could plant an installer, a hidden instruction or a
request to skip an approval. Every public skill scanner has been bypassed, so
this is not the security boundary (approvals, tiers and capability gates are
enforced in code whatever a skill says). It is the review aid that makes a
PR's skill text fail loudly when it carries a known attack shape (the
ClawHavoc, ToxicSkills, Cisco and Unit 42 incidents in
docs/superpowers/specs/2026-09-25-skills-design.md §2), and the report the
owner reads in Settings ▸ Skills and the model reads through
skills.scan_report.

Deterministic and offline: regexes, the frontmatter's types and the shared
prompt guard. The guard is services.agent.prompt_guard.PromptGuard, called
directly so an exception blocks the skill (rule ``guard_error``) instead of
failing open the way the runtime's wrapper does. That module imports only
the standard library, so ``python -m scripts.skills_manifest`` runs this
scanner without the app's settings or environment (no SECRET_KEY needed).

Format, size and file rules (spec §3) are block findings whose rule is in
FORMAT_RULES; the loader marks a skill with one of them ``invalid`` rather
than ``blocked``. The frontmatter is parsed here too (parse_skill_md), with
``yaml.safe_load`` only, after an event walk has refused anchors, aliases,
tags, directives, duplicate keys and deep nesting.

Beyond spec §4.1, a few rules close neighbouring gaps: C0/C1 control
characters, Markdown comments and hidden markup (script, style,
display:none) block like HTML comments, and the description, the only skill
text that reaches the system prompt, must be exactly what the prompt shows
(no character services.skills.prompt.sanitise_line would remove: rule
``description_invalid``) and must grade NONE or LOW with the prompt guard,
raw and as shown (rule ``description_guard``), the bar saved memory facts
meet.
Content findings name the pattern rather than quote the matched text, so
the report cannot carry an injection back to the model; only URLs, ignored
keys and what an openclaw block wanted are listed, as the spec asks, on one
printable line and capped.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional
from urllib.parse import unquote

import yaml

from services.agent.prompt_guard import _INVISIBLE_CHARS, PromptGuard, ThreatLevel
from services.skills.prompt import VARIATION_SELECTORS, sanitise_line

# -- Size and count caps (spec §3.3). Oversize is rejected, never truncated:
# a scanner that reads only the first N bytes is the Unit 42 padding attack.
MAX_SKILL_BYTES = 24_000
MAX_REFERENCE_BYTES = 24_000
MAX_FILES = 20
MAX_TOTAL_BYTES = 512 * 1024
MAX_TOOLS = 16

MAX_NAME_CHARS = 64
MAX_DESCRIPTION_CHARS = 1024
MAX_TITLE_CHARS = 80
CATEGORIES = frozenset({"school", "life", "work", "research", "safety"})

SKILL_FILE = "SKILL.md"
REFERENCES_DIR = "references"

NAME_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
# A "type.action" tool name as the tool catalog spells them.
TOOL_NAME_PATTERN = re.compile(r"[a-z0-9_]+\.[a-z0-9_]+")
# A connector type or a capability key.
KEY_PATTERN = re.compile(r"[a-z0-9_]{1,64}")
# One plain name per reference: no dot first (dotfiles), no separators, no
# characters a filesystem might fold or normalise differently on another OS.
_REFERENCE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.(?:md|txt)")

BLOCK = "block"
WARN = "warn"

# Block findings that break a format, size or file rule: the skill is
# `invalid`, not merely `blocked`.
FORMAT_RULES = frozenset(
    {
        "skill_md_missing",
        "symlink",
        "dotfile",
        "folder_not_allowed",
        "file_not_allowed",
        "not_utf8",
        "binary_file",
        "file_too_large",
        "too_many_files",
        "skill_too_large",
        "unreadable",
        "frontmatter_missing",
        "frontmatter_not_mapping",
        "frontmatter_key",
        "yaml_error",
        "yaml_alias",
        "yaml_tag",
        "yaml_duplicate_key",
        "name_invalid",
        "name_mismatch",
        "description_invalid",
        "field_invalid",
    }
)


@dataclass(frozen=True)
class Finding:
    """One scanner result. ``line`` is 1-based, or None when the finding is
    about a whole file or skill."""

    severity: str
    rule: str
    file: str
    line: Optional[int]
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "message": self.message,
        }


@dataclass(frozen=True)
class ParsedSkillMd:
    """SKILL.md split into its frontmatter and body. ``meta`` is None when
    the frontmatter is missing or was refused (the findings say why)."""

    meta: Optional[dict[str, Any]]
    body: str
    body_line: int
    findings: tuple[Finding, ...]


def _block(rule: str, file: str, line: Optional[int], message: str) -> Finding:
    return Finding(BLOCK, rule, file, line, message)


def _warn(rule: str, file: str, line: Optional[int], message: str) -> Finding:
    return Finding(WARN, rule, file, line, message)


def _shown(value: Any, cap: int = 80) -> str:
    """A value quoted for a finding message: printable, one line, capped."""
    text = "".join(c if c.isprintable() else " " for c in str(value))
    text = " ".join(text.split())
    return text if len(text) <= cap else text[: cap - 1] + "…"


# --------------------------------------------------------------------------- #
# Markdown structure (shared with loader.split_sections)
# --------------------------------------------------------------------------- #

_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")
# An ATX heading. A closing run of "#" counts only after a space, so
# "## Learn C#" keeps its "#".
_HEADING = re.compile(r" {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*")


def fence_mask(lines: list[str]) -> list[bool]:
    """For each line, whether it belongs to a fenced code block (the fence
    lines included). A fence closes on a line of the same character, at
    least as long, with nothing after it; an unclosed fence runs to the end."""
    mask: list[bool] = []
    fence: Optional[str] = None
    for line in lines:
        match = _FENCE.match(line)
        if fence is None:
            if match:
                fence = match.group(1)
            mask.append(fence is not None)
            continue
        mask.append(True)
        if (
            match
            and match.group(1)[0] == fence[0]
            and len(match.group(1)) >= len(fence)
            and not line[match.end() :].strip()
        ):
            fence = None
    return mask


def heading(line: str) -> Optional[tuple[int, str]]:
    """``(level, text)`` when *line* is an ATX heading, else None."""
    match = _HEADING.fullmatch(line)
    if match is None:
        return None
    return len(match.group(1)), (match.group(2) or "").strip()


# --------------------------------------------------------------------------- #
# Frontmatter
# --------------------------------------------------------------------------- #

# The deepest frontmatter needs is metadata.crawler.requires.<list> (4).
_MAX_YAML_DEPTH = 8


def split_frontmatter(text: str) -> Optional[tuple[str, str, int]]:
    """``(yaml text, body, first body line)`` when *text* starts with a
    "---" line and a later "---" line closes the block, else None."""
    lines = text.split("\n")
    if lines[0].rstrip(" \t") != "---":
        return None
    for index in range(1, len(lines)):
        if lines[index].rstrip(" \t") == "---":
            return "\n".join(lines[1:index]), "\n".join(lines[index + 1 :]), index + 2
    return None


def _event_line(event: Any) -> Optional[int]:
    mark = getattr(event, "start_mark", None)
    # +1 for 1-based lines, +1 for the opening "---" line of SKILL.md.
    return mark.line + 2 if mark is not None else None


def _yaml_shape_problem(yaml_text: str) -> Optional[Finding]:
    """Walk the YAML event stream before anything is constructed and refuse
    what safe_load would otherwise accept: anchors and aliases (an alias can
    expand into a huge document), explicit tags and directives, a second
    document, a non-scalar key, a key given twice (YAML keeps the last one
    silently) and nesting deeper than the format needs."""

    def refuse(rule: str, event: Any, message: str) -> Finding:
        return _block(rule, SKILL_FILE, _event_line(event), message)

    # One frame per open collection: [is_mapping, keys seen, expecting a key].
    stack: list[list[Any]] = []
    documents = 0
    for event in yaml.parse(yaml_text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            return refuse("yaml_alias", event, "YAML anchors and aliases are not allowed")
        if getattr(event, "tag", None) is not None:
            return refuse("yaml_tag", event, "YAML tags (! or !!) are not allowed")
        if isinstance(event, yaml.DocumentStartEvent):
            documents += 1
            if event.version is not None or event.tags:
                return refuse("yaml_tag", event, "YAML directives are not allowed")
            if documents > 1:
                return refuse("yaml_error", event, "The frontmatter must be one YAML document")
            continue
        top = stack[-1] if stack else None
        if isinstance(event, yaml.ScalarEvent):
            if top is not None and top[0]:
                if top[2]:
                    if event.value in top[1]:
                        return refuse(
                            "yaml_duplicate_key",
                            event,
                            f"The key {_shown(event.value)!r} appears twice",
                        )
                    top[1].add(event.value)
                top[2] = not top[2]
            continue
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            if top is not None and top[0]:
                if top[2]:
                    return refuse("frontmatter_key", event, "Frontmatter keys must be plain text")
                top[2] = True
            stack.append([isinstance(event, yaml.MappingStartEvent), set(), True])
            if len(stack) > _MAX_YAML_DEPTH:
                return refuse("yaml_error", event, "The frontmatter is nested too deeply")
            continue
        if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)) and stack:
            stack.pop()
    return None


def parse_frontmatter(yaml_text: str) -> tuple[Optional[dict[str, Any]], list[Finding]]:
    """The frontmatter mapping, or None with the finding that refused it."""
    try:
        problem = _yaml_shape_problem(yaml_text)
        if problem is not None:
            return None, [problem]
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 2 if mark is not None else None
        return None, [_block("yaml_error", SKILL_FILE, line, "The frontmatter is not valid YAML")]
    except Exception:  # RecursionError, MemoryError on hostile input: fail closed
        return None, [_block("yaml_error", SKILL_FILE, None, "The frontmatter could not be read")]
    if data is None:
        data = {}
    if not isinstance(data, dict):
        return None, [
            _block(
                "frontmatter_not_mapping",
                SKILL_FILE,
                2,
                "The frontmatter must be a mapping of keys to values",
            )
        ]
    return data, []


def parse_skill_md(text: str) -> ParsedSkillMd:
    """Split SKILL.md (LF line endings) and parse its frontmatter."""
    split = split_frontmatter(text)
    if split is None:
        finding = _block(
            "frontmatter_missing",
            SKILL_FILE,
            1,
            'SKILL.md must start with a "---" line, its YAML frontmatter and a closing "---" line',
        )
        return ParsedSkillMd(None, text, 1, (finding,))
    yaml_text, body, body_line = split
    meta, findings = parse_frontmatter(yaml_text)
    return ParsedSkillMd(meta, body, body_line, tuple(findings))


def _key_line(text: Optional[str], dotted: str) -> Optional[int]:
    """The SKILL.md line where a (possibly nested) frontmatter key is set,
    found by walking down the frontmatter lines one key at a time."""
    if text is None or not dotted:
        return None
    split = split_frontmatter(text)
    if split is None:
        return None
    lines = split[0].split("\n")
    start = 0
    for part in dotted.split("."):
        pattern = re.compile(rf"\s*(?:-\s+)?[\"']?{re.escape(part)}[\"']?\s*:")
        for index in range(start, len(lines)):
            if pattern.match(lines[index]):
                start = index
                break
        else:
            return None
    return start + 2


def _describe(value: Any, cap: int = 160) -> str:
    """What an ignored openclaw block asked for, flattened to one line."""
    if isinstance(value, dict):
        text = "; ".join(f"{_describe(k)} {_describe(v)}" for k, v in value.items())
    elif isinstance(value, list):
        text = ", ".join(_describe(v) for v in value)
    else:
        text = str(value)
    return _shown(text, cap)


_UNSUPPORTED_KEYS = ("command-dispatch", "disable-model-invocation", "user-invocable")
# fail(rule, dotted key, message) / warn(...): how the frontmatter checks report.
_Report = Callable[[str, str, str], None]
_OPTIONAL_TEXT_KEYS = ("version", "license", "compatibility", "homepage")


def check_frontmatter(
    meta: Mapping[Any, Any], *, folder: Optional[str] = None, text: Optional[str] = None
) -> list[Finding]:
    """Format findings (types, required keys, the name rule) and warn
    findings (ignored and unsupported keys) for a parsed frontmatter.
    *text* is SKILL.md, used only to put line numbers on the findings."""
    findings: list[Finding] = []

    def fail(rule: str, key: str, message: str) -> None:
        findings.append(_block(rule, SKILL_FILE, _key_line(text, key), message))

    def warn(rule: str, key: str, message: str) -> None:
        findings.append(_warn(rule, SKILL_FILE, _key_line(text, key), message))

    for key in meta:
        if not isinstance(key, str):
            fail(
                "frontmatter_key",
                "",
                f"The key {_shown(key)!r} is not text (YAML reads on/off/yes/no as true/false); "
                "quote it",
            )

    name = meta.get("name")
    if name is None:
        fail("name_invalid", "name", "name is required")
    elif not isinstance(name, str):
        fail("name_invalid", "name", "name must be text")
    elif len(name) > MAX_NAME_CHARS or not NAME_PATTERN.fullmatch(name):
        fail(
            "name_invalid",
            "name",
            "name must be lowercase letters and digits joined by single hyphens, "
            f"at most {MAX_NAME_CHARS} characters",
        )
    elif folder is not None and name != folder:
        fail(
            "name_mismatch",
            "name",
            f"name {name!r} must equal the folder name {_shown(folder, MAX_NAME_CHARS)!r}",
        )

    description = meta.get("description")
    if description is None:
        fail("description_invalid", "description", "description is required")
    elif not isinstance(description, str):
        fail(
            "description_invalid",
            "description",
            "description must be text (YAML reads on/off/yes/no as true/false); quote it",
        )
    elif not description.strip() or len(description) > MAX_DESCRIPTION_CHARS:
        fail(
            "description_invalid",
            "description",
            f"description must be 1 to {MAX_DESCRIPTION_CHARS} characters",
        )

    title = meta.get("title")
    if title is not None and (
        not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE_CHARS
    ):
        fail("field_invalid", "title", f"title must be text of 1 to {MAX_TITLE_CHARS} characters")

    for key in _OPTIONAL_TEXT_KEYS:
        value = meta.get(key)
        if value is not None and not isinstance(value, str):
            fail(
                "field_invalid",
                key,
                f"{key} must be text (YAML reads 1.0 as a number and bare dates as dates); "
                "quote it",
            )

    if "metadata" in meta:
        _check_metadata(meta["metadata"], fail, warn)

    if "allowed-tools" in meta:
        warn(
            "allowed_tools_ignored",
            "allowed-tools",
            "allowed-tools is ignored: Crawler never pre-approves tools, and every action "
            "still goes through its approval rules",
        )
    for key in _UNSUPPORTED_KEYS:
        if key in meta:
            warn("unsupported_key", key, f"{key} is not supported and is ignored")

    known = {"name", "description", "title", "metadata", "allowed-tools"}
    known.update(_OPTIONAL_TEXT_KEYS)
    known.update(_UNSUPPORTED_KEYS)
    for key in meta:
        if isinstance(key, str) and key not in known:
            warn("ignored_key", key, f"{_shown(key)} is not a SKILL.md key and is ignored")
    return findings


def _check_metadata(metadata: Any, fail: _Report, warn: _Report) -> None:
    """metadata.crawler is checked strictly; metadata.openclaw/clawdbot keep
    only os and emoji; anything else is reported as ignored."""
    if metadata is None:
        return
    if not isinstance(metadata, dict):
        fail("field_invalid", "metadata", "metadata must be a mapping")
        return
    for key, value in metadata.items():
        if not isinstance(key, str):
            fail("frontmatter_key", "metadata", f"metadata key {_shown(key)!r} is not text")
            continue
        path = f"metadata.{key}"
        if key == "crawler":
            _check_crawler(value, fail, warn)
        elif key in ("openclaw", "clawdbot"):
            if not isinstance(value, dict):
                warn("ignored_key", path, f"{path} is ignored")
                continue
            for sub, wanted in value.items():
                if sub == "install":
                    warn(
                        "openclaw_ignored",
                        f"{path}.install",
                        f"{path}.install is ignored: it wanted to install {_describe(wanted)}. "
                        "Crawler never installs anything for a skill",
                    )
                elif sub == "requires":
                    warn(
                        "openclaw_ignored",
                        f"{path}.requires",
                        f"{path}.requires is ignored: it wanted {_describe(wanted)}",
                    )
                elif sub not in ("os", "emoji"):
                    warn("ignored_key", f"{path}.{sub}", f"{path}.{_shown(sub)} is ignored")
        else:
            warn("ignored_key", path, f"metadata.{_shown(key)} is ignored")


def _check_name_list(
    value: Any, path: str, pattern: re.Pattern[str], what: str, fail: _Report, limit: int = 64
) -> None:
    if not isinstance(value, list):
        fail("field_invalid", path, f"{path} must be a list")
        return
    if len(value) > limit:
        fail("field_invalid", path, f"{path} lists at most {limit} names")
        return
    if any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value):
        fail("field_invalid", path, f"{path} must list {what}")
        return
    if len(set(value)) != len(value):
        fail("field_invalid", path, f"{path} lists a name twice")


def _check_crawler(crawler: Any, fail: _Report, warn: _Report) -> None:
    if crawler is None:
        return
    if not isinstance(crawler, dict):
        fail("field_invalid", "metadata.crawler", "metadata.crawler must be a mapping")
        return
    for key, value in crawler.items():
        path = f"metadata.crawler.{_shown(key)}"
        if key == "category":
            if not isinstance(value, str) or value not in CATEGORIES:
                fail(
                    "field_invalid",
                    path,
                    f"{path} must be one of {', '.join(sorted(CATEGORIES))}",
                )
        elif key == "tools":
            _check_name_list(
                value, path, TOOL_NAME_PATTERN, 'tool names written "type.action"', fail, MAX_TOOLS
            )
        elif key == "requires":
            if value is None:
                continue
            if not isinstance(value, dict):
                fail("field_invalid", path, f"{path} must be a mapping")
                continue
            for sub, names in value.items():
                sub_path = f"{path}.{_shown(sub)}"
                if sub == "connectors":
                    _check_name_list(names, sub_path, KEY_PATTERN, "connector types", fail)
                elif sub == "capabilities":
                    _check_name_list(names, sub_path, KEY_PATTERN, "capability keys", fail)
                elif isinstance(sub, str):
                    warn("ignored_key", sub_path, f"{sub_path} is ignored")
                else:
                    fail("frontmatter_key", path, f"{path} has a key that is not text")
        elif isinstance(key, str):
            warn("ignored_key", path, f"{path} is ignored")
        else:
            fail(
                "frontmatter_key", "metadata.crawler", "metadata.crawler has a key that is not text"
            )


# --------------------------------------------------------------------------- #
# Layout: which files a skill may contain
# --------------------------------------------------------------------------- #

_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".jar",
    ".whl",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".msi",
    ".apk",
    ".iso",
)
_CODE_SUFFIXES = (
    ".py",
    ".pyc",
    ".pyo",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".com",
    ".command",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".rb",
    ".pl",
    ".php",
    ".lua",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".app",
    ".applescript",
    ".scpt",
    ".vbs",
    ".jse",
    ".wsf",
    ".class",
)
_CODE_FOLDERS = frozenset({"scripts", "bin", "hooks", "lib", "src", "node_modules", "dist"})


def symlink_finding(relpath: str) -> Finding:
    return _block("symlink", relpath, None, f"{relpath}: symlinks are not allowed in a skill")


def path_finding(relpath: str, *, is_dir: bool = False) -> Optional[Finding]:
    """The format finding for a file (or, with *is_dir*, a folder) at
    *relpath*, "/"-separated and relative to the skill folder; None when the
    layout allows it: SKILL.md at the top and references/<name>.md|.txt."""
    parts = relpath.split("/")
    if any(part.startswith(".") for part in parts):
        return _block(
            "dotfile", relpath, None, f"{relpath}: hidden files and folders are not allowed"
        )
    if is_dir:
        if relpath == REFERENCES_DIR:
            return None
        if parts[0] in _CODE_FOLDERS:
            message = f"{relpath}/: a skill never runs code, so a {parts[0]}/ folder is not allowed"
        elif parts[0] == REFERENCES_DIR:
            message = f"{relpath}/: references/ holds files only, one level deep"
        else:
            message = f"{relpath}/: the only folder a skill may have is references/"
        return _block("folder_not_allowed", relpath, None, message)
    if relpath == SKILL_FILE:
        return None
    if len(parts) == 2 and parts[0] == REFERENCES_DIR and _REFERENCE_NAME.fullmatch(parts[1]):
        return None
    if len(parts) > 2 or (len(parts) == 2 and parts[0] != REFERENCES_DIR):
        folder = "/".join(parts[:-1])
        return path_finding(folder, is_dir=True) or _block(
            "folder_not_allowed", relpath, None, f"{folder}/: nested folders are not allowed"
        )
    lowered = relpath.lower()
    if lowered.endswith(_ARCHIVE_SUFFIXES):
        message = f"{relpath}: archives are not allowed in a skill"
    elif lowered.endswith(_CODE_SUFFIXES):
        message = f"{relpath}: a skill never runs code, so program and script files are not allowed"
    else:
        message = (
            f"{relpath}: only SKILL.md and references/<name>.md or .txt "
            "(letters, digits, '.', '_' and '-') are allowed"
        )
    return _block("file_not_allowed", relpath, None, message)


def _layout_findings(files: Mapping[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    if SKILL_FILE not in files:
        findings.append(
            _block("skill_md_missing", SKILL_FILE, None, "SKILL.md is missing or could not be read")
        )
    if len(files) > MAX_FILES:
        findings.append(
            _block(
                "too_many_files",
                ".",
                None,
                f"A skill has at most {MAX_FILES} files; this one has {len(files)}",
            )
        )
    total = 0
    for relpath in sorted(files):
        problem = path_finding(relpath)
        if problem is not None:
            findings.append(problem)
        size = len(files[relpath].encode("utf-8", "surrogatepass"))
        total += size
        cap = MAX_SKILL_BYTES if relpath == SKILL_FILE else MAX_REFERENCE_BYTES
        if size > cap:
            findings.append(file_too_large(relpath, size, cap))
    if total > MAX_TOTAL_BYTES:
        findings.append(skill_too_large(total))
    return findings


def file_too_large(relpath: str, size: Optional[int], cap: int) -> Finding:
    shown = f"{size:,} bytes" if size is not None else "more"
    return _block(
        "file_too_large",
        relpath,
        None,
        f"{relpath} is {shown}; the cap is {cap:,} bytes (oversize files are rejected, never cut)",
    )


def skill_too_large(total: int) -> Finding:
    return _block(
        "skill_too_large",
        ".",
        None,
        f"The skill's files total {total:,} bytes; the cap is {MAX_TOTAL_BYTES:,}",
    )


# --------------------------------------------------------------------------- #
# Content rules
# --------------------------------------------------------------------------- #

_FETCHERS = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|aria2c)"
_INTERPRETERS = (
    r"(?:sh|bash|zsh|dash|ksh|csh|tcsh|fish|python[0-9.]*|perl|ruby|node|deno|bun|php|"
    r"pwsh|powershell|iex|invoke-expression|osascript|source)"
)
# A bare pipe (no fetch on the line) is checked for every interpreter but
# "fish" and "source", which end ordinary prose and table rows ("Claim |
# Source", "rice | beans | fish"); a fetch piped into either still blocks.
_BARE_INTERPRETERS = (
    r"(?:sh|bash|zsh|dash|ksh|csh|tcsh|python[0-9.]*|perl|ruby|node|deno|bun|php|"
    r"pwsh|powershell|iex|invoke-expression|osascript)"
)
# A flag (of sudo or env) never spans a pipe, so each pipe's check stops at
# the next one.
_FLAGS = r"(?:-[^\s|]+\s+)*"
_SUDO = rf"(?:sudo\s+{_FLAGS})?"
# An interpreter named by its path or run through env: "/bin/bash",
# "/usr/bin/env bash", "env sh". After a fetch any path counts.
_PATHED = rf"(?:[\w.~-]*/)*(?:env\s+{_FLAGS}(?:[\w.~-]*/)*)?"
# After a bare pipe only a path written as one counts ("/bin/bash", "~/x/sh",
# "./venv/bin/python", ".venv/bin/python", "../x/node"): a repo slug
# ("nodejs/node") or a docs path ("docs/python") that ends a table cell or
# prose is not a shell.
_EXPLICIT_PATH = r"(?:~|\.[\w.~-]*)?/(?:[\w.~-]+/)*"
_BARE_PATHED = rf"(?:{_EXPLICIT_PATH})?(?:env\s+{_FLAGS}(?:{_EXPLICIT_PATH})?)?"

_FETCH = re.compile(rf"\b{_FETCHERS}\b", re.IGNORECASE)
# What a fetch on the same line must come before: a pipe into an
# interpreter that does not pipe on.
_PIPE_INTO = re.compile(rf"\|\s*{_SUDO}{_PATHED}{_INTERPRETERS}\b(?!\s*\|)", re.IGNORECASE)
_INTERPRETER = re.compile(rf"\b{_INTERPRETERS}\b", re.IGNORECASE)
# What an interpreter on the same line must come before: a fetch run through
# command or process substitution (bash -c "$(curl ...)", bash <(curl ...),
# sh -c `wget ...`).
_SUBSTITUTED_FETCH = re.compile(rf"(?:\$\(|<\(|`)\s*{_FETCHERS}\b", re.IGNORECASE)
_SHELL_PIPE = re.compile(
    # Any pipe into an interpreter that then ends the line, takes a flag
    # ("| bash -s", "| python3 -") or ends the command. A Markdown table
    # cell ("| python |") is followed by another "|", and a dash that starts
    # prose ("| Fish - salmon |") by a space and more words; neither matches.
    rf"\|\s*{_SUDO}{_BARE_PATHED}{_BARE_INTERPRETERS}"
    r"(?=\s*(?:$|-(?:\S|\s*$)|[;&)<>`'\"]))"
    # Possessive: the spaces either side of the optional "(" never trade
    # characters, so a long run of them after "iex" is scanned once.
    r"|\biex\s*+\(*+\s*+(?:irm|iwr|invoke-restmethod|invoke-webrequest|new-object)\b",
    re.IGNORECASE,
)
_DECODE_EXEC = re.compile(
    r"\bbase64\s+(?:-[a-z]*d[a-z]*|--decode)\b"
    r"|\b(?:eval|exec)\s*\("
    r"|\beval\s+[\"'`$]"
    r"|\binvoke-expression\b"
    # Windows binaries that fetch, decode or run code for the caller.
    r"|\bcertutil(?:\.exe)?\b[^\n]*?\s[-/](?:decode|decodehex|urlcache)\b"
    r"|\b(?:mshta|rundll32|regsvr32)(?:\.exe)?\b"
    # -e, -ec and any prefix of -EncodedCommand.
    r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?\s[-/](?:e|ec|en\w*)\b",
    re.IGNORECASE,
)
_PASSWORD_ARCHIVE = re.compile(
    r"\bpassword[\s-]*protected\s+(?:\w+\s+){0,2}(?:zip|archive|rar|7z|7-zip|tarball)s?\b"
    r"|\b(?:zip|rar|7z|archive)\b[^\n.]{0,40}\b(?:password|passphrase)\s*[:=]"
    r"|\bpassword\s*[:=]\s*[\"'`]?openclaw\b"
    r"|\b(?:unzip|7z|7za|unrar)\b[^\n]*\s-p\S*",
    re.IGNORECASE,
)
_PASTE_SITE = re.compile(
    r"\b(?:pastebin|requestbin|ngrok|hastebin|ghostbin)\b"
    r"|\b(?:glot\.io|rentry\.(?:co|org)|webhook\.site|paste\.ee|pipedream\.net|transfer\.sh|"
    r"termbin\.com|dpaste\.(?:com|org)|interact\.sh|burpcollaborator\.net|"
    r"requestcatcher\.com)\b",
    re.IGNORECASE,
)
_PRIVILEGE = re.compile(
    r"\bsudo\b|\bdoas\b|\brunas\b"
    r"|\b(?:run|start|launch|open|execute)\b[^\n.]{0,40}?\bas\s+(?:an?\s+)?"
    r"(?:administrator|admin|root|superuser)\b"
    r"|\b(?:administrator|admin|root|elevated|superuser)\s+(?:rights|privileges?)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATH = re.compile(
    r"(?<!\w)\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b"
    r"|(?<!\w)\.aws\b"
    r"|(?<![\w.])\.env\b"
    r"|(?<!\w)\.(?:netrc|npmrc|pypirc|git-credentials|gnupg)\b"
    r"|\.kube[/\\]config\b|\.docker[/\\]config\.json\b|\.config[/\\]gcloud\b"
    r"|/etc/(?:passwd|shadow|sudoers)\b|\bwallet\.dat\b"
    r"|\bKeychains?[/\\]|\.keychain(?:-db)?\b"
    r"|\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain)\b"
    r"|\bcookies\.sqlite\b|\.binarycookies\b|\bkey4\.db\b|\blogins\.json\b"
    r"|(?:chrome|chromium|edge|brave|opera|vivaldi|default|profile\s*\d*)[/\\]+"
    r"(?:network[/\\]+)?(?:cookies|login\s+data)\b"
    r"|\b(?:SOUL|MEMORY|AGENTS|TOOLS|IDENTITY)\.md\b",
    re.IGNORECASE,
)
# Bidi controls and Unicode tag characters, named so this source stays ASCII.
_SPLICE_OR_BIDI = re.compile(
    "[\N{ARABIC LETTER MARK}\N{LEFT-TO-RIGHT MARK}\N{RIGHT-TO-LEFT MARK}"
    "\N{LEFT-TO-RIGHT EMBEDDING}-\N{RIGHT-TO-LEFT OVERRIDE}"
    "\N{LEFT-TO-RIGHT ISOLATE}-\N{POP DIRECTIONAL ISOLATE}"
    "\U000e0000-\U000e007f]"
)
# A run of variation selectors (prompt.VARIATION_SELECTORS): they hide bytes
# after a visible character. Only one U+FE0F right after a visible
# character (an emoji's presentation) is allowed.
_SELECTOR_RUN = re.compile(f"(?:{VARIATION_SELECTORS.pattern})+")
_EMOJI_PRESENTATION = "\N{VARIATION SELECTOR-16}"
# C0 and C1 controls other than tab and newline (a lone carriage return
# survives CRLF normalisation and can hide the start of a line).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_HTML_COMMENT = re.compile(r"<!--(.*?)(?:-->|\Z)", re.DOTALL)
# "[//]: # (text)" and "[x]: <> (text)": Markdown's own comments.
_MARKDOWN_COMMENT = re.compile(r" {0,3}\[[^\]\n]*\]:\s*(?:#|<>)")
_HIDDEN_MARKUP = re.compile(
    r"<\s*(?:script|style|iframe|object|embed)\b"
    r"|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])",
    re.IGNORECASE,
)

_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s<>\"'`]+", re.IGNORECASE)
_URL_TRAILER = ".,;:!?)]}*_"
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}\.?", re.I)

# Searched anywhere in a heading's text: "How to install", "Initial setup"
# and "Prereqs" open a setup section as "Install" and "Setup" do.
_INSTALL_HEADING = re.compile(
    r"\b(?:pre-?req(?:uisite)?s?|install\w*|set[\s-]?up\w*|requirements|dependencies|"
    r"getting\s+started|quick[\s-]?start|before\s+you\s+(?:start|begin))\b",
    re.IGNORECASE,
)
_INSTALL_HEADING_ACTION = re.compile(r"\b(?:install|download)\w*\s+\S", re.I)
_INSTALL_ACTION = re.compile(
    r"\b(?:re)?(?:download|install)(?:s|ed|ing|er|ers|ation)?\b"
    r"|\b(?:run|execute|launch|double-click)\s+"
    r"(?:(?:the|this|that|a|an|following|below|above|attached|downloaded)\s+){0,3}"
    r"(?:commands?|scripts?|installers?|binar(?:y|ies)|programs?|executables?|one-liners?|"
    r"\S+\.(?:exe|dmg|pkg|sh|ps1|bat|msi|app))\b"
    r"|\b(?:in|into|from)\s+(?:your|a|the)\s+(?:terminal|shell|command\s+line|console|powershell)\b"
    r"|(?:^|[\s`$>])(?:sudo\s+)?(?:pip3?|pipx|npm|npx|pnpm|yarn|brew|apt(?:-get)?|yum|dnf|"
    r"pacman|choco|winget|scoop|curl|wget|chmod|bash|sh|zsh|python3?|node|clawhub|openclaw|"
    r"git\s+clone|go\s+install|cargo\s+install)(?=\s|$)"
    r"|(?:^|[\s`$>])\./\S",
    re.IGNORECASE,
)

# A line's wording counts as an instruction only when nothing in the same
# clause before it negates or reports it: "never skip an approval" and "a
# skill that asks you to skip approvals is a red flag" are ordinary prose.
_NEGATION = re.compile(
    r"\b(?:never|not|no|nor|cannot|\w+n['’]t|nobody|nothing|refuses?|asks?|asking|tells?|"
    r"telling|wants?|tries|trying|attempts?|claims?|says?|red\s+flags?)\b",
    re.IGNORECASE,
)
_CLAUSE_BREAK = re.compile(r"[.!?;:]")
_BYPASS = re.compile(
    r"\b(?:skip(?:s|ping)?|bypass\w*|disabl\w*|circumvent\w*|suppress\w*|ignor(?:e|es|ing)|"
    r"avoid\w*|turn(?:s|ing)?\s+off|switch(?:es|ing)?\s+off|get\s+around|work\s+around)\s+"
    r"(?:(?:the|any|all|every|each|this|these|those|an?|its|their|your|user's|owner's|further|"
    r"extra|manual|human)\s+){0,3}"
    r"(?:approvals?|confirmations?|approval\s+(?:cards?|steps?|prompts?)|"
    r"confirmation\s+(?:prompts?|steps?|dialogs?)|permission\s+(?:prompts?|checks?|cards?)|"
    r"consent)\b"
    r"|\bwithout\s+(?:first\s+)?(?:asking|checking\s+with|confirming\s+with)\b"
    r"|\b(?:no\s+need\s+to|(?:you\s+)?(?:don't|do\s+not)\s+need\s+to)\s+"
    r"(?:ask|confirm|wait\s+for\s+(?:approval|confirmation))\b",
    re.IGNORECASE,
)
_SECRETS = (
    r"(?:passwords?|passcodes?|passphrases?|api[\s_-]?keys?|access\s+keys?|secret\s+keys?|"
    r"private\s+keys?|tokens?|credentials?|2fa\s+codes?|otp|one[\s-]time\s+(?:codes?|passwords?)|"
    r"verification\s+codes?|pins?|seed\s+phrases?|recovery\s+(?:phrases?|codes?)|"
    r"security\s+codes?|cvv|card\s+numbers?)"
)
_CREDENTIAL_REQUEST = re.compile(
    rf"\b(?:ask|request|prompt)\s+(?:the\s+)?(?:user|owner|them|people)\s+"
    rf"(?:for|to\s+(?:send|share|paste|type|enter|provide|give))\b[^.\n!?]{{0,40}}?\b{_SECRETS}\b"
    rf"|\b(?:paste|send|share|give|type|enter|provide|tell|post|dm)\s+(?:me|us|crawler)\s+"
    rf"(?:with\s+)?(?:your|their|the)\s+(?:\w+\s+){{0,2}}{_SECRETS}\b"
    rf"|\b(?:paste|send|share|type|enter|provide|post)\s+(?:your|their|the\s+user's)\s+"
    rf"(?:\w+\s+){{0,2}}{_SECRETS}\s+(?:here|below|to\s+me|with\s+me|"
    rf"in(?:to)?\s+(?:the\s+|this\s+)?(?:chat|conversation|message|reply))\b"
    rf"|\bwhat(?:'s|\s+is)\s+(?:your|the\s+user's)\s+(?:\w+\s+){{0,2}}{_SECRETS}\b",
    re.IGNORECASE,
)


def _later(first: re.Pattern[str], then: re.Pattern[str], line: str) -> bool:
    """Whether *then* matches on *line* after *first* does, in one search
    for each: whatever can follow a later *first* can follow the leftmost
    one, so the leftmost is enough. A lazy "first.*?then" regex retries
    every *then* from every *first*, quadratic on a long line."""
    start = first.search(line)
    return start is not None and then.search(line, start.end()) is not None


def _shell_pipe(line: str) -> bool:
    """Whether *line* pipes a fetch into an interpreter anywhere later on it,
    runs a fetch through substitution after an interpreter, or pipes into an
    interpreter that then ends the command. Linear in the line's length."""
    return (
        _later(_FETCH, _PIPE_INTO, line)
        or _later(_INTERPRETER, _SUBSTITUTED_FETCH, line)
        or _SHELL_PIPE.search(line) is not None
    )


# Each rule's check takes one line and returns something truthy on a hit.
_LINE_RULES: tuple[tuple[str, Callable[[str], object], str], ...] = (
    ("shell_pipe", _shell_pipe, "Pipes text into a shell or an interpreter"),
    (
        "decode_exec",
        _DECODE_EXEC.search,
        "Decodes, evaluates or loads hidden code (base64 decoding, eval, exec, "
        "Invoke-Expression, an encoded PowerShell command or a Windows loader binary)",
    ),
    ("password_archive", _PASSWORD_ARCHIVE.search, "Mentions a password-protected archive"),
    ("paste_site", _PASTE_SITE.search, "Names a paste or request-capture site"),
    ("privilege_escalation", _PRIVILEGE.search, "Asks for administrator or root rights"),
    (
        "sensitive_path",
        _SENSITIVE_PATH.search,
        "Names a credential store or an agent memory file (SSH or cloud keys, .env, a "
        "keychain, browser cookies or saved logins, SOUL.md, MEMORY.md, AGENTS.md, TOOLS.md, "
        "IDENTITY.md)",
    ),
    (
        "hidden_markup",
        _HIDDEN_MARKUP.search,
        "Has markup that hides text from the rendered page (script, style or a hidden element)",
    ),
)


def _negated(line: str, start: int) -> bool:
    before = line[:start]
    cut = max((m.end() for m in _CLAUSE_BREAK.finditer(before)), default=0)
    return _NEGATION.search(before[cut:][-80:]) is not None


def _url_host(url: str) -> tuple[str, bool]:
    """The URL's host and whether it was written in brackets (IPv6)."""
    rest = url.split("://", 1)[1]
    authority = re.split(r"[/?#\\]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]
    if authority.startswith("["):
        return authority[1:].split("]", 1)[0], True
    return unquote(authority.split(":", 1)[0]).lower(), False


def _is_ip_literal(url: str) -> bool:
    host, bracketed = _url_host(url)
    if bracketed:
        return True
    if not host:
        return False
    if _NUMERIC_HOST.fullmatch(host):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _codepoints(chars: list[str]) -> str:
    unique = sorted(set(chars))
    shown = ", ".join(f"U+{ord(c):04X}" for c in unique[:4])
    return shown + (", …" if len(unique) > 4 else "")


def _hidden_selectors(line: str) -> list[str]:
    """The variation selectors on *line* that could hide text: all of them
    but a single U+FE0F right after a visible character."""
    found: list[str] = []
    for match in _SELECTOR_RUN.finditer(line):
        start = match.start()
        if match.group() == _EMOJI_PRESENTATION and start > 0 and not line[start - 1].isspace():
            continue
        found.extend(match.group())
    return found


def _line_findings(relpath: str, number: int, line: str) -> list[Finding]:
    findings: list[Finding] = []
    hidden = (
        _INVISIBLE_CHARS.findall(line) + _SPLICE_OR_BIDI.findall(line) + _hidden_selectors(line)
    )
    if hidden:
        findings.append(
            _block(
                "invisible_unicode",
                relpath,
                number,
                f"Invisible or direction-changing characters ({_codepoints(hidden)})",
            )
        )
    controls = _CONTROL.findall(line)
    if controls:
        findings.append(
            _block(
                "control_character",
                relpath,
                number,
                f"Control characters ({_codepoints(controls)})",
            )
        )
    for rule, matches, message in _LINE_RULES:
        if matches(line):
            findings.append(_block(rule, relpath, number, message))
    if _MARKDOWN_COMMENT.match(line):
        findings.append(
            _block(
                "hidden_comment",
                relpath,
                number,
                "A Markdown comment: hidden from the rendered page but read by the model",
            )
        )
    for match in _URL.finditer(line):
        url = match.group().rstrip(_URL_TRAILER)
        if _is_ip_literal(url):
            findings.append(
                _block(
                    "ip_literal_url",
                    relpath,
                    number,
                    f"Links an address by IP number instead of a name: {_shown(url, 200)}",
                )
            )
        else:
            findings.append(
                _warn("external_url", relpath, number, f"External link: {_shown(url, 200)}")
            )
    for match in _BYPASS.finditer(line):
        if not _negated(line, match.start()):
            findings.append(
                _warn(
                    "approval_bypass",
                    relpath,
                    number,
                    "Asks to skip, bypass or turn off an approval or confirmation",
                )
            )
            break
    for match in _CREDENTIAL_REQUEST.finditer(line):
        if not _negated(line, match.start()):
            findings.append(
                _warn(
                    "credential_request",
                    relpath,
                    number,
                    "Asks for a password, key, token or code in chat",
                )
            )
            break
    return findings


def _install_findings(relpath: str, lines: list[str], body_start: int) -> list[Finding]:
    """Block lines in a Prerequisites / Install / Setup section (up to the
    next heading of the same or a higher level) that tell the reader to
    download, install or run something."""
    findings: list[Finding] = []
    fenced = fence_mask(lines)
    level: Optional[int] = None
    message = "A setup section tells the reader to download, install or run something"
    for number, line in enumerate(lines, start=1):
        if number < body_start:
            continue
        found = None if fenced[number - 1] else heading(line)
        if found is not None:
            found_level, title = found
            if level is not None and found_level <= level:
                level = None
            if level is None and _INSTALL_HEADING.search(title):
                level = found_level
                if _INSTALL_HEADING_ACTION.search(title):
                    findings.append(_block("install_section", relpath, number, message))
            elif level is not None and _INSTALL_ACTION.search(title):
                # A sub-heading of a setup section ("### Download the helper").
                findings.append(_block("install_section", relpath, number, message))
            continue
        if level is not None and _INSTALL_ACTION.search(line):
            findings.append(_block("install_section", relpath, number, message))
    return findings


def _comment_findings(relpath: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _HTML_COMMENT.finditer(text):
        if any(ch.isalpha() for ch in match.group(1)):
            findings.append(
                _block(
                    "hidden_comment",
                    relpath,
                    text.count("\n", 0, match.start()) + 1,
                    "An HTML comment with words in it: hidden from the rendered page but read "
                    "by the model",
                )
            )
    return findings


def _guard_findings(relpath: str, text: str) -> list[Finding]:
    """PromptGuard grades HIGH or CRITICAL block the skill; an exception in
    the guard blocks it too (fail closed)."""
    try:
        result = PromptGuard().scan(text)
        level = result.threat_level
        if level not in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            return []
        findings: list[Finding] = []
        for detection in result.detections:
            if detection.severity not in ("high", "critical"):
                continue
            matched = str(detection.matched_text or "")
            offset = text.find(matched) if matched else -1
            line = text.count("\n", 0, offset) + 1 if offset >= 0 else None
            findings.append(
                _block(
                    "prompt_guard",
                    relpath,
                    line,
                    f"The prompt guard grades this {detection.severity}: "
                    f"{_shown(detection.pattern_name)}",
                )
            )
        if not findings:
            findings.append(
                _block(
                    "prompt_guard",
                    relpath,
                    None,
                    f"The prompt guard grades this file {level.value}",
                )
            )
        return findings
    except Exception:
        return [
            _block(
                "guard_error",
                relpath,
                None,
                "The prompt guard failed on this file, so it is blocked (fail closed)",
            )
        ]


def _description_findings(description: Any, text: Optional[str]) -> list[Finding]:
    """The description is the one piece of skill text that goes into the
    system prompt, the slot the model trusts most. The prompt shows it
    through sanitise_line, so it may hold nothing that would remove (a
    format finding): what the guard checks is then exactly what the prompt
    shows, and a "<>" or private-use splice cannot hide words from the
    guard that the sanitiser would join back up. It is held to the bar
    saved memory facts meet: the guard must grade it NONE or LOW, raw and
    as shown (a whole file only blocks at HIGH). A guard exception blocks
    it (fail closed)."""
    if not isinstance(description, str) or not description.strip():
        return []
    line = _key_line(text, "description")
    shown = sanitise_line(description)
    if shown != " ".join(description.split()):
        return [
            _block(
                "description_invalid",
                SKILL_FILE,
                line,
                "The description goes into the system prompt, so it may not contain '<', '>' "
                "or control, private-use, unassigned, invisible or variation-selector characters",
            )
        ]
    try:
        unsafe = [
            result
            for result in (PromptGuard().scan(description), PromptGuard().scan(shown))
            if not result.is_safe
        ]
        if not unsafe:
            return []
        level = unsafe[0].threat_level.value
    except Exception:
        return [
            _block(
                "guard_error",
                SKILL_FILE,
                line,
                "The prompt guard failed on the description, so it is blocked (fail closed)",
            )
        ]
    return [
        _block(
            "description_guard",
            SKILL_FILE,
            line,
            f"The description goes into the system prompt and the prompt guard grades it {level}; "
            "it must grade none or low",
        )
    ]


def scan_text(relpath: str, text: str, *, body_start: int = 1) -> list[Finding]:
    """Every content rule for one file. *body_start* is the first line that
    counts as Markdown body for the setup-section rule (SKILL.md's
    frontmatter is YAML, where "#" starts a comment, not a heading)."""
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    findings: list[Finding] = []
    for number, line in enumerate(lines, start=1):
        findings.extend(_line_findings(relpath, number, line))
    findings.extend(_install_findings(relpath, lines, body_start))
    findings.extend(_comment_findings(relpath, text))
    findings.extend(_guard_findings(relpath, text))
    return findings


def _body_start(text: str) -> int:
    split = split_frontmatter(text.replace("\r\n", "\n"))
    return split[2] if split is not None else 1


_SEVERITY_ORDER = {BLOCK: 0, WARN: 1}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates and order SKILL.md first, then by file, line,
    severity and rule, so the same files always give the same report."""
    unique = list(dict.fromkeys(findings))
    return sorted(
        unique,
        key=lambda f: (
            f.file != SKILL_FILE,
            f.file,
            f.line or 0,
            _SEVERITY_ORDER.get(f.severity, 2),
            f.rule,
            f.message,
        ),
    )


def scan(
    files: Mapping[str, str],
    frontmatter: Optional[Mapping[str, Any]],
    *,
    folder: Optional[str] = None,
) -> list[Finding]:
    """Every block and warn rule of spec §4.1 over one skill's files.

    *files* maps each relative path ("SKILL.md", "references/x.md") to its
    text. Beyond the spec's list, the description (the only skill text that
    reaches the system prompt) must be exactly what the prompt shows (rule
    ``description_invalid``) and grade NONE or LOW with the prompt guard
    (rule ``description_guard``). *frontmatter* is SKILL.md's parsed
    frontmatter, or None when it
    could not be parsed (parse_skill_md reports why, so the key checks are
    skipped here rather than repeated as "name is required"). *folder*, when
    given, must equal the frontmatter's name.
    """
    findings = _layout_findings(files)
    if frontmatter is not None:
        skill_md = files.get(SKILL_FILE)
        findings.extend(check_frontmatter(frontmatter, folder=folder, text=skill_md))
        findings.extend(_description_findings(frontmatter.get("description"), skill_md))
    for relpath in sorted(files):
        text = files[relpath]
        body_start = _body_start(text) if relpath == SKILL_FILE else 1
        findings.extend(scan_text(relpath, text, body_start=body_start))
    return sort_findings(findings)
