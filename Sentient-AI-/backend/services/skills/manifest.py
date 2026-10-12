"""manifest.json: the SHA-256 pin of every file of every bundled skill, and
the check that turns a loaded skill into ``ok``, ``unpinned`` or
``changed``.

Why it exists: the manifest is how a PR reviewer sees exactly which skill
text changed (one hash per file, keys sorted, so a diff names the file),
and how the loader refuses text nobody pinned. A skill missing from it is
``unpinned``; one whose hashes differ is ``changed``; neither is usable.
``python -m scripts.skills_manifest`` writes it from compute_manifest and
render_manifest, so the bytes on disk are always exactly what render_manifest
gives for the loaded skills, and ``--check`` can compare them byte for byte.

Format (spec §3.4):
``{"version": 1, "skills": {"<name>": {"sha256": "...", "files":
{"SKILL.md": "...", "references/x.md": "..."}}}}``, keys sorted, 2-space
indent, trailing newline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Optional

if TYPE_CHECKING:
    from services.skills.loader import SkillCatalog

MANIFEST_VERSION = 1
# A manifest is a few KB; anything far larger is not one.
_MAX_MANIFEST_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")

UNPINNED_REASON = "Not pinned in manifest.json (run python -m scripts.skills_manifest)"
CHANGED_REASON = "Changed on disk: the files no longer match manifest.json"


def empty_manifest() -> dict[str, Any]:
    return {"version": MANIFEST_VERSION, "skills": {}}


def compute_manifest(catalog: SkillCatalog) -> dict[str, Any]:
    """The manifest for every loaded skill that is not ``invalid`` (an
    invalid skill's files were not all readable, so its hash pins nothing;
    the manifest script refuses to write while one exists)."""
    skills: dict[str, Any] = {}
    for name, record in catalog.skills.items():
        if record.status == "invalid":
            continue
        skills[name] = {"sha256": record.sha256, "files": dict(sorted(record.files.items()))}
    return {"version": MANIFEST_VERSION, "skills": skills}


def render_manifest(data: Mapping[str, Any]) -> str:
    """The manifest's exact file text: sorted keys, 2-space indent, ASCII,
    trailing newline."""
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _valid_entry(name: Any, entry: Any) -> bool:
    if not isinstance(name, str) or not isinstance(entry, dict):
        return False
    files = entry.get("files")
    if not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(entry["sha256"]):
        return False
    if not isinstance(files, dict) or not files:
        return False
    return all(
        isinstance(path, str) and isinstance(digest, str) and _SHA256.fullmatch(digest)
        for path, digest in files.items()
    )


def read_manifest(path: Path) -> dict[str, Any]:
    """The manifest at *path*. A missing, unreadable, oversized or invalid
    file reads as an empty manifest (every skill unpinned: fail closed); a
    malformed entry is dropped, which leaves that skill unpinned."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return empty_manifest()
    if len(raw) > _MAX_MANIFEST_BYTES:
        return empty_manifest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return empty_manifest()
    if not isinstance(data, dict) or not isinstance(data.get("skills"), dict):
        return empty_manifest()
    version = data.get("version")
    if type(version) is not int or version != MANIFEST_VERSION:
        return empty_manifest()
    skills = {
        name: {"sha256": entry["sha256"], "files": dict(entry["files"])}
        for name, entry in data["skills"].items()
        if _valid_entry(name, entry)
    }
    return {"version": MANIFEST_VERSION, "skills": skills}


def pin_status(
    name: str, sha256: str, files: Mapping[str, str], manifest: Mapping[str, Any]
) -> tuple[str, Optional[str]]:
    """``("ok", None)`` when the manifest pins exactly this skill hash and
    these file hashes; ``("unpinned", reason)`` when it has no entry for
    *name*; ``("changed", reason)`` otherwise."""
    entry = manifest.get("skills", {}).get(name)
    if not isinstance(entry, dict):
        return "unpinned", UNPINNED_REASON
    if entry.get("sha256") != sha256 or entry.get("files") != dict(files):
        return "changed", CHANGED_REASON
    return "ok", None
