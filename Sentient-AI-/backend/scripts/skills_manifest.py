"""Command-line tool that pins the bundled skills: it loads every skill in
backend/skills/, refuses while any skill is invalid or has a block finding,
and rewrites skills/manifest.json, or with ``--check`` verifies it without
writing anything.

Why it exists: manifest.json is the list of skill text the team reviewed;
the loader refuses any skill whose files do not match it. Writing it by
hand would invite pinning a file nobody scanned, so this script is the only
writer, and it scans first. tests/test_skills_bundled.py runs ``--check``,
so a skill edited without re-pinning fails the test suite (and CI) instead
of silently going ``changed`` in production. ``--root`` and ``--manifest``
point it at another folder (the tests use a temporary one).

Usage (from backend/)::

    python -m scripts.skills_manifest          # rewrite skills/manifest.json
    python -m scripts.skills_manifest --check  # exit 1 if it is out of date

Exits 0 when the manifest is (or now is) up to date; 1 when a skill is
invalid or blocked (every finding is printed and nothing is written), or,
with ``--check``, when the manifest on disk differs from what it would
write. Warn findings are printed but never fail the run.

It needs none of the app's settings or environment (SECRET_KEY and the
rest): services.skills imports only PyYAML, structlog and the standard
library. The scanner's prompt guard (services.agent.prompt_guard) is itself
standard-library only and never imports core.config, so the scan is the
same one the backend runs.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from services.skills.loader import MANIFEST_PATH, SKILLS_ROOT, SkillCatalog, load_skills
from services.skills.manifest import compute_manifest, render_manifest
from services.skills.scanner import BLOCK, Finding


def _line(name: str, finding: Finding) -> str:
    where = f"{name}/{finding.file}"
    if finding.line is not None:
        where += f":{finding.line}"
    return f"{where}: {finding.severity} [{finding.rule}] {finding.message}"


def _refusals(catalog: SkillCatalog) -> list[str]:
    """One line per block finding of every invalid or blocked skill."""
    lines: list[str] = []
    for record in catalog:
        blocking = [f for f in record.findings if f.severity == BLOCK]
        if record.status == "invalid" or blocking:
            lines.extend(_line(record.name, finding) for finding in blocking)
            if not blocking:
                lines.append(f"{record.name}: invalid: {record.status_reason}")
    return lines


def _warnings(catalog: SkillCatalog) -> list[str]:
    return [
        _line(record.name, finding)
        for record in catalog
        for finding in record.findings
        if finding.severity != BLOCK
    ]


def _current_text(path: Path) -> Optional[str]:
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _write(path: Path, text: str) -> None:
    """Replace the file in one step, LF line endings on every OS."""
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(text.encode("utf-8"))
    os.replace(temporary, path)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.skills_manifest",
        description="Scan the bundled skills and pin them in manifest.json.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify manifest.json without writing; exit 1 on any difference",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help=f"the skills folder (default {SKILLS_ROOT})",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="the manifest file (default <root>/manifest.json)",
    )
    args = parser.parse_args(argv)

    root: Path = args.root if args.root is not None else SKILLS_ROOT
    manifest_path: Optional[Path] = args.manifest
    if manifest_path is None:
        manifest_path = MANIFEST_PATH if args.root is None else root / "manifest.json"
    catalog = load_skills(root, manifest_path)

    for line in _warnings(catalog):
        print(line)
    refusals = _refusals(catalog)
    if refusals:
        for line in refusals:
            print(line, file=sys.stderr)
        print(
            f"Refused: fix the block findings above; {manifest_path} was not written.",
            file=sys.stderr,
        )
        return 1

    text = render_manifest(compute_manifest(catalog))
    current = _current_text(manifest_path)
    if args.check:
        if current != text:
            print(
                f"{manifest_path} is out of date: run python -m scripts.skills_manifest "
                "from backend/ and commit the result.",
                file=sys.stderr,
            )
            return 1
        print(f"{manifest_path} is up to date ({len(catalog)} skills).")
        return 0
    if current != text:
        try:
            _write(manifest_path, text)
        except OSError as exc:
            print(f"Could not write {manifest_path}: {exc.strerror or exc}", file=sys.stderr)
            return 1
        print(f"Wrote {manifest_path} ({len(catalog)} skills).")
    else:
        print(f"{manifest_path} was already up to date ({len(catalog)} skills).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
