"""Bundled skills: short SKILL.md playbooks in backend/skills/ that teach
Crawler how to do a kind of task with its own tools, read by the model on
demand through skills.read.

Why it exists: groups the rules that decide which skill text may ever reach
the model. A skill is text the team reviewed in a PR and pinned by SHA-256;
it never runs code, installs anything, grants a tool or changes an approval.
Kept import-light: the agent runtime imports ``services.skills.prompt`` from
here, so nothing in this file loads PyYAML or reads the disk.

Modules:
- ``scanner``: the format, size, file and content rules (block and warn
  findings) and the frontmatter parser.
- ``loader``: reading, hashing and loading the skills into a catalog with a
  status per skill; the process-wide bundled catalog.
- ``manifest``: manifest.json, the per-file SHA-256 pins.
- ``prompt``: the <available_skills> system-prompt block.
"""
