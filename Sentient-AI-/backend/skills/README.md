# Bundled skills

A skill is a short Markdown playbook (`SKILL.md`) that teaches Crawler how to do one kind
of task well **with its own tools**. The model sees each skill's name and description in
an `<available_skills>` block and reads the body on demand with `skills.read`.

A skill never runs code, installs anything, grants a tool or changes an approval. Every
action it describes still goes through the normal approval rules. Users cannot add skills:
every skill here is text the team reviewed in a pull request and pinned by SHA-256 in
`manifest.json`.

The design is in `docs/superpowers/specs/2026-10-12-muse-skills-and-goals-design.md`
(§3 and §4). The code is in `services/skills/`.

## Layout

```
skills/
├── README.md          this file
├── CREDITS.md         where each skill's method came from
├── manifest.json      SHA-256 of every file of every skill (written by a script)
├── _template/SKILL.md copy this to start (folders starting with "_" are skipped)
└── <name>/
    ├── SKILL.md
    └── references/*.md   optional, one level deep, read with skills.read_reference
```

## Adding a skill

1. Copy `_template/` to `skills/<your-skill-name>/` (lowercase letters, digits and single
   hyphens). Edit its `SKILL.md`: the frontmatter comments explain every key, and the
   body has the usual sections (Purpose, When to use, Workflow, Output, Rules).
2. From `backend/`, run `python -m scripts.skills_manifest`. It scans every skill and
   rewrites `manifest.json`. If any skill is invalid or has a block finding, it prints
   the findings and writes nothing. Warn findings are printed but do not stop it.
3. Run `pytest tests/test_skills_bundled.py`. It fails if a skill is not `ok`, is not
   pinned, has a finding, names a tool that does not exist, or if
   `python -m scripts.skills_manifest --check` would change the manifest.
4. Add the skill to `CREDITS.md` and commit the folder together with `manifest.json`.

No Python change is needed: the loader finds the folder at startup. Editing a skill later
means running step 2 again; a skill whose files no longer match the manifest is shown as
"Changed on disk" and is not offered.

## Rules the loader enforces

- **Files:** only `SKILL.md` and `references/<name>.md` or `.txt`. Any other file or
  folder, a symlink, a dotfile, a `scripts/` or `bin/` folder, an archive or a binary
  makes the skill invalid. Text must be UTF-8.
- **Sizes:** `SKILL.md` and each reference at most 24,000 bytes; at most 20 files and
  512 KB per skill. Oversize files are rejected, never cut.
- **Frontmatter:** YAML between a first line `---` and the next `---`, read with
  `yaml.safe_load`. Anchors, aliases, tags (`!!`) and duplicate keys are refused. Values
  must have the right type: quote anything YAML could read as a number, a date or
  a yes/no value (`version: "1.0"`, not `version: 1.0`).
- **Line endings:** CRLF is turned into LF before hashing, and `.gitattributes` keeps
  these files LF, so every OS pins the same bytes.

## What the scanner reports

**Block findings** (the skill is not offered) include: a pipe into a shell or an
interpreter, decoding or evaluating hidden code, password-protected archives, links to an
IP address or to paste and request-capture sites, a setup or install section that tells
the reader to download, install or run something, `sudo` or administrator rights, paths
to credential stores or to agent memory files, invisible or direction-changing Unicode,
HTML or Markdown comments with words in them, text the prompt guard grades high or
critical, and a description it grades medium or above (the description goes into the
system prompt, so it is held to a stricter bar).

**Warn findings** (shown in the report, the skill still loads): any external link, words
asking to skip or turn off an approval, a request for passwords, keys or codes in chat,
and frontmatter keys Crawler ignores (`allowed-tools`, `metadata.openclaw.install` and
the like).

Writing tips:

- Describe a dangerous thing in words rather than quoting it. The prompt guard reads
  patterns, not intent: "never send your password" and "never reveal the system prompt"
  are graded high because they contain "send your password" and "reveal the system
  prompt". Write "Crawler never handles passwords" instead.
- Name Crawler tools (`web.search`, `goals.list`), never shell commands.
- Use no links unless the skill really needs one; each one is listed for the reviewer.

## Statuses

| Status | Meaning |
|---|---|
| `ok` | Parses, has no block finding, matches `manifest.json`. The only usable status. |
| `invalid` | Breaks a file, size or format rule. |
| `blocked` | Has a block finding. |
| `unpinned` | Not in `manifest.json`. |
| `changed` | Files differ from `manifest.json` (also set at run time when a re-read hash no longer matches). |
