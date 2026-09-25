# Skills: design

Date: 2026-09-25. Branch: `feat/connectors-and-skills` (from `origin/main` at `5f6ddc1`).
Backlog item covered: C5 (SKILL.md loader). The companion spec is
`2026-09-25-connectors-design.md`. Both specs share the OpenClaw research summarised in §2.

## 1. Goal

A skill is a short Markdown playbook that teaches Crawler how to do a kind of task
well. Crawler should read the same `SKILL.md` format as OpenClaw, so the ecosystem's best
playbooks can be adapted. The difference is that a skill must never be able to run
code, install anything, or quietly change what Crawler believes.

We adapt the five most-downloaded OpenClaw skills, as chosen by the owner on 2026-09-25:

| Skill | ClawHub downloads, 2026-09-25 | What it teaches |
|---|---|---|
| `self-improving-agent` | 481K | Log mistakes, corrections and feature requests, and promote repeated lessons |
| `skill-vetter` | 274K | Vet a skill before trusting it |
| `github` | 199K | Triage PRs, issues and CI |
| `ontology` | 199K | Keep a typed knowledge graph of people, projects, tasks and events |
| `google-workspace`, adapted from `gog` | 195K | Gmail, Calendar, Drive, Docs, Sheets and Contacts, plus Microsoft 365 |

`self-improving` (210K, third place) was dropped because it duplicates `self-improving-agent`.

The owner also chose **"skills drive our tools only"**. A skill never runs a shell command or a script.

**Adding a skill must be easy.** Adding one means adding one folder under `backend/skills/`
(§3).

## 2. What OpenClaw does, and what went wrong

OpenClaw skills are `SKILL.md` files in the [AgentSkills](https://agentskills.io/specification) format:

- YAML frontmatter with `name` and `description`, plus an OpenClaw `metadata` block that can declare required binaries and installers.
- A body the model reads when the skill is relevant.

Most skills tell the model to run a command-line tool through the `exec` shell tool,
with the user's full privileges. OpenClaw's docs say skill allowlists are "not a host
shell authorization boundary".

| Incident | Vector | Our answer |
|---|---|---|
| Koi "ClawHavoc", 341 then 824 malicious skills | A "Prerequisites" section tells the user or agent to install `openclaw-agent`, delivered as a password-protected ZIP or a `curl` one-liner that dropped AMOS stealer | No shell and no installers. Install instructions are a block finding (§5). |
| Snyk "ToxicSkills", 76 payloads | Base64 `eval`, Unicode smuggling, credentials passed through the model | The scanner blocks these. Secrets never reach the model. |
| Cisco, "What Would Elon Do?" (#1 ranked) | Silent `curl` exfiltration plus a prompt injection telling the agent to skip approval | No shell. Approvals are enforced in code, not by the prompt. |
| Unit 42, `omnicogg` | A 22 MB README padded past the scanner's size threshold | Hard size caps. Oversize files are rejected, not skipped. |
| Zenity, "OpenClaw or OpenDoor" | An injected Google Doc made the agent rewrite `SOUL.md`, add a Telegram bot and install a cron job | Writes to memory need owner approval. Skills are read-only to the model and cannot schedule anything. |
| Typosquats (`clawhubb`, `clawhub1`) and one slug shared by four publishers (`skill-vetter`) | Name confusion | No marketplace. Skills are pinned by SHA-256 and have one local name. |

Sources are listed in §12.

**What is worth copying.**
- The format.
- Progressive disclosure: the prompt lists only each skill's name and description, and the body is read on demand.
- The content of the top skills: logging formats, vetting checklists, graph types and CI triage flows.

## 3. Where skills live, and how to add one

```
backend/skills/
├── README.md                 # how to add a skill (the steps below)
├── CREDITS.md                # source URL, author, version, licence of each adapted skill
├── manifest.json             # SHA-256 of every file in every bundled skill
├── _template/SKILL.md        # copy this to start a new skill
├── self-improving-agent/SKILL.md
├── skill-vetter/SKILL.md
├── github/SKILL.md
├── ontology/SKILL.md
└── google-workspace/SKILL.md
```

**To add a bundled skill:**

1. Copy `backend/skills/_template/` to `backend/skills/<your-skill>/`. Edit its `SKILL.md`.
2. Run `python -m scripts.skills_manifest` from `backend/`. It scans every skill and rewrites `manifest.json`. It refuses to write the manifest if any skill has a block finding.
3. Run `pytest tests/test_skills_bundled.py`. It fails if any bundled skill is missing from the manifest, has a hash mismatch, or has a block finding.

No Python code changes are needed. The loader discovers folders at startup. The
manifest is how a PR reviewer sees exactly which skill text changed.

The desktop app already bundles the whole `backend/` folder (`desktop/scripts/stage-stack.mjs`),
so bundled skills ship with it automatically.

**User-added skills** go in `skills/` inside the per-user data directory that the
platform layer provides: Application Support on macOS, `%APPDATA%` on Windows and
`/data` in containers. They are added only through Settings ▸ Skills (§8).

## 4. Format

A skill is a folder containing `SKILL.md` and, optionally, `references/*.md`.

**Frontmatter** is parsed with `yaml.safe_load` only. There is no JSON5 fallback and no single-line parser, because each extra parser is one more way for an input to be read two different ways.

| Key | Treatment |
|---|---|
| `name` | Required. Must match `^[a-z0-9]+(-[a-z0-9]+)*$`, be at most 64 characters, and equal the folder name. |
| `description` | Required. 1 to 1024 characters. |
| `license`, `compatibility`, `homepage`, `version` | Kept for display. |
| `allowed-tools` | Honoured as a **restriction**. While the skill is active, only these tools are offered. It can narrow the tool set but never grant a tool. |
| `metadata.crawler.requires.connectors` | A list of connector types, such as `[github]`. The skill is left out of the prompt unless the user has one of them connected. This keeps the prompt small. |
| `metadata.crawler.requires.capabilities` | A list of capability keys. The skill is left out of the prompt unless all of them are on. |
| `metadata.openclaw` / `metadata.clawdbot` | `requires` and `install` are **ignored** and listed in the scan report as "wanted to install X". `os` and `emoji` are kept. |
| `command-dispatch`, `disable-model-invocation`, `user-invocable` | Not supported in v1. Reported as ignored. |

**Size caps.**
- `SKILL.md`: at most 24 KB, which is about 6,000 tokens. The AgentSkills spec recommends staying under 5,000.
- Each reference file: at most 24 KB.
- A folder: at most 20 files and 512 KB in total.

Anything larger is **rejected**. Only `.md` and `.txt` files are allowed. Any other file makes the scan fail with the file named. That includes `scripts/`, `hooks/`, `.pyc` files, archives, symlinks and dotfiles.

## 5. Scanner (`backend/services/skills/scanner.py`)

The scanner is deterministic and needs no network. Its rules come from `skill-vetter`'s
red-flag list and the Koi, Snyk, Cisco and Unit 42 findings. Each finding is
`block` or `warn`, and carries the file, the line number and the rule id.

**Block findings:**

- a shell pipe to an interpreter (`curl … | sh`, `wget … | bash`, `iex (irm …)`);
- `base64 -d`, `eval`, `exec(` or `Invoke-Expression`;
- a password-protected archive, or the text "password: openclaw";
- a URL whose host is an IP literal;
- links to paste sites (glot.io, rentry.co, pastebin) or webhook.site;
- a "Prerequisites" or "Install" section that tells the reader to download or run a binary;
- a request for sudo or admin rights;
- a path to `~/.ssh`, `~/.aws`, a Keychain, browser cookies, `SOUL.md`, `MEMORY.md` or `AGENTS.md`;
- invisible Unicode (zero-width, bidi overrides, tag characters);
- a hidden HTML comment that contains instructions;
- text in the existing `RuntimePromptGuard` high-threat set;
- any size or file-type rule from §4.

**Warn findings:**

- any external URL (listed in the report);
- words that ask the agent to skip or disable confirmations;
- a request for credentials or API keys in chat;
- frontmatter keys we ignore.

A skill with any block finding cannot be enabled. The owner can read the whole report, and every line of the skill, in the UI before approving it.

## 6. Loading, trust and the prompt

### 6.1 Sources and trust

| Source | Trust |
|---|---|
| Bundled, in `backend/skills/` | Reviewed in PRs. `manifest.json` pins each file's SHA-256. On load, a mismatch or a block finding disables the skill and writes an audit event. Bundled skills are on by default. |
| User-added, in the data directory | Added through Settings ▸ Skills ▸ Add by uploading a folder or zip. The upload is staged in a temporary folder and scanned. The owner reads the report and approves. Only then is the folder moved into place and its hash stored in a new `skill_approvals` table. If the files change later, the skill is disabled until it is re-approved. |

There is no marketplace, no URL install and no auto-update. The model cannot add, edit
or delete a skill. OpenClaw's `skill-creator` path, where the agent writes skills, is left out on purpose.

### 6.2 Prompt block

When the `skills` capability is on, the system prompt gets an `<available_skills>`
block. It has one line per skill that is enabled and whose `metadata.crawler.requires`
are met, giving the skill's name and description.

The block is capped at 2,000 characters, which is under about 500 tokens. Past the cap, descriptions are
shortened and names are kept. Names and descriptions are sanitised the way connector account labels are: non-printable characters are stripped and the text is length-capped.

The block sits after `<permissions>` and before `<user_memory>` in the one system message.
It is sorted and byte-stable, so the provider's prompt cache survives. That means
`_build_tools_and_memory` returns a fourth value, and `_with_system_prompt`, `chat` and
`stream_chat` gain a `skills_text` parameter. It is threaded through all four call sites: web, stream,
resume and the channel applier.

### 6.3 Skill tools (`skills.*`)

- **`skills.read(name)`** returns the body of `SKILL.md`.
- **`skills.read_reference(name, file)`** returns one file from `references/`.
- **`skills.scan_report(name)`** returns the scanner's findings for one skill. The `skill-vetter` skill uses it (§9.2).

These are the only ways a skill's text reaches the model. All three are READ actions. The hash is checked again at read time, so a skill that
changed on disk since startup is refused. Each tool is part of the `skills` built-in family.

**Offered tools.** `skills.read` is a core tool whenever the `skills` capability is on, so the
tool cap never hides it (connectors spec §4.5). The other `skills.*`, `learnings.*` and
`graph.*` tools are found through `tools.find`. A skill's body names the tools it uses, so the
model loads them when it reads the skill.

**Result budget.** `RESULT_CHAR_BUDGETS` gains `skills.read` and `skills.read_reference` at
24,000 characters, which matches the file cap, so a skill body is never cut in the middle.

A skill body is **instructions from a source the owner approved**, so it is not marked as
tainted. It is still screened by the prompt guard on every read.

## 7. Skill data tools

Two of the chosen skills need somewhere to store things. Instead of letting them write
files, we give them typed, bounded stores.

**Storage.** Both stores live in one new table, `skill_records`, with columns `id`, `user_id`, `namespace`,
`kind`, `record_id`, `data` (JSON), `version`, `created_at` and `updated_at`. The
limits are 5,000 records per user and 8 KB per record. An update writes a new version
and keeps the previous one, which matches the append-only rule in `ontology`.

**`learnings.*`** is used by `self-improving-agent`:

- `learnings.log` records a learning, error or feature request, with a Pattern-Key, priority, area and summary. It returns the id, such as `LRN-20260925-001`. If an entry with the same Pattern-Key exists, the log folds into it: it bumps `recurrence_count`, sets `last_seen` and returns the existing id.
- `learnings.search` searches by pattern key, text, kind, area or status.
- `learnings.update` changes status (`pending`, `in_progress`, `resolved`, `wont_fix`, `promoted`) and adds resolution notes.
- `learnings.propose_memory` turns a learning into a proposed entry in Crawler's persistent memory. It **always needs the owner's approval**, under every tier. When approved, it goes through the existing memory write path, including its injection screening.

This is the safe version of "promote to `SOUL.md`". Nothing reaches the system prompt
without a person saying yes, which closes the Zenity persistence path.

**`graph.*`** is used by `ontology`:

- `graph.create`, `graph.update`, `graph.get` and `graph.query` handle entities. `graph.query` filters by type and by exact-match properties.
- `graph.relate` and `graph.related` handle relations.
- `graph.validate` checks the whole graph and returns every violation.

The validation rules are enforced in code on every write, not left as documentation:

- required properties per type;
- status enums;
- `Credential` and `Account` entities may not hold `password`, `secret`, `token` or `api_key` properties, which forces the use of `secret_ref`;
- relations marked acyclic, such as `blocks`, may not form a cycle;
- an event's `end` must not be before its `start`.

**Permissions.**
- The `skills`, `learnings` and `graph` families are built-ins with stance `user_confirm`, like `desktop` and `browser`. With an `auto_approve` stance and an auto-approve account default, the offer step would relabel every approval-gated action as "auto" and run it unattended.
- Their policy rows make the reads and the bounded-store writes (`learnings.log`, `learnings.search`, `learnings.update` and all `graph.*`) AUTO_APPROVE, so they run without a card.
- `learnings.propose_memory` uses its own permission key, `memory`, with a USER_CONFIRM row. It is marked `always_confirm` (connectors spec §4.4), so it gets a card under every tier.

**Why unattended store writes are safe.** A learning or graph record can contain text copied from an
untrusted page. That is acceptable because:
- neither store is ever rendered into the system prompt;
- records come back only as tool results, which the prompt guard scans like any other tool output;
- the only path into the prompt is `propose_memory`. It re-runs `screen_memory_content` when the proposal is made and again when it is approved, and a person reads the card.

**Memory write.** An approved proposal becomes a normal `Memory` row with
`source = MemorySource.agent`. It is the first writer of that value. Proposals are not stored
anywhere else. If the card expires after 15 minutes, the learning stays `pending` and can be proposed again.

**Identity.** Both stores take `user_id` from the executor, never from the model's arguments. Any
`user_id` or `user_confirmed` in the arguments is dropped, as `ReminderToolkit` does.

**Account export and delete.** `skill_records` is added to the account export. Its rows cascade on user delete.

**Capability.** A new `skills` capability in `backend/services/capabilities/skills.py`
claims `skills.*`, `learnings.*` and `graph.*`. It is on by default, with risk "low".

## 8. Settings ▸ Skills page

- It lists every skill with its source, version, hash, scan verdict and an on/off switch.
- "View" shows the full `SKILL.md` and its references, with scan findings highlighted on their lines.
- "Add skill" accepts a folder or zip. It shows the scan report and asks the owner to confirm "I have read this skill" before approving.
- A skill whose files changed since approval shows "Changed on disk, re-approve".
- Settings ▸ Permissions gains the `skills` capability automatically through the existing capability report.

The API lives in `backend/api/routes/skills.py`. Every route requires the owner.

| Route | Purpose |
|---|---|
| `GET /api/skills` | List skills |
| `GET /api/skills/{name}` | Show files and findings |
| `POST /api/skills/upload` | Stage and scan, returning a staging id and the report |
| `POST /api/skills/{staging_id}/approve` | Approve a staged skill |
| `PATCH /api/skills/{name}` | Turn a skill on or off |
| `DELETE /api/skills/{name}` | Remove a user-added skill. Bundled skills cannot be deleted, only turned off. |

## 9. Adapting the five skills

Each source file was read in full on 2026-09-25. Each skill is rewritten into
`backend/skills/<name>/SKILL.md`:

- Its method and formats are kept.
- Every shell command is mapped to a Crawler tool.
- Every step that installs, executes or reaches outside the skill's own store is removed.

`CREDITS.md` records the source URL, author, version and licence of each.

### 9.1 `self-improving-agent` (pskoett, v4.0.2, 21 KB)

- **Keep:**
  - the LRN, ERR and FEAT entry formats and their `TYPE-YYYYMMDD-XXX` ids;
  - the Pattern-Key taxonomy and its "reuse before minting" rule;
  - recurrence folding;
  - the promotion rule: at least 3 recurrences, across at least 2 tasks, within 30 days;
  - the detection triggers and priority levels;
  - the rule against logging secrets.
- **Map:** the `mkdir` and `printf` initialisation and every `grep` query become `learnings.log` and `learnings.search`. The Area tags gain personal-assistant areas (email, calendar, shopping, travel, school) next to the coding ones.
- **Remove:**
  - hook installation (`cp -r hooks`, `openclaw hooks enable`);
  - the `extract-skill.sh` automatic skill extraction, so the model may *suggest* a skill but cannot write one;
  - the `sessions_*` cross-session tools;
  - the `git clone` and `clawhub install` instructions;
  - the `.gitignore` section;
  - "promote aggressively" to `SOUL.md`, `TOOLS.md` and `AGENTS.md`, which becomes `learnings.propose_memory` with approval.
- **Security note:** the original writes durable prompt files on its own. That is the persistence path Zenity abused, so it is the one behaviour that changes in substance.
- **Metadata:** `requires.capabilities: [skills]`.

### 9.2 `skill-vetter` (spclaudehome, v1.0.0, 4.5 KB)

- **Keep:** the four-step protocol (source, code review, permission scope, risk class), the red-flag list, the risk table, the report format, the trust hierarchy, and "Paranoia is a feature".
- **Map:** the model does not vet from scratch. When the user asks about a skill, the model calls `skills.scan_report(name)` and explains the report in the skill's format. The "Quick Vet" `curl` commands to the GitHub API are removed. Source metadata comes from the upload record.
- **Remove:** any "install OK" verdict the model could act on. Only the owner's click in Settings enables a skill.
- **Note:** four ClawHub publishers use the slug `skill-vetter`. We credit spclaudehome's text and use our own copy only.
- **Scanner clash:** the original red-flag list quotes the very strings our scanner blocks, such as `base64` decoding and memory file names. Our copy describes each red flag in words ("decodes hidden text and runs it", "reads the agent's own memory files"). It must pass the scanner with no exceptions, because an allowlist for our own skill would be a hole.

### 9.3 `github` (steipete, ClawHub v1.0.0, and the current bundled version)

- **Keep:** "always name owner/repo"; the CI triage flow (checks, then run, then failed logs); structured output before prose; and the PR, issue and CI sections of the bundled version.
- **Map:**

  | `gh` command | Crawler tool |
  |---|---|
  | `gh pr checks` | `github.get_pr_checks` |
  | `gh run list` | `github.list_runs` |
  | `gh run view` | `github.get_run` |
  | `gh run view --log-failed` | `github.get_failed_logs` |
  | `gh api repos/.../pulls/N` | `github.get_pr` |
  | `gh issue list --json` | `github.list_issues` |

- **Remove:**
  - `gh auth login` and `GH_CONFIG_DIR`, because the connector owns auth;
  - the brew installer metadata;
  - the bundled version's "landing ownership" rule, which said to keep working until the PR is merged. A merge always needs the user's approval.
- **Metadata:** `requires.connectors: [github]`.

### 9.4 `ontology` (oswalpalash, v1.0.4, 6.7 KB)

- **Keep:** the core types (Person, Organization, Project, Task, Goal, Event, Location, Document, Message, Thread, Note, Account, Device, Credential, Action, Policy), the relation examples, "planning as graph transformation", the append-only rule, and the trigger phrases ("remember that…", "what do I know about…").
- **Map:** each `python3 scripts/ontology.py create|query|get|related|relate|validate` call becomes the matching `graph.*` tool. The `schema.yaml` constraints become code (§7).
- **Remove:** the `scripts/` folder, the `mkdir` and `touch` quick start, the Python examples for cross-skill communication and causal inference, and the "migrate to SQLite" advice. Storage is already a database.
- **Security note:** "Credential stores only `secret_ref`, never secrets" was only documentation in the original. Here it is enforced.
- **Metadata:** `requires.capabilities: [skills]`.

### 9.5 `google-workspace`, adapted from `gog` (steipete, ClawHub v1.0.0, 1.7 KB)

- **Keep:** the command coverage: Gmail search and send, Calendar events, Drive search, Contacts, Sheets (get, update, append, clear, metadata) and Docs read. Also keep "Confirm before sending mail or creating events" and "prefer structured output".
- **Map:** each `gog` subcommand becomes the matching `google_workspace.*` action in the connectors spec.
- **Remove:** `gog auth credentials` and `gog auth add`, because the OAuth broker owns auth. Also remove `GOG_ACCOUNT`, `--no-input` and the export to `/tmp`.
- **Add:** the Microsoft 365 equivalents, so the same skill covers Outlook users.
- **Metadata:** `requires.connectors: [google_workspace, microsoft]`, meaning either one satisfies it.

## 10. Error handling

- **Hash check fails at read time.** The skill is disabled and the event is audited. The model is told "skill unavailable", and Settings shows the reason.
- **Malformed upload.** The API returns 422 with the list of findings. Nothing is left on disk outside the staging folder, and staging folders expire after one hour.
- **Store limits.** When a record or the per-user store limit is reached, the tool returns a clear error that names the limit. It never silently drops data.
- **Graph violations.** A graph write that breaks a rule returns every violation and writes nothing.

**Open item for the owner: licences.** ClawHub lists a licence on each skill page. Step 4
records each one in `CREDITS.md` before shipping. If a licence forbids reuse, we write our own text
from the method and keep no copied prose. The full research report, with the verbatim
source texts, stays outside the repo for the same reason.

## 11. Build order

Each step ends with the backend suite green, ruff and tsc clean, and new tests for everything it adds.

1. **Loader, scanner and manifest.** Build `backend/services/skills/` (`loader.py`, `scanner.py`, `manifest.py`), `scripts/skills_manifest.py`, the `_template` folder and `test_skills_bundled.py`. Add the loader and scanner tests to the Windows CI job's list, because paths differ there.
2. **Tools and capability.** Add `skills.*`, the `skills` capability, and the `<available_skills>` prompt block. This step depends on the connectors spec's tool-offering step (§4.5), which adds `tools.find`.
3. **Data stores.** Add the `skill_records` and `skill_approvals` migration, `learnings.*`, `graph.*` and `propose_memory`.
4. **Skill content.** Write the five adapted skills and `CREDITS.md`.
5. **UI.** Build the Settings ▸ Skills page and its API.

## 12. Sources

- OpenClaw skills docs: https://github.com/openclaw/openclaw/blob/main/docs/tools/skills.md
- AgentSkills spec: https://agentskills.io/specification
- ClawHub download ranking: https://clawhub.ai/api/v1/skills?sort=downloads&limit=30
- Skill pages:
  - https://clawhub.ai/pskoett/skills/self-improving-agent
  - https://clawhub.ai/spclaudehome/skills/skill-vetter
  - https://clawhub.ai/steipete/skills/github
  - https://clawhub.ai/oswalpalash/skills/ontology
  - https://clawhub.ai/steipete/skills/gog
- Koi ClawHavoc: https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html
- Snyk ToxicSkills:
  - https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
  - https://snyk.io/blog/clawhub-malicious-google-skill-openclaw-malware/
- Cisco: https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare
- Unit 42: https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
- Zenity: https://labs.zenity.io/p/openclaw-or-opendoor-indirect-prompt-injection-makes-openclaw-vulnerable-to-backdoors-and-much-more
