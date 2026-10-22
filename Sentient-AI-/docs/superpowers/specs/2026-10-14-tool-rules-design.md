# Tool rules: rules on tool-call arguments (security S9)

Built-in safety rules and owner-written rules that are checked against every tool call's
arguments. A call that breaks a rule gets an approval card that names the rule. A rule can never
block a call outright, and it can never let a call run that would otherwise have needed a card.

Status: built in the security wave (WAVE 1, S9), on the WAVE 0 call-checks pipeline. The full
design with every review note is `security10/design/S9.md`; this page is the trimmed record that
ships with the code.

## 1. Decision

- decisions.md item 3 (Progent-style rules): a call that breaks a rule raises an approval card
  that names the rule; it does not hard-fail. A few built-in rules are on by default; the owner
  adds rules on the web; rules only narrow automatically, and widening needs the owner.
- One install-wide switch, the `tool_rules` capability ("Ask before calls that break a tool
  rule"): a policy switch (`tools=()`), on by default, low risk, no settings, no key, no outbound
  calls. A switch read that fails counts as on.
- Owner decision 8c: rule B3 stays quiet on a personal install with no organisation known; S1's
  first-time-recipient note does the asking there.
- Rules cannot be managed from chat, a channel or a tool (like tutor locks). A change that
  loosens protection (a rule removed, a built-in turned off) sends the owner a fact-only notice on
  every linked channel; tightening changes are audited and send nothing.

## 2. The rule grammar

An owner rule is `{name, tool, conditions[0..5]}`. A call breaks it when the tool glob matches
and every condition holds; with no conditions it asks before every call of the matched tools.

- `name`: 3-60 characters from `[A-Za-z0-9 .,&:()'/_-]`, whitespace collapsed; never `@`, a link
  or a host name; unique (case-insensitive) and never a built-in rule's name.
- `tool`: a lower-case glob over canonical tool names (no per-account slug), from
  `[a-z0-9_.*?-]`, 1-120 characters, matched with `fnmatchcase`. MCP tools are
  `mcp.<server>.<tool>`. A glob that can only match the runtime's own tools (`tools.find`,
  `tutor.*`) is refused, and the engine skips those tools whatever a glob says.
- `arg`: a top-level argument, a dotted path into nested objects (`fields.text`; lists flattened
  at every level), or `*` for every argument. Keys starting with `_` (card-bound facts) are never
  read. An absent argument never satisfies a condition.

| op | value | holds when |
|---|---|---|
| `equals` | text ≤200 or number | any leaf equals it (normalised text, look-alike spellings too, or numerically) |
| `not_equals` | text ≤200 or number | the argument is present and some leaf differs (strict: a look-alike differs) |
| `contains` | text 1-200 | a leaf's normalised or homoglyph-folded form contains it (zero-width splices, fullwidth and Cyrillic look-alikes cannot dodge it) |
| `regex` | pattern ≤100 that passes the safety check | `re.search` (ignore case) matches a leaf's normalised or folded form; a leaf over 4,000 characters, or more than 16,000 characters searched for one condition, counts as a match |
| `in_list` | 1-50 texts ≤200 | any leaf equals one of them (as `equals`) |
| `domain_in` | 1-50 domains | an address, link host or bare host name in the leaves is at one of them or a subdomain |
| `domain_not_in` | 1-50 domains | one is not; for a named argument a non-empty leaf with nothing recognisable also counts (fail closed) |
| `number_gt` / `number_lt` | finite number | a leaf that reads as a number (`$1,250.50`) is more / less |

Domains are lower-cased, IDNA-encoded (`münchen.de` is stored as `xn--mnchen-3ya.de`), at least one
dot, no scheme or wildcard. Nothing that looks like a key, password, card, bank or ID number can
be saved (the secret guard's detector over the name, the glob and each condition read as
`{arg: value}`); the refusal never echoes the value. At most 50 rules; identical rules are refused.

**The regex safety check** (`grammar.compile_regex`, on the parser of the venv's Python 3.12):

- at most 100 characters; no back-references, look-arounds or conditionals;
- a group that repeats more than once may hold no repeat (fixed or not) and no alternation;
- at most one open-ended repeat (`*`, `+`, `{n,}`); no bounded repeat above 50;
- the backtracking choices multiply to at most 4,000 with an open-ended repeat, 1,000 without;
- the estimated worst-case steps of one search over a 4,000-character value are at most
  5 × 4,000² (`MAX_SEARCH_STEPS`), every step inside a repeat of more than one character counting
  4 times (`GENERAL_REPEAT_WEIGHT`);
- the pattern is compiled without capturing groups (the parser must read the capture-free twin as
  the same pattern, else it is refused).

A search cannot be interrupted once started, so these static limits are what bound one search:
the slowest accepted shapes take 0.1-0.3 s of CPU on 4,000 hostile characters on an idle machine
(about 0.6 s with the machine busy). One evaluation starts no new search after 0.25 s; a rule
whose search budget ran out asks.

## 3. The built-in rules

All four are on by default; a missing row means on. B1-B3 never apply to reads; B4 applies to
writes only. "Content Crawler read" is the turn's taint tracker (`TaintTracker.seen_untrusted`,
this turn's tool results and fenced shared content) plus the history: tool-result envelopes,
someone else's fenced words (a forwarded Telegram message), attachment file names, Crawler's own
earlier replies and every conversation-summary line that is not the person's first line. "The
person's own messages" are the rest of the user-role text plus an unattended run's approved prompt.

| key | name | breaks when |
|---|---|---|
| `untrusted_recipient` (B1) | Address seen only in content Crawler read | a write's address argument holds an address the person did not type that appeared in read content, or one with unusual characters (non-ASCII, punycode, invisible, a quoted local part, or a local-part character beyond letters, digits and `. _ % + -`), or an address the rules cannot read |
| `many_recipients` (B2) | More than 10 recipients | a write's address arguments hold more than 10 unique addresses (each unreadable one counts) |
| `outside_share` (B3) | Sharing outside your organisation | a write declared `shares_content` (forward, share, invite) aims at an address outside the calling person's organisation domains, or at one the rules cannot read; quiet when none is known; every share asks when they cannot be read |
| `untrusted_link` (B4) | Link seen only in content Crawler read | a write's string leaf holds an http(s) link whose site appeared only in read content and is not (a subdomain of) a host the person named; or a link written to deceive (user information, a `\` in the authority, a percent-encoded host, odd slashes), whatever the person named |

Address arguments are the tool's declared `spec.outbound.recipients`; for a tool that declares
none (MCP tools, built-ins), every leaf that is itself an address or a list of addresses (any
RFC 5322 form: bare, quoted local part, `mailto:`, `Name <address>` with any display name, a group
label, a comment), never an address mentioned in prose. Local parts are read with every RFC 5322
character (`x=@evil.com`, `a#@evil.com`), and a quoted local part both as one address at the
domain after it and for any address written inside the quotes. On a declared recipients path, an
`@` (or a fullwidth one) that no readable address accounts for is an unreadable recipient: B1 and
B3 ask and B2 counts it; on an undeclared tool, a list entry shaped like one address that does not
parse (`bob@[10.0.0.1]`) counts the same way, while mentions such as `@channel` do not. Links are
read with the host a browser opens (WHATWG: `\` ends the authority like `/`), and every host
urllib reads too counts for owner rules and lookups. Gmail `reply`/`send_draft` and Outlook
`reply` carry no recipient argument, so B1-B3 cannot see their recipients; they always ask anyway.

Card texts name rules, argument names, counts and the owner's own rule text, never an argument
value: reason `Tool rule: <name>.` (or `Tool rules: <a>; <b>; <c>; and N more.`) appended to
today's reason, and one `tool_rule` / `warn` security note per rule (at most five, then
"and N more tool rules").

## 4. The three stages and the failure policy

The check is `ToolRulesCheck` (`name = policy = "tool_rules"`, stages turn, approve, execute),
first in the call-checks pipeline (S9, S5, S7, S1, S10).

- **Turn** (inside `_run_turn`): the switch, the rule snapshot and the turn's view (owner text,
  history indicators, the taint tracker) are read once per turn into the turn's scratch;
  organisation domains only for a sharing call, once per turn. A hit answers `Escalate(...,
  names_rule=True)`: an auto-run call (tier, low-risk run, grant, a policy-auto write such as
  `reminders.create`, a weekly desktop act) becomes a card with one `call_check_escalated` row,
  its low-risk slot handed back and no grant offered; a call already going to a card gets the
  sentence and notes only. A call parked outside a turn (`park_card`: mail and upload cards) is
  checked without the turn: B1 and B4 are skipped, the switch is read directly, and it never
  raises.
- **Approve** (`approve_action`): Allow, without touching the store (a person's tap satisfies
  every "ask" rule; `applies_to` is False there).
- **Execute** (the executor's backstop): a call a person approved and every READ go on untouched
  (the briefing, trigger, knowledge and tutor reads call the executor directly). Any other call
  is checked again with B2, B3 and the owner rules; a hit is refused with
  `{"ok": false, "requires_approval": true, "call_check": "tool_rules", "policy": "tool_rules",
  "rule": "<ids>", "error": "This needs the owner's approval first: it matches one of their tool
  rules. Nothing was run."}`. The model never learns a rule's name. This fires when a rule was
  added mid-turn or a caller skipped the runtime.

| failure | turn | execute |
|---|---|---|
| switch read raises | counts as on | counts as on |
| store unreadable | writes ask with "rules unavailable" and every built-in on; reads go on (logged once per turn) | a non-person-approved write is refused |
| a stored row today's validator refuses | every write its glob covers asks ("could not check") | same |
| one rule's evaluation raises, or its search budget runs out | that rule counts as broken | same |
| organisation domains raise | every share asks | same |
| arguments deeper than 16 levels or over 5,000 values | the rule asks | same |
| the check itself raises | the pipeline's fail-closed path | refusal for a non-read |

## 5. Data model

Migration `0031_tool_rules` (parent `0030_browser_site_rules`), two install-wide tables, guarded
against already existing, no enums, no CHECK constraints:

- `tool_rules`: `id` UUID PK, `name` varchar(60), `tool_pattern` varchar(120), `conditions` JSON,
  `created_by` UUID → `users.id` ON DELETE SET NULL, `created_at` timestamptz (indexed
  `ix_tool_rules_created_at`, oldest-first listing).
- `tool_rule_builtins`: `key` varchar(40) PK, `enabled` boolean, `changed_by` UUID → `users.id`
  ON DELETE SET NULL, `changed_at` timestamptz. Unknown keys are ignored on read.

Nothing is encrypted (owner policy matched on every turn, never sent to a model, secret-shaped
values refused). `DbToolRuleStore` keeps a 30 s snapshot cache dropped on every write through the
store; one write at a time per process; each write and its audit row commit together. Audit
events (`connector_name` "agent", endpoint `/api/security/tool-rules`): `tool_rule_created` and
`tool_rule_deleted` carry the rule id, name, tool pattern, argument and operator names and a
16-hex sha256 digest of the canonical rule, never a condition value; `tool_rule_builtin_changed`
carries `{key, enabled}`.

## 6. Routes

Owner-only (`require_admin`: 401 signed out, 403 otherwise) and web-only, under
`/api/security/tool-rules`:

| method + path | answer |
|---|---|
| `GET /` | `{enabled, store_ok, builtins[], rules[] (oldest first, with summary and created_by email), org_domains, limits, operators}`; 503 when the store is not wired |
| `POST /` | 201 the rule; 422 `{"detail": "<the validator's reason>"}`; 503 when the store cannot be written |
| `DELETE /{rule_id}` | 204; 404 "No such tool rule."; then the owner notice |
| `PUT /builtins/{key}` `{"enabled": bool}` | 200 the built-in; 404 "No such built-in rule."; turning one off sends the owner notice |
| `POST /preview` `{tool, conditions}` | `{valid, error, summary, matches (at most 50), reads, writes, mcp, truncated}`; an invalid draft is `valid: false`, never a 422; saves nothing |
| `GET /catalog` | `{tools: [{tool, category, args}], mcp_hint: "mcp.<server>.<tool>"}`, without the runtime's own tools |

The notices go through `app.state.owner_send` after the commit; an absent sender is skipped and
logged (`tool_rules_owner_notice_skipped`), a failed one logged by type, and neither undoes the
change. The UI is Security → Tool rules (`frontend/src/pages/security/ToolRulesTab.tsx`).

## 7. Open gaps

1. Reply and `send_draft` recipients are derived server-side, so B1-B3 cannot see them before the
   card. Those tools always ask, and S1's bind shows the resolved recipients: no card is lost.
2. Another process sees a rule change within 30 s (the snapshot cache). The executor backstop
   reads the store's snapshot, so a rule saved through the same process applies at once.
3. Text the owner pastes into web or Slack counts as their own words (no marker exists there);
   Telegram forwards are fenced and count as read content.
4. On a forward, S1 and S9 may both show an "outside your organisation" style line (accepted for
   v1; S1 speaks about the send, S9 about sharing).
5. The regex choice budget still refuses some reasonable patterns (`https?://[^/]+/login`,
   `\d+(\.\d{2})?`): an optional element next to an open-ended repeat. Widening it is a decision
   for the owner.
6. Two shared helpers the runtime calls on every turn are quadratic on hostile text:
   `services/agent/taint.py extract_indicators` (S9 no longer calls it) and
   `services/agent/shared_content.py _FENCE_RE` on unfinished opening tags (an integration
   request with the suggested fix is in the S9 delivery notes).

## 8. Deviations from the design text (each asks more, never less)

- The regex check adds the choice budget, the step estimate, the general-repeat weight and the
  capture-free compile (section 2): the design's five checks alone admitted patterns that took
  from one second to a minute on 4,000 characters.
- `equals` and `in_list` also match look-alike spellings; `domain_in` / `domain_not_in` also read
  a value that is itself a bare host name.
- `scan_form` strips every invisible and format character first (the prompt guard's list misses
  U+206A-206F).
- Names that look like a host name are refused, and an owner rule may not reuse a built-in's name.
- `owner_text_of` also drops attachment notes and, of the conversation summary, everything but
  the person's first line; history indicators are read with the rules' own linear extractors.
- A stored row today's validator refuses is kept and asks before every write its glob covers
  (shown on the page as "a rule that could not be read" when its name is refused too), instead of
  failing the whole store.
- Rules created in the same clock instant are stamped one microsecond apart, so the oldest-first
  order (and the order of their notes) is the order they were made.
- B1's "unusual characters" also covers a quoted local part and any local-part character beyond
  letters, digits and `. _ % + -` (the taint tracker cannot read those addresses), so a send to
  `o'brien@...` the person did not type asks. An `@` on a recipients path that no readable address
  accounts for makes B1 and B3 ask and counts for B2; `domain_not_in` on a named argument counts it
  as outside.
- B4 asks before any link written to deceive (user information, a `\` where urllib keeps reading
  the authority, a percent-encoded host, slashes other than `//`), even when its site was not seen
  in read content, and no host the person named exempts it; such a link in the person's own text
  names no host or address for them.

## 9. Tests

`backend/tests/test_tool_rules_grammar.py` and `test_tool_rules_engine.py` (pure, Windows CI),
`test_tool_rules_store.py` (SQLite), `test_tool_rules_runtime.py` (the real runtime and executor
with the pipeline), `test_tool_rules_routes.py` (ASGI), `test_tool_rules_migration.py` (Alembic on a
temporary SQLite file), `test_tool_rules_capability.py`; frontend
`src/pages/security/ToolRulesTab.test.tsx`.

## Shared doc text (pasted at integration)

### docs/CODE-MAP.md

Under "### Tool rules (security S9)":

- `backend/services/security/tool_rules/` — rules on tool-call arguments (security S9): a call
  that breaks one becomes an approval card naming the rule.
  - `grammar.py` — the rule grammar and its validation (name, glob, conditions, the regex safety
    check with its step estimate), summaries, the audit digest, the catalog and the preview's
    matching.
  - `values.py` — leaf selection, text normalisation (NFKC, invisible characters, homoglyph
    folding), address, link and host extraction in linear time, domain matching, numbers.
  - `engine.py` — `evaluate`: the pure evaluator (built-ins B1-B4 first, then owner rules oldest
    first; anything that cannot be checked asks).
  - `builtins.py` — the four built-in rules (address seen only in read content, more than 10
    recipients, sharing outside the organisation, link seen only in read content).
  - `context.py` — what the person wrote versus what Crawler only read, from the turn's messages.
  - `texts.py` — every user-facing sentence: card reasons and notes, the executor's fixed
    refusal, owner notices, validation reasons.
  - `store.py` — `DbToolRuleStore` (rows, audit rows, the 30 s snapshot cache) and
    `InMemoryToolRuleStore`.
  - `check.py` — `ToolRulesCheck`, first in the call-checks pipeline (turn, approve and execute
    stages).
- `backend/api/routes/security_tool_rules.py` — owner-only tool rules (list, add, remove,
  built-in switches, preview, catalog), with the loosening notices.
- `backend/services/capabilities/tool_rules.py` — the `tool_rules` policy switch.
- `backend/models/tool_rule.py` / `alembic/versions/0031_tool_rules.py` — `tool_rules`,
  `tool_rule_builtins`.
- `frontend/src/pages/security/ToolRulesTab.tsx` — Security → Tool rules.
- Backend tests: `test_tool_rules_grammar.py`, `test_tool_rules_engine.py`,
  `test_tool_rules_store.py`, `test_tool_rules_runtime.py`, `test_tool_rules_routes.py`,
  `test_tool_rules_migration.py`, `test_tool_rules_capability.py`.

Under "API routes": `security_tool_rules.py — owner-only tool rules (list, add, remove, built-in
switches, preview, catalog)`. Under "Models & migrations": `tool_rule.py — tool_rules,
tool_rule_builtins (0031)`.

### docs/BACKLOG.md

Under "### Tool rules (security S9)":

**S9 tool rules: shipped.** `services/security/tool_rules/`, `api/routes/security_tool_rules.py`,
`ToolRulesTab.tsx`, migration `0031_tool_rules`. Cards name the rule; rules only add cards. Four
built-in rules are on by default and the owner adds argument rules on Security → Tool rules.
Follow-ups:

- Reply and `send_draft` recipients are not visible to B1-B3 before the card (they always ask).
- The regex choice budget refuses some reasonable patterns (an optional element beside an
  open-ended repeat); widening it needs the owner's decision.
- Rule changes made in another process apply within 30 s.
- `taint.extract_indicators` and `shared_content._FENCE_RE` are quadratic on hostile text.

In the F4 row ("Still open: ... no separate 'new recipient' check"), add: "Partly addressed by
tool rules (security S9): built-in rules ask before an address seen only in read content, more
than 10 recipients, sharing outside the organisation and a link seen only in read content, and
owners can add their own argument rules (Security → Tool rules). Shell side effects are still
open."

### SECURITY.md

Under "### Tool rules":

Every tool call's arguments are checked against four built-in rules and the owner's own rules
before it runs, and a call that breaks one waits for the owner's approval on a card that names
the rule; a rule never blocks a call outright and can never let one skip a card. The built-in
rules ask before a send, share or invite to an address that appeared only in content Crawler
read (an email, a web page, a file, a forwarded message or Crawler's own earlier replies) or that
uses look-alike characters, before one action addresses more than 10 people, before a forward,
share or invite outside the owner's organisation, and before a change that includes a link to a
site seen only in read content. Owner rules (Security → Tool rules, owner only, web only) match a
tool glob and up to five argument conditions; values are normalised (invisible characters,
fullwidth and look-alike letters) so a spliced word cannot dodge a rule, patterns pass a static
safety check that bounds their cost, and anything that cannot be checked asks. The executor
refuses a write a rule matches that no person approved, with a fixed text that never tells the
model the rule. Removing a rule or turning a built-in off notifies the owner on Telegram and
Slack; every change is audited with ids, names and a digest, never a condition value.

### backend/services/capabilities/README.md

Under "### Tool rules (`tool_rules`)":

`tool_rules` ('Ask before calls that break a tool rule', on by default) is a policy switch
(`tools=()`) like `hide_personal_details` and `low_risk_actions`: it only ever adds approval
cards (a call that breaks a built-in or owner rule asks, and its card names the rule), never
removes one. It is read once per turn by the first check of the security call-checks pipeline
(`services/security/tool_rules/check.py`), treats a gate error as on, and keeps its rules in
their own tables (migration `0031_tool_rules`), since capability settings hold numbers only.

### backend/services/security/README.md

The `tool_rules/` row stays as WAVE 0 wrote it. In the paragraph that calls
`tool_rules/{grammar,engine,values,builtins}` "stdlib-only and local", say "local (no network)"
for them instead: they import `prompt_guard`, `permissions` and `redact`, and `tool_registry`
lazily.
