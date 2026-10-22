# Outbound message checks: hidden characters, recipients and data-carrying links

Status: shipped (security S1). Migration `0026_known_recipients`. Capability `outbound_checks`
(on by default, always available; a policy switch with a floor).

## Why

An injected instruction's goal is usually to get Crawler to send something somewhere. Every send
already asks, but a card that only says "send_email requires approval" is easy to approve without
reading it, and text the owner cannot see (Unicode tag characters, a right-to-left override) can
ride along on a card that looks harmless. S1 cleans what can be cleaned, puts the facts on the
card, and turns a flagged call that would have run without a card into a card. It never removes a
card, and nothing is rewritten except the hidden-character floor.

## What is checked

Before anything Crawler writes leaves the account (an email, a reply, a Slack post, a GitHub
comment, a Notion page, a calendar invitation, text typed into a page or an app, any MCP call):

- **The floor (always on, whatever the switch says).** The executor
  (`ConnectorToolExecutor`, `services/agent/tool_registry.py`) runs `OutboundFloor` at both card
  binds and again right before every dispatch, on every path (approved cards, standing consent,
  unattended runs, weekly acts, MCP):
  - declared outbound text (`ToolSpec.outbound.content`) and every MCP string leaf get the full
    rules of `services/security/outbound_text.clean_text`: tag characters (the three RGI
    subdivision flags kept whole), bidi overrides and isolates, runs of 4+ invisible characters,
    every out-of-context invisible character once a field holds 16+, chained or meaningless
    variation selectors;
  - every other string leaf of a non-READ call (memory, schedule, triggers, knowledge, Drive,
    Docs, built-ins) gets the always-safe subset: tag characters and bidi controls only (review
    SEC-F3, scaffold A35); argument names are cleaned the same way, so a hidden name cannot
    dodge a declared path; reserved `_` names of connector calls (set by binds) are left alone,
    an MCP call's are not;
  - a recipient address that hides any invisible or format character is refused before any card
    (`outbound_rule`, rule `hidden_characters_in_recipient`): stripping it would silently change
    who receives the mail. Arguments the floor cannot clean (nested past 64 levels, or two names
    that differ only by hidden characters) are refused too (`arguments_not_checkable`);
  - a READ is never touched.
- **The notes (switch on), at the turn stage only:**
  - `invisible_characters_kept` (info): isolated zero-width characters left in;
  - links in the declared text: `remote_image` and `encoded_link` (warn), S1's own findings;
    `link_text_mismatch` (S4's `check_local`, high); S4's lookup of `scheme://host/` only
    (`link_dangerous`, `link_suspicious`, `link_not_checked`, in S4's wording). At most three
    link notes from S1, then "And N more links were flagged.";
  - recipients: `recipient_first_time` (warn when a new domain outside the organisation, or with
    no organisation known, gets a real send; info for a draft, a colleague or a known domain),
    `recipient_outside_organisation` (info, only when an organisation is known),
    `recipient_lookalike` (high for a typo or letter swap of a familiar domain, warn for a brand
    used in another name), `recipient_unusual_characters` (high for mixed or confusable scripts
    and for a resolved address that hides characters; info for a single-script international
    domain), `recipient_history_not_checked` (info);
  - replies and drafts: one READ through the executor (`get_message_security` for replies, the
    new Gmail `get_draft` for `send_draft`), pinned to the call's own connector row:
    `recipients_resolved` (info: "This reply goes to: ...", "Outlook picks who this reply goes
    to; from the original it should be: ...", "This draft goes to: ..."), `reply_to_elsewhere`
    (warn), `hidden_characters_in_draft` (warn), `recipients_not_checked` (warn, with the plain
    reason: no read scope, a timeout, the message gone, the service not answering).
- **Order and caps.** High, then warn, then info; within a severity hidden characters, links,
  recipients. At most 6 notes, at most 5 addresses per note, 300 characters per note. Addresses
  appear through `note_address` (the local part as written minus control and format characters,
  then the ASCII domain); hosts in their ASCII form; never message text.
- **The verdict.** No notes: allow. A call that would run without a card (`runs_without_card`,
  scaffold A29) with a high or warn note: `Escalate` with `ESCALATE_REASON`
  (`names_rule=False`, so the sentence reaches the card only when the call really would have run
  unasked). Anything else: `Note`. The switch off: the floor note only, never an escalation.
- **Approve stage:** only the recipient refusal (a row swapped in the database). **Execute
  stage:** pure; a call no person approved is escalated (the executor answers
  `requires_approval`) when the floor removed something or a link finding is certain locally.

The turn-stage check is bounded at 8.5 s inside its 9 s `timeout_s` (the pipeline gives at least
10 s); the recipient READs (6 s), the account probe (4 s), the history SELECT (3 s) and S4's
lookup (4 s) run concurrently, and a part that did not finish says "not checked". Nothing is
ever called safe.

## The sent-to history and its privacy

- `known_recipients` holds, per user, one row per normalised address and one per domain:
  `value_hmac = HMAC-SHA256(key, user_id \0 kind \0 value)` with
  `key = sha256("sentientai.known_recipients.hmac.v1:" + ENCRYPTION_KEY)`, plus `key_id` (first 8
  hex of sha256(key)), first and last sent, and a count. No address, domain, subject or text is
  stored anywhere by S1. A changed key makes every recipient "first time" again (the cautious
  direction) and the old rows are pruned.
- Written only after a successful, approved send of one of the seven mail sends
  (`Outbound.history`): the declared recipients, a Gmail reply's result, or (Gmail `send_draft`,
  Outlook `reply`) the recipients one READ resolved just before the send. The user's own sign-in
  address is never recorded. Recording never changes or fails a send.
- At most 5,000 address and 2,000 domain rows per user (least recently sent pruned first), rows
  unused for 730 days pruned, pruning at most once an hour per user. Forget-all on the Security
  page; the rows go with the user (ON DELETE CASCADE) and are in the account export as
  fingerprints, dates and counts.
- `organisation_domains` is install policy (plaintext, at most 50, owner-edited). Consumer mail
  domains never count as an organisation. `OrgDomains.for_user` (S9's rule B3) answers the
  sign-in domain plus the list, and raises on a read error (scaffold A24).
- Connector account addresses learned from the sent folder live in process memory only (12 h
  found, 1 h not found, at most 1,000).
- What leaves the machine: only `scheme://host/` of each link, to S4's `LinkChecker` (which drops
  userinfo before any lookup, and sends nothing without the owner's key).

## Declarations

`ToolSpec.outbound` (`services/connectors/definition.py`) on 39 actions: the seven mail sends
(`history`), the two drafts (`delivers=False`), calendar events and invitations, Drive sharing,
Slack posts, replies, uploads, statuses and scheduled messages, GitHub issues, comments, pull
requests, reviews, merges, releases, gists, repositories and files, Notion pages, blocks,
properties, rows and comments, Canvas submissions, and the built-in `desktop.act` (`text`) and
`browser.act` (`text`, `fields`). Exempt with a reason (pinned by
`tests/test_outbound_declarations.py`): `google_workspace.respond_to_invite`,
`google_workspace.create_contact`, `microsoft.create_share_link`, `slack.invite_to_channel`,
`github.publish_release`, `github.dispatch_workflow`, every DELETE and FINANCIAL action.

## The call check's contract

Slot 4 of `S9 tool rules -> S5 MCP pin -> S7 site rules -> S1 outbound -> S10` (scaffold D1, D2).
`OutboundCheck(executor, known, org_domains, users, links=None, enabled=None)`; `name="outbound"`,
`policy="outbound_rule"`, stages `turn`, `approve`, `execute`, `timeout_s=9.0`. `applies_to` is
true for every MCP call and every non-READ call with a spec (no I/O). S1's READs go through
`executor.execute(..., approved=False)`; S9's built-in rules must let those internal READs pass.

## Deviations (each with its reason)

1. The three RGI subdivision flags keep their tag sequences; every other tag character goes.
   They are Unicode's only legitimate tag use and carry no data.
2. The reply and draft READ runs in the call check (turn stage), not in the card bind: only a
   check can add typed notes. The bind still stores the cleaned arguments.
3. Escalation is for warn and high notes only; first time on a draft is info, so a fresh history
   does not turn every low-risk draft into a card. The `send_draft` card shows the recipients.
4. An "Outgoing messages" Security tab and a second table, `organisation_domains`: the owner's
   domain list has to be edited somewhere, and `capability_settings` holds numbers only.
5. A hidden character in a recipient address is refused, not flagged.
6. New READ `google_workspace.get_draft` (scope `gmail.read`).
7. Connector account addresses are learned from the sent folder and kept in memory only.
8. A variation selector after a base it means nothing for (a basic selector after ASCII other than
   digits, `#` and `*`; a supplementary one after anything but a CJK ideograph) is removed as
   `extra_variation`: one per letter would otherwise carry a hidden byte per visible character.
9. `ExfilFinding.size` is the total coded characters one link carries (summed over userinfo, path,
   query, fragment and subdomain labels), not the longest single value.
10. URLs are read the way a browser reads them (WHATWG for http and https: backslashes, missing
    slashes, userinfo before the last `@`, IDNA 2008 for `ß` and `ς`), Markdown through
    CommonMark's escapes, HTML through the tokenizer's quoting, CSS through its escapes; where a
    text reads two ways, both readings are checked. Over-reporting costs a card line,
    under-reporting a leak.
11. GitHub's image proxy (`camo.githubusercontent.com`) is judged by itself and by its hex-encoded
    target; a proxy nested deeper than two levels is judged as it stands (the cap never makes a
    link quiet).
12. Argument names are cleaned of tag and bidi characters too; two names that become the same
    are refused rather than guessed between.
13. A host with characters outside ASCII that can never be looked up (one such label over 63
    characters once encoded, or such labels over 253 characters together) is not read as a web
    address: DNS carries nothing longer, so nothing loads from it. Each label is measured before
    any encoding (what IDNA maps to nothing and browsers ignore is removed first, so padding a
    host neither hides it nor gets it refused), and S1 writes punycode itself in O(n log n)
    (CPython's codec rescans a label once per distinct character). A port is read with its
    leading zeros dropped and at most five digits, so the reader never raises. An all-ASCII host
    is read as written, whatever its length.
14. A recipient piece the mail parser fails on (comments or groups nested hundreds deep make
    `email.utils` raise `RecursionError`) gives every `local@domain` token in it, so each still
    gets its notes; for the refusal, such a value holding a hidden character is refused.

Residual, by design: coded data spelled as short words, or cut into pieces under 16 characters
inside a link under 512 characters, is not flagged; a basic variation selector after a non-ASCII
letter is kept (Unicode defines such sequences); Gmail `forward` quotes the original body inside
the connector, which S1 does not clean (third-party text); data carried in a `web.fetch` or
browser URL is S7's and S9's concern; attachments are S10's.

## Tests

`tests/test_outbound_text.py`, `tests/test_outbound_recipients.py` (pure, Windows CI),
`tests/test_known_recipients_store.py`, `tests/test_outbound_check.py`,
`tests/test_outbound_executor_floor.py`, `tests/test_outbound_runtime.py`,
`tests/test_security_outbound_routes.py`, `tests/test_outbound_declarations.py`,
`tests/test_known_recipients_migration.py`, `tests/connectors/test_gmail_get_draft.py`;
frontend `src/pages/security/OutgoingMessagesTab.test.tsx`. Two cases in
`test_outbound_check.py` need S4's real `link_checks` (`@requires_real`).

## Shared doc text (pasted at integration)

### docs/BACKLOG.md ("### Outbound message checks (security S1)")

Done (security S1): the hidden-character floor on every write (full rules on declared outbound
text and MCP arguments, tag and bidi characters everywhere else, argument names included), the
recipient refusal, typed card notes for first-time, outside-organisation, look-alike and
unusual-letter recipients, the real recipients of replies and saved drafts, remote images, coded
values and mismatched link text, S4's lookups of `scheme://host/` only, escalation of a flagged
call that would have run without a card, the keyed-fingerprint sent-to history (migration
`0026_known_recipients`), the owner's organisation domains and the Security page's "Outgoing
messages" tab. The F4 row: "new recipient: done by security S1 (a note, not a rule)".

Follow-ups:
- Web reads that carry data in a URL (`web.fetch`, the browser) are not S1's: S7 and S9.
- Gmail `forward` quotes the original body inside the connector; S1 does not clean that
  third-party text.
- Converge S1's link reading (`outbound_text.find_links`, WHATWG URL reading) and S4's
  (`link_checks`) if both keep growing; S4's `check_local` is handed `scheme://host/` so the two
  never disagree on a host meanwhile.
- A basic variation selector after a non-ASCII letter is kept (no StandardizedVariants table in
  Python); counting it as `kept` would need that table.
- Slack user ids are not recipients S1 can classify.

### docs/CODE-MAP.md ("### Outbound message checks (security S1)")

- `backend/services/security/outbound_text.py` — pure: hidden-character cleaning
  (`clean_text`, `clean_safe_subset`, `hidden_count`, `hides_characters_in_address`), link
  finding in Markdown, HTML, CSS, Slack and bare text (`find_links`), data-carrying links
  (`exfil_findings`), `origin_only`.
- `backend/services/security/outbound_recipients.py` — pure: recipient parsing and
  normalisation, `note_address`, the HMAC (`recipient_hmac`, `hmac_key_id`), `OrgView`,
  `classify`, `address_concern`, `validate_organisation_domain`.
- `backend/services/security/outbound_store.py` — `KnownRecipientStore` (the sent-to history),
  `OrganisationDomainStore`, `UserEmails`, `OrgDomains.for_user` (S9's rule B3),
  `export_for_user`.
- `backend/services/security/outbound.py` — `outbound_fields`, `OutboundFloor` (the executor's
  floor and card bind), `OutboundService` (audit row `outbound_cleaned`, recording after a
  send), `OutboundCheck` (slot 4 of the call checks).
- `backend/api/routes/security_outbound.py` — `/api/security/outbound` (counts, own and
  organisation domains, forget, owner add/remove).
- `backend/services/capabilities/outbound_checks.py`, `backend/models/known_recipient.py`,
  `backend/alembic/versions/0026_known_recipients.py`, Gmail `get_draft`
  (`services/connectors/google_api/gmail.py`), `ToolSpec.outbound` declarations.
- `frontend/src/pages/security/OutgoingMessagesTab.tsx` — Security ▸ Outgoing messages.
- Tests: `test_outbound_text.py`, `test_outbound_recipients.py`, `test_known_recipients_store.py`,
  `test_outbound_check.py`, `test_outbound_executor_floor.py`, `test_outbound_runtime.py`,
  `test_security_outbound_routes.py`, `test_outbound_declarations.py`,
  `test_known_recipients_migration.py`, `tests/connectors/test_gmail_get_draft.py`,
  `OutgoingMessagesTab.test.tsx`.

### SECURITY.md ("### Outbound message checks", under "Prompt-injection defenses")

Before anything Crawler writes leaves the account, S1 removes the characters a reader cannot see
that are used to smuggle text: Unicode tag characters, bidi overrides and isolates, long runs of
zero-width characters and meaningless variation selectors in the text other people read and in
every MCP argument, and tag and bidi characters from every other argument of every write (names
included). This floor runs at the approval card and again right before dispatch, on every path,
whatever the owner's switch says, so no card shows text the owner cannot see and nothing hidden
reaches another person. A recipient address that hides any such character is refused before any
card. With "Check messages before they go out" on (the default), the card also says who the
message really goes to (first time Crawler sends there, outside the organisation, a look-alike of
a familiar address, the real recipients of a reply or a saved draft) and which links can carry
data out (images that load by themselves, long coded values, link text naming another site, the
owner's Google lookup); a flagged call that would have run without a card gets one, and a card
with a warning never offers standing consent. "Could not check" is always said; nothing is called
safe. The sent-to history keeps per-user keyed fingerprints (HMAC under a key derived from
`ENCRYPTION_KEY`), never an address; only `scheme://host/` of a link is handed to the link
lookup, and nothing leaves without the owner's key.

### backend/services/capabilities/README.md ("### Outbound message checks (`outbound_checks`)")

A policy switch with a floor. Some protections must never be off: their core lives in
`services/security` and runs whatever the switch says. For outbound messages that core is the
hidden-character floor (`services/security/outbound.OutboundFloor`, the executor's default at
both card binds and at dispatch) and the refusal of a recipient address that hides characters.
The `outbound_checks` switch (`tools=()`, always available, on by default, `risk="low"`) adds only
the parts that cost reads or only inform: the recipient and link notes on the card (READs through
the executor, one history SELECT, S4's lookup) and the escalation of a flagged call that would
have run without a card. A switch read error counts as on. Its `when_denied` line tells the model
hidden characters are still removed.

### backend/services/security/README.md (the paragraph under the module table)

Replace "are stdlib-only and local." for `outbound_recipients` with a precise line: everything
listed is local and makes no network call; `outbound_recipients` also reads
`core.config.settings.ENCRYPTION_KEY` (lazily, for the HMAC key) and `lookalike`. The four
`outbound*.py` rows of the module table are already right.
