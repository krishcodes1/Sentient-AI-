# Mail scam scan: automatic scam and phishing checks on new email

Status: built in the security wave (security10, skill S2; S2a facts and checks, S2b service, routes
and tab). Migration `0027_mail_security`. Capability `mail_scam_scan` ("Check new email for scams",
on by default, medium risk). Owner decision 8a (2026-10-14): no "Block sender" in this wave.

## Why

Phishing arrives by mail, usually before anyone asks Crawler about it, and is most dangerous in
the minutes after it lands. The owner asked (decision 1) for free local checks on every new email,
an AI review with an explanation only for the ones those checks flag, alerts on the person's own
channels, and every action on a mail behind an approval card.

## What the person sees

- **Telegram and Slack** (the same plain text, built in code): a "Likely scam email" or
  "Suspicious email" alert naming the account, the sender and address (defanged), the subject
  (withheld when it reads like instructions to an AI), when it arrived, Crawler's own reasons as
  fixed sentences, the AI review's sanitised reasons or why no review ran, fixed advice, and the
  card line. A likely scam is followed by a "Move to Spam/Junk" approval card; a suspicious alert
  points to the Security page, where the card is one click away. Never the body, never "safe".
- **Security ▸ Mail alerts**: the switch, today's AI reviews against the daily limit, which link
  and attachment checks ran, each mailbox (active, starting, paused, stopped after errors, or not
  allowed to read mail) with Pause/Resume, and every alert with its reasons, notes, review, cards
  (Approve/Deny inline), "Move to Spam/Junk" and "Not a scam". The owner also sees install-wide
  counts, never anyone else's mail.
- One "too many alerts this hour" line, one daily line for weak findings no AI review was
  available for, and one "stopped checking" line when an account fails five times in a row.

## Decisions

- **Free checks on every message, the AI only on flagged ones.** `mail_checks.evaluate` scores
  the provider's own topmost Authentication-Results (a sender cannot forge it), look-alike and
  mixed-script sender domains, display names claiming a brand or another address, Reply-To
  domains, links whose text names another site, code links, forms, risky and disguised
  attachments, pressure wording, hidden characters and text aimed at AI assistants, plus S4's
  link verdicts. Weights are capped per group; an authenticated sender whose only signs are
  wording is dampened. Score 3 flags, 7 or any hard hit (a listed link, a VirusTotal-flagged
  attachment) is a likely scam.
- **The review can raise, never silence** (review SEC-M1, scaffold A33). `review.combine` is a
  maximum. A weak finding goes quiet only after a "no signs" review when every hit is soft, the
  sender authenticated (DMARC or compauth pass) and there is no injection or hidden-character
  hit. An answer carrying instructions is withheld and cannot quiet anything.
- **Its own budget.** At most `ai_reviews_per_day` (20) reviews per person per UTC day, counted
  from `reviewed_at`; the shared unattended budget is never touched. A local Ollama
  (`MAIL_REVIEW_OLLAMA_MODEL` with a local `OLLAMA_BASE_URL`) is used first; a cloud provider
  always gets contact details as placeholders.
- **Fail open, never "safe".** S4 (links), S10 (attachments) and the AI provider are optional;
  each failure becomes a fixed note on the alert and the tab.
- **Bounded noise** (reviews FEA-SF2, SEC-F7). Only likely scams get an automatic card. With no
  review, a finding whose signs are all noisy is listed and summed up once a day at 18:00 local.
  More than 10 pushed suspicious alerts an hour become one line; a likely scam is always pushed.
- **No backlog flood.** The first check of an account, one left for a day, and a provider reset
  only record where the inbox is.
- **Every action is a card** (decision 1): `AgentRuntime.park_card` with origin
  `mailcheck:<finding id>`, a day to answer, Gmail `modify_labels` (add SPAM, remove INBOX) or
  Outlook `move_message` to `junkemail`, both graded HIGH. No Block sender (decision 8a).

## Data (`0027_mail_security`)

- `mail_scan_cursors`: one row per connected Gmail or Outlook account: the provider cursor, the
  queue of listed ids (`{"id","tries"}`, newest 200), a ring of 500 16-hex hashes of checked
  mail, counters, status (active, paused, error) and the sweeper's own error and note sentences.
- `mail_scam_findings`: one row per flagged email: the hashed external key (unique per
  connector), the provider message reference the card needs, signal codes, the display facts
  (sender, subject, link hosts, attachment names, auth summary; capped at 4 KB), the review, its
  note, the alert and its cards. `review_input` (the excerpt the AI reads, at most 1,500
  characters) is cleared as soon as the review is done, and after a day at the latest.
- Both cascade with their user and connector. Findings are deleted after `keep_alerts_days` (30).

## Flows

1. **Reconcile** (every 5 minutes): a cursor row per active mail connector that may read mail; a
   stopped row restarts once its connector changed since and may read mail again.
2. **Detect** (every minute, only while the switch is on, re-read before each account): claim up
   to 20 due accounts; `list_new_message_ids` through the executor; save the cursor and the queue
   at once; read up to a third of the row's rate limit (at most 10) with `get_message_security`;
   gone messages are dropped, a message that fails twice is skipped, mail older than a day is
   skipped; each read message gets S4's verdicts for at most 5 query-stripped URLs (one per host)
   and the local checks; flagged ones become findings. Failures back off; the fifth stops the
   account with one message.
3. **Review and alert** (background, at most 2 at a time, 5-minute lease, one retry): S10 for up
   to two risky attachments; the review under the daily cap; quiet, listed, held or alerted; the
   alert first, then the card for a likely scam.
4. **Housekeeping** (hourly, even while off): retention, excerpt clearing, expiry of findings that
   waited over a day.

## Privacy

- Unflagged mail leaves only a 16-hex hash. Audit rows carry ids, counts and codes, never
  addresses, subjects, hosts or message ids; logs carry ids and exception types only.
- Only flagged mail reaches the AI: the excerpt, link hosts (never full links), attachment names
  and Crawler's findings, inside the runtime's untrusted-data fence, pseudonymised for a cloud
  provider. URLs go to S4 without query, fragment or user info.
- The account export lists each finding's verdict, codes, facts and review, never the message
  reference, attachment references or the review input.

## Tests

`test_mail_security_facts.py`, `test_mail_security_checks.py`,
`tests/connectors/test_google_workspace_mail_security.py`,
`tests/connectors/test_microsoft_mail_security.py` (S2a); `test_mail_scan_service.py`,
`test_mail_scan_review.py`, `test_mail_scan_messages.py`, `test_mail_scan_routes.py`,
`test_mail_scan_capability.py`, `test_mail_security_migration.py` (S2b);
`frontend/src/pages/security/MailAlertsTab.test.tsx` and `mailAlertFormat.test.ts`. Two
cross-skill cases (`requires_real`) run once S4's `link_checks` and S10's file service are real.

## Shared doc text (pasted at integration)

### docs/CODE-MAP.md

Under "### Scam checks on new email (security S2)":

- `backend/services/security/mail_facts.py` — pure: one email's security facts (the provider's
  topmost Authentication-Results, From, Reply-To, links with shown text and real destination,
  attachment names, a capped visible-text excerpt) from Gmail and Graph payloads; the
  `MailSecurityFacts` answer S1 also reads (scaffold A7).
- `backend/services/security/mail_checks.py` — pure: the signal table, weights, group caps, the
  authenticated-sender dampener, the levels, `may_go_quiet` / `pushes_without_review` /
  `combine`, the reason sentences, the URL list for S4 and the display facts a finding keeps.
- `backend/services/connectors/google_api/mail_security.py`,
  `backend/services/connectors/microsoft_api/mail_security.py` — the bodies of the Gmail and
  Outlook READs `list_new_message_ids` (history and delta cursors) and `get_message_security`
  (answers `{"id", "gone": true}` for a deleted message).
- `backend/services/mail_scan/` — `review.py` (the AI review: provider choice, fenced input,
  parsing, line cleaning, `combine`), `messages.py` (every alert and card text, model-free),
  `actions.py` (the Move-to-Spam/Junk card plan, `park_card` wrapper, account export).
- `backend/services/notifications/mail_scan.py` — `MailScanService`: the sweeper (reconcile,
  detect, review and alert, housekeeping) and the methods the routes call
  (`app.state.mail_scan`).
- `backend/api/routes/security_mail.py` — `/api/security/mail/*`: status, alerts, a card for an
  alert, dismiss, pause or resume a mailbox.
- `backend/services/capabilities/mail_scam_scan.py` — the `mail_scam_scan` switch and its two
  settings.
- `backend/models/mail_security.py` / `alembic/versions/0027_mail_security.py` —
  `mail_scan_cursors` and `mail_scam_findings`.
- `frontend/src/pages/security/MailAlertsTab.tsx` — Security ▸ Mail alerts;
  `mailAlertFormat.ts` — its wording (verdict badges, card lines, mailbox states, notes).
- Backend tests: `test_mail_security_facts.py`, `test_mail_security_checks.py`,
  `tests/connectors/test_google_workspace_mail_security.py`,
  `tests/connectors/test_microsoft_mail_security.py`, `test_mail_scan_service.py`,
  `test_mail_scan_review.py`, `test_mail_scan_messages.py`, `test_mail_scan_routes.py`,
  `test_mail_scan_capability.py`, `test_mail_security_migration.py`.

### docs/BACKLOG.md

Under "### Scam checks on new email (security S2)":

**S2 Automatic scam check on new mail: done.** Every new email in each connected Gmail and
Outlook inbox is checked on this computer; flagged mail gets one AI review (its own daily cap,
pseudonymised for a cloud provider) and an alert on the person's own Telegram and Slack, with a
Move-to-Spam/Junk approval card for a likely scam; everything is listed on Security ▸ Mail alerts.
Block sender is deferred (F9). Follow-ups:

- Urgency and payment wording in languages other than English.
- Outlook immutable ids (`Prefer: IdType="ImmutableId"`), so a card survives the person moving
  the mail before approving it.
- Feeding the DMARC verdict into trigger sender matching.
- A Telegram `/mailalerts` command.
- Sender history ("first mail from this sender").
- The organisation's other domains (northwind.co for northwind.com) for the look-alike and
  Reply-To checks, which need a list the owner keeps.
- Text a stylesheet adds with `content:` is not read; the regional-ending and brand-owned domain
  lists are kept by hand.

Also, in the existing event-triggers bullet "SPF/DKIM checks before trusting a From header", add
after its text: "(S2 parses the provider's Authentication-Results in
`services/security/mail_facts.py`; triggers do not use it yet)".

### SECURITY.md

Under "## Scam and phishing checks on new email":

Crawler checks every new email in each connected Gmail and Outlook inbox for signs of a scam
(switch "Check new email for scams" in Settings → Permissions, on by default; the first check of
each account only records where the inbox is). The checks run on this computer: the receiving
provider's own topmost Authentication-Results (lower copies, which a sender can forge, are never
read), look-alike and mixed-script sender domains, Reply-To domains, links whose text names
another site, code links, forms, risky and disguised attachments, pressure wording, hidden
characters and text aimed at AI assistants, plus the link reputation service when its key is set
(URLs sent without query, fragment or user name, at most five per email, one per site). Mail
that is not flagged leaves only a 16-character hash. Only flagged mail reaches an AI provider,
and only an excerpt of at most 1,500 characters with link hosts (never full links), inside the
untrusted-data fence, with contact details replaced by placeholders for a cloud provider; a local
Ollama can be set with `MAIL_REVIEW_OLLAMA_MODEL`. Reviews have their own daily cap per person and
never use the shared budget for tasks run while away. The review can make a finding stricter but
never silence it: a weak finding goes quiet only when the sender authenticated, every sign is
weak and the review found none, and an answer carrying instructions is withheld. Alerts are
fixed sentences (the review's lines are stripped of links, addresses and phone numbers and
checked by PromptGuard), defang every domain, withhold a subject that reads like instructions,
never quote the body and never call an email safe. Nothing in the mailbox changes without an
approval card (Move to Spam/Junk, parked with the same checks as any card); Block sender is not
offered. Audit rows hold ids, counts and signal codes only.

### backend/services/capabilities/README.md

Under "### Scam checks on new email (`mail_scam_scan`)":

`mail_scam_scan` is a policy switch (`tools=()`) that runs a background check with its own model
budget. It is on by default (medium risk) and always available, since alerts also reach the
Security page. Its sweeper (`services/notifications/mail_scan.py`) re-reads the switch before
every account it checks and every review (a gate that cannot be read is off). Its AI spending is
capped by its own setting, `ai_reviews_per_day` (20 per person per UTC day, counted from the
findings' `reviewed_at`), never by the shared unattended budget, and `keep_alerts_days` (30)
sets how long findings are kept. Every change it proposes is an approval card parked with
`AgentRuntime.park_card` and the origin `mailcheck:<finding id>`.
