# File reputation through VirusTotal (hash lookups with the owner's key)

Date: 2026-10-14. Status: built as security skill S10 of the security wave (security10).
Capability `file_reputation` (on by default, blocked until the owner saves a VirusTotal key).
Migration `0032_file_reputation`. Tools `security.check_file` (READ, no card) and
`security.upload_to_virustotal` (WRITE, its own card every time). Connector READs
`google_workspace.get_attachment_hash` and `microsoft.get_attachment_hash`. Call check
`file_reputation` (last in the pipeline, notes only). Security tab "File checks".

## 1. Problem

People send Crawler files (web chat, Telegram, Slack) and ask about email attachments. Some of
those files are known malware. VirusTotal knows most of them by fingerprint, but asking it means
sending something to a third party with a key that has small public limits (4 lookups a minute,
500 a day, non-commercial), and sending a file itself shares it with security companies and
VirusTotal's paying users.

## 2. Decisions

- Only the SHA-256 leaves the machine automatically, with the owner's own key in the `x-apikey`
  header. Without a key, or with the switch off, nothing is hashed, stored or sent, and every
  caller gets an explicit "not checked" result (decisions 2).
- Answers are cached install-wide (7 days flagged, 24 h no detections, 1 h unknown); failures are
  never cached. A request log in the database keeps the limits true across restarts and users
  (reserve before request, sliding windows), with a share for automatic checks and one per person.
- A file VirusTotal does not know is sent only after its own approval card. The bytes are
  fetched again at that moment (Telegram by file id, Gmail or Outlook through the executor, web
  and Slack from a bounded in-memory holder), hashed again and compared with the card. After a
  restart a card whose bytes are gone refuses and sends nothing.
- Personal documents (PDF, plain Office, pictures, text) are never held, never keep a
  re-fetchable reference, and can never be proposed for upload from a chat; the owner can still
  send one from the Security page by picking it there (review SEC-F2).
- Nothing ever says "safe". No detections is "not a guarantee", unknown is "VirusTotal has never
  seen it", and anything that failed is "not checked" with a reason.
- A rejected key pauses every lookup for 10 minutes and tells the owners at most once a day
  (review FEA-SF8).

## 3. Flows

- **A. An upload.** `FileIntake.ingest` calls `screen` first for every file (a refused executable
  included). With the switch on and a key: hash, upsert the person's row, hold risky web/Slack
  bytes for 30 minutes (dropped as soon as VirusTotal turns out to know the file), keep a
  Telegram file id encrypted for risky kinds only, and look the file up in the background
  (cache, then the quota with no wait; no room means the row is queued). A flagged verdict is
  told once through the person's own chats. `annotate` waits at most 3 s in all and adds
  `file_check` (counts and the label only) to flagged entries; `prompting.attachment_note` turns
  it into one fixed line in the `[Attached file]` note.
- **B. The model checks a file.** `security.check_file` with exactly one of `file_id` (one of the
  person's own uploads) or `sha256`; explicit priority, waits up to 20 s for the minute window.
- **C. An email attachment.** The model calls the mail connector's `get_attachment_hash` (the
  hash, size, name and type only; over 25 MB answers `too_large` without downloading) and then
  `check_file`; S2 calls `check_mail_attachment`, which runs the hash action through the executor,
  keeps the source encrypted (risky kinds only) and the message id only as an HMAC.
- **D. The Security page checks a file.** The browser hashes it (`crypto.subtle`); only the
  fingerprint is posted.
- **E. An upload card in a turn.** Precheck (bad arguments, a call that brings its own `_upload`,
  no row, already known, not checked yet, personal document, bytes gone), then the bind stores
  the file facts under `_upload` (the name escaped to ASCII and defanged, so the approval-time
  re-scan never meets a mixed-script word) and pins held bytes for 60 minutes, then the card.
- **F. An upload card from the Security page.** `request_upload`: the row must be the person's,
  checked and unknown; a body (at most 20 MB) must hash to the row and is held as an explicit
  pick; without a body the server needs its own copy. `park_card` runs the same precheck, bind
  and checks. A second request answers the waiting card; a denied or expired card puts the row
  back to `checked`. At most 5 requests an hour per person.
- **G. An approved upload runs.** The card's fingerprint, the person's row and the check id only
  the bind writes must all match; the switch and key are read again; bytes are fetched (holder,
  Telegram, mail), re-hashed, size-checked and sent as `file` under the quota. Any refusal sends
  nothing and writes one `file_reputation_upload_refused` row. A failure after the bytes went out
  (a timeout, a 200 with a bad body, a 5xx) says "It may have been received."; nothing is retried.
- **H. Analysis polls.** First after 90 s, then every 120 s, at most 8 (about 15 minutes); the
  result is cached and told once, a timeout is told once.
- **I. Queued lookups.** The sweep takes them explicit first, oldest first, while the minute
  window has room; a verdict that arrives this way is always told by the service.

## 4. Data (`0032_file_reputation`)

- `file_reputation_verdicts` (PK `sha256`): VirusTotal's four answers with counts, a sanitised
  threat label (`[a-z0-9._/:-]{1,64}`) and type description, `origin`, `fetched_at`,
  `expires_at`. No user data.
- `file_reputation_checks` (one row per person and file, cascading with the user): the
  sanitised name, source, state (`queued`, `checked`, `not_checked`, `upload_pending`,
  `analysing`), a verdict snapshot, the reason code, `alerted_verdict` (each verdict told once),
  the encrypted `source_ref` (AES-GCM), the HMAC `source_key`, the card and analysis ids, poll
  state and the sweep claim; `expires_at` 30 days after the last sighting.
- `file_reputation_calls`: one row per reserved request (`kind`, `priority`, `user_id` set to
  NULL on delete), kept 48 hours.

## 5. Limits and failure policy

| limit | default | when hit |
| --- | --- | --- |
| per minute (every kind) | 4 | explicit callers wait (tool 20 s, page 10 s, upload 20 s), then pending; automatic ones queue |
| per day | 500 | not checked (`daily_limit`) |
| automatic share | 100 a day | not checked (`automatic_limit`); explicit checks still work |
| per person | 100 explicit lookups a day | not checked (`user_limit`) |
| VirusTotal's 429 | 60 s pause, doubling to 1 h | pending (`virustotal_limit`), nothing sent meanwhile |
| rejected key (401/403) | 600 s pause | not checked (`key_rejected`), owners told once a day |
| page upload requests | 5 an hour per person | 429 with `Retry-After` |
| hashing | 25 MB | not checked (`too_large`) |

Lookups fail open with a reason and never block an upload, a read or a turn. The call check fails
open to Allow. An approved upload fails closed. A switch that cannot be read counts as off.

## 6. Card wording

`Send "setup․exe" (2.4 MB, SHA-256 3f2a9c1d…d41e) to VirusTotal to be scanned. VirusTotal shares
files it receives with security companies, and its paying users can download them: never send
private documents.` The card's shown arguments are the `sha256` only (`_upload` is a reserved
key on every surface), and the audit log keeps only a marker for `_upload`.

## 7. Tests

Backend (`backend/tests/file_reputation/`): `test_virustotal_client.py`, `test_file_hashing.py`,
`test_byte_holder.py`, `test_file_reputation_quota.py`, `test_file_reputation_store.py`,
`test_file_reputation_texts.py`, `test_file_reputation_service.py`,
`test_file_reputation_intake.py`, `test_file_reputation_toolkit.py`,
`test_file_reputation_runtime.py`, `test_file_reputation_capability.py`,
`test_file_reputation_call_check.py`, `test_file_reputation_routes.py`,
`test_file_reputation_sweeper.py`, `test_file_reputation_migration.py`, and
`backend/tests/connectors/test_attachment_hash.py`. Shared fakes in `fakevt.py` (a VirusTotal v3
API behind `httpx.MockTransport`, settings, outbox, audit, executor, Telegram, runtime) and
`helpers.py`. Frontend: `pages/security/FileChecksTab.test.tsx`, `fileHash.test.ts`,
`fileCheckFormat.test.ts`. No real network, DNS or key anywhere.

## Shared doc text (pasted at integration)

### docs/CODE-MAP.md

Under "### File reputation (security S10)":

- `backend/services/file_reputation/` — VirusTotal hash lookups with the owner's key:
  `virustotal.py` (`VirusTotalClient`: lookup, upload, analysis under the `virustotal_lookup` and
  `virustotal_upload` network policies; `parse_file_report`, `verdict_of`, `test_key` for the
  Service keys tab), `quota.py` (`VirusTotalQuota`: reserve-before-request limits from the request
  log, the 429 cool-down, the rejected-key pause), `store.py` (`FileReputationStore`: every read
  and write of the three tables, `source_ref` encryption, the `source_key` HMAC, claims, purge),
  `holder.py` (`ByteHolder`: bytes an approved upload may send, in memory with a TTL),
  `byte_sink.py` (stdlib: the 25 MB cap, the hash helpers, the contextvar sink the mail hash
  actions hand bytes to), `kinds.py` (risky files by magic bytes, extension and type),
  `verdicts.py` (`FileVerdict` and every sentence; never "safe"), `alerts.py` (alert texts,
  defanged), `service.py` (`FileReputationService`: switch and key, cache, quota, in-flight
  dedupe, rows, alerts, the intake screen and annotate, mail checks, uploads, sweep, status;
  `app.state.file_reputation`), `toolkit.py` (`FileReputationToolkit`: `security.check_file` and
  `security.upload_to_virustotal` with the upload card's precheck, bind and describe),
  `sweeper.py` (`FileReputationSweeper` on `SweepLoop`: queued lookups, analysis polls, purges;
  `kick()` after an upload), `call_check.py` (`FileReputationCallCheck`: a `file_flagged` note on
  forwarding mail with a flagged attachment or saving a flagged upload to the knowledge base).
- `backend/services/connectors/google_api/attachment_hash.py`,
  `backend/services/connectors/microsoft_api/attachment_hash.py` — the bodies of the
  `get_attachment_hash` READs (SHA-256, size, name and type only; 25 MB cap before download).
- `backend/api/routes/security_files.py` — `/api/security/files` (list, check a browser-computed
  fingerprint, request an upload card, forget).
- `backend/services/capabilities/file_reputation.py` — the `file_reputation` switch, blocked until
  a VirusTotal key exists; four owner-editable limits.
- `backend/models/file_reputation.py` / `alembic/versions/0032_file_reputation.py` —
  `file_reputation_verdicts`, `file_reputation_checks`, `file_reputation_calls`.
- `frontend/src/pages/security/FileChecksTab.tsx` — Security ▸ File checks; `fileHash.ts`
  (SHA-256 in the browser), `fileCheckFormat.ts` (labels and tones, never a success colour).
- Intake hooks: `services/files/intake.py` calls `screen` for every inbound file and `annotate`
  for attachment entries; `services/files/prompting.py` appends `attachment_check_line`.
- Backend tests: `backend/tests/file_reputation/` and `backend/tests/connectors/test_attachment_hash.py`.

### docs/BACKLOG.md

Under "### File reputation (security S10)":

**S10 File reputation with VirusTotal: done.** With the owner's VirusTotal key (Security →
Service keys), every file people send Crawler and the email attachments S2 or the model ask about
are looked up by SHA-256; only the fingerprint is sent, answers are cached, and VirusTotal's
public limits hold across restarts with a share for automatic checks and one per person. A
flagged file reaches its sender's own chats once and the model's `[Attached file]` note. A file
VirusTotal does not know is sent only after its own approval card, with the bytes fetched again
and re-hashed; personal documents can be sent only from Security ▸ File checks, picked there.
Without a key nothing is sent anywhere. Follow-ups:

- Re-fetch Slack files at approval instead of holding them in memory.
- Fingerprint Drive and OneDrive documents in `read_connector_document`
  (`connectors/documents.py`).
- A multi-worker quota (a database lock instead of the process lock).
- A premium-key mode (higher limits, behaviour reports).
- A per-sighting `source_key`, so every forwarded copy of a flagged attachment gets the note.

### SECURITY.md

Under "### File reputation":

Crawler can look files up in VirusTotal with the owner's own key (Security → Service keys);
without a key, or with "Check files with VirusTotal" off in Settings → Permissions, nothing is
hashed, stored or sent. Only a file's SHA-256 is sent automatically, through the SSRF-checked
client under a network policy that lets the lookup reach only `GET /api/v3/files/<sha256>` on
`www.virustotal.com` over HTTPS (uploads and analysis polls have their own policy); the key
travels only in the `x-apikey` header and never appears in a URL, log line, audit row or
response. Answers are cached, VirusTotal's limits are kept in a request log written before each
request, and only stats, dates, a sanitised threat label and the type description are read from
an answer (names, tags, comments and vendor texts never are). A file is uploaded only after its
own approval card, which says that VirusTotal shares uploads with security companies; at
approval the bytes are fetched again and must hash to the card's fingerprint, the neutral name
`file` is sent, and a restart, a changed file or a missing key sends nothing. Personal documents
are never kept for an upload and cannot be proposed from a chat. Telegram file ids and mail
message references are stored encrypted (AES-GCM) and mail message ids only as an HMAC; audit
rows carry fingerprints, counts and codes, never a file name, message id or key. The upload tool
is never offered to an unattended run. A rejected key pauses lookups for 10 minutes and alerts
the owner at most once a day.

### backend/services/capabilities/README.md

Under "### File reputation (`file_reputation`)":

`file_reputation` claims `security.check_file` and `security.upload_to_virustotal` (exact names,
because S3's `check_scam` shares the `security.` family). It is a key-gated capability: its
availability reads `"virustotal" in ctx.service_keys`, so it is on by default but blocked until
a key exists, and its four limits (`lookups_per_minute` 4, `lookups_per_day` 500,
`automatic_lookups_per_day` 100, `lookups_per_user_per_day` 100, whole numbers 1..10000) are read
per request through `capability_statuses()["file_reputation"].settings`; a report that cannot be
read counts as off. `security.upload_to_virustotal` has an approval card of its own: its bind
ties the card to the file's SHA-256 and stores the file's facts under the reserved `_upload` key
(hidden from the card's shown arguments and kept out of the audit log); at approval the toolkit
fetches the bytes again (Telegram, the mail connector through the executor) or reads them from
memory (web, Slack), hashes them again, and refuses a mismatch or missing bytes, so nothing but
the approved file can be sent.
