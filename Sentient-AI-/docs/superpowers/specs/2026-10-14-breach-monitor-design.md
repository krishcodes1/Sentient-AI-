# Breach monitor and the in-browser password check

Date: 2026-10-14. Status: built as security skill S6 of the security wave (security10).
Capability `breach_monitor` (on by default, blocked until the owner saves a Have I Been Pwned
key). Migration `0029_breach_watch`. No tool, no approval card, no call check, no connector
action, no Telegram or Slack command.

## 1. Problem

An owner's email address can turn up in a data breach years after they signed up somewhere,
and nobody tells them. Have I Been Pwned (HIBP) knows, but asking it means sending the address
to a third party, with a paid key. Separately, anyone using Crawler may want to know whether a
password is already in a public leak list, without that password ever leaving their browser.

## 2. Decisions

- **Owners only, their own key.** Every `is_admin` account watches its own sign-in address plus
  up to 10 addresses it types in. Nothing is sent to HIBP's account API without the owner's own
  key (decisions item 2). The key lives in the shared owner key store (`InstallationService`,
  `.env` `HIBP_API_KEY` wins) and is tested before it is stored (`services.breach.hibp.check_key`,
  one `subscription/status` call).
- **One switch, two readings.** The capability's effective state (on / off / blocked) gates the
  weekly sweeper and Check now. The keyless password check reads only the owner's switch value
  (`CapabilityStatus.enabled`), so it works without a key and stops when the owner turns breach
  checks off. A report that cannot be read counts as off everywhere (fail closed).
- **Weekly, paced, once per breach.** A `SweepLoop` wakes every 15 minutes; each address is due
  once a week. Lookups are spaced by a process-wide pacer to the lowest plan's 10 a minute plus a
  0.5 s margin, and a 429's retry-after holds the next slot (one paced retry). The first answer
  for an address is its baseline (one summary message); later answers alert only breaches this
  call inserted into the seen list. The unique `(address_id, breach_name)` index, not the diff,
  decides what is new, so racing checks never alert twice.
- **Fail open with a note.** A failed lookup is stored as a fixed code and always reads as "not
  checked" with its reason, never "no breaches". Failures back off hourly, doubling to a day; the
  fifth in a row stops the address with one message. A refused key holds every address for a day
  and tells each owner once; saving a key releases the hold at once.
- **Model-free texts.** Alerts are fixed sentences built in code; vendor text (breach title and
  domain) is cleaned and defanged so the attribution host is the only link; a breach HIBP marks
  sensitive is never named on a channel; the address appears only as a hint (`k•••＠example․com`).
- **k-anonymity in the browser.** The tab works out the SHA-1 itself (crypto.subtle, or a pure
  FIPS 180-4 fallback for plain-http LAN installs), sends only the first 5 hex characters to a
  backend proxy (the SPA's CSP allows only its own server) and matches the rest in the browser.

## 3. Data

`breach_watch_addresses`: one row per watched address per owner; `address_sealed` is
`encrypt_credentials(normalised address)` (AES-256-GCM), `address_digest` is an HMAC-SHA256
under a key derived from `ENCRYPTION_KEY` with the domain `sentientai.breach_watch.address.v1:`
(uniqueness, "is this the sign-in address", email changes, all without plain text; someone with
only the database cannot confirm a guessed address offline). Status `active | paused | error`,
the schedule (`next_check_at`, `last_checked_at`, `baseline_at`), health (`consecutive_errors`,
`last_error_code`: a fixed code, never vendor text).

`breach_watch_findings`: the seen list. Public HIBP catalogue facts only (name, title, domain,
dates, count, data classes, flags), plus `baseline`, `first_seen_at`, `alerted_at` (a channel
delivered it or a Check now answer showed it) and `acknowledged_at` (the owner pressed "Mark as
handled"). HIBP's `Description` (HTML) and logo are never stored. Capped at 1,000 per address.

Retention: rows stay until the owner removes them (cascade with the account); the sign-in row
follows `User.email` (resealed and baselined again when it changes); housekeeping deletes the
rows of an account that is no longer an admin; an unreadable row (the `ENCRYPTION_KEY` changed)
is never sent and shows "can no longer be read" with Remove.

## 4. Flows

- **Sweep** (`BreachMonitorService.sweep_once`): gate, key, housekeeping at most daily, claim up
  to 20 due rows by a conditional UPDATE (30-minute lease), and for each one re-read the gate and
  the key, open the address, look it up (45 s answer budget that excludes the pacer's waits),
  record, alert, audit.
- **Check now** (`check_now`): gate and key (409 with the report's reason otherwise), a busy pacer
  or a check in the last 5 minutes is a 429 with `Retry-After`, then the same lookup path with
  trigger `owner`; it sends no channel message (the owner sees the answer), and a failed lookup
  is a 200 `not_checked` whose note promises a retry only for a row that will be retried.
- **Kick**: every "capabilities" change (a key saved or removed, a switch flipped) releases the
  key holds under the sweep lock and runs one sweep; a kick that arrives during another runs once
  more afterwards.
- **Password proxy** (`POST /api/security/pwned-passwords/range`): any signed-in user; the
  owner's switch (403 off, 503 unreadable), 20 requests a minute per user (429), the prefix
  checked by hand (422), one request with `Add-Padding: true` through the guarded client (503
  "not checked" on any failure). Nothing about a check is kept: no cache, no audit row, and the
  one log line carries the user id only (review SEC-F13: no prefix, no entry count).

Routes (`api/routes/security_breach.py`, all owner-only except the proxy): `GET
/api/security/breach`, `POST /breach/addresses`, `PATCH|DELETE /breach/addresses/{id}`, `POST
/breach/addresses/{id}/check`, `POST /breach/findings/{id}/acknowledge`, `POST
/breach/findings/acknowledge-all`, `POST /pwned-passwords/range`. Bodies are read by hand with a
2 KB cap, so no answer ever echoes an address, a prefix or a key; another owner's id is the same
404 as an unknown one.

## 5. Privacy and terms

- Egress: both vendors go through `build_guarded_client` with `services/breach/egress.py`'s
  resolver: the full URL is checked against the vendor's own network policy (`hibp`: two API
  paths over HTTPS; `pwned_passwords`: `/range/` over HTTPS) without DNS or logging, and the SSRF
  check runs on the origin only, so no log line or refusal carries the address. Redirects are
  never followed; bodies are streamed under a cap (2 MB HIBP, 256 KB ranges).
- The HIBP key travels only in the `hibp-api-key` header; addresses only in the URL path (after
  normalisation and percent-encoding). No exception message, log line or audit row carries an
  address, a key, a prefix or vendor text: logs and audit rows carry ids, counts, codes and
  exception type names. The failure code is stored in audit rows as `error_code` (the audit
  sanitizer masks a key named exactly `code`).
- HIBP's terms: an accurate user agent (`Crawler-AI-breach-monitor`,
  `Crawler-AI-password-check`), no enumeration (owners' own addresses, a cap of 10, weekly),
  per-owner keys, the plan's rate limit, and CC BY 4.0 attribution ("Breach data: Have I Been
  Pwned" with a link on the tab, "Source: Have I Been Pwned (haveibeenpwned.com)." in every
  message, "Pwned Passwords by Have I Been Pwned (haveibeenpwned.com)" with each range answer).

## 6. Deviations from the design text (each with its reason)

1. Audit rows carry `error_code`, not `code` (the audit sanitizer would mask `code`).
2. No SAVEPOINT per finding: each new finding is committed on its own and an `IntegrityError` on
   the unique index means "already seen" (the codebase's pattern; pysqlite's SAVEPOINTs are
   unreliable). A test covers the race.
3. The lookup deadline counts only HIBP's answer time (both requests together); the pacer's
   queue and a 429's hold are outside it, so a rate limit never reads as a counted timeout.
4. Check now asks the pacer before claiming, so a busy pacer never moves the schedule.
5. `CheckTooSoon` is defined in `store.py` and re-exported by the service module.
6. A Pwned Passwords answer over 2,000 entries is "not checked" rather than cut short.
7. A malformed key or address is refused without being sent.
8. A key refusal on one owner's Check now still sends the one message to every other owner.
9. A refusal of a key that was replaced while the lookup was out is ignored (no hold, no message).
10. No "Crawler tries again" promise for a row that is not retried on its own (stopped, paused,
    or while checks are off or have no key).
11. An `AddedDate` HIBP cannot move to UTC (an edge-of-calendar moment with an offset) drops only
    that field, never the whole answer.
12. The add route counts again after the insert, so two adds racing past the limit cannot leave
    an owner with more than 10 typed addresses.
13. Owner actions on the tab (add, pause, resume, remove, acknowledge) are audited through the
    service's one writer; acknowledging a single finding writes `{count: 1, finding_id}`.

## 7. Tests

Backend (no network: `httpx.MockTransport` behind the real request hook, `check_ssrf` replaced,
a scripted HIBP, in-memory SQLite): `test_breach_addresses.py`, `test_breach_hibp_client.py`,
`test_pwned_passwords_client.py` (pure, Windows CI), `test_breach_monitor_service.py`,
`test_breach_monitor_api.py`, `test_breach_monitor_capability.py`, `test_breach_watch_migration.py`.
Frontend: `pages/security/pwnedPasswords.test.ts` (FIPS 180 vectors, prefix-only requests,
padding never matches, a failed fetch never reads as "not found") and
`pages/security/BreachMonitorTab.test.tsx`.

## Shared doc text (pasted at integration)

### docs/CODE-MAP.md

Under "### Breach monitor (security S6)":

- `backend/services/breach/` — the breach monitor's building blocks: `addresses.py` (normalise,
  HMAC-digest, seal, open and hint a watched address; pure), `egress.py` (the guarded client's
  resolver for a fixed vendor: policy check on the full URL, SSRF check on the origin only, so no
  log line carries the address), `hibp.py` (HIBP v3 `breachedaccount` and `subscription/status`,
  the process-wide `Pacer`, `parse_breaches`, `check_key` for the Service keys tab),
  `pwned_passwords.py` (the k-anonymity range lookup behind the password-check proxy, its
  per-user limiter), `store.py` (`BreachStore`: every read and write of the two tables, the seen
  list, claims, failures, key holds; `export_for_user`), `messages.py` (model-free alert texts and
  the owner-facing failure sentences).
- `backend/services/notifications/breach_monitor.py` — `BreachMonitorService`: the weekly
  `SweepLoop` sweeper, the owner's Check now, the kick on a "capabilities" change, the audit
  writer (`app.state.breach_monitor`).
- `backend/api/routes/security_breach.py` — `/api/security/breach/*` (owner only) and `POST
  /api/security/pwned-passwords/range` (any signed-in user, gated by the owner's switch).
- `backend/services/capabilities/breach_monitor.py` — the `breach_monitor` policy switch, blocked
  until an HIBP key is configured.
- `backend/models/breach_watch.py` / `alembic/versions/0029_breach_watch.py` —
  `breach_watch_addresses` (sealed address, HMAC digest, schedule, health) and
  `breach_watch_findings` (the seen list).
- `frontend/src/pages/security/BreachMonitorTab.tsx` — Security ▸ Breach monitor (status line,
  watched addresses, breaches, the password check); `pwnedPasswords.ts` — SHA-1 in the browser
  (crypto.subtle or a pure fallback) and the prefix-only check.
- Backend tests: `test_breach_addresses.py`, `test_breach_hibp_client.py`,
  `test_pwned_passwords_client.py`, `test_breach_monitor_service.py`, `test_breach_monitor_api.py`,
  `test_breach_monitor_capability.py`, `test_breach_watch_migration.py`.

### docs/BACKLOG.md

Under "### Breach monitor (security S6)":

**S6 Breach monitor and password check: done.** Every owner's sign-in address plus up to 10
typed addresses are looked up in Have I Been Pwned once a week with the owner's own key (blocked
until a key is saved; nothing is sent without one); new breaches reach the owner's Telegram and
Slack and always show on Security ▸ Breach monitor; anyone signed in can check a password there
with only a 5-character SHA-1 prefix leaving the browser. Follow-ups:

- An owner-editable check interval (today a fixed week).
- A Pwned Passwords warning on change-password, register and owner setup (computed in the
  browser with the same helper).
- HIBP's k-anonymity `breachedaccount/range` for plans with `IncludesKAnon`, so the address
  itself is never sent.
- A Telegram `/breaches` command.
- Check now does not refuse an address the sweeper is checking at that moment (both lookups are
  sent; the seen list's unique index still alerts each breach once).

### SECURITY.md

Under "### Breach monitoring":

Crawler can watch the owners' email addresses for new data breaches with Have I Been Pwned, using
the owner's own key (Security → Service keys); without a key nothing is sent, and the owner can
turn it off in Settings → Permissions. Only owner accounts are watched: each owner's sign-in
address plus at most 10 addresses they add, looked up once a week, paced to the key's rate
limit. Addresses are stored encrypted (AES-256-GCM) and found by a keyed HMAC, never in plain
text; no log line, audit row or error message carries an address or the key, which travels only
in a request header. The request goes through the SSRF-checked client under a network policy
that allows only HIBP's two API paths over HTTPS, and the SSRF check sees only the host, so the
address never reaches a log. Alerts are fixed sentences (no model), go only to the owner's own
linked Telegram and Slack chats, never name a breach HIBP marks sensitive, and defang the
vendor's text so the attribution is the only link. The password check on the same page hashes
the password in the browser and sends only the first 5 hex characters of its SHA-1 to Crawler,
which asks Pwned Passwords for every suffix with that prefix (padded) and hands the list back;
the match is made in the browser. The password never leaves the browser, and nothing about a
check is kept: no cache, no audit row, and no log line with the prefix or the number of entries.
The proxy is limited to 20 checks a minute per user.

### backend/services/capabilities/README.md

Under "### Breach monitor (`breach_monitor`)":

`breach_monitor` is a policy switch (`tools=()`) whose availability is an owner key: it reads
`"hibp" in ctx.service_keys`, so it is on by default but blocked, with "Breach checks use your
own Have I Been Pwned key, and none is saved yet. Add one in Security → Service keys.", until the
key exists (stored or in `.env`); saving one turns it on with no second click. The weekly sweeper
and Check now read the effective state through `capability_gate` (fail closed), and re-read it
before every lookup. The keyless feature it governs, the Security page's password check, reads
the owner's switch value (`CapabilityStatus.enabled`), not `effective`, so it works without a key
yet stops when the owner turns breach checks off. It has no settings (the weekly cadence is a
constant), so there is no `_SETTINGS_DEFAULTS` entry and no `CapabilitySettings.tsx` row.
