# Link reputation: free local link checks, and the owner's own Google lookup

Date: 2026-10-14. Status: built as security wave skill S4 (security10). Capability
`link_reputation` (policy switch, no model tool), no table of its own (the owner key column
`installation.security_service_keys` is migration `0025_security_service_keys`, shared with the
breach monitor and file reputation), no new dependency.

## 1. Why

Mail alerts (S2), scam checks (S3), outgoing-message checks (S1) and the agent's browser all
need one answer to "what do we know about this link?". Before this, only checkout knew about
look-alike hosts, and nothing could ask Google's list of dangerous sites. Decisions 2: an
outside service is used only with the owner's own key; local checks always work.

## 2. Two layers

1. **Local checks, always on, no network** (`backend/services/security/link_checks.py`, pure):
   look-alike letters and punycode, a typo or homograph of a well-known brand, a brand used as a
   label or glued to another word, bare public IP addresses (in every spelling a browser
   accepts), credentials before an "@", link shorteners (never expanded), abused domain endings,
   script links (`javascript:`, `vbscript:`, `data:`, `file:`), and link text that names another
   site. A link is read the way a browser reads it (the URL standard, not urllib): tabs and line
   breaks dropped, a backslash is a slash outside the query, the authority ends at the first
   "/", "\", "?" or "#" and the host follows its last "@" (so "user[@host" and a full-width "/"
   before the "@" still name the host), the characters a browser drops from a host (soft
   hyphen, zero-width characters, variation selectors, the byte-order mark and, since UTS 46
   16.0, the Hangul fillers and the other invisible controls it added) are dropped, every code
   point is mapped the UTS 46 way (`lookalike.fold_host`: NFKC_Casefold per code point, then
   NFC, never `str.lower()`; the capital sharp s is "ß" as in browsers with UTS 46 15.1 or
   later, and letters newer than Python's Unicode database fold as current Chromium folds
   them), a ZWNJ or ZWJ is kept where a browser keeps it (after a virama, a ZWNJ between
   joining letters) and dropped where the browser refuses the host anyway, a name
   only IDNA 2008 allows is read (UTS 46, nontransitional: "faß.de" is `xn--fa-hia.de`), a host
   may hold every character the standard allows (`x$y.example.org`; only its forbidden domain
   code points make a link unreadable), an IPv4 part holds only its base's digits and a
   zero-padded address or port is the one the browser opens, known wrappers (Outlook Safe Links,
   `google.com/url`, `l.facebook.com`) are unwrapped at most twice. Every step is linear in the
   input and never raises: a host is measured before it is encoded, numbers and ports are
   bounded before they are converted, a link over 32 KB is read up to its host only, link text
   is read up to 4 KB and 32 host-like tokens, and a link (or link text) that breaks a check is
   reported with the "unreadable" signal instead of costing the report its other findings.
2. **The owner's Google lookup** (`backend/services/reputation/links.py`, `LinkReputation`):
   Safe Browsing v4 Lookup (`threatMatches:find`, batches of 100) or Web Risk (`uris:search`,
   one GET per link, at most 10 per call, 3 at a time). Web Risk wins when both keys exist (its
   terms allow commercial use). Only with a key, the `link_reputation` switch on, and an
   eligible link.

`services/security/lookalike.py` holds the shared look-alike facts (checkout, S1, S2, S4, S7).
Checkout keeps `decode_host` (IDNA 2003, refuses what it cannot decode); link checks read with
`browser_host` / `ascii_host` (the host a browser really opens).

## 3. What leaves the machine

`link_checks.lookup_url(url, purpose)` is the one rule:

- only http(s); never a non-public host (`.local`, `.internal`, `.home.arpa`, `.test`, a single
  label, a private, loopback, link-local or reserved IP, including IPv4 carried inside IPv6);
- the browser sends `scheme://host[:port]/` only (account-mode URLs carry session ids and
  OAuth codes);
- other purposes send `scheme://host[:port]/path`; userinfo and fragment never; the query only
  when no parameter name is sensitive (`token`, `code`, `state`, `sig`, `session`, `otp`, ...;
  split on "&" and ";", bracketed names count, decoded until stable), no value is a 32+
  character token or padded base64, no e-mail address is in it and the secret detector finds
  nothing;
- the path is dropped (host only) when a segment holds a 24+ character token run with a digit,
  base64 padding ends a segment, an e-mail address is in it, or the secret detector flags it
  (review SEC-F10);
- at most 2,048 characters (longer: the query goes, then the path);
- a host holding a character no public name uses (`x$y.listed.example.org`, which a browser
  opens) is looked up as its nearest ancestor made of DNS labels, `scheme://ancestor[:port]/`
  only, for every purpose (Google matches a host's suffixes, so a listed parent is found); when
  that ancestor would not hold the registrable domain (`pay$pal.com`) the link is unreadable.

The key travels in the `X-Goog-Api-Key` header, never in a URL. Every request goes through the
SSRF-guarded client under the `link_reputation` network policy (two hosts, one path each); the
policy resolver never sees the query (Web Risk carries the checked link there, and `check_ssrf`
logs the URL it is given on a private hit). Verdicts are cached in process memory only (at most
4,096 entries, a match for at most 30 minutes and never past Google's `cacheDuration` /
`expireTime`, no match for 5 minutes). Logs carry event names, the service, an HTTP status and
exception type names: never a link, a host, a query, a key or an exception message.

## 4. Failure policy

Fail open, always with a "not checked" status, never "safe" (the best a report says is
`no_known_threats`). The only thing S4 blocks is a browser navigation to a site Google lists.

| Google answer | status | cool-down | owner alert |
| --- | --- | --- | --- |
| network error, policy refusal | `error` | none | no |
| timeout | `timeout` | none | no |
| 5xx | `error` | 30 s | no |
| 429 | `rate_limited` | Retry-After clamped to 60..900 s, else 60 s doubling | no |
| 400 `API_KEY_INVALID`, 401, 403 | `key_rejected` | 600 s | once per service per 24 h, one `link_reputation_key_rejected` audit row per admin |
| other 4xx, bad JSON, oversized | `error` | none | no |

Limits: `lookups_per_minute` (60) and `lookups_per_day` (2,000) per service and key fingerprint,
in memory; background mail checks may use at most half of each window (review FEA-SF1). The
owner's "dangerous found" and "not checked" day counters keep at most one entry per 10 seconds
and drop old ones on every add, so they never grow with traffic.

## 5. The browser

`LinkReputation.navigation_check(url, state)` is attached per toolkit context as
`EgressHooks.reputation` (scaffold A1). The guard calls it for every top-level navigation,
redirect hop and the bound order POST's redirect, after the SSRF check and the owner's site
rules (S7), before the order checks; never for a page's own requests, frames or WebSockets.
Sign-in, MFA and plain CAPTCHA hosts are never looked up (Okta tenants are: anyone can register
one); google.com and its user-content sites still are. An approved checkout's 3-D Secure window
is looked up like any navigation (review SEC-F4): a listing blocks, an error or timeout lets the
bank page open. An address the hook cannot read is noted "not checked (its address could not be
read)" when the owner has Google set up, never passed on as if it had been looked up. The hook
never raises (an exception would abort the navigation); its notes
(look-alike letters, "not checked") go back to the model in punycode only, so PromptGuard never
redacts them (review SEC-F12), and browser.read's open and click return the notes of their own
navigation as `security_notes`.

## 6. The owner

Security → Service keys (`frontend/src/pages/security/ServiceKeysTab.tsx`): one row per service
from `GET /api/security/keys`, Test / Save (tested first, stored only on success) / Remove (asks
first), the `.env` sentence instead of a field when the server provides the key, and under the
Google rows the link-check line from `GET /api/security/link-reputation/status` (owner only;
counts, limits, the service in use, cool-down and the last problem; never a key, a link or a
host). Settings → Permissions shows `link_reputation` blocked until a Google key exists.

## 7. Deviations from the designer spec (S4.md)

- The scaffold's overrides (A1 hook mechanism, A8 `remote_configured`, A11 `KeyTestResult` from
  `keys.py`, A32 no checkout-hand-off exemption, A36 background share) are built as written.
- Hosts are read as a browser reads them (UTS 46) instead of with Python's IDNA 2003 codec,
  which refused names a browser opens (a Hebrew name ending in digits, letters added to Unicode
  after 3.2) and folded "ß" to "ss": such a link was "unreadable" and never looked up. Letters
  are folded per code point the UTS 46 way, not lower-cased: `str.lower()` read another host
  than the browser opens for the Cyrillic Extended-C letters, Cherokee, the combining iota and
  final-position capital sigma, and refused the ACE form Chromium writes for a Cherokee name.
  The reference is the browser that opens the link (the Chromium Playwright runs here, swept
  code point by code point), not Node's URL parser: for the capital sharp s Node 22 still
  reads "ss" (pre-15.1 tables), current browsers read "ß", and "ß" is what is looked up.
- A link over 32 KB is read up to its host instead of being unreadable: padding a link must not
  hide its site from the lookup. Over the browser's own 2 MB limit it is unreadable.
- A host with a character the URL standard allows but DNS names do not use
  (`x$y.listed.example.org`) is looked up as its nearest DNS ancestor (host only), not left
  unreadable; one whose registrable domain holds such a character is unreadable (no public site
  is spelled that way). A link whose lookup cannot be worked out reads `error` ("not checked"),
  never `not_eligible`, and the browser hook notes an address it cannot read.
- Okta tenant subdomains (`TENANT_IDP_DOMAINS`) are looked up; only bare `okta.com` and
  `oktapreview.com` are exempt (spec 4.5 exempted every subdomain).
- Extra narrowing of what is flagged and sent: a brand of four letters or fewer counts as a
  typo only when the label reads as the brand (`nice.com` is not `nike.com`); Japanese, Chinese
  and Korean names written in their usual script mixes are international names, not look-alikes
  (UTS 39 highly restrictive); an e-mail address in a path or query is never sent or shown.
- Card notes: only a listed link (`link_dangerous`, high) and a link with a high local signal
  (`link_suspicious`, warn) make a note; warn and info signals alone do not.

## 8. Tests

`backend/tests/test_link_checks.py` (pure, Windows CI), `test_link_reputation_client.py` (the
service behind `httpx.MockTransport`, `check_ssrf` replaced), `test_link_reputation_browser.py`
(the hook directly and through the real `Guard._route` with request doubles, and browser.read's
open/click on a fake page), `test_link_reputation_capability.py`, `test_link_reputation_api.py`
(the status route and the Google rows of the key routes with S4's real tester),
`test_lookalike.py`, and `frontend/src/pages/security/ServiceKeysTab.test.tsx`. An optional live
smoke test runs only with `CRAWLER_LIVE_SAFE_BROWSING_KEY` set.

## Shared doc text (pasted at integration)

### docs/CODE-MAP.md

Under "### Link reputation (security S4)":

- `backend/services/security/link_checks.py` — free link checks with no network (look-alike
  letters, brand typos and homographs, bare IPs in every browser spelling, credentials before an
  "@", shorteners, abused endings, script links, link text naming another site), links read the
  way a browser reads them, `lookup_url` (the one rule for what may be sent to Google),
  `display_url`, the card notes (`security_notes`, `coverage_note`, `model_safe_text`), and the
  `LinkChecker` protocol S1, S2 and S3 take (`LocalOnlyLinkChecker` is the null object).
- `backend/services/security/lookalike.py` — look-alike host facts shared by checkout, mail,
  outgoing-message and link checks: confusables, `decode_host` (IDNA 2003, checkout's refusal),
  `browser_host` / `ascii_host` (the host a browser opens, UTS 46), `fold_host` (the UTS 46
  mapping, per code point), `strip_ignored`,
  `registrable_domain`, `lookalike_of`, `mixed_script_reading`, `is_ip_literal`,
  `WELL_KNOWN_BRANDS`, `CONSUMER_MAIL_DOMAINS`.
- `backend/services/reputation/links.py` — `LinkReputation` (`app.state.link_reputation`): the
  owner-keyed Google Safe Browsing / Web Risk lookups, the in-memory verdict cache, the owner's
  limits (mail held to half), cool-downs, single-flight, the browser guard's
  `navigation_check` (`EgressHooks.reputation`), `status()`, `test_google_key` (the key routes'
  tester) and `owner_alert` (key rejected).
- `backend/services/capabilities/link_reputation.py` — the `link_reputation` switch and its
  two limits; blocked until a Google key exists.
- `backend/api/routes/link_reputation.py` — `GET /api/security/link-reputation/status` (owner
  only).
- `frontend/src/pages/security/ServiceKeysTab.tsx` — Security ▸ Service keys: every service a
  key can be saved for, Test / Save / Remove, and the link-check line under the Google rows.

### docs/BACKLOG.md

Under "### Link reputation (security S4)":

Done: local link checks for every consumer (S1, S2, S3, the browser); the owner's Google Safe
Browsing or Web Risk lookup with key-in-header, query-free policy checks, Google-bounded cache,
owner limits with a half share for mail, cool-downs and a once-a-day key-rejected alert; the
browser guard's reputation step (also inside a checkout's 3-D Secure window); the Service keys
tab and the link-check status line. Follow-ups:

- web.fetch and web.screenshot (a separate, unguarded Playwright) are not looked up.
- Subframes and WebSockets are not looked up; neither are back/forward cache restores.
- Privacy upgrade: Safe Browsing v5 / Web Risk hash-prefix lookups, so no URL leaves at all.
- Counters and cool-downs are per process and reset on restart; persist them if owners hit
  Google's quota.
- Feed the owner's Blocked sites (S7) into mail and chat link reports.
- Brand typos still collide with some dictionary words of five letters or more
  (`cooking.com` reads near `booking.com`); an allowlist of common words, or warn instead of
  high for a raw-edit typo, would cut the noise.
- Duo's and the CAPTCHA vendors' subdomains are exempt from the lookup like their bare hosts;
  review whether any of them serve tenant-authored pages (Okta tenants already are looked up).
- The Save line reads "Saved. <Service> accepted the key." because PUT /api/security/keys
  answers without the tester's sentence; return it to show Google's own words.
- A host with characters DNS names never use (`x$y.listed.example.org`) is looked up as its
  nearest DNS ancestor but carries no signal of its own (the signal codes are fixed for S1, S2
  and S3); a dedicated warning would need their wording too.
- Python 3.12's Unicode database is 15.0. `lookalike._NEWER_MAPPINGS` holds what current
  Chromium maps for letters added later (Unicode 16 and 17 capitals, the outlined Latin letters
  and digits, the modifier capital S); re-sweep against the browser and trim it when the backend
  moves to a Python whose database has them.
- Browsers older than UTS 46 15.1 read the capital sharp s as "ss"; such a link is looked up as
  current browsers read it ("ß"). A second lookup of the older reading would cover them.
- The joiner rule is wider than CONTEXTJ (the standard library has no Joining_Type table): a
  ZWNJ beside a non-joining letter of a joining script is kept, so a host the browser refuses
  is looked up. That costs a lookup, never a miss.

### SECURITY.md

Under "### Link reputation":

Links in mail alerts, scam checks, outgoing messages and pages Crawler's browser opens are
checked on this server for look-alike letters, brand imitations, bare IP addresses, credentials
before an "@", shorteners, script links and link text that names another site, reading each link
the way a browser does. With the owner's own Google Safe Browsing or Web Risk key (and the
"Check links with Google Safe Browsing" switch on), links are also looked up in Google's list of
dangerous sites. Only the link is sent, in a reduced form: for the browser only the site's
scheme and host; otherwise the path without userinfo or fragment, and the query only when it
carries nothing that looks like a token, a code, a session id, a secret or an e-mail address.
Non-public hosts are never sent. The key travels in a request header through the
`link_reputation` network policy and the SSRF-checked client; verdicts are kept in memory only,
within Google's stated cache lifetime; logs never carry a link, host or key. A lookup that fails
never blocks anything and is reported as "not checked"; no answer is ever called "safe". The
browser refuses only a page Google lists.

### backend/services/capabilities/README.md

Under "### Link reputation (`link_reputation`)":

A policy switch (`tools=()`), on by default and low risk, that reads blocked until
`ReportContext.service_keys` holds `safe_browsing` or `web_risk` (an HIBP or VirusTotal key
alone does not unblock it), so adding a Google key is the only step. The key lives in the shared
encrypted store (`InstallationService.service_key`), never in `capability_settings`, which holds
only `lookups_per_minute` (60) and `lookups_per_day` (2,000). `LinkReputation` reads the switch
per call through `capability_statuses()` and fails closed for egress when it cannot (nothing is
sent, the link is marked "not checked"). Local link checks need no switch. There is no model
tool: the in-turn path for "is this link dangerous?" is the scam check's `security.check_scam`.

### backend/services/security/README.md

Replace the `lookalike.py` row with:

| `lookalike.py` | Look-alike host facts shared by checkout, mail, outgoing-message and link checks: punycode and mixed-script letters, typo and homograph domains of well-known brands, a brand used as a label of another site, registrable domains, bare IP literals, the host a browser really opens (`browser_host`, `ascii_host`, `fold_host`: UTS 46, letters mapped per code point as a current browser maps them, the characters a browser drops dropped, joiners kept where a browser keeps them, linear in the input), `WELL_KNOWN_BRANDS` and `CONSUMER_MAIL_DOMAINS` (security wave, owned by S4). |
