# Site rules for Crawler's browser (Blocked, Always ask, Trusted, sensitive-site defaults)

Status: implemented (security top 10, S7). Migration `0030_browser_site_rules`. Capability
`browser_site_rules` (a policy switch, on by default).

## Why

Some sites should never be opened by an agent, because the owner says so. On banks, brokers, crypto
exchanges and tax portals, every step deserves a second look. Before this change, Crawler's browser
treated every public site the same way: the only per-site behaviour was the SSRF guard and the
purchase rules.

## What the owner gets

- One install-wide list of **site rules**, managed on the Security page ("Site rules" tab, owner only;
  never from chat, so no message, forwarded text or tool can change it). A rule names an exact host
  (`docs.example.com`) or a site with all its subdomains (`*.example.com`) and one of three kinds:
  - **Blocked**: Crawler never opens the site or acts on it.
  - **Always ask**: Crawler may read the site, but every action there goes through an approval card
    that carries a "sensitive site" note, and it can never run without a card.
  - **Trusted**: no extra warnings (cards still apply; SSRF, link reputation, tool rules, outbound
    checks and the purchase rules are untouched).
- A built-in list of **161 sensitive sites** in four categories (banks and money accounts 72,
  brokers and investing 32, crypto exchanges and wallets 26, tax and government services 31), Always
  ask by default. The owner can set a whole category to another kind, or override one site with a
  rule of their own.
- A **Check a site** box that explains which rule applies and why, and a "Recently stopped or
  flagged" list (in memory, since Crawler last started, hosts only).
- Nothing leaves the machine: no key, no network, no model.

## Precedence (one place: `services/site_rules/snapshot.py`)

1. The switch is off: no rule applies (owner rules, overrides and the built-in list alike).
2. An owner rule that covers the host wins, whatever the built-in list says. Among owner rules the
   exact host wins, then the longest `*.` suffix ("Trust docs.example.com" beats "Block
   *.example.com"). This is `core.network_security.match_host_pattern`'s order (tested).
3. Otherwise a built-in entry applies with its category's kind (the owner's override, else Always
   ask).
4. A Blocked result on a protected sign-in, CAPTCHA or payment host is answered as Always ask
   (`protected=True`). The API already refuses such rules; this catches rows written any other way.
5. Two rules of equal reach: the stricter kind wins (Blocked, then Always ask, then Trusted).

## Where the rules are enforced

1. **The call checks**, slot 3 of 5 (tool rules, MCP pins, **site rules**, outbound, file
   reputation): `browser.read open`, `web.fetch_page` and `web.screenshot` of a Blocked URL are
   refused before anything starts; a read on a page already open on a Blocked site is refused; an
   act or checkout on a Blocked page is refused before its card and again at approval (judged on the
   card's bound page, never a page the model names). An act or checkout on an Always-ask site gets a
   `site_sensitive` warn note for its card, and an escalation if it would ever run without one.
   Rules that were never read refuse these tools only (fail closed).
2. **The browser guard** (`Guard._route`, through `EgressHooks.site_rules`), in the order SSRF, site
   rules, link reputation: top-level navigations, redirect hops, popups and frame navigations to a
   Blocked site are aborted. Always ask never stops a navigation.
3. **The observe step** (`_shared.observe`): a page on a Blocked site (one loaded before the rule
   existed, a "back" from the browser's cache) is blanked, refused and never remembered as the page
   a later act binds to; a page on an Always-ask site is described with a `site_notice` the model is
   told to respect.
4. **The web toolkit's resolver** (wrapped in `main.py`): every hop of `web.fetch_page`, each source
   `web.research` considers, and the first and final URL of `web.screenshot` are refused for a
   Blocked host before a socket opens.

**Approved checkouts are never broken.** Inside an approved checkout's order window or its 3-D
Secure hand-off, a Blocked verdict is set aside only for protected hosts and hosts on the built-in
"banks" list (where card issuers' 3-D Secure pages live); an owner Blocked rule on any other host
still blocks there (review SEC-F4, scaffold A32). browser.act's window and the person's ordinary
hand-off are not exempt.

## Privacy

Audit rows (`connector_name="site_rules"`) hold rule ids, kinds, the category key and a keyed hash
of the host (`HMAC-SHA256` under `sha256("crawler-site-rules\0" + ENCRYPTION_KEY)`, 16 hex
characters), never a host, URL, path or query. Owner changes are audited in the same transaction as
the change (`site_rule_created`, `site_rule_updated`, `site_rule_deleted`, `site_category_changed`);
blocks and Always-ask reads (`site_rule_blocked`, `site_rule_noted`) are de-duplicated per user,
site and 10 minutes. Logs keep a host at most. The recent-hits list is memory only, holds hosts
without user ids, and is lost on restart.

## Failure policy

| failure | behaviour |
| --- | --- |
| rules never loaded | call check refuses browser and web page tools; guard stops navigations; observe describes no web page; the resolver lets hops through (the call already failed) |
| a refresh fails after a good load | the last good snapshot stays; retried after 5 s |
| the switch cannot be read | counts as on |
| a hook raises in the guard or in observe | the navigation is stopped / the page is not described, with a named reason |
| an owner write's audit row fails | the transaction rolls back; 500 "The rule could not be saved. Try again." |
| a refresh after an owner write fails | the snapshot is marked stale and the next call retries; the API still answers 201 |

## Hostile input

Hosts are read the way Chromium reads them (WHATWG URL parsing, UTS #46 nontransitional mapping,
checked against Chromium code point by code point), so a rule cannot be walked around by spelling a
host differently. Every reading is linear in the URL's length however hostile: lookups probe only
suffixes as long as the longest rule, punycode and NFKC see one bounded label at a time (a label
longer than any rule can name becomes a stand-in without being normalised), and the guard judges a
megabyte-long frame URL in milliseconds.

## Deviations from the design (accepted)

- **D1**: Blocked also covers `web.fetch_page`, `web.research` and `web.screenshot`, so the agent
  cannot read a Blocked site one tool call away from the browser.
- **D2**: Blocked also stops frame navigations (an embedded Blocked site is still "opened").
- **D3**: turning the switch off suspends every rule, owner rules included.
- Hosts are normalised the way Chromium does it, not with `core.network_security.normalize_policy_host`
  (Python's IDNA 2003): owner rules and the hosts the browser reports are spelled the same way,
  including "ß" and "ς". `parse_site` refuses those two letters and the joiners with a plain sentence
  (browsers and IDNA versions spell them two ways), so the owner types the `xn--` form.
- `SiteVerdict.exempted`: a blocked bank page set aside inside an approved checkout still carries a
  sensitive-site notice and card note.
- No "Always allow on this site" card button (it would loosen cards).

## Not covered (follow-ups)

- A page's subresources and WebSockets to a Blocked host (Blocked means "never navigate there").
- Intermediate redirects inside `web.screenshot`'s own browser (its first and final URL are judged).
- `desktop.act` driving the owner's real browser (out of scope; browsers are never weekly-approved).
- reCAPTCHA is served from the path `www.google.com/recaptcha`; an owner Blocked rule on exactly
  `www.google.com` would also block reCAPTCHA frames (`*.google.com` cannot be blocked: it covers
  `accounts.google.com`).
- Parity with Chromium's host mapping is pinned for Chromium 1243 (Unicode 16) on Python 3.12; rerun
  the code-point comparison when either is upgraded (the guard itself always judges Chromium's
  canonical ASCII host, so only the call check's reading of a model-written URL could drift).

## Shared doc text (pasted at integration)

### docs/CODE-MAP.md

Under "Site rules for the browser (security S7)":

- `backend/services/site_rules/` — the owner's site rules for Crawler's browser and web reads (local
  only: no network, no model, no key).
  - `patterns.py` — what a typed site means (`parse_site`, `validate_kind`), how a browser reads a
    host (`host_of`, Chromium's UTS #46 mapping, linear on hostile input), `PatternIndex` (exact,
    then longest `*.` suffix), the keyed `host_hash` for audit rows.
  - `sensitive_sites.py` — the built-in categories (banks, brokers, crypto, government; Always ask by
    default) and `PROTECTED_PATTERNS` (sign-in, CAPTCHA and payment hosts that are never Blocked).
  - `snapshot.py` — `SiteRuleSnapshot`: the immutable view every reader asks (precedence, the
    protected downgrade, the checkout-window exemption), plus the card notes and read notices.
  - `messages.py` — every sentence the owner, the approver or the model reads.
  - `store.py` — rows of `browser_site_rules` (model `models/browser_site_rule.py`, migration 0030):
    create/update/delete/set_category, each audited in the same transaction.
  - `service.py` — `SiteRulesService`: the cached snapshot (refreshed after owner changes, on a
    "capabilities" change and every 60 s), the per-user guard hook, the resolver wrapper, the call
    check, recent hits and the de-duplicated hit audit rows.
  - `hooks.py` — `SiteRuleGuardHook` (`EgressHooks.site_rules`: `Guard._route` and
    `_shared.observe`) and `wrap_resolver` (the web toolkit's hops).
  - `check.py` — `SiteRulesCallCheck`, slot 3 of the call checks.
- `backend/api/routes/security_site_rules.py` — owner-only `/api/security/site-rules` (list, add,
  change, remove, set a category, check a site).
- `backend/services/capabilities/browser_site_rules.py` — the `browser_site_rules` switch.
- `frontend/src/pages/security/SiteRulesTab.tsx`, `siteRulesFormat.ts` — the Security page's "Site
  rules" tab.
- Hook points: `main.wire_services` builds the service, passes `EgressHooks(site_rules=...)` to the
  three browser toolkits, wraps the executor's `WebToolkit` resolver, and registers the call check
  third.
- Tests: `test_site_rules_patterns.py`, `test_site_rules_sensitive_list.py`,
  `test_site_rules_snapshot.py`, `test_site_rules_service.py`, `test_site_rules_call_check.py`,
  `test_site_rules_guard.py`, `test_site_rules_observe.py`, `test_site_rules_web.py`,
  `test_site_rules_routes.py`, `test_site_rules_capability.py`, `test_site_rules_wiring.py`,
  `test_site_rules_browser.py`, `test_site_rules_migration.py` (helper `tests/site_rules_fakes.py`);
  frontend `SiteRulesTab.test.tsx`, `siteRulesFormat.test.ts`.

### docs/BACKLOG.md

Under "Site rules for the browser (security S7)":

Done: owner site rules (Blocked / Always ask / Trusted, exact host or site with subdomains, at most
500), a built-in list of 161 sensitive sites in four categories (Always ask by default, overridable
per category or per site), enforced by the call checks (slot 3), the browser guard (navigations,
redirects, popups, frames), the observe step and the web toolkit's resolver; approved checkout
windows exempt only protected and bank hosts (SEC-F4); audit rows carry keyed host hashes only;
Security page tab with Check a site and recent hits. Deviations D1 (web tools covered), D2 (frames
covered), D3 (the switch off suspends every rule).

Open:
- Subresources and WebSockets to a Blocked host are not judged (Blocked means "never navigate
  there").
- `web.screenshot`'s intermediate redirects inside its own browser are not judged (first and final
  URL are).
- `desktop.act` in the owner's real browser is out of scope.
- Rerun the Chromium host-mapping parity check when Playwright's Chromium or Python is upgraded.

### SECURITY.md

Under "Site rules for Crawler's browser":

The owner can mark sites **Blocked**, **Always ask** or **Trusted** (Security → Site rules, owner
only; never from chat). Banks, brokers, crypto exchanges and tax and government portals (161 sites)
are Always ask by default. The rules are enforced at four points: the pre-dispatch call checks
(a browser or web page call on a Blocked site is refused before anything starts, and again when a
card is approved; an act on an Always-ask site carries a "sensitive site" note and never runs
without a card), the browser egress guard after its SSRF check (navigations, redirect hops, popups
and frames), the observe step (a page on a Blocked site is blanked and never described), and the web
toolkit's resolver (every hop of a fetch, research source or screenshot). Inside an approved
checkout's order window or 3-D Secure hand-off, a Blocked verdict is set aside only for protected
sign-in, CAPTCHA and payment hosts and hosts on the built-in banks list; Blocked rules over those
protected hosts are refused outright. Hosts are read the way Chromium reads them, so a rule cannot
be evaded by spelling a host differently, and every reading is linear in the URL's length. Rules
that cannot be read fail closed for the browser and web page tools. Hosts reach the audit log only
as keyed hashes (HMAC-SHA256 under a key derived from `ENCRYPTION_KEY`); nothing is sent anywhere.

### backend/services/capabilities/README.md

Under "Site rules for the browser (`browser_site_rules`)" (the pattern: an owner list behind a
policy switch):

`browser_site_rules` is a policy switch (`tools=()`, on by default, low risk) for a list the owner
keeps: Blocked / Always ask / Trusted site rules and overrides of the built-in sensitive-site
categories. Lists never live in `capability_settings` (whole numbers only); they get their own
table (`browser_site_rules`) behind owner-only routes, and every write is audited in the same
transaction as the change. Hot paths (the browser guard on every navigation, the web resolver on
every hop) read an immutable in-memory snapshot without touching the database; the service rebuilds
it after each owner change, on a "capabilities" change and at most every 60 s, keeps the last good
one when a read fails, and fails closed (browser and web page tools refused, navigations stopped)
when none was ever loaded. The switch is re-read on every call (the installation's 5 s cache); one
that cannot be read counts as on. Off means no rule applies at all, owner rules included.

### README.md

No change: the Permissions row WAVE 0 wrote ("Site rules for Crawler's browser … On") is final.
