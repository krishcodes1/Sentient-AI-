# On-demand scam check: "is this a scam?" (security S3)

Status: built in two halves, delivered together. **S3a**: the check itself
(`services/scam_check/` except `channels.py`, `services/security/scam_signals.py`), the web
chat's `/scam`, the Security page's Check for scams tab and its two routes, and the in-turn
`security.check_scam` tool. **S3b**: the Telegram and Slack entry points in
`services/scam_check/channels.py`.

## 1. What it does

Someone forwards the owner a text, an email, a link, a screenshot or a QR code. The owner asks
Crawler "is this a scam?":

- `/scam <text>` in a web chat (with or without pasted screenshots or attached files),
- the Security page's **Check for scams** tab (paste, add up to 4 screenshots, optional note),
- in an ordinary chat turn, where the model calls `security.check_scam`,
- `/scam` in Telegram (text, a reply, a captioned photo or album, or a bare `/scam` that
  checks the next message) and `scam ...` in a Slack DM.

The answer is one of four fixed headlines, never "safe":

| verdict | headline |
| --- | --- |
| `likely_scam` | 🚩 Likely a scam |
| `suspicious` | ⚠️ Suspicious, be careful |
| `no_signs_found` | 🔎 No signs of a scam found (always with "No check can prove a message is safe.") |
| `not_checked` | ❔ I couldn't check this (only when nothing could be read) |

It always gives Crawler's own reasons (fixed sentences), what to do (a fixed table), and notes
on what was not checked. The AI provider's own reasons, when any survive the filter, are shown
apart under "Your AI provider also noted:".

## 2. Two decisions that shape it

**The check runs outside the chat turn.** A pasted scam often carries look-alike letters or hidden
characters. PromptGuard's input scan blocks such a message whole in a normal turn, and a pasted
message is someone else's words: run as a turn it would read as the owner's own instructions
(review SEC-F11). So every entry point that takes pasted content (the web `/scam`, the Security
box, Telegram and Slack) runs the check out of turn and asks the account's own AI provider once,
through `AgentRuntime.complete_once` (no tools, no input scan; the model-egress floor and "Hide
personal details" still apply). PromptGuard is not loosened anywhere: it is used only as an
information signal on the text (`ai_injection`) and as a fail-closed filter on the AI's reasons.

**The in-turn tool makes no model call.** `security.check_scam` runs the local checks, the sender
checks and link reputation only. A model call inside a turn would not reach `/usage` (only the
turn's own message rows carry usage), and the turn's model already reads the message. The tool
takes no quota; the chat's own rate limit covers it.

## 3. The out-of-turn check, step by step (`ScamCheckService.check`)

1. **Switch.** `InstallationService.capability_statuses()["scam_check"]`: off or blocked refuses
   with the capability's `when_denied` or blocked reason; a report that cannot be read refuses
   (fail closed). Nothing is downloaded, looked up or sent.
2. **Inputs.** Text stripped and cut to 8,000 characters (`text_cut`); the person's note cut to
   500 (kept outside the fence); at most 4 pictures (`too_many_pictures`), each base64-decoded,
   at most 5 MB and sniffed from its bytes (`services.files.detect`) as PNG, JPEG, WebP or GIF
   (`picture_unusable` otherwise); files only as sha256 + size. Nothing usable refuses (`empty`).
3. **The same content within 10 minutes** is answered from memory (`RecentChecks`, 256 entries,
   in memory): no quota, no model call, the note "Same result as your check a few minutes ago."
4. **Quota** (`ScamQuota`, in memory): 4 checks per minute and the owner's `checks_per_day`
   (default 30) per person per rolling 24 hours.
5. **Local pass** (`scam_signals.analyse_text`, stdlib only): hidden characters, wording tricks,
   links and label/address pairs (Markdown, HTML, Slack `<url|label>`, Telegram `text_link`).
   PromptGuard on the text adds the weak `ai_injection` sign when it finds instructions aimed at
   an AI; it never blocks the check.
6. **Links** go to S4's `LinkChecker` (`purpose="scam_check"`): Crawler's own lists always,
   Google Safe Browsing / Web Risk only with the owner's key. At most 10 per check.
7. **Files** go to S10's `FileReputationService.check_hash` (hash only, never an upload).
8. **AI review**: one `complete_once` with `SCAM_SYSTEM_PROMPT`, Crawler's automatic findings
   (hosts in punycode), the note, the message fenced as someone else's words
   (`fence_untrusted(..., preamble=SCAM_FENCE_PREAMBLE)`, a fresh nonce) and the pictures as
   image blocks. 60 s timeout. A provider that cannot see pictures gets the text only (note
   `no_vision`); only pictures and a blind provider refuses (`provider_blind`) and gives the
   quota back. The reply must be one JSON object; anything else is `ai_unreadable` (usage kept).
9. **Links read from pictures or a QR code** are checked too; a QR code the AI could not read
   leads nowhere (`qr_unreadable`, no URL is ever guessed).
10. **Verdict** (section 4), then one facts-only audit row (`scam_check_ran`).

The answer is saved as two chat rows (section 6) by the entry point that asked.

## 4. Verdict rules, reasons and advice

Signals (codes, weights and fixed sentences in `scam_signals.SIGNAL_SENTENCES` and
`verdict.link_sentence`):

- decisive: `link_malicious` (Google's list), `file_malicious` (VirusTotal);
- strong: `link_lookalike`, `anchor_mismatch`, `sender_impersonation`, `credential_ask`,
  `code_ask`, `financial_ask`, `payment_odd`, `remote_access`, `hidden_tags`, `bidi_override`;
- weak: `link_suspicious`, `urgent_pressure`, `prize_or_refund`, `threat`, `delivery_fee`,
  `secrecy`, `too_good`, `invisible_chars`, `reply_to_mismatch`, `ai_injection`,
  `file_suspicious`.

Rules (`verdict.combine`): **likely scam** for any decisive sign, two strong, or one strong and
two weak; **suspicious** for one strong or two weak; otherwise **no signs found**. A repeated
trick counts once. A link that was not checked counts neither way. The AI's verdict can raise the
rule verdict, never lower it. "Couldn't check" only when nothing could be analysed and no rule
fired.

Reasons: Crawler's own sentences only, strongest first, flagged links (at most 3) first in each
weight, at most 6. The AI's reasons (at most 3) pass `review.filter_reasons` first: a reason is
dropped when it holds a link, `www.`, a domain on any letter ending, an `@`, a phone number
(7+ digits with short separators), a vanity number, an IP address, an HTML character reference,
Markdown link syntax, a "safe/legitimate/genuine" claim, or anything PromptGuard flags, in any
form a person could read it (invisible and combining marks, character references, look-alike
letters and dot-like characters undone first). A scanner error withholds them all. Any drop adds
the note "Some of your AI provider's notes were left out ...".

Advice (`verdict.advice_for`, at most 4, fixed table): don't click or scan; don't sign in from the
message; never share a code; don't pay by gift card, crypto or wire; don't install apps or give
remote access; agencies don't threaten arrest by text; if you already clicked or paid, change the
password and call your bank; contact the sender another way; for no signs found, "No check can
prove a message is safe. ..."; for couldn't check, "Try again with the text pasted in, or the
link itself."

Rendering: `render_plain` (Telegram, Slack) defangs every reason, note and link line
(`page_watch.defang`); `render_markdown` (web chat) puts hosts in code spans and escapes the AI's
reasons (backslash, brackets, parentheses, `*`, `_`, the backtick, `<`, `>`, `!`, `#`, `&`, `~`
and `|`), so neither renderer can produce a link; `to_json`
(the route and the tool) scrubs every string of look-alike and invisible characters, so the
runtime's PromptGuard pass never redacts the tool result. Hosts with look-alike letters are always
shown in punycode ("xn--pypal-4ve.com").

## 5. Links, files and senders (the other skills' contracts)

`services/scam_check/links.py` is the only module that reads another skill's answers:

- S4 (`LinkChecker.check(urls, purpose="scam_check", network=True, timeout_s=8)`, scaffold A8):
  `dangerous`/`listed` -> malicious; a look-alike or risky signal or level `suspicious` ->
  suspicious; a failed lookup (`settings_unreadable`, `rate_limited`, `cooling_down`, `timeout`,
  `error`, `key_rejected`) -> not checked with the note `links_unavailable`; an `unreadable`
  link -> not checked; otherwise nothing found. `no_key`/`off` add `links_local_only`. No
  checker, an exception or a short answer: every link not checked, never clean.
- S10 (`check_hash(user_id, sha256, size_bytes=..., source="scam", priority="explicit",
  alert="caller")`, scaffold A9): `malicious` -> decisive, `suspicious` -> weak; anything else
  counts neither way, with `file_not_checked` (no service, no key, switched off),
  `file_unknown` (VirusTotal never saw it) or `file_unavailable` (pending, a limit, an error).
  Only a real sha256 is ever sent.
- Senders (the tool's `sender` and `reply_to`): a display name naming a well-known brand
  (`services.security.lookalike.WELL_KNOWN_BRANDS`) as a whole word, glued to a service word
  ("PayPalSupport") or spelt across words ("Pay Pal"), on a domain that is none of the named
  brands' own sites, is `sender_impersonation`. Everyday-word brands (Apple, Delta, Target,
  United, Zoom ...) count only beside service or product words ("Apple ID", "Zoom Meeting");
  Booking and Hotels only when the domain is spelt ("Booking.com"). A brand's own site is its
  domain or its name on .com or a country ending (amazon.co.uk, paypal.de; never paypal.tk).
  Mail another listed platform relays under a chosen name ("Amazon Security" from google.com) is
  still checked. A Reply-To on another site is `reply_to_mismatch`.

S3 never builds a network client, never reads a key and never sends anything itself.

## 6. Data and privacy

- **No table.** A check is two ordinary `messages` rows, which is also how its provider spend
  reaches `/usage`: the web chat's own conversation; the Security tab's per-person "Scam checks"
  conversation (`Conversation.origin = "scam_check"`); the Telegram / Slack thread.
- **The user row holds the checked text fenced** as someone else's words (`fence_message`), the
  person's note outside the fence, and a fact line for pictures and files. A later turn in the
  same thread therefore seeds its taint tracker from the fence: the scam's links and addresses
  stay untrusted. Attachments on the row: picture metadata only (media type, size, sha256) and
  one facts entry `{"kind": "scam_check", "channel", "verdict", "images", "links", "files",
  "cached"}`.
- **The assistant row** holds the rendered verdict and the usage columns.
- **Pictures** live in memory for one check; only their sha256 is kept.
- **Audit rows** (`scam_check_ran` approved, `scam_check_refused` blocked; endpoint
  `<channel>:scam`): verdicts, counts, signal and note codes, the provider and model, picture
  and file sha256s, `usage_input` / `usage_output`. Never the text, the note, a link, a host, a
  file name or a reason (the text is counted; links are counted by level). The in-turn tool
  writes nothing of its own: the runtime's `tool_executed` row keeps the lengths of `text`,
  `sender`, `reply_to` and the number of `urls`.
- Logs carry error type names and counts only.

## 7. Limits and failure policy

| what | behaviour |
| --- | --- |
| switch off / blocked | refuse with `when_denied` or the reason (route 403); nothing runs |
| capability report unreadable | refuse "I couldn't check whether scam checks are turned on ..." (route 503) |
| over 4 a minute or the daily cap | refuse with the sentence (route 429); the in-turn tool is never counted |
| S4 absent, failing or rate limited | links "not checked" with a note; never clean |
| S10 absent or keyless | file not counted, with a note |
| no provider, provider error, 60 s timeout | the automatic checks stand, with a note |
| unreadable AI reply (including one nested too deep to parse) | left out with a note; usage kept |
| PromptGuard error on the AI's reasons | all withheld (fail closed) |
| PromptGuard error on the text | no `ai_injection` sign; the check goes on |
| audit write fails | logged by type; the answer stands |
| any unexpected exception | "⚠️ The scam check hit an unexpected error. Nothing was checked." (refusal reason `error`) |

The quota, the recent answers and the service live on one `ScamCheckService` per process
(`app.state.scam_check`, `scam_check_for`); a restart resets them (they only guard spend; the
real spend shows in `/usage`).

## 8. Routes and the Security tab

- `POST /api/security/scam-check` (any signed-in user): `{text <= 8000, note <= 500, images <= 4
  (base64 or data URLs, the chat's ImageAttachment)}` -> the verdict JSON plus
  `conversation_id`, `usage`, `provider`, `model`. 422 for nothing to check or bad input, 403,
  429, 503 as above. A picture-only check with a blind provider answers 200 "I couldn't check
  this" with the note.
- `GET /api/security/scam-check/status`: `effective`, `reason`, `provider`, `sees_images`,
  `google_list` (null when S4 cannot say), `file_reputation`, `checks_per_day`,
  `checks_used_today`.
- `pages/security/ScamCheckTab.tsx`: every signed-in user; the reason and no form when off or
  blocked; a textarea (8,000), an optional note, up to 4 screenshots (4 MB each, PNG/JPEG/WebP/
  GIF; picker, paste or drop; hidden when the provider cannot see pictures); "Links are checked
  against Crawler's own lists." and, for the owner, "Add a Safe Browsing key"; the result with
  links as code text (never an `<a>`), the AI's reasons as plain text; "n of m checks used
  today".

## 9. Capability and settings

`scam_check` ("Check messages for scams when asked"): on by default, low risk, always available,
claims `security.check_scam` (a READ in the shared `security` family, dispatched by
`SecurityToolkit`; no card). One owner setting, `checks_per_day` (1..10000, default 30), read per
check (a read error falls back to 30). There is no key field: the Safe Browsing / Web Risk key
that makes link checks stronger lives in Security ▸ Service keys (S4).

## 10. Tests

All offline (scripted runtime, S4/S10-shaped fakes, SQLite):

- `test_scam_signals.py`, `test_scam_check_review.py`, `test_scam_check_verdict.py` (pure, in the
  Windows CI list): links and hosts, hidden characters, wording patterns and their 1 MB timing
  bounds, the fence, strict reply parsing, the reason filter (every bypass a checker found has a
  regression case), verdict rules, advice, the three renderers, audit facts.
- `test_scam_check_service.py`: quota and memory, the S4/S10 adapters, sender rules, and the
  whole out-of-turn flow (switch, gate, one tool-less call with the fence and pictures, every
  degrade note, quota, memory, files by hash, audit rows, the in-turn handler, the one service
  per app, a message that tells the checker to add a callback number), plus the channel records.
- `test_scam_check_web.py`: web `/scam` over the blocking route and the stream, with files (out of
  turn, by fingerprint) and another person's file, the saved rows, a later turn treating the
  message as untrusted, and the two routes (200, 422, 403, 503, 429, 401, status).
- `test_scam_check_tool.py`: the capability claim and offer, the executor running it as a READ
  without a card or a model call, the audit row's lengths, the progress line, the report row and
  its setting, `main.py` registering the handler.
- Frontend: `ScamCheckTab.test.tsx` (16) and `scamVerdict.test.ts` (4).
- `test_scam_check_telegram.py` (31) and `test_scam_check_slack.py` (24): every section-7 name
  plus the album take-over, external replies, fingerprints, the unwired service, audit failure,
  unexpected errors, the trigger patterns' worst cases and `register_slack`'s placement.

## 11. Where the build differs from the design (`security10/design/S3.md`) and why

1. S4 and S10 are called through their final contracts (scaffold A8, A9), not the assumed
   `check(urls) -> Mapping` and `lookup(sha256)`; `remote_configured()` replaces
   `sources_available()` / `configured()`.
2. Two more file notes, `file_unknown` and `file_unavailable`: an S10 answer that counts neither
   way is not always "no key".
3. `ai_injection` fires only on PromptGuard detections that address an AI (instruction overrides,
   role hijacks, prompt extraction, hidden HTML/Markdown, delimiter injection, jailbreak words,
   base64 instructions, role-play), not on its style heuristics, which fire on plain phishing
   wording.
4. `credential_ask` ignores a request negated in its own clause ("we will never ask you to
   verify your account") unless the negation follows "if"/"unless"; "confirm the details of your
   booking" and "sign in to continue" do not count. `code_ask` follows the design's pattern but
   leaves out "the code of conduct", "the code for the login page" and plural gift-card "codes"
   (`payment_odd` covers those). Known limit: a negation within one clause up to 40 characters
   before an ask still reads as a warning; the AI review covers it out of turn.
5. The reason filter is stricter than the design's list (section 4) after two checker rounds:
   any letter ending counts as a domain, and the rules read the reason with invisible marks,
   character references and dot look-alikes undone.
6. Audit token counts are stored as `usage_input` / `usage_output`: the audit log redacts the
   whole value of any key whose name contains "token".
7. A refusal reason `error` exists for an unexpected exception inside the check.
8. The Security tab has an optional note field (the design's request carries `note`), and shows
   links as a list rather than a table (a table squeezed the address at phone width).
9. Every `scam_signals` function reads at most 100,000 characters, so S2 can run
   `language_signals` on a whole mail body within the 1 MB timing bound.
10. Telegram: the words after `/scam` in a photo's or document's caption are checked as the
    message's text (fenced), as with `/scam <text>`; only a `/scam` that replies to a message
    treats them as the person's own note. A caption often carries the pasted scam; fencing the
    owner's words is harmless, leaving a scam's words unfenced is not.
11. A document declared as a picture that does not sniff as PNG/JPEG/WebP/GIF is looked up by
    its fingerprint, never passed off as a picture or skipped. At most 4 pictures and 4 files
    per channel check, with "Only the first 4 ... were checked." in the reply. A picture or
    file that is too large (declared, or streamed past its cap) or cannot be fetched refuses
    the whole check (`too_large`, `download_failed`) instead of silently checking the rest.
12. Telegram: a reply to a message from another chat (`external_reply` and its `quote`) is
    checked like a reply and counted as forwarded; album items that arrived before the `/scam`
    caption are taken over from the file intake, and a claimed album swallows its late items
    for 10 s, so no item of it becomes a chat turn.
13. Slack: "stop", "pending" and "new" run before the scam handler (the seam test pins them
    first), so they do not end a bare "scam"'s 2-minute wait; "scam <text>" while waiting
    checks <text>, and a bare "scam" waits again.
14. Channel refusals are audited best effort, and a `/new` (Telegram) or "new" (Slack) is used
    only by a check that was saved; a refused, stopped or unsaved check leaves it for the next
    message. Without a wired service a channel answers "Scam checks aren't set up in this
    process." (web.py's sentence).
15. Reading the AI's reply never raises: a reply nested deeper than the interpreter can parse
    (a `RecursionError`, well inside the 20,000-character cap), or any other error while
    reading it, is an unreadable reply (`ai_unreadable`), so the local checks and link
    reputation stand. A failed audit row is logged as `scam_check_audit_failed` with
    `audit_event` (structlog reserves `event`) and never costs the answer.

## Shared doc text (pasted at integration)

### docs/CODE-MAP.md

Under "### Scam checks when asked (security S3)":

- `backend/services/scam_check/` — the on-demand "is this a scam?" check: `service.py`
  (`ScamCheckService`: switch, quota, local pass, link and file reputation, one tool-less
  `complete_once` review, verdict, audit; `check_for_tool` for `security.check_scam`;
  `scam_check_for` keeps one per process on `app.state.scam_check`), `review.py` (inputs, the
  fenced review prompt, strict reply parsing, the AI-reason filter), `verdict.py` (the fixed
  rules, reasons and advice, `render_plain` / `render_markdown` / `to_json`, audit facts),
  `links.py` (the S4 and S10 adapters, sender look-alike checks), `quota.py` (`ScamQuota`,
  `RecentChecks`), `records.py` (the fenced user row and the verdict row with usage), `web.py`
  (the web chat's `/scam`), `channels.py` (Telegram `message_interceptors` hook and the Slack
  `scam` keyword).
- `backend/services/security/scam_signals.py` — the local half: wording and hidden-character
  signals, link extraction and label/address pairs, punycode display, `clean_ai_reason`. Stdlib
  only, no network, no model.
- `backend/api/routes/security_scam.py` — `POST /api/security/scam-check` and `GET
  /api/security/scam-check/status` (any signed-in user).
- `backend/services/capabilities/scam_check.py` — the `scam_check` switch and its
  `checks_per_day` setting.
- `frontend/src/pages/security/ScamCheckTab.tsx` — Security ▸ Check for scams;
  `scamVerdict.ts` — headlines, labels and the screenshot reader.
- Backend tests: `test_scam_signals.py`, `test_scam_check_review.py`,
  `test_scam_check_verdict.py`, `test_scam_check_service.py`, `test_scam_check_web.py`,
  `test_scam_check_tool.py`, `test_scam_check_telegram.py`, `test_scam_check_slack.py`.

### docs/BACKLOG.md

Under "### Scam checks when asked (security S3)":

**S3 On-demand scam check: done.** `/scam` in a web chat (with screenshots or files), Security ▸
Check for scams, `security.check_scam` in a chat turn, and `/scam` in Telegram and "scam"
in a Slack DM. Local checks always; links through Crawler's own lists and Google's only with the
owner's key; one look by the account's own AI provider out of turn; the answer is never "safe".
Follow-ups:

- Wording patterns in languages other than English (the AI review covers them today).
- A Slack message shortcut ("Check for scams") on any message.
- Per-model vision (Ollama llava) instead of the per-provider flag.
- Offer a check when a forwarded Telegram message arrives.
- Show a `/scam` message's fenced text as a quoted block in the web chat (today the stored row
  shows the fence markup).

### SECURITY.md

Under "### Scam checks when asked":

Crawler can check a message, link, screenshot or QR code for signs of a scam when someone asks
(`/scam` in a web chat, Telegram or Slack, Security ▸ Check for scams, or the
`security.check_scam` tool in a chat turn). The checked message is someone else's words: it is
checked outside the chat turn, sent to the account's own AI provider inside a fence with a fixed
preamble, and stored fenced, so its links and addresses stay untrusted in later turns. Crawler's
fixed rules decide the verdict; the AI can raise it but never lower it, the advice comes from a
fixed table, and the AI's own reasons are dropped when they hold a link, a domain, an address, a
phone number or wording aimed at an AI (a scanner error withholds them all). No answer says
"safe", and no link in an answer is clickable (defanged in Telegram and Slack, code text on the
web, punycode for look-alike letters). Links go to Google Safe Browsing / Web Risk only with the
owner's key; files are looked up by fingerprint only. Pictures are never stored; audit rows hold
verdicts, counts, codes and sha256s, never the text, a link or a host.

### backend/services/capabilities/README.md

Under "### Scam checks when asked (`scam_check`)":

A capability with a tool and channel entry points. `scam_check` claims one exact tool,
`security.check_scam` (a READ in the shared `security` family dispatched by `SecurityToolkit`;
`main.py` registers `ScamCheckService.check_for_tool`). Its out-of-turn entry points (the web
chat's `/scam`, the Security page route, and the Telegram interceptor and Slack keyword) read the
switch per check from `capability_statuses` and fail closed, like the input features. Its one
owner setting is a per-person daily cap, `checks_per_day` (default 30), read per check through
`capability_settings` (a read error falls back to the default). It has no key of its own: the
Safe Browsing / Web Risk key belongs to `link_reputation`.
