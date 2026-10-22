# Secret and personal-data protection

One detector, one policy table, every sink (backlog F6). The security wave
(security10) adds the call checks every tool call passes and the free checks
on links, mail and outgoing messages (the rows from `lookalike.py` down).

| Module | What it does |
| --- | --- |
| `secrets.py` | `RULES`, the one format table, and `find(text, *, kinds, min_confidence)`. A `Finding` holds the rule, kind, label, offsets and confidence, never the value. |
| `policies.py` | What each sink does with a finding: `MEMORY` refuses, `AUDIT` and `LOGS` mask with `***REDACTED***`, `CHANNEL` masks as `[hidden: <label>]`, `TOOL_ARGS` refuses, `MODEL_FLOOR` (and `INDEX`) mask as `[hidden by Crawler: <label>]`, `MODEL_PERSONAL` pseudonymises contact details. |
| `redact.py` | `contains`, `first_finding`, `redact_text`, `redact_obj`, `argument_findings`, the structlog processor and the stdlib `SecretLogFilter`. Each fails closed. |
| `pseudonyms.py` | The per-turn `PseudonymVault`: `[[EMAIL_1@uni.edu]]`, `[[PHONE_1]]`, `[[ADDRESS_1]]`, `[[DOB_1]]`. |
| `egress.py` | `ModelEgress`, applied at `AgentRuntime._provider_complete`, the one model call; `current_egress`; `is_local_provider`; `redact_for_model`; `redact_for_embedding`. |
| `guard.py` | The per-call secret guard the runtime runs for every tool call, and the turn's `sensitive_data_hidden` audit row. |
| `channels.py` | Telegram and Slack masking, the footer and the inbound warning. |
| `lookalike.py` | Look-alike host facts shared by checkout, mail, outgoing-message and link checks: punycode and mixed-script letters, typo and homograph domains of well-known brands, a brand used as a label of another site, registrable domains, bare IP literals, the host a browser really opens (`browser_host`, `ascii_host`, `fold_host`: UTS 46, letters mapped per code point as a current browser maps them, the characters a browser drops dropped, joiners kept where a browser keeps them, linear in the input), `WELL_KNOWN_BRANDS` and `CONSUMER_MAIL_DOMAINS` (security wave, owned by S4). |
| `link_checks.py` | Free link checks with no network (look-alike letters, bare IPs, credentials before an "@", shorteners, link text naming another site), what may be sent to a lookup service, and the `LinkChecker` protocol S1, S2 and S3 take (S4). |
| `call_checks.py` | The pre-dispatch call checks: one ordered pipeline (tool rules, MCP pins, site rules, outbound, file reputation) run per call in the turn, again at approval and as the executor's fail-closed backstop; `CallFacts` in, `Allow`/`Note`/`Escalate`/`Refuse` out, and the typed `SecurityNote` a card shows. |
| `outbound.py` | Which fields of a write are outbound, the hidden-character floor the executor applies to every write (`OutboundFloor`), `OutboundService` (the floor plus audit and recording after a send) and the check on an outgoing message's recipients and links (`OutboundCheck`) (S1). |
| `outbound_store.py` | Who Crawler has sent to (keyed HMACs only), the owner's organisation domains, a user's sign-in address and `OrgDomains.for_user` for the tool rules (S1). |
| `outbound_text.py` | Outgoing text: hidden-character cleaning and counting, links found in Markdown, HTML, Slack and bare text, and the signs a message carries data out (remote images, encoded values) (S1). |
| `outbound_recipients.py` | Who an outgoing message goes to: recipients parsed and normalised, the HMAC, organisation classification, look-alike and unusual-character checks, organisation-domain validation (S1). |
| `mail_facts.py` | The provider-neutral `MailSecurityFacts` of one email (sender authentication, addresses, links, attachments) and the parsers the Gmail and Outlook `get_message_security` READs answer with (S2). |
| `mail_checks.py` | The free checks on those facts that decide which new emails get an AI review: forged or look-alike senders, reply-to mismatches, links that hide where they go, risky attachments (S2). |
| `scam_signals.py` | The local half of the on-demand scam check: wording and hidden-character signals, link extraction and label/address pairs, punycode display; no network, no model (S3). |
| `tool_rules/` | Rules on tool arguments: the grammar and values, the built-in rules, the engine, the store of the owner's rules and the call check that turns a call breaking one into a card naming the rule (S9). |

The detector modules (`secrets`, `policies`, `redact`, `pseudonyms`, `egress`,
`guard`, `channels`, `lookalike`, `call_checks`, `mail_facts`, `mail_checks`,
`scam_signals`, `outbound_text`) are stdlib-only and local.
`outbound_recipients` is local and makes no network call; it also reads
`core.config.settings.ENCRYPTION_KEY` (lazily, for the HMAC key) and
`lookalike`. `tool_rules/{grammar,engine,values,builtins}` are local (no
network): they import `prompt_guard`, `permissions` and `redact`, and
`tool_registry` lazily.
`outbound_store`, `outbound` and `tool_rules/{store,check,context}` hold
injected stores and collaborators. They make no network call themselves;
anything remote goes through the executor or S4's `LinkChecker`. Logs and
audit rows carry labels, counts and exception type names only.

## Adding a format

1. Add one `Rule` row to `RULES` in `secrets.py`: an id, a kind, a label the
   person can read ("GitLab token"), a pattern, a confidence, and when only
   part of the match is the secret, its `group`; a `check` when a pattern
   alone would match too much (Luhn, mod-97, entropy).
2. Add one positive and one negative row to `tests/test_security_secrets.py`
   (the `POSITIVES` and `NEGATIVES` tables), built from obvious fake filler.

Keep every quantifier bounded, and when the body can run long, start the
match only where the body cannot already be running (a lookbehind over the
body's own characters, as the existing rows do): the adversarial test runs
1 MB of each rule's worst case and fails when it takes more than 32 times
as long as an eighth of the same text (linear is 8).

A new sink uses an existing policy, or adds one to `policies.py` with a
table row in `tests/test_security_policies.py`.

## Confidence

- `HINT`: a loose stated form ("PIN: 4821", "passcode = x"): memory only.
- `LOW`: the audit log's and memory's broad card rules (any 13-19 digit run,
  grouped digits without a checksum).
- `MEDIUM` / `HIGH`: what channels, tool arguments and the model act on. A
  card needs the Luhn check and an issuer prefix here, so order numbers,
  chat ids and millisecond timestamps stay readable.
- At every level, a card or stated bank-account number is never found inside
  a longer identifier: a digit run glued to a letter or digit (a commit sha,
  a hex digest) or inside a UUID is an id, not a secret.
