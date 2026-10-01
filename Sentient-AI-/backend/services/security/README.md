# Secret and personal-data protection

One detector, one policy table, every sink (backlog F6).

| Module | What it does |
| --- | --- |
| `secrets.py` | `RULES`, the one format table, and `find(text, *, kinds, min_confidence)`. A `Finding` holds the rule, kind, label, offsets and confidence, never the value. |
| `policies.py` | What each sink does with a finding: `MEMORY` refuses, `AUDIT` and `LOGS` mask with `***REDACTED***`, `CHANNEL` masks as `[hidden: <label>]`, `TOOL_ARGS` refuses, `MODEL_FLOOR` (and `INDEX`) mask as `[hidden by Crawler: <label>]`, `MODEL_PERSONAL` pseudonymises contact details. |
| `redact.py` | `contains`, `first_finding`, `redact_text`, `redact_obj`, `argument_findings`, the structlog processor and the stdlib `SecretLogFilter`. Each fails closed. |
| `pseudonyms.py` | The per-turn `PseudonymVault`: `[[EMAIL_1@uni.edu]]`, `[[PHONE_1]]`, `[[ADDRESS_1]]`, `[[DOB_1]]`. |
| `egress.py` | `ModelEgress`, applied at `AgentRuntime._provider_complete`, the one model call; `current_egress`; `is_local_provider`; `redact_for_model`; `redact_for_embedding`. |
| `guard.py` | The per-call secret guard the runtime runs for every tool call, and the turn's `sensitive_data_hidden` audit row. |
| `channels.py` | Telegram and Slack masking, the footer and the inbound warning. |

Everything here is local: no network, no model, no package beyond the
standard library (plus structlog for the two modules that log counts). Logs
and audit rows carry labels, counts and exception type names only.

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
1 MB of each rule's worst case and must finish in under 2 seconds.

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
