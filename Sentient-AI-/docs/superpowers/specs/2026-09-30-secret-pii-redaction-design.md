# Keys, card and ID numbers never leave; contact details only as placeholders

Date: 2026-09-30. Status: built as the top-10 skill `secret_pii_redaction`
(backlog F6, wave 1). No dependency, table, migration, model-facing tool or
frontend change.

## 1. Why

Before this, only `memory.remember` refused secrets (its own `_SECRET_RE`), the
audit log redacted a partly different list (`_SENSITIVE_VALUE_PATTERNS`), and
nothing stopped a key, a card number or an ID number from reaching the AI
provider, a Telegram or Slack message, or a tool call's arguments. Nothing
hid a user's contact details from a cloud model either.

## 2. One detector, one table, named policies

`backend/services/security/` (stdlib only):

- `secrets.py`: `RULES`, the one format table, and
  `find(text, *, kinds, min_confidence)`. A `Finding` carries the rule, kind,
  label, offsets and confidence, never the value. Kinds: credential,
  payment_card, bank_account, government_id, email, phone, street_address,
  birth_date. Confidence: HINT < LOW < MEDIUM < HIGH.
- The table holds every format `audit.py` and `memory.py` knew (with the same
  minimum body lengths), plus provider keys (`sk-ant-`, `sk-proj-`, `sk-`,
  `AIza`, `gsk_`, `xai-`), Telegram bot and Canvas tokens, PEM private keys,
  pre-signed link signatures, passwords in links, authorization headers,
  `KEY=value` assignments with a random-looking value (Shannon entropy 3.5+
  bits per character, 20+ characters, which catches Mistral keys), stated
  passwords, PINs and card codes, payment cards (Luhn plus issuer prefix),
  IBANs (mod-97), stated bank account numbers, US SSNs and ITINs (area rules),
  stated passport and driver's licence numbers, emails, NANP and E.164 phones,
  US street lines and birth dates after DOB or "born".
- Every quantifier is bounded and every long body starts only where it cannot
  already be running, so 1 MB of any rule's worst case scans in well under 2
  seconds; input over 2,000,000 characters raises `ScanTooLarge`, which every
  policy treats as a detector failure.
- `policies.py`: MEMORY (refuse, from HINT), AUDIT and LOGS (mask with
  `***REDACTED***` from LOW, plus their key-name rules), CHANNEL (mask as
  `[hidden: <label>]` from MEDIUM), TOOL_ARGS (refuse from MEDIUM),
  MODEL_FLOOR and INDEX (mask as `[hidden by Crawler: <label>]` from MEDIUM),
  MODEL_PERSONAL (pseudonymise contact details).
- The deliberate card split: the audit log and memory keep the broad "any
  13-19 digit run" rule (LOW), so nothing they redacted or refused before gets
  through. Channels, tool arguments and the model need Luhn plus an issuer
  prefix (MEDIUM), so order numbers, chat ids and timestamps stay readable.
- `redact.py`: `contains`, `first_finding`, `redact_text`, `redact_obj`,
  `argument_findings`, `mask_arguments`, the structlog processor
  `redact_log_event` and the stdlib `SecretLogFilter`. A detector error counts
  as a hit for a refusal and withholds the whole text for a mask.

## 3. Every sink

| Sink | What happens |
| --- | --- |
| Memory (`memory.remember` and `POST`/`PATCH /api/memories`) | Refused: `screen_memory_content` raises `MemorySecretRejected`, so the REST route answers 422 and the tool its `secret` rule. Contact details are allowed. |
| Audit rows | `_sanitize` is `redact_obj(data, AUDIT)`; `contains_sensitive_value` stays as a wrapper. |
| Logs | `redact_log_event` runs after `format_exc_info`; `SecretLogFilter` sits on uvicorn.access, uvicorn.error, httpx, httpcore and root (loggers and their handlers). |
| Telegram | `_api` masks sendMessage and editMessageText; `_send_photo` masks the caption; `_send_reply` masks the whole reply before splitting and adds one footer; `send_text` masks before cutting. |
| Slack | `_post` masks the text and every plain_text block; `_send_reply` masks before splitting with the footer; `send_text` masks before cutting. |
| Approval cards on channels | `cards.layout_card` renders `redact_obj(arguments, CHANNEL)`; the digest still hashes the real arguments, so it matches the web card. |
| Tool arguments | Every call, reads, web.*, MCP and tools.find included, after the prompt-guard argument scan and before the weekly-app branch and any card: a key, card, bank or ID number is refused (`secret_guard` / `credential_in_arguments`), filed like a rule refusal. `approve_action` checks the stored arguments again before `tool_approved`. |
| The model | `AgentRuntime._provider_complete` passes the turn's `ModelEgress`: the floor always, placeholders for contact details when the switch is on and the provider is not a local Ollama. |
| Connector errors | A vendor code that looks like a credential is dropped (`looks_like_credential`); the exact-value scrub stays. |

Contact details are never masked on channels or in the audit log: it is the
owner's own chat and log.

## 4. The model request

- `ModelEgress.outbound(messages)` copies the messages and scans only text
  parts (images and audio pass through), once per text per turn.
- With "Hide personal details from the AI provider" on and a cloud provider
  (anything but Ollama on loopback, `*.localhost` or `host.docker.internal`;
  an Ollama on a LAN host counts as cloud), contact details become
  `[[EMAIL_1@uni.edu]]`, `[[PHONE_1]]`, `[[ADDRESS_1]]`, `[[DOB_1]]` from a
  per-turn vault held only in memory (at most 500 values; beyond that masked
  irreversibly). Placeholder-shaped text already in content is neutralised
  first.
- `inbound(response)` restores the reply and every tool call's arguments
  before permission, taint, cards and execution; a placeholder the turn never
  minted is refused (`unknown_placeholder`, the call's own error).
- The system prompt gains a `<privacy>` block only while hiding; otherwise it
  is byte-identical to before (apart from the new `<permissions>` line).
- One `sensitive_data_hidden` audit row per turn, only when values new this
  turn were hidden: labels, counts and the provider.
- `redact_for_embedding(text, cloud=..., hide_personal=...)` is the rule for
  the knowledge base: the floor always, and `[email]`/`[phone]`/`[address]`/
  `[birth date]` for a cloud endpoint while the switch is on.

## 5. The switch

`hide_personal_details` ("Hide personal details from the AI provider"),
`tools=()`, on by default (owner decision), risk low, always available. main.py
wires it into the runtime as `"hide_personal_details" in
installation.enabled_keys()`; a gate error counts as hide.

## 6. Deviations from the plan

- The turn's `ModelEgress` is bound in `chat()` around `_run_turn`
  (`async with self._lease(...) as provider, bind_egress(...)`), so it is
  reset whether the turn returns or raises; `turn_start` reads it.
- `ModelEgress.inbound` returns the restored response; unknown placeholders
  are read with `unknown_placeholders(tool_call_id)`.
- main.py wires the switch with `AgentRuntime.use_personal_details_gate`
  under its anchor; the constructor keyword `personal_details_hidden` is the
  same hook.

## 7. Not in v1

Names (needs a named-entity model), OCR inside images, non-US ID formats,
restoring a credential into a tool call on the host it came from, deleting an
inbound Telegram message that holds a key.
