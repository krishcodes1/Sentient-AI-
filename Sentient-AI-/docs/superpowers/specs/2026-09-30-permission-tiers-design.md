# Permission tiers: risk grades, "Allow low-risk changes" and 7-day grants

Status: shipped (top10 `permission_tiers`, research item 128, backlog F4). Migration
`0023_permission_grants`.

## Why

Every change to a connected account asked for its own approval card, and the only way out was
`auto_approve`, which ran everything but always-confirm actions, including invitations, moves to
Trash and workflow re-runs. Owners want small, undoable changes (a star, a label, a draft, a
private event, a to-do) to just happen on the accounts they choose, while sends, deletes, sharing
and anything other people see keep asking.

## Risk grades (`backend/services/agent/risk.py`)

Computed only in code, from the action's `ToolSpec` and the arguments actually sent. The model
never grades anything, and no reason quotes an argument value.

- READ is LOW. DELETE, EXECUTE, FINANCIAL and `always_confirm` actions are HIGH. A WRITE is MEDIUM
  unless its spec declares `risk="low"`.
- `risk_check` reads the arguments and can only escalate; one that raises grades HIGH.
- An argument the schema does not list, or one of the wrong type or outside its enum, is MEDIUM.
- Built-in, MCP and unknown tools are HIGH: only a registry connector's action is ever eligible.
- Registry validation refuses `risk="low"` on anything but a WRITE without `always_confirm`, and
  requires a `low_risk_note` (at most 80 characters) and `ref_args` that are schema properties.

The v1 LOW set (pinned by `tests/test_risk_grading.py`): Gmail `create_draft` and
`modify_labels` (STARRED, IMPORTANT and the owner's `Label_*` only; INBOX and UNREAD are MEDIUM,
CATEGORY_ labels MEDIUM, TRASH and SPAM HIGH); Outlook `create_draft` and `flag_message`
(`move_message` is MEDIUM, HIGH to Deleted Items or Junk); Google and Outlook calendar
`create_event` without attendees and with the checked fields only (attendees are HIGH; Google
`update_event` with attendees is HIGH); Drive and OneDrive `create_folder` and `upload_file` at
the top of the drive (a parent folder or an overwrite is MEDIUM); Docs `create_document`;
Contacts `create_contact`; To Do `create_task` and `complete_task`; GitHub
`mark_notification_read`. A public gist or repository is HIGH.

`canvas.submit_assignment`, both `respond_to_invite` actions and `slack.invite_to_channel` became
`always_confirm`: they speak for the user (connectors spec §4.4's own criteria).

## Tiers and grants

- `PermissionTier.low_risk` ("Allow low-risk changes") sits between `auto_approve` and
  `user_confirm`; the stricter of a connection's tier and the account default still wins.
- A 7-day grant (`permission_grants`, per user and connection, not per channel) is offered on an
  untainted, attended card for a LOW action with no origin while the owner's switch is on. It is
  re-checked when the button is pressed (still LOW, the row is the user's, active, not admin_only
  or hard_blocked), audited (`permission_grant_granted`; taken back if that row cannot be
  written), renewed by allowing again, revoked from Settings, Telegram `/grants` or Slack `revoke
  grants`, revoked when credentials are replaced, the connection is reconnected or a scope is
  added, and deleted with the connection or the user.
- The owner switch `low_risk_actions` ("Make low-risk changes without asking") is on by default:
  it loosens nothing by itself.

## Per call, in the runtime's canonical gate order

After the permission check and the unattended rule (`call_post_permission`):

- Unattended turns use no standing consent; neither does a turn in which PromptGuard flagged a
  tool result (the tripwire).
- `auto_approve` runs the call unless it grades HIGH (then a card with a plain risk note).
- The `low_risk` tier or a live grant runs the call only when it grades LOW, the switch is on and
  fewer than `LOW_RISK_MAX_PER_TURN` (10) such runs happened this turn.

Then the taint gate (`call_taint`): a LOW call's `ref_args` are exempt only for ids the same
connection returned this turn in `id` / `*_id` fields (`TaintTracker.add_result(source=)`). The
secret guard and every later gate apply unchanged. The executor re-grades what it sends and
re-checks the tier, the grant and the switch (`execute(approval=...)`) before any rate-limit slot
or request; without a grants store it refuses low-risk runs. The reply ends with "Done without
asking (low-risk changes you allowed): 3 × google_workspace.modify_labels on School Gmail.",
built from facts only.

Audit: runs carry `approval` (`tier` | `low_risk` | `low_risk_grant`), `risk`, `risk_reason` and
`grant_id`; events `permission_grant_granted`, `permission_grant_revoked`,
`connector_tier_changed`, `account_tier_changed`.

## Surfaces

- Web: `LowRiskGrantButton` on Chat and Dashboard cards, Settings ▸ Permissions ▸ "Accounts
  allowed low-risk changes", the tier option on the Connectors page with its notes and a "Capped
  by your account setting" line, corrected tier help texts.
- Telegram: the `apl:` row "⚡ Allow low-risk on <account> · 7 days", the card line, `/grants`
  with `rvg:` Revoke buttons. Slack: a third button, `grants` and `revoke grants`.
- API: `GET` / `DELETE /api/agent/permission-grants`, `remember: "low_risk"` on the approvals
  route, `low_risk_account` on pending approvals and the SSE event, `low_risk` on the decision.

## Deferred

The cap and the grant length are constants; the tripwire does not suspend weekly desktop app
approvals; the account export does not list grants; F1's panic button should revoke grants too.
