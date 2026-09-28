# Weekly app approvals, and approved acts that bring their app forward

Date: 2026-09-25. Status: built on `feat/weekly-app-approvals` (from main `50fcd90`).

## 1. What went wrong

Seen live on Telegram: "what am I doing on the 15th of this month" took six approval
cards and about 129k tokens (13.5k, 15.1k, 14.2k, 16.4k, 15.3k, 8.2k and 46.2k per step)
to read one month view in Calendar. The cards alternated: Switch to Calendar, Click,
Switch to Calendar, Click, Switch to Calendar, Click.

Two causes:

1. **Every card ends the turn.** After each Approve tap the task resumes as a new turn
   that sends the system prompt, the tool schemas, up to 60 rows of the Telegram
   thread and the approved result to the model again (`_resume_after_approval`). Each
   `desktop.act` therefore costs one tap and at least one full-context model call,
   even in an app the owner has already said yes to a dozen times.
2. **The tap took the front.** When the owner taps Approve in Telegram on the same
   computer, Telegram is in front when the approved act runs. The toolkit refuses
   every act unless the app the card was made from is in front (rule
   `frontmost_changed`), and its message tells the model to ask for `focus_window`,
   which needs another card, whose tap takes the front again. Clicks 1 and 2 were
   refused this way; the Telegram progress lines show no model step between the click
   and the next "Switch to Calendar". Reproduced on the fake desktop
   (`tests/test_weekly_app_approvals.py::test_an_approve_tap_in_telegram_on_this_computer_no_longer_refuses_the_act`
   before the fix): cards "Switch to Calendar", "Scroll down in Calendar",
   "Switch to Calendar", and the scroll never ran.

## 2. Approved acts bring their app forward

An approved `desktop.act` that sends input (click, double click, type, key, scroll)
now brings the app its card was made from back to the front first
(`ComputerToolkit._bring_forward`: the backend's `focus_window(app, 0)`), when another
app took it. Every rule then runs as before and is checked again: the front app must
be the card's app, the window is scanned for payment fields, and a password field is
never typed into. The approval named that app, so bringing it forward is what the
owner asked for. It never happens:

- when the app in front is a blocked app other than Crawler's own: the login or
  lock window, an OS security prompt, a terminal, a password manager. The owner
  may be typing a password there, and moving the keyboard away mid-word could
  put the rest of it into the approved app. Those are refused as before;
- when the front app cannot be read;
- for an act nobody approved (every `desktop.act` needs `approved=True`);
- for an act a weekly approval runs (§3): no tap came just before it, so the owner may
  be typing anywhere, a browser's password field included. It is refused
  (`frontmost_changed`) when another app is in front, and the model can ask for
  `focus_window`, which §3.3 guards;
- for `open_app` and `focus_window`, which pick their app themselves.

## 3. Weekly app approvals

### 3.1 What the owner sees

A `desktop.act` card for an app on the weekly list gets a third button:

- Telegram: `✅ Approve` `❌ Deny` on the first row, `📅 Allow Calendar for 7 days` on
  the second, plus the line "Or allow Calendar for 7 days: Crawler then scrolls and
  clicks around in Calendar without a card for requests from this chat; typing, and
  buttons that change or send something, still ask. /apps lists and revokes."
- Web and the desktop app: the same button on the card, for requests from this
  browser.

Pressing it approves this act and allows the app for 7 days. Until then, a
`desktop.act` in that app that only looks around in it (§3.3) runs at once, in the
same turn, with no card, when the request comes from the same Telegram chat (or the
same browser) that allowed it. When
the week is up the next act raises a normal card with the same button again: that is
the weekly renewal. Allowing again renews the week.

Revoking: Telegram `/apps` lists the allowed apps with a Revoke button each; the web
lists them in Settings ▸ Permissions ▸ "Apps allowed for a week". Unlinking Telegram
revokes every approval given from Telegram.

### 3.2 Which apps

Only the apps on `rules.WEEKLY_APPS`: everyday apps whose data stays on the computer
and that have no store (Calendar, Reminders, Notes, Contacts, Stickies, Clock,
Calculator, Weather, Maps, Photos, Preview, Freeform; on Windows also Paint, Sticky
Notes, Microsoft To Do). Matched on the whole app name, exact, never by prefix or a
bundle-id part. Some of these can still send in the owner's name (Calendar answers
and sends invitations; Notes, Photos, Contacts and Preview have share sheets), which
is why an allowed app covers only looking around (§3.3).

Never on it, so every act there keeps its own card:

- browsers: an unattended click could place an order, which breaks the purchases rule
  that no money moves before the owner sees the page on a card;
- mail, messages and chat apps: an unattended click could send something in the
  owner's name;
- file managers, stores (the App Store, and Music, TV, Books and Podcasts, which
  sell), Shortcuts and anything that runs other programs;
- text editors (TextEdit, Notepad): their Save sheet belongs to the app's own window,
  so typing and keys there could write any file, a shell's startup file included;
- the blocked apps (§4 of the computer-control spec), which nothing can approve.

An app is added by adding its spellings to `WEEKLY_APPS`, with a test.

### 3.3 What still applies to an allowed app

- Every toolkit rule (§4 of the computer-control spec): blocked apps and key combos,
  password fields, payment fields, the stop, the front-app check.
- The taint gate: an act whose arguments came from untrusted tool data (a web page, an
  email) gets a card with the risk note, as a standing connector approval does.
- The prompt-guard scan of the arguments.
- Only acts that look around (`app_approvals.weekly_covers`): scrolling, opening or
  switching to the app, navigation keys (arrows, page up/down, home, end, bare or with
  cmd), and a click by ref on an element that only selects or shows something (a
  cell, row, list, table, tab, radio button, text or image, or a button named like
  "Next month", "Today" or "Week"), as `ComputerToolkit.bind` recorded it
  (`_screen.target`). Typing, any other key, a click by coordinates, and a click on
  anything named like a control that changes or sends something (Send, Share,
  Invite, Accept, Decline, Reply, Delete, Save, Export and the like) keep their card.
  Nobody looks at these acts, and a click by ref carries no text the taint gate could
  match.
- No tap comes before an act a weekly approval runs, so it never brings its app
  forward (§2), and `open_app` / `focus_window` are refused (`owner_busy`) while the
  front app is a blocked app other than Crawler's own, or its focused element is a
  password field or cannot be read.
- Only `desktop.act` is covered, and only in the allowed app. The target app is the
  `app` argument for `open_app` and `focus_window`, and the app of the screen the call
  is bound to (`_screen.app`, from `ComputerToolkit.bind`) for everything else. When
  the latest outline shows another app, the act gets a card.
- The act runs with the same bound arguments a card would store, so the toolkit holds
  it to that screen exactly as it holds an approved card.

### 3.4 Tied to the chat or the device

A turn carries the channel it came from (`app_approvals.Channel`):

- Telegram: `Channel("telegram", <chat id>)`. The bot serves only the linked private
  chat (`from.id == chat.id`), and the appliers drop the channel unless it is the
  user's linked chat, so an approval never applies after Telegram is re-linked to
  another chat.
- Web and the desktop app: `Channel("web", sha256(<device id>))`. The device id is a
  random id the web app keeps in `localStorage` and sends as `X-Crawler-Device` on
  every request. Only its hash is stored.
- No channel (automations, a missing header): no weekly approval applies; cards as
  before.

An approval matches only the channel kind and key it was given from. Telegram
approvals never apply to web turns, and the reverse.

### 3.5 Records and audit

Table `app_approvals` (migration `0015_app_approvals`): id, user_id, tool, app_key
(squashed), app_name, channel_kind, channel_key, granted_at, expires_at, revoked_at,
last_used_at, uses, source_action_id. At most one live row per (user, tool, app_key,
channel): allowing again renews it.

Audit events: `app_approval_granted` (app, channel kind, expiry, the card's action id),
`app_approval_revoked` (from the web, `/apps`, or unlinking Telegram, with the count),
and on every act run under one, the usual `tool_executing` and result rows carry
`approval: "weekly"`, `app_approval_id`, `app`, `channel` and `expires_at`.

## 4. API contract

- `PendingApprovalOut.weekly_app: str | null`, and the same key in the SSE
  `pending_approval` event: the app the card can be allowed for a week.
- `POST /api/agent/approvals/{action_id}` body `{approved: bool, remember?: "week"}`.
  `remember` with no usable device header approves once. Response adds
  `weekly: {app, expires_at} | null`.
- `GET /api/agent/app-approvals` → `[{id, app, channel: "telegram" | "web",
  this_device: bool, granted_at, expires_at, last_used_at}]`.
- `DELETE /api/agent/app-approvals/{id}` → 204; 404 when not the caller's or not live.
- Every web request sends `X-Crawler-Device` (CORS allows it).

## 5. What this does not change

- `_BUILTIN_STANCE["desktop"]` stays `user_confirm`: no account setting auto-approves
  `desktop.act`. A weekly approval is the owner's own consent for one app, from one
  chat or device, for 7 days.
- `browser.act`, `browser.checkout` and every connector write keep their cards.
