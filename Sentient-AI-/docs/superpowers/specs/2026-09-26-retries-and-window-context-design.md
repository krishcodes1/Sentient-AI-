# Fewer "send continue" stops, and a better view of the window

Date: 2026-09-26. Status: built on `feat/retries-and-window-context` (stacked on
`feat/weekly-app-approvals`).

## 1. Why

The owner asked why Crawler "says to continue after an update" and why it does
not understand the window it is working in. A read of the code found:

- Gemini is called over plain HTTP with no retries. The SDK providers (Anthropic,
  OpenAI and the OpenAI-compatible ones) retry twice on their own. One Gemini
  rate limit, server error, dropped connection or blank completion ended the
  task. After an Approve tap that became "Send 'continue' to try again".
- The model sees only the focused window's accessibility outline. It is read
  8-150 ms after an act, so a sheet that slides in a moment later ("What's
  New… Continue") is missed. A sheet at the end of a long window can be cut by
  the 6,000-character cap. A leftover popover can hide the window the model
  wants, and nothing says another window exists. On macOS the menu bar is
  outside the window, so the model never sees the menus.

## 2. Retries

- **Gemini** (`GeminiProvider.complete`) asks again after a pause, at most
  twice (`_MAX_RETRIES`, as the SDK providers):
  - It retries 408, 429 and 5xx answers, a dropped connection, "no candidates"
    without a block reason, and a blank completion whose finishReason is STOP,
    OTHER, MALFORMED_FUNCTION_CALL or UNEXPECTED_TOOL_CALL.
  - It does not retry a bad key or model (400, 401, 403, 404), a blocked
    prompt, or SAFETY and RECITATION stops: those would repeat.
  - The pause is 1 s, then 2 s. On a 429 it uses the wait Google asks for (a
    Retry-After header or a RetryInfo `retryDelay`), capped at 8 s so a task
    never stalls for a quota window.
  - `ProviderError` carries `retryable` and `retry_after`.
- **The turn resumed after an approval** (`_apply_decision`) runs once more,
  after 2 s, when it failed on a provider hiccup before it ran a tool or was
  billed a token. Nothing happened, so nothing is repeated. A turn that ran a
  tool or was billed is never re-run: its calls and cost are recorded, and the
  chat is told in plain words, as before.

## 3. The window

All in `ComputerToolkit` unless noted, the same on macOS and Windows.

- **Settle before reading.** After an act the front window is read until two
  reads in a row match (the role, name and hidden flag of the first 400
  nodes), polling every 0.2 s for at most 1.5 s and 6 reads. After `open_app`
  or `focus_window` it also waits until that app is in front with a window,
  for at most 3 s, and never settles sooner than 0.8 s: an app's first sheet
  often arrives a moment after its window.
  - The last read becomes the act's `then` outline, so it costs no extra read.
  - It never raises, since the act has already happened.
  - It never reads a password manager's window.
- **Sheets, dialogs and popovers first.** A `sheet`, `dialog`, `alert`,
  `popover` or inner window in the window moves to the front of its children,
  so the cap never cuts it off. The result names it in `modal` and says to deal
  with it first in `note`.
  - A dialog window is labelled `dialog`: the macOS AXDialog and AXSystemDialog
    subroles, and the standard Win32 dialog class `#32770` on Windows.
- **Other windows.** When the app has more than one window, `windows` lists
  them (title and index, at most 8) and `note` says `focus_window(app, index)`
  switches.
  - `ComputerBackend.list_windows(app)` now takes an optional app.
- **Menus (macOS).** `ComputerBackend.menu_bar(app)` adds the app's menus:
  - One `menu bar item` line per menu. The Apple menu, always the first, is
    never listed: its Restart, Shut Down, Log Out, Lock Screen and Force Quit
    are not Crawler's.
  - The open menu lists its items; separators are left out.
  - Clicking a menu's ref opens it, and clicking an item's ref chooses it
    (AXPress).
  - While a menu is open it comes first, with a note.
  - On Windows a classic menu bar is already part of the window's own tree, so
    `menu_bar` adds nothing.

Every existing rule still applies:

- The front-app check.
- The payment scan, which reads the window only.
- Password fields.
- Blocked apps: their menus are acts in a blocked app, and are refused.
- Approval cards and weekly approvals.

Menus cost about 60 tokens per outline. The settle wait adds no tokens.

## 4. Verified

- Unit tests:
  - `tests/test_gemini_retries.py`, `tests/test_resume_retry.py` and
    `tests/test_computer_window_context.py`.
  - Window listing and dialog labels in `tests/test_computer_backend_mac.py`
    and `tests/test_computer_backend_windows.py`.
  - A suite-wide fixture skips the real pauses.
- Real Mac (macOS, Accessibility granted), before the screen locked:
  - Calendar's menu bar read in about 0.25 s: Apple, Calendar, File, Edit,
    View, Window, Help.
  - AXPress on "View" opened it: `AXSelected` true, items By Day, By Week, By
    Month, By Year, then Next and Previous, with a separator between.
  - AXCancel closed it.
