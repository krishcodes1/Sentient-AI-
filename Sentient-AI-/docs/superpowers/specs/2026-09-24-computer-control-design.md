# `computer_control` — the agent sees and operates the computer

**Date:** 2026-09-24 · **Status:** approved direction (owner: "Both", build tonight; test on a throwaway headless Mac)

## 1. Goal and limits

Let the agent use any app on the Mac or Windows PC the way a person does — look at what is on screen, click, type, press keys, scroll, open apps — so tasks that have no website and no API can still be done. It is the most dangerous capability Crawler has, so it is **off by default, native only, every action approved** in v1, and it can be stopped instantly.

v1 is text-first (accessibility tree with refs, like the browser outline); screenshots are a fallback. Not in v1: "take control for N minutes" sessions (per-action approval only), OCR, drag-and-drop, file dialogs by path, multi-monitor coordinate mapping beyond the main display.

## 2. Capability

`services/capabilities/computer_control.py` — key `computer_control`, label "Control this computer", tools `("desktop.observe", "desktop.act")`, `default_enabled=False`, `risk="high"`.
- **Availability:** native only (not in a container, not Linux in v1); the platform backend imports (pyobjc on Mac, comtypes/uiautomation on Windows).
- **Probe (Mac):** Accessibility permission (`AXIsProcessTrustedWithOptions`, no prompt) — denied → blocked with the fix URL `x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility` and steps naming the binary that needs the grant; `request_access` prompts (`kAXTrustedCheckOptionPrompt`) and opens the pane. Screen capture uses the existing `screen` capability's probe. **Windows:** `not_required`; the UIPI limit (cannot act on elevated windows) is reported in `desktop.observe`.
- `desktop.screenshot` stays under the `screen` capability.

## 3. Tools

Both tools use the same backend and return untrusted content (fenced, PromptGuard-scanned, tainted) like every tool result.

**`desktop.observe`** — READ (runs without approval when the capability is on):
```
{action: "outline"|"apps"|"windows", app?: str, max_chars?: int≤12000, for_model_image?: bool}
→ {ok, frontmost_app, window_title, outline: [lines], refs, truncated, secure_fields_redacted: int,
   apps?: [{name, pid, active}], windows?: [{app, title, index}], image?: data-url(≤1280px, only if for_model_image)}
```
Outline lines mirror the browser format: `- button "Send" [ref=d12]`, `- text field "Subject" [ref=d7] value="…"`; refs are valid until the next `observe` (a per-user ref map stored in the toolkit). Values of secure/password fields are never read (`[redacted]`); off-screen and hidden elements are dropped; depth and size capped.

**`desktop.act`** — WRITE (approval card for every call in v1):
```
{action: "click"|"double_click"|"type"|"key"|"scroll"|"open_app"|"focus_window",
 ref?: str, x?: int, y?: int, text?: str (≤2000), keys?: str ("cmd+s"), direction?: "up"|"down", app?: str, index?: int}
→ {ok, did: "click button \"Send\" in Mail", then: <fresh outline of the frontmost window>}
```
Coordinates only when no ref exists (screenshot fallback); refs are preferred. `type` goes to the focused element or the given ref.

## 4. Hard rules (enforced in the toolkit, before the backend is called)

- **Never type into a secure/password field** (Mac `AXSecureTextField` subrole; Windows UIA `IsPassword`). Refuse and suggest the owner does it.
- **Blocked apps** (refuse any `act` whose target app is one of these): Keychain Access, Passwords, 1Password, Bitwarden, LastPass, Dashlane, System Settings / System Preferences, Terminal, iTerm2, Warp, PowerShell, Windows Terminal, Command Prompt, Registry Editor, Task Manager, the login/lock window, and Crawler AI itself. (A later `shell` capability is the only path to commands.)
- **Blocked key combos:** logout/lock/shutdown/restart combos, `cmd+option+esc`/`ctrl+alt+del`, `cmd+q` on Finder, anything with the Globe/Fn key; `key` accepts only a small grammar (modifiers + one key).
- **Financial:** refuse when the frontmost window's outline contains payment fields (card number / CVC / IBAN patterns) — same rule as the browser.
- **Kill switch:** `/stop` (Telegram) and the web Stop button cancel the turn; the toolkit checks a per-user cancel flag before every action.
- Every `act` is audited (existing intent row + result), including refusals.

## 5. Platform backends

A `ComputerBackend` protocol in `services/tools/computer/backend.py`:
```python
class ComputerBackend(Protocol):
    name: str
    def available(self) -> tuple[bool, str]
    def permission(self) -> Literal["granted","denied","not_required","unknown"]
    def request_permission(self) -> None
    def list_apps(self) -> list[AppInfo]
    def list_windows(self) -> list[WindowInfo]
    def frontmost(self) -> tuple[str, str]                       # app, window title
    def outline(self, app: str | None, max_nodes: int) -> list[Node]   # Node: role, name, value, secure, bounds, children-depth, handle
    def click(self, node_or_point, *, double: bool = False) -> None
    def type_text(self, text: str, target: Node | None) -> None
    def key(self, combo: KeyCombo) -> None
    def scroll(self, direction: str, amount: int) -> None
    def open_app(self, name: str) -> None
    def focus_window(self, app: str, index: int) -> None
```
- **Mac** (`backend_mac.py`): pyobjc — `ApplicationServices` (AXUIElement tree: `AXRole`, `AXSubrole`, `AXTitle`/`AXDescription`/`AXValue`, `AXPosition`/`AXSize`, `AXPress` action when available, else a CGEvent click at the element centre), `Quartz` (`CGEventCreateMouseEvent`, `CGEventCreateKeyboardEvent` + `CGEventKeyboardSetUnicodeString` for text, `CGEventCreateScrollWheelEvent`), `AppKit.NSWorkspace` (running apps, `launchApplication`/`openApplicationAtURL`, `activateWithOptions`). Dependencies with markers: `pyobjc-framework-ApplicationServices; sys_platform == "darwin"`, `pyobjc-framework-Quartz; sys_platform == "darwin"`, `pyobjc-framework-Cocoa; sys_platform == "darwin"`.
- **Windows** (`backend_windows.py`): `uiautomation` (UIA tree: ControlType, Name, Value pattern, `IsPassword`, BoundingRectangle; `InvokePattern` for clicks when available) + ctypes `SendInput` for mouse/keyboard/unicode text + `ShellExecuteW`/`os.startfile` for open_app; UIPI: detect elevated target (`GetTokenInformation` on the window's process) and refuse with an explanation. Dependency: `uiautomation; sys_platform == "win32"`.
- **Fake** (`backend_fake.py`): an in-memory desktop (apps, windows, a node tree, an event log) used by every unit test. **Tests never use a real backend** — no real clicks, keys or screen reads on the development machine.
- **Selection:** `select_backend(platform_name)` — `"mac"` → Mac, `"windows"` → Windows, anything else → unavailable. The platform name comes from `services.platform.current().name` at wiring time (the only OS branch lives there).

## 6. Wiring

Built-in family `desktop` already exists (screenshot). Add `ToolSpec("observe", READ)` and `ToolSpec("act", WRITE)` to its catalog entry; policy rows: `("desktop", WRITE) = USER_CONFIRM` (currently HARD_BLOCKED — change deliberately, with a test), keep DELETE/EXECUTE/FINANCIAL hard-blocked. `_BUILTIN_STANCE["desktop"] = "user_confirm"` stays, so no account setting auto-approves `act`. The `computer_control` capability claims `desktop.observe` and `desktop.act`; `screen` keeps `desktop.screenshot`. The executor's `desktop` `_Builtin` entry routes `screenshot` to the existing toolkit and `observe`/`act` to the new `ComputerToolkit` (constructed with the selected backend in `wire_services`).

Approval card text is built from facts, not the model's words: `Click "Send" in Mail`, `Type 42 characters into "Subject" in Mail`, `Press cmd+s in TextEdit`, `Open Calculator`.

## 7. Testing

- Unit (here, CI): toolkit against the fake backend — outline format and caps, secure-field redaction, ref map lifetime, every hard rule (secure field, blocked apps, blocked combos, payment fields, cancel flag), approval categories, audit of refusals; Mac backend tests with pyobjc calls monkeypatched (no real events); Windows backend tests with `uiautomation`/`SendInput` mocked; key-combo grammar; capability availability/probe per platform.
- **Real (headless test Mac only):** grant Accessibility + Screen Recording to the backend's Python binary in System Settings (via Screen Sharing), attach a display or a virtual display (a headless Mac has no framebuffer otherwise, so screen capture is black and some apps don't lay out), then run the scripted checks in `docs/testing/computer-control-headless-mac.md`: open TextEdit → observe → type → save-dialog cancel → blocked-app refusal (Terminal) → secure-field refusal (a password field in a test app) → `/stop`.
- Windows: the same script on the team's Windows VM.
