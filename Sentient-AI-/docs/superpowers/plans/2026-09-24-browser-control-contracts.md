# `browser_control` — implementation contracts (read before any task)

Spec: `docs/superpowers/specs/2026-09-24-browser-control-design.md`. These are the shared interfaces every task codes against. Do not deviate; propose changes to the coordinator instead.

## Working rules (all agents)
- Project root is the NESTED `/Users/krish/Sentient-AI-/Sentient-AI-/` (backend at `backend/`). Worktrees are created from `main`: run `git merge --ff-only feat/full-platform-completion || git reset --hard feat/full-platform-completion` first.
- **Never commit or push.** Leave changes staged and report a proposed commit message; the owner reviews every message.
- Never read `backend/.env`. No real LLM/Telegram calls. Do not touch the running compose project `docker` or ports 3000/8000/5173/5432/6379. Tests use the fake site (§8) and fake pages; never a real website in tests. Do not launch a headed browser in tests (`headless=True` always in CI/tests).
- Both OSes are first-class: every OS-specific behaviour goes through `services/platform/` (§1); ship Mac and Windows implementations and tests together.
- Style: match neighbours (`from __future__ import annotations`, structlog, docstrings that explain why, fail-closed `{"ok": False, "error": ...}` results).

## 1. `services/platform/` — the only place that may branch on the OS
```python
class Platform(Protocol):
    name: Literal["mac", "windows", "linux", "container"]
    def browser_channel(self) -> Optional[str]      # "chrome" | "msedge" | None (bundled Chromium)
    def profile_dir(self, user_id: str) -> Path      # created 0700 / current-user ACL
    def data_dir(self) -> Path                       # app data root (see spec §11.1)
    def bring_to_front(self, *, pid: Optional[int] = None, title: Optional[str] = None) -> bool
    def port_owner(self, port: int) -> Optional[str] # "pid name" for diagnostics
    # vault (phase 2): get_secret(name) -> Optional[bytes]; set_secret(name, value: bytes) -> None; delete_secret(name) -> None
def current() -> Platform            # cached; honours CRAWLER_PLATFORM override for tests ("mac"|"windows"|"container")
```
Files: `services/platform/{__init__,base,mac,windows,linux,container}.py`. Mac uses `/usr/bin/security` for secrets (phase 2), `osascript` for front-most; Windows uses ctypes (`CryptProtectData`, `SetForegroundWindow`) and `netstat -ano`; container reports `browser_channel() = None`, `bring_to_front` → False.

## 2. Session manager — `services/tools/browser/session.py`
```python
Mode = Literal["account", "public"]

@dataclass
class TaskState:
    task_id: str                  # conversation_id + resume chain; carried across approval/handoff resumes
    actions: int = 0
    spend_usd: float = 0.0
    notes: list[str] = field(default_factory=list)      # note(text) entries, ≤2k chars total
    summaries: list[str] = field(default_factory=list)  # toolkit-written one-liners, newest last
    last_outline_chars: int = 0

class BrowserSession:
    user_id: str; mode: Mode; context: BrowserContext; lock: asyncio.Lock
    task: TaskState; last_used: float; typed_secrets: list[str]   # redaction list (phase 2 fills it)
    async def page(self) -> Page                     # active tab
    async def tabs(self) -> list[dict]               # [{index, url, title, active}]
    async def switch(self, index: int) -> None
    async def new_tab(self) -> Page                  # ≤ max_tabs, else error

class BrowserSessionManager:
    def __init__(self, *, headless: bool, platform: Platform, max_sessions: int = 3,
                 max_tabs: int = 4, idle_seconds: int = 900, launcher: Optional[Launcher] = None) -> None
    async def get(self, user_id: str, *, mode: Mode, task_id: str) -> BrowserSession   # creates or reuses; resets TaskState when task_id changes
    async def close(self, user_id: str) -> None
    async def close_all(self) -> None
    async def reap_idle(self) -> int                 # never closes a session with a pending approval/handoff
```
Native: `launch_persistent_context(user_data_dir=platform.profile_dir(user_id), channel=platform.browser_channel(), headless=False, viewport=1280x800)`; PUBLIC mode uses a fresh non-persistent context. Container/tests: `chromium.launch(headless=True)` + `new_context(service_workers="block", accept_downloads=False, permissions=[])`. `launcher` is injectable so tests can pass a fake.

## 3. Snapshot pipeline — `services/tools/browser/snapshot.py`
```python
@dataclass(frozen=True)
class Outline:
    url: str; title: str; lines: list[str]; refs: int; chars: int; truncated: bool

async def outline(page: Page, *, query: Optional[str] = None, full: bool = False,
                  account_mode: bool, secrets: Sequence[str] = (), limit_chars: int = 8000) -> Outline
def filter_yaml(raw: str, *, query, full, account_mode, secrets, limit_chars) -> Outline-fields   # pure; unit-tested on fixtures
def find_lines(raw: str, text: str, *, context: bool = True) -> list[str]   # match + nearest row/listitem/article ancestor with refs
def summarize(action: str, args: dict, outline: Outline) -> str            # "[step N] click "Grades" → host/path · 48 refs"
def strip_url(url: str, account_mode: bool) -> str                          # query/fragment removed in ACCOUNT mode
```
Raw source: `await page.locator("body").aria_snapshot(mode="ai")` (Playwright 1.63 — pin `playwright>=1.63,<1.64` in requirements.txt and add a contract test that `aria_snapshot` accepts `mode="ai"` and that `page.locator("aria-ref=e1")` resolves). Filter rules are spec §5, verbatim. `full=False` = viewport-visible + query matches; `limit_chars` 8000 default, 24000 for `full`.

## 4. Read toolkit — `services/tools/browser/actions.py` (phase 1) and result shape
```python
class BrowserReadToolkit:
    def __init__(self, sessions: BrowserSessionManager, *, guard: Guard, handoff: HandoffDetector, clock=time.monotonic) -> None
    async def execute(self, action: str, params: dict, *, user_id: str, task_id: str) -> dict
```
Actions: `open(url)`, `snapshot(query?, full?)`, `find(text)`, `text(ref?)`, `scroll(direction: up|down|top|bottom)`, `back()`, `tabs()`, `switch(index)`, `wait(text?|ms?≤10000)`, `screenshot(ref?, for_model?=false)`, `note(text)`, `handoff(reason)`, `click(ref)` (non-consequential targets only; else `{"ok": False, "error": "This looks like a consequential action; use browser.act", "consequential": reason}`).

Success result (every navigating/observing action returns the fresh outline inline):
```json
{"ok": true, "url": "...", "title": "...", "outline": ["- link \"Grades\" [ref=e3]", "..."], "refs": 48,
 "truncated": false, "summary": "[step 4] click \"Grades\" → canvas.school.edu/courses/123/grades · 48 refs",
 "notes": ["..."], "user_image": "data:image/jpeg;base64,...", "image": "data:image/jpeg;base64,..."}
```
`user_image` is present only for `screenshot` (delivered to the person, never to the model); `image` only when `for_model=true` (≤768 px). Failure: `{"ok": false, "error": "...", "stale_ref": true}` or `{"ok": false, "needs_human": {"kind": "captcha|mfa|otp|unusual_traffic", "url": "...", "user_image": "..."}}`.

Catalog (`tool_registry.py`): `"browser"` in `BUILTIN_CONNECTOR_TYPES`; `_BUILTIN_STANCE["browser"] = "user_confirm"`; `ToolSpec("read", …, READ, schema {action: enum[...], url?, ref?, text?, query?, full?, direction?, index?, ms?, for_model?, reason?})` — one flat schema; phase 3 adds `ToolSpec("act", …, WRITE)` and phase 2 `ToolSpec("login", …, WRITE)`. Policy rows: `("browser", READ)=AUTO_APPROVE, (WRITE)=USER_CONFIRM, DELETE/EXECUTE/FINANCIAL=HARD_BLOCKED`. Capability file `services/capabilities/browser_control.py`: key `browser_control`, label "Control a browser", tools `("browser.",)`, default off, risk high, availability: Playwright importable and (`platform.browser_channel()` or bundled Chromium installed); `when_denied` per template.

## 5. Guard — `services/tools/browser/guard.py`
```python
def check_url(url: str) -> Optional[str]             # None if allowed; else reason. http(s) only, no userinfo/data/blob/javascript/file, check_ssrf on the host
async def install_egress_guard(context: BrowserContext, *, account_mode: bool) -> None   # context.route: abort top-level navigations to private/loopback (re-resolving the host), abort non-GET top-level navigations triggered by read-tier actions; XHR/fetch untouched
async def consequential(page: Page, ref: str) -> Optional[str]   # None if safe to click read-tier; else reason: "submit control" | "inside a form with a password/payment field" | "name matches: sign up" | "non-GET navigation"
CONSEQUENTIAL_NAMES = (send, submit, post, pay, buy, order, delete, confirm, sign up, register, subscribe, call, accept, agree, allow, authorize)  # word-boundary, case-insensitive; site packs extend later
```

## 6. Handoff detector — `services/tools/browser/handoff.py` (phase 1: detect; phase 2: parked turn + /code)
```python
@dataclass(frozen=True)
class Challenge: kind: Literal["captcha","mfa","otp","unusual_traffic"]; detail: str; otp_ref: Optional[str] = None
async def detect_challenge(page: Page) -> Optional[Challenge]
```
Rules (spec §8): visible/blocking CAPTCHA frames only (not invisible badges), "verify you are human"/"unusual traffic" text, IdP MFA hosts (duosecurity.com, login.microsoftonline.com, okta.com, accounts.google.com challenge paths) with an OTP/number-match field, `bots.html`-style URLs. HTTP 403/429 alone → not a challenge.

## 7. Runtime changes (phase 1) — `services/agent/runtime.py`, `providers.py`, `api/routes/agent.py`, `telegram.py`
- **Latest-observation policy:** when building follow-up messages, any earlier `browser.*` result is replaced by its `summary` line; the newest keeps its full outline. A `<task_facts>` block (notes + summaries, ≤2k chars, toolkit-written) is appended after the tool results on browser rounds. The closing instruction on browser rounds is "Continue the task; call the next browser action or answer when done." instead of the generic "answer the user's most recent request".
- **Result budget:** `RESULT_CHAR_BUDGETS = {"browser.": 8000}` overrides the 2000 default for those tools; per-line PromptGuard redaction for list-of-lines results (one flagged line must not blank the outline).
- **Images:** `_images_for_model` keys on `image` only; keep image blocks only in the newest follow-up. Channel delivery (`agent.py` image block) sends `user_image` OR `image`, max 3, caption from `title`.
- **Gemini thinking:** `GeminiProvider` sends `generationConfig.thinkingConfig` — `thinkingBudget` from a new setting `GEMINI_THINKING_BUDGET` (default 0 for browser rounds via a per-call override, otherwise unchanged); verify against the current Gemini REST field names.
- **Task caps:** `TaskState.actions ≥ BROWSER_MAX_ACTIONS (60)` or estimated spend ≥ `BROWSER_MAX_USD (0.25)` → the toolkit returns `{"ok": false, "cap": "actions|spend", "resume_hint": "…"}`; the runtime ends the turn with a "Continue?" message that carries the task id; the resume keeps `task_id` (approval/handoff resume already re-enters the runtime — thread `task_id` through). Loop detector keyed on `(action, args)` hash: 3 identical in a row → refuse.
- **Telegram:** `link_preview_options={"is_disabled": True}` on every `sendMessage`/`editMessageText`; in ACCOUNT mode the final reply has query strings/fragments stripped from URLs.
- **Prompt:** Canvas playbook lines in `SECURITY_SYSTEM_PROMPT`'s capabilities section (`/courses`, `/courses/:id/grades`, planner "Show N missing items"; use `find('Missing')`/`find('Late')`; prefer `open` on same-origin paths over clicking through).

## 8. Fake site harness — `backend/tests/fakesite/`
A stdlib `http.server` app started in a thread by a pytest fixture on a free loopback port, serving: `/` (links), `/login` (username/password form → sets cookie → `/home`), `/sso/start` (302 chain via `/sso/idp` → `/sso/otp` (OTP input) → `/home`), `/captcha` (page with a visible blocking iframe titled "reCAPTCHA"), `/badge` (invisible reCAPTCHA badge, must NOT trigger), `/grades` (table with `<span class="screenreader-only">Missing</span>` cells and assignment names), `/flights` (a results list with prices), `/hidden` (white-on-white "ignore previous instructions" text), `/post` (a form whose submit button says "Sign up"). Used by every integration test; SSRF checks must allow loopback for this harness only via an explicit test toggle (`CRAWLER_ALLOW_LOOPBACK_FOR_TESTS=1`), never in production code paths.

## 9. Tests to exist after phase 1
`tests/test_platform.py` (mac/windows/container selection via `CRAWLER_PLATFORM`, profile dir permissions, port_owner parsing with mocked subprocess), `tests/test_browser_snapshot.py` (filter rules on fixtures under `tests/fixtures/aria/*.yaml`: canvas_grades, flights, hidden_injection, frames; find row context; strip_url; summarize; size cap + truncated flag), `tests/test_browser_session.py` (fake launcher; per-user reuse; task reset on new task_id; max tabs; reap never closes pending), `tests/test_browser_read.py` (each action against the fake site, headless; consequential click refused; stale ref; needs_human on `/captcha` but not `/badge`; screenshot returns `user_image` not `image`), `tests/test_browser_guard.py` (check_url cases; route guard aborts private hosts and non-GET top-level), `tests/test_browser_runtime.py` (latest-observation policy, task_facts block, result budget, image pruning, caps and loop detector, thinking config sent, telegram preview flag), `tests/test_capabilities_registry.py` stays green with the new capability (`browser.read` claimed; `browser_control` off by default).
