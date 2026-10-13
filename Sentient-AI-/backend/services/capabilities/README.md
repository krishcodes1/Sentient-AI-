# Adding a capability

A capability is one switch the owner sees in the setup wizard and in
Settings → Permissions. Declaring it drives everything else: the tools it
unlocks are offered only when it is on, refused before and at dispatch
otherwise, and the agent's `<permissions>` block tells it (and the user)
why. A refusal says which case applies: *off* (the owner's switch;
audited as `capability_off`), *blocked* (switched on but unusable here —
not installed, no OS permission — with the reason and first fix step;
`capability_blocked`), or the owner's settings could not be read
(`capability_gate_error`; the tool is refused, never run).

## Five steps

1. **Toolkit.** Write `services/tools/<family>.py` with
   `async def execute(self, action: str, params: dict) -> dict`, returning
   `{"ok": True, ...}` or `{"ok": False, "error": "..."}`. Fail closed: an
   unknown action or a bad argument is an `ok: False` result, never an
   exception. Add a `user_id: str` parameter only when the toolkit stores
   something per user (as `ReminderToolkit.execute(action, params, user_id)`
   does); never take it from `params`. Approval is not the toolkit's
   business — the executor checks it before the call (see `confirm` below).
2. **Catalog, toolkit map and policy.** In `services/agent/tool_registry.py`
   add the `ToolSpec`s under `CONNECTOR_CATALOG["<family>"]` and add
   `<family>` to `BUILTIN_CONNECTOR_TYPES` and `_BUILTIN_STANCE`. Then
   register the toolkit in `ConnectorToolExecutor.__init__`:
   - a constructor argument, `<family>_toolkit: Optional[<Family>Toolkit] = None`,
     defaulting to a fresh instance (`<family>_toolkit or <Family>Toolkit()`),
     so tests can hand in a fake;
   - a `_Builtin` entry in `self._builtins["<family>"]`: a label for
     refusals; a lambda adapting the executor's `(action, params, user_id,
     approved)` call to your toolkit's signature; the `ActionCategory`s it
     may run at all; and in `confirm` the ones that run only after the
     approval card. The lambda is where `user_id` is passed on, and only for
     a toolkit that takes it:

     ```python
     # Stores nothing per user:
     lambda a, p, uid, ok: toolkit.execute(a, p)
     # Stores something per user (the executor's user_id, never the model's):
     lambda a, p, uid, ok: toolkit.execute(a, p, uid)
     ```

   `test_every_builtin_type_has_a_stance_and_an_executor_entry` fails until
   both the `_BUILTIN_STANCE` and the `_builtins` entries exist (a runtime
   built-in has no `_builtins` entry; see "Runtime built-ins" below). In
   `services/agent/permissions.py` add one policy row per `ActionCategory`
   (hard-block what you don't use).
3. **Capability file.** Copy `_template.py` to `services/capabilities/<key>.py`,
   fill it in (your own `label` and `when_denied`, not the template's), and
   append `CAPABILITY` to `REGISTRY` in `__init__.py`.
4. **Tests.** Toolkit behaviour with fakes (no display, no network), and one
   report test for your `availability`/`probe`.
5. **Run** `python3 -m pytest tests/test_capabilities_registry.py tests/test_capabilities_report.py tests/test_wiring.py tests/test_capability_gating.py -q`.
   It fails if a key is not unique snake_case, a claimed tool does not exist
   or is not a built-in toolkit's, a tool is claimed twice, a built-in tool
   is unclaimed, `install` is not an `ALLOWLIST` key, the template's label or
   `when_denied` was left in, `when_denied` is empty, or a built-in family
   is missing its `_BUILTIN_STANCE` or executor entry (runtime built-ins
   excepted).

Nothing in the wizard, Settings, the gates or the prompt needs changing.

## Adding an environment fact

`availability()` reads only the `ReportContext` it is given; it never calls
the OS. When it needs a fact the context lacks (is a program installed? is
a token configured?), add a field with a default to `ReportContext` in
`base.py` and fill it in `default_context()` in `__init__.py`, which is the
one place that gathers them. Keep the field hashable: the context is part
of the probe-cache key. A probe, by contrast, may ask the OS; it runs only
when the capability is on and available, and is cached for 10 s.

## Tools that stay on

A tool in `ALWAYS_ON_TOOLS` (`__init__.py`) is never gated, even when a
capability's family prefix covers it: `reminders.now` is the model's clock
and stays available with Reminders off. Never name one of these in a
capability's `tools`.

## A tool that needs two switches

A tool is claimed by exactly one capability (`tools=`), and the registry
test holds that. When it must also be off whenever another capability is
off, list the other in `_REQUIRED_CAPABILITIES` in
`services/agent/tool_registry.py`: `browser.act` is claimed by
`browser_act` and `browser.checkout` by `purchases`, and both require
`browser_control`, so `_capabilities_of` answers both and the offer, the
permission adapter and the executor each refuse on the first that is not
on (the claiming one first, so the plain `when_denied` of `purchases` is
what the owner reads). `capabilities_of_tool` is the public form.

## A capability that needs another on

When a switch is useless without another one (acting on sites without
opening them), give it `requires=("other_key",)`: the report then shows it
`blocked`, with the plain reason "Needs 'Control a browser' on in
Permissions." (or why the other one is blocked), while the other is not
on, so the Permissions page, the `<permissions>` block and every gate say
the same thing. `browser_act` requires `browser_control`. A new switch
starts off on every existing install (a stored row without its key reads
as its default), so turning a risky ability into its own switch never
turns it on for anyone.

## Settings a capability carries

A capability with owner-editable numbers (the purchase caps) declares
their defaults in its module (`purchases.PURCHASE_SETTINGS_DEFAULTS`) and
registers them in `_SETTINGS_DEFAULTS` in `__init__.py`, keyed by the
capability. The registry exposes `settings_defaults(key)`;
`InstallationService.capability_settings(key)`
merges the defaults with what the owner stored in
`installation.capability_settings` (only the changed values are stored, so
a new default reaches every install), `set_capability_settings` validates
(known names, numbers above 0 and at most 10000, never a bool) and audits
`capability_settings_updated`, and the report puts the merged values on
`CapabilityStatus.settings` (read-only) for the Permissions page and the
cards. `PUT /api/capabilities/{key}/settings` is the owner's route. The
toolkit that enforces them reads them through a small protocol
(`PurchaseSettings.purchase_caps()`), never the row.

## A tool with an approval card of its own

`desktop.act`, `browser.act` and `browser.checkout` are WRITE or FINANCIAL
tools whose card must say what will really happen and be tied to what the
owner saw. Every `browser.act` card shows the page: its async bind
(`BrowserActToolkit.bind_async`) takes a masked screenshot with the target
outlined in red, kept in memory for `approval_image`, and adds a money
warning built from the page's facts; a failed capture still makes the
card, which then says "No picture of the page could be taken." The executor's hooks route them to their toolkit:
`precheck_approval` (a hard rule the toolkit refuses before any card, filed
under `computer_rule` / `browser_rule` / `purchase_rule` with the rule
name), `approval_arguments` (the bind: the screen or page the card was made
from, under a reserved `_screen` / `_page` key the model may not supply),
`approval_arguments_async` (the binds that may touch the browser:
`browser.act` takes the card's picture; `browser.checkout` reads the page's
facts now and answers a refusal dict instead of card arguments when a rule
fails), `describe_approval` (the
card's sentence from facts, never the model's words) and `approval_image`
(a picture kept in memory by the toolkit, served to the card and never
stored). An approved call runs only while that screen or page still holds.

`FINANCIAL` stays hard-blocked for every connector; the executor dispatches
a FINANCIAL action only when it is in `FINANCIAL_BUILTINS`
(`browser.checkout`), and `("browser", FINANCIAL)` is the one policy row at
`USER_CONFIRM` (`FINANCIAL_CONFIRM_KEYS`). Do not widen either without a
spec.

## Rules

- Consequential actions (send, create account, spend, delete, install,
  type into a form) must be WRITE/DELETE/EXECUTE in the catalog so the
  approval flow applies. READ runs unattended when the capability is on.
- Never ask the user for a password in chat; credentials go through the
  Connectors UI and are filled in by the toolkit.
- OS permission grants attach to the running binary on macOS; say which
  one in `probe()` (`ctx.executable`, already resolved past symlinks).
- A broken check fails closed: an `availability()` or `probe()` that
  raises reports the capability as blocked, never as on.

## Runtime built-ins

A family whose calls need what only the agent runtime holds during a turn
is a runtime built-in. Today that is `tools`: `tools.find` searches the
turn's full tool list. It still gets its `CONNECTOR_CATALOG` entry, its
place in `BUILTIN_CONNECTOR_TYPES` and `_BUILTIN_STANCE`, and its policy
rows, but no toolkit and no `_builtins` entry. Instead, add its type to
`RUNTIME_BUILTIN_TYPES` in `services/agent/tool_registry.py` and answer
the call in `AgentRuntime` (`services/agent/runtime.py`, where
`_find_tools` answers `tools.find`). The executor refuses a runtime
built-in call that reaches it, and the checks in step 2 and step 5 leave
these types out of the executor comparison. Prefer a toolkit: add a
runtime built-in only when the call truly needs the turn's state.

### A runtime built-in claimed by a capability

`tools.find` is always on (`ALWAYS_ON_TOOLS`), but a runtime built-in can
also be claimed by a capability like any toolkit tool: `tutor.start` is
claimed by `tutor_mode` (`tools=("tutor.",)`). The offer and the permission
adapter gate it as usual (off: not offered, refused as `capability_off`).
Because the runtime answers it itself, the runtime answers it only when
the capability is on: the caller builds the turn's state object
(`TurnContext.tutor`) only then, and a turn without one sends the call
down the ordinary path, where the adapter refuses it. Give the family its
catalog entry, `BUILTIN_CONNECTOR_TYPES`, `_BUILTIN_STANCE` and policy
rows, add it to `RUNTIME_BUILTIN_TYPES` (reassigned under your anchor:
`RUNTIME_BUILTIN_TYPES = RUNTIME_BUILTIN_TYPES | {"tutor"}`), and give it
no `_builtins` entry.

## Channels: capabilities with no tools

A chat channel (`telegram`, `slack` for Slack DMs) is a capability with
`tools=()`. Its switch turns the channel on or off for the whole install;
it gates no tool. Its `availability()` reads a `ReportContext` fact
(`telegram_configured`, `slack_configured`), added as described in "Adding
an environment fact". When that fact is a running service's state rather
than a stored setting, the service reports it through a callback:
`main.wire_services` calls
`InstallationService.set_slack_status(lambda: slack_manager.is_running)`,
and the Slack manager calls `installation.invalidate` when it starts or
stops, so the cached report follows. A channel capability never claims its
connector's tools: the `slack.*` workspace tools stay governed by the Slack
connector's own permissions, so the `slack` capability must not claim
`slack.`.

## Policy switches (tools=())

A policy switch is a capability with `tools=()` that is not a channel: it
changes how Crawler treats data, not what it can do.
`hide_personal_details` ("Hide personal details from the AI provider", on by
default, always available) is one. It gates no tool, so nothing is refused
when it is off; instead the runtime reads it once per turn through a hook
main.py wires to `installation.enabled_keys()` (`AgentRuntime(personal_details_hidden=...)`,
the same pattern as the page watcher's switch), treats a gate error as on,
and ignores it for a turn on an Ollama on this computer. Its `when_denied`
doubles as the `<permissions>` line the model reads while it is off. A
protection that must never be switched off (the model floor that hides keys,
passwords, card, bank and ID numbers) is not a capability at all: it lives in
`services/security` and has no switch.

`low_risk_actions` ("Make low-risk changes without asking", on by default) is
another policy switch: it gates standing consent for LOW actions (the "Allow
low-risk changes" tier and 7-day grants from a card) for the whole install,
read by `RuntimePermissionAdapter.low_risk_enabled` and by the executor's
backstop through the owner's report. It loosens nothing by itself.

## A capability that gates an argument

Some switches decide what a tool may be asked to do rather than whether it
is offered. `trigger_runs` ("Run a task when something happens in my apps",
off by default, high risk) has `tools=()` and `requires=("event_triggers",)`:
the `triggers.*` family belongs to `event_triggers`, and `trigger_runs`
gates only the argument `mode="run_task"`. Because no tool carries it, the
offer and the permission adapter cannot enforce it, so the toolkit does:
its `precheck` (read by the executor's `precheck_approval`) refuses
`run_task` before any card while the switch is off, with its `when_denied`
as the reason, filed under the toolkit's own policy (`trigger_rule`), and
the background job that acts on the argument (the trigger sweeper) re-reads
the switch before every run and falls back to the harmless behaviour while
it is off (the plain notice, saying task runs are off). Declare such a
switch with `requires=` on the capability whose tools it qualifies, so the
Permissions page shows it blocked, with the plain reason, until that one is
on.

## Input features with no tools

An input feature changes what a channel accepts, not what the agent can do,
so it is a capability with `tools=()` that is read where the input arrives.
`voice_notes` ("Voice notes, transcribed on this computer") and
`voice_notes_cloud` ("Voice notes, transcribed by your AI provider") are two:
`services/notifications/voice.py` reads both per Telegram voice note from
`InstallationService.capability_statuses` (a read error refuses the note,
fail closed) and picks the engine: the local one whenever `voice_notes` is
on, never falling back to the cloud; otherwise the provider when
`voice_notes_cloud` is on and the account's own provider hears audio;
otherwise a plain refusal naming the switch or the provider. Their
availability reads environment facts (`speech_local_installed`,
`default_provider_audio`), and `voice_notes` names its `install`
(`speech_to_text`), so the Permissions page shows the Install button and
the `<permissions>` block may offer `system.install_capability`. Nothing is
offered to the model: no fetched content can ask for audio to be processed.
