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
