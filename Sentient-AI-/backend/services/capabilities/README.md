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

1. **Toolkit.** Write `services/tools/<family>.py`. New toolkits take the
   shape `async def execute(self, action, params, *, user_id, approved) -> dict`,
   returning `{"ok": True, ...}` or `{"ok": False, "error": "..."}`. Fail closed.
2. **Catalog, toolkit map and policy.** In `services/agent/tool_registry.py`
   add the `ToolSpec`s under `CONNECTOR_CATALOG["<family>"]` and add
   `<family>` to `BUILTIN_CONNECTOR_TYPES` and `_BUILTIN_STANCE`. Then
   register the toolkit in `ConnectorToolExecutor.__init__`:
   - a constructor argument, `<family>_toolkit: Optional[<Family>Toolkit] = None`,
     defaulting to a fresh instance (`<family>_toolkit or <Family>Toolkit()`),
     so tests can hand in a fake;
   - a `_Builtin` entry in `self._builtins["<family>"]`: a label for
     refusals, a lambda adapting the executor's `(action, params, user_id,
     approved)` call to your toolkit's signature (e.g.
     `lambda a, p, uid, ok: toolkit.execute(a, p)`; pass `uid` only if the
     toolkit stores anything per user), the `ActionCategory`s it may run at
     all, and in `confirm` the ones that run only after the approval card.

   `test_every_builtin_type_has_a_toolkit` fails until the entry exists. In
   `services/agent/permissions.py` add one policy row per `ActionCategory`
   (hard-block what you don't use).
3. **Capability file.** Copy `_template.py` to `services/capabilities/<key>.py`,
   fill it in (your own `label` and `when_denied`, not the template's), and
   append `CAPABILITY` to `REGISTRY` in `__init__.py`.
4. **Tests.** Toolkit behaviour with fakes (no display, no network), and one
   report test for your `availability`/`probe`.
5. **Run** `python3 -m pytest tests/test_capabilities_registry.py tests/test_capabilities_report.py -q`.
   It fails if a key is not unique snake_case, a claimed tool does not exist
   or is not a built-in toolkit's, a tool is claimed twice, a built-in tool
   is unclaimed, `install` is not an `ALLOWLIST` key, the template's label or
   `when_denied` was left in, or `when_denied` is empty.

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
