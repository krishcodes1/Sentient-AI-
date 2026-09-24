# Adding a capability

A capability is one switch the owner sees in the setup wizard and in
Settings → Permissions. Declaring it drives everything else: the tools it
unlocks are offered only when it is on, refused at dispatch when it is off,
and the agent's `<permissions>` block tells it (and the user) why.

## Five steps

1. **Toolkit.** Write `services/tools/<family>.py` with
   `async def execute(self, action, params, ...) -> dict` returning
   `{"ok": True, ...}` or `{"ok": False, "error": "..."}`. Fail closed.
2. **Catalog and policy.** In `services/agent/tool_registry.py` add the
   `ToolSpec`s under `CONNECTOR_CATALOG["<family>"]`, add `<family>` to
   `BUILTIN_CONNECTOR_TYPES` and `_BUILTIN_STANCE`, and register the toolkit
   in `ConnectorToolExecutor._builtins`. In `services/agent/permissions.py`
   add one policy row per `ActionCategory` (hard-block what you don't use).
3. **Capability file.** Copy `_template.py` to `services/capabilities/<key>.py`,
   fill it in, and append `CAPABILITY` to `REGISTRY` in `__init__.py`.
4. **Tests.** Toolkit behaviour with fakes (no display, no network), and one
   report test for your `availability`/`probe`.
5. **Run** `python3 -m pytest tests/test_capabilities_registry.py tests/test_capabilities_report.py -q`.
   It fails if a claimed tool does not exist, a tool is claimed twice, a
   built-in tool is unclaimed, or `when_denied` is empty.

Nothing in the wizard, Settings, the gates or the prompt needs changing.

## Rules

- Consequential actions (send, create account, spend, delete, install,
  type into a form) must be WRITE/DELETE/EXECUTE in the catalog so the
  approval flow applies. READ runs unattended when the capability is on.
- Never ask the user for a password in chat; credentials go through the
  Connectors UI and are filled in by the toolkit.
- OS permission grants attach to the running binary on macOS; say which
  one in `probe()` (`ctx.executable`).
