"""The computer_control toolkit: desktop.observe (read the front window as an
outline with refs) and desktop.act (click, type, press keys, scroll, open apps,
switch windows), over a per-OS ComputerBackend.

Why it exists: Tasks with no website and no API can still be done by using the
apps on the Mac or PC the way a person does. The package keeps the safety rules
(rules.py, keys.py), the outline format (outline.py) and the OS code (one
backend per platform, plus an in-memory fake for tests) apart, so each can be
tested on its own and no test ever touches the real desktop.

Wiring (not done here): construct ``ComputerToolkit(select_backend(platform),
cancel_flag=...)`` in ``wire_services`` and route ``desktop.observe`` /
``desktop.act`` to ``execute("observe" | "act", params, user_id=...)``;
``describe(params, user_id=...)`` gives the approval-card sentence and
``precheck(params, user_id=...)`` a refusal that needs no approval card.
"""

from services.tools.computer.backend import (
    AppInfo,
    ComputerBackend,
    KeyCombo,
    Node,
    UnavailableBackend,
    WindowInfo,
    select_backend,
)
from services.tools.computer.toolkit import ComputerToolkit

__all__ = [
    "AppInfo",
    "ComputerBackend",
    "ComputerToolkit",
    "KeyCombo",
    "Node",
    "UnavailableBackend",
    "WindowInfo",
    "select_backend",
]
