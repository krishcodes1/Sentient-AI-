"""Parses the small key-combo grammar desktop.act accepts ("cmd+s", "enter",
"ctrl+shift+t") and names the combos Crawler never sends.

Why it exists: A key press is the shortest path from the model to the whole
machine (log out, force quit, a launcher that runs anything), so the grammar is
deliberately tiny and the dangerous combos are refused here, before any backend
is asked to press anything.

Grammar: zero or more modifiers, then exactly one key, joined by "+",
case-insensitive. Modifiers are cmd | ctrl | alt | option | shift | win
("option" is "alt"). A key is one character from ``PRINTABLE`` (letters are
written lower-case; add "shift" for a capital) or a named key from
``NAMED_KEYS``. "backspace" deletes to the left (the Mac "delete" key),
"delete" deletes to the right. Write "+" as "plus". Anything with the Fn or
Globe key is refused outright.
"""

from __future__ import annotations

import re
from typing import Optional

from services.tools.computer.backend import KeyCombo
from services.tools.computer.rules import squash

MAX_COMBO_CHARS = 40

MODIFIER_ALIASES: dict[str, str] = {
    "cmd": "cmd",
    "ctrl": "ctrl",
    "alt": "alt",
    "option": "alt",
    "shift": "shift",
    "win": "win",
}
_FN_TOKENS = frozenset({"fn", "globe"})

PRINTABLE = "abcdefghijklmnopqrstuvwxyz0123456789`-=[]\\;',./"

_NAMED_ALIASES: dict[str, str] = {
    "enter": "enter",
    "return": "enter",
    "tab": "tab",
    "space": "space",
    "escape": "escape",
    "esc": "escape",
    "backspace": "backspace",
    "delete": "delete",
    "del": "delete",
    "up": "up",
    "down": "down",
    "left": "left",
    "right": "right",
    "home": "home",
    "end": "end",
    "pageup": "pageup",
    "pagedown": "pagedown",
    "insert": "insert",
    "plus": "plus",
    **{f"f{n}": f"f{n}" for n in range(1, 13)},
}
NAMED_KEYS: frozenset[str] = frozenset(_NAMED_ALIASES.values())

# Keys that put characters into a field when pressed without cmd/ctrl/win.
_TEXT_KEYS = frozenset({"space", "plus"})
_COMMAND_MODIFIERS = frozenset({"cmd", "ctrl", "win"})

_WS = re.compile(r"\s+")


class KeyComboError(ValueError):
    """The text is not a combo in the grammar. The message is safe to show."""


class BlockedKeyError(KeyComboError):
    """The combo is in the grammar's reach but is never sent."""


def parse_combo(text: object) -> KeyCombo:
    """Parse *text* into a KeyCombo, or raise KeyComboError / BlockedKeyError."""
    if not isinstance(text, str):
        raise KeyComboError("keys must be a string such as 'cmd+s' or 'enter'.")
    cleaned = _WS.sub("", text).lower()
    if not cleaned:
        raise KeyComboError("keys is empty; give a combo such as 'cmd+s' or 'enter'.")
    if len(cleaned) > MAX_COMBO_CHARS:
        raise KeyComboError(f"keys is too long (at most {MAX_COMBO_CHARS} characters).")
    tokens = cleaned.split("+")
    if any(t in _FN_TOKENS for t in tokens):
        raise BlockedKeyError("Combos with the Fn/Globe key are never sent.")
    if any(t == "" for t in tokens):
        raise KeyComboError("Empty part in keys; write the + key as 'plus' (e.g. 'cmd+plus').")
    *mod_tokens, key_token = tokens
    modifiers: set[str] = set()
    for token in mod_tokens:
        mod = MODIFIER_ALIASES.get(token)
        if mod is None:
            raise KeyComboError(
                f"'{token}' is not a modifier (use cmd, ctrl, alt/option, shift or win), "
                "and a combo has only one non-modifier key."
            )
        if mod in modifiers:
            raise KeyComboError(f"'{token}' appears twice in keys.")
        modifiers.add(mod)
    if key_token in MODIFIER_ALIASES:
        raise KeyComboError("keys needs one non-modifier key after the modifiers (e.g. 'cmd+s').")
    if len(key_token) == 1 and key_token in PRINTABLE:
        key = key_token
    else:
        named = _NAMED_ALIASES.get(key_token)
        if named is None:
            raise KeyComboError(
                f"Unknown key '{key_token[:20]}'. Use one letter, digit or punctuation mark, "
                "or a named key such as enter, tab, escape, space, backspace, delete, "
                "up/down/left/right, home, end, pageup, pagedown or f1-f12. "
                "To enter text, use the type action."
            )
        key = named
    return KeyCombo(frozenset(modifiers), key)


def _combo(text: str) -> KeyCombo:
    mods, _, key = text.rpartition("+")
    return KeyCombo(frozenset(m for m in mods.split("+") if m), key)


# Never sent, whatever app is in front: each would log out, lock, force
# quit, open a system security screen, or open a launcher that can start
# any program (open_app is the sanctioned, checked way to start one).
BLOCKED_COMBOS: dict[KeyCombo, str] = {
    _combo("cmd+shift+q"): "logs out of the Mac",
    _combo("cmd+alt+shift+q"): "logs out of the Mac immediately",
    _combo("ctrl+cmd+q"): "locks the Mac",
    _combo("cmd+alt+escape"): "opens Force Quit",
    _combo("cmd+alt+shift+escape"): "force-quits the front app",
    _combo("ctrl+alt+delete"): "opens the Windows security screen",
    _combo("ctrl+shift+escape"): "opens Task Manager",
    _combo("ctrl+alt+end"): "opens the Windows security screen in a remote session",
    _combo("cmd+space"): "opens Spotlight, which can start any program (use open_app)",
    _combo("ctrl+escape"): "opens the Start menu, which can start any program (use open_app)",
    _combo("alt+space"): "opens a launcher or the window menu (use open_app or focus_window)",
}

# Blocked only when one of these apps is the target: quitting Finder, or
# alt+f4 on the Windows desktop (which opens the Shut Down dialog).
_CONTEXT_COMBOS: dict[KeyCombo, tuple[frozenset[str], str]] = {
    _combo("cmd+q"): (frozenset({"finder"}), "quits Finder"),
    _combo("alt+f4"): (
        frozenset(
            {"explorer", "fileexplorer", "windowsexplorer", "programmanager", "desktop", "finder"}
        ),
        "opens the Shut Down dialog on the desktop",
    ),
}


def blocked_reason(combo: KeyCombo, app: Optional[str]) -> Optional[str]:
    """Why *combo* must not be pressed in *app*, or None when it may be.

    With *app* unknown (None or empty) the app-dependent combos are
    refused too: fail closed.
    """
    if "win" in combo.modifiers:
        return f"{combo} uses the Windows key, which opens Start, Run and system menus"
    reason = BLOCKED_COMBOS.get(combo)
    if reason is not None:
        return f"{combo} {reason}"
    context = _CONTEXT_COMBOS.get(combo)
    if context is not None:
        apps, why = context
        squashed = squash(app or "")
        if not squashed or squashed in apps:
            return f"{combo} {why}"
    return None


def produces_text(combo: KeyCombo) -> bool:
    """True when pressing *combo* would put characters into a text field."""
    printable = len(combo.key) == 1 or combo.key in _TEXT_KEYS
    return printable and not (combo.modifiers & _COMMAND_MODIFIERS)


def is_paste(combo: KeyCombo) -> bool:
    """True for the paste shortcuts (cmd/ctrl+v, shift+insert)."""
    if combo.key == "v" and combo.modifiers & {"cmd", "ctrl"}:
        return True
    return combo.key == "insert" and "shift" in combo.modifiers


def enters_text(combo: KeyCombo) -> bool:
    """True when *combo* types or pastes into the focused field."""
    return produces_text(combo) or is_paste(combo)
