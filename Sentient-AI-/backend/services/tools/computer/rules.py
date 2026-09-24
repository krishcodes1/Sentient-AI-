"""The fixed safety rules of computer control that depend on what is on screen:
the apps Crawler never acts in, the apps whose windows it never reads, how a
secure (password) field is recognised, and how payment fields are spotted in an
outline.

Why it exists: These rules are the hard floor under every approval card. Keeping
them pure (names, nodes and outline lines in, a verdict out) means the toolkit
applies them before any backend call and the tests can prove each one without a
desktop.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable, Optional

from services.tools.computer.backend import Node

# ── App names ──────────────────────────────────────────────────────────────


def squash(name: str) -> str:
    """The comparable form of an app name: compatibility-normalized (so
    full-width lookalikes fold to ASCII), last path component, no .app or
    .exe suffix, case-folded, letters and digits only."""
    text = unicodedata.normalize("NFKC", str(name)).strip()
    base = re.split(r"[\\/]", text)[-1].casefold()
    for suffix in (".app", ".exe"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return "".join(ch for ch in base if ch.isalnum())


def same_app(a: str, b: str) -> bool:
    sa, sb = squash(a), squash(b)
    return bool(sa) and sa == sb


# Display name → the squashed spellings that identify it. A spelling ending
# in "*" matches any name that starts with it ("1password*" covers
# "1Password 7"). Names are the English/executable ones; see backend.py.
_SECRET_APPS: dict[str, tuple[str, ...]] = {
    "Keychain Access": ("keychainaccess", "keychain*"),
    "Passwords": ("passwords",),
    "1Password": ("1password*", "onepassword*", "agilebits*"),
    "Bitwarden": ("bitwarden*",),
    "LastPass": ("lastpass*",),
    "Dashlane": ("dashlane*",),
    # Beyond the spec's list: the Windows backend names these by their
    # executables, and all of them hold passwords too.
    "KeePass": ("keepass*",),
    "Keeper": ("keeper*",),
    "NordPass": ("nordpass*",),
    "Enpass": ("enpass*",),
    "RoboForm": ("roboform*",),
    "Proton Pass": ("protonpass*",),
}

_BLOCKED_APPS: dict[str, tuple[str, ...]] = {
    **_SECRET_APPS,
    # "systemsettings*" also covers Windows' SystemSettingsAdminFlows.exe;
    # "control" is Control Panel's executable.
    "System Settings": ("systemsettings*", "systempreferences", "controlpanel", "control"),
    # Terminals and command runners: a later shell capability is the only
    # path to commands.
    "Terminal": ("terminal",),
    "iTerm2": ("iterm", "iterm2"),
    "Warp": ("warp*",),
    "PowerShell": ("powershell*", "windowspowershell*", "pwsh"),
    "Windows Terminal": ("windowsterminal", "wt", "openconsole"),
    "Command Prompt": ("commandprompt", "cmd", "conhost"),
    "Other terminals": (
        "hyper",
        "alacritty",
        "kitty",
        "wezterm*",
        "ghostty",
        "tabby",
        "mintty",
        "gitbash",
        "wsl",
    ),
    "Script Editor": ("scripteditor*",),
    "Automator": ("automator",),
    # Anything that starts any program from typed text: Spotlight, the
    # Windows Start menu and its search (what ctrl+escape opens).
    "Launchers": (
        "alfred*",
        "raycast",
        "launchbar",
        "spotlight",
        "startmenu*",
        "searchhost",
        "searchapp",
        "searchui",
        "windowssearch",
    ),
    "Registry Editor": ("registryeditor", "regedit", "regedt32"),
    "Task Manager": ("taskmanager", "taskmgr"),
    "Activity Monitor": ("activitymonitor",),
    "Microsoft Management Console": ("microsoftmanagementconsole", "mmc"),
    # The login/lock window and the OS's own security prompts (admin
    # password, Touch ID, privacy consent, Windows UAC and credentials),
    # under the names the Windows backend reports them by too.
    "the login or lock window": (
        "loginwindow",
        "lockapp",
        "lockscreen",
        "useraccountcontrol",
        "windowssecurity",
        "logonui",
        "screensaverengine",
        "securityagent",
        "coreautha",
        "usernotificationcenter",
        "consent",
        "credentialuibroker",
    ),
    "Crawler AI": ("crawler*",),
}

# Every blocked display name, for documentation and tests.
BLOCKED_APPS: tuple[str, ...] = tuple(_BLOCKED_APPS)
SECRET_APPS: tuple[str, ...] = tuple(_SECRET_APPS)


def _candidates(name: str) -> set[str]:
    """The whole name plus each dot-separated part, so a bundle id such as
    "com.apple.Terminal" is caught by its last part."""
    text = str(name)
    found = {squash(text)}
    if "." in text:
        found.update(squash(part) for part in text.split("."))
    found.discard("")
    return found


def _match(name: str, table: dict[str, tuple[str, ...]]) -> Optional[str]:
    candidates = _candidates(name)
    if not candidates:
        return None
    for display, spellings in table.items():
        for spelling in spellings:
            if spelling.endswith("*"):
                prefix = spelling[:-1]
                if any(c.startswith(prefix) for c in candidates):
                    return display
            elif spelling in candidates:
                return display
    return None


def blocked_app(name: str) -> Optional[str]:
    """The blocked entry *name* matches (e.g. "Terminal"), or None."""
    return _match(name, _BLOCKED_APPS)


def secret_app(name: str) -> Optional[str]:
    """The password-holding app *name* matches, or None. Crawler neither
    acts in nor reads the windows of these."""
    return _match(name, _SECRET_APPS)


# The web UI's page title ("Crawler AI - Secure Agentic AI Platform"), as a
# browser shows it in its window title. Acting there could approve Crawler's
# own approval cards.
_CRAWLER_WINDOW = re.compile(r"^\s*Crawler AI\b", re.IGNORECASE)


def crawler_window(title: str) -> bool:
    """True when a window title says it is Crawler's own UI (in a browser)."""
    return bool(_CRAWLER_WINDOW.match(str(title or "")))


# ── Secure fields ──────────────────────────────────────────────────────────

_FIELD_ROLE = re.compile(r"field|text area|text box|textbox|edit|combo box|spin", re.IGNORECASE)
_PASSWORD_NAME = re.compile(
    r"\b(password|passcode|passphrase|pin|pin code|one[- ]time code)\b", re.IGNORECASE
)


def is_field_role(role: str) -> bool:
    return bool(_FIELD_ROLE.search(role or ""))


def looks_secure(node: Node) -> bool:
    """A secure (password) field by the OS flag, or a text field whose name
    says it holds a password. Either way its value is never read or typed
    into."""
    if node.secure or "secure" in (node.role or "").lower():
        return True
    return is_field_role(node.role) and bool(_PASSWORD_NAME.search(node.name or ""))


# ── Payment fields ─────────────────────────────────────────────────────────

# Matched anywhere in a field's name, or as the whole of a short label.
_PAYMENT_NAME = re.compile(
    r"\b("
    r"card\s*number|card\s*no\.?|credit\s*card|debit\s*card|name\s+on\s+card|cc\s*(?:num|number)"
    r"|cvc2?|cvv2?|csc|card\s*verification|security\s*code"
    r"|expir(?:y|ation)(?:\s*date)?|exp\.?\s*date|mm\s*/\s*yy"
    r"|iban|bic|swift(?:\s*code)?|routing\s*number|sort\s*code|account\s*number|bank\s*account"
    r")\b",
    re.IGNORECASE,
)
_LABEL_MAX_CHARS = 40
# Everything but letters, digits and "/" (kept for "MM/YY").
_PUNCTUATION = re.compile(r"(?:[^\w/]|_)+")
_CARD_DIGITS = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30})")
# ISO 13616 registry lengths by country code.
# fmt: off
_IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}
# fmt: on

# Parses the lines outline.py writes:
#   <indent>- <role> ["<name>"] [ref=dN] [flags...] [value="<v>" | value=[redacted]]
_LINE = re.compile(
    r'^\s*- (?P<role>[^"\[]*?)\s*(?:"(?P<name>(?:[^"\\]|\\.)*)")?\s*(?:\[ref=d\d+\])?'
    r'(?:\s*\[[a-z ]+\])*\s*(?:value=(?:"(?P<value>(?:[^"\\]|\\.)*)"|\[redacted\]))?\s*$'
)


def luhn_ok(digits: str) -> bool:
    """The Luhn checksum every payment card number passes."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_ok(text: str) -> bool:
    """The ISO 13616 mod-97 check an IBAN passes."""
    compact = text.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34 or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        number = int("".join(str(int(ch, 36)) for ch in rearranged))
    except ValueError:
        return False
    return number % 97 == 1


def _unescape(text: Optional[str]) -> str:
    if not text:
        return ""
    return re.sub(r"\\(.)", r"\1", text)


def _has_card_number(text: str) -> bool:
    for match in _CARD_DIGITS.finditer(text):
        if luhn_ok(re.sub(r"[ -]", "", match.group(0))):
            return True
    return False


def _has_iban(text: str) -> bool:
    for match in _IBAN.finditer(text.upper()):
        compact = match.group(1).replace(" ", "")
        length = _IBAN_LENGTHS.get(compact[:2])
        # The pattern is greedy, so trailing words may ride along: cut the
        # candidate to its country's IBAN length before checking it.
        candidate = compact[:length] if length else compact
        if iban_ok(candidate):
            return True
    return False


def payment_reason(lines: Iterable[str]) -> Optional[str]:
    """Why the outline *lines* look like a payment form, or None.

    A payment field is a text field whose name mentions a card number,
    CVC, expiry, IBAN or bank account; a short label that is exactly such
    a name; or any name or value holding a Luhn-valid card number or a
    valid IBAN.
    """
    for line in lines:
        match = _LINE.match(line)
        if match is None:
            continue
        role = match.group("role") or ""
        name = _unescape(match.group("name"))
        value = _unescape(match.group("value"))
        # "cc-number", "Card_Number", 'Card "number"' all read as words.
        words = _PUNCTUATION.sub(" ", name).strip()
        if is_field_role(role) and _PAYMENT_NAME.search(words):
            return f'payment field "{name[:60]}"'
        if len(words) <= _LABEL_MAX_CHARS and _PAYMENT_NAME.fullmatch(words):
            return f'payment field label "{name[:60]}"'
        for text in (name, value):
            if text and _has_card_number(text):
                return "a card number"
            if text and _has_iban(text):
                return "an IBAN"
    return None
