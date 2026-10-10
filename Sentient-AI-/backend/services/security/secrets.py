"""Finds credentials, payment cards, bank and ID numbers and contact details in
text, and says where they are and what they are, never what they are.

Why it exists: every place that stores, sends or shows text (memory, the audit
log, logs, Telegram and Slack, tool arguments, the model request) must agree on
what a secret looks like. ``RULES`` is that one table; each place applies it
through a named policy (``services/security/policies.py``). BACKLOG F6.

Design:

- Local, stateless and pure Python: regular expressions plus the Luhn,
  IBAN mod-97, SSN area and Shannon-entropy checks. No I/O, no dependency.
- A ``Finding`` carries the rule, kind, label, offsets and confidence. It
  never holds the matched text, and neither does its repr.
- Linear time. Every quantifier is bounded, and every rule whose body can
  run long starts only where the body cannot already be running (a
  lookbehind over the body's own characters, or a prefix the body cannot
  contain), so no crafted input makes a rule rescan the same run from each
  position. Input over ``MAX_SCAN_CHARS`` raises ``ScanTooLarge``, which
  every policy treats as a detector failure (fail closed).
- Overlapping matches merge leftmost-longest: the match that starts first
  (the longest of those, then the most confident, then the earlier rule)
  names the finding, which is widened to cover every match it overlaps, so
  a masked span never leaves the tail of another match behind.

To add a format: add one ``Rule`` row to ``RULES`` and one positive and one
negative row to tests/test_security_secrets.py (see README.md).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Callable, Iterable, Optional

# Longest text find() scans. Larger input raises ScanTooLarge, which the
# policies treat as a detector failure: refuse, or withhold the text.
MAX_SCAN_CHARS = 2_000_000


class ScanTooLarge(ValueError):
    """The text is longer than ``MAX_SCAN_CHARS``; it was not scanned."""


class Kind(str, Enum):
    """What a finding is. The first four are secrets every sink hides; the
    last four are contact details only the model-facing pseudonymiser
    touches."""

    credential = "credential"
    payment_card = "payment_card"
    bank_account = "bank_account"
    government_id = "government_id"
    email = "email"
    phone = "phone"
    street_address = "street_address"
    birth_date = "birth_date"


class Confidence(IntEnum):
    """How sure a rule is. HINT is a loose stated form (memory only); LOW
    adds the broad card-length rule the audit log has always had; MEDIUM
    and HIGH are what channels, tool arguments and the model act on."""

    HINT = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


SECRET_KINDS: frozenset[Kind] = frozenset(
    {Kind.credential, Kind.payment_card, Kind.bank_account, Kind.government_id}
)
CONTACT_KINDS: frozenset[Kind] = frozenset(
    {Kind.email, Kind.phone, Kind.street_address, Kind.birth_date}
)

# A check gets the rule's match and says whether it is a real finding.
Check = Callable[["re.Match[str]"], bool]


@dataclass(frozen=True)
class Rule:
    """One format. ``group`` is the part of the match that is hidden (0 for
    the whole match); ``check`` validates a match (Luhn, mod-97, entropy)."""

    id: str
    kind: Kind
    label: str
    pattern: "re.Pattern[str]"
    confidence: Confidence
    group: int = 0
    check: Optional[Check] = None


@dataclass(frozen=True)
class Finding:
    """Where a value is and what it is. Never the value itself."""

    rule: str
    kind: Kind
    label: str
    start: int
    end: int
    confidence: Confidence

    def __repr__(self) -> str:
        return (
            f"Finding(rule={self.rule!r}, kind={self.kind.value!r}, label={self.label!r}, "
            f"start={self.start}, end={self.end}, confidence={self.confidence.name})"
        )


# ── validators ───────────────────────────────────────────────────────────


def luhn(digits: str) -> bool:
    """True when *digits* (only 0-9) pass the Luhn checksum."""
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def card_iin(digits: str) -> bool:
    """True when *digits* start with a card network's issuer prefix and have
    a length that network issues: Visa, Mastercard, Amex, Discover, JCB,
    Diners Club, UnionPay and Maestro. Millisecond timestamps (1...), most
    chat and order ids fail here."""
    n = len(digits)
    if not digits.isdigit() or not 12 <= n <= 19:
        return False
    two, three, four, six = (int(digits[:k]) for k in (2, 3, 4, 6))
    if digits[0] == "4":
        return n in (13, 16, 19)
    if 51 <= two <= 55 or 2221 <= four <= 2720:
        return n == 16
    if two in (34, 37):
        return n == 15
    if four == 6011 or 644 <= three <= 649 or two == 65 or 622126 <= six <= 622925:
        return 16 <= n <= 19
    if 3528 <= four <= 3589:
        return 16 <= n <= 19
    if 300 <= three <= 305 or two in (36, 38, 39) or four == 3095:
        return 14 <= n <= 19
    if two == 62:
        return 16 <= n <= 19
    if two == 50 or 56 <= two <= 69:
        return 12 <= n <= 19
    return False


def iban_mod97(value: str) -> bool:
    """True when *value* (spaces allowed) is 15-34 characters of an IBAN
    whose mod-97 check comes out at 1."""
    compact = value.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34 or not compact.isalnum() or not compact.isascii():
        return False
    if not (compact[:2].isalpha() and compact[2:4].isdigit()):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for char in rearranged:
        chunk = str(int(char, 36))
        for digit in chunk:
            remainder = (remainder * 10 + ord(digit) - 48) % 97
    return remainder == 1


def ssn_valid(area: str, group: str, serial: str) -> bool:
    """US SSN issuance rules: no area 000, 666 or 900-999, no group 00, no
    serial 0000."""
    if not (area.isdigit() and group.isdigit() and serial.isdigit()):
        return False
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def itin_valid(area: str, group: str, serial: str) -> bool:
    """US ITIN: area 9xx with group 50-65, 70-88, 90-92 or 94-99."""
    if not (area.isdigit() and group.isdigit() and serial.isdigit()) or area[0] != "9":
        return False
    g = int(group)
    return 50 <= g <= 65 or 70 <= g <= 88 or 90 <= g <= 92 or 94 <= g <= 99


def shannon_entropy(value: str) -> float:
    """Bits per character of *value* (0.0 for an empty string)."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# Values that are examples or placeholders, not secrets: the model is told to
# write YOUR_API_KEY in examples, and none of these may trip a refusal.
_PLACEHOLDER_WORDS = ("YOUR", "XXXX", "****", "EXAMPLE", "PLACEHOLDER", "REDACTED", "HIDDEN", "CHANGEME", "DUMMY")
_ENV_REFERENCE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]{0,63}\}?$")


def is_placeholder(value: str) -> bool:
    """True for an obvious placeholder: YOUR_API_KEY, <token>, ${SECRET},
    xxxx..., or text Crawler already hid."""
    text = value.strip().strip("\"'`")
    if not text:
        return True
    if text[0] in "<[{(" or _ENV_REFERENCE.match(text):
        return True
    upper = text.upper()
    return any(word in upper for word in _PLACEHOLDER_WORDS)


def _password_like(value: str) -> bool:
    """A stated password's value looks like one: a digit, a symbol, or a
    capital after the first letter. "changed" or "incorrect" does not."""
    text = value.strip("()[]{}\"'`.,;:!?")
    if len(text) < 4 or is_placeholder(text):
        return False
    if any(ch.isdigit() for ch in text):
        return True
    if any(not ch.isalnum() for ch in text):
        return True
    return any(ch.isupper() for ch in text[1:])


def _secretish(value: str) -> bool:
    """A stated key or token looks random: a digit or mixed case, and it is
    no placeholder."""
    text = value.strip("()[]{}\"'`.,;:!?")
    if len(text) < 8 or is_placeholder(text):
        return False
    has_digit = any(ch.isdigit() for ch in text)
    mixed = any(ch.isupper() for ch in text) and any(ch.islower() for ch in text)
    return has_digit or mixed


# ── checks ───────────────────────────────────────────────────────────────


def _group_text(match: "re.Match[str]", group: int) -> str:
    return match.group(group) or ""


def _sk_body_ok(match: "re.Match[str]") -> bool:
    body = match.group(0)[3:]
    if body.isalnum():
        return True
    has_digit = any(ch.isdigit() for ch in body)
    mixed = any(ch.isupper() for ch in body) and any(ch.islower() for ch in body)
    return has_digit or mixed


# A UUID (8-4-4-4-12 hex): the id of every row, file, task and watch.
_UUID_RE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)


def _alnum_at(text: str, index: int) -> bool:
    return 0 <= index < len(text) and text[index].isascii() and text[index].isalnum()


def _embedded(match: "re.Match[str]") -> bool:
    """True when the match is part of a longer identifier: glued to a letter
    or digit on either side (a hex digest such as a commit sha, a base64
    id), or inside a UUID. A digit run there is never a card or an account
    number, and flagging it would mask ids in the audit log and refuse a
    tool call that names one (a 40-hex commit sha holds a Luhn-valid run
    about once in two thousand)."""
    text, start, end = match.string, match.start(), match.end()
    if _alnum_at(text, start - 1) or _alnum_at(text, end):
        return True
    # A UUID holding [start, end) starts at most 36 characters before it.
    for uid in _UUID_RE.finditer(text, max(0, start - 36), min(len(text), end + 36)):
        if uid.start() <= start and end <= uid.end():
            return True
    return False


def _standalone(match: "re.Match[str]") -> bool:
    return not _embedded(match)


def _card_check(match: "re.Match[str]") -> bool:
    digits = "".join(ch for ch in match.group(0) if ch.isdigit())
    return card_iin(digits) and luhn(digits) and not _embedded(match)


def _iban_check(match: "re.Match[str]") -> bool:
    return iban_mod97(match.group(0))


def _ssn_check(match: "re.Match[str]") -> bool:
    return ssn_valid(match.group(1), match.group(3), match.group(4))


def _itin_check(match: "re.Match[str]") -> bool:
    return itin_valid(match.group(1), match.group(3), match.group(4))


def _stated_ssn_check(match: "re.Match[str]") -> bool:
    digits = "".join(ch for ch in match.group(1) if ch.isdigit())
    return len(digits) == 9 and ssn_valid(digits[:3], digits[3:5], digits[5:])


def _digit_count_at_least(group: int, minimum: int) -> Check:
    def check(match: "re.Match[str]") -> bool:
        return sum(ch.isdigit() for ch in _group_text(match, group)) >= minimum

    return check


_BANK_KEYWORD = re.compile(r"bank[ \t]{1,3}account|routing|aba", re.IGNORECASE)
_bank_digits = _digit_count_at_least(1, 6)


def _stated_bank_check(match: "re.Match[str]") -> bool:
    """A stated bank account: the keyword stands apart from the number
    ("ABA 021000021", not the "aba403756815" of a UUID or hex id)."""
    if not _bank_digits(match) or _embedded(match):
        return False
    keyword = _BANK_KEYWORD.match(match.group(0))
    return keyword is not None and not _alnum_at(match.group(0), keyword.end())


def _phone_digits(minimum: int, maximum: int) -> Check:
    def check(match: "re.Match[str]") -> bool:
        return minimum <= sum(ch.isdigit() for ch in match.group(0)) <= maximum

    return check


def _password_check(match: "re.Match[str]") -> bool:
    return _password_like(_group_text(match, 1))


def _secretish_check(match: "re.Match[str]") -> bool:
    return _secretish(_group_text(match, 1))


def _bearer_check(match: "re.Match[str]") -> bool:
    value = _group_text(match, 1)
    return not is_placeholder(value) and shannon_entropy(value) >= 3.0


# Names whose value is a secret when assigned (KEY=..., "secret": ...).
# Compared lower-cased with everything but letters and digits removed.
_SECRET_NAME_ENDINGS = (
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "apikey",
    "secretkey",
    "accesskey",
    "privatekey",
    "signingkey",
    "encryptionkey",
    "masterkey",
    "authkey",
    "credential",
    "credentials",
)
# Names that end like a secret but hold a paging or sync cursor: Google's
# nextPageToken, Microsoft Graph's $skiptoken and deltatoken, and the like.
_NOT_SECRET_NAME_PARTS = (
    "page",
    "skip",
    "next",
    "continuation",
    "cursor",
    "sync",
    "delta",
    "resume",
    "public",
    "publishable",
)
_ENV_KEY_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,62}_KEY$")


def secret_name(name: str) -> bool:
    """True when *name* (a variable, header or JSON key) names a secret:
    api_key, client_secret, GITHUB_TOKEN, password, MISTRAL_API_KEY. Paging
    tokens (nextPageToken, $skiptoken) and public keys are not."""
    raw = name.strip().lstrip("$@")
    flat = re.sub(r"[^a-z0-9]", "", raw.lower())
    if not flat or any(part in flat for part in _NOT_SECRET_NAME_PARTS):
        return False
    if _ENV_KEY_NAME.match(raw):
        return True
    return flat.endswith(_SECRET_NAME_ENDINGS)


def _assignment_check(match: "re.Match[str]") -> bool:
    name, value = match.group(1), match.group(2)
    if not secret_name(name) or is_placeholder(value):
        return False
    return len(value) >= 20 and shannon_entropy(value) >= 3.5


# ── the table ────────────────────────────────────────────────────────────


def _rx(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(pattern, re.ASCII | flags)


_I = re.IGNORECASE
_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]{0,6}\.?"
_STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Place|Pl|"
    r"Way|Terrace|Ter|Parkway|Pkwy|Circle|Cir|Highway|Hwy|Square|Sq|Trail|Trl|Loop|"
    r"Crescent|Close)"
)

C, P, B, G = Kind.credential, Kind.payment_card, Kind.bank_account, Kind.government_id
HIGH, MEDIUM, LOW, HINT = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW, Confidence.HINT

# Order matters only on ties (same start and end): the earlier rule names the
# finding, so specific formats come before generic ones.
RULES: tuple[Rule, ...] = (
    # ── provider keys ────────────────────────────────────────────────
    Rule("anthropic_api_key", C, "Anthropic API key",
         _rx(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,4096}"), HIGH),
    Rule("openai_project_key", C, "OpenAI API key",
         _rx(r"(?<![A-Za-z0-9_-])sk-proj-[A-Za-z0-9_-]{20,4096}"), HIGH),
    # OpenAI legacy, DeepSeek and other sk- keys. An alphanumeric body is
    # the audit log's old rule; one with - or _ needs a digit or mixed case,
    # so a kebab-case word after "sk-" is not a key.
    Rule("sk_api_key", C, "API key",
         _rx(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,4096}"), HIGH, check=_sk_body_ok),
    Rule("google_api_key", C, "Google API key", _rx(r"AIza[0-9A-Za-z_-]{35}"), HIGH),
    Rule("groq_api_key", C, "Groq API key", _rx(r"(?<![A-Za-z0-9_])gsk_[A-Za-z0-9]{20,4096}"), HIGH),
    Rule("xai_api_key", C, "xAI API key", _rx(r"(?<![A-Za-z0-9_-])xai-[A-Za-z0-9]{20,4096}"), HIGH),
    # ── connector tokens (connectors spec §4.3) ──────────────────────
    Rule("github_fine_grained_token", C, "GitHub token",
         _rx(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,4096}"), HIGH),
    Rule("github_token", C, "GitHub token", _rx(r"gh[opusr]_[A-Za-z0-9]{30,4096}"), HIGH),
    Rule("gitlab_token", C, "GitLab token", _rx(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,4096}"), HIGH),
    Rule("slack_token", C, "Slack token", _rx(r"(?<![A-Za-z0-9-])xox[abeoprs]-[A-Za-z0-9-]{10,4096}"), HIGH),
    Rule("slack_app_token", C, "Slack app token", _rx(r"(?<![A-Za-z0-9-])xapp-[A-Za-z0-9-]{10,4096}"), HIGH),
    Rule("notion_secret", C, "Notion secret", _rx(r"secret_[A-Za-z0-9]{32,4096}"), HIGH),
    Rule("notion_token", C, "Notion token", _rx(r"ntn_[A-Za-z0-9]{32,4096}"), HIGH),
    Rule("google_access_token", C, "Google access token", _rx(r"ya29\.[A-Za-z0-9_-]{20,4096}"), HIGH),
    Rule("google_refresh_token", C, "Google refresh token",
         _rx(r"(?<![A-Za-z0-9/])1//[A-Za-z0-9_-]{30,4096}"), HIGH),
    Rule("google_client_secret", C, "Google client secret",
         _rx(r"(?<![A-Za-z0-9_-])GOCSPX-[A-Za-z0-9_-]{20,4096}"), HIGH),
    # Microsoft: personal-account access tokens ("EwB..." blobs), personal
    # refresh tokens and codes ("M.C5xx_BAY.0.U...."), work and school
    # refresh tokens ("0.A..." / "1.A..."). Each needs a long unbroken body
    # and never ends on a dot, so prose and a sentence's full stop survive.
    Rule("microsoft_access_token", C, "Microsoft access token",
         _rx(r"(?<![A-Za-z0-9+/_-])EwB[A-Za-z0-9+/_-]{100,16384}={0,2}"), HIGH),
    Rule("microsoft_account_token", C, "Microsoft refresh token",
         _rx(r"(?<![A-Za-z0-9!*$._-])M\.[CR][0-9]{1,4}_[A-Za-z0-9]{2,8}\.[A-Za-z0-9!*$._-]{29,4096}[A-Za-z0-9!*$_-]"), HIGH),
    Rule("microsoft_entra_refresh_token", C, "Microsoft refresh token",
         _rx(r"(?<![A-Za-z0-9_*.-])[01]\.A[A-Za-z0-9_*.-]{99,4096}[A-Za-z0-9_*-]"), HIGH),
    # A JWT or JWE (header.payload.signature and beyond), or a bare header.
    # It may follow a %XX escape (a JWT inside a URL-encoded link).
    Rule("jwt", C, "sign-in token (JWT)",
         _rx(r"(?:(?<![A-Za-z0-9_-])|(?<=%[0-9A-Fa-f]{2}))eyJ[A-Za-z0-9_-]{10,16384}\.[A-Za-z0-9_-]{0,16384}(?:\.[A-Za-z0-9_-]{1,16384}){0,3}"), HIGH),
    Rule("aws_access_key", C, "AWS access key", _rx(r"AKIA[A-Z0-9]{16}"), HIGH),
    Rule("aws_temporary_access_key", C, "AWS access key",
         _rx(r"(?<![A-Za-z0-9])ASIA[A-Z0-9]{16}(?![A-Za-z0-9])"), HIGH),
    Rule("telegram_bot_token", C, "Telegram bot token",
         _rx(r"(?<![0-9])[0-9]{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"), HIGH),
    Rule("canvas_token", C, "Canvas access token", _rx(r"(?<![0-9])[0-9]{4,5}~[A-Za-z0-9]{60,4096}"), HIGH),
    # The whole block when its body is plain base64 (line breaks raw, or
    # escaped as \n inside JSON, as a tool result reaches the model).
    Rule("private_key", C, "private key",
         _rx(r"-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY-----(?:[A-Za-z0-9+/=\s]|\\[nrt]){0,16384}(?:-----END (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY-----)?"), HIGH),
    # ── credentials in context ────────────────────────────────────────
    # The signature (or token) of a pre-signed link: S3, Google Cloud,
    # Azure SAS, Canvas file links.
    Rule("signed_link_signature", C, "signed link signature",
         _rx(r"(?<=[?&])(?:x-amz-signature|x-amz-security-token|x-goog-signature|x-goog-credential|sig|signature|verifier)=([A-Za-z0-9%/+=_.-]{16,4096})", _I),
         MEDIUM, group=1),
    Rule("link_password", C, "password in a link",
         _rx(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s/:@]{1,128}:([^\s/@]{1,256})@"), MEDIUM, group=1),
    Rule("authorization_header", C, "authorization header",
         _rx(r"(?<![A-Za-z0-9_-])(?:proxy-)?authorization[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?(?:bearer|basic|token|bot)[ \t]{1,3}([A-Za-z0-9+/=._~-]{8,4096})", _I),
         MEDIUM, group=1),
    Rule("bearer_token", C, "bearer token",
         _rx(r"(?<![A-Za-z0-9])[Bb]earer[ \t]{1,3}([A-Za-z0-9+/._~-]{20,4096}=*)"), MEDIUM, group=1, check=_bearer_check),
    # KEY=value, "secret": "value", password: value, with a random-looking
    # value (Shannon entropy at least 3.5 bits per character, 20+ chars):
    # catches keys with no prefix, such as Mistral's.
    Rule("secret_assignment", C, "secret value",
         _rx(r"(?<![A-Za-z0-9_.$-])(\$?[A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?[ \t]{0,3}(?::=|=>|[:=])[ \t]{0,3}[\"']?([A-Za-z0-9+/_.~!@#$%^&*-]{20,512}={0,2})"),
         MEDIUM, group=2, check=_assignment_check),
    # A password stated outright with a value that looks like one ("password
    # is Tr0ub4dor&3"); "password was changed" is left alone. Meeting
    # passcodes are deliberately not here.
    Rule("stated_password", C, "password",
         _rx(r"\b(?:password|passwd|passphrase)\b[ \t]{0,3}(?:is|was|=|:)[ \t]{0,3}[\"']?([^\s\"']{4,128})", _I),
         MEDIUM, group=1, check=_password_check),
    Rule("stated_api_secret", C, "API key or token",
         _rx(r"\b(?:api[ _-]?key|secret[ _-]?key|client[ _-]?secret|access[ _-]?token|auth[ _-]?token|bearer[ _-]?token|refresh[ _-]?token|bot[ _-]?token|private[ _-]?key|recovery[ _-]?code|app[ _-]?password)\b[ \t]{0,3}(?:is|was|=|:)[ \t]{0,3}[\"']?([^\s\"'=:,;]{8,512}={0,2})", _I),
         MEDIUM, group=1, check=_secretish_check),
    Rule("stated_pin_or_card_code", C, "PIN or card security code",
         _rx(r"\b(?:pin(?:[ \t]{1,3}(?:code|number))?|cvv2?|cvc2?|csc|security[ \t]{1,3}code)\b[ \t]{0,3}(?:is|was|=|:|#)[ \t]{0,3}([0-9]{3,8})(?![0-9])", _I),
         MEDIUM, group=1),
    # memory.remember's loose rule: any password, PIN, key or token stated
    # outright, whatever its value. Memory only (HINT): a false refusal
    # there costs a reworded memory, while a stored secret goes into every
    # future prompt.
    Rule("stated_secret_loose", C, "password or key",
         _rx(r"\b(?:password|passcode|passphrase|passwd|pin(?:\s{1,3}code)?|cvv|cvc|security\s{1,3}code|api[\s_-]?key|secret[\s_-]?key|client[\s_-]?secret|private[\s_-]?key|(?:access|auth|bearer|bot|refresh|api)?[\s_-]?token|recovery\s{1,3}(?:code|phrase)|seed\s{1,3}phrase)\s{0,8}(?:is|was|=|:)\s{0,8}\S", _I),
         HINT),
    # ── payment cards ─────────────────────────────────────────────────
    # Luhn plus issuer prefix: order numbers, chat ids and timestamps stay
    # readable. One rule per grouping, so a trailing number (an expiry, a
    # CVV) never spoils the grouping it follows.
    Rule("card_number", P, "card number", _rx(r"(?<![0-9])[0-9]{13,19}(?![0-9])"), HIGH, check=_card_check),
    Rule("card_number_grouped", P, "card number",
         _rx(r"(?<![0-9-])[0-9]{4}([ -])[0-9]{4}\1[0-9]{4}\1[0-9]{4}(?![0-9])"), HIGH, check=_card_check),
    Rule("card_number_grouped_19", P, "card number",
         _rx(r"(?<![0-9-])[0-9]{4}([ -])[0-9]{4}\1[0-9]{4}\1[0-9]{4}\1[0-9]{3}(?![0-9])"), HIGH, check=_card_check),
    Rule("card_number_4_6_5", P, "card number",
         _rx(r"(?<![0-9-])[0-9]{4}([ -])[0-9]{6}\1[0-9]{4,5}(?![0-9])"), HIGH, check=_card_check),
    # The audit log's and memory's broad rules, kept for compatibility at
    # LOW: any 13-19 digit run, and a card written in groups.
    # None inside a longer identifier (a UUID, a hex digest): _standalone.
    Rule("card_length_number", P, "card number", _rx(r"\b[0-9]{13,19}\b"), LOW, check=_standalone),
    Rule("card_groups_loose", P, "card number",
         _rx(r"(?<![0-9])[0-9]{4}(?:[ -][0-9]{4}){2}[ -][0-9]{1,7}(?![0-9])"), LOW, check=_standalone),
    Rule("card_groups_amex_loose", P, "card number",
         _rx(r"(?<![0-9])[0-9]{4}[ -][0-9]{6}[ -][0-9]{4,5}(?![0-9])"), LOW, check=_standalone),
    # ── bank accounts ─────────────────────────────────────────────────
    Rule("iban", B, "IBAN",
         _rx(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), HIGH, check=_iban_check),
    Rule("stated_bank_account", B, "bank account number",
         _rx(r"\b(?:bank[ \t]{1,3}account|routing|ABA)(?:[ \t]{1,3}(?:number|no\.?|num|#))?[ \t]{0,3}(?:is|:|#|=)?[ \t]{0,3}([0-9][0-9 -]{4,20}[0-9])(?![0-9])", _I),
         MEDIUM, group=1, check=_stated_bank_check),
    # ── government ids ────────────────────────────────────────────────
    Rule("us_ssn", G, "US Social Security number",
         _rx(r"(?<![0-9-])([0-9]{3})([- ])([0-9]{2})\2([0-9]{4})(?![0-9-])"), MEDIUM, check=_ssn_check),
    Rule("us_itin", G, "US ITIN",
         _rx(r"(?<![0-9-])([0-9]{3})([- ])([0-9]{2})\2([0-9]{4})(?![0-9-])"), MEDIUM, check=_itin_check),
    Rule("us_ssn_stated", G, "US Social Security number",
         _rx(r"\b(?:SSN|social[ \t]{1,3}security(?:[ \t]{1,3}(?:number|no\.?|#))?)[ \t]{0,3}(?:is|:|#|=)?[ \t]{0,3}([0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4})(?![0-9])", _I),
         HIGH, group=1, check=_stated_ssn_check),
    Rule("passport_number", G, "passport number",
         _rx(r"\bpassport(?:[ \t]{1,3}(?:number|no\.?|num|#))?[ \t]{0,3}(?:is|:|#|=)?[ \t]{0,3}([A-Z0-9]{6,12})\b", _I),
         MEDIUM, group=1, check=_digit_count_at_least(1, 6)),
    Rule("drivers_licence_number", G, "driver's licence number",
         _rx(r"\b(?:driver'?s?|driving)[ \t]{1,3}licen[cs]e(?:[ \t]{1,3}(?:number|no\.?|num|#))?[ \t]{0,3}(?:is|:|#|=)?[ \t]{0,3}([A-Z0-9][A-Z0-9-]{4,18}[A-Z0-9])\b", _I),
         MEDIUM, group=1, check=_digit_count_at_least(1, 4)),
    # ── contact details (pseudonymised for cloud models, never masked on
    #    channels) ───────────────────────────────────────────────────────
    Rule("email", Kind.email, "email",
         _rx(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}(?![A-Za-z0-9-])"), MEDIUM),
    Rule("phone_nanp", Kind.phone, "phone",
         _rx(r"(?<![\w+.-])(?:\+?1[ .-]?)?(?:\([2-9][0-9]{2}\)[ .-]?|[2-9][0-9]{2}[ .-])[2-9][0-9]{2}[ .-][0-9]{4}(?![\w-])"), MEDIUM),
    Rule("phone_e164", Kind.phone, "phone",
         _rx(r"(?<![\w+])\+[1-9](?:[ .-]?[0-9]){7,14}(?![\w-])"), MEDIUM, check=_phone_digits(8, 15)),
    Rule("us_street_address", Kind.street_address, "address",
         _rx(r"\b[0-9]{1,6}[A-Za-z]?[ \t]{1,3}(?:[NSEW]\.?[ \t]{1,3})?(?:[A-Z][A-Za-z0-9'.-]{0,30}[ \t]{1,3}){1,4}" + _STREET_SUFFIX
             + r"\b\.?(?:[ \t]{1,3}(?:NE|NW|SE|SW|N|S|E|W)\b)?(?:,?[ \t]{1,3}(?:Apt|Apartment|Suite|Ste|Unit|#)\.?[ \t]{0,3}[A-Za-z0-9-]{1,8})?"),
         MEDIUM),
    Rule("birth_date", Kind.birth_date, "birth date",
         _rx(r"\b(?:DOB|D\.O\.B\.?|date[ \t]{1,3}of[ \t]{1,3}birth|birth[ \t]{0,3}date|born(?:[ \t]{1,3}on)?)[ \t]{0,3}[:=-]?[ \t]{0,3}"
             r"((?:[0-9]{1,2}[/.-][0-9]{1,2}[/.-](?:[0-9]{4}|[0-9]{2}))|(?:[0-9]{4}-[0-9]{2}-[0-9]{2})|"
             r"(?:" + _MONTH + r"[ \t]{1,3}[0-9]{1,2}(?:st|nd|rd|th)?,?[ \t]{1,3}[0-9]{4})|"
             r"(?:[0-9]{1,2}(?:st|nd|rd|th)?[ \t]{1,3}(?:of[ \t]{1,3})?" + _MONTH + r",?[ \t]{1,3}[0-9]{4}))(?![0-9])", _I),
         MEDIUM, group=1),
    # ── appended formats (RULES is append-only) ───────────────────────
    # top10:flashcards_quizzes: a study deck's one-time download token
    # (services/study/export.py: "cse_" + secrets.token_urlsafe(32)). LOW on
    # purpose: the audit log and the logs hide it, but the model and the
    # chat must still carry the link to the user (it works once, for 10
    # minutes), so the model floor, channels and tool arguments leave it.
    Rule("study_export_token", C, "export link token",
         _rx(r"(?<![A-Za-z0-9_-])cse_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"), LOW),
)

_RULE_ORDER = {rule.id: index for index, rule in enumerate(RULES)}

# The fixed prefixes of the prefixed credential formats in RULES, for a caller
# that must reject a short string merely shaped like one (a vendor error
# code "ghp_abc"): see looks_like_credential.
CREDENTIAL_PREFIXES: tuple[str, ...] = (
    "sk-",
    "xox",
    "xapp-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "secret_",
    "ntn_",
    "ya29.",
    "1//",
    "gocspx-",
    "aiza",
    "gsk_",
    "xai-",
    "bearer",
    "eyj",
    "-----begin",
)


def _rule_matches(text: str, rule: Rule) -> Iterable["re.Match[str]"]:
    """Every match of *rule* that passes its check. After a match the check
    rejects, the search goes on from the next character rather than past
    the match, so a rejected match never hides one that overlaps it ("is:
    TOKEN=..." must still find TOKEN=...). Starts are sparse by design (see
    the module docstring), so this stays linear."""
    if rule.check is None:
        yield from rule.pattern.finditer(text)
        return
    pos = 0
    length = len(text)
    while pos <= length:
        match = rule.pattern.search(text, pos)
        if match is None:
            return
        if rule.check(match):
            yield match
            pos = match.end() if match.end() > match.start() else match.start() + 1
        else:
            pos = match.start() + 1


def _candidates(text: str, rules: Iterable[Rule]) -> list[Finding]:
    found: list[Finding] = []
    for rule in rules:
        for match in _rule_matches(text, rule):
            start, end = match.span(rule.group)
            if start < 0 or end <= start:
                continue
            found.append(Finding(rule.id, rule.kind, rule.label, start, end, rule.confidence))
    return found


def _merge(candidates: list[Finding]) -> list[Finding]:
    """Leftmost-longest, non-overlapping: the earliest start wins (then the
    longest, the most confident, the earlier rule), widened over whatever
    it overlaps."""
    ordered = sorted(
        candidates,
        key=lambda f: (f.start, -f.end, -int(f.confidence), _RULE_ORDER.get(f.rule, 0)),
    )
    merged: list[Finding] = []
    for finding in ordered:
        if merged and finding.start < merged[-1].end:
            last = merged[-1]
            if finding.end > last.end or finding.confidence > last.confidence:
                merged[-1] = Finding(
                    last.rule,
                    last.kind,
                    last.label,
                    last.start,
                    max(last.end, finding.end),
                    max(last.confidence, finding.confidence),
                )
            continue
        merged.append(finding)
    return merged


def rules_for(
    kinds: Optional[Iterable[Kind]] = None, min_confidence: Confidence = Confidence.LOW
) -> tuple[Rule, ...]:
    """The rules find() runs for *kinds* at *min_confidence* or above."""
    wanted = frozenset(kinds) if kinds is not None else None
    return tuple(
        rule
        for rule in RULES
        if rule.confidence >= min_confidence and (wanted is None or rule.kind in wanted)
    )


def find(
    text: str,
    *,
    kinds: Optional[Iterable[Kind]] = None,
    min_confidence: Confidence = Confidence.LOW,
) -> list[Finding]:
    """Every finding of *kinds* (all when None) at *min_confidence* or
    above in *text*, leftmost-longest and non-overlapping, in order.
    Raises ``ScanTooLarge`` above ``MAX_SCAN_CHARS`` characters and
    TypeError for anything but a str."""
    if not isinstance(text, str):
        raise TypeError("find() scans text only")
    if len(text) > MAX_SCAN_CHARS:
        raise ScanTooLarge(f"text of {len(text)} characters is over the {MAX_SCAN_CHARS} limit")
    if not text:
        return []
    return _merge(_candidates(text, rules_for(kinds, min_confidence)))


def looks_like_credential(text: str) -> bool:
    """True when *text* holds a credential at MEDIUM or above, or starts
    with one of the credential prefixes (a vendor error code shaped like a
    token: "xoxb-test", "ghp_abc"). A scan failure counts as True."""
    stripped = text.strip().lower()
    if stripped.startswith(CREDENTIAL_PREFIXES):
        return True
    try:
        return bool(find(text, kinds=(Kind.credential,), min_confidence=Confidence.MEDIUM))
    except Exception:  # noqa: BLE001 - fail closed: an unreadable value counts as a credential
        return True


def with_article(label: str) -> str:
    """"a GitHub token", "an AWS access key", "an IBAN"."""
    return ("an " if label[:1].upper() in "AEIOU" else "a ") + label


__all__ = [
    "CONTACT_KINDS",
    "CREDENTIAL_PREFIXES",
    "Confidence",
    "Finding",
    "Kind",
    "MAX_SCAN_CHARS",
    "RULES",
    "Rule",
    "SECRET_KINDS",
    "ScanTooLarge",
    "card_iin",
    "find",
    "iban_mod97",
    "is_placeholder",
    "itin_valid",
    "looks_like_credential",
    "luhn",
    "rules_for",
    "secret_name",
    "shannon_entropy",
    "ssn_valid",
    "with_article",
]
