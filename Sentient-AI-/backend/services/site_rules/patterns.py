"""What a typed site means as a rule, and which hosts a rule covers.

A rule's pattern is one of two shapes, always lower-case ASCII (IDNA):

- ``"chase.com"``: that exact host and nothing else;
- ``"*.chase.com"``: the site and every subdomain at any depth
  (``chase.com``, ``secure.chase.com``, ``a.b.chase.com``), never a
  look-alike suffix (``evilchase.com``, ``chase.com.evil.com``).

This is the meaning ``core.network_security.host_matches`` gives the same
two shapes, and ``PatternIndex`` answers "which pattern covers this host"
the way ``core.network_security.match_host_pattern`` does: the exact entry
first, then the ``*.`` entry with the longest suffix
(``tests/test_site_rules_patterns.py`` asserts the two agree).

Why it exists: the owner types sites in every shape ("https://www.Chase.com/x",
"*.chase.com", "bücher.de", "user@site:8443"), the browser reports hosts in
canonical form ("xn--bcher-kva.de"), and the model writes URLs in any form.
``host_of`` reduces all of them to one host string, never raising, so a rule
cannot be walked around by spelling a host differently (case, trailing
dot, port, userinfo, percent-encoding, full-width and other compatibility
letters, invisible characters browsers drop, IDNA, the ``0x7f.1`` forms of
an IPv4 address, ``blob:`` and ``view-source:`` wrappers, backslashes and
missing slashes after ``https:``).
``parse_site`` is stricter: it refuses, with a plain sentence from
``messages``, anything that is not a site the owner can sensibly name.

Every reading is linear in the length of the URL, however hostile: the
guard asks on the event loop for every frame a page opens, and a URL may be
two megabytes long.

Pure: standard library only, plus the shared look-alike facts
(``services/security/lookalike.py``). No network, no I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from typing import Callable, Generic, Iterable, Literal, Mapping, Optional, TypeVar
from urllib.parse import unquote

# Look-alike facts and the two-part public suffixes come from the one shared
# look-alike module (scaffold A6), the same facts the checkout's merchant
# check reads; only the facts are used here, never its checkout wording.
from services.security.lookalike import TWO_PART_SUFFIXES, decode_host, mixed_script_reading
from services.site_rules import messages
from services.site_rules.sensitive_sites import PROTECTED_PATTERNS

KINDS: tuple[str, ...] = ("blocked", "always_ask", "trusted")
RuleKind = Literal["blocked", "always_ask", "trusted"]
TARGET_TYPES: tuple[str, ...] = ("host", "category")
MAX_HOST_RULES = 500
MAX_HOST_CHARS = 253

# When two rules of the same reach meet (a site on two built-in lists, two
# stored rows that normalise to one pattern), the stricter kind wins:
# Blocked over Always ask over Trusted. Reach decides first: an owner rule
# beats the built-in list, and an exact host beats the longest "*." suffix
# (snapshot.py), so "Trust docs.example.com" still overrides "Block
# *.example.com".
_STRICTNESS: Mapping[str, int] = {"blocked": 2, "always_ask": 1, "trusted": 0}

# WHATWG URL parsing removes tabs and newlines anywhere and trims C0 controls
# and spaces at both ends; browsers do, so the host seen here must too.
_TAB_OR_NEWLINE = re.compile(r"[\t\n\r]")
_C0_AND_SPACE = "".join(chr(code) for code in range(0x21))
_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(.*)$", re.DOTALL)
# Schemes whose URLs carry a host after "//" (WHATWG "special" schemes,
# without "file", whose host is a file share and never a web site).
_WEB_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})
# Wrappers whose page belongs to the inner URL's site.
_WRAPPER_SCHEMES = frozenset({"blob", "view-source"})
_AUTHORITY_END = re.compile(r"[/\\?#]")
_DIGITS = re.compile(r"[0-9]*")
# Characters that never belong in a stored pattern's host: a glob, an
# escape, userinfo, a path, query or fragment, a port, a space.
_NOT_IN_PATTERN = re.compile(r"[*%@/\\?#:\s]")

# Code points a browser drops from a host before it looks the host up
# (UTS #46 "ignored": soft hyphen, zero-width space, word joiner, the
# invisible operators, variation selectors, Hangul and Khmer fillers, ...).
# The list is what Chromium's URL parser drops, checked code point by code
# point; "c<U+3164>hase.com" opens chase.com, so it must read as chase.com.
_IGNORED_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200B),
    (0x2060, 0x2064),
    (0x206A, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0100, 0xE01EF),
)
# Letters newer than this Python's Unicode tables (15.0) that Chromium
# already maps (Unicode 16): outlined Latin letters and digits read as plain
# ones, and new capital letters read as their small forms. Without them
# "<outlined c>hase.com" would open chase.com and read as something else.
_NEWER_LETTERS: dict[int, str] = {
    0x1C89: chr(0x1C8A),
    0xA7CB: chr(0x0264),
    0xA7CC: chr(0xA7CD),
    0xA7CE: chr(0xA7CF),
    0xA7D2: chr(0xA7D3),
    0xA7D4: chr(0xA7D5),
    0xA7DA: chr(0xA7DB),
    0xA7DC: chr(0x019B),
    0xA7F1: "s",
    **{0x16EA0 + offset: chr(0x16EBB + offset) for offset in range(25)},
    **{0x1CCD6 + offset: chr(ord("a") + offset) for offset in range(26)},
    **{0x1CCF0 + offset: chr(ord("0") + offset) for offset in range(10)},
}
# Code points whose mapping holds a full stop: the dot leaders and the
# ellipses (U+2024..U+2026, U+FE19, U+FE30), the small and vertical full
# stops (U+FE12, U+FE52), the digits with a full stop (U+2488..U+249B
# "1."..."20.", U+1F100 "0.") and the squared "a.m.", "co." and "p.m."
# (U+33C2, U+33C7, U+33D8). They are mapped before a host is split into
# labels, so no label maps to a full stop of its own. Each is a starter
# whose mapping composes with nothing on either side, so mapping it alone
# is mapping it in place. tests/test_site_rules_patterns.py checks the
# list against every code point.
_DOTTED: tuple[int, ...] = (
    0x2024,
    0x2025,
    0x2026,
    *range(0x2488, 0x249C),
    0x33C2,
    0x33C7,
    0x33D8,
    0xFE12,
    0xFE19,
    0xFE30,
    0xFE52,
    0x1F100,
)
_HOST_MAP: dict[int, Optional[str]] = {
    **{code: None for first, last in _IGNORED_RANGES for code in range(first, last + 1)},
    **_NEWER_LETTERS,
    **{
        code: unicodedata.normalize("NFKC", chr(code)).casefold().replace(chr(0x3002), ".")
        for code in _DOTTED
    },
    0x1E9E: "ß",  # capital sharp s: browsers read it as ß, and keep ß
    0x3002: ".",
    0xFF0E: ".",
    0xFF61: ".",
}
# Letters UTS #46 keeps as they are (nontransitional, as Chromium reads
# them) where case folding would change them: "faß.de" opens xn--fa-hia.de.
_KEPT_AS_TYPED = re.compile("([ßς])")
# A stand-in label (see _host_labels) is longer than any host a rule can
# name, so a suffix that contains one never matches a rule.
_STAND_IN_LENGTH = MAX_HOST_CHARS + 1
# Mapping a label (NFKC) is quadratic in a run of combining marks out of
# canonical order (CPython sorts them by insertion), so a label longer than
# this is never normalised as a whole. Nothing is lost: NFKC can at most
# shrink a label to a quarter (the longest canonical decomposition is four
# code points), so such a label still reads longer than any host a rule
# can name. Eight times the stand-in leaves a wide margin.
_LABEL_MAP_LIMIT = 8 * _STAND_IN_LENGTH
# A label the owner may type, after IDNA: letters, digits, "-" and "_".
_OWNER_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
# IDNA 2003 and transitional UTS #46 spell these letters one way ("faß.de"
# -> fass.de), Chromium another (xn--fa-hia.de, which host_of follows), so
# what the owner meant by them is ambiguous: the owner types the xn-- form.
_TWO_SPELLINGS = re.compile("[ßς‌‍ẞ]")
_AUDIT_KEY_DOMAIN = b"crawler-site-rules\x00"


class SiteRuleError(Exception):
    """A typed site or rule the owner cannot have; ``.status`` is 422 or 409,
    ``str()`` is the plain reason shown as is on the Security tab."""

    def __init__(self, message: str, *, status: int = 422) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def as_kind(value: object) -> Optional[RuleKind]:
    """*value* as a rule kind, or None when it is not one."""
    if value == "blocked":
        return "blocked"
    if value == "always_ask":
        return "always_ask"
    if value == "trusted":
        return "trusted"
    return None


def strictness(kind: Optional[str]) -> int:
    """2 for Blocked, 1 for Always ask, 0 for Trusted, -1 for no rule."""
    return _STRICTNESS.get(kind or "", -1)


def stricter(a: RuleKind, b: RuleKind) -> RuleKind:
    """The stricter of two kinds (Blocked > Always ask > Trusted); *a* on a tie."""
    return b if strictness(b) > strictness(a) else a


# --- Hosts -----------------------------------------------------------------


def host_of(url_or_host: object) -> str:
    """The ASCII (IDNA), lower-case host of a URL or bare host: no port, no
    userinfo, no trailing dot; an IPv4 address in dotted form, an IPv6
    address compressed without brackets. "" when there is none (``about:``,
    ``data:``, ``file:``, ``chrome-error:``, an empty string, not a string).
    Never raises."""
    if not isinstance(url_or_host, str):
        return ""
    try:
        authority = _authority(_TAB_OR_NEWLINE.sub("", url_or_host).strip(_C0_AND_SPACE))
        if authority is None:
            return ""
        return _normalise_host(_without_userinfo_and_port(authority))
    except (ValueError, UnicodeError):
        return ""


def _is_port(rest: str) -> bool:
    """Whether what follows "name:" is a port ("8080", "8080/x", or nothing
    at all), which makes "name" a host rather than a scheme. "//x" is not."""
    if rest == "":
        return True
    head = _AUTHORITY_END.split(rest, 1)[0]
    return head != "" and _DIGITS.fullmatch(head) is not None


def _is_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _authority(text: str) -> Optional[str]:
    """The "user@host:port" part of *text*, or None for a URL that has no
    web host."""
    if not text:
        return None
    first = _AUTHORITY_END.split(text, 1)[0]
    if ":" in first and _is_ipv6(first.strip("[]")):
        return first  # a bare IPv6 address ("fe80::1" would look like a scheme)
    for _ in range(4):  # "blob:https://site/x", "view-source:https://site/"
        wrapped = _SCHEME.match(text)
        if wrapped is None or wrapped.group(1).lower() not in _WRAPPER_SCHEMES:
            break
        text = wrapped.group(2).strip(_C0_AND_SPACE)
    match = _SCHEME.match(text)
    if match is not None:
        if match.group(1).lower() in _WEB_SCHEMES:
            # Browsers read "https:site", "https:/site" and "https:\\site"
            # as "https://site"; so does this.
            return _AUTHORITY_END.split(match.group(2).lstrip("/\\"), 1)[0]
        if not _is_port(match.group(2)):
            return None  # about:, data:, mailto:, javascript:, file:, chrome-error:
    return first  # a bare host, maybe with a port ("example.com:8080/x")


def _without_userinfo_and_port(authority: str) -> str:
    host = authority.rpartition("@")[2]
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end > 0 else ""
    if host.count(":") == 1:
        return host.partition(":")[0]
    return host  # no port, or a bare IPv6 address


def _nfkc_casefold(text: str) -> str:
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", text).casefold())


def _mapped_label(label: str) -> str:
    """One label of a host (``_HOST_MAP`` already applied, the host already
    split on its full stops) mapped the way Chromium maps a host (UTS #46,
    nontransitional): compatibility forms folded (NFKC), case folded, "ß"
    and "ς" kept. Python's own IDNA codec cannot be used for this: it
    knows Unicode 3.2 only, so it leaves "ᶜhase.com" (a modifier letter c,
    which Chromium opens as chase.com) unmapped.

    Mapping label by label is mapping the whole host: "." is a starter that
    neither decomposes nor composes with anything, so NFKC never reaches
    across it, and every code point that maps to a full stop was mapped
    before the split (``_DOTTED``), so no label maps to two. Callers keep
    each label under _LABEL_MAP_LIMIT (see _long_label), which keeps NFKC's
    sorting of combining marks bounded."""
    if label.isascii():
        return label.lower()
    mapped = "".join(
        part if part in ("ß", "ς") else _nfkc_casefold(part)
        for part in _KEPT_AS_TYPED.split(label)
    )
    return mapped.replace(chr(0x3002), ".")  # never reached today: U+FE12 is in _DOTTED


def _long_label(label: str) -> Optional[str]:
    """A label over _LABEL_MAP_LIMIT, mapped, when every one of its letters
    maps to ASCII on its own (a run of full-width digits that is the last
    part of an IPv4 address, written with a thousand leading zeros), else
    None: it then reads longer than any host a rule can name, which a
    stand-in says without normalising it. Letters that map to ASCII are
    starters that compose with nothing, so mapping them one by one is
    mapping the label; only distinct letters are mapped (a few thousand
    code points map to ASCII at all), and the label is rewritten in one
    linear ``translate``."""
    table: dict[int, str] = {}
    for char in set(label):
        mapped = _mapped_label(char)
        if not mapped.isascii():
            return None
        table[ord(char)] = mapped
    return label.translate(table)


def _stand_in(text: str) -> str:
    """One ASCII label for *text*, longer than any host a rule can name."""
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return ("xn--" + digest).ljust(_STAND_IN_LENGTH, "0")


def _ascii_label(label: str) -> str:
    """A mapped label in ASCII: punycode for one that is not, a stand-in for
    one longer than any host (Python's punycode encoder is quadratic in a
    label's distinct letters)."""
    if label.isascii():
        return label
    if len(label) > MAX_HOST_CHARS:
        return _stand_in(label)
    return "xn--" + label.encode("punycode").decode("ascii")


def _host_labels(text: str) -> list[str]:
    """The ASCII labels of a non-ASCII host (*text*, percent-decoded), mapped
    the way Chromium maps a host and read from the right.

    Only the last MAX_HOST_CHARS characters of a host can be named by a rule
    (a longer host never resolves), so a label is mapped and punycoded only
    while it may still be part of such a suffix; past that point the labels
    on the left are kept as one label when they are ASCII and written as
    one stand-in otherwise. The exception is a host of at most four labels,
    which may still be an IPv4 address (``_whatwg_ipv4``): all of them are
    read. Each label is normalised on its own and only up to
    _LABEL_MAP_LIMIT, so the work stays linear in the host however a
    hostile page or model spells it (NFKC on a whole host is quadratic in a
    run of combining marks)."""
    raw = text.translate(_HOST_MAP).strip(".").split(".")
    out: list[str] = []  # right to left
    suffix = -1  # characters already read on the right, with their dots
    for index in range(len(raw) - 1, -1, -1):
        if suffix >= MAX_HOST_CHARS and len(out) + index + 1 > 4:
            rest = ".".join(raw[: index + 1])
            out.append(rest.lower() if rest.isascii() else _stand_in(rest))
            break
        label = raw[index]
        mapped = _mapped_label(label) if len(label) <= _LABEL_MAP_LIMIT else _long_label(label)
        parts = [_stand_in(label)] if mapped is None else mapped.split(".")
        for part in reversed(parts):
            if not out and not part:
                continue  # a trailing empty label (defence in depth: see _DOTTED)
            ascii_part = _ascii_label(part)
            out.append(ascii_part)
            suffix += len(ascii_part) + 1
    while out and not out[-1]:
        out.pop()  # a leading empty label (defence in depth)
    out.reverse()
    return out


def _ipv4_number(part: str) -> Optional[int]:
    """One part of a WHATWG IPv4 address: decimal, 0x hex or 0-led octal."""
    if not part:
        return None
    try:
        if part[:2] in ("0x", "0X"):
            return int(part[2:], 16) if part[2:] else 0
        if len(part) > 1 and part[0] == "0":
            return int(part[1:], 8)
        return int(part, 10) if part.isdigit() and part.isascii() else None
    except ValueError:
        return None


def _whatwg_ipv4(labels: list[str]) -> Optional[str]:
    """The dotted IPv4 address a browser reads in *labels* ("0x7f.1",
    "2130706433", "127.1" are all 127.0.0.1), or None for a domain."""
    last = labels[-1]
    ends_in_number = (last.isdigit() and last.isascii()) or re.fullmatch(
        r"0[xX][0-9a-fA-F]*", last
    ) is not None
    if not ends_in_number or len(labels) > 4:
        return None
    numbers = [_ipv4_number(part) for part in labels]
    if any(n is None for n in numbers):
        return None
    values = [n for n in numbers if n is not None]
    if any(n > 255 for n in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return None
    address = values[-1]
    for index, n in enumerate(values[:-1]):
        address += n * 256 ** (3 - index)
    return str(ipaddress.IPv4Address(address))


def _normalise_host(host: str) -> str:
    host = host.strip()
    if not host:
        return ""
    if ":" in host:  # only an IPv6 literal keeps a colon at this point
        if "%" in host:
            return ""  # a zone id ("fe80::1%eth0"): browsers refuse it in a URL
        try:
            return ipaddress.IPv6Address(host).compressed
        except ValueError:
            return ""
    # Browsers percent-decode a host and map it (UTS #46: invisible
    # characters, width, case, IDNA) before they compare or resolve it.
    # Empty labels at either end are dropped ("chase.com." is chase.com).
    text = unquote(host)
    if text.isascii():
        # The usual case (the browser hands over hosts already in ASCII;
        # nothing in _HOST_MAP is ASCII): only the last labels can make an
        # IPv4 address, so only they are split.
        text = text.lower().strip(".")
        if not text:
            return ""
        return _whatwg_ipv4(text.rsplit(".", 4)) or text
    labels = _host_labels(text)
    if not labels:
        return ""
    return _whatwg_ipv4(labels) or ".".join(labels)


def is_ip_address(host: str) -> bool:
    """Whether *host* (normalised) is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


# --- Patterns --------------------------------------------------------------


def is_wildcard(pattern: str) -> bool:
    """Whether *pattern* covers the site and its subdomains ("*.example.com")."""
    return pattern.startswith("*.")


def pattern_base(pattern: str) -> str:
    """The host a pattern is named after: "*.chase.com" -> "chase.com"."""
    return pattern[2:] if pattern.startswith("*.") else pattern


def _pattern_shaped(base: str) -> bool:
    """Whether *base* (a pattern without its "*.") can only be a host: no
    glob, escape, userinfo, path, query, port or space; an IPv6 address
    keeps its colons."""
    stripped = base.strip("[]")
    if ":" in stripped and _is_ipv6(stripped):
        return True
    return _NOT_IN_PATTERN.search(base) is None


def normalise_pattern(pattern: object) -> str:
    """*pattern* in stored form (lower-case ASCII host, or "*." plus one), or
    "" when it is not a pattern: a "*" anywhere but a leading "*." (spelled
    "%2a" or with a full-width star too), a percent-escape (stored patterns
    are decoded), a path, port or userinfo, or a host longer than
    MAX_HOST_CHARS (which never resolves). Lenient on purpose otherwise: it
    reads rows however they were written; the owner's input goes through
    the stricter ``parse_site``."""
    if not isinstance(pattern, str):
        return ""
    text = pattern.strip()
    wildcard = text.startswith("*.")
    base = text[2:] if wildcard else text
    if not base or not _pattern_shaped(base):
        return ""
    host = host_of(base)
    # Checked again once decoded and mapped: a full-width star or colon
    # would otherwise come back as "*" or ":" ("*.com" covers every .com).
    if not host or len(host) > MAX_HOST_CHARS or not _pattern_shaped(host):
        return ""
    return f"*.{host}" if wildcard else host


def _covers(host: str, pattern: str) -> bool:
    """Both already normalised."""
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def pattern_matches(host: str, pattern: str) -> bool:
    """Whether *pattern* covers *host* (``core.network_security.host_matches``
    semantics, exact or "*.suffix"; any other glob covers nothing)."""
    normalised_host = host_of(host)
    normalised_pattern = normalise_pattern(pattern)
    if not normalised_host or not normalised_pattern:
        return False
    return _covers(normalised_host, normalised_pattern)


def overlaps(a: str, b: str) -> bool:
    """Whether two patterns cover a common host (either covers the other's base)."""
    pa, pb = normalise_pattern(a), normalise_pattern(b)
    if not pa or not pb:
        return False
    return _covers(pattern_base(pa), pb) or _covers(pattern_base(pb), pa)


V = TypeVar("V")


class PatternIndex(Generic[V]):
    """Patterns ("host" or "*.suffix") mapped to values, answering which entry
    covers a host the way ``core.network_security.match_host_pattern`` does:
    the exact entry first, then the "*." entry with the longest suffix.

    A lookup is a handful of dict probes, one per label of the host
    ("a.b.chase.com": exact, then "*." of a.b.chase.com, b.chase.com,
    chase.com, com), with no lock and no I/O, so the guard and the resolver
    can ask on every navigation and hop. Only suffixes no longer than the
    longest pattern held are probed, so a megabyte-long host a hostile page
    hands over costs a few probes, not one per label (each hashing a
    megabyte). Entries that are not patterns are skipped and counted in
    ``skipped``; two entries for one pattern are combined by *merge* (the
    first one is kept without it)."""

    __slots__ = ("_exact", "_wild", "_longest_exact", "_longest_wild", "skipped")

    def __init__(
        self,
        entries: Iterable[tuple[str, V]],
        *,
        merge: Optional[Callable[[V, V], V]] = None,
    ) -> None:
        self._exact: dict[str, tuple[str, V]] = {}
        self._wild: dict[str, tuple[str, V]] = {}
        self.skipped = 0
        for raw, value in entries:
            pattern = normalise_pattern(raw)
            if not pattern:
                self.skipped += 1
                continue
            table = self._wild if is_wildcard(pattern) else self._exact
            key = pattern_base(pattern)
            held = table.get(key)
            if held is not None:
                if merge is None:
                    continue
                value = merge(held[1], value)
            table[key] = (pattern, value)
        self._longest_exact = max(map(len, self._exact), default=0)
        self._longest_wild = max(map(len, self._wild), default=0)

    def __len__(self) -> int:
        return len(self._exact) + len(self._wild)

    def patterns(self) -> list[str]:
        """Every pattern held, exact hosts first."""
        return [p for p, _ in self._exact.values()] + [p for p, _ in self._wild.values()]

    def lookup(self, host: str) -> Optional[tuple[str, V]]:
        """(pattern, value) of the entry covering *host*, which must already
        be normalised (``host_of``); None when no entry covers it."""
        if not host:
            return None
        if len(host) <= self._longest_exact:
            hit = self._exact.get(host)
            if hit is not None:
                return hit
        longest = self._longest_wild
        if not longest:
            return None
        # The suffixes are the host itself and what follows each dot; one
        # longer than every "*." key cannot match, so start at the first
        # label boundary that leaves at most *longest* characters.
        start = 0
        if len(host) > longest:
            dot = host.find(".", len(host) - longest - 1)
            if dot < 0:
                return None
            start = dot + 1
        while True:
            hit = self._wild.get(host[start:])
            if hit is not None:
                return hit
            dot = host.find(".", start)
            if dot < 0:
                return None
            start = dot + 1


_PROTECTED: PatternIndex[bool] = PatternIndex((p, True) for p in PROTECTED_PATTERNS)


def is_protected(host: str) -> bool:
    """Whether *host* is a sign-in, CAPTCHA or payment host that a Blocked
    rule never applies to (``sensitive_sites.PROTECTED_PATTERNS``)."""
    return is_protected_host(host_of(host))


def is_protected_host(host: str) -> bool:
    """``is_protected`` for a host ``host_of`` already read. It is not read
    again: a second reading could decode it once more and answer for a
    different host than the rule lookup did."""
    return _PROTECTED.lookup(host) is not None


def protected_overlap(pattern: str) -> Optional[str]:
    """The first protected pattern *pattern* overlaps (in
    ``PROTECTED_PATTERNS`` order), or None."""
    for protected in PROTECTED_PATTERNS:
        if overlaps(pattern, protected):
            return protected
    return None


def display_host(pattern: str) -> str:
    """The pattern as the owner reads it: punycode decoded, without "*."
    ("*.xn--bcher-kva.de" -> "bücher.de"). A label that does not decode is
    shown as stored."""
    base = pattern_base(normalise_pattern(pattern) or pattern.strip().lower())
    labels = []
    for label in base.split("."):
        # A punycode label is at most 63 characters; a longer one is shown
        # as stored rather than decoded (the decoder is quadratic).
        if label.startswith("xn--") and len(label) <= 63:
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def host_hash(host: str, secret: str) -> str:
    """The keyed hash a host is written as in audit rows (16 hex characters):
    HMAC-SHA256 under ``sha256(b"crawler-site-rules\\x00" + secret)``, the
    domain-separated idiom of ``services/connectors/oauth.py``. *secret* is
    ``settings.ENCRYPTION_KEY``. Rows can say "the same site twice" without a
    dictionary of bank names reversing them."""
    key = hashlib.sha256(_AUDIT_KEY_DOMAIN + secret.encode("utf-8")).digest()
    return hmac.new(key, (host_of(host) or host).encode("utf-8"), hashlib.sha256).hexdigest()[:16]


# --- The owner's input -----------------------------------------------------


def _typed_host(text: str) -> str:
    """The host part of what the owner typed, before normalisation; raises
    for a non-web scheme."""
    first = _AUTHORITY_END.split(text, 1)[0]
    if ":" in first and _is_ipv6(first.strip("[]")):
        return first.strip("[]")
    match = _SCHEME.match(text)
    if match is not None:
        scheme = match.group(1).lower()
        if scheme in ("http", "https"):
            first = _AUTHORITY_END.split(match.group(2).lstrip("/\\"), 1)[0]
        elif scheme in _WEB_SCHEMES or not _is_port(match.group(2)):
            raise SiteRuleError(messages.NOT_WEB)
    return _without_userinfo_and_port(first).strip()


def parse_site(raw: str, *, include_subdomains: bool) -> str:
    """The stored pattern for what the owner typed
    ("https://www.Chase.com/x?y" with subdomains -> "*.chase.com"); raises
    ``SiteRuleError`` with the plain reason (S7 §4.2 rules 1-8)."""
    text = _TAB_OR_NEWLINE.sub("", raw).strip() if isinstance(raw, str) else ""
    if not text:
        raise SiteRuleError(messages.EMPTY_SITE)
    host = _typed_host(text)
    if host.startswith("*."):
        include_subdomains, host = True, host[2:]
    if "*" in host:
        raise SiteRuleError(messages.STAR_INSIDE)
    if _TWO_SPELLINGS.search(host.lower()):
        raise SiteRuleError(messages.TWO_SPELLINGS)
    try:
        ascii_host = _normalise_host(host)
    except (ValueError, UnicodeError):
        ascii_host = ""
    if not ascii_host:
        raise SiteRuleError(messages.UNREADABLE_SITE)
    if is_ip_address(ascii_host):
        if include_subdomains:
            raise SiteRuleError(messages.IP_SUBDOMAINS)
        return ascii_host
    if len(ascii_host) > MAX_HOST_CHARS:
        raise SiteRuleError(messages.TOO_LONG)
    if not all(_OWNER_LABEL.fullmatch(label) for label in ascii_host.split(".")):
        raise SiteRuleError(messages.UNREADABLE_SITE)
    if "." not in ascii_host:
        # "*.com" is the owner reaching for a whole top-level domain; a bare
        # "localhost" or "com" is a name that is not a site.
        if include_subdomains:
            raise SiteRuleError(messages.too_broad(f"*.{ascii_host}"))
        raise SiteRuleError(messages.SINGLE_LABEL)
    if not include_subdomains:
        return ascii_host
    if ascii_host.startswith("www."):
        ascii_host = ascii_host[4:]
    if "." not in ascii_host or ascii_host in TWO_PART_SUFFIXES:
        raise SiteRuleError(messages.too_broad(f"*.{ascii_host}"))
    return f"*.{ascii_host}"


def _lookalike_reading(host: str) -> Optional[str]:
    """How *host* (decoded) reads when one of its labels mixes scripts or
    carries a confusable letter ("аpple.com" -> "apple.com"), else None
    (``lookalike.mixed_script_reading``, the facts the checkout's merchant
    check refuses on)."""
    return mixed_script_reading(host)


def validate_kind(pattern: str, kind: str) -> RuleKind:
    """The kind if *pattern* may carry it: Blocked is refused over a protected
    sign-in, CAPTCHA or payment host (naming the first one it covers), and
    Trusted on a look-alike or undecodable address."""
    checked = as_kind(kind)
    if checked is None:
        raise SiteRuleError(messages.BAD_KIND)
    base = pattern_base(normalise_pattern(pattern) or pattern)
    if checked == "blocked":
        hit = protected_overlap(pattern)
        if hit is not None:
            raise SiteRuleError(messages.protected_block(pattern_base(hit)))
    elif checked == "trusted" and not is_ip_address(base):
        decoded = decode_host(base)
        if decoded is None:
            raise SiteRuleError(messages.undecodable_trust(base))
        reading = _lookalike_reading(decoded)
        if reading is not None:
            raise SiteRuleError(messages.lookalike_trust(base, reading))
    return checked
