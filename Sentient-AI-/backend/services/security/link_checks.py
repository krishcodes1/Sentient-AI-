"""Checks a link without any network: look-alike letters and punycode, bare IP addresses,
credentials before an "@", link shorteners, abused domain endings, script links, link text that
names another site; and reduces a link to what may be sent to a lookup service.

Why it exists: S1 (outgoing messages), S2 (mail scan), S3 (scam check) and the browser guard all
need the same free checks and the same wording, and the owner's Google lookup
(services/reputation/links.py) needs one rule for what leaves the machine. Everything here is
local (services/security/README.md): no network, no model.

How a link is read: the way a browser reads it (WHATWG URL rules where they matter for safety).
Tabs and line breaks inside it are dropped, a backslash is a slash in an http(s) address, the
authority ends at the first "/", "\\", "?" or "#" and its host follows the last "@", a
percent-encoded host is decoded, a host may hold every character the URL standard allows
(``x$y.example.org``), and a host that ends in a number is an IPv4 address in any of the
spellings a browser accepts (``0x7f.1``, ``2130706433``, zero-padded parts), so a link cannot
look like one site here and open another in the browser. Reading never raises and never does
more than linear work: numbers and ports are bounded before they are converted, and a link that
cannot be read is reported with the "unreadable" signal. Nothing here ever calls a link "safe":
the best a report says is ``no_known_threats`` ("not on Google's list of dangerous sites").
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import AbstractSet, Any, Literal, Mapping, Optional, Protocol, Sequence, Union
from urllib.parse import parse_qs, unquote, unquote_to_bytes

from services.security import lookalike
from services.security.policies import TOOL_ARGS
from services.security.redact import contains

Purpose = Literal["browser", "mail", "chat", "outbound", "scam_check"]
Level = Literal["dangerous", "suspicious", "no_known_threats", "unknown"]
Severity = Literal["high", "warn", "info"]
ServiceName = Literal["safe_browsing", "web_risk"]
ServiceStatus = Literal[
    "listed", "not_listed",                        # Google answered
    "no_key", "off", "settings_unreadable",        # not asked: configuration
    "not_eligible", "too_many", "cache_miss",      # not asked: this link or this call
    "rate_limited", "cooling_down", "timeout", "error", "key_rejected",  # due but failed
]
# Statuses that mean "the owner expects a lookup and it did not happen": they produce the
# link_not_checked note.
NOT_CHECKED_STATUSES: frozenset[str] = frozenset(
    {"settings_unreadable", "too_many", "rate_limited", "cooling_down", "timeout", "error",
     "key_rejected"}
)

SIGNAL_CODES: frozenset[str] = frozenset({
    "lookalike_characters",   # high: a label mixes scripts or uses a confusable
    "international_address",  # info: a single-script non-Latin (IDN) host
    "lookalike_brand",        # high: typo or homograph of a well-known brand (amazom.com)
    "brand_in_address",       # warn: a brand used as a label or glued (amazon.shop, paypalsecure.com)
    "ip_address",             # high: the host is a bare public IP literal
    "credentials_in_url",     # high: userinfo before "@" hides the real host
    "shortener",              # info: bit.ly and friends (never expanded)
    "suspicious_tld",         # warn: a domain ending on SUSPICIOUS_TLDS
    "script_link",            # high: javascript:, vbscript:, data:, file:
    "text_mismatch",          # high: link text names another site than the href
    "unreadable",             # info: the link could not be parsed
})

# Compared by registrable domain (lookalike.registrable_domain), so go.bit.ly counts too.
SHORTENER_HOSTS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "bl.ink",
    "x.gd", "qrco.de", "lnkd.in", "shorturl.gg",
})
# Domain endings that cost little and are used mostly for throwaway scam sites. A warning only:
# plenty of honest sites live under them, so alone they never make a link suspicious.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "zip", "mov", "top", "xyz", "click", "link", "cyou", "icu", "buzz", "rest", "sbs", "cfd",
    "quest", "bond", "tk", "ml", "ga", "cf", "gq", "work", "support", "loan", "win", "bid",
    "date", "faith", "racing", "review", "stream", "download", "men", "party", "cricket",
    "science", "accountant", "monster", "lol",
})
# Names that never reach the public internet: such a host is never sent for a lookup (it would
# tell Google about the owner's network, and Google cannot know it anyway).
NON_PUBLIC_SUFFIXES: tuple[str, ...] = (
    ".local", ".localhost", ".internal", ".intranet", ".lan", ".home.arpa", ".corp",
    ".private", ".test", ".example", ".invalid",
)
# Query parameter names (compared case-insensitively) whose presence keeps the whole query
# from being sent: they carry sign-in codes, session ids, reset tokens and signatures.
SENSITIVE_QUERY_NAMES: frozenset[str] = frozenset({
    "token", "access_token", "id_token", "refresh_token", "code", "state", "key", "apikey",
    "api_key", "sig", "signature", "session", "sessionid", "sid", "auth", "password", "pass",
    "pwd", "otp", "reset", "ticket", "jwt",
})

SERVICE_LABELS: Mapping[str, str] = {
    "safe_browsing": "Google Safe Browsing",
    "web_risk": "Google Web Risk",
}

# Google's threat types in the order their words are joined, with the hedged wording Google's
# guidelines ask for ("may be", never "is").
_THREAT_WORDS: tuple[tuple[str, str], ...] = (
    ("SOCIAL_ENGINEERING", "may be phishing or a scam"),
    ("MALWARE", "may host malware"),
    ("UNWANTED_SOFTWARE", "may offer unwanted software"),
    ("POTENTIALLY_HARMFUL_APPLICATION", "may offer harmful apps"),
)

# Schemes by what a link with them does.
_WEB_SCHEMES = frozenset({"http", "https"})
_SCRIPT_SCHEMES = frozenset({"javascript", "vbscript", "data", "file"})
_CONTACT_SCHEMES = frozenset({"mailto", "tel", "sms"})
# Schemes recognised without "//" after them; anything else before a ":" that is not followed
# by "//" (example.com:8080/x, localhost:3000) is a host written without a scheme.
_BARE_SCHEMES = _SCRIPT_SCHEMES | _CONTACT_SCHEMES | frozenset({"about", "blob", "callto", "sip"})
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_DEFAULT_PORTS = {"http": 80, "https": 443}

# A link longer than this is not read at all: a browser refuses an address this long (Chromium's
# limit is 2 MB), so it opens nothing. It is reported unreadable.
_MAX_URL_CHARS = 2 * 1024 * 1024
# A link longer than this is read only up to the end of its host: a browser still opens it, so
# its site is checked and looked up like any other (padding a link must never hide its host),
# but its path and query are neither sent nor shown, and nothing slower than one pass over the
# text runs on them.
_MAX_INPUT_CHARS = 32_768
# The longest host name DNS can carry (RFC 1035). A longer one never resolves; checking the
# length first keeps every per-label step below linear in the input.
_MAX_HOST_CHARS = 253
# Link text: at most this much is read for host names, and at most this many host-like tokens
# are parsed (link text names its site near the start; an unbounded text would cost an
# unbounded number of parses).
_MAX_TEXT_CHARS = 4_096
_MAX_TEXT_HOSTS = 32
# What may be sent for one link, at most (lookup_url): past it the query goes, then the path.
_MAX_LOOKUP_CHARS = 2_048
# A run this long of token characters, holding a digit, is taken for a token wherever it sits in
# a path segment (reset, magic sign-in and share links carry their secret there, review SEC-F10;
# a session id rides along as "cart;jsessionid=...", and a token can end in "!" or "="). "+" is
# base64's own letter, so it is a token character too. The digit is looked for in the run itself.
_PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_.%~+\-]{24,}")
# Base64 with its "=" padding ending a segment: 16 or more base64 characters, which may cross a
# "/" because standard base64 writes one ("/confirm/abcd+EFGH/ijkl1234mnop5678qrst=="). A path
# that ends a segment in padding is almost never an ordinary page name. The lookbehind lets a
# match start only where a run of base64 characters starts: without it, a long run with no "="
# is rescanned from every position (quadratic in the 32 KB a link may be).
_PADDED_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{16,}={1,2}(?=$|[/;,!])")
# A query value holding a run this long is taken for a token.
_QUERY_TOKEN_RE = re.compile(r"[A-Za-z0-9_.%\-]{32,}")
# A query value that is base64 with its padding ("MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=").
_PADDED_VALUE_RE = re.compile(r"[A-Za-z0-9+/_\-]{16,}={1,2}")
# An e-mail address (someone's personal data: an unsubscribe or invitation link names the
# recipient). The domain must end in letters, so a package pin ("react@18.3.1") or a profile
# path ("/@someone") is not one. The lookbehind lets a match start only where a run of
# address characters starts (linear, as for _PADDED_TOKEN_RE).
_EMAIL_RE = re.compile(r"(?<![^\s/@?#&;=])[^\s/@?#&;=]+@(?:[\w\-]+\.)+[^\W\d_]{2,}")
# Characters a server may split a query on: "&" everywhere, and ";" in many servers and
# frameworks (and Python's parse_qsl before 3.10), so "?a=1;otp=123456" carries an "otp".
_QUERY_SEPARATORS_RE = re.compile(r"[&;]")
# How many rounds of percent-decoding a check looks through ("%2540" is "%40" is "@").
_UNQUOTE_ROUNDS = 4
# How much of a path a card shows (display_url).
_SHOWN_PATH_CHARS = 60
# One host label as a public DNS name writes it (underscores and edge hyphens occur in real
# hosts). A label with any other character the URL standard allows ("x$y", "a!b") is still read,
# but only its nearest ancestor made of such labels is looked up (_lookup_host).
_CLEAN_LABEL_RE = re.compile(r"[a-z0-9_\-]{1,63}")
# The URL standard's forbidden domain code points that can survive to the ASCII host: a host
# holding one is a URL a browser refuses. Controls, space and DEL are refused by range.
_FORBIDDEN_IN_HOST = frozenset("#%/:<>?@[\\]^|")
# An IPv4 part, by its base: the digits it may hold, and how many significant digits the
# largest value an address can hold (2**32 - 1) takes. A longer number is refused before it is
# converted, so a zero-padded or huge part costs one pass and never meets int()'s digit limit.
_IPV4_DIGITS: Mapping[int, re.Pattern[str]] = {
    10: re.compile(r"[0-9]+"),
    8: re.compile(r"[0-7]+"),
    16: re.compile(r"[0-9a-fA-F]+"),
}
_IPV4_MAX_DIGITS: Mapping[int, int] = {10: 10, 8: 11, 16: 8}
# The most significant digits a port can have (65535).
_MAX_PORT_DIGITS = 5
# A typo of a brand this short is usually another ordinary word (nice/nike, easy/etsy,
# room/zoom), so for these only a homograph (the label reads as the brand) counts.
_SHORT_BRAND = 4
# The alphabets whose letters pass for one another (UTS 39 leaves Cyrillic and Greek out of every
# allowed mix for that reason): a label that mixes scripts is a look-alike only when one of
# these is in the mix.
_CONFUSABLE_SCRIPTS: frozenset[str] = frozenset({"LATIN", "CYRILLIC", "GREEK"})
# Script mixes ordinary CJK names are written in (UTS 39 "highly restrictive"): Japanese,
# Chinese with Bopomofo, Korean, each with Latin allowed.
_CJK_SCRIPT_SETS: tuple[frozenset[str], ...] = (
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),
    frozenset({"LATIN", "HAN", "BOPOMOFO"}),
    frozenset({"LATIN", "HAN", "HANGUL"}),
)
# Dots other scripts write that a browser reads as ".".
_DOT_LOOKALIKES = str.maketrans({"。": ".", "．": ".", "｡": "."})

# Known wrappers and the query parameter that holds the real destination.
_REDIRECTOR_DEPTH = 2

# Link text: tokens that look like a host. File names (report.pdf) are not hosts.
_TEXT_SPLIT_RE = re.compile(r"[\s<>\"'`|]+")
_TEXT_STRIP = "()[]{}<>\"'`.,;:!?*"
_FILE_EXTENSIONS: frozenset[str] = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf", "odt", "jpg",
    "jpeg", "png", "gif", "svg", "webp", "heic", "mp3", "mp4", "wav", "m4a", "avi", "mov",
    "mkv", "exe", "msi", "dmg", "apk", "pkg", "html", "htm", "php", "asp", "aspx", "js", "json",
    "xml", "zip", "rar", "7z", "gz", "tar", "eml", "ics", "vcf", "py", "md", "log", "iso",
})
_TEXT_HOST_RE = re.compile(r"^[^\W_](?:[\w\-]*[^\W_])?(?:\.[^\W_](?:[\w\-]*[^\W_])?)+$")

_SEVERITY_RANK: Mapping[str, int] = {"high": 0, "warn": 1, "info": 2}
# Within one severity, the order signals are listed in (most telling first).
_CODE_RANK: Mapping[str, int] = {
    code: index
    for index, code in enumerate((
        "script_link", "credentials_in_url", "ip_address", "lookalike_characters",
        "lookalike_brand", "text_mismatch", "brand_in_address", "suspicious_tld", "shortener",
        "international_address", "unreadable",
    ))
}

# Why a lookup did not happen, in the words a note uses, most important first.
_NOT_CHECKED_WHY: tuple[tuple[str, str], ...] = (
    ("key_rejected", "Google refused the key"),
    ("settings_unreadable", "the owner's settings could not be read"),
    ("rate_limited", "the lookup limit was reached"),
    ("cooling_down", "lookups are paused for a few minutes after a problem with Google"),
    ("timeout", "Google did not answer in time"),
    ("error", "Google could not be reached"),
    ("too_many", "there were too many links to check at once"),
)
_NO_KEY_COVERAGE = (
    "Links were checked on this computer only. Add a Google Safe Browsing or Web Risk key in "
    "Security → Service keys to also check them against Google's list of dangerous sites."
)
_OFF_COVERAGE = (
    "Links were checked on this computer only: Check links with Google Safe Browsing is turned "
    "off in Settings → Permissions."
)
_OFFLINE_COVERAGE = (
    "Links were checked on this computer only; Google was not asked this time."
)


@dataclass(frozen=True)
class LinkSignal:
    """One local finding about a link. ``text`` is one plain sentence that names hosts only,
    never a query, path secret or userinfo."""
    code: str
    severity: Severity
    text: str


@dataclass(frozen=True)
class LinkReport:
    """What is known about one link. ``url`` is the caller's input, kept only so the caller can
    match reports to its links (never logged or stored by S4); ``shown`` is safe to show on a card:
    scheme://host/path with userinfo, query and fragment removed and a non-ASCII host in punycode;
    ``host`` is the ASCII host ("" when unreadable)."""
    url: str
    shown: str
    host: str
    level: Level
    signals: tuple[LinkSignal, ...] = ()
    threats: tuple[str, ...] = ()            # e.g. ("SOCIAL_ENGINEERING",)
    service: Optional[ServiceName] = None
    service_status: ServiceStatus = "no_key"
    cached: bool = False

    def reasons(self) -> tuple[str, ...]:
        """Plain-English lines, most serious first: the Google advisory (when listed), then
        high, warn and info signals."""
        lines: list[str] = []
        if self.service_status == "listed":
            lines.append(advisory(self.service, self.threats) + ".")
        for severity in ("high", "warn", "info"):
            lines.extend(s.text for s in self.signals if s.severity == severity)
        return tuple(lines)


# ── reading a link ─────────────────────────────────────────────────────


IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
_Kind = Literal["web", "script", "contact", "other", "unreadable"]


@dataclass(frozen=True)
class _Link:
    """A link as a browser would read it. For ``web`` links every field is set; for the
    others only ``kind`` and ``scheme``."""
    kind: _Kind
    scheme: str = ""
    host: str = ""                 # ASCII (punycode) host; an IPv6 literal without brackets
    unicode_host: str = ""         # the host as a person sees it (decoded), "" for an IP
    ip: Optional[IPAddress] = None
    port: Optional[int] = None     # None for the scheme's default port
    path: str = "/"                # canonical, percent-escaped
    query: str = ""                # raw (only unsafe characters escaped), "" for none
    userinfo: bool = False
    # The host a lookup names: ``host`` itself, or for a host with characters a public DNS name
    # never holds ("x$y.listed.example.org") its nearest ancestor made of DNS labels, which
    # Google's host-suffix matching would have reached from the full host.
    lookup_host: str = ""

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if isinstance(self.ip, ipaddress.IPv6Address) else self.host
        return host if self.port is None else f"{host}:{self.port}"

    @property
    def lookup_netloc(self) -> str:
        if self.lookup_host == self.host:
            return self.netloc
        return self.lookup_host if self.port is None else f"{self.lookup_host}:{self.port}"


_UNREADABLE = _Link(kind="unreadable")
_UNREADABLE_SIGNAL_TEXT = "The link could not be read."


def _clean_input(url: str) -> str:
    """What a browser does to typed or pasted text before reading it as a URL: leading and
    trailing control characters and spaces go, tabs and line breaks anywhere go."""
    text = url.strip("".join(chr(c) for c in range(0x21)))
    return text.replace("\t", "").replace("\n", "").replace("\r", "")


def _ipv4_part(part: str) -> Optional[int]:
    """One dotted part of a browser's IPv4 spelling (the URL standard's IPv4 number parser):
    decimal, 0x hex or 0-led octal, ASCII digits of that base only (no sign, space or "_",
    which int() would accept); None when a browser refuses it. Bounded: leading zeros are
    dropped and a number longer than any address part could be is refused before int() runs
    (such a part fails in the browser too: no part may reach 2**32)."""
    base = 10
    if part[:2] in ("0x", "0X"):
        base, part = 16, part[2:]
    elif len(part) > 1 and part.startswith("0"):
        base, part = 8, part[1:]
    if not part:
        return 0
    if not _IPV4_DIGITS[base].fullmatch(part):
        return None
    significant = part.lstrip("0")
    if len(significant) > _IPV4_MAX_DIGITS[base]:
        return None
    return int(significant or "0", base)


def _port(text: str) -> Optional[int]:
    """A port as a browser reads it (ASCII digits, leading zeros allowed, at most 65535), or
    None when it refuses it. Bounded: the zeros go and more than five digits are refused
    before int() runs, so a port padded to thousands of digits never raises."""
    if not (text.isascii() and text.isdigit()):
        return None
    significant = text.lstrip("0")
    if len(significant) > _MAX_PORT_DIGITS:
        return None
    value = int(significant or "0")
    return value if value <= 65535 else None


def _numeric_host(host: str) -> tuple[bool, Optional[ipaddress.IPv4Address]]:
    """(ends in a number, the IPv4 address). A browser reads any host whose last label is a
    number as an IPv4 address (WHATWG "ends in a number"); when that reading fails the URL is
    invalid, so (True, None) means unreadable."""
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts = parts[:-1]
    last = parts[-1] if parts else ""
    # ASCII digits only: other scripts' digits make an international name, not an address.
    if not last or not last.isascii() or not (
        last.isdigit() or re.fullmatch(r"0[xX][0-9A-Fa-f]*", last)
    ):
        return False, None
    if len(parts) > 4:
        return True, None
    numbers = [_ipv4_part(part) if part else None for part in parts]
    if any(n is None for n in numbers):
        return True, None
    values = [n for n in numbers if n is not None]
    if any(n > 255 for n in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return True, None
    total = values[-1]
    for index, value in enumerate(values[:-1]):
        total += value * 256 ** (3 - index)
    return True, ipaddress.IPv4Address(total)


def _escape_bytes(raw: bytes, *, keep: bytes = b"") -> str:
    """Percent-escape every byte at or below space, at or above DEL, and "#" and "%" (Safe
    Browsing's canonical form), except the bytes in *keep*."""
    out: list[str] = []
    for byte in raw:
        if (byte <= 0x20 or byte >= 0x7F or byte in b"#%") and byte not in keep:
            out.append(f"%{byte:02X}")
        else:
            out.append(chr(byte))
    return "".join(out)


def _canonical_path(raw: str) -> str:
    """The path percent-unescaped until stable, re-escaped (Safe Browsing's rules), with "."
    and ".." segments resolved and runs of slashes collapsed. Always starts with "/"."""
    data = raw.encode("utf-8", "surrogatepass") if raw else b"/"
    for _ in range(4):
        decoded = unquote_to_bytes(data)
        if decoded == data:
            break
        data = decoded
    escaped = _escape_bytes(data)
    segments = escaped.split("/")
    kept: list[str] = []
    for segment in segments:
        if segment in ("", "."):
            continue
        if segment == "..":
            if kept:
                kept.pop()
            continue
        kept.append(segment)
    path = "/" + "/".join(kept)
    if kept and (escaped.endswith("/") or segments[-1] in (".", "..")):
        path += "/"
    return path


# Where a special (http/https) URL's authority ends: a browser treats "\" as "/" there.
_AUTHORITY_END_RE = re.compile(r"[/\\?#]")


@dataclass(frozen=True)
class _Parts:
    """A cleaned link split the way a browser splits it: its kind and scheme and, for a web
    link, the authority, the path (backslashes already slashes) and the raw query."""
    kind: _Kind
    scheme: str
    authority: str = ""
    path: str = ""
    query: str = ""


def _split(text: str) -> _Parts:
    """*text* (already through _clean_input) split as the URL standard splits a special URL,
    without urllib (whose netloc checks refuse links a browser opens, "user[@host" and a
    full-width "/" before "@"): any run of slashes or backslashes after the scheme is skipped,
    the authority runs to the first "/", "\\", "?" or "#", the fragment (from the first "#")
    is dropped and the query follows the first "?" before it. A host written without a scheme
    (www.example.com/x, example.com:8080, //x.com) is an http link. One pass over *text*."""
    match = _SCHEME_RE.match(text)
    scheme = match.group(1).lower() if match else ""
    rest = text[match.end():] if match else ""
    if match and (scheme in _WEB_SCHEMES or scheme in _BARE_SCHEMES or rest.startswith("//")):
        if scheme in _SCRIPT_SCHEMES:
            return _Parts("script", scheme)
        if scheme in _CONTACT_SCHEMES:
            return _Parts("contact", scheme)
        if scheme not in _WEB_SCHEMES:
            return _Parts("other", scheme)
    else:
        scheme, rest = "http", text
    # Extra or missing slashes after the scheme do not matter to a browser, and in an http(s)
    # address a backslash is a slash to it, so "evil.com\@good.com" opens evil.com.
    body = rest.lstrip("/\\")
    end = _AUTHORITY_END_RE.search(body)
    if end is None:
        return _Parts("web", scheme, body)
    tail = body[end.start():].partition("#")[0]
    path, _, query = tail.partition("?")
    return _Parts("web", scheme, body[: end.start()], path.replace("\\", "/"), query)


def _lookup_host(host: str) -> Optional[str]:
    """The host a lookup names for ASCII *host*: *host* itself when every label is a DNS label
    (_CLEAN_LABEL_RE); else its longest suffix of DNS labels, which must still hold the
    registrable domain ("x$y.listed.example.org" -> "listed.example.org"; Google matches a
    host's suffixes, so the listing of an ancestor is found either way). None when the
    registrable domain itself holds another character ("pay$pal.com"): no public name is
    spelled that way, so there is no site to look up."""
    labels = host.split(".")
    if all(_CLEAN_LABEL_RE.fullmatch(label) for label in labels):
        return host
    kept: list[str] = []
    for label in reversed(labels):
        if not _CLEAN_LABEL_RE.fullmatch(label):
            break
        kept.append(label)
    suffix = ".".join(reversed(kept))
    domain = lookalike.registrable_domain(host)
    if not suffix or not (suffix == domain or suffix.endswith("." + domain)):
        return None
    return suffix


def _parse_unguarded(url: object) -> _Link:
    """_parse without its guard: see _parse."""
    if not isinstance(url, str):
        return _UNREADABLE
    text = _clean_input(url)
    if not text or len(text) > _MAX_URL_CHARS:
        return _UNREADABLE
    parts = _split(text)
    if parts.kind != "web":
        return _Link(kind=parts.kind, scheme=parts.scheme)
    scheme = parts.scheme
    # A link over _MAX_INPUT_CHARS is read up to the end of its host only.
    path, raw_query = (parts.path, parts.query) if len(text) <= _MAX_INPUT_CHARS else ("", "")
    userinfo = "@" in parts.authority
    hostport = parts.authority.rpartition("@")[2]
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            return _UNREADABLE
        raw_host, port_text = hostport[1:end], hostport[end + 1:]
        if port_text and not port_text.startswith(":"):
            return _UNREADABLE
        port_text = port_text[1:]
        try:
            ip6 = ipaddress.IPv6Address(raw_host.split("%", 1)[0])
        except ValueError:
            return _UNREADABLE
        ip: Optional[IPAddress] = ip6
        host, unicode_host = str(ip6), ""
        lookup_host = host
    else:
        raw_host, _, port_text = hostport.partition(":")
        try:
            decoded = unquote(raw_host, errors="strict") if "%" in raw_host else raw_host
        except UnicodeDecodeError:
            return _UNREADABLE
        # The characters a browser drops from a host go first ("ev&shy;il.com" opens evil.com),
        # then the forms and cases it folds, the UTS 46 way and never with str.lower(), which
        # reads another host than the browser opens (with the capital sharp s U+1E9E,
        # "account-a" + U+1E9E + "ist.com" is account-assist.com to a browser; lower() made it a
        # sharp s, so the listed site was never looked up).
        decoded = lookalike.fold_host(decoded)
        if not decoded or decoded == ".":
            return _UNREADABLE
        # An address first: a browser opens "1.2.3.0000...04" as 1.2.3.4 whatever its length
        # (the check is linear), so a padded address is never left unread.
        numeric, ip4 = _numeric_host(decoded)
        if numeric:
            if ip4 is None:
                return _UNREADABLE
            ip, host, unicode_host = ip4, str(ip4), ""
            lookup_host = host
        else:
            # Only then is a name's length known; a longer one never resolves, and refusing it
            # here keeps every per-label step below linear.
            if len(decoded.rstrip(".")) > _MAX_HOST_CHARS:
                return _UNREADABLE
            ip = None
            # The host as a browser puts it on the wire (UTS 46, so a name only IDNA 2008
            # allows is read, never left unreadable and unlooked-up) and as a person reads it.
            ascii_form = lookalike.ascii_host(decoded)
            readable = lookalike.browser_host(ascii_form or "")
            if not ascii_form or readable is None:
                return _UNREADABLE
            # Every character the URL standard allows in a host is read ("x$y.example.org"
            # opens in a browser, so it must be looked up here); a forbidden one is a link the
            # browser refuses.
            if not all("!" <= ch <= "~" and ch not in _FORBIDDEN_IN_HOST for ch in ascii_form):
                return _UNREADABLE
            found = _lookup_host(ascii_form)
            if found is None:
                return _UNREADABLE
            host, unicode_host, lookup_host = ascii_form, readable, found
    port: Optional[int] = None
    if port_text:
        port = _port(port_text)
        if port is None:
            return _UNREADABLE
        if port == _DEFAULT_PORTS[scheme]:
            port = None
    query = _escape_bytes(raw_query.encode("utf-8", "surrogatepass"), keep=b"%")
    return _Link(
        kind="web",
        scheme=scheme,
        host=host,
        unicode_host=unicode_host,
        ip=ip,
        port=port,
        path=_canonical_path(path),
        query=query,
        userinfo=userinfo,
        lookup_host=lookup_host,
    )


def _parse(url: object) -> _Link:
    """*url* read as a browser reads it (see the module docstring). Never raises: anything it
    cannot read, hostile input included, is the unreadable link. Linear in the length of *url*:
    a link over _MAX_INPUT_CHARS is read up to the end of its host only, a name over
    _MAX_HOST_CHARS (after the characters a browser drops) is unreadable before any per-label
    work, and numbers and ports are bounded before they are converted."""
    try:
        return _parse_unguarded(url)
    except Exception:  # noqa: BLE001 - a link that cannot be read is reported unreadable
        return _UNREADABLE


def _public_ip(ip: IPAddress) -> bool:
    """True for an address on the public internet. An IPv6 form that carries an IPv4 address
    (mapped, 6to4, Teredo, NAT64) is judged by the address inside it too."""
    if isinstance(ip, ipaddress.IPv6Address):
        inner: Optional[ipaddress.IPv4Address] = ip.ipv4_mapped or ip.sixtofour
        if inner is None and ip.teredo:
            inner = ip.teredo[1]
        if inner is None and ip in ipaddress.ip_network("64:ff9b::/96"):
            inner = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if inner is not None and not _public_ip(inner):
            return False
    return ip.is_global and not ip.is_reserved and not ip.is_multicast


def _public_host(link: _Link) -> bool:
    """A host that can be on the public internet: not a private, loopback, link-local or
    reserved IP, not a single label, not under NON_PUBLIC_SUFFIXES."""
    if link.ip is not None:
        return _public_ip(link.ip)
    host = link.lookup_host or link.host
    if "." not in host:
        return False
    return not any(host == suffix[1:] or host.endswith(suffix) for suffix in NON_PUBLIC_SUFFIXES)


def _unquoted(text: str) -> str:
    """*text* percent-decoded until it stops changing (at most _UNQUOTE_ROUNDS rounds), so a
    double-encoded "@" ("%2540") or token is seen as what it finally reads as."""
    for _ in range(_UNQUOTE_ROUNDS):
        decoded = unquote(text, errors="replace")
        if decoded == text:
            break
        text = decoded
    return text


def _private_path(path: str) -> bool:
    """True when the path probably carries a secret or someone's address, so only the host may
    leave or be shown: a run of 24+ token characters holding a digit anywhere in a segment,
    base64 with "=" padding ending a segment, an e-mail address, or something the secret
    detector finds (review SEC-F10)."""
    if any(any(ch.isdigit() for ch in run.group()) for run in _PATH_TOKEN_RE.finditer(path)):
        return True
    plain = _unquoted(path)
    if _PADDED_TOKEN_RE.search(path) or _EMAIL_RE.search(plain):
        return True
    return contains(path, TOOL_ARGS) or (plain != path and contains(plain, TOOL_ARGS))


def _query_names(name: str) -> set[str]:
    """The names a query parameter is known by: the whole name and each part of a bracketed one
    ("token[]", "user[token]"), lower-case."""
    lowered = name.strip().lower()
    return {lowered, *(part.strip() for part in re.split(r"[\[\]]", lowered) if part.strip())}


def _token_value(value: str) -> bool:
    """True when a query value (or name) looks like a token: a run of 32+ token characters, or
    padded base64."""
    return bool(_QUERY_TOKEN_RE.search(value) or _PADDED_VALUE_RE.fullmatch(value.strip()))


def _query_shareable(query: str) -> bool:
    """True when the query may be sent: no sensitive parameter name, no token-like value, no
    e-mail address, nothing the secret detector finds. Parameters are split on "&" and ";" and
    decoded until stable, as any server might read them."""
    plain = _unquoted(query)
    if "@" in plain:
        return False
    for part in _QUERY_SEPARATORS_RE.split(query):
        if not part:
            continue
        raw_name, _, raw_value = part.partition("=")
        name = _unquoted(raw_name.replace("+", " "))
        value = _unquoted(raw_value.replace("+", " "))
        if _query_names(name) & SENSITIVE_QUERY_NAMES:
            return False
        if any(_token_value(text) for text in (raw_name, raw_value, name, value)):
            return False
    return not (contains(query, TOOL_ARGS) or contains(plain, TOOL_ARGS))


def _strip_invisible(text: str) -> str:
    """*text* without control and format characters (bidi controls, zero-width letters), which a
    host may carry and a sentence must not."""
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))


def _without_format_characters(text: str) -> str:
    """*text* without what a reader never sees in it: the characters a browser drops from a host
    (lookalike.IGNORED_IN_HOSTS) and every other format character (bidi controls, zero-width
    letters). Line breaks and tabs stay, as they separate words."""
    text = lookalike.strip_ignored(text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


# ── unwrapping known redirectors ───────────────────────────────────────


def _wrapped_target(link: _Link, raw_query: str) -> Optional[str]:
    """The destination a known wrapper carries in its query, or None."""
    host, path = link.host, link.path
    names: tuple[str, ...] = ()
    if host.endswith(".safelinks.protection.outlook.com"):
        names = ("url",)
    elif host in ("www.google.com", "google.com") and path == "/url":
        names = ("q", "url")
    elif host in ("l.facebook.com", "lm.facebook.com") and path == "/l.php":
        names = ("u",)
    if not names:
        return None
    values = parse_qs(raw_query, keep_blank_values=False)
    for name in names:
        for value in values.get(name, ()):
            candidate = value.strip()
            match = _SCHEME_RE.match(candidate)
            if match and match.group(1).lower() in _WEB_SCHEMES:
                return candidate
    return None


def unwrap_redirector(url: str) -> str:
    """The real destination of a known wrapper (Outlook Safe Links
    *.safelinks.protection.outlook.com/?url=, Google www.google.com/url?q= or ?url=,
    l.facebook.com/l.php?u=), at most two levels deep; *url* itself otherwise. Never fetches
    and never raises (a wrapper that cannot be read is left as it is)."""
    current = url
    try:
        for _ in range(_REDIRECTOR_DEPTH):
            link = _parse(current)
            if link.kind != "web":
                break
            # The whole query, even past _MAX_INPUT_CHARS: padding a wrapper must not hide
            # where it leads.
            target = _wrapped_target(link, _split(_clean_input(current)).query)
            if target is None:
                break
            current = target
    except Exception:  # noqa: BLE001 - the link as unwrapped so far
        pass
    return current


# ── local checks ───────────────────────────────────────────────────────


def _host_label(link: _Link) -> str:
    """The host as sentences name it: ASCII (punycode), IPv6 in brackets."""
    return f"[{link.host}]" if isinstance(link.ip, ipaddress.IPv6Address) else link.host


def _typo_counts(host: str, known: str) -> bool:
    """Whether a typo hit on *known* is worth a high signal for any link (checkout asks it
    only of the site the person named). A brand of _SHORT_BRAND letters or fewer counts only
    when a label or hyphenated part of *host* reads as the brand (a homograph: "z00m" counts,
    "room" does not), because one edit from a four-letter brand is mostly another ordinary
    word."""
    brand = known.split(".", 1)[0]
    if len(brand) > _SHORT_BRAND:
        return True
    words = {part for label in host.split(".") for part in (label, *label.split("-"))}
    return any(lookalike.skeleton(word) == brand for word in words)


def _script(char: str) -> str:
    """The script of a letter as Unicode's mixed-script rules (UTS 39) group them: every Han
    ideograph and ideographic mark is "HAN", the long-vowel mark both kana share is "KATAKANA",
    anything else by lookalike.script_of."""
    script = lookalike.script_of(char)
    if script in ("CJK", "IDEOGRAPHIC"):
        return "HAN"
    if script == "KATAKANA-HIRAGANA":
        return "KATAKANA"
    return script


def _mixes_lookalike_scripts(scripts: AbstractSet[str]) -> bool:
    """Whether a label's *scripts* mix in a way that can imitate a Latin (or Cyrillic or Greek)
    word: more than one script, at least one of them a confusable alphabet, and not one of the
    combinations ordinary CJK names are written in (UTS 39 "highly restrictive": Japanese mixes
    Han, Hiragana and Katakana, Chinese Han and Bopomofo, Korean Han and Hangul, each also with
    Latin, as in "qq邮箱.com")."""
    if len(scripts) < 2 or not scripts & _CONFUSABLE_SCRIPTS:
        return False
    return not any(scripts <= allowed for allowed in _CJK_SCRIPT_SETS)


def _imitates_latin(host: str) -> bool:
    """Whether a label of *host* only pretends to be Latin: it mixes a confusable alphabet with
    another script (outside the CJK combinations, see _mixes_lookalike_scripts), every letter of
    a non-Latin label is a known confusable ("аррӏе" reads as "apple"), or a Latin label carries
    a Latin-script confusable ("ɡ" for "g"). Checkout flags any confusable at all
    (lookalike.mixed_script_reading), which is right where the person named the shop; for every
    link in a mail it would make every Cyrillic or Greek word a look-alike, so an ordinary
    single-script name (пример.рф) or a Japanese one (日本のサイト.jp) is only an international
    address here."""
    for label in host.split("."):
        letters = [ch for ch in label if ch.isalpha()]
        scripts = {_script(ch) for ch in letters}
        if _mixes_lookalike_scripts(scripts):
            return True
        confusable = [ch in lookalike.CONFUSABLES for ch in letters]
        if scripts and scripts != {"LATIN"} and all(confusable):
            return True
        if scripts == {"LATIN"} and any(confusable):
            return True
    return False


def _lookalike_signals(link: _Link) -> list[LinkSignal]:
    signals: list[LinkSignal] = []
    shown_unicode = _strip_invisible(link.unicode_host)
    reading = lookalike.mixed_script_reading(link.unicode_host)
    if reading is not None and _imitates_latin(link.unicode_host):
        shown_reading = _strip_invisible(reading)
        if shown_reading == shown_unicode:
            # No letter has a known Latin twin (a Cyrillic "п" among Latin letters), so there is
            # no other reading to name: saying "x reads as x" would explain nothing.
            text = (
                f"The address uses look-alike letters: {shown_unicode} mixes alphabets in one "
                f"name (written {link.host})."
            )
        else:
            text = (
                f"The address uses look-alike letters: {shown_unicode} reads as {shown_reading} "
                f"(written {link.host})."
            )
        signals.append(LinkSignal("lookalike_characters", "high", text))
        return signals
    if not link.unicode_host.isascii():
        scripts = {lookalike.script_of(ch) for ch in link.unicode_host if ch.isalpha()}
        if scripts - {"LATIN"}:
            signals.append(LinkSignal(
                "international_address", "info",
                f"The address uses non-Latin letters ({shown_unicode}, written {link.host}).",
            ))
    hit = lookalike.lookalike_of(link.unicode_host)
    if hit is not None and hit.rule == "typo" and not _typo_counts(link.unicode_host, hit.known):
        hit = None
    if hit is not None:
        if hit.rule == "typo":
            signals.append(LinkSignal(
                "lookalike_brand", "high",
                f"{link.host} looks like {hit.known} but is a different site.",
            ))
        else:
            brand = hit.known.split(".", 1)[0]
            signals.append(LinkSignal(
                "brand_in_address", "warn",
                f"{link.host} uses the name {brand} but is not {hit.known}.",
            ))
    return signals


def _unreadable_signal() -> LinkSignal:
    return LinkSignal("unreadable", "info", _UNREADABLE_SIGNAL_TEXT)


def _signals(link: _Link) -> list[LinkSignal]:
    """Every local finding for *link*. Never raises: a step that fails on hostile input makes
    the link unreadable rather than dropping the findings silently."""
    try:
        return _signals_unguarded(link)
    except Exception:  # noqa: BLE001 - reported as a link that could not be read
        return [_unreadable_signal()]


def _signals_unguarded(link: _Link) -> list[LinkSignal]:
    if link.kind == "unreadable":
        return [_unreadable_signal()]
    if link.kind == "script":
        return [LinkSignal(
            "script_link", "high",
            f"The link runs code or opens a local file instead of a web page ({link.scheme}:).",
        )]
    if link.kind != "web":
        return []
    signals: list[LinkSignal] = []
    host = _host_label(link)
    if link.userinfo:
        signals.append(LinkSignal(
            "credentials_in_url", "high",
            f'The link hides where it goes: everything before "@" is ignored, so it really '
            f"opens {host}.",
        ))
    if link.ip is not None:
        if _public_ip(link.ip):
            signals.append(LinkSignal(
                "ip_address", "high",
                f"The link goes to a bare IP address ({host}) instead of a site name.",
            ))
        return signals
    try:
        signals.extend(_lookalike_signals(link))
    except Exception:  # noqa: BLE001 - the other findings stay; this one could not be read
        signals.append(_unreadable_signal())
    if lookalike.registrable_domain(link.host) in SHORTENER_HOSTS:
        signals.append(LinkSignal(
            "shortener", "info",
            f"The link uses a link shortener ({link.host}), which hides where it really goes.",
        ))
    tld = link.host.rsplit(".", 1)[-1]
    if "." in link.host and tld in SUSPICIOUS_TLDS:
        signals.append(LinkSignal(
            "suspicious_tld", "warn",
            f"The address ends in .{tld}, an ending often used for throwaway scam sites.",
        ))
    return signals


def _ordered(signals: Sequence[LinkSignal]) -> tuple[LinkSignal, ...]:
    """Highest severity first, then the most telling code first; duplicates dropped."""
    unique = list(dict.fromkeys(signals))
    unique.sort(key=lambda s: (_SEVERITY_RANK.get(s.severity, 3), _CODE_RANK.get(s.code, 99)))
    return tuple(unique)


def host_of(url: str) -> str:
    """The host a browser opens for *url* exactly as written (no redirector unwrapped): ASCII,
    punycode for an international name, an IPv4 address in its dotted form, IPv6 in brackets;
    "" for a link that opens no site or cannot be read. For exemption lists, which must match
    the host the browser really reaches: with a backslash before "@accounts.google.com" the
    browser opens the host written before it). Never raises."""
    link = _parse(url)
    return _host_label(link) if link.kind == "web" else ""


def local_signals(url: str) -> tuple[LinkSignal, ...]:
    """Every local finding for *url* (after unwrap_redirector), highest severity first. Never
    raises: a link that cannot be read has the "unreadable" signal."""
    return _ordered(_signals(_parse(unwrap_redirector(url))))


def _text_hosts(text: str) -> list[_Link]:
    """The hosts link text names: URLs, www. names and bare domain tokens, in order. E-mail
    addresses and file names (report.pdf) name no host. Bounded: only the first
    _MAX_TEXT_CHARS of the text are read (a token cut by that limit is left out) and at most
    _MAX_TEXT_HOSTS host-like tokens are parsed."""
    # What the person sees: the invisible characters ("pay&shy;pal.com" reads as paypal.com)
    # go, or the text would name no host and a mismatch would go unnoticed.
    visible = _without_format_characters(text[: _MAX_TEXT_CHARS + 1])
    tokens = _TEXT_SPLIT_RE.split(visible)
    if len(text) > _MAX_TEXT_CHARS:
        tokens = tokens[:-1]
    found: list[_Link] = []
    parsed = 0
    for token in tokens:
        token = token.strip(_TEXT_STRIP)
        if not token or len(token) > 2_048:
            continue
        if parsed >= _MAX_TEXT_HOSTS:
            break
        match = _SCHEME_RE.match(token)
        if match and match.group(1).lower() in _WEB_SCHEMES:
            candidate = token
        elif "@" in token:
            continue
        else:
            bare = re.split(r"[/?#]", token, maxsplit=1)[0].rstrip(".")
            bare = bare.translate(_DOT_LOOKALIKES)
            if not _TEXT_HOST_RE.match(bare):
                continue
            tld = bare.rsplit(".", 1)[-1].lower()
            if not tld.isalpha() or not 2 <= len(tld) <= 24 or tld in _FILE_EXTENSIONS:
                if not bare.lower().startswith("www."):
                    continue
            candidate = "http://" + token
        parsed += 1
        link = _parse(candidate)
        if link.kind == "web":
            found.append(link)
    return found


def _site(link: _Link) -> str:
    """What "the same site" means for the text check: the registrable domain, or the IP."""
    return link.host if link.ip is not None else lookalike.registrable_domain(link.host)


def link_text_mismatch(text: str, href: str) -> Optional[LinkSignal]:
    """A text_mismatch signal when *text* names a host (a URL or a bare domain token) whose
    registrable domain differs from *href*'s; None when the text names no host or the same site.
    Never raises: link text is written by whoever sent the message, and a token in it that
    cannot be read names no host (the href's own findings are never lost to it)."""
    try:
        return _text_mismatch(text, href)
    except Exception:  # noqa: BLE001 - no finding from text that cannot be read
        return None


def _text_mismatch(text: str, href: str) -> Optional[LinkSignal]:
    if not isinstance(text, str) or not text.strip():
        return None
    target = _parse(unwrap_redirector(href))
    if target.kind != "web":
        return None
    named = _text_hosts(text)
    if not named:
        return None
    site = _site(target)
    if any(_site(link) == site for link in named):
        return None
    return LinkSignal(
        "text_mismatch", "high",
        f"The link text says {_host_label(named[0])} but the link goes to {_host_label(target)}.",
    )


# ── what may leave, and what a card shows ──────────────────────────────


def lookup_url(url: str, purpose: Purpose) -> Optional[str]:
    """What may be sent to Google for *url*, or None when it must not be looked up:
    - only http(s); never a non-public host (NON_PUBLIC_SUFFIXES, single label, private, loopback,
      link-local or reserved IP literal);
    - purpose "browser": scheme://host[:port]/ only (ACCOUNT-mode URLs carry session ids and OAuth
      codes; resolutions S4);
    - any other purpose: scheme://host[:port]/path, userinfo and fragment dropped, the query kept
      only when no parameter name is in SENSITIVE_QUERY_NAMES, no value is a 32+ character token
      ([A-Za-z0-9_.%-]{32,}) and services.security.contains() finds no secret in it; parameters
      are split on "&" and ";" (many servers read both) and decoded until stable;
    - and the path itself is dropped (scheme://host[:port]/ only) when any path segment holds a
      run of 24 or more characters of [A-Za-z0-9_.%~+-] with a digit in it (anywhere in the
      segment, so "cart;jsessionid=<32 hex>" and "<token>!" count), ends in base64 "=" padding, or
      contains() flags the path (review SEC-F10: reset links, magic sign-in links and share links
      carry their secret in a path segment, and S2 checks every new email's links);
    - capped at 2,048 characters (longer: the query is dropped; still longer: host only).

    For every purpose but "browser" a known redirector is unwrapped first (unwrap_redirector);
    the browser looks up the host it is really opening, and the redirect's own hop is checked
    when it happens. An e-mail address is never sent either, in the query or in the path
    (extra narrowing: it is the recipient's personal data, as in an unsubscribe link).

    A host holding a character the URL standard allows but no public name uses
    ("x$y.listed.example.org", which a browser opens) is looked up as its nearest ancestor made
    of DNS labels, scheme://ancestor[:port]/ only for every purpose: Google matches a host's
    suffixes, so a listed parent is still found, and a path under another host means nothing
    there. Never raises: when reducing the path or query fails, only scheme://host[:port]/ is
    sent, so the link is still looked up and less leaves."""
    link = _parse(url if purpose == "browser" else unwrap_redirector(url))
    if link.kind != "web" or not _public_host(link):
        return None
    origin = f"{link.scheme}://{link.lookup_netloc}"
    if purpose == "browser" or link.lookup_host != link.host:
        return origin + "/"
    try:
        path = "/" if _private_path(link.path) else link.path
        candidate = origin + path
        if link.query and _query_shareable(link.query):
            with_query = f"{candidate}?{link.query}"
            if len(with_query) <= _MAX_LOOKUP_CHARS:
                return with_query
        if len(candidate) <= _MAX_LOOKUP_CHARS:
            return candidate
    except Exception:  # noqa: BLE001 - the host alone: less leaves, and it is still looked up
        pass
    return origin + "/"


def _display(link: _Link) -> str:
    if link.kind == "web":
        try:
            path = "/" if _private_path(link.path) else link.path
        except Exception:  # noqa: BLE001 - a path that cannot be judged is not shown
            path = "/"
        if len(path) > _SHOWN_PATH_CHARS:
            path = path[: _SHOWN_PATH_CHARS - 3] + "..."
        return f"{link.scheme}://{link.netloc}{path}"
    if link.kind in ("script", "contact", "other"):
        return f"{link.scheme}:"
    return ""


def display_url(url: str) -> str:
    """The ``shown`` form (see LinkReport): of the real destination when *url* is a known
    redirector; a path that looks like it carries a token or an e-mail address (the same rule as
    lookup_url) shows as "/" and a long path is cut
    with "..."; a script, mail or phone link shows its scheme only; "" when unreadable. Never
    raises."""
    return _display(_parse(unwrap_redirector(url)))


def level_for(signals: Sequence[LinkSignal], service_status: ServiceStatus) -> Level:
    """dangerous when Google listed it; else suspicious when any signal is high; else
    no_known_threats when Google answered not_listed; else unknown."""
    if service_status == "listed":
        return "dangerous"
    if any(s.severity == "high" for s in signals):
        return "suspicious"
    if service_status == "not_listed":
        return "no_known_threats"
    return "unknown"


def _report(url: str, link: _Link, signals: Sequence[LinkSignal],
            service_status: ServiceStatus) -> LinkReport:
    if link.kind == "contact":
        # A mail, phone or text-message link opens no site: there is nothing to look up.
        service_status = "not_eligible"
    ordered = _ordered(signals)
    return LinkReport(
        url=url,
        shown=_display(link),
        host=_host_label(link) if link.kind == "web" else "",
        level=level_for(ordered, service_status),
        signals=ordered,
        service_status=service_status,
    )


def unreadable_report(url: Any, *, service_status: ServiceStatus = "no_key") -> LinkReport:
    """The report for a link that could not be read: the "unreadable" signal, nothing shown,
    no host. What every check falls back to, so a link that breaks a check still says so."""
    return _report(url, _UNREADABLE, [_unreadable_signal()], service_status)


def local_report(url: str, *, text: Optional[str] = None,
                 service_status: ServiceStatus = "no_key") -> LinkReport:
    """A report from the local checks alone (plus link_text_mismatch when *text* is given).
    mailto:, tel: and sms: links always report not_eligible. Never raises: link text that
    cannot be read adds nothing and keeps the link's own findings, and a link that cannot be
    read is reported with the "unreadable" signal."""
    try:
        target = unwrap_redirector(url) if isinstance(url, str) else url
        link = _parse(target)
        signals = _signals(link)
    except Exception:  # noqa: BLE001 - reported as a link that could not be read
        return unreadable_report(url, service_status=service_status)
    if text:
        mismatch = link_text_mismatch(text, target)
        if mismatch is not None:
            signals.append(mismatch)
    try:
        return _report(url, link, signals, service_status)
    except Exception:  # noqa: BLE001 - reported as a link that could not be read
        return unreadable_report(url, service_status=service_status)


# ── wording ────────────────────────────────────────────────────────────


def threat_words(threats: Sequence[str]) -> str:
    """'may be phishing or a scam' / 'may host malware' / 'may offer unwanted software' /
    'may offer harmful apps', joined; Google's guidelines ask for hedged wording."""
    wanted = set(threats)
    words = [text for code, text in _THREAT_WORDS if code in wanted]
    if not words:
        return "may be dangerous"
    if len(words) == 1:
        return words[0]
    return ", ".join(words[:-1]) + " and " + words[-1]


def advisory(service: Optional[str], threats: Sequence[str]) -> str:
    """"Google Safe Browsing says this site may be phishing or a scam (advisory provided by
    Google)", without a final full stop: the browser guard's block reason and the start of a
    listed link's note."""
    label = SERVICE_LABELS.get(service or "", "Google")
    return f"{label} says this site {threat_words(threats)} (advisory provided by Google)"


def model_safe_text(signal: LinkSignal) -> str:
    """The signal's sentence for text that goes back to the model (the browser hook's notes):
    a look-alike host is named in punycode only, because PromptGuard marks any mixed-script word
    high and the runtime then redacts the whole note (review SEC-F12). Owner-facing notes keep
    the Unicode form."""
    text = signal.text
    if signal.code == "lookalike_characters":
        match = re.fullmatch(
            r"The address uses look-alike letters: (.+) reads as (.+) \(written (\S+)\)\.", text
        )
        if match:
            reading, written = match.group(2), match.group(3)
            if reading.isascii():
                return f"The address uses look-alike letters: {written} reads as {reading}."
            return f"The address uses look-alike letters (written {written})."
        match = re.fullmatch(
            r"The address uses look-alike letters: .+ mixes alphabets in one name "
            r"\(written (\S+)\)\.",
            text,
        )
        if match:
            return (
                f"The address uses look-alike letters: {match.group(1)} mixes alphabets in one "
                "name."
            )
    if signal.code == "international_address":
        match = re.fullmatch(r"The address uses non-Latin letters \((.+), written (\S+)\)\.", text)
        if match:
            return f"The address uses non-Latin letters (written {match.group(2)})."
    if text.isascii():
        return text
    # A safety net for a sentence written another way: every word with a non-ASCII letter is
    # replaced by its punycode form when it is a host, else dropped.
    words: list[str] = []
    for word in text.split(" "):
        if word.isascii():
            words.append(word)
            continue
        core = word.strip(_TEXT_STRIP)
        encoded = lookalike.ascii_host(core) if "." in core else None
        words.append(word.replace(core, encoded) if encoded else "[non-Latin text]")
    return " ".join(words)


def _where(report: LinkReport) -> str:
    """The link as a note names it: the shown form without its scheme ("paypa1-verify.xyz/login")."""
    shown = report.shown or report.host or "a link"
    shown = shown.split("://", 1)[1] if "://" in shown else shown
    return shown[:-1] if shown.endswith("/") and shown.count("/") == 1 else shown


def _decapitalised(sentence: str) -> str:
    return "the " + sentence[4:] if sentence.startswith("The ") else sentence


def _not_checked_why(statuses: AbstractSet[str]) -> str:
    for status, why in _NOT_CHECKED_WHY:
        if status in statuses:
            return why
    return "Google could not be reached"


def security_notes(reports: Sequence[LinkReport], *, limit: int = 3) -> list[dict[str, str]]:
    """Typed notes for PendingApproval.security_notes: kind link_dangerous (high), link_suspicious
    (warn), and at most one aggregated link_not_checked (info); at most *limit* per-link notes plus
    'and N more links were flagged'. Text names hosts only.

    A link Google lists gets link_dangerous with Google's advisory; a link with a high local
    signal gets link_suspicious naming its most serious finding. Warning- and info-level
    signals alone (a shortener, an abused ending) add no note."""
    flagged: list[tuple[str, str, str]] = []   # (kind, severity, text), most serious first
    seen: set[str] = set()
    for report in sorted(reports, key=lambda r: 0 if r.level == "dangerous" else 1):
        if report.level == "dangerous":
            item = ("link_dangerous", "high",
                    f"Link check: {_where(report)} - {advisory(report.service, report.threats)}.")
        elif report.level == "suspicious":
            high = next((s for s in report.signals if s.severity == "high"), None)
            if high is None:
                continue
            item = ("link_suspicious", "warn", f"Link check: {_decapitalised(high.text)}")
        else:
            continue
        if item[2] in seen:
            continue
        seen.add(item[2])
        flagged.append(item)
    limit = max(int(limit), 0)
    notes = [{"kind": kind, "severity": sev, "text": text} for kind, sev, text in flagged[:limit]]
    rest = flagged[limit:]
    if rest:
        dangerous = any(kind == "link_dangerous" for kind, _, _ in rest)
        count = len(rest)
        notes.append({
            "kind": "link_dangerous" if dangerous else "link_suspicious",
            "severity": "high" if dangerous else "warn",
            "text": f"And {count} more link{'s were' if count != 1 else ' was'} flagged.",
        })
    not_checked = [r for r in reports if r.service_status in NOT_CHECKED_STATUSES]
    if not_checked:
        statuses = {r.service_status for r in not_checked}
        services = {r.service for r in not_checked if r.service}
        label = SERVICE_LABELS[sorted(services)[0]] if len(services) == 1 else "Google"
        eligible = [r for r in reports if r.service_status != "not_eligible"]
        some = "Links" if len(not_checked) == len(eligible) else "Some links"
        notes.append({
            "kind": "link_not_checked",
            "severity": "info",
            "text": f"{some} were not checked with {label} ({_not_checked_why(statuses)}).",
        })
    return notes


def coverage_note(reports: Sequence[LinkReport]) -> Optional[str]:
    """One sentence saying links were checked on this computer only (no key / switch off), or
    None when Google answered for every eligible link."""
    statuses = {r.service_status for r in reports if r.service_status != "not_eligible"}
    if not statuses or statuses <= {"listed", "not_listed"}:
        return None
    if "no_key" in statuses:
        return _NO_KEY_COVERAGE
    if "off" in statuses:
        return _OFF_COVERAGE
    failed = statuses & NOT_CHECKED_STATUSES
    if failed:
        return (
            f"Some links were checked on this computer only ({_not_checked_why(set(failed))})."
        )
    return _OFFLINE_COVERAGE


# ── the checker consumers depend on ────────────────────────────────────


def text_for(texts: Optional[Mapping[str, str]], url: Any) -> Optional[str]:
    """The link text a caller gave for *url*, or None (none given, not a string, or a *url*
    that cannot be a key). Never raises."""
    if not texts:
        return None
    try:
        text = texts.get(url)
    except Exception:  # noqa: BLE001 - an unhashable url has no text
        return None
    return text if isinstance(text, str) else None


class LinkChecker(Protocol):
    """What consumers (S1, S2, S3) depend on; LinkReputation and LocalOnlyLinkChecker satisfy it."""
    async def check(self, urls: Sequence[str], *, purpose: Purpose,
                    texts: Optional[Mapping[str, str]] = None, network: bool = True,
                    timeout_s: float = 8.0) -> list[LinkReport]: ...
    def check_local(self, url: str, *, text: Optional[str] = None) -> LinkReport: ...
    def cached_report(self, url: str, *, purpose: Purpose) -> Optional[LinkReport]: ...
    async def remote_configured(self) -> bool: ...


class LocalOnlyLinkChecker:
    """The null object: local checks only, every report service_status="no_key" (a mail, phone
    or text-message link: not_eligible). The default for consumers before wiring and in their
    tests."""

    async def check(self, urls: Sequence[str], *, purpose: Purpose,
                    texts: Optional[Mapping[str, str]] = None, network: bool = True,
                    timeout_s: float = 8.0) -> list[LinkReport]:
        try:
            items = list(urls)
        except Exception:  # noqa: BLE001 - nothing to report on
            return []
        return [local_report(url, text=text_for(texts, url)) for url in items]

    def check_local(self, url: str, *, text: Optional[str] = None) -> LinkReport:
        return local_report(url, text=text)

    def cached_report(self, url: str, *, purpose: Purpose) -> Optional[LinkReport]:
        return None

    async def remote_configured(self) -> bool:
        return False
