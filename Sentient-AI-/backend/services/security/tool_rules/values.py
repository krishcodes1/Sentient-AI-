"""Reads what a tool rule tests out of a call's arguments: the leaf values at an argument path,
text in the two normalised forms the matchers compare, the email addresses and link hosts a value
holds (domains IDNA-encoded, with a flag for look-alike characters), domain membership, and
numbers written as text.

Why it exists: a rule must see what a person would read, not what the bytes spell. It walks leaf
values one by one and normalises each (it never scans ``str(arguments)``, so tag characters and
zero-width splices cannot hide a match), and it treats the taint tracker's ASCII-only address
pattern as not enough: a homoglyph address is still found here and flagged as unusual. Keys that
start with "_" (facts the runtime binds to a card) are never read.

Addresses are read with every RFC 5322 local-part character and with quoted local parts, and an
"@" no readable address accounts for is counted (address_scan), so a spelling the parser misses
is a recipient the rules ask about, never one they cannot see. Links are read with the host a
browser opens (a "\" ends the authority as "/" does), and a link readers disagree about, or one
with user information, is marked deceptive.

Connects to: services.agent.prompt_guard.normalize_for_scan (look-alike folding and spliced-word
repair). Everything else is the standard library. Every pattern here starts a match only where
the run it scans cannot already be running, so a long hostile value costs linear time.
Used by: engine.py (conditions), builtins.py (B1-B4), context.py (the person's own addresses and
hosts) and grammar.py (domain values).
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterator, Mapping, Optional
from urllib.parse import unquote, urlsplit

from services.agent.prompt_guard import normalize_for_scan

# How deep and how wide a rule reads. A call beyond either is not read partly: the caller counts
# the rule as broken, so Crawler asks.
MAX_DEPTH = 16
MAX_LEAVES = 5000


class TooManyValues(ValueError):
    """The arguments are nested deeper or hold more values than a rule reads."""


# Characters that render as nothing (format characters, joiners, bidi controls, tag letters,
# variation selectors and the Hangul fillers). Removed before comparing text; inside an address
# they make it "unusual".
_INVISIBLE_CLASS = (
    "­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮"
    "⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ￹-￻"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef"
)
_INVISIBLE = re.compile(f"[{_INVISIBLE_CLASS}]")


def strip_invisible(text: str) -> str:
    """*text* without characters that render as nothing (every Unicode format character too)."""
    text = _INVISIBLE.sub("", text)
    if text.isascii():
        return text
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def has_invisible(text: str) -> bool:
    if _INVISIBLE.search(text):
        return True
    return not text.isascii() and any(unicodedata.category(ch) == "Cf" for ch in text)


# ---------------------------------------------------------------------------
# Selecting leaves
# ---------------------------------------------------------------------------


def _walk(value: Any, path: str, depth: int, out: list[tuple[str, Any]]) -> None:
    if depth > MAX_DEPTH:
        raise TooManyValues("arguments nested too deeply")
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key)
            if name.startswith("_"):
                continue  # card-bound facts the runtime adds; never the model's
            _walk(child, f"{path}.{name}" if path else name, depth + 1, out)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk(item, path, depth + 1, out)
    elif value is not None:
        out.append((path, value))
        if len(out) > MAX_LEAVES:
            raise TooManyValues("too many argument values")


def leaves(arguments: Any) -> list[tuple[str, Any]]:
    """Every leaf value with its dotted path (list positions are not part of a path): dicts
    descended, lists flattened, keys starting with "_" skipped, None counted as absent."""
    out: list[tuple[str, Any]] = []
    _walk(arguments, "", 0, out)
    return out


def _flatten(node: Any, depth: int) -> Iterator[Any]:
    if depth > MAX_DEPTH:
        raise TooManyValues("arguments nested too deeply")
    if isinstance(node, (list, tuple)):
        for item in node:
            yield from _flatten(item, depth + 1)
    else:
        yield node


def select(arguments: Any, path: str) -> list[Any]:
    """Leaf values at *path* ("to", "fields.text"; lists flattened at every level, a path that
    names an object covers every leaf inside it); "*" is every leaf. Keys starting with "_"
    (card-bound facts) are never read, and an absent argument has no leaves."""
    if path == "*":
        return [value for _, value in leaves(arguments)]
    nodes: list[Any] = [arguments]
    for segment in path.split("."):
        if segment.startswith("_"):
            return []
        found: list[Any] = []
        for node in nodes:
            for item in _flatten(node, 0):
                if isinstance(item, Mapping) and segment in item:
                    found.append(item[segment])
        nodes = found
        if not nodes:
            return []
    out: list[tuple[str, Any]] = []
    for node in nodes:
        _walk(node, "", 0, out)
    return [value for _, value in out]


def leaf_text(value: Any) -> Optional[str]:
    """A leaf as text for the text matchers: strings as they are, numbers as written, booleans
    as "true"/"false"; None for anything else."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return None


# ---------------------------------------------------------------------------
# Normalised text
# ---------------------------------------------------------------------------


def simple_form(text: str) -> str:
    """NFKC, invisible and bidi characters removed, casefolded, whitespace collapsed."""
    if text.isascii():
        return " ".join(text.lower().split())
    folded = strip_invisible(unicodedata.normalize("NFKC", text)).casefold()
    return " ".join(folded.split())


def scan_form(text: str) -> str:
    """The prompt guard's canonical form (fullwidth folded, Cyrillic and Greek look-alikes mapped
    to Latin, spliced words re-joined), casefolded and whitespace-collapsed. Invisible characters
    are removed first, so a format character the guard's own list misses cannot split a word."""
    return " ".join(normalize_for_scan(strip_invisible(text)).casefold().split())


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

_ASCII_HOST = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
)


def idna_domain(domain: str) -> Optional[str]:
    """*domain* lower-case and IDNA-encoded ("München.de." -> "xn--mnchen-3ya.de"), or None when
    it cannot be encoded. Invisible characters are dropped first."""
    cleaned = strip_invisible(domain).strip().rstrip(".")
    if not cleaned:
        return None
    if cleaned.isascii():
        return cleaned.lower()
    try:
        return cleaned.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None


def is_hostname(domain: str) -> bool:
    """True for an encoded host with at least one dot and a real top-level label."""
    return bool(_ASCII_HOST.fullmatch(domain))


def in_domains(domain: str, domains: frozenset[str] | set[str]) -> bool:
    """True when *domain* is one of *domains* or a subdomain of one. A look-alike is neither:
    "myco.com.evil.net" and "rnyco.com" are outside "myco.com"."""
    host = domain.strip().rstrip(".").lower()
    if not host:
        return False
    if host in domains:
        return True
    return any(host.endswith("." + d) for d in domains if d)


def parent_domains(host: str) -> list[str]:
    """*host* and each domain it sits under: "a.b.example.com" -> [itself, "b.example.com",
    "example.com", "com"]."""
    labels = host.strip().rstrip(".").lower().split(".")
    return [".".join(labels[i:]) for i in range(len(labels)) if labels[i]]


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

# Local part characters: every RFC 5322 atext character (word characters in any script, the dot,
# and ! # $ % & ' * + - / = ? ^ _ ` { | } ~), plus the invisible ones, so a zero-width splice is
# part of the address (and makes it unusual) rather than cutting it in two. Reading only the
# common ones let "x=@evil.com" or "a#@evil.com" go unseen: no address, so B1-B3 had nothing to
# check. A match starts only where a local part cannot already be running.
_LOCAL_CHARS = rf"\w.!#$%&'*+/=?^`{{|}}~\-{_INVISIBLE_CLASS}"
_DOMAIN_CHARS = rf"\w\-.{_INVISIBLE_CLASS}"
# The domain is read in a look-ahead, so it is not consumed: in "a@b@evil.com" the scan goes on
# to read "b@evil.com" (as the taint tracker does) after "a@b" fails. Each run of characters is
# still read at most twice (once as a domain, once as a local part).
_ADDRESS = re.compile(rf"(?<![{_LOCAL_CHARS}])([{_LOCAL_CHARS}]+)@(?=([{_DOMAIN_CHARS}]+))")
# A quoted local part ('"ceo@myco.com"@evil.com' is one address at evil.com). At most 64
# characters inside the quotes (the RFC's local-part limit). An opening quote never follows a
# backslash (a backslash outside quotes is no address character), so every '"' a scan can start
# at ends the scan before it: the scans never overlap, and a run of '\"' costs linear time.
_QUOTED_ADDRESS = re.compile(rf'(?<!\\)("(?:[^"\\\r\n]|\\[^\r\n]){{0,64}}")@([{_DOMAIN_CHARS}]+)')
# The local-part characters most addresses use, and the ones the taint tracker's own address
# pattern reads (services/agent/taint.py reads only the ASCII ones). A local part with any other
# character, or a quoted one, is "unusual": the tracker cannot see it, so B1 asks unless the person
# typed it.
_COMMON_LOCAL = re.compile(rf"[\w.%+\-{_INVISIBLE_CLASS}]*")
_UNCOMMON_LOCAL_CHAR = re.compile(rf"[^\w.%+\-{_INVISIBLE_CLASS}]")
# Characters a reader or a later system may take for "@" (fullwidth and small commercial at).
_AT_LOOKALIKES = ("＠", "﹫")


@dataclass(frozen=True)
class Address:
    """One email address found in a value.

    ``text`` is the address as written (invisible characters kept); ``local`` is its local part,
    casefolded; ``domain`` is lower-case and IDNA-encoded (the casefolded text when it cannot be
    encoded); ``unusual`` is True for non-ASCII, punycode or invisible characters, a quoted local
    part, or a local-part character beyond letters, digits and . _ % + - (an RFC 5322 character
    such as = # ' / that the taint tracker's pattern cannot see). ``key`` is the identity used to
    compare addresses: two spellings that deliver to the same mailbox share it, and an address
    with a hidden character never shares one with its visible twin.

    ``narrow`` is the address the common characters alone spell at the end of the local part
    ("bob@x.com" inside "x=bob@x.com"), when that differs: what the taint tracker records for
    this text, so lookups try it too (``forms``), and what the person's own text has always
    counted as (context.owner_addresses_of). It is never a separate recipient."""

    text: str
    local: str
    domain: str
    unusual: bool
    key: str
    narrow: Optional["Address"] = None

    @property
    def forms(self) -> tuple[str, ...]:
        """The lower-case spellings a taint lookup should try."""
        own = (self.text.lower(), f"{self.local}@{self.domain}", self.key)
        extra = self.narrow.forms if self.narrow is not None else ()
        return tuple(dict.fromkeys((*own, *extra)))

    @property
    def keys(self) -> tuple[str, ...]:
        """``key``, and the narrow address's key when there is one."""
        return (self.key,) if self.narrow is None else (self.key, self.narrow.key)


def _narrow_local(local_raw: str) -> str:
    """The run of common local-part characters at the end of *local_raw* (linear: the reversed
    text is matched once from its start)."""
    run = _COMMON_LOCAL.match(local_raw[::-1])
    return run.group()[::-1] if run else ""


def _address(local_raw: str, domain_raw: str, *, quoted: bool = False) -> Optional[Address]:
    if not quoted:
        local_raw = local_raw.strip(".")
    domain_raw = domain_raw.rstrip(".-").lstrip(".")
    if not local_raw or not domain_raw:
        return None
    labels = strip_invisible(domain_raw).split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None
    tld = labels[-1]
    if not (
        (len(tld) >= 2 and tld.isalpha()) or (tld.lower().startswith("xn--") and len(tld) > 4)
    ):
        return None
    text = f"{local_raw}@{domain_raw}"
    encoded = idna_domain(domain_raw)
    hidden = has_invisible(text)
    uncommon = quoted or _UNCOMMON_LOCAL_CHAR.search(local_raw) is not None
    unusual = (
        not text.isascii()
        or hidden
        or uncommon
        or encoded is None
        or any(label.lower().startswith("xn--") for label in labels)
    )
    domain = encoded if encoded is not None else strip_invisible(domain_raw).casefold()
    local = unicodedata.normalize("NFC", local_raw).casefold()
    # A hidden character in the domain keeps the key apart from the visible twin even though
    # IDNA would map it away.
    key_domain = domain if not has_invisible(domain_raw) else domain_raw.casefold()
    narrow: Optional[Address] = None
    if uncommon and not quoted:
        tail = _narrow_local(local_raw)
        if tail.strip("."):
            narrow = _address(tail, domain_raw)
    return Address(
        text=text,
        local=local,
        domain=domain,
        unusual=unusual,
        key=f"{local}@{key_domain}",
        narrow=narrow,
    )


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
        return
    for _, leaf in leaves(value):
        if isinstance(leaf, str):
            yield leaf


def _scan(text: str) -> list[tuple[int, int, Address]]:
    """(start, end, address) for every address in one string, in order of position.

    Both readings count: an address with a quoted local part, and every unquoted address,
    including one inside a quoted local part ('"a, x@evil.com, b"@myco.com' is read as the
    quoted address at myco.com and as x@evil.com, since a system that splits at commas would
    send to the second). Rules then see every place the text could go."""
    found: list[tuple[int, int, Address]] = []
    for match in _ADDRESS.finditer(text):
        address = _address(match.group(1), match.group(2))
        if address is not None:
            found.append((match.start(), match.end(2), address))
    if '"@' in text:  # a quoted local part always ends right before its "@"
        for match in _QUOTED_ADDRESS.finditer(text):
            address = _address(match.group(1), match.group(2), quoted=True)
            if address is not None:
                found.append((match.start(), match.end(), address))
        found.sort(key=lambda item: (item[0], -item[1]))
    return found


def _unread_at_signs(text: str, spans: list[tuple[int, int, Address]]) -> int:
    """How many "@" signs (or look-alikes) in *text* no address in *spans* accounts for."""
    count = sum(text.count(sign) for sign in _AT_LOOKALIKES)
    position, index, covered_to = text.find("@"), 0, -1
    while position >= 0:
        while index < len(spans) and spans[index][0] <= position:
            covered_to = max(covered_to, spans[index][1])
            index += 1
        if position >= covered_to:
            count += 1
        position = text.find("@", position + 1)
    return count


def address_scan(value: Any) -> tuple[list[Address], int]:
    """(every email address in *value*, how many "@" signs no address accounts for).

    The count is what a rule cannot read: an "@" with no local part, a one-label or numeric
    domain, a comment or an IP literal where a domain should be, or a fullwidth "@". On a
    recipients argument each one is a recipient the rules cannot place, so they ask. Linear in
    the length of the value."""
    found: list[Address] = []
    unread = 0
    for text in _strings(value):
        if "@" not in text and not any(sign in text for sign in _AT_LOOKALIKES):
            continue
        spans = _scan(text)
        found.extend(address for _, _, address in spans)
        unread += _unread_at_signs(text, spans)
    return found, unread


def addresses_in(value: Any) -> list[Address]:
    """Every email address in *value* (display names, comma or semicolon lists, nested lists,
    quoted local parts), in order; repeats are kept (callers count unique ``key``s)."""
    found: list[Address] = []
    for text in _strings(value):
        if "@" not in text:
            continue
        found.extend(address for _, _, address in _scan(text))
    return found


_PART_SPLIT = re.compile(r"[,;\n]")
# Stands in for each character inside a closed quoted string while a list is split, so a quoted
# display name keeps its commas, "@" and "<" to itself ("Smith, Bob" <bob@x.com>). It is no
# address character and no separator.
_MASK = "\x01"
# An angle-bracketed address ("Name <bob@x.com>"): "<", one run with no angle bracket, ">". The
# spaces inside are stripped afterwards in Python: written into the pattern as "<\s*...+?\s*>",
# three runs could split the same spaces between them, which cost cubic time on a value such as
# "a@b.com, <" followed by thousands of spaces (25 s for 4,000).
_ANGLE = re.compile(r"<([^<>]*)>")
# An RFC 5322 comment after an address ("bob@x.com (Bob)").
_COMMENT = re.compile(r"\([^()]*\)")
# An RFC 5322 group label in front of its addresses ("Team: a@b.com, c@d.com;").
_GROUP_LABEL = re.compile(r"[^:<>@\"]{1,200}:")


def _masked_quotes(text: str) -> str:
    """*text* with the inside of every closed double-quoted string replaced by _MASK (same
    length, so positions still match the original); backslash escapes inside are skipped, and
    a quote that never closes is left as it is. One pass."""
    if '"' not in text:
        return text
    out: list[str] = []
    index, size = 0, len(text)
    while index < size:
        quote = text.find('"', index)
        if quote < 0:
            out.append(text[index:])
            break
        out.append(text[index : quote + 1])
        end = quote + 1
        while end < size and text[end] != '"':
            end += 2 if text[end] == "\\" else 1
        if end >= size:  # never closed: an ordinary character
            out.append(text[quote + 1 :])
            break
        out.append(_MASK * (end - quote - 1) + '"')
        index = end + 1
    return "".join(out)


def _whole_entry(text: str) -> Optional[list[Address]]:
    """The addresses *text* is aimed at, when the whole of it is one address: that address, and
    for a quoted local part also any address written inside the quotes (see _scan)."""
    text = text.strip()
    found = _scan(text)
    if any(text.strip(".") == address.text for _, _, address in found):
        return [address for _, _, address in found]
    return None


def _address_like(text: str) -> bool:
    """True for one token that is shaped like an address but is not one the rules can read:
    something before its last "@", and after it a domain-like part (a dot or an IP literal, no
    "/"), with no spaces: "bob@[10.0.0.1]", "a(b)@evil.com", "x@evil.c0m". Not "@channel",
    "<@U123>" or "git@github.com:org/repo.git"."""
    text = text.strip()
    if not text or any(ch.isspace() for ch in text):
        return False
    at = text.rfind("@")
    if at <= 0 or at == len(text) - 1:
        return False
    domain = text[at + 1 :]
    return "/" not in domain and ("." in domain or domain.startswith("["))


def _part_addresses(part: str, masked: str) -> Optional[tuple[list[Address], int]]:
    """(the addresses one list entry is aimed at, how many address-shaped spellings in it no
    rule can read), or None when the entry is prose. *masked* is the same entry with its quoted
    strings masked.

    - Every angle-bracketed address counts, whatever the display name in front of it holds
      (quotes, "@", "<", any length): '"ceo@myco.com" <attacker@evil.com>' is aimed at the
      second address, and is a valid RFC 5322 entry, not prose.
    - Otherwise the entry must be one address, after "mailto:", a group label ("Team:"), a
      trailing comment ("(Bob)") and surrounding quotes are taken off.
    - An entry, or an angle-bracketed part, shaped like one address that cannot be read
      ("bob@[10.0.0.1]") counts as one unreadable address, never as prose: the rules ask."""
    angled: list[Address] = []
    unread = 0
    for match in _ANGLE.finditer(masked):
        inner = part[match.start(1) : match.end(1)]
        entry = _whole_entry(inner)
        if entry is not None:
            angled.extend(entry)
        elif _address_like(inner):
            unread += 1
    if angled or unread:
        return angled, unread
    text = part.strip()
    if text.lower().startswith("mailto:"):
        text = text[len("mailto:") :]
    else:
        label = _GROUP_LABEL.match(masked.strip())
        if label is not None:
            text = text[label.end() :]
    text = _COMMENT.sub(" ", text).strip()
    for candidate in (text, text.strip("\"'").strip()):
        entry = _whole_entry(candidate)
        if entry is not None:
            return entry, 0
    if _address_like(text) or _address_like(part):
        return [], 1
    return None


def whole_address_scan(value: Any) -> tuple[list[Address], int]:
    """(the addresses in string leaves that ARE addresses or lists of them, how many entries of
    those lists are shaped like an address that cannot be read). Prose that mentions an address
    contributes neither: this is what counts as an address argument for a tool that declares
    none (an MCP tool, a built-in, a connector write without a recipients declaration).

    A list is split at commas, semicolons and line breaks outside quoted strings. Every entry
    must be an address (any RFC 5322 form: bare, quoted local part, "mailto:", 'Name <address>'
    with any display name, a group label, a comment) or an unreadable address-shaped token for
    the leaf to count; one prose entry makes the whole leaf prose. Linear in the length of the
    value."""
    found: list[Address] = []
    unread = 0
    for text in _strings(value):
        if "@" not in text:
            continue
        masked = _masked_quotes(text)
        entries: list[Optional[tuple[list[Address], int]]] = []
        start = 0
        for separator in (*_PART_SPLIT.finditer(masked), None):
            end = separator.start() if separator is not None else len(text)
            if masked[start:end].strip():
                entries.append(_part_addresses(text[start:end], masked[start:end]))
            start = separator.end() if separator is not None else end
        if entries and all(entry is not None for entry in entries):
            for entry in entries:
                if entry is not None:
                    found.extend(entry[0])
                    unread += entry[1]
    return found, unread


def whole_addresses(value: Any) -> list[Address]:
    """The addresses of whole_address_scan: string leaves that ARE addresses, or lists of them,
    not prose that mentions one."""
    return whole_address_scan(value)[0]


# ---------------------------------------------------------------------------
# Links and hosts
# ---------------------------------------------------------------------------

# The taint tracker's own URL pattern and trimming (services/agent/taint.py), so a URL found here
# is spelled exactly as the tracker recorded it; it also takes the spellings a browser reads as
# the same link ("https:\\evil.com", "https:/evil.com", "https:///evil.com"). The first
# character after the slashes is not a slash, so the two runs cannot split the same characters.
_URL = re.compile(r"https?:[/\\]+[^\s\"'<>)\]/\\][^\s\"'<>)\]]*", re.IGNORECASE)
# Where a browser ends a URL's authority: the first "/", "\", "?" or "#" (WHATWG URL parsing
# treats "\" like "/" in http and https URLs).
_AUTHORITY_END = re.compile(r"[/\\?#]")
# A bare host name in prose ("check evil.example"), any script, at most ten labels. A match starts
# only where a word, dot or hyphen is not already running.
_BARE_HOST = re.compile(
    r"(?<![\w.\-@])(?:[^\W_](?:[\w\-]{0,61}[^\W_])?\.){1,10}"
    r"(?:[^\W\d_]{2,63}|xn--[a-z0-9\-]{1,59})(?![\w\-])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Link:
    """One http(s) URL in a value.

    ``url`` is lower-case as the taint tracker spells it. ``host`` is the host a browser opens,
    lower-case and IDNA-encoded (None when the URL has no readable host), and ``raw_host`` is
    that host as written, lower-case. ``hosts`` holds every host any reader may take from the
    URL (the browser's and urllib's, encoded and as written).

    ``deceptive`` is True when the URL is written so that readers disagree about its site, or
    so that it shows one site and opens another: user information before an "@" in the
    authority ("https://myco.com@evil.com"), a "\\" where urllib keeps reading the authority
    ("https://evil.com\\@myco.com" opens evil.com in a browser, while urllib reads myco.com),
    a percent-encoded host, or slashes other than "//" after the scheme. Such a link never
    counts as one the person named (B4)."""

    url: str
    host: Optional[str]
    raw_host: Optional[str]
    hosts: tuple[str, ...] = ()
    deceptive: bool = False


def _clean_host(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    host = host.strip().rstrip(".").lower()
    return host or None


def _browser_host(url: str) -> tuple[Optional[str], bool]:
    """(the host a WHATWG browser opens for *url*, whether the authority is written in a way
    that hides it: user information, a percent-encoded host, or odd slashes)."""
    rest = url[url.index(":") + 1 :]
    slashes = len(rest) - len(rest.lstrip("/\\"))
    odd_slashes = rest[:slashes] != "//"
    rest = rest[slashes:]
    end = _AUTHORITY_END.search(rest)
    authority = rest[: end.start()] if end else rest
    userinfo, at, hostport = authority.rpartition("@")
    if hostport.startswith("["):
        close = hostport.find("]")
        host = hostport[1:close] if close > 0 else hostport[1:]
    else:
        host = hostport.partition(":")[0]
    hidden = bool(at) or "%" in authority or odd_slashes
    if "%" in host:
        host = unquote(host)
    return _clean_host(host), hidden


def _link(url: str) -> Link:
    browser_host, hidden = _browser_host(url)
    try:
        split_host = _clean_host(urlsplit(url).hostname)
    except ValueError:
        split_host = None
    hosts: list[str] = []
    for raw in (browser_host, split_host):
        if raw:
            hosts.append(raw)
            encoded = idna_domain(raw)
            if encoded:
                hosts.append(encoded)
    deceptive = hidden or split_host != browser_host
    return Link(
        url=url.lower(),
        host=idna_domain(browser_host) if browser_host else None,
        raw_host=browser_host,
        hosts=tuple(dict.fromkeys(hosts)),
        deceptive=deceptive,
    )


def link_spans(text: str) -> list[tuple[int, int, Link]]:
    """(start, end, link) for every http(s) URL in one string, in order."""
    if ":" not in text:
        return []
    found: list[tuple[int, int, Link]] = []
    for match in _URL.finditer(text):
        url = match.group().rstrip(".,);")
        found.append((match.start(), match.start() + len(url), _link(url)))
    return found


def without_deceptive_links(text: str) -> str:
    """*text* with every deceptive link (Link.deceptive) blanked out, same length."""
    spans = [(start, end) for start, end, link in link_spans(text) if link.deceptive]
    if not spans:
        return text
    parts: list[str] = []
    position = 0
    for start, end in spans:
        parts.append(text[position:start])
        parts.append(" " * (end - start))
        position = end
    parts.append(text[position:])
    return "".join(parts)


def links_in(value: Any) -> list[Link]:
    """Every http(s) URL in *value*'s string leaves, in order."""
    found: list[Link] = []
    for text in _strings(value):
        found.extend(link for _, _, link in link_spans(text))
    return found


def hosts_in(value: Any) -> list[str]:
    """The hosts of every http(s) URL in *value*, lower-case and IDNA-encoded: the host a browser
    opens and, for a URL readers disagree about, the host urllib reads too."""
    found: dict[str, None] = {}
    for link in links_in(value):
        for host in link.hosts:
            encoded = idna_domain(host)
            if encoded:
                found.setdefault(encoded, None)
    return list(found)


def bare_hosts_in(text: str) -> list[str]:
    """Host names written without a scheme in *text*, lower-case and IDNA-encoded."""
    found: list[str] = []
    for match in _BARE_HOST.finditer(text):
        host = idna_domain(match.group())
        if host and is_hostname(host):
            found.append(host)
    return found


def whole_host(text: str) -> Optional[str]:
    """The host *text* is when the whole value is one host name ("myco.com"), else None."""
    stripped = text.strip()
    match = _BARE_HOST.fullmatch(stripped)
    if match is None:
        return None
    host = idna_domain(stripped)
    return host if host and is_hostname(host) else None


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------

_CURRENCY = r"(?:[$€£¥₹]|usd|eur|gbp|us\$)"
_NUMBER = re.compile(
    rf"(?P<sign>[+-])?\s*{_CURRENCY}?\s*(?P<sign2>[+-])?\s*"
    r"(?P<int>\d{1,3}(?:,\d{3})+|\d+)?(?P<frac>\.\d+)?"
    rf"\s*{_CURRENCY}?",
    re.IGNORECASE,
)


def parse_number(value: Any) -> Optional[float]:
    """A number, or a string that is only a number ("$1,250.50", "1250", "-3.5 EUR"); None for
    anything else (booleans, prose, infinities)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 40:
        return None
    match = _NUMBER.fullmatch(text)
    if match is None or (match.group("int") is None and match.group("frac") is None):
        return None
    if match.group("sign") and match.group("sign2"):
        return None
    digits = (match.group("int") or "0").replace(",", "") + (match.group("frac") or "")
    try:
        number = float(digits)
    except ValueError:
        return None
    if "-" in (match.group("sign") or "", match.group("sign2") or ""):
        number = -number
    return number if math.isfinite(number) else None


__all__ = [
    "Address",
    "Link",
    "MAX_DEPTH",
    "MAX_LEAVES",
    "TooManyValues",
    "address_scan",
    "addresses_in",
    "bare_hosts_in",
    "has_invisible",
    "hosts_in",
    "idna_domain",
    "in_domains",
    "is_hostname",
    "leaf_text",
    "leaves",
    "link_spans",
    "links_in",
    "parent_domains",
    "parse_number",
    "scan_form",
    "select",
    "simple_form",
    "strip_invisible",
    "whole_address_scan",
    "whole_addresses",
    "whole_host",
    "without_deceptive_links",
]
