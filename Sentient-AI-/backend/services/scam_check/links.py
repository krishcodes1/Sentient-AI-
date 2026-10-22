"""The scam check's adapters to the link and file reputation services, and its sender checks.

Why it exists: S4's LinkChecker and S10's FileReputationService answer in their own words
(levels, signal codes, service statuses, file verdicts). The scam check needs one small shape
(LinkFinding, Signal, note codes) and one rule: whatever goes wrong, a link or file is "not
checked", never clean. This module is the only place that reads the other services' answers, so
if their final shape moves, only this file changes (S3 4.7; scaffold A8/A9).

What it relies on, read by attribute (duck-typed, so nothing here imports S4 or S10):
- S4 (scaffold A8, S4.md 4.2): ``await checker.check(urls, purpose="scam_check", network=True,
  timeout_s=...)`` -> one report per input URL in input order, each with ``url``, ``shown``,
  ``host``, ``level`` (dangerous / suspicious / no_known_threats / unknown), ``signals`` (each
  with a ``code``), ``threats``, ``service`` and ``service_status``; and ``await
  checker.remote_configured()``.
- S10 (scaffold A9, S10.md 4.2): ``await files.check_hash(user_id, sha256, source="scam",
  priority="explicit", alert="caller")`` -> a verdict with ``verdict`` (malicious / suspicious /
  no_detections / unknown / not_checked / pending), ``malicious``, ``suspicious``, ``engines``
  and ``reason`` (S10.md 4.6: no_key, switched_off, key_rejected, a limit ...); and ``await
  files.remote_configured()``. Hash lookups only: nothing here can
  upload a file (an upload is S10's own write, on its own approval card).

S3 never builds a network client, never reads a key and never sends anything itself.
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol, Sequence

import structlog

from services.security.lookalike import WELL_KNOWN_BRANDS, registrable_domain
from services.security.scam_signals import (
    MAX_URLS,
    Signal,
    ascii_host,
    display_url,
    fold_text,
    make_signal,
    url_host,
)

if TYPE_CHECKING:
    from services.scam_check.service import LinkFinding, ScamFile

logger = structlog.get_logger(__name__)

PURPOSE = "scam_check"
LINK_TIMEOUT_S = 8.0
MAX_FILES = 10

# S4 statuses that mean "Google was due to answer and did not": the link is not counted either
# way (S4.md 4.2 NOT_CHECKED_STATUSES, less too_many, which has its own note).
_FAILED_STATUSES = frozenset(
    {"settings_unreadable", "rate_limited", "cooling_down", "timeout", "error", "key_rejected"}
)
# Statuses that mean the owner has not set Google up (or turned it off): local lists only.
_LOCAL_ONLY_STATUSES = frozenset({"no_key", "off"})
# S4 signal codes that make a link a look-alike (strong) or otherwise risky (weak) for S3.
_LOOKALIKE_SIGNALS = frozenset({"lookalike_characters", "lookalike_brand", "brand_in_address"})
_RISKY_SIGNALS = frozenset({"ip_address", "credentials_in_url", "shortener", "suspicious_tld", "script_link"})


class LinkChecker(Protocol):
    """The part of S4's LinkChecker the scam check uses (scaffold A8)."""

    async def check(
        self,
        urls: Sequence[str],
        *,
        purpose: Any,
        texts: Any = None,
        network: bool = True,
        timeout_s: float = LINK_TIMEOUT_S,
    ) -> Sequence[Any]: ...

    async def remote_configured(self) -> bool: ...


class FileChecker(Protocol):
    """The part of S10's FileReputationService the scam check uses (scaffold A9)."""

    async def check_hash(self, user_id: str, sha256: str, **kwargs: Any) -> Any: ...

    async def remote_configured(self) -> bool: ...


KnownSite = Callable[[str], Optional[str]]


def _field(obj: Any, name: str, default: Any = None) -> Any:
    """*name* read as an attribute or a mapping key (a report may be either)."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _not_checked(url: str, origin: str) -> "LinkFinding":
    from services.scam_check.service import LinkFinding

    return LinkFinding(
        shown=display_url(url),
        host=url_host(url) or "",
        looks_like="",
        level="not_checked",
        checked_by=(),
        origin=origin,  # type: ignore[arg-type]  # checked by the callers' Literal
        codes=(),
    )


def _finding(url: str, report: Any, origin: str, known_site: Optional[KnownSite]) -> tuple["LinkFinding", str]:
    """One S4 report as a LinkFinding, and the note code it adds ("" for none)."""
    from services.scam_check.service import LinkFinding

    host = ascii_host(str(_field(report, "host", "") or "")) or url_host(url) or ""
    shown = str(_field(report, "shown", "") or "")
    if not shown or not shown.replace("\u2026", "").isascii():
        shown = display_url(url)
    signal_codes = tuple(
        str(_field(s, "code", "")).lower() for s in (_field(report, "signals", ()) or ()) if _field(s, "code", "")
    )
    service = str(_field(report, "service", "") or "").lower()
    status = str(_field(report, "service_status", "") or "").lower()
    threats = tuple(str(t).upper() for t in (_field(report, "threats", ()) or ()))
    level_in = str(_field(report, "level", "") or "").lower()
    codes = signal_codes + tuple(f"{service or 'safe_browsing'}:{t}" for t in threats)

    google_answered = status in ("listed", "not_listed") and service in ("safe_browsing", "web_risk")
    checked_by: tuple[str, ...] = ("local", service) if google_answered else ("local",)
    note = ""
    if level_in == "dangerous" or status == "listed":
        level = "malicious"
    elif set(signal_codes) & (_LOOKALIKE_SIGNALS | _RISKY_SIGNALS) or level_in == "suspicious":
        level = "suspicious"
    elif status in _FAILED_STATUSES:
        level, note = "not_checked", "links_unavailable"
    elif "unreadable" in signal_codes:
        # S4 could not parse the link, so its local lists never looked at it.
        level = "not_checked"
    else:
        level = "no_signs_found"
    if status in _LOCAL_ONLY_STATUSES:
        note = note or "links_local_only"
    elif status == "too_many":
        note = "too_many_links"
    looks_like = ""
    if level == "suspicious" and set(signal_codes) & _LOOKALIKE_SIGNALS and known_site and host:
        try:
            looks_like = ascii_host(known_site(host) or "") or ""
        except Exception as exc:  # a helper bug must not cost the whole check
            logger.warning("scam_check_known_site_failed", error_type=type(exc).__name__)
    finding = LinkFinding(
        shown=shown,
        host=host,
        looks_like=looks_like if looks_like != host else "",
        level=level,  # type: ignore[arg-type]  # one of the four above
        checked_by=checked_by,
        origin=origin,  # type: ignore[arg-type]
        codes=codes,
    )
    return finding, note


async def check_links(
    checker: Optional[LinkChecker],
    urls: Sequence[str],
    origin: str,
    *,
    known_site: Optional[KnownSite] = None,
    timeout_s: float = LINK_TIMEOUT_S,
) -> tuple[list["LinkFinding"], list[str]]:
    """LinkFindings for *urls* (at most MAX_URLS) and note codes; an absent checker or any
    exception makes every link not_checked with note "links_unavailable" (fail open, never
    clean). *known_site* names the site a look-alike imitates (the service passes
    services.security.lookalike's lookalike_of); without it a look-alike says only that it
    imitates another site."""
    wanted = list(dict.fromkeys(u for u in urls if isinstance(u, str) and u.strip()))
    notes: list[str] = []
    if len(wanted) > MAX_URLS:
        wanted = wanted[:MAX_URLS]
        notes.append("too_many_links")
    if not wanted:
        return [], notes
    if checker is None:
        return [_not_checked(u, origin) for u in wanted], [*notes, "links_unavailable"]
    try:
        reports = list(await checker.check(wanted, purpose=PURPOSE, network=True, timeout_s=timeout_s))
    except Exception as exc:
        logger.warning("scam_check_links_failed", error_type=type(exc).__name__)
        return [_not_checked(u, origin) for u in wanted], [*notes, "links_unavailable"]
    findings: list[LinkFinding] = []
    for index, url in enumerate(wanted):
        if index >= len(reports):
            findings.append(_not_checked(url, origin))
            notes.append("links_unavailable")
            continue
        try:
            finding, note = _finding(url, reports[index], origin, known_site)
        except Exception as exc:
            logger.warning("scam_check_link_report_unreadable", error_type=type(exc).__name__)
            finding, note = _not_checked(url, origin), "links_unavailable"
        findings.append(finding)
        if note:
            notes.append(note)
    return findings, list(dict.fromkeys(notes))


async def link_sources(checker: Optional[LinkChecker]) -> Optional[frozenset[str]]:
    """The sources S4 can use now ({"local", "safe_browsing"} with a Google key, {"local"}
    without); None when it cannot say (no checker, or it failed)."""
    if checker is None:
        return None
    try:
        remote = bool(await checker.remote_configured())
    except Exception as exc:
        logger.warning("scam_check_link_sources_failed", error_type=type(exc).__name__)
        return None
    return frozenset({"local", "safe_browsing"}) if remote else frozenset({"local"})


async def files_configured(checker: Optional[FileChecker]) -> Optional[bool]:
    """Whether S10 can look fingerprints up now (the status route's file_reputation); None
    when it cannot say."""
    if checker is None:
        return None
    try:
        return bool(await checker.remote_configured())
    except Exception as exc:
        logger.warning("scam_check_file_sources_failed", error_type=type(exc).__name__)
        return None


def _int(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


# S10's not_checked reasons that mean "no VirusTotal key, or file checks switched off" (S10.md
# 4.6): the only case where the file_not_checked note's "needs the owner's key" is true.
_FILE_KEY_MISSING = frozenset({"", "no_key", "switched_off", "off"})


def _file_note(answer: Any) -> str:
    """The note for one S10 answer that counts neither way: file_not_checked (no key or
    switched off), file_unknown (VirusTotal has never seen the hash) or file_unavailable
    (pending, a limit, a rejected key, an unreadable answer)."""
    kind = str(_field(answer, "verdict", "") or "").lower()
    if kind == "not_checked":
        reason = str(_field(answer, "reason", "") or "").lower()
        return "file_not_checked" if reason in _FILE_KEY_MISSING else "file_unavailable"
    if kind == "unknown":
        return "file_unknown"
    return "file_unavailable"


_FILE_NOTE_ORDER = ("file_not_checked", "file_unknown", "file_unavailable")


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _wanted_files(files: Sequence["ScamFile"]) -> list[tuple[str, Optional[int]]]:
    """(sha256 in lower case, size or None) of each file whose fingerprint is a real sha256,
    at most MAX_FILES; anything else is never sent to the file service."""
    wanted: list[tuple[str, Optional[int]]] = []
    for item in files:
        digest = getattr(item, "sha256", None)
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest.strip().lower()):
            continue
        size = getattr(item, "size_bytes", None)
        ok_size = isinstance(size, int) and not isinstance(size, bool) and size >= 0
        wanted.append((digest.strip().lower(), size if ok_size else None))
        if len(wanted) >= MAX_FILES:
            break
    return wanted


async def check_files_counted(
    checker: Optional[FileChecker],
    files: Sequence["ScamFile"],
    *,
    user_id: str,
) -> tuple[list[Signal], list[str], int]:
    """check_files plus how many files got an answer that counts (flagged or no detections):
    the service's "was anything analysed" fact. Hash lookups only, never an upload."""
    wanted = _wanted_files(files)
    if not wanted:
        return [], [], 0
    if checker is None:
        return [], ["file_not_checked"], 0
    flagged: dict[str, list[tuple[int, int]]] = {"file_malicious": [], "file_suspicious": []}
    notes: set[str] = set()
    answered = 0
    for digest, size in wanted:
        try:
            answer = await checker.check_hash(
                user_id,
                digest,
                size_bytes=size,
                source="scam",
                priority="explicit",
                alert="caller",
            )
        except Exception as exc:
            logger.warning("scam_check_file_lookup_failed", error_type=type(exc).__name__)
            notes.add("file_unavailable")
            continue
        kind = str(_field(answer, "verdict", "") or "").lower()
        engines = _int(_field(answer, "engines", 0))
        if kind == "malicious":
            flagged["file_malicious"].append((_int(_field(answer, "malicious", 0)), engines))
        elif kind == "suspicious":
            scanners = _int(_field(answer, "malicious", 0)) + _int(_field(answer, "suspicious", 0))
            flagged["file_suspicious"].append((scanners, engines))
        elif kind != "no_detections":
            notes.add(_file_note(answer))
            continue
        answered += 1
    signals: list[Signal] = []
    for code, counts in flagged.items():
        if counts:
            n, m = max(counts)
            signals.append(make_signal(code, count=len(counts), n=n, m=m))
    return signals, [code for code in _FILE_NOTE_ORDER if code in notes], answered


async def check_files(
    checker: Optional[FileChecker],
    files: Sequence["ScamFile"],
    *,
    user_id: str,
) -> tuple[list[Signal], list[str]]:
    """file_malicious / file_suspicious signals and note codes; hash lookups only, never an
    upload. A file with no answer counts neither way and adds a note saying why: no file
    service, no key or switched off is "file_not_checked"; a hash VirusTotal has never seen is
    "file_unknown"; pending, a limit, an error or an unreadable answer is "file_unavailable".
    A fingerprint that is not a sha256 is never sent."""
    signals, notes, _answered = await check_files_counted(checker, files, user_id=user_id)
    return signals, notes


def _registrable(host: str) -> str:
    return registrable_domain(host)


def _brands() -> tuple[str, ...]:
    """The well-known brands (services/security/lookalike.py, scaffold A6: the list the
    checkout's merchant check re-exports)."""
    return WELL_KNOWN_BRANDS


def _address_domain(value: str) -> tuple[str, str]:
    """(display name, ASCII domain) of an address as shown; ("", "") when unreadable."""
    if not isinstance(value, str) or not value.strip():
        return "", ""
    name, address = parseaddr(value.strip()[:320])
    _, at, domain = address.rpartition("@")
    host = ascii_host(domain) if at else None
    return name, host or ""


# Brand names that are also everyday words or names: "United States Postal Service", "Delta
# Dental", "Marriott Hotels" and "Target practice" are not those brands. A display name counts
# as one of them only when every other word in it is a service or product word ("Delta Air
# Lines", "Apple Support", "Target.com", "Zoom Meeting"). Adobe is not on this list: "Adobe
# Sign" and "Adobe Acrobat" are classic lures and the word is rare in a sender's name
# (checker finding).
_COMMON_WORD_BRANDS = frozenset(
    {
        "aa", "apple", "booking", "chewy", "delta", "dominos", "fandango", "hotels", "kayak",
        "lowes", "southwest", "stripe", "target", "united", "zoom",
    }
)
# Words a sender puts beside a brand's name in a display name ("PayPal Service", "Amazon.co.uk",
# "Apple ID", "Adobe Sign", "Zoom Meeting", "Your Apple Account Recovery"), and that may be
# glued to it ("PayPalSupport", "AppleID").
_SERVICE_WORDS = frozenset(
    {
        "access", "account", "accounts", "acrobat", "admin", "air", "airline", "airlines",
        "alert", "alerts", "app", "bank", "banking", "bill", "billing", "call", "calls", "card",
        "cards", "care", "center", "centre", "cloud", "co", "com", "communications", "corp",
        "credit", "customer", "customers", "delivery", "department", "dept", "desk", "doc",
        "docs", "document", "documents", "drive", "file", "files", "fraud", "help", "helpdesk",
        "icloud", "id", "inc", "info", "invitation", "invite", "invoice", "invoices", "lines",
        "llc", "login", "ltd", "mail", "meeting", "meetings", "member", "members",
        "membership", "message", "messages", "music", "net", "noreply", "notice",
        "notification", "notifications", "official", "online", "order", "orders", "org",
        "password", "pay", "payment", "payments", "plus", "premium", "prime", "protection",
        "purchase", "purchases", "receipt", "receipts", "recovery", "refund", "refunds",
        "renewal", "reply", "reset", "rewards", "secure", "security", "service", "services",
        "share", "shared", "shipping", "shop", "sign", "signin", "statement", "statements",
        "storage", "store", "subscription", "subscriptions", "support", "team", "the",
        "ticket", "tickets", "tv", "uk", "update", "updates", "us", "verification", "verify",
        "video", "wallet", "webinar", "webinars", "your",
    }
)
# Brands whose name is a plain travel word: a hotel's "Booking Receipt" or a site's
# "Hotels Support" is not Booking.com or Hotels.com. They count only when the display name
# spells the domain ("Booking.com", "Hotels.com Support").
_SPELLED_DOMAIN_BRANDS = frozenset({"booking", "hotels"})
# Two-letter endings anyone can register for nothing or that are sold as generic names
# (paypal.tk, amazon.co): the brand's name on them is not the brand's own country site.
_GENERIC_COUNTRY_ENDINGS = frozenset({"ai", "cc", "cf", "co", "ga", "gq", "io", "me", "ml", "su", "tk", "to", "ws"})
_NAME_WORD = re.compile(r"[^\W_]+")
_MAX_NAME_WORDS = 40


def _brand_named(label: str, words: Sequence[str]) -> bool:
    """Whether display-name *words* name the brand whose domain label is *label*: as a whole
    word, glued to a service word ("paypalsupport"), or (a brand of 5+ letters that is not an
    everyday word) spelt across words ("Pay Pal", "Home Depot"). Never as part of another word:
    Pineapple and Snapple are not Apple, Targeted is not Target. An everyday-word brand also
    needs every other word to be a service word; a travel-word brand needs its domain
    spelt out ("booking com")."""
    if label in _SPELLED_DOMAIN_BRANDS:
        spelt = any(a == label and b == "com" for a, b in zip(words, words[1:], strict=False))
        if not spelt:
            return False
        rest = [w for w in words if w not in (label, "com")]
    elif label in words:
        rest = [w for w in words if w != label]
    else:
        glued = [
            w
            for w in words
            if len(w) > len(label)
            and (
                (w.startswith(label) and w[len(label) :] in _SERVICE_WORDS)
                or (w.endswith(label) and w[: -len(label)] in _SERVICE_WORDS)
            )
        ]
        if glued:
            rest = [w for w in words if w not in glued]
        elif label not in _COMMON_WORD_BRANDS and len(label) >= 5 and _spelt_across(label, words):
            return True
        else:
            return False
    return label not in _COMMON_WORD_BRANDS or all(w in _SERVICE_WORDS for w in rest)


def _spelt_across(label: str, words: Sequence[str]) -> bool:
    """Two or more consecutive words that together spell *label* exactly."""
    for start in range(len(words)):
        joined = words[start]
        for end in range(start + 1, len(words)):
            joined += words[end]
            if joined == label:
                return True
            if len(joined) >= len(label) or not label.startswith(joined):
                break
    return False


def _brands_own_site(site: str, brand_domain: str) -> bool:
    """Whether the registrable *site* belongs to the brand: its own domain, or its name on a
    country ending (amazon.co.uk, paypal.de) or on .com. Not a cheap generic ending: on
    paypal.tk or amazon-help.lat the name proves nothing."""
    if site == _registrable(brand_domain):
        return True
    label = brand_domain.split(".", 1)[0]
    head, _, suffix = site.partition(".")
    if head != label or not suffix:
        return False
    # A two-part suffix only comes back from registrable_domain for a known country suffix
    # (co.uk, com.au).
    if suffix == "com" or "." in suffix:
        return True
    return len(suffix) == 2 and suffix.isalpha() and suffix not in _GENERIC_COUNTRY_ENDINGS


def sender_findings(sender: str, reply_to: str) -> tuple[list[Signal], list[str]]:
    """Signals from a sender and Reply-To (display-name brand vs domain, Reply-To on another
    domain) and the sender's domain as an https://<domain>/ URL for
    check_links(origin="sender").

    A display name that names a well-known brand (services.security.lookalike's list; see
    _brand_named) while the address is on none of the named brands' own sites (see
    _brands_own_site) is sender_impersonation (strong). Mail from one of the named brands'
    own sites is not ("Uber Eats" from ubereats.com, which also says Uber). Mail from another
    listed brand's domain is checked like any other: Google Docs, PayPal invoices, Square and
    Zoom relay mail under a display name the sender chooses ("Amazon Security" from
    google.com; checker finding). A Reply-To on another site than the sender's is
    reply_to_mismatch (weak)."""
    name, domain = _address_domain(sender)
    signals: list[Signal] = []
    urls: list[str] = []
    if domain:
        urls.append(f"https://{domain}/")
        site = _registrable(domain)
        words = _NAME_WORD.findall(fold_text(name))[:_MAX_NAME_WORDS] if name else []
        brands = _brands() if words else ()
        named = [b for b in brands if _brand_named(b.split(".", 1)[0], words)]
        if named and not any(_brands_own_site(site, b) for b in named):
            brand = named[0].split(".", 1)[0]
            signals.append(make_signal("sender_impersonation", brand=brand.capitalize(), domain=domain))
    _, reply_domain = _address_domain(reply_to)
    if reply_domain and domain and _registrable(reply_domain) != _registrable(domain):
        signals.append(make_signal("reply_to_mismatch", domain=reply_domain))
    return signals, urls
