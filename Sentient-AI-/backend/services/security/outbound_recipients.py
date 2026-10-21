"""Reads who an outgoing message goes to: parses recipient arguments (header strings, lists,
Google attendees, Microsoft Graph recipients), normalises each address, fingerprints addresses
and domains with a keyed hash for the sent-to history, says whether a recipient is the user, a
colleague, outside the organisation or unknown, flags addresses that imitate a familiar one or
use look-alike letters, and validates the organisation domains the owner types in.

Why it exists: an injected instruction's goal is usually to get Crawler to send something
somewhere (security S1), and a card that says "send_email requires approval" is easy to approve
without reading the address. These facts ("first time Crawler sends to anyone at
acme-payrnents.com", "looks like acmepayments.com", "outside your organisation") are what make
the card worth reading. The history must never hold an address (resolutions S1): only a keyed
HMAC per user, so the database alone cannot list or test the owner's correspondents.

Connects to: services/security/outbound.py (the call check builds its notes from these
answers), services/security/outbound_store.py (KnownRecipientStore keeps recipient_hmac values;
OrgDomains reuses organisation_domain_of), services/security/lookalike.py (WAVE 0's shared
look-alike helpers, scaffold A6: decode_host, mixed_script_reading, lookalike_of,
registrable_domain, WELL_KNOWN_BRANDS, TWO_PART_SUFFIXES) and core.config (ENCRYPTION_KEY, read
lazily for the HMAC key). No I/O and no logging: an address never reaches a log line from here.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from email.utils import parseaddr
from functools import lru_cache
from typing import Any, Collection, Iterable, Iterator, Literal, Optional, Protocol, Sequence, cast

from services.security import lookalike as _lookalike_module

# Public mail services: an address there says nothing about who the person works for, so these
# domains never count as "your organisation" and never as an owner-entered organisation domain
# (resolutions S1). services/security/lookalike.py is the one home of this list (scaffold A6;
# S2 reads it there too); it is re-exported here under the name S1's design gives it.
from services.security.lookalike import CONSUMER_MAIL_DOMAINS as CONSUMER_MAIL_DOMAINS

RecipientKind = Literal["address", "domain"]
RECIPIENT_KINDS: tuple[RecipientKind, ...] = ("address", "domain")

# A consumer domain is a look-alike reference only when its name is distinctive: "mail",
# "live", "free", "web", "me" or "tuta" are ordinary words, and the typo rule (one edit for a
# four-to-six letter name) would call mail to tata.com, line.me or tree.com an imitation of a
# mail service. An exact consumer domain is still never a concern. The ordinary-word names from
# three letters are still matched letter for letter after folding look-alike letters (1ive.com,
# rnsn.com, a0l.com, grnx.de): such a spelling is never an accident (_short_service_homograph).
_CONSUMER_REFERENCE_MIN = 5
_HOMOGRAPH_ONLY_MIN = 3


def _consumer_reference_order(domain: str) -> tuple[str, int, str]:
    """By name, and within one name the .com domain first, so a hit that could name yahoo.com,
    yahoo.co.uk or yahoo.co.jp names yahoo.com unless the recipient's own ending says otherwise."""
    name, _, ending = domain.partition(".")
    return (name, 0 if ending == "com" else 1, domain)


_CONSUMER_REFERENCES: tuple[str, ...] = tuple(
    sorted(CONSUMER_MAIL_DOMAINS, key=_consumer_reference_order)
)


def _is_short_service(domain: str) -> bool:
    """A consumer domain whose name is an ordinary word (see _CONSUMER_REFERENCE_MIN)."""
    name = domain.split(".", 1)[0]
    return len(name) < _CONSUMER_REFERENCE_MIN or name.isdigit()


_SHORT_SERVICES: tuple[str, ...] = tuple(
    domain
    for domain in _CONSUMER_REFERENCES
    if _is_short_service(domain)
    and len(domain.split(".", 1)[0]) >= _HOMOGRAPH_ONLY_MIN
    and not domain.split(".", 1)[0].isdigit()
)

_HMAC_DOMAIN = b"sentientai.known_recipients.hmac.v1:"

_MAX_RECIPIENTS = 500
_MAX_VALUE_CHARS = 20_000
_MAX_ADDRESS_CHARS = 320
_MAX_DEPTH = 3
_NOTE_LOCAL_MAX = 64
_LABEL_DOMAINS = 3

_ENTER_A_DOMAIN = "Enter a domain such as acme.com."
_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_BARE_ADDRESS_RE = re.compile(r"[^@\s<>\",;]+@[^@\s<>\",;]+")
# Where a list piece the parser could not read is cut into the tokens an address can be: at
# whitespace and every character that ends an address in a header. One split, no backtracking.
_ADDRESS_TOKEN_SPLIT_RE = re.compile(r"[\s<>\",;:()]+")
# IDNA 2003 (the stdlib codec) maps these to other letters ("faß" -> "fass"), which would show
# and fingerprint a different domain from the one mail is delivered to; IDNA 2008 keeps them.
_IDNA2008_DEVIATIONS = frozenset("\u00df\u03c2")  # sharp s, final sigma


# ---------------------------------------------------------------------------
# The look-alike helpers (scaffold A6)
# ---------------------------------------------------------------------------


class _LookalikeHit(Protocol):
    @property
    def known(self) -> str: ...

    @property
    def rule(self) -> str: ...


class _LookalikeApi(Protocol):
    """The part of services/security/lookalike.py (scaffold A6/F39) this module reads."""

    WELL_KNOWN_BRANDS: Sequence[str]
    TWO_PART_SUFFIXES: Collection[str]

    def registrable_domain(self, host: str) -> str: ...

    def decode_host(self, host: str) -> Optional[str]: ...

    def mixed_script_reading(self, host: str) -> Optional[str]: ...

    def skeleton(self, label: str) -> str: ...

    def lookalike_of(self, host: str, known: Sequence[str] = ...) -> Optional[_LookalikeHit]: ...


def _lookalike() -> _LookalikeApi:
    """services/security/lookalike.py (scaffold A6), as the narrow interface this module reads.
    Only address_concern, org_view, organisation_domain_of and validate_organisation_domain
    need it; parsing, normalising and fingerprinting never do."""
    return cast(_LookalikeApi, _lookalike_module)


# ---------------------------------------------------------------------------
# Recipients
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Recipient:
    shown: str  # the bare address as written (kept for matching; never put in a note as is)
    address: str  # normalised: lower case, "+tag" dropped, gmail dots dropped, A-label domain
    domain: str  # A-label domain


def _a_label(domain: str) -> Optional[str]:
    """*domain* as lower-case IDNA A-labels, or None when it is not a usable domain."""
    domain = domain.strip().rstrip(".").lower()
    if not domain or len(domain) > 253 or domain.startswith("["):
        return None
    if domain.isascii():
        labels = domain.split(".")
        if any(not ch.isprintable() or ch.isspace() for ch in domain):
            return None
        return domain if all(0 < len(label) <= 63 for label in labels) else None
    out: list[str] = []
    for label in domain.split("."):
        if not label:
            return None
        if label.isascii():
            out.append(label)
            continue
        label = unicodedata.normalize("NFC", label)
        try:
            if any(ch in _IDNA2008_DEVIATIONS for ch in label):
                encoded = "xn--" + label.encode("punycode").decode("ascii")
            else:
                encoded = label.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if not 0 < len(encoded) <= 63:
            return None
        out.append(encoded.lower())
    joined = ".".join(out)
    return joined if len(joined) <= 253 else None


def _parsed_address(text: str) -> Optional[str]:
    """email.utils' reading of one list piece: its address ("" when it reads none), or None
    when the parser fails on it. The parser recurses once per nested comment or ":" group, so a
    piece of a few hundred nested "(" or a thousand ":" raises RecursionError; that must never
    escape (unparseable entries are skipped, and the call check reads attacker-written text)."""
    try:
        return parseaddr(text)[1]
    except Exception:  # RecursionError on deep nesting, or a parser bug on odd input
        return None


def _bare_addresses(text: str) -> list[str]:
    """The address part of ``Name <addr>`` or a bare address ([] when there is none).
    email.utils refuses some inputs a connector still accepts (Outlook's own check is looser),
    so a plain local@domain token is accepted too. When the parser fails on the piece, every
    local@domain token in it is returned: an address the parser could not place still gets its
    notes (a look-alike, a first-time domain) instead of vanishing from the card. Linear."""
    address = _parsed_address(text)
    if address is None:
        return [
            token
            for token in _ADDRESS_TOKEN_SPLIT_RE.split(text)
            if _BARE_ADDRESS_RE.fullmatch(token)
        ]
    if address and "@" in address:
        return [address.strip()]
    candidate = text.strip().strip("<>").strip()
    return [candidate] if _BARE_ADDRESS_RE.fullmatch(candidate) else []


def _bare_address(text: str) -> str:
    """The one address in *text*; "" when there is none or more than one."""
    found = _bare_addresses(text)
    return found[0] if len(found) == 1 else ""


def normalize_address(raw: str) -> Optional[str]:
    """The address Crawler compares and fingerprints: parsed with email.utils.parseaddr, lower
    case, a "+tag" dropped from the local part, the domain stripped of a trailing dot and
    IDNA-encoded (failure: None), googlemail.com read as gmail.com and dots dropped there (Gmail
    ignores them). None for anything that is not a single usable address."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or len(text) > _MAX_ADDRESS_CHARS * 2:
        return None
    address = _bare_address(text)
    local, at, domain = address.rpartition("@")
    if not at or not local or not domain or any(ch.isspace() for ch in local):
        return None
    local = local.lower().split("+", 1)[0]
    ascii_domain = _a_label(domain)
    if not local or ascii_domain is None:
        return None
    if ascii_domain == "googlemail.com":
        ascii_domain = "gmail.com"
    if ascii_domain == "gmail.com":
        local = local.replace(".", "")
        if not local:
            return None
    return f"{local}@{ascii_domain}"


def _split_address_list(text: str) -> Iterator[str]:
    """Pieces of a comma- or semicolon-separated list, keeping a quoted display name with a
    comma in it ("Doe, John" <j@x.com>) whole."""
    piece: list[str] = []
    quoted = False
    escaped = False
    angle = 0
    for ch in text[:_MAX_VALUE_CHARS]:
        if escaped:
            escaped = False
        elif quoted and ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif not quoted and ch == "<":
            angle += 1
        elif not quoted and ch == ">":
            angle = max(0, angle - 1)
        elif not quoted and not angle and ch in ",;":
            joined = "".join(piece).strip()
            if joined:
                yield joined
            piece = []
            continue
        piece.append(ch)
    joined = "".join(piece).strip()
    if joined:
        yield joined


def _raw_addresses(value: Any, depth: int = 0) -> Iterator[str]:
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, str):
        for piece in _split_address_list(value):
            yield from _bare_addresses(piece)
    elif isinstance(value, dict):
        nested = value.get("emailAddress")
        candidate = value.get("email") or value.get("address")
        if candidate is None and isinstance(nested, dict):
            candidate = nested.get("address")
        if isinstance(candidate, str):
            yield from _raw_addresses(candidate, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value[:_MAX_RECIPIENTS]:
            yield from _raw_addresses(item, depth + 1)


def parse_recipients(value: Any) -> list[Recipient]:
    """From a comma/semicolon string ("Ann <a@x.com>, b@y.com"), a list of strings, Google
    attendee dicts ({"email": ...}) or Graph recipients ({"emailAddress": {"address": ...}}).
    Unparseable entries are skipped (the connector's own validation refuses them); a piece the
    mail parser fails on (comments or groups nested hundreds deep) gives every local@domain
    token in it. Each address appears once, in the order written. Never raises."""
    recipients: list[Recipient] = []
    seen: set[str] = set()
    for shown in _raw_addresses(value):
        address = normalize_address(shown)
        if address is None or address in seen:
            continue
        seen.add(address)
        recipients.append(
            Recipient(shown=shown, address=address, domain=address.rpartition("@")[2])
        )
        if len(recipients) >= _MAX_RECIPIENTS:
            break
    return recipients


def _shows_nothing(ch: str) -> bool:
    if unicodedata.category(ch) in ("Cc", "Cf"):
        return True
    code = ord(ch)
    return (
        code in (0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0)
        or 0xFE00 <= code <= 0xFE0F
        or 0xE0100 <= code <= 0xE01EF
    )


def note_address(r: Recipient) -> str:
    """How an address appears in a note (review SEC-F9): the local part as written with every
    unicodedata Cc and Cf character removed (bidi controls, zero-width characters, tag
    characters), then "@", then the A-label domain. Keeps "+tags" and dots the owner would
    recognise; never shows a raw mixed-script or right-to-left-overridden address. Every S1 note
    builds addresses with it. (Hangul fillers, the grapheme joiner and variation selectors,
    which show nothing either, go too.)"""
    local = r.shown.rpartition("@")[0] or r.address.rpartition("@")[0]
    visible = "".join(ch for ch in local if not _shows_nothing(ch))
    if len(visible) > _NOTE_LOCAL_MAX:
        visible = visible[:_NOTE_LOCAL_MAX] + "..."
    return f"{visible or r.address.rpartition('@')[0]}@{r.domain}"


# ---------------------------------------------------------------------------
# Fingerprints for the sent-to history (S1 design 3.3)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=4)
def _derive_key(encryption_key: str) -> tuple[bytes, str]:
    key = hashlib.sha256(_HMAC_DOMAIN + encryption_key.encode("utf-8")).digest()
    return key, hashlib.sha256(key).hexdigest()[:8]


def _hmac_key() -> tuple[bytes, str]:
    # Read on every call (not at import) so a changed ENCRYPTION_KEY takes effect and this
    # module stays importable where settings are not configured.
    from core.config import settings

    return _derive_key(settings.ENCRYPTION_KEY)


def hmac_key_id() -> str:
    """The first 8 hex of sha256(hmac_key): stored beside every fingerprint so rows made under
    another ENCRYPTION_KEY are ignored (every recipient is "first time" again, the cautious
    direction) and pruned."""
    return _hmac_key()[1]


def recipient_hmac(user_id: str, kind: Literal["address", "domain"], value: str) -> str:
    """Hex HMAC-SHA256 of ``f"{user_id}\\x00{kind}\\x00{value}"`` under a key derived from
    ENCRYPTION_KEY (domain-separated from its other uses). Keyed, so the database alone cannot
    test guesses or list correspondents; per user, so one address gives two users different
    values. *value* is a normalised address or its domain."""
    if kind not in RECIPIENT_KINDS:
        raise ValueError(f"unknown recipient kind: {kind!r}")
    key, _ = _hmac_key()
    message = f"{str(user_id).strip().lower()}\x00{kind}\x00{value}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Organisation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrgView:
    own_addresses: frozenset[str]  # normalised: User.email + connector account addresses known
    domains: frozenset[str]  # non-consumer domains of those + organisation_domains rows
    label: str  # "northwind.com" or "northwind.com, acme.co.uk"


def _is_consumer(domain: str, registrable: str) -> bool:
    return domain in CONSUMER_MAIL_DOMAINS or registrable in CONSUMER_MAIL_DOMAINS


def organisation_domain_of(address: str) -> Optional[str]:
    """The organisation domain an address speaks for: the registrable domain of its normalised
    domain (``ann@eu.northwind.com`` -> ``northwind.com``), or None for a public mail service or
    anything that is not an address. Shared with OrgDomains (scaffold A24)."""
    normalised = normalize_address(address) if isinstance(address, str) else None
    if normalised is None:
        return None
    domain = normalised.rpartition("@")[2]
    registrable = _lookalike().registrable_domain(domain)
    if _is_consumer(domain, registrable):
        return None
    return registrable


def _domain_label(domains: Sequence[str]) -> str:
    if len(domains) <= _LABEL_DOMAINS:
        return ", ".join(domains)
    return f"{', '.join(domains[:_LABEL_DOMAINS])} and {len(domains) - _LABEL_DOMAINS} more"


def org_view(own_addresses: Iterable[str], organisation_domains: Iterable[str] = ()) -> OrgView:
    """The user's organisation as the check sees it: their own addresses (the sign-in email
    and any connector account address known), the non-consumer registrable domains of those,
    and the owner's organisation_domains rows (already validated A-labels). Consumer domains
    never join ``domains``."""
    own: list[str] = []
    ordered: list[str] = []
    for raw in own_addresses:
        normalised = normalize_address(raw) if isinstance(raw, str) else None
        if normalised is None or normalised in own:
            continue
        own.append(normalised)
        domain = organisation_domain_of(normalised)
        if domain and domain not in ordered:
            ordered.append(domain)
    lookalike = _lookalike()
    for row in organisation_domains:
        domain = _a_label(row) if isinstance(row, str) else None
        if not domain or domain in ordered:
            continue
        if _is_consumer(domain, lookalike.registrable_domain(domain)):
            continue
        ordered.append(domain)
    return OrgView(
        own_addresses=frozenset(own), domains=frozenset(ordered), label=_domain_label(ordered)
    )


def _inside(domain: str, domains: Iterable[str]) -> bool:
    return any(domain == known or domain.endswith("." + known) for known in domains)


def classify(r: Recipient, org: OrgView) -> Literal["self", "inside", "outside", "unknown"]:
    """self: one of own_addresses; inside: domain equals or is a subdomain of org.domains;
    unknown: org.domains is empty (nobody is "outside" an organisation that is not known);
    outside: otherwise."""
    if r.address in org.own_addresses:
        return "self"
    if not org.domains:
        return "unknown"
    return "inside" if _inside(r.domain, org.domains) else "outside"


@dataclass(frozen=True)
class AddressConcern:
    kind: Literal["lookalike", "unusual_characters"]
    severity: Literal["high", "warn", "info"]
    reference: str  # the domain it imitates ("" for unusual_characters)
    # unusual_characters (high): how the domain reads in Latin letters ("acme.com"), for the
    # note "{shown} uses look-alike letters: it reads as {reading}."; "" otherwise.
    reading: str = ""


def _references(org: OrgView, lookalike: _LookalikeApi) -> tuple[str, ...]:
    """What a recipient domain is compared against, as registrable domains: the organisation,
    the user's own address domains, the distinctive public mail services and the well-known
    brands."""
    references: list[str] = []
    seen: set[str] = set()
    own_domains = (address.rpartition("@")[2] for address in sorted(org.own_addresses))
    candidates: Iterable[str] = (
        *sorted(org.domains),
        *own_domains,
        *_CONSUMER_REFERENCES,
        *lookalike.WELL_KNOWN_BRANDS,
    )
    for candidate in candidates:
        if candidate in CONSUMER_MAIL_DOMAINS and _is_short_service(candidate):
            continue
        registrable = lookalike.registrable_domain(candidate)
        if registrable not in seen:
            seen.add(registrable)
            references.append(registrable)
    return tuple(references)


def _ending(domain: str) -> str:
    return domain.partition(".")[2]


def _preferred_reference(known: str, registrable: str, references: Sequence[str]) -> str:
    """Among the references with the hit's name (yahoo.com, yahoo.co.uk, yahoo.co.jp), the one
    under the recipient's own ending, so the card names the domain the address imitates."""
    name = known.split(".", 1)[0]
    for reference in references:
        if reference.split(".", 1)[0] == name and _ending(reference) == _ending(registrable):
            return reference
    return known


def _short_service_homograph(
    decoded: str, registrable: str, lookalike: _LookalikeApi
) -> Optional[AddressConcern]:
    """A label (or a hyphenated part of one) that reads as an ordinary-word mail service's name
    once look-alike letters are folded, without being it (1ive.com, rnsn.com, a0l.com,
    grnx.de, login-1ive.example): high when it is the recipient's registrable name, warn when it
    is another label. The plain word itself (live.example, mail.beta.example) is no concern."""
    labels = decoded.split(".")[:-1]
    name = registrable.split(".", 1)[0]
    for word in (part for label in labels for part in (label, *label.split("-"))):
        reading = lookalike.skeleton(word)
        if reading == word:
            continue
        matches = [domain for domain in _SHORT_SERVICES if domain.split(".", 1)[0] == reading]
        if not matches:
            continue
        same_ending = [domain for domain in matches if _ending(domain) == _ending(registrable)]
        reference = (same_ending or matches)[0]
        return AddressConcern("lookalike", "high" if word == name else "warn", reference)
    return None


def address_concern(r: Recipient, org: OrgView) -> Optional[AddressConcern]:
    """unusual_characters (high) when the domain decodes to mixed scripts or a confusable
    (lookalike.mixed_script_reading); (info) for a single-script international domain; lookalike
    via lookalike.lookalike_of(domain, references) with references = org.domains + own address
    domains + CONSUMER_MAIL_DOMAINS + lookalike.WELL_KNOWN_BRANDS: rule "typo" -> high,
    "brand_label" or "glued" -> warn. An exact reference is never a concern. A consumer domain
    with an ordinary-word name (mail.com, live.com, free.fr) is an exact reference but not a
    pattern to imitate (see _CONSUMER_REFERENCE_MIN), except letter for letter: a name that reads
    as one after folding look-alike letters (1ive.com, rnsn.com) is a high look-alike. The
    reference named is the one under the recipient's own ending when several share the name
    (yah00.com looks like yahoo.com, yah00.co.uk like yahoo.co.uk)."""
    lookalike = _lookalike()
    decoded = lookalike.decode_host(r.domain)
    if decoded is None:  # punycode that does not decode: nobody can read it as written
        return AddressConcern("unusual_characters", "high", "", reading=r.domain)
    international: Optional[AddressConcern] = None
    if not decoded.isascii():
        reading = lookalike.mixed_script_reading(decoded)
        if reading:
            return AddressConcern("unusual_characters", "high", "", reading=reading)
        international = AddressConcern("unusual_characters", "info", "")

    references = _references(org, lookalike)
    registrable = lookalike.registrable_domain(r.domain)
    exact = (
        registrable in references
        or _is_consumer(r.domain, registrable)
        or _inside(r.domain, org.domains)
        or r.address in org.own_addresses
    )
    if not exact:
        hit = lookalike.lookalike_of(decoded, references)
        if hit is not None:
            return AddressConcern(
                "lookalike",
                _lookalike_severity(hit, registrable, lookalike),
                _preferred_reference(hit.known, registrable, references),
            )
        homograph = _short_service_homograph(decoded, registrable, lookalike)
        if homograph is not None:
            return homograph
    return international


def _lookalike_severity(
    hit: _LookalikeHit, registrable: str, lookalike: _LookalikeApi
) -> Literal["high", "warn"]:
    """typo -> high; brand_label and glued -> warn, except when the recipient's whole name
    reads as the reference once look-alike letters are folded (arnazon.com, paypa1.com,
    northvvind.com): lookalike_of reports that skeleton match as brand_label, but a domain
    written to be read as another one is the typo case, not a brand used in a longer name."""
    if hit.rule == "typo":
        return "high"
    name = registrable.split(".", 1)[0]
    known_name = hit.known.split(".", 1)[0]
    if name != known_name and lookalike.skeleton(name) == known_name:
        return "high"
    return "warn"


def validate_organisation_domain(text: str) -> str:
    """The domain to store (lower-case A-label), or ValueError with a plain sentence: not a domain,
    a public mail service, a bare public suffix (com, co.uk), an IP address, too long."""
    raw = unicodedata.normalize("NFKC", text if isinstance(text, str) else "").strip().lower()
    if raw.startswith("@"):
        raw = raw[1:].strip()
    raw = raw.rstrip(".")
    if raw.startswith("www."):
        raw = raw[4:]
    if not raw or len(raw) > 253 or any(ch.isspace() or ch in "/:@?#[]\\" for ch in raw):
        raise ValueError(_ENTER_A_DOMAIN)
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValueError(_ENTER_A_DOMAIN)
    domain = _a_label(raw)
    if domain is None:
        raise ValueError(_ENTER_A_DOMAIN)
    labels = domain.split(".")
    if (
        len(labels) < 2
        or len(domain) > 253
        or labels[-1].isdigit()
        or not all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels)
    ):
        raise ValueError(_ENTER_A_DOMAIN)
    lookalike = _lookalike()
    if domain in lookalike.TWO_PART_SUFFIXES:
        raise ValueError(
            f"{domain} is a domain ending, not a domain. Enter your organisation's own, such "
            f"as acme.{domain}."
        )
    if _is_consumer(domain, lookalike.registrable_domain(domain)):
        raise ValueError(
            f"{domain} is a public mail service, so it cannot be your organisation's domain."
        )
    return domain
