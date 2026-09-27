"""Is this page the merchant the owner asked for? (purchases spec §6)

Why: a card is only ever filled on the site the person named, and
phishing sites live on look-alike hosts: punycode that renders as
"аmazon.com" with a Cyrillic а, "amazom.com", "arnazon.com" (rn for m),
"ticketmaster-tickets.co", "paypalsecure.com", "amazon.com.evil.com".
``merchant_refusal`` answers with a plain sentence the owner reads on the
refusal, or None when the host is the merchant asked for. It needs no
network and no third-party suffix list: registrable domains are the last
two labels plus a short list of two-part public suffixes, which is enough
for "is checkout.ticketmaster.com ticketmaster.com".
"""

from __future__ import annotations

import ipaddress
import os
import unicodedata
from typing import Optional
from urllib.parse import urlsplit

from services.tools.browser.guard import LOOPBACK_TOGGLE

# Merchants people buy from often enough that a near-miss host is far more
# likely a phishing page than a real shop. A host whose brand label is
# the brand of one of these on another domain (amazon.shop), a typo of it
# (amazom.com; the edits allowed scale with the brand's length, so a
# short real brand is not mistaken for another short one), a homograph of
# it (arnazon.com reads as amazon.com), or that carries the brand as any
# label or hyphenated part of one (ticketmaster-tickets.co,
# amazon.com.evil.com, ticketmaster.evil.com) or glued to another word
# (paypalsecure.com, nikestore.com, amazonprime-deals.com) is refused
# unless it is on exactly that merchant's domain.
WELL_KNOWN_MERCHANTS: tuple[str, ...] = (
    "amazon.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com", "costco.com",
    "apple.com", "etsy.com", "newegg.com", "wayfair.com", "homedepot.com", "lowes.com",
    "ikea.com", "nike.com", "adidas.com", "zappos.com", "sephora.com", "ulta.com",
    "chewy.com", "cvs.com", "walgreens.com", "kroger.com", "instacart.com",
    "ticketmaster.com", "livenation.com", "stubhub.com", "seatgeek.com", "axs.com",
    "eventbrite.com", "vividseats.com", "fandango.com", "atomtickets.com",
    "amctheatres.com", "regmovies.com", "cinemark.com",
    "expedia.com", "booking.com", "airbnb.com", "hotels.com", "kayak.com", "priceline.com",
    "united.com", "delta.com", "southwest.com", "aa.com", "jetblue.com", "alaskaair.com",
    "amtrak.com", "uber.com", "lyft.com", "doordash.com", "ubereats.com", "grubhub.com",
    "starbucks.com", "chipotle.com", "dominos.com", "mcdonalds.com",
    "paypal.com", "stripe.com", "shopify.com", "squareup.com", "venmo.com",
    "google.com", "microsoft.com", "netflix.com", "spotify.com", "hulu.com",
    "disneyplus.com", "steampowered.com", "playstation.com", "nintendo.com", "xbox.com",
    "adobe.com", "dropbox.com", "zoom.us", "github.com", "openai.com", "anthropic.com",
)

# Two-part public suffixes under which the registrable domain is three
# labels long ("shop.example.co.uk" -> "example.co.uk").
_TWO_PART_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp",
        "co.in", "net.in", "org.in", "firm.in",
        "com.br", "com.mx", "com.ar", "com.co", "com.pe", "com.cl",
        "com.sg", "com.hk", "com.tw", "com.cn", "com.my", "com.ph", "co.id", "co.th",
        "co.kr", "co.za", "com.tr", "co.il", "com.eg", "com.sa", "com.ng",
    }
)

# Characters from other scripts that render like a Latin letter, mapped
# to the letter they imitate. Small on purpose: a map that covered every
# confusable would be a Unicode table; the mixed-script rule below catches
# the rest of the alphabet by refusing any label that mixes scripts.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ь": "b",
    "т": "t", "к": "k", "м": "m", "н": "h", "в": "b", "г": "r",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "κ": "k", "ι": "i", "ϲ": "c",
    "υ": "u", "ε": "e", "χ": "x", "β": "b", "η": "n", "μ": "u",
    # Other
    "ɡ": "g", "ℓ": "l", "ⅼ": "l", "ⅰ": "i", "ｅ": "e",
}

_ADDRESS_UNREADABLE = (
    "The site's address could not be read safely, so Crawler will not pay here."
)
_NAME_THE_SITE = (
    "Say which site the purchase is on (for example ticketmaster.com) so Crawler can check "
    "it is the right one."
)
# How many edits away from a well-known brand a label may be before it is
# taken for an imitation, by the length of the shorter of the two: a
# two- or three-letter brand (aa, cvs, hp) is within two edits of every
# other short word, so only an exact match counts there.
_TYPO_EDITS: tuple[tuple[int, int], ...] = ((3, 0), (6, 1))
_TYPO_EDITS_LONG = 2
# Letters that read as another at a glance in a host name ("rn" as "m",
# "vv" as "w", "cl" as "d", digits as the letters they resemble): a label
# is compared with the brands as it is written and as it reads.
_SKELETON: tuple[tuple[str, str], ...] = (
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("5", "s"),
)
# How long a brand must be to be looked for glued to another word: at the
# start or the end of a label from four letters (nikestore, mypaypal),
# anywhere inside one from five (a four-letter brand is inside too many
# ordinary words: "nike" in "moniker", "ulta" in "consultant").
_GLUED_EDGE = 4
_GLUED_INSIDE = 5


def _typo_edits_allowed(length: int) -> int:
    for up_to, edits in _TYPO_EDITS:
        if length <= up_to:
            return edits
    return _TYPO_EDITS_LONG


def _script(char: str) -> str:
    """The script a letter belongs to ("LATIN", "CYRILLIC", "GREEK", ...)
    from its Unicode name; digits, hyphens and punctuation have none."""
    if not char.isalpha():
        return ""
    return unicodedata.name(char, "").split(" ", 1)[0]


def _decode_host(host: str) -> Optional[str]:
    """*host* as a person sees it: lower-case, punycode labels decoded to
    Unicode, compatibility forms folded (NFKC). None when it cannot be
    decoded, which is refused rather than guessed at."""
    host = unicodedata.normalize("NFKC", (host or "").strip().rstrip(".")).lower()
    if not host:
        return None
    labels: list[str] = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                return None
        labels.append(unicodedata.normalize("NFKC", label).lower())
    return ".".join(labels)


def _lookalike_script_refusal(host: str) -> Optional[str]:
    """Refuse a host whose letters imitate another alphabet: any label
    that mixes scripts, or carries a known confusable (a wholly Cyrillic
    "аррӏе" reads as "apple" and mixes nothing)."""
    for label in host.split("."):
        scripts = {_script(ch) for ch in label if ch.isalpha()}
        if len(scripts) > 1 or any(ch in _CONFUSABLES for ch in label):
            shown = "".join(_CONFUSABLES.get(ch, ch) for ch in host)
            return (
                f"The site's address uses look-alike characters ({host}, which reads as "
                f"{shown}), so Crawler will not pay here."
            )
    return None


def registrable_domain(host: str) -> str:
    """``shop.example.com`` -> ``example.com``; ``a.b.example.co.uk`` ->
    ``example.co.uk``; an IP address or a single label is returned as is."""
    host = (host or "").strip().rstrip(".").lower()
    labels = host.split(".")
    if len(labels) < 2 or all(label.isdigit() for label in labels):
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _expected_host(expected: str) -> Optional[str]:
    """What the person or the model named, as a host: a URL loses its
    scheme and path, ``www.`` goes, a bare brand ("ticketmaster") stays a
    single label. None when nothing usable was given."""
    if not isinstance(expected, str):
        return None
    text = unicodedata.normalize("NFKC", expected).strip().lower()
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        text = text.split("/", 1)[0].split("?", 1)[0]
    text = text.rpartition("@")[2].split(":", 1)[0].replace(" ", "")
    if text.startswith("www."):
        text = text[4:]
    decoded = _decode_host(text)
    return decoded or None


def _matches(host: str, want: str) -> bool:
    """*host* is *want* (a host, a registrable domain or a bare brand)."""
    if host == want or host.endswith("." + want):
        return True
    if "." in want:
        return registrable_domain(host) == registrable_domain(want)
    return registrable_domain(host).split(".", 1)[0] == want


def _skeleton(label: str) -> str:
    for pair, letter in _SKELETON:
        label = label.replace(pair, letter)
    return label


def _glued(word: str, brand: str) -> bool:
    """*brand* glued to other letters in *word* (paypalsecure, nikestore,
    myamazon), by the lengths above; the whole word is the exact rule's."""
    if word == brand or len(brand) < _GLUED_EDGE:
        return False
    if word.startswith(brand) or word.endswith(brand):
        return True
    return len(brand) >= _GLUED_INSIDE and brand in word


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _lookalike_of_known(host: str) -> Optional[str]:
    """The well-known merchant *host* imitates without being it, or None:
    the brand as any label of the host or a hyphenated part of one, on a
    domain that is not the brand's own (amazon.shop, ticketmaster-tickets.co,
    amazon.com.evil.com, www.paypal.com.secure-login.xyz); a typo or a
    homograph of it in the brand label (amazom.com, arnazon.com); or the
    brand glued to another word in any label or part (paypalsecure.com,
    amazonprime-deals.com, appleid-verify.com). A short brand is never
    read into a longer word ("aa" is not in "aaa.com" or "bath.com", "cvs"
    not in "cvsphotos"); typos are measured on the brand label alone,
    never the suffix, with the edits allowed scaled to the brand's
    length."""
    domain = registrable_domain(host)
    if domain in WELL_KNOWN_MERCHANTS:
        return None
    words = {part for label in host.split(".") for part in (label, *label.split("-"))}
    words |= {_skeleton(word) for word in words}
    for known in WELL_KNOWN_MERCHANTS:
        if known.split(".", 1)[0] in words:
            return known
    brand = domain.split(".", 1)[0]
    for known in WELL_KNOWN_MERCHANTS:
        known_brand = known.split(".", 1)[0]
        allowed = _typo_edits_allowed(min(len(brand), len(known_brand)))
        if min(_edit_distance(brand, known_brand), _edit_distance(_skeleton(brand), known_brand)) <= allowed:
            return known
    for known in WELL_KNOWN_MERCHANTS:
        if any(_glued(word, known.split(".", 1)[0]) for word in words):
            return known
    return None


def _address_refusal(host: str) -> Optional[str]:
    """A host that is not a name: a bare IP address, or one carrying a
    user name (``user@host``, which a browser shows as the site). Neither
    is a merchant anyone asked for. The loopback toggle the guard honours
    for the fake site lets a test's ``https://127.0.0.1`` through."""
    if "@" in host:
        return "The site's address carries a user name, so Crawler will not pay here."
    literal = host.strip("[]")
    try:
        address = ipaddress.ip_address(literal)
    except ValueError:
        return None
    if address.is_loopback and os.environ.get(LOOPBACK_TOGGLE) == "1":
        return None
    return (
        f"The site is addressed by a bare IP address ({literal}), not a name, so Crawler will "
        "not pay here."
    )


def merchant_refusal(host: str, expected: str) -> Optional[str]:
    """Why Crawler will not pay on *host* when the owner asked for
    *expected*, or None when it is that merchant. The sentence is shown to
    the owner and the model; it names hosts, never anything from the page."""
    shown = _decode_host(host)
    if shown is None:
        return _ADDRESS_UNREADABLE
    address = _address_refusal(shown)
    if address is not None:
        return address
    lookalike = _lookalike_script_refusal(shown)
    if lookalike is not None:
        return lookalike
    want = _expected_host(expected)
    if want is None:
        return _NAME_THE_SITE
    if not _matches(shown, want):
        return f"This page is on {shown}, not {want} as asked, so Crawler will not pay here."
    known = _lookalike_of_known(shown)
    if known is not None:
        return (
            f"{shown} looks like {known} but is not that site, so Crawler will not pay here. "
            f"If it really is the right shop, the owner can open it themselves."
        )
    return None
