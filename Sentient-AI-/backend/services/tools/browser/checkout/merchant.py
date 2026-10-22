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

The pure look-alike helpers (punycode, scripts, confusables, typos, glued
brands, registrable domains) moved to ``services/security/lookalike.py``,
which the security wave's mail, message and link checks share; this module
re-imports them under its old names and keeps every sentence it shows.
"""

from __future__ import annotations

import ipaddress
import os
import unicodedata
from typing import Optional
from urllib.parse import urlsplit

from services.security.lookalike import WELL_KNOWN_BRANDS as WELL_KNOWN_MERCHANTS
from services.security.lookalike import decode_host as _decode_host
from services.security.lookalike import lookalike_of, mixed_script_reading, registrable_domain
from services.tools.browser.guard import LOOPBACK_TOGGLE

__all__ = ["WELL_KNOWN_MERCHANTS", "merchant_refusal", "registrable_domain"]

_ADDRESS_UNREADABLE = (
    "The site's address could not be read safely, so Crawler will not pay here."
)
_NAME_THE_SITE = (
    "Say which site the purchase is on (for example ticketmaster.com) so Crawler can check "
    "it is the right one."
)


def _lookalike_script_refusal(host: str) -> Optional[str]:
    """Refuse a host whose letters imitate another alphabet: any label
    that mixes scripts, or carries a known confusable (a wholly Cyrillic
    "аррӏе" reads as "apple" and mixes nothing)."""
    shown = mixed_script_reading(host)
    if shown is None:
        return None
    return (
        f"The site's address uses look-alike characters ({host}, which reads as "
        f"{shown}), so Crawler will not pay here."
    )


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


def _lookalike_of_known(host: str) -> Optional[str]:
    """The well-known merchant *host* imitates without being it, or None
    (``lookalike.lookalike_of``: a brand label on another domain, a typo or
    homograph, or the brand glued to another word)."""
    hit = lookalike_of(host)
    return hit.known if hit is not None else None


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
