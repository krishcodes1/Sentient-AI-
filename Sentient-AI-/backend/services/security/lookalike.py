"""Look-alike host names: punycode and mixed-script letters, typo and
homograph domains of well-known brands, a brand used as a label of another
site or glued to another word, registrable domains and bare IP literals.

Why it exists: phishing lives on hosts that read like a real one ("аmazon.com"
with a Cyrillic а, "amazom.com", "arnazon.com", "paypalsecure.com",
"amazon.com.evil.com"). The browser checkout (merchant.py) refused them first;
the security wave's outbound message check (S1), mail scam check (S2), link
reputation (S4) and site rules (S7) need the same answers, so the pure
helpers live here once instead of four times. Pure and stdlib-only: no
network, no third-party suffix list, no browser import (the loopback toggle
stays in merchant.py, which must not be needed here). Registrable domains are
the last two labels plus a short list of two-part public suffixes, which is
enough for "is checkout.ticketmaster.com ticketmaster.com".

Two readings of a host: ``decode_host`` is IDNA 2003 (Python's idna codec)
and refuses what it cannot decode, which checkout relies on; ``browser_host``
and ``ascii_host`` read a host the way a current browser does (UTS 46: the
characters it drops are dropped, every code point is mapped as the browser
maps it, ``fold_host``, a name only IDNA 2008 allows is read), so a link
check looks up the host the browser really opens. Every helper is linear in
its input: lengths are checked before anything quadratic runs.

Connects to: services/tools/browser/checkout/merchant.py (re-imports these
under its old names, sentences unchanged), and from the security wave
services/security/link_checks.py (S4), outbound_recipients.py (S1, which
re-exports ``CONSUMER_MAIL_DOMAINS``), mail_checks.py (S2) and S7's site
rules. Owned by S4 after WAVE 0.
"""

from __future__ import annotations

import functools
import ipaddress
import re
import string
import unicodedata
from dataclasses import dataclass
from typing import Literal, Optional, Sequence

# Brands people buy from or sign in to often enough that a near-miss host is
# far more likely a phishing page than a real site. A host whose brand label
# is the brand of one of these on another domain (amazon.shop), a typo of it
# (amazom.com; the edits allowed scale with the brand's length, so a short
# real brand is not mistaken for another short one), a homograph of it
# (arnazon.com reads as amazon.com), or that carries the brand as any label
# or hyphenated part of one (ticketmaster-tickets.co, amazon.com.evil.com,
# ticketmaster.evil.com) or glued to another word (paypalsecure.com,
# nikestore.com, amazonprime-deals.com) imitates it unless it is on exactly
# that brand's domain. Moved here from merchant.WELL_KNOWN_MERCHANTS, which
# re-exports it.
WELL_KNOWN_BRANDS: tuple[str, ...] = (
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

# Free mail providers: an address there names a person, never an
# organisation, so its domain never counts as "your organisation" (S1, S9)
# and a sender there is not vouched for by its domain (S2).
CONSUMER_MAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
        "yahoo.com", "ymail.com", "yahoo.co.uk", "yahoo.co.jp", "icloud.com", "me.com",
        "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
        "gmx.de", "web.de", "mail.com", "zoho.com", "fastmail.com", "hey.com",
        "tutanota.com", "tuta.io", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com",
        "126.com", "naver.com", "hanmail.net", "comcast.net", "verizon.net", "att.net",
        "sbcglobal.net", "btinternet.com", "orange.fr", "free.fr", "laposte.net", "libero.it",
        "t-online.de", "seznam.cz", "rediffmail.com",
    }
)

# Two-part public suffixes under which the registrable domain is three
# labels long ("shop.example.co.uk" -> "example.co.uk").
TWO_PART_SUFFIXES: frozenset[str] = frozenset(
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
# confusable would be a Unicode table; the mixed-script rule catches the
# rest of the alphabet by flagging any label that mixes scripts.
CONFUSABLES: dict[str, str] = {
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
# A host label a browser reads as a number, which makes the whole host an
# IPv4 address to it ("2130706433", "0x7f.1"): the WHATWG URL standard's
# "ends in a number" rule.
_NUMBER_LABEL_RE = re.compile(r"[0-9]+|0x[0-9a-f]*")

# Characters a browser drops from a host name before it reads it (UTS 46
# "ignored": the soft hyphen, the combining grapheme joiner, the Mongolian
# free variation selectors, the zero-width space, the word joiner, the
# invisible plus, the variation selectors, the byte-order mark and the
# shorthand format controls; and since UTS 46 16.0, which current browsers
# follow, the Hangul fillers, the Khmer inherent vowels, the Mongolian vowel
# separator, the invisible function application, times and separator, the
# deprecated format controls U+206A..U+206F and the musical beam, tie, slur
# and phrase controls, all invisible). An e-mail's link can carry them
# ("ev&shy;il.com", "%C2%ADevil.com", "pay" + U+3164 + "pal.com"): the
# browser opens evil.com, so a check must read evil.com too, never another
# host and never "unreadable". The two joiners (ZWNJ, ZWJ) are not here: a
# browser keeps them where they may stand (``_JOINERS``).
IGNORED_IN_HOSTS: frozenset[str] = frozenset(
    {
        "\u00ad", "\u034f", "\u115f", "\u1160", "\u17b4", "\u17b5", "\u180b", "\u180c",
        "\u180d", "\u180e", "\u180f", "\u200b", "\u2060", "\u2061", "\u2062", "\u2063",
        "\u2064", "\u3164", "\ufeff", "\uffa0",
        *(chr(code) for code in range(0x206A, 0x2070)),
        *(chr(code) for code in range(0xFE00, 0xFE10)),
        *(chr(code) for code in range(0x1BCA0, 0x1BCA4)),
        *(chr(code) for code in range(0x1D173, 0x1D17B)),
        *(chr(code) for code in range(0xE0100, 0xE01F0)),
    }
)
_IGNORED_TABLE: dict[int, None] = dict.fromkeys(ord(ch) for ch in IGNORED_IN_HOSTS)
# The two letters a browser keeps as written although case folding would change them (UTS 46
# nontransitional "deviation" characters: the sharp s U+00DF and the final sigma U+03C2; the
# joiners are the other two, below). Only these code points as written are kept: their
# compatibility forms (the lunate sigma U+03F2, a mathematical final sigma) are folded like
# every other letter, to the sigma U+03C3, as a browser folds them.
_DEVIATIONS: frozenset[int] = frozenset({0x00DF, 0x03C2})
# Mappings the standard library's Unicode database (15.0 in Python 3.12) lacks, which a current
# browser applies (UTS 46 15.1 to 17.0; checked code point by code point against the Chromium
# that Playwright runs here). The capital sharp s U+1E9E is the sharp s since 15.1 (it was "ss"
# before, and Node 22's URL parser still reads "ss"; the browser that opens the link is what
# counts). Letters Unicode added later are folded as the browser folds them: the Cyrillic capital
# tje, the new Latin capitals, the modifier capital S U+A7F1 (to "s"), the Garay and Beria Erfe
# capitals, and the outlined Latin letters and digits U+1CCD6..U+1CCF9, which are plain a..z and
# 0..9 to a browser ("paypal" written in them opens paypal.com, so it is read as paypal.com).
_NEWER_MAPPINGS: dict[int, str] = {
    0x1E9E: "\u00df",
    0x1C89: "\u1c8a",
    0xA7CB: "\u0264", 0xA7CC: "\ua7cd", 0xA7CE: "\ua7cf", 0xA7D2: "\ua7d3", 0xA7D4: "\ua7d5",
    0xA7DA: "\ua7db", 0xA7DC: "\u019b", 0xA7F1: "s",
    **{code: chr(code + 0x20) for code in range(0x10D50, 0x10D66)},
    **{code: chr(code + 0x1B) for code in range(0x16EA0, 0x16EB9)},
    **{0x1CCD6 + index: char for index, char in enumerate(string.ascii_lowercase + string.digits)},
}
# The two joiners, ZWNJ U+200C and ZWJ U+200D, the other two deviation characters. A browser
# keeps one where the IDNA CONTEXTJ rule lets it stand (RFC 5892 A.1, A.2: right after a
# virama, or a ZWNJ between letters that join, as Persian names are written) and refuses the
# host anywhere else (a ZWJ between two Latin letters never opens). So a joiner is kept
# wherever it may stand, and the host is read as the browser opens it, and dropped only where
# the browser refuses the host anyway (reading it without the joiner then only ever looks up
# more). Dropping every joiner read a Persian host with a ZWNJ as another host than the one
# the browser opens, and that other host was looked up instead.
_ZWNJ = "\u200c"
_ZWJ = "\u200d"
_JOINERS: frozenset[str] = frozenset({_ZWNJ, _ZWJ})
_VIRAMA = 9  # the canonical combining class of a virama
# The scripts whose letters join (Unicode Joining_Type D, L or R). Wider than the exact
# Joining_Type table, which the standard library lacks: a joiner kept beside a letter that
# does not join is one the browser refuses, which costs nothing.
_JOINING_SCRIPTS: tuple[str, ...] = (
    "ARABIC", "SYRIAC", "NKO", "MONGOLIAN", "MANDAIC", "PHAGS-PA", "MANICHAEAN",
    "PSALTER PAHLAVI", "HANIFI ROHINGYA", "SOGDIAN", "OLD UYGHUR", "CHORASMIAN", "ADLAM",
)
# Dots other scripts write that a browser reads as "." (UTS 46 maps them; part of the fold).
_UTS46_DOTS: dict[int, str] = {0x3002: ".", 0xFF0E: ".", 0xFF61: "."}
# The longest DNS label and host name (RFC 1035): a longer one never
# resolves, and checking the length before encoding keeps the work linear
# (Python's punycode encoder is quadratic in the length of a label).
_MAX_LABEL = 63
_MAX_HOST = 253
_ACE_PREFIX = "xn--"


def _typo_edits_allowed(length: int) -> int:
    for up_to, edits in _TYPO_EDITS:
        if length <= up_to:
            return edits
    return _TYPO_EDITS_LONG


def script_of(char: str) -> str:
    """The script a letter belongs to ("LATIN", "CYRILLIC", "GREEK", ...)
    from its Unicode name; digits, hyphens and punctuation have none."""
    if not char.isalpha():
        return ""
    return unicodedata.name(char, "").split(" ", 1)[0]


def decode_host(host: str) -> Optional[str]:
    """*host* as a person sees it: lower-case, punycode labels decoded to
    Unicode, compatibility forms folded (NFKC). None when it cannot be
    decoded, which callers refuse rather than guess at."""
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


def strip_ignored(text: str) -> str:
    """*text* without the characters a browser drops from a host name
    (``IGNORED_IN_HOSTS``)."""
    return text.translate(_IGNORED_TABLE)


@functools.cache
def _fold_table() -> dict[int, Optional[str]]:
    """The UTS 46 mapping of every code point a browser changes in a host name, for
    ``str.translate``: each one mapped on its own, the way UTS 46 maps (NFKC_Casefold of that
    code point, which the NFKC, case fold, NFKC chain below gives), the deviation letters kept,
    ``_NEWER_MAPPINGS`` and the other scripts' dots on top and the ignored characters
    dropped. About 6,700 entries; built once, on the first host that is not plain ASCII (a
    fifth of a second), so importing this module stays cheap."""
    table: dict[int, Optional[str]] = {}
    for code in range(0x110000):
        if 0xD800 <= code < 0xE000 or code in _DEVIATIONS:
            continue
        char = chr(code)
        if char.casefold() == char and not unicodedata.decomposition(char):
            continue
        mapped = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", char).casefold())
        if mapped != char:
            table[code] = mapped
    table.update(_NEWER_MAPPINGS)
    table.update(_UTS46_DOTS)
    table.update(_IGNORED_TABLE)
    return table


def fold_host(text: str) -> str:
    """*text* with its letters mapped the way a browser maps a host name (UTS 46, as the URL
    standard and current browsers do): every code point mapped on its own (the ignored
    characters dropped, compatibility forms and case folded together, NFKC_Casefold, only the
    sharp s and the final sigma kept as written: nontransitional processing), then NFC.

    Not ``str.lower()``, which reads another host than the browser opens: the Cyrillic
    Extended-C letters U+1C80..U+1C88 are the ordinary Cyrillic letters to a browser (lower()
    kept them), a Cherokee small letter is its capital (lower() went the other way), the
    combining iota U+0345 is the letter iota, and a capital sigma is the sigma U+03C3 wherever
    it stands. And not NFKC of the whole text first: that reorders combining marks before the
    iota U+0345 is a letter, where the browser maps each code point first. Letters newer than
    the standard library's Unicode database are folded as a current browser folds them
    (``_NEWER_MAPPINGS``), and the joiners are kept where a browser keeps them (``_JOINERS``).
    Other scripts' dots are dots. Linear in the length of *text* (one table lookup per code
    point, then NFC); plain ASCII is just lower-cased."""
    if text.isascii():
        return text.lower()
    folded = unicodedata.normalize("NFC", text.translate(_fold_table()))
    if _ZWNJ not in folded and _ZWJ not in folded:
        return folded
    if len(folded) > _MAX_HOST:
        # Too long to be a host name, so no joiner here is in a name a browser opens; reading
        # the text without them keeps this linear.
        kept = folded.replace(_ZWNJ, "").replace(_ZWJ, "")
    else:
        kept = "".join(
            ch for index, ch in enumerate(folded)
            if ch not in _JOINERS or _joiner_may_stand(folded, index)
        )
    return unicodedata.normalize("NFC", kept)


def _transparent(ch: str) -> bool:
    """A mark or format character, which the ZWNJ rule looks past (Joining_Type T; the joiners
    count too, so a doubled ZWNJ between joining letters is kept, as a browser may keep it)."""
    return unicodedata.category(ch) in ("Mn", "Me", "Cf")


def _joins(ch: str) -> bool:
    return unicodedata.name(ch, "").startswith(_JOINING_SCRIPTS)


def _joiner_may_stand(text: str, index: int) -> bool:
    """Whether the joiner at *index* of *text* (a host of at most 253 characters) may stand
    where it is (RFC 5892 CONTEXTJ, widened as ``_JOINING_SCRIPTS`` says): right after a
    virama; or, for a ZWNJ, with a joining letter before and after it, past any marks."""
    if index > 0 and unicodedata.combining(text[index - 1]) == _VIRAMA:
        return True
    if text[index] == _ZWJ:
        return False
    before = index - 1
    while before >= 0 and _transparent(text[before]):
        before -= 1
    after = index + 1
    while after < len(text) and _transparent(text[after]):
        after += 1
    return before >= 0 and after < len(text) and _joins(text[before]) and _joins(text[after])


def _punycode_label(label: str) -> Optional[str]:
    """The Unicode letters of one ``xn--`` *label* as a browser accepts it:
    valid punycode that is not plain ASCII, encodes back to exactly *label*,
    is already in the form a browser maps a name to (``fold_host``: a
    Cherokee capital is kept, a capital Latin letter is not) and holds no
    control, format (but a joiner where it may stand), private-use or space
    character; None otherwise (a browser refuses such a host). Bounded: a
    label over 63 characters is refused before it is decoded."""
    if len(label) > _MAX_LABEL:
        return None
    try:
        decoded = label[len(_ACE_PREFIX):].encode("ascii").decode("punycode")
        again = _ACE_PREFIX + decoded.encode("punycode").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    if not decoded or decoded.isascii() or again != label:
        return None
    if fold_host(decoded) != decoded:
        return None
    # A joiner is the one format character a browser keeps (where fold_host keeps it).
    categories = (unicodedata.category(ch) for ch in decoded if ch not in _JOINERS)
    if any(category[0] in "CZ" and category != "Cn" for category in categories):
        return None
    return decoded


def browser_host(host: str) -> Optional[str]:
    """*host* as a browser reads it (UTS 46): the ignored characters
    dropped, compatibility forms and case folded the UTS 46 way
    (``fold_host``, never ``str.lower()``), other scripts' dots read as dots,
    no trailing dot, every ``xn--`` label decoded. Unlike ``decode_host``
    (IDNA 2003, which checkout keeps for its refusals), an ``xn--`` label
    only IDNA 2008 allows is decoded too ("faß.de", a Hebrew name ending in
    digits, letters Unicode added after 3.2, a Cherokee name): a browser
    opens those, so a link check must read them. None for an empty host or
    an ``xn--`` label a browser refuses (``_punycode_label``)."""
    text = fold_host(host or "").strip().rstrip(".")
    if not text:
        return None
    labels: list[str] = []
    for label in text.split("."):
        if label.startswith(_ACE_PREFIX):
            decoded = _punycode_label(label)
            if decoded is None:
                return None
            # _punycode_label accepts only a label already in its folded form.
            label = decoded
        labels.append(label)
    return ".".join(labels)


def ascii_host(host: str) -> Optional[str]:
    """*host* in its IDNA (xn--) lower-case form, the way a browser puts it
    on the wire (UTS 46 nontransitional, as current browsers: "faß.de" is
    ``xn--fa-hia.de``, never "fass.de") and the way a person can compare it
    letter by letter; read with ``browser_host`` first. None when it cannot
    be a host name: an empty label ("a..com"), a label over 63 characters or
    a name over 253, or an ``xn--`` label a browser refuses. Linear in the
    length of *host*: a label too long to fit is refused before it is
    encoded."""
    decoded = browser_host(host)
    if decoded is None or len(decoded) > _MAX_HOST:
        return None
    labels: list[str] = []
    for label in decoded.split("."):
        if not label:
            return None
        if label.isascii():
            encoded = label
        else:
            # Every letter takes at least one character of punycode, so a
            # longer label can never fit in 63 with its "xn--".
            if len(label) > _MAX_LABEL - len(_ACE_PREFIX):
                return None
            try:
                encoded = _ACE_PREFIX + label.encode("punycode").decode("ascii")
            except (UnicodeError, ValueError):
                return None
        if len(encoded) > _MAX_LABEL:
            return None
        labels.append(encoded)
    result = ".".join(labels)
    return result if len(result) <= _MAX_HOST else None


def registrable_domain(host: str) -> str:
    """``shop.example.com`` -> ``example.com``; ``a.b.example.co.uk`` ->
    ``example.co.uk``; an IP address or a single label is returned as is."""
    host = (host or "").strip().rstrip(".").lower()
    labels = host.split(".")
    if len(labels) < 2 or all(label.isdigit() for label in labels):
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def skeleton(label: str) -> str:
    """*label* as it reads at a glance ("arnazon" -> "amazon", "paypa1" ->
    "paypal")."""
    for pair, letter in _SKELETON:
        label = label.replace(pair, letter)
    return label


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance, capped: any pair whose lengths differ by more
    than two answers 3 (only "within two edits" is ever asked)."""
    if abs(len(a) - len(b)) > 2:
        return 3
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _decoded_labels(host: str) -> str:
    """*host* with its punycode labels decoded and every other label left as
    written (a label that will not decode stays as written)."""
    labels: list[str] = []
    for label in (host or "").split("."):
        if label.lower().startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def mixed_script_reading(host: str) -> Optional[str]:
    """The Latin reading of *host* when a label mixes scripts or carries a
    confusable (a wholly Cyrillic "аррӏе" reads as "apple" and mixes
    nothing), else None. Punycode labels are read decoded, so the IDNA form
    of a look-alike is caught too."""
    shown = _decoded_labels(host)
    for label in shown.split("."):
        scripts = {script_of(ch) for ch in label if ch.isalpha()}
        if len(scripts) > 1 or any(ch in CONFUSABLES for ch in label):
            return "".join(CONFUSABLES.get(ch, ch) for ch in shown)
    return None


def reads_as(host: str) -> str:
    """*host* decoded and with every confusable folded to the Latin letter it
    imitates ("аррӏе.com" -> "apple.com"); always a string (an undecodable
    host is folded as written, lower-case)."""
    shown = decode_host(host) or (host or "").strip().lower()
    return "".join(CONFUSABLES.get(ch, ch) for ch in shown)


def is_ip_literal(host: str) -> bool:
    """Whether *host* is an IP address rather than a name: IPv4, a
    bracketed or bare IPv6, or a host whose last label a browser reads as a
    number (``2130706433``, ``0x7f.1``: a browser opens those as IPv4)."""
    text = (host or "").strip().rstrip(".").lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    return _NUMBER_LABEL_RE.fullmatch(text.rsplit(".", 1)[-1]) is not None


@dataclass(frozen=True)
class LookalikeHit:
    """Which well-known brand a host imitates, and how: ``brand_label`` (the
    brand is a label or hyphenated part of a label on another domain),
    ``typo`` (a typo or a homograph of the brand: amazom.com, arnazon.com)
    or ``glued`` (the brand glued to another word: paypalsecure.com)."""

    known: str
    rule: Literal["brand_label", "typo", "glued"]


def _glued(word: str, brand: str) -> bool:
    """*brand* glued to other letters in *word* (paypalsecure, nikestore,
    myamazon), by the lengths above; the whole word is the exact rule's."""
    if word == brand or len(brand) < _GLUED_EDGE:
        return False
    if word.startswith(brand) or word.endswith(brand):
        return True
    return len(brand) >= _GLUED_INSIDE and brand in word


def lookalike_of(host: str, known: Sequence[str] = WELL_KNOWN_BRANDS) -> Optional[LookalikeHit]:
    """The well-known site *host* imitates without being it, or None, by
    three rules in this order: the brand as any label of the host or a
    hyphenated part of one, on a domain that is not the brand's own
    (amazon.shop, ticketmaster-tickets.co, amazon.com.evil.com,
    www.paypal.com.secure-login.xyz; a word that only reads as the brand,
    arnazon, is a homograph and answers ``typo``); a typo or a homograph of
    it in the brand label (amazom.com); or the brand glued to another word
    in any label or part (paypalsecure.com, amazonprime-deals.com,
    appleid-verify.com). A short brand is never read into a longer word
    ("aa" is not in "aaa.com" or "bath.com", "cvs" not in "cvsphotos");
    typos are measured on the brand label alone, never the suffix, with the
    edits allowed scaled to the brand's length. *host* is the decoded form
    (``decode_host``)."""
    host = (host or "").strip().rstrip(".").lower()
    domain = registrable_domain(host)
    if domain in known:
        return None
    written = {part for label in host.split(".") for part in (label, *label.split("-"))}
    read = {skeleton(word) for word in written}
    words = written | read
    for site in known:
        brand = site.split(".", 1)[0]
        if brand in written:
            return LookalikeHit(site, "brand_label")
        if brand in read:
            return LookalikeHit(site, "typo")
    label = domain.split(".", 1)[0]
    for site in known:
        brand = site.split(".", 1)[0]
        allowed = _typo_edits_allowed(min(len(label), len(brand)))
        if min(edit_distance(label, brand), edit_distance(skeleton(label), brand)) <= allowed:
            return LookalikeHit(site, "typo")
    for site in known:
        if any(_glued(word, site.split(".", 1)[0]) for word in words):
            return LookalikeHit(site, "glued")
    return None
