"""Cleans and reads the text Crawler is about to send: removes the characters a reader cannot see
that are used to smuggle text (Unicode tag characters, bidi overrides and isolates, long runs of
zero-width characters, chained or meaningless variation selectors), counts the invisible
characters it leaves in, finds the links in Markdown, HTML, Slack and plain text, and picks out the
links that can carry data out (a remote image that loads by itself, a long encoded value in a link).

Why it exists: an injected instruction's goal is usually to get Crawler to send something
somewhere (security S1). Text the owner cannot see (an instruction smuggled in tag characters, a
right-to-left override that makes the card read differently from what is sent) must never reach
another person, and a link that loads on its own or carries a long coded value can hand the
owner's data to whoever runs that site. The card can only warn about what something has found,
so the finding has to be cheap, exact and the same everywhere: one module, no I/O.

What is removed, kept and counted (S1 design 4.5):
- removed always: tag characters U+E0000-U+E007F (the three RGI subdivision flags, England,
  Scotland and Wales, are kept whole), bidi controls U+202A-U+202E and U+2066-U+2069, runs of 4
  or more invisible characters, every out-of-context invisible character once a field holds 16
  or more of them (bit-by-bit smuggling inserts them one at a time), a variation selector
  directly after another one, and a variation selector after a base it means nothing for (a basic
  selector after an ASCII letter, punctuation or space; a supplementary one after anything but a
  CJK ideograph), which would otherwise carry a hidden byte per visible letter;
- kept and never counted: a zero-width joiner inside an emoji sequence, ZWJ/ZWNJ between letters
  of a joining script (Arabic, Persian, Indic scripts, ...), a zero-width space between Thai, Lao,
  Khmer or Myanmar letters, LRM/RLM/ALM next to a right-to-left letter, and one byte order mark
  at the start of a file's content;
- kept and counted (``TextClean.kept``): any other invisible character, which usually comes from
  copied web text and is only worth an "info" line;
- never touched: visible characters, spaces, line endings (CRLF stays CRLF); NFKC is never
  applied.

Links are read the way the programs that show the message read them, not the way Python's
urlsplit does: a URL goes through the browser's (WHATWG) rules for http and https (``https:evil``,
``https:\\evil``, ``https://evil\\@trusted`` all reach "evil"), a Markdown destination through
CommonMark's escapes and entities, and an HTML tag through the HTML tokenizer's quoting. Where a
reader could take a text two ways, every way is reported: a missed image costs a leak, an extra
one costs a line on the card.

Connects to: services/security/outbound.py (the floor the executor runs on every write, and the
call check that turns these findings into security_notes) and services/security/outbound_recipients.py
(addresses). Pure: standard library only, no I/O and no logging, so it never sees a place to leak
text to. Every pattern is linear: a megabyte of adversarial text is scanned well within two seconds
(tests/test_outbound_text.py). So is the reading of a URL: a host outside ASCII is measured before
it is encoded (one that can never be looked up is refused), punycode is written here in
O(n log n), and a port never reaches int() with more than five digits.
"""

from __future__ import annotations

import bisect
import html
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from email.utils import getaddresses
from encodings.idna import nameprep
from functools import lru_cache
from types import MappingProxyType
from typing import Callable, Iterator, Literal, Mapping, Optional, Sequence
from urllib.parse import quote, unquote

StripKind = Literal["tag", "bidi", "zero_width_run", "extra_variation"]
STRIP_KINDS: tuple[StripKind, ...] = ("tag", "bidi", "zero_width_run", "extra_variation")

# How many invisible characters in a row are a smuggling run rather than an accident, and how
# many out-of-context ones in one field mean they were inserted one by one on purpose.
RUN_MIN = 4
SCATTERED_MAX = 16

# A link whose query values and names, path segments, fragment pieces and userinfo together
# carry at least this many encoded characters can carry data out, whether they sit in one value
# or are spread over many. 64 keeps an ordinary tracking id (Google's ved, Facebook's fbclid) or
# document id (44 characters) quiet. Only runs from ENCODED_PIECE_MIN characters count: below
# that an id and a word cannot be told apart. All those parts together from LONG_VALUE_CHARS
# characters count whatever they hold (data spelled as words, or cut into short pieces).
ENCODED_MIN_CHARS = 64
ENCODED_PIECE_MIN = 16
LONG_VALUE_CHARS = 512
# A run this long with no separator for many letters at a time is not words, even with no digit
# in it (data written as letters only, two letters a-p per byte): real words, slugs and titles
# break every few letters. ENCODED_WORD_MEAN is the average length between separators from
# which a long run reads as data.
ENCODED_WORDLESS_MIN = 32
ENCODED_WORD_MEAN = 12
# Subdomain labels: DNS exfiltration splits the data into labels of a host the attacker runs
# (``mzxw6ytboi2dqnrrgy3tcmzq.collect.example``). A label from this length that looks encoded
# counts, and the counted labels together must reach ENCODED_LABEL_TOTAL. Every label but the
# top-level one is read (no suffix list to guess wrong: the labels of an ending such as co.uk
# are far too short to count).
ENCODED_LABEL_MIN = 16
ENCODED_LABEL_TOTAL = 24

# Image hosts that are the platform's own uploads: nobody but the platform reads their request
# logs, so an image there cannot report that a message was read or carry data to a third
# party. Matched as the host itself or a subdomain of it. (googleusercontent.com is NOT here:
# Apps Script web apps answer from script.googleusercontent.com and read every query.)
TRUSTED_CONTENT_HOSTS: tuple[str, ...] = (
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "notion.so",
    "notion.site",
    "notion-static.com",
    "notionusercontent.com",
)
# Exact hosts only: Notion's own upload bucket. Any other amazonaws.com host may be anyone's.
TRUSTED_CONTENT_EXACT_HOSTS: frozenset[str] = frozenset(
    {"prod-files-secure.s3.us-west-2.amazonaws.com"}
)
# The same bucket addressed path-style (host, first path segment), as Notion's older image
# links are. A path with dot segments is never matched (it can climb into another bucket).
TRUSTED_CONTENT_BUCKETS: frozenset[tuple[str, str]] = frozenset(
    {
        ("s3-us-west-2.amazonaws.com", "secure.notion-static.com"),
        ("s3.us-west-2.amazonaws.com", "secure.notion-static.com"),
    }
)
# A trusted host can still hand a link on: Notion's image proxy
# (``notion.so/image/https%3A%2F%2Fsomeone.example%2F...``) fetches the image from the site named
# in its own address. Such a nested link is judged as a link of its own, this many levels deep;
# a link nested deeper, or holding more nested links than are read, is judged as an untrusted
# link itself (the cap never makes a link quiet).
_NESTED_DEPTH = 2
_NESTED_MAX = 4
# Image proxies under a trusted name that fetch whatever their address names, signed URLs
# anyone can reuse (GitHub's camo: ``/<hmac>/<hex of the target URL>``; the CamoLeak technique
# spells data out one pre-signed image per character). Never trusted: the proxy itself is a
# remote image, and the target it names is judged as well.
PROXY_HOSTS: frozenset[str] = frozenset({"camo.githubusercontent.com"})
# A path segment written in hex that may spell a URL (camo's target).
_HEX_SEGMENT_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")

# How many links the exfiltration heuristics read in one field. find_links' default of 50 is
# what the notes and S4's lookups need; the heuristics are cheap, so the check reads far more,
# and padding a message with harmless links does not push the one that leaks out of view.
SCAN_LINK_LIMIT = 1000

_MAX_PASSES = 6
_LINK_TEXT_MAX = 500

# ---------------------------------------------------------------------------
# Character sets (code point ranges, so the regex classes and the sets agree)
# ---------------------------------------------------------------------------

_TAG_RANGES: tuple[tuple[int, int], ...] = ((0xE0000, 0xE007F),)
_BIDI_RANGES: tuple[tuple[int, int], ...] = ((0x202A, 0x202E), (0x2066, 0x2069))
_INVISIBLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x200B, 0x200D),  # zero-width space, non-joiner, joiner
    (0x200E, 0x200F),  # left-to-right and right-to-left marks
    (0x2060, 0x2064),  # word joiner and the invisible math operators
    (0xFEFF, 0xFEFF),  # zero-width no-break space / byte order mark
    (0x00AD, 0x00AD),  # soft hyphen
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x061C, 0x061C),  # Arabic letter mark
    (0x115F, 0x1160),  # Hangul choseong and jungseong fillers
    (0x17B4, 0x17B5),  # Khmer inherent vowels
    (0x180E, 0x180E),  # Mongolian vowel separator
    (0x3164, 0x3164),  # Hangul filler
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
    (0xFFF9, 0xFFFB),  # interlinear annotation controls
)
_VARIATION_RANGES: tuple[tuple[int, int], ...] = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def _class(ranges: Sequence[tuple[int, int]]) -> str:
    return "".join(chr(a) if a == b else f"{chr(a)}-{chr(b)}" for a, b in ranges)


def _charset(ranges: Sequence[tuple[int, int]]) -> frozenset[str]:
    return frozenset(chr(c) for a, b in ranges for c in range(a, b + 1))


_TAG_CLASS = _class(_TAG_RANGES)
_BIDI_CLASS = _class(_BIDI_RANGES)
_INVISIBLE_CLASS = _class(_INVISIBLE_RANGES)
_VARIATION_CLASS = _class(_VARIATION_RANGES)

_INVISIBLE = _charset(_INVISIBLE_RANGES)

_ZWSP, _ZWNJ, _ZWJ = "\u200b", "\u200c", "\u200d"
_LRM, _RLM, _ALM = "\u200e", "\u200f", "\u061c"
_BOM = "\ufeff"
_EMOJI_VS = "\ufe0f"

# The only legitimate use of tag characters: the three RGI subdivision flags, a black flag,
# five tag letters and the cancel tag, kept whole and only when exact.
_BLACK_FLAG = "\U0001f3f4"
_CANCEL_TAG = "\U000e007f"


def _tag_letters(letters: str) -> str:
    return "".join(chr(0xE0000 + ord(ch)) for ch in letters)


RGI_SUBDIVISION_FLAGS: tuple[str, ...] = tuple(
    _BLACK_FLAG + _tag_letters(code) + _CANCEL_TAG for code in ("gbeng", "gbsct", "gbwls")
)
_FLAGS_ALTERNATIVE = "|".join(re.escape(flag) for flag in RGI_SUBDIVISION_FLAGS)

_SPECIAL_RE = re.compile(f"[{_TAG_CLASS}{_BIDI_CLASS}{_INVISIBLE_CLASS}{_VARIATION_CLASS}]")
_TAG_OR_BIDI_PRESENT_RE = re.compile(f"[{_TAG_CLASS}{_BIDI_CLASS}]")
# Group 1: a flag kept whole; group 2: tag characters; group 3: bidi controls.
_TAG_OR_BIDI_RE = re.compile(f"({_FLAGS_ALTERNATIVE})|([{_TAG_CLASS}]+)|([{_BIDI_CLASS}]+)")
_FLAG_RE = re.compile(_FLAGS_ALTERNATIVE)
_TAG_RUN_RE = re.compile(f"[{_TAG_CLASS}]+")
_BIDI_RUN_RE = re.compile(f"[{_BIDI_CLASS}]+")
_RUN_RE = re.compile(f"[{_INVISIBLE_CLASS}]{{{RUN_MIN},}}")
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE_CLASS}]")
_VARIATION_PRESENT_RE = re.compile(f"[{_VARIATION_CLASS}]")
_EXTRA_VARIATION_RE = re.compile(f"(?<=[{_VARIATION_CLASS}])[{_VARIATION_CLASS}]+")
# A variation selector picks a glyph only after a base it is defined for. The sixteen basic
# selectors never follow an ASCII letter, punctuation mark, space or line end (of ASCII only the
# digits, "#" and "*" take one: keycaps, and the zero with a slash); the 240 supplementary ones
# follow only CJK ideographs (the Ideographic Variation Database). Anywhere else a selector shows
# nothing and changes nothing, so one after each letter would carry a hidden byte per visible
# character; it is removed as an extra selector. Non-ASCII bases keep their basic selectors (emoji,
# math symbols, Myanmar and many more have defined sequences).
_IDEOGRAPH_RANGES: tuple[tuple[int, int], ...] = (
    (0x3400, 0x4DBF),  # CJK Unified Ideographs Extension A
    (0x4E00, 0x9FFF),  # CJK Unified Ideographs
    (0xF900, 0xFAFF),  # CJK Compatibility Ideographs
    (0x20000, 0x2FA1F),  # Extensions B to F and I, Compatibility Ideographs Supplement
    (0x30000, 0x323AF),  # Extensions G and H
)
_BASIC_VARIATION_CLASS = _class(((0xFE00, 0xFE0F),))
_SUPPLEMENTARY_VARIATION_CLASS = _class(((0xE0100, 0xE01EF),))
_LONE_VARIATION_RE = re.compile(
    r"(?:(?<=[\x00-\x22\x24-\x29\x2b-\x2f\x3a-\x7f])|^)"
    f"[{_BASIC_VARIATION_CLASS}]"
    f"|(?<![{_class(_IDEOGRAPH_RANGES)}])[{_SUPPLEMENTARY_VARIATION_CLASS}]"
)

# Scripts whose letters join (or whose conjuncts are formed) with ZWJ/ZWNJ, judged from the
# first word of the neighbours' Unicode names.
_JOINING_SCRIPTS = frozenset(
    {
        "ARABIC",
        "SYRIAC",
        "NKO",
        "MONGOLIAN",
        "DEVANAGARI",
        "BENGALI",
        "GURMUKHI",
        "GUJARATI",
        "ORIYA",
        "TAMIL",
        "TELUGU",
        "KANNADA",
        "MALAYALAM",
        "SINHALA",
        "TIBETAN",
        "MYANMAR",
        "KHMER",
    }
)
# Scripts written without spaces, where a zero-width space marks a word break.
_WORD_BREAK_SCRIPTS = frozenset({"THAI", "LAO", "KHMER", "MYANMAR"})

_NOTHING: Mapping[str, int] = MappingProxyType({})


# ---------------------------------------------------------------------------
# Hidden characters
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TextClean:
    """*text* after the floor. ``removed`` counts what was taken out by kind (empty when
    nothing); ``kept`` counts isolated invisible formatting characters left in (flagged, not
    removed)."""

    text: str
    removed: Mapping[str, int]
    kept: int


def _strip_tags_and_bidi(text: str, removed: dict[str, int]) -> str:
    if _BLACK_FLAG in text:
        # A subdivision flag may be here: one left-to-right scan keeps exact flags whole.
        def replace(match: re.Match[str]) -> str:
            if match.group(1):
                return match.group(1)
            kind = "tag" if match.group(2) else "bidi"
            removed[kind] = removed.get(kind, 0) + len(match.group(0))
            return ""

        return _TAG_OR_BIDI_RE.sub(replace, text)
    for kind, pattern in (("tag", _TAG_RUN_RE), ("bidi", _BIDI_RUN_RE)):
        stripped = pattern.sub("", text)
        if len(stripped) != len(text):
            removed[kind] = removed.get(kind, 0) + len(text) - len(stripped)
            text = stripped
    return text


# Code point blocks the scripts above live in (Arabic presentation forms included), and the
# blocks that hold every right-to-left letter (tests/test_outbound_text.py checks that claim
# against the whole of Unicode). Scanning only these keeps the one-time build cheap.
_JOINING_BLOCKS: tuple[tuple[int, int], ...] = (
    (0x0600, 0x18AF),  # Arabic to Mongolian, the Indic scripts, Tibetan, Myanmar, Khmer
    (0xA8E0, 0xA8FF),  # Devanagari Extended
    (0xA9E0, 0xA9FF),  # Myanmar Extended-B
    (0xAA60, 0xAA7F),  # Myanmar Extended-A
    (0xFB50, 0xFDFF),  # Arabic Presentation Forms-A
    (0xFE70, 0xFEFC),  # Arabic Presentation Forms-B
    (0x10EC0, 0x10EFF),  # Arabic Extended-C
    (0x1EE00, 0x1EEFF),  # Arabic Mathematical Alphabetic Symbols
)
_WORD_BREAK_BLOCKS: tuple[tuple[int, int], ...] = (
    (0x0E00, 0x0EFF),  # Thai, Lao
    (0x1000, 0x109F),  # Myanmar
    (0x1780, 0x17FF),  # Khmer
    (0xA9E0, 0xA9FF),  # Myanmar Extended-B
    (0xAA60, 0xAA7F),  # Myanmar Extended-A
)
_RIGHT_TO_LEFT_BLOCKS: tuple[tuple[int, int], ...] = (
    (0x0590, 0x08FF),
    (0xFB1D, 0xFDFF),
    (0xFE70, 0xFEFF),
    (0x10800, 0x10FFF),
    (0x1E800, 0x1EFFF),
)
_EMOJI_BLOCK = (0x1F000, 0x1FAFF)
_LAST_SCANNED = 0x1FFFF  # planes 0 and 1: no letter, mark or symbol these rules name is beyond


def _in_blocks(code: int, blocks: tuple[tuple[int, int], ...]) -> bool:
    return any(low <= code <= high for low, high in blocks)


def _script_of(ch: str) -> str:
    return unicodedata.name(ch, "").split(" ", 1)[0]


def _is_emoji(ch: str) -> bool:
    """An emoji or other pictograph: the emoji blocks, or any symbol of category So."""
    code = ord(ch)
    return _EMOJI_BLOCK[0] <= code <= _EMOJI_BLOCK[1] or unicodedata.category(ch) == "So"


def _is_joining_letter(ch: str) -> bool:
    """A letter or mark of a script whose letters join, judged from its Unicode name."""
    return (
        _in_blocks(ord(ch), _JOINING_BLOCKS)
        and unicodedata.category(ch)[0] in "LM"
        and _script_of(ch) in _JOINING_SCRIPTS
    )


def _is_word_break_letter(ch: str) -> bool:
    """A letter or mark of a script written without spaces (Thai, Lao, Khmer, Myanmar)."""
    return (
        _in_blocks(ord(ch), _WORD_BREAK_BLOCKS)
        and unicodedata.category(ch)[0] in "LM"
        and _script_of(ch) in _WORD_BREAK_SCRIPTS
    )


def _is_right_to_left_letter(ch: str) -> bool:
    return unicodedata.category(ch)[0] == "L" and unicodedata.bidirectional(ch) in ("R", "AL")


def _class_of(codes: list[int]) -> str:
    """A regex character class body for *codes* (sorted), as ranges."""
    ranges: list[tuple[int, int]] = []
    for code in codes:
        if ranges and code == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], code)
        else:
            ranges.append((code, code))
    return _class(ranges)


def _codes(blocks: tuple[tuple[int, int], ...], test: Callable[[str], bool]) -> list[int]:
    return [code for low, high in blocks for code in range(low, high + 1) if test(chr(code))]


@lru_cache(maxsize=1)
def _in_context_re() -> re.Pattern[str]:
    """One pattern matching exactly the invisible characters that are in context (the "kept and
    never counted" list in the module docstring), built on first use from the tests above. Every
    alternative starts with the invisible character itself, so the regex engine skips ordinary
    text at C speed and judges a megabyte without a Python step per character."""
    emoji = _codes(((0x80, _LAST_SCANNED),), _is_emoji)
    joining = _class_of(_codes(_JOINING_BLOCKS, _is_joining_letter))
    word_break = _class_of(_codes(_WORD_BREAK_BLOCKS, _is_word_break_letter))
    right_to_left = _class_of(_codes(_RIGHT_TO_LEFT_BLOCKS, _is_right_to_left_letter))
    before_emoji = _class_of(sorted({*emoji, ord(_EMOJI_VS)}))
    emoji_class = _class_of(emoji)
    joiners = _ZWNJ + _ZWJ
    marks = _LRM + _RLM + _ALM
    return re.compile(
        f"{_ZWJ}(?<=[{before_emoji}]{_ZWJ})(?=[{emoji_class}])"
        f"|[{joiners}](?<=[{joining}][{joiners}])(?=[{joining}])"
        f"|{_ZWSP}(?<=[{word_break}]{_ZWSP})(?=[{word_break}])"
        f"|[{marks}](?<=[{right_to_left}][{marks}])"
        f"|[{marks}](?=[{right_to_left}])"
    )


def _in_context_positions(text: str, file_content: bool) -> list[int]:
    """Positions, in order, of the invisible characters in *text* that do a job a reader
    relies on: a ZWJ inside an emoji sequence, ZWJ/ZWNJ between letters of a joining script, a
    zero-width space between Thai, Lao, Khmer or Myanmar letters, LRM/RLM/ALM next to a
    right-to-left letter, and a file's leading byte order mark."""
    positions = [match.start() for match in _in_context_re().finditer(text)]
    if file_content and text.startswith(_BOM):
        positions.insert(0, 0)
    return positions


def _remove_unprotected(text: str, protected: Sequence[int]) -> str:
    """*text* without its invisible characters, except those at *protected* positions."""
    pieces: list[str] = []
    start = 0
    for position in protected:
        pieces.append(_INVISIBLE_RE.sub("", text[start:position]))
        pieces.append(text[position])
        start = position + 1
    pieces.append(_INVISIBLE_RE.sub("", text[start:]))
    return "".join(pieces)


def _one_pass(text: str, file_content: bool, removed: dict[str, int]) -> tuple[str, int]:
    """One round of the floor; returns the text and how many out-of-context invisible
    characters it left in. The order matters: a removed run can leave two variation selectors
    side by side, so chained selectors are judged last, and a chain is cut to its first selector
    before that one is judged against its base."""
    if _TAG_OR_BIDI_PRESENT_RE.search(text):
        text = _strip_tags_and_bidi(text, removed)

    kept = 0
    if _INVISIBLE_RE.search(text):
        without_runs = _RUN_RE.sub("", text)
        if len(without_runs) != len(text):
            removed["zero_width_run"] = (
                removed.get("zero_width_run", 0) + len(text) - len(without_runs)
            )
            text = without_runs
        invisible = len(text) - len(_INVISIBLE_RE.sub("", text))
        if invisible:
            protected = _in_context_positions(text, file_content)
            kept = invisible - len(protected)
            if kept >= SCATTERED_MAX:
                removed["zero_width_run"] = removed.get("zero_width_run", 0) + kept
                text = _remove_unprotected(text, protected)
                kept = 0

    if _VARIATION_PRESENT_RE.search(text):
        before = len(text)
        text = _LONE_VARIATION_RE.sub("", _EXTRA_VARIATION_RE.sub("", text))
        if len(text) != before:
            removed["extra_variation"] = removed.get("extra_variation", 0) + before - len(text)
    return text, kept


def clean_text(text: str, *, file_content: bool = False) -> TextClean:
    """Remove tag characters, bidi overrides and isolates, smuggling runs and extra variation
    selectors (chained ones, and ones after a base they mean nothing for); keep ZWJ/ZWNJ inside
    emoji and joining scripts, and every visible character. Returns the SAME str object when
    nothing is removed. Idempotent."""
    if not _SPECIAL_RE.search(text):
        return TextClean(text, _NOTHING, 0)
    removed: dict[str, int] = {}
    current = text
    kept = 0
    # Run to a fixed point, so cleaning the result again removes nothing (removing one thing
    # can, rarely, change the neighbours another rule looks at). Two passes are the norm.
    for _ in range(_MAX_PASSES):
        cleaned, kept = _one_pass(current, file_content, removed)
        if len(cleaned) == len(current):
            break
        current = cleaned
    if not removed:
        return TextClean(text, _NOTHING, kept)
    return TextClean(current, MappingProxyType(removed), kept)


def clean_safe_subset(text: str) -> TextClean:
    """The always-safe part of the floor for the string arguments of every write (scaffold A35,
    review SEC-F3): tag characters (keeping the three RGI subdivision flag sequences whole) and
    the bidi controls U+202A-U+202E and U+2066-U+2069. Nothing else is touched: LRM/RLM/ALM, ZWJ,
    ZWNJ, variation selectors and every visible character stay. Same object when nothing is
    removed; idempotent; kept is always 0."""
    if not _TAG_OR_BIDI_PRESENT_RE.search(text):
        return TextClean(text, _NOTHING, 0)
    removed: dict[str, int] = {}
    cleaned = _strip_tags_and_bidi(text, removed)
    if not removed:  # only whole subdivision flags
        return TextClean(text, _NOTHING, 0)
    return TextClean(cleaned, MappingProxyType(removed), 0)


def hidden_count(text: str) -> int:
    """Every character a reader cannot see that clean_text would remove or flag (a draft's body)."""
    result = clean_text(text)
    return sum(result.removed.values()) + result.kept


# Where one address ends and the next (or a display name) begins. A quote is not a boundary: a
# quoted local part ("ann"@acme.com) is part of its address.
_ADDRESS_SEPARATORS_RE = re.compile(r"[\s,;<>()]+")
# Mail parsers fold whitespace around "@" and between the dots of an address ("ann @acme.com" and
# "ann . lee@acme.com" are addresses to email.utils), so a character hidden before the space is
# still inside the address. Split, not substituted: a pattern like \s*@ would rescan a long run
# of spaces from every position in it.
_WHITESPACE_PIECES_RE = re.compile(r"(\s+)")
_FOLDS_AROUND = "@."
# Longer recipient values are read by the token rule only (the parser's own cost grows with the
# text); parse_recipients reads no further than this either.
_PARSE_ADDRESSES_MAX = 20_000
# How many strings, lists and dicts one recipient value may hold before the walk gives up and
# counts it as hiding characters (fail closed). 500 Graph or calendar recipients fit easily.
_ADDRESS_WALK_MAX = 50_000


@lru_cache(maxsize=1)
def _hidden_in_address_re() -> re.Pattern[str]:
    """Any character that has no place inside an address: S1's invisible set, variation
    selectors, tags, bidi controls, and every Unicode Cc or Cf character (built once, on first
    use, from this Python's Unicode tables)."""
    format_codes = _codes(((0x80, 0x1FFFF), (0xE0000, 0xE0FFF)), _is_control_or_format)
    extra = _class_of(format_codes)
    return re.compile(
        f"[\\x00-\\x1f\\x7f{_INVISIBLE_CLASS}{_VARIATION_CLASS}{_TAG_CLASS}{_BIDI_CLASS}{extra}]"
    )


def _is_control_or_format(ch: str) -> bool:
    return unicodedata.category(ch) in ("Cc", "Cf")


def _parsed_addresses(value: str) -> Optional[list[str]]:
    """The addresses email.utils reads in *value* (the connectors parse recipients the same
    way), [] when it reads none, or None when the parser fails on it: it recurses once per
    nested comment or ":" group, so a few hundred nested "(" raise RecursionError."""
    try:
        try:
            # strict=False reads what a lenient parser (and a connector) reads; Pythons before
            # the strict mode was added take no keyword and are lenient already.
            pairs = getaddresses([value], strict=False)
        except TypeError:
            pairs = getaddresses([value])
    except Exception:  # RecursionError on deep nesting, or a parser bug on odd input
        return None
    # A lone word (a display name walked on its own) reads as an address with no domain.
    return [address for _, address in pairs if "@" in address]


def _fold_address_spaces(value: str) -> str:
    """*value* without the whitespace next to an "@" or a ".", which a mail parser folds into
    the address. Linear."""
    pieces = _WHITESPACE_PIECES_RE.split(value)
    kept: list[str] = []
    for index, piece in enumerate(pieces):
        if index % 2:  # whitespace between pieces[index - 1] and pieces[index + 1]
            before = pieces[index - 1][-1:]
            after = pieces[index + 1][:1] if index + 1 < len(pieces) else ""
            if (before and before in _FOLDS_AROUND) or (after and after in _FOLDS_AROUND):
                continue
        kept.append(piece)
    return "".join(kept)


def _string_hides_characters(value: str) -> bool:
    if not value:
        return False
    if _TAG_OR_BIDI_PRESENT_RE.search(_FLAG_RE.sub("", value)):
        return True
    hidden = _hidden_in_address_re()
    if not hidden.search(value):
        return False
    folded = _fold_address_spaces(value) if "@" in value else value
    for token in _ADDRESS_SEPARATORS_RE.split(folded):
        if "@" in token and hidden.search(token):
            return True
    if len(value) <= _PARSE_ADDRESSES_MAX:
        parsed = _parsed_addresses(value)
        if parsed is None:
            # The value holds a character that has no place in an address and the parser
            # could not say where its addresses end ('"a<ZWSP> b"@x.example' followed by
            # nested comments): refuse rather than guess, like a value too large to walk.
            return True
        return any(hidden.search(address) for address in parsed)
    return False


def hides_characters_in_address(value: object) -> bool:
    """True when a recipient value carries a tag or bidi control anywhere, or any invisible or
    format character inside an address token (local@domain). A display name may keep a ZWNJ.
    An address is read the way a mail parser reads it: whitespace next to "@" or "." is folded
    into it ("ann\\u200b @acme.com"), a quoted local part belongs to it, and every address
    email.utils reads in the value (up to 20,000 characters) is checked as well.

    A list, tuple, set or dict (Graph ``to`` recipients, calendar ``attendees``) is walked to
    every string inside it, keys included, so the shape of a value can never skip the check
    (parse_recipients reads the same shapes). A value too large to walk counts as hiding
    characters, and so does a string holding such a character that the mail parser fails on:
    the refusal fails closed. Anything else (a number, None) hides nothing. Never raises."""
    stack: list[object] = [value]
    walked = 0
    while stack:
        item = stack.pop()
        walked += 1
        if walked > _ADDRESS_WALK_MAX:
            return True
        if isinstance(item, str):
            if _string_hides_characters(item):
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            stack.extend(item)
    return False


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FoundLink:
    url: str  # as written (never logged)
    text: Optional[str]  # the link's visible text when it has one (Markdown, HTML <a>, Slack <u|t>)
    image: bool  # loads by itself when shown: Markdown ![..](..), HTML src, CSS url(), ...


# Markdown (CommonMark) link text: brackets nest (two levels here) and the text may run over
# lines; a backslash escapes the next character. Possessive repeats: no backtracking, ever.
_MD_PLAIN = r"(?:[^\[\]\\]|\\[\s\S])"
_MD_TEXT = r"(?:" + _MD_PLAIN + r"|\[(?:" + _MD_PLAIN + r"|\[" + _MD_PLAIN + r"*+\])*+\])*+"
# A raw destination: no space or control character, parentheses balanced (three levels here;
# deeper nesting is read by the image fallback below and by the bare-link pass). A backslash
# before ASCII punctuation escapes it.
_MD_DEST_CHAR = r"(?:[^\x00-\x20\x7f()\\]|\\[!-/:-@\[-`{-~]|\\)"
_MD_PARENS_3 = r"\(" + _MD_DEST_CHAR + r"*+\)"
_MD_PARENS_2 = r"\((?:" + _MD_DEST_CHAR + "|" + _MD_PARENS_3 + r")*+\)"
_MD_PARENS_1 = r"\((?:" + _MD_DEST_CHAR + "|" + _MD_PARENS_2 + r")*+\)"
_MD_RAW_DEST = r"(?:" + _MD_DEST_CHAR + "|" + _MD_PARENS_1 + r")++"
_MD_ANGLE_DEST = r"<(?:[^<>\n\\]|\\[^\n])*+>"
_MD_GAP = r"[ \t]*+(?:\r?\n[ \t]*+)?"
# An optional title, then the closing parenthesis.
_MD_CLOSE = (
    _MD_GAP
    + r"(?:(?:\"(?:[^\"\\]|\\[\s\S])*+\"|'(?:[^'\\]|\\[\s\S])*+'|\((?:[^()\\]|\\[\s\S])*+\))"
    + _MD_GAP
    + r")?+\)"
)
# Inline links and images: [text](destination "title"). The pattern sits in a lookahead so every
# opener is tried, also one inside another link's text (the badge pattern [![alt](img)](link)),
# while the scan itself stays in the regex engine; the "[" of an image is not tried again as a
# link of its own.
_MD_INLINE_RE = re.compile(
    r"(?=(?:(!)|(?<!!))\[("
    + _MD_TEXT
    + r")\]\("
    + _MD_GAP
    + "("
    + _MD_ANGLE_DEST
    + "|"
    + _MD_RAW_DEST
    + ")"
    + _MD_CLOSE
    + ")"
)
# An image the pattern above cannot read to its end (parentheses nested deeper, no closing
# parenthesis) may still be shown: its address up to the first parenthesis names the host. Only
# an address that can name another site (it holds ":", "/", "\" or an entity) is read.
_MD_IMAGE_OPEN_RE = re.compile(
    r"(?=!\[(?:"
    + _MD_TEXT
    + r")\]\("
    + _MD_GAP
    + r"<?((?=[^\x00-\x20\x7f()<>]*?[:/\\&])[^\x00-\x20\x7f()<>]++))"
)
# Backslash escapes and entity references, which CommonMark resolves in destinations and text.
_MD_ESCAPE_OR_ENTITY_RE = re.compile(
    r"\\([!-/:-@\[-`{-~])|&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});"
)
# Reference definitions ([label]: destination) and their uses ([text][label], [label][], and the
# shortcut [label] / ![label] when a definition exists).
_MD_LABEL = r"(?:[^\[\]\\]|\\[\s\S]){1,999}+"
_MD_DEFINITION_RE = re.compile(
    r"^[ \t]{0,3}\[("
    + _MD_LABEL
    + r")\]:"
    + _MD_GAP
    + r"(<(?:[^<>\n\\]|\\[^\n])*+>|[^\x00-\x20\x7f]++)",
    re.MULTILINE,
)
_MD_FULL_REFERENCE_RE = re.compile(
    r"(?=((!?)\[(" + _MD_TEXT + r")\]\[((?:[^\[\]\\]|\\[\s\S]){0,999}+)\]))"
)
_MD_SHORTCUT_REFERENCE_RE = re.compile(r"(?=((!?)\[(" + _MD_LABEL + r")\](?![\[(:])))")
# HTML: a start tag's name, then where the tag ends by the tokenizer's quoting rules (a ">" inside
# a quoted attribute value does not end it; an unclosed quote does not swallow the rest here, so
# the scan stays forward-only), then every attribute that names a URL anywhere in the tag,
# including inside another attribute's value (a decoy cannot hide the real one).
_HTML_OPENER_RE = re.compile(r"<([A-Za-z][^\s/>]*+)")
_HTML_TAG_END_RE = re.compile(r"""(?:[^>"'=]++|=\s*+(?:"[^"]*+"|'[^']*+')?+|["'])*+>""")
_HTML_URL_ATTRIBUTE_RE = re.compile(
    r"""(?<![^\s"'/])(src|srcset|lowsrc|dynsrc|background|poster|data|href|xlink:href)\s*+=\s*+"""
    r"""(?:"([^"]*+)"|'([^']*+)'|([^\s"'>][^\s>]*+))""",
    re.IGNORECASE,
)
# Attributes a browser fetches on its own when the message is shown, on any tag.
_LOADING_ATTRIBUTES = frozenset(
    {"src", "srcset", "lowsrc", "dynsrc", "background", "poster", "data"}
)
# Tags whose href is fetched on its own too (SVG images and uses, style sheets, SVG scripts).
_HREF_LOADS_IN = frozenset({"image", "use", "feimage", "link", "script"})
_SRCSET_DESCRIPTOR_RE = re.compile(r",*[0-9.]+[a-z]?,*", re.IGNORECASE)
_HTML_A_CLOSE_RE = re.compile(r"</a\s{0,8}>", re.IGNORECASE)
_HTML_END_TAG_RE = re.compile(r"</[A-Za-z][^>]{0,1000}+>")
_HTML_A_TEXT_SPAN = 2000
_HTML_CACHE_MAX = 4096
# CSS images (url(), image-set() and @import) in a style attribute or block load on open like
# <img>. Only a value that starts like a web address is read (url(s) in prose is not a link).
_CSS_URL_RE = re.compile(
    r"""(?:\b(?:url|image-set)\(\s*+['"]?+|@import\s++['"])"""
    r"""((?:[A-Za-z][A-Za-z0-9+.\-]*+:|[/\\]{2}|www\.)[^'"()\s<>]*+)""",
    re.IGNORECASE,
)
_CSS_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{1,6})\s?|\\(.)")
# Slack's <url> and <url|text>; also Markdown autolinks <url>.
_SLACK_RE = re.compile(r"<(https?://[^|<>\s]++)(?:\|([^<>\n]*+))?>", re.IGNORECASE)
# Bare links in plain text.
_BARE_RE = re.compile(r"(?<![\w@/.])(?:https?://|www\.)[^\s<>\"'`\\\x00-\x1f\x7f]++", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?*_~'\""
_BRACKETS = ((")", "("), ("]", "["), ("}", "{"))
_TAIL_CHARACTERS = _TRAILING_PUNCTUATION + "".join(closing for closing, _ in _BRACKETS)
_WHITESPACE_RE = re.compile(r"\s+")


# A numeric character reference, its digits read whole (a browser reads any number of them).
_NUMERIC_REFERENCE_RE = re.compile(r"&#(?:([0-9]+)|[xX]([0-9a-fA-F]+))(;?)")
# More significant digits than any code point needs: the reference is U+FFFD to a browser.
_REFERENCE_DIGITS_MAX = {10: 7, 16: 6}


def _shorten_reference(match: re.Match[str]) -> str:
    decimal, hexadecimal = match.group(1), match.group(2)
    base, digits = (10, decimal) if decimal is not None else (16, hexadecimal)
    significant = digits.lstrip("0") or "0"
    if len(significant) > _REFERENCE_DIGITS_MAX[base]:
        return "�"
    return f"&#{int(significant, base)}{match.group(3)}"


def _html_unescape(text: str) -> str:
    """``html.unescape``, safe on any input: a numeric reference with thousands of digits makes
    ``int()`` refuse it (Python's integer-string limit), and an attribute value is attacker
    text. Leading zeros are dropped (``&#0000000058;`` is ":" to a browser) and a reference too
    long for any code point becomes U+FFFD, as a browser reads it; everything else is the
    standard library's reading."""
    if "&" not in text:
        return text
    if "&#" in text:
        text = _NUMERIC_REFERENCE_RE.sub(_shorten_reference, text)
    return html.unescape(text)


def _visible(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    collapsed = _WHITESPACE_RE.sub(" ", text[: _LINK_TEXT_MAX * 8]).strip()
    return collapsed[:_LINK_TEXT_MAX] or None


def _reference_label(label: str) -> str:
    return _WHITESPACE_RE.sub(" ", label).strip().casefold()


def _md_unescape(text: str) -> str:
    """*text* with CommonMark's backslash escapes and entity references resolved, as a Markdown
    renderer resolves them in a link destination (``https\\://`` and ``https&#58;//`` are
    ``https://``)."""
    if "\\" not in text and "&" not in text:
        return text

    def resolve(match: re.Match[str]) -> str:
        if match.group(1) is not None:
            return match.group(1)
        return html.unescape(match.group(0))

    return _MD_ESCAPE_OR_ENTITY_RE.sub(resolve, text)


def _md_destinations(raw: str) -> tuple[str, ...]:
    """The address a Markdown destination names: as CommonMark reads it (escapes and entities
    resolved), and, when it holds a backslash, also as written, since a renderer that does not
    resolve escapes hands the backslash to the browser (``https://evil.example\\@trusted.example``
    is trusted.example to one and evil.example to the other)."""
    if raw.startswith("<") and raw.endswith(">"):
        raw = raw[1:-1]
    resolved = _md_unescape(raw).strip()
    written = raw.strip()
    if "\\" in written and written != resolved:
        return (resolved, written)
    return (resolved,)


# A link or image written inside a link's text shows as its own text (the badge pattern
# [![build](badge.svg)](ci-link) shows an image, not Markdown).
_MD_NESTED_LINK_RE = re.compile(
    r"!?\[((?:[^\[\]\\]|\\[\s\S])*+)\](?:\((?:[^()\\]|\\[\s\S])*+\)|\[(?:[^\[\]\\]|\\[\s\S])*+\])"
)


def _md_visible_text(text: str) -> str:
    """A Markdown link's text as a reader sees it: nested links and images reduced to their own
    text, escapes and entity references resolved."""
    shortened = text[: _LINK_TEXT_MAX * 8]
    for _ in range(2):  # the text nests at most two levels deep (_MD_TEXT)
        if "](" not in shortened and "][" not in shortened:
            break
        shortened = _MD_NESTED_LINK_RE.sub(r"\1", shortened)
    return _md_unescape(shortened)


def _css_unescape(value: str) -> str:
    if "\\" not in value:
        return value

    def resolve(match: re.Match[str]) -> str:
        if match.group(1) is not None:
            code = int(match.group(1), 16)
            return chr(code) if 0 < code <= 0x10FFFF else "\ufffd"
        return match.group(2)

    return _CSS_ESCAPE_RE.sub(resolve, value)


def _trim_bare(url: str) -> str:
    """A bare link without the sentence punctuation after it and without a closing bracket
    it never opened ("(see https://x.com/a)." -> "https://x.com/a"). Linear: each bracket is
    counted once and the cut is found with string methods, never one character per loop."""
    tail_start = len(url.rstrip(_TAIL_CHARACTERS))
    if tail_start == len(url):
        return url
    tail = url[tail_start:]
    stop = tail_start  # everything in the tail may go, unless a closing bracket must stay
    for closing, opening in _BRACKETS:
        in_tail = tail.count(closing)
        if not in_tail:
            continue
        removable = max(url.count(closing) - url.count(opening), 0)
        if in_tail > removable:
            # The (removable + 1)-th closing bracket from the end is balanced: it stays.
            blocker = len(tail.rsplit(closing, removable + 1)[0])
            stop = max(stop, tail_start + blocker + 1)
    return url[:stop]


class _Spans:
    """Character ranges already claimed (a link's visible text, a Slack link, a reference
    definition) or holding a structured link's address, so a later pass does not report the same
    URL, or a URL written as a link's text, a second time."""

    def __init__(self) -> None:
        self._ranges: list[tuple[int, int]] = []
        self._starts: list[int] = []
        self._ends: list[int] = []

    def add(self, start: int, end: int) -> None:
        if end <= start:
            return
        ranges = self._ranges
        if ranges and ranges[-1][0] <= start <= ranges[-1][1]:
            if end > ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], end)
            return
        ranges.append((start, end))

    def freeze(self) -> None:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(self._ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        self._ranges = merged
        self._starts = [start for start, _ in merged]
        self._ends = [end for _, end in merged]

    def ranges(self) -> list[tuple[int, int]]:
        """The ranges, merged and in order (after ``freeze``)."""
        return list(self._ranges)

    def covers(self, position: int) -> bool:
        index = bisect.bisect_right(self._starts, position) - 1
        return index >= 0 and position < self._ends[index]

    def holds(self, start: int, end: int) -> bool:
        """Whether [start, end) lies inside one range: a bare URL that runs past a structured
        link's address (deeper parentheses than that pass reads) is still reported."""
        index = bisect.bisect_right(self._starts, start) - 1
        return index >= 0 and start < self._ends[index] and end <= self._ends[index]


class _Pass:
    """One pattern's links, each recorded at its first position only. A pass stops once it
    holds *limit* different links: anything it would find later is preceded by *limit*
    different links already, so it can never be among the first *limit* of the whole text.
    That keeps the work for a small limit small however long the text is, and is exact."""

    def __init__(self, limit: int, found: list[tuple[int, FoundLink]]) -> None:
        self.limit = limit
        self.found = found
        self.written: set[tuple[str, Optional[str], bool]] = set()
        self.seen: set[FoundLink] = set()

    @property
    def full(self) -> bool:
        return len(self.seen) >= self.limit

    def add(self, start: int, url: str, text: Optional[str], image: bool) -> None:
        written = (url, text, image)
        if not url or written in self.written:
            return
        self.written.add(written)
        link = FoundLink(url, _visible(text), image)
        if link not in self.seen:
            self.seen.add(link)
            self.found.append((start, link))


@dataclass(frozen=True)
class _Attribute:
    offset: int  # from the tag's "<"
    name: str  # lower case
    value: str  # entity references resolved, outer whitespace removed
    value_start: int  # offsets of the value as written
    value_end: int


def _tag_attributes(tag: str) -> tuple[_Attribute, ...]:
    """Every URL-naming attribute anywhere in *tag* (the text from "<" to the tag's end)."""
    attributes: list[_Attribute] = []
    for match in _HTML_URL_ATTRIBUTE_RE.finditer(tag):
        group = next(index for index in (2, 3, 4) if match.group(index) is not None)
        attributes.append(
            _Attribute(
                match.start(),
                match.group(1).lower(),
                _html_unescape(match.group(group)).strip(),
                match.start(group),
                match.end(group),
            )
        )
    return tuple(attributes)


@dataclass(frozen=True)
class _Tag:
    start: int  # the "<"
    end: int  # just after the tag's ">" (or the end of the text)
    name: str  # lower case


class _Tags:
    """The start tags of a text in order, read lazily the way the tokenizer reads them: an
    opener inside another tag (inside a quoted value, say) is part of that tag, not a tag of
    its own. Read once and kept, so looking ahead for the next anchor costs nothing extra."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._tags: list[_Tag] = []
        self._position = 0
        self._done = False

    def get(self, index: int) -> Optional[_Tag]:
        while len(self._tags) <= index and not self._done:
            self._read_one()
        return self._tags[index] if index < len(self._tags) else None

    def _read_one(self) -> None:
        opener = _HTML_OPENER_RE.search(self._text, self._position)
        if opener is None:
            self._done = True
            return
        tag_end = _HTML_TAG_END_RE.match(self._text, opener.end())
        # A tag that never ends runs to the end of the text: its attributes are still read.
        end = tag_end.end() if tag_end else len(self._text)
        self._position = end
        self._tags.append(_Tag(opener.start(), end, opener.group(1).lower()))

    def inside(self, index: int, before: int) -> tuple[list[_Tag], Optional[int]]:
        """The start tags from tag *index* on that begin before *before*, up to the first real
        ``<a`` among them, and where that one begins (None when there is none): a browser ends
        an open link at the next one (a link cannot hold a link)."""
        inner: list[_Tag] = []
        while True:
            tag = self.get(index)
            if tag is None or tag.start >= before:
                return inner, None
            if tag.name == "a":
                return inner, tag.start
            inner.append(tag)
            index += 1


_SRCSET_URL_RE = re.compile(r"[^\s,][^\s]*+|,++")
_SRCSET_DESCRIPTORS_END_RE = re.compile(r"(?:[^,(]++|\([^)]*+\)?+)*+,?+")


def _srcset_urls(value: str) -> list[str]:
    """The URLs of a srcset ("a.png 1x,https://cdn.example/b.png 2x"), read the way the HTML
    standard's srcset parser reads them: skip whitespace and commas, a candidate's URL runs to
    the next whitespace (commas at its end are dropped), and its descriptors run to the next
    comma outside parentheses, so "a.png 1x,https://evil.example/p.png 2x" is two candidates.
    Every other reading is listed too (a URL token split at its commas, any token that is not a
    descriptor), since a sloppier parser loads those: a missed image costs a leak. Linear."""
    urls: list[str] = []
    position, end = 0, len(value)
    while position < end:
        match = _SRCSET_URL_RE.search(value, position)
        if match is None:
            break
        token = match.group(0)
        position = match.end()
        if token.startswith(","):
            continue
        url = token.rstrip(",")
        if url:
            urls.append(url)
        if url != token:
            continue  # the candidate ended at its trailing comma: no descriptors
        descriptors = _SRCSET_DESCRIPTORS_END_RE.match(value, position)
        if descriptors is not None:
            position = max(position, descriptors.end())
    readings: list[str] = []
    seen: set[str] = set()
    for url in urls:
        for reading in (url, *url.split(",")):
            reading = reading.strip()
            if reading and reading not in seen:
                seen.add(reading)
                readings.append(reading)
    for token in value.replace(",", " ").split():
        if token not in seen and not _SRCSET_DESCRIPTOR_RE.fullmatch(token):
            seen.add(token)
            readings.append(token)
    return readings


def _markdown_inline(
    text: str,
    limit: int,
    found: list[tuple[int, FoundLink]],
    claimed: _Spans,
    values: _Spans,
    texts: _Spans,
) -> None:
    if "](" not in text:
        return
    step = _Pass(limit, found)
    read: set[int] = set()
    for match in _MD_INLINE_RE.finditer(text):
        start = match.start()
        image = match.group(1) is not None
        read.add(start)
        link_text = None if image else _md_visible_text(match.group(2))
        for url in _md_destinations(match.group(3)):
            step.add(start, url, link_text, image)
        values.add(*match.span(3))
        claimed.add(*match.span(2))
        texts.add(*match.span(2))
        if step.full:
            break
    if "![" not in text:
        return
    step = _Pass(limit, found)
    destinations: dict[str, tuple[str, ...]] = {}
    for match in _MD_IMAGE_OPEN_RE.finditer(text):
        start = match.start()
        if start in read:
            continue
        written = match.group(1)
        urls = destinations.get(written)
        if urls is None:
            urls = destinations[written] = _md_destinations(written)
        for url in urls:
            step.add(start, url, None, True)
        values.add(*match.span(1))
        if step.full:
            return


def _markdown_references(
    text: str,
    limit: int,
    found: list[tuple[int, FoundLink]],
    claimed: _Spans,
    texts: _Spans,
) -> None:
    definitions: dict[str, tuple[str, ...]] = {}
    # Where each label is first defined, in order: an unused definition is listed at its place.
    first_definition: dict[str, int] = {}
    for match in _MD_DEFINITION_RE.finditer(text):
        label = _reference_label(match.group(1))
        if label not in definitions:
            definitions[label] = _md_destinations(match.group(2))
            first_definition[label] = match.start()
        claimed.add(match.start(), match.end())
    if not definitions:
        return
    used: set[str] = set()
    for pattern in (_MD_FULL_REFERENCE_RE, _MD_SHORTCUT_REFERENCE_RE):
        claimed.freeze()
        step = _Pass(limit, found)
        # Each distinct reference as written is resolved once: (label, urls, text) or None.
        resolved: dict[str, Optional[tuple[str, tuple[str, ...], Optional[str]]]] = {}
        # Every use is read, also once the pass holds its limit (only adding stops), so which
        # definitions are used does not depend on the limit asked for.
        for match in pattern.finditer(text):
            whole = match.group(1)
            image = match.group(2) == "!"
            start = match.start()
            if not image and start and text[start - 1] == "!":
                continue
            if whole not in resolved:
                groups = match.groups()  # (whole, "!" or "", text, [label of a full reference])
                label = _reference_label((groups[3] if len(groups) > 3 else "") or groups[2])
                urls = definitions.get(label)
                link_text = None if image else _md_visible_text(groups[2])
                resolved[whole] = (label, urls, link_text) if urls else None
            reference = resolved[whole]
            # An image loads wherever it sits, also inside a link's text; a link inside another
            # link's text is not a link.
            if reference is None or (not image and claimed.covers(start)):
                continue
            used.add(reference[0])
            if not step.full:
                for url in reference[1]:
                    step.add(start, url, reference[2], image)
            claimed.add(start, start + len(whole))
            texts.add(match.start(3), match.end(3))
    # A definition nobody uses shows nothing once rendered, but text/plain mail and Slack show
    # it as it is written, and the reader's program links the address: it is listed as a link
    # of its own at the definition's place, so its data and its host are still checked.
    step = _Pass(limit, found)
    for label, position in first_definition.items():
        if label in used:
            continue
        for url in definitions[label]:
            step.add(position, url, None, False)
        if step.full:
            break


@dataclass(frozen=True)
class _AnchorWindow:
    start: int  # just after the anchor's start tag
    stop: int  # its </a>, or the next real <a> start tag
    inner: tuple[_Tag, ...]  # the start tags in between


def _anchor_window(
    tags: _Tags,
    index: int,
    tag: _Tag,
    closing_tags: list[re.Match[str]],
    closings: list[int],
    claimed: _Spans,
    texts: _Spans,
) -> Optional[_AnchorWindow]:
    """Where the visible text of the link whose start tag is *tag* (number *index*) lies: up
    to its ``</a>``, or up to the next real ``<a`` start tag when one comes first (a browser
    ends the open link there), at most _HTML_A_TEXT_SPAN characters away. Ending at the next
    anchor also keeps the work linear: many anchors before one ``</a>`` each read only their
    own stretch."""
    position = bisect.bisect_left(closings, tag.end)
    if position >= len(closings) or closings[position] - tag.end > _HTML_A_TEXT_SPAN:
        return None
    stop, claim_end = closings[position], closing_tags[position].end()
    inner, next_anchor = tags.inside(index + 1, before=stop)
    if next_anchor is not None:
        stop = claim_end = next_anchor
    claimed.add(tag.end, claim_end)
    texts.add(tag.end, stop)
    return _AnchorWindow(tag.end, stop, tuple(inner))


def _window_text(text: str, window: _AnchorWindow) -> str:
    """The anchor's visible text: the text between the tags the tokenizer reads (a "<" inside a
    quoted value is not a tag), end tags dropped, entities resolved."""
    pieces: list[str] = []
    cursor = window.start
    for inner_tag in window.inner:
        if inner_tag.start >= window.stop:
            break
        pieces.append(text[cursor : inner_tag.start])
        pieces.append(" ")
        cursor = max(cursor, min(inner_tag.end, window.stop))
    pieces.append(text[cursor : window.stop])
    return _html_unescape(_HTML_END_TAG_RE.sub(" ", "".join(pieces)))


def _html_links(
    text: str,
    limit: int,
    found: list[tuple[int, FoundLink]],
    claimed: _Spans,
    values: _Spans,
    texts: _Spans,
) -> None:
    if "<" not in text:
        return
    # Every closing </a> once, so finding an anchor's text is a bisect, not a scan per anchor.
    closing_tags = list(_HTML_A_CLOSE_RE.finditer(text)) if "</" in text else []
    closings = [closing.start() for closing in closing_tags]
    cache: dict[str, tuple[_Attribute, ...]] = {}
    window_texts: dict[str, str] = {}
    step = _Pass(limit, found)
    tags = _Tags(text)
    index = -1
    while True:
        index += 1
        current = tags.get(index)
        if current is None:
            return
        start, name = current.start, current.name
        tag = text[start : current.end]
        attributes = cache.get(tag)
        if attributes is None:
            attributes = _tag_attributes(tag)
            if len(cache) < _HTML_CACHE_MAX:
                cache[tag] = attributes
        if not attributes:
            continue
        inner = [(m.start(), m.group(1).lower()) for m in _HTML_OPENER_RE.finditer(tag)]
        inner_starts = [offset for offset, _ in inner]
        anchor_text: Optional[str] = None
        # Only an href reads the anchor's text (an anchor without one is no link, and the
        # addresses in its text are read as bare links); the same stretch is read once.
        window = (
            _anchor_window(tags, index, current, closing_tags, closings, claimed, texts)
            if name == "a" and any(a.name not in _LOADING_ATTRIBUTES for a in attributes)
            else None
        )
        if window is not None:
            raw = text[window.start : window.stop]
            anchor_text = window_texts.get(raw)
            if anchor_text is None:
                anchor_text = _window_text(text, window)
                if len(window_texts) < _HTML_CACHE_MAX:
                    window_texts[raw] = anchor_text
        for attribute in attributes:
            values.add(start + attribute.value_start, start + attribute.value_end)
            if attribute.name in _LOADING_ATTRIBUTES:
                urls = (
                    _srcset_urls(attribute.value)
                    if attribute.name == "srcset"
                    else [attribute.value]
                )
                for url in urls:
                    step.add(start + attribute.offset, url, None, True)
            else:
                # What an href does depends on its tag. A browser reads the tag's own name; an
                # opener written inside the tag (a decoy "<a" in a title) is another reading, so
                # both are listed: src-like attributes load whatever tag they are on.
                owner_index = bisect.bisect_right(inner_starts, attribute.offset) - 1
                owner = inner[owner_index][1] if owner_index >= 0 else name
                for reading in dict.fromkeys((name, owner)):
                    if reading in _HREF_LOADS_IN:
                        step.add(start + attribute.offset, attribute.value, None, True)
                    else:
                        # Only the anchor's own reading carries its visible text.
                        link_text = anchor_text if reading == name == "a" else None
                        step.add(start + attribute.offset, attribute.value, link_text, False)
            if step.full:
                return


def _css_links(text: str, limit: int, found: list[tuple[int, FoundLink]], values: _Spans) -> None:
    """CSS images (``url()``, ``image-set()``, ``@import``), read as written and, when the text
    holds an entity or a backslash, as a browser reads it too: the HTML parser resolves a style
    attribute's entities before CSS sees it (``url(&quot;https://...&quot;)``,
    ``url(&#104;ttps://...)``), and CSS resolves its own escapes anywhere (``\\75rl(...)``,
    ``url(\\68ttps://...)``). Each reading is its own pass over the whole text: linear."""
    # Whether a url() names a web address is asked without encoding its host (ascii_host=False
    # accepts everything the full reading does): the readings below can hold thousands of
    # url()s, and the host is encoded once, later, for the links that are kept.
    step = _Pass(limit, found)
    for match in _CSS_URL_RE.finditer(text):
        url = _css_unescape(match.group(1))
        values.add(match.start(1), match.end(1))
        if _web_url(url, ascii_host=False) is not None:
            step.add(match.start(), url, None, True)
        if step.full:
            break
    readings: list[str] = []
    if "&" in text:
        readings.append(_html_unescape(text))
    if "\\" in text:
        readings.extend([_css_unescape(reading) for reading in (text, *readings)])
    for reading in readings:
        step = _Pass(limit, found)
        for match in _CSS_URL_RE.finditer(reading):
            url = match.group(1)
            if _web_url(url, ascii_host=False) is not None:
                # The position is the reading's: close enough to order the links (a reading is
                # never longer than the text).
                step.add(match.start(), url, None, True)
            if step.full:
                break


def _links_in_link_text(
    text: str,
    limit: int,
    found: list[tuple[int, FoundLink]],
    values: _Spans,
    texts: _Spans,
) -> None:
    """An address written as a link's visible text, listed as a link of its own. Mail goes out
    as plain text and Slack shows a label as it is written, so "[https://evil/?d=...](https://
    trusted/)" puts a live, auto-linked evil address in front of the reader: its data and its
    host are checked like any bare link's. An address a structured pass read there (an image
    inside a link's text) is that pass's."""
    texts.freeze()
    step = _Pass(limit, found)
    for start, end in texts.ranges():
        for match in _BARE_RE.finditer(text, start, end):
            url = _trim_bare(match.group(0))
            position = match.start()
            if len(url) <= len("https://") or values.holds(position, position + len(url)):
                continue
            step.add(position, url, None, False)
            if step.full:
                return


def find_links(text: str, *, limit: int = 50) -> list[FoundLink]:
    """Every link in *text*, in the order written, at most *limit*: Markdown inline and
    reference links and images, HTML attributes that name a URL (``<a href>``, ``src``,
    ``srcset``, ``background``, ``poster``, SVG ``href`` ...), CSS ``url(...)``, Slack
    ``<url|text>`` and bare ``http(s)://`` / ``www.`` links. A link's visible text is kept so the
    caller can ask whether it names another site (S4's check); an image has no link text.
    ``image`` is True for anything that loads by itself when the message is shown. Where a text
    can be read two ways (an image inside a link's text, a src inside another attribute), each
    reading is listed. The same link written twice is listed once."""
    if not text or limit <= 0:
        return []
    found: list[tuple[int, FoundLink]] = []
    claimed = _Spans()  # a link's visible text, Slack links, reference definitions
    values = _Spans()  # the addresses structured passes read
    texts = _Spans()  # a link's visible text, where an address is text the reader sees

    _markdown_inline(text, limit, found, claimed, values, texts)
    _markdown_references(text, limit, found, claimed, texts)
    _html_links(text, limit, found, claimed, values, texts)
    _css_links(text, limit, found, values)

    # An angle-bracket link inside a Markdown link, a reference definition or an attribute is
    # the same link.
    claimed.freeze()
    values.freeze()
    step = _Pass(limit, found)
    for match in _SLACK_RE.finditer(text):
        if claimed.covers(match.start()) or values.covers(match.start()):
            continue
        step.add(match.start(), match.group(1), match.group(2), False)
        claimed.add(match.start(), match.end())
        if match.group(2) is not None:
            texts.add(match.start(2), match.end(2))
        if step.full:
            break

    claimed.freeze()
    step = _Pass(limit, found)
    for match in _BARE_RE.finditer(text):
        start = match.start()
        if claimed.covers(start):
            continue
        url = _trim_bare(match.group(0))
        if len(url) <= len("https://") or values.holds(start, start + len(url)):
            continue
        step.add(start, url, None, False)
        if step.full:
            break

    _links_in_link_text(text, limit, found, values, texts)

    found.sort(key=lambda item: item[0])
    links: list[FoundLink] = []
    seen: set[FoundLink] = set()
    for _, link in found:
        if link not in seen:
            seen.add(link)
            links.append(link)
            if len(links) >= limit:
                break
    return links


# ---------------------------------------------------------------------------
# Reading a URL the way a browser does
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _WebUrl:
    """An http(s) URL as a browser reads it (WHATWG URL standard, special schemes)."""

    scheme: str  # "http" or "https"
    userinfo: str  # as written; "" when there is none
    host: str  # ASCII (IDNA), lower case, no trailing dot; an IPv6 address without brackets
    port: Optional[int]
    path: str  # backslashes read as slashes
    query: str
    fragment: str


_C0_AND_SPACE = "".join(chr(code) for code in range(0x21))
_TAB_OR_NEWLINE_RE = re.compile("[\t\n\r]")
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")
_AUTHORITY_END_RE = re.compile(r"[/\\?#]")
_FORBIDDEN_HOST_RE = re.compile(r"[\x00-\x20\x7f#%/:<>?@\[\\\]^|]")


def _web_url(url: str, *, ascii_host: bool = True) -> Optional[_WebUrl]:
    """*url* read as a browser reads an http(s) address, or None for anything else (mailto:,
    data:, cid:, a relative path, a host a browser refuses or can never look up). The scheme may
    be followed by any number of slashes or backslashes, none included (``https:evil.example``,
    ``https:\\\\evil.example``); the host ends at the first ``/``, ``\\``, ``?`` or ``#``, so
    ``https://evil.example\\@trusted.example`` is evil.example; the userinfo is everything before
    the host's last ``@``; the host is percent-decoded and IDNA-encoded; tabs and line breaks
    anywhere are dropped. ``//host`` (or ``\\\\host``) is read as https and ``www.host`` as http.

    Never raises, and linear in *url*. With ``ascii_host=False`` the host is not encoded (it is
    left lower-cased as written) and a host that cannot be looked up is not refused: the cheap
    answer to "could this be a web address", which accepts everything the full reading does."""
    candidate = _TAB_OR_NEWLINE_RE.sub("", url.strip(_C0_AND_SPACE))
    if candidate[:4].lower() == "www.":
        scheme, rest = "http", candidate
    elif candidate[:2] in ("//", "\\\\", "/\\", "\\/"):
        scheme, rest = "https", candidate
    else:
        match = _SCHEME_RE.match(candidate)
        if match is None:
            return None
        scheme = match.group(0)[:-1].lower()
        if scheme not in ("http", "https"):
            return None
        rest = candidate[match.end() :]
    rest = rest.lstrip("/\\")
    boundary = _AUTHORITY_END_RE.search(rest)
    authority, tail = (
        (rest[: boundary.start()], rest[boundary.start() :]) if boundary else (rest, "")
    )
    userinfo, _, host_and_port = authority.rpartition("@")
    decoded: Optional[str] = None
    if host_and_port.startswith("["):
        close = host_and_port.find("]")
        after = host_and_port[close + 1 :]
        if close < 0 or (after and not after.startswith(":")):
            return None
        try:
            host = ipaddress.IPv6Address(host_and_port[1:close]).compressed
        except ValueError:
            return None
        port_text = after[1:]
    else:
        raw_host, _, port_text = host_and_port.partition(":")
        try:
            decoded = unquote(raw_host, errors="strict")
        except UnicodeDecodeError:
            return None
        if not decoded or _FORBIDDEN_HOST_RE.search(decoded):
            return None
    port_ok, port = _port(port_text)
    if not port_ok:
        return None
    if decoded is not None:
        # The port is read first: a URL refused for its port costs no host encoding.
        written = _ascii_host(decoded) if ascii_host else decoded.strip().rstrip(".").lower()
        if not written or (ascii_host and not written.isascii()):
            return None
        host = written
    before_fragment, _, fragment = tail.partition("#")
    path, _, query = before_fragment.partition("?")
    return _WebUrl(scheme, userinfo, host, port, path.replace("\\", "/"), query, fragment)


_PORT_DIGITS_MAX = 5


def _port(text: str) -> tuple[bool, Optional[int]]:
    """(True, the port) for the port text of a URL, (True, None) when there is none, (False,
    None) when a browser refuses it. Leading zeros are allowed (``:00080`` is port 80) and go
    before the length check, so int() never sees more than five digits: it raises on a string
    of more than 4,300 (Python's integer-string limit), and the reader must never raise."""
    if not text:
        return True, None
    digits = text.lstrip("0")
    if not (text.isascii() and text.isdigit()) or len(digits) > _PORT_DIGITS_MAX:
        return False, None
    port = int(digits or "0")
    return (True, port) if port <= 65535 else (False, None)


# IDNA 2003 (the stdlib codec) maps these to other letters ("faß" -> "fass"), so S4 would look up
# and the note would name a different, real domain from the one a browser loads; IDNA 2008, which
# browsers follow, keeps them (outbound_recipients reads addresses the same way).
_IDNA2008_DEVIATIONS = frozenset("ßς")  # sharp s, final sigma

# DNS carries a label of at most 63 characters and a name of at most 253, so a host whose ASCII
# form is longer can never be looked up: no browser or mail client loads anything from it. The
# limits are checked before the encoding work, which a hostile host made slow: CPython's
# punycode codec rescans a label once per distinct character, and a 6,000-character host of
# distinct letters held the event loop for ten seconds.
_LABEL_ASCII_MAX = 63
_HOST_ASCII_MAX = 253
_ACE_PREFIX = "xn--"
# The mapping that decides a label's real length (case folding, NFKC) can merge two characters
# into one (a half-width kana and its sound mark), so a label is measured with room to spare
# before it: one longer than this cannot map to 63 characters or fewer.
_LABEL_CHARS_MAX = 4 * _LABEL_ASCII_MAX
# What IDNA maps to nothing (RFC 3454 table B.1, which the stdlib codec removes) and what UTS #46,
# which browsers follow, ignores: removed before a label is measured or encoded, so padding a
# host with them can neither push it over the limits nor hide the host a browser loads. ZWNJ and
# ZWJ are not removed here: browsers keep them (or refuse them outside a joining script).
_IGNORED_IN_HOST_RE = re.compile(
    "[\u00ad\u034f\u1806\u180b-\u180d\u180f\u200b\u2060-\u2064\ufe00-\ufe0f\ufeff"
    "\U0001bca0-\U0001bca3\U000e0100-\U000e01ef]"
)
# Ideographic and full-width full stops separate labels too (browsers and the stdlib codec).
_HOST_DOTS_RE = re.compile("[\u3002\uff0e\uff61]")

_PUNY_BASE = 36
_PUNY_TMIN = 1
_PUNY_TMAX = 26
_PUNY_SKEW = 38
_PUNY_DAMP = 700
_PUNY_INITIAL_BIAS = 72
_PUNY_INITIAL_N = 0x80


def _punycode_adapt(delta: int, points: int, first: bool) -> int:
    delta = delta // _PUNY_DAMP if first else delta // 2
    delta += delta // points
    k = 0
    while delta > ((_PUNY_BASE - _PUNY_TMIN) * _PUNY_TMAX) // 2:
        delta //= _PUNY_BASE - _PUNY_TMIN
        k += _PUNY_BASE
    return k + (_PUNY_BASE - _PUNY_TMIN + 1) * delta // (delta + _PUNY_SKEW)


def _punycode_digit(digit: int) -> str:
    return chr(digit + 97) if digit < 26 else chr(digit + 22)  # a-z, then 0-9


def _punycode(label: str) -> str:
    """RFC 3492 punycode of *label*, exactly as the stdlib codec writes it, in O(n log n): the
    codec rescans the whole label once per distinct character. Each insertion's delta counts the
    smaller characters before it, which a sorted list of their positions answers by bisection."""
    codes = [ord(ch) for ch in label]
    out = [ch for ch in label if ord(ch) < _PUNY_INITIAL_N]
    basic = len(out)
    if basic:
        out.append("-")
    smaller = [index for index, code in enumerate(codes) if code < _PUNY_INITIAL_N]
    pending = sorted((code, index) for index, code in enumerate(codes) if code >= _PUNY_INITIAL_N)
    n, delta, bias, handled = _PUNY_INITIAL_N, 0, _PUNY_INITIAL_BIAS, basic
    next_index = 0
    while next_index < len(pending):
        value = pending[next_index][0]
        delta += (value - n) * (handled + 1)
        n = value
        start = next_index
        scanned = 0  # where the count of smaller characters for the next delta begins
        while next_index < len(pending) and pending[next_index][0] == value:
            position = pending[next_index][1]
            delta += bisect.bisect_left(smaller, position) - bisect.bisect_left(smaller, scanned)
            q, k = delta, _PUNY_BASE
            while True:
                t = min(max(k - bias, _PUNY_TMIN), _PUNY_TMAX)
                if q < t:
                    break
                out.append(_punycode_digit(t + (q - t) % (_PUNY_BASE - t)))
                q = (q - t) // (_PUNY_BASE - t)
                k += _PUNY_BASE
            out.append(_punycode_digit(q))
            bias = _punycode_adapt(delta, handled + 1, handled == basic)
            delta = 0
            handled += 1
            scanned = position + 1
            next_index += 1
        delta += len(smaller) - bisect.bisect_left(smaller, scanned) + 1
        n += 1
        for _value, position in pending[start:next_index]:
            bisect.insort(smaller, position)
    return "".join(out)


@lru_cache(maxsize=2048)
def _a_label(label: str) -> Optional[str]:
    """The A-label of one NFC label with characters outside ASCII and no ignored ones (at most
    _LABEL_CHARS_MAX characters), or None when it is longer than 63 characters. The stdlib
    codec's reading (nameprep, then punycode), keeping ß and final sigma (IDNA 2008); a label
    the mapping refuses is written as punycode as it is, as before. Cached: one host is read by
    the link pass, the heuristics and origin_only."""
    mapped = label
    if not any(ch in _IDNA2008_DEVIATIONS for ch in label):
        try:
            mapped = nameprep(label)
        except UnicodeError:
            mapped = label
        if mapped.isascii():
            return mapped  # full-width letters: the plain label a browser reads
        if mapped.startswith(_ACE_PREFIX):
            mapped = label  # the codec refuses a mapped label that looks encoded already
    if len(mapped) + len(_ACE_PREFIX) > _LABEL_ASCII_MAX:
        return None  # every character takes at least one: it cannot fit
    encoded = _ACE_PREFIX + _punycode(mapped)
    return encoded if len(encoded) <= _LABEL_ASCII_MAX else None


def _ascii_label(label: str) -> Optional[str]:
    if label.isascii():
        return label
    label = unicodedata.normalize("NFC", _IGNORED_IN_HOST_RE.sub("", label))
    if label.isascii():
        return label
    if len(label) > _LABEL_CHARS_MAX:
        return None
    return _a_label(label)


def _ascii_host(host: str) -> Optional[str]:
    """*host* in ASCII (IDNA A-labels, label by label, keeping ß and final sigma the way IDNA
    2008 and browsers do). A label IDNA refuses is still written as punycode, so a note never
    carries a raw Unicode host. None for a host with characters outside ASCII that can never be
    looked up (one of those labels over 63 characters once encoded, or those labels over 253
    characters together): nothing loads from it, and every label is measured before it is
    encoded, so the work stays linear in the host. An all-ASCII host is read as written."""
    host = host.strip().rstrip(".").lower()
    if host.isascii():
        return host
    labels: list[str] = []
    encoded = 0
    for label in _HOST_DOTS_RE.sub(".", host).rstrip(".").split("."):
        if label.isascii():
            labels.append(label)
            continue
        ascii_label = _ascii_label(label)
        encoded += len(ascii_label or "") + 1
        if ascii_label is None or encoded > _HOST_ASCII_MAX + 1:
            return None
        labels.append(ascii_label)
    return ".".join(labels)


# ---------------------------------------------------------------------------
# Links that can carry data out
# ---------------------------------------------------------------------------


ExfilKind = Literal["remote_image", "encoded_link"]


@dataclass(frozen=True)
class ExfilFinding:
    kind: ExfilKind
    host: str  # ASCII host; the only part of the URL a note may name
    size: int  # encoded characters the link carries (encoded_link) or 0


def _trusted_content(web: _WebUrl) -> bool:
    host = web.host
    if host in PROXY_HOSTS:
        return False
    if host in TRUSTED_CONTENT_EXACT_HOSTS:
        return True
    if any(host == known or host.endswith("." + known) for known in TRUSTED_CONTENT_HOSTS):
        return True
    path = web.path.lower()
    if ".." in path or "%2e" in path or "/./" in path:
        return False
    return (host, path.lstrip("/").split("/", 1)[0]) in TRUSTED_CONTENT_BUCKETS


_ENCODED_RUN_RE = re.compile(f"[A-Za-z0-9+/=_.\\-]{{{ENCODED_PIECE_MIN},}}")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_BASE32_RE = re.compile(r"[A-Z2-7]+|[a-z2-7]+")
_DIGIT_RE = re.compile(r"[0-9]")
_ALPHA_RE = re.compile(r"[A-Za-z]")
_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_SEPARATOR_RUN_RE = re.compile(r"[+/_.\-]+")
_SEPARATORS = "+/_-."
_QUERY_SPLIT_RE = re.compile(r"[&;]")
_NESTED_URL_RE = re.compile(r"(?:https?:[/\\]*+|(?<![\w.\-])www\.)[^\s\"'<>]++", re.IGNORECASE)


def _looks_encoded(run: str) -> bool:
    """Whether a run of URL-safe characters reads as encoded data (base64, base32, hex, a long
    number, or letters with no word breaks) rather than words: words come with separators every
    few letters and seldom mix digits with both cases. String methods and compiled patterns
    only, so a megabyte-long run costs no Python loop per character."""
    core = run.rstrip("=")
    if len(core) < ENCODED_PIECE_MIN:
        return False
    if core.isdigit():
        return True
    has_digit = _DIGIT_RE.search(core) is not None
    if (
        has_digit
        and _ALPHA_RE.search(core)
        and (_HEX_RE.fullmatch(core) or _BASE32_RE.fullmatch(core))
    ):
        return True
    separators = sum(core.count(ch) for ch in _SEPARATORS)
    if (
        has_digit
        and _UPPER_RE.search(core)
        and _LOWER_RE.search(core)
        and separators * 8 <= len(core)
    ):
        return True
    if len(core) >= ENCODED_WORDLESS_MIN:
        words = len(_SEPARATOR_RUN_RE.split(core.strip(_SEPARATORS)))
        return len(core) - separators >= ENCODED_WORD_MEAN * words
    return False


def _components(web: _WebUrl) -> Iterator[str]:
    """The parts of a URL that can carry data: userinfo, path segments, query and fragment
    names and values."""
    if web.userinfo:
        yield web.userinfo
    yield from web.path.split("/")
    for component in (web.query, web.fragment):
        for piece in _QUERY_SPLIT_RE.split(component):
            name, _, value = piece.partition("=")
            yield name
            yield value


def _encoded_label(label: str) -> bool:
    if len(label) < ENCODED_LABEL_MIN or not (label.isascii() and label.isalnum()):
        return False
    digits = sum(1 for ch in label if ch.isdigit())
    if digits == len(label):
        return True
    if digits == 0:
        return len(label) >= ENCODED_WORDLESS_MIN  # no word or name runs this long
    if _HEX_RE.fullmatch(label) or _BASE32_RE.fullmatch(label):
        return True
    return digits * 5 >= len(label)


def _label_size(host: str) -> int:
    """Encoded data carried in the labels of *host*: every label but the top-level one is read,
    so no guess about where the registrable name starts can be gamed with a short name under a
    country ending (``<data>.xss.ht``); an ending's own labels are far too short to count."""
    labels = host.split(".")[:-1]
    total = sum(len(label) for label in labels if _encoded_label(label))
    return total if total >= ENCODED_LABEL_TOTAL else 0


def _encoded_size(web: _WebUrl) -> int:
    """How many encoded characters the link carries (0 below the thresholds): the encoded runs
    of all its parts together, or the length of all its parts together once that is
    LONG_VALUE_CHARS or more, or its encoded subdomain labels; the largest of the three."""
    total = 0
    encoded = 0
    for value in _components(web):
        if not value:
            continue
        decoded = unquote(value, errors="replace")
        total += len(decoded)
        for match in _ENCODED_RUN_RE.finditer(decoded):
            if _looks_encoded(match.group(0)):
                encoded += len(match.group(0))
    size = encoded if encoded >= ENCODED_MIN_CHARS else 0
    if total >= LONG_VALUE_CHARS:
        size = max(size, total)
    return max(size, _label_size(web.host))


def _hex_urls(path: str) -> Iterator[str]:
    """Web addresses spelled in hex in a path segment (camo's ``/<hmac>/<hex of the URL>``)."""
    for segment in path.split("/"):
        if not _HEX_SEGMENT_RE.fullmatch(segment):
            continue
        spelled = bytes.fromhex(segment).decode("utf-8", errors="replace")
        match = _NESTED_URL_RE.match(spelled)
        if match is not None:
            yield match.group(0)


def _nested_urls(web: _WebUrl) -> tuple[list[str], bool]:
    """Web addresses written inside a URL's path, query or fragment (percent-encoded once or
    twice, as is, or spelled in hex in a path segment): the link a proxy or redirect passes
    on. The second value is True when there were more than _NESTED_MAX of them."""
    found: list[str] = []
    for url in _hex_urls(web.path):
        found.append(url)
        if len(found) > _NESTED_MAX:
            return found[:_NESTED_MAX], True
    for component in (web.path, web.query, web.fragment):
        text = component
        for _ in range(2):
            decoded = unquote(text, errors="replace")
            if decoded == text:
                break
            text = decoded
        for match in _NESTED_URL_RE.finditer(text):
            found.append(match.group(0))
            if len(found) > _NESTED_MAX:
                return found[:_NESTED_MAX], True
    return found, False


def _exposures(url: str, image: bool, depth: int) -> Iterator[tuple[ExfilKind, str, int]]:
    web = _web_url(url)
    if web is None:
        return
    proxy = web.host in PROXY_HOSTS
    if _trusted_content(web) or proxy:
        # The platform's own upload: nobody else reads its logs, but a link it passes on
        # (an image proxy) reaches the site named inside it.
        nested, more = _nested_urls(web)
        if nested and depth < _NESTED_DEPTH:
            for inner in nested:
                yield from _exposures(inner, image, depth + 1)
        if not proxy and not more and not (nested and depth >= _NESTED_DEPTH):
            return
        # A proxy is never trusted, and a trusted link the reading had to stop in (nested too
        # deep, too many nested links) is judged as it stands: the cap never makes it quiet.
    if image:
        yield "remote_image", web.host, 0
    size = _encoded_size(web)
    if size:
        yield "encoded_link", web.host, size


def exfil_findings(links: Sequence[FoundLink]) -> list[ExfilFinding]:
    """The links that can carry data out, one finding per kind and host in the order first
    seen: ``remote_image`` for an image on a remote http(s) host (it loads when the message is
    opened, telling that site the message was read and handing it whatever the address holds),
    ``encoded_link`` for a link whose query, path, fragment, userinfo or subdomain labels carry
    encoded data (``size`` is the largest amount one link to that host carries). Platform upload
    hosts (GitHub, Notion) are not flagged themselves, since nobody else reads their logs, but
    a link they pass on (Notion's image proxy) is judged as its own link. Every URL is read as
    a browser reads it (_web_url)."""
    findings: dict[tuple[str, str], ExfilFinding] = {}
    for link in links:
        for kind, host, size in _exposures(link.url, link.image, 0):
            key = (kind, host)
            previous = findings.get(key)
            if previous is None or previous.size < size:
                findings[key] = ExfilFinding(kind, host, size)
    return list(findings.values())


# Characters a userinfo may keep as they are in origin_only's answer; anything else is
# percent-encoded so the answer reads the same in every URL parser.
_USERINFO_SAFE = "!$&'()*+,;=:%"


def origin_only(url: str) -> Optional[str]:
    """``scheme://[userinfo@]host[:port]/`` for an http(s) URL (path, query and fragment dropped),
    or None. What S1 hands S4: an outgoing message is private, and a host-level answer is enough
    to warn. S4's lookup_url drops the userinfo before anything leaves (S4.md 4.2). The URL is
    read as a browser reads it (_web_url), and the answer is written in the plain form every
    parser reads the same way: ASCII host, IPv6 in brackets, explicit port kept, userinfo
    percent-encoded where it holds anything unusual."""
    web = _web_url(url)
    if web is None:
        return None
    origin = f"{web.scheme}://"
    if web.userinfo:
        # errors="replace": a lone surrogate (JSON arguments can carry one) cannot be encoded.
        origin += quote(web.userinfo, safe=_USERINFO_SAFE, errors="replace") + "@"
    origin += f"[{web.host}]" if ":" in web.host else web.host
    if web.port is not None:
        origin += f":{web.port}"
    return origin + "/"
