"""The local half of the on-demand scam check (security S3): wording and hidden-character
signals, link extraction and label/address pairs, punycode display, and the filter that
decides whether a reason the AI wrote may be shown.

Why it exists: a pasted phishing text often carries tricks a person cannot see (tag
characters, text-direction controls, look-alike letters) and the same few requests (sign in,
send the code, pay by gift card). These checks need nothing: no network, no model, no key, so
every scam check always has them, and a missing key or a failing provider only narrows what
else is checked. Every sentence here is fixed text; a signal never quotes the message, and a
host is only ever shown in its punycode (xn--) form, so Crawler's own answer cannot carry the
look-alike letters PromptGuard would redact.

The wording patterns are English (v1); the AI review covers other languages. Every pattern is
a bounded word alternation run per sentence (two sentences at a time), so a megabyte of hostile
text stays linear; tests/test_scam_signals.py times each one.

Stdlib only, plus the prompt guard's invisible-character and look-alike sets (as
services/agent/shared_content.py). Used by services/scam_check (review, verdict, service).
"""

from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterable, Literal, Optional, Sequence
from urllib.parse import quote, urlsplit

from services.agent.prompt_guard import _HOMOGLYPH_MAP, _INVISIBLE_CHARS

Strength = Literal["weak", "strong", "decisive"]

MAX_TEXT_CHARS = 8000
MAX_URLS = 10
# Label/address pairs kept per text: enough for any real message, bounded for a hostile one.
MAX_ANCHORS = 20
MAX_URL_CHARS = 2048
MAX_LABEL_CHARS = 200
# The most any function here reads of one text (analyse_text already cuts to MAX_TEXT_CHARS;
# S2 may call language_signals on a whole mail body).
MAX_SCAN_CHARS = 100_000
# The longest path display_url shows before cutting it with "…".
DISPLAY_PATH_CHARS = 60


@dataclass(frozen=True)
class Signal:
    """One warning sign: a stable code, how much it weighs, a fixed plain sentence (never words
    copied from the message), and how many times it was seen."""

    code: str
    strength: Strength
    text: str
    count: int = 1


@dataclass(frozen=True)
class TextFindings:
    """What the local pass found in one text: its signals, the links in it (at most MAX_URLS,
    in order), links whose shown label names another site, and whether it was cut to
    MAX_TEXT_CHARS. *more_urls* is True when the text held more links than MAX_URLS (the
    service's too_many_links note)."""

    signals: tuple[Signal, ...]
    urls: tuple[str, ...]
    anchors: tuple[tuple[str, str], ...]  # (label, href)
    truncated: bool
    more_urls: bool = False


# ── Signal table (S3 section 4.6) ────────────────────────────────────────
# Every code a scam check can raise, with its weight. The link and file codes are raised by the
# link and file adapters (services/scam_check/links.py); their sentences live in verdict.py
# (links) or below (files), so every sentence a person reads is in one of two fixed tables.
SIGNAL_STRENGTHS: dict[str, Strength] = {
    "link_malicious": "decisive",
    "file_malicious": "decisive",
    "link_lookalike": "strong",
    "anchor_mismatch": "strong",
    "sender_impersonation": "strong",
    "credential_ask": "strong",
    "code_ask": "strong",
    "financial_ask": "strong",
    "payment_odd": "strong",
    "remote_access": "strong",
    "hidden_tags": "strong",
    "bidi_override": "strong",
    "link_suspicious": "weak",
    "urgent_pressure": "weak",
    "prize_or_refund": "weak",
    "threat": "weak",
    "delivery_fee": "weak",
    "secrecy": "weak",
    "too_good": "weak",
    "invisible_chars": "weak",
    "reply_to_mismatch": "weak",
    "ai_injection": "weak",
    "file_suspicious": "weak",
}

# The fixed sentences. Placeholders are filled by make_signal with counts and ASCII hosts only.
SIGNAL_SENTENCES: dict[str, str] = {
    "credential_ask": "It asks you to sign in, or to confirm your password or account details.",
    "code_ask": "It asks for a code sent to your phone or email.",
    "financial_ask": "It asks for card or bank details.",
    "payment_odd": "It asks for payment by gift card, crypto or wire transfer.",
    "remote_access": "It asks you to install an app or give remote access to your device.",
    "hidden_tags": "It hides {n} invisible tag {characters}, a trick to smuggle hidden text.",
    "bidi_override": (
        "It uses {n} text-direction control {characters} that can disguise a link or file name."
    ),
    "urgent_pressure": "It gives you a deadline or threatens to close your account to rush you.",
    "prize_or_refund": "It offers a prize, refund or money you didn't expect.",
    "threat": "It threatens arrest, fines or legal action.",
    "delivery_fee": "It asks for a small fee to release a delivery.",
    "secrecy": "It asks you to keep it secret.",
    "too_good": "It promises guaranteed or unusually high returns.",
    "invisible_chars": "It contains {n} invisible {characters}.",
    "anchor_mismatch": "A link shows {label_host} but really goes to {href_host}.",
    "sender_impersonation": "The sender's name says {brand} but the address is on {domain}.",
    "reply_to_mismatch": "Replies would go to a different address ({domain}) than the sender's.",
    "ai_injection": "It contains hidden instructions aimed at AI assistants.",
    "file_malicious": "VirusTotal engines flag this file as harmful ({n} of {m}).",
    "file_suspicious": "A few scanners flag this file ({n} of {m}).",
}

WORDING_CODES: tuple[str, ...] = (
    "credential_ask",
    "code_ask",
    "financial_ask",
    "payment_odd",
    "remote_access",
    "urgent_pressure",
    "prize_or_refund",
    "threat",
    "delivery_fee",
    "secrecy",
    "too_good",
)
HIDDEN_CODES: tuple[str, ...] = ("hidden_tags", "bidi_override", "invisible_chars")

_VALUE_CHARS = 80
_UNSAFE_VALUE = re.compile(r"[^A-Za-z0-9 ._:/'&+-]")


def _safe_value(value: object) -> str:
    """A placeholder value as it may appear in a fixed sentence: a host goes to its ASCII
    (punycode) form; anything else keeps only plain ASCII. Never the message's own words
    beyond a host, a brand from Crawler's list, or a number."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        return str(value)
    text = str(value or "").strip()
    if "." in text and " " not in text:
        host = ascii_host(text)
        if host:
            return host[:_VALUE_CHARS]
    cleaned = _UNSAFE_VALUE.sub("", text)[:_VALUE_CHARS].strip()
    return cleaned or "?"


def make_signal(code: str, *, count: int = 1, **values: object) -> Signal:
    """The Signal for *code* with its fixed sentence; {n} defaults to *count* and
    {characters} agrees with it. Unknown codes raise KeyError (a programming error)."""
    strength = SIGNAL_STRENGTHS[code]
    template = SIGNAL_SENTENCES[code]
    count = max(int(count), 1)
    fields: dict[str, str] = {"n": str(count), "characters": "character" if count == 1 else "characters"}
    fields.update({key: _safe_value(value) for key, value in values.items()})
    return Signal(code=code, strength=strength, text=template.format(**fields), count=count)


# ── Hidden characters ────────────────────────────────────────────────────

_TAG_FIRST, _TAG_LAST = 0xE0000, 0xE007F
_TAG_CANCEL = "\U000e007f"
_BLACK_FLAG = "\U0001f3f4"
# The three emoji flags Unicode recommends (England, Scotland, Wales) are spelled with tag
# characters after a black flag; they are a picture, not hidden text.
_RGI_FLAGS: tuple[str, ...] = tuple(
    _BLACK_FLAG + "".join(chr(0xE0000 + ord(c)) for c in region) + _TAG_CANCEL
    for region in ("gbeng", "gbsct", "gbwls")
)
_OVERRIDES = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067")
_FSI, _PDI = "\u2068", "\u2069"
_JOINERS = frozenset("\u200c\u200d")
_DIRECTION_MARKS = frozenset("\u200e\u200f\u061c")
# U+2000..U+200A are visible spaces (en space, thin space ...): web copy is full of them.
_VISIBLE_SPACES = frozenset(chr(c) for c in range(0x2000, 0x200B))
_EMOJI_TAILS = frozenset("\ufe0f\u20e3") | frozenset(chr(c) for c in range(0x1F3FB, 0x1F400))
_INVISIBLE_THRESHOLD = 3


def _is_tag(char: str) -> bool:
    return _TAG_FIRST <= ord(char) <= _TAG_LAST


def _is_emoji(char: str) -> bool:
    code = ord(char)
    return (
        char in _EMOJI_TAILS
        or 0x1F000 <= code <= 0x1FAFF
        or 0x2600 <= code <= 0x27BF
        or 0x2300 <= code <= 0x23FF
        or 0x2B00 <= code <= 0x2BFF
    )


def _script_of(char: str) -> str:
    """The script of a letter or combining mark from its Unicode name ("ARABIC",
    "DEVANAGARI", ...); "" for anything else."""
    if not (char.isalpha() or unicodedata.category(char).startswith("M")):
        return ""
    return unicodedata.name(char, "").split(" ", 1)[0]


def _joiner_is_spelling(text: str, index: int) -> bool:
    """A ZWJ/ZWNJ that is part of how something is written: after an emoji (family and
    profession emoji), or between two letters of the same non-Latin script (Persian, Indic)."""
    before = text[index - 1] if index > 0 else ""
    after = text[index + 1] if index + 1 < len(text) else ""
    if before and _is_emoji(before):
        return True
    script = _script_of(before) if before else ""
    if not script or script == "LATIN" or not after:
        return False
    return _script_of(after) == script


_TAG_RE = re.compile("[\U000e0000-\U000e007f]")
_OVERRIDE_RE = re.compile("[\u202a-\u202e\u2066\u2067]")
# Hebrew, Arabic, Syriac, Thaana, NKo and their presentation forms.
_RTL_RE = re.compile("[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufefc]")


def hidden_character_signals(text: str) -> list[Signal]:
    """Unicode tag characters and bidi overrides/isolates (strong, with counts); 3+ other
    invisible characters outside emoji ZWJ sequences (weak).

    Not counted: the three emoji subdivision flags (tag characters after a black flag), a
    joiner inside an emoji sequence or between two letters of one non-Latin script, the
    direction marks of right-to-left text, visible typographic spaces, and a first-strong
    isolate closed by its pop (what phones put around names when text is copied). An unclosed
    isolate or pop counts as an override. Reads the first MAX_SCAN_CHARS characters."""
    if not isinstance(text, str) or not text:
        return []
    text = text[:MAX_SCAN_CHARS]
    for flag in _RGI_FLAGS:
        if flag in text:
            text = text.replace(flag, _BLACK_FLAG)
    tags = len(_TAG_RE.findall(text))
    fsi, pdi = text.count(_FSI), text.count(_PDI)
    overrides = len(_OVERRIDE_RE.findall(text)) + abs(fsi - pdi)
    rtl = bool(_RTL_RE.search(text))
    other = 0
    for match in _INVISIBLE_CHARS.finditer(text):
        ch = match.group()
        if _is_tag(ch) or ch in _OVERRIDES or ch in (_FSI, _PDI) or ch in _VISIBLE_SPACES:
            continue
        if ch in _JOINERS and _joiner_is_spelling(text, match.start()):
            continue
        if ch in _DIRECTION_MARKS and rtl:
            continue
        other += 1
    signals: list[Signal] = []
    if tags:
        signals.append(make_signal("hidden_tags", count=tags))
    if overrides:
        signals.append(make_signal("bidi_override", count=overrides))
    if other >= _INVISIBLE_THRESHOLD:
        signals.append(make_signal("invisible_chars", count=other))
    return signals


# ── Wording ──────────────────────────────────────────────────────────────

_QUOTE_FOLD = str.maketrans(
    {"\u2018": "'", "\u2019": "'", "\u201b": "'", "\u2032": "'", "\u201c": '"', "\u201d": '"'}
)
_HOMOGLYPH_FOLD = str.maketrans(_HOMOGLYPH_MAP)
_HSPACE_RUN = re.compile(r"[^\S\n]+")
# A sentence ends at . ! or ? followed by a space or the end, or at a line break: "$1.99" and
# "paypal.com/login" stay whole.
_SENTENCE_END = re.compile(r"[.!?]+(?=\s|$)|\n+")
_SENTENCE_CHARS = 600
_SENTENCE_STEP = 500


def fold_text(text: str) -> str:
    """The form the wording patterns read: NFKC, invisible characters removed, look-alike
    letters folded to Latin, curly quotes straightened, lower case, one space between words."""
    folded = unicodedata.normalize("NFKC", text or "")
    folded = _INVISIBLE_CHARS.sub("", folded)
    folded = folded.translate(_HOMOGLYPH_FOLD).translate(_QUOTE_FOLD).lower()
    return _HSPACE_RUN.sub(" ", folded)


def _sentences(folded: str) -> list[str]:
    """Sentences of the folded text, a very long one cut into overlapping pieces so a
    co-occurrence never spans more than a short stretch of text."""
    out: list[str] = []
    for part in _SENTENCE_END.split(folded):
        part = part.strip()
        if not part:
            continue
        if len(part) <= _SENTENCE_CHARS:
            out.append(part)
            continue
        for start in range(0, len(part), _SENTENCE_STEP):
            out.append(part[start : start + _SENTENCE_CHARS])
    return out


# What joins two sentences into one window. It is a clause break (see _CLAUSE_BREAK), so a
# "not" at the end of one sentence never reads as negating an ask that opens the next ("We could
# not process your payment. Update your billing information." still asks), and no single
# pattern can match across the sentence end.
_WINDOW_JOIN = "; "


def _windows(folded: str) -> list[str]:
    """Each sentence joined with the next: "Buy gift cards. Send me the codes." is one ask."""
    sentences = _sentences(folded)
    if len(sentences) <= 1:
        return sentences
    return [f"{a}{_WINDOW_JOIN}{b}" for a, b in zip(sentences, sentences[1:], strict=False)]


def _w(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


_S = r"\s{1,3}"
_ASK = r"(?:send|share|tell|read|give|forward)"

# A request that is negated in its own clause ("we will never ask you to verify your account",
# "do not share your OTP") is the sender's warning, not the ask; a negation after "if" or
# "unless" is a threat ("if you don't verify your account ...") and still asks.
_NEGATION = re.compile(r"n't\b|\b(?:never|not|no one|nobody|dont|doesnt|wont)\b")
_CONDITIONAL = re.compile(r"\b(?:if|unless|until|or else)\b")
_CLAUSE_BREAK = re.compile(r"[,;:]")
_NEGATION_REACH = 40

# S3 4.6's credential_ask, widened only where phishing and ordinary mail differ: "confirm the
# details of your booking" and "sign in to continue" are everyday wording and do not count.
_CREDENTIAL = (
    _w(
        r"\b(?:verify|confirm|update|validate|re-?confirm|re-?validate)"
        rf"{_S}(?:your{_S})?"
        r"(?:account|identity|password|passcode|login|log-?in|sign-?in|details|information|info"
        rf"|credentials|apple{_S}id|username)\b"
    ),
    _w(
        rf"\b(?:sign|log)\s{{0,3}}-?\s{{0,3}}in{_S}(?:now{_S})?to{_S}"
        r"(?:restore|unlock|keep|verify|confirm|avoid|re-?activate|prevent)\b"
    ),
    _w(
        rf"\b(?:enter|provide|re-?enter|type|send|share|give|tell|reply{_S}with)"
        rf"{_S}(?:us{_S}|me{_S})?your{_S}"
        rf"(?:password|passcode|login|username|credentials|pin|security{_S}answers?)\b"
    ),
)
_CODE_QUALIFIER = (
    r"(?:\d\s?-?\s?digit|(?:four|five|six|eight)\s?-?\s?digit|verification|security|login"
    r"|confirmation|sms|one\s?-?\s?time|2fa|authentication|access)"
)
# "code" right after the ask, as S3 4.6's own pattern has it, but not where "code" is plainly
# something else ("send me the code of conduct", "share the code snippet").
_DIGITS = rf"(?:\d\s?-?\s?digit{_S})?"
_NOT_A_PASSCODE = rf"(?!{_S}(?:of{_S}conduct|snippet|review)\b)"
_CODE = (
    _w(
        rf"\b(?:{_ASK}|text|reply{_S}with){_S}(?:(?:me|us|it|back|over){_S}){{0,2}}"
        rf"(?:the{_S}|your{_S}|that{_S}|this{_S})?{_CODE_QUALIFIER}{_S}"
        r"(?:code|pin|passcode|password|number)\b"
    ),
    _w(
        rf"\b{_ASK}{_S}(?:(?:me|us){_S})?(?:the{_S}|your{_S}|that{_S}|this{_S})?"
        rf"(?:otp|passcode|2fa{_S}code|one-?time{_S}pin)\b"
    ),
    # S3 4.6's pattern when the code is to come to the sender: "send me the code", "read us
    # the 6-digit code", "give me your code".
    _w(
        rf"\b{_ASK}{_S}(?:me|us){_S}(?:(?:back|over|now){_S})?(?:the{_S}|your{_S}|that{_S}|this{_S})?"
        rf"{_DIGITS}code\b{_NOT_A_PASSCODE}"
    ),
    # ... or when it is the person's own: "share your code", "send your 6-digit code".
    _w(
        rf"\b(?:send|share|tell|give|forward){_S}(?:(?:it|back|over|now){_S})?your{_S}"
        rf"{_DIGITS}code\b{_NOT_A_PASSCODE}"
    ),
)
_CODE_TO_ME = _w(rf"\b{_ASK}{_S}(?:it{_S})?(?:to{_S})?(?:me|us)\b")
# A bare "share the code" asks for a passcode only next to words saying the code was sent to
# the person ("the code we sent you"), which _CODE_SENT finds.
_CODE_BARE = _w(
    rf"\b{_ASK}{_S}(?:(?:me|us|it|back|over){_S}){{0,2}}(?:the{_S}|your{_S}|that{_S}|this{_S})?"
    rf"{_DIGITS}code\b{_NOT_A_PASSCODE}"
)
_CODE_SENT = _w(
    rf"\b(?:code|otp|pin){_S}(?:(?:that|which|we|i|was|were|has|have|been|just|recently|you)"
    rf"{_S}){{0,4}}(?:sent|texted|emailed)\b"
    rf"|\b(?:code|otp){_S}(?:(?:that|which|you|have|has|just){_S}){{0,3}}(?:got|received|get)\b"
)
_FINANCIAL = (
    _w(
        r"\b(?:enter|provide|confirm|verify|send|update|share|give|re-?enter|submit|text"
        rf"|reply{_S}with){_S}(?:us{_S}|me{_S})?(?:your{_S}|the{_S})?(?:full{_S})?"
        rf"(?:credit{_S}card|debit{_S}card|card|bank{_S}account|banking|bank|account|payment"
        rf"|billing){_S}(?:number|details|info|information|login|method|data|credentials)\b"
    ),
)
_CARD_FIELD = _w(
    rf"\b(?:cvv2?|cvc|card{_S}security{_S}code|expiry{_S}date|expiration{_S}date"
    rf"|routing{_S}number|sort{_S}code|iban)\b"
)
_ASK_VERB = _w(r"\b(?:enter|provide|send|confirm|share|give|reply|text|verify|update|need)\b")
_ODD_METHOD = _w(
    rf"\b(?:gift\s?-?\s?cards?|(?:itunes|steam|apple|google{_S}play){_S}(?:gift{_S})?cards?"
    rf"|bitcoin(?:{_S}atm)?|btc|crypto(?:currency|currencies)?|usdt|tether|ethereum"
    rf"|wire{_S}transfer|western{_S}union|moneygram)\b"
)
_PAYISH = _w(
    r"\b(?:pay|paid|paying|payment|fee|fine|settle|deposit|owe|transfer"
    rf"|send{_S}(?:the{_S})?money)\b"
)
_GIFT_CARD = _w(
    rf"\bgift\s?-?\s?cards?\b|\b(?:itunes|steam|apple|google{_S}play){_S}cards?\b"
)
_GIFT_CODES = _w(
    rf"\b(?:send|text|email|share){_S}(?:(?:me|us){_S})?(?:the{_S}|their{_S}|those{_S})?"
    rf"(?:codes|pins|numbers|card{_S}numbers)\b|\bscratch\b"
    rf"|\bback{_S}of{_S}the{_S}cards?\b|\b(?:photo|picture)s?{_S}of{_S}the{_S}cards?\b"
)
_REMOTE_TOOL = _w(
    r"\b(?:anydesk|teamviewer|ultraviewer|quick\s{0,3}support|quick\s{0,3}assist|logmein"
    r"|rustdesk|screenconnect|connectwise|supremo|airdroid|splashtop)\b"
)
_REMOTE_TOOL_VERB = _w(
    r"\b(?:install|download|open|run|launch|give|allow|grant|connect|share|accept|enter)\b"
)
_REMOTE_PHRASE = _w(
    rf"\bremote{_S}(?:access|control|desktop|session|connection)\b|\bscreen\s?-?\s?shar(?:e|ing)\b"
)
_REMOTE_PHRASE_VERB = _w(
    rf"\b(?:give|allow|grant|install|download|need|let{_S}(?:me|us)|start|accept|enable)\b"
)
_APK = _w(rf"\.apk\b|\bapk{_S}file\b")
_INSTALL = _w(r"\b(?:install|download|open)\b")
_URGENT = (
    _w(
        rf"\b(?:within|in{_S}the{_S}next|in{_S}less{_S}than){_S}\d{{1,3}}\s{{0,3}}"
        r"(?:hours?|hrs?|h|minutes?|mins?|days?)\b"
    ),
    _w(
        rf"\b(?:immediately|urgent(?:ly)?|right{_S}away|act{_S}now|final{_S}(?:notice|warning"
        rf"|reminder)|last{_S}(?:chance|warning|notice)|expires?{_S}(?:today|tonight|in{_S}\d)"
        rf"|before{_S}it(?:'s|{_S}is){_S}too{_S}late|time{_S}is{_S}running{_S}out)\b"
    ),
    _w(
        r"\b(?:account|access|card|service|password|profile|membership|subscription"
        rf"|apple{_S}id){_S}(?:will{_S}be{_S}|has{_S}been{_S}|have{_S}been{_S}|is{_S}"
        rf"(?:now{_S})?(?:being{_S})?|was{_S})?(?:suspended|locked|limited|restricted|disabled"
        rf"|closed|terminated|deactivated|blocked|frozen|on{_S}hold|compromised)\b"
    ),
)
_PRIZE = (
    _w(
        rf"\byou(?:'ve|{_S}have)?{_S}(?:won|been{_S}selected|been{_S}chosen)\b"
        rf"|\byou{_S}are{_S}(?:a|our|the){_S}(?:lucky{_S})?winner\b"
        rf"|\bclaim{_S}(?:your|the){_S}(?:prize|reward|refund|money|gift|winnings|bonus"
        r"|compensation|cash)\b"
        rf"|\bunclaimed{_S}(?:funds|money|refund|prize|package)\b"
        rf"|\brefund{_S}(?:of|is{_S}(?:waiting|pending|ready|available))\b"
        rf"|\b(?:eligible|entitled){_S}(?:for|to){_S}(?:a{_S})?(?:refund|compensation|payment"
        r"|reward|grant|rebate)\b"
        r"|\b(?:lottery|jackpot|inheritance)\b"
        rf"|\bfree{_S}(?:iphone|ipad|gift{_S}card|money|cash)\b"
    ),
)
_THREAT = (
    _w(
        rf"\b(?:arrest(?:ed)?|warrant{_S}(?:for|has)|legal{_S}action|lawsuit"
        rf"|prosecut(?:e|ed|ion)|court{_S}(?:case|summons|order|date)|jail|prison"
        rf"|deport(?:ed|ation)?|criminal{_S}(?:charges?|case|investigation)"
        rf"|police{_S}(?:will|are{_S}on)|fined|penalt(?:y|ies){_S}(?:of|will|fee))\b"
    ),
)
_DELIVERY = _w(
    r"\b(?:package|parcel|delivery|redelivery|re-?delivery|shipment|shipping|courier|customs"
    rf"|usps|ups|fedex|dhl|royal{_S}mail|postal|post{_S}office|evri|hermes)\b"
)
_FEE = _w(
    rf"\b(?:fee|fees|pay|payment|charge|duty|duties|small{_S}amount|postage)\b|[$\u00a3\u20ac]\s?\d"
)
_HELD = _w(
    rf"\b(?:on{_S}hold|held|pending|unable{_S}to{_S}(?:deliver|be{_S}delivered)"
    rf"|could{_S}not{_S}be{_S}delivered|failed|release|reschedule|redeliver\w{{0,4}}"
    rf"|re-?delivery|unpaid|outstanding|incomplete{_S}address|missed)\b"
)
_SECRECY = (
    _w(
        rf"\bkeep{_S}(?:this|it){_S}(?:a{_S})?(?:secret|between{_S}us|confidential|private"
        rf"|to{_S}yourself|quiet)\b"
        rf"|\b(?:don't|dont|do{_S}not){_S}(?:tell|inform){_S}(?:anyone|anybody|your{_S}"
        r"(?:family|bank|husband|wife|parents|kids|children|friends))\b"
        rf"|\btell{_S}no{_S}one\b"
        rf"|\b(?:don't|dont|do{_S}not){_S}(?:discuss|share){_S}this{_S}with{_S}"
        rf"(?:anyone|anybody|your{_S}bank)\b"
    ),
)
_TOO_GOOD = (
    _w(
        rf"\bguaranteed{_S}(?:returns?|profits?|income|payouts?|gains?|winnings)\b"
        rf"|\brisk\s?-?\s?free{_S}(?:investment|returns?|profits?|trading)\b"
        rf"|\bdouble{_S}your{_S}(?:money|investment|bitcoin|crypto|income)\b"
        rf"|\b\d{{2,4}}\s?%{_S}(?:returns?|profits?|gains?|roi)\b"
        rf"|\b(?:earn|make){_S}[$\u00a3\u20ac]?\s?\d[\d,]{{0,9}}\s{{0,3}}(?:k{_S})?"
        rf"(?:dollars{_S}|usd{_S}|pounds{_S})?(?:a|per|every){_S}(?:day|week|hour)\b"
    ),
)

# Every compiled wording pattern, for the adversarial timing test.
WORDING_PATTERNS: tuple[re.Pattern[str], ...] = (
    *_CREDENTIAL,
    *_CODE,
    _CODE_TO_ME,
    _CODE_BARE,
    _CODE_SENT,
    *_FINANCIAL,
    _CARD_FIELD,
    _ASK_VERB,
    _ODD_METHOD,
    _PAYISH,
    _GIFT_CARD,
    _GIFT_CODES,
    _REMOTE_TOOL,
    _REMOTE_TOOL_VERB,
    _REMOTE_PHRASE,
    _REMOTE_PHRASE_VERB,
    _APK,
    _INSTALL,
    *_URGENT,
    *_PRIZE,
    *_THREAT,
    _DELIVERY,
    _FEE,
    _HELD,
    *_SECRECY,
    *_TOO_GOOD,
)


def _asked(pattern: re.Pattern[str], window: str) -> bool:
    """*pattern* matches in *window* at least once outside a negated clause."""
    for match in pattern.finditer(window):
        before = window[max(0, match.start() - _NEGATION_REACH) : match.start()]
        clause = _CLAUSE_BREAK.split(before)[-1]
        negation = _NEGATION.search(clause)
        if not negation or _CONDITIONAL.search(clause[: negation.start()]):
            return True
    return False


def _any(patterns: Iterable[re.Pattern[str]], window: str) -> bool:
    return any(p.search(window) for p in patterns)


def _wording_codes(window: str) -> set[str]:
    found: set[str] = set()
    if any(_asked(p, window) for p in _CREDENTIAL):
        found.add("credential_ask")
    if any(_asked(p, window) for p in _CODE) or (
        (_asked(_CODE_TO_ME, window) or _asked(_CODE_BARE, window)) and _CODE_SENT.search(window)
    ):
        found.add("code_ask")
    if any(_asked(p, window) for p in _FINANCIAL) or (
        _CARD_FIELD.search(window) and _asked(_ASK_VERB, window)
    ):
        found.add("financial_ask")
    if (_ODD_METHOD.search(window) and _PAYISH.search(window)) or (
        _GIFT_CARD.search(window) and _GIFT_CODES.search(window)
    ):
        found.add("payment_odd")
    if (
        (_REMOTE_TOOL.search(window) and _REMOTE_TOOL_VERB.search(window))
        or (_REMOTE_PHRASE.search(window) and _REMOTE_PHRASE_VERB.search(window))
        or (_APK.search(window) and _INSTALL.search(window))
    ):
        found.add("remote_access")
    if _any(_URGENT, window):
        found.add("urgent_pressure")
    if _any(_PRIZE, window):
        found.add("prize_or_refund")
    if _any(_THREAT, window):
        found.add("threat")
    if _DELIVERY.search(window) and _FEE.search(window) and _HELD.search(window):
        found.add("delivery_fee")
    if _any(_SECRECY, window):
        found.add("secrecy")
    if _any(_TOO_GOOD, window):
        found.add("too_good")
    return found


def language_signals(text: str) -> list[Signal]:
    """Fixed, bounded patterns for the wording tricks in 4.6's signal table; each code at most
    once, in the table's order (strong before weak). Reads the first MAX_SCAN_CHARS
    characters."""
    if not isinstance(text, str) or not text.strip():
        return []
    found: set[str] = set()
    for window in _windows(fold_text(text[:MAX_SCAN_CHARS])):
        found |= _wording_codes(window)
        if len(found) == len(WORDING_CODES):
            break
    return [make_signal(code) for code in WORDING_CODES if code in found]


# ── Hosts and links ──────────────────────────────────────────────────────

_IDNA_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_ASCII_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
# The letters IDNA 2003 (Python's "idna" codec) rewrites but browsers keep (UTS 46
# non-transitional): fa\u00df.de opens xn--fa-hia.de, not fass.de, a different real domain.
_IDNA_DEVIATIONS = str.maketrans({"\u00df": "ss", "\u03c2": "\u03c3"})


def _ascii_label(label: str) -> Optional[str]:
    """One non-ASCII label in the punycode form a browser opens, or None. Python's codec is
    IDNA 2003, which maps the deviation letters (sharp s, final sigma) to other letters; such a
    label is encoded as written, as browsers do, and a label the codec rewrites in any other
    way is refused, never shown under a tidier name than the one the link really uses."""
    try:
        encoded = label.encode("idna").decode("ascii").lower()
        back = encoded.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return None
    if back != label:
        if back != label.translate(_IDNA_DEVIATIONS):
            return None
        try:
            encoded = "xn--" + label.encode("punycode").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None
    return encoded


def ascii_host(host: str) -> Optional[str]:
    """*host* in IDNA/punycode form, lower-case, no trailing dot; None when it cannot be
    encoded. A label holding an invisible character is refused rather than cleaned, because
    cleaning would show a tidier name than the one the link really uses; for the same reason
    a sharp s or final sigma is encoded as a browser does (non-transitional), not as ss or
    sigma."""
    if not isinstance(host, str):
        return None
    text = unicodedata.normalize("NFKC", host).translate(_IDNA_DOTS).strip().rstrip(".").lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if not text or len(text) > 253:
        return None
    if ":" in text:
        try:
            return ipaddress.IPv6Address(text).compressed
        except ValueError:
            return None
    labels: list[str] = []
    for label in text.split("."):
        if not label or len(label) > 63:
            return None
        if label.isascii():
            if not _ASCII_LABEL.fullmatch(label):
                return None
            labels.append(label)
            continue
        if _INVISIBLE_CHARS.search(label):
            return None
        encoded = _ascii_label(label)
        if not encoded or len(encoded) > 63 or not _ASCII_LABEL.fullmatch(encoded):
            return None
        labels.append(encoded)
    joined = ".".join(labels)
    return joined if len(joined) <= 253 else None


# Characters display_url keeps as they are in a path; everything else is percent-encoded, so a
# path never carries a look-alike letter, an invisible character, a backtick or a quote.
_PATH_SAFE = "/-._~%!$&()*+,;=:@"


def display_url(url: str) -> str:
    """scheme://<ascii host><path up to 60 chars>, with the query and fragment replaced by
    "…"; never a raw non-ASCII host. "" when the address cannot be read. A user name before
    "@" is left out, so the host shown is where the link really goes."""
    if not isinstance(url, str) or not url.strip():
        return ""
    try:
        parts = urlsplit(url.strip())
        hostname = parts.hostname or ""
        port = parts.port
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return f"{scheme}:\u2026" if scheme.isascii() and scheme.isalnum() else ""
    host = ascii_host(hostname)
    if not host:
        return ""
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = quote(parts.path, safe=_PATH_SAFE)
    cut = len(path) > DISPLAY_PATH_CHARS
    if cut:
        path = path[:DISPLAY_PATH_CHARS]
    tail = "\u2026" if cut or parts.query or parts.fragment else ""
    return f"{scheme}://{netloc}{path}{tail}"


def url_host(url: str) -> Optional[str]:
    """The ASCII host of *url* (or of a bare host), None when it cannot be read."""
    if not isinstance(url, str) or not url.strip():
        return None
    text = url.strip()
    if "://" not in text:
        text = "http://" + text
    try:
        hostname = urlsplit(text).hostname or ""
    except ValueError:
        return None
    return ascii_host(hostname) if hostname else None


# A host may be written without a scheme when it ends in one of these (or any two-letter
# country ending). A name ending in a file extension (report.pdf, setup.zip) is a file unless
# a path follows it.
KNOWN_TLDS: frozenset[str] = frozenset(
    {
        "com", "net", "org", "info", "biz", "io", "co", "app", "dev", "xyz", "top", "shop",
        "store", "online", "site", "website", "live", "club", "vip", "win", "bid", "loan",
        "work", "click", "link", "help", "support", "icu", "cyou", "buzz", "rest", "sbs", "cfd",
        "quest", "bond", "men", "party", "review", "stream", "download", "racing", "date",
        "faith", "science", "accountant", "cricket", "monster", "lol", "space", "tech", "cloud",
        "email", "life", "today", "news", "blog", "page", "pro", "mobi", "name", "fun", "one",
        "asia", "edu", "gov", "mil", "int", "services", "secure", "account", "bank", "finance",
        "money", "pay", "delivery", "express", "post", "tickets", "travel", "digital", "agency",
        "company", "group", "global", "solutions", "center", "network", "systems",
    }
)
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt", "csv", "tsv",
        "json", "xml", "yaml", "yml", "md", "log", "ini", "cfg", "conf", "jpg", "jpeg", "png",
        "gif", "bmp", "svg", "webp", "heic", "tif", "tiff", "mp3", "mp4", "m4a", "wav", "mov",
        "avi", "mkv", "zip", "rar", "tar", "gz", "tgz", "exe", "msi", "dmg", "apk", "iso",
        "bin", "dll", "py", "js", "ts", "sh", "bat", "ps1", "rb", "java", "cpp", "cs", "php",
        "html", "htm", "css", "sql", "eml", "ics", "vcf",
    }
)

_TOKEN = re.compile(r"[^\s<>\"'`|\\^{}\[\]]{1,4096}")
_TOKEN_SPLIT = re.compile(r"(?i)(?=https?://)|(?<=[^\w.])(?=www\.)")
_LEAD = "(*_~"
_TRAIL = ".,;:!?*_~\u2026"
_UNICODE_LABEL = re.compile(r"[^\W_](?:[\w-]{0,61}[^\W_])?")
_PORT = re.compile(r"\d{1,5}")


def _trim(token: str) -> str:
    """*token* without the punctuation around a link in prose: leading brackets and marks,
    trailing sentence punctuation, and closing parentheses that close nothing in the link
    (one pass from the end, so a run of them stays linear)."""
    token = token.lstrip(_LEAD).rstrip(_TRAIL)
    excess = token.count(")") - token.count("(")
    end = len(token)
    while excess > 0 and end > 0 and (token[end - 1] == ")" or token[end - 1] in _TRAIL):
        if token[end - 1] == ")":
            excess -= 1
        end -= 1
    return token[:end].rstrip(_TRAIL)


def _bare_host_ok(host: str, has_path: bool) -> bool:
    labels = host.split(".")
    if len(labels) < 2 or not all(labels):
        return False
    if all(label.isdigit() for label in labels):
        return has_path and len(labels) == 4
    if not all(_UNICODE_LABEL.fullmatch(label) for label in labels):
        return False
    tld = labels[-1].lower()
    if tld.startswith("xn--"):
        return len(tld) > 4
    if not tld.isalpha() or not 2 <= len(tld) <= 24:
        return False
    if has_path:
        return True
    if tld in FILE_EXTENSIONS:
        return False
    return tld in KNOWN_TLDS or len(tld) == 2 or not tld.isascii()


def _as_url(token: str) -> Optional[str]:
    """*token* as a link (bare ones get http:// in front), or None."""
    token = _trim(token)
    if not token:
        return None
    lower = token.lower()
    if lower.startswith(("http://", "https://")):
        url = token
    elif lower.startswith("www.") and len(token) > 4:
        url = "http://" + token
    elif "@" in token or token.startswith(("/", ".", "-")):
        return None
    else:
        host_part = re.split(r"[/?#]", token, maxsplit=1)[0]
        rest = token[len(host_part) :]
        host, _, port = host_part.partition(":")
        if port and not _PORT.fullmatch(port):
            return None
        if not _bare_host_ok(host, has_path=bool(rest)):
            return None
        url = "http://" + token
    if len(url) > MAX_URL_CHARS:
        return None
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return None
    return url if hostname else None


def extract_urls(text: str, *, limit: int = MAX_URLS) -> list[str]:
    """http(s) links, www. links and bare domains with a path or a real-looking TLD, in order,
    deduped; never e-mail addresses or file names (report.pdf); bare ones get http://
    prepended. Reads the first MAX_SCAN_CHARS characters."""
    if not isinstance(text, str) or not text or limit <= 0:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for match in _TOKEN.finditer(text[:MAX_SCAN_CHARS]):
        for piece in _TOKEN_SPLIT.split(match.group()):
            url = _as_url(piece) if piece else None
            if url is None or url.lower() in seen:
                continue
            seen.add(url.lower())
            found.append(url)
            if len(found) >= limit:
                return found
    return found


_MD_ANCHOR = re.compile(
    r"\[(?P<label>[^\[\]\n]{1,200})\]\(\s{0,3}<?(?P<href>https?://[^\s()<>]{1,2048})>?"
    r"(?:\s{1,3}\"[^\"\n]{0,200}\")?\s{0,3}\)",
    re.IGNORECASE,
)
# An HTML anchor is read in three bounded steps (the opening tag, its href, the closing tag
# within 300 characters), so a page of unclosed "<a href=" stays linear.
_HTML_OPEN = re.compile(r"<a\b[^<>]{0,1000}>", re.IGNORECASE)
_HTML_HREF = re.compile(r"\bhref\s{0,3}=\s{0,3}[\"']?(https?://[^\"'\s>]{1,2048})", re.IGNORECASE)
_HTML_CLOSE = re.compile(r"</a\s{0,3}>", re.IGNORECASE)
_HTML_LABEL_CHARS = 300
_SLACK_ANCHOR = re.compile(r"<(?P<href>https?://[^|>\s]{1,2048})\|(?P<label>[^>\n]{1,200})>", re.IGNORECASE)
_TAG_STRIP = re.compile(r"<[^<>]{0,200}>")
_WHITESPACE = re.compile(r"\s+")


def _clean_label(label: str) -> str:
    label = html.unescape(_TAG_STRIP.sub(" ", label))
    return _WHITESPACE.sub(" ", label).strip()[:MAX_LABEL_CHARS]


def _anchor_matches(text: str) -> list[tuple[int, int, str, str]]:
    """(start, end, label, href) for every anchor, in order, overlapping ones dropped. Reads
    the first MAX_SCAN_CHARS characters."""
    text = text[:MAX_SCAN_CHARS]
    spans: list[tuple[int, int, str, str]] = []
    for pattern in (_MD_ANCHOR, _SLACK_ANCHOR):
        for match in pattern.finditer(text):
            label = _clean_label(match.group("label"))
            if label:
                spans.append((match.start(), match.end(), label, match.group("href")))
    for opening in _HTML_OPEN.finditer(text):
        href = _HTML_HREF.search(opening.group())
        closing = _HTML_CLOSE.search(text, opening.end(), opening.end() + _HTML_LABEL_CHARS + 8)
        if href is None or closing is None:
            continue
        label = _clean_label(text[opening.end() : closing.start()])
        if label:
            spans.append((opening.start(), closing.end(), label, href.group(1)))
    spans.sort()
    kept: list[tuple[int, int, str, str]] = []
    for span in spans:
        if kept and span[0] < kept[-1][1]:
            continue
        kept.append(span)
    return kept


def anchor_pairs(text: str) -> list[tuple[str, str]]:
    """(label, href) for [label](href), <a href="href">label</a> and Slack <href|label>."""
    if not isinstance(text, str) or not text:
        return []
    return [(label, href) for _, _, label, href in _anchor_matches(text)][:MAX_ANCHORS]


def _registrable_guess(host: str) -> str:
    """The site a host belongs to, without a suffix list: the last two labels, or three under
    a two-part country ending (co.uk, com.au, ne.jp). services.security.lookalike has the
    exact helper; callers that have it pass it as *registrable*."""
    labels = host.split(".")
    if len(labels) < 2 or all(label.isdigit() for label in labels):
        return host
    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in {"co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go"}
    ):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def anchor_signals(
    anchors: Sequence[tuple[str, str]],
    *,
    registrable: Optional[Callable[[str], str]] = None,
) -> list[Signal]:
    """anchor_mismatch (strong) when a link's shown label names a site (a URL or a bare domain)
    on another registrable domain than the address it really opens; one signal counting every
    such link, its sentence naming the first pair's hosts in punycode."""
    site_of = registrable or _registrable_guess
    pairs: list[tuple[str, str]] = []
    for label, href in anchors:
        named = extract_urls(label, limit=1)
        if not named:
            continue
        label_host, href_host = url_host(named[0]), url_host(href)
        if not label_host or not href_host:
            continue
        if site_of(label_host) != site_of(href_host):
            pairs.append((label_host, href_host))
    if not pairs:
        return []
    label_host, href_host = pairs[0]
    return [make_signal("anchor_mismatch", count=len(pairs), label_host=label_host, href_host=href_host)]


def _valid_anchor(pair: object) -> Optional[tuple[str, str]]:
    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
        return None
    label, href = pair
    if not isinstance(label, str) or not isinstance(href, str):
        return None
    href = href.strip()
    if not href.lower().startswith(("http://", "https://")) or len(href) > MAX_URL_CHARS:
        return None
    label = _clean_label(label)
    return (label, href) if label else None


def analyse_text(
    text: str,
    *,
    extra_anchors: Sequence[tuple[str, str]] = (),
    registrable: Optional[Callable[[str], str]] = None,
) -> TextFindings:
    """The whole local pass: hidden characters, wording signals, links and label/address pairs
    (Markdown, HTML, Slack <url|label>, plus the channel's own extra_anchors such as Telegram
    text_link entities). The text is cut to MAX_TEXT_CHARS first. A label shown on a link is
    not itself counted as a link; the address behind it is, in the place it appears, and the
    hidden addresses of extra_anchors come last. *registrable* is the registrable-domain helper
    for the label check (services.security.lookalike.registrable_domain in the service)."""
    text = text if isinstance(text, str) else ""
    truncated = len(text) > MAX_TEXT_CHARS
    text = text[:MAX_TEXT_CHARS]
    matches = _anchor_matches(text)
    anchors: list[tuple[str, str]] = [(label, href) for _, _, label, href in matches]
    for pair in extra_anchors:
        valid = _valid_anchor(pair)
        if valid and valid not in anchors:
            anchors.append(valid)
    anchors = anchors[:MAX_ANCHORS]
    # The links: the text with every anchor's markup replaced by its address.
    pieces: list[str] = []
    cursor = 0
    for start, end, _, href in matches:
        pieces.append(text[cursor:start])
        pieces.append(f" {href} ")
        cursor = end
    pieces.append(text[cursor:])
    urls = extract_urls("".join(pieces), limit=MAX_URLS + 1)
    seen = {u.lower() for u in urls}
    for _, href in anchors:
        if href.lower() not in seen:
            seen.add(href.lower())
            urls.append(href)
    signals = [
        *hidden_character_signals(text),
        *anchor_signals(anchors, registrable=registrable),
        *language_signals(text),
    ]
    return TextFindings(
        signals=tuple(signals),
        urls=tuple(urls[:MAX_URLS]),
        anchors=tuple(anchors),
        truncated=truncated,
        more_urls=len(urls) > MAX_URLS,
    )


# ── What an AI-written reason may show (review SEC-M2) ───────────────────

_WWW = re.compile(r"\bwww\s?\.", re.IGNORECASE)
# A dot written so it does not look like one: "[.]", "(dot)", "paypal-help dot lat" (any
# ending: the attacker picks it), and "45 dot 9" between digits.
_DEFANGED_DOT = re.compile(
    r"[\[({<]\s?(?:\.|dot)\s?[\])}>]"
    r"|(?<=\w)[\s_-]{1,3}dot[\s_-]{1,3}(?=[^\W\d_]{2}|\d)",
    re.IGNORECASE,
)
# A phone number: 7 or more digits with at most a short run of separators between each two
# ("888_555_0101", "888 -- 555 -- 0101", "888, 555, 0101"). A comma counts only before a
# space, so an amount ("$1,000,000") is not a phone number.
_PHONE = re.compile(r"\d(?:(?:[^\w,]|_|,\s){0,4}\d){6,}")
# A vanity number: a toll-free prefix before letters ("1-800-PAYPAL-1", "(888) PAYNOW"), or
# three digits and a dash before capitals ("555-SCAMMER").
_VANITY = re.compile(
    r"(?:\b1[\s.\-]{1,3}\(?8(?:00|33|44|55|66|77|88)\)?[\s.\-]{1,3}"
    r"|\b8(?:00|33|44|55|66|77|88)[.\-]|\(8(?:00|33|44|55|66|77|88)\)\s{0,2})[A-Za-z0-9]{3,}"
    r"|\b\d{3}[.\-][A-Z]{4,}"
)
# An IP address: IPv4 (any digit count), or IPv6 (five groups, or a "::").
_IP_ADDRESS = re.compile(
    r"\b\d{1,3}(?:\s{0,2}\.\s{0,2}\d{1,3}){3}\b"
    r"|(?:[0-9A-Fa-f]{1,4}:){4,}[0-9A-Fa-f]{1,4}|[0-9A-Fa-f]{0,4}::[0-9A-Fa-f]{1,4}"
)
# An HTML character reference: a Markdown renderer decodes "&period;" to "." and "&commat;"
# to "@" (checker finding), and an AI reason has no need for one.
_CHARACTER_REFERENCE = re.compile(r"&(?:#[0-9]{1,8}|#[xX][0-9A-Fa-f]{1,8}|[A-Za-z][A-Za-z0-9]{1,31});")
_MARKDOWN_LINK = ("](", "![")
_LINE_BREAKS = str.maketrans({"\t": " ", "\r": " ", "\n": " ", "\u2028": " ", "\u2029": " "})
# Characters a reader cannot see that are not control or format characters: Unicode's
# default-ignorable marks and fillers (the combining grapheme joiner, Khmer inherent vowels,
# Mongolian variation selectors, variation selectors, Hangul fillers). Left in, they split
# "paypal-help<U+FE0F>.lat" into tokens no domain rule matches while it still reads as one
# domain (checker finding).
_DEFAULT_IGNORABLE = re.compile(
    "[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u3164\ufe00-\ufe0f\uffa0\U000e0100-\U000e01ef]"
)
# Characters that read as a dot in a domain but are not "." (NFKC already folds the
# fullwidth and small forms, and _IDNA_DOTS the ideographic ones).
_DOT_LIKE = str.maketrans(dict.fromkeys("\u00b7\u2027\u2219\u22c5\u30fb\u2e31\ua78f", "."))
# Punctuation pressed against a dot ("paypal-help\.lat", "x*.*lat") or spaces before one
# ("paypal-help . lat"): read as a plain dot when judging. Prose never has a space before its
# full stop, so a sentence is not joined to the next.
_PUNCT_AT_DOT = re.compile(r"[^\w\s.]{1,3}(?=\.)|(?<=\.)[^\w\s.]{1,3}|(?<=\w)\s{1,3}\.\s{0,3}(?=\w)")


def _strip_format(text: str) -> str:
    """Control, format, private-use and unassigned characters (bidi controls, zero-width
    characters, tag characters), lone surrogates (which cannot be written as UTF-8) and the
    default-ignorable marks removed; tabs and line breaks become spaces; whitespace
    collapsed."""
    text = _DEFAULT_IGNORABLE.sub("", text.translate(_LINE_BREAKS))
    text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
    return _WHITESPACE.sub(" ", text).strip()


def _judged_forms(text: str) -> tuple[str, ...]:
    """The forms of a reason the link, address and number rules read: as shown and with HTML
    character references decoded; each of those also with every combining mark removed, the
    look-alike letters and dot-like characters folded, and then with punctuation pressed
    against a dot dropped. Whatever a person could read as a link is plain in one of them."""
    forms: list[str] = []
    for variant in dict.fromkeys((text, html.unescape(text))):
        variant = _strip_format(unicodedata.normalize("NFKC", variant))
        bare = "".join(ch for ch in variant if not unicodedata.category(ch).startswith("M"))
        bare = bare.translate(_HOMOGLYPH_FOLD).translate(_DOT_LIKE).translate(_IDNA_DOTS)
        forms.extend((variant, bare, _PUNCT_AT_DOT.sub(".", bare.replace("\\", ""))))
    return tuple(dict.fromkeys(forms))


def _shows_contact(form: str) -> bool:
    """Whether *form* holds a link, a domain, an address, a phone number or an IP address."""
    return bool(
        "://" in form
        or "@" in form
        or any(mark in form for mark in _MARKDOWN_LINK)
        or _WWW.search(form)
        or _DEFANGED_DOT.search(form)
        or _PHONE.search(form)
        or _VANITY.search(form)
        or _IP_ADDRESS.search(form)
        or _names_a_domain(form)
        or extract_urls(form, limit=1)
    )


_HOST_TOKEN_SPLIT = re.compile(r"[^\w.\-]+")
_LETTER_ENDING = re.compile(r"[^\W\d_]{2,63}")


def _names_a_domain(text: str) -> bool:
    """Whether *text* holds a label.label token whose last label is 2+ letters (any script) or
    punycode: a domain, whatever its ending. extract_urls only takes a bare domain on endings it
    knows, which is right for a pasted message but not for an AI's reason, where the attacker
    picks the ending (amazon-help.lat, evil.zip). Abbreviations such as "e.g." and "U.S." end
    in one letter and are not domains."""
    for token in _HOST_TOKEN_SPLIT.split(text.translate(_IDNA_DOTS)):
        token = token.strip(".-_")
        if "." not in token:
            continue
        labels = token.split(".")
        if not all(labels):
            continue
        ending = labels[-1].lower()
        if ending.startswith("xn--") or _LETTER_ENDING.fullmatch(ending):
            return True
    return False


def clean_ai_reason(text: str, *, limit: int = 200) -> Optional[str]:
    """One AI-written reason as it may be shown, or None to drop it (review SEC-M2; the same idea
    as S2's clean_line, but dropping instead of scrubbing: a reason that needs scrubbing was
    written for the attacker). None when the text holds a URL or a "www." token, a domain on
    any letter ending (stricter than the extract_urls rules: name.claims, evil.zip and
    login-paypal.mov all count), a defanged dot ("[.]", "paypal-help dot lat"), an "@", a run
    of 7 or more digits with short separators between them (a phone number), a vanity number
    ("1-800-PAYPAL"), an IP address, an HTML character reference, or Markdown link or image
    syntax ("](", "!["), in any form a person could read it (_judged_forms: invisible and
    combining marks, character references, look-alike letters and dot-like characters
    undone). Else the text collapsed to one line, control, format and default-ignorable
    characters removed, capped at *limit*."""
    if not isinstance(text, str):
        return None
    # What could be shown is the first *limit* characters; a little past the cut is read too,
    # so a number or address the cut would split is still seen whole. The raw text is cut
    # first, generously (removed characters shrink it), so a huge reply costs no more.
    window = limit + 64
    cleaned = _strip_format(unicodedata.normalize("NFKC", text[: window * 8]))
    cleaned = cleaned.lstrip("-*\u2022 ").strip()[:window]
    if not cleaned or _CHARACTER_REFERENCE.search(cleaned):
        return None
    if any(_shows_contact(form) for form in _judged_forms(cleaned)):
        return None
    if len(cleaned) > limit:
        cleaned = cleaned[: max(limit - 1, 0)].rstrip() + "\u2026"
    return cleaned
