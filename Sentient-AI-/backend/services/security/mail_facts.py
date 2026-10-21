"""Reads the security facts of one email out of what Gmail or Outlook
returned: the receiving provider's own verdict on the sender (its topmost
Authentication-Results), From, Sender, Reply-To and Return-Path, every link
with the text it shows and where it really goes, the attachments' names and
types, a short excerpt of the visible text, and the recipient keys S1 reads
(scaffold A7).

Why it exists: the mail scam check (services/notifications/mail_scan.py,
scored by services/security/mail_checks.py) and S1's outgoing-message check
both need the same facts about one message, from both providers, and every
one of them was written by whoever sent the mail. Parsing them is pure data
handling, so it lives here, apart from the connector actions that only fetch
(google_api/mail_security.py, microsoft_api/mail_security.py). The rules
that make the facts trustworthy live here too:

- Only the topmost Authentication-Results the receiving provider wrote is
  read (Gmail: authserv-id mx.google.com; Outlook: the topmost one, Exchange
  writes no id). A sender can add any header below it, so lower copies are
  never read.
- A link that runs code (javascript:, vbscript:, data:, file:) becomes a
  code with no href before the connector's PromptGuard (connectors/base.py)
  rewrites the scheme to [REDACTED]; Outlook Safe Links and Google redirects
  are unwrapped once, so the real destination is what gets checked.
- The HTML is read the way a browser reads it, in linear time (see "The HTML
  body"): no markup trick hides a link or visible wording from the checks,
  and text a mail hides with inline styles stays out of the excerpt only
  while nothing in the mail can show it again.
- A From header that mail apps may read two ways keeps its text as the name
  and no address, so the checks report it instead of skipping the sender.
- Hidden characters (zero-width, tag and bidi controls) are counted, then
  removed from what is kept, so "pass\u200bword" still reads as a word. In an
  attachment's name each run of them becomes U+FFFD instead, so a name that
  hides its real ending ("invoice<RLO>fdp.exe") still shows that it does.
- The excerpt ("text") is capped, but a long mail cannot push the wording the
  checks look for out of it: the sentences that carry urgency, payment or
  sign-in words are kept wherever they are (``wording_excerpt``), and text a
  stylesheet may be hiding comes after the text that is surely shown.
- Every value is capped, every walk is bounded, and nothing here raises on a
  hostile payload: a part that cannot be read is left out.

No network, no model; standard library plus the pure look-alike table
(services/security/README.md). Connects to: the two connector modules above
(they answer ``facts_from_gmail`` / ``facts_from_graph``), S2's
mail_checks.py, and S1's outbound check (it reads the scaffold A7 keys).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr
from html import unescape
from typing import Any, Mapping, Optional, Sequence, TypedDict, cast
from urllib.parse import unquote, unquote_plus, urljoin, urlsplit

from services.security.lookalike import CONFUSABLES
from services.triggers import facts as trigger_facts

MAX_LINKS = 40  # links returned per message (deduped by href)
MAX_ANCHORS = 400  # anchors parsed before giving up (links_total keeps counting to here)
MAX_REPLY_TO = 5
MAX_ATTACHMENTS = 20
SUBJECT_CHARS = 300
TEXT_CHARS = 2000  # excerpt returned by the action
MAX_HTML_CHARS = 500_000  # longer HTML (or plain text) is cut before parsing
MAX_HEADER_CHARS = 4096  # one header value
MAX_HEADERS_READ = 300
GMAIL_AUTHSERV_IDS = frozenset({"mx.google.com"})

# Recipient keys S1 reads (scaffold A7): bare addresses, at most this many each.
MAX_RECIPIENTS = 50
MAX_LABELS = 30
HREF_CHARS = 2048
LINK_TEXT_CHARS = 200
NAME_CHARS = 80
ADDRESS_CHARS = 254
FILENAME_CHARS = 200
REF_CHARS = 255
# One results header carries a handful of methods; a value with more parts
# than this is hostile or broken and the rest is not read.
MAX_RESINFO = 20
MAX_DKIM_DOMAINS = 5
MAX_MIME_DEPTH = 20
MAX_MIME_PARTS = 200
# A DNS label holds at most 63 characters, so a longer one names no host a
# browser can reach; it is refused before the (quadratic) IDNA encoder sees it.
MAX_LABEL_CHARS = 63
# Query fields read when unwrapping a Safe Links or Google redirect; the
# target is looked for among these only, however many the link carries.
MAX_QUERY_FIELDS = 256
# The excerpt keeps the passages that carry pressure wording (see
# wording_excerpt): at most this share of it, each passage at most this long
# (three passages, one per kind of wording, fit in the AI review's 1,500).
WORDING_SHARE = 0.45
WORDING_CHUNK_CHARS = 200
# The answer for a message the provider says no longer exists (review FEA-SF3).
GONE_KEY = "gone"

PROVIDERS = ("gmail", "outlook")
AUTH_SOURCES = ("authentication-results", "received-spf", "internal", "none")
LINK_SCHEMES = ("https", "http", "mailto", "tel", "javascript", "data", "vbscript", "file", "other")
LINK_CODES = ("script_link", "data_link", "file_link")

# Result words kept as they are; anything else reads as "unknown". Exchange
# writes bestguesspass (no DMARC record, but it would pass) and compauth
# softpass; neither is a pass.
_RESULT_WORDS = frozenset(
    {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass", "softpass"}
)
_RESULT_ALIASES = {"hardfail": "fail"}
_POLICY_WORDS = {
    "reject": "reject",
    "oreject": "reject",
    "pct.reject": "reject",
    "quarantine": "quarantine",
    "pct.quarantine": "quarantine",
    "none": "none",
}
_CODE_FOR_SCHEME = {
    "javascript": "script_link",
    "vbscript": "script_link",
    "data": "data_link",
    "file": "file_link",
}
_SAFELINKS_SUFFIX = ".safelinks.protection.outlook.com"
_GOOGLE_REDIRECT_HOSTS = frozenset({"google.com", "www.google.com"})

# Characters that render as nothing, or as blank space that is not
# whitespace: format characters (Unicode category Cf: zero-width, soft
# hyphen, bidi controls, tags) and the Hangul and other fillers.
_HIDDEN_RE = re.compile(
    "[\u00ad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2\u115f\u1160\u17b4\u17b5\u180e"
    "\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\u3164\ufeff\uffa0\ufff9-\ufffb"
    "\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    "\U000e0001\U000e0020-\U000e007f]"
)
_ZWJ = "\u200d"
# The three RGI subdivision flags (England, Scotland, Wales) are spelled with
# tag characters; they are pictures, not hidden text (scaffold A35).
_RGI_TAG_FLAGS = tuple(
    "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in code) + "\U000e007f"
    for code in ("gbeng", "gbsct", "gbwls")
)
_EMOJI_MODIFIERS = frozenset(chr(c) for c in range(0x1F3FB, 0x1F400)) | {"\ufe0f"}
_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]{0,30}):")
_LEADING_SLASHES_RE = re.compile(r"[\\/]{2,}")
# A browser reads "https:evil.example", "https:/evil.example" and
# "https:///evil.example" (and the same with backslashes) as a link to
# evil.example: for http and https any run of slashes after the scheme,
# none included, starts the host.
_SPECIAL_SLASHES_RE = re.compile(r"(https?):[\\/]*", re.IGNORECASE)
# Characters a browser refuses in a host once it has percent-decoded it.
_FORBIDDEN_HOST_CHARS = frozenset("\x00\t\n\r #/:<>?@[\\]^|%")
_CHARSET_RE = re.compile(r"charset\s*=\s*\"?([A-Za-z0-9_.:\-]{1,40})", re.IGNORECASE)
_ADDRESS_RE = re.compile(r"[^@\s<>\"(),;:]{1,64}@[^@\s<>\"(),;:]{1,253}")
_DOMAIN_RE = re.compile(r"(?:[^\W_][\w-]{0,62}\.){1,10}[^\W\d_]{2,63}")
# A shown text ending like a file name, not a site ("invoice.pdf").
_FILE_SUFFIXES = frozenset(
    {
        "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "txt", "csv",
        "rtf", "odt", "ods", "odp", "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic",
        "webp", "htm", "html", "shtml", "php", "asp", "aspx", "jsp", "exe", "msi", "json", "xml",
        "eml", "msg", "ics", "vcf", "wav", "mp3", "mp4", "avi", "wmv", "mkv", "dmg", "iso", "apk",
        "js", "css", "log", "bak", "tmp",
    }
)  # fmt: skip
_TEXT_EDGE = "<>()[]{}\"'\u00ab\u00bb\u201c\u201d\u2018\u2019"
_BLOCK_TAGS = frozenset(
    {
        "p", "div", "br", "li", "tr", "table", "ul", "ol", "blockquote", "section", "article",
        "header", "footer", "hr", "center", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "dd", "dt",
    }
)  # fmt: skip
_VOID_TAGS = frozenset(
    {
        "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "image", "img",
        "input", "keygen", "link", "meta", "param", "source", "track", "wbr",
    }
)  # fmt: skip
_MAX_STACK = 256
_ANCHOR_TEXT_CHARS = 1000

# The HTML tokenizer (see "The HTML body" below). Whitespace, names and
# unquoted values as the HTML5 tokenizer reads them.
_TAG_NAME_RE = re.compile(r"[^\t\n\f\r />]*")
# "<" then what starts markup; any other "<" is text.
_MARKUP_RE = re.compile(r"<[A-Za-z/!?]")
# A tag in the usual shape (names, then values quoted or plain, blanks
# between), read in one step; anything else takes the full state machine.
_SIMPLE_TAG_RE = re.compile(
    r"([A-Za-z][^\t\n\f\r />]*)"
    r"((?:[\t\n\f\r ]+[^\t\n\f\r /=>\"'<]+"
    r"(?:[\t\n\f\r ]*=[\t\n\f\r ]*(?:\"[^\"]*\"|'[^']*'|[^\t\n\f\r >\"'][^\t\n\f\r >]*))?)*+)"
    r"[\t\n\f\r ]*+(/?)>"
)
_SIMPLE_ATTR_RE = re.compile(
    r"([^\t\n\f\r /=>\"'<]+)"
    r"(?:[\t\n\f\r ]*=[\t\n\f\r ]*(?:\"([^\"]*)\"|'([^']*)'|([^\t\n\f\r >\"'][^\t\n\f\r >]*)))?"
)
_ATTR_NAME_RE = re.compile(r"[^\t\n\f\r /=>]*")
_SPACES_RE = re.compile(r"[\t\n\f\r ]*")
_UNQUOTED_RE = re.compile(r"[^\t\n\f\r >]*")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
# The attributes these checks read. As in a browser, the first of two with
# the same name wins (a second href never replaces where a link goes).
_WANTED_ATTRS = frozenset({"href", "xlink:href", "src", "alt", "style", "hidden", "type"})
# Elements whose content is text, not markup, up to their own end tag
# ("</style" then a blank, "/" or ">"): never shown, or shown as written.
_RAW_HIDDEN = frozenset({"script", "style", "title", "iframe", "noembed", "noframes"})
_RAW_SHOWN = frozenset({"textarea", "xmp"})
_RAW_END_RES = {
    name: re.compile(rf"</{name}[\t\n\f\r />]", re.IGNORECASE) for name in sorted(_RAW_HIDDEN | _RAW_SHOWN)
}
# Where a browser closes an element before its end tag (HTML5 tree
# construction, the parts that decide what is shown): a hidden <p> ends at
# the next <div>, a hidden <li> at the next <li>, a hidden cell at the next
# cell, and text written straight inside <table> is moved out in front of it.
_SPECIAL_TAGS = frozenset(
    """
    address applet area article aside base basefont bgsound blockquote body br button caption
    center col colgroup dd details dir div dl dt embed fieldset figcaption figure footer form
    frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html iframe img input keygen li link
    listing main marquee menu meta nav noembed noframes noscript object ol p param plaintext pre
    script search section select source style summary table tbody td template textarea tfoot th
    thead title tr track ul wbr xmp
    """.split()
)
_SCOPE_TAGS = frozenset({"applet", "caption", "html", "table", "td", "th", "marquee", "object", "template"})
_CLOSES_P = frozenset(
    """
    address article aside blockquote center details dialog dir div dl fieldset figcaption figure
    footer form h1 h2 h3 h4 h5 h6 header hgroup hr main menu nav ol p pre listing search section
    summary table ul li dd dt plaintext xmp
    """.split()
)
_HEADINGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
_TABLE_CONTEXT = frozenset({"table", "tbody", "thead", "tfoot", "tr"})
_ROW_PARTS = frozenset({"td", "th", "tr", "tbody", "thead", "tfoot", "caption", "colgroup", "table"})
# Start tags a table keeps; any other written straight inside one is moved
# out in front of it ("foster parenting").
_TABLE_PARTS = frozenset(
    {"caption", "colgroup", "col", "tbody", "thead", "tfoot", "tr", "td", "th", "table", "style", "script",
     "template", "form", "input"}
)  # fmt: skip
# HTML start tags that end an <svg> or <math> block they appear in.
_BREAKOUT_TAGS = frozenset(
    """
    b big blockquote body br center code dd div dl dt em embed h1 h2 h3 h4 h5 h6 head hr i img li
    listing menu meta nobr ol p pre ruby s small span strong strike sub sup table tt u ul var
    """.split()
)
# Start tags before which a browser may close something.
_IMPLIES_ENDS = (
    _CLOSES_P | _HEADINGS | _BREAKOUT_TAGS | _ROW_PARTS | {"li", "dd", "dt", "a", "button", "option", "optgroup"}
)
# Groups of open elements the tree rules ask about ("is there a <p> open
# below the nearest table cell?"), kept as index stacks so each question
# costs one lookup however deep the document nests.
_GROUPS: Mapping[str, frozenset[str]] = {
    "#scope": _SCOPE_TAGS,
    "#button_scope": _SCOPE_TAGS | {"button"},
    "#list_scope": _SCOPE_TAGS | {"ol", "ul"},
    "#table_scope": frozenset({"html", "table", "template"}),
    "#special": _SPECIAL_TAGS,
    "#special_li": _SPECIAL_TAGS - {"address", "div", "p", "li"},
    "#special_dd": _SPECIAL_TAGS - {"address", "div", "p", "dd", "dt"},
    "#markers": frozenset({"applet", "caption", "html", "marquee", "object", "td", "th", "template"}),
    "#rows": frozenset({"tr", "tbody", "thead", "tfoot", "table"}),
    "#sections": frozenset({"tbody", "thead", "tfoot", "table"}),
}
# End tags a browser honours only while their element is "in scope" (HTML5
# "in body" and table rules): an end tag that would reach past a table
# cell, a table or another scope boundary is ignored, so "</div>" inside a
# cell never closes a hidden <div> around the table.
_SCOPED_END_TAGS = frozenset(
    """
    address article aside blockquote button center details dialog dir div dl fieldset figcaption
    figure footer form header hgroup listing main menu nav ol pre search section summary ul dd dt
    applet marquee object
    """.split()
)
_TABLE_END_TAGS = frozenset({"table", "tbody", "thead", "tfoot", "tr", "td", "th", "caption", "colgroup"})
# Formatting elements ("</a>", "</b>"): ignored when not in scope; when
# their element is no longer open at all, "</a>" still ends the link.
_FORMATTING_TAGS = frozenset({"a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u"})
# Inline styles that may hide text without this module knowing for sure:
# the text is kept, but after the text that is surely shown (_Look.doubt).
_DOUBT_ZERO_SIZES = ("max-height", "height", "max-width", "width", "line-height")
_TAG_GROUPS: Mapping[str, tuple[str, ...]] = {
    tag: tuple(group for group, members in _GROUPS.items() if tag in members)
    for tag in {member for members in _GROUPS.values() for member in members}
}
# Inline CSS, read the way a browser reads it: strings and comments are
# whole pieces, so a ";" inside a string never ends a declaration.
_CSS_PIECE_RE = re.compile(
    r'"(?:[^"\\]|\\.)*+(?:"|\Z)'
    r"|'(?:[^'\\]|\\.)*+(?:'|\Z)"
    r"|/\*(?:[^*]|\*(?!/))*+(?:\*/|\Z)"
    r"|[^;\"'/]++"
    r"|[;/]",
    re.DOTALL,
)
_CSS_ESCAPE_RE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})[ \t\n\f\r]?|(.))", re.DOTALL)
_IMPORTANT_RE = re.compile(r"!\s*important$")
_CSS_IMPORTANT_RE = re.compile(r"!\s*important")
_STYLE_OPEN_RE = re.compile(r"<style[\t\n\f\r />]", re.IGNORECASE)
# A stylesheet this module cannot read can override anything inline.
_LINKED_CSS_RE = re.compile(r"<link[\t\n\f\r /][^<>]{0,1000}stylesheet|@import", re.IGNORECASE)
# CSS lengths. Every quantifier is possessive and every value is length-
# checked before matching: a value such as "0000...0001" (tens of KB) once
# made a backtracking pattern quadratic, which let one mail stall the sweeper.
_CSS_UNITS = r"(?:px|pt|pc|em|rem|ex|ch|%|vw|vh|vmin|vmax|cm|mm|in|q)"
_CSS_ZERO_RE = re.compile(r"[+-]?+(?:0++(?:\.0*+)?+|\.0++)" + _CSS_UNITS + r"?+")
_CSS_NUMBER_RE = re.compile(r"[+-]?+(?:[0-9]++(?:\.[0-9]*+)?+|\.[0-9]++)")
_FONT_SIZE_TOKEN_RE = re.compile(
    r"(?:[+-]?+(?:[0-9]++(?:\.[0-9]*+)?+|\.[0-9]++)" + _CSS_UNITS + r"|0"
    r"|xx-small|x-small|small|medium|large|x-large|xx-large|xxx-large|smaller|larger)(?:/\S*+)?+"
)
# Longer CSS values are not read as lengths at all (a real one is short).
_CSS_VALUE_CHARS = 40
_CSS_KEEPS_PARENT = frozenset({"inherit", "unset", "revert", "revert-layer"})
# A From the parser could not read as one address keeps this much of its
# text as the name, so the addresses and brands it shows are still checked.
UNREADABLE_FROM_CHARS = 160


# -- The answer's shape (scaffold A7: S1 codes against it) ----------------------------


class MailSender(TypedDict):
    """The From header: display name, bare lower-case address and its domain.
    The display name never counts as the address; for a From a mail app may
    read two ways the address and domain are "" and the name holds the
    header's text (up to UNREADABLE_FROM_CHARS), so S1 and the checks never
    take one reading of it for the sender."""

    name: str
    address: str
    domain: str


class MailAuth(TypedDict):
    """The receiving provider's verdict on the sender (``AuthVerdict`` as JSON)."""

    source: str
    spf: str
    dkim: str
    dmarc: str
    compauth: str
    dmarc_policy: str
    spf_domain: str
    dkim_domains: list[str]
    header_from_domain: str


class MailLink(TypedDict):
    """One link of the body (``LinkFact`` as JSON)."""

    href: str
    text: str
    host: str
    scheme: str
    code: str
    wrapped: str


class MailAttachment(TypedDict):
    """One attachment's facts; ``ref`` is the provider's part or attachment
    id. ``filename`` has each run of hidden or bidi characters replaced by
    U+FFFD and keeps its real ending when cut; ``size`` is 0 when the
    provider gave none."""

    ref: str
    filename: str
    mime_type: str
    size: int
    is_inline: bool


# The whole answer of get_message_security (S2 4.4, plus scaffold A7's four
# keys for S1). Functional syntax because "from" is a Python keyword. A full
# answer carries every key ("gone" is False there); a message that is gone
# answers only {"id": ..., "gone": True}, which is why every key is optional
# here.
MailSecurityFacts = TypedDict(
    "MailSecurityFacts",
    {
        "id": str,
        "gone": bool,
        "provider": str,  # "gmail" | "outlook"
        "thread_id": Optional[str],
        "received": Optional[str],  # ISO 8601, UTC
        "folder": str,
        "labels": list[str],
        "subject": str,
        "from": MailSender,
        "sender": str,
        "reply_to": list[str],  # bare addresses, at most MAX_REPLY_TO
        "return_path_domain": str,
        "message_id_domain": str,
        "list_unsubscribe": bool,
        "auth": MailAuth,
        "links": list[MailLink],
        "links_total": int,
        "has_form": bool,
        "remote_images": int,
        "attachments": list[MailAttachment],
        "text": str,
        "hidden_chars": int,
        # Scaffold A7, for S1's outbound check:
        "to": list[str],  # bare addresses, at most MAX_RECIPIENTS
        "cc": list[str],  # bare addresses, at most MAX_RECIPIENTS
        "sent_by_me": bool,  # Gmail: SENT label; Outlook: the Sent Items folder
        "mailbox": str,  # the account's own address when known, else ""
    },
    total=False,
)


@dataclass(frozen=True)
class AuthVerdict:
    """The receiving provider's verdict on the sender, from its own topmost header."""

    source: str  # "authentication-results" | "received-spf" | "internal" | "none"
    spf: str = "unknown"  # pass | fail | softfail | neutral | none | temperror | permerror | unknown
    dkim: str = "unknown"  # pass if any signature passed, else the first result
    dmarc: str = "unknown"
    compauth: str = "unknown"  # Microsoft only
    dmarc_policy: str = "unknown"  # reject | quarantine | none | unknown
    spf_domain: str = ""  # smtp.mailfrom domain
    dkim_domains: tuple[str, ...] = ()  # header.d of passing signatures, at most 5
    header_from_domain: str = ""

    def as_dict(self) -> MailAuth:
        return {
            "source": self.source,
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "compauth": self.compauth,
            "dmarc_policy": self.dmarc_policy,
            "spf_domain": self.spf_domain,
            "dkim_domains": list(self.dkim_domains),
            "header_from_domain": self.header_from_domain,
        }


@dataclass(frozen=True)
class LinkFact:
    """One link of a message body. ``code`` is set before BaseConnector's
    PromptGuard sees the answer, so a script link survives as a code."""

    href: str  # unwrapped, at most 2048 chars; "" when code is set
    text: str  # visible text, at most 200 chars
    host: str  # lower-case ASCII (IDNA) host, "" when none
    scheme: str  # "https" | "http" | "mailto" | "tel" | "javascript" | "data" | "vbscript" | "file" | "other"
    code: str = ""  # "script_link" | "data_link" | "file_link" | ""
    wrapped: str = ""  # "safelinks" | "google_redirect" | ""

    def as_dict(self) -> MailLink:
        return {
            "href": self.href,
            "text": self.text,
            "host": self.host,
            "scheme": self.scheme,
            "code": self.code,
            "wrapped": self.wrapped,
        }


# -- Small cleaners -------------------------------------------------------------------


def _unfold(value: str) -> str:
    """A header value with its folding removed (CRLF or LF, then blanks)."""
    return re.sub(r"\r?\n[ \t]*|\r[ \t]*", " ", value)


def _drop_hidden(text: str) -> str:
    return _HIDDEN_RE.sub("", text)


def _clean_line(value: Any, limit: int) -> str:
    """One printable line: hidden characters dropped (so a word split by a
    zero-width space reads whole), other non-printables made blanks,
    whitespace folded, capped with an ellipsis."""
    if not isinstance(value, str) or not value:
        return ""
    text = _drop_hidden(value[: limit * 8 + 64])
    text = "".join(c if c.isprintable() else " " for c in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "\u2026"
    return text


def _clean_text(value: str, limit: int) -> str:
    """Printable text with its line breaks, hidden characters dropped, capped."""
    if not value:
        return ""
    text = _drop_hidden(value[:MAX_HTML_CHARS])
    lines: list[str] = []
    size = 0
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line.isprintable():
            line = "".join(c if c.isprintable() else " " for c in line)
        kept = " ".join(line.split())
        lines.append(kept)
        size += len(kept) + 1
        if size > limit * 2:
            break
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "\u2026"
    return text


def _decode_words(value: str) -> str:
    """RFC 2047 encoded words decoded ("=?utf-8?B?...?="); the value as it
    is when it has none or they cannot be decoded. Graph returns header
    values raw, Gmail mostly decoded: both read the same here."""
    if "=?" not in value:
        return value
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # hostile or broken encoding: keep the raw text
        return value


def _ascii_host(host: Any) -> str:
    """*host* lower-cased with every non-ASCII label in its A-label
    (punycode) form; "" when it is empty or cannot be written that way."""
    if not isinstance(host, str) or len(host) > 1024:
        return ""
    text = unicodedata.normalize("NFKC", host.translate(_DOTS)).strip().strip(".").lower()
    if not text or len(text) > 1024:
        return ""
    labels: list[str] = []
    for label in text.split("."):
        if not label:
            return ""
        if label.isascii():
            labels.append(label)
            continue
        if len(label) > MAX_LABEL_CHARS:
            # No DNS label is this long, so no browser reaches it; the IDNA
            # and punycode encoders are quadratic in the label's length, and
            # a mail with hundreds of such links once took minutes here.
            return ""
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            try:
                labels.append("xn--" + label.encode("punycode").decode("ascii"))
            except UnicodeError:
                return ""
    out = ".".join(labels)
    return out if len(out) <= 253 else ""


def _address(value: Any) -> str:
    """A bare address, lower-cased, its domain in A-label form; "" when it
    is not one plain address."""
    if not isinstance(value, str):
        return ""
    text = value.strip().strip("<>").strip()
    if not text or len(text) > ADDRESS_CHARS * 4 or text.count("@") != 1:
        return ""
    local, _, domain = text.rpartition("@")
    if not local or any(c.isspace() or not c.isprintable() for c in local) or len(local) > 64:
        return ""
    ascii_domain = _ascii_host(domain)
    if not ascii_domain or "." not in ascii_domain or not re.fullmatch(r"[a-z0-9.\-\[\]:]+", ascii_domain):
        return ""
    out = f"{_drop_hidden(local).lower()}@{ascii_domain}"
    return out if len(out) <= ADDRESS_CHARS else ""


def _domain_of(address: str) -> str:
    return address.rpartition("@")[2] if "@" in address else ""


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.isdigit() and len(value) < 16:
            return int(value)
        return None
    return value if value >= 0 else None


# -- Headers -----------------------------------------------------------------------------


def header_values(headers: Sequence[Mapping[str, Any]], name: str, *, limit: int = 20) -> list[str]:
    """Every value of header *name* (any case), top to bottom, each capped; malformed entries skipped.
    Exists because mime.header_map keeps only the first value (mime.py:39-48)."""
    if not isinstance(headers, (list, tuple)) or not isinstance(name, str):
        return []
    wanted = name.strip().lower()
    found: list[str] = []
    for item in headers[:MAX_HEADERS_READ]:
        if not isinstance(item, Mapping):
            continue
        key, value = item.get("name"), item.get("value")
        if not isinstance(key, str) or not isinstance(value, str) or key.strip().lower() != wanted:
            continue
        found.append(_unfold(value[: MAX_HEADER_CHARS * 2])[:MAX_HEADER_CHARS])
        if len(found) >= limit:
            break
    return found


def _first_header(headers: Sequence[Mapping[str, Any]], name: str) -> str:
    values = header_values(headers, name, limit=1)
    return values[0] if values else ""


def _split_resinfo(value: str) -> list[tuple[str, str]]:
    """(text without comments, the comments' text) for each ';'-separated
    part, respecting comments (nested) and quoted strings; bounded."""
    parts: list[tuple[str, str]] = []
    text: list[str] = []
    comment: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    for ch in value[:MAX_HEADER_CHARS]:
        if escaped:
            (comment if depth else text).append(ch)
            escaped = False
            continue
        if ch == "\\" and (quoted or depth):
            escaped = True
            continue
        if quoted:
            text.append(ch)
            if ch == '"':
                quoted = False
            continue
        if depth:
            if ch == "(":
                depth = min(depth + 1, 32)
            elif ch == ")":
                depth -= 1
                if not depth:
                    comment.append(" ")
                    continue
            comment.append(ch)
            continue
        if ch == "(":
            depth = 1
            continue
        if ch == '"':
            quoted = True
            text.append(ch)
            continue
        if ch == ";":
            parts.append(("".join(text), "".join(comment)))
            text, comment = [], []
            if len(parts) > MAX_RESINFO:
                return parts
            continue
        text.append(ch)
    parts.append(("".join(text), "".join(comment)))
    return parts


def _result_word(value: str) -> str:
    word = value.strip().strip('"').lower()
    word = _RESULT_ALIASES.get(word, word)
    return word if word in _RESULT_WORDS else "unknown"


@dataclass(frozen=True)
class _ResInfo:
    method: str
    result: str
    props: dict[str, str]
    comment: str


def _resinfo(text: str, comment: str) -> Optional[_ResInfo]:
    """One "method=result prop=value ..." part, or None."""
    cleaned = re.sub(r'"[^"]*"', '""', text)
    cleaned = re.sub(r"\s*=\s*", "=", cleaned).strip()
    tokens = cleaned.split()
    if not tokens or "=" not in tokens[0]:
        return None
    method, _, result = tokens[0].partition("=")
    method = method.split("/", 1)[0].strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_\-]{0,30}", method):
        return None
    props: dict[str, str] = {}
    for token in tokens[1:24]:
        key, sep, val = token.partition("=")
        if sep and key and val and len(props) < 16:
            props.setdefault(key.strip().lower(), val.strip().strip('"'))
    return _ResInfo(method, _result_word(result), props, comment)


@dataclass(frozen=True)
class _Parsed:
    authserv_id: str
    infos: tuple[_ResInfo, ...]


def _parse_ar(value: str) -> _Parsed:
    """One Authentication-Results value (RFC 8601). Exchange writes no
    authserv-id: a first part that is already "method=result" is a result."""
    if not isinstance(value, str):
        return _Parsed("", ())
    parts = _split_resinfo(_unfold(value))
    if not parts:
        return _Parsed("", ())
    authserv_id = ""
    infos: list[_ResInfo] = []
    first_text, first_comment = parts[0]
    first_tokens = re.sub(r"\s*=\s*", "=", first_text).split()
    if first_tokens and "=" not in first_tokens[0]:
        authserv_id = first_tokens[0].strip().lower()
        rest = " ".join(first_tokens[1:])
        if "=" in rest:  # a result written without its ';' (lenient)
            info = _resinfo(rest, first_comment)
            if info is not None:
                infos.append(info)
    else:
        info = _resinfo(first_text, first_comment)
        if info is not None:
            infos.append(info)
    for text, comment in parts[1 : MAX_RESINFO + 1]:
        info = _resinfo(text, comment)
        if info is not None:
            infos.append(info)
    return _Parsed(authserv_id, tuple(infos[:MAX_RESINFO]))


def _prop_domain(value: str) -> str:
    """The domain of a property value: "user@x.com", "@x.com" or "x.com"."""
    if not value or value.lower() == "none":
        return ""
    text = value.strip().strip("<>").rpartition("@")[2]
    host = _ascii_host(text)
    return host if host and "." in host else ""


def _dmarc_policy(info: _ResInfo) -> str:
    """Gmail writes the policy in a comment "(p=REJECT sp=REJECT dis=NONE)";
    Exchange writes what it did as action=...; RFC 7489 receivers may use
    policy.dmarc=... ."""
    match = re.search(r"(?:^|\s)p=([a-z.]+)", info.comment.lower())
    candidates = [
        match.group(1) if match else "",
        info.props.get("policy.dmarc", ""),
        info.props.get("policy.p", ""),
        info.props.get("action", ""),
    ]
    for candidate in candidates:
        word = _POLICY_WORDS.get(candidate.strip().lower())
        if word:
            return word
    return "unknown"


def _summary(parsed: _Parsed) -> tuple[dict[str, str], dict[str, str], tuple[str, ...]]:
    """({method: result}, {property: value}, passing DKIM domains)."""
    results: dict[str, str] = {}
    props: dict[str, str] = {}
    dkim_pass: list[str] = []
    first_dkim_domain = ""
    for info in parsed.infos:
        if info.method == "dkim":
            domain = _prop_domain(info.props.get("header.d", "")) or _prop_domain(info.props.get("header.i", ""))
            if info.result == "pass":
                results["dkim"] = "pass"
                if domain and domain not in dkim_pass and len(dkim_pass) < MAX_DKIM_DOMAINS:
                    dkim_pass.append(domain)
            else:
                results.setdefault("dkim", info.result)
                first_dkim_domain = first_dkim_domain or domain
            continue
        if info.method in results:
            continue
        results[info.method] = info.result
        if info.method == "spf":
            domain = _prop_domain(info.props.get("smtp.mailfrom", "")) or _prop_domain(
                info.props.get("smtp.helo", "")
            )
            if domain:
                props["smtp.mailfrom"] = domain
        elif info.method == "dmarc":
            domain = _prop_domain(info.props.get("header.from", ""))
            if domain:
                props["header.from"] = domain
            props["dmarc.p"] = _dmarc_policy(info)
    if dkim_pass or first_dkim_domain:
        props["header.d"] = dkim_pass[0] if dkim_pass else first_dkim_domain
    return results, props, tuple(dkim_pass)


def parse_authentication_results(value: str) -> tuple[str, dict[str, str], dict[str, str]]:
    """(authserv-id, {method: result}, {"smtp.mailfrom", "header.d", "header.from", "dmarc.p"})
    from one RFC 8601 value. At most 20 resinfo parts, comments dropped; never raises.
    The property values are domains (the mailfrom's, the first passing DKIM
    signature's, the From's) and the DMARC policy word."""
    try:
        parsed = _parse_ar(value)
        results, props, _ = _summary(parsed)
        return parsed.authserv_id, results, props
    except Exception:  # never raises on a hostile header
        return "", {}, {}


def _received_spf(value: str) -> tuple[str, str]:
    """(result, domain) of one Received-SPF value: "pass (google.com: domain
    of x@y.com designates ...) client-ip=...; envelope-from=x@y.com;"."""
    text = _unfold(value).strip()
    word = text.split(None, 1)[0] if text else ""
    result = _result_word(word.rstrip(";"))
    match = re.search(r"(?:envelope-from|smtp\.mailfrom)\s*=\s*\"?<?([^\s;\">]+)", text, re.IGNORECASE)
    domain = _prop_domain(match.group(1)) if match else ""
    if not domain:
        match = re.search(r"domain of\s+([^\s;()]+)", text, re.IGNORECASE)
        domain = _prop_domain(match.group(1)) if match else ""
    return result, domain


def _outlook_internal(headers: Sequence[Mapping[str, Any]]) -> bool:
    """Exchange marks mail from inside the organisation AuthAs: Internal and
    strips that header from mail arriving from outside, so it cannot be
    forged; internal mail read through Graph may also carry no internet
    headers at all."""
    if not isinstance(headers, (list, tuple)) or not headers:
        return True
    auth_as = _first_header(headers, "X-MS-Exchange-Organization-AuthAs").strip().lower()
    return auth_as == "internal"


def auth_verdict(headers: Sequence[Mapping[str, Any]], *, provider: str) -> AuthVerdict:
    """gmail: the topmost Authentication-Results whose authserv-id is in GMAIL_AUTHSERV_IDS;
    outlook: the topmost Authentication-Results (Exchange writes no authserv-id), and
    'X-MS-Exchange-Organization-AuthAs: Internal' (or no internet headers at all) reads as
    "internal". Lower copies are never read: a sender can forge them. Received-SPF
    (topmost) is the fallback, then "none"."""
    try:
        return _auth_verdict(headers, provider)
    except Exception:  # never raises on a hostile header list
        return AuthVerdict(source="none")


def _auth_verdict(headers: Sequence[Mapping[str, Any]], provider: str) -> AuthVerdict:
    headers = headers if isinstance(headers, (list, tuple)) else []
    _, from_address, _ = _sender_of(header_values(headers, "From", limit=2))
    from_domain = _domain_of(from_address)
    chosen: Optional[_Parsed] = None
    values = header_values(headers, "Authentication-Results", limit=20)
    if provider == "outlook":
        if values:
            chosen = _parse_ar(values[0])
    else:
        for value in values:
            parsed = _parse_ar(value)
            if parsed.authserv_id in GMAIL_AUTHSERV_IDS:
                chosen = parsed
                break
    internal = provider == "outlook" and _outlook_internal(headers)
    if chosen is not None and chosen.infos:
        results, props, dkim_pass = _summary(chosen)
        return AuthVerdict(
            source="internal" if internal else "authentication-results",
            spf=results.get("spf", "unknown"),
            dkim=results.get("dkim", "unknown"),
            dmarc=results.get("dmarc", "unknown"),
            compauth=results.get("compauth", "unknown"),
            dmarc_policy=props.get("dmarc.p", "unknown"),
            spf_domain=props.get("smtp.mailfrom", ""),
            dkim_domains=dkim_pass,
            header_from_domain=props.get("header.from", "") or from_domain,
        )
    if internal:
        return AuthVerdict(source="internal", header_from_domain=from_domain)
    spf_values = header_values(headers, "Received-SPF", limit=1)
    if spf_values:
        result, domain = _received_spf(spf_values[0])
        return AuthVerdict(source="received-spf", spf=result, spf_domain=domain, header_from_domain=from_domain)
    return AuthVerdict(source="none", header_from_domain=from_domain)


def address_parts(value: Any) -> tuple[str, str]:
    """(display name, lower-cased address) of one header value; the display name never
    counts as the address (same rule as triggers.facts.sender_address, facts.py:153).
    Encoded words in the name are decoded after the address is found, so an
    encoded "<" in a name can never move the address."""
    if not isinstance(value, str) or not value.strip():
        return "", ""
    text = _unfold(value[: MAX_HEADER_CHARS * 2])[:MAX_HEADER_CHARS]
    try:
        name, raw_address = parseaddr(text)
    except Exception:  # the stdlib parser on a hostile value
        return "", ""
    address = _address(raw_address)
    if not address:
        return "", ""
    return _clean_line(_decode_words(name), NAME_CHARS), address


def _angle_address(value: str) -> Optional[tuple[str, str]]:
    """(name, address) of a From with exactly one <address> outside quotes
    and comments and nothing but blanks and comments after it
    ("info@shop.com <info@shop.com>", "Doe, John <j@x.example>"), which every
    mail app shows with that address; None for anything else. The strict
    parser refuses these, and refusing them would make ordinary mail read as
    unreadable."""
    text = _unfold(value[: MAX_HEADER_CHARS * 2])[:MAX_HEADER_CHARS]
    spans: list[tuple[int, int]] = []
    quoted = escaped = False
    depth = 0
    opened = -1
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and (quoted or depth):
            escaped = True
        elif quoted:
            quoted = char != '"'
        elif depth:
            depth += 1 if char == "(" else -1 if char == ")" else 0
        elif opened >= 0:
            if char == ">":
                spans.append((opened, index))
                opened = -1
        elif char == '"':
            quoted = True
        elif char == "(":
            depth = 1
        elif char == "<":
            opened = index
        elif spans and not char.isspace():
            return None  # text after the address: read two ways
    if len(spans) != 1 or opened >= 0:
        return None
    start, stop = spans[0]
    address = _address(text[start + 1 : stop])
    if not address:
        return None
    return _clean_line(_decode_words(text[:start].strip().strip('"')), NAME_CHARS), address


def _sender_of(values: Sequence[str]) -> tuple[str, str, str]:
    """(display name, address, the header as written) of the From header(s).

    A From that mail apps may read two ways (two From headers naming two
    addresses, two addresses, text after the address) has no address here,
    because which one the person sees depends on the app: its text, up to
    UNREADABLE_FROM_CHARS, is kept as the name, so every address and brand
    it shows is still checked, and mail_checks reports it (sender_unreadable)
    instead of skipping the sender checks."""
    if not values:
        return "", "", ""
    parsed: list[tuple[str, str]] = []
    for value in values:
        name, address = address_parts(value)
        if not address:
            recovered = _angle_address(value)
            if recovered is not None:
                name, address = recovered
        parsed.append((name, address))
    raw = ", ".join(_decode_words(_unfold(value[: MAX_HEADER_CHARS * 2])[:MAX_HEADER_CHARS]) for value in values)
    if all(address and address == parsed[0][1] for _, address in parsed):
        return parsed[0][0], parsed[0][1], raw
    return _clean_line(raw, UNREADABLE_FROM_CHARS), "", raw


def _address_list(values: Sequence[str], limit: int) -> list[str]:
    found: dict[str, None] = {}
    for value in values:
        try:
            pairs = getaddresses([_unfold(value)[:MAX_HEADER_CHARS]])
        except Exception:  # hostile value: nothing from it
            continue
        for _name, raw in pairs:
            address = _address(raw)
            if address:
                found.setdefault(address, None)
            if len(found) >= limit:
                return list(found)
    return list(found)


def _message_id_domain(value: str) -> str:
    match = re.search(r"@([^>\s]{1,253})>?", value or "")
    return _prop_domain(match.group(1)) if match else ""


# -- Links and the visible text ------------------------------------------------------------


def _query_param(query: str, *names: str) -> str:
    """The first non-empty value of the first of *names* the query carries,
    decoded, read from at most MAX_QUERY_FIELDS fields. Never refuses a long
    query (urllib's parse_qs raises past its field limit, which once left a
    hand-made Safe Links URL with many fields wrapped, so the link checks saw
    only Microsoft's host)."""
    found: dict[str, str] = {}
    for piece in query.split("&", MAX_QUERY_FIELDS)[:MAX_QUERY_FIELDS]:
        key, sep, value = piece.partition("=")
        if not sep or not value:
            continue
        try:
            key = unquote_plus(key)
        except ValueError:  # an encoding the decoder refuses names nothing
            continue
        if key in names and key not in found:
            try:
                found[key] = unquote_plus(value)
            except ValueError:
                continue
    for name in names:
        if found.get(name):
            return found[name]
    return ""


def unwrap(href: str) -> tuple[str, str]:
    """(real URL, wrapper): one level of Outlook Safe Links (*.safelinks.protection.outlook.com
    ?url=) or google.com/url?q=; anything else unchanged."""
    if not isinstance(href, str) or not href:
        return ("", "")
    try:
        parts = urlsplit(href)
        host = (parts.hostname or "").lower()
    except ValueError:
        return (href, "")
    if parts.scheme.lower() not in ("http", "https"):
        return (href, "")
    target, wrapper = "", ""
    if host.endswith(_SAFELINKS_SUFFIX):
        target, wrapper = _query_param(parts.query, "url"), "safelinks"
    elif host in _GOOGLE_REDIRECT_HOSTS and parts.path == "/url":
        target, wrapper = _query_param(parts.query, "q", "url"), "google_redirect"
    if target and _SCHEME_RE.match(target.strip()):
        return (target.strip()[: HREF_CHARS * 2], wrapper)
    return (href, "")


def _whatwg_clean(href: str) -> str:
    """The href as a browser reads it: leading and trailing controls and
    spaces gone, tabs and line breaks inside removed ("java\\nscript:")."""
    text = href.strip("".join(chr(c) for c in range(0x21)))
    return re.sub(r"[\t\n\r]", "", text)[: HREF_CHARS * 2]


def _scheme_of(href: str) -> str:
    match = _SCHEME_RE.match(href)
    return match.group(1).lower() if match else ""


def _host_of(href: str) -> str:
    """The host a browser opens for *href*: percent-encoded letters decoded
    ("%65vil.example" is evil.example), "" when the decoded host holds a
    character a browser refuses there."""
    try:
        host = urlsplit(href).hostname or ""
    except ValueError:
        return ""
    if "%" in host:
        host = unquote(host)
        if any(char in _FORBIDDEN_HOST_CHARS for char in host):
            return ""
    return host


def text_host(text: Any) -> str:
    """The ASCII host a link's shown text names when the whole text is a URL
    or a domain ("paypal.com/signin", "https://www.paypal.com"), else "".
    An email address or a file name ("invoice.pdf") names no site."""
    if not isinstance(text, str):
        return ""
    shown = unicodedata.normalize("NFKC", _drop_hidden(text)).translate(_DOTS).strip().lower()
    shown = shown.strip(_TEXT_EDGE).rstrip(".,;:!?").strip(_TEXT_EDGE)
    if not shown or len(shown) > 300 or any(c.isspace() for c in shown):
        return ""
    if "://" in shown:
        scheme, _, rest = shown.partition("://")
        if scheme not in ("http", "https", "hxxp", "hxxps"):
            return ""
        host = _host_of("http://" + rest.replace("\\", "/"))
    else:
        if "@" in shown:
            return ""
        host = re.split(r"[/?#:]", shown, maxsplit=1)[0]
    host = host.strip(".")
    if not host or not _DOMAIN_RE.fullmatch(host):
        return ""
    if host.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
        return ""
    return _ascii_host(host)


def _resolved(href: str, base: str) -> str:
    """A relative link read against the mail's <base href> (http or https)
    the way a browser resolves it; unchanged without one."""
    if not base or _scheme_of(href):
        return href
    root = _whatwg_clean(base).replace("\\", "/")
    if _scheme_of(root) not in ("http", "https"):
        return href
    try:
        return urljoin(root, href)
    except ValueError:  # a base a URL parser refuses: the link stays relative
        return href


def _special_url(href: str) -> str:
    """An http(s) URL written the way a browser reads it: whatever run of
    slashes or backslashes follows the scheme (none, one, three) becomes
    "//", and every other backslash is a slash. Without this,
    "https:///evil.example" or "http:evil.example" had no host here, so the
    link skipped every check while a mail app still opened evil.example."""
    match = _SPECIAL_SLASHES_RE.match(href)
    if match:
        href = f"{match.group(1).lower()}://{href[match.end():]}"
    return href.replace("\\", "/")


def _link_fact(raw_href: str, text: str, base: str = "") -> Optional[LinkFact]:
    href = _whatwg_clean(raw_href)
    if not href or href.startswith("#"):
        return None
    leading = _LEADING_SLASHES_RE.match(href)
    if leading:  # "//host", and "\\host" or "/\host", read the way a browser reads them
        href = "https://" + href[leading.end() :]
    href = _resolved(href, base)
    scheme = _scheme_of(href)
    if scheme in ("http", "https"):
        href = _special_url(href)
    wrapped = ""
    if scheme in ("http", "https"):
        real, wrapped = unwrap(href)
        if wrapped:
            href = _whatwg_clean(real)
            scheme = _scheme_of(href)
            if scheme in ("http", "https"):
                href = _special_url(href)
    shown = _clean_line(text, LINK_TEXT_CHARS)
    if shown and _SCHEME_RE.match(shown):
        real_text, text_wrapper = unwrap(shown)
        if text_wrapper:
            shown = _clean_line(real_text, LINK_TEXT_CHARS)
    kind = scheme if scheme in LINK_SCHEMES else "other"
    code = _CODE_FOR_SCHEME.get(kind, "")
    if code:
        return LinkFact(href="", text=shown, host="", scheme=kind, code=code, wrapped=wrapped)
    host = _ascii_host(_host_of(href)) if kind in ("http", "https") else ""
    return LinkFact(href=href[:HREF_CHARS], text=shown, host=host, scheme=kind, wrapped=wrapped)


# -- The HTML body ----------------------------------------------------------------------------
#
# Why not html.parser.HTMLParser: it rescans to the end of the document for
# every construct that never closes ("<a" * 25_000 took 3 s), and it reads
# some markup differently from a browser. Each difference is a way for a mail
# to hide a link or its wording from these checks: a "<" inside a quoted
# attribute value, a comment ended by "--!>", a style block ended by
# "</style x>", a second href, an "<a .../>" that stays open, a hidden <p>
# that a browser closes at the next <div>. The tokenizer below follows the
# HTML5 tokenizer for tags, attributes, comments and raw-text elements, and
# the tree rules that decide what a browser shows. It is linear: every search
# starts where the previous one ended, and markup that runs to the end of the
# document ends the walk, as it ends what a browser shows.


@dataclass(frozen=True)
class _Look:
    """How an element's content renders, as far as inline styles tell."""

    gone: bool = False  # display:none, opacity:0, [hidden], <template>: nothing inside can show
    unseen: bool = False  # visibility:hidden; a descendant's visibility:visible shows again
    tiny: bool = False  # font-size:0; a descendant's own non-zero size shows again
    # Shown as far as this module can tell, but possibly hidden: inline
    # hiding a stylesheet may override (so it is not trusted), or hiding this
    # module does not model (max-height:0, a 1px font, mso-hide:all). Such
    # text is kept, after the text that is surely shown, so filler hidden
    # this way never crowds the real wording out of the excerpt.
    doubt: bool = False

    @property
    def shown(self) -> bool:
        return not (self.gone or self.unseen or self.tiny)


_SHOWN = _Look()


def _skip(pattern: re.Pattern[str], text: str, pos: int) -> int:
    match = pattern.match(text, pos)
    return match.end() if match else pos


def _css_pieces(text: str) -> list[str]:
    """CSS split into strings, comments, ";" and the rest (linear)."""
    return [match.group(0) for match in _CSS_PIECE_RE.finditer(text)]


def _add_declaration(found: dict[str, tuple[str, bool]], text: str) -> None:
    name, sep, value = text.partition(":")
    if not sep:
        return
    name = name.strip().lower()
    value = " ".join(value.lower().split())
    important = False
    match = _IMPORTANT_RE.search(value)
    if match:
        value, important = value[: match.start()].strip(), True
    if name == "font":  # the shorthand sets the size too ("font: 0/0 a")
        size = _font_shorthand_size(value)
        if size:
            _add_declaration(found, f"font-size:{size}{' !important' if important else ''}")
        return
    if not name or (name in found and found[name][1] and not important):
        return  # an earlier !important declaration wins
    found[name] = (value, important)


def _declarations(style: str) -> dict[str, tuple[str, bool]]:
    """{property: (value, !important)} of an inline style: comments dropped, the
    last declaration of a property wins unless an earlier one is !important."""
    found: dict[str, tuple[str, bool]] = {}
    current: list[str] = []
    for piece in _css_pieces(style):
        if piece == ";":
            _add_declaration(found, "".join(current))
            current = []
        elif not piece.startswith("/*"):
            current.append(piece)
    _add_declaration(found, "".join(current))
    return found


def _font_shorthand_size(value: str) -> str:
    if value in _CSS_KEEPS_PARENT:
        return value
    for token in value[: _CSS_VALUE_CHARS * 8].split()[:8]:
        if len(token) <= _CSS_VALUE_CHARS and _FONT_SIZE_TOKEN_RE.fullmatch(token):
            return token.split("/", 1)[0]
    return ""


def _css_zero(value: str) -> bool:
    """A CSS length that is zero ("0", "0px", "-0.00em"). A value too long to
    be a real length reads as not zero, so it never hides anything."""
    return len(value) <= _CSS_VALUE_CHARS and "0" in value and bool(_CSS_ZERO_RE.fullmatch(value))


def _css_tiny(value: str) -> bool:
    """A font size of at most one pixel (or point) that is not zero: text a
    person cannot read, so it is read after the text that is surely shown."""
    if len(value) > _CSS_VALUE_CHARS or not value.endswith(("px", "pt")):
        return False
    number = _CSS_NUMBER_RE.fullmatch(value[:-2])
    try:
        return number is not None and 0 < float(number.group(0)) <= 1
    except ValueError:
        return False


def _plain_css(text: str) -> str:
    """Stylesheet text with comments removed and escapes decoded, lower case."""
    kept = "".join(piece for piece in _css_pieces(text) if not piece.startswith("/*"))

    def one(match: re.Match[str]) -> str:
        if match.group(1):
            code = int(match.group(1), 16)
            return chr(code) if 0 < code <= 0x10FFFF else "\ufffd"
        return match.group(2)

    return _CSS_ESCAPE_RE.sub(one, kept).lower()


def _stylesheet_trust(html: str) -> tuple[bool, bool]:
    """(trust inline hiding, trust the hidden attribute).

    An inline display:none, visibility:hidden, opacity:0 or font-size:0
    hides text only while no stylesheet can override it with !important
    (responsive mail shows "desktop-hidden" blocks that way). The hidden
    attribute is only a browser default, which any author display rule
    overrides, so it hides only in a mail with no stylesheet at all. A linked
    or @imported stylesheet could say anything: neither is trusted then."""
    if _LINKED_CSS_RE.search(html):
        return False, False
    sheets: list[str] = []
    pos = 0
    while True:
        opened = _STYLE_OPEN_RE.search(html, pos)
        if opened is None:
            break
        closed = _RAW_END_RES["style"].search(html, opened.end())
        sheets.append(html[opened.end() : closed.start() if closed else len(html)])
        if closed is None:
            break
        pos = closed.end()
    css = _plain_css("".join(sheets)) if sheets else ""
    return _CSS_IMPORTANT_RE.search(css) is None, not css.strip()


class _Ahead:
    """str.find for one needle when the searches only move forward: each
    stretch of the text is searched once, so a thousand comments cost one
    pass rather than a thousand."""

    def __init__(self, text: str, needle: str) -> None:
        self.text = text
        self.needle = needle
        self.searched_from = -1
        self.found = -1

    def at_or_after(self, start: int) -> int:
        if 0 <= self.searched_from <= start and (self.found < 0 or self.found >= start):
            return self.found
        self.searched_from = start
        self.found = self.text.find(self.needle, start)
        return self.found


def _is_letter(char: str) -> bool:
    return len(char) == 1 and char.isascii() and char.isalpha()


def _scan_tag(html: str, pos: int) -> Optional[tuple[int, str, dict[str, str], bool]]:
    """(end, name, wanted attributes, self-closing) of the tag whose name
    starts at *pos*, read the way a browser reads it: a quoted value may hold
    "<" and ">", a "=" that starts an attribute name belongs to the name, the
    first of two attributes with one name wins. None when the document ends
    inside the tag: a browser then drops the tag and everything after it."""
    simple = _SIMPLE_TAG_RE.match(html, pos)
    if simple is not None:  # the usual shape, read in one step
        attrs: dict[str, str] = {}
        if simple.group(2):
            for found in _SIMPLE_ATTR_RE.finditer(simple.group(2)):
                key = found.group(1).translate(_ASCII_LOWER)
                if key in _WANTED_ATTRS and key not in attrs:
                    value = next((v for v in found.group(2, 3, 4) if v is not None), "")
                    attrs[key] = unescape(value) if "&" in value else value
        return simple.end(), simple.group(1).translate(_ASCII_LOWER), attrs, simple.group(3) == "/"
    size = len(html)
    stop = _skip(_TAG_NAME_RE, html, pos)
    name = html[pos:stop].translate(_ASCII_LOWER)
    attrs = {}
    i = stop
    while True:
        i = _skip(_SPACES_RE, html, i)
        if i >= size:
            return None
        char = html[i]
        if char == ">":
            return i + 1, name, attrs, False
        if char == "/":
            if html.startswith(">", i + 1):
                return i + 2, name, attrs, True
            i += 1
            continue
        stop = _skip(_ATTR_NAME_RE, html, i + 1)
        key = html[i:stop].translate(_ASCII_LOWER)
        i = _skip(_SPACES_RE, html, stop)
        value = ""
        if html.startswith("=", i):
            i = _skip(_SPACES_RE, html, i + 1)
            if i >= size:
                return None
            quote = html[i]
            if quote in "\"'":
                close = html.find(quote, i + 1)
                if close < 0:
                    return None
                value, i = html[i + 1 : close], close + 1
            elif quote != ">":
                stop = _skip(_UNQUOTED_RE, html, i)
                value, i = html[i:stop], stop
        if key in _WANTED_ATTRS and key not in attrs:
            attrs[key] = unescape(value) if "&" in value else value


def _comment_end(html: str, start: int, dashes: _Ahead, bangs: _Ahead) -> int:
    """Where the comment opened at *start* ends, the HTML5 way: "<!-->",
    "<!--->", "-->" and "--!>" all close one, and an unclosed one runs to the
    end. An Outlook conditional block ("<!--[if mso]>...<![endif]-->") is
    shown by Outlook, so only its opening is skipped and what is inside is
    read as markup."""
    if html[start + 4 : start + 7].lower() == "[if":
        close = html.find("]>", start + 7, start + 300)
        if close >= 0:
            return close + 2
    ends: list[int] = []
    found = dashes.at_or_after(start + 2)
    if found >= 0:
        ends.append(found + 3)
    found = bangs.at_or_after(start + 4)
    if found >= 0:
        ends.append(found + 4)
    return min(ends) if ends else len(html)


def _tokenize(html: str, sink: _MailHTML) -> None:
    """Feeds *html* to *sink* as start tags, end tags and text (entities
    decoded), comments and declarations dropped."""
    size = len(html)
    dashes, bangs = _Ahead(html, "-->"), _Ahead(html, "--!>")
    text_from = i = 0
    while True:
        markup = _MARKUP_RE.search(html, i)
        if markup is None:
            break
        lt = markup.start()
        nxt, after = html[lt + 1 : lt + 2], html[lt + 2 : lt + 3]
        if nxt == "/" and not after:
            break  # "</" at the very end is text
        if lt > text_from:
            sink.text(unescape(html[text_from:lt]))
        if nxt not in "/!?":  # a letter (_MARKUP_RE)
            tag = _scan_tag(html, lt + 1)
            if tag is None:
                return
            i, name, attrs, self_closing = tag
            sink.start(name, attrs, self_closing)
            if name == "plaintext":  # the rest of the document is text
                sink.text(html[i:])
                return
            raw_end = _RAW_END_RES.get(name)
            if raw_end is not None:
                closed = raw_end.search(html, i)
                stop = closed.start() if closed else size
                if name in _RAW_SHOWN:
                    sink.text(unescape(html[i:stop]) if name == "textarea" else html[i:stop])
                if closed is None:
                    return
                i = stop
        elif nxt == "/":
            if _is_letter(after):
                tag = _scan_tag(html, lt + 2)
                if tag is None:
                    return
                i = tag[0]
                sink.end(tag[1])
            elif after == ">":
                i = lt + 3
            else:  # "</ x>", "</1>": a comment to a browser
                close = html.find(">", lt + 2)
                if close < 0:
                    return
                i = close + 1
        elif html.startswith("<!--", lt):
            i = _comment_end(html, lt, dashes, bangs)
        else:  # "<!DOCTYPE ...>", "<![CDATA[...", "<?xml ...>": up to the next ">"
            close = html.find(">", lt + 2)
            if close < 0:
                return
            i = close + 1
        text_from = i
    if text_from < size:
        sink.text(unescape(html[text_from:]))


class _MailHTML:
    """What one pass over an HTML body collects: the anchors (href and
    visible text), whether it holds a form, its remote images, the first
    <base href>, and its visible text without what scripts, styles, titles
    and hidden elements hold."""

    def __init__(self, *, trust_inline: bool = True, trust_hidden: bool = True) -> None:
        self.trust_inline = trust_inline
        self.trust_hidden = trust_hidden
        self.stack: list[tuple[str, _Look]] = []
        self.where: dict[str, list[int]] = {}  # tag or group -> stack indexes, lowest first
        self.parts: list[str] = []  # text that is surely shown
        self.doubted: list[str] = []  # text that may be hidden (_Look.doubt), read after it
        self.size = 0
        self.anchors: list[tuple[str, str]] = []
        self.anchors_seen = 0
        self.open_href: Optional[str] = None
        self.open_tag = ""
        self.open_text: list[str] = []
        self.open_size = 0
        self.open_alt: list[str] = []
        self.has_form = False
        self.remote_images = 0
        self.base = ""

    # -- the open elements --

    def _nearest(self, *names: str) -> int:
        best = -1
        for name in names:
            found = self.where.get(name)
            if found and found[-1] > best:
                best = found[-1]
        return best

    def _push(self, tag: str, look: _Look) -> None:
        index = len(self.stack)
        self.stack.append((tag, look))
        self.where.setdefault(tag, []).append(index)
        for group in _TAG_GROUPS.get(tag, ()):
            self.where.setdefault(group, []).append(index)

    def _pop_to(self, index: int) -> None:
        """Closes the element at *index* and everything opened after it."""
        while len(self.stack) > max(index, 0):
            tag, _ = self.stack.pop()
            self.where[tag].pop()
            for group in _TAG_GROUPS.get(tag, ()):
                self.where[group].pop()

    def _look(self) -> _Look:
        return self.stack[-1][1] if self.stack else _SHOWN

    def _foster_look(self) -> Optional[_Look]:
        """The look of what a browser moves out in front of a table: text or
        a non-table element written straight inside <table> or <tr> lands
        beside the table, not in it."""
        if not self.stack or self.stack[-1][0] not in _TABLE_CONTEXT:
            return None
        table = self._nearest("table")
        if table < 0:
            return None
        return self.stack[table - 1][1] if table else _SHOWN

    def _close_p(self) -> None:
        found = self.where.get("p")
        if found and found[-1] > self._nearest("#button_scope"):
            self._pop_to(found[-1])

    def _implied_ends(self, tag: str) -> None:
        """Closes what a browser closes before opening *tag* (HTML5 "in body",
        "in table", "in row" and "in cell" rules, simplified)."""
        if tag not in _IMPLIES_ENDS:
            return
        if self.where.get("svg") or self.where.get("math"):
            if tag in _BREAKOUT_TAGS:  # an HTML block ends an <svg>/<math> it sits in
                roots = [found[0] for found in (self.where.get("svg"), self.where.get("math")) if found]
                self._pop_to(min(roots))
        if tag == "li":
            index = self._nearest("li")
            if index >= 0 and index > self._nearest("#special_li"):
                self._pop_to(index)
        elif tag in ("dd", "dt"):
            index = self._nearest("dd", "dt")
            if index >= 0 and index > self._nearest("#special_dd"):
                self._pop_to(index)
        elif tag == "a":
            index = self._nearest("a")
            if index >= 0 and index > self._nearest("#markers"):
                self._pop_to(index)
        elif tag == "button":
            index = self._nearest("button")
            if index >= 0 and index > self._nearest("#scope"):
                self._pop_to(index)
        elif tag in ("option", "optgroup"):
            if self.stack and self.stack[-1][0] == "option":
                self._pop_to(len(self.stack) - 1)
        elif tag in ("td", "th"):
            cell = self._nearest("td", "th")
            if cell >= 0 and cell > self._nearest("#rows"):
                self._pop_to(cell)
            row = self._nearest("#rows")
            if row >= 0:
                self._pop_to(row + 1)
        elif tag == "tr":
            section = self._nearest("#sections")
            if section >= 0:
                self._pop_to(section + 1)
        elif tag in ("tbody", "thead", "tfoot", "caption", "colgroup"):
            table = self._nearest("table")
            if table >= 0:
                self._pop_to(table + 1)
        elif tag == "table":
            table = self._nearest("table")
            if table >= 0 and table > self._nearest("td", "th", "caption"):
                self._pop_to(table)
        if tag in _CLOSES_P:
            self._close_p()
        if tag in _HEADINGS and self.stack and self.stack[-1][0] in _HEADINGS:
            self._pop_to(len(self.stack) - 1)

    def _child_look(self, parent: _Look, tag: str, attrs: Mapping[str, str]) -> _Look:
        """The look of an element's content. Inline hiding a stylesheet may
        override is not trusted: its text stays readable but is marked as
        doubtful (read after the text that is surely shown)."""
        if tag != "template" and "style" not in attrs and "hidden" not in attrs:
            return parent
        gone, unseen, tiny, doubt = parent.gone, parent.unseen, parent.tiny, parent.doubt
        if tag == "template":
            gone = True
        style = attrs.get("style")
        found = _declarations(style) if style else {}
        display = found.get("display")
        if display is not None and display[0] == "none":
            if display[1] or self.trust_inline:
                gone = True
            else:
                doubt = True
        if "hidden" in attrs and display is None:
            if self.trust_hidden:
                gone = True
            else:
                doubt = True
        opacity = found.get("opacity")
        if opacity is not None and _css_zero(opacity[0]):
            if opacity[1] or self.trust_inline:
                gone = True
            else:
                doubt = True
        visibility = found.get("visibility")
        if visibility is not None:
            if visibility[0] in ("hidden", "collapse"):
                if visibility[1] or self.trust_inline:
                    unseen = True
                else:
                    doubt = True
            elif visibility[0] == "visible":
                unseen = False
        font_size = found.get("font-size")
        if font_size is not None:
            if _css_zero(font_size[0]):
                if font_size[1] or self.trust_inline:
                    tiny = True
                else:
                    doubt = True
            elif font_size[0] and font_size[0] not in _CSS_KEEPS_PARENT:
                tiny = False
                doubt = doubt or _css_tiny(font_size[0])
        if not doubt:
            doubt = (
                any(_css_zero(found[name][0]) for name in _DOUBT_ZERO_SIZES if name in found)
                or found.get("mso-hide", ("", False))[0] == "all"
                or found.get("color", ("", False))[0] == "transparent"
            )
        return _Look(gone, unseen, tiny, doubt)

    # -- what the tokenizer feeds --

    def _emit(self, text: str, doubt: bool = False) -> None:
        if self.size < MAX_HTML_CHARS:
            (self.doubted if doubt else self.parts).append(text)
            self.size += len(text)

    def _close_anchor(self) -> None:
        if self.open_href is None:
            return
        text = " ".join("".join(self.open_text).split()) or " ".join(self.open_alt)
        if self.anchors_seen < MAX_ANCHORS:
            self.anchors.append((self.open_href, text))
        self.anchors_seen = min(self.anchors_seen + 1, MAX_ANCHORS)
        self.open_href, self.open_tag = None, ""
        self.open_text, self.open_alt, self.open_size = [], [], 0

    def start(self, tag: str, attrs: Mapping[str, str], self_closing: bool) -> None:
        self._implied_ends(tag)
        parent = (self._foster_look() if tag not in _TABLE_PARTS else None) or self._look()
        look = self._child_look(parent, tag, attrs)
        href = attrs.get("href", attrs.get("xlink:href"))
        if tag == "a" or (tag.startswith("v:") and href is not None):
            # <a>, and the Outlook (VML) buttons inside conditional blocks.
            self._close_anchor()
            if href is not None:
                self.open_href, self.open_tag = href, tag
        elif tag == "area" and href is not None:
            if self.anchors_seen < MAX_ANCHORS:
                self.anchors.append((href, attrs.get("alt", "")))
            self.anchors_seen = min(self.anchors_seen + 1, MAX_ANCHORS)
        elif tag == "base" and href and not self.base:
            self.base = href
        elif tag in ("img", "image"):
            src = attrs.get("src", "").strip().lower()
            if src.startswith(("http://", "https://", "//")):
                self.remote_images += 1
            if self.open_href is not None and attrs.get("alt") and look.shown and len(self.open_alt) < 4:
                self.open_alt.append(_clean_line(attrs["alt"], LINK_TEXT_CHARS))
        elif tag == "form" or (tag == "input" and attrs.get("type", "").lower() == "password"):
            self.has_form = True
        if tag in _BLOCK_TAGS and parent.shown:
            self._emit("\n", parent.doubt)
        elif tag in ("td", "th") and parent.shown:
            self._emit(" ", parent.doubt)
        foreign = bool(self.where.get("svg") or self.where.get("math")) or tag in ("svg", "math")
        if tag in _VOID_TAGS or (self_closing and foreign) or len(self.stack) >= _MAX_STACK:
            return  # (a "/>" on an HTML element is ignored by browsers: <a .../> stays open)
        self._push(tag, look)

    def _end_index(self, tag: str) -> int:
        """The stack index an end tag closes to, or -1 when a browser
        ignores it: the element must be "in scope" (no table, cell or other
        boundary opened after it; for "any other" end tags, no special
        element such as a <div> or <p> opened after it). Ignoring what a
        browser ignores keeps "</div>" inside a cell, or "</span>" past a
        <div>, from closing a hidden element whose descendants a browser
        still shows, or keeps hidden."""
        if self.where.get("svg") or self.where.get("math"):
            return self._nearest(tag)  # foreign content: the nearest element of that name
        if tag in _HEADINGS:
            found = self._nearest(*_HEADINGS)  # "</h2>" closes an open <h1>
            return found if found >= 0 and found >= self._nearest("#scope") else -1
        found = self._nearest(tag)
        if found < 0:
            return -1
        if tag == "p":
            boundary = self._nearest("#button_scope")
        elif tag == "li":
            boundary = self._nearest("#list_scope")
        elif tag in _TABLE_END_TAGS:
            boundary = self._nearest("#table_scope")
        elif tag in _SCOPED_END_TAGS or tag in _FORMATTING_TAGS:
            boundary = self._nearest("#scope")
        else:
            boundary = self._nearest("#special")
        return found if found >= boundary else -1

    def end(self, tag: str) -> None:
        if tag in ("html", "body"):  # a browser keeps <body> open after </body>
            return
        index = -1 if tag == "br" else self._end_index(tag)
        if tag == self.open_tag and (index >= 0 or self._nearest(tag) < 0):
            # The link ends at its end tag, or at an "</a>" once its element
            # is closed already; a "</a>" a browser ignores (inside a table
            # cell the link wraps) leaves the link open.
            self._close_anchor()
        if index >= 0:
            self._pop_to(index)
        look = self._look()
        if tag in _BLOCK_TAGS and look.shown:
            self._emit("\n", look.doubt)

    def text(self, data: str) -> None:
        if not data:
            return
        look = self._look()
        if self.stack and self.stack[-1][0] in _TABLE_CONTEXT and data.strip("\t\n\f\r "):
            look = self._foster_look() or look
        if len(self.stack) >= _MAX_STACK:
            # Deeper elements are not tracked, so a descendant that shows
            # text again (its own font size, visibility:visible) may be
            # missed: past the cap, only what nothing can undo stays hidden.
            look = _Look(gone=look.gone, doubt=True)
        if not look.shown:
            return
        self._emit(data, look.doubt)
        if self.open_href is not None and self.open_size < _ANCHOR_TEXT_CHARS:
            kept = data[: _ANCHOR_TEXT_CHARS - self.open_size]
            self.open_text.append(kept)
            self.open_size += len(kept)


@dataclass(frozen=True)
class _HtmlFacts:
    anchors: tuple[tuple[str, str], ...]
    anchors_seen: int
    has_form: bool
    remote_images: int
    raw_text: str
    base: str = ""


def _parse_html(html: str) -> _HtmlFacts:
    if not isinstance(html, str) or not html:
        return _HtmlFacts((), 0, False, 0, "")
    html = html[:MAX_HTML_CHARS]
    trust_inline, trust_hidden = _stylesheet_trust(html)
    sink = _MailHTML(trust_inline=trust_inline, trust_hidden=trust_hidden)
    try:
        _tokenize(html, sink)
    except Exception:  # never raises on hostile markup: keep what was read
        pass
    sink._close_anchor()
    # Text that may be hidden is read after the text that is surely shown,
    # so filler hidden by a style this module cannot be sure of never comes
    # first in the excerpt.
    raw_text = "".join(sink.parts)
    if sink.doubted:
        raw_text += "\n" + "".join(sink.doubted)
    return _HtmlFacts(tuple(sink.anchors), sink.anchors_seen, sink.has_form, sink.remote_images, raw_text, sink.base)


def _bare_urls(text: str, room: int) -> list[str]:
    """URLs written as plain text (mail apps make them clickable)."""
    found: list[str] = []
    if not text or room <= 0:
        return found
    for match in trigger_facts._URL_RE.finditer(text[:MAX_HTML_CHARS]):
        url = match.group(0).rstrip(".,;:!?)]}'\"")
        if url.lower().startswith("www."):
            url = "http://" + url
        found.append(url)
        if len(found) >= room:
            break
    return found


def _collect_links(
    anchors: Sequence[tuple[str, str]], bare: Sequence[str], seen_before: int, base: str = ""
) -> tuple[list[LinkFact], int]:
    links: list[LinkFact] = []
    index: dict[str, int] = {}
    entries = [*anchors, *((url, "") for url in bare)]
    for raw_href, text in entries:
        fact = _link_fact(raw_href, text, base)
        if fact is None:
            continue
        key = fact.href or f"{fact.code}\x00{fact.text}"
        if key in index:
            kept = links[index[key]]
            if not text_host(kept.text) and text_host(fact.text):
                # The same destination shown once as "Click here" and once
                # as "paypal.com": keep the text that names a site, which is
                # the one worth comparing.
                links[index[key]] = replace(kept, text=fact.text)
            continue
        if len(links) >= MAX_LINKS:
            continue
        index[key] = len(links)
        links.append(fact)
    return links, min(seen_before + len(bare), MAX_ANCHORS)


def extract_links(html: str, plain: str) -> tuple[list[LinkFact], int, bool, int]:
    """(links, anchors seen, has a <form>, remote <img> count) from the HTML body (this
    module's linear tokenizer, capped) plus bare URLs in the plain text (triggers.facts._URL_RE,
    facts.py:56). With no plain part, bare URLs in the HTML's visible text count instead."""
    parsed = _parse_html(html)
    source = plain if isinstance(plain, str) and plain.strip() else parsed.raw_text
    bare = _bare_urls(source, MAX_ANCHORS - parsed.anchors_seen)
    links, total = _collect_links(parsed.anchors, bare, parsed.anchors_seen, parsed.base)
    return links, total, parsed.has_form, parsed.remote_images


def visible_text(html: str, limit: int) -> str:
    """Readable text of an HTML body, without script/style/head, whitespace folded, capped.
    Text a stylesheet may be hiding comes after the text that is surely shown."""
    return _clean_text(_parse_html(html).raw_text, max(0, limit))


# -- Pressure wording and the excerpt ------------------------------------------------------
#
# The word lists of S2.md 4.6 (English only in v1, bounded patterns), matched
# on folded text (wording_fold). mail_checks.py scores them; they live here
# because the excerpt this module returns keeps the sentences that carry
# them, wherever they are in the mail. Without that, a long mail (or filler
# a stylesheet hides) pushed the real wording past the excerpt's cap, and
# the checks and the AI review never saw it.

URGENCY_RE = re.compile(
    r"\b(?:urgent(?:ly)?|immediately|right\s{1,3}away|act\s{1,3}now|as\s{1,3}soon\s{1,3}as\s{1,3}possible"
    r"|within\s{1,3}(?:24|48|72)\s{0,3}(?:hours?|hrs?|h)\b"
    r"|final\s{1,3}(?:notice|warning)"
    r"|account\s{1,3}(?:(?:will\s{1,3}be|has\s{1,3}been|have\s{1,3}been|is|was)\s{1,3})?"
    r"(?:suspended|locked|closed|limited|disabled)"
    r"|unusual\s{1,3}(?:sign[\s-]{0,2}in|log[\s-]{0,2}in|activity)"
    r"|verify\s{1,3}your\s{1,3}(?:account|identity|email))"
)
PAYMENT_RE = re.compile(
    r"\b(?:gift\s{1,3}cards?|wire\s{1,3}transfer|bank\s{1,3}(?:details|account)|routing\s{1,3}number"
    r"|bitcoin|btc|crypto(?:currency)?|usdt"
    r"|payment\s{1,3}(?:is\s{1,3})?(?:overdue|failed|declined)"
    r"|update\s{1,3}(?:your\s{1,3})?(?:payment|billing)"
    r"|invoice|refund|outstanding\s{1,3}balance|new\s{1,3}bank\s{1,3}details)\b"
)
CREDENTIALS_RE = re.compile(
    r"\b(?:password|passcode|log[\s-]{0,2}in|sign[\s-]{0,2}in|verification\s{1,3}code"
    r"|one[\s-]{0,2}time\s{1,3}(?:pass)?code|otp|2fa|security\s{1,3}code"
    r"|confirm\s{1,3}your\s{1,3}(?:details|identity|account)|social\s{1,3}security|ssn)\b"
)
WORDING_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "urgency": URGENCY_RE,
    "payment": PAYMENT_RE,
    "credentials": CREDENTIALS_RE,
}
_FOLD_DROP_RE = re.compile("[\u00ad\u200b-\u200f\u2060-\u2064\ufeff]")
_CONFUSABLE_TABLE = str.maketrans(CONFUSABLES)
_QUOTES_TABLE = str.maketrans({"\u2019": "'", "\u2018": "'"})
# The window the excerpt reads the wording in: windows overlap by more than
# the longest phrase the patterns match, so no phrase falls between two.
_WINDOW_OVERLAP = 60
_WORDING_SEPARATOR = " \u2026 "


def wording_fold(text: str, limit: int = 4000) -> str:
    """Text as the word lists read it: compatibility forms folded, lower case,
    hidden characters dropped, curly quotes straightened, look-alike letters
    read as Latin. At most *limit* characters of *text* are read."""
    if not isinstance(text, str) or not text:
        return ""
    folded = unicodedata.normalize("NFKC", text[: max(0, limit)]).lower()
    folded = _FOLD_DROP_RE.sub("", folded).translate(_QUOTES_TABLE)
    return folded.translate(_CONFUSABLE_TABLE)


def wording_kinds(text: str, limit: int = 4000) -> frozenset[str]:
    """Which of "urgency", "payment" and "credentials" the wording of *text* carries."""
    folded = wording_fold(text, limit)
    return frozenset(kind for kind, pattern in WORDING_PATTERNS.items() if pattern.search(folded))


def _wording_windows(text: str) -> list[tuple[int, int, frozenset[str]]]:
    """(start, end, kinds) of the windows of *text* that carry pressure
    wording, in order; each window is cut to whole words. Linear: a fixed
    window slides over the text once, and a text with no such wording at all
    is answered from one folded pass."""
    if not wording_kinds(text, len(text)):
        return []
    size = len(text)
    step = WORDING_CHUNK_CHARS - _WINDOW_OVERLAP
    found: list[tuple[int, int, frozenset[str]]] = []
    for start in range(0, size, step):
        stop = min(start + WORDING_CHUNK_CHARS, size)
        begin, end = start, stop
        if begin and not text[begin - 1].isspace():  # a word cut at the start
            blank = next((i for i in range(begin, min(begin + 20, end)) if text[i].isspace()), -1)
            begin = blank + 1 if blank >= 0 else begin
        if end < size and not text[end].isspace():  # a word cut at the end
            blank = next((i for i in range(end - 1, max(begin, end - 20), -1) if text[i].isspace()), -1)
            end = blank if blank > begin else end
        kinds = wording_kinds(text[begin:end], WORDING_CHUNK_CHARS)
        if kinds:
            found.append((begin, end, kinds))
        if stop >= size:
            break
    return found


def _picked_windows(windows: Sequence[tuple[int, int, frozenset[str]]], budget: int) -> list[tuple[int, int]]:
    """The windows the excerpt keeps: the first of each kind, then the rest in
    order while *budget* characters allow; overlapping windows merged."""
    chosen: list[tuple[int, int]] = []
    used = 0
    for kind in WORDING_PATTERNS:
        first = next(((begin, end) for begin, end, kinds in windows if kind in kinds), None)
        if first is not None and first not in chosen and used + first[1] - first[0] <= budget:
            chosen.append(first)
            used += first[1] - first[0]
    for begin, end, _ in windows:
        if (begin, end) not in chosen and used + end - begin <= budget:
            chosen.append((begin, end))
            used += end - begin
    merged: list[tuple[int, int]] = []
    for begin, end in sorted(chosen):
        if merged and begin <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((begin, end))
    return merged


def wording_excerpt(text: str, limit: int) -> str:
    """*text* cut to *limit* characters the way the excerpt is: the start of
    the text, then (when the text is longer) the passages that carry urgency,
    payment or sign-in wording wherever they are, joined by " ... ". The
    first passage of each kind is always kept, so the checks read the same
    wording in the excerpt as in the whole text, and at most WORDING_SHARE of
    the excerpt goes to these passages."""
    if not isinstance(text, str) or limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    windows = _wording_windows(text)
    spans = _picked_windows(windows, int(limit * WORDING_SHARE)) if windows else []
    lead_end = limit - 1
    for _ in range(4):  # a passage the lead already holds needs no copy
        kept = sum(end - begin for begin, end in spans) + len(_WORDING_SEPARATOR) * len(spans)
        lead_end = max(0, limit - 1 - kept)
        remaining = [(begin, end) for begin, end in spans if end > lead_end]
        if remaining == spans:
            break
        spans = remaining
    # A passage that starts inside the lead is repeated whole, so a phrase
    # cut by the lead's end is still read in one piece.
    pieces = [text[:lead_end].rstrip()]
    pieces += [text[begin:end].strip() for begin, end in spans]
    excerpt = _WORDING_SEPARATOR.join(piece for piece in pieces if piece)
    if not spans:
        excerpt += "\u2026"
    return excerpt if len(excerpt) <= limit else excerpt[: limit - 1].rstrip() + "\u2026"


def _emoji_join(text: str, index: int) -> bool:
    """A zero-width joiner between two pictures (a family emoji) is part of
    the picture, not hidden text."""
    before = index - 1
    while before >= 0 and text[before] in _EMOJI_MODIFIERS:
        before -= 1
    after = index + 1
    return (
        before >= 0
        and after < len(text)
        and unicodedata.category(text[before]) == "So"
        and unicodedata.category(text[after]) == "So"
    )


def hidden_char_count(text: str) -> int:
    """Invisible, tag (U+E0000-E007F) and bidi-control characters in *text*."""
    if not isinstance(text, str) or not text:
        return 0
    for flag in _RGI_TAG_FLAGS:
        if flag in text:
            text = text.replace(flag, "")
    count = 0
    for match in _HIDDEN_RE.finditer(text[:MAX_HTML_CHARS]):
        if match.group(0) == _ZWJ and _emoji_join(text, match.start()):
            continue
        count += 1
    return count


# -- Attachments ----------------------------------------------------------------------------


# What a run of hidden or bidi characters in an attachment's name becomes.
HIDDEN_MARK = "\ufffd"


def _mark_hidden(text: str) -> str:
    """*text* with each run of the characters hidden_char_count counts
    replaced by one HIDDEN_MARK: a name that reverses its own ending
    ("invoice<RLO>fdp.exe" shows as "invoiceexe.pdf") keeps a visible trace
    of the trick, which mail_checks reads as a disguised name. The pictures
    built with such characters (a family emoji, the England flag) stay."""
    protected: set[int] = set()
    for flag in _RGI_TAG_FLAGS:
        start = text.find(flag)
        while start >= 0:
            protected.update(range(start, start + len(flag)))
            start = text.find(flag, start + len(flag))
    out: list[str] = []
    last = 0
    for match in _HIDDEN_RE.finditer(text):
        index = match.start()
        if index in protected or (match.group(0) == _ZWJ and _emoji_join(text, index)):
            continue
        if not (index == last and out and out[-1] == HIDDEN_MARK):  # one mark per run
            out += [text[last:index], HIDDEN_MARK]
        last = match.end()
    out.append(text[last:])
    return "".join(out)


def _clean_filename(value: str) -> str:
    """The name with hidden characters marked (HIDDEN_MARK) and controls made
    blanks; a long name keeps its end, where the real type is
    ("....pdf          .exe")."""
    text = _mark_hidden(value[:2000])
    # Every format character _HIDDEN_RE knows was marked above, so one still
    # here belongs to a picture _mark_hidden kept (a family emoji's joiner, a
    # flag's tags); other controls become blanks.
    text = "".join(c if c.isprintable() or unicodedata.category(c) == "Cf" else " " for c in text).strip()
    if len(text) > FILENAME_CHARS:
        text = text[: FILENAME_CHARS - 41] + "\u2026" + text[-40:]
    return text


def _attachment(entry: Mapping[str, Any]) -> Optional[MailAttachment]:
    if not isinstance(entry, Mapping):
        return None
    raw_name = entry.get("filename")
    if not isinstance(raw_name, str):
        raw_name = entry.get("name") if isinstance(entry.get("name"), str) else ""
    name = _clean_filename(raw_name or "")
    raw_ref = entry.get("ref")
    ref = _clean_line(str(raw_ref), REF_CHARS) if isinstance(raw_ref, (str, int)) and not isinstance(raw_ref, bool) else ""
    if not name and not ref:
        return None
    mime = entry.get("mime_type") if isinstance(entry.get("mime_type"), str) else entry.get("content_type")
    return {
        "ref": ref,
        "filename": name,
        "mime_type": _clean_line(mime, 100).lower() if isinstance(mime, str) else "",
        "size": _int(entry.get("size")) or 0,
        "is_inline": entry.get("is_inline") is True,
    }


# -- The whole answer -----------------------------------------------------------------------


def _field_list(fields: Mapping[str, Any], key: str) -> list[str]:
    value = fields.get(key)
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value[:MAX_RECIPIENTS * 2] if isinstance(v, str)]
    return []


def _sender_field(value: Any) -> tuple[str, str]:
    """A provider's own sender field: "Name <addr>" or {"name", "address"}."""
    if isinstance(value, Mapping):
        name = value.get("name") if isinstance(value.get("name"), str) else ""
        return _clean_line(name, NAME_CHARS), _address(value.get("address"))
    return address_parts(value)


def _received(value: Any) -> Optional[str]:
    """ISO 8601 UTC ("...Z"), or None when the provider gave no readable time."""
    moment = trigger_facts.parse_time(value) if isinstance(value, str) else None
    return trigger_facts.iso(moment) or None


def security_facts(
    *,
    provider: str,
    message_id: str,
    thread_id: Optional[str],
    received: Optional[str],
    folder: str,
    labels: Sequence[str],
    headers: Sequence[Mapping[str, Any]],
    html: str,
    plain: str,
    attachments: Sequence[Mapping[str, Any]],
    fields: Optional[Mapping[str, Any]] = None,
    sent_by_me: bool = False,
    mailbox: str = "",
) -> dict[str, Any]:
    """The whole answer of get_message_security (shape in S2.md 4.4 plus the
    scaffold A7 keys: MailSecurityFacts), JSON-ready and capped.

    *fields* are values a provider gives outside the headers (Graph's from,
    sender, replyTo, toRecipients, ccRecipients, subject: keys "from",
    "sender", "reply_to", "to", "cc", "subject"); each is used only when no
    header gives it (internal Outlook mail carries no internet headers)."""
    headers = headers if isinstance(headers, (list, tuple)) else []
    extra: Mapping[str, Any] = fields if isinstance(fields, Mapping) else {}
    html = html if isinstance(html, str) else ""
    plain = plain if isinstance(plain, str) else ""

    from_values = header_values(headers, "From", limit=2)
    name, address, raw_name = _sender_of(from_values)
    if not from_values and "from" in extra:
        name, address = _sender_field(extra.get("from"))

    subject_header = header_values(headers, "Subject", limit=1)
    raw_subject = _decode_words(subject_header[0]) if subject_header else ""
    if not raw_subject and isinstance(extra.get("subject"), str):
        raw_subject = extra["subject"][: MAX_HEADER_CHARS]

    sender_value = _first_header(headers, "Sender")
    sender = address_parts(sender_value)[1] if sender_value else ""
    if not sender and "sender" in extra:
        sender = _sender_field(extra.get("sender"))[1]

    reply_values = header_values(headers, "Reply-To", limit=5)
    reply_to = _address_list(reply_values, MAX_REPLY_TO) if reply_values else []
    if not reply_values and "reply_to" in extra:
        reply_to = _address_list(_field_list(extra, "reply_to"), MAX_REPLY_TO)

    to_values = header_values(headers, "To", limit=5)
    to = _address_list(to_values or _field_list(extra, "to"), MAX_RECIPIENTS)
    cc_values = header_values(headers, "Cc", limit=5)
    cc = _address_list(cc_values or _field_list(extra, "cc"), MAX_RECIPIENTS)

    parsed = _parse_html(html)
    body_text = parsed.raw_text if html else plain[:MAX_HTML_CHARS]
    bare_source = plain if plain.strip() else parsed.raw_text
    bare = _bare_urls(bare_source, MAX_ANCHORS - parsed.anchors_seen)
    links, links_total = _collect_links(parsed.anchors, bare, parsed.anchors_seen, parsed.base)

    shaped_attachments: list[MailAttachment] = []
    for entry in attachments if isinstance(attachments, (list, tuple)) else []:
        shaped = _attachment(entry)
        if shaped is not None:
            shaped_attachments.append(shaped)
        if len(shaped_attachments) >= MAX_ATTACHMENTS:
            break

    clean_labels = [
        label for label in (_clean_line(v, 64) for v in (labels or [])[:MAX_LABELS] if isinstance(v, str)) if label
    ]
    provider_name = provider if provider in PROVIDERS else _clean_line(provider, 16)
    # Built as the TypedDict so mypy checks every key and type, returned as
    # the plain dict the connector actions and S2.md 4.2 declare.
    answer: MailSecurityFacts = {
        "id": _clean_line(message_id, REF_CHARS) if isinstance(message_id, str) else "",
        "gone": False,
        "provider": provider_name,
        "thread_id": (_clean_line(thread_id, REF_CHARS) or None) if isinstance(thread_id, str) else None,
        "received": _received(received),
        "folder": _clean_line(folder, 32).lower() if isinstance(folder, str) else "",
        "labels": clean_labels,
        "subject": _clean_line(raw_subject, SUBJECT_CHARS),
        "from": {"name": name, "address": address, "domain": _domain_of(address)},
        "sender": sender,
        "reply_to": reply_to,
        "return_path_domain": _domain_of(address_parts(_first_header(headers, "Return-Path"))[1]),
        "message_id_domain": _message_id_domain(_first_header(headers, "Message-ID")),
        "list_unsubscribe": bool(_first_header(headers, "List-Unsubscribe").strip()),
        "auth": auth_verdict(headers, provider=provider).as_dict(),
        "links": [link.as_dict() for link in links],
        "links_total": links_total,
        "has_form": parsed.has_form,
        "remote_images": parsed.remote_images,
        "attachments": shaped_attachments,
        # The excerpt keeps the pressure wording wherever it is in the mail
        # (wording_excerpt), so filler cannot push it out of the checks' view.
        "text": wording_excerpt(_clean_text(body_text, MAX_HTML_CHARS), TEXT_CHARS),
        "hidden_chars": hidden_char_count(raw_subject) + hidden_char_count(raw_name) + hidden_char_count(body_text),
        "to": to,
        "cc": cc,
        "sent_by_me": sent_by_me is True,
        "mailbox": _address(mailbox),
    }
    return cast("dict[str, Any]", answer)


def gone_answer(message_id: Any) -> dict[str, Any]:
    """The answer for a message the provider says no longer exists (a 404),
    so the sweeper can tell "gone" from "broken" (review FEA-SF3): only
    {"id", "gone": True}."""
    answer: MailSecurityFacts = {
        "id": _clean_line(message_id, REF_CHARS) if isinstance(message_id, str) else "",
        "gone": True,
    }
    return cast("dict[str, Any]", answer)


def is_gone(answer: Any) -> bool:
    return isinstance(answer, Mapping) and answer.get(GONE_KEY) is True


# -- Provider payloads ------------------------------------------------------------------------


def _get_str(item: Mapping[str, Any], key: str) -> str:
    value = item.get(key)
    return value if isinstance(value, str) else ""


def _get_map(item: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = item.get(key)
    return value if isinstance(value, Mapping) else {}


def _get_list(item: Mapping[str, Any], key: str) -> list[Any]:
    value = item.get(key)
    return value if isinstance(value, list) else []


def _decode_b64url(data: Any, charset: str) -> str:
    if not isinstance(data, str) or not data:
        return ""
    data = data[: (MAX_HTML_CHARS * 4) // 3 + 8]
    try:
        raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError):
        return ""
    try:
        codecs.lookup(charset)
    except LookupError:
        charset = "utf-8"
    try:
        return raw.decode(charset, errors="replace")[:MAX_HTML_CHARS]
    except Exception:  # a codec that fails on this input
        return raw.decode("utf-8", errors="replace")[:MAX_HTML_CHARS]


def _gmail_parts(payload: Mapping[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    """(html, plain, attachments) of a Gmail format=full payload: the first
    text/html and text/plain parts without a file name, and every named part
    (ref = partId, inline when its Content-Disposition says so), depth first
    and bounded."""
    html, plain = "", ""
    found: list[dict[str, Any]] = []
    todo: list[tuple[Any, int]] = [(payload, 0)]
    walked = 0
    while todo and walked < MAX_MIME_PARTS:
        part, depth = todo.pop()
        walked += 1
        if not isinstance(part, Mapping):
            continue
        mime = _get_str(part, "mimeType").lower()
        filename = _get_str(part, "filename")
        body = _get_map(part, "body")
        part_headers = _get_list(part, "headers")
        if filename:
            disposition = _first_header(part_headers, "Content-Disposition").strip().lower()
            if len(found) < MAX_ATTACHMENTS:
                found.append(
                    {
                        "ref": _get_str(part, "partId"),
                        "filename": filename,
                        "mime_type": mime,
                        "size": body.get("size"),
                        "is_inline": disposition.startswith("inline"),
                    }
                )
        elif (mime == "text/html" and not html) or (mime == "text/plain" and not plain):
            match = _CHARSET_RE.search(_first_header(part_headers, "Content-Type"))
            text = _decode_b64url(body.get("data"), match.group(1) if match else "utf-8")
            if mime == "text/html":
                html = text
            else:
                plain = text
        children = _get_list(part, "parts")
        if children and depth < MAX_MIME_DEPTH:
            todo.extend((child, depth + 1) for child in reversed(children[:MAX_MIME_PARTS]))
    return html, plain, found


def _gmail_received(value: Any) -> str:
    millis = _int(value)
    if millis is None:
        return ""
    try:
        moment = datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _gmail_folder(labels: Sequence[str]) -> str:
    for label, folder in (("SPAM", "spam"), ("TRASH", "trash"), ("INBOX", "inbox"), ("SENT", "sent")):
        if label in labels:
            return folder
    return "other"


def facts_from_gmail(message: Mapping[str, Any], *, mailbox: str = "") -> dict[str, Any]:
    """security_facts for one Gmail messages.get(format=full) answer: the
    payload's headers in order, its first HTML and plain parts, its named
    parts as attachments, internalDate as the received time, and "SENT" in
    labelIds as sent_by_me (scaffold A7)."""
    message = message if isinstance(message, Mapping) else {}
    payload = _get_map(message, "payload")
    labels = [v for v in _get_list(message, "labelIds") if isinstance(v, str)]
    html, plain, attachments = _gmail_parts(payload)
    return security_facts(
        provider="gmail",
        message_id=_get_str(message, "id"),
        thread_id=_get_str(message, "threadId") or None,
        received=_gmail_received(message.get("internalDate")),
        folder=_gmail_folder(labels),
        labels=labels,
        headers=_get_list(payload, "headers"),
        html=html,
        plain=plain,
        attachments=attachments,
        sent_by_me="SENT" in labels,
        mailbox=mailbox,
    )


def _graph_address(value: Any) -> dict[str, str]:
    inner = _get_map(value, "emailAddress") if isinstance(value, Mapping) else {}
    if not inner:
        return {}
    return {"name": _get_str(inner, "name"), "address": _get_str(inner, "address")}


def _graph_addresses(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out = []
    for item in value[: MAX_RECIPIENTS * 2]:
        address = _graph_address(item).get("address", "")
        if address:
            out.append(address)
    return out


def facts_from_graph(
    message: Mapping[str, Any],
    attachments: Sequence[Mapping[str, Any]] = (),
    *,
    mailbox: str = "",
    sent_by_me: bool = False,
    folder: str = "inbox",
) -> dict[str, Any]:
    """security_facts for one Graph message (internetMessageHeaders, body,
    from, sender, replyTo, subject, receivedDateTime, and conversationId,
    toRecipients, ccRecipients when selected) and its attachment list
    (id, name, contentType, size, isInline). Graph's own fields stand in for
    headers that internal mail does not carry."""
    message = message if isinstance(message, Mapping) else {}
    body = _get_map(message, "body")
    content = _get_str(body, "content")
    is_html = _get_str(body, "contentType").lower() == "html"
    items = attachments if isinstance(attachments, (list, tuple)) else []
    shaped_attachments = [
        {
            "ref": _get_str(item, "id"),
            "filename": _get_str(item, "name"),
            "mime_type": _get_str(item, "contentType"),
            "size": item.get("size"),
            "is_inline": item.get("isInline") is True,
        }
        for item in items[:MAX_ATTACHMENTS]
        if isinstance(item, Mapping)
    ]
    fields: dict[str, Any] = {
        "from": _graph_address(message.get("from")),
        "sender": _graph_address(message.get("sender")),
        "reply_to": _graph_addresses(message.get("replyTo")),
        "to": _graph_addresses(message.get("toRecipients")),
        "cc": _graph_addresses(message.get("ccRecipients")),
        "subject": _get_str(message, "subject"),
    }
    return security_facts(
        provider="outlook",
        message_id=_get_str(message, "id"),
        thread_id=_get_str(message, "conversationId") or None,
        received=_get_str(message, "receivedDateTime") or None,
        folder=folder,
        labels=[],
        headers=_get_list(message, "internetMessageHeaders"),
        html=content if is_html else "",
        plain="" if is_html else content,
        attachments=shaped_attachments,
        fields=fields,
        sent_by_me=sent_by_me,
        mailbox=mailbox,
    )
