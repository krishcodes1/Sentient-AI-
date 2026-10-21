"""Scores one email's security facts (services/security/mail_facts.py) with
the free checks that need no network: the provider's own authentication
verdict, look-alike and mixed-script sender domains, a From that mail apps
may read two ways, a display name that claims a brand or shows another
address, a Reply-To that leads elsewhere,
links whose text names one site while they go to another, code links,
forms, risky and disguised attachments, pressure wording, hidden characters
and text aimed at AI assistants; plus S4's link verdicts and S10's
attachment verdicts when the caller has them. Every reason is a fixed
sentence.

Why it exists: the mail scam sweeper (services/notifications/mail_scan.py)
runs these checks on every new email, so they must be cheap, predictable and
explainable, and they must never be talked out of a finding by the email
itself. The weights, the per-group caps (one kind of sign cannot dominate),
the authenticated-sender dampener (a newsletter with urgent wording stays
quiet) and the levels (S2.md 4.6) live here in one table, with the rules
that decide what may stay off the person's channels: ``may_go_quiet`` (review
SEC-M1), ``pushes_without_review`` (review FEA-SF2) and ``combine`` (scaffold
A33: the AI review can make a finding stricter, never lift it). Nothing here
says an email is safe: the lowest level is "none", meaning "nothing to report
from these checks". Pure: no network, no model, no database.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, replace
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urlsplit

import services.security.lookalike as lookalike
from services.security.mail_facts import (
    CREDENTIALS_RE,
    HIDDEN_MARK,
    PAYMENT_RE,
    URGENCY_RE,
    text_host,
    wording_excerpt,
    wording_fold,
)
from services.triggers import facts as trigger_facts

FLAG_SCORE = 3  # flagged (stored, reviewed, alerted unless the review clears it)
LIKELY_SCORE = 7  # likely scam without a hard signal
GROUP_CAPS = {"auth": 3, "sender": 3, "reply": 3, "links": 6, "attachments": 4, "content": 2}
MAX_LINKS_FOR_REPUTATION = 5  # review FEA-SF1: one URL per registrable host, ESP hosts left out
# Weak codes (review SEC-M1): a no_signs review may quiet a finding only when every hit is one of
# these, the sender authenticated (DMARC or compauth pass), and there is no injection_text or
# hidden_characters hit. Never quiet with any auth_*_fail, sender_*, display_name_*,
# reply_to_lookalike, reply_to_freemail, other link_*, form_in_body or attachment_* hit.
SOFT_CODES: frozenset[str] = frozenset(
    {"pressure_payment", "pressure_credentials", "link_shortener", "link_suspicious_tld", "reply_to_mismatch", "auth_none"}
)
# Codes that may stay off the channels when no AI review ran (review FEA-SF2): SOFT_CODES plus the
# common marketing pattern link_text_mismatch. Any other hit is still pushed.
NOISY_CODES: frozenset[str] = SOFT_CODES | {"link_text_mismatch"}
# Hits that make a finding a likely scam on their own and are never held by
# the hourly alert cap (review SEC-F7).
HARD_CODES: frozenset[str] = frozenset({"link_malicious", "attachment_malicious"})
LEVELS = ("likely_scam", "suspicious", "none")
# The order combine() reads verdicts on: a later one is stricter.
VERDICT_ORDER = ("no_signs", "suspicious", "likely_scam")
# A finding row keeps at most this many hits (mail_scam_findings.signals).
MAX_HITS = 20
MAX_REASON_LINES = 5
HIDDEN_CHARS_MIN = 3
EXCERPT_CHARS = 1500
EXCERPT_LINKS = 10
DISPLAY_FACTS_MAX_BYTES = 4096  # like triggers.facts.FACTS_MAX_BYTES (facts.py:30)
DISPLAY_LINK_HOSTS = 10
DISPLAY_ATTACHMENTS = 5
# Fixed notes the sweeper adds when S4 or S10 could not answer (S2.md 4.3).
LINKS_NOT_CHECKED_NOTE = "Links were not checked against the link service this time."
FILES_NOT_CHECKED_NOTE = "Attachments were not checked with VirusTotal this time."

# Favourite phishing targets (S2.md 4.6), on top of lookalike.WELL_KNOWN_BRANDS,
# plus the scam brands the display-name check names below.
_PHISHING_FAVOURITES: tuple[str, ...] = (
    "microsoft.com", "office.com", "office365.com", "microsoftonline.com", "outlook.com", "live.com",
    "sharepoint.com", "onedrive.com", "apple.com", "icloud.com", "google.com", "gmail.com",
    "docusign.com", "docusign.net", "dropbox.com", "adobe.com", "fedex.com", "ups.com", "usps.com",
    "dhl.com", "irs.gov", "ssa.gov", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "capitalone.com", "americanexpress.com", "discover.com", "coinbase.com", "binance.com",
    "kraken.com", "linkedin.com", "facebook.com", "instagram.com", "whatsapp.com", "zelle.com",
    "cash.app", "roblox.com", "instructure.com", "okta.com", "intuit.com", "quickbooks.com",
    "mcafee.com", "norton.com", "geeksquad.com",
)  # fmt: skip
BRAND_DOMAINS: tuple[str, ...] = tuple(dict.fromkeys((*lookalike.WELL_KNOWN_BRANDS, *_PHISHING_FAVOURITES)))

_MICROSOFT = (
    "microsoft.com", "office.com", "office365.com", "microsoftonline.com", "outlook.com", "live.com",
    "sharepoint.com", "sharepointonline.com", "onedrive.com", "microsoft365.com", "skype.com", "xbox.com",
)  # fmt: skip
_AMAZON = (
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca",
    "amazon.com.au", "amazon.co.jp", "amazon.in", "amazon.com.mx", "amazon.com.br", "amazon.nl",
    "amazon.se", "amazon.pl", "amazon.sg", "amazon.ae", "amazonaws.com", "primevideo.com",
)  # fmt: skip
_GOV_SENDERS = ("govdelivery.com",)
# (label, display name, phrases a display name may carry, domains the brand
# really sends from). A phrase in capitals ("UPS", "IRS") is matched only in
# capitals, so "pop-ups" or "irs" inside a word never count; a display name
# that is exactly the brand's display name ("Apple", "Chase") counts too.
_BRANDS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("paypal", "PayPal", ("paypal",), ("paypal.com",)),
    ("docusign", "DocuSign", ("docusign",), ("docusign.com", "docusign.net")),
    (
        "microsoft",
        "Microsoft",
        ("microsoft", "office 365", "office365", "microsoft 365", "sharepoint", "onedrive", "windows defender"),
        _MICROSOFT,
    ),
    (
        "apple",
        "Apple",
        ("apple support", "apple id", "apple pay", "apple account", "apple billing", "app store", "itunes", "icloud"),
        ("apple.com", "icloud.com", "me.com", "mac.com", "itunes.com"),
    ),
    ("google", "Google", ("google", "gmail"), ("google.com", "gmail.com", "googlemail.com", "youtube.com", "googlegroups.com")),
    ("amazon", "Amazon", ("amazon", "prime video"), _AMAZON),
    ("netflix", "Netflix", ("netflix",), ("netflix.com",)),
    ("dropbox", "Dropbox", ("dropbox",), ("dropbox.com", "dropboxmail.com")),
    ("fedex", "FedEx", ("fedex",), ("fedex.com",)),
    ("usps", "USPS", ("usps", "postal service"), ("usps.com", "usps.gov", *_GOV_SENDERS)),
    ("dhl", "DHL", ("dhl",), ("dhl.com", "dhl.de", "dhl.co.uk")),
    ("ups", "UPS", ("UPS",), ("ups.com",)),
    ("irs", "IRS", ("IRS", "internal revenue service"), ("irs.gov", *_GOV_SENDERS)),
    ("ssa", "Social Security", ("social security administration", "SSA"), ("ssa.gov", *_GOV_SENDERS)),
    ("chase", "Chase", ("chase bank", "chase online", "jpmorgan chase", "chase alerts"), ("chase.com", "jpmorgan.com", "jpmchase.com")),
    ("bankofamerica", "Bank of America", ("bank of america", "bankofamerica", "bofa"), ("bankofamerica.com", "bofa.com")),
    ("wellsfargo", "Wells Fargo", ("wells fargo", "wellsfargo"), ("wellsfargo.com", "wf.com")),
    ("citi", "Citi", ("citibank", "citi"), ("citi.com", "citibank.com", "citigroup.com")),
    ("capitalone", "Capital One", ("capital one", "capitalone"), ("capitalone.com",)),
    ("americanexpress", "American Express", ("american express", "amex"), ("americanexpress.com", "aexp.com")),
    ("coinbase", "Coinbase", ("coinbase",), ("coinbase.com",)),
    ("binance", "Binance", ("binance",), ("binance.com",)),
    ("linkedin", "LinkedIn", ("linkedin",), ("linkedin.com",)),
    ("facebook", "Facebook", ("facebook", "meta for business"), ("facebook.com", "facebookmail.com", "meta.com", "fb.com")),
    ("instagram", "Instagram", ("instagram",), ("instagram.com", "facebookmail.com")),
    ("whatsapp", "WhatsApp", ("whatsapp",), ("whatsapp.com", "facebookmail.com")),
    ("venmo", "Venmo", ("venmo",), ("venmo.com",)),
    ("cashapp", "Cash App", ("cash app", "cashapp"), ("cash.app", "square.com", "squareup.com")),
    ("roblox", "Roblox", ("roblox",), ("roblox.com",)),
    ("adobe", "Adobe", ("adobe",), ("adobe.com", "adobesign.com", "echosign.com")),
    ("intuit", "QuickBooks", ("quickbooks", "intuit", "turbotax"), ("intuit.com", "quickbooks.com", "turbotax.com")),
    ("mcafee", "McAfee", ("mcafee",), ("mcafee.com",)),
    ("norton", "Norton", ("norton antivirus", "norton 360", "nortonlifelock", "norton security"), ("norton.com", "nortonlifelock.com", "gen.com")),
    ("geeksquad", "Geek Squad", ("geek squad", "geeksquad"), ("geeksquad.com", "bestbuy.com")),
    ("ebay", "eBay", ("ebay",), ("ebay.com", "ebay.co.uk", "ebay.de", "ebay.ca", "ebay.com.au")),
    ("walmart", "Walmart", ("walmart",), ("walmart.com",)),
    ("costco", "Costco", ("costco",), ("costco.com",)),
    ("steam", "Steam", ("steam support", "steam community", "steampowered"), ("steampowered.com", "steamcommunity.com")),
    ("spotify", "Spotify", ("spotify",), ("spotify.com",)),
)
BRAND_NAMES: Mapping[str, str] = {label: display for label, display, _, _ in _BRANDS}
# What a display_name_brand hit's arg (the brand's first domain) is shown as.
_DISPLAY_BY_DOMAIN: Mapping[str, str] = {domains[0]: display for _, display, _, domains in _BRANDS}
# Domains brands really send from: a sender here is never read as imitating one.
_BRAND_OWNED: frozenset[str] = frozenset(BRAND_DOMAINS) | frozenset(d for *_, domains in _BRANDS for d in domains)
# Brand names whose .com is theirs, so the same name under a _REGIONAL_ENDINGS
# ending is too.
_REGIONAL_BRAND_LABELS: frozenset[str] = frozenset(d.split(".", 1)[0] for d in _BRAND_OWNED if d.endswith(".com"))
# Brand names that are also everyday words or names ("adobe" houses, "intuit"
# inside "intuitive"). For these the brand's name in a sender's domain counts
# only with more to go on: a typo or homograph of it (app1e.com), the brand's
# whole domain in front of another (apple.com.evil.tk), a phishing word beside
# it (chase-bank, ups-tracking) or a display name claiming the same brand.
# "deltadental", "unitedway", "applebees", "office-supplies" and "liveperson"
# are real senders.
_COMMON_WORD_BRANDS: frozenset[str] = frozenset(
    {
        "apple", "target", "delta", "united", "chase", "discover", "office", "live", "ups", "square",
        "booking", "kayak", "zoom", "chewy", "southwest", "chipotle", "dominos", "stripe", "adobe",
        "outlook", "cash", "kraken", "intuit", "hotels", "fandango", "nike", "uber", "aa", "axs",
        "cvs", "ulta", "lowes",
    }
)  # fmt: skip
# Words that, next to an everyday-word brand, make a domain read as an
# imitation after all ("apple-id-support", "ups-tracking", "chase-bank").
_PHISHING_WORDS: frozenset[str] = frozenset(
    {
        "id", "support", "secure", "security", "verify", "verification", "login", "signin", "logon",
        "account", "accounts", "billing", "update", "service", "services", "help", "helpdesk",
        "alert", "alerts", "auth", "wallet", "recover", "recovery", "unlock", "confirm", "invoice",
        "refund", "pay", "payment", "payments", "online", "notice", "care", "delivery", "tracking",
        "track", "parcel", "package", "bank", "banking", "share", "sharing", "docs", "doc",
        "document", "documents", "file", "files", "sign", "esign", "webmail", "portal", "reset",
        "password", "renew", "renewal", "order", "orders", "shipping", "shipment", "claim",
        "reward", "rewards", "gift", "cloud", "drive", "storage", "notification", "notifications",
        "message", "messages", "protect", "protection", "fraud", "dispute", "validate", "validation",
    }
)  # fmt: skip
# Country endings under which a brand's own name is the brand's own site
# (amazon.de, paypal.co.uk): big-country registries where brands hold their
# names. Under any other ending (paypal.tk, netflix.xyz, amazon.shop,
# microsoft.support, and paypal.co, one key away from .com) the name is an
# imitation unless the brand is known to send from that exact domain.
_REGIONAL_ENDINGS: frozenset[str] = frozenset(
    """
    de fr it es nl be at ch se no dk fi pl pt ie cz gr hu ro sk lu jp in ca mx br au nz sg hk tw kr
    za tr il ae sa ar cl cn co.uk com.au co.jp co.in com.br com.mx co.nz com.sg com.hk com.tw co.kr
    co.za com.tr co.il com.ar com.cn
    """.split()
)
# How many brands one domain is compared with before giving up: a domain
# naming an everyday-word brand first ("delta-paypal") is still compared
# with the next one.
_MAX_BRAND_TRIES = 6
ESP_TRACKING_DOMAINS: frozenset[str] = frozenset(
    {
        "sendgrid.net", "list-manage.com", "mcsv.net", "mailchi.mp", "hubspotlinks.com",
        "hubspotemail.net", "mandrillapp.com", "sparkpostmail.com", "mailgun.org", "rs6.net",
        "exacttarget.com", "exct.net", "createsend.com", "cmail19.com", "cmail20.com",
        "klclick.com", "klaviyomail.com", "mjt.lu", "sendibt2.com", "sendibt3.com", "awstrack.me",
        "pstmrk.it", "customeriomail.com", "convertkit-mail.com", "convertkit-mail2.com",
        "mlsend.com", "emltrk.com", "mktomail.com", "intercom-clicks.com", "intercom-mail.com",
    }
)  # fmt: skip
RISKY_EXTENSIONS: frozenset[str] = frozenset(
    """
    exe scr com bat cmd pif msi msix appx js jse vbs vbe wsf wsh hta ps1 lnk iso img vhd vhdx jar
    apk dmg pkg html htm shtml svg xll docm xlsm pptm one reg cpl
    """.split()
)
ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({"zip", "rar", "7z", "gz", "tar", "ace"})
# The type a disguised name pretends to be ("invoice.pdf.exe").
_DOCUMENT_EXTENSIONS: frozenset[str] = frozenset(
    """
    pdf doc docx xls xlsx ppt pptx txt rtf csv odt ods jpg jpeg png gif bmp tif tiff heic mp3 mp4
    mov avi wav eml msg
    """.split()
)
# S4's signal codes (scaffold A8; and the older names of S2.md 4.5) as S2's
# hit codes, so the sweeper's adapter can pass S4's codes straight through.
LINK_CODE_MAP: Mapping[str, str] = {
    "ip_address": "link_ip",
    "local:ip_literal": "link_ip",
    "shortener": "link_shortener",
    "local:shortener": "link_shortener",
    "lookalike_characters": "link_lookalike",
    "lookalike_brand": "link_lookalike",
    "local:punycode": "link_lookalike",
    "local:lookalike": "link_lookalike",
    "credentials_in_url": "link_credentials",
    "local:credentials_in_url": "link_credentials",
    "suspicious_tld": "link_suspicious_tld",
    "local:suspicious_tld": "link_suspicious_tld",
    "script_link": "link_script",
    "text_mismatch": "link_text_mismatch",
}

# The word lists (S2.md 4.6) live in mail_facts, whose excerpt keeps the
# sentences that carry them; the same compiled patterns are scored here.
_URGENCY_RE = URGENCY_RE
_PAYMENT_RE = PAYMENT_RE
_CREDENTIALS_RE = CREDENTIALS_RE
_NAME_ADDRESS_RE = re.compile(r"[\w.%+'-]{1,64}@((?:[^\W_][\w-]{0,62}\.){1,10}[^\W\d_]{2,63})")
_SAFE_ARG_RE = re.compile(r"[A-Za-z0-9.\-:\[\]]{0,253}")
_REDACTED_MARK = "[REDACTED]"
_MATCH_CHARS = 4000


# -- The signal table ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignalSpec:
    code: str
    weight: int
    group: str
    sentence: str  # {arg} / {arg2} are filled with defanged safe values
    hard: bool = False
    bare: str = ""  # the sentence when the hit carries no arg: no placeholder at all
    partial: str = ""  # the sentence when it carries arg but no arg2


_SPECS: tuple[SignalSpec, ...] = (
    SignalSpec("auth_dmarc_fail", 3, "auth",
               "The sender's domain failed its own authentication check (DMARC), so the From address may be forged."),
    SignalSpec("auth_compauth_fail", 3, "auth",
               "Microsoft could not confirm the sender is who the From address says."),
    SignalSpec("auth_spf_fail", 2, "auth",
               "The server that sent it may not send mail for the sender's domain (SPF fail), and no signature "
               "vouches for it."),
    SignalSpec("auth_none", 1, "auth", "Nothing vouches for the sender: no passing SPF, DKIM or DMARC result."),
    SignalSpec("sender_mixed_script", 3, "sender",
               "The sender's domain uses look-alike letters from another alphabet ({arg}); it reads like {arg2}.",
               partial="The sender's domain uses look-alike letters from another alphabet ({arg}).",
               bare="The sender's domain uses look-alike letters from another alphabet."),
    SignalSpec("sender_lookalike_brand", 3, "sender", "The sender's domain {arg2} imitates {arg} but is not it.",
               partial="The sender's domain imitates {arg} but is not it.",
               bare="The sender's domain imitates a well-known company's domain."),
    SignalSpec("sender_lookalike_owner", 3, "sender",
               "The sender's domain {arg2} imitates your own organisation's domain {arg}.",
               partial="The sender's domain imitates your own organisation's domain {arg}.",
               bare="The sender's domain imitates your own organisation's domain."),
    SignalSpec("sender_unreadable", 3, "sender",
               "The From address can be read more than one way, so the sender you see may not be the one "
               "that was checked."),
    SignalSpec("display_name_address", 2, "sender",
               "The sender's name shows a different email address from the one it came from."),
    SignalSpec("display_name_brand", 2, "sender",
               "The sender's name says {brand}, but the mail did not come from {brand}'s domain.",
               bare="The sender's name claims a well-known company, but the mail did not come from its domain."),
    SignalSpec("reply_to_lookalike", 3, "reply", "Replies would go to {arg}, a look-alike domain.",
               bare="Replies would go to a look-alike domain."),
    SignalSpec("reply_to_freemail", 2, "reply",
               "Replies would go to a free webmail address ({arg}), not to the sender's domain.",
               bare="Replies would go to a free webmail address, not to the sender's domain."),
    SignalSpec("reply_to_mismatch", 1, "reply", "Replies would go to a different domain ({arg}) from the sender's.",
               bare="Replies would go to a different domain from the sender's."),
    SignalSpec("link_text_mismatch", 2, "links", "A link shows {arg2} but goes to {arg}.",
               partial="A link shows one site but goes to {arg}.",
               bare="A link shows one site but goes to another."),
    SignalSpec("link_script", 3, "links", "A link runs code or opens a file instead of a web page."),
    SignalSpec("link_ip", 2, "links", "A link goes to a bare IP address instead of a named site."),
    SignalSpec("link_shortener", 1, "links",
               "A link uses a link shortener ({arg}), which hides where it really goes.",
               bare="A link uses a link shortener, which hides where it really goes."),
    SignalSpec("link_lookalike", 3, "links", "A link goes to {arg}, which imitates a well-known site.",
               bare="A link goes to a site that imitates a well-known one."),
    SignalSpec("link_credentials", 3, "links", "A link hides a user name in front of the real site's address."),
    SignalSpec("link_suspicious_tld", 1, "links",
               "A link goes to a domain ending often used for throwaway sites ({arg}).",
               bare="A link goes to a domain ending often used for throwaway sites."),
    SignalSpec("link_malicious", 5, "links", "A link is on a list of dangerous sites ({arg}).", hard=True,
               bare="A link is on a list of dangerous sites."),
    SignalSpec("link_suspicious", 2, "links", "The link check marked a link as suspicious ({arg}).",
               bare="The link check marked a link as suspicious."),
    SignalSpec("form_in_body", 2, "links", "The email has a form to type into, which real companies don't send."),
    SignalSpec("attachment_risky", 2, "attachments",
               "An attachment is a file type often used to run harmful code (.{arg}).",
               bare="An attachment is a file type often used to run harmful code."),
    SignalSpec("attachment_disguised", 3, "attachments", "An attachment's name hides its real type (.{arg}).",
               bare="An attachment's name hides its real type."),
    SignalSpec("attachment_malicious", 5, "attachments",
               "VirusTotal reports an attachment as harmful ({arg} engines).", hard=True,
               bare="VirusTotal reports an attachment as harmful."),
    SignalSpec("attachment_suspicious", 2, "attachments", "VirusTotal reports an attachment as suspicious."),
    SignalSpec("pressure_payment", 2, "content",
               "It pushes you to act fast and asks for money, a payment change, gift cards or crypto."),
    SignalSpec("pressure_credentials", 2, "content",
               "It pushes you to act fast and asks you to sign in, verify your account or share a code."),
    SignalSpec("hidden_characters", 1, "content", "It contains {arg} hidden characters.",
               bare="It contains hidden characters."),
    SignalSpec("injection_text", 1, "content", "It contains text aimed at AI assistants, which Crawler removed."),
)  # fmt: skip
SIGNALS: Mapping[str, SignalSpec] = {spec.code: spec for spec in _SPECS}
_ORDER: Mapping[str, int] = {spec.code: index for index, spec in enumerate(_SPECS)}
# Any of these switches the authenticated-sender dampener off.
_DAMPENER_BREAKERS = ("sender_", "display_name_", "reply_", "link_", "attachment_", "form_in_body")


# -- Public types ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Hit:
    code: str
    weight: int
    arg: str = ""  # only values safe to show: a domain from BRAND_DOMAINS, an ASCII host, an extension, a count
    arg2: str = ""  # a second safe value: the sender's or the shown ASCII host, a Latin reading


@dataclass(frozen=True)
class LinkSignal:  # S4's answer, adapted (S2.md 4.5, scaffold A8)
    url: str
    verdict: str  # "malicious" | "suspicious" | "unknown"
    codes: tuple[str, ...]  # S2 hit codes, or S4's own codes (LINK_CODE_MAP)
    checked_remote: bool
    note: str = ""


@dataclass(frozen=True)
class FileSignal:  # S10's answer, adapted (S2.md 4.5, scaffold A9)
    ref: str
    verdict: str
    codes: tuple[str, ...]
    checked_remote: bool
    engines_malicious: int = 0
    note: str = ""


@dataclass(frozen=True)
class CheckContext:
    owner_domains: frozenset[str]  # registrable domains; never consumer domains


@dataclass(frozen=True)
class Assessment:
    hits: tuple[Hit, ...]
    score: int
    level: str  # "likely_scam" | "suspicious" | "none"
    notes: tuple[str, ...]  # fixed "not checked" sentences from S4/S10


# -- Small readers (facts arrive after the connector's PromptGuard) ------------------------------------


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any, limit: int = 100) -> list[Any]:
    return list(value[:limit]) if isinstance(value, (list, tuple)) else []


def _str(value: Any, limit: int = 2000) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _ascii(host: str) -> str:
    if not host:
        return ""
    try:
        return (lookalike.ascii_host(host) or "").lower()
    except Exception:  # a host the helper cannot encode reads as none
        return ""


def _unicode(host: str) -> str:
    try:
        return lookalike.decode_host(host) or ""
    except Exception:  # undecodable punycode reads as none
        return ""


def _registrable(host: str) -> str:
    return lookalike.registrable_domain(host) if host else ""


def _safe_arg(value: str) -> str:
    """Only plain ASCII host-like values ever reach a sentence."""
    value = (value or "").strip()
    return value if _SAFE_ARG_RE.fullmatch(value) else ""


def _fold(text: str) -> str:
    """Text as the word lists read it (mail_facts.wording_fold): compatibility
    forms folded, lower case, hidden characters dropped, look-alike letters
    read as Latin."""
    return wording_fold(text, _MATCH_CHARS)


def _dmarc_ok(auth: Mapping[str, Any]) -> bool:
    return auth.get("dmarc") == "pass" or auth.get("compauth") == "pass"


# -- The checks ----------------------------------------------------------------------------------------


def _auth_hits(auth: Mapping[str, Any]) -> list[Hit]:
    hits: list[Hit] = []
    spf, dkim, dmarc, compauth = (auth.get(k) for k in ("spf", "dkim", "dmarc", "compauth"))
    if dmarc == "fail":
        hits.append(Hit("auth_dmarc_fail", 3))
    if compauth == "fail":
        hits.append(Hit("auth_compauth_fail", 3))
    if spf == "fail" and dkim != "pass":
        hits.append(Hit("auth_spf_fail", 2))
    vouched = "pass" in (spf, dkim, dmarc, compauth)
    if not vouched and auth.get("source") != "internal":
        hits.append(Hit("auth_none", 1))
    return hits


def _brand_imitated(host_unicode: str, claimed: frozenset[str] = frozenset()) -> str:
    """The brand domain *host_unicode* imitates, or "". Domains a brand sends
    from, and its own name under a big country's ending (amazon.de), never
    reach here (_skips_lookalike); its name under any other ending
    (paypal.tk, amazon.shop) is an imitation. An everyday-word brand counts
    only with more to go on (_COMMON_WORD_BRANDS); *claimed* holds the
    domains of the brand the display name claims. A domain that names an
    everyday-word brand first ("delta-paypal") is compared with the next."""
    remaining: tuple[str, ...] = BRAND_DOMAINS
    for _ in range(_MAX_BRAND_TRIES):
        hit = lookalike.lookalike_of(host_unicode, remaining)
        if hit is None:
            return ""
        if _imitation_counts(host_unicode, hit.known, hit.rule, claimed):
            return hit.known
        remaining = tuple(known for known in remaining if known != hit.known)
    return ""


def _typo_like(host: str, known: str, rule: str) -> bool:
    """A near-miss or homograph of *known*'s name ("paypa1", "arnazon"), not
    the name itself (whichever rule name the shared helper gives it)."""
    return rule == "typo" or (rule == "brand_label" and known.split(".", 1)[0] not in host)


def _imitation_counts(host: str, known: str, rule: str, claimed: frozenset[str]) -> bool:
    """Whether a look-alike hit on *known* is an imitation worth a signal.

    Always: a typo or homograph of the brand (paypa1, arnazon), the brand's
    whole domain in front of another (apple.com.evil.tk), a phishing word
    beside it (chase-bank, dropboxdocs, docusign-secure) or a display name
    claiming the same brand. A distinctive brand's name also counts on its
    own as a whole label of the host (paypal.tk, paypal.evil.example). Its
    name glued into a longer one (nortonhealthcare, citizensbank,
    costcotravel, withgoogle) or as one part of a hyphenated one
    (paypal-community) is an ordinary company's or the brand's own domain as
    often as an imitation, and every authenticated mail from such a sender
    would be pushed as an alert, so it needs one of the signs above. An
    everyday-word brand (_COMMON_WORD_BRANDS) never counts by its name alone."""
    label = known.split(".", 1)[0]
    if _typo_like(host, known, rule):
        return True
    if known in claimed or _embeds(host, known) or _beside_phishing_word(host, label):
        return True
    if label in _COMMON_WORD_BRANDS:
        return False
    return label in host.split(".")


def _embeds(host: str, known: str) -> bool:
    """*host* carries *known*'s whole domain in front of another one
    ("apple.com.evil.tk", "paypal.com-secure.example")."""
    start = host.find(known)
    while start >= 0:
        end = start + len(known)
        if (start == 0 or host[start - 1] in ".-") and host[end : end + 1] in (".", "-"):
            return True
        start = host.find(known, start + 1)
    return False


def _regional_brand_site(registrable: str) -> bool:
    """A brand's own name under a big country's ending (amazon.de, paypal.co.uk)."""
    label, _, ending = registrable.partition(".")
    return label in _REGIONAL_BRAND_LABELS and ending in _REGIONAL_ENDINGS


def _brand_sends_from(registrable: str, domains: Sequence[str]) -> bool:
    if registrable in {_registrable(domain) for domain in domains}:
        return True
    label, _, ending = registrable.partition(".")
    return ending in _REGIONAL_ENDINGS and any(d.endswith(".com") and d.split(".", 1)[0] == label for d in domains)


def _phishing_word(word: str) -> bool:
    """A word phishing domains use, or its plural ("renewals", "accounts")."""
    return word in _PHISHING_WORDS or (len(word) > 3 and word.endswith("s") and word[:-1] in _PHISHING_WORDS)


def _beside_phishing_word(host: str, brand: str) -> bool:
    """The host pairs the brand with a word phishing domains use
    ("appleid-verify", "chase-online-alert", "office365-login",
    "mcafee-renewals", "apple.support")."""
    for part in re.split(r"[.\-_]", host):
        if _phishing_word(part):
            return True
        if brand in part and _phishing_word(re.sub(r"[0-9]", "", part.replace(brand, "", 1))):
            return True
    return False


def _known_imitated(host_unicode: str, known: Sequence[str]) -> str:
    if not known:
        return ""
    hit = lookalike.lookalike_of(host_unicode, tuple(known))
    if hit is None:
        return ""
    if _registrable(host_unicode).split(".", 1)[0] == hit.known.split(".", 1)[0]:
        return ""
    return hit.known


def _skips_lookalike(registrable: str, ctx: CheckContext) -> bool:
    return (
        not registrable
        or registrable in _BRAND_OWNED
        or _regional_brand_site(registrable)
        or registrable in lookalike.CONSUMER_MAIL_DOMAINS
        or registrable in ctx.owner_domains
        or lookalike.is_ip_literal(registrable)
    )


def _reading(host_unicode: str) -> str:
    reading = lookalike.mixed_script_reading(host_unicode)
    return reading if isinstance(reading, str) and reading.isascii() else ""


def _from_domains(facts: Mapping[str, Any]) -> tuple[str, str, bool]:
    """(the From address's domain, the domain the receiving provider checked
    as the From (its Authentication-Results header.from), whether the From is
    unreadable). Unreadable: a From whose text gave no single address
    (mail_facts keeps that text as the name and leaves the address empty), or
    one whose domain is not the domain the provider checked. Either way, the
    sender a mail app shows may not be the one DMARC vouched for. Internal
    Outlook mail is never unreadable: Graph may name an internal sender by an
    Exchange path rather than an address."""
    sender = _map(facts.get("from"))
    auth = _map(facts.get("auth"))
    domain = _ascii(_str(sender.get("domain"), 253) or _str(sender.get("address"), 300).rpartition("@")[2])
    checked = _ascii(_str(auth.get("header_from_domain"), 253))
    if auth.get("source") == "internal":
        return domain, checked, False
    no_address = not domain and bool(_str(sender.get("name"), 300).strip())
    differs = bool(domain and checked) and _registrable(domain) != _registrable(checked)
    return domain, checked, no_address or differs


def _domain_hits(domain: str, ctx: CheckContext, claimed: frozenset[str]) -> list[Hit]:
    registrable = _registrable(domain)
    shown = _unicode(domain)
    if not shown or _skips_lookalike(registrable, ctx):
        return []
    hits: list[Hit] = []
    if lookalike.mixed_script_reading(shown) is not None:
        hits.append(Hit("sender_mixed_script", 3, _safe_arg(domain), _safe_arg(_reading(shown))))
    brand = _brand_imitated(shown, claimed)
    if brand:
        hits.append(Hit("sender_lookalike_brand", 3, brand, _safe_arg(domain)))
    owner = _known_imitated(shown, sorted(ctx.owner_domains))
    if owner:
        hits.append(Hit("sender_lookalike_owner", 3, _safe_arg(owner), _safe_arg(domain)))
    return hits


def _sender_hits(facts: Mapping[str, Any], ctx: CheckContext) -> list[Hit]:
    """The sender's domain checks, and the display-name checks. An
    unreadable From is a sign of its own (sender_unreadable), and every
    domain it may stand for (its own and the one the provider checked) is
    still checked, so a From that parses two ways never skips the checks."""
    name = _str(_map(facts.get("from")).get("name"), 300)
    domain, checked, unreadable = _from_domains(facts)
    hits: list[Hit] = [Hit("sender_unreadable", 3)] if unreadable else []
    claimed = _brand_in_name(name)
    claimed_domains = frozenset(claimed[1]) if claimed is not None else frozenset()
    for candidate in dict.fromkeys(d for d in (domain, checked if unreadable else "") if d):
        hits.extend(_domain_hits(candidate, ctx, claimed_domains))
    shown_registrable = _registrable(checked if unreadable and checked else domain)
    hits.extend(_display_name_hits(name, shown_registrable, claimed))
    return hits


def _brand_in_name(name: str) -> Optional[tuple[str, tuple[str, ...]]]:
    """(the brand's first domain, its sending domains) for the first brand
    the display name claims, or None."""
    folded = "".join(lookalike.CONFUSABLES.get(ch, ch) for ch in unicodedata.normalize("NFKC", name))
    lower = " ".join(folded.lower().split())
    for label, display, phrases, domains in _BRANDS:
        if lower == display.lower():
            return domains[0], domains
        for phrase in phrases:
            if phrase.isupper():
                pattern, haystack = rf"(?<![A-Za-z0-9]){re.escape(phrase)}(?![A-Za-z0-9])", folded
            else:
                words = r"[\s._-]{0,3}".join(re.escape(w) for w in phrase.split())
                pattern, haystack = rf"(?<![a-z0-9]){words}(?![a-z0-9])", lower
            if re.search(pattern, haystack):
                return domains[0], domains
        # The brand glued to other words ("PayPalService"): only for long,
        # distinctive brand names that are themselves a phrase, so a person
        # called "Edward Norton" never reads as the antivirus company.
        if len(label) >= 6 and label in phrases and label not in _COMMON_WORD_BRANDS:
            if label in re.sub(r"[^a-z0-9]", "", lower):
                return domains[0], domains
    return None


def _display_name_hits(
    name: str, sender_registrable: str, claimed: Optional[tuple[str, tuple[str, ...]]]
) -> list[Hit]:
    if not name or not sender_registrable:
        return []
    hits: list[Hit] = []
    folded = unicodedata.normalize("NFKC", name).lower()
    for match in _NAME_ADDRESS_RE.finditer(folded[:300]):
        shown = _registrable(_ascii(match.group(1)))
        if shown and shown != sender_registrable:
            hits.append(Hit("display_name_address", 2))
            break
    if claimed is not None:
        primary, domains = claimed
        if not _brand_sends_from(sender_registrable, domains):
            hits.append(Hit("display_name_brand", 2, primary))
    return hits


def _reply_hits(facts: Mapping[str, Any], sender_registrable: str, ctx: CheckContext) -> list[Hit]:
    """The strongest Reply-To sign: a look-alike domain (of a brand, the
    person's organisation or the sender's own domain), then a free webmail
    address the sender's domain is not, then any other domain."""
    best: Optional[Hit] = None
    for address in _list(facts.get("reply_to"), 5):
        if not isinstance(address, str) or "@" not in address:
            continue
        domain = _ascii(address.rpartition("@")[2])
        registrable = _registrable(domain)
        if not domain or not registrable or registrable == sender_registrable:
            continue
        hit: Hit
        if registrable in lookalike.CONSUMER_MAIL_DOMAINS and sender_registrable not in lookalike.CONSUMER_MAIL_DOMAINS:
            hit = Hit("reply_to_freemail", 2, _safe_arg(registrable))
        elif _reply_imitates(domain, registrable, sender_registrable, ctx):
            hit = Hit("reply_to_lookalike", 3, _safe_arg(domain))
        else:
            hit = Hit("reply_to_mismatch", 1, _safe_arg(registrable))
        if best is None or hit.weight > best.weight:
            best = hit
    return [best] if best is not None else []


def _reply_imitates(domain: str, registrable: str, sender_registrable: str, ctx: CheckContext) -> bool:
    """A Reply-To domain written in look-alike letters, or imitating a
    brand, the person's organisation or the sender's own domain
    (ceo@northwind.com replying to northwlnd.com).

    Against the organisation's and the sender's own domains the name has to
    be imitated in the Reply-To's own registrable name (a typo or homograph,
    or the name as part of it for the organisation) or its whole domain put
    in front of another (northwind.com.evil.example). The name only as a
    subdomain of another service is an ordinary helpdesk Reply-To
    (support@acme.zendesk.com for hello@acme.com) and reads as
    reply_to_mismatch."""
    shown = _unicode(domain)
    if not shown or _skips_lookalike(registrable, ctx):
        return False
    if lookalike.mixed_script_reading(shown) is not None or _brand_imitated(shown):
        return True
    if ctx.owner_domains and _owner_name_imitated(shown, sorted(ctx.owner_domains)):
        return True
    if sender_registrable and sender_registrable not in ctx.owner_domains:
        hit = lookalike.lookalike_of(shown, (sender_registrable,))
        if hit is not None and _registrable(shown).split(".", 1)[0] != sender_registrable.split(".", 1)[0]:
            return _typo_like(shown, hit.known, hit.rule) or _embeds(shown, hit.known)
    return False


def _owner_name_imitated(host: str, owners: Sequence[str]) -> bool:
    hit = lookalike.lookalike_of(host, tuple(owners))
    if hit is None:
        return False
    label = hit.known.split(".", 1)[0]
    own_label = _registrable(host).split(".", 1)[0]
    if own_label == label:
        return False  # the organisation's name under another ending (as for the sender)
    return _typo_like(host, hit.known, hit.rule) or _embeds(host, hit.known) or label in own_label


def _has_userinfo(href: str) -> bool:
    try:
        netloc = urlsplit(href).netloc
    except ValueError:
        return False
    return "@" in netloc


def _link_hits(facts: Mapping[str, Any], auth: Mapping[str, Any]) -> list[Hit]:
    hits: list[Hit] = []
    dmarc_ok = _dmarc_ok(auth)
    for link in _list(facts.get("links"), 100):
        if not isinstance(link, Mapping):
            continue
        if _str(link.get("code"), 32) in ("script_link", "data_link", "file_link"):
            hits.append(Hit("link_script", 3))
            continue
        host = _ascii(_str(link.get("host"), 253))
        if _str(link.get("scheme"), 16) not in ("http", "https") or not host:
            continue
        href = _str(link.get("href"), 4096)
        if lookalike.is_ip_literal(host):
            hits.append(Hit("link_ip", 2, _safe_arg(host)))
        if _has_userinfo(href):
            hits.append(Hit("link_credentials", 3, _safe_arg(host)))
        shown = text_host(_str(link.get("text"), 300))
        if not shown:
            continue
        href_registrable = _registrable(host)
        if _registrable(shown) == href_registrable:
            continue
        if dmarc_ok and href_registrable in ESP_TRACKING_DOMAINS:
            continue  # marketing click tracking from an authenticated sender
        hits.append(Hit("link_text_mismatch", 2, _safe_arg(host), _safe_arg(shown)))
    if facts.get("has_form") is True:
        hits.append(Hit("form_in_body", 2))
    return hits


def _url_host(url: str) -> str:
    try:
        return _ascii(urlsplit(url).hostname or "")
    except ValueError:
        return ""


def _link_signal_hits(links: Sequence[LinkSignal]) -> tuple[list[Hit], list[str]]:
    hits: list[Hit] = []
    notes: list[str] = []
    for signal in links:
        host = _safe_arg(_url_host(signal.url))
        mapped = False
        for raw in signal.codes or ():
            code = raw if raw in SIGNALS else LINK_CODE_MAP.get(raw, "")
            if not code and isinstance(raw, str) and raw.startswith("local:lookalike:"):
                code = "link_lookalike"
            if not code or not code.startswith("link_") or code in ("link_malicious", "link_suspicious"):
                continue
            # The same (code, arg) as the local checks, so one link counts once.
            hits.append(Hit(code, SIGNALS[code].weight, "" if code == "link_script" else host))
            mapped = True
        if signal.verdict == "malicious":
            hits.append(Hit("link_malicious", 5, host))
        elif signal.verdict == "suspicious" and not mapped:
            hits.append(Hit("link_suspicious", 2, host))
        if signal.note:
            notes.append(signal.note)
    return hits, notes


def _extensions(name: str) -> list[str]:
    """The name's dot-separated endings, lower case; trailing dots and
    blanks dropped the way Windows drops them."""
    text = unicodedata.normalize("NFKC", name).lower().rstrip(". ")
    parts = [part.strip() for part in text.split(".")]
    return parts[1:] if len(parts) > 1 else []


def _attachment_kinds(attachment: Mapping[str, Any]) -> tuple[str, bool, bool, bool]:
    """(real extension, disguised, risky, archive) of one attachment."""
    name = _str(attachment.get("filename"), 2000)
    endings = _extensions(name)
    real = endings[-1] if endings else ""
    real = real if re.fullmatch(r"[a-z0-9]{1,10}", real) else ""
    risky = real in RISKY_EXTENSIONS
    head = name.rpartition(".")[0]
    disguised = bool(
        (risky and len(endings) >= 2 and endings[-2] in _DOCUMENT_EXTENSIONS)
        or (risky and len(head) - len(head.rstrip()) >= 3)  # "report.docx      .js"
        # mail_facts marks hidden or bidi characters in a name with U+FFFD
        # ("invoice<RLO>fdp.exe" shows as "invoiceexe.pdf" in a mail app);
        # the answer's attachments carry no separate count (scaffold A7).
        or HIDDEN_MARK in name
    )
    return real, disguised, risky, real in ARCHIVE_EXTENSIONS


def _attachment_hits(facts: Mapping[str, Any]) -> tuple[list[Hit], list[Hit]]:
    """(hits, archive hits): archives count (weight 1 under attachment_risky)
    only when the mail is flagged without them."""
    hits: list[Hit] = []
    archives: list[Hit] = []
    for attachment in _list(facts.get("attachments"), 20):
        if not isinstance(attachment, Mapping):
            continue
        real, disguised, risky, archive = _attachment_kinds(attachment)
        if disguised:
            hits.append(Hit("attachment_disguised", 3, real))
        if risky:
            hits.append(Hit("attachment_risky", 2, real))
        elif archive:
            archives.append(Hit("attachment_risky", 1, real))
    return hits, archives


def _content_hits(facts: Mapping[str, Any]) -> list[Hit]:
    subject = _str(facts.get("subject"), 600)
    text = _str(facts.get("text"), 4000)
    hits: list[Hit] = []
    blob = _fold(subject + "\n" + text)
    if _URGENCY_RE.search(blob):
        if _PAYMENT_RE.search(blob):
            hits.append(Hit("pressure_payment", 2))
        if _CREDENTIALS_RE.search(blob):
            hits.append(Hit("pressure_credentials", 2))
    hidden = _count(facts.get("hidden_chars"))
    if hidden >= HIDDEN_CHARS_MIN:
        hits.append(Hit("hidden_characters", 1, str(min(hidden, 99999))))
    if _REDACTED_MARK in subject or _REDACTED_MARK in text:
        hits.append(Hit("injection_text", 1))
    return hits


# -- Scoring --------------------------------------------------------------------------------------------


def _strength(hit: Hit) -> tuple[int, int, int]:
    spec = SIGNALS.get(hit.code)
    return (0 if spec is not None and spec.hard else 1, -hit.weight, _ORDER.get(hit.code, len(_ORDER)))


def _finish(hits: Sequence[Hit]) -> tuple[Hit, ...]:
    """Known codes only, one hit per (code, arg), strongest first, capped."""
    seen: set[tuple[str, str]] = set()
    kept: list[Hit] = []
    for hit in sorted(hits, key=_strength):
        spec = SIGNALS.get(hit.code)
        key = (hit.code, hit.arg)
        if spec is None or key in seen:
            continue
        seen.add(key)
        kept.append(replace(hit, weight=max(0, min(hit.weight, spec.weight))))
    return tuple(kept[:MAX_HITS])


def _score(hits: Sequence[Hit]) -> int:
    groups: dict[str, int] = {}
    hard = 0
    for hit in hits:
        spec = SIGNALS.get(hit.code)
        if spec is None:
            continue
        if spec.hard:
            hard += hit.weight
        else:
            groups[spec.group] = groups.get(spec.group, 0) + hit.weight
    return hard + sum(min(GROUP_CAPS.get(group, 0), total) for group, total in groups.items())


def _level(score: int, hits: Sequence[Hit]) -> str:
    if any(hit.code in HARD_CODES for hit in hits) or score >= LIKELY_SCORE:
        return "likely_scam"
    if score >= FLAG_SCORE:
        return "suspicious"
    return "none"


def level_for(hits: Sequence[Hit]) -> tuple[int, str]:
    """(score, level): likely_scam on any hard hit or score >= LIKELY_SCORE; suspicious from FLAG_SCORE.
    Each group is capped by GROUP_CAPS; hard hits always count in full."""
    score = _score(hits)
    return score, _level(score, hits)


def _dampened(hits: Sequence[Hit], auth: Mapping[str, Any]) -> bool:
    """An authenticated sender whose only signs are wording or its own
    authentication results is never flagged (S2.md 4.6)."""
    return _dmarc_ok(auth) and not any(hit.code.startswith(_DAMPENER_BREAKERS) for hit in hits)


def _assess(hits: Sequence[Hit], auth: Mapping[str, Any]) -> tuple[int, str]:
    score, _ = level_for(hits)
    if _dampened(hits, auth):
        score = min(score, FLAG_SCORE - 1)
    return score, _level(score, hits)


def _dedupe_notes(notes: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(n for n in notes if isinstance(n, str) and n))[:5]


def evaluate(
    facts: Mapping[str, Any],
    ctx: CheckContext,
    *,
    links: Sequence[LinkSignal] = (),
    notes: Sequence[str] = (),
) -> Assessment:
    """Every local signal plus S4's link verdicts, capped per group, then the dampener and the level.
    *notes* are the caller's own fixed "not checked" sentences (LINKS_NOT_CHECKED_NOTE when S4
    failed); they never lower anything. Never raises on a hostile answer: a part that cannot be
    read gives no hit."""
    facts = _map(facts)
    auth = _map(facts.get("auth"))
    domain, checked, unreadable = _from_domains(facts)
    found: list[Hit] = []
    found += _auth_hits(auth)
    found += _sender_hits(facts, ctx)
    found += _reply_hits(facts, _registrable(domain or (checked if unreadable else "")), ctx)
    found += _link_hits(facts, auth)
    signal_hits, signal_notes = _link_signal_hits(links)
    found += signal_hits
    attachment_hits, archive_hits = _attachment_hits(facts)
    found += attachment_hits
    found += _content_hits(facts)

    hits = _finish(found)
    score, level = _assess(hits, auth)
    if archive_hits and level != "none":
        hits = _finish([*hits, *archive_hits])
        score, level = _assess(hits, auth)
    return Assessment(hits=hits, score=score, level=level, notes=_dedupe_notes([*signal_notes, *notes]))


def with_files(assessment: Assessment, files: Sequence[FileSignal]) -> Assessment:
    """The assessment with S10's attachment verdicts added (review phase). A verdict can only add:
    the level and score never go down."""
    added: list[Hit] = []
    notes = list(assessment.notes)
    for signal in files:
        if signal.verdict == "malicious":
            engines = signal.engines_malicious
            count = str(engines) if isinstance(engines, int) and not isinstance(engines, bool) and engines > 0 else ""
            added.append(Hit("attachment_malicious", 5, count))
        elif signal.verdict == "suspicious":
            added.append(Hit("attachment_suspicious", 2))
        if signal.note:
            notes.append(signal.note)
    if not added:
        return replace(assessment, notes=_dedupe_notes(notes))
    hits = _finish([*assessment.hits, *added])
    score, level = level_for(hits)
    if VERDICT_ORDER.index(_as_verdict(level)) < VERDICT_ORDER.index(_as_verdict(assessment.level)):
        level = assessment.level
    return Assessment(hits=hits, score=max(score, assessment.score), level=level, notes=_dedupe_notes(notes))


def has_hard_hit(hits: Sequence[Hit]) -> bool:
    return any(hit.code in HARD_CODES for hit in hits)


# -- What may stay off the channels (reviews SEC-M1, FEA-SF2; scaffold A33) --------------------------------


def may_go_quiet(hits: Sequence[Hit], auth: Mapping[str, Any]) -> bool:
    """True only when every hit code is in SOFT_CODES and auth["dmarc"] == "pass" or
    auth["compauth"] == "pass" (review SEC-M1). The caller also needs a no_signs review.
    No hits at all is not a reason to go quiet (a finding always has some)."""
    if not hits:
        return False
    if any(hit.code not in SOFT_CODES for hit in hits):
        return False
    return _dmarc_ok(_map(auth))


def pushes_without_review(level: str, hits: Sequence[Hit]) -> bool:
    """When no AI review ran: True for likely_scam, and for suspicious with any hit outside
    NOISY_CODES; False means "list it on the tab and count it in the daily summary" (FEA-SF2)."""
    if level == "likely_scam":
        return True
    if level != "suspicious":
        return False
    return any(hit.code not in NOISY_CODES for hit in hits)


def _as_verdict(level: Optional[str]) -> str:
    return level if level in VERDICT_ORDER else "no_signs"


def combine(level: str, review_verdict: Optional[str]) -> str:
    """The final verdict (scaffold A33): the stricter of Crawler's own level and the review's
    verdict, on the order no_signs < suspicious < likely_scam. The review may raise suspicious to
    likely_scam; it never lowers a level, so a no_signs review leaves "suspicious" as it is. No
    review (None, or a verdict outside the three) leaves the level. Going quiet is a separate
    decision (goes_quiet). services/mail_scan/review.combine(level, review) passes
    ``review.verdict`` for a Review and None for a ReviewSkipped."""
    if review_verdict not in VERDICT_ORDER:
        return level
    if level not in VERDICT_ORDER:
        return review_verdict if review_verdict != "no_signs" else level
    stricter = max(VERDICT_ORDER.index(level), VERDICT_ORDER.index(review_verdict))
    return VERDICT_ORDER[stricter]


def goes_quiet(level: str, review_verdict: Optional[str], hits: Sequence[Hit], auth: Mapping[str, Any]) -> bool:
    """S2.md 4.3 step 4.f: a suspicious finding goes quiet (no push, no card) only after a
    no_signs review AND may_go_quiet. Any other no_signs review still alerts."""
    return review_verdict == "no_signs" and level == "suspicious" and may_go_quiet(hits, auth)


# -- What leaves this module -----------------------------------------------------------------------------


def owner_domains(user_email: Optional[str], account_domain: Optional[str]) -> frozenset[str]:
    """Registrable domains of the person's sign-in address and the mailbox's own address,
    minus lookalike.CONSUMER_MAIL_DOMAINS."""
    found: set[str] = set()
    for value in (user_email, account_domain):
        if not isinstance(value, str) or not value.strip():
            continue
        domain = _ascii(value.strip().rpartition("@")[2])
        registrable = _registrable(domain)
        if (
            registrable
            and "." in registrable
            and registrable not in lookalike.CONSUMER_MAIL_DOMAINS
            and not lookalike.is_ip_literal(registrable)
        ):
            found.add(registrable)
    return frozenset(found)


def urls_for_reputation(facts: Mapping[str, Any]) -> list[str]:
    """At most MAX_LINKS_FOR_REPUTATION (5) http(s) link URLs: the first link of each registrable
    host, ESP_TRACKING_DOMAINS hosts left out, userinfo, query and fragment removed (a
    password-reset token in a query never leaves the computer; S4's lookup_url also drops a path
    that carries a token, review SEC-F10). Paths are kept: host-only lookups would miss phishing
    pages listed by path on compromised sites."""
    urls: list[str] = []
    seen: set[str] = set()
    for link in _list(_map(facts).get("links"), 100):
        if not isinstance(link, Mapping) or _str(link.get("code"), 32):
            continue
        scheme = _str(link.get("scheme"), 16)
        host = _ascii(_str(link.get("host"), 253))
        if scheme not in ("http", "https") or not host:
            continue
        registrable = _registrable(host)
        if registrable in seen or registrable in ESP_TRACKING_DOMAINS:
            continue
        try:
            parts = urlsplit(_str(link.get("href"), 4096))
            port = parts.port
        except ValueError:
            continue
        netloc = f"[{host}]" if ":" in host and lookalike.is_ip_literal(host) else host
        if port is not None and port not in (80, 443):
            netloc += f":{port}"
        path = parts.path or "/"
        seen.add(registrable)
        urls.append(f"{scheme}://{netloc}{path}"[:2048])
        if len(urls) >= MAX_LINKS_FOR_REPUTATION:
            break
    return urls


def risky_attachments(facts: Mapping[str, Any], *, limit: int = 2) -> list[Mapping[str, Any]]:
    """The attachments worth an S10 lookup, riskiest first (disguised, then risky type, then
    archives); only those with a ref the hash action can read."""
    ranked: list[tuple[int, int, Mapping[str, Any]]] = []
    for index, attachment in enumerate(_list(_map(facts).get("attachments"), 20)):
        if not isinstance(attachment, Mapping) or not _str(attachment.get("ref"), 255):
            continue
        _, disguised, risky, archive = _attachment_kinds(attachment)
        rank = 0 if disguised else 1 if risky else 2 if archive else -1
        if rank >= 0:
            ranked.append((rank, index, attachment))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [attachment for _, _, attachment in ranked[: max(0, limit)]]


def _sentence(hit: Hit) -> str:
    """The hit's fixed sentence. A value is filled in only when it is a plain
    host-like value, defanged so no chat app links it; without one the
    sentence's shorter form is used."""
    spec = SIGNALS[hit.code]
    if hit.code == "display_name_brand":
        brand = _DISPLAY_BY_DOMAIN.get(hit.arg, "")
        return spec.sentence.format(brand=brand) if brand else spec.bare
    arg = trigger_facts.defang(_safe_arg(hit.arg)) if hit.arg else ""
    arg2 = trigger_facts.defang(_safe_arg(hit.arg2)) if hit.arg2 else ""
    template = spec.sentence
    if "{arg2}" in template and not arg2:
        template = spec.partial if arg else spec.bare
    if "{arg}" in template and not arg:
        template = spec.bare
    return template.format(arg=arg, arg2=arg2)


def reason_lines(hits: Sequence[Hit]) -> list[str]:
    """One fixed sentence per hit, strongest first, at most 5; args defanged (facts.defang)."""
    lines: list[str] = []
    for hit in sorted((h for h in hits if h.code in SIGNALS), key=_strength):
        line = _sentence(hit)
        if line not in lines:
            lines.append(line)
        if len(lines) >= MAX_REASON_LINES:
            break
    return lines


def hit_rows(hits: Sequence[Hit]) -> list[dict[str, Any]]:
    """The hits as mail_scam_findings.signals stores them (at most MAX_HITS)."""
    rows: list[dict[str, Any]] = []
    for hit in _finish(hits):
        row: dict[str, Any] = {"code": hit.code, "weight": hit.weight, "arg": hit.arg}
        if hit.arg2:
            row["arg2"] = hit.arg2
        rows.append(row)
    return rows


def hits_from_rows(rows: Any) -> tuple[Hit, ...]:
    """Hits read back from a stored signals list: unknown codes dropped, weights held to the
    table's, args kept only when they are plain host-like values."""
    hits: list[Hit] = []
    for row in _list(rows, MAX_HITS * 2):
        if not isinstance(row, Mapping):
            continue
        code = row.get("code")
        if not isinstance(code, str) or code not in SIGNALS:
            continue
        weight = row.get("weight")
        spec_weight = SIGNALS[code].weight
        if not isinstance(weight, int) or isinstance(weight, bool) or not 0 <= weight <= spec_weight:
            weight = spec_weight
        hits.append(Hit(code, weight, _safe_arg(_str(row.get("arg"), 253)), _safe_arg(_str(row.get("arg2"), 253))))
    return _finish(hits)


def _clip(value: Any, limit: int) -> str:
    text = _str(value, limit * 4)
    text = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "\u2026"


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def display_facts(facts: Mapping[str, Any]) -> dict[str, Any]:
    """What a finding row keeps: from name/address/domain, reply-to domains, subject, received,
    link hosts (at most 10), attachments (name, type, size, ref; at most 5), auth summary
    (`"auth": {spf, dkim, dmarc, compauth, spf_domain, dkim_domains, header_from_domain}`: what
    may_go_quiet and actions.from_domain_vouched read later; reviews SEC-M1, SEC-F6).
    Capped at 4 KB like triggers.facts._sanitised (facts.py:197)."""
    facts = _map(facts)
    sender = _map(facts.get("from"))
    auth = _map(facts.get("auth"))
    reply_domains: list[str] = []
    for address in _list(facts.get("reply_to"), 5):
        domain = _ascii(_str(address, 300).rpartition("@")[2]) if isinstance(address, str) else ""
        if domain and domain not in reply_domains:
            reply_domains.append(domain)
    hosts: list[str] = []
    for link in _list(facts.get("links"), 100):
        host = _ascii(_str(_map(link).get("host"), 253))
        if host and host not in hosts:
            hosts.append(host)
        if len(hosts) >= DISPLAY_LINK_HOSTS:
            break
    attachments = [
        {
            "name": _clip(_map(a).get("filename"), 120),
            "type": _clip(_map(a).get("mime_type"), 80),
            "size": _map(a).get("size") if isinstance(_map(a).get("size"), int) else None,
            "ref": _clip(_map(a).get("ref"), 255),
        }
        for a in _list(facts.get("attachments"), DISPLAY_ATTACHMENTS)
    ]
    dkim_domains = [d for d in (_ascii(_str(x, 253)) for x in _list(auth.get("dkim_domains"), 5)) if d]
    shaped: dict[str, Any] = {
        "from": {
            "name": _clip(sender.get("name"), 80),
            "address": _clip(sender.get("address"), 254),
            "domain": _ascii(_str(sender.get("domain"), 253)),
        },
        "reply_to_domains": reply_domains,
        "subject": _clip(facts.get("subject"), 300),
        "received": _clip(facts.get("received"), 40),
        "link_hosts": hosts,
        "attachments": attachments,
        "auth": {
            "source": _clip(auth.get("source"), 32),
            "spf": _clip(auth.get("spf"), 16),
            "dkim": _clip(auth.get("dkim"), 16),
            "dmarc": _clip(auth.get("dmarc"), 16),
            "compauth": _clip(auth.get("compauth"), 16),
            "spf_domain": _ascii(_str(auth.get("spf_domain"), 253)),
            "dkim_domains": dkim_domains,
            "header_from_domain": _ascii(_str(auth.get("header_from_domain"), 253)),
        },
    }
    while _json_size(shaped) > DISPLAY_FACTS_MAX_BYTES:
        if len(shaped["link_hosts"]) > 1:
            shaped["link_hosts"].pop()
        elif len(shaped["attachments"]) > 1:
            shaped["attachments"].pop()
        elif len(shaped["reply_to_domains"]) > 1:
            shaped["reply_to_domains"].pop()
        elif len(shaped["subject"]) > 40:
            shaped["subject"] = _clip(shaped["subject"], len(shaped["subject"]) // 2)
        elif len(shaped["from"]["name"]) > 20:
            shaped["from"]["name"] = _clip(shaped["from"]["name"], len(shaped["from"]["name"]) // 2)
        elif shaped["attachments"] and len(shaped["attachments"][0]["name"]) > 40:
            shaped["attachments"][0]["name"] = _clip(shaped["attachments"][0]["name"], 40)
        else:
            shaped["link_hosts"], shaped["attachments"], shaped["reply_to_domains"] = [], [], []
            break
    return shaped


def _hosts_only(text: str) -> str:
    """Every URL in *text* replaced by its host: the model never gets a full link."""

    def one(match: re.Match[str]) -> str:
        url = match.group(0)
        target = url if "://" in url else f"http://{url}"
        return _url_host(target) or "(a link)"

    return trigger_facts._URL_RE.sub(one, text)


def review_excerpt(facts: Mapping[str, Any]) -> dict[str, Any]:
    """{"text": <=1500 chars, "links": [{"shows","goes_to"}] hosts only (<=10)} for review_input.
    A shown text that names a site is reduced to that site's host too. The text is cut the way
    the facts' excerpt is (mail_facts.wording_excerpt), so the passages carrying pressure wording
    reach the AI review even when the excerpt is longer than 1,500 characters."""
    facts = _map(facts)
    text = wording_excerpt(_hosts_only(_str(facts.get("text"), 4000)), EXCERPT_CHARS)
    links: list[dict[str, str]] = []
    for link in _list(facts.get("links"), 100):
        link = _map(link)
        host = _ascii(_str(link.get("host"), 253))
        if _str(link.get("scheme"), 16) not in ("http", "https") or not host:
            continue
        raw_text = _str(link.get("text"), 300)
        shows = text_host(raw_text) or _clip(_hosts_only(raw_text), 80)
        entry = {"shows": shows, "goes_to": host}
        if entry not in links:
            links.append(entry)
        if len(links) >= EXCERPT_LINKS:
            break
    return {"text": text, "links": links}
