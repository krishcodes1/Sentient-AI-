"""The scam check's answer: the fixed verdict rules, Crawler's reasons, the advice table, the
notes on what was not checked, and the three renderers (plain text for Telegram and Slack,
Markdown for the web chat, JSON for the Security page and the security.check_scam tool).

Why it exists: the verdict a person acts on must not depend on what the checked message
persuaded a model to say. The rules below decide from Crawler's own findings; the AI review may
raise that verdict but never lower it. Every sentence a person reads here is fixed text with
hosts in punycode; the AI's own reasons (already filtered by review.filter_reasons) are kept
apart under "Your AI provider also noted:", never mixed into Crawler's list (review SEC-M2).
The answer is never "safe": the best it says is "No signs of a scam found", always with "No
check can prove a message is safe."

Pure: no network, no model, no database. Plain text is defanged with page_watch.defang so no
host or address in it can become a link; Markdown puts hosts in code spans and escapes the AI's
reasons; JSON keeps only ASCII hosts and no look-alike or invisible character.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Iterable, Literal, Optional, Sequence

from services.agent.prompt_guard import _HOMOGLYPH_MAP, _INVISIBLE_CHARS
from services.notifications.page_watch import defang
from services.security.scam_signals import (
    MAX_TEXT_CHARS,
    SIGNAL_STRENGTHS,
    Signal,
    Strength,
    ascii_host,
    display_url,
    url_host,
)

if TYPE_CHECKING:
    from services.scam_check.review import Review
    from services.scam_check.service import LinkFinding, ScamCheckRequest, ScamCheckResult, Verdict

ORDER: dict[str, int] = {"no_signs_found": 0, "suspicious": 1, "likely_scam": 2}
VERDICTS: tuple[str, ...] = ("likely_scam", "suspicious", "no_signs_found", "not_checked")

HEADLINES: dict[str, str] = {
    "likely_scam": "\U0001f6a9 Likely a scam",
    "suspicious": "\u26a0\ufe0f Suspicious, be careful",
    "no_signs_found": "\U0001f50e No signs of a scam found",
    "not_checked": "\u2754 I couldn't check this",
}
# The same headlines without the emoji, for JSON (the Security tab draws its own icon).
HEADLINE_TEXT: dict[str, str] = {
    "likely_scam": "Likely a scam",
    "suspicious": "Suspicious, be careful",
    "no_signs_found": "No signs of a scam found",
    "not_checked": "I couldn't check this",
}
CAVEAT = "No check can prove a message is safe."
MAX_REASONS = 6
MAX_LINK_REASONS = 3
MAX_AI_REASONS = 3
MAX_ADVICE = 4

# ── Links ────────────────────────────────────────────────────────────────

# S4's codes (S4.md 4.2) and the older names of S3 4.7, read the same way.
LOOKALIKE_CODES = frozenset(
    {"lookalike", "homoglyph", "punycode", "lookalike_characters", "lookalike_brand", "brand_in_address", "link_lookalike"}
)
_LETTER_CODES = frozenset({"homoglyph", "punycode", "lookalike_characters"})
_WEAK_LINK_SENTENCES: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"shortener"}), "{subject} is a link shortener that hides where it goes."),
    (frozenset({"ip_literal", "ip_address"}), "{subject} is a bare IP address instead of a name."),
    (frozenset({"suspicious_tld"}), "{subject} ends in an address type often used by scam sites."),
    (frozenset({"userinfo", "credentials_in_url"}), "{subject} hides its real address behind a user name."),
)
_THREATS: dict[str, str] = {
    "SOCIAL_ENGINEERING": "phishing",
    "MALWARE": "malware",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful apps",
}


def _link_host(link: "LinkFinding") -> str:
    return ascii_host(link.host) or url_host(link.shown) or "an unreadable address"


def _codes(link: "LinkFinding") -> set[str]:
    return {str(code).lower() for code in (link.codes or ())}


def link_code(link: "LinkFinding") -> Optional[str]:
    """The signal code a checked link raises: link_malicious (Google's list or another
    "malicious" answer), link_lookalike (a look-alike or an imitation of a known site),
    link_suspicious (any other risky link), or None for a link with nothing found or one that
    was not checked (a not-checked link counts neither way)."""
    if link.level == "malicious":
        return "link_malicious"
    if link.level != "suspicious":
        return None
    if _codes(link) & LOOKALIKE_CODES or link.looks_like:
        return "link_lookalike"
    return "link_suspicious"


def _threat(link: "LinkFinding") -> tuple[str, str]:
    """(source name, threat words) for a listed link, from codes like
    "safe_browsing:SOCIAL_ENGINEERING" or a bare "MALWARE"; ("", "") when no list named it."""
    source, words = "", ""
    for code in link.codes or ():
        name, _, kind = str(code).partition(":")
        kind = (kind or name).strip().upper()
        if name.lower() == "web_risk":
            source = source or "Google Web Risk"
        elif name.lower() == "safe_browsing":
            source = source or "Google Safe Browsing"
        if kind in _THREATS and not words:
            words = _THREATS[kind]
    if not source:
        checked = {str(s).lower() for s in link.checked_by or ()}
        if "safe_browsing" in checked:
            source = "Google Safe Browsing"
        elif "web_risk" in checked:
            source = "Google Web Risk"
    return source, words


def link_sentence(link: "LinkFinding") -> Optional[str]:
    """Crawler's fixed sentence for a flagged link (hosts in punycode), or None for a link with
    nothing found or not checked."""
    code = link_code(link)
    if code is None:
        return None
    host = _link_host(link)
    subject = {
        "qr": f"The QR code's link {host}",
        "sender": f"The sender's domain {host}",
    }.get(link.origin, f"The link {host}")
    if code == "link_malicious":
        source, words = _threat(link)
        if source:
            return f"{source} lists {host} as {words or 'harmful'}."
        return f"Crawler's link check flagged {host}."
    codes = _codes(link)
    if code == "link_lookalike":
        looks_like = ascii_host(link.looks_like) if link.looks_like else None
        letters = bool(codes & _LETTER_CODES) or host.startswith("xn--") or ".xn--" in host
        if letters and looks_like:
            return f"{subject} uses look-alike letters, imitating {looks_like}."
        if letters:
            return f"{subject} uses look-alike letters."
        if looks_like:
            return f"{subject} imitates {looks_like} but isn't it."
        return f"{subject} imitates another site."
    for names, template in _WEAK_LINK_SENTENCES:
        if codes & names:
            return template.format(subject=subject)
    return f"Crawler's link check flagged {host}."


# ── Verdict ──────────────────────────────────────────────────────────────


def _strengths(signals: Sequence[Signal], links: Sequence["LinkFinding"]) -> dict[str, Strength]:
    """Each distinct code once, with its weight: a trick repeated is one sign, not two."""
    found: dict[str, Strength] = {}
    for signal in signals:
        found.setdefault(signal.code, signal.strength)
    for link in links:
        code = link_code(link)
        if code:
            found.setdefault(code, SIGNAL_STRENGTHS[code])
    return found


def rule_verdict(signals: Sequence[Signal], links: Sequence["LinkFinding"]) -> str:
    """The rules alone (S3 4.6): likely_scam for any decisive sign, two strong, or one strong
    and two weak; suspicious for one strong or two weak; else no_signs_found."""
    strengths = list(_strengths(signals, links).values())
    decisive = strengths.count("decisive")
    strong = strengths.count("strong")
    weak = strengths.count("weak")
    if decisive or strong >= 2 or (strong == 1 and weak >= 2):
        return "likely_scam"
    if strong == 1 or weak >= 2:
        return "suspicious"
    return "no_signs_found"


def combine(
    signals: Sequence[Signal],
    links: Sequence["LinkFinding"],
    review: Optional["Review"],
    *,
    analysed: bool,
) -> tuple["Verdict", "Verdict"]:
    """(final, rule-only) per 4.6: the rules' verdict, raised (never lowered) by the AI's;
    not_checked when nothing could be analysed and no rule fired. *analysed* is True when there
    was text, a picture the AI looked at, a link or a checked file; a review only runs on
    something, so the service passes analysed=True whenever one did."""
    rule = rule_verdict(signals, links)
    if not analysed and rule == "no_signs_found":
        return "not_checked", "not_checked"
    final = rule
    if review is not None and ORDER.get(review.verdict, -1) > ORDER[rule]:
        final = review.verdict
    return final, rule  # type: ignore[return-value]  # both are members of ORDER


_RANK: dict[str, int] = {"decisive": 0, "strong": 1, "weak": 2}


def reasons_for(signals: Sequence[Signal], links: Sequence["LinkFinding"]) -> tuple[str, ...]:
    """<= 6 of Crawler's own sentences, strongest first: in each weight, flagged links (at most
    3 in all, one per host) before the other signs; a code is said once."""
    flagged: list[tuple[Strength, str]] = []
    hosts: set[str] = set()
    ranked = sorted(
        (link for link in links if link_code(link)),
        key=lambda link: _RANK[SIGNAL_STRENGTHS[link_code(link) or "link_suspicious"]],
    )
    for link in ranked:
        host = _link_host(link)
        sentence = link_sentence(link)
        if not sentence or host in hosts:
            continue
        hosts.add(host)
        flagged.append((SIGNAL_STRENGTHS[link_code(link) or "link_suspicious"], sentence))
        if len(flagged) >= MAX_LINK_REASONS:
            break
    seen: set[str] = set()
    own: list[Signal] = []
    for signal in signals:
        if signal.code not in seen:
            seen.add(signal.code)
            own.append(signal)
    out: list[str] = []
    for weight in ("decisive", "strong", "weak"):
        out.extend(sentence for strength, sentence in flagged if strength == weight)
        out.extend(s.text for s in own if s.strength == weight)
    return tuple(dict.fromkeys(out))[:MAX_REASONS]



def ai_reasons_for(review: Optional["Review"], scanner: Any) -> tuple[tuple[str, ...], bool]:
    """filter_reasons over the review's reasons, at most 3: (ScamCheckResult.ai_reasons,
    withheld)."""
    if review is None or not review.reasons:
        return (), False
    from services.scam_check.review import filter_reasons

    kept, withheld = filter_reasons(review.reasons, scanner)
    return kept[:MAX_AI_REASONS], withheld


# ── Advice (fixed table, S3 4.6) ─────────────────────────────────────────

ADVICE_DONT_CLICK = "Don't click links or scan QR codes in it."
ADVICE_DONT_SIGN_IN = "Don't sign in from the message. Open the company's app or type its address yourself."
ADVICE_NO_CODES = "Never share a code sent to your phone or email; no real company asks for it."
ADVICE_DONT_PAY = (
    "Don't pay or send card details from the message. Real companies and agencies don't ask for "
    "gift cards, crypto or wire transfers."
)
ADVICE_NO_REMOTE = "Don't install apps or give anyone remote access to your device."
ADVICE_THREATS = "Government agencies and banks don't threaten arrest or fines by text or email."
ADVICE_ALREADY = (
    "If you already clicked, paid, or shared a password or code, change that password and call "
    "your bank now."
)
ADVICE_UNSURE = "If you're unsure, contact the sender using a phone number or website you already trust."
ADVICE_NO_SIGNS = (
    f"{CAVEAT} If it asks for money, a password or a code, check with the sender another way first."
)
ADVICE_NOT_CHECKED = "Try again with the text pasted in, or the link itself."

_SIGN_IN_CODES = frozenset({"credential_ask", "link_lookalike", "anchor_mismatch", "sender_impersonation"})
_PAY_CODES = frozenset({"payment_odd", "financial_ask", "delivery_fee"})
_PAY_ASKS = frozenset({"gift_card", "crypto", "card", "bank"})


def advice_for(verdict: str, codes: Iterable[str], asks_for: Iterable[str]) -> tuple[str, ...]:
    """<= 4 lines from the fixed table, in its order, deduplicated. Never the AI's words: the
    AI only contributes which fixed lines apply (asks_for)."""
    have = set(codes)
    asks = set(asks_for)
    flagged = verdict in ("likely_scam", "suspicious")
    lines: list[str] = []
    if flagged:
        lines.append(ADVICE_DONT_CLICK)
    if have & _SIGN_IN_CODES or "password" in asks:
        lines.append(ADVICE_DONT_SIGN_IN)
    if "code_ask" in have or "code" in asks:
        lines.append(ADVICE_NO_CODES)
    if have & _PAY_CODES or asks & _PAY_ASKS:
        lines.append(ADVICE_DONT_PAY)
    if "remote_access" in have or "remote_access" in asks:
        lines.append(ADVICE_NO_REMOTE)
    if "threat" in have:
        lines.append(ADVICE_THREATS)
    if verdict == "likely_scam":
        lines.append(ADVICE_ALREADY)
    if flagged:
        lines.append(ADVICE_UNSURE)
    if verdict == "no_signs_found":
        lines.append(ADVICE_NO_SIGNS)
    if verdict == "not_checked":
        lines.append(ADVICE_NOT_CHECKED)
    return tuple(dict.fromkeys(lines))[:MAX_ADVICE]


def codes_for(signals: Sequence[Signal], links: Sequence["LinkFinding"]) -> tuple[str, ...]:
    """Every signal code of a check, the link ones included, each once (for advice_for and the
    audit row's facts)."""
    return tuple(_strengths(signals, links))


# ── Notes (S3 2.3, in its order) ─────────────────────────────────────────

NOTE_SENTENCES: dict[str, str] = {
    "links_local_only": (
        "Links were checked against Crawler's own lists only; the owner can add a Google Safe "
        "Browsing key under Security \u2192 Service keys."
    ),
    "links_unavailable": "Links couldn't be checked right now, so they are not counted either way.",
    "file_not_checked": "The file wasn't checked: file checks need the owner's VirusTotal key.",
    # With a key set, VirusTotal may never have seen the file, or the lookup may be queued or
    # fail; saying the key is missing would be wrong (and is no reason to call it clean).
    "file_unknown": "VirusTotal has no record of the file, so it is not counted either way.",
    "file_unavailable": "The file couldn't be checked right now, so it is not counted either way.",
    "ai_not_set_up": (
        "The AI review didn't run: no AI provider is set up for your account. This is based on "
        "the automatic checks only."
    ),
    "no_vision": (
        "The picture wasn't checked: your AI provider ({provider}) can't look at pictures. Paste "
        "the text or the link instead."
    ),
    "ai_failed": (
        "The AI review didn't run (your AI provider did not answer), so this is based on the "
        "automatic checks only."
    ),
    "ai_unreadable": "The AI review's answer couldn't be read, so it was left out.",
    "reasons_withheld": (
        "Some of your AI provider's notes were left out because they held a link, an address, a "
        "phone number or wording aimed at an AI."
    ),
    "text_cut": "Only the first {limit} characters were checked.",
    "too_many_pictures": "Only the first 4 pictures were checked.",
    "picture_unusable": "A picture was left out: it was over 5 MB or not a PNG, JPEG, WebP or GIF image.",
    "too_many_links": "Only the first 10 links were checked.",
    "qr_unreadable": "A QR code couldn't be read clearly, so where it leads wasn't checked.",
    "files_by_fingerprint": (
        "Attached files were checked by their fingerprint only; paste their text after /scam to "
        "have the wording checked."
    ),
    "cached": "Same result as your check a few minutes ago.",
}
NOTE_ORDER: tuple[str, ...] = tuple(NOTE_SENTENCES)
_PROVIDER_UNSAFE = re.compile(r"[^A-Za-z0-9 ._-]")


def provider_label(provider: str) -> str:
    """A provider name as it may appear in a sentence: plain ASCII, short; "your AI provider"
    stays readable when the name is missing."""
    cleaned = _PROVIDER_UNSAFE.sub("", str(provider or ""))[:40].strip()
    return cleaned or "unknown"


def notes_for(codes: Iterable[str], *, provider: str = "", text_limit: int = MAX_TEXT_CHARS) -> tuple[str, ...]:
    """The note sentences for *codes*, in the order of S3 2.3, each once; unknown codes are
    skipped (a code is a programming fact, never shown raw)."""
    have = set(codes)
    out: list[str] = []
    for code in NOTE_ORDER:
        if code in have:
            out.append(NOTE_SENTENCES[code].format(provider=provider_label(provider), limit=f"{text_limit:,}"))
    return tuple(out)


def headline(verdict: str) -> str:
    """The fixed headline with its emoji; an unknown verdict reads as not checked."""
    return HEADLINES.get(verdict, HEADLINES["not_checked"])


# ── Rendering ────────────────────────────────────────────────────────────


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _link_sources(result: "ScamCheckResult") -> str:
    checked = [link for link in result.links if link.level != "not_checked"]
    if not checked:
        return "not checked right now"
    sources = {str(s).lower() for link in checked for s in (link.checked_by or ())}
    names = ["Crawler's own lists"]
    if "safe_browsing" in sources:
        names.append("Google Safe Browsing")
    if "web_risk" in sources:
        names.append("Google Web Risk")
    phrase = " and ".join(names)
    if len(names) == 1 and "links_local_only" in result.note_codes:
        phrase += "; Google Safe Browsing is not set up"
    return phrase


def checked_line(result: "ScamCheckResult") -> str:
    """What was looked at and by which sources, one line."""
    parts: list[str] = []
    if result.text_chars:
        parts.append(f"the text ({result.text_chars:,} characters)")
    if result.images:
        seen = result.ai_ran and "no_vision" not in result.note_codes
        parts.append(_plural(result.images, "picture") + (" (read by your AI provider)" if seen else ""))
    if result.links:
        from_qr = sum(1 for link in result.links if link.origin == "qr")
        count = _plural(len(result.links), "link")
        if from_qr:
            count += f", {from_qr} from the QR code"
        parts.append(f"{count} ({_link_sources(result)})")
    if result.files:
        parts.append(_plural(result.files, "file") + " (by fingerprint)")
    if not parts:
        return "Checked: nothing could be read."
    line = "Checked: " + ", ".join(parts) + "."
    if result.ai_ran:
        line += f" Reviewed by your AI provider ({provider_label(result.provider)})."
    return line


def _needs_caveat(result: "ScamCheckResult") -> bool:
    """"No signs found" always says no check can prove a message is safe; the advice table
    carries the sentence, and a result built without it still shows it."""
    return result.verdict == "no_signs_found" and not any(CAVEAT in line for line in result.advice)


def _reasons_heading(verdict: str) -> str:
    return "Worth noting" if verdict in ("no_signs_found", "not_checked") else "Why"


def render_plain(result: "ScamCheckResult") -> str:
    """Telegram/Slack: plain text. Reasons, the AI's reasons, notes and the Checked line are
    defanged (page_watch.defang: no dot between two letters, no slash, no @ survives as such),
    so nothing in the reply can become a link; the fixed advice is not. A refusal is its
    sentence."""
    if not result.ok:
        return result.refusal
    blocks: list[str] = [headline(result.verdict)]
    if _needs_caveat(result):
        blocks.append(CAVEAT)
    if result.reasons:
        heading = _reasons_heading(result.verdict)
        blocks.append(f"{heading}:\n" + "\n".join(f"\u2022 {defang(r)}" for r in result.reasons))
    if result.ai_reasons:
        blocks.append("Your AI provider also noted:\n" + "\n".join(f"\u2022 {defang(r)}" for r in result.ai_reasons))
    if result.advice:
        blocks.append("What to do:\n" + "\n".join(f"\u2022 {a}" for a in result.advice))
    if result.notes:
        blocks.append("Notes:\n" + "\n".join(f"\u2022 {defang(n)}" for n in result.notes))
    blocks.append(defang(checked_line(result)))
    return "\n\n".join(blocks)


# A host or address inside one of Crawler's own sentences: wrapped in a code span on the web.
_HOST_TOKEN = re.compile(
    r"(?<![\w`.-])(?:https?://)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    r"(?::\d{1,5})?(?:/[^\s`]*[^\s`.,;:!?)])?",
    re.IGNORECASE,
)
# "&" is escaped too: CommonMark decodes "&period;" to "." and "&commat;" to "@", which would
# rebuild a domain or an address the reason filter never saw (checker finding). "~" and "|"
# (strike-through, tables) only tidy the output.
_MD_SPECIAL = re.compile(r"([\\\[\]()*_`<>!#&~|])")


def _code_hosts(sentence: str) -> str:
    return _HOST_TOKEN.sub(lambda m: f"`{m.group()}`", sentence)


def escape_markdown(text: str) -> str:
    """*text* with \\ [ ] ( ) * _ ` < > ! # & ~ | escaped, so a Markdown renderer can neither
    build a link, autolink one nor decode a character reference into one (the AI's reasons,
    review SEC-M2)."""
    return _MD_SPECIAL.sub(r"\\\1", text)


_LEVEL_WORDS: dict[str, str] = {
    "malicious": "known bad",
    "suspicious": "look-alike or risky",
    "no_signs_found": "nothing found",
    "not_checked": "not checked",
}


_CODE_SPAN_BREAKS = re.compile(r"[\x00-\x1f\x7f]")


def _code_span(text: str) -> str:
    """*text* as one code span: a backtick cannot close it early and a control character
    (a line break) cannot end the list item it sits in."""
    return "`" + _CODE_SPAN_BREAKS.sub("", text).replace("`", "%60") + "`"


def render_markdown(result: "ScamCheckResult") -> str:
    """The web chat's reply: a bold headline, bullet lists, hosts and addresses in code spans,
    the AI's reasons escaped under their own heading, and no link anywhere. A refusal is its
    sentence."""
    if not result.ok:
        return result.refusal
    blocks: list[str] = [f"**{headline(result.verdict)}**"]
    if _needs_caveat(result):
        blocks.append(CAVEAT)
    if result.reasons:
        heading = _reasons_heading(result.verdict)
        blocks.append(f"**{heading}**\n" + "\n".join(f"- {_code_hosts(r)}" for r in result.reasons))
    if result.ai_reasons:
        blocks.append(
            "**Your AI provider also noted:**\n" + "\n".join(f"- {escape_markdown(r)}" for r in result.ai_reasons)
        )
    if result.advice:
        blocks.append("**What to do**\n" + "\n".join(f"- {a}" for a in result.advice))
    if result.links:
        rows = [
            f"- {_code_span(_safe_shown(link))}: {_LEVEL_WORDS.get(link.level, 'not checked')}"
            for link in result.links
        ]
        blocks.append("**Links checked**\n" + "\n".join(rows))
    if result.notes:
        blocks.append("**Notes**\n" + "\n".join(f"- {n}" for n in result.notes))
    blocks.append(checked_line(result))
    return "\n\n".join(blocks)


# ── JSON (Security page route and the in-turn tool) ──────────────────────

_HOMOGLYPHS = frozenset(_HOMOGLYPH_MAP)


def scrub(text: Any) -> str:
    """*text* with no invisible character and no look-alike letter: each becomes "?". Every
    string to_json returns passes through here, so the tool result can never be redacted by the
    runtime's PromptGuard pass, whatever an adapter handed in."""
    value = _INVISIBLE_CHARS.sub("?", str(text if text is not None else ""))
    return "".join("?" if ch in _HOMOGLYPHS else ch for ch in value)


def _safe_shown(link: "LinkFinding") -> str:
    """The link's display form; one that is not plain ASCII (apart from display_url's "…") is
    displayed again from scratch, so a raw host never slips through."""
    shown = str(link.shown or "")
    if not shown.replace("\u2026", "").isascii() or _INVISIBLE_CHARS.search(shown):
        shown = display_url(shown) or _link_host(link)
    return scrub(shown)


_SOURCES = ("local", "safe_browsing", "web_risk")
_ORIGINS = ("text", "picture", "qr", "sender")


def link_json(link: "LinkFinding") -> dict[str, Any]:
    """One link for the route and the tool: display form, punycode host, the site it imitates,
    level, sources and origin; never S4's raw codes."""
    looks_like = ascii_host(link.looks_like) if link.looks_like else None
    level: Literal["malicious", "suspicious", "no_signs_found", "not_checked"] = (
        link.level if link.level in _LEVEL_WORDS else "not_checked"
    )
    return {
        "shown": _safe_shown(link),
        "host": _link_host(link) if link.host or link.shown else "",
        "looks_like": looks_like or "",
        "level": level,
        "checked_by": [s for s in _SOURCES if s in {str(c).lower() for c in (link.checked_by or ())}],
        "origin": link.origin if link.origin in _ORIGINS else "text",
    }


def to_json(result: "ScamCheckResult") -> dict[str, Any]:
    """The route body and the tool result (S3 4.5.4): verdict, headline (no emoji), Crawler's
    reasons, the AI's reasons apart, advice, links, notes, QR facts, what was checked, and
    whether it was a repeat. No conversation id, usage, provider or model: the web route adds
    those itself; the tool never carries them."""
    verdict = result.verdict if result.verdict in HEADLINE_TEXT else "not_checked"
    return {
        "verdict": verdict,
        "headline": HEADLINE_TEXT[verdict],
        "reasons": [scrub(r) for r in result.reasons],
        "ai_reasons": [scrub(r) for r in result.ai_reasons],
        "advice": [scrub(a) for a in result.advice],
        "links": [link_json(link) for link in result.links],
        "notes": [scrub(n) for n in result.notes],
        "qr": {"present": bool(result.qr_present), "readable": bool(result.qr_readable)},
        "checked": {
            "text_chars": int(result.text_chars),
            "images": int(result.images),
            "links": len(result.links),
            "ai": bool(result.ai_ran),
        },
        "cached": bool(result.cached),
    }


# ── Audit facts (S3 4.10) ────────────────────────────────────────────────

REFUSAL_REASONS: tuple[str, ...] = (
    "gate_error",
    "capability_off",
    "capability_blocked",
    "quota_burst",
    "quota_daily",
    "empty",
    "provider_blind",
    "too_large",
    "unsupported_media",
    "download_failed",
    "not_set_up",
    # An unexpected error inside the check itself (logged by type only; nothing was checked).
    "error",
)


_AUDIT_CHANNELS = ("telegram", "slack", "web_chat", "web_box")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _file_digests(request: "ScamCheckRequest", limit: int) -> list[str]:
    """The checked files' sha256s as the service sent them (real digests only, lower case, in
    order, at most *limit*): never a name or anything else a caller put in the field."""
    digests: list[str] = []
    for item in request.files:
        digest = str(getattr(item, "sha256", "") or "").strip().lower()
        if _SHA256_HEX.fullmatch(digest):
            digests.append(digest)
    return digests[: max(limit, 0)]


def ran_facts(request: "ScamCheckRequest", result: "ScamCheckResult") -> dict[str, Any]:
    """The scam_check_ran row's facts: verdicts, counts, codes, the provider and the pictures'
    and files' sha256s. Never the text, the note, a URL, a host, a file name or a reason: the
    text and note are counted, links are counted by level.

    The token counts are stored as usage_input / usage_output: the audit log redacts the whole
    value of any key whose name holds "token" (services/security/policies.AUDIT_KEY_NAMES), so
    "input_tokens" would always read "***REDACTED***"."""
    levels = [link.level for link in result.links]
    note = request.note.strip() if isinstance(request.note, str) else ""
    return {
        "event": "scam_check_ran",
        "channel": request.channel if request.channel in _AUDIT_CHANNELS else "web_box",
        "verdict": result.verdict,
        "rule_verdict": result.rule_verdict,
        "ai_verdict": result.ai_verdict or "",
        "ai": bool(result.ai_ran),
        "engine": result.provider,
        "model": result.model,
        "text_chars": int(result.text_chars),
        "note_chars": min(len(note), 500),
        "images": int(result.images),
        "image_sha256": list(result.image_sha256),
        "files": int(result.files),
        "file_sha256": _file_digests(request, int(result.files)),
        "links": len(levels),
        "links_malicious": levels.count("malicious"),
        "links_suspicious": levels.count("suspicious"),
        "links_not_checked": levels.count("not_checked"),
        "signals": list(result.signal_codes),
        "notes": list(result.note_codes),
        "qr_present": bool(result.qr_present),
        "qr_readable": bool(result.qr_readable),
        "forwarded": bool(request.forwarded),
        "cached": bool(result.cached),
        "usage_input": int(result.usage.get("input_tokens", 0) or 0),
        "usage_output": int(result.usage.get("output_tokens", 0) or 0),
    }


def refused_facts(channel: str, reason: str) -> dict[str, Any]:
    """The scam_check_refused row's facts; an unknown reason is recorded as not_set_up rather
    than as free text."""
    return {
        "event": "scam_check_refused",
        "channel": channel,
        "reason": reason if reason in REFUSAL_REASONS else "not_set_up",
    }
