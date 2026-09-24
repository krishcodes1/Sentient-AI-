"""Scans text for prompt-injection patterns, on the raw bytes and on a de-
obfuscated form, and reports a threat level.

Why it exists: The runtime scans user input, tool output and model output, and
the memory service screens saved facts; keeping the patterns and the
normalisation in one place means every path sees the same defenses.

Multi-layer prompt injection defense for Crawler AI.

Provides pattern matching, heuristic analysis, and output validation
to detect and block prompt injection attacks across all agent interactions.

Every scan also runs against a canonical (normalized) form of the input:
regex guards are bypassed in practice via ENCODING tricks (zero-width
splices, homoglyphs, fullwidth forms, separator-spliced letters, base64)
rather than novel phrasing, so the same pattern families must see the
de-obfuscated text as well as the raw bytes.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Detection:
    layer: str
    pattern_name: str
    matched_text: str
    severity: str


@dataclass
class ScanResult:
    is_safe: bool
    threat_level: ThreatLevel
    detections: list[Detection] = field(default_factory=list)
    confidence: float = 1.0


# -- Homoglyph map: Cyrillic/Greek lookalikes to Latin --
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P",
    "\u03a4": "T", "\u03a7": "X", "\u0391": "A",
    # Lowercase confusables that allow a WHOLE word to be spelled in
    # Cyrillic (e.g. "skip" or "mode" with every letter swapped). The
    # mixed-script detector requires Latin inside the same word, so
    # whole-word substitutions were invisible to it -- only the
    # normalization fold brings them back in range of the phrase regexes.
    "\u043a": "k", "\u043c": "m", "\u0456": "i", "\u0455": "s",
    "\u0458": "j", "\u04bb": "h", "\u0501": "d", "\u051b": "q",
    "\u051d": "w",
    # Greek omicron renders identically to Latin o in common fonts.
    "\u03bf": "o",
}

# Zero-width and invisible Unicode characters
_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5"
    r"\u180e\u2000-\u200a\u202a-\u202e\u2066-\u2069\ufff9-\ufffb]"
)

# Separator characters used to splice a word ("i-g-n-o-r-e") so a literal
# phrase regex never sees it assembled. Only runs of SINGLE letters joined
# by these characters are collapsed; multi-letter segments ("study-group",
# "e-mail", "TCP/IP") stay untouched so ordinary hyphenated prose cannot be
# rewritten into an attack phrase.
_WORD_SPLICE_RUN = re.compile(
    r"(?:[A-Za-z][\-\u2010\u2011\u2012\u2013\u2014._\u00b7\u2022*+|/\\]){2,}[A-Za-z]"
)
_NON_LETTER = re.compile(r"[^A-Za-z]")

# Long encoded runs worth opportunistically decoding. 20+ base64 chars /
# 32+ hex chars is enough to carry a real instruction while staying above
# the noise of short identifiers.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RUN = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")


def normalize_for_scan(content: str) -> str:
    """Produce the canonical form of *content* used by the evasion pre-pass.

    The regex layers match literal English phrases, so any encoding that
    changes the byte sequence without changing what a human reads
    (fullwidth forms, zero-width splices, Cyrillic lookalikes, hyphen/dot
    splicing) bypasses them when only the raw text is scanned. Scanning
    this canonical form alongside the raw text closes that gap.
    """
    # NFKC first: folds fullwidth/compatibility forms and converts exotic
    # spaces (en/em space, ideographic space) to ASCII before anything else.
    text = unicodedata.normalize("NFKC", content)
    # Zero-width and bidi-control characters survive NFKC; strip them so a
    # splice like "ig<ZWSP>nore" reassembles into the literal word.
    text = _INVISIBLE_CHARS.sub("", text)
    # Fold confusable Cyrillic/Greek onto Latin. Pure non-Latin text stays
    # non-matching (English phrase regexes cannot fire on it), so folding
    # unconditionally is safe for legitimate Cyrillic/Greek prose.
    text = "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)
    # Reassemble separator-spliced words.
    text = _WORD_SPLICE_RUN.sub(lambda m: _NON_LETTER.sub("", m.group()), text)
    # Collapse horizontal whitespace runs but KEEP newlines: the heuristic
    # layer splits sentences on newlines, and merging lines would change
    # its verdicts between the raw and normalized passes.
    text = re.sub(r"[^\S\n]+", " ", text)
    return text


def _mostly_printable(text: str) -> bool:
    """True when decoded bytes look like text rather than binary noise.

    Hashes and random blobs also match the encoded-run regexes; scanning
    their garbage decodings would only add noise, so they are skipped.
    """
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch.isspace())
    return printable / len(text) >= 0.85


class PromptGuard:
    """Multi-layer prompt injection defense engine."""

    # ------------------------------------------------------------------ #
    # Layer 1 — Pattern matching
    # ------------------------------------------------------------------ #

    _INJECTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
        (
            "ignore_instructions",
            re.compile(
                r"(?:ignore|disregard|forget|override|bypass|skip|drop)"
                r"\s+(?:all\s+)?(?:previous|prior|above|earlier|existing|original|"
                r"the\s+above|system)\s+(?:instructions?|prompts?|rules?|context|directives?|guidelines?)",
                re.IGNORECASE,
            ),
            "high",
        ),
        (
            "role_hijack",
            re.compile(
                # "switch to/enter/activate X mode" is only hostile for modes
                # that target the ASSISTANT's behavior. The old catch-all
                # (?:\w+\s+)?mode blocked everyday sentences like "switch to
                # dark mode" and "how do I enter focus mode on iPhone?".
                r"(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|"
                r"act\s+as\s+if\s+you\s+are|you\s+have\s+been\s+reprogrammed|"
                r"new\s+instructions?:\s*you\s+are|"
                r"(?:switch\s+to|enter|activate)\s+"
                r"(?:developer|debug|admin|root|sudo|god|dan|evil|opposite|"
                r"unrestricted|unfiltered|uncensored|unsafe|jailbreak|bypass|"
                r"override)\s+mode)",
                re.IGNORECASE,
            ),
            "critical",
        ),
        (
            "system_prompt_extract",
            re.compile(
                r"(?:reveal|show|display|print|output|repeat|echo|leak|expose|"
                r"dump|tell|give)"
                # Allow up to four filler words (e.g. "me your full verbatim")
                # between the verb and the target so "print your full system
                # prompt" is caught, not just "print your system prompt".
                r"\s+(?:(?:your|the|me|us|entire|full|complete|exact|verbatim|raw|"
                r"initial|original|hidden|secret|base|actual)\s+){0,4}"
                r"(?:system\s+prompt|instructions?|initial\s+prompt|"
                r"hidden\s+prompt|secret\s+prompt|original\s+prompt|base\s+prompt|"
                r"pre-?prompt|meta-?prompt|"
                # Only the full "guidelines and rules" phrasing, so ordinary
                # requests mentioning "rules" or "guidelines" alone are safe.
                r"guidelines?\s+and\s+rules?|rules?\s+and\s+guidelines?)",
                re.IGNORECASE,
            ),
            "high",
        ),
        (
            "hidden_html_markdown",
            re.compile(
                r"<!--.*?-->|<\s*script[^>]*>.*?<\s*/\s*script\s*>|"
                r"<\s*style[^>]*>.*?<\s*/\s*style\s*>|"
                r"\[//\]:\s*#\s*\(.*?\)|"
                r"<\s*div\s+style\s*=\s*[\"'].*?display\s*:\s*none.*?[\"'].*?>",
                re.IGNORECASE | re.DOTALL,
            ),
            "medium",
        ),
        (
            "delimiter_injection",
            re.compile(
                r"```\s*system\s*```|"
                r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|"
                r"<\|system\|>|<\|user\|>|<\|assistant\|>|"
                r"### (?:System|Human|Assistant|Instruction):|"
                r"<\|endoftext\|>|<\|pad\|>",
                re.IGNORECASE,
            ),
            "critical",
        ),
        (
            "jailbreak_keywords",
            re.compile(
                # The DAN jailbreak is the literal uppercase token; the
                # whole pattern is case-insensitive, so it is scoped back to
                # case-sensitive and word-bounded here — otherwise "Dan",
                # "abundant", or any base64 payload containing "dan" trips
                # a CRITICAL block.
                r"(?:(?-i:\bDAN\b)|do\s+anything\s+now|jail\s*break|"
                r"developer\s+mode|god\s+mode|unrestricted\s+mode|"
                r"no\s+restrictions?\s+mode|unfiltered\s+mode)",
                re.IGNORECASE,
            ),
            "critical",
        ),
        (
            "data_exfiltration",
            re.compile(
                # Two hostile shapes, chosen so everyday requests ("export
                # all my data as JSON", "send me the information") pass:
                # (a) moving SENSITIVE material (credentials/tokens/keys/
                #     passwords/secrets) with any transfer verb;
                # (b) moving generic data/info/results to an EXTERNAL
                #     destination (URL, email address, or an explicitly
                #     external/remote/third-party target).
                # "share" and "export" were dropped from the verb set: export
                # is a first-class feature of this app and both verbs are
                # ordinary conversation.
                r"(?:(?:send|post|transmit|exfiltrate|forward|upload|email|leak)\s+"
                r"(?:(?:to|the|all|my|your|user|this)\s+){0,4}"
                r"(?:credentials?|tokens?|keys?|passwords?|secrets?|api[\s_-]?keys?))"
                r"|"
                r"(?:(?:send|post|transmit|exfiltrate|forward|upload|email|leak)\s+"
                r"(?:(?:the|all|my|your|user|this)\s+){0,4}"
                r"(?:data|info(?:rmation)?|results?)\s+to\s+"
                r"(?:https?://|\S+@|(?:an?\s+)?(?:external|remote|third[-\s]?party)))",
                re.IGNORECASE,
            ),
            "high",
        ),
        (
            "authority_claim",
            re.compile(
                r"(?:i\s+am\s+(?:an?\s+)?(?:admin(?:istrator)?|developer|root|"
                r"system\s+admin|superuser|anthropic\s+(?:staff|employee|engineer))|"
                r"admin\s+override|emergency\s+protocol|"
                r"this\s+is\s+(?:a\s+)?(?:authorized|approved|sanctioned))",
                re.IGNORECASE,
            ),
            "high",
        ),
    ]

    def scan(self, content: str) -> ScanResult:
        """Run all defense layers and return a consolidated scan result.

        Layers run against both the raw text and its canonical
        (``normalize_for_scan``) form, plus the decodings of any long
        base64/hex runs. Detections are de-duplicated so a plain attack is
        not reported twice; anything found only after normalization keeps a
        ``:normalized`` layer suffix (and decoded findings a
        ``:decoded`` layer) so attempted evasion stays visible downstream.
        """
        detections: list[Detection] = []
        seen: set[tuple[str, str]] = set()

        def _dedup_key(det: Detection) -> tuple[str, str]:
            # Whitespace-insensitive key: the raw and normalized passes can
            # match the same span with different internal spacing.
            return (det.pattern_name, re.sub(r"\s+", " ", det.matched_text).lower())

        def _collect(found: list[Detection], evaded: bool = False) -> None:
            for det in found:
                key = _dedup_key(det)
                if key in seen:
                    continue
                seen.add(key)
                if evaded:
                    det.layer = f"{det.layer}:normalized"
                detections.append(det)

        _collect(self._layer1_pattern_matching(content))
        _collect(self._layer2_heuristic_analysis(content))

        normalized = normalize_for_scan(content)
        if normalized != content:
            # The text changed under normalization, i.e. something stood
            # between the reader and the bytes. Re-scan the canonical form
            # so spliced/confusable phrasings hit the same patterns.
            _collect(self._layer1_pattern_matching(normalized), evaded=True)
            _collect(self._layer2_heuristic_analysis(normalized), evaded=True)

        _collect(self._scan_decoded_payloads(content, normalized))

        if not detections:
            return ScanResult(
                is_safe=True,
                threat_level=ThreatLevel.NONE,
                detections=[],
                confidence=1.0,
            )

        # Determine overall threat level from worst detection
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        worst = max(detections, key=lambda d: severity_rank.get(d.severity, 0))
        threat_level = ThreatLevel(worst.severity)

        # Confidence rises with more detections (capped at 1.0)
        confidence = min(1.0, 0.5 + 0.1 * len(detections))

        is_safe = threat_level in (ThreatLevel.NONE, ThreatLevel.LOW)

        return ScanResult(
            is_safe=is_safe,
            threat_level=threat_level,
            detections=detections,
            confidence=confidence,
        )

    # ------------------------------------------------------------------ #
    # Layer 1 — Regex pattern matching
    # ------------------------------------------------------------------ #

    def _layer1_pattern_matching(self, content: str) -> list[Detection]:
        detections: list[Detection] = []

        # Check for zero-width / invisible characters
        invisible_matches = _INVISIBLE_CHARS.findall(content)
        if len(invisible_matches) > 2:
            detections.append(
                Detection(
                    layer="pattern_matching",
                    pattern_name="zero_width_characters",
                    matched_text=f"{len(invisible_matches)} invisible chars detected",
                    severity="high",
                )
            )

        # Homoglyph detection — mixed-script words
        detections.extend(self._detect_homoglyphs(content))

        # Base64 encoded instructions
        detections.extend(self._detect_base64_instructions(content))

        # Run regex patterns
        for pattern_name, regex, severity in self._INJECTION_PATTERNS:
            matches = regex.findall(content)
            for match in matches:
                matched = match if isinstance(match, str) else match[0]
                detections.append(
                    Detection(
                        layer="pattern_matching",
                        pattern_name=pattern_name,
                        matched_text=matched[:200],
                        severity=severity,
                    )
                )

        return detections

    def _detect_homoglyphs(self, content: str) -> list[Detection]:
        """Detect words that mix Latin characters with lookalike Cyrillic/Greek."""
        detections: list[Detection] = []
        words = re.findall(r"\b\S+\b", content)

        for word in words:
            if len(word) < 3:
                continue
            has_latin = False
            has_homoglyph = False
            for ch in word:
                if ch in _HOMOGLYPH_MAP:
                    has_homoglyph = True
                elif "LATIN" in unicodedata.name(ch, ""):
                    has_latin = True
            if has_latin and has_homoglyph:
                detections.append(
                    Detection(
                        layer="pattern_matching",
                        pattern_name="homoglyph_mixed_script",
                        matched_text=word[:100],
                        severity="high",
                    )
                )

        return detections

    def _detect_base64_instructions(self, content: str) -> list[Detection]:
        """Detect base64-encoded strings that decode to suspicious instructions."""
        detections: list[Detection] = []
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

        for match in b64_pattern.finditer(content):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Check if decoded content looks like an instruction
            instruction_signals = [
                "ignore", "system", "prompt", "instruction", "execute",
                "override", "admin", "password", "secret", "token",
            ]
            decoded_lower = decoded.lower()
            if any(sig in decoded_lower for sig in instruction_signals):
                detections.append(
                    Detection(
                        layer="pattern_matching",
                        pattern_name="base64_encoded_instruction",
                        matched_text=f"Encoded: {candidate[:60]}... -> {decoded[:100]}",
                        severity="critical",
                    )
                )

        return detections

    def _scan_decoded_payloads(self, *texts: str) -> list[Detection]:
        """Decode long base64/hex runs and give the decoded text the full
        pattern treatment.

        ``_detect_base64_instructions`` only keyword-matches decoded bytes,
        so an encoded injection phrased without its keyword list (e.g.
        "disregard all prior rules") slips through. Here every decoded
        candidate is normalized and run against the real regex families.
        Candidates are gathered from both the raw and normalized text so a
        zero-width-spliced encoded run still gets decoded.
        """
        detections: list[Detection] = []
        candidates: dict[tuple[str, str], str] = {}

        for text in texts:
            for match in _B64_RUN.finditer(text):
                run = match.group()
                try:
                    padded = run + "=" * (-len(run) % 4)
                    decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                candidates.setdefault(("base64", run), decoded)
            for match in _HEX_RUN.finditer(text):
                run = match.group()
                try:
                    decoded = bytes.fromhex(run).decode("utf-8", errors="ignore")
                except ValueError:
                    continue
                candidates.setdefault(("hex", run), decoded)

        for (encoding, run), decoded in candidates.items():
            if len(decoded) < 8 or not _mostly_printable(decoded):
                continue
            canonical = normalize_for_scan(decoded)
            for pattern_name, regex, _severity in self._INJECTION_PATTERNS:
                for match in regex.finditer(canonical):
                    detections.append(
                        Detection(
                            layer="pattern_matching:decoded",
                            pattern_name=pattern_name,
                            matched_text=(
                                f"{encoding}: {run[:48]}... -> {match.group()[:120]}"
                            ),
                            # Wrapping a working injection in an encoding is
                            # deliberate evasion, so the floor is critical
                            # regardless of the underlying family's rating.
                            severity="critical",
                        )
                    )

        return detections

    # ------------------------------------------------------------------ #
    # Layer 2 — Heuristic analysis
    # ------------------------------------------------------------------ #

    _IMPERATIVE_VERBS = re.compile(
        r"\b(?:do|execute|run|perform|send|delete|remove|create|"
        r"write|update|change|modify|set|grant|allow|enable|disable|"
        r"stop|start|open|close|fetch|retrieve|download|upload|"
        r"install|uninstall|deploy|destroy|kill|terminate|abort|"
        r"ignore|forget|disregard|override|bypass)\b",
        re.IGNORECASE,
    )

    _ROLEPLAY_PATTERNS = re.compile(
        r"(?:pretend\s+(?:you\s+are|to\s+be)|act\s+as\s+(?:if\s+you\s+(?:are|were)|a)|"
        r"imagine\s+you\s+are|simulate\s+being|behave\s+as|"
        r"respond\s+as\s+(?:if\s+you\s+were|a)|play\s+the\s+role\s+of|"
        r"take\s+on\s+the\s+(?:role|persona)\s+of|"
        r"you\s+are\s+(?:a\s+)?(?:helpful|unrestricted|unfiltered)\s+(?:AI|assistant|bot))",
        re.IGNORECASE,
    )

    _AUTHORITY_LANGUAGE = re.compile(
        r"(?:you\s+must|you\s+shall|you\s+are\s+required\s+to|"
        r"it\s+is\s+(?:critical|essential|mandatory|imperative)\s+that\s+you|"
        r"under\s+no\s+circumstances|failure\s+to\s+comply|"
        r"this\s+is\s+(?:an?\s+)?(?:order|command|directive|mandate)|"
        r"i\s+(?:order|command|direct|instruct)\s+you\s+to|"
        r"do\s+not\s+question|do\s+as\s+(?:i|you\s+are)\s+told)",
        re.IGNORECASE,
    )

    def _layer2_heuristic_analysis(self, content: str) -> list[Detection]:
        detections: list[Detection] = []

        # Instruction density — many imperative verbs in a short span
        sentences = re.split(r"[.!?\n]", content)
        imperative_sentences = 0
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            verb_count = len(self._IMPERATIVE_VERBS.findall(sentence))
            if verb_count >= 2:
                imperative_sentences += 1

        total_sentences = max(len([s for s in sentences if s.strip()]), 1)
        density = imperative_sentences / total_sentences

        if density > 0.6 and imperative_sentences >= 3:
            detections.append(
                Detection(
                    layer="heuristic_analysis",
                    pattern_name="high_instruction_density",
                    matched_text=f"Instruction density: {density:.0%} ({imperative_sentences}/{total_sentences} sentences)",
                    severity="medium",
                )
            )

        # Role-play attempts
        for match in self._ROLEPLAY_PATTERNS.finditer(content):
            detections.append(
                Detection(
                    layer="heuristic_analysis",
                    pattern_name="roleplay_attempt",
                    matched_text=match.group()[:200],
                    severity="high",
                )
            )

        # Delimiter injection (checked in layer 1 too, but heuristic catches novel delimiters)
        delimiter_chars = content.count("```") + content.count("---") + content.count("===")
        if delimiter_chars > 6:
            detections.append(
                Detection(
                    layer="heuristic_analysis",
                    pattern_name="excessive_delimiters",
                    matched_text=f"{delimiter_chars} delimiter sequences detected",
                    severity="low",
                )
            )

        # Authority language
        authority_matches = self._AUTHORITY_LANGUAGE.findall(content)
        if len(authority_matches) >= 2:
            detections.append(
                Detection(
                    layer="heuristic_analysis",
                    pattern_name="excessive_authority_language",
                    matched_text="; ".join(m[:50] for m in authority_matches[:5]),
                    severity="medium",
                )
            )

        return detections

    # ------------------------------------------------------------------ #
    # Layer 3 — Output / action validation
    # ------------------------------------------------------------------ #

    def _layer3_output_validation(
        self,
        intended_action: str,
        permission_policy: dict[str, list[str]],
    ) -> ScanResult:
        """
        Validate that an agent's intended action falls within the user's
        approved permission policy.

        Args:
            intended_action: The action the agent wants to take (e.g. "gmail.send").
            permission_policy: Mapping of connector -> list of allowed actions
                               e.g. {"gmail": ["read", "list"], "canvas": ["read", "submit"]}

        Returns:
            ScanResult indicating whether the action is permitted.
        """
        detections: list[Detection] = []

        parts = intended_action.split(".", 1)
        connector = parts[0] if parts else ""
        action = parts[1] if len(parts) > 1 else intended_action

        allowed_actions = permission_policy.get(connector, [])

        if connector not in permission_policy:
            detections.append(
                Detection(
                    layer="output_validation",
                    pattern_name="unauthorized_connector",
                    matched_text=f"Connector '{connector}' not in approved policy",
                    severity="high",
                )
            )
        elif action not in allowed_actions:
            detections.append(
                Detection(
                    layer="output_validation",
                    pattern_name="unauthorized_action",
                    matched_text=f"Action '{action}' not permitted for '{connector}' (allowed: {allowed_actions})",
                    severity="high",
                )
            )

        if detections:
            return ScanResult(
                is_safe=False,
                threat_level=ThreatLevel.HIGH,
                detections=detections,
                confidence=1.0,
            )

        return ScanResult(
            is_safe=True,
            threat_level=ThreatLevel.NONE,
            detections=[],
            confidence=1.0,
        )
