"""
Multi-layer prompt injection defense for SentientAI.

Provides pattern matching, heuristic analysis, and output validation
to detect and block prompt injection attacks across all agent interactions.
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
}

# Zero-width and invisible Unicode characters
_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5"
    r"\u180e\u2000-\u200a\u202a-\u202e\u2066-\u2069\ufff9-\ufffb]"
)


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
                r"(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|"
                r"act\s+as\s+if\s+you\s+are|you\s+have\s+been\s+reprogrammed|"
                r"new\s+instructions?:\s*you\s+are|switch\s+to\s+(?:\w+\s+)?mode|"
                r"enter\s+(?:\w+\s+)?mode|activate\s+(?:\w+\s+)?mode)",
                re.IGNORECASE,
            ),
            "critical",
        ),
        (
            "system_prompt_extract",
            re.compile(
                r"(?:reveal|show|display|print|output|repeat|echo|leak|expose|dump)"
                r"\s+(?:your\s+)?(?:system\s+prompt|instructions?|initial\s+prompt|"
                r"hidden\s+prompt|secret\s+prompt|original\s+prompt|base\s+prompt|"
                r"pre-?prompt|meta-?prompt)",
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
                r"(?:DAN|do\s+anything\s+now|jail\s*break|"
                r"developer\s+mode|god\s+mode|unrestricted\s+mode|"
                r"no\s+restrictions?\s+mode|unfiltered\s+mode)",
                re.IGNORECASE,
            ),
            "critical",
        ),
        (
            "data_exfiltration",
            re.compile(
                r"(?:send|post|transmit|exfiltrate|forward|upload|email)\s+"
                r"(?:to|the|all|my|user|this)\s*"
                r"(?:data|info(?:rmation)?|credentials?|tokens?|keys?|passwords?|secrets?|"
                r"api[\s_-]?keys?|results?)",
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
        """Run all defense layers and return a consolidated scan result."""
        detections: list[Detection] = []

        detections.extend(self._layer1_pattern_matching(content))
        detections.extend(self._layer2_heuristic_analysis(content))

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
