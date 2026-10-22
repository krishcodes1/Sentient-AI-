"""The scam check service (security S3): one ``ScamCheckService`` per process
that runs every out-of-turn check (Telegram, Slack, web chat, the Security
page) and answers the in-turn security.check_scam tool.

Why it exists: every entry point must give the same answer for the same
message, under the same switch, quota and failure policy, and must never say
"safe". The service reads the owner's switch per check, runs the free local
checks, sends links to the link reputation service (Google's list only with
the owner's key), asks the account's own AI provider once (out of turn only;
the AI can raise the verdict, never lower it), and writes a facts-only audit
row (``scam_check_ran`` / ``scam_check_refused``). It touches the network and
the model, so it is not in services/security (local only).

The out-of-turn flow (``check``, S3 section 4.3): switch, inputs, the answer
kept from a few minutes ago, quota, the local pass, links, files (hash only),
one tool-less ``complete_once`` under a 60 s timeout, the links the AI read
from pictures and QR codes, the verdict, the audit row. The in-turn tool
(``check_for_tool``, 4.4) runs the local pass, the sender checks and link
reputation only: no model call (it would not reach /usage, and the turn's own
model already reads the message) and no quota.

Privacy: the checked text, the note, links, hosts and reasons never reach a
log line or an audit row; pictures live in memory for one check and leave
only their sha256. Logs carry error type names only.

Import rule: never import api.routes.agent at module level here.

Connects to: main.py (``scam_check_for``), services/scam_check/channels.py and
web.py, services/tools/security_checks.py (``check_for_tool``),
api/routes/security_scam.py.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Literal, Mapping, Optional, Protocol

import structlog

from services.capabilities.scam_check import CAPABILITY as SCAM_CHECK_CAPABILITY
from services.capabilities.scam_check import SCAM_CHECK_SETTINGS_DEFAULTS
from services.scam_check.links import (
    FileChecker,
    LinkChecker,
    check_files_counted,
    check_links,
    files_configured,
    link_sources,
    sender_findings,
)
from services.scam_check.quota import RecentChecks, ScamQuota
from services.scam_check.review import (
    SCAM_SYSTEM_PROMPT,
    Review,
    build_review_messages,
    injection_signals,
    parse_review,
    prepare_input,
    prepare_tool_input,
    review_links,
)
from services.scam_check.verdict import (
    advice_for,
    ai_reasons_for,
    codes_for,
    combine,
    notes_for,
    provider_label,
    ran_facts,
    reasons_for,
    refused_facts,
    to_json,
)
from services.security.lookalike import decode_host, lookalike_of, registrable_domain
from services.security.scam_signals import MAX_URLS, Signal, TextFindings, analyse_text

logger = structlog.get_logger(__name__)

Channel = Literal["telegram", "slack", "web_chat", "web_box"]
Verdict = Literal["likely_scam", "suspicious", "no_signs_found", "not_checked"]
CAPABILITY_KEY = "scam_check"
CHANNELS: tuple[str, ...] = ("telegram", "slack", "web_chat", "web_box")

# What the WAVE 0 stub answered; kept for callers that still name them. The real
# service never answers NOT_BUILT; TOOL_NOT_AVAILABLE is the security family's
# own sentence (services/tools/security_checks.py).
NOT_BUILT = "Scam checks are being built."
NOT_BUILT_REASON = "not_built"
TOOL_NOT_AVAILABLE = "This safety check is not available right now."

# Refusal sentences: fixed text, never the checked content.
GATE_ERROR = (
    "\u26a0\ufe0f I couldn't check whether scam checks are turned on, so I didn't check that. "
    "Please try again in a minute."
)
QUOTA_BURST = "That's a lot of scam checks at once. Please wait a minute and try again."
QUOTA_DAILY = (
    "You've used today's {n} scam checks. Try again tomorrow, or ask the owner to raise the "
    "limit in Settings \u2192 Permissions."
)
NOTHING_TO_CHECK = "There's nothing to check. Paste the message or link, or add a screenshot."
PROVIDER_BLIND = (
    "\u2754 I couldn't check this\n\nYour AI provider ({provider}) can't look at pictures. "
    "Paste the text or the link instead{how}"
)
UNEXPECTED_ERROR = "\u26a0\ufe0f The scam check hit an unexpected error. Nothing was checked."
TOOL_FAILED = "The scam check failed; nothing was checked."
# How each channel asks for a check, for the "paste the text instead" line (the web
# chat's reply is Markdown, where "<text>" would read as a tag).
_HOW_TO_ASK: dict[str, str] = {
    "telegram": ":\n/scam <text>",
    "web_chat": " after /scam.",
    "slack": ":\nscam <text>",
    "web_box": ".",
}
# At most this many files are looked up per check (links.MAX_FILES).
_MAX_FILES = 10


@dataclass(frozen=True)
class ScamImage:
    """One picture to check, in memory only: base64 data with no data: prefix,
    a sniffed media type in ALLOWED_IMAGE_TYPES (agent.py), and where it came
    from (photo|document|upload|reply)."""

    media_type: str
    data: str
    source: str = "photo"


@dataclass(frozen=True)
class ScamFile:
    """A non-image file sent for checking: only its sha256 and size (the bytes
    are already gone)."""

    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class ScamCheckRequest:
    """One out-of-turn check. *text* is the content to check (someone else's
    words); *note* is the person's own words about it (<= 500 chars, kept
    outside the fence); *anchors* are hidden links the channel found (Telegram
    text_link)."""

    user_id: str
    channel: Channel
    text: str = ""
    note: str = ""
    images: tuple[ScamImage, ...] = ()
    files: tuple[ScamFile, ...] = ()
    anchors: tuple[tuple[str, str], ...] = ()
    forwarded: bool = False


@dataclass(frozen=True)
class LinkFinding:
    """One link as checked: its display form (ASCII), host (punycode), the site
    it imitates ("" if none), the level, which sources looked
    (local|safe_browsing|web_risk), where it came from, and S4's codes."""

    shown: str
    host: str
    looks_like: str
    level: Literal["malicious", "suspicious", "no_signs_found", "not_checked"]
    checked_by: tuple[str, ...]
    origin: Literal["text", "picture", "qr", "sender"]
    codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScamCheckResult:
    """A check's answer. ok=False is a refusal (nothing was checked): *refusal*
    is the sentence and *reason* its code. Otherwise the verdict, fixed-length
    reasons and advice, links, notes on what was not checked, and the facts
    the audit row and the usage columns need."""

    ok: bool
    verdict: Verdict = "not_checked"
    reasons: tuple[str, ...] = ()  # Crawler's own fixed sentences only
    ai_reasons: tuple[str, ...] = ()  # the provider's, after filter_reasons (SEC-M2), <= 3
    advice: tuple[str, ...] = ()
    links: tuple[LinkFinding, ...] = ()
    notes: tuple[str, ...] = ()
    note_codes: tuple[str, ...] = ()
    signal_codes: tuple[str, ...] = ()
    rule_verdict: Verdict = "not_checked"
    ai_verdict: str = ""
    ai_ran: bool = False
    qr_present: bool = False
    qr_readable: bool = False
    provider: str = ""
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    text_chars: int = 0
    images: int = 0
    image_sha256: tuple[str, ...] = ()
    files: int = 0
    cached: bool = False
    refusal: str = ""
    reason: str = ""


class ScamSettings(Protocol):
    """The owner's settings for the check (InstallationService satisfies it)."""

    async def capability_settings(self, key: str) -> dict[str, Any]: ...


# The owner's capability report by key (InstallationService.capability_statuses).
CapabilityGate = Callable[[], Awaitable[Mapping[str, Any]]]


class ScamGateUnavailable(RuntimeError):
    """The capability report could not be read (status() only: check() and
    precheck() refuse with GATE_ERROR instead)."""


def provider_sees_images(name: Optional[str]) -> bool:
    """Whether the provider registered as *name* accepts image blocks: the
    class flag (providers.py), so no key or network is needed. An unknown or
    empty name sees nothing."""
    from services.agent.providers import PROVIDER_REGISTRY

    provider_cls = PROVIDER_REGISTRY.get((name or "").strip().lower())
    return bool(provider_cls is not None and provider_cls.supports_vision)


def scam_check_for(app: Any, session_factory: Callable[[], Any]) -> Optional["ScamCheckService"]:
    """The process's one ScamCheckService on app.state.scam_check (made on
    first use: main.py asks from _wire_telegram, which can run before the end
    of wire_services, and again at its end); None without an
    InstallationService. A service made for another InstallationService (a
    test that wired the app again) is replaced."""
    installation = getattr(app.state, "installation", None)
    existing = getattr(app.state, "scam_check", None)
    if existing is not None and (installation is None or getattr(existing, "installation", None) is installation):
        return existing  # type: ignore[no-any-return]
    if installation is None:
        return None
    service = ScamCheckService(
        session_factory,
        capability_gate=installation.capability_statuses,
        settings=installation,
        runtime_getter=lambda: getattr(app.state, "agent_runtime", None),
        links_getter=lambda: getattr(app.state, "link_reputation", None),
        files_getter=lambda: getattr(app.state, "file_reputation", None),
    )
    service.installation = installation
    app.state.scam_check = service
    return service


def _known_site(host: str) -> Optional[str]:
    """The well-known site a look-alike host imitates (services.security.lookalike), or None."""
    decoded = decode_host(host)
    if not decoded:
        return None
    hit = lookalike_of(decoded)
    return hit.known if hit is not None else None


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _default_per_day() -> int:
    return int(SCAM_CHECK_SETTINGS_DEFAULTS["checks_per_day"])


def _refused(reason: str, sentence: str, *, provider: str = "") -> ScamCheckResult:
    return ScamCheckResult(ok=False, refusal=sentence, reason=reason, provider=provider)


def _ordered_codes(codes: Any) -> tuple[str, ...]:
    """Note codes, each once, in the order first seen."""
    return tuple(dict.fromkeys(code for code in codes if code))


def _channel(channel: Any) -> str:
    """A channel name for an audit row: one of CHANNELS, never free text."""
    return channel if channel in CHANNELS else "web_box"


def _provider_name(provider: str) -> str:
    return provider_label(provider) if provider else "not set up"


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class ScamCheckService:
    """See the module docstring. *capability_gate* is
    InstallationService.capability_statuses and *settings* the
    InstallationService; *runtime_getter* answers the AgentRuntime
    (resolve_turn_provider, complete_once); *links_getter* and *files_getter*
    answer S4's LinkChecker and S10's FileReputationService (or None). The
    quota, the recent answers, the PromptGuard scanner and the clock are
    injectable for tests."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        capability_gate: CapabilityGate,
        settings: ScamSettings,
        runtime_getter: Callable[[], Any],
        links_getter: Callable[[], Optional[LinkChecker]],
        files_getter: Callable[[], Optional[FileChecker]] = lambda: None,
        quota: Optional[ScamQuota] = None,
        recent: Optional[RecentChecks] = None,
        scanner: Optional[Any] = None,
        clock: Callable[[], float] = time.monotonic,
        ai_timeout_s: float = 60.0,
    ) -> None:
        self._session_factory = session_factory
        self._capability_gate = capability_gate
        self._settings = settings
        self._runtime_getter = runtime_getter
        self._links_getter = links_getter
        self._files_getter = files_getter
        self.quota = quota or ScamQuota(clock=clock)
        self.recent = recent or RecentChecks(clock=clock)
        self._scanner = scanner
        self._clock = clock
        self._ai_timeout_s = ai_timeout_s
        # The InstallationService scam_check_for built this service from (None when built by hand).
        self.installation: Optional[Any] = None

    # ── the switch and the owner's daily cap ────────────────────────────

    async def _switch(self) -> Optional[tuple[str, str]]:
        """(reason code, sentence) when scam checks may not run now, else None.
        Fail closed: a gate that raises refuses."""
        try:
            statuses = await self._capability_gate()
        except Exception as exc:
            logger.warning("scam_check_capability_gate_failed", error_type=type(exc).__name__)
            return "gate_error", GATE_ERROR
        status = _field(statuses, CAPABILITY_KEY) if statuses is not None else None
        when_denied = SCAM_CHECK_CAPABILITY.when_denied
        if status is None:
            return "capability_off", when_denied
        effective = str(_field(status, "effective", "") or "")
        if effective == "on":
            return None
        if effective == "blocked":
            reason = str(_field(status, "reason", "") or "").strip()
            return "capability_blocked", reason or when_denied
        return "capability_off", str(_field(status, "when_denied", "") or "").strip() or when_denied

    async def _per_day(self) -> int:
        """The owner's checks_per_day; the default on a read error or an odd value."""
        try:
            value = (await self._settings.capability_settings(CAPABILITY_KEY)).get("checks_per_day")
        except Exception as exc:
            logger.warning("scam_check_settings_unreadable", error_type=type(exc).__name__)
            return _default_per_day()
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return _default_per_day()
        return value

    def _quota_refusal(self, user_id: str, per_day: int) -> Optional[tuple[str, str]]:
        over = self.quota.refusal(user_id, per_day)
        if over == "burst":
            return "quota_burst", QUOTA_BURST
        if over == "daily":
            return "quota_daily", QUOTA_DAILY.format(n=per_day)
        return None

    async def precheck(self, user_id: str, channel: Channel) -> Optional[str]:
        """Before any download: the refusal sentence (switch off/blocked, gate
        error, burst or daily quota), audited as scam_check_refused, or None.
        Reads only; takes no quota."""
        refusal = await self._switch()
        if refusal is None:
            refusal = self._quota_refusal(str(user_id), await self._per_day())
        if refusal is None:
            return None
        await self.refused(user_id, channel, refusal[0])
        return refusal[1]

    async def refused(self, user_id: str, channel: str, reason: str) -> None:
        """Record a refusal: one this service made, or one a channel met itself
        (too large, a download that failed, an unsupported kind)."""
        await self._audit(user_id, channel, refused_facts(_channel(channel), reason), ok=False)

    # ── the out-of-turn check ───────────────────────────────────────────

    async def check(self, request: ScamCheckRequest) -> ScamCheckResult:
        """The full out-of-turn check (4.3): switch, quota, local pass, link and
        file reputation, one AI review, verdict, audit. Never raises for bad
        input or a failing dependency."""
        try:
            return await self._check(request)
        except Exception as exc:
            logger.error("scam_check_failed", error_type=type(exc).__name__)
        # Recording the refusal is best effort too: the caller always gets the sentence.
        try:
            await self.refused(request.user_id, request.channel, "error")
        except Exception as exc:
            logger.error("scam_check_audit_failed", audit_event="scam_check_refused", error_type=type(exc).__name__)
        return _refused("error", UNEXPECTED_ERROR)

    async def _refuse(self, request: ScamCheckRequest, reason: str, sentence: str, provider: str = "") -> ScamCheckResult:
        await self.refused(request.user_id, request.channel, reason)
        return _refused(reason, sentence, provider=provider)

    async def _check(self, request: ScamCheckRequest) -> ScamCheckResult:
        user_id = str(request.user_id)
        refusal = await self._switch()
        if refusal is not None:
            return await self._refuse(request, *refusal)
        prepared = prepare_input(request)
        files = [f for f in request.files if getattr(f, "sha256", "")][:_MAX_FILES]
        if prepared.empty and not files:
            return await self._refuse(request, "empty", NOTHING_TO_CHECK)

        key = self.recent.key(request, prepared.image_sha256)
        kept = self.recent.get(key)
        if kept is not None:
            return await self._answer_again(request, kept)

        per_day = await self._per_day()
        refusal = self._quota_refusal(user_id, per_day)
        if refusal is not None:
            return await self._refuse(request, *refusal)
        self.quota.take(user_id)

        # Step 5: the local pass (the text is already cut to 8,000 characters).
        findings = analyse_text(prepared.text, extra_anchors=request.anchors, registrable=registrable_domain)
        signals: list[Signal] = [*findings.signals, *injection_signals(prepared.text, self._scanner)]
        notes: list[str] = list(prepared.note_codes)
        if findings.more_urls:
            notes.append("too_many_links")

        # Step 6: the links in the text (and the channel's hidden ones).
        links = self._links_getter()
        found, link_notes = await check_links(links, findings.urls, "text", known_site=_known_site)
        notes.extend(link_notes)

        # Step 7: files, by fingerprint only (never an upload).
        file_signals, file_notes, files_answered = await check_files_counted(
            self._files_getter(), files, user_id=user_id
        )
        signals.extend(file_signals)
        notes.extend(file_notes)
        if files and request.channel == "web_chat":
            notes.append("files_by_fingerprint")

        # Step 8: one look by the account's own AI provider.
        review: Optional[Review] = None
        ai_reasons: tuple[str, ...] = ()
        usage: dict[str, int] = {}
        provider = model = ""
        images = prepared.images
        if prepared.text or images:
            try:
                provider, model = await self.turn_provider(user_id)
            except Exception as exc:
                logger.info("scam_check_no_provider", error_type=type(exc).__name__)
                notes.append("ai_not_set_up")
                provider = model = ""
            else:
                if images and not provider_sees_images(provider):
                    notes.append("no_vision")
                    images = ()
                    if not prepared.text and not files:
                        # Nothing else to look at: give the check back (4.3 step 8.2).
                        self.quota.give_back(user_id)
                        how = _HOW_TO_ASK.get(request.channel, ".")
                        sentence = PROVIDER_BLIND.format(provider=_provider_name(provider), how=how)
                        return await self._refuse(request, "provider_blind", sentence, provider)
                if prepared.text or images:
                    review, usage, provider, model, ai_notes = await self._review(
                        dataclasses.replace(request, text=prepared.text, note=prepared.note),
                        findings,
                        found,
                        images,
                        provider,
                        model,
                    )
                    notes.extend(ai_notes)
                    if review is not None:
                        ai_reasons, withheld = ai_reasons_for(review, self._scanner)
                        if withheld:
                            notes.append("reasons_withheld")

        # Step 9: links the AI read from the pictures or a readable QR code.
        picture_urls, qr_urls, review_notes = review_links(review, findings.urls)
        notes.extend(review_notes)
        for urls, origin in ((picture_urls, "picture"), (qr_urls, "qr")):
            if urls:
                more, more_notes = await check_links(links, urls, origin, known_site=_known_site)
                found.extend(more)
                notes.extend(more_notes)

        # Step 10: the verdict. The AI can raise it, never lower it.
        pictures_read = review is not None and bool(images)
        analysed = bool(prepared.text) or pictures_read or bool(found) or files_answered > 0
        final, rule = combine(signals, found, review, analysed=analysed)
        codes = codes_for(signals, found)
        note_codes = _ordered_codes(notes)
        result = ScamCheckResult(
            ok=True,
            verdict=final,
            reasons=reasons_for(signals, found),
            ai_reasons=ai_reasons,
            advice=advice_for(final, codes, review.asks_for if review is not None else frozenset()),
            links=tuple(found),
            notes=notes_for(note_codes, provider=provider),
            note_codes=note_codes,
            signal_codes=codes,
            rule_verdict=rule,
            ai_verdict=review.verdict if review is not None else "",
            ai_ran=review is not None,
            qr_present=bool(review is not None and review.qr_present),
            qr_readable=bool(review is not None and review.qr_readable),
            provider=provider,
            model=model,
            usage=usage,
            text_chars=len(prepared.text),
            images=len(prepared.images),
            image_sha256=prepared.image_sha256,
            files=len(files),
        )
        # Step 11: the facts-only row, then the memory for the same content.
        await self._audit(user_id, request.channel, ran_facts(request, result), ok=True)
        self.recent.put(key, result)
        return result

    async def _answer_again(self, request: ScamCheckRequest, kept: ScamCheckResult) -> ScamCheckResult:
        """The answer kept for the same content a few minutes ago: no quota, no
        model call, no new usage (the earlier rows already carry it)."""
        note_codes = _ordered_codes((*kept.note_codes, "cached"))
        result = dataclasses.replace(
            kept,
            cached=True,
            usage={},
            note_codes=note_codes,
            notes=notes_for(note_codes, provider=kept.provider),
        )
        await self._audit(request.user_id, request.channel, ran_facts(request, result), ok=True)
        return result

    async def _review(
        self,
        request: ScamCheckRequest,
        findings: TextFindings,
        links: list[LinkFinding],
        images: tuple[ScamImage, ...],
        provider: str,
        model: str,
    ) -> tuple[Optional[Review], dict[str, int], str, str, list[str]]:
        """One tool-less complete_once over the fenced message and the pictures
        (4.3 step 8.3-8.6): (review or None, usage, provider, model, note
        codes). Never raises: a failure is a note and the automatic checks
        stand. The call runs no PromptGuard input scan, so pasted look-alike
        letters and hidden characters reach the model; the model-egress floor
        and "Hide personal details" still apply inside complete_once."""
        from services.agent.providers import ProviderError, ProviderNotConfigured

        runtime = self._runtime_getter()
        if runtime is None:
            return None, {}, provider, model, ["ai_not_set_up"]
        messages = build_review_messages(request, findings, links, images)
        try:
            once = await asyncio.wait_for(
                runtime.complete_once(messages, llm_provider=provider, llm_model=model, system=SCAM_SYSTEM_PROMPT),
                self._ai_timeout_s,
            )
        except ProviderNotConfigured:
            return None, {}, provider, model, ["ai_not_set_up"]
        except ProviderError as exc:
            logger.warning("scam_check_review_failed", error_type=type(exc).__name__, status_code=exc.status_code)
            return None, {}, provider, model, ["ai_failed"]
        except asyncio.TimeoutError:
            logger.warning("scam_check_review_timed_out", timeout_s=self._ai_timeout_s)
            return None, {}, provider, model, ["ai_failed"]
        except Exception as exc:
            logger.warning("scam_check_review_failed", error_type=type(exc).__name__)
            return None, {}, provider, model, ["ai_failed"]
        raw_usage = getattr(once, "usage", None)
        usage = {str(k): int(v) for k, v in dict(raw_usage or {}).items() if _is_count(v)}
        provider = str(getattr(once, "provider", "") or provider)
        model = str(getattr(once, "model", "") or model)
        # The reply is shaped by the pasted message (prompt injection), so reading it may meet
        # anything: whatever goes wrong here is an unreadable answer, and the local checks and
        # link reputation stand (4.9). It must never reach check()'s catch-all, which would
        # throw away the rule verdict.
        try:
            review = parse_review(str(getattr(once, "text", "") or ""))
        except Exception as exc:
            logger.warning("scam_check_review_unreadable", error_type=type(exc).__name__)
            review = None
        return review, usage, provider, model, ([] if review is not None else ["ai_unreadable"])

    # ── the in-turn tool ────────────────────────────────────────────────

    async def check_for_tool(
        self, params: dict[str, Any], user_id: str, *, approved: bool = False
    ) -> dict[str, Any]:
        """The security.check_scam handler (4.4): local pass and link reputation
        only, no model call and no quota; {"ok": True, ...to_json...} or
        {"ok": False, "error": ...}; never raises. *approved* is ignored (a
        READ needs no card). No row is written here: the runtime's
        tool_executed row keeps the arguments' lengths and counts."""
        try:
            return await self._check_for_tool(params)
        except Exception as exc:
            logger.error("scam_check_tool_failed", error_type=type(exc).__name__)
            return {"ok": False, "error": TOOL_FAILED}

    async def _check_for_tool(self, params: Any) -> dict[str, Any]:
        tool = prepare_tool_input(params)
        if isinstance(tool, str):
            return {"ok": False, "error": tool}
        findings = analyse_text(tool.text, registrable=registrable_domain)
        signals: list[Signal] = [*findings.signals, *injection_signals(tool.text, self._scanner)]
        sender_signals, sender_urls = sender_findings(tool.sender, tool.reply_to)
        signals.extend(sender_signals)
        notes: list[str] = list(tool.note_codes)
        urls: list[str] = []
        seen: set[str] = set()
        for url in (*findings.urls, *tool.urls):
            if url.lower() not in seen:
                seen.add(url.lower())
                urls.append(url)
        if len(urls) > MAX_URLS or findings.more_urls:
            notes.append("too_many_links")
            urls = urls[:MAX_URLS]
        links = self._links_getter()
        found, link_notes = await check_links(links, urls, "text", known_site=_known_site)
        notes.extend(link_notes)
        if sender_urls:
            sender_links, sender_notes = await check_links(links, sender_urls, "sender", known_site=_known_site)
            found.extend(sender_links)
            notes.extend(sender_notes)
        final, rule = combine(signals, found, None, analysed=True)
        codes = codes_for(signals, found)
        note_codes = _ordered_codes(notes)
        result = ScamCheckResult(
            ok=True,
            verdict=final,
            reasons=reasons_for(signals, found),
            advice=advice_for(final, codes, frozenset()),
            links=tuple(found),
            notes=notes_for(note_codes),
            note_codes=note_codes,
            signal_codes=codes,
            rule_verdict=rule,
            text_chars=len(tool.text),
        )
        return {"ok": True, **to_json(result)}

    # ── what the Security tab shows ─────────────────────────────────────

    async def status(self, user_id: str) -> dict[str, Any]:
        """What the Security tab shows before a check (the GET status route's
        body, 4.5.4). ScamGateUnavailable when the switch cannot be read."""
        try:
            statuses = await self._capability_gate()
        except Exception as exc:
            logger.warning("scam_check_capability_gate_failed", error_type=type(exc).__name__)
            raise ScamGateUnavailable("capability report unreadable") from None
        status = _field(statuses, CAPABILITY_KEY) if statuses is not None else None
        effective = str(_field(status, "effective", "") or "off") if status is not None else "off"
        if effective not in ("on", "off", "blocked"):
            effective = "off"
        reason = ""
        if effective == "blocked":
            reason = str(_field(status, "reason", "") or "").strip() or SCAM_CHECK_CAPABILITY.when_denied
        elif effective == "off":
            reason = str(_field(status, "when_denied", "") or "").strip() or SCAM_CHECK_CAPABILITY.when_denied
        try:
            provider, _model = await self.turn_provider(user_id)
        except Exception as exc:
            logger.info("scam_check_no_provider", error_type=type(exc).__name__)
            provider = ""
        sources = await link_sources(self._links_getter())
        google = None if sources is None else bool(sources & {"safe_browsing", "web_risk"})
        return {
            "effective": effective,
            "reason": reason,
            "provider": provider,
            "sees_images": provider_sees_images(provider) if provider else False,
            "google_list": google,
            "file_reputation": await files_configured(self._files_getter()),
            "checks_per_day": await self._per_day(),
            "checks_used_today": self.quota.used_today(str(user_id)),
        }

    async def turn_provider(self, user_id: str) -> tuple[str, str]:
        """(provider, model) this account's turns use: its own pick, else the
        install default (AgentRuntime.resolve_turn_provider, as voice notes
        do). Raises when there is no runtime or no provider."""
        from sqlalchemy import select

        from models.user import User

        runtime = self._runtime_getter()
        if runtime is None:
            raise RuntimeError("no runtime")
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(User.llm_provider, User.llm_model).where(User.id == uuid.UUID(str(user_id)))
                )
            ).first()
        pinned_provider, pinned_model = (row[0], row[1]) if row is not None else (None, None)
        provider, model = await runtime.resolve_turn_provider(pinned_provider, pinned_model)
        return str(provider or ""), str(model or "")

    # ── audit ───────────────────────────────────────────────────────────

    async def _audit(self, user_id: str, channel: str, facts: dict[str, Any], *, ok: bool) -> None:
        """One row: facts only (verdicts, counts, codes, picture and file
        sha256s), never the text, the note, a link, a host or a reason. Best
        effort: the answer stands when the row cannot be written."""
        from models.audit import AuditStatus
        from services.audit import append_audit_log

        try:
            async with self._session_factory() as session:
                await append_audit_log(
                    session,
                    user_id=str(user_id),
                    connector_name="scam_check",
                    action="check",
                    endpoint=f"{_channel(channel)}:scam",
                    scope_used=CAPABILITY_KEY,
                    status=AuditStatus.approved if ok else AuditStatus.blocked,
                    reasoning_chain=facts,
                )
                await session.commit()
        except Exception as exc:
            # "audit_event", never "event": structlog's own first argument is named event,
            # so event= would raise a TypeError here and turn a failed row into a lost answer.
            logger.error("scam_check_audit_failed", audit_event=facts.get("event"), error_type=type(exc).__name__)
