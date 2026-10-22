"""The VirusTotal v3 client: looks a file up by its SHA-256 (``GET /files/{sha256}``), uploads a
file after an approved card (``POST /files``), polls the upload's analysis
(``GET /analyses/{id}``), and tests a key for the Service keys tab.

Why it exists: VirusTotal is the one outside service S10 talks to, with the owner's own key, and
every rule about that conversation lives here so it is written once and tested once:

- The key travels only in the ``x-apikey`` header: never in a URL, a log line, an error message
  or a result. Errors keep the exception's type name only, because an httpx message can quote
  the URL.
- Every request goes through the SSRF-guarded client (``services.tools.net``) under one of two
  network policies (``core/network_security.py``). The lookup policy reaches only
  ``/api/v3/files/<something>`` (its prefix ends in a slash, so even a bug cannot reach the upload
  endpoint ``/api/v3/files``); the upload policy is used only by an approved upload and its
  analysis polls. The resolvers log the policy key, never the URL. Redirects are not followed.
- A fingerprint must be 64 lowercase hex characters and an analysis id must match
  ``[A-Za-z0-9=_-]{1,128}`` before any request is built, so nothing a caller passes can change the
  path.
- An answer is read up to 1 MB. Only the counts, dates, a sanitised threat label and the type
  description are kept; names, tags, comments, votes and every vendor's result text are
  attacker-controlled and never read. Anything but the documented shape is a ``service_error``,
  never a verdict.
- ``verdict_of`` maps the counts to malicious / suspicious / no_detections / unknown. There is no
  "safe": no detections is not a guarantee, and a file VirusTotal never saw is unknown.

Connects to: core.network_security (VIRUSTOTAL_LOOKUP_POLICY, VIRUSTOTAL_UPLOAD_POLICY),
services.tools.net (build_guarded_client), services.reputation.keys (KeyTestResult; that registry
imports ``test_key`` lazily for the VirusTotal row).

Used by: services/file_reputation/service.py and store.py, and the Service keys tester.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Optional

import httpx
import structlog

from core.network_security import (
    VIRUSTOTAL_LOOKUP_POLICY,
    VIRUSTOTAL_UPLOAD_POLICY,
    check_network_policy,
)
from services.file_reputation.byte_sink import is_sha256
from services.file_reputation.verdicts import FileVerdict, clean_file_type, clean_threat_label
from services.reputation.keys import KeyTestResult
from services.tools.net import EgressBlocked, build_guarded_client

logger = structlog.get_logger(__name__)

VT_API = "https://www.virustotal.com/api/v3"
VT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # the direct POST /files limit
LOOKUP_TIMEOUT_S = 15.0
UPLOAD_TIMEOUT_S = 120.0
# Answers are small JSON documents; anything larger is not one.
MAX_ANSWER_BYTES = 1024 * 1024
# The EICAR test file's fingerprint: every vendor flags it, and looking it up downloads nothing.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# Three or more vendors calling a file malicious makes it malicious; one or two, or any
# "suspicious" vote, makes it suspicious (single detections are often false alarms).
MALICIOUS_THRESHOLD = 3
# A sanity bound on one count; VirusTotal runs about 70 engines.
_MAX_ENGINE_COUNT = 1000
# Unix times VirusTotal could plausibly answer (1990 .. 2100); anything else is dropped.
_MIN_TIMESTAMP = 631152000
_MAX_TIMESTAMP = 4102444800

_ANALYSIS_ID_RE = re.compile(r"[A-Za-z0-9=_-]{1,128}")
_HEADER_SAFE_KEY_RE = re.compile(r"[\x21-\x7e]{1,256}")
_KEY_FORMAT_RE = re.compile(r"[0-9A-Fa-f]{64}")

ErrorCode = Literal["key_rejected", "virustotal_limit", "service_error", "too_large", "empty"]
LookupVerdict = Literal["malicious", "suspicious", "no_detections", "unknown"]
AnalysisStatus = Literal["queued", "in-progress", "completed"]

_ERROR_SENTENCES: dict[str, str] = {
    "key_rejected": "VirusTotal rejected the key",
    "virustotal_limit": "VirusTotal asked Crawler to slow down",
    "service_error": "VirusTotal could not be reached",
    "too_large": "the file is larger than VirusTotal accepts (32 MB)",
    "empty": "the file is empty",
}

# Failures that happen before a request is on the wire: an upload that failed this way was
# certainly not received. Any other failure after sending (a read timeout, a dropped
# connection) may have been.
_NOT_SENT_ERRORS: tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
    httpx.UnsupportedProtocol,
    httpx.LocalProtocolError,
    httpx.ProxyError,
)

KEY_TEST_OK = "VirusTotal answered: the key works."
KEY_TEST_SLOW_DOWN = "VirusTotal accepted the key but asked to slow down."
KEY_TEST_REFUSED = (
    "VirusTotal refused the key: check that you pasted the whole API key from your VirusTotal "
    "profile."
)
KEY_TEST_UNREACHABLE = "VirusTotal could not be reached."
KEY_TEST_FORMAT = "A VirusTotal key is 64 characters, 0-9 and a-f."


class VirusTotalError(Exception):
    """A request that gave no answer. ``code``: key_rejected | virustotal_limit | service_error |
    too_large | empty. The message is a fixed sentence; it never holds the key, the URL or vendor
    text. ``status_code`` is VirusTotal's HTTP status when there was one, ``error_type`` the
    exception type behind a transport failure, and ``maybe_received`` is True when an upload
    failed after its bytes were sent (the card then says the file may have been received)."""

    def __init__(
        self,
        code: ErrorCode,
        message: str = "",
        *,
        status_code: Optional[int] = None,
        error_type: Optional[str] = None,
        maybe_received: bool = False,
    ) -> None:
        # The sentence comes from the code; *message* (the WAVE 0 signature) is used only for a
        # code without one, so no caller can put a URL or vendor text into the error.
        super().__init__(_ERROR_SENTENCES.get(code) or message or "VirusTotal could not be asked")
        self.code: ErrorCode = code
        self.status_code = status_code
        self.error_type = error_type
        self.maybe_received = maybe_received


@dataclass(frozen=True)
class VtFileReport:
    """The facts Crawler keeps from one VirusTotal file report or finished analysis."""

    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    # malicious + suspicious + harmless + undetected (timeouts, failures and unsupported types
    # are left out: those engines gave no opinion).
    engines: int
    threat_label: Optional[str]
    file_type: Optional[str]
    first_seen_at: Optional[datetime]
    analysed_at: Optional[datetime]


@dataclass(frozen=True)
class VtAnalysis:
    status: AnalysisStatus
    report: Optional[VtFileReport]  # only when completed
    # The fingerprint VirusTotal says it analysed, when its answer names one; the service checks
    # it against the uploaded file before trusting the report.
    sha256: Optional[str] = None


def verdict_of(report: Optional[VtFileReport]) -> LookupVerdict:
    """None or engines == 0 -> unknown; malicious >= 3 -> malicious; malicious 1-2 or
    suspicious >= 1 -> suspicious; else no_detections. Never 'safe'."""
    if report is None or report.engines <= 0:
        return "unknown"
    if report.malicious >= MALICIOUS_THRESHOLD:
        return "malicious"
    if report.malicious > 0 or report.suspicious > 0:
        return "suspicious"
    return "no_detections"


def verdict_from_report(
    sha256: str,
    report: Optional[VtFileReport],
    *,
    cached: bool = False,
    check_id: Optional[str] = None,
    can_upload: bool = False,
) -> FileVerdict:
    """The ``FileVerdict`` for VirusTotal's answer about *sha256* (None: VirusTotal does not know
    the file). ``can_upload`` is kept only for an unknown file."""
    verdict = verdict_of(report)
    if report is None:
        return FileVerdict(
            sha256=sha256,
            verdict=verdict,
            cached=cached,
            check_id=check_id,
            can_upload=can_upload,
        )
    return FileVerdict(
        sha256=sha256,
        verdict=verdict,
        malicious=report.malicious,
        suspicious=report.suspicious,
        engines=report.engines,
        threat_label=report.threat_label,
        file_type=report.file_type,
        first_seen=report.first_seen_at.date() if report.first_seen_at else None,
        last_scanned=report.analysed_at.date() if report.analysed_at else None,
        cached=cached,
        check_id=check_id,
        can_upload=can_upload and verdict == "unknown",
    )


# -- parsing --------------------------------------------------------------------------------


def _shape_error() -> VirusTotalError:
    return VirusTotalError("service_error", status_code=200, error_type="unexpected_answer")


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _shape_error()
    return value


def _stat(stats: dict[str, Any], key: str) -> int:
    value = stats.get(key, 0)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise _shape_error()
    if value < 0 or value > _MAX_ENGINE_COUNT:
        raise _shape_error()
    return value


def _timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not _MIN_TIMESTAMP <= value <= _MAX_TIMESTAMP:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _report_from_stats(
    stats: Any,
    *,
    threat_label: Optional[str] = None,
    file_type: Optional[str] = None,
    first_seen_at: Optional[datetime] = None,
    analysed_at: Optional[datetime] = None,
) -> VtFileReport:
    counts = _mapping(stats)
    malicious = _stat(counts, "malicious")
    suspicious = _stat(counts, "suspicious")
    harmless = _stat(counts, "harmless")
    undetected = _stat(counts, "undetected")
    return VtFileReport(
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        engines=malicious + suspicious + harmless + undetected,
        threat_label=threat_label,
        file_type=file_type,
        first_seen_at=first_seen_at,
        analysed_at=analysed_at,
    )


def parse_file_report(payload: Any) -> VtFileReport:
    """data.attributes.last_analysis_stats and the few safe facts. meaningful_name, names, tags,
    comments, votes and every vendor's result string are never read (attacker-controlled text).
    Raises VirusTotalError('service_error') for anything but the documented shape."""
    data = _mapping(_mapping(payload).get("data"))
    attributes = _mapping(data.get("attributes"))
    classification = attributes.get("popular_threat_classification")
    label = (
        clean_threat_label(classification.get("suggested_threat_label"))
        if isinstance(classification, dict)
        else None
    )
    return _report_from_stats(
        attributes.get("last_analysis_stats"),
        threat_label=label,
        file_type=clean_file_type(attributes.get("type_description")),
        first_seen_at=_timestamp(attributes.get("first_submission_date")),
        analysed_at=_timestamp(attributes.get("last_analysis_date")),
    )


def parse_analysis(payload: Any) -> VtAnalysis:
    """data.attributes.status, and for a completed analysis its stats and date. The analysed
    file's fingerprint is taken from meta.file_info.sha256 when it is one."""
    body = _mapping(payload)
    attributes = _mapping(_mapping(body.get("data")).get("attributes"))
    status = attributes.get("status")
    if status not in ("queued", "in-progress", "completed"):
        raise _shape_error()
    meta = body.get("meta")
    file_info = meta.get("file_info") if isinstance(meta, dict) else None
    reported = file_info.get("sha256") if isinstance(file_info, dict) else None
    sha256 = reported.lower() if isinstance(reported, str) and is_sha256(reported.lower()) else None
    if status != "completed":
        return VtAnalysis(status=status, report=None, sha256=sha256)
    report = _report_from_stats(
        attributes.get("stats"), analysed_at=_timestamp(attributes.get("date"))
    )
    return VtAnalysis(status="completed", report=report, sha256=sha256)


# -- transport ------------------------------------------------------------------------------


def _policy_addresses(url: str, policy: str) -> tuple[str, ...]:
    result = check_network_policy(url, policy)
    if not result.safe:
        # The policy key only: the URL holds a fingerprint, and check_ssrf keeps the address.
        logger.warning("virustotal_egress_blocked", policy=policy)
        raise EgressBlocked("VirusTotal is not reachable under the network policy.")
    return result.resolved_ips


def _lookup_addresses(url: str) -> tuple[str, ...]:
    """The lookup client's resolver: the ``virustotal_lookup`` policy, then the addresses to
    pin. Reaches nothing but ``GET /api/v3/files/<sha256>``."""
    return _policy_addresses(url, VIRUSTOTAL_LOOKUP_POLICY)


def _upload_addresses(url: str) -> tuple[str, ...]:
    """The upload client's resolver: the ``virustotal_upload`` policy (``POST /api/v3/files`` and
    ``GET /api/v3/analyses/<id>``)."""
    return _policy_addresses(url, VIRUSTOTAL_UPLOAD_POLICY)


def _require_sha256(sha256: Any) -> str:
    if not is_sha256(sha256):
        raise ValueError("not a SHA-256 fingerprint (64 lowercase hex characters)")
    return str(sha256)


def _require_key(api_key: Any) -> str:
    # A key that cannot be a header value (a stray newline from .env, a pasted space) is
    # refused here, before httpx could put it into an error message.
    if not isinstance(api_key, str) or _HEADER_SAFE_KEY_RE.fullmatch(api_key) is None:
        raise VirusTotalError("key_rejected", error_type="malformed_key")
    return api_key


async def _read_capped(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > MAX_ANSWER_BYTES:
            raise VirusTotalError(
                "service_error", status_code=response.status_code, error_type="answer_too_large"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _may_have_taken(status_code: Optional[int]) -> bool:
    """Whether an upload answered with *status_code* may still have reached VirusTotal: a 200
    (accepted, whatever its body) or any 5xx (a gateway error after the whole body was sent)."""
    return status_code is not None and (status_code == 200 or status_code >= 500)


class VirusTotalClient:
    """Lookups, uploads and analysis polls with one owner key per call. Holds no key and no
    state; *transport* is the test seam (the network policy still runs in front of it)."""

    def __init__(self, *, transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        self._transport = transport

    async def _request(
        self,
        kind: str,
        method: str,
        url: str,
        *,
        api_key: str,
        resolver: Callable[[str], tuple[str, ...]],
        timeout_s: float,
        files: Optional[dict[str, Any]] = None,
        not_found_ok: bool = False,
    ) -> tuple[int, Any]:
        """(status, parsed JSON) for a 200, or (404, None) when *not_found_ok*. Every other
        outcome raises ``VirusTotalError``."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "Crawler-AI",
            "x-apikey": _require_key(api_key),
        }
        try:
            client = build_guarded_client(
                timeout_s=timeout_s,
                headers=headers,
                resolver=resolver,
                transport=self._transport,
                follow_redirects=False,
            )
            async with client:
                async with client.stream(method, url, files=files) as response:
                    status = response.status_code
                    body = await _read_capped(response) if status == 200 else b""
        except VirusTotalError:
            raise
        except EgressBlocked:
            raise VirusTotalError("service_error", error_type="EgressBlocked") from None
        except httpx.HTTPError as exc:
            # Only the type: an httpx message can carry the URL.
            error_type = type(exc).__name__
            logger.warning("virustotal_request_failed", kind=kind, error_type=error_type)
            raise VirusTotalError(
                "service_error",
                error_type=error_type,
                maybe_received=not isinstance(exc, _NOT_SENT_ERRORS),
            ) from None
        if status == 200:
            try:
                return status, json.loads(body)
            # ValueError covers JSONDecodeError, UnicodeDecodeError and an over-long integer;
            # RecursionError is deeply nested JSON that still fits under MAX_ANSWER_BYTES. Both
            # are no answer, and callers rely on VirusTotalError being the only failure.
            except (ValueError, RecursionError):
                raise VirusTotalError(
                    "service_error", status_code=200, error_type="not_json"
                ) from None
        if status == 404 and not_found_ok:
            return status, None
        logger.warning("virustotal_request_refused", kind=kind, status_code=status)
        if status in (401, 403):
            raise VirusTotalError("key_rejected", status_code=status)
        if status == 429:
            raise VirusTotalError("virustotal_limit", status_code=status)
        if status == 413:
            raise VirusTotalError("too_large", status_code=status)
        raise VirusTotalError("service_error", status_code=status)

    async def lookup(self, api_key: str, sha256: str) -> Optional[VtFileReport]:
        """GET /files/{sha256} under the 'virustotal_lookup' policy; None on 404 (unknown).
        ``ValueError`` for a value that is not a fingerprint, before any request."""
        digest = _require_sha256(sha256)
        _status, payload = await self._request(
            "lookup",
            "GET",
            f"{VT_API}/files/{digest}",
            api_key=api_key,
            resolver=_lookup_addresses,
            timeout_s=LOOKUP_TIMEOUT_S,
            not_found_ok=True,
        )
        if payload is None:
            return None
        report = parse_file_report(payload)
        answered_for = payload["data"].get("id")
        if answered_for is not None and (
            not isinstance(answered_for, str) or answered_for.lower() != digest
        ):
            # A report about some other file is no answer about this one.
            raise _shape_error()
        return report

    async def upload(self, api_key: str, data: bytes) -> str:
        """POST /files (multipart field 'file', filename 'file') under 'virustotal_upload'; the
        analysis id. The file's own name never leaves the machine.

        ``maybe_received`` is True on every failure after the bytes were sent whose answer does
        not say VirusTotal refused them: a timeout or dropped connection while waiting, a 200
        (VirusTotal accepted the file) whose body is not the documented shape, and a 5xx (a
        gateway that may have passed the whole upload on). A 401/403, 413 or 429 is
        VirusTotal's own refusal, so the file was not taken."""
        if not data:
            raise VirusTotalError("empty")
        if len(data) > VT_MAX_UPLOAD_BYTES:
            raise VirusTotalError("too_large")
        try:
            _status, payload = await self._request(
                "upload",
                "POST",
                f"{VT_API}/files",
                api_key=api_key,
                resolver=_upload_addresses,
                timeout_s=UPLOAD_TIMEOUT_S,
                files={"file": ("file", data, "application/octet-stream")},
            )
            data_obj = _mapping(_mapping(payload).get("data"))
            analysis_id = data_obj.get("id")
            if not isinstance(analysis_id, str) or _ANALYSIS_ID_RE.fullmatch(analysis_id) is None:
                raise _shape_error()
        except VirusTotalError as exc:
            if exc.maybe_received or not _may_have_taken(exc.status_code):
                raise
            raise VirusTotalError(
                exc.code,
                status_code=exc.status_code,
                error_type=exc.error_type,
                maybe_received=True,
            ) from None
        return analysis_id

    async def analysis(self, api_key: str, analysis_id: str) -> VtAnalysis:
        """GET /analyses/{id} under 'virustotal_upload'. ``ValueError`` for an id outside
        ``[A-Za-z0-9=_-]{1,128}``, before any request."""
        if not isinstance(analysis_id, str) or _ANALYSIS_ID_RE.fullmatch(analysis_id) is None:
            raise ValueError("not a VirusTotal analysis id")
        _status, payload = await self._request(
            "analysis",
            "GET",
            f"{VT_API}/analyses/{analysis_id}",
            api_key=api_key,
            resolver=_upload_addresses,
            timeout_s=LOOKUP_TIMEOUT_S,
        )
        return parse_analysis(payload)


async def test_key(
    key: str, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> KeyTestResult:
    """S4's Service keys tester: one lookup of EICAR_SHA256 with *key* (no store, no cache, no
    limiter). 200 or 404 -> ok; 401/403 -> refused; 429 -> ok ('VirusTotal accepted the key but
    asked to slow down'); network -> not ok ('VirusTotal could not be reached'). Never quotes the
    key. A key that is not 64 hex characters is refused without a request."""
    if not isinstance(key, str) or _KEY_FORMAT_RE.fullmatch(key) is None:
        return KeyTestResult(False, KEY_TEST_FORMAT)
    try:
        await VirusTotalClient(transport=transport).lookup(key, EICAR_SHA256)
    except VirusTotalError as exc:
        if exc.code == "key_rejected":
            return KeyTestResult(False, KEY_TEST_REFUSED)
        if exc.code == "virustotal_limit":
            return KeyTestResult(True, KEY_TEST_SLOW_DOWN)
        return KeyTestResult(False, KEY_TEST_UNREACHABLE)
    return KeyTestResult(True, KEY_TEST_OK)


# pytest collects module-level callables named test_*; this one is the key tester, not a test.
test_key.__test__ = False  # type: ignore[attr-defined]
