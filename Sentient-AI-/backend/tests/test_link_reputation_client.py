"""Tests for services/reputation/links.py, the owner-keyed Google link lookups: they prove
nothing is sent without a key, with the switch off or when the owner's settings cannot be
read; Safe Browsing gets one batched POST and Web Risk one GET per link (capped), always with
the key in a header and never in the URL, and Web Risk wins when both keys exist; requests
reach only the link_reputation policy's hosts and paths, and the policy check never sees the
query; a match is "dangerous" in hedged words and no match is only "no known threats"; answers
are cached within Google's stated lifetime (30 minutes at most for a match, 5 for no match),
failures never are, and the cache is bounded; concurrent checks share one request that a
cancelled caller cannot cancel; the owner's minute and day limits (mail held to half of each)
skip lookups, per key; 429, 5xx and a rejected key cool down, a rejected key alerts the owners
once a day with one audit row each; every failure fails open with a not-checked status and logs
only types; hostile link text never costs a link its own findings and one hostile link never
costs the others their answers, while a listed site behind a padded port or a host with
characters DNS names do not use is still found; the key test maps Google's answers to plain
sentences without ever quoting the key or touching the limiter or cache; and the status carries
counts, never a key, link or host.

Why it exists: this is the only code that sends a link (with the owner's key) to a third party
(decisions 2). A leak of the key or the link into a log or an audit row, a lookup without
consent, a cached verdict outliving Google's terms, or an error read as "safe" would each break
a promise S4 makes to every consumer. No network or DNS: check_ssrf is replaced, and
httpx.MockTransport answers behind the real guarded client and request hook.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
import pytest
import structlog
from sqlalchemy import select, update

import core.network_security as netsec
from models.audit import AuditLog
from models.user import User
from services.capabilities.link_reputation import LINK_REPUTATION_SETTINGS_DEFAULTS
from services.reputation import links
from services.reputation.links import KeyTestResult, LinkReputation
from services.security.link_checks import security_notes
from services.tools.net import EgressBlocked
from tests.conftest import make_user

KEY = "AIza" + "FAKEfake" * 4 + "000"
OTHER_KEY = "AIza" + "OTHERkey" * 4 + "111"
PUBLIC_IP = "203.0.113.10"  # TEST-NET-3; check_ssrf is stubbed
SB_HOST = "safebrowsing.googleapis.com"
WR_HOST = "webrisk.googleapis.com"
WALL0 = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
EVIL = "https://paypa1-verify.xyz/login"


@pytest.fixture(autouse=True)
def ssrf_urls(monkeypatch) -> Iterator[list[str]]:
    """The URLs that reached the DNS check (never a real lookup), and no default transport."""
    urls: list[str] = []

    def fake_check_ssrf(url: str) -> netsec.SSRFCheckResult:
        urls.append(url)
        return netsec.SSRFCheckResult(safe=True, resolved_ip=PUBLIC_IP, resolved_ips=(PUBLIC_IP,))

    monkeypatch.setattr(netsec, "check_ssrf", fake_check_ssrf)
    monkeypatch.setattr(links, "DEFAULT_TRANSPORT", None)
    yield urls


@pytest.fixture
def logs(monkeypatch):
    """structlog capture with links' logger bound inside it."""
    with structlog.testing.capture_logs() as captured:
        monkeypatch.setattr(links, "logger", structlog.get_logger(links.__name__))
        yield captured


class Clock:
    """An injected monotonic clock and its wall-clock twin."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def wall(self) -> datetime:
        return WALL0 + timedelta(seconds=self.now - 1000.0)

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Status:
    effective: str
    reason: str = ""


class FakeSource:
    """What InstallationService answers: keys, the switch and the limits, each able to fail."""

    def __init__(self, *, keys: Optional[dict[str, str]] = None, effective: str = "on",
                 settings: Optional[dict[str, Any]] = None) -> None:
        self.keys = dict({"safe_browsing": KEY} if keys is None else keys)
        self.effective = effective
        self.settings = dict(settings or {})
        self.statuses_error: Optional[Exception] = None
        self.key_error: Optional[Exception] = None
        self.settings_error: Optional[Exception] = None

    async def service_key(self, name: str) -> Optional[str]:
        if self.key_error:
            raise self.key_error
        return self.keys.get(name)

    async def capability_statuses(self):
        if self.statuses_error:
            raise self.statuses_error
        reason = "" if self.effective == "on" else "Add a Google Safe Browsing or Web Risk key."
        return {"link_reputation": Status(self.effective, reason)}

    async def capability_settings(self, key: str) -> dict[str, Any]:
        if self.settings_error:
            raise self.settings_error
        assert key == "link_reputation"
        return {**LINK_REPUTATION_SETTINGS_DEFAULTS, **self.settings}


class FakeGoogle:
    """Both Google endpoints behind MockTransport. ``listed`` maps a sent URL to its threat
    types; ``answers`` are scripted responses (or exceptions) used first, in order; ``gate``
    holds every request until it is set."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.listed: dict[str, tuple[str, ...]] = {}
        self.cache_duration: Optional[str] = None
        self.expire_time: Optional[str] = None
        self.answers: list[Any] = []
        self.gate: Optional[asyncio.Event] = None

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.gate is not None:
            await self.gate.wait()
        if self.answers:
            answer = self.answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        if request.url.host == SB_HOST:
            body = json.loads(request.content)
            matches = []
            for entry in body["threatInfo"]["threatEntries"]:
                for kind in self.listed.get(entry["url"], ()):
                    match = {"threatType": kind, "platformType": "ANY_PLATFORM",
                             "threatEntryType": "URL", "threat": {"url": entry["url"]}}
                    if self.cache_duration:
                        match["cacheDuration"] = self.cache_duration
                    matches.append(match)
            return httpx.Response(200, json={"matches": matches} if matches else {})
        kinds = self.listed.get(request.url.params.get("uri", ""))
        if not kinds:
            return httpx.Response(200, json={})
        threat: dict[str, Any] = {"threatTypes": list(kinds)}
        if self.expire_time:
            threat["expireTime"] = self.expire_time
        return httpx.Response(200, json={"threat": threat})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def sent(self) -> list[str]:
        """Every link sent to Google, in order."""
        out: list[str] = []
        for request in self.requests:
            if request.url.host == SB_HOST:
                out += [e["url"] for e in json.loads(request.content)["threatInfo"]["threatEntries"]]
            else:
                out.append(request.url.params.get("uri", ""))
        return out


def make(source: Optional[FakeSource] = None, google: Optional[FakeGoogle] = None,
         clock: Optional[Clock] = None, **kwargs: Any) -> LinkReputation:
    clock = clock or Clock()
    return LinkReputation(
        source or FakeSource(),
        transport=(google or FakeGoogle()).transport(),
        clock=clock,
        wall_clock=clock.wall,
        **kwargs,
    )


async def settle(rep: LinkReputation) -> None:
    """Wait for the service's background tasks (shared lookups, owner alerts)."""
    for _ in range(50):
        pending = [t for t in rep._tasks if not t.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)


async def until(predicate, *, rounds: int = 200) -> None:
    for _ in range(rounds):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition never held")


# ── nothing leaves without consent ─────────────────────────────────────


@pytest.mark.asyncio
async def test_no_request_leaves_without_a_google_key_and_local_checks_still_run(ssrf_urls):
    google = FakeGoogle()
    rep = make(FakeSource(keys={}, effective="blocked"), google)
    (report,) = await rep.check(["https://pаypal.com/login"], purpose="mail")
    assert report.service_status == "no_key" and report.service is None
    assert report.signals[0].code == "lookalike_characters"
    assert report.level == "suspicious"
    assert google.requests == [] and ssrf_urls == []
    # An HIBP or VirusTotal key alone is not a Google key.
    rep = make(FakeSource(keys={"hibp": "a" * 32, "virustotal": "b" * 64}), google)
    (report,) = await rep.check(["https://example.org/"], purpose="chat")
    assert report.service_status == "no_key" and google.requests == []
    assert await rep.remote_configured() is False


@pytest.mark.asyncio
async def test_no_request_leaves_while_the_owner_switch_is_off(ssrf_urls):
    google = FakeGoogle()
    rep = make(FakeSource(effective="off"), google)
    reports = await rep.check(["https://example.org/", EVIL], purpose="scam_check")
    assert [r.service_status for r in reports] == ["off", "off"]
    assert reports[1].level == "suspicious"
    assert google.requests == [] and ssrf_urls == []
    assert await rep.remote_configured() is False


@pytest.mark.asyncio
async def test_no_request_leaves_when_the_owners_settings_cannot_be_read_and_the_link_is_marked_not_checked():
    google = FakeGoogle()
    source = FakeSource()
    source.statuses_error = RuntimeError("database down")
    rep = make(source, google)
    (report,) = await rep.check(["https://example.org/"], purpose="mail")
    assert report.service_status == "settings_unreadable"
    assert google.requests == []
    assert security_notes([report])[-1]["kind"] == "link_not_checked"
    source.statuses_error, source.key_error = None, RuntimeError("blob")
    (report,) = await rep.check(["https://example.org/"], purpose="mail")
    assert report.service_status == "settings_unreadable" and google.requests == []


@pytest.mark.asyncio
async def test_mail_and_phone_links_are_never_looked_up():
    google = FakeGoogle()
    rep = make(google=google)
    reports = await rep.check(["mailto:a@example.org", "tel:+15550100", "javascript:x",
                               "http://10.0.0.5/"], purpose="mail")
    assert [r.service_status for r in reports] == ["not_eligible"] * 4
    assert google.requests == []


# ── the requests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_safe_browsing_posts_one_batched_request_with_the_key_in_a_header_and_never_in_the_url():
    google = FakeGoogle()
    rep = make(google=google)
    urls = ["https://a.example.org/x?id=1", "https://user:pw@b.example.org/y#frag",
            "https://c.example.org/reset/8f3k2a9d0f8s7d6f5g4h3j2k1l", "https://a.example.org/x?id=1"]
    reports = await rep.check(urls, purpose="mail")
    assert len(reports) == 4 and [r.url for r in reports] == urls
    (request,) = google.requests
    assert request.method == "POST"
    assert str(request.url) == links.SAFE_BROWSING_URL
    assert request.headers["X-Goog-Api-Key"] == KEY
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["User-Agent"] == "Crawler-AI"
    assert KEY not in str(request.url)
    body = json.loads(request.content)
    assert body == {
        "client": {"clientId": "crawler-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "https://a.example.org/x?id=1"},
                              {"url": "https://b.example.org/y"},
                              {"url": "https://c.example.org/"}],
        },
    }
    assert {r.service_status for r in reports} == {"not_listed"}
    assert {r.service for r in reports} == {"safe_browsing"}


@pytest.mark.asyncio
async def test_web_risk_sends_one_get_per_link_with_the_key_in_a_header_and_caps_the_links_per_call():
    google = FakeGoogle()
    rep = make(FakeSource(keys={"web_risk": KEY}), google)
    urls = [f"https://site{i}.example.org/p" for i in range(12)]
    reports = await rep.check(urls, purpose="chat")
    assert len(google.requests) == links.WR_MAX_PER_CALL == 10
    for request in google.requests:
        assert request.method == "GET"
        assert request.url.host == WR_HOST and request.url.path == "/v1/uris:search"
        assert request.url.params.get_list("threatTypes") == [
            "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
        assert request.headers["X-Goog-Api-Key"] == KEY
        assert KEY not in str(request.url)
    assert sorted(google.sent()) == sorted(urls[:10])
    assert [r.service_status for r in reports] == ["not_listed"] * 10 + ["too_many"] * 2
    assert security_notes(reports)[-1] == {
        "kind": "link_not_checked", "severity": "info",
        "text": "Some links were not checked with Google Web Risk "
                "(there were too many links to check at once).",
    }


@pytest.mark.asyncio
async def test_web_risk_is_used_when_both_google_keys_exist():
    google = FakeGoogle()
    rep = make(FakeSource(keys={"safe_browsing": OTHER_KEY, "web_risk": KEY}), google)
    (report,) = await rep.check(["https://example.org/"], purpose="chat")
    assert report.service == "web_risk"
    (request,) = google.requests
    assert request.url.host == WR_HOST and request.headers["X-Goog-Api-Key"] == KEY
    assert (await rep.status())["both_keys"] is True


@pytest.mark.asyncio
async def test_a_match_is_dangerous_with_hedged_threat_words_and_no_match_is_no_known_threats():
    google = FakeGoogle()
    google.listed["https://paypa1-verify.xyz/login"] = ("SOCIAL_ENGINEERING", "MALWARE")
    rep = make(google=google)
    listed, clean = await rep.check([EVIL, "https://example.org/"], purpose="scam_check")
    assert listed.level == "dangerous" and listed.service_status == "listed"
    assert listed.threats == ("SOCIAL_ENGINEERING", "MALWARE")
    assert listed.reasons()[0] == (
        "Google Safe Browsing says this site may be phishing or a scam and may host malware "
        "(advisory provided by Google)."
    )
    assert clean.level == "no_known_threats" and clean.service_status == "not_listed"
    assert all("safe" not in line.lower().replace("safe browsing", "") for line in clean.reasons())


@pytest.mark.asyncio
async def test_requests_reach_only_the_link_reputation_policy_hosts_and_paths(ssrf_urls):
    google = FakeGoogle()
    await make(google=google).check([EVIL], purpose="mail")
    await make(FakeSource(keys={"web_risk": KEY}), google).check([EVIL], purpose="mail")
    assert ssrf_urls == [links.SAFE_BROWSING_URL, links.WEB_RISK_URL]
    for url in ("https://evil.example.net/v4/threatMatches:find",
                "http://safebrowsing.googleapis.com/v4/threatMatches:find",
                "https://safebrowsing.googleapis.com/v4/threatLists",
                "https://webrisk.googleapis.com/v1/hashes:search",
                "https://www.googleapis.com/gmail/v1/users"):
        with pytest.raises(EgressBlocked) as refused:
            links._policy_addresses(url)
        assert "evil" not in str(refused.value) and "googleapis" not in str(refused.value)


@pytest.mark.asyncio
async def test_the_policy_check_never_sees_the_query_so_a_refusal_log_cannot_print_the_checked_link(
    ssrf_urls,
):
    google = FakeGoogle()
    rep = make(FakeSource(keys={"web_risk": KEY}), google)
    await rep.check(["https://private-share.example.org/doc?id=42"], purpose="chat")
    (request,) = google.requests
    assert request.url.params["uri"] == "https://private-share.example.org/doc?id=42"
    assert ssrf_urls == [links.WEB_RISK_URL]
    assert all("?" not in url and "private-share" not in url for url in ssrf_urls)


@pytest.mark.asyncio
async def test_browser_lookups_send_only_the_scheme_and_host_through_the_client():
    google = FakeGoogle()
    rep = make(google=google)
    await rep.check(["https://bank.example.org/oauth/cb?code=s3cr3t&state=x"], purpose="browser")
    assert google.sent() == ["https://bank.example.org/"]


# ── cache ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_positive_answers_are_cached_at_most_thirty_minutes_and_never_past_googles_cache_lifetime():
    clock, google = Clock(), FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    rep = make(google=google, clock=clock)
    assert (await rep.check_one(EVIL, purpose="mail")).cached is False
    clock.advance(links.POSITIVE_TTL_S - 1)
    assert (await rep.check_one(EVIL, purpose="mail")).cached is True
    clock.advance(2)
    assert (await rep.check_one(EVIL, purpose="mail")).cached is False
    assert len(google.requests) == 2

    clock, google = Clock(), FakeGoogle()
    google.listed[EVIL] = ("MALWARE",)
    google.cache_duration = "60s"
    rep = make(google=google, clock=clock)
    await rep.check_one(EVIL, purpose="mail")
    clock.advance(59)
    assert (await rep.check_one(EVIL, purpose="mail")).cached is True
    clock.advance(2)
    assert (await rep.check_one(EVIL, purpose="mail")).cached is False

    clock, google = Clock(), FakeGoogle()
    google.listed[EVIL] = ("MALWARE",)
    google.expire_time = (clock.wall() + timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
    rep = make(FakeSource(keys={"web_risk": KEY}), google, clock)
    await rep.check_one(EVIL, purpose="mail")
    clock.advance(89)
    assert (await rep.check_one(EVIL, purpose="mail")).cached is True
    clock.advance(2)
    report = await rep.check_one(EVIL, purpose="mail")
    assert report.cached is False and report.level == "dangerous"
    # A match whose lifetime is already over is reported but never cached.
    google.expire_time = (clock.wall() - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rep.clear()
    await rep.check_one(EVIL, purpose="mail")
    assert (await rep.check_one(EVIL, purpose="mail")).cached is False


@pytest.mark.asyncio
async def test_negative_answers_are_cached_for_five_minutes():
    clock, google = Clock(), FakeGoogle()
    rep = make(google=google, clock=clock)
    url = "https://example.org/a"
    await rep.check_one(url, purpose="chat")
    clock.advance(links.NEGATIVE_TTL_S - 1)
    cached = await rep.check_one(url, purpose="chat")
    assert cached.cached is True and cached.service_status == "not_listed"
    clock.advance(2)
    assert (await rep.check_one(url, purpose="chat")).cached is False
    assert len(google.requests) == 2


@pytest.mark.asyncio
async def test_errors_timeouts_and_limits_are_never_cached():
    clock, google = Clock(), FakeGoogle()
    rep = make(FakeSource(settings={"lookups_per_minute": 100}), google, clock)
    google.answers = [httpx.Response(500)]
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service_status == "error"
    clock.advance(links.COOL_DOWN_5XX_S + 1)
    google.answers = [httpx.ConnectError("down")]
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service_status == "error"
    google.answers = [httpx.ReadTimeout("slow")]
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service_status == "timeout"
    assert rep.cached_report("https://a.example.org/", purpose="chat") is None
    assert (await rep.status())["cache_entries"] == 0
    report = await rep.check_one("https://a.example.org/", purpose="chat")
    assert report.service_status == "not_listed" and report.cached is False
    assert len(google.requests) == 4


@pytest.mark.asyncio
async def test_the_cache_is_bounded_and_drops_the_oldest_entry(monkeypatch):
    monkeypatch.setattr(links, "CACHE_MAX_ENTRIES", 2)
    google = FakeGoogle()
    rep = make(google=google)
    for name in ("a", "b", "c"):
        await rep.check_one(f"https://{name}.example.org/", purpose="chat")
    assert (await rep.status())["cache_entries"] == 2
    assert rep.cached_report("https://a.example.org/", purpose="chat") is None
    assert rep.cached_report("https://c.example.org/", purpose="chat") is not None
    await rep.check_one("https://a.example.org/", purpose="chat")
    assert len(google.requests) == 4


# ── sharing one request ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_checks_of_the_same_link_share_one_request():
    google = FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    google.gate = asyncio.Event()
    rep = make(google=google)
    first = asyncio.create_task(rep.check_one(EVIL, purpose="mail"))
    second = asyncio.create_task(rep.check_one(EVIL + "#again", purpose="chat"))
    await until(lambda: len(google.requests) == 1)
    google.gate.set()
    one, two = await asyncio.gather(first, second)
    assert one.level == two.level == "dangerous"
    assert len(google.requests) == 1


class WaitingSettingsSource(FakeSource):
    """A source whose limits read waits, as InstallationService's does on a database read when
    its settings snapshot is stale: it yields a few times, and while ``hold`` is set the
    *second and later* reads wait for it."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.reads = 0
        self.hold: Optional[asyncio.Event] = None

    async def capability_settings(self, key: str) -> dict[str, Any]:
        self.reads += 1
        number = self.reads
        for _ in range(3):
            await asyncio.sleep(0)
        if self.hold is not None and number > 1:
            await self.hold.wait()
        return await super().capability_settings(key)


@pytest.mark.asyncio
async def test_concurrent_checks_of_one_link_share_one_request_even_while_reading_the_limits_waits():
    # Review of S4: both checks missed the in-flight table across the limits read and both sent.
    google = FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    rep = make(WaitingSettingsSource(), google)
    reports = await asyncio.gather(*(rep.check_one(EVIL, purpose="chat") for _ in range(3)))
    assert [r.level for r in reports] == ["dangerous"] * 3
    assert len(google.requests) == 1
    assert (await rep.status())["lookups_last_minute"] == 1


@pytest.mark.asyncio
async def test_an_answer_that_lands_while_a_check_waits_for_the_limits_is_taken_from_the_cache():
    google = FakeGoogle()
    google.listed[EVIL] = ("MALWARE",)
    source = WaitingSettingsSource()
    source.hold = asyncio.Event()
    rep = make(source, google)
    first = asyncio.create_task(rep.check_one(EVIL, purpose="chat"))
    second = asyncio.create_task(rep.check_one(EVIL, purpose="chat"))
    done = await first
    assert done.level == "dangerous" and not second.done()
    source.hold.set()
    late = await second
    assert late.level == "dangerous" and late.cached is True
    assert len(google.requests) == 1
    assert (await rep.status())["lookups_last_minute"] == 1


@pytest.mark.asyncio
async def test_a_cancelled_caller_does_not_cancel_the_shared_request():
    google = FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    google.gate = asyncio.Event()
    rep = make(google=google)
    first = asyncio.create_task(rep.check_one(EVIL, purpose="mail"))
    await until(lambda: len(google.requests) == 1)
    second = asyncio.create_task(rep.check_one(EVIL, purpose="chat"))
    await asyncio.sleep(0)
    first.cancel()
    google.gate.set()
    report = await second
    assert report.level == "dangerous"
    with pytest.raises(asyncio.CancelledError):
        await first
    assert rep.cached_report(EVIL, purpose="mail") is not None
    assert len(google.requests) == 1


@pytest.mark.asyncio
async def test_a_caller_that_stops_waiting_reports_a_timeout_and_the_answer_still_lands_in_the_cache():
    google = FakeGoogle()
    google.listed[EVIL] = ("MALWARE",)
    google.gate = asyncio.Event()
    rep = make(google=google)
    report = await rep.check_one(EVIL, purpose="chat", timeout_s=0.01)
    assert report.service_status == "timeout" and report.level == "suspicious"
    google.gate.set()
    await settle(rep)
    cached = rep.cached_report(EVIL, purpose="chat")
    assert cached is not None and cached.level == "dangerous"


# ── the owner's limits and Google's ────────────────────────────────────


@pytest.mark.asyncio
async def test_the_owners_minute_and_day_limits_skip_lookups_with_a_rate_limited_status(logs):
    clock, google = Clock(), FakeGoogle()
    rep = make(FakeSource(settings={"lookups_per_minute": 2, "lookups_per_day": 3}), google, clock)
    statuses = [(await rep.check_one(f"https://s{i}.example.org/", purpose="chat")).service_status
                for i in range(3)]
    assert statuses == ["not_listed", "not_listed", "rate_limited"]
    clock.advance(61)
    assert (await rep.check_one("https://s3.example.org/", purpose="chat")).service_status == "not_listed"
    assert (await rep.check_one("https://s4.example.org/", purpose="chat")).service_status == "rate_limited"
    clock.advance(links.DAY_S)
    assert (await rep.check_one("https://s5.example.org/", purpose="chat")).service_status == "not_listed"
    assert len(google.requests) == 4
    windows = [e["window"] for e in logs if e["event"] == "link_reputation_rate_limited"]
    assert windows == ["minute", "day"]
    assert (await rep.status())["last_problem"]["kind"] == "rate_limited"


@pytest.mark.asyncio
async def test_mail_lookups_never_use_more_than_half_of_either_window():
    google = FakeGoogle()
    rep = make(FakeSource(settings={"lookups_per_minute": 4}), google)
    mail = [(await rep.check_one(f"https://m{i}.example.org/", purpose="mail")).service_status
            for i in range(3)]
    assert mail == ["not_listed", "not_listed", "rate_limited"]
    chat = await rep.check_one("https://c.example.org/", purpose="chat")
    assert chat.service_status == "not_listed"
    assert len(google.requests) == 3

    google = FakeGoogle()
    rep = make(FakeSource(settings={"lookups_per_day": 4}), google)
    mail = [(await rep.check_one(f"https://d{i}.example.org/", purpose="mail")).service_status
            for i in range(3)]
    assert mail == ["not_listed", "not_listed", "rate_limited"]
    for purpose in ("browser", "outbound"):
        assert (await rep.check_one(f"https://{purpose}.example.org/", purpose=purpose)
                ).service_status == "not_listed"


@pytest.mark.asyncio
async def test_unreadable_limits_fall_back_to_the_defaults():
    google = FakeGoogle()
    source = FakeSource()
    source.settings_error = RuntimeError("no")
    rep = make(source, google)
    assert (await rep.check_one("https://example.org/", purpose="chat")).service_status == "not_listed"
    status = await rep.status()
    assert status["lookups_per_minute"] == 60 and status["lookups_per_day"] == 2000


@pytest.mark.asyncio
async def test_a_replaced_key_starts_fresh_counters():
    google = FakeGoogle()
    source = FakeSource(settings={"lookups_per_minute": 1})
    rep = make(source, google)
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service_status == "not_listed"
    assert (await rep.check_one("https://b.example.org/", purpose="chat")).service_status == "rate_limited"
    source.keys["safe_browsing"] = OTHER_KEY
    assert (await rep.check_one("https://c.example.org/", purpose="chat")).service_status == "not_listed"
    assert google.requests[-1].headers["X-Goog-Api-Key"] == OTHER_KEY


@pytest.mark.asyncio
async def test_a_429_starts_a_cool_down_that_honours_retry_after_within_bounds():
    clock, google = Clock(), FakeGoogle()
    rep = make(google=google, clock=clock)
    google.answers = [httpx.Response(429, headers={"Retry-After": "5"})]
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service_status == "rate_limited"
    assert (await rep.check_one("https://b.example.org/", purpose="chat")).service_status == "cooling_down"
    assert len(google.requests) == 1
    clock.advance(59)          # Retry-After 5 is clamped up to 60 s
    assert (await rep.check_one("https://b.example.org/", purpose="chat")).service_status == "cooling_down"
    clock.advance(2)
    google.answers = [httpx.Response(429, headers={"Retry-After": "100000"})]
    assert (await rep.check_one("https://b.example.org/", purpose="chat")).service_status == "rate_limited"
    clock.advance(899)         # clamped down to 900 s
    assert (await rep.check_one("https://c.example.org/", purpose="chat")).service_status == "cooling_down"
    clock.advance(2)
    google.answers = [httpx.Response(429)]
    await rep.check_one("https://c.example.org/", purpose="chat")
    status = await rep.status()
    assert status["cooling_down_until"] is not None
    assert status["last_problem"] == {"kind": "rate_limited", "at": status["last_problem"]["at"],
                                      "http_status": 429}
    # The third 429 in a row with no Retry-After: 60 s doubled twice.
    clock.advance(links.COOL_DOWN_429_S[0] * 4 - 1)
    assert (await rep.check_one("https://d.example.org/", purpose="chat")).service_status == "cooling_down"
    clock.advance(2)
    google.answers = []
    assert (await rep.check_one("https://d.example.org/", purpose="chat")).service_status == "not_listed"


@pytest.mark.asyncio
async def test_consecutive_429s_without_retry_after_double_the_cool_down():
    clock, google = Clock(), FakeGoogle()
    rep = make(google=google, clock=clock)
    google.answers = [httpx.Response(429), httpx.Response(429)]
    await rep.check_one("https://a.example.org/", purpose="chat")
    clock.advance(61)
    await rep.check_one("https://b.example.org/", purpose="chat")
    clock.advance(61)
    assert (await rep.check_one("https://c.example.org/", purpose="chat")).service_status == "cooling_down"
    clock.advance(60)
    assert (await rep.check_one("https://c.example.org/", purpose="chat")).service_status == "not_listed"


@pytest.mark.asyncio
async def test_a_rejected_key_cools_down_alerts_the_owner_once_a_day_and_writes_one_audit_row_per_admin(
    session_factory,
):
    from services.audit import RuntimeAuditLogger

    owner, _ = await make_user(session_factory, "owner@example.org")
    second, _ = await make_user(session_factory, "admin2@example.org")
    member, _ = await make_user(session_factory, "member@example.org")
    async with session_factory() as s:
        await s.execute(update(User).where(User.id.in_([owner.id, second.id])).values(is_admin=True))
        await s.commit()
    sent: list[tuple[str, str]] = []

    async def send(user_id: str, text: str) -> bool:
        sent.append((user_id, text))
        return True

    clock, google = Clock(), FakeGoogle()
    rep = make(google=google, clock=clock, owner_alert=links.owner_alert(
        session_factory, send, RuntimeAuditLogger(session_factory=session_factory).log))
    google.answers = [httpx.Response(403, json={"error": {"code": 403}})]
    report = await rep.check_one(EVIL, purpose="chat")
    assert report.service_status == "key_rejected" and report.level == "suspicious"
    await settle(rep)
    assert sorted(uid for uid, _ in sent) == sorted([str(owner.id), str(second.id)])
    assert sent[0][1] == (
        "Link checks with Google Safe Browsing stopped working: Google refused the key (HTTP 403). "
        "Links are checked on this computer only until you replace the key in Security → Service keys."
    )
    assert (await rep.check_one("https://x.example.org/", purpose="chat")).service_status == "cooling_down"
    clock.advance(links.KEY_REJECTED_COOL_DOWN_S + 1)
    google.answers = [httpx.Response(400, json={"error": {"details": [{"reason": "API_KEY_INVALID"}]}})]
    assert (await rep.check_one("https://y.example.org/", purpose="chat")).service_status == "key_rejected"
    await settle(rep)
    assert len(sent) == 2      # once per service per 24 hours
    async with session_factory() as s:
        rows = list((await s.execute(select(AuditLog).where(AuditLog.action == "key_rejected"))).scalars())
    assert sorted(r.user_id for r in rows) == sorted([owner.id, second.id])
    for row in rows:
        assert row.connector_name == "link_reputation"
        assert row.request_data == {"service": "safe_browsing", "http_status": 403}
        assert KEY not in json.dumps(row.request_data) and "paypa1" not in str(row.reasoning_chain)
    clock.advance(links.OWNER_ALERT_EVERY_S)
    google.answers = [httpx.Response(401)]
    await rep.check_one("https://z.example.org/", purpose="chat")
    await settle(rep)
    assert len(sent) == 4
    assert (await rep.status())["last_problem"]["kind"] == "key_rejected"


@pytest.mark.asyncio
async def test_an_owner_alert_that_fails_never_breaks_the_check(logs):
    async def broken(message, facts):
        raise RuntimeError("telegram down " + KEY)

    google = FakeGoogle()
    google.answers = [httpx.Response(403)]
    rep = make(google=google, owner_alert=broken)
    assert (await rep.check_one(EVIL, purpose="chat")).service_status == "key_rejected"
    await settle(rep)
    failed = [e for e in logs if e["event"] == "link_reputation_owner_alert_failed"]
    assert failed and failed[0]["error_type"] == "RuntimeError"
    assert KEY not in repr(logs)


@pytest.mark.asyncio
async def test_a_5xx_or_network_error_fails_open_with_a_not_checked_status_and_logs_only_the_type(logs):
    clock, google = Clock(), FakeGoogle()
    rep = make(google=google, clock=clock)
    google.answers = [httpx.Response(503)]
    report = await rep.check_one(EVIL, purpose="mail")
    assert report.service_status == "error" and report.level != "dangerous"
    assert security_notes([report])[-1]["kind"] == "link_not_checked"
    assert (await rep.check_one("https://a.example.org/", purpose="mail")).service_status == "cooling_down"
    clock.advance(links.COOL_DOWN_5XX_S + 1)
    google.answers = [httpx.ConnectError(f"cannot reach {EVIL} with {KEY}")]
    assert (await rep.check_one(EVIL, purpose="mail")).service_status == "error"
    failures = [e for e in logs if e["event"] == "link_reputation_lookup_failed"]
    assert [(e["status_code"], e["error_type"]) for e in failures] == [
        (503, "server"), (None, "ConnectError")]
    assert "paypa1" not in repr(logs) and KEY not in repr(logs)


@pytest.mark.asyncio
async def test_an_oversized_or_non_json_answer_is_an_error_and_never_a_verdict():
    google = FakeGoogle()
    rep = make(google=google)
    for answer in (httpx.Response(200, content=b"x" * (links.MAX_RESPONSE_BYTES + 1)),
                   httpx.Response(200, content=b"<html>not json</html>"),
                   httpx.Response(200, json=[{"matches": []}]),
                   httpx.Response(200, json={"matches": {"url": EVIL}}),
                   httpx.Response(404, json={})):
        google.answers = [answer]
        report = await rep.check_one(EVIL, purpose="chat")
        assert report.service_status == "error", answer
        assert report.level == "suspicious"
    assert (await rep.status())["cache_entries"] == 0


@pytest.mark.asyncio
async def test_a_match_for_a_link_that_was_not_asked_or_a_threat_type_not_requested_is_ignored():
    google = FakeGoogle()
    rep = make(google=google)
    google.answers = [httpx.Response(200, json={"matches": [
        {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://other.example.org/"}},
        {"threatType": "THREAT_TYPE_UNSPECIFIED", "threat": {"url": "https://example.org/"}},
        "not a match",
        {"threatType": "MALWARE"},
    ]})]
    (report,) = await rep.check(["https://example.org/"], purpose="chat")
    assert report.service_status == "not_listed"
    wr_google = FakeGoogle()
    wr = make(FakeSource(keys={"web_risk": KEY}), wr_google)
    wr_google.answers = [httpx.Response(200, json={"threat": {"threatTypes": ["SOMETHING_ELSE"]}})]
    assert (await wr.check_one("https://example.org/", purpose="chat")).service_status == "not_listed"


@pytest.mark.asyncio
async def test_more_links_than_the_per_call_cap_are_reported_too_many():
    google = FakeGoogle()
    rep = make(google=google)
    urls = [f"https://h{i}.example.org/" for i in range(links.MAX_URLS_PER_CALL + 1)]
    reports = await rep.check(urls, purpose="scam_check")
    assert len(google.requests) == 1
    assert len(google.sent()) == links.MAX_URLS_PER_CALL
    assert reports[-1].service_status == "too_many"
    assert {r.service_status for r in reports[:-1]} == {"not_listed"}


@pytest.mark.asyncio
async def test_cache_only_mode_answers_from_the_cache_and_never_calls_google():
    google = FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    rep = make(google=google)
    await rep.check_one(EVIL, purpose="outbound")
    reports = await rep.check([EVIL, "https://unseen.example.org/", "mailto:x@example.org"],
                              purpose="outbound", network=False)
    assert [r.service_status for r in reports] == ["listed", "cache_miss", "not_eligible"]
    assert reports[0].cached is True and reports[0].level == "dangerous"
    assert len(google.requests) == 1


@pytest.mark.asyncio
async def test_cached_report_is_synchronous_and_network_free():
    google = FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    rep = make(google=google)
    assert rep.cached_report(EVIL, purpose="outbound") is None
    await rep.check_one(EVIL, purpose="outbound")
    report = rep.cached_report(EVIL, purpose="outbound")
    assert not asyncio.iscoroutine(report)
    assert report is not None and report.cached and report.level == "dangerous"
    assert report.threats == ("SOCIAL_ENGINEERING",) and report.service == "safe_browsing"
    assert rep.cached_report("mailto:a@example.org", purpose="outbound") is None
    assert rep.cached_report("http://10.0.0.1/", purpose="outbound") is None
    assert len(google.requests) == 1


@pytest.mark.asyncio
async def test_check_never_raises_and_answers_one_report_per_input_in_order(monkeypatch):
    rep = make()

    async def boom(*_a, **_k):
        raise RuntimeError("internal")

    monkeypatch.setattr(rep, "_config", boom)
    urls = [EVIL, "https://example.org/", EVIL]
    reports = await rep.check(urls, purpose="chat")
    assert [r.url for r in reports] == urls
    assert {r.service_status for r in reports} == {"error"}
    assert rep.check_local(EVIL).service_status == "no_key"


@pytest.mark.asyncio
async def test_no_log_line_or_audit_row_carries_the_key_the_link_or_the_host(logs):
    clock, google = Clock(), FakeGoogle()
    rep = make(FakeSource(settings={"lookups_per_minute": 3}), google, clock)
    scenario = [httpx.Response(500, text=f"{KEY} {EVIL}"), httpx.ReadTimeout(f"{EVIL} {KEY}"),
                httpx.Response(200, content=EVIL.encode()), httpx.Response(429, text=KEY),
                httpx.Response(403, text=f"{KEY} paypa1-verify.xyz")]
    for answer in scenario:
        google.answers = [answer]
        await rep.check_one(EVIL, purpose="chat")
        clock.advance(links.KEY_REJECTED_COOL_DOWN_S + 1)
    await rep.check([EVIL] * 5 + [f"https://n{i}.example.org/" for i in range(5)], purpose="mail")
    await settle(rep)
    dump = repr(logs)
    assert logs
    for secret in (KEY, "paypa1-verify", "/login", "example.org"):
        assert secret not in dump, secret
    status = json.dumps(await rep.status())
    for secret in (KEY, "paypa1", "example.org"):
        assert secret not in status


# ── the key test ───────────────────────────────────────────────────────


def _answering(*responses: Any) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    seen: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = queue.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    return httpx.MockTransport(handler), seen


@pytest.mark.asyncio
async def test_key_test_reports_a_working_key_and_maps_googles_errors_to_plain_sentences():
    cases = [
        ("safe_browsing", httpx.Response(200, json={}), KeyTestResult(True, "Google answered: the key works.")),
        ("safe_browsing", httpx.Response(200, json={"matches": [{"threatType": "MALWARE", "threat": {
            "url": links.SAFE_BROWSING_TEST_URL}}]}), KeyTestResult(True, "Google answered: the key works.")),
        ("web_risk", httpx.Response(200, json={"threat": {"threatTypes": ["MALWARE"]}}),
         KeyTestResult(True, "Google answered: the key works.")),
        ("safe_browsing", httpx.Response(400, json={"error": {"details": [{"reason": "API_KEY_INVALID"}]}}),
         KeyTestResult(False, "Google refused the key: it is not a valid API key.")),
        ("safe_browsing", httpx.Response(403), KeyTestResult(False,
         "Google refused the key: the Safe Browsing API is not turned on for this key's project, "
         "or the key is restricted to other APIs.")),
        ("web_risk", httpx.Response(403), KeyTestResult(False,
         "Google refused the key: the Web Risk API is not turned on for this key's project, "
         "or the key is restricted to other APIs.")),
        ("web_risk", httpx.Response(429), KeyTestResult(False,
         "Google says this key's quota is used up. Try again later.")),
        ("safe_browsing", httpx.Response(502), KeyTestResult(False, "Google answered HTTP 502.")),
        ("safe_browsing", httpx.ConnectError("refused"), KeyTestResult(False,
         "Could not reach Google (ConnectError).")),
    ]
    for service, answer, expected in cases:
        transport, seen = _answering(answer)
        assert await links.test_google_key(service, KEY, transport=transport) == expected, answer
        (request,) = seen
        assert request.headers["X-Goog-Api-Key"] == KEY and KEY not in str(request.url)
        if service == "safe_browsing":
            entries = json.loads(request.content)["threatInfo"]["threatEntries"]
            assert entries == [{"url": links.SAFE_BROWSING_TEST_URL}]
        else:
            assert request.url.params["uri"] == links.WEB_RISK_TEST_URL
    assert (await links.test_google_key("hibp", KEY)).ok is False  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_key_test_uses_the_default_transport_seam_the_key_routes_rely_on(monkeypatch):
    transport, seen = _answering(httpx.Response(200, json={}))
    monkeypatch.setattr(links, "DEFAULT_TRANSPORT", transport)
    assert (await links.test_google_key("safe_browsing", KEY)).ok is True
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_key_test_never_quotes_the_key_even_when_google_echoes_it():
    transport, _ = _answering(httpx.Response(400, text=f"API_KEY_INVALID: {KEY} is not valid"))
    result = await links.test_google_key("safe_browsing", KEY, transport=transport)
    assert result.ok is False and KEY not in result.detail

    class Echo(Exception):
        pass

    transport, _ = _answering(Echo(f"bad key {KEY}"))
    result = await links.test_google_key("web_risk", KEY, transport=transport)
    assert result == KeyTestResult(False, "Could not reach Google (Echo).")


@pytest.mark.asyncio
async def test_key_tests_count_against_neither_the_limiter_nor_the_cache():
    google = FakeGoogle()
    rep = make(FakeSource(settings={"lookups_per_minute": 1}), google)
    for _ in range(3):
        assert (await links.test_google_key("safe_browsing", KEY, transport=google.transport())).ok
    status = await rep.status()
    assert status["lookups_last_minute"] == 0 and status["cache_entries"] == 0
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).service_status == "not_listed"


# ── the owner's view ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_reports_counts_limits_cool_down_and_the_last_problem_without_secrets():
    clock, google = Clock(), FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    rep = make(FakeSource(settings={"lookups_per_minute": 3}), google, clock)
    fresh = await rep.status()
    assert fresh == {
        "capability": "on", "reason": "", "service": "safe_browsing", "both_keys": False,
        "lookups_last_minute": 0, "lookups_per_minute": 3, "lookups_last_day": 0,
        "lookups_per_day": 2000, "counting_since": "2026-10-14T12:00:00Z", "cache_entries": 0,
        "dangerous_found_last_day": 0, "not_checked_last_day": 0, "cooling_down_until": None,
        "last_problem": None,
    }
    await rep.check([EVIL, "https://example.org/"], purpose="chat")
    clock.advance(30)
    google.answers = [httpx.Response(503)]
    await rep.check_one("https://down.example.org/", purpose="chat")
    status = await rep.status()
    assert status["lookups_last_minute"] == 2 and status["lookups_last_day"] == 2
    assert status["cache_entries"] == 2
    assert status["dangerous_found_last_day"] == 1 and status["not_checked_last_day"] == 1
    assert status["cooling_down_until"] == "2026-10-14T12:01:00Z"
    assert status["last_problem"] == {"kind": "error", "at": "2026-10-14T12:00:30Z",
                                      "http_status": 503}
    clock.advance(links.DAY_S)
    later = await rep.status()
    assert later["lookups_last_day"] == 0 and later["dangerous_found_last_day"] == 0
    dumped = json.dumps(later)
    assert KEY not in dumped and "paypa1" not in dumped and "example.org" not in dumped
    blocked = make(FakeSource(keys={}, effective="blocked"))
    view = await blocked.status()
    assert view["capability"] == "blocked" and view["service"] is None
    assert view["reason"] == "Add a Google Safe Browsing or Web Risk key."
    source = FakeSource()
    source.statuses_error = RuntimeError("x")
    assert (await make(source).status())["capability"] == "blocked"


@pytest.mark.asyncio
async def test_clear_forgets_the_cache_counters_cool_downs_and_alerts():
    clock, google = Clock(), FakeGoogle()
    rep = make(google=google, clock=clock)
    await rep.check_one("https://a.example.org/", purpose="chat")
    google.answers = [httpx.Response(503)]
    await rep.check_one("https://b.example.org/", purpose="chat")
    rep.clear()
    status = await rep.status()
    assert status["cache_entries"] == 0 and status["lookups_last_day"] == 0
    assert status["cooling_down_until"] is None and status["last_problem"] is None
    assert (await rep.check_one("https://a.example.org/", purpose="chat")).cached is False


@pytest.mark.asyncio
async def test_the_day_counters_stay_bounded_when_nobody_opens_the_owners_tab():
    """Review of S4: the "dangerous found" and "not checked" counters kept one entry per link
    and were pruned only when the owner's tab read them, so a mail sweep running while the key
    was rejected grew them for the life of the process. They now keep at most one entry per
    COUNT_RESOLUTION_S and drop old ones on every add."""
    clock, google = Clock(), FakeGoogle()
    google.answers = [httpx.Response(403)]
    rep = make(google=google, clock=clock)
    not_checked = 0
    for index in range(1_200):
        report = await rep.check_one(f"https://site{index}.example.org/", purpose="mail")
        not_checked += report.service_status in links.NOT_CHECKED_STATUSES
        clock.advance(1)
    assert not_checked > 500
    assert len(rep._not_checked) <= 1_200 / links.COUNT_RESOLUTION_S + 1
    assert (await rep.status())["not_checked_last_day"] == not_checked
    # A day later every old entry is gone at the next count or add.
    clock.advance(links.DAY_S)
    assert (await rep.status())["not_checked_last_day"] == 0
    assert len(rep._not_checked) == 0


@pytest.mark.asyncio
async def test_a_host_hiding_characters_the_browser_drops_is_looked_up_and_reported_dangerous():
    """Review of S4: a soft hyphen or a zero-width space inside a listed host made the link
    unreadable, so Google was never asked and no note was made, while the browser opened the
    listed site. The host is now read as the browser reads it."""
    google = FakeGoogle()
    google.listed["https://evil-phish.example.com/login"] = ("SOCIAL_ENGINEERING",)
    rep = make(google=google)
    reports = await rep.check(
        ["https://ev\u00adil-phish.example.com/login", "https://ev%E2%80%8Bil-phish.example.com/login"],
        purpose="mail",
    )
    assert [r.level for r in reports] == ["dangerous", "dangerous"]
    assert google.sent() == ["https://evil-phish.example.com/login"]
    assert security_notes(reports)[0]["kind"] == "link_dangerous"


# ── review fixes: hostile links never cost a report its findings ───────

LOOKALIKE_HREF = "http://user@pаypal.com/login"
LISTED = "https://listed.example.org/login"


@pytest.mark.asyncio
async def test_link_text_that_cannot_be_read_keeps_the_links_own_findings_in_every_check():
    """Review of S4: S2's mail and S1's outgoing messages pass attacker-written link text, and
    text such as "http://-1.0.0.1" raised inside the text check; _local then answered a bare
    report (level unknown, no signals, nothing shown), so "http://user@pаypal.com/login" went
    from suspicious to unknown and lost its card note."""
    from services.security.link_checks import LocalOnlyLinkChecker

    rep = make()
    for text in ("http://-1.0.0.1", "https://listed.example.org:" + "9" * 2_000):
        texts = {LOOKALIKE_HREF: text}
        for report in (
            (await rep.check([LOOKALIKE_HREF], purpose="mail", texts=texts))[0],
            (await rep.check([LOOKALIKE_HREF], purpose="mail", texts=texts, network=False))[0],
            rep.check_local(LOOKALIKE_HREF, text=text),
            (await LocalOnlyLinkChecker().check([LOOKALIKE_HREF], purpose="mail", texts=texts))[0],
        ):
            codes = {s.code for s in report.signals}
            assert {"credentials_in_url", "lookalike_characters"} <= codes
            assert report.level == "suspicious" and report.shown.startswith("http://xn--pypal")
        assert security_notes([report])[0]["kind"] == "link_suspicious"


@pytest.mark.asyncio
async def test_a_local_check_that_breaks_still_answers_the_links_findings_or_says_it_could_not_read_it(
    monkeypatch,
):
    """Defence in depth: when the local report with text breaks, the report without the text
    is used; when that breaks too, the link is reported unreadable (the "could not be read"
    signal), never as a bare report that hides that anything went wrong."""
    real = links.local_report

    def text_breaks(url: str, *, text: Optional[str] = None, **kwargs: Any):
        if text:
            raise RuntimeError("internal")
        return real(url, **kwargs)

    rep = make()
    monkeypatch.setattr(links, "local_report", text_breaks)
    report = rep.check_local(LOOKALIKE_HREF, text="paypal.com")
    assert report.level == "suspicious" and "credentials_in_url" in {s.code for s in report.signals}

    def always_breaks(*_args: Any, **_kwargs: Any):
        raise RuntimeError("internal")

    monkeypatch.setattr(links, "local_report", always_breaks)
    report = rep.check_local(LOOKALIKE_HREF)
    assert [(s.code, s.text) for s in report.signals] == [
        ("unreadable", "The link could not be read.")
    ]


@pytest.mark.asyncio
async def test_a_listed_site_behind_a_zero_padded_port_is_looked_up_and_reported_dangerous():
    """Review of S4: a port of more than 4,300 digits (zeros a browser ignores) raised, so a
    listed site behind it was never looked up and got no signal, and with network=False one
    such link turned every link of the call into "error"."""
    google = FakeGoogle()
    google.listed[LISTED] = ("SOCIAL_ENGINEERING",)
    rep = make(google=google)
    padded = "https://listed.example.org:" + "0" * 5_000 + "443/login"
    hostile = ["http://-1.0.0.1/", "https://listed.example.org:" + "9" * 5_000 + "/login"]
    reports = await rep.check([padded, *hostile, LISTED], purpose="mail")
    assert [r.level for r in reports] == ["dangerous", "unknown", "unknown", "dangerous"]
    assert [r.service_status for r in reports] == ["listed", "not_eligible", "not_eligible",
                                                   "listed"]
    assert [s.code for s in reports[1].signals] == ["unreadable"]
    assert google.sent() == [LISTED]
    cached = await rep.check([*hostile, padded, LISTED], purpose="mail", network=False)
    assert [r.service_status for r in cached] == ["not_eligible", "not_eligible", "listed",
                                                  "listed"]
    assert cached[2].level == "dangerous" and cached[3].level == "dangerous"


@pytest.mark.asyncio
async def test_a_host_with_characters_the_url_standard_allows_is_looked_up_as_its_listed_parent():
    """Review of S4: "https://x$y.listed.example.org/" was unreadable, so a mail check sent
    nothing to Google and reported nothing, while the browser opens it and Google lists
    listed.example.org. Its nearest DNS ancestor is looked up now."""
    google = FakeGoogle()
    google.listed["https://listed.example.org/"] = ("SOCIAL_ENGINEERING",)
    rep = make(google=google)
    reports = await rep.check(
        ["https://x$y.listed.example.org/login?page=2", "https://a!b.listed.example.org/"],
        purpose="mail",
    )
    assert [r.level for r in reports] == ["dangerous", "dangerous"]
    assert reports[0].host == "x$y.listed.example.org"
    assert google.sent() == ["https://listed.example.org/"]
    assert security_notes(reports)[0]["text"].startswith(
        "Link check: x$y.listed.example.org/login - Google Safe Browsing says"
    )


@pytest.mark.asyncio
async def test_one_link_that_breaks_a_check_never_costs_the_others_their_answers(monkeypatch):
    """Review of S4: one link whose lookup could not be worked out made the whole cache-only
    call fall back to "error" for every link, dropping a cached dangerous answer to unknown.
    Now only that link is affected, and it reads "not checked" (a note says so), never quietly
    not eligible."""
    google = FakeGoogle()
    google.listed[EVIL] = ("SOCIAL_ENGINEERING",)
    rep = make(google=google)
    await rep.check_one(EVIL, purpose="outbound")
    odd = "https://odd.example.org/"
    real = links.lookup_url

    def flaky(url: str, purpose: str) -> Optional[str]:
        if url == odd:
            raise RuntimeError("internal")
        return real(url, purpose)  # type: ignore[arg-type]

    monkeypatch.setattr(links, "lookup_url", flaky)
    cached = await rep.check([EVIL, odd], purpose="outbound", network=False)
    assert [r.service_status for r in cached] == ["listed", "error"]
    assert cached[0].level == "dangerous"
    reports = await rep.check([EVIL, odd, "https://fine.example.org/"], purpose="outbound")
    assert [r.service_status for r in reports] == ["listed", "error", "not_listed"]
    assert reports[0].level == "dangerous"
    assert any(note["kind"] == "link_not_checked" for note in security_notes(reports))


@pytest.mark.asyncio
async def test_check_never_raises_on_inputs_that_cannot_be_links_or_keys():
    """check() promises never to raise: an unhashable "link" used to break the fallback too
    (its text was looked up with it as a key)."""
    from services.security.link_checks import LocalOnlyLinkChecker

    rep = make()
    odd: Any = ["not", "a", "link"]
    texts = {EVIL: "paypal.com"}
    reports = await rep.check([odd, EVIL], purpose="chat", texts=texts)
    assert [s.code for s in reports[0].signals] == ["unreadable"]
    assert reports[1].level == "suspicious"
    assert "text_mismatch" in {s.code for s in reports[1].signals}
    assert await rep.check(42, purpose="chat") == []  # type: ignore[arg-type]
    local = await LocalOnlyLinkChecker().check([odd, EVIL], purpose="chat", texts=texts)
    assert [s.code for s in local[0].signals] == ["unreadable"]
    assert await LocalOnlyLinkChecker().check(42, purpose="chat") == []  # type: ignore[arg-type]


@pytest.mark.skipif(
    not __import__("os").environ.get("CRAWLER_LIVE_SAFE_BROWSING_KEY"),
    reason="live smoke test: set CRAWLER_LIVE_SAFE_BROWSING_KEY to a real Safe Browsing key",
)
@pytest.mark.asyncio
async def test_live_google_answers_its_own_test_page_with_a_real_key(monkeypatch):
    """Optional, never in default CI: one real lookup of Google's own test page with the key
    in CRAWLER_LIVE_SAFE_BROWSING_KEY, through the real guarded client and real DNS."""
    import os

    monkeypatch.undo()   # the real check_ssrf, the real DNS
    key = os.environ["CRAWLER_LIVE_SAFE_BROWSING_KEY"]
    result = await links.test_google_key("safe_browsing", key)
    assert result.ok, result.detail
    assert key not in result.detail


@pytest.mark.asyncio
async def test_a_host_written_with_letters_a_browser_folds_is_looked_up_as_the_site_it_opens():
    """Review of S4 (batch 2): hosts were lower-cased, not folded as a browser folds them, so a
    link spelled with such letters was looked up as another host and reported "no known
    threats" for mail, chat, outbound and scam checks while the browser opened a listed site.
    Each is now looked up as the host the browser opens (the forms the Chromium Playwright runs
    writes) and reported dangerous. The capital sharp s is the sharp s to a current browser
    (UTS 46 15.1 and later), so that host is the one looked up."""
    es, sharp, cap_s = chr(0x1C83), chr(0x1E9E), chr(0xA7F1)
    outlined = "".join(chr(0x1CCD6 + "abcdefghijklmnopqrstuvwxyz".index(ch)) for ch in "account")
    persian = "".join(map(chr, (0x645, 0x6CC, 0x200C, 0x62E, 0x648, 0x627, 0x647, 0x645)))
    written = [
        "https://" + es * 2 + ".com/login",
        "https://xn--g9da0d5gqac.com/",
        "https://account-a" + sharp + "ist.com/login",
        "https://" + outlined + "-a" + cap_s * 2 + "ist.com/login",
        "https://" + persian + ".com/",
        "https://pay" + chr(0x3164) + "pal-verify.com/login",
    ]
    google = FakeGoogle()
    for url in ("https://xn--q1aa.com/login", "https://xn--g9da0d5gqac.com/",
                "https://xn--account-aist-t9a.com/login", "https://account-assist.com/login",
                "https://xn--mgbn2ecje63gr19l.com/", "https://paypal-verify.com/login"):
        google.listed[url] = ("SOCIAL_ENGINEERING",)
    for purpose in ("mail", "chat", "outbound", "scam_check"):
        reports = await make(google=google).check(written, purpose=purpose)
        assert [r.level for r in reports] == ["dangerous"] * len(written), purpose
        assert all(r.service_status == "listed" for r in reports)
    assert set(google.sent()) == set(google.listed)
