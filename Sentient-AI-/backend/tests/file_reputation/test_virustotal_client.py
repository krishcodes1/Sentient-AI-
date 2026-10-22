"""Tests for services/file_reputation/virustotal.py, the VirusTotal v3 client: they prove the
owner's key travels only in the x-apikey header, each request reaches only the path its own
network policy allows, answers become counts and one of four verdicts (never "safe"), the text
VirusTotal holds about a file (names, tags, vendor results) never comes through, and every
failure is a fixed-sentence error that names neither the key nor the URL.

Why it exists: this is the one module that sends anything to VirusTotal with the owner's key.
No real network or DNS: check_ssrf is replaced (conftest.py) and VirusTotal is
``httpx.MockTransport`` (fakevt.FakeVirusTotal), with fake keys built by repetition.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone

import httpx
import pytest
from structlog.testing import capture_logs

import core.network_security as netsec
from services.file_reputation import virustotal
from services.file_reputation.virustotal import (
    EICAR_SHA256,
    VT_API,
    VT_MAX_UPLOAD_BYTES,
    VirusTotalClient,
    VirusTotalError,
    VtFileReport,
    parse_file_report,
    verdict_from_report,
    verdict_of,
)
from services.tools.net import EgressBlocked
from tests.file_reputation.fakevt import (
    ANALYSIS_ID,
    KEY,
    OTHER_KEY,
    SUBMITTED_NAME,
    TAG_TEXT,
    VENDOR_TEXT,
    FakeVirusTotal,
    analysis_body,
    answering,
    file_body,
    sha_of,
)

SHA = sha_of(b"MZ fake program bytes")


@pytest.fixture
def vt() -> FakeVirusTotal:
    return FakeVirusTotal()


@pytest.fixture
def policy_calls(monkeypatch) -> list[tuple[str, str]]:
    """(url, policy key) of every network-policy check the client's resolvers made; the real
    policy still decides."""
    calls: list[tuple[str, str]] = []
    real = netsec.check_network_policy

    def recording(url: str, connector_type: str, **kwargs):
        calls.append((url, connector_type))
        return real(url, connector_type, **kwargs)

    monkeypatch.setattr(virustotal, "check_network_policy", recording)
    return calls


def report(**counts: int) -> VtFileReport:
    values = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, **counts}
    return VtFileReport(
        **values,
        engines=sum(values.values()),
        threat_label=None,
        file_type=None,
        first_seen_at=None,
        analysed_at=None,
    )


def every_log_text(logs: list[dict]) -> str:
    return json.dumps(logs, default=str)


# ---------------------------------------------------------------------------------------------
# The key and the policies
# ---------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_lookup_sends_the_key_only_in_the_x_apikey_header_and_never_in_the_url(vt):
    vt.add_file(SHA, malicious=5, undetected=60)
    with capture_logs() as logs:
        await VirusTotalClient(transport=vt.transport).lookup(KEY, SHA)

    (request,) = vt.requests
    assert request.headers["x-apikey"] == KEY
    assert KEY not in str(request.url)
    assert request.url.query == b""
    assert "authorization" not in request.headers
    assert request.headers["accept"] == "application/json"
    assert KEY not in every_log_text(logs)


@pytest.mark.asyncio
async def test_a_lookup_reaches_nothing_but_the_files_path_under_its_own_policy(
    vt, policy_calls, ssrf_urls
):
    vt.add_file(SHA, undetected=60)

    await VirusTotalClient(transport=vt.transport).lookup(KEY, SHA)

    (request,) = vt.requests
    assert (request.method, request.url.scheme, request.url.host, request.url.path) == (
        "GET",
        "https",
        "www.virustotal.com",
        f"/api/v3/files/{SHA}",
    )
    assert policy_calls == [(f"{VT_API}/files/{SHA}", "virustotal_lookup")]
    # The address check ran in front of the mock transport.
    assert ssrf_urls == [f"{VT_API}/files/{SHA}"]


def test_the_lookup_policy_cannot_reach_the_upload_endpoint():
    upload_url = f"{VT_API}/files"
    analysis_url = f"{VT_API}/analyses/{ANALYSIS_ID}"

    with pytest.raises(EgressBlocked):
        virustotal._lookup_addresses(upload_url)
    with pytest.raises(EgressBlocked):
        virustotal._lookup_addresses(analysis_url)
    with pytest.raises(EgressBlocked):
        virustotal._lookup_addresses(f"https://evil.example/api/v3/files/{SHA}")
    with pytest.raises(EgressBlocked):
        virustotal._lookup_addresses(f"http://www.virustotal.com/api/v3/files/{SHA}")
    # The upload policy is the one that reaches them.
    assert virustotal._upload_addresses(upload_url)
    assert virustotal._upload_addresses(analysis_url)
    assert virustotal._lookup_addresses(f"{VT_API}/files/{SHA}")


@pytest.mark.asyncio
async def test_a_refused_destination_logs_the_policy_key_and_never_the_url(monkeypatch, vt):
    def refuse(url: str, connector_type: str, **kwargs):
        return netsec.SSRFCheckResult(safe=False, reason=f"refused {url}")

    monkeypatch.setattr(virustotal, "check_network_policy", refuse)
    with capture_logs() as logs:
        with pytest.raises(VirusTotalError) as caught:
            await VirusTotalClient(transport=vt.transport).lookup(KEY, SHA)

    assert caught.value.code == "service_error"
    assert vt.requests == []
    text = every_log_text(logs)
    assert "virustotal_lookup" in text
    assert SHA not in text and KEY not in text and "virustotal.com" not in text


# ---------------------------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_known_file_becomes_counts_a_verdict_and_a_sanitised_threat_label(vt):
    vt.add_file(
        SHA,
        malicious=41,
        suspicious=2,
        harmless=1,
        undetected=28,
        label="Trojan.Emotet/Gen:Variant-7",
        type_description="Win32 EXE\x00\x1b[31m (packed)\u202e",
    )

    found = await VirusTotalClient(transport=vt.transport).lookup(KEY, SHA)

    assert found is not None
    assert (found.malicious, found.suspicious, found.harmless, found.undetected) == (41, 2, 1, 28)
    # Timeouts, failures and unsupported types are no opinion and are not counted.
    assert found.engines == 72
    assert found.threat_label == "trojan.emotet/gen:variant-7"
    assert found.file_type == "Win32 EXE [31m (packed)"
    assert found.first_seen_at == datetime(2024, 3, 1, tzinfo=timezone.utc)
    assert found.analysed_at == datetime(2025, 10, 10, tzinfo=timezone.utc)
    assert verdict_of(found) == "malicious"

    verdict = verdict_from_report(SHA, found)
    assert (verdict.verdict, verdict.flagged_by, verdict.engines) == ("malicious", 41, 72)
    assert verdict.first_seen == date(2024, 3, 1)
    assert verdict.last_scanned == date(2025, 10, 10)


def test_threat_labels_that_are_not_short_plain_tokens_are_dropped():
    for label in ("trojan emotet", "трoян.emotet", "x" * 65, "", "<script>", 42, None):
        body = file_body(SHA, malicious=3, undetected=10, label=label)  # type: ignore[arg-type]
        assert parse_file_report(body).threat_label is None
    assert parse_file_report(file_body(SHA, type_description=None)).file_type is None
    assert parse_file_report(file_body(SHA, type_description="x" * 90)).file_type == "x" * 40


def test_three_or_more_malicious_engines_read_as_malicious_and_one_or_two_as_suspicious():
    assert verdict_of(report(malicious=3, undetected=60)) == "malicious"
    assert verdict_of(report(malicious=41, undetected=30)) == "malicious"
    assert verdict_of(report(malicious=2, undetected=60)) == "suspicious"
    assert verdict_of(report(malicious=1, undetected=60)) == "suspicious"
    assert verdict_of(report(suspicious=1, undetected=60)) == "suspicious"
    assert verdict_of(report(harmless=5, undetected=60)) == "no_detections"
    # Nobody gave an opinion: VirusTotal could not judge it.
    assert verdict_of(report()) == "unknown"
    assert verdict_of(None) == "unknown"


@pytest.mark.asyncio
async def test_a_404_reads_as_unknown_to_virustotal_and_never_as_safe(vt):
    found = await VirusTotalClient(transport=vt.transport).lookup(KEY, SHA)

    assert found is None
    verdict = verdict_from_report(SHA, found, can_upload=True)
    assert verdict.verdict == "unknown"
    assert verdict.can_upload is True
    assert "safe" not in verdict.summary().lower()
    assert "safe" not in json.dumps(verdict.as_tool_result()).replace(
        "never suggest it for personal documents", ""
    ).lower()


@pytest.mark.asyncio
async def test_a_401_reads_as_a_rejected_key_and_a_429_as_virustotals_own_limit(vt):
    client = VirusTotalClient(transport=vt.transport)

    with pytest.raises(VirusTotalError) as rejected:
        await client.lookup(OTHER_KEY, SHA)
    assert (rejected.value.code, rejected.value.status_code) == ("key_rejected", 401)

    vt.fail_with = 403
    with pytest.raises(VirusTotalError) as forbidden:
        await client.lookup(KEY, SHA)
    assert forbidden.value.code == "key_rejected"

    vt.fail_with = None
    vt.throttle = True
    with pytest.raises(VirusTotalError) as limited:
        await client.lookup(KEY, SHA)
    assert (limited.value.code, limited.value.status_code) == ("virustotal_limit", 429)

    vt.throttle = False
    vt.fail_with = 503
    with pytest.raises(VirusTotalError) as broken:
        await client.lookup(KEY, SHA)
    assert (broken.value.code, broken.value.status_code) == ("service_error", 503)
    # VirusTotal's own error text is never carried.
    for error in (rejected.value, forbidden.value, limited.value, broken.value):
        assert VENDOR_TEXT not in str(error)


@pytest.mark.asyncio
async def test_submitted_file_names_and_vendor_texts_never_reach_the_result(vt):
    vt.add_file(SHA, malicious=12, undetected=50, label="trojan.agent")

    found = await VirusTotalClient(transport=vt.transport).lookup(KEY, SHA)
    verdict = verdict_from_report(SHA, found)

    everything = " ".join(
        [repr(found), verdict.summary(), json.dumps(verdict.as_tool_result())]
    )
    for outside_text in (SUBMITTED_NAME, "setup.exe", VENDOR_TEXT, TAG_TEXT, "VendorA"):
        assert outside_text not in everything


@pytest.mark.asyncio
async def test_errors_carry_the_exception_type_only_never_the_key_or_url(vt):
    leaky = f"connect failed for {VT_API}/files/{SHA} with x-apikey: {KEY}"
    vt.fail_with = httpx.ConnectError(leaky)

    with capture_logs() as logs:
        with pytest.raises(VirusTotalError) as caught:
            await VirusTotalClient(transport=vt.transport).lookup(KEY, SHA)

    error = caught.value
    assert (error.code, error.error_type) == ("service_error", "ConnectError")
    assert str(error) == "VirusTotal could not be reached"
    assert error.__cause__ is None and error.__suppress_context__
    text = every_log_text(logs)
    assert "ConnectError" in text
    for secret in (KEY, SHA, VT_API, leaky):
        assert secret not in str(error) and secret not in text


@pytest.mark.asyncio
async def test_redirects_are_not_followed():
    transport, seen = answering(302, headers={"Location": "http://127.0.0.1/steal"})

    with pytest.raises(VirusTotalError) as caught:
        await VirusTotalClient(transport=transport).lookup(KEY, SHA)

    assert (caught.value.code, caught.value.status_code) == ("service_error", 302)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_a_fingerprint_that_is_not_64_hex_is_refused_before_any_request(vt, ssrf_urls):
    client = VirusTotalClient(transport=vt.transport)
    for bad in (
        SHA.upper(),
        SHA[:63],
        SHA + "0",
        f"{SHA[:60]}/../",
        f"{SHA[:62]}?x",
        "",
        None,
    ):
        with pytest.raises(ValueError):
            await client.lookup(KEY, bad)  # type: ignore[arg-type]
    assert vt.requests == [] and ssrf_urls == []


@pytest.mark.asyncio
async def test_a_key_that_cannot_be_a_header_is_refused_before_any_request(vt, ssrf_urls):
    client = VirusTotalClient(transport=vt.transport)
    for bad in (KEY + "\n", "a b", "", "ключ" * 16, None):
        with pytest.raises(VirusTotalError) as caught:
            await client.lookup(bad, SHA)  # type: ignore[arg-type]
        assert caught.value.code == "key_rejected"
    assert vt.requests == [] and ssrf_urls == []


# ---------------------------------------------------------------------------------------------
# Uploads and analyses
# ---------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_upload_posts_multipart_with_the_neutral_name_file_under_the_upload_policy(
    vt, policy_calls
):
    data = b"MZ\x90\x00 a program someone sent"

    analysis_id = await VirusTotalClient(transport=vt.transport).upload(KEY, data)

    assert analysis_id == ANALYSIS_ID
    (request,) = vt.requests
    assert (request.method, request.url.path) == ("POST", "/api/v3/files")
    assert request.headers["content-type"].startswith("multipart/form-data")
    assert request.headers["x-apikey"] == KEY
    (body,) = vt.uploads
    assert b'name="file"; filename="file"' in body
    assert data in body
    assert policy_calls == [(f"{VT_API}/files", "virustotal_upload")]


@pytest.mark.asyncio
async def test_uploads_that_are_empty_or_over_32_mb_are_refused_without_a_request(vt):
    client = VirusTotalClient(transport=vt.transport)

    with pytest.raises(VirusTotalError) as empty:
        await client.upload(KEY, b"")
    with pytest.raises(VirusTotalError) as too_large:
        await client.upload(KEY, b"\0" * (VT_MAX_UPLOAD_BYTES + 1))

    assert (empty.value.code, too_large.value.code) == ("empty", "too_large")
    assert vt.requests == []


@pytest.mark.asyncio
async def test_an_upload_that_times_out_after_sending_may_have_been_received(vt):
    client = VirusTotalClient(transport=vt.transport)

    vt.fail_with = httpx.ReadTimeout("no answer")
    with pytest.raises(VirusTotalError) as late:
        await client.upload(KEY, b"MZ bytes")
    vt.fail_with = httpx.ConnectTimeout("never connected")
    with pytest.raises(VirusTotalError) as early:
        await client.upload(KEY, b"MZ bytes")

    assert (late.value.code, late.value.maybe_received) == ("service_error", True)
    assert (early.value.code, early.value.maybe_received) == ("service_error", False)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "content", "maybe_received"),
    [
        # VirusTotal answered 200 (it took the file) with a body that is not its documented shape.
        (200, b"not json at all", True),
        (200, json.dumps({"data": {"type": "analysis", "id": "bad id!"}}).encode(), True),
        (200, b'{"data": "' + b"x" * (2 * 1024 * 1024) + b'"}', True),
        # A gateway error after the whole upload went out: it may have been passed on.
        (502, b"Bad Gateway", True),
        (504, b"Gateway Timeout", True),
        # VirusTotal's own refusals: the file was not taken.
        (401, b"{}", False),
        (413, b"{}", False),
        (429, b"{}", False),
    ],
    ids=["200-not-json", "200-bad-id", "200-too-long", "502", "504", "401", "413", "429"],
)
async def test_an_upload_answer_that_may_mean_the_file_was_taken_says_it_may_have_been_received(
    status, content, maybe_received
):
    """Checker finding (early S10 recheck): a 200 with a malformed answer or a 5xx after the
    body was sent must not read as "not shared", or the card would tell the user the file never
    reached a service that passes uploads to security companies."""
    transport, seen = answering(status, content=content)
    client = VirusTotalClient(transport=transport)

    with pytest.raises(VirusTotalError) as failed:
        await client.upload(KEY, b"MZ bytes")

    assert failed.value.maybe_received is maybe_received
    assert len(seen) == 1
    assert KEY not in str(failed.value)


@pytest.mark.asyncio
async def test_an_analysis_poll_reads_queued_in_progress_and_completed(vt, policy_calls):
    client = VirusTotalClient(transport=vt.transport)

    vt.analyses[ANALYSIS_ID] = analysis_body("queued")
    queued = await client.analysis(KEY, ANALYSIS_ID)
    vt.analyses[ANALYSIS_ID] = analysis_body("in-progress", sha256=SHA.upper())
    running = await client.analysis(KEY, ANALYSIS_ID)
    vt.analyses[ANALYSIS_ID] = analysis_body(
        "completed", sha256=SHA, malicious=1, harmless=2, undetected=68
    )
    done = await client.analysis(KEY, ANALYSIS_ID)

    assert (queued.status, queued.report, queued.sha256) == ("queued", None, None)
    assert (running.status, running.report, running.sha256) == ("in-progress", None, SHA)
    assert done.status == "completed" and done.sha256 == SHA
    assert done.report is not None
    assert (done.report.malicious, done.report.engines) == (1, 71)
    assert done.report.analysed_at == datetime(2025, 10, 10, tzinfo=timezone.utc)
    assert verdict_of(done.report) == "suspicious"
    assert {policy for _url, policy in policy_calls} == {"virustotal_upload"}
    assert VENDOR_TEXT not in repr(done)


@pytest.mark.asyncio
async def test_an_analysis_id_outside_the_safe_alphabet_is_refused_before_any_request(vt):
    client = VirusTotalClient(transport=vt.transport)
    for bad in ("../files/" + SHA, "a/b", "a?b=1", "", "x" * 129, None):
        with pytest.raises(ValueError):
            await client.analysis(KEY, bad)  # type: ignore[arg-type]
    assert vt.requests == []


@pytest.mark.asyncio
async def test_an_upload_answer_without_a_safe_analysis_id_is_a_service_error():
    for payload in ({"data": {"id": "../../files"}}, {"data": {}}, {"error": "x"}, []):
        transport, _seen = answering(200, content=json.dumps(payload).encode())
        with pytest.raises(VirusTotalError) as caught:
            await VirusTotalClient(transport=transport).upload(KEY, b"MZ bytes")
        assert caught.value.code == "service_error"


@pytest.mark.asyncio
async def test_a_malformed_or_oversized_answer_is_a_service_error_not_a_verdict(vt):
    other = sha_of(b"some other file")
    stats_text = file_body(SHA)
    stats_text["data"]["attributes"]["last_analysis_stats"]["malicious"] = "41"
    stats_bool = file_body(SHA)
    stats_bool["data"]["attributes"]["last_analysis_stats"]["malicious"] = True
    stats_negative = file_body(SHA)
    stats_negative["data"]["attributes"]["last_analysis_stats"]["harmless"] = -1
    no_stats = file_body(SHA)
    del no_stats["data"]["attributes"]["last_analysis_stats"]
    bodies = [
        b"<html>not json</html>",
        b"\xff\xfe\x00",
        json.dumps([1, 2, 3]).encode(),
        json.dumps({"data": None}).encode(),
        json.dumps({"data": {"attributes": []}}).encode(),
        json.dumps(stats_text).encode(),
        json.dumps(stats_bool).encode(),
        json.dumps(stats_negative).encode(),
        json.dumps(no_stats).encode(),
        # An integer too long for Python to convert (over 4300 digits) is a ValueError.
        b'{"data": ' + b"1" * 5000 + b"}",
        # A report about another fingerprint is no answer about this one.
        json.dumps(file_body(other, malicious=50)).encode(),
        # Over the 1 MB answer cap.
        json.dumps({"data": {"attributes": {"pad": "x" * (1024 * 1024)}}}).encode(),
    ]
    for body in bodies:
        transport, _seen = answering(200, content=body)
        with pytest.raises(VirusTotalError) as caught:
            await VirusTotalClient(transport=transport).lookup(KEY, SHA)
        assert caught.value.code == "service_error"


@pytest.mark.asyncio
async def test_a_deeply_nested_json_answer_under_the_size_cap_is_a_service_error_not_a_recursion_error(
    vt,
):
    # Small enough to pass the 1 MB cap, deep enough to exhaust the JSON parser's recursion
    # limit. Every caller must still get a VirusTotalError, never a raw RecursionError.
    nested_bodies = [
        b"[" * 200_000,
        b'{"data":' * 100_000 + b"1" + b"}" * 100_000,
    ]
    for body in nested_bodies:
        assert len(body) <= virustotal.MAX_ANSWER_BYTES
        transport, _seen = answering(200, content=body)
        client = VirusTotalClient(transport=transport)
        for method, argument in (
            (client.lookup, SHA),
            (client.upload, b"MZ bytes"),
            (client.analysis, ANALYSIS_ID),
        ):
            with pytest.raises(VirusTotalError) as caught:
                await method(KEY, argument)
            error = caught.value
            assert (error.code, error.status_code, error.error_type) == (
                "service_error",
                200,
                "not_json",
            )
            assert error.__cause__ is None and error.__suppress_context__
        tested = await virustotal.test_key(KEY, transport=transport)
        assert (tested.ok, tested.detail) == (False, "VirusTotal could not be reached.")


# ---------------------------------------------------------------------------------------------
# The Service keys tester
# ---------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_key_tester_accepts_a_working_key_and_never_quotes_a_refused_one(vt, ssrf_urls):
    # EICAR unknown (404) and known (200) both prove the key works.
    unknown = await virustotal.test_key(KEY, transport=vt.transport)
    vt.add_file(EICAR_SHA256, malicious=60, undetected=5)
    known = await virustotal.test_key(KEY, transport=vt.transport)
    refused = await virustotal.test_key(OTHER_KEY, transport=vt.transport)
    vt.throttle = True
    slow = await virustotal.test_key(KEY, transport=vt.transport)
    vt.throttle = False
    vt.fail_with = httpx.ConnectError("down")
    unreachable = await virustotal.test_key(KEY, transport=vt.transport)

    assert (unknown.ok, known.ok) == (True, True)
    assert known.detail == "VirusTotal answered: the key works."
    assert refused.ok is False
    assert refused.detail.startswith("VirusTotal refused the key")
    assert (slow.ok, slow.detail) == (True, "VirusTotal accepted the key but asked to slow down.")
    assert (unreachable.ok, unreachable.detail) == (False, "VirusTotal could not be reached.")
    for result in (unknown, known, refused, slow, unreachable):
        assert KEY not in result.detail and OTHER_KEY not in result.detail
    # Every request was the one EICAR lookup.
    assert {request.url.path for request in vt.requests} == {f"/api/v3/files/{EICAR_SHA256}"}

    sent_before = len(vt.requests)
    malformed = await virustotal.test_key("not-a-key " + KEY[:20], transport=vt.transport)
    assert malformed.ok is False and "64 characters" in malformed.detail
    assert KEY[:20] not in malformed.detail
    assert len(vt.requests) == sent_before


@pytest.mark.asyncio
async def test_the_key_registry_reaches_this_tester_lazily(monkeypatch, vt):
    from services.reputation.keys import spec_for

    seen: list[str] = []
    real_test_key = virustotal.test_key

    async def fake_test_key(key: str):
        seen.append(key)
        return await real_test_key(key, transport=vt.transport)

    monkeypatch.setattr(virustotal, "test_key", fake_test_key)
    spec = spec_for("virustotal")

    assert spec is not None
    result = await spec.tester(KEY)

    assert result.ok is True and seen == [KEY]
