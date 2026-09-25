"""Challenge detector: pure rules on fact dicts, then the same rules
against the fake site in headless Chromium (no false positive on the
invisible badge, a 403 or a 429)."""

from __future__ import annotations

from typing import Any

import pytest

from services.tools.browser.handoff import Challenge, classify, detect_challenge


def facts(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "url": "https://canvas.school.edu/courses/1",
        "title": "Course",
        "text": "Welcome to Biology 101",
        "frames": [],
        "otp": [],
        "idp_frames": [],
    }
    base.update(over)
    return base


def frame(**over: Any) -> dict[str, Any]:
    base = {"title": "reCAPTCHA", "src": "https://www.google.com/recaptcha/api2/anchor", "visible": True, "badge": False}
    base.update(over)
    return base


def test_invisible_badge_and_hidden_frame_are_not_challenges():
    assert classify(facts(frames=[frame(badge=True), frame(visible=False)])) is None


@pytest.mark.parametrize(
    "challenge_frame",
    [
        frame(),
        frame(title="", src="https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html"),
        frame(title="Widget containing a Cloudflare security challenge", src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile"),
        frame(title="Verification challenge", src="https://client-api.arkoselabs.com/fc/gc/"),
    ],
)
def test_visible_challenge_frame_by_title_or_host(challenge_frame):
    challenge = classify(facts(frames=[challenge_frame]))
    assert challenge is not None and challenge.kind == "captcha"


def test_captcha_wins_over_human_check_text():
    challenge = classify(facts(frames=[frame()], text="Please complete the security check"))
    assert challenge is not None and challenge.kind == "captcha"


def test_otp_field_records_a_selector():
    challenge = classify(facts(otp=[{"id": "otp", "name": "code", "autocomplete": "one-time-code"}]))
    assert challenge == Challenge("otp", "one-time code field on the page", otp_ref='css=[id="otp"]')


@pytest.mark.parametrize(
    "field, selector",
    [
        ({"id": "", "name": "code", "autocomplete": ""}, 'css=input[name="code"]'),
        ({"id": "", "name": "", "autocomplete": "one-time-code"}, 'css=input[autocomplete="one-time-code"]'),
    ],
)
def test_otp_selector_fallbacks(field, selector):
    challenge = classify(facts(otp=[field]))
    assert challenge is not None and challenge.otp_ref == selector


def test_otp_in_an_idp_frame_counts():
    challenge = classify(facts(idp_frames=[facts(url="https://api-1234.duosecurity.com/frame/v4", otp=[{"id": "passcode", "name": "passcode", "autocomplete": ""}])]))
    assert challenge is not None and (challenge.kind, challenge.otp_ref) == ("otp", 'css=[id="passcode"]')


@pytest.mark.parametrize(
    "url, text",
    [
        ("https://api-1234.duosecurity.com/frame/v4/auth/prompt", "Check for a Duo Push on your phone"),
        ("https://login.microsoftonline.com/common/SAS/ProcessAuth", "Approve sign in request. Enter the number shown to sign in."),
        ("https://school.okta.com/signin/verify/okta/push", "Push notification sent. Open the Okta Verify app."),
        ("https://accounts.google.com/v3/signin/challenge/dp", "Check your phone. Google sent a notification."),
    ],
)
def test_idp_second_factor_pages_are_mfa(url, text):
    challenge = classify(facts(url=url, text=text))
    assert challenge is not None and challenge.kind == "mfa"


def test_duo_frame_inside_a_school_page_is_mfa():
    challenge = classify(facts(url="https://sso.school.edu/idp/profile", idp_frames=[facts(url="https://api-1234.duosecurity.com/frame/v4", text="Check for a Duo Push")]))
    assert challenge is not None and challenge.kind == "mfa"


@pytest.mark.parametrize(
    "url, text",
    [
        ("https://login.microsoftonline.com/common/login", "Enter password"),  # IdP, no second factor yet
        ("https://accounts.google.com/v3/signin/identifier", "Enter the number shown"),  # not a challenge path
        ("https://canvas.school.edu/profile/settings", "Set up your authenticator app"),  # words, wrong host
    ],
)
def test_mfa_needs_both_an_idp_and_second_factor_words(url, text):
    assert classify(facts(url=url, text=text)) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://www.google.com/sorry/index?continue=https://www.google.com/flights",
        "https://shop.example/bots.html",
        "https://shop.example/cdn-cgi/challenge-platform/h/b/orchestrate/",
        "https://shop.example/_Incapsula_Resource?SWUDNSAI=9",
    ],
)
def test_bot_wall_urls(url):
    challenge = classify(facts(url=url, text="Please wait."))
    assert challenge is not None and challenge.kind == "unusual_traffic"


@pytest.mark.parametrize(
    "text",
    [
        "Verify you are human",
        "Our systems have detected unusual traffic from your computer network.",
        "Checking your browser before accessing the site.",
        "Are you a robot?",
    ],
)
def test_human_check_text(text):
    challenge = classify(facts(text=text))
    assert challenge is not None and challenge.kind == "unusual_traffic"


@pytest.mark.parametrize(
    "title, text",
    [
        ("Forbidden", "You do not have access to this course."),
        ("Too Many Requests", "Slow down."),
        ("Grades", "Lab report 2 Missing"),
        ("Log in", "Username Password Log in"),
    ],
)
def test_plain_pages_and_errors_are_not_challenges(title, text):
    assert classify(facts(title=title, text=text)) is None


# -- against the fake site in headless Chromium ----------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path, kind",
    [
        ("/captcha", "captcha"),
        ("/badge", None),
        ("/sso/otp", "otp"),
        ("/human", "unusual_traffic"),
        ("/bots.html", "unusual_traffic"),
        ("/forbidden", None),
        ("/throttled", None),
        ("/grades", None),
        ("/login", None),
        ("/flights", None),
    ],
)
async def test_detect_challenge_on_the_fake_site(page, fakesite, path, kind):
    await page.goto(fakesite.url(path))
    challenge = await detect_challenge(page)
    assert (challenge.kind if challenge else None) == kind


@pytest.mark.asyncio
async def test_otp_ref_resolves_to_the_code_field(page, fakesite):
    await page.goto(fakesite.url("/sso/otp"))
    challenge = await detect_challenge(page)
    assert challenge is not None and challenge.otp_ref == 'css=[id="otp"]'
    await page.locator(challenge.otp_ref).fill("123456")
    assert await page.locator("#otp").input_value() == "123456"


@pytest.mark.asyncio
async def test_detector_survives_a_navigating_page(page, fakesite):
    await page.goto(fakesite.url("/"))
    await page.close()
    assert await detect_challenge(page) is None


# -- review hardening ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_detection_log_carries_no_query_or_fragment(monkeypatch):
    # IdP and bot-wall URLs carry session ids and SAML/OAuth state in the
    # query; logs are persistent and must not hold them.
    from structlog.testing import capture_logs

    from services.tools.browser import handoff

    async def fake_collect(_page):
        return facts(url="https://api-1.duosecurity.com/frame/v4/auth/prompt?sid=SECRET1#SECRET2", text="Check for a Duo Push")

    monkeypatch.setattr(handoff, "collect_facts", fake_collect)
    with capture_logs() as logs:
        challenge = await detect_challenge(object())
    assert challenge is not None and challenge.kind == "mfa"
    assert logs and "SECRET" not in repr(logs)
    assert logs[-1]["url"] == "https://api-1.duosecurity.com/frame/v4/auth/prompt"


@pytest.mark.parametrize(
    "field, selector",
    [
        # page value x\"], input[name=evil  →  backslash and quote both escaped
        ({"id": 'x\\"], input[name=evil', "name": "", "autocomplete": ""}, 'css=[id="x\\\\\\"], input[name=evil"]'),
        ({"id": "", "name": 'code\\"], [name=evil', "autocomplete": ""}, 'css=input[name="code\\\\\\"], [name=evil"]'),
        ({"id": "line\nbreak", "name": "", "autocomplete": ""}, 'css=[id="line\\a break"]'),
    ],
)
def test_otp_selector_escapes_page_controlled_attribute_values(field, selector):
    # The id/name come from the page: a backslash must not unescape the
    # closing quote and splice a second selector in.
    challenge = classify(facts(otp=[field]))
    assert challenge is not None and challenge.otp_ref == selector


@pytest.mark.asyncio
async def test_otp_ref_with_a_hostile_id_selects_only_the_code_field(page):
    await page.set_content(
        '<input id=\'x\\"], input[name=evil\' autocomplete="one-time-code">'
        '<input name="evil" value="decoy">'
    )
    challenge = await detect_challenge(page)
    assert challenge is not None and challenge.kind == "otp" and challenge.otp_ref is not None
    target = page.locator(challenge.otp_ref)
    assert await target.count() == 1
    assert await target.get_attribute("autocomplete") == "one-time-code"
