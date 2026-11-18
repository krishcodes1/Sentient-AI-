"""Challenge detector: pure rules on fact dicts, then the same rules
against the fake site in headless Chromium (no false positive on the
invisible badge, a 403, a 429 or an ordinary checkout page, whose card
security code is named like a one-time code). A sign-in form is handed
over too, on a page named for signing in: a password box beside a box for
the account, or one box alone. A sign-in form on any other page (a bank's
home page, a forum's header, a checkout) is read with SIGNIN_FORM_NOTE,
and a sign-in step with a real guest path with GUEST_PATH_NOTE; neither is
handed over (``detect_challenge`` answers None). A sign-in frame is
judged by its page's name, as an inline form is, and a frame the person
cannot see is not read. A "Sign in" link, a
search, newsletter or contact box, a sign-up or change-password form and
a form that takes a card are no sign-in form at all."""

from __future__ import annotations

import time
from typing import Any

import pytest

from services.tools.browser.handoff import (
    GUEST_PATH_NOTE,
    SIGNIN_FORM_NOTE,
    Challenge,
    classify,
    detect,
    detect_challenge,
)


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
        "Please complete the security check to access shop.example.",
        "Complete the check below.",
    ],
)
def test_human_check_text(text):
    challenge = classify(facts(text=text))
    assert challenge is not None and challenge.kind == "unusual_traffic"


@pytest.mark.parametrize(
    "title, text",
    [
        ("Complete the checkout | Tickets", "Order summary"),
        ("Checkout", "Complete the checkout to get your tickets."),
        ("Your trip", "Please complete the check-in before you travel."),
        ("Tickets", "Complete the check out to get your seats."),
        ("Your trip", "Please complete the check in online."),
    ],
)
def test_checkout_and_check_in_wording_is_not_a_human_check(title, text):
    # "complete the check" is how a traffic wall says it; a shop says
    # "complete the checkout" and an airline "complete the check-in".
    assert classify(facts(title=title, text=text)) is None


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


SIGNIN = Challenge("signin", "the site wants you to sign in")


@pytest.mark.parametrize(
    "title, url",
    [
        ("Amazon Sign-In", "https://www.amazon.com/ax/claim?arb=abc&openid.return_to=x"),
        ("", "https://www.amazon.com/ap/signin"),
        ("Log in to Fake School", "https://school.example/"),
        ("Logon", "https://bank.example/"),
        ("Single Sign-On", "https://idp.school.edu/"),
        ("Fake School", "https://school.example/users/sign_in"),
        ("Fake School", "https://school.example/user_login.php"),
        ("Please authenticate", "https://school.example/"),
        ("Sign In | Hotel Rewards", "https://hotel.example/"),
        ("Login", "https://shop.example/"),
        ("Example.com: Sign In", "https://shop.example/"),
    ],
)
def test_a_sign_in_field_on_a_page_named_for_signing_in_is_a_sign_in_step(title, url):
    assert classify(facts(url=url, title=title, signin="field")) == SIGNIN


@pytest.mark.parametrize(
    "title, url",
    [
        ("Chain wax lube", "https://shop.example/dp/B0001"),
        ("Designing chairs", "https://blog.example/"),
        ("Signing up is free", "https://blog.example/"),
        ("Our blog in pictures", "https://blog.example/"),
        ("Catalog", "https://shop.example/catalog/online"),
        # The words in the query are where the page goes next, not what it is.
        ("Chain wax lube", "https://shop.example/dp/B0001?ref=signin"),
        # A thread whose title only mentions signing in, in a sentence.
        ("Can't log in after password reset - Fragrance Forum", "https://forum.example/showthread.php"),
        ("Can't sign in to Steam : r/Steam", "https://old.reddit.example/r/Steam/comments/1"),
        # Or ends with the words in a complaint.
        ("Can't log in - Fragrance Forum", "https://forum.example/showthread.php"),
        ("Problem with login : r/Steam", "https://old.reddit.example/r/Steam/comments/2"),
        ("Help! Can't sign in | Example Community", "https://forum.example/t/3"),
    ],
)
def test_a_sign_in_field_on_a_page_not_named_for_signing_in_is_an_ordinary_page(title, url):
    # One password box, or one account box, on a page the agent reads.
    assert classify(facts(url=url, title=title, signin="field")) is None
    # A password box beside an account box there is a note, never a handoff.
    assert classify(facts(url=url, title=title, signin="pair")) == SIGNIN_FORM


def test_a_page_named_for_signing_in_without_a_sign_in_field_is_an_ordinary_page():
    assert classify(facts(url="https://www.amazon.com/ap/signin", title="Amazon Sign-In")) is None


SIGNIN_FORM = Challenge("signin_form", SIGNIN_FORM_NOTE)
GUEST = Challenge("guest", GUEST_PATH_NOTE)


def test_a_sign_in_form_on_a_page_not_named_for_signing_in_is_read_with_a_note():
    # A bank's home page, titled for the bank, with its sign-on form: the
    # model hands it over itself when the task needs the account.
    bank = facts(url="https://www.bank.example/", title="Example Bank - Credit Cards, Loans", signin="pair")
    assert classify(bank) == SIGNIN_FORM
    assert classify({**bank, "title": "Sign On | Example Bank"}) == SIGNIN
    assert classify({**bank, "url": "https://www.bank.example/logon"}) == SIGNIN
    assert "browser.read handoff" in SIGNIN_FORM_NOTE and "otherwise go on" in SIGNIN_FORM_NOTE
    assert "—" not in SIGNIN_FORM_NOTE and "–" not in SIGNIN_FORM_NOTE


def test_a_sign_in_step_that_offers_a_guest_path_is_read_with_the_guest_note():
    assert classify(facts(title="Sign In to Shop", signin="pair", guest=True)) == GUEST
    assert classify(facts(title="Sign In to Shop", signin="field", guest=True)) == GUEST
    assert classify(facts(title="Checkout", signin="pair", guest=True)) == GUEST
    # One box on a page not named for signing in is no sign-in step, guest path or not.
    assert classify(facts(title="Checkout", signin="field", guest=True)) is None
    # The note the page is described with: the guest path first, the handoff only for the account.
    assert "guest path" in GUEST_PATH_NOTE and "browser.read handoff" in GUEST_PATH_NOTE
    assert "—" not in GUEST_PATH_NOTE and "–" not in GUEST_PATH_NOTE


def test_a_sign_in_form_in_an_identity_provider_frame_is_a_sign_in_step():
    idp = facts(url="https://login.microsoftonline.com/common/oauth2/authorize",
                title="Sign in to your account", signin="field")
    assert classify(facts(idp_frames=[idp])) == SIGNIN


def test_a_sign_in_frame_is_judged_by_its_pages_name_as_an_inline_form_is():
    logon = facts(url="https://bank.example/login", title="", signin="pair")
    email = facts(url="https://wallet.example/pay/login", title="", signin="field")
    # On a page not named for signing in: a pair is a note, one box is nothing.
    assert classify(facts(title="Bank | Home", signin_frames=[logon])) == SIGNIN_FORM
    assert classify(facts(title="Checkout", signin_frames=[email])) is None
    # On a page named for signing in, either is a sign-in step, found in that frame.
    named = facts(url="https://bank.example/logon")
    assert classify({**named, "signin_frames": [logon]}) == SIGNIN
    assert classify({**named, "signin_frames": [email]}) == SIGNIN
    assert classify({**named, "signin_frames": [email]}).frame == "https://wallet.example/pay/login"
    assert classify({**named, "signin": "pair"}).frame is None
    # A sign-in frame is no identity provider: its page's words name no second factor.
    assert classify({**named, "text": "Use a security key", "signin_frames": [logon]}) == SIGNIN


def test_a_one_time_code_a_second_factor_and_a_traffic_wall_win_over_a_sign_in_step():
    def kind(**over: Any) -> Any:
        return getattr(classify(facts(**{**named, **over})), "kind", None)

    named = {"url": "https://school.okta.com/signin/verify", "title": "Sign In", "signin": "field"}
    assert kind() == "signin"
    assert kind(otp=[{"id": "otp", "name": "", "autocomplete": "one-time-code"}]) == "otp"
    assert kind(text="Push notification sent") == "mfa"
    assert kind(url="https://shop.example/signin", text="Are you a robot?") == "unusual_traffic"


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
        # The live failure's two pages (Amazon's email step, then its
        # password step), and the stock login form, which is a sign-in
        # step too: only the person can finish it, and the guard lets
        # their submit through only once the page is handed to them.
        ("/ax/claim", "signin"),
        ("/ap/signin", "signin"),
        ("/login", "signin"),
        # A form that makes an account, with a new password: not a sign-in.
        ("/signup", None),
        ("/controls", None),
        ("/post", None),
        ("/flights", None),
        ("/checkout", None),
        ("/checkout-hint", None),
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


# A card's security code is called what a one-time code is called
# ("security code", "verification code"). Next to a card-number field
# those words name the card's code, which is the checkout's to fill.

CARD_NUMBER = '<label>Card number <input name="field1"></label>'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code_field",
    [
        '<input name="securityCode">',
        '<input name="cvv" placeholder="Security code">',
        '<input id="card-verification-code" aria-label="Card verification code">',
        '<input name="verification_code">',
    ],
)
async def test_a_cards_security_code_next_to_its_number_is_not_a_one_time_code(page, code_field):
    await page.set_content(f"<h1>Checkout</h1><form>{CARD_NUMBER}{code_field}</form>")
    assert await detect_challenge(page) is None


@pytest.mark.asyncio
async def test_a_field_the_page_marks_as_a_card_code_is_not_a_one_time_code(page):
    # A card on file: no number field on the page, only its code, marked
    # with the card vocabulary of the autocomplete attribute.
    await page.set_content(
        '<p>Visa ending 4242</p><input name="security_code" autocomplete="cc-csc">'
    )
    assert await detect_challenge(page) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body, otp_ref",
    [
        # No card-number field: the words keep their one-time meaning.
        ('<input name="securityCode">', 'css=input[name="securityCode"]'),
        ('<input name="verification_code">', 'css=input[name="verification_code"]'),
        # Next to a card number: a field named for a one-time code, and one
        # the page itself marks as a one-time code, are still that.
        (CARD_NUMBER + '<input name="otp" placeholder="Security code">', 'css=input[name="otp"]'),
        (
            CARD_NUMBER + '<input name="cvv"><input id="sms" placeholder="One-time passcode">',
            'css=[id="sms"]',
        ),
        (
            CARD_NUMBER + '<input name="securityCode" autocomplete="one-time-code">',
            'css=input[name="securityCode"]',
        ),
    ],
)
async def test_a_one_time_code_prompt_is_still_detected(page, body, otp_ref):
    await page.set_content(body)
    challenge = await detect_challenge(page)
    assert challenge is not None and (challenge.kind, challenge.otp_ref) == ("otp", otp_ref)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        '<input type="password" name="pw">',  # outside any form, as on many app pages
        '<label>Username <input name="u"></label>',
        '<input name="login" autocomplete="username">',
        '<input name="contact" autocomplete="section-a email webauthn">',
        '<input type="tel" name="x">',
        '<input name="userEmail" placeholder="Your address">',
        '<input name="x" aria-label="Mobile number">',
    ],
)
async def test_a_sign_in_field_is_found_however_the_page_names_it(page, field):
    await page.set_content(f"<title>Sign in</title><form method='post'>{field}<button>Next</button></form>")
    assert await detect_challenge(page) == SIGNIN


async def kinds(page) -> tuple[Any, Any]:
    """(what the outline is told, what every other caller hands over)."""
    noted, handed = await detect(page), await detect_challenge(page)
    return getattr(noted, "kind", None), getattr(handed, "kind", None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body, kind",
    [
        # A bank's home page: its sign-on form under the bank's own title.
        (
            '<title>Example Bank - Banking, Credit Cards, Loans</title><form method="post">'
            '<label>Online ID <input name="onlineId1"></label><label>Passcode '
            '<input type="password" name="passcode1"></label><button>Log In</button></form>',
            "signin_form",
        ),
        # A bank that signs on with its card: a number with no code or expiry beside it.
        (
            '<title>Online Banking</title><form method="post"><label>Card number <input name="cardNumber">'
            '</label><label>Password <input type="password" name="pw"></label><button>Sign on</button></form>',
            "signin_form",
        ),
        (
            '<title>Sign On | Online Banking</title><form method="post"><label>Card number <input '
            'name="cardNumber"></label><label>Password <input type="password" name="pw"></label>'
            "<button>Sign on</button></form>",
            "signin",
        ),
        # A refused page that shows the sign-in form itself.
        (
            '<title>Members only</title><form method="post" action="/login"><label>Username '
            '<input name="u"></label><label>Password <input name="p" type="password"></label>'
            '<button type="submit">Enter</button></form>',
            "signin_form",
        ),
        # One box for the account on a page named for signing in ("PAN" is not a card here).
        (
            '<title>Login | e-Filing</title><form method="post"><label>Enter PAN/Aadhaar/User ID '
            '<input name="panAdhaarUserId"></label><button>Continue</button></form>',
            "signin",
        ),
        # An ASP.NET page: one form wraps the page, and its first submit is the header's search.
        (
            "<title>Home | Community Credit Union</title><form method='post' action='/Default.aspx'>"
            "<div><input name='ctl00$q' placeholder='Search'><input type='submit' name='ctl00$go' "
            "value='Search'></div><div><label>Username <input name='ctl00$user'></label><label>Password "
            "<input type='password' name='ctl00$pw'></label><input type='submit' name='ctl00$signon' "
            "value='Sign On'></div><p>Rates and offers</p></form>",
            "signin_form",
        ),
        # A sign-in pair with the register panel's password hidden in the same form.
        (
            "<title>Sign In - Shop</title><form method='post' action='/account'><label>Email <input "
            "type='email' name='email'></label><label>Password <input type='password' name='pw'></label>"
            "<button name='login'>Sign in</button><div style='display:none'><input type='password' "
            "name='newpw'></div></form>",
            "signin",
        ),
    ],
)
async def test_a_sign_on_form_is_handed_over_on_a_page_named_for_it_and_noted_on_any_other(page, body, kind):
    await page.set_content(body)
    assert await kinds(page) == (kind, kind if kind == "signin" else None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body, kind",
    [
        # A forum thread with a login in its header: the thread is to be read.
        (
            "<title>Perfume reviews - Fragrance Forum</title><div id='navbar'><form "
            "action='/login.php?do=login' method='post'><input type='text' name='vb_login_username' "
            "placeholder='User Name'><input type='password' name='vb_login_password' placeholder='Password'>"
            "<input type='submit' value='Log in'></form></div><h1>Best summer fragrances</h1>",
            "signin_form",
        ),
        (
            "<title>r/fragrance</title><h1>Best perfume?</h1><form method='post' action='/post/login'>"
            "<input name='user' placeholder='username'><input type='password' name='passwd' "
            "placeholder='password'><button type='submit'>login</button></form>",
            "signin_form",
        ),
        # Threads whose titles mention logging in, in a sentence, not as the page's name.
        (
            "<title>Can't log in after password reset - Fragrance Forum</title><div id='navbar'><form "
            "action='/login.php?do=login' method='post'><input type='text' name='vb_login_username' "
            "placeholder='User Name'><input type='password' name='vb_login_password' placeholder='Password'>"
            "<input type='submit' value='Log in'></form></div><h1>Can't log in after password reset</h1>",
            "signin_form",
        ),
        (
            "<title>Can't sign in to Steam : r/Steam</title><h1>Can't sign in to Steam</h1><div "
            "class='side'><form method='post' action='/post/login'><input name='user' placeholder='username'>"
            "<input type='password' name='passwd' placeholder='password'><button type='submit'>login</button>"
            "</form></div>",
            "signin_form",
        ),
        # A checkout with an optional login above its form ("Sign in or
        # continue as guest" as plain words): browser.checkout goes on.
        (
            "<title>Checkout</title><h1>Shipping Address</h1><form class='form-login' method='post'>"
            "<label>Email Address <input type='email' name='username'></label><span>You already have an "
            "account with us. Sign in or continue as guest.</span><label>Password <input type='password' "
            "name='password'></label><button type='submit'>Login</button></form><form id='shipping'>"
            "<label>First Name <input name='firstname'></label><label>Street <input name='street'>"
            "</label></form>",
            "signin_form",
        ),
        (
            "<title>Checkout - Shop</title><form method='post' action='/checkout/shipping'><label>Email "
            "<input type='email' name='email'></label><label>Full name <input name='name'></label>"
            "<label>Address <input name='addr'></label><label>Create a password (optional) <input "
            "type='password' name='pw'></label><button>Continue to shipping</button></form>",
            "signin_form",
        ),
        # A checkout whose guest path is a radio beside its login form.
        (
            "<title>Checkout</title><h1>Checkout Method</h1><div><label><input type='radio' "
            "name='checkout_method' value='guest'> Checkout as Guest</label><label><input type='radio' "
            "name='checkout_method' value='register'> Register</label></div><form method='post'><label>"
            "Email Address <input type='email' name='login[username]'></label><label>Password <input "
            "type='password' name='login[password]'></label><button type='submit'>Login</button></form>",
            "guest",
        ),
    ],
)
async def test_a_sign_in_form_on_a_page_that_is_no_sign_in_step_is_read_with_a_note(page, body, kind):
    await page.set_content(body)
    assert await kinds(page) == (kind, None)


GUEST_SHOP = (
    '<title>Sign In to Shop</title><h1>Sign in</h1><form method="post" action="/login">'
    '<label>Email <input type="email" name="email"></label><label>Password '
    '<input type="password" name="pw"></label><button>Sign in</button></form>'
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "guest_path, kind",
    [
        ('<a href="/checkout/guest">Continue as Guest</a>', "guest"),
        ('<button type="button">Checkout as guest</button>', "guest"),
        ('<a href="/next" aria-label="Continue without an account">Skip</a>', "guest"),
        ('<label><input type="radio" name="method" value="guest"> Check out as a guest</label>', "guest"),
        ('<a href="/guest/checkout">Guest checkout</a>', "guest"),
        ('<button type="button">Pay as guest</button>', "guest"),
        ('<a href="/book/guest">Book as a guest</a>', "guest"),
        ('<a href="/checkout/guest">Order as guest</a>', "guest"),
        ('<a href="/checkout">Purchase as a guest</a>', "guest"),
        ('<a href="/checkout">Continue without signing in</a>', "guest"),
        ('<a href="/checkout">Check out without logging in</a>', "guest"),
        ("<a onclick='go()' class='btn'>Continue as guest</a>", "guest"),
        ("<span onclick='go()'>Continue as guest</span>", "guest"),
        ('<label><input type="checkbox" name="guest"> Check out as guest</label>', "guest"),
        # Below the fold is still a way on.
        ('<div style="height:900px"></div><a href="/checkout">Continue as guest</a>', "guest"),
        # The word alone is no way on: these pages still need the account.
        ('<a href="/guest-services">Guest Services</a>', "signin"),
        ('<a href="/reviews">Guest reviews</a>', "signin"),
        ('<p>Continue as guest</p>', "signin"),
        # A question about it, or a wrapper's whole sentence that it is not offered.
        ('<a href="/help/guest">Why can\'t I check out as a guest?</a>', "signin"),
        ("<div onclick='x()'><p>Guest checkout is not available for subscriptions.</p></div>", "signin"),
    ],
)
async def test_only_a_way_on_without_an_account_is_a_guest_path(page, guest_path, kind):
    await page.set_content(GUEST_SHOP)
    assert await kinds(page) == ("signin", "signin")
    await page.set_content(GUEST_SHOP + f"<h2>New here?</h2>{guest_path}")
    assert await kinds(page) == (kind, None if kind == "guest" else kind)


@pytest.mark.asyncio
async def test_a_sign_in_form_in_a_child_frame_is_judged_by_its_pages_name(page, fakesite, monkeypatch):
    """A bank's home page whose logon box is a child frame (Chase's shape)
    is read with the note, as the same form inline is; the same frame on a
    page named for signing in is handed over."""
    from tests.fakesite.pages import PAGES, _page

    frame = "<iframe src='/login' style='width:500px;height:300px'></iframe>"
    monkeypatch.setitem(PAGES, "/bank-home", (200, "text/html", _page(
        "Credit Card, Mortgage, Banking | Bank", f"<h1>Banking</h1>{frame}",
    )))
    monkeypatch.setitem(PAGES, "/bank-signon", (200, "text/html", _page("Sign On | Bank", frame)))
    await page.goto(fakesite.url("/bank-home"))
    assert await kinds(page) == ("signin_form", None)
    await page.goto(fakesite.url("/bank-signon"))
    assert await kinds(page) == ("signin", "signin")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "style",
    [
        "position:absolute;left:-10000px;top:0;width:400px;height:300px",
        "visibility:hidden;width:400px;height:300px",
        "opacity:0;width:400px;height:300px",
        "margin-top:1500px;width:400px;height:300px",
    ],
)
async def test_a_sign_in_frame_the_person_cannot_see_is_not_read(page, fakesite, monkeypatch, style):
    from tests.fakesite.pages import PAGES, _page

    monkeypatch.setitem(PAGES, "/signon", (200, "text/html", _page(
        "Sign On | Bank", f"<h1>Bank</h1><iframe src='/login' style='{style}'></iframe>",
    )))
    await page.goto(fakesite.url("/signon"))
    assert await kinds(page) == (None, None)


@pytest.mark.asyncio
async def test_a_checkouts_optional_wallet_login_frame_is_no_sign_in_step(page, fakesite, monkeypatch):
    """An express wallet's email box and Continue, in a frame at a sign-in
    address on a card checkout: the person need not use it."""
    from tests.fakesite.pages import PAGES, _page

    monkeypatch.setitem(PAGES, "/pay/login", (200, "text/html", _page(
        "Wallet", "<form method='post' action='/wallet/session'><label>Email <input type='email' "
        "name='email'></label><button>Continue</button></form>",
    )))
    monkeypatch.setitem(PAGES, "/checkout-wallet", (200, "text/html", _page(
        "Checkout", "<h1>Checkout</h1><iframe src='/pay/login' style='width:400px;height:160px'></iframe>",
    )))
    await page.goto(fakesite.url("/checkout-wallet"))
    assert await kinds(page) == (None, None)


@pytest.mark.asyncio
async def test_a_form_of_thousands_of_boxes_beside_a_password_is_read_in_linear_time(page):
    """One form, a password box and 8000 small boxes on screen, each labels
    read walking the document: every box asked about its account words
    took 2.2 s; the first twenty take a few hundredths."""
    cells = "".join(
        f"<input name='d{i}' style='width:10px;height:10px;padding:0;border:0;margin:0'>" for i in range(8000)
    )
    labels = "".join(f"<label for='zz{i}'>L{i}</label>" for i in range(8000))
    await page.set_content(
        "<title>Timesheet</title><form method='post'><input type='password' name='p' "
        f"style='width:10px;height:10px'><div style='display:flex;flex-wrap:wrap;width:1200px'>{cells}"
        f"</div><div>{labels}</div></form>"
    )
    started = time.perf_counter()
    await detect(page)
    assert time.perf_counter() - started < 1.0


@pytest.mark.asyncio
async def test_a_page_whose_address_names_the_sign_in_is_a_sign_in_step(page, fakesite, monkeypatch):
    from tests.fakesite.pages import PAGES, _page

    monkeypatch.setitem(PAGES, "/users/sign_in", (200, "text/html", _page(
        "Fake School", '<form method="post"><input name="user[email]"><button>Next</button></form>'
    )))
    await page.goto(fakesite.url("/users/sign_in"))
    assert await detect_challenge(page) == SIGNIN


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        # Only the way to the sign-in, as every shop page has it.
        '<title>Sign in</title><a href="/ap/signin">Hello, sign in</a><button>Sign in</button>',
        # A search box on a page named for signing in, and a newsletter box.
        '<title>Sign in</title><form role="search"><input type="search" name="q" '
        'placeholder="Search"></form><input name="field-keywords" aria-label="Search Amazon">',
        '<title>Chain care tips</title><form method="post"><label>Email '
        '<input type="email" name="email"></label><button>Subscribe</button></form>',
        # A checkout: its email box and its password-typed card code are the checkout's.
        '<title>Sign in or check out as a guest</title><form method="post"><label>Email '
        f'<input type="email" name="email"></label>{CARD_NUMBER}</form>',
        f'<title>Sign in</title><form method="post">{CARD_NUMBER}<label>Security code '
        '<input name="cvv" type="password"></label></form>',
        # A sign-in field the person cannot see.
        '<title>Sign in</title><form style="display:none"><input type="password" name="pw"></form>',
        '<title>Sign in</title><input type="email" name="email" style="visibility:hidden">',
        # Pages about signing in whose box is for something else: a post with
        # its subscribe box, a help article's contact form, docs with an
        # updates box outside any form, and a signed-in password change.
        '<title>How to sign in with a passkey</title><form><input type="email" name="email" '
        'placeholder="Type your email..."><button>Subscribe</button></form>',
        "<title>Can't log in? | Help Center</title><form><label>Your email <input type=\"email\" "
        'name="email"></label><textarea name="msg"></textarea><button>Send</button></form>',
        '<title>Authentication | Example API</title><input type="email" placeholder="Get product updates">',
        '<title>Password and authentication</title><form><input type="password" name="old">'
        '<input type="password" name="new"><button>Update password</button></form>',
        # Making an account, on a page that also names signing in.
        '<title>Sign in or create account</title><form method="post"><label>Username <input name="u">'
        '</label><label>Password <input type="password" name="p" autocomplete="new-password"></label>'
        "<button>Create account</button></form>",
        # A card form with a password box for its code, under a sign-on title.
        '<title>Sign on</title><form method="post"><label>Card number <input name="cardNumber"></label>'
        '<label>Expiry <input name="exp"></label><label>Password <input type="password" name="pw">'
        "</label><button>Sign on</button></form>",
    ],
)
async def test_a_page_that_is_not_a_sign_in_step_is_not_handed_over(page, body):
    await page.set_content(body)
    assert await detect_challenge(page) is None


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
