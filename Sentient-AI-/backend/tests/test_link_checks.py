"""Tests for services/security/link_checks.py, the free local link checks: they prove a plain
public link carries no signal; look-alike letters, a brand typo or homograph, a bare public IP,
credentials before an "@", a script link and link text that names another site are high; a
brand used as a label and an abused domain ending are only warnings; shorteners and
single-script international names are only info; a link is read the way a browser reads it
(obfuscated and zero-padded IPv4, padded ports, backslashes, missing slashes, every host
character the URL standard allows, userinfo urllib refuses, wrappers unwrapped at most twice)
and no hostile number, port, host or link text ever raises or costs a report its findings;
what may be sent to Google drops userinfo, fragments, secret-carrying queries and token paths,
keeps only scheme and host for the browser, never names a non-public host and is capped;
levels are dangerous only from Google and suspicious only from a high signal; and every
sentence and note names hosts only, never calls a link safe, and is model-safe when it goes
back to the model.

Why it exists: S1, S2, S3 and the browser guard all quote these checks to the owner and act on
them, and lookup_url is the one rule for what leaves the machine with the owner's key
(decisions 2, resolutions S4). Pure: no network, no database, no key.
"""

from __future__ import annotations

import itertools
from typing import Callable, TypeVar

import pytest

from services.agent.prompt_guard import PromptGuard
from services.security import link_checks
from services.security.link_checks import (
    NOT_CHECKED_STATUSES,
    SIGNAL_CODES,
    LinkReport,
    LinkSignal,
    LocalOnlyLinkChecker,
    coverage_note,
    display_url,
    level_for,
    link_text_mismatch,
    local_report,
    local_signals,
    lookup_url,
    model_safe_text,
    security_notes,
    threat_words,
    unwrap_redirector,
)
from tests.linear_time import scales_linearly

ALL_STATUSES = (
    "listed", "not_listed", "no_key", "off", "settings_unreadable", "not_eligible", "too_many",
    "cache_miss", "rate_limited", "cooling_down", "timeout", "error", "key_rejected",
)
PURPOSES = ("browser", "mail", "chat", "outbound", "scam_check")


def codes(url: str) -> dict[str, str]:
    return {s.code: s.severity for s in local_signals(url)}


# ── signals ────────────────────────────────────────────────────────────


def test_a_plain_public_link_has_no_signals_and_is_eligible_for_a_lookup():
    report = local_report("https://www.example.org/blog/post?page=2")
    assert report.signals == ()
    assert report.level == "unknown"
    assert report.host == "www.example.org"
    assert report.shown == "https://www.example.org/blog/post"
    assert report.service_status == "no_key"
    assert lookup_url("https://www.example.org/blog/post?page=2", "mail") == (
        "https://www.example.org/blog/post?page=2"
    )


def test_a_mixed_script_host_is_flagged_as_look_alike_letters_with_its_latin_reading_and_punycode():
    for url in ("https://pаypal.com/login", "http://xn--pypal-4ve.com/login"):
        (signal,) = local_signals(url)
        assert signal.code == "lookalike_characters" and signal.severity == "high"
        assert signal.text == (
            "The address uses look-alike letters: pаypal.com reads as paypal.com "
            "(written xn--pypal-4ve.com)."
        )
    report = local_report("https://аррӏе.com/")
    assert report.level == "suspicious"
    assert report.host == "xn--80ak6aa92e.com"
    assert report.shown == "https://xn--80ak6aa92e.com/"


def test_a_single_script_international_host_is_only_an_info_note_and_not_suspicious():
    report = local_report("https://пример.рф/")
    assert [(s.code, s.severity) for s in report.signals] == [("international_address", "info")]
    assert report.signals[0].text == (
        "The address uses non-Latin letters (пример.рф, written xn--e1afmkfd.xn--p1ai)."
    )
    assert report.level == "unknown"
    # An accented Latin name is an ordinary address, not even an info note.
    assert local_signals("https://café.fr/") == ()


def test_japanese_chinese_and_korean_names_written_in_their_own_script_mixes_are_only_international_addresses():
    # Review of S4: Han with kana, Hangul or Latin is how ordinary CJK names are written (UTS 39
    # "highly restrictive"); flagging them made every Japanese site a high look-alike whose
    # sentence read "x reads as x" and whose warn note suppressed standing-consent offers.
    for url in ("https://日本のサイト.jp/", "https://例え.テスト.jp/", "https://qq邮箱.com/",
                "https://韓國어.kr/", "https://日本ーテスト.jp/", "https://abcテスト.jp/",
                "https://ㄅㄆ中文.tw/"):
        report = local_report(url)
        assert [(s.code, s.severity) for s in report.signals] == [("international_address", "info")], url
        assert report.level == "unknown"
        assert security_notes([report]) == []
    # A mix with no Latin, Cyrillic or Greek letter cannot imitate a Latin name either.
    assert codes("https://ไทยລາວ.com/") == {"international_address": "info"}
    # A confusable alphabet inside a CJK mix still is a look-alike.
    assert codes("https://аpple中.com/") == {"lookalike_characters": "high"}


def test_a_latin_word_with_a_cyrillic_letter_that_has_no_latin_twin_is_flagged_without_a_self_referential_reading():
    (signal,) = local_signals("https://payпal.com/")
    assert (signal.code, signal.severity) == ("lookalike_characters", "high")
    assert signal.text == (
        "The address uses look-alike letters: payпal.com mixes alphabets in one name "
        "(written xn--payal-rye.com)."
    )
    assert model_safe_text(signal) == (
        "The address uses look-alike letters: xn--payal-rye.com mixes alphabets in one name."
    )
    detections = PromptGuard().scan(model_safe_text(signal)).detections
    assert not [d for d in detections if d.severity in ("high", "critical")]
    (note,) = security_notes([local_report("https://payпal.com/")])
    assert "payпal.com reads as payпal.com" not in note["text"]


def test_a_latin_label_carrying_a_latin_script_look_alike_letter_is_flagged():
    (signal,) = local_signals("https://ɡmail.com/")
    assert (signal.code, signal.severity) == ("lookalike_characters", "high")
    assert signal.text == (
        "The address uses look-alike letters: ɡmail.com reads as gmail.com (written xn--mail-z7b.com)."
    )
    assert local_signals("https://café.fr/") == ()


def test_a_typo_of_a_well_known_brand_is_high_and_a_brand_used_as_a_label_is_only_a_warning():
    (typo,) = local_signals("https://amazom.com/deals")
    assert (typo.code, typo.severity) == ("lookalike_brand", "high")
    assert typo.text == "amazom.com looks like amazon.com but is a different site."
    assert codes("https://arnazon.com/") == {"lookalike_brand": "high"}
    (label,) = local_signals("https://amazon.shop/")
    assert (label.code, label.severity) == ("brand_in_address", "warn")
    assert label.text == "amazon.shop uses the name amazon but is not amazon.com."
    assert codes("https://paypalsecure.com/") == {"brand_in_address": "warn"}
    assert local_report("https://amazon.shop/").level == "unknown"
    assert local_signals("https://www.amazon.com/") == ()


def test_one_edit_from_a_four_letter_brand_is_an_ordinary_word_unless_it_reads_as_the_brand():
    for url in ("https://easy.com/", "https://room.com/", "https://nice.com/"):
        assert local_signals(url) == ()
    assert codes("https://z00m.com/") == {"lookalike_brand": "high"}


def test_a_bare_public_ip_link_is_high_and_a_private_ip_is_never_eligible_for_a_lookup():
    (signal,) = local_signals("http://8.8.8.8/login")
    assert (signal.code, signal.severity) == ("ip_address", "high")
    assert signal.text == "The link goes to a bare IP address (8.8.8.8) instead of a site name."
    assert codes("http://[2001:4860:4860::8888]/") == {"ip_address": "high"}
    assert lookup_url("http://8.8.8.8/login", "mail") == "http://8.8.8.8/login"
    for private in ("http://10.0.0.1/", "http://192.168.1.1/admin", "http://[::1]/",
                    "http://169.254.169.254/latest/meta-data/"):
        assert local_signals(private) == ()
        assert lookup_url(private, "mail") is None


def test_an_ip_in_any_spelling_a_browser_accepts_is_read_as_that_ip():
    for spelled in ("http://2130706433/", "http://0x7f.1/", "http://0177.0.0.1/", "http://127.1/"):
        report = local_report(spelled)
        assert report.host == "127.0.0.1"
        assert lookup_url(spelled, "chat") is None
    assert local_report("http://0x08.0x08.0x08.0x08/").host == "8.8.8.8"
    assert codes("http://134744072/") == {"ip_address": "high"}
    assert codes("http://999.1.1.1/") == {"unreadable": "info"}


def test_userinfo_before_the_at_sign_is_flagged_as_hiding_the_real_destination():
    (signal,) = local_signals("https://www.paypal.com@evil.example.net/login")
    assert (signal.code, signal.severity) == ("credentials_in_url", "high")
    assert signal.text == (
        'The link hides where it goes: everything before "@" is ignored, so it really opens '
        "evil.example.net."
    )
    report = local_report("https://user:secret@evil.example.net/")
    assert report.host == "evil.example.net"
    assert "secret" not in report.shown and "user" not in report.shown
    assert lookup_url("https://user:secret@evil.example.net/x", "mail") == (
        "https://evil.example.net/x"
    )


def test_a_backslash_is_a_slash_as_in_the_browser_so_the_host_is_the_one_it_opens():
    report = local_report("http://evil.example.net\\@www.paypal.com/")
    assert report.host == "evil.example.net"
    assert local_report("http:///evil.example.net/x").host == "evil.example.net"
    assert local_report("www.example.org/path").shown == "http://www.example.org/path"
    assert local_report("example.org:8080/x").shown == "http://example.org:8080/x"


def test_link_shorteners_are_noted_but_never_expanded():
    (signal,) = local_signals("https://bit.ly/3xYz")
    assert (signal.code, signal.severity) == ("shortener", "info")
    assert signal.text == (
        "The link uses a link shortener (bit.ly), which hides where it really goes."
    )
    assert codes("https://go.bit.ly/x") == {"shortener": "info"}
    assert local_report("https://bit.ly/3xYz").level == "unknown"
    assert lookup_url("https://bit.ly/3xYz", "mail") == "https://bit.ly/3xYz"


def test_a_suspicious_domain_ending_alone_is_a_warning_and_does_not_make_the_link_suspicious():
    (signal,) = local_signals("https://invoice-center.xyz/pay")
    assert (signal.code, signal.severity) == ("suspicious_tld", "warn")
    assert signal.text == (
        "The address ends in .xyz, an ending often used for throwaway scam sites."
    )
    assert local_report("https://invoice-center.xyz/pay").level == "unknown"


def test_javascript_data_vbscript_and_file_links_are_high_and_mailto_tel_sms_are_not_eligible():
    for url, scheme in (("javascript:alert(document.cookie)", "javascript"),
                        ("JaVa\tScRiPt:alert(1)", "javascript"),
                        ("data:text/html;base64,PHNjcmlwdD4=", "data"),
                        ("vbscript:msgbox(1)", "vbscript"),
                        ("file:///C:/Windows/system32", "file")):
        report = local_report(url)
        (signal,) = report.signals
        assert (signal.code, signal.severity) == ("script_link", "high")
        assert signal.text == (
            f"The link runs code or opens a local file instead of a web page ({scheme}:)."
        )
        assert report.shown == f"{scheme}:" and report.level == "suspicious"
        assert lookup_url(url, "chat") is None
    for url in ("mailto:billing@example.org", "tel:+15550100", "sms:+15550100"):
        report = local_report(url)
        assert report.signals == ()
        assert report.service_status == "not_eligible"
        assert "example" not in report.shown and "555" not in report.shown


def test_an_unreadable_link_is_only_an_info_signal():
    for url in ("[REDACTED]", "http://exa mple.com/", "http://%zz.com/", "", "http://[1::2::3]/"):
        report = local_report(url)
        assert [(s.code, s.severity) for s in report.signals] == [("unreadable", "info")]
        assert report.signals[0].text == "The link could not be read."
        assert report.host == "" and report.shown == ""
        assert lookup_url(url, "mail") is None


def test_link_text_naming_another_site_than_the_href_is_flagged_and_same_site_text_is_not():
    signal = link_text_mismatch("paypal.com", "https://paypa1-verify.xyz/login")
    assert signal == LinkSignal(
        "text_mismatch", "high",
        "The link text says paypal.com but the link goes to paypa1-verify.xyz.",
    )
    assert link_text_mismatch("https://www.paypal.com/signin", "https://evil.example.net/") is not None
    assert link_text_mismatch("Sign in at PayPal.com today", "https://evil.example.net/") is not None
    assert link_text_mismatch("www.paypal.com", "https://paypal.com/myaccount") is None
    assert link_text_mismatch("paypal.com", "https://www.paypal.com/x") is None
    report = local_report("https://paypa1-verify.xyz/login", text="paypal.com")
    assert report.signals[0].code == "lookalike_brand"
    assert {s.code for s in report.signals} >= {"text_mismatch", "lookalike_brand"}
    assert report.level == "suspicious"


def test_link_text_without_a_host_never_counts_as_a_mismatch():
    for text in ("Click here", "Download report.pdf", "Write to help@paypal.com", "3.14 percent",
                 "", "   ", "e.g. now"):
        assert link_text_mismatch(text, "https://evil.example.net/") is None
    assert link_text_mismatch("paypal.com", "javascript:alert(1)") is None


def test_outlook_safe_links_and_google_redirects_are_unwrapped_at_most_twice():
    real = "https://evil.example.net/x"
    outlook = (
        "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.net%2Fx"
        "&data=05%7C02%7Cperson%40example.org&reserved=0"
    )
    assert unwrap_redirector(outlook) == real
    assert unwrap_redirector("https://www.google.com/url?q=https://evil.example.net/x&sa=D") == real
    assert unwrap_redirector("https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example.net%2Fx") == real
    twice = "https://www.google.com/url?q=" + outlook.replace("%", "%25").replace("&", "%26")
    assert unwrap_redirector(twice) == real
    thrice = "https://www.google.com/url?q=" + twice.replace("%", "%25").replace("&", "%26")
    assert unwrap_redirector(thrice) == outlook
    assert unwrap_redirector("https://www.google.com/search?q=https://x.example.net") == (
        "https://www.google.com/search?q=https://x.example.net"
    )
    assert unwrap_redirector("https://www.google.com/url?q=javascript:alert(1)") == (
        "https://www.google.com/url?q=javascript:alert(1)"
    )
    report = local_report(outlook)
    assert report.url == outlook and report.host == "evil.example.net"
    assert lookup_url(outlook, "mail") == real


# ── what leaves the machine ────────────────────────────────────────────


def test_browser_lookups_send_only_the_scheme_and_host():
    assert lookup_url(
        "https://accounts.example.org/oauth/callback?code=abc&state=xyz#frag", "browser"
    ) == "https://accounts.example.org/"
    assert lookup_url("http://shop.example.org:8443/cart?session=1", "browser") == (
        "http://shop.example.org:8443/"
    )
    assert lookup_url("https://shop.example.org:443/x", "browser") == "https://shop.example.org/"


def test_other_lookups_drop_userinfo_fragment_and_a_query_that_carries_a_token_or_secret():
    base = "https://login.example.org/continue"
    for query in ("token=abc", "Code=123", "session=1&x=2", "sig=zz", "next=/home&state=s",
                  "ref=" + "A1b2C3d4" * 5, "u=person%40example.org", "email=person@example.org",
                  "k=ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2):
        assert lookup_url(f"{base}?{query}#section", "mail") == base
    assert lookup_url("https://u:p@login.example.org/continue#top", "chat") == base


def test_lookup_url_drops_a_path_that_carries_a_token():
    assert lookup_url("https://example.org/reset/8f3k2a9d0f8s7d6f5g4h3j2k1l", "mail") == (
        "https://example.org/"
    )
    assert lookup_url("https://example.org/s/AbCdEfGhIjKlMnOpQrStUv12/view", "chat") == (
        "https://example.org/"
    )
    secret_path = "https://example.org/hook/" + "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
    assert lookup_url(secret_path, "outbound") == "https://example.org/"
    assert lookup_url("https://example.org/blog/2026/10/post-title", "mail") == (
        "https://example.org/blog/2026/10/post-title"
    )
    assert display_url("https://example.org/reset/8f3k2a9d0f8s7d6f5g4h3j2k1l") == (
        "https://example.org/"
    )


def test_a_token_sharing_its_path_segment_with_other_characters_still_drops_the_path_from_lookups_and_cards():
    # Review of S4 (SEC-F10 follow-up): a token was only seen when it filled its whole segment.
    session = "0123456789ABCDEF" * 2
    for url, origin in (
        (f"https://shop.example.com/cart;jsessionid={session}", "https://shop.example.com/"),
        ("https://ex.example.com/verify/MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=/", "https://ex.example.com/"),
        ("https://ex.example.com/confirm/abcd+EFGH/ijkl1234mnop5678qrst==", "https://ex.example.com/"),
        ("https://ex.example.com/share/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4!", "https://ex.example.com/"),
    ):
        for purpose in ("mail", "chat", "outbound", "scam_check"):
            assert lookup_url(url, purpose) == origin, (url, purpose)
        assert display_url(url) == origin
        report = LinkReport(**{**local_report(url, service_status="listed").__dict__,
                               "threats": ("SOCIAL_ENGINEERING",), "service": "safe_browsing"})
        (note,) = security_notes([report])
        for secret in (session, "MTIzNDU2", "ijkl1234", "a1b2c3d4"):
            assert secret not in note["text"] and secret not in report.shown
    # Ordinary paths keep their path: dates, a profile, a package pin, a matrix parameter.
    for url in ("https://example.org/blog/2026/10/post-title", "https://medium.example.com/@someone/a-post",
                "https://cdn.example.net/npm/react@18.3.1/umd/react.min.js",
                "https://example.org/a;b=1/c", "https://example.org/wiki/Main_Page"):
        assert lookup_url(url, "mail") == url
        assert display_url(url) == url


def test_query_parameters_separated_by_semicolons_or_bracketed_are_checked_for_sensitive_names_too():
    base = "https://login.example.org/continue"
    for query in ("a=1;otp=123456", "a=1;code=abcd", "a=1;%73ession=x", "user[token]=x",
                  "token[]=x", "x=MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", "a=1;" + "q" * 4 + "=" + "Z9" * 16):
        assert lookup_url(f"{base}?{query}", "mail") == base, query
    for query in ("q=hello%20world;lang=en", "a=1;b=2", "q=foo+bar", "zip=12345;country=nl"):
        assert lookup_url(f"{base}?{query}", "chat") == f"{base}?{query}", query


def test_an_email_address_in_the_path_or_a_double_encoded_one_in_the_query_is_never_sent_or_shown():
    for url in ("https://ex.example.com/unsubscribe/john.doe@example.com",
                "https://ex.example.com/unsubscribe/john.doe%40example.com/confirm",
                "https://ex.example.com/u/john.doe%2540example.com"):
        for purpose in ("mail", "chat", "outbound", "scam_check"):
            assert lookup_url(url, purpose) == "https://ex.example.com/", (url, purpose)
        assert display_url(url) == "https://ex.example.com/"
    assert lookup_url("https://ex.example.com/u?to=john.doe%2540example.com", "mail") == (
        "https://ex.example.com/u"
    )
    assert lookup_url("https://ex.example.com/u?to=john.doe%252540example.com", "mail") == (
        "https://ex.example.com/u"
    )


_Input = TypeVar("_Input")


def _linear(work: Callable[[_Input], object], build: Callable[[int], _Input], size: int) -> bool:
    """scales_linearly for *work* on *build*'s input, built at *size* and at the eighth of it
    the check times it against before the clock starts."""
    inputs = {n: build(n) for n in (size // 8, size)}
    return scales_linearly(lambda n: work(inputs[n]), size)


def _reduce(url: str) -> None:
    for purpose in ("mail", "chat", "outbound", "scam_check"):
        lookup_url(url, purpose)
    display_url(url)


def test_long_links_without_padding_or_an_at_sign_are_reduced_in_linear_time():
    # The padding and e-mail rules above search the whole path: unanchored, they rescan a long
    # run from every position (about 3.5 s per call at the 32 KB input cap, over a minute for
    # this set). Each link is timed against one an eighth as long in the same process: linear
    # work grows 8x, a rescan from every position 64x.
    base = "https://example.org/"
    for build in (lambda n: base + "a" * n, lambda n: base + "a/" * (n // 2),
                  lambda n: base + "a." * (n // 2), lambda n: base + "x?q=" + "a" * n,
                  lambda n: base + "x?" + "a;" * (n // 2)):
        assert _linear(_reduce, build, 32_000), build(32_000)[:30]


def test_a_hostile_host_or_link_text_is_read_in_linear_time():
    """Python's punycode encoder is quadratic in a label's length: one link whose host was
    20,000 distinct ideographs took about 100 s, link text with many such tokens about half a
    second per token, all on the event loop. Hosts are now measured before they are encoded
    and link text is read up to a bound. Each host is timed against one an eighth as long, and
    each link text against tokens an eighth as long, in the same process: the encoder's cost
    grew 64x there, measuring grows 8x at most."""
    ideographs = "".join(chr(0x4E00 + i) for i in range(32_000))

    def many_tokens(length: int) -> str:
        return " ".join(
            "".join(chr(0x4E00 + j) for j in range(i % 50, i % 50 + length)) + ".com"
            for i in range(500)
        )

    def read_host(url: str) -> None:
        assert local_report(url).signals[0].code == "unreadable"
        assert lookup_url(url, "mail") is None and lookup_url(url, "browser") is None
        assert link_checks.host_of(url) == ""

    def names_no_other_site(text: str, href: str = "https://evil.example.net/") -> None:
        assert link_text_mismatch(text, href) is None

    # The first host outside ASCII builds the fold table once (a fifth of a second): untimed.
    local_report(f"http://{ideographs[:8]}.com/")
    for url, size in ((lambda n: f"http://{ideographs[:n]}.com/", 32_000),
                      (lambda n: "http://xn--" + "a" * n + ".com/", 32_000),
                      (lambda n: "http://" + ".".join(["ab"] * n) + ".com/", 10_000),
                      (lambda n: "http://" + "%E4%B8%80" * n + ".com/", 10_000)):
        assert _linear(read_host, url, size), url(size)[:20]
    assert _linear(names_no_other_site, many_tokens, 2_000)
    assert _linear(
        lambda text: names_no_other_site(text, "https://x.example.net/"),
        lambda n: " ".join(["a" * n + ".com"] * 2_000),
        2_000,
    )


def test_a_host_hidden_behind_characters_the_browser_drops_is_looked_up_as_the_host_it_opens():
    """A soft hyphen or a zero-width character inside a host (written as is, or as %C2%AD in an
    href) is dropped by the browser, which opens the plain host. Read as unreadable, a listed
    site would never be looked up; read as the browser reads it, it is the same lookup as the
    plain link."""
    plain = "https://evil-phish.example.com/login"
    for hidden in ("\u00ad", "%C2%AD", "\u200b", "\u2060", "\ufeff", "\u034f", "\ufe0f", "\u180b",
                   "\u200d"):
        url = f"https://ev{hidden}il-phish.example.com/login"
        report = local_report(url)
        assert report.host == "evil-phish.example.com", repr(hidden)
        assert "unreadable" not in {s.code for s in report.signals}
        for purpose in PURPOSES:
            assert lookup_url(url, purpose) == lookup_url(plain, purpose), (repr(hidden), purpose)
        assert link_checks.host_of(url) == "evil-phish.example.com"
    padded = "https://ev" + "\u00ad" * 40_000 + "il-phish.example.com/login"
    assert lookup_url(padded, "browser") == "https://evil-phish.example.com/"


def test_names_only_idna_2008_allows_are_read_and_looked_up_not_left_unreadable():
    """Python's idna codec (IDNA 2003) refuses a Hebrew name ending in digits and folds the
    sharp s to "ss"; a browser opens xn--fa-hia.de for faß.de. Both are read as the browser
    reads them, so the host Google is asked about is the one the browser opens."""
    assert lookup_url("http://faß.de/x", "mail") == "http://xn--fa-hia.de/x"
    assert lookup_url("http://xn--fa-hia.de/x", "mail") == "http://xn--fa-hia.de/x"
    hebrew = local_report("http://שלום123.com/")
    assert hebrew.host.startswith("xn--") and hebrew.host.endswith(".com")
    assert [s.code for s in hebrew.signals] == ["international_address"]
    assert lookup_url(f"http://{hebrew.host}/", "browser") == f"http://{hebrew.host}/"
    # A label a browser refuses stays unreadable: not valid punycode, or a control character.
    assert local_report("http://xn--a.com/").signals[0].code == "unreadable"


def test_an_overlong_link_is_still_read_up_to_its_host_so_padding_never_hides_the_site():
    """A browser opens a link of 100 KB; reading it as unreadable would let padding hide a
    listed site from the lookup. Past 32 KB only the host is read: it is checked and looked up
    as scheme and host, and its path and query are neither sent nor shown. Past the browser's
    own 2 MB limit nothing opens, so the link is unreadable."""
    long_path = "https://evil.example.net/" + "a" * 100_000 + "?token=" + "b" * 100_000
    report = local_report(long_path)
    assert report.host == "evil.example.net" and report.shown == "https://evil.example.net/"
    for purpose in PURPOSES:
        assert lookup_url(long_path, purpose) == "https://evil.example.net/"
    hidden_by_userinfo = "https://" + "paypal.com" * 5_000 + "@evil.example.net/x"
    assert local_report(hidden_by_userinfo).host == "evil.example.net"
    assert codes(hidden_by_userinfo)["credentials_in_url"] == "high"
    assert lookup_url(hidden_by_userinfo, "mail") == "https://evil.example.net/"
    too_long = "https://evil.example.net/" + "a" * (2 * 1024 * 1024)
    assert local_report(too_long).signals[0].code == "unreadable"
    assert lookup_url(too_long, "browser") is None


def test_link_text_with_invisible_characters_still_names_its_site():
    """The person sees "paypal.com" when the text hides a soft hyphen or a bidi control in it;
    the text check reads what they see, so the mismatch is still found."""
    for text in ("pay\u00adpal.com", "pay\u200bpal.com", "\u202apaypal.com\u202c"):
        signal = link_text_mismatch(text, "https://evil.example.net/")
        assert signal is not None and signal.code == "text_mismatch", repr(text)
        assert "paypal.com" in signal.text
    assert link_text_mismatch("paypal.com\nhelp", "https://evil.example.net/") is not None


def test_a_harmless_query_is_kept_for_mail_and_chat_lookups():
    for purpose in ("mail", "chat", "outbound", "scam_check"):
        assert lookup_url("https://news.example.org/a?id=42&lang=en", purpose) == (
            "https://news.example.org/a?id=42&lang=en"
        )


def test_non_public_hosts_are_never_sent_for_a_lookup():
    for url in ("http://localhost:3000/", "http://intranet/", "http://printer.local/",
                "http://wiki.internal/x", "http://nas.home.arpa/", "http://app.test/",
                "http://10.0.0.1/", "http://[::1]/", "http://169.254.1.1/", "http://foo.localhost/",
                "http://[::ffff:127.0.0.1]/", "http://example.invalid/"):
        for purpose in PURPOSES:
            assert lookup_url(url, purpose) is None, (url, purpose)


def test_overlong_links_are_shortened_to_path_then_host_before_a_lookup():
    query = "&".join(f"p{i}=v" for i in range(600))
    url = f"https://example.org/a/b?{query}"
    assert lookup_url(url, "mail") == "https://example.org/a/b"
    long_path = "/" + "/".join(["segment"] * 400)
    assert lookup_url(f"https://example.org{long_path}?q=1", "mail") == "https://example.org/"
    assert all(len(lookup_url(u, "mail") or "") <= 2048 for u in (url, f"https://example.org{long_path}"))


def test_paths_are_canonicalised_before_they_are_sent():
    assert lookup_url("HTTPS://Example.ORG/a/./b/../c//d%7e?x=1", "mail") == (
        "https://example.org/a/c/d~?x=1"
    )
    assert lookup_url("https://example.org/%2541", "mail") == "https://example.org/A"
    assert lookup_url("https://example.org/a b", "mail") == "https://example.org/a%20b"


def test_shown_links_never_carry_userinfo_query_fragment_or_a_long_path():
    shown = display_url("https://me:pw@Example.org/p/" + "x" * 100 + "?token=1#f")
    assert shown.startswith("https://example.org/p/") and shown.endswith("...")
    assert len(shown) <= len("https://example.org") + 60
    assert "me" not in shown.split("//", 1)[1].split("/", 1)[0].replace("example", "")
    assert "token" not in shown and "#" not in shown


# ── levels and wording ─────────────────────────────────────────────────


def test_level_is_dangerous_only_from_a_google_match_and_suspicious_only_from_a_high_signal():
    high = LinkSignal("ip_address", "high", "x")
    warn = LinkSignal("suspicious_tld", "warn", "y")
    assert level_for([], "listed") == "dangerous"
    assert level_for([high], "not_listed") == "suspicious"
    assert level_for([warn], "not_listed") == "no_known_threats"
    assert level_for([warn], "no_key") == "unknown"
    for status in ALL_STATUSES:
        if status != "listed":
            assert level_for([], status) != "dangerous"
            assert level_for([warn], status) in ("no_known_threats", "unknown")


def test_threat_words_are_hedged_and_joined():
    assert threat_words(["SOCIAL_ENGINEERING"]) == "may be phishing or a scam"
    assert threat_words(["MALWARE"]) == "may host malware"
    assert threat_words(["UNWANTED_SOFTWARE"]) == "may offer unwanted software"
    assert threat_words(["POTENTIALLY_HARMFUL_APPLICATION"]) == "may offer harmful apps"
    assert threat_words(["MALWARE", "SOCIAL_ENGINEERING"]) == (
        "may be phishing or a scam and may host malware"
    )
    assert threat_words([]) == "may be dangerous"


def _reports_for_every_level_and_status() -> list[LinkReport]:
    reports = []
    for url, status in itertools.product(
        ("https://pаypal.com/", "https://example.org/", "https://bit.ly/x", "javascript:1"),
        ALL_STATUSES,
    ):
        report = local_report(url, text="paypal.com", service_status=status)
        if status == "listed":
            report = LinkReport(**{**report.__dict__, "threats": ("MALWARE",),
                                   "service": "safe_browsing"})
        reports.append(report)
    return reports


def test_no_report_text_or_note_ever_calls_a_link_safe():
    reports = _reports_for_every_level_and_status()
    texts = [line for r in reports for line in r.reasons()]
    texts += [n["text"] for n in security_notes(reports, limit=100)]
    texts += [coverage_note([r]) or "" for r in reports]
    texts += [model_safe_text(s) for r in reports for s in r.signals]
    assert texts
    for text in texts:
        lowered = text.lower()
        assert "safe" not in lowered.replace("safe browsing", ""), text
        assert "harmless" not in lowered and "trusted" not in lowered, text


def test_reasons_put_googles_advisory_first_then_high_warn_and_info():
    report = local_report("https://paypa1-verify.xyz/login", service_status="listed")
    report = LinkReport(**{**report.__dict__, "threats": ("SOCIAL_ENGINEERING",),
                           "service": "web_risk"})
    assert report.reasons() == (
        "Google Web Risk says this site may be phishing or a scam (advisory provided by Google).",
        "paypa1-verify.xyz looks like paypal.com but is a different site.",
        "The address ends in .xyz, an ending often used for throwaway scam sites.",
    )


def test_security_notes_are_capped_aggregate_not_checked_and_name_hosts_never_queries():
    listed = local_report("https://paypa1-verify.xyz/login?token=abc&user=me", service_status="listed")
    listed = LinkReport(**{**listed.__dict__, "threats": ("SOCIAL_ENGINEERING",),
                           "service": "safe_browsing"})
    mismatch = local_report("https://evil.example.net/", text="paypal.com",
                            service_status="not_listed")
    suspicious = [local_report(f"http://8.8.8.{i}/?session=s{i}") for i in range(1, 5)]
    not_checked = local_report("https://example.org/a", service_status="rate_limited")
    plain = local_report("https://bit.ly/x", service_status="not_listed")
    notes = security_notes([plain, *suspicious, mismatch, listed, not_checked, listed])
    assert notes[0] == {
        "kind": "link_dangerous", "severity": "high",
        "text": "Link check: paypa1-verify.xyz/login - Google Safe Browsing says this site may be "
                "phishing or a scam (advisory provided by Google).",
    }
    assert notes[1] == {
        "kind": "link_suspicious", "severity": "warn",
        "text": "Link check: the link goes to a bare IP address (8.8.8.1) instead of a site name.",
    }
    assert notes[3] == {"kind": "link_suspicious", "severity": "warn",
                        "text": "And 3 more links were flagged."}
    assert notes[4] == {
        "kind": "link_not_checked", "severity": "info",
        "text": "Some links were not checked with Google (the lookup limit was reached).",
    }
    assert len(notes) == 5
    assert sum(1 for n in notes if n["kind"] == "link_not_checked") == 1
    for note in notes:
        assert "token" not in note["text"] and "session" not in note["text"]
        assert "?" not in note["text"] and "user=me" not in note["text"]
    assert {n["severity"] for n in notes} <= {"high", "warn", "info"}
    assert security_notes([plain]) == []
    assert security_notes([local_report("https://example.org/", service_status="no_key")]) == []


def test_the_text_mismatch_note_reads_as_the_cards_show_it():
    report = local_report("https://paypa1-verify.xyz/", text="paypal.com")
    report = LinkReport(**{**report.__dict__, "signals": tuple(
        s for s in report.signals if s.code == "text_mismatch")})
    (note,) = security_notes([report])
    assert note["text"] == (
        "Link check: the link text says paypal.com but the link goes to paypa1-verify.xyz."
    )


def test_signal_texts_never_quote_a_query_userinfo_or_fragment():
    urls = [
        "https://alice:hunter2@pаypal.com/x?token=SECRETVALUE#FRAGMENT",
        "https://alice:hunter2@8.8.8.8/x?token=SECRETVALUE#FRAGMENT",
        "https://alice:hunter2@bit.ly/x?token=SECRETVALUE#FRAGMENT",
        "https://alice:hunter2@amazom.xyz/x?token=SECRETVALUE#FRAGMENT",
        "https://alice:hunter2@amazon.shop/x?token=SECRETVALUE#FRAGMENT",
    ]
    for url in urls:
        report = local_report(url, text="see paypal.com?token=SECRETVALUE")
        for text in (*report.reasons(), report.shown, *(n["text"] for n in security_notes([report]))):
            for secret in ("hunter2", "alice", "SECRETVALUE", "FRAGMENT", "token"):
                assert secret not in text, (url, text)


def test_coverage_note_appears_only_when_links_were_checked_locally():
    def at(*statuses):
        return [local_report("https://example.org/", service_status=s) for s in statuses]

    assert coverage_note(at("not_listed", "listed", "not_eligible")) is None
    assert coverage_note([]) is None
    assert coverage_note(at("not_eligible")) is None
    assert coverage_note(at("no_key")) == (
        "Links were checked on this computer only. Add a Google Safe Browsing or Web Risk key in "
        "Security → Service keys to also check them against Google's list of dangerous sites."
    )
    assert "turned off" in (coverage_note(at("off")) or "")
    assert coverage_note(at("not_listed", "timeout")) == (
        "Some links were checked on this computer only (Google did not answer in time)."
    )
    assert coverage_note(at("cache_miss")) is not None


def test_model_safe_text_names_look_alike_hosts_in_punycode_only():
    (look,) = local_signals("https://pаypal.com/")
    assert model_safe_text(look) == (
        "The address uses look-alike letters: xn--pypal-4ve.com reads as paypal.com."
    )
    (intl,) = local_signals("https://пример.рф/")
    assert model_safe_text(intl) == "The address uses non-Latin letters (written xn--e1afmkfd.xn--p1ai)."
    other = LinkSignal("text_mismatch", "high", "The link text says pаypal.com but goes elsewhere.")
    assert model_safe_text(other).isascii()
    assert "xn--pypal-4ve.com" in model_safe_text(other)
    guard = PromptGuard()
    for signal in (look, intl, other):
        assert not [d for d in guard.scan(model_safe_text(signal)).detections
                    if d.pattern_name == "homoglyph_mixed_script"]


def test_every_signal_code_used_is_a_declared_one_and_not_checked_statuses_are_failures():
    urls = ("https://pаypal.com/", "https://пример.рф/", "https://amazom.com/", "https://amazon.shop/",
            "http://8.8.8.8/", "http://u@x.example.org/", "https://bit.ly/x", "https://a.xyz/",
            "javascript:1", "[x]")
    used = {s.code for u in urls for s in local_signals(u)}
    used.add(link_text_mismatch("paypal.com", "https://x.example.org/").code)
    assert used == SIGNAL_CODES
    assert NOT_CHECKED_STATUSES <= set(ALL_STATUSES)
    assert not NOT_CHECKED_STATUSES & {"listed", "not_listed", "no_key", "off", "not_eligible"}


@pytest.mark.asyncio
async def test_the_local_only_checker_answers_no_key_and_never_touches_the_network(monkeypatch):
    import httpx
    import socket

    def refuse(*_a, **_k):
        raise AssertionError("the local checker reached the network")

    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    checker = LocalOnlyLinkChecker()
    urls = ["https://pаypal.com/", "https://example.org/", "https://example.org/"]
    reports = await checker.check(urls, purpose="mail", texts={"https://example.org/": "x.com"})
    assert [r.url for r in reports] == urls
    assert [r.service_status for r in reports] == ["no_key"] * 3
    assert reports[1].signals[0].code == "text_mismatch"
    assert checker.check_local("https://amazom.com/").level == "suspicious"
    assert checker.cached_report("https://example.org/", purpose="chat") is None
    assert await checker.remote_configured() is False
    for name in ("check", "check_local", "cached_report", "remote_configured"):
        assert callable(getattr(checker, name)) and hasattr(link_checks.LinkChecker, name)


def test_nothing_here_raises_on_hostile_input():
    hostile = [None, 42, "", " ", "http://", "http://:80", "https://[", "http://a:99999/",
               "http://" + "a." * 200 + "com", "x" * 40_000, "http://ex%00ample.com/",
               "\u202ehttps://evil.example.net", "https://evil.example.net/\u0000"]
    for value in hostile:
        report = local_report(value)  # type: ignore[arg-type]
        assert report.level in ("unknown", "suspicious")
        for purpose in PURPOSES:
            lookup_url(value, purpose)  # type: ignore[arg-type]
        link_text_mismatch("paypal.com", value)  # type: ignore[arg-type]


def test_digits_from_other_scripts_never_make_an_ip_address():
    # A browser reads Arabic-Indic digits as an international name, not as 127.0.0.1.
    report = local_report("http://١٢٧.٠.٠.١/")
    assert report.host != "127.0.0.1"
    assert local_report("http://１２７.０.０.１/").host == "127.0.0.1"   # full-width folds (NFKC)
    # A port must be ASCII digits to a browser too; anything else is not a link it opens.
    assert local_report("http://example.org:８０/").signals[0].code == "unreadable"


def test_host_of_names_the_host_the_browser_really_opens():
    assert link_checks.host_of(r"https://evil.example.net\@accounts.google.com/") == "evil.example.net"
    assert link_checks.host_of("https://user@accounts.google.com/") == "accounts.google.com"
    assert link_checks.host_of("https://pаypal.com/") == "xn--pypal-4ve.com"
    assert link_checks.host_of("http://[2001:db8::1]:8080/") == "[2001:db8::1]"
    assert link_checks.host_of("https://www.google.com/url?q=https://evil.example.net/") == (
        "www.google.com"
    )
    assert link_checks.host_of("javascript:alert(1)") == ""
    assert link_checks.host_of("[REDACTED]") == ""


def test_the_browser_looks_up_the_host_it_opens_and_other_purposes_the_wrapped_destination():
    wrapped = "https://www.google.com/url?q=https://evil.example.net/x"
    assert lookup_url(wrapped, "browser") == "https://www.google.com/"
    assert lookup_url(wrapped, "mail") == "https://evil.example.net/x"


# ── review fixes: hostile numbers, ports and hosts ─────────────────────


def _public_calls(url: object, text: str = "paypal.com") -> None:
    """Every public function that takes a link, on *url*: none may raise."""
    local_report(url, text=text)  # type: ignore[arg-type]
    local_signals(url)  # type: ignore[arg-type]
    display_url(url)  # type: ignore[arg-type]
    link_checks.host_of(url)  # type: ignore[arg-type]
    unwrap_redirector(url)  # type: ignore[arg-type]
    link_text_mismatch(text, url)  # type: ignore[arg-type]
    link_text_mismatch(url, "https://example.org/")  # type: ignore[arg-type]
    LocalOnlyLinkChecker().check_local(url, text=text)  # type: ignore[arg-type]
    for purpose in PURPOSES:
        lookup_url(url, purpose)  # type: ignore[arg-type]


def test_ipv4_parts_hold_only_the_digits_a_browser_reads_and_never_raise():
    """Review of S4: int() accepts a sign, "_" and spaces, so "http://-1.0.0.1/" built a
    negative address and raised AddressValueError out of local_report, lookup_url, display_url,
    host_of and unwrap_redirector, and "1_0.0.0.1" read as 10.0.0.1 although a browser refuses
    both. A part now holds only its base's ASCII digits, as the URL standard's parser reads it."""
    for url in ("http://-1.0.0.1/", "http://+1.0.0.1/", "http://1_0.0.0.1/", "http:// 1.0.0.1/",
                "http://0x-1.0.0.1/", "http://0x+f.0.0.1/", "http://08.0.0.1/", "http://1..1/",
                "http://1.0.0.1.1/", "http://4294967296/", "http://0x100000000/",
                "http://040000000000/", "http://256.0.0.1/"):
        _public_calls(url)
        report = local_report(url)
        assert [s.code for s in report.signals] == ["unreadable"], url
        assert link_checks.host_of(url) == "" and display_url(url) == ""
        assert all(lookup_url(url, purpose) is None for purpose in PURPOSES)
    # The largest address in each base is still read (the bounds are not one short).
    for url in ("http://4294967295/", "http://0xffffffff/", "http://037777777777/",
                "http://0xFF.0377.65535/"):
        assert local_report(url).host == "255.255.255.255", url


def test_a_zero_padded_address_is_the_address_the_browser_opens_and_a_huge_part_never_raises():
    """A browser reads leading zeros as octal (or as nothing after "0x"), so
    "1.2.3.0000...04" opens 1.2.3.4 whatever the padding: it is read as that address (a bare
    IP, looked up), never left unreadable because the host is long. A part too large for any
    address is refused before int() runs, so thousands of digits never meet its digit limit,
    and each huge part is read in linear time (timed against one an eighth as long in the same
    process, where converting it grows with the square of its digits)."""
    padded = "http://1.2.3." + "0" * 5_000 + "4/x"
    assert local_report(padded).host == "1.2.3.4"
    assert codes(padded) == {"ip_address": "high"}
    assert lookup_url(padded, "browser") == "http://1.2.3.4/"
    assert lookup_url(padded, "mail") == "http://1.2.3.4/x"
    assert local_report("http://0x" + "0" * 5_000 + "8.8.8.8/").host == "8.8.8.8"

    def refused(huge: str) -> None:
        _public_calls(huge)
        assert codes(huge) == {"unreadable": "info"}

    for huge, size in ((lambda n: "http://1.1.1." + "9" * n + "/", 5_000),
                       (lambda n: "http://0x" + "f" * n + "/", 5_000),
                       (lambda n: "http://0" + "7" * n + "/", 5_000),
                       (lambda n: "http://" + "9" * n + "/", 30_000)):
        assert _linear(refused, huge, size), huge(size)[:20]


def test_a_zero_padded_port_is_the_port_a_browser_opens_and_an_overlong_one_never_raises():
    """Review of S4: int() of a port of more than 4,300 digits raises (Python's digit limit),
    so "https://listed.example.org:000...0443/login", which a browser opens, raised out of every
    function and a listed site behind it was never looked up. Leading zeros are dropped and
    more than five digits refused before int() runs."""
    padded = "https://listed.example.org:" + "0" * 5_000 + "443/login"
    _public_calls(padded)
    report = local_report(padded)
    assert report.host == "listed.example.org" and report.signals == ()
    assert report.shown == "https://listed.example.org/login"
    assert lookup_url(padded, "mail") == "https://listed.example.org/login"
    assert lookup_url(padded, "browser") == "https://listed.example.org/"
    assert local_report("http://example.org:0008080/x").shown == "http://example.org:8080/x"
    assert local_report("http://example.org:65535/").shown == "http://example.org:65535/"
    for url in ("https://listed.example.org:" + "9" * 5_000 + "/login",
                "http://example.org:" + "0" * 5_000 + "65536/", "http://example.org:65536/",
                "http://example.org:-1/", "http://example.org:+80/", "http://example.org:8_0/",
                "http://example.org: 80/"):
        _public_calls(url)
        assert codes(url) == {"unreadable": "info"}, url
        assert lookup_url(url, "mail") is None and link_checks.host_of(url) == ""


def test_link_text_that_cannot_be_read_never_costs_the_link_its_own_findings(monkeypatch):
    """Review of S4: link text is written by whoever sent the message, and text such as
    "http://-1.0.0.1" raised inside the text check, which took the whole report with it: the
    href's credentials and look-alike findings were lost and "suspicious" became "unknown". A
    text token that cannot be read now names no host, and the link keeps its own findings."""
    href = "http://user@pаypal.com/login"
    for text in ("http://-1.0.0.1", "http://-1.0.0.1/", "https://listed.example.org:" + "9" * 2_000,
                 "https://[1::2::3]/", "http://x^y.example.org/"):
        assert link_text_mismatch(text, href) is None
        report = local_report(href, text=text)
        assert {"credentials_in_url", "lookalike_characters"} <= {s.code for s in report.signals}
        assert report.level == "suspicious"
    # A readable host next to a hostile token is still compared.
    mixed = local_report(href, text="http://-1.0.0.1 or paypal.com")
    assert "text_mismatch" in {s.code for s in mixed.signals}

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("internal")

    # Even a text check that breaks outright adds nothing and takes nothing away.
    monkeypatch.setattr(link_checks, "_text_hosts", boom)
    assert link_text_mismatch("paypal.com", href) is None
    assert local_report(href, text="paypal.com").level == "suspicious"


def test_a_host_with_characters_the_url_standard_allows_is_read_and_its_dns_ancestor_looked_up():
    """Review of S4: a host label only allowed a-z, 0-9, "_" and "-", so
    "https://x$y.listed.example.org/" (which the URL standard accepts, and a browser opens) was
    unreadable and never looked up, while Google lists listed.example.org and matches its
    subdomains. Every character the standard allows is now read; the lookup names the nearest
    ancestor made of DNS labels (host and scheme only, for every purpose)."""
    for char in "!$&'()*+,;=~\"`{}":
        url = f"https://X{char}y.listed.example.org/login?page=2"
        report = local_report(url)
        assert report.host == f"x{char}y.listed.example.org", char
        assert report.shown == f"https://x{char}y.listed.example.org/login"
        assert report.signals == ()
        for purpose in PURPOSES:
            assert lookup_url(url, purpose) == "https://listed.example.org/", (char, purpose)
    assert lookup_url("https://a$b.c!d.shop.example.co.uk:8443/x", "mail") == (
        "https://shop.example.co.uk:8443/"
    )
    assert link_checks.host_of("https://x$y.accounts.google.com/") == "x$y.accounts.google.com"
    assert codes("http://u@x$y.listed.example.xyz/") == {
        "credentials_in_url": "high", "suspicious_tld": "warn",
    }
    # A forbidden code point (written, or percent-encoded) is a link the browser refuses.
    for url in ("http://x^y.example.org/", "http://x|y.example.org/", "http://x%2Fy.example.org/",
                "http://x%25y.example.org/", "http://x%3Cy.example.org/",
                "http://x\x7fy.example.org/", "http://x＾y.example.org/"):
        assert codes(url) == {"unreadable": "info"}, url
    # No public name is spelled with one in its registrable domain: nothing to look up.
    for url in ("http://pay$pal.com/", "http://evil.co$/", "http://x$y.co.uk/"):
        assert codes(url) == {"unreadable": "info"}, url
        assert lookup_url(url, "browser") is None
    # And a non-public ancestor is never sent.
    assert lookup_url("http://x$y.printer.local/", "mail") is None
    assert lookup_url("http://x$y.corp.internal/", "browser") is None


def test_userinfo_a_browser_accepts_is_cut_off_where_the_browser_cuts_it():
    """Found while fixing the review: urllib refuses "user[@host" and a full-width "/" (or
    U+2100, which NFKC folds to "a/c") before the "@", so those links were unreadable and never
    looked up, while a browser opens the host after the last "@". Links are now split the way
    the URL standard splits them, and a backslash is a slash in the path but not in the query."""
    for url in ("http://user[@listed.example.org/x", "http://evil.com／@listed.example.org/x",
                "http://a]b@listed.example.org/x", "http://evil.com℀@listed.example.org/x",
                "http://a@b@listed.example.org/x"):
        report = local_report(url)
        assert report.host == "listed.example.org", url
        assert codes(url) == {"credentials_in_url": "high"}
        assert lookup_url(url, "browser") == "http://listed.example.org/"
    assert lookup_url("https://example.org/a\\b?q=a\\b#f", "mail") == (
        "https://example.org/a/b?q=a\\b"
    )
    assert local_report("https:\\\\example.org\\x").shown == "https://example.org/x"


def test_a_check_that_breaks_on_a_link_reports_it_unreadable_and_keeps_every_other_finding(
    monkeypatch,
):
    """Defence in depth behind the bounded parsing: whatever step breaks on a link, the
    public functions answer instead of raising, a broken step adds the "unreadable" signal
    instead of silently dropping the other findings, and a lookup falls back to sending less
    (the host only) rather than nothing."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("internal")

    monkeypatch.setattr(link_checks, "_lookalike_signals", boom)
    assert codes("http://user@evil.example.xyz/") == {
        "credentials_in_url": "high", "suspicious_tld": "warn", "unreadable": "info",
    }
    monkeypatch.setattr(link_checks, "_private_path", boom)
    assert lookup_url("https://example.org/a?b=1", "mail") == "https://example.org/"
    assert display_url("https://example.org/a") == "https://example.org/"
    monkeypatch.setattr(link_checks, "_parse_unguarded", boom)
    _public_calls("https://example.org/")
    report = local_report("https://example.org/", text="paypal.com")
    assert [s.code for s in report.signals] == ["unreadable"] and report.level == "unknown"
    assert link_checks.host_of("https://example.org/") == ""
    wrapped = "https://www.google.com/url?q=https://evil.example.net/"
    assert unwrap_redirector(wrapped) == wrapped
    assert link_checks.unreadable_report("x").signals == report.signals


def test_no_public_function_raises_on_a_fuzzed_mix_of_hostile_link_parts():
    """A seeded fuzz over the parts the review's probes combined (signed, padded and huge
    numbers, every host character, hostile userinfo and ports), assembled as scheme, userinfo,
    host labels, port and tail: nothing raises, and reading the links is linear in the length of
    their long parts. (Against the code the review checked, this raised within the first few
    dozen.)"""
    import random

    schemes = ["http://", "https://", "HTTP:\\\\", "//", "", "https:"]
    userinfo = ["", "", "user@", "user[@", "a]b@", "evil.com／@", "x℀@", "@", "a@b@"]
    tails = ["", "/", "/x?q=1", "\\a\\b", "?q=" + "%25" * 10, "#f", "/@x", "?u=a%40b.com"]

    def fuzzed(size: int) -> list[str]:
        """The same 1,500 links at every *size*: only the long parts are longer or shorter."""
        labels = ["-1", "+1", "1_0", " 1", "0x", "0xff", "0x-f", "08", "0377", "1", "255", "4294967296",
                  "0" * size + "1", "9" * size, "f" * 40, "x$y", "a!b~c", "x^y", "x|y", "", "%2D1",
                  "%C2%AD", "%E2%80%8B", "%zz", "１", "١", "xn--", "xn--p1ai", "pаypal",
                  "example", "org", "com", "。", "[::1]", "[1::2::3]"]
        ports = ["", "", "", ":", ":0", ":443", ":65536", ":" + "0" * size + "443", ":" + "9" * size,
                 ":-1", ":+80", ":８０", ":8_0"]
        rng = random.Random(20261021)
        urls = []
        for _ in range(1_500):
            host = ".".join(rng.choice(labels) for _ in range(rng.randint(1, 5)))
            urls.append(rng.choice(schemes) + rng.choice(userinfo) + host + rng.choice(ports)
                        + rng.choice(tails))
        return urls

    def call_everything(urls: list[str]) -> None:
        for url in urls:
            _public_calls(url, text=url)
            _public_calls("https://www.google.com/url?q=" + url)

    links = fuzzed(5_000)
    call_everything(links)
    # Timed where the long parts are: the 50 longest links (the 39 with two or three long parts,
    # and 11 with one) against the same links with those parts an eighth as long, in the same
    # process. Linear reading grows 8x at most, a part rescanned from every
    # position 64x. Timing the whole fuzz would mostly time the fixed cost of 3,000 short calls,
    # which hides even a large slowdown in the long ones.
    longest = sorted(range(len(links)), key=lambda index: len(links[index]))[-50:]

    def longest_at(size: int) -> list[str]:
        built = fuzzed(size)
        return [built[index] for index in longest]

    assert _linear(call_everything, longest_at, 5_000)


def test_a_host_is_read_and_looked_up_as_the_browser_folds_it_never_as_another_host():
    """Review of S4 (batch 2): the parser lower-cased hosts, so a Cyrillic host spelled with the
    Extended-C letters was looked up as a host nobody opens, and the Cherokee ACE form Chromium
    hands the guard was unreadable and never looked up. Each is now read as the host the
    browser opens (as the Chromium Playwright runs writes it) and that host is what leaves."""
    es = chr(0x1C83)
    assert lookup_url("https://" + es * 2 + ".com/login", "mail") == "https://xn--q1aa.com/login"
    report = local_report("https://xn--g9da0d5gqac.com/")
    assert "unreadable" not in {s.code for s in report.signals}
    assert report.host == "xn--g9da0d5gqac.com"
    for purpose in PURPOSES:
        assert lookup_url("https://xn--g9da0d5gqac.com/", purpose) == "https://xn--g9da0d5gqac.com/"
    outlined = "".join(chr(0x1CCD6 + "abcdefghijklmnopqrstuvwxyz".index(ch)) for ch in "paypal")
    assert lookup_url("https://" + outlined + ".com/signin", "mail") == "https://paypal.com/signin"
    assert local_report("https://" + outlined + ".com/").host == "paypal.com"
    persian = "".join(map(chr, (0x645, 0x6CC, 0x200C, 0x62E, 0x648, 0x627, 0x647, 0x645)))
    assert lookup_url("https://" + persian + ".com/", "browser") == "https://xn--mgbn2ecje63gr19l.com/"
    hidden = "https://pay" + chr(0x3164) + "pal.com/login"
    assert lookup_url(hidden, "chat") == "https://paypal.com/login"
