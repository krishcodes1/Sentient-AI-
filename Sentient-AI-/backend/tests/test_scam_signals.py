"""Tests for the scam check's local pass (services/security/scam_signals.py): links are found
with and without a scheme but never e-mail addresses or file names; hidden tag characters and
text-direction controls are strong signs while joiners inside emoji and Persian words are not
counted; the wording patterns catch password, code and odd-payment requests and leave a
newsletter, an invite and a friend's text alone; Markdown, HTML and Slack links give their
label and real address; hosts are shown in punycode; a reason the AI wrote is dropped when it
holds a link, a domain, an address or a phone number; and every pattern stays fast on a
megabyte of its worst case.

Why it exists: these checks run on every scam check with no network and no model, and their
sentences are what a person reads first. A sentence that quoted the message, or showed a
look-alike host as written, would carry the scam into Crawler's own answer.

Non-ASCII test data is written as \\u escapes (this file runs in the Windows CI job).
"""

from __future__ import annotations

import time

import pytest

from services.agent.prompt_guard import _HOMOGLYPH_MAP, _INVISIBLE_CHARS
from services.security import scam_signals as sig
from services.security.scam_signals import (
    MAX_TEXT_CHARS,
    MAX_URLS,
    SIGNAL_SENTENCES,
    SIGNAL_STRENGTHS,
    analyse_text,
    anchor_pairs,
    ascii_host,
    clean_ai_reason,
    display_url,
    extract_urls,
    hidden_character_signals,
    language_signals,
)

CYRILLIC_A = "\u0430"
PAYPAL_LOOKALIKE = f"p{CYRILLIC_A}ypal.com"  # "paypal.com" with a Cyrillic a
TAG_HELLO = "".join(chr(0xE0000 + ord(c)) for c in "hello")
RLO = "\u202e"
ZWSP = "\u200b"
ZWJ = "\u200d"
ZWNJ = "\u200c"


def codes(signals) -> list[str]:
    return [s.code for s in signals]


def test_urls_are_found_with_and_without_a_scheme_and_file_names_and_email_addresses_are_not():
    text = (
        "Open https://paypa1-secure.com/login?id=7 or www.example.org/help, then "
        "paypal-secure.help and bit.ly/3xYz. Mail help@x.example, read report.pdf and "
        "setup.zip, see e.g. version 1.2 at 10.30am."
    )
    assert extract_urls(text) == [
        "https://paypa1-secure.com/login?id=7",
        "http://www.example.org/help",
        "http://paypal-secure.help",
        "http://bit.ly/3xYz",
    ]
    # A file extension with a path after it is a link after all; a link in brackets loses them.
    assert extract_urls("get it at files.zip/download (see https://x.example/a_(b)).") == [
        "http://files.zip/download",
        "https://x.example/a_(b)",
    ]
    # Look-alike letters are still a link, written as given.
    assert extract_urls(f"Log in at {PAYPAL_LOOKALIKE}/signin now") == [f"http://{PAYPAL_LOOKALIKE}/signin"]
    # A link glued to a word or a colon is split off it.
    assert extract_urls("visit:https://evil.example/x") == ["https://evil.example/x"]
    assert extract_urls("first.last@company.com wrote: ok") == []


def test_at_most_ten_urls_come_back_in_the_order_they_appear_without_duplicates():
    links = [f"https://site{i}.example/p" for i in range(15)]
    text = " ".join(links[:3] + [links[0].upper().replace("HTTPS", "https")] + links[3:])
    found = extract_urls(text)
    assert found == links[:MAX_URLS]
    findings = analyse_text(" ".join(links))
    assert findings.urls == tuple(links[:MAX_URLS]) and findings.more_urls is True
    assert analyse_text(" ".join(links[:4])).more_urls is False


def test_tag_characters_and_bidi_overrides_are_strong_signals_with_their_counts():
    found = hidden_character_signals(f"Invoice{TAG_HELLO} for file {RLO}fdp.exe and {RLO}x")
    by_code = {s.code: s for s in found}
    assert by_code["hidden_tags"].strength == "strong" and by_code["hidden_tags"].count == 5
    assert by_code["hidden_tags"].text == "It hides 5 invisible tag characters, a trick to smuggle hidden text."
    assert by_code["bidi_override"].strength == "strong" and by_code["bidi_override"].count == 2
    assert "invisible_chars" not in by_code
    # Three other invisible characters are a weak sign; two are not.
    assert codes(hidden_character_signals(f"pay{ZWSP}pal ver{ZWSP}ify ac{ZWSP}count")) == ["invisible_chars"]
    assert hidden_character_signals(f"pay{ZWSP}pal ver{ZWSP}ify") == []
    # One override alone is still counted, in the singular.
    (one,) = hidden_character_signals(f"photo{RLO}gnp.exe")
    assert one.text == "It uses 1 text-direction control character that can disguise a link or file name."


def test_joiners_inside_emoji_and_persian_words_are_not_counted_as_invisible_characters():
    family = f"\U0001f468{ZWJ}\U0001f469{ZWJ}\U0001f467{ZWJ}\U0001f466"
    technologist = f"\U0001f469\U0001f3fd{ZWJ}\U0001f4bb"
    persian = f"\u0645\u06cc{ZWNJ}\u062e\u0648\u0627\u0647\u0645 \u0646\u0645\u06cc{ZWNJ}\u062f\u0627\u0646\u0645"
    devanagari = f"\u0915\u094d{ZWJ}\u0937 \u0915\u094d{ZWNJ}\u0937"
    scotland = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbsct") + "\U000e007f"
    # A phone wraps a name in a first-strong isolate and its pop when the text is copied.
    copied_name = "\u2068Sam\u2069 sent you \u2068Ana\u2069's number"
    hebrew = "\u05e9\u05dc\u05d5\u05dd\u200f 123 \u200e\u05e2\u05d5\u05d3\u200f"
    text = " ".join([family, technologist, persian, devanagari, scotland, copied_name, hebrew])
    assert hidden_character_signals(text) == []
    # The same joiners between Latin letters are hidden splices.
    assert codes(hidden_character_signals(f"pa{ZWJ}y pa{ZWNJ}l ac{ZWJ}count")) == ["invisible_chars"]
    # An isolate that is never closed is an override.
    assert codes(hidden_character_signals("\u2068report.pdf")) == ["bidi_override"]


def test_password_and_code_requests_are_strong_and_a_deadline_alone_is_weak():
    asks = {
        "Please confirm your details to restore access.": "credential_ask",
        "Sign in to restore your account.": "credential_ask",
        "Reply with your password so we can fix it.": "credential_ask",
        "Send me the 6-digit code we just texted you.": "code_ask",
        "Can you read me the code that we sent to your phone? Send it to me now": "code_ask",
        "Tell us your verification code to finish.": "code_ask",
        "Enter your card number and CVV below.": "financial_ask",
        "Update your billing information today.": "financial_ask",
    }
    for text, code in asks.items():
        found = language_signals(text)
        assert code in codes(found), text
        assert all(s.strength == "strong" for s in found if s.code == code)
    (deadline,) = language_signals("Please respond within 24 hours.")
    assert deadline.code == "urgent_pressure" and deadline.strength == "weak"
    assert codes(language_signals("Your account has been suspended.")) == ["urgent_pressure"]


def test_a_warning_never_to_share_a_code_is_not_an_ask_but_an_if_you_dont_threat_is():
    bank_sms = (
        "Your verification code is 482913. Do not share your OTP with anyone. "
        "We will never ask you to verify your account by text."
    )
    assert language_signals(bank_sms) == []
    threat = "If you don't verify your account, it will be closed today."
    assert "credential_ask" in codes(language_signals(threat))


def test_a_negation_in_the_sentence_before_never_switches_off_the_ask_in_the_last_sentence():
    # Checker finding: the two-sentence window was joined with a plain space, so a "not" at the
    # end of one sentence read as negating an ask that opens the next one.
    cases = {
        "We could not process your payment. Update your billing information.": "financial_ask",
        "Do not reply. Verify your account now.": "credential_ask",
        "We noticed a sign-in we don't recognise. Confirm your identity.": "credential_ask",
        "This is not spam. Confirm your password here.": "credential_ask",
        "Your PayPal account is limited and we can't let you pay. Confirm your details within 24 hours.": (
            "credential_ask"
        ),
        "Don't worry. Send me the 6-digit code we just texted you.": "code_ask",
    }
    for text, code in cases.items():
        assert code in codes(language_signals(text)), text
        # The same ask is found whether or not another sentence follows it.
        assert code in codes(language_signals(text + " Thanks.")), text
    # A negation in the ask's own clause is still a warning, not an ask.
    assert "credential_ask" not in codes(language_signals("Hello. We will never ask you to verify your account."))
    # No single pattern reads across the sentence end: "verify." then "Your account ..." is no ask.
    assert "credential_ask" not in codes(language_signals("Thanks, we could verify. Your account is fine."))


def test_code_asks_follow_the_spec_pattern_for_send_me_the_code_and_the_code_we_sent_you():
    # Checker finding: code_ask needed a qualifier ("6-digit", "verification") before "code",
    # so the classic account-takeover asks of S3 4.6's own pattern were missed.
    for text in (
        "Send me the code",
        "Please share the code we sent you",
        "Can you send me the code that was just sent to you?",
        "Read us the code, quick.",
        "Give me your code so I can finish the transfer.",
        "Please share your code with the agent.",
        "Forward the code you just received.",
    ):
        found = language_signals(text)
        assert "code_ask" in codes(found), text
        assert next(s for s in found if s.code == "code_ask").strength == "strong"
    # Where "code" is plainly something else, or the ask is a warning, it is no code ask.
    for text in (
        "Can you share the code for the login page on GitHub?",
        "Send me the code of conduct before Friday.",
        "Buy four gift cards. Send me the codes.",
        "Never share the code we sent you.",
        "Use code HOLIDAY10 at checkout.",
    ):
        assert "code_ask" not in codes(language_signals(text)), text


def test_gift_card_crypto_and_wire_requests_are_strong_payment_signals():
    for text in (
        "Pay the fine in Google Play gift cards before noon.",
        "Buy four Apple gift cards for the client. Send me the codes on the back.",
        "Send the money by Bitcoin ATM to settle the account.",
        "The fee must be paid by wire transfer or Western Union.",
        "Deposit USDT to this wallet to release your payment.",
    ):
        found = language_signals(text)
        assert "payment_odd" in codes(found), text
        assert next(s for s in found if s.code == "payment_odd").strength == "strong"
    # A shop's gift-card advert with a promo code is not a payment trick.
    assert "payment_odd" not in codes(language_signals("Gift cards make a great present. Use code HOLIDAY10 at checkout."))


def test_other_wording_tricks_each_raise_their_own_weak_or_strong_sign():
    cases = {
        "Install AnyDesk and give me the access code so I can fix your PC.": "remote_access",
        "Download the attached .apk file and install it.": "remote_access",
        "Congratulations, you have won an iPhone! Claim your prize now.": "prize_or_refund",
        "A warrant for your arrest has been issued; legal action follows.": "threat",
        "Your package is on hold. Pay the $1.99 redelivery fee to release it.": "delivery_fee",
        "Keep this between us and don't tell your bank.": "secrecy",
        "Guaranteed returns of 300% profits every week, risk-free investment.": "too_good",
    }
    for text, code in cases.items():
        found = language_signals(text)
        assert code in codes(found), text
        assert next(s for s in found if s.code == code).strength == SIGNAL_STRENGTHS[code]


def test_wording_is_read_through_look_alike_letters_curly_quotes_and_invisible_splices():
    disguised = f"V\u0435rify y{ZWSP}our acc\u043eunt. If you don\u2019t, it will be closed."
    assert "credential_ask" in codes(language_signals(disguised))


def test_a_newsletter_a_calendar_invite_and_a_friends_text_raise_no_signal():
    newsletter = (
        "This week in the garden: our spring planting guide, ten tomato varieties to try, and "
        "a recipe for basil pesto. Shop seeds at https://shop.example.com/seeds. You can "
        "unsubscribe at any time from your preferences page."
    )
    invite = (
        "Invitation: Team sync @ Thu 3pm - 3:30pm. Join with Google Meet: "
        "https://meet.google.com/abc-defg-hij. Agenda: roadmap review, hiring update."
    )
    friend = (
        "hey! landed safely \U0001f60a dinner at 8 still on? I'll bring the board games. "
        "Also mum says thanks for the flowers \U0001f468\u200d\U0001f469\u200d\U0001f467"
    )
    booking = "Please confirm the details of your booking. Sign in to continue to your calendar."
    for text in (newsletter, invite, friend, booking):
        assert analyse_text(text).signals == (), text


def test_markdown_html_and_slack_links_give_their_label_and_real_address():
    text = (
        'Pay [paypal.com](https://evil.example/pay "PayPal") or '
        '<a class="btn" href="https://evil2.example/x">Your <b>Amazon</b> order</a> or '
        "<https://evil3.example/y|paypal.com>"
    )
    assert anchor_pairs(text) == [
        ("paypal.com", "https://evil.example/pay"),
        ("Your Amazon order", "https://evil2.example/x"),
        ("paypal.com", "https://evil3.example/y"),
    ]
    findings = analyse_text(text)
    # The labels are not links; the addresses behind them are, in order.
    assert findings.urls == ("https://evil.example/pay", "https://evil2.example/x", "https://evil3.example/y")
    (mismatch,) = [s for s in findings.signals if s.code == "anchor_mismatch"]
    assert mismatch.strength == "strong" and mismatch.count == 2
    assert mismatch.text == "A link shows paypal.com but really goes to evil.example."


def test_a_label_on_the_same_site_is_not_a_mismatch_and_the_registrable_helper_decides():
    same = "<https://www.paypal.com/signin|paypal.com> and [https://paypal.com](https://paypal.com/)"
    assert "anchor_mismatch" not in codes(analyse_text(same).signals)
    uk = "[shop.example.co.uk](https://pay.example.co.uk/x)"
    assert "anchor_mismatch" not in codes(analyse_text(uk).signals)
    # A caller's own helper (services.security.lookalike.registrable_domain) is used when given.
    every_host_differs = analyse_text(uk, registrable=lambda host: host)
    assert "anchor_mismatch" in codes(every_host_differs.signals)


def test_telegram_hidden_links_join_the_links_after_the_texts_own_and_their_labels_are_checked():
    findings = analyse_text(
        "Your parcel: tracking page. Or see https://post.example/t",
        extra_anchors=[("royalmail.com", "https://royalmail-fees.example/pay"), ("bad", "javascript:alert(1)")],
    )
    assert findings.urls == ("https://post.example/t", "https://royalmail-fees.example/pay")
    assert findings.anchors == (("royalmail.com", "https://royalmail-fees.example/pay"),)
    assert "anchor_mismatch" in codes(findings.signals)


def test_a_text_over_eight_thousand_characters_is_cut_before_any_check():
    findings = analyse_text("a" * MAX_TEXT_CHARS + " Send me the 6-digit code now https://late.example")
    assert findings.truncated is True and findings.urls == () and findings.signals == ()
    assert analyse_text("short").truncated is False


def test_ascii_host_turns_look_alike_letters_into_punycode_and_leaves_ascii_hosts_alone():
    assert ascii_host(PAYPAL_LOOKALIKE) == "xn--pypal-4ve.com"
    assert ascii_host("PayPal.COM.") == "paypal.com"
    assert ascii_host("xn--pypal-4ve.com") == "xn--pypal-4ve.com"
    assert ascii_host("b\u00fccher.example") == "xn--bcher-kva.example"
    assert ascii_host("[::1]") == "::1"
    # A host hiding an invisible character is unreadable rather than shown tidied up.
    assert ascii_host(f"pay{ZWSP}pal.com") is None
    assert ascii_host("") is None and ascii_host("a..b") is None and ascii_host("bad host.com") is None


def test_ascii_host_encodes_sharp_s_and_final_sigma_as_browsers_do_never_as_another_real_domain():
    # Checker finding: Python's IDNA 2003 codec maps sharp s to "ss" and final sigma to sigma,
    # so fa\u00df.de was shown as fass.de, a different real domain from the one a browser opens
    # (UTS 46 non-transitional: xn--fa-hia.de).
    assert ascii_host("fa\u00df.de") == "xn--fa-hia.de"
    assert ascii_host("FA\u00df.DE") == "xn--fa-hia.de"
    assert ascii_host("stra\u00dfe.de") == "xn--strae-oqa.de"
    assert ascii_host("\u03c3\u03bf\u03c6\u03bf\u03c2.gr") == "xn--0xaajbq.gr"
    assert display_url("https://fa\u00df.de/x") == "https://xn--fa-hia.de/x"
    assert sig.url_host("https://fa\u00df.de/x") == "xn--fa-hia.de"
    # Labels without those letters are unchanged.
    assert ascii_host("m\u00fcnchen.de") == "xn--mnchen-3ya.de"
    assert ascii_host("fass.de") == "fass.de"
    assert ascii_host(PAYPAL_LOOKALIKE) == "xn--pypal-4ve.com"


def test_display_url_hides_the_query_and_never_shows_a_raw_non_ascii_host():
    assert display_url(f"https://{PAYPAL_LOOKALIKE}/login?session=abc#top") == "https://xn--pypal-4ve.com/login\u2026"
    assert display_url("https://paypal.com@evil.example:8443/x") == "https://evil.example:8443/x"
    long_path = "https://evil.example/" + "a" * 100
    assert display_url(long_path) == "https://evil.example/" + "a" * 59 + "\u2026"
    path_lookalike = display_url(f"https://evil.example/{CYRILLIC_A}`x")
    assert path_lookalike == "https://evil.example/%D0%B0%60x"
    assert display_url("javascript:alert(1)") == "javascript:\u2026"
    assert display_url("https://[bad") == "" and display_url("") == ""
    for shown in (display_url(f"https://{PAYPAL_LOOKALIKE}/{CYRILLIC_A}"), display_url(f"http://{PAYPAL_LOOKALIKE}")):
        assert shown.replace("\u2026", "").isascii()


def test_signal_sentences_are_fixed_and_never_quote_the_message():
    message = (
        f"URGENT!!! Confirm your details within 2 hours at {PAYPAL_LOOKALIKE} or face arrest. "
        f"Pay with gift cards and send me the 6-digit code.{TAG_HELLO}{RLO} "
        f"[paypal.com](https://{PAYPAL_LOOKALIKE}/x) keep this secret"
    )
    findings = analyse_text(message)
    assert len(findings.signals) >= 6
    for signal in findings.signals:
        assert signal.code in SIGNAL_SENTENCES and signal.strength == SIGNAL_STRENGTHS[signal.code]
        assert signal.text.isascii(), signal
        assert not any(ch in _HOMOGLYPH_MAP for ch in signal.text)
        assert not _INVISIBLE_CHARS.search(signal.text)
        for word in ("URGENT", "2 hours", "gift cards", "6-digit", "face arrest"):
            assert word not in signal.text
    mismatch = next(s for s in findings.signals if s.code == "anchor_mismatch")
    assert mismatch.text == "A link shows paypal.com but really goes to xn--pypal-4ve.com."


def test_make_signal_keeps_placeholder_values_to_ascii_hosts_and_plain_words():
    signal = sig.make_signal("sender_impersonation", brand="PayPal<script>", domain=f"{PAYPAL_LOOKALIKE}")
    assert signal.text == "The sender's name says PayPalscript but the address is on xn--pypal-4ve.com."
    assert sig.make_signal("file_malicious", count=12, m=70).text == (
        "VirusTotal engines flag this file as harmful (12 of 70)."
    )


@pytest.mark.parametrize(
    "reason",
    [
        "Visit https://x.example to check",
        "It says to go to www.x.example",
        "The link goes to paypal-secure.help",
        "Write to help@x.example",
        "Call 1-888-555-0101 now",
        "Call (888) 555 0101 now",
        "Click [here](https://x.example)",
        "It shows ![logo](x)",
        "It points to paypal[.]com",
        f"It points to {PAYPAL_LOOKALIKE}",
    ],
)
def test_ai_reasons_with_a_link_domain_email_or_phone_number_are_dropped(reason):
    assert clean_ai_reason(reason) is None


@pytest.mark.parametrize(
    "reason",
    [
        "Visit amazon-help.lat to claim",
        "Reply to support at paypal-help.best",
        "See paypal.claims",
        "Pay at usps-fee.cam",
        "Open evil.zip",
        "login-paypal.mov is fake",
        "It points to paypal.xn--p1ai",
        "It points to paypal\u3002claims",
        "It points to \u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444",
    ],
)
def test_ai_reasons_naming_a_domain_on_any_letter_ending_or_a_file_extension_ending_are_dropped(reason):
    # Checker finding (SEC-M2 bypass): a bare domain was dropped only on an ending from
    # KNOWN_TLDS or a two-letter one, and never on a file-extension ending; the attacker picks
    # the ending.
    assert clean_ai_reason(reason) is None


def test_abbreviations_and_numbers_with_dots_in_an_ai_reason_are_not_taken_for_domains():
    for reason in (
        "It uses e.g. a fake deadline, i.e. a threat.",
        "It claims to be from the U.S. tax office at 9 a.m. today.",
        "It asks for version 1.2 of the app and 3.5 percent.",
    ):
        assert clean_ai_reason(reason) == reason


def test_a_lone_surrogate_in_an_ai_reason_is_removed_so_the_reason_can_be_written_as_utf8():
    kept = clean_ai_reason("It uses a fake \ud800deadline.")
    assert kept is not None and kept == "It uses a fake deadline."
    assert kept.encode("utf-8") == b"It uses a fake deadline."


def test_a_plain_ai_reason_is_kept_on_one_line_without_format_characters_and_capped():
    assert clean_ai_reason("  It uses\n a fake\tdeadline.\u200b ") == "It uses a fake deadline."
    assert clean_ai_reason("- It pretends to be the bank's fraud team.") == "It pretends to be the bank's fraud team."
    long = clean_ai_reason("It pressures you. " * 30, limit=40)
    assert long is not None and len(long) <= 40 and long.endswith("\u2026")
    assert clean_ai_reason("") is None and clean_ai_reason(None) is None  # type: ignore[arg-type]
    # A 6-digit code is not a phone number.
    assert clean_ai_reason("It asks for the 6-digit code 123456.") is not None


@pytest.mark.parametrize(
    "reason",
    [
        "Visit paypal-help\ufe0f.lat to restore access.",
        "Visit paypal-help.\ufe0flat to restore access.",
        "Visit paypal-help\u034f.lat now",
        "Visit paypal-help.\u180blat now",
        "Visit paypal-help\U000e0100.lat now",
        "Visit paypal-help\u0301.lat now",
        "Visit paypal-help\u30fblat now",
        "Visit paypal-help\u00b7lat now",
    ],
)
def test_an_ai_reason_hiding_a_domain_behind_invisible_marks_or_a_dot_lookalike_is_dropped(reason):
    # Checker finding (SEC-M2 bypass): variation selectors, the combining grapheme joiner and
    # other default-ignorable marks are not format characters, so they stayed in the reason and
    # split "paypal-help.lat" into tokens no domain rule matched, while it still read as one.
    assert clean_ai_reason(reason) is None


def test_a_kept_ai_reason_has_no_default_ignorable_mark_left_in_it():
    kept = clean_ai_reason("It uses a fake\ufe0f dead\u034fline.")
    assert kept == "It uses a fake deadline."


@pytest.mark.parametrize(
    "reason",
    [
        "Visit paypal-help&period;lat to claim",
        "Write to help&commat;paypal-help&period;lat now",
        "Open https&colon;&sol;&sol;paypal-help&period;lat&sol;login",
        "Call 888&hyphen;555&hyphen;0101 now",
        "It says &#46; and &#x40; somewhere",
        "It uses the word &amp; nothing else",
    ],
)
def test_an_ai_reason_holding_an_html_character_reference_is_dropped(reason):
    # Checker finding (SEC-M2 bypass in the web chat): CommonMark decodes "&period;" to "." and
    # "&commat;" to "@", so a reason with no dot or "@" in it could still show a domain or an
    # address. An AI reason has no need for a character reference, so any one drops it.
    assert clean_ai_reason(reason) is None


@pytest.mark.parametrize(
    "reason",
    [
        "Go to paypal-help dot lat",
        "Go to paypal-help dot shop",
        "Go to paypal-help DOT claims",
        "Go to paypal-help . lat",
        "Go to paypal-help (.) lat",
        "Go to paypal-help\\.lat",
        "Call 888_555_0101",
        "Call 888*555*0101",
        "Call 888, 555, 0101",
        "Call 888 -- 555 -- 0101",
        "Call 1-800-PAYPAL-1",
        "Call (888) PAYNOW today",
        "Call 555-SCAMMER today",
        "It points to 45.9.20.1 today",
        "It points to 45 . 9 . 20 . 1 today",
        "It points to 2001:db8:85a3:0:8a2e:370 today",
        "It points to fe80::1 today",
    ],
)
def test_defanged_domains_odd_phone_separators_vanity_numbers_and_ip_addresses_drop_the_reason(reason):
    # Checker finding (SEC-M2 hardening): "dot <ending>" matched only six endings, a spaced dot
    # and the separators "_ * , --" were not read, and a vanity number or a short IP address
    # was kept and shown raw.
    assert clean_ai_reason(reason) is None


def test_amounts_times_and_sentences_with_dots_are_still_kept():
    for reason in (
        "It asks for $1,000,000 in prizes.",
        "It asks you to pay within 24 hours.",
        "It uses a deadline, e.g. 5 p.m. today.",
        "The sender pretends to be the U.S. Postal Service.",
        "It asks for 2 payments. Then it asks for more.",
        "It mentions a dotted line on the form.",
    ):
        assert clean_ai_reason(reason) == reason, reason


_REASON_SEEDS = (
    "1 ", "1-", "1_", "1, ", "12345 -- ", "a:", "aaaa:", "1.1.1 ", "1 . ", "x dot ", "&a",
    "&#1", "1-800-", "(888) ", "555-", "a.", "*.", "a .", "\u00b7", "a::", "\ufe0f.",
)


@pytest.mark.parametrize(
    "name", ["_PHONE", "_VANITY", "_IP_ADDRESS", "_DEFANGED_DOT", "_PUNCT_AT_DOT", "_CHARACTER_REFERENCE"]
)
def test_each_ai_reason_rule_finishes_a_megabyte_of_its_worst_case_in_under_two_seconds(name):
    # clean_ai_reason reads only the first few hundred characters, but each rule must stay
    # linear on its own too, so a later caller cannot make it slow.
    pattern = getattr(sig, name)
    for seed in _REASON_SEEDS:
        text = _megabyte(seed) + "!"
        started = time.perf_counter()
        for _ in pattern.finditer(text):
            pass
        assert time.perf_counter() - started < 2.0, f"{name} is slow on {seed!r}"


# The worst cases of the wording patterns: an ask verb with its object never arriving, a run of
# the bounded word lists in the "code we just sent" patterns, and dotted tokens.
_SEEDS = (
    "send me the ",
    "verify your ",
    "$1 ",
    "1 ",
    "gift card ",
    "a",
    "share us the 6 digit ",
    "code that was just ",
    "x.y ",
)


def _megabyte(seed: str) -> str:
    size = 1_000_000
    return (seed * (size // len(seed) + 1))[:size]


@pytest.mark.parametrize("index", range(len(sig.WORDING_PATTERNS)))
def test_every_pattern_finishes_a_megabyte_of_its_worst_case_in_under_two_seconds(index):
    pattern = sig.WORDING_PATTERNS[index]
    for seed in _SEEDS:
        text = _megabyte(seed)
        started = time.perf_counter()
        for _ in pattern.finditer(text):
            pass
        assert time.perf_counter() - started < 2.0, f"{pattern.pattern[:60]} is slow on {seed!r}"


@pytest.mark.parametrize(
    "seed", ["a.", "1 ", "<a href=", "[a](http://", "<http://x|", "http://", "\u200d", "\U000e0041", "x@y.", "send me the "]
)
def test_the_whole_local_pass_on_a_megabyte_of_hostile_text_is_bounded(seed):
    text = _megabyte(seed)
    for fn in (
        language_signals,
        hidden_character_signals,
        anchor_pairs,
        lambda t: extract_urls(t, limit=10**6),
        lambda t: clean_ai_reason(t, limit=200),
        analyse_text,
    ):
        started = time.perf_counter()
        fn(text)
        assert time.perf_counter() - started < 2.0, f"{fn} is slow on {seed!r}"
