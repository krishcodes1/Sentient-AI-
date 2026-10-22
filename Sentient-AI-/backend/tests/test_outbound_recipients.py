"""Tests for services/security/outbound_recipients.py: they prove that recipient arguments are
read from every shape the connectors take (header strings, lists, Google attendees, Graph
recipients), that addresses are normalised the way the sent-to history needs (lower case, no
"+tag", Gmail dots and googlemail.com folded, A-label domains), that the history's fingerprint is
a keyed, per-user, per-kind HMAC that never contains the address, that consumer mail domains
never make an organisation, that "self", "inside", "outside" and "unknown" follow the owner's
domains, that typo, homograph and brand-name imitations of familiar domains and look-alike
letters are flagged at the right severity while exact domains never are (homographs of the
ordinary-word mail services included, each naming the reference under the recipient's own
ending), and that the owner's organisation domains are validated with plain reasons.

Why it exists: these answers become the notes on every outgoing-message approval card (security
S1). A wrong "inside your organisation" hides the one warning an injected "send the invoice to
billing@acme-payrnents.com" needs, and a fingerprint that leaks or collides would either expose
the owner's correspondents or silence "first time Crawler sends to".

The look-alike helpers are the real services/security/lookalike.py (WAVE 0, scaffold A6/F39),
which also holds the consumer mail list this module re-exports.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

import pytest

from core.config import settings
from services.security.outbound_recipients import (
    CONSUMER_MAIL_DOMAINS,
    AddressConcern,
    OrgView,
    Recipient,
    address_concern,
    classify,
    hmac_key_id,
    normalize_address,
    note_address,
    org_view,
    organisation_domain_of,
    parse_recipients,
    recipient_hmac,
    validate_organisation_domain,
)


def _one(value: str) -> Recipient:
    recipients = parse_recipients(value)
    assert len(recipients) == 1, recipients
    return recipients[0]


def _org(*own: str, domains: tuple[str, ...] = ()) -> OrgView:
    return org_view(own, domains)


NORTHWIND = ("ann@northwind.com",)


# ---------------------------------------------------------------------------
# Normalising and parsing
# ---------------------------------------------------------------------------


def test_addresses_are_lower_cased_without_plus_tags_and_gmail_dots():
    assert normalize_address("Ann.Lee+invoices@Acme.COM") == "ann.lee@acme.com"
    assert normalize_address("Ann Lee <Ann.Lee+x@Acme.com.>") == "ann.lee@acme.com"
    assert normalize_address("j.o.h.n+news@GMail.com") == "john@gmail.com"
    # Dots matter everywhere else.
    assert normalize_address("j.o.h.n@outlook.com") == "j.o.h.n@outlook.com"


def test_googlemail_and_gmail_addresses_are_the_same_address():
    assert normalize_address("Jo.Doe@googlemail.com") == normalize_address("jodoe@gmail.com")
    assert normalize_address("jo.doe@googlemail.com") == "jodoe@gmail.com"


def test_an_international_domain_is_stored_in_its_ascii_form():
    recipient = _one("Maria <maria@bücher.de>")
    assert recipient.domain == "xn--bcher-kva.de"
    assert recipient.address == "maria@xn--bcher-kva.de"
    assert recipient.shown == "maria@bücher.de"


def test_a_german_sharp_s_domain_keeps_its_own_ascii_form_instead_of_becoming_ss():
    # IDNA 2003 would turn faß.de into fass.de, a different domain from the one mail reaches.
    assert normalize_address("ann@faß.de") == "ann@xn--fa-hia.de"
    assert normalize_address("ann@fass.de") == "ann@fass.de"


def test_anything_that_is_not_a_single_usable_address_normalises_to_none():
    for raw in (
        "",
        "   ",
        "no-at-sign",
        "@acme.com",
        "ann@",
        "+tag@acme.com",
        "a b@acme.com",
        "ann@[10.0.0.1]",
        "ann@acme..com",
        "....@gmail.com",
    ):
        assert normalize_address(raw) is None, raw
    assert normalize_address(None) is None  # type: ignore[arg-type]


def test_recipients_are_read_from_strings_lists_attendee_objects_and_graph_recipients():
    header = parse_recipients('Ann <ann@acme.com>, bob@beta.example; "Lee, Cy" <cy@gamma.example>')
    assert [r.address for r in header] == ["ann@acme.com", "bob@beta.example", "cy@gamma.example"]

    listed = parse_recipients(["ann@acme.com", "Bob <bob@beta.example>"])
    assert [r.address for r in listed] == ["ann@acme.com", "bob@beta.example"]

    attendees = parse_recipients(
        [{"email": "ann@acme.com", "responseStatus": "accepted"}, {"email": "Bob@Beta.example"}]
    )
    assert [r.address for r in attendees] == ["ann@acme.com", "bob@beta.example"]

    graph = parse_recipients(
        [
            {"emailAddress": {"address": "ann@acme.com", "name": "Ann"}},
            {"emailAddress": {"name": "nobody"}},
            {"type": "required"},
        ]
    )
    assert [r.address for r in graph] == ["ann@acme.com"]

    assert parse_recipients(None) == []
    assert parse_recipients(42) == []
    assert parse_recipients({"to": "ann@acme.com"}) == []


def test_a_quoted_display_name_with_a_comma_or_semicolon_stays_one_recipient():
    recipients = parse_recipients('"Doe; Jane, CFO" <jane@acme.com>, ops@acme.com')
    assert [r.address for r in recipients] == ["jane@acme.com", "ops@acme.com"]
    assert recipients[0].shown == "jane@acme.com"


def test_unparseable_entries_are_skipped_and_an_address_written_twice_is_listed_once():
    recipients = parse_recipients(
        "not an address, Ann <ann@acme.com>, ANN+x@acme.com, , ann@acme.com>"
    )
    assert [r.address for r in recipients] == ["ann@acme.com"]
    assert recipients[0].shown == "ann@acme.com"


def test_recipients_nested_hundreds_deep_never_raise_and_every_address_in_them_is_still_read():
    # Batch-2 check: email.utils.parseaddr recurses once per nested comment or ":" group, so a
    # list piece of ~600 nested "(" or ~1,000 ":" raised RecursionError out of parse_recipients,
    # and the call check lost every recipient note. A piece the parser fails on now gives each
    # local@domain token in it (an address it could not place still gets its notes).
    nested = "(" * 1200 + ")" * 1200
    cases = {
        "billing@acme-payrnents.com " + nested: ["billing@acme-payrnents.com"],
        ":" * 1500 + "billing@acme-payrnents.com": ["billing@acme-payrnents.com"],
        "x:" * 1500 + "billing@acme-payrnents.com": ["billing@acme-payrnents.com"],
        "Ann <ann@acme.com> (" + "(" * 1200 + "cc evil@exfil.example" + ")" * 1201: [
            "ann@acme.com",
            "evil@exfil.example",
        ],
    }
    for value, expected in cases.items():
        assert [r.address for r in parse_recipients(value)] == expected, value[:40]
        assert [r.address for r in parse_recipients([value])] == expected
        assert [r.address for r in parse_recipients({"emailAddress": {"address": value}})] == (
            expected
        )
        assert normalize_address(value) is None  # never one usable address, never a raise
    # The other pieces of the list are read as before.
    assert [r.address for r in parse_recipients("bo@beta.example, a@acme.com " + nested)] == [
        "bo@beta.example",
        "a@acme.com",
    ]
    assert normalize_address("a@acme.com " + "(" * 300 + ")" * 300) == "a@acme.com"


# ---------------------------------------------------------------------------
# How an address appears in a note (review SEC-F9)
# ---------------------------------------------------------------------------


def test_note_address_drops_invisible_and_bidi_characters_but_keeps_plus_tags_and_dots():
    hidden = _one("Pay <pa\u202ey\u200b.ment+billing@vendor.example>")
    assert note_address(hidden) == "pay.ment+billing@vendor.example"
    assert all(ch.isprintable() for ch in note_address(hidden))


def test_note_address_shows_an_international_domain_in_its_ascii_form():
    assert note_address(_one("maria@bücher.de")) == "maria@xn--bcher-kva.de"
    # A Cyrillic o (U+043E) never reaches the card as a letter that reads like Latin.
    shown = note_address(_one("ann@n\u043erthwind.com"))
    assert shown.isascii() and shown.endswith(".com") and "xn--" in shown


# ---------------------------------------------------------------------------
# The fingerprint (S1 design 3.3)
# ---------------------------------------------------------------------------


def test_the_hmac_differs_per_user_and_per_kind_and_never_contains_the_address():
    user_a, user_b = "6f1c0e1e-0000-4000-8000-000000000001", "6f1c0e1e-0000-4000-8000-000000000002"
    address = "ann@acme.com"
    one = recipient_hmac(user_a, "address", address)
    assert len(one) == 64 and all(ch in "0123456789abcdef" for ch in one)
    assert one == recipient_hmac(user_a, "address", address)
    assert one != recipient_hmac(user_b, "address", address)
    assert recipient_hmac(user_a, "domain", "acme.com") != recipient_hmac(
        user_a, "address", "acme.com"
    )
    for part in ("ann", "acme", "@"):
        assert part not in one


def test_the_hmac_matches_the_documented_derivation():
    key = hashlib.sha256(
        b"sentientai.known_recipients.hmac.v1:" + settings.ENCRYPTION_KEY.encode()
    ).digest()
    user_id = "6f1c0e1e-0000-4000-8000-000000000001"
    expected = hmac.new(
        key, f"{user_id}\x00domain\x00acme.com".encode(), hashlib.sha256
    ).hexdigest()
    assert recipient_hmac(user_id, "domain", "acme.com") == expected
    assert hmac_key_id() == hashlib.sha256(key).hexdigest()[:8]


def test_a_different_encryption_key_gives_a_different_key_id(monkeypatch):
    before_id = hmac_key_id()
    before_hmac = recipient_hmac("u1", "address", "ann@acme.com")
    monkeypatch.setattr(
        settings, "ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode()
    )
    assert hmac_key_id() != before_id
    assert len(hmac_key_id()) == 8
    assert recipient_hmac("u1", "address", "ann@acme.com") != before_hmac


def test_an_unknown_fingerprint_kind_is_refused():
    with pytest.raises(ValueError):
        recipient_hmac("u1", "person", "ann@acme.com")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Organisation
# ---------------------------------------------------------------------------


def test_consumer_mail_domains_never_count_as_the_organisation():
    org = _org("me@gmail.com", "me@outlook.com", domains=("hotmail.com", "yahoo.co.uk"))
    assert org.domains == frozenset()
    assert org.label == ""
    assert organisation_domain_of("me@mail.yahoo.co.uk") is None
    # So nobody is "outside" a consumer user's organisation.
    assert classify(_one("x@beta.example"), org) == "unknown"


def test_the_consumer_list_matches_the_design():
    assert CONSUMER_MAIL_DOMAINS == frozenset(
        "gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com "
        "yahoo.co.uk yahoo.co.jp icloud.com me.com mac.com aol.com proton.me protonmail.com pm.me "
        "gmx.com gmx.net gmx.de web.de mail.com zoho.com fastmail.com hey.com tutanota.com tuta.io "
        "yandex.com yandex.ru mail.ru qq.com 163.com 126.com naver.com hanmail.net comcast.net "
        "verizon.net att.net sbcglobal.net btinternet.com orange.fr free.fr laposte.net libero.it "
        "t-online.de seznam.cz rediffmail.com".split()
    )


def test_the_consumer_list_is_the_one_lookalike_holds():
    # Scaffold A6: one list, in lookalike.py; S1 re-exports it under its design's name.
    from services.security import lookalike

    assert CONSUMER_MAIL_DOMAINS is lookalike.CONSUMER_MAIL_DOMAINS


def test_org_view_keeps_the_sign_in_domain_first_and_adds_the_owner_list():
    org = _org(
        "Ann@EU.Northwind.com", "ann@gmail.com", domains=("acme.co.uk", "ACME.co.uk", "gmail.com")
    )
    assert org.own_addresses == frozenset({"ann@eu.northwind.com", "ann@gmail.com"})
    assert org.domains == frozenset({"northwind.com", "acme.co.uk"})
    assert org.label == "northwind.com, acme.co.uk"


def test_org_view_label_names_at_most_three_domains():
    org = _org(domains=("a1.example", "a2.example", "a3.example", "a4.example", "a5.example"))
    assert org.label == "a1.example, a2.example, a3.example and 2 more"
    assert len(org.domains) == 5


def test_organisation_domain_of_reads_the_registrable_domain():
    assert organisation_domain_of("ann@eu.northwind.com") == "northwind.com"
    assert organisation_domain_of("Ann <ann@shop.acme.co.uk>") == "acme.co.uk"
    assert organisation_domain_of("ann@gmail.com") is None
    assert organisation_domain_of("not an address") is None


def test_a_subdomain_of_an_organisation_domain_is_inside():
    org = _org(*NORTHWIND, domains=("acme.co.uk",))
    assert classify(_one("bob@northwind.com"), org) == "inside"
    assert classify(_one("bob@mail.eu.northwind.com"), org) == "inside"
    assert classify(_one("cy@sales.acme.co.uk"), org) == "inside"
    assert classify(_one("eve@northwind.com.evil.example"), org) == "outside"
    assert classify(_one("eve@notnorthwind.com"), org) == "outside"


def test_with_no_organisation_domains_nobody_is_outside():
    org = _org("me@gmail.com")
    assert classify(_one("anyone@beta.example"), org) == "unknown"
    assert classify(_one("anyone@gmail.com"), org) == "unknown"


def test_the_users_own_address_is_self_even_on_a_consumer_domain():
    org = _org("Jo.Doe+crawler@googlemail.com", *NORTHWIND)
    assert classify(_one("jodoe@gmail.com"), org) == "self"
    assert classify(_one("ANN@northwind.com"), org) == "self"
    assert classify(_one("bob@northwind.com"), org) == "inside"


# ---------------------------------------------------------------------------
# Look-alikes and unusual characters
# ---------------------------------------------------------------------------


def test_a_one_letter_typo_of_the_organisation_domain_is_a_high_lookalike():
    org = _org(*NORTHWIND, domains=("acmepayments.com",))
    assert address_concern(_one("ceo@northwlnd.com"), org) == AddressConcern(
        "lookalike", "high", "northwind.com"
    )
    assert address_concern(_one("billing@acme-payrnents.com"), org) == AddressConcern(
        "lookalike", "high", "acmepayments.com"
    )


def test_rn_for_m_and_digit_for_letter_swaps_are_lookalikes():
    org = _org(*NORTHWIND)
    for address, reference in (
        ("sales@arnazon.com", "amazon.com"),
        ("help@paypa1.com", "paypal.com"),
        ("ceo@northvvind.com", "northwind.com"),
    ):
        concern = address_concern(_one(address), org)
        assert concern == AddressConcern("lookalike", "high", reference), address


def test_a_typo_of_gmail_com_is_a_lookalike():
    org = _org(*NORTHWIND)
    for address in ("friend@gnail.com", "friend@gmai1.com", "friend@gmaill.com"):
        assert address_concern(_one(address), org) == AddressConcern(
            "lookalike", "high", "gmail.com"
        ), address


def test_the_organisation_name_on_another_domain_is_a_warn_lookalike():
    org = _org(*NORTHWIND)
    for address in (
        "billing@northwind-invoices.com",
        "billing@northwind.co",
        "it@northwindsupport.com",
    ):
        assert address_concern(_one(address), org) == AddressConcern(
            "lookalike", "warn", "northwind.com"
        ), address


def test_a_known_brand_used_in_another_name_is_a_warn_lookalike():
    org = _org(*NORTHWIND)
    assert address_concern(_one("refunds@paypal-billing.com"), org) == AddressConcern(
        "lookalike", "warn", "paypal.com"
    )


def test_an_exact_organisation_domain_is_never_a_lookalike():
    org = _org(*NORTHWIND, domains=("acme.co.uk",))
    for address in (
        "bob@northwind.com",
        "bob@eu.northwind.com",
        "cy@acme.co.uk",
        "ann@northwind.com",
        "pal@paypal.com",
        "friend@gmail.com",
        "friend@yahoo.co.uk",
        "x@mail.com",
    ):
        assert address_concern(_one(address), org) is None, address


def test_ordinary_word_mail_services_are_not_patterns_to_imitate():
    # live.com, tuta.io, free.fr and mail.com have names that are ordinary words: mail to
    # line.me, tata.com, tree.com or a company's mail subdomain is not an imitation of them.
    org = _org(*NORTHWIND)
    for address in (
        "a@line.me",
        "b@tata.com",
        "c@tree.com",
        "d@mail.beta.example",
        "e@lime.example",
    ):
        assert address_concern(_one(address), org) is None, address


def test_homographs_of_ordinary_word_mail_services_are_still_high_lookalikes():
    # Review of the early core: leaving the ordinary-word mail services out of the look-alike
    # patterns turned off letter-for-letter (homograph) matching for them too.
    org = _org(*NORTHWIND)
    for address, reference in (
        ("a@1ive.com", "live.com"),
        ("b@a0l.com", "aol.com"),
        ("c@zoh0.com", "zoho.com"),
        ("d@rnsn.com", "msn.com"),
        ("e@grnx.de", "gmx.de"),
        ("f@vveb.de", "web.de"),
    ):
        assert address_concern(_one(address), org) == AddressConcern(
            "lookalike", "high", reference
        ), address
    # In another label it is a warn, like a brand inside a longer name.
    assert address_concern(_one("g@login-1ive.example"), org) == AddressConcern(
        "lookalike", "warn", "live.com"
    )
    # The plain words, and two-letter names, stay quiet.
    for address in ("a@live.example", "b@web.com", "c@rne.com"):
        assert address_concern(_one(address), org) is None, address


def test_a_lookalike_names_the_reference_under_the_recipients_own_ending():
    # Review of the early core: the references were read in sorted order, so the card said
    # yah00.com looks like yahoo.co.jp.
    org = _org(*NORTHWIND)
    for address, reference in (
        ("a@yah00.com", "yahoo.com"),
        ("b@yah00.co.uk", "yahoo.co.uk"),
        ("c@yah00.co.jp", "yahoo.co.jp"),
        ("d@yah00.de", "yahoo.com"),
    ):
        assert address_concern(_one(address), org) == AddressConcern(
            "lookalike", "high", reference
        ), address


def test_a_cyrillic_letter_in_a_domain_is_high_unusual_characters():
    org = _org(*NORTHWIND)
    concern = address_concern(_one("ceo@n\u043erthwind.com"), org)
    assert concern == AddressConcern("unusual_characters", "high", "", reading="northwind.com")


def test_a_single_script_international_domain_is_only_info():
    org = _org(*NORTHWIND)
    assert address_concern(_one("li@\u4f8b\u5b50.\u4e2d\u56fd"), org) == AddressConcern(
        "unusual_characters", "info", ""
    )


def test_punycode_that_does_not_decode_is_high_unusual_characters():
    org = _org(*NORTHWIND)
    concern = address_concern(_one("ann@xn--zz.example"), org)
    assert (
        concern is not None and concern.kind == "unusual_characters" and concern.severity == "high"
    )


def test_an_ordinary_new_domain_has_no_concern():
    org = _org(*NORTHWIND)
    assert address_concern(_one("ana@partner.example"), org) is None
    assert address_concern(_one("ana@partner.example"), _org("me@gmail.com")) is None


# ---------------------------------------------------------------------------
# Organisation domains the owner types in (Security tab, S1 design 4.7)
# ---------------------------------------------------------------------------


_ENTER = "Enter a domain such as acme.com."
_PUBLIC = "{} is a public mail service, so it cannot be your organisation's domain."


@pytest.mark.parametrize(
    ("typed", "stored", "refusal"),
    [
        ("gmail.com", None, _PUBLIC.format("gmail.com")),
        ("mail.yahoo.co.uk", None, _PUBLIC.format("mail.yahoo.co.uk")),
        (
            "co.uk",
            None,
            "co.uk is a domain ending, not a domain. Enter your organisation's own, such as acme.co.uk.",
        ),
        ("acme", None, _ENTER),
        ("10.0.0.1", None, _ENTER),
        ("https://acme.com/x", None, _ENTER),
        ("ann@acme.com", None, _ENTER),
        ("acme .com", None, _ENTER),
        ("-acme.com", None, _ENTER),
        ("", None, _ENTER),
        ("a" * 250 + ".com", None, _ENTER),
        ("@acme.com", "acme.com", None),
        ("WWW.Acme.COM", "acme.com", None),
        ("  acme.co.uk.  ", "acme.co.uk", None),
        ("bücher.de", "xn--bcher-kva.de", None),
    ],
)
def test_organisation_domains_are_validated_with_plain_reasons(typed, stored, refusal):
    if stored is not None:
        assert validate_organisation_domain(typed) == stored
        return
    with pytest.raises(ValueError) as refused:
        validate_organisation_domain(typed)
    assert str(refused.value) == refusal
