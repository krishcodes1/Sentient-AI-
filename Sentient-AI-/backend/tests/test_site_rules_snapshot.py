"""Tests for the site-rules snapshot (services/site_rules/snapshot.py): they
prove the precedence the owner reads on the Security page (an owner rule
beats the built-in list; among owner rules the exact host beats the
longest "*." suffix; a category override changes every site in it; the
stricter kind wins a tie), that a protected sign-in or payment host is
never Blocked whatever a row says, that inside an approved checkout's
window a Blocked verdict is set aside only for protected and built-in bank
hosts (review SEC-F4), that the switch off means no rule applies, that
hosts match however a URL spells them, and that the card notes, read
notices and Check explanations say the right thing in at most 200
characters.

Why it exists: the browser guard, the web resolver, observe and the call
check all ask this one object on every navigation and call, so a
precedence slip here would either block a bank's 3-D Secure page in the
middle of a purchase or let a Blocked site open. Pure: no database, no
browser, no network.
"""

from __future__ import annotations

import pytest

from services.site_rules import messages
from services.site_rules.patterns import overlaps
from services.site_rules.sensitive_sites import BANKS, BROKERS, CATEGORIES
from services.site_rules.snapshot import (
    NO_VERDICT,
    OwnerRule,
    SiteRuleSnapshot,
    SiteVerdict,
    builtin_entry,
    card_note,
    exempt_in_checkout_window,
    overlapping_builtin,
    read_notice,
)
from tests.site_rules_fakes import snapshot_of

BLOCKED = messages.NAVIGATION_BLOCKED


def _bases(sites):
    return [site[2:] for site in sites]


def test_an_unlisted_host_has_no_verdict():
    snapshot = snapshot_of()
    for host in ("example.org", "www.example.org", "evilchase.com", "chase.com.evil.com"):
        assert snapshot.verdict(host) == NO_VERDICT, host
        assert snapshot.verdict(host).kind is None


def test_a_built_in_bank_defaults_to_always_ask():
    verdict = snapshot_of().verdict("secure.chase.com")
    assert verdict == SiteVerdict(
        "always_ask", source="builtin", pattern="*.chase.com", category="banks"
    )
    assert not verdict.protected and not verdict.exempted
    # Every built-in site in every category starts as Always ask.
    snapshot = snapshot_of()
    for c in CATEGORIES:
        for host in _bases(c.sites):
            got = snapshot.verdict(f"www.{host}")
            assert (got.kind, got.category) == ("always_ask", c.key), host


def test_an_owner_rule_beats_the_built_in_list_whatever_its_specificity():
    # A broader owner rule (one validation would refuse, written by hand) still wins.
    broad = snapshot_of({"*.com": "trusted"})
    verdict = broad.verdict("secure.chase.com")
    assert (verdict.kind, verdict.source, verdict.pattern) == ("trusted", "owner", "*.com")
    assert verdict.rule_id == "rule-1"
    # A narrower owner rule wins for its host; the rest of the site keeps the list.
    narrow = snapshot_of({"secure.chase.com": "blocked"})
    assert narrow.verdict("secure.chase.com").kind == "blocked"
    assert narrow.verdict("secure.chase.com").source == "owner"
    assert narrow.verdict("www.chase.com").source == "builtin"
    # An owner rule must cover the host to win: "chase.com" exact leaves secure.chase.com.
    exact = snapshot_of({"chase.com": "trusted"})
    assert exact.verdict("chase.com").kind == "trusted"
    assert exact.verdict("secure.chase.com").kind == "always_ask"


def test_among_owner_rules_the_exact_host_beats_the_longest_wildcard_which_beats_shorter_ones():
    snapshot = snapshot_of(
        {
            "*.example.com": "blocked",
            "*.docs.example.com": "trusted",
            "api.docs.example.com": "always_ask",
        }
    )
    assert snapshot.verdict("api.docs.example.com").kind == "always_ask"
    assert snapshot.verdict("v2.api.docs.example.com").kind == "trusted"
    assert snapshot.verdict("docs.example.com").kind == "trusted"
    assert snapshot.verdict("x.docs.example.com").pattern == "*.docs.example.com"
    assert snapshot.verdict("example.com").kind == "blocked"
    assert snapshot.verdict("www.example.com").pattern == "*.example.com"


def test_a_trusted_exact_host_overrides_a_blocked_wildcard_only_for_that_host():
    snapshot = snapshot_of({"*.example.com": "blocked", "docs.example.com": "trusted"})
    assert snapshot.verdict("docs.example.com").kind == "trusted"
    assert snapshot.navigation_reason("https://docs.example.com/", exempt=False) is None
    assert snapshot.verdict("a.docs.example.com").kind == "blocked"
    assert snapshot.navigation_reason("https://a.docs.example.com/", exempt=False) == BLOCKED


def test_a_category_override_changes_every_site_in_it_and_an_owner_host_rule_still_wins():
    snapshot = snapshot_of({"*.fidelity.com": "trusted"}, categories={"brokers": "blocked"})
    for host in _bases(BROKERS.sites):
        if host == "fidelity.com":
            continue
        verdict = snapshot.verdict(host)
        assert (verdict.kind, verdict.source, verdict.category) == ("blocked", "builtin", "brokers"), host
    assert snapshot.verdict("digital.fidelity.com").kind == "trusted"
    assert snapshot.verdict("digital.fidelity.com").source == "owner"
    # Other categories keep their default.
    assert snapshot.verdict("secure.chase.com").kind == "always_ask"
    assert snapshot.category_kind("brokers") == "blocked"
    assert snapshot.category_kind("banks") == "always_ask"
    assert snapshot.category_overridden("brokers")
    assert not snapshot.category_overridden("banks")


def test_two_rows_for_one_pattern_keep_the_stricter_kind():
    # The unique index prevents this through the API; rows written any other
    # way (or spelled differently) still resolve the strict way.
    snapshot = snapshot_of([("*.example.com", "trusted"), ("*.EXAMPLE.com.", "blocked")])
    verdict = snapshot.verdict("www.example.com")
    assert (verdict.kind, verdict.rule_id) == ("blocked", "rule-2")
    first_kept = snapshot_of([("x.example.com", "always_ask"), ("x.example.com", "trusted")])
    assert first_kept.verdict("x.example.com").rule_id == "rule-1"
    assert first_kept.verdict("x.example.com").kind == "always_ask"


def test_rows_that_are_not_rules_are_skipped_and_counted_and_bad_category_rows_ignored():
    snapshot = snapshot_of(
        {"ch*se.com": "blocked", "ok.example.com": "nonsense", "fine.example.com": "blocked"},
        categories={"banks": "nope", "payments": "blocked", "crypto": "trusted"},
    )
    assert snapshot.skipped == 2
    assert [rule.pattern for rule in snapshot.rules] == ["fine.example.com"]
    assert snapshot.verdict("ok.example.com") == NO_VERDICT
    assert snapshot.category_kind("banks") == "always_ask"
    assert snapshot.category_kind("payments") == "always_ask"
    assert snapshot.category_kind("crypto") == "trusted"
    assert "skipped=2" in repr(snapshot)


def test_build_normalises_stored_patterns_and_keeps_rule_ids_as_strings():
    snapshot = SiteRuleSnapshot.build(
        [OwnerRule(id="6f0c", pattern="*.Bücher.DE.", kind="blocked")],
        {},
        enabled=True,
        loaded_at=12.5,
    )
    assert snapshot.rules == (OwnerRule(id="6f0c", pattern="*.xn--bcher-kva.de", kind="blocked"),)
    assert snapshot.loaded_at == 12.5
    assert snapshot.verdict("shop.bücher.de").rule_id == "6f0c"


def test_a_protected_host_is_never_blocked_even_by_a_stored_rule():
    snapshot = snapshot_of({"*.google.com": "blocked", "*.cardinalcommerce.com": "blocked"})
    verdict = snapshot.verdict("accounts.google.com")
    assert (verdict.kind, verdict.source, verdict.protected) == ("always_ask", "owner", True)
    assert snapshot.navigation_reason("https://accounts.google.com/signin", exempt=False) is None
    assert snapshot.verdict("acs.cardinalcommerce.com").protected
    # The rest of the blocked site stays blocked.
    assert snapshot.verdict("www.google.com").kind == "blocked"
    assert not snapshot.verdict("www.google.com").protected
    # Trusted and Always ask on a protected host are left as they are.
    trusted = snapshot_of({"*.paypal.com": "trusted"}).verdict("www.paypal.com")
    assert (trusted.kind, trusted.protected) == ("trusted", False)


def test_a_government_category_set_to_blocked_still_lets_its_sign_in_services_open():
    snapshot = snapshot_of(categories={"government": "blocked"})
    assert snapshot.navigation_reason("https://www.irs.gov/", exempt=False) == BLOCKED
    for host in ("secure.login.gov", "api.id.me"):
        verdict = snapshot.verdict(host)
        assert (verdict.kind, verdict.source, verdict.protected) == ("always_ask", "builtin", True)
        assert snapshot.navigation_reason(f"https://{host}/", exempt=False) is None


def test_navigation_reason_inside_the_checkout_window_skips_only_protected_and_bank_hosts():
    snapshot = snapshot_of(
        {
            "*.example-casino.com": "blocked",
            "*.wellsfargo.com": "blocked",
            "*.stripe.com": "blocked",
        },
        categories={"banks": "blocked", "brokers": "blocked"},
    )
    outside = {
        "https://secure.chase.com/3ds": BLOCKED,
        "https://www.fidelity.com/": BLOCKED,
        "https://example-casino.com/": BLOCKED,
        "https://connect.secure.wellsfargo.com/": BLOCKED,
        "https://js.stripe.com/v3": None,  # protected: never blocked at all
    }
    for url, reason in outside.items():
        assert snapshot.navigation_reason(url, exempt=False) == reason, url
    inside = {
        # A category-level Block cannot stop a bank's 3-D Secure page...
        "https://secure.chase.com/3ds": None,
        # ...nor an owner's Block on a bank (whoever blocked it, it is on the list)...
        "https://connect.secure.wellsfargo.com/": None,
        # ...but every other Blocked host still blocks inside the window (SEC-F4).
        "https://www.fidelity.com/": BLOCKED,
        "https://example-casino.com/": BLOCKED,
        "https://js.stripe.com/v3": None,
    }
    for url, reason in inside.items():
        assert snapshot.navigation_reason(url, exempt=True) == reason, url


def test_page_verdict_marks_an_exempted_bank_page_always_ask_so_it_still_gets_a_notice():
    snapshot = snapshot_of(categories={"banks": "blocked"})
    exempted = snapshot.page_verdict("https://secure.chase.com/3ds", exempt=True)
    assert (exempted.kind, exempted.exempted, exempted.category) == ("always_ask", True, "banks")
    assert snapshot.page_verdict("https://secure.chase.com/3ds", exempt=False).kind == "blocked"
    # Outside a Blocked verdict nothing is marked exempted.
    plain = snapshot_of().page_verdict("https://secure.chase.com/", exempt=True)
    assert (plain.kind, plain.exempted) == ("always_ask", False)
    assert read_notice("secure.chase.com", exempted) == messages.read_notice_exempt("secure.chase.com")
    assert card_note("secure.chase.com", exempted) == messages.card_note_exempt("secure.chase.com")


def test_exempt_in_checkout_window_is_protected_or_on_the_banks_list():
    assert exempt_in_checkout_window("secure.chase.com")
    assert exempt_in_checkout_window("https://acs.cardinalcommerce.com/x")
    assert exempt_in_checkout_window("www.paypal.com")
    assert not exempt_in_checkout_window("www.fidelity.com")
    assert not exempt_in_checkout_window("www.coinbase.com")
    assert not exempt_in_checkout_window("example.com")
    assert not exempt_in_checkout_window("")
    assert all(exempt_in_checkout_window(host) for host in _bases(BANKS.sites))


def test_always_ask_and_trusted_never_stop_a_navigation():
    snapshot = snapshot_of({"*.example.com": "always_ask", "*.example.org": "trusted"})
    for url in ("https://www.example.com/", "https://example.org/", "https://secure.chase.com/"):
        assert snapshot.navigation_reason(url, exempt=False) is None, url
        assert snapshot.navigation_reason(url, exempt=True) is None, url


def test_with_the_switch_off_nothing_has_a_verdict():
    snapshot = snapshot_of(
        {"*.example-casino.com": "blocked"}, categories={"banks": "blocked"}, enabled=False
    )
    assert not snapshot.enabled
    for host in ("example-casino.com", "secure.chase.com", "www.coinbase.com"):
        assert snapshot.verdict(host) == NO_VERDICT, host
        assert snapshot.navigation_reason(f"https://{host}/", exempt=False) is None, host
    # The rules are still there for the Check box ("if they were on").
    assert snapshot.would_apply("example-casino.com").kind == "blocked"


@pytest.mark.parametrize(
    "url",
    [
        "https://BÜCHER.de:443/katalog",
        "https://shop.xn--bcher-kva.de./",
        "https://user:pw@Example.COM.:8443/x?y=1",
        "EXAMPLE.com",
        "http://example.com%2e/",
        "blob:https://example.com/0b1c",
        "view-source:https://example.com/",
    ],
)
def test_hosts_match_after_idna_case_port_and_trailing_dot_normalisation(url):
    snapshot = snapshot_of({"*.bücher.de": "blocked", "example.com": "blocked"})
    assert snapshot.verdict(url).kind == "blocked"
    assert snapshot.navigation_reason(url, exempt=False) == BLOCKED


@pytest.mark.parametrize(
    "value",
    ["about:blank", "data:text/html,x", "chrome-error://chromewebdata/", "", None, 42, "https://[bad/"],
)
def test_urls_without_a_web_host_get_no_verdict_and_the_snapshot_never_raises(value):
    snapshot = snapshot_of({"*.example.com": "blocked"}, categories={"banks": "blocked"})
    assert snapshot.verdict(value) == NO_VERDICT
    assert snapshot.page_verdict(value, exempt=True) == NO_VERDICT
    assert snapshot.navigation_reason(value, exempt=False) is None
    assert snapshot.would_apply(value) == NO_VERDICT


def test_builtin_entry_and_overlapping_builtin_find_the_list_entry_behind_a_host_or_rule():
    assert builtin_entry("https://secure.chase.com/") == ("*.chase.com", ("banks",))
    assert builtin_entry("example.com") is None
    assert overlapping_builtin("secure.chase.com") == "*.chase.com"
    assert overlapping_builtin("*.chase.com") == "*.chase.com"
    # A broad rule that contains built-in entries overrides them too.
    assert overlapping_builtin("*.gov.au") in {"*.ato.gov.au", "*.my.gov.au", "*.servicesaustralia.gov.au"}
    assert overlapping_builtin("*.example-casino.com") is None
    assert overlapping_builtin("evilchase.com") is None
    assert overlapping_builtin("not a pattern") is None


@pytest.mark.parametrize(
    "pattern",
    [
        "*.gov.au",
        "*.chase.com",
        "secure.chase.com",
        "*.secure.chase.com",
        "chase.com",
        "*.co.uk",
        "*.com",
        "*.de",
        "*.ing.de",
        "*.state.gov",
        "*.example.com",
        "evilchase.com",
        "*.hase.com",
    ],
)
def test_overlapping_builtin_agrees_with_overlaps_against_every_built_in_entry(pattern):
    brute_force = [site for c in CATEGORIES for site in c.sites if overlaps(pattern, site)]
    found = overlapping_builtin(pattern)
    assert (found is not None) == bool(brute_force)
    assert found is None or found in brute_force


def test_card_notes_name_the_list_or_the_owner_rule_and_stay_under_two_hundred_characters():
    builtin = snapshot_of()
    assert card_note("secure.chase.com", builtin.verdict("secure.chase.com")) == (
        "Sensitive site: secure.chase.com is on the built-in Banks and money accounts list in "
        "Site rules. Look at the page before you approve."
    )
    owner = snapshot_of({"example-bank.test": "always_ask", "*.mybank.example": "always_ask"})
    assert card_note("example-bank.test", owner.verdict("example-bank.test")) == (
        "You marked example-bank.test Always ask in Site rules. Look at the page before you approve."
    )
    assert card_note("login.mybank.example", owner.verdict("login.mybank.example")) == (
        "You marked mybank.example and its subdomains Always ask in Site rules. Look at the page "
        "before you approve."
    )
    protected = snapshot_of({"*.okta.com": "blocked"})
    assert card_note("acme.okta.com", protected.verdict("acme.okta.com")) == (
        messages.card_note_protected("acme.okta.com")
    )
    # The longest host a URL can carry still gives a short note on every list.
    long_host = ".".join(["a" * 60] * 3) + ".x" * 30 + ".chase.com"
    long_rule = snapshot_of({f"*.{long_host}": "always_ask"})
    for c in CATEGORIES:
        site = f"{'b' * 60}.{'c' * 60}.{c.sites[0][2:]}"
        note = card_note(site, builtin.verdict(site))
        assert note is not None and len(note) <= messages.NOTE_LIMIT, c.key
        assert c.label in note
    note = card_note(long_host, long_rule.verdict(long_host))
    assert note is not None and len(note) <= messages.NOTE_LIMIT
    assert note.startswith("You marked …")


def test_read_notices_tell_the_model_reading_is_fine_and_actions_need_approval():
    snapshot = snapshot_of({"*.example-bank.test": "always_ask"})
    assert read_notice("secure.chase.com", snapshot.verdict("secure.chase.com")) == (
        "secure.chase.com is a sensitive site (Banks and money accounts list in Site rules). "
        "Reading it is fine; every action on it needs the person's approval, and the approval "
        "card will say it is a sensitive site."
    )
    assert read_notice("www.example-bank.test", snapshot.verdict("www.example-bank.test")) == (
        messages.read_notice_owner("www.example-bank.test")
    )
    protected = snapshot_of(categories={"government": "blocked"})
    assert read_notice("secure.login.gov", protected.verdict("secure.login.gov")) == (
        messages.read_notice_protected("secure.login.gov")
    )


def test_trusted_blocked_and_unlisted_sites_get_no_card_note_or_read_notice():
    snapshot = snapshot_of({"*.chase.com": "trusted", "*.example-casino.com": "blocked"})
    for host in ("secure.chase.com", "example-casino.com", "example.org"):
        verdict = snapshot.verdict(host)
        assert card_note(host, verdict) is None, host
        assert read_notice(host, verdict) is None, host


def test_the_check_explanation_names_the_rule_that_applies_and_says_when_rules_are_off():
    snapshot = snapshot_of(
        {"*.example-casino.com": "blocked", "docs.mybank.example": "trusted"},
        categories={"brokers": "blocked"},
    )
    assert snapshot.explain("secure.chase.com") == (
        "secure.chase.com is on the built-in Banks and money accounts list, so Crawler asks before "
        "every action there and notes when it reads there."
    )
    assert snapshot.explain("www.fidelity.com") == (
        "www.fidelity.com is on the built-in Brokers and investing list, which you set to Blocked, "
        "so Crawler never opens it or acts on it."
    )
    assert snapshot.explain("https://www.example-casino.com/x") == (
        "Your rule for example-casino.com and subdomains (Blocked) covers www.example-casino.com, "
        "so Crawler never opens it or acts on it."
    )
    assert snapshot.explain("docs.mybank.example") == (
        "Your rule for docs.mybank.example (Trusted) covers docs.mybank.example, so Crawler adds no "
        "extra warnings there (actions still need your approval)."
    )
    assert snapshot.explain("example.org") == (
        "No rule applies to example.org: Crawler treats it like any other site."
    )
    protected = snapshot_of({"*.google.com": "blocked"})
    assert protected.explain("accounts.google.com") == messages.EXPLAIN_PROTECTED.format(
        host="accounts.google.com"
    )
    off = snapshot_of({"*.example-casino.com": "blocked"}, enabled=False)
    assert off.explain("example-casino.com") == (
        "Site rules are off, so nothing applies now. If they were on: Your rule for "
        "example-casino.com and subdomains (Blocked) covers example-casino.com, so Crawler never "
        "opens it or acts on it."
    )


def test_tool_refusals_and_guard_reasons_read_as_the_spec_says():
    assert messages.blocked_call("example-casino.com") == (
        "example-casino.com is blocked in this Crawler's Site rules, so Crawler did not open it or "
        "act on it. The owner can change this on the Security page (Site rules)."
    )
    assert "secure.chase.com" in messages.blocked_page("secure.chase.com")
    assert messages.NAVIGATION_BLOCKED == "the site is blocked in this Crawler's Site rules"
    assert messages.NAVIGATION_UNAVAILABLE == "the owner's site rules could not be read"
    # Hosts are shortened from the left, so the site's own name stays visible.
    long_host = "a" * 200 + ".example-casino.com"
    refusal = messages.blocked_call(long_host)
    assert "…" in refusal and "example-casino.com is blocked" in refusal
    assert len(messages.short_host(long_host)) == messages.HOST_SHOWN


# --- Hostile spellings and hostile lengths (checker findings, early core) ---


def _spelled(*parts: object) -> str:
    """A string from text pieces and code points (no invisible characters
    pasted into the source)."""
    return "".join(chr(part) if isinstance(part, int) else str(part) for part in parts)


@pytest.mark.parametrize(
    "parts",
    [
        ("c", 0x3164, "hase.com"),  # Hangul filler, dropped by the browser
        ("c", 0xE0100, "hase.com"),  # variation selector 17
        ("c", 0x2064, "hase.com"),  # invisible plus
        ("c", 0x180E, "hase.com"),  # Mongolian vowel separator
        (0x1D9C, "hase.com"),  # modifier letter small c
        (0x1CCD8, 0x1CCDD, 0x1CCD6, 0x1CCE8, 0x1CCDA, ".com"),  # outlined letters
        ("CHASE", 0xFF0E, "COM"),  # full-width full stop
    ],
)
def test_a_blocked_site_stays_blocked_however_invisible_or_newer_letters_spell_it(parts):
    # Each spelling opens chase.com in Chromium; the rule must see chase.com too.
    snapshot = snapshot_of({"chase.com": "blocked"})
    url = _spelled("https://", *parts, "/login")
    verdict = snapshot.verdict(url)
    assert (verdict.kind, verdict.source, verdict.pattern) == ("blocked", "owner", "chase.com")
    assert snapshot.navigation_reason(url, exempt=False) == BLOCKED


@pytest.mark.parametrize(
    "url",
    [
        # The checker's case: a megabyte host of ten-letter labels (36 s before).
        "https://" + ".".join(["abcdefghij"] * 100_000) + ".example-casino.com/",
        # A megabyte of leading dots (each one used to shift the whole label list).
        "https://" + "." * 1_000_000 + "www.example-casino.com/",
        # One label of 20,000 distinct letters (the punycode encoder is quadratic).
        "https://" + "".join(chr(0x4E00 + i) for i in range(20_000)) + ".example-casino.com/",
        # The recheck's case: combining marks out of canonical order (NFKC
        # sorts them by insertion, quadratic), raw and percent-encoded (9.5 s
        # for a megabyte before the host was mapped label by label).
        "https://a" + "̖́" * 250_000 + ".example-casino.com/",
        "https://a" + "%CC%81%CC%96" * 90_000 + ".example-casino.com/",
        # Many labels of out-of-order marks, each just under the mapping limit.
        "https://" + ".".join(["̖́" * 1_000] * 250) + ".example-casino.com/",
        # A letter NFKC writes as eighteen (unicodedata grows its buffer slowly).
        "https://" + "ﷺ" * 100_000 + ".example-casino.com/",
    ],
    ids=[
        "ten-letter-labels",
        "leading-dots",
        "distinct-letters",
        "combining-marks",
        "percent-encoded-marks",
        "many-labels-of-marks",
        "eighteen-fold-letter",
    ],
)
def test_judging_a_megabyte_hostile_url_stays_fast_and_still_finds_the_rule(url):
    # The guard judges every frame a page opens, on the event loop, before
    # any DNS step. The bound is generous (the machine may be busy); the
    # work is a few passes over the URL, tens of milliseconds.
    import time

    snapshot = snapshot_of({"*.example-casino.com": "blocked", "*.chase.com": "trusted"})
    started = time.perf_counter()
    reason = snapshot.navigation_reason(url, exempt=True)
    verdict = snapshot.page_verdict(url, exempt=False)
    elapsed = time.perf_counter() - started
    assert reason == BLOCKED
    assert (verdict.kind, verdict.pattern) == ("blocked", "*.example-casino.com")
    assert elapsed < 5.0, f"{elapsed:.1f} s"


def test_a_stored_row_that_decodes_into_a_wildcard_is_skipped_not_read_as_one():
    # "%2a.com" is not a pattern parse_site writes; read leniently it became
    # "*.com" and blocked (or trusted) every .com site.
    blocked = snapshot_of({"%2a.com": "blocked", _spelled(0xFF0A, ".com"): "blocked"})
    assert blocked.skipped == 2 and blocked.rules == ()
    assert blocked.verdict("foo.com") == NO_VERDICT
    assert blocked.navigation_reason("https://www.fidelity.com/", exempt=False) is None
    trusted = snapshot_of({"%2a.com": "trusted"})
    verdict = trusted.verdict("www.fidelity.com")
    assert (verdict.kind, verdict.source, verdict.category) == ("always_ask", "builtin", "brokers")


def test_the_protected_downgrade_and_the_checkout_exemption_read_the_host_once():
    # A full-width @ reads as part of the host; a second reading would cut it
    # as userinfo and answer for accounts.google.com, a host the rule lookup
    # never saw. The browser refuses such a URL anyway; the verdict must not
    # depend on how often the host is read.
    url = _spelled("https://x", 0xFF20, "accounts.google.com/")
    snapshot = snapshot_of({"*.google.com": "blocked"})
    verdict = snapshot.verdict(url)
    assert (verdict.kind, verdict.protected) == ("blocked", False)
    assert snapshot.navigation_reason(url, exempt=True) == BLOCKED
    # The real sign-in host is still protected, and a real bank still exempt.
    assert snapshot.verdict("https://accounts.google.com/").protected
    banks = snapshot_of(categories={"banks": "blocked"})
    assert banks.navigation_reason("https://secure.chase.com/3ds", exempt=True) is None
