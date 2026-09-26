"""Money parsing for the checkout toolkit: the table of strings a checkout
page writes a price in, what parses to nothing, and the USD-only helpers.
Pure; no browser."""

from __future__ import annotations

from decimal import Decimal

import pytest

from services.tools.browser.checkout.amounts import Money, fmt_usd, parse_money, usd


@pytest.mark.parametrize(
    "text, amount, currency",
    [
        ("$1,234.50", "1234.50", "USD"),
        ("$23.40", "23.40", "USD"),
        ("$ 12", "12", "USD"),
        ("US$ 12", "12", "USD"),
        ("us$12", "12", "USD"),
        ("USD 12.00", "12.00", "USD"),
        ("12.00 USD", "12.00", "USD"),
        ("USD12", "12", "USD"),
        ("Total: $23.40 USD", "23.40", "USD"),
        ("$1,234", "1234", "USD"),
        ("$0.99", "0.99", "USD"),
        ("€23,40", "23.40", "EUR"),
        ("1.234,50 €", "1234.50", "EUR"),
        ("1 234,50 EUR", "1234.50", "EUR"),
        ("£10", "10", "GBP"),
        ("¥1200", "1200", "JPY"),
        ("CA$ 5", "5", "CAD"),
        ("A$5.50", "5.50", "AUD"),
        ("₹499", "499", "INR"),
        ("12,5 USD", "12.5", "USD"),
        ("Concert ticket — $19.00", "19.00", "USD"),
    ],
)
def test_parse_money_table(text, amount, currency):
    assert parse_money(text) == Money(Decimal(amount), currency)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "12 items",
        "Total: 2 items",
        "junk",
        "-$5.00",
        "−$5.00",
        "($5.00)",
        "1,2,3",
        "$1,23,4",
        "$1.2.3",
        "call 800 555 0199",
    ],
)
def test_parse_money_refuses_what_is_not_money(text):
    assert parse_money(text) is None


def test_parse_money_takes_the_first_amount_and_ignores_non_strings():
    assert parse_money("$19.00 then $4.40") == Money(Decimal("19.00"), "USD")
    assert parse_money(None) is None  # type: ignore[arg-type]
    assert parse_money(23.4) is None  # type: ignore[arg-type]


def test_parse_money_caps_absurd_amounts():
    assert parse_money("$1,000,000,000.00") is None
    assert parse_money("$999,999.99") == Money(Decimal("999999.99"), "USD")


def test_money_is_frozen():
    money = Money(Decimal("1"), "USD")
    with pytest.raises(AttributeError):
        money.amount = Decimal("2")  # type: ignore[misc]


def test_usd_is_only_for_us_dollars():
    assert usd(Money(Decimal("23.40"), "USD")) == Decimal("23.40")
    assert usd(Money(Decimal("23.40"), "EUR")) is None
    assert usd(None) is None


@pytest.mark.parametrize(
    "amount, text",
    [("23.4", "23.40"), ("23", "23.00"), ("23.405", "23.41"), ("1234.5", "1234.50"), ("0", "0.00")],
)
def test_fmt_usd(amount, text):
    assert fmt_usd(Decimal(amount)) == text
