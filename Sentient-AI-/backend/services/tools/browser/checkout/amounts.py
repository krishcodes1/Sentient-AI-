"""Money as a checkout page writes it ("$1,234.50", "US$ 12", "€23,40",
"12.00 USD") -> an exact Decimal with its ISO currency.

Why: the amount Crawler pays is read off the page, never taken from the
model's words, so the page's string must become a number the cap check
can compare exactly (Decimal, never float) and anything that is not
clearly money must parse to nothing rather than to a guess. Only USD is
paid (``usd``); other currencies parse so the refusal can say which one
the page is in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Optional

_CENT = Decimal("0.01")
# The largest amount a checkout page could plausibly show; anything above
# is a parsing accident (a phone number next to a "$"), not a total.
_MAX_AMOUNT = Decimal("1000000")

# Symbols that name a currency on their own. Longer ones first so "US$"
# is not read as "$" (USD would still be right there, but "CA$" must not
# become USD). A bare "$" is taken as USD: the one currency Crawler pays.
_SYMBOLS: tuple[tuple[str, str], ...] = (
    ("US$", "USD"),
    ("CA$", "CAD"),
    ("AU$", "AUD"),
    ("NZ$", "NZD"),
    ("MX$", "MXN"),
    ("HK$", "HKD"),
    ("R$", "BRL"),
    ("C$", "CAD"),
    ("A$", "AUD"),
    ("S$", "SGD"),
    ("$", "USD"),
    ("€", "EUR"),
    ("£", "GBP"),
    ("¥", "JPY"),
    ("₹", "INR"),
    ("₩", "KRW"),
    ("₱", "PHP"),
    ("₺", "TRY"),
)
_CODES: tuple[str, ...] = (
    "USD", "EUR", "GBP", "CAD", "AUD", "NZD", "JPY", "INR", "CHF", "MXN", "BRL", "SGD",
    "HKD", "KRW", "SEK", "NOK", "DKK", "PLN", "CNY", "PHP", "TRY", "ZAR",
)
_SYMBOL_BY_TEXT = dict(_SYMBOLS)

_SYMBOL_RE = "|".join(re.escape(symbol) for symbol, _ in _SYMBOLS)
_CODE_RE = "|".join(_CODES)
# Digits with optional thousands groups and an optional decimal part, in
# either convention ("1,234.50", "1.234,50", "1 234,50", "23,40", "12").
_NUMBER_RE = r"\d+(?:[.,   ]\d+)*"
_MONEY_RE = re.compile(
    rf"(?P<lead>[-−(]\s*)?"
    rf"(?:(?P<sym>{_SYMBOL_RE})\s?(?P<num1>{_NUMBER_RE})"
    rf"|(?<![A-Za-z])(?P<code>{_CODE_RE})(?![A-Za-z])\s?(?P<num2>{_NUMBER_RE})"
    rf"|(?P<num3>{_NUMBER_RE})\s?(?:(?P<sym2>{_SYMBOL_RE})|(?<![A-Za-z])(?P<code2>{_CODE_RE})(?![A-Za-z])))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Money:
    amount: Decimal
    currency: str


def _normalise_number(text: str) -> Optional[Decimal]:
    """The digits of one price as a Decimal, whichever convention wrote
    them. Both separators present: the last one is the decimal point. One
    kind only: a single separator followed by one or two digits is a
    decimal point, anything else groups thousands."""
    text = re.sub(r"[   ]", "", text)
    if "," in text and "." in text:
        decimal_sep = "," if text.rfind(",") > text.rfind(".") else "."
        thousands_sep = "." if decimal_sep == "," else ","
        text = text.replace(thousands_sep, "")
        if text.count(decimal_sep) != 1:
            return None
        text = text.replace(decimal_sep, ".")
    else:
        sep = "," if "," in text else "." if "." in text else ""
        if sep:
            head, _, tail = text.rpartition(sep)
            if text.count(sep) == 1 and 1 <= len(tail) <= 2:
                text = f"{head}.{tail}"
            elif all(len(group) == 3 for group in text.split(sep)[1:]):
                text = text.replace(sep, "")
            else:
                return None
    try:
        amount = Decimal(text)
    except InvalidOperation:
        return None
    if not amount.is_finite() or amount < 0 or amount > _MAX_AMOUNT:
        return None
    return amount


def parse_money(text: str) -> Optional[Money]:
    """The first amount in *text* that carries a currency, or None.

    A negative or parenthesised amount (a discount line) is not money to
    pay and is skipped; so is anything with no currency mark at all, since
    "2" next to "items" must never become two dollars.
    """
    if not isinstance(text, str):
        return None
    for match in _MONEY_RE.finditer(text):
        if match.group("lead"):
            continue
        number = match.group("num1") or match.group("num2") or match.group("num3") or ""
        amount = _normalise_number(number)
        if amount is None:
            continue
        symbol = match.group("sym") or match.group("sym2")
        if symbol is not None:
            # The regex is case-insensitive ("us$"); the table is upper-case.
            currency = _SYMBOL_BY_TEXT.get(symbol.upper(), "USD")
        else:
            currency = (match.group("code") or match.group("code2") or "").upper()
        return Money(amount=amount, currency=currency)
    return None


def usd(money: Optional[Money]) -> Optional[Decimal]:
    """The amount when it is in US dollars; None for any other currency
    (or no money), so a EUR total can never pass a USD cap check."""
    if money is None or money.currency != "USD":
        return None
    return money.amount


def fmt_usd(amount: Decimal) -> str:
    """``"23.40"``: two decimals, no symbol, the form cards and audit rows
    carry so every channel formats the same number the same way."""
    return str(Decimal(amount).quantize(_CENT, rounding=ROUND_HALF_UP))
