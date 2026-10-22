"""The built-in sensitive sites (S7 Appendix A) and the protected sign-in,
CAPTCHA and payment hosts no Blocked rule ever applies to (Appendix B).

Why it exists: on banks, brokers, crypto exchanges and tax or government
portals every step an agent takes deserves the person's second look, from
the first boot and with no setup, so these four categories are Always ask
by default (the owner can change a whole category, or any single site, on
the Security page). Separately, some hosts must never be blocked, because
blocking them would stop a sign-in or an approved purchase half-way: the
sign-in and MFA pages the handoff detector knows, the CAPTCHA hosts, the
payment processors and the 3-D Secure services banks use.

Every built-in entry is ``"*." + domain`` (the site and every subdomain).
Payment processors and sign-in or CAPTCHA hosts are deliberately absent
from the categories (``tests/test_site_rules_sensitive_list.py`` pins it);
the two government sign-in services ``login.gov`` and ``id.me`` are both on
the government list and protected (``SENSITIVE_AND_PROTECTED``): protected
only forbids Blocked, so they stay Always ask at worst.

Pure data: no network, no I/O. It imports ``RuleKind`` only for type
checking, so ``patterns`` can import ``PROTECTED_PATTERNS`` from here
without a cycle. Category keys are stored in ``browser_site_rules`` rows
(``target_type="category"``) and never change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from services.tools.browser import handoff

if TYPE_CHECKING:
    from services.site_rules.patterns import RuleKind


@dataclass(frozen=True)
class Category:
    key: str  # "banks" | "brokers" | "crypto" | "government" (stable: stored in rows)
    label: str  # "Banks and money accounts", ... (the tab and the notes say it)
    sites: tuple[str, ...]  # "*.chase.com", ...


def _site_and_subdomains(domains: str) -> tuple[str, ...]:
    return tuple(f"*.{domain}" for domain in domains.split())


BANKS = Category(
    key="banks",
    label="Banks and money accounts",
    sites=_site_and_subdomains(
        """
        chase.com bankofamerica.com wellsfargo.com citi.com citibank.com usbank.com pnc.com
        truist.com capitalone.com tdbank.com ally.com discover.com americanexpress.com
        navyfederal.org usaa.com regions.com key.com fifththird.com huntington.com mtb.com
        citizensbank.com sofi.com chime.com marcus.com synchrony.com becu.org penfed.org
        zellepay.com cash.app wise.com
        barclays.co.uk hsbc.co.uk lloydsbank.com natwest.com santander.co.uk nationwide.co.uk
        halifax.co.uk rbs.co.uk monzo.com starlingbank.com revolut.com bankofireland.com aib.ie
        ing.nl ing.de deutsche-bank.de commerzbank.de sparkasse.de n26.com rabobank.nl
        abnamro.nl bbva.es caixabank.es
        rbcroyalbank.com td.com scotiabank.com bmo.com cibc.com tangerine.ca
        commbank.com.au westpac.com.au anz.com anz.com.au nab.com.au asb.co.nz
        hdfcbank.com icicibank.com axisbank.com onlinesbi.sbi kotak.com dbs.com.sg ocbc.com
        """
    ),
)

BROKERS = Category(
    key="brokers",
    label="Brokers and investing",
    sites=_site_and_subdomains(
        """
        fidelity.com vanguard.com schwab.com etrade.com robinhood.com tdameritrade.com
        interactivebrokers.com webull.com merrilledge.com ml.com morganstanley.com
        wealthfront.com betterment.com public.com stash.com acorns.com firstrade.com
        tastytrade.com ameriprise.com edwardjones.com empower.com tiaa.org troweprice.com
        trading212.com hl.co.uk ajbell.co.uk degiro.com etoro.com zerodha.com questrade.com
        wealthsimple.com commsec.com.au
        """
    ),
)

CRYPTO = Category(
    key="crypto",
    label="Crypto exchanges and wallets",
    sites=_site_and_subdomains(
        """
        coinbase.com binance.com binance.us kraken.com gemini.com crypto.com kucoin.com
        bitstamp.net okx.com bybit.com bitfinex.com blockchain.com uphold.com bitpanda.com
        bitget.com gate.io htx.com mexc.com upbit.com bithumb.com coinspot.com.au wazirx.com
        exodus.com metamask.io ledger.com trezor.io
        """
    ),
)

GOVERNMENT = Category(
    key="government",
    label="Tax and government services",
    sites=_site_and_subdomains(
        """
        irs.gov ssa.gov login.gov id.me healthcare.gov studentaid.gov va.gov medicare.gov
        uscis.gov treasurydirect.gov travel.state.gov
        service.gov.uk hmrc.gov.uk canada.ca cra-arc.gc.ca ato.gov.au my.gov.au
        servicesaustralia.gov.au incometax.gov.in gst.gov.in uidai.gov.in epfindia.gov.in
        elster.de impots.gouv.fr ameli.fr agenziaentrate.gov.it belastingdienst.nl digid.nl
        agenciatributaria.gob.es revenue.ie ird.govt.nz
        """
    ),
)

CATEGORIES: tuple[Category, ...] = (BANKS, BROKERS, CRYPTO, GOVERNMENT)
CATEGORY_KEYS: tuple[str, ...] = tuple(c.key for c in CATEGORIES)
# Every built-in site is Always ask until the owner changes its category
# (an override row) or the site itself (an owner host rule).
DEFAULT_CATEGORY_KIND: RuleKind = "always_ask"
# Inside an approved checkout's order window or its 3-D Secure hand-off, a
# Blocked verdict is set aside only for protected hosts and for hosts in
# this category, where card issuers' 3-D Secure pages live (scaffold A32,
# review SEC-F4). Any other owner Blocked rule still blocks there.
CHECKOUT_EXEMPT_CATEGORY = "banks"

# --- Protected hosts (Appendix B) -------------------------------------------

# The payment processors among checkout/merchant.py WELL_KNOWN_MERCHANTS
# (the sensitive-list test pins that each one is in that list).
PAYMENT_PROCESSORS: tuple[str, ...] = (
    "paypal.com", "stripe.com", "squareup.com", "venmo.com", "shopify.com",
)
# Hosts a purchase or a sign-in passes through that neither the handoff
# detector nor the merchant list names: processors' asset and API hosts,
# buy-now-pay-later checkouts, 3-D Secure services, identity providers.
_EXTRA_SITES: tuple[str, ...] = (
    "paypalobjects.com", "stripe.network", "braintreegateway.com", "braintree-api.com",
    "adyen.com", "klarna.com", "affirm.com", "afterpay.com", "checkout.com", "shop.app",
    "cardinalcommerce.com", "arcot.com", "3dsecure.io", "auth0.com", "login.gov", "id.me",
)
# Exact hosts only: their parent domains carry ordinary sites an owner may
# block (google.com, apple.com, live.com).
_EXTRA_EXACT: tuple[str, ...] = ("pay.google.com", "appleid.apple.com", "login.live.com")


def _protected_patterns() -> tuple[str, ...]:
    """Built from the handoff detector's lists at import time, so a sign-in
    host added there is protected here too."""
    patterns: list[str] = [f"*.{host.strip().lower()}" for host in handoff.MFA_HOSTS]
    # CAPTCHA_HOSTS mixes hosts and one path ("google.com/recaptcha"); a
    # path is not a host pattern, so it is left out.
    patterns += [
        f"*.{host.strip().lower()}" for host in handoff.CAPTCHA_HOSTS if "/" not in host
    ]
    patterns += [f"*.{host}" for host in PAYMENT_PROCESSORS]
    patterns += [f"*.{host}" for host in _EXTRA_SITES]
    patterns += list(_EXTRA_EXACT)
    return tuple(dict.fromkeys(patterns))


PROTECTED_PATTERNS: tuple[str, ...] = _protected_patterns()

# Built-in entries that are also protected: government sign-in services. They
# stay on the list (Always ask by default) and can never become Blocked.
SENSITIVE_AND_PROTECTED: frozenset[str] = frozenset({"*.login.gov", "*.id.me"})

_BY_KEY: dict[str, Category] = {c.key: c for c in CATEGORIES}


def category(key: str) -> Optional[Category]:
    """The built-in category stored under *key*, or None."""
    return _BY_KEY.get(key) if isinstance(key, str) else None
