"""Searches Instructure's public directory of Canvas schools, so the Canvas
connect form can offer "find your school" instead of asking for an address.

Why it exists: most students do not know their school's Canvas address, and a
wrong one only fails later, on the token page. Instructure answers
``GET https://canvas.instructure.com/api/v1/accounts/search?name=...`` without
credentials, with each school's name and Canvas domain. ``search_schools`` asks
it through the guarded client (SSRF check and DNS pinning on every hop) under
its own narrow network policy, ``canvas_school_search`` in
core/network_security.py, keeps only answers whose domain is a plain hostname,
and caches them for a few minutes so a user typing a name does not send
Instructure a request per keystroke.

Used by ``GET /api/connectors/canvas/schools`` (api/routes/connectors.py).
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from core.network_security import CANVAS_SCHOOL_SEARCH_POLICY, check_network_policy
from services.tools.net import EgressBlocked, build_guarded_client

from .base import clean_display_text

SEARCH_URL = "https://canvas.instructure.com/api/v1/accounts/search"
# Asked of Instructure; the answer is cut to MAX_RESULTS after filtering.
PAGE_SIZE = 50
MAX_RESULTS = 20
NAME_MAX_CHARS = 120
TIMEOUT_S = 10.0
CACHE_TTL_S = 600.0
CACHE_MAX_ENTRIES = 256

# A plain DNS name: dot-separated labels of letters, digits and inner
# hyphens, at least two labels, and a last label that starts with a letter
# (so never an IP address). No scheme, port, path, userinfo or space fits.
_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(f"(?:{_LABEL}[.])+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?")
_DOMAIN_MAX_CHARS = 253


class SchoolSearchError(Exception):
    """Instructure's school directory could not be searched.

    The message is a short reason for the server log; it never holds the
    query or the request URL.
    """


@dataclass(frozen=True)
class CanvasSchool:
    """One school from the directory, ready to show and to fill the form."""

    name: str
    # The school's Canvas host, lowercased (nyit.instructure.com).
    domain: str


# Lowercased query -> (monotonic time stored, schools). Oldest first.
_cache: OrderedDict[str, tuple[float, tuple[CanvasSchool, ...]]] = OrderedDict()


def clear_cache() -> None:
    """Forget every cached answer (a test hook)."""
    _cache.clear()


def _policy_addresses(url: str) -> tuple[str, ...]:
    """The guarded client's resolver: this search's policy, then the
    addresses to pin. Refuses anything but the one search address."""
    result = check_network_policy(url, CANVAS_SCHOOL_SEARCH_POLICY)
    if not result.safe:
        raise EgressBlocked(
            result.reason or "The school search address is not allowed by the network policy."
        )
    return result.resolved_ips


def _plain_domain(value: Any) -> str:
    """*value* lowercased when it is a plain hostname, else ""."""
    if not isinstance(value, str) or not value.isascii():
        return ""
    domain = value.strip().lower()
    if len(domain) > _DOMAIN_MAX_CHARS or not _DOMAIN_RE.fullmatch(domain):
        return ""
    return domain


def parse_schools(payload: Any) -> list[CanvasSchool]:
    """The usable schools in a directory answer, first MAX_RESULTS of them.

    Drops entries without a name or with a domain that is not a plain
    hostname, and later entries for a domain already listed (several
    sub-accounts of one school share its Canvas host).
    """
    if not isinstance(payload, list):
        raise SchoolSearchError("the directory did not answer with a list")
    schools: list[CanvasSchool] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = clean_display_text(item.get("name"), NAME_MAX_CHARS)
        domain = _plain_domain(item.get("domain"))
        if not name or not domain or domain in seen:
            continue
        seen.add(domain)
        schools.append(CanvasSchool(name=name, domain=domain))
        if len(schools) == MAX_RESULTS:
            break
    return schools


async def _fetch(query: str, transport: Optional[httpx.AsyncBaseTransport]) -> list[CanvasSchool]:
    try:
        client = build_guarded_client(
            timeout_s=TIMEOUT_S,
            headers={"Accept": "application/json", "User-Agent": "Crawler-AI"},
            resolver=_policy_addresses,
            transport=transport,
            follow_redirects=False,
        )
        async with client:
            response = await client.get(
                SEARCH_URL, params={"name": query, "per_page": PAGE_SIZE}
            )
    except EgressBlocked as exc:
        raise SchoolSearchError(f"refused by the network policy: {exc}") from None
    except httpx.HTTPError as exc:
        # Only the type: an httpx message can carry the URL, query included.
        raise SchoolSearchError(f"the request failed ({type(exc).__name__})") from None
    if response.status_code != 200:
        raise SchoolSearchError(f"the directory answered HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError:  # JSONDecodeError and UnicodeDecodeError both
        raise SchoolSearchError("the directory did not answer with JSON") from None
    return parse_schools(payload)


async def search_schools(
    query: str, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> list[CanvasSchool]:
    """Schools whose name matches *query*, at most MAX_RESULTS of them.

    Raises ``SchoolSearchError`` when the policy refuses the request, it
    fails or times out, or the directory answers with anything but a JSON
    list. Answers are cached per lowercased query for CACHE_TTL_S, at most
    CACHE_MAX_ENTRIES of them; failures are not cached. *transport* is the
    test seam; the network policy still runs in front of it.
    """
    key = query.strip().lower()
    cached = _cache.get(key)
    if cached is not None and time.monotonic() - cached[0] < CACHE_TTL_S:
        return list(cached[1])
    schools = await _fetch(key, transport)
    _cache[key] = (time.monotonic(), tuple(schools))
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX_ENTRIES:
        _cache.popitem(last=False)
    return schools
