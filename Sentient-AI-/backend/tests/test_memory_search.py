"""Search and category filtering on GET /api/memories/.

Covers the two things a substring search gets wrong by default: LIKE
wildcards smuggled in through the query term, and a filter that forgets it
must still be owner-scoped.
"""

from __future__ import annotations

import httpx
import pytest

from services.memory import LIKE_ESCAPE_CHAR, MAX_SEARCH_CHARS, build_search_pattern


# ---------------------------------------------------------------------------
# Unit: pattern building
# ---------------------------------------------------------------------------


def test_blank_query_is_no_filter():
    assert build_search_pattern("") is None
    assert build_search_pattern("   \t\n ") is None
    assert build_search_pattern(None) is None


def test_pattern_wraps_term_in_wildcards():
    assert build_search_pattern("  kayak ") == "%kayak%"


def test_pattern_escapes_like_wildcards():
    # A bare "%" must not become the match-everything pattern "%%%".
    assert build_search_pattern("%") == f"%{LIKE_ESCAPE_CHAR}%%"
    assert build_search_pattern("_") == f"%{LIKE_ESCAPE_CHAR}_%"
    assert build_search_pattern("100%") == f"%100{LIKE_ESCAPE_CHAR}%%"


def test_pattern_escapes_the_escape_character():
    # Otherwise a trailing backslash would escape the closing wildcard and
    # turn the pattern into a literal-% match.
    assert build_search_pattern("a\\b") == "%a\\\\b%"


# ---------------------------------------------------------------------------
# Route: filtering
# ---------------------------------------------------------------------------


async def _auth(client: httpx.AsyncClient, email: str) -> dict[str, str]:
    await client.post(
        "/api/auth/register", json={"email": email, "password": "password-123"}
    )
    login = await client.post(
        "/api/auth/login", json={"email": email, "password": "password-123"}
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


async def _add(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    content: str,
    category: str = "fact",
) -> str:
    resp = await client.post(
        "/api/memories/",
        json={"content": content, "category": category},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _contents(
    client: httpx.AsyncClient, headers: dict[str, str], **params: object
) -> list[str]:
    resp = await client.get("/api/memories/", params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return [m["content"] for m in resp.json()]


@pytest.mark.asyncio
async def test_search_matches_substring(client: httpx.AsyncClient):
    headers = await _auth(client, "search-sub@example.com")
    await _add(client, headers, "Goes kayaking every Saturday")
    await _add(client, headers, "Roasts coffee at home")

    assert await _contents(client, headers, q="kayak") == [
        "Goes kayaking every Saturday"
    ]


@pytest.mark.asyncio
async def test_search_is_case_insensitive(client: httpx.AsyncClient):
    headers = await _auth(client, "search-case@example.com")
    await _add(client, headers, "Studies at NYIT in Manhattan")
    await _add(client, headers, "Roasts coffee at home")

    assert await _contents(client, headers, q="nyit") == [
        "Studies at NYIT in Manhattan"
    ]
    assert await _contents(client, headers, q="MANHATTAN") == [
        "Studies at NYIT in Manhattan"
    ]


@pytest.mark.asyncio
async def test_category_filter(client: httpx.AsyncClient):
    headers = await _auth(client, "search-cat@example.com")
    await _add(client, headers, "Prefers concise answers", category="preference")
    await _add(client, headers, "Building SentientAI", category="project")
    await _add(client, headers, "Lives in Queens", category="profile")

    assert await _contents(client, headers, category="project") == [
        "Building SentientAI"
    ]
    assert await _contents(client, headers, category="preference") == [
        "Prefers concise answers"
    ]


@pytest.mark.asyncio
async def test_invalid_category_is_rejected(client: httpx.AsyncClient):
    headers = await _auth(client, "search-badcat@example.com")
    resp = await client.get(
        "/api/memories/", params={"category": "not-a-category"}, headers=headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_search_and_category_combine(client: httpx.AsyncClient):
    headers = await _auth(client, "search-combo@example.com")
    await _add(client, headers, "Ships the memory page", category="project")
    await _add(client, headers, "Ships replies fast", category="preference")
    await _add(client, headers, "Writes the memory docs", category="profile")

    # Both clauses must apply — either one alone would return two rows.
    assert await _contents(client, headers, q="ships", category="project") == [
        "Ships the memory page"
    ]


@pytest.mark.asyncio
async def test_search_is_owner_scoped(client: httpx.AsyncClient):
    alice = await _auth(client, "alice-search@example.com")
    bob = await _auth(client, "bob-search@example.com")
    await _add(client, alice, "Alice goes kayaking on weekends")
    await _add(client, bob, "Bob goes kayaking on weekdays")

    # A matching memory belonging to someone else is still invisible.
    assert await _contents(client, bob, q="kayaking") == [
        "Bob goes kayaking on weekdays"
    ]
    assert await _contents(client, alice, q="kayaking") == [
        "Alice goes kayaking on weekends"
    ]


@pytest.mark.asyncio
async def test_percent_in_query_is_not_a_wildcard(client: httpx.AsyncClient):
    headers = await _auth(client, "search-pct@example.com")
    await _add(client, headers, "Battery health sits at 100% capacity")
    await _add(client, headers, "Roasts coffee at home")

    # Unescaped this is "%%%", which matches every row.
    assert await _contents(client, headers, q="%") == [
        "Battery health sits at 100% capacity"
    ]
    assert await _contents(client, headers, q="100%") == [
        "Battery health sits at 100% capacity"
    ]
    # And a term whose wildcard reading would match must still miss.
    assert await _contents(client, headers, q="at 100% cap") == [
        "Battery health sits at 100% capacity"
    ]
    assert await _contents(client, headers, q="1%y") == []


@pytest.mark.asyncio
async def test_underscore_in_query_is_not_a_wildcard(client: httpx.AsyncClient):
    headers = await _auth(client, "search-underscore@example.com")
    await _add(client, headers, "Prefers snake_case identifiers")
    await _add(client, headers, "Roasts coffee at home")

    # Unescaped this is "%_%", which matches every non-empty row.
    assert await _contents(client, headers, q="_") == [
        "Prefers snake_case identifiers"
    ]
    # "sn_ke" as a wildcard would match "snake"; as a literal it matches
    # nothing.
    assert await _contents(client, headers, q="sn_ke") == []
    assert await _contents(client, headers, q="snake_case") == [
        "Prefers snake_case identifiers"
    ]


@pytest.mark.asyncio
async def test_blank_query_returns_everything(client: httpx.AsyncClient):
    headers = await _auth(client, "search-blank@example.com")
    await _add(client, headers, "Goes kayaking every Saturday")
    await _add(client, headers, "Roasts coffee at home")

    for blank in ("", "   "):
        assert len(await _contents(client, headers, q=blank)) == 2
    # Contrast: a real term does filter, so the above is "no filter" and not
    # "the filter is broken".
    assert len(await _contents(client, headers, q="kayak")) == 1


@pytest.mark.asyncio
async def test_overlong_query_is_rejected(client: httpx.AsyncClient):
    headers = await _auth(client, "search-long@example.com")
    await _add(client, headers, "Goes kayaking every Saturday")

    at_cap = await client.get(
        "/api/memories/", params={"q": "k" * MAX_SEARCH_CHARS}, headers=headers
    )
    assert at_cap.status_code == 200

    over_cap = await client.get(
        "/api/memories/", params={"q": "k" * (MAX_SEARCH_CHARS + 1)}, headers=headers
    )
    assert over_cap.status_code == 422


@pytest.mark.asyncio
async def test_null_byte_in_query_is_rejected(client: httpx.AsyncClient):
    headers = await _auth(client, "search-nul@example.com")
    # asyncpg cannot bind a NUL byte, so on Postgres an unvalidated term
    # would surface as an opaque 500 instead of a 422.
    resp = await client.get(
        "/api/memories/", params={"q": "kayak\x00"}, headers=headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_search_requires_auth(client: httpx.AsyncClient):
    resp = await client.get("/api/memories/", params={"q": "kayak"})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_pagination_applies_to_the_filtered_set(client: httpx.AsyncClient):
    headers = await _auth(client, "search-page@example.com")
    for i in range(3):
        await _add(client, headers, f"Roasts coffee batch {i}")
        await _add(client, headers, f"Goes kayaking on trip {i}")

    # LIMIT/OFFSET must window the matches, not the whole table — otherwise
    # page 2 of a search would come back empty.
    page_one = await _contents(client, headers, q="kayaking", limit=2, offset=0)
    page_two = await _contents(client, headers, q="kayaking", limit=2, offset=2)
    assert len(page_one) == 2
    assert len(page_two) == 1
    assert all("kayaking" in c for c in page_one + page_two)
    assert not set(page_one) & set(page_two)
