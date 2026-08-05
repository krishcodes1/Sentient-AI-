"""Conversation search (GET /agent/conversations?q=).

The search spans titles and message bodies, which makes three things worth
pinning: it must never cross accounts, it must not treat a user's text as a
LIKE pattern, and a conversation with several matching messages must come
back once.
"""

from __future__ import annotations

import uuid as _uuid

import pytest

from models.conversation import Message, MessageRole
from tests.conftest import auth_headers


async def _account(client, email: str):
    await client.post(
        "/api/auth/register", json={"email": email, "password": "password-123"}
    )
    login = await client.post(
        "/api/auth/login", json={"email": email, "password": "password-123"}
    )
    return auth_headers(login.json()["access_token"])


async def _conversation(client, headers, title: str) -> str:
    resp = await client.post(
        "/api/agent/conversations", json={"title": title}, headers=headers
    )
    return resp.json()["id"]


async def _add_messages(session_factory, conversation_id: str, *contents: str):
    async with session_factory() as session:
        for content in contents:
            session.add(
                Message(
                    conversation_id=_uuid.UUID(conversation_id),
                    role=MessageRole.user,
                    content=content,
                )
            )
        await session.commit()


async def _search(client, headers, term):
    resp = await client.get(
        "/api/agent/conversations", params={"q": term}, headers=headers
    )
    assert resp.status_code == 200
    return [c["title"] for c in resp.json()]


@pytest.mark.asyncio
async def test_search_matches_conversation_titles(client):
    headers = await _account(client, "titles@example.com")
    await _conversation(client, headers, "Thesis outline")
    await _conversation(client, headers, "Grocery list")

    assert await _search(client, headers, "thesis") == ["Thesis outline"]


@pytest.mark.asyncio
async def test_search_matches_message_contents(client, session_factory):
    headers = await _account(client, "bodies@example.com")
    target = await _conversation(client, headers, "Untitled")
    await _conversation(client, headers, "Other")
    await _add_messages(session_factory, target, "remind me about the dentist")

    assert await _search(client, headers, "dentist") == ["Untitled"]


@pytest.mark.asyncio
async def test_search_is_case_insensitive(client, session_factory):
    headers = await _account(client, "case@example.com")
    conv = await _conversation(client, headers, "Untitled")
    await _add_messages(session_factory, conv, "The Eiffel Tower is in Paris")

    assert await _search(client, headers, "EIFFEL") == ["Untitled"]
    assert await _search(client, headers, "eiffel") == ["Untitled"]


@pytest.mark.asyncio
async def test_conversation_with_many_matches_is_returned_once(
    client, session_factory
):
    headers = await _account(client, "dupes@example.com")
    conv = await _conversation(client, headers, "Untitled")
    await _add_messages(
        session_factory, conv, *["dentist appointment" for _ in range(5)]
    )

    results = await _search(client, headers, "dentist")
    assert results == ["Untitled"], f"expected one row, got {results}"


@pytest.mark.asyncio
async def test_title_and_message_match_still_returns_one_row(
    client, session_factory
):
    headers = await _account(client, "both@example.com")
    conv = await _conversation(client, headers, "dentist")
    await _add_messages(session_factory, conv, "dentist again")

    assert await _search(client, headers, "dentist") == ["dentist"]


@pytest.mark.asyncio
async def test_search_never_crosses_accounts(client, session_factory):
    owner = await _account(client, "owner@example.com")
    conv = await _conversation(client, owner, "Owner secret plan")
    await _add_messages(session_factory, conv, "the password is hunter2")

    intruder = await _account(client, "intruder@example.com")

    assert await _search(client, intruder, "secret") == []
    assert await _search(client, intruder, "hunter2") == []


@pytest.mark.asyncio
async def test_percent_is_matched_literally_not_as_a_wildcard(
    client, session_factory
):
    """A bare % would otherwise match every conversation the user owns."""
    headers = await _account(client, "wildcard@example.com")
    match = await _conversation(client, headers, "Scored 100% on the exam")
    await _add_messages(session_factory, match, "nice")
    await _conversation(client, headers, "Unrelated thread")

    assert await _search(client, headers, "100%") == ["Scored 100% on the exam"]
    # A lone % is text, not "everything".
    assert await _search(client, headers, "%") == ["Scored 100% on the exam"]


@pytest.mark.asyncio
async def test_underscore_is_matched_literally(client):
    headers = await _account(client, "underscore@example.com")
    await _conversation(client, headers, "draft_1 notes")
    await _conversation(client, headers, "draftX1 notes")

    assert await _search(client, headers, "draft_1") == ["draft_1 notes"]


@pytest.mark.asyncio
async def test_blank_query_behaves_as_no_filter(client):
    headers = await _account(client, "blank@example.com")
    await _conversation(client, headers, "First")
    await _conversation(client, headers, "Second")

    for term in ("", "   "):
        assert len(await _search(client, headers, term)) == 2


@pytest.mark.asyncio
async def test_no_matches_returns_empty_list(client):
    headers = await _account(client, "nomatch@example.com")
    await _conversation(client, headers, "Alpha")

    assert await _search(client, headers, "zzzznothing") == []


@pytest.mark.asyncio
async def test_over_long_query_is_rejected(client):
    headers = await _account(client, "long@example.com")

    resp = await client.get(
        "/api/agent/conversations", params={"q": "x" * 5000}, headers=headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_search_respects_pagination(client):
    headers = await _account(client, "paged@example.com")
    for i in range(5):
        await _conversation(client, headers, f"report {i}")

    resp = await client.get(
        "/api/agent/conversations",
        params={"q": "report", "limit": 2},
        headers=headers,
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 2
