"""Tests for the owner's site rules in the page fetchers beside the browser
and the web toolkit: ``watch.create``, the page-watch sweeper's background
checks and ``knowledge.add`` of a web page, each built on the S7 resolver
wrapper (``hooks.wrap_resolver`` with ``fail_closed=True``, as main.py
builds it). They prove that a Blocked site is refused with S7's own
sentence before any request leaves, that a watch saved before its site was
Blocked stops being fetched, that rules which were never read fetch
nothing (fail closed), and that a site no rule matches is saved, checked
and imported exactly as before.

Why it exists: Blocked means "Crawler never opens the site" (S7). Before
these seams were wrapped, a watch kept fetching a Blocked site in the
background with no card, and a web page saved to the knowledge base could
then be read back through knowledge.search. Every HTTP call is served by an
``httpx.MockTransport`` and every DNS answer by a stand-in; no network.
"""

from __future__ import annotations

import functools
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Optional

import httpx
import pytest
from sqlalchemy import select

from services.notifications.page_watch import PageWatchService
from services.site_rules import messages
from services.site_rules.hooks import wrap_resolver
from services.tools.knowledge import KnowledgeToolkit
from services.tools.watch import WatchFetchError, WatchToolkit, fetch_snapshot
from tests.conftest import make_user
from tests.site_rules_fakes import FakeSiteRules, snapshot_of

PUBLIC_ADDRESS = "93.184.216.34"
CASINO = "https://www.example-casino.com/promo?token=SECRET1"
CASINO_HOST = "www.example-casino.com"
NEWS = "https://news.example/story"
T0 = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
PAGE = (
    "<html><head><title>Story</title></head>"
    "<body><h1>Story</h1><p>Story text that stays the same.</p></body></html>"
)


class Resolver:
    """DNS stand-in: every host is public; records what it was asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, url: str) -> tuple[str, ...]:
        self.asked.append(url)
        return (PUBLIC_ADDRESS,)


class Web:
    """A mock transport serving the same page for every URL; records each request."""

    def __init__(self) -> None:
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if request.url.path == "/to-casino":
            return httpx.Response(302, headers={"location": CASINO})
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, text=PAGE)


def _blocking() -> FakeSiteRules:
    return FakeSiteRules(snapshot_of({"*.example-casino.com": "blocked"}))


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


async def _watches(session_factory, owner_id):
    from models.page_watch import PageWatch

    async with session_factory() as session:
        return (
            (await session.execute(select(PageWatch).where(PageWatch.user_id == owner_id)))
            .scalars()
            .all()
        )


# -- watch.create -------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_create_on_a_blocked_site_is_refused_with_s7s_sentence_and_nothing_is_saved(
    session_factory,
):
    owner, _ = await make_user(session_factory, "fetchers-watch@example.com")
    inner = Resolver()
    kit = WatchToolkit(session_factory, resolver=wrap_resolver(_blocking(), inner, fail_closed=True))

    result = await kit.create(str(owner.id), url=CASINO, label="Promos")
    assert result == {"ok": False, "error": messages.blocked_call(CASINO_HOST), "blocked": True}
    assert inner.asked == []  # no DNS query for a site the owner blocked
    assert await _watches(session_factory, owner.id) == []

    # A site no rule matches is saved exactly as before.
    saved = await kit.create(str(owner.id), url=NEWS, label="News")
    assert saved["ok"] is True and saved["url"] == NEWS
    assert inner.asked == [NEWS]
    assert [w.url for w in await _watches(session_factory, owner.id)] == [NEWS]


@pytest.mark.asyncio
async def test_watch_create_saves_nothing_while_the_site_rules_cannot_be_read(session_factory):
    owner, _ = await make_user(session_factory, "fetchers-watch-unread@example.com")
    inner = Resolver()
    kit = WatchToolkit(
        session_factory, resolver=wrap_resolver(FakeSiteRules(None), inner, fail_closed=True)
    )
    result = await kit.create(str(owner.id), url=NEWS, label="News")
    assert result == {"ok": False, "error": messages.UNAVAILABLE, "blocked": True}
    assert inner.asked == [] and await _watches(session_factory, owner.id) == []


# -- the page-watch sweeper ---------------------------------------------------


@pytest.mark.asyncio
async def test_a_watch_saved_before_its_site_was_blocked_is_no_longer_fetched(session_factory):
    from models.page_watch import PageWatch

    owner, _ = await make_user(session_factory, "fetchers-sweeper@example.com")
    rules = FakeSiteRules(snapshot_of({}))
    web, clock = Web(), Clock()
    fetch = functools.partial(
        fetch_snapshot,
        resolver=wrap_resolver(rules, Resolver(), fail_closed=True),
        transport=httpx.MockTransport(web),
    )
    sweeper = PageWatchService(session_factory, send=None, fetch=fetch, clock=clock)
    async with session_factory() as session:
        watch = PageWatch(
            user_id=owner.id,
            url=CASINO,
            label="Promos",
            interval_minutes=60,
            next_check_at=T0,
            created_at=T0 - timedelta(days=1),
        )
        session.add(watch)
        await session.commit()
        watch_id = watch.id

    # No rule yet: the first check records the baseline, as before.
    assert await sweeper.sweep_once() == 1
    assert web.requests == [CASINO]
    async with session_factory() as session:
        row = await session.get(PageWatch, watch_id)
        assert row.last_hash is not None and row.consecutive_errors == 0

    # The owner blocks the site: the next check opens nothing and records
    # S7's sentence as the reason (watch.list and the stop message show it).
    rules.snapshot = _blocking().snapshot
    clock.now += timedelta(hours=2)
    assert await sweeper.sweep_once() == 1
    assert web.requests == [CASINO]
    async with session_factory() as session:
        row = await session.get(PageWatch, watch_id)
        assert row.last_error == messages.blocked_call(CASINO_HOST)
        assert row.consecutive_errors == 1

    # Rules that cannot be read: still nothing is fetched (fail closed).
    rules.snapshot = None
    clock.now += timedelta(days=2)
    assert await sweeper.sweep_once() == 1
    assert web.requests == [CASINO]
    async with session_factory() as session:
        row = await session.get(PageWatch, watch_id)
        assert row.last_error == messages.UNAVAILABLE and row.consecutive_errors == 2


@pytest.mark.asyncio
async def test_a_check_redirected_into_a_blocked_site_is_refused_before_that_hop():
    web = Web()
    with pytest.raises(WatchFetchError) as caught:
        await fetch_snapshot(
            "https://news.example/to-casino",
            resolver=wrap_resolver(_blocking(), Resolver(), fail_closed=True),
            transport=httpx.MockTransport(web),
        )
    assert str(caught.value) == messages.blocked_call(CASINO_HOST)
    assert web.requests == ["https://news.example/to-casino"]
    # A page no rule matches is read as before.
    snapshot = await fetch_snapshot(
        NEWS,
        resolver=wrap_resolver(_blocking(), Resolver(), fail_closed=True),
        transport=httpx.MockTransport(web),
    )
    assert "Story text that stays the same." in snapshot.text


# -- knowledge.add of a web page ---------------------------------------------


async def _gate_on(_key: str) -> Optional[str]:
    return None


def _knowledge(session_factory, rules: FakeSiteRules, web: Web, inner: Resolver) -> KnowledgeToolkit:
    files = SimpleNamespace(store=None, registry=None, sandbox=None)
    return KnowledgeToolkit(
        session_factory,
        executor_getter=lambda: None,
        files_getter=lambda: files,
        capability_refusal=_gate_on,
        url_transport=httpx.MockTransport(web),
        url_resolver=wrap_resolver(rules, inner, fail_closed=True),
    )


@pytest.mark.asyncio
async def test_a_web_page_on_a_blocked_site_is_never_saved_to_the_knowledge_base(session_factory):
    from models.knowledge import KbDocument

    owner, _ = await make_user(session_factory, "fetchers-knowledge@example.com")
    user_id = str(owner.id)
    web, inner = Web(), Resolver()
    toolkit = _knowledge(session_factory, _blocking(), web, inner)

    result = await toolkit.execute("add", {"collection": "Reading", "url": CASINO}, user_id)
    assert result["ok"] is False
    (item,) = result["items"]
    assert item["status"] == "error" and item["error"] == messages.blocked_call(CASINO_HOST)
    assert web.requests == [] and inner.asked == []
    # A redirect into the Blocked site is refused before that hop too.
    redirected = await toolkit.execute(
        "add", {"collection": "Reading", "url": "https://news.example/to-casino"}, user_id
    )
    assert redirected["items"][0]["error"] == messages.blocked_call(CASINO_HOST)
    assert web.requests == ["https://news.example/to-casino"]
    async with session_factory() as session:
        assert (await session.execute(select(KbDocument))).scalars().all() == []

    # A page no rule matches is saved exactly as before.
    saved = await toolkit.execute("add", {"collection": "Reading", "url": NEWS}, user_id)
    assert saved["ok"] is True, saved
    assert saved["items"][0]["status"] == "ready"
    async with session_factory() as session:
        (doc,) = (await session.execute(select(KbDocument))).scalars().all()
    assert doc.source_ref == NEWS


@pytest.mark.asyncio
async def test_a_web_page_is_not_imported_while_the_site_rules_cannot_be_read(session_factory):
    owner, _ = await make_user(session_factory, "fetchers-knowledge-unread@example.com")
    web, inner = Web(), Resolver()
    toolkit = _knowledge(session_factory, FakeSiteRules(None), web, inner)
    result = await toolkit.execute("add", {"collection": "Reading", "url": NEWS}, str(owner.id))
    assert result["ok"] is False
    assert result["items"][0]["error"] == messages.UNAVAILABLE
    assert web.requests == [] and inner.asked == []
    # A note opens no site, so it is saved whatever the rules say.
    note = await toolkit.execute(
        "add", {"collection": "Reading", "text": "Chapter one is due Friday.", "title": "Due"}, str(owner.id)
    )
    assert note["ok"] is True, note
