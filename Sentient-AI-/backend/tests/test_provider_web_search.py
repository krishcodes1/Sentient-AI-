"""Tests for the provider's own web search (Gemini's Google Search grounding): the
request it sends, the sources it returns, and how a turn reaches it.

Why it exists: web.search had two keyless engines and both failed from an ordinary
home connection (one answers every request with a bot check, the other with results
for the first word of the query only), so the assistant could not find a page it was
asked for. The turn's own provider can search; what comes back must be the pages the
search cited, never the model's prose, which paraphrases and invents addresses.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from services.agent import turn_context
from services.agent.providers import GeminiProvider, ProviderError
from services.tools.web import WebToolkit

GROUNDED = {
    "candidates": [
        {
            "finishReason": "STOP",
            "content": {
                "parts": [
                    {
                        "text": (
                            "AMC Lincoln Square 13 Showtimes - Movie times at the theatre.\n"
                            "Paper Tiger tickets - See https://invented.example/not-a-real-page"
                        )
                    }
                ]
            },
            "groundingMetadata": {
                "webSearchQueries": ["paper tiger amc lincoln square"],
                "groundingChunks": [
                    {"web": {"uri": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/AAA", "title": "amctheatres.com"}},
                    {"web": {"uri": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/BBB", "title": "fandango.com"}},
                    {"web": {"uri": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/CCC", "title": "unused.example"}},
                    {"retrievedContext": {"uri": "gs://not-a-web-source"}},
                ],
                "groundingSupports": [
                    {
                        "segment": {"text": "AMC Lincoln Square 13 Showtimes - Movie times at the theatre."},
                        "groundingChunkIndices": [0],
                    },
                    {
                        "segment": {"text": "Paper Tiger tickets - See https://invented.example/not-a-real-page"},
                        "groundingChunkIndices": [1, 0],
                    },
                ],
            },
        }
    ],
    "usageMetadata": {"promptTokenCount": 63, "candidatesTokenCount": 97, "toolUsePromptTokenCount": 40},
}


def provider_answering(body: dict[str, Any], sent: list[dict[str, Any]], status: int = 200) -> GeminiProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(status, json=body)

    provider = GeminiProvider(api_key="k", model="gemini-3.5-flash-lite")
    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"x-goog-api-key": "k"}
    )
    return provider


@pytest.mark.asyncio
async def test_search_web_asks_for_google_search_and_returns_only_what_it_cited():
    sent: list[dict[str, Any]] = []
    provider = provider_answering(GROUNDED, sent)
    found = await provider.search_web("  Paper Tiger   AMC Lincoln Square  ", max_results=5)
    await provider.aclose()

    request = sent[0]
    assert request["tools"] == [{"google_search": {}}]  # the search tool alone: no functions
    assert "systemInstruction" not in request
    asked = request["contents"][0]["parts"][0]["text"]
    assert "Paper Tiger AMC Lincoln Square" in asked  # the query, whitespace collapsed
    assert request["generationConfig"]["maxOutputTokens"] <= 1000

    # The cited pages in the search's own order, each with the lines it supported;
    # a page nothing cited and a non-web source are left out.
    assert found["sources"] == [
        {
            "site": "amctheatres.com",
            "link": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/AAA",
            "text": "AMC Lincoln Square 13 Showtimes - Movie times at the theatre.",
        },
        {
            # The only line that cites this page also cites the first one:
            # which of the two it was written about cannot be told, so it
            # carries no text (the row is then named by its site).
            "site": "fandango.com",
            "link": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/BBB",
            "text": "",
        },
    ]
    # Billed like any call: the search tool's own prompt counts as input.
    assert found["usage"]["input_tokens"] == 103 and found["usage"]["output_tokens"] == 97


PLAIN = {
    "candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": "Some page - made up."}]}}],
    "usageMetadata": {"promptTokenCount": 60, "candidatesTokenCount": 20},
}


def provider_scripted(answer_for, sent: list[tuple[str, dict[str, Any]]]) -> GeminiProvider:
    """A provider whose every request is recorded as (model asked, body) and
    answered by ``answer_for(model, how many requests so far)``."""

    def handler(request: httpx.Request) -> httpx.Response:
        model = request.url.path.rsplit("/", 1)[-1].split(":")[0]
        sent.append((model, json.loads(request.content)))
        status, body = answer_for(model, len(sent))
        return httpx.Response(status, json=body)

    provider = GeminiProvider(api_key="k", model="gemini-3.5-flash-lite")
    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"x-goog-api-key": "k"}
    )
    return provider


@pytest.mark.asyncio
async def test_search_web_respects_the_limit_and_answers_no_sources_without_grounding():
    sent: list[dict[str, Any]] = []
    provider = provider_answering(GROUNDED, sent)
    assert len((await provider.search_web("x y z", max_results=1))["sources"]) == 1
    assert "List the 1 pages" in sent[0]["contents"][0]["parts"][0]["text"]
    await provider.aclose()

    # Every model answered from memory: no sources, and what the three
    # attempts cost is what is reported.
    asked: list[tuple[str, dict[str, Any]]] = []
    provider = provider_scripted(lambda model, n: (200, PLAIN), asked)
    found = await provider.search_web("x y z")
    await provider.aclose()
    assert found["sources"] == []
    assert [model for model, _body in asked] == ["gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.5-flash-lite"]
    assert found["usage"]["input_tokens"] == 180 and found["usage"]["output_tokens"] == 60


@pytest.mark.asyncio
async def test_a_model_that_answered_without_searching_is_backed_up_by_one_that_searches():
    asked: list[tuple[str, dict[str, Any]]] = []
    provider = provider_scripted(
        lambda model, n: (200, GROUNDED if model == "gemini-3.8-flash" else PLAIN), asked
    )
    found = await provider.search_web("paper tiger amc lincoln square")
    await provider.aclose()
    assert [model for model, _body in asked] == ["gemini-3.5-flash-lite", "gemini-3.8-flash"]
    (_own, first), (_backup, second) = asked
    # The same question; each model with the lowest thinking setting it takes.
    assert first["contents"] == second["contents"] and first["tools"] == second["tools"]
    assert first["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "minimal"}
    assert second["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "low"}
    assert [source["site"] for source in found["sources"]] == ["amctheatres.com", "fandango.com"]
    assert found["usage"]["input_tokens"] == 60 + 103 and found["usage"]["output_tokens"] == 20 + 97
    assert provider._model == "gemini-3.5-flash-lite"  # the turn's model is untouched


@pytest.mark.asyncio
async def test_a_backup_model_that_cannot_be_used_is_skipped_not_raised():
    asked: list[tuple[str, dict[str, Any]]] = []

    def answer(model: str, n: int):
        if model == "gemini-3.8-flash":
            return 404, {"error": {"message": "models/gemini-3.8-flash is not found"}}
        return 200, GROUNDED if n == 3 else PLAIN

    provider = provider_scripted(answer, asked)
    found = await provider.search_web("paper tiger amc lincoln square")
    await provider.aclose()
    assert [model for model, _body in asked] == ["gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.5-flash-lite"]
    assert len(found["sources"]) == 2

    with pytest.raises(ValueError):
        await GeminiProvider(api_key="k", model="gemini-3.5-flash-lite").search_web("   ")


@pytest.mark.asyncio
async def test_search_web_errors_are_provider_errors_without_the_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"message": "search grounding is not enabled"}})

    key = "AIza-test-key-123"
    provider = GeminiProvider(api_key=key, model="gemini-3.5-flash-lite")
    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"x-goog-api-key": key}
    )
    with pytest.raises(ProviderError) as raised:
        await provider.search_web("x y z")
    await provider.aclose()
    said = str(raised.value)
    assert key not in said and "x-goog-api-key" not in said
    assert "generativelanguage.googleapis.com" not in said


@pytest.mark.asyncio
async def test_a_model_that_cannot_search_at_all_is_backed_up_too():
    """An own model that refuses the search tool (or is rate limited) is an
    attempt without sources like any other: the backup is asked."""
    asked: list[tuple[str, dict[str, Any]]] = []

    def answer(model: str, n: int):
        if model == "gemini-3.5-flash-lite":
            return 400, {"error": {"message": "Search Grounding is not supported"}}
        return 200, GROUNDED

    provider = provider_scripted(answer, asked)
    found = await provider.search_web("paper tiger amc lincoln square")
    await provider.aclose()
    assert [model for model, _body in asked] == ["gemini-3.5-flash-lite", "gemini-3.8-flash"]
    assert len(found["sources"]) == 2


@pytest.mark.asyncio
async def test_what_was_billed_is_reported_even_when_a_later_attempt_fails():
    asked: list[tuple[str, dict[str, Any]]] = []

    def answer(model: str, n: int):
        if n == 1:
            return 200, PLAIN  # own model: answered from memory, billed
        if model == "gemini-3.8-flash":
            return 200, PLAIN  # backup: the same, billed
        return 400, {"error": {"message": "bad request"}}  # own model again: fails

    provider = provider_scripted(answer, asked)
    found = await provider.search_web("x y z")
    await provider.aclose()
    assert found["sources"] == []
    assert found["usage"]["input_tokens"] == 120 and found["usage"]["output_tokens"] == 40


@pytest.mark.asyncio
async def test_the_backup_is_asked_once_and_never_retried(monkeypatch):
    asked: list[tuple[str, dict[str, Any]]] = []
    slept: list[float] = []

    def answer(model: str, n: int):
        if model == "gemini-3.8-flash":
            return 429, {"error": {"message": "quota", "details": [{"retryDelay": "41s"}]}}
        return 200, PLAIN

    provider = provider_scripted(answer, asked)

    async def no_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(provider, "_retry_sleep", no_sleep)
    found = await provider.search_web("x y z")
    await provider.aclose()
    assert [model for model, _body in asked] == ["gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.5-flash-lite"]
    assert slept == [] and found["sources"] == []


@pytest.mark.asyncio
async def test_no_further_attempt_is_made_after_stop_or_the_deadline(monkeypatch):
    from services.agent import providers as providers_module

    asked: list[tuple[str, dict[str, Any]]] = []
    provider = provider_scripted(lambda model, n: (200, PLAIN), asked)
    monkeypatch.setattr(providers_module.agent_cancel, "current_work_stopped", lambda: True)
    found = await provider.search_web("x y z")
    assert len(asked) == 1 and found["sources"] == []  # the owner pressed Stop: one answer, no more

    asked.clear()
    monkeypatch.setattr(providers_module.agent_cancel, "current_work_stopped", lambda: False)
    monkeypatch.setattr(provider, "_SEARCH_DEADLINE_S", 0.0)
    found = await provider.search_web("x y z")
    await provider.aclose()
    assert len(asked) == 1 and found["usage"]["input_tokens"] == 60  # past the deadline: the same


@pytest.mark.asyncio
async def test_a_turn_on_the_backup_model_does_not_ask_it_twice_in_a_row():
    asked: list[tuple[str, dict[str, Any]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.path.rsplit("/", 1)[-1].split(":")[0], json.loads(request.content)))
        return httpx.Response(200, json=PLAIN)

    provider = GeminiProvider(api_key="k", model="gemini-3.8-flash")
    provider._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), headers={"x-goog-api-key": "k"})
    await provider.search_web("x y z")
    await provider.aclose()
    assert [model for model, _body in asked] == ["gemini-3.8-flash", "gemini-3.8-flash"]


def test_a_page_is_given_the_line_written_about_it_alone():
    """A line that cites two pages was written about one of them. The page
    it was not written about must not get its title: each page takes the
    first line that cites it alone, and a page only shared lines cite takes
    none."""
    def supports(*pairs):
        return {
            "candidates": [
                {
                    "groundingMetadata": {
                        "groundingChunks": [
                            {"web": {"uri": "https://r.example/a", "title": "amctheatres.com"}},
                            {"web": {"uri": "https://r.example/b", "title": "fandango.com"}},
                        ],
                        "groundingSupports": [
                            {"segment": {"text": text}, "groundingChunkIndices": list(indices)} for text, indices in pairs
                        ],
                    }
                }
            ]
        }

    amc, fandango = "AMC Lincoln Square 13 - Showtimes at the theatre.", "Paper Tiger on Fandango - Tickets and times."
    found = GeminiProvider._cited_sources(supports((amc, [0, 1]), (fandango, [1])), 5)
    assert [(s["site"], s["text"]) for s in found] == [("amctheatres.com", ""), ("fandango.com", fandango)]
    found = GeminiProvider._cited_sources(supports((amc, [0]), (fandango, [1, 0])), 5)
    assert [(s["site"], s["text"]) for s in found] == [("amctheatres.com", amc), ("fandango.com", "")]
    # Odd metadata cites nothing rather than raising.
    for odd in ({}, {"candidates": {}}, {"candidates": [7]}, {"candidates": [{"groundingMetadata": 3}]}):
        assert GeminiProvider._cited_sources(odd, 5) == []
    out_of_range = supports((amc, [9, True, "x"]))
    assert GeminiProvider._cited_sources(out_of_range, 5) == []


def test_a_turn_reaches_the_search_only_on_gemini():
    class WithSearch:
        async def search_web(self, query: str, *, max_results: int = 5) -> dict[str, Any]:
            return {"sources": [], "usage": {}}

    provider = WithSearch()
    assert turn_context.web_searcher_of(provider, "gemini") == provider.search_web
    assert turn_context.web_searcher_of(provider, "Gemini ") == provider.search_web
    assert turn_context.web_searcher_of(provider, "anthropic") is None
    assert turn_context.web_searcher_of(object(), "gemini") is None
    # A TurnModel built without it (older callers, tests) has none.
    model = turn_context.TurnModel(provider="gemini", model="m", read_video_url=None, record_usage=lambda usage: None)
    assert model.search_web is None


# ── web.search asks the turn's provider first ────────────────────────────────

REDIRECT = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/"
PAGES = {"AAA": "https://www.amctheatres.com/movie-theatres/new-york-city/amc-lincoln-square-13", "BBB": "https://www.fandango.com/paper-tiger-2026-246826/movie-overview"}
SOURCES = [
    {"site": "amctheatres.com", "link": REDIRECT + "AAA", "text": "**AMC Lincoln Square 13** - Showtimes and tickets at the theatre. [1]"},
    {"site": "fandango.com", "link": REDIRECT + "BBB", "text": "2. Paper Tiger (2026) showtimes: see https://invented.example/not-a-real-page for times"},
]
DDG_ROW = (
    '<div class="result results_links"><h2 class="result__title"><a class="result__a" '
    'href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fkeyless">Keyless result</a></h2>'
    '<a class="result__snippet" href="#">From the keyless search.</a></div>'
)


class Web:
    """A WebToolkit over a fake network: the provider's redirect links
    answer 302 to ``PAGES``, DuckDuckGo answers one row, and every request
    is recorded."""

    def __init__(self, pages: dict[str, str] | None = None) -> None:
        self.pages = PAGES if pages is None else pages
        self.requests: list[str] = []
        self.kit = WebToolkit(
            transport=httpx.MockTransport(self._answer),
            resolver=lambda url: ("93.184.216.34",),
        )

    def _answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if request.url.host == "vertexaisearch.cloud.google.com":
            target = self.pages.get(request.url.path.rsplit("/", 1)[-1])
            if target is None:
                return httpx.Response(404)
            return httpx.Response(302, headers={"location": target})
        if request.url.host == "html.duckduckgo.com":
            return httpx.Response(200, text=f"<html><body>{DDG_ROW}</body></html>")
        return httpx.Response(500)


def turn_with(searcher, *, usd_left=None, recorded=None):
    return turn_context.bound(
        turn_context.TurnModel(
            provider="gemini",
            model="gemini-3.5-flash-lite",
            read_video_url=None,
            record_usage=(recorded if recorded is not None else []).append,
            usd_left=usd_left,
            search_web=searcher,
        )
    )


def answering(sources, usage=None, asked=None):
    async def search_web(query: str, *, max_results: int = 5) -> dict[str, Any]:
        if asked is not None:
            asked.append((query, max_results))
        return {"sources": sources, "usage": usage or {}}

    return search_web


@pytest.mark.asyncio
async def test_web_search_in_a_gemini_turn_returns_the_pages_the_providers_search_cited():
    web, asked, recorded = Web(), [], []
    usage = {"input_tokens": 103, "output_tokens": 97}
    with turn_with(answering(SOURCES, usage, asked), recorded=recorded):
        found = await web.kit.search("Paper Tiger AMC Lincoln Square tonight", 4)
    assert asked == [("Paper Tiger AMC Lincoln Square tonight", 4)]
    assert found == {
        "ok": True,
        "query": "Paper Tiger AMC Lincoln Square tonight",
        "source": "google",
        "results": [
            {
                "title": "AMC Lincoln Square 13",
                "url": PAGES["AAA"],
                "snippet": "Showtimes and tickets at the theatre.",
            },
            {
                # The model's own address is gone: the only address a row
                # carries is the one the search itself gave.
                "title": "Paper Tiger (2026) showtimes",
                "url": PAGES["BBB"],
                "snippet": "see for times",
            },
        ],
        "count": 2,
    }
    # Each redirect link was asked once and not followed; no keyless engine was asked.
    assert sorted(web.requests) == [REDIRECT + "AAA", REDIRECT + "BBB"]
    # What the nested call cost is the turn's cost.
    assert recorded == [usage]


@pytest.mark.asyncio
async def test_a_source_line_without_a_dash_is_titled_by_its_site():
    web = Web()
    sources = [{"site": "amctheatres.com", "link": REDIRECT + "AAA", "text": "Showtimes at the theatre"}]
    with turn_with(answering(sources)):
        [row] = (await web.kit.search("amc lincoln square"))["results"]
    assert row == {"title": "amctheatres.com", "url": PAGES["AAA"], "snippet": "Showtimes at the theatre"}


@pytest.mark.asyncio
async def test_a_link_that_is_already_a_page_is_kept_and_one_that_does_not_resolve_is_dropped():
    web = Web(pages={"AAA": "javascript:alert(1)"})
    sources = [
        {"site": "a.example", "link": REDIRECT + "AAA", "text": "A - points nowhere usable"},
        {"site": "b.example", "link": REDIRECT + "ZZZ", "text": "B - answers 404"},
        {"site": "c.example", "link": "http://c.example/plain", "text": "C - not https"},
        {"site": "d.example", "link": "https://d.example/page", "text": "D - a page already"},
    ]
    with turn_with(answering(sources)):
        found = await web.kit.search("a b c d")
    assert [row["url"] for row in found["results"]] == ["https://d.example/page"]
    assert "https://d.example/page" not in web.requests  # never fetched: only redirect links are asked


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["raises", "no-sources", "nothing-resolves", "not-a-dict"])
async def test_web_search_falls_back_to_the_keyless_search_when_the_provider_has_nothing(case):
    web = Web(pages={})

    async def raises(query: str, *, max_results: int = 5) -> dict[str, Any]:
        raise ProviderError("gemini", 400, "search grounding is not enabled")

    async def junk(query: str, *, max_results: int = 5) -> Any:
        return ["not", "a", "dict"]

    searcher = {
        "raises": raises,
        "no-sources": answering([]),
        "nothing-resolves": answering(SOURCES),
        "not-a-dict": junk,
    }[case]
    with turn_with(searcher):
        found = await web.kit.search("keyless please")
    assert found["ok"] is True and "source" not in found
    assert [row["url"] for row in found["results"]] == ["https://example.com/keyless"]


@pytest.mark.asyncio
async def test_web_search_outside_a_turn_or_without_a_provider_search_never_asks_one():
    web = Web()
    found = await web.kit.search("keyless please")
    assert [row["title"] for row in found["results"]] == ["Keyless result"]
    with turn_with(None):
        again = await web.kit.search("keyless please")
    assert again == found
    assert all("vertexaisearch" not in url for url in web.requests)


@pytest.mark.asyncio
async def test_an_unattended_run_with_no_budget_left_does_not_pay_for_a_search():
    web, asked = Web(), []
    with turn_with(answering(SOURCES, asked=asked), usd_left=lambda: 0.0):
        found = await web.kit.search("keyless please")
    assert asked == [] and "source" not in found
    with turn_with(answering(SOURCES, asked=asked), usd_left=lambda: 0.25):
        found = await web.kit.search("paper tiger")
    assert len(asked) == 1 and found["source"] == "google"


# ── what the provider is never sent, and rows that survive odd input ────────


@pytest.mark.asyncio
async def test_a_query_with_details_hidden_from_the_provider_goes_to_the_keyless_search():
    """With "Hide personal details from the AI provider" on, the model
    writes a placeholder and the real value is put back for the tool. The
    provider's search would send that value to the provider after all, so a
    query the provider may not see as it is never reaches it."""
    from services.security.egress import ModelEgress, bind_egress

    web, asked = Web(), []
    with turn_with(answering(SOURCES, asked=asked)), bind_egress(ModelEgress(hide_personal=True)):
        found = await web.kit.search("who is prof.lee@uni.edu phone +1 212 555 0147")
        assert asked == [] and "source" not in found
        # The same turn still uses the provider for a query with nothing to hide.
        found = await web.kit.search("paper tiger showtimes")
        assert len(asked) == 1 and found["source"] == "google"
    # The switch off: contact details are the owner's to send; a key never is.
    with turn_with(answering(SOURCES, asked=asked)), bind_egress(ModelEgress(hide_personal=False)):
        await web.kit.search("who is prof.lee@uni.edu")
        assert len(asked) == 2
        await web.kit.search("is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH leaked")  # gitleaks:allow (fake key)
        assert len(asked) == 2
    assert all("vertexaisearch" not in url or "prof.lee" not in url for url in web.requests)


@pytest.mark.parametrize(
    ("text", "title", "snippet"),
    [
        # An address the search model made up, with or without a scheme, never stays.
        ("AMC Lincoln Square 13 - see amctheatres.com/movie-theatres/new-york-city/amc-lincoln-square-99 for times",
         "AMC Lincoln Square 13", "see for times"),
        ("Cheap tickets - buy tickets at www.amc-tickets-cheap.example/checkout", "Cheap tickets", "buy tickets at"),
        ("Times - see HTTPS://Invented.example/page today", "Times", "see today"),
        # The dash the prompt asked for splits the line, not a colon in the title.
        ("Mission: Impossible - Dead Reckoning - Showtimes at AMC", "Mission: Impossible", "Dead Reckoning - Showtimes at AMC"),
        # A markdown link keeps its words only.
        ("[AMC Lincoln Square](https://invented.example/page) - Showtimes", "AMC Lincoln Square", "Showtimes"),
        # No line of its own: the row is the site's.
        ("", "amctheatres.com", ""),
    ],
)
def test_a_row_is_shaped_from_the_cited_line_and_carries_no_address_but_the_searchs(text, title, snippet):
    from services.tools.web import _provider_row

    row = _provider_row({"site": "amctheatres.com", "text": text}, PAGES["AAA"])
    assert row == {"title": title, "url": PAGES["AAA"], "snippet": snippet}


@pytest.mark.asyncio
async def test_a_link_or_a_location_that_is_no_address_costs_one_row_not_the_search():
    web = Web(pages={"AAA": PAGES["AAA"], "BAD": "http://[bad"})
    sources = [
        {"site": "x.example", "link": "https://[bad", "text": "X - a link no parser reads"},
        {"site": "y.example", "link": REDIRECT + "BAD", "text": "Y - points at no address"},
        {"site": "amctheatres.com", "link": REDIRECT + "AAA", "text": "AMC - showtimes"},
    ]
    with turn_with(answering(sources)):
        found = await web.kit.execute("search", {"query": "amc lincoln square"})
    assert found["ok"] is True and [row["url"] for row in found["results"]] == [PAGES["AAA"]]


# ── through a whole turn ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_gemini_turns_web_search_reaches_the_providers_search_and_is_billed_once():
    """End to end: the runtime binds the provider's search for a Gemini turn,
    the rows reach the model as untrusted tool output, their tokens are in
    the turn's totals once, and a turn on another provider never asks."""
    from core.config import settings
    from services.agent.approvals import InMemoryApprovalStore
    from services.agent.providers import LLMResponse, ToolCall
    from services.agent.runtime import AgentRuntime
    from services.agent.tool_registry import ConnectorToolExecutor, RuntimePermissionAdapter, build_tools
    from tests.conftest import use_provider
    from tests.test_agent_runtime_vision import RecordingAudit
    from tests.test_purchases_wiring import _gate

    class Searching:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []
            self.searched: list[str] = []
            self._script = [
                LLMResponse(
                    content="",
                    tool_calls=[ToolCall(id="s1", name="web.search", arguments={"query": "paper tiger showtimes"})],
                    usage={"input_tokens": 1000, "output_tokens": 20},
                ),
                LLMResponse(content="It plays at 7:45 PM.", usage={"input_tokens": 1100, "output_tokens": 20}),
            ]

        async def complete(self, messages, tools=None):
            self.calls.append({"messages": list(messages)})
            return self._script.pop(0)

        async def stream(self, messages, tools=None):
            yield "done"

        async def search_web(self, query: str, *, max_results: int = 5) -> dict[str, Any]:
            self.searched.append(query)
            return {"sources": SOURCES, "usage": {"input_tokens": 60, "output_tokens": 90}}

    async def turn(pair: tuple[str, str]):
        web = Web()
        gate = _gate("web_browsing")
        provider = Searching()
        runtime = AgentRuntime(
            config=settings,
            permission_engine=RuntimePermissionAdapter(capability_gate=gate),
            audit_service=RecordingAudit(),
            approval_store=InMemoryApprovalStore(),
            tool_executor=ConnectorToolExecutor(session_factory=None, capability_gate=gate, web_toolkit=web.kit),
        )
        use_provider(runtime, provider, pair)
        response = await runtime.chat(
            messages=[{"role": "user", "content": "when is paper tiger on"}],
            tools=build_tools([], enabled_capabilities=frozenset({"web_browsing"})),
            user_id="u-search",
            llm_provider=pair[0],
            llm_model=pair[1],
        )
        return provider, response

    provider, response = await turn(("gemini", "gemini-3.5-flash-lite"))
    assert provider.searched == ["paper tiger showtimes"]
    [search] = response.tool_calls
    assert search["result"]["source"] == "google"
    shown = provider.calls[1]["messages"][-1]["content"]
    assert PAGES["AAA"] in shown and 'trust="untrusted"' in shown
    assert response.usage["input_tokens"] == 1000 + 1100 + 60
    assert response.usage["output_tokens"] == 20 + 20 + 90

    # Another provider with a search_web of its own is never asked.
    provider, response = await turn(("openai", "gpt-4o-mini"))
    assert provider.searched == [] and response.tool_calls[0]["result"].get("source") != "google"
