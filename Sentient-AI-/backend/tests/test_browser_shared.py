"""Tests for the helpers the three browser toolkits share
(``services/tools/browser/_shared.py``): they prove that handing the page
to the person parks the session for the idle reaper until the agent acts
again, with or without an egress state behind the guard, and that an
observation passes on how many outline lines lie below the ones it
returns, with one fixed hint when there are any.

Why it exists: a window was closed fifteen minutes after a handoff while
the person was still typing in it (nothing ever marked the session as
parked), and the model took the visible part of a page for the whole of
it (a film's page "had no showtimes": they were further down). Pure: a
fake page and a fake outline, no browser.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Optional

import pytest

from services.tools.browser import _shared
from services.tools.browser import snapshot as snap
from services.tools.browser.session import TaskState


class FakePage:
    def __init__(self, url: str) -> None:
        self.url = url

    async def wait_for_load_state(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class NoChallenge:
    async def detect_challenge(self, page: Any) -> None:
        return None


def _session(page: FakePage) -> SimpleNamespace:
    async def current_page() -> FakePage:
        return page

    return SimpleNamespace(
        context=object(),
        user_id="ann",
        mode="account",
        task=TaskState(task_id="t1"),
        typed_secrets=[],
        pending=None,
        page=current_page,
    )


# ── the handoff parks the session ────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_handoff_parks_the_session_until_the_agent_acts_again():
    state = SimpleNamespace(human_driving=False, checkout_handoff=False, handoff_page=None)
    guard = SimpleNamespace(egress_state=lambda context: state)
    page = FakePage("https://school.example/login")
    session = _session(page)
    _shared.hand_over(guard, session, page)
    assert session.pending == "handoff" and state.human_driving is True
    await _shared.take_back(guard, session)
    assert session.pending is None and state.human_driving is False


@pytest.mark.asyncio
async def test_a_handoff_parks_the_session_without_an_egress_state_too():
    """The window is the person's whether or not the guard has a state to
    open (not installed yet, a test double)."""
    guard = SimpleNamespace(egress_state=lambda context: None)
    page = FakePage("https://school.example/login")
    session = _session(page)
    _shared.hand_over(guard, session, page)
    assert session.pending == "handoff"
    await _shared.take_back(guard, session)
    assert session.pending is None


@pytest.mark.asyncio
async def test_a_challenge_found_while_looking_parks_the_session(monkeypatch):
    class Wall:
        async def detect_challenge(self, page: Any) -> Any:
            return SimpleNamespace(kind="captcha", detail="visible challenge frame")

    async def no_picture(page: Any, ref: Optional[str]) -> str:
        raise _shared.PlaywrightError("no screenshot on a fake page")

    monkeypatch.setattr(_shared, "jpeg", no_picture)
    guard = SimpleNamespace(egress_state=lambda context: None)
    page = FakePage("https://shop.example/")
    session = _session(page)
    result = await _shared.observe(session, Wall(), "open", {"url": page.url}, guard=guard)
    assert result["needs_human"]["kind"] == "captcha" and session.pending == "handoff"


# ── what the outline leaves out ──────────────────────────────────────────


def _outline_with(below: Optional[int]) -> Any:
    """An outline as snapshot.py hands it over. ``below`` is the count of
    lines under the ones returned; None stands for an outline that carries
    no count."""
    fields: dict[str, Any] = {
        "url": "https://cinema.example/paper-tiger",
        "title": "Paper Tiger",
        "lines": ['- heading "Paper Tiger" [level=1] [ref=e1]'],
        "refs": 1,
        "chars": 42,
        "truncated": False,
    }
    if below is not None:
        fields["below"] = below
    return SimpleNamespace(**fields)


async def _observe(
    monkeypatch: pytest.MonkeyPatch, outline: Any, *, full: bool = False
) -> dict[str, Any]:
    async def fake_outline(page: Any, **_kwargs: Any) -> Any:
        return outline

    monkeypatch.setattr(_shared.snap, "outline", fake_outline)
    page = FakePage(outline.url)
    return await _shared.observe(
        _session(page), NoChallenge(), "open", {"url": page.url}, full=full
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "below, hint",
    [
        (379, "379 more lines are below: use find(text), scroll(down) or snapshot(full=true)"),
        (1, "1 more line is below: use find(text), scroll(down) or snapshot(full=true)"),
    ],
)
async def test_an_observation_says_how_many_lines_lie_below_the_outline(monkeypatch, below, hint):
    result = await _observe(monkeypatch, _outline_with(below))
    assert result["ok"] is True and result["below"] == below and result["hint"] == hint
    assert result["outline"] == ['- heading "Paper Tiger" [level=1] [ref=e1]']


@pytest.mark.asyncio
async def test_an_observation_of_the_whole_page_carries_a_zero_and_no_hint(monkeypatch):
    result = await _observe(monkeypatch, _outline_with(0))
    assert result["below"] == 0 and "hint" not in result


@pytest.mark.asyncio
async def test_a_whole_page_too_long_to_return_does_not_send_the_model_back_to_itself(monkeypatch):
    """snapshot(full=true) of a long page is cut at its cap. The lines cut
    are below what was returned, and asking for the whole page again
    would return the same part: the hint names only what reaches them."""
    result = await _observe(monkeypatch, _outline_with(212), full=True)
    assert result["below"] == 212
    assert result["hint"] == "212 more lines are below: use find(text) or scroll(down)"


@pytest.mark.asyncio
async def test_an_outline_without_a_count_adds_neither(monkeypatch):
    """Nothing is made up: an outline that does not say how much is below
    gives a result that does not say it either."""
    result = await _observe(monkeypatch, _outline_with(None))
    assert result["ok"] is True and "below" not in result and "hint" not in result
    # The outline class itself, built the way other tests build it: no hint.
    real = snap.Outline(url="https://a.example/", title="A", lines=["- text: a"], refs=0, chars=9, truncated=False)
    result = await _observe(monkeypatch, real)
    assert result["ok"] is True and "hint" not in result


# A Google Web Designer banner: a custom element whose content nobody can read.
_CLOSED_BANNER = (
    "<script>customElements.define('gwd-pagedeck', class extends HTMLElement { constructor() { super(); "
    "this.attachShadow({mode: 'closed'}).innerHTML = '<p>Sale</p>'; } });</script>"
    "<gwd-pagedeck style='display:block;width:300px;height:250px'></gwd-pagedeck>"
)


@pytest.mark.asyncio
@pytest.mark.parametrize("frame_host, unread", [("localhost", False), ("127.0.0.1", True)])
async def test_an_unreadable_widget_hides_the_page_only_on_the_pages_own_site(
    page, fakesite, monkeypatch, frame_host, unread
):
    """An ad from another site with a closed shadow root made Fandango's
    theater page count as showing a total and a saved card, so every
    showtime click was refused as paying. Another site's frame is judged by
    what it shows in words; the page's own site keeps failing closed."""
    from tests.fakesite.pages import PAGES, _page

    here = fakesite.url("/").rstrip("/")
    monkeypatch.setitem(PAGES, "/banner", (200, "text/html", _page("Ad", _CLOSED_BANNER)))
    monkeypatch.setitem(PAGES, "/showtimes", (200, "text/html", _page(
        "Showtimes", "<h1>Showtimes</h1><button>7:15 PM</button>"
        f"<iframe src='{here.replace('127.0.0.1', frame_host)}/banner' style='width:320px;height:270px'></iframe>",
    )))
    await page.goto(fakesite.url("/showtimes"))
    await page.wait_for_timeout(300)
    answers = await _shared.page_facts(page)
    banner = next(a for f, a in zip(page.frames, answers, strict=True) if f.url.endswith("/banner"))
    assert bool(banner.get("unread")) is unread and bool(banner["saved_payment"]) is unread
