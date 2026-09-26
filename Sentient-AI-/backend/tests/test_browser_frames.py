"""A frame that never gets a document must never hold a browser step.

Why it exists: on a real shop's product page (tonight's dbrand page) one
iframe, a video embed, never loaded a document. Playwright's
frame.evaluate has no timeout, so every picture of that page (a
screenshot, the browser.act card, the checkout card) waited on it
forever, a cancelled card build waited again in its cleanup while it held
the session lock, and the Telegram chat showed "typing" until someone
killed the process. A lazy iframe far below the fold does the same on the
fake site, and the snapshot waited 30 s for it on every look. These pin
that each step now answers within seconds, that such a frame is blacked
out rather than left out of a picture, and that it counts as showing
nothing rather than as a page that may take payment. The fake site only;
never a real website.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from services.tools.browser import _shared
from services.tools.browser import snapshot as snap
from services.tools.browser.act import CARD_KEY
from services.tools.browser.checkout import markers
from tests import test_browser_act as _act_tests
from tests.fakesite.pages import PAGES, _page
from tests.test_browser_act import USER, live_page, read, ref_of

kits = _act_tests.kits
page_at = _act_tests.page_at

# A lazy iframe below the fold: it gets its document once scrolled to.
LAZY = (
    '<h1>Grip case</h1><p>Holo White $59.90</p><button type="button">Add to Cart</button>'
    '<div style="height:20000px"></div><iframe loading="lazy" src="/grades"></iframe>'
)
# One that never does: hidden (so the snapshot does not wait on it, as on
# the shop's page) and pinned lazy by the page's own script.
NEVER_LOADS = (
    '<h1>Grip case</h1><p>Holo White $59.90</p><button type="button">Add to Cart</button>'
    '<div style="display:none"><iframe id="video" loading="lazy" src="/grades"></iframe></div>'
    '<script>Object.defineProperty(document.getElementById("video"), "loading", '
    "{get() { return 'lazy'; }, set(_v) {}});</script>"
)


async def within(seconds: float, coro):
    started = time.monotonic()
    result = await asyncio.wait_for(coro, seconds)
    return result, time.monotonic() - started


async def stuck(frame) -> bool:
    try:
        await asyncio.wait_for(frame.evaluate("1"), 1)
    except asyncio.TimeoutError:
        return True
    return False


@pytest.mark.asyncio
async def test_a_lazy_frame_below_the_fold_is_loaded_for_the_outline(kits, fakesite_tls, page_at):
    opened, took = await within(8, read(kits, "open", url=fakesite_tls.url(page_at("/lazy-frame", LAZY))))
    assert opened["ok"] is True and took < 5, took
    assert any("Grades for" in line for line in opened["outline"])  # the frame's own content
    shot, took = await within(8, read(kits, "screenshot"))
    assert shot["ok"] is True and took < 5, took
    card, took = await within(
        10, kits[1].bind_async({"action": "click", "ref": ref_of(opened, '- button "Add to Cart"')}, user_id=USER, task_id="t1")
    )
    assert card[CARD_KEY]["picture"] and took < 5, took


@pytest.mark.asyncio
async def test_the_snapshot_waits_a_bounded_time_for_a_shown_frame_that_never_loads(kits, fakesite_tls, page_at, monkeypatch):
    monkeypatch.setattr(snap, "SNAPSHOT_TIMEOUT_MS", 1500)
    shown = NEVER_LOADS.replace('<div style="display:none">', '<div style="margin-top:20000px">')
    opened, took = await within(15, read(kits, "open", url=fakesite_tls.url(page_at("/never-loads-shown", shown))))
    assert opened["ok"] is True and took < 6, took
    assert any('button "Add to Cart"' in line for line in opened["outline"])  # the page, without the frame


@pytest.mark.asyncio
async def test_a_frame_that_never_loads_holds_no_step_and_no_later_one(kits, fakesite_tls, page_at):
    opened, took = await within(15, read(kits, "open", url=fakesite_tls.url(page_at("/never-loads", NEVER_LOADS))))
    assert opened["ok"] is True and took < 5, took
    page = await live_page(kits)
    assert await stuck(page.frames[1]), "the fake site no longer reproduces a frame with no document"

    shot, took = await within(15, read(kits, "screenshot"))
    assert shot["ok"] is True and shot["user_image"].startswith("data:image/jpeg") and took < 8, took
    call = {"action": "click", "ref": ref_of(opened, '- button "Add to Cart"')}
    card, took = await within(20, kits[1].bind_async(call, user_id=USER, task_id="t1"))
    assert took < 12, took
    assert card[CARD_KEY]["picture"]  # the picture was taken, and the overlay removed again
    assert "money" not in card[CARD_KEY]  # a frame with no document shows no total or saved card
    assert await page.locator("[data-crawler-outline]").count() == 0
    later, took = await within(10, read(kits, "snapshot"))  # the session lock is free again
    assert later["ok"] is True and took < 5, took


@pytest.mark.asyncio
async def test_a_frame_with_no_document_is_blacked_out_whole_and_shows_nothing(page, fakesite, monkeypatch):
    monkeypatch.setitem(PAGES, "/never-loads", (200, "text/html", _page("Grip case", NEVER_LOADS)))
    await page.goto(fakesite.url("/never-loads"))
    frame = page.frames[1]
    assert frame.url == "" and await stuck(frame)

    image, took = await within(10, _shared.jpeg(page, None))
    assert image.startswith("data:image/jpeg;base64,") and took < 8, took
    assert await page.locator(f"iframe[{markers.MASK_ATTRIBUTE}]").count() == 1  # its whole box is masked
    facts, took = await within(10, _shared.page_facts(page))
    assert facts[1] == dict.fromkeys(markers.PAGE_FACT_KEYS, False) and took < 5, took
    assert await _shared.frame_evaluate(page.main_frame, "1") == 1
    with pytest.raises(asyncio.TimeoutError):
        await _shared.frame_evaluate(frame, "1")


@pytest.mark.asyncio
async def test_a_frame_whose_parent_wrote_into_it_is_read_and_masked_as_usual(page, fakesite, monkeypatch):
    """A frame with no URL of its own that its parent wrote a password box
    into has a document: it answers, and its field is masked as always."""
    body = (
        '<div style="height:20000px"></div><iframe id="lz" loading="lazy" src="/grades"></iframe>'
        '<script>document.getElementById("lz").contentDocument.body.innerHTML = '
        '"<input type=password value=hunter2>";</script>'
    )
    monkeypatch.setitem(PAGES, "/written", (200, "text/html", _page("Written", body)))
    await page.goto(fakesite.url("/written"))
    frame = page.frames[1]
    assert frame.url == "" and not await stuck(frame)
    locators, _took = await within(5, _shared.mask_locators(page))
    assert len(locators) == 2  # both frames' own fields, the frame not blacked out whole
    assert await page.locator(f"iframe[{markers.MASK_ATTRIBUTE}]").count() == 0
    assert await frame.locator(f"input[{markers.MASK_ATTRIBUTE}]").count() == 1
