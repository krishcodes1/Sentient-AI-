"""Tests for what an outline tells the model about the window: it is read once
the app has settled after an act, a sheet, dialog or popover comes first with
a note, and the app's other windows are listed.

Why it exists: the model saw only the focused window, read a fraction of a
second after its act. A "What's New / Continue" sheet that slides in a moment
later was missed, a sheet at the end of a long window could be cut off by the
size cap, and a leftover popover hid the window the model wanted with nothing
saying another window existed. Runs on the in-memory fake desktop; nothing
touches a real screen or sleeps.
"""

from __future__ import annotations

import re

import pytest

from services.tools.computer import toolkit
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.toolkit import ComputerToolkit

U1 = "user-1"


def month_view(*extra) -> FakeWindow:
    return FakeWindow(
        "September 2026",
        (
            make_node("button", "Next month", handle="next"),
            *[make_node("cell", f"September {day}", handle=f"day{day}") for day in range(1, 31)],
            *extra,
        ),
    )


WHATS_NEW = make_node(
    "sheet",
    "What's New in Calendar",
    handle="whatsnew",
    children=(make_node("button", "Continue", handle="continue"),),
)


def desktop(*windows: FakeWindow, front: str = "Calendar") -> FakeBackend:
    return FakeBackend(
        [
            FakeApp("Calendar", 201, list(windows) or [month_view()]),
            FakeApp("Telegram", 202, [FakeWindow("Chats", (make_node("button", "Approve"),))]),
        ],
        frontmost=front,
        installed={"Calendar"},
    )


def kit_for(fake: FakeBackend) -> ComputerToolkit:
    return ComputerToolkit(fake, cancel_flag=lambda uid: False)


async def observe(kit: ComputerToolkit) -> dict:
    result = await kit.execute("observe", {"action": "outline"}, user_id=U1)
    assert result["ok"], result
    return result


async def approved(kit: ComputerToolkit, params: dict) -> dict:
    return await kit.execute("act", kit.bind(params, user_id=U1), user_id=U1, approved=True)


def ref(result: dict, needle: str) -> str:
    for line in result["outline"]:
        if needle in line:
            return re.search(r"\[ref=(d\d+)\]", line).group(1)
    raise AssertionError(f"{needle!r} not in {result['outline']}")


@pytest.fixture(autouse=True)
def no_real_pauses(monkeypatch):
    monkeypatch.setattr(toolkit, "_pause", lambda seconds: None)


# ── read once the app has settled ────────────────────────────────────────────


class LateSheet(FakeBackend):
    """Calendar starts sliding its "What's New" sheet in as the click lands:
    the first read after it still shows the plain month view, the next one
    has the sheet."""

    reads_until_sheet = 1

    def outline(self, app, max_nodes):
        if self.events and self.reads_until_sheet >= 0:
            if self.reads_until_sheet == 0:
                window = self.apps["Calendar"].windows[0]
                if WHATS_NEW not in window.nodes:
                    window.nodes = (*window.nodes, WHATS_NEW)
            self.reads_until_sheet -= 1
        return super().outline(app, max_nodes)


@pytest.mark.asyncio
async def test_the_outline_after_an_act_is_read_once_the_window_settles():
    fake = LateSheet(desktop().apps.values(), frontmost="Calendar")
    kit = kit_for(fake)
    seen = await observe(kit)
    result = await approved(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert result["ok"] is True, result
    then = result["then"]
    assert any("What's New in Calendar" in line for line in then["outline"]), then["outline"]
    assert any('"Continue"' in line for line in then["outline"])


@pytest.mark.asyncio
async def test_settling_gives_up_after_its_limit(monkeypatch):
    # A window that never stops changing (a ticking clock) costs a bounded
    # wait, then the outline is read as it is.
    class Ticking(FakeBackend):
        ticks = 0

        def outline(self, app, max_nodes):
            self.ticks += 1
            self.apps["Calendar"].windows[0].nodes = (
                make_node("text", f"12:00:{self.ticks:02d}"),
                make_node("button", "Next month", handle="next"),
            )
            return super().outline(app, max_nodes)

    fake = Ticking(desktop().apps.values(), frontmost="Calendar")
    kit = kit_for(fake)
    seen = await observe(kit)
    fake.reads.clear()
    result = await approved(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert result["ok"] is True
    assert result["then"]["ok"] is True
    assert fake.reads.count("outline") <= toolkit.SETTLE_MAX_READS + 2  # live checks + settle


@pytest.mark.asyncio
async def test_open_app_waits_for_the_app_to_have_a_window():
    class SlowWindow(FakeBackend):
        polls = 0

        def open_app(self, name):
            super().open_app(name)
            self.apps[name].windows = []  # launched, no window yet

        def outline(self, app, max_nodes):
            name = app or self.front
            if name == "Calendar" and not self.apps["Calendar"].windows:
                self.polls += 1
                if self.polls >= 3:
                    self.apps["Calendar"].windows = [month_view()]
            return super().outline(app, max_nodes)

    fake = SlowWindow(
        [FakeApp("Telegram", 1, [FakeWindow("Chats", ())])],
        frontmost="Telegram",
        installed={"Calendar"},
    )
    kit = kit_for(fake)
    result = await approved(kit, {"action": "open_app", "app": "Calendar"})
    assert result["ok"] is True, result
    assert result["then"]["app"] == "Calendar"
    assert any('"Next month"' in line for line in result["then"]["outline"])


# ── a sheet, dialog or popover comes first, with a note ──────────────────────


@pytest.mark.asyncio
async def test_a_sheet_at_the_end_of_a_long_window_is_listed_first_with_a_note():
    fake = desktop(month_view(WHATS_NEW))
    result = await observe(kit_for(fake))
    lines = result["outline"]
    assert "What's New in Calendar" in lines[1], lines[:3]  # right after the window line
    assert '"Continue"' in lines[2]
    assert result["modal"] == 'sheet "What\'s New in Calendar"'
    assert "sheet" in result["note"] and "first" in result["note"]


@pytest.mark.asyncio
async def test_a_sheet_survives_a_small_size_cap():
    fake = desktop(month_view(WHATS_NEW))
    result = await kit_for(fake).execute(
        "observe", {"action": "outline", "max_chars": 300}, user_id=U1
    )
    assert result["truncated"] is True
    assert any('"Continue"' in line for line in result["outline"])


@pytest.mark.asyncio
async def test_a_dialog_window_is_named_in_the_note():
    dialog = FakeWindow(
        "Delete Event?", (make_node("button", "Delete"), make_node("button", "Cancel"))
    )
    fake = FakeBackend([FakeApp("Calendar", 1, [dialog])], frontmost="Calendar")

    # The Mac backend labels a dialog window's root "dialog".
    class DialogRoot(FakeBackend):
        def outline(self, app, max_nodes):
            nodes = super().outline(app, max_nodes)
            import dataclasses

            return [dataclasses.replace(nodes[0], role="dialog")] + nodes[1:]

    fake = DialogRoot(fake.apps.values(), frontmost="Calendar")
    result = await observe(kit_for(fake))
    assert result["modal"] == 'dialog "Delete Event?"'
    assert "dialog" in result["note"]


@pytest.mark.asyncio
async def test_a_plain_window_has_no_modal_note():
    result = await observe(kit_for(desktop()))
    assert "modal" not in result
    assert "note" not in result


# ── the app's other windows ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_other_windows_of_the_app_are_listed():
    popover = FakeWindow("", (make_node("text field", "Title", handle="title", value="Dentist"),))
    fake = desktop(popover, month_view())
    result = await observe(kit_for(fake))
    assert result["windows"] == [
        {"title": "", "index": 0},
        {"title": "September 2026", "index": 1},
    ]
    assert "focus_window" in result["note"]


@pytest.mark.asyncio
async def test_one_window_lists_nothing():
    result = await observe(kit_for(desktop()))
    assert "windows" not in result


@pytest.mark.asyncio
async def test_list_windows_can_be_asked_for_one_app():
    fake = desktop(month_view(), FakeWindow("Inbox", ()))
    assert [w.title for w in fake.list_windows("Calendar")] == ["September 2026", "Inbox"]
    assert [w.app for w in fake.list_windows()] == ["Calendar", "Calendar", "Telegram"]


# ── the menu bar (macOS keeps it outside the window) ─────────────────────────


def menus(open_view: bool = False) -> list:
    view_items = (
        (
            make_node("menu item", "By Day", handle="byday"),
            make_node("menu item", "By Month", handle="bymonth"),
        )
        if open_view
        else ()
    )
    return [
        make_node("menu bar item", "Calendar", handle="m-calendar"),
        make_node("menu bar item", "File", handle="m-file"),
        make_node("menu bar item", "View", handle="m-view", children=view_items),
    ]


@pytest.mark.asyncio
async def test_the_menu_bar_follows_the_window():
    fake = desktop()
    fake.menus["Calendar"] = menus()
    result = await observe(kit_for(fake))
    lines = result["outline"]
    assert lines[0].startswith('- window "September 2026"')
    assert lines[-3:] == [
        '- menu bar item "Calendar" [ref=d33]',
        '- menu bar item "File" [ref=d34]',
        '- menu bar item "View" [ref=d35]',
    ]
    assert "note" not in result


@pytest.mark.asyncio
async def test_an_open_menu_is_listed_first_and_its_item_can_be_chosen():
    fake = desktop()
    fake.menus["Calendar"] = menus(open_view=True)
    kit = kit_for(fake)
    result = await observe(kit)
    lines = result["outline"]
    assert lines[:3] == [
        '- menu bar item "Calendar" [ref=d1]',
        '- menu bar item "File" [ref=d2]',
        '- menu bar item "View" [ref=d3]',
    ]
    assert lines[3:5] == ['  - menu item "By Day" [ref=d4]', '  - menu item "By Month" [ref=d5]']
    assert 'The "View" menu is open' in result["note"]
    assert result["window_title"] == "September 2026"
    chosen = await approved(kit, {"action": "click", "ref": ref(result, '"By Month"')})
    assert chosen["ok"] is True, chosen
    assert chosen["did"] == 'click menu item "By Month" in Calendar'
    assert fake.events == [("click", "bymonth", False)]


@pytest.mark.asyncio
async def test_a_backend_without_a_menu_bar_reader_still_outlines():
    class Plain(FakeBackend):
        menu_bar = None

    fake = Plain(desktop().apps.values(), frontmost="Calendar")
    result = await observe(kit_for(fake))
    assert result["ok"] is True
    assert not any("menu bar item" in line for line in result["outline"])
