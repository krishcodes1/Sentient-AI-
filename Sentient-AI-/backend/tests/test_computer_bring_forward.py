"""Tests for approved desktop acts bringing their app back to the front.

Why it exists: seen live. The owner tapped Approve in Telegram on the same
computer, which put Telegram in front; the approved click in Calendar was then
refused (rule frontmost_changed) and its message sent the model to ask for
focus_window, another card whose tap put Telegram in front again. An approved
act now brings the app its card was made from forward first, and every rule
still runs after that, reading the front app again. Runs on the in-memory fake
desktop; nothing touches a real screen.
"""

from __future__ import annotations

import pytest

from services.tools.computer import rules
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.toolkit import CARD_KEY, ComputerToolkit

U1 = "user-1"


def calendar_desktop(front: str = "Calendar") -> FakeBackend:
    return FakeBackend(
        [
            FakeApp(
                "Calendar",
                201,
                [
                    FakeWindow(
                        "September 2026",
                        (
                            make_node("button", "Next month", handle="next"),
                            make_node("text field", "Search", handle="search"),
                        ),
                    )
                ],
            ),
            FakeApp("Telegram", 202, [FakeWindow("Chats", (make_node("button", "Approve"),))]),
            FakeApp(
                "Safari",
                203,
                [
                    FakeWindow(
                        "Crawler AI - Secure Agentic AI Platform", (make_node("button", "Approve"),)
                    )
                ],
            ),
            FakeApp("loginwindow", 204, [FakeWindow("", ())]),
            FakeApp("Terminal", 205, [FakeWindow("bash", (make_node("text area", "Shell"),))]),
            FakeApp("1Password", 206, [FakeWindow("Vault", ())]),
            FakeApp(
                "Crawler AI", 207, [FakeWindow("Approvals", (make_node("button", "Approve"),))]
            ),
        ],
        frontmost=front,
        focused="search",
    )


async def observed(fake: FakeBackend):
    kit = ComputerToolkit(fake, cancel_flag=lambda uid: False)
    seen = await kit.execute("observe", {"action": "outline"}, user_id=U1)
    assert seen["ok"], seen
    return kit, seen


def ref(result, needle: str) -> str:
    import re

    for line in result["outline"]:
        if needle in line:
            return re.search(r"\[ref=(d\d+)\]", line).group(1)
    raise AssertionError(f"{needle!r} not in {result['outline']}")


async def approved_act(kit: ComputerToolkit, params: dict):
    """An act as the executor runs it after its card: bound to the screen,
    with approved=True."""
    bound = kit.bind(params, user_id=U1)
    return await kit.execute("act", bound, user_id=U1, approved=True)


def assert_refused(result, rule: str) -> None:
    assert result["ok"] is False and result.get("refused") is True, result
    assert result["rule"] == rule, result


# ── the approved act runs in its app ─────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("took_the_front", ["Telegram", "Safari", "Crawler AI"])
async def test_an_approved_click_brings_its_app_back_and_runs(took_the_front):
    # Telegram, or Crawler's own window (its web UI in a browser, or the
    # desktop app), came to the front with the Approve tap.
    fake = calendar_desktop()
    kit, seen = await observed(fake)
    fake.front = took_the_front
    result = await approved_act(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert result["ok"] is True, result
    assert fake.events == [("focus_window", "Calendar", 0), ("click", "next", False)]
    assert fake.front == "Calendar"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {"action": "scroll", "direction": "down"},
        {"action": "key", "keys": "cmd+right"},
        {"action": "type", "text": "dentist"},
    ],
)
async def test_every_approved_input_act_brings_its_app_back(params):
    fake = calendar_desktop()
    kit, _ = await observed(fake)
    fake.front = "Telegram"
    result = await approved_act(kit, params)
    assert result["ok"] is True, result
    assert fake.events[0] == ("focus_window", "Calendar", 0)
    assert len(fake.events) == 2


@pytest.mark.asyncio
async def test_nothing_is_brought_forward_when_the_app_is_already_in_front():
    fake = calendar_desktop()
    kit, seen = await observed(fake)
    result = await approved_act(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert result["ok"] is True
    assert fake.events == [("click", "next", False)]


# ── where it never happens ───────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("in_front", ["loginwindow", "Terminal", "1Password"])
async def test_a_blocked_app_in_front_is_never_pushed_aside(in_front):
    # The lock window, a terminal or a password manager: the owner may be
    # typing a password there, and moving the keyboard away mid-word could
    # put the rest of it into the approved app.
    fake = calendar_desktop()
    kit, seen = await observed(fake)
    fake.front = in_front
    result = await approved_act(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert_refused(result, "blocked_app")
    assert fake.events == []


@pytest.mark.asyncio
async def test_an_act_nobody_approved_is_still_refused_when_another_app_is_in_front():
    fake = calendar_desktop()
    kit, seen = await observed(fake)
    fake.front = "Telegram"
    result = await kit.execute(
        "act", {"action": "click", "ref": ref(seen, '"Next month"')}, user_id=U1
    )
    assert_refused(result, "frontmost_changed")
    assert fake.events == []


@pytest.mark.asyncio
async def test_a_card_for_another_screen_is_refused_before_anything_moves():
    fake = calendar_desktop()
    kit, seen = await observed(fake)
    params = {
        "action": "click",
        "ref": ref(seen, '"Next month"'),
        CARD_KEY: {"app": "Mail", "outline": "x"},
    }
    fake.front = "Telegram"
    result = await kit.execute("act", params, user_id=U1, approved=True)
    assert_refused(result, "screen_changed")
    assert fake.events == []


@pytest.mark.asyncio
async def test_if_the_app_does_not_come_forward_the_act_is_refused_as_before(monkeypatch):
    from services.tools.computer import toolkit

    monkeypatch.setattr(toolkit, "BRING_FORWARD_WAIT_S", 0.1)

    class Stubborn(FakeBackend):
        def focus_window(self, app, index):
            self._event("focus_window", app, index)  # recorded, but nothing moves

    fake = Stubborn(calendar_desktop().apps.values(), frontmost="Calendar", focused="search")
    kit, seen = await observed(fake)
    fake.front = "Telegram"
    result = await approved_act(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert_refused(result, "frontmost_changed")
    # Asked twice (macOS can ignore the first request), then refused.
    assert fake.events == [("focus_window", "Calendar", 0)] * toolkit.BRING_FORWARD_ATTEMPTS


@pytest.mark.asyncio
async def test_an_app_that_ignores_the_first_request_comes_forward_on_the_second(monkeypatch):
    # Seen on a real Mac: a background process's first activation request
    # was ignored and the second one worked.
    from services.tools.computer import toolkit

    monkeypatch.setattr(toolkit, "BRING_FORWARD_WAIT_S", 0.1)

    class SecondTime(FakeBackend):
        asked = 0

        def focus_window(self, app, index):
            self.asked += 1
            if self.asked == 1:
                self._event("focus_window", app, index)  # ignored
                return
            super().focus_window(app, index)

    fake = SecondTime(calendar_desktop().apps.values(), frontmost="Calendar", focused="search")
    kit, seen = await observed(fake)
    fake.front = "Telegram"
    result = await approved_act(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert result["ok"] is True, result
    assert fake.events == [
        ("focus_window", "Calendar", 0),
        ("focus_window", "Calendar", 0),
        ("click", "next", False),
    ]


@pytest.mark.asyncio
async def test_a_failing_bring_forward_is_refused_as_before():
    fake = calendar_desktop()
    kit, seen = await observed(fake)
    fake.front = "Telegram"
    fake.failures["focus_window"] = RuntimeError("activation refused")
    result = await approved_act(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert_refused(result, "frontmost_changed")
    assert [e[0] for e in fake.events] == ["focus_window"]


@pytest.mark.asyncio
async def test_an_unreadable_front_app_is_refused_as_before():
    fake = calendar_desktop()
    kit, seen = await observed(fake)
    fake.front = "Telegram"
    fake.failures["frontmost"] = RuntimeError("no answer")
    result = await approved_act(kit, {"action": "click", "ref": ref(seen, '"Next month"')})
    assert_refused(result, "unknown_app")
    assert fake.events == []


def test_crawlers_own_app_is_the_blocked_entry_named_crawler_app():
    assert rules.blocked_app("Crawler AI") == rules.CRAWLER_APP
    assert rules.CRAWLER_APP in rules.BLOCKED_APPS
