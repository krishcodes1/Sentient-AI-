"""browser.read: against fakes (no browser) and, further down, against the
fake site in headless Chromium (skipped when Playwright's Chromium is not
installed). Never a real website, never a headed window."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import re
import threading
import time
from pathlib import Path

import pytest
import pytest_asyncio
from PIL import Image

from services.tools.browser import actions, guard, handoff
from services.tools.browser import snapshot as snap
from services.tools.browser.actions import (
    BROWSER_MAX_ACTIONS,
    BROWSER_MAX_USD,
    BrowserReadToolkit,
)
from services.tools.browser.checkout import markers
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.session import BrowserSessionManager, TaskState
from services.tools.system import browser_installed
from tests.fakesite.pages import DELAYS, PAGES, SAVED_CARD_LEAD, _page


class FakeSession:
    def __init__(self, task_id: str = "t1") -> None:
        self.user_id = "u1"
        self.mode = "account"
        self.context = object()
        self.lock = asyncio.Lock()
        self.task = TaskState(task_id=task_id)
        self.last_used = 0.0
        self.typed_secrets: list[str] = []

    async def page(self):
        raise AssertionError("this test must not touch a page")

    async def tabs(self):
        return []

    async def switch(self, index):
        raise IndexError(index)


class FakeSessions:
    def __init__(self) -> None:
        self.session = FakeSession()
        self.calls: list[tuple[str, str, str]] = []

    async def get(self, user_id, *, mode, task_id):
        self.calls.append((user_id, mode, task_id))
        if self.session.task.task_id != task_id:
            self.session.task = TaskState(task_id=task_id)
        return self.session

    async def close_all(self):
        pass


class FakeGuard:
    BLOCKED_NAVIGATION_MARKER = "net::ERR_BLOCKED_BY_CLIENT"

    def __init__(self) -> None:
        self.installed: list[tuple[object, bool]] = []

    def check_url(self, url):
        return None

    async def install_egress_guard(self, context, *, account_mode):
        self.installed.append((context, account_mode))

    async def consequential(self, page, ref):
        return None

    async def settle_blocked_navigation(self, page, *, timeout_ms=1500):
        return None

    def egress_state(self, context):
        return None


class FakeHandoff:
    async def detect_challenge(self, page):
        return None


def fake_kit():
    sessions, guard = FakeSessions(), FakeGuard()
    return BrowserReadToolkit(sessions, guard=guard, handoff=FakeHandoff()), sessions, guard


async def call(kit, action, task_id="t1", **params):
    return await kit.execute(action, params, user_id="u1", task_id=task_id)


# ── dispatch and gates (no browser) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_action_fails_closed_without_a_browser():
    kit, sessions, _ = fake_kit()
    result = await call(kit, "type", ref="e1", text="x")
    assert result["ok"] is False and "Unknown browser action 'type'" in result["error"]
    assert sessions.calls == []
    assert (await kit.execute(None, {}, user_id="u1", task_id="t1"))["ok"] is False  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_bad_arguments_fail_closed_without_a_browser():
    kit, sessions, _ = fake_kit()
    result = await call(kit, "note", ref="e1")
    assert result["ok"] is False and "browser.read note" in result["error"]
    assert sessions.calls == []


@pytest.mark.asyncio
async def test_null_arguments_are_treated_as_absent_and_notes_are_not_counted():
    kit, sessions, _ = fake_kit()
    result = await kit.execute(
        "note", {"text": "keep this", "url": None, "ref": None}, user_id="u1", task_id="t1"
    )
    assert result == {
        "ok": True,
        "notes": ["keep this"],
        "summary": "note · 1 kept",
        "mode": "account",
    }
    assert sessions.calls == [("u1", "account", "t1")]
    assert sessions.session.task.actions == 0


@pytest.mark.asyncio
async def test_notes_are_capped_at_two_thousand_characters():
    kit, sessions, _ = fake_kit()
    assert (await call(kit, "note", text="a" * 1900))["ok"] is True
    full = await call(kit, "note", text="b" * 200)
    assert full["ok"] is False and "Notes are full (1900 of 2000" in full["error"]
    assert full["notes"] == ["a" * 1900]
    assert (await call(kit, "note", text="   "))["ok"] is False


@pytest.mark.asyncio
async def test_action_cap_returns_a_resume_hint():
    kit, sessions, _ = fake_kit()
    sessions.session.task.actions = BROWSER_MAX_ACTIONS
    result = await call(kit, "note", text="x")
    assert result == {
        "ok": False,
        "cap": "actions",
        "resume_hint": result["resume_hint"],
    }
    assert "60" in result["resume_hint"] and sessions.session.task.notes == []


@pytest.mark.asyncio
async def test_spend_cap_returns_a_resume_hint():
    kit, sessions, _ = fake_kit()
    sessions.session.task.spend_usd = BROWSER_MAX_USD
    result = await call(kit, "note", text="x")
    assert result["cap"] == "spend" and "$0.25" in result["resume_hint"]


@pytest.mark.asyncio
async def test_three_identical_calls_in_a_row_are_a_loop():
    kit, sessions, _ = fake_kit()
    for _ in range(2):
        assert (await call(kit, "note", text="same"))["ok"] is True
    third = await call(kit, "note", text="same")
    assert third["ok"] is False and "Loop detected" in third["error"]
    assert sessions.session.task.notes == ["same", "same"]
    # a different call breaks the streak; the streak is per task
    assert (await call(kit, "note", text="other"))["ok"] is True
    assert (await call(kit, "note", text="same", task_id="t2"))["ok"] is True


@pytest.mark.asyncio
async def test_egress_guard_is_installed_once_per_context():
    kit, sessions, guard = fake_kit()
    await call(kit, "note", text="a")
    await call(kit, "note", text="b")
    assert guard.installed == [(sessions.session.context, True)]
    sessions.session.context = object()  # the manager relaunched the browser
    await call(kit, "note", text="c")
    assert len(guard.installed) == 2


@pytest.mark.asyncio
async def test_a_browser_that_will_not_start_is_a_result_not_an_exception():
    class Broken(FakeSessions):
        async def get(self, user_id, *, mode, task_id):
            raise RuntimeError("Executable doesn't exist at /Users/x/.cache/ms-playwright")

    kit = BrowserReadToolkit(Broken(), guard=FakeGuard(), handoff=FakeHandoff())
    result = await call(kit, "note", text="x")
    assert result["ok"] is False
    assert result["error"].startswith("Could not start the browser")
    assert "ms-playwright" not in result["error"]


@pytest.mark.asyncio
async def test_egress_guard_memo_does_not_trust_a_recycled_id(monkeypatch):
    """CPython reuses the id() of a freed object, so a relaunched context
    can carry the old one's id. The guard must still be installed on it."""
    from services.tools.browser import actions

    monkeypatch.setattr(actions, "id", lambda _obj: 1, raising=False)
    kit, sessions, guard = fake_kit()
    await call(kit, "note", text="a")
    first = sessions.session.context
    sessions.session.context = object()  # relaunched; same id() under the patch
    await call(kit, "note", text="b")
    assert guard.installed == [(first, True), (sessions.session.context, True)]


@pytest.mark.asyncio
async def test_a_guard_that_will_not_install_fails_closed():
    class BrokenGuard(FakeGuard):
        async def install_egress_guard(self, context, *, account_mode):
            raise RuntimeError("Target page, context or browser has been closed")

    sessions = FakeSessions()
    kit = BrowserReadToolkit(sessions, guard=BrokenGuard(), handoff=FakeHandoff())
    result = await call(kit, "note", text="x")
    assert result["ok"] is False and "browser" in result["error"].lower()
    assert "has been closed" not in result["error"]
    # the action never ran on an unguarded context
    assert sessions.session.task.notes == [] and sessions.session.task.actions == 0


@pytest.mark.asyncio
async def test_action_failure_logs_carry_no_query_string_or_fragment():
    from structlog.testing import capture_logs

    kit, _, _ = fake_kit()

    async def boom(session, text):
        raise RuntimeError(
            "page.goto: net::ERR_FAILED at "
            f"https://canvas.school.edu/c?token=SECRET1#SECRET2 ({text})"
        )

    kit._handlers["note"] = boom
    with capture_logs() as logs:
        result = await call(kit, "note", text="x")
    assert result == {"ok": False, "error": "browser.read note failed."}
    assert logs and "canvas.school.edu/c" in repr(logs)
    assert "SECRET" not in repr(logs)


@pytest.mark.asyncio
async def test_params_that_are_not_an_object_fail_closed():
    kit, sessions, _ = fake_kit()
    result = await kit.execute("note", ["x"], user_id="u1", task_id="t1")  # type: ignore[arg-type]
    assert result["ok"] is False and "browser.read note" in result["error"]
    assert sessions.calls == []


# ── against the fake site (headless Chromium) ────────────────────────────


class TestPlatform:
    """The container platform, minus services.platform's cache: headless
    Chromium, no channel, profiles under the test's tmp dir."""

    __test__ = False  # a helper, not a test class (pytest collects Test*)
    name = "container"

    def __init__(self, root: Path) -> None:
        self._root = root

    def browser_channel(self):
        return None

    def profile_dir(self, user_id: str) -> Path:
        path = self._root / user_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def data_dir(self) -> Path:
        return self._root

    def bring_to_front(self, *, pid=None, title=None) -> bool:
        return False

    def port_owner(self, port: int):
        return None


@pytest_asyncio.fixture
async def kit(fakesite, tmp_path):
    if not browser_installed():
        pytest.skip(
            "Playwright's Chromium is not installed (python -m playwright install chromium)"
        )
    sessions = BrowserSessionManager(
        headless=True, platform=TestPlatform(tmp_path), max_sessions=1, max_tabs=2
    )
    toolkit = BrowserReadToolkit(sessions, guard=guard, handoff=handoff)
    try:
        yield toolkit, sessions
    finally:
        await sessions.close_all()


async def run(kit, action, **params):
    toolkit, _ = kit
    return await toolkit.execute(action, params, user_id="u1", task_id="t1")


def ref_of(result, prefix: str) -> str:
    """The ref on the first outline line that starts with *prefix*."""
    for line in result["outline"]:
        if line.lstrip().startswith(prefix):
            match = re.search(r"\[ref=((?:f\d+)?e\d+)\]", line)
            if match:
                return match.group(1)
    raise AssertionError(f"no {prefix!r} line with a ref in {result['outline']}")


def safe_link(result) -> tuple[str, str]:
    """(ref, name) of the first link whose name is not a consequential word."""
    for line in result["outline"]:
        match = re.search(r'- link "([^"]+)".*\[ref=((?:f\d+)?e\d+)\]', line)
        if match and not any(word in match.group(1).lower() for word in guard.CONSEQUENTIAL_NAMES):
            return match.group(2), match.group(1)
    raise AssertionError(f"no plain link in {result['outline']}")


def decode(data_url: str) -> Image.Image:
    return Image.open(io.BytesIO(base64.b64decode(data_url.split(",", 1)[1]))).convert("RGB")


@pytest.mark.asyncio
async def test_open_returns_the_outline_with_refs(kit, fakesite):
    result = await run(kit, "open", url=fakesite.url("/"))
    assert result["ok"] is True
    assert result["url"].rstrip("/") == fakesite.url("/").rstrip("/")
    assert result["refs"] >= 1 and any("[ref=e" in line for line in result["outline"])
    assert result["truncated"] is False and result["notes"] == []
    assert result["mode"] == "account"
    assert result["summary"].startswith("[step 1] open ")
    assert "user_image" not in result and "image" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/hosts", "http://10.0.0.1/"])
async def test_open_refuses_urls_the_guard_rejects(kit, url):
    result = await run(kit, "open", url=url)
    assert result["ok"] is False and "Refusing to open" in result["error"]
    assert (await run(kit, "open", url=""))["ok"] is False


@pytest.mark.asyncio
async def test_a_redirect_to_a_private_host_is_refused_with_the_blocked_host(kit, fakesite):
    result = await run(kit, "open", url=fakesite.url("/redirect-private"))
    assert result["ok"] is False and result["error"].startswith("Refusing to open http://10.0.0.1/")
    assert "10.0.0.1" in result["error"]
    assert (await run(kit, "open", url=fakesite.url("/")))["ok"] is True  # the next open works


@pytest.mark.asyncio
async def test_open_follows_a_multi_hop_redirect_to_the_page_it_lands_on(kit, fakesite, monkeypatch):
    from tests.fakesite.pages import REDIRECTS

    monkeypatch.setitem(REDIRECTS, "/go/1", "/go/2")
    monkeypatch.setitem(REDIRECTS, "/go/2", fakesite.url("/go/3"))
    monkeypatch.setitem(REDIRECTS, "/go/3", "/grades")
    result = await run(kit, "open", url=fakesite.url("/go/1"))
    assert result["ok"] is True and result["url"] == fakesite.url("/grades")
    assert result["http_status"] == 200 and "error_page" not in result
    assert any("Grades for" in line for line in result["outline"])
    assert [path for _m, path in fakesite.handled] == ["/go/1", "/go/2", "/go/3", "/grades"]


@pytest.mark.asyncio
async def test_a_later_hop_to_a_private_host_is_refused_as_plainly_as_the_first(kit, fakesite, monkeypatch):
    """The first hop's goto succeeds (the guard hands a redirect back as a
    page that moves on), so a hop stopped further down the chain must still
    come back as a refusal naming the host, never as an empty error page."""
    from tests.fakesite.pages import REDIRECTS

    monkeypatch.setitem(REDIRECTS, "/go/1", "/go/2")
    monkeypatch.setitem(REDIRECTS, "/go/2", "http://10.0.0.1/admin")
    result = await run(kit, "open", url=fakesite.url("/go/1"))
    assert result == {
        "ok": False,
        "error": "Refusing to open http://10.0.0.1/admin: 10.0.0.1 resolves to a private or local address (10.0.0.1)",
    }
    assert (await run(kit, "open", url=fakesite.url("/")))["ok"] is True  # the next open works


@pytest.mark.asyncio
async def test_open_says_plainly_when_the_address_is_not_a_page_of_the_site(kit, fakesite):
    """A shop's 404 page has menus and reads like a page: the result and
    the summary line that outlives its outline both carry the status."""
    result = await run(kit, "open", url=fakesite.url("/shop/iphone-16-pro-max-grip-case-holo-white"))
    assert result["ok"] is True and result["http_status"] == 404
    assert result["error_page"].startswith("The site answered HTTP 404: there is no page at this address.")
    assert "blocked" not in result  # a missing page is not the site refusing the browser
    assert result["summary"].endswith(" · HTTP 404")
    _toolkit, sessions = kit
    session = await sessions.get("u1", mode="account", task_id="t1")
    assert session.task.summaries[-1] == result["summary"]
    assert "error_page" not in await run(kit, "open", url=fakesite.url("/grades"))


@pytest.mark.asyncio
async def test_account_mode_strips_query_strings_from_urls(kit, fakesite):
    result = await run(kit, "open", url=fakesite.url("/grades?student=42#top"))
    assert result["ok"] is True
    assert result["url"].endswith("/grades") and "student" not in result["url"]


@pytest.mark.asyncio
async def test_snapshot_filters_by_query_and_full_reads_more(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/grades"))
    narrow = await run(kit, "snapshot", query="Missing")
    assert narrow["ok"] is True and narrow["outline"]
    assert any("Missing" in line for line in narrow["outline"])
    assert "Privacy" not in "\n".join(narrow["outline"])  # below the fold, not matching
    full = await run(kit, "snapshot", full=True)
    assert full["ok"] is True and len(full["outline"]) >= len(narrow["outline"])
    assert "Privacy policy" in "\n".join(full["outline"])
    assert full["summary"].startswith("[step 3] ")


@pytest.mark.asyncio
async def test_click_on_a_link_navigates_and_returns_the_new_page(kit, fakesite):
    home = await run(kit, "open", url=fakesite.url("/"))
    ref, name = safe_link(home)
    result = await run(kit, "click", ref=ref)
    assert result["ok"] is True
    assert result["url"] != home["url"]
    assert result["summary"].startswith(f'[step 2] click "{name}" → ')


@pytest.mark.asyncio
async def test_read_tier_click_on_a_sign_up_button_is_refused(kit, fakesite):
    page = await run(kit, "open", url=fakesite.url("/post"))
    ref = ref_of(page, '- button "Sign up"')
    result = await run(kit, "click", ref=ref)
    assert result["ok"] is False
    assert result["error"] == markers.READ_CLICK_MESSAGE
    assert result["consequential"]
    assert result["ref"] == ref  # what browser.act is called with for the same click
    assert (await run(kit, "snapshot"))["url"].endswith("/post")  # nothing was submitted


@pytest.mark.asyncio
async def test_stale_ref_is_reported_within_a_few_seconds(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/"))
    started = time.monotonic()
    result = await run(kit, "click", ref="e9999")
    assert result == {"ok": False, "error": "stale ref: re-snapshot", "stale_ref": True}
    assert time.monotonic() - started < 8
    assert (await run(kit, "click", ref="not-a-ref"))["ok"] is False


@pytest.mark.asyncio
async def test_open_a_blocking_captcha_needs_a_human(kit, fakesite):
    result = await run(kit, "open", url=fakesite.url("/captcha"))
    assert result["ok"] is False and "outline" not in result and result["mode"] == "account"
    needs = result["needs_human"]
    assert needs["kind"] == "captcha" and needs["url"].endswith("/captcha")
    assert needs["user_image"].startswith("data:image/jpeg;base64,")
    # and the agent never clicks on a challenge page
    assert "needs_human" in await run(kit, "click", ref="e1")


@pytest.mark.asyncio
async def test_an_invisible_badge_is_not_a_challenge(kit, fakesite):
    result = await run(kit, "open", url=fakesite.url("/badge"))
    assert result["ok"] is True and "needs_human" not in result


@pytest.mark.asyncio
async def test_each_page_action_is_counted_and_summarised(kit, fakesite):
    _toolkit, sessions = kit
    await run(kit, "open", url=fakesite.url("/"))
    await run(kit, "note", text="remember")
    await run(kit, "snapshot")
    session = await sessions.get("u1", mode="account", task_id="t1")
    assert session.task.actions == 2
    assert [s.split("]")[0] for s in session.task.summaries] == ["[step 1", "[step 2"]


@pytest.mark.asyncio
async def test_counted_action_cap_is_checked_before_the_increment():
    kit, sessions, _ = fake_kit()
    sessions.session.task.actions = BROWSER_MAX_ACTIONS - 1
    assert (await call(kit, "tabs"))["ok"] is True  # the 60th action runs
    assert sessions.session.task.actions == BROWSER_MAX_ACTIONS
    assert (await call(kit, "tabs"))["cap"] == "actions"  # the 61st is refused
    assert sessions.session.task.actions == BROWSER_MAX_ACTIONS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action, params", [("snapshot", {}), ("find", {"text": "x"}), ("text", {})]
)
async def test_every_reading_action_refuses_on_a_challenge_page(kit, fakesite, action, params):
    await run(kit, "open", url=fakesite.url("/captcha"))
    result = await run(kit, action, **params)
    assert result["ok"] is False and result["needs_human"]["kind"] == "captcha"
    assert "outline" not in result and "matches" not in result and "text" not in result


@pytest.mark.asyncio
async def test_find_returns_matches_with_their_row(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/grades"))
    result = await run(kit, "find", text="Missing")
    assert result["ok"] is True and result["count"] >= 1
    assert any("Missing" in line for line in result["matches"])
    assert any(line.lstrip().startswith("- row") for line in result["matches"])
    assert result["truncated"] is False and result["mode"] == "account"
    assert (
        result["summary"]
        == f'[step 2] find "Missing" → {snap.host_path(result["url"])} · {result["count"]} matches'
    )
    assert (await run(kit, "find", text=" "))["ok"] is False


@pytest.mark.asyncio
async def test_text_returns_visible_text_of_the_page_or_an_element(kit, fakesite):
    home = await run(kit, "open", url=fakesite.url("/"))
    whole = await run(kit, "text")
    assert whole["ok"] is True and whole["chars"] == len(whole["text"]) > 0
    assert whole["truncated"] is False
    ref, name = safe_link(home)
    part = await run(kit, "text", ref=ref)
    assert part["text"].strip() == name
    assert (
        part["summary"]
        == f"[step 3] text {ref} → {snap.host_path(part['url'])} · {part['chars']} chars"
    )
    assert (await run(kit, "text", ref="e9999"))["stale_ref"] is True


@pytest.mark.asyncio
async def test_scroll_returns_the_outline_and_refuses_bad_directions(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/flights"))
    assert (await run(kit, "scroll", direction="down"))["ok"] is True
    assert (await run(kit, "scroll", direction="bottom"))["ok"] is True
    bad = await run(kit, "scroll", direction="sideways")
    assert bad["ok"] is False and "direction" in bad["error"]


@pytest.mark.asyncio
async def test_back_returns_to_the_previous_page_and_knows_when_there_is_none(kit, fakesite):
    assert "no earlier page" in (await run(kit, "back"))["error"]
    await run(kit, "open", url=fakesite.url("/"))
    only = await run(kit, "back")
    assert only["ok"] is False and "no earlier page" in only["error"]
    assert (await run(kit, "snapshot"))["url"].rstrip("/") == fakesite.url("/").rstrip("/")
    await run(kit, "open", url=fakesite.url("/grades"))
    result = await run(kit, "back")
    assert result["ok"] is True and result["url"].rstrip("/") == fakesite.url("/").rstrip("/")


@pytest.mark.asyncio
async def test_tabs_and_switch(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/"))
    tabs = await run(kit, "tabs")
    assert tabs["ok"] is True and len(tabs["tabs"]) == 1
    assert tabs["tabs"][0]["active"] is True and tabs["tabs"][0]["index"] == 0
    assert tabs["summary"] == "[step 2] tabs · 1 open" and tabs["mode"] == "account"
    assert (await run(kit, "switch", index=0))["ok"] is True
    missing = await run(kit, "switch", index=5)
    assert missing["ok"] is False and "No tab 5" in missing["error"]
    assert (await run(kit, "switch", index=-1))["ok"] is False
    assert (await run(kit, "switch", index=True))["ok"] is False


@pytest.mark.asyncio
async def test_wait_for_text_and_for_time(kit, fakesite):
    home = await run(kit, "open", url=fakesite.url("/"))
    _ref, name = safe_link(home)
    assert (await run(kit, "wait", text=name))["ok"] is True
    assert (await run(kit, "wait", ms=50))["ok"] is True
    gone = await run(kit, "wait", text="zzz-not-on-this-page", ms=300)
    assert gone["ok"] is False and "did not appear" in gone["error"]
    assert (await run(kit, "wait", ms=20_000))["ok"] is False
    assert (await run(kit, "wait", ms=0))["ok"] is False
    assert (await run(kit, "wait"))["ok"] is False


@pytest.mark.asyncio
async def test_screenshot_goes_to_the_person_not_the_model(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/flights"))
    result = await run(kit, "screenshot")
    assert result["ok"] is True
    assert result["user_image"].startswith("data:image/jpeg;base64,")
    assert "image" not in result
    assert result["outline"] and result["summary"].startswith("[step 2] ")


@pytest.mark.asyncio
async def test_screenshot_for_model_adds_a_small_copy(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/flights"))
    result = await run(kit, "screenshot", for_model=True)
    small, big = decode(result["image"]), decode(result["user_image"])
    assert max(small.size) <= 768 < max(big.size)


@pytest.mark.asyncio
async def test_screenshot_of_a_ref_and_of_a_stale_ref(kit, fakesite):
    home = await run(kit, "open", url=fakesite.url("/"))
    ref, _ = safe_link(home)
    result = await run(kit, "screenshot", ref=ref)
    assert result["ok"] is True and result["user_image"]
    started = time.monotonic()
    assert (await run(kit, "screenshot", ref="e9999"))["stale_ref"] is True
    assert time.monotonic() - started < 8  # REF_TIMEOUT_MS, not Playwright's 30 s default


@pytest.mark.asyncio
async def test_screenshot_masks_password_fields_in_both_copies(kit, fakesite):
    _toolkit, sessions = kit
    await run(kit, "open", url=fakesite.url("/signup"))
    result = await run(kit, "screenshot", for_model=True)
    page = await (await sessions.get("u1", mode="account", task_id="t1")).page()
    box = await page.locator("input[type=password]").bounding_box()
    cx, cy = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    big = decode(result["user_image"])
    assert sum(big.getpixel((int(cx), int(cy)))) < 60
    small = decode(result["image"])
    scale = small.size[0] / big.size[0]
    assert sum(small.getpixel((int(cx * scale), int(cy * scale)))) < 60


@pytest.mark.asyncio
async def test_handoff_ends_the_turn_with_a_picture(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/login"))
    result = await run(kit, "handoff", reason="Please  sign in")
    assert result["ok"] is False
    assert result["needs_human"]["kind"] == "requested"
    assert result["needs_human"]["detail"] == "Please sign in"
    assert result["needs_human"]["url"].endswith("/login")
    assert result["needs_human"]["user_image"].startswith("data:image/jpeg;base64,")
    assert (await run(kit, "handoff", reason=""))["ok"] is False


async def guard_state(kit):
    _toolkit, sessions = kit
    session = await sessions.get("u1", mode="account", task_id="t1")
    return session, guard.egress_state(session.context)


@pytest.mark.asyncio
async def test_the_person_signs_in_during_a_handoff_and_the_agent_reads_the_signed_in_page(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/login"))
    assert (await run(kit, "handoff", reason="Please sign in"))["needs_human"]["kind"] == "requested"
    session, state = await guard_state(kit)
    assert state.human_driving is True
    assert session.pending == "handoff"  # the idle reaper leaves the window to the person
    # The person, in Crawler's window: the login POST goes through.
    page = await session.page()
    await page.fill("input[name=username]", "krish")
    await page.fill("input[name=password]", "hunter2")
    await page.locator("button").click()
    await page.wait_for_url("**/home")
    assert state.blocked == []
    # "done": the first read sees the signed-in page, no second handoff,
    # and the window is shut before the agent touches the page.
    result = await run(kit, "snapshot")
    assert result["ok"] is True and "needs_human" not in result and result["url"].endswith("/home")
    assert any("Signed in" in line for line in result["outline"])
    assert state.human_driving is False and session.pending is None
    # From here a form submit in the agent's page is read-tier again.
    await run(kit, "open", url=fakesite.url("/post"))
    await page.locator("button").click()
    await guard.settle_blocked_navigation(page)
    assert state.blocked[-1]["reason"].startswith("non-GET top-level navigation")


@pytest.mark.asyncio
async def test_a_detected_challenge_is_a_handoff_too_and_stays_cleared_once_the_person_is_through(kit, fakesite):
    assert (await run(kit, "open", url=fakesite.url("/sso/otp")))["needs_human"]["kind"] == "otp"
    session, state = await guard_state(kit)
    assert state.human_driving is True
    page = await session.page()
    await page.fill("#otp", "123456")
    await page.locator("button").click()
    await page.wait_for_load_state("domcontentloaded")
    result = await run(kit, "snapshot")
    assert result["ok"] is True and "needs_human" not in result
    assert any("Thanks" in line for line in result["outline"]) and state.blocked == []
    assert state.human_driving is False


@pytest.mark.asyncio
async def test_closing_the_session_ends_a_pending_handoff(kit, fakesite):
    _toolkit, sessions = kit
    await run(kit, "open", url=fakesite.url("/login"))
    await run(kit, "handoff", reason="Please sign in")
    _session, state = await guard_state(kit)
    assert state.human_driving is True
    await sessions.close("u1")
    assert state.human_driving is False


@pytest.mark.asyncio
async def test_notes_come_back_with_every_observation(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/grades"))
    await run(kit, "note", text="Essay 1 is missing")
    assert (await run(kit, "snapshot"))["notes"] == ["Essay 1 is missing"]


# ── review fixes: secrets, frames, stale refs, bookkeeping ───────────────


async def live_page(kit):
    _toolkit, sessions = kit
    return await (await sessions.get("u1", mode="account", task_id="t1")).page()


def textbox_refs(result) -> list[str]:
    refs = []
    for line in result["outline"]:
        match = re.search(r"\[ref=((?:f\d+)?e\d+)\]", line)
        if "textbox" in line and match:
            refs.append(match.group(1))
    return refs


@pytest.mark.asyncio
async def test_a_click_summary_never_carries_a_field_value(kit, fakesite):
    """A password field outside any <form> is not consequential, so the
    read-tier click runs; its summary must name the field, never echo the
    (autofilled) password or a card number the way el.value would."""
    await run(kit, "open", url=fakesite.url("/"))
    page = await live_page(kit)
    await page.set_content(
        "<label>Password <input type=password value='hunter2secret'></label>"
        "<label>Number <input name=num value='4111111111111111'></label>"
        "<input aria-label='Search' value='typed-by-the-owner'>"
    )
    refs = textbox_refs(await run(kit, "snapshot"))
    assert len(refs) == 3
    summaries = []
    for ref in refs:
        result = await run(kit, "click", ref=ref)
        assert result["ok"] is True
        summaries.append(result["summary"])
    joined = "\n".join(summaries)
    for value in ("hunter2secret", "4111111111111111", "typed-by-the-owner"):
        assert value not in joined
    assert 'click "Password"' in summaries[0] and 'click "Search"' in summaries[2]


@pytest.mark.asyncio
async def test_a_click_summary_keeps_the_value_of_an_input_button(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/"))
    page = await live_page(kit)
    await page.set_content("<input type=button value='Show more'>")
    ref = ref_of(await run(kit, "snapshot"), '- button "Show more"')
    assert 'click "Show more"' in (await run(kit, "click", ref=ref))["summary"]


@pytest.mark.asyncio
async def test_screenshot_masks_password_fields_inside_frames(kit, fakesite):
    """An IdP login or a card form embedded in an iframe is masked too:
    page.locator() alone never looks inside frames."""
    await run(kit, "open", url=fakesite.url("/"))
    page = await live_page(kit)
    await page.set_content(
        "<body style='margin:0'><iframe style='width:600px;height:300px;border:0' "
        "srcdoc=\"<body style='margin:0'><input type=password value='xxxxxxxx' "
        "style='width:400px;height:100px;border:0;background:red;color:red'></body>\">"
        "</iframe></body>"
    )
    await page.frames[1].wait_for_selector("input[type=password]")
    result = await run(kit, "screenshot", for_model=True)
    big = decode(result["user_image"])
    assert sum(big.getpixel((200, 50))) < 60
    small = decode(result["image"])
    scale = small.size[0] / big.size[0]
    assert sum(small.getpixel((int(200 * scale), int(50 * scale)))) < 60
    needs = await run(kit, "handoff", reason="Please sign in")
    assert sum(decode(needs["needs_human"]["user_image"]).getpixel((200, 50))) < 60


@pytest.mark.asyncio
async def test_a_ref_into_a_frame_that_does_not_exist_is_stale(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/"))
    assert (await run(kit, "text", ref="f9e1"))["stale_ref"] is True
    assert (await run(kit, "screenshot", ref="f9e1"))["stale_ref"] is True


@pytest.mark.asyncio
async def test_for_model_takes_only_a_real_true(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/flights"))
    result = await run(kit, "screenshot", for_model="false")
    assert result["ok"] is True and "image" not in result


@pytest.mark.asyncio
async def test_an_earlier_block_is_not_blamed_for_a_later_failed_click(kit, fakesite):
    """The blocked-navigation message names what THIS click tripped, not
    whatever the guard refused earlier in the session."""
    await run(kit, "open", url=fakesite.url("/redirect-private"))  # recorded as blocked
    await run(kit, "open", url=fakesite.url("/"))
    page = await live_page(kit)
    await page.set_content('<a href="http://127.0.0.1:9/">Docs</a>')  # connection refused
    ref = ref_of(await run(kit, "snapshot"), '- link "Docs"')
    result = await run(kit, "click", ref=ref)
    assert "10.0.0.1" not in str(result.get("error", ""))


@pytest.mark.asyncio
async def test_find_and_text_redact_typed_secrets_everywhere(kit, fakesite):
    _toolkit, sessions = kit
    await run(kit, "open", url=fakesite.url("/"))
    session = await sessions.get("u1", mode="account", task_id="t1")
    session.typed_secrets.append("s3cr3t-token")
    page = await session.page()
    await page.set_content(
        "<title>s3cr3t-token inbox</title><main><p>Your code s3cr3t-token is here</p></main>"
    )
    for result in (
        await run(kit, "text"),
        await run(kit, "find", text="code"),
        await run(kit, "tabs"),
    ):
        assert result["ok"] is True
        assert "s3cr3t-token" not in json.dumps(result)


@pytest.mark.asyncio
async def test_text_and_title_redact_a_typed_card_number_in_any_grouping(kit, fakesite):
    """The checkout puts the card number on the redaction list as digits;
    a page that echoes it grouped its own way (dots, spaces, dashes) must
    show none of it through ``text``, the title in ``tabs`` or ``find``,
    the way the outline hides it (snapshot.redact, not a plain replace)."""
    _toolkit, sessions = kit
    await run(kit, "open", url=fakesite.url("/"))
    session = await sessions.get("u1", mode="account", task_id="t1")
    session.typed_secrets.append("4242424242424242")
    page = await session.page()
    await page.set_content(
        "<title>Receipt for card 4242.4242.4242.4242</title><main><p>Charged card "
        "4242 4242 4242 4242 (also written 4242-4242-4242-4242); order 1987</p></main>"
    )
    for result in (
        await run(kit, "text"),
        await run(kit, "find", text="Charged"),
        await run(kit, "tabs"),
    ):
        assert result["ok"] is True
        shown = json.dumps(result)
        assert "4242 4242" not in shown and "4242.4242" not in shown and "4242-4242" not in shown
        assert "order 1987" in shown or "Receipt" in shown  # the rest of the page is intact


@pytest.mark.asyncio
async def test_open_checks_the_url_off_the_event_loop():
    """check_url resolves the host (blocking DNS); on the event loop it
    would stall every other request the server is handling."""
    kit, _sessions, fake_guard = fake_kit()
    on_loop_thread: list[bool] = []

    def check_url(url):
        on_loop_thread.append(threading.current_thread() is threading.main_thread())
        return "refused for the test"

    fake_guard.check_url = check_url
    result = await call(kit, "open", url="https://example.test/")
    assert result["ok"] is False and "refused for the test" in result["error"]
    assert on_loop_thread == [False]


@pytest.mark.asyncio
async def test_find_summary_keeps_long_search_text_short(kit, fakesite):
    await run(kit, "open", url=fakesite.url("/grades"))
    result = await run(kit, "find", text="Missing " + "x" * 500)
    assert result["ok"] is True and len(result["summary"]) < 160


# ── dead ends: refusals, loading, blocked sites, new tabs, a quit browser ──
# An owner asked for a cinema ticket. The read looked at a page before its
# showtimes had loaded, took the visible part for the whole page, was shown
# a site's block page as an ordinary one, and a refused click named no rule
# and no ref. Each test here is one of those, on the fake site.


@pytest.fixture
def page_at(monkeypatch):
    """Serve a page on the fake site for one test: ``page_at(path, body)``."""

    def add(path: str, body: str, title: str = "Test page", status: int = 200) -> str:
        monkeypatch.setitem(PAGES, path, (status, "text/html", _page(title, body)))
        return path

    return add


def posts(site) -> list[str]:
    return [path for method, path in site.handled if method == "POST"]


@pytest.mark.parametrize(
    "facts, rule",
    [
        (None, "could not tell what this click lands on"),
        ({"frame": True}, "could not tell what this click lands on"),
        ({"name": "Book now", "buttonish": True}, "its words read as a purchase"),
        ({"name": "$3.99", "buttonish": True}, "its words read as a purchase"),
        ({"name": "$3.99"}, "its words read as a purchase"),
        ({"name": "Continue", "buttonish": True, "in_form": True, "card_in_form": True}, "its form holds a card number"),
        ({"name": "Seats", "link": True, "plain_link": True, "href": "/buy/1?qty=2"}, "it leads to an order address"),
        (
            {"name": "Continue", "buttonish": True, "in_form": True, "sends": True, "action": "/place-order"},
            "it leads to an order address",
        ),
        (
            {"name": "Continue", "buttonish": True, "order_total": True, "saved_payment": True, "money": True},
            "the page shows a payment method or an order total",
        ),
        ({"name": "Show more", "wallet": True}, "the page shows a payment method or an order total"),
        ({"name": "Filters", "buttonish": True, "in_form": True}, "it is a button or a form control"),
    ],
)
def test_a_refused_click_is_put_down_to_a_rule_that_refuses_it(facts, rule):
    assert not markers.read_click_allowed(facts)  # each of these is a click browser.read leaves alone
    assert actions._click_rule(facts) == rule


@pytest.mark.parametrize(
    "body, prefix, consequential",
    [
        (
            SAVED_CARD_LEAD + '<button type="button">Continue</button>',
            '- button "Continue"',
            "may place an order: the page shows a payment method or an order total",
        ),
        (
            '<h1>Paper Tiger</h1><a href="/buy/1?qty=2">Seats</a>',
            '- link "Seats"',
            "may place an order: it leads to an order address",
        ),
        (
            '<h1>Paper Tiger</h1><button type="button">Book now</button>',
            '- button "Book now"',
            "may place an order: its words read as a purchase",
        ),
        (
            '<h1>Showtimes</h1><form action="/search"><button type="button">Filters</button></form>',
            '- button "Filters"',
            "it is a button or a form control",
        ),
    ],
)
@pytest.mark.asyncio
async def test_a_refused_click_carries_its_ref_and_the_rule_that_fired(kit, fakesite, page_at, body, prefix, consequential):
    """The model is told to make the click with browser.act: it needs the
    ref to do it, and the rule to say why in its own words. The log line
    holds the rule and booleans, never the page's words or addresses."""
    from structlog.testing import capture_logs

    page = await run(kit, "open", url=fakesite.url(page_at("/refused", body)))
    ref = ref_of(page, prefix)
    with capture_logs() as logs:
        result = await run(kit, "click", ref=ref)
    assert result == {
        "ok": False,
        "error": markers.READ_CLICK_MESSAGE,
        "consequential": consequential,
        "ref": ref,
    }
    [line] = [entry for entry in logs if entry["event"] == "browser_read_click_refused"]
    assert line.pop("rule") == consequential.removeprefix("may place an order: ")
    assert line.pop("log_level") == "info" and line.pop("event")
    assert line and all(isinstance(value, bool) for value in line.values()), line
    _toolkit, sessions = kit
    session = await sessions.get("u1", mode="account", task_id="t1")
    assert session.task.summaries[-1] == f"[step 2] click {ref} refused: {consequential}"
    assert (await run(kit, "snapshot"))["url"].endswith("/refused")  # nothing was clicked


@pytest.mark.asyncio
async def test_a_click_the_guard_refuses_by_name_is_logged_by_its_rule_alone(kit, fakesite):
    from structlog.testing import capture_logs

    page = await run(kit, "open", url=fakesite.url("/post"))
    with capture_logs() as logs:
        result = await run(kit, "click", ref=ref_of(page, '- button "Sign up"'))
    assert result["consequential"] == "submit control"
    assert [entry for entry in logs if entry["event"] == "browser_read_click_refused"] == [
        {"event": "browser_read_click_refused", "log_level": "info", "rule": "submit control"}
    ]


@pytest.mark.parametrize(
    "body, name",
    [
        # The click's own handler sends page statistics, then the link is followed.
        ('<a href="/grades" onclick="navigator.sendBeacon(\'/collect\', \'click=1\')">Paper Tiger</a>', "Paper Tiger"),
        # The page the link leads to sends something of its own as it loads.
        ('<a href="/loads-and-sends">Paper Tiger</a>', "Paper Tiger"),
        # The same, opened in a new tab.
        ('<a href="/loads-and-sends" target="_blank">Paper Tiger</a>', "Paper Tiger"),
    ],
)
@pytest.mark.asyncio
async def test_a_click_that_opened_a_page_describes_it_though_a_page_script_request_was_stopped(
    kit, fakesite, page_at, body, name
):
    """The click was made and the page changed; the guard stopped a request
    a page script tried to send meanwhile. Reported as refused, the model
    believed nothing had happened and the page memory kept the old page."""
    _toolkit, sessions = kit
    memory = PageMemory()
    toolkit = BrowserReadToolkit(sessions, guard=guard, handoff=handoff, page_memory=memory)
    page_at(
        "/loads-and-sends",
        "<h1>Grades for nobody</h1><script>fetch('/graphql', {method: 'POST', body: '{}'}).catch(() => {})</script>",
    )
    page_at("/films", f"<h1>Films</h1>{body}")
    page = await toolkit.execute("open", {"url": fakesite.url("/films")}, user_id="u1", task_id="t1")
    result = await toolkit.execute("click", {"ref": ref_of(page, f'- link "{name}"')}, user_id="u1", task_id="t1")
    assert result["ok"] is True, result
    assert not result["url"].endswith("/films") and any("Grades for" in line for line in result["outline"])
    assert result["stopped_request"] == actions.STOPPED_REQUEST_NOTE
    assert result["summary"].startswith(f'[step 2] click "{name}" → ')
    assert posts(fakesite) == []  # the guard still stopped it: nothing was sent
    remembered = memory.get("u1")
    assert remembered is not None and remembered.url == result["url"]  # what the next browser.act is bound to
    # A look that follows carries no such note: nothing was stopped during it.
    again = await toolkit.execute("snapshot", {}, user_id="u1", task_id="t1")
    assert again["ok"] is True and "stopped_request" not in again


@pytest.mark.asyncio
async def test_a_page_that_came_up_empty_because_its_start_was_stopped_is_loaded_again(kit, fakesite, page_at):
    """A seat page asks for its cart by POST as it starts. Opened by a
    click with no card, that request is stopped with the click and the
    page shows nothing. It is loaded again once, like an open, and then
    described: the model used to be left on an empty page."""
    page_at(
        "/seat-start",
        "<script>fetch('/api/cart/status', {method: 'POST'})"
        ".then(() => { document.body.innerHTML = '<h1>Choose seats</h1><button>F7</button>' })"
        ".catch(() => {})</script>",
    )
    page = await run(kit, "open", url=fakesite.url(page_at("/films-seats", '<h1>Films</h1><a href="/seat-start">9:45 PM</a>')))
    result = await run(kit, "click", ref=ref_of(page, '- link "9:45 PM"'))
    assert result["ok"] is True and any("Choose seats" in line for line in result["outline"]), result
    assert "empty_page" not in result and result["opened_link"] == fakesite.url("/seat-start")


REFUSED_SEATS = (
    "<h1>Choose seats</h1><div id='map'>Loading</div>"
    "<script>fetch('/api/seat-map-missing').then(r => { if (!r.ok) document.getElementById('map')"
    ".innerHTML = '<div role=\"alertdialog\" aria-label=\"Alert\"><p>not found. Please try again.</p>"
    "<button>OK</button></div>' })</script>"
)


@pytest.mark.asyncio
async def test_a_page_whose_own_site_refused_its_content_says_so_and_gives_the_link(kit, fakesite, page_at):
    """A seat page asks its own site for the seat map, is refused, and puts
    up "not found. Please try again." The answer says the site refused the
    page and gives the link the click followed, query and all, which a
    person opens on their own device. Looking again says the same."""
    page_at("/seat-refused", REFUSED_SEATS)
    body = '<h1>Showtimes</h1><a href="/seat-refused?tid=AAQQP&sdate=2026-11-13">8:30 PM</a>'
    page = await run(kit, "open", url=fakesite.url(page_at("/showtimes-refused", body)))
    result = await run(kit, "click", ref=ref_of(page, '- link "8:30 PM"'))
    assert result["ok"] is True and result["site_refused"].startswith("This page could not load its own content"), result
    assert "HTTP 404" in result["site_refused"]
    assert result["finish_link"] == fakesite.url("/seat-refused?tid=AAQQP&sdate=2026-11-13")
    again = await run(kit, "snapshot")
    assert again["finish_link"] == result["finish_link"]


@pytest.mark.asyncio
async def test_a_failed_side_request_or_a_dialog_alone_is_not_a_refused_page(kit, fakesite, page_at):
    """A page whose one side request fails still works, and a dialog alone
    is a cookie banner as often as an error: neither is flagged."""
    fails_quietly = "<h1>Seats</h1><script>fetch('/api/recommendations-missing')</script><button>F7</button>"
    banner = "<h1>Seats</h1><div role='dialog' aria-label='Cookies'><p>We use cookies.</p><button>OK</button></div>"
    for path, body in (("/side-fails", fails_quietly), ("/banner-only", banner)):
        result = await run(kit, "open", url=fakesite.url(page_at(path, body)))
        await run(kit, "wait", ms=300)
        again = await run(kit, "snapshot")
        assert "site_refused" not in result and "site_refused" not in again, (path, again)


@pytest.mark.asyncio
async def test_a_link_whose_click_left_the_page_where_it_was_is_followed_by_its_address(kit, fakesite, page_at):
    """A carousel slide that moves under the click, a link a banner covers:
    the click is made and nothing happens. Told it had clicked, the model
    made the same click again and again. A link is followed by opening
    its address."""
    deaf = "<script>document.addEventListener('click', e => e.preventDefault(), true)</script>"
    page = await run(kit, "open", url=fakesite.url(page_at("/carousel", f'<h1>Films</h1><a href="/grades">Paper Tiger</a>{deaf}')))
    result = await run(kit, "click", ref=ref_of(page, '- link "Paper Tiger"'))
    assert result["ok"] is True and result["url"].endswith("/grades"), result
    assert result["opened_link"] == fakesite.url("/grades")


@pytest.mark.asyncio
async def test_a_wall_against_automated_browsers_is_a_block_not_a_handoff(kit, fakesite):
    """A search engine's "unusual traffic" page ended the whole task with
    "I need you to take over", on a site the model had only tried in
    passing. It is the site turning the browser away: the answer says so
    and to go another way. A CAPTCHA on a page still hands over."""
    from services.tools.browser import _shared

    for path in ("/human", "/bots.html"):
        result = await run(kit, "open", url=fakesite.url(path))
        assert result["ok"] is True and "needs_human" not in result, result
        assert result["blocked"] is True and result["error_page"] == _shared.TRAFFIC_WALL_NOTE
    captcha = await run(kit, "open", url=fakesite.url("/captcha"))
    assert captcha["ok"] is False and captcha["needs_human"]["kind"] == "captcha"


@pytest.mark.asyncio
async def test_a_banner_button_that_closed_its_banner_is_not_left_to_the_approval_step(kit, fakesite, page_at):
    """A cookie banner's "Continue" closes the banner and reports the
    choice. The report is stopped (reading sends nothing), but the banner
    is gone: told to make the same click with browser.act, the model was
    answered "stale ref" and had to look again."""
    banner = (
        '<div id="banner"><p>We use cookies.</p><button type="button" '
        "onclick=\"navigator.sendBeacon('/collect', 'ok=1'); document.getElementById('banner').remove()\">"
        "Continue</button></div><h1>Showtimes</h1>"
    )
    page = await run(kit, "open", url=fakesite.url(page_at("/banner", banner)))
    result = await run(kit, "click", ref=ref_of(page, '- button "Continue"'))
    assert result["ok"] is True and result["stopped_request"] == actions.STOPPED_REQUEST_NOTE, result
    assert not any("Continue" in line for line in result["outline"])
    assert posts(fakesite) == []


@pytest.mark.asyncio
async def test_a_click_says_which_link_it_followed_and_when_the_page_came_up_empty(kit, fakesite, page_at):
    """The showtime link opened a ticket page that showed an automated
    browser nothing. The page's own address had lost its query, so the
    model passed on a link that led nowhere and guessed at a sign-in."""
    page_at("/seats", "")
    body = '<a href="/seats?tid=AAQQP&date=2026-11-12">Buy tickets for 9:45 PM showtime</a> <a href="/grades">Grades</a>'
    page = await run(kit, "open", url=fakesite.url(page_at("/theater", f"<h1>Showtimes</h1>{body}")))
    result = await run(kit, "click", ref=ref_of(page, '- link "Buy tickets for 9:45 PM showtime"'))
    assert result["ok"] is True, result
    assert result["opened_link"] == fakesite.url("/seats?tid=AAQQP&date=2026-11-12")
    assert result["empty_page"] == actions.EMPTY_PAGE_NOTE
    # Looking again says the same, so the model stops looking.
    again = await run(kit, "snapshot")
    assert again["empty_page"] == actions.EMPTY_PAGE_NOTE
    # A page with something on it carries the link and no such note.
    page = await run(kit, "open", url=fakesite.url("/theater"))
    result = await run(kit, "click", ref=ref_of(page, '- link "Grades"'))
    assert result["opened_link"] == fakesite.url("/grades") and "empty_page" not in result


@pytest.mark.asyncio
async def test_a_stopped_request_to_an_order_address_is_not_called_statistics(kit, fakesite, page_at):
    """Next to a page that opened, a script's POST to an order address was
    passed over as "usually page statistics". It is still stopped; the
    answer now says what it was. With no page opened the click stays
    refused, for that reason."""
    body = "<a href=\"/grades\" onclick=\"fetch('/place-order', {method: 'POST'}).catch(() => {})\">Paper Tiger</a>"
    page = await run(kit, "open", url=fakesite.url(page_at("/films-order", f"<h1>Films</h1>{body}")))
    result = await run(kit, "click", ref=ref_of(page, '- link "Paper Tiger"'))
    assert result["ok"] is True and result["stopped_request"] == actions.STOPPED_ORDER_NOTE, result
    assert posts(fakesite) == []

    # A page that opened and then tried to move on to an order address: the
    # tab is on the page that opened, so that page is what the answer
    # describes (it used to be "refused", with a ref of a page that was gone).
    page_at("/seat-page", '<h1>Pick a seat</h1><iframe src="/buy/1" title="cart"></iframe>')
    page = await run(kit, "open", url=fakesite.url(page_at("/films-jump", '<h1>Films</h1><a href="/seat-page">9:45 PM</a>')))
    result = await run(kit, "click", ref=ref_of(page, '- link "9:45 PM"'))
    assert result["ok"] is True and result["url"].endswith("/seat-page"), result
    assert result["stopped_request"] == actions.STOPPED_ORDER_NOTE
    assert result["opened_link"] == fakesite.url("/seat-page")

    # A page that sends itself on to an order address by script: the click
    # is undone, and the page loaded again does not get there either.
    page_at("/jumps", "<h1>Wait</h1><script>setTimeout(() => { location.href = '/buy/1' }, 50)</script>")
    page = await run(kit, "open", url=fakesite.url(page_at("/films-jumps", '<h1>Films</h1><a href="/jumps">9:45 PM</a>')))
    result = await run(kit, "click", ref=ref_of(page, '- link "9:45 PM"'))
    assert result["ok"] is False, result
    assert not str((await run(kit, "tabs"))["tabs"][0].get("url", "")).endswith("/buy/1")

    stays = "<button type=\"button\" onclick=\"fetch('/place-order', {method: 'POST'})\">Show more</button>"
    page = await run(kit, "open", url=fakesite.url(page_at("/stays-order", f"<h1>Films</h1>{stays}")))
    ref = ref_of(page, '- button "Show more"')
    refused = await run(kit, "click", ref=ref)
    assert refused["ok"] is False and refused["consequential"] == actions.ORDER_REQUEST_REASON, refused
    assert posts(fakesite) == []


@pytest.mark.parametrize(
    "control, prefix, reason",
    [
        # Sends and stays: nothing was opened, so the request is all the click did.
        (
            "<button type=\"button\" onclick=\"fetch('/api/cart/items', {method: 'POST'})\">Show more</button>",
            '- button "Show more"',
            guard.READ_CLICK_REQUEST,
        ),
        # Sends and only moves within the page: the same page is still open.
        (
            "<a href=\"#more\" onclick=\"fetch('/api/cart/items', {method: 'POST'})\">Show more</a>",
            '- link "Show more"',
            guard.READ_CLICK_REQUEST,
        ),
        # Sends and opens an empty tab: no page was opened, and the tab is closed again.
        (
            "<button type=\"button\" onclick=\"fetch('/api/cart/items', {method: 'POST'}); "
            "window.open('about:blank')\">Show more</button>",
            '- button "Show more"',
            guard.READ_CLICK_REQUEST,
        ),
    ],
)
@pytest.mark.asyncio
async def test_a_click_that_only_sends_and_opens_no_page_is_still_refused(
    kit, fakesite, page_at, control, prefix, reason
):
    page = await run(kit, "open", url=fakesite.url(page_at("/sends", f"<h1>Concert ticket</h1>{control}")))
    ref = ref_of(page, prefix)
    result = await run(kit, "click", ref=ref)
    assert result == {"ok": False, "error": markers.READ_CLICK_MESSAGE, "consequential": reason, "ref": ref}
    assert posts(fakesite) == []
    assert len((await run(kit, "tabs"))["tabs"]) == 1
    # The page is still there, and the ref still names the control on it.
    here = await run(kit, "snapshot")
    assert here["url"] == fakesite.url("/sends") and ref_of(here, prefix) == ref


@pytest.mark.parametrize(
    "control, reason",
    [
        # Sends, then moves the page to an order address: the navigation is the click's own.
        (
            "<button type=\"button\" onclick=\"navigator.sendBeacon('/collect', 'x=1'); location.href = '/buy/1'\">"
            "Show more</button>",
            guard.READ_CLICK_ADDRESS,
        ),
        # Sends a form: a POST navigation of the page itself.
        (
            "<button type=\"button\" onclick=\"const f = document.createElement('form'); f.method = 'post'; "
            "f.action = '/next'; document.body.appendChild(f); f.submit()\">Show more</button>",
            guard.READ_TIER_POST,
        ),
    ],
)
@pytest.mark.asyncio
async def test_a_click_whose_own_navigation_was_stopped_is_refused_and_the_page_is_put_back(
    kit, fakesite, page_at, control, reason
):
    """A navigation the guard stops leaves the tab on Chrome's error page.
    The refusal named a ref of a page that was gone, the next look found
    an empty page, and browser.act had nothing to make the click on."""
    _toolkit, sessions = kit
    memory = PageMemory()
    toolkit = BrowserReadToolkit(sessions, guard=guard, handoff=handoff, page_memory=memory)
    path = page_at("/sends", f"<h1>Concert ticket</h1>{control}")
    page = await toolkit.execute("open", {"url": fakesite.url(path)}, user_id="u1", task_id="t1")
    ref = ref_of(page, '- button "Show more"')
    result = await toolkit.execute("click", {"ref": ref}, user_id="u1", task_id="t1")
    assert result["ok"] is False and result["error"] == markers.READ_CLICK_MESSAGE
    assert result["consequential"] == reason
    assert posts(fakesite) == [] and ("GET", "/buy/1") not in fakesite.handled  # still nothing sent or opened
    # The tab is back on the page the click was made on, and the result
    # describes it: that page was loaded again, so the old ref is not passed on.
    assert result["url"] == fakesite.url(path) and result["reloaded"] == actions.RELOADED_NOTE
    assert "ref" not in result
    assert result["summary"].startswith("[step 2] click stopped, back → ")
    here = await toolkit.execute("snapshot", {}, user_id="u1", task_id="t1")
    assert here["url"] == fakesite.url(path)
    assert ref_of(here, '- button "Show more"') == ref_of(result, '- button "Show more"')
    remembered = memory.get("u1")
    assert remembered is not None and remembered.url == fakesite.url(path)  # what browser.act binds to
    session = await sessions.get("u1", mode="account", task_id="t1")
    assert f"[step 2] click {ref} refused: {reason}" in session.task.summaries


@pytest.mark.parametrize(
    "href, error",
    [
        # An address the network policy refuses.
        (
            "http://10.0.0.1/",
            "That click was refused by the network policy: http://10.0.0.1/: "
            "10.0.0.1 resolves to a private or local address (10.0.0.1)",
        ),
        # A host nothing answers on: it used to be described as an empty page.
        ("http://127.0.0.1:9/", "The page that click leads to did not load."),
    ],
)
@pytest.mark.asyncio
async def test_a_link_that_opens_no_page_leaves_the_tab_on_the_page_it_was_on(kit, fakesite, page_at, href, error):
    path = page_at("/links", f'<h1>Links</h1><a href="{href}">Router</a> <a href="/grades">Grades</a>')
    page = await run(kit, "open", url=fakesite.url(path))
    result = await run(kit, "click", ref=ref_of(page, '- link "Router"'))
    assert result["ok"] is False and result["error"] == error
    assert result["url"] == fakesite.url(path) and result["reloaded"] == actions.RELOADED_NOTE
    # The outline in the result is the page's own again: its other link can be followed.
    followed = await run(kit, "click", ref=ref_of(result, '- link "Grades"'))
    assert followed["ok"] is True and followed["url"] == fakesite.url("/grades")


LATE_SHOWTIMES = """<h1>Paper Tiger</h1><div id="times">Loading showtimes</div>
<script>
fetch('/showtimes-data').then(() => {
  document.getElementById('times').innerHTML = '<a href="/grades">7:00 PM</a>';
});
</script>"""


@pytest.mark.asyncio
async def test_open_and_back_wait_for_what_the_page_loads_after_its_document(kit, fakesite, page_at, monkeypatch):
    """The outline used to be taken the moment the document was parsed: a
    page that fetches its showtimes had none in it, and the model concluded
    there were none."""
    monkeypatch.setitem(PAGES, "/showtimes-data", (200, "text/plain", "ok"))
    monkeypatch.setitem(DELAYS, "/showtimes-data", 0.6)
    path = page_at("/film", LATE_SHOWTIMES)
    opened = await run(kit, "open", url=fakesite.url(path))
    assert any('link "7:00 PM"' in line for line in opened["outline"]), opened["outline"]
    await run(kit, "open", url=fakesite.url("/"))
    back = await run(kit, "back")
    assert back["url"] == fakesite.url(path)
    assert any('link "7:00 PM"' in line for line in back["outline"]), back["outline"]


@pytest.mark.asyncio
async def test_a_page_that_never_goes_quiet_is_described_after_the_cap_and_does_not_slow_the_next_open(
    kit, fakesite, page_at, monkeypatch
):
    """A request that never answers holds the wait for its cap, not for
    ever. And once its page is left it never reports an end: counted on,
    it would run every later wait to the cap as well."""
    monkeypatch.setitem(PAGES, "/slow-data", (200, "text/plain", "ok"))
    monkeypatch.setitem(DELAYS, "/slow-data", 20.0)
    path = page_at("/busy", "<h1>Busy</h1><script>fetch('/slow-data').catch(() => {})</script>")
    started = time.monotonic()
    busy = await run(kit, "open", url=fakesite.url(path))
    waited = time.monotonic() - started
    assert busy["ok"] is True and actions.LOAD_QUIET_CAP_S - 0.5 < waited < 10, waited
    started = time.monotonic()
    assert (await run(kit, "open", url=fakesite.url("/")))["ok"] is True
    assert time.monotonic() - started < actions.LOAD_QUIET_CAP_S - 0.5


@pytest.mark.asyncio
async def test_an_observation_of_the_visible_part_says_how_much_is_below(kit, fakesite):
    """End to end on a long page. The count is the outline's to make
    (``snapshot.Outline.below``); ``tests/test_browser_shared.py`` covers
    the passing on."""
    opened = await run(kit, "open", url=fakesite.url("/grades"))
    assert opened["below"] > 0 and "Privacy policy" not in "\n".join(opened["outline"])
    assert opened["hint"].startswith(f"{opened['below']} more line")
    assert opened["hint"].endswith("below: use find(text), scroll(down) or snapshot(full=true)")
    full = await run(kit, "snapshot", full=True)
    assert full["below"] == 0 and "hint" not in full
    assert len(full["outline"]) == len(opened["outline"]) + opened["below"]
    bottom = await run(kit, "scroll", direction="bottom")
    assert bottom["below"] == 0 and "Privacy policy" in "\n".join(bottom["outline"])
    home = await run(kit, "open", url=fakesite.url("/"))
    assert home["below"] == 0 and "hint" not in home


def test_the_tool_description_says_the_outline_is_the_visible_part_and_how_to_see_the_rest():
    """The old last sentence ("do not snapshot right after open or click")
    told the model the first screenful was all there was to read."""
    from services.agent.tool_registry import CONNECTOR_CATALOG

    read = next(spec for spec in CONNECTOR_CATALOG["browser"] if spec.action == "read")
    assert read.description.endswith(
        "Every result carries the fresh outline of the visible part of the page, so do not "
        "snapshot right after open or click unless the page was still loading or what you "
        "need is further down (find, scroll or snapshot(full=true))."
    )


# The film page of the 2026-11-12 booking, in small: the day's line and
# the showtimes are fetched after the document, and the showtimes sit
# under the first screenful.
FILM_PAGE = """<h1>Paper Tiger</h1><p id="day">Loading</p>
<div style="height:1500px"></div>
<ul id="times"></ul>
<script>
fetch('/showtimes-data').then(() => {
  document.getElementById('day').textContent = 'Showtimes for tonight';
  document.getElementById('times').innerHTML =
    '<li><a href="/seats?show=1915">7:15 PM</a></li><li><a href="/seats?show=2140">9:40 PM</a></li>';
});
</script>"""


@pytest.mark.asyncio
async def test_a_film_page_is_read_once_it_has_loaded_and_says_its_showtimes_are_further_down(
    kit, fakesite, page_at, monkeypatch
):
    """The live case end to end. Opened, the page was described at the
    moment its document was parsed and by its first screenful alone: no
    showtimes, and nothing to say there was more. The model concluded the
    film had none."""
    monkeypatch.setitem(PAGES, "/showtimes-data", (200, "text/plain", "ok"))
    monkeypatch.setitem(DELAYS, "/showtimes-data", 0.6)
    opened = await run(kit, "open", url=fakesite.url(page_at("/paper-tiger", FILM_PAGE, "Paper Tiger")))
    seen = "\n".join(opened["outline"])
    # What arrived after the document is in the outline of the visible part...
    assert opened["ok"] is True and "Showtimes for tonight" in seen and "Loading" not in seen
    # ...and what is under it is counted, with the three ways to reach it.
    assert "7:15 PM" not in seen and opened["below"] >= 4, opened
    assert opened["hint"] == (
        f"{opened['below']} more lines are below: use find(text), scroll(down) or snapshot(full=true)"
    )
    # Each of the three does reach the showtimes.
    found = await run(kit, "find", text="7:15 PM")
    assert found["count"] > 0 and any('link "7:15 PM"' in line for line in found["matches"])
    full = await run(kit, "snapshot", full=True)
    assert any('link "9:40 PM"' in line for line in full["outline"])
    assert full["below"] == 0 and "hint" not in full
    assert len(full["outline"]) == len(opened["outline"]) + opened["below"]
    down = await run(kit, "scroll", direction="bottom")
    assert any('link "7:15 PM"' in line for line in down["outline"]) and down["below"] == 0


BLOCKED_NOTE = (
    "The site refused Crawler's browser (HTTP {status}). This is the site's own block, not a "
    "Crawler permission, and the person can't clear it. Don't retry or hand off: get the same "
    "information from another site and tell the person this one blocked Crawler."
)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 429, 451, 503])
async def test_a_page_the_site_refused_is_called_blocked_and_not_shown_as_an_ordinary_page(
    kit, fakesite, page_at, status
):
    path = page_at("/cinema", "<h1>Access denied</h1><p>Reference 18.2f3</p>", "Access denied", status=status)
    result = await run(kit, "open", url=fakesite.url(path))
    assert result["ok"] is True and result["http_status"] == status and result["blocked"] is True
    assert result["error_page"] == BLOCKED_NOTE.format(status=status)
    assert result["summary"].endswith(f" · HTTP {status}")


@pytest.mark.asyncio
async def test_a_server_error_is_an_error_page_but_not_a_block(kit, fakesite, page_at):
    path = page_at("/broken", "<h1>Something went wrong</h1>", "Error", status=500)
    result = await run(kit, "open", url=fakesite.url(path))
    assert result["http_status"] == 500 and "blocked" not in result
    assert result["error_page"] == (
        "The site answered HTTP 500: the outline shows its error page, not the page asked for."
    )


@pytest.mark.parametrize(
    "status, body",
    [
        # No form, only the way to it.
        (401, '<h1>Members only</h1><p>You need an account to see this page.</p><a href="/login">Log in</a>'),
        (403, '<h1>Members only</h1><a href="/login" aria-label="Sign in to Fake School">→</a>'),
    ],
)
@pytest.mark.asyncio
async def test_a_refused_page_that_offers_a_sign_in_is_not_called_blocked(kit, fakesite, page_at, status, body):
    """The person can clear this one by signing in, so the result must not
    tell the model that they can't and to give up on a handoff."""
    path = page_at("/members", body, "Members only", status=status)
    result = await run(kit, "open", url=fakesite.url(path))
    assert result["ok"] is True and result["http_status"] == status and "blocked" not in result
    assert result["error_page"] == (
        f"The site answered HTTP {status}: the outline shows its error page, not the page asked for."
    )


@pytest.mark.asyncio
async def test_a_refused_page_that_shows_the_sign_in_form_itself_says_to_hand_it_over(kit, fakesite, page_at):
    """A username and a password box on a page not named for signing in
    (a bank's home page, a members page): only the person can sign in
    there. The page is read with a note that says to hand it over when the
    task needs the account, and once the model does, their submit passes."""
    path = page_at(
        "/members",
        '<h1>Members only</h1><form method="post" action="/login"><label>Username <input name="u"></label>'
        '<label>Password <input name="p" type="password"></label><button type="submit">Enter</button></form>',
        "Members only",
        status=403,
    )
    result = await run(kit, "open", url=fakesite.url(path))
    assert result["ok"] is True and "needs_human" not in result and "blocked" not in result
    assert result["signin_note"] == handoff.SIGNIN_FORM_NOTE
    session, state = await guard_state(kit)
    assert state.human_driving is False
    assert (await run(kit, "handoff", reason="Please sign in"))["needs_human"]["kind"] == "requested"
    page = await session.page()
    await page.fill("input[name=u]", "krish")
    await page.evaluate("document.forms[0].submit()")
    await page.wait_for_url("**/home")
    assert state.blocked == [] and ("POST", "/login") in fakesite.handled


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "title",
    [
        "Perfume reviews - Fragrance Forum",
        # A thread about login trouble, the page a research task opens.
        "Can't log in after password reset - Fragrance Forum",
    ],
)
async def test_a_thread_under_a_forums_header_login_is_read_and_never_handed_over(kit, fakesite, page_at, title):
    """A forum's header login handed the whole thread to the person: open,
    snapshot and text all ended the turn, and the agent could not read it."""
    path = page_at(
        "/forum/thread",
        "<div id='navbar'><form action='/login' method='post'><input type='text' name='vb_login_username' "
        "placeholder='User Name'><input type='password' name='vb_login_password' placeholder='Password'>"
        "<input type='submit' value='Log in'></form></div><h1>Best summer fragrances</h1><p>Replies</p>",
        title,
    )
    opened = await run(kit, "open", url=fakesite.url(path))
    assert opened["ok"] is True and opened["signin_note"] == handoff.SIGNIN_FORM_NOTE
    assert (await run(kit, "snapshot"))["ok"] is True
    text = await run(kit, "text")
    assert text["ok"] is True and "needs_human" not in text
    session, state = await guard_state(kit)
    assert state.human_driving is False and session.pending is None


@pytest.mark.asyncio
async def test_a_sign_in_box_in_a_child_frame_is_noted_and_once_handed_over_the_persons_frame_submit_passes(
    kit, fakesite, page_at
):
    """A bank's home page whose logon box is a frame at /login: read with
    the note, as the same form inline is; the person's frame POST was
    stopped at the read tier before the page was handed over."""
    path = page_at(
        "/bank-home",
        "<h1>Banking</h1><iframe src='/login' style='width:500px;height:300px'></iframe><p>Offers</p>",
        "Credit Card, Mortgage, Banking | Bank",
    )
    result = await run(kit, "open", url=fakesite.url(path))
    assert result["ok"] is True and result["signin_note"] == handoff.SIGNIN_FORM_NOTE
    assert (await run(kit, "handoff", reason="Please sign in"))["needs_human"]["kind"] == "requested"
    session, state = await guard_state(kit)
    page = await session.page()
    frame = next(f for f in page.frames if f.url.endswith("/login"))
    await frame.fill("input[name=username]", "krish")
    await frame.evaluate("document.forms[0].submit()")
    await frame.wait_for_url("**/home")
    assert state.blocked == [] and ("POST", "/login") in fakesite.handled


@pytest.mark.asyncio
async def test_a_sign_in_step_with_a_guest_path_is_read_so_the_agent_can_take_it(kit, fakesite, page_at):
    """A shop's sign-in in front of its checkout, with "Continue as Guest":
    handing it over sent the person to sign in where no account was needed."""
    path = page_at(
        "/identity/signin",
        "<h1>Sign in</h1><form method='post' action='/login'><label>Email <input type='email' name='email'>"
        "</label><label>Password <input type='password' name='pw'></label><button>Sign in</button></form>"
        "<h2>New here?</h2><a href='/grades'>Continue as Guest</a>",
        "Sign In to Shop",
    )
    result = await run(kit, "open", url=fakesite.url(path))
    assert result["ok"] is True and "needs_human" not in result
    # Told to take the guest path, and to hand over only for the account.
    assert result["signin_note"] == handoff.GUEST_PATH_NOTE
    guest = await run(kit, "click", ref=ref_of(result, '- link "Continue as Guest"'))
    assert guest["ok"] is True and guest["url"] == fakesite.url("/grades")
    _session, state = await guard_state(kit)
    assert state.human_driving is False


@pytest.mark.asyncio
async def test_a_click_or_a_back_that_lands_on_a_refused_page_says_so_too(kit, fakesite, page_at):
    path = page_at("/cinemas", '<h1>Cinemas</h1><a href="/forbidden">Lincoln Square</a>')
    page = await run(kit, "open", url=fakesite.url(path))
    clicked = await run(kit, "click", ref=ref_of(page, '- link "Lincoln Square"'))
    assert clicked["ok"] is True and clicked["http_status"] == 403 and clicked["blocked"] is True
    assert clicked["error_page"] == BLOCKED_NOTE.format(status=403)
    assert clicked["summary"].endswith(" · HTTP 403")
    await run(kit, "open", url=fakesite.url("/"))
    back = await run(kit, "back")
    assert back["url"] == fakesite.url("/forbidden") and back["blocked"] is True
    # A page that answered normally carries its status and neither note.
    cinemas = await run(kit, "back")
    assert cinemas["url"] == fakesite.url(path) and cinemas["http_status"] == 200
    assert "blocked" not in cinemas and "error_page" not in cinemas


@pytest.mark.asyncio
async def test_a_click_that_opens_a_new_tab_describes_the_new_tab(kit, fakesite, page_at):
    """A link with target=_blank, or a script's window.open: the result was
    the outline of the tab the click was made in, so the model took the
    click for one that did nothing."""
    path = page_at(
        "/tabs",
        '<h1>Tabs</h1><a href="/grades" target="_blank">Grades</a> '
        "<button type=\"button\" onclick=\"window.open('/flights')\">Timetable</button>",
    )
    page = await run(kit, "open", url=fakesite.url(path))
    result = await run(kit, "click", ref=ref_of(page, '- link "Grades"'))
    assert result["ok"] is True and result["new_tab"] is True, result
    assert result["url"] == fakesite.url("/grades") and any("Grades for" in line for line in result["outline"])
    tabs = (await run(kit, "tabs"))["tabs"]
    assert [(tab["url"], tab["active"]) for tab in tabs] == [
        (fakesite.url(path), False),
        (fakesite.url("/grades"), True),
    ]
    # The session goes on in the new tab; a click that opens none says nothing of tabs.
    here = await run(kit, "snapshot")
    assert here["url"] == fakesite.url("/grades") and "new_tab" not in here
    followed = await run(kit, "click", ref=ref_of(here, '- link "Homework 1"'))
    assert followed["ok"] is True and "new_tab" not in followed
    # window.open from the first tab, over the cap of two tabs: the other tab
    # goes, and the one the click was made in stays under the tab it opened.
    assert (await run(kit, "switch", index=0))["url"] == fakesite.url(path)
    popped = await run(kit, "click", ref=ref_of(await run(kit, "snapshot"), '- button "Timetable"'))
    assert popped["ok"] is True and popped["new_tab"] is True and popped["url"] == fakesite.url("/flights")
    tabs = (await run(kit, "tabs"))["tabs"]
    assert [(tab["url"], tab["active"]) for tab in tabs] == [
        (fakesite.url(path), False),
        (fakesite.url("/flights"), True),
    ]


@pytest.mark.asyncio
async def test_a_new_tab_whose_page_is_slow_to_answer_is_waited_for(kit, fakesite, page_at, monkeypatch):
    """The click's own window closes after two seconds. A new tab whose
    site takes longer was described while it was still empty."""
    monkeypatch.setitem(DELAYS, "/slow-film", guard.READ_CLICK_CAP_S + 0.7)
    page_at("/slow-film", "<h1>Paper Tiger showtimes</h1>", "Showtimes")
    path = page_at("/films", '<h1>Films</h1><a href="/slow-film" target="_blank">Paper Tiger</a>')
    page = await run(kit, "open", url=fakesite.url(path))
    result = await run(kit, "click", ref=ref_of(page, '- link "Paper Tiger"'))
    assert result["ok"] is True and result["new_tab"] is True, result
    assert result["url"] == fakesite.url("/slow-film")
    assert any("Paper Tiger showtimes" in line for line in result["outline"]), result["outline"]


@pytest.mark.parametrize(
    "target, error, consequential",
    [
        # An order address: left to browser.act, as in the same tab.
        ("/buy/1", markers.READ_CLICK_MESSAGE, guard.READ_CLICK_ADDRESS),
        # An address the network policy refuses.
        (
            "http://10.0.0.1/",
            "That click was refused by the network policy: http://10.0.0.1/: "
            "10.0.0.1 resolves to a private or local address (10.0.0.1)",
            None,
        ),
        # A host nothing answers on.
        ("http://127.0.0.1:9/", "The page that click opened in a new tab did not load.", None),
    ],
)
@pytest.mark.asyncio
async def test_a_new_tab_that_shows_no_page_is_closed_and_the_click_says_why(
    kit, fakesite, page_at, target, error, consequential
):
    """A new tab whose navigation was stopped, or failed, is not what the
    session goes on in: it stays on the page the ref belongs to (so the
    same click can be made with browser.act) and the result says what
    happened, where it used to describe the old tab as if nothing had."""
    path = page_at(
        "/pop", f"<h1>Paper Tiger</h1><button type=\"button\" onclick=\"window.open('{target}')\">Seats</button>"
    )
    page = await run(kit, "open", url=fakesite.url(path))
    ref = ref_of(page, '- button "Seats"')
    result = await run(kit, "click", ref=ref)
    expected = {"ok": False, "error": error}
    if consequential is not None:
        expected.update(consequential=consequential, ref=ref)
    assert result == expected
    assert ("GET", "/buy/1") not in fakesite.handled
    tabs = (await run(kit, "tabs"))["tabs"]
    assert [(tab["url"], tab["active"]) for tab in tabs] == [(fakesite.url(path), True)]


@pytest.mark.asyncio
async def test_a_browser_the_person_quit_is_started_again_on_the_next_call(kit, fakesite):
    """Every call used to answer "browser.read open failed." until the app
    was restarted."""
    _toolkit, sessions = kit
    assert (await run(kit, "open", url=fakesite.url("/")))["ok"] is True
    session = await sessions.get("u1", mode="account", task_id="t1")
    await session.context.browser.close()  # the person quits Crawler's browser
    result = await run(kit, "open", url=fakesite.url("/grades"))
    assert result["ok"] is True and result["url"] == fakesite.url("/grades"), result
    assert (await sessions.get("u1", mode="account", task_id="t1")) is not session


# ── a sign-in step is the person's ─────────────────────────────────────────


async def submit_as_the_person(page) -> None:
    """The person, in Crawler's window, types their email and sends the form."""
    await page.fill("#ap_email_login", "me@example.com")
    await page.evaluate("document.forms[0].submit()")


@pytest.mark.asyncio
async def test_opening_a_sign_in_page_hands_it_over_and_the_persons_own_sign_in_goes_through(kit, fakesite):
    result = await run(kit, "open", url=fakesite.url("/ax/claim"))
    assert result["ok"] is False and "outline" not in result
    assert result["needs_human"]["kind"] == "signin"
    assert result["needs_human"]["detail"] == "the site wants you to sign in"
    session, state = await guard_state(kit)
    assert state.human_driving is True and session.pending == "handoff"
    page = await session.page()
    await submit_as_the_person(page)
    await page.wait_for_url("**/home")
    assert state.blocked == [] and ("POST", "/login") in fakesite.handled
    # "done": the agent reads the signed-in page and the window is its again.
    after = await run(kit, "snapshot")
    assert after["ok"] is True and after["url"].endswith("/home") and state.human_driving is False


@pytest.mark.asyncio
async def test_without_the_handoff_the_persons_sign_in_on_crawlers_page_is_blocked(kit, fakesite, monkeypatch):
    """The live failure: the sign-in page came back as an ordinary page, the
    model told the person in prose to sign in, and the guard stopped every
    submit of their own form (ERR_BLOCKED_BY_CLIENT)."""
    monkeypatch.setattr(handoff, "classify", lambda _facts: None)
    result = await run(kit, "open", url=fakesite.url("/ax/claim"))
    assert result["ok"] is True
    session, state = await guard_state(kit)
    assert state.human_driving is False
    page = await session.page()
    await submit_as_the_person(page)
    await guard.settle_blocked_navigation(page)
    assert state.blocked[-1]["reason"] == guard.READ_TIER_POST
    assert ("POST", "/login") not in fakesite.handled
