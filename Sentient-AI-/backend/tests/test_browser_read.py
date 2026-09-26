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

from services.tools.browser import guard, handoff
from services.tools.browser import snapshot as snap
from services.tools.browser.actions import (
    BROWSER_MAX_ACTIONS,
    BROWSER_MAX_USD,
    BrowserReadToolkit,
)
from services.tools.browser.session import BrowserSessionManager, TaskState
from services.tools.system import browser_installed


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
    assert result["error"] == (
        "Reading can't click that. Ask to fill in forms and click (needs 'Fill in forms and "
        "click on sites' in Permissions)."
    )
    assert result["consequential"]
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
    await run(kit, "open", url=fakesite.url("/login"))
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
    assert state.human_driving is False
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
