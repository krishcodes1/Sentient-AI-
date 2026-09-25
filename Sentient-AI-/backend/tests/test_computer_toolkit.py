"""Tests for ComputerToolkit (desktop.observe / desktop.act) against the in-memory
fake desktop: outline results, per-user ref lifetime, every hard rule, the
approval-card sentences, fresh outlines after acts, and fail-closed errors.

Why it exists: Computer control is the riskiest capability Crawler has. Every
refusal here also asserts the fake's event log is empty, proving a refused
action never reached the backend; static refusals also assert no read happened.
No test uses a real backend: nothing clicks, types or reads the real screen.
"""

from __future__ import annotations

import re

import pytest

from services.tools.computer import rules
from services.tools.computer.backend import (
    AppNotFoundError,
    BlockedTargetError,
    CoveredTargetError,
    ElementGoneError,
    ElevatedTargetError,
    Node,
    SecureTargetError,
    select_backend,
)
from services.tools.computer.backend_fake import FakeApp, FakeBackend, FakeWindow, make_node
from services.tools.computer.toolkit import CARD_KEY, ComputerToolkit

U1 = "user-1"
U2 = "user-2"

# ── fixtures ─────────────────────────────────────────────────────────────────


def mail_window(extra=()):
    return FakeWindow(
        "New Message",
        (
            make_node(
                "group",
                children=(
                    make_node("text field", "Subject", handle="subject", value="Hi"),
                    make_node("text area", "Message", handle="body"),
                ),
            ),
            make_node("button", "Send", handle="send"),
            make_node("text field", "Password", handle="pw", secure=True, value="hunter2"),
            *extra,
        ),
    )


def desktop(*, mail_extra=(), front="Mail", focused="subject", apps=(), **kw):
    return FakeBackend(
        [
            FakeApp("Mail", 101, [mail_window(mail_extra)]),
            FakeApp(
                "TextEdit",
                102,
                [
                    FakeWindow("Untitled", (make_node("text area", "Document", handle="doc"),)),
                    FakeWindow("Notes.txt", ()),
                ],
            ),
            FakeApp("Terminal", 103, [FakeWindow("bash", (make_node("text area", "Shell"),))]),
            FakeApp("Finder", 104, [FakeWindow("Desktop", (make_node("button", "Trash"),))]),
            *apps,
        ],
        frontmost=front,
        focused=focused,
        installed={"Calculator"},
        **kw,
    )


def kit_for(backend, cancel=lambda uid: False, **kw):
    return ComputerToolkit(backend, cancel_flag=cancel, **kw)


async def observe(kit, user=U1, **params):
    return await kit.execute("observe", {"action": "outline", **params}, user_id=user)


async def act(kit, user=U1, **params):
    return await kit.execute("act", params, user_id=user)


def ref(result, needle):
    """The ref on the outline line containing *needle*."""
    for line in result["outline"]:
        if needle in line:
            return re.search(r"\[ref=(d\d+)\]", line).group(1)
    raise AssertionError(f"{needle!r} not in outline: {result['outline']}")


async def observed(**kw):
    """A fake desktop, a toolkit, and U1's first outline of Mail; the fake's
    read log is cleared so a test can prove what the next call reads."""
    fake = desktop(**kw)
    kit = kit_for(fake)
    first = await observe(kit)
    assert first["ok"], first
    fake.reads.clear()
    return fake, kit, first


def assert_refused(result, rule):
    assert result["ok"] is False, result
    assert result.get("refused") is True, result
    assert result["rule"] == rule, result
    assert result["error"]


# ── observe: outline ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_outline_mirrors_the_browser_format():
    fake = desktop()
    result = await observe(kit_for(fake))
    assert result == {
        "ok": True,
        "frontmost_app": "Mail",
        "app": "Mail",
        "window_title": "New Message",
        "outline": [
            '- window "New Message" [ref=d1]',
            '  - text field "Subject" [ref=d2] [focused] value="Hi"',
            '  - text area "Message" [ref=d3]',
            '  - button "Send" [ref=d4]',
            '  - text field "Password" [ref=d5] value=[redacted]',
        ],
        "refs": 5,
        "truncated": False,
        "secure_fields_redacted": 1,
    }
    assert "hunter2" not in str(result)
    assert fake.events == []


@pytest.mark.asyncio
async def test_outline_redacts_password_named_fields_the_os_did_not_flag():
    fake = desktop(mail_extra=(make_node("text field", "PIN", value="4321"),))
    result = await observe(kit_for(fake))
    assert "4321" not in str(result)
    assert '  - text field "PIN" [ref=d6] value=[redacted]' in result["outline"]
    assert result["secure_fields_redacted"] == 2


@pytest.mark.asyncio
async def test_outline_drops_hidden_and_offscreen_elements():
    fake = desktop(
        mail_extra=(
            make_node("button", "Hidden button", hidden=True),
            make_node(
                "group", "Offscreen", offscreen=True, children=(make_node("button", "Below"),)
            ),
        )
    )
    text = "\n".join((await observe(kit_for(fake)))["outline"])
    assert "Hidden button" not in text and "Offscreen" not in text and "Below" not in text


@pytest.mark.asyncio
async def test_outline_of_a_named_app_that_is_not_in_front():
    fake = desktop()
    result = await observe(kit_for(fake), app="TextEdit")
    assert result["ok"] and result["app"] == "TextEdit" and result["frontmost_app"] == "Mail"
    assert result["window_title"] == "Untitled"
    assert any('text area "Document"' in line for line in result["outline"])


@pytest.mark.asyncio
async def test_a_named_app_is_recorded_under_its_real_name():
    fake = desktop()
    kit = kit_for(fake)
    result = await observe(kit, app="textedit")
    assert result["app"] == "TextEdit"
    fake.front = "TextEdit"
    assert kit.describe({"action": "key", "keys": "cmd+s"}, user_id=U1) == "Press cmd+s in TextEdit"
    done = await act(kit, action="key", keys="cmd+s")
    assert done["did"] == "press cmd+s in TextEdit"


@pytest.mark.asyncio
async def test_outline_caps_size_and_clamps_max_chars():
    many = tuple(make_node("button", f"Button number {i}") for i in range(2000))
    fake = desktop(mail_extra=many)
    kit = kit_for(fake)
    small = await observe(kit, max_chars=300)
    assert small["truncated"] is True
    assert sum(len(line) + 1 for line in small["outline"]) <= 300
    big = await observe(kit, max_chars=10**9)
    assert big["truncated"] is True
    assert sum(len(line) + 1 for line in big["outline"]) <= 12000


@pytest.mark.asyncio
async def test_outline_of_an_unknown_app_is_an_error():
    result = await observe(kit_for(desktop()), app="Nope")
    assert result == {"ok": False, "error": "No running app named 'Nope'."}


@pytest.mark.asyncio
@pytest.mark.parametrize("app", ["1Password 7", "Keychain Access", "Bitwarden", "Passwords"])
async def test_password_managers_are_never_read(app):
    fake = desktop(
        apps=(
            FakeApp(app, 200, [FakeWindow("GitHub login", (make_node("text field", "Password"),))]),
        ),
        front=app,
    )
    kit = kit_for(fake)
    assert_refused(await observe(kit), "secret_app")
    assert_refused(await observe(kit, app=app), "secret_app")
    assert "outline" not in fake.reads
    assert fake.events == []


@pytest.mark.asyncio
async def test_screenshot_for_the_model_is_optional_and_fails_soft():
    fake = desktop()
    without = await observe(kit_for(fake), for_model_image=True)
    assert without["ok"] and "image" not in without and without["image_error"]

    with_image = await observe(
        kit_for(fake, image_source=lambda: "data:image/jpeg;base64,AAAA"), for_model_image=True
    )
    assert with_image["image"] == "data:image/jpeg;base64,AAAA"

    def broken():
        raise RuntimeError("no display")

    failed = await observe(kit_for(fake, image_source=broken), for_model_image=True)
    assert failed["ok"] and "image" not in failed and failed["image_error"]


# ── observe: apps and windows ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_observe_apps():
    fake = desktop(apps=(FakeApp("Admin Tool", 300, [FakeWindow("x")], elevated=True),))
    result = await kit_for(fake).execute("observe", {"action": "apps"}, user_id=U1)
    assert result["ok"] and result["frontmost_app"] == "Mail"
    assert {"name": "Mail", "pid": 101, "active": True} in result["apps"]
    assert {"name": "TextEdit", "pid": 102, "active": False} in result["apps"]
    assert {"name": "Admin Tool", "pid": 300, "active": False, "elevated": True} in result["apps"]
    assert "administrator" in result["note"]
    assert fake.events == []


@pytest.mark.asyncio
async def test_observe_windows_all_and_filtered():
    fake = desktop()
    kit = kit_for(fake)
    everything = await kit.execute("observe", {"action": "windows"}, user_id=U1)
    assert {"app": "Mail", "title": "New Message", "index": 0} in everything["windows"]
    textedit = await kit.execute("observe", {"action": "windows", "app": "textedit"}, user_id=U1)
    assert textedit["windows"] == [
        {"app": "TextEdit", "title": "Untitled", "index": 0},
        {"app": "TextEdit", "title": "Notes.txt", "index": 1},
    ]


@pytest.mark.asyncio
async def test_observe_windows_hides_password_manager_titles():
    fake = desktop(apps=(FakeApp("1Password", 200, [FakeWindow("Bank of Example login")]),))
    result = await kit_for(fake).execute("observe", {"action": "windows"}, user_id=U1)
    assert {"app": "1Password", "title": "", "index": 0} in result["windows"]
    assert "Bank of Example" not in str(result)


# ── refs ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refs_last_until_the_next_outline_and_never_repeat():
    fake, kit, first = await observed()
    send_old = ref(first, '"Send"')
    second = await observe(kit)
    send_new = ref(second, '"Send"')
    assert send_old == "d4" and send_new == "d9"  # numbering carries on
    stale = await act(kit, action="click", ref=send_old)
    assert stale["ok"] is False and stale["stale_ref"] is True
    assert fake.events == []
    fresh = await act(kit, action="click", ref=send_new)
    assert fresh["ok"] is True
    assert fake.events == [("click", "send", False)]


@pytest.mark.asyncio
async def test_an_act_replaces_the_refs_with_its_fresh_outline():
    fake, kit, first = await observed()
    send = ref(first, '"Send"')
    done = await act(kit, action="click", ref=send)
    assert done["ok"] and done["then"]["ok"]
    assert ref(done["then"], '"Send"') == "d9"
    again = await act(kit, action="click", ref=send)
    assert again["ok"] is False and again["stale_ref"] is True
    assert fake.events == [("click", "send", False)]


@pytest.mark.asyncio
async def test_refs_are_per_user():
    fake, kit, first = await observed()
    send = ref(first, '"Send"')
    other = await act(kit, user=U2, action="click", ref=send)
    assert other["ok"] is False and other["needs_observe"] is True
    mine = await observe(kit, user=U2)
    assert ref(mine, '"Send"') == "d4"  # U2 numbers from d1 on its own
    assert (await act(kit, action="click", ref=send))["ok"] is True  # U1's still valid
    assert fake.events == [("click", "send", False)]


@pytest.mark.asyncio
async def test_acting_before_looking_is_refused_without_touching_the_backend():
    fake = desktop()
    result = await act(kit_for(fake), action="key", keys="cmd+s")
    assert result["ok"] is False and result["needs_observe"] is True
    assert fake.events == [] and fake.reads == []


# ── act: results carry a fresh outline ───────────────────────────────────────


@pytest.mark.asyncio
async def test_type_into_a_ref_returns_the_fresh_outline():
    fake, kit, first = await observed()
    result = await act(kit, action="type", text="Hello", ref=ref(first, '"Subject"'))
    assert result["ok"] is True
    assert result["did"] == 'type 5 characters into text field "Subject" in Mail'
    assert fake.events == [("type", "Hello", "subject")]
    assert any(
        '"Subject"' in line and 'value="HiHello"' in line for line in result["then"]["outline"]
    )
    assert result["then"]["frontmost_app"] == "Mail"


@pytest.mark.asyncio
async def test_click_did_names_the_role_and_app():
    fake, kit, first = await observed()
    result = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert result["did"] == 'click button "Send" in Mail'
    double = await act(kit, action="double_click", ref=ref(result["then"], '"Message"'))
    assert double["did"] == 'double-click text area "Message" in Mail'
    assert fake.events == [("click", "send", False), ("click", "body", True)]


@pytest.mark.asyncio
async def test_type_into_the_focused_field():
    fake, kit, _ = await observed()
    result = await act(kit, action="type", text="abc")
    assert result["ok"] and result["did"] == "type 3 characters into the focused field in Mail"
    assert fake.events == [("type", "abc", "subject")]


@pytest.mark.asyncio
async def test_key_scroll_open_and_focus():
    fake, kit, _ = await observed()
    assert (await act(kit, action="key", keys="cmd+s"))["did"] == "press cmd+s in Mail"
    assert (await act(kit, action="scroll", direction="down"))["did"] == "scroll down in Mail"
    opened = await act(kit, action="open_app", app="Calculator")
    assert opened["did"] == "open Calculator"
    assert opened["then"]["frontmost_app"] == "Calculator"
    focused = await act(kit, action="focus_window", app="TextEdit", index=1)
    assert focused["did"] == "switch to TextEdit window 1"
    assert focused["then"]["window_title"] == "Notes.txt"
    assert fake.events == [
        ("key", "cmd+s"),
        ("scroll", "down", 5),
        ("open_app", "Calculator"),
        ("focus_window", "TextEdit", 1),
    ]


@pytest.mark.asyncio
async def test_click_by_coordinates_inside_the_window():
    fake, kit, _ = await observed()
    result = await act(kit, action="click", x=10, y=20)
    assert result["ok"] and result["did"] == "click at (10, 20) in Mail"
    assert fake.events == [("click", (10, 20), False)]


@pytest.mark.asyncio
async def test_then_is_withheld_when_an_act_brings_up_a_password_manager():
    fake, kit, first = await observed(
        apps=(
            FakeApp("1Password", 200, [FakeWindow("Vault", (make_node("text", "secret item"),))]),
        )
    )

    def opens_vault(backend, event):
        backend.front = "1Password"

    fake.on_event = opens_vault
    result = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert result["ok"] is True
    assert result["then"]["ok"] is False and result["then"]["withheld"] is True
    assert "secret item" not in str(result)
    follow_up = await act(kit, action="key", keys="enter")
    assert follow_up["ok"] is False and follow_up["needs_observe"] is True
    assert len(fake.events) == 1


# ── hard rule: secure fields ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_never_types_into_a_secure_ref():
    fake, kit, first = await observed()
    result = await act(kit, action="type", text="hunter2", ref=ref(first, '"Password"'))
    assert_refused(result, "secure_field")
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
async def test_never_types_into_a_password_named_field():
    fake, kit, first = await observed(mail_extra=(make_node("text field", "New password"),))
    result = await act(kit, action="type", text="x", ref=ref(first, '"New password"'))
    assert_refused(result, "secure_field")
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
async def test_never_types_into_a_focused_secure_field():
    fake, kit, _ = await observed(focused="pw")
    assert_refused(await act(kit, action="type", text="hunter2"), "secure_field")
    assert fake.events == []


@pytest.mark.asyncio
async def test_a_field_that_turned_secure_since_the_outline_is_refused():
    fake, kit, first = await observed()
    subject = ref(first, '"Subject"')
    window = fake.apps["Mail"].windows[0]
    group = window.nodes[0]
    turned = make_node("text field", "Subject", handle="subject", secure=True)
    window.nodes = (
        Node("group", children=(turned, group.children[1]), handle=group.handle),
        *window.nodes[1:],
    )
    assert_refused(await act(kit, action="type", text="x", ref=subject), "secure_field")
    assert fake.events == []


@pytest.mark.asyncio
async def test_typing_blind_is_refused():
    fake, kit, _ = await observed(focused=None)
    assert_refused(await act(kit, action="type", text="hello"), "focus_unknown")
    assert_refused(await act(kit, action="key", keys="a"), "focus_unknown")
    assert fake.events == []


@pytest.mark.asyncio
@pytest.mark.parametrize("keys", ["a", "shift+a", "space", "1", "cmd+v", "ctrl+v", "shift+insert"])
async def test_text_keys_into_a_focused_secure_field_are_refused(keys):
    fake, kit, _ = await observed(focused="pw")
    assert_refused(await act(kit, action="key", keys=keys), "secure_field")
    assert fake.events == []


@pytest.mark.asyncio
@pytest.mark.parametrize("keys", ["enter", "tab", "escape", "cmd+a"])
async def test_non_text_keys_in_a_secure_field_are_allowed(keys):
    fake, kit, _ = await observed(focused="pw")
    assert (await act(kit, action="key", keys=keys))["ok"] is True
    assert len(fake.events) == 1


# ── hard rule: blocked apps ──────────────────────────────────────────────────

BLOCKED_NAMES = [
    "Keychain Access",
    "Passwords",
    "1Password 7",
    "Bitwarden",
    "LastPass",
    "Dashlane",
    "System Settings",
    "System Preferences",
    "Terminal",
    "iTerm2",
    "Warp",
    "PowerShell",
    "Windows PowerShell",
    "Windows Terminal",
    "Command Prompt",
    "cmd.exe",
    "Registry Editor",
    "regedit",
    "Task Manager",
    "Taskmgr.exe",
    "loginwindow",
    "LockApp",
    "Crawler AI",
    "Activity Monitor",
    "Script Editor",
    "com.apple.Terminal",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", BLOCKED_NAMES)
async def test_open_app_refuses_every_blocked_app(name):
    fake = desktop()
    kit = kit_for(fake)
    assert_refused(await act(kit, action="open_app", app=name), "blocked_app")
    assert_refused(await act(kit, action="focus_window", app=name, index=0), "blocked_app")
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [n for n in BLOCKED_NAMES if not rules.secret_app(n)])
async def test_no_input_reaches_a_blocked_app_even_when_observed(name):
    fake = desktop(
        apps=(FakeApp(name, 500, [FakeWindow("w", (make_node("text area", "Input"),))]),),
        front=name,
        focused=None,
    )
    kit = kit_for(fake)
    seen = await observe(kit)  # reading it is allowed
    assert seen["ok"], seen
    fake.reads.clear()
    for params in (
        {"action": "click", "ref": ref(seen, '"Input"')},
        {"action": "type", "text": "rm -rf ~", "ref": ref(seen, '"Input"')},
        {"action": "key", "keys": "enter"},
        {"action": "scroll", "direction": "down"},
        {"action": "click", "x": 5, "y": 5},
    ):
        assert_refused(await act(kit, **params), "blocked_app")
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
async def test_a_blocked_app_that_came_to_the_front_is_refused():
    fake, kit, first = await observed()
    fake.front = "Terminal"
    assert_refused(await act(kit, action="click", ref=ref(first, '"Send"')), "blocked_app")
    assert fake.events == []


@pytest.mark.asyncio
async def test_crawlers_own_web_ui_in_a_browser_is_never_acted_in():
    ui = FakeWindow(
        "Crawler AI - Secure Agentic AI Platform",
        (make_node("button", "Approve", handle="approve"),),
    )
    fake = desktop(apps=(FakeApp("Safari", 400, [ui, FakeWindow("News", ())]),), front="Safari")
    kit = kit_for(fake)
    seen = await observe(kit)
    assert seen["ok"]
    fake.reads.clear()
    assert_refused(await act(kit, action="click", ref=ref(seen, '"Approve"')), "blocked_app")
    assert fake.events == [] and fake.reads == []

    # Observed on another tab, then the Crawler tab came to the front.
    fake.apps["Safari"].windows.reverse()
    other = await observe(kit)
    fake.apps["Safari"].windows.reverse()
    assert_refused(await act(kit, action="key", keys="enter"), "blocked_app")
    assert other["window_title"] == "News"
    assert fake.events == []


@pytest.mark.asyncio
async def test_switching_away_from_a_blocked_app_is_allowed():
    fake = desktop(front="Terminal")
    result = await act(kit_for(fake), action="focus_window", app="Mail")
    assert result["ok"] is True and result["then"]["frontmost_app"] == "Mail"
    assert fake.events == [("focus_window", "Mail", 0)]


# ── hard rule: key combos ────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "keys",
    [
        "cmd+shift+q",
        "cmd+option+shift+q",
        "ctrl+cmd+q",
        "cmd+option+esc",
        "cmd+alt+shift+escape",
        "ctrl+alt+del",
        "ctrl+shift+esc",
        "cmd+space",
        "alt+space",
        "win+r",
        "win+l",
        "fn+f",
        "globe+e",
    ],
)
async def test_blocked_combos_never_reach_the_backend(keys):
    fake, kit, _ = await observed()
    assert_refused(await act(kit, action="key", keys=keys), "blocked_key")
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
async def test_cmd_q_is_refused_on_finder_only():
    fake = desktop(front="Finder")
    kit = kit_for(fake)
    await observe(kit)
    assert_refused(await act(kit, action="key", keys="cmd+q"), "blocked_key")
    assert fake.events == []
    fake.front = "Mail"
    await observe(kit)
    assert (await act(kit, action="key", keys="cmd+q"))["ok"] is True
    assert fake.events == [("key", "cmd+q")]


@pytest.mark.asyncio
async def test_key_grammar_errors_are_errors_not_input():
    fake, kit, _ = await observed()
    for keys in ("cmd+shift", "hyper+s", "cmd+s+t", "", 7):
        result = await act(kit, action="key", keys=keys)
        assert result["ok"] is False and "refused" not in result
    assert fake.events == []


# ── hard rule: payment fields ────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        make_node("text field", "Card number"),
        make_node("text field", "CVC"),
        make_node("text field", "IBAN"),
        make_node("text", "Expiration date"),
        make_node("text field", "Notes", value="4111 1111 1111 1111"),
        make_node("text field", "Card number", offscreen=True),
    ],
)
async def test_payment_windows_are_refused(extra):
    fake, kit, first = await observed(mail_extra=(extra,))
    for params in (
        {"action": "click", "ref": ref(first, '"Send"')},
        {"action": "type", "text": "4111", "ref": ref(first, '"Subject"')},
        {"action": "key", "keys": "enter"},
        {"action": "scroll", "direction": "down"},
    ):
        assert_refused(await act(kit, **params), "payment")
    assert fake.events == []


@pytest.mark.asyncio
async def test_payment_fields_deep_in_web_content_are_found():
    field = make_node("text field", "Card number")
    for _ in range(80):
        field = make_node("group", children=(field,))
    fake, kit, first = await observed(mail_extra=(field,))
    assert_refused(await act(kit, action="click", ref=ref(first, '"Send"')), "payment")
    assert fake.events == []


@pytest.mark.asyncio
async def test_a_ref_whose_app_quit_is_stale():
    fake, kit, first = await observed()
    fake.failures["click"] = AppNotFoundError("Mail quit")
    result = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert result["ok"] is False and result["stale_ref"] is True
    assert "no longer running" in result["error"]


@pytest.mark.asyncio
async def test_a_window_that_cannot_be_checked_is_not_touched():
    fake, kit, first = await observed()
    fake.failures["outline"] = RuntimeError("AX timeout")
    assert_refused(await act(kit, action="click", ref=ref(first, '"Send"')), "check_failed")
    assert fake.events == []


# ── hard rule: the cancel flag ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancelled_turns_do_nothing_at_all():
    fake = desktop()
    kit = kit_for(fake, cancel=lambda uid: uid == U1)
    assert_refused(await observe(kit), "cancelled")
    assert_refused(await act(kit, action="open_app", app="Calculator"), "cancelled")
    assert fake.events == [] and fake.reads == []
    assert (await observe(kit, user=U2))["ok"] is True  # per user


@pytest.mark.asyncio
async def test_a_cancel_flag_that_fails_counts_as_cancelled():
    def broken(uid):
        raise RuntimeError("redis down")

    fake = desktop()
    assert_refused(await observe(kit_for(fake, cancel=broken)), "cancelled")
    assert fake.reads == []


@pytest.mark.asyncio
async def test_stop_pressed_while_the_screen_is_checked_still_stops_the_act():
    fake = desktop()
    checks = []

    def flag(uid):
        checks.append(uid)
        # Clear for the observe and at the act's start; set by the final check.
        return len(checks) >= 3

    kit = kit_for(fake, cancel=flag)
    first = await observe(kit)
    assert_refused(await act(kit, action="click", ref=ref(first, '"Send"')), "cancelled")
    assert checks == [U1, U1, U1]
    assert fake.events == []
    assert "outline" in fake.reads  # the live checks ran; the input did not


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("comes_forward", "rule"), [("Terminal", "blocked_app"), ("TextEdit", "frontmost_changed")]
)
async def test_an_app_that_comes_forward_during_the_window_scan_gets_no_input(comes_forward, rule):
    # The payment scan reads the whole window, which can take seconds; the
    # front app is read again after it, so keys never go to whatever came
    # forward meanwhile (a blocked app included).
    class SlowScan(FakeBackend):
        def outline(self, app, max_nodes):
            nodes = super().outline(app, max_nodes)
            if scanning:
                self.front = comes_forward
            return nodes

    scanning = False
    fake = SlowScan(desktop().apps.values(), frontmost="Mail", focused="subject")
    kit = kit_for(fake)
    await observe(kit)
    scanning = True
    result = await act(kit, action="key", keys="cmd+a")
    assert_refused(result, rule)
    assert fake.events == []


# ── other live rules ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_input_goes_only_to_the_app_last_observed():
    fake, kit, first = await observed()
    fake.front = "TextEdit"
    assert_refused(await act(kit, action="key", keys="cmd+s"), "frontmost_changed")
    assert_refused(await act(kit, action="click", ref=ref(first, '"Send"')), "frontmost_changed")
    assert fake.events == []


@pytest.mark.asyncio
async def test_coordinates_outside_the_window_are_refused():
    fake, kit, _ = await observed()
    assert_refused(await act(kit, action="click", x=900, y=10), "outside_window")
    assert fake.events == []


@pytest.mark.asyncio
async def test_unknown_frontmost_app_is_refused():
    fake, kit, _ = await observed()
    fake.failures["frontmost"] = RuntimeError("no answer")
    assert_refused(await act(kit, action="key", keys="enter"), "unknown_app")
    assert fake.events == []


# ── describe(): approval-card text from facts ───────────────────────────────


@pytest.mark.asyncio
async def test_describe_builds_the_card_from_facts():
    fake, kit, first = await observed()
    reads = list(fake.reads)
    subject, send = ref(first, '"Subject"'), ref(first, '"Send"')
    assert kit.describe({"action": "click", "ref": send}, user_id=U1) == 'Click "Send" in Mail'
    assert (
        kit.describe({"action": "type", "text": "x" * 42, "ref": subject}, user_id=U1)
        == 'Type 42 characters into "Subject" in Mail'
    )
    assert kit.describe({"action": "type", "text": "a"}, user_id=U1) == (
        "Type 1 character into the focused field in Mail"
    )
    assert kit.describe({"action": "type", "text": "hi\nthere\n"}, user_id=U1) == (
        "Type 9 characters (including 2 line breaks) into the focused field in Mail"
    )
    assert kit.describe({"action": "double_click", "ref": send}, user_id=U1) == (
        'Double-click "Send" in Mail'
    )
    assert (
        kit.describe({"action": "click", "x": 3, "y": 4}, user_id=U1) == "Click at (3, 4) in Mail"
    )
    assert kit.describe({"action": "scroll", "direction": "up"}, user_id=U1) == "Scroll up in Mail"
    assert kit.describe({"action": "open_app", "app": "Calculator"}) == "Open Calculator"
    assert kit.describe({"action": "focus_window", "app": "TextEdit", "index": 1}) == (
        "Switch to TextEdit window 1"
    )
    assert fake.events == [] and fake.reads == reads  # describe calls no backend


@pytest.mark.asyncio
async def test_describe_press_names_the_observed_app():
    fake = desktop(front="TextEdit")
    kit = kit_for(fake)
    await observe(kit)
    assert kit.describe({"action": "key", "keys": "Shift+CMD+S"}, user_id=U1) == (
        "Press cmd+shift+s in TextEdit"
    )
    assert kit.describe({"action": "key", "keys": "cmd+s"}) == "Press cmd+s in the frontmost app"


@pytest.mark.asyncio
async def test_describe_uses_element_names_not_model_words():
    fake, kit, first = await observed(
        mail_extra=(make_node("button", 'Say "hi"\nnow‮', handle="evil"),)
    )
    evil = ref(first, "Say")
    assert (
        kit.describe({"action": "click", "ref": evil}, user_id=U1)
        == "Click \"Say 'hi' now\" in Mail"
    )
    assert kit.describe({"action": "click", "ref": "d999"}, user_id=U1) == (
        "Click d999 (not in the latest outline, so it will be refused)"
    )
    assert kit.describe({"action": "click", "ref": evil}, user_id=U2) == (
        f"Click {evil} (not in the latest outline, so it will be refused)"
    )
    assert kit.describe({"action": "click", "ref": evil, "label": "Cancel"}, user_id=U1).startswith(
        "Invalid desktop action:"
    )
    assert kit.describe({"action": "key", "keys": "fn+q"}).startswith("Blocked desktop action:")
    assert kit.describe(None).startswith("Invalid desktop action:")


# ── precheck(): refuse before the approval card ─────────────────────────────


@pytest.mark.asyncio
async def test_precheck_refuses_statically_and_reads_nothing():
    fake, kit, first = await observed()
    assert (
        kit.precheck({"action": "open_app", "app": "Terminal"}, user_id=U1)["rule"] == "blocked_app"
    )
    assert (
        kit.precheck({"action": "key", "keys": "cmd+shift+q"}, user_id=U1)["rule"] == "blocked_key"
    )
    secure = kit.precheck(
        {"action": "type", "text": "x", "ref": ref(first, '"Password"')}, user_id=U1
    )
    assert secure["rule"] == "secure_field"
    assert kit.precheck({"action": "click", "ref": "d999"}, user_id=U1)["stale_ref"] is True
    assert kit.precheck({"action": "click", "ref": ref(first, '"Send"')}, user_id=U1) is None
    assert kit.precheck({"action": "open_app", "app": "Calculator"}, user_id=U1) is None
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
async def test_precheck_refuses_when_a_check_fails(monkeypatch):
    fake, kit, _ = await observed()

    def broken(*_args):
        raise RuntimeError("rules unavailable")

    monkeypatch.setattr(kit, "_static_rules", broken)
    result = kit.precheck({"action": "open_app", "app": "Calculator"}, user_id=U1)
    assert_refused(result, "check_failed")
    assert "rules unavailable" not in result["error"]
    assert fake.events == [] and fake.reads == []


# ── bind(): an approval card is tied to the screen it was made from ─────────


async def approve(kit, card, user=U1):
    """Run the act an approval card stored (``bind``'s copy of the call),
    as the executor does once the owner approves it."""
    return await kit.execute("act", card, user_id=user, approved=True)


def messages_app():
    return FakeApp(
        "Messages", 105, [FakeWindow("Ann", (make_node("text field", "iMessage", handle="imsg"),))]
    )


@pytest.mark.asyncio
async def test_bind_records_the_latest_outline_and_reads_nothing():
    fake = desktop()
    kit = kit_for(fake)
    # Before any outline there is no screen to tie the card to.
    assert kit.bind({"action": "open_app", "app": "Calculator"}, user_id=U1) == {
        "action": "open_app",
        "app": "Calculator",
        CARD_KEY: {"app": "", "outline": ""},
    }
    first = await observe(kit)
    fake.reads.clear()
    send = ref(first, '"Send"')
    card = kit.bind({"action": "click", "ref": send}, user_id=U1)
    screen = card.pop(CARD_KEY)
    assert card == {"action": "click", "ref": send}
    assert screen["app"] == "Mail" and re.fullmatch(r"[0-9a-f]{12}", screen["outline"])
    # A value the call itself carried is replaced, never kept.
    forged = kit.bind(
        {"action": "key", "keys": "enter", CARD_KEY: {"app": "Messages", "outline": "x"}},
        user_id=U1,
    )
    assert forged[CARD_KEY] == screen
    assert fake.events == [] and fake.reads == []
    # Every outline gets a new id; another user's card is tied to their own.
    await observe(kit)
    assert kit.bind({}, user_id=U1)[CARD_KEY]["outline"] != screen["outline"]
    assert kit.bind({}, user_id=U2)[CARD_KEY] == {"app": "", "outline": ""}


@pytest.mark.asyncio
async def test_an_approved_act_runs_while_its_screen_holds():
    fake, kit, first = await observed()
    send = ref(first, '"Send"')
    card = kit.bind({"action": "click", "ref": send}, user_id=U1)
    done = await approve(kit, card)
    assert done["ok"] is True, done
    assert fake.events == [("click", "send", False)]
    # Keys and typing name no element, so only the app has to be the same:
    # a newer outline of Mail keeps the card good.
    card = kit.bind({"action": "type", "text": "Thanks"}, user_id=U1)
    await observe(kit)
    done = await approve(kit, card)
    assert done["ok"] is True, done
    assert fake.events[-1] == ("type", "Thanks", "subject")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {"action": "type", "text": "I quit\n"},
        {"action": "key", "keys": "cmd+a"},
        {"action": "key", "keys": "enter"},
        {"action": "scroll", "direction": "down"},
        {"action": "click", "x": 10, "y": 10},
    ],
)
async def test_input_is_refused_once_another_app_was_looked_at(params):
    # The card said "in Mail"; by approval time the latest outline is of
    # Messages, which is in front with its chat box focused.
    fake, kit, _ = await observed(apps=(messages_app(),))
    card = kit.bind(params, user_id=U1)
    assert kit.describe(card, user_id=U1).endswith(" in Mail")
    fake.front, fake.focused_handle = "Messages", "imsg"
    assert (await observe(kit))["app"] == "Messages"
    fake.reads.clear()
    result = await approve(kit, card)
    assert_refused(result, "screen_changed")
    assert result["error"] == "The screen changed since this was approved. Look again first."
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
async def test_input_is_refused_when_the_app_was_looked_at_but_not_brought_forward():
    # The latest outline is of Messages, named while Mail stayed in front.
    # The card, made in Mail, is refused whichever of the two is in front.
    fake, kit, _ = await observed(apps=(messages_app(),))
    card = kit.bind({"action": "key", "keys": "cmd+a"}, user_id=U1)
    assert (await observe(kit, app="Messages"))["app"] == "Messages"
    assert_refused(await approve(kit, card), "screen_changed")
    fake.front = "Messages"
    assert_refused(await approve(kit, card), "screen_changed")
    assert fake.events == []


@pytest.mark.asyncio
async def test_a_ref_card_is_refused_once_its_outline_was_replaced():
    fake, kit, first = await observed()
    card = kit.bind({"action": "click", "ref": ref(first, '"Send"')}, user_id=U1)
    await observe(kit)  # same app, new outline: the card's ref is gone
    assert_refused(await approve(kit, card), "screen_changed")
    assert fake.events == []


@pytest.mark.asyncio
async def test_a_ref_card_is_refused_after_a_restart_even_when_the_ref_is_reused():
    # Ref numbers start over in a new process, so d4 can name another
    # element in the same app; only the outline's id tells them apart.
    fake, kit, first = await observed()
    send = ref(first, '"Send"')
    card = kit.bind({"action": "click", "ref": send}, user_id=U1)
    fake.apps["Mail"].windows.insert(
        0,
        FakeWindow(
            "Inbox",
            (
                make_node("button", "Archive", handle="archive"),
                make_node("button", "Junk", handle="junk"),
                make_node("button", "Delete", handle="delete"),
            ),
        ),
    )
    restarted = kit_for(fake)
    again = await observe(restarted)
    assert ref(again, '"Delete"') == send  # the same ref, another element
    assert_refused(await approve(restarted, card), "screen_changed")
    assert fake.events == []


@pytest.mark.asyncio
async def test_opening_an_app_needs_only_the_cards_screen_to_be_there():
    fake, kit, _ = await observed()
    card = kit.bind({"action": "open_app", "app": "Calculator"}, user_id=U1)
    fake.front = "TextEdit"
    await observe(kit)
    done = await approve(kit, card)
    assert done["ok"] is True, done
    assert fake.events == [("open_app", "Calculator")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "screen",
    [
        "missing",
        None,
        "Mail",
        {"app": "Mail"},
        {"app": "Mail", "outline": 3},
        ["Mail", "abc"],
    ],
)
@pytest.mark.parametrize(
    "params",
    [
        {"action": "key", "keys": "enter"},
        {"action": "open_app", "app": "Calculator"},
    ],
)
async def test_an_approved_act_without_its_cards_screen_is_refused(screen, params):
    fake, kit, _ = await observed()
    card = dict(params) if screen == "missing" else {**params, CARD_KEY: screen}
    result = await approve(kit, card)
    assert_refused(result, "unbound_approval")
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
async def test_a_card_made_before_any_outline_never_sends_input():
    fake = desktop()
    kit = kit_for(fake)
    card = kit.bind({"action": "key", "keys": "enter"}, user_id=U1)
    await observe(kit)
    assert_refused(await approve(kit, card), "screen_changed")
    assert fake.events == []


@pytest.mark.asyncio
async def test_the_card_key_from_the_model_is_an_argument_no_action_takes():
    fake, kit, first = await observed()
    screen = kit.bind({}, user_id=U1)[CARD_KEY]
    params = {"action": "click", "ref": ref(first, '"Send"'), CARD_KEY: screen}
    refused = kit.precheck(params, user_id=U1)
    assert refused is not None and refused["ok"] is False
    assert f"does not take {CARD_KEY}" in refused["error"]
    # Unapproved, the key is not read as a card: the call is refused.
    result = await act(kit, **params)
    assert result["ok"] is False and f"does not take {CARD_KEY}" in result["error"]
    observed_with = await observe(kit, **{CARD_KEY: screen})
    assert observed_with["ok"] is False
    assert fake.events == []


@pytest.mark.asyncio
async def test_describe_names_the_cards_screen_not_a_newer_one():
    fake, kit, first = await observed(apps=(messages_app(),))
    send = ref(first, '"Send"')
    click = kit.bind({"action": "click", "ref": send}, user_id=U1)
    press = kit.bind({"action": "key", "keys": "cmd+s"}, user_id=U1)
    assert kit.describe(click, user_id=U1) == 'Click "Send" in Mail'
    assert kit.describe(press, user_id=U1) == "Press cmd+s in Mail"
    fake.front = "Messages"
    await observe(kit)
    # A newer outline of another app does not move the card there.
    assert kit.describe(press, user_id=U1) == "Press cmd+s in Mail"
    assert kit.describe(click, user_id=U1) == (
        f"Click {send} (not in the latest outline, so it will be refused)"
    )
    assert kit.describe({**press, CARD_KEY: "junk"}, user_id=U1) == (
        "Press cmd+s in the frontmost app"
    )
    assert fake.events == []


# ── errors fail closed ───────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {},
        {"action": "hack"},
        {"action": "click"},
        {"action": "click", "x": 1},
        {"action": "click", "ref": "d1", "x": 1, "y": 1},
        {"action": "click", "ref": "button-1"},
        {"action": "click", "x": -5, "y": 1},
        {"action": "click", "x": True, "y": 1},
        {"action": "click", "ref": "d1", "user_confirmed": True},
        {"action": "type"},
        {"action": "type", "text": ""},
        {"action": "type", "text": "x" * 2001},
        {"action": "type", "text": "bad\x1bescape"},
        {"action": "scroll", "direction": "sideways"},
        {"action": "open_app", "app": "/System/Applications/Utilities/Terminal.app"},
        {"action": "open_app", "app": "x-apple.systempreferences:com.apple.preference"},
        {"action": "open_app", "app": "-a Terminal"},
        {"action": "open_app", "app": ""},
        {"action": "focus_window", "app": "Mail", "index": 99},
        {"action": "focus_window", "app": "Mail", "index": "0"},
    ],
)
async def test_bad_act_arguments_are_errors_and_touch_nothing(params):
    fake, kit, _ = await observed()
    result = await act(kit, **params)
    assert result["ok"] is False and result["error"] and "refused" not in result
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {},
        {"action": "screenshot"},
        {"action": "outline", "max_chars": "lots"},
        {"action": "outline", "max_chars": True},
        {"action": "outline", "for_model_image": "yes"},
        {"action": "outline", "app": "../etc"},
        {"action": "outline", "depth": 3},
    ],
)
async def test_bad_observe_arguments_are_errors(params):
    fake = desktop()
    result = await kit_for(fake).execute("observe", params, user_id=U1)
    assert result["ok"] is False and result["error"]
    assert fake.reads == []


@pytest.mark.asyncio
async def test_malformed_calls_never_raise():
    kit = kit_for(desktop())
    assert (await kit.execute("teleport", {}, user_id=U1))["ok"] is False
    assert (await kit.execute("observe", "outline", user_id=U1))["ok"] is False
    assert (await kit.execute("observe", {"action": "outline"}, user_id=""))["ok"] is False
    assert (await kit.execute("observe", None, user_id=U1))["ok"] is False


@pytest.mark.asyncio
async def test_unavailable_backend_is_a_clean_error():
    kit = kit_for(select_backend("linux"))
    result = await observe(kit)
    assert result["ok"] is False and "not available" in result["error"]
    opened = await act(kit, action="open_app", app="Calculator")
    assert opened["ok"] is False and "not available" in opened["error"]


@pytest.mark.asyncio
async def test_missing_permission_is_reported_and_nothing_runs():
    fake = desktop(permission="denied")
    kit = kit_for(fake)
    result = await observe(kit)
    assert result["ok"] is False and result["needs_permission"] is True
    assert (await act(kit, action="open_app", app="Calculator"))["needs_permission"] is True
    assert fake.events == [] and "outline" not in fake.reads


@pytest.mark.asyncio
async def test_a_permission_check_that_fails_counts_as_denied():
    fake = desktop()
    fake.failures["permission"] = RuntimeError("tcc")
    result = await observe(kit_for(fake))
    assert result["ok"] is False and result["needs_permission"] is True


@pytest.mark.asyncio
async def test_backend_read_failure_is_generic_and_drops_old_refs():
    fake, kit, first = await observed()
    fake.failures["outline"] = RuntimeError("secret internal detail")
    result = await observe(kit)
    assert result == {"ok": False, "error": "desktop.observe failed."}
    del fake.failures["outline"]
    stale = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert stale["ok"] is False and stale["needs_observe"] is True
    assert fake.events == []


@pytest.mark.asyncio
async def test_backend_act_failure_is_reported_as_uncertain():
    fake, kit, first = await observed()
    fake.failures["click"] = RuntimeError("CGEvent failed")
    result = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert result["ok"] is False
    assert "may or may not" in result["error"] and "CGEvent" not in result["error"]
    again = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert again["needs_observe"] is True  # refs dropped: the state is unknown


@pytest.mark.asyncio
async def test_backend_specific_failures_get_specific_messages():
    fake, kit, first = await observed()
    fake.failures["click"] = ElementGoneError("gone")
    gone = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert gone["ok"] is False and gone["stale_ref"] is True

    fake.failures["focus_window"] = ElevatedTargetError("uipi")
    elevated = await act(kit, action="focus_window", app="TextEdit")
    assert elevated["ok"] is False and "administrator" in elevated["error"]

    fake.failures["open_app"] = AppNotFoundError("x")
    missing = await act(kit, action="open_app", app="Calculator")
    assert missing["ok"] is False and "Could not find" in missing["error"]


@pytest.mark.asyncio
async def test_backend_refusals_are_refusals_with_the_toolkits_own_words():
    # The backend is the last line: it can resolve a name the toolkit never
    # saw (a localized app name, an executable stem) to a blocked app, see a
    # password field take focus mid-typing, or find a click point covered by
    # another app's window. Those come back as refusals under the rule, not
    # as "may or may not have taken effect", and the refs are dropped.
    fake, kit, first = await observed()
    fake.failures["focus_window"] = BlockedTargetError("raw backend text", app="System Settings")
    blocked = await act(kit, action="focus_window", app="Systemeinstellungen")
    assert_refused(blocked, "blocked_app")
    assert "System Settings" in blocked["error"] and "raw backend text" not in blocked["error"]

    await observe(kit)
    fake.failures["type"] = SecureTargetError("raw backend text")
    secure = await act(kit, action="type", ref=ref(await observe(kit), '"Subject"'), text="x")
    assert_refused(secure, "secure_field")
    assert "raw backend text" not in secure["error"]

    fresh = await observe(kit)
    fake.failures["click"] = CoveredTargetError("raw backend text")
    covered = await act(kit, action="click", x=10, y=10)
    assert_refused(covered, "covered")
    assert "raw backend text" not in covered["error"]
    again = await act(kit, action="click", ref=ref(fresh, '"Send"'))
    assert again["needs_observe"] is True  # refs dropped after a backend refusal


@pytest.mark.asyncio
@pytest.mark.parametrize("keys", ["ctrl+escape", "ctrl+alt+end"])
async def test_start_menu_and_remote_security_combos_never_reach_the_backend(keys):
    fake, kit, _ = await observed()
    assert_refused(await act(kit, action="key", keys=keys), "blocked_key")
    assert fake.events == [] and fake.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("app", ["KeePassXC", "KeePass", "Keeper Password Manager"])
async def test_other_password_managers_are_never_read_or_acted_in(app):
    fake = desktop(
        apps=(FakeApp(app, 200, [FakeWindow("Vault", (make_node("button", "Copy"),))]),),
        front=app,
    )
    kit = kit_for(fake)
    assert_refused(await observe(kit), "secret_app")
    assert_refused(await act(kit, action="focus_window", app=app), "blocked_app")
    assert_refused(await act(kit, action="open_app", app=app), "blocked_app")
    assert "outline" not in fake.reads
    assert fake.events == []


@pytest.mark.asyncio
async def test_open_app_that_does_not_exist():
    fake = desktop()
    result = await act(kit_for(fake), action="open_app", app="Nonexistent App")
    assert result["ok"] is False and "Could not find" in result["error"]


@pytest.mark.asyncio
async def test_a_failed_then_outline_does_not_turn_a_done_act_into_a_failure():
    fake, kit, first = await observed()

    def breaks_reads(backend, event):
        backend.failures["outline"] = RuntimeError("AX gone")

    fake.on_event = breaks_reads
    result = await act(kit, action="click", ref=ref(first, '"Send"'))
    assert result["ok"] is True and result["did"] == 'click button "Send" in Mail'
    assert result["then"]["ok"] is False
    assert fake.events == [("click", "send", False)]
