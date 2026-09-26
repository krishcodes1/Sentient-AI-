"""browser.act and the page memory: against fakes (no browser) and, further
down, against the fake site over TLS in headless Chromium (skipped when
Playwright's Chromium is not installed). Never a real website, never a
headed window, never a real card."""

from __future__ import annotations

import json
import re

import pytest
import pytest_asyncio

from services.tools.browser import guard, handoff
from services.tools.browser import snapshot as snap
from services.tools.browser.act import (
    ACT_ACTIONS,
    CARD_KEY,
    MAX_FIELD_CHARS,
    MAX_FORM_FIELDS,
    PRESS_KEYS,
    BrowserActToolkit,
)
from services.tools.browser.actions import BROWSER_MAX_ACTIONS, BrowserReadToolkit
from services.tools.browser.checkout.markers import READ_CLICK_MESSAGE, USE_CHECKOUT_MESSAGE
from services.tools.browser.pagememory import LastPage, PageMemory, outline_digest, page_address, page_origin
from services.tools.browser.session import BrowserSessionManager
from services.tools.system import browser_installed
from tests.conftest import tls_launcher
from tests.fakesite.pages import DELAYS, PAGES, SAVED_CARD_LEAD, _page
from tests.test_browser_read import FakeGuard, FakeHandoff, FakeSessions, TestPlatform

USER = "u1"
LOGIN_LINES = [
    '- heading "Log in" [level=1] [ref=e1]',
    '- textbox "Username" [ref=e2]',
    '- textbox "Password" [ref=e3]',
    '- button "Log in" [ref=e4]',
]
CHECKOUT_LINES = [
    '- heading "Checkout" [level=1] [ref=e1]',
    '- textbox "Email" [ref=e2]',
    '- textbox "Name" [ref=e3]',
    '- textbox "Address" [ref=e4]',
    '- combobox "Country" [ref=e5]:',
    '  - option "United States" [selected]',
    '  - option "Canada"',
    '- checkbox "Gift wrap" [ref=e6]',
    '- textbox "Expiry (MM/YY)" [ref=e7]',
    '- button "Place order" [ref=e8]',
    "- textbox [ref=e9]",
    "- 'link \"Terms: read them\" [ref=e10]'",
    '- button "Continue" [ref=e11]',
]


def remember(memory, lines=CHECKOUT_LINES, url="https://shop.example.com/checkout", secret=None):
    facts = snap.PageFacts(secret_fields=secret if secret is not None else {})
    return memory.remember(USER, url=url, outline_lines=lines, facts=facts)


def fake_kit(*, cancelled=False):
    sessions, fake_guard, memory = FakeSessions(), FakeGuard(), PageMemory()
    kit = BrowserActToolkit(
        sessions,
        guard=fake_guard,
        handoff=FakeHandoff(),
        memory=memory,
        cancel_flag=lambda user_id: cancelled,
    )
    return kit, sessions, memory


def refused(result, rule):
    assert result["ok"] is False and result["refused"] is True, result
    assert result["rule"] == rule, result
    assert result["error"]
    return result


# ── page memory ──────────────────────────────────────────────────────────


def test_outline_digest_is_stable_and_sensitive_to_any_line():
    assert outline_digest(CHECKOUT_LINES) == outline_digest(list(CHECKOUT_LINES))
    assert outline_digest(CHECKOUT_LINES) != outline_digest(CHECKOUT_LINES[:-1])
    assert len(outline_digest([])) == 40


@pytest.mark.parametrize(
    "url, scheme, origin",
    [
        ("https://Shop.Example.com/checkout?x=1#f", "https", "https://shop.example.com"),
        ("https://user:pw@shop.example.com:8443/", "https", "https://shop.example.com:8443"),
        ("http://127.0.0.1:5000/login", "http", "http://127.0.0.1:5000"),
        ("about:blank", "about", "about:blank"),
        ("chrome-error://chromewebdata/", "chrome-error", "chrome-error://chromewebdata"),
    ],
)
def test_page_origin(url, scheme, origin):
    assert page_origin(url) == (scheme, origin)


def test_memory_records_refs_names_secrets_origin_and_scheme():
    memory = PageMemory()
    page = remember(memory, secret={"e7": "cc-exp", "e99": "password"})
    assert isinstance(page, LastPage) and memory.get(USER) is page
    assert page.origin == "https://shop.example.com" and page.scheme == "https"
    assert page.url == "https://shop.example.com/checkout"
    assert page.outline_digest == outline_digest(CHECKOUT_LINES)
    assert dict(page.names) == {
        "e1": "Checkout",
        "e2": "Email",
        "e3": "Name",
        "e4": "Address",
        "e5": "Country",
        "e6": "Gift wrap",
        "e7": "Expiry (MM/YY)",
        "e8": "Place order",
        "e9": "",
        "e10": "Terms: read them",
        "e11": "Continue",
    }
    # facts mark e7; e99 is not on the page; nothing here is named like a secret
    assert page.secret_refs == frozenset({"e7"})
    assert page.query is None and page.full is False
    memory.forget(USER)
    assert memory.get(USER) is None and memory.get("nobody") is None


def test_memory_marks_secret_fields_by_name_when_facts_are_unknown():
    memory = PageMemory()
    page = memory.remember(
        USER, url="http://127.0.0.1:1/login", outline_lines=LOGIN_LINES, facts=snap.PageFacts()
    )
    assert page.secret_refs == frozenset({"e3"}) and page.scheme == "http"


def test_memory_keeps_the_latest_page_per_user_and_is_bounded():
    memory = PageMemory()
    remember(memory, LOGIN_LINES)
    latest = remember(memory)
    assert memory.get(USER) is latest
    for index in range(70):
        memory.remember(f"user-{index}", url="https://a/", outline_lines=[], facts=snap.PageFacts())
    assert memory.get(USER) is None  # the oldest entry went first
    assert memory.get("user-69") is not None and memory.get("user-5") is None


# ── precheck, bind, describe (no browser) ─────────────────────────────────


def test_precheck_refuses_before_any_page_was_looked_at():
    kit, sessions, _memory = fake_kit()
    result = refused(kit.precheck({"action": "click", "ref": "e1"}, user_id=USER), "needs_observe")
    assert result["needs_observe"] is True and sessions.calls == []


@pytest.mark.parametrize(
    "params",
    [
        {"action": "type", "ref": "e2", "text": "x"},
        {"ref": "e2", "text": "x"},
        {"action": "fill", "ref": "e2"},
        {"action": "fill", "ref": "e2", "text": 5},
        {"action": "fill", "ref": "e2", "text": "x" * (MAX_FIELD_CHARS + 1)},
        {"action": "fill", "ref": "e2", "text": "a\x00b"},
        {"action": "fill", "ref": "not-a-ref", "text": "x"},
        {"action": "fill", "ref": "e2", "text": "x", "value": "y"},
        {"action": "fill", "ref": "e2", "text": "x", CARD_KEY: {"origin": "x", "outline": "y", "scheme": "https"}},
        {"action": "fill_form", "fields": []},
        {"action": "fill_form", "fields": "e2"},
        {"action": "fill_form", "fields": [{"ref": "e2"}]},
        {"action": "fill_form", "fields": [{"ref": "e2", "text": "a", "extra": 1}]},
        {"action": "fill_form", "fields": [{"ref": "e2", "text": "a"}, {"ref": "e2", "text": "b"}]},
        {"action": "fill_form", "fields": [{"ref": f"e{n}", "text": "a"} for n in range(MAX_FORM_FIELDS + 1)]},
        {"action": "select", "ref": "e5"},
        {"action": "select", "ref": "e5", "value": "  "},
        {"action": "press", "key": "F5"},
        {"action": "press", "key": "Enter", "ref": "e2"},
        {"action": "submit"},
        {"action": "check", "ref": 7},
    ],
)
def test_precheck_refuses_bad_arguments_without_a_browser(params):
    kit, sessions, memory = fake_kit()
    remember(memory)
    refused(kit.precheck(params, user_id=USER), "invalid_arguments")
    assert sessions.calls == []


def test_precheck_refuses_a_non_object():
    kit, _sessions, memory = fake_kit()
    remember(memory)
    refused(kit.precheck(["click", "e1"], user_id=USER), "invalid_arguments")  # type: ignore[arg-type]


def test_precheck_refuses_when_the_task_was_stopped():
    kit, _sessions, memory = fake_kit(cancelled=True)
    remember(memory)
    refused(kit.precheck({"action": "click", "ref": "e8"}, user_id=USER), "cancelled")


def test_a_cancel_flag_that_raises_counts_as_set():
    kit, _sessions, memory = fake_kit()
    remember(memory)

    def boom(user_id):
        raise RuntimeError("redis is down")

    kit._cancel_flag = boom
    refused(kit.precheck({"action": "click", "ref": "e8"}, user_id=USER), "cancelled")


def test_precheck_refuses_a_ref_the_latest_outline_does_not_have():
    kit, _sessions, memory = fake_kit()
    remember(memory)
    result = refused(kit.precheck({"action": "click", "ref": "e77"}, user_id=USER), "stale_ref")
    assert result["stale_ref"] is True and result["error"] == "stale ref: re-snapshot"
    form = {"action": "fill_form", "fields": [{"ref": "e2", "text": "a"}, {"ref": "e77", "text": "b"}]}
    refused(kit.precheck(form, user_id=USER), "stale_ref")


@pytest.mark.parametrize(
    "params",
    [
        {"action": "fill", "ref": "e3", "text": "hunter2"},  # named "Password"
        {"action": "fill_form", "fields": [{"ref": "e2", "text": "me"}, {"ref": "e3", "text": "pw"}]},
    ],
)
def test_precheck_refuses_typing_into_a_field_named_like_a_secret(params):
    kit, _sessions, memory = fake_kit()
    remember(memory, LOGIN_LINES, url="https://idp.example.com/login")
    result = refused(kit.precheck(params, user_id=USER), "secure_field")
    assert "never types into one" in result["error"] and "hunter2" not in json.dumps(result)


@pytest.mark.parametrize("action, extra", [("fill", {"text": "12/28"}), ("select", {"value": "12"})])
def test_precheck_refuses_typing_into_a_field_the_facts_mark_as_a_card_field(action, extra):
    kit, _sessions, memory = fake_kit()
    remember(memory, ['- textbox "Ends" [ref=e7]'], secret={"e7": "cc-exp"})  # a name that says nothing
    refused(kit.precheck({"action": action, "ref": "e7", **extra}, user_id=USER), "secure_field")


@pytest.mark.parametrize(
    "name",
    ["Expiry (MM/YY)", "Card no.", "CSC", "Name on card", "Cardholder", "Security code", "PAN", "Valid thru"],
)
def test_precheck_refuses_typing_into_a_field_named_like_any_card_field(name):
    """The checkout's own field names (markers), not just the few the
    outline knew: what the checkout would fill, browser.act never types."""
    kit, _sessions, memory = fake_kit()
    remember(memory, [f'- textbox "{name}" [ref=e1]', '- textbox "City" [ref=e2]'])
    refused(kit.precheck({"action": "fill", "ref": "e1", "text": "x"}, user_id=USER), "secure_field")
    assert kit.precheck({"action": "fill", "ref": "e2", "text": "x"}, user_id=USER) is None


@pytest.mark.parametrize(
    "name",
    ["Place order", "Place your order", "Pay now", "Pay", "Buy now", "Buy", "Purchase",
     "Complete order", "Confirm payment", "Confirm and pay", "Subscribe", "Order now", "Book now",
     "Start free trial", "PLACE ORDER", "Buy now with 1-Click"],
)
def test_precheck_refuses_a_click_or_submit_on_a_button_that_pays(name):
    """Whatever the purchases switch says: paying is browser.checkout's
    job. The reason names the switch, in the owner's words."""
    kit, _sessions, memory = fake_kit()
    remember(memory, [f'- button "{name}" [ref=e1]', '- link "Continue" [ref=e2]'])
    for action in ("click", "submit"):
        result = refused(kit.precheck({"action": action, "ref": "e1"}, user_id=USER), "use_checkout")
        assert result["error"] == USE_CHECKOUT_MESSAGE
    assert kit.precheck({"action": "click", "ref": "e2"}, user_id=USER) is None


def test_precheck_refuses_a_submit_through_a_field_whose_form_button_pays():
    """``submit`` names a field, but the form goes out through its default
    button: the page memory kept that button's words for the field, so
    the refusal comes before any card. A click on the field, or a submit
    through a field of a form whose button pays nothing, is not refused."""
    kit, _sessions, memory = fake_kit()
    lines = ['- textbox "Gift note" [ref=e1]', '- textbox "Email" [ref=e2]', '- button "Place order" [ref=e3]']
    facts = snap.PageFacts(secret_fields={}, form_buttons={"e1": "Place order", "e2": "Sign up"})
    memory.remember(USER, url="https://shop.example.com/cart", outline_lines=lines, facts=facts)
    result = refused(kit.precheck({"action": "submit", "ref": "e1"}, user_id=USER), "use_checkout")
    assert result["error"] == USE_CHECKOUT_MESSAGE
    assert kit.precheck({"action": "click", "ref": "e1"}, user_id=USER) is None
    assert kit.precheck({"action": "submit", "ref": "e2"}, user_id=USER) is None
    assert memory.get(USER).form_buttons == {"e1": "Place order", "e2": "Sign up"}


@pytest.mark.parametrize(
    "name",
    ["Checkout", "Proceed to checkout", "Continue to payment", "Payment methods", "PayPal",
     "Buyer protection", "Add to cart", "Apply"],
)
def test_buttons_that_lead_to_the_checkout_or_merely_mention_paying_are_not_refused(name):
    kit, _sessions, memory = fake_kit()
    remember(memory, [f'- button "{name}" [ref=e1]'])
    assert kit.precheck({"action": "click", "ref": "e1"}, user_id=USER) is None, name


def test_clicking_a_secret_field_or_pressing_a_key_is_not_typing_into_it():
    kit, _sessions, memory = fake_kit()
    remember(memory, LOGIN_LINES, url="https://idp.example.com/login")
    assert kit.precheck({"action": "click", "ref": "e3"}, user_id=USER) is None
    assert kit.precheck({"action": "press", "key": "Tab"}, user_id=USER) is None


@pytest.mark.parametrize(
    "params",
    [
        {"action": "fill", "ref": "e2", "text": "x"},
        {"action": "click", "ref": "e11"},
        {"action": "press", "key": "Enter"},
    ],
)
def test_precheck_refuses_every_act_on_an_http_page(params):
    kit, _sessions, memory = fake_kit()
    remember(memory, url="http://shop.example.com/checkout")
    result = refused(kit.precheck(params, user_id=USER), "insecure_page")
    assert "http://" in result["error"]
    remember(memory, url="https://shop.example.com/checkout")
    assert kit.precheck(params, user_id=USER) is None


def test_precheck_passes_every_action_on_a_good_page():
    kit, sessions, memory = fake_kit()
    remember(memory)
    calls = {
        "fill": {"ref": "e2", "text": "me@example.com"},
        "fill_form": {"fields": [{"ref": "e2", "text": "a"}, {"ref": "e3", "text": "b"}]},
        "select": {"ref": "e5", "value": "Canada"},
        "check": {"ref": "e6"},
        "click": {"ref": "e11"},
        "press": {"key": "Enter"},
        "submit": {"ref": "e2"},
    }
    assert set(calls) == set(ACT_ACTIONS)
    for action, params in calls.items():
        assert kit.precheck({"action": action, **params}, user_id=USER) is None, action
    assert sessions.calls == []


def test_precheck_refuses_when_a_check_fails():
    kit, _sessions, memory = fake_kit()
    remember(memory)

    class Broken(PageMemory):
        def get(self, user_id):
            raise RuntimeError("boom")

    kit._memory = Broken()
    result = refused(kit.precheck({"action": "click", "ref": "e8"}, user_id=USER), "check_failed")
    assert "boom" not in result["error"]


def test_bind_ties_the_call_to_the_latest_page_and_overrides_a_supplied_card():
    kit, _sessions, memory = fake_kit()
    empty = kit.bind({"action": "click", "ref": "e8"}, user_id=USER)
    assert empty[CARD_KEY] == {"origin": "", "address": "", "outline": "", "scheme": ""}
    page = remember(memory)
    bound = kit.bind({"action": "click", "ref": "e8", CARD_KEY: {"origin": "https://evil"}}, user_id=USER)
    assert bound == {
        "action": "click",
        "ref": "e8",
        CARD_KEY: {
            "origin": "https://shop.example.com",
            "address": page_address("https://shop.example.com/checkout"),
            "outline": page.outline_digest,
            "scheme": "https",
        },
    }
    # The address is a digest: the card never keeps the URL's query string.
    assert page_address("https://shop.example.com/checkout?sid=1#x") == page_address(
        "https://shop.example.com/checkout?sid=1"
    ) != page_address("https://shop.example.com/checkout")


def test_describe_builds_the_sentence_from_the_page_not_the_model():
    kit, _sessions, memory = fake_kit()
    remember(memory)
    d = lambda **params: kit.describe(params, user_id=USER)  # noqa: E731
    assert d(action="fill", ref="e2", text="me@example.com") == 'Type 14 characters into "Email" on shop.example.com'
    assert d(action="fill", ref="e2", text="a") == 'Type 1 character into "Email" on shop.example.com'
    assert d(action="fill", ref="e2", text="") == 'Clear "Email" on shop.example.com'
    assert d(action="fill", ref="e9", text="abc") == "Type 3 characters into e9 on shop.example.com"
    assert (
        d(action="fill_form", fields=[{"ref": "e2", "text": "a"}, {"ref": "e3", "text": "b"}, {"ref": "e4", "text": "c"}])
        == "Fill 3 fields on shop.example.com: Email, Name, Address"
    )
    assert (
        d(action="fill_form", fields=[{"ref": f"e{n}", "text": "a"} for n in (2, 3, 4, 9)])
        == "Fill 4 fields on shop.example.com: Email, Name, Address…"
    )
    assert (
        d(action="fill_form", fields=[{"ref": "e9", "text": "a"}, {"ref": "e2", "text": "b"}])
        == "Fill 2 fields on shop.example.com: e9, Email"
    )
    assert d(action="select", ref="e5", value="Canada") == 'Select "Canada" in "Country" on shop.example.com'
    assert d(action="check", ref="e6") == 'Check "Gift wrap" on shop.example.com'
    assert d(action="click", ref="e8") == 'Click "Place order" on shop.example.com'
    assert d(action="press", key="Enter") == "Press Enter on shop.example.com"
    assert d(action="submit", ref="e8") == 'Submit the form with "Place order" on shop.example.com'
    assert d(action="click", ref="e10") == 'Click "Terms: read them" on shop.example.com'
    assert d(action="fill", ref="e2", text="x" * 5000).startswith("Blocked browser action: text is too long")
    assert d(action="hover", ref="e2").startswith("Blocked browser action: action must be one of")


def test_describe_names_the_cards_page_not_a_newer_one():
    kit, _sessions, memory = fake_kit()
    remember(memory)
    card = kit.bind({"action": "click", "ref": "e8"}, user_id=USER)
    assert kit.describe(card, user_id=USER) == 'Click "Place order" on shop.example.com'
    # the person looked at another page since: the ref is not resolved against it
    remember(memory, LOGIN_LINES, url="https://idp.example.com/login")
    assert kit.describe(card, user_id=USER) == "Click e8 on shop.example.com"
    assert kit.describe({"action": "click", "ref": "e4"}, user_id=USER) == 'Click "Log in" on idp.example.com'
    # a card with no page (bound before anything was read) names no host
    blank = {"action": "press", "key": "Tab", CARD_KEY: {"origin": "", "outline": "", "scheme": ""}}
    assert kit.describe(blank, user_id=USER) == "Press Tab"
    assert kit.describe({"action": "press", "key": "Tab", CARD_KEY: "junk"}, user_id=USER) == "Press Tab"


def test_describe_keeps_long_names_short():
    kit, _sessions, memory = fake_kit()
    remember(memory, ['- button "' + "x" * 100 + '" [ref=e1]'])
    sentence = kit.describe({"action": "click", "ref": "e1"}, user_id=USER)
    assert len(sentence) < 80 and sentence.endswith('…" on shop.example.com')


# ── execute gates (no browser) ────────────────────────────────────────────


async def execute(kit, action, approved=True, task_id="t1", **params):
    return await kit.execute(action, params, user_id=USER, task_id=task_id, approved=approved)


@pytest.mark.asyncio
async def test_unknown_action_and_bad_shapes_fail_closed_without_a_browser():
    kit, sessions, memory = fake_kit()
    remember(memory)
    result = await execute(kit, "hover", ref="e1")
    assert result["ok"] is False and "Unknown browser.act action 'hover'" in result["error"]
    assert (await kit.execute("click", ["e1"], user_id=USER, task_id="t1", approved=True))["ok"] is False  # type: ignore[arg-type]
    two = await kit.execute("click", {"action": "fill", "ref": "e8"}, user_id=USER, task_id="t1", approved=True)
    assert two["ok"] is False and "two different actions" in two["error"]
    assert (await kit.execute(None, {}, user_id=USER, task_id="t1", approved=True))["ok"] is False  # type: ignore[arg-type]
    assert sessions.calls == []


@pytest.mark.asyncio
async def test_an_approved_act_without_its_page_is_refused_before_the_browser():
    kit, sessions, memory = fake_kit()
    remember(memory)
    refused(await execute(kit, "click", ref="e11"), "unbound_approval")
    refused(await execute(kit, "click", ref="e11", **{CARD_KEY: {"origin": "x"}}), "unbound_approval")
    assert sessions.calls == []


@pytest.mark.asyncio
async def test_an_unapproved_act_may_not_carry_a_card():
    kit, sessions, memory = fake_kit()
    remember(memory)
    card = kit.bind({"action": "click", "ref": "e8"}, user_id=USER)
    result = await kit.execute("click", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=False)
    refused(result, "invalid_arguments")
    assert sessions.calls == []


@pytest.mark.asyncio
async def test_execute_runs_the_static_rules_again():
    kit, sessions, memory = fake_kit()
    remember(memory, LOGIN_LINES, url="https://idp.example.com/login")
    card = kit.bind({"action": "fill", "ref": "e3", "text": "pw"}, user_id=USER)
    refused(await execute(kit, "fill", ref="e3", text="pw", **{CARD_KEY: card[CARD_KEY]}), "secure_field")
    refused(await execute(kit, "click", ref="e77", **{CARD_KEY: card[CARD_KEY]}), "stale_ref")
    memory.forget(USER)
    refused(await execute(kit, "click", ref="e4", **{CARD_KEY: card[CARD_KEY]}), "needs_observe")
    assert sessions.calls == []


@pytest.mark.asyncio
async def test_null_arguments_are_treated_as_absent():
    kit, sessions, memory = fake_kit()
    remember(memory)
    card = kit.bind({"action": "press", "key": "Enter"}, user_id=USER)
    result = await kit.execute(
        "press", {"key": "Enter", "ref": None, "text": None, CARD_KEY: card[CARD_KEY]}, user_id=USER, task_id="t1", approved=True
    )
    # past every static gate: the fake session refuses to open a page
    assert result == {"ok": False, "error": "browser.act press failed."}
    assert sessions.calls == [(USER, "account", "t1")]


@pytest.mark.asyncio
async def test_action_cap_and_loop_detector_apply_to_acts():
    kit, sessions, memory = fake_kit()
    remember(memory)
    card = kit.bind({"action": "press", "key": "Enter"}, user_id=USER)[CARD_KEY]
    for _ in range(2):
        assert "Loop detected" not in str(await execute(kit, "press", key="Enter", **{CARD_KEY: card}))
    third = await execute(kit, "press", key="Enter", **{CARD_KEY: card})
    assert third["ok"] is False and "Loop detected: browser.act press" in third["error"]
    # a different call breaks the streak; the streak is per task
    assert "Loop detected" not in str(await execute(kit, "press", key="Tab", **{CARD_KEY: card}))
    assert "Loop detected" not in str(await execute(kit, "press", key="Enter", task_id="t2", **{CARD_KEY: card}))
    sessions.session.task.actions = BROWSER_MAX_ACTIONS  # the fake session is now on task t2
    capped = await execute(kit, "press", key="Escape", task_id="t2", **{CARD_KEY: card})
    assert capped["cap"] == "actions" and "60" in capped["resume_hint"]
    assert sessions.session.task.actions == BROWSER_MAX_ACTIONS  # a capped act is not counted


@pytest.mark.asyncio
async def test_a_browser_that_will_not_start_is_a_result_not_an_exception():
    class Broken(FakeSessions):
        async def get(self, user_id, *, mode, task_id):
            raise RuntimeError("Executable doesn't exist at /Users/x/.cache/ms-playwright")

    memory = PageMemory()
    remember(memory)
    kit = BrowserActToolkit(Broken(), guard=FakeGuard(), handoff=FakeHandoff(), memory=memory, cancel_flag=lambda u: False)
    card = kit.bind({"action": "press", "key": "Enter"}, user_id=USER)[CARD_KEY]
    result = await execute(kit, "press", key="Enter", **{CARD_KEY: card})
    assert result["ok"] is False and result["error"].startswith("Could not start the browser")
    assert "ms-playwright" not in result["error"]


@pytest.mark.asyncio
async def test_a_guard_that_will_not_install_fails_closed():
    class BrokenGuard(FakeGuard):
        async def install_egress_guard(self, context, *, account_mode):
            raise RuntimeError("Target page, context or browser has been closed")

    sessions, memory = FakeSessions(), PageMemory()
    remember(memory)
    kit = BrowserActToolkit(sessions, guard=BrokenGuard(), handoff=FakeHandoff(), memory=memory, cancel_flag=lambda u: False)
    card = kit.bind({"action": "press", "key": "Enter"}, user_id=USER)[CARD_KEY]
    result = await execute(kit, "press", key="Enter", **{CARD_KEY: card})
    assert result["ok"] is False and "network guard" in result["error"]
    assert sessions.session.task.actions == 0


@pytest.mark.asyncio
async def test_refusal_logs_carry_the_rule_never_the_text():
    from structlog.testing import capture_logs

    kit, _sessions, memory = fake_kit()
    remember(memory, LOGIN_LINES, url="https://idp.example.com/login")
    with capture_logs() as logs:
        await execute(kit, "fill", ref="e3", text="hunter2-secret", **{CARD_KEY: {"origin": "", "outline": "", "scheme": ""}})
    assert logs and logs[0]["rule"] == "secure_field"
    assert "hunter2" not in repr(logs)


# ── against the fake site over TLS (headless Chromium) ───────────────────


class SpyGuard:
    """The real guard, with ``write_allowed`` observed on every route call
    so a test can see the write window was open for the act's request and
    closed again afterwards."""

    BLOCKED_NAVIGATION_MARKER = guard.BLOCKED_NAVIGATION_MARKER

    def __init__(self) -> None:
        self._guard = guard.Guard(resolver=lambda host: ["127.0.0.1"])
        self.seen: list[tuple[str, str, bool]] = []  # (method, path, write_allowed)

    def check_url(self, url):
        return self._guard.check_url(url)

    async def install_egress_guard(self, context, *, account_mode):
        await self._guard.install_egress_guard(context, account_mode=account_mode)
        state = guard.egress_state(context)
        original = self._guard._route

        async def spying_route(route, request, st):
            if request.is_navigation_request():
                self.seen.append((request.method, request.url.split("?")[0].rsplit("/", 1)[-1], st.write_allowed))
            await original(route, request, st)

        self._guard._route = spying_route  # type: ignore[method-assign]
        assert state is not None

    async def consequential(self, page, ref):
        return await self._guard.consequential(page, ref)

    async def settle_blocked_navigation(self, page, *, timeout_ms=1500):
        await guard.settle_blocked_navigation(page, timeout_ms=timeout_ms)

    def egress_state(self, context):
        return guard.egress_state(context)


@pytest_asyncio.fixture
async def kits(fakesite_tls, tmp_path):
    """(read toolkit, act toolkit, sessions, memory, spy guard) on one
    headless Chromium session that trusts the fake site's certificate."""
    if not browser_installed():
        pytest.skip("Playwright's Chromium is not installed (python -m playwright install chromium)")
    sessions = BrowserSessionManager(
        headless=True, platform=TestPlatform(tmp_path), max_sessions=1, max_tabs=2, launcher=tls_launcher
    )
    memory, spy = PageMemory(), SpyGuard()
    read = BrowserReadToolkit(sessions, guard=spy, handoff=handoff, page_memory=memory)
    act = BrowserActToolkit(sessions, guard=spy, handoff=handoff, memory=memory, cancel_flag=lambda u: False)
    try:
        yield read, act, sessions, memory, spy
    finally:
        await sessions.close_all()


async def read(kits, action, **params):
    return await kits[0].execute(action, params, user_id=USER, task_id="t1")


async def act(kits, action, *, bind=True, **params):
    """A browser.act call the way the runtime makes one: precheck, bind the
    card, then run it approved with the card's arguments."""
    toolkit = kits[1]
    call = {"action": action, **params}
    pre = toolkit.precheck(call, user_id=USER)
    assert pre is None, pre
    card = toolkit.bind(call, user_id=USER) if bind else call
    arguments = {k: v for k, v in card.items() if k != "action"}
    return await toolkit.execute(action, arguments, user_id=USER, task_id="t1", approved=True)


async def live_page(kits):
    return await (await kits[2].get(USER, mode="account", task_id="t1")).page()


def ref_of(result, prefix: str) -> str:
    for line in result["outline"]:
        if line.lstrip().startswith(prefix):
            match = re.search(r"\[ref=((?:f\d+)?e\d+)\]", line)
            if match:
                return match.group(1)
    raise AssertionError(f"no {prefix!r} line with a ref in {result['outline']}")


@pytest.mark.asyncio
async def test_a_read_records_the_page_in_the_shared_memory(kits, fakesite_tls):
    _read, _act, _sessions, memory, _spy = kits
    assert memory.get(USER) is None
    result = await read(kits, "open", url=fakesite_tls.url("/login?next=%2Fgrades"))
    page = memory.get(USER)
    assert page is not None and page.scheme == "https" and page.origin == fakesite_tls.base
    assert page.outline_digest == outline_digest(result["outline"])
    assert page.names[ref_of(result, '- textbox "Password"')] == "Password"
    # the empty password box is known as one before anything is typed into it
    assert ref_of(result, '- textbox "Password"') in page.secret_refs
    assert ref_of(result, '- textbox "Username"') not in page.secret_refs


@pytest.mark.asyncio
async def test_fill_types_into_the_field_and_returns_the_fresh_outline(kits, fakesite_tls):
    _read, _act, _sessions, memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/post"))
    ref = ref_of(before, '- textbox "Email"')
    result = await act(kits, "fill", ref=ref, text="me@example.com")
    assert result["ok"] is True and result["did"] == 'Typed 14 characters into "Email"'
    assert result["url"].endswith("/post") and result["mode"] == "account"
    assert result["summary"].startswith('[step 2] act fill "Email" → ') and "example.com" not in result["summary"]
    assert any("me@example.com" in line for line in result["outline"])  # what the model typed, on the page
    assert (await (await live_page(kits)).locator("input[name=email]").input_value()) == "me@example.com"
    assert memory.get(USER).outline_digest == outline_digest(result["outline"])  # type: ignore[union-attr]
    cleared = await act(kits, "fill", ref=ref, text="")
    assert cleared["did"] == 'Cleared "Email"'


@pytest.mark.asyncio
async def test_fill_form_fills_three_fields_in_one_act(kits, fakesite_tls):
    before = await read(kits, "open", url=fakesite_tls.url("/checkout"))
    fields = [
        {"ref": ref_of(before, '- textbox "Email"'), "text": "me@example.com"},
        {"ref": ref_of(before, '- textbox "Name"'), "text": "Krish Q"},
        {"ref": ref_of(before, '- textbox "Address"'), "text": "1 Main St"},
    ]
    result = await act(kits, "fill_form", fields=fields)
    assert result["ok"] is True and result["did"] == "Filled 3 fields: Email, Name, Address"
    assert result["summary"].startswith('[step 2] act fill_form "3 fields" → ')
    page = await live_page(kits)
    assert await page.locator("input[name=name]").input_value() == "Krish Q"
    assert await page.locator("input[name=address]").input_value() == "1 Main St"


@pytest.mark.asyncio
async def test_select_and_check(kits, fakesite_tls):
    before = await read(kits, "open", url=fakesite_tls.url("/checkout"))
    chosen = await act(kits, "select", ref=ref_of(before, '- combobox "Country"'), value="Canada")
    assert chosen["ok"] is True and chosen["did"] == 'Selected "Canada" in "Country"'
    page = await live_page(kits)
    assert await page.locator("select[name=country]").input_value() == "CA"
    missing = await act(kits, "select", ref=ref_of(chosen, '- combobox "Country"'), value="Narnia")
    assert missing["ok"] is False and 'No option matches "Narnia"' in missing["error"]
    ticked = await act(kits, "check", ref=ref_of(chosen, '- checkbox "Gift wrap"'))
    assert ticked["ok"] is True and ticked["did"] == 'Checked "Gift wrap"'
    assert await page.locator("input[name=gift]").is_checked()


@pytest.mark.asyncio
async def test_click_on_a_consequential_button_submits_inside_the_write_window(kits, fakesite_tls):
    _read, _act, sessions, _memory, spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/post"))
    await act(kits, "fill", ref=ref_of(before, '- textbox "Email"'), text="me@example.com")
    filled = await read(kits, "snapshot")
    result = await act(kits, "click", ref=ref_of(filled, '- button "Sign up"'))
    assert result["ok"] is True and result["did"] == 'Clicked "Sign up"'
    assert any("Thanks" in line for line in result["outline"])  # the POST went through
    assert ("POST", "post", True) in spy.seen  # the write window was open for it
    context = (await sessions.get(USER, mode="account", task_id="t1")).context
    assert guard.egress_state(context).write_allowed is False  # and closed again
    # every POST the guard saw ran inside a write window
    assert not any(method == "POST" and allowed is False for method, _p, allowed in spy.seen)


@pytest.mark.asyncio
async def test_submit_and_press_enter_submit_the_form(kits, fakesite_tls):
    before = await read(kits, "open", url=fakesite_tls.url("/post"))
    email = ref_of(before, '- textbox "Email"')
    result = await act(kits, "submit", ref=email)
    assert result["ok"] is True and result["did"] == 'Submitted the form with "Email"'
    assert any("Thanks" in line for line in result["outline"])
    again = await read(kits, "open", url=fakesite_tls.url("/post"))
    await act(kits, "fill", ref=ref_of(again, '- textbox "Email"'), text="me@example.com")
    pressed = await act(kits, "press", key="Enter")
    assert pressed["ok"] is True and pressed["did"] == "Pressed Enter"
    assert pressed["summary"].startswith('[step ') and 'act press "Enter"' in pressed["summary"]
    assert any("Thanks" in line for line in pressed["outline"])


@pytest.mark.asyncio
async def test_submit_outside_a_form_is_an_error_not_a_submission(kits, fakesite_tls):
    before = await read(kits, "open", url=fakesite_tls.url("/"))
    ref = ref_of(before, '- link "Grades"')
    result = await act(kits, "submit", ref=ref)
    assert result["ok"] is False and "nothing to submit" in result["error"]


@pytest.mark.asyncio
async def test_a_password_field_is_refused_before_the_card_and_by_the_live_page(kits, fakesite_tls):
    _read, toolkit, _sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/login"))
    password = ref_of(before, '- textbox "Password"')
    refused(toolkit.precheck({"action": "fill", "ref": password, "text": "pw"}, user_id=USER), "secure_field")
    # A field the outline and the facts saw as plain, turned into a password
    # box after the card was made: the live check still refuses it.
    page = await live_page(kits)
    await page.set_content(
        "<form action='/login' method='post'><label>Secret word <input id='w' name='w'></label>"
        "<button type='submit'>Go</button></form>"
    )
    plain = await read(kits, "snapshot")
    ref = ref_of(plain, '- textbox "Secret word"')
    call = {"action": "fill", "ref": ref, "text": "swordfish"}
    assert toolkit.precheck(call, user_id=USER) is None
    card = toolkit.bind(call, user_id=USER)
    await page.evaluate("document.getElementById('w').type = 'password'")
    result = await toolkit.execute("fill", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "secure_field")
    assert await page.locator("#w").input_value() == ""
    assert "swordfish" not in json.dumps(result)


@pytest.mark.asyncio
async def test_card_fields_are_refused_by_their_autocomplete_not_their_name(kits, fakesite_tls):
    _read, toolkit, _sessions, memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/checkout"))
    expiry = ref_of(before, '- textbox "Expiry (MM/YY)"')
    assert expiry in memory.get(USER).secret_refs  # type: ignore[union-attr]
    for ref in (expiry, ref_of(before, '- textbox "Card number"'), ref_of(before, '- textbox "CVC"')):
        refused(toolkit.precheck({"action": "fill", "ref": ref, "text": "12/28"}, user_id=USER), "secure_field")
    assert toolkit.precheck({"action": "fill", "ref": ref_of(before, '- textbox "Email"'), "text": "x"}, user_id=USER) is None


@pytest.mark.asyncio
async def test_page_changed_when_the_page_moved_between_the_card_and_the_run(kits, fakesite_tls, fakesite):
    _read, toolkit, _sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/post"))
    call = {"action": "click", "ref": ref_of(before, '- button "Sign up"')}
    card = toolkit.bind(call, user_id=USER)
    page = await live_page(kits)
    await page.goto(fakesite.url("/post"))  # another origin (the plain http site)
    result = await toolkit.execute("click", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "page_changed")
    assert page.url.endswith("/post") and "Thanks" not in await page.content()


@pytest.mark.asyncio
async def test_outline_changed_after_a_scroll(kits, fakesite_tls):
    _read, toolkit, _sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/flights"))
    call = {"action": "click", "ref": ref_of(before, '- link "10:40 AM')}
    card = toolkit.bind(call, user_id=USER)
    page = await live_page(kits)
    await page.mouse.wheel(0, 1_000_000)
    await page.wait_for_timeout(150)
    result = await toolkit.execute("click", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "outline_changed")
    assert page.url.endswith("/flights")


@pytest.mark.asyncio
async def test_insecure_page_on_http_and_the_same_act_over_tls(kits, fakesite_tls, fakesite):
    _read, toolkit, _sessions, _memory, _spy = kits
    plain = await read(kits, "open", url=fakesite.url("/post"))
    call = {"action": "fill", "ref": ref_of(plain, '- textbox "Email"'), "text": "me@example.com"}
    result = refused(toolkit.precheck(call, user_id=USER), "insecure_page")
    assert "http://" in result["error"]
    # and at run time, should a card somehow have been made
    card = toolkit.bind(call, user_id=USER)
    refused(
        await toolkit.execute("fill", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True),
        "insecure_page",
    )
    secure = await read(kits, "open", url=fakesite_tls.url("/post"))
    done = await act(kits, "fill", ref=ref_of(secure, '- textbox "Email"'), text="me@example.com")
    assert done["ok"] is True and done["did"] == 'Typed 14 characters into "Email"'


@pytest.mark.asyncio
async def test_an_act_on_a_challenge_page_needs_a_human(kits, fakesite_tls):
    _read, toolkit, _sessions, memory, _spy = kits
    await read(kits, "open", url=fakesite_tls.url("/post"))
    card = toolkit.bind({"action": "press", "key": "Enter"}, user_id=USER)
    page = await live_page(kits)
    await page.goto(fakesite_tls.url("/captcha"))
    result = await toolkit.execute("press", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    assert result["ok"] is False and result["needs_human"]["kind"] == "captcha"
    assert result["needs_human"]["user_image"].startswith("data:image/jpeg;base64,")
    # The page is the person's now, as after a browser.read handoff.
    state = guard.egress_state(page.context)
    assert state is not None and state.human_driving is True


@pytest.mark.asyncio
async def test_an_act_shuts_a_pending_handoffs_window_before_it_touches_the_page(kits, fakesite_tls):
    """An act is the agent's next action on the session: whichever
    toolkit handed the page to the person, the act takes it back, so a
    form submit from the agent's page is read-tier again afterwards."""
    _read, _toolkit, _sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/post"))
    page = await live_page(kits)
    state = guard.egress_state(page.context)
    assert state is not None
    state.human_driving = True  # a handoff is pending
    done = await act(kits, "fill", ref=ref_of(before, '- textbox "Email"'), text="me@example.com")
    assert done["ok"] is True and state.human_driving is False


@pytest.mark.asyncio
async def test_an_element_removed_after_the_card_changes_the_outline(kits, fakesite_tls):
    _read, toolkit, _sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/post"))
    ref = ref_of(before, '- textbox "Email"')
    card = toolkit.bind({"action": "fill", "ref": ref, "text": "x"}, user_id=USER)
    page = await live_page(kits)
    await page.evaluate("document.querySelector('input[name=email]').remove()")
    result = await toolkit.execute("fill", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "outline_changed")


@pytest.mark.asyncio
async def test_each_act_is_counted_and_the_text_never_reaches_a_summary(kits, fakesite_tls):
    _read, _act, sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/post"))
    await act(kits, "fill", ref=ref_of(before, '- textbox "Email"'), text="private-note@example.com")
    session = await sessions.get(USER, mode="account", task_id="t1")
    assert session.task.actions == 2
    assert "private-note" not in "\n".join(session.task.summaries)
    assert session.typed_secrets == []  # model text is not a secret


@pytest.mark.asyncio
async def test_a_typed_secret_is_redacted_from_did_and_summaries(kits, fakesite_tls):
    _read, _act, sessions, _memory, _spy = kits
    session = await sessions.get(USER, mode="account", task_id="t1")
    session.typed_secrets.append("s3cr3t-token")
    await read(kits, "open", url=fakesite_tls.url("/"))
    page = await live_page(kits)
    await page.set_content("<form><label>Code s3cr3t-token <input name=c></label></form>")
    before = await read(kits, "snapshot")
    ref = ref_of(before, "- textbox")
    result = await act(kits, "fill", ref=ref, text="abc")
    assert result["ok"] is True and "s3cr3t-token" not in json.dumps(result)
    assert "•••" in result["did"]


@pytest.mark.asyncio
async def test_press_keys_are_the_listed_ones_only(kits, fakesite_tls):
    _read, toolkit, _sessions, _memory, _spy = kits
    await read(kits, "open", url=fakesite_tls.url("/post"))
    for key in PRESS_KEYS:
        assert toolkit.precheck({"action": "press", "key": key}, user_id=USER) is None
    result = await act(kits, "press", key="Tab")
    assert result["ok"] is True and result["did"] == "Pressed Tab"


def test_the_card_hooks_never_touch_the_session():
    """precheck, bind and describe read the page memory only."""
    kit, sessions, memory = fake_kit()
    remember(memory)
    call = {"action": "click", "ref": "e8"}
    kit.precheck(call, user_id=USER)
    kit.bind(call, user_id=USER)
    kit.describe(call, user_id=USER)
    assert sessions.calls == []


@pytest.mark.asyncio
async def test_a_submit_through_a_field_of_a_saved_card_order_form_is_refused(kits, fakesite_tls):
    """The saved-card review page: no card field on it, one form whose
    only button says "Place order". ``browser.act submit`` names the
    form's plain field, not the button; what would send the form is its
    default button, and that is what is judged, before the card (the
    page memory kept the button's words for the field) and on the live
    page."""
    _read, toolkit, _sessions, memory, spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/cart-saved-note"))
    gift = ref_of(before, '- textbox "Gift note"')
    assert memory.get(USER).form_buttons[gift] == "Place order"
    call = {"action": "submit", "ref": gift}
    refused(toolkit.precheck(call, user_id=USER), "use_checkout")
    card = toolkit.bind(call, user_id=USER)
    result = await toolkit.execute("submit", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "use_checkout")
    assert not any(m == "POST" and p == "place-order" for m, p, _a in spy.seen), spy.seen


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/cart-saved-script", "/cart-saved-coupon"])
async def test_enter_on_a_focused_order_button_is_refused(kits, fakesite_tls, path):
    """Enter activates whatever has the focus: a script button outside
    any form, or the form's second submit button behind "Apply coupon".
    Tab, Tab, Enter would place the order through three cards that say
    nothing about paying; the Enter is judged by the focused button's
    own words and refused."""
    _read, toolkit, _sessions, _memory, spy = kits
    before = await read(kits, "open", url=fakesite_tls.url(path))
    page = await live_page(kits)
    cards: list[str] = []

    async def act_and_note(action, **params):
        call = {"action": action, **params}
        cards.append(toolkit.describe(toolkit.bind(call, user_id=USER), user_id=USER))
        return await act(kits, action, **params)

    filled = await act_and_note("fill", ref=ref_of(before, '- textbox "Gift note"'), text="thanks")
    assert filled["ok"] is True, filled
    for _ in range(3):
        if await page.evaluate("document.activeElement && document.activeElement.id === 'place'"):
            break
        tabbed = await act_and_note("press", key="Tab")
        assert tabbed["ok"] is True, tabbed
    assert await page.evaluate("document.activeElement.id") == "place"
    call = {"action": "press", "key": "Enter"}
    assert toolkit.precheck(call, user_id=USER) is None  # the focus is not in the page memory
    card = toolkit.bind(call, user_id=USER)
    result = await toolkit.execute("press", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "use_checkout")
    assert not any(m == "POST" and p == "place-order" for m, p, _a in spy.seen), (cards, spy.seen)
    assert "Review your order" in await page.content()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/cart-saved-confirm", "/cart-saved-plain"])
async def test_an_order_button_not_named_like_one_is_refused(kits, fakesite_tls, path):
    """The review page with the button many sites use: "Confirm". Not a
    purchase word, no card in the form: the form's target (/place-order)
    says what it does, and when the target says nothing either, the page
    does (an order total on screen next to the card on file). Refused on
    the live page, whatever the purchases switch says."""
    _read, toolkit, _sessions, _memory, spy = kits
    before = await read(kits, "open", url=fakesite_tls.url(path))
    call = {"action": "click", "ref": ref_of(before, '- button "Confirm"')}
    assert toolkit.precheck(call, user_id=USER) is None
    card = toolkit.bind(call, user_id=USER)
    result = await toolkit.execute("click", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "use_checkout")
    assert result["error"] == USE_CHECKOUT_MESSAGE
    assert not any(m == "POST" for m, _p, _a in spy.seen), spy.seen


@pytest.mark.asyncio
async def test_a_saved_card_order_button_is_refused_by_the_live_page(kits, fakesite_tls):
    """A cart with a payment method on file: no card field to protect, one
    button that places a $499 order. browser.act refuses it before the
    card (the outline's name) and again on the live page, so an order can
    never be placed outside browser.checkout, however the click is
    routed to it."""
    _read, toolkit, _sessions, _memory, spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/cart-saved"))
    ref = ref_of(before, '- button "Place order"')
    refused(toolkit.precheck({"action": "click", "ref": ref}, user_id=USER), "use_checkout")
    # A button whose visible words are harmless but whose name attribute
    # says what it does: the outline (and so the precheck) sees
    # "Continue", the live page's check reads the name too.
    page = await live_page(kits)
    await page.set_content(
        "<h1>Review your order</h1><p>Order total: $499.00</p>"
        "<form method='post' action='/place-order'><button type='submit' name='place-order'>Continue</button></form>"
    )
    plain = await read(kits, "snapshot")
    call = {"action": "click", "ref": ref_of(plain, '- button "Continue"')}
    assert toolkit.precheck(call, user_id=USER) is None
    card = toolkit.bind(call, user_id=USER)
    result = await toolkit.execute("click", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "use_checkout")
    assert result["error"] == USE_CHECKOUT_MESSAGE
    assert not any(method == "POST" for method, _p, _a in spy.seen)
    assert "Review your order" in await page.content()


@pytest.mark.asyncio
async def test_enter_and_submit_in_a_form_holding_a_card_are_refused(kits, fakesite_tls):
    """A card the owner typed by hand sits in the form: neither Enter in
    a field of that form nor a submit through one of its fields may send
    it; Enter in a form with no card still works."""
    _read, toolkit, _sessions, _memory, _spy = kits
    await read(kits, "open", url=fakesite_tls.url("/checkout"))
    page = await live_page(kits)
    await page.fill("input[name=cc-number]", "4242424242424242")
    await page.focus("input[name=email]")
    before = await read(kits, "snapshot")  # the card and the focus are on the page the acts are bound to
    email = ref_of(before, '- textbox "Email"')
    call = {"action": "press", "key": "Enter"}
    assert toolkit.precheck(call, user_id=USER) is None
    card = toolkit.bind(call, user_id=USER)
    refused(await toolkit.execute("press", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True), "use_checkout")
    call = {"action": "submit", "ref": email}
    card = toolkit.bind(call, user_id=USER)
    refused(await toolkit.execute("submit", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True), "use_checkout")
    assert page.url.endswith("/checkout")
    # With the card cleared, Enter in that form still places the order:
    # refused by the button's words. Enter in a form that pays nothing works.
    await page.fill("input[name=cc-number]", "")
    await read(kits, "snapshot")
    refused(await act(kits, "press", key="Enter"), "use_checkout")
    again = await read(kits, "open", url=fakesite_tls.url("/post"))
    await act(kits, "fill", ref=ref_of(again, '- textbox "Email"'), text="me@example.com")
    result = await act(kits, "press", key="Enter")
    assert result["ok"] is True and result["did"] == "Pressed Enter"


# ── routes around the order button (final review F1) ─────────────────────
# Money moves only through browser.checkout: an order must not leave the
# browser through a change the page sends by itself, a focus inside a
# frame or a shadow root, a clickable <div>, a button in another language
# or a link. ``fakesite_tls.handled`` is what the server answered, the
# proof that nothing reached it.

AUTO_SUBMIT = "That change tried to send the page. Crawler didn't let it."


async def attempt(kits, action, **params):
    """A browser.act call the way the runtime makes one, refusals
    included: a precheck refusal is the result (no card was made)."""
    toolkit = kits[1]
    call = {"action": action, **params}
    pre = toolkit.precheck(call, user_id=USER)
    if pre is not None:
        return pre
    card = toolkit.bind(call, user_id=USER)
    return await toolkit.execute(action, {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)


def sent(site, method: str, path: str) -> bool:
    return (method, path) in site.handled


@pytest.mark.parametrize(
    "path, action, prefix, extra, rule, error",
    [
        ("/cart-saved-radio", "check", '- radio "Use this card"', {}, "use_checkout", USE_CHECKOUT_MESSAGE),
        ("/cart-saved-select", "select", '- combobox "Payment"', {"value": "Card on file"}, "use_checkout", USE_CHECKOUT_MESSAGE),
        ("/cart-saved-autosubmit", "fill", '- textbox "Gift note"', {"text": "thanks"}, "auto_submit", AUTO_SUBMIT),
    ],
)
@pytest.mark.asyncio
async def test_a_change_whose_page_sends_the_order_places_nothing(kits, fakesite_tls, path, action, prefix, extra, rule, error):
    """A radio, a dropdown or a note field whose page script sends the
    order form the moment it changes. A choice on a page that holds a card
    and a price is refused before it is made; a fill is made, with the
    write window shut, so the form's POST is stopped by the guard and the
    act says so in one sentence."""
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await attempt(kits, action, ref=ref_of(before, prefix), **extra)
    refused(result, rule)
    assert result["error"] == error
    assert not sent(fakesite_tls, "POST", "/place-order"), fakesite_tls.handled


def test_a_choice_named_like_a_purchase_is_refused_before_the_card():
    kit, _sessions, memory = fake_kit()
    remember(memory, ['- radio "Pay with the card on file" [ref=e1]', '- combobox "Plan" [ref=e2]', *CHECKOUT_LINES[4:8]])
    refused(kit.precheck({"action": "check", "ref": "e1"}, user_id=USER), "use_checkout")
    refused(kit.precheck({"action": "select", "ref": "e2", "value": "Buy now"}, user_id=USER), "use_checkout")
    assert kit.precheck({"action": "select", "ref": "e5", "value": "Canada"}, user_id=USER) is None
    assert kit.precheck({"action": "check", "ref": "e6"}, user_id=USER) is None


@pytest.mark.asyncio
async def test_a_page_that_sends_itself_on_a_change_is_stopped_anywhere(kits, fakesite_tls):
    """No card on file, no price: a note field whose own script sends its
    form as it is typed into is still not a send the owner approved."""
    _read, _act, sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/note-autosubmit"))
    result = await attempt(kits, "fill", ref=ref_of(before, '- textbox "Note"'), text="hi")
    refused(result, "auto_submit")
    assert result["error"] == AUTO_SUBMIT
    assert not sent(fakesite_tls, "POST", "/post")
    context = (await sessions.get(USER, mode="account", task_id="t1")).context
    state = guard.egress_state(context)
    assert state.blocked[-1]["reason"] == guard.READ_TIER_POST
    assert state.write_allowed is False and state.changing is False


@pytest.mark.parametrize("path", ["/cart-saved-frame", "/cart-saved-shadow"])
@pytest.mark.asyncio
async def test_enter_with_the_focus_in_a_frame_or_a_shadow_root_is_judged_there(kits, fakesite_tls, path):
    """The order form inside a frame, or inside a shadow root, with the
    focus in its note field: the top document's focus is the <iframe> or
    the shadow host, so Enter is followed to the field itself and judged
    by its form's button, with the review page around it."""
    before = await read(kits, "open", url=fakesite_tls.url(path))
    filled = await attempt(kits, "fill", ref=ref_of(before, '- textbox "Gift note"'), text="thanks")
    assert filled["ok"] is True, filled
    page = await live_page(kits)
    assert await page.evaluate("document.activeElement.tagName.toLowerCase()") in ("iframe", "x-pay")
    result = await attempt(kits, "press", key="Enter")
    refused(result, "use_checkout")
    assert result["error"] == USE_CHECKOUT_MESSAGE
    assert not sent(fakesite_tls, "POST", "/place-order"), fakesite_tls.handled


@pytest.mark.asyncio
async def test_enter_in_an_ordinary_frame_still_sends_its_form(kits, fakesite_tls):
    before = await read(kits, "open", url=fakesite_tls.url("/frame"))
    filled = await attempt(kits, "fill", ref=ref_of(before, "- textbox"), text="x")
    assert filled["ok"] is True, filled
    pressed = await attempt(kits, "press", key="Enter")
    assert pressed["ok"] is True, pressed
    assert sent(fakesite_tls, "POST", "/inner")


@pytest.mark.asyncio
async def test_a_focused_frame_that_cannot_be_entered_refuses_enter():
    """Fail closed: Enter's focus is in a frame nobody can look into."""

    class Handle:
        def as_element(self):
            return None

        async def dispose(self):
            return None

    class Frame:
        async def evaluate(self, script):
            return {"frame": True}

        async def evaluate_handle(self, script):
            return Handle()

    class Page:
        main_frame = Frame()

    assert await BrowserActToolkit._enter_target(Page()) is None


@pytest.mark.parametrize(
    "path, prefix",
    [
        ("/cart-saved-frame-confirm", '- button "Confirm"'),  # a button in a frame, the card on the page
        ("/cart-saved-div", "- generic"),  # a <div> with a click handler
        ("/bestellung", '- button "Jetzt kaufen"'),  # a purchase word in German
        ("/bestellung", '- button "Weiter"'),  # any button next to "•••• 4242" and "23,40 €"
        ("/cart-saved-link", '- link "Confirm"'),  # a link to an order path
    ],
)
@pytest.mark.asyncio
async def test_clicks_the_old_rules_missed_are_refused(kits, fakesite_tls, path, prefix):
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await attempt(kits, "click", ref=ref_of(before, prefix))
    refused(result, "use_checkout")
    assert result["error"] == USE_CHECKOUT_MESSAGE
    posts = [p for m, p in fakesite_tls.handled if m == "POST"]
    assert posts == [], fakesite_tls.handled
    assert not sent(fakesite_tls, "GET", "/place-order-now")


@pytest.mark.asyncio
async def test_a_plain_link_on_a_saved_card_page_is_followed_without_a_write_window(kits, fakesite_tls):
    _read, _act, _sessions, _memory, spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/cart-saved-link"))
    result = await attempt(kits, "click", ref=ref_of(before, '- link "Keep shopping"'))
    assert result["ok"] is True and result["did"] == 'Clicked "Keep shopping"', result
    assert result["url"].endswith("/") and sent(fakesite_tls, "GET", "/")
    assert ("GET", "", False) in spy.seen  # the home page, loaded with the window shut


@pytest.mark.asyncio
async def test_ordinary_writes_still_work(kits, fakesite_tls):
    """No payment method on file: a search box and Enter, a product's
    "Add to cart" (a POST), a newsletter sign-up."""
    before = await read(kits, "open", url=fakesite_tls.url("/search-box"))
    await act(kits, "fill", ref=ref_of(before, '- textbox "Search"'), text="tickets")
    searched = await act(kits, "press", key="Enter")
    assert searched["ok"] is True and searched["did"] == "Pressed Enter", searched
    assert sent(fakesite_tls, "GET", "/")  # the search form's GET, the only way to the home page here
    product = await read(kits, "open", url=fakesite_tls.url("/product"))
    added = await act(kits, "click", ref=ref_of(product, '- button "Add to cart"'))
    assert added["ok"] is True and any("Thanks" in line for line in added["outline"]), added
    assert sent(fakesite_tls, "POST", "/cart/add")
    newsletter = await read(kits, "open", url=fakesite_tls.url("/post"))
    filled = await act(kits, "fill", ref=ref_of(newsletter, '- textbox "Email"'), text="me@example.com")
    assert filled["ok"] is True
    signed = await act(kits, "click", ref=ref_of(filled, '- button "Sign up"'))
    assert signed["ok"] is True and sent(fakesite_tls, "POST", "/post")


# ── routes around the purchase rules (round-9 review) ─────────────────────
# browser.read's click (no approval card at all) and open; a click judged
# by where it lands (a <label>, a wrapper, a closed shadow root); a submit
# sent through the button it was judged by; Enter on any focus, a hidden
# one included; a page script's fetch() during a fill; review pages the
# words and patterns did not read. Each page below placed an order before.

# A review page with an order total and no payment method in words: what
# is judged here is the control the act reaches, not the page.
TOTAL_LEAD = "<h1>Review your order</h1><p>Order total: $499.00</p>"
# The same page naming the card as one-click shops do.
DEFAULT_CARD_LEAD = "<h1>Review your order</h1><p>Charged to your default card.</p><p>Order total: $499.00</p>"
_PLACE_ORDER_JS = (
    "<script>function placeOrder(){const f=document.createElement('form');f.method='post';"
    "f.action='/place-order';document.body.appendChild(f);f.submit();}</script>"
)
_CLOSED_REVIEW = (
    "<script>customElements.define('x-review', class extends HTMLElement { constructor() { super(); "
    "const r = this.attachShadow({mode: 'closed'}); r.innerHTML = "
    "'<p>Paying with the card on file (Visa ending 4242).</p><p>Order total: $499.00</p>"
    "<form method=\"post\" action=\"/place-order\"><button type=\"submit\" style=\"width:100%;height:120px\">"
    "Place order</button></form>'; } });</script>"
)


@pytest.fixture
def page_at():
    """Serve a page on the fake site for one test: ``page_at(path, body)``."""
    added: list[str] = []

    def add(path: str, body: str, title: str = "Your cart") -> str:
        PAGES[path] = (200, "text/html", _page(title, body))
        added.append(path)
        return path

    yield add
    for path in added:
        PAGES.pop(path, None)


def posted(site) -> list[str]:
    return [path for method, path in site.handled if method == "POST"]


async def settled(kits, ms: int = 400) -> None:
    """A page script's fetch() runs after the click returns: give it time."""
    await (await live_page(kits)).wait_for_timeout(ms)


@pytest.mark.parametrize(
    "body, prefix, path",
    [
        # A script button (the ordinary single-page-app pattern) orders by fetch().
        (SAVED_CARD_LEAD + '<button type="button" onclick="fetch(\'/place-order\', {method: \'POST\'})">'
         "Complete purchase</button>", '- button "Complete purchase"', "/place-order"),
        # The same in German, with a path no rule knows.
        ("<h1>Bestellung prüfen</h1><p>Zahlungsart: Visa •••• 4242</p><p>Gesamtsumme: 23,40 €</p>"
         '<button type="button" onclick="fetch(\'/bestellung-absenden\', {method: \'POST\'})">Jetzt kaufen</button>',
         '- button "Jetzt kaufen"', "/bestellung-absenden"),
        # A button with any words on the review page.
        (SAVED_CARD_LEAD + '<button type="button" onclick="fetch(\'/next-step\', {method: \'POST\'})">Continue</button>',
         '- button "Continue"', "/next-step"),
    ],
)
@pytest.mark.asyncio
async def test_a_read_tier_click_that_may_order_is_left_to_browser_act(kits, fakesite_tls, page_at, body, prefix, path):
    """browser.read clicks with no approval card: a click browser.act
    would refuse, or any button on a review page, is refused before it is
    made, and nothing reaches the server."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-read-click", body)))
    result = await read(kits, "click", ref=ref_of(before, prefix))
    await settled(kits)
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert "may place an order" in result["consequential"]
    assert path not in posted(fakesite_tls), fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_read_never_opens_an_order_step_by_click_or_open(kits, fakesite_tls, page_at):
    """A link that places the order by GET: browser.read's click refuses
    it, and opening its address directly is stopped by the guard."""
    path = page_at("/r-link", SAVED_CARD_LEAD + '<a href="/place-order-now?token=abc">Continue</a>')
    before = await read(kits, "open", url=fakesite_tls.url(path))
    clicked = await read(kits, "click", ref=ref_of(before, '- link "Continue"'))
    assert clicked["ok"] is False and "may place an order" in clicked["consequential"], clicked
    opened = await read(kits, "open", url=fakesite_tls.url("/place-order-now?token=abc"))
    assert opened["ok"] is False and opened["error"].startswith("Refusing to open"), opened
    assert guard.READ_TIER_ORDER_STEP in opened["error"]
    assert not sent(fakesite_tls, "GET", "/place-order-now"), fakesite_tls.handled
    history = await read(kits, "open", url=fakesite_tls.url("/orders"))  # an order history is read (a 404 here)
    assert history["ok"] is True and sent(fakesite_tls, "GET", "/orders")


@pytest.mark.asyncio
async def test_a_read_tier_click_on_an_ordinary_button_still_works(kits, fakesite_tls, page_at):
    """A price alone (a product page) is not a review page: its buttons are
    clicked at read tier as before."""
    path = page_at("/r-product", '<h1>Socks</h1><p>Price: $5.00</p><button type="button" '
                   "onclick=\"document.getElementById('more').hidden = false\">Show more</button>"
                   '<p id="more" hidden>Wool, size M.</p>', "Socks")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "click", ref=ref_of(before, '- button "Show more"'))
    assert result["ok"] is True and any("Wool, size M." in line for line in result["outline"]), result


@pytest.mark.parametrize("lead", [TOTAL_LEAD, DEFAULT_CARD_LEAD])
@pytest.mark.parametrize(
    "body, prefix",
    [
        # A <label for> the order button: its click activates the button.
        ('<form method="post" action="/place-order"><button type="submit" id="po" '
         'style="position:absolute;left:-9999px">Place order</button></form>'
         '<label for="po" style="display:inline-block;padding:8px;cursor:pointer">Continue</label>', "- generic"),
        # A paragraph whose centre is the order form's button.
        ('<form method="post" action="/place-order"><p style="margin:0;padding:0">'
         '<button type="submit" style="width:100%;height:40px">Continue</button></p></form>', "- paragraph"),
    ],
)
@pytest.mark.asyncio
async def test_a_click_is_judged_by_the_control_it_lands_on(kits, fakesite_tls, page_at, lead, body, prefix):
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-landing", lead + body)))
    last = [line for line in before["outline"] if line.lstrip().startswith(prefix)][-1]  # the one around the button
    result = await attempt(kits, "click", ref=ref_of({"outline": [last]}, prefix))
    refused(result, "use_checkout")
    assert "/place-order" not in posted(fakesite_tls), fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_click_on_a_region_holding_a_closed_shadow_root_is_refused(kits, fakesite_tls, page_at):
    """The review page inside a closed shadow root: nobody can read what
    the click reaches, nor what the page shows, so the click is refused."""
    path = page_at("/r-closed-region", '<h1>Checkout</h1><section aria-label="Your order"><x-review></x-review>'
                   "</section>" + _CLOSED_REVIEW, "Checkout")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await attempt(kits, "click", ref=ref_of(before, '- region "Your order"'))
    refused(result, "use_checkout")
    assert posted(fakesite_tls) == [], fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_submit_through_a_field_goes_through_the_button_it_was_judged_by(kits, fakesite_tls, page_at):
    """A gift-card field before "Apply" and "Place order": the submit is
    judged by the form's default button ("Apply", to /cart/add) and sent
    through that same button, never through the form's own action."""
    path = page_at("/r-giftcard", TOTAL_LEAD + '<form method="post" action="/place-order"><label>Gift card code '
                   '<input name="gc"></label><button type="submit" formaction="/cart/add">Apply</button>'
                   '<button type="submit">Place order</button></form>')
    before = await read(kits, "open", url=fakesite_tls.url(path))
    refused(await attempt(kits, "click", ref=ref_of(before, '- button "Place order"')), "use_checkout")
    result = await attempt(kits, "submit", ref=ref_of(before, '- textbox "Gift card code"'))
    assert result["ok"] is True and result["did"] == 'Submitted the form with "Gift card code"', result
    assert posted(fakesite_tls) == ["/cart/add"], fakesite_tls.handled


@pytest.mark.asyncio
async def test_enter_in_a_field_is_judged_by_a_default_button_outside_its_form(kits, fakesite_tls, page_at):
    """The browser's default button is the form's first submit control in
    tree order, a form= button placed before the form included."""
    path = page_at("/r-formattr", TOTAL_LEAD + '<aside><button type="submit" form="cart" formaction="/place-order">'
                   'Place order</button></aside><form id="cart" method="post" action="/cart/add"><label>Quantity '
                   '<input name="qty" value="1"></label><button type="submit">Update</button></form>')
    before = await read(kits, "open", url=fakesite_tls.url(path))
    filled = await attempt(kits, "fill", ref=ref_of(before, '- textbox "Quantity"'), text="2")
    assert filled["ok"] is True, filled
    refused(await attempt(kits, "press", key="Enter"), "use_checkout")
    assert posted(fakesite_tls) == [], fakesite_tls.handled


@pytest.mark.parametrize(
    "body",
    [
        # A focusable <div> that orders on Enter: judged by its own words.
        '<div tabindex="0" style="cursor:pointer" onkeydown="if (event.key === \'Enter\') placeOrder()">Place order</div>'
        + _PLACE_ORDER_JS,
        # The whole review inside a closed shadow root: the focus is hidden.
        "<x-review></x-review>" + _CLOSED_REVIEW,
    ],
)
@pytest.mark.asyncio
async def test_tab_then_enter_on_a_focus_that_orders_is_refused(kits, fakesite_tls, page_at, body):
    await read(kits, "open", url=fakesite_tls.url(page_at("/r-focus", TOTAL_LEAD + body)))
    tab = await attempt(kits, "press", key="Tab")
    assert tab["ok"] is True, tab
    refused(await attempt(kits, "press", key="Enter"), "use_checkout")
    assert posted(fakesite_tls) == [], fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_fill_whose_page_orders_by_fetch_is_stopped(kits, fakesite_tls, page_at):
    """A field whose own script sends the order with fetch() as it is
    typed into: the request is stopped and the fill refused."""
    path = page_at("/r-fill-fetch", SAVED_CARD_LEAD + '<label>Gift note <input name="gift" '
                   "oninput=\"fetch('/place-order', {method: 'POST'})\"></label>")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await attempt(kits, "fill", ref=ref_of(before, '- textbox "Gift note"'), text="thanks")
    await settled(kits)
    refused(result, "auto_submit")
    assert result["error"] == AUTO_SUBMIT
    assert "/place-order" not in posted(fakesite_tls), fakesite_tls.handled


REVIEW_PAGES = {
    "dots": ("<h1>Review your order</h1><p>Card: Visa ...4242 (default)</p><p>Order total: $499.00</p>", "Continue"),
    "total-image": (
        "<h1>Review your order</h1><p>Paying with the card on file (Visa ending 4242).</p>"
        '<p>Order total: <img alt="" width="80" height="20" '
        'src="data:image/gif;base64,R0lGODlhAQABAAAAACwAAAAAAQABAAACAkQBADs="></p>',
        "Continue",
    ),
    "ru": ("<h1>Ваш заказ</h1><p>Карта •••• 4242</p><p>Итого: 1 234 ₽</p>", "Оплатить"),
    "ar-rtl": (
        '<div dir="rtl"><h1>مراجعة الطلب</h1><p>البطاقة المحفوظة •••• 4242</p><p>الإجمالي: 499 ر.س</p></div>',
        "ادفع الآن",
    ),
    "he-rtl": ('<div dir="rtl"><h1>סיכום הזמנה</h1><p>כרטיס •••• 4242</p><p>סה"כ לתשלום: ₪499</p></div>', "לתשלום"),
    "ja-yen": ("<h1>ご注文内容の確認</h1><p>お支払い方法: クレジットカード 末尾 4242</p><p>合計 1,234円</p>", "確定する"),
    "one-click-rent": ("<h1>The Movie (2026)</h1><p>Rent or buy in HD.</p>", "Rent HD $3.99"),
    "price-only": ("<h1>The App</h1><p>Productivity.</p>", "$0.99"),
}


@pytest.mark.parametrize("key", list(REVIEW_PAGES))
@pytest.mark.asyncio
async def test_review_pages_in_other_shapes_and_languages_are_refused(kits, fakesite_tls, page_at, key):
    """A card written with dots, a total shown as a picture, the rouble,
    riyal, shekel and yen, Russian, Arabic, Hebrew and Japanese order
    buttons (right to left included), and one-click buttons that are
    little more than a price."""
    lead, words = REVIEW_PAGES[key]
    path = page_at(f"/r-review-{key}", lead + f'<form method="post" action="/checkout/finalize">'
                   f'<button type="submit">{words}</button></form>', "Review")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    refused(await attempt(kits, "click", ref=ref_of(before, f'- button "{words}"')), "use_checkout")
    assert posted(fakesite_tls) == [], fakesite_tls.handled


# ── no order request without a card (final review, round 2) ──────────────
# A page's own script, a link or a key can place an order as well as a
# button can. browser.read has no card: its click sends nothing but GETs
# and follows no link to an order path, and nothing a read sets off (a
# page that orders on load or when scrolled to) and nothing a page sends
# while the person holds it after the model's handoff reaches an order
# address. browser.act runs only on the page its card showed, a key press
# included.

PRODUCT_LEAD = "<h1>Concert ticket</h1><p>Price: $19.00</p>"
ORDER_FETCH = "fetch('/orders', {method: 'POST', body: 'sku=1'})"
ICON = '<svg width="20" height="20"><circle cx="10" cy="10" r="8"/></svg>'


@pytest.mark.parametrize("label", [ICON, "Get it tomorrow", "1-Click", "Order again"])
@pytest.mark.asyncio
async def test_a_read_click_whose_script_orders_sends_nothing(kits, fakesite_tls, page_at, label):
    """A product page (a price, no total, no saved card, no wallet) whose
    button outside any form creates the order with POST /orders: the
    read click sends nothing, and the model is sent to browser.act."""
    path = page_at("/r2-product", PRODUCT_LEAD + f'<button type="button" onclick="{ORDER_FETCH}">{label}</button>',
                   "Concert ticket")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    ref = next(re.search(r"\[ref=((?:f\d+)?e\d+)\]", line).group(1) for line in before["outline"] if "button" in line)
    result = await read(kits, "click", ref=ref)
    await settled(kits, 800)
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert not sent(fakesite_tls, "POST", "/orders"), fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_read_click_whose_script_posts_anywhere_sends_nothing(kits, fakesite_tls, page_at):
    """While browser.read clicks, no page script sends anything but a GET,
    whatever its address: the click is left to browser.act and its card."""
    path = page_at("/r2-save", PRODUCT_LEAD + "<button type=\"button\" onclick=\"fetch('/api/cart/items', "
                   "{method: 'POST'})\">Save for later</button>", "Concert ticket")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "click", ref=ref_of(before, '- button "Save for later"'))
    await settled(kits)
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert result["consequential"] == guard.READ_CLICK_REQUEST
    assert not sent(fakesite_tls, "POST", "/api/cart/items"), fakesite_tls.handled
    state = guard.egress_state((await live_page(kits)).context)
    assert state is not None and state.read_click is False


@pytest.mark.asyncio
async def test_a_read_click_follows_no_link_to_an_order_path_but_reads_the_order_history(kits, fakesite_tls, page_at):
    """A plain link to /buy/1?qty=1 is an order address, not only an order
    step: the read click refuses it. A link to the order history is read."""
    path = page_at("/r2-link", PRODUCT_LEAD + "<a href='/buy/1?qty=1'>Get it now</a> <a href='/orders'>Your orders</a>",
                   "Concert ticket")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "click", ref=ref_of(before, '- link "Get it now"'))
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert not sent(fakesite_tls, "GET", "/buy/1"), fakesite_tls.handled
    history = await read(kits, "click", ref=ref_of(before, '- link "Your orders"'))
    assert history["ok"] is True and sent(fakesite_tls, "GET", "/orders"), history


@pytest.mark.asyncio
async def test_a_read_click_whose_script_opens_an_order_path_is_stopped(kits, fakesite_tls, page_at):
    """A script button that moves the page to /buy/1 by GET: the guard
    stops it while the read click runs."""
    path = page_at("/r2-go", PRODUCT_LEAD + "<button type=\"button\" onclick=\"location.href = '/buy/1'\">Go</button>",
                   "Concert ticket")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "click", ref=ref_of(before, '- button "Go"'))
    await settled(kits)
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert result["consequential"] == guard.READ_CLICK_ADDRESS
    assert not sent(fakesite_tls, "GET", "/buy/1"), fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_page_that_orders_when_scrolled_to_sends_nothing(kits, fakesite_tls, page_at):
    path = page_at(
        "/r2-scroll",
        "<h1>Deals</h1><div style='height:3000px'>x</div><div id='s'>end</div>"
        "<script>new IntersectionObserver(e => { if (e[0].isIntersecting) "
        f"{ORDER_FETCH}; }}).observe(document.getElementById('s'));</script>",
        "Deals",
    )
    await read(kits, "open", url=fakesite_tls.url(path))
    await read(kits, "scroll", direction="bottom")
    await settled(kits, 800)
    assert not sent(fakesite_tls, "POST", "/orders"), fakesite_tls.handled
    state = guard.egress_state((await live_page(kits)).context)
    assert state is not None and state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_REQUEST


@pytest.mark.asyncio
async def test_a_page_that_orders_on_load_sends_nothing(kits, fakesite_tls, page_at):
    path = page_at("/r2-onload", f"<h1>Deals</h1><script>addEventListener('load', () => {ORDER_FETCH});</script>",
                   "Deals")
    await read(kits, "open", url=fakesite_tls.url(path))
    await settled(kits, 800)
    assert not sent(fakesite_tls, "POST", "/orders"), fakesite_tls.handled


@pytest.mark.parametrize(
    "script, method",
    [
        ("document.getElementById('f').submit()", "POST"),
        ("location.href = '/place-order?one=1'", "GET"),
    ],
)
@pytest.mark.asyncio
async def test_the_models_handoff_opens_no_order_address(kits, fakesite_tls, page_at, script, method):
    """The model asks for a handoff on a page whose script sends the order
    a moment later: the person may sign in while they hold the page, but
    nothing reaches an order address."""
    path = page_at(
        "/r2-handoff",
        PRODUCT_LEAD + "<form id='f' method='post' action='/place-order'><input type='hidden' name='x' value='1'></form>"
        f"<script>setTimeout(() => {{ {script}; }}, 1500);</script>",
    )
    await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "handoff", reason="Please check the page")
    assert result.get("needs_human"), result
    state = guard.egress_state((await live_page(kits)).context)
    assert state is not None and state.human_driving is True and state.checkout_handoff is False
    await settled(kits, 2500)
    assert not sent(fakesite_tls, method, "/place-order"), fakesite_tls.handled
    assert state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_STEP


@pytest.mark.asyncio
async def test_an_enter_card_runs_only_on_the_page_it_showed(kits, fakesite_tls, page_at):
    """A press(Enter) card made on a search page that moves itself, a
    moment later, to a page whose focused button orders: the approved
    Enter is refused there, and nothing is sent."""
    page_at("/r2-enter-b", PRODUCT_LEAD + f'<button autofocus onclick="{ORDER_FETCH}">Continue</button>', "Ticket")
    path = page_at("/r2-enter-a", "<h1>Search</h1><input aria-label='Search' autofocus>"
                   "<script>setTimeout(() => { location.href = '/r2-enter-b'; }, 1200);</script>", "Search")
    await read(kits, "open", url=fakesite_tls.url(path))
    toolkit = kits[1]
    call = {"action": "press", "key": "Enter"}
    assert toolkit.precheck(call, user_id=USER) is None
    card = await toolkit.bind_async(call, user_id=USER, task_id="t1")
    await settled(kits, 2500)
    assert (await live_page(kits)).url.endswith("/r2-enter-b")
    result = await toolkit.execute(
        "press", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True
    )
    await settled(kits)
    refused(result, "outline_changed")
    assert not sent(fakesite_tls, "POST", "/orders"), fakesite_tls.handled


@pytest.mark.asyncio
async def test_an_enter_card_on_the_same_page_still_runs(kits, fakesite_tls, page_at):
    path = page_at("/r2-search", "<h1>Search</h1><form action='/search'><input aria-label='Query' name='q' "
                   "autofocus></form>", "Search")
    await read(kits, "open", url=fakesite_tls.url(path))
    toolkit = kits[1]
    card = await toolkit.bind_async({"action": "press", "key": "Enter"}, user_id=USER, task_id="t1")
    result = await toolkit.execute(
        "press", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True
    )
    assert result["ok"] is True and result["did"] == "Pressed Enter", result


# ── every window is its page's (final review, round 3) ───────────────────
# Approving a step on one tab opens nothing for another; opening an order
# step by GET is stopped for a page's own request as for a navigation; a
# read click's window stays open while its script keeps the network busy.


@pytest.mark.asyncio
async def test_an_approved_act_opens_nothing_for_another_tab(kits, fakesite_tls, page_at):
    """The owner approves "Add to cart" on the product page (the card's
    picture). Another tab of the same session, never on any card, keeps
    trying POST /place-order: it is stopped before, during and after the
    act, and the act's own POST goes through."""
    page_at("/r3-saved", "<h1>Saved for later</h1><script>setInterval(() => fetch('/place-order', "
            "{method: 'POST', body: 'sku=9'}).catch(() => {}), 25);</script>", "Saved for later")
    path = page_at("/r3-list", PRODUCT_LEAD + "<a href='/r3-saved' target='_blank'>Saved for later</a>",
                   "Concert ticket")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    await read(kits, "click", ref=ref_of(before, '- link "Saved for later"'))
    await settled(kits, 600)
    session = await kits[2].get(USER, mode="account", task_id="t1")
    assert len(session.context.pages) == 2, "the link did not open a second tab"
    product = await read(kits, "open", url=fakesite_tls.url("/product"))
    toolkit = kits[1]
    call = {"action": "click", "ref": ref_of(product, '- button "Add to cart"')}
    assert toolkit.precheck(call, user_id=USER) is None
    card = await toolkit.bind_async(call, user_id=USER, task_id="t1")
    done = await toolkit.execute(
        "click", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True
    )
    await settled(kits, 300)
    assert done["ok"] is True and sent(fakesite_tls, "POST", "/cart/add"), done
    assert not sent(fakesite_tls, "POST", "/place-order"), fakesite_tls.handled
    state = guard.egress_state(session.context)
    assert state is not None and state.write_allowed is False and state.write_page is None


@pytest.mark.parametrize("script", ["new Image().src = '/place-order?sku=1'", "fetch('/checkout/complete?sku=1')"])
@pytest.mark.asyncio
async def test_a_read_click_whose_script_opens_an_order_step_by_get_sends_nothing(kits, fakesite_tls, page_at, script):
    """A GET to /place-order can be the order: a click's image or GET
    fetch to an order step is stopped like a navigation there, and the
    click is left to browser.act."""
    path = page_at("/r3-get", PRODUCT_LEAD + f'<button type="button" onclick="{script}">Show more</button>',
                   "Concert ticket")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "click", ref=ref_of(before, '- button "Show more"'))
    await settled(kits, 600)
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert not sent(fakesite_tls, "GET", "/place-order") and not sent(fakesite_tls, "GET", "/checkout/complete"), (
        fakesite_tls.handled
    )


@pytest.mark.asyncio
async def test_a_page_whose_image_opens_an_order_step_on_load_sends_nothing(kits, fakesite_tls, page_at):
    path = page_at("/r3-pixel", "<h1>Deals</h1><img src='/place-order?sku=1' alt=''>", "Deals")
    await read(kits, "open", url=fakesite_tls.url(path))
    await settled(kits, 400)
    assert not sent(fakesite_tls, "GET", "/place-order"), fakesite_tls.handled
    state = guard.egress_state((await live_page(kits)).context)
    assert state is not None and state.blocked[-1]["reason"] == guard.READ_TIER_ORDER_STEP


@pytest.mark.asyncio
async def test_a_read_click_window_stays_open_while_its_script_keeps_the_network_busy(kits, fakesite_tls, page_at):
    """A click whose script fetches eight times, 100 ms apart, then sends a
    POST: the window stays open until the network has been quiet for
    250 ms, so the POST is stopped and the click left to browser.act."""
    page_at("/r3-more-data", "<p>more</p>", "More")
    chain = ("(async () => { for (let i = 0; i < 8; i++) { await fetch('/r3-more-data'); "
             "await new Promise(r => setTimeout(r, 100)); } "
             "await fetch('/api/cart/items', {method: 'POST'}); })()")
    path = page_at("/r3-busy", PRODUCT_LEAD + f'<button type="button" onclick="{chain}">Show more</button>',
                   "Concert ticket")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    result = await read(kits, "click", ref=ref_of(before, '- button "Show more"'))
    await settled(kits, 600)
    assert sent(fakesite_tls, "GET", "/r3-more-data"), fakesite_tls.handled
    assert not sent(fakesite_tls, "POST", "/api/cart/items"), fakesite_tls.handled
    assert result["ok"] is False and result["consequential"] == guard.READ_CLICK_REQUEST, result


# ── the tab that started a navigation (final review, round 6)
# Inside a write window only the approved page may point its own tab
# anywhere: another site's tab that holds it may not.


@pytest.fixture
def slow_at():
    """``slow_at(path, seconds)`` makes a GET of *path* wait that long."""
    slowed: list[str] = []

    def slow(path: str, seconds: float) -> None:
        DELAYS[path] = seconds
        slowed.append(path)

    yield slow
    for path in slowed:
        DELAYS.pop(path, None)


@pytest.mark.parametrize("through", [False, True])
@pytest.mark.asyncio
async def test_another_sites_tab_cannot_point_the_approved_tab_at_an_order_step(
    kits, fakesite_tls, page_at, slow_at, through
):
    """A tab of another site (localhost here, the shop is 127.0.0.1) opened
    the shop with window.open and keeps its handle. When the owner's
    approved "Add to cart" lands, it points the shop's tab at an order
    step, directly or *through* a page of its own that opens the step as
    the tab's own document. The navigation is the approved tab's, but the
    other site started it, so it is stopped inside the window; the result
    page's slow script keeps the window open long enough for that to be
    certain."""
    order = fakesite_tls.url("/place-order?sku=expensive")
    page_at("/r6-bounce", f"<h1>One moment</h1><script>location.href = '{order}';</script>", "Deals")
    if through:
        order = fakesite_tls.url("/r6-bounce").replace("127.0.0.1", "localhost")
    slow_at("/r6-slow.js", 1.5)
    PAGES["/r6-slow.js"] = (200, "text/javascript", "window.slow = true;")
    page_at("/r6-added", "<h1>Added to cart</h1><script src='/r6-slow.js'></script>", "Cart")
    page_at(
        "/r6-deals-tab",
        "<h1>Deals</h1><script>const w = window.open('" + fakesite_tls.url("/r6-ticket") + "');"
        "let armed = false, done = false; setInterval(() => { try { const n = w.length;"
        "if (n === 2) armed = true; else if (armed && !done) { done = true; w.location.href = '"
        + order + "'; } } catch (e) {} }, 1);</script>",
        "Deals",
    )
    page_at(
        "/r6-ticket",
        PRODUCT_LEAD + "<iframe srcdoc='<p>video</p>'></iframe><iframe srcdoc='<p>map</p>'></iframe>"
        "<form method='get' action='/r6-added'><label>Quantity <input name='qty' value='1'></label>"
        "<button type='submit'>Add to cart</button></form>",
        "Concert ticket",
    )
    try:
        opened = await read(kits, "open", url=fakesite_tls.url("/r6-deals-tab").replace("127.0.0.1", "localhost"))
        assert opened["ok"] is True, opened
        await settled(kits, 600)
        session = await kits[2].get(USER, mode="account", task_id="t1")
        assert [p.url for p in session.context.pages][1].endswith("/r6-ticket"), session.context.pages
        await read(kits, "switch", index=1)
        ticket = await read(kits, "snapshot")
        toolkit = kits[1]
        call = {"action": "click", "ref": ref_of(ticket, '- button "Add to cart"')}
        assert toolkit.precheck(call, user_id=USER) is None
        card = await toolkit.bind_async(call, user_id=USER, task_id="t1")
        await toolkit.execute(
            "click", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True
        )
        await settled(kits, 800)
        assert sent(fakesite_tls, "GET", "/r6-added"), "control: the approved click did not send"
        assert not sent(fakesite_tls, "GET", "/place-order"), fakesite_tls.handled
        state = guard.egress_state(session.context)
        assert state is not None and any(e["reason"] == guard.OTHER_PAGE_NAVIGATION for e in state.blocked), state.blocked
    finally:
        PAGES.pop("/r6-slow.js", None)
