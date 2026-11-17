"""browser.act and the page memory: against fakes (no browser) and, further
down, against the fake site over TLS in headless Chromium (skipped when
Playwright's Chromium is not installed). Never a real website, never a
headed window, never a real card.

Also here: a step that only looks like paying is no dead end (a plain
link is followed whatever it says, purchase words refuse an act only
where money can move, and the live page's refusal comes instead of a
card); the sentence for the person on every refusal (``reason``); which
acts the live page calls quiet (what a site approval may run with no
card); which are errand steps (what may run with no card while "Ask
before every website step" is off), judged by the words a person reads,
on Amazon's and Shopify's own markup shapes too, and what an errand step
run unasked may still send (only to a cart or its own cart or cookie form,
never on through a redirect toward an order, and nothing a page saves a
moment later); and an approved act that opens a new tab going on in that
tab."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

from services.agent.app_approvals import errand_covers, unasked_arguments
from services.tools.browser import _shared, guard, handoff
from services.tools.browser import act as act_module
from services.tools.browser import snapshot as snap
from services.tools.browser.act import (
    ACT_ACTIONS,
    CARD_KEY,
    MAX_FIELD_CHARS,
    MAX_FORM_FIELDS,
    MAY_ORDER_NOTE,
    PRESS_KEYS,
    BrowserActToolkit,
)
from services.tools.browser.actions import BROWSER_MAX_ACTIONS, BrowserReadToolkit
from services.tools.browser.checkout import facts as checkout_facts
from services.tools.browser.checkout import markers
from services.tools.browser.checkout.markers import READ_CLICK_MESSAGE, USE_CHECKOUT_MESSAGE
from services.tools.browser.pagememory import (
    LastPage,
    PageMemory,
    outline_digest,
    page_address,
    page_origin,
)
from services.tools.browser.session import BrowserSessionManager
from services.tools.system import browser_installed
from tests.conftest import tls_launcher
from tests.fakesite import _Handler
from tests.fakesite.pages import DELAYS, PAGES, REDIRECTS, SAVED_CARD_LEAD, SR, _page
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


# What a sentence the person reads never holds (docs/bot-message-style.md):
# a tool's id, a dash, a snake_case or internal word, an uncontracted verb.
_NOT_PLAIN_RE = re.compile(
    r"browser\.|tools\.|desktop\.|[—–_{}]"
    r"|\b(?:tool|token|session|digest|payload|arguments?|policy|model|ref|outline|snapshot|invalid"
    r"|do not|did not|does not|is not|cannot|will not|could not|I will|I am|Crawler)\b",
    re.I,
)


def plain(reason):
    """*reason* is one or two sentences the person can read as they are."""
    assert isinstance(reason, str) and reason.strip() and reason.endswith("."), reason
    assert not _NOT_PLAIN_RE.search(reason), reason
    assert reason.count(". ") <= 1, reason
    return reason


def refused(result, rule):
    """A rule's refusal: the rule, the sentence the model reads (it may
    name the tool to call next) and the one the person reads (it never
    does). Every refusal these tests look at passes through here."""
    assert result["ok"] is False and result["refused"] is True, result
    assert result["rule"] == rule, result
    assert result["error"]
    plain(result["reason"])
    return result


# ── page memory ──────────────────────────────────────────────────────────


def test_outline_digest_is_of_the_structure_not_of_text_or_state():
    """What an approved click, fill or choice is tied to: the lines that
    carry a ref, as they stand without their inline value and without the
    markers that only say what state an element is in. A countdown, a
    typed value, a ticked box, an opened menu or a moved focus is the same
    page; a ref that came, went, moved or was renamed is not. One digest,
    shared with the checkout card."""
    lines = [
        '- heading "Tickets" [level=1] [ref=e1]',
        "- text: Cart expires in 9:59",
        "- paragraph [ref=e2]: 2 seats left",
        '- textbox "Email" [active] [ref=e3]: me@example.com',
        '- checkbox "Send me news" [checked] [ref=e4]',
        '- button "Menu" [expanded] [ref=e5] [cursor=pointer]',
        '- tab "Evening" [selected] [ref=e6]',
        '- button "Mute" [pressed] [ref=e7]',
        '- button "Add to cart" [disabled] [ref=e8]',
        '- combobox "Seats" [ref=e9]:',
        '  - option "2" [selected]',
    ]
    calm = [
        '- heading "Tickets" [level=1] [ref=e1]',
        "- text: Cart expires in 9:58",
        "- paragraph [ref=e2]: 1 seat left",
        '- textbox "Email" [ref=e3]',
        '- checkbox "Send me news" [ref=e4]',
        '- button "Menu" [ref=e5] [cursor=pointer]',
        '- tab "Evening" [ref=e6]',
        '- button "Mute" [pressed=mixed] [ref=e7]',
        '- button "Add to cart" [active] [ref=e8]',
        '- combobox "Seats" [ref=e9]:',
        '  - option "3" [selected]',
    ]
    digest = outline_digest(lines)
    assert len(digest) == 40 and outline_digest(calm) == digest
    assert outline_digest(lines[:-3]) != digest  # a ref line went
    assert outline_digest([*lines, '- link "Remove" [ref=e10]']) != digest  # one came
    assert outline_digest([line.replace("e8", "e11") for line in lines]) != digest  # another element
    assert outline_digest([line.replace("Add to cart", "Place order") for line in lines]) != digest
    assert outline_digest([line.replace("[level=1]", "[level=2]") for line in lines]) != digest
    assert checkout_facts.outline_digest is outline_digest


def test_a_key_press_is_tied_to_the_focus_as_well():
    """Enter acts on whatever has the focus, so the digest an approved key
    press is tied to keeps the focus marker: the same structure with the
    focus elsewhere is another page to it, while text and state still do
    not count."""
    focused = [line.replace('"Email" [ref', '"Email" [active] [ref') for line in CHECKOUT_LINES]
    moved = [line.replace('"Name" [ref', '"Name" [active] [ref') for line in CHECKOUT_LINES]
    assert outline_digest(focused) == outline_digest(moved) == outline_digest(CHECKOUT_LINES)
    key = outline_digest(focused, focus=True)
    assert len(key) == 40 and key != outline_digest(moved, focus=True)
    assert key != outline_digest(CHECKOUT_LINES, focus=True)
    typed = [line.replace('[active] [ref=e2]', '[active] [ref=e2]: me@example.com') for line in focused]
    ticked = [line.replace('"Gift wrap" [ref', '"Gift wrap" [checked] [ref') for line in typed]
    assert outline_digest(ticked, focus=True) == key


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
    assert page.focus_digest == outline_digest(CHECKOUT_LINES, focus=True)
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
def test_precheck_refuses_a_submit_on_a_button_that_pays_and_leaves_a_click_to_the_live_page(name):
    """Whatever the purchases switch says: a submit sends a form, and
    sending one through a button that pays is browser.checkout's job. A
    click is not refused on the outline's name alone: the name cannot say
    whether money moves ("Buy tickets" may only open the next page), so
    the live page is judged when the card would be made."""
    kit, _sessions, memory = fake_kit()
    remember(memory, [f'- button "{name}" [ref=e1]', '- link "Continue" [ref=e2]'])
    result = refused(kit.precheck({"action": "submit", "ref": "e1"}, user_id=USER), "use_checkout")
    assert result["error"] == USE_CHECKOUT_MESSAGE
    assert kit.precheck({"action": "click", "ref": "e1"}, user_id=USER) is None
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
            # The control's own name on that page: what a click stays tied to.
            "ref_name": page.names["e8"],
        },
    }
    # The address is a digest: the card never keeps the URL's query string.
    assert page_address("https://shop.example.com/checkout?sid=1#x") == page_address(
        "https://shop.example.com/checkout?sid=1"
    ) != page_address("https://shop.example.com/checkout")


def test_bind_ties_a_key_press_to_the_focus_and_any_other_act_to_the_structure():
    kit, _sessions, memory = fake_kit()
    page = remember(memory, ['- textbox "Search" [active] [ref=e1]', '- button "Go" [ref=e2]'])
    assert page.focus_digest != page.outline_digest
    for call in ({"action": "press", "key": "Enter"}, {"action": "press", "key": "Tab"}):
        assert kit.bind(call, user_id=USER)[CARD_KEY]["outline"] == page.focus_digest
    for call in ({"action": "click", "ref": "e2"}, {"action": "fill", "ref": "e1", "text": "x"}):
        assert kit.bind(call, user_id=USER)[CARD_KEY]["outline"] == page.outline_digest


def test_describe_builds_the_sentence_from_the_page_not_the_model():
    kit, _sessions, memory = fake_kit()
    remember(memory)
    d = lambda **params: kit.describe(params, user_id=USER)  # noqa: E731
    assert d(action="fill", ref="e2", text="me@example.com") == 'Type 14 characters into "Email" on shop.example.com'
    assert d(action="fill", ref="e2", text="a") == 'Type 1 character into "Email" on shop.example.com'
    assert d(action="fill", ref="e2", text="") == 'Clear "Email" on shop.example.com'
    assert d(action="fill", ref="e9", text="abc") == "Type 3 characters into an unnamed control on shop.example.com"
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
    assert kit.describe(card, user_id=USER) == "Click an unnamed control on shop.example.com"
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


def checkout_log(logs) -> dict:
    """The one line a use_checkout refusal logs, checked to hold nothing
    but the action, the rule names and booleans."""
    [line] = [entry for entry in logs if entry["event"] == "browser_act_use_checkout"]
    assert line["rule"] == "use_checkout" and line["action"] in ACT_ACTIONS, line
    facts = {k: v for k, v in line.items() if k not in ("event", "log_level", "action", "rule", "why")}
    assert {"judged", "purchase_words", "plain_link", "sends", "order_total", "saved_payment"} <= set(facts), line
    assert all(isinstance(value, bool) for value in facts.values()), line
    return line


def test_a_use_checkout_refusal_before_the_card_logs_the_rule_never_the_words():
    """Which rule refused, and what was judged, as booleans: enough to
    trace a refusal the owner asks about, with nothing of the page in it."""
    from structlog.testing import capture_logs

    kit, _sessions, memory = fake_kit()
    remember(memory, ['- button "Place order" [ref=e1]'])
    with capture_logs() as logs:
        refused(kit.precheck({"action": "submit", "ref": "e1"}, user_id=USER), "use_checkout")
    line = checkout_log(logs)
    assert line["why"] == "purchase_words" and line["judged"] is False and line["purchase_words"] is True
    assert "Place order" not in repr(logs)


# ── a sentence for the person on every refusal ───────────────────────────


def test_every_refusal_carries_a_sentence_for_the_person_that_names_no_tool():
    """A refusal's "error" is written for the model and may name the tool
    to call next. The runtime copied it into what the owner sees ("I
    didn't click on the page. ... call browser.checkout ..."), so tool ids
    reached the owner. Each refusal now carries "reason" too: one or two
    plain sentences saying why the step wasn't done and what happens
    next. The model's sentence stays as it was."""
    import inspect

    for reason in act_module._REASONS.values():
        plain(reason)
    assert act_module._REASONS["use_checkout"] == markers.USE_CHECKOUT_REASON == (
        "That step pays or places an order. I only pay through my payment step, where you "
        "approve the amount first."
    )
    # Every rule the toolkit refuses under has its own sentence, and a
    # rule nobody wrote one for still gets a plain one.
    raised = set(re.findall(r'_Refused\(\s*"(\w+)"', inspect.getsource(act_module)))
    assert raised and raised <= set(act_module._REASONS), raised - set(act_module._REASONS)
    plain(act_module._Refused("some_new_rule", "x").result()["reason"])
    # Before the card, rule by rule.
    kit, _sessions, memory = fake_kit()
    refused(kit.precheck({"action": "click", "ref": "e1"}, user_id=USER), "needs_observe")
    remember(memory)
    for call, rule in [
        ({"action": "wave"}, "invalid_arguments"),
        ({"action": "click", "ref": "e99"}, "stale_ref"),
        ({"action": "fill", "ref": "e7", "text": "12/30"}, "secure_field"),
        ({"action": "submit", "ref": "e8"}, "use_checkout"),
    ]:
        result = refused(kit.precheck(call, user_id=USER), rule)
        assert result["reason"] == act_module._REASONS[rule] != result["error"], rule
    assert kit.precheck({"action": "submit", "ref": "e8"}, user_id=USER)["error"] == USE_CHECKOUT_MESSAGE
    remember(memory, url="http://shop.example.com/checkout")
    refused(kit.precheck({"action": "click", "ref": "e11"}, user_id=USER), "insecure_page")
    stopped, _stopped_sessions, stopped_memory = fake_kit(cancelled=True)
    remember(stopped_memory)
    refused(stopped.precheck({"action": "click", "ref": "e11"}, user_id=USER), "cancelled")


# ── what a site approval may run with no card (``_page.quiet``) ──────────
# The owner can allow clicks on a site for an hour. Nobody looks at the
# acts that then run, so which ones count is the toolkit's word about the
# live page (``quiet``), never the model's.

# One frame's facts on a page that shows prices and nothing to pay with.
QUIET_FRAME = {"order_total": False, "saved_payment": False, "wallet": False, "money": True}
# A seat on a seat map, as the live page judges a click on it.
SEAT = {
    "name": "Seat F7", "sends": False, "submits": False, "buttonish": True, "in_form": False,
    "card_in_form": False, "link": False, "plain_link": False, "href": "", "action": "",
}
PLAIN = {**SEAT, "name": "All showtimes", "buttonish": False, "link": True, "plain_link": True, "href": "/showtimes"}
CLICK = {"action": "click", "ref": "e1"}
SELECT = {"action": "select", "ref": "e1", "value": "2"}
CHECK = {"action": "check", "ref": "e1"}


def without(target, key):
    return {k: v for k, v in target.items() if k != key}


@pytest.mark.parametrize(
    "call, judged, quiet",
    [
        (CLICK, SEAT, True),
        # A script button inside a form can send it, and only a native
        # submit says so: it keeps its card. A plain link in a form does not.
        (CLICK, {**SEAT, "name": "Next", "in_form": True}, False),
        (CLICK, without(SEAT, "in_form"), False),
        (CLICK, {**PLAIN, "in_form": True}, True),
        (CLICK, PLAIN, True),
        (CLICK, {**PLAIN, "name": ""}, True),  # a poster with no words: a link, followed by GET
        (SELECT, {"name": "Seats | 2"}, True),
        (CHECK, {"name": "Send me news"}, True),
        *[({"action": "press", "key": key}, None, True) for key in ("Tab", "Escape", "ArrowDown", "ArrowUp")],
        # A control that sends a form, by POST or (its own submit button) by GET.
        (CLICK, {**SEAT, "sends": True}, False),
        (CLICK, {**SEAT, "name": "Search", "submits": True}, False),
        # Words that read as a purchase, a wallet or a price, on a link too.
        (CLICK, {**SEAT, "name": "Buy tickets"}, False),
        (CLICK, {**PLAIN, "name": "Buy tickets for 7:15 PM showtime"}, False),
        (CLICK, {**SEAT, "name": "PayPal"}, False),
        (CLICK, {**SEAT, "name": "$4.99"}, False),
        (SELECT, {"name": "Tickets | 2 seats $30.00"}, False),
        # Aimed at an order path, or next to a typed card.
        (CLICK, {**PLAIN, "href": "/buy"}, False),
        (CLICK, {**SEAT, "action": "/place-order"}, False),
        (CLICK, {**SEAT, "card_in_form": True}, False),
        # Nothing to judge by: a button with no words, a fact that is missing, no answer.
        (CLICK, {**SEAT, "name": ""}, False),
        (CLICK, without(SEAT, "name"), False),
        (CLICK, without(SEAT, "sends"), False),
        (CLICK, without(SEAT, "submits"), False),
        (CLICK, None, False),
        (CHECK, {"name": ""}, False),
        (CHECK, None, False),
        # Typing, a submit and Enter always keep their card.
        ({"action": "press", "key": "Enter"}, SEAT, False),
        ({"action": "submit", "ref": "e1"}, SEAT, False),
        ({"action": "fill", "ref": "e1", "text": "x"}, None, False),
        ({"action": "fill_form", "fields": [{"ref": "e1", "text": "x"}]}, None, False),
    ],
)
def test_only_an_act_that_clicks_around_is_quiet(call, judged, quiet):
    """A click, a choice or a key that only moves, on a target that sends
    no form and whose words are no purchase, wallet or price. Anything
    missing counts against it."""
    assert act_module._quiet(act_module._parse(call), "https", judged, [QUIET_FRAME], None) is quiet


@pytest.mark.parametrize(
    "scheme, answers, money",
    [
        ("http", [QUIET_FRAME], None),
        ("https", [QUIET_FRAME], {"unread": False}),  # the card warns about money: a person looks at it
        ("https", [{**QUIET_FRAME, "order_total": True}], None),
        ("https", [QUIET_FRAME, {**QUIET_FRAME, "saved_payment": True}], None),  # any frame counts
        ("https", [{**QUIET_FRAME, "wallet": True}], None),
        ("https", [{**QUIET_FRAME, "unread": True}], None),
        ("https", [QUIET_FRAME, None], None),  # a frame that could not be asked
        ("https", [{}], None),
        ("https", [], None),
    ],
)
def test_nothing_is_quiet_on_a_page_that_shows_a_way_to_pay_or_cannot_be_read(scheme, answers, money):
    for call, judged in ((CLICK, SEAT), ({"action": "press", "key": "Tab"}, None)):
        request = act_module._parse(call)
        assert act_module._quiet(request, "https", judged, [QUIET_FRAME], None) is True  # control
        assert act_module._quiet(request, scheme, judged, answers, money) is False


@pytest.mark.asyncio
async def test_a_page_the_call_brings_itself_can_never_make_it_quiet():
    """``_page`` is the card's: a call that carries one is refused before
    any card, the bind replaces it, and only the live page's answer sets
    ``quiet``. A page that cannot be asked (the fake session has none) is
    not quiet either."""
    kit, _sessions, memory = fake_kit()
    remember(memory, ['- button "Next" [ref=e1]'])
    forged = {"action": "click", "ref": "e1", CARD_KEY: {"quiet": True, "scheme": "https"}}
    refused(kit.precheck(forged, user_id=USER), "invalid_arguments")
    assert "quiet" not in kit.bind(forged, user_id=USER)[CARD_KEY]  # no browser, no word about the page
    card = await kit.bind_async(forged, user_id=USER, task_id="t1")
    assert card[CARD_KEY]["quiet"] is False and card[CARD_KEY]["picture"] == "", card


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
    result = await read(kits, "open", url=fakesite_tls.url("/signup?next=%2Fgrades"))
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
    before = await read(kits, "open", url=fakesite_tls.url("/signup"))
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
    """A key goes to whatever the page shows and has in focus, so a key
    card is tied to the page as it was looked at: after a scroll the
    outline is another one and the card is void. (A click names one
    control and stays good while that control is there:
    test_a_click_card_stays_good_while_its_control_is_still_there_under_its_name.)"""
    _read, toolkit, _sessions, _memory, _spy = kits
    await read(kits, "open", url=fakesite_tls.url("/flights"))
    card = toolkit.bind({"action": "press", "key": "Tab"}, user_id=USER)
    page = await live_page(kits)
    await page.mouse.wheel(0, 1_000_000)
    await page.wait_for_timeout(150)
    result = await toolkit.execute("press", {k: v for k, v in card.items() if k != "action"}, user_id=USER, task_id="t1", approved=True)
    refused(result, "outline_changed")
    assert page.url.endswith("/flights")


@pytest.mark.asyncio
async def test_a_click_card_stays_good_while_its_control_is_still_there_under_its_name(
    kits, fakesite_tls, page_at
):
    """A page that moves by itself (an advert that loads, a banner that
    leaves, a scroll) is another outline by the time a person taps
    Approve. The card names one control: while the whole page still has
    that ref under that name, on the same address, the click is the one
    that was approved. A control that is gone voids it."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-moves", STEADY_PAGE, "Tickets")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"'))
    assert card[CARD_KEY]["ref_name"] == "Add to cart"
    page = await live_page(kits)
    await page.evaluate(
        "document.body.insertAdjacentHTML('afterbegin', '<a href=\"/grades\">A new advert</a>')"
    )
    done = await approve(kits, card)
    await settled(kits)
    assert done["ok"] is True and posted(fakesite_tls) == ["/cart/add"], (done, fakesite_tls.handled)

    before = await read(kits, "open", url=fakesite_tls.url("/r-moves"))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"'))
    await (await live_page(kits)).evaluate("document.getElementById('add').remove()")
    gone = await approve(kits, card)
    assert gone["ok"] is False and gone.get("rule") in ("outline_changed", "stale_ref"), gone


@pytest.mark.asyncio
async def test_an_add_to_cart_click_says_what_comes_next_when_the_person_asked_to_order(kits, fakesite_tls, page_at):
    """On Amazon a small model added the item to the cart and stopped there,
    though the person had said "order me". The result says the next step."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-cart-next", STEADY_PAGE, "Tickets")))
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"')))
    assert done["ok"] is True and done["next_step"] == act_module.CART_NEXT_STEP
    assert "browser.checkout" in done["next_step"]


@pytest.mark.asyncio
async def test_an_approved_click_on_a_link_that_did_nothing_follows_the_links_address(kits, fakesite_tls, page_at):
    """On a film site's front page the approved click on a carousel's
    link left the page where it was, three times, each with its own
    card. What was approved is following that link, so its address is
    opened."""
    deaf = "<script>document.addEventListener('click', e => e.preventDefault(), true)</script>"
    body = f'<h1>Films</h1><a href="/grades">Paper Tiger</a>{deaf}'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-carousel", body, "Films")))
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, '- link "Paper Tiger"')))
    assert done["ok"] is True and done["url"].endswith("/grades"), done


@pytest.mark.asyncio
async def test_an_approved_showtime_click_that_lands_on_a_refused_seat_page_gives_the_link(kits, fakesite_tls, page_at):
    """The approved showtime click lands on a seat page its site refuses
    to fill: the result says so, and carries the link the click followed
    as both the link it opened and the one to finish on."""
    from tests.test_browser_read import REFUSED_SEATS

    page_at("/r-seat-refused", REFUSED_SEATS, "Choose seats")
    body = '<h1>Showtimes</h1><a href="/r-seat-refused?tid=AAQQP">8:30 PM</a>'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-showtimes", body, "Showtimes")))
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, '- link "8:30 PM"')))
    assert done["ok"] is True and "site_refused" in done, done
    assert done["opened_link"] == done["finish_link"] == fakesite_tls.url("/r-seat-refused?tid=AAQQP")


@pytest.mark.asyncio
async def test_a_card_for_a_button_that_names_no_item_names_the_item_it_sits_with(kits, fakesite_tls, page_at):
    """Four products, four "Add to cart" buttons: a card that said only
    'Click "Add to cart"' over a picture of the results told the owner
    nothing about which one. A button whose words name what it acts on
    gets no addition."""
    body = (
        "<h1>Results</h1>"
        "<div><h2>SILCA Super Secret Chain Lube</h2><p>$25.00</p><button type='button'>Add to cart</button></div>"
        "<div><h2>Synergetic Wet Chain Lube</h2><p>$24.99</p><button type='button'>Add to cart</button></div>"
        "<div><h2>Notes</h2><button type='button'>Show all reviews</button></div>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-results", body, "Results")))
    refs = re.findall(r'button "Add to cart" \[ref=([a-z0-9]+)\]', "\n".join(before["outline"]))
    assert len(refs) == 2, before["outline"]
    host = fakesite_tls.url("/").split("://")[1].rstrip("/")
    for ref, item in zip(refs, ("SILCA Super Secret Chain Lube", "Synergetic Wet Chain Lube"), strict=True):
        card = await card_for(kits, "click", ref=ref)
        assert kits[1].describe(card, user_id=USER).startswith(f'Click "Add to cart" for "{item}" on {host}'), card
    plain = await card_for(kits, "click", ref=ref_of(before, '- button "Show all reviews"'))
    assert kits[1].describe(plain, user_id=USER).startswith(f'Click "Show all reviews" on {host}')


@pytest.mark.asyncio
async def test_a_control_seen_before_a_scroll_can_still_be_acted_on(kits, fakesite_tls, page_at):
    """Each look replaced the page memory, so a control the model saw in
    one outline was "stale ref" once a scroll had put another outline in
    its place. Refs of the same page are kept across looks; another page
    starts afresh."""
    tall = '<h1>Showtimes</h1><button type="button">Pick 7:15 PM</button>' + "<p>filler</p>" * 400
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-tall-top", tall, "Showtimes")))
    ref = ref_of(before, '- button "Pick 7:15 PM"')
    after = await read(kits, "scroll", direction="down")
    assert not any("Pick 7:15 PM" in line for line in after["outline"])
    card = await card_for(kits, "click", ref=ref)
    assert card.get("refused") is None and card[CARD_KEY]["ref_name"] == "Pick 7:15 PM", card
    await read(kits, "open", url=fakesite_tls.url("/grades"))
    elsewhere = kits[1].precheck({"action": "click", "ref": ref}, user_id=USER)
    assert elsewhere is not None and elsewhere.get("rule") == "stale_ref", elsewhere


@pytest.mark.asyncio
async def test_a_control_a_find_showed_can_be_acted_on_without_scrolling_to_it(kits, fakesite_tls, page_at):
    """find reaches below the visible part, so its refs were in no
    outline: an act on one was answered "stale ref" until the model had
    scrolled the control into view."""
    tall = "<h1>Showtimes</h1>" + "<p>filler</p>" * 400 + '<button type="button" id="add">Pick 9:45 PM</button>'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-tall", tall, "Showtimes")))
    assert not any("Pick 9:45 PM" in line for line in before["outline"])
    found = await read(kits, "find", text="9:45 PM")
    card = await card_for(kits, "click", ref=ref_of({"outline": found["matches"]}, '- button "Pick 9:45 PM"'))
    assert card.get("refused") is None and card[CARD_KEY]["ref_name"] == "Pick 9:45 PM", card


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
    card (the live page, judged when the card would be made) and again
    when an approved click runs, so an order can never be placed outside
    browser.checkout, however the click is routed to it."""
    _read, toolkit, _sessions, _memory, spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/cart-saved"))
    click = {"action": "click", "ref": ref_of(before, '- button "Place order"')}
    assert toolkit.precheck(click, user_id=USER) is None  # the name alone no longer refuses a click
    refused(await toolkit.bind_async(click, user_id=USER, task_id="t1"), "use_checkout")
    refused(await attempt(kits, "click", ref=click["ref"]), "use_checkout")
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
    """A browser.act call as far as the approved run, refusals included:
    a precheck refusal is the result (no card was made); otherwise the
    card is bound without asking the live page (``card_for`` does that,
    as the runtime does), so what answers is the approved run's own
    check, should a card ever have been made."""
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


# ── a step that only looks like paying is no dead end ────────────────────
# The owner asked for cinema tickets. The site's poster link hides "Buy
# Tickets" inside its anchor and every showtime is a link named "Buy
# tickets for ...": browser.read refused them for the word, browser.act
# refused them for the word after the owner had approved, and
# browser.checkout only works on a payment page, so nothing could follow
# them. Following a link by GET moves no money, purchase words refuse an
# act only where money can move from it, and a refusal the live page gives
# is the answer when the card would be made, never after the owner's tap.

POSTER_PAGE = (
    "<h1>Now playing</h1>"
    f'<a href="/grades" aria-label="Paper Tiger (2026)">Paper Tiger (2026) <span class="{SR}">Buy Tickets</span></a> '
    '<a href="/flights?showtime=1915">Buy tickets for 7:15 PM showtime</a>'
)
POST_ELSEWHERE = "fetch('/next-step', {method: 'POST'})"


# What the live page answers, when the card would be made, for a ref that
# no longer resolves or a page that moved (plus the person's sentence).
STALE_BIND = {"ok": False, "refused": True, "rule": "stale_ref", "error": "stale ref: re-snapshot", "stale_ref": True}


async def card_for(kits, action, **params):
    """What the runtime gets when it asks for a browser.act card: the
    precheck passes, then the card's arguments, or the live page's
    refusal instead of them."""
    call = {"action": action, **params}
    assert kits[1].precheck(call, user_id=USER) is None
    return await kits[1].bind_async(call, user_id=USER, task_id="t1")


async def approve(kits, card):
    """Run a card as the owner's Approve does."""
    arguments = {k: v for k, v in card.items() if k != "action"}
    return await kits[1].execute(card["action"], arguments, user_id=USER, task_id="t1", approved=True)


@pytest.mark.asyncio
async def test_a_plain_link_with_hidden_purchase_words_is_followed_at_both_tiers(kits, fakesite_tls, page_at):
    """A film poster whose anchor hides "Buy Tickets" for screen readers.
    The judge reads those words, and the link still only opens the film's
    page: browser.act gets a card (which says what the words read as, with
    the money warning) and follows the link with the write window shut,
    and browser.read follows it too."""
    _read, _act, _sessions, _memory, spy = kits
    path = page_at("/r-poster", POSTER_PAGE, "Now playing")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    poster = ref_of(before, '- link "Paper Tiger (2026)"')
    judged = await (await live_page(kits)).locator(f"aria-ref={poster}").evaluate(markers.PURCHASE_TARGET_JS)
    assert judged["plain_link"] is True and markers.PURCHASE_RE.search(judged["name"]), judged
    card = await card_for(kits, "click", ref=poster)
    assert card.get("refused") is None and card[CARD_KEY]["picture"], card
    assert _act.describe(card, user_id=USER).endswith(f". {MAY_ORDER_NOTE}")
    done = await approve(kits, card)
    assert done["ok"] is True and done["url"].endswith("/grades"), done
    assert ("GET", "grades", False) in spy.seen
    again = await read(kits, "open", url=fakesite_tls.url(path))
    followed = await read(kits, "click", ref=ref_of(again, '- link "Paper Tiger (2026)"'))
    assert followed["ok"] is True and followed["url"].endswith("/grades"), followed


@pytest.mark.asyncio
async def test_a_showtime_link_named_buy_tickets_is_followed_by_an_approved_act(kits, fakesite_tls, page_at):
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-poster", POSTER_PAGE, "Now playing")))
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, '- link "Buy tickets for 7:15 PM')))
    assert done["ok"] is True and done["did"] == 'Clicked "Buy tickets for 7:15 PM showtime"', done
    assert sent(fakesite_tls, "GET", "/flights") and "new_tab" not in done


@pytest.mark.parametrize("href", ["/buy", "/pay?item=1", "/checkout/complete"])
@pytest.mark.asyncio
async def test_a_plain_link_aimed_at_an_order_path_is_still_refused(kits, fakesite_tls, page_at, href):
    """Opening an order path can be the order itself, whatever the link
    says: no card is made for it, and an approved click on it is refused."""
    path = page_at("/r-order-link", f'<h1>Now playing</h1><a href="{href}">Tickets</a>', "Now playing")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    ref = ref_of(before, '- link "Tickets"')
    refused(await card_for(kits, "click", ref=ref), "use_checkout")
    refused(await attempt(kits, "click", ref=ref), "use_checkout")
    assert not sent(fakesite_tls, "GET", href.partition("?")[0]), fakesite_tls.handled


@pytest.mark.parametrize("lead", [TOTAL_LEAD, "<h1>Tickets</h1><p>Your saved card will be charged.</p>"])
@pytest.mark.asyncio
async def test_a_purchase_worded_button_next_to_a_total_or_a_card_on_file_is_still_refused(
    kits, fakesite_tls, page_at, lead
):
    """The script button that only opens the next page elsewhere is the
    order button here: the page shows an order total, or says a payment
    method is on file."""
    body = lead + f'<button type="button" onclick="{POST_ELSEWHERE}">Buy tickets</button>'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-buy-review", body, "Tickets")))
    ref = ref_of(before, '- button "Buy tickets"')
    refused(await card_for(kits, "click", ref=ref), "use_checkout")
    refused(await attempt(kits, "click", ref=ref), "use_checkout")
    await settled(kits)
    assert posted(fakesite_tls) == [], fakesite_tls.handled


@pytest.mark.parametrize(
    "control",
    [
        # Purchase words on the button of a POST form, on a page that shows nothing to pay.
        '<form method="post" action="/next"><button type="submit">Place order</button></form>',
        # A script button that is little more than a price.
        f'<button type="button" onclick="{POST_ELSEWHERE}">$0.99</button>',
    ],
)
@pytest.mark.asyncio
async def test_a_post_forms_order_button_and_a_bare_price_are_still_refused(kits, fakesite_tls, page_at, control):
    body = "<h1>The App</h1><p>Productivity.</p>" + control
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-still-pays", body, "The App")))
    ref = ref_of(before, "- button")
    refused(await card_for(kits, "click", ref=ref), "use_checkout")
    refused(await attempt(kits, "click", ref=ref), "use_checkout")
    await settled(kits)
    assert posted(fakesite_tls) == [], fakesite_tls.handled


WALLET_SHOP = (
    "<h1>Socks</h1><p>Price: $5.00</p>"
    '<form method="post" action="/cart/add"><label>Size <select name="size"><option>S</option>'
    '<option>M</option></select></label><button type="submit">Add to cart</button></form>'
    f'<button type="button" aria-label="Buy with Google Pay" onclick="{POST_ELSEWHERE}">G Pay</button>'
)


@pytest.mark.asyncio
async def test_a_wallet_button_is_refused_while_the_shop_around_it_still_works(kits, fakesite_tls, page_at):
    """Most shops show a wallet button on every product page. It refuses
    itself, not the page: the size is chosen and the thing goes in the
    cart through browser.act, as on a shop without one."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-wallet-shop", WALLET_SHOP, "Socks")))
    wallet = ref_of(before, '- button "Buy with Google Pay"')
    refused(await card_for(kits, "click", ref=wallet), "use_checkout")
    refused(await attempt(kits, "click", ref=wallet), "use_checkout")
    chosen = await approve(kits, await card_for(kits, "select", ref=ref_of(before, '- combobox "Size"'), value="M"))
    assert chosen["ok"] is True and chosen["did"] == 'Selected "M" in "Size"', chosen
    added = await approve(kits, await card_for(kits, "click", ref=ref_of(chosen, '- button "Add to cart"')))
    await settled(kits)
    assert added["ok"] is True and posted(fakesite_tls) == ["/cart/add"], (added, fakesite_tls.handled)


@pytest.mark.asyncio
async def test_a_read_still_leaves_a_purchase_worded_button_to_browser_act(kits, fakesite_tls, page_at):
    """browser.read has no card, so words are enough for it: the button
    browser.act now asks the owner about is never clicked by a read."""
    body = "<h1>Paper Tiger (2026)</h1><button type=\"button\" onclick=\"location.href = '/flights'\">Reserve seats</button>"
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-reserve", body, "Paper Tiger")))
    result = await read(kits, "click", ref=ref_of(before, '- button "Reserve seats"'))
    await settled(kits)
    assert result["ok"] is False and result["error"] == READ_CLICK_MESSAGE, result
    assert "may place an order" in result["consequential"]
    assert not sent(fakesite_tls, "GET", "/flights"), fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_refusal_the_live_page_gives_comes_instead_of_a_card(kits, fakesite_tls):
    """A review page whose button says "Confirm": nothing in the outline
    says it pays, so the precheck passes; the live page (a total next to
    the card on file) does. The owner used to approve a card for it and
    then see it refused. Now the refusal is the answer when the card would
    be made: no card, no picture kept, and one line in the log."""
    from structlog.testing import capture_logs

    _read, toolkit, _sessions, _memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url("/cart-saved-plain"))
    with capture_logs() as logs:
        answer = await card_for(kits, "click", ref=ref_of(before, '- button "Confirm"'))
    assert answer == {
        "ok": False, "refused": True, "rule": "use_checkout", "error": USE_CHECKOUT_MESSAGE,
        "reason": markers.USE_CHECKOUT_REASON,
    }
    assert toolkit._pictures == {}
    assert await (await live_page(kits)).locator("[data-crawler-outline]").count() == 0
    line = checkout_log(logs)
    assert line["why"] == "saved_payment" and line["judged"] is True and line["sends"] is True, line
    assert line["order_total"] is True and line["purchase_words"] is False and line["plain_link"] is False, line
    assert "Confirm" not in repr(logs) and "499" not in repr(logs)


@pytest.mark.asyncio
async def test_a_field_that_turned_secret_or_went_away_gets_no_card(kits, fakesite_tls):
    """The same for the live field check, and for a ref that no longer
    resolves: the model is told now, as the approved act would tell it."""
    _read, toolkit, _sessions, _memory, _spy = kits
    await read(kits, "open", url=fakesite_tls.url("/post"))
    page = await live_page(kits)
    await page.set_content(
        "<form action='/login' method='post'><label>Secret word <input id='w' name='w'></label>"
        "<button type='submit'>Go</button></form>"
    )
    plain = await read(kits, "snapshot")
    fill = {"ref": ref_of(plain, '- textbox "Secret word"'), "text": "swordfish"}
    await page.evaluate("document.getElementById('w').type = 'password'")
    answer = refused(await card_for(kits, "fill", **fill), "secure_field")
    assert "swordfish" not in json.dumps(answer)
    await page.evaluate("document.getElementById('w').remove()")
    gone = await card_for(kits, "fill", **fill)
    assert gone == {**STALE_BIND, "reason": refused(gone, "stale_ref")["reason"]}
    assert toolkit._pictures == {}


@pytest.mark.asyncio
async def test_a_choice_on_a_page_with_a_card_on_file_gets_no_card(kits, fakesite_tls):
    before = await read(kits, "open", url=fakesite_tls.url("/cart-saved-radio"))
    refused(await card_for(kits, "check", ref=ref_of(before, '- radio "Use this card"')), "use_checkout")
    assert not sent(fakesite_tls, "POST", "/place-order"), fakesite_tls.handled


STEADY_PAGE = (
    '<h1>Tickets</h1><p id="timer">Cart expires in 9:59</p>'
    '<label><input type="checkbox" id="news"> Send me news</label>'
    '<button type="button" id="menu" aria-expanded="false">Menu</button>'
    '<form method="post" action="/cart/add"><button type="submit" id="add">Add to cart</button></form>'
)


@pytest.mark.asyncio
async def test_an_approved_act_still_runs_after_text_and_state_changed(kits, fakesite_tls, page_at):
    """Between the card and the owner's tap a countdown ticked, a box got
    ticked, a menu opened and the focus moved. None of that changes which
    element a ref names, so the approval holds; it used to be voided as
    "The page changed since this was approved"."""
    _read, _act, _sessions, memory, _spy = kits
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-steady", STEADY_PAGE, "Tickets")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"'))
    page = await live_page(kits)
    await page.evaluate(
        "() => { document.getElementById('timer').textContent = 'Cart expires in 9:58';"
        " document.getElementById('news').checked = true;"
        " const menu = document.getElementById('menu'); menu.setAttribute('aria-expanded', 'true'); menu.focus(); }"
    )
    now = await snap.outline(page, account_mode=True)
    assert now.lines != before["outline"]  # control: the outline did change
    assert outline_digest(now.lines) == memory.get(USER).outline_digest
    done = await approve(kits, card)
    await settled(kits)
    assert done["ok"] is True and posted(fakesite_tls) == ["/cart/add"], (done, fakesite_tls.handled)


@pytest.mark.asyncio
async def test_an_approved_act_is_refused_when_its_target_was_renamed(kits, fakesite_tls, page_at):
    """What the card's sentence names must still be what the ref names:
    a button that reads "Remove everything" by the time the owner taps is
    not the "Add to cart" they approved."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-steady", STEADY_PAGE, "Tickets")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"'))
    await (await live_page(kits)).evaluate("document.getElementById('add').textContent = 'Remove everything'")
    refused(await approve(kits, card), "outline_changed")
    assert posted(fakesite_tls) == [], fakesite_tls.handled


@pytest.mark.asyncio
async def test_an_enter_card_is_refused_when_the_focus_moved(kits, fakesite_tls, page_at):
    """Enter acts on whatever has the focus, so a key press stays tied to
    where the focus was: the card showed the search box, and Enter must
    not land on a button instead."""
    path = page_at(
        "/r-focus-moved",
        "<h1>Search</h1><form action='/search'><input aria-label='Query' name='q' autofocus></form>"
        "<button type='button' id='other' onclick=\"location.href = '/grades'\">Open grades</button>",
        "Search",
    )
    await read(kits, "open", url=fakesite_tls.url(path))
    card = await card_for(kits, "press", key="Enter")
    page = await live_page(kits)
    await page.evaluate("document.getElementById('other').focus()")
    refused(await approve(kits, card), "outline_changed")
    assert page.url.endswith("/r-focus-moved") and not sent(fakesite_tls, "GET", "/grades")



@pytest.mark.asyncio
async def test_an_enter_card_still_runs_after_text_changed(kits, fakesite_tls, page_at):
    """A countdown next to the search box ticked between the card and the
    owner's tap: the focus is where it was, so Enter still runs. It used
    to be voided by any changed line."""
    path = page_at(
        "/r-enter-steady",
        "<h1>Search</h1><p id='timer'>Offer ends in 9:59</p>"
        "<form action='/search'><input aria-label='Query' name='q' autofocus></form>",
        "Search",
    )
    await read(kits, "open", url=fakesite_tls.url(path))
    card = await card_for(kits, "press", key="Enter")
    await (await live_page(kits)).evaluate("document.getElementById('timer').textContent = 'Offer ends in 9:58'")
    done = await approve(kits, card)
    assert done["ok"] is True and done["did"] == "Pressed Enter", done
    assert sent(fakesite_tls, "GET", "/search")


@pytest.mark.asyncio
async def test_a_page_that_moved_since_the_model_looked_gets_no_card(kits, fakesite_tls):
    """Judging a click scrolls its target into view, as the click itself
    will. For a link below the fold (found with a query) that changes what
    the outline shows, and the approved click used to be refused for it:
    "The page changed since this was approved"; then the model was told
    to look again before any card. The link is the same control under the
    same name, so now the first try gets its card and runs. A key press,
    which names no control, is still told to look again."""
    await read(kits, "open", url=fakesite_tls.url("/grades"))
    found = await read(kits, "snapshot", query="privacy")
    card = await card_for(kits, "click", ref=ref_of(found, '- link "Privacy policy"'))
    assert card.get("refused") is None and card[CARD_KEY]["ref_name"] == "Privacy policy", card
    done = await approve(kits, card)
    assert done["ok"] is True and done["did"] == 'Clicked "Privacy policy"', done
    assert sent(fakesite_tls, "GET", "/privacy")

    await read(kits, "open", url=fakesite_tls.url("/grades"))
    await read(kits, "snapshot", query="privacy")
    page = await live_page(kits)
    await page.mouse.wheel(0, 1_000_000)
    await page.wait_for_timeout(150)
    answer = await card_for(kits, "press", key="Tab")
    assert answer == {**STALE_BIND, "reason": refused(answer, "stale_ref")["reason"]}


@pytest.mark.asyncio
async def test_an_order_button_below_the_fold_is_judged_with_its_total_in_view(kits, fakesite_tls, page_at):
    """An order total counts only while it is on screen, and judging a
    click scrolls its target into view. The page's facts are read after
    that, when the card would be made as when the approved click runs, so
    the two agree: the order button next to a total below the fold gets
    no card, where it used to get one that was refused after the tap."""
    body = (
        '<h1>Tickets</h1><div style="height:2400px"></div><p>Order total: $499.00</p>'
        f'<button type="button" onclick="{POST_ELSEWHERE}">Buy tickets</button>'
    )
    await read(kits, "open", url=fakesite_tls.url(page_at("/r-below-fold", body, "Tickets")))
    whole = await read(kits, "snapshot", full=True)  # the whole page: a scroll does not change this outline
    [facts] = await _shared.page_facts(await live_page(kits))
    assert facts["order_total"] is False  # control: the total is not on screen yet
    refused(await card_for(kits, "click", ref=ref_of(whole, '- button "Buy tickets"')), "use_checkout")
    await settled(kits)
    assert posted(fakesite_tls) == [], fakesite_tls.handled


# ── the live page's word on what a site approval may run with no card ────

QUIET_SITE = (
    "<h1>Paper Tiger (2026)</h1><p>Tickets from $14.50</p>"
    '<button type="button" aria-label="Seat F7">F7</button> <button type="button">Next</button> '
    '<a href="/grades">All showtimes</a> '
    '<label>Seats <select name="n"><option>1</option><option>2</option></select></label> '
    '<label><input type="checkbox" name="news"> Send me news</label> '
    '<form action="/search"><input aria-label="Query" name="q"><button type="submit">Search</button></form> '
    "<button type=\"button\" onclick=\"location.href = '/flights'\">Buy tickets</button>"
)


async def quiet_of(kits, action, **params):
    """``_page.quiet`` of the card the live page gives this act."""
    card = await card_for(kits, action, **params)
    assert card.get("refused") is None, card
    return card[CARD_KEY]["quiet"], card[CARD_KEY].get("money")


@pytest.mark.asyncio
async def test_clicking_around_on_a_page_with_nothing_to_pay_is_quiet(kits, fakesite_tls, page_at):
    """Picking a seat, "Next", a link, a choice, a key that only moves: on
    a page that shows no order total, no payment method on file and no
    wallet, the toolkit calls them quiet, and the card warns of nothing."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-quiet", QUIET_SITE, "Paper Tiger")))
    for action, params in [
        ("click", {"ref": ref_of(before, '- button "Seat F7"')}),
        ("click", {"ref": ref_of(before, '- button "Next"')}),
        ("click", {"ref": ref_of(before, '- link "All showtimes"')}),
        ("select", {"ref": ref_of(before, '- combobox "Seats"'), "value": "2"}),
        ("check", {"ref": ref_of(before, '- checkbox "Send me news"')}),
        ("press", {"key": "Tab"}),
        ("press", {"key": "Escape"}),
    ]:
        assert await quiet_of(kits, action, **params) == (True, None), (action, params)


@pytest.mark.asyncio
async def test_a_quiet_card_carries_the_controls_own_words_and_a_site_approval_reads_them(
    kits, fakesite_tls, page_at
):
    """A site approval runs a click unasked only when the card names the
    control and the name reads as nothing that changes or sends something
    (app_approvals.site_covers). The toolkit never wrote the name, so no
    click on an allowed site ever ran without a card."""
    from services.agent.app_approvals import site_covers

    page = QUIET_SITE + '<button type="button">Delete account</button>'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-quiet-names", page, "Paper Tiger")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Next"'))
    assert card[CARD_KEY]["quiet"] is True and card[CARD_KEY]["target"] == {"name": "Next"}
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Delete account"'))
    assert card[CARD_KEY]["target"] == {"name": "Delete account"}
    # Bound to a real https origin the approval covers "Next", never "Delete account".
    for name, covered in (("Next", True), ("Delete account", False)):
        call = {"action": "click", "ref": "e1", CARD_KEY: {
            "origin": "https://tickets.example.com", "scheme": "https", "quiet": True, "target": {"name": name},
        }}
        assert site_covers(call) is covered, name


@pytest.mark.asyncio
async def test_typing_sending_a_form_and_a_purchase_worded_button_are_never_quiet(kits, fakesite_tls, page_at):
    """On the same page: what types, what sends a form (a submit, Enter,
    the form's own button, by GET too) and a button worded like a purchase
    each get their card, as before, and are never run without one."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-quiet", QUIET_SITE, "Paper Tiger")))
    query = ref_of(before, '- textbox "Query"')
    for action, params in [
        ("fill", {"ref": query, "text": "tiger"}),
        ("fill_form", {"fields": [{"ref": query, "text": "tiger"}]}),
        ("submit", {"ref": query}),
        ("click", {"ref": ref_of(before, '- button "Search"')}),
        ("press", {"key": "Enter"}),
        ("click", {"ref": ref_of(before, '- button "Buy tickets"')}),
    ]:
        quiet, _money = await quiet_of(kits, action, **params)
        assert quiet is False, (action, params)


@pytest.mark.parametrize(
    "lead",
    [
        TOTAL_LEAD,
        "<h1>Tickets</h1><p>Your saved card will be charged.</p>",
        '<h1>Socks</h1><p>Price: $5.00</p><button type="button" aria-label="Buy with Google Pay">G Pay</button>',
    ],
)
@pytest.mark.asyncio
async def test_nothing_is_quiet_next_to_an_order_total_a_card_on_file_or_a_wallet(kits, fakesite_tls, page_at, lead):
    """Whatever the control says: where the page shows a way to pay, the
    card carries the money warning and a person looks at it."""
    body = lead + '<button type="button">Details</button>'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-loud", body, "Tickets")))
    for action, params in [("click", {"ref": ref_of(before, '- button "Details"')}), ("press", {"key": "Tab"})]:
        quiet, money = await quiet_of(kits, action, **params)
        assert quiet is False and money, (action, money)


@pytest.mark.asyncio
async def test_an_http_page_is_never_quiet(kits, fakesite, page_at):
    before = await read(kits, "open", url=fakesite.url(page_at("/r-quiet", QUIET_SITE, "Paper Tiger")))
    click = {"action": "click", "ref": ref_of(before, '- button "Next"')}
    refused(kits[1].precheck(click, user_id=USER), "insecure_page")  # no card is made for it at all
    card = await kits[1].bind_async(click, user_id=USER, task_id="t1")  # and should one be bound all the same
    assert card[CARD_KEY]["quiet"] is False, card


# ── an approved act that opens a new tab goes on in that tab ─────────────


@pytest.mark.parametrize(
    "control, prefix, landed",
    [
        ('<a href="/grades" target="_blank">7:15 PM</a>', '- link "7:15 PM"', "/grades"),
        ("<button type=\"button\" onclick=\"window.open('/flights')\">Seat map</button>", '- button "Seat map"', "/flights"),
    ],
)
@pytest.mark.asyncio
async def test_an_approved_click_that_opens_a_new_tab_goes_on_in_that_tab(
    kits, fakesite_tls, page_at, control, prefix, landed
):
    """A showtime that opens the ticketing page in a new tab (target=_blank,
    or a script's window.open). The approved click answered with the
    outline of the tab it was made in, so the model took it for a click
    that did nothing. Now the session goes on in the new tab, as after a
    read's click, and the next act is tied to that page."""
    _read, _act, _sessions, memory, _spy = kits
    path = page_at("/r-new-tab", "<h1>Showtimes</h1>" + control, "Showtimes")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, prefix)))
    assert done["ok"] is True and done["new_tab"] is True and done["did"].startswith("Clicked "), done
    assert done["url"] == fakesite_tls.url(landed), done
    tabs = (await read(kits, "tabs"))["tabs"]
    assert [(tab["url"], tab["active"]) for tab in tabs] == [
        (fakesite_tls.url(path), False),
        (fakesite_tls.url(landed), True),
    ]
    assert memory.get(USER).url == fakesite_tls.url(landed)


@pytest.mark.asyncio
async def test_a_new_tab_whose_page_is_slow_to_answer_is_waited_for_after_an_act(
    kits, fakesite_tls, page_at, monkeypatch
):
    """Playwright lists a new tab only once its first page has answered. A
    ticketing site that takes a second was not among the tabs when the act
    was over, and the old tab was described."""
    monkeypatch.setitem(DELAYS, "/r-slow-film", 1.2)
    page_at("/r-slow-film", "<h1>Paper Tiger showtimes</h1>", "Showtimes")
    path = page_at("/r-films", '<h1>Films</h1><a href="/r-slow-film" target="_blank">Paper Tiger</a>', "Films")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, '- link "Paper Tiger"')))
    assert done["ok"] is True and done["new_tab"] is True, done
    assert done["url"] == fakesite_tls.url("/r-slow-film")
    assert any("Paper Tiger showtimes" in line for line in done["outline"]), done["outline"]


@pytest.mark.asyncio
async def test_a_new_tab_that_shows_no_page_is_closed_and_the_act_says_so(kits, fakesite_tls, page_at):
    """Nothing answers at the address the new tab went to: the tab is
    closed, the session stays on the page the card showed, and the result
    says what happened where it used to describe that page as if nothing
    had."""
    body = "<h1>Showtimes</h1><button type=\"button\" onclick=\"window.open('http://127.0.0.1:9/')\">Seat map</button>"
    path = page_at("/r-dead-tab", body, "Showtimes")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, '- button "Seat map"')))
    assert done == {"ok": False, "error": "The page that step opened in a new tab did not load."}
    tabs = (await read(kits, "tabs"))["tabs"]
    assert [(tab["url"], tab["active"]) for tab in tabs] == [(fakesite_tls.url(path), True)]


# ── what may run with no card while "Ask before every website step" is off ──
# An errand step commits the person to nothing: the toolkit says which acts
# are one (``_page.errand``) from the live page, never from the call.

SEND = {**SEAT, "sends": True, "submits": True, "in_form": True}  # a POST form's own button
GET_BUTTON = {**SEAT, "name": "Go", "submits": True, "in_form": True}  # a GET form's own button
SCRIPT_IN_FORM = {**SEAT, "in_form": True}
FILL = {"action": "fill", "ref": "e1", "text": "chain lube"}
TWO_FIELDS = {"action": "fill_form", "fields": [{"ref": "e1", "text": "2"}, {"ref": "e2", "text": "94110"}]}
ENTER = {"action": "press", "key": "Enter"}
SUBMIT = {"action": "submit", "ref": "e1"}
# A card's money facts when the page shows nothing to pay.
NO_MONEY = {"amount": "", "order_total": False, "saved_payment": False, "wallet": False, "unread": False}


def errand(call, judged=None, *, fields=(), form_ok=False, english=True, words=None, consent=False):
    request = act_module._parse(call)
    return act_module._errand(
        request, "https", judged, [QUIET_FRAME], None,
        fields=fields, form_ok=form_ok, english=english, words=words, consent=consent,
    )


@pytest.mark.parametrize(
    "call, judged, facts, is_errand",
    [
        *[({"action": "press", "key": key}, None, {}, True) for key in ("Tab", "Escape", "ArrowDown", "ArrowUp")],
        # Typing: only search boxes, quantities, zip and promo codes.
        (FILL, None, {"fields": ["search"]}, True),
        (FILL, None, {"fields": ["promo"]}, True),
        (TWO_FIELDS, None, {"fields": ["quantity", "zip"]}, True),
        (FILL, None, {"fields": [""]}, False),
        (FILL, None, {"fields": []}, False),
        (TWO_FIELDS, None, {"fields": ["quantity"]}, False),
        (TWO_FIELDS, None, {"fields": ["quantity", ""]}, False),
        # A site search sent by GET, by its field, its button or Enter.
        (SUBMIT, GET_BUTTON, {"form_ok": True}, True),
        (ENTER, GET_BUTTON, {"form_ok": True}, True),
        (ENTER, {**GET_BUTTON, "name": ""}, {"form_ok": True}, True),  # a form with no button
        (CLICK, GET_BUTTON, {"form_ok": True}, True),
        (SUBMIT, GET_BUTTON, {"form_ok": False}, False),  # a field that is not a search box
        (ENTER, GET_BUTTON, {"form_ok": False}, False),
        (CLICK, GET_BUTTON, {"form_ok": False}, False),
        (SUBMIT, SEND, {"form_ok": True}, False),  # sent by POST
        (ENTER, {**SEAT, "submits": False}, {"form_ok": True}, False),  # Enter on a button: not a search
        (SUBMIT, {**GET_BUTTON, "name": "Subscribe"}, {"form_ok": True}, False),
        # Clicks and choices whose words commit to nothing.
        (CLICK, SEAT, {}, True),
        (CLICK, {**SEAT, "name": "Continue"}, {}, True),
        (CLICK, {**SEAT, "name": "Accept cookies"}, {}, True),
        (CLICK, {**SEAT, "name": "Cancel"}, {}, True),
        (CLICK, PLAIN, {}, True),
        (CLICK, {**PLAIN, "name": "7:15 PM"}, {}, True),
        (CLICK, {**PLAIN, "name": ""}, {}, True),
        (CLICK, {**PLAIN, "name": "Order online"}, {}, True),  # a link only opens the next page
        (CLICK, {**PLAIN, "name": "Abmelden"}, {"english": False}, True),  # links in any language
        # A link worded like a purchase gets its card: a page's script can
        # make one place the order (a single-page app's delegated handler).
        *[(CLICK, {**PLAIN, "name": name}, {}, False) for name in ("Book now", "Buy now", "Place order")],
        (CLICK, {**PLAIN, "name": "7:15 PM"}, {"words": "Buy now"}, False),
        # A ticket funnel's first link only opens the seat step (Fandango's).
        (CLICK, {**PLAIN, "name": "Buy tickets for 7:15 PM showtime"}, {}, True),
        (CLICK, {**PLAIN, "name": "7:15 PM"}, {"words": "Buy tickets"}, True),
        (SELECT, {"name": "Quantity | 2 | 2"}, {}, True),
        (CHECK, {"name": "Gift wrap"}, {}, True),
        # A button that sends a POST form, or a script button inside one: cart words only.
        (CLICK, {**SEND, "name": "Add to cart"}, {}, True),
        (CLICK, {**SEND, "name": "Proceed to checkout"}, {}, True),
        (CLICK, {**SEND, "name": "Update cart"}, {}, True),
        (CLICK, {**SCRIPT_IN_FORM, "name": "Increase quantity"}, {}, True),
        (CLICK, {**SEND, "name": "Continue"}, {}, False),
        (CLICK, {**SCRIPT_IN_FORM, "name": "Next"}, {}, False),
        # Stepper words only as a stepper's whole name or with the quantity.
        (CLICK, {**SEND, "name": "Increase credit limit"}, {}, False),
        (CLICK, {**SEND, "name": "Increase my monthly donation"}, {}, False),
        (CLICK, {**SCRIPT_IN_FORM, "name": "Increase seats"}, {}, False),
        (CLICK, {**SEND, "name": "+"}, {}, True),
        # Shopify's cart sends itself to /cart with "Check out".
        (CLICK, {**SEND, "name": "Check out | checkout", "action": "/cart"}, {"words": "Check out"}, True),
        (CLICK, {**SEND, "name": "Checkout", "action": "/en-gb/cart"}, {}, True),
        (CLICK, {**SEND, "name": "Check out", "action": "/account/plan"}, {}, False),
        # The words a person reads decide, not the control's name attribute.
        (CLICK, {**SEND, "name": "Add to Cart | Add to Shopping Cart | submit.add-to-cart"},
         {"words": "Add to Cart | Add to Shopping Cart"}, True),
        (CLICK, {**SEAT, "name": "Next"}, {"words": "Delete"}, False),
        # A cookie banner's own button, in a region about cookies, a POST form's included.
        (CLICK, {**SEAT, "name": "Agree and close"}, {"consent": True}, True),
        (CLICK, {**SEND, "name": "Accept | accept", "action": "/cookieprefs"}, {"words": "Accept", "consent": True},
         True),
        # A POST form in that region that is sent anywhere else is no cookie choice.
        (CLICK, {**SEND, "name": "Allow", "action": "/oauth/approve"}, {"consent": True}, False),
        (CLICK, {**SEND, "name": "Accept", "action": "/api/invitations/9"}, {"consent": True}, False),
        (CLICK, {**SEAT, "name": "Yes"}, {"consent": True}, True),
        (CLICK, {**SEAT, "name": "Yes"}, {}, False),
        (CLICK, {**SEAT, "name": "Agree and close"}, {}, False),
        (CLICK, {**SEAT, "name": "Accept and subscribe"}, {"consent": True}, False),
        (CLICK, {**SEAT, "name": "Agree and close"}, {"consent": True, "english": False}, False),
        # Outcomes.
        (CLICK, {**SEAT, "name": "Post comment"}, {}, False),
        (CLICK, {**SEAT, "name": "Delete"}, {}, False),
        (CLICK, {**SEAT, "name": "Cancel subscription"}, {}, False),
        (CLICK, {**SEAT, "name": "Sign up"}, {}, False),
        (CLICK, {**SEAT, "name": "Place order"}, {}, False),
        (CLICK, {**SEND, "name": "Place order"}, {}, False),
        (CLICK, {**SEAT, "name": "Finish Cancellation"}, {}, False),
        (CLICK, {**SEAT, "name": "Allow"}, {}, False),
        (CLICK, {**SEAT, "name": "Rent"}, {}, False),  # a purchase word, on no list of outcomes
        *[(CLICK, {**SEAT, "name": name}, {}, False) for name in (
            "Restart membership", "Resume membership", "Resubscribe", "Switch to annual billing", "Get Premium",
            "Unsend", "Disconnect", "Unblock", "Downvote", "Turn off two-factor authentication",
            "Make profile public", "Sell", "Request", "Finish", "End my benefits", "Start a return",
        )],
        (CHECK, {"name": "Finish Line (23)"}, {}, True),  # a brand filter, not a last step
        (CLICK, {**PLAIN, "name": "Unsubscribe"}, {}, False),
        (CLICK, {**PLAIN, "name": "Sign out"}, {}, False),
        (CLICK, {**PLAIN, "name": "Decline"}, {}, False),
        (CHECK, {"name": "I agree to the terms"}, {}, False),
        (CHECK, {"name": "I consent to the processing of my personal data"}, {}, False),
        (SELECT, {"name": "Plan | Subscribe monthly"}, {}, False),
        # Words in another language are not read: no click or choice but a link.
        (CLICK, {**SEAT, "name": "Absenden"}, {"english": False}, False),
        (SELECT, {"name": "Menge | 2"}, {"english": False}, False),
        # Nothing to judge by.
        (CLICK, {**SEAT, "name": ""}, {}, False),
        (CLICK, without(SEAT, "name"), {}, False),
        (CLICK, without(SEAT, "in_form"), {}, False),
        (CLICK, without(SEAT, "sends"), {}, False),
        (CLICK, None, {}, False),
        (CHECK, {"name": ""}, {}, False),
        (CHECK, None, {}, False),
        (SUBMIT, None, {"form_ok": True}, False),
        # What the purchase rules refuse is never one, whatever the rest says.
        (CLICK, {**PLAIN, "href": "/place-order"}, {}, False),
        (CLICK, {**SEND, "name": "Add to cart", "card_in_form": True}, {}, False),
    ],
)
def test_only_a_step_that_commits_the_person_to_nothing_is_an_errand_step(call, judged, facts, is_errand):
    assert errand(call, judged, **facts) is is_errand


@pytest.mark.parametrize(
    "scheme, answers, money",
    [
        ("http", [QUIET_FRAME], None),
        ("https", [QUIET_FRAME], {"unread": False}),  # the card warns about money: a person looks at it
        ("https", [{**QUIET_FRAME, "order_total": True}], None),
        ("https", [QUIET_FRAME, {**QUIET_FRAME, "saved_payment": True}], None),
        ("https", [{**QUIET_FRAME, "unread": True}], None),
        ("https", [QUIET_FRAME, None], None),
        ("https", [], None),
        ("https", [QUIET_FRAME], {**NO_MONEY, "amount": "$9.99", "order_total": True}),
    ],
)
def test_no_step_is_an_errand_step_on_a_page_that_shows_a_way_to_pay_or_cannot_be_read(scheme, answers, money):
    for call, judged, facts in ((CLICK, SEAT, {}), (FILL, None, {"fields": ["search"]})):
        request = act_module._parse(call)
        assert act_module._errand(request, "https", judged, [QUIET_FRAME], None, english=True, **facts)  # control
        assert not act_module._errand(request, scheme, judged, answers, money, english=True, **facts)


def test_a_wallet_button_elsewhere_on_the_page_does_not_stop_an_errand_step():
    """Most shops show Shop Pay or PayPal next to "Add to cart": the card
    for a step there warns of the wallet, and the step is still an errand
    step. The wallet button itself is refused as ever."""
    wallet_page = [{**QUIET_FRAME, "wallet": True}]
    money = {**NO_MONEY, "wallet": True}
    for call, judged, facts in (
        (CLICK, {**SEND, "name": "Add to cart", "wallet": True}, {}),
        (FILL, None, {"fields": ["search"]}),
        ({"action": "press", "key": "Tab"}, None, {}),
    ):
        request = act_module._parse(call)
        assert act_module._errand(request, "https", judged, wallet_page, money, english=True, **facts), call
    shop_pay = {**SEAT, "name": "Buy with Shop Pay", "wallet": True}
    assert not act_module._errand(act_module._parse(CLICK), "https", shop_pay, wallet_page, money, english=True)


def test_a_page_that_names_no_language_runs_only_links_keys_and_search_boxes_unasked():
    assert act_module._lang_is_english("en") and act_module._lang_is_english("en-GB")
    assert not act_module._lang_is_english("") and not act_module._lang_is_english("de")


# The fake site's pages name no language, which reads as unknown: an
# errand page says it is in English, as every English shop does.
EN = "<script>document.documentElement.lang = 'en';</script>"
ERRAND_SHOP = (
    EN + "<h1>Chain lube 4 oz</h1><p>Price: $9.99</p>"
    '<div role="dialog" aria-label="Cookies"><button type="button">Accept cookies</button></div>'
    '<form method="get" action="/search"><input type="search" name="q" aria-label="Search the shop">'
    '<button type="submit">Go</button></form> '
    '<a href="/grades">7:15 PM</a> '
    '<form method="post" action="/cart/add"><label>Quantity <select name="quantity"><option>1</option>'
    '<option>2</option></select></label> <button type="submit">Add to cart</button></form> '
    '<form method="post" action="/cart"><button type="submit" name="go">Proceed to checkout</button></form> '
    '<button type="button">Continue</button>'
)
ERRAND_OUTCOMES = (
    EN + "<h1>Your account</h1>"
    '<button type="button">Post comment</button> <button type="button">Delete</button> '
    '<button type="button">Cancel subscription</button> <button type="button">Sign up</button> '
    "<button type=\"button\" onclick=\"location.href = '/flights'\">Place order</button> "
    '<label><input type="checkbox" name="terms"> I agree to the terms</label> '
    '<form method="post" action="/next"><button type="submit">Continue</button></form> '
    '<form method="post" action="/post"><label>Full name <input name="fullname"></label> '
    '<label>Email <input type="email" name="email"></label> '
    '<label>Street address <input name="street"></label> '
    # The account's details with a new password: not a sign-in form, which
    # would hand the page over before the agent read it.
    '<label>Password <input type="password" name="pw" autocomplete="new-password"></label></form>'
)


def on_public_host(card):
    """The card as it reads on a public https host: the fake site is
    127.0.0.1 on a high port, which no approval ever covers."""
    return {**card, CARD_KEY: {**card[CARD_KEY], "origin": "https://shop.example.com"}}


async def errand_of(kits, action, **params):
    """``_page.errand`` of the card the live page gives this act, with the
    card's page facts."""
    card = await card_for(kits, action, **params)
    assert card.get("refused") is None, card
    return card[CARD_KEY]["errand"], card[CARD_KEY]


@pytest.mark.asyncio
async def test_the_steps_of_a_shop_errand_are_errand_steps_on_the_live_page(kits, fakesite_tls, page_at):
    """Accepting cookies, a search typed and sent by GET (its button, the
    field's submit, Enter), a showtime link, a quantity, "Add to cart" and
    "Proceed to checkout" (each a POST form's own button) and a script
    "Continue": none commits the person, so none needs a card."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-shop", ERRAND_SHOP, "Chain lube")))
    query = ref_of(before, '- searchbox "Search the shop"')
    steps = [
        ("click", {"ref": ref_of(before, '- button "Accept cookies"')}),
        ("fill", {"ref": query, "text": "chain lube"}),
        ("fill_form", {"fields": [{"ref": query, "text": "chain lube"}]}),
        ("submit", {"ref": query}),
        ("click", {"ref": ref_of(before, '- button "Go"')}),
        ("click", {"ref": ref_of(before, '- link "7:15 PM"')}),
        ("select", {"ref": ref_of(before, '- combobox "Quantity"'), "value": "2"}),
        ("click", {"ref": ref_of(before, '- button "Add to cart"')}),
        ("click", {"ref": ref_of(before, '- button "Proceed to checkout"')}),
        ("click", {"ref": ref_of(before, '- button "Continue"')}),
        ("press", {"key": "Tab"}),
    ]
    for action, params in steps:
        is_errand, page = await errand_of(kits, action, **params)
        assert is_errand is True and "money" not in page, (action, params, page)
    _is_errand, page = await errand_of(kits, "fill", ref=query, text="chain lube")
    assert page["fields"] == ["search"]
    _is_errand, page = await errand_of(kits, "click", ref=ref_of(before, '- link "7:15 PM"'))
    assert page["target"] == {"name": "7:15 PM", "words": "7:15 PM", "plain_link": True}
    # Enter from the search box sends that GET form: a site search too.
    await (await live_page(kits)).focus("input[name=q]")
    await read(kits, "snapshot")
    assert (await errand_of(kits, "press", key="Enter"))[0] is True


@pytest.mark.asyncio
async def test_outcomes_and_the_persons_details_are_never_errand_steps(kits, fakesite_tls, page_at):
    """Posting, deleting, cancelling a subscription, signing up, "Place
    order", agreeing to terms, a POST form's "Continue" that is no cart
    button, and typing a name, an email or an address each keep their card;
    a password field is refused before any card."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-no", ERRAND_OUTCOMES, "Account")))
    for action, params in [
        ("click", {"ref": ref_of(before, '- button "Post comment"')}),
        ("click", {"ref": ref_of(before, '- button "Delete"')}),
        ("click", {"ref": ref_of(before, '- button "Cancel subscription"')}),
        ("click", {"ref": ref_of(before, '- button "Sign up"')}),
        ("click", {"ref": ref_of(before, '- button "Place order"')}),
        ("check", {"ref": ref_of(before, '- checkbox "I agree to the terms"')}),
        ("click", {"ref": ref_of(before, '- button "Continue"')}),
        ("fill", {"ref": ref_of(before, '- textbox "Full name"'), "text": "Ada Lovelace"}),
        ("fill", {"ref": ref_of(before, '- textbox "Email"'), "text": "ada@example.com"}),
        ("fill", {"ref": ref_of(before, '- textbox "Street address"'), "text": "1 Main St"}),
    ]:
        is_errand, page = await errand_of(kits, action, **params)
        assert is_errand is False and "fields" not in page, (action, params, page)
    password = {"action": "fill", "ref": ref_of(before, '- textbox "Password"'), "text": "hunter2"}
    refused(kits[1].precheck(password, user_id=USER), "secure_field")


@pytest.mark.parametrize(
    ("lead", "is_errand"),
    [
        (TOTAL_LEAD, False),
        ("<h1>Tickets</h1><p>Your saved card will be charged.</p>", False),
        # A wallet button elsewhere on the page stops no step: the card would
        # still say so, and the wallet button itself is refused.
        ('<h1>Socks</h1><p>Price: $5.00</p><button type="button" aria-label="Buy with Google Pay">G Pay</button>',
         True),
    ],
)
@pytest.mark.asyncio
async def test_no_step_is_an_errand_step_next_to_an_order_total_or_a_card_on_file(
    kits, fakesite_tls, page_at, lead, is_errand
):
    body = EN + lead + '<button type="button">Continue</button><input type="search" aria-label="Search">'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-pay", body, "Tickets")))
    for action, params in [
        ("click", {"ref": ref_of(before, '- button "Continue"')}),
        ("fill", {"ref": ref_of(before, '- searchbox "Search"'), "text": "socks"}),
        ("press", {"key": "Tab"}),
    ]:
        card = await card_for(kits, action, **params)
        assert card[CARD_KEY]["errand"] is is_errand and card[CARD_KEY].get("money"), (action, card)
        assert errand_covers(on_public_host(card)) is is_errand


@pytest.mark.asyncio
async def test_a_page_in_another_language_runs_only_links_keys_and_search_boxes_unasked(kits, fakesite_tls, page_at):
    """The outcome words are English: on a page that says it is in German
    a "Kündigen" button reads as nothing, so it keeps its card. A link, a key
    and a search box are judged without words, so they still run."""
    body = (
        "<script>document.documentElement.lang = 'de';</script><h1>Konto</h1>"
        '<button type="button">Kündigen</button> <a href="/grades">19:15</a> '
        '<input type="search" aria-label="Suche">'
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-de", body, "Konto")))
    assert (await errand_of(kits, "click", ref=ref_of(before, '- button "Kündigen"')))[0] is False
    assert (await errand_of(kits, "click", ref=ref_of(before, '- link "19:15"')))[0] is True
    assert (await errand_of(kits, "fill", ref=ref_of(before, '- searchbox "Suche"'), text="x"))[0] is True


@pytest.mark.asyncio
async def test_an_errand_step_on_an_http_page_or_one_that_could_not_be_looked_at_is_none(kits, fakesite, page_at):
    before = await read(kits, "open", url=fakesite.url(page_at("/r-errand-http", ERRAND_SHOP, "Chain lube")))
    click = {"action": "click", "ref": ref_of(before, '- button "Continue"')}
    card = await kits[1].bind_async(click, user_id=USER, task_id="t1")
    assert card[CARD_KEY]["errand"] is False, card
    kit, _sessions, memory = fake_kit()
    remember(memory, ['- button "Next" [ref=e1]'])
    forged = {"action": "click", "ref": "e1", CARD_KEY: {"errand": True, "scheme": "https"}}
    card = await kit.bind_async(forged, user_id=USER, task_id="t1")
    assert card[CARD_KEY]["errand"] is False and "target" not in card[CARD_KEY], card


# ── an errand step that runs unasked: what the live page lets it do ──────────


async def unasked(kits, card):
    """Run *card* as the runtime runs an errand step: no person approved it,
    so its page is marked unasked."""
    marked = unasked_arguments(card)
    arguments = {k: v for k, v in marked.items() if k != "action"}
    return await kits[1].execute(card["action"], arguments, user_id=USER, task_id="t1", approved=True)


ORDER_BY_SCRIPT = [
    # A page the markers read as nothing to pay, whose "Continue" places the order.
    EN + "<h1>Review</h1><p>Chain lube 4 oz</p>"
    "<button type=\"button\" onclick=\"fetch('/api/orders', {method: 'POST'})\">Continue</button>",
    # The review's page: the card on file and the amount in words the markers miss.
    EN + "<h1>Review</h1><p>Order summary: Chain lube 4 oz, $9.99. Shipping free.</p><p>Card: Visa 4242</p>"
    "<button type=\"button\" onclick=\"fetch('/api/orders', {method: 'POST'})\">Continue</button>",
]


@pytest.mark.parametrize("body", ORDER_BY_SCRIPT, ids=["no-markers", "missed-markers"])
@pytest.mark.asyncio
async def test_an_unasked_step_never_reaches_an_order_address_whatever_the_page_shows(
    kits, fakesite_tls, page_at, body
):
    """A "Continue" whose script posts to /api/orders reads as an errand step
    when the page's markers miss the total and the card. Run unasked, the
    order request is stopped, the step answers ``auto_submit`` and the same
    step asks with a card next time; approved on that card, it runs as
    every approved act always did."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-order", body, "Review")))
    ref = ref_of(before, '- button "Continue"')
    card = await card_for(kits, "click", ref=ref)
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits)
    refused(done, "auto_submit")
    assert "browser.act" in done["error"] and "–" not in done["reason"] and "—" not in done["reason"]
    assert ("POST", "/api/orders") not in fakesite_tls.handled
    again = await card_for(kits, "click", ref=ref)
    assert again[CARD_KEY]["errand"] is False and not errand_covers(on_public_host(again))
    done = await approve(kits, again)
    await settled(kits)
    assert done["ok"] is True, done
    assert ("POST", "/api/orders") in fakesite_tls.handled


@pytest.mark.parametrize(
    "body, action, prefix, params, endpoint",
    [
        (EN + "<h1>Subscribe and save: Chain lube</h1><p>Next delivery: Dec 3</p>"
         "<label>Deliver every <select name=\"frequency\" onchange=\"fetch('/api/subscriptions/42', "
         "{method: 'POST', body: this.value})\"><option>1 month</option><option>2 months</option></select></label>",
         "select", '- combobox "Deliver every"', {"value": "2 months"}, "/api/subscriptions/42"),
        # Words on no list ("Make my profile public" is an outcome now): the
        # guard, not the words, stops what the page saves.
        (EN + "<h1>Settings</h1><label><input type=\"checkbox\" name=\"compact\" "
         "onchange=\"fetch('/api/profile/visibility', {method: 'POST'})\"> Compact view</label>",
         "check", '- checkbox "Compact view"', {}, "/api/profile/visibility"),
    ],
    ids=["subscription-frequency", "settings-tick"],
)
@pytest.mark.asyncio
async def test_a_choice_the_page_saves_at_once_is_not_saved_unasked(
    kits, fakesite_tls, page_at, body, action, prefix, params, endpoint
):
    """A select or a tick whose page saves it at once with a POST: run
    unasked, the POST is stopped and the step answers ``auto_submit``, so
    the next one asks with a card."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-save", body, "Settings")))
    card = await card_for(kits, action, ref=ref_of(before, prefix), **params)
    assert card[CARD_KEY]["errand"] is True, card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits)
    refused(done, "auto_submit")
    assert ("POST", endpoint) not in fakesite_tls.handled
    assert (await card_for(kits, action, ref=ref_of(before, prefix), **params))[CARD_KEY]["errand"] is False


@pytest.mark.parametrize("delay", [450, 700])
@pytest.mark.asyncio
async def test_a_choice_the_page_saves_a_moment_later_is_not_saved_unasked(kits, fakesite_tls, page_at, delay):
    """A debounced autosave: the send stop holds until the page has gone
    quiet, so the POST a moment after the choice is stopped too."""
    body = EN + (
        "<h1>Subscribe and save: Chain lube</h1><p>Next delivery: Dec 3</p>"
        "<label>Deliver every <select name=\"frequency\" onchange=\"setTimeout(() => fetch('/api/subscriptions/42', "
        f"{{method: 'POST', body: this.value}}), {delay})\"><option>1 month</option><option>2 months</option>"
        "</select></label>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-debounce", body, "Settings")))
    card = await card_for(kits, "select", ref=ref_of(before, '- combobox "Deliver every"'), value="2 months")
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits, 1200)
    refused(done, "auto_submit")
    assert ("POST", "/api/subscriptions/42") not in fakesite_tls.handled


# The fake site's answers to a POST that these tests need: a 307 that would
# send the same POST on to an order address, and Amazon's cart answering
# with its checkout's entry page.
_POST_ANSWERS = {
    "/api/step307": (307, "/api/orders"),
    "/cart/step307": (307, "/api/orders"),
    "/api/frame307": (307, "/place-order"),
    "/cart/frame307": (307, "/place-order"),
    "/gp/cart/view.html": (302, "/gp/buy/spc/handlers/display.html?hasWorkingJavascript=1"),
    "/cart/hop302": (302, "/cart/next"),  # whose GET (``chains``) answers with an order step
}


@pytest.fixture
def redirects(monkeypatch):
    original = _Handler.do_POST

    def do_post(handler):
        path = urlsplit(handler.path).path
        if path not in _POST_ANSWERS:
            original(handler)
            return
        handler._record("POST", path)
        handler.rfile.read(int(handler.headers.get("Content-Length") or 0))
        status, location = _POST_ANSWERS[path]
        handler._send(status, "text/plain", "", Location=location)

    monkeypatch.setattr(_Handler, "do_POST", do_post)


def _sends(script: str) -> str:
    return f'<button type="button" onclick="{script}">Continue</button>'


_FRAME_FORM = (
    '<iframe name="sink" style="width:1px;height:1px"></iframe>'
    '<form id="f" method="post" action="{path}" target="sink"></form>'
    + _sends("document.getElementById('f').submit()")
)
_REVIEW_MISSED = "<h1>Review</h1><p>Order summary: Chain lube 4 oz, $9.99. Shipping free.</p><p>Card: Visa 4242</p>"


@pytest.mark.parametrize(
    "body, never",
    [
        # A page's fetch to an ordinary address, and to a cart, answered
        # with a 307 that would send the same POST on to an order address.
        (_sends("fetch('/api/step307', {method: 'POST'})"), ("POST", "/api/orders")),
        (_sends("fetch('/cart/step307', {method: 'POST'})"), ("POST", "/api/orders")),
        # A form aimed at a hidden frame, answered with a 307 to an order step.
        (_FRAME_FORM.format(path="/api/frame307"), ("POST", "/place-order")),
        (_FRAME_FORM.format(path="/cart/frame307"), ("POST", "/place-order")),
        # Order endpoints on no list (WooCommerce, Magento), on a review page
        # whose markers miss the total and the card.
        (_REVIEW_MISSED + _sends("fetch('/?wc-ajax=checkout', {method: 'POST'})"), ("POST", "/")),
        (_REVIEW_MISSED + _sends("fetch('/rest/V1/carts/mine/payment-information', {method: 'POST'})"),
         ("POST", "/rest/V1/carts/mine/payment-information")),
        # An order step opened in a new tab.
        (_sends("window.open('/place-order?x=1')"), ("GET", "/place-order")),
    ],
    ids=["fetch-307", "cart-fetch-307", "frame-307", "cart-frame-307", "woocommerce", "magento", "new-tab"],
)
@pytest.mark.asyncio
async def test_an_unasked_step_sends_nothing_toward_an_order_by_any_route(
    kits, fakesite_tls, page_at, redirects, body, never
):
    """A script "Continue" that commits nothing by its words runs unasked,
    and the guard is what holds: whatever it sends, through a redirect, a
    frame, an order endpoint no list knows or a new tab, reaches no order.
    The step answers ``auto_submit`` and asks with a card next time; a
    form a script sends to a cart address is stopped too on a step that is
    no cart step (only a cart step, or the form the card judged, sends to
    a cart)."""
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-route", EN + body, "Review")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Continue"'))
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits, 600)
    refused(done, "auto_submit")
    assert never not in fakesite_tls.handled, fakesite_tls.handled
    assert (await card_for(kits, "click", ref=ref_of(before, '- button "Continue"')))[CARD_KEY]["errand"] is False


@pytest.mark.asyncio
async def test_an_approved_step_still_sends_where_its_page_sends(kits, fakesite_tls, page_at):
    """The card the stopped step gets next time, approved, runs in the
    write window approved acts always had."""
    body = EN + _REVIEW_MISSED + _sends("fetch('/?wc-ajax=checkout', {method: 'POST'})")
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-woo", body, "Review")))
    done = await unasked(kits, await card_for(kits, "click", ref=ref_of(before, '- button "Continue"')))
    refused(done, "auto_submit")
    done = await approve(kits, await card_for(kits, "click", ref=ref_of(before, '- button "Continue"')))
    await settled(kits)
    assert done["ok"] is True and ("POST", "/") in fakesite_tls.handled, done


OUTCOMES_OFF_THE_OLD_LIST = [
    ("Restart membership", "/api/membership/restart"),
    ("Resume membership", "/api/membership/resume"),
    ("Resubscribe", "/api/subscription"),
    ("Switch to annual billing", "/api/billing/plan"),
    ("Get Premium", "/api/plan"),
    ("Unsend", "/api/messages/9/unsend"),
    ("Disconnect", "/api/bank/disconnect"),
    ("Unblock", "/api/users/9/unblock"),
    ("Downvote", "/api/posts/9/vote"),
    ("Turn off two-factor authentication", "/api/security/2fa"),
    ("Make profile public", "/api/profile/visibility"),
    ("Sell", "/api/holdings/sell"),
    ("Request", "/api/payments/request"),
]


@pytest.mark.parametrize("words, endpoint", OUTCOMES_OFF_THE_OLD_LIST)
@pytest.mark.asyncio
async def test_an_outcome_the_old_word_list_missed_gets_a_card_and_sends_nothing_unasked(
    kits, fakesite_tls, page_at, words, endpoint
):
    """Each is an outcome now. Run unasked anyway (a word still missing),
    its POST is stopped by the guard, so a missing word costs one card."""
    body = EN + (
        "<h1>Your account</h1><p>Premium: $22.99 a month</p>"
        f"<button type=\"button\" onclick=\"fetch('{endpoint}', {{method: 'POST'}})\">{words}</button>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-outcome", body, "Account")))
    card = await card_for(kits, "click", ref=ref_of(before, f'- button "{words}"'))
    assert card[CARD_KEY]["errand"] is False and not errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits)
    refused(done, "auto_submit")
    assert ("POST", endpoint) not in fakesite_tls.handled


@pytest.mark.parametrize(
    "body, prefix",
    [
        ('<div class="oauth-consent"><h1>Acme Notes wants to access your account</h1>'
         "<p>It will be able to read, send and delete your email.</p>"
         '<form method="post" action="/oauth/approve"><button type="submit">Allow</button></form></div>',
         '- button "Allow"'),
        ('<div role="dialog" aria-label="Updated terms"><p>By selecting I agree, you consent to the '
         "updated Terms of Service, including binding arbitration and a class action waiver.</p>"
         "<button type=\"button\" onclick=\"fetch('/api/terms/accept', {method: 'POST'})\">I agree</button></div>",
         '- button "I agree"'),
        ('<div role="dialog" aria-label="Invitation"><p>Sam invited you to join the team Acme. '
         "By accepting you consent to share your profile.</p>"
         '<form method="post" action="/api/invitations/9"><button type="submit">Accept</button></form></div>',
         '- button "Accept"'),
    ],
    ids=["oauth-allow", "terms-agree", "invite-accept"],
)
@pytest.mark.asyncio
async def test_agreeing_in_a_region_that_says_consent_but_not_cookies_gets_a_card(kits, fakesite_tls, page_at, body, prefix):
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-consent", EN + body, "Page")))
    card = await card_for(kits, "click", ref=ref_of(before, prefix))
    assert card[CARD_KEY]["errand"] is False and not errand_covers(on_public_host(card)), card[CARD_KEY]


@pytest.mark.asyncio
async def test_a_cookie_banner_that_also_asks_for_terms_sends_nothing_unasked(kits, fakesite_tls, page_at):
    """Its "I agree" reads as a cookie choice, so it runs unasked; what it
    sends is no cookie form, so the guard stops it and it asks next time."""
    body = EN + (
        '<div role="dialog" aria-label="Cookies and terms"><p>We use cookies. By selecting I agree you also '
        "accept our updated Terms of Service.</p>"
        "<button type=\"button\" onclick=\"fetch('/api/terms/accept', {method: 'POST'})\">I agree</button></div>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-cookie-terms", body, "News")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "I agree"'))
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits)
    refused(done, "auto_submit")
    assert ("POST", "/api/terms/accept") not in fakesite_tls.handled


@pytest.mark.asyncio
async def test_unasked_cart_steps_still_reach_the_cart(kits, fakesite_tls, page_at):
    """A quantity the cart page saves itself (a POST to /cart/...) and an
    "Add to cart" that posts its form both run unasked, all the way."""
    body = EN + (
        "<h1>Your cart</h1><label>Quantity <select name=\"quantity\" "
        "onchange=\"fetch('/cart/change.js', {method: 'POST', body: this.value})\">"
        "<option>1</option><option>2</option></select></label>"
        '<form method="post" action="/cart/add"><button type="submit">Add to cart</button></form>'
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-cart", body, "Your cart")))
    card = await card_for(kits, "select", ref=ref_of(before, '- combobox "Quantity"'), value="2")
    assert card[CARD_KEY]["errand"] is True
    done = await unasked(kits, card)
    await settled(kits)
    assert done["ok"] is True, done
    assert ("POST", "/cart/change.js") in fakesite_tls.handled
    card = await card_for(kits, "click", ref=ref_of(done, '- button "Add to cart"'))
    assert card[CARD_KEY]["errand"] is True
    done = await unasked(kits, card)
    assert done["ok"] is True and any("Thanks" in line for line in done["outline"]), done
    assert ("POST", "/cart/add") in fakesite_tls.handled


@pytest.mark.asyncio
async def test_an_unasked_link_opens_a_page_that_loads_itself_by_post(kits, fakesite_tls, page_at):
    """A showtime link run unasked opens its seat page, which asks for its
    seats by POST as it loads: a link sends nothing itself, so that page
    loads as it would for the person."""
    page_at("/r-unasked-seats", EN + "<h1>Seats</h1><script>fetch('/post', {method: 'POST'})</script>", "Seats")
    body = EN + '<h1>Paper Tiger</h1><a href="/r-unasked-seats">7:15 PM</a>'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-link", body, "Showtimes")))
    card = await card_for(kits, "click", ref=ref_of(before, '- link "7:15 PM"'))
    assert card[CARD_KEY]["errand"] is True
    done = await unasked(kits, card)
    await settled(kits)
    assert done["ok"] is True and any("Seats" in line for line in done["outline"]), done
    assert ("POST", "/post") in fakesite_tls.handled


# Magento's order endpoint, which no order list knows.
_OFF_LIST = "/rest/V1/carts/mine/payment-information"


def _spa_link(words: str, *, before: str = "") -> str:
    """A link a single-page app's delegated click handler takes over (no
    onclick of its own): it sends the order by fetch, then opens the link."""
    return (
        f'<a href="/r-spa-done" data-spa>{words}</a>'
        "<script>document.addEventListener('click', e => { const a = e.target.closest('a[data-spa]');"
        f" if (!a) return; e.preventDefault(); {before}fetch('{_OFF_LIST}', {{method: 'POST', body: 'order'}})"
        ".then(() => location.assign(a.href)); });</script>"
    )


@pytest.mark.parametrize("before", ["", "history.pushState({}, '', a.href); "], ids=["handler", "after-push-state"])
@pytest.mark.asyncio
async def test_an_unasked_link_whose_page_script_sends_is_stopped_like_a_script_button(
    kits, fakesite_tls, page_at, before
):
    """A plain link run unasked has the send stop until its page commits a
    new document: a link a script takes over sends nothing but a cart, even
    after it changed the address in place (pushState is no new document).
    The step answers ``auto_submit`` and its link is never followed."""
    page_at("/r-spa-done", EN + "<h1>Thank you</h1>", "Thanks")
    body = EN + _REVIEW_MISSED + _spa_link("Continue", before=before)
    before_read = await read(kits, "open", url=fakesite_tls.url(page_at("/r-spa-link", body, "Review")))
    card = await card_for(kits, "click", ref=ref_of(before_read, '- link "Continue"'))
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits, 600)
    refused(done, "auto_submit")
    assert ("POST", _OFF_LIST) not in fakesite_tls.handled
    assert ("GET", "/r-spa-done") not in fakesite_tls.handled


@pytest.mark.parametrize("words", ["Place order", "Buy now", "Book now"])
@pytest.mark.asyncio
async def test_a_plain_link_worded_like_a_purchase_gets_a_card(kits, fakesite_tls, page_at, words):
    body = EN + "<h1>Review</h1><p>Chain lube 4 oz</p>" + _spa_link(words)
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-buy-link", body, "Review")))
    card = await card_for(kits, "click", ref=ref_of(before, f'- link "{words}"'))
    assert card.get("refused") is None and card[CARD_KEY]["errand"] is False, card
    assert not errand_covers(on_public_host(card))


@pytest.mark.asyncio
async def test_an_unasked_step_sends_nothing_on_a_websocket(kits, fakesite_tls, page_at):
    """A shop that runs its clicks over one socket: what the page sends on
    it while the step runs is dropped, and the step asks first next time."""
    script = "const ws = new WebSocket('wss://' + location.host + '/live'); ws.onopen = () => ws.send('placeOrder:cart-1');"
    body = EN + _REVIEW_MISSED + _sends(script)
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-ws", body, "Review")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Continue"'))
    assert card[CARD_KEY]["errand"] is True, card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits, 800)
    refused(done, "auto_submit")
    assert ("WS", "placeOrder:cart-1") not in fakesite_tls.handled
    assert (await card_for(kits, "click", ref=ref_of(before, '- button "Continue"')))[CARD_KEY]["errand"] is False


@pytest.fixture
def chains(monkeypatch):
    """GETs the fake site answers with a redirect to an order step."""
    for path in ("/cart/next", "/r-get", "/r-frame"):
        monkeypatch.setitem(REDIRECTS, path, "/place-order")


@pytest.mark.parametrize(
    "script",
    [
        "fetch('/r-get')",
        "new Image().src = '/r-get'",
        "document.body.appendChild(Object.assign(document.createElement('iframe'), {src: '/r-frame'}))",
    ],
    ids=["get-fetch", "image", "frame"],
)
@pytest.mark.asyncio
async def test_an_unasked_steps_page_reaches_no_order_step_through_a_redirect(
    kits, fakesite_tls, page_at, chains, script
):
    """A GET fetch, an image or a frame whose address redirects to an order
    step: every hop is judged while the step runs, so the order step is
    never opened, and the step asks first next time."""
    body = EN + _REVIEW_MISSED + _sends(script)
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-chain", body, "Review")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Continue"'))
    assert card[CARD_KEY]["errand"] is True, card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits, 800)
    refused(done, "auto_submit")
    assert ("GET", "/place-order") not in fakesite_tls.handled, fakesite_tls.handled


@pytest.mark.asyncio
async def test_a_cart_send_whose_redirect_chain_ends_at_an_order_step_is_held_there_and_the_step_is_done(
    kits, fakesite_tls, page_at, redirects, chains
):
    """An "Add to cart" whose cart answers 302 to another cart address,
    which answers 302 to an order step: the cart add goes out, the hop to
    the order step does not. What the step itself sent went out, so it is
    done (never "not taken", which would add the item twice) with a note,
    and it asks first next time."""
    body = EN + "<h1>Chain lube 4 oz</h1>" + (
        "<button type=\"button\" onclick=\"fetch('/cart/hop302', {method: 'POST'})\">Add to cart</button>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-cart-chain", body, "Shop")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"'))
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits, 600)
    assert done["ok"] is True and "held back" in done["note"], done
    assert "–" not in done["note"] and "—" not in done["note"]
    handled = fakesite_tls.handled
    assert ("POST", "/cart/hop302") in handled and ("GET", "/cart/next") in handled
    assert ("GET", "/place-order") not in handled, handled
    assert (await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"')))[CARD_KEY]["errand"] is False


@pytest.mark.asyncio
async def test_an_add_to_cart_whose_page_sends_a_beacon_is_done_and_runs_unasked_again(kits, fakesite_tls, page_at):
    """Amazon's "Add to Cart" on a page that sends a metrics beacon when
    clicked: the beacon is held back without counting as a send, the cart
    add goes out once, the step is done with a note, and the same step runs
    unasked again next time."""
    body = AMAZON_ADD_TO_CART + (
        "<script>document.addEventListener('click', () => navigator.sendBeacon('/1/batch/1/OE/', 'csm'));</script>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-beacon", body, "Shop")))
    line = next(line for line in before["outline"] if "Add to Cart" in line and "button" in line)
    prefix = line.strip().split(" [ref=")[0]
    card = await card_for(kits, "click", ref=ref_of(before, prefix))
    assert card[CARD_KEY]["errand"] is True, card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits)
    assert done["ok"] is True and "held back" in done["note"], done
    assert fakesite_tls.handled.count(("POST", "/cart/add")) == 1
    assert ("POST", "/1/batch/1/OE/") not in fakesite_tls.handled
    again = await read(kits, "open", url=fakesite_tls.url("/r-beacon"))
    assert (await card_for(kits, "click", ref=ref_of(again, prefix)))[CARD_KEY]["errand"] is True


@pytest.mark.asyncio
async def test_a_step_stopped_unasked_asks_first_next_time_even_when_a_new_look_renumbered_it(
    kits, fakesite_tls, page_at
):
    """Ask-first remembers the step by its page's address and its control's
    name, not by its ref: the page drew a link above it, so the same
    "Continue" has another ref, and it still gets its card."""
    script = _sends("fetch('/api/orders', {method: 'POST'})")
    path = page_at("/r-ask-first", EN + "<h1>Review</h1><p>Chain lube 4 oz</p>" + script, "Review")
    before = await read(kits, "open", url=fakesite_tls.url(path))
    ref = ref_of(before, '- button "Continue"')
    refused(await unasked(kits, await card_for(kits, "click", ref=ref)), "auto_submit")
    page_at(path, EN + '<h1>Review</h1><p><a href="/grades">Help</a></p><p>Chain lube 4 oz</p>' + script, "Review")
    after = await read(kits, "open", url=fakesite_tls.url(path))
    moved = ref_of(after, '- button "Continue"')
    assert moved != ref
    assert (await card_for(kits, "click", ref=moved))[CARD_KEY]["errand"] is False


@pytest.mark.parametrize(
    "words, endpoint",
    [
        *[("Continue", endpoint) for endpoint in (
            "/cart/complete", "/cart/submit", "/basket/confirm", "/cart/payment-information", "/api/cart/place",
            "/cart/change.js",
        )],
        ("Add to cart", "/cart/complete"),
    ],
)
@pytest.mark.asyncio
async def test_an_unasked_page_script_reaches_a_cart_only_on_a_cart_step_and_never_a_carts_order(
    kits, fakesite_tls, page_at, words, endpoint
):
    """A "Continue" is no cart step, so its script sends nothing even to a
    cart; and a cart address that names an order after the cart is no
    cart for any step."""
    body = EN + _REVIEW_MISSED + (
        f"<button type=\"button\" onclick=\"fetch('{endpoint}', {{method: 'POST'}})\">{words}</button>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-cart-order", body, "Review")))
    card = await card_for(kits, "click", ref=ref_of(before, f'- button "{words}"'))
    assert card[CARD_KEY]["errand"] is True, card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits)
    refused(done, "auto_submit")
    assert ("POST", endpoint) not in fakesite_tls.handled


@pytest.mark.asyncio
async def test_an_unasked_form_whose_address_moved_after_the_card_is_not_sent(kits, fakesite_tls, page_at):
    """The card pins the address the form was judged by. A page that moves
    the form elsewhere before the step runs (an "Add to cart" now aimed at
    a checkout session) has changed under the card: the step is refused
    and nothing is sent."""
    body = EN + (
        '<h1>Chain lube 4 oz</h1><form id="f" method="post" action="/cart/add">'
        '<button type="submit">Add to cart</button></form>'
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-moved-form", body, "Shop")))
    card = await card_for(kits, "click", ref=ref_of(before, '- button "Add to cart"'))
    assert card[CARD_KEY]["errand"] is True and card[CARD_KEY]["target"]["action"] == "/cart/add", card[CARD_KEY]
    await (await live_page(kits)).evaluate("document.getElementById('f').action = '/api/v2/checkout-session'")
    done = await unasked(kits, card)
    await settled(kits)
    refused(done, "outline_changed")
    assert ("POST", "/api/v2/checkout-session") not in fakesite_tls.handled
    assert ("POST", "/cart/add") not in fakesite_tls.handled


@pytest.mark.parametrize(
    "words",
    [
        "Finish Cancellation", "Continue to cancel", "Yes, cancel", "End membership", "Adopt and Sign",
        "Allow", "Accept", "Connect", "Remove", "Enroll",
    ],
)
@pytest.mark.asyncio
async def test_a_script_button_that_does_an_outcome_is_no_errand_step(kits, fakesite_tls, page_at, words):
    body = EN + (
        "<h1>Your account</h1>"
        f"<button type=\"button\" onclick=\"fetch('/api/do', {{method: 'POST'}})\">{words}</button>"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-outcome", body, "Account")))
    card = await card_for(kits, "click", ref=ref_of(before, f'- button "{words}"'))
    assert card[CARD_KEY]["errand"] is False and not errand_covers(on_public_host(card)), card[CARD_KEY]


@pytest.mark.parametrize(
    "label",
    [
        "I have read and understood the Terms and Conditions",
        "I consent to the processing of my personal data",
        "I acknowledge the non-refundable cancellation policy",
        "Keep me subscribed to marketing emails",
    ],
)
@pytest.mark.asyncio
async def test_a_consent_or_assent_tick_is_no_errand_step(kits, fakesite_tls, page_at, label):
    body = EN + f'<h1>Booking</h1><label><input type="checkbox" name="c"> {label}</label>'
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-tick", body, "Booking")))
    card = await card_for(kits, "check", ref=ref_of(before, f'- checkbox "{label}"'))
    assert card[CARD_KEY]["errand"] is False and not errand_covers(on_public_host(card)), card[CARD_KEY]


@pytest.mark.parametrize("words", ["Increase credit limit", "Increase my monthly donation", "Increase seats"])
@pytest.mark.asyncio
async def test_a_post_button_that_only_mentions_increasing_is_no_cart_step(kits, fakesite_tls, page_at, words):
    body = EN + (
        "<h1>Your account</h1><p>Available credit: $5,000</p>"
        f'<form method="post" action="/post"><button type="submit">{words}</button></form>'
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-qty", body, "Account")))
    card = await card_for(kits, "click", ref=ref_of(before, f'- button "{words}"'))
    assert card[CARD_KEY]["errand"] is False, card[CARD_KEY]


@pytest.mark.asyncio
async def test_a_page_that_names_no_language_runs_only_links_and_search_boxes_unasked(kits, fakesite_tls, page_at):
    """A page with no lang attribute is in a language nobody knows: its
    buttons ("Abo jetzt kündigen", even "Continue") keep their card; a
    link, a key and a search box are judged without words and still run."""
    body = (
        "<h1>Mein Konto</h1>"
        "<button type=\"button\" onclick=\"fetch('/api/abo/kuendigen', {method: 'POST'})\">Abo jetzt kündigen</button>"
        '<button type="button">Continue</button> <a href="/grades">19:15</a> <input type="search" aria-label="Suche">'
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-nolang", body, "Konto")))
    assert (await errand_of(kits, "click", ref=ref_of(before, '- button "Abo jetzt kündigen"')))[0] is False
    assert (await errand_of(kits, "click", ref=ref_of(before, '- button "Continue"')))[0] is False
    assert (await errand_of(kits, "click", ref=ref_of(before, '- link "19:15"')))[0] is True
    assert (await errand_of(kits, "fill", ref=ref_of(before, '- searchbox "Suche"'), text="x"))[0] is True
    assert (await errand_of(kits, "press", key="Tab"))[0] is True


# Amazon's product page, in its own markup shape (no real site): the
# input's name is "submit.add-to-cart", which no person reads.
AMAZON_ADD_TO_CART = EN + (
    "<h1>Finish Line Dry Teflon Bike Chain Lube, 4 oz</h1><p>$9.99</p>"
    '<form id="addToCart" method="post" action="/cart/add">'
    '<label>Quantity <select name="quantity"><option>1</option><option>2</option></select></label>'
    '<span id="submit.add-to-cart"><span>'
    '<input id="add-to-cart-button" name="submit.add-to-cart" title="Add to Shopping Cart" type="submit" '
    'value="Add to Cart" aria-labelledby="submit.add-to-cart-announce">'
    '<span id="submit.add-to-cart-announce" aria-hidden="true">Add to Cart</span></span></span>'
    "</form>"
)
# Amazon's cookie banner in Europe: a POST form of its own.
AMAZON_COOKIES = EN + (
    "<h1>Bike chain lube</h1>"
    '<div id="sp-cc-wrapper"><form id="sp-cc" method="post" action="/cookieprefs?ref_=portal_banner_all">'
    "<p>Select your cookie preferences</p><p>We use cookies and similar tools to improve your shopping.</p>"
    '<input type="hidden" name="operation" value="accept">'
    '<input type="submit" name="accept" id="sp-cc-accept" value="Accept"></form></div>'
)
# Shopify: a wallet button beside "Add to cart", and a cart that sends
# itself to /cart with "Check out".
SHOPIFY_PRODUCT = EN + (
    '<h1>Chain lube</h1><p>$9.99</p><button type="button" aria-label="Buy with Shop Pay">Shop Pay</button>'
    '<form method="post" action="/cart/add"><button type="submit" name="add">Add to cart</button></form>'
)
SHOPIFY_CART = EN + (
    '<h1>Your cart</h1><p>Chain lube $9.99</p><form method="post" action="/cart">'
    '<button type="submit" name="checkout">Check out</button></form>'
)
CONSENT_BANNER = EN + (
    '<h1>News</h1><div role="dialog" aria-label="Cookies"><p>We and our partners use cookies.</p>'
    '<button type="button">Agree and close</button></div>'
)
SHOWTIME_LINK = EN + '<h1>Paper Tiger</h1><a href="/grades">7:15 PM</a>'


@pytest.mark.parametrize(
    "body, prefix, sent",
    [
        (AMAZON_ADD_TO_CART, None, ("POST", "/cart/add")),
        (AMAZON_ADD_TO_CART.replace('action="/cart/add"', 'action="/gp/product/handle-buy-box/ref=dp_start-bbf_1"'),
         None, ("POST", "/gp/product/handle-buy-box/ref=dp_start-bbf_1")),
        (EN + "<h1>Chain lube</h1><p>$9.99</p><button type=\"button\" "
         "onclick=\"fetch('/gp/add-to-cart/json', {method: 'POST', body: 'asin=B0001'})\">Add to Cart</button>",
         None, ("POST", "/gp/add-to-cart/json")),
        (AMAZON_COOKIES, '- button "Accept"', ("POST", "/cookieprefs")),
        (SHOPIFY_PRODUCT, '- button "Add to cart"', ("POST", "/cart/add")),
        (SHOPIFY_CART, '- button "Check out"', ("POST", "/cart")),
        (CONSENT_BANNER, '- button "Agree and close"', None),
        (SHOWTIME_LINK, '- link "7:15 PM"', ("GET", "/grades")),
    ],
    ids=["amazon-add-to-cart", "amazon-buy-box-form", "amazon-add-to-cart-json", "amazon-cookies",
         "shopify-add-next-to-shop-pay", "shopify-check-out", "agree-and-close", "showtime-link"],
)
@pytest.mark.asyncio
async def test_the_owners_own_steps_run_unasked_on_real_shop_markup(kits, fakesite_tls, page_at, body, prefix, sent):
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-errand-real", body, "Shop")))
    if prefix is None:
        line = next(line for line in before["outline"] if "Add to Cart" in line and "button" in line)
        prefix = line.strip().split(" [ref=")[0]
    card = await card_for(kits, "click", ref=ref_of(before, prefix))
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    if body is SHOPIFY_PRODUCT:
        # The wallet button itself is still refused.
        refused(await card_for(kits, "click", ref=ref_of(before, '- button "Buy with Shop Pay"')), "use_checkout")
    done = await unasked(kits, card)
    await settled(kits)
    assert done["ok"] is True, done
    assert sent is None or sent in fakesite_tls.handled, fakesite_tls.handled


@pytest.mark.asyncio
async def test_amazons_proceed_to_checkout_opens_the_checkouts_first_page_unasked(kits, fakesite_tls, page_at, redirects):
    """Amazon's cart form answers with a 302 to /gp/buy/spc/handlers/display.html,
    its checkout's entry page: opened by GET it orders nothing, so the step
    runs unasked and lands there. Paying is still browser.checkout's."""
    page_at("/gp/buy/spc/handlers/display.html", EN + "<h1>Review your order</h1>", "Checkout")
    body = EN + (
        "<h1>Shopping Cart</h1><p>Subtotal (1 item): $9.99</p>"
        '<form method="post" action="/gp/cart/view.html?ref_=ox_sc_proceed">'
        '<input type="submit" name="proceedToRetailCheckout" value="Proceed to checkout"></form>'
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-amazon-cart", body, "Amazon Cart")))
    line = next(line for line in before["outline"] if "Proceed to checkout" in line and "button" in line)
    card = await card_for(kits, "click", ref=ref_of(before, line.strip().split(" [ref=")[0]))
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    await settled(kits)
    assert done["ok"] is True, done
    assert ("GET", "/gp/buy/spc/handlers/display.html") in fakesite_tls.handled, fakesite_tls.handled


@pytest.mark.asyncio
async def test_typing_into_a_search_box_whose_suggestions_come_by_get_runs_unasked(kits, fakesite_tls, page_at):
    body = EN + (
        '<h1>Shop</h1><input type="search" aria-label="Search the shop" '
        "oninput=\"fetch('/api/suggest?q=' + encodeURIComponent(this.value))\">"
    )
    before = await read(kits, "open", url=fakesite_tls.url(page_at("/r-unasked-search", body, "Shop")))
    card = await card_for(kits, "fill", ref=ref_of(before, '- searchbox "Search the shop"'), text="chain lube")
    assert card[CARD_KEY]["errand"] is True and errand_covers(on_public_host(card)), card[CARD_KEY]
    done = await unasked(kits, card)
    assert done["ok"] is True, done
    assert ("GET", "/api/suggest") in fakesite_tls.handled
