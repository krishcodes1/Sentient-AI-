"""What browser.read, browser.act and browser.checkout share (spec §5).

One browser session serves three toolkits, and each of them ends its
actions the same way: a challenge check, a fresh outline, a summary line
for the task, a note in the page memory the write tiers bind their cards
to. Keeping that in one place means a page is described to the model in
exactly one way whichever tool looked at it, and a masked screenshot is
taken by exactly one function, so the mask can never drift between the
picture the person sees after a read and the one on a purchase card.

Moved here from ``actions.py`` unchanged in behaviour; ``actions.py``
keeps its old names as aliases so browser.read's tests and callers see
no difference. The handoff window lives here too (``hand_over`` /
``take_back``): whichever toolkit hands the page to the person opens it,
and whichever acts next shuts it, so a sign-in or a one-time code the
person types during a checkout's handoff passes the guard the same way
it does after a read's. Nothing here logs page text, typed text or a URL's query
string: those are the person's data and log lines are persistent.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from typing import Any, Optional, Protocol, Sequence

import structlog

from services.tools.browser import snapshot as snap
from services.tools.browser.checkout import markers
from services.tools.browser.handoff import Challenge
from services.tools.browser.pagememory import PageMemory
from services.tools.browser.session import BrowserSession

try:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
except ImportError:  # the capability reports the missing install; the module must import

    class PlaywrightError(Exception):  # type: ignore[no-redef]
        pass

    class PlaywrightTimeoutError(PlaywrightError):  # type: ignore[no-redef]
        pass


logger = structlog.get_logger(__name__)

BROWSER_MAX_ACTIONS = 60
BROWSER_MAX_USD = 0.25
OUTLINE_CHARS = 8000
FULL_OUTLINE_CHARS = 24000
NAVIGATION_TIMEOUT_MS = 20_000
# A ref that no longer resolves must answer "stale" quickly, not hang.
REF_TIMEOUT_MS = 3_000
# How long a frame with no URL may take to answer before a picture treats
# it as having no document (``frame_evaluate``).
EMPTY_FRAME_TIMEOUT_S = 0.5
JPEG_QUALITY = 70
# Fields whose pixels never leave the machine, even in a screenshot the
# person asked for: the checkout's classifier marks them (``mask_locators``)
# and this selector finds the marks and the plain attribute cases.
MASK_SELECTOR = markers.MASK_SELECTOR
_LOG_DETAIL_CHARS = 200
_REF_RE = re.compile(r"(f\d+)?e\d+")
# A URL's query string and fragment inside exception text: Playwright
# errors quote the URL they failed on, and on ACCOUNT-mode pages that part
# carries session ids and OAuth codes (the guard's logs drop it too).
_URL_TAIL_RE = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s?#'\"<>]*)[?#][^\s'\"<>]*")
# Playwright's call log echoes the value a fill or select was given
# (``fill("4242…")``), and the message carries the value again after a
# retry; neither belongs in a log line.
_CALL_LOG_RE = re.compile(r"\s*Call log:.*", re.DOTALL)
_TYPED_VALUE_RE = re.compile(r"\b(fill|type|select_option|selectOption|press_sequentially)\((\"|').*?\2\)")
# The name a summary shows for an element ('click "Grades"', 'Typed 12
# characters into "Email"'). A field is named by its label, never by its
# value: el.value is an autofilled password, a card number or whatever the
# owner typed, and the summary stays in the model's context for the rest
# of the task. Only button-like inputs are named by their value, which is
# their visible caption.
ELEMENT_NAME_JS = r"""
el => {
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const field = ['input', 'textarea', 'select'].includes(tag) || el.isContentEditable;
  const caption = tag === 'input' && ['button', 'submit', 'reset'].includes(type) ? el.value : '';
  // A label wrapping its control ("<label>Country <select>…</select></label>")
  // names it by the label's own words, not the options' text.
  const labelText = lab => {
    const copy = lab.cloneNode(true);
    copy.querySelectorAll('input, select, textarea, button').forEach(n => n.remove());
    return copy.textContent || '';
  };
  const label = el.labels && el.labels.length ? labelText(el.labels[0]) : '';
  return [el.getAttribute('aria-label'), field ? label : el.innerText, caption,
          el.getAttribute('title'), el.getAttribute('placeholder'), el.getAttribute('alt')]
    .map(s => (s || '').replace(/\s+/g, ' ').trim()).find(s => s) || '';
}
"""
# What kind of secret a field holds, from its live attributes and labels:
# the one rule ``snapshot.page_facts``, the screenshot mask and the
# checkout share (password, one-time code, cc-* by token or by what the
# site calls the field). Null for an ordinary field. The page memory
# records this for every field the outline shows, empty ones included
# (page_facts only asks about fields with a value, and a login form is
# empty before anyone types into it).
FIELD_KIND_JS = markers.FIELD_KIND_JS
_FIELD_LINE_RE = re.compile(
    r"^\s*- '?(?:textbox|searchbox|spinbutton|combobox)\b.*\[ref=((?:f\d+)?e\d+)\]"
)


class HandoffDetector(Protocol):
    """What the toolkits need from services/tools/browser/handoff.py."""

    async def detect_challenge(self, page: Any) -> Optional[Challenge]: ...


def error_result(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def stale_result() -> dict[str, Any]:
    return {"ok": False, "error": "stale ref: re-snapshot", "stale_ref": True}


def log_detail(exc: BaseException) -> str:
    """The exception text a log line may keep: the call log (which quotes
    typed values) goes, a quoted fill/select argument goes, and URLs lose
    their query string and fragment, all before truncation so a cut can
    never expose one."""
    text = _CALL_LOG_RE.sub("", str(exc))
    text = _TYPED_VALUE_RE.sub(r"\1(…)", text)
    return _URL_TAIL_RE.sub(r"\1", text)[:_LOG_DETAIL_CHARS]


def log_failure(event: str, exc: BaseException, **fields: Any) -> None:
    logger.warning(event, error_type=type(exc).__name__, error=log_detail(exc), **fields)


def valid_ref(ref: Any) -> bool:
    return isinstance(ref, str) and _REF_RE.fullmatch(ref) is not None


def call_key(action: str, params: dict[str, Any]) -> str:
    """The loop detector's key: the action and its arguments, hashed so
    the per-task history never holds typed text."""
    return hashlib.sha1(
        json.dumps([action, params], sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def cap_refusal(task: Any) -> Optional[dict[str, Any]]:
    """The action and spend caps every browser toolkit enforces on the
    shared TaskState; the runtime turns the result into "Continue?"."""
    if task.actions >= BROWSER_MAX_ACTIONS:
        return {
            "ok": False,
            "cap": "actions",
            "resume_hint": (
                f"This task has used {task.actions} browser actions (the cap is "
                f"{BROWSER_MAX_ACTIONS}). Ask the person whether to continue."
            ),
        }
    if task.spend_usd >= BROWSER_MAX_USD:
        return {
            "ok": False,
            "cap": "spend",
            "resume_hint": (
                f"This task has spent about ${task.spend_usd:.2f} (the cap is "
                f"${BROWSER_MAX_USD:.2f}). Ask the person whether to continue."
            ),
        }
    return None


def where(session: BrowserSession, page: Any) -> str:
    return snap.strip_url(page.url, session.mode == "account")


async def frame_evaluate(frame: Any, script: str, *, quick: bool = False) -> Any:
    """``frame.evaluate`` bounded by REF_TIMEOUT_MS. Playwright's has no
    timeout, and a frame whose document never loaded (a lazy video embed
    far below the fold: its URL stays "") never answers, so one such
    frame would hold every picture, card and step of the page forever.
    With *quick*, a frame with no URL gets EMPTY_FRAME_TIMEOUT_S: one
    whose parent wrote into it shares the parent's thread and answers at
    once, so waiting longer only delays a picture (never a judgement:
    those keep the full bound). Raises ``asyncio.TimeoutError`` when the
    frame does not answer."""
    timeout = EMPTY_FRAME_TIMEOUT_S if quick and not frame.url else REF_TIMEOUT_MS / 1000
    return await asyncio.wait_for(frame.evaluate(script), timeout)


async def _mask_whole_frame(frame: Any) -> bool:
    """Mark the ``<iframe>`` element of a frame that would not run the
    classifier and has no document (URL ""), so the picture blacks out
    its whole box, asked of its parent, which answers. Its own locator is
    then left out: the screenshot would wait on that frame too."""
    if frame.url:
        return False
    try:
        element = await asyncio.wait_for(frame.frame_element(), REF_TIMEOUT_MS / 1000)
        try:
            await asyncio.wait_for(
                element.evaluate("(el, name) => el.setAttribute(name, '')", markers.MASK_ATTRIBUTE),
                REF_TIMEOUT_MS / 1000,
            )
        finally:
            await element.dispose()
    except Exception as exc:  # noqa: BLE001 - its own locator stays in the mask
        logger.debug("browser_mask_frame_failed", error_type=type(exc).__name__)
        return False
    return True


async def mask_locators(page: Any, refs: Sequence[str] = ()) -> list[Any]:
    """The locators a screenshot blacks out: every secret field in every
    frame, plus the fields at *refs* (a checkout's card fields) while
    they still resolve.

    Every frame first runs the classifier, which marks the fields it
    finds (a card field named by its label has no attribute a selector
    could match), then ``MASK_SELECTOR`` finds the marks and the plain
    cases. ``page.locator`` never looks inside an iframe, and an embedded
    IdP login or card form is exactly where a password or card number
    sits. A frame that will not run the script (mid-navigation, gone)
    keeps the selector part, except one with no document at all, whose
    whole box is blacked out instead (``_mask_whole_frame``); a ref that
    no longer resolves is left out, because a ref into a frame that
    navigated away fails the whole screenshot. Frames are asked at once,
    each for at most REF_TIMEOUT_MS (``frame_evaluate``)."""

    async def mark(frame: Any) -> Optional[Any]:
        try:
            await frame_evaluate(frame, markers.MARK_SECRET_FIELDS_JS, quick=True)
        except Exception as exc:  # noqa: BLE001 - the selector still masks by attribute
            logger.debug("browser_mask_mark_failed", error_type=type(exc).__name__)
            if await _mask_whole_frame(frame):
                return None
        return frame.locator(MASK_SELECTOR)

    locators: list[Any] = [
        locator
        for locator in await asyncio.gather(*(mark(frame) for frame in page.frames))
        if locator is not None
    ]
    for ref in refs:
        if not ref:
            continue
        locator = page.locator(f"aria-ref={ref}")
        try:
            live = await locator.count() > 0
        except Exception:  # noqa: BLE001 - the ref's frame is gone with the page
            live = False
        if live:
            locators.append(locator)
    return locators


async def jpeg(page: Any, ref: Optional[str], *, mask_refs: Sequence[str] = ()) -> str:
    """Masked JPEG data URL of the page or of one element. Raises
    PlaywrightTimeoutError for a ref that no longer resolves.

    The mask is ``mask_locators``: every frame's secret fields plus
    *mask_refs* (a checkout's card fields by ref)."""
    options: dict[str, Any] = {
        "type": "jpeg",
        "quality": JPEG_QUALITY,
        "mask": await mask_locators(page, mask_refs),
        "mask_color": "#000000",
    }
    if not ref:
        raw = await page.screenshot(timeout=NAVIGATION_TIMEOUT_MS, **options)
    else:
        # Locator.screenshot (Playwright 1.63) does not pass its timeout
        # to the element lookup, so a stale ref would wait the 30 s
        # default. Resolve the element here, under REF_TIMEOUT_MS.
        handle = await page.locator(f"aria-ref={ref}").element_handle(timeout=REF_TIMEOUT_MS)
        try:
            raw = await handle.screenshot(timeout=REF_TIMEOUT_MS, **options)
        finally:
            await handle.dispose()
    return "data:image/jpeg;base64," + base64.b64encode(raw).decode("ascii")


async def settle(page: Any) -> None:
    """Give a click that navigates a moment to land; one that does not
    returns at once because the state is already reached."""
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=5_000)
    except PlaywrightError:
        pass


def hand_over(guard: Any, session: BrowserSession, page: Any, *, checkout: bool = False) -> None:
    """The page is the person's until the agent's next action on this
    session: their own submit (the sign-in form, the one-time code) must
    pass the guard's read-tier block (``EgressState.human_driving``),
    shut again by ``take_back``. The order addresses stay shut to it
    (the model may ask for a handoff on any page), except with
    *checkout*: browser.checkout's handoff right after the approved
    order, where the bank's check returns to the shop's payment address
    (``EgressState.checkout_handoff``), on *page* only, never another
    tab (``EgressState.handoff_page``). A guard without state (not
    installed yet, a test double) has no window to open."""
    state = guard.egress_state(session.context)
    if state is not None:
        state.human_driving = True
        if checkout:
            state.checkout_handoff = True
            state.handoff_page = page


async def take_back(guard: Any, session: BrowserSession) -> None:
    """The agent is acting again, so the person is no longer driving:
    shut the handoff window before anything touches the page, then let
    the navigation their last click started land, so the first look
    after "done" sees the signed-in page and not the form."""
    state = guard.egress_state(session.context)
    if state is None or not getattr(state, "human_driving", False):
        return
    state.human_driving = False
    state.checkout_handoff = False
    state.handoff_page = None
    await settle(await session.page())


async def needs_human(
    session: BrowserSession, page: Any, kind: str, detail: str, *, guard: Any = None
) -> dict[str, Any]:
    """End the turn: the person clears the challenge (or does what the
    model asked for) and resumes. The masked picture goes to them, and
    with *guard* given the window is theirs (``hand_over``) until the
    agent's next action.
    (Phase 4 hook: ``platform.bring_to_front`` belongs here.)"""
    if guard is not None:
        hand_over(guard, session, page)
    payload: dict[str, Any] = {
        "kind": kind,
        "detail": detail,
        "url": where(session, page),
    }
    try:
        image = await jpeg(page, None)
    except PlaywrightError as exc:
        log_failure("browser_handoff_screenshot_failed", exc, kind=kind)
        image = None
    if image is not None:
        payload["user_image"] = image
    return {"ok": False, "needs_human": payload, "mode": session.mode}


async def field_facts(page: Any, lines: Sequence[str]) -> snap.PageFacts:
    """Which fields of the outline just taken hold a secret, and what the
    default button of each field's form says, asked of the live page for
    every field line (``markers.FIELD_FACTS_JS``), so the page memory
    knows a password box before anything is typed into it and an order
    form before a submit goes through one of its fields. Resolves the
    refs of the current snapshot, so it must run before the next one.
    Fails closed to "unknown" (both ``None``) on any error; the write
    tiers then still check the live element before acting."""
    refs = [match.group(1) for line in lines if (match := _FIELD_LINE_RE.match(line))]

    async def gather() -> list[Any]:
        return list(
            await asyncio.gather(
                *(page.locator(f"aria-ref={ref}").evaluate(markers.FIELD_FACTS_JS) for ref in refs)
            )
        )

    try:
        facts = await asyncio.wait_for(gather(), snap.FACTS_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 - unknown facts fail closed
        logger.warning("browser_field_facts_failed", error=type(exc).__name__)
        return snap.PageFacts()
    answers = [fact if isinstance(fact, dict) else {} for fact in facts]
    secret = {ref: str(a["kind"]) for ref, a in zip(refs, answers, strict=True) if a.get("kind")}
    buttons = {ref: str(a["button"]) for ref, a in zip(refs, answers, strict=True) if a.get("button")}
    return snap.PageFacts(secret_fields=secret, form_buttons=buttons)


async def page_facts(page: Any) -> list[Any]:
    """What every frame of the page shows (``markers.PAGE_FACTS_JS``): a
    total, a payment method on file, a price. A frame that cannot be asked
    answers None, which counts as all of them shown; a frame that went
    away shows nothing, and so does one that never answered because it has
    no document (URL "": a frame whose parent wrote into it has one, and
    answers). browser.act and browser.read's click join these into what
    they judge (``markers.join_page``)."""

    async def ask(frame: Any) -> Any:
        try:
            return await frame_evaluate(frame, markers.PAGE_FACTS_JS)
        except Exception as exc:  # noqa: BLE001 - unknown facts fail closed
            if frame.is_detached() or (isinstance(exc, asyncio.TimeoutError) and not frame.url):
                return dict.fromkeys(markers.PAGE_FACT_KEYS, False)
            log_failure("browser_frame_facts_failed", exc)
            return None

    return list(await asyncio.gather(*(ask(frame) for frame in page.frames)))


async def observe(
    session: BrowserSession,
    handoff: HandoffDetector,
    action: str,
    args: dict[str, Any],
    *,
    query: Optional[str] = None,
    full: bool = False,
    extra: Optional[dict[str, Any]] = None,
    memory: Optional[PageMemory] = None,
    guard: Any = None,
) -> dict[str, Any]:
    """The fresh page as the model sees it, or ``needs_human`` when the
    page is a challenge (checked first, so a CAPTCHA wall is never
    described as if it were content; with *guard*, the page is the
    person's from that moment: ``hand_over``). With *memory*, the page
    is remembered as the one the user's next browser.act may be bound to."""
    page = await session.page()
    challenge = await handoff.detect_challenge(page)
    if challenge is not None:
        return await needs_human(session, page, challenge.kind, challenge.detail, guard=guard)
    account = session.mode == "account"
    out = await snap.outline(
        page,
        query=query,
        full=full,
        account_mode=account,
        secrets=session.typed_secrets,
        limit_chars=FULL_OUTLINE_CHARS if full else OUTLINE_CHARS,
    )
    summary = snap.summarize(action, args, out, step=session.task.actions)
    session.task.summaries.append(summary)
    session.task.last_outline_chars = out.chars
    if memory is not None:
        facts = await field_facts(page, out.lines)
        memory.remember(
            session.user_id,
            url=page.url,
            outline_lines=out.lines,
            facts=facts,
            query=query,
            full=full,
        )
    return {
        "ok": True,
        "url": out.url,
        "title": out.title,
        "outline": list(out.lines),
        "refs": out.refs,
        "truncated": out.truncated,
        "summary": summary,
        "notes": list(session.task.notes),
        "mode": session.mode,
        **(extra or {}),
    }
