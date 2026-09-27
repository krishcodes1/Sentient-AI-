"""Challenge detection for the human handoff (spec §8).

The detector runs before every action and answers one question: is this
page asking a *person* to do something the agent must never do — solve a
CAPTCHA, approve an MFA push, type a one-time code? It looks at what is
on the page (visible challenge frames, OTP inputs, the words) and where
the page is (IdP hosts, bot-wall URLs). It never looks at HTTP status
codes: Canvas answers locked content with 403 and throttles with 429,
and neither is a challenge.

``collect_facts`` is the only part that touches the browser; ``classify``
is a pure function over its result so every rule is tested with a dict.
Phase 2 parks the turn on the returned ``Challenge`` and types ``/code``
into ``otp_ref`` (a Playwright selector, IdP origin only).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Optional
from urllib.parse import urlparse

import structlog

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = structlog.get_logger(__name__)

Kind = Literal["captcha", "mfa", "otp", "unusual_traffic"]


@dataclass(frozen=True)
class Challenge:
    kind: Kind
    detail: str
    otp_ref: Optional[str] = None  # Playwright selector for the code field, e.g. 'css=[id="otp"]'


CAPTCHA_HOSTS = (
    "google.com/recaptcha", "recaptcha.net", "hcaptcha.com", "challenges.cloudflare.com",
    "arkoselabs.com", "funcaptcha.com", "captcha-delivery.com",
)
_CAPTCHA_TITLE = re.compile(
    r"recaptcha|hcaptcha|captcha|security challenge|turnstile|arkose|funcaptcha|verification challenge",
    re.IGNORECASE,
)
MFA_HOSTS = ("duosecurity.com", "login.microsoftonline.com", "okta.com", "oktapreview.com", "accounts.google.com")
_MFA_TEXT = re.compile(
    r"duo push|approve (the )?(sign[- ]?in|request|notification)|push notification|enter the number|"
    r"number (shown|displayed)|two[- ]step verification|2-step verification|verify your identity|"
    r"authenticator app|okta verify|security key|check your phone",
    re.IGNORECASE,
)
_HUMAN_TEXT = re.compile(
    r"verify (that )?you('re| are) (a )?human|confirm (that )?you('re| are) (a )?human|"
    r"prove you('re| are) (not a robot|human)|are you a robot|unusual traffic|checking your browser|"
    r"verify you are not a bot|automated (queries|traffic)|complete the (security )?check",
    re.IGNORECASE,
)
_WALL_URLS = ("/bots.html", "/sorry/", "/cdn-cgi/challenge-platform/", "_incapsula_resource", "/distil_r_", "__cf_chl")

# ``visible(el, min)``: rendered and at least min×min px inside the viewport.
# Challenge frames need 32 px (a real widget, not a 1-px tracker); inputs
# need 8 px, because a stock text field is ~21 px tall and would never pass
# the frame threshold.
_FACTS_JS = r"""
() => {
  const visible = (el, min) => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const w = Math.min(r.right, innerWidth) - Math.max(r.left, 0);
    const h = Math.min(r.bottom, innerHeight) - Math.max(r.top, 0);
    return w >= min && h >= min;
  };
  const frames = [...document.querySelectorAll('iframe')].map(f => ({
    title: f.title || '', src: f.src || '', visible: visible(f, 32), badge: !!f.closest('.grecaptcha-badge'),
  }));
  const otpish = /(^|[^a-z])(otp|otc|totp|passcode|one[-_ ]?time|verification[-_ ]?code|mfa[-_ ]?code|security[-_ ]?code)([^a-z]|$)/i;
  const skip = ['hidden', 'password', 'checkbox', 'radio', 'submit', 'button', 'file'];
  const otp = [...document.querySelectorAll('input')].filter(i =>
      visible(i, 8) && !skip.includes((i.type || '').toLowerCase()) &&
      (i.autocomplete === 'one-time-code' ||
       otpish.test([i.name, i.id, i.placeholder, i.getAttribute('aria-label')].join(' '))))
    .map(i => ({id: i.id || '', name: i.name || '', autocomplete: i.autocomplete || ''}));
  return {
    url: location.href, title: document.title || '',
    text: (document.body ? document.body.innerText : '').slice(0, 4000),
    frames, otp,
  };
}
"""


def _is_mfa_host(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    for known in MFA_HOSTS:
        if host == known or host.endswith("." + known):
            if known == "accounts.google.com":
                return "challenge" in parsed.path.lower()
            return True
    return False


def _css_string(value: str) -> str:
    """*value* as the body of a double-quoted CSS string. The id/name come
    from the page: escaping only the quote would let a trailing backslash
    un-escape it and splice a second selector into ``otp_ref``."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return escaped.replace("\n", "\\a ").replace("\r", "\\d ").replace("\f", "\\c ")


def _selector_for(field: dict[str, str]) -> str:
    if field.get("id"):
        return 'css=[id="' + _css_string(field["id"]) + '"]'
    if field.get("name"):
        return 'css=input[name="' + _css_string(field["name"]) + '"]'
    return 'css=input[autocomplete="one-time-code"]'


def _log_url(url: str) -> str:
    """scheme://host/path only: IdP and bot-wall URLs carry session ids and
    SAML/OAuth state in the query, and log lines are persistent."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else parsed.path


def classify(facts: dict[str, Any]) -> Optional[Challenge]:
    """Spec §8 rules over the facts ``collect_facts`` gathered; first match wins."""
    url = facts.get("url") or ""
    lowered = url.lower()
    if any(marker in lowered for marker in _WALL_URLS):
        return Challenge("unusual_traffic", f"bot-wall URL: {urlparse(url).path}")
    for frame in facts.get("frames", []):
        if frame.get("badge") or not frame.get("visible"):
            continue
        title = frame.get("title") or ""
        src = (frame.get("src") or "").lower()
        if _CAPTCHA_TITLE.search(title) or any(host in src for host in CAPTCHA_HOSTS):
            return Challenge("captcha", f"visible challenge frame: {title or src}")
    idp_frames = facts.get("idp_frames", [])
    for scope in (facts, *idp_frames):
        for field in scope.get("otp", []):
            return Challenge("otp", "one-time code field on the page", otp_ref=_selector_for(field))
    text = f"{facts.get('title', '')}\n{facts.get('text', '')}"
    idp_text = "\n".join(f.get("text", "") for f in idp_frames)
    if (_is_mfa_host(url) or idp_frames) and _MFA_TEXT.search(text + "\n" + idp_text):
        return Challenge("mfa", "the identity provider is asking for a second factor")
    match = _HUMAN_TEXT.search(text)
    if match:
        return Challenge("unusual_traffic", f"page says: {match.group(0)}")
    return None


# How long one IdP frame may take to answer (``_shared.REF_TIMEOUT_MS``).
_FRAME_TIMEOUT_S = 3.0


async def collect_facts(page: "Page") -> dict[str, Any]:
    """One evaluate on the main frame, plus one per IdP-hosted child frame
    (Duo's prompt lives in an iframe on the school's IdP page)."""
    facts = await page.evaluate(_FACTS_JS)
    facts["idp_frames"] = []
    for frame in page.frames:
        if frame is page.main_frame or not _is_mfa_host(frame.url):
            continue
        try:
            # Bounded: Playwright's frame.evaluate has none, and a frame
            # still without a document never answers.
            facts["idp_frames"].append(await asyncio.wait_for(frame.evaluate(_FACTS_JS), _FRAME_TIMEOUT_S))
        except Exception:  # noqa: BLE001 - detached mid-read or no document; nothing to hand off in it
            continue
    return facts


async def detect_challenge(page: "Page") -> Optional[Challenge]:
    try:
        facts = await collect_facts(page)
    except Exception as exc:  # noqa: BLE001 - page mid-navigation or closed: nothing to hand off yet
        logger.debug("browser_handoff_facts_failed", error=str(exc)[:200])
        return None
    challenge = classify(facts)
    if challenge is not None:
        logger.info("browser_challenge_detected", kind=challenge.kind, url=_log_url(facts.get("url") or ""))
    return challenge
