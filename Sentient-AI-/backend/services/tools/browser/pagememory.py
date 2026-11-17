"""The last page each user looked at, for binding a write to it (spec §5).

browser.act and browser.checkout make their approval cards from what the
model last saw, and run only while that is still what is on screen. This
module is the memory both read from: every observation (browser.read's
and the write tiers' own) records the page's origin, scheme, its outline
digests, the refs it showed with their names, and which of its fields
hold a secret. The precheck that decides whether a call gets a card at
all reads this and nothing else, so it never touches the browser; the
run re-checks the live page against the digest.

"Still the same page" means the page's structure (``outline_digest``:
which refs there are and what each is called), so a countdown, a typed
value, a ticked box or an opened menu between the card and the owner's
tap does not void the approval, while an element that came, went or was
renamed still does. The checkout card is tied to the same digest
(``checkout.facts`` imports it). An act that names its target by ref (a
click, a fill, a choice) lands on that element wherever the focus is; a
key press acts on whatever has the focus, so its digest keeps the focus
marker too (``LastPage.focus_digest``).

Process memory only, one entry per user, never persisted and never sent
to the model as a whole: ``url`` is kept as the page reported it (query
string included, so the origin check is exact) and only its host is ever
quoted back.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Mapping, Optional, Sequence
from urllib.parse import urlsplit

from services.tools.browser import snapshot as snap

# Memory for more users than a single install ever has; the oldest entries
# go first when it fills, so one process never grows without bound.
_MAX_USERS = 64
# The markers of an outline line that say what state an element is in
# (ticked, greyed out, open, held down, chosen; and focused), not which
# element it is: a page changes them by itself, and a click on a ref
# lands on the same element whatever they say. The focus marker is kept
# apart: a key press goes to the focused element, so it is no mere state
# there.
_STATE = "checked|disabled|expanded|pressed|selected"
_STATE_RE = re.compile(rf" \[(?:{_STATE})(?:=[^\]]*)?\]")
_FOCUS_ONLY_RE = re.compile(r" \[active\]")
_STATE_OR_FOCUS_RE = re.compile(rf" \[(?:active|{_STATE})(?:=[^\]]*)?\]")


@dataclass(frozen=True)
class LastPage:
    """One observation, as the write tiers need it. ``names`` holds every
    ref the outline showed (value ``""`` when the element has no name), so
    ``ref in names`` is the stale check; ``secret_refs`` are the fields
    the page facts or the field's own name mark as a password, one-time
    code or card field; ``form_buttons`` are, per field ref, the words on
    the default button of the field's form (what a submit through the
    field would send it with). ``query``/``full`` are how the outline was
    taken, so a run can retake it the same way and compare digests:
    ``outline_digest`` for an act on a ref, ``focus_digest`` (the same,
    with the focus marker kept) for a key press."""

    url: str
    origin: str
    outline_digest: str
    secret_refs: frozenset[str]
    names: Mapping[str, str]
    scheme: str
    query: Optional[str] = None
    full: bool = False
    form_buttons: Mapping[str, str] = MappingProxyType({})
    focus_digest: str = ""


def outline_digest(lines: Sequence[str], *, focus: bool = False, states: bool = False) -> str:
    """sha1 of the page's interactive structure: the outline lines that
    carry a ref, minus their inline value and their state markers. Text-only
    lines are left out, so a ticking cart timer, a typed value, a ticked
    box or a focus change does not void an approval; a ref that came, went
    or was renamed does. With *focus* the focus marker stays in: what a
    key press is tied to, since Enter acts on whatever has the focus when
    it is pressed. What an act would do on the page as it is now is judged
    on the live page each time, and a checkout's total is compared by the
    checkout toolkit itself."""
    # *states* keeps the state markers and drops the focus marker alone:
    # what a purchase card is tied to, where a box ticked or an option
    # chosen after the card was made must void it.
    markers = _FOCUS_ONLY_RE if states else _STATE_RE if focus else _STATE_OR_FOCUS_RE
    kept: list[str] = []
    for line in lines:
        if "[ref=" not in line:
            continue
        head, sep, _value = markers.sub("", line).partition("]: ")
        kept.append(head + ("]" if sep else ""))
    return hashlib.sha1("\n".join(kept).encode("utf-8")).hexdigest()


def page_address(url: str) -> str:
    """sha1 of *url* without its fragment: the page an approval card was
    made on, which the card may keep without keeping the address (its
    query string can carry a session id)."""
    return hashlib.sha1(url.partition("#")[0].encode("utf-8")).hexdigest()


def page_origin(url: str) -> tuple[str, str]:
    """``(scheme, origin)`` of *url*: ``https://shop.example.com`` for web
    pages (userinfo dropped, lower-cased), ``about:blank`` and the like
    for everything else, so two pages compare equal exactly when a
    browser would treat them as the same origin."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", ""
    scheme = parts.scheme.lower()
    if parts.netloc:
        return scheme, f"{scheme}://{parts.netloc.rpartition('@')[2].lower()}"
    return scheme, f"{scheme}:{parts.path}"


def _ref_names(lines: Sequence[str]) -> dict[str, str]:
    """ref -> accessible name for every line of the outline that carries a
    ref. Parsed with the outline's own parser so quoting (a name with
    ``: `` in it is single-quoted by the renderer) is read back exactly."""
    names: dict[str, str] = {}
    stack = list(snap._parse("\n".join(lines)))
    while stack:
        node = stack.pop()
        if node.ref:
            names[node.ref] = snap._plain(node.name)
        stack.extend(node.children)
    return names


# The most refs one page's memory keeps across looks at it.
_MAX_NAMES = 3000


class PageMemory:
    def __init__(self) -> None:
        self._pages: dict[str, LastPage] = {}

    def remember(
        self,
        user_id: str,
        *,
        url: str,
        outline_lines: Sequence[str],
        facts: snap.PageFacts,
        query: Optional[str] = None,
        full: bool = False,
    ) -> LastPage:
        """Record *user_id*'s latest observation and return it. Unknown
        facts (``secret_fields`` None) leave only the name rule; the write
        tiers check the live element again before acting either way."""
        names = _ref_names(outline_lines)
        secret = set(facts.secret_fields or ())
        secret.update(ref for ref, name in names.items() if snap._SECRET_NAME_RE.search(name))
        earlier = self._pages.get(user_id)
        if earlier is not None and page_address(earlier.url) == page_address(url):
            # Another look at the same page (a scroll, a find, the result of
            # an act that stayed on it): the refs seen before are kept, so a
            # control the model saw a moment ago is not answered "stale ref"
            # because it scrolled out of the outline. Whether it is still
            # there under that name is asked of the live page before any act.
            kept = {ref: name for ref, name in earlier.names.items() if ref not in names}
            names = dict(list({**kept, **names}.items())[-_MAX_NAMES:])
            secret.update(earlier.secret_refs)
        scheme, origin = page_origin(url)
        page = LastPage(
            url=url,
            origin=origin,
            outline_digest=outline_digest(outline_lines),
            secret_refs=frozenset(secret & names.keys()),
            names=MappingProxyType(names),
            scheme=scheme,
            query=query,
            full=full,
            form_buttons=MappingProxyType(
                {ref: str(words) for ref, words in (facts.form_buttons or {}).items() if ref in names}
            ),
            focus_digest=outline_digest(outline_lines, focus=True),
        )
        self._pages.pop(user_id, None)
        if len(self._pages) >= _MAX_USERS:
            del self._pages[next(iter(self._pages))]
        self._pages[user_id] = page
        return page

    def add_names(self, user_id: str, *, url: str, lines: Sequence[str]) -> None:
        """Add the refs of *lines* (what a find answered with) to *user_id*'s
        latest observation, when that is of the page at *url*. A find
        reaches below the visible part, so its refs are in no outline: a
        click on one was answered "stale ref" until the model had scrolled
        the control into an outline. The outline digest is left as it is;
        a ref that names a secret field by its name is kept as one."""
        last = self._pages.get(user_id)
        if last is None or page_address(last.url) != page_address(url):
            return
        found = {ref: name for ref, name in _ref_names(lines).items() if ref not in last.names}
        if not found:
            return
        secret = {ref for ref, name in found.items() if snap._SECRET_NAME_RE.search(name)}
        self._pages[user_id] = replace(
            last,
            names=MappingProxyType({**last.names, **found}),
            secret_refs=last.secret_refs | secret,
        )

    def get(self, user_id: str) -> Optional[LastPage]:
        return self._pages.get(user_id)

    def forget(self, user_id: str) -> None:
        self._pages.pop(user_id, None)
