"""The last page each user looked at, for binding a write to it (spec §5).

browser.act and browser.checkout make their approval cards from what the
model last saw, and run only while that is still what is on screen. This
module is the memory both read from: every observation (browser.read's
and the write tiers' own) records the page's origin, scheme, an outline
digest, the refs it showed with their names, and which of its fields hold
a secret. The precheck that decides whether a call gets a card at all
reads this and nothing else, so building a card never touches the
browser; the run re-checks the live page against the digest.

Process memory only, one entry per user, never persisted and never sent
to the model as a whole: ``url`` is kept as the page reported it (query
string included, so the origin check is exact) and only its host is ever
quoted back.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional, Sequence
from urllib.parse import urlsplit

from services.tools.browser import snapshot as snap

# Memory for more users than a single install ever has; the oldest entries
# go first when it fills, so one process never grows without bound.
_MAX_USERS = 64


@dataclass(frozen=True)
class LastPage:
    """One observation, as the write tiers need it. ``names`` holds every
    ref the outline showed (value ``""`` when the element has no name), so
    ``ref in names`` is the stale check; ``secret_refs`` are the fields
    the page facts or the field's own name mark as a password, one-time
    code or card field; ``form_buttons`` are, per field ref, the words on
    the default button of the field's form (what a submit through the
    field would send it with). ``query``/``full`` are how the outline was
    taken, so a run can retake it the same way and compare digests."""

    url: str
    origin: str
    outline_digest: str
    secret_refs: frozenset[str]
    names: Mapping[str, str]
    scheme: str
    query: Optional[str] = None
    full: bool = False
    form_buttons: Mapping[str, str] = MappingProxyType({})


def outline_digest(lines: Sequence[str]) -> str:
    """sha1 of the joined outline lines: same lines, same page."""
    return hashlib.sha1("\n".join(lines).encode("utf-8")).hexdigest()


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
        )
        self._pages.pop(user_id, None)
        if len(self._pages) >= _MAX_USERS:
            del self._pages[next(iter(self._pages))]
        self._pages[user_id] = page
        return page

    def get(self, user_id: str) -> Optional[LastPage]:
        return self._pages.get(user_id)

    def forget(self, user_id: str) -> None:
        self._pages.pop(user_id, None)
