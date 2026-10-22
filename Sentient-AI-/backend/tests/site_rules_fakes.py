"""Shared helpers for the site-rules tests (not a test module, so no test
file imports another).

Why it exists: ``snapshot_of`` builds a ``SiteRuleSnapshot`` without the
database and without the owner-input checks of ``patterns.parse_site`` and
``validate_kind``, so a test can block ``127.0.0.1`` or ``localhost`` (which
the API refuses as rules) and point a rule at the fake site.
``FakeSiteRules`` stands in for ``SiteRulesService`` where a test needs the
hooks or the call check but not the database. The guard fakes
(``FakeRequest``/``FakeRoute``/``FakeResponse``, the resolvers and
``egress_state``) are copies of the shapes in ``tests/test_browser_guard.py``,
kept here so no test module imports another.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Iterable, Mapping, Optional, Union, cast

from services.site_rules.hooks import Where
from services.site_rules.patterns import RuleKind
from services.site_rules.snapshot import OwnerRule, SiteRuleSnapshot, SiteVerdict
from services.tools.browser.guard import EgressState

Rules = Union[Mapping[str, str], Iterable[tuple[str, str]]]


def snapshot_of(
    rules: Rules = (),
    categories: Optional[Mapping[str, str]] = None,
    enabled: bool = True,
    *,
    loaded_at: float = 0.0,
) -> SiteRuleSnapshot:
    """A snapshot of owner rules ``{pattern: kind}`` (or pairs, so one pattern
    can appear twice) and category overrides ``{key: kind}``. Rule ids are
    ``"rule-1"``, ``"rule-2"``, ... in the order given."""
    pairs = list(rules.items()) if isinstance(rules, Mapping) else list(rules)
    owner = [
        OwnerRule(id=f"rule-{number}", pattern=pattern, kind=cast(RuleKind, kind))
        for number, (pattern, kind) in enumerate(pairs, start=1)
    ]
    return SiteRuleSnapshot.build(
        owner, dict(categories or {}), enabled=enabled, loaded_at=loaded_at
    )


class FakeSiteRules:
    """Stands in for ``SiteRulesService``: a fixed snapshot (None: never
    loaded), and every hit it was told about."""

    def __init__(self, snapshot: Optional[SiteRuleSnapshot]) -> None:
        self._snapshot = snapshot
        self.hits: list[dict[str, Any]] = []
        self.fresh_calls = 0

    @property
    def snapshot(self) -> Optional[SiteRuleSnapshot]:
        return self._snapshot

    @snapshot.setter
    def snapshot(self, value: Optional[SiteRuleSnapshot]) -> None:
        self._snapshot = value

    async def ensure_fresh(self) -> Optional[SiteRuleSnapshot]:
        self.fresh_calls += 1
        return self._snapshot

    def record_hit(
        self,
        *,
        user_id: Optional[str],
        host: str,
        kind: RuleKind,
        where: Where,
        verdict: SiteVerdict,
        audit: bool,
    ) -> None:
        self.hits.append(
            {"user_id": user_id, "host": host, "kind": kind, "where": where, "audit": audit}
        )


# -- guard fakes (shapes of tests/test_browser_guard.py) ----------------------


def public_resolver(host: str) -> list[str]:
    return ["93.184.216.34"]


def private_resolver(host: str) -> list[str]:
    return ["10.0.0.1"]


TAB = SimpleNamespace(name="the card's tab", url="https://shop.example/cart")
FROM_TAB = {"referer": "https://shop.example/cart"}


class FakeFrame:
    def __init__(self, parent: Any = None, page: Any = TAB) -> None:
        self.parent_frame = parent
        self.page = page


class FakeRequest:
    def __init__(
        self,
        url: str,
        *,
        method: str = "GET",
        navigation: bool = True,
        top: bool = True,
        page: Any = TAB,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self.url, self.method, self._navigation = url, method, navigation
        self.frame = FakeFrame(None if top else FakeFrame(page=page), page=page)
        self.headers = dict(FROM_TAB if headers is None else headers)

    def is_navigation_request(self) -> bool:
        return self._navigation


class FakeResponse:
    def __init__(self, status: int, location: Optional[str] = None) -> None:
        self.status = status
        self.headers = {"location": location} if location else {}


class FakeRoute:
    def __init__(self, response: Any = None) -> None:
        self.calls: list[tuple[str, object]] = []
        self._response = response

    async def continue_(self) -> None:
        self.calls.append(("continue", None))

    async def abort(self, code: str) -> None:
        self.calls.append(("abort", code))

    async def fetch(self, *, max_redirects: int) -> Any:
        assert max_redirects == 0
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def fulfill(self, **kwargs: Any) -> None:
        self.calls.append(("fulfill", kwargs))


def egress_state(*, account_mode: bool = True) -> EgressState:
    """A guard state whose windows, when opened, belong to ``TAB``."""
    return EgressState(account_mode=account_mode, write_page=TAB, handoff_page=TAB)
