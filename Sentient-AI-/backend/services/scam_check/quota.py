"""Per-user limits on out-of-turn scam checks, and the short memory of recent answers.

Why it exists: every out-of-turn check can ask the account's AI provider to read a message and
up to four pictures, which costs the owner money. ScamQuota caps that per person (4 checks a
minute, and the owner's checks_per_day per rolling day); RecentChecks answers the same content
again within 10 minutes without another model call (a forwarded scam is often checked twice).
Both live in memory only (a restart clears them): they guard spend, and the real spend shows in
/usage. Modelled on services/tools/transcribe.VoiceQuota. Clocks are injectable for tests.

Only checks that reach the AI step take quota; a repeat answered from RecentChecks and a refusal
take none, and a check refused after its quota was taken (a provider that cannot see the only
picture) gives it back.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from typing import TYPE_CHECKING, Callable, Literal, Optional, Sequence

if TYPE_CHECKING:
    from services.scam_check.service import ScamCheckRequest, ScamCheckResult

BURST = 4
WINDOW_S = 60.0
DAY_S = 86_400.0
DEFAULT_CHECKS_PER_DAY = 30
TTL_S = 600.0
MAX_ENTRIES = 256

QuotaRefusal = Literal["burst", "daily"]


class ScamQuota:
    """Per-user limits, in memory: BURST (4) checks per WINDOW_S (60 s) and the owner's
    checks_per_day per rolling day."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        burst: int = BURST,
        window_s: float = WINDOW_S,
        day_s: float = DAY_S,
    ) -> None:
        self._clock = clock
        self._burst = burst
        self._window_s = window_s
        self._day_s = day_s
        self._taken: dict[str, deque[float]] = {}

    def _stamps(self, user_id: str, now: float) -> deque[float]:
        stamps = self._taken.get(user_id)
        if stamps is None:
            return deque()
        while stamps and now - stamps[0] >= self._day_s:
            stamps.popleft()
        if not stamps:
            del self._taken[user_id]
        return stamps

    def refusal(self, user_id: str, per_day: int) -> Optional[QuotaRefusal]:
        """"burst" (BURST checks in the last minute), "daily" (*per_day* checks in the last
        day; a value that is not a whole number of at least 1 counts as the default 30), or
        None."""
        now = self._clock()
        stamps = self._stamps(user_id, now)
        if sum(1 for t in stamps if now - t < self._window_s) >= self._burst:
            return "burst"
        limit = per_day if isinstance(per_day, int) and not isinstance(per_day, bool) and per_day >= 1 else DEFAULT_CHECKS_PER_DAY
        if len(stamps) >= limit:
            return "daily"
        return None

    def take(self, user_id: str) -> None:
        """Count one check now."""
        self._taken.setdefault(user_id, deque()).append(self._clock())

    def give_back(self, user_id: str) -> None:
        """Undo the newest take (a check refused after it took its quota)."""
        stamps = self._taken.get(user_id)
        if stamps:
            stamps.pop()
            if not stamps:
                del self._taken[user_id]

    def used_today(self, user_id: str) -> int:
        """Checks counted in the last rolling day (the Security tab's "3 of 30 used today")."""
        return len(self._stamps(user_id, self._clock()))


def _family(channel: str) -> str:
    """The web chat and the Security box share answers; Telegram and Slack each have their own."""
    return "web" if channel in ("web_chat", "web_box") else str(channel)


class RecentChecks:
    """Answers the same content again within TTL_S (600 s) without a model call. Per user, at
    most 256 entries in all; keyed by sha256 over (user_id, channel family, note, text, picture
    sha256s), plus the files' sha256s and the channel's hidden links, which change what is
    checked."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl_s: float = TTL_S,
        max_entries: int = MAX_ENTRIES,
    ) -> None:
        self._clock = clock
        self._ttl_s = ttl_s
        self._max_entries = max_entries
        self._entries: dict[str, tuple[float, "ScamCheckResult"]] = {}

    def key(self, request: "ScamCheckRequest", image_sha256: Sequence[str]) -> str:
        """The content's key. The text and note are compared as stripped; pictures by their
        sha256, in order. Never raises for odd text: the payload is ASCII JSON (a lone
        surrogate in a pasted text, which SafeStr lets through, is written as its \\u escape
        rather than failing the UTF-8 encode)."""
        payload = json.dumps(
            [
                request.user_id,
                _family(request.channel),
                (request.note or "").strip(),
                (request.text or "").strip(),
                list(image_sha256),
                [f.sha256 for f in request.files],
                [list(pair) for pair in request.anchors],
            ],
            ensure_ascii=True,
        )
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    def _prune(self, now: float) -> None:
        for key in [k for k, (at, _) in self._entries.items() if now - at >= self._ttl_s]:
            del self._entries[key]

    def get(self, key: str) -> Optional["ScamCheckResult"]:
        """The answer stored under *key* less than TTL_S ago, or None."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        at, result = entry
        if self._clock() - at >= self._ttl_s:
            del self._entries[key]
            return None
        return result

    def put(self, key: str, result: "ScamCheckResult") -> None:
        """Keep *result* under *key*; the oldest entry goes when the memory is full. A refusal
        is never kept (it is not an answer to the content)."""
        if not getattr(result, "ok", False):
            return
        now = self._clock()
        self._prune(now)
        self._entries.pop(key, None)
        while len(self._entries) >= self._max_entries:
            del self._entries[next(iter(self._entries))]
        self._entries[key] = (now, result)
