"""Checks IANA time zone names and picks the zone a scheduled task runs in.

Why it exists: a task's "08:00" means nothing without a zone, and the server
itself often runs in UTC (Docker). Every zone that reaches a row, a card or
``users.timezone`` passes ``parse_zone`` first: only real zone names, never a
path ("../etc") or a directory of zones ("America"). The standard library's
zoneinfo (with the tzdata package already in requirements.txt) is the only
source; no dependency is added.
"""

from __future__ import annotations

import functools
import re
from typing import Any, Optional
from zoneinfo import ZoneInfo, available_timezones

# What a zone name may look like before zoneinfo is asked: letters, digits
# and _ + - in up to three slash-separated parts ("America/Argentina/Salta",
# "Etc/GMT+5", "UTC"). No dots, so nothing can walk up a directory.
_ZONE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_+\-]{0,30}(?:/[A-Za-z0-9_+\-]{1,30}){0,2}")
ZONE_NAME_MAX_CHARS = 64


@functools.lru_cache(maxsize=1)
def _known_zones() -> frozenset[str]:
    """Every zone name this Python can load (tzdata or the system's)."""
    try:
        return frozenset(available_timezones())
    except Exception:  # an unreadable zone database: fall back to loading
        return frozenset()


@functools.lru_cache(maxsize=512)
def _load(name: str) -> Optional[ZoneInfo]:
    try:
        return ZoneInfo(name)
    except Exception:  # not found, a directory, a malformed file
        return None


def parse_zone(name: object) -> tuple[Optional[ZoneInfo], Optional[str]]:
    """``(zone, None)`` for a real IANA zone name, else ``(None, error)``.

    The error is a plain sentence for the model or the owner. A name must
    look like a zone, be one zoneinfo knows (``available_timezones``, when
    that list can be read) and load; "../etc", "America" and "" all fail."""
    if not isinstance(name, str) or not name.strip():
        return None, "A time zone must be an IANA name such as 'America/New_York'."
    text = name.strip()
    if len(text) > ZONE_NAME_MAX_CHARS or not _ZONE_NAME_RE.fullmatch(text):
        return None, f"'{text[:ZONE_NAME_MAX_CHARS]}' is not a time zone name (use one like 'Europe/London')."
    known = _known_zones()
    if known and text not in known:
        return None, f"'{text}' is not a known time zone (use one like 'America/Chicago')."
    zone = _load(text)
    if zone is None:
        return None, f"'{text}' is not a known time zone (use one like 'America/Chicago')."
    return zone, None


def is_valid_zone(name: object) -> bool:
    return parse_zone(name)[0] is not None


# The header the web app sends with the browser's zone (Intl), so a user
# who never set one still gets scheduled tasks in their own local time.
TIMEZONE_HEADER = "X-Crawler-Timezone"


def remember_zone(user: Any, value: object) -> bool:
    """Store the browser's zone on *user* (``users.timezone``) when it is a
    valid zone and differs from what is stored; True when it changed. The
    caller's session commits it."""
    zone, _error = parse_zone(value) if isinstance(value, str) and value.strip() else (None, None)
    if zone is None or not isinstance(value, str):
        return False
    name = value.strip()
    if getattr(user, "timezone", None) == name:
        return False
    user.timezone = name
    return True


def resolve_zone(
    arg: Optional[str], user_tz: Optional[str], config_default: Optional[str]
) -> Optional[ZoneInfo]:
    """The zone a task runs in: the call's own ``arg`` when given (and valid;
    an invalid one resolves to nothing rather than to a guess), else the
    user's saved zone, else the install's ``CRAWLER_TIMEZONE``. None when
    none of them is a valid zone: the caller then asks the owner."""
    if arg is not None and str(arg).strip():
        return parse_zone(arg)[0]
    for candidate in (user_tz, config_default):
        if candidate:
            zone, _error = parse_zone(candidate)
            if zone is not None:
                return zone
    return None
