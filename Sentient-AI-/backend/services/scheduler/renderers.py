"""The registry of nudge renderers: a feature (flashcards' "cards are due")
registers a function that writes a short reminder text for one user, and the
schedule sweeper sends it on the task's recurrence, with no model call.

Why it exists: a nudge is a scheduled_tasks row of kind "nudge" whose
``options.renderer`` names one entry here; the sweeper looks the renderer up
at run time, re-reads the renderer's own capability switch before each run,
and skips an occurrence silently when the renderer answers None (nothing is
due). Features register at import time and never touch the sweeper.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional, Protocol

# (session, user_id, now_utc) -> the text to send, or None to skip this
# occurrence silently. The session is the sweeper's; the renderer only reads.
NudgeRender = Callable[[Any, str, datetime], Awaitable[Optional[str]]]

_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")


@dataclass(frozen=True)
class NudgeRenderer:
    name: str
    # The capability key that must be on for a nudge to run (its feature's
    # switch); the sweeper re-reads it before every run.
    capability: str
    render: NudgeRender


_RENDERERS: dict[str, NudgeRenderer] = {}


class NudgeScheduler(Protocol):
    """What a feature schedules its nudges through (implemented by
    services/notifications/schedules.ScheduleService, at
    ``app.state.schedules``). ``recurrence`` takes the schedule.create
    fields (freq, time, days, day_of_month, date); ``timezone`` None means
    the nudge's own zone, then the user's, then CRAWLER_TIMEZONE. Both
    raise ValueError with a plain sentence ("timezone_required" when no zone
    is known)."""

    async def upsert_nudge(
        self,
        user_id: Any,
        *,
        renderer: str,
        label: str,
        recurrence: dict[str, Any],
        timezone: Optional[str],
        channels: tuple[str, ...],
    ) -> str: ...

    async def cancel_nudge(self, user_id: Any, *, renderer: str) -> bool: ...


def register_nudge_renderer(name: str, capability: str, render: NudgeRender) -> None:
    """Register (or replace) the renderer called *name*. ``capability`` is
    the switch that gates its nudges. Raises ValueError for a malformed
    name or capability, so a typo fails at import, not at 8am."""
    if not _NAME_RE.fullmatch(name or ""):
        raise ValueError(f"Invalid nudge renderer name: {name!r}")
    if not _NAME_RE.fullmatch(capability or ""):
        raise ValueError(f"Invalid capability key for nudge renderer {name!r}")
    if not callable(render):
        raise ValueError(f"Nudge renderer {name!r} is not callable")
    _RENDERERS[name] = NudgeRenderer(name=name, capability=capability, render=render)


def get_renderer(name: Any) -> Optional[NudgeRenderer]:
    """The renderer registered as *name*, or None."""
    return _RENDERERS.get(name) if isinstance(name, str) else None


def registered_renderers() -> tuple[str, ...]:
    return tuple(sorted(_RENDERERS))


def unregister_nudge_renderer(name: str) -> None:
    """Remove a renderer (tests)."""
    _RENDERERS.pop(name, None)
