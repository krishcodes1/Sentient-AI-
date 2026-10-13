"""Google Calendar actions of the Google Workspace connector: list events and
calendars, check free/busy, and create, update, answer and delete events.

Why it exists: keeps the Calendar endpoints and event shaping out of
``google_workspace.py``. Event descriptions are written by other people, so
they are capped before they reach the model.

External service: the Google Calendar API v3
(https://www.googleapis.com/calendar/v3/). Depends on ``google_api.client``
(GoogleBase, validation), ``base`` (errors, path_segment) and ``definition``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from services.agent import risk
from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import cap_text, clamp_limit

from .client import (
    CALENDAR_API,
    GoogleBase,
    as_dict,
    as_list,
    optional_bool,
    optional_line,
    optional_text,
    require_email,
    require_id,
    scalar,
    scalar_fields,
)

# Most events returned by get_events (the contract's hard list maximum).
MAX_EVENTS = 50
EVENT_DESCRIPTION_CHARS = 1000
_RESPONSES = ("accepted", "declined", "tentative")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$")

_EVENT_ID = {"type": "string", "description": "Calendar event id", "required": True}
_CALENDAR_ID = {"type": "string", "description": "Calendar id (default: primary)"}
_WHEN = "RFC 3339 date-time (2026-09-25T10:00:00-04:00) or all-day date (2026-09-25)"

# The event fields a low-risk create_event may set (permission tiers): a
# private event on the owner's own calendar. Guests get an invitation (HIGH);
# anything else (visibility, conference links, recurrence, guest settings) is
# not checked and stays MEDIUM.
_LOW_RISK_EVENT_KEYS = frozenset(
    {"summary", "description", "location", "start", "end", "reminders", "colorId", "transparency"}
)


def event_data_risk(arguments: Any) -> Optional[tuple[str, str]]:
    """risk_check of create_event: HIGH with attendees, MEDIUM with any field
    outside ``_LOW_RISK_EVENT_KEYS``, None otherwise."""
    data = arguments.get("event_data")
    if not isinstance(data, dict):
        return None
    if data.get("attendees"):
        return "high", "it invites other people"
    if any(key not in _LOW_RISK_EVENT_KEYS for key in data):
        return "medium", "it sets event fields other people may see"
    return None

CALENDAR_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_events",
        "List upcoming Google Calendar events.",
        ActionCategory.READ,
        _schema(time_min={"type": "string"}, time_max={"type": "string"}),
        policy_key="google_calendar",
        required_scope="calendar.read",
        starter=True,
    ),
    ToolSpec(
        "check_availability",
        "Check Google Calendar availability for a time range.",
        ActionCategory.READ,
        _schema(time_min={"type": "string"}, time_max={"type": "string"}),
        policy_key="google_calendar",
        required_scope="calendar.read",
    ),
    ToolSpec(
        "create_event",
        "Create a Google Calendar event.",
        ActionCategory.WRITE,
        _schema(
            event_data={
                "type": "object",
                "description": "Google Calendar event resource (summary, start, end, ...)",
                "required": True,
            },
        ),
        policy_key="google_calendar",
        required_scope="calendar.write",
        risk="low",
        risk_check=event_data_risk,
        low_risk_note="add private events with no guests to your calendar",
    ),
    ToolSpec(
        "list_calendars",
        "List the user's Google calendars (id, name, access role).",
        ActionCategory.READ,
        _schema(limit={"type": "integer", "description": "How many (default 10, max 50)"}),
        policy_key="google_calendar",
        required_scope="calendar.read",
    ),
    ToolSpec(
        "update_event",
        "Change fields of a Google Calendar event. Only the fields given change; "
        "attendees, when given, replace the guest list.",
        ActionCategory.WRITE,
        _schema(
            event_id=_EVENT_ID,
            calendar_id=_CALENDAR_ID,
            summary={"type": "string"},
            description={"type": "string"},
            location={"type": "string"},
            start={"type": "string", "description": _WHEN},
            end={"type": "string", "description": _WHEN},
            attendees={"type": "array", "items": {"type": "string"}, "description": "Guest emails"},
            notify_attendees={"type": "boolean", "description": "Email guests (default true)"},
        ),
        policy_key="google_calendar",
        required_scope="calendar.write",
        # Changing the guest list invites or removes other people.
        risk_check=risk.when_given("attendees", "high", "it invites or removes other people"),
    ),
    ToolSpec(
        "respond_to_invite",
        "Accept, decline or tentatively accept a Google Calendar invitation.",
        ActionCategory.WRITE,
        _schema(
            event_id=_EVENT_ID,
            response={"type": "string", "enum": list(_RESPONSES), "required": True},
            calendar_id=_CALENDAR_ID,
        ),
        policy_key="google_calendar",
        required_scope="calendar.write",
        # The answer goes to the organizer: it speaks for the user.
        always_confirm=True,
    ),
    ToolSpec(
        "delete_event",
        "Delete a Google Calendar event (guests are told it was cancelled by default).",
        ActionCategory.DELETE,
        _schema(
            event_id=_EVENT_ID,
            calendar_id=_CALENDAR_ID,
            notify_attendees={"type": "boolean", "description": "Email guests (default true)"},
        ),
        policy_key="google_calendar",
        required_scope="calendar.write",
        always_confirm=True,
    ),
)


def _when(value: Any, field: str) -> Optional[dict[str, str]]:
    """``{"date": ...}`` or ``{"dateTime": ...}`` for a start/end argument."""
    text = optional_line(value, field, max_chars=64)
    if text is None:
        return None
    if _DATE_RE.match(text):
        return {"date": text}
    if _DATETIME_RE.match(text):
        return {"dateTime": text}
    raise ConnectorError(f"'{field}' must be {_WHEN}.")


def _calendar(calendar_id: Any) -> str:
    return optional_line(calendar_id, "calendar_id", max_chars=512) or "primary"


def _shape_event(raw: Any) -> dict[str, Any]:
    event = as_dict(raw)
    shaped: dict[str, Any] = {
        key: event[key] for key in ("id", "summary", "status", "location", "htmlLink") if isinstance(event.get(key), str)
    }
    for key in ("start", "end"):
        when = scalar_fields(event.get(key), date="date", dateTime="dateTime", timeZone="timeZone")
        if when:
            shaped[key] = when
    description = event.get("description")
    if isinstance(description, str) and description:
        shaped["description"], cut = cap_text(description, EVENT_DESCRIPTION_CHARS)
        if cut:
            shaped["description_truncated"] = True
    organizer = scalar(as_dict(event.get("organizer")).get("email"))
    if organizer:
        shaped["organizer"] = organizer
    attendees = [
        scalar_fields(a, email="email", response="responseStatus")
        for a in as_list(event.get("attendees"))[:50]
        if isinstance(a, dict)
    ]
    if attendees:
        shaped["attendees"] = attendees
    return shaped


class CalendarActions(GoogleBase):
    """Google Calendar action coroutines (mixed into GoogleWorkspaceConnector)."""

    @staticmethod
    def _default_window(time_min: Optional[str], time_max: Optional[str]) -> tuple[str, str]:
        now = datetime.now(timezone.utc)
        return (
            time_min or now.isoformat(),
            time_max or (now + timedelta(days=7)).isoformat(),
        )

    def _event_url(self, calendar_id: str, event_id: Optional[str] = None) -> str:
        url = f"{CALENDAR_API}/calendars/{path_segment(calendar_id)}/events"
        return f"{url}/{path_segment(event_id)}" if event_id else url

    # -- READ ------------------------------------------------------------------

    async def get_events(
        self,
        time_min: Optional[str] = None,
        time_max: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Fetch calendar events within a time window (RFC 3339 strings);
        defaults to the next 7 days."""
        start, end = self._default_window(
            optional_line(time_min, "time_min", max_chars=64),
            optional_line(time_max, "time_max", max_chars=64),
        )
        data = await self._call_object(
            "GET",
            self._event_url("primary"),
            params={
                "timeMin": start,
                "timeMax": end,
                "singleEvents": True,
                "orderBy": "startTime",
                "maxResults": MAX_EVENTS,
            },
        )
        return [_shape_event(item) for item in as_list(data.get("items")) if isinstance(item, dict)]

    async def check_availability(
        self,
        time_min: Optional[str] = None,
        time_max: Optional[str] = None,
    ) -> dict[str, Any]:
        """Free/busy for the primary calendar (defaults to the next 7 days)."""
        start, end = self._default_window(
            optional_line(time_min, "time_min", max_chars=64),
            optional_line(time_max, "time_max", max_chars=64),
        )
        data = await self._call_object(
            "POST",
            f"{CALENDAR_API}/freeBusy",
            json={"timeMin": start, "timeMax": end, "items": [{"id": "primary"}]},
        )
        primary = as_dict(as_dict(data.get("calendars")).get("primary"))
        busy_slots = [
            scalar_fields(slot, start="start", end="end")
            for slot in as_list(primary.get("busy"))[:100]
            if isinstance(slot, dict)
        ]
        return {
            "time_min": start,
            "time_max": end,
            "busy_slots": busy_slots,
            "is_free": len(busy_slots) == 0,
        }

    async def list_calendars(self, limit: Any = None) -> list[dict[str, Any]]:
        count = clamp_limit(limit)
        data = await self._call_object(
            "GET", f"{CALENDAR_API}/users/me/calendarList", params={"maxResults": count}
        )
        calendars = []
        for item in as_list(data.get("items"))[:count]:
            if not isinstance(item, dict):
                continue
            shaped = scalar_fields(
                item, id="id", name="summary", access_role="accessRole", time_zone="timeZone"
            )
            shaped["primary"] = item.get("primary") is True
            calendars.append(shaped)
        return calendars

    # -- WRITE -----------------------------------------------------------------

    async def create_event(
        self,
        event_data: dict[str, Any],
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Create a calendar event on the primary calendar."""
        if not isinstance(event_data, dict) or not event_data:
            raise ConnectorError("'event_data' must be a Google Calendar event object.")
        if not user_confirmed:
            summary = event_data.get("summary", "Untitled event")
            start = as_dict(event_data.get("start"))
            raise UserConfirmationRequired(
                action="create_event",
                details=(
                    f"Create calendar event '{summary}' starting at "
                    f"{start.get('dateTime', start.get('date', '?'))}? "
                    "Please confirm."
                ),
            )
        created = await self._call_object("POST", self._event_url("primary"), json=event_data)
        return _shape_event(created)

    async def update_event(
        self,
        event_id: str,
        calendar_id: Optional[str] = None,
        summary: Optional[str] = None,
        description: Optional[str] = None,
        location: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        attendees: Optional[list[str]] = None,
        notify_attendees: Optional[bool] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        eid = require_id(event_id, "event_id")
        cal = _calendar(calendar_id)
        changes: dict[str, Any] = {}
        if (value := optional_line(summary, "summary")) is not None:
            changes["summary"] = value
        if (text := optional_text(description, "description", max_chars=20_000)) is not None:
            changes["description"] = text
        if (value := optional_line(location, "location")) is not None:
            changes["location"] = value
        for field, raw in (("start", start), ("end", end)):
            if (when := _when(raw, field)) is not None:
                changes[field] = when
        if attendees is not None:
            if not isinstance(attendees, list) or len(attendees) > 100:
                raise ConnectorError("'attendees' must be a list of at most 100 email addresses.")
            changes["attendees"] = [{"email": require_email(a, "attendees")} for a in attendees]
        notify = optional_bool(notify_attendees, "notify_attendees", True)
        if not changes:
            raise ConnectorError("Give at least one field to change on the event.")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="update_event",
                details=(
                    f"Update calendar event {eid} on calendar '{cal}': set {sorted(changes)}"
                    f"{' and email the guests' if notify else ''}?"
                ),
            )
        updated = await self._call_object(
            "PATCH",
            self._event_url(cal, eid),
            params={"sendUpdates": "all" if notify else "none"},
            json=changes,
        )
        return _shape_event(updated)

    async def respond_to_invite(
        self,
        event_id: str,
        response: str,
        calendar_id: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Set the user's own RSVP on an invitation.

        The guest list is read, the user's entry (``self: true``) changed,
        and the list written back with the event's etag as ``If-Match`` so a
        concurrent change to the guest list is refused, not overwritten.
        """
        eid = require_id(event_id, "event_id")
        cal = _calendar(calendar_id)
        if response not in _RESPONSES:
            raise ConnectorError(f"'response' must be one of {', '.join(_RESPONSES)}.")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="respond_to_invite",
                details=f"Answer '{response}' to calendar invitation {eid}? The organizer is notified.",
            )
        event = await self._call_object("GET", self._event_url(cal, eid))
        attendees = [a for a in as_list(event.get("attendees")) if isinstance(a, dict)]
        mine = next((a for a in attendees if a.get("self") is True), None)
        if mine is None:
            raise ConnectorError(f"You are not a guest of event {eid}, so there is nothing to answer.")
        mine["responseStatus"] = response
        etag = event.get("etag")
        headers = {"If-Match": etag} if isinstance(etag, str) and etag else None
        updated = await self._call_object(
            "PATCH",
            self._event_url(cal, eid),
            params={"sendUpdates": "all"},
            json={"attendees": attendees},
            headers=headers,
        )
        return {"status": response, **_shape_event(updated)}

    # -- DELETE ----------------------------------------------------------------

    async def delete_event(
        self,
        event_id: str,
        calendar_id: Optional[str] = None,
        notify_attendees: Optional[bool] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        eid = require_id(event_id, "event_id")
        cal = _calendar(calendar_id)
        notify = optional_bool(notify_attendees, "notify_attendees", True)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_event",
                details=(
                    f"Delete calendar event {eid} from calendar '{cal}'"
                    f"{' and email the guests a cancellation' if notify else ''}? "
                    "This cannot be undone."
                ),
            )
        await self._call(
            "DELETE", self._event_url(cal, eid), params={"sendUpdates": "all" if notify else "none"}
        )
        return {"status": "deleted", "id": eid, "calendar_id": cal}
