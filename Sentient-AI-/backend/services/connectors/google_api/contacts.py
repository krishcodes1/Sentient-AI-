"""Google Contacts actions of the Google Workspace connector (People API):
search and read contacts, create, update (with etag handling) and delete them.

Why it exists: keeps the People API field masks, person shaping and the
read-modify-write update cycle out of ``google_workspace.py``.

External service: the Google People API v1 (https://people.googleapis.com/v1/).
Depends on ``google_api.client`` (GoogleBase, validation), ``base`` (errors,
path_segment) and ``definition``.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import cap_text, clamp_limit

from .client import (
    PEOPLE_API,
    GoogleBase,
    as_dict,
    as_list,
    is_precondition_failure,
    optional_line,
    optional_text,
    require_email,
    require_line,
    scalar,
)

# searchContacts accepts at most 30 results per call.
MAX_SEARCH_RESULTS = 30
NOTES_CHARS = 1000
_READ_MASK = "names,emailAddresses,phoneNumbers,organizations,biographies"
_PERSON_ID_RE = re.compile(r"^(?:people/)?([A-Za-z0-9_-]{1,128})$")
# Person fields update_contact may change, by argument name.
_UPDATE_FIELDS = ("given_name", "family_name", "email", "phone", "organization", "notes")

_RESOURCE = {"type": "string", "description": "Contact resource name (people/c123...)", "required": True}
_FIELDS: dict[str, dict[str, Any]] = {
    "family_name": {"type": "string"},
    "email": {"type": "string"},
    "phone": {"type": "string"},
    "organization": {"type": "string"},
    "notes": {"type": "string"},
}

CONTACTS_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "search_contacts",
        "Search Google Contacts by name, email or phone.",
        ActionCategory.READ,
        _schema(
            query={"type": "string", "required": True},
            limit={"type": "integer", "description": "How many (default 10, max 30)"},
        ),
        policy_key="google_contacts",
        required_scope="contacts.read",
    ),
    ToolSpec(
        "get_contact",
        "Read one Google contact by resource name.",
        ActionCategory.READ,
        _schema(resource_name=_RESOURCE),
        policy_key="google_contacts",
        required_scope="contacts.read",
    ),
    ToolSpec(
        "create_contact",
        "Create a Google contact.",
        ActionCategory.WRITE,
        _schema(given_name={"type": "string", "required": True}, **_FIELDS),
        policy_key="google_contacts",
        required_scope="contacts.write",
        risk="low",
        low_risk_note="add new contacts",
    ),
    ToolSpec(
        "update_contact",
        "Change fields of a Google contact. A given email or phone becomes the primary "
        "one (others are kept); other given fields replace the old value.",
        ActionCategory.WRITE,
        _schema(resource_name=_RESOURCE, given_name={"type": "string"}, **_FIELDS),
        policy_key="google_contacts",
        required_scope="contacts.write",
    ),
    ToolSpec(
        "delete_contact",
        "Delete a Google contact. Cannot be undone.",
        ActionCategory.DELETE,
        _schema(resource_name=_RESOURCE),
        policy_key="google_contacts",
        required_scope="contacts.write",
        always_confirm=True,
    ),
)


def _person_id(value: Any) -> str:
    """The id part of ``people/<id>`` (or a bare id), strictly validated."""
    text = require_line(value, "resource_name", max_chars=200)
    match = _PERSON_ID_RE.match(text)
    if not match:
        raise ConnectorError("'resource_name' must look like people/c123456789.")
    return match.group(1)


def _values(entries: Any, key: str) -> list[str]:
    return [v for v in (scalar(as_dict(e).get(key)) for e in as_list(entries)[:10]) if v]


def shape_person(raw: Any) -> dict[str, Any]:
    person = as_dict(raw)
    name = as_dict(next(iter(as_list(person.get("names"))), {}))
    org = as_dict(next(iter(as_list(person.get("organizations"))), {}))
    shaped: dict[str, Any] = {"resource_name": scalar(person.get("resourceName"))}
    for key, value in (
        ("name", name.get("displayName")),
        ("given_name", name.get("givenName")),
        ("family_name", name.get("familyName")),
        ("organization", org.get("name")),
        ("title", org.get("title")),
    ):
        text = scalar(value)
        if text:
            shaped[key] = text
    shaped["emails"] = _values(person.get("emailAddresses"), "value")
    shaped["phones"] = _values(person.get("phoneNumbers"), "value")
    notes = as_dict(next(iter(as_list(person.get("biographies"))), {})).get("value")
    if isinstance(notes, str) and notes:
        shaped["notes"], cut = cap_text(notes, NOTES_CHARS)
        if cut:
            shaped["notes_truncated"] = True
    return shaped


def _primary_first(existing: Any, value: str) -> list[dict[str, Any]]:
    """*value* as the first entry, keeping the other existing entries."""
    others = [
        as_dict(e) for e in as_list(existing)
        if isinstance(e, dict) and str(e.get("value", "")).lower() != value.lower()
    ]
    return [{"value": value}] + others[:20]


class ContactsActions(GoogleBase):
    """Google Contacts action coroutines (mixed into GoogleWorkspaceConnector)."""

    def _person_url(self, person_id: str, suffix: str = "") -> str:
        return f"{PEOPLE_API}/people/{path_segment(person_id)}{suffix}"

    # -- READ ------------------------------------------------------------------

    async def search_contacts(self, query: str, limit: Any = None) -> list[dict[str, Any]]:
        # Google recommends a warm-up search with an empty query before the
        # first real one; it is skipped to keep one request per call (a cold
        # cache can return fewer results on the very first search).
        words = require_line(query, "query", max_chars=200)
        count = clamp_limit(limit, maximum=MAX_SEARCH_RESULTS)
        data = await self._call_object(
            "GET",
            f"{PEOPLE_API}/people:searchContacts",
            params={"query": words, "readMask": _READ_MASK, "pageSize": count},
        )
        return [
            shape_person(as_dict(item).get("person"))
            for item in as_list(data.get("results"))[:count]
            if isinstance(item, dict)
        ]

    async def get_contact(self, resource_name: str) -> dict[str, Any]:
        person = await self._call_object(
            "GET", self._person_url(_person_id(resource_name)), params={"personFields": _READ_MASK}
        )
        return shape_person(person)

    # -- WRITE -----------------------------------------------------------------

    async def create_contact(
        self,
        given_name: str,
        family_name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        organization: Optional[str] = None,
        notes: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        given = require_line(given_name, "given_name", max_chars=200)
        family = optional_line(family_name, "family_name", max_chars=200)
        address = require_email(email, "email") if email else None
        number = optional_line(phone, "phone", max_chars=50)
        org = optional_line(organization, "organization", max_chars=200)
        text = optional_text(notes, "notes", max_chars=5000)
        if not user_confirmed:
            label = " ".join(x for x in (given, family) if x)
            raise UserConfirmationRequired(
                action="create_contact",
                details=f"Create the Google contact '{label}'{f' <{address}>' if address else ''}?",
            )
        body: dict[str, Any] = {"names": [{"givenName": given, **({"familyName": family} if family else {})}]}
        if address:
            body["emailAddresses"] = [{"value": address}]
        if number:
            body["phoneNumbers"] = [{"value": number}]
        if org:
            body["organizations"] = [{"name": org}]
        if text:
            body["biographies"] = [{"value": text, "contentType": "TEXT_PLAIN"}]
        created = await self._call_object(
            "POST", f"{PEOPLE_API}/people:createContact", params={"personFields": _READ_MASK}, json=body
        )
        return shape_person(created)

    async def update_contact(
        self,
        resource_name: str,
        given_name: Optional[str] = None,
        family_name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        organization: Optional[str] = None,
        notes: Optional[str] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Read the contact (for its etag and current values), merge the
        changes, write them back. If the contact changed in between (People
        answers 400 FAILED_PRECONDITION) the cycle runs once more."""
        person_id = _person_id(resource_name)
        changes = {
            "given_name": optional_line(given_name, "given_name", max_chars=200),
            "family_name": optional_line(family_name, "family_name", max_chars=200),
            "email": require_email(email, "email") if email else None,
            "phone": optional_line(phone, "phone", max_chars=50),
            "organization": optional_line(organization, "organization", max_chars=200),
            "notes": optional_text(notes, "notes", max_chars=5000),
        }
        wanted = {k: v for k, v in changes.items() if v is not None}
        if not wanted:
            raise ConnectorError(f"Give at least one of {', '.join(_UPDATE_FIELDS)} to change.")
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="update_contact",
                details=f"Update Google contact people/{person_id}: set {sorted(wanted)}?",
            )
        for attempt in range(2):
            current = await self._call_object(
                "GET", self._person_url(person_id), params={"personFields": _READ_MASK}
            )
            body, fields = self._merge(current, wanted)
            try:
                updated = await self._call_object(
                    "PATCH",
                    self._person_url(person_id, ":updateContact"),
                    params={"updatePersonFields": ",".join(fields), "personFields": _READ_MASK},
                    json=body,
                )
                return shape_person(updated)
            except ConnectorError as exc:
                if attempt == 0 and is_precondition_failure(exc):
                    continue
                if is_precondition_failure(exc):
                    raise ConnectorError(
                        "The contact kept changing while it was being updated; try again."
                    ) from None
                raise
        raise ConnectorError("The contact could not be updated.")  # pragma: no cover

    @staticmethod
    def _merge(current: dict[str, Any], wanted: dict[str, str]) -> tuple[dict[str, Any], list[str]]:
        """The update body (with the etag) and its updatePersonFields."""
        body: dict[str, Any] = {"etag": current.get("etag")}
        sources = [
            {k: s[k] for k in ("type", "id", "etag") if k in s}
            for s in as_list(as_dict(current.get("metadata")).get("sources"))
            if isinstance(s, dict)
        ]
        if sources:
            body["metadata"] = {"sources": sources}
        fields: list[str] = []
        if "given_name" in wanted or "family_name" in wanted:
            name = {
                k: v for k, v in as_dict(next(iter(as_list(current.get("names"))), {})).items()
                if k in ("givenName", "familyName", "middleName")
            }
            if "given_name" in wanted:
                name["givenName"] = wanted["given_name"]
            if "family_name" in wanted:
                name["familyName"] = wanted["family_name"]
            body["names"] = [name]
            fields.append("names")
        if "email" in wanted:
            body["emailAddresses"] = _primary_first(current.get("emailAddresses"), wanted["email"])
            fields.append("emailAddresses")
        if "phone" in wanted:
            body["phoneNumbers"] = _primary_first(current.get("phoneNumbers"), wanted["phone"])
            fields.append("phoneNumbers")
        if "organization" in wanted:
            body["organizations"] = [{"name": wanted["organization"]}]
            fields.append("organizations")
        if "notes" in wanted:
            body["biographies"] = [{"value": wanted["notes"], "contentType": "TEXT_PLAIN"}]
            fields.append("biographies")
        return body, fields

    # -- DELETE ----------------------------------------------------------------

    async def delete_contact(self, resource_name: str, *, user_confirmed: bool = False) -> dict[str, Any]:
        person_id = _person_id(resource_name)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="delete_contact",
                details=f"Delete Google contact people/{person_id}? This cannot be undone.",
            )
        await self._call("DELETE", self._person_url(person_id, ":deleteContact"))
        return {"status": "deleted", "resource_name": f"people/{person_id}"}
