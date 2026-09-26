"""Shared plumbing for the Microsoft 365 connector: Graph URLs, argument
validation, output shaping and safe ``@odata.nextLink`` pagination.

Why it exists: the mail, calendar, OneDrive, To Do and contacts mixins all
validate model-supplied arguments, quote OData values and page through Graph
collections the same way. Keeping one copy means one place enforces that a
provider-supplied next link can never leave the collection it came from.
Talks to Microsoft Graph v1.0 (https://graph.microsoft.com/v1.0/me/...) only
through ``BaseConnector._request`` / ``_request_json`` (policy-checked,
pinned, error-mapped). Depends on ``services/connectors/base.py`` and
``services/connectors/shaping.py``.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any, Optional
from urllib.parse import unquote, urlparse

import httpx

from ..base import BaseConnector, ConnectorError
from ..shaping import cap_text, collect_pages

GRAPH_HOST = "graph.microsoft.com"
GRAPH_API = f"https://{GRAPH_HOST}/v1.0"
#: Every Graph call this connector makes lives under the signed-in user.
ME = f"{GRAPH_API}/me"
#: Human-readable connector name used in error messages.
CONNECTOR_NAME = "Microsoft 365"

#: Mail reads ask Outlook for plain-text bodies instead of HTML.
PREFER_TEXT_BODY = {"Prefer": 'outlook.body-content-type="text"'}

# Upper bounds on model-supplied strings, so a runaway argument cannot turn
# into a multi-megabyte request.
MAX_ID_CHARS = 1024
MAX_SHORT_TEXT = 1000
MAX_LONG_TEXT = 100_000
MAX_RECIPIENTS = 50

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_RE = re.compile(r"^[^@\s<>\"(),;:]+@[^@\s<>\"(),;:]+\.[^@\s<>\"(),;:]+$")
_TIME_ZONE_RE = re.compile(r"^[A-Za-z0-9_+\-/ ().:]{1,64}$")

#: MIME types (beyond text/*) and file extensions treated as readable text.
_TEXT_MIME_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/csv",
        "application/x-yaml",
        "application/yaml",
        "application/javascript",
        "application/x-javascript",
        "application/sql",
        "application/x-sh",
        "application/x-ndjson",
        "message/rfc822",
    }
)
_TEXT_EXTENSIONS = frozenset(
    {
        "txt", "md", "markdown", "csv", "tsv", "json", "xml", "yaml", "yml", "log",
        "html", "htm", "ics", "vcf", "ini", "cfg", "conf", "toml", "sql", "sh",
        "py", "js", "ts", "css", "rst", "tex", "srt", "vtt", "eml",
    }
)


# ---------------------------------------------------------------------------
# Errors and JSON shapes
# ---------------------------------------------------------------------------


def malformed() -> ConnectorError:
    """The one error a response with an unexpected shape becomes."""
    return ConnectorError(f"Malformed response from {CONNECTOR_NAME}.")


def json_object(data: Any) -> dict[str, Any]:
    """*data* when Graph answered with a JSON object, else a clean error."""
    if not isinstance(data, dict):
        raise malformed()
    return data


def text_of(value: Any, limit: int = MAX_SHORT_TEXT) -> Optional[str]:
    """A provider string cut to *limit* chars; anything else becomes None.

    Used for short display fields (names, subjects) so a hostile payload
    with a huge or wrongly typed value can neither crash nor flood a result.
    """
    if isinstance(value, str):
        return value[:limit]
    return None


def sub(mapping: Any, key: str) -> dict[str, Any]:
    """``mapping[key]`` when both are objects, else ``{}``."""
    if isinstance(mapping, dict):
        value = mapping.get(key)
        if isinstance(value, dict):
            return value
    return {}


def address_of(entry: Any) -> Optional[str]:
    """``"Name <address>"`` (or just the address) from a Graph recipient."""
    email = sub(entry, "emailAddress")
    address = text_of(email.get("address"), 320)
    name = text_of(email.get("name"), 200)
    if address and name and name != address:
        return f"{name} <{address}>"
    return address or name


def addresses_of(entries: Any) -> list[str]:
    """Every recipient in a Graph recipient list, skipping malformed ones."""
    if not isinstance(entries, list):
        return []
    found = (address_of(entry) for entry in entries[:MAX_RECIPIENTS])
    return [value for value in found if value]


def when_of(value: Any) -> Optional[str]:
    """The ``dateTime`` of a Graph ``dateTimeTimeZone``, suffixed with its zone."""
    if not isinstance(value, dict):
        return None
    moment = text_of(value.get("dateTime"), 64)
    zone = text_of(value.get("timeZone"), 64)
    if moment and zone:
        return f"{moment} ({zone})"
    return moment


def capped_text(text: Any, limit: int, *, hint: str) -> dict[str, Any]:
    """``{"text", "truncated"}`` plus *hint* when the text was cut."""
    body, truncated = cap_text(text if isinstance(text, str) else "", limit)
    result: dict[str, Any] = {"text": body, "truncated": truncated}
    if truncated:
        result["hint"] = hint
    return result


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


def require_text(value: Any, field: str, *, max_chars: int = MAX_SHORT_TEXT) -> str:
    """A non-empty string argument, stripped, at most *max_chars* long."""
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError(f"'{field}' is required and must be a non-empty string.")
    if len(value) > max_chars:
        raise ConnectorError(f"'{field}' is too long (at most {max_chars} characters).")
    return value.strip()


def optional_text(value: Any, field: str, *, max_chars: int = MAX_SHORT_TEXT) -> Optional[str]:
    """``None`` when omitted, else the same rules as ``require_text``.

    Long bodies keep their inner whitespace; only the ends are stripped.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConnectorError(f"'{field}' must be a string.")
    if len(value) > max_chars:
        raise ConnectorError(f"'{field}' is too long (at most {max_chars} characters).")
    return value


def require_id(value: Any, field: str) -> str:
    """An opaque Graph id: a non-empty string without control characters.

    It still goes through ``path_segment()`` at the call site; this only
    rejects values no real id can have, with a clear message.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError(f"'{field}' is required and must be a non-empty string.")
    value = value.strip()
    if len(value) > MAX_ID_CHARS or _CONTROL_RE.search(value):
        raise ConnectorError(f"'{field}' is not a valid id.")
    return value


def optional_id(value: Any, field: str) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return require_id(value, field)


def optional_bool(value: Any, field: str, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConnectorError(f"'{field}' must be true or false.")
    return value


def choice(value: Any, field: str, allowed: tuple[str, ...], *, default: str) -> str:
    """One of *allowed* (case-insensitive), or *default* when omitted."""
    if value is None:
        return default
    if isinstance(value, str):
        for option in allowed:
            if value.strip().lower() == option.lower():
                return option
    raise ConnectorError(f"'{field}' must be one of: {', '.join(allowed)}.")


def email_list(value: Any, field: str, *, required: bool) -> list[str]:
    """Email addresses from a list or a comma/semicolon separated string."""
    if value is None or value == "" or value == []:
        if required:
            raise ConnectorError(f"'{field}' needs at least one email address.")
        return []
    if isinstance(value, str):
        items: list[Any] = list(re.split(r"[,;]", value))
    elif isinstance(value, list):
        items = value
    else:
        raise ConnectorError(f"'{field}' must be a list of email addresses.")
    addresses: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ConnectorError(f"'{field}' must contain only email address strings.")
        address = item.strip()
        if not address:
            continue
        if len(address) > 320 or not _EMAIL_RE.match(address):
            raise ConnectorError(f"'{field}' contains an invalid email address: {address[:80]!r}.")
        if address.lower() not in (a.lower() for a in addresses):
            addresses.append(address)
    if required and not addresses:
        raise ConnectorError(f"'{field}' needs at least one email address.")
    if len(addresses) > MAX_RECIPIENTS:
        raise ConnectorError(f"'{field}' has too many addresses (at most {MAX_RECIPIENTS}).")
    return addresses


def recipients(addresses: list[str]) -> list[dict[str, Any]]:
    """Graph ``recipient`` objects for plain addresses."""
    return [{"emailAddress": {"address": address}} for address in addresses]


def odata_string(value: str) -> str:
    """A single-quoted OData string literal (quotes doubled)."""
    return "'" + value.replace("'", "''") + "'"


def search_phrase(value: str) -> str:
    """A ``$search`` value as Graph requires: the whole clause in double
    quotes, with backslashes and double quotes inside escaped."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def parse_moment(value: Any, field: str) -> datetime:
    """An ISO 8601 date or date-time as an aware UTC datetime.

    A value without an offset is read as UTC; a bare date is midnight UTC.
    """
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError(f"'{field}' must be an ISO 8601 date or date-time string.")
    text = value.strip()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        raise ConnectorError(
            f"'{field}' must be an ISO 8601 date or date-time, e.g. 2026-10-01T09:00:00Z."
        ) from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def utc_iso(moment: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` for an aware datetime."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def time_zone(value: Any, field: str = "time_zone") -> str:
    """A Windows or IANA time-zone name (Graph accepts both); default UTC."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return "UTC"
    if not isinstance(value, str) or not _TIME_ZONE_RE.match(value.strip()):
        raise ConnectorError(
            f"'{field}' must be a time-zone name such as 'UTC', 'Europe/London' "
            "or 'Pacific Standard Time'."
        )
    return value.strip()


def graph_time(value: Any, field: str, zone: str) -> dict[str, str]:
    """A Graph ``dateTimeTimeZone`` for an event start or end.

    A wall-clock value (no offset) is kept as given and read in *zone*. A
    value carrying an offset is converted to UTC, which is then its zone.
    """
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError(f"'{field}' must be an ISO 8601 date-time string.")
    text = value.strip()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        raise ConnectorError(
            f"'{field}' must be an ISO 8601 date-time, e.g. 2026-10-01T09:00:00."
        ) from None
    if moment.tzinfo is not None:
        return {"dateTime": utc_iso(moment)[:-1], "timeZone": "UTC"}
    return {"dateTime": moment.strftime("%Y-%m-%dT%H:%M:%S"), "timeZone": zone}


def due_date(value: Any, field: str = "due_date") -> Optional[dict[str, str]]:
    """A To Do ``dueDateTime`` from a ``YYYY-MM-DD`` date."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ConnectorError(f"'{field}' must be a date like 2026-10-01.")
    try:
        day = date.fromisoformat(value.strip()[:10])
    except ValueError:
        raise ConnectorError(f"'{field}' must be a date like 2026-10-01.") from None
    return {"dateTime": f"{day.isoformat()}T00:00:00", "timeZone": "UTC"}


# ---------------------------------------------------------------------------
# Text files and attachments
# ---------------------------------------------------------------------------


def is_text_like(name: Any, content_type: Any) -> bool:
    """True for plain-text MIME types and well-known text file extensions."""
    mime = content_type.split(";", 1)[0].strip().lower() if isinstance(content_type, str) else ""
    if mime.startswith("text/") or mime in _TEXT_MIME_TYPES or mime.endswith("+json") or mime.endswith("+xml"):
        return True
    if isinstance(name, str) and "." in name:
        return name.rsplit(".", 1)[1].strip().lower() in _TEXT_EXTENSIONS
    return False


def decode_text(raw: bytes, *, what: str) -> str:
    """Bytes of a text file as a string; binary content is refused.

    UTF-16 is recognised by its byte-order mark; anything else is read as
    UTF-8 (undecodable bytes replaced). Otherwise a NUL byte in the first
    8 KiB means the "text" file is really binary, and handing its bytes to
    the model would be noise at best.
    """
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if b"\x00" in raw[:8192]:
        raise ConnectorError(f"{what} is not a text file, so it cannot be read as text.")
    return raw.decode("utf-8-sig", errors="replace")


# ---------------------------------------------------------------------------
# Graph base: requests and pagination
# ---------------------------------------------------------------------------


class GraphBase(BaseConnector):
    """Graph request and pagination helpers shared by every mixin.

    Abstract: ``services/connectors/microsoft.py`` supplies the name,
    authentication and health check.
    """

    async def _graph(self, method: str, path: str, **kwargs: Any) -> Any:
        """``_request_json`` against ``/v1.0/me<path>``."""
        return await self._request_json(method, f"{ME}{path}", **kwargs)

    async def _graph_response(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """``_request`` against ``/v1.0/me<path>`` (raw body, 2xx only)."""
        return await self._request(method, f"{ME}{path}", **kwargs)

    async def _graph_object(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return json_object(await self._graph(method, path, **kwargs))

    async def _graph_list(
        self,
        path: str,
        params: dict[str, Any],
        *,
        limit: int,
        headers: Optional[dict[str, str]] = None,
    ) -> list[dict[str, Any]]:
        """Up to *limit* items of a Graph collection.

        Asks for ``$top`` so one request usually suffices, then follows
        ``@odata.nextLink`` only while it stays on this exact collection
        (``_next_page_url``) and ``collect_pages`` allows (limit, repeated
        link, five pages at most). Non-object items are dropped.
        """
        first_url = f"{ME}{path}"
        collection_path = urlparse(first_url).path

        async def fetch(cursor: Optional[str]) -> tuple[list[Any], Optional[str]]:
            if cursor is None:
                data = await self._request_json("GET", first_url, params=params, headers=headers)
            else:
                data = await self._request_json("GET", cursor, headers=headers)
            body = json_object(data)
            items = body.get("value")
            if not isinstance(items, list):
                raise malformed()
            next_url = self._next_page_url(body.get("@odata.nextLink"), collection_path)
            return [item for item in items if isinstance(item, dict)], next_url

        return await collect_pages(fetch, limit=limit)

    def _next_page_url(self, link: Any, collection_path: str) -> Optional[str]:
        """*link* when it is safe to follow, else ``None`` (stop paging).

        ``@odata.nextLink`` is a URL chosen by the provider (or by whoever
        can tamper with the response), so it is never trusted as is: it
        must be https on graph.microsoft.com's default port, carry no user
        info, and point at the same collection path as the first request.
        The network policy hook re-checks it on the wire as well.
        """
        if link is None or link == "":
            return None
        if not isinstance(link, str) or len(link) > 8192:
            self._log.warning("graph_next_link_refused", reason="not a string")
            return None
        try:
            parsed = urlparse(link)
            port = parsed.port
        except ValueError:
            self._log.warning("graph_next_link_refused", reason="unparseable")
            return None
        same_collection = unquote(parsed.path).lower() == unquote(collection_path).lower()
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() != GRAPH_HOST
            or port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or not same_collection
        ):
            # Host and path only: the query carries paging tokens.
            self._log.warning(
                "graph_next_link_refused",
                host=parsed.hostname,
                path=parsed.path[:200],
            )
            return None
        return link
