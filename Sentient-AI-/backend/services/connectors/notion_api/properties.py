"""Renders Notion page and database property values compactly, and builds
property values for writes from the plain values the model supplies.

Why it exists: a Notion property value is a deeply nested object (a select is
``{"type": "select", "select": {"id", "name", "color"}}``). The model needs
``"Done"``, not the envelope, and should be able to write ``{"Status": "Done"}``
without knowing Notion's shapes. Every common type is covered (title,
rich_text, number, select, multi_select, status, date, people, checkbox, url,
email, phone_number, relation, formula, rollup and a few read-only ones);
unknown types render as their type name only.

It connects to the sibling action modules ``reads.py`` (get_page,
query_database, get_database), ``writes.py`` (update_page_properties,
create_database_row) and ``common.py`` (Notion id check). It talks to no
external service and depends on ``services.connectors.base``
(ConnectorError), ``services.connectors.shaping`` (cap_text) and the sibling
``markdown`` module (rich-text conversion).
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Mapping, Optional

from services.connectors.base import ConnectorError
from services.connectors.shaping import cap_text

from .markdown import ARRAY_MAX_ITEMS, markdown_to_rich_text, rich_text_plain

#: Items shown for a multi-valued property (multi_select, people, relation).
_MAX_LIST_VALUES = 25
#: Most properties one write may set.
MAX_WRITE_PROPERTIES = 50
#: Longest text one title or rich_text property value may carry. Checked
#: before the inline Markdown parse, so a hostile value costs nothing.
MAX_PROPERTY_TEXT_CHARS = 20_000
#: Largest properties object (as JSON) one write accepts, so 50 long text
#: values cannot add up to a slow parse before approval.
MAX_PROPERTIES_JSON_CHARS = 100_000
#: Property types a write may set.
WRITABLE_TYPES = frozenset(
    {
        "title",
        "rich_text",
        "number",
        "select",
        "multi_select",
        "status",
        "date",
        "people",
        "checkbox",
        "url",
        "email",
        "phone_number",
        "relation",
    }
)

_ID_RE = re.compile(
    r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


def is_notion_id(value: Any) -> bool:
    """True for a Notion id: 32 hex characters, with or without dashes."""
    return isinstance(value, str) and bool(_ID_RE.match(value))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _text(value: Any, max_chars: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text, truncated = cap_text(value, max_chars)
    return text + "..." if truncated else text


def _name(value: Any) -> Optional[str]:
    if isinstance(value, dict) and isinstance(value.get("name"), str):
        return str(value["name"])
    return None


def _date(value: Any) -> Optional[str]:
    if not isinstance(value, dict) or not isinstance(value.get("start"), str):
        return None
    end = value.get("end")
    return f"{value['start']} to {end}" if isinstance(end, str) and end else str(value["start"])


def _person(value: Any) -> Optional[str]:
    if not isinstance(value, dict):
        return None
    name = value.get("name")
    if isinstance(name, str) and name:
        return name
    ident = value.get("id")
    return str(ident) if isinstance(ident, str) else None


def _number(value: Any) -> Optional[float | int]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    return value


def _listed(values: Any, render: Any) -> list[Any]:
    if not isinstance(values, list):
        return []
    out = [item for item in (render(v) for v in values[:_MAX_LIST_VALUES]) if item is not None]
    if len(values) > _MAX_LIST_VALUES:
        out.append(f"... {len(values) - _MAX_LIST_VALUES} more")
    return out


def _formula(value: Any) -> Any:
    if not isinstance(value, dict):
        return None
    kind = value.get("type")
    inner = value.get(kind) if isinstance(kind, str) else None
    if kind == "date":
        return _date(inner)
    if kind == "number":
        return _number(inner)
    if kind in ("string", "boolean") and isinstance(inner, (str, bool)):
        return inner
    return None


def _rollup(value: Any, max_chars: int) -> Any:
    if not isinstance(value, dict):
        return None
    kind = value.get("type")
    if kind == "number":
        return _number(value.get("number"))
    if kind == "date":
        return _date(value.get("date"))
    if kind == "array":
        items = value.get("array")
        return _listed(items, lambda item: render_property(item, max_chars=max_chars))
    return f"<rollup {kind}>" if isinstance(kind, str) else None


def render_property(prop: Any, *, max_chars: int = 300) -> Any:
    """One property value as a compact JSON value (string, number, bool,
    list or None). Unknown types render as ``<type>``."""
    if not isinstance(prop, dict):
        return None
    ptype = prop.get("type")
    if not isinstance(ptype, str):
        return None
    value = prop.get(ptype)
    if ptype in ("title", "rich_text"):
        return _text(rich_text_plain(value), max_chars)
    if ptype == "number":
        return _number(value)
    if ptype in ("select", "status"):
        return _name(value)
    if ptype == "multi_select":
        return _listed(value, _name)
    if ptype == "date":
        return _date(value)
    if ptype in ("people", "created_by", "last_edited_by"):
        return _listed(value, _person) if ptype == "people" else _person(value)
    if ptype == "checkbox":
        return value if isinstance(value, bool) else None
    if ptype in ("url", "email", "phone_number", "created_time", "last_edited_time"):
        return _text(value, max_chars)
    if ptype == "relation":
        ids = _listed(value, lambda item: item.get("id") if isinstance(item, dict) else None)
        if prop.get("has_more") is True:
            ids.append("... more")
        return ids
    if ptype == "formula":
        return _formula(value)
    if ptype == "rollup":
        return _rollup(value, max_chars)
    if ptype == "files":
        return _listed(value, lambda item: _text(item.get("name"), 200) if isinstance(item, dict) else None)
    if ptype == "unique_id" and isinstance(value, dict):
        number = _number(value.get("number"))
        prefix = value.get("prefix")
        return f"{prefix}-{number}" if isinstance(prefix, str) and prefix else number
    if ptype == "verification" and isinstance(value, dict):
        return _text(value.get("state"), 50)
    return f"<{ptype}>"


def render_properties(
    properties: Any, *, max_chars: int = 300, skip_title: bool = False
) -> dict[str, Any]:
    """Every property of a page as ``{name: compact value}``."""
    if not isinstance(properties, dict):
        return {}
    out: dict[str, Any] = {}
    for name, prop in properties.items():
        if not isinstance(name, str) or not isinstance(prop, dict):
            continue
        if skip_title and prop.get("type") == "title":
            continue
        out[name] = render_property(prop, max_chars=max_chars)
    return out


def page_title(page: Any) -> str:
    """The plain title of a page (its ``title`` property) or a database."""
    if not isinstance(page, dict):
        return ""
    title = page.get("title")
    if isinstance(title, list):  # a database object
        return rich_text_plain(title)
    properties = page.get("properties")
    if isinstance(properties, dict):
        for prop in properties.values():
            if isinstance(prop, dict) and prop.get("type") == "title":
                return rich_text_plain(prop.get("title"))
    return ""


def render_schema(properties: Any) -> dict[str, Any]:
    """A database's property schema: ``{name: type}``, or ``{type, options}``
    for select, multi_select and status columns."""
    if not isinstance(properties, dict):
        return {}
    out: dict[str, Any] = {}
    for name, prop in properties.items():
        if not isinstance(name, str) or not isinstance(prop, dict):
            continue
        ptype = prop.get("type")
        if not isinstance(ptype, str):
            continue
        config = prop.get(ptype)
        options = config.get("options") if isinstance(config, dict) else None
        if ptype in ("select", "multi_select", "status") and isinstance(options, list):
            out[name] = {"type": ptype, "options": _listed(options, _name)}
        else:
            out[name] = ptype
    return out


def schema_types(properties: Any) -> dict[str, str]:
    """``{name: type}`` from a page's or database's ``properties``."""
    if not isinstance(properties, dict):
        return {}
    return {
        name: prop["type"]
        for name, prop in properties.items()
        if isinstance(name, str) and isinstance(prop, dict) and isinstance(prop.get("type"), str)
    }


# ---------------------------------------------------------------------------
# Building values for writes
# ---------------------------------------------------------------------------


def typed_value(value: Any) -> Optional[tuple[str, Any]]:
    """``(type, inner)`` when *value* names its type (``{"select": "Done"}``
    or a full Notion value such as ``{"select": {"name": "Done"}}``)."""
    if isinstance(value, dict) and len(value) == 1:
        (key, inner), = value.items()
        if key in WRITABLE_TYPES:
            return key, inner
    return None


def needs_schema(values: Mapping[str, Any]) -> bool:
    """True when some value is plain, so its type must come from the schema."""
    return any(typed_value(value) is None for value in values.values())


def _fail(name: str, message: str) -> ConnectorError:
    return ConnectorError(f"Property '{name}': {message}")


def _id_list(name: str, value: Any) -> list[dict[str, str]]:
    items = value if isinstance(value, list) else [value]
    if len(items) > ARRAY_MAX_ITEMS:
        raise _fail(name, f"at most {ARRAY_MAX_ITEMS} ids")
    ids: list[dict[str, str]] = []
    for item in items:
        ident = item.get("id") if isinstance(item, dict) else item
        if not is_notion_id(ident):
            raise _fail(name, "expected Notion ids (32 hex characters)")
        ids.append({"id": str(ident)})
    return ids


def _option(name: str, value: Any) -> Optional[dict[str, str]]:
    if value is None:
        return None
    if isinstance(value, dict) and isinstance(value.get("name"), str):
        value = value["name"]
    if not isinstance(value, str) or not value.strip() or len(value) > 100:
        raise _fail(name, "expected an option name (text up to 100 characters)")
    if "," in value:
        raise _fail(name, "option names cannot contain commas")
    return {"name": value.strip()}


def _convert(name: str, ptype: str, value: Any) -> Any:
    """The Notion value of type *ptype* for a plain *value*."""
    if ptype in ("title", "rich_text"):
        if value is None:
            return []
        formatting = True
        if isinstance(value, list):
            # A Notion rich-text array: keep its text, drop its formatting.
            if len(value) > ARRAY_MAX_ITEMS:
                raise _fail(name, f"at most {ARRAY_MAX_ITEMS} rich-text items")
            value, formatting = rich_text_plain(value), False
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str):
            raise _fail(name, "expected text")
        if len(value) > MAX_PROPERTY_TEXT_CHARS:
            raise _fail(name, f"text is longer than {MAX_PROPERTY_TEXT_CHARS} characters")
        rich = markdown_to_rich_text(value, formatting=formatting)
        if len(rich) > ARRAY_MAX_ITEMS:
            raise _fail(name, "text is too long for one property")
        return rich
    if ptype == "number":
        if value is None:
            return None
        if isinstance(value, str):
            try:
                value = float(value.strip())
            except ValueError:
                raise _fail(name, "expected a number") from None
        if _number(value) is None:
            raise _fail(name, "expected a number")
        return value
    if ptype in ("select", "status"):
        return _option(name, value)
    if ptype == "multi_select":
        items = value.split(",") if isinstance(value, str) else value
        if not isinstance(items, list) or len(items) > ARRAY_MAX_ITEMS:
            raise _fail(name, "expected a list of option names")
        return [option for option in (_option(name, item) for item in items) if option]
    if ptype == "date":
        if value is None:
            return None
        if isinstance(value, str):
            value = {"start": value}
        if not isinstance(value, dict) or not isinstance(value.get("start"), str):
            raise _fail(name, "expected an ISO 8601 date or {start, end}")
        date = {k: value[k] for k in ("start", "end", "time_zone") if isinstance(value.get(k), str)}
        return date
    if ptype in ("people", "relation"):
        return [] if value is None else _id_list(name, value)
    if ptype == "checkbox":
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true"
        if not isinstance(value, bool):
            raise _fail(name, "expected true or false")
        return value
    if ptype in ("url", "email", "phone_number"):
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > 2000:
            raise _fail(name, "expected text up to 2000 characters")
        return value
    raise _fail(name, f"type '{ptype}' cannot be written")


def _check_shape(values: Any) -> dict[str, Any]:
    if not isinstance(values, dict) or not values:
        raise ConnectorError("properties must be a non-empty object of name to value.")
    if len(values) > MAX_WRITE_PROPERTIES:
        raise ConnectorError(f"At most {MAX_WRITE_PROPERTIES} properties per call.")
    for name in values:
        if not isinstance(name, str) or not name.strip():
            raise ConnectorError("Property names must be non-empty text.")
    try:
        size = len(json.dumps(values, default=str))
    except (TypeError, ValueError, RecursionError):
        raise ConnectorError("properties must be plain JSON values.") from None
    if size > MAX_PROPERTIES_JSON_CHARS:
        raise ConnectorError(
            f"properties is larger than {MAX_PROPERTIES_JSON_CHARS} characters; "
            "set fewer or shorter values per call."
        )
    return values


def precheck_properties(values: Any) -> None:
    """Every check possible without the schema: the object's shape, the
    names, and every typed value. Run before asking for approval, so a bad
    call fails at once instead of after the user said yes."""
    checked = _check_shape(values)
    for name, value in checked.items():
        typed = typed_value(value)
        if typed is not None:
            _convert(name, typed[0], typed[1])


def build_properties(
    values: Any, schema: Optional[Mapping[str, str]]
) -> dict[str, Any]:
    """Notion property values for a write.

    *values* maps property names to plain values (``"Done"``, ``3``,
    ``["a", "b"]``, ``"2026-10-01"``, ``true``) or typed values
    (``{"select": "Done"}``). Plain values take their type from *schema*
    (``{name: type}``); pass None only when every value is typed.
    """
    built: dict[str, Any] = {}
    for name, value in _check_shape(values).items():
        typed = typed_value(value)
        if typed is not None:
            ptype, inner = typed
        else:
            ptype = (schema or {}).get(name, "")
            if not ptype:
                known = ", ".join(sorted(schema or {})[:20])
                raise _fail(name, f"no such property. Known properties: {known or 'none'}")
            inner = value
        built[name] = {ptype: _convert(name, ptype, inner)}
    return built
