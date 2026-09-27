"""Google Sheets actions of the Google Workspace connector: read values and
spreadsheet metadata, update and append rows, add a sheet and clear a range.

Why it exists: keeps the Sheets endpoints, A1 range handling and value limits
out of ``google_workspace.py``. Values are written RAW by default: typed-in
parsing (``parse_input``) evaluates formulas, and a formula such as
``=IMPORTDATA(...)`` can send sheet data to an outside URL, so the model must
ask for it explicitly and the approval card says so.

External service: the Google Sheets API v4 (https://sheets.googleapis.com/v4/spreadsheets).
Depends on ``google_api.client`` (GoogleBase, validation), ``base`` (errors,
path_segment) and ``definition``.
"""

from __future__ import annotations

from typing import Any, NoReturn, Optional

from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, UserConfirmationRequired, path_segment
from services.connectors.definition import ToolSpec, _schema

from .client import (
    SHEETS_API,
    GoogleBase,
    as_dict,
    as_list,
    optional_bool,
    require_id,
    require_line,
    scalar,
    scalar_fields,
)

# Read limits: rows and cells returned by get_values, characters per cell.
MAX_READ_ROWS = 200
MAX_READ_CELLS = 2000
CELL_CHARS = 500
# Write limits for update_values and append_rows.
MAX_WRITE_ROWS = 1000
MAX_WRITE_CELLS = 10_000
MAX_WRITE_CELL_CHARS = 50_000

_SPREADSHEET_ID = {"type": "string", "description": "Spreadsheet id", "required": True}
_RANGE = {"type": "string", "description": "A1 range, e.g. Sheet1!A1:D20", "required": True}
_VALUES = {
    "type": "array",
    "description": "Rows of cell values",
    "items": {"type": "array", "items": {"type": ["string", "number", "boolean", "null"]}},
    "required": True,
}
_PARSE = {
    "type": "boolean",
    "description": "Interpret values as typed in the UI (formulas, dates). Default false.",
}

SHEETS_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "get_values",
        "Read cell values from a Google Sheets range.",
        ActionCategory.READ,
        _schema(spreadsheet_id=_SPREADSHEET_ID, a1_range=_RANGE),
        policy_key="google_sheets",
        required_scope="sheets.read",
    ),
    ToolSpec(
        "get_metadata",
        "Get a spreadsheet's title and its sheets (names, ids, sizes).",
        ActionCategory.READ,
        _schema(spreadsheet_id=_SPREADSHEET_ID),
        policy_key="google_sheets",
        required_scope="sheets.read",
    ),
    ToolSpec(
        "update_values",
        "Overwrite the cells of a Google Sheets range with new values.",
        ActionCategory.WRITE,
        _schema(spreadsheet_id=_SPREADSHEET_ID, a1_range=_RANGE, values=_VALUES, parse_input=_PARSE),
        policy_key="google_sheets",
        required_scope="sheets.write",
    ),
    ToolSpec(
        "append_rows",
        "Append rows after the last row of data in a Google Sheets range.",
        ActionCategory.WRITE,
        _schema(spreadsheet_id=_SPREADSHEET_ID, a1_range=_RANGE, values=_VALUES, parse_input=_PARSE),
        policy_key="google_sheets",
        required_scope="sheets.write",
    ),
    ToolSpec(
        "add_sheet",
        "Add a new sheet (tab) to a spreadsheet.",
        ActionCategory.WRITE,
        _schema(spreadsheet_id=_SPREADSHEET_ID, title={"type": "string", "required": True}),
        policy_key="google_sheets",
        required_scope="sheets.write",
    ),
    ToolSpec(
        "clear_range",
        "Erase every value in a Google Sheets range (formatting stays).",
        ActionCategory.DELETE,
        _schema(spreadsheet_id=_SPREADSHEET_ID, a1_range=_RANGE),
        policy_key="google_sheets",
        required_scope="sheets.write",
        always_confirm=True,
    ),
)


def _range(value: Any) -> str:
    return require_line(value, "a1_range", max_chars=300)


def _rows(values: Any) -> list[list[Any]]:
    """Validate a model-supplied grid of scalar cell values."""
    if not isinstance(values, list) or not values or len(values) > MAX_WRITE_ROWS:
        raise ConnectorError(f"'values' must be a list of 1 to {MAX_WRITE_ROWS} rows.")
    cells = 0
    for row in values:
        if not isinstance(row, list):
            raise ConnectorError("'values' must be a list of rows, each a list of cells.")
        cells += len(row)
        for cell in row:
            if cell is not None and not isinstance(cell, (str, int, float, bool)):
                raise ConnectorError("Cell values must be text, numbers, true/false or null.")
            if isinstance(cell, str) and len(cell) > MAX_WRITE_CELL_CHARS:
                raise ConnectorError(f"A cell value is longer than {MAX_WRITE_CELL_CHARS} characters.")
    if cells > MAX_WRITE_CELLS:
        raise ConnectorError(f"'values' holds more than {MAX_WRITE_CELLS} cells.")
    return values


def _cell(value: Any) -> Any:
    if isinstance(value, str):
        return value[:CELL_CHARS]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return None


class SheetsActions(GoogleBase):
    """Google Sheets action coroutines (mixed into GoogleWorkspaceConnector)."""

    def _values_url(self, spreadsheet_id: str, a1_range: str, suffix: str = "") -> str:
        return f"{SHEETS_API}/{path_segment(spreadsheet_id)}/values/{path_segment(a1_range)}{suffix}"

    # -- READ ------------------------------------------------------------------

    async def get_values(self, spreadsheet_id: str, a1_range: str) -> dict[str, Any]:
        sid = require_id(spreadsheet_id, "spreadsheet_id")
        cells_range = _range(a1_range)
        data = await self._call_object(
            "GET",
            self._values_url(sid, cells_range),
            params={"majorDimension": "ROWS", "valueRenderOption": "FORMATTED_VALUE"},
        )
        rows: list[list[Any]] = []
        cells = 0
        truncated = False
        for row in as_list(data.get("values")):
            if len(rows) >= MAX_READ_ROWS or cells >= MAX_READ_CELLS:
                truncated = True
                break
            cells_row = [_cell(v) for v in as_list(row)][: MAX_READ_CELLS - cells]
            cells += len(cells_row)
            rows.append(cells_row)
        result: dict[str, Any] = {
            "range": scalar(data.get("range")) or cells_range,
            "values": rows,
            "row_count": len(rows),
            "truncated": truncated,
        }
        if truncated:
            result["hint"] = (
                f"Only the first {len(rows)} rows are shown; call get_values with a smaller "
                "range (for example the next block of rows) to read more."
            )
        return result

    async def get_metadata(self, spreadsheet_id: str) -> dict[str, Any]:
        sid = require_id(spreadsheet_id, "spreadsheet_id")
        data = await self._call_object(
            "GET",
            f"{SHEETS_API}/{path_segment(sid)}",
            params={
                "fields": "spreadsheetId,spreadsheetUrl,properties(title,locale,timeZone),"
                "sheets(properties(sheetId,title,index,gridProperties(rowCount,columnCount)))"
            },
        )
        sheets = []
        for sheet in as_list(data.get("sheets"))[:100]:
            props = as_dict(as_dict(sheet).get("properties"))
            grid = as_dict(props.get("gridProperties"))
            sheets.append(
                {
                    **scalar_fields(props, sheet_id="sheetId", title="title", index="index"),
                    **scalar_fields(grid, rows="rowCount", columns="columnCount"),
                }
            )
        return {
            "spreadsheet_id": scalar(data.get("spreadsheetId")) or sid,
            **scalar_fields(data.get("properties"), title="title", time_zone="timeZone"),
            **scalar_fields(data, link="spreadsheetUrl"),
            "sheets": sheets,
        }

    # -- WRITE -----------------------------------------------------------------

    @staticmethod
    def _confirm_write(
        action: str, verb: str, sid: str, cells_range: str, rows: list[Any], parse: bool
    ) -> NoReturn:
        raise UserConfirmationRequired(
            action=action,
            details=(
                f"{verb} {len(rows)} row(s) in spreadsheet {sid}, range '{cells_range}'"
                + (
                    ", interpreting values as typed (formulas run)?"
                    if parse
                    else ", stored exactly as given?"
                )
            ),
        )

    async def update_values(
        self,
        spreadsheet_id: str,
        a1_range: str,
        values: list[list[Any]],
        parse_input: Optional[bool] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        sid = require_id(spreadsheet_id, "spreadsheet_id")
        cells_range = _range(a1_range)
        rows = _rows(values)
        parse = optional_bool(parse_input, "parse_input", False)
        if not user_confirmed:
            self._confirm_write("update_values", "Overwrite", sid, cells_range, rows, parse)
        data = await self._call_object(
            "PUT",
            self._values_url(sid, cells_range),
            params={"valueInputOption": "USER_ENTERED" if parse else "RAW"},
            json={"range": cells_range, "majorDimension": "ROWS", "values": rows},
        )
        return scalar_fields(
            data, updated_range="updatedRange", updated_rows="updatedRows", updated_cells="updatedCells"
        )

    async def append_rows(
        self,
        spreadsheet_id: str,
        a1_range: str,
        values: list[list[Any]],
        parse_input: Optional[bool] = None,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        sid = require_id(spreadsheet_id, "spreadsheet_id")
        cells_range = _range(a1_range)
        rows = _rows(values)
        parse = optional_bool(parse_input, "parse_input", False)
        if not user_confirmed:
            self._confirm_write("append_rows", "Append", sid, cells_range, rows, parse)
        data = await self._call_object(
            "POST",
            self._values_url(sid, cells_range, ":append"),
            params={
                "valueInputOption": "USER_ENTERED" if parse else "RAW",
                "insertDataOption": "INSERT_ROWS",
            },
            json={"majorDimension": "ROWS", "values": rows},
        )
        return scalar_fields(
            data.get("updates"),
            updated_range="updatedRange",
            updated_rows="updatedRows",
            updated_cells="updatedCells",
        )

    async def add_sheet(
        self, spreadsheet_id: str, title: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        sid = require_id(spreadsheet_id, "spreadsheet_id")
        name = require_line(title, "title", max_chars=100)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="add_sheet", details=f"Add a sheet named '{name}' to spreadsheet {sid}?"
            )
        data = await self._call_object(
            "POST",
            f"{SHEETS_API}/{path_segment(sid)}:batchUpdate",
            json={"requests": [{"addSheet": {"properties": {"title": name}}}]},
        )
        replies = as_list(data.get("replies"))
        props = as_dict(as_dict(as_dict(replies[0] if replies else {}).get("addSheet")).get("properties"))
        return {"spreadsheet_id": sid, **scalar_fields(props, sheet_id="sheetId", title="title", index="index")}

    # -- DELETE ----------------------------------------------------------------

    async def clear_range(
        self, spreadsheet_id: str, a1_range: str, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        sid = require_id(spreadsheet_id, "spreadsheet_id")
        cells_range = _range(a1_range)
        if not user_confirmed:
            raise UserConfirmationRequired(
                action="clear_range",
                details=f"Erase every value in range '{cells_range}' of spreadsheet {sid}?",
            )
        data = await self._call_object("POST", self._values_url(sid, cells_range, ":clear"), json={})
        return {"status": "cleared", **scalar_fields(data, cleared_range="clearedRange")}
