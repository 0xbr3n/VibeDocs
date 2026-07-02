"""Excel tracker write-back via COM automation (Windows only).

Used for the tracker-update workflow: open an existing tracker xlsx, look up
each row's finding in the current scan, mark rows NOT present in the new
scan as Closed (and optionally fill a comment column). Uses COM so embedded
images, formatting, conditional formatting, and data validation are preserved.

Falls back to a clear error on non-Windows or when pywin32 is unavailable.
"""
from __future__ import annotations
from pathlib import Path
import platform
import pandas as pd

try:
    import win32com.client as win32
    HAS_WIN32COM = True
except ImportError:
    win32 = None
    HAS_WIN32COM = False

from .matching import NewScanIndex, TIER_NO_MATCH, TIER_ORDER
from .identifiers import normalize_text


def is_available() -> bool:
    return platform.system().lower() == "windows" and HAS_WIN32COM


def read_tracker_sheet(
    tracker_path: Path,
    sheet_index: int = 1,
) -> tuple[pd.DataFrame, list[str], list[str]]:
    """Read a tracker sheet via Excel COM as DataFrame.

    Returns (df, headers, all_sheet_names). Workbook is closed before returning.
    """
    if not is_available():
        raise RuntimeError("Excel COM not available (need Windows + pywin32).")

    excel = win32.DispatchEx("Excel.Application")
    excel.Visible = False
    excel.DisplayAlerts = False
    wb = None
    try:
        wb = excel.Workbooks.Open(str(Path(tracker_path).resolve()))
        sheet_names = [wb.Worksheets(i).Name for i in range(1, wb.Worksheets.Count + 1)]
        si = max(1, min(sheet_index, wb.Worksheets.Count))
        ws = wb.Worksheets(si)

        used = ws.UsedRange
        values = used.Value
        if not values or len(values) < 2:
            raise RuntimeError(f"Tracker sheet '{ws.Name}' is empty or has no data rows.")

        headers = [str(h).strip() if h is not None else "" for h in values[0]]
        rows = values[1:]
        df = pd.DataFrame(list(rows), columns=headers).fillna("")
        df.columns = df.columns.str.strip()
        return df, headers, sheet_names
    finally:
        if wb is not None:
            wb.Close(SaveChanges=False)
        excel.Quit()


def update_tracker_inplace(
    tracker_path: Path,
    sheet_index: int,
    column_map: dict[str, str],
    new_scan_index: NewScanIndex,
    only_open: bool = True,
    mark_closed: bool = True,
    comment_col: str | None = None,
    comment_text: str = "",
    output_path: Path | None = None,
    dry_run: bool = False,
) -> dict:
    """Update a tracker by marking remediated rows as Closed.

    column_map keys (values are tracker column headers):
      - finding_name (required)
      - ip           (required, "Host" in most trackers)
      - status       (required)
      - plugin_id    (optional - enables top-tier matching when present)
      - port         (optional)

    Match tier reported per row in diagnostics. Rows matched at any tier
    are considered "still open" and left untouched. Rows with no_match
    are considered remediated and marked Closed (if mark_closed=True).

    If dry_run=True, no save is performed (still reports what would happen).
    If output_path given, SaveAs(output_path); else Save() in place.
    """
    if not is_available():
        raise RuntimeError("Excel COM not available (need Windows + pywin32).")

    excel = win32.DispatchEx("Excel.Application")
    excel.Visible = False
    excel.DisplayAlerts = False
    wb = None

    diag = {
        "rows_checked": 0,
        "rows_considered": 0,
        "rows_matched": 0,
        "rows_remediated": 0,
        "rows_marked_closed": 0,
        "tier_counts": {t: 0 for t in TIER_ORDER},
        "unmatched_samples": [],
        "output_file": "",
    }

    try:
        wb = excel.Workbooks.Open(str(Path(tracker_path).resolve()))
        si = max(1, min(sheet_index, wb.Worksheets.Count))
        ws = wb.Worksheets(si)

        used = ws.UsedRange
        values = used.Value
        if not values or len(values) < 2:
            raise RuntimeError(f"Tracker sheet '{ws.Name}' is empty.")

        headers = [str(h).strip() if h is not None else "" for h in values[0]]

        def find_col_idx(name: str) -> int:
            if not name:
                return 0
            target = normalize_text(name)
            for i, h in enumerate(headers, start=1):
                if normalize_text(h) == target:
                    return i
            return 0

        status_idx = find_col_idx(column_map.get("status", "Status"))
        if status_idx == 0:
            raise RuntimeError(
                f"Tracker missing Status column '{column_map.get('status')}'"
            )

        name_idx = find_col_idx(column_map.get("finding_name", "Name"))
        host_idx = find_col_idx(column_map.get("ip", "Host"))
        pid_idx = find_col_idx(column_map.get("plugin_id", ""))
        port_idx = find_col_idx(column_map.get("port", ""))
        comment_idx = find_col_idx(comment_col) if comment_col else 0

        if name_idx == 0 or host_idx == 0:
            raise RuntimeError("Tracker missing Name or Host column.")

        rows = values[1:]
        samples: list[tuple] = []

        for row_offset, row in enumerate(rows):
            diag["rows_checked"] += 1
            excel_row = row_offset + 2

            def cell(idx: int) -> str:
                if idx == 0:
                    return ""
                v = row[idx - 1]
                return "" if v is None else str(v).strip()

            status_val = cell(status_idx)
            if only_open and status_val.lower() != "open":
                continue

            diag["rows_considered"] += 1

            tier = new_scan_index.match(
                cell(pid_idx),
                cell(name_idx),
                cell(host_idx),
                cell(port_idx),
            )
            diag["tier_counts"][tier] = diag["tier_counts"].get(tier, 0) + 1

            if tier != TIER_NO_MATCH:
                diag["rows_matched"] += 1
                continue

            diag["rows_remediated"] += 1
            if len(samples) < 10:
                samples.append((
                    cell(name_idx), cell(host_idx),
                    cell(port_idx) or "(no-port)",
                    cell(pid_idx) or "(no-pid)",
                ))

            if mark_closed and not dry_run:
                ws.Cells(excel_row, status_idx).Value = "Closed"
                diag["rows_marked_closed"] += 1
                if comment_idx and comment_text:
                    ws.Cells(excel_row, comment_idx).Value = comment_text

        diag["unmatched_samples"] = samples

        if dry_run:
            diag["output_file"] = "(dry-run, no save)"
        else:
            if output_path is None:
                out_path = Path(tracker_path).resolve()
                wb.Save()
            else:
                out_path = Path(output_path).resolve()
                wb.SaveAs(str(out_path))
            diag["output_file"] = str(out_path)

        return diag
    finally:
        if wb is not None:
            try:
                wb.Close(SaveChanges=False)
            except Exception:
                pass
        excel.Quit()
