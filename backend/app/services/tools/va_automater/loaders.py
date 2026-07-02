"""File loaders.

All loaders return DataFrames conformant to schema.CANON_COLS. Source-specific
quirks (column naming, multi-IP cells, embedded ports) are absorbed here so
downstream code is uniform.
"""
from __future__ import annotations
from pathlib import Path
import pandas as pd

from .schema import CANON_COLS, COL_ALIASES, TRACKER_COL_ALIASES
from .identifiers import (
    pick_first_column, normalize_plugin_id, safe_port,
    extract_first_ip, extract_ip_port_pairs,
)


class ColumnMappingError(ValueError):
    """Raised when required canonical fields can't be auto-mapped."""

    def __init__(self, missing: list[str], available: list[str]):
        self.missing = missing
        self.available = available
        super().__init__(
            f"Could not auto-map required columns: {missing}. "
            f"Available columns: {available}"
        )


def _dedupe_columns(cols: list[str]) -> tuple[list[str], list[str]]:
    """Make column names unique by suffixing duplicates with __2, __3, ...

    Returns (deduped_columns, duplicates_renamed). Without this, two columns
    that collapse to the same name after `.str.strip()` (e.g. 'Plugin ID'
    and 'Plugin ID ') make df[name] return a DataFrame, which then crashes
    `_build_canonical` with: "Cannot set a DataFrame with multiple columns
    to the single column plugin_id".
    """
    seen: dict[str, int] = {}
    out: list[str] = []
    renamed: list[str] = []
    for c in cols:
        if c in seen:
            seen[c] += 1
            new = f"{c}__{seen[c]}"
            out.append(new)
            renamed.append(c)
        else:
            seen[c] = 1
            out.append(c)
    return out, renamed


def auto_map_columns(df_columns: list[str]) -> dict[str, str | None]:
    """For each canonical field, find best source column (or None)."""
    return {
        canon: pick_first_column(df_columns, candidates)
        for canon, candidates in COL_ALIASES.items()
    }


def _build_canonical(
    df: pd.DataFrame,
    mapping: dict[str, str | None],
    source_file: str = "",
) -> pd.DataFrame:
    """Project a source df into canonical columns."""
    out = pd.DataFrame()
    for canon in CANON_COLS:
        src = mapping.get(canon)
        if src and src in df.columns:
            picked = df[src]
            # Defensive: if duplicate column names slipped past the loader's
            # dedupe, df[src] is a DataFrame, not a Series. Take the first
            # column to avoid crashing the canonical projection.
            if isinstance(picked, pd.DataFrame):
                picked = picked.iloc[:, 0]
            # fillna BEFORE astype(str): NaN → "" → "" (empty string).
            # The reversed order (astype first) bakes NaN as the string
            # "nan" THEN fillna has nothing left to replace, causing the
            # literal token "nan" to appear in Risk / other columns.
            out[canon] = picked.fillna("").astype(str)
        else:
            out[canon] = ""

    out["plugin_id"] = out["plugin_id"].apply(normalize_plugin_id)
    out["port"] = out["port"].apply(safe_port)

    # Normalize the ip column: pull first IP if present, else keep raw
    # (so DNS hostnames are preserved).
    def _norm_ip(v: str) -> str:
        ip = extract_first_ip(v)
        return ip if ip else str(v).strip()

    out["ip"] = out["ip"].apply(_norm_ip)

    if source_file:
        out["source_file"] = source_file
    out["source_row"] = list(range(2, len(out) + 2))  # 1-based + header row
    return out


# -----------------------------------------------------------
# Nessus CSV folder loader
# -----------------------------------------------------------
def load_nessus_folder(folder: Path) -> pd.DataFrame:
    """Load all *.csv in folder as Nessus exports, concatenated to canonical schema.

    Accepts either a folder (loads every *.csv in it) or a single CSV file
    (loads just that one). Sets df.attrs['load_warnings'] with any non-fatal
    warnings (e.g. files missing Plugin ID).
    """
    folder = Path(folder)
    if folder.is_file():
        if folder.suffix.lower() != ".csv":
            raise FileNotFoundError(
                f"Path is a file but not a CSV: {folder}"
            )
        csv_files = [folder]
    else:
        csv_files = sorted(folder.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {folder}")

    frames: list[pd.DataFrame] = []
    warnings: list[str] = []
    for fp in csv_files:
        try:
            df = pd.read_csv(fp, encoding="utf-8", dtype=str, on_bad_lines="skip")
        except UnicodeDecodeError:
            df = pd.read_csv(fp, encoding="latin-1", dtype=str, on_bad_lines="skip")
        df.columns = df.columns.str.strip()
        deduped, dupes = _dedupe_columns(df.columns.tolist())
        if dupes:
            df.columns = deduped
            warnings.append(
                f"{fp.name}: duplicate column header(s) {sorted(set(dupes))} "
                "renamed with __N suffix to keep first occurrence usable"
            )
        mapping = auto_map_columns(df.columns.tolist())

        if mapping["plugin_id"] is None:
            warnings.append(
                f"{fp.name}: no Plugin ID column found - matching will fall back "
                "to finding-name keys for these rows"
            )
        if mapping["finding_name"] is None and mapping["plugin_id"] is None:
            raise ColumnMappingError(
                missing=["finding_name", "plugin_id"],
                available=df.columns.tolist(),
            )
        if mapping["ip"] is None:
            raise ColumnMappingError(
                missing=["ip"], available=df.columns.tolist()
            )

        canon = _build_canonical(df, mapping, source_file=fp.name)
        frames.append(canon)

    out = pd.concat(frames, ignore_index=True)
    out.attrs["load_warnings"] = warnings
    # Clean the freshly-loaded scan: drop junk rows (blank Plugin ID,
    # blank Host) and de-duplicate on the canonical match key. Centralised
    # here so EVERY caller (recurring pipeline, retest, CLI preview) gets
    # identical cleaning rather than each remembering to dedup itself.
    out = clean_scan_dataframe(out)
    return out


# -----------------------------------------------------------
# Scan cleaning / de-duplication
# -----------------------------------------------------------
# Canonical match key used everywhere a scan or risk-accept set is
# de-duplicated. CVE is part of the key on purpose: Nessus emits one CVE
# per row, so the SAME finding on the same host/port can legitimately
# appear as several rows that differ ONLY by CVE — collapsing them would
# lose CVE coverage. Keeping this as a module constant means the dedup
# key can't silently drift apart between the loader, the pipeline, and
# the retest tool.
SCAN_DEDUP_KEY: list[str] = ["plugin_id", "finding_name", "ip", "port", "cve"]


def clean_scan_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Drop junk rows and duplicate findings from a loaded scan.

    Applied to the CURRENT/rescan Nessus data (not the risk-accept /
    tracker side, which has its own loaders). Removes, in order:

      1. Rows with a blank Plugin ID. A real Nessus finding row always
         carries a Plugin ID; blank-ID rows are separators, host-summary
         lines, or export artefacts ("weird rows" with no usable ID).
      2. Rows with no Host/IP value — they can't be matched or reported.
      3. Exact duplicates on ``SCAN_DEDUP_KEY``
         (plugin_id + finding_name + host + port + CVE), keeping the
         first occurrence. Duplicates arise when Nessus exports overlap,
         a scan is split across CSVs, or the same plugin runs twice.

    Counts are recorded in ``df.attrs['clean_stats']`` and human-readable
    lines appended to ``df.attrs['load_warnings']`` so the run summary can
    show exactly what was cleaned. Returns a NEW DataFrame; the input is
    not mutated.
    """
    if df is None or len(df) == 0:
        return df

    warnings = list(df.attrs.get("load_warnings", []))
    n_raw = len(df)
    out = df

    # 1. Blank Plugin ID. plugin_id is already canonicalised by
    #    _build_canonical (normalize_plugin_id -> "" for blank/nan/0-junk).
    if "plugin_id" in out.columns:
        pid_blank = out["plugin_id"].astype(str).str.strip() == ""
    else:
        pid_blank = pd.Series(False, index=out.index)
    n_blank_pid = int(pid_blank.sum())
    out = out[~pid_blank]

    # 2. Blank Host/IP.
    if "ip" in out.columns:
        ip_blank = out["ip"].astype(str).str.strip() == ""
    else:
        ip_blank = pd.Series(False, index=out.index)
    n_blank_ip = int(ip_blank.sum())
    out = out[~ip_blank]

    # 3. Duplicate findings on the canonical key.
    subset = [c for c in SCAN_DEDUP_KEY if c in out.columns]
    n_before_dedup = len(out)
    if subset:
        out = out.drop_duplicates(subset=subset, keep="first")
    out = out.reset_index(drop=True)
    n_dupes = n_before_dedup - len(out)

    if n_blank_pid:
        warnings.append(
            f"Dropped {n_blank_pid} row(s) with a blank Plugin ID "
            f"(separator / non-finding rows)."
        )
    if n_blank_ip:
        warnings.append(
            f"Dropped {n_blank_ip} row(s) with no Host/IP value."
        )
    if n_dupes:
        warnings.append(
            f"Removed {n_dupes} duplicate row(s) from the scan "
            f"(same Plugin ID + Finding Name + Host + Port + CVE — "
            f"kept first occurrence)."
        )

    out.attrs["load_warnings"] = warnings
    out.attrs["clean_stats"] = {
        "raw_rows": n_raw,
        "dropped_blank_plugin_id": n_blank_pid,
        "dropped_blank_host": n_blank_ip,
        "dropped_duplicates": n_dupes,
        "clean_rows": len(out),
    }
    return out


# -----------------------------------------------------------
# Excel utility loaders
# -----------------------------------------------------------
def list_excel_sheets(path: Path) -> list[str]:
    """Return sheet names. For CSV returns []."""
    path = Path(path)
    if path.suffix.lower() in (".xlsx", ".xls"):
        return pd.ExcelFile(path).sheet_names
    return []


def load_excel_sheet_raw(path: Path, sheet: int | str = 0) -> pd.DataFrame:
    """Load a single sheet as raw DataFrame (no canonicalization).

    Used when caller wants to inspect columns before deciding the mapping.
    """
    path = Path(path)
    if path.suffix.lower() in (".xlsx", ".xls"):
        xls = pd.ExcelFile(path)
        sname = xls.sheet_names[sheet] if isinstance(sheet, int) else sheet
        df = xls.parse(sname, dtype=str).fillna("")
    elif path.suffix.lower() == ".csv":
        try:
            df = pd.read_csv(path, dtype=str, on_bad_lines="skip").fillna("")
        except UnicodeDecodeError:
            df = pd.read_csv(path, dtype=str, encoding="latin-1", on_bad_lines="skip").fillna("")
    else:
        raise ValueError(f"Unsupported file type: {path.suffix}")
    df.columns = df.columns.str.strip()
    deduped, _ = _dedupe_columns(df.columns.tolist())
    df.columns = deduped
    return df


# -----------------------------------------------------------
# Risk-acceptance file loader (Excel/CSV; PDF planned)
# -----------------------------------------------------------
# File extensions the risk-accept folder walker will pick up. Anything
# else in the supplied folder is silently ignored so consultants can
# park unrelated files (READMEs, change logs, source emails) alongside
# the data without breaking the load.
RISKACCEPT_FILE_EXTS = (".xlsx", ".xls", ".csv", ".pdf", ".docx")


def _is_excel_lock_file(path: Path) -> bool:
    """Excel writes a sibling `~$<name>.xlsx` lock file while the
    workbook is open. Globbing `*.xlsx` picks those up too — and they
    aren't valid OOXML, so pandas blows up. Skip them. Same convention
    for .doc/.docx."""
    return path.name.startswith("~$")


def _collect_riskaccept_files(folder: Path) -> list[Path]:
    """Return every supported risk-accept file directly under `folder`,
    sorted alphabetically. Lock files (`~$*.xlsx`) and hidden dotfiles
    are skipped. Non-recursive — sub-folders are deliberately ignored
    so consultants can drop "archive" / "drafts" beneath the working
    directory without polluting the run."""
    out: list[Path] = []
    for p in sorted(folder.iterdir()):
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        if _is_excel_lock_file(p):
            continue
        if p.suffix.lower() in RISKACCEPT_FILE_EXTS:
            out.append(p)
    return out


def load_riskaccept_folder(
    folder: Path,
    column_overrides: dict | None = None,
) -> pd.DataFrame:
    """Walk `folder` and load every supported risk-accept file in it
    (.xlsx/.xls/.csv/.pdf/.docx), concatenated to a canonical
    DataFrame.

    Multi-sheet xlsx workbooks load EVERY sheet (the per-file
    `load_riskaccept_file` call uses ``sheet=None``). Files whose
    canonical projection is empty (no IP / no plugin_id / no
    finding_name column found) are skipped with a warning. The
    surviving rows are concatenated and de-duplicated on the standard
    match-key tuple so a finding listed in BOTH a prior quarter's
    tracker AND an explicit risk-accept letter only contributes once.

    Sets `df.attrs['load_warnings']` with per-file failures so the
    caller can surface them in the run summary. Raises only if the
    folder has NO supported files at all.
    """
    folder = Path(folder)
    files = _collect_riskaccept_files(folder)
    if not files:
        raise FileNotFoundError(
            f"No risk-accept files found in {folder}. "
            f"Supported extensions: {', '.join(RISKACCEPT_FILE_EXTS)}."
        )
    warnings: list[str] = []
    frames: list[pd.DataFrame] = []
    for fp in files:
        try:
            df = load_riskaccept_file(
                fp, sheet=None, column_overrides=column_overrides,
            )
        except Exception as e:
            warnings.append(f"{fp.name}: skipped - {e}")
            continue
        if not len(df):
            warnings.append(
                f"{fp.name}: produced 0 canonical rows (no IP / no "
                "finding_name / no plugin_id column matched)"
            )
            continue
        frames.append(df)
    if not frames:
        out = pd.DataFrame(columns=CANON_COLS)
    else:
        out = pd.concat(frames, ignore_index=True).drop_duplicates(
            subset=["plugin_id", "finding_name", "ip", "port", "cve"],
        ).reset_index(drop=True)
    out.attrs["load_warnings"] = warnings
    out.attrs["loaded_files"] = [str(p) for p in files]
    return out


def load_riskaccept_file(
    path: Path,
    sheet: int | str | None = None,
    column_overrides: dict | None = None,
) -> pd.DataFrame:
    """Load risk-acceptance file, expanding multi-IP cells.

    - **If `path` is a directory**, every supported file in it
      (.xlsx/.xls/.csv/.pdf/.docx) is loaded and concatenated via
      `load_riskaccept_folder`. The `sheet` argument is ignored in
      folder mode (each xlsx in the folder loads ALL sheets).
    - For .xlsx/.xls with multiple sheets: if sheet is None, ALL sheets loaded
      and concatenated. If sheet given, only that one.
    - For .csv: sheet parameter is ignored.
    - For .pdf: only blocks marked "risk accepted" in their status text
      are extracted; see `pdf_loader.load_riskaccept_pdf`.
    - For .docx: every table row is loaded; see `_load_riskaccept_docx`.
    - Cells like '172.156.55.43 (53), 10.0.0.5:443' are expanded into one
      output row per (ip, port) pair, inheriting all other fields.
    - If the row has a separate Port column AND a host cell with bare IPs,
      that port is applied to the bare IPs.

    Returns canonical DataFrame.
    """
    path = Path(path)
    # Folder mode — delegate to the walker. Done BEFORE the suffix
    # check so a directory path doesn't fall through to the
    # "Unsupported file type" branch (a directory's `.suffix` is the
    # empty string, which used to produce the cryptic
    # `Unsupported file type: . Use .xlsx/.xls/.csv` error).
    if path.is_dir():
        return load_riskaccept_folder(path, column_overrides=column_overrides)
    sheets_to_load: list[tuple[str, pd.DataFrame]] = []

    if path.suffix.lower() in (".xlsx", ".xls"):
        with pd.ExcelFile(path) as xls:
            if sheet is None:
                for s in xls.sheet_names:
                    df = xls.parse(s, dtype=str).fillna("")
                    df.columns = df.columns.str.strip()
                    df.columns, _ = _dedupe_columns(df.columns.tolist())
                    sheets_to_load.append((f"{path.name}::{s}", df))
            else:
                sname = xls.sheet_names[sheet] if isinstance(sheet, int) else sheet
                df = xls.parse(sname, dtype=str).fillna("")
                df.columns = df.columns.str.strip()
                df.columns, _ = _dedupe_columns(df.columns.tolist())
                sheets_to_load.append((f"{path.name}::{sname}", df))
    elif path.suffix.lower() == ".csv":
        try:
            df = pd.read_csv(path, dtype=str, on_bad_lines="skip").fillna("")
        except UnicodeDecodeError:
            df = pd.read_csv(path, dtype=str, encoding="latin-1", on_bad_lines="skip").fillna("")
        df.columns = df.columns.str.strip()
        df.columns, _ = _dedupe_columns(df.columns.tolist())
        sheets_to_load.append((path.name, df))
    elif path.suffix.lower() == ".pdf":
        from .pdf_loader import load_riskaccept_pdf
        return load_riskaccept_pdf(path)
    elif path.suffix.lower() == ".docx":
        # docx risk-accept docs are usually one or more tables with the
        # same column layout an xlsx would have. Extract every table
        # and feed it through the same canonical projection so the
        # caller treats it uniformly.
        for label, df in _load_docx_tables_as_sheets(path):
            sheets_to_load.append((label, df))
        if not sheets_to_load:
            # No tables found — return an empty canonical frame rather
            # than raising. The folder walker treats this as a "0
            # canonical rows" warning, not a hard failure.
            return pd.DataFrame(columns=CANON_COLS)
    else:
        raise ValueError(
            f"Unsupported file type: {path.suffix}. "
            f"Use {', '.join(RISKACCEPT_FILE_EXTS)} or pass a folder."
        )

    return _expand_sheets_to_canonical(sheets_to_load, column_overrides)


def _load_docx_tables_as_sheets(
    path: Path,
) -> list[tuple[str, pd.DataFrame]]:
    """Pull every table out of a .docx as a list of (label, raw_df)
    pairs suitable for feeding into `_expand_sheets_to_canonical`.

    The first row of each table is treated as the header (consistent
    with how an admin would type a risk-accept table in Word). Tables
    smaller than 2 rows are skipped (header-only / blank table).

    Returns an empty list if `python-docx` isn't installed or the
    file has no tables — the caller decides how to surface that
    (typically as a "0 canonical rows" warning in the folder walker).
    """
    try:
        from docx import Document
    except ImportError:
        return []
    try:
        doc = Document(str(path))
    except Exception:
        return []
    out: list[tuple[str, pd.DataFrame]] = []
    for ti, table in enumerate(doc.tables, start=1):
        rows = [
            [cell.text.strip() for cell in row.cells]
            for row in table.rows
        ]
        if len(rows) < 2:
            continue
        header, *body = rows
        # Pad / trim each body row to the header length so pandas
        # accepts the construction even when Word's "merged cell"
        # behaviour drops cells off the end of certain rows.
        n = len(header)
        normalised: list[list[str]] = []
        for r in body:
            if len(r) < n:
                r = r + [""] * (n - len(r))
            elif len(r) > n:
                r = r[:n]
            normalised.append(r)
        df = pd.DataFrame(normalised, columns=header, dtype=str).fillna("")
        df.columns = df.columns.str.strip()
        df.columns, _ = _dedupe_columns(df.columns.tolist())
        out.append((f"{path.name}::table_{ti}", df))
    return out


def _expand_sheets_to_canonical(
    sheets_to_load: list[tuple[str, pd.DataFrame]],
    column_overrides: dict | None = None,
) -> pd.DataFrame:
    """Project a list of (label, raw_df) into canonical schema with multi-IP
    cell expansion. Shared by load_riskaccept_file and the tracker-comment
    loader.
    """
    all_rows: list[dict] = []
    for src_label, df in sheets_to_load:
        mapping = auto_map_columns(df.columns.tolist())
        if column_overrides:
            mapping.update(column_overrides)

        # Need at least an IP column and one of plugin_id / finding_name
        if mapping["ip"] is None:
            continue
        if mapping["finding_name"] is None and mapping["plugin_id"] is None:
            continue

        name_col = mapping["finding_name"]
        pid_col = mapping["plugin_id"]
        ip_col = mapping["ip"]
        port_col = mapping["port"]

        for ridx, row in df.iterrows():
            pid = normalize_plugin_id(row[pid_col]) if pid_col else ""
            name = str(row[name_col]).strip() if name_col else ""
            if not pid and not name:
                continue

            ip_cell = row[ip_col] if ip_col else ""
            port_cell = row[port_col] if port_col else ""

            pairs = extract_ip_port_pairs(ip_cell)
            if not pairs:
                fallback_ip = str(ip_cell).strip()
                fallback_port = safe_port(port_cell)
                if fallback_ip:
                    pairs = [(fallback_ip, fallback_port)]

            single_port = safe_port(port_cell)

            for ip, port in pairs:
                effective_port = port or single_port
                rec = {c: "" for c in CANON_COLS}
                rec["plugin_id"] = pid
                rec["finding_name"] = name
                rec["ip"] = ip
                rec["port"] = effective_port
                rec["source_file"] = src_label
                rec["source_row"] = ridx + 2
                for canon in ("risk", "synopsis", "description", "solution",
                              "plugin_family", "plugin_output", "protocol",
                              "see_also", "cve"):
                    if mapping.get(canon):
                        rec[canon] = str(row[mapping[canon]]).strip()
                all_rows.append(rec)

    if not all_rows:
        return pd.DataFrame(columns=CANON_COLS)

    out = pd.DataFrame(all_rows, columns=CANON_COLS).drop_duplicates(
        subset=["plugin_id", "finding_name", "ip", "port", "cve"]
    ).reset_index(drop=True)
    return out


# -----------------------------------------------------------
# Tracker comment-keyword risk-accept loader (two-source workflow)
# -----------------------------------------------------------
_COMMENT_FUZZY_SUBSTRINGS: tuple[str, ...] = (
    "comment", "note", "remark", "review",
)


def load_tracker_comment_riskaccept(
    path: Path,
    sheet: int | str | None = 0,
    keywords: list[str] | None = None,
    case_sensitive: bool = False,
    column_overrides: dict | None = None,
    custom_comment_col: str = "",
) -> tuple[pd.DataFrame, dict]:
    """Scan a previous-quarter tracker xlsx for rows whose comment column
    contains a risk-accept phrase; return them as canonical-schema findings
    suitable for subtraction.

    This is the second-source workflow: management's dedicated risk-accept
    file is one input, last quarter's tracker (with free-text comments like
    'Mgmt accepted 2025-Q3') is another. Both feed into the subtract step.

    Comment column detection order (per sheet):
      1. ``custom_comment_col`` if provided and present in the sheet.
      2. Exact case-insensitive match against TRACKER_COL_ALIASES["comments"].
      3. Substring fallback — any column whose name contains "comment",
         "note", "remark", or "review" (catches "Audit Comments",
         "Review Notes", "Risk Comment", etc.).  Fuzzy matches are labelled
         with a ``(fuzzy)`` suffix in the ``comment_columns`` diagnostic so
         callers can surface them in the run summary.

    Returns (canonical_df, diag). diag keys:
      - rows_scanned       : total rows in the sheet(s) examined
      - comment_columns    : list of comment column names found
      - rows_matched       : rows whose comment hit a keyword
      - keyword_hits       : dict {keyword: count}
      - match_evidence     : up to 10 (keyword, column, snippet) tuples
      - sheets_examined    : list of sheet names actually read
    """
    if keywords is None:
        from .risk_keywords import DEFAULT_RISK_KEYWORDS
        keywords = list(DEFAULT_RISK_KEYWORDS)
    from .risk_keywords import comment_matches_riskaccept

    path = Path(path)
    # Folder mode — fan out to every tracker xlsx in the directory,
    # merge their canonical rows + diagnostics. Done before the
    # extension check so a directory path doesn't fall through to
    # "Tracker must be .xlsx/.xls" (a directory has no suffix).
    if path.is_dir():
        return _load_tracker_comment_riskaccept_folder(
            path, sheet=sheet, keywords=keywords,
            case_sensitive=case_sensitive,
            column_overrides=column_overrides,
            custom_comment_col=custom_comment_col,
        )
    if path.suffix.lower() not in (".xlsx", ".xls"):
        raise ValueError(
            f"Tracker must be .xlsx/.xls for comment scanning; got {path.suffix}"
        )

    # Evidence map: (source_label, source_row_excel) -> (keyword, ccol, snippet).
    # source_row_excel matches what _expand_sheets_to_canonical writes into
    # the canonical 'source_row' column (= original ridx + 2, 1-based + header).
    evidence_by_row: dict[tuple[str, int], tuple[str, str, str]] = {}

    with pd.ExcelFile(path) as xls:
        if sheet is None:
            sheet_names = list(xls.sheet_names)
        elif isinstance(sheet, int):
            sheet_names = [xls.sheet_names[sheet]]
        else:
            sheet_names = [sheet]

        rows_scanned = 0
        comment_cols_seen: list[str] = []
        keyword_hits: dict[str, int] = {}
        match_evidence: list[tuple[str, str, str]] = []
        matched_sheets: list[tuple[str, pd.DataFrame]] = []

        for sname in sheet_names:
            df = xls.parse(sname, dtype=str).fillna("")
            df.columns = df.columns.str.strip()
            df.columns, _ = _dedupe_columns(df.columns.tolist())
            rows_scanned += len(df)

            # Resolve comment columns for THIS sheet (could differ per sheet).
            # Priority: (1) custom_comment_col, (2) exact alias match,
            # (3) substring fallback for ad-hoc column names.
            ccols: list[str] = []
            # 1. Explicit custom column — highest priority.
            if custom_comment_col and custom_comment_col in df.columns:
                if custom_comment_col not in ccols:
                    ccols.append(custom_comment_col)
            # 2. Exact case-insensitive alias match.
            for cand in TRACKER_COL_ALIASES["comments"]:
                for col in df.columns:
                    if col.strip().lower() == cand.lower() and col not in ccols:
                        ccols.append(col)
            # 3. Substring fallback — catches "Audit Comments", "Review Notes", etc.
            #    Only triggers when no exact match was found so genuine alias columns
            #    are not duplicated.
            fuzzy_cols: list[str] = []
            if not ccols:
                for col in df.columns:
                    col_lower = col.strip().lower()
                    if (
                        any(s in col_lower for s in _COMMENT_FUZZY_SUBSTRINGS)
                        and col not in ccols
                    ):
                        fuzzy_cols.append(col)
                ccols.extend(fuzzy_cols)
            if not ccols:
                continue
            for c in ccols:
                label = f"{c} (fuzzy)" if c in fuzzy_cols else c
                if label not in comment_cols_seen:
                    comment_cols_seen.append(label)

            src_label = f"{path.name}::{sname}"
            matched_idx: list[int] = []
            for ridx, row in df.iterrows():
                for ccol in ccols:
                    kw = comment_matches_riskaccept(row[ccol], keywords, case_sensitive)
                    if kw:
                        matched_idx.append(ridx)
                        keyword_hits[kw] = keyword_hits.get(kw, 0) + 1
                        snippet = str(row[ccol])[:200]
                        if len(match_evidence) < 10:
                            match_evidence.append((kw, ccol, snippet))
                        evidence_by_row[(src_label, ridx + 2)] = (kw, ccol, snippet)
                        break
            if matched_idx:
                matched_sheets.append((src_label, df.loc[matched_idx].copy()))

    canonical = (
        _expand_sheets_to_canonical(matched_sheets, column_overrides)
        if matched_sheets
        else pd.DataFrame(columns=CANON_COLS)
    )

    # Attach per-row evidence so the user can audit WHY each row was flagged.
    # Multi-IP expansion of one tracker row produces N canonical rows that
    # all share the same evidence.
    if len(canonical):
        def _ev(row, idx):
            ev = evidence_by_row.get((row["source_file"], int(row["source_row"])))
            return ev[idx] if ev else ""
        canonical["riskaccept_keyword"] = [
            _ev(r, 0) for _, r in canonical.iterrows()
        ]
        canonical["riskaccept_comment_col"] = [
            _ev(r, 1) for _, r in canonical.iterrows()
        ]
        canonical["riskaccept_comment_text"] = [
            _ev(r, 2) for _, r in canonical.iterrows()
        ]
    else:
        for c in ("riskaccept_keyword", "riskaccept_comment_col",
                  "riskaccept_comment_text"):
            canonical[c] = []

    diag = {
        "rows_scanned": rows_scanned,
        "comment_columns": comment_cols_seen,
        "rows_matched": int(sum(len(d) for _, d in matched_sheets)),
        "keyword_hits": keyword_hits,
        "match_evidence": match_evidence,
        "sheets_examined": sheet_names,
    }
    return canonical, diag


def _load_tracker_comment_riskaccept_folder(
    folder: Path,
    sheet: int | str | None = 0,
    keywords: list[str] | None = None,
    case_sensitive: bool = False,
    column_overrides: dict | None = None,
    custom_comment_col: str = "",
) -> tuple[pd.DataFrame, dict]:
    """Folder fan-out of `load_tracker_comment_riskaccept`.

    Each xlsx/xls in `folder` is scanned independently with the
    requested `sheet` selector (default ``0`` = first sheet of each
    workbook, matching the single-file convention). Per-file
    diagnostics are merged into a single dict the caller can render
    in the run summary:

      - rows_scanned         : SUM of per-file scans
      - comment_columns      : UNION across files
      - rows_matched         : SUM
      - keyword_hits         : SUMs per keyword
      - match_evidence       : first 10 across all files (preserves order)
      - sheets_examined      : flat list of `<filename>::<sheet>` labels
      - files_examined       : list of paths actually opened
      - files_skipped        : list of `{path, reason}` for files that failed to load
    """
    folder = Path(folder)
    # Only xlsx/xls are valid for the tracker-comment scan — `.csv`
    # has no sheets, `.pdf`/`.docx` are not tracker shape.
    files = [
        p for p in _collect_riskaccept_files(folder)
        if p.suffix.lower() in (".xlsx", ".xls")
    ]
    if not files:
        raise FileNotFoundError(
            f"No tracker .xlsx/.xls files found in {folder}."
        )

    merged_canonical_frames: list[pd.DataFrame] = []
    merged_rows_scanned = 0
    merged_cols_seen: list[str] = []
    merged_keyword_hits: dict[str, int] = {}
    merged_evidence: list[tuple[str, str, str]] = []
    merged_sheets: list[str] = []
    files_examined: list[str] = []
    files_skipped: list[dict] = []

    for fp in files:
        try:
            canonical, diag = load_tracker_comment_riskaccept(
                fp, sheet=sheet, keywords=keywords,
                case_sensitive=case_sensitive,
                column_overrides=column_overrides,
                custom_comment_col=custom_comment_col,
            )
        except Exception as e:
            files_skipped.append({"path": str(fp), "reason": str(e)})
            continue
        files_examined.append(str(fp))
        if len(canonical):
            merged_canonical_frames.append(canonical)
        merged_rows_scanned += int(diag.get("rows_scanned", 0))
        for c in diag.get("comment_columns", []) or []:
            if c not in merged_cols_seen:
                merged_cols_seen.append(c)
        for kw, n in (diag.get("keyword_hits") or {}).items():
            merged_keyword_hits[kw] = merged_keyword_hits.get(kw, 0) + int(n)
        for ev in diag.get("match_evidence", []) or []:
            if len(merged_evidence) < 10:
                merged_evidence.append(ev)
        for s in diag.get("sheets_examined", []) or []:
            # Disambiguate cross-file sheets by prefixing with filename.
            label = s if "::" in s else f"{fp.name}::{s}"
            merged_sheets.append(label)

    if merged_canonical_frames:
        canonical = pd.concat(
            merged_canonical_frames, ignore_index=True,
        ).drop_duplicates(
            subset=["plugin_id", "finding_name", "ip", "port", "cve"],
        ).reset_index(drop=True)
    else:
        canonical = pd.DataFrame(columns=CANON_COLS)
        for c in ("riskaccept_keyword", "riskaccept_comment_col",
                  "riskaccept_comment_text"):
            canonical[c] = []

    diag = {
        "rows_scanned": merged_rows_scanned,
        "comment_columns": merged_cols_seen,
        "rows_matched": int(len(canonical)),
        "keyword_hits": merged_keyword_hits,
        "match_evidence": merged_evidence,
        "sheets_examined": merged_sheets,
        "files_examined": files_examined,
        "files_skipped": files_skipped,
    }
    return canonical, diag
