"""
PT Risk Register Excel parser.

Handles the standard VibeDocs VAPT Excel tracker: a multi-sheet workbook where
findings live in the 'Risk Register' sheet (one row per finding). Sheet name
and column headers vary between projects, so we drive everything from
`tracker_schema.yaml` (sibling file). Add new aliases there without touching code.

Two-step API:
    preview(file_bytes, db, template_id) -> ParsedTracker (no DB writes)
    commit(parsed, ..., db, user)        -> persists ReportFinding rows + auto-
                                             creates pending_review FindingLibrary
                                             entries for novel titles.
"""
from __future__ import annotations
import io
import re
import yaml
import unicodedata
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from sqlalchemy.orm import Session

from ..models import (
    FindingLibrary, LibraryStatus, ReportFinding, Severity, FindingStatus, User
)
from .cvss_v4 import parse_vector


_SCHEMA_PATH = Path(__file__).with_name("tracker_schema.yaml")


def _load_schema() -> dict:
    with _SCHEMA_PATH.open() as f:
        return yaml.safe_load(f)


def _norm_header(s: str) -> str:
    """Lowercase + collapse whitespace and punctuation for fuzzy header matching."""
    s = unicodedata.normalize("NFKD", str(s)).strip().lower()
    s = re.sub(r"[._\-/]+", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def _norm_title(s: str) -> str:
    s = unicodedata.normalize("NFKD", str(s)).strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


@dataclass
class ParsedRow:
    row_number: int
    fields: dict[str, Any]
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    library_match_id: Optional[int] = None
    library_match_status: Optional[str] = None

    @property
    def has_blocking_issues(self) -> bool:
        return bool(self.issues)


@dataclass
class ParsedTracker:
    sheet_name: str
    column_mapping: dict[str, str]
    missing_required: list[str]
    unknown_columns: list[str]
    rows: list[ParsedRow]

    def to_dict(self) -> dict:
        return {
            "sheet_name": self.sheet_name,
            "column_mapping": self.column_mapping,
            "missing_required": self.missing_required,
            "unknown_columns": self.unknown_columns,
            "rows": [asdict(r) for r in self.rows],
            "summary": {
                "total_rows": len(self.rows),
                "ready": sum(1 for r in self.rows if not r.has_blocking_issues),
                "blocked": sum(1 for r in self.rows if r.has_blocking_issues),
                "library_matches": sum(1 for r in self.rows if r.library_match_id),
            },
        }


def _resolve_columns(df_columns: list[str], schema: dict):
    norm_to_actual = {_norm_header(c): c for c in df_columns}
    column_mapping: dict[str, str] = {}
    missing_required: list[str] = []
    used_actual: set[str] = set()
    for canonical, cfg in schema["fields"].items():
        found = None
        for alias in cfg.get("aliases", []):
            actual = norm_to_actual.get(_norm_header(alias))
            if actual and actual not in used_actual:
                found = actual
                break
        if found:
            column_mapping[canonical] = found
            used_actual.add(found)
        elif cfg.get("required"):
            missing_required.append(canonical)
    unknown_columns = [c for c in df_columns if c not in used_actual]
    return column_mapping, missing_required, unknown_columns


def _find_sheet(xls: pd.ExcelFile, schema: dict) -> Optional[str]:
    normed = {_norm_header(s): s for s in xls.sheet_names}
    for candidate in schema["sheet_candidates"]:
        actual = normed.get(_norm_header(candidate))
        if actual:
            return actual
    return None


def _value(row: pd.Series, mapping: dict, key: str) -> Any:
    col = mapping.get(key)
    if not col:
        return None
    v = row.get(col)
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return v


def _coerce_severity(raw: Any, schema: dict):
    warnings: list[str] = []
    if raw is None:
        return None, warnings
    key = str(raw).strip().lower()
    sev = schema["severity_map"].get(key)
    if not sev:
        warnings.append(f"Unknown severity '{raw}' - defaulting to Medium")
        return Severity.medium.value, warnings
    return sev, warnings


def _coerce_status(raw: Any, schema: dict):
    warnings: list[str] = []
    if raw is None:
        return None, warnings
    key = str(raw).strip().lower()
    st = schema["status_map"].get(key)
    if not st:
        warnings.append(f"Unknown status '{raw}' - defaulting to Open")
        return FindingStatus.open.value, warnings
    return st, warnings


def _coerce_cvss(vector: Any, score: Any):
    issues: list[str] = []
    v_out: Optional[str] = None
    s_out: Optional[float] = None
    if vector:
        s = str(vector).strip()
        try:
            parse_vector(s)
            v_out = s
        except ValueError as e:
            issues.append(f"Invalid CVSS vector: {e}")
    if score is not None and score != "":
        try:
            f = float(score)
            if not (0.0 <= f <= 10.0):
                issues.append(f"CVSS score {f} outside 0.0-10.0")
            else:
                s_out = f
        except (TypeError, ValueError):
            issues.append(f"CVSS score '{score}' is not a number")
    return v_out, s_out, issues


def preview(file_bytes: bytes, db: Session, template_id: int) -> ParsedTracker:
    """Parse the Excel workbook and produce a non-destructive preview."""
    schema = _load_schema()
    xls = pd.ExcelFile(io.BytesIO(file_bytes), engine="openpyxl")
    sheet_name = _find_sheet(xls, schema)
    if not sheet_name:
        raise ValueError(
            f"No findings sheet found. Expected one of: {schema['sheet_candidates']}. "
            f"Sheets present: {xls.sheet_names}"
        )

    df = pd.read_excel(xls, sheet_name=sheet_name, dtype=object)
    df = df.dropna(how="all")

    column_mapping, missing_required, unknown_columns = _resolve_columns(
        list(df.columns), schema
    )

    rows: list[ParsedRow] = []
    seen_finding_ids: set[str] = set()

    library_titles: dict[str, int] = {
        _norm_title(t): i
        for i, t in db.query(FindingLibrary.id, FindingLibrary.title)
                       .filter(FindingLibrary.template_id == template_id)
                       .all()
    }

    for idx, row in df.iterrows():
        excel_row = int(idx) + 2
        pr = ParsedRow(row_number=excel_row, fields={})
        for canonical in column_mapping:
            pr.fields[canonical] = _value(row, column_mapping, canonical)
        if not pr.fields.get("title"):
            continue

        for canonical, cfg in schema["fields"].items():
            if cfg.get("required") and canonical in column_mapping and not pr.fields.get(canonical):
                pr.issues.append(f"Empty required field: {canonical}")
        for req in missing_required:
            pr.issues.append(f"Required field missing in sheet: {req}")

        sev, sev_warn = _coerce_severity(pr.fields.get("severity"), schema)
        pr.warnings.extend(sev_warn)
        if sev:
            pr.fields["severity"] = sev
        status, status_warn = _coerce_status(pr.fields.get("status"), schema)
        pr.warnings.extend(status_warn)
        if status:
            pr.fields["status"] = status

        v, s, cvss_issues = _coerce_cvss(pr.fields.get("cvss_vector"),
                                         pr.fields.get("cvss_score"))
        pr.fields["cvss_vector"] = v
        pr.fields["cvss_score"] = s
        pr.issues.extend(cvss_issues)

        fid = pr.fields.get("finding_id")
        if fid:
            fid_str = str(fid)
            if fid_str in seen_finding_ids:
                pr.warnings.append(f"Duplicate finding_id '{fid_str}' in sheet")
            seen_finding_ids.add(fid_str)

        title_norm = _norm_title(pr.fields["title"])
        lib_id = library_titles.get(title_norm)
        if lib_id:
            pr.library_match_id = lib_id
            pr.library_match_status = "exact"

        rows.append(pr)

    return ParsedTracker(
        sheet_name=sheet_name,
        column_mapping=column_mapping,
        missing_required=missing_required,
        unknown_columns=unknown_columns,
        rows=rows,
    )


@dataclass
class CommitResult:
    findings_created: int
    library_pending_created: int
    skipped: int
    skipped_rows: list[int]


def commit(parsed: ParsedTracker, *, template_id: int, report_version_id: int,
           db: Session, user: User, skip_blocked: bool = True,
           promote_new_to_library: bool = True) -> CommitResult:
    """Persist parsed rows. Blocked rows are skipped (caller fixes & re-uploads).
    New finding titles become pending_review FindingLibrary entries when
    `promote_new_to_library` is True (per team workflow).
    """
    findings_created = 0
    library_created = 0
    skipped = 0
    skipped_rows: list[int] = []

    for pr in parsed.rows:
        if pr.has_blocking_issues and skip_blocked:
            skipped += 1
            skipped_rows.append(pr.row_number)
            continue

        f = pr.fields
        library_id = pr.library_match_id
        if not library_id and promote_new_to_library:
            lib = FindingLibrary(
                template_id=template_id,
                title=f["title"],
                description=f.get("description") or "",
                impact=f.get("impact"),
                remediation=f.get("remediation"),
                references=f.get("references"),
                default_severity=Severity(f.get("severity") or Severity.medium.value),
                default_cvss_vector=f.get("cvss_vector"),
                default_cvss_score=f.get("cvss_score"),
                status=LibraryStatus.pending_review,
                cwe=f.get("cwe"),
                owasp_category=f.get("owasp"),
                created_by_id=user.id,
            )
            db.add(lib)
            db.flush()
            library_id = lib.id
            library_created += 1

        rf = ReportFinding(
            report_version_id=report_version_id,
            library_id=library_id,
            title=f["title"],
            description=f.get("description"),
            impact=f.get("impact"),
            remediation=f.get("remediation"),
            references=f.get("references"),
            affected_asset=f.get("affected_asset"),
            poc_steps=f.get("steps_to_reproduce"),
            severity=Severity(f.get("severity") or Severity.medium.value),
            cvss_vector=f.get("cvss_vector"),
            cvss_score=f.get("cvss_score"),
            status=FindingStatus(f.get("status") or FindingStatus.open.value),
            source="excel_tracker",
            source_ref=str(f.get("finding_id")) if f.get("finding_id") else None,
            added_by_id=user.id,
        )
        db.add(rf)
        findings_created += 1

    db.commit()
    return CommitResult(
        findings_created=findings_created,
        library_pending_created=library_created,
        skipped=skipped,
        skipped_rows=skipped_rows,
    )
