"""PDF parser for management risk-acceptance documents.

The input PDFs typically contain BOTH risk-accepted and previously-closed
findings in the same document. We only want to extract the ones explicitly
marked as risk-accepted. The distinguishing signal is the comments/status
field on each finding-block: rows where any cell contains a risk-accept
marker pattern (default: "risk accept") are treated as accepted; others
are skipped.

PDF structure handled (example - 'Information Disclosure' finding block):
  | S/N | Finding name + bulleted IPs (with optional embedded ports) | CVSS | Observations |
  | ... | ...                                                          | ...  | Status: Risk Accepted by XYZ on 2024-09-12 |

The status cell may be a separate column, or buried within the
Observations/Recommendations text - we scan every cell of every row.

Extraction strategy per row:
  1. If any cell matches a REJECT pattern ("closed", "remediated", etc.),
     skip the row entirely.
  2. If any cell matches a RISK-ACCEPT pattern, the row is in-scope.
  3. Extract the finding name (first substantive non-status non-IP cell,
     or the text BEFORE the first IP in the IP cell).
  4. Extract all (ip, port) pairs from any cell using extract_ip_port_pairs.
  5. Output one canonical row per (finding_name, ip, port) tuple.

If the PDF has no extractable tables, fall back to whole-page text scanning
with the same risk-accept marker logic on text blocks (less precise but
better than nothing for poorly-formatted PDFs).
"""
from __future__ import annotations
from pathlib import Path
import re
import pandas as pd

try:
    import pdfplumber
    HAS_PDFPLUMBER = True
except ImportError:
    pdfplumber = None
    HAS_PDFPLUMBER = False

from .schema import CANON_COLS
from .identifiers import extract_ip_port_pairs, extract_ips


# Patterns that mark a row as risk-accepted. Case-insensitive substring match.
DEFAULT_RISK_ACCEPT_PATTERNS = [
    "risk accept",
    "risk-accept",
    "risk accepted",
    "accepted by",
    "approved exception",
]

# Patterns that explicitly mark a row as NOT risk-accepted (override accept).
# Checked first - if any of these match, the row is skipped regardless of
# any risk-accept marker.
DEFAULT_REJECT_PATTERNS = [
    "closed",
    "remediated",
    "fixed",
    "resolved",
    "false positive",
    "not accepted",
    "not risk accepted",
    "rejected",
]


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BULLET_CHARS = re.compile(r"[\u2022\u00b7\u25cf\u25e6\u2023\*\-]+")
_CID_REF = re.compile(r"\(cid:\d+\)")  # pdfplumber emits these for unsupported glyphs


def _clean_text_for_name(s: str) -> str:
    """Strip bullets, (cid:NNN) glyph refs, collapse whitespace, trim. Used to
    recover a finding name from a cell that mixes a header with bulleted IPs."""
    s = _CID_REF.sub("", s)
    s = _BULLET_CHARS.sub("", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _row_status(cells_lc: list[str], accept_patterns: list[str],
                reject_patterns: list[str]) -> tuple[str | None, int]:
    """Return ('accept'|None, index_of_match) for a row.

    Reject patterns take priority. Returns (None, -1) if neither accept nor
    reject markers are found.
    """
    for i, c in enumerate(cells_lc):
        for rj in reject_patterns:
            if rj in c:
                return None, i  # explicitly rejected
    for i, c in enumerate(cells_lc):
        for ap in accept_patterns:
            if ap in c:
                return "accept", i
    return None, -1


def _split_name_and_ips(cell_text: str) -> tuple[str, str]:
    """Given a cell that mixes a finding name with bulleted IPs (header + list),
    return (finding_name, ip_text). If the cell has no IPs, returns
    (cleaned_text, '')."""
    m = _IPV4.search(cell_text)
    if not m:
        return _clean_text_for_name(cell_text), ""
    name_part = cell_text[:m.start()]
    ip_part = cell_text[m.start():]
    name_clean = _clean_text_for_name(name_part)
    return name_clean, ip_part


def _extract_from_table(
    table: list[list[str | None]],
    accept_patterns: list[str],
    reject_patterns: list[str],
    page_num: int,
    table_idx: int,
    source_name: str,
) -> list[dict]:
    """Walk one table, return canonical records for risk-accepted rows."""
    records: list[dict] = []
    for row_idx, raw_row in enumerate(table):
        if not raw_row:
            continue
        cells = [str(c or "").strip() for c in raw_row]
        cells_lc = [c.lower() for c in cells]

        status, status_idx = _row_status(cells_lc, accept_patterns, reject_patterns)
        if status != "accept":
            continue

        # Find which cells contain IPs and which look like finding-name candidates
        ip_cells_idx: list[int] = []
        for i, c in enumerate(cells):
            if i == status_idx:
                continue
            if _IPV4.search(c):
                ip_cells_idx.append(i)

        if not ip_cells_idx:
            continue  # marked accepted but no IPs - skip

        # Strategy: PDFs in this format usually have the finding name as a
        # header text immediately preceding the bulleted IP list in the same
        # cell, like:
        #     "Information Disclosure
        #      * 192.0.2.27 (443)
        #      * 192.0.2.11 (53), ..."
        # Try that first - it's the most reliable signal. Only fall back to
        # scanning other cells if the IP cell has no text prefix at all.
        finding_name = ""
        first_ip_cell_text = cells[ip_cells_idx[0]]
        recovered_name, _ = _split_name_and_ips(first_ip_cell_text)
        if recovered_name and len(recovered_name) > 2 and len(recovered_name) < 200:
            finding_name = recovered_name

        # Fallback: scan other cells for a substantive non-numeric text cell.
        # Skip Observations-style long-prose cells (>200 chars) since those
        # are usually descriptions, not titles.
        if not finding_name:
            for i, c in enumerate(cells):
                if i == status_idx or i in ip_cells_idx:
                    continue
                if not c:
                    continue
                if re.fullmatch(r"\d+(\.\d+)?", c):
                    continue
                if len(c) < 3 or len(c) > 200:
                    continue
                finding_name = _clean_text_for_name(c)
                if finding_name:
                    break

        if not finding_name:
            continue

        # Collect all (ip, port) pairs across all IP cells
        ip_text_combined = "\n".join(cells[i] for i in ip_cells_idx)
        seen = set()
        pairs = []
        for pair in extract_ip_port_pairs(ip_text_combined):
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)

        for ip, port in pairs:
            rec = {c: "" for c in CANON_COLS}
            rec["finding_name"] = finding_name
            rec["ip"] = ip
            rec["port"] = port
            rec["source_file"] = f"{source_name}::page{page_num}::table{table_idx + 1}"
            rec["source_row"] = row_idx + 1
            records.append(rec)
    return records


def load_riskaccept_pdf(
    path: Path,
    risk_accept_patterns: list[str] | None = None,
    reject_patterns: list[str] | None = None,
) -> pd.DataFrame:
    """Extract risk-accepted findings from a PDF management report.

    Args:
        path: PDF file path.
        risk_accept_patterns: Substrings (case-insensitive) that mark a row
            as risk-accepted. Defaults to DEFAULT_RISK_ACCEPT_PATTERNS.
        reject_patterns: Substrings that explicitly mark a row as NOT
            accepted (closed, remediated, etc.) - take priority.

    Returns canonical DataFrame (CANON_COLS). Plugin ID is empty (PDFs rarely
    include it); matching will fall back to (finding_name, ip, port) tiers.
    """
    if not HAS_PDFPLUMBER:
        raise RuntimeError(
            "pdfplumber not installed. pip install pdfplumber"
        )

    path = Path(path)
    if path.suffix.lower() != ".pdf":
        raise ValueError(f"Not a PDF: {path}")

    accept_patterns = [p.lower() for p in (risk_accept_patterns or DEFAULT_RISK_ACCEPT_PATTERNS)]
    rej_patterns = [r.lower() for r in (reject_patterns or DEFAULT_REJECT_PATTERNS)]

    all_records: list[dict] = []
    page_count = 0
    tables_count = 0

    with pdfplumber.open(path) as pdf:
        page_count = len(pdf.pages)
        for page_num, page in enumerate(pdf.pages, start=1):
            tables = page.extract_tables() or []
            for tbl_idx, table in enumerate(tables):
                tables_count += 1
                recs = _extract_from_table(
                    table, accept_patterns, rej_patterns,
                    page_num=page_num, table_idx=tbl_idx,
                    source_name=path.name,
                )
                all_records.extend(recs)

    if not all_records:
        df = pd.DataFrame(columns=CANON_COLS)
        df.attrs["pdf_page_count"] = page_count
        df.attrs["pdf_table_count"] = tables_count
        df.attrs["pdf_extracted_rows"] = 0
        return df

    df = pd.DataFrame(all_records, columns=CANON_COLS).drop_duplicates(
        subset=["plugin_id", "finding_name", "ip", "port", "cve"]
    ).reset_index(drop=True)
    df.attrs["pdf_page_count"] = page_count
    df.attrs["pdf_table_count"] = tables_count
    df.attrs["pdf_extracted_rows"] = len(df)
    return df
