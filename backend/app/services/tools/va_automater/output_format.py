"""Output formatting for per-category xlsx files.

Internally we use canonical lowercase_snake_case columns. For user-facing
output files we want:
  - Human-friendly column names (Host, Plugin ID, Finding Name, Risk, etc.)
  - Writable "Status" column (defaults to 'Open' so the user can mark Closed)
  - Writable "Comments" column (blank, for general notes)
  - Optional custom-named comments column (e.g. "VibeDocs Comments")
  - Plugin Output (raw observation from Nessus - shows observed vs fixed version)
  - Solution (remediation guidance)
  - Stable column ordering across all output files

Output files round-trip cleanly back into the loader: the display names are
already in COL_ALIASES, so a tracker created from an output file can be used
as input to the next quarter's risk-accept subtraction without renaming.
"""
from __future__ import annotations
import pandas as pd

# Risk levels considered "real" findings. Anything outside this set
# (None, NaN, Informational, empty, etc.) gets Status = "N/A" and is
# dropped from the output after the status stamp.
_VALID_RISK_LEVELS: frozenset[str] = frozenset(
    {"critical", "high", "medium", "low"}
)

# Canonical -> display rename map
CANON_TO_DISPLAY: dict[str, str] = {
    "plugin_id":     "Plugin ID",
    "finding_name":  "Finding Name",
    "ip":            "Host",
    "port":          "Port",
    "protocol":      "Protocol",
    "risk":          "Risk",
    "cvss3_score":   "CVSS3 Score",
    "cvss3_vector":  "CVSS3 Vector",
    "cvss2_score":   "CVSS2 Score",
    "cve":           "CVE",
    "plugin_family": "Plugin Family",
    "synopsis":      "Synopsis",
    "description":   "Description",
    "solution":      "Solution",
    "see_also":      "See Also",
    "plugin_output": "Plugin Output",
    "source_file":   "Source File",
    "source_row":    "Source Row",
    "category":      "Category",
    "category_score": "Category Score",
    "ip_in_current_scan":   "IP in Current Scan",
    "finding_on_same_host": "Near-Miss on Same Host",
    "near_miss_in_current": "Near-Miss in Current Scan",
    "ip_in_accepted":                    "IP in Accepted Tracker",
    "finding_on_same_host_in_accepted":  "Near-Miss on Same Host (Accepted)",
    "near_miss_in_accepted":             "Near-Miss in Accepted Tracker",
    # subtract_review.xlsx-only columns. `build_subtract_review`
    # tags every row with its bucket (review_reason) + a one-line
    # action hint (review_action). Display them with friendly names
    # so the consultant doesn't have to read snake_case.
    "review_reason":                     "Review Reason",
    "review_action":                     "Review Action",
}

# Column order for output files (first = leftmost). Columns not in this list
# are appended at the end in their natural order.
DISPLAY_COL_ORDER: list[str] = [
    # Review Reason / Action lead the row on subtract_review.xlsx so
    # the consultant sees WHY a row is in the triage file + WHAT to
    # verify before scanning the rest of the columns. These columns
    # are absent from every other output file — format_for_output's
    # intersection rule filters them out automatically.
    "Review Reason",
    "Review Action",
    "Host",
    "Port",
    "Plugin ID",
    "CVE",
    "Finding Name",
    "Category",
    "Risk",
    "Status",
    "Comments",
    # custom comments column inserted here (after "Comments") if provided
    "Solution",
    "Plugin Output",
    # Near-miss diagnostics — only present on considered_not_removed.xlsx
    # OR audit_remaining_vs_accepted.xlsx. Each file carries one direction's
    # set; the other direction's columns are filtered out by format_for_output's
    # intersection rule.
    "IP in Current Scan",
    "Near-Miss on Same Host",
    "Near-Miss in Current Scan",
    "IP in Accepted Tracker",
    "Near-Miss on Same Host (Accepted)",
    "Near-Miss in Accepted Tracker",
    "Synopsis",
    "Description",
    "Plugin Family",
    "CVSS3 Score",
    "Source File",
]


def format_for_output(
    df: pd.DataFrame,
    custom_comment_col: str = "",
    custom_comment_default: str = "",
    default_status: str = "Open",
    drop_columns: list[str] | None = None,
) -> pd.DataFrame:
    """Rename canonical columns to display names, inject Status + Comments
    columns, reorder, and drop noisy internal columns.

    Args:
        df: DataFrame in canonical schema (post-categorize).
        custom_comment_col: Optional extra column name like "VibeDocs Comments".
            Inserted right after the standard "Comments" column. Empty string
            means don't add an extra column.
        custom_comment_default: Value used to pre-fill every row of the
            custom comments column. Empty string (the default) leaves cells
            blank for the user to fill in manually; passing e.g.
            ``"Per VibeDocs recommendation"`` writes that exact text into
            every row, which is what the toolkit UI offers consultants when
            the same boilerplate applies to the whole engagement.
        default_status: Value used to populate the new "Status" column.
            Default 'Open' so the user can mark rows Closed manually.
        drop_columns: Optional list of column names to drop from the output.
            Accepts canonical OR display names (matched after rename). Used by
            the by-category split writer to drop the redundant "Category"
            column from each per-category file.

    Returns a new DataFrame with display column names and order.
    """
    out = df.copy()

    # Drop truly empty rows first (no finding name AND no IP = scanner noise).
    for name_col in ("finding_name", "Finding Name"):
        if name_col in out.columns:
            out = out[out[name_col].astype(str).str.strip() != ""].reset_index(drop=True)
            break

    # Drop internal-only noise columns that shouldn't appear in user files
    drop_internal = ["source_row", "category_score"]
    for c in drop_internal:
        if c in out.columns:
            out = out.drop(columns=[c])

    # Rename canonical -> display
    rename_map = {k: v for k, v in CANON_TO_DISPLAY.items() if k in out.columns}
    out = out.rename(columns=rename_map)

    # Caller-requested column drops (post-rename so display names work)
    if drop_columns:
        for c in drop_columns:
            if c in out.columns:
                out = out.drop(columns=[c])

    # Add writable columns (only if not already present - so re-running on
    # an existing file preserves user edits). The custom comments column
    # gets pre-filled with `custom_comment_default` when supplied — useful
    # for engagements where the same boilerplate ("Per VibeDocs
    # recommendation, …") applies to every row and would otherwise have to
    # be pasted in by hand. An empty default leaves the column blank, which
    # is the standalone CLI's historical behaviour.
    if "Status" not in out.columns:
        out["Status"] = default_status
    if "Comments" not in out.columns:
        out["Comments"] = ""
    if custom_comment_col and custom_comment_col not in out.columns:
        # Guard against a caller passing float NaN or the string "nan"
        # as the default — both produce literal "nan" cells in Excel.
        _safe_default = custom_comment_default or ""
        if str(_safe_default).strip().lower() == "nan":
            _safe_default = ""
        out[custom_comment_col] = _safe_default

    # Mark non-actionable risk levels as N/A.
    # Nessus emits "None" or blank for informational / no-risk plugins.
    # Any risk value not in {Critical, High, Medium, Low} gets Status = "N/A"
    # so the consultant can see them but knows they require no action.
    if "Risk" in out.columns:
        no_risk_mask = ~out["Risk"].astype(str).str.strip().str.lower().isin(_VALID_RISK_LEVELS)
        out.loc[no_risk_mask, "Status"] = "N/A"

    # Build final column order
    base_order = [c for c in DISPLAY_COL_ORDER if c in out.columns]
    if custom_comment_col and custom_comment_col in out.columns:
        # Insert right after Comments
        try:
            insert_at = base_order.index("Comments") + 1
            base_order.insert(insert_at, custom_comment_col)
        except ValueError:
            base_order.append(custom_comment_col)

    # Append any remaining columns at the end (for audit / debugging)
    extras = [c for c in out.columns if c not in base_order]
    final_order = base_order + extras
    return out[final_order]
