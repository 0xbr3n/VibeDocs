"""End-to-end pipeline orchestrators.

Each function takes explicit paths/params, performs the workflow, and returns
a result dataclass. No prompting here - prompting lives in cli.py. This makes
the same functions reusable from any future UI (e.g. Streamlit).
"""
from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass, field, asdict
import pandas as pd

from .loaders import (
    load_nessus_folder, load_riskaccept_file,
    load_tracker_comment_riskaccept,
)
from .matching import (
    NewScanIndex, subtract_riskaccepted, TIER_ORDER,
    build_match_preview, find_accepted_not_matched, annotate_near_misses,
    annotate_remaining_near_misses,
)
from .identifiers import normalize_name
from .categorize import (
    categorize_dataframe, load_pid_map, save_pid_map, merge_into_pid_map,
    DEFAULT_RULES,
)
from .output_format import format_for_output
from .risk_keywords import load_keyword_config

OUT_REMAINING               = "remaining_findings.xlsx"
OUT_REMOVED                 = "risk_accepted_removed.xlsx"
OUT_CATEGORIZED             = "categorized_findings.xlsx"
OUT_BY_CATEGORY_DIR         = "by_category"
OUT_SUMMARY                 = "summary.txt"
OUT_MATCH_PREVIEW           = "match_preview.xlsx"
OUT_CONSIDERED_NOT_REMOVED  = "considered_not_removed.xlsx"
OUT_AUDIT_REMAINING         = "audit_remaining_vs_accepted.xlsx"


def group_by_finding_and_port(df: pd.DataFrame) -> pd.DataFrame:
    """Collapse rows sharing the same (finding_name, port) into one row.

    The merged row's `ip` field becomes a comma-separated list of unique
    IPs (numerically sorted via the ipaddress module, with fallback to
    lex sort for non-IP values). All other columns take the FIRST row's
    value — the assumption is that for rows of the same finding+port,
    columns like solution/risk/synopsis are essentially identical.

    Operates on canonical schema (lowercase columns). Called BEFORE
    format_for_output, so the display rename still works downstream.

    Used by the by_category writer when the user opts into the
    "consolidate same-finding rows" prompt. Does not alter the source
    DataFrame.
    """
    import ipaddress

    if df is None or len(df) == 0:
        return df.copy() if df is not None else df
    if "finding_name" not in df.columns or "port" not in df.columns:
        return df.copy()

    def _sorted_unique_ips(s: pd.Series) -> str:
        vals = [v for v in s.dropna().astype(str).tolist() if v.strip()]
        if not vals:
            return ""
        uniq = list(dict.fromkeys(vals))  # preserve first-seen order pre-sort

        def _key(v: str):
            try:
                return (0, int(ipaddress.ip_address(v)))
            except ValueError:
                return (1, v)

        return ", ".join(sorted(uniq, key=_key))

    group_cols = ["finding_name", "port"]
    other_cols = [c for c in df.columns if c not in group_cols + ["ip"]]
    agg: dict = {c: "first" for c in other_cols}
    agg["ip"] = _sorted_unique_ips

    out = df.groupby(group_cols, dropna=False, as_index=False).agg(agg)

    # groupby reorders columns; restore the original column order so
    # downstream renaming + DISPLAY_COL_ORDER work predictably.
    out = out[[c for c in df.columns if c in out.columns]]
    return out
OUT_NEW_HOSTS               = "new_hosts.xlsx"
OUT_VERSION_REMEDIATED      = "version_remediated.xlsx"
# Consolidated "humans should eyeball this" file. Replaces the need to
# open risk_accepted_removed.xlsx + considered_not_removed.xlsx +
# audit_remaining_vs_accepted.xlsx + match_preview.xlsx separately
# during triage — every row that warrants a manual check lands here,
# tagged with `review_reason` + `review_action` so the consultant knows
# what to verify. See `build_subtract_review` for the four buckets.
OUT_SUBTRACT_REVIEW         = "subtract_review.xlsx"
# Cross-scan partial-upgrade detector output. Rows where the client
# upgraded the installed version between scans but it's STILL below
# the recommended fix — needs a "you upgraded, go further" client
# conversation + manual verification. See
# `version_check.analyze_partial_upgrades`.
OUT_PARTIAL_UPGRADES        = "partial_upgrades.xlsx"

# Extra metadata columns attached to removed.xlsx and considered_not_removed.xlsx
# so the user can audit WHY each row was flagged.
EVIDENCE_COLUMNS = (
    "riskaccept_source",
    "riskaccept_keyword",
    "riskaccept_comment_col",
    "riskaccept_comment_text",
)


def build_subtract_review(
    removed: pd.DataFrame | None,
    considered: pd.DataFrame | None,
    audit_suspects: pd.DataFrame | None,
) -> pd.DataFrame:
    """Consolidate every "humans should eyeball this" risk-accept
    matching decision into a single DataFrame.

    Four review buckets:
      1. ``removed_weak_tier`` — current rows in `removed` matched at
         ``loose_name`` (least reliable tier). False-positive risk.
      2. ``removed_evidence_drift`` — current rows in `removed` with
         ``match_quality == 'evidence_drift'``. Plugin output differed
         between scans but row was still matched.
      3. ``possibly_missed_subtraction`` — current rows in
         `audit_suspects`. These weren't subtracted, but a same-host
         near-miss exists in the accepted tracker. Likely missed
         subtraction.
      4. ``accepted_no_current_match`` — accepted rows in `considered`
         (already filtered to same-host near-miss). Sanity-check that
         the finding really is gone from that host.

    Output is canonical-column-based; downstream ``format_for_output``
    renames to display names. Adds two text columns:
      - ``review_reason``  : one of the four bucket names above
      - ``review_action``  : one-line guidance on what to verify

    Returns an empty DataFrame when nothing needs review. The caller
    decides whether to write the file.
    """
    pieces: list[pd.DataFrame] = []

    if removed is not None and len(removed) and "matched_tier" in removed.columns:
        weak = removed[removed["matched_tier"] == "loose_name"].copy()
        if len(weak):
            weak["review_reason"] = "removed_weak_tier"
            weak["review_action"] = (
                "Subtracted on name+IP only (weakest tier). "
                "Verify match is correct, esp. if finding names are generic."
            )
            pieces.append(weak)

        if "match_quality" in removed.columns:
            drift = removed[removed["match_quality"] == "evidence_drift"].copy()
            if len(drift):
                drift["review_reason"] = "removed_evidence_drift"
                drift["review_action"] = (
                    "Subtracted despite plugin_output drift between scans. "
                    "Verify it's the same finding, not a similar one."
                )
                pieces.append(drift)

    if audit_suspects is not None and len(audit_suspects):
        a = audit_suspects.copy()
        a["review_reason"] = "possibly_missed_subtraction"
        a["review_action"] = (
            "Survived subtraction but a similar accepted entry exists on "
            "this host. Likely missed subtraction — check accepted tracker."
        )
        pieces.append(a)

    if considered is not None and len(considered):
        c = considered.copy()
        c["review_reason"] = "accepted_no_current_match"
        c["review_action"] = (
            "Accepted entry from last quarter has no exact match in current. "
            "Verify the finding is truly remediated on that host."
        )
        pieces.append(c)

    if not pieces:
        return pd.DataFrame()

    out = pd.concat(pieces, ignore_index=True, sort=False).fillna("")

    # Stable sort: group by bucket so the user can walk the file top-to-bottom.
    bucket_order = {
        "removed_weak_tier": 0,
        "removed_evidence_drift": 1,
        "possibly_missed_subtraction": 2,
        "accepted_no_current_match": 3,
    }
    out["_bucket_order"] = out["review_reason"].map(bucket_order).fillna(99)
    out = out.sort_values(
        ["_bucket_order", "finding_name", "ip", "port"], kind="stable",
    ).drop(columns=["_bucket_order"]).reset_index(drop=True)
    return out


@dataclass
class ScanPipelineResult:
    total_current: int = 0
    total_after_subtract: int = 0
    n_removed_riskaccepted: int = 0
    n_considered_not_removed: int = 0
    # Accepted-side rows dropped from considered_not_removed.xlsx because
    # no near-miss exists on the same host in current — either the host
    # is gone from the scan entirely, or the host is scanned but the
    # finding has moved off it. Either way, nothing to triage. Surfaced
    # for audit; not written to disk.
    n_accepted_dropped_no_match: int = 0
    # Audit signal: remaining current rows that have at least one
    # same-host near-miss in the accepted tracker. If non-zero, the
    # matcher may have missed a subtraction (column-mapping issue,
    # name drift, etc). Written to audit_remaining_vs_accepted.xlsx.
    n_remaining_with_accepted_near_miss: int = 0
    # Total rows written to subtract_review.xlsx — the consolidated
    # "humans should eyeball this" file built from weak-tier removed
    # rows, evidence-drift removed rows, audit suspects, and considered
    # rows. If 0, the matcher's decisions look clean. If non-zero,
    # that's the ONE file the consultant opens to triage all four
    # classes of risk-accept matching risk.
    n_subtract_review_rows: int = 0
    # Cross-scan partial-upgrade rows: client upgraded the installed
    # version between scans but it's still below the recommended fix.
    # Written to partial_upgrades.xlsx; surfaced to the consultant for
    # manual verification + a tailored client message.
    n_partial_upgrades: int = 0
    n_from_management_file: int = 0
    n_from_tracker_comments: int = 0
    subtract_diag: dict = field(default_factory=dict)
    tracker_comment_diag: dict = field(default_factory=dict)
    category_counts: dict = field(default_factory=dict)
    new_pid_mappings: int = 0
    output_folder: str = ""
    load_warnings: list = field(default_factory=list)
    output_files: list = field(default_factory=list)
    # Retest-mode diagnostics. Empty when those features are disabled.
    new_ips_detected: list = field(default_factory=list)   # sorted list of new IPs
    n_new_host_rows_filtered: int = 0                       # rows dropped from retest
    n_version_check_remediated: int = 0                     # rows confidently remediated
    n_version_check_uncertain: int = 0                      # rows ambiguous; left as-is
    n_version_check_closed: int = 0                         # rows the user opted to close
    # Per-category row counts AFTER group_by_finding_and_port (when enabled).
    # Empty when group_ips_in_by_category=False — in that case category_counts
    # already gives the true output row counts.
    grouped_category_counts: dict = field(default_factory=dict)


def run_scan_pipeline(
    current_folder: Path,
    output_folder: Path,
    prev_accepted_path: Path | None = None,
    riskaccept_sheet: int | str | None = None,
    pid_map_path: Path | None = None,
    save_categorized_split: bool = True,
    auto_learn_pid_map: bool = True,
    learn_threshold: int = 4,
    custom_comment_col: str = "",
    # Pre-fill value for every row of `custom_comment_col`. Empty
    # string (default) leaves the column blank for the consultant to
    # fill in manually — matches the CLI's historical behaviour.
    # Passing a value (e.g. "Per VibeDocs recommendation, ...") stamps
    # it into every row of every output xlsx so engagements with one
    # boilerplate comment for the entire scan don't need a manual
    # post-process step.
    custom_comment_default: str = "",
    custom_key_fields: list[str] | None = None,
    strict_output: bool = True,
    write_match_preview: bool = True,
    prev_tracker_path: Path | None = None,
    prev_tracker_sheet: int | str | None = 0,
    risk_keywords_config: Path | None = None,
    # ----- Retest-mode extensions -----
    # `new_ip_action` controls the IP-diff step that runs RIGHT after
    # the risk-accept source(s) are loaded but BEFORE the subtract:
    #   "skip"                : no IP-diff at all (back-compat default)
    #   "export_only"         : write new_hosts.xlsx with rows whose
    #                           IP is net-new (not in original) but
    #                           keep them in the main flow.
    #   "filter_and_export"   : write new_hosts.xlsx AND drop those
    #                           rows from the retest scan so subtract
    #                           only operates on hosts that existed in
    #                           the original engagement.
    # The CLI pre-computes the new-IP list, shows it to the user,
    # and only invokes the pipeline with a non-"skip" action once the
    # user confirms.
    new_ip_action: str = "skip",
    # When True, rows in by_category/*.xlsx files are grouped by
    # (finding_name, port): all rows sharing the same finding name and
    # port get merged into one row whose Host cell is the
    # comma-separated list of unique IPs. Other output files
    # (remaining/removed/categorized/audit/etc.) are unaffected.
    # Useful for clients who don't want to see N nearly-identical rows
    # for the same finding across many hosts.
    group_ips_in_by_category: bool = False,
) -> ScanPipelineResult:
    """Full processing pipeline for a quarter's scan.

    Steps:
      1. Load all CSVs in current_folder -> canonical df.
      2. (Optional) Build the risk-accept set from up to two sources:
           a. prev_accepted_path - management's dedicated risk-accept file
              (.xlsx, .xls, .csv, .pdf).
           b. prev_tracker_path  - last quarter's tracker xlsx; comment
              columns are scanned for keywords like "management accepted"
              and matching rows are also treated as risk-accepted.
         Both sources are unioned, then subtracted from current.
      3. Categorize remaining findings (persistent pid_map + rules).
      4. (Optional) Auto-extend pid_map with high-confidence categorizations.
      5. Write outputs with display-friendly column names, writable
         Status + Comments columns, and optional custom comments column.
    """
    current_folder = Path(current_folder)
    output_folder = Path(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    result = ScanPipelineResult(output_folder=str(output_folder))

    # Step 1: load the current scan. `load_nessus_folder` now cleans the
    # data itself — drops blank-Plugin-ID / blank-Host junk rows and
    # de-duplicates on (plugin_id, finding_name, ip, port, cve), recording
    # what it removed in `attrs['load_warnings']` (which we surface to the
    # consultant) and `attrs['clean_stats']`. CVE is part of the dedup key
    # so distinct-CVE rows for the same finding survive as separate rows.
    current = load_nessus_folder(current_folder)
    result.load_warnings = list(current.attrs.get("load_warnings", []))
    result.total_current = len(current)

    # Step 2: build the risk-accept set from up to two sources, then subtract.
    # Inputs (Nessus CSVs, management file, tracker xlsx) are READ-ONLY -
    # every write below targets `output_folder`.
    accepted_frames: list[pd.DataFrame] = []
    if prev_accepted_path:
        mgmt = load_riskaccept_file(
            Path(prev_accepted_path), sheet=riskaccept_sheet,
        )
        if len(mgmt):
            mgmt = mgmt.assign(
                riskaccept_source="management_file",
                riskaccept_keyword="",
                riskaccept_comment_col="",
                riskaccept_comment_text="",
            )
            accepted_frames.append(mgmt)
            result.n_from_management_file = len(mgmt)

    if prev_tracker_path:
        keywords, case_sensitive = load_keyword_config(
            Path(risk_keywords_config) if risk_keywords_config else None
        )
        tracker_df, tdiag = load_tracker_comment_riskaccept(
            Path(prev_tracker_path),
            sheet=prev_tracker_sheet,
            keywords=keywords,
            case_sensitive=case_sensitive,
            custom_comment_col=custom_comment_col,
        )
        result.tracker_comment_diag = tdiag
        if len(tracker_df):
            tracker_df = tracker_df.assign(riskaccept_source="tracker_comments")
            accepted_frames.append(tracker_df)
            result.n_from_tracker_comments = len(tracker_df)

    # Hoisted out of the `if accepted_frames:` block so the audit step
    # below can still see the accepted set after categorize runs.
    accepted_clean: pd.DataFrame | None = None

    if accepted_frames:
        accepted = pd.concat(accepted_frames, ignore_index=True)
        # Dedup the unioned risk-accept set; prefer management_file rows.
        accepted = accepted.sort_values(
            "riskaccept_source", kind="stable",
        ).drop_duplicates(
            subset=["plugin_id", "finding_name", "ip", "port", "cve"],
            keep="first",
        ).reset_index(drop=True)

        # Build multi-tier lookup so we can attach source+evidence to rows
        # on EITHER side (current-side `removed`, accepted-side
        # `considered_not_removed`) even when names drift across quarters.
        meta_lookup = _build_evidence_lookup(accepted)

        # Drop evidence columns before subtract so they don't pollute the
        # canonical match keys.
        accepted_clean = accepted.drop(columns=list(EVIDENCE_COLUMNS))

        # ----- Retest-mode IP diff -----
        # Compute IPs that exist in the retest but NOT the original
        # engagement. The CLI has already decided (and shown the user)
        # what to do with them via `new_ip_action`. We do it here
        # (rather than in the CLI) so the filter happens against the
        # SAME `current` DataFrame the subtract sees, eliminating any
        # chance of a downstream skew. See [ip_diff.py](ip_diff.py)
        # for the helpers.
        if new_ip_action != "skip":
            from .ip_diff import find_new_ips, split_by_new_ips
            new_ips = find_new_ips(current, accepted_clean)
            if new_ips:
                kept_current, new_host_rows = split_by_new_ips(
                    current, new_ips,
                )
                if len(new_host_rows):
                    new_hosts_path = output_folder / OUT_NEW_HOSTS
                    format_for_output(
                        new_host_rows, custom_comment_col=custom_comment_col,
                    custom_comment_default=custom_comment_default,
                    ).to_excel(new_hosts_path, index=False)
                    result.output_files.append(str(new_hosts_path))
                if new_ip_action == "filter_and_export":
                    current = kept_current
                    result.n_new_host_rows_filtered = len(new_host_rows)
                result.new_ips_detected = sorted(new_ips)

        remaining, removed, diag = subtract_riskaccepted(
            current, accepted_clean,
            custom_key_fields=custom_key_fields,
            strict_output=strict_output,
        )
        result.subtract_diag = diag
        result.n_removed_riskaccepted = len(removed)

        if len(removed):
            removed = _attach_evidence_columns(removed, meta_lookup)
        removed_path = output_folder / OUT_REMOVED
        format_for_output(removed, custom_comment_col=custom_comment_col, custom_comment_default=custom_comment_default).to_excel(
            removed_path, index=False
        )
        result.output_files.append(str(removed_path))

        # NEW: accepted-side rows the script considered but didn't subtract,
        # usually because the finding is already gone from current. Reviewing
        # this file catches near-misses where the user may want manual cleanup.
        considered = find_accepted_not_matched(
            accepted_clean, current,
            custom_key_fields=custom_key_fields,
            strict_output=strict_output,
        )
        if len(considered):
            considered = _attach_evidence_columns(considered, meta_lookup)
            # Near-miss diagnostics: for each unmatched accepted row, surface
            # which current rows share plugin_id / finding_name. This is the
            # main signal the user needs to triage "why didn't this get
            # subtracted" — host gone, finding moved, port shifted, etc.
            considered = annotate_near_misses(considered, current)
            # Filter: drop rows where no near-miss exists on the SAME host
            # in current. Host-level visibility ("IP in Current Scan") isn't
            # enough — the host can be scanned this quarter but the finding
            # has shifted off it (host scanned, no Glassfish anymore), in
            # which case there's nothing to triage on that host either.
            # We keep only rows where the matcher came close on the same IP.
            drop_mask = considered["finding_on_same_host"] == "no"
            result.n_accepted_dropped_no_match = int(drop_mask.sum())
            considered = considered[~drop_mask].reset_index(drop=True)
            if len(considered):
                considered_path = output_folder / OUT_CONSIDERED_NOT_REMOVED
                format_for_output(
                    considered, custom_comment_col=custom_comment_col,
                    custom_comment_default=custom_comment_default,
                ).to_excel(considered_path, index=False)
                result.output_files.append(str(considered_path))
        result.n_considered_not_removed = len(considered)

        # Diagnostic preview: lets the user spot-check borderline matches.
        if write_match_preview and len(removed):
            preview = build_match_preview(removed)
            if len(preview):
                preview_path = output_folder / OUT_MATCH_PREVIEW
                preview.to_excel(preview_path, index=False)
                result.output_files.append(str(preview_path))
    else:
        remaining = current.copy()

    result.total_after_subtract = len(remaining)

    # Step 3
    pid_map = load_pid_map(Path(pid_map_path)) if pid_map_path else {}
    categorized = categorize_dataframe(remaining, rules=DEFAULT_RULES, pid_map=pid_map)

    # Step 4
    if auto_learn_pid_map and pid_map_path:
        new_map, added = merge_into_pid_map(
            pid_map, categorized, confirm_threshold=learn_threshold,
        )
        if added:
            save_pid_map(Path(pid_map_path), new_map)
        result.new_pid_mappings = added

    # Step 5: write outputs (formatted for human use)
    remaining_path = output_folder / OUT_REMAINING
    format_for_output(categorized, custom_comment_col=custom_comment_col, custom_comment_default=custom_comment_default).to_excel(
        remaining_path, index=False
    )
    result.output_files.append(str(remaining_path))

    categorized_path = output_folder / OUT_CATEGORIZED
    format_for_output(categorized, custom_comment_col=custom_comment_col, custom_comment_default=custom_comment_default).to_excel(
        categorized_path, index=False
    )
    result.output_files.append(str(categorized_path))

    result.category_counts = (
        categorized["category"].value_counts().to_dict() if "category" in categorized else {}
    )

    # Audit step (only when we actually had risk-accept input). For every
    # remaining current row, surface any accepted-side rows that share
    # plugin_id or finding_name on the SAME host. Filtered to suspect
    # rows only so an empty file means "no missed subtractions
    # detected". A populated file means: investigate — likely a
    # column-mapping miss on the accepted side or a name drift the
    # matcher couldn't bridge.
    # Captured outside the audit block so build_subtract_review can
    # pick it up regardless of whether the audit file was written. None
    # when no accepted input was supplied (subtract pass was skipped).
    audit_suspects_for_review: pd.DataFrame | None = None
    if accepted_clean is not None and len(categorized):
        audited = annotate_remaining_near_misses(categorized, accepted_clean)
        suspect_mask = audited["finding_on_same_host_in_accepted"] == "yes"
        suspects = audited[suspect_mask].reset_index(drop=True)
        result.n_remaining_with_accepted_near_miss = len(suspects)
        if len(suspects):
            audit_path = output_folder / OUT_AUDIT_REMAINING
            format_for_output(
                suspects, custom_comment_col=custom_comment_col,
                    custom_comment_default=custom_comment_default,
            ).to_excel(audit_path, index=False)
            result.output_files.append(str(audit_path))
        audit_suspects_for_review = suspects

    # ------------------------------------------------------------
    # subtract_review.xlsx — the single consolidated triage file.
    # Builds from `removed` (weak-tier + drift), filtered `considered`
    # (accepted-no-match), and the audit suspects (possibly missed
    # subtractions). Only meaningful when risk-accept input was
    # supplied — otherwise there are no subtract decisions to triage.
    # ------------------------------------------------------------
    if accepted_clean is not None:
        review_df = build_subtract_review(
            removed=removed,
            considered=considered,
            audit_suspects=audit_suspects_for_review,
        )
        result.n_subtract_review_rows = len(review_df)
        if len(review_df):
            review_path = output_folder / OUT_SUBTRACT_REVIEW
            format_for_output(
                review_df, custom_comment_col=custom_comment_col,
                custom_comment_default=custom_comment_default,
            ).to_excel(review_path, index=False)
            result.output_files.append(str(review_path))

    # ------------------------------------------------------------
    # Partial-upgrade detection (Infra VA recurring). Compares the
    # installed version parsed from the CURRENT scan's plugin_output
    # against the PREVIOUS source for the same (finding, host). Flags
    # rows where the client upgraded BUT the new version is still below
    # the recommended fix — they need a "you upgraded, go further"
    # client conversation, distinct from rows that never moved. Only
    # meaningful when a previous source with plugin_output exists.
    # ------------------------------------------------------------
    if accepted_clean is not None and len(categorized):
        try:
            from .version_check import analyze_partial_upgrades
            pu = analyze_partial_upgrades(categorized, accepted_clean)
            flagged = pu[pu["partial_upgrade"] == "yes"].reset_index(drop=True)
            result.n_partial_upgrades = len(flagged)
            if len(flagged):
                pu_path = output_folder / OUT_PARTIAL_UPGRADES
                format_for_output(
                    flagged, custom_comment_col=custom_comment_col,
                    custom_comment_default=custom_comment_default,
                ).to_excel(pu_path, index=False)
                result.output_files.append(str(pu_path))
        except Exception as e:                              # pragma: no cover
            import logging
            logging.getLogger(__name__).warning(
                "partial-upgrade detection skipped: %s", e)

    if save_categorized_split:
        split_dir = output_folder / OUT_BY_CATEGORY_DIR
        split_dir.mkdir(exist_ok=True)
        for cat, grp in categorized.groupby("category"):
            safe = "".join(c if c.isalnum() or c in "._- " else "_" for c in cat)
            split_path = split_dir / f"{safe}.xlsx"
            # Optional: collapse same-(finding_name, port) rows so the
            # client doesn't see N near-identical rows for the same
            # finding across many hosts. Only applied to by_category
            # files — remaining/removed/categorized stay row-per-host.
            grp_out = group_by_finding_and_port(grp) if group_ips_in_by_category else grp
            if group_ips_in_by_category:
                result.grouped_category_counts[cat] = len(grp_out)
            # Drop the Category column here - each split file is already
            # a single category, so the column would be redundant.
            format_for_output(
                grp_out,
                custom_comment_col=custom_comment_col,
                    custom_comment_default=custom_comment_default,
                drop_columns=["Category"],
            ).to_excel(split_path, index=False)
            result.output_files.append(str(split_path))

    _write_summary(output_folder / OUT_SUMMARY, result)
    result.output_files.append(str(output_folder / OUT_SUMMARY))

    return result


def _build_evidence_lookup(accepted: pd.DataFrame) -> dict:
    """Index accepted rows at multiple key strengths so source+evidence can
    be attached to rows whose name has drifted across quarters.

    Returns four nested dicts keyed by (pid, ip, port), (pid, ip),
    (name_norm, ip, port), (name_norm, ip). Lookups try strongest first.
    """
    by_pid_ip_port: dict = {}
    by_pid_ip: dict = {}
    by_name_ip_port: dict = {}
    by_name_ip: dict = {}
    for _, r in accepted.iterrows():
        pid = str(r["plugin_id"]).strip()
        name_n = normalize_name(r["finding_name"])
        ip = str(r["ip"]).strip()
        port = str(r["port"]).strip()
        meta = {col: str(r.get(col, "") or "") for col in EVIDENCE_COLUMNS}
        if pid:
            by_pid_ip_port.setdefault((pid, ip, port), meta)
            by_pid_ip.setdefault((pid, ip), meta)
        if name_n:
            by_name_ip_port.setdefault((name_n, ip, port), meta)
            by_name_ip.setdefault((name_n, ip), meta)
    return {
        "pid_ip_port": by_pid_ip_port,
        "pid_ip":      by_pid_ip,
        "name_ip_port": by_name_ip_port,
        "name_ip":     by_name_ip,
    }


def _attach_evidence_columns(df: pd.DataFrame, lookup: dict) -> pd.DataFrame:
    """Attach EVIDENCE_COLUMNS to df by looking each row up in `lookup`."""
    df = df.copy()
    empty = {col: "" for col in EVIDENCE_COLUMNS}
    metas: list[dict] = []
    for _, r in df.iterrows():
        pid = str(r["plugin_id"]).strip()
        name_n = normalize_name(r["finding_name"])
        ip = str(r["ip"]).strip()
        port = str(r["port"]).strip()
        meta = (
            (pid and lookup["pid_ip_port"].get((pid, ip, port)))
            or (pid and lookup["pid_ip"].get((pid, ip)))
            or (name_n and lookup["name_ip_port"].get((name_n, ip, port)))
            or (name_n and lookup["name_ip"].get((name_n, ip)))
            or empty
        )
        metas.append(meta)
    for col in EVIDENCE_COLUMNS:
        df[col] = [m.get(col, "") for m in metas]
    return df


def _write_summary(path: Path, result: ScanPipelineResult) -> None:
    lines = [
        "VA-Automater Scan Pipeline Summary",
        "=" * 50,
        f"Output folder: {result.output_folder}",
        f"Total current findings loaded:    {result.total_current}",
        f"After risk-accepted subtraction:  {result.total_after_subtract}",
        f"Risk-accepted removed:            {result.n_removed_riskaccepted}",
        f"  from management file:           {result.n_from_management_file}",
        f"  from tracker comments:          {result.n_from_tracker_comments}",
        f"Considered but not removed:       {result.n_considered_not_removed}",
        f"  (accepted entries no longer in current scan -",
        f"   see considered_not_removed.xlsx for manual review)",
        f"New plugin_id->category learned:  {result.new_pid_mappings}",
        "",
        "Category counts:",
    ]
    for cat, n in sorted(result.category_counts.items(), key=lambda x: -x[1]):
        if result.grouped_category_counts and cat in result.grouped_category_counts:
            g = result.grouped_category_counts[cat]
            lines.append(f"  {cat:35s} {n} rows  →  {g} grouped findings")
        else:
            lines.append(f"  {cat:35s} {n}")

    if result.subtract_diag and result.subtract_diag.get("tier_counts"):
        lines.append("")
        lines.append("Risk-accepted match tiers (how the subtraction matched):")
        for tier in TIER_ORDER:
            n = result.subtract_diag["tier_counts"].get(tier, 0)
            if n:
                lines.append(f"  {tier:20s} {n}")

        ckf = result.subtract_diag.get("custom_key_fields") or []
        if ckf:
            lines.append("")
            lines.append(f"Match mode: CUSTOM key = {ckf}")
        qc = result.subtract_diag.get("quality_counts") or {}
        if qc:
            lines.append("")
            lines.append("Evidence quality (plugin_output disambiguation):")
            for q, n in sorted(qc.items(), key=lambda x: -x[1]):
                lines.append(f"  {q:20s} {n}")

    # ---- Subtract-review triage guide ----
    # The single most useful section for a consultant after a recurring
    # pipeline run. Tells them exactly which xlsx to open and how to
    # interpret each of the four review buckets. Only printed when there
    # was risk-accept input (otherwise no subtract decisions to triage).
    if result.n_from_management_file or result.n_from_tracker_comments:
        lines.append("")
        lines.append("=" * 50)
        if result.n_subtract_review_rows:
            lines.append(f">> SUBTRACT REVIEW: {result.n_subtract_review_rows} "
                         "row(s) need eyeballing")
            lines.append("   -> open: subtract_review.xlsx  "
                         "(the ONE file to open for triage)")
            lines.append("")
            lines.append("   The file consolidates four review buckets — walk")
            lines.append("   top-to-bottom. Each row carries Review Reason +")
            lines.append("   Review Action columns telling you what to check.")
            lines.append("")
            lines.append("   1. removed_weak_tier")
            lines.append("      Subtracted on name+IP only (the weakest match")
            lines.append("      tier). Highest false-positive risk — verify the")
            lines.append("      finding really is the same one, especially when")
            lines.append("      finding names are generic.")
            lines.append("")
            lines.append("   2. removed_evidence_drift")
            lines.append("      Subtracted despite plugin_output drift between")
            lines.append("      scans. Key matched but evidence changed. Verify")
            lines.append("      it's the same finding, not a similar one.")
            lines.append("")
            lines.append("   3. possibly_missed_subtraction")
            lines.append("      Current row survived subtraction BUT a similar")
            lines.append("      accepted entry exists on the same host. Most")
            lines.append("      actionable bucket — these are likely missed")
            lines.append("      subtractions you should add to the accepted set.")
            lines.append("")
            lines.append("   4. accepted_no_current_match")
            lines.append("      Accepted entry from last quarter has no exact")
            lines.append("      match in current. Sanity-check the host really")
            lines.append("      got remediated rather than the finding silently")
            lines.append("      moving.")
            lines.append("")
            lines.append("   Mark each row Open/Closed in the Status column and")
            lines.append("   note your reasoning in Comments — same as every")
            lines.append("   other output file.")
        else:
            lines.append(">> SUBTRACT REVIEW: 0 rows flagged — matcher decisions "
                         "look clean.")
        lines.append("=" * 50)

        # Partial-upgrade callout — separate block so it doesn't get
        # lost inside the subtract-review wall of text.
        lines.append("")
        lines.append("=" * 50)
        if result.n_partial_upgrades:
            lines.append(f">> PARTIAL UPGRADES: {result.n_partial_upgrades} "
                         "host/finding row(s) the client upgraded but NOT far "
                         "enough")
            lines.append("   -> open: partial_upgrades.xlsx")
            lines.append("")
            lines.append("   These rows still appear in the current scan, BUT")
            lines.append("   the installed version PARSED FROM plugin_output")
            lines.append("   changed vs the previous scan (the client patched)")
            lines.append("   and is STILL below the recommended fix. They need")
            lines.append("   a different client message than a row that never")
            lines.append("   moved: \"you upgraded — finish the job\". Columns")
            lines.append("   prev_installed_version / curr_installed_version /")
            lines.append("   recommended_version show the exact deltas; verify")
            lines.append("   each one manually before reporting.")
        else:
            lines.append(">> PARTIAL UPGRADES: 0 — no host shows a "
                         "moved-but-still-vulnerable version delta.")
        lines.append("=" * 50)

    if result.tracker_comment_diag:
        td = result.tracker_comment_diag
        lines.append("")
        lines.append("Tracker comment scan:")
        lines.append(f"  rows scanned:       {td.get('rows_scanned', 0)}")
        lines.append(f"  rows flagged:       {td.get('rows_matched', 0)}")
        lines.append(f"  comment columns:    {td.get('comment_columns', [])}")
        if td.get("keyword_hits"):
            lines.append("  keyword hits:")
            for kw, n in sorted(td["keyword_hits"].items(), key=lambda x: -x[1]):
                lines.append(f"    {kw!r:35s} {n}")

    if result.new_ips_detected or result.n_new_host_rows_filtered:
        lines.append("")
        lines.append("Retest IP-diff:")
        lines.append(f"  new IPs in retest:       {len(result.new_ips_detected)}")
        lines.append(f"  rows filtered out:       {result.n_new_host_rows_filtered}")
        for ip in result.new_ips_detected[:20]:
            lines.append(f"    - {ip}")
        if len(result.new_ips_detected) > 20:
            lines.append(f"    ... and {len(result.new_ips_detected) - 20} more")

    if (result.n_version_check_remediated or result.n_version_check_uncertain
            or result.n_version_check_closed):
        lines.append("")
        lines.append("Version-check (installed >= recommended fix):")
        lines.append(f"  candidates flagged:      {result.n_version_check_remediated}")
        lines.append(f"  ambiguous (kept open):   {result.n_version_check_uncertain}")
        lines.append(f"  closed by consultant:    {result.n_version_check_closed}")

    if result.load_warnings:
        lines.append("")
        lines.append("Load warnings:")
        for w in result.load_warnings:
            lines.append(f"  - {w}")

    path.write_text("\n".join(lines), encoding="utf-8")


# -----------------------------------------------------------
# Tracker-update workflow (analyze + apply, split for UI)
# -----------------------------------------------------------
@dataclass
class TrackerAnalysis:
    tracker_sheet_names: list = field(default_factory=list)
    new_scan_sheet_names: list = field(default_factory=list)
    new_scan_index_summary: dict = field(default_factory=dict)
    suggested_column_map: dict = field(default_factory=dict)
    tracker_columns_preview: list = field(default_factory=list)
    new_scan_has_plugin_id: bool = False
    port_embed_ratio_in_tracker_host: float = 0.0
    recommended_port_mode: int = 2  # 1=embedded, 2=no port in host
    tracker_has_status: bool = False
    tracker_status_column: str = ""


def analyze_for_tracker_update(
    tracker_path: Path,
    new_scan_path: Path,
    tracker_sheet_index: int = 1,
    new_scan_sheet: int | str = 0,
) -> tuple[TrackerAnalysis, NewScanIndex]:
    """Read both files, build the new-scan index, suggest column mappings.

    Returns (analysis, index). Caller can show analysis to the user, get
    confirmed column map + options, then call apply_tracker_update().
    """
    from .tracker_writer import read_tracker_sheet
    from .loaders import (
        list_excel_sheets, load_excel_sheet_raw, auto_map_columns,
    )
    from .identifiers import detect_port_embed_ratio, pick_first_column
    from .schema import TRACKER_COL_ALIASES

    new_scan_path = Path(new_scan_path)
    tracker_path = Path(tracker_path)

    # Load new scan
    new_sheets = list_excel_sheets(new_scan_path) if new_scan_path.suffix.lower() in (".xlsx", ".xls") else []
    raw_new = load_excel_sheet_raw(new_scan_path, sheet=new_scan_sheet)
    new_mapping = auto_map_columns(raw_new.columns.tolist())

    # Project new scan to canonical for index-building
    from .loaders import _build_canonical
    canonical_new = _build_canonical(raw_new, new_mapping, source_file=new_scan_path.name)
    idx = NewScanIndex.build(canonical_new)

    # Load tracker
    tracker_df, headers, tracker_sheets = read_tracker_sheet(
        tracker_path, sheet_index=tracker_sheet_index,
    )
    tracker_mapping = auto_map_columns(tracker_df.columns.tolist())

    # Detect embedded ports in tracker Host column
    port_ratio = 0.0
    if tracker_mapping.get("ip"):
        port_ratio = detect_port_embed_ratio(tracker_df[tracker_mapping["ip"]])
    recommended_mode = 1 if port_ratio >= 0.15 else 2

    # Detect a real Status column on the tracker. A raw Nessus scan CSV will
    # NOT have one, which is the strongest signal the user picked the wrong
    # file (e.g. a previous-quarter scan instead of a marked-up tracker).
    status_col = pick_first_column(
        tracker_df.columns.tolist(), TRACKER_COL_ALIASES["status"],
    ) or ""

    suggested = {
        "plugin_id": tracker_mapping.get("plugin_id") or "",
        "finding_name": tracker_mapping.get("finding_name") or "",
        "ip": tracker_mapping.get("ip") or "",
        "port": tracker_mapping.get("port") or "",
        "status": status_col or "Status",
    }

    analysis = TrackerAnalysis(
        tracker_sheet_names=tracker_sheets,
        new_scan_sheet_names=new_sheets,
        new_scan_index_summary=idx.summary(),
        suggested_column_map=suggested,
        tracker_columns_preview=tracker_df.columns.tolist(),
        new_scan_has_plugin_id=new_mapping.get("plugin_id") is not None,
        port_embed_ratio_in_tracker_host=port_ratio,
        recommended_port_mode=recommended_mode,
        tracker_has_status=bool(status_col),
        tracker_status_column=status_col,
    )
    return analysis, idx


def apply_tracker_update(
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
    """Thin wrapper around tracker_writer.update_tracker_inplace."""
    from .tracker_writer import update_tracker_inplace
    return update_tracker_inplace(
        tracker_path=tracker_path,
        sheet_index=sheet_index,
        column_map=column_map,
        new_scan_index=new_scan_index,
        only_open=only_open,
        mark_closed=mark_closed,
        comment_col=comment_col,
        comment_text=comment_text,
        output_path=output_path,
        dry_run=dry_run,
    )


# -----------------------------------------------------------
# Retest-mode version-check helpers (post-pipeline)
# -----------------------------------------------------------
def analyze_version_check_candidates(
    removed_xlsx_path: Path,
) -> "pd.DataFrame":
    """Read the already-written `risk_accepted_removed.xlsx`, run the
    version-remediation analyzer over it, and return the augmented
    DataFrame. Used by the CLI to preview candidates BEFORE asking the
    consultant to confirm closure.

    The returned DataFrame has every original column plus
    ``installed_version``, ``recommended_version``,
    ``version_check_status``. Filter the result on
    ``version_check_status == "remediated"`` for the rows that are
    safe-to-close candidates; ``"uncertain"`` rows are flagged for
    manual review.
    """
    from .version_check import analyze_version_remediation
    removed_xlsx_path = Path(removed_xlsx_path)
    if not removed_xlsx_path.exists():
        raise FileNotFoundError(f"No removed file at: {removed_xlsx_path}")
    df = pd.read_excel(removed_xlsx_path, dtype=str).fillna("")
    # The xlsx has DISPLAY column names (`Plugin Output`, `Solution` etc.)
    # but `analyze_version_remediation` reads lowercase canonical
    # fields. Map the few we need so the analyzer works whether the
    # caller hands us a display-named or canonical-named frame.
    column_map = {
        "Plugin Output": "plugin_output",
        "Solution":      "solution",
        "Synopsis":      "synopsis",
        "Description":   "description",
        "Finding Name":  "finding_name",
    }
    work = df.rename(columns={
        old: new for old, new in column_map.items() if old in df.columns
    })
    annotated = analyze_version_remediation(work)
    # Restore display column names so the caller can write the file
    # back without re-projection.
    annotated = annotated.rename(columns={
        new: old for old, new in column_map.items() if new in annotated.columns
    })
    return annotated


def apply_version_check_closures(
    removed_xlsx_path: Path,
    row_indices_to_close: list[int],
    justification_column: str,
    justification_text: str,
) -> dict:
    """Modify `risk_accepted_removed.xlsx` in place: flip Status to
    "Closed" for every row index in `row_indices_to_close`, and write
    `justification_text` into `justification_column` for those rows
    (column is created if it doesn't already exist).

    Indices are zero-based and refer to the file AS LOADED by
    `pd.read_excel` — i.e. the same order the caller saw when they
    inspected the analyzed candidates. The caller is responsible for
    mapping their displayed row numbers back to these indices; the CLI
    handles that.

    Returns a small diagnostic dict for logging in summary.txt.
    """
    removed_xlsx_path = Path(removed_xlsx_path)
    if not removed_xlsx_path.exists():
        raise FileNotFoundError(f"No removed file at: {removed_xlsx_path}")
    df = pd.read_excel(removed_xlsx_path, dtype=str).fillna("")
    if "Status" not in df.columns:
        df["Status"] = "Open"
    if justification_column and justification_column not in df.columns:
        df[justification_column] = ""
    # Bounds-check the indices so a stale caller can't write past EOF.
    valid_indices = [i for i in row_indices_to_close
                     if 0 <= i < len(df)]
    df.loc[valid_indices, "Status"] = "Closed"
    if justification_column and justification_text:
        df.loc[valid_indices, justification_column] = justification_text
    df.to_excel(removed_xlsx_path, index=False)

    # Sibling audit file: extract just the rows that we just closed,
    # write them to `version_remediated.xlsx` so the consultant has a
    # quick reference of WHAT got closed and WHY.
    out_dir = removed_xlsx_path.parent
    audit_path = out_dir / OUT_VERSION_REMEDIATED
    if valid_indices:
        df.loc[valid_indices].to_excel(audit_path, index=False)

    return {
        "closed": len(valid_indices),
        "out_of_range": len(row_indices_to_close) - len(valid_indices),
        "audit_file": str(audit_path) if valid_indices else "",
    }
