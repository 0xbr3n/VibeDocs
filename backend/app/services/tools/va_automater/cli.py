"""CLI: thin wrapper around the pipelines.

All user prompting happens here. The library itself never prompts; it raises
exceptions or returns auto-detected values that the CLI can confirm.

This same pattern will let us drop a Streamlit (or other) UI on top later -
the UI replaces this file, the rest of the library is untouched.
"""
from __future__ import annotations
import os
import sys
import traceback
from pathlib import Path
from datetime import datetime

import pandas as pd

from . import __version__
from .pipelines import (
    run_scan_pipeline, analyze_for_tracker_update, apply_tracker_update,
)
from .matching import TIER_ORDER, ALLOWED_CUSTOM_KEY_FIELDS
from .cvss_score import (
    HAS_CVSS3, HAS_CVSS4, CVSS31_METRICS, CVSS40_METRICS,
    build_cvss31_vector, build_cvss40_vector,
    score_vector, apply_vector_to_rows,
)
from .tracker_writer import is_available as com_available


ASCII_ART = r"""
__     __    _               _             _                             _
\ \   / /   / \             / \    _   _  | |_   ___   _ __ ___    __ _ | |_   ___   _ __
 \ \ / /   / _ \   _____   / _ \  | | | | | __| / _ \ | '_ ` _ \  / _` || __| / _ \ | '__|
  \ V /   / ___ \          / ___ \ | |_| | | |_ | (_) || | | | | || (_| || |_ |  __/ | |
   \_/   /_/   \_\       /_/   \_\ \__,_|  \__| \___/ |_| |_| |_| \__,_| \__| \___| |_|

                            VA-Automater  (v{ver})
"""


def _yn(prompt: str, default: str = "n") -> bool:
    default = default.lower().strip()
    while True:
        x = input(prompt).strip().lower()
        if not x:
            x = default
        if x in ("y", "yes"):
            return True
        if x in ("n", "no"):
            return False
        print("Please enter y/n.")


def _prompt_int(prompt: str, default: int, lo: int = 1, hi: int = 999) -> int:
    s = input(prompt).strip()
    if not s:
        return default
    try:
        v = int(s)
    except ValueError:
        return default
    return max(lo, min(hi, v))


def _prompt_metric(label: str, allowed: list[str], default: str) -> str:
    while True:
        v = input(f"  {label} ({'/'.join(allowed)}) [default={default}]: ").strip().upper()
        if not v:
            return default
        if v in allowed:
            return v
        print(f"  Invalid. Allowed: {allowed}")


def _collect_metrics(metric_defs) -> dict[str, str]:
    return {k: _prompt_metric(k, allowed, default) for k, allowed, default in metric_defs}


def _print_error(stage: str, e: BaseException) -> None:
    """Print a full traceback plus a one-line hint for common Windows quirks.

    The old `print(f'ERROR: {e}')` swallowed the traceback, which made
    intermittent crashes effectively un-diagnosable. Now the user always
    sees the real line that broke, plus a hint when we recognize the cause.
    """
    print(f"\nERROR during {stage}: {type(e).__name__}: {e}")
    if isinstance(e, PermissionError):
        print("  Hint: the output file is likely open in Excel. "
              "Close it (and any temporary ~$lock file) and re-run.")
    elif isinstance(e, FileNotFoundError):
        print("  Hint: check the path you entered exists "
              "(watch for stray quotes or trailing spaces).")
    print("\n--- Full traceback (paste this if asking for help) ---")
    traceback.print_exc()
    print("------------------------------------------------------")


def _prompt_custom_key_fields() -> list[str]:
    """Interactive picker for the manual-override match key.

    Shows numbered allowed fields, accepts comma-separated indices or names,
    returns the chosen list (preserving the user's order). Empty -> [].
    """
    print("\n  Available match-key fields (canonical names):")
    for i, f in enumerate(ALLOWED_CUSTOM_KEY_FIELDS, 1):
        print(f"    {i}) {f}")
    raw = input(
        "  Enter fields in match-priority order, comma-separated\n"
        "  (numbers OR names; e.g. '1,3,4' or 'plugin_id,ip,port'): "
    ).strip()
    if not raw:
        return []
    chosen: list[str] = []
    for chunk in raw.split(","):
        c = chunk.strip().lower()
        if not c:
            continue
        if c.isdigit():
            i = int(c)
            if 1 <= i <= len(ALLOWED_CUSTOM_KEY_FIELDS):
                f = ALLOWED_CUSTOM_KEY_FIELDS[i - 1]
                if f not in chosen:
                    chosen.append(f)
        elif c in ALLOWED_CUSTOM_KEY_FIELDS:
            if c not in chosen:
                chosen.append(c)
        else:
            print(f"  (ignoring unknown field '{chunk.strip()}')")
    return chosen


def _parse_exclude_indices(s: str) -> set[int]:
    out: set[int] = set()
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                a, b = chunk.split("-", 1)
                a, b = int(a), int(b)
                lo, hi = min(a, b), max(a, b)
                out.update(range(lo, hi + 1))
            except ValueError:
                continue
        else:
            try:
                out.add(int(chunk))
            except ValueError:
                continue
    return out


# -----------------------------------------------------------
# Option 1 / 2: Scan pipeline
# -----------------------------------------------------------
def cli_scan_pipeline(mode: str | None = None) -> None:
    """Interactive scan-pipeline runner.

    `mode` controls the workflow shape:
      "1" = complete/new VA scan, no prior-scan comparison
      "2" = retest workflow, subtract findings already present in the
            original engagement / risk-accepted file
      None = prompt the user (kept for back-compat with old callers /
             unit tests / anything that imports `cli_scan_pipeline`
             directly).
    The main-menu now passes "1" or "2" explicitly so the consultant
    sees a single coherent flow per option rather than a sub-prompt
    they have to navigate inside whichever option they picked.
    """
    if mode is None:
        # Standalone-invocation fallback: keep the legacy in-line
        # mode prompt so direct imports still work.
        print("=== Scan Pipeline (load CSVs -> subtract risk-accepted -> categorize) ===\n")
        print("Modes:")
        print("  1) Complete / new VA scan (no comparison against prior data)")
        print("  2) Retest VA scan (compare against original engagement findings)")
        mode = input("Choose 1/2 [default=2]: ").strip() or "2"
        if mode not in ("1", "2"):
            mode = "2"
    else:
        if mode == "1":
            print("=== Complete / new VA scan ===")
            print("Loads the current quarter's Nessus CSV(s), categorizes every")
            print("finding into individual per-category Excel sheets. No prior-scan")
            print("subtraction — every detected finding ships through to the output.\n")
        elif mode == "2":
            print("=== Retest VA scan ===")
            print("Compares the current Nessus CSV(s) against the ORIGINAL engagement's")
            print("findings (a risk-accepted file or prior tracker xlsx). Findings still")
            print("present in the retest stay open; findings that have disappeared land")
            print("in considered_not_removed.xlsx as candidates to close. Includes the")
            print("net-new IP diff and installed-vs-recommended version-check prompts.\n")
        else:
            mode = "2"

    current_folder = input(
        "\nFolder with current Nessus CSV(s) — OR a single .csv file path: "
    ).strip().strip('"')
    if not current_folder or not Path(current_folder).exists():
        print("ERROR: invalid current scans folder.")
        return

    prev_accepted_path = None
    riskaccept_sheet = None
    if mode == "2":
        p = input(
            "Path to PREVIOUS risk-accepted file OR FOLDER\n"
            "  (xlsx/xls/csv/pdf/docx; folder = scan all supported files in it): "
        ).strip().strip('"')
        if p and Path(p).exists():
            prev_accepted_path = Path(p)
            if prev_accepted_path.is_dir():
                # Folder mode — sheet selector is meaningless (each
                # xlsx inside loads ALL its sheets). Tell the user
                # what we found so a typo on the path isn't silent.
                from .loaders import _collect_riskaccept_files
                found = _collect_riskaccept_files(prev_accepted_path)
                print(f"  Folder mode: {len(found)} supported file(s) found:")
                for fp in found[:20]:
                    print(f"    - {fp.name}")
                if len(found) > 20:
                    print(f"    ... and {len(found) - 20} more")
                if not found:
                    print(
                        "  WARNING: no .xlsx/.xls/.csv/.pdf/.docx files in "
                        "that folder - skipping subtraction."
                    )
                    prev_accepted_path = None
            elif prev_accepted_path.suffix.lower() in (".xlsx", ".xls"):
                from .loaders import list_excel_sheets
                sheets = list_excel_sheets(prev_accepted_path)
                if len(sheets) > 1:
                    print("\nSheets in risk-accepted file:")
                    for i, s in enumerate(sheets, 1):
                        print(f"  {i}) {s}")
                    print("  0) Load ALL sheets (concatenate)")
                    si = _prompt_int("Choose sheet number [default=0=ALL]: ", default=0, lo=0, hi=len(sheets))
                    riskaccept_sheet = None if si == 0 else (si - 1)
            elif prev_accepted_path.suffix.lower() == ".pdf":
                print("  PDF mode: only blocks with 'risk accept' marker will be subtracted.")
                print("  Previously-closed findings in the PDF are ignored.")
            elif prev_accepted_path.suffix.lower() == ".docx":
                print("  DOCX mode: every table in the document will be parsed.")
        else:
            print("WARNING: previous risk-accepted file not provided or not found - skipping subtraction.")

    output_folder = input("\nOutput folder: ").strip().strip('"')
    if not output_folder:
        print("ERROR: output folder required.")
        return
    output_folder = Path(output_folder)

    # Persistent plugin-id map
    default_pid_map = output_folder.parent / "plugin_id_categories.json"
    pid_map_input = input(
        f"\nPlugin-ID category map JSON [default={default_pid_map}]: "
    ).strip().strip('"')
    pid_map_path = Path(pid_map_input) if pid_map_input else default_pid_map

    save_split = _yn(
        "Save per-category files into a 'by_category' subfolder? (y/n) [default=y]: ",
        default="y",
    )
    auto_learn = _yn(
        "Auto-learn confident category mappings into the JSON map? (y/n) [default=y]: ",
        default="y",
    )

    custom_comment_col = input(
        "\nName for an additional comments column in every output file\n"
        "  (e.g. 'VibeDocs Comments') or press Enter to skip: "
    ).strip()

    # Second source: scan last quarter's tracker for risk-accept phrases in
    # comment columns. Skipped by default — existing single-source flow
    # stays untouched.
    prev_tracker_path = None
    prev_tracker_sheet: int | str | None = 0
    risk_keywords_config = None
    if mode == "2":
        if _yn(
            "\nAlso subtract findings flagged as risk-accepted in last quarter's "
            "tracker comments? (y/n) [default=n]: ",
            default="n",
        ):
            tp = input(
                "  Path to LAST QUARTER tracker xlsx OR FOLDER\n"
                "    (folder = scan every .xlsx/.xls tracker in it): "
            ).strip().strip('"')
            if tp and Path(tp).exists():
                prev_tracker_path = Path(tp)
                if prev_tracker_path.is_dir():
                    # Folder mode — sheet 0 is applied per file; tell
                    # the user what we found and skip the sheet picker.
                    from .loaders import _collect_riskaccept_files
                    found = [
                        f for f in _collect_riskaccept_files(prev_tracker_path)
                        if f.suffix.lower() in (".xlsx", ".xls")
                    ]
                    print(f"  Folder mode: {len(found)} tracker file(s) found:")
                    for fp in found[:20]:
                        print(f"    - {fp.name}")
                    if len(found) > 20:
                        print(f"    ... and {len(found) - 20} more")
                    if not found:
                        print(
                            "  WARNING: no .xlsx/.xls trackers in that "
                            "folder - skipping second source."
                        )
                        prev_tracker_path = None
                    else:
                        # Per-file default: first sheet. Override is
                        # not offered in folder mode because workbooks
                        # often have different sheet layouts.
                        prev_tracker_sheet = 0
                else:
                    from .loaders import list_excel_sheets
                    tsheets = list_excel_sheets(prev_tracker_path)
                    if len(tsheets) > 1:
                        print("\n  Tracker sheets:")
                        for i, s in enumerate(tsheets, 1):
                            print(f"    {i}) {s}")
                        print(f"    0) ALL sheets")
                        si = _prompt_int(
                            "  Choose sheet number [default=1]: ",
                            default=1, lo=0, hi=len(tsheets),
                        )
                        prev_tracker_sheet = None if si == 0 else (si - 1)
                kw_path = input(
                    "  Keyword config JSON (Enter for built-in defaults): "
                ).strip().strip('"')
                if kw_path:
                    risk_keywords_config = Path(kw_path)
            else:
                print("  WARNING: tracker path not provided/found — skipping second source.")

    # Advanced: override the match key. Default is the 4-tier hierarchy
    # (plugin_id -> name fallback). Use this only when auto-mapping fails
    # or you want exact-tuple matching with no fallback.
    custom_key_fields: list[str] | None = None
    strict_output = True
    if mode == "2" and prev_accepted_path:
        if _yn("\nAdvanced: override the match key? (y/n) [default=n]: ", default="n"):
            custom_key_fields = _prompt_custom_key_fields()
            if custom_key_fields:
                print(f"  Custom match key: {custom_key_fields}")
                print("  (No fallback tiers — exact-tuple match only)")
            else:
                print("  No fields selected — using default hierarchy.")
        else:
            strict_output = _yn(
                "Use plugin_output as a disambiguator when both files have it?\n"
                "  (y = strict; drops rows whose plugin_output drifted between\n"
                "       the two scans down to no_match. Safer for QUARTERLY VAs\n"
                "       where drift signals a different finding.\n"
                "   n = lenient; keeps the match with an 'evidence_drift' quality\n"
                "       flag. RECOMMENDED FOR RETESTS because the retest workflow\n"
                "       EXPECTS plugin_output to change when a version is upgraded\n"
                "       between the original scan and the retest, and the\n"
                "       version-check step will catch and auto-close those rows.)\n"
                "  (y/n) [default=y]: ",
                default="y",
            )

    # ----- Retest IP-diff prompt (mode 2 only) -----
    # When the workflow is a retest, surface any net-new hosts in the
    # retest scan BEFORE the matcher runs. The consultant decides
    # whether to filter them out (so the tracker only contains hosts
    # the original engagement covered) or leave them in place.
    new_ip_action = "skip"
    if mode == "2" and prev_accepted_path:
        if _yn(
            "\nRetest mode: check for net-new IPs in the current scan that "
            "weren't in the original / risk-accept file? (y/n) [default=y]: ",
            default="y",
        ):
            try:
                from .loaders import load_nessus_folder, load_riskaccept_file
                from .ip_diff import find_new_ips, split_by_new_ips, summarize_new_ips
                _cur = load_nessus_folder(Path(current_folder))
                _acc = load_riskaccept_file(
                    Path(prev_accepted_path), sheet=riskaccept_sheet,
                )
                _new_ips = find_new_ips(_cur, _acc)
                if _new_ips:
                    _, _new_rows = split_by_new_ips(_cur, _new_ips)
                    for line in summarize_new_ips(_new_ips, _new_rows):
                        print("  " + line)
                    print(
                        "  These IPs are NOT in the original / risk-accept "
                        "file, so subtract would treat them as brand-new "
                        "findings."
                    )
                    if _yn(
                        "  Filter them out of the main flow AND write "
                        "new_hosts.xlsx for audit? (y/n) [default=y]: ",
                        default="y",
                    ):
                        new_ip_action = "filter_and_export"
                    elif _yn(
                        "  Keep them in the main flow but still write "
                        "new_hosts.xlsx for audit? (y/n) [default=n]: ",
                        default="n",
                    ):
                        new_ip_action = "export_only"
                else:
                    print("  No new IPs in the retest scan — every host "
                          "was already in the original.")
            except Exception as e:                          # pragma: no cover
                print(f"  WARNING: IP-diff preview failed ({e}); "
                      "skipping IP-diff step.")

    # Final prompt: optional row consolidation for the by_category files.
    # The client-facing per-category xlsx files can be collapsed so each
    # (finding_name, port) tuple becomes ONE row with all affected IPs
    # joined into the Host cell. Other files (remaining/removed/etc.)
    # stay row-per-host regardless. Default no, since the row-per-host
    # view is more useful internally for triage.
    group_ips_in_by_category = False
    if save_split:
        group_ips_in_by_category = _yn(
            "\nIn the by_category/*.xlsx files, group rows by finding name"
            " + port?\n"
            "  (y = combine same-finding-same-port rows into one row with"
            " comma-separated IPs.\n"
            "       Cleaner for client deliverables; loses per-host detail"
            " in those files.\n"
            "   n = keep one row per (host, port) — default, better for"
            " internal triage.)\n"
            "  (y/n) [default=n]: ",
            default="n",
        )

    print("\n>> Running pipeline...")
    print("   (Inputs are READ-ONLY. All outputs go to: "
          f"{output_folder})")
    try:
        result = run_scan_pipeline(
            current_folder=Path(current_folder),
            output_folder=output_folder,
            prev_accepted_path=prev_accepted_path,
            riskaccept_sheet=riskaccept_sheet,
            pid_map_path=pid_map_path,
            save_categorized_split=save_split,
            auto_learn_pid_map=auto_learn,
            custom_comment_col=custom_comment_col,
            custom_key_fields=custom_key_fields,
            strict_output=strict_output,
            prev_tracker_path=prev_tracker_path,
            prev_tracker_sheet=prev_tracker_sheet,
            risk_keywords_config=risk_keywords_config,
            new_ip_action=new_ip_action,
            group_ips_in_by_category=group_ips_in_by_category,
        )
    except Exception as e:
        _print_error("scan pipeline", e)
        return

    print("\n--- Pipeline Result ---")
    print(f"Loaded:            {result.total_current}")
    print(f"After subtract:    {result.total_after_subtract}")
    print(f"Risk-accepted removed: {result.n_removed_riskaccepted}")
    if result.n_from_management_file or result.n_from_tracker_comments:
        print(f"  from management file:  {result.n_from_management_file}")
        print(f"  from tracker comments: {result.n_from_tracker_comments}")
    if result.n_considered_not_removed:
        print(f"Considered but not removed: {result.n_considered_not_removed}")
        print(f"  -> see considered_not_removed.xlsx for manual review")
    if result.n_accepted_dropped_no_match:
        print(f"Accepted rows dropped (no near-miss on same host): "
              f"{result.n_accepted_dropped_no_match}")
        print(f"  -> host gone OR host scanned but finding no longer detected on it")
        print(f"  -> see audit count; not written to considered_not_removed.xlsx")
    if result.n_remaining_with_accepted_near_miss:
        print(f"\nAUDIT - remaining rows w/ same-host accepted near-miss: "
              f"{result.n_remaining_with_accepted_near_miss}")
        print(f"  -> see audit_remaining_vs_accepted.xlsx")
        print(f"  -> these rows weren't subtracted but a similar accepted entry "
              f"exists on the same host - likely column-mapping miss or name drift")
    if result.tracker_comment_diag:
        td = result.tracker_comment_diag
        print(f"\nTracker comment scan: {td.get('rows_matched', 0)} of "
              f"{td.get('rows_scanned', 0)} rows flagged")
        if td.get("keyword_hits"):
            for kw, n in sorted(td["keyword_hits"].items(), key=lambda x: -x[1]):
                print(f"  {kw!r}: {n}")
    if result.subtract_diag.get("tier_counts"):
        print("Match tiers (subtract):")
        for tier in TIER_ORDER:
            n = result.subtract_diag["tier_counts"].get(tier, 0)
            if n:
                print(f"  {tier:20s} {n}")
        ckf = result.subtract_diag.get("custom_key_fields") or []
        if ckf:
            print(f"  (custom key: {ckf})")
        qc = result.subtract_diag.get("quality_counts") or {}
        if qc:
            print("Evidence quality:")
            for q, n in sorted(qc.items(), key=lambda x: -x[1]):
                print(f"  {q:20s} {n}")
    print(f"\nNew pid->category mappings: {result.new_pid_mappings}")
    print("\nCategory counts:")
    for cat, n in sorted(result.category_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:35s} {n}")
    if result.load_warnings:
        print("\nWarnings:")
        for w in result.load_warnings:
            print(f"  - {w}")
    print(f"\nOutputs in: {result.output_folder}")

    # ----- Retest version-check (post-pipeline) -----
    # Only meaningful when subtract actually produced a "removed" set
    # the user can scan against. Skipped automatically for new-scan
    # (mode 1) or when nothing matched in the original.
    if mode == "2" and result.n_removed_riskaccepted > 0:
        _maybe_run_version_check(Path(result.output_folder), result)

    # Optional CVSS reassessment after categorization
    if _yn("\nRun bulk CVSS reassessment on the categorized output? (y/n) [default=n]: ", default="n"):
        cli_cvss_reassess(default_input=Path(result.output_folder) / "categorized_findings.xlsx")


# -----------------------------------------------------------
# Post-pipeline: version-check (installed >= recommended fix)
# -----------------------------------------------------------
def _maybe_run_version_check(output_folder: Path, result) -> None:
    """Offer to scan the just-written `risk_accepted_removed.xlsx` for
    rows where the installed version meets-or-exceeds the recommended
    fix. Confirmed closures flip Status to "Closed" and write the
    consultant's justification into a user-chosen column.

    Self-contained — no-op if the user declines or if no candidates
    are detected. Errors are logged but never crash the run, since
    the rest of the output is already on disk by the time we get here.
    """
    if not _yn(
        "\nRetest mode: scan the matched (still-open) findings for rows "
        "whose installed version is >= the recommended fix? (y/n) "
        "[default=y]: ",
        default="y",
    ):
        return
    removed_path = output_folder / "risk_accepted_removed.xlsx"
    if not removed_path.exists():
        print(f"  WARNING: {removed_path} not found; skipping version check.")
        return
    try:
        from .pipelines import (
            analyze_version_check_candidates, apply_version_check_closures,
        )
    except Exception as e:                                  # pragma: no cover
        print(f"  WARNING: version-check helpers unavailable ({e}); skipping.")
        return
    try:
        annotated = analyze_version_check_candidates(removed_path)
    except Exception as e:                                  # pragma: no cover
        print(f"  WARNING: version-check analysis failed ({e}); skipping.")
        return

    remediated = annotated[annotated["version_check_status"] == "remediated"]
    uncertain  = annotated[annotated["version_check_status"] == "uncertain"]
    result.n_version_check_remediated = len(remediated)
    result.n_version_check_uncertain = len(uncertain)

    if len(remediated) == 0:
        print("  No 'installed >= recommended' rows confidently detected.")
        if len(uncertain):
            print(f"  ({len(uncertain)} row(s) had ambiguous version data — "
                  "review manually if needed.)")
        return

    # Show the candidate list. Print at most 30 rows so a huge result
    # set doesn't blow the terminal — the consultant can open the
    # xlsx for the full picture.
    print(f"\n  {len(remediated)} candidate(s) where installed version "
          "appears to meet or exceed the recommended fix:")
    for i, (_, row) in enumerate(remediated.iterrows(), start=1):
        if i > 30:
            print(f"    ... and {len(remediated) - 30} more (see "
                  "risk_accepted_removed.xlsx for full list)")
            break
        host = row.get("Host", "")
        port = row.get("Port", "")
        name = row.get("Finding Name", "")
        inst = row.get("installed_version", "")
        rec  = row.get("recommended_version", "")
        print(f"    [{i:3d}] {host:<18s} {port:<6s} {name!s:<60s} "
              f"installed={inst!s:<12s} >= recommended={rec}")
    if len(uncertain):
        print(f"\n  ({len(uncertain)} additional row(s) had ambiguous "
              "version data — kept as-is for manual review.)")

    if not _yn(
        "\n  Mark these candidates as Closed in risk_accepted_removed.xlsx? "
        "(y/n) [default=n]: ", default="n",
    ):
        print("  Leaving as-is.")
        return

    # Per-run prompts for column name + justification text. No defaults
    # so the consultant types the wording fresh every engagement (matches
    # the user's preference).
    col_name = input(
        "  Column to receive the closure justification\n"
        "    (will be created if missing; e.g. 'VibeDocs Comments'): "
    ).strip()
    text = input(
        "  Justification text to write into that column: "
    ).strip()

    # The row indices we hand to `apply_version_check_closures` MUST be
    # zero-based file indices, matching what `pd.read_excel` returns.
    # `annotated` already comes from a fresh read of the same file, so
    # its index is the file row order — pass it directly.
    indices = remediated.index.tolist()
    try:
        result_diag = apply_version_check_closures(
            removed_xlsx_path=removed_path,
            row_indices_to_close=indices,
            justification_column=col_name,
            justification_text=text,
        )
    except Exception as e:                                  # pragma: no cover
        print(f"  WARNING: closure failed ({e}); file left untouched.")
        return
    result.n_version_check_closed = int(result_diag.get("closed", 0))
    print(f"\n  Closed {result_diag['closed']} row(s). "
          f"Audit file: {result_diag.get('audit_file', '(none)')}")


# -----------------------------------------------------------
# Option 2: Tracker update (image-safe, Windows only)
# -----------------------------------------------------------
def cli_tracker_update() -> None:
    print("=== Tracker Update (mark missing findings as Closed, image-safe) ===\n")

    if not com_available():
        print("ERROR: Excel COM not available. Tracker update requires Windows + pywin32.")
        print("       Install pywin32: pip install pywin32")
        return

    tracker_path = input("Path to OLD tracker xlsx (previous quarter): ").strip().strip('"')
    new_scan_path = input("Path to NEW scan file (xlsx/xls/csv): ").strip().strip('"')

    if not tracker_path or not Path(tracker_path).exists():
        print("ERROR: tracker not found.")
        return
    if not new_scan_path or not Path(new_scan_path).exists():
        print("ERROR: new scan not found.")
        return

    # New-scan sheet selection (if Excel with multiple sheets)
    from .loaders import list_excel_sheets
    new_scan_sheet: int | str = 0
    if Path(new_scan_path).suffix.lower() in (".xlsx", ".xls"):
        sheets = list_excel_sheets(Path(new_scan_path))
        if len(sheets) > 1:
            print("\nNEW scan sheets:")
            for i, s in enumerate(sheets, 1):
                print(f"  {i}) {s}")
            si = _prompt_int("Choose NEW scan sheet [default=1]: ", default=1, hi=len(sheets))
            new_scan_sheet = si - 1

    # Tracker sheet selection happens inside analyze_for_tracker_update on sheet 1,
    # but we may need to redo if multi-sheet. Quick path: read sheet list first.
    # We'll use the analyze function and then re-call if user picks a different tracker sheet.
    print("\n>> Reading files and building new-scan index...")
    try:
        analysis, idx = analyze_for_tracker_update(
            tracker_path=Path(tracker_path),
            new_scan_path=Path(new_scan_path),
            tracker_sheet_index=1,
            new_scan_sheet=new_scan_sheet,
        )
    except Exception as e:
        _print_error("tracker analysis", e)
        return

    # If tracker has multiple sheets, let user pick
    if len(analysis.tracker_sheet_names) > 1:
        print("\nTracker sheets:")
        for i, s in enumerate(analysis.tracker_sheet_names, 1):
            print(f"  {i}) {s}")
        tsi = _prompt_int("Choose tracker sheet [default=1]: ",
                          default=1, hi=len(analysis.tracker_sheet_names))
        if tsi != 1:
            try:
                analysis, idx = analyze_for_tracker_update(
                    tracker_path=Path(tracker_path),
                    new_scan_path=Path(new_scan_path),
                    tracker_sheet_index=tsi,
                    new_scan_sheet=new_scan_sheet,
                )
            except Exception as e:
                _print_error(f"tracker re-analysis (sheet {tsi})", e)
                return
        else:
            tsi = 1
    else:
        tsi = 1

    print("\nNew-scan index summary:")
    for k, v in analysis.new_scan_index_summary.items():
        if isinstance(v, float):
            print(f"  {k:25s} {v:.1f}")
        else:
            print(f"  {k:25s} {v}")

    print(f"\nNew scan has Plugin ID column: {analysis.new_scan_has_plugin_id}")
    if not analysis.new_scan_has_plugin_id:
        print("  WARNING: matching will use finding-name fallback - less reliable.")

    print("\nTracker columns (preview):")
    print(", ".join(analysis.tracker_columns_preview))

    # Pre-flight: a real tracker MUST have a Status (or State) column. If it
    # doesn't, the user almost certainly picked the wrong file (a raw Nessus
    # scan CSV is a common mistake — it has Plugin ID/Name/Host/etc. but no
    # Status). Fail fast here instead of after 6 more prompts and a dry-run.
    if not analysis.tracker_has_status:
        print("\n" + "!" * 70)
        print("! WARNING: this tracker has NO 'Status' or 'State' column.")
        print("! Raw Nessus scan exports look like this. A real quarterly tracker")
        print("! always has a Status column you've been marking Open/Closed in.")
        print("! Did you pick the wrong file? (e.g. the new scan instead of the")
        print("! previous-quarter tracker xlsx)")
        print("!" * 70)
        if not _yn("Continue anyway and type a Status column name yourself? "
                   "(y/n) [default=n]: ", default="n"):
            print("Aborted. Re-run with the correct tracker file.")
            return

    # Column-map confirmation
    print("\nAuto-suggested column mapping (press Enter to accept each):")
    sug = analysis.suggested_column_map
    name_col = input(f"  finding_name [default={sug.get('finding_name','')}]: ").strip() or sug.get("finding_name", "")
    host_col = input(f"  ip/host     [default={sug.get('ip','')}]: ").strip() or sug.get("ip", "")
    status_col = input(f"  status      [default=Status]: ").strip() or "Status"
    pid_col_default = sug.get("plugin_id", "")
    pid_col = input(f"  plugin_id   [default={pid_col_default or '(none)'}]: ").strip() or pid_col_default
    port_col_default = sug.get("port", "")
    port_col = input(f"  port        [default={port_col_default or '(none)'}]: ").strip() or port_col_default

    column_map = {
        "finding_name": name_col,
        "ip": host_col,
        "status": status_col,
    }
    if pid_col:
        column_map["plugin_id"] = pid_col
    if port_col:
        column_map["port"] = port_col

    print(f"\nPort-embed detection in tracker host column: "
          f"{analysis.port_embed_ratio_in_tracker_host:.1%}")
    if analysis.recommended_port_mode == 1:
        print("  Recommendation: tracker DOES embed ports in host (e.g. '10.0.0.1 (443)').")
        print("  The library extracts those automatically.")

    only_open = _yn("Only process rows where Status=='Open'? (y/n) [default=y]: ", default="y")
    mark_closed = _yn("Mark NOT-found rows as Closed? (y/n) [default=y]: ", default="y")

    fill_comment = _yn("Fill a comments column for closed rows? (y/n) [default=y]: ", default="y")
    comment_col = ""
    comment_text = ""
    if fill_comment:
        comment_col = input("  Comment column header (e.g. 'VibeDocs Comments'): ").strip()
        comment_text = input("  Text to fill for closed rows: ").strip()

    # Dry run first
    print("\n>> Running DRY-RUN first (no save)...")
    try:
        diag = apply_tracker_update(
            tracker_path=Path(tracker_path),
            sheet_index=tsi,
            column_map=column_map,
            new_scan_index=idx,
            only_open=only_open,
            mark_closed=mark_closed,
            comment_col=comment_col or None,
            comment_text=comment_text,
            dry_run=True,
        )
    except Exception as e:
        _print_error("tracker dry-run", e)
        return

    print("\n--- Dry-run results ---")
    print(f"Rows checked:     {diag['rows_checked']}")
    print(f"Rows considered:  {diag['rows_considered']}")
    print(f"Rows matched:     {diag['rows_matched']}")
    print(f"Rows remediated:  {diag['rows_remediated']}")
    print("Match tiers:")
    for tier in TIER_ORDER:
        n = diag["tier_counts"].get(tier, 0)
        if n:
            print(f"  {tier:20s} {n}")
    if diag["unmatched_samples"]:
        print("\nFirst 10 unmatched (would be Closed):")
        for nm, hst, prt, pid in diag["unmatched_samples"]:
            print(f"  Name='{nm[:60]}' | Host='{hst}' | Port='{prt}' | PID='{pid}'")

    considered = diag["rows_considered"] or 1
    match_rate = diag["rows_matched"] / considered
    print(f"\nOverall match rate: {match_rate:.1%}")
    if match_rate < 0.20:
        print("WARNING: match rate <20%. Likely wrong sheet or wrong column mapping.")
        if not _yn("Proceed to actually update the tracker anyway? (y/n) [default=n]: ", default="n"):
            print("Aborted.")
            return
    else:
        if not _yn("\nProceed to actually update the tracker? (y/n) [default=y]: ", default="y"):
            print("Aborted.")
            return

    # Save options
    in_place = _yn("Save in-place (overwrite original)? (y/n) [default=n]: ", default="n")
    out_path = None
    if not in_place:
        base = Path(tracker_path)
        out_path = base.with_name(
            f"{base.stem}__updated_{datetime.now():%Y%m%d_%H%M%S}{base.suffix}"
        )

    try:
        diag = apply_tracker_update(
            tracker_path=Path(tracker_path),
            sheet_index=tsi,
            column_map=column_map,
            new_scan_index=idx,
            only_open=only_open,
            mark_closed=mark_closed,
            comment_col=comment_col or None,
            comment_text=comment_text,
            output_path=out_path,
            dry_run=False,
        )
    except Exception as e:
        _print_error("tracker update", e)
        return

    print("\n--- Update complete ---")
    print(f"Rows marked Closed: {diag['rows_marked_closed']}")
    print(f"Saved to: {diag['output_file']}")


# -----------------------------------------------------------
# Option 3: Bulk CVSS reassessment on an existing file
# -----------------------------------------------------------
def cli_cvss_reassess(default_input: Path | None = None) -> None:
    print("=== Bulk CVSS reassessment ===\n")
    p = input(f"Path to xlsx to update [default={default_input or ''}]: ").strip().strip('"') or (
        str(default_input) if default_input else ""
    )
    if not p or not Path(p).exists():
        print("ERROR: input file not found.")
        return

    print("\nVersion:")
    print("  1) CVSS 3.1")
    print("  2) CVSS 4.0")
    vchoice = input("Choose [default=1]: ").strip() or "1"
    version = "4.0" if vchoice == "2" else "3.1"

    if version == "3.1" and not HAS_CVSS3:
        print("ERROR: python-cvss not installed. pip install cvss")
        return
    if version == "4.0" and not HAS_CVSS4:
        print("ERROR: CVSS 4.0 not available in installed python-cvss. Upgrade: pip install -U cvss")
        return

    df = pd.read_excel(p, dtype=str).fillna("")
    if "finding_name" not in df.columns:
        # legacy column name
        if "Name" in df.columns:
            df = df.rename(columns={"Name": "finding_name"})
        else:
            print("ERROR: input must have a finding_name (or Name) column.")
            return
    if "plugin_id" not in df.columns:
        df["plugin_id"] = ""
    if "risk" not in df.columns and "Risk" in df.columns:
        df = df.rename(columns={"Risk": "risk"})

    # Show unique findings
    df["finding_name"] = df["finding_name"].astype(str).str.strip()
    uniq = df["finding_name"].replace("", pd.NA).dropna().drop_duplicates().tolist()
    if not uniq:
        print("No unique findings to reassess.")
        return

    print("\nUnique findings:")
    for i, nm in enumerate(uniq, 1):
        print(f"  {i}. {nm}")

    exclude = _parse_exclude_indices(
        input("\nNumbers to EXCLUDE (e.g. 1,3,5-10) or Enter for none: ")
    )
    included = [uniq[i-1] for i in range(1, len(uniq)+1) if i not in exclude]
    if not included:
        print("No findings selected.")
        return

    # Group into one vector per pass
    while True:
        print(f"\nApply ONE vector to {len(included)} findings.")
        metrics_def = CVSS31_METRICS if version == "3.1" else CVSS40_METRICS
        metrics = _collect_metrics(metrics_def)
        vector = build_cvss31_vector(metrics) if version == "3.1" else build_cvss40_vector(metrics)
        try:
            score, sev = score_vector(vector, version)
        except Exception as e:
            print(f"ERROR: {e}")
            continue
        print(f"\n  Vector: {vector}")
        print(f"  Base score: {score:.1f}  ->  {sev}")

        if not _yn("Apply this vector to selected findings? (y/n) [default=y]: ", default="y"):
            continue

        df, n = apply_vector_to_rows(
            df, vector, version,
            target_finding_names=set(included),
        )
        print(f"Updated {n} rows.")

        if not _yn("Reassess another subset with a different vector? (y/n) [default=n]: ", default="n"):
            break
        # Pick a new subset
        print("\nUnique findings remaining:")
        for i, nm in enumerate(uniq, 1):
            print(f"  {i}. {nm}")
        excl = _parse_exclude_indices(
            input("Numbers to EXCLUDE this round: ")
        )
        included = [uniq[i-1] for i in range(1, len(uniq)+1) if i not in excl]

    out = Path(p).with_name(
        f"{Path(p).stem}__cvss{version.replace('.', '')}_{datetime.now():%Y%m%d_%H%M%S}.xlsx"
    )
    df.to_excel(out, index=False)
    print(f"\nWrote: {out}")


# -----------------------------------------------------------
# Main menu
# -----------------------------------------------------------
def main() -> None:
    print(ASCII_ART.format(ver=__version__))
    print("\nSelect an option:")
    print("  1) Complete / new VA scan")
    print("       Load the current quarter's Nessus CSV(s), categorize every")
    print("       finding, and write per-category Excel sheets. No comparison")
    print("       against any prior scan.")
    print()
    print("  2) Retest VA scan")
    print("       Compare the current Nessus CSV(s) against an ORIGINAL engagement")
    print("       (risk-accepted file or prior tracker xlsx). Identifies findings")
    print("       no longer present (candidates to close), still-open findings,")
    print("       net-new hosts, and rows where the installed version already")
    print("       meets the recommended fix. Outputs per-category Excel sheets.")
    print()
    print("  3) Bulk CVSS reassessment")
    print("       Re-score an existing output file with CVSS 3.1 or 4.0 in bulk.")
    print()
    # Tracker-update (image-safe Excel COM workflow) is still exposed
    # for the few users who need it but isn't promoted in the main menu
    # anymore — option 2 covers the same close-missing-findings use
    # case for most consultants. Type "4" or "tracker" to invoke it.
    print("  (advanced) 4 / tracker  -> image-safe Excel tracker update (Windows + pywin32)")
    print()
    choice = input("Enter 1/2/3 [default=2]: ").strip().lower() or "2"

    if choice == "1":
        cli_scan_pipeline(mode="1")
    elif choice == "2":
        cli_scan_pipeline(mode="2")
    elif choice == "3":
        cli_cvss_reassess()
    elif choice in ("4", "tracker", "t"):
        cli_tracker_update()
    else:
        print(f"Unrecognised choice {choice!r}; defaulting to retest scan.")
        cli_scan_pipeline(mode="2")
