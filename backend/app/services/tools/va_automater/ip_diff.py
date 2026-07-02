"""Retest-mode IP diff.

When the workflow is a retest of a prior scan (option 2 in the CLI),
the "previous" file holds the original engagement's findings and the
"current" file is the follow-up retest. Before any matching runs, we
walk the unique IPs on both sides and flag any address that appears
ONLY in the retest. Those are net-new hosts (often a different
production segment, an expansion, or a different scan target) that
weren't part of the original engagement.

The consultant decides what to do with them:
  - generate a side-file (`new_hosts.xlsx`) listing every retest row
    on a net-new IP, AND
  - filter those rows out of the main flow so the
    risk-accepted-subtract step doesn't try to match them against
    the original.

Net-new hosts are NOT the same as missing-from-retest hosts — those
fall out naturally via `find_accepted_not_matched()` in the existing
pipeline, since an original-side row with no retest counterpart ends
up in `considered_not_removed.xlsx`.
"""
from __future__ import annotations
import pandas as pd

from .identifiers import normalize_ip


def find_new_ips(retest: pd.DataFrame, original: pd.DataFrame) -> set[str]:
    """Return the set of IPs present in `retest` but NOT in `original`.

    Both DataFrames are expected to be canonical schema (already
    multi-IP-expanded by the loader). IP comparison is byte-equal after
    `normalize_ip` (lowercased, stripped) so trailing whitespace doesn't
    cause spurious "new IP" reports.

    Empty IP cells are dropped from both sides — they can't be diffed
    meaningfully.
    """
    if retest is None or len(retest) == 0:
        return set()
    if original is None or len(original) == 0:
        # Edge case: no original data at all -> EVERY retest IP is "new".
        # We still return them so the CLI can surface this for the user
        # to sanity-check the original path before running.
        return {ip for ip in retest["ip"].map(normalize_ip).unique() if ip}

    retest_ips = {ip for ip in retest["ip"].map(normalize_ip).unique() if ip}
    original_ips = {ip for ip in original["ip"].map(normalize_ip).unique() if ip}
    return retest_ips - original_ips


def split_by_new_ips(
    retest: pd.DataFrame, new_ips: set[str],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split `retest` into (kept, new_host_rows) based on `new_ips`.

    `kept` is the subset whose IP is NOT in `new_ips` — the rows the
    main pipeline should process. `new_host_rows` is the subset on the
    net-new addresses, written out as `new_hosts.xlsx` for the
    consultant's audit trail. Both DataFrames preserve their input
    column order; indices are reset.
    """
    if retest is None or len(retest) == 0 or not new_ips:
        empty = retest.iloc[0:0].copy() if retest is not None else pd.DataFrame()
        return (retest.copy() if retest is not None else pd.DataFrame()), empty
    mask = retest["ip"].map(normalize_ip).isin(new_ips)
    new_rows = retest[mask].reset_index(drop=True)
    kept = retest[~mask].reset_index(drop=True)
    return kept, new_rows


def summarize_new_ips(
    new_ips: set[str], new_host_rows: pd.DataFrame, max_ips: int = 20,
) -> list[str]:
    """Build a short human-readable preview the CLI can print so the
    consultant can sanity-check the diff before deciding what to do.

    Returns a list of pre-formatted lines, e.g.::

        Found 3 new IPs in the retest scan that weren't in the original:
          - 10.0.0.50         (12 finding rows)
          - 10.0.0.51         (4 finding rows)
          - 10.0.0.52         (1 finding row)
    """
    if not new_ips:
        return ["No new IPs detected — every retest host was in the original scan."]
    lines: list[str] = [
        f"Found {len(new_ips)} new IP{'s' if len(new_ips) != 1 else ''} "
        f"in the retest scan that weren't in the original "
        f"({len(new_host_rows)} affected finding row"
        f"{'s' if len(new_host_rows) != 1 else ''}):"
    ]
    by_ip = new_host_rows.groupby(new_host_rows["ip"].map(normalize_ip)).size()
    shown = 0
    for ip, n in by_ip.sort_values(ascending=False).items():
        if shown >= max_ips:
            lines.append(f"  ... and {len(by_ip) - shown} more")
            break
        plural = "rows" if n != 1 else "row"
        lines.append(f"  - {ip:<18s} ({n} finding {plural})")
        shown += 1
    return lines
