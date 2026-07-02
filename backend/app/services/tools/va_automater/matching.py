"""Hierarchical finding matching.

NewScanIndex builds lookup sets from the current quarter's scan. A row from
an old tracker or risk-accept file is matched at the highest applicable
tier:
  TIER_STRICT_PID      - (plugin_id, ip, port) - gold standard
  TIER_SOFT_PORT_PID   - (plugin_id, ip), port present on exactly one side
                         (e.g. tracker has port 443, new scan is host-level)
  TIER_MEDIUM_PID      - (plugin_id, ip) - both have ports but they differ
  TIER_OUTPUT_IP_PORT  - (plugin_output_hash, ip, port) - used when Plugin
                         ID is missing on at least one side. Plugin output
                         is what Tenable literally observed in the target's
                         response and is far more stable across quarters
                         than the finding-name string, so prefer it over
                         name-based tiers when available.
  TIER_OUTPUT_IP       - (plugin_output_hash, ip) - port info missing on
                         one side but output evidence agrees.
  TIER_STRICT_NAME     - (name_norm, ip, port) - no plugin_id, no useful
                         plugin_output
  TIER_LOOSE_NAME      - (name_norm, ip) - last resort
  TIER_CUSTOM          - matched against a user-supplied custom key
                         (manual-override mode; bypasses the hierarchy)

Plugin ID is THE stable identifier across Tenable plugin revisions; finding
name strings drift over time, so name-based matching is treated as fallback.
Plugin output sits between them: more stable than name (consultants don't
edit it; Tenable updates it less frequently than the plugin title) but
absent when the previous quarter's tracker chose not to capture it.

When plugin_output is available on both sides AND strict_output=True is
passed to .match(), a normalized output-hash is used to disambiguate
duplicate (plugin_id, ip, port) rows AT THE strict_pid tier. Evidence drift
on a strict_pid key causes the row to fall through to lower tiers rather
than match. This is separate from the OUTPUT_IP_PORT / OUTPUT_IP primary
match tiers above — those fire when the pid block produced no match at all.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import pandas as pd

from .identifiers import (
    normalize_name, normalize_ip, normalize_plugin_id, safe_port,
    plugin_output_hash,
)

TIER_STRICT_PID     = "strict_pid"
TIER_SOFT_PORT_PID  = "soft_port_pid"
TIER_MEDIUM_PID     = "medium_pid"
TIER_OUTPUT_IP_PORT = "output_ip_port"
TIER_OUTPUT_IP      = "output_ip"
TIER_STRICT_NAME    = "strict_name"
TIER_LOOSE_NAME     = "loose_name"
TIER_CUSTOM         = "custom"
TIER_NO_MATCH       = "no_match"

# Tiers in reliability order (most -> least). Used for sorting diagnostics.
TIER_ORDER = [
    TIER_STRICT_PID,
    TIER_SOFT_PORT_PID,
    TIER_MEDIUM_PID,
    TIER_OUTPUT_IP_PORT,
    TIER_OUTPUT_IP,
    TIER_STRICT_NAME,
    TIER_LOOSE_NAME,
    TIER_CUSTOM,
    TIER_NO_MATCH,
]

# Quality annotations returned alongside the tier (for diagnostics; never
# changes which rows are subtracted/closed unless strict_output is set).
QUALITY_EXACT_EVIDENCE = "exact_evidence"   # plugin_output hash matched
QUALITY_EVIDENCE_DRIFT = "evidence_drift"   # key matched but output_hash didn't
QUALITY_NO_EVIDENCE    = "no_evidence"      # one side lacked plugin_output
QUALITY_NA             = ""                 # tier doesn't use evidence


# Fields that can appear in a user-supplied custom match key.
ALLOWED_CUSTOM_KEY_FIELDS = [
    "plugin_id", "finding_name", "ip", "port",
    "protocol", "plugin_output", "plugin_family",
]


def _normalize_field(name: str, value) -> str:
    """Field-aware normalization used by custom-key matching."""
    if value is None:
        return ""
    if name == "plugin_id":
        return normalize_plugin_id(value)
    if name == "finding_name":
        return normalize_name(value)
    if name == "ip":
        return normalize_ip(value)
    if name == "port":
        return safe_port(value)
    if name == "plugin_output":
        return plugin_output_hash(value)
    return str(value).strip().lower()


@dataclass
class NewScanIndex:
    """Lookup indices built once from a new-quarter scan.

    Use .match() for the hierarchical default; .match_custom() for the
    advanced manual-override mode. Use .summary() for diagnostics.
    """
    by_pid_ip_port: set = field(default_factory=set)
    by_pid_ip: set = field(default_factory=set)
    by_name_ip_port: set = field(default_factory=set)
    by_name_ip: set = field(default_factory=set)
    # plugin_output hashes keyed by (pid, ip, port) - empty hashes excluded.
    # Used for evidence-drift disambiguation when strict_output=True.
    output_hashes_by_key: dict = field(default_factory=dict)
    # Primary plugin-output match tiers. These fire when the pid block
    # produced no match (typically because plugin_id is missing on one
    # side - common in manually-maintained risk-accept spreadsheets).
    # Plugin output reflects what Tenable literally observed, so it's a
    # stronger key than the finding-name string which Tenable revises
    # between plugin releases.
    by_output_ip_port: set = field(default_factory=set)
    by_output_ip: set = field(default_factory=set)
    # All ports observed for a (pid, ip), to distinguish "port missing on one
    # side" (soft_port) from "both sides have ports, different value" (medium).
    ports_for_pid_ip: dict = field(default_factory=dict)
    # Custom-key mode (manual override).
    custom_key_fields: list = field(default_factory=list)
    custom_index: set = field(default_factory=set)
    n_rows: int = 0
    n_with_pid: int = 0
    n_with_output_hash: int = 0

    @classmethod
    def build(
        cls,
        df: pd.DataFrame,
        custom_key_fields: list[str] | None = None,
    ) -> "NewScanIndex":
        idx = cls()
        idx.n_rows = len(df)
        if custom_key_fields:
            invalid = [f for f in custom_key_fields if f not in ALLOWED_CUSTOM_KEY_FIELDS]
            if invalid:
                raise ValueError(
                    f"Unsupported custom-key field(s): {invalid}. "
                    f"Allowed: {ALLOWED_CUSTOM_KEY_FIELDS}"
                )
            idx.custom_key_fields = list(custom_key_fields)

        for _, r in df.iterrows():
            pid = normalize_plugin_id(r.get("plugin_id", ""))
            name = normalize_name(r.get("finding_name", ""))
            ip = normalize_ip(r.get("ip", ""))
            port = safe_port(r.get("port", ""))
            out_hash = plugin_output_hash(r.get("plugin_output", ""))

            if not ip:
                # Without IP we can't match anything; custom-key mode is the
                # only path that might still work, handled below.
                pass
            else:
                if pid:
                    idx.n_with_pid += 1
                    idx.by_pid_ip_port.add((pid, ip, port))
                    idx.by_pid_ip.add((pid, ip))
                    idx.ports_for_pid_ip.setdefault((pid, ip), set()).add(port)
                    if out_hash:
                        idx.output_hashes_by_key.setdefault(
                            (pid, ip, port), set()
                        ).add(out_hash)
                # Plugin-output primary-match index. Populated regardless
                # of whether pid is present, so the OUTPUT tiers can fire
                # when EITHER the accepted file OR the current scan is
                # missing Plugin ID for this row. Without this, the
                # matcher silently falls through to name-based tiers,
                # which fail on findings whose name string has drifted
                # between quarters.
                if out_hash:
                    idx.n_with_output_hash += 1
                    idx.by_output_ip_port.add((out_hash, ip, port))
                    idx.by_output_ip.add((out_hash, ip))
                if name:
                    idx.by_name_ip_port.add((name, ip, port))
                    idx.by_name_ip.add((name, ip))

            if idx.custom_key_fields:
                key = tuple(
                    _normalize_field(f, r.get(f, ""))
                    for f in idx.custom_key_fields
                )
                if all(k != "" for k in key):
                    idx.custom_index.add(key)

        return idx

    def match(
        self,
        plugin_id,
        finding_name,
        ip,
        port,
        plugin_output: str = "",
        strict_output: bool = False,
    ) -> str:
        """Hierarchical match. Returns the highest-applicable tier name.

        plugin_output / strict_output are optional and back-compat: existing
        callers (tracker_writer) that omit them get the v0.2 behavior.
        """
        tier, _ = self.match_detailed(
            plugin_id, finding_name, ip, port,
            plugin_output=plugin_output, strict_output=strict_output,
        )
        return tier

    def match_detailed(
        self,
        plugin_id,
        finding_name,
        ip,
        port,
        plugin_output: str = "",
        strict_output: bool = False,
    ) -> tuple[str, str]:
        """Same as .match() but also returns an evidence-quality annotation.

        Returns (tier, quality). quality is one of QUALITY_* constants.
        """
        pid = normalize_plugin_id(plugin_id)
        name = normalize_name(finding_name)
        ipn = normalize_ip(ip)
        pn = safe_port(port)
        q_hash = plugin_output_hash(plugin_output)

        if not ipn:
            return TIER_NO_MATCH, QUALITY_NA

        drift_detected = False
        if pid:
            if (pid, ipn, pn) in self.by_pid_ip_port:
                stored = self.output_hashes_by_key.get((pid, ipn, pn), set())
                if stored and q_hash:
                    if q_hash in stored:
                        return TIER_STRICT_PID, QUALITY_EXACT_EVIDENCE
                    # Same (pid, ip, port) but different evidence string.
                    if strict_output:
                        drift_detected = True
                    else:
                        return TIER_STRICT_PID, QUALITY_EVIDENCE_DRIFT
                else:
                    return TIER_STRICT_PID, QUALITY_NO_EVIDENCE

            if (pid, ipn) in self.by_pid_ip:
                ports = self.ports_for_pid_ip.get((pid, ipn), set())
                if drift_detected:
                    # Don't let the drifted port itself underwrite a
                    # medium/soft fallback — that would silently re-match
                    # the same evidence we just rejected.
                    ports = ports - {pn}
                if ports:
                    # Soft-port: port info missing on exactly one side.
                    if pn == "" and (ports - {""}):
                        return TIER_SOFT_PORT_PID, QUALITY_NA
                    if pn != "" and "" in ports:
                        return TIER_SOFT_PORT_PID, QUALITY_NA
                    return TIER_MEDIUM_PID, QUALITY_NA

            if drift_detected:
                # Drift with no other pid-based support. Name-based fallback
                # would re-match the SAME logical finding under a weaker key,
                # defeating strict_output. Drop to no_match.
                return TIER_NO_MATCH, QUALITY_NA

        # Plugin-output primary tier. Fires when:
        #   - this row has a non-empty plugin_output, AND
        #   - the pid block above didn't already return a match (because
        #     pid was missing on this row, OR the pid block found nothing
        #     in current).
        # This is what catches the "tracker doesn't have a Plugin ID
        # column, only Plugin Output" case described by the user — the
        # output column ships verbatim from the previous quarter's
        # scan, so its hash is identical to the current scan's hash for
        # the same finding.
        if q_hash:
            if (q_hash, ipn, pn) in self.by_output_ip_port:
                return TIER_OUTPUT_IP_PORT, QUALITY_EXACT_EVIDENCE
            if (q_hash, ipn) in self.by_output_ip:
                return TIER_OUTPUT_IP, QUALITY_EXACT_EVIDENCE

        if name:
            if (name, ipn, pn) in self.by_name_ip_port:
                return TIER_STRICT_NAME, QUALITY_NA
            # TIER_LOOSE_NAME: only fire when the normalised name is long
            # enough to be meaningful. normalize_name() strips every
            # non-alphanumeric character, so short acronyms like "SMB",
            # "SSL", "FTP" (3-7 chars) could produce false positives when
            # matched purely on (name_norm, ip). Requiring ≥ 8 characters
            # ensures we only loose-match names that contain at least a
            # noun + one more descriptive word (e.g. "smbsigning" = 10,
            # "icmptimestamp" = 13, "ipforwarding" = 12).
            if (name, ipn) in self.by_name_ip and len(name) >= 8:
                return TIER_LOOSE_NAME, QUALITY_NA

        return TIER_NO_MATCH, QUALITY_NA

    def match_custom(self, row: dict | pd.Series) -> str:
        """Match against the user-supplied custom key.

        Returns TIER_CUSTOM on hit, TIER_NO_MATCH otherwise. Requires
        the index to have been built with custom_key_fields set.
        """
        if not self.custom_key_fields:
            return TIER_NO_MATCH
        key = tuple(
            _normalize_field(f, row.get(f, ""))
            for f in self.custom_key_fields
        )
        if not all(k != "" for k in key):
            return TIER_NO_MATCH
        return TIER_CUSTOM if key in self.custom_index else TIER_NO_MATCH

    def summary(self) -> dict:
        return {
            "rows_indexed": self.n_rows,
            "rows_with_plugin_id": self.n_with_pid,
            "pct_with_plugin_id": (self.n_with_pid / self.n_rows * 100) if self.n_rows else 0,
            "rows_with_plugin_output": self.n_with_output_hash,
            "pct_with_plugin_output": (self.n_with_output_hash / self.n_rows * 100) if self.n_rows else 0,
            "unique_pid_ip_port": len(self.by_pid_ip_port),
            "unique_pid_ip": len(self.by_pid_ip),
            "unique_output_ip_port": len(self.by_output_ip_port),
            "unique_output_ip": len(self.by_output_ip),
            "unique_name_ip_port": len(self.by_name_ip_port),
            "unique_name_ip": len(self.by_name_ip),
            "keys_with_output_hash": len(self.output_hashes_by_key),
            "custom_key_fields": list(self.custom_key_fields),
            "custom_keys_indexed": len(self.custom_index),
        }


def annotate_with_match_tier(df: pd.DataFrame, idx: NewScanIndex) -> pd.DataFrame:
    """Add 'match_tier', 'match_quality', 'is_remediated' columns based on idx."""
    out = df.copy().reset_index(drop=True)
    tiers, quals = [], []
    for _, r in out.iterrows():
        t, q = idx.match_detailed(
            r.get("plugin_id", ""), r.get("finding_name", ""),
            r.get("ip", ""), r.get("port", ""),
            plugin_output=r.get("plugin_output", ""),
        )
        tiers.append(t)
        quals.append(q)
    out["match_tier"] = tiers
    out["match_quality"] = quals
    out["is_remediated"] = [t == TIER_NO_MATCH for t in tiers]
    return out


def subtract_riskaccepted(
    current: pd.DataFrame,
    accepted: pd.DataFrame,
    custom_key_fields: list[str] | None = None,
    strict_output: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Remove risk-accepted findings from a current scan.

    Default mode: 4-tier hierarchical match (plugin_id-first), with
    plugin_output disambiguation when both sides have it (strict_output=True).

    Custom mode: when custom_key_fields is non-empty, match using the exact
    user-specified key tuple ONLY (no fallback tiers). Useful when
    auto-detection picks the wrong column.

    Returns (remaining, removed, diagnostics). Removed rows carry
    'matched_tier' and 'match_quality' columns.
    """
    if current is None or len(current) == 0:
        return (
            current.copy() if current is not None else pd.DataFrame(),
            (current.iloc[0:0].copy() if current is not None else pd.DataFrame()),
            {"current_rows": 0, "accepted_rows": len(accepted) if accepted is not None else 0,
             "removed": 0, "tier_counts": {}, "quality_counts": {},
             "custom_key_fields": list(custom_key_fields or [])},
        )
    if accepted is None or len(accepted) == 0:
        return current.copy(), current.iloc[0:0].copy(), {
            "current_rows": len(current),
            "accepted_rows": 0,
            "removed": 0,
            "tier_counts": {},
            "quality_counts": {},
            "custom_key_fields": list(custom_key_fields or []),
        }

    accepted_idx = NewScanIndex.build(accepted, custom_key_fields=custom_key_fields)
    cur = current.copy().reset_index(drop=True)

    tiers: list[str] = []
    quals: list[str] = []
    if custom_key_fields:
        for _, r in cur.iterrows():
            t = accepted_idx.match_custom(r)
            tiers.append(t)
            quals.append(QUALITY_NA)
    else:
        for _, r in cur.iterrows():
            t, q = accepted_idx.match_detailed(
                r.get("plugin_id", ""), r.get("finding_name", ""),
                r.get("ip", ""), r.get("port", ""),
                plugin_output=r.get("plugin_output", ""),
                strict_output=strict_output,
            )
            tiers.append(t)
            quals.append(q)

    cur["_match_tier"] = tiers
    cur["_match_quality"] = quals

    removed = cur[cur["_match_tier"] != TIER_NO_MATCH].copy()
    remaining = cur[cur["_match_tier"] == TIER_NO_MATCH].copy()

    tier_counts = {t: 0 for t in TIER_ORDER}
    for t in tiers:
        tier_counts[t] = tier_counts.get(t, 0) + 1
    quality_counts: dict[str, int] = {}
    for q in quals:
        if q:
            quality_counts[q] = quality_counts.get(q, 0) + 1

    diag = {
        "current_rows": len(cur),
        "accepted_rows": len(accepted),
        "removed": len(removed),
        "remaining": len(remaining),
        "tier_counts": tier_counts,
        "quality_counts": quality_counts,
        "custom_key_fields": list(custom_key_fields or []),
        "strict_output": bool(strict_output) and not custom_key_fields,
    }

    remaining = remaining.drop(columns=["_match_tier", "_match_quality"]).reset_index(drop=True)
    removed = removed.rename(columns={
        "_match_tier": "matched_tier",
        "_match_quality": "match_quality",
    }).reset_index(drop=True)
    return remaining, removed, diag


# ---------------------------------------------------------------
# Inverse-direction check: accepted rows the script considered but
# didn't actually subtract (because they don't appear in current).
# ---------------------------------------------------------------
def find_accepted_not_matched(
    accepted: pd.DataFrame,
    current: pd.DataFrame,
    custom_key_fields: list[str] | None = None,
    strict_output: bool = True,
) -> pd.DataFrame:
    """Return accepted-side rows that match nothing in current.

    Use this to surface "the script considered this risk-accepted entry but
    didn't subtract anything" — usually because the finding is already gone
    from the current scan, but occasionally because matching missed by a
    hair (different port, name drift, etc.). The user reviews this file
    and manually checks the tracker if needed.

    Mirrors subtract_riskaccepted's match settings so the two stay
    consistent: same custom key, same strict_output behavior.
    """
    if accepted is None or len(accepted) == 0:
        return pd.DataFrame(columns=accepted.columns if accepted is not None else [])
    if current is None or len(current) == 0:
        return accepted.copy()

    current_idx = NewScanIndex.build(current, custom_key_fields=custom_key_fields)
    keep_rows: list[pd.Series] = []
    for _, r in accepted.iterrows():
        if custom_key_fields:
            tier = current_idx.match_custom(r)
        else:
            tier = current_idx.match(
                r.get("plugin_id", ""), r.get("finding_name", ""),
                r.get("ip", ""), r.get("port", ""),
                plugin_output=r.get("plugin_output", ""),
                strict_output=strict_output,
            )
        if tier == TIER_NO_MATCH:
            keep_rows.append(r)
    if not keep_rows:
        return accepted.iloc[0:0].copy()
    return pd.DataFrame(keep_rows, columns=accepted.columns).reset_index(drop=True)


# ---------------------------------------------------------------
# Near-miss diagnostics
# ---------------------------------------------------------------
def _compute_near_misses(
    rows: pd.DataFrame,
    target: pd.DataFrame,
    max_per_row: int,
) -> tuple[list[str], list[str], list[str]]:
    """Shared engine for both directions of near-miss annotation.

    For each row in `rows`, find rows in `target` that share plugin_id
    or finding_name with it. Returns three parallel lists:
      - ip_present : 'yes' / 'no' — is row's IP anywhere in target?
      - same_host  : 'yes' / 'no' — is there a near-miss on the SAME IP?
      - entries    : ' | '-separated 'ip:port (reasons)' strings

    Used by both:
      - annotate_near_misses (considered_not_removed direction): accepted
        rows searched against current.
      - annotate_remaining_near_misses (audit direction): remaining
        current rows searched against accepted.
    """
    from collections import defaultdict
    pid_to_rows: dict[str, list[tuple[str, str]]] = defaultdict(list)
    name_to_rows: dict[str, list[tuple[str, str]]] = defaultdict(list)
    ips_in_target: set[str] = set()

    for _, c in target.iterrows():
        pid_c = normalize_plugin_id(c.get("plugin_id", ""))
        name_c = normalize_name(c.get("finding_name", ""))
        ip_c = normalize_ip(c.get("ip", ""))
        port_c = safe_port(c.get("port", ""))

        if ip_c:
            ips_in_target.add(ip_c)
        if pid_c and ip_c:
            pid_to_rows[pid_c].append((ip_c, port_c))
        if name_c and ip_c:
            name_to_rows[name_c].append((ip_c, port_c))

    ip_present: list[str] = []
    same_host: list[str] = []
    entries: list[str] = []
    for _, r in rows.iterrows():
        pid_a = normalize_plugin_id(r.get("plugin_id", ""))
        name_a = normalize_name(r.get("finding_name", ""))
        ip_a = normalize_ip(r.get("ip", ""))
        port_a = safe_port(r.get("port", ""))

        ip_present.append("yes" if ip_a in ips_in_target else "no")

        cands: dict[tuple[str, str], set[str]] = {}
        if pid_a:
            for (ipc, portc) in pid_to_rows.get(pid_a, []):
                cands.setdefault((ipc, portc), set()).add("same_pid")
        if name_a:
            for (ipc, portc) in name_to_rows.get(name_a, []):
                cands.setdefault((ipc, portc), set()).add("same_name")
        # NOTE: we INCLUDE candidates at the exact (ip_a, port_a) tuple
        # because both call directions (considered_not_removed and audit)
        # exist precisely to surface cases where subtract should have
        # caught a row but didn't — evidence drift, custom-key
        # mismatch, etc. An exact-tuple candidate is the strongest
        # missed-subtraction signal, not a redundant match.

        same_host.append(
            "yes" if any(ipc == ip_a for (ipc, _) in cands.keys()) else "no"
        )

        def _sort_key(item: tuple) -> tuple:
            (ipc, portc), _reasons = item
            return (ipc != ip_a, ipc, portc)

        formatted: list[str] = []
        ordered = sorted(cands.items(), key=_sort_key)
        for (ipc, portc), reasons in ordered[:max_per_row]:
            ip_port = f"{ipc}:{portc}" if portc else ipc
            formatted.append(f"{ip_port} ({'+'.join(sorted(reasons))})")
        if len(cands) > max_per_row:
            formatted.append(f"... +{len(cands) - max_per_row} more")
        entries.append(" | ".join(formatted))

    return ip_present, same_host, entries


def annotate_near_misses(
    considered: pd.DataFrame,
    current: pd.DataFrame,
    max_per_row: int = 5,
) -> pd.DataFrame:
    """Enrich `considered_not_removed` rows with near-miss diagnostics.

    For each accepted-side row that didn't match anything in current, find
    current rows that share at least one of (plugin_id, finding_name) with
    it and emit them as 'ip:port (reason)' entries. Also flag whether the
    accepted row's IP itself appears anywhere in current.

    The point: the user wants to see *why* an accepted row didn't get
    subtracted — host gone from the scan? finding moved to a different
    IP? port changed? — without having to grep the source files manually.

    Adds three canonical columns:
      - ip_in_current_scan : 'yes' / 'no' — host-level signal. Does the
        accepted row's IP appear ANYWHERE in current (regardless of
        finding)? Useful to distinguish "host decommissioned" from
        "host scanned but finding gone".
      - finding_on_same_host : 'yes' / 'no' — finding-level signal. Is
        there a current row on the SAME IP that shares plugin_id or
        finding_name with the accepted row? This is the real triage
        signal: 'yes' means the matcher came close but missed (port
        shift, name drift, etc.); 'no' means there's nothing on this
        host that looks like this finding.
      - near_miss_in_current : '|'-separated 'ip:port (reasons)' entries
        for current rows sharing plugin_id or finding_name. Capped at
        `max_per_row` with an overflow indicator so the cell stays
        readable for findings present on many hosts.
    """
    out = considered.copy()
    if out is None or len(out) == 0:
        out["ip_in_current_scan"] = ""
        out["finding_on_same_host"] = ""
        out["near_miss_in_current"] = ""
        return out
    if current is None or len(current) == 0:
        out["ip_in_current_scan"] = "no"
        out["finding_on_same_host"] = "no"
        out["near_miss_in_current"] = ""
        return out

    ip_present, same_host, entries = _compute_near_misses(out, current, max_per_row)
    out["ip_in_current_scan"] = ip_present
    out["finding_on_same_host"] = same_host
    out["near_miss_in_current"] = entries
    return out


def annotate_remaining_near_misses(
    remaining: pd.DataFrame,
    accepted: pd.DataFrame,
    max_per_row: int = 5,
) -> pd.DataFrame:
    """Inverse direction of `annotate_near_misses`. For each remaining
    current-scan row (one that survived subtraction), surface any
    accepted-side rows that share plugin_id or finding_name.

    Use case: audit. If a remaining row has a same-host near-miss in the
    accepted tracker, the matcher may have missed a subtraction it should
    have made (e.g. column-mapping issue on the accepted side, name
    drift, plugin_id revision). Pipelines.run_scan_pipeline runs this
    over the categorized output and writes audit_remaining_vs_accepted.xlsx
    containing only the suspect rows.

    Columns added:
      - ip_in_accepted : 'yes' / 'no' — host-level visibility
      - finding_on_same_host_in_accepted : 'yes' / 'no' — finding-level
        signal (the audit filter uses this)
      - near_miss_in_accepted : '|'-separated 'ip:port (reasons)' entries
    """
    out = remaining.copy()
    if out is None or len(out) == 0:
        out["ip_in_accepted"] = ""
        out["finding_on_same_host_in_accepted"] = ""
        out["near_miss_in_accepted"] = ""
        return out
    if accepted is None or len(accepted) == 0:
        out["ip_in_accepted"] = "no"
        out["finding_on_same_host_in_accepted"] = "no"
        out["near_miss_in_accepted"] = ""
        return out

    ip_present, same_host, entries = _compute_near_misses(out, accepted, max_per_row)
    out["ip_in_accepted"] = ip_present
    out["finding_on_same_host_in_accepted"] = same_host
    out["near_miss_in_accepted"] = entries
    return out


# ---------------------------------------------------------------
# Match-preview builder (diagnostic — written to xlsx by pipelines)
# ---------------------------------------------------------------
PREVIEW_COLS = [
    "matched_tier", "match_quality",
    "plugin_id", "finding_name", "ip", "port", "risk",
    "plugin_family", "source_file",
]


def build_match_preview(
    removed: pd.DataFrame,
    samples_per_tier: int = 5,
) -> pd.DataFrame:
    """Build a review-friendly preview DataFrame from subtract output.

    Includes:
      - Up to `samples_per_tier` rows from each reliable tier
      - ALL rows from loose_name (highest false-positive risk)
      - ALL rows with match_quality == 'evidence_drift'
    """
    if removed is None or len(removed) == 0:
        return pd.DataFrame(columns=PREVIEW_COLS)

    df = removed.copy()
    if "matched_tier" not in df.columns:
        return pd.DataFrame(columns=PREVIEW_COLS)
    if "match_quality" not in df.columns:
        df["match_quality"] = ""

    pieces: list[pd.DataFrame] = []

    # Full dump of the high-risk groups
    loose = df[df["matched_tier"] == TIER_LOOSE_NAME]
    if len(loose):
        pieces.append(loose.assign(_preview_reason="loose_name (review)"))

    drift = df[df["match_quality"] == QUALITY_EVIDENCE_DRIFT]
    if len(drift):
        pieces.append(drift.assign(_preview_reason="evidence_drift (review)"))

    # Samples from other tiers
    for tier in [TIER_STRICT_PID, TIER_SOFT_PORT_PID, TIER_MEDIUM_PID,
                 TIER_OUTPUT_IP_PORT, TIER_OUTPUT_IP,
                 TIER_STRICT_NAME, TIER_CUSTOM]:
        grp = df[df["matched_tier"] == tier]
        if len(grp):
            pieces.append(
                grp.head(samples_per_tier)
                   .assign(_preview_reason=f"{tier} sample")
            )

    if not pieces:
        return pd.DataFrame(columns=PREVIEW_COLS)

    preview = pd.concat(pieces, ignore_index=True)
    # Keep only columns that actually exist, in PREVIEW_COLS order, plus reason
    cols_present = [c for c in PREVIEW_COLS if c in preview.columns]
    if "_preview_reason" in preview.columns:
        cols_present = ["_preview_reason"] + cols_present
    extras = [c for c in preview.columns if c not in cols_present]
    return preview[cols_present + extras].rename(columns={"_preview_reason": "review_reason"})
