"""Canonical schema and column aliasing.

All loaders normalize source-specific columns into this canonical shape.
Downstream code operates ONLY on canonical column names.
"""
from __future__ import annotations

# Canonical column order for output / display
CANON_COLS: list[str] = [
    "plugin_id",
    "finding_name",
    "ip",
    "port",
    "protocol",
    "risk",
    "cvss2_score",
    "cvss3_score",
    "cvss3_vector",
    "cve",
    "plugin_family",
    "synopsis",
    "description",
    "solution",
    "see_also",
    "plugin_output",
    "source_file",
    "source_row",
]

# Source-column candidates per canonical field. First match wins.
# Covers Nessus, common tracker spreadsheet conventions, and management report variants.
COL_ALIASES: dict[str, list[str]] = {
    "plugin_id":     ["Plugin ID", "PluginID", "Plugin_ID", "PID"],
    "finding_name":  ["Name", "Plugin Name", "Plugin", "Finding Name", "Finding",
                      "Title", "Vulnerability", "Issue", "Vulnerability Name"],
    "ip":            ["Host", "IP Address", "IP", "Hostname", "Affected Host",
                      "Affected Hosts", "Target", "Asset"],
    "port":          ["Port", "Service Port"],
    "protocol":      ["Protocol"],
    "risk":          ["Risk", "Severity", "Risk Factor"],
    "cvss2_score":   ["CVSS Version 2.0 Base Score", "CVSS Base Score",
                      "CVSSv2 Base Score", "CVSS2 Base Score", "CVSS"],
    "cvss3_score":   ["CVSS v3.0 Base Score", "CVSS Version 3.0 Base Score",
                      "CVSS3 Base Score", "CVSSv3 Base Score", "CVSS v3 Base Score"],
    "cvss3_vector":  ["CVSS v3.0 Vector", "CVSS Version 3.0 Vector",
                      "CVSS3 Vector", "CVSS v3 Vector"],
    # CVE column — Nessus exports one CVE per row, so the SAME finding on the
    # same host/port can appear as multiple rows differing ONLY by CVE. The
    # dedup key includes `cve` so those distinct-CVE rows are preserved.
    "cve":           ["CVE", "CVEs", "CVE ID", "CVE-ID", "CVE IDs"],
    "plugin_family": ["Plugin Family", "Family"],
    "synopsis":      ["Synopsis"],
    "description":   ["Description", "Plugin Description"],
    "solution":      ["Solution", "Remediation", "Recommendations",
                      "Recommendation", "Fix"],
    "see_also":      ["See Also", "References"],
    "plugin_output": ["Plugin Output", "Output", "Plugin output"],
}

# Tracker-specific column aliases (for old quarterly trackers / risk-accept registers)
TRACKER_COL_ALIASES: dict[str, list[str]] = {
    "status":         ["Status", "State"],
    "comments":       ["Comments", "Notes", "VibeDocs Comments", "Auditor Comments",
                       "Remarks", "Comment"],
    "accepted_until": ["Accepted Until", "Expiry", "Risk Accepted Until",
                       "Valid Until", "Review Date"],
    "ticket_ref":     ["Ticket", "Ticket Ref", "Reference", "JIRA", "Ticket #"],
}
