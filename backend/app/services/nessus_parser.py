"""
Nessus CSV parser for Infra VA reports.

The standard Nessus 'Export -> CSV' format has these columns (case-sensitive):
    Plugin ID, CVE, CVSS v2.0 Base Score, Risk, Host, Protocol, Port,
    Name, Synopsis, Description, Solution, See Also, Plugin Output

Some exports include CVSS v3.0 / CVSS v4.0. We tolerate either.

Functions:
- parse_nessus_csv(path)        -> list of normalised raw rows
- group_findings(rows)          -> grouped findings ready to become ReportFindings
- diff_against_existing(...)    -> figure out which existing findings are still present and which to auto-close
"""
from __future__ import annotations
import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Severity normaliser. Nessus uses "Critical/High/Medium/Low/None/Info"
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
    "none": "Informational",
}

# Patterns for grouping common families of findings.
# Order matters - first match wins. Each tuple is (group_title, regex on plugin name).
GROUP_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SSL/TLS - Untrusted or Expired Certificate",
     re.compile(r"ssl.*(certificate|cert).*(self.signed|untrusted|expired|chain)", re.I)),
    ("SSL/TLS - Weak Cipher Suites",
     re.compile(r"ssl.*(weak|cbc|rc4|3des|export|null).*cipher", re.I)),
    ("SSL/TLS - Deprecated Protocol (SSLv2/SSLv3/TLS 1.0/1.1)",
     re.compile(r"(sslv[23]|tls\s*1\.(0|1))\s*(detected|enabled|supported)", re.I)),
    ("SMB - Signing Not Required",
     re.compile(r"smb\s*signing.*(not.required|disabled)", re.I)),
    ("SNMP - Default Community String",
     re.compile(r"snmp.*(default|public|private).*community", re.I)),
    ("Outdated Software - End of Life / Unsupported",
     re.compile(r"(unsupported|end[\s-]?of[\s-]?life|EOL)", re.I)),
    ("Outdated Software - Missing Security Patches",
     re.compile(r"(missing.*patch|security update|vulnerab.*version)", re.I)),
    ("Default Credentials",
     re.compile(r"default.*credential", re.I)),
    ("Information Disclosure",
     re.compile(r"information.*disclos", re.I)),
]


def _pick(row: dict, *keys: str, default: str = "") -> str:
    """Return first non-empty value among the given column keys (case-insensitive)."""
    lower = {k.lower(): v for k, v in row.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, ""):
            return str(v).strip()
    return default


@dataclass
class NessusRow:
    plugin_id: str
    name: str
    risk: str             # normalised: Critical/High/Medium/Low/Informational
    host: str
    port: str
    protocol: str
    cve: str
    cvss_score: float | None
    synopsis: str
    description: str
    solution: str
    see_also: str
    plugin_output: str


@dataclass
class GroupedFinding:
    """A finding ready to be turned into a ReportFinding row."""
    title: str
    severity: str
    description: str
    impact: str
    remediation: str
    references: str
    affected_assets: list[str] = field(default_factory=list)  # "host:port/proto" strings
    plugin_ids: list[str] = field(default_factory=list)
    cve_list: list[str] = field(default_factory=list)
    cvss_score: float | None = None

    def to_report_finding_payload(self) -> dict:
        affected = "\n".join(sorted(set(self.affected_assets)))
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "affected_asset": affected,
            "cvss_score": self.cvss_score,
            "source": "nessus",
            "source_ref": ",".join(sorted(set(self.plugin_ids))),
        }


def parse_nessus_csv(path: str | Path) -> list[NessusRow]:
    """
    Parse Nessus vulnerability export file (CSV or XLSX format).
    
    For CSV: standard Nessus export columns
    For XLSX: reads first sheet, expects same column names as CSV
    """
    import pandas as pd
    
    path = Path(path)
    rows: list[NessusRow] = []
    
    # Detect file type and read into DataFrame
    if path.suffix.lower() in ['.xlsx', '.xls']:
        # Read Excel file - first sheet
        df = pd.read_excel(path, sheet_name=0, engine='openpyxl' if path.suffix.lower() == '.xlsx' else None)
    elif path.suffix.lower() == '.csv':
        # Read CSV file
        df = pd.read_csv(path, encoding='utf-8-sig', encoding_errors='replace')
    else:
        raise ValueError(f"Unsupported file type: {path.suffix}. Expected .csv, .xlsx, or .xls")
    
    # Convert DataFrame to dict records (same as csv.DictReader output)
    for raw in df.to_dict('records'):
        risk_raw = str(_pick_dict(raw, "Risk")).lower()
        risk = SEVERITY_MAP.get(risk_raw, "Informational")
        
        cvss_raw = _pick_dict(raw, "CVSS v4.0 Base Score", "CVSS v3.0 Base Score",
                         "CVSS v3 Base Score", "CVSS Base Score",
                         "CVSS v2.0 Base Score", "CVSS")
        try:
            cvss_score = float(cvss_raw) if cvss_raw and str(cvss_raw).strip() else None
        except (ValueError, TypeError):
            cvss_score = None
        
        rows.append(NessusRow(
            plugin_id=_pick_dict(raw, "Plugin ID", "Plugin"),
            name=_pick_dict(raw, "Name", "Plugin Name"),
            risk=risk,
            host=_pick_dict(raw, "Host", "IP Address"),
            port=_pick_dict(raw, "Port"),
            protocol=_pick_dict(raw, "Protocol"),
            cve=_pick_dict(raw, "CVE"),
            cvss_score=cvss_score,
            synopsis=_pick_dict(raw, "Synopsis"),
            description=_pick_dict(raw, "Description"),
            solution=_pick_dict(raw, "Solution"),
            see_also=_pick_dict(raw, "See Also"),
            plugin_output=_pick_dict(raw, "Plugin Output"),
        ))
    return rows


def _pick_dict(d: dict, *keys) -> str:
    """Helper to find first available key in dict, return as string."""
    for k in keys:
        val = d.get(k)
        if val is not None and str(val).strip() and str(val) != 'nan':
            return str(val).strip()
    return ""


def _assign_group(name: str) -> str | None:
    for label, pattern in GROUP_PATTERNS:
        if pattern.search(name or ""):
            return label
    return None


# Severity sort key (highest first)
_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def group_findings(rows: Iterable[NessusRow]) -> list[GroupedFinding]:
    """
    Group rows by:
      1. A known family (SSL issues / outdated software / ...) when the plugin name matches.
      2. Otherwise by plugin_id (so each unique vuln becomes one finding with multiple affected hosts).
    Severity escalates upward inside a group (Critical wins over Medium).
    """
    buckets: dict[str, GroupedFinding] = {}

    for r in rows:
        if r.risk == "Informational":
            # Skip pure info plugins for the main findings list. They can still be referenced separately.
            continue

        group_label = _assign_group(r.name)
        key = f"group::{group_label}" if group_label else f"plugin::{r.plugin_id}"

        if key not in buckets:
            title = group_label or r.name
            buckets[key] = GroupedFinding(
                title=title,
                severity=r.risk,
                description=r.synopsis or r.description or "",
                impact=r.description or "",
                remediation=r.solution or "",
                references=r.see_also or "",
            )

        b = buckets[key]
        # Escalate severity if this row is more severe
        if _SEV_RANK.get(r.risk, 99) < _SEV_RANK.get(b.severity, 99):
            b.severity = r.risk
        if r.cvss_score and (b.cvss_score is None or r.cvss_score > b.cvss_score):
            b.cvss_score = r.cvss_score

        b.affected_assets.append(f"{r.host}:{r.port}/{r.protocol}" if r.port else r.host)
        if r.plugin_id:
            b.plugin_ids.append(r.plugin_id)
        if r.cve:
            for c in re.split(r"[,\s]+", r.cve):
                if c:
                    b.cve_list.append(c)

    # Append CVE list to references if present
    for b in buckets.values():
        if b.cve_list:
            extra = "CVEs: " + ", ".join(sorted(set(b.cve_list)))
            b.references = (b.references + "\n" + extra).strip() if b.references else extra

    # Return sorted: most severe first, then by title
    return sorted(buckets.values(),
                  key=lambda g: (_SEV_RANK.get(g.severity, 99), g.title.lower()))


def diff_against_existing(
        new_groups: list[GroupedFinding],
        existing_findings: list,  # list[ReportFinding-like objects with .title, .source_ref]
) -> tuple[list[GroupedFinding], list, dict]:
    """
    Compare a new scan import against existing findings on the report version.

    Returns:
        - to_create: groups that should become new ReportFindings
        - to_auto_close: existing findings (with source='nessus') no longer present
        - kept: dict of (existing finding id -> group title) for findings that recur
    """
    # Use a tuple of (title, sorted(plugin_ids)) as the identity for grouped findings
    new_key_to_group = {
        (g.title, tuple(sorted(set(g.plugin_ids)))): g for g in new_groups
    }

    existing_keys = set()
    kept: dict[int, str] = {}
    to_auto_close = []

    for ef in existing_findings:
        if ef.source != "nessus":
            continue  # only auto-close prior Nessus-sourced findings
        ef_pids = tuple(sorted(set((ef.source_ref or "").split(","))))
        key = (ef.title, ef_pids)
        existing_keys.add(key)
        if key in new_key_to_group:
            kept[ef.id] = ef.title
        else:
            to_auto_close.append(ef)

    to_create = [g for k, g in new_key_to_group.items() if k not in existing_keys]
    return to_create, to_auto_close, kept
