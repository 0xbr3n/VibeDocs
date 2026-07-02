"""
CVSS v4.0 server-side helpers.

The full calculator lives in app/static/js/cvss_v4.js so the UI gives a live score
as the tester picks metrics. The server only needs to:
  - validate the vector string syntax
  - extract the headline score so we can store it and rank findings

Vector format example:
  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

If you want a fully accurate server-side numeric score, install `cvss` from PyPI
and replace `score_from_vector` with that library's CVSS4().scores().

For now we trust the score the JS calculator returns, but still verify the
vector parses cleanly.
"""
from __future__ import annotations
import re

V4_PREFIX = "CVSS:4.0/"

# Required base metrics in v4.0
REQUIRED_BASE = {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

# Allowed values per metric (subset - covers Base, Threat, Environmental)
ALLOWED = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"N", "L", "H"},
    "VI": {"N", "L", "H"},
    "VA": {"N", "L", "H"},
    "SC": {"N", "L", "H"},
    "SI": {"N", "L", "H"},
    "SA": {"N", "L", "H"},
    # Threat
    "E":  {"X", "A", "P", "U"},
    # Environmental modifiers
    "CR": {"X", "L", "M", "H"},
    "IR": {"X", "L", "M", "H"},
    "AR": {"X", "L", "M", "H"},
    "MAV": {"X", "N", "A", "L", "P"},
    "MAC": {"X", "L", "H"},
    "MAT": {"X", "N", "P"},
    "MPR": {"X", "N", "L", "H"},
    "MUI": {"X", "N", "P", "A"},
    "MVC": {"X", "N", "L", "H"},
    "MVI": {"X", "N", "L", "H"},
    "MVA": {"X", "N", "L", "H"},
    "MSC": {"X", "N", "L", "H"},
    "MSI": {"X", "N", "L", "H", "S"},
    "MSA": {"X", "N", "L", "H", "S"},
    # Supplemental
    "S":   {"X", "N", "P"},
    "AU":  {"X", "N", "Y"},
    "R":   {"X", "A", "U", "I"},
    "V":   {"X", "D", "C"},
    "RE":  {"X", "L", "M", "H"},
    "U":   {"X", "Clear", "Green", "Amber", "Red"},
}

_PAIR = re.compile(r"^([A-Z]+):([A-Za-z]+)$")


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS:4.0 vector. Raises ValueError on syntax issues."""
    if not vector or not vector.startswith(V4_PREFIX):
        raise ValueError("Vector must start with CVSS:4.0/")
    body = vector[len(V4_PREFIX):]
    out: dict[str, str] = {}
    for part in body.split("/"):
        part = part.strip()
        if not part:
            continue
        m = _PAIR.match(part)
        if not m:
            raise ValueError(f"Malformed metric: {part!r}")
        metric, value = m.group(1), m.group(2)
        if metric not in ALLOWED:
            raise ValueError(f"Unknown metric: {metric}")
        if value not in ALLOWED[metric]:
            raise ValueError(f"Invalid value {value!r} for metric {metric}")
        out[metric] = value
    missing = REQUIRED_BASE - out.keys()
    if missing:
        raise ValueError(f"Missing required base metrics: {sorted(missing)}")
    return out


def severity_for_score(score: float | None) -> str:
    """v4.0 severity bands (same as v3.1)."""
    if score is None:
        return "Informational"
    if score == 0.0:
        return "Informational"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ============================================================
# Metric metadata for the CVSS calculator UI.
#
# The frontend reads these definitions to build dropdowns with friendly
# labels. Keeping the metadata server-side means both the form and the
# validator stay in sync if the spec ever updates.
# ============================================================

CVSS4_METRICS = {
    "base": [
        {"key": "AV", "label": "Attack Vector", "values": [
            {"v": "N", "label": "Network"},
            {"v": "A", "label": "Adjacent"},
            {"v": "L", "label": "Local"},
            {"v": "P", "label": "Physical"},
        ]},
        {"key": "AC", "label": "Attack Complexity", "values": [
            {"v": "L", "label": "Low"},
            {"v": "H", "label": "High"},
        ]},
        {"key": "AT", "label": "Attack Requirements", "values": [
            {"v": "N", "label": "None"},
            {"v": "P", "label": "Present"},
        ]},
        {"key": "PR", "label": "Privileges Required", "values": [
            {"v": "N", "label": "None"},
            {"v": "L", "label": "Low"},
            {"v": "H", "label": "High"},
        ]},
        {"key": "UI", "label": "User Interaction", "values": [
            {"v": "N", "label": "None"},
            {"v": "P", "label": "Passive"},
            {"v": "A", "label": "Active"},
        ]},
        {"key": "VC", "label": "Vulnerable System Confidentiality Impact", "values": [
            {"v": "H", "label": "High"},
            {"v": "L", "label": "Low"},
            {"v": "N", "label": "None"},
        ]},
        {"key": "VI", "label": "Vulnerable System Integrity Impact", "values": [
            {"v": "H", "label": "High"},
            {"v": "L", "label": "Low"},
            {"v": "N", "label": "None"},
        ]},
        {"key": "VA", "label": "Vulnerable System Availability Impact", "values": [
            {"v": "H", "label": "High"},
            {"v": "L", "label": "Low"},
            {"v": "N", "label": "None"},
        ]},
        {"key": "SC", "label": "Subsequent System Confidentiality Impact", "values": [
            {"v": "H", "label": "High"},
            {"v": "L", "label": "Low"},
            {"v": "N", "label": "None"},
        ]},
        {"key": "SI", "label": "Subsequent System Integrity Impact", "values": [
            {"v": "H", "label": "High"},
            {"v": "L", "label": "Low"},
            {"v": "N", "label": "None"},
        ]},
        {"key": "SA", "label": "Subsequent System Availability Impact", "values": [
            {"v": "H", "label": "High"},
            {"v": "L", "label": "Low"},
            {"v": "N", "label": "None"},
        ]},
    ],
    "threat": [
        {"key": "E", "label": "Exploit Maturity", "values": [
            {"v": "X", "label": "Not Defined"},
            {"v": "A", "label": "Attacked"},
            {"v": "P", "label": "POC"},
            {"v": "U", "label": "Unreported"},
        ]},
    ],
}


# ============================================================
# Heuristic score estimator (server-side fallback)
#
# The JS calculator in the frontend uses the official CVSS 4.0 scoring
# tables. The Python module historically just validated the vector. To
# let the server compute a score without requiring the `cvss` PyPI
# package, this estimator approximates the score via metric weights.
# Approximation is "close enough" for prioritisation; for legal-grade
# accuracy, install `pip install cvss` and use cvss.CVSS4(vector).scores()[0]
# instead -- see TODO at the bottom of this file.
# ============================================================

_BASE_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "AT": {"N": 0.86, "P": 0.62},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "P": 0.62, "A": 0.43},
}
_IMPACT_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}


def estimate_score(vector: str) -> float:
    """Compute the official CVSS 4.0 base score from a vector string.

    Uses the `cvss` PyPI package (already a project dependency via
    backend/app/services/tools/va_automater/cvss_score.py) which
    implements the full MacroVector lookup table algorithm from FIRST.org.
    Falls back to a simple heuristic if the package is unavailable.
    """
    parse_vector(vector)  # validate syntax first
    try:
        from cvss import CVSS4
        obj = CVSS4(vector)
        score = obj.scores()[0]
        return round(float(score), 1)
    except Exception:
        pass

    # Fallback heuristic (approximation only — avoids hard import failure)
    metrics = parse_vector(vector)
    exploitability = 1.0
    for k in ("AV", "AC", "AT", "PR", "UI"):
        exploitability *= _BASE_WEIGHTS[k].get(metrics.get(k, "N"), 0.5)
    impact_vuln = max(
        _IMPACT_WEIGHTS.get(metrics.get("VC", "N"), 0),
        _IMPACT_WEIGHTS.get(metrics.get("VI", "N"), 0),
        _IMPACT_WEIGHTS.get(metrics.get("VA", "N"), 0),
    )
    impact_subs = max(
        _IMPACT_WEIGHTS.get(metrics.get("SC", "N"), 0),
        _IMPACT_WEIGHTS.get(metrics.get("SI", "N"), 0),
        _IMPACT_WEIGHTS.get(metrics.get("SA", "N"), 0),
    )
    return min(10.0, round((exploitability * 8.22 + (impact_vuln + impact_subs * 0.5) * 6.42), 1))
