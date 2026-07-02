"""CVSS 3.1 and CVSS 4.0 bulk reassessment.

Library functions take explicit vectors and identifiers. Interactive metric
collection (prompting) lives in cli.py.
"""
from __future__ import annotations
import pandas as pd

try:
    from cvss import CVSS3
    HAS_CVSS3 = True
except ImportError:
    CVSS3 = None
    HAS_CVSS3 = False

try:
    from cvss import CVSS4
    HAS_CVSS4 = True
except ImportError:
    CVSS4 = None
    HAS_CVSS4 = False


# CVSS 3.1 base-metric definitions: (label, allowed values, default)
CVSS31_METRICS: list[tuple[str, list[str], str]] = [
    ("AV", ["N", "A", "L", "P"], "N"),
    ("AC", ["L", "H"], "L"),
    ("PR", ["N", "L", "H"], "N"),
    ("UI", ["N", "R"], "N"),
    ("S",  ["U", "C"], "U"),
    ("C",  ["N", "L", "H"], "N"),
    ("I",  ["N", "L", "H"], "N"),
    ("A",  ["N", "L", "H"], "N"),
]

# CVSS 4.0 base-metric definitions
CVSS40_METRICS: list[tuple[str, list[str], str]] = [
    ("AV", ["N", "A", "L", "P"], "N"),
    ("AC", ["L", "H"], "L"),
    ("AT", ["N", "P"], "N"),
    ("PR", ["N", "L", "H"], "N"),
    ("UI", ["N", "P", "A"], "N"),
    ("VC", ["H", "L", "N"], "N"),
    ("VI", ["H", "L", "N"], "N"),
    ("VA", ["H", "L", "N"], "N"),
    ("SC", ["H", "L", "N"], "N"),
    ("SI", ["H", "L", "N"], "N"),
    ("SA", ["H", "L", "N"], "N"),
]


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


def build_cvss31_vector(metrics: dict[str, str]) -> str:
    parts = [f"{k}:{metrics[k]}" for k, _, _ in CVSS31_METRICS]
    return "CVSS:3.1/" + "/".join(parts)


def build_cvss40_vector(metrics: dict[str, str]) -> str:
    parts = [f"{k}:{metrics[k]}" for k, _, _ in CVSS40_METRICS]
    return "CVSS:4.0/" + "/".join(parts)


def score_vector(vector: str, version: str) -> tuple[float, str]:
    """Calculate (base_score, severity) for a CVSS vector string."""
    if version == "3.1":
        if not HAS_CVSS3:
            raise RuntimeError("python-cvss not installed (pip install cvss)")
        return float(CVSS3(vector).scores()[0]), severity_from_score(float(CVSS3(vector).scores()[0]))
    if version == "4.0":
        if not HAS_CVSS4:
            raise RuntimeError(
                "CVSS 4.0 unavailable. Upgrade python-cvss: pip install -U cvss"
            )
        score = float(CVSS4(vector).scores()[0])
        return score, severity_from_score(score)
    raise ValueError(f"Unsupported CVSS version: {version}")


def apply_vector_to_rows(
    df: pd.DataFrame,
    vector: str,
    version: str,
    target_plugin_ids: set[str] | None = None,
    target_finding_names: set[str] | None = None,
) -> tuple[pd.DataFrame, int]:
    """Apply a CVSS vector to rows whose plugin_id OR finding_name matches.

    Updates 'risk' to the new severity. Sets cvss3_score/vector or
    cvss4_score/vector columns accordingly. Returns (new_df, n_rows_updated).
    """
    out = df.copy()
    score, sev = score_vector(vector, version)

    mask = pd.Series([False] * len(out), index=out.index)
    if target_plugin_ids:
        mask = mask | out["plugin_id"].astype(str).isin(target_plugin_ids)
    if target_finding_names:
        mask = mask | out["finding_name"].astype(str).str.strip().isin(target_finding_names)

    n = int(mask.sum())
    if n == 0:
        return out, 0

    out.loc[mask, "risk"] = sev
    if version == "3.1":
        out.loc[mask, "cvss3_score"] = f"{score:.1f}"
        out.loc[mask, "cvss3_vector"] = vector
    elif version == "4.0":
        if "cvss4_score" not in out.columns:
            out["cvss4_score"] = ""
            out["cvss4_vector"] = ""
        out.loc[mask, "cvss4_score"] = f"{score:.1f}"
        out.loc[mask, "cvss4_vector"] = vector
    return out, n
