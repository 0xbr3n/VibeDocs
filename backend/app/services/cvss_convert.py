"""Convert a CVSS v4.0 base vector to an approximate CVSS v3.1 base vector,
recomputing the 3.1 base score with the `cvss` library so the number is
mathematically correct for the derived vector.

The two standards use different metric sets, so the mapping is necessarily a
best-effort projection of the v4.0 BASE metrics onto v3.1 BASE metrics:

    v4.0                         -> v3.1
    AV (N/A/L/P)                 -> AV   (identical values)
    AC (L/H) + AT (N/P)          -> AC   (H if AC=H OR AT=P, else L)
    PR (N/L/H)                   -> PR   (identical values)
    UI (N/P/A)                   -> UI   (N if UI=N, else R)
    VC/VI/VA (H/L/N)             -> C/I/A (identical values; vulnerable system)
    SC/SI/SA (any != N)          -> S    (Changed if any subsequent impact, else Unchanged)

The score + severity are then produced by `cvss.CVSS3` on the derived vector,
so callers get the canonical 3.1 base score (no hand-rolled arithmetic).
"""
from __future__ import annotations

from .cvss_v4 import parse_vector as _parse_v4

# v3.1 impact letters match v4.0 vuln-impact letters (H/L/N), so they pass
# through unchanged.
_PASS = {"H", "L", "N"}


def is_cvss4(vector: str | None) -> bool:
    return bool(vector) and str(vector).strip().upper().startswith("CVSS:4.0/")


def is_cvss31(vector: str | None) -> bool:
    v = (vector or "").strip().upper()
    return v.startswith("CVSS:3.1/") or v.startswith("CVSS:3.0/")


def cvss4_to_cvss31(vector4: str) -> tuple[str, float, str]:
    """Return (vector31, base_score, severity) for a CVSS:4.0 base vector.

    Raises ValueError if `vector4` is not a parseable 4.0 vector.
    """
    m = _parse_v4(vector4)   # validates + returns {metric: value}

    av = m.get("AV", "N")
    ac4, at4 = m.get("AC", "L"), m.get("AT", "N")
    ac = "H" if (ac4 == "H" or at4 == "P") else "L"
    pr = m.get("PR", "N")
    ui = "N" if m.get("UI", "N") == "N" else "R"

    c = m.get("VC", "N"); c = c if c in _PASS else "N"
    i = m.get("VI", "N"); i = i if i in _PASS else "N"
    a = m.get("VA", "N"); a = a if a in _PASS else "N"

    sc, si, sa = m.get("SC", "N"), m.get("SI", "N"), m.get("SA", "N")
    scope = "C" if any(x not in ("N", "X") for x in (sc, si, sa)) else "U"

    vector31 = (
        f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}"
        f"/C:{c}/I:{i}/A:{a}"
    )

    from cvss import CVSS3
    c3 = CVSS3(vector31)
    score = float(c3.base_score)
    sev = c3.severities()[0]          # None / Low / Medium / High / Critical
    if sev == "None":
        sev = "Informational"
    return vector31, score, sev


def cvss31_to_cvss4(vector31: str) -> tuple[str, float, str]:
    """Return (vector40, base_score, severity) for a CVSS:3.1 base vector.

    The reverse projection. NOTE: CVSS 4.0 splits impact into vulnerable-system
    (VC/VI/VA) and subsequent-system (SC/SI/SA); v3.1 has no subsequent-system
    metrics, so SC/SI/SA are emitted as N and the consultant MUST review them
    (this is surfaced as a disclaimer in the UI). AT defaults to N.

    Raises ValueError if `vector31` is not a parseable 3.1/3.0 vector.
    """
    from cvss import CVSS3, CVSS4
    c3 = CVSS3(vector31)              # validates
    m = c3.metrics                    # dict of {AV,AC,PR,UI,S,C,I,A: value}

    av = m.get("AV", "N")
    ac = m.get("AC", "L")            # L/H pass through
    pr = m.get("PR", "N")
    ui = "N" if m.get("UI", "N") == "N" else "P"   # 3.1 R -> 4.0 P (passive)
    vc = m.get("C", "N")
    vi = m.get("I", "N")
    va = m.get("A", "N")

    vector40 = (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:N/PR:{pr}/UI:{ui}"
        f"/VC:{vc}/VI:{vi}/VA:{va}/SC:N/SI:N/SA:N"
    )
    c4 = CVSS4(vector40)
    score = float(c4.base_score)
    sev = c4.severity
    if sev == "None":
        sev = "Informational"
    return vector40, score, sev


# Map the cvss-library / band severity word to the app's Severity enum value
# string (Title-case spellings the FindingStatus/Severity columns store).
_SEV_TO_ENUM = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "None": "Informational",
    "Informational": "Informational",
}


def severity_enum_value(sev_word: str) -> str:
    """Normalise a band word to the Severity enum's stored value string."""
    return _SEV_TO_ENUM.get(sev_word, "Informational")
