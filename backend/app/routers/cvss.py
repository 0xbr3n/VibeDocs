"""
CVSS 4.0 helper endpoints for the calculator UI.

  GET  /api/cvss/v4/metrics                  metric metadata for dropdowns
  POST /api/cvss/v4/validate                 validate a vector + get a score
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from ..auth import get_current_user
from ..models import User
from ..services.cvss_v4 import CVSS4_METRICS, parse_vector, estimate_score, severity_for_score


router = APIRouter(prefix="/api/cvss/v4", tags=["cvss"])


@router.get("/metrics")
def metrics(_: User = Depends(get_current_user)):
    """Return the full metric metadata. The frontend renders dropdowns
    from this so the server stays the source of truth.
    """
    return CVSS4_METRICS


class ValidateRequest(BaseModel):
    vector: str


@router.post("/validate")
def validate(req: ValidateRequest, _: User = Depends(get_current_user)):
    """Validate a vector and return an estimated score + severity band.

    The JS calculator should compute the authoritative score live. This
    endpoint exists so manual entry / API clients can get a server-side
    sanity check.
    """
    try:
        metrics_dict = parse_vector(req.vector)
    except ValueError as e:
        return {"valid": False, "error": str(e)}

    score = estimate_score(req.vector)
    return {
        "valid": True,
        "vector": req.vector,
        "metrics": metrics_dict,
        "score_estimate": score,
        "severity": severity_for_score(score),
        "note": "Score is an estimate. The authoritative score should come from a CVSS 4.0 spec-compliant calculator.",
    }


class ScoreRequest(BaseModel):
    vector: str


@router.post("/score")
def score_any(req: ScoreRequest, _: User = Depends(get_current_user)):
    """Authoritative base score + severity for ANY CVSS 3.0 / 3.1 / 4.0 vector,
    computed with the `cvss` library. Powers live re-scoring when a consultant
    edits a CVSS 3.1 vector by hand or via the 3.1 calculator.
    """
    v = (req.vector or "").strip()
    up = v.upper()
    try:
        if up.startswith("CVSS:4.0"):
            from cvss import CVSS4
            c = CVSS4(v)
            sev = c.severity
            return {"valid": True, "version": "4.0", "vector": v,
                    "score": float(c.base_score),
                    "severity": "Informational" if sev == "None" else sev}
        if up.startswith("CVSS:3.1") or up.startswith("CVSS:3.0"):
            from cvss import CVSS3
            c = CVSS3(v)
            sev = c.severities()[0]
            return {"valid": True, "version": "3.1" if "3.1" in up else "3.0",
                    "vector": v, "score": float(c.base_score),
                    "severity": "Informational" if sev == "None" else sev}
        return {"valid": False,
                "error": "Vector must start with CVSS:3.0/, CVSS:3.1/ or CVSS:4.0/"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
