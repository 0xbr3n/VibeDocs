"""Risk-accept keyword detection for tracker comment columns.

Used by the two-source subtract workflow: when a previous-quarter tracker
xlsx has free-text comments like "management accepted Q3 2025", those rows
should be treated as risk-accepted and subtracted from the current scan
even though they aren't in the dedicated risk-accept document.

The keyword list is substring-based (case-insensitive by default). Use a
JSON config file to override or extend defaults.
"""
from __future__ import annotations
from pathlib import Path
import json

# Default phrases. These are intentionally specific - bare "accepted" is
# excluded by default because comments like "patch accepted by IT" are too
# common to safely match.
DEFAULT_RISK_KEYWORDS: list[str] = [
    # Generic
    "risk accepted",
    "risk-accepted",
    "risk acceptance",
    "accept the risk",
    "accepted the risk",
    "accepting the risk",
    "accepted risk",            # inverted order variant
    # Management / client variants
    "management accepted",
    "mgmt accepted",
    "client accepted",
    "business accepted",
    "customer accepted",
    "accepted by management",
    "accepted by mgmt",
    "accepted by client",
    "accepted by the client",
    "accepted by business",
    # Approval phrasing
    "approved by management",
    "approved by mgmt",
    "approved by client",
    "approved by the client",
    "approved by business",
    # Formal risk management language
    "risk exception",
    "exception granted",
    "exception approved",
    "waiver granted",
    "risk waiver",
    "security exception",
    "compensating control",
    # Deferred / won't fix variants
    "risk deferred",
    "deferred risk",
    "wont fix",
    "won't fix",
    "will not fix",
    "not fixing",
    "no remediation",
    "no fix required",
    "no action required",
    # Director / executive sign-off
    "director accepted",
    "ciso accepted",
    "cso accepted",
    "cto accepted",
    "signed off",
    "sign off accepted",
]


def load_keyword_config(path: Path | None) -> tuple[list[str], bool]:
    """Load a keyword config JSON. Returns (keywords, case_sensitive).

    Config schema (all fields optional):
        {
          "keywords":       [list of phrases],
          "use_defaults":   true | false,  # default true
          "case_sensitive": true | false   # default false
        }

    If path is None or missing, returns (DEFAULT_RISK_KEYWORDS, False).
    Unknown fields are ignored. Bad JSON raises ValueError with a clear
    message rather than silently falling back.
    """
    if path is None or not Path(path).exists():
        return list(DEFAULT_RISK_KEYWORDS), False
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Risk-keyword config {path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"Risk-keyword config {path} must be a JSON object")

    user_kw = [str(k).strip() for k in data.get("keywords", []) if str(k).strip()]
    use_defaults = bool(data.get("use_defaults", True))
    case_sensitive = bool(data.get("case_sensitive", False))

    kws = list(DEFAULT_RISK_KEYWORDS) if use_defaults else []
    for k in user_kw:
        if k not in kws:
            kws.append(k)
    return kws, case_sensitive


def comment_matches_riskaccept(
    comment: str,
    keywords: list[str],
    case_sensitive: bool = False,
) -> str:
    """Return the first matched keyword in `comment`, or '' if none match.

    Returning the matched phrase (not just bool) is useful for diagnostics —
    the caller can show the user which keyword fired.
    """
    if comment is None:
        return ""
    text = str(comment)
    haystack = text if case_sensitive else text.lower()
    for kw in keywords:
        needle = kw if case_sensitive else kw.lower()
        if needle and needle in haystack:
            return kw
    return ""


def write_default_config(path: Path) -> None:
    """Write a starter config file the user can edit.

    Includes the default keywords as a visible list so the user knows what's
    being matched, plus use_defaults=False so editing the keywords field
    replaces (not extends) the list. They can flip use_defaults back to true
    if they prefer to extend.
    """
    cfg = {
        "_comment": (
            "Risk-accept keyword config. case_sensitive defaults to false. "
            "Set use_defaults=true to extend the built-in list with yours; "
            "set false to replace it entirely."
        ),
        "keywords": list(DEFAULT_RISK_KEYWORDS),
        "use_defaults": False,
        "case_sensitive": False,
    }
    Path(path).write_text(
        json.dumps(cfg, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
