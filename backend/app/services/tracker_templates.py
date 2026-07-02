"""
Tracker template registry — picks the correct VibeDocs Excel tracker
template for a given report type and builds the output filename in the
team's canonical naming convention.

Files in `TRACKER_TEMPLATES_DIR` are named (verbatim):
  XXX <Type> [variant suffix].xlsx
e.g.
  XXX Web VAPT Tracking List v0.1 (OWASP 2021).xlsx
  XXX API VAPT Tracking List v0.1.xlsx
  XXX Cloud VAPT Tracking List v0.1.xlsx
  XXX Mobile VAPT Tracking List v0.1.xlsx
  XXX Network VAPT Tracking List v0.1.xlsx
  XXX SCR Tracking List v0.1.xlsx
  XXX Thick Client VAPT Tracking List v0.1.xlsx

We map each `ReportTemplate.code` value to the substring its
corresponding tracker filename starts with. When a code has multiple
templates (e.g. Web VAPT has OWASP 2021 and OWASP 2025 variants) we
prefer the plain non-ICT/non-OWASP-suffixed file and fall back to any
match.

Output filename convention (used by the export route):
  "<report_name> <Type> Tracking List v<version>.xlsx"
e.g. for a report called "test" at v0.1 on an API VAPT template:
  "test API VAPT Tracking List v0.1.xlsx"
"""
from __future__ import annotations
import logging
import re
from pathlib import Path
from typing import Optional

from ..config import settings

logger = logging.getLogger(__name__)


# Map a report template `code` to the canonical tracker label that
# appears in the filename. The label feeds BOTH the file picker
# (matches against "XXX <label> Tracking List …") AND the output
# filename ("<report> <label> Tracking List v<ver>.xlsx").
TRACKER_TYPE_BY_CODE: dict[str, str] = {
    "web_vapt":           "Web VAPT",
    "api_vapt":           "API VAPT",
    "infra_vapt":         "Network VAPT",
    # Network VA shares the same Risk-Register layout as Network VAPT in
    # the bundled templates, so we route it at the same file.
    "infra_va":           "Network VAPT",
    "mobile_pt":          "Mobile VAPT",
    "thick_client_pt":    "Thick Client VAPT",
    "cloud_vapt":         "Cloud VAPT",
    "cloud_pt":           "Cloud VAPT",
    "cloud_review":       "Cloud VAPT",
    "aws_cloud_vapt":     "Cloud VAPT",
    "azure_cloud_vapt":   "Cloud VAPT",
    "source_code_review": "SCR",
    "scr":                "SCR",
    # No dedicated kiosk / Wi-Fi / OT / IoT templates in the bundle —
    # the team uses the Network VAPT tracker for all four (closest
    # column shape: per-asset findings on a network-style scope). When
    # dedicated trackers ship in the future, replace these mappings.
    "kiosk_pt":           "Network VAPT",
    "wifi_pt":            "Network VAPT",
    "ot_vapt":            "Network VAPT",
    "iot_vapt":           "Network VAPT",
}


def tracker_type_for_code(code: Optional[str]) -> str:
    """Return the canonical tracker-type label for a `ReportTemplate.code`.

    Falls back to "Web VAPT" so an unknown template still generates a
    sensible filename + finds a template on disk. The mapping above is
    exhaustive for the codes the seed ships with; new codes should be
    added there explicitly when they're introduced.
    """
    return TRACKER_TYPE_BY_CODE.get((code or "").lower(), "Web VAPT")


def _tracker_dir() -> Path:
    """Resolve the on-disk tracker-template folder. Returns an existing
    Path or one that doesn't yet exist — callers handle the missing case.
    """
    return Path(settings.TRACKER_TEMPLATES_DIR)


def pick_tracker_template(code: Optional[str]) -> Optional[Path]:
    """Return the path to the .xlsx tracker template that matches this
    report template `code`, or None if the bundle is missing / no file
    matches.

    Resolution order:
      1. **DB override** — `ReportTemplate.tracker_filename` set
         from the admin "Tasking Assignments" tab. Wins if the
         filename still exists on disk; if it doesn't, we log a
         WARNING and fall through to the filename-pattern path so
         the export doesn't silently switch to the synthesised
         layout.
      2. **Filename-pattern** — `XXX <label> Tracking List …` where
         `<label>` comes from the hardcoded `TRACKER_TYPE_BY_CODE`
         map. Picks the shortest-name match so the plain
         "XXX Web VAPT Tracking List v0.1.xlsx" beats the
         "(OWASP 2025).xlsx" / "(ICT RMM).xlsx" variants.
      3. None.

    The DB-override step is wrapped in a defensive try so importing
    this module never depends on a live DB session being available
    (the `gen_word_templates` boot path imports `tracker_templates`
    well before the engine is reachable in some test environments).

    Files starting with "~$" (Office lock files) are ignored.
    `.xlsm` (macro-enabled) is accepted as well.
    """
    folder = _tracker_dir()
    if not folder.exists():
        logger.warning(
            "Tracker template folder does not exist: %s "
            "(TRACKER_TEMPLATES_DIR setting). "
            "Every tracker export will fall back to the synthesised flat layout "
            "until this directory is populated.",
            folder,
        )
        return None
    accepted_suffixes = {".xlsx", ".xlsm"}

    # ---- Step 1: DB override ----
    override = _db_tracker_override(code)
    if override:
        candidate = folder / override
        if candidate.exists() and candidate.is_file():
            return candidate
        logger.warning(
            "Tracker override %r set on report_templates.code=%r is "
            "missing on disk under %s — falling back to the legacy "
            "filename-pattern resolver.",
            override, code, folder,
        )

    # ---- Step 2: Filename pattern ----
    label = tracker_type_for_code(code)
    prefix = f"XXX {label} Tracking List".lower()
    candidates: list[Path] = []
    for p in folder.iterdir():
        if not p.is_file() or p.suffix.lower() not in accepted_suffixes:
            continue
        if p.name.startswith("~$"):
            continue
        if p.name.lower().startswith(prefix):
            candidates.append(p)
    if not candidates:
        logger.warning(
            "No tracker template matches code=%r (label=%r) in %s. "
            "Files present: %s. "
            "Export will fall back to the synthesised flat layout.",
            code, label, folder,
            [p.name for p in folder.iterdir() if p.is_file()],
        )
        return None
    # Prefer the file with the *shortest* extra suffix — that's the
    # plain "XXX Web VAPT Tracking List v0.1.xlsx" over the "(OWASP
    # 2025).xlsx" / "(ICT RMM).xlsx" variants.
    candidates.sort(key=lambda p: len(p.name))
    return candidates[0]


def _db_tracker_override(code: Optional[str]) -> Optional[str]:
    """Return the `tracker_filename` set on the `ReportTemplate` with
    this `code`, or None when:
      * the column doesn't exist yet (light migration hasn't run on
        the deploy's DB),
      * no row matches the code,
      * the row has no override set.

    Wrapped in a try/except so the legacy filename-pattern path keeps
    working on a fresh / pre-migration DB. We never raise from this
    helper — the picker treats any error as "no override".
    """
    if not code:
        return None
    try:
        # Late imports so importing this module doesn't pull in the
        # whole SQLAlchemy stack at boot time. Both modules are
        # cheap to re-import — Python caches them.
        from ..database import SessionLocal
        from ..models import ReportTemplate
    except Exception:
        return None
    db = None
    try:
        db = SessionLocal()
        row = (db.query(ReportTemplate)
                 .filter(ReportTemplate.code == code)
                 .first())
        if row is None:
            return None
        return getattr(row, "tracker_filename", None) or None
    except Exception as e:                                  # pragma: no cover
        logger.warning("DB tracker override lookup failed for code=%r: %s",
                       code, e)
        return None
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def diagnose() -> dict:
    """Diagnostic snapshot of the tracker-template configuration.

    Returns a dict with the configured folder, whether it exists, the
    list of detected `.xlsx` / `.xlsm` files, and the resolution for
    every known report-template code. Surfaced via
    `/api/admin/tracker-templates/diagnose` so support can answer
    \"why is the export synthesised?\" without shell access.
    """
    folder = _tracker_dir()
    files: list[str] = []
    if folder.exists():
        for p in sorted(folder.iterdir()):
            if not p.is_file() or p.name.startswith("~$"):
                continue
            if p.suffix.lower() not in {".xlsx", ".xlsm"}:
                continue
            files.append(p.name)
    code_resolutions: dict[str, dict] = {}
    for code, label in TRACKER_TYPE_BY_CODE.items():
        match = pick_tracker_template(code)
        code_resolutions[code] = {
            "label": label,
            "matched_file": match.name if match else None,
            "fell_back_to_synthesis": match is None,
        }
    return {
        "folder": str(folder),
        "folder_exists": folder.exists(),
        "files_found": files,
        "type_label_map": TRACKER_TYPE_BY_CODE,
        "per_code_resolution": code_resolutions,
    }


def list_available_trackers() -> list[dict]:
    """Diagnostic helper for the UI — lists every tracker template
    discovered in `TRACKER_TEMPLATES_DIR`, along with the code(s) we'd
    match them against. Used by the report-edit page to show
    "tracker template: XXX Web VAPT …".
    """
    folder = _tracker_dir()
    out: list[dict] = []
    if not folder.exists():
        return out
    for p in sorted(folder.iterdir()):
        if not p.is_file() or p.suffix.lower() != ".xlsx" or p.name.startswith("~$"):
            continue
        out.append({"filename": p.name, "path": str(p), "size": p.stat().st_size})
    return out


# ============================================================
# Output filename
# ============================================================

_SAFE_FILE_CHARS = re.compile(r"[^A-Za-z0-9 _\-().]+")


def _sanitise(s: str) -> str:
    """Strip characters that would confuse Windows / Office. Keeps
    spaces, underscores, hyphens, parens, dots."""
    return _SAFE_FILE_CHARS.sub("", s or "").strip()


def output_filename(report_name: str, code: Optional[str], version: str) -> str:
    """Build the canonical output filename for an exported tracker.

    Example:
        report_name = "test"
        code = "api_vapt"
        version = "0.1"
      → "test API VAPT Tracking List v0.1.xlsx"
    """
    name = _sanitise(report_name) or "report"
    label = tracker_type_for_code(code)
    ver = version or "0.1"
    if not ver.startswith("v"):
        ver = f"v{ver}"
    return f"{name} {label} Tracking List {ver}.xlsx"
