"""
Server-side wrapper around the bundled `va_automater` library.

The library lives untouched under
``services/tools/va_automater/`` (a verbatim copy of the user's
standalone CLI tool). This wrapper handles the web-app concerns the
CLI didn't need to think about:

  * marshalling uploaded files (Nessus CSVs + optional risk-accept doc
    + optional previous tracker) into a temp-folder layout the library
    expects;
  * running the scan pipeline against that temp folder;
  * zipping the generated outputs back into a single download;
  * sanitising filenames + capping inputs so a misbehaving client
    can't fill the worker's disk;
  * surfacing a friendly summary JSON for the "preview" call so the
    consultant sees row counts / category breakdown BEFORE committing
    to the download.

The CLI tool's three menu options:
  1) Scan pipeline (csv -> subtract risk-accepted -> categorize)  ← exposed
  2) Tracker update (Windows COM only — needs Excel)              ← skipped
  3) CVSS re-assessment on an existing xlsx                       ← skipped

We only expose option 1. Option 2 is Windows-only and the container
runs Linux. Option 3 is useful but reads/writes an xlsx the consultant
already has on disk — easier as a future addition.

Naming note: we keep the upload key names short — ``current_csvs``,
``risk_accept``, ``prev_tracker`` — and document them on the router
side. The toolkit landing page already directs the consultant to the
right uploads via labels, so the API surface can stay terse.
"""
from __future__ import annotations

import io
import logging
import re
import shutil
import tempfile
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Optional, Tuple


# Defer importing va_automater into the call sites so a misconfigured
# install (missing `cvss` / `pdfplumber`) doesn't break unrelated
# imports of this wrapper. The CLI itself imports lazily for the same
# reason — Option 1 doesn't need cvss / pdfplumber unless the user
# supplies a PDF risk-accept doc.

log = logging.getLogger(__name__)


# Caps. Same per-file ceiling as the Nessus → Excel tool; the
# total-bytes cap protects against "drag the entire scans archive".
_MAX_FILE_BYTES   = 100 * 1024 * 1024     # 100 MB per upload
_MAX_TOTAL_BYTES  = 500 * 1024 * 1024     # 500 MB total across all uploads
_MAX_CSV_FILES    = 50                    # one quarter rarely exceeds ~20

CSV_EXTS  = {".csv"}
ACCEPT_EXTS = {".xlsx", ".xls", ".csv", ".pdf"}
TRACKER_EXTS = {".xlsx", ".xls"}


def _safe_basename(name: str) -> str:
    """Strip any path components an attacker / clueless drag-and-drop
    might leave in the filename. We rebuild the local filesystem layout
    ourselves; never trust the upload's directory hint."""
    name = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._-")
    return name or "upload"


def _check_size(filename: str, size: int, running_total: int) -> int:
    if size > _MAX_FILE_BYTES:
        raise ValueError(
            f"{filename}: file exceeds the {_MAX_FILE_BYTES // (1024*1024)} MB upload limit."
        )
    if running_total + size > _MAX_TOTAL_BYTES:
        raise ValueError(
            f"Total uploaded bytes exceed the {_MAX_TOTAL_BYTES // (1024*1024)} MB request limit."
        )
    return running_total + size


def _ext_of(name: str) -> str:
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def run_pipeline(
    *,
    current_csvs: Iterable[Tuple[str, bytes]],
    risk_accept: Optional[Iterable[Tuple[str, bytes]]] = None,
    prev_tracker: Optional[Iterable[Tuple[str, bytes]]] = None,
    custom_comment_col: str = "",
    custom_comment_default: str = "",
    group_ips_in_by_category: bool = False,
) -> dict:
    """Run the recurring-VA-scan pipeline against the supplied uploads.

    ``risk_accept`` and ``prev_tracker`` each accept an iterable of
    ``(filename, bytes)`` tuples — pass an empty iterable / None when
    skipping. Multiple files are landed in a per-input subdirectory
    and the library's directory-mode loader fans out across every
    file (folder-mode is documented behaviour of
    ``load_riskaccept_file`` and ``load_tracker_comment_riskaccept``).

    Returns a dict with:
      * ``zip_bytes``  — bytes of a ZIP containing every output file
        the pipeline wrote (per-category xlsx, summary.txt, audit
        files, etc.).
      * ``summary``    — dataclass dict of the pipeline result, used
        for the UI preview pane.
      * ``zip_name``   — suggested download filename (timestamped).

    Hard-fails on:
      * No current-quarter CSVs at all.
      * Wrong extensions (csv expected for current; xlsx/xls/csv/pdf
        for risk-accept; xlsx/xls for prev_tracker).
      * Total-bytes overrun.
    """
    from .va_automater.pipelines import run_scan_pipeline

    # 1. Normalise the optional inputs to lists (caller may have
    #    passed None, a generator, or a list — we want all three to
    #    behave the same after this point) and validate every file
    #    BEFORE we touch disk so the error surfaces as a clean 400.
    current_list = list(current_csvs)
    risk_accept_list  = list(risk_accept  or [])
    prev_tracker_list = list(prev_tracker or [])

    if not current_list:
        raise ValueError("Upload at least one Nessus CSV scan.")
    if len(current_list) > _MAX_CSV_FILES:
        raise ValueError(f"Too many Nessus CSVs (max {_MAX_CSV_FILES}).")

    total = 0
    for name, data in current_list:
        if _ext_of(name) not in CSV_EXTS:
            raise ValueError(f"{name}: scans must be .csv files.")
        total = _check_size(name, len(data), total)

    for rname, rdata in risk_accept_list:
        if _ext_of(rname) not in ACCEPT_EXTS:
            raise ValueError(
                f"{rname}: risk-accept must be .xlsx, .xls, .csv, or .pdf."
            )
        total = _check_size(rname, len(rdata), total)

    for tname, tdata in prev_tracker_list:
        if _ext_of(tname) not in TRACKER_EXTS:
            raise ValueError(
                f"{tname}: previous tracker must be .xlsx or .xls."
            )
        total = _check_size(tname, len(tdata), total)

    # 2. Lay out a temp working directory. The library expects a
    #    folder of CSVs and writes outputs to another folder; we give
    #    it both inside the temp root so cleanup is one rmtree. Risk-
    #    accept and tracker each get their own subfolder so the
    #    library's folder-mode loaders (load_riskaccept_folder /
    #    _load_tracker_comment_riskaccept_folder) can fan out across
    #    every uploaded file without us hand-merging DataFrames.
    with tempfile.TemporaryDirectory(prefix="va_recur_") as tmproot_str:
        tmproot = Path(tmproot_str)
        csv_dir = tmproot / "current"
        out_dir = tmproot / "output"
        csv_dir.mkdir()
        out_dir.mkdir()

        for name, data in current_list:
            (csv_dir / _safe_basename(name)).write_bytes(data)

        # `_unique_basename` guards the (rare) case where two uploads
        # share the same sanitised name — without it the second write
        # silently overwrites the first and that file's contribution
        # would vanish.
        def _unique_basename(used: set[str], name: str) -> str:
            base = _safe_basename(name)
            if base not in used:
                used.add(base)
                return base
            stem, _, ext = base.rpartition(".")
            n = 2
            while True:
                candidate = (f"{stem}_{n}.{ext}" if ext else f"{base}_{n}")
                if candidate not in used:
                    used.add(candidate)
                    return candidate
                n += 1

        prev_accepted_path: Optional[Path] = None
        if risk_accept_list:
            ra_dir = tmproot / "risk_accept"
            ra_dir.mkdir()
            seen: set[str] = set()
            for name, data in risk_accept_list:
                (ra_dir / _unique_basename(seen, name)).write_bytes(data)
            prev_accepted_path = ra_dir

        prev_tracker_path: Optional[Path] = None
        if prev_tracker_list:
            tr_dir = tmproot / "prev_tracker"
            tr_dir.mkdir()
            seen = set()
            for name, data in prev_tracker_list:
                (tr_dir / _unique_basename(seen, name)).write_bytes(data)
            prev_tracker_path = tr_dir

        # `pid_map_path` lets the library persist the high-confidence
        # plugin-id -> category learnings across runs. Per-user
        # persistence would be nicer but adds DB complexity; for now
        # we keep a single shared file inside the upload dir so every
        # consultant benefits from the org's accumulated categorisation
        # history. The file is opaque JSON (one
        # `{"<plugin_id>": "<category>", …}` mapping).
        from ...config import settings as _settings
        shared_dir = Path(_settings.UPLOAD_DIR) / "toolkit" / "va_recurring"
        shared_dir.mkdir(parents=True, exist_ok=True)
        pid_map_path = shared_dir / "plugin_id_categories.json"

        # 3. Run the pipeline. Anything that goes wrong here is
        #    library-level; we surface the message as-is.
        try:
            result = run_scan_pipeline(
                current_folder=csv_dir,
                output_folder=out_dir,
                prev_accepted_path=prev_accepted_path,
                prev_tracker_path=prev_tracker_path,
                pid_map_path=pid_map_path,
                custom_comment_col=custom_comment_col or "",
                custom_comment_default=custom_comment_default or "",
                group_ips_in_by_category=bool(group_ips_in_by_category),
            )
        except Exception:
            log.exception("VA-Recurring pipeline failed")
            raise

        # 4. Zip up everything in out_dir.
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(out_dir.rglob("*")):
                if path.is_file():
                    arc = path.relative_to(out_dir).as_posix()
                    zf.writestr(arc, path.read_bytes())
        zip_bytes = zip_buf.getvalue()

    # 5. Suggest a download filename. The pipeline doesn't know what
    #    quarter / engagement this is, so timestamp is the safe bet.
    from datetime import datetime
    zip_name = datetime.utcnow().strftime("va_recurring_%Y%m%d_%H%M%S.zip")

    summary = asdict(result)
    return {"zip_bytes": zip_bytes, "summary": summary, "zip_name": zip_name}
