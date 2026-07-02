"""
Source-code integrity verification.

Used in source-code review engagements to prove that what we tested is
literally byte-for-byte what the client gave us. The client provides
an MD5 (and ideally SHA256) of the archive; we recompute on receipt and
record the match for audit. If a client later disputes the scope ("you
tested a different version"), we have a timestamped hash chain.

Persistence:
  Hashes are stored as a list under project.details["source_code_hashes"]
  rather than a dedicated table -- it keeps the schema simple and these
  records are append-only per project. Each entry has:
    {
      "filename": "ibanking_src_v2.4.0.zip",
      "size":     12_345_678,
      "received_at": "2026-05-11T14:22:00Z",
      "received_by": "brendon.t",
      "client_md5": "abc123...",          # what the client said
      "computed_md5": "abc123...",        # what we measured
      "client_sha256": "..." or null,
      "computed_sha256": "...",           # always computed
      "match_md5": true,
      "match_sha256": true | null,
      "notes": "Sent via Sharefile · email 2026-05-09",
    }

Note: MD5 is broken for cryptographic uses but fine here -- we're matching
an integrity hash the client supplied, and we compute SHA256 alongside for
defence-in-depth. If only MD5 was sent, we record that and recommend the
team ask for SHA256 next engagement.
"""
from __future__ import annotations
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, BinaryIO


CHUNK_SIZE = 1024 * 1024  # 1 MB chunks for streaming hash computation


def compute_hashes(fh: BinaryIO) -> tuple[str, str, int]:
    """Stream-compute MD5 and SHA256 of an open binary file handle.

    Returns (md5_hex, sha256_hex, total_bytes). Caller is responsible for
    seeking to start beforehand if needed.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    total = 0
    while True:
        chunk = fh.read(CHUNK_SIZE)
        if not chunk:
            break
        md5.update(chunk)
        sha256.update(chunk)
        total += len(chunk)
    return md5.hexdigest(), sha256.hexdigest(), total


def compute_hashes_path(path: Path) -> tuple[str, str, int]:
    with path.open("rb") as fh:
        return compute_hashes(fh)


def verify_against_client(
    *,
    filename: str,
    size_bytes: int,
    computed_md5: str,
    computed_sha256: str,
    client_md5: Optional[str] = None,
    client_sha256: Optional[str] = None,
    received_by_username: Optional[str] = None,
    notes: Optional[str] = None,
) -> dict:
    """Build a verification record from inputs."""
    def _norm(h: Optional[str]) -> Optional[str]:
        if not h:
            return None
        return h.strip().lower().replace(":", "").replace("-", "").replace(" ", "")

    cm5 = _norm(client_md5)
    cs256 = _norm(client_sha256)

    match_md5 = (cm5 is not None and cm5 == computed_md5.lower()) if cm5 else None
    match_sha256 = (cs256 is not None and cs256 == computed_sha256.lower()) if cs256 else None

    overall = None
    if match_sha256 is True:
        overall = "match"
    elif match_md5 is True and match_sha256 is None:
        overall = "match_md5_only"
    elif match_md5 is False or match_sha256 is False:
        overall = "mismatch"
    else:
        overall = "no_client_hash"   # nothing to compare against

    return {
        "filename":         filename,
        "size":             size_bytes,
        "received_at":      datetime.utcnow().isoformat() + "Z",
        "received_by":      received_by_username,
        "client_md5":       cm5,
        "computed_md5":     computed_md5.lower(),
        "client_sha256":    cs256,
        "computed_sha256":  computed_sha256.lower(),
        "match_md5":        match_md5,
        "match_sha256":     match_sha256,
        "result":           overall,
        "notes":            notes,
    }


def overall_status_label(record: dict) -> str:
    """Human-readable label for the UI."""
    return {
        "match":            "Verified",
        "match_md5_only":   "Verified (MD5 only)",
        "mismatch":         "Mismatch",
        "no_client_hash":   "No client hash to compare",
    }.get(record.get("result", ""), "Unknown")
