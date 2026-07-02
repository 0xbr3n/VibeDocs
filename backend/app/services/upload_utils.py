"""
Shared upload helpers.

`stream_save` is a single-spot replacement for every bare `shutil.copyfileobj`
call in the routers.  It streams in 64 KB chunks and aborts + cleans up if the
caller-supplied byte cap is exceeded, preventing memory exhaustion when a
large file is later parsed by pandas / openpyxl into RAM.
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import IO

from fastapi import HTTPException

_log = logging.getLogger(__name__)

_CHUNK = 64 * 1024   # 64 KB


def stream_save(
    src: IO[bytes],
    dest: Path,
    max_bytes: int,
) -> int:
    """Stream `src` to `dest`, enforcing `max_bytes`.

    Returns total bytes written.  Raises HTTPException(413) if the stream
    exceeds `max_bytes`, deletes the partial destination file on failure.
    """
    total = 0
    try:
        with dest.open("wb") as out:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    out.close()
                    dest.unlink(missing_ok=True)
                    mb = max_bytes // (1024 * 1024)
                    raise HTTPException(413, f"Upload exceeds the {mb} MB limit.")
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        dest.unlink(missing_ok=True)
        _log.exception("stream_save: I/O error writing to %s", dest)
        raise HTTPException(500, "Failed to save upload. Please try again.") from exc
    return total
