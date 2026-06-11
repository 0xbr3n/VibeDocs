"""
Postman Collection v2.1 parser.

Used by the API VAPT template to auto-populate the scope section in the
executive summary. The consultant uploads the .json collection the client
sent (or that the dev team produced); the parser walks all folders and
counts endpoints by HTTP method, builds an endpoint inventory, and returns
data shaped for the docxtpl context.

Postman collection schema (v2.1, abbreviated):

  {
    "info":  { "name": "...", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/..." },
    "item":  [ Item, Item, ... ]
  }

Where each Item is either:
  - A folder: { "name": "...", "item": [ ... ] }                  (recursive)
  - A request: {
        "name": "...",
        "request": {
            "method": "GET",
            "url": "https://api.example.com/v1/users"     # or url object below
                       OR { "raw": "...", "host": [...], "path": [...] },
            "header": [ { "key": "...", "value": "..." } ],
            "body":   { ... }    # optional
        }
    }
"""
from __future__ import annotations
import json
from typing import Any


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE",
                "OPTIONS", "HEAD", "TRACE", "CONNECT"}


def parse_postman(raw: bytes | str | dict) -> dict:
    """Parse a Postman collection. Accepts bytes, str, or already-decoded dict.

    Returns:
        {
            "name":     str,              # collection.info.name
            "schema":   str,              # detected schema version
            "total":    int,              # total endpoints
            "counts":   {METHOD: int},    # GET/POST/PUT/etc. counts
            "endpoints": [                # flat endpoint list
                {"method": "GET", "url": "...", "name": "...", "folder": "..."},
                ...
            ],
            "folders":  [str],            # unique folder names
            "errors":   [str],            # malformed items / unknown methods
        }
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            return {
                "name": "(invalid)", "schema": "?", "total": 0,
                "counts": {}, "endpoints": [], "folders": [],
                "errors": [f"JSON parse error: {e}"],
            }
    else:
        data = raw

    info = data.get("info", {}) if isinstance(data, dict) else {}
    name = info.get("name") or "Unnamed Collection"
    schema = info.get("schema") or "unknown"

    items = data.get("item", []) if isinstance(data, dict) else []
    endpoints: list[dict] = []
    folders: set[str] = set()
    errors: list[str] = []

    def _walk(items: list, folder_path: list[str]) -> None:
        for it in items:
            if not isinstance(it, dict):
                errors.append("Non-dict item ignored")
                continue
            if "item" in it:
                # Folder (may contain nested folders + requests)
                fname = it.get("name") or "(unnamed folder)"
                folders.add(fname)
                _walk(it.get("item", []), folder_path + [fname])
                continue
            if "request" not in it:
                continue
            req = it["request"]
            if isinstance(req, str):
                # Shorthand: request is just a URL string, method assumed GET
                method = "GET"
                url = req
            else:
                method = (req.get("method") or "GET").upper()
                url = _extract_url(req.get("url"))

            if method not in HTTP_METHODS:
                errors.append(f"Unknown method '{method}' on '{it.get('name')}'")
                continue

            endpoints.append({
                "method":   method,
                "url":      url,
                "name":     it.get("name") or "",
                "folder":   " / ".join(folder_path) if folder_path else "",
            })

    _walk(items, [])

    counts: dict[str, int] = {}
    for e in endpoints:
        counts[e["method"]] = counts.get(e["method"], 0) + 1
    # Stable ordering for display
    ordered_counts = {m: counts.get(m, 0) for m in
                      ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
                      if counts.get(m, 0) > 0}

    return {
        "name":      name,
        "schema":    schema,
        "total":     len(endpoints),
        "counts":    ordered_counts,
        "endpoints": endpoints,
        "folders":   sorted(folders),
        "errors":    errors,
    }


def _extract_url(url: Any) -> str:
    """Postman stores URLs as either a string or a complex object. Normalize."""
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        if url.get("raw"):
            return url["raw"]
        # Build from components
        protocol = url.get("protocol", "")
        host = url.get("host", []) or []
        if isinstance(host, list):
            host = ".".join(host)
        path = url.get("path", []) or []
        if isinstance(path, list):
            path = "/".join(
            p if isinstance(p, str)
            else (p.get("value", "") if isinstance(p, dict) else "")
            for p in path
            if p is not None
        )
        scheme = f"{protocol}://" if protocol else ""
        return f"{scheme}{host}/{path}".rstrip("/")
    return ""


def build_scope_summary(parsed: dict) -> str:
    """Build a human-readable scope summary suitable for the exec summary.

    Example output:
        "The assessment covered 47 API endpoints across 6 functional areas
         (12 GET, 18 POST, 9 PUT, 8 DELETE)."
    """
    if not parsed or not parsed.get("total"):
        return "No API endpoints were imported from the Postman collection."

    parts = []
    for method, n in parsed["counts"].items():
        parts.append(f"{n} {method}")
    method_summary = ", ".join(parts)

    folder_text = ""
    if parsed["folders"]:
        folder_text = f" across {len(parsed['folders'])} functional area{'s' if len(parsed['folders']) != 1 else ''}"

    return (f"The assessment covered {parsed['total']} API endpoint"
            f"{'s' if parsed['total'] != 1 else ''}{folder_text} "
            f"({method_summary}).")
