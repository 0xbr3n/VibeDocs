"""IP, port, and identifier normalization helpers.

All functions are pure - no I/O, no side effects.
"""
from __future__ import annotations
import hashlib
import re
import pandas as pd

# IPv4 with optional embedded port in (...), [...], {...} (with optional /proto) or :NNNN
_IP_WITH_OPT_PORT = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\b"
    r"(?:"
        r"\s*[\(\[\{]\s*(\d{1,5})(?:\s*/\s*\w+)?\s*[\)\]\}]"
        r"|\s*:\s*(\d{1,5})\b"
    r")?"
)

_IP_ONLY = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_PORT_EMBED_PAT = re.compile(r"(\(\s*\d{1,5}\s*[\)\}]|\[\s*\d{1,5}\s*\]|:\s*\d{1,5}\b)")


def normalize_text(s) -> str:
    """Lowercase, NBSP->space, collapse whitespace, trim."""
    if s is None:
        return ""
    s = str(s).replace("\u00A0", " ").strip().lower()
    return re.sub(r"\s+", " ", s)


def normalize_name(s) -> str:
    """Strong key for finding names: lowercase, drop ALL non-alphanumeric.

    Used to absorb minor Tenable plugin-name revisions across quarters
    (e.g. trailing version markers, parenthetical CVEs, punctuation drift).
    """
    if s is None:
        return ""
    s = str(s).replace("\u00A0", " ").lower()
    return re.sub(r"[^a-z0-9]+", "", s)


def normalize_ip(s) -> str:
    if s is None:
        return ""
    return str(s).strip().lower()


def safe_port(p) -> str:
    """Canonicalize port. 0/blank/nan/non-numeric-junk -> '' (host-level)."""
    if p is None:
        return ""
    s = str(p).strip()
    if not s or s.lower() == "nan":
        return ""
    try:
        f = float(s)
        if int(f) == 0:
            return ""
        return str(int(f))
    except ValueError:
        return s


def normalize_plugin_id(p) -> str:
    """Plugin IDs may be int, float-with-trailing-zero, or string. Canonicalize."""
    if p is None:
        return ""
    s = str(p).strip()
    if not s or s.lower() == "nan":
        return ""
    try:
        return str(int(float(s)))
    except ValueError:
        return s


def extract_ips(cell) -> list[str]:
    """All unique IPv4 addresses in a cell, in order of appearance."""
    text = "" if cell is None else str(cell)
    out, seen = [], set()
    for ip in _IP_ONLY.findall(text):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def extract_first_ip(cell) -> str:
    ips = extract_ips(cell)
    return ips[0] if ips else ""


def extract_ip_port_pairs(cell) -> list[tuple[str, str]]:
    """All unique (ip, port) pairs in a cell.

    Handles common embedding patterns. Multiple pairs per cell is common in
    management risk-acceptance spreadsheets, e.g.:
        '172.156.55.43 (53), 10.0.0.5:443, 192.168.1.1 [8080], 10.0.0.6 (443/tcp)'
    Returns one entry per pair; port is '' if not embedded next to its IP.
    """
    text = "" if cell is None else str(cell)
    out, seen = [], set()
    for m in _IP_WITH_OPT_PORT.finditer(text):
        ip = m.group(1)
        port = m.group(2) or m.group(3) or ""
        key = (ip, safe_port(port))
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def detect_port_embed_ratio(host_series: pd.Series) -> float:
    """Fraction of cells in `host_series` that contain an embedded port pattern.

    Use this to decide whether to parse ports from a Host column or not.
    """
    if host_series is None or len(host_series) == 0:
        return 0.0
    sample = host_series.astype(str).head(500).tolist()
    if not sample:
        return 0.0
    hits = sum(1 for x in sample if _PORT_EMBED_PAT.search(x or ""))
    return hits / len(sample)


# Patterns stripped from plugin_output before hashing — these drift between
# scans of the same finding and would otherwise cause hash mismatches.
# WARNING: be conservative. Bare dates (e.g. cert expiry "2026-09-01") are
# semantic PAYLOAD, not metadata, and must NOT be stripped. We only strip
# patterns that are very likely to be per-scan drift, not finding evidence.
_PLUGIN_OUTPUT_NOISE = [
    # Full ISO datetime WITH time — almost always a scan timestamp, not payload
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ tT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[zZ]|[+-]\d{2}:?\d{2})?\b"),
    # Bare HH:MM:SS (clock time)
    re.compile(r"\b\d{2}:\d{2}:\d{2}\b"),
    # Whole lines like "Last checked: ...", "Verified at: ...", "Scanned: ..."
    re.compile(
        r"(?im)^.*\b(?:last\s+(?:checked|seen|verified|scanned)"
        r"|verified\s+at|scanned\s+at|scan\s+date)\b\s*[:=].*$"
    ),
    # Long hex blobs (session IDs, fingerprints) — 32+ hex chars to avoid
    # eating short MACs, short hex IDs, or hex-looking words
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    # TLS handshake "Random:" / "Server Random:" lines
    re.compile(r"(?im)^\s*(?:server|client)?\s*random\s*[:=].*$"),
]


def normalize_plugin_output(s) -> str:
    """Strip per-scan noise (timestamps, session IDs) from plugin output.

    Goal: produce a string whose value is stable across scans of the SAME
    finding so it can be used as a disambiguator. We deliberately do NOT
    fold whitespace away entirely — line structure carries signal.
    """
    if s is None:
        return ""
    text = str(s)
    # Treat pandas NaN (-> "nan" after str()) and empty strings as empty
    # plugin_output. The OUTPUT_IP / OUTPUT_IP_PORT match tiers use the
    # hash of this string as a primary match key - if NaN-bearing rows
    # produced a stable non-empty hash (the hash of "nan"), two unrelated
    # rows with no plugin_output would collide and match incorrectly.
    if not text or text.strip().lower() == "nan":
        return ""
    text = text.replace(" ", " ")
    for pat in _PLUGIN_OUTPUT_NOISE:
        text = pat.sub("", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip().lower()


def plugin_output_hash(s) -> str:
    """Short stable hash of normalized plugin_output. '' if input is empty.

    16 hex chars (64-bit) is enough collision space for ~10k-row scans and
    keeps the hash visually scannable in diagnostics.
    """
    norm = normalize_plugin_output(s)
    if not norm:
        return ""
    return hashlib.sha1(norm.encode("utf-8", errors="replace")).hexdigest()[:16]


def pick_first_column(df_columns: list[str], candidates: list[str]) -> str | None:
    """First candidate present in df_columns. Strips whitespace; case-sensitive match."""
    cols = {c.strip() for c in df_columns}
    for c in candidates:
        if c in cols:
            return c
    # Case-insensitive fallback
    lower_to_orig = {c.strip().lower(): c.strip() for c in df_columns}
    for c in candidates:
        if c.lower() in lower_to_orig:
            return lower_to_orig[c.lower()]
    return None
