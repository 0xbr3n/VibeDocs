"""Detect findings where the installed version is already >= the
recommended fix.

Nessus often keeps flagging an "Apache HTTP Server < 2.4.55" finding
after the host has been upgraded to 2.4.58, because the plugin only
inspects the response banner and the banner may still match a
detection pattern Nessus considers vulnerable. In a retest workflow
we can save the consultant a lot of manual triage by scanning the
plugin_output / solution / finding_name text for version numbers and
auto-closing rows whose installed version meets-or-exceeds the
recommended fix.

The detection is INTENTIONALLY conservative:
  - We only fire when BOTH an "installed" and a "fixed/recommended"
    version can be confidently extracted.
  - When the heuristic is unsure (multiple candidates, non-numeric
    suffixes that don't sort cleanly), we mark the row as "uncertain"
    and DO NOT auto-close it.
  - The consultant always sees the final list and confirms before
    anything is closed.

Public surface:
  - ``analyze_version_remediation(df)``: returns the same DataFrame
    with three new columns:
      * ``installed_version``    parsed from plugin_output
      * ``recommended_version``  parsed from solution / synopsis /
                                  finding_name
      * ``version_check_status`` one of ``"remediated"``,
                                  ``"still_vulnerable"``,
                                  ``"unknown"``,
                                  ``"uncertain"``
  - ``flag_already_remediated(df)``: shortcut returning a boolean
    Series of rows where ``version_check_status == "remediated"``.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
import pandas as pd


# Version-number regex. Matches things like:
#   1.2 / 1.2.3 / 1.2.3.4 / 12.7.5 / 1.20.0a1 / 1.20.0-rc1 / v1.20.0
# Anchored on a digit-dot-digit core so we don't catch things like
# "2024" or "8" (a port number) as a version.
_VERSION_NUM_RE = re.compile(
    r"""
    (?<![\w.\-])              # left boundary - not preceded by word/dot/dash
    v?                         # optional leading 'v'
    (\d{1,4}(?:\.\d{1,4}){1,4})   # core: N.N or N.N.N etc, up to 5 segments
    (?:[\-_]?[A-Za-z0-9]{1,12})?  # optional suffix: -rc1, .alpha, _patch1
    (?![\w])                   # right boundary - not followed by word char
    """,
    re.VERBOSE,
)


# Phrases that mark a version as the INSTALLED / OBSERVED one in plugin_output.
_INSTALLED_HINT_PATTERNS = [
    r"installed\s+version",
    r"installed\s+versions?",
    r"\binstalled\s*:",
    r"\bversion\s+installed",
    r"current\s+version",
    r"running\s+version",
    r"remote\s+version",
    r"observed\s+version",
    r"reported\s+version",
    r"server\s+version",
    r"client\s+version",
    r"\bversion\s*:",          # "Version: 1.2.3"
    r"\bversion\s*=",
]

# Phrases that mark a version as the RECOMMENDED / FIXED one.
_FIXED_HINT_PATTERNS = [
    r"fixed\s+version",
    r"fixed\s+in",
    r"fix\s+version",
    r"patched\s+version",
    r"resolved\s+in",
    r"resolved\s+by",
    r"\bupgrade\s+to",
    r"\bupdate\s+to",
    r"\bpatch\s+to",
    r"recommended\s+version",
    r"recommended\s+fix",
    r"recommended\s+upgrade",
    r"vendor\s+has\s+released",
    # Negative-direction phrases let us infer the threshold from
    # "versions prior to X are vulnerable" / "earlier than X".
    r"versions?\s+(?:prior\s+to|before|earlier\s+than|older\s+than|less\s+than)",
    r"\bprior\s+to",
    r"\bearlier\s+than",
    r"<\s*",                   # "Apache < 2.4.55"
]

_INSTALLED_HINT_RE = re.compile(
    r"|".join(f"(?:{p})" for p in _INSTALLED_HINT_PATTERNS), re.IGNORECASE,
)
_FIXED_HINT_RE = re.compile(
    r"|".join(f"(?:{p})" for p in _FIXED_HINT_PATTERNS), re.IGNORECASE,
)


# Per finding-name pattern: "Apache HTTP Server < 2.4.55" / "OpenSSL prior to 3.0"
# The vulnerable threshold (recommended fix) is the version on the right.
_NAME_THRESHOLD_RE = re.compile(
    r"(?:<|prior\s+to|earlier\s+than|older\s+than|before|less\s+than)\s*"
    r"v?(\d{1,4}(?:\.\d{1,4}){1,4})",
    re.IGNORECASE,
)


def _parse_version_tuple(s: str) -> tuple | None:
    """Parse a version string into a tuple of ints suitable for
    ordered comparison. Returns None for un-parseable input.

    Strategy: split on '.', take the leading-digit run of each
    segment. So '1.20.0' -> (1, 20, 0); '1.20.0a1' -> (1, 20, 0).
    Suffix letters / pre-release tags are dropped, which is the
    conservative choice — a "1.20.0a1" should NOT be treated as
    greater-than "1.20.0" without more domain knowledge than this
    heuristic has.
    """
    if not s:
        return None
    parts = s.strip().lstrip("vV").split(".")
    out: list[int] = []
    for p in parts:
        m = re.match(r"^(\d+)", p)
        if not m:
            break
        out.append(int(m.group(1)))
    return tuple(out) if out else None


def _compare_versions(a: str, b: str) -> int:
    """Return -1 if a < b, 0 if equal-as-tuples, +1 if a > b, or
    None when either side fails to parse. Pads the shorter tuple with
    zeros so '1.20' compares equal to '1.20.0' (industry convention)."""
    ta = _parse_version_tuple(a)
    tb = _parse_version_tuple(b)
    if ta is None or tb is None:
        return None
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    if ta < tb: return -1
    if ta > tb: return 1
    return 0


def _find_versions_near_hint(text: str, hint_re: re.Pattern) -> list[str]:
    """Return every version string within a small window (~80 chars)
    after a hint phrase like 'installed version' or 'fix version'.

    Why a window: plugin_output is free-form text, often multi-line.
    A "Fix Version: 1.20.0" hit and the literal "1.20.0" are usually
    in the same line; capturing within 80 chars of the hint avoids
    grabbing an unrelated version from elsewhere on the page (e.g. a
    library version mentioned later).
    """
    if not text:
        return []
    out: list[str] = []
    for hm in hint_re.finditer(text):
        end = hm.end()
        window = text[end : end + 80]
        for vm in _VERSION_NUM_RE.finditer(window):
            v = vm.group(1)
            if v not in out:
                out.append(v)
    return out


@dataclass
class VersionDecision:
    installed: str
    recommended: str
    status: str  # "remediated" / "still_vulnerable" / "unknown" / "uncertain"

    @classmethod
    def unknown(cls) -> "VersionDecision":
        return cls("", "", "unknown")


def decide_for_row(
    plugin_output: str,
    solution: str,
    synopsis: str,
    description: str,
    finding_name: str,
) -> VersionDecision:
    """Inspect a single row's free-text fields and decide whether the
    installed version is >= the recommended fix.

    Search priority for INSTALLED version:
      1. plugin_output windows around "installed/remote/observed/reported"
      2. plugin_output windows around bare "Version:" hints
    Search priority for RECOMMENDED version:
      1. solution windows around "upgrade to / fixed in / patched in"
      2. synopsis windows around the same hints
      3. finding_name "< X" / "prior to X" threshold pattern

    Returns a `VersionDecision`. The `uncertain` status fires when we
    found multiple plausible installed/recommended versions and they
    don't all agree, OR when one side has multiple candidates that
    span both "newer" and "older" than the other side. The CLI never
    auto-closes uncertain rows.
    """
    plug = (plugin_output or "")
    sol  = (solution or "")
    syn  = (synopsis or "")
    desc = (description or "")
    name = (finding_name or "")

    installed_candidates = (
        _find_versions_near_hint(plug, _INSTALLED_HINT_RE)
    )
    recommended_candidates = (
        _find_versions_near_hint(sol, _FIXED_HINT_RE)
        + _find_versions_near_hint(syn, _FIXED_HINT_RE)
        + _find_versions_near_hint(desc, _FIXED_HINT_RE)
    )
    # Name-style "< X" / "prior to X" is a STRONG hint for the recommended
    # threshold — Nessus plugin names canonically encode it this way.
    name_match = _NAME_THRESHOLD_RE.search(name)
    if name_match:
        recommended_candidates.insert(0, name_match.group(1))

    # De-dup while preserving order.
    seen: set[str] = set()
    installed_candidates = [v for v in installed_candidates
                            if not (v in seen or seen.add(v))]
    seen = set()
    recommended_candidates = [v for v in recommended_candidates
                              if not (v in seen or seen.add(v))]

    # Cross-contamination filter: the bare "version :" hint can match
    # text like "Fixed version : 3.0.5" and pull `3.0.5` into the
    # installed bucket. When we have MULTIPLE installed candidates,
    # any that ALSO appear as a recommended candidate are almost
    # always the cross-contaminated copy of the fix version — drop
    # them. The single-installed-candidate case is preserved as-is so
    # the "installed == recommended" (exactly-at-the-fix) scenario
    # still resolves to "remediated" rather than collapsing to
    # "unknown".
    if len(installed_candidates) > 1:
        recommended_set = set(recommended_candidates)
        filtered = [v for v in installed_candidates
                    if v not in recommended_set]
        # Don't strip ALL installed candidates — if every one of them
        # is also recommended, that's a different signal (probably the
        # plugin_output only mentions the fix version) and we keep the
        # list as-is so "uncertain" is the natural outcome.
        if filtered:
            installed_candidates = filtered

    if not installed_candidates or not recommended_candidates:
        return VersionDecision.unknown()

    installed = installed_candidates[0]
    recommended = recommended_candidates[0]

    # Pairwise compare. If ALL installed values are >= all recommended,
    # this row is confidently "remediated". If ALL installed < ALL
    # recommended, it's "still_vulnerable". Otherwise the comparison is
    # ambiguous and we return "uncertain" so the consultant can review.
    results = []
    for i in installed_candidates:
        for r in recommended_candidates:
            cmp = _compare_versions(i, r)
            if cmp is None:
                continue
            results.append(cmp)
    if not results:
        return VersionDecision(installed, recommended, "unknown")
    if all(c >= 0 for c in results):
        return VersionDecision(installed, recommended, "remediated")
    if all(c < 0 for c in results):
        return VersionDecision(installed, recommended, "still_vulnerable")
    return VersionDecision(installed, recommended, "uncertain")


def analyze_version_remediation(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of `df` with three extra columns:
    ``installed_version``, ``recommended_version``, ``version_check_status``.
    See `decide_for_row` for the status values.
    """
    if df is None or len(df) == 0:
        return df.copy() if df is not None else pd.DataFrame()
    df = df.copy().reset_index(drop=True)
    inst: list[str] = []
    rec: list[str] = []
    stat: list[str] = []
    for _, r in df.iterrows():
        d = decide_for_row(
            plugin_output=str(r.get("plugin_output", "") or ""),
            solution=str(r.get("solution", "") or ""),
            synopsis=str(r.get("synopsis", "") or ""),
            description=str(r.get("description", "") or ""),
            finding_name=str(r.get("finding_name", "") or ""),
        )
        inst.append(d.installed)
        rec.append(d.recommended)
        stat.append(d.status)
    df["installed_version"] = inst
    df["recommended_version"] = rec
    df["version_check_status"] = stat
    return df


def flag_already_remediated(df: pd.DataFrame) -> pd.Series:
    """Return a boolean Series indicating which rows are
    confidently remediated (installed >= recommended).
    """
    if df is None or len(df) == 0:
        return pd.Series([], dtype=bool)
    if "version_check_status" not in df.columns:
        annotated = analyze_version_remediation(df)
        return annotated["version_check_status"] == "remediated"
    return df["version_check_status"] == "remediated"


def _installed_version_from_row(row: dict) -> str:
    """Best-effort: pull the single most-likely INSTALLED version from a
    row's plugin_output (falls back to description). Returns "" when
    nothing parses. Used by the cross-scan partial-upgrade detector."""
    for field in ("plugin_output", "Plugin Output", "description",
                   "Description"):
        txt = str(row.get(field, "") or "")
        if not txt:
            continue
        cands = _find_versions_near_hint(txt, _INSTALLED_HINT_RE)
        if cands:
            return cands[0]
    return ""


def _recommended_version_from_row(row: dict) -> str:
    """Best-effort: pull the recommended/fixed version threshold from
    solution / synopsis / finding_name. Mirrors `decide_for_row`'s
    recommended-side search but returns just the first candidate."""
    for field in ("solution", "Solution", "synopsis", "Synopsis",
                  "description", "Description"):
        txt = str(row.get(field, "") or "")
        if not txt:
            continue
        cands = _find_versions_near_hint(txt, _FIXED_HINT_RE)
        if cands:
            return cands[0]
    name = str(row.get("finding_name", "") or row.get("Finding Name", "") or "")
    m = _NAME_THRESHOLD_RE.search(name)
    if m:
        return m.group(1)
    return ""


def analyze_partial_upgrades(
    current_df: pd.DataFrame,
    previous_df: pd.DataFrame | None,
) -> pd.DataFrame:
    """Cross-scan detector for "the client upgraded, but not enough".

    A *partial upgrade* is a finding that:
      1. Still appears in the CURRENT scan (Nessus still flags it), AND
      2. The installed version PARSED FROM plugin_output CHANGED versus
         the same finding on the same host in the PREVIOUS scan/tracker
         (i.e. the version number went UP — the client did patch), AND
      3. The current installed version is STILL BELOW the recommended
         fix (so it's genuinely still vulnerable, not a false positive).

    This is the case the team specifically called out: a host that was
    on Apache 2.4.41, got bumped to 2.4.52, but the fix is 2.4.58 — the
    client clearly acted on the report yet the row is still open. These
    rows deserve a *different* client conversation ("you upgraded but
    need to go further") than a row that never moved, so we surface
    them separately for manual verification rather than auto-closing
    or silently leaving them in the generic open bucket.

    Returns a copy of `current_df` with extra columns:
      * ``prev_installed_version``  — parsed installed version last scan
      * ``curr_installed_version``  — parsed installed version this scan
      * ``recommended_version``     — parsed fix threshold
      * ``partial_upgrade``         — "yes" only when all 3 conditions
                                       hold; "" otherwise.
      * ``partial_upgrade_note``    — human sentence for the reviewer.

    Matching key: (normalised finding_name, ip). Conservative — when
    either side's version can't be parsed the row is left unflagged
    (blank), never a false "yes". The consultant reviews every "yes"
    row manually; nothing here mutates status automatically.
    """
    from .identifiers import normalize_name

    if current_df is None or len(current_df) == 0:
        return current_df.copy() if current_df is not None else pd.DataFrame()
    cur = current_df.copy().reset_index(drop=True)

    # Build a lookup of previous-scan installed versions keyed by
    # (name_norm, ip). Empty when there's no previous source or it
    # carries no parseable plugin_output (e.g. a bare tracker xlsx).
    prev_lookup: dict[tuple[str, str], str] = {}
    if previous_df is not None and len(previous_df):
        for _, pr in previous_df.iterrows():
            pr_d = pr.to_dict()
            nm = normalize_name(
                str(pr_d.get("finding_name",
                    pr_d.get("Finding Name", "")) or ""))
            ip = str(pr_d.get("ip", pr_d.get("Host", "")) or "").strip()
            if not nm or not ip:
                continue
            iv = _installed_version_from_row(pr_d)
            if iv:
                prev_lookup.setdefault((nm, ip), iv)

    prev_iv_col: list[str] = []
    curr_iv_col: list[str] = []
    rec_col: list[str] = []
    flag_col: list[str] = []
    note_col: list[str] = []

    for _, r in cur.iterrows():
        rd = r.to_dict()
        nm = normalize_name(
            str(rd.get("finding_name", rd.get("Finding Name", "")) or ""))
        ip = str(rd.get("ip", rd.get("Host", "")) or "").strip()
        curr_iv = _installed_version_from_row(rd)
        rec_v = _recommended_version_from_row(rd)
        prev_iv = prev_lookup.get((nm, ip), "")

        prev_iv_col.append(prev_iv)
        curr_iv_col.append(curr_iv)
        rec_col.append(rec_v)

        flag = ""
        note = ""
        if prev_iv and curr_iv and rec_v:
            moved_up = _compare_versions(prev_iv, curr_iv)   # -1 => prev<curr
            still_low = _compare_versions(curr_iv, rec_v)     # -1 => curr<rec
            if moved_up == -1 and still_low == -1:
                flag = "yes"
                note = (
                    f"Installed version moved {prev_iv} -> {curr_iv} between "
                    f"scans (client upgraded) but is still below the "
                    f"recommended {rec_v}. Manually verify the residual risk "
                    f"and advise the client to complete the upgrade."
                )
        flag_col.append(flag)
        note_col.append(note)

    cur["prev_installed_version"] = prev_iv_col
    cur["curr_installed_version"] = curr_iv_col
    cur["recommended_version"] = rec_col
    cur["partial_upgrade"] = flag_col
    cur["partial_upgrade_note"] = note_col
    return cur
