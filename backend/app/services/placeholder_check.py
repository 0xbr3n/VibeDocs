"""
Unresolved-placeholder detection for library findings.

Library findings ship with bracketed prompts the consultant is meant to
replace before the finding ends up in a real report — `[DESCRIBE HOW THIS
WAS PERFORMED]`, `[DELETE IF IRRELEVANT]`, `[ENTER ...]`, sometimes a code
block literally containing the word "Request" or "Response" with nothing
else. Without a gate, those prompts ride straight into the delivered DOCX.

This module exposes the regex set and a small `scan_finding(...)` helper
used in two places:

  1. `GET /api/reports/findings/{fid}/placeholders` and the version-level
     bulk variant — the UI calls these so it can show "needs customisation"
     badges and a confirmation modal.
  2. The reviewer gate in the submit/decision flow — a version with any
     finding still containing unresolved tokens cannot be approved or
     published. The consultant has to clean them up first.

The check is deliberately permissive on text fields that are blank — a
*missing* description is a separate validation concern; this module only
flags text that *looks unresolved*. That way enabling the gate doesn't
suddenly fail every legacy finding that simply has no description yet.
"""
from __future__ import annotations
import re
from html import unescape as _html_unescape


# Fields on ReportFinding (and FindingLibrary, which shares the shape)
# whose prose is rendered into the delivered DOCX. Title is included so
# placeholder leakage in the heading is caught too.
_SCANNED_FIELDS = (
    "title",
    "description",
    "impact",
    "remediation",
    "references",
    "affected_asset",
    "poc_steps",
)

# Patterns we consider "still a placeholder". Designed conservative — if it
# can plausibly be the author's intentional copy, we don't flag it.
# Each entry: (label_shown_in_UI, compiled_regex)
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Square-bracket prompts. Matches [DESCRIBE ...], [DELETE IF IRRELEVANT],
    # [ENTER YOUR EVIDENCE], [SCREENSHOT HERE], [REPLACE WITH ...], etc.
    # Requires ALL-CAPS so it doesn't trigger on things like "[CVE-2024-...]".
    ("bracketed_prompt",
     re.compile(r"\[(?:[A-Z][A-Z0-9 _/&\-]{2,}?)\]")),

    # Curly-brace template-style placeholders e.g. {{CLIENT_NAME}} that
    # leaked from a Word template into a library entry.
    ("curly_placeholder",
     re.compile(r"\{\{\s*[A-Z][A-Z0-9_]+\s*\}\}")),

    # Standalone TODO/FIXME/TBD markers in the body of a field.
    ("todo_marker",
     re.compile(r"\b(?:TODO|FIXME|TBD|XXX)\b")),

    # "Lorem ipsum" / placeholder filler text.
    ("lorem_ipsum",
     re.compile(r"\blorem\s+ipsum\b", re.IGNORECASE)),

    # Label-only evidence — the literal phrase "Evidence template" or
    # "Request:" / "Response:" appearing in body copy without anything
    # after it. Catches the seeded ASP.NET-style findings whose
    # "evidence template" rides verbatim into the deliverable.
    ("template_header",
     re.compile(r"\bevidence\s+template\b", re.IGNORECASE)),

    # Un-customised prompt phrases that show up *without* the brackets
    # (some seed findings store the prompt as plain text). Conservative
    # set — we only flag phrases that are clearly template guidance.
    ("plain_prompt",
     re.compile(
         r"\b(?:"
         r"describe\s+how\s+this\s+was\s+performed"
         r"|delete\s+if\s+irrelevant"
         r"|replace\s+with\s+(?:your|engagement|client)"
         r"|insert\s+(?:screenshot|evidence)\s+here"
         r"|screenshot\s+goes\s+here"
         r"|paste\s+(?:the\s+)?(?:request|response)\s+here"
         r")\b", re.IGNORECASE)),
]

# Code-block evidence whose text content is *only* the literal word
# "Request" or "Response" (with no actual data). We tolerate any wrapping
# markup — Quill emits `<pre><code>...</code></pre>`, raw `<pre>...</pre>`,
# or `<code>...</code>`, sometimes with `&nbsp;` or whitespace padding.
# Strategy: strip nested tags inside the outer code/pre block, then check
# whether the remaining text is just the label.
_CODE_BLOCK = re.compile(
    r"<(?P<tag>pre|code)\b[^>]*>(?P<body>.*?)</(?P=tag)>",
    re.IGNORECASE | re.DOTALL,
)
_LABEL_ONLY = re.compile(
    r"^\s*(?:request|response|req|res|http\s+request|http\s+response)\s*[:\.]?\s*$",
    re.IGNORECASE,
)


def _label_only_evidence_blocks(html: str) -> list[str]:
    """Return any <pre>/<code> blocks whose plain text is just the word
    'Request' / 'Response' / similar — i.e. an evidence placeholder the
    consultant never replaced with real captured data."""
    hits: list[str] = []
    for m in _CODE_BLOCK.finditer(html or ""):
        body = m.group("body")
        # Strip nested tags + entities, then test against the label-only pattern.
        plain = _html_unescape(re.sub(r"<[^>]+>", "", body)).replace(" ", " ")
        if _LABEL_ONLY.match(plain):
            hits.append(m.group(0)[:120])
    return hits


def _strip_html_tags(s: str) -> str:
    """Crude tag stripper for HTML-rich fields. We don't need a parser —
    we're looking for placeholder text, not parsing structure."""
    return re.sub(r"<[^>]+>", " ", s or "")


def scan_text(text: str) -> list[dict]:
    """Return a list of `{kind, snippet}` matches for unresolved tokens
    in `text`. Empty list = no problems."""
    if not text:
        return []
    plain = _html_unescape(_strip_html_tags(text))
    hits: list[dict] = []
    for kind, pat in _PATTERNS:
        for m in pat.finditer(plain):
            hits.append({"kind": kind, "snippet": m.group(0)})

    # Label-only evidence blocks — scanned against the HTML, not the
    # stripped text, so we can detect the <pre><code>Request</code></pre>
    # shape regardless of wrapping markup variants.
    for snippet in _label_only_evidence_blocks(text):
        hits.append({"kind": "empty_evidence", "snippet": snippet})
    return hits


def scan_finding(obj) -> dict:
    """Scan every renderable text field on a finding-like object (either a
    `ReportFinding` SQLAlchemy row or a dict-shaped equivalent).

    Returns:
        {
          "ok":              bool,             # True if no unresolved tokens
          "field_issues":    {field: [hits]},  # per-field bracket / prompt hits
          "missing_fields":  [str],            # consultant-fillable fields blank
          "total":           int,
        }

    What counts as "ok" since the library-sanitiser shipped:

      1. NONE of the consultant-fillable fields is blank. These three
         fields are owned by the engagement, not by the library:
             - `affected_asset`
             - `poc_steps`
             - CVSS — at least one of `cvss_score` / `cvss_vector`
      2. AND no bracketed / prompt token leaked into any scanned text
         field (caught for paranoia — the sanitiser strips them at
         seed time, so a real hit here means someone hand-typed one).

    The product direction is: the consultant should ONLY see the
    orange "needs customisation" prompt for missing engagement fields.
    Library prose is pre-filled and signed off centrally — they don't
    rewrite it. The bracket-token scan stays as defence-in-depth (in
    case a custom finding is added by hand with a stray placeholder).
    """
    field_issues: dict[str, list[dict]] = {}
    total = 0
    for field in _SCANNED_FIELDS:
        val = obj.get(field) if isinstance(obj, dict) else getattr(obj, field, None)
        if not val:
            continue
        hits = scan_text(str(val))
        if hits:
            field_issues[field] = hits
            total += len(hits)

    # ---- Missing-engagement-field check ----
    def _get(name: str):
        return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)

    missing_fields: list[str] = []
    for required in ("affected_asset", "poc_steps"):
        v = _get(required)
        if v is None or (isinstance(v, str) and not v.strip()):
            missing_fields.append(required)

    # CVSS: require BOTH a vector AND a score.
    # A vector alone is not enough — the numeric score is shown in
    # every exported tracker/report column and reviewers use it at a
    # glance. If only the vector is present, flag cvss_score as missing
    # so the consultant gets an in-card prompt to also fill the score.
    # NOTE: 0 is a valid score (Informational severity) — only None / ""
    # means the score has never been set.
    cvss_score  = _get("cvss_score")
    cvss_vector = _get("cvss_vector")
    has_vector = bool(isinstance(cvss_vector, str) and cvss_vector.strip())
    has_score  = cvss_score is not None and cvss_score != ""
    if not has_vector and not has_score:
        missing_fields.append("cvss")
    elif has_vector and not has_score:
        missing_fields.append("cvss_score")

    return {
        "ok": total == 0 and not missing_fields,
        "field_issues": field_issues,
        "missing_fields": missing_fields,
        "total": total,
    }


def summarise_unresolved(findings: list) -> dict:
    """Bulk scan: useful for the reviewer-gate path. Takes any iterable of
    finding rows / dicts; returns a per-finding summary plus an aggregate
    list of titles that still contain unresolved tokens.

    Used by the submit-for-review and review-decision endpoints to short
    circuit the workflow with a 400 + a structured payload the UI can
    render directly.
    """
    per_finding: list[dict] = []
    blockers: list[str] = []
    for f in findings:
        res = scan_finding(f)
        fid = f.get("id") if isinstance(f, dict) else getattr(f, "id", None)
        title = f.get("title") if isinstance(f, dict) else getattr(f, "title", "(untitled)")
        per_finding.append({
            "id": fid,
            "title": title,
            **res,
        })
        if not res["ok"]:
            blockers.append(title or f"finding #{fid}")
    return {
        "all_ok": not blockers,
        "blocker_count": len(blockers),
        "blocker_titles": blockers,
        "findings": per_finding,
    }
