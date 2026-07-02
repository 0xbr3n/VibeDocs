"""Library placeholder sanitiser.

The XML knowledge-base seeded under `seed_data/Knowledgebase.xml` (and
some legacy seed paths) ships findings whose prose still contains
authoring prompts the consultant was expected to overwrite —
`[DELETE IF IRRELEVANT]`, `[DESBCRIBE HOW THIS WAS PERFORMED]`,
`#code#\\nRequest\\n#/code#`, etc.

The seeder is idempotent (skip-if-title-exists), so these placeholders
have been carried forward indefinitely. The product direction is now:
the consultant must NOT have to rewrite description / impact /
remediation / references — those are owned by the library. The only
per-engagement fields are `affected_asset`, `poc_steps`, and the CVSS
score.

This module provides a deterministic transform that walks every
`FindingLibrary` row and rewrites those four fields so they no longer
carry authoring artefacts. The transform is intentionally non-AI:
every rule below has a known input → known output mapping, so the
admin can audit the change in `git diff` and re-run safely.

`run_sanitiser(db)` returns a structured summary the admin endpoint
serialises straight back to the UI.
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from ..models import FindingLibrary

logger = logging.getLogger(__name__)


# ============================================================
# Transform rules
# ============================================================
#
# Each rule is (compiled_pattern, replacement_str). They run in order
# so earlier rules can normalise input the later rules count on.
#
# Replacement strings are deliberately neutral — they do not invent
# engagement-specific evidence. The goal is to remove placeholder
# RESIDUE, not to populate the field with fabricated detail.


# 1) "[DELETE IF IRRELEVANT]" / "[DELETE AS APPROPRIATE]" /
#    "[DELETE WHEN NOT NEEDED]" / variants — these tokens were
#    authoring flags the consultant was expected to remove. The
#    sentence around them usually reads fine without the marker, so
#    we strip the marker and let the prose stand.
_DELETE_IF_IRRELEVANT = re.compile(
    r"\s*\[\s*DELETE\b[A-Za-z ]*\]\s*",
    re.IGNORECASE,
)

# 2) "[DESBCRIBE HOW THIS WAS PERFORMED]" (note the typo —
#    canonical to the team's knowledge base) and the spelt variant
#    "[DESCRIBE HOW THIS WAS PERFORMED]". Used as a prompt the
#    consultant was expected to overwrite with engagement-specific
#    repro detail. The replacement leaves a neutral sentence that
#    works for every report; engagement-specific repro now belongs
#    in `ReportFinding.poc_steps`.
#
#    The character class `[BC]{0,2}` between `DES` and `RIBE`
#    accepts every spelling the team has shipped historically:
#    `DESCRIBE` (correct), `DESBRIBE`, and `DESBCRIBE` (the XML
#    knowledge-base typo). Two-char window is enough — anything
#    longer is unlikely.
_DESCRIBE_PERFORMED = re.compile(
    r"\bThis\s+was\s+performed\s+by\s+\[DES[BC]{0,2}RIBE\s+HOW\s+THIS\s+WAS\s+PERFORMED\]\.?",
    re.IGNORECASE,
)
_DESCRIBE_PERFORMED_BARE = re.compile(
    r"\[DES[BC]{0,2}RIBE\s+HOW\s+THIS\s+WAS\s+PERFORMED\]",
    re.IGNORECASE,
)

# 3) "[ENTER YOUR EVIDENCE]" / "[REPLACE WITH ...]" /
#    "[SCREENSHOT HERE]" / "[INSERT ...]" — generic prompt tokens.
#    Removing the entire bracketed token plus surrounding whitespace
#    is the safest deterministic transform.
_GENERIC_BRACKETED_PROMPT = re.compile(
    r"\[\s*(?:ENTER|REPLACE|INSERT|SCREENSHOT|EVIDENCE|TBA|TBC|TBD|PLACEHOLDER)"
    r"[A-Z0-9 _/&\-]*\]",
    re.IGNORECASE,
)

# 4) Catch-all for ALL-CAPS bracketed prompts the targeted rules
#    didn't already strip. Requires the inner text to contain a
#    SPACE (i.e. multi-word) so single hyphenated tokens like
#    `[CVE-2024-1234]`, `[CWE-79]`, `[RFC-7540]`, `[A01:2021]` are
#    preserved as legitimate references. Widened to accept periods,
#    commas, and parens so long author notes like `[INSERT
#    SCREENSHOT OF BURP INTRUDER SHOWING A SUCCESSFUL ACCOUNT
#    LOCKOUT. THE NARRATIVE SHOULD MAKE DISTINCTION...]` are caught.
_ALL_CAPS_BRACKETED = re.compile(
    r"\[(?=[^a-z\]]*[A-Z]{3})"
    r"(?=[^\]]*\s[A-Z]{2})"               # space then ≥2 caps letters
    r"[A-Z0-9 _/&\-\.,;:'()]+\]"
)

# 5) Short author tokens — `[XX]`, `[XXX]`, `[YY]`, `[NN]`, `[N]`,
#    `[INSERT]` (when it landed alone). Numeric-only bracketed refs
#    like `[1]`, `[2]` survive because they don't match.
_SHORT_AUTHOR_TOKEN = re.compile(
    r"\[(?:X{1,4}|Y{1,4}|N{1,4}|INSERT|EDIT|FILL|VALUE|NUMBER|"
    r"AMOUNT|COUNT|TIME)\]",
    re.IGNORECASE,
)

# 6) Lowercase / mixed-case bracketed prompt phrases. The legacy XML
#    knowledge base wraps optional sentences with brackets like
#    `[automatically unlock accounts after N period of time]` —
#    the consultant was expected to either rewrite or drop them.
#    Match a bracket pair that contains AT LEAST TWO WORDS — the
#    lookahead `(?=[^\]]*\s[A-Za-z])` enforces a space followed by
#    another letter inside the brackets, so single-token shorthand
#    like `[iOS]`, `[v1.2]`, `[CVE-2024-1234]`, `[CWE-79]` is
#    preserved (no internal space). `[RFC 7540]` does have a space
#    but the digit-then-end means no second WORD — also preserved.
#    The body pattern is non-greedy + capped at ~300 chars per
#    match so it never swallows giant code-fenced regions.
_PROMPT_PHRASE = re.compile(
    r"\[(?=[^\]]*\s[A-Za-z])"               # ≥1 space then a letter
    r"[A-Za-z][A-Za-z0-9 ,.;:/&'\"\-]{8,300}?\]"
)

# 5) Empty `Request` / `Response` code blocks (the XML knowledge base
#    seeded these as `#code#Request#/code#` which then became
#    ```\nRequest\n``` once converted to markdown). They convey
#    nothing in the library entry — the consultant fills the real
#    evidence in their finding's `poc_steps` field instead.
_EMPTY_REQUEST_BLOCK = re.compile(
    r"```\s*\n?\s*(?:request|response|req|res|http\s+request|http\s+response)\s*\n?\s*```",
    re.IGNORECASE,
)

# 6) The `**Request:**` / `**Response:**` headers that precede the
#    empty code blocks above. Once the block is gone the bold-marker
#    label sits there orphaned; drop it too.
_ORPHAN_REQ_RES_HEADER = re.compile(
    r"\*\*\s*(?:Request|Response)\s*:\s*\*\*\s*\n*",
    re.IGNORECASE,
)

# 7) The literal phrase "Evidence template" — surface signal of the
#    legacy seeded ASP.NET-family findings that bake the word into
#    body prose. Replaced with a neutral lead-in.
_EVIDENCE_TEMPLATE = re.compile(
    r"\bEvidence\s+template\b\s*[:\.]?",
    re.IGNORECASE,
)

# 8) TODO / FIXME / TBD / XXX markers inside prose. Strip outright —
#    they are author-side breadcrumbs.
_AUTHOR_MARKER = re.compile(
    r"\b(?:TODO|FIXME|TBD|XXX)\b\s*[:\-]?\s*",
    re.IGNORECASE,
)

# 9) "Lorem ipsum" filler.
_LOREM_IPSUM = re.compile(
    r"\bLorem\s+ipsum[^.\n]*\.?\s*",
    re.IGNORECASE,
)

# 10) Plain-text prompt sentences without brackets. These leaked from
#     the original XML pseudo-markup into rendered library entries.
#     Removing the entire sentence is safer than partial replacement.
_PLAIN_PROMPT_SENTENCE = re.compile(
    r"(?:^|\.\s+|\n)[^.\n]*?"
    r"\b(?:"
    r"paste\s+(?:the\s+)?(?:request|response)\s+here"
    r"|insert\s+(?:screenshot|evidence)\s+here"
    r"|screenshot\s+goes\s+here"
    r"|replace\s+with\s+(?:your|engagement|client)[^.\n]*"
    r")\b[^.\n]*\.?",
    re.IGNORECASE,
)


# Compound replacement list — `(pattern, replacement)`. Order matters
# (see comments above). `replacement` may be a plain string or a
# callable receiving the match.
_RULES: list[tuple[re.Pattern, object]] = [
    (_DELETE_IF_IRRELEVANT, " "),
    (_DESCRIBE_PERFORMED, "The condition was confirmed through manual testing during the engagement."),
    (_DESCRIBE_PERFORMED_BARE, "manual testing during the engagement"),
    (_GENERIC_BRACKETED_PROMPT, ""),
    (_SHORT_AUTHOR_TOKEN, ""),
    (_EMPTY_REQUEST_BLOCK, ""),
    (_ORPHAN_REQ_RES_HEADER, ""),
    (_EVIDENCE_TEMPLATE, "Evidence for this finding is recorded in the report's per-finding Steps to Reproduce section."),
    (_AUTHOR_MARKER, ""),
    (_LOREM_IPSUM, ""),
    (_PLAIN_PROMPT_SENTENCE, ""),
    # Strip any leftover all-caps bracketed prompts the specific
    # rules didn't already cover. Runs LAST so the rules above had
    # their chance to do targeted replacements.
    (_ALL_CAPS_BRACKETED, ""),
    # Lowercase / mixed-case bracketed phrases. Runs after the
    # all-caps catcher so canonical `[INSERT SCREENSHOT OF BURP
    # INTRUDER…]` and similar caught earlier don't get touched
    # again by the broader matcher.
    (_PROMPT_PHRASE, ""),
]


# Whitespace tidy-ups applied after every rule pass.
_WS_RUNS    = re.compile(r"[ \t]{2,}")
_BLANK_LINES = re.compile(r"\n{3,}")
_TRAILING_WS = re.compile(r"[ \t]+\n")


def _post_clean(text: str) -> str:
    text = _WS_RUNS.sub(" ", text)
    text = _TRAILING_WS.sub("\n", text)
    text = _BLANK_LINES.sub("\n\n", text)
    return text.strip()


# Fields we sanitise. NOT `title` — the rules can eat tokens like
# "[ANDROID]" prefixes that the XML loader uses for routing, and
# `title` is short enough that placeholders are spotted by eye.
_SANITISED_FIELDS = ("description", "impact", "remediation", "references")


def sanitise_text(value: Optional[str]) -> tuple[str, int]:
    """Apply every rule in order. Returns `(cleaned_text, hits)` where
    `hits` is the total number of substitutions made.

    Multi-pass: the rule chain is run up to 3 times because the
    legacy XML knowledge base sometimes nests prompts inside other
    prompts (e.g. `[automatically unlock accounts after [XX] period
    of time]`). After the inner `[XX]` is stripped, the outer
    `[automatically …]` becomes a normal phrase pattern that the
    next pass can clean. Three passes is enough for every nesting
    depth we've seen; we stop early when a pass changes nothing.

    None input round-trips to an empty string with zero hits, which
    is safe to write back to the DB.
    """
    if not value:
        return "", 0
    out = value
    hits = 0
    for _ in range(3):
        pass_hits = 0
        for pat, repl in _RULES:
            out, n = pat.subn(repl, out)
            pass_hits += n
        hits += pass_hits
        if pass_hits == 0:
            break
    out = _post_clean(out)
    return out, hits


@dataclass
class _RowReport:
    id: int
    title: str
    fields_changed: list[str] = field(default_factory=list)
    hits: int = 0


@dataclass
class SanitiseSummary:
    rows_scanned: int = 0
    rows_modified: int = 0
    total_hits: int = 0
    per_field: dict[str, int] = field(default_factory=dict)
    sample_changes: list[_RowReport] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rows_scanned": self.rows_scanned,
            "rows_modified": self.rows_modified,
            "total_hits": self.total_hits,
            "per_field": self.per_field,
            "sample_changes": [
                {"id": r.id, "title": r.title,
                 "fields_changed": r.fields_changed, "hits": r.hits}
                for r in self.sample_changes
            ],
        }


def run_sanitiser(db: Session, *, dry_run: bool = False,
                   sample_limit: int = 25) -> SanitiseSummary:
    """Walk every `FindingLibrary` AND `ReportFinding` row, apply the
    rules, and persist the cleaned values. Returns a summary with
    counts plus the first `sample_limit` modified rows for the admin
    UI.

    Why ReportFinding too: a clean library row only helps NEW report
    findings. Findings the consultant already pulled into a report
    BEFORE the sweep keep their placeholder text — until the
    sanitiser clears them here. Both tables share the same shape
    (description / impact / remediation / references), so the same
    rule chain applies.

    `dry_run=True` reports what WOULD change without committing.
    """
    from ..models import ReportFinding

    summary = SanitiseSummary()

    def _scan_rows(rows: Iterable, row_kind: str) -> None:
        for row in rows:
            summary.rows_scanned += 1
            row_hits = 0
            fields_changed: list[str] = []
            for field_name in _SANITISED_FIELDS:
                original = getattr(row, field_name, None)
                cleaned, hits = sanitise_text(original)
                if hits > 0 and cleaned != (original or ""):
                    if not dry_run:
                        setattr(row, field_name, cleaned)
                    fields_changed.append(field_name)
                    summary.per_field[field_name] = \
                        summary.per_field.get(field_name, 0) + hits
                    row_hits += hits
            if row_hits:
                summary.rows_modified += 1
                summary.total_hits += row_hits
                if len(summary.sample_changes) < sample_limit:
                    summary.sample_changes.append(_RowReport(
                        id=row.id,
                        title=f"[{row_kind}] " + ((row.title or "(untitled)")[:110]),
                        fields_changed=fields_changed,
                        hits=row_hits,
                    ))

    _scan_rows(db.query(FindingLibrary).all(), "library")
    _scan_rows(db.query(ReportFinding).all(), "report")

    if not dry_run and summary.rows_modified:
        db.commit()
    return summary
