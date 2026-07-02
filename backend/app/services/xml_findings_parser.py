"""
Parser for the team's XML knowledge base of findings.

The XML uses inline pseudo-markup tags like #bullet#...#/bullet#, #code#...#/code#,
#scope#...#/scope#, #bold#...#/bold#, #italic#...#/italic#, #list#...#/list#,
#highlight#...#/highlight#. These are converted to Markdown so the prose
renders cleanly in the editor and the generated DOCX.

XML schema:
  <Records>
    <Record>
      <ID>0</ID>
      <Vulnerability_Name>Unverified Password Change</Vulnerability_Name>
      <Vulnerability_Description>...</Vulnerability_Description>
      <Vulnerability_Evidence>...</Vulnerability_Evidence>
      <Vulnerability_Impact>...</Vulnerability_Impact>
      <Vulnerability_Recommendation>...</Vulnerability_Recommendation>
      <Further_Information>...</Further_Information>
      <abs_scoring>...</abs_scoring>
    </Record>
    ...
  </Records>

Each record maps to a FindingLibrary row. The PT type (which ReportTemplate to
scope the finding under) is inferred from:
  1. Explicit prefix in the title like [ANDROID], [iOS], [WEB], [API]
  2. Keyword heuristic on title + description if no prefix

Library entries land with status='approved' since the XML database is
already curated by the team. Admins can re-review individual entries later.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Optional, Iterable
import defusedxml.ElementTree as ET


# ============================================================
# Inline markup → Markdown conversion
# ============================================================

_TAG = re.compile(r"#(/?\w+)#")


def _convert_inline_markup(text: str) -> str:
    """Convert the team's #tag# syntax to Markdown-flavoured plain text.

    Mapping:
      #scope#...#/scope#       → "### {label}\n" (used as section headings:
                                  'Affected Resources', 'Affected Cookie' etc.)
      #bullet#...#/bullet#     → each non-empty line gets a "- " prefix
      #list#...#/list#         → numbered list
      #code#...#/code#         → triple-backtick code fence
      #bold#...#/bold#         → **...**
      #italic#...#/italic#     → *...*
      #highlight#...#/highlight# → ==...== (kept simple; renderer can style)

    Unknown tags are stripped silently rather than failing — better to ship
    slightly-imperfect prose than to break the seed flow.
    """
    if not text:
        return ""
    text = text.replace("&#39;", "'").replace("&quot;", '"')

    def _wrap_bullet(body: str) -> str:
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        return "\n".join(f"- {ln}" for ln in lines)

    def _wrap_list(body: str) -> str:
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        return "\n".join(f"{i+1}. {ln}" for i, ln in enumerate(lines))

    def _wrap_scope(body: str) -> str:
        label = body.strip().splitlines()[0] if body.strip() else "Affected Resources"
        return f"### {label}"

    def _wrap_code(body: str) -> str:
        return f"```\n{body.strip()}\n```"

    REPLACERS = {
        "scope":     ("",            _wrap_scope),
        "bullet":    ("",            _wrap_bullet),
        "list":      ("",            _wrap_list),
        "code":      ("",            _wrap_code),
        "bold":      ("**", "**"),
        "italic":    ("*",  "*"),
        "highlight": ("==", "=="),
    }

    # Process tags one at a time, repeatedly, until none remain
    for _ in range(20):
        opens = list(_TAG.finditer(text))
        if not opens:
            break
        progressed = False
        for m in opens:
            tag = m.group(1)
            if tag.startswith("/") or tag not in REPLACERS:
                continue
            close_pat = re.compile(r"#/" + re.escape(tag) + r"#")
            close_m = close_pat.search(text, m.end())
            if not close_m:
                continue  # malformed; skip
            inner = text[m.end():close_m.start()]
            spec = REPLACERS[tag]
            if callable(spec[1]):
                converted = spec[1](inner)
            else:
                converted = f"{spec[0]}{inner.strip()}{spec[1]}"
            text = text[:m.start()] + converted + text[close_m.end():]
            progressed = True
            break
        if not progressed:
            break

    # Strip any leftover lone tags
    text = _TAG.sub("", text)
    # Collapse 3+ blank lines
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


# ============================================================
# PT-type inference
# ============================================================

_WEB_HINTS = {"http", "cookie", "cors", "session", "xss", "csrf", "header",
              "browser", "jwt", "saml", "tls", "ssl", "cipher", "web",
              "form", "csp", "x-frame", "hsts", "redirect", "url", "captcha"}
_API_HINTS = {"api", "graphql", "rest", "json", "xml external", "xxe",
              "endpoint", "mass assignment", "bola", "bfla", "swagger"}
_MOBILE_HINTS = {"mobile", "android", "ios", "apk", "ipa", "task switcher",
                 "screenshot", "minimise", "logout on", "webview", "pinning",
                 "root", "jailbreak", "tapjacking", "database", "storage",
                 "anti-debug", "obfuscat"}
_INFRA_HINTS = {"port", "service", "smb", "ssh", "dns", "firewall", "snmp",
                "default cred", "patch", "outdated", "nessus", "telnet",
                "ftp", "ldap", "kerberos", "asa firmware"}


def _infer_template_code(name: str, description: str = "") -> str:
    """Best-effort mapping from vuln name+description to ReportTemplate.code."""
    name_u = name.upper()

    # Explicit platform prefix wins
    m = re.match(r"^\[([^\]]+)\]", name_u)
    if m:
        prefix = m.group(1).upper()
        if "ANDROID" in prefix or "IOS" in prefix:
            return "mobile_pt"
        if "API" in prefix:
            return "api_vapt"
        if "WEB" in prefix:
            return "web_vapt"
        if "INFRA" in prefix or "NETWORK" in prefix:
            return "infra_va"

    haystack = (name + " " + description).lower()
    scores = {
        "web_vapt":  sum(1 for h in _WEB_HINTS  if h in haystack),
        "api_vapt":  sum(1 for h in _API_HINTS  if h in haystack),
        "mobile_pt": sum(1 for h in _MOBILE_HINTS if h in haystack),
        "infra_va":  sum(1 for h in _INFRA_HINTS  if h in haystack),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "web_vapt"


def _strip_prefix(name: str) -> str:
    """Drop the [ANDROID]/[iOS] prefix so the library title reads cleanly."""
    return re.sub(r"^\[[^\]]+\]\s*", "", name).strip()


# ============================================================
# Reference extraction (CWE / OWASP) from Further_Information
# ============================================================

_CWE_PAT = re.compile(r"CWE-\d+", re.I)
# The team's XML uses formats like:
#   OWASP Top 10-2017 A2-Broken Authentication
#   OWASP Top 10 2013: A5 - Security Misconfiguration
#   OWASP Top Ten 2010 Category A4 - Insecure Direct Object References
# Capture year and category code into a normalised "A2:2017" form.
_OWASP_PAT = re.compile(
    r"OWASP\s+Top\s+(?:10|Ten)[-\s]*(\d{4})[^A-Za-z]*"
    r"(?:Category\s+)?(A\d{1,2}|API\d{1,2}|M\d{1,2})",
    re.I,
)


def _extract_refs(further_info: str) -> tuple[Optional[str], Optional[str], list[str]]:
    """Pull (cwe, owasp_category, tags) from the Further_Information blob."""
    cwe = None
    owasp = None
    tags: list[str] = []
    if not further_info:
        return cwe, owasp, tags

    cwe_m = _CWE_PAT.search(further_info)
    if cwe_m:
        cwe = cwe_m.group(0).upper()
        tags.append(cwe.lower())

    owasp_m = _OWASP_PAT.search(further_info)
    if owasp_m:
        year, code = owasp_m.group(1), owasp_m.group(2).upper()
        owasp = f"{code}:{year}"           # e.g. "A2:2017"
        tags.append("owasp")
        tags.append(owasp.lower())

    return cwe, owasp, tags


# ============================================================
# Severity guess (XML doesn't ship one; admins refine later)
# ============================================================

_CRITICAL_KW = {"sql injection", "remote code execution", "rce", "command injection",
                "authentication bypass", "privilege escalation", "deserialization"}
_HIGH_KW = {"xxe", "ssrf", "stored xss", "idor", "insecure direct object",
            "csrf", "sensitive information", "path traversal", "open redirect",
            "broken access", "mass assignment", "weak crypt"}
_LOW_KW = {"information disclosure", "verbose error", "directory listing",
           "version disclosure", "banner grab", "clickjacking", "tapjacking"}


def _guess_severity(name: str, impact: str = "") -> str:
    haystack = (name + " " + impact).lower()
    if any(k in haystack for k in _CRITICAL_KW):
        return "Critical"
    if any(k in haystack for k in _HIGH_KW):
        return "High"
    if any(k in haystack for k in _LOW_KW):
        return "Low"
    return "Medium"


# ============================================================
# Public API
# ============================================================

def parse_xml_knowledgebase(xml_path: Path) -> list[dict]:
    """Parse the XML file and return a list of dicts ready to insert.

    Each dict has the fields FindingLibrary expects, plus a `template_code`
    string so the seeder can resolve the template_id.
    """
    if not xml_path.exists():
        raise FileNotFoundError(f"Knowledge base XML not found: {xml_path}")

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise ValueError(f"Knowledge base XML is malformed: {exc}") from exc
    root = tree.getroot()
    out: list[dict] = []

    for rec in root.findall("Record"):
        name = (rec.findtext("Vulnerability_Name") or "").strip()
        if not name:
            continue
        desc = _convert_inline_markup(rec.findtext("Vulnerability_Description") or "")
        evidence = _convert_inline_markup(rec.findtext("Vulnerability_Evidence") or "")
        impact = _convert_inline_markup(rec.findtext("Vulnerability_Impact") or "")
        remediation = _convert_inline_markup(rec.findtext("Vulnerability_Recommendation") or "")
        further = _convert_inline_markup(rec.findtext("Further_Information") or "")

        template_code = _infer_template_code(name, desc)
        cwe, owasp, ref_tags = _extract_refs(rec.findtext("Further_Information") or "")
        severity = _guess_severity(name, impact)
        clean_title = _strip_prefix(name)

        # Combine evidence into description if non-trivial -- the team's
        # XML evidence section is usually a template stub (placeholder PoC)
        # that consultants fill in per-engagement. We don't want it as
        # a separate library field but it's useful context.
        full_description = desc
        if evidence and len(evidence) > 40:
            full_description = f"{desc}\n\n#### Evidence template\n\n{evidence}"

        # Build a tags list combining inferred type + CWE/OWASP
        tags = list({template_code, *ref_tags})

        out.append({
            "template_code":       template_code,
            "title":               clean_title or name,
            "original_title":      name,        # preserves [ANDROID] prefix etc.
            "description":         full_description,
            "impact":              impact,
            "remediation":         remediation,
            "references":          further,
            "default_severity":    severity,
            "default_cvss_vector": None,        # XML doesn't ship a vector
            "default_cvss_score":  None,
            "cwe":                 cwe,
            "owasp_category":      owasp,
            "tags":                tags,
            "status":              "approved",  # team-curated DB
            "xml_source_id":       rec.findtext("ID"),
        })

    return out


def summarize(records: list[dict]) -> dict:
    """Quick stats dict for seed-time logging."""
    by_template: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in records:
        by_template[r["template_code"]] = by_template.get(r["template_code"], 0) + 1
        by_severity[r["default_severity"]] = by_severity.get(r["default_severity"], 0) + 1
    return {
        "total": len(records),
        "by_template": by_template,
        "by_severity": by_severity,
        "with_cwe": sum(1 for r in records if r["cwe"]),
        "with_owasp": sum(1 for r in records if r["owasp_category"]),
    }
