"""
Single source of truth for the CWE-ID → human-readable name mapping.

Used by:
  * `seed_findings_v2.py` — emits library entries with `cwe` already in
    the canonical "CWE-XXX (Human Name)" form, so the exported tracker's
    CWE ID column reads cleanly without further look-up.
  * A startup backfill (called from `main.py`) — enriches any existing
    DB rows whose `cwe` field is still a bare "CWE-XXX" identifier.

Names are taken verbatim from the MITRE CWE catalogue
(https://cwe.mitre.org/data/definitions/<id>.html). We deliberately keep
the short forms — long enough to be unambiguous, short enough to fit in
the Excel column without wrapping.

When you add a new CWE to the library, add the matching entry here too
so the backfill can enrich it on next boot.
"""
from __future__ import annotations
import re
from typing import Optional


# Order: keep numerically sorted so future additions are easy to spot.
CWE_NAMES: dict[str, str] = {
    "CWE-22":   "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-78":   "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79":   "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89":   "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-95":   "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    "CWE-200":  "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-204":  "Observable Response Discrepancy",
    "CWE-209":  "Generation of Error Message Containing Sensitive Information",
    "CWE-213":  "Exposure of Sensitive Information Due to Incompatible Policies",
    "CWE-244":  "Improper Clearing of Heap Memory Before Release",
    "CWE-256":  "Plaintext Storage of a Password",
    "CWE-262":  "Not Using Password Aging",
    "CWE-269":  "Improper Privilege Management",
    "CWE-272":  "Least Privilege Violation",
    "CWE-284":  "Improper Access Control",
    "CWE-287":  "Improper Authentication",
    "CWE-295":  "Improper Certificate Validation",
    "CWE-300":  "Channel Accessible by Non-Endpoint",
    "CWE-306":  "Missing Authentication for Critical Function",
    "CWE-307":  "Improper Restriction of Excessive Authentication Attempts",
    "CWE-308":  "Use of Single-factor Authentication",
    "CWE-311":  "Missing Encryption of Sensitive Data",
    "CWE-312":  "Cleartext Storage of Sensitive Information",
    "CWE-319":  "Cleartext Transmission of Sensitive Information",
    "CWE-324":  "Use of a Key Past its Expiration Date",
    "CWE-326":  "Inadequate Encryption Strength",
    "CWE-330":  "Use of Insufficiently Random Values",
    "CWE-347":  "Improper Verification of Cryptographic Signature",
    "CWE-352":  "Cross-Site Request Forgery (CSRF)",
    "CWE-384":  "Session Fixation",
    "CWE-406":  "Insufficient Control of Network Message Volume (Network Amplification)",
    "CWE-427":  "Uncontrolled Search Path Element",
    "CWE-434":  "Unrestricted Upload of File with Dangerous Type",
    "CWE-444":  "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')",
    "CWE-494":  "Download of Code Without Integrity Check",
    "CWE-502":  "Deserialization of Untrusted Data",
    "CWE-521":  "Weak Password Requirements",
    "CWE-532":  "Insertion of Sensitive Information into Log File",
    "CWE-540":  "Inclusion of Sensitive Information in Source Code",
    "CWE-552":  "Files or Directories Accessible to External Parties",
    "CWE-613":  "Insufficient Session Expiration",
    "CWE-601":  "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-602":  "Client-Side Enforcement of Server-Side Security",
    "CWE-639":  "Authorization Bypass Through User-Controlled Key",
    "CWE-693":  "Protection Mechanism Failure",
    "CWE-732":  "Incorrect Permission Assignment for Critical Resource",
    "CWE-749":  "Exposed Dangerous Method or Function",
    "CWE-770":  "Allocation of Resources Without Limits or Throttling",
    "CWE-778":  "Insufficient Logging",
    "CWE-798":  "Use of Hard-coded Credentials",
    "CWE-915":  "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-916":  "Use of Password Hash With Insufficient Computational Effort",
    "CWE-918":  "Server-Side Request Forgery (SSRF)",
    "CWE-926":  "Improper Export of Android Application Components",
    "CWE-940":  "Improper Verification of Source of a Communication Channel",
    "CWE-942":  "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1059": "Insufficient Technical Documentation",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1188": "Insecure Default Initialization of Resource",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
    "CWE-1385": "Missing Origin Validation in WebSockets",
    "CWE-1392": "Use of Default Credentials",
    # ---- Additions for the 2026-05 catalogue expansion ----
    "CWE-20":   "Improper Input Validation",
    "CWE-90":   "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
    "CWE-93":   "Improper Neutralization of CRLF Sequences ('CRLF Injection')",
    "CWE-94":   "Improper Control of Generation of Code ('Code Injection')",
    "CWE-98":   "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')",
    "CWE-113":  "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
    "CWE-120":  "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-190":  "Integer Overflow or Wraparound",
    "CWE-191":  "Integer Underflow (Wrap or Wraparound)",
    "CWE-235":  "Improper Handling of Extra Parameters",
    "CWE-242":  "Use of Inherently Dangerous Function",
    "CWE-257":  "Storing Passwords in a Recoverable Format",
    "CWE-285":  "Improper Authorization",
    "CWE-310":  "Cryptographic Issues",
    "CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-353":  "Missing Support for Integrity Check",
    "CWE-358":  "Improperly Implemented Security Check for Standard",
    "CWE-362":  "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-367":  "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-425":  "Direct Request ('Forced Browsing')",
    "CWE-489":  "Active Debug Code",
    "CWE-525":  "Use of Web Browser Cache Containing Sensitive Information",
    "CWE-530":  "Exposure of Backup File to an Unauthorized Control Sphere",
    "CWE-538":  "Insertion of Sensitive Information into Externally-Accessible File or Directory",
    "CWE-548":  "Exposure of Information Through Directory Listing",
    "CWE-598":  "Use of GET Request Method With Sensitive Query Strings",
    "CWE-611":  "Improper Restriction of XML External Entity Reference",
    "CWE-614":  "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-640":  "Weak Password Recovery Mechanism for Forgotten Password",
    "CWE-643":  "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
    "CWE-799":  "Improper Control of Interaction Frequency",
    "CWE-829":  "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-922":  "Insecure Storage of Sensitive Information",
    "CWE-943":  "Improper Neutralization of Special Elements in Data Query Logic",
}


_CANONICAL_RE = re.compile(r"^\s*(CWE-\d+)\s*(?:\(([^)]*)\))?\s*$", re.IGNORECASE)


def canonicalise(raw: Optional[str]) -> Optional[str]:
    """Return the "CWE-XXX (Human Name)" form of `raw`.

    Behaviour:
      * `None` / empty / whitespace → returned unchanged (None).
      * `"CWE-79"` → `"CWE-79 (Improper Neutralization …)"` if the id is
        in `CWE_NAMES`; otherwise returned as `"CWE-79"`.
      * `"CWE-79 (anything)"` → returned unchanged. We never overwrite
        an existing name the consultant typed — they may have a more
        engagement-specific framing.
      * Garbage strings (not matching the `CWE-\\d+` pattern) → returned
        unchanged so we don't drop data the consultant pasted in.
    """
    if not raw or not raw.strip():
        return raw
    m = _CANONICAL_RE.match(raw)
    if not m:
        return raw
    id_part = m.group(1).upper()
    name_part = (m.group(2) or "").strip()
    if name_part:
        # Already has a parenthesised name — keep whatever the user/seed
        # set, just normalise the ID's case.
        return f"{id_part} ({name_part})"
    catalogue = CWE_NAMES.get(id_part)
    if catalogue:
        return f"{id_part} ({catalogue})"
    return id_part


def backfill_library_cwes(db) -> int:
    """Enrich every FindingLibrary row whose `cwe` is a bare `CWE-XXX`.

    Idempotent — rows already in the canonical "CWE-XXX (Name)" form are
    skipped. Returns the number of rows updated so the caller can log it.
    Safe to call on every app start.

    Imported lazily inside the function so this helper module stays
    standalone and can be unit-tested without the SQLAlchemy stack.
    """
    from ..models import FindingLibrary
    updated = 0
    rows = db.query(FindingLibrary).all()
    for row in rows:
        if not row.cwe:
            continue
        canon = canonicalise(row.cwe)
        if canon and canon != row.cwe:
            row.cwe = canon
            updated += 1
    if updated:
        db.commit()
    return updated
