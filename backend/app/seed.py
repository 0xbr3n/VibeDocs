"""
First-run bootstrap:
  - admin / consultant default users (you MUST change passwords after first login)
  - the six standard VAPT report templates
  - a starter findings library scoped to each template

Run with:  docker compose exec app python -m app.seed
"""
import sys
from pathlib import Path
from sqlalchemy.orm import Session

from .database import Base, engine, SessionLocal
from .models import (
    User, Role, ReportTemplate, FindingLibrary,
    LibraryStatus, Severity,
)
from .auth import hash_password
from .config import settings


TEMPLATE_DEFS = [
    {
        "code": "web_vapt",
        "name": "Web Application VAPT",
        "docx_filename": "web_vapt_template.docx",
        "description": "Web application penetration test report.",
        "scope_of_work": (
            "Conduct a grey-box web application penetration test of the in-scope "
            "applications. Identify vulnerabilities aligned to the OWASP Top 10 (2021), "
            "ASVS L2, and business-logic flaws."
        ),
        "methodology": (
            "Reconnaissance, authentication & session management testing, access control, "
            "input validation (SQLi/XSS/SSRF/XXE), business logic, file upload, API endpoints, "
            "cryptography, and configuration review. Tools: Burp Suite Pro, manual testing."
        ),
        "extra_fields": ["urls_in_scope", "user_roles_tested", "credentials_provided"],
        "supports_nessus_import": False,
        "supports_nmap_import": False,
    },
    {
        "code": "infra_va",
        "name": "Infrastructure Vulnerability Assessment",
        "docx_filename": "infra_va_template.docx",
        "description": "Automated infrastructure vulnerability assessment from Nessus scans.",
        "scope_of_work": (
            "Perform an automated authenticated/unauthenticated vulnerability scan of the "
            "in-scope hosts using Tenable Nessus. Recurring scans support delta-tracking."
        ),
        "methodology": (
            "Host discovery, port enumeration (Nmap), Nessus vulnerability scan, manual "
            "validation of high/critical issues, false-positive removal, severity scoring."
        ),
        "extra_fields": ["ips_in_scope", "scan_window", "credentialed"],
        "supports_nessus_import": True,
        "supports_nmap_import": True,
    },
    {
        "code": "infra_vapt",
        "name": "Infrastructure VAPT",
        "docx_filename": "infra_vapt_template.docx",
        "description": "Manual infrastructure penetration test plus VA scans.",
        "scope_of_work": (
            "Perform external and/or internal infrastructure penetration testing. "
            "Combine automated scanning with manual exploitation and lateral-movement attempts."
        ),
        "methodology": (
            "Recon, port scan, service enumeration, vulnerability identification, "
            "exploitation, privilege escalation, lateral movement, persistence (where in scope), "
            "and post-exploitation analysis."
        ),
        "extra_fields": ["ips_in_scope", "external_or_internal", "credentials_provided"],
        "supports_nessus_import": True,
        "supports_nmap_import": True,
    },
    {
        "code": "api_vapt",
        "name": "API Penetration Test",
        "docx_filename": "api_vapt_template.docx",
        "description": "REST / GraphQL / SOAP API penetration test.",
        "scope_of_work": (
            "Penetration test of the in-scope API endpoints aligned to OWASP API Security Top 10."
        ),
        "methodology": (
            "Endpoint discovery, authentication & token testing, BOLA/BFLA, mass assignment, "
            "rate-limiting, input validation, business-logic abuse, schema fuzzing."
        ),
        "extra_fields": ["api_base_urls", "auth_mechanism", "swagger_url"],
        "supports_nessus_import": False,
        "supports_nmap_import": False,
    },
    {
        "code": "thick_client_pt",
        "name": "Thick Client Penetration Test",
        "docx_filename": "thick_client_pt_template.docx",
        "description": "Desktop / thick-client application penetration test.",
        "scope_of_work": (
            "Penetration test of the in-scope thick-client application binary and its backend."
        ),
        "methodology": (
            "Static & dynamic analysis of binary, traffic interception (Burp + proxy-aware "
            "tooling), IPC review, registry/file-system analysis, memory inspection, "
            "DLL hijacking checks, backend API testing."
        ),
        "extra_fields": ["binary_version", "os_target", "user_roles_tested"],
        "supports_nessus_import": False,
        "supports_nmap_import": False,
    },
    {
        "code": "mobile_pt",
        "name": "Mobile Application Penetration Test",
        "docx_filename": "mobile_pt_template.docx",
        "description": "Android / iOS mobile application penetration test.",
        "scope_of_work": (
            "Penetration test of in-scope mobile application(s) and backend, aligned to OWASP MASVS."
        ),
        "methodology": (
            "Static analysis (decompilation, manifest review), dynamic analysis on rooted/"
            "jailbroken devices, certificate pinning bypass, IPC, local storage, network "
            "traffic, backend API."
        ),
        "extra_fields": ["app_versions", "platforms", "user_roles_tested"],
        "supports_nessus_import": False,
        "supports_nmap_import": False,
    },
]


# Starter findings library. Keep these short - the team adds the real ones.
STARTER_FINDINGS = {
    "web_vapt": [
        {
            "title": "Reflected Cross-Site Scripting (XSS)",
            "description": (
                "The application reflects unsanitised user input into the response, allowing "
                "an attacker to inject arbitrary JavaScript that executes in the victim's browser."
            ),
            "impact": (
                "Session hijacking, credential theft, defacement, or delivery of further "
                "client-side attacks depending on victim privileges."
            ),
            "remediation": (
                "Encode output contextually (HTML, JS, URL, CSS). Implement a strict "
                "Content-Security-Policy. Validate input on the server side."
            ),
            "references": "https://owasp.org/www-community/attacks/xss/\nCWE-79",
            "default_severity": Severity.high,
            "default_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            "default_cvss_score": 5.1,
            "cwe": "CWE-79",
            "owasp_category": "A03:2021",
        },
        {
            "title": "SQL Injection",
            "description": (
                "User input is concatenated into SQL queries without parameterisation, "
                "allowing attackers to manipulate query logic."
            ),
            "impact": "Unauthorised data access, modification, or destruction; possible RCE.",
            "remediation": (
                "Use parameterised queries / prepared statements throughout. Apply least-privilege "
                "database accounts. Validate and reject unexpected input types."
            ),
            "references": "https://owasp.org/www-community/attacks/SQL_Injection\nCWE-89",
            "default_severity": Severity.critical,
            "default_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "default_cvss_score": 9.3,
            "cwe": "CWE-89",
            "owasp_category": "A03:2021",
        },
        {
            "title": "Insecure Direct Object Reference (IDOR)",
            "description": "Object identifiers are exposed and not validated against the requesting user's authorisation context.",
            "impact": "Unauthorised access to other users' data or actions.",
            "remediation": "Enforce server-side authorisation checks for every object access. Prefer indirect references.",
            "references": "CWE-639",
            "default_severity": Severity.high,
            "default_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "default_cvss_score": 7.1,
            "cwe": "CWE-639",
            "owasp_category": "A01:2021",
        },
    ],
    "infra_va": [
        {
            "title": "Outdated Software - Missing Security Patches",
            "description": "Hosts run software versions with known, patched vulnerabilities.",
            "impact": "Exposure to publicly known exploits.",
            "remediation": "Establish a patch-management cadence. Apply vendor security updates within SLA.",
            "references": "",
            "default_severity": Severity.high,
            "default_cvss_score": 7.5,
            "cwe": "CWE-1104",
        },
        {
            "title": "SSL/TLS - Weak Cipher Suites",
            "description": "Server supports weak or deprecated cipher suites (e.g. CBC-mode, RC4, 3DES).",
            "impact": "Cryptographic attacks against transport, including downgrade and oracle attacks.",
            "remediation": "Disable weak ciphers. Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305). Enforce TLS 1.2+.",
            "references": "",
            "default_severity": Severity.medium,
            "default_cvss_score": 5.3,
        },
        {
            "title": "SSL/TLS - Untrusted or Expired Certificate",
            "description": "TLS certificate is self-signed, expired, or chains to an untrusted CA.",
            "impact": "Users cannot verify server identity, enabling man-in-the-middle attacks.",
            "remediation": "Deploy certificates issued by a trusted CA. Monitor expiry.",
            "references": "",
            "default_severity": Severity.medium,
            "default_cvss_score": 5.0,
        },
    ],
    "api_vapt": [
        {
            "title": "Broken Object Level Authorization (BOLA)",
            "description": "API endpoints accept user-supplied object IDs without verifying ownership.",
            "impact": "Cross-tenant data access; data theft at scale.",
            "remediation": "Authorise every object access against the authenticated principal. Use opaque identifiers.",
            "references": "OWASP API1:2023",
            "default_severity": Severity.critical,
            "default_cvss_score": 9.1,
            "owasp_category": "API1:2023",
        },
        {
            "title": "Excessive Data Exposure",
            "description": "API responses contain sensitive fields not used by the client.",
            "impact": "Sensitive data leakage to clients (or via proxies/logs).",
            "remediation": "Filter response payloads server-side. Avoid relying on client filtering.",
            "references": "OWASP API3:2023",
            "default_severity": Severity.medium,
            "default_cvss_score": 5.3,
            "owasp_category": "API3:2023",
        },
    ],
    "thick_client_pt": [
        {
            "title": "Hardcoded Credentials in Binary",
            "description": "Static analysis of the binary reveals embedded credentials.",
            "impact": "Trivial backend compromise via decompiled secrets.",
            "remediation": "Move secrets to runtime configuration. Issue per-user/credentials via authenticated channels.",
            "references": "CWE-798",
            "default_severity": Severity.high,
            "default_cvss_score": 7.5,
            "cwe": "CWE-798",
        },
    ],
    "mobile_pt": [
        {
            "title": "Insufficient Certificate Pinning",
            "description": "The mobile app does not pin server certificates / public keys.",
            "impact": "An attacker with a trusted CA cert can intercept TLS traffic.",
            "remediation": "Implement public-key pinning for backend APIs. Reject connections on pin mismatch.",
            "references": "OWASP MASVS-NETWORK-2",
            "default_severity": Severity.medium,
            "default_cvss_score": 5.4,
        },
    ],
    "infra_vapt": [],
}


def ensure_admin(db: Session) -> User:
    admin = db.query(User).filter(User.username == "admin").first()
    if admin:
        return admin
    admin = User(
        username="admin",
        email="admin@example.com",
        full_name="Initial Admin",
        hashed_password=hash_password("change_me_now"),
        role=Role.admin,
    )
    db.add(admin); db.commit(); db.refresh(admin)
    print("Created admin user (admin / change_me_now) - CHANGE THIS PASSWORD")
    return admin


def ensure_templates(db: Session) -> dict[str, ReportTemplate]:
    out = {}
    for tpl in TEMPLATE_DEFS:
        existing = db.query(ReportTemplate).filter(ReportTemplate.code == tpl["code"]).first()
        if existing:
            out[tpl["code"]] = existing
            continue
        rt = ReportTemplate(**tpl)
        db.add(rt); db.flush()
        out[tpl["code"]] = rt
        print(f"  Template seeded: {tpl['code']}")
    db.commit()
    return out


def ensure_findings(db: Session, templates: dict[str, ReportTemplate], admin: User):
    for code, items in STARTER_FINDINGS.items():
        tpl = templates.get(code)
        if not tpl:
            continue
        for item in items:
            exists = (db.query(FindingLibrary)
                      .filter(FindingLibrary.template_id == tpl.id,
                              FindingLibrary.title == item["title"]).first())
            if exists:
                continue
            f = FindingLibrary(
                template_id=tpl.id,
                created_by_id=admin.id,
                reviewed_by_id=admin.id,
                status=LibraryStatus.approved,
                **item,
            )
            db.add(f)
            print(f"  Finding seeded: [{code}] {item['title']}")
    db.commit()


def main():
    Base.metadata.create_all(bind=engine)
    print("Tables ensured.")
    db = SessionLocal()
    try:
        admin = ensure_admin(db)
        # Verify template .docx files exist (warn if not)
        missing = []
        for tpl in TEMPLATE_DEFS:
            p = Path(settings.TEMPLATE_DIR) / tpl["docx_filename"]
            if not p.exists():
                missing.append(p)
        if missing:
            print(f"WARNING - {len(missing)} template DOCX file(s) missing -- auto-generating now...")
            try:
                from . import gen_word_templates
                gen_word_templates.main()
                # Re-check after generation
                still_missing = [p for p in missing if not p.exists()]
                if still_missing:
                    print("   Still missing after auto-gen:")
                    for m in still_missing:
                        print(f"     {m}")
                else:
                    print(f"   ✓ Generated all {len(missing)} starter templates.")
            except Exception as e:
                print(f"   FAILED to auto-generate templates: {e}")
                print("   Run manually: docker compose exec app python -m app.gen_word_templates")
        templates_map = ensure_templates(db)
        ensure_findings(db, templates_map, admin)

        # Seed bundled reference standards (OWASP Top 10 2021, API 2023, Mobile 2024).
        # Admins can upload newer versions via POST /api/standards anytime.
        from .seed_standards import seed_standards
        added = seed_standards(db)
        if added:
            print(f"Seeded {added} reference standard(s)")

        # Seed the team's XML knowledge base (Knowledgebase.xml shipped with
        # the project). On Docker container start this runs automatically so
        # the full team library (145 findings) is available immediately.
        from .seed_xml_knowledgebase import seed_xml_knowledgebase
        kb_stats = seed_xml_knowledgebase(db, admin)
        if kb_stats.get("added"):
            print(f"Seeded {kb_stats['added']} XML knowledge-base findings "
                  f"({kb_stats['skipped']} already existed): "
                  f"{kb_stats['by_template_added']}")
        elif kb_stats.get("error"):
            print(f"WARNING - XML knowledge base seed: {kb_stats['error']}")

        print("Seed complete.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
