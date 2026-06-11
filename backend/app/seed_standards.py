"""
Seed the bundled reference standards on first run.

Runs as part of `python -m app.seed` after users + templates are created.
Adds OWASP Top 10 2021 (web), OWASP API Security Top 10 2023, and OWASP
Mobile Top 10 2024 as a starting point. Admins upload new versions when
frameworks update -- this just provides sensible defaults so the team
isn't starting from an empty taxonomy.
"""
from sqlalchemy.orm import Session
from .models import ReferenceStandard


OWASP_TOP10_2021 = {
    "code": "owasp_top10",
    "name": "OWASP Top 10",
    "version": "2021",
    "description": "OWASP Top 10 Web Application Security Risks (2021)",
    "is_active": True,
    "entries": [
        {"id": "A01:2021", "title": "Broken Access Control", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
        {"id": "A02:2021", "title": "Cryptographic Failures", "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"},
        {"id": "A03:2021", "title": "Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
        {"id": "A04:2021", "title": "Insecure Design", "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"},
        {"id": "A05:2021", "title": "Security Misconfiguration", "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
        {"id": "A06:2021", "title": "Vulnerable and Outdated Components", "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"},
        {"id": "A07:2021", "title": "Identification and Authentication Failures", "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
        {"id": "A08:2021", "title": "Software and Data Integrity Failures", "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"},
        {"id": "A09:2021", "title": "Security Logging and Monitoring Failures", "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"},
        {"id": "A10:2021", "title": "Server-Side Request Forgery (SSRF)", "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"},
    ],
}

OWASP_API_2023 = {
    "code": "owasp_api_top10",
    "name": "OWASP API Security Top 10",
    "version": "2023",
    "description": "OWASP API Security Top 10 (2023)",
    "is_active": True,
    "entries": [
        {"id": "API1:2023", "title": "Broken Object Level Authorization", "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
        {"id": "API2:2023", "title": "Broken Authentication", "url": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"},
        {"id": "API3:2023", "title": "Broken Object Property Level Authorization", "url": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"},
        {"id": "API4:2023", "title": "Unrestricted Resource Consumption", "url": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"},
        {"id": "API5:2023", "title": "Broken Function Level Authorization", "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"},
        {"id": "API6:2023", "title": "Unrestricted Access to Sensitive Business Flows", "url": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"},
        {"id": "API7:2023", "title": "Server Side Request Forgery", "url": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"},
        {"id": "API8:2023", "title": "Security Misconfiguration", "url": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"},
        {"id": "API9:2023", "title": "Improper Inventory Management", "url": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"},
        {"id": "API10:2023", "title": "Unsafe Consumption of APIs", "url": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"},
    ],
}

OWASP_MOBILE_2024 = {
    "code": "owasp_mobile_top10",
    "name": "OWASP Mobile Top 10",
    "version": "2024",
    "description": "OWASP Mobile Application Security Top 10 (2024)",
    "is_active": True,
    "entries": [
        {"id": "M1:2024", "title": "Improper Credential Usage", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m1-improper-credential-usage"},
        {"id": "M2:2024", "title": "Inadequate Supply Chain Security", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m2-inadequate-supply-chain-security"},
        {"id": "M3:2024", "title": "Insecure Authentication/Authorization", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m3-insecure-authentication-authorization"},
        {"id": "M4:2024", "title": "Insufficient Input/Output Validation", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m4-insufficient-input-output-validation"},
        {"id": "M5:2024", "title": "Insecure Communication", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m5-insecure-communication"},
        {"id": "M6:2024", "title": "Inadequate Privacy Controls", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m6-inadequate-privacy-controls"},
        {"id": "M7:2024", "title": "Insufficient Binary Protections", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m7-insufficient-binary-protection"},
        {"id": "M8:2024", "title": "Security Misconfiguration", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m8-security-misconfiguration"},
        {"id": "M9:2024", "title": "Insecure Data Storage", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m9-insecure-data-storage"},
        {"id": "M10:2024", "title": "Insufficient Cryptography", "url": "https://owasp.org/www-project-mobile-top-10/2024-risks/m10-insufficient-cryptography"},
    ],
}

BUNDLED = [OWASP_TOP10_2021, OWASP_API_2023, OWASP_MOBILE_2024]


def seed_standards(db: Session) -> int:
    """Insert the bundled standards if not already present. Returns count added."""
    added = 0
    for spec in BUNDLED:
        existing = (db.query(ReferenceStandard)
                      .filter(ReferenceStandard.code == spec["code"],
                              ReferenceStandard.version == spec["version"])
                      .first())
        if existing:
            continue
        std = ReferenceStandard(**spec)
        db.add(std)
        added += 1
    db.commit()
    return added
