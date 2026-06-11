"""
Cloud VA/VAPT CSV parser — normalises Prowler v3 and Steampipe CIS benchmark
output into a common CloudFinding schema, then groups by AWS/Azure service.

Supported input formats
-----------------------
* Prowler v3 CSV  — columns include SERVICE_NAME, METADATA_SERVICE_NAME,
                    CHECK_ID, SEVERITY, STATUS, COMPLIANCE, …
* Steampipe CIS   — columns include service (optional, e.g. "AWS/IAM"),
                    control_id, control_title, group_title, status, reason, …

Only FAIL / ALARM rows are imported; PASS / SKIP / INFO rows are discarded.
Duplicate findings with the same (check_id, resource) key are removed
automatically when multiple CSV files are merged together.
"""
from __future__ import annotations

import csv
import io
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_CVSS: dict[str, float] = {
    "critical":      9.5,
    "high":          8.0,
    "medium":        5.5,
    "low":           2.0,
    "informational": 0.0,
    "info":          0.0,
    "none":          0.0,
}

SEV_RANK: dict[str, int] = {
    "Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1,
}

_SEV_NORM: dict[str, str] = {
    "critical":      "Critical",
    "high":          "High",
    "medium":        "Medium",
    "med":           "Medium",
    "low":           "Low",
    "informational": "Informational",
    "info":          "Informational",
    "none":          "Informational",
}


def _norm_sev(raw: str) -> str:
    return _SEV_NORM.get((raw or "").strip().lower(), "Medium")


# ─────────────────────────────────────────────────────────────────────────────
# AWS / Azure service display mapping
# ─────────────────────────────────────────────────────────────────────────────

_SERVICE_DISPLAY: dict[str, str] = {
    # AWS
    "s3":             "S3",
    "iam":            "IAM",
    "ec2":            "EC2",
    "lambda":         "Lambda",
    "rds":            "RDS",
    "cloudtrail":     "CloudTrail",
    "cloudwatch":     "CloudWatch",
    "vpc":            "VPC",
    "kms":            "KMS",
    "config":         "Config",
    "guardduty":      "GuardDuty",
    "securityhub":    "SecurityHub",
    "eks":            "EKS",
    "ecs":            "ECS",
    "elb":            "ELB",
    "elbv2":          "ELBv2",
    "sns":            "SNS",
    "sqs":            "SQS",
    "dynamodb":       "DynamoDB",
    "ssm":            "SSM",
    "secretsmanager": "SecretsManager",
    "wafv2":          "WAFv2",
    "waf":            "WAF",
    "cognito":        "Cognito",
    "ecr":            "ECR",
    "emr":            "EMR",
    "glue":           "Glue",
    "redshift":       "Redshift",
    "elasticsearch":  "Elasticsearch",
    "opensearch":     "OpenSearch",
    "athena":         "Athena",
    "backup":         "Backup",
    "codebuild":      "CodeBuild",
    "dax":            "DAX",
    "glacier":        "Glacier",
    "macie":          "Macie",
    "route53":        "Route53",
    "shield":         "Shield",
    "sagemaker":      "SageMaker",
    "accessanalyzer": "AccessAnalyzer",
    "acm":            "ACM",
    "apigateway":     "APIGateway",
    "cloudformation": "CloudFormation",
    "cloudfront":     "CloudFront",
    "codecommit":     "CodeCommit",
    "docdb":          "DocumentDB",
    "efs":            "EFS",
    "fsx":            "FSx",
    "inspector2":     "Inspector",
    "inspector":      "Inspector",
    "lightsail":      "Lightsail",
    "msk":            "MSK",
    "neptune":        "Neptune",
    "networkfirewall": "NetworkFirewall",
    "organizations":  "Organizations",
    "ses":            "SES",
    "transfer":       "Transfer",
    "trustedadvisor": "TrustedAdvisor",
    "wellarchitected": "WellArchitected",
    "workspaces":     "WorkSpaces",
    "account":        "Account",
    # Azure (Prowler azure provider)
    "azure_ad":          "Azure AD",
    "entra":             "Entra ID",
    "keyvault":          "Key Vault",
    "storage":           "Storage",
    "securitycenter":    "Security Center",
    "monitor":           "Monitor",
    "network":           "Network",
    "sql":               "SQL",
    "containerregistry": "Container Registry",
    "containerservice":  "Container Service (AKS)",
    "appservice":        "App Service",
    "virtualmachine":    "Virtual Machine",
    "defender":          "Microsoft Defender",
}


def _service_display(raw: str) -> str:
    """Return a display name for any service identifier."""
    if not raw:
        return "Other"
    # Handle "AWS/IAM" → "IAM", "AWS/EC2" → "EC2"
    if "/" in raw:
        raw = raw.split("/", 1)[-1]
    key = raw.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    return _SERVICE_DISPLAY.get(key, raw.strip())


# CIS section keywords → service (Steampipe fallback)
_CIS_SECTION_TO_SERVICE: list[tuple[str, str]] = [
    ("identity and access management", "IAM"),
    (" iam",                           "IAM"),
    ("storage",                        "S3"),
    ("logging",                        "CloudTrail"),
    ("monitoring",                     "CloudWatch"),
    ("networking",                     "VPC"),
    ("compute",                        "EC2"),
    ("database",                       "RDS"),
    ("container",                      "EKS"),
    # Azure
    ("virtual machine",                "Virtual Machine"),
    ("key vault",                      "Key Vault"),
    ("security center",                "Security Center"),
    ("defender",                       "Microsoft Defender"),
    ("app service",                    "App Service"),
    ("sql server",                     "SQL"),
]

_CIS_NUM_TO_SERVICE: dict[str, str] = {
    "1": "IAM",
    "2": "S3",
    "3": "CloudTrail",
    "4": "CloudWatch",
    "5": "VPC",
}


def _service_from_cis_group(group_title: str, control_id: str = "") -> str:
    lower = (group_title or "").lower()
    for keyword, svc in _CIS_SECTION_TO_SERVICE:
        if keyword in lower:
            return svc
    if control_id:
        parts = control_id.replace("-", "_").split("_")
        for p in parts:
            if p.isdigit() and p in _CIS_NUM_TO_SERVICE:
                return _CIS_NUM_TO_SERVICE[p]
    return "Other"


# ─────────────────────────────────────────────────────────────────────────────
# Issue title and benchmark reference helpers
# ─────────────────────────────────────────────────────────────────────────────

_SERVICE_ISSUE_TITLE: dict[str, str] = {
    "IAM":            "Multiple IAM and Account-Level Security Controls Are Not Fully Implemented",
    "Account":        "Multiple IAM and Account-Level Security Controls Are Not Fully Implemented",
    "S3":             "Multiple S3 Storage Security Controls Are Not Fully Implemented",
    "EC2":            "Multiple EC2 Instance and Network Security Controls Are Not Fully Implemented",
    "CloudTrail":     "CloudTrail Logging and Monitoring Controls Are Not Fully Implemented",
    "CloudWatch":     "CloudWatch Monitoring and Alerting Controls Are Not Fully Implemented",
    "VPC":            "Multiple VPC Networking Security Controls Are Not Fully Implemented",
    "RDS":            "Multiple RDS Database Security Controls Are Not Fully Implemented",
    "KMS":            "KMS Key Management Security Controls Are Not Fully Implemented",
    "GuardDuty":      "Amazon GuardDuty Threat Detection Is Not Fully Enabled",
    "Lambda":         "Multiple Lambda Function Security Controls Are Not Fully Implemented",
    "EKS":            "Multiple EKS Container Security Controls Are Not Fully Implemented",
    "ECS":            "Multiple ECS Container Security Controls Are Not Fully Implemented",
    "SecurityHub":    "AWS Security Hub Is Not Fully Enabled or Configured",
    "SecretsManager": "Secrets Manager Security Controls Are Not Fully Implemented",
    "Config":         "AWS Config Is Not Enabled in All Regions",
    "Organizations":  "AWS Organizations Security Controls Are Not Fully Implemented",
    "ACM":            "ACM Certificate Management Controls Are Not Fully Implemented",
    "AccessAnalyzer": "IAM Access Analyzer Is Not Fully Enabled",
    "WAFv2":          "WAF Web Application Firewall Controls Are Not Fully Implemented",
    "WAF":            "WAF Web Application Firewall Controls Are Not Fully Implemented",
    "OpenSearch":     "OpenSearch / Elasticsearch Security Controls Are Not Fully Implemented",
    "Elasticsearch":  "OpenSearch / Elasticsearch Security Controls Are Not Fully Implemented",
    "Redshift":       "Amazon Redshift Security Controls Are Not Fully Implemented",
    "DynamoDB":       "DynamoDB Database Security Controls Are Not Fully Implemented",
    "SNS":            "SNS Notification Service Security Controls Are Not Fully Implemented",
    "SQS":            "SQS Queue Security Controls Are Not Fully Implemented",
    "ECR":            "ECR Container Registry Security Controls Are Not Fully Implemented",
    "Backup":         "AWS Backup Controls Are Not Fully Implemented",
}


def _get_issue_title(service: str, group_title: str = "") -> str:
    """Return a standard grouped finding title for the given service."""
    if group_title:
        cleaned = re.sub(r'^\d+(\.\d+)*\s+', '', group_title).strip()
        cleaned = re.sub(r'\s*\(Level \d+\)', '', cleaned).strip()
        if cleaned and cleaned.lower() not in ("other",):
            return f"Multiple {cleaned} Controls Are Not Fully Implemented"
    return _SERVICE_ISSUE_TITLE.get(
        service,
        f"Multiple {service} Security Controls Are Not Fully Implemented",
    )


def _format_benchmark(check_id: str, compliance: str = "") -> str:
    """Extract a clean CIS section number from a check_id or compliance string.

    Examples:
      cis_v140_1_10            → 1.10
      cis_v140_2_1_1           → 2.1.1
      CIS-AWS v1.4.0/1.6       → 1.6
      iam_root_hardware_mfa    → iam_root_hardware_mfa  (no CIS ref)
    """
    # Try compliance field first: "CIS-AWS v1.4.0/1.10;..." → "1.10"
    if compliance:
        for part in re.split(r"[;,|]", compliance):
            m = re.search(r"/(\d+(?:\.\d+)+)", part)
            if m:
                return m.group(1)

    # Try formatting control_id: "cis_v140_1_10" → "1.10"
    if check_id:
        parts = check_id.replace("-", "_").lower().split("_")
        numeric: list[str] = []
        skip = {"cis", "aws", "azure", "l1", "l2", "level", "benchmark"}
        for p in parts:
            if p in skip:
                continue
            if p.startswith("v") and p[1:].isdigit():
                continue  # version token e.g. "v140"
            if re.match(r"^\d+$", p):
                numeric.append(p)
        if numeric and len(numeric) >= 2:
            return ".".join(numeric)

    return check_id or ""


# ─────────────────────────────────────────────────────────────────────────────
# Canonical Cloud Finding
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CloudFinding:
    source:        str       # "prowler" | "steampipe"
    service:       str       # Display name: S3 / IAM / EC2 …
    check_id:      str       # Raw check identifier
    benchmark_ref: str       # Formatted CIS section number, e.g. "1.10"
    issue_title:   str       # Overarching group title for the Issue Title column
    title:         str       # Specific control/check title → Benchmark Clause
    description:   str       # Detailed description → Observation column
    risk:          str       # Risk/reason → Implication column
    remediation:   str       # Recommended fix → Recommendation column
    severity:      str       # Critical / High / Medium / Low / Informational
    cvss_score:    float
    resource:      str       # Affected resource ARN / identifier
    region:        str
    status:        str       # Always "FAIL"
    compliance:    str       # CIS reference(s)
    cis_level:     str = ""  # "L1" | "L2" | ""
    raw:           dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        return {
            "source":        self.source,
            "service":       self.service,
            "check_id":      self.check_id,
            "benchmark_ref": self.benchmark_ref,
            "issue_title":   self.issue_title,
            "title":         self.title,
            "description":   self.description,
            "risk":          self.risk,
            "remediation":   self.remediation,
            "severity":      self.severity,
            "cvss_score":    self.cvss_score,
            "resource":      self.resource,
            "region":        self.region,
            "status":        self.status,
            "compliance":    self.compliance,
            "cis_level":     self.cis_level,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CloudFinding":
        known = {f.name for f in cls.__dataclass_fields__.values()
                 if f.name != "raw"}
        return cls(**{k: v for k, v in d.items() if k in known})


# ─────────────────────────────────────────────────────────────────────────────
# Prowler v3 parser
# ─────────────────────────────────────────────────────────────────────────────

def _detect_prowler(headers: list[str]) -> bool:
    h = {c.strip().upper() for c in headers}
    return "CHECK_ID" in h and "SEVERITY" in h and "STATUS" in h


def _parse_prowler(reader: csv.DictReader) -> list[CloudFinding]:
    findings: list[CloudFinding] = []
    for row in reader:
        status_raw = (row.get("STATUS") or row.get("status") or "").strip().upper()
        if status_raw not in ("FAIL", "FAILED"):
            continue

        sev_raw = (row.get("SEVERITY") or row.get("severity") or "medium").strip()
        sev     = _norm_sev(sev_raw)

        # Service: prefer METADATA_SERVICE_NAME → SERVICE_NAME → subservice
        svc_raw = (
            row.get("METADATA_SERVICE_NAME") or row.get("metadata_service_name") or
            row.get("SERVICE_NAME") or row.get("service_name") or
            row.get("SUBSERVICE_NAME") or row.get("subservice_name") or ""
        ).strip()
        svc = _service_display(svc_raw) if svc_raw else "Other"

        check_id   = (row.get("CHECK_ID") or row.get("check_id") or "").strip()
        compliance = (row.get("COMPLIANCE") or row.get("compliance") or "").strip()
        bench_ref  = _format_benchmark(check_id, compliance)

        findings.append(CloudFinding(
            source        = "prowler",
            service       = svc,
            check_id      = check_id,
            benchmark_ref = bench_ref,
            issue_title   = _get_issue_title(svc),
            title         = (
                row.get("CHECK_TITLE") or row.get("check_title") or
                row.get("FINDING_UNIQUE_ID") or row.get("finding_unique_id") or ""
            ).strip(),
            description   = (row.get("DESCRIPTION") or row.get("description") or "").strip(),
            risk          = (row.get("RISK") or row.get("risk") or "").strip(),
            remediation   = (
                row.get("REMEDIATION_RECOMMENDATION_TEXT") or
                row.get("remediation_recommendation_text") or ""
            ).strip(),
            severity      = sev,
            cvss_score    = SEVERITY_CVSS.get(sev.lower(), 5.5),
            resource      = (
                row.get("RESOURCE_UID") or row.get("resource_uid") or
                row.get("RESOURCE_NAME") or row.get("resource_name") or ""
            ).strip(),
            region        = (row.get("REGION") or row.get("region") or "").strip(),
            status        = "FAIL",
            compliance    = compliance,
            raw           = dict(row),
        ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Steampipe CIS benchmark parser
# ─────────────────────────────────────────────────────────────────────────────

_STEAMPIPE_FAIL = {"alarm", "fail", "error"}


def _detect_steampipe(headers: list[str]) -> bool:
    h = {c.strip().lower() for c in headers}
    return (
        ("control_id" in h or "control_title" in h)
        and "status" in h
        and ("reason" in h or "resource" in h)
    )


def _parse_steampipe(reader: csv.DictReader) -> list[CloudFinding]:
    findings: list[CloudFinding] = []
    for row in reader:
        status_raw = (row.get("status") or "").strip().lower()
        if status_raw not in _STEAMPIPE_FAIL:
            continue

        group_title = (row.get("group_title") or row.get("title") or "").strip()
        ctrl_id     = (row.get("control_id") or "").strip()
        ctrl_title  = (row.get("control_title") or row.get("title") or "").strip()

        # Explicit "service" column takes priority: "AWS/IAM" → "IAM"
        svc_col = (row.get("service") or row.get("SERVICE") or "").strip()
        if svc_col:
            svc = _service_display(svc_col)
        else:
            svc = _service_from_cis_group(group_title, ctrl_id)

        # CIS level detection
        tags_raw  = (row.get("tags") or row.get("tag") or "").lower()
        grp_lower = group_title.lower()
        cis_level = ""
        if "level_2" in tags_raw or "level 2" in grp_lower or "_l2_" in ctrl_id.lower():
            cis_level = "L2"
        elif "level_1" in tags_raw or "level 1" in grp_lower or "_l1_" in ctrl_id.lower():
            cis_level = "L1"

        bench_ref = _format_benchmark(ctrl_id)

        findings.append(CloudFinding(
            source        = "steampipe",
            service       = svc,
            check_id      = ctrl_id,
            benchmark_ref = bench_ref,
            issue_title   = _get_issue_title(svc, group_title),
            title         = ctrl_title,
            description   = (row.get("control_description") or row.get("description") or "").strip(),
            risk          = (row.get("reason") or "").strip(),
            remediation   = "",
            severity      = "Medium",
            cvss_score    = 5.5,
            resource      = (row.get("resource") or "").strip(),
            region        = (row.get("region") or "").strip(),
            status        = "FAIL",
            compliance    = ctrl_id,
            cis_level     = cis_level,
            raw           = dict(row),
        ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────────────────────

def deduplicate(findings: list[CloudFinding]) -> list[CloudFinding]:
    """Remove duplicate findings with the same (check_id, resource) key.

    When multiple CSV files are merged (e.g. Prowler + Steampipe L1 + L2),
    the same benchmark check on the same resource may appear more than once.
    The first occurrence (highest severity wins on sort) is kept.
    """
    seen: set[tuple[str, str]] = set()
    out:  list[CloudFinding]   = []
    for f in findings:
        # Deduplicate on normalised (check_id, resource) pair
        key = (f.check_id.lower().strip(), f.resource.lower().strip())
        if key not in seen:
            seen.add(key)
            out.append(f)
        else:
            logger.debug("Duplicate removed: check_id=%r resource=%r", f.check_id, f.resource)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def parse_cloud_csv(content: bytes, filename: str = "") -> list[CloudFinding]:
    """Parse a Prowler or Steampipe CIS CSV; returns FAIL findings only.

    Auto-detects the format from the header row. Raises ValueError if
    neither format is recognised and no findings can be extracted.
    """
    text    = content.decode("utf-8-sig", errors="replace")
    reader  = csv.DictReader(io.StringIO(text))
    headers = reader.fieldnames or []

    if _detect_prowler(headers):
        logger.info("Prowler format detected in %r (%d headers)", filename, len(headers))
        return _parse_prowler(reader)

    if _detect_steampipe(headers):
        logger.info("Steampipe CIS format detected in %r (%d headers)", filename, len(headers))
        return _parse_steampipe(reader)

    # Last-resort: try each parser and keep the one that yields findings
    for parser_fn, label in [(_parse_prowler, "prowler"), (_parse_steampipe, "steampipe")]:
        r2 = csv.DictReader(io.StringIO(text))
        rows = parser_fn(r2)
        if rows:
            logger.info("Fallback %s parser yielded %d rows for %r", label, len(rows), filename)
            return rows

    raise ValueError(
        f"Unrecognised cloud CSV format in {filename!r}. "
        "Supported: Prowler v3 CSV and Steampipe CIS benchmark CSV."
    )


def group_by_service(findings: list[CloudFinding]) -> dict[str, list[CloudFinding]]:
    """Group findings by service name; within each group sort worst-first."""
    groups: dict[str, list[CloudFinding]] = {}
    for f in findings:
        groups.setdefault(f.service, []).append(f)
    for grp in groups.values():
        grp.sort(key=lambda x: (-SEV_RANK.get(x.severity, 0), x.benchmark_ref, x.title.lower()))
    return dict(sorted(groups.items()))


def best_severity(findings: list[CloudFinding]) -> tuple[str, float]:
    """Return (severity_label, cvss_score) of the worst finding in a list."""
    if not findings:
        return ("Informational", 0.0)
    worst = max(findings, key=lambda f: (SEV_RANK.get(f.severity, 0), f.cvss_score))
    return (worst.severity, worst.cvss_score)
