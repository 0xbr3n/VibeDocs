"""
Data model for the VAPT reporting platform.

Key concepts:
- ReportTemplate: a Word .docx Jinja-template plus metadata (Web VAPT / Infra VAPT / API / Thick Client / Mobile / etc.)
- FindingLibrary: re-usable canonical findings (description, impact, remediation, references)
    scoped to a finding_type (matches a ReportTemplate.code) so search stays focused.
- Project: an engagement for a client. Holds scope, dates, testers.
- Report: a generated deliverable inside a project. Versions auto-increment (0.1, 0.2, ...).
- ReportFinding: instance of a finding inside a specific report version.
    Carries its own description / impact / remediation overrides (copied from library on insert),
    CVSS vector + score, screenshots, retest info, status.
- ScanImport: a Nessus/Nmap upload tied to a project; we keep audit history of what was processed.
"""
from datetime import datetime
import enum
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Boolean,
    Enum, JSON, Float, Table, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship
from .database import Base


# -------- Enums --------

class Role(str, enum.Enum):
    admin = "admin"
    senior = "senior"          # can approve findings, sign off reports
    consultant = "consultant"  # default - can create / generate
    viewer = "viewer"


class Severity(str, enum.Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    informational = "Informational"


class FindingStatus(str, enum.Enum):
    open = "Open"
    closed = "Closed"
    risk_accepted = "Risk Accepted"
    false_positive = "False Positive"
    not_applicable = "N/A"
    in_remediation = "In Remediation"


class TemplateStatus(str, enum.Enum):
    draft = "draft"                    # Being edited, not submitted
    pending_review = "pending_review"  # Submitted, awaiting admin approval
    approved = "approved"              # Approved, available to all
    rejected = "rejected"              # Rejected by admin, back to draft


class ReportReviewStatus(str, enum.Enum):
    """Workflow state for a ReportVersion.

    Lifecycle:
      draft -> in_review -> (approved | rejected)
      approved -> draft  (re-opened for follow-up edits) OR
      approved -> published (locked, used for final delivery)

    `in_review` always carries the DRAFT watermark regardless of the
    consultant's intent — the reviewer's job is to see the latest WIP
    *before* it's signed off.
    """
    draft       = "draft"        # Consultant is still working
    in_review   = "in_review"    # Submitted for senior review
    approved    = "approved"     # Reviewer signed off; back to editable
    rejected    = "rejected"     # Reviewer sent it back with notes
    published   = "published"    # Locked final version, no watermark


class LibraryStatus(str, enum.Enum):
    draft = "draft"
    pending_review = "pending_review"
    approved = "approved"
    archived = "archived"


# -------- Users --------

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255))
    # Reporter contact number. Auto-fills the tester "Contact No" cell on
    # every tracker Info sheet (set once on the profile, reused for all
    # reports — same pattern as email/full_name).
    phone = Column(String(64))
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(Role), default=Role.consultant, nullable=False)
    is_active = Column(Boolean, default=True)
    # ---- Two-Factor Authentication (TOTP) ----
    # totp_secret is the base32 secret shared with the authenticator app.
    # Stored encrypted-at-rest by the DB layer (Postgres TDE/pgcrypto if enabled).
    # NULL when 2FA has never been enrolled.
    totp_secret = Column(String(64))
    # True only after the user verifies their first code, proving they have
    # the authenticator. Login enforces 2FA only when this is True.
    totp_enabled = Column(Boolean, default=False, nullable=False)
    totp_enabled_at = Column(DateTime)
    # Admin-controlled forced 2FA. When True AND `totp_enabled=False`,
    # the next login lets the user past password auth but immediately
    # routes them to a forced MFA-enrollment screen (see ui.py +
    # forced_mfa middleware). Every non-enrollment route returns 403
    # until they finish setup, at which point `totp_enabled` flips
    # True and the gate clears. When admin sets this back to False,
    # whatever the user's `totp_enabled` state is, that's what they
    # keep — i.e. disabling enforcement does NOT auto-disable an
    # already-enrolled second factor.
    totp_required = Column(Boolean, default=False, nullable=False)
    totp_required_by_id = Column(Integer, ForeignKey("users.id"))
    totp_required_at = Column(DateTime)
    # Account lockout — tracks consecutive failed password attempts and the
    # timestamp at which the account was locked (auto or by an admin).
    # Reset to 0 / NULL on every successful login or admin unlock.
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_at = Column(DateTime)
    lock_reason = Column(String(64))   # "auto" | "admin"
    created_at = Column(DateTime, default=datetime.utcnow)
    # User-uploaded background image for the in-app theme. NULL = use the
    # default. Path is a server-local file under UPLOAD_DIR/backgrounds/.
    background_path = Column(String(500))
    # Timestamp of the last time this user clicked "Mark all read" on the
    # notification bell. Notifications newer than this are unread; the
    # dropdown / badge count derive from comparison against AuditLog.at.
    # NULL = bell has never been acknowledged (every notification is
    # therefore unread). See routers/notifications.py.
    notifications_read_at = Column(DateTime)
    # Per-notification read state for items that arrived AFTER
    # `notifications_read_at`. Allows clicking a single notification
    # to dismiss only that row without forcing the user to "Mark all
    # read". List of AuditLog ids (ints). Pruned when the user clicks
    # "Mark all read" because the watermark then supersedes them.
    dismissed_notifications = Column(JSON, default=list)
    # Master switch for outbound collaboration / notification emails.
    # When False, the `services.notifier` helper short-circuits and
    # never sends — applies to project-assignment, report-access-
    # granted, report-version-approved, library-finding-approved,
    # and custom-template-approved templates.
    # Security-critical emails (password reset, password changed)
    # bypass this flag deliberately — a user must be reachable for
    # account-recovery flows even when they've muted notifications.
    notifications_email_enabled = Column(Boolean, default=True, nullable=False)
    # Per-user toggle for the floating "VibeDocs scratchpad" notes widget
    # rendered at the bottom-right of every authenticated page. When
    # False, base.html skips the widget block entirely — no DOM, no
    # JS, no /api/notes polling. Users who prefer a quieter UI can
    # turn it off from /profile and re-enable it any time.
    notes_widget_enabled = Column(Boolean, default=True, nullable=False)
    # Per-user dashboard widget selection. NULL / empty => show the
    # default set (every widget). Otherwise a JSON list of widget keys
    # the user has chosen to display, e.g.
    #   ["reports_owned","pending_reviews","findings_authored"]
    # Drives which stat tiles render on /dashboard. Editable from the
    # dashboard's "Customize" panel; persisted via PATCH /api/auth/me/preferences.
    dashboard_widgets = Column(JSON, default=None)
    # ── SSO Identity (Azure AD / OIDC) ───────────────────────────────────
    # Set when the user authenticated via Azure AD SSO for the first time.
    # sso_provider: "azure_ad" (or future providers such as "okta")
    # sso_subject:  the Azure OID (object ID) — stable across apps in the
    #               tenant, unlike `sub` which is app-scoped.
    # Together they form a unique key used by JIT provisioning in routers/sso.py.
    # NULL on accounts created via the local username+password form.
    sso_provider = Column(String(32), nullable=True, index=True)
    sso_subject  = Column(String(128), nullable=True, index=True)
    # ── Local / Standalone (no-login) mode ───────────────────────────────
    # TRUE only for the singleton built-in account used by the no-login
    # "Local Mode" (the Kali VMware image). The account has role=admin so
    # every approval gate is bypassed; `is_local` lets the UI hide the
    # Admin / Reviews nav that make no sense in a single-user local deploy.
    # FALSE for every SSO and username/password account.
    is_local = Column(Boolean, default=False, nullable=False)

    projects_led = relationship("Project", back_populates="lead", foreign_keys="Project.lead_id")
    findings_contributed = relationship("FindingLibrary", back_populates="created_by",
                                        foreign_keys="FindingLibrary.created_by_id")


# -------- Report Templates --------

class ReportTemplate(Base):
    """
    A Word .docx Jinja template + metadata.
    code is a short identifier (e.g. 'web_vapt', 'infra_vapt', 'api_vapt', 'thick_client_pt',
    'mobile_pt', 'cloud_review'). Findings library entries reference this code so the UI
    can filter the library by template.
    """
    __tablename__ = "report_templates"
    id = Column(Integer, primary_key=True)
    code = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    docx_filename = Column(String(255), nullable=False)        # stored in TEMPLATE_DIR
    # Original filename as the admin chose it locally before upload —
    # preserved verbatim so the admin templates table can show
    # "MyCorpWebVAPT_v3.docx" rather than the hashed `web_vapt__<uuid>.docx`
    # that lives on disk. NULL for templates that have never been
    # admin-replaced; in that case `docx_filename` is itself the
    # canonical name shipped with the deployment.
    original_filename = Column(String(500))
    # Admin-pickable Excel tracker file for this VAPT tasking.
    # NULL = fall back to the legacy `TRACKER_TYPE_BY_CODE`
    # filename-pattern resolver in `tracker_templates.py`. Set to a
    # bare filename (e.g. "XXX Web VAPT Tracking List v0.1.xlsx")
    # under TRACKER_TEMPLATES_DIR to override the routing. Surfaced +
    # editable from the central "Tasking Assignments" admin tab.
    tracker_filename = Column(String(500))
    scope_of_work = Column(Text)                                # default SoW text
    methodology = Column(Text)                                  # default methodology
    # JSON list of dynamic field names this template asks the tester to fill in.
    # e.g. ["client_name","testing_window","user_roles_tested","urls_in_scope"]
    extra_fields = Column(JSON, default=list)
    # Capability flags
    supports_nessus_import = Column(Boolean, default=False)
    supports_nmap_import = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    findings = relationship("FindingLibrary", back_populates="template")
    reports = relationship("Report", back_populates="template")


# -------- Findings Library --------

class FindingLibrary(Base):
    """
    Canonical reusable finding. Scoped to a ReportTemplate so consultants searching
    in an 'Infra VAPT' report see only relevant entries.
    """
    __tablename__ = "finding_library"
    id = Column(Integer, primary_key=True)
    template_id = Column(Integer, ForeignKey("report_templates.id"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    impact = Column(Text)
    remediation = Column(Text)
    references = Column(Text)  # multi-line URLs / CVEs
    # Default severity and CVSS vector. Tester can override per-project.
    default_severity = Column(Enum(Severity), default=Severity.medium)
    default_cvss_vector = Column(String(255))      # e.g. CVSS:4.0/AV:N/AC:L/...
    default_cvss_score = Column(Float)
    # Tagging
    tags = Column(JSON, default=list)              # ["OWASP-A01", "auth", "ssl"]
    # OWASP / CWE references for filtering. `cwe` is widened to 255
    # to hold the canonicalised "CWE-XXX (Human Readable Name)"
    # format that `services.cwe_names.canonicalise` produces — the
    # longer names (e.g. "CWE-1336 (Improper Neutralization of
    # Special Elements Used in a Template Engine)") exceed the
    # original 64-char limit and were silently truncating the
    # `default_cwe` backfill on startup.
    cwe = Column(String(255))
    owasp_category = Column(String(64))

    status = Column(Enum(LibraryStatus), default=LibraryStatus.pending_review)
    created_by_id = Column(Integer, ForeignKey("users.id"))
    reviewed_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    template = relationship("ReportTemplate", back_populates="findings")
    created_by = relationship("User", back_populates="findings_contributed", foreign_keys=[created_by_id])
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])

    __table_args__ = (
        Index("ix_finding_library_title_template", "title", "template_id"),
    )


# -------- Projects --------

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)
    sector = Column(String(64))                # Government / SI / CII / Commercial
    status = Column(String(32), default="active")  # active, closed
    lead_id = Column(Integer, ForeignKey("users.id"), index=True)
    # Scope - free-text plus structured list of targets
    scope_description = Column(Text)
    scope_targets = Column(JSON, default=list)   # ["https://app.example.com","10.0.0.0/24"]
    testing_start = Column(DateTime)
    testing_end = Column(DateTime)
    # Engagement-level structured payload. Holds:
    #   - custom_template_path        (per-project Word template override)
    #   - postman_summary / postman_endpoints   (API VAPT scope auto-import)
    #   - source_code_hashes          (MD5/SHA256 verification chain for source-code review)
    # Free-form so we can add more without schema migrations.
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    lead = relationship("User", back_populates="projects_led", foreign_keys=[lead_id])
    reports = relationship("Report", back_populates="project", cascade="all, delete-orphan")
    scan_imports = relationship("ScanImport", back_populates="project", cascade="all, delete-orphan")


# -------- Reports (a deliverable + its versions) --------

class Report(Base):
    """
    A 'report' is the named deliverable inside a project (e.g. 'Q1 Web App Pentest').
    Each generation produces a ReportVersion. Versions auto-increment (0.1, 0.2, 1.0, ...).

    Ownership & access:
      - `created_by_id` is the report's owner (the tester who created it). Owners always
        have full access and can never be locked out.
      - Additional users get access via `ReportAccess` rows (view / edit / admin levels).
      - Users with `admin` Role also have implicit access to every report.
      - `lead_id` on Project gives the project lead implicit admin access.
    """
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    template_id = Column(Integer, ForeignKey("report_templates.id"), nullable=False)
    name = Column(String(255), nullable=False)        # tester-supplied report name
    current_version = Column(String(16), default="0.1")
    created_by_id = Column(Integer, ForeignKey("users.id"), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Report-level fields shown in 'Report Details' section
    # These mirror the placeholders in the VibeDocs template.
    details = Column(JSON, default=dict)
    # Combined-report test sections — list of dicts:
    #   [{idx, label, scope_name, scope_urls: [str]}]
    # When non-empty, findings are grouped by chapter_idx and each section
    # renders as its own "Detailed Findings" chapter (Ch 3, Ch 4, …).
    report_sections = Column(JSON, default=list)

    project = relationship("Project", back_populates="reports")
    template = relationship("ReportTemplate", back_populates="reports")
    versions = relationship("ReportVersion", back_populates="report",
                            cascade="all, delete-orphan",
                            order_by="ReportVersion.created_at")
    created_by = relationship("User", foreign_keys=[created_by_id])
    access_grants = relationship("ReportAccess",
                                 back_populates="report",
                                 cascade="all, delete-orphan",
                                 foreign_keys="ReportAccess.report_id")


class ReportVersion(Base):
    __tablename__ = "report_versions"
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False, index=True)
    version = Column(String(16), nullable=False)     # e.g. "0.1", "0.2", "1.0"
    is_draft = Column(Boolean, default=True)         # True => watermark applied
    notes = Column(Text)                              # changelog entry
    generated_docx_path = Column(String(500))
    generated_pdf_path = Column(String(500))
    generated_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    # ---- Review workflow ----
    # Stored as plain VARCHAR rather than a Postgres ENUM to avoid the
    # CREATE TYPE / ALTER TABLE dance on live databases. The Python enum
    # `ReportReviewStatus(str, enum.Enum)` subclasses `str`, so equality
    # comparisons like `rv.review_status == ReportReviewStatus.in_review`
    # work transparently against the string value pulled out of the DB.
    # NULL is treated as `draft` for backward compatibility with rows
    # created before the workflow was introduced.
    review_status = Column(String(32), default=ReportReviewStatus.draft.value)
    reviewer_id = Column(Integer, ForeignKey("users.id"))
    submitted_for_review_at = Column(DateTime)
    review_decision_at = Column(DateTime)
    review_notes = Column(Text)

    report = relationship("Report", back_populates="versions")
    findings = relationship("ReportFinding", back_populates="report_version",
                            cascade="all, delete-orphan")
    generated_by = relationship("User", foreign_keys=[generated_by_id])
    reviewer = relationship("User", foreign_keys=[reviewer_id])

    __table_args__ = (
        UniqueConstraint("report_id", "version", name="uq_report_version"),
    )


# -------- Report Access (per-user sharing) --------

class AccessLevel(str, enum.Enum):
    """Granted access level on a report.
    view  : read-only (sees the report on their dashboard, can download generated docs)
    edit  : can add/edit/delete findings, generate new versions
    admin : everything edit can do, plus grant/revoke access to other users
    """
    view = "view"
    edit = "edit"
    admin = "admin"


class ReportAccess(Base):
    """A user-to-report grant. Owners (Report.created_by_id) don't need a row here -
    their access is implicit and immutable.
    """
    __tablename__ = "report_access"
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    access_level = Column(Enum(AccessLevel), default=AccessLevel.edit, nullable=False)
    granted_by_id = Column(Integer, ForeignKey("users.id"))
    granted_at = Column(DateTime, default=datetime.utcnow)
    note = Column(String(255))  # optional reason / context

    report = relationship("Report", back_populates="access_grants", foreign_keys=[report_id])
    user = relationship("User", foreign_keys=[user_id])
    granted_by = relationship("User", foreign_keys=[granted_by_id])

    __table_args__ = (
        UniqueConstraint("report_id", "user_id", name="uq_report_user_access"),
        Index("ix_report_access_user", "user_id"),
    )


# -------- Report Findings (instance of a finding within a report version) --------

class ReportFinding(Base):
    __tablename__ = "report_findings"
    id = Column(Integer, primary_key=True)
    report_version_id = Column(Integer, ForeignKey("report_versions.id"),
                               nullable=False, index=True)
    library_id = Column(Integer, ForeignKey("finding_library.id"), index=True)  # null for manually-added

    title = Column(String(500), nullable=False)
    description = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    references = Column(Text)
    # Widened to Text (no length cap) because the Infra Scan
    # Pipeline groups rows by (finding, port) and emits a
    # comma-joined IP list as the affected_asset — a single
    # "ICMP Timestamp Request" finding on 60 hosts easily blows
    # past 500 chars. Text is unbounded in Postgres; the column
    # still round-trips as a plain string at every existing
    # call-site.
    affected_asset = Column(Text)
    poc_steps = Column(Text)
    severity = Column(Enum(Severity), default=Severity.medium)
    cvss_vector = Column(String(255))
    cvss_score = Column(Float)
    # CWE classification of the finding in the format "CWE-XXX (Human Name)".
    # Seeded from the library finding's `cwe` on add but the consultant can
    # override per-report. Echoed back out into the "CWE ID" column of the
    # exported Risk Register tracker.
    cwe = Column(String(255))
    status = Column(Enum(FindingStatus), default=FindingStatus.open)

    # Retest section - matches VibeDocs template
    retest_notes = Column(Text)
    retest_evidence = Column(JSON, default=list)  # screenshot paths
    client_statement = Column(Text)               # esp. for risk acceptance
    # Date the management comment was given (ISO "YYYY-MM-DD"). Rendered as a
    # "[DD-MM-YYYY] …" prefix on the Management Comments in the Word report.
    # (Legacy single-comment field — mirrors client_statements[0].)
    client_statement_date = Column(String(32))
    # Multiple dated management comments: list of {"date": "YYYY-MM-DD",
    # "text": "..."}. Each renders as its own "[DD-MM-YYYY]\n\n<text>" block so
    # retests/updates append a new dated section under the previous ones.
    client_statements = Column(JSON, default=list)
    # Multiple dated retest follow-up entries: list of {"date": "YYYY-MM-DD",
    # "text": "..."}. Mirrors client_statements but for the consultant's own
    # retest observations.  The legacy scalar retest_notes stays for backward
    # compat; new reports write to this list instead.
    retest_entries = Column(JSON, default=list)

    # Combined-report chapter assignment. NULL = default chapter 3.
    # When a report has multiple test sections (e.g. Web VAPT + API VAPT),
    # each finding is tagged with the 0-based section index it belongs to.
    # chapter_idx=0 → sections[0] → renders as Chapter 3; idx=1 → Chapter 4, etc.
    chapter_idx = Column(Integer, default=None, nullable=True)

    # Provenance
    added_by_id = Column(Integer, ForeignKey("users.id"))
    added_at = Column(DateTime, default=datetime.utcnow)
    # If sourced from a Nessus row, track that
    source = Column(String(32), default="manual")  # manual / library / nessus / nmap
    source_ref = Column(String(255))               # nessus plugin id or similar

    # Screenshots for the finding itself (NOT the retest)
    screenshots = Column(JSON, default=list)       # list of file paths under UPLOAD_DIR
    # File attachments for the finding — populated by the infra-scan
    # pipeline (one Excel workbook per grouped category: Outdated
    # Software, SSL Misconfig, Information Disclosure). Each entry is
    # a dict `{filename, path, kind, label, uploaded_at, uploaded_by}`
    # where `filename` is the user-facing name (kept stable across
    # re-uploads) and `path` is the disk path under UPLOAD_DIR.
    # `label` is rendered as the caption in the Word output / the
    # tracker export.
    attachments = Column(JSON, default=list)

    library = relationship("FindingLibrary")
    report_version = relationship("ReportVersion", back_populates="findings")
    added_by = relationship("User")


# -------- Scan Imports (audit trail for Nessus / Nmap uploads) --------

class ScanImport(Base):
    __tablename__ = "scan_imports"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    report_version_id = Column(Integer, ForeignKey("report_versions.id"))
    scan_type = Column(String(32), nullable=False)  # 'nessus' / 'nmap'
    original_filename = Column(String(500))
    stored_path = Column(String(500))
    uploaded_by_id = Column(Integer, ForeignKey("users.id"))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    summary = Column(JSON, default=dict)
    # summary example for Nessus:
    # { "rows": 1234, "hosts": 30, "findings_created": 42, "auto_closed": 5 }
    # for Nmap:
    # { "hosts": 30, "open_ports": 188 }

    # Nmap: parsed ports table; Nessus: grouped findings preview
    parsed_data = Column(JSON, default=dict)

    project = relationship("Project", back_populates="scan_imports")
    uploaded_by = relationship("User")


# -------- Audit log --------

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(128), nullable=False)
    object_type = Column(String(64))
    object_id = Column(Integer)
    detail = Column(JSON, default=dict)
    at = Column(DateTime, default=datetime.utcnow, index=True)

    actor = relationship("User")


# ============================================================
# Free edit mode + custom templates + reusable snippets +
# reference standards + auth providers
# Added to support: master/per-report prose overrides, client
# custom .docx templates per project/report, OWASP-style
# standards registry, snippet library, SSO provider config.
# ============================================================


class TemplateSection(Base):
    """Master template prose, editable by admins.

    Each ReportTemplate (Web VAPT, API VAPT, etc.) has named sections
    (executive_summary, methodology, scope_disclaimer, ...). Admins edit
    these to update the master prose; the next report generation uses
    the latest text. Existing reports keep the version they were generated
    against because each ReportVersion snapshots resolved prose.

    Sections are referenced from the Word template via Jinja placeholders
    like {{ sections.executive_summary }} or {{ sections.methodology }}.
    """
    __tablename__ = "template_sections"
    id = Column(Integer, primary_key=True)
    template_id = Column(Integer, ForeignKey("report_templates.id"), nullable=False, index=True)
    key = Column(String(64), nullable=False)        # e.g. "executive_summary", "methodology"
    title = Column(String(255))                     # human-readable label for the editor
    body = Column(Text, nullable=False, default="") # the prose (markdown/plain text)
    order = Column(Integer, default=0)              # for UI ordering
    updated_by_id = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    template = relationship("ReportTemplate")
    updated_by = relationship("User")

    __table_args__ = (
        UniqueConstraint("template_id", "key", name="uq_template_section_key"),
    )


class ReportSectionOverride(Base):
    """Per-report override of a master template section.

    If a row exists for (report_id, key), its body wins over the master.
    Consultants edit these per engagement (e.g. tailoring the methodology
    to a specific client) without touching the master.
    """
    __tablename__ = "report_section_overrides"
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False, index=True)
    key = Column(String(64), nullable=False)
    body = Column(Text, nullable=False, default="")
    updated_by_id = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    report = relationship("Report")
    updated_by = relationship("User")

    __table_args__ = (
        UniqueConstraint("report_id", "key", name="uq_report_section_override"),
    )


class TextSnippet(Base):
    """Reusable boilerplate paragraphs (Pwndoc-style).

    Consultants pick snippets from this library when filling in
    description / impact / remediation / steps fields on findings,
    so the team builds up shared phrasing over time. Snippets are
    scoped by category (e.g. 'remediation_password_policy') and
    optionally by report template (Web only, Mobile only, ...).
    """
    __tablename__ = "text_snippets"
    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)       # what shows in the picker
    body = Column(Text, nullable=False)                # the actual text to insert
    category = Column(String(64), nullable=False, index=True)
    # category examples:
    #   "description" / "impact" / "remediation" / "steps" / "exec_summary_intro"
    template_id = Column(Integer, ForeignKey("report_templates.id"), index=True, nullable=True)
    # If set, snippet only appears for this template. NULL = visible everywhere.
    tags = Column(JSON, default=list)                  # ["owasp_a03", "auth"] etc.
    language = Column(String(8), default="en")         # future i18n hook
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    use_count = Column(Integer, default=0)             # popularity ranking in picker

    template = relationship("ReportTemplate")
    created_by = relationship("User")

    __table_args__ = (
        Index("ix_snippet_category_template", "category", "template_id"),
    )


class ReferenceStandard(Base):
    """Versioned reference frameworks (OWASP Top 10, NIST, CWE, etc.).

    When OWASP releases Top 10 2027, admins upload it as a new
    ReferenceStandard with version='2027'. Findings reference entries by
    (standard_id, entry_id). is_active=True means it shows up in dropdowns;
    older versions stay queryable for historical reports.
    """
    __tablename__ = "reference_standards"
    id = Column(Integer, primary_key=True)
    code = Column(String(32), nullable=False, index=True)   # "owasp_top10", "nist_csf"
    name = Column(String(255), nullable=False)              # "OWASP Top 10"
    version = Column(String(32), nullable=False)            # "2021", "2027"
    is_active = Column(Boolean, default=True)
    description = Column(Text)
    entries = Column(JSON, default=list)
    # entries example for OWASP:
    # [
    #   {"id": "A01:2021", "title": "Broken Access Control",
    #    "url": "https://owasp.org/Top10/A01_2021/"},
    #   {"id": "A02:2021", "title": "Cryptographic Failures", ...},
    # ]
    uploaded_by_id = Column(Integer, ForeignKey("users.id"))
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    uploaded_by = relationship("User")

    __table_args__ = (
        UniqueConstraint("code", "version", name="uq_standard_code_version"),
    )


# ---- Custom client templates (per project / per report overrides) ----
# We don't need new tables for these -- adding columns to Project and Report
# below would be cleaner, but to avoid mutating the existing Base classes,
# we keep the override as a JSON detail entry handled by the generator.
# See services/docx_generator.resolve_template_path().


class AuthProviderConfig(Base):
    """Pluggable auth backend config (Local now; OIDC for VibeDocs SSO later).

    Only one provider is active at a time. Switching from local to OIDC
    doesn't delete local users -- they remain available as a fallback
    until an admin disables them individually.
    """
    __tablename__ = "auth_provider_configs"
    id = Column(Integer, primary_key=True)
    provider_type = Column(String(32), nullable=False)  # "local" / "oidc" / "saml"
    is_active = Column(Boolean, default=False)
    name = Column(String(255))                          # "VibeDocs Azure AD"
    # config_json is provider-specific:
    # OIDC: {"issuer": "...", "client_id": "...", "client_secret_env": "OIDC_SECRET",
    #        "scopes": ["openid","email","profile"], "username_claim": "preferred_username"}
    config_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================================
# Two-Factor Authentication (TOTP)
#
# Compatible with Google Authenticator, Microsoft Authenticator, Authy,
# and any other RFC 6238 TOTP app.
#
# Flow:
#   1. User initiates enrollment: server generates a secret (stored in
#      User.totp_secret) and returns it + a QR code (otpauth:// URI).
#   2. User scans the QR code, enters a 6-digit code from the app.
#      Server verifies; if valid, sets totp_enabled=True.
#   3. Server also generates 10 backup codes (stored hashed in
#      TOTPBackupCode). User downloads them for recovery.
#   4. Login: after username+password, if totp_enabled the server returns
#      a "totp_required" challenge instead of an access token. The client
#      submits the code (or one of the unused backup codes) to complete
#      authentication.
#
# Backup codes are single-use (marked used after redemption) and stored
# hashed (bcrypt). They survive losing the authenticator device.
# ============================================================


class EmailTemplate(Base):
    """Admin-editable email body templates.

    Each template is identified by a stable `key` (e.g. "password_reset",
    "project_deleted") that the router code looks up at send time. The
    body is rendered through a small Jinja2 sandbox so admins can
    insert variables like {{ user.full_name }} and {{ reset_url }} —
    see services.email_templates.render_template for the allow-list of
    variables per key.

    Hardcoded defaults still live in services.email_templates as a
    safety net: if the DB row hasn't been seeded yet (fresh deploy) the
    code falls back to those, so password reset never breaks on a
    missing row.
    """
    __tablename__ = "email_templates"
    id = Column(Integer, primary_key=True)
    key = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(255))
    subject = Column(Text, nullable=False)
    body_text = Column(Text, nullable=False)
    body_html = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by_id = Column(Integer, ForeignKey("users.id"))


class PasswordResetToken(Base):
    """Single-use reset tokens emailed to users when they hit "forgot password".

    Storage model:
      - `token_hash`: bcrypt hash of the random URL token. The plaintext token
        is sent ONCE in the reset email and never stored. On reset, we hash
        the candidate and compare; this means a DB read can't be replayed.
      - `csrf_token_hash`: independent token issued when the user opens the
        reset form. The form submits the plaintext CSRF token, which we hash
        and match here. Prevents replay of the URL alone from anywhere except
        a real browser that has visited the form first.
      - `expires_at`: 30-minute window by default; older rows are ignored.
      - `used_at`: set on successful reset; prevents re-use.
      - `requested_ip` / `user_agent`: forensics if a reset is contested.
    """
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(255), nullable=False, index=True)
    csrf_token_hash = Column(String(255))
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime)
    requested_ip = Column(String(64))
    user_agent = Column(String(255))

    user = relationship("User")


class AccountUnlockToken(Base):
    """Single-use tokens emailed to locked users to self-service unlock.

    Minted by an admin via POST /api/admin/panel/users/{uid}/send-unlock-link.
    The user clicks the link → POST /api/auth/unlock?token=<plaintext> which
    verifies the bcrypt hash, clears the lock, and marks the token used.
    Token TTL mirrors the password-reset TTL (30 minutes by default).
    """
    __tablename__ = "account_unlock_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(255), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime)
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", foreign_keys=[user_id])


class TOTPBackupCode(Base):
    """One-time recovery codes shown at TOTP enrollment.

    Stored hashed, single-use. After enrollment we generate 10 of these and
    show them to the user once -- they're responsible for saving them.
    """
    __tablename__ = "totp_backup_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code_hash = Column(String(255), nullable=False)
    used_at = Column(DateTime)  # NULL = unused
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


# ============================================================
# CUSTOM TEMPLATE SYSTEM
# Allows users to upload client-specific Word templates with
# visual placeholder marking, approval workflow, and sharing.
# ============================================================


class CustomTemplate(Base):
    """User-uploaded Word template with marked placeholders.
    
    Workflow:
    1. User uploads .docx file
    2. Visual editor lets them click to mark where placeholders go
    3. Placeholder mappings stored in JSON
    4. User submits for admin review
    5. Admin approves → becomes available to all consultants
    """
    __tablename__ = "custom_templates"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # File storage
    docx_path = Column(String(500), nullable=False)  # /data/custom_templates/template_{id}.docx
    docx_filename = Column(String(255))  # Original filename
    docx_hash = Column(String(64))  # SHA256 for integrity check
    
    # Placeholder mappings - JSON structure:
    # {
    #   "client_name": {"paragraph": 3, "text_sample": "Client Name: ..."},
    #   "project_title": {"paragraph": 5, "text_sample": "Project: ..."},
    #   "findings_table": {"paragraph": 12, "text_sample": "Findings..."},
    # }
    placeholder_map = Column(JSON, default=dict)
    
    # Approval workflow
    status = Column(Enum(TemplateStatus), default=TemplateStatus.draft, nullable=False)
    reviewed_by_id = Column(Integer, ForeignKey("users.id"))
    reviewed_at = Column(DateTime)
    review_notes = Column(Text)
    
    # Sharing scope
    is_public = Column(Boolean, default=False)  # If true, all users can use it
    project_id = Column(Integer, ForeignKey("projects.id"))  # If set, project-specific
    uploaded_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Template type - which report types it applies to
    template_type = Column(
    String,
    default="web_vapt",
    comment="Template type: web_vapt, mobile_vapt, network_vapt, wifi_pt, source_code_review, cloud_vapt, cloud_pt, kiosk_pt"
    )

    
    # Relationships
    uploaded_by = relationship("User", foreign_keys=[uploaded_by_id])
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
    project = relationship("Project", foreign_keys=[project_id])
    placeholders = relationship("TemplatePlaceholder", back_populates="template", cascade="all, delete-orphan")


class TemplatePlaceholder(Base):
    """Individual placeholder marking within a custom template.
    
    Stores the location and metadata for each required placeholder
    (client_name, findings, etc.) that the user marked in the visual editor.
    """
    __tablename__ = "template_placeholders"
    
    id = Column(Integer, primary_key=True)
    template_id = Column(Integer, ForeignKey("custom_templates.id"), nullable=False)
    
    # Placeholder identification
    placeholder_key = Column(String(100), nullable=False)  # "client_name", "findings", etc.
    placeholder_type = Column(String(20), nullable=False)  # "text", "list", "table"
    display_name = Column(String(200), nullable=False)  # "Client Name", "Findings List"
    is_required = Column(Boolean, default=True)
    
    # Location in document - JSON structure:
    # {"paragraph": 5, "run": 0, "text_sample": "Client Name: [____]"}
    location_json = Column(JSON)

    # Relationships
    template = relationship("CustomTemplate", back_populates="placeholders")


# ============================================================
# Permission overrides (system-wide RBAC layer on top of Role)
#
# The Role column on `users` gives every user a baseline set of
# capabilities (admin / senior / consultant / viewer). The two tables
# below let admins customise that baseline:
#
#   * UserPermissionOverride
#       Per-user grant or revoke of a specific permission code (e.g.
#       "project.create"). A row with `granted=True` adds a permission
#       the role wouldn't otherwise carry; `granted=False` revokes one
#       the role normally would.
#
#   * RolePermissionOverride
#       Adjusts the default permission set for an entire role, without
#       a code change. Useful for one-off site-policy tweaks ("seniors
#       can delete library entries here, even though they can't in the
#       default mapping").
#
# Permission STRINGS are stored verbatim — see
# `services.permissions_service.Permission` for the catalog. Strings
# (not enum columns) keep the table forward-compatible with new
# permissions added in code without a schema migration.
# ============================================================


class UserPermissionOverride(Base):
    """Per-user permission grant or revoke. UNIQUE on (user_id,
    permission) so we only have one row per (user, permission) pair —
    re-granting flips the row in place rather than appending.
    """
    __tablename__ = "user_permission_overrides"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"),
                      nullable=False, index=True)
    permission = Column(String(64), nullable=False, index=True)
    granted = Column(Boolean, default=True, nullable=False)
    granted_by_id = Column(Integer, ForeignKey("users.id"))
    granted_at = Column(DateTime, default=datetime.utcnow)
    note = Column(String(500))

    user = relationship("User", foreign_keys=[user_id])
    granted_by = relationship("User", foreign_keys=[granted_by_id])

    __table_args__ = (
        UniqueConstraint("user_id", "permission",
                          name="uq_user_permission_override"),
    )


class RolePermissionOverride(Base):
    """Adjustment to a role's default permission set. UNIQUE on
    (role, permission) so a role+permission pair has at most one row.
    The hardcoded defaults in
    `services.permissions_service.ROLE_DEFAULT_PERMISSIONS` are the
    baseline; rows here override them.
    """
    __tablename__ = "role_permission_overrides"
    id = Column(Integer, primary_key=True)
    role = Column(String(32), nullable=False, index=True)
    permission = Column(String(64), nullable=False, index=True)
    granted = Column(Boolean, default=True, nullable=False)
    updated_by_id = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime, default=datetime.utcnow,
                         onupdate=datetime.utcnow)

    updated_by = relationship("User")

    __table_args__ = (
        UniqueConstraint("role", "permission",
                          name="uq_role_permission_override"),
    )


# -------- Per-consultant sticky notes / pending-task tracker --------

class UserNote(Base):
    """Free-form note stored per-user for the floating terminal-style
    notes widget. Surfaced on every page so the consultant can jot
    down pending reports / TODOs / engagement scratch and have them
    persist across sessions.

    Intentionally minimal: just `content` + `is_done`. No tagging, no
    sharing, no rich text. The widget renders this as a plain
    terminal-style checklist; anything more elaborate would compete
    with the actual reports / findings library.
    """
    __tablename__ = "user_notes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"),
                      nullable=False, index=True)
    content = Column(Text, nullable=False)
    is_done = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow,
                         nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow,
                         onupdate=datetime.utcnow, nullable=False)

    user = relationship("User", foreign_keys=[user_id])


# -------- Persistent rate-limit hit log (shared across uvicorn workers) --------

class RateLimitHit(Base):
    """One row per request counted against a rate-limited bucket.
    Used by services.rate_limit.hit_db() so the sliding-window limiter
    works correctly when uvicorn runs with --workers > 1.

    hit_db() prunes expired rows for (bucket, key) on each call so the
    table stays small without a separate background sweeper.
    """
    __tablename__ = "rate_limit_hits"
    id = Column(Integer, primary_key=True)
    bucket = Column(String(64), nullable=False)
    key = Column(String(255), nullable=False)
    hit_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_rate_limit_hits_bk", "bucket", "key", "hit_at"),
    )
