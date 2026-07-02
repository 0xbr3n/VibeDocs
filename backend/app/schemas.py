"""Pydantic schemas. Kept lean - we use SQLAlchemy models as the source of truth."""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, EmailStr, Field, model_validator
from .models import Role, Severity, FindingStatus, LibraryStatus


# ---- Auth ----

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    password: str
    role: Role = Role.consultant


class UserOut(BaseModel):
    id: int
    username: str
    # Plain str (not EmailStr) on the RESPONSE: stored emails may be synthetic
    # placeholders for accounts created without one (e.g. the local-standalone
    # user "local@standalone.local", or self-registrations "<user>@vibedocs.local").
    # Strict EmailStr validation on output rejects reserved TLDs like .local and
    # 500s the whole endpoint. Input is still validated via UserCreate.email.
    email: str
    full_name: Optional[str] = None
    role: Role
    is_active: bool

    class Config:
        from_attributes = True


# ---- Templates ----

class TemplateOut(BaseModel):
    id: int
    code: str
    name: str
    description: Optional[str] = None
    docx_filename: str
    # Admin-uploaded original filename (what the admin's local file was
    # called before we stamped it with a UUID-suffixed safe_name). NULL
    # for templates that have never been replaced via the admin UI — in
    # that case `docx_filename` already IS the canonical name.
    original_filename: Optional[str] = None
    scope_of_work: Optional[str] = None
    methodology: Optional[str] = None
    extra_fields: list = []
    supports_nessus_import: bool
    supports_nmap_import: bool
    # Expose `is_active` so the admin UI can round-trip the toggle
    # against the server's authoritative value after a PATCH. Without
    # this the JS can't distinguish "Saved as enabled" from "Saved as
    # disabled" by reading the response, and was inferring state from
    # `toggle.checked` (the pre-PATCH DOM state) — fine on the happy
    # path but a footgun if the server ever decides to coerce.
    is_active: bool = True
    # On-disk byte size of the .docx the row points at, or None when
    # the file is missing. Populated by the templates list endpoint so
    # the admin panel can show a Size column for admin-uploaded files
    # (which the `/diagnose-defaults` endpoint can't match because it
    # only iterates canonical filenames). Not stored on the model —
    # computed at serialise time from TEMPLATE_DIR + docx_filename.
    docx_filesize: Optional[int] = None
    # Per-tasking Excel tracker override. NULL = legacy filename-pattern
    # mapping wins (see `services/tracker_templates.py`). Set to a
    # bare filename under `TRACKER_TEMPLATES_DIR` to bind a specific
    # .xlsx to this VAPT tasking. Editable from the Tasking Assignments
    # admin tab.
    tracker_filename: Optional[str] = None

    class Config:
        from_attributes = True


# ---- Findings library ----

class FindingLibraryBase(BaseModel):
    template_id: int
    title: str
    description: str
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[str] = None
    default_severity: Severity = Severity.medium
    default_cvss_vector: Optional[str] = None
    default_cvss_score: Optional[float] = None
    tags: list[str] = []
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None


class FindingLibraryCreate(FindingLibraryBase):
    pass


class FindingLibraryOut(FindingLibraryBase):
    id: int
    status: LibraryStatus
    created_by_id: Optional[int] = None
    reviewed_by_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    created_by_username: Optional[str] = None

    @model_validator(mode='before')
    @classmethod
    def _extract_creator_username(cls, v: Any) -> Any:
        if hasattr(v, 'created_by'):
            try:
                cb = v.created_by
                if cb is not None:
                    v.__dict__['created_by_username'] = cb.username
            except Exception:
                pass
        return v

    class Config:
        from_attributes = True


# ---- Projects ----

class ProjectCreate(BaseModel):
    name: str
    client_name: str
    sector: Optional[str] = None
    scope_description: Optional[str] = None
    scope_targets: list[str] = []
    testing_start: Optional[datetime] = None
    testing_end: Optional[datetime] = None
    # Template-specific scope (mobile: app name + platforms; etc.) lands here.
    # Kept loose so future template types can extend without a schema bump.
    details: dict = {}


class ProjectOut(BaseModel):
    id: int
    name: str
    client_name: str
    sector: Optional[str] = None
    status: str
    scope_description: Optional[str] = None
    scope_targets: list = []
    testing_start: Optional[datetime] = None
    testing_end: Optional[datetime] = None
    lead_id: Optional[int] = None
    created_at: datetime
    # Free-form JSON for non-schema fields: client_poc {name,email},
    # remarks, mobile_app_name, mobile_platforms, custom_template_path,
    # postman_summary, source_code_hashes, scope_description. Anything
    # the UI / generator needs without a column.
    details: dict = {}

    class Config:
        from_attributes = True


# ---- Reports ----

class ReportCreate(BaseModel):
    project_id: int
    template_id: int
    name: str
    initial_version: str = "0.1"
    # Required milestone label for the initial version. Must be one of
    # the kinds the versions list renders: "initial" / "retest" /
    # "final" / "update". Mandatory at creation so the report's first
    # version never lands as "Uncategorised" in the versions table —
    # consultants want to see the report's stage at a glance from day
    # one rather than backfill it later. We accept the bare codes here
    # (matching the `New Version` modal's <option value> set) and
    # store them as a `[code]` prefix on `ReportVersion.notes`.
    report_kind: str = "initial"
    details: dict = {}


class ReportOut(BaseModel):
    id: int
    project_id: int
    template_id: int
    name: str
    current_version: str
    details: dict
    created_at: datetime

    class Config:
        from_attributes = True


# ---- Report findings ----

class ReportFindingCreate(BaseModel):
    library_id: Optional[int] = None  # null = manual entry
    title: str
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[str] = None
    affected_asset: Optional[str] = None
    poc_steps: Optional[str] = None
    severity: Severity = Severity.medium
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    # Free-form CWE classification — format "CWE-XXX (Human Name)" by
    # convention but accepted as any string so consultants can paste raw
    # CWE-IDs from external sources without manual reformatting.
    cwe: Optional[str] = None
    # Combined-report chapter assignment (0-based section index, NULL = default).
    chapter_idx: Optional[int] = None


class ReportFindingOut(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[str] = None
    affected_asset: Optional[str] = None
    poc_steps: Optional[str] = None
    severity: Severity
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe: Optional[str] = None
    status: FindingStatus
    retest_notes: Optional[str] = None
    retest_evidence: list = []
    client_statement: Optional[str] = None
    client_statement_date: Optional[str] = None
    client_statements: list = []
    retest_entries: list = []
    chapter_idx: Optional[int] = None
    screenshots: list = []
    added_by_id: Optional[int] = None
    added_at: datetime
    source: str
    source_ref: Optional[str] = None
    attachments: list = []

    class Config:
        from_attributes = True


class RetestUpdate(BaseModel):
    retest_notes: Optional[str] = None
    status: Optional[FindingStatus] = None
    client_statement: Optional[str] = None
    client_statement_date: Optional[str] = None
    client_statements: list = []
    retest_entries: list = []


# ---- Generation ----

class GenerateRequest(BaseModel):
    is_draft: bool = True   # toggles watermark
    notes: Optional[str] = None
    increment_version: bool = True
    as_pdf: bool = False
    # ---- Encrypted ZIP packaging (optional) ----
    # When `encrypt=True` the renderer also produces an AES-256 ZIP
    # containing the DOCX (and PDF, if `as_pdf=True`). Exactly one of
    # `encrypt_password` (new plaintext) or `reuse_password_id` (id of a
    # previously-stored project password) must be supplied.
    encrypt: bool = False
    encrypt_password: Optional[str] = None
    reuse_password_id: Optional[str] = None
    # Optional human label for the saved password ("Acme zip Q2 2026").
    # Ignored when reusing an existing record.
    encrypt_password_label: Optional[str] = None
    # If True (default), a fresh plaintext password is encrypted-at-rest
    # under the parent project for future reuse. Set False if the user is
    # generating a one-off bundle and doesn't want it remembered.
    encrypt_save_password: bool = True
