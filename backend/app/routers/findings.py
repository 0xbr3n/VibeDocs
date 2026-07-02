"""
Findings library: the team-wide knowledge base of canonical findings,
scoped per ReportTemplate type (Web VAPT, Infra VAPT, etc).

Workflow:
1. Any consultant can submit a finding (status=pending_review).
2. A senior or admin can approve (status=approved).
3. Approved findings appear by default in the picker; non-approved ones can be opted into.
4. Searchable by title, description, tags, OWASP / CWE.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..models import FindingLibrary, LibraryStatus, User, Role, AuditLog, ReportTemplate
from ..schemas import FindingLibraryCreate, FindingLibraryOut
from ..auth import get_current_user, require_roles
from ..services.cvss_v4 import parse_vector

router = APIRouter(prefix="/api/findings-library", tags=["findings-library"])


@router.get("", response_model=list[FindingLibraryOut])
def search(
    template_id: Optional[int] = None,
    q: Optional[str] = Query(None, description="Free-text search across title/description/tags"),
    status: Optional[LibraryStatus] = None,
    include_pending: bool = False,
    limit: int = Query(default=100, ge=1, le=2000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Findings library search.

    Visibility model (applied when no explicit `status` filter is given):
      • Everyone sees: every approved finding.
      • The author sees: their own findings regardless of status — so a
        consultant who just created a new finding can reuse it
        immediately on their next report even though it's still
        `pending_review` for everyone else.
      • Admins / seniors with `include_pending=true` see: the global
        pending queue (everyone's pending findings, for review).

    This replaces the previous behaviour where a consultant's own brand
    new finding silently disappeared from the picker until an admin
    approved it.
    """
    query = db.query(FindingLibrary).options(joinedload(FindingLibrary.created_by))
    if template_id:
        # Match findings whose PRIMARY template_id is this one OR
        # whose `tags` JSON list contains `template:<code>`. This is
        # what makes a SSRF / SSTI / etc. finding (primary template
        # `web_vapt`, extra-tagged `template:api_vapt`) actually
        # appear when the consultant is browsing under the API VAPT
        # template. Without the tag arm of the OR, only the primary
        # template ever saw the finding even though the seeder
        # explicitly tagged it as cross-applicable.
        from sqlalchemy import String, cast
        tpl_row = db.get(ReportTemplate, template_id)
        if tpl_row and tpl_row.code:
            tag_token = f'"template:{tpl_row.code}"'
            query = query.filter(or_(
                FindingLibrary.template_id == template_id,
                # Cast the JSON column to text and substring-match
                # the tag token. Works on Postgres regardless of
                # whether the column is JSON or JSONB and avoids the
                # dialect-specific `?` operator.
                cast(FindingLibrary.tags, String).ilike(f"%{tag_token}%"),
            ))
        else:
            query = query.filter(FindingLibrary.template_id == template_id)
    if status:
        # Explicit status request — respect it, but still scope so a
        # plain consultant can't enumerate other users' drafts.
        query = query.filter(FindingLibrary.status == status)
        if user.role not in (Role.admin, Role.senior) and status != LibraryStatus.approved:
            query = query.filter(FindingLibrary.created_by_id == user.id)
    elif include_pending and user.role in (Role.admin, Role.senior):
        # Admin / senior review queue: approved + every pending row.
        query = query.filter(FindingLibrary.status.in_(
            [LibraryStatus.approved, LibraryStatus.pending_review]
        ))
    else:
        # Default feed: approved findings ∪ caller's own findings (any status).
        # This is what makes the "draft is immediately reusable by its author"
        # behaviour work — own pending/draft rows still appear in the picker.
        query = query.filter(or_(
            FindingLibrary.status == LibraryStatus.approved,
            FindingLibrary.created_by_id == user.id,
        ))
    if q:
        pat = f"%{q}%"
        query = query.filter(or_(
            FindingLibrary.title.ilike(pat),
            FindingLibrary.description.ilike(pat),
            FindingLibrary.cwe.ilike(pat),
            FindingLibrary.owasp_category.ilike(pat),
        ))
    return query.order_by(FindingLibrary.title).limit(limit).all()


@router.get("/{finding_id}", response_model=FindingLibraryOut)
def get_finding(finding_id: int, db: Session = Depends(get_db),
                _: User = Depends(get_current_user)):
    f = (
        db.query(FindingLibrary)
        .options(joinedload(FindingLibrary.created_by))
        .filter(FindingLibrary.id == finding_id)
        .first()
    )
    if not f:
        raise HTTPException(404, "Not found")
    return f


@router.post("", response_model=FindingLibraryOut)
def create_finding(
    payload: FindingLibraryCreate,
    submit_for_review: bool = Query(
        False,
        description="If true, the new finding goes straight into the admin "
                    "review queue. If false (default), it stays as a personal "
                    "draft only the author can pick from.",
    ),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a new library finding.

    Lifecycle for a regular consultant:
      1. Save as `draft` — visible only to the author. They can reuse
         it immediately on their own reports via the picker (which now
         OR-includes own findings regardless of status).
      2. Optionally call POST /{id}/submit-for-review (or pass
         `?submit_for_review=true` on creation) to push it into the
         admin queue as `pending_review`.
      3. Admin / senior approves → `approved`, visible team-wide.

    Admin / senior users can skip the queue: their new findings land
    as `approved` directly (they're the reviewer).
    """
    if payload.default_cvss_vector:
        try:
            parse_vector(payload.default_cvss_vector)
        except ValueError as e:
            raise HTTPException(400, f"Invalid CVSS vector: {e}")

    if user.role in (Role.admin, Role.senior):
        initial_status = LibraryStatus.approved
    elif submit_for_review:
        initial_status = LibraryStatus.pending_review
    else:
        initial_status = LibraryStatus.draft

    f = FindingLibrary(
        **payload.model_dump(),
        status=initial_status,
        created_by_id=user.id,
        reviewed_by_id=user.id if initial_status == LibraryStatus.approved else None,
    )
    db.add(f); db.commit(); db.refresh(f)
    return f


@router.post("/{finding_id}/submit-for-review", response_model=FindingLibraryOut)
def submit_finding_for_review(
    finding_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Promote a personal draft to the admin review queue.

    The author of the draft (or an admin/senior) flips its status from
    `draft` → `pending_review`. The admin queue endpoint
    (`GET /api/findings-library?include_pending=true`) will then surface
    it for approval. Already-approved or already-pending rows are
    rejected with 400 so re-submission is explicit.
    """
    f = db.get(FindingLibrary, finding_id)
    if not f:
        raise HTTPException(404, "Not found")
    if user.role not in (Role.admin, Role.senior) and f.created_by_id != user.id:
        raise HTTPException(403, "Only the author or an admin can submit this finding")
    if f.status == LibraryStatus.approved:
        raise HTTPException(400, "Finding is already approved")
    if f.status == LibraryStatus.pending_review:
        raise HTTPException(400, "Finding is already awaiting review")
    f.status = LibraryStatus.pending_review
    # AuditLog row drives the in-app bell + the Reviews page; admins /
    # seniors see it as a new pending review task.
    db.add(AuditLog(
        actor_id=user.id,
        action="finding.review.requested",
        object_type="finding_library",
        object_id=f.id,
        detail={
            "finding_title": f.title,
            "severity": (f.default_severity.value
                         if f.default_severity else None),
        },
    ))
    db.commit(); db.refresh(f)
    return f


@router.put("/{finding_id}", response_model=FindingLibraryOut)
def update_finding(
    finding_id: int,
    payload: FindingLibraryCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    f = db.get(FindingLibrary, finding_id)
    if not f:
        raise HTTPException(404, "Not found")
    # Author can edit own pending entry; senior/admin can edit any
    if user.role not in (Role.admin, Role.senior) and f.created_by_id != user.id:
        raise HTTPException(403, "Not your finding")
    for k, v in payload.model_dump().items():
        setattr(f, k, v)
    db.commit(); db.refresh(f)
    return f


@router.post("/{finding_id}/approve", response_model=FindingLibraryOut)
def approve_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.senior)),
):
    f = db.get(FindingLibrary, finding_id)
    if not f:
        raise HTTPException(404, "Not found")
    prev_status = f.status.value if f.status else None
    f.status = LibraryStatus.approved
    f.reviewed_by_id = user.id
    # Notify the original submitter that their finding is live.
    db.add(AuditLog(
        actor_id=user.id,
        action="finding.review.decided",
        object_type="finding_library",
        object_id=f.id,
        detail={
            "finding_title": f.title,
            "decision": "approved",
            "previous_status": prev_status,
            "submitter_id": f.created_by_id,
        },
    ))
    db.commit(); db.refresh(f)

    # Best-effort approval email to the finding submitter. Routed
    # through `notify_user` so the submitter's email-opt-out applies
    # and self-trigger is short-circuited (admin approving their own
    # draft never emails themselves).
    if f.created_by_id:
        from ..services.notifier import notify_user
        from ..services.url_helpers import absolute_url
        submitter = db.get(User, f.created_by_id)
        notify_user(
            db, submitter, "finding_approved", {
                "user": submitter,
                "reviewer_username": user.username,
                "finding_title": f.title,
                "finding_url": absolute_url(f"/library?finding={f.id}"),
            },
            actor_user_id=user.id,
        )

    return f


@router.post("/{finding_id}/reject", response_model=FindingLibraryOut)
def reject_finding(
    finding_id: int,
    notes: Optional[str] = Query(None, description="Reason shown to the submitter"),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Reject a pending finding. Pushes it back to `draft` (visible
    only to the author) so they can clean it up and resubmit. We don't
    use a `rejected` state on findings (no enum value) — draft +
    reviewer notes covers the same ground.
    """
    f = db.get(FindingLibrary, finding_id)
    if not f:
        raise HTTPException(404, "Not found")
    if f.status != LibraryStatus.pending_review:
        raise HTTPException(400, "Finding is not awaiting review")
    f.status = LibraryStatus.draft
    f.reviewed_by_id = user.id
    db.add(AuditLog(
        actor_id=user.id,
        action="finding.review.decided",
        object_type="finding_library",
        object_id=f.id,
        detail={
            "finding_title": f.title,
            "decision": "rejected",
            "notes": notes or "",
            "submitter_id": f.created_by_id,
        },
    ))
    db.commit(); db.refresh(f)
    return f


@router.delete("/{finding_id}")
def delete_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin, Role.senior)),
):
    f = db.get(FindingLibrary, finding_id)
    if not f:
        raise HTTPException(404, "Not found")
    db.delete(f); db.commit()
    return {"ok": True}


# ============================================================
# Multi-template categorisation
# ============================================================
# A single finding (e.g. "Stored XSS") often applies to multiple report types:
# Web VAPT, API PT, Mobile PT. We surface that by storing extra applicability
# as "template:<code>" entries inside the existing `tags` JSON column — no
# schema migration needed, just a convention.

# Keyword → list of applicable template codes. Hand-built from common VAPT
# nomenclature. Each finding gets ALL templates whose keyword list contains
# any matching word/phrase in its title or description (case-insensitive).
_CLASSIFICATION_RULES: list[tuple[str, list[str]]] = [
    # phrase                              -> applicable template codes
    ("xss",                               ["web_vapt", "api_vapt", "mobile_pt"]),
    ("cross-site scripting",              ["web_vapt", "api_vapt", "mobile_pt"]),
    ("sql injection",                     ["web_vapt", "api_vapt"]),
    ("sqli",                              ["web_vapt", "api_vapt"]),
    ("csrf",                              ["web_vapt"]),
    ("cross-site request forgery",        ["web_vapt"]),
    ("clickjacking",                      ["web_vapt"]),
    ("session fixation",                  ["web_vapt", "api_vapt"]),
    ("idor",                              ["web_vapt", "api_vapt", "mobile_pt"]),
    ("insecure direct object",            ["web_vapt", "api_vapt", "mobile_pt"]),
    ("broken access control",             ["web_vapt", "api_vapt", "mobile_pt"]),
    ("broken authentication",             ["web_vapt", "api_vapt", "mobile_pt"]),
    ("rate limit",                        ["web_vapt", "api_vapt"]),
    ("missing rate",                      ["web_vapt", "api_vapt"]),
    ("jwt",                               ["web_vapt", "api_vapt", "mobile_pt"]),
    ("oauth",                             ["web_vapt", "api_vapt", "mobile_pt"]),
    ("graphql",                           ["api_vapt"]),
    ("xxe",                               ["web_vapt", "api_vapt"]),
    ("xml external entity",               ["web_vapt", "api_vapt"]),
    ("ssrf",                              ["web_vapt", "api_vapt"]),
    ("server-side request forgery",       ["web_vapt", "api_vapt"]),
    ("rce",                               ["web_vapt", "api_vapt", "infra_vapt", "infra_va"]),
    ("remote code execution",             ["web_vapt", "api_vapt", "infra_vapt", "infra_va"]),
    ("command injection",                 ["web_vapt", "api_vapt", "infra_vapt"]),
    ("deserialization",                   ["web_vapt", "api_vapt", "thick_client_pt"]),
    ("ldap injection",                    ["web_vapt", "api_vapt", "infra_vapt"]),
    ("path traversal",                    ["web_vapt", "api_vapt"]),
    ("directory traversal",               ["web_vapt", "api_vapt"]),
    ("file upload",                       ["web_vapt", "api_vapt", "mobile_pt"]),
    ("ssl",                               ["web_vapt", "api_vapt", "infra_vapt", "infra_va"]),
    ("tls",                               ["web_vapt", "api_vapt", "infra_vapt", "infra_va"]),
    ("certificate",                       ["web_vapt", "api_vapt", "infra_vapt", "infra_va", "mobile_pt"]),
    ("weak cipher",                       ["infra_vapt", "infra_va", "web_vapt", "api_vapt"]),
    ("smb",                               ["infra_vapt", "infra_va"]),
    ("smbv1",                             ["infra_vapt", "infra_va"]),
    ("netbios",                           ["infra_vapt", "infra_va"]),
    ("snmp",                              ["infra_vapt", "infra_va"]),
    ("rdp",                               ["infra_vapt", "infra_va"]),
    ("default credentials",               ["infra_vapt", "infra_va", "web_vapt", "api_vapt"]),
    ("open port",                         ["infra_vapt", "infra_va"]),
    ("eol",                               ["infra_vapt", "infra_va"]),
    ("end of life",                       ["infra_vapt", "infra_va"]),
    ("end-of-life",                       ["infra_vapt", "infra_va"]),
    ("unsupported",                       ["infra_vapt", "infra_va"]),
    ("missing patch",                     ["infra_vapt", "infra_va"]),
    ("dns ",                              ["infra_vapt", "infra_va"]),
    ("debug",                             ["web_vapt", "api_vapt", "infra_vapt", "thick_client_pt"]),
    ("verbose error",                     ["web_vapt", "api_vapt", "infra_vapt"]),
    ("information disclosure",            ["web_vapt", "api_vapt", "infra_vapt", "infra_va", "mobile_pt"]),
    ("cors",                              ["web_vapt", "api_vapt"]),
    ("security header",                   ["web_vapt"]),
    ("cookie",                            ["web_vapt", "api_vapt"]),
    ("samesite",                          ["web_vapt"]),
    ("httponly",                          ["web_vapt"]),
    ("hsts",                              ["web_vapt"]),
    ("csp",                               ["web_vapt"]),
    ("content security policy",           ["web_vapt"]),
    ("api key",                           ["api_vapt", "mobile_pt", "thick_client_pt"]),
    ("hardcoded",                         ["mobile_pt", "thick_client_pt", "api_vapt"]),
    ("hard-coded",                        ["mobile_pt", "thick_client_pt", "api_vapt"]),
    ("dll hijack",                        ["thick_client_pt"]),
    ("binary",                            ["thick_client_pt", "mobile_pt"]),
    ("root detection",                    ["mobile_pt"]),
    ("jailbreak",                         ["mobile_pt"]),
    ("certificate pinning",               ["mobile_pt"]),
    ("ssl pinning",                       ["mobile_pt"]),
    ("intent",                            ["mobile_pt"]),  # Android
    ("ios",                               ["mobile_pt"]),
    ("android",                           ["mobile_pt"]),
    ("apk",                               ["mobile_pt"]),
    ("plist",                             ["mobile_pt"]),

    # ---- Wi-Fi PT ----
    ("wpa2",                              ["wifi_pt"]),
    ("wpa3",                              ["wifi_pt"]),
    ("wep",                               ["wifi_pt"]),
    ("pmkid",                             ["wifi_pt"]),
    ("rogue ap",                          ["wifi_pt"]),
    ("evil twin",                         ["wifi_pt"]),
    ("kr00k",                             ["wifi_pt"]),
    ("krack",                             ["wifi_pt"]),
    ("wps",                               ["wifi_pt"]),
    ("ssid",                              ["wifi_pt"]),
    ("eap",                               ["wifi_pt"]),
    ("radius",                            ["wifi_pt", "infra_vapt"]),
    ("deauth",                            ["wifi_pt"]),
    ("802.11",                            ["wifi_pt"]),
    ("wireless",                          ["wifi_pt"]),

    # ---- Kiosk PT ----
    ("kiosk",                             ["kiosk_pt"]),
    ("keyboard shortcut",                 ["kiosk_pt"]),
    ("ctrl+alt",                          ["kiosk_pt"]),
    ("task manager",                      ["kiosk_pt", "thick_client_pt"]),
    ("breakout",                          ["kiosk_pt"]),
    ("usb boot",                          ["kiosk_pt"]),
    ("autorun",                           ["kiosk_pt"]),
    ("autoplay",                          ["kiosk_pt"]),
    ("sticky keys",                       ["kiosk_pt", "infra_vapt"]),
    ("file:// uri",                       ["kiosk_pt"]),

    # ---- OT VAPT ----
    ("modbus",                            ["ot_vapt"]),
    ("dnp3",                              ["ot_vapt"]),
    ("scada",                             ["ot_vapt"]),
    ("plc",                               ["ot_vapt"]),
    ("hmi",                               ["ot_vapt"]),
    ("ics",                               ["ot_vapt"]),
    ("iec 61850",                         ["ot_vapt"]),
    ("iec61850",                          ["ot_vapt"]),
    ("opc",                               ["ot_vapt"]),
    ("bacnet",                            ["ot_vapt"]),
    ("profinet",                          ["ot_vapt"]),
    ("rtu",                               ["ot_vapt"]),

    # ---- AWS Cloud VAPT ----
    ("aws ",                              ["aws_cloud_vapt"]),
    ("amazon s3",                         ["aws_cloud_vapt"]),
    ("s3 bucket",                         ["aws_cloud_vapt"]),
    ("iam role",                          ["aws_cloud_vapt"]),
    ("iam policy",                        ["aws_cloud_vapt", "azure_cloud_vapt"]),
    ("instance metadata",                 ["aws_cloud_vapt"]),
    ("imds",                              ["aws_cloud_vapt"]),
    ("ec2",                               ["aws_cloud_vapt"]),
    ("lambda",                            ["aws_cloud_vapt"]),
    ("cloudtrail",                        ["aws_cloud_vapt"]),
    ("guardduty",                         ["aws_cloud_vapt"]),
    ("rds",                               ["aws_cloud_vapt"]),
    ("kms",                               ["aws_cloud_vapt", "azure_cloud_vapt"]),

    # ---- Azure Cloud VAPT ----
    ("azure",                             ["azure_cloud_vapt"]),
    ("entra id",                          ["azure_cloud_vapt"]),
    ("aad",                               ["azure_cloud_vapt"]),
    ("conditional access",                ["azure_cloud_vapt"]),
    ("storage account",                   ["azure_cloud_vapt"]),
    ("blob container",                    ["azure_cloud_vapt"]),
    ("key vault",                         ["azure_cloud_vapt"]),
    ("managed identity",                  ["azure_cloud_vapt"]),
    ("nsg",                               ["azure_cloud_vapt"]),
    ("app service",                       ["azure_cloud_vapt"]),
    ("function app",                      ["azure_cloud_vapt"]),
    ("sentinel",                          ["azure_cloud_vapt"]),
    ("intune",                            ["azure_cloud_vapt"]),

    # ---- Source Code Review ----
    ("source code",                       ["source_code_review"]),
    ("static analysis",                   ["source_code_review"]),
    ("sast",                              ["source_code_review"]),
    ("secret in source",                  ["source_code_review"]),
    ("secret in repo",                    ["source_code_review"]),
    ("hardcoded secret",                  ["source_code_review", "mobile_pt", "thick_client_pt"]),
    ("hardcoded password",                ["source_code_review", "mobile_pt", "thick_client_pt"]),
    ("eval(",                             ["source_code_review", "web_vapt"]),
    ("md5",                               ["source_code_review", "infra_vapt"]),
    ("sha1",                              ["source_code_review", "infra_vapt"]),
    ("predictable random",                ["source_code_review", "web_vapt", "api_vapt"]),
    ("math.random",                       ["source_code_review", "web_vapt"]),
    ("insecure deserialization",          ["source_code_review", "web_vapt", "api_vapt"]),
    ("dead code",                         ["source_code_review"]),
]


def _classify_finding(text: str) -> set[str]:
    """Return the set of template codes whose keyword list matches `text`."""
    t = (text or "").lower()
    codes: set[str] = set()
    for phrase, applicable in _CLASSIFICATION_RULES:
        if phrase in t:
            codes.update(applicable)
    return codes


@router.post("/seed-defaults")
def seed_defaults(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.senior)),
):
    """Insert the comprehensive seed catalogue (see seed_findings_v2.py)
    covering every VAPT category. Idempotent — re-running only adds new
    titles and refreshes template:* tags on existing rows.
    """
    from ..seed_findings_v2 import seed_default_findings
    return seed_default_findings(db)


@router.post("/sanitise-placeholders")
def sanitise_placeholders(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.senior)),
    dry_run: bool = False,
):
    """Walk every `FindingLibrary` row, strip authoring-prompt
    placeholders (`[DELETE IF IRRELEVANT]`, `[DESCRIBE HOW THIS WAS
    PERFORMED]`, empty `Request` / `Response` code blocks, etc.) from
    the description / impact / remediation / references fields, and
    persist the cleaned values.

    The product direction is: a consultant should never need to
    rewrite the library text — they only fill `affected_asset`,
    `poc_steps`, and confirm the CVSS for their engagement. This
    endpoint is the one-shot to migrate the legacy XML knowledge
    base to that contract.

    `?dry_run=true` reports what WOULD change without persisting.
    """
    from ..services.library_sanitiser import run_sanitiser
    summary = run_sanitiser(db, dry_run=dry_run)
    try:
        from ..models import AuditLog
        db.add(AuditLog(
            actor_id=user.id,
            action="library.sanitise" if not dry_run else "library.sanitise.dry_run",
            object_type="finding_library", object_id=None,
            detail={"rows_modified": summary.rows_modified,
                    "total_hits": summary.total_hits,
                    "per_field": summary.per_field},
        ))
        db.commit()
    except Exception:                                       # pragma: no cover
        db.rollback()
    return {"ok": True, "dry_run": dry_run, **summary.to_dict()}


@router.post("/classify-all")
def classify_all(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.senior)),
    dry_run: bool = False,
):
    """Heuristically tag every library finding with the report templates it
    applies to. The finding's own `template_id` (its 'primary' template) is
    always considered applicable; additional templates are inferred from
    keywords in the title + description and stored as `template:<code>` tags
    inside the existing `tags` JSON column.

    Idempotent. Returns a per-finding diff so the caller can show what changed.

    Pass `?dry_run=true` to preview without writing.
    """
    rows = db.query(FindingLibrary).all()
    # template_id -> code
    templates = {t.id: t.code for t in db.query(ReportTemplate).all()}

    changes: list[dict] = []
    for f in rows:
        existing_tags = list(f.tags or [])
        # Strip any prior template: tags so re-running gives a clean state.
        non_tpl = [t for t in existing_tags if not (isinstance(t, str) and t.startswith("template:"))]
        codes = _classify_finding((f.title or "") + " " + (f.description or "") + " " +
                                  (f.impact or "") + " " + (f.remediation or ""))
        primary = templates.get(f.template_id)
        if primary:
            codes.add(primary)
        new_tags = non_tpl + sorted(f"template:{c}" for c in codes)
        if set(existing_tags) != set(new_tags):
            changes.append({
                "id": f.id,
                "title": f.title,
                "added": sorted(set(new_tags) - set(existing_tags)),
                "removed": sorted(set(existing_tags) - set(new_tags)),
            })
            if not dry_run:
                f.tags = new_tags
    if not dry_run:
        db.commit()
    return {
        "dry_run": dry_run,
        "total_findings": len(rows),
        "changed": len(changes),
        "changes": changes[:200],   # cap the response size
        "applied_by": user.username if not dry_run else None,
    }
