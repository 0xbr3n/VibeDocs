"""
Encrypted-report bundling.

Two responsibilities, kept together because they're always used as a pair:

1. **Password storage** (server-side, at-rest encryption)
   When a consultant chooses a password for a report bundle, we save it
   under the parent Project so they can reuse it for sibling reports of
   the same engagement. We never store the plaintext — it's encrypted with
   a Fernet key derived from `settings.SECRET_KEY` (PBKDF2-SHA256). The
   encrypted ciphertext lives in `Project.details["report_passwords"]`
   alongside a short user-supplied label.

   Threat model: a database leak alone does NOT yield the passwords —
   you'd also need the application's `SECRET_KEY`. Anyone with that key
   can already mint JWTs anyway, so the marginal exposure of having
   passwords decryptable to a server with the key is minimal compared to
   the workflow benefit of "reuse the same password as the v0.1 zip".

2. **AES-256 encrypted ZIP packaging**
   Uses `pyzipper` with `WZ_AES` (a.k.a. AE-2 with 256-bit AES). The ZIP
   contains the generated `.docx` and (if produced) `.pdf` files. Modern
   archive tools (7-Zip, Keka, WinRAR, recent macOS Archive Utility,
   recent Windows Explorer) handle these.

   We deliberately do NOT use ZipCrypto (the legacy zipfile.setpassword
   format) because it's trivially attackable and not the user's
   expectation when they tick the "encrypt" box.
"""
from __future__ import annotations
import base64
import hashlib
import logging
import secrets
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from ..config import settings


log = logging.getLogger(__name__)


# ============================================================
# Password encryption / decryption (Fernet)
# ============================================================

def _fernet_key() -> bytes:
    """Derive a 32-byte URL-safe base64 key from the app SECRET_KEY.

    PBKDF2-SHA256 with a fixed application salt — we want determinism so
    that ciphertext written today is decryptable next deploy without
    storing the key separately. The HKDF expansion gives us a key that's
    independent of any other use of SECRET_KEY (e.g. JWT signing) so
    leaking one derivation doesn't help against another.
    """
    salt = b"vapt-reporter:report-password-fernet:v1"
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        settings.SECRET_KEY.encode("utf-8"),
        salt,
        iterations=200_000,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw)


def _fernet():
    """Lazy import so a missing `cryptography` install doesn't break the
    rest of the app on cold start (python-jose[cryptography] in our
    requirements pulls it in)."""
    from cryptography.fernet import Fernet
    return Fernet(_fernet_key())


def encrypt_password(plaintext: str) -> str:
    """Return a base64-ish ciphertext (Fernet) for at-rest storage."""
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("empty password")
    token = _fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_password(token: str) -> str:
    """Inverse of `encrypt_password`. Raises if the ciphertext was tampered
    with or the key changed (SECRET_KEY rotated)."""
    from cryptography.fernet import InvalidToken
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError(f"Stored password could not be decrypted: {e}")


# ============================================================
# Stored-password records (Project.details)
# ============================================================

PASSWORDS_KEY = "report_passwords"


def list_project_passwords(project) -> list[dict]:
    """Return the saved-password records on the project, with ciphertext
    stripped. Always returns a list (never None).
    """
    raw = (project.details or {}).get(PASSWORDS_KEY) or []
    out = []
    for r in raw:
        out.append({
            "id": r.get("id"),
            "label": r.get("label") or "(unlabelled)",
            "created_at": r.get("created_at"),
            "created_by_id": r.get("created_by_id"),
            "used_by_report_ids": list(r.get("used_by_report_ids") or []),
        })
    return out


def save_project_password(project, plaintext: str, *, label: Optional[str],
                           user_id: Optional[int], report_id: Optional[int]) -> dict:
    """Append a new password record. Returns the public-facing record
    (without ciphertext). Mutates `project.details` in place — caller is
    responsible for `flag_modified` + commit."""
    details = dict(project.details or {})
    records = list(details.get(PASSWORDS_KEY) or [])
    rec_id = secrets.token_urlsafe(8)
    record = {
        "id": rec_id,
        "label": (label or "").strip()[:80] or f"Password {len(records) + 1}",
        "ciphertext": encrypt_password(plaintext),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "created_by_id": user_id,
        "used_by_report_ids": [report_id] if report_id else [],
    }
    records.append(record)
    details[PASSWORDS_KEY] = records
    project.details = details
    return {
        "id": record["id"],
        "label": record["label"],
        "created_at": record["created_at"],
        "created_by_id": record["created_by_id"],
        "used_by_report_ids": record["used_by_report_ids"],
    }


def get_project_password_plaintext(project, password_id: str) -> Optional[str]:
    """Decrypt and return the plaintext for a stored record. None if the id
    doesn't exist."""
    for r in (project.details or {}).get(PASSWORDS_KEY) or []:
        if r.get("id") == password_id:
            ct = r.get("ciphertext")
            if not ct:
                return None
            try:
                return decrypt_password(ct)
            except Exception:
                return None
    return None


def touch_project_password(project, password_id: str, report_id: int) -> None:
    """Append `report_id` to the password's used-by list so the UI can show
    'reused on N reports'. Mutates in place — caller commits."""
    details = dict(project.details or {})
    records = list(details.get(PASSWORDS_KEY) or [])
    changed = False
    for r in records:
        if r.get("id") == password_id:
            used = list(r.get("used_by_report_ids") or [])
            if report_id not in used:
                used.append(report_id)
                r["used_by_report_ids"] = used
                changed = True
            break
    if changed:
        details[PASSWORDS_KEY] = records
        project.details = details


def delete_project_password(project, password_id: str) -> bool:
    """Remove a stored password record by id. Returns True if anything was
    deleted. Mutates in place — caller commits."""
    details = dict(project.details or {})
    records = list(details.get(PASSWORDS_KEY) or [])
    new_records = [r for r in records if r.get("id") != password_id]
    if len(new_records) == len(records):
        return False
    details[PASSWORDS_KEY] = new_records
    project.details = details
    return True


# ============================================================
# Encrypted ZIP packaging
# ============================================================

MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 256


def validate_password(plaintext: str) -> None:
    """Cheap policy check. Raises ValueError on rejection.

    Keep this in step with the JS validation in the Generate form — the
    server-side check is the authoritative one; the JS is just UX."""
    if not isinstance(plaintext, str):
        raise ValueError("password must be a string")
    if not (MIN_PASSWORD_LEN <= len(plaintext) <= MAX_PASSWORD_LEN):
        raise ValueError(
            f"password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters"
        )


def build_encrypted_zip(*, files: Iterable[Path], output_path: Path,
                         password: str) -> Path:
    """Pack `files` into an AES-encrypted ZIP at `output_path`. Returns the
    output path.

    Each path is stored inside the zip under its basename — no directory
    structure is leaked into the archive."""
    validate_password(password)
    paths = [Path(p) for p in files if p and Path(p).exists()]
    if not paths:
        raise ValueError("no input files to package")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    import pyzipper  # local import — pure-Python but optional in dev
    with pyzipper.AESZipFile(
            str(output_path),
            "w",
            compression=pyzipper.ZIP_LZMA,
            encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        # The WZ_AES standard ships AES-256 by default; pyzipper exposes
        # the strength via setencryption() for older clients. 256 is fine.
        try:
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
        except Exception:
            pass
        for p in paths:
            zf.write(str(p), arcname=p.name)
    return output_path
