"""Full VibeDocs export / import — for the monthly Kali VM image swap.

A consultant runs VibeDocs inside a Kali VM image that is refreshed every month. To
carry their work across to the new image they EXPORT a single bundle (all
projects, reports, trackers, findings, library + every screenshot / evidence /
generated file) and IMPORT it into the fresh image — with no missing assets.

Bundle layout (a single ZIP):
    manifest.json          schema + app version, timestamp, table list
    data.json              {table_name: [row, ...]} for every exported table,
                           ordered by FK dependency (Base.metadata.sorted_tables)
    files/uploads/<rel>    every file under settings.UPLOAD_DIR
    files/reports/<rel>    every file under settings.REPORT_DIR

Design choices
--------------
* Generic over `Base.metadata.sorted_tables` so new tables are picked up without
  touching this module. A small denylist excludes transient / security tables
  (rate-limit hits, reset tokens, SSO secrets).
* IMPORT is a clean "wipe-and-restore": rows are deleted in reverse-FK order,
  then re-inserted with their ORIGINAL primary keys (so foreign keys stay
  valid), and Postgres identity sequences are bumped past the restored maxima.
  This matches the VM-swap use case (a fresh image whose DB only has seed data).
* Fernet-encrypted report passwords (`Project.details["report_passwords"]`) are
  derived from this server's SECRET_KEY and CANNOT decrypt on a new image, so
  they are dropped on import — the consultant re-enters any needed passwords.

Values are JSON-encoded with type markers so datetimes / bytes / enums survive
a round-trip losslessly.
"""
from __future__ import annotations

import base64
import datetime as _dt
import enum as _enum
import io
import json
import zipfile
from pathlib import Path

SCHEMA_VERSION = 1

# Tables we never export/import: transient throttling, single-use security
# tokens, and SSO provider secrets (host-specific). Everything else — projects,
# reports, versions, findings, library, templates, users, notes — travels.
_DENYLIST = {
    "rate_limit_hits",
    "password_reset_tokens",
    "account_unlock_tokens",
    "totp_backup_codes",
    "auth_provider_configs",
}


# ----------------------------------------------------------------------------
# JSON-safe (de)serialisation with type markers
# ----------------------------------------------------------------------------
def _enc_value(v):
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, _enum.Enum):
        # SQLAlchemy persists a Python Enum by its NAME (e.g. "high"), so we
        # store the NAME — re-inserting it on import then matches the column.
        return {"__enum__": v.name}
    if isinstance(v, (_dt.datetime, _dt.date)):
        return {"__dt__": v.isoformat()}
    if isinstance(v, _dt.time):
        return {"__time__": v.isoformat()}
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"__b64__": base64.b64encode(bytes(v)).decode("ascii")}
    if isinstance(v, (list, dict)):               # JSON columns
        return v
    return str(v)


def _dec_value(v):
    if isinstance(v, dict):
        if "__dt__" in v:
            return _dt.datetime.fromisoformat(v["__dt__"])
        if "__time__" in v:
            return _dt.time.fromisoformat(v["__time__"])
        if "__b64__" in v:
            return base64.b64decode(v["__b64__"])
    return v


def _enc_row(row: dict) -> dict:
    return {k: _enc_value(v) for k, v in row.items()}


def _dec_row(row: dict) -> dict:
    return {k: _dec_value(v) for k, v in row.items()}


def _by_value(eclass, val):
    """Look up an enum member by its .value (fallback when a plain string was
    stored instead of an {'__enum__': name} marker)."""
    for member in eclass:
        if member.value == val:
            return member
    return None


# ----------------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------------
def export_bundle(db, *, now_iso: str) -> bytes:
    """Serialise the whole VibeDocs dataset + asset files into a ZIP, returned as
    bytes. `now_iso` is passed in (callers stamp the time) so this stays pure.
    """
    from ..database import Base
    from ..config import settings

    tables = [t for t in Base.metadata.sorted_tables if t.name not in _DENYLIST]
    data: dict[str, list] = {}
    for table in tables:
        rows = [dict(m) for m in db.execute(table.select()).mappings()]
        data[table.name] = [_enc_row(r) for r in rows]

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "app": "VibeDocs",
        "exported_at": now_iso,
        "tables": [t.name for t in tables],
        "row_counts": {name: len(rows) for name, rows in data.items()},
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("data.json", json.dumps(data))
        _add_tree(zf, Path(settings.UPLOAD_DIR), "files/uploads")
        _add_tree(zf, Path(settings.REPORT_DIR), "files/reports")
    return buf.getvalue()


def _add_tree(zf: zipfile.ZipFile, root: Path, arc_prefix: str) -> None:
    if not root.exists():
        return
    for p in root.rglob("*"):
        if p.is_file() and not p.name.startswith("~$"):
            try:
                arc = f"{arc_prefix}/{p.relative_to(root).as_posix()}"
                zf.write(p, arc)
            except Exception:
                continue


# ----------------------------------------------------------------------------
# Import (wipe-and-restore)
# ----------------------------------------------------------------------------
def import_bundle(db, zip_bytes: bytes) -> dict:
    """Restore a bundle produced by `export_bundle` into THIS instance.

    Returns a summary dict. Raises ValueError on an unreadable / incompatible
    bundle BEFORE any destructive change is made.
    """
    from ..database import Base
    from ..config import settings

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception as e:
        raise ValueError(f"Not a valid bundle ZIP: {e}")

    names = set(zf.namelist())
    if "data.json" not in names or "manifest.json" not in names:
        raise ValueError("Bundle is missing manifest.json / data.json.")

    manifest = json.loads(zf.read("manifest.json"))
    if int(manifest.get("schema_version", 0)) > SCHEMA_VERSION:
        raise ValueError(
            f"Bundle schema v{manifest.get('schema_version')} is newer than this "
            f"VibeDocs supports (v{SCHEMA_VERSION}). Update VibeDocs first."
        )
    data = json.loads(zf.read("data.json"))

    tables = [t for t in Base.metadata.sorted_tables
              if t.name not in _DENYLIST and t.name in data]
    bind = db.get_bind()
    dialect = bind.dialect.name

    # 1. Wipe existing rows (children first) — only the tables we restore.
    for table in reversed(tables):
        db.execute(table.delete())

    # 2. Insert restored rows (parents first), original PKs preserved.
    from sqlalchemy import Enum as _SAEnum
    restored: dict[str, int] = {}
    for table in tables:
        # Map enum columns -> their Python enum class so we can turn the stored
        # NAME back into the actual member SQLAlchemy expects on insert.
        enum_cols: dict[str, type] = {}
        for col in table.columns:
            if isinstance(col.type, _SAEnum) and getattr(col.type, "enum_class", None):
                enum_cols[col.name] = col.type.enum_class
        rows = []
        for raw in data.get(table.name, []):
            row = _dec_row(raw)
            for cname, eclass in enum_cols.items():
                val = row.get(cname)
                if isinstance(val, dict) and "__enum__" in val:
                    try:
                        row[cname] = eclass[val["__enum__"]]
                    except KeyError:
                        row[cname] = None
                elif isinstance(val, str):
                    # tolerate a plain name/value string
                    row[cname] = eclass.__members__.get(val) or _by_value(eclass, val)
            row = _sanitise_row(table.name, row)
            if row:
                rows.append(row)
        if rows:
            db.execute(table.insert(), rows)
        restored[table.name] = len(rows)

    # 3. Bump Postgres identity sequences past the restored maxima.
    if dialect == "postgresql":
        for table in tables:
            _reset_pg_sequence(db, table)

    db.commit()

    # 4. Restore asset files (overwrite — the fresh image only has seed assets).
    files_restored = _extract_tree(zf, "files/uploads", Path(settings.UPLOAD_DIR))
    files_restored += _extract_tree(zf, "files/reports", Path(settings.REPORT_DIR))

    return {
        "tables_restored": restored,
        "rows_restored": sum(restored.values()),
        "files_restored": files_restored,
        "exported_at": manifest.get("exported_at"),
    }


def _sanitise_row(table_name: str, row: dict) -> dict:
    """Strip non-portable / host-specific secrets from a row before insert."""
    if table_name == "projects":
        details = row.get("details")
        if isinstance(details, dict) and "report_passwords" in details:
            # Fernet ciphertext is bound to the OLD image's SECRET_KEY — drop it
            # so import never carries undecryptable blobs. Consultant re-enters.
            details = dict(details)
            details.pop("report_passwords", None)
            row["details"] = details
    return row


def _reset_pg_sequence(db, table) -> None:
    from sqlalchemy import text
    pk_cols = [c for c in table.primary_key.columns]
    if len(pk_cols) != 1:
        return
    col = pk_cols[0]
    if not (col.type.python_type is int):
        return
    try:
        db.execute(text(
            f"SELECT setval(pg_get_serial_sequence(:t, :c), "
            f"COALESCE((SELECT MAX({col.name}) FROM {table.name}), 1), true)"
        ), {"t": table.name, "c": col.name})
    except Exception:
        # Table may have no sequence (non-identity PK) — harmless.
        pass


def _extract_tree(zf: zipfile.ZipFile, arc_prefix: str, dest_root: Path) -> int:
    count = 0
    prefix = arc_prefix.rstrip("/") + "/"
    for name in zf.namelist():
        if not name.startswith(prefix) or name.endswith("/"):
            continue
        rel = name[len(prefix):]
        if not rel or ".." in rel.split("/"):
            continue
        target = dest_root / rel
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(name) as src, target.open("wb") as out:
                out.write(src.read())
            count += 1
        except Exception:
            continue
    return count
