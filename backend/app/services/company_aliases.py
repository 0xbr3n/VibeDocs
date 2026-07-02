"""Company alias list — persistent JSON file.

The list is stored at /data/config/company_aliases.json inside the container.
On first read the file is seeded with a couple of generic example entity names
so a fresh deployment works without admin configuration.
"""
from __future__ import annotations
import json
import logging
from pathlib import Path

_ALIASES_FILE = Path("/data/config/company_aliases.json")

DEFAULT_ALIASES: list[str] = [
    "Your Security Company Pte Ltd",
    "Your Security Team",
]

_log = logging.getLogger(__name__)


def get_aliases() -> list[str]:
    """Return the current list of company aliases (seeding defaults if absent)."""
    if _ALIASES_FILE.exists():
        try:
            data = json.loads(_ALIASES_FILE.read_text("utf-8"))
            if isinstance(data, list):
                cleaned = [str(a).strip() for a in data if str(a).strip()]
                if cleaned:
                    return cleaned
        except Exception as exc:
            _log.warning("Failed to load company aliases from %s: %s", _ALIASES_FILE, exc)
    # File absent or empty — seed defaults and persist
    return set_aliases(DEFAULT_ALIASES)


def set_aliases(aliases: list[str]) -> list[str]:
    """Replace the alias list and persist to disk. Returns the saved list."""
    cleaned = [str(a).strip() for a in aliases if str(a).strip()]
    try:
        _ALIASES_FILE.parent.mkdir(parents=True, exist_ok=True)
        _ALIASES_FILE.write_text(
            json.dumps(cleaned, indent=2, ensure_ascii=False), "utf-8"
        )
    except Exception as exc:
        _log.error("Failed to persist company aliases: %s", exc)
    return cleaned
