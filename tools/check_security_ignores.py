"""Validate .github/security-ignores.yaml schema + flag expired entries.

Exit 0 if file is valid + nothing expired. Exit 1 on schema violation
or any expired entry. Used by both T10's security.yml workflow (as a
pre-step) and T11's weekly expiry-check cron.
"""

from __future__ import annotations

import datetime as _dt
import sys
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_IGNORES = _REPO_ROOT / ".github" / "security-ignores.yaml"
_REQUIRED_FIELDS = {"id", "reason", "expires", "reviewer"}


def main() -> int:
    if not _IGNORES.exists():
        print(f"ERROR: {_IGNORES} missing", file=sys.stderr)
        return 1

    data = yaml.safe_load(_IGNORES.read_text()) or {}
    entries = data.get("ignores") or []

    today = _dt.date.today()
    errors: list[str] = []
    expired: list[str] = []

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entry {i}: not a dict")
            continue
        missing = _REQUIRED_FIELDS - set(entry.keys())
        if missing:
            errors.append(f"entry {i} ({entry.get('id', '<no-id>')}): missing fields {missing}")
            continue
        try:
            expires_date = _dt.date.fromisoformat(str(entry["expires"]))
        except ValueError:
            errors.append(
                f"entry {i} ({entry['id']}): expires={entry['expires']!r} is not ISO date"
            )
            continue
        if expires_date < today:
            expired.append(
                f"  - {entry['id']}: expired {expires_date} (reviewer={entry['reviewer']})"
            )

    if errors:
        print("Schema errors in security-ignores.yaml:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    if expired:
        print(f"Expired security ignore entries (today={today}):", file=sys.stderr)
        for e in expired:
            print(e, file=sys.stderr)
        return 1

    print(f"OK: {len(entries)} ignore entries, all valid + unexpired (as of {today})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
