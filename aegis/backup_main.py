"""Write a consistent backup of the incident database: python -m aegis.backup_main [DEST]."""

import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from aegis.settings import Settings
from aegis.storage import backup_database


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        print("usage: python -m aegis.backup_main [DEST]", file=sys.stderr)
        return 2
    source = Settings().db_path
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    dest = argv[0] if argv else str(Path(source).parent / "backups" / f"aegis-{stamp}.db")
    try:
        print(backup_database(source, dest))
    except (OSError, sqlite3.Error) as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
