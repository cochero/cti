"""Minimal SQL migration runner.

Applies db/migrations/NNNN_*.sql in lexical order, once each, inside a
transaction, recording the file's SHA-256. A previously applied migration
whose content has changed fails loudly -- history is immutable here for
the same reason it is in the ledger.

Usage:
    python db/migrate.py <database-url>
    python db/migrate.py            # uses TRUVO_DATABASE_URL
"""

import hashlib
import os
import sys
from pathlib import Path

import psycopg2

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

DDL_STATE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   text PRIMARY KEY,
    sha256     char(64) NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)
"""


def migrate(dsn: str) -> int:
    applied = 0
    conn = psycopg2.connect(dsn)
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(DDL_STATE)
        conn.commit()

        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            sql = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT sha256 FROM schema_migrations WHERE filename = %s",
                    (path.name,),
                )
                row = cur.fetchone()
                if row is not None:
                    if row[0] != digest:
                        raise RuntimeError(
                            "%s was already applied with a different content hash; "
                            "migrations are immutable -- add a new file instead"
                            % path.name
                        )
                    continue
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations (filename, sha256) VALUES (%s, %s)",
                    (path.name, digest),
                )
            conn.commit()
            applied += 1
            print("applied %s" % path.name)
    finally:
        conn.close()
    return applied


def main() -> None:
    dsn = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRUVO_DATABASE_URL")
    if not dsn:
        print("usage: migrate.py <database-url>  (or set TRUVO_DATABASE_URL)")
        raise SystemExit(2)
    n = migrate(dsn)
    print("done: %d migration(s) applied" % n)


if __name__ == "__main__":
    main()
