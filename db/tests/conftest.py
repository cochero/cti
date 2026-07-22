import os
import uuid

import pytest

TEST_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")

if TEST_URL:
    import psycopg2  # noqa: F401  (import only when a database is configured)

pytestmark = pytest.mark.skipif(
    not TEST_URL,
    reason="TRUVO_TEST_DATABASE_URL not set (CI always sets it; see db/README.md)",
)


def _require_db():
    if not TEST_URL:
        pytest.skip("TRUVO_TEST_DATABASE_URL not set")


def _app_url():
    """Derive the truvo_app connection URL from the admin URL."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(TEST_URL)
    netloc = "truvo_app:truvo-app-dev-only@%s" % parts.hostname
    if parts.port:
        netloc += ":%d" % parts.port
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


@pytest.fixture(scope="session")
def admin_conn():
    _require_db()
    import psycopg2

    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from migrate import migrate

    migrate(TEST_URL)
    conn = psycopg2.connect(TEST_URL)
    conn.autocommit = True
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def app_conn():
    _require_db()
    import psycopg2

    conn = psycopg2.connect(_app_url())
    conn.autocommit = True
    yield conn
    conn.close()


@pytest.fixture()
def two_tenants(admin_conn):
    """Provision two throwaway tenants; remove them (and their rows) after."""
    ids = []
    with admin_conn.cursor() as cur:
        for _ in range(2):
            slug = "t-%s" % uuid.uuid4().hex[:12]
            cur.execute(
                "INSERT INTO tenants (slug, name) VALUES (%s, %s) RETURNING tenant_id",
                (slug, slug),
            )
            ids.append(cur.fetchone()[0])
    yield ids
    with admin_conn.cursor() as cur:
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id = ANY(%s::uuid[])", (ids,))
        cur.execute("DELETE FROM tenants WHERE tenant_id = ANY(%s::uuid[])", (ids,))


def set_tenant(conn, tenant_id):
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('truvo.tenant_id', %s, false)", (str(tenant_id),))


def clear_tenant(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('truvo.tenant_id', '', false)")


def insert_entry(conn, tenant_id, seq):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ledger_entries
                (tenant_id, seq, ts_iso, actor, kind, payload, prev_hash, entry_hash)
            VALUES (%s, %s, '2026-07-22T00:00:00Z', 'test', 'test.event', '{}',
                    repeat('0', 64), repeat('a', 64))
            """,
            (str(tenant_id), seq),
        )
