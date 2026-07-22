"""ledger-svc on real Postgres (run with: pytest tests_live).

Proves on live storage what the unit tier proves in memory — plus the two
things memory cannot prove:
1. RLS fences the service's own connections (app role, per-tx context).
2. Tamper-evidence survives storage: an admin-level UPDATE to history is
   caught by /verify as CHAIN INVALID.

Env: TRUVO_TEST_DATABASE_URL (admin). The service under test connects as
truvo_app via TRUVO_LEDGER_DB_URL set here before app import.
"""

import os
import uuid

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
APP_URL = "postgresql://truvo_app:truvo-app-dev-only@localhost:5432/truvo"

pytestmark = pytest.mark.skipif(
    not ADMIN_URL, reason="TRUVO_TEST_DATABASE_URL not set"
)

if ADMIN_URL:
    import psycopg2
    from fastapi.testclient import TestClient

    import app.main as ledger
    from app.store import PostgresStore

    _pg_store = PostgresStore(APP_URL)
    client = TestClient(ledger.app)


@pytest.fixture(autouse=True)
def _postgres_store():
    # per-test, not import-time: unit tests in the same process swap the
    # store to MemoryStore in their own setup; each tier claims it explicitly
    ledger.use_store(_pg_store)


@pytest.fixture()
def tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, 'live')",
            (tid, "lgr-%s" % tid[:8]),
        )
    yield tid, admin
    with admin.cursor() as cur:
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id = %s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (tid,))
    admin.close()


def _append(tid, kind="score.emitted", n=0):
    r = client.post(
        "/v1/entries",
        json={
            "tenant": tid, "actor": "scoring-svc", "kind": kind,
            "payload": {"threat": "TA-%d" % n, "score_millis": 80000 + n},
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_store_is_postgres():
    assert client.get("/healthz").json()["store"] == "PostgresStore"


def test_append_persists_and_verifies(tenant):
    tid, admin = tenant
    for i in range(3):
        entry = _append(tid, n=i)
        assert entry["seq"] == i

    v = client.get("/v1/%s/verify" % tid).json()
    assert v == {"tenant": tid, "entries": 3, "chain_valid": True, "replay_ok": True}

    # rows really are in Postgres (admin view), chained correctly
    with admin.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM ledger_entries WHERE tenant_id = %s", (tid,)
        )
        assert cur.fetchone()[0] == 3


def test_chain_continues_across_requests(tenant):
    tid, _ = tenant
    first = _append(tid, n=0)
    second = _append(tid, n=1)
    assert second["prev_hash"] == first["entry_hash"]


def test_admin_tamper_is_detected_by_verify(tenant):
    """History rewritten under the service (superuser UPDATE) -> sev-1."""
    tid, admin = tenant
    for i in range(3):
        _append(tid, n=i)
    with admin.cursor() as cur:
        cur.execute(
            "UPDATE ledger_entries SET payload = '{\"score_millis\": 1}'"
            " WHERE tenant_id = %s AND seq = 1",
            (tid,),
        )
    r = client.get("/v1/%s/verify" % tid)
    assert r.status_code == 500
    assert "CHAIN INVALID" in r.json()["detail"]


def test_rls_isolates_service_connections(tenant):
    """The service, as truvo_app, cannot see another tenant's chain even
    though it queries the same table."""
    tid, admin = tenant
    _append(tid, n=0)
    other = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, 'live')",
            (other, "lgr-%s" % other[:8]),
        )
    try:
        assert client.get("/v1/%s/entries" % other).json() == []
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (other,))
