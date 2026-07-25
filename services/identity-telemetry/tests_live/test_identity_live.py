"""identity-telemetry live: sync pipeline, snapshot semantics, blast radius, RLS.

Uses FakeProvider — the sync/storage/RLS/blast machinery is identical for
real providers; only fetch_identities() differs (see providers.py note).

Env: TRUVO_TEST_DATABASE_URL. Run with: pytest tests_live
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
    os.environ["TRUVO_IDENTITY_DB_URL"] = APP_URL
    import psycopg2
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)


FAKE_ORG = [
    {"principal_id": "u-ceo", "kind": "user", "display": "CEO",
     "privileged": False, "roles": []},
    {"principal_id": "u-ga", "kind": "user", "display": "IT Admin",
     "privileged": True, "roles": ["Global Administrator"]},
    {"principal_id": "u-sec", "kind": "user", "display": "SecOps",
     "privileged": True, "roles": ["Security Administrator"]},
    {"principal_id": "s-backup", "kind": "service", "display": "Backup svc",
     "privileged": True, "roles": ["Global Administrator"]},
    {"principal_id": "u-dev1", "kind": "user", "display": "Dev",
     "privileged": False, "roles": []},
]


@pytest.fixture()
def tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, 'live')",
            (tid, "idt-%s" % tid[:8]),
        )
    yield tid, admin
    with admin.cursor() as cur:
        cur.execute("DELETE FROM identities WHERE tenant_id = %s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (tid,))
    admin.close()


def _sync(tid, identities):
    r = client.post(
        "/v1/%s/sync" % tid,
        json={"provider": "fake", "fake_identities": identities},
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_sync_and_blast_radius(tenant):
    tid, _ = tenant
    assert _sync(tid, FAKE_ORG)["synced"] == 5

    b = client.get("/v1/%s/blast-radius" % tid).json()
    assert b["total_principals"] == 5
    assert b["privileged_principals"] == 3
    assert b["privileged_ratio_millis"] == 600
    assert b["privileged_service_accounts"] == 1
    assert b["top_privileged_roles"][0] == {
        "role": "Global Administrator", "principals": 2,
    }


def test_resync_replaces_snapshot(tenant):
    """Departed admin disappears; privilege surface shrinks accordingly."""
    tid, _ = tenant
    _sync(tid, FAKE_ORG)
    smaller = [i for i in FAKE_ORG if i["principal_id"] != "u-ga"]
    assert _sync(tid, smaller)["synced"] == 4

    b = client.get("/v1/%s/blast-radius" % tid).json()
    assert b["total_principals"] == 4
    assert b["privileged_principals"] == 2


def test_unknown_tenant_rejected():
    r = client.post(
        "/v1/%s/sync" % uuid.uuid4(),
        json={"provider": "fake", "fake_identities": FAKE_ORG},
    )
    assert r.status_code == 404


def test_rls_isolates_snapshots(tenant):
    tid, admin = tenant
    _sync(tid, FAKE_ORG)
    other = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, 'live')",
            (other, "idt-%s" % other[:8]),
        )
    try:
        assert client.get("/v1/%s/blast-radius" % other).status_code == 404
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (other,))


def test_empty_snapshot_404(tenant):
    tid, _ = tenant
    assert client.get("/v1/%s/blast-radius" % tid).status_code == 404
