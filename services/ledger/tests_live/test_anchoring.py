"""Anchoring live (ADR-0004): the full-rewrite attack, defeated.

The headline test rewrites a tenant's ENTIRE chain (internally consistent,
passes /verify) — and shows the externally held anchor still catches it.
Also proves MinIO delivery: the anchor lands in the (dev stand-in for a)
customer-controlled bucket.

Env: TRUVO_TEST_DATABASE_URL; MinIO delivery additionally uses the dev
stack's MinIO on localhost:9000.
"""

import json
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
    ledger.use_store(_pg_store)


@pytest.fixture()
def tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, 'live')",
            (tid, "anc-%s" % tid[:8]),
        )
    yield tid, admin
    with admin.cursor() as cur:
        cur.execute("DELETE FROM anchors WHERE tenant_id = %s", (tid,))
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id = %s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (tid,))
    admin.close()


def _append(tid, n=0, actor="scoring-svc"):
    r = client.post(
        "/v1/entries",
        json={"tenant": tid, "actor": actor, "kind": "score.emitted",
              "payload": {"n": n}},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _anchor_params(a):
    return {
        "anchor_as_of": a["as_of_iso"], "anchor_seq": a["last_seq"],
        "anchor_hash": a["head_hash"], "anchor_sig": a["signature"],
    }


def test_anchor_create_and_verify_extension(tenant):
    tid, _ = tenant
    for i in range(3):
        _append(tid, n=i)
    a = client.post("/v1/%s/anchor" % tid).json()
    assert a["last_seq"] == 2

    # chain later grows; anchor still verifies (extension, not equality)
    _append(tid, n=3)
    v = client.get("/v1/%s/verify" % tid, params=_anchor_params(a)).json()
    assert v["chain_valid"] and v["anchor_ok"]


def test_empty_chain_cannot_anchor(tenant):
    tid, _ = tenant
    assert client.post("/v1/%s/anchor" % tid).status_code == 409


def test_full_rewrite_defeated_by_anchor(tenant):
    """The attack ADR-0004 exists for: attacker with DB access deletes the
    chain and forges a fresh, internally consistent one."""
    tid, admin = tenant
    for i in range(3):
        _append(tid, n=i)
    a = client.post("/v1/%s/anchor" % tid).json()

    # attacker: wipe and rebuild a consistent chain (as superuser)
    with admin.cursor() as cur:
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id = %s", (tid,))
    for i in range(4):
        _append(tid, n=100 + i, actor="attacker")

    # plain verify is fooled — the forged chain is internally consistent
    v = client.get("/v1/%s/verify" % tid).json()
    assert v["chain_valid"] and v["replay_ok"]

    # the externally held anchor is not
    r = client.get("/v1/%s/verify" % tid, params=_anchor_params(a))
    assert r.status_code == 500
    assert "ANCHOR MISMATCH" in r.json()["detail"]


def test_anchor_delivered_to_minio(tenant, monkeypatch):
    tid, _ = tenant
    monkeypatch.setenv("TRUVO_ANCHOR_S3_ENDPOINT", "localhost:9000")
    monkeypatch.setenv("TRUVO_ANCHOR_S3_ACCESS_KEY", "truvo")
    monkeypatch.setenv("TRUVO_ANCHOR_S3_SECRET_KEY", "truvo-dev-only")
    _append(tid, n=0)
    a = client.post("/v1/%s/anchor" % tid).json()

    from minio import Minio

    m = Minio("localhost:9000", access_key="truvo",
              secret_key="truvo-dev-only", secure=False)
    name = "%s/%s.json" % (tid, a["as_of_iso"].replace(":", "-"))
    obj = m.get_object("truvo-anchors", name)
    stored = json.loads(obj.read())
    obj.close()
    assert stored["head_hash"] == a["head_hash"]
    assert stored["signature"] == a["signature"]
