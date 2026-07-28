"""detect-svc live: IOC match with graph context, credential scan (§11.3), RLS.

Env: TRUVO_TEST_DATABASE_URL. Run: pytest tests_live
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
    os.environ["TRUVO_DETECT_DB_URL"] = APP_URL
    os.environ.pop("TRUVO_VAULT_ADDR", None)  # env salt for deterministic test
    os.environ["TRUVO_DEV_CRED_SALT"] = "test-salt"
    import psycopg2
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)


@pytest.fixture()
def tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    tag = uuid.uuid4().hex[:8]
    ioc = "evil-%s.com" % tag
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'d')",
                    (tid, "dt-%s" % tag))
        cur.execute("INSERT INTO tenant_watchlist (tenant_id, ioc_type, ioc_value)"
                    " VALUES (%s,'domain',%s)", (tid, ioc))
        cur.execute("INSERT INTO tenant_domains (tenant_id, domain) VALUES (%s,%s)",
                    (tid, "acme-%s.com" % tag))
        # graph context: a malware node exploits this IOC infrastructure
        cur.execute("INSERT INTO graph_edges (src_type,src_id,rel,dst_type,dst_id)"
                    " VALUES ('MALWARE',%s,'communicates_with','INFRASTRUCTURE',%s)",
                    ("Mal-%s" % tag, ioc))
    yield {"tid": tid, "tag": tag, "ioc": ioc, "domain": "acme-%s.com" % tag,
           "admin": admin}
    with admin.cursor() as cur:
        cur.execute("DELETE FROM credential_leaks WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenant_watchlist WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenant_domains WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM graph_edges WHERE dst_id=%s", (ioc,))
        cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (tid,))
    admin.close()


def test_ioc_match_with_graph_context(tenant):
    w = tenant
    r = client.post("/v1/ioc-match", json={
        "tenant": w["tid"],
        "iocs": [w["ioc"], "clean1.com", "clean2.com", "clean3.com"],
    }).json()
    assert r["matched"] == [w["ioc"]]
    assert r["prescreen_rejected"] >= 1  # the clean ones bloom-rejected
    ctx = r["graph_context"][w["ioc"]]
    assert any(c["type"] == "MALWARE" for c in ctx)


def test_credential_scan_scopes_to_registered_domains(tenant):
    w = tenant
    r = client.post("/v1/credential-scan", json={
        "tenant": w["tid"], "source": "breach-x",
        "records": [
            {"email": "ceo@%s" % w["domain"], "credential": "hunter2"},
            {"email": "attacker@evil.com", "credential": "x"},  # not registered
            {"email": "dev@%s" % w["domain"], "credential": "pw"},
        ],
    }).json()
    assert r["scanned"] == 3
    assert r["in_scope_hits"] == 2  # evil.com dropped, never stored
    assert r["newly_stored"] == 2

    leaks = client.get("/v1/%s/leaks" % w["tid"]).json()
    accounts = {leak["account"] for leak in leaks["leaks"]}
    assert accounts == {"ceo@%s" % w["domain"], "dev@%s" % w["domain"]}


def test_cleartext_credential_never_stored(tenant):
    w = tenant
    client.post("/v1/credential-scan", json={
        "tenant": w["tid"], "source": "breach-y",
        "records": [{"email": "x@%s" % w["domain"], "credential": "PLAINTEXTPW"}],
    })
    # inspect the raw table as admin: no column holds the cleartext
    with w["admin"].cursor() as cur:
        cur.execute("SELECT cred_salted_sha256 FROM credential_leaks"
                    " WHERE tenant_id=%s", (w["tid"],))
        rows = cur.fetchall()
    assert rows
    for (h,) in rows:
        assert h != "PLAINTEXTPW"
        assert len(h) == 64  # a hash, not the password


def test_credential_scan_idempotent(tenant):
    w = tenant
    body = {"tenant": w["tid"], "source": "breach-z",
            "records": [{"email": "a@%s" % w["domain"], "credential": "p"}]}
    assert client.post("/v1/credential-scan", json=body).json()["newly_stored"] == 1
    assert client.post("/v1/credential-scan", json=body).json()["newly_stored"] == 0


def test_rls_isolates_detect(tenant):
    w = tenant
    client.post("/v1/credential-scan", json={
        "tenant": w["tid"], "source": "b",
        "records": [{"email": "a@%s" % w["domain"], "credential": "p"}]})
    other = str(uuid.uuid4())
    with w["admin"].cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'o')",
                    (other, "dt-o-%s" % other[:8]))
    try:
        assert client.get("/v1/%s/leaks" % other).json()["count"] == 0
        # other tenant's IOC match sees an empty watchlist
        m = client.post("/v1/ioc-match",
                        json={"tenant": other, "iocs": [w["ioc"]]}).json()
        assert m["matched"] == []
    finally:
        with w["admin"].cursor() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (other,))
