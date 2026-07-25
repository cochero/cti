"""Service-identity enforcement live (S7): keys provisioned in the vault,
signed requests pass, everything else is 401.

Env: TRUVO_TEST_DATABASE_URL + TRUVO_VAULT_ADDR/TOKEN.
"""

import json
import os
import uuid

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
VAULT = os.environ.get("TRUVO_VAULT_ADDR")
APP_URL = "postgresql://truvo_app:truvo-app-dev-only@localhost:5432/truvo"

pytestmark = pytest.mark.skipif(
    not (ADMIN_URL and VAULT), reason="db/vault env not set"
)

if ADMIN_URL and VAULT:
    import app.main as ledger
    import psycopg2
    from app.store import PostgresStore
    from fastapi.testclient import TestClient
    from truvo_secrets import SecretsClient
    from truvo_svcauth import generate_keypair, sign_headers

    _pg_store = PostgresStore(APP_URL)
    client = TestClient(ledger.app)

    # provision a signing identity for a fake internal caller
    CALLER = "scoring-svc"
    PRIV, PUB = generate_keypair()
    SecretsClient().kv_put("secret", "truvo/services/%s" % CALLER, {"pubkey": PUB})


@pytest.fixture(autouse=True)
def _enforced(monkeypatch):
    ledger.use_store(_pg_store)
    monkeypatch.setenv("TRUVO_SVCAUTH", "1")


@pytest.fixture()
def tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, 'live')",
            (tid, "sva-%s" % tid[:8]),
        )
    yield tid
    with admin.cursor() as cur:
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id = %s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (tid,))
    admin.close()


def _body(tid):
    return json.dumps(
        {"tenant": tid, "actor": CALLER, "kind": "score.emitted",
         "payload": {"n": 1}}
    ).encode()


def test_signed_request_accepted(tenant):
    body = _body(tenant)
    headers = sign_headers(CALLER, PRIV, "POST", "/v1/entries", body)
    r = client.post("/v1/entries", content=body, headers={
        **headers, "Content-Type": "application/json",
    })
    assert r.status_code == 201, r.text


def test_unsigned_request_rejected(tenant):
    r = client.post("/v1/entries", content=_body(tenant),
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 401
    assert "missing" in r.json()["detail"]


def test_tampered_body_rejected(tenant):
    body = _body(tenant)
    headers = sign_headers(CALLER, PRIV, "POST", "/v1/entries", body)
    tampered = body.replace(b'"n": 1', b'"n": 9')
    r = client.post("/v1/entries", content=tampered, headers={
        **headers, "Content-Type": "application/json",
    })
    assert r.status_code == 401


def test_unknown_service_rejected(tenant):
    rogue_priv, _ = generate_keypair()
    body = _body(tenant)
    headers = sign_headers("rogue-svc", rogue_priv, "POST", "/v1/entries", body)
    r = client.post("/v1/entries", content=body, headers={
        **headers, "Content-Type": "application/json",
    })
    assert r.status_code == 401


def test_reads_unaffected_by_enforcement(tenant):
    assert client.get("/v1/%s/entries" % tenant).status_code == 200
