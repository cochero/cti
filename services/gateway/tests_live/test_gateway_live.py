"""gateway-svc live (§8.3): signed commands push; unsigned/tampered/replayed
are refused; SIEM creds come from the vault; RLS isolates.

Env: TRUVO_TEST_DATABASE_URL + TRUVO_VAULT_ADDR/TOKEN. Run: pytest tests_live
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
    os.environ["TRUVO_GATEWAY_DB_URL"] = APP_URL
    os.environ["TRUVO_SVCAUTH"] = "1"          # enforce signing
    os.environ["TRUVO_DEV_SIEM_TOKEN"] = "dev-token"
    import psycopg2
    from app.main import app
    from fastapi.testclient import TestClient
    from truvo_secrets import SecretsClient
    from truvo_svcauth import generate_keypair, sign_headers

    client = TestClient(app)
    CALLER = "response-orchestrator"
    PRIV, PUB = generate_keypair()
    SecretsClient().kv_put("secret", "truvo/services/%s" % CALLER, {"pubkey": PUB})


@pytest.fixture()
def tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'g')",
                    (tid, "gw-%s" % tid[:8]))
    # provision the tenant's SIEM credentials in the vault (the gateway
    # resolves them per push — never from our DB, §8.3/T4)
    SecretsClient().kv_put(
        "secret", "truvo/tenants/%s/siem/fake" % tid, {"token": "siem-token-xyz"})
    yield tid, admin
    with admin.cursor() as cur:
        cur.execute("DELETE FROM gateway_commands WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (tid,))
    admin.close()


def _cmd_body(tid, nonce=None):
    return json.dumps({
        "tenant": tid, "nonce": nonce or uuid.uuid4().hex,
        "action_type": "isolate_host", "target": "host-1", "adapter": "fake",
    }).encode()


def _signed_headers(body):
    h = sign_headers(CALLER, PRIV, "POST", "/v1/push", body)
    h["Content-Type"] = "application/json"
    return h


def test_signed_command_pushes(tenant):
    tid, _ = tenant
    body = _cmd_body(tid)
    r = client.post("/v1/push", content=body, headers=_signed_headers(body))
    assert r.status_code == 201, r.text
    assert r.json()["pushed"] is True


def test_unsigned_command_refused(tenant):
    tid, _ = tenant
    body = _cmd_body(tid)
    r = client.post("/v1/push", content=body,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 401


def test_tampered_body_refused(tenant):
    tid, _ = tenant
    body = _cmd_body(tid)
    headers = _signed_headers(body)
    tampered = body.replace(b"host-1", b"host-99")
    r = client.post("/v1/push", content=tampered, headers=headers)
    assert r.status_code == 401


def test_replayed_nonce_refused(tenant):
    tid, _ = tenant
    nonce = uuid.uuid4().hex
    body = _cmd_body(tid, nonce=nonce)
    assert client.post("/v1/push", content=body,
                       headers=_signed_headers(body)).status_code == 201
    # exact same signed command again -> nonce already used
    r = client.post("/v1/push", content=body, headers=_signed_headers(body))
    assert r.status_code == 409
    assert "replay" in r.json()["detail"]


def test_rogue_service_refused(tenant):
    tid, _ = tenant
    rogue_priv, _ = generate_keypair()
    body = _cmd_body(tid)
    h = sign_headers("rogue-svc", rogue_priv, "POST", "/v1/push", body)
    h["Content-Type"] = "application/json"
    r = client.post("/v1/push", content=body, headers=h)
    assert r.status_code == 401


def test_command_on_ledger_and_recorded(tenant):
    tid, admin = tenant
    body = _cmd_body(tid)
    r = client.post("/v1/push", content=body, headers=_signed_headers(body)).json()
    with admin.cursor() as cur:
        cur.execute("SELECT kind, payload FROM ledger_entries"
                    " WHERE tenant_id=%s AND seq=%s", (tid, r["ledger_seq"]))
        kind, payload = cur.fetchone()
    assert kind == "command.pushed"
    assert payload["pushed"] is True
    q = client.get("/v1/%s/commands" % tid).json()
    assert q["count"] == 1


def test_rls_isolates_commands(tenant):
    tid, admin = tenant
    body = _cmd_body(tid)
    client.post("/v1/push", content=body, headers=_signed_headers(body))
    other = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'o')",
                    (other, "gw-o-%s" % other[:8]))
    try:
        assert client.get("/v1/%s/commands" % other).json()["count"] == 0
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (other,))
