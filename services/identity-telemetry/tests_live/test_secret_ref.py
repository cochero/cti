"""Secret-reference handling live (S7): the sync API accepts vault refs,
resolves them, and never accepts raw secrets.

Env: TRUVO_TEST_DATABASE_URL + TRUVO_VAULT_ADDR/TOKEN.
"""

import os
import uuid

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
VAULT = os.environ.get("TRUVO_VAULT_ADDR")

pytestmark = pytest.mark.skipif(
    not (ADMIN_URL and VAULT), reason="db/vault env not set"
)

if ADMIN_URL and VAULT:
    os.environ.setdefault(
        "TRUVO_IDENTITY_DB_URL",
        "postgresql://truvo_app:truvo-app-dev-only@localhost:5432/truvo",
    )
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)


def test_raw_secret_field_no_longer_exists():
    r = client.post(
        "/v1/%s/sync" % uuid.uuid4(),
        json={
            "provider": "entra", "idp_tenant_id": "t", "client_id": "c",
            "client_secret": "raw-secret-value",  # legacy field: ignored
        },
    )
    assert r.status_code == 422
    assert "client_secret_ref" in r.json()["detail"]


def test_unresolvable_ref_rejected_cleanly():
    r = client.post(
        "/v1/%s/sync" % uuid.uuid4(),
        json={
            "provider": "entra", "idp_tenant_id": "t", "client_id": "c",
            "client_secret_ref": "vault:secret/truvo-test/absent-%s#client_secret"
                                 % uuid.uuid4().hex[:8],
        },
    )
    assert r.status_code == 422
    assert "client_secret_ref" in r.json()["detail"]


def test_plaintext_ref_rejected():
    r = client.post(
        "/v1/%s/sync" % uuid.uuid4(),
        json={
            "provider": "entra", "idp_tenant_id": "t", "client_id": "c",
            "client_secret_ref": "raw-secret-not-a-ref",
        },
    )
    assert r.status_code == 422
    assert "unsupported" in r.json()["detail"]
