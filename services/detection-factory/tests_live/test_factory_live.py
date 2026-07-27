"""detection-factory live: the full compile→test→sign→stage→promote flow.

Asserts a good rule stages+signs and promotes to active; a bad (over-
matching or useless) rule is stored REJECTED, cannot be promoted, and never
carries a valid signature; RLS isolates rules; and a signature-tampered
rule is refused promotion.

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
    os.environ["TRUVO_DETECTION_DB_URL"] = APP_URL
    os.environ.setdefault("TRUVO_RULE_KEY", "test-rule-key")
    os.environ.pop("TRUVO_VAULT_ADDR", None)  # use env key for deterministic test
    import psycopg2
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)


@pytest.fixture()
def tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'d')",
                    (tid, "df-%s" % tid[:8]))
    yield tid, admin
    with admin.cursor() as cur:
        cur.execute("DELETE FROM detection_rules WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (tid,))
    admin.close()


def _good_rule(tid):
    return client.post("/v1/rules", json={
        "tenant": tid, "cve": "CVE-2026-9001", "title": "Evil binary",
        "indicators": {"Image": "C:\\Temp\\evil.exe"},
        "malicious_samples": [{"Image": "C:\\Temp\\evil.exe", "CommandLine": "-x"}],
    })


def test_good_rule_stages_signs_and_promotes(tenant):
    tid, _ = tenant
    r = _good_rule(tid).json()
    assert r["status"] == "staged"
    assert r["detonation"]["passed"] is True
    assert r["signature"] != "0" * 64  # signed
    assert "title: Evil binary" in r["content"]

    p = client.post("/v1/rules/%s/promote?tenant=%s" % (r["rule_id"], tid))
    assert p.status_code == 200
    assert p.json()["status"] == "active"


def test_overmatching_rule_rejected_and_unpromotable(tenant):
    tid, _ = tenant
    r = client.post("/v1/rules", json={
        "tenant": tid, "cve": "CVE-2026-9002", "title": "Greedy",
        "indicators": {"Image|contains": "\\"},  # matches most benign Windows paths
        "malicious_samples": [{"Image": "C:\\Temp\\evil.exe"}],
    }).json()
    assert r["status"] == "rejected"
    assert r["signature"] == "0" * 64  # never signed
    assert "FP rate" in r["detonation"]["reason"]

    p = client.post("/v1/rules/%s/promote?tenant=%s" % (r["rule_id"], tid))
    assert p.status_code == 409
    assert "rejected" in p.json()["detail"]


def test_useless_rule_rejected(tenant):
    tid, _ = tenant
    r = client.post("/v1/rules", json={
        "tenant": tid, "cve": "CVE-2026-9003", "title": "Whiffs",
        "indicators": {"Image": "never-seen.exe"},
        "malicious_samples": [{"Image": "C:\\Temp\\evil.exe"}],
    }).json()
    assert r["status"] == "rejected"
    assert "catches none" in r["detonation"]["reason"]


def test_tampered_signature_refused_promotion(tenant):
    tid, admin = tenant
    r = _good_rule(tid).json()
    # tamper the stored content (as an attacker with DB access would)
    with admin.cursor() as cur:
        cur.execute("UPDATE detection_rules SET content = content || '\n# injected'"
                    " , content_sha256 = repeat('e',64) WHERE rule_id=%s",
                    (r["rule_id"],))
    p = client.post("/v1/rules/%s/promote?tenant=%s" % (r["rule_id"], tid))
    assert p.status_code == 409
    assert "tampered" in p.json()["detail"]


def test_rls_isolates_rules(tenant):
    tid, admin = tenant
    _good_rule(tid)
    other = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'o')",
                    (other, "df-o-%s" % other[:8]))
    try:
        q = client.get("/v1/%s/rules" % other).json()
        assert q["count"] == 0
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (other,))


def test_list_filters_by_status(tenant):
    tid, _ = tenant
    _good_rule(tid)  # staged
    client.post("/v1/rules", json={  # rejected
        "tenant": tid, "cve": "CVE-2026-9004", "title": "Bad",
        "indicators": {"Image|contains": "\\"},
        "malicious_samples": [],
    })
    staged = client.get("/v1/%s/rules?status=staged" % tid).json()
    rejected = client.get("/v1/%s/rules?status=rejected" % tid).json()
    assert staged["count"] == 1
    assert rejected["count"] == 1
