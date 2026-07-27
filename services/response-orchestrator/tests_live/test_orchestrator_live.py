"""response-orchestrator live: decisions recorded, ledger-audited, breakers
fire on real accumulated state, RLS isolates, global breaker sees across
tenants.

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
    os.environ["TRUVO_ORCH_DB_URL"] = APP_URL
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
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'r')",
                    (tid, "ro-%s" % tid[:8]))
    yield tid, admin
    with admin.cursor() as cur:
        cur.execute("DELETE FROM response_actions WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (tid,))
    admin.close()


def _evaluate(tid, **kw):
    body = dict(tenant=tid, action_type="isolate_host", target="host-1",
                evidence_level=3, criticality=1, reversible=True,
                asset_class_affected_millis=0, telemetry_age_seconds=10)
    body.update(kw)
    r = client.post("/v1/evaluate", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_osint_action_is_never_autonomous_live(tenant):
    """The §7.3 floor, end to end: OSINT evidence -> human, never executed,
    no matter that the asset is trivial and the action reversible."""
    r = _evaluate(tid=tenant[0], evidence_level=2)  # MULTI_OSINT
    assert r["verdict"] == "human"
    assert r["executed"] is False


def test_high_trust_noncritical_first_time_goes_through_human(tenant):
    """Novelty breaker: even a clean Tier-1 candidate runs through a human
    on first use of the action type for this tenant."""
    r = _evaluate(tid=tenant[0], evidence_level=3, criticality=1)
    assert r["decided_tier"] == 1
    assert r["verdict"] == "human"
    assert "novelty" in r["reason"]


def test_second_use_is_autonomous(tenant):
    tid, admin = tenant
    # seed a prior EXECUTED action of this type so novelty is satisfied
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO response_actions (tenant_id, action_type, target,"
            " evidence_level, criticality, reversible, decided_tier, executed,"
            " verdict, reason) VALUES (%s,'isolate_host','h0',3,1,true,1,true,"
            "'approved','seed')", (tid,))
    r = _evaluate(tid=tid, evidence_level=3, criticality=1)
    assert r["verdict"] == "approved"
    assert r["executed"] is True


def test_critical_asset_forced_human(tenant):
    r = _evaluate(tid=tenant[0], evidence_level=4, criticality=3)
    assert r["decided_tier"] == 3
    assert r["verdict"] == "human"


def test_dead_man_switch_blocks(tenant):
    tid, admin = tenant
    with admin.cursor() as cur:  # satisfy novelty so we isolate the dead-man path
        cur.execute(
            "INSERT INTO response_actions (tenant_id, action_type, target,"
            " evidence_level, criticality, reversible, decided_tier, executed,"
            " verdict, reason) VALUES (%s,'isolate_host','h0',3,1,true,1,true,"
            "'approved','seed')", (tid,))
    r = _evaluate(tid=tid, evidence_level=3, criticality=1,
                  telemetry_age_seconds=5000)
    assert r["verdict"] == "blocked"
    assert "dead-man" in r["reason"]


def test_decision_is_on_the_ledger(tenant):
    tid, admin = tenant
    r = _evaluate(tid=tid, evidence_level=2)
    with admin.cursor() as cur:
        cur.execute("SELECT kind, payload FROM ledger_entries"
                    " WHERE tenant_id=%s AND seq=%s", (tid, r["ledger_seq"]))
        kind, payload = cur.fetchone()
    assert kind == "action.decided"
    assert payload["verdict"] == "human"
    assert payload["evidence_level"] == 2


def test_rls_isolates_actions(tenant):
    tid, admin = tenant
    _evaluate(tid=tid, evidence_level=2)
    other = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'o')",
                    (other, "ro-o-%s" % other[:8]))
    try:
        q = client.get("/v1/%s/actions" % other).json()
        assert q["count"] == 0
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM response_actions WHERE tenant_id=%s", (other,))
            cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (other,))
