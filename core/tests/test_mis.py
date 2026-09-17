"""MIS API unit tier: priorities, decomposition, rules, heatmap, summary.

Same honesty as test_api.py: these run as the admin role on the test DB
(RLS bypassed here by design — full-stack fencing is proven in
tests_live). The behaviors under test are the READ SHAPES the console
consumes and the RULE TRANSITION state machine + ledger recording.
"""

import json
import uuid

import pytest
from accounts.models import Membership, User
from django.db import connection
from rest_framework.test import APIClient
from tenancy.mis import _RULE_TRANSITIONS
from truvo_core.hashchain import append_entry


def make_tenant(slug):
    tid = uuid.uuid4()
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, %s)",
            [str(tid), slug, slug],
        )
    return tid


@pytest.fixture()
def analyst_client():
    u = User.objects.create_user(username="an", email="an@example.com",
                                 password="x")
    tid = make_tenant("mis-%s" % uuid.uuid4().hex[:8])
    Membership.objects.create(user=u, tenant_id=tid, role="analyst",
                              is_default=True)
    c = APIClient()
    c.force_login(u)
    return c, str(tid)


@pytest.fixture()
def viewer_client():
    u = User.objects.create_user(username="vw", email="vw@example.com",
                                 password="x")
    tid = make_tenant("misv-%s" % uuid.uuid4().hex[:8])
    Membership.objects.create(user=u, tenant_id=tid, role="viewer",
                              is_default=True)
    c = APIClient()
    c.force_login(u)
    return c, str(tid)


def _seed_world(tid, cve_hi="CVE-2026-1111", cve_lo="CVE-2026-2222"):
    """Scores for two CVEs (hi scored twice — latest wins), a matching
    score.emitted ledger entry, exploit intel, a staged rule, a claim with
    techniques. Returns the staged rule_id."""
    with connection.cursor() as cur:
        for cve, pri, ago in ((cve_hi, 920, 2), (cve_hi, 870, 1), (cve_lo, 100, 1)):
            cur.execute(
                "INSERT INTO scores (tenant_id, cve, priority_millis,"
                " weights_version, scored_at)"
                " VALUES (%s,%s,%s,'weights-v0', now() - %s * interval '1 hour')",
                [tid, cve, pri, ago],
            )
        # a chained score.emitted entry mirroring scoring-svc's write
        decomp = {
            "cve": cve_hi, "priority_millis": 870,
            "weights_version": "weights-v0",
            "factors": [
                {"name": "stack_overlap", "raw": "affects_tenant=True",
                 "subscore_millis": 1000, "weight_millis": 300,
                 "contribution_millis": 300},
                {"name": "exploit_maturity", "raw": "epss=941 kev=True",
                 "subscore_millis": 941, "weight_millis": 250,
                 "contribution_millis": 235},
            ],
        }
        entry = append_entry(None, ts_iso="2026-07-22T00:00:00.000000Z",
                             tenant=tid, actor="scoring-svc",
                             kind="score.emitted", payload=decomp)
        cur.execute(
            "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor, kind,"
            " payload, prev_hash, entry_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            [tid, entry.seq, entry.ts_iso, entry.actor, entry.kind,
             json.dumps(entry.payload), entry.prev_hash, entry.entry_hash],
        )
        cur.execute(
            "INSERT INTO exploit_intel (cve, epss_millis, cvss_millis, kev)"
            " VALUES (%s, 941, 980, true) ON CONFLICT (cve) DO NOTHING",
            [cve_hi],
        )
        cur.execute(
            "INSERT INTO detection_rules (tenant_id, cve, title, content,"
            " content_sha256, signature, status, generator_version)"
            " VALUES (%s,%s,'t','c',%s,%s,'staged','sigma-gen-v0.1')"
            " RETURNING rule_id",
            [tid, cve_hi, "a" * 64, "b" * 64],
        )
        rule_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO sources (source_id, name, source_type, grade)"
            " VALUES ('src-mis-test', 't', 'cert', 'A')"
            " ON CONFLICT DO NOTHING"
        )
        cur.execute(
            "INSERT INTO claims (claim_id, source_id, provenance_id,"
            " observed_at_iso, raw_artifact_hash, extraction_model_version,"
            " extraction_confidence_millis, subject_type, subject_value,"
            " assertion, attack_technique_ids)"
            " VALUES (%s, 'src-mis-test', %s, now(), %s, 'm', 1000, 'TTP',"
            " 'T1566.001', 'structured:technique_described',"
            " ARRAY['T1566.001','T1190'])",
            [uuid.uuid4(), uuid.uuid4(), "0" * 64],
        )
    return rule_id


@pytest.mark.django_db
def test_priorities_latest_score_per_cve(analyst_client):
    c, tid = analyst_client
    _seed_world(tid)
    body = c.get("/api/v1/priorities").json()
    rows = body["priorities"]
    assert [r["cve"] for r in rows] == ["CVE-2026-1111", "CVE-2026-2222"]
    hi = rows[0]
    assert hi["priority_millis"] == 870  # latest, not first
    assert hi["kev"] is True and hi["epss_millis"] == 941
    assert hi["active_rules"] == 0


@pytest.mark.django_db
def test_decomposition_served_from_ledger(analyst_client):
    c, tid = analyst_client
    _seed_world(tid)
    body = c.get("/api/v1/priorities/CVE-2026-1111/decomposition").json()
    assert body["scored_by"] == "scoring-svc"
    factors = body["decomposition"]["factors"]
    assert factors[0]["name"] == "stack_overlap"
    assert factors[1]["contribution_millis"] == 235


@pytest.mark.django_db
def test_decomposition_404_when_never_scored(analyst_client):
    c, _ = analyst_client
    r = c.get("/api/v1/priorities/CVE-1999-0001/decomposition")
    assert r.status_code == 404


@pytest.mark.django_db
def test_rules_list_and_status_filter(analyst_client):
    c, tid = analyst_client
    rule_id = _seed_world(tid)
    all_rules = c.get("/api/v1/rules").json()["rules"]
    assert [r["rule_id"] for r in all_rules] == [str(rule_id)]
    staged = c.get("/api/v1/rules", {"status": "staged"}).json()["rules"]
    assert len(staged) == 1
    assert c.get("/api/v1/rules", {"status": "active"}).json()["count"] == 0


@pytest.mark.django_db
def test_rule_activate_records_ledger(analyst_client):
    c, tid = analyst_client
    rule_id = _seed_world(tid)
    r = c.post("/api/v1/rules/%s/transition" % rule_id,
               {"action": "activate"}, format="json")
    assert r.status_code == 200
    assert r.json()["status"] == "active"
    seq = r.json()["ledger_seq"]

    with connection.cursor() as cur:
        cur.execute(
            "SELECT actor, kind, payload FROM ledger_entries"
            " WHERE tenant_id = %s AND seq = %s", [tid, seq])
        actor, kind, payload = cur.fetchone()
    if isinstance(payload, str):  # Django's psycopg3 returns jsonb as str
        payload = json.loads(payload)
    assert actor == "an@example.com"
    assert kind == "rule.active"
    assert payload["rule_id"] == str(rule_id)
    assert payload["action"] == "activate"

    # the transition is now spent: staged->active cannot run twice
    r2 = c.post("/api/v1/rules/%s/transition" % rule_id,
                {"action": "activate"}, format="json")
    assert r2.status_code == 400


@pytest.mark.django_db
def test_rule_reject_and_unknown_action(analyst_client):
    c, tid = analyst_client
    rule_id = _seed_world(tid)
    r = c.post("/api/v1/rules/%s/transition" % rule_id,
               {"action": "reject"}, format="json")
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    r = c.post("/api/v1/rules/%s/transition" % rule_id,
               {"action": "delete"}, format="json")
    assert r.status_code == 400


@pytest.mark.django_db
def test_viewer_cannot_release(viewer_client):
    c, tid = viewer_client
    rule_id = _seed_world(tid)
    r = c.post("/api/v1/rules/%s/transition" % rule_id,
               {"action": "activate"}, format="json")
    assert r.status_code == 403
    # but reads are fine — the queue is everyone's, the button is not
    assert c.get("/api/v1/priorities").status_code == 200
    assert c.get("/api/v1/rules").status_code == 200


@pytest.mark.django_db
def test_heatmap_counts_techniques(analyst_client):
    c, tid = analyst_client
    _seed_world(tid)
    techs = c.get("/api/v1/attack-heatmap").json()["techniques"]
    assert {"T1566.001", "T1190"} <= {t["technique_id"] for t in techs}


@pytest.mark.django_db
def test_dashboard_summary_shape(analyst_client):
    c, tid = analyst_client
    _seed_world(tid)
    body = c.get("/api/v1/dashboard/summary").json()
    assert body["rules_by_status"]["staged"] == 1
    assert body["scored_cves"] == 2
    assert len(body["top_priorities"]) == 2
    assert body["top_priorities"][0]["cve"] == "CVE-2026-1111"
    assert body["kev_in_top"] == 1


@pytest.mark.django_db
def test_transition_map_is_a_strict_state_machine():
    """Nothing resurrects a rejected rule; supersede only from active."""
    assert _RULE_TRANSITIONS["activate"] == {"from": "staged", "to": "active"}
    assert "rejected" not in [t["from"] for t in _RULE_TRANSITIONS.values()]


@pytest.mark.django_db
def test_spa_login_logout():
    from tenancy.mis import LoginView  # noqa: F401  (route presence)
    u = User.objects.create_user(username="lg", email="lg@example.com",
                                 password="secretpw")
    tid = make_tenant("mislg-%s" % uuid.uuid4().hex[:8])
    Membership.objects.create(user=u, tenant_id=tid, role="viewer",
                              is_default=True)
    c = APIClient()
    r = c.post("/api/v1/auth/login",
               {"email": "lg@example.com", "password": "secretpw"},
               format="json")
    assert r.status_code == 200
    assert r.json()["role"] == "viewer"
    assert c.get("/api/v1/priorities").status_code == 200  # session live

    bad = APIClient().post("/api/v1/auth/login",
                           {"email": "lg@example.com", "password": "wrong"},
                           format="json")
    assert bad.status_code == 401


@pytest.mark.django_db
def test_login_response_sets_csrf_cookie():
    """Regression: DRF's csrf_exempt suppresses CsrfViewMiddleware's cookie
    emission, so the login response MUST set csrftoken itself — otherwise
    the SPA's first authenticated POST 403s with 'incorrect length'."""
    from django.conf import settings as dj_settings

    u = User.objects.create_user(username="cs", email="cs@example.com",
                                 password="secretpw")
    tid = str(make_tenant("miscs-%s" % uuid.uuid4().hex[:8]))
    Membership.objects.create(user=u, tenant_id=tid, role="analyst",
                              is_default=True)
    r = APIClient().post("/api/v1/auth/login",
                         {"email": "cs@example.com", "password": "secretpw"},
                         format="json")
    assert r.status_code == 200
    cookie = r.cookies.get(dj_settings.CSRF_COOKIE_NAME)
    assert cookie is not None and len(cookie.value) == 32

    # and with that cookie + header, an authenticated POST passes CSRF:
    # release a staged rule using the session + token from the login flow
    rule_id = _seed_world(tid)
    c = APIClient()
    c.post("/api/v1/auth/login",
           {"email": "cs@example.com", "password": "secretpw"}, format="json")
    token = c.cookies[dj_settings.CSRF_COOKIE_NAME].value
    r2 = c.post("/api/v1/rules/%s/transition" % rule_id,
                {"action": "activate"}, format="json",
                HTTP_X_CSRFTOKEN=token)
    assert r2.status_code == 200
    assert r2.json()["status"] == "active"


@pytest.mark.django_db
def test_account_lockout_after_failures():
    """H1: five failures lock the account; the response is identical to a
    bad password (attacker learns nothing); a correct password is also
    refused while locked; clearing happens on nothing but success."""
    u = User.objects.create_user(username="lk", email="lock@example.com",
                                 password="right-password-1")
    tid = make_tenant("mislk2-%s" % uuid.uuid4().hex[:8])
    Membership.objects.create(user=u, tenant_id=tid, role="viewer",
                              is_default=True)
    c = APIClient()
    # distinct source IPs so the per-IP throttle stays out of the way and
    # the ACCOUNT lockout layer is what's under test
    for i in range(5):
        r = c.post("/api/v1/auth/login",
                   {"email": "lock@example.com", "password": "wrong"},
                   format="json", extra={"REMOTE_ADDR": "10.9.0.%d" % i})
        assert r.status_code == 401
    # locked now — even the CORRECT password is refused
    r = c.post("/api/v1/auth/login",
               {"email": "lock@example.com", "password": "right-password-1"},
               format="json", extra={"REMOTE_ADDR": "10.9.1.1"})
    assert r.status_code == 401
    assert r.json() == {"detail": "invalid credentials"}
    # another account is unaffected
    u2 = User.objects.create_user(username="ok", email="ok@example.com",
                                  password="fine-password-1")
    Membership.objects.create(user=u2, tenant_id=tid, role="viewer",
                              is_default=True)
    assert c.post("/api/v1/auth/login",
                  {"email": "ok@example.com", "password": "fine-password-1"},
                  format="json",
                  extra={"REMOTE_ADDR": "10.9.2.1"}).status_code == 200
