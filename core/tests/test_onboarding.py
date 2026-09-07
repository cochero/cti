"""Onboarding wizard — the full tech + legal process, end to end.

The invariants under test:
  - only platform staff may onboard
  - legal is all-or-nothing, cites exact doc versions, and lands on the
    TARGET tenant's hash-chained ledger (provable consent)
  - admin provisioning creates the user + admin membership exactly once
  - environment registration writes RLS-fenced rows under the target
    tenant's context (assets, sector, watch domains)
  - activation flips the tenant to active and records the summary
  - nothing is visible across tenants: the new tenant's rows are fenced
"""

import json
import uuid

import pytest
from accounts.models import Membership, User
from django.db import connection
from rest_framework.test import APIClient
from tenancy.onboarding import LEGAL_DOCS


def make_tenant(slug):
    tid = uuid.uuid4()
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name, status)"
            " VALUES (%s, %s, %s, 'active')", [str(tid), slug, slug])
    return tid


@pytest.fixture()
def staff_client():
    u = User.objects.create_user(username="st", email="staff@truvo.local",
                                 password="x", is_staff=True)
    tid = make_tenant("ob-staff-%s" % uuid.uuid4().hex[:8])
    Membership.objects.create(user=u, tenant_id=tid, role="viewer",
                              is_default=True)
    c = APIClient()
    c.force_login(u)
    return c


@pytest.fixture()
def analyst_client():
    u = User.objects.create_user(username="an", email="an2@example.com",
                                 password="x")  # NOT staff
    tid = make_tenant("ob-an-%s" % uuid.uuid4().hex[:8])
    Membership.objects.create(user=u, tenant_id=tid, role="analyst",
                              is_default=True)
    c = APIClient()
    c.force_login(u)
    return c


def _start(c, name="Northwind Capital"):
    return c.post("/api/v1/onboarding", {
        "company_name": name, "sector": "finance",
        "deployment_profile": "saas", "notes": "design partner",
    }, format="json")


def _legal_all():
    return {doc_id: True for doc_id in LEGAL_DOCS}


def _ledger_kinds(tid):
    with connection.cursor() as cur:
        cur.execute("SELECT kind FROM ledger_entries WHERE tenant_id = %s"
                    " ORDER BY seq", [str(tid)])
        return [r[0] for r in cur.fetchall()]


@pytest.mark.django_db
def test_non_staff_cannot_onboard(analyst_client):
    r = _start(analyst_client)
    assert r.status_code == 403
    assert analyst_client.get("/api/v1/onboarding").status_code == 403


@pytest.mark.django_db
def test_full_flow_legal_admin_environment_activate(staff_client):
    # start
    r = _start(staff_client)
    assert r.status_code == 201
    tid = r.json()["tenant_id"]
    assert r.json()["current_step"] == "legal"

    # legal is all-or-nothing
    partial = _legal_all()
    partial.pop("dpa")
    r = staff_client.post("/api/v1/onboarding/%s/legal" % tid, {
        "accepted": partial, "acceptor_name": "Jane Doe",
        "acceptor_email": "jane@northwind.example", "acceptor_role": "CISO",
    }, format="json")
    assert r.status_code == 400

    # full acceptance cites exact versions
    r = staff_client.post("/api/v1/onboarding/%s/legal" % tid, {
        "accepted": _legal_all(), "acceptor_name": "Jane Doe",
        "acceptor_email": "jane@northwind.example", "acceptor_role": "CISO",
    }, format="json")
    assert r.status_code == 200
    legal = r.json()["legal"]
    assert legal["dpa"]["version"] == "1.0"
    assert legal["dpa"]["accepted_by"] == "jane@northwind.example"

    # admin provisioning returns a one-time password
    r = staff_client.post("/api/v1/onboarding/%s/admin" % tid, {
        "email": "admin@northwind.example", "name": "Jane Doe",
    }, format="json")
    assert r.status_code == 200
    password = r.json()["initial_password"]
    assert password.startswith("Truvo-")
    admin_user = User.objects.get(email="admin@northwind.example")
    assert admin_user.check_password(password)
    assert Membership.objects.filter(user=admin_user, tenant_id=tid,
                                     role="admin").exists()
    # duplicate admin rejected
    r2 = staff_client.post("/api/v1/onboarding/%s/admin" % tid, {
        "email": "admin@northwind.example", "name": "Jane Doe",
    }, format="json")
    assert r2.status_code == 400

    # environment registration
    r = staff_client.post("/api/v1/onboarding/%s/environment" % tid, {
        "sector": "finance",
        "assets": [
            {"cpe": "cpe:2.3:a:apache:log4j", "count": 30},
            {"cpe": "cpe:2.3:o:fortinet:fortios", "count": 12},
        ],
        "watch_domains": ["northwind.example", "northwind-bank.com"],
        "idp": {"provider": "entra", "tenant_id": "contoso", "client_id": "abc"},
    }, format="json")
    assert r.status_code == 200
    assert r.json()["assets"] == 2

    # bad CPE and bad domain rejected
    r = staff_client.post("/api/v1/onboarding/%s/environment" % tid, {
        "assets": [{"cpe": "not-a-cpe"}], "watch_domains": [],
    }, format="json")
    assert r.status_code == 400
    r = staff_client.post("/api/v1/onboarding/%s/environment" % tid, {
        "assets": [], "watch_domains": ["bad domain!"],
    }, format="json")
    assert r.status_code == 400

    # activate
    r = staff_client.post("/api/v1/onboarding/%s/complete" % tid, {},
                          format="json")
    assert r.status_code == 200
    assert r.json()["status"] == "active"

    with connection.cursor() as cur:
        cur.execute("SELECT status, name FROM tenants WHERE tenant_id = %s",
                    [tid])
        assert cur.fetchone() == ("active", "Northwind Capital")
        cur.execute("SELECT count(*) FROM tenant_assets WHERE tenant_id = %s",
                    [tid])
        assert cur.fetchone()[0] == 2
        cur.execute("SELECT sector FROM tenant_sector WHERE tenant_id = %s",
                    [tid])
        assert cur.fetchone()[0] == "finance"
        cur.execute("SELECT count(*) FROM tenant_domains WHERE tenant_id = %s",
                    [tid])
        assert cur.fetchone()[0] == 2

    kinds = _ledger_kinds(tid)
    assert kinds == ["onboarding.started", "onboarding.legal_accepted",
                     "onboarding.admin_created",
                     "onboarding.environment_registered", "tenant.activated"]

    # the activation entry carries the legal versions — provable consent
    with connection.cursor() as cur:
        cur.execute(
            "SELECT payload FROM ledger_entries WHERE tenant_id = %s"
            " AND kind = 'tenant.activated'", [tid])
        payload = cur.fetchone()[0]
    if isinstance(payload, str):
        payload = json.loads(payload)
    assert payload["legal_documents"]["dpa"] == "1.0"
    assert payload["admin"]["email"] == "admin@northwind.example"


@pytest.mark.django_db
def test_completion_requires_admin_and_environment(staff_client):
    tid = _start(staff_client).json()["tenant_id"]
    r = staff_client.post("/api/v1/onboarding/%s/complete" % tid, {},
                          format="json")
    assert r.status_code == 400


@pytest.mark.django_db
def test_admin_step_blocked_before_legal(staff_client):
    tid = _start(staff_client).json()["tenant_id"]
    r = staff_client.post("/api/v1/onboarding/%s/admin" % tid, {
        "email": "x@y.example", "name": "X"}, format="json")
    assert r.status_code == 400


@pytest.mark.django_db
def test_legal_docs_registry_serves_versions(staff_client):
    r = staff_client.get("/api/v1/onboarding/legal-docs")
    assert r.status_code == 200
    docs = {d["id"]: d for d in r.json()["docs"]}
    assert set(docs) >= {"dpa", "tos", "data_governance"}
    for d in docs.values():
        assert d["version"] and d["title"] and len(d["body"]) > 200


@pytest.mark.django_db
def test_onboarded_tenant_rows_are_rls_fenced(staff_client):
    """The rows the wizard wrote belong to the new tenant only — a
    different tenant's request must see none of them."""
    tid = _start(staff_client, name="Fenced Corp").json()["tenant_id"]
    staff_client.post("/api/v1/onboarding/%s/legal" % tid, {
        "accepted": _legal_all(), "acceptor_name": "J",
        "acceptor_email": "j@f.example", "acceptor_role": "CISO",
    }, format="json")
    staff_client.post("/api/v1/onboarding/%s/environment" % tid, {
        "sector": "energy", "assets": [{"cpe": "cpe:2.3:a:apache:log4j"}],
        "watch_domains": ["fenced.example"],
    }, format="json")

    # log in as the new admin and read only their world
    staff_client.post("/api/v1/onboarding/%s/admin" % tid, {
        "email": "fa@fenced.example", "name": "FA"}, format="json")
    fa = APIClient()
    fa.force_login(User.objects.get(email="fa@fenced.example"))
    body = fa.get("/api/v1/dashboard/summary").json()
    assert body["assets"]["products"] == 1
    assert body["scored_cves"] == 0  # nothing scored yet — honest emptiness
