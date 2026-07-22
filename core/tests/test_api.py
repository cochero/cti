"""API unit tier: auth, membership routing, serializer shape.

These run as the admin role on the test DB, so RLS is *bypassed* here by
design — tenant fencing through the full stack is proven in
tests_live/test_rls_via_django.py against the app role.
"""

import uuid

import pytest
from django.db import connection
from rest_framework.test import APIClient

from accounts.models import Membership, User


def make_tenant(slug):
    tid = uuid.uuid4()
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, %s)",
            [str(tid), slug, slug],
        )
    return tid


@pytest.mark.django_db
def test_anonymous_is_rejected():
    assert APIClient().get("/api/v1/tenants/me").status_code == 403


@pytest.mark.django_db
def test_user_without_membership_is_rejected():
    u = User.objects.create_user(username="a", email="a@example.com", password="x")
    c = APIClient()
    c.force_authenticate(u)
    assert c.get("/api/v1/tenants/me").status_code == 403
    assert c.get("/api/v1/ledger/entries").status_code == 403


@pytest.mark.django_db
def test_tenant_me_reflects_default_membership():
    u = User.objects.create_user(username="a", email="a@example.com", password="x")
    t1, t2 = make_tenant("t-one"), make_tenant("t-two")
    Membership.objects.create(user=u, tenant_id=t1, role="viewer", is_default=False)
    Membership.objects.create(user=u, tenant_id=t2, role="analyst", is_default=True)

    c = APIClient()
    c.force_login(u)
    body = c.get("/api/v1/tenants/me").json()
    assert body == {"tenant_id": str(t2), "role": "analyst", "user": "a@example.com"}


@pytest.mark.django_db
def test_ledger_serializer_shape():
    u = User.objects.create_user(username="a", email="a@example.com", password="x")
    t1 = make_tenant("t-shape")
    Membership.objects.create(user=u, tenant_id=t1, role="analyst", is_default=True)
    with connection.cursor() as cur:
        cur.execute(
            "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor, kind, payload,"
            " prev_hash, entry_hash) VALUES (%s, 0, '2026-07-22T00:00:00Z', 'svc',"
            " 'score.emitted', '{\"score_millis\": 80000}', repeat('0',64), repeat('a',64))",
            [str(t1)],
        )

    c = APIClient()
    c.force_login(u)
    rows = c.get("/api/v1/ledger/entries").json()
    assert len(rows) >= 1
    row = next(r for r in rows if r["tenant_id"] == str(t1))
    assert row["seq"] == 0
    assert row["kind"] == "score.emitted"
    assert row["payload"] == {"score_millis": 80000}
    assert set(row) == {
        "tenant_id", "seq", "ts_iso", "actor", "kind", "payload", "entry_hash"
    }
