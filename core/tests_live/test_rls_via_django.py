"""RLS through the full Django stack, live (run with: pytest tests_live -p no:django).

The proof S1-S2 exists to deliver: an authenticated request through
session auth -> TenantContextMiddleware -> ORM -> Postgres RLS, with the
connection running as `truvo_app`, sees ONLY its tenant's ledger rows —
while a second tenant's rows sit in the same table.

Env (all required; test skips without them):
    TRUVO_TEST_DATABASE_URL  admin URL (tenant provisioning + cleanup)
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
    os.environ["TRUVO_DB_URL"] = APP_URL  # Django runtime = RLS-enforced role
    os.environ.setdefault("TRUVO_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()

    import psycopg2
    from accounts.models import Membership, User
    from django.test import Client


@pytest.fixture()
def live_world():
    """Two tenants with one ledger entry each (admin conn); one user with a
    membership in tenant A (Django ORM over the app role)."""
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    email = "live-%s@example.com" % uuid.uuid4().hex[:8]
    with admin.cursor() as cur:
        for tid in (tenant_a, tenant_b):
            cur.execute(
                "INSERT INTO tenants (tenant_id, slug, name) VALUES (%s, %s, %s)",
                (str(tid), "live-%s" % str(tid)[:8], "live"),
            )
            cur.execute(
                "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor, kind,"
                " payload, prev_hash, entry_hash) VALUES (%s, 0, '2026-07-22T00:00:00Z',"
                " 'live-test', 'test.event', '{}', repeat('0',64), repeat('a',64))",
                (str(tid),),
            )
    user = User.objects.create_user(
        username=email, email=email, password="live-test-pw"
    )
    Membership.objects.create(
        user=user, tenant_id=tenant_a, role="analyst", is_default=True
    )
    yield user, tenant_a, tenant_b
    user.delete()
    with admin.cursor() as cur:
        cur.execute(
            "DELETE FROM ledger_entries WHERE tenant_id IN (%s, %s)",
            (str(tenant_a), str(tenant_b)),
        )
        cur.execute(
            "DELETE FROM tenants WHERE tenant_id IN (%s, %s)",
            (str(tenant_a), str(tenant_b)),
        )
    admin.close()


def test_django_request_sees_only_its_tenant(live_world):
    user, tenant_a, tenant_b = live_world
    c = Client()
    c.force_login(user)

    me = c.get("/api/v1/tenants/me").json()
    assert me["tenant_id"] == str(tenant_a)
    assert me["role"] == "analyst"

    rows = c.get("/api/v1/ledger/entries").json()
    tenant_ids = {r["tenant_id"] for r in rows}
    assert str(tenant_a) in tenant_ids, "own tenant's rows must be visible"
    assert str(tenant_b) not in tenant_ids, "LEAK: other tenant's rows visible"
    # stronger: as truvo_app, *nothing* outside the fence is visible at all
    assert tenant_ids == {str(tenant_a)}


def test_membership_swap_moves_the_fence(live_world):
    """Same user, membership flipped to tenant B -> now sees only B."""
    user, tenant_a, tenant_b = live_world
    m = user.memberships.get()
    m.tenant_id = tenant_b
    m.save()

    c = Client()
    c.force_login(user)
    rows = c.get("/api/v1/ledger/entries").json()
    assert {r["tenant_id"] for r in rows} == {str(tenant_b)}
