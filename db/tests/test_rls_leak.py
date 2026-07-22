"""Cross-tenant leak tests (platform DoD SS1.3).

These tests are the enforcement of Architecture v2's tenant-isolation
guarantee. They run as `truvo_app` -- the exact role services use -- against
a real Postgres. If any of them fails, tenant data can leak: treat as sev-1.
"""

import pytest

psycopg2 = pytest.importorskip("psycopg2")

from conftest import clear_tenant, insert_entry, set_tenant  # noqa: E402


def test_app_role_is_unprivileged(admin_conn):
    """Privilege drift on truvo_app must fail CI, not be discovered later."""
    with admin_conn.cursor() as cur:
        cur.execute(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
            "FROM pg_roles WHERE rolname = 'truvo_app'"
        )
        row = cur.fetchone()
    assert row is not None, "truvo_app role missing"
    assert row == (False, False, False, False)


def test_rls_is_enabled_and_forced(admin_conn):
    with admin_conn.cursor() as cur:
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname = 'ledger_entries'"
        )
        assert cur.fetchone() == (True, True)


def test_tenant_sees_only_its_own_rows(app_conn, two_tenants):
    tenant_a, tenant_b = two_tenants
    set_tenant(app_conn, tenant_a)
    insert_entry(app_conn, tenant_a, 0)
    set_tenant(app_conn, tenant_b)
    insert_entry(app_conn, tenant_b, 0)

    set_tenant(app_conn, tenant_a)
    with app_conn.cursor() as cur:
        cur.execute("SELECT tenant_id FROM ledger_entries")
        rows = cur.fetchall()
    assert {r[0] for r in rows} == {str(tenant_a)}


def test_where_clause_cannot_escape_the_fence(app_conn, two_tenants):
    """Explicitly naming another tenant's id must return nothing, not leak."""
    tenant_a, tenant_b = two_tenants
    set_tenant(app_conn, tenant_b)
    insert_entry(app_conn, tenant_b, 0)

    set_tenant(app_conn, tenant_a)
    with app_conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM ledger_entries WHERE tenant_id = %s",
            (str(tenant_b),),
        )
        assert cur.fetchone()[0] == 0


def test_cannot_insert_into_another_tenant(app_conn, two_tenants):
    tenant_a, tenant_b = two_tenants
    set_tenant(app_conn, tenant_a)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        insert_entry(app_conn, tenant_b, 0)


def test_no_tenant_context_means_zero_rows(app_conn, two_tenants):
    tenant_a, _ = two_tenants
    set_tenant(app_conn, tenant_a)
    insert_entry(app_conn, tenant_a, 0)

    clear_tenant(app_conn)
    with app_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM ledger_entries")
        assert cur.fetchone()[0] == 0


def test_no_tenant_context_cannot_insert(app_conn, two_tenants):
    tenant_a, _ = two_tenants
    clear_tenant(app_conn)
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        insert_entry(app_conn, tenant_a, 99)


def test_ledger_is_append_only_for_app_role(app_conn, two_tenants):
    """No UPDATE or DELETE grants: history is immutable at the SQL layer too."""
    tenant_a, _ = two_tenants
    set_tenant(app_conn, tenant_a)
    insert_entry(app_conn, tenant_a, 0)

    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with app_conn.cursor() as cur:
            cur.execute("UPDATE ledger_entries SET kind = 'tampered'")
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with app_conn.cursor() as cur:
            cur.execute("DELETE FROM ledger_entries")


def test_app_role_cannot_write_tenant_registry(app_conn):
    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        with app_conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (slug, name) VALUES ('rogue-tenant', 'rogue')"
            )
