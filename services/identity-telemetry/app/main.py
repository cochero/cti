"""identity-telemetry-svc — read-only IdP sync + blast-radius (Arch SS4.2).

Snapshot model: each sync replaces the tenant's identity snapshot for that
source inside one transaction (RLS-fenced, tenant context per-tx). Blast
radius v0 is deterministic arithmetic over the snapshot — inputs to the
scoring engine (SS6.4), never a prediction.

Requires TRUVO_IDENTITY_DB_URL (truvo_app role).
"""

import os
from typing import Any, Dict, List, Optional

import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.providers import EntraProvider, FakeProvider, Identity, IdentityProvider

app = FastAPI(title="truvo-identity-telemetry", version="0.1.0")

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_IDENTITY_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_IDENTITY_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


class SyncRequest(BaseModel):
    provider: str = Field(pattern="^(entra|okta|fake)$")
    # entra
    idp_tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None  # S7: vault reference, not the secret
    # fake (tests)
    fake_identities: Optional[List[Dict[str, Any]]] = None


def _provider(req: SyncRequest) -> IdentityProvider:
    if req.provider == "entra":
        if not (req.idp_tenant_id and req.client_id and req.client_secret):
            raise HTTPException(422, "entra requires idp_tenant_id/client_id/client_secret")
        return EntraProvider(req.idp_tenant_id, req.client_id, req.client_secret)
    if req.provider == "fake":
        return FakeProvider([Identity(**i) for i in req.fake_identities or []])
    raise HTTPException(422, "okta provider lands in a later sprint")


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "identity-telemetry"}


@app.post("/v1/{tenant}/sync")
def sync(tenant: str, req: SyncRequest) -> Dict[str, Any]:
    provider = _provider(req)
    identities = list(provider.fetch_identities())
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
            # snapshot semantics: replace this source's view atomically
            cur.execute(
                "DELETE FROM identities WHERE tenant_id = %s AND source = %s",
                (tenant, provider.source),
            )
            for ident in identities:
                cur.execute(
                    "INSERT INTO identities (tenant_id, source, principal_id,"
                    " kind, display, privileged, roles)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        tenant, provider.source, ident.principal_id, ident.kind,
                        ident.display, ident.privileged, ident.roles,
                    ),
                )
        conn.commit()
    except psycopg2.errors.ForeignKeyViolation:
        conn.rollback()
        raise HTTPException(404, "unknown tenant")
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)
    return {"tenant": tenant, "source": provider.source, "synced": len(identities)}


@app.get("/v1/{tenant}/blast-radius")
def blast_radius(tenant: str) -> Dict[str, Any]:
    """v0: deterministic privilege-surface arithmetic over the snapshot."""
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
            cur.execute(
                "SELECT count(*),"
                " count(*) FILTER (WHERE privileged),"
                " count(*) FILTER (WHERE privileged AND kind = 'service')"
                " FROM identities WHERE tenant_id = %s",
                (tenant,),
            )
            total, privileged, privileged_services = cur.fetchone()
            cur.execute(
                "SELECT r.role, count(*) FROM identities, unnest(roles) AS r(role)"
                " WHERE tenant_id = %s AND privileged"
                " GROUP BY r.role ORDER BY count(*) DESC, r.role LIMIT 10",
                (tenant,),
            )
            top_roles = [{"role": r[0], "principals": r[1]} for r in cur.fetchall()]
        conn.commit()
    finally:
        pool().putconn(conn)
    if total == 0:
        raise HTTPException(404, "no identity snapshot for tenant")
    return {
        "tenant": tenant,
        "total_principals": total,
        "privileged_principals": privileged,
        "privileged_ratio_millis": privileged * 1000 // total,
        "privileged_service_accounts": privileged_services,
        "top_privileged_roles": top_roles,
        "blast_version": "blast-v0.1",
    }
