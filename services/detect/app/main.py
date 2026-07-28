"""detect-svc — continuous monitoring (Architecture v2 §4.2 Detect, §11.3).

Two capabilities:
- POST /v1/ioc-match: cross-reference an inbound IOC batch against the
  tenant's watchlist (bloom pre-screen -> exact), returning hits with graph
  context (which actor/malware the IOC belongs to).
- POST /v1/credential-scan: scan a breach dump for the tenant's registered
  domains ONLY, storing salted hashes (never cleartext) — §11.3.

Requires TRUVO_DETECT_DB_URL. Salt from vault (dev falls back to env).
"""

import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.credleak import scan_breach
from app.ioc import match_iocs

app = FastAPI(title="truvo-detect", version="0.1.0")

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_DETECT_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_DETECT_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


def _cred_salt(tenant: str) -> str:
    if os.environ.get("TRUVO_VAULT_ADDR"):
        from truvo_secrets import SecretsClient
        client = SecretsClient()
        path = "truvo/tenants/%s" % tenant
        try:
            return client.kv_get("secret", path)["cred_salt"]
        except KeyError:
            import secrets as _s
            salt = _s.token_hex(16)
            existing = {}
            try:
                existing = client.kv_get("secret", path)
            except KeyError:
                pass
            existing["cred_salt"] = salt
            client.kv_put("secret", path, existing)
            return salt
    return os.environ.get("TRUVO_DEV_CRED_SALT", "dev-salt")


class IocBatch(BaseModel):
    tenant: str = Field(min_length=1)
    iocs: List[str] = Field(min_length=1)


class BreachScan(BaseModel):
    tenant: str = Field(min_length=1)
    source: str = Field(min_length=1)
    records: List[Dict[str, str]] = Field(min_length=1)


def _tenant_cursor(conn, tenant: str):
    cur = conn.cursor()
    cur.execute("BEGIN")
    cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
    cur.execute("SELECT 1 FROM tenants WHERE tenant_id=%s", (tenant,))
    if cur.fetchone() is None:
        raise HTTPException(404, "unknown tenant")
    return cur


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "detect"}


@app.post("/v1/ioc-match")
def ioc_match(batch: IocBatch) -> Dict[str, Any]:
    conn = pool().getconn()
    try:
        cur = _tenant_cursor(conn, batch.tenant)
        cur.execute("SELECT ioc_value FROM tenant_watchlist WHERE tenant_id=%s",
                    (batch.tenant,))
        watchlist = {r[0] for r in cur.fetchall()}
        matched, rejected = match_iocs(watchlist, batch.iocs)
        # graph context: which actor/malware each matched IOC (as INFRASTRUCTURE
        # node) is attributed to
        context = {}
        for ioc in matched:
            cur.execute(
                "SELECT src_type, src_id FROM graph_edges"
                " WHERE dst_type='INFRASTRUCTURE' AND dst_id=%s", (ioc,))
            context[ioc] = [{"type": r[0], "id": r[1]} for r in cur.fetchall()]
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)
    return {"tenant": batch.tenant, "inbound": len(batch.iocs),
            "matched": matched, "prescreen_rejected": rejected,
            "graph_context": context}


@app.post("/v1/credential-scan")
def credential_scan(scan: BreachScan) -> Dict[str, Any]:
    salt = _cred_salt(scan.tenant)
    conn = pool().getconn()
    try:
        cur = _tenant_cursor(conn, scan.tenant)
        cur.execute("SELECT domain FROM tenant_domains WHERE tenant_id=%s",
                    (scan.tenant,))
        domains = {r[0] for r in cur.fetchall()}
        hits = scan_breach(scan.records, domains, salt)
        stored = 0
        for h in hits:
            cur.execute(
                "INSERT INTO credential_leaks (tenant_id, local_part, domain,"
                " cred_salted_sha256, source) VALUES (%s,%s,%s,%s,%s)"
                " ON CONFLICT DO NOTHING",
                (scan.tenant, h["local_part"], h["domain"],
                 h["cred_salted_sha256"], scan.source))
            stored += cur.rowcount
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)
    return {"tenant": scan.tenant, "scanned": len(scan.records),
            "in_scope_hits": len(hits), "newly_stored": stored}


@app.get("/v1/{tenant}/leaks")
def list_leaks(tenant: str, limit: int = 100) -> Dict[str, Any]:
    conn = pool().getconn()
    try:
        cur = _tenant_cursor(conn, tenant)
        cur.execute("SELECT local_part, domain, source, discovered_at"
                    " FROM credential_leaks WHERE tenant_id=%s"
                    " ORDER BY discovered_at DESC LIMIT %s", (tenant, limit))
        rows = cur.fetchall()
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)
    # note: response exposes local_part@domain (the customer's OWN asset) and
    # source — never any credential material, salted or not
    return {"tenant": tenant, "count": len(rows),
            "leaks": [{"account": "%s@%s" % (r[0], r[1]), "source": r[2],
                       "discovered_at": r[3].isoformat()} for r in rows]}
