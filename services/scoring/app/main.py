"""scoring-svc — deterministic prioritization + auditable decomposition.

POST /v1/score {tenant, cve}: set tenant context (RLS), gather inputs from
the read model, run the PURE engine, write a hash-chained ledger entry
holding the full decomposition (so the score is replayable and tamper-
evident, §2.4/§6.4), persist the score row, and return the decomposition.

The engine is pure and versioned; this service is the thin I/O shell.
Requires TRUVO_SCORING_DB_URL (truvo_app role).
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from truvo_core.hashchain import append_entry

from app.engine import WEIGHTS_V0, score
from app.gather import gather_inputs

app = FastAPI(title="truvo-scoring", version="0.1.0")

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_SCORING_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_SCORING_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


class ScoreRequest(BaseModel):
    tenant: str = Field(min_length=1)
    cve: str = Field(min_length=1)


def _ledger_append(cur, tenant: str, kind: str, payload: Dict[str, Any]) -> int:
    """Append a hash-chained ledger entry for this tenant (same discipline
    as ledger-svc): per-tenant advisory lock, chain from the prior head."""
    cur.execute("SELECT pg_advisory_xact_lock(hashtext('ledger:' || %s))", (tenant,))
    cur.execute(
        "SELECT seq, ts_iso, actor, kind, payload, prev_hash, entry_hash"
        " FROM ledger_entries WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
        (tenant,),
    )
    row = cur.fetchone()
    from truvo_core.hashchain import LedgerEntry
    prev = LedgerEntry(seq=row[0], ts_iso=row[1], tenant=tenant, actor=row[2],
                       kind=row[3], payload=row[4], prev_hash=row[5],
                       entry_hash=row[6]) if row else None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    entry = append_entry(prev, ts_iso=ts, tenant=tenant, actor="scoring-svc",
                         kind=kind, payload=payload)
    cur.execute(
        "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor, kind,"
        " payload, prev_hash, entry_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (tenant, entry.seq, entry.ts_iso, entry.actor, entry.kind,
         json.dumps(entry.payload), entry.prev_hash, entry.entry_hash),
    )
    return entry.seq


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "scoring", "weights": WEIGHTS_V0.version}


@app.post("/v1/score")
def do_score(req: ScoreRequest) -> Dict[str, Any]:
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (req.tenant,))
            # tenant must exist (FK + RLS visibility)
            cur.execute("SELECT 1 FROM tenants WHERE tenant_id = %s", (req.tenant,))
            if cur.fetchone() is None:
                conn.rollback()
                raise HTTPException(404, "unknown tenant")

            inputs = gather_inputs(cur, req.cve)
            result = score(inputs, WEIGHTS_V0)
            decomp = result.decomposition()

            seq = _ledger_append(cur, req.tenant, "score.emitted", decomp)
            cur.execute(
                "INSERT INTO scores (tenant_id, cve, priority_millis,"
                " weights_version, ledger_seq) VALUES (%s,%s,%s,%s,%s)",
                (req.tenant, req.cve, result.priority_millis,
                 result.weights_version, seq),
            )
        conn.commit()
    except HTTPException:
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)
    return {"tenant": req.tenant, "priority_millis": result.priority_millis,
            "weights_version": result.weights_version, "ledger_seq": seq,
            "decomposition": decomp}


@app.get("/v1/{tenant}/priorities")
def priorities(tenant: str, limit: int = 20) -> Dict[str, Any]:
    """The SOC's daily queue: top current priorities for the tenant."""
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
            cur.execute(
                "SELECT DISTINCT ON (cve) cve, priority_millis, scored_at,"
                " weights_version FROM scores WHERE tenant_id = %s"
                " ORDER BY cve, scored_at DESC",
                (tenant,),
            )
            rows = cur.fetchall()
        conn.commit()
    finally:
        pool().putconn(conn)
    ranked = sorted(rows, key=lambda r: r[1], reverse=True)[:limit]
    return {"tenant": tenant, "count": len(ranked),
            "priorities": [{"cve": r[0], "priority_millis": r[1],
                            "scored_at": r[2].isoformat(),
                            "weights_version": r[3]} for r in ranked]}
