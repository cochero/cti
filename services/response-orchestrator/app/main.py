"""response-orchestrator — the only service allowed to command outbound action.

POST /v1/evaluate: given a proposed action, decide its tier (§8.1), gather
live circuit-breaker state from the action log, apply the breakers (§8.2),
and return a verdict. Tier-1 that survives every breaker is 'approved' for
autonomous execution; everything else routes to policy eval or a human. The
full reasoning is written to a hash-chained ledger entry, and the action is
recorded append-only for accountability + breaker state.

This service NEVER calls a customer SIEM directly here — gateway-svc does
the push, and only on an 'approved'/'executed' verdict from this service.
Requires TRUVO_ORCH_DB_URL.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from truvo_core.hashchain import LedgerEntry, append_entry

from app.guardrails import (
    AssetCriticality,
    CircuitState,
    EvidenceLevel,
    Tier,
    check_circuit_breakers,
    decide_tier,
)

app = FastAPI(title="truvo-response-orchestrator", version="0.1.0")

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_ORCH_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_ORCH_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


class ActionRequest(BaseModel):
    tenant: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    target: str = Field(min_length=1)
    evidence_level: int = Field(ge=1, le=4)
    criticality: int = Field(ge=1, le=3)
    reversible: bool
    asset_class_affected_millis: int = Field(default=0, ge=0, le=1000)
    telemetry_age_seconds: int = Field(default=0, ge=0)


def _gather_state(cur, tenant: str, action_type: str, req: ActionRequest) -> CircuitState:
    cur.execute(
        "SELECT count(*) FROM response_actions WHERE tenant_id = %s"
        "  AND created_at > now() - interval '1 hour'", (tenant,))
    per_tenant = cur.fetchone()[0]
    # cross-tenant count via the SECURITY DEFINER aggregate (bypasses RLS,
    # returns only an integer — see migration 0012). This is what makes the
    # platform-compromise breaker actually functional under RLS.
    cur.execute("SELECT truvo_global_action_count(interval '1 hour')")
    global_count = cur.fetchone()[0]
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM response_actions WHERE tenant_id = %s"
        "  AND action_type = %s AND executed)", (tenant, action_type))
    seen = bool(cur.fetchone()[0])
    return CircuitState(
        actions_last_hour=per_tenant,
        global_actions_last_hour=global_count,
        asset_class_affected_millis=req.asset_class_affected_millis,
        action_type_seen_before=seen,
        telemetry_age_seconds=req.telemetry_age_seconds,
    )


def _ledger_append(cur, tenant: str, payload: Dict[str, Any]) -> int:
    cur.execute("SELECT pg_advisory_xact_lock(hashtext('ledger:' || %s))", (tenant,))
    cur.execute(
        "SELECT seq, ts_iso, actor, kind, payload, prev_hash, entry_hash"
        " FROM ledger_entries WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
        (tenant,))
    row = cur.fetchone()
    prev = LedgerEntry(seq=row[0], ts_iso=row[1], tenant=tenant, actor=row[2],
                       kind=row[3], payload=row[4], prev_hash=row[5],
                       entry_hash=row[6]) if row else None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    entry = append_entry(prev, ts_iso=ts, tenant=tenant,
                         actor="response-orchestrator", kind="action.decided",
                         payload=payload)
    cur.execute(
        "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor, kind,"
        " payload, prev_hash, entry_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (tenant, entry.seq, entry.ts_iso, entry.actor, entry.kind,
         json.dumps(entry.payload), entry.prev_hash, entry.entry_hash))
    return entry.seq


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "response-orchestrator"}


@app.post("/v1/evaluate")
def evaluate(req: ActionRequest) -> Dict[str, Any]:
    tier = decide_tier(EvidenceLevel(req.evidence_level),
                       AssetCriticality(req.criticality), req.reversible)
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (req.tenant,))
            cur.execute("SELECT 1 FROM tenants WHERE tenant_id = %s", (req.tenant,))
            if cur.fetchone() is None:
                conn.rollback()
                raise HTTPException(404, "unknown tenant")

            state = _gather_state(cur, req.tenant, req.action_type, req)
            breaker = check_circuit_breakers(tier, state)

            final_tier = breaker.forced_tier or tier
            if not breaker.allowed and breaker.forced_tier is None:
                # hard block (spike / dead-man / velocity): refuse outright
                verdict, executed = "blocked", False
            elif breaker.allowed and final_tier == Tier.TIER1_AUTONOMOUS:
                verdict, executed = "approved", True   # gateway would push now
            elif breaker.allowed and final_tier == Tier.TIER2_POLICY:
                verdict, executed = "policy", False
            else:
                # decided Tier 3, or a breaker downgraded to human review
                verdict, executed = "human", False

            payload = {
                "action_type": req.action_type, "target": req.target,
                "evidence_level": req.evidence_level, "criticality": req.criticality,
                "reversible": req.reversible, "decided_tier": int(tier),
                "final_tier": int(final_tier), "verdict": verdict,
                "reason": breaker.reason, "executed": executed,
            }
            seq = _ledger_append(cur, req.tenant, payload)
            cur.execute(
                "INSERT INTO response_actions (tenant_id, action_type, target,"
                " evidence_level, criticality, reversible, decided_tier, executed,"
                " verdict, reason, ledger_seq) VALUES"
                " (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING action_id",
                (req.tenant, req.action_type, req.target, req.evidence_level,
                 req.criticality, req.reversible, int(final_tier), executed,
                 verdict, breaker.reason, seq))
            action_id = cur.fetchone()[0]
        conn.commit()
    except HTTPException:
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)

    return {"action_id": str(action_id), "decided_tier": int(tier),
            "final_tier": int(final_tier), "verdict": verdict, "executed": executed,
            "reason": breaker.reason, "ledger_seq": seq}


@app.get("/v1/{tenant}/actions")
def list_actions(tenant: str, limit: int = 50) -> Dict[str, Any]:
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
            cur.execute(
                "SELECT action_id, action_type, target, verdict, executed,"
                " decided_tier FROM response_actions WHERE tenant_id=%s"
                " ORDER BY created_at DESC LIMIT %s", (tenant, limit))
            rows = cur.fetchall()
        conn.commit()
    finally:
        pool().putconn(conn)
    return {"tenant": tenant, "count": len(rows),
            "actions": [{"action_id": str(r[0]), "action_type": r[1],
                         "target": r[2], "verdict": r[3], "executed": r[4],
                         "tier": r[5]} for r in rows]}
