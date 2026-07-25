"""Backtest reader — join scores to ground truth and report calibration.

Reads a tenant's (score, did-it-materialize) pairs and runs the pure
metrics. This is the report that gates a weights-version promotion: a new
version ships only if it improves Brier / precision@k over the incumbent on
the same historical window (§9.2).

Requires TRUVO_EVAL_DB_URL (truvo_app role). Reads RLS-fenced scores +
ground_truth under the tenant context.
"""

import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.pool

from app.calibration import brier, precision_at_k, reliability_curve

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_EVAL_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_EVAL_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


def _pairs(cur, tenant: str, weights_version: Optional[str]) -> List:
    """Latest score per CVE joined to whether it materialized. Optionally
    filtered to one weights version (to compare versions on equal ground)."""
    cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
    q = (
        "SELECT DISTINCT ON (s.cve) s.cve, s.priority_millis, gt.materialized"
        " FROM scores s JOIN ground_truth gt"
        "   ON gt.tenant_id = s.tenant_id AND gt.cve = s.cve"
        " WHERE s.tenant_id = %s"
    )
    params = [tenant]
    if weights_version:
        q += " AND s.weights_version = %s"
        params.append(weights_version)
    q += " ORDER BY s.cve, s.scored_at DESC"
    cur.execute(q, params)
    return [(int(p), bool(m)) for (_cve, p, m) in cur.fetchall()]


def backtest(tenant: str, weights_version: Optional[str] = None,
             top_k: int = 10) -> Dict[str, Any]:
    conn = pool().getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            pairs = _pairs(cur, tenant, weights_version)
        conn.commit()
    finally:
        pool().putconn(conn)
    return {
        "tenant": tenant,
        "weights_version": weights_version,
        "sample": len(pairs),
        "brier": brier(pairs),
        "precision_at_k": precision_at_k(pairs, top_k),
        "reliability": [
            {"band": "%d-%d" % (b.lo_millis, b.hi_millis), "n": b.n,
             "predicted_mid_millis": b.predicted_mid_millis,
             "actual_rate_millis": b.actual_rate_millis,
             "gap_millis": b.calibration_gap_millis()}
            for b in reliability_curve(pairs)
        ],
    }
