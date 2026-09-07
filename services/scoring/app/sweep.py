"""Scoring sweep — keep every active tenant's queue current.

One pass over all active tenants; for each, score the CVEs that could
possibly matter to THEM:
  a) CVEs exploiting products in their registered stack (graph edges)
  b) high-EPSS CVEs (global exploit probability above threshold)
  c) KEV-listed CVEs (actively exploited in the wild)
  d) CVEs with recent corroborated claims (campaign momentum)

Idempotent and append-only: a sweep re-scores and appends a fresh ledger
entry per (tenant, cve) — the scores table is a time series, the queue
reads the latest. Candidate cap per tenant keeps a sweep bounded.

    python -m app.sweep      # env: TRUVO_SCORING_DB_URL
"""

import json
import os
from typing import Any, Dict, List

from app.main import pool, score_and_record


def candidate_cves(conn, tenant: str) -> List[str]:
    """Relevant CVEs for this tenant, best-first, capped."""
    cap = int(os.environ.get("TRUVO_SWEEP_MAX_CVE", "150"))
    epss_floor = int(os.environ.get("TRUVO_SWEEP_EPSS_FLOOR", "300"))

    with conn.cursor() as cur:
        return _candidates(cur, tenant, cap, epss_floor)


def _candidates(cur, tenant: str, cap: int, epss_floor: int) -> List[str]:
    cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
    # (a) the tenant's own stack — the heaviest factor
    cur.execute(
        """
        SELECT DISTINCT e.dst_id FROM tenant_assets ta
        JOIN graph_edges e ON e.src_type = 'INFRASTRUCTURE'
                          AND e.src_id = ta.cpe
                          AND e.rel = 'exploits' AND e.dst_type = 'CVE'
        """)
    stack = [r[0] for r in cur.fetchall()]

    # (b)+(c) global exploit momentum: EPSS above floor or KEV, ranked
    cur.execute(
        "SELECT cve FROM exploit_intel"
        " WHERE kev OR epss_millis >= %s"
        " ORDER BY kev DESC, epss_millis DESC LIMIT %s",
        (epss_floor, cap))
    hot = [r[0] for r in cur.fetchall()]

    # (d) recently claimed CVEs (corroboration stream, last 14 days)
    cur.execute(
        "SELECT DISTINCT subject_value FROM claims"
        " WHERE subject_type = 'CVE' AND ingested_at > now() - interval '14 days'"
        " LIMIT %s", (cap,))
    recent = [r[0] for r in cur.fetchall()]

    seen, ordered = set(), []
    for cve in stack + hot + recent:  # stack first — never drop those
        if cve not in seen:
            seen.add(cve)
            ordered.append(cve)
    return ordered[:max(cap, len(stack))]


def run() -> Dict[str, Any]:
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tenant_id FROM tenants WHERE status = 'active'"
                " ORDER BY created_at")
            tenants = [str(r[0]) for r in cur.fetchall()]

        scored = errors = 0
        per_tenant = {}
        for tenant in tenants:
            n = err = 0
            for cve in candidate_cves(conn, tenant):
                try:
                    score_and_record(conn, tenant, cve)
                    n += 1
                except Exception:  # one CVE must not stop the sweep
                    conn.rollback()
                    err += 1
            scored += n
            errors += err
            per_tenant[tenant] = {"scored": n, "errors": err}
    finally:
        pool().putconn(conn)
    return {"tenants": len(tenants), "scored": scored, "errors": errors,
            "per_tenant": per_tenant}


def main() -> None:
    print(json.dumps(run()))


if __name__ == "__main__":
    main()
