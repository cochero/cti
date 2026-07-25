"""Gather scoring inputs for one (tenant, CVE) from the read model.

v0 reads directly from the shared Postgres (ADR-0007): global tables
(exploit_intel, graph_edges, claims) and the tenant's RLS-fenced tables
(tenant_assets, tenant_sector, identities) under the connection's tenant
context. The mesh era replaces cross-domain reads with API calls / read
replicas — see ADR-0007. The engine stays pure; only this file touches I/O.
"""


from app.engine import ScoringInput


def _actor_count(cur, cve: str, max_depth: int = 5) -> int:
    cur.execute(
        """
        WITH RECURSIVE walk(node_type, node_id, depth, path) AS (
            SELECT 'CVE', %s, 0, ARRAY['CVE:' || %s]
          UNION ALL
            SELECT e.src_type, e.src_id, w.depth + 1,
                   w.path || (e.src_type || ':' || e.src_id)
            FROM walk w JOIN graph_edges e
              ON e.dst_type = w.node_type AND e.dst_id = w.node_id
            WHERE w.depth < %s
              AND NOT (e.src_type || ':' || e.src_id) = ANY(w.path)
        )
        SELECT count(DISTINCT node_id) FROM walk WHERE node_type = 'THREAT_ACTOR'
        """,
        (cve, cve, max_depth),
    )
    return cur.fetchone()[0]


def _sector_targeted(cur, cve: str) -> bool:
    """Does any actor that can reach this CVE target the tenant's sector?
    (tenant_sector is RLS-fenced; graph 'targets' edges are global.)"""
    cur.execute("SELECT sector FROM tenant_sector LIMIT 1")
    row = cur.fetchone()
    if not row:
        return False
    sector = row[0]
    cur.execute(
        """
        WITH RECURSIVE walk(node_type, node_id, depth, path) AS (
            SELECT 'CVE', %s, 0, ARRAY['CVE:' || %s]
          UNION ALL
            SELECT e.src_type, e.src_id, w.depth + 1,
                   w.path || (e.src_type || ':' || e.src_id)
            FROM walk w JOIN graph_edges e
              ON e.dst_type = w.node_type AND e.dst_id = w.node_id
            WHERE w.depth < 5
              AND NOT (e.src_type || ':' || e.src_id) = ANY(w.path)
        )
        SELECT EXISTS (
            SELECT 1 FROM walk w JOIN graph_edges t
              ON t.src_type = 'THREAT_ACTOR' AND t.src_id = w.node_id
            WHERE w.node_type = 'THREAT_ACTOR'
              AND t.rel = 'targets' AND t.dst_type = 'SECTOR' AND t.dst_id = %s
        )
        """,
        (cve, cve, sector),
    )
    return bool(cur.fetchone()[0])


def _identity_exposure_millis(cur) -> int:
    cur.execute(
        "SELECT count(*), count(*) FILTER (WHERE privileged) FROM identities"
    )
    total, priv = cur.fetchone()
    return (priv * 1000 // total) if total else 0


def _campaign_momentum_millis(cur, cve: str) -> int:
    """Recent corroborated activity: distinct sources claiming this CVE in
    the last 30 days, scaled (0->0, 1->300, 2->550, 3+->approaching 1000).
    Deterministic given the DB state; the 30-day window is relative to the
    claim rows, not wall-clock in the engine."""
    cur.execute(
        "SELECT count(DISTINCT source_id) FROM claims"
        " WHERE subject_type = 'CVE' AND subject_value = %s"
        "   AND ingested_at > now() - interval '30 days'",
        (cve,),
    )
    n = cur.fetchone()[0]
    # bounded accumulation: each source adds into remaining headroom
    m = 0
    for _ in range(n):
        m += (1000 - m) * 350 // 1000
    return min(m, 1000)


def gather_inputs(cur, cve: str) -> ScoringInput:
    """cur must already have tenant context set (RLS)."""
    cur.execute(
        "SELECT epss_millis, cvss_millis, kev, poc_public FROM exploit_intel"
        " WHERE cve = %s",
        (cve,),
    )
    ex = cur.fetchone()
    epss, cvss, kev, poc = (ex if ex else (0, 0, False, False))

    # affects_tenant: the tenant runs an asset whose CPE is linked to this
    # CVE by a graph 'exploits' edge (INFRASTRUCTURE cpe -exploits-> CVE).
    # tenant_assets is RLS-fenced; graph_edges is global.
    cur.execute(
        "SELECT count(*), coalesce(sum(ta.count), 0) FROM tenant_assets ta"
        " WHERE EXISTS ("
        "   SELECT 1 FROM graph_edges e"
        "   WHERE e.rel = 'exploits' AND e.dst_type = 'CVE' AND e.dst_id = %s"
        "     AND e.src_type = 'INFRASTRUCTURE' AND e.src_id = ta.cpe"
        " )",
        (cve,),
    )
    n_assets, asset_sum = cur.fetchone()
    affects = n_assets > 0

    return ScoringInput(
        cve=cve,
        epss_millis=epss, cvss_millis=cvss, kev=kev, poc_public=poc,
        affects_tenant=affects, asset_count=int(asset_sum),
        actor_count=_actor_count(cur, cve),
        identity_exposure_millis=_identity_exposure_millis(cur),
        campaign_momentum_millis=_campaign_momentum_millis(cur, cve),
        sector_targeted=_sector_targeted(cur, cve),
    )
