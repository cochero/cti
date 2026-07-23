"""graph-svc — threat knowledge graph v0 (Architecture v2 §5.1).

Ingest edges (actor uses malware, malware exploits CVE, ...) and traverse
them: attack paths (who can reach this CVE?) and neighborhoods. v0 is
recursive-CTE over graph_edges; the API is the graph DAL, so the storage
engine (Neo4j/AGE) can change beneath it without moving callers.

Requires TRUVO_GRAPH_DB_URL (truvo_app role). Global threat intel, no RLS.
"""

import os
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="truvo-graph", version="0.1.0")

_NODE = "^(THREAT_ACTOR|MALWARE|CVE|INFRASTRUCTURE|CAMPAIGN|TTP|SECTOR)$"
_REL = "^(uses|exploits|targets|attributed_to|variant_of|communicates_with)$"

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_GRAPH_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_GRAPH_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


def _tx(fn):
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            result = fn(cur)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)


class Edge(BaseModel):
    src_type: str = Field(pattern=_NODE)
    src_id: str = Field(min_length=1, max_length=512)
    rel: str = Field(pattern=_REL)
    dst_type: str = Field(pattern=_NODE)
    dst_id: str = Field(min_length=1, max_length=512)
    weight_millis: int = Field(default=1000, ge=0, le=1000)
    provenance_id: Optional[str] = None


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "graph"}


@app.post("/v1/edges", status_code=201)
def upsert_edge(edge: Edge) -> Dict[str, str]:
    def op(cur):
        cur.execute(
            "INSERT INTO graph_edges (src_type, src_id, rel, dst_type, dst_id,"
            " weight_millis, provenance_id, updated_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, now())"
            " ON CONFLICT (src_type, src_id, rel, dst_type, dst_id) DO UPDATE"
            " SET weight_millis = EXCLUDED.weight_millis,"
            " provenance_id = EXCLUDED.provenance_id, updated_at = now()",
            (edge.src_type, edge.src_id, edge.rel, edge.dst_type, edge.dst_id,
             edge.weight_millis, edge.provenance_id),
        )
        return {"status": "ok"}
    return _tx(op)


@app.get("/v1/neighbors/{node_type}/{node_id}")
def neighbors(node_type: str, node_id: str, direction: str = "out") -> Dict[str, Any]:
    """Immediate neighbors, outbound or inbound."""
    def op(cur):
        if direction == "out":
            cur.execute(
                "SELECT rel, dst_type, dst_id, weight_millis FROM graph_edges"
                " WHERE src_type = %s AND src_id = %s ORDER BY weight_millis DESC",
                (node_type, node_id),
            )
        else:
            cur.execute(
                "SELECT rel, src_type, src_id, weight_millis FROM graph_edges"
                " WHERE dst_type = %s AND dst_id = %s ORDER BY weight_millis DESC",
                (node_type, node_id),
            )
        return [{"rel": r[0], "node_type": r[1], "node_id": r[2],
                 "weight_millis": r[3]} for r in cur.fetchall()]
    return {"node_type": node_type, "node_id": node_id, "direction": direction,
            "neighbors": _tx(op)}


@app.get("/v1/attack-paths/{cve_id}")
def attack_paths(cve_id: str, max_depth: int = 5) -> Dict[str, Any]:
    """Which threat actors can reach this CVE, and by what path.

    Reverse-traverses inbound edges from the CVE up to actors (CVE <-
    exploits <- malware <- uses <- actor), bounded by max_depth. Returns
    the distinct actors and one representative path each. This is the graph
    query scoring (§6.4) uses to weight a CVE by who is known to wield it."""
    if max_depth < 1 or max_depth > 10:
        raise HTTPException(422, "max_depth must be 1..10")

    def op(cur):
        # recursive reverse walk; cycle-safe via visited path array
        cur.execute(
            """
            WITH RECURSIVE walk(node_type, node_id, depth, path) AS (
                SELECT 'CVE', %s, 0, ARRAY['CVE:' || %s]
              UNION ALL
                SELECT e.src_type, e.src_id, w.depth + 1,
                       w.path || (e.src_type || ':' || e.src_id)
                FROM walk w
                JOIN graph_edges e
                  ON e.dst_type = w.node_type AND e.dst_id = w.node_id
                WHERE w.depth < %s
                  AND NOT (e.src_type || ':' || e.src_id) = ANY(w.path)
            )
            SELECT node_id, path FROM walk
            WHERE node_type = 'THREAT_ACTOR'
            ORDER BY array_length(path, 1)
            """,
            (cve_id, cve_id, max_depth),
        )
        seen = {}
        for actor_id, path in cur.fetchall():
            if actor_id not in seen:  # shortest path first (ordered)
                seen[actor_id] = list(reversed(path))
        return seen
    actors = _tx(op)
    return {"cve": cve_id, "actor_count": len(actors),
            "actors": [{"actor": a, "path": p} for a, p in actors.items()]}
