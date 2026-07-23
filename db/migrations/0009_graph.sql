-- 0009: threat knowledge graph v0 (Architecture v2 §5.1 graph-svc).
--
-- Global threat-intel edges: actor -> uses -> malware -> exploits -> CVE,
-- actor -> targets -> sector, etc. Nodes are canonical entities (from
-- entity-resolution, §0008) identified by (node_type, node_id) where
-- node_id is the entity's canonical_id or a canonical value.
--
-- v0 is relational adjacency + recursive-CTE traversal behind the graph
-- DAL. The architecture's target substrate is Neo4j (Full Mesh) / Apache
-- AGE (Compact) speaking openCypher; this table is the swap-point
-- implementation so attack-path queries exist NOW without a new engine
-- (ADR note: revisit when traversal depth/latency needs a real graph db).
--
-- Global infrastructure: threat relationships are shared intel, not
-- tenant data, so no RLS. Tenant-asset edges (CVE -> asset) arrive with
-- Phase 3 scoring and WILL be tenant-RLS-fenced in their own table.

CREATE TABLE IF NOT EXISTS graph_edges (
    src_type   text NOT NULL CHECK (src_type IN
        ('THREAT_ACTOR','MALWARE','CVE','INFRASTRUCTURE','CAMPAIGN','TTP','SECTOR')),
    src_id     text NOT NULL,
    rel        text NOT NULL CHECK (rel IN
        ('uses','exploits','targets','attributed_to','variant_of','communicates_with')),
    dst_type   text NOT NULL CHECK (dst_type IN
        ('THREAT_ACTOR','MALWARE','CVE','INFRASTRUCTURE','CAMPAIGN','TTP','SECTOR')),
    dst_id     text NOT NULL,
    weight_millis int NOT NULL DEFAULT 1000 CHECK (weight_millis BETWEEN 0 AND 1000),
    provenance_id text,          -- claim/rawdoc that asserted this edge
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (src_type, src_id, rel, dst_type, dst_id)
);

CREATE INDEX IF NOT EXISTS graph_edges_dst_idx ON graph_edges (dst_type, dst_id);
CREATE INDEX IF NOT EXISTS graph_edges_src_idx ON graph_edges (src_type, src_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON graph_edges TO truvo_app;
