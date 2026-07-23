# graph-svc

Threat knowledge graph: actor -> uses -> malware -> exploits -> CVE, and attack-path traversal (Architecture v2 §5.1).

- **Reference:** Architecture v2 §5.1; db/migrations/0009; ADR-0006
- **Owner:** Intelligence Pipeline
- **Status:** relational-adjacency v0 (recursive CTE); Neo4j/AGE deferred per ADR-0006

## What it does
Ingests global threat-intel edges and answers the query scoring needs: "which actors can reach this CVE, by what path?" — a cycle-safe, depth-bounded reverse traversal. The HTTP API is the graph DAL, so the storage engine can swap (Neo4j Full Mesh / Apache AGE Compact) without moving callers.

## Proven (live)
- Multi-actor attack paths (two actors reaching one CVE via different malware), deeper chains via campaigns, cycle safety (variant_of loops terminate, no duplicate actors), depth bounding.

## Not yet
- openCypher / real graph analytics (centrality, community detection) — see ADR-0006 revisit triggers.
- Tenant-asset subgraph (CVE -> asset), which will be RLS-fenced, lands with Phase 3 scoring.

Before staging: OTel, runbook, THREAT_MODEL.md.
