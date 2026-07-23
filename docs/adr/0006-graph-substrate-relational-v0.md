# ADR-0006: Threat graph on relational adjacency (v0), Neo4j/AGE deferred

- **Status:** Accepted
- **Date:** 2026-07-24
- **Deciders:** founding engineering team
- **Relates to:** Architecture v2 §5.1 (graph-svc), §10; DEVELOPMENT_PLAN Phase 2

## Context
The architecture names Neo4j (Full Mesh) / Apache AGE (Compact) as the
graph substrate, behind a DAL speaking openCypher. But: AGE is not in our
Postgres image, Neo4j is another tier-0 container, and the actual Phase 2
need — "which actors can reach this CVE, by what path" for scoring — is a
bounded reverse traversal, not arbitrary graph analytics.

## Decision
graph-svc v0 stores edges in a relational `graph_edges` table and answers
traversal with recursive CTEs (cycle-safe via a visited-path array, depth-
bounded). The service's HTTP API IS the graph DAL: neighbors and
attack-paths are the only traversal primitives callers use, so the storage
engine can change beneath them without moving a single caller.

## Consequences
Real attack-path capability ships now, on the Postgres we already run, with
no new container and full RLS/backup/ops story inherited. Recursive CTEs
comfortably handle the depth (≤10) and fan-out of threat-intel graphs at
current scale. Costs: no openCypher yet; complex analytics (centrality,
community detection) aren't expressible in this v0. Revisit trigger —
promote to Neo4j/AGE when ANY of: traversal depth/latency regresses at
scale, an analytics query needs real graph algorithms, or the tenant-asset
subgraph (Phase 3) makes join-heavy CTEs unwieldy. The DAL boundary is
drawn so that swap is a service-internal change, not an API change.
