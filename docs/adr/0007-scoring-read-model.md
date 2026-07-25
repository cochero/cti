# ADR-0007: Scoring gathers inputs via a shared read model (v0)

- **Status:** Accepted
- **Date:** 2026-07-24
- **Deciders:** founding engineering team
- **Relates to:** Architecture v2 §4.3 (no service reads another's DB), §6.4;
  DEVELOPMENT_PLAN Phase 3

## Context
Design principle #7 / §4.3 says "No service reads another's database. APIs
and events only." Scoring, though, needs to combine signals owned by
several services — graph edges, identity blast-radius, exploit intel,
tenant assets, provenance claims — into one score, on demand, per (tenant,
CVE). Orchestrating five synchronous cross-service HTTP calls per score
adds latency, failure modes, and test complexity disproportionate to a v0.

## Decision
scoring-svc v0 gathers its inputs by direct **read-only** SQL from the
shared Postgres (`app/gather.py` is the only I/O surface; the engine stays
pure). Reads honor RLS: tenant tables (tenant_assets, identities, ...) are
read under the connection's tenant context, so scoring sees only the
scoring tenant's data — the isolation guarantee is unchanged. Writes stay
within scoring's own tables (scores) and the shared ledger.

This is scoped as a **read model**, not a general license to cross DB
boundaries: only read-only, RLS-respecting, analytical gathers qualify.

## Consequences
Scoring ships now, testably, with correct tenant isolation and full
decomposition to the ledger. Cost: a real coupling to other services'
schemas — a breaking change to graph_edges or identities can break
scoring's gather. Mitigation + revisit trigger: when the mesh lands (S8+)
or when a schema-coupling break actually bites, promote the hottest gathers
to service APIs or a materialized read model / read replica. The pure
engine and the gather/engine split are drawn so that swap touches only
`gather.py`. Until then, gather.py carries an explicit note and its SQL is
reviewed as a cross-domain contract.
