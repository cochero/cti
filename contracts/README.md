# Contracts

The integration surface between squads. **Schema/API changes land here first, by PR, before any implementation.** (DEVELOPMENT_PLAN.md §3)

- `events/` — Avro schemas for the event backbone. Registered in the schema registry (Redpanda dev: `localhost:18081`). Naming: `<domain>.<entity>.v<N>.avsc`. Compatibility mode: BACKWARD — additive changes only within a version; breaking changes bump `vN`.
- `api/` — OpenAPI specs, one per service. The spec is the review artifact; generated clients/servers are never hand-edited.

Rules:
1. Every event carries `tenant`, `provenance_id`, and `schema_version` (Architecture v2 §5.2).
2. No floats in payloads that feed the ledger or scoring — string decimals or scaled integers (see `truvo_core.canonical`).
3. A contract nobody consumes yet is still a contract: keep it honest, it is the plan of record for the squad building against it.
