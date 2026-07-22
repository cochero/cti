# TRUVO Monorepo

**PRIORITIZE · HUNT · DETECT** — Explainable threat intelligence & automated detection engineering.

- Architecture of record: `../TRUVO_Architecture_v2.md`
- Execution plan: `../DEVELOPMENT_PLAN.md`
- Decisions: `docs/adr/` — deviations from the architecture require an ADR, not a Slack thread.

## Layout

| Path | What lives here |
|---|---|
| `contracts/` | Avro event schemas + OpenAPI specs. PR-reviewed. Squads integrate against these, not against each other's calendars. |
| `services/` | One directory per microservice (see Architecture §4.2). Each owns its code, tests, Dockerfile, threat-model note. |
| `core/` | Django project: tenancy, RBAC, SSO, admin, MIS API. |
| `web/` / `mobile/` | React analyst console + CISO dashboard; Flutter approvals app (Phase 4). |
| `libs/py/` | Shared Python libraries (`truvo_core`: canonical JSON, hash-chain ledger primitives). |
| `deploy/` | `compose/` dev stack · `helm/` charts (both profiles) · `k3s-compact/` air-gap reference. |
| `docs/adr/` | Architecture Decision Records. |
| `ops/runbooks/` | One runbook per service; every alert links here. |

## Dev environment (Sprint S0 stack)

Requires Docker Desktop. From repo root:

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

Brings up:
- **PostgreSQL 17 + TimescaleDB** on `localhost:5432` (db `truvo`, user `truvo`)
- **Redpanda** (Kafka API) on `localhost:9092`, console on `localhost:8080`
- **MinIO** (S3 API) on `localhost:9000`, console on `localhost:9001`

Tear down: `docker compose -f deploy/compose/docker-compose.yml down -v`

## Python setup

Target runtime is Python 3.13 (CI); code must stay compatible with 3.9+ during bootstrap.

```bash
python -m pip install -e libs/py/truvo_core[dev]
python -m pytest libs/py/truvo_core
```

## Ground rules (from DEVELOPMENT_PLAN.md §1, §3)

1. Trunk-based: short-lived branches, PR review, `main` always deployable.
2. Everything merged is production-candidate. No prototype track.
3. Contracts first: schema/API changes land in `contracts/` before implementation.
4. Every service: OTel instrumentation, runbook, and threat-model note **before** first staging traffic.
5. The replay property (`replay(ledger_entry) == original_output`) is a CI test, not a claim.
