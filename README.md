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

## Bringing up a working system end to end (dev)

After the data stack is up and migrations applied (`python db/migrate.py "$DB_URL"`):

```bash
# 1. real intelligence into the pipeline (KEV + EPSS + ATT&CK STIX)
cd services/collector && PYTHONPATH=. python -m app.run_feeds kev epss attack
# 2. extract -> gate -> claims; 3. corroboration; 4. scoring read model
cd ../extraction   && PYTHONPATH=. python -m app.run
cd ../provenance   && PYTHONPATH=. python -m app.consumer
cd ../scoring      && PYTHONPATH=. python -m app.enrich
# 5. demo tenant + users; 6. core + console
cd ../../core && python manage.py seed_demo && python manage.py runserver 8000
cd ../web && npm install && npm run dev     # console on :5173/5174
```

Login: `demo-analyst@truvo.local` / `demo-pass`. Scoring runs per CVE via
`POST :8020/v1/score` (scoring-svc); rules are generated via detection-factory
`POST :8030/v1/rules` and reviewed in the console.

## Scheduled intelligence (the heartbeat)

`ops/run_cycle.py` runs the full pipeline as one cycle — collect (KEV/EPSS/ATT&CK)
→ extract (structured feeds parse directly; text takes the quarantined extractor,
`TRUVO_EXTRACTOR=llm` for a served OpenAI-compatible model) → corroborate →
enrich → **sweep** (every active tenant × relevant CVEs re-scored; the queue
readers take the latest). Failed stages exit non-zero. Deploy as the compose
`pipeline` service, the Helm CronJob (`pipeline.enabled`), or plain cron.

## The honesty artifact

`services/eval-harness`: `python -m app.report` publishes the calibration &
platform-integrity report — replay verification (every score re-derived from
its ledger entry, bit-exact; a failure is a sev-1), score distributions,
stack coverage, baseline agreement, and outcome calibration that is
**withheld** until ground truth clears the floor. Reports land in
`services/eval-harness/reports/`.

## Console (web/)

React analyst console + CISO dashboard (priority queue, score decomposition
from the ledger, rule review/release, ATT&CK heatmap). Dev: `npm run dev`
proxies `/api` to the core on :8000. Prod: `deploy/docker/Dockerfile.web`
behind Caddy. See `web/README.md`.

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
