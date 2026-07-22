# db/ — cluster bootstrap, tenancy schema, RLS enforcement

The tenancy boundary is enforced **in Postgres, not in application code**
(Architecture v2 §4 "Tenant Isolation", ADR-0003). Frameworks and services
consume tenant-scoped tables; they cannot widen them.

## Layout
- `migrations/` — ordered SQL migrations (`NNNN_name.sql`). Applied by `migrate.py`.
- `migrate.py` — minimal runner: applies each file once, transactionally,
  and records its SHA-256 so a mutated already-applied migration fails loudly.
- `tests/` — **the cross-tenant leak test suite** (platform DoD §1.3).
  Runs against `TRUVO_TEST_DATABASE_URL`; skips locally if unset; CI runs it
  against a service container on every PR.

## The RLS pattern (copy this for every tenant-scoped table)
1. `tenant_id uuid NOT NULL` column, part of the primary key.
2. `ENABLE` + `FORCE ROW LEVEL SECURITY`.
3. One policy: `USING` **and** `WITH CHECK` on
   `tenant_id = truvo_current_tenant()` — reads and writes both fenced.
4. Grants to `truvo_app` only for the verbs the table's semantics allow
   (e.g. `ledger_entries` is append-only: SELECT + INSERT, no UPDATE/DELETE).
5. Services set tenant context per-connection/transaction:
   `SELECT set_config('truvo.tenant_id', '<uuid>', true)`.

The application role `truvo_app` has no superuser and no BYPASSRLS — and the
test suite asserts that, so privilege drift fails CI.

## Run locally
```bash
docker compose -f deploy/compose/docker-compose.yml up -d postgres
export TRUVO_TEST_DATABASE_URL=postgresql://truvo:truvo-dev-only@localhost:5432/truvo
python db/migrate.py "$TRUVO_TEST_DATABASE_URL"
python -m pytest db/tests -v
```
