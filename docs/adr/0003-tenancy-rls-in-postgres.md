# ADR-0003: Enforce tenancy with Postgres RLS, SQL-first

- **Status:** Accepted
- **Date:** 2026-07-22
- **Deciders:** founding engineering team
- **Relates to:** Architecture v2 §4 (Tenant Isolation), §11.1; DEVELOPMENT_PLAN §4 S1–S2

## Context
Tenant isolation is the highest-consequence invariant in the SaaS profile: a
single leak is an unrecoverable trust event for a security product. Enforcing
it in application code (per-query `WHERE tenant_id = ...`) means every new
query is a chance to forget, across every service and every framework.

## Decision
Tenancy is enforced in Postgres itself:
- Tenant-scoped tables carry `tenant_id` in the primary key, with
  `ENABLE` + `FORCE ROW LEVEL SECURITY` and a single policy fencing both
  `USING` (reads) and `WITH CHECK` (writes) to
  `truvo_current_tenant()` — a function reading `truvo.tenant_id` from the
  connection context.
- Services connect as `truvo_app` (no SUPERUSER, no BYPASSRLS) and set the
  tenant context per connection/transaction. Frameworks (Django, FastAPI)
  consume this; they cannot widen it.
- Schema lives in SQL-first migrations (`db/migrations/`) applied by a
  content-hash-checking runner. Django models map onto these tables
  (`managed = False` for RLS-bearing tables) rather than generating them.
- The cross-tenant leak test suite (`db/tests/`) runs as `truvo_app` against
  real Postgres in CI on every PR, and additionally asserts role privileges
  and RLS flags so drift fails loudly.

## Consequences
Easier: one enforcement point; every future tenant-scoped table inherits a
proven pattern; the DoD leak test is meaningful (it exercises the exact
mechanism production uses). Harder: two schema tools in play (SQL runner +
Django migrations for Django-owned, non-tenant tables) — the boundary is
"RLS-bearing tables are SQL-first, always." Per-tenant encryption keys and
connection pooling with per-transaction `set_config` need care at S3+
(pgbouncer transaction mode requires transaction-scoped settings).
Revisit trigger: a service genuinely needing cross-tenant queries (e.g.
k-anonymized aggregates, Arch §6.6.4) — that path gets a dedicated read-only
role and its own ADR, never a policy exception on `truvo_app`.
