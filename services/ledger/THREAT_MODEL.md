# Threat-model note — ledger-svc

*Template instance (DEVELOPMENT_PLAN.md §8). Reviewed by: security champion. Status: S0 draft — re-review before first staging traffic.*

**Assets:** the audit chain itself (integrity is the product); tenant event payloads (confidential).

**Entry points:** REST API (append, read, verify). S3 adds Postgres and the anchoring channel.

**Trust boundaries:** callers are internal services only (mTLS + SPIFFE identity from S7); the ledger trusts no caller's claim of prior state — linkage is recomputed on every append.

**Top abuse cases:**
1. **Tamper-and-rewrite** (Arch §3.1-T7): attacker with DB access rewrites history → mitigated by hash chain + periodic external anchor (S4) + replay checks in CI and at runtime (`/verify`).
2. **Cross-tenant read:** payloads leak between tenants → per-tenant chains now; Postgres RLS + per-tenant encryption keys at S3.
3. **Poisoned payload as log injection:** payload content is data, never interpolated into queries/prompts; canonical JSON rejects non-JSON-safe content.

**Non-goals here:** availability under DoS (fronted by mesh rate-limits), payload semantics (callers own their schemas via `contracts/`).
