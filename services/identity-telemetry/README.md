# identity-telemetry-svc

Read-only IdP sync (Entra ID / Okta) into the tenant identity snapshot +
blast-radius v0 computation.

- **Reference:** Architecture v2 §4.2; db/migrations/0007
- **Owner:** Product & Integrations
- **Status:** walking skeleton, live-tested via FakeProvider

## Verification status — be precise about what is proven
- **Live-tested** (tests_live/, real Postgres as `truvo_app`): sync
  pipeline, atomic snapshot-replace semantics, RLS tenant isolation,
  blast-radius arithmetic.
- **Written but NOT verified against a live IdP tenant:** `EntraProvider`
  (Graph API client-credential flow, paginated users/servicePrincipals/
  directoryRoles). First design-partner or dev Entra tenant must run
  `POST /v1/{tenant}/sync` with real credentials before this provider is
  called production-ready. Okta provider: not yet written.
- Read-only scopes only (`User.Read.All`, `RoleManagement.Read.Directory`)
  — the service holds no write permission to any customer IdP, by design.

Secrets note: `client_secret` in the sync request is S1–S6 scaffolding;
S7 replaces it with a vault reference (the API shape already anticipates
this — see field comment in `SyncRequest`).

Before first staging traffic this component still needs: OTel
instrumentation, a runbook in `ops/runbooks/`, and a reviewed
THREAT_MODEL.md (pattern: `services/ledger/THREAT_MODEL.md`).
