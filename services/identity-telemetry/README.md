# identity-telemetry-svc

Entra ID / Okta read-only sync into the tenant asset model; privilege graph; blast-radius computation.

- **Reference:** Arch SS4.2; built S5-S6
- **Owner:** Product & Integrations
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).
